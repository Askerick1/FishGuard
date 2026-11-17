"""
Azerbaijan Phishing Protection Backend API
==========================================
Production-ready FastAPI backend for automated anti-phishing protection tailored
for the Azerbaijani digital ecosystem (banks, government, logistics, telecommunications, e-commerce).

Features:
- SQLite database with persistent Whitelist and Blocklist tables + Reporting storage.
- Automatic seeding of major Azerbaijani targets and known test phishing domains.
- Deep Typosquatting & Lookalike detection (Levenshtein distance, Damerau-Levenshtein,
  Homoglyph/Confusable normalization, Combosquatting, and Subdomain Spoofing).
- Smart domain heuristics: IP hosts, suspicious TLDs, Azerbaijani & English phishing keywords,
  excessive hyphens, length, and Shannon entropy analysis.
- Pending phishing reports and a separate operator-verified threat feed.
"""

from contextlib import asynccontextmanager
import datetime
import ipaddress
import math
import os
import re
import sqlite3
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from starlette.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, Field

# ------------------------------------------------------------------------------
# Configuration & Constants
# ------------------------------------------------------------------------------

DATABASE_FILE = os.getenv("DATABASE_FILE", "antiphish_az.db")
API_VERSION = "v1"

# Confusable & Homoglyph normalization map (Visual lookalikes, Cyrillic, Leetspeak)
# Cyrillic characters are frequently used in Azerbaijan/CIS regions to spoof Latin letters.
CONFUSABLES_MAP: Dict[str, str] = {
    # Numbers and symbols used as leetspeak
    "1": "i", "!": "i", "|": "i", "¡": "i", "ı": "i", "í": "i", "ì": "i", "ï": "i", "î": "i",
    "0": "o", "ó": "o", "ò": "o", "ö": "o", "ô": "o", "ø": "o",
    "3": "e", "€": "e", "é": "e", "è": "e", "ë": "e", "ê": "e", "ə": "e",
    "4": "a", "@": "a", "á": "a", "à": "a", "ä": "a", "â": "a", "ã": "a", "å": "a",
    "5": "s", "$": "s", "ş": "s", "š": "s",
    "7": "t",
    "8": "b",
    "9": "g",
    # Cyrillic homoglyphs mapping to Latin
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "в": "b", "к": "k",
    "м": "m", "н": "h", "т": "t",
    # Greek homoglyphs
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "ε": "e", "ι": "i",
}

# Suspicious TLDs commonly abused in low-cost automated phishing campaigns
SUSPICIOUS_TLDS = {
    "top", "xyz", "buzz", "fit", "tk", "ml", "cf", "gq", "ga", "online",
    "site", "vip", "icu", "work", "click", "live", "shop", "cfd", "sbs",
    "rest", "country", "quest", "cyou", "monster", "fun", "uno", "casa"
}

# Phishing and deceptive keywords in English and Azerbaijani
AZ_PHISHING_KEYWORDS = [
    "hesab", "odenis", "giris", "tehlukesizlik", "kart", "pul", "bonus",
    "kocurme", "xidmet", "kargo", "poct", "tesdiq", "blok", "qeydiyyat",
    "parol", "emekhaqqi", "yardim", "kompensasiya", "lotereya", "kampaniya",
    "odenish", "tehlukesiz"
]

EN_PHISHING_KEYWORDS = [
    "login", "secure", "verify", "account", "banking", "auth", "signin",
    "update", "wallet", "confirm", "portal", "security", "recovery", "billing",
    "support", "token", "session", "password", "validate", "credential", "auth-az",
    "verify-account", "login-secure"
]

# Curated seed whitelist: Major Azerbaijani brands and essential domains
AZ_SEED_WHITELIST: List[Dict[str, str]] = [
    {"domain": "google.com", "brand_name": "Google", "category": "Technology"},
    {"domain": "google.az", "brand_name": "Google", "category": "Technology"},
    # Banking & Fintech
    {"domain": "kapitalbank.az", "brand_name": "Kapital Bank", "category": "Banking"},
    {"domain": "birbank.az", "brand_name": "Birbank", "category": "Banking"},
    {"domain": "abb.az", "brand_name": "ABB - Azərbaycan Beynəlxalq Bankı", "category": "Banking"},
    {"domain": "ibar.az", "brand_name": "ABB / IBA", "category": "Banking"},
    {"domain": "pashabank.az", "brand_name": "PASHA Bank", "category": "Banking"},
    {"domain": "unibank.az", "brand_name": "Unibank", "category": "Banking"},
    {"domain": "rabitabank.az", "brand_name": "Rabitəbank", "category": "Banking"},
    {"domain": "bankofbaku.com", "brand_name": "Bank of Baku", "category": "Banking"},
    {"domain": "yapikredi.com.az", "brand_name": "Yapı Kredi Bank Azərbaycan", "category": "Banking"},
    {"domain": "expressbank.az", "brand_name": "Expressbank", "category": "Banking"},
    {"domain": "accessbank.az", "brand_name": "AccessBank", "category": "Banking"},
    {"domain": "azer-turkbank.az", "brand_name": "Azər-Türk Bank", "category": "Banking"},
    {"domain": "xalqbank.az", "brand_name": "Xalq Bank", "category": "Banking"},
    {"domain": "yelo.az", "brand_name": "Yelo Bank", "category": "Banking"},
    {"domain": "premiumbank.az", "brand_name": "Premium Bank", "category": "Banking"},
    {"domain": "turanbank.az", "brand_name": "TuranBank", "category": "Banking"},
    {"domain": "ziraatbank.az", "brand_name": "Ziraat Bank Azərbaycan", "category": "Banking"},
    {"domain": "mplus.az", "brand_name": "M10 by PashaPay", "category": "Fintech"},
    {"domain": "emanat.az", "brand_name": "eManat", "category": "Fintech"},
    {"domain": "million.az", "brand_name": "MilliÖN", "category": "Fintech"},
    # Postal, Logistics & Delivery
    {"domain": "azerpost.az", "brand_name": "Azərpoçt", "category": "Postal & Logistics"},
    {"domain": "166.az", "brand_name": "166 Yükdaşıma və Logistika", "category": "Postal & Logistics"},
    {"domain": "post.az", "brand_name": "Post.az", "category": "Postal & Logistics"},
    {"domain": "limak.az", "brand_name": "Limak Kuryer", "category": "Postal & Logistics"},
    {"domain": "camex.az", "brand_name": "Camex", "category": "Postal & Logistics"},
    {"domain": "mover.az", "brand_name": "Mover", "category": "Postal & Logistics"},
    {"domain": "starex.az", "brand_name": "Starex", "category": "Postal & Logistics"},
    # Government & Digital Identity
    {"domain": "login.gov.az", "brand_name": "Digital Login / ASAN İmza", "category": "Government"},
    {"domain": "digital.gov.az", "brand_name": "Rəqəmsal İnkişaf və Nəqliyyat Nazirliyi", "category": "Government"},
    {"domain": "mygov.az", "brand_name": "myGov Portalı", "category": "Government"},
    {"domain": "asan.gov.az", "brand_name": "ASAN Xidmət", "category": "Government"},
    {"domain": "e-gov.az", "brand_name": "Elektron Hökumət Portalı", "category": "Government"},
    {"domain": "e-taxes.gov.az", "brand_name": "Dövlət Vergi Xidməti", "category": "Government"},
    {"domain": "customs.gov.az", "brand_name": "Dövlət Gömrük Komitəsi", "category": "Government"},
    {"domain": "mia.gov.az", "brand_name": "Daxili İşlər Nazirliyi", "category": "Government"},
    {"domain": "justice.gov.az", "brand_name": "Ədliyyə Nazirliyi", "category": "Government"},
    {"domain": "sosial.gov.az", "brand_name": "Əmək və Əhalinin Sosial Müdafiəsi Nazirliyi", "category": "Government"},
    {"domain": "edu.gov.az", "brand_name": "Elm və Təhsil Nazirliyi", "category": "Government"},
    # Telecommunications & ISPs
    {"domain": "azercell.com", "brand_name": "Azercell", "category": "Telecommunications"},
    {"domain": "bakcell.com", "brand_name": "Bakcell", "category": "Telecommunications"},
    {"domain": "nar.az", "brand_name": "Nar", "category": "Telecommunications"},
    {"domain": "aztelekom.az", "brand_name": "Aztelekom", "category": "Telecommunications"},
    {"domain": "baktelecom.az", "brand_name": "Baktelecom", "category": "Telecommunications"},
    {"domain": "azernet.az", "brand_name": "Azernet", "category": "Telecommunications"},
    {"domain": "citynet.az", "brand_name": "CityNet", "category": "Telecommunications"},
    # Classifieds, Marketplaces & Portals
    {"domain": "tap.az", "brand_name": "Tap.az", "category": "Classifieds"},
    {"domain": "turbo.az", "brand_name": "Turbo.az", "category": "Classifieds"},
    {"domain": "bina.az", "brand_name": "Bina.az", "category": "Classifieds"},
    {"domain": "lalafo.az", "brand_name": "Lalafo", "category": "Classifieds"},
    {"domain": "umico.az", "brand_name": "Umico", "category": "E-Commerce"},
    {"domain": "baku.ws", "brand_name": "Baku.ws", "category": "Media"},
    {"domain": "oxu.az", "brand_name": "Oxu.az", "category": "Media"},
    {"domain": "apa.az", "brand_name": "APA", "category": "Media"},
    {"domain": "trend.az", "brand_name": "Trend", "category": "Media"},
    {"domain": "report.az", "brand_name": "Report", "category": "Media"},
]

# Known test phishing domains targeting Azerbaijani users
AZ_SEED_BLOCKED: List[Dict[str, str]] = [
    {"domain": "kap1talbank.az", "target_brand": "Kapital Bank", "source": "seed"},
    {"domain": "kapital-bank.az", "target_brand": "Kapital Bank", "source": "seed"},
    {"domain": "kapitall-bank.az", "target_brand": "Kapital Bank", "source": "seed"},
    {"domain": "kaptal-bank.az", "target_brand": "Kapital Bank", "source": "seed"},
    {"domain": "kapitalbank-login.az", "target_brand": "Kapital Bank", "source": "seed"},
    {"domain": "kapital-odenis.com", "target_brand": "Kapital Bank", "source": "seed"},
    {"domain": "kapitalbank-auth.top", "target_brand": "Kapital Bank", "source": "seed"},
    {"domain": "birbank-az.com", "target_brand": "Birbank", "source": "seed"},
    {"domain": "bir-bank.az", "target_brand": "Birbank", "source": "seed"},
    {"domain": "birbank-tehlukesizlik.top", "target_brand": "Birbank", "source": "seed"},
    {"domain": "birbank-odenis.xyz", "target_brand": "Birbank", "source": "seed"},
    {"domain": "b1rbank.az", "target_brand": "Birbank", "source": "seed"},
    {"domain": "azerpost-odeme.top", "target_brand": "Azərpoçt", "source": "seed"},
    {"domain": "azerpost-kargo.net", "target_brand": "Azərpoçt", "source": "seed"},
    {"domain": "azerpost-tracking.xyz", "target_brand": "Azərpoçt", "source": "seed"},
    {"domain": "azerpost-tesdiq.site", "target_brand": "Azərpoçt", "source": "seed"},
    {"domain": "166-kargo.xyz", "target_brand": "166 Yükdaşıma", "source": "seed"},
    {"domain": "166-odenis.online", "target_brand": "166 Yükdaşıma", "source": "seed"},
    {"domain": "166-dashinma.top", "target_brand": "166 Yükdaşıma", "source": "seed"},
    {"domain": "login-gov-az.com", "target_brand": "Digital Login / ASAN", "source": "seed"},
    {"domain": "digital-gov-az.net", "target_brand": "Digital Login / ASAN", "source": "seed"},
    {"domain": "asan-odenis.click", "target_brand": "ASAN Xidmət", "source": "seed"},
    {"domain": "tap-az.site", "target_brand": "Tap.az", "source": "seed"},
    {"domain": "turbo-az.top", "target_brand": "Turbo.az", "source": "seed"},
    {"domain": "abb-az.online", "target_brand": "ABB", "source": "seed"},
    {"domain": "azercell-bonus.xyz", "target_brand": "Azercell", "source": "seed"},
    {"domain": "bakcell-hesab.site", "target_brand": "Bakcell", "source": "seed"},
    {"domain": "azernet-auth.com", "target_brand": "Azernet", "source": "seed"},
]

# ------------------------------------------------------------------------------
# Database Layer
# ------------------------------------------------------------------------------

def get_db_connection() -> sqlite3.Connection:
    """Creates a new SQLite connection with optimal pragmas."""
    conn = sqlite3.connect(DATABASE_FILE, timeout=15.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn

def init_db():
    """Initializes tables and seeds initial datasets if empty."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Table: whitelist_domains
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS whitelist_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            brand_name TEXT NOT NULL,
            category TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # Table: blocked_domains
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            target_brand TEXT,
            source TEXT DEFAULT 'seed',
            confidence REAL DEFAULT 1.0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # Table: reported_urls
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reported_urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            domain TEXT NOT NULL,
            reason TEXT,
            category TEXT DEFAULT 'phishing',
            reported_by TEXT DEFAULT 'user',
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # Table: check_logs (audit log for detection metrics)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS check_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            domain TEXT NOT NULL,
            verdict TEXT NOT NULL,
            risk_score REAL NOT NULL,
            reasons TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # Indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_whitelist_domain ON whitelist_domains(domain);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocked_domain ON blocked_domains(domain);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_reported_domain ON reported_urls(domain);")

    # Seed Whitelist
    for item in AZ_SEED_WHITELIST:
        cursor.execute(
            """
            INSERT OR IGNORE INTO whitelist_domains (domain, brand_name, category)
            VALUES (?, ?, ?);
            """,
            (item["domain"].lower(), item["brand_name"], item["category"])
        )

    # Seed Blocklist
    for item in AZ_SEED_BLOCKED:
        cursor.execute(
            """
            INSERT OR IGNORE INTO blocked_domains (domain, target_brand, source, confidence)
            VALUES (?, ?, ?, ?);
            """,
            (item["domain"].lower(), item["target_brand"], item["source"], 1.0)
        )

    conn.commit()
    conn.close()

def db_dependency():
    """FastAPI dependency to yield database connection."""
    conn = get_db_connection()
    try:
        yield conn
    finally:
        conn.close()

# ------------------------------------------------------------------------------
# Algorithmic & Heuristic Detection Engine
# ------------------------------------------------------------------------------

def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """
    Computes Damerau-Levenshtein distance between two strings,
    supporting insertions, deletions, substitutions, and transpositions.
    """
    len1, len2 = len(s1), len(s2)
    d = [[0] * (len2 + 1) for _ in range(len1 + 1)]

    for i in range(len1 + 1):
        d[i][0] = i
    for j in range(len2 + 1):
        d[0][j] = j

    for i in range(1, len1 + 1):
        for j in range(1, len2 + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            d[i][j] = min(
                d[i - 1][j] + 1,       # deletion
                d[i][j - 1] + 1,       # insertion
                d[i - 1][j - 1] + cost  # substitution
            )
            # Transposition check
            if i > 1 and j > 1 and s1[i - 1] == s2[j - 2] and s1[i - 2] == s2[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + cost)

    return d[len1][len2]

def string_similarity_ratio(s1: str, s2: str) -> float:
    """Normalized similarity score between 0.0 and 1.0."""
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    dist = damerau_levenshtein_distance(s1, s2)
    return 1.0 - (dist / max_len)

def normalize_confusables(text: str) -> str:
    """Replaces homoglyphs, leetspeak characters, and confusables with base Latin characters."""
    result = []
    for char in text.lower():
        result.append(CONFUSABLES_MAP.get(char, char))
    return "".join(result)

def calculate_shannon_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string to detect randomly generated domains (DGA)."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def extract_domain_details(raw_url: str) -> Dict[str, Any]:
    """
    Parses a URL or domain string, extracting hostname, registered domain,
    subdomain, path, and port safely. Handles schemes, punycode, and IDNA.
    """
    url_cleaned = raw_url.strip()
    if not url_cleaned:
        raise ValueError("URL cannot be empty")

    # If scheme is missing, prepend http:// for proper urlsplit parsing
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url_cleaned):
        parse_target = "http://" + url_cleaned
    else:
        parse_target = url_cleaned

    parsed = urlsplit(parse_target)
    decoded_hostname = (parsed.hostname or "").removesuffix(".").lower()
    if parsed.scheme not in {"http", "https"} or not decoded_hostname:
        raise ValueError("Expected an HTTP(S) URL or hostname")

    # Convert Punycode to Unicode if applicable
    try:
        hostname = decoded_hostname.encode("idna").decode("ascii")
        decoded_hostname = hostname.encode("ascii").decode("idna")
        _ = parsed.port
    except UnicodeError as exc:
        raise ValueError("Invalid hostname") from exc

    # Check if host is an IP address
    is_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False
    if not is_ip and (len(hostname) > 253 or not re.fullmatch(
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
        hostname,
    )):
        raise ValueError("Invalid hostname")

    # Extract TLD and SLD (handles compound TLDs in Azerbaijan and globally)
    compound_tlds = {
        "gov.az", "com.az", "edu.az", "net.az", "org.az", "co.az", "mil.az",
        "biz.az", "info.az", "pp.az", "name.az", "co.uk", "com.tr", "gov.tr"
    }

    labels = hostname.split(".")
    tld = ""
    second_level = ""
    subdomains = []

    if len(labels) >= 2:
        two_part_tld = ".".join(labels[-2:])
        if two_part_tld in compound_tlds:
            tld = two_part_tld
            if len(labels) >= 3:
                second_level = labels[-3]
                subdomains = labels[:-3]
            else:
                second_level = labels[0]
        else:
            tld = labels[-1]
            second_level = labels[-2]
            subdomains = labels[:-2]
    elif len(labels) == 1:
        second_level = labels[0]

    registered_domain = hostname if is_ip else (f"{second_level}.{tld}" if tld else second_level)

    return {
        "original_url": raw_url,
        "clean_url": url_cleaned,
        "hostname": hostname,
        "decoded_hostname": decoded_hostname,
        "registered_domain": registered_domain,
        "second_level_domain": second_level,
        "tld": tld,
        "subdomain": ".".join(subdomains),
        "path": parsed.path,
        "query": parsed.query,
        "is_ip": is_ip,
    }

class PhishingDetector:
    """Smart heuristic and rule-based phishing detection engine for Azerbaijan."""

    def __init__(self, db: sqlite3.Connection):
        self.db = db
        self._load_cache()

    def _load_cache(self):
        """Loads whitelist and target brands into memory for rapid matching."""
        cursor = self.db.cursor()
        cursor.execute("SELECT domain, brand_name, category FROM whitelist_domains")
        self.whitelist_rows = cursor.fetchall()

        self.whitelist_domains = {row["domain"]: row for row in self.whitelist_rows}

        # Build target brand profiles for typosquatting checks
        self.target_brands = []
        for row in self.whitelist_rows:
            domain = row["domain"]
            sld = domain.split(".")[0]
            brand_variants = {sld}
            if "-" in sld:
                brand_variants.add(sld.replace("-", ""))
            if "bank" in sld and sld != "bank":
                brand_variants.add(sld.replace("bank", ""))

            self.target_brands.append({
                "brand_name": row["brand_name"],
                "canonical_domain": domain,
                "sld": sld,
                "variants": brand_variants,
                "category": row["category"]
            })

        # Sort brands by SLD length descending so specific brands (e.g. 'kapitalbank', 'birbank')
        # take matching precedence over shorter generic words (e.g. 'login', 'abb', '166')
        self.target_brands.sort(key=lambda item: len(item["sld"]), reverse=True)

    def is_explicitly_blocked(self, hostname: str, registered_domain: str) -> Optional[Dict[str, Any]]:
        """Checks if the domain is directly listed in the blocked table."""
        cursor = self.db.cursor()
        cursor.execute(
            """
            SELECT domain, target_brand, source, confidence
            FROM blocked_domains
            WHERE (domain = ? OR domain = ?) AND source IN ('seed', 'verified')
            LIMIT 1;
            """,
            (hostname, registered_domain)
        )
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None

    def is_explicitly_whitelisted(self, hostname: str, registered_domain: str) -> Optional[Dict[str, Any]]:
        """Checks if hostname is an exact whitelisted domain or legitimate subdomain."""
        # Compare complete DNS labels, including allowlisted nested roots.
        for root, row in self.whitelist_domains.items():
            if hostname == root or hostname.endswith("." + root):
                return dict(row)
        return None

    def evaluate(self, raw_url: str) -> Dict[str, Any]:
        """
        Main inspection routine combining database queries and smart heuristics.
        Returns detailed evaluation dictionary.
        """
        extracted = extract_domain_details(raw_url)
        hostname = extracted["hostname"]
        registered_domain = extracted["registered_domain"]
        sld = extracted["second_level_domain"]
        subdomain = extracted["subdomain"]
        tld = extracted["tld"]
        path = extracted["path"].lower()

        reasons: List[str] = []
        risk_score = 0.0
        matched_target: Optional[str] = None
        details: Dict[str, Any] = {
            "hostname": hostname,
            "registered_domain": registered_domain,
            "tld": tld,
            "subdomain": subdomain,
            "is_ip": extracted["is_ip"],
            "entropy": round(calculate_shannon_entropy(sld), 3),
            "hyphen_count": hostname.count("-"),
            "heuristic_flags": [],
        }

        # -------------------------------------------------------------
        # STEP 1: Direct Blocklist Match
        # -------------------------------------------------------------
        blocked_info = self.is_explicitly_blocked(hostname, registered_domain)
        if blocked_info:
            target = blocked_info.get("target_brand") or "General Azerbaijani target"
            return {
                "url": raw_url,
                "domain": hostname,
                "status": "blocked",
                "risk_score": 1.0,
                "confidence": 1.0,
                "reasons": [
                    f"Domain is listed in verified blocklist (Source: {blocked_info.get('source', 'threat_intel')}, Target: {target})"
                ],
                "matched_target": target,
                "is_whitelisted": False,
                "is_blocked": True,
                "details": details,
            }

        # -------------------------------------------------------------
        # STEP 2: Direct Whitelist Match
        # -------------------------------------------------------------
        whitelisted_info = self.is_explicitly_whitelisted(hostname, registered_domain)
        if whitelisted_info:
            return {
                "url": raw_url,
                "domain": hostname,
                "status": "safe",
                "risk_score": 0.0,
                "confidence": 1.0,
                "reasons": [
                    f"Verified authentic domain for {whitelisted_info['brand_name']} ({whitelisted_info['category']})"
                ],
                "matched_target": whitelisted_info["brand_name"],
                "is_whitelisted": True,
                "is_blocked": False,
                "details": details,
            }

        # -------------------------------------------------------------
        # STEP 3: Subdomain Spoofing Check
        # (e.g. 'kapitalbank.az.malicious.com' or 'birbank.login-secure.org')
        # -------------------------------------------------------------
        for target in self.target_brands:
            canonical = target["canonical_domain"]
            target_sld = target["sld"]

            if canonical in subdomain or f".{canonical}" in hostname:
                risk_score += 0.85
                matched_target = target["brand_name"]
                reasons.append(
                    f"Subdomain spoofing detected: Attempting to impersonate '{canonical}' on rogue root domain '{registered_domain}'"
                )
                details["heuristic_flags"].append("subdomain_spoofing")
                break
            elif target_sld in subdomain.split("."):
                risk_score += 0.75
                matched_target = target["brand_name"]
                reasons.append(
                    f"Subdomain brand impersonation detected: Brand '{target['brand_name']}' placed in subdomain"
                )
                details["heuristic_flags"].append("subdomain_brand_injection")
                break

        # -------------------------------------------------------------
        # STEP 4: Typosquatting, Lookalikes & Combosquatting Checks
        # (Replacing 'i' with '1'/'l', extra hyphens like 'kaptal-bank.az' or 'kapitall-bank.az')
        # -------------------------------------------------------------
        if sld.startswith("xn--"):
            sld = sld.encode("ascii").decode("idna")
        normalized_sld = normalize_confusables(sld)
        sld_no_hyphens = sld.replace("-", "")
        normalized_sld_no_hyphens = normalized_sld.replace("-", "")

        for target in self.target_brands:
            target_sld = target["sld"]
            target_brand_name = target["brand_name"]
            canonical_domain = target["canonical_domain"]

            # Don't compare target with itself if canonical
            if registered_domain == canonical_domain:
                continue

            # 4a. Homoglyph / Confusable replacement match
            # E.g. 'kap1talbank' -> normalized to 'kapitalbank'
            if (normalized_sld == target_sld or normalized_sld_no_hyphens == target_sld) and sld != target_sld:
                risk_score += 0.85
                matched_target = target_brand_name
                reasons.append(
                    f"Lookalike / Homoglyph typosquatting detected targeting '{target_brand_name}' (confusable replacement like '1' for 'i' or '0' for 'o')"
                )
                details["heuristic_flags"].append("homoglyph_typosquatting")
                break

            # 4b. Hyphen insertion & Combosquatting
            # E.g. 'kapital-bank.az', 'kapitall-bank.az', 'bir-bank.az', 'kapital-bank-security.az'
            if "-" in sld:
                if sld_no_hyphens == target_sld or normalized_sld_no_hyphens == target_sld:
                    risk_score += 0.80
                    matched_target = target_brand_name
                    reasons.append(
                        f"Hyphenated combosquatting detected targeting '{target_brand_name}' ({sld} mimics {canonical_domain})"
                    )
                    details["heuristic_flags"].append("hyphen_combosquatting")
                    break

                dist_no_hyphen = damerau_levenshtein_distance(sld_no_hyphens, target_sld)
                if dist_no_hyphen == 1 and len(target_sld) >= 5:
                    risk_score += 0.80
                    matched_target = target_brand_name
                    reasons.append(
                        f"Suspicious hyphenated typosquatting variant targeting '{target_brand_name}' (e.g., added/deleted letter with dashes)"
                    )
                    details["heuristic_flags"].append("hyphen_typosquatting_variant")
                    break

                # Check if target_sld is embedded within hyphenated domain
                # e.g., 'kapital-bank-security' -> sld_no_hyphens: 'kapitalbanksecurity'
                if len(target_sld) >= 4 and (target_sld in sld_no_hyphens or target_sld in normalized_sld_no_hyphens):
                    risk_score += 0.75
                    matched_target = target_brand_name
                    reasons.append(
                        f"Targeted brand combosquatting detected: Brand '{target_brand_name}' embedded with security/action keywords"
                    )
                    details["heuristic_flags"].append("brand_hyphen_combosquatting")
                    break

            # 4c. Damerau-Levenshtein edit distance on SLD
            # Catches: 1 deletion ('kaptalbank'), 1 insertion ('kapitallbank'),
            # 1 swap ('kaptialbank'), 1 substitution ('kapitolbank')
            if len(target_sld) >= 4:
                dist = damerau_levenshtein_distance(sld, target_sld)
                dist_norm = damerau_levenshtein_distance(normalized_sld, target_sld)
                min_dist = min(dist, dist_norm)
                sim = string_similarity_ratio(sld, target_sld)

                if min_dist == 1:
                    risk_score += 0.75
                    matched_target = target_brand_name
                    reasons.append(
                        f"Direct typosquatting detected: Single-character edit distance to Azerbaijani brand '{target_brand_name}' ({target_sld})"
                    )
                    details["heuristic_flags"].append("edit_distance_1")
                    break
                elif min_dist == 2 and len(target_sld) >= 8 and sim >= 0.80:
                    risk_score += 0.65
                    matched_target = target_brand_name
                    reasons.append(
                        f"Close lookalike typosquatting detected: High similarity ({sim:.0%}) to '{target_brand_name}'"
                    )
                    details["heuristic_flags"].append("edit_distance_2")
                    break

            # 4d. Brand Keyword Embedding / Combosquatting
            # E.g. 'kapitalbank-online.com', 'birbank-az.com', 'azerpost-kargo.net', 'b1rbank-login.az'
            if len(target_sld) >= 4:
                if target_sld in sld or target_sld in normalized_sld or target_sld in normalized_sld_no_hyphens:
                    risk_score += 0.70
                    matched_target = target_brand_name
                    reasons.append(
                        f"Brand name combosquatting detected: Brand '{target_brand_name}' found embedded within unauthorized domain '{registered_domain}'"
                    )
                    details["heuristic_flags"].append("brand_embedding")
                    break
            else:
                # For short brands (e.g. '166', 'abb', 'nar', 'tap')
                # Require hyphen separator or word boundary to prevent false positives
                pattern = rf"(^|-){re.escape(target_sld)}(-|$)"
                if re.search(pattern, sld) or re.search(pattern, normalized_sld):
                    risk_score += 0.70
                    matched_target = target_brand_name
                    reasons.append(
                        f"Short brand identity combosquatting detected targeting '{target_brand_name}'"
                    )
                    details["heuristic_flags"].append("short_brand_combosquatting")
                    break

        # -------------------------------------------------------------
        # STEP 5: Domain Characteristics & Smart Heuristics
        # -------------------------------------------------------------
        # 5a. Host is raw IP address
        if extracted["is_ip"]:
            risk_score += 0.45
            reasons.append("URL uses raw numerical IP address instead of a reputable domain name")
            details["heuristic_flags"].append("raw_ip_host")

        # 5b. Suspicious / High-abuse TLDs
        if tld in SUSPICIOUS_TLDS:
            risk_score += 0.25
            reasons.append(f"Domain uses high-risk, low-reputation top-level domain (.{tld})")
            details["heuristic_flags"].append(f"suspicious_tld_{tld}")

        # 5c. Excessive hyphens in domain
        hyphen_count = hostname.count("-")
        if hyphen_count >= 3:
            risk_score += 0.30
            reasons.append(f"Excessive hyphens in hostname ({hyphen_count} hyphens detected), typical of phishing disguises")
            details["heuristic_flags"].append("excessive_hyphens")
        elif hyphen_count == 2:
            risk_score += 0.15
            reasons.append("Multiple hyphens present in domain structure")
            details["heuristic_flags"].append("multiple_hyphens")

        # 5d. Excessive domain / hostname length
        if len(hostname) > 35:
            risk_score += 0.25
            reasons.append(f"Unusually long hostname ({len(hostname)} characters), often used to push deceptive subdomains")
            details["heuristic_flags"].append("excessive_length")

        # 5e. Excessive subdomain nesting (dots count)
        subdomain_depth = len(subdomain.split(".")) if subdomain else 0
        if subdomain_depth >= 3:
            risk_score += 0.20
            reasons.append(f"Excessive subdomain depth ({subdomain_depth} levels)")
            details["heuristic_flags"].append("deep_subdomains")

        # 5f. Azerbaijani & English Phishing Keywords in Hostname or Path
        found_keywords = set()
        all_text_to_scan = f"{hostname} {path}".lower()

        for kw in AZ_PHISHING_KEYWORDS:
            if kw in all_text_to_scan:
                found_keywords.add(kw)

        for kw in EN_PHISHING_KEYWORDS:
            if kw in all_text_to_scan:
                found_keywords.add(kw)

        if found_keywords:
            kw_sample = list(found_keywords)[:4]
            domain_has_kw = any(kw in hostname for kw in found_keywords)
            weight = 0.35 if domain_has_kw else 0.20
            risk_score += weight
            reasons.append(
                f"Suspicious security/banking keywords identified: {', '.join(kw_sample)}"
            )
            details["heuristic_flags"].append("phishing_keywords_found")
            details["detected_keywords"] = list(found_keywords)

        # 5g. High Shannon Entropy (Random DGA domain detection)
        entropy = calculate_shannon_entropy(sld)
        if entropy > 3.7 and len(sld) >= 10:
            risk_score += 0.25
            reasons.append(f"High character entropy ({entropy:.2f}), suggesting machine-generated or randomized domain")
            details["heuristic_flags"].append("high_entropy_domain")

        # -------------------------------------------------------------
        # STEP 6: Final Verdict & Risk Score Normalization
        # -------------------------------------------------------------
        risk_score = min(max(risk_score, 0.0), 1.0)
        confidence = 0.90 if reasons else 0.95

        # Decision Threshold
        if risk_score >= 0.40:
            status_verdict = "suspicious"
        else:
            status_verdict = "safe"
            if not reasons:
                reasons.append("No phishing patterns, brand lookalikes, or suspicious heuristics detected")

        return {
            "url": raw_url,
            "domain": hostname,
            "status": status_verdict,
            "risk_score": round(risk_score, 2),
            "confidence": round(confidence, 2),
            "reasons": reasons,
            "matched_target": matched_target,
            "is_whitelisted": False,
            "is_blocked": False,
            "details": details,
        }

# ------------------------------------------------------------------------------
# Pydantic Schemas
# ------------------------------------------------------------------------------

class CheckURLRequest(BaseModel):
    url: str = Field(
        ...,
        description="The URL or domain to inspect for phishing / lookalikes",
        json_schema_extra={"example": "https://kap1talbank.az/auth/login"}
    )

class CheckURLResponse(BaseModel):
    url: str
    domain: str
    status: str = Field(..., description="Verdict: 'safe', 'suspicious', or 'blocked'")
    risk_score: float = Field(..., description="Risk score from 0.0 (safe) to 1.0 (malicious)")
    confidence: float = Field(..., description="Confidence level of detection")
    reasons: List[str] = Field(..., description="List of reasons and heuristics triggered")
    matched_target: Optional[str] = Field(None, description="Azerbaijani brand targeted if identified")
    is_whitelisted: bool
    is_blocked: bool
    details: Dict[str, Any]
    scan_timestamp: str

class ReportURLRequest(BaseModel):
    url: str = Field(
        ...,
        description="The suspicious or phishing URL to report",
        json_schema_extra={"example": "https://kapital-odenis.site/pay"}
    )
    reason: Optional[str] = Field(
        None,
        description="Reason or user comments on why this link is phishing",
        json_schema_extra={"example": "Received via fake SMS impersonating bank"}
    )
    category: Optional[str] = Field("phishing", description="Threat category: phishing, scam, malware, impersonation")
    reported_by: Optional[str] = Field("extension_user", description="Identifier of reporting client or user")

class ReportURLResponse(BaseModel):
    status: str
    message: str
    report_id: int
    reported_url: str
    domain: str
    auto_blocked: bool
    reported_at: str

class WhitelistItem(BaseModel):
    domain: str
    brand_name: str
    category: str

class StatsResponse(BaseModel):
    total_whitelisted_domains: int
    total_blocked_domains: int
    total_reports_received: int
    total_scans_recorded: int
    system_status: str

# ------------------------------------------------------------------------------
# FastAPI Application & Lifespan
# ------------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager to initialize the SQLite database on startup."""
    init_db()
    yield

app = FastAPI(
    title="Azerbaijan Anti-Phishing Protection API",
    description=(
        "Production-ready backend API for real-time phishing detection, brand impersonation defense, "
        "and threat intelligence tailored for Azerbaijani financial institutions, government portals, "
        "and logistics services."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ------------------------------------------------------------------------------
# Localhost API. The extension uses its loopback host permission for fetch.
# ------------------------------------------------------------------------------
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1"],
)

# ------------------------------------------------------------------------------
# API Endpoints
# ------------------------------------------------------------------------------

@app.get("/", tags=["General"])
def root_endpoint():
    """Root metadata endpoint."""
    return {
        "service": "Azerbaijan Anti-Phishing Protection Backend",
        "version": "1.0.0",
        "documentation": "/docs",
        "status": "online",
        "local_time": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

@app.get("/api/v1/health", tags=["Health"])
def health_check(db: sqlite3.Connection = Depends(db_dependency)):
    """Health check verifying database connectivity."""
    try:
        cursor = db.cursor()
        cursor.execute("SELECT 1;")
        return {
            "status": "healthy",
            "database": "connected",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database health check failed: {str(e)}"
        )

# ------------------------------------------------------------------------------
# Requirement 3 & 4: POST /api/v1/check-url
# ------------------------------------------------------------------------------
@app.post(
    "/api/v1/check-url",
    response_model=CheckURLResponse,
    status_code=status.HTTP_200_OK,
    tags=["Phishing Detection"],
    summary="Check URL for Phishing, Lookalikes and Typosquatting"
)
def check_url(
    payload: CheckURLRequest,
    db: sqlite3.Connection = Depends(db_dependency)
):
    """
    Evaluates a URL or domain string against:
    1. Verified Blocklist (returns 'blocked').
    2. Verified Whitelist of legitimate Azerbaijani domains (returns 'safe').
    3. Typosquatting & Lookalike algorithms targeting Azerbaijani brands:
       - Confusable / Homoglyph mapping (e.g. '1' for 'i', '0' for 'o', Cyrillic lookalikes)
       - Extra dashes (e.g. 'kaptal-bank.az', 'kapitall-bank.az')
       - Damerau-Levenshtein edit distance (single/double character insertions/deletions/swaps)
       - Subdomain spoofing (e.g. 'kapitalbank.az.scam-site.com')
       - Combosquatting (brand embedded with keywords like 'birbank-az.com')
    4. Domain heuristics: IP hosts, suspicious TLDs, excessive hyphens/length,
       and Azerbaijani/English phishing keywords (returns 'suspicious' or 'safe').
    """
    raw_url = payload.url.strip()
    if not raw_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL field cannot be empty"
        )

    try:
        detector = PhishingDetector(db)
        eval_result = detector.evaluate(raw_url)

        # Audit log into check_logs
        try:
            cursor = db.cursor()
            cursor.execute(
                """
                INSERT INTO check_logs (url, domain, verdict, risk_score, reasons)
                VALUES (?, ?, ?, ?, ?);
                """,
                (
                    eval_result["domain"],
                    eval_result["domain"],
                    eval_result["status"],
                    eval_result["risk_score"],
                    "; ".join(eval_result["reasons"])
                )
            )
            db.commit()
        except Exception:
            pass

        return CheckURLResponse(
            url=eval_result["url"],
            domain=eval_result["domain"],
            status=eval_result["status"],
            risk_score=eval_result["risk_score"],
            confidence=eval_result["confidence"],
            reasons=eval_result["reasons"],
            matched_target=eval_result["matched_target"],
            is_whitelisted=eval_result["is_whitelisted"],
            is_blocked=eval_result["is_blocked"],
            details=eval_result["details"],
            scan_timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat()
        )

    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error evaluating URL"
        )

# ------------------------------------------------------------------------------
# Requirement 5: POST /api/v1/report
# ------------------------------------------------------------------------------
@app.post(
    "/api/v1/report",
    response_model=ReportURLResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Reporting"],
    summary="Report Phishing Link from Users or Browser Extension"
)
def report_phishing_link(
    payload: ReportURLRequest,
    db: sqlite3.Connection = Depends(db_dependency),
    x_phishguard_client: str = Header(default=""),
):
    """
    Submits a user or browser extension report for a suspicious URL.
    - Extracts the domain from the URL.
    - Saves the hostname as a pending report for review.
    """
    # This non-safelisted header forces a browser preflight for ordinary
    # cross-origin pages. Extension fetch uses its explicit host permission.
    if x_phishguard_client != "extension-v1":
        raise HTTPException(status_code=403, detail="Expected a FishGuard report")
    raw_url = payload.url.strip()
    if not raw_url:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="URL cannot be empty")

    try:
        extracted = extract_domain_details(raw_url)
        domain_to_block = extracted["hostname"]

        cursor = db.cursor()

        # Insert report into reported_urls
        cursor.execute(
            """
            INSERT INTO reported_urls (url, domain, reason, category, reported_by, status)
            VALUES (?, ?, ?, ?, ?, 'pending');
            """,
            (
                domain_to_block,
                domain_to_block,
                payload.reason or "Reported via browser extension",
                payload.category or "phishing",
                payload.reported_by or "user"
            )
        )
        report_id = cursor.lastrowid

        db.commit()

        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        return ReportURLResponse(
            status="success",
            message="Domain report recorded for review.",
            report_id=report_id,
            reported_url=domain_to_block,
            domain=domain_to_block,
            auto_blocked=False,
            reported_at=now_str
        )

    except ValueError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid HTTP(S) address")
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to submit phishing report"
        )

# ------------------------------------------------------------------------------
# Ancillary Management & Intelligence Endpoints
# ------------------------------------------------------------------------------

@app.get("/api/v1/stats", response_model=StatsResponse, tags=["Threat Intelligence"])
def get_system_stats(db: sqlite3.Connection = Depends(db_dependency)):
    """Provides real-time statistics on protection coverage."""
    cursor = db.cursor()
    cursor.execute("SELECT COUNT(*) FROM whitelist_domains;")
    whitelisted_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM blocked_domains WHERE source IN ('seed', 'verified');")
    blocked_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM reported_urls;")
    reports_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM check_logs;")
    scans_count = cursor.fetchone()[0]

    return StatsResponse(
        total_whitelisted_domains=whitelisted_count,
        total_blocked_domains=blocked_count,
        total_reports_received=reports_count,
        total_scans_recorded=scans_count,
        system_status="operational"
    )

@app.get("/api/v1/whitelist", tags=["Threat Intelligence"])
def list_whitelist(
    search: Optional[str] = Query(None, description="Search term for domain or brand"),
    db: sqlite3.Connection = Depends(db_dependency)
):
    """Lists trusted whitelisted domains with optional query filter."""
    cursor = db.cursor()
    if search:
        pattern = f"%{search.strip().lower()}%"
        cursor.execute(
            """
            SELECT domain, brand_name, category, created_at
            FROM whitelist_domains
            WHERE domain LIKE ? OR brand_name LIKE ?
            ORDER BY domain ASC;
            """,
            (pattern, pattern)
        )
    else:
        cursor.execute(
            """
            SELECT domain, brand_name, category, created_at
            FROM whitelist_domains
            ORDER BY category ASC, domain ASC;
            """
        )
    rows = cursor.fetchall()
    return {"count": len(rows), "whitelist": [dict(r) for r in rows]}

@app.get("/api/v1/blocked", tags=["Threat Intelligence"])
def list_blocked_domains(
    limit: int = Query(50, ge=1, le=500),
    db: sqlite3.Connection = Depends(db_dependency)
):
    """Lists actively blocked phishing domains."""
    cursor = db.cursor()
    cursor.execute(
        """
        SELECT id, domain, target_brand, source, confidence, created_at
        FROM blocked_domains
        WHERE source IN ('seed', 'verified')
        ORDER BY id DESC
        LIMIT ?;
        """,
        (limit,)
    )
    rows = cursor.fetchall()
    return {"count": len(rows), "blocked_domains": [dict(r) for r in rows]}


@app.get("/api/v1/threat-feed", tags=["Threat Intelligence"])
def threat_feed(db: sqlite3.Connection = Depends(db_dependency)):
    """Publish a bounded snapshot of individually verified domain-wide blocks."""
    rows = db.execute(
        "SELECT domain FROM blocked_domains WHERE source = 'verified' ORDER BY domain LIMIT 2001"
    ).fetchall()
    if len(rows) > 2000:
        raise HTTPException(status_code=503, detail="Verified feed exceeds its configured capacity")
    return {"domains": [row["domain"] for row in rows]}


# ------------------------------------------------------------------------------
# Direct Execution Support
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    init_db()
    print("Anti-Phishing Protection Server running at http://127.0.0.1:8000")
    print("Interactive OpenAPI Documentation available at http://127.0.0.1:8000/docs")
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
