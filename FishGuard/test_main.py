import pytest
from fastapi.testclient import TestClient

import main

client = TestClient(main.app, base_url="http://127.0.0.1")

@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DATABASE_FILE", str(tmp_path / "phishguard.db"))
    main.init_db()

def test_health_check():
    """Verify health endpoint."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert response.json()["database"] == "connected"

def test_root_endpoint():
    """Verify root documentation link and service status."""
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "online"

def test_seeding_presence():
    """Verify initial seed data for whitelist and blocklist."""
    stats = client.get("/api/v1/stats").json()
    assert stats["total_whitelisted_domains"] >= 40
    assert stats["total_blocked_domains"] >= 20

    # Whitelist inspection
    wl = client.get("/api/v1/whitelist").json()
    domains = [d["domain"] for d in wl["whitelist"]]
    assert "kapitalbank.az" in domains
    assert "birbank.az" in domains
    assert "azerpost.az" in domains
    assert "166.az" in domains
    assert "login.gov.az" in domains

def test_check_whitelisted_domain_safe():
    """Authentic Azerbaijani brand domains must return status 'safe' with 0 risk."""
    test_urls = [
        "https://kapitalbank.az",
        "https://www.kapitalbank.az/en/cards",
        "https://birbank.az",
        "https://online.birbank.az/login",
        "https://azerpost.az",
        "https://166.az/services",
        "https://login.gov.az",
    ]
    for url in test_urls:
        response = client.post("/api/v1/check-url", json={"url": url})
        assert response.status_code == 200, f"Failed for {url}"
        data = response.json()
        assert data["status"] == "safe", f"Expected safe for {url}, got {data['status']}"
        assert data["risk_score"] == 0.0
        assert data["is_whitelisted"] is True
        assert data["is_blocked"] is False

def test_check_explicitly_blocked_domain():
    """Explicitly seeded phishing domains must return status 'blocked'."""
    blocked_test_urls = [
        "https://kap1talbank.az",
        "http://kapital-bank.az/login",
        "https://birbank-az.com/verify",
        "https://azerpost-odeme.top/pay",
        "https://166-kargo.xyz",
        "https://login-gov-az.com",
    ]
    for url in blocked_test_urls:
        response = client.post("/api/v1/check-url", json={"url": url})
        assert response.status_code == 200, f"Failed for {url}"
        data = response.json()
        assert data["status"] == "blocked", f"Expected blocked for {url}, got {data['status']}"
        assert data["risk_score"] == 1.0
        assert data["is_blocked"] is True

def test_check_typosquatting_homoglyph_replacement():
    """Check replacing 'i' with '1' or 'l' or Cyrillic homoglyphs and extra dashes."""
    urls = [
        "https://kaptal-bank.az",               # extra dash + deletion
        "https://kapitall-bank.az",             # extra dash + insertion
        "https://bir-bank.az",                  # extra dash
        "https://kapital-bank-security.az",     # brand with extra dash
        "https://b1rbank-login.az",             # leetspeak '1' + keyword
    ]
    for url in urls:
        response = client.post("/api/v1/check-url", json={"url": url})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ["suspicious", "blocked"], f"Expected suspicious/blocked for {url}, got {data['status']}"
        assert data["risk_score"] >= 0.40
        assert data["matched_target"] is not None

def test_check_subdomain_spoofing():
    """Check target brand used in subdomain on rogue domain."""
    url = "https://kapitalbank.az.attacker-domain.com/secure-login"
    response = client.post("/api/v1/check-url", json={"url": url})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["suspicious", "blocked"]
    assert data["risk_score"] >= 0.70
    assert any("subdomain" in r.lower() for r in data["reasons"])

def test_check_suspicious_heuristics_keywords_and_tld():
    """Check domain with suspicious keywords and high-risk TLD."""
    url = "https://verify-account-auth-az.top/login-secure"
    response = client.post("/api/v1/check-url", json={"url": url})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "suspicious"
    assert data["risk_score"] >= 0.40
    assert any("keyword" in r.lower() or "tld" in r.lower() for r in data["reasons"])

def test_check_raw_ip_address():
    """Check URL using numerical IP address."""
    url = "http://185.220.101.5/kapitalbank"
    response = client.post("/api/v1/check-url", json={"url": url})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "suspicious"
    assert data["details"]["is_ip"] is True

def test_check_safe_generic_domain():
    """Unrelated reputable sites without brand spoofing should be safe."""
    url = "https://python.org/downloads"
    response = client.post("/api/v1/check-url", json={"url": url})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "safe"
    assert data["risk_score"] < 0.40

def test_report_is_pending_and_stores_only_hostname():
    new_phishing_url = "https://new-fake-azerpost-scam.xyz/tracking/payment?token=private#fragment"
    report_payload = {
        "url": new_phishing_url,
        "reason": "Fake SMS phishing claim for undelivered package",
        "category": "phishing",
        "reported_by": "chrome_extension_agent"
    }

    # 1. Submit report
    rep_response = client.post("/api/v1/report", json=report_payload,
                               headers={"X-PhishGuard-Client": "extension-v1"})
    assert rep_response.status_code == 201
    rep_data = rep_response.json()
    assert rep_data["status"] == "success"
    assert rep_data["auto_blocked"] is False
    assert rep_data["domain"] == "new-fake-azerpost-scam.xyz"
    assert rep_data["reported_url"] == rep_data["domain"]
    assert rep_data["report_id"] > 0

    check_response = client.post("/api/v1/check-url", json={"url": new_phishing_url})
    assert check_response.status_code == 200
    assert check_response.json()["is_blocked"] is False
    assert client.get("/api/v1/threat-feed").json()["domains"] == []
    db = main.get_db_connection()
    try:
        assert tuple(db.execute("SELECT url, status FROM reported_urls").fetchone()) == (
            rep_data["domain"], "pending",
        )
        assert db.execute("SELECT url FROM check_logs").fetchone()["url"] == rep_data["domain"]
        db.executemany("INSERT INTO blocked_domains (domain, source) VALUES (?, ?)", [
            ("legacy.example", "user_report"), ("verified.example", "verified"),
        ])
        db.commit()
    finally:
        db.close()
    assert client.get("/api/v1/threat-feed").json()["domains"] == ["verified.example"]
    assert client.post("/api/v1/check-url", json={"url": "https://legacy.example"}).json()["is_blocked"] is False

def test_google_hostname_boundary():
    for host in ("google.com", "accounts.google.com", "docs.google.com", "www.google.com."):
        response = client.post("/api/v1/check-url", json={"url": f"https://{host}/login"})
        assert response.json()["is_whitelisted"] is True
    response = client.post("/api/v1/check-url", json={
        "url": "https://google.com.security-check.xyz/verify",
    })
    assert response.json()["is_whitelisted"] is False
    assert response.json()["status"] in {"blocked", "suspicious"}

def test_untrusted_web_origin_and_host():
    response = client.options(
        "/api/v1/report",
        headers={
            "Origin": "https://untrusted.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type"
        }
    )
    assert response.status_code == 405
    assert "access-control-allow-origin" not in response.headers
    assert client.post("/api/v1/report", json={"url": "https://example.test"}).status_code == 403
    assert client.get("/api/v1/threat-feed", headers={"Host": "untrusted.example"}).status_code == 400
