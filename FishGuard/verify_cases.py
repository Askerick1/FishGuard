import json
from main import init_db, get_db_connection, PhishingDetector

def run_verification():
    init_db()
    conn = get_db_connection()
    detector = PhishingDetector(conn)

    test_cases = [
        # Authentic Azerbaijani targets -> must be safe
        ("https://kapitalbank.az", "safe"),
        ("https://birbank.az/pay", "safe"),
        ("https://online.birbank.az", "safe"),
        ("https://azerpost.az", "safe"),
        ("https://166.az", "safe"),
        ("https://azernet.az", "safe"),
        ("https://login.gov.az", "safe"),
        # Known test phishing domains -> must be blocked
        ("https://kap1talbank.az", "blocked"),
        ("https://kaptal-bank.az/login", "blocked"),
        ("https://kapitall-bank.az", "blocked"),
        ("https://azerpost-odeme.top", "blocked"),
        ("https://166-kargo.xyz", "blocked"),
        # Algorithmic Typosquatting / Combosquatting / Lookalikes -> suspicious
        ("https://kapitalbank.az.scam-service.com/login", "suspicious"),
        ("https://birbank-az.com", "blocked"),
        ("https://bir-bank.az", "blocked"),
        ("https://birbank-az-login.net", "suspicious"),
        ("https://166-dashinma.top", "blocked"),
        # Heuristic checks (Suspicious keywords + Suspicious TLD) -> suspicious
        ("https://auth-az-login-secure.xyz", "suspicious"),
        ("http://192.168.1.50/kapitalbank", "suspicious"),
        # Generic legitimate external domain -> safe
        ("https://google.com", "safe"),
    ]

    print("\n" + "=" * 95)
    print(f"{'URL':<45} | {'EXPECTED':<11} | {'ACTUAL':<11} | {'RISK':<5} | {'MATCHED BRAND'}")
    print("=" * 95)

    all_passed = True
    for url, expected in test_cases:
        res = detector.evaluate(url)
        actual = res["status"]
        passed = (actual == expected)
        if not passed:
            all_passed = False
        symbol = "✓" if passed else "✗"
        print(f"{symbol} {url:<43} | {expected:<11} | {actual:<11} | {res['risk_score']:<5} | {res['matched_target']}")

    print("=" * 95)
    print(f"Verification Result: {'ALL TEST CASES PASSED!' if all_passed else 'SOME FAILED!'}\n")
    return all_passed

if __name__ == "__main__":
    success = run_verification()
    exit(0 if success else 1)

