import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phishguard.detector import PhishGuard  # noqa: E402
from phishguard.url_features import extract_features, find_urls, FEATURE_NAMES  # noqa: E402


@pytest.fixture(scope="module")
def guard():
    return PhishGuard()


def test_feature_vector_length():
    assert len(extract_features("https://www.google.com/search?q=x")) == len(FEATURE_NAMES)


def test_find_urls():
    urls = find_urls("Visit http://a.xyz/login now and also www.example.com/page.")
    assert "http://a.xyz/login" in urls
    assert "www.example.com/page" in urls


def test_phishing_sms(guard):
    r = guard.analyze("URGENT: Your SBI account has been suspended. Verify now at http://sbi-kyc-update.xyz/login")
    assert r["verdict"] == "PHISHING"


def test_ip_url(guard):
    r = guard.analyze("http://192.168.4.23/paypal/signin.php?id=88231")
    assert r["verdict"] in ("PHISHING", "SUSPICIOUS")
    assert r["mode"] == "url"


def test_safe_text(guard):
    assert guard.analyze("Hey, are we still meeting for lunch at 1 PM?")["verdict"] == "SAFE"


def test_safe_url(guard):
    assert guard.analyze("https://www.wikipedia.org/wiki/Python")["verdict"] == "SAFE"


def test_empty_input(guard):
    with pytest.raises(ValueError):
        guard.analyze("   ")


def test_api():
    from app import app
    c = app.test_client()
    assert c.get("/health").status_code == 200
    assert c.get("/").status_code == 200
    assert c.post("/api/analyze", json={}).status_code == 400
    r = c.post("/api/analyze", json={"content": "Your KYC is expired. Update immediately: http://hdfc-kyc.top/verify"})
    assert r.status_code == 200 and r.get_json()["verdict"] in ("PHISHING", "SUSPICIOUS")
