"""Hand-crafted lexical / host-based features for URL phishing detection."""
import math
import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "work",
    "support", "country", "zip", "mov", "icu", "buzz", "monster", "cam",
}
PHISH_WORDS = [
    "login", "signin", "verify", "update", "secure", "account", "bank",
    "confirm", "password", "wallet", "billing", "suspend", "unlock",
    "payment", "invoice", "alert", "recover", "validate", "kyc",
]
BRANDS = [
    "paypal", "google", "amazon", "apple", "microsoft", "facebook", "netflix",
    "sbi", "hdfc", "icici", "paytm", "instagram", "whatsapp", "linkedin",
    "dhl", "fedex", "irctc", "flipkart",
]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
              "rb.gy", "ow.ly", "shorturl.at"}
TWO_PART_TLDS = {"co.uk", "co.in", "com.au", "org.uk", "ac.in", "gov.in",
                 "com.br", "co.jp", "net.in", "org.in"}

URL_REGEX = re.compile(
    r"(?i)\b((?:https?://|www\.)[^\s<>\"']+|(?:[a-z0-9-]+\.)+(?:com|net|org|in|xyz|top|tk|ml|ga|cf|gq|click|link|info|biz|co|io|me|support|work|zip)(?:/[^\s<>\"']*)?)"
)

FEATURE_NAMES = [
    "url_len", "host_len", "path_len", "num_dots", "num_hyphens_host",
    "num_digits", "digit_ratio", "num_subdomains", "has_ip", "has_at",
    "is_https", "suspicious_tld", "num_phish_words", "brand_in_subdomain",
    "brand_in_path", "num_params", "has_punycode", "host_entropy",
    "is_shortener", "num_special", "double_slash_path", "has_port",
]


def normalize(url: str) -> str:
    url = url.strip().rstrip(".,;:!?)")
    if not re.match(r"(?i)^[a-z][a-z0-9+.-]*://", url):
        url = "http://" + url
    return url


def split_host(host: str):
    """Return (subdomain_labels, registered_domain, tld)."""
    host = host.lower().strip(".")
    labels = host.split(".")
    if len(labels) < 2:
        return [], host, ""
    last_two = ".".join(labels[-2:])
    if last_two in TWO_PART_TLDS and len(labels) >= 3:
        return labels[:-3], ".".join(labels[-3:]), last_two
    return labels[:-2], ".".join(labels[-2:]), labels[-1]


def entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def parse(url: str):
    url = normalize(url)
    p = urlparse(url)
    host = (p.hostname or "").lower()
    return url, p, host


def extract_features(url: str) -> list:
    url, p, host = parse(url)
    path_q = (p.path or "") + ("?" + p.query if p.query else "")
    subs, reg_domain, tld = split_host(host)
    reg_name = reg_domain.split(".")[0] if reg_domain else ""
    sub_str = ".".join(subs)
    lower = url.lower()

    has_ip = int(bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))
                 or bool(re.fullmatch(r"0x[0-9a-f]+", host)))
    brand_sub = int(any(b in sub_str for b in BRANDS)
                    or any(b in reg_name and b != reg_name for b in BRANDS))
    brand_path = int(any(b in path_q.lower() for b in BRANDS))
    digits = sum(c.isdigit() for c in url)

    return [
        len(url),
        len(host),
        len(path_q),
        host.count("."),
        host.count("-"),
        digits,
        digits / max(len(url), 1),
        len(subs),
        has_ip,
        int("@" in p.netloc or "@" in url.split("?")[0]),
        int(p.scheme == "https"),
        int(tld in SUSPICIOUS_TLDS),
        sum(w in lower for w in PHISH_WORDS),
        brand_sub,
        brand_path,
        len([x for x in p.query.split("&") if x]),
        int("xn--" in host),
        entropy(host),
        int(host in SHORTENERS),
        sum(url.count(c) for c in "!$%^*()=+[]{}|;,~"),
        int("//" in (p.path or "")),
        int(p.port is not None and p.port not in (80, 443)),
    ]


def explain(url: str) -> list:
    """Human-readable reasons a URL looks risky."""
    f = dict(zip(FEATURE_NAMES, extract_features(url)))
    url_n, p, host = parse(url)
    reasons = []
    if f["has_ip"]:
        reasons.append("Uses a raw IP address instead of a domain name")
    if f["has_at"]:
        reasons.append("Contains '@' which can hide the real destination")
    if not f["is_https"]:
        reasons.append("Does not use HTTPS")
    if f["suspicious_tld"]:
        reasons.append("Uses a top-level domain often abused for phishing")
    if f["brand_in_subdomain"]:
        reasons.append("Mentions a well-known brand in a sub-domain / look-alike domain")
    if f["num_phish_words"] >= 2:
        reasons.append("Contains several credential-related words (login, verify, secure...)")
    if f["num_subdomains"] >= 3:
        reasons.append("Has an unusually deep chain of sub-domains")
    if f["has_punycode"]:
        reasons.append("Uses punycode (possible look-alike characters)")
    if f["is_shortener"]:
        reasons.append("Uses a link shortener that hides the destination")
    if f["num_hyphens_host"] >= 2:
        reasons.append("Domain contains many hyphens")
    if f["url_len"] > 90:
        reasons.append("Very long URL")
    if f["has_port"]:
        reasons.append("Uses a non-standard port")
    return reasons


def find_urls(text: str) -> list:
    found = []
    for m in URL_REGEX.finditer(text or ""):
        u = m.group(1).rstrip(".,;:!?)")
        if u not in found:
            found.append(u)
    return found
