"""Inference engine combining text model, URL model and rule-based reasons."""
import os
import re

import joblib
import numpy as np

from .url_features import explain as explain_url
from .url_features import extract_features, find_urls

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE, "models")

URGENCY = ["urgent", "immediately", "within 24 hours", "final notice", "act now",
           "expires today", "suspended", "blocked", "last warning", "asap", "today"]
SENSITIVE = ["otp", "password", "pin", "cvv", "card number", "bank account",
             "kyc", "aadhaar", "pan card", "ssn", "credentials", "card details"]
REWARD = ["won", "winner", "prize", "lottery", "gift card", "free", "congratulations",
          "refund", "cashback", "claim"]
URL_TOKEN = "urltoken"


def prepare_text(text: str) -> str:
    """Strip URLs so the text model judges wording only (links are scored by the URL model)."""
    t = text or ""
    for u in sorted(find_urls(t), key=len, reverse=True):
        t = t.replace(u, " ")
    t = re.sub(r"\d{4,}", " bignum ", t)
    return t.lower()


def text_reasons(text: str) -> list:
    low = (text or "").lower()
    reasons = []
    if any(w in low for w in URGENCY):
        reasons.append("Creates urgency / threatens account closure")
    if any(w in low for w in SENSITIVE):
        reasons.append("Asks for or mentions sensitive details (OTP, password, card, KYC)")
    if any(w in low for w in REWARD):
        reasons.append("Promises a prize, refund or reward")
    if re.search(r"(?i)dear (customer|user|sir|madam)", low):
        reasons.append("Uses a generic greeting instead of your name")
    if low.count("!") >= 3:
        reasons.append("Excessive exclamation marks")
    return reasons


class PhishGuard:
    def __init__(self, model_dir: str = MODEL_DIR):
        tp = os.path.join(model_dir, "text_model.joblib")
        up = os.path.join(model_dir, "url_model.joblib")
        if not (os.path.exists(tp) and os.path.exists(up)):
            raise FileNotFoundError(
                "Trained models not found. Run `python train.py` first.")
        self.text_model = joblib.load(tp)
        self.url_model = joblib.load(up)

    # ---- single-URL scoring ----
    def score_url(self, url: str) -> dict:
        feats = np.array([extract_features(url)], dtype=float)
        prob = float(self.url_model.predict_proba(feats)[0][1])
        return {"url": url, "probability": round(prob, 4),
                "verdict": self._verdict(prob), "reasons": explain_url(url)}

    # ---- message scoring ----
    def score_text(self, text: str) -> float:
        return float(self.text_model.predict_proba([prepare_text(text)])[0][1])

    @staticmethod
    def _verdict(p: float) -> str:
        if p >= 0.70:
            return "PHISHING"
        if p >= 0.40:
            return "SUSPICIOUS"
        return "SAFE"

    def analyze(self, content: str) -> dict:
        content = (content or "").strip()
        if not content:
            raise ValueError("Empty input")

        urls = find_urls(content)
        is_pure_url = (len(urls) == 1 and len(content.split()) == 1)

        url_results = [self.score_url(u) for u in urls]
        url_max = max((r["probability"] for r in url_results), default=None)

        if is_pure_url:
            final, text_prob, mode = url_max, None, "url"
        else:
            text_prob = self.score_text(content)
            mode = "message"
            if url_max is None:
                final = text_prob
            else:
                final = 0.5 * text_prob + 0.5 * url_max
                # a clearly malicious link or clearly malicious text should dominate
                final = max(final, 0.85 * url_max, 0.85 * text_prob)

        reasons = [] if is_pure_url else text_reasons(content)
        for r in url_results:
            for why in r["reasons"]:
                reasons.append(f"{r['url']}: {why}")

        if not is_pure_url and len(reasons) >= 3:
            final = min(1.0, final + 0.05)

        final = float(round(final, 4))
        return {
            "mode": mode,
            "verdict": self._verdict(final),
            "risk_score": round(final * 100, 1),
            "text_probability": None if text_prob is None else round(text_prob, 4),
            "urls": url_results,
            "reasons": reasons,
            "advice": {
                "PHISHING": "Do NOT click any link or share any details. Delete it and report it (India: cybercrime.gov.in / 1930).",
                "SUSPICIOUS": "Be careful. Verify through the official website or app (type the address yourself) before acting.",
                "SAFE": "No strong phishing signs found, but always stay cautious with unexpected links.",
            }[self._verdict(final)],
        }
