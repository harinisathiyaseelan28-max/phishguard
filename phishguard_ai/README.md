# 🛡️ PhishGuard AI – Phishing Detection Mini Project

PhishGuard AI detects phishing in **URLs, SMS messages and emails** using two machine-learning
models plus rule-based explanations, served through a Flask web app and a JSON API.

## How it works

```
 user input (URL / SMS / email)
        │
        ├── find_urls() ──► URL features (22 lexical/host features) ──► Random Forest ─┐
        │                                                                              ├─► risk score 0-100
        └── strip URLs ──► TF-IDF (word + char n-grams) ──► Logistic Regression ───────┘      │
                                                                                      SAFE / SUSPICIOUS / PHISHING
        rule-based explainer (urgency, OTP/KYC requests, rewards, IP host, bad TLD, brand spoofing...) ──► "Why?"
```

| Component | Technique |
|---|---|
| Text model | TF-IDF (word 1-2 grams + char 3-5 grams) + Logistic Regression |
| URL model | 22 hand-crafted features + Random Forest |
| Final score | combination of both (a clearly bad link or text dominates) |
| Verdict | ≥ 70 % PHISHING · 40-70 % SUSPICIOUS · < 40 % SAFE |

## Project structure

```
phishguard_ai/
├── app.py                  Flask app (UI + /api/analyze, /api/metrics, /health)
├── train.py                Trains both models and saves them to models/
├── requirements.txt
├── phishguard/
│   ├── dataset.py          Synthetic dataset generator / real-CSV loader
│   ├── url_features.py     URL feature extraction + URL explanations
│   └── detector.py         Inference engine (PhishGuard class)
├── templates/index.html    Web UI
├── static/                 style.css, app.js
├── models/                 Trained models (pre-trained copy included)
├── data/                   Put real messages.csv / urls.csv here (optional)
└── tests/test_phishguard.py
```

## Setup & run (Windows / Linux / macOS)

```bash
python -m venv venv
venv\Scripts\activate          # Windows      (Linux/macOS: source venv/bin/activate)
pip install -r requirements.txt
python train.py                # optional – a trained model is already included
python app.py                  # open http://127.0.0.1:5000
```

Run the tests: `python -m pytest tests`

## API

```bash
curl -X POST http://127.0.0.1:5000/api/analyze \
     -H "Content-Type: application/json" \
     -d '{"content": "Your KYC is expired. Update now: http://hdfc-kyc.top/verify"}'
```

Response: `verdict`, `risk_score`, `text_probability`, per-link `urls`, `reasons`, `advice`.

## ⚠️ Important note about the dataset

No internet is needed: by default the project **generates a synthetic, template-based dataset**.
Because of that, the test accuracy printed by `train.py` is ~100 % – that number is **not** a
real-world accuracy. For your report / viva, train on real data:

* Messages: [SMS Spam Collection (UCI)](https://archive.ics.uci.edu/dataset/228/sms+spam+collection) –
  save as `data/messages.csv` with columns `text,label` (`1` = spam/phishing, `0` = ham).
* URLs: PhishTank / OpenPhish (phishing) + Tranco top sites (legitimate) –
  save as `data/urls.csv` with columns `url,label`.

Then run `python train.py` again – real CSV files automatically replace the synthetic data.

## Limitations

* Lexical URL features only (no live WHOIS / page-content / blacklist lookups).
* English-centric text model; retrain with your own data for other languages.
* Educational tool – not a replacement for professional security software.

## Possible extensions

Browser extension, email (.eml) upload, LSTM / BERT text model, Google Safe Browsing API check,
domain-age lookup, feedback loop to retrain on user-reported messages.
