"""Synthetic dataset generator.

No internet is needed to run the project: this module generates a realistic,
noisy training set of phishing / legitimate messages and URLs.

To use REAL data instead, drop CSV files into data/ (see README):
  data/messages.csv -> columns: text,label   (label: 1 = phishing/spam, 0 = safe)
  data/urls.csv     -> columns: url,label
and run `python train.py`. Real files override the synthetic ones.
"""
import os
import random
import string

import pandas as pd

BRANDS = ["PayPal", "Amazon", "Netflix", "SBI", "HDFC Bank", "ICICI Bank",
          "Paytm", "Apple", "Microsoft", "Google", "Instagram", "DHL", "FedEx",
          "IRCTC", "Flipkart", "WhatsApp"]
BRAND_DOMAINS = ["paypal", "amazon", "netflix", "sbi", "hdfc", "icici", "paytm",
                 "apple", "microsoft", "google", "instagram", "dhl", "fedex",
                 "irctc", "flipkart", "whatsapp"]
KEYWORDS = ["login", "verify", "secure", "update", "account", "signin",
            "confirm", "billing", "kyc", "wallet"]
BAD_TLDS = ["xyz", "top", "tk", "ml", "ga", "cf", "click", "link", "icu", "work", "support"]
GOOD_DOMAINS = [
    "google.com", "amazon.in", "wikipedia.org", "github.com", "youtube.com",
    "microsoft.com", "apple.com", "netflix.com", "flipkart.com", "irctc.co.in",
    "paypal.com", "linkedin.com", "stackoverflow.com", "annauniv.edu",
    "nptel.ac.in", "python.org", "bbc.co.uk", "thehindu.com", "zoho.com",
    "hdfcbank.com", "onlinesbi.sbi", "icicibank.com", "paytm.com", "mozilla.org",
    "medium.com", "coursera.org", "reddit.com", "nytimes.com", "gov.in",
]
GOOD_PATHS = ["", "/", "/about", "/products/item-{n}", "/search?q={w}", "/docs/{w}",
              "/news/{n}", "/help/contact", "/blog/{w}-{w2}", "/store/category/{w}",
              "/watch?v={r}", "/wiki/{w}", "/user/{w}/profile", "/careers",
              "/login", "/signin", "/account/settings", "/gp/your-account/order-history",
              "/account/billing", "/accounts/login/?next=/{w}", "/secure/payment/{n}",
              "/verify-email?token={r}", "/password/reset", "/support/account-help"]
WORDS = ["python", "laptop", "weather", "cricket", "recipe", "college", "machine",
         "learning", "travel", "music", "movie", "science", "market", "health"]


def _rand(n=6):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _path(templates):
    return random.choice(templates).format(
        n=random.randint(1, 99999), w=random.choice(WORDS),
        w2=random.choice(WORDS), r=_rand(11))


# ------------------------------------------------------------------ URLs
def good_url():
    d = random.choice(GOOD_DOMAINS)
    scheme = "https" if random.random() < 0.93 else "http"
    sub = random.choice(["", "www.", "www.", "mail.", "docs.", "support.", "m."])
    return f"{scheme}://{sub}{d}{_path(GOOD_PATHS)}"


def phish_url():
    brand = random.choice(BRAND_DOMAINS)
    kw = random.choice(KEYWORDS)
    kw2 = random.choice(KEYWORDS)
    tld = random.choice(BAD_TLDS)
    kind = random.randint(0, 7)
    scheme = "http" if random.random() < 0.7 else "https"
    if kind == 0:
        host = ".".join(str(random.randint(1, 250)) for _ in range(4))
        return f"http://{host}/{brand}/{kw}.php?id={_rand(8)}"
    if kind == 1:
        return f"{scheme}://{brand}.{kw}-{kw2}.{_rand(5)}.{tld}/{kw}"
    if kind == 2:
        return f"{scheme}://{brand}-{kw}-{_rand(4)}.{tld}/{kw2}/index.html?session={_rand(20)}"
    if kind == 3:
        return f"{scheme}://www.{brand}.com@{_rand(7)}.{tld}/{kw}"
    if kind == 4:
        return f"{scheme}://{kw}.{brand}.{kw2}.{_rand(6)}.com/{kw}/{_rand(10)}"
    if kind == 5:
        return f"{scheme}://secure-{brand}{random.randint(1,99)}.{tld}/{kw}?token={_rand(30)}&redirect={kw2}"
    if kind == 6:
        return f"http://{brand}{kw}.{random.choice(['com','net','in'])}-{_rand(5)}.{tld}:8080/{kw}"
    return f"https://xn--{brand}-{_rand(5)}.{tld}/{kw}/{kw2}"


# -------------------------------------------------------------- messages
PHISH_TEMPLATES = [
    "URGENT: Your {b} account has been suspended. Verify now at {u} to avoid permanent closure.",
    "Dear customer, your {b} KYC is expired. Update immediately: {u}",
    "{b} Alert: unusual login detected. Confirm your identity within 24 hours {u}",
    "Congratulations! You have won a Rs {amt} {b} gift card. Claim your prize here {u}",
    "Your package could not be delivered. Pay the Rs {small} customs fee at {u}",
    "Dear user, your password will expire today. Click {u} to keep your account active.",
    "We detected suspicious activity on your {b} account. Secure your account now: {u}",
    "Final notice: your {b} bill of Rs {amt} is overdue. Pay now {u} or service will be disconnected.",
    "Your debit card has been blocked. Call {ph} or visit {u} to unblock immediately.",
    "You are selected for a work-from-home job earning Rs {amt} per day. Register at {u}",
    "Refund pending of Rs {amt} from {b}. Submit your card details at {u} to receive it.",
    "Security warning from {b}: verify your OTP and account details at {u} immediately.",
    "Hi, this is {b} support. Your account will be closed unless you confirm your details: {u}",
    "FREE entry! Win a brand new phone. Text WIN to {ph} now. Offer ends today!!!",
    "Your income tax refund of Rs {amt} is approved. Click {u} to claim.",
    "Dear Sir/Madam, kindly update your bank details to receive the pending payment {u}",
    "Lottery winner!! Your number was selected for Rs {amt}. Reply with your bank account number.",
    "Action required: your mailbox storage is full. Login to {u} to avoid losing emails.",
]
# Subtler phishing (fewer obvious cues)
PHISH_SUBTLE = [
    "Hi, please review the attached invoice and sign in here: {u}",
    "Your document has been shared with you. Open {u}",
    "Missed call from {b}. Check details {u}",
    "Hello, we could not process your payment method. Update here {u}",
]
GOOD_TEMPLATES = [
    "Hey, are we still meeting for lunch at {t}?",
    "Your OTP for {b} login is {otp}. Do not share it with anyone. Valid for 10 minutes.",
    "Reminder: your appointment is scheduled for tomorrow at {t}. Reply YES to confirm.",
    "Thanks for your purchase! Your order #{n} will be delivered by Friday. Track it in the {b} app.",
    "Can you send me the lecture notes for Operating Systems?",
    "Happy birthday! Wishing you a wonderful year ahead.",
    "Your {b} statement for this month is available. Log in to the official app to view it.",
    "Meeting moved to {t}. Please check the shared calendar.",
    "Don't forget to submit the mini project report by Monday.",
    "Rs {small} debited from A/c XX{n4} on UPI. If not you, call the number on your card.",
    "Hi mom, I reached the hostel safely. Will call you in the evening.",
    "Your package from {b} has been delivered. Rate your experience in the app.",
    "Dinner at my place tonight? I'm making biryani.",
    "The exam timetable has been published on the college website: {gu}",
    "Please find the agenda for tomorrow's review meeting attached. Let me know your thoughts.",
    "Your cab is arriving in 3 minutes. Driver: Ravi, vehicle TN 49 AB {n4}.",
    "Thanks for registering for the workshop. Details: {gu}",
    "Your password was changed successfully. If this wasn't you, contact support through the official app.",
    "Bro, check this tutorial on machine learning: {gu}",
    "Invoice #{n} for your subscription has been paid. Thank you for your business.",
    "Class cancelled today because the professor is on leave.",
    "Weekly report: all systems operational. No action required.",
    "Your {b} order #{n} has shipped. Track it here: {gu}",
    "Your {b} order has been delivered. View your order history: {gu}",
    "Please review the project documents here: {gu}",
    "Registration for the symposium is open. Details and schedule at {gu}",
    "Your {b} subscription renews next week. Manage it any time at {gu}",
    "Notes for the Data Science unit are uploaded: {gu}",
    "Here is the link to join the meeting at {t}: {gu}",
    "Your {b} receipt for Rs {small} is available at {gu}",
]


def _fill(t, bad_url):
    return t.format(
        b=random.choice(BRANDS), u=bad_url(), gu=good_url(),
        amt=random.choice([5000, 10000, 25000, 50000, 100000]),
        small=random.choice([25, 49, 99, 199, 450]),
        ph=str(random.randint(50000, 99999)),
        t=random.choice(["1 PM", "5:30 PM", "9 AM", "noon"]),
        otp=random.randint(100000, 999999), n=random.randint(10000, 99999),
        n4=random.randint(1000, 9999),
    )


def make_messages(n=3000, seed=42):
    random.seed(seed)
    rows = []
    for i in range(n):
        if i % 2 == 0:
            tpl = random.choice(PHISH_TEMPLATES if random.random() < 0.8 else PHISH_SUBTLE)
            text, label = _fill(tpl, phish_url), 1
        else:
            text, label = _fill(random.choice(GOOD_TEMPLATES), phish_url), 0
        # noise: random casing / typos so it is not a pure template match
        if random.random() < 0.15:
            text = text.lower()
        if random.random() < 0.10 and len(text) > 20:
            k = random.randrange(len(text))
            text = text[:k] + text[k + 1:]
        rows.append((text, label))
    return pd.DataFrame(rows, columns=["text", "label"])


def make_urls(n=4000, seed=7):
    random.seed(seed)
    rows = [(good_url(), 0) if i % 2 else (phish_url(), 1) for i in range(n)]
    return pd.DataFrame(rows, columns=["url", "label"])


def load_or_generate(data_dir="data"):
    mp, up = os.path.join(data_dir, "messages.csv"), os.path.join(data_dir, "urls.csv")
    if os.path.exists(mp):
        msgs = pd.read_csv(mp).dropna(subset=["text", "label"])
        msgs["label"] = msgs["label"].astype(int)
        print(f"Loaded real messages dataset: {len(msgs)} rows")
    else:
        msgs = make_messages()
        print(f"Generated synthetic messages dataset: {len(msgs)} rows")
    if os.path.exists(up):
        urls = pd.read_csv(up).dropna(subset=["url", "label"])
        urls["label"] = urls["label"].astype(int)
        print(f"Loaded real URL dataset: {len(urls)} rows")
    else:
        urls = make_urls()
        print(f"Generated synthetic URL dataset: {len(urls)} rows")
    return msgs, urls
