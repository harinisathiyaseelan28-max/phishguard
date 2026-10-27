"""Train the PhishGuard AI models and save them to models/.

Usage:  python train.py
"""
import json
import os

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, f1_score, precision_score,
                             recall_score)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

from phishguard.dataset import load_or_generate
from phishguard.detector import prepare_text
from phishguard.url_features import FEATURE_NAMES, extract_features

BASE = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE, "models")


def metrics(y_true, y_pred):
    return {
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "precision": round(precision_score(y_true, y_pred), 4),
        "recall": round(recall_score(y_true, y_pred), 4),
        "f1": round(f1_score(y_true, y_pred), 4),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
    }


def main():
    os.makedirs(MODEL_DIR, exist_ok=True)
    msgs, urls = load_or_generate(os.path.join(BASE, "data"))

    # ---------------- text model (SMS / email body) ----------------
    X = msgs["text"].astype(str).map(prepare_text)
    y = msgs["label"].values
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    text_model = Pipeline([
        ("features", FeatureUnion([
            ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True)),
            ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3, sublinear_tf=True)),
        ])),
        ("clf", LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced")),
    ])
    text_model.fit(Xtr, ytr)
    text_m = metrics(yte, text_model.predict(Xte))
    print("\n=== TEXT MODEL (TF-IDF + Logistic Regression) ===")
    print(classification_report(yte, text_model.predict(Xte), target_names=["safe", "phishing"]))

    # ---------------- URL model ----------------
    Xu = np.array([extract_features(u) for u in urls["url"]], dtype=float)
    yu = urls["label"].values
    Xutr, Xute, yutr, yute = train_test_split(Xu, yu, test_size=0.2, random_state=42, stratify=yu)
    url_model = RandomForestClassifier(n_estimators=250, max_depth=14, random_state=42,
                                       class_weight="balanced", n_jobs=-1)
    url_model.fit(Xutr, yutr)
    url_m = metrics(yute, url_model.predict(Xute))
    print("=== URL MODEL (Random Forest on lexical features) ===")
    print(classification_report(yute, url_model.predict(Xute), target_names=["safe", "phishing"]))
    imp = sorted(zip(FEATURE_NAMES, url_model.feature_importances_), key=lambda t: -t[1])[:8]
    print("Top URL features:", ", ".join(f"{n}={v:.3f}" for n, v in imp))

    joblib.dump(text_model, os.path.join(MODEL_DIR, "text_model.joblib"))
    joblib.dump(url_model, os.path.join(MODEL_DIR, "url_model.joblib"))
    with open(os.path.join(MODEL_DIR, "metrics.json"), "w") as f:
        json.dump({"text_model": text_m, "url_model": url_m,
                   "top_url_features": [[n, round(float(v), 4)] for n, v in imp]}, f, indent=2)
    print("\nModels saved to", MODEL_DIR)


if __name__ == "__main__":
    main()
