"""PhishGuard AI - Flask web app + JSON API.

Run:  python app.py      then open http://127.0.0.1:5000
"""
import json
import os

from flask import Flask, jsonify, render_template, request

from phishguard.detector import PhishGuard

BASE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)
guard = PhishGuard()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    content = (data.get("content") or "").strip()
    if not content:
        return jsonify({"error": "Please provide 'content' (URL, SMS or email text)."}), 400
    if len(content) > 20000:
        return jsonify({"error": "Input too long (max 20000 characters)."}), 400
    return jsonify(guard.analyze(content))


@app.route("/api/metrics")
def metrics():
    path = os.path.join(BASE, "models", "metrics.json")
    if not os.path.exists(path):
        return jsonify({"error": "metrics not available"}), 404
    with open(path) as f:
        return jsonify(json.load(f))


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
