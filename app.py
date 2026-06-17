"""
app.py
------
Flask application: serves the frontend (templates/index.html) and exposes
a JSON API that scores a URL using the trained model in model/phishing_model.pkl.

Run:
    pip install -r requirements.txt
    python train_model.py     # only needed once, to (re)build the model
    python app.py
    -> open http://127.0.0.1:5000
"""

import json
import time
from pathlib import Path

import joblib
from flask import Flask, jsonify, render_template, request

from feature_extraction import feature_vector, explain

APP_DIR = Path(__file__).resolve().parent
MODEL_PATH = APP_DIR / "model" / "phishing_model.pkl"
METRICS_PATH = APP_DIR / "model" / "metrics.json"

app = Flask(__name__)

_model = None
_metrics = None


def get_model():
    global _model
    if _model is None:
        if not MODEL_PATH.exists():
            raise RuntimeError(
                "No trained model found. Run `python train_model.py` first."
            )
        _model = joblib.load(MODEL_PATH)
    return _model


def get_metrics():
    global _metrics
    if _metrics is None and METRICS_PATH.exists():
        _metrics = json.loads(METRICS_PATH.read_text())
    return _metrics or {}


def verdict_from_score(score: int) -> str:
    if score < 30:
        return "safe"
    if score < 65:
        return "suspicious"
    return "phishing"


@app.route("/")
def index():
    return render_template("index.html", metrics=get_metrics())


@app.route("/api/metrics")
def api_metrics():
    return jsonify(get_metrics())


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()

    if not url:
        return jsonify({"error": "Please provide a URL to scan."}), 400
    if len(url) > 2048:
        return jsonify({"error": "That URL is too long to scan (max 2048 characters)."}), 400

    start = time.time()
    vector, feats = feature_vector(url)
    model = get_model()

    proba = model.predict_proba([vector])[0]
    # proba[1] = probability of class "1" = phishing
    phishing_probability = float(proba[1])
    risk_score = round(phishing_probability * 100)

    checks = explain(feats)
    elapsed_ms = round((time.time() - start) * 1000, 2)

    return jsonify({
        "url": url,
        "risk_score": risk_score,
        "verdict": verdict_from_score(risk_score),
        "model_probability_phishing": round(phishing_probability, 4),
        "checks": checks,
        "processing_time_ms": elapsed_ms,
    })


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok", "model_loaded": MODEL_PATH.exists()})


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
