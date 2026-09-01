from __future__ import annotations

import math
import os
from pathlib import Path

import joblib
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Make the custom transformer importable before loading the joblib artifact.
from url_features import explain_url  # noqa: E402,F401

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "phishing_url_detector.joblib"

if not MODEL_PATH.exists():
    raise RuntimeError(
        f"Model file not found: {MODEL_PATH}. Copy the downloaded "
        "phishing_url_detector.joblib from Google Colab into this folder."
    )

artifact = joblib.load(MODEL_PATH)
preprocessor = artifact["preprocessor"]
scaler = artifact["scaler"]
classifier = artifact["classifier"]
threshold = float(artifact.get("threshold", 0.0))
model_version = artifact.get("model_version", "phishguard-1.0")

app = FastAPI(
    title="PhishGuard URL Detection API",
    version=str(model_version),
    description="Defensive URL-only phishing risk classifier. The API does not visit the submitted URL.",
)

allowed = os.getenv("ALLOWED_ORIGINS", "*")
origins = [x.strip() for x in allowed.split(",") if x.strip()] or ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


class PredictRequest(BaseModel):
    url: str = Field(min_length=3, max_length=4096)


def sigmoid(x: float) -> float:
    x = max(-60.0, min(60.0, x))
    return 1.0 / (1.0 + math.exp(-x))


def classify(url: str) -> dict:
    transformed = preprocessor.transform([url])
    transformed = scaler.transform(transformed)
    decision = float(classifier.decision_function(transformed)[0])
    phishing_score = sigmoid(decision)
    phishing = decision >= threshold
    return {
        "url": url,
        "prediction": "Potential phishing" if phishing else "Likely legitimate",
        "is_phishing": bool(phishing),
        "risk_score": round(phishing_score * 100.0, 2),
        "decision_score": round(decision, 6),
        "threshold": round(threshold, 6),
        "signals": explain_url(url),
        "model_version": str(model_version),
        "note": "Risk score is a model-derived score, not a guarantee of safety or maliciousness.",
    }


@app.get("/")
def root():
    return {
        "service": "PhishGuard URL Detection API",
        "status": "ok",
        "model_version": model_version,
        "docs": "/docs",
    }


@app.get("/health")
def health():
    return {"status": "healthy", "model_loaded": True, "model_version": model_version}


@app.post("/predict")
def predict(payload: PredictRequest):
    url = payload.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")
    try:
        return classify(url)
    except Exception as exc:
        # Do not expose stack traces to clients.
        raise HTTPException(status_code=500, detail="Prediction failed. Check the Render logs for details.") from exc
