import os
import logging
from typing import Dict, Optional
import joblib
import streamlit as st
import gdown

# Cache loaded models
_MODEL_CACHE: Dict[str, object] = {}

# -----------------------------
# Helper: download model if missing
# -----------------------------
def ensure_model(local_path: str, url: Optional[str] = None):
    """Download the model from URL if it doesn't exist locally."""
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    if url and not os.path.exists(local_path):
        logging.info(f"Downloading model from {url} to {local_path}...")
        gdown.download(url, local_path, quiet=False)
    elif not os.path.exists(local_path):
        raise FileNotFoundError(f"Model file not found at '{local_path}' and no URL provided.")

# -----------------------------
# Helper: get secret or env var
# -----------------------------
def _env_model_url(env_var: str, secret_key: Optional[str] = None) -> Optional[str]:
    """Get URL from environment variable or Streamlit secret."""
    value = os.getenv(env_var)
    if value:
        return value
    if secret_key:
        try:
            return st.secrets.get(secret_key)
        except Exception:
            pass
    return None

# -----------------------------
# Load model with caching
# -----------------------------
def load_model(local_path: str, url: Optional[str] = None):
    """Load a model from local path; download from URL if needed."""
    if local_path in _MODEL_CACHE:
        return _MODEL_CACHE[local_path]

    ensure_model(local_path, url)
    model = joblib.load(local_path)
    _MODEL_CACHE[local_path] = model
    return model

# -----------------------------
# Prediction helpers
# -----------------------------
def _model_predict(model, payload):
    """Run model.predict and optionally predict_proba on payload."""
    try:
        pred = model.predict(payload)
        label = str(pred[0])
    except Exception as e:
        logging.exception("Model prediction raised an exception")
        raise RuntimeError(f"Model prediction failed: {e}")

    confidence = _calculate_confidence(model, payload, label)
    return {'label': label, 'confidence': confidence}

def _calculate_confidence(model, payload, label):
    """
    Calculate confidence for the predicted label.
    Handles models with predict_proba, decision_function, or neither.
    """
    try:
        # 1) Try predict_proba first (returns class probabilities)
        if hasattr(model, 'predict_proba'):
            probs = model.predict_proba(payload)[0]
            if hasattr(model, 'classes_'):
                classes = [str(c) for c in model.classes_]  # normalize to str
                if label in classes:
                    return float(probs[classes.index(label)])
            # Fallback: return max probability
            return float(max(probs))

        # 2) Try decision_function (SVM, etc.) and convert to pseudo-probability
        if hasattr(model, 'decision_function'):
            decision = model.decision_function(payload)[0]
            # Handle binary or multi-class
            if hasattr(decision, '__iter__'):
                score = float(max(decision))
            else:
                score = float(decision)
            # Sigmoid to map unbounded score to 0-1 range
            import math
            confidence = 1 / (1 + math.exp(-score))
            return confidence

        # 3) No probability method available; return neutral confidence
        return 0.5

    except Exception as e:
        logging.exception("Confidence calculation raised an exception")
        return 0.5

# -----------------------------
# Public API
# -----------------------------
def predict_url(url_input: str, model_path="models/url_model.joblib"):
    """Predict a single URL with the cached URL model."""
    # Use your secret MODEL_URL
    model_url = _env_model_url("URL_MODEL_URL", "MODEL_URL")
    model = load_model(model_path, model_url)
    return _model_predict(model, [url_input])

def predict_email(subject: str, body: str, model_path="models/email_model.joblib"):
    """Predict email content using the cached email model (subject+body only)."""
    # Use your secret MODEL_EMAIL
    model_url = _env_model_url("EMAIL_MODEL_URL", "MODEL_EMAIL")
    model = load_model(model_path, model_url)
    content = " ".join(filter(None, [subject, body])).strip()
    payload = [content or "empty"]
    return _model_predict(model, payload)
