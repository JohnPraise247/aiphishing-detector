import os
import logging
import hashlib
import base64
import socket
import ssl
from typing import Any, Dict, Optional, Sequence
from urllib.parse import urlparse

import joblib
import streamlit as st
import gdown
import requests
from requests.exceptions import RequestException, SSLError
from google.protobuf.message import DecodeError

from utils.google.security.safebrowsing.v5alpha1 import safebrowsing_pb2

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
def _url_feature_vector(url_input: str, keywords: Sequence[str] = ('verify', 'account', 'login', 'secure', 'update', 'confirm')) -> list:
    parsed = urlparse(url_input)
    domain = parsed.netloc or ''
    path = parsed.path or ''
    normalized_url = url_input.lower()
    digits = sum(1 for ch in url_input if ch.isdigit())
    hyphen = normalized_url.count('-')
    underscore = normalized_url.count('_')
    keyword_hits = sum(1 for kw in keywords if kw in normalized_url)

    domain_depth = max(domain.count('.') - 1, 0)
    return [
        float(len(url_input)),
        float(len(domain)),
        float(len(path)),
        float(len(parsed.query)),
        float(len(parsed.fragment)),
        1.0 if parsed.scheme == 'https' else 0.0,
        float(int(parsed.port is not None)),
        float(domain_depth),
        float(digits),
        float(hyphen),
        float(underscore),
        float(keyword_hits)
    ]


def _compute_url_hashes(url_input: str) -> list[tuple[bytes, bytes]]:
    """
    Compute SHA-256 hash expressions for a URL per Safe Browsing spec.
    Returns list of (full_hash, 4-byte prefix) tuples for all URL variants.
    """
    parsed = urlparse(url_input)
    host = parsed.netloc.lower()
    path = parsed.path or "/"
    
    # Remove port if present
    if ":" in host:
        host = host.split(":")[0]
    
    # Generate host suffixes (e.g., a.b.c.com -> [a.b.c.com, b.c.com, c.com])
    host_parts = host.split(".")
    suffixes = []
    for i in range(len(host_parts)):
        suffix = ".".join(host_parts[i:])
        if "." in suffix:  # Must have at least one dot
            suffixes.append(suffix)
    if host not in suffixes:
        suffixes.insert(0, host)
    
    # Generate path prefixes (e.g., /a/b/c -> [/, /a/, /a/b/, /a/b/c])
    path_prefixes = ["/"]
    if path != "/":
        parts = path.split("/")
        current = ""
        for part in parts[1:]:  # Skip empty first element
            current += "/" + part
            if current.endswith("/"):
                path_prefixes.append(current)
            else:
                path_prefixes.append(current + "/")
                path_prefixes.append(current)
    
    # Remove duplicates and keep order
    path_prefixes = list(dict.fromkeys(path_prefixes))
    
    # Compute hashes for all combinations
    hashes = []
    for suffix in suffixes[:5]:  # Limit to 5 host suffixes
        for prefix in path_prefixes[:6]:  # Limit to 6 path prefixes
            expression = suffix + prefix.rstrip("/")
            if not expression.endswith("/") and prefix == "/":
                expression = suffix + "/"
            else:
                expression = suffix + prefix
            full_hash = hashlib.sha256(expression.encode()).digest()
            hash_prefix = full_hash[:4]  # 4-byte prefix
            hashes.append((full_hash, hash_prefix))
    
    # Deduplicate by prefix
    seen = set()
    unique = []
    for full, prefix in hashes:
        if prefix not in seen:
            seen.add(prefix)
            unique.append((full, prefix))
    
    return unique


def _check_tls_certificate(host: str, port: int) -> bool:
    """Verify TLS certificate by establishing an SSL socket handshake."""
    try:
        addr_info = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        family, _, _, _, sockaddr = addr_info[0]
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        with context.wrap_socket(socket.socket(family), server_hostname=host) as sock:
            sock.settimeout(5)
            sock.connect(sockaddr)
            sock.getpeercert()
        return True
    except Exception:
        return False


def _probe_url(url_input: str) -> Dict[str, Any]:
    """Perform DNS resolution and an HTTP probe to record reachability metadata."""
    parsed = urlparse(url_input)
    host = parsed.hostname
    scheme = parsed.scheme
    port = parsed.port or (443 if scheme == 'https' else 80)

    probe_result: Dict[str, Any] = {
        'reachable': False,
        'status_code': None,
        'status_message': None,
        'final_url': None,
        'redirect_count': 0,
        'redirects': [],
        'response_time_ms': None,
        'error': None,
        'tls_valid': None
    }

    if not host:
        probe_result['error'] = 'Invalid URL: missing host'
        return probe_result

    try:
        socket.getaddrinfo(host, port)
    except socket.gaierror as exc:
        probe_result['error'] = f'DNS resolution failed: {exc}'
        return probe_result

    try:
        with requests.Session() as session:
            response = session.head(url_input, allow_redirects=True, timeout=6)
            if response.status_code in (405, 501):
                response = session.get(url_input, stream=True, allow_redirects=True, timeout=6)
    except (RequestException, SSLError) as exc:
        probe_result['error'] = str(exc)
        if isinstance(exc, SSLError):
            probe_result['tls_valid'] = False
        return probe_result

    probe_result.update({
        'reachable': True,
        'status_code': response.status_code,
        'status_message': response.reason,
        'final_url': response.url,
        'redirect_count': len(response.history),
        'redirects': [resp.url for resp in response.history],
        'response_time_ms': int(response.elapsed.total_seconds() * 1000)
    })

    if scheme == 'https':
        probe_result['tls_valid'] = _check_tls_certificate(host, port)

    return probe_result


def _safe_browsing_lookup(url_input: str, api_key: str) -> Dict[str, str]:
    """
    Look up URL in Safe Browsing using the v5alpha1 hashes:search endpoint.
    This requires computing URL hash prefixes locally and sending them.
    """
    # Compute all hash prefixes for URL expressions
    url_hashes = _compute_url_hashes(url_input)
    if not url_hashes:
        return {"label": "benign", "confidence": 0.5}
    
    # Build the hash prefixes parameter (base64-encoded, as separate params)
    hash_prefixes_b64 = [base64.b64encode(prefix).decode('ascii') for _, prefix in url_hashes]
    
    endpoint = "https://safebrowsing.googleapis.com/v5alpha1/hashes:search"
    params = {
        "key": api_key,
        "hashPrefixes": hash_prefixes_b64
    }
    
    headers = {"Accept": "application/x-protobuf"}

    response = requests.get(endpoint, params=params, headers=headers, timeout=10)
    response.raise_for_status()

    payload = response.content
    if not payload:
        # Empty response means no threats found
        return {"label": "benign", "confidence": 0.89}

    search_response = safebrowsing_pb2.SearchHashesResponse()
    try:
        search_response.ParseFromString(payload)
    except DecodeError as exc:
        logging.exception("Safe Browsing protobuf parse failed")
        raise RuntimeError("Safe Browsing response could not be decoded") from exc

    if not search_response.full_hashes:
        return {"label": "benign", "confidence": 0.89}

    # Check if any returned full hash matches our computed full hashes
    our_full_hashes = {full_hash for full_hash, _ in url_hashes}
    
    for returned_hash in search_response.full_hashes:
        if returned_hash.full_hash in our_full_hashes:
            # Found a match - URL is flagged
            label, confidence = _interpret_safebrowsing_match(returned_hash)
            return {"label": label, "confidence": confidence}
    
    # No full hash match, URL is safe
    return {"label": "benign", "confidence": 0.89}


def _interpret_safebrowsing_match(full_hash) -> tuple[str, float]:
    detail = None
    if full_hash.full_hash_details:
        detail = full_hash.full_hash_details[0]

    if not detail:
        return "suspicious", 0.92

    try:
        threat_name = safebrowsing_pb2.ThreatType.Name(detail.threat_type)
    except ValueError:
        threat_name = "THREAT_TYPE_UNSPECIFIED"

    label = threat_name.lower()
    confidence_map = {
        safebrowsing_pb2.ThreatType.MALWARE: 0.98,
        safebrowsing_pb2.ThreatType.SOCIAL_ENGINEERING: 0.95,
        safebrowsing_pb2.ThreatType.UNWANTED_SOFTWARE: 0.94,
        safebrowsing_pb2.ThreatType.POTENTIALLY_HARMFUL_APPLICATION: 0.92,
    }
    confidence = confidence_map.get(detail.threat_type, 0.9)
    return label, confidence


def predict_url(url_input: str, model_path=None, reachability: Optional[Dict[str, Any]] = None):
    """Use Google Safe Browsing to classify a single URL."""
    api_key = _env_model_url("SAFE_BROWSING_API_KEY", "SAFE_BROWSING_API_KEY")
    if not api_key:
        raise RuntimeError("SAFE_BROWSING_API_KEY is required for URL predictions.")

    if reachability is None:
        reachability = _probe_url(url_input)
    else:
        reachability = reachability if isinstance(reachability, dict) else {}

    if not reachability.get('reachable'):
        # Skip Safe Browsing lookup when the host is not reachable
        return {"label": "unreachable", "confidence": 0.0, "reachability": reachability}

    try:
        sb_result = _safe_browsing_lookup(url_input, api_key)
    except requests.RequestException as exc:
        logging.exception("Safe Browsing lookup failed")
        raise RuntimeError(f"Model prediction failed: {exc}")

    sb_result['reachability'] = reachability
    return sb_result


def probe_url(url_input: str) -> Dict[str, Any]:
    """Expose the reachability probe so the UI can pre-check the hostname."""
    return _probe_url(url_input)

def predict_email(subject: str, body: str, model_path="models/email_model.joblib"):
    """Predict email content using the cached email model (subject+body only)."""
    # Use your secret MODEL_EMAIL
    model_url = _env_model_url("EMAIL_MODEL_URL", "MODEL_EMAIL")
    model = load_model(model_path, model_url)
    content = " ".join(filter(None, [subject, body])).strip()
    payload = [content or "empty"]
    return _model_predict(model, payload)
