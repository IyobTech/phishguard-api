from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlsplit

import numpy as np
from scipy import sparse
from sklearn.base import BaseEstimator, TransformerMixin

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "link", "work", "live", "online",
    "site", "shop", "club", "icu", "buzz", "rest", "fit", "cfd", "gq", "tk",
    "ml", "ga", "cf", "win", "loan", "download", "stream", "pro", "support",
}

SUSPICIOUS_KEYWORDS = {
    "login", "log-in", "signin", "sign-in", "verify", "verification", "secure",
    "security", "account", "update", "confirm", "confirmation", "password", "passwd",
    "credential", "wallet", "payment", "billing", "invoice", "bank", "banking", "paypal",
    "amazon", "microsoft", "apple", "google", "facebook", "instagram", "netflix",
    "dhl", "fedex", "ups", "irs", "crypto", "bitcoin", "bonus", "gift", "reward",
    "free", "urgent", "suspended", "unlock", "recover", "support", "helpdesk", "otp",
}

BRAND_KEYWORDS = {
    "google", "microsoft", "apple", "amazon", "paypal", "facebook", "instagram", "netflix",
    "linkedin", "twitter", "x.com", "dropbox", "adobe", "dhl", "fedex", "ups", "spotify",
    "steam", "binance", "coinbase", "bank", "visa", "mastercard", "amex",
}


def _safe_url(url: str) -> str:
    return str(url).strip()


def _parse(url: str):
    raw = _safe_url(url)
    candidate = raw if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw) else "http://" + raw
    try:
        return urlsplit(candidate)
    except ValueError:
        return urlsplit("http://invalid.local")


def _is_ip(hostname: str) -> int:
    host = hostname.strip("[]")
    try:
        ipaddress.ip_address(host)
        return 1
    except ValueError:
        return 0


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return float(-sum((c / n) * math.log2(c / n) for c in counts.values()))


def extract_url_features(url: str) -> list[float]:
    raw = _safe_url(url)
    parts = _parse(raw)
    host = (parts.hostname or "").lower()
    path = parts.path or ""
    query = parts.query or ""
    fragment = parts.fragment or ""
    full_lower = raw.lower()

    length = len(raw)
    letters = sum(ch.isalpha() for ch in raw)
    digits = sum(ch.isdigit() for ch in raw)
    special = sum(not ch.isalnum() for ch in raw)
    host_digits = sum(ch.isdigit() for ch in host)
    path_segments = len([p for p in path.split("/") if p])
    query_params = 0 if not query else query.count("&") + 1
    subdomains = max(0, len([p for p in host.split(".") if p]) - 2)
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    keyword_hits = sum(1 for k in SUSPICIOUS_KEYWORDS if k in full_lower)
    brand_hits = sum(1 for k in BRAND_KEYWORDS if k in full_lower)
    percent_encoded = len(re.findall(r"%[0-9a-fA-F]{2}", raw))
    repeated_separator = int(bool(re.search(r"[._-]{2,}", raw)))

    features = [
        length,
        len(host),
        len(path),
        len(query),
        len(fragment),
        len(parts.scheme),
        raw.count("."),
        raw.count("-"),
        raw.count("_"),
        raw.count("/"),
        raw.count("?"),
        raw.count("="),
        raw.count("&"),
        raw.count("@"),
        raw.count("%"),
        raw.count("#"),
        raw.count(":"),
        raw.count("\\"),
        raw.count(";") ,
        raw.count("+"),
        raw.count(","),
        digits,
        letters,
        special,
        host_digits,
        sum(1 for ch in path if ch.isdigit()),
        sum(1 for ch in query if ch.isdigit()),
        digits / max(1, length),
        letters / max(1, length),
        special / max(1, length),
        host_digits / max(1, len(host)),
        int(parts.scheme.lower() == "https"),
        int(parts.scheme.lower() == "http"),
        int(_is_ip(host)),
        int("xn--" in host.lower()),
        int("@" in raw),
        int(bool(parts.port)),
        subdomains,
        len(tld),
        int(tld in SUSPICIOUS_TLDS),
        path_segments,
        query_params,
        keyword_hits,
        brand_hits,
        percent_encoded,
        repeated_separator,
        _entropy(raw),
        _entropy(host),
        int(bool(re.search(r"//.+//", raw.replace("https://", "").replace("http://", "")))),
    ]
    return [float(x) for x in features]


def explain_url(url: str) -> list[str]:
    raw = _safe_url(url)
    parts = _parse(raw)
    host = (parts.hostname or "").lower()
    full_lower = raw.lower()
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    signals: list[str] = []

    if len(raw) > 120:
        signals.append("URL is unusually long")
    if len(host) > 45:
        signals.append("hostname is unusually long")
    if raw.count(".") >= 5:
        signals.append("many subdomain/domain separators")
    if raw.count("-") >= 4:
        signals.append("many hyphens")
    if raw.count("@") > 0:
        signals.append("contains @ in the URL")
    if "xn--" in host:
        signals.append("contains punycode hostname")
    if _is_ip(host):
        signals.append("uses an IP address instead of a normal domain")
    if tld in SUSPICIOUS_TLDS:
        signals.append(f"uses a TLD often seen in suspicious URL datasets (.{tld})")
    keyword_matches = [k for k in SUSPICIOUS_KEYWORDS if k in full_lower]
    if keyword_matches:
        signals.append("contains security/account-related keywords")
    brand_matches = [k for k in BRAND_KEYWORDS if k in full_lower]
    if brand_matches:
        signals.append("contains a recognizable brand/service name in the URL")
    if "%" in raw:
        signals.append("contains percent-encoded characters")
    if parts.scheme.lower() == "http":
        signals.append("uses HTTP rather than HTTPS")
    if len([p for p in host.split(".") if p]) >= 5:
        signals.append("has multiple hostname levels")

    if not signals:
        signals.append("no strong lexical warning signal was detected")
    return signals[:8]


class URLFeatureExtractor(BaseEstimator, TransformerMixin):
    """Convert a 1-D URL sequence into sparse numeric lexical/security features."""

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        rows = [extract_url_features(str(x)) for x in X]
        matrix = np.asarray(rows, dtype=np.float32)
        return sparse.csr_matrix(matrix)
