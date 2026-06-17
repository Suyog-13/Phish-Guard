"""
feature_extraction.py
----------------------
Turns a raw URL string into a fixed-length numeric feature vector plus a
human-readable list of "checks" (used by both the training script and the
live Flask API, so the model always sees exactly what the UI explains).

All features are LEXICAL / structural only — they are computed from the
URL string itself (scheme, host, path, query) with no network calls
(no DNS, no WHOIS, no live page fetch). That keeps the detector fast,
offline-friendly, and safe to run against untrusted input.
"""

import re
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Reference lists used by several heuristics below.
# These are illustrative / commonly-cited patterns from phishing research,
# not a live threat feed.
# ---------------------------------------------------------------------------

SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "account", "update", "confirm", "signin",
    "password", "bank", "paypal", "ebay", "webscr", "recover", "unlock",
    "suspend", "billing", "invoice", "wallet", "support", "security",
]

SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "bl.ink", "rebrand.ly", "cutt.ly",
]

# Free / low-cost TLDs that show up disproportionately often in phishing
# reports. This is a heuristic signal, not proof of anything by itself.
SUSPICIOUS_TLDS = [
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work", "click",
    "loan", "win", "men", "gdn", "info", "support",
]

IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

# Fixed order — training and inference must agree on this list.
FEATURE_ORDER = [
    "url_length",
    "hostname_length",
    "path_length",
    "num_dots",
    "num_hyphens",
    "num_at_symbols",
    "num_question_marks",
    "num_equal_signs",
    "num_underscores",
    "num_percent_signs",
    "num_ampersands",
    "num_digits",
    "digit_ratio",
    "num_subdomains",
    "has_ip_host",
    "is_https",
    "https_in_path_or_host",
    "is_shortened",
    "suspicious_word_count",
    "has_nonstandard_port",
    "has_dash_in_domain",
    "suspicious_tld",
    "num_redirect_tokens",
]


def _ensure_scheme(url: str) -> str:
    """If the user pasted a bare domain ('example.com/login'), assume http
    so urlparse can split host/path correctly. Doesn't change scoring of
    the https feature below — that's read from the ORIGINAL string."""
    if "://" not in url:
        return "http://" + url
    return url


def extract_features(raw_url: str) -> dict:
    """Returns an ordered dict of {feature_name: numeric_value} for one URL."""
    raw_url = raw_url.strip()
    parsed = urlparse(_ensure_scheme(raw_url))

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    full = raw_url

    labels = hostname.split(".") if hostname else []
    tld = labels[-1].lower() if len(labels) >= 2 else ""
    # crude subdomain count: anything before the registrable domain+tld
    num_subdomains = max(len(labels) - 2, 0)

    digits = sum(c.isdigit() for c in full)

    feats = {
        "url_length": len(full),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "num_dots": full.count("."),
        "num_hyphens": full.count("-"),
        "num_at_symbols": full.count("@"),
        "num_question_marks": full.count("?"),
        "num_equal_signs": full.count("="),
        "num_underscores": full.count("_"),
        "num_percent_signs": full.count("%"),
        "num_ampersands": full.count("&"),
        "num_digits": digits,
        "digit_ratio": round(digits / len(full), 4) if full else 0,
        "num_subdomains": num_subdomains,
        "has_ip_host": 1 if IPV4_RE.match(hostname) else 0,
        "is_https": 1 if parsed.scheme.lower() == "https" else 0,
        "https_in_path_or_host": 1 if "https" in (hostname + path + query).lower().replace(parsed.scheme, "", 1) else 0,
        "is_shortened": 1 if hostname.lower() in SHORTENER_DOMAINS else 0,
        "suspicious_word_count": sum(w in full.lower() for w in SUSPICIOUS_WORDS),
        "has_nonstandard_port": 1 if (parsed.port and parsed.port not in (80, 443)) else 0,
        "has_dash_in_domain": 1 if "-" in hostname else 0,
        "suspicious_tld": 1 if tld in SUSPICIOUS_TLDS else 0,
        "num_redirect_tokens": max(full.count("//") - 1, 0),
    }
    return feats


def feature_vector(raw_url: str):
    """Returns (list_of_values_in_FEATURE_ORDER, feats_dict)."""
    feats = extract_features(raw_url)
    vector = [feats[name] for name in FEATURE_ORDER]
    return vector, feats


# ---------------------------------------------------------------------------
# Human-readable "scan log" used by the frontend to explain a verdict.
# Each entry says what was checked, what was found, and whether it's a
# red flag. This is independent of (and a sanity check on) the ML model.
# ---------------------------------------------------------------------------

def explain(feats: dict) -> list:
    checks = []

    def add(id_, label, value, flag, severity="medium"):
        checks.append({
            "id": id_, "label": label, "value": value,
            "flag": bool(flag), "severity": severity,
        })

    add("length", "Overall URL length", f"{feats['url_length']} characters",
        feats["url_length"] > 75, "low")
    add("ip_host", "Domain is a raw IP address", "yes" if feats["has_ip_host"] else "no",
        feats["has_ip_host"], "high")
    add("https", "Uses HTTPS", "yes" if feats["is_https"] else "no",
        not feats["is_https"], "low")
    add("https_token", "'https' appears outside the scheme (a known disguise trick)",
        "yes" if feats["https_in_path_or_host"] else "no",
        feats["https_in_path_or_host"], "medium")
    add("shortener", "Uses a known link-shortening service", "yes" if feats["is_shortened"] else "no",
        feats["is_shortened"], "medium")
    add("subdomains", "Number of subdomains", feats["num_subdomains"],
        feats["num_subdomains"] >= 3, "medium")
    add("hyphens", "Hyphens in the URL", feats["num_hyphens"],
        feats["num_hyphens"] >= 3, "low")
    add("dash_domain", "Hyphen inside the domain itself", "yes" if feats["has_dash_in_domain"] else "no",
        feats["has_dash_in_domain"], "medium")
    add("at_symbol", "Contains '@' (can hide the real destination)", feats["num_at_symbols"],
        feats["num_at_symbols"] > 0, "high")
    add("suspicious_words", "Sensitive keywords found (login, verify, secure...)",
        feats["suspicious_word_count"], feats["suspicious_word_count"] >= 2, "medium")
    add("tld", "Top-level domain commonly abused in phishing reports",
        "yes" if feats["suspicious_tld"] else "no", feats["suspicious_tld"], "low")
    add("port", "Uses a non-standard port", "yes" if feats["has_nonstandard_port"] else "no",
        feats["has_nonstandard_port"], "medium")
    add("digit_ratio", "Share of the URL made of digits", f"{feats['digit_ratio']*100:.0f}%",
        feats["digit_ratio"] > 0.25, "low")
    add("redirects", "Extra '//' redirect-style tokens", feats["num_redirect_tokens"],
        feats["num_redirect_tokens"] > 0, "medium")

    return checks
