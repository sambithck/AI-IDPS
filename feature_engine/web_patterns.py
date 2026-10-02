"""
feature_engine/web_patterns.py

Lightweight heuristic scanner for suspicious patterns in incoming
HTTP requests (query string, form body, headers). This produces a
"suspicious_pattern_score" that feeds into the feature vector — it is
NOT the final verdict, just a signal for the ML model.
"""

import re

SQLI_PATTERNS = [
    r"(\bunion\b.+\bselect\b)",
    r"(\bor\b\s+1\s*=\s*1)",
    r"(--|\#|;)\s*$",
    r"(\bdrop\b\s+\btable\b)",
    r"(\bxp_cmdshell\b)",
    r"('\s*or\s*')",
]

XSS_PATTERNS = [
    r"<script.*?>",
    r"onerror\s*=",
    r"onload\s*=",
    r"javascript:",
    r"<img[^>]+src",
]

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"/etc/passwd",
    r"boot\.ini",
]

CMD_INJECTION_PATTERNS = [
    r";\s*(cat|ls|whoami|id|wget|curl)\b",
    r"\|\s*(cat|ls|whoami|id)\b",
    r"`.*`",
]

ALL_PATTERNS = {
    "sqli": SQLI_PATTERNS,
    "xss": XSS_PATTERNS,
    "path_traversal": PATH_TRAVERSAL_PATTERNS,
    "cmd_injection": CMD_INJECTION_PATTERNS,
}

_COMPILED = {
    name: [re.compile(p, re.IGNORECASE) for p in patterns]
    for name, patterns in ALL_PATTERNS.items()
}


def score_request(full_target_string: str):
    """
    Returns (score, matched_categories)
    score: float 0.0 - 1.0+ (higher = more suspicious)
    matched_categories: list of pattern category names matched
    """
    if not full_target_string:
        return 0.0, []

    matched = []
    for category, patterns in _COMPILED.items():
        for p in patterns:
            if p.search(full_target_string):
                matched.append(category)
                break

    score = min(1.0, 0.35 * len(matched)) if matched else 0.0
    return score, matched


def build_target_string(path, query_string, body, headers=None):
    parts = [path or "", query_string or "", body or ""]
    if headers:
        parts.append(str(headers.get("User-Agent", "")))
    return " ".join(parts)
