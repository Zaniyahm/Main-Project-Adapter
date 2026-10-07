"""Feature extraction pipeline for the Stage/Intent Classifier.

Provides a fixed-order numeric feature vector for each session, computed
exclusively from data available up to "now" (no future information).
Both training and live inference import FEATURE_NAMES and
extract_session_features from this module to guarantee feature order sync.
"""
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import core_db

# ---------------------------------------------------------------------------
# Feature names — single source of truth for training and inference
# ---------------------------------------------------------------------------
FEATURE_NAMES = [
    "request_count",
    "request_rate",
    "distinct_actions",
    "error_ratio",
    "has_sqli_pattern",
    "has_traversal_pattern",
    "has_xss_pattern",
    "auth_attempt_count",
    "time_since_session_start",
    "user_agent_category",
    "is_idle",
]

ANOMALY_FEATURE_NAMES = [f for f in FEATURE_NAMES if f != "is_idle"]

_SQLI_PATTERNS = [
    "' OR ",
    "' AND ",
    "'; --",
    "') OR ",
    "admin' --",
    "1' AND 1=",
    "' OR ''='",
    "UNION SELECT",
    "UNION ALL SELECT",
    "union select",
    "union all select",
]

_TRAVERSAL_PATTERNS = [
    "../",
    "..\\",
    "%2e%2e%2f",
    "%2e%2e/",
    "..%2f",
    "%2e%2e\\",
    "..%5c",
    "%2e%2e%5c",
]

_XSS_PATTERNS = [
    "<script",
    "</script",
    "javascript:",
    "onerror=",
    "onload=",
    "onclick=",
    "onmouseover=",
    "onfocus=",
    "onmouse",
    "onkey",
    "oninput=",
    "onsubmit=",
    "onchange=",
    "onresize=",
    "onabort=",
    "onanimation",
    "ontransition",
    "<img",
    "<svg",
    "<iframe",
    "<body",
    "<input",
    "<details",
    "<marquee",
    "<video",
    "<audio",
    "eval(",
    "alert(",
    "document.cookie",
    "document.domain",
    "window.location",
    "prompt(",
    "confirm(",
]

_TOOL_SIGNATURES = [
    "sqlmap", "nikto", "curl", "python-requests", "python-urllib",
    "wget", "go-http-client", "java/", "libwww", "scrapy", "httpclient",
    "nmap", "masscan", "zgrab", "gobuster", "dirbuster", "ffuf",
    "hydra", "medusa", "patator",
]

_BROWSER_SIGNATURES = [
    "chrome", "firefox", "safari", "edge", "opera", "msie", "trident",
    "mozilla",
]


def _classify_user_agent(user_agent: str) -> int:
    lower = user_agent.lower()
    for sig in _TOOL_SIGNATURES:
        if sig in lower:
            return 1
    for sig in _BROWSER_SIGNATURES:
        if sig in lower:
            return 2
    return 0


def _has_sqli_in_params(parameters: dict) -> bool:
    for key, value in parameters.items():
        if isinstance(value, list):
            value = " ".join(value)
        value_str = str(value).lower()
        for pattern in _SQLI_PATTERNS:
            if pattern.lower() in value_str:
                return True
    return False


def _has_traversal_in_params(parameters: dict) -> bool:
    for key, value in parameters.items():
        if isinstance(value, list):
            value = " ".join(value)
        value_str = str(value).lower()
        for pattern in _TRAVERSAL_PATTERNS:
            if pattern.lower() in value_str:
                return True
    return False


def _has_xss_in_params(parameters: dict) -> bool:
    for key, value in parameters.items():
        if isinstance(value, list):
            value = " ".join(value)
        value_str = str(value).lower()
        for pattern in _XSS_PATTERNS:
            if pattern.lower() in value_str:
                return True
    return False


def extract_session_features(session_id: str) -> list:
    db = core_db.get_db()

    sess = db.execute(
        "SELECT first_seen, last_seen, request_count, user_agent "
        "FROM sessions WHERE session_id = ?",
        (session_id,),
    ).fetchone()
    if sess is None:
        raise ValueError(f"Session {session_id} not found in sessions table")

    user_agent = sess["user_agent"] or ""

    logs = db.execute(
        "SELECT action, parameters, response_status FROM logs "
        "WHERE session_id = ? ORDER BY timestamp ASC",
        (session_id,),
    ).fetchall()

    request_count = sess["request_count"]

    try:
        first_seen = datetime.fromisoformat(sess["first_seen"])
        last_seen = datetime.fromisoformat(sess["last_seen"])
        duration_seconds = (last_seen - first_seen).total_seconds()
    except (TypeError, ValueError):
        duration_seconds = 0.0

    duration_minutes = duration_seconds / 60.0
    request_rate = request_count / duration_minutes if duration_minutes > 0 else float(request_count)

    distinct_actions = db.execute(
        "SELECT COUNT(DISTINCT action) as cnt FROM logs WHERE session_id = ?",
        (session_id,),
    ).fetchone()["cnt"]

    error_count = 0
    has_sqli = False
    has_traversal = False
    has_xss = False
    auth_attempt_count = 0

    for log in logs:
        status = log["response_status"]
        if status >= 400:
            error_count += 1

        parameters = json.loads(log["parameters"]) if isinstance(log["parameters"], str) else log["parameters"]

        if _has_sqli_in_params(parameters):
            has_sqli = True

        if _has_traversal_in_params(parameters):
            has_traversal = True

        if _has_xss_in_params(parameters):
            has_xss = True

        action_lower = log["action"].lower()
        if "post" in action_lower and any(
            p in action_lower
            for p in ["/login", "/admin", "/wp-admin", "/administrator", "/api/login"]
        ):
            auth_attempt_count += 1

    error_ratio = error_count / len(logs) if logs else 0.0

    now = datetime.now(timezone.utc)
    try:
        time_since_start = (now - first_seen).total_seconds()
    except (TypeError, ValueError):
        time_since_start = 0.0

    user_agent_category = _classify_user_agent(user_agent)

    is_idle = 1.0 if (time_since_start > core_db.SESSION_TIMEOUT_SECONDS and request_count <= 1) else 0.0

    return [
        float(request_count),
        request_rate,
        float(distinct_actions),
        error_ratio,
        1.0 if has_sqli else 0.0,
        1.0 if has_traversal else 0.0,
        1.0 if has_xss else 0.0,
        float(auth_attempt_count),
        time_since_start,
        float(user_agent_category),
        is_idle,
    ]
