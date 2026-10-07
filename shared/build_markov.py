"""Section 4 — Build Next-Action Predictor (Markov chain).

Defines action categories, builds a transition probability table from
training sessions, evaluates accuracy, and persists the table.
READ-ONLY against the database.

When run directly: builds, evaluates, and saves the transition table.
When imported: only ACTION_CATEGORIES and classify_action() are available.
"""
import json
import sys
import warnings
from pathlib import Path
warnings.filterwarnings("ignore")

sys.path.insert(0, str(Path(__file__).resolve().parent))

from features import _SQLI_PATTERNS, _has_sqli_in_params, _has_traversal_in_params

# ── Section 4.1: Action categories (importable by predictor.py) ──
ACTION_CATEGORIES = ["recon", "auth_probe", "sqli_attempt", "config_probe", "other"]


def classify_action(action: str, parameters: dict = None) -> str:
    if parameters is None:
        parameters = {}

    lower = action.lower()

    if _has_sqli_in_params(parameters):
        return "sqli_attempt"

    if any(p in lower for p in ["/robots.txt", "/sitemap.xml", "/server-status",
                                  "/server-info", "/.htaccess", "/readme.html",
                                  "/license.txt", "/wp-includes/", "/wp-content/",
                                  "/wp-admin", "/administrator", "/.git/config",
                                  "/.svn/entries", "/web.config", "/crossdomain.xml"]):
        return "recon"

    if "post" in lower and any(p in lower for p in ["/login", "/admin", "/wp-admin",
                                                      "/administrator", "/api/login"]):
        return "auth_probe"

    if any(p in lower for p in ["/.env", "/config.php.bak", "/backup.zip",
                                  "/database.sql", "/db.sql", "/dump.sql",
                                  "/.DS_Store", "/wp-config.php.bak"]):
        return "config_probe"

    return "other"


def build_transition_table(session_ids, db):
    transition_counts = {}
    all_transitions = 0

    for sid in session_ids:
        logs = db.execute(
            "SELECT action, parameters FROM logs WHERE session_id = ? ORDER BY timestamp ASC",
            (sid,),
        ).fetchall()

        categories = [classify_action(log["action"],
                                       json.loads(log["parameters"]) if isinstance(log["parameters"], str) else log["parameters"])
                      for log in logs]

        for i in range(len(categories) - 1):
            from_cat = categories[i]
            to_cat = categories[i + 1]

            if from_cat not in transition_counts:
                transition_counts[from_cat] = {}
            transition_counts[from_cat][to_cat] = transition_counts[from_cat].get(to_cat, 0) + 1
            all_transitions += 1

    transition_table = {}
    for from_cat in ACTION_CATEGORIES:
        counts = transition_counts.get(from_cat, {})
        total = sum(counts.values())
        if total > 0:
            transition_table[from_cat] = {to_cat: count / total for to_cat, count in counts.items()}
        else:
            transition_table[from_cat] = {cat: 1.0 / len(ACTION_CATEGORIES) for cat in ACTION_CATEGORIES}

    return transition_table, all_transitions
