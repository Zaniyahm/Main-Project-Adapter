"""
scripts/baseline_accuracy.py
===============================
Phase 6, formalized: scores the rule-based baseline
(shared/rl_policy.py's stage_from_reason(), fed by decide_response()'s
`reason` labels) against a small hand-labeled test set.

Runs against a SEPARATE test database (test_utils.py's convention,
borrowed from the web adapter's own test infrastructure) via
HONEYPOT_DB_PATH — never the live shared DB.
"""
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

TEST_DB_PATH = str(Path(__file__).resolve().parent.parent / "shared" / "instance" / "test_honeypot.db")

# (query, expected_stage) — ground truth, hand-labeled.
LABELED_QUERIES = [
    ("SHOW DATABASES;", "recon"),
    ("SHOW TABLES;", "recon"),
    ("SELECT @@version;", "recon"),
    ("SELECT VERSION();", "recon"),
    ("SELECT * FROM users WHERE 1=1 UNION SELECT 1,2,3,4-- ", "injection_attempt"),
    ("SELECT * FROM users", "exfiltration_attempt"),
    ("SELECT * FROM orders", "exfiltration_attempt"),
    ("SELECT * FROM audit_log", "exfiltration_attempt"),
]


def main():
    import os
    os.environ["HONEYPOT_DB_PATH"] = TEST_DB_PATH
    os.environ["RL_FORCE_ACTION"] = "serve_data"  # isolate the RULE baseline — no RL variation for this test

    from shared.core_db import setup_database
    Path(TEST_DB_PATH).unlink(missing_ok=True)
    setup_database(TEST_DB_PATH)

    from mysql_adapter.decide_response import _rule_based_plan
    from shared.rl_policy import _stage_from_reason as stage_from_reason

    correct = 0
    print(f"{'query':<60} {'expected':<22} {'got':<22} {'match'}")
    print("-" * 115)
    for query, expected in LABELED_QUERIES:
        plan = _rule_based_plan("test-session", query, {})
        got = stage_from_reason(plan.reason)
        match = got == expected
        correct += match
        print(f"{query[:58]:<60} {expected:<22} {got:<22} {'YES' if match else 'NO'}")

    accuracy = correct / len(LABELED_QUERIES)
    print("-" * 115)
    print(f"\nRule-based baseline accuracy: {correct}/{len(LABELED_QUERIES)} = {accuracy:.1%}")
    print(f"(scored against test DB: {TEST_DB_PATH}, live DB untouched)")


if __name__ == "__main__":
    main()
