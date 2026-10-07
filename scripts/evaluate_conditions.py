"""
scripts/evaluate_conditions.py
=================================
Phase 11 (pulled forward): the 3-condition comparison — Static vs
Rule-based vs RL — run against the same labeled query set used in
scripts/baseline_accuracy.py, against an isolated test DB (never live).

HONEST SCOPE: this is a MECHANISM comparison, not a real-world
evaluation. There is no deployed attacker traffic yet (Phase 8), so
"engagement time" here is a simulated proxy (total added latency,
response-variation rate) — not a measured real deception-success
outcome. A 4th condition (fully retrained ML classifier) is
deliberately NOT included — 2 days of hypothetical traffic is not
enough to responsibly retrain and claim the result means anything.
That is tracked as future work, not faked here.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

TEST_DB_PATH = str(Path(__file__).resolve().parent.parent / "shared" / "instance" / "test_honeypot.db")

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


def run_static(queries):
    """Floor baseline: same canned empty response regardless of input —
    Phase 0's "no logic at all" condition."""
    correct = 0  # static never classifies anything correctly by design
    total_latency = 0
    variation_count = 0  # static never varies its response
    return {
        "condition": "static",
        "stage_accuracy": 0.0,
        "total_latency_ms": total_latency,
        "response_variation_rate": 0.0,
    }


def run_rule_based(queries):
    from mysql_adapter.decide_response import _rule_based_plan
    from shared.rl_policy import _stage_from_reason as stage_from_reason

    correct = 0
    for query, expected in queries:
        plan = _rule_based_plan("eval-session-rule", query, {})
        got = stage_from_reason(plan.reason)
        correct += (got == expected)

    return {
        "condition": "rule_based",
        "stage_accuracy": correct / len(queries),
        "total_latency_ms": 0,  # rule engine alone never adds latency
        "response_variation_rate": 0.0,  # deterministic — same query, same response, always
    }


def run_rl(queries, trials=20):
    """
    RL's action selection is stochastic (epsilon-greedy), so unlike the
    other two conditions this is run multiple times to characterize its
    behavior distribution rather than a single deterministic pass.
    """
    os.environ.pop("RL_FORCE_ACTION", None)  # ensure real policy runs, not the test hook

    from mysql_adapter.decide_response import decide_response
    from shared.rl_policy import _stage_from_reason as stage_from_reason

    total_latency = 0
    variations = 0
    total_interactions = 0
    correct = 0

    for trial in range(trials):
        session_id = f"eval-session-rl-{trial}"
        for query, expected in queries:
            plan = decide_response(session_id, query, {})
            stage = stage_from_reason(plan.reason)
            correct += (stage == expected)
            total_interactions += 1
            if plan.rl_action == "delay":
                from shared.rl_policy import DELAY_MS
                total_latency += DELAY_MS
            if plan.rl_action != "serve_data":
                variations += 1

    return {
        "condition": "rl",
        "stage_accuracy": correct / total_interactions,
        "total_latency_ms": total_latency,
        "response_variation_rate": variations / total_interactions,
        "trials": trials,
    }


def main():
    os.environ["HONEYPOT_DB_PATH"] = TEST_DB_PATH
    from shared.core_db import setup_database
    Path(TEST_DB_PATH).unlink(missing_ok=True)
    setup_database(TEST_DB_PATH)

    results = [
        run_static(LABELED_QUERIES),
        run_rule_based(LABELED_QUERIES),
        run_rl(LABELED_QUERIES),
    ]

    print(f"{'condition':<14} {'stage_accuracy':<16} {'total_latency_ms':<18} {'response_variation_rate'}")
    print("-" * 70)
    for r in results:
        print(f"{r['condition']:<14} {r['stage_accuracy']:<16.1%} {r['total_latency_ms']:<18} {r['response_variation_rate']:.1%}")

    print("\nNotes:")
    print("- static: floor baseline, no classification logic at all")
    print("- rule_based: deterministic — same result every run")
    print(f"- rl: stochastic, averaged over {results[2]['trials']} trials (epsilon-greedy exploration)")
    print("- 'total_latency_ms' is a simulated added-delay proxy for attacker time wasted, not a")
    print("  measured real-world outcome — no deployed traffic exists yet to measure that against")
    print("- a 4th (fully retrained ML classifier) condition is intentionally excluded — tracked as")
    print("  future work pending real deployment data, not faked here")


if __name__ == "__main__":
    main()
