"""
shared/rl_policy.py
======================
Day 1 task 3 (RL pulled forward from Phase 10): a tabular Q-learning
policy that chooses an ADAPTIVE ACTION on top of decide_response()'s
already-decided fake content — it never changes WHAT fake data gets
served, only HOW: delay the response, subtly vary the data, or
escalate to a fake permission error even when the rule-based logic
would have served data normally.

Uses the exact action vocabulary already defined in shared/decision.py
(Decision.action: serve_data | delay | serve_decoy_variant |
escalate_error) rather than inventing a second one.

HONEST SCOPING: with only a few days of live traffic, this will NOT
converge to statistically meaningful learned behavior by any near-term
deadline — genuine Q-learning needs many sessions per state to learn
anything real. What's actually true and demonstrable today: the
MECHANISM is live — state is tracked per session, actions are chosen
via an epsilon-greedy policy over a Q-table seeded with sensible
priors, and a real reward signal (session engagement time) updates it
after every session. The table keeps learning from every session run
against it from now on; convergence is a function of deployment time,
not code.
"""

from __future__ import annotations

import os
import random
import time

ACTIONS = ["serve_data", "delay", "serve_decoy_variant", "escalate_error"]

EPSILON = 0.15       # exploration rate
LEARNING_RATE = 0.2
DELAY_MS = 300        # kept short deliberately so tests/demos don't hang

# Testing hook ONLY: forces every choice to this action, bypassing the
# policy, so each action path can be verified deterministically instead
# of waiting on random epsilon-greedy draws. Never set in production.
_FORCE_ACTION = os.environ.get("RL_FORCE_ACTION")

# Seed priors (not learned — a starting point): after injection-looking
# behavior, favor delay/escalate (waste time, look locked-down); for
# plain recon, mostly serve_data so the session keeps looking real and
# keeps generating data instead of getting suspicious immediately.
_DEFAULT_Q = {
    "recon":                 {"serve_data": 1.0, "delay": 0.2, "serve_decoy_variant": 0.3, "escalate_error": -0.5},
    "credential_attack":     {"serve_data": 0.5, "delay": 0.6, "serve_decoy_variant": 0.2, "escalate_error": 0.1},
    "injection_attempt":     {"serve_data": -0.3, "delay": 0.7, "serve_decoy_variant": 0.4, "escalate_error": 0.6},
    "exfiltration_attempt":  {"serve_data": 0.2, "delay": 0.5, "serve_decoy_variant": 0.7, "escalate_error": 0.3},
    "unknown":                {"serve_data": 0.5, "delay": 0.0, "serve_decoy_variant": 0.0, "escalate_error": -0.2},
}

_q_table: dict[str, dict[str, float]] = {k: dict(v) for k, v in _DEFAULT_Q.items()}

# Per-session tracking, in-memory (fine at this scale) — used to compute
# a reward once the outcome of the last decision is known (next event,
# or session end).
_session_state: dict[str, dict] = {}


def _stage_from_reason(reason: str) -> str:
    """Coarse state bucket from decide_response()'s `reason` string."""
    if not reason:
        return "unknown"
    if "injection" in reason or "copy_to_program" in reason:
        return "injection_attempt"
    if reason.startswith("recon_") or reason.startswith("client_housekeeping") or reason == "unrecognized_read_query":
        return "recon"
    if reason.startswith("data_access_"):
        return "exfiltration_attempt"
    if reason in ("login_attempt", "login_failed", "login_success"):
        return "credential_attack"
    return "unknown"


def choose_action(session_id: str, reason: str) -> tuple[str, str]:
    """
    Returns (action, state). Also closes the reward loop for this
    session's PREVIOUS decision — if a new event arrived, the attacker
    stuck around, which is treated as a positive engagement signal.
    """
    state = _stage_from_reason(reason)
    q_row = _q_table.setdefault(state, dict.fromkeys(ACTIONS, 0.0))

    if random.random() < EPSILON:
        action = random.choice(ACTIONS)
    else:
        action = max(q_row, key=q_row.get)

    if _FORCE_ACTION in ACTIONS:
        action = _FORCE_ACTION

    prev = _session_state.get(session_id)
    if prev is not None:
        _update(prev["state"], prev["action"], reward=1.0)

    _session_state[session_id] = {"state": state, "action": action, "ts": time.time()}
    return action, state


def record_session_end(session_id: str) -> None:
    """
    Called on disconnect/terminate. A session that ends very soon after
    the last decision is treated as likely abandonment (attacker may
    have detected something) — a negative signal — vs. a normal
    wind-down after some activity.
    """
    prev = _session_state.pop(session_id, None)
    if prev is None:
        return
    elapsed = time.time() - prev["ts"]
    reward = -1.0 if elapsed < 2.0 else 0.3
    _update(prev["state"], prev["action"], reward)


def _update(state: str, action: str, reward: float) -> None:
    q_row = _q_table.setdefault(state, dict.fromkeys(ACTIONS, 0.0))
    q_row[action] = q_row.get(action, 0.0) + LEARNING_RATE * (reward - q_row.get(action, 0.0))


def get_q_table() -> dict:
    """For inspection/debugging/demo — e.g. print this after a test run."""
    return {k: dict(v) for k, v in _q_table.items()}
