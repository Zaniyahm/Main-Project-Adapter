"""
shared/decision.py
====================
The Common Decision Contract (Phase 2, sub-goal 2): the single,
protocol-agnostic envelope every adapter's decision-making passes
through, on its way from "what should we do" to "what bytes do we
actually send back".

Today, every adapter's `payload` is protocol-specific (MySQL's
ResponsePlan, later Postgres's own equivalent, later HTTP's own) and
every Decision is produced by simple rule-based logic (source="rules").
Nothing about *that* changes here — this file exists so later phases
(the ML classifier in Phase 9, the RL policy in Phase 10) can swap out
*how* a Decision gets produced without any adapter needing to change
how it *consumes* one. The shape is fixed now specifically so it
doesn't need to change again once Postgres (Phase 3) or the AI engine
show up — retrofitting a field onto N adapters later is more expensive
than reserving it, unused, while only one adapter exists.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

DecisionAction = Literal[
    "serve_data",           # respond with the payload as-is
    "reject_auth",          # deny login / access (not yet wired — see note below)
    "delay",                # (Phase 10) stall the response to waste attacker time
    "escalate_error",       # respond with an error — a plausible, intentional failure
    "serve_decoy_variant",  # (Phase 10) serve an alternate fake dataset/behavior
]

DecisionSource = Literal["rules", "ml", "rl", "fallback_static"]


@dataclass
class Decision:
    """
    action:      what kind of behavior this decision represents, at a
                 level every adapter and the future AI engine both
                 understand — regardless of protocol.
    payload:     the protocol-specific data needed to actually render
                 this decision as real bytes (e.g. a MySQL ResponsePlan).
                 Opaque to anything outside the owning adapter.
    latency_ms:  reserved for Phase 10's RL policy (varying response
                 timing as a deception lever). Unused and always 0
                 until then.
    confidence:  reserved for Phase 9's ML classifier. Rule-based
                 decisions (today) are always fully confident (1.0).
    source:      which layer produced this decision. Always "rules"
                 until Phase 9/10 exist.
    reason:      human-readable label for logging/debugging — mirrors
                 whatever the producing layer used internally (e.g.
                 ResponsePlan.reason for MySQL today).

    NOTE: login accept/reject does not route through this contract yet
    — it remains a plain boolean via userdb.check_login(). "reject_auth"
    is reserved here for when that gets unified in a later phase; wiring
    it in now would expand this sub-goal's scope beyond query/command
    decisions, which is all decide_response() currently owns.
    """

    action: DecisionAction
    payload: Any = None
    latency_ms: int = 0
    confidence: float = 1.0
    source: DecisionSource = "rules"
    reason: str = ""
