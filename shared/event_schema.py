"""
shared/event_schema.py
========================
Phase 4, sub-goal 2: the Common Event Schema every adapter's logging
conforms to, so a dashboard consuming events from MySQL, Postgres, and
any future adapter sees one consistent shape regardless of source.

STATUS: field names and the reason->stage/intent mapping below are
PROVISIONAL — finalized shape is pending real integration with the
teammate's dashboard (agreed explicitly: adjust after integration,
not before). Everything adjustable lives in ONE place — the
REASON_TO_STAGE / REASON_TO_INTENT dicts and DISPLAY_STAGE_FALLBACK
below — specifically so a post-integration tweak means editing a
handful of dict entries here, not touching either adapter's code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

# Your team's real 4-stage lifecycle. Adapters always log the TRUE
# stage here — nothing about this list changes based on what any
# particular dashboard can currently display.
STAGES = ("recon", "credential_attack", "injection_attempt", "exfiltration_attempt")

# If a downstream dashboard only understands a subset of STAGES (e.g.
# 3 stages, no "injection_attempt"), map the unsupported one to the
# closest bucket it already renders. The TRUE stage is never lost —
# it's still in CommonEvent.stage; this fallback only affects what
# display_stage() returns for UI purposes. Delete an entry here (or
# the whole dict) once the dashboard supports all 4 stages natively.
DISPLAY_STAGE_FALLBACK: dict[str, str] = {
    "injection_attempt": "exfiltration_attempt",  # placeholder — confirm/adjust post-integration
}

# Maps each adapter's internal `reason` string (from ResponsePlan /
# PostgresResponsePlan) to a (stage, intent) pair. Both adapters'
# reason vocabularies were deliberately named consistently
# (recon_*, data_access_*_table, injection_pattern_detected, etc.)
# specifically so ONE mapping table works for both — this is the
# payoff of that naming discipline.
REASON_TO_STAGE_INTENT: dict[str, tuple[str, str]] = {
    # --- recon ---
    "recon_show_databases": ("recon", "enumeration"),
    "recon_show_tables": ("recon", "enumeration"),
    "recon_show_tables_unknown_db": ("recon", "enumeration"),
    "recon_list_databases": ("recon", "enumeration"),
    "recon_list_tables": ("recon", "enumeration"),
    "recon_version_query": ("recon", "fingerprinting"),
    "recon_version_comment_query": ("recon", "fingerprinting"),
    "recon_system_variable_query": ("recon", "fingerprinting"),
    "recon_show_variable": ("recon", "fingerprinting"),
    "recon_show_variables": ("recon", "fingerprinting"),
    "recon_current_db_query": ("recon", "fingerprinting"),
    "recon_current_user_query": ("recon", "fingerprinting"),
    "recon_session_user_query": ("recon", "fingerprinting"),
    "recon_use_database_valid": ("recon", "enumeration"),
    "recon_use_database_unknown": ("recon", "enumeration"),
    "client_housekeeping_set": ("recon", "session_setup"),
    "client_housekeeping_reset": ("recon", "session_setup"),
    # any table-describe reason, e.g. "recon_describe_table_users"
    # matched via prefix check in from_reason() below, not listed here.

    # --- credential_attack ---
    "login_attempt": ("credential_attack", "credentials"),
    "login_failed": ("credential_attack", "brute_force"),
    "login_success": ("credential_attack", "credentials"),

    # --- injection_attempt ---
    "injection_pattern_detected": ("injection_attempt", "sqli_probe"),
    "exploitation_copy_to_program_attempt": ("injection_attempt", "rce_attempt"),
    "unrecognized_statement": ("injection_attempt", "probing"),

    # --- exfiltration_attempt ---
    "data_access_users_table": ("exfiltration_attempt", "data_theft"),
    "data_access_orders_table": ("exfiltration_attempt", "data_theft"),
    "data_access_sessions_table": ("exfiltration_attempt", "data_theft"),
    "data_access_audit_log_table": ("exfiltration_attempt", "data_theft"),
    "write_query_faked_success": ("exfiltration_attempt", "data_manipulation"),
    "unrecognized_read_query": ("recon", "enumeration"),
    "disconnect": ("recon", "session_end"),
}

DEFAULT_STAGE_INTENT = ("recon", "unknown")


def _lookup_stage_intent(reason: str) -> tuple[str, str]:
    if reason in REASON_TO_STAGE_INTENT:
        return REASON_TO_STAGE_INTENT[reason]
    if reason.startswith("recon_describe_table_"):
        return ("recon", "enumeration")
    if reason.startswith("data_access_"):
        return ("exfiltration_attempt", "data_theft")
    return DEFAULT_STAGE_INTENT


@dataclass
class CommonEvent:
    """
    The shared event shape. `stage` and `intent` are ALWAYS the true
    values (derived via from_reason() below) — display_stage() is the
    only place a dashboard-compatibility fallback is applied, and only
    for rendering, never for storage or future ML training data.
    """

    event_id: str
    session_id: str
    source_ip: str
    protocol: str            # "mysql" | "postgresql" | ...
    action: str
    stage: str                # one of STAGES — the TRUE value, always
    intent: str
    confidence: float
    reason: str
    response_status: Any = None
    response_type: str = ""
    metadata: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def display_stage(self) -> str:
        """Dashboard-safe stage value — see DISPLAY_STAGE_FALLBACK above."""
        return DISPLAY_STAGE_FALLBACK.get(self.stage, self.stage)

    @classmethod
    def from_reason(
        cls, *, event_id: str, session_id: str, source_ip: str, protocol: str,
        action: str, reason: str, confidence: float = 1.0,
        response_status: Any = None, response_type: str = "",
        metadata: Optional[dict] = None,
    ) -> "CommonEvent":
        """
        The one place an adapter's `reason` string (already produced by
        decide_response()/pg_decide_response()) gets translated into
        stage+intent. Both adapters call this exact same classmethod —
        neither adapter contains its own stage/intent logic.
        """
        stage, intent = _lookup_stage_intent(reason)
        return cls(
            event_id=event_id, session_id=session_id, source_ip=source_ip,
            protocol=protocol, action=action, stage=stage, intent=intent,
            confidence=confidence, reason=reason,
            response_status=response_status, response_type=response_type,
            metadata=metadata or {},
        )
