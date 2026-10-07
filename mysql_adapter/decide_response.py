"""
mysql_adapter/decide_response.py
==================================

Job 3 from the adapter contract: a single, clean seam for the future
Control Engine to plug into. Every place in the adapter that decides
"what do I send back to the attacker" calls decide_response() — nothing
else in the adapter contains response-decision logic.

RIGHT NOW: simple rule-based canned logic (fixed fake schema/data,
pattern-matching on the SQL text) — no AI engine involved.

LATER: the body of decide_response() gets replaced with a call into the
shared Control Engine (Classifier + Predictor + Vulnerability Graph).
Callers of this function do not need to change at all when that swap
happens — only what's inside this function changes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

from mysql_adapter import fake_data
from shared import rl_policy
from shared.decision import Decision

ResponseKind = Literal["ok", "error", "resultset"]


@dataclass
class ResponsePlan:
    """What the adapter should send back for one COM_QUERY interaction."""

    kind: ResponseKind
    # Used when kind == "resultset"
    columns: list[str] = field(default_factory=list)
    rows: list[list[str]] = field(default_factory=list)
    table: str = ""
    # Used when kind == "error"
    error_code: int = 1064
    error_message: str = "You have an error in your SQL syntax"
    # Used when kind == "ok"
    affected_rows: int = 0
    # Free-form label describing why this decision was made — logged
    # alongside the event, useful later for the Classifier/analysts.
    reason: str = ""
    # Set by the RL policy layer (shared/rl_policy.py), not by the rule
    # engine itself. "serve_data" means the RL layer left the rule
    # engine's plan untouched.
    rl_action: str = "serve_data"


# --- lightweight pattern hints, purely for labeling right now --------
# NOTE: these are NOT a security control and NOT real SQLi detection —
# they only shape which canned fake reply looks most plausible, and
# give the logged event a useful `reason` label for later analysis.
_INJECTION_HINTS = re.compile(
    r"(\bunion\s+select\b|\bor\s+1\s*=\s*1\b|--\s|;\s*drop\b|\bsleep\s*\(|"
    r"\binto\s+outfile\b|\bload_file\s*\(|\bxp_cmdshell\b)",
    re.IGNORECASE,
)


def _rule_based_plan(session_id: str, action: str, parameters: dict) -> ResponsePlan:
    """
    action: the raw SQL text for a MySQL adapter's COM_QUERY interactions,
            or a synthesized "USE <db>" string for COM_INIT_DB interactions.
    parameters: currently unused here, reserved for future context
                (e.g. session history) the same way the real Control
                Engine will want it.
    """
    sql = action.strip()
    sql_lower = sql.lower()

    if _INJECTION_HINTS.search(sql):
        # Looks like a probing/injection-style query. A real, slightly
        # exposed backend would very plausibly throw a syntax error on
        # a malformed injection payload — that's what we return, which
        # keeps the interaction believable and invites the attacker to
        # keep iterating (more data captured) rather than instantly
        # revealing itself as fake.
        return ResponsePlan(
            kind="error",
            error_code=1064,
            error_message="You have an error in your SQL syntax; check the manual "
            "that corresponds to your MySQL server version",
            reason="injection_pattern_detected",
        )

    if sql_lower.startswith("use "):
        # COM_INIT_DB arrives here as a synthesized "USE <db>" string
        # (see server.py); a client typing "USE app_db;" as a query
        # arrives here too. Extract the name with the same \w+ pattern
        # used by the SHOW TABLES FROM branch below, rather than naive
        # slicing — a trailing ';' or extra whitespace must not leak
        # into the extracted name, or a valid database gets falsely
        # rejected as unknown.
        db_match = re.match(r"^use\s+`?(\w+)`?", sql, re.IGNORECASE)
        db_name = db_match.group(1) if db_match else ""
        if db_name in fake_data.FAKE_DATABASES:
            return ResponsePlan(kind="ok", reason="recon_use_database_valid")
        return ResponsePlan(
            kind="error",
            error_code=1049,
            error_message=f"Unknown database '{db_name}'",
            reason="recon_use_database_unknown",
        )

    if sql_lower.startswith("set "):
        # Client housekeeping (SET NAMES, SET autocommit, SET
        # character_set_results, etc.) — real servers just ack these.
        return ResponsePlan(kind="ok", reason="client_housekeeping_set")

    if sql_lower.startswith("show variables"):
        return ResponsePlan(
            kind="resultset",
            columns=["Variable_name", "Value"],
            rows=[],
            reason="recon_show_variables",
        )

    if "select @@version_comment" in sql_lower:
        # Must be checked BEFORE the generic "^select @@..." branch below —
        # that broader pattern also matches this query, and being listed
        # first would silently swallow it, which is exactly the ordering
        # bug that caused this to return an empty placeholder instead of
        # the real fake version comment.
        return ResponsePlan(
            kind="resultset",
            columns=["@@version_comment"],
            rows=[[fake_data.FAKE_VERSION_COMMENT]],
            reason="recon_version_comment_query",
        )

    if re.match(r"^select\s+@@", sql_lower):
        # Generic system-variable probe (@@version, @@sql_mode, etc.)
        # not covered by a specific rule above — return a single
        # plausible placeholder rather than erroring the connection.
        return ResponsePlan(
            kind="resultset",
            columns=["@@var"],
            rows=[[""]],
            reason="recon_system_variable_query",
        )

    if re.match(r"^select\s+version\s*\(\s*\)", sql_lower):
        return ResponsePlan(
            kind="resultset",
            columns=["VERSION()"],
            rows=[[fake_data.FAKE_VERSION]],
            reason="recon_version_query",
        )

    if re.match(r"^select\s+database\s*\(\s*\)", sql_lower):
        return ResponsePlan(
            kind="resultset",
            columns=["DATABASE()"],
            rows=[["app_db"]],
            reason="recon_current_db_query",
        )

    if re.match(r"^select\s+user\s*\(\s*\)", sql_lower) or re.match(
        r"^select\s+current_user\s*\(\s*\)", sql_lower
    ):
        return ResponsePlan(
            kind="resultset",
            columns=["USER()"],
            rows=[["root@localhost"]],
            reason="recon_current_user_query",
        )

    if sql_lower.startswith("show databases"):
        return ResponsePlan(
            kind="resultset",
            columns=["Database"],
            rows=[[d] for d in fake_data.FAKE_DATABASES],
            reason="recon_show_databases",
        )

    if sql_lower.startswith("show tables"):
        db_match = re.search(r"from\s+`?(\w+)`?", sql_lower)
        db = db_match.group(1) if db_match else "app_db"
        if db not in fake_data.FAKE_DATABASES:
            # Matches COM_INIT_DB's behavior (sub-goal 1): a real server
            # errors on an unknown database rather than fabricating
            # tables for it, so the fake schema holds together under
            # direct "SHOW TABLES FROM x" probes too, not just USE x.
            return ResponsePlan(
                kind="error",
                error_code=1049,
                error_message=f"Unknown database '{db}'",
                reason="recon_show_tables_unknown_db",
            )
        tables = fake_data.FAKE_TABLES_BY_DB.get(db, [])
        return ResponsePlan(
            kind="resultset",
            columns=[f"Tables_in_{db}"],
            rows=[[t] for t in tables],
            table=db,
            reason="recon_show_tables",
        )

    if "mysql.user" in sql_lower or ("from" in sql_lower and re.search(r"\buser\b", sql_lower) and "authentication_string" in sql_lower):
        return ResponsePlan(
            kind="resultset",
            columns=fake_data.FAKE_MYSQL_USER_COLUMNS,
            rows=fake_data.FAKE_MYSQL_USER_ROWS,
            table="mysql.user",
            reason="recon_mysql_user_table",
        )

    if "information_schema.tables" in sql_lower:
        return ResponsePlan(
            kind="resultset",
            columns=fake_data.FAKE_INFORMATION_SCHEMA_TABLES_COLUMNS,
            rows=fake_data.information_schema_tables_rows(),
            table="information_schema.tables",
            reason="recon_information_schema_tables",
        )

    if sql_lower.startswith("select"):
        table_match = re.search(r"from\s+`?(\w+)`?", sql_lower)
        table = table_match.group(1) if table_match else None
        if table == "users":
            # Per-session variant, not one static global dataset — same
            # session always sees the same rows, different sessions may see
            # different fake data.
            return ResponsePlan(
                kind="resultset",
                columns=fake_data.FAKE_USERS_TABLE_COLUMNS,
                rows=fake_data.get_users_table_rows(session_id),
                table=table,
                reason="data_access_users_table",
            )
        if table and table in fake_data.FAKE_TABLE_DATA:
            columns, rows = fake_data.FAKE_TABLE_DATA[table]
            return ResponsePlan(
                kind="resultset",
                columns=columns,
                rows=rows,
                table=table,
                reason=f"data_access_{table}_table",
            )

    if sql_lower.startswith(("select", "show", "describe", "explain")):
        # Generic, unrecognized read-only-looking query — return an
        # empty-but-valid result set rather than an error, since a real
        # server would too for a syntactically valid query on an
        # unknown/empty table.
        return ResponsePlan(
            kind="resultset",
            columns=["result"],
            rows=[],
            reason="unrecognized_read_query",
        )

    if sql_lower.startswith(("insert", "update", "delete")):
        return ResponsePlan(
            kind="ok",
            affected_rows=1,
            reason="write_query_faked_success",
        )

    # Fallback: unrecognized statement shape.
    return ResponsePlan(
        kind="error",
        error_code=1064,
        error_message="You have an error in your SQL syntax",
        reason="unrecognized_statement",
    )


def _apply_rl_action(plan: ResponsePlan, rl_action: str) -> ResponsePlan:
    """
    Applies the RL policy's chosen action ON TOP of the rule engine's
    plan. Never changes WHAT data would be shown, only HOW the response
    behaves — "delay" is handled separately via Decision.latency_ms in
    to_decision(); this function handles the two actions that change
    the actual response content/shape.
    """
    if rl_action == "serve_decoy_variant" and plan.kind == "resultset" and plan.rows:
        # Subtly wrong data, not obviously fake — mutate one cell in the
        # first row rather than the whole result set, so it's harder to
        # spot at a glance than an empty or nonsense response would be.
        new_rows = [list(r) for r in plan.rows]
        if len(new_rows[0]) > 1:
            val = str(new_rows[0][1])
            new_rows[0][1] = val[::-1] if val else val  # reversed, still plausible-looking
        plan = ResponsePlan(
            kind=plan.kind, columns=plan.columns, rows=new_rows, table=plan.table,
            reason=plan.reason, rl_action=rl_action,
        )
        return plan

    if rl_action == "escalate_error":
        # Override whatever the rule engine decided with a plausible
        # permission-denied response — even for a query that would
        # normally succeed.
        return ResponsePlan(
            kind="error", error_code=1044,
            error_message="Access denied for user to database 'app_db'",
            reason=plan.reason, rl_action=rl_action,
        )

    plan.rl_action = rl_action
    return plan


def decide_response(session_id: str, action: str, parameters: dict) -> ResponsePlan:
    """
    Job 3's public seam — signature unchanged from before RL existed,
    per the contract's promise that callers never need to change when
    what's inside this function changes. Internally: rule engine first,
    then the RL policy layer decides HOW to actually respond.
    """
    plan = _rule_based_plan(session_id, action, parameters)
    rl_action, _state = rl_policy.choose_action(session_id, plan.reason)
    return _apply_rl_action(plan, rl_action)


def to_decision(plan: ResponsePlan) -> Decision:
    """
    Wraps a MySQL-specific ResponsePlan in the generic Decision envelope
    (Phase 2, sub-goal 2). decide_response() itself is untouched — it
    still returns a ResponsePlan, since that's the natural shape for
    MySQL's internal SET/USE/SELECT branching. This function is the
    only place that knows how to translate that MySQL-specific shape
    into the protocol-agnostic contract the Adapter Manager and future
    ML/RL layers will eventually consume — a future Postgres adapter
    will have its own equivalent function for its own payload shape.
    """
    action = plan.rl_action if plan.rl_action != "serve_data" else ("escalate_error" if plan.kind == "error" else "serve_data")
    return Decision(
        action=action,
        payload=plan,
        source="rl" if plan.rl_action != "serve_data" else "rules",
        confidence=1.0,
        reason=plan.reason,
        latency_ms=rl_policy.DELAY_MS if plan.rl_action == "delay" else 0,
    )
