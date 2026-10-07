"""
postgres_adapter/pg_decide_response.py
========================================
Job 3 from the adapter contract: the single, clean seam for the future
Control Engine to plug into.

Every response decision in the Postgres adapter goes through
decide_response() — nothing else contains response-decision logic.

RIGHT NOW: simple rule-based canned logic, matching the MySQL adapter's
pattern exactly, but handling Postgres-specific reconnaissance queries
(\\l, \\dt, SELECT version(), information_schema, pg_catalog, etc.).

LATER: the body of decide_response() gets replaced with a call into the
shared Control Engine. Callers do not need to change.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal, Optional

from postgres_adapter import pg_fake_data as fake_data
from shared import rl_policy
from shared.decision import Decision

PostgresResponseKind = Literal["error", "command_complete", "resultset"]


@dataclass
class PostgresResponsePlan:
    """What the adapter should send back for one Postgres Query interaction."""

    kind: PostgresResponseKind
    columns: list[str] = field(default_factory=list)
    rows: list[list[Optional[str]]] = field(default_factory=list)
    tag: str = ""                       # e.g. "SELECT 3", "SET", "INSERT 0 1"
    error_code: str = "42601"           # 5-char SQLSTATE
    error_message: str = ""
    reason: str = ""
    # Set by the RL policy layer (shared/rl_policy.py), not the rule
    # engine. "serve_data" means the RL layer left the rule engine's
    # plan untouched.
    rl_action: str = "serve_data"


# --- injection / probing hints ----------------------------------------
# NOTE: \bsleep\s*\( alone does NOT match pg_sleep( — \b is a word
# boundary, and there is no boundary between "_" and "s" in "pg_sleep",
# both being word characters. pg_sleep() is Postgres's actual timing-
# attack idiom (the SLEEP()/pg_sleep() equivalent), so it needs its own
# explicit pattern rather than relying on the generic one ported from
# the MySQL adapter.
_INJECTION_HINTS = re.compile(
    r"(\bunion\s+select\b|\bor\s+1\s*=\s*1\b|--\s|;\s*drop\b|\bsleep\s*\(|"
    r"\bpg_sleep\s*\(|\binto\s+outfile\b|\bload_file\s*\(|\bxp_cmdshell\b)",
    re.IGNORECASE,
)

# COPY ... TO/FROM PROGRAM is a real, well-known Postgres RCE vector
# (arbitrary command execution via a misconfigured superuser role).
# Not a generic "injection pattern" — its own named recon/exploit
# category, and it needs to be checked as its own top-level statement
# type since COPY isn't a SELECT/INSERT/UPDATE/DELETE.
_COPY_TO_PROGRAM_HINT = re.compile(r"\bcopy\b.*\b(to|from)\s+program\b", re.IGNORECASE)


def _rule_based_plan(session_id: str, action: str, parameters: dict) -> PostgresResponsePlan:
    """
    action: the raw SQL text for a Postgres Query message.
    parameters: reserved for context — today only "current_database" is used.
    """
    sql = action.strip()
    sql_lower = sql.lower()
    current_db = parameters.get("current_database", "postgres")

    # ------------------------------------------------------------------
    # 1. COPY ... TO/FROM PROGRAM — real Postgres RCE vector, own category
    # ------------------------------------------------------------------
    if _COPY_TO_PROGRAM_HINT.search(sql_lower):
        # Matches the real error a properly-locked-down Postgres gives a
        # non-superuser role attempting this — convincing AND safe,
        # since we never execute anything either way.
        return PostgresResponsePlan(
            kind="error",
            error_code="42501",
            error_message=(
                "must be superuser or a member of the pg_execute_server_program "
                "role to COPY to or from an external program"
            ),
            reason="exploitation_copy_to_program_attempt",
        )

    # ------------------------------------------------------------------
    # 2. Injection / probing patterns
    # ------------------------------------------------------------------
    if _INJECTION_HINTS.search(sql):
        return PostgresResponsePlan(
            kind="error",
            error_code="42601",
            error_message='syntax error at or near "1"',
            reason="injection_pattern_detected",
        )

    # ------------------------------------------------------------------
    # 3. Client housekeeping (SET, SHOW, RESET)
    # ------------------------------------------------------------------
    if sql_lower.startswith("set "):
        return PostgresResponsePlan(
            kind="command_complete",
            tag="SET",
            reason="client_housekeeping_set",
        )

    if sql_lower.startswith("show "):
        var = sql[5:].strip().rstrip(";")
        return PostgresResponsePlan(
            kind="resultset",
            columns=[var],
            rows=[[""]],
            tag="SELECT 1",
            reason="recon_show_variable",
        )

    if sql_lower.startswith("reset "):
        return PostgresResponsePlan(
            kind="command_complete",
            tag="RESET",
            reason="client_housekeeping_reset",
        )

    # ------------------------------------------------------------------
    # 4. Version / identity reconnaissance
    # ------------------------------------------------------------------
    if re.match(r"^select\s+version\s*\(\s*\)", sql_lower):
        return PostgresResponsePlan(
            kind="resultset",
            columns=["version"],
            rows=[[fake_data.FAKE_VERSION]],
            tag="SELECT 1",
            reason="recon_version_query",
        )

    if re.match(r"^select\s+current_database\s*\(\s*\)", sql_lower):
        return PostgresResponsePlan(
            kind="resultset",
            columns=["current_database"],
            rows=[[current_db]],
            tag="SELECT 1",
            reason="recon_current_db_query",
        )

    if re.match(r"^select\s+(current_user|user)\s*\(\s*\)", sql_lower) or \
       re.match(r"^select\s+current_user\s*;?\s*$", sql_lower):
        return PostgresResponsePlan(
            kind="resultset",
            columns=["current_user"],
            rows=[["postgres"]],
            tag="SELECT 1",
            reason="recon_current_user_query",
        )

    if re.match(r"^select\s+session_user\s*\(\s*\)", sql_lower):
        return PostgresResponsePlan(
            kind="resultset",
            columns=["session_user"],
            rows=[["postgres"]],
            tag="SELECT 1",
            reason="recon_session_user_query",
        )

    # ------------------------------------------------------------------
    # 5. Database listing  (\l  or  pg_catalog.pg_database queries)
    # ------------------------------------------------------------------
    if "pg_catalog.pg_database" in sql_lower or sql_lower.startswith("\\l"):
        rows = [
            [d, "postgres", "UTF8", "en_US.UTF-8", "en_US.UTF-8", ""]
            for d in fake_data.FAKE_DATABASES
        ]
        return PostgresResponsePlan(
            kind="resultset",
            columns=["Name", "Owner", "Encoding", "Collate", "Ctype", "Access privileges"],
            rows=rows,
            tag=f"SELECT {len(rows)}",
            reason="recon_list_databases",
        )

    # ------------------------------------------------------------------
    # 6. Table listing  (\dt  or  pg_catalog.pg_class / information_schema.tables)
    # ------------------------------------------------------------------
    if "pg_catalog.pg_class" in sql_lower or "information_schema.tables" in sql_lower or \
       sql_lower.startswith("\\dt"):
        tables = fake_data.FAKE_TABLES_BY_DB.get(current_db, [])
        rows = [["public", t, "table", "postgres"] for t in tables]
        return PostgresResponsePlan(
            kind="resultset",
            columns=["Schema", "Name", "Type", "Owner"],
            rows=rows,
            tag=f"SELECT {len(rows)}",
            reason="recon_list_tables",
        )

    # ------------------------------------------------------------------
    # 7. Column / schema introspection  (\d  or  information_schema.columns)
    # ------------------------------------------------------------------
    if "information_schema.columns" in sql_lower:
        table_match = re.search(r"table_name\s*=\s*['\"](\w+)['\"]", sql_lower)
        table = table_match.group(1) if table_match else None
        if table and table in fake_data.FAKE_TABLE_DATA:
            columns, _ = fake_data.FAKE_TABLE_DATA[table]
            rows = [[c, "text", "", ""] for c in columns]
            return PostgresResponsePlan(
                kind="resultset",
                columns=["column_name", "data_type", "is_nullable", "column_default"],
                rows=rows,
                tag=f"SELECT {len(rows)}",
                reason=f"recon_describe_table_{table}",
            )

    if "pg_catalog.pg_attribute" in sql_lower:
        rel_match = re.search(r"attrelid\s*=\s*['\"]?(\w+)['\"]?::regclass", sql_lower)
        if not rel_match:
            rel_match = re.search(r"'(\w+)'::regclass", sql_lower)
        table = rel_match.group(1) if rel_match else None
        if table and table in fake_data.FAKE_TABLE_DATA:
            columns, _ = fake_data.FAKE_TABLE_DATA[table]
            rows = [[c, "text"] for c in columns]
            return PostgresResponsePlan(
                kind="resultset",
                columns=["Column", "Type"],
                rows=rows,
                tag=f"SELECT {len(rows)}",
                reason=f"recon_describe_table_{table}",
            )

    # ------------------------------------------------------------------
    # 7b. Deep introspection: pg_shadow / information_schema.tables —
    # classic recon/privesc targets that returned empty before.
    # ------------------------------------------------------------------
    if "pg_shadow" in sql_lower or "pg_authid" in sql_lower:
        return PostgresResponsePlan(
            kind="resultset",
            columns=fake_data.FAKE_PG_SHADOW_COLUMNS,
            rows=fake_data.FAKE_PG_SHADOW_ROWS,
            tag=f"SELECT {len(fake_data.FAKE_PG_SHADOW_ROWS)}",
            reason="exploitation_pg_shadow_access",
        )

    if "information_schema.tables" in sql_lower:
        rows = fake_data.information_schema_tables_rows()
        return PostgresResponsePlan(
            kind="resultset",
            columns=fake_data.FAKE_INFORMATION_SCHEMA_TABLES_COLUMNS,
            rows=rows,
            tag=f"SELECT {len(rows)}",
            reason="recon_information_schema_tables",
        )

    # 8. Regular SELECT (data access)
    # ------------------------------------------------------------------
    if sql_lower.startswith("select"):
        table_match = re.search(r"from\s+['\"]?(\w+)['\"]?", sql_lower)
        table = table_match.group(1) if table_match else None
        if table == "users":
            rows = fake_data.get_users_table_rows(session_id)
            return PostgresResponsePlan(
                kind="resultset",
                columns=fake_data.FAKE_USERS_TABLE_COLUMNS,
                rows=rows,
                tag=f"SELECT {len(rows)}",
                reason="data_access_users_table",
            )
        if table and table in fake_data.FAKE_TABLE_DATA:
            columns, rows = fake_data.FAKE_TABLE_DATA[table]
            return PostgresResponsePlan(
                kind="resultset",
                columns=columns,
                rows=rows,
                tag=f"SELECT {len(rows)}",
                reason=f"data_access_{table}_table",
            )
        return PostgresResponsePlan(
            kind="resultset",
            columns=["result"],
            rows=[],
            tag="SELECT 0",
            reason="unrecognized_read_query",
        )

    # ------------------------------------------------------------------
    # 9. Write queries (INSERT / UPDATE / DELETE)
    # ------------------------------------------------------------------
    if sql_lower.startswith("insert"):
        return PostgresResponsePlan(
            kind="command_complete",
            tag="INSERT 0 1",
            reason="write_query_faked_success",
        )

    if sql_lower.startswith("update"):
        return PostgresResponsePlan(
            kind="command_complete",
            tag="UPDATE 1",
            reason="write_query_faked_success",
        )

    if sql_lower.startswith("delete"):
        return PostgresResponsePlan(
            kind="command_complete",
            tag="DELETE 1",
            reason="write_query_faked_success",
        )

    # ------------------------------------------------------------------
    # 10. Fallback
    # ------------------------------------------------------------------
    first_token = sql.split()[0] if sql else ""
    return PostgresResponsePlan(
        kind="error",
        error_code="42601",
        error_message=f'syntax error at or near "{first_token}"',
        reason="unrecognized_statement",
    )


def _apply_rl_action(plan: PostgresResponsePlan, rl_action: str) -> PostgresResponsePlan:
    """Same treatment as mysql_adapter/decide_response.py's version —
    "delay" is handled via Decision.latency_ms in to_decision()."""
    if rl_action == "serve_decoy_variant" and plan.kind == "resultset" and plan.rows:
        new_rows = [list(r) for r in plan.rows]
        if len(new_rows[0]) > 1:
            val = str(new_rows[0][1])
            new_rows[0][1] = val[::-1] if val else val
        return PostgresResponsePlan(
            kind=plan.kind, columns=plan.columns, rows=new_rows, tag=plan.tag,
            reason=plan.reason, rl_action=rl_action,
        )

    if rl_action == "escalate_error":
        return PostgresResponsePlan(
            kind="error", error_code="42501",
            error_message="permission denied for relation app_db",
            reason=plan.reason, rl_action=rl_action,
        )

    plan.rl_action = rl_action
    return plan


def decide_response(session_id: str, action: str, parameters: dict) -> PostgresResponsePlan:
    """Job 3's public seam — signature unchanged from before RL existed.
    Rule engine first, then the RL policy layer decides HOW to respond."""
    plan = _rule_based_plan(session_id, action, parameters)
    rl_action, _state = rl_policy.choose_action(session_id, plan.reason)
    return _apply_rl_action(plan, rl_action)


def to_decision(plan: PostgresResponsePlan) -> Decision:
    """
    Wraps a Postgres-specific PostgresResponsePlan in the generic Decision
    envelope (Phase 2, sub-goal 2). Same pattern as
    mysql_adapter/decide_response.py's to_decision().
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
