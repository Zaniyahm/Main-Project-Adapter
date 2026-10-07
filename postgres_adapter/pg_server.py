"""
postgres_adapter/pg_server.py
================================

The PostgreSQL honeypot adapter's connection handler. Mirrors
mysql_adapter/server.py's structure exactly, adapted for Postgres's
different wire protocol shape:
  - pg_protocol.py         (Job 1: enough real Postgres wire protocol
                             to be convincing)
  - shared/logging.py       (Job 2: every interaction -> log_event())
  - session tracking         (Job 2a: one TCP connection = one session)
  - pg_decide_response.py   (Job 3: the single response-decision seam)
  - shared/adapter_interface.py (Phase 2: implements the Common
    Adapter Interface, same as MySQLAdapter)

KEY DIFFERENCE FROM MYSQL: Postgres has no mid-session "USE <db>" —
the database is fixed for the whole session, chosen in the
StartupMessage. So the "is this database real" check that MySQL does
per-USE-command happens here exactly once, right after the startup
message, before authentication even begins (matching real Postgres,
which also validates the database name before requesting a password).

SAFETY: this file never executes real SQL, never touches a real
database/filesystem, and never performs any real authentication. Every
query result comes from pg_decide_response()'s canned/rule-based logic.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Also add shared/ itself to sys.path — the shared classifier files
# (predictor.py, features.py, build_markov.py) use bare imports
# ("import core_db", "from features import ...") written assuming a
# flat sibling-files layout from their original repo, rather than our
# package structure. Adding shared/ directly lets those imports resolve
# to the SAME single shared/core_db.py our own event_bus.py already
# uses via "shared.core_db" — no duplicate copy of the file needed.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_REPO_ROOT, "shared"))

from postgres_adapter import pg_fake_data as fake_data
from postgres_adapter import pg_protocol as protocol
from postgres_adapter import pg_userdb as userdb
from postgres_adapter.pg_decide_response import decide_response, to_decision
import datetime

from shared import classifier_bridge, event_bus
from shared.adapter_interface import HoneypotAdapter

# Postgres SQLSTATE codes are alphanumeric ("28P01", "3D000"), but the
# shared logs schema's response_status is used as an HTTP-style integer
# elsewhere (e.g. features.py's error_ratio does `status >= 400`, which
# raises TypeError on a string). Map to HTTP-semantic integers for
# logging purposes only — the real SQLSTATE is preserved in
# `parameters["sqlstate"]` for anyone who wants it.
_SQLSTATE_TO_HTTP_LIKE = {
    "28P01": 401,  # password authentication failed
    "3D000": 404,  # unknown database
    "42501": 403,  # insufficient privilege (e.g. COPY TO PROGRAM)
    "42601": 400,  # syntax error / injection-pattern rejection
}
_DEFAULT_ERROR_STATUS = 500

IDLE_TIMEOUT_SECONDS = 30  # Minimum Safe Deployment: terminate idle sockets


def _numeric_status(sqlstate) -> int:
    """Best-effort numeric status for the shared schema. Never raises."""
    if isinstance(sqlstate, int):
        return sqlstate
    return _SQLSTATE_TO_HTTP_LIKE.get(sqlstate, _DEFAULT_ERROR_STATUS)


def _log(protocol_name, source_ip, session_id, action, reason="",
          parameters=None, raw_metadata=None, response_status=None, response_type=""):
    """
    Publishes ONE event onto the Phase 4 event bus, matching the team's
    adapter contract EXACTLY — mirrors mysql_adapter/server.py's _log().

    response_status must never be None (NOT NULL in the shared schema).
    Note: Postgres SQLSTATE codes ("28P01", "3D000", "42501") are
    alphanumeric, not integers, unlike the schema's declared INTEGER
    column — SQLite's dynamic typing tolerates this, but it's a known
    mismatch worth raising with the team.
    """
    merged_parameters = dict(parameters or {})
    if reason:
        merged_parameters["reason"] = reason

    try:
        event = dict(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            protocol=protocol_name,
            source_ip=source_ip,
            session_id=session_id,
            action=action,
            parameters=merged_parameters,
            raw_metadata=raw_metadata or {},
            session_source="protocol_native",
            response_status=response_status if response_status is not None else 0,
            response_type=response_type,
        )
        event_bus.publish(event)
    except Exception as e:
        print(f"[!] event bus publish failed: {e}", file=sys.stderr)


class PostgreSQLAdapter(HoneypotAdapter):
    """Implements the Common Adapter Interface for PostgreSQL."""

    protocol_name = "postgresql"
    listen_port = int(os.environ.get("PG_HONEYPOT_PORT", "5432"))

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        source_ip = peer[0] if peer else "unknown"
        session_id = str(uuid.uuid4())

        try:
            # --- Job 1: startup handshake (client speaks first) --------
            startup = await protocol.read_startup_message(reader, writer)
            username = startup.parameters.get("user", "")
            # Real libpq defaults the target database to the username if
            # none is given explicitly — matching that here too.
            requested_db = startup.parameters.get("database") or username or "postgres"

            _log(
                self.protocol_name, source_ip, session_id,
                action=f"LOGIN_ATTEMPT user={username}",
                reason="login_attempt",
                parameters={"username": username, "database": requested_db},
                response_status=None,
                response_type="login_attempt",
            )

            # Postgres validates the database BEFORE requesting a
            # password — there is no per-query "USE" to intercept later,
            # so this is the one and only place a fake/unknown database
            # can be caught.
            if requested_db not in fake_data.FAKE_DATABASES:
                err = protocol.build_error_response(
                    "FATAL", "3D000", f'database "{requested_db}" does not exist'
                )
                writer.write(err)
                await writer.drain()
                _log(
                    self.protocol_name, source_ip, session_id,
                    action=f"LOGIN_FAILED user={username}",
                    reason="login_failed",
                    parameters={"database": requested_db, "sqlstate": "3D000"},
                    response_status=_numeric_status("3D000"),
                    response_type="fatal_error",
                )
                return

            salt = secrets.token_bytes(4)
            writer.write(protocol.build_auth_md5_password(salt))
            await writer.drain()

            msg_type, payload = await protocol.read_message(reader)
            if msg_type != b"p":
                return  # client didn't follow the auth handshake; nothing to do
            auth_response = protocol.parse_password_message(payload)

            accepted = userdb.check_login(username, auth_response, salt)
            if not accepted:
                err = protocol.build_error_response(
                    "FATAL", "28P01", f'password authentication failed for user "{username}"'
                )
                writer.write(err)
                await writer.drain()
                _log(
                    self.protocol_name, source_ip, session_id,
                    action=f"LOGIN_FAILED user={username}",
                    reason="login_failed",
                    parameters={"username": username, "sqlstate": "28P01"},
                    response_status=_numeric_status("28P01"),
                    response_type="auth_error",
                )
                return

            writer.write(protocol.build_auth_ok())
            writer.write(protocol.build_parameter_status("server_version", fake_data.FAKE_VERSION_SHORT))
            writer.write(protocol.build_parameter_status("client_encoding", "UTF8"))
            writer.write(protocol.build_backend_key_data(os.getpid() & 0xFFFF, secrets.randbits(31)))
            writer.write(protocol.build_ready_for_query())
            await writer.drain()
            _log(
                self.protocol_name, source_ip, session_id,
                action=f"LOGIN_SUCCESS user={username}",
                reason="login_success",
                parameters={"username": username, "database": requested_db},
                response_status=0,
                response_type="auth_ok",
            )

            # --- command loop -------------------------------------------
            while True:
                try:
                    msg_type, payload = await asyncio.wait_for(
                        protocol.read_message(reader), timeout=IDLE_TIMEOUT_SECONDS
                    )
                except asyncio.TimeoutError:
                    _log(self.protocol_name, source_ip, session_id, action="IDLE_TIMEOUT",
                         reason="idle_timeout", response_type="disconnect")
                    from shared import rl_policy
                    rl_policy.record_session_end(session_id)
                    break

                if msg_type == b"X":
                    _log(self.protocol_name, source_ip, session_id, action="TERMINATE",
                         reason="disconnect", response_type="disconnect")
                    from shared import rl_policy
                    rl_policy.record_session_end(session_id)
                    break

                if msg_type == b"Q":
                    query = protocol.parse_query_message(payload)

                    # --- Job 3: the single decision seam ------------------
                    plan = decide_response(session_id, query, {"current_database": requested_db})
                    decision = to_decision(plan)
                    plan = decision.payload  # unwrap: render bytes from the Postgres-specific payload
                    print(f"[RL] postgresql session={session_id} action={decision.action} "
                          f"source={decision.source} latency_ms={decision.latency_ms}")

                    if decision.latency_ms:
                        await asyncio.sleep(decision.latency_ms / 1000)

                    if plan.kind == "error":
                        writer.write(protocol.build_error_response("ERROR", plan.error_code, plan.error_message))
                        writer.write(protocol.build_ready_for_query())
                        resp_status, resp_type = _numeric_status(plan.error_code), "error"

                    elif plan.kind == "command_complete":
                        writer.write(protocol.build_command_complete(plan.tag))
                        writer.write(protocol.build_ready_for_query())
                        resp_status, resp_type = 0, "ok"

                    else:  # resultset
                        writer.write(protocol.build_row_description(plan.columns))
                        for row in plan.rows:
                            writer.write(protocol.build_data_row(row))
                        writer.write(protocol.build_command_complete(plan.tag))
                        writer.write(protocol.build_ready_for_query())
                        resp_status, resp_type = 0, "resultset"

                    await writer.drain()
                    _log(
                        self.protocol_name, source_ip, session_id,
                        action=query[:500],
                        reason=plan.reason,
                        # Raw query text also goes in `parameters` (not just
                        # `action`) so the shared feature extractor's
                        # _has_sqli_in_params()/_has_traversal_in_params()/
                        # _has_xss_in_params() — which only scan `parameters`
                        # values — can actually see injection payloads we
                        # detect. Without this, has_sqli_pattern etc. would
                        # silently always read 0.0 for every SQL adapter event.
                        parameters={"query": query, "sqlstate": plan.error_code if plan.kind == "error" else None},
                        raw_metadata={"query_length": len(query)},
                        response_status=resp_status,
                        response_type=resp_type,
                    )
                    asyncio.create_task(classifier_bridge.best_effort_classify(session_id, self.protocol_name))
                    continue

                # Any other message type (e.g. Parse/Bind/Describe from
                # the extended query protocol, or Sync): acknowledge
                # nothing, log it, don't crash. Simple-query protocol
                # (what psql and most tools use by default) never sends
                # these for plain SQL text.
                _log(self.protocol_name, source_ip, session_id,
                     action=f"UNHANDLED_MESSAGE type={msg_type!r}",
                     response_status=0, response_type="ignored")

        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionResetError):
            pass  # client disconnected mid-protocol; nothing to do
        except Exception as e:
            print(f"[!] connection error from {source_ip}: {e}", file=sys.stderr)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def main():
    adapter = PostgreSQLAdapter()
    await adapter.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
