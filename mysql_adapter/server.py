"""
mysql_adapter/server.py
=========================

The MySQL honeypot adapter's connection handler. Ties together:
  - protocol.py         (Job 1: enough real MySQL wire protocol to be convincing)
  - shared/logging.py    (Job 2: every interaction -> log_event())
  - session tracking      (Job 2a: one TCP connection = one session)
  - decide_response.py   (Job 3: the single response-decision seam)
  - shared/adapter_interface.py (Phase 2: implements the Common Adapter
    Interface so the future Adapter Manager can start/stop this adapter
    the same way it starts/stops any other protocol adapter)

SAFETY: this file never executes real SQL, never touches a real
database/filesystem, and never performs any real authentication. Every
"query result" comes from decide_response()'s canned/rule-based logic.
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

import datetime

from mysql_adapter import protocol, userdb
from mysql_adapter.decide_response import decide_response, to_decision
from shared import classifier_bridge, event_bus
from shared.adapter_interface import HoneypotAdapter

SERVER_VERSION = "8.0.34-0ubuntu0.22.04.1"
IDLE_TIMEOUT_SECONDS = 30  # Minimum Safe Deployment: terminate idle sockets

# COM_* command bytes we care about
COM_QUIT = 0x01
COM_INIT_DB = 0x02
COM_QUERY = 0x03
COM_PING = 0x0E


def _log(protocol_name, source_ip, session_id, action, reason="",
          parameters=None, raw_metadata=None, response_status=None, response_type=""):
    """
    Publishes ONE event onto the Phase 4 event bus, matching the team's
    adapter contract EXACTLY: event_id, timestamp, protocol, source_ip,
    session_id, action, parameters, raw_metadata, session_source,
    response_status, response_type. No stage/intent/confidence here —
    those are the shared Control Engine's job, computed later from raw
    logs, never by the adapter itself (per contract Job 2).

    response_status must never be None — the shared logs table declares
    it NOT NULL; 0 is used as a neutral placeholder when status isn't
    yet known (e.g. at LOGIN_ATTEMPT, before accept/reject is decided).
    `reason` (from decide_response's ResponsePlan) is contract-compliant
    context, so it goes inside `parameters`, not as a new top-level field.
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
    except Exception as e:  # logging must never crash the honeypot
        print(f"[!] event bus publish failed: {e}", file=sys.stderr)


class MySQLAdapter(HoneypotAdapter):
    """
    Implements the Common Adapter Interface (shared/adapter_interface.py)
    for MySQL. `handle_connection` below is exactly the same logic that
    used to be a standalone module-level function — wrapping it as a
    class method is the only structural change; connection-handling
    behavior is unchanged from Phase 1.
    """

    protocol_name = "mysql"
    listen_port = int(os.environ.get("MYSQL_HONEYPOT_PORT", "3306"))

    def __init__(self) -> None:
        self._connection_counter = 0
        self._counter_lock = asyncio.Lock()

    async def _next_connection_id(self) -> int:
        async with self._counter_lock:
            self._connection_counter += 1
            return self._connection_counter

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        source_ip = peer[0] if peer else "unknown"
        session_id = str(uuid.uuid4())  # one TCP connection = one session (protocol_native)
        connection_id = await self._next_connection_id()

        seq = 0
        try:
            # --- Job 1: speak enough real protocol to be convincing -----
            salt = secrets.token_bytes(20)
            handshake_payload = protocol.build_handshake_v10(connection_id, SERVER_VERSION, salt)
            writer.write(protocol.pack_packet(handshake_payload, seq))
            await writer.drain()

            client_payload, client_seq = await asyncio.wait_for(
                protocol.read_packet(reader), timeout=IDLE_TIMEOUT_SECONDS
            )
            hr = protocol.parse_handshake_response(client_payload)

            _log(
                self.protocol_name, source_ip, session_id,
                action=f"LOGIN_ATTEMPT user={hr.username}",
                reason="login_attempt",
                parameters={"username": hr.username, "database": hr.database},
                raw_metadata={
                    "client_flags": hr.client_flags,
                    "charset": hr.charset,
                    "client_plugin": hr.client_plugin,
                },
                response_status=None,
                response_type="login_attempt",
            )

            accepted = userdb.check_login(hr.username, hr.auth_response, salt, hr.client_plugin)
            seq = client_seq + 1

            if not accepted:
                err = protocol.build_err_packet(
                    1045, f"Access denied for user '{hr.username}'@'{source_ip}' (using password: YES)"
                )
                writer.write(protocol.pack_packet(err, seq))
                await writer.drain()
                _log(
                    self.protocol_name, source_ip, session_id,
                    action=f"LOGIN_FAILED user={hr.username}",
                    reason="login_failed",
                    parameters={"username": hr.username},
                    response_status=1045,
                    response_type="auth_error",
                )
                return  # real MySQL closes the connection on auth failure too

            # caching_sha2_password clients expect a fast-auth-success signal
            # before the final OK — otherwise their client library sits
            # waiting for a phase-2 (full auth / RSA) round trip we're never
            # going to send. mysql_native_password clients skip this; they
            # go straight to OK exactly as before.
            if hr.client_plugin == protocol.AUTH_PLUGIN_NAME:
                more_data = protocol.build_auth_more_data()
                writer.write(protocol.pack_packet(more_data, seq))
                await writer.drain()
                seq += 1

            ok = protocol.build_ok_packet()
            writer.write(protocol.pack_packet(ok, seq))
            await writer.drain()
            _log(
                self.protocol_name, source_ip, session_id,
                action=f"LOGIN_SUCCESS user={hr.username}",
                reason="login_success",
                parameters={"username": hr.username, "database": hr.database},
                response_status=0,
                response_type="auth_ok",
            )

            # --- command loop -------------------------------------------
            while True:
                try:
                    cmd_payload, cmd_seq = await asyncio.wait_for(
                        protocol.read_packet(reader), timeout=IDLE_TIMEOUT_SECONDS
                    )
                except asyncio.TimeoutError:
                    _log(self.protocol_name, source_ip, session_id, action="IDLE_TIMEOUT",
                         reason="idle_timeout", response_type="disconnect")
                    from shared import rl_policy
                    rl_policy.record_session_end(session_id)
                    break
                if not cmd_payload:
                    break

                cmd = cmd_payload[0]

                if cmd == COM_QUIT:
                    _log(self.protocol_name, source_ip, session_id, action="QUIT",
                         reason="disconnect", response_type="disconnect")
                    from shared import rl_policy
                    rl_policy.record_session_end(session_id)
                    break

                if cmd == COM_PING:
                    resp = protocol.build_ok_packet()
                    writer.write(protocol.pack_packet(resp, cmd_seq + 1))
                    await writer.drain()
                    _log(self.protocol_name, source_ip, session_id, action="PING",
                         response_status=0, response_type="ok")
                    continue

                if cmd == COM_INIT_DB:
                    # "USE <db>" — client switching the active database.
                    # Routed through decide_response() (as a synthesized
                    # "USE <db>" string) so this stays the single response
                    # seam rather than a second decision path living here.
                    db_name = cmd_payload[1:].decode("utf-8", errors="replace")
                    plan = decide_response(session_id, f"USE {db_name}", {})
                    decision = to_decision(plan)
                    plan = decision.payload  # unwrap: render bytes from the MySQL-specific payload

                    out_seq = cmd_seq + 1
                    if plan.kind == "error":
                        pkt = protocol.build_err_packet(plan.error_code, plan.error_message)
                        writer.write(protocol.pack_packet(pkt, out_seq))
                        resp_status, resp_type = plan.error_code, "error"
                    else:
                        pkt = protocol.build_ok_packet()
                        writer.write(protocol.pack_packet(pkt, out_seq))
                        resp_status, resp_type = 0, "ok"

                    await writer.drain()
                    _log(
                        self.protocol_name, source_ip, session_id,
                        action=f"INIT_DB {db_name}",
                        reason=plan.reason,
                        parameters={"database": db_name},
                        response_status=resp_status,
                        response_type=resp_type,
                    )
                    continue

                if cmd == COM_QUERY:
                    sql_text = cmd_payload[1:].decode("utf-8", errors="replace")

                    # --- Job 3: the single decision seam ------------------
                    plan = decide_response(session_id, sql_text, {})
                    decision = to_decision(plan)
                    plan = decision.payload  # unwrap: render bytes from the MySQL-specific payload
                    print(f"[RL] mysql session={session_id} action={decision.action} "
                          f"source={decision.source} latency_ms={decision.latency_ms}")

                    if decision.latency_ms:
                        # Honors the RL policy's "delay" action for real —
                        # not just logged, an actual wasted-time cost to
                        # the attacker's session.
                        await asyncio.sleep(decision.latency_ms / 1000)

                    out_seq = cmd_seq + 1
                    if plan.kind == "error":
                        pkt = protocol.build_err_packet(plan.error_code, plan.error_message)
                        writer.write(protocol.pack_packet(pkt, out_seq))
                        resp_status, resp_type = plan.error_code, "error"

                    elif plan.kind == "ok":
                        pkt = protocol.build_ok_packet(affected_rows=plan.affected_rows)
                        writer.write(protocol.pack_packet(pkt, out_seq))
                        resp_status, resp_type = 0, "ok"

                    else:  # resultset
                        packets = protocol.build_text_resultset(plan.columns, plan.rows, plan.table)
                        for p in packets:
                            writer.write(protocol.pack_packet(p, out_seq))
                            out_seq += 1
                        resp_status, resp_type = 0, "resultset"

                    await writer.drain()

                    _log(
                        self.protocol_name, source_ip, session_id,
                        action=sql_text[:500],  # normalized action = the query itself
                        reason=plan.reason,
                        # Raw query text also in `parameters` (not just
                        # `action`) so the shared feature extractor's
                        # SQLi/traversal/XSS pattern scanners — which only
                        # scan `parameters` values — can actually see it.
                        parameters={"query": sql_text},
                        raw_metadata={"query_length": len(sql_text)},
                        response_status=resp_status,
                        response_type=resp_type,
                    )
                    asyncio.create_task(classifier_bridge.best_effort_classify(session_id, self.protocol_name))
                    continue

                # Any other COM_* opcode: acknowledge minimally, log it,
                # don't crash. Real behavior isn't needed for opcodes real
                # attackers rarely send to a scanner-facing DB honeypot.
                resp = protocol.build_ok_packet()
                writer.write(protocol.pack_packet(resp, cmd_seq + 1))
                await writer.drain()
                _log(self.protocol_name, source_ip, session_id,
                     action=f"UNHANDLED_COMMAND opcode=0x{cmd:02x}",
                     response_status=0, response_type="ok")

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
    adapter = MySQLAdapter()
    await adapter.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
