"""
shared/adapter_interface.py
=============================
The Common Adapter Interface (Phase 2, sub-goal 1): the single contract
every protocol adapter (MySQL, PostgreSQL, HTTP, ...) implements, so the
future Adapter Manager/Registry (Phase 5) can start, stop, and route to
any adapter uniformly — without ever needing to know protocol-specific
details.

Design note: this interfaces at the CONNECTION-LIFECYCLE level, not a
per-command level. MySQL/Postgres handshakes are inherently stateful,
multi-round-trip conversations — salt, sequence numbers, and auth state
all need to be threaded through one connection's whole lifetime — so a
single handle_connection(reader, writer) entry point per adapter is the
right granularity.

Protocol-specific decision logic (what fake data to return, when to
error) does NOT live here — that's decide_response.py's job (Job 3),
exposed to this layer via the Decision contract (Phase 2, sub-goal 2).
"""

from __future__ import annotations

import asyncio
import sys
from abc import ABC, abstractmethod
from collections import defaultdict

from shared import event_bus
from shared.limits import MAX_CONNECTIONS_PER_IP

# Minimum Safe Deployment: per-IP connection cap, shared across every
# adapter that goes through serve_forever() below — one DoS/resource-
# exhaustion guard for the whole system instead of one per adapter.
_active_connections: dict[str, int] = defaultdict(int)


class HoneypotAdapter(ABC):
    """
    Every concrete adapter (MySQLAdapter, PostgreSQLAdapter, ...) must:

      - set `protocol_name` (used in every log_event() call and in the
        Common Event Schema's `protocol` field — Phase 4)
      - set `listen_port` (used by the Adapter Manager/Registry —
        Phase 5 — to know which port to bind this adapter to)
      - implement `handle_connection()`, owning one TCP connection
        end-to-end: greet, authenticate, read commands, respond, log,
        clean up.

    Optional: override `max_connections_per_ip` to change the Minimum
    Safe Deployment connection cap for a specific adapter. Defaults to
    shared/limits.py's MAX_CONNECTIONS_PER_IP so there's one tunable
    source of truth across every adapter.
    """

    protocol_name: str
    listen_port: int
    max_connections_per_ip: int = MAX_CONNECTIONS_PER_IP

    @abstractmethod
    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Own one full connection lifecycle, start to finish."""
        ...

    async def _guarded_handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """
        Minimum Safe Deployment gate: enforces the per-IP connection cap
        BEFORE handle_connection() ever runs, so a concrete adapter's
        own code never needs to implement this itself — every adapter
        gets it for free, the same way serve_forever() and the event
        bus consumer are already shared.
        """
        peer = writer.get_extra_info("peername")
        ip = peer[0] if peer else "unknown"

        if _active_connections[ip] >= self.max_connections_per_ip:
            print(f"[!] {self.protocol_name}: rejecting connection from {ip} "
                  f"— per-IP limit ({self.max_connections_per_ip}) reached", file=sys.stderr)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return

        _active_connections[ip] += 1
        try:
            await self.handle_connection(reader, writer)
        finally:
            _active_connections[ip] = max(0, _active_connections[ip] - 1)

    async def serve_forever(self, host: str = "0.0.0.0") -> None:
        """
        Default implementation every adapter gets for free: bind
        `listen_port` and serve connections (through the Minimum Safe
        Deployment guard above) forever. Concrete adapters normally
        don't need to override this — only `handle_connection` needs
        protocol-specific logic.

        Also starts the Phase 4 event-bus consumer (shared/event_bus.py)
        in the background — safe to call once per process; run_consumer()
        no-ops if already running.
        """
        asyncio.create_task(event_bus.run_consumer())
        server = await asyncio.start_server(self._guarded_handle_connection, host, self.listen_port)
        addr = server.sockets[0].getsockname()
        print(f"[*] {self.protocol_name} honeypot adapter listening on {addr[0]}:{addr[1]}")
        async with server:
            await server.serve_forever()
