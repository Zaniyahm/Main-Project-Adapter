"""
shared/event_bus.py
======================
Phase 4 (corrected per the team's adapter contract): the transport
between an adapter's connection-handling loop and the REAL shared
log_event() in shared/core_db.py — the same function the web adapter
uses. This keeps every protocol's events in one unified logs/sessions
SQLite store, per the contract's explicit requirement.

Golden rule unchanged: the packet-handling loop must NEVER await a
slow I/O call directly. log_event() does blocking file AND SQLite I/O,
so this queue is exactly what keeps that off the connection-handling
coroutine's critical path.

IMPORTANT: events published here must match shared/core_db.py's
log_event() keyword arguments EXACTLY — no stage/intent/confidence
fields. Those are computed later, centrally, by the shared classifier
reading from the logs table — never by an adapter itself.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Callable

from shared.core_db import log_event as _core_log_event

_queue: asyncio.Queue = asyncio.Queue()
_consumer_started = False  # guards against double-starting if multiple
                            # adapters ever share one process (Phase 5)


def publish(event: dict) -> None:
    """
    Non-blocking. `event` must be a plain dict whose keys exactly match
    shared.core_db.log_event()'s keyword arguments.
    """
    try:
        _queue.put_nowait(event)
    except asyncio.QueueFull:
        print("[!] event bus queue full — dropping event", file=sys.stderr)


def _default_sink(event: dict) -> None:
    _core_log_event(**event)


async def run_consumer(sink: Callable[[dict], None] = _default_sink) -> None:
    """Background task: drains the queue forever. A broken sink never
    crashes the honeypot."""
    global _consumer_started
    if _consumer_started:
        return
    _consumer_started = True

    while True:
        event = await _queue.get()
        try:
            sink(event)
        except Exception as e:
            print(f"[!] event bus sink failed: {e}", file=sys.stderr)
