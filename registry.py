"""
registry.py
=============
Phase 5: the Adapter Manager/Registry. Reads adapters_config.json,
dynamically imports each adapter class, instantiates it, and runs all
of them concurrently in one process.

Deliberately thin — infrastructure, not a differentiator (per the
original phase plan). No plugin-discovery system, no database: adding
or removing an adapter means editing the config file, not this script.

Both HoneypotAdapter.serve_forever() (Phase 2) and the event bus's
_consumer_started guard (Phase 4) exist specifically so this file can
be this short: every adapter already knows how to bind its own port
and start the shared logging pipeline safely, even when several
adapters share one process.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import sys

CONFIG_PATH = os.environ.get("ADAPTER_CONFIG", "adapters_config.json")


def load_adapters(config_path: str) -> list[tuple[str, object]]:
    with open(config_path) as f:
        entries = json.load(f)

    adapters = []
    for entry in entries:
        module = importlib.import_module(entry["module"])
        cls = getattr(module, entry["class"])
        instance = cls()
        if "port" in entry:
            # Overrides whatever env-var default the adapter's class
            # attribute normally falls back to — the config file is
            # now the single source of truth for ports.
            instance.listen_port = entry["port"]
        adapters.append((entry["name"], instance))
    return adapters


async def main():
    adapters = load_adapters(CONFIG_PATH)
    names = [name for name, _ in adapters]
    print(f"[*] Adapter Manager starting {len(adapters)} adapter(s): {names}")

    await asyncio.gather(*(adapter.serve_forever() for _, adapter in adapters))


if __name__ == "__main__":
    asyncio.run(main())
