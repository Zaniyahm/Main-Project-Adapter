"""
shared/limits.py
===================
Minimum Safe Deployment gate: single source of truth for the
connection-safety limits every adapter enforces, so tuning them means
editing one file, not hunting through each protocol's code.

Env-overridable so tests can use short timeouts without changing the
shipped production defaults.
"""
import os

MAX_CONNECTIONS_PER_IP = int(os.environ.get("HONEYPOT_MAX_CONN_PER_IP", "10"))
IDLE_TIMEOUT_SECONDS = int(os.environ.get("HONEYPOT_IDLE_TIMEOUT", "30"))
MAX_PACKET_SIZE = int(os.environ.get("HONEYPOT_MAX_PACKET_SIZE", str(1024 * 1024)))  # 1 MiB
