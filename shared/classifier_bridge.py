"""
shared/classifier_bridge.py
=============================
Best-effort, non-blocking bridge from an adapter's async connection loop
into the shared Stage/Intent Classifier (shared/predictor.py). Runs the
blocking work (joblib model load + SQLite reads) in a thread executor so
it never stalls the connection-handling coroutine, and never raises.

CURRENT LIMITATIONS (flagged deliberately, not hidden):
- No trained models exist yet covering MySQL/PostgreSQL session data —
  the classifier was trained on HTTP-only sessions. predict_stage_intent()
  returns (None, None, 0.0) until models are retrained including our
  protocols' traffic (this is exactly what Phase 8/9 exists to produce).
- classify_action()'s auth_probe/recon detection is hardcoded to HTTP
  paths ("post"+"/login", "/robots.txt", etc.) — will not recognize
  action strings like "LOGIN_ATTEMPT ..." or "SHOW DATABASES;". This is
  a gap in the shared code itself, not something patched here — needs a
  fix from whoever owns build_markov.py/features.py, not a local
  workaround (see project notes for the exact scoped ask).
- Postgres response_status is mapped to HTTP-semantic integers before
  logging (see pg_server.py's _numeric_status) specifically so
  features.py's `status >= 400` check doesn't crash on a SQLSTATE string.
"""

from __future__ import annotations

import asyncio
import sys


async def best_effort_classify(session_id: str, protocol_name: str) -> None:
    """Fire-and-forget: predicts stage/intent for this session and logs
    the result. Never raises, never blocks the caller."""
    try:
        from predictor import predict_stage_intent
    except Exception as e:
        print(f"[!] classifier import failed: {e}", file=sys.stderr)
        return

    try:
        loop = asyncio.get_event_loop()
        stage, intent, confidence = await loop.run_in_executor(None, predict_stage_intent, session_id)
        if stage is not None:
            print(f"[classifier] {protocol_name} session={session_id} "
                  f"stage={stage} intent={intent} confidence={confidence:.2f}")
        else:
            print(f"[classifier] {protocol_name} session={session_id}: "
                  f"no prediction available (model missing or extraction failed)")
    except Exception as e:
        print(f"[!] classifier call failed: {e}", file=sys.stderr)
