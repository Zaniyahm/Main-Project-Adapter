# Integration Notes — MySQL/PostgreSQL Adapters (Team Hydra)

## What's here

- `mysql_adapter/`, `postgres_adapter/` — the two adapters, contract-compliant
- `shared/` — `adapter_interface.py` (Common Adapter Interface), `decision.py`
  (Decision contract), `core_db.py` (framework-agnostic logging — same
  functions/signatures as the HTTP adapter's), `event_bus.py`, `limits.py`
  (connection safety), `rl_policy.py`, `classifier_bridge.py`, `predictor.py`,
  `features.py`, `build_markov.py`
- `registry.py` + `adapters_config.json` — starts both adapters concurrently
  from one command; add new adapters by editing the config, not this script
- `scripts/` — `correlate_sessions.py` (cross-protocol session correlation),
  `baseline_accuracy.py`, `evaluate_conditions.py` (Static/Rule/RL comparison)
- `tests/` — `run_demo_commands.py`, `test_pg_client.py`

## Required for integration — please confirm/adjust

1. **`HONEYPOT_DB_PATH`** — our `shared/core_db.py` is a verbatim copy of
   what you sent us (diffed byte-for-byte, confirmed identical for
   `log_event()`/`setup_database()`/`get_db()`). **Please replace it
   with your canonical `core_db.py`** if yours has since diverged, and
   set `HONEYPOT_DB_PATH` to the same absolute path your `app.py` uses,
   so all adapters write into one physical database file.

2. **Adding these adapters to a combined launcher** — if you're
   merging all protocol adapters (HTTP, SSH, Telnet, FTP, MySQL,
   Postgres) into one process/launcher, `adapters_config.json` already
   supports this — just add entries for the other adapters
   (`{"name", "module", "class", "port"}` each) alongside ours. Every
   adapter needs to implement `shared.adapter_interface.HoneypotAdapter`
   (see `mysql_adapter/server.py`'s `MySQLAdapter` class for the pattern).

## Known limitations — flagged honestly, not hidden

- **Docker not live-tested.** `Dockerfile`/`DEPLOYMENT.md` are reviewed-correct
  but never actually run (no Docker daemon was available while building).
  Please build/run and confirm before relying on it.
- **Classifier produces no real predictions yet.** `shared/predictor.py`'s
  models were trained only on HTTP session data. `classifier_bridge.py`
  calls it safely (graceful fallback, never crashes), but predictions for
  SQL sessions are not yet meaningful — needs retraining on real MySQL/
  Postgres traffic once deployed.
- **Stage vocabulary gap:** your trained classifier's 5 stages
  (`credential_attack, injection_attempt, path_traversal, recon, xss_probing`)
  don't include an `exfiltration_attempt` class, which our RL policy
  (`shared/rl_policy.py`) uses for "reading real table data" events. Worth
  a conversation before any joint retraining — not something we changed
  unilaterally.
- **Postgres `response_status`:** Postgres's SQLSTATE codes are
  alphanumeric (`"28P01"`), not integers. We map them to HTTP-semantic
  integers before logging (`pg_server.py`'s `_numeric_status()`) so
  `features.py`'s `status >= 400` check doesn't crash — worth the same
  pattern for any other non-HTTP adapter (SSH/FTP) whose natural status
  codes also aren't integers.
- **`raw_metadata["User-Agent"]` is populated** via each protocol's real
  equivalent: MySQL's `CLIENT_CONNECT_ATTRS` (`_client_name`, e.g. `pymysql`)
  and Postgres's `application_name` (e.g. `psql`) — both confirmed live
  against real clients. Note: some client *libraries* (e.g. raw `psycopg2`
  without an explicit `application_name`) don't set this themselves — that's
  the library's own default, not a gap in the adapter.

## Verified live (not just written)

Every adapter behavior described above — protocol handshakes, weak-credential
acceptance, fake schema, injection detection, RL action variation, connection
safety limits (idle timeout, packet-size bounds, per-IP caps), cross-protocol
session correlation — was tested against real `mysql`/`psql` clients, not
just unit-style assertions. See `README.md` for how to run the same checks.
