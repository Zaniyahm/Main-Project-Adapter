# Database Honeypots (MySQL + PostgreSQL decoys)

Harmless MySQL and PostgreSQL servers that speak enough of each real
wire protocol to convince real client tools (`mysql`, `psql`,
`sqlmap`, `nmap`), for cybersecurity research, scanning-tool tests,
and honeypot labs. Built to the team's shared adapter contract — every
interaction is logged through the same `core_db.log_event()` used by
the web adapter, so all protocols land in one unified `logs`/`sessions`
store.

## Run

Both adapters can be started together with one command via the
Adapter Manager:

```
cd db-honeypot
python3 -m venv .venv
source .venv/bin/activate          # .\.venv\Scripts\Activate.ps1 on Windows
pip install -r requirements.txt
mkdir -p shared/instance
python3 -c "from shared.core_db import setup_database; setup_database()"
python3 registry.py
```

This starts MySQL on port 3306 and PostgreSQL on port 5432 from
`adapters_config.json`. To run only one, or on different ports, edit
that config file — no code changes needed.

To run a single adapter directly instead:

```
MYSQL_HONEYPOT_PORT=3306 python3 mysql_adapter/server.py
PG_HONEYPOT_PORT=5432 python3 postgres_adapter/pg_server.py
```

Connect with a real client to verify:

```
mysql -h 127.0.0.1 -P 3306 -u admin -p --skip-ssl
psql "host=127.0.0.1 port=5432 user=admin dbname=app_db sslmode=disable"
```

> **Note:** exact client flags vary by installed version. On Kali,
> `--ssl-mode=DISABLED` is not recognized by some `mysql` client builds
> — use `--skip-ssl` instead. Likewise, `psql`'s `--ssl-mode=disable`/
> `--sslmode=disable` flags are not accepted by all versions — use the
> connection-string form (`"host=... sslmode=disable"`) instead, which
> works consistently across `psql` versions.
>
> **All commands below assume you are in the `db-honeypot/` directory**
> (`cd ~/db-honeypot` first) — `shared`, `registry.py`, etc. are only
> importable/runnable from there, not from your home directory.

To check the shared database directly (also run from `db-honeypot/`):

```
python3 -c "from shared.core_db import get_db; db = get_db(); print([dict(r) for r in db.execute('SELECT protocol, action, response_status FROM logs ORDER BY id')])"
```

## Honeypot Behavior

- **Authentication Decoy**: Neither adapter performs real authentication.
  A small set of deliberately weak, commonly-brute-forced credentials
  (e.g. `admin`/`admin`, `root`/`toor`, `postgres`/`postgres`) is
  "accepted" so brute-force sessions look successful and keep
  generating richer interaction data instead of being abandoned after
  one probe. All submitted credentials are logged regardless of outcome.
- **Fake Schema, Not a Real Database**: Both adapters expose a
  consistent fictional company's data (`app_db`, with `users`,
  `orders`, `sessions`, `audit_log` tables) plus realistic system
  databases/catalogs (`information_schema`, `mysql`, `performance_schema`,
  `sys` for MySQL; `postgres`, `template0`, `template1` for Postgres).
  No real SQL is ever executed — every response is canned or
  rule-matched.
- **Protocol Impersonation**: MySQL identifies as
  `8.0.34-0ubuntu0.22.04.1` and correctly negotiates both
  `mysql_native_password` and `caching_sha2_password` (MySQL 8's
  default auth plugin). PostgreSQL identifies as `14.10
  (Debian 14.10-1.pgdg120+1)` and correctly declines SSL/GSS
  encryption negotiation so real clients fall back to plaintext
  instead of hanging.
- **Structured Logging**: Every interaction (login attempt, query,
  disconnect) is logged through the shared `core_db.log_event()`
  function — the same one the web adapter uses — into:
  - `shared/instance/honeypot_events.jsonl` (JSON Lines)
  - `shared/instance/legacy_cms.db` (`logs` and `sessions` tables)
- **Session Tracking**: One TCP connection = one session
  (`session_source: "protocol_native"`), matching each protocol's
  natural session boundary — no cookies needed, unlike the HTTP adapter.
- **Single Decision Seam**: All response-decision logic for each
  protocol goes through one function — `decide_response()` (MySQL) /
  `pg_decide_response()` (Postgres) — so future upgrades (rule-based →
  ML-driven → RL-driven responses) only ever change what's inside that
  function, never the callers.
- **Safety**: No real SQL execution, no real filesystem or network
  access, no real credential verification. Every "query result" is
  canned or rule-based fake data.

## Adapter Manager

`registry.py` reads `adapters_config.json` and starts every adapter
listed in it concurrently, in one process. Adding a new adapter (or
changing which ones run) means editing the config file, not this
script.
