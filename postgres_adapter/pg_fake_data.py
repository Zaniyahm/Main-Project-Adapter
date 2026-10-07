"""
postgres_adapter/pg_fake_data.py
===================================
Static, entirely fabricated data. Deliberately reuses the SAME fake
users/orders/sessions/audit_log data as mysql_adapter/fake_data.py —
if an attacker (or campaign) probes both this and the MySQL adapter,
they see one consistent fictional organization, not two unrelated
fake worlds. This is the "Fake World State" idea applied across
protocols, not just within one.

Database list differs from MySQL's on purpose — these are Postgres's
own real default databases (postgres, template0, template1), not
copied from MySQL's system-database names, since a real attacker who
knows Postgres would notice MySQL-style system DBs on a Postgres
server immediately.
"""

FAKE_VERSION = (
    "PostgreSQL 14.10 (Debian 14.10-1.pgdg120+1) on x86_64-pc-linux-gnu, "
    "compiled by gcc (Debian 12.2.0-14) 12.2.0, 64-bit"
)
# Shorter form Postgres reports via the startup ParameterStatus message
# (real servers report a short version string there, not the full
# SELECT version() output).
FAKE_VERSION_SHORT = "14.10 (Debian 14.10-1.pgdg120+1)"

# Postgres's real default databases, plus our one "interesting" app
# database. template0/template1 are real Postgres internals every
# fresh install has — omitting them would itself be a tell.
FAKE_DATABASES = ["postgres", "template0", "template1", "app_db"]

# Unlike MySQL, Postgres has no mid-session "USE db" — a client can
# only be connected to ONE database per session, chosen at connection
# time. So there's no per-database table-list lookup here; only
# app_db (the one interesting database) has real fake tables. postgres/
# template0/template1 are real databases you CAN connect to, but they
# have no user tables in real life either — an empty-but-valid list is
# the honest, believable answer for those.
FAKE_TABLES_BY_DB = {
    "app_db": ["users", "orders", "sessions", "audit_log"],
    "postgres": [],
    "template0": [],
    "template1": [],
}

# Identical fake data to mysql_adapter/fake_data.py, intentionally —
# same fictional organization behind both protocol adapters.
FAKE_USERS_TABLE_COLUMNS = ["id", "username", "email", "created_at"]
FAKE_USERS_TABLE_ROWS = [
    ["1", "admin", "admin@example.local", "2024-01-04 10:12:03"],
    ["2", "svc_backup", "svc_backup@example.local", "2024-01-05 09:03:41"],
    ["3", "jdoe", "jdoe@example.local", "2024-02-11 14:27:56"],
    ["4", "reporting_ro", "reporting_ro@example.local", "2024-03-02 08:41:19"],
]

FAKE_ORDERS_TABLE_COLUMNS = ["id", "user_id", "product", "amount", "status", "created_at"]
FAKE_ORDERS_TABLE_ROWS = [
    ["1001", "1", "Enterprise License", "4999.00", "paid", "2024-01-10 11:02:15"],
    ["1002", "3", "Support Contract", "1200.00", "paid", "2024-02-14 09:44:02"],
    ["1003", "3", "Enterprise License", "4999.00", "pending", "2024-03-05 16:20:47"],
]

FAKE_SESSIONS_TABLE_COLUMNS = ["id", "user_id", "ip_address", "created_at", "expires_at"]
FAKE_SESSIONS_TABLE_ROWS = [
    ["a1f9c2", "1", "10.0.4.22", "2024-03-10 08:01:00", "2024-03-10 20:01:00"],
    ["b7e0d4", "3", "10.0.4.57", "2024-03-11 09:15:32", "2024-03-11 21:15:32"],
]

FAKE_AUDIT_LOG_TABLE_COLUMNS = ["id", "actor", "action", "target", "timestamp"]
FAKE_AUDIT_LOG_TABLE_ROWS = [
    ["1", "admin", "UPDATE", "orders.1003", "2024-03-05 16:21:03"],
    ["2", "svc_backup", "EXPORT", "users", "2024-03-06 02:00:11"],
]

FAKE_TABLE_DATA = {
    "users": (FAKE_USERS_TABLE_COLUMNS, FAKE_USERS_TABLE_ROWS),
    "orders": (FAKE_ORDERS_TABLE_COLUMNS, FAKE_ORDERS_TABLE_ROWS),
    "sessions": (FAKE_SESSIONS_TABLE_COLUMNS, FAKE_SESSIONS_TABLE_ROWS),
    "audit_log": (FAKE_AUDIT_LOG_TABLE_COLUMNS, FAKE_AUDIT_LOG_TABLE_ROWS),
}

# pg_shadow / pg_authid — the classic Postgres privesc/credential-dump
# target ("SELECT usename, passwd FROM pg_shadow"). Fabricated MD5-shaped
# hashes, not real hashes of anything.
FAKE_PG_SHADOW_COLUMNS = ["usename", "passwd", "usesuper"]
FAKE_PG_SHADOW_ROWS = [
    ["postgres", "md5d2d9a3d5a2c8e1f4b6a7c9e0d1f2a3b4", "t"],
    ["admin", "md5a1b2c3d4e5f6789abcdef0123456789a", "f"],
    ["svc_backup", "md5f0e1d2c3b4a5968778695a4b3c2d1e0", "f"],
]

FAKE_INFORMATION_SCHEMA_TABLES_COLUMNS = ["table_schema", "table_name", "table_type"]


def information_schema_tables_rows():
    rows = []
    for db, tables in FAKE_TABLES_BY_DB.items():
        for t in tables:
            rows.append(["public", t, "BASE TABLE"])
    return rows


# Per-session fake-world variation — same pattern as
# mysql_adapter/fake_data.py and core_db.py's own generate_fake_world():
# hash(session_id) % len(variants), so a given session is internally
# consistent but different sessions may see different fake data.
_USER_VARIANTS = [
    FAKE_USERS_TABLE_ROWS,
    [
        ["1", "administrator", "administrator@example.local", "2023-11-02 09:00:11"],
        ["2", "backup_svc", "backup_svc@example.local", "2023-11-03 14:22:05"],
        ["3", "mgarcia", "mgarcia@example.local", "2023-12-19 08:15:40"],
        ["4", "analyst_ro", "analyst_ro@example.local", "2024-01-08 11:30:02"],
    ],
    [
        ["1", "root_admin", "root_admin@example.local", "2024-02-14 07:45:19"],
        ["2", "svc_etl", "svc_etl@example.local", "2024-02-16 13:10:33"],
        ["3", "khassan", "khassan@example.local", "2024-03-01 16:05:27"],
        ["4", "readonly", "readonly@example.local", "2024-03-04 10:20:11"],
    ],
]


def get_users_table_rows(session_id: str) -> list:
    idx = hash(session_id) % len(_USER_VARIANTS)
    return _USER_VARIANTS[idx]
