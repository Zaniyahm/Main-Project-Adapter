"""
mysql_adapter/fake_data.py
============================
Static, entirely fabricated data used to answer common reconnaissance
queries plausibly. Nothing here reflects a real database, real schema,
or real data of any kind — it exists purely to make the honeypot look
like a real, moderately interesting MySQL server worth continuing to
probe (which is the whole point: the more plausible this looks, the
longer an attacker's session runs, and the more behavioral data we
capture about *how* they probe).
"""

FAKE_VERSION = "8.0.34-0ubuntu0.22.04.1"
FAKE_VERSION_COMMENT = "(Ubuntu)"

FAKE_DATABASES = ["information_schema", "mysql", "performance_schema", "app_db", "sys"]

# Every database listed in FAKE_DATABASES needs an entry here — an
# attacker enumerating a system database and getting back app-looking
# table names (or vice versa) is an easy tell that the schema is fake.
FAKE_TABLES_BY_DB = {
    "app_db": ["users", "orders", "sessions", "audit_log"],
    "mysql": ["user", "db", "tables_priv", "columns_priv"],
    "information_schema": ["TABLES", "COLUMNS", "SCHEMATA", "KEY_COLUMN_USAGE", "STATISTICS"],
    "performance_schema": [
        "threads",
        "events_statements_current",
        "events_statements_history",
        "file_instances",
    ],
    "sys": ["version", "host_summary", "user_summary"],
}

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

# Central lookup so decide_response.py can serve any known table by name
# with one generic rule instead of one hardcoded branch per table.
FAKE_TABLE_DATA = {
    "users": (FAKE_USERS_TABLE_COLUMNS, FAKE_USERS_TABLE_ROWS),
    "orders": (FAKE_ORDERS_TABLE_COLUMNS, FAKE_ORDERS_TABLE_ROWS),
    "sessions": (FAKE_SESSIONS_TABLE_COLUMNS, FAKE_SESSIONS_TABLE_ROWS),
    "audit_log": (FAKE_AUDIT_LOG_TABLE_COLUMNS, FAKE_AUDIT_LOG_TABLE_ROWS),
}

# ---------------------------------------------------------------------
# Deep introspection: mysql.user — a real, classic recon target
# ("SELECT user, authentication_string FROM mysql.user") that returned
# empty before. Hashes are fabricated (structurally valid-looking
# mysql_native_password format), not real hashes of anything.
# ---------------------------------------------------------------------
FAKE_MYSQL_USER_COLUMNS = ["Host", "User", "authentication_string", "Select_priv", "Insert_priv", "Super_priv"]
FAKE_MYSQL_USER_ROWS = [
    ["localhost", "root", "*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B", "Y", "Y", "Y"],
    ["localhost", "admin", "*E6CC90B878B948C35E92B003C792C46C58C4AF4", "Y", "Y", "N"],
    ["%", "svc_backup", "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E1", "Y", "N", "N"],
    ["%", "reporting_ro", "*9F1B7DA23E32DD8C2ADDB4DC6E29AACA31FE01B4", "Y", "N", "N"],
]

# information_schema.tables — realistic response instead of empty,
# for "SELECT * FROM information_schema.tables" style enumeration.
FAKE_INFORMATION_SCHEMA_TABLES_COLUMNS = ["TABLE_SCHEMA", "TABLE_NAME", "TABLE_TYPE"]


def information_schema_tables_rows():
    rows = []
    for db, tables in FAKE_TABLES_BY_DB.items():
        for t in tables:
            rows.append([db, t, "BASE TABLE"])
    return rows


# ---------------------------------------------------------------------
# Per-session fake-world variation: same deterministic pattern
# core_db.py's generate_fake_world() already uses
# (hash(session_id) % len(variants)) — so a given session always sees
# the same variant (internally consistent), but different sessions see
# different data, rather than every attacker seeing byte-identical rows.
# ---------------------------------------------------------------------
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
    """Deterministic per-session variant — same session always sees the
    same rows (internally consistent), different sessions may see
    different fake data (not one static global dataset)."""
    idx = hash(session_id) % len(_USER_VARIANTS)
    return _USER_VARIANTS[idx]
