"""Framework-agnostic core DB and logging module.

Provides database access, structured logging, session correlation,
and query functions without any Flask dependency. Any Python code can
call these functions — Flask routes, the admin dashboard, standalone
scripts, or a future SSH adapter.

Connection strategy: open a connection per call, use it, close it.
Simple and correct for this project's scale.
"""
import json
import logging
import os
import sqlite3
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

SESSION_TIMEOUT_SECONDS = 900

def _get_db_path() -> str:
    env_path = os.environ.get("HONEYPOT_DB_PATH")
    if env_path:
        return env_path
    return str(Path(__file__).parent / "instance" / "legacy_cms.db")


def get_db(db_path: str = None) -> sqlite3.Connection:
    path = db_path or _get_db_path()
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def setup_database(db_path: str = None):
    db = get_db(db_path)
    db.execute("""CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT UNIQUE NOT NULL,
        timestamp TEXT NOT NULL,
        protocol TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        session_id TEXT NOT NULL,
        session_source TEXT NOT NULL,
        action TEXT NOT NULL,
        parameters TEXT NOT NULL,
        raw_metadata TEXT NOT NULL,
        response_status INTEGER NOT NULL,
        response_type TEXT NOT NULL
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        source_ip TEXT NOT NULL,
        user_agent TEXT NOT NULL,
        protocol TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        request_count INTEGER NOT NULL DEFAULT 1,
        distinct_actions INTEGER NOT NULL DEFAULT 1,
        status TEXT NOT NULL DEFAULT 'active'
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS session_unlocked_nodes (
        session_id TEXT NOT NULL,
        node_id TEXT NOT NULL,
        unlocked_at TEXT NOT NULL,
        PRIMARY KEY (session_id, node_id),
        FOREIGN KEY (session_id) REFERENCES sessions(session_id)
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS session_fake_world (
        session_id TEXT PRIMARY KEY,
        fake_company TEXT NOT NULL,
        fake_db_name TEXT NOT NULL,
        fake_usernames TEXT NOT NULL,
        fake_domain TEXT NOT NULL,
        persona_id TEXT NOT NULL DEFAULT 'legacy',
        FOREIGN KEY (session_id) REFERENCES sessions(session_id)
    )""")
    try:
        db.execute("ALTER TABLE session_fake_world ADD COLUMN persona_id TEXT NOT NULL DEFAULT 'legacy'")
    except Exception:
        pass
    db.execute("""CREATE TABLE IF NOT EXISTS admin_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""")
    db.execute("CREATE INDEX IF NOT EXISTS idx_logs_session_id ON logs(session_id)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_sessions_last_seen ON sessions(last_seen)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_unlocked_session_id ON session_unlocked_nodes(session_id)")
    db.commit()
    db.close()


def log_event(
    *,
    event_id: str,
    timestamp: str,
    protocol: str,
    source_ip: str,
    session_id: str,
    action: str,
    parameters: dict,
    raw_metadata: dict,
    session_source: str,
    response_status: int,
    response_type: str,
    db_path: str = None,
    log_file_path: str = None,
) -> str:
    if log_file_path is None:
        log_file_path = str(Path(__file__).parent / "instance" / "honeypot_events.jsonl")

    event = {
        "event_id": event_id, "timestamp": timestamp, "protocol": protocol,
        "source_ip": source_ip, "session_id": session_id, "action": action,
        "parameters": parameters, "raw_metadata": raw_metadata,
        "session_source": session_source, "response_status": response_status,
        "response_type": response_type,
    }
    try:
        with open(log_file_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
    except Exception as e:
        logger.error(f"Failed to write JSONL log: {e}")

    try:
        db = get_db(db_path)
        db.execute(
            """INSERT INTO logs (
                event_id, timestamp, protocol, source_ip, session_id,
                session_source, action, parameters, raw_metadata,
                response_status, response_type
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (event_id, timestamp, protocol, source_ip, session_id, session_source,
             action, json.dumps(parameters), json.dumps(raw_metadata),
             response_status, response_type),
        )
        now_iso = datetime.now(timezone.utc).isoformat()
        existing = db.execute(
            "SELECT session_id, request_count, distinct_actions FROM sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        if existing:
            new_count = existing["request_count"] + 1
            distinct = db.execute(
                "SELECT COUNT(DISTINCT action) as cnt FROM logs WHERE session_id = ?",
                (session_id,),
            ).fetchone()["cnt"]
            db.execute(
                "UPDATE sessions SET last_seen = ?, request_count = ?, distinct_actions = ?, status = 'active' WHERE session_id = ?",
                (now_iso, new_count, distinct, session_id),
            )
        else:
            db.execute(
                "INSERT INTO sessions (session_id, source_ip, user_agent, protocol, first_seen, last_seen, request_count, distinct_actions, status) VALUES (?, ?, ?, ?, ?, ?, 1, 1, 'active')",
                (session_id, source_ip, raw_metadata.get("User-Agent", ""), protocol, now_iso, now_iso),
            )
        cutoff_end = (datetime.now(timezone.utc) - timedelta(seconds=SESSION_TIMEOUT_SECONDS)).isoformat()
        db.execute(
            "UPDATE sessions SET status = 'ended' WHERE status = 'active' AND last_seen < ?",
            (cutoff_end,),
        )
        db.commit()
        db.close()
    except Exception as e:
        logger.error(f"Failed to log to database: {e}")

    return session_id


def resolve_session_id(cookie_value, source_ip: str, user_agent: str, db_path: str = None):
    if cookie_value:
        return cookie_value, "cookie"
    db = get_db(db_path)
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=SESSION_TIMEOUT_SECONDS)).isoformat()
    row = db.execute(
        "SELECT session_id FROM sessions WHERE source_ip = ? AND user_agent = ? AND last_seen >= ? ORDER BY last_seen DESC LIMIT 1",
        (source_ip, user_agent, cutoff),
    ).fetchone()
    db.close()
    if row:
        return row["session_id"], "ip_ua_correlation"
    return str(uuid.uuid4()), "new"


_FAKE_COMPANIES = ["Nexus Technologies", "Orion Healthcare", "Pinnacle Logistics", "Meridian Systems", "Vanguard Manufacturing"]
_FAKE_DOMAINS = ["nexus-tech.local", "orion-health.internal", "pinnacle-log.net", "meridian-sys.lan", "vanguard-mfg.corp"]
_FAKE_DB_NAMES = ["app_production", "main_database", "core_system_db", "enterprise_data", "operations_db"]
_FAKE_USERNAMES_LIST = [
    ["jmartinez", "schen", "akowalski"],
    ["rthompson", "lgarcia", "mjohnson"],
    ["dwilliams", "nkim", "bpetersen"],
    ["tadams", "jlee", "cbrooks"],
    ["epatel", "mwong", "kanderson"],
]
_COMPANY_TO_PERSONA = {
    "Nexus Technologies": "nexus", "Meridian Systems": "nexus",
    "Orion Healthcare": "orion", "Pinnacle Logistics": "orion",
    "Vanguard Manufacturing": "orion",
}

PERSONA_THEMES = {
    "legacy": {"name": "LegacyCMS", "bg": "#eef1f3", "accent": "#315a82", "text": "#333",
               "card_header": "#e9ecef", "btn": "#315a82", "hero_bg": "#e9ecef", "border": "#dee2e6",
               "tagline": "A familiar, slightly dated content-management experience.",
               "notice": "Server migration scheduled for Q4 2011.", "version": "2.4.1"},
    "nexus": {"name": "NexusPortal", "bg": "#0f172a", "accent": "#06b6d4", "text": "#e2e8f0",
              "card_header": "#1e293b", "btn": "#0891b2", "hero_bg": "#1e293b", "border": "#334155",
              "tagline": "Cloud-native content platform for modern teams.",
              "notice": "Scheduled maintenance window: Sunday 02:00-04:00 UTC.", "version": "3.1.0-beta"},
    "orion": {"name": "OrionHealth", "bg": "#f8fafc", "accent": "#1e40af", "text": "#1e293b",
              "card_header": "#dbeafe", "btn": "#1d4ed8", "hero_bg": "#dbeafe", "border": "#93c5fd",
              "tagline": "HIPAA-compliant content portal for healthcare teams.",
              "notice": "System audit completed - all compliance checks passed.", "version": "5.2.3"},
}


def generate_fake_world(session_id: str, db_path: str = None) -> dict:
    idx = hash(session_id) % len(_FAKE_COMPANIES)
    company = _FAKE_COMPANIES[idx]
    persona_id = _COMPANY_TO_PERSONA.get(company, "legacy")
    fake_world = {
        "fake_company": company, "fake_db_name": _FAKE_DB_NAMES[idx],
        "fake_usernames": _FAKE_USERNAMES_LIST[idx], "fake_domain": _FAKE_DOMAINS[idx],
        "persona_id": persona_id,
    }
    db = get_db(db_path)
    db.execute(
        "INSERT OR IGNORE INTO session_fake_world (session_id, fake_company, fake_db_name, fake_usernames, fake_domain, persona_id) VALUES (?, ?, ?, ?, ?, ?)",
        (session_id, fake_world["fake_company"], fake_world["fake_db_name"],
         json.dumps(fake_world["fake_usernames"]), fake_world["fake_domain"], persona_id),
    )
    db.commit()
    db.close()
    return fake_world


def get_fake_world(session_id: str, db_path: str = None):
    db = get_db(db_path)
    row = db.execute("SELECT * FROM session_fake_world WHERE session_id = ?", (session_id,)).fetchone()
    db.close()
    if row:
        persona_id = row["persona_id"] if "persona_id" in row.keys() else "legacy"
        return {
            "fake_company": row["fake_company"], "fake_db_name": row["fake_db_name"],
            "fake_usernames": json.loads(row["fake_usernames"]),
            "fake_domain": row["fake_domain"], "persona_id": persona_id,
        }
    return None


def get_all_sessions(status: str = None, db_path: str = None) -> list:
    db = get_db(db_path)
    if status:
        rows = db.execute("SELECT * FROM sessions WHERE status = ? ORDER BY last_seen DESC", (status,)).fetchall()
    else:
        rows = db.execute("SELECT * FROM sessions ORDER BY last_seen DESC").fetchall()
    db.close()
    return [dict(r) for r in rows]


def get_session_events(session_id: str, db_path: str = None, limit: int = None, offset: int = None) -> list:
    db = get_db(db_path)
    query = "SELECT * FROM logs WHERE session_id = ? ORDER BY timestamp ASC"
    params = [session_id]
    if limit is not None:
        query += " LIMIT ?"
        params.append(limit)
        if offset is not None:
            query += " OFFSET ?"
            params.append(offset)
    rows = db.execute(query, params).fetchall()
    db.close()
    return [dict(r) for r in rows]


def get_aggregate_stats(db_path: str = None) -> dict:
    db = get_db(db_path)
    total_sessions = db.execute("SELECT COUNT(*) as cnt FROM sessions").fetchone()["cnt"]
    total_events = db.execute("SELECT COUNT(*) as cnt FROM logs").fetchone()["cnt"]
    top_actions = db.execute(
        "SELECT action, COUNT(*) as cnt FROM logs GROUP BY action ORDER BY cnt DESC LIMIT 10"
    ).fetchall()
    db.close()
    return {
        "total_sessions": total_sessions, "total_events": total_events,
        "most_frequent_actions": [{"action": r["action"], "count": r["cnt"]} for r in top_actions],
    }


def get_unlocked_node_ids(session_id: str, db_path: str = None) -> set:
    db = get_db(db_path)
    rows = db.execute(
        "SELECT node_id FROM session_unlocked_nodes WHERE session_id = ?", (session_id,),
    ).fetchall()
    db.close()
    return {row["node_id"] for row in rows}


def get_session_events_for_graph(session_id: str, db_path: str = None) -> list:
    db = get_db(db_path)
    rows = db.execute(
        "SELECT action, parameters, response_type FROM logs WHERE session_id = ? ORDER BY timestamp ASC",
        (session_id,),
    ).fetchall()
    db.close()
    return [dict(r) for r in rows]


def insert_unlocked_node(session_id: str, node_id: str, unlocked_at: str, db_path: str = None):
    db = get_db(db_path)
    db.execute(
        "INSERT OR IGNORE INTO session_unlocked_nodes (session_id, node_id, unlocked_at) VALUES (?, ?, ?)",
        (session_id, node_id, unlocked_at),
    )
    db.commit()
    db.close()


def check_post_reveal_reuse(session_id: str, username: str, db_path: str = None) -> bool:
    db = get_db(db_path)
    terminal = db.execute(
        "SELECT 1 FROM session_unlocked_nodes WHERE session_id = ? AND node_id = 'terminal_reveal'",
        (session_id,),
    ).fetchone()
    if not terminal:
        db.close()
        return False
    fake_world = get_fake_world(session_id, db_path)
    if not fake_world:
        db.close()
        return False
    if username in fake_world["fake_usernames"]:
        db.execute(
            """UPDATE logs SET response_type = 'post_reveal_credential_reuse'
               WHERE id = (
                   SELECT id FROM logs WHERE session_id = ? AND response_type = 'login_failed'
                   ORDER BY id DESC LIMIT 1
               )""",
            (session_id,),
        )
        db.commit()
        db.close()
        logger.info(f"Post-reveal credential reuse detected in session {session_id}: username={username}")
        return True
    db.close()
    return False
