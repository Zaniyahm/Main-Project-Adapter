"""
tests/test_pg_client.py
=========================
Automated regression test for the PostgreSQL honeypot adapter — the
Postgres counterpart to tests/run_demo_commands.py (MySQL). Requires
psycopg2-binary: pip install psycopg2-binary --break-system-packages

Run with the adapter already listening:
    PG_HONEYPOT_PORT=5432 python3 postgres_adapter/pg_server.py &
    python3 tests/test_pg_client.py

Note: \\l and \\dt are psql client-side meta-commands, not real SQL —
psycopg2 can't send them directly. The exact SQL text psql translates
them into (captured live against a real psql client during Phase 3
sub-goal 1/2 verification) is used below instead, so this test
exercises the identical code path a real psql \\l / \\dt would.
"""
import sys
import psycopg2


def section(title):
    print(f"\n{'='*70}\n{title}\n{'='*70}")


def run(cur, sql, label=None):
    print(f"\n{label or sql}")
    try:
        cur.execute(sql)
        if cur.description:
            cols = [d[0] for d in cur.description]
            print(f"  columns: {cols}")
            for row in cur.fetchall():
                print(f"  {row}")
        else:
            print(f"  OK ({cur.statusmessage})")
    except psycopg2.Error as e:
        print(f"  ERROR {e.pgcode}: {e.pgerror.strip() if e.pgerror else e}")
        cur.connection.rollback()


section("1. Rejected login (wrong password)")
try:
    psycopg2.connect(host="127.0.0.1", port=5432, user="admin", password="wrongpass", dbname="app_db")
    print("  CONNECTED (unexpected — should have been rejected)")
except psycopg2.OperationalError as e:
    print(f"  REJECTED as expected: {e}".strip())

section("2. Unknown database at connect time")
try:
    psycopg2.connect(host="127.0.0.1", port=5432, user="admin", password="admin", dbname="totally_fake_db")
    print("  CONNECTED (unexpected — should have been rejected)")
except psycopg2.OperationalError as e:
    print(f"  REJECTED as expected: {e}".strip())

section("3. Accepted login (admin/admin) + full session")
conn = psycopg2.connect(host="127.0.0.1", port=5432, user="admin", password="admin", dbname="app_db")
conn.autocommit = True
cur = conn.cursor()
print("  Connected OK.")

run(cur, "SELECT version();")
run(cur, "SELECT current_database();")
run(cur, "SELECT current_user;")

run(cur, """
SELECT d.datname as "Name", pg_catalog.pg_get_userbyid(d.datdba) as "Owner",
       pg_catalog.pg_encoding_to_char(d.encoding) as "Encoding",
       d.datcollate as "Collate", d.datctype as "Ctype",
       pg_catalog.array_to_string(d.datacl, E'\\n') AS "Access privileges"
FROM pg_catalog.pg_database d ORDER BY 1;
""", label="\\l  (real query psql sends for this meta-command)")

run(cur, """
SELECT n.nspname as "Schema", c.relname as "Name",
       'table' as "Type", pg_catalog.pg_get_userbyid(c.relowner) as "Owner"
FROM pg_catalog.pg_class c
LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r','p','') AND n.nspname <> 'pg_catalog'
      AND n.nspname !~ '^pg_toast' AND n.nspname <> 'information_schema'
      AND pg_catalog.pg_table_is_visible(c.oid)
ORDER BY 1,2;
""", label="\\dt  (real query psql sends for this meta-command)")

run(cur, "SELECT * FROM users;")
run(cur, "SELECT * FROM orders;")
run(cur, "SELECT * FROM sessions;")
run(cur, "SELECT * FROM audit_log;")

section("4. pg_sleep injection probe (should error instantly, not sleep)")
import time
start = time.time()
run(cur, "SELECT pg_sleep(5);")
elapsed = time.time() - start
print(f"  elapsed: {elapsed:.3f}s  ({'PASS - did not actually sleep' if elapsed < 1 else 'FAIL - actually slept!'})")

section("5. COPY TO PROGRAM exploit attempt")
run(cur, "COPY (SELECT 1) TO PROGRAM 'id';")

section("6. Clean disconnect")
conn.close()
print("  connection closed cleanly")
