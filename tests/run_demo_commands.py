import pymysql

def section(title):
    print(f"\n{'='*70}\n{title}\n{'='*70}")

section("CONNECT: mysql -h 127.0.0.1 -P 3306 -u admin -p")
conn = pymysql.connect(host="127.0.0.1", port=3306, user="admin", password="admin")
print(f"Connected OK. Server version reported by client lib: {conn.get_server_info()}")
cur = conn.cursor()

def run(sql):
    print(f"\nmysql> {sql}")
    try:
        cur.execute(sql)
        rows = cur.fetchall()
        if cur.description:
            cols = [d[0] for d in cur.description]
            print(f"  columns: {cols}")
        for r in rows:
            print(f"  {r}")
        if not rows and not cur.description:
            print(f"  OK, {cur.rowcount} row(s) affected")
    except pymysql.err.MySQLError as e:
        print(f"  ERROR {e.args[0]} ({e.args[1]})")

section("SHOW DATABASES;")
run("SHOW DATABASES;")

section("USE app_db; SHOW TABLES;")
run("USE app_db;")
run("SHOW TABLES;")

section("SHOW TABLES FROM performance_schema;")
run("SHOW TABLES FROM performance_schema;")

section("SHOW TABLES FROM fake_random_db;  (expect 1049 Unknown database)")
run("SHOW TABLES FROM fake_random_db;")

section("USE fake_random_db;  (expect 1049 Unknown database, via COM_INIT_DB)")
try:
    cur.execute("USE fake_random_db;")
    print("  (unexpectedly succeeded)")
except pymysql.err.MySQLError as e:
    print(f"  ERROR {e.args[0]} ({e.args[1]})")
except Exception as e:
    print(f"  connection-level exception: {e}")

# USE failure via COM_INIT_DB can behave differently across client libs;
# reconnect fresh to keep the rest of the demo clean either way.
try:
    conn.ping(reconnect=False)
except Exception:
    conn = pymysql.connect(host="127.0.0.1", port=3306, user="admin", password="admin", database="app_db")
    cur = conn.cursor()

section("Recon queries")
run("SELECT VERSION();")
run("SELECT @@version_comment;")
run("SELECT DATABASE();")
run("SELECT USER();")

section("SELECT * FROM users;")
run("SELECT * FROM users;")

section("SELECT * FROM orders;  (previously empty — should now return fake rows)")
run("SELECT * FROM orders;")

section("SELECT * FROM sessions;  (previously empty — should now return fake rows)")
run("SELECT * FROM sessions;")

section("SELECT * FROM audit_log;  (previously empty — should now return fake rows)")
run("SELECT * FROM audit_log;")

section("SELECT @@version_comment;  (previously empty string — should now show '(Ubuntu)')")
run("SELECT @@version_comment;")

section("Real COM_INIT_DB (protocol-level, not typed SQL) via conn.select_db()")
try:
    conn.select_db("app_db")
    print("  select_db('app_db') succeeded")
except pymysql.err.MySQLError as e:
    print(f"  ERROR {e.args[0]} ({e.args[1]})")

try:
    conn.select_db("fake_random_db")
    print("  (unexpectedly succeeded)")
except pymysql.err.MySQLError as e:
    print(f"  ERROR {e.args[0]} ({e.args[1]})  <- expected 1049")

section("COM_PING  (conn.ping())")
try:
    conn.ping(reconnect=False)
    print("  PING OK")
except Exception as e:
    print(f"  PING failed: {e}")

section("Injection-pattern probe (expect 1064 syntax error, not real execution)")
run("SELECT * FROM users WHERE 1=1 UNION SELECT 1,2,3,4-- ")

section("COM_QUIT  (clean disconnect)")
conn.close()
print("  connection closed cleanly")
