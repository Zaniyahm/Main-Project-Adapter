import pymysql
import sys

HOST = "127.0.0.1"
PORT = 3306


def try_login(user, password, label):
    print(f"\n--- {label}: user={user!r} password={password!r} ---")
    try:
        conn = pymysql.connect(host=HOST, port=PORT, user=user, password=password, connect_timeout=5)
        print("  LOGIN OK")
        return conn
    except pymysql.err.OperationalError as e:
        print(f"  LOGIN REJECTED: {e}")
        return None


# 1) Wrong password -> should be rejected
try_login("root", "totally-wrong-password", "Wrong password test")

# 2) Accepted weak credential -> should succeed
conn = try_login("root", "toor", "Accepted weak credential test")
if conn is None:
    sys.exit("FAILED: expected accepted login to succeed")

cur = conn.cursor()

queries = [
    "SELECT VERSION()",
    "SELECT DATABASE()",
    "SELECT USER()",
    "SHOW DATABASES",
    "SHOW TABLES",
    "SELECT * FROM users",
    "SELECT * FROM users WHERE id=1 OR 1=1 -- ",  # injection-style probe
    "INSERT INTO users (username) VALUES ('x')",
]

for q in queries:
    print(f"\n>>> {q}")
    try:
        cur.execute(q)
        rows = cur.fetchall()
        print(f"    columns={[d[0] for d in cur.description] if cur.description else None}")
        print(f"    rows={rows}")
    except pymysql.err.Error as e:
        print(f"    ERROR RESPONSE: {e}")

conn.close()
print("\n--- test complete ---")
