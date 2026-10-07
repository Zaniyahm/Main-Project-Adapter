"""
TEMPORARY smoke-test only — proves pg_protocol.py's wire-level plumbing
against a real client BEFORE pg_userdb.py / pg_decide_response.py /
pg_server.py (sub-goals 2-3) exist. Accepts any password unconditionally
and returns one hardcoded fake row for any query. Throwaway.
"""
import asyncio
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from postgres_adapter import pg_protocol as pg

PORT = int(os.environ.get("PG_HONEYPOT_PORT", "5432"))


async def handle(reader, writer):
    try:
        startup = await pg.read_startup_message(reader, writer)
        print(f"[*] StartupMessage: {startup.parameters}")

        salt = secrets.token_bytes(4)
        writer.write(pg.build_auth_md5_password(salt))
        await writer.drain()

        msg_type, payload = await pg.read_message(reader)
        assert msg_type == b"p", f"expected PasswordMessage 'p', got {msg_type}"
        pw_response = pg.parse_password_message(payload)
        print(f"[*] PasswordMessage received: {pw_response[:10]}...")

        # Smoke test only: accept unconditionally.
        writer.write(pg.build_auth_ok())
        writer.write(pg.build_parameter_status("server_version", "14.10 (Debian 14.10-1)"))
        writer.write(pg.build_parameter_status("client_encoding", "UTF8"))
        writer.write(pg.build_backend_key_data(12345, 999))
        writer.write(pg.build_ready_for_query())
        await writer.drain()
        print("[*] auth OK, ready for query")

        while True:
            msg_type, payload = await pg.read_message(reader)
            if msg_type == b"X":
                print("[*] Terminate received")
                break
            if msg_type == b"Q":
                query = pg.parse_query_message(payload)
                print(f"[*] Query: {query!r}")
                writer.write(pg.build_row_description(["smoke_test_column"]))
                writer.write(pg.build_data_row(["it_works"]))
                writer.write(pg.build_command_complete("SELECT 1"))
                writer.write(pg.build_ready_for_query())
                await writer.drain()
            else:
                print(f"[*] unhandled message type: {msg_type}")

    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    except Exception as e:
        print(f"[!] error: {e}")
    finally:
        writer.close()


async def main():
    server = await asyncio.start_server(handle, "0.0.0.0", PORT)
    print(f"[*] pg_protocol smoke-test server listening on 0.0.0.0:{PORT}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
