"""
postgres_adapter/pg_protocol.py
=================================

Low-level PostgreSQL frontend/backend protocol (v3.0) helpers: message
framing, the startup-message exchange (including SSL/GSS-encryption
negotiation real clients attempt before the real handshake), MD5
password-auth request/response, and query-response builders
(RowDescription / DataRow / CommandComplete / ErrorResponse /
ReadyForQuery).

Mirrors mysql_adapter/protocol.py's role exactly: pure wire-format
plumbing, zero decision logic. No real authentication, no real query
execution lives in this file — see pg_userdb.py and
pg_decide_response.py for that.

Byte order note: unlike MySQL (little-endian), the Postgres wire
protocol is BIG-endian throughout.
"""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass, field
from typing import Optional

from shared.limits import IDLE_TIMEOUT_SECONDS

# ---------------------------------------------------------------------
# Special startup-phase request codes a real client may send BEFORE
# the actual StartupMessage — we must answer these or clients that
# default to "try encryption first" (psql, psycopg2) will hang/fail.
# ---------------------------------------------------------------------
SSL_REQUEST_CODE = 80877103          # 0x04D2162F
GSSENC_REQUEST_CODE = 80877104       # 0x04D2162E
PROTOCOL_VERSION_3 = 196608          # 0x00030000

# Postgres auth type codes (sent inside an AuthenticationXXX 'R' message)
AUTH_TYPE_OK = 0
AUTH_TYPE_MD5_PASSWORD = 5


# ---------------------------------------------------------------------
# Post-startup message framing: 1-byte type + 4-byte big-endian length
# (length includes itself, excludes the type byte) + payload.
# ---------------------------------------------------------------------


def pack_message(msg_type: bytes, payload: bytes) -> bytes:
    length = struct.pack(">I", len(payload) + 4)
    return msg_type + length + payload


MAX_MESSAGE_SIZE = 1_000_000  # 1 MB — same rationale as MySQL's MAX_PACKET_SIZE


async def read_message(reader) -> tuple[bytes, bytes]:
    """Reads one post-startup message. Returns (type_byte, payload)."""
    header = await asyncio.wait_for(reader.readexactly(5), timeout=IDLE_TIMEOUT_SECONDS)
    msg_type = header[0:1]
    length = struct.unpack(">I", header[1:5])[0]
    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f"declared message length {length} exceeds MAX_MESSAGE_SIZE {MAX_MESSAGE_SIZE}")
    payload = await asyncio.wait_for(reader.readexactly(length - 4), timeout=IDLE_TIMEOUT_SECONDS) if length > 4 else b""
    return msg_type, payload


# ---------------------------------------------------------------------
# Startup phase: handles SSLRequest / GSSENCRequest negotiation (both
# declined — we don't support either), then parses the real
# StartupMessage's key/value parameters.
# ---------------------------------------------------------------------


@dataclass
class StartupInfo:
    protocol_version: int
    parameters: dict = field(default_factory=dict)  # e.g. {"user": ..., "database": ...}


async def read_startup_message(reader, writer) -> StartupInfo:
    """
    Loops past any SSLRequest / GSSENCRequest probes (declining each
    with a single 'N' byte, telling the client "not supported, continue
    unencrypted") until it receives the real StartupMessage, then parses
    and returns it.
    """
    while True:
        header = await asyncio.wait_for(reader.readexactly(8), timeout=IDLE_TIMEOUT_SECONDS)
        length = struct.unpack(">I", header[0:4])[0]
        code_or_version = struct.unpack(">I", header[4:8])[0]

        if length > MAX_MESSAGE_SIZE:
            raise ValueError(f"declared startup length {length} exceeds MAX_MESSAGE_SIZE {MAX_MESSAGE_SIZE}")

        if code_or_version in (SSL_REQUEST_CODE, GSSENC_REQUEST_CODE):
            # Length is always exactly 8 for these probes — nothing more
            # to read. Decline; client will retry with a plain startup.
            kind = "SSLRequest" if code_or_version == SSL_REQUEST_CODE else "GSSENCRequest"
            print(f"[*] {kind} received, declining with 'N' (unencrypted)")
            writer.write(b"N")
            await writer.drain()
            continue

        # Real StartupMessage: remaining bytes are (length - 8) of
        # null-terminated "key\0value\0" pairs, ending with a lone \0.
        remaining = await asyncio.wait_for(reader.readexactly(length - 8), timeout=IDLE_TIMEOUT_SECONDS)
        parameters = {}
        pos = 0
        while pos < len(remaining) and remaining[pos] != 0:
            key, pos = _read_cstring(remaining, pos)
            value, pos = _read_cstring(remaining, pos)
            parameters[key] = value

        return StartupInfo(protocol_version=code_or_version, parameters=parameters)


def _read_cstring(buf: bytes, pos: int) -> tuple[str, int]:
    end = buf.index(b"\x00", pos)
    return buf[pos:end].decode("utf-8", errors="replace"), end + 1


# ---------------------------------------------------------------------
# Server -> Client: authentication messages
# ---------------------------------------------------------------------


def build_auth_md5_password(salt: bytes) -> bytes:
    """salt must be exactly 4 bytes."""
    assert len(salt) == 4
    payload = struct.pack(">I", AUTH_TYPE_MD5_PASSWORD) + salt
    return pack_message(b"R", payload)


def build_auth_ok() -> bytes:
    payload = struct.pack(">I", AUTH_TYPE_OK)
    return pack_message(b"R", payload)


def build_parameter_status(name: str, value: str) -> bytes:
    payload = name.encode("utf-8") + b"\x00" + value.encode("utf-8") + b"\x00"
    return pack_message(b"S", payload)


def build_backend_key_data(process_id: int, secret_key: int) -> bytes:
    payload = struct.pack(">II", process_id, secret_key)
    return pack_message(b"K", payload)


def build_ready_for_query(status: bytes = b"I") -> bytes:
    """status: b'I' idle, b'T' in-transaction, b'E' failed-transaction."""
    return pack_message(b"Z", status)


# ---------------------------------------------------------------------
# Client -> Server: parse the PasswordMessage sent in response to an
# AuthenticationMD5Password request.
# ---------------------------------------------------------------------


def parse_password_message(payload: bytes) -> str:
    """Payload is a single null-terminated string, e.g. 'md5<32 hex chars>'."""
    return payload.rstrip(b"\x00").decode("utf-8", errors="replace")


def parse_query_message(payload: bytes) -> str:
    """Payload is a single null-terminated SQL string."""
    return payload.rstrip(b"\x00").decode("utf-8", errors="replace")


# ---------------------------------------------------------------------
# Server -> Client: ErrorResponse
# ---------------------------------------------------------------------


def build_error_response(severity: str, code: str, message: str) -> bytes:
    """
    code is a 5-char SQLSTATE (e.g. '28P01' = invalid_password,
    '3D000' = invalid_catalog_name / unknown database,
    '42601' = syntax_error).
    """
    payload = bytearray()
    payload += b"S" + severity.encode("ascii") + b"\x00"   # localized severity
    payload += b"V" + severity.encode("ascii") + b"\x00"   # non-localized severity
    payload += b"C" + code.encode("ascii") + b"\x00"
    payload += b"M" + message.encode("utf-8") + b"\x00"
    payload += b"\x00"  # terminator
    return pack_message(b"E", bytes(payload))


# ---------------------------------------------------------------------
# Server -> Client: a simple text query result set
# ---------------------------------------------------------------------

TEXT_OID = 25  # Postgres OID for the `text` type — fine for an all-text fake result set


def build_row_description(columns: list[str]) -> bytes:
    payload = bytearray()
    payload += struct.pack(">H", len(columns))
    for name in columns:
        payload += name.encode("utf-8") + b"\x00"
        payload += struct.pack(">I", 0)       # table OID (0 = not from a real table)
        payload += struct.pack(">H", 0)       # column attribute number
        payload += struct.pack(">I", TEXT_OID)
        payload += struct.pack(">h", -1)      # type size: -1 = variable-length
        payload += struct.pack(">i", -1)      # type modifier: -1 = none
        payload += struct.pack(">H", 0)       # format code: 0 = text
    return pack_message(b"T", bytes(payload))


def build_data_row(values: list[Optional[str]]) -> bytes:
    payload = bytearray()
    payload += struct.pack(">H", len(values))
    for v in values:
        if v is None:
            payload += struct.pack(">i", -1)  # NULL marker
        else:
            v_bytes = str(v).encode("utf-8")
            payload += struct.pack(">i", len(v_bytes))
            payload += v_bytes
    return pack_message(b"D", bytes(payload))


def build_command_complete(tag: str) -> bytes:
    """tag examples: 'SELECT 3', 'SET', 'INSERT 0 1'."""
    payload = tag.encode("utf-8") + b"\x00"
    return pack_message(b"C", payload)
