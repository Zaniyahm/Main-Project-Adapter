"""
mysql_adapter/protocol.py
===========================

Low-level MySQL client/server wire protocol helpers: packet framing,
length-encoded integers/strings, the initial handshake packet, the
client handshake-response parser, and OK/ERR/result-set packet builders.

Reference behavior modeled on the real MySQL protocol (protocol version
10 / mysql_native_password), the same way the contract asks SSH adapters
to study Cowrie first rather than invent protocol handling from scratch.

Everything here is READ-ONLY protocol plumbing — no real authentication,
no real query execution lives in this file.
"""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass, field
from typing import Optional

from shared.limits import IDLE_TIMEOUT_SECONDS, MAX_PACKET_SIZE

# ---------------------------------------------------------------------
# Packet framing: 3-byte little-endian length + 1-byte sequence number
# ---------------------------------------------------------------------


def pack_packet(payload: bytes, seq: int) -> bytes:
    length = len(payload)
    header = struct.pack("<I", length)[:3] + struct.pack("<B", seq & 0xFF)
    return header + payload


MAX_PACKET_SIZE = MAX_PACKET_SIZE  # imported from shared/limits.py — single source of truth


async def read_packet(reader) -> tuple[bytes, int]:
    # Minimum Safe Deployment: idle timeout — a client that connects and
    # never sends anything (or slow-drips bytes) gets disconnected
    # rather than holding a connection/resources open indefinitely.
    header = await asyncio.wait_for(reader.readexactly(4), timeout=IDLE_TIMEOUT_SECONDS)
    length = header[0] | (header[1] << 8) | (header[2] << 16)
    if length > MAX_PACKET_SIZE:
        raise ValueError(f"declared packet length {length} exceeds MAX_PACKET_SIZE {MAX_PACKET_SIZE}")
    seq = header[3]
    payload = await asyncio.wait_for(reader.readexactly(length), timeout=IDLE_TIMEOUT_SECONDS) if length else b""
    return payload, seq


# ---------------------------------------------------------------------
# Length-encoded integers / strings (MySQL "lenenc" format)
# ---------------------------------------------------------------------


def read_lenenc_int(buf: bytes, pos: int) -> tuple[int, int]:
    first = buf[pos]
    if first < 0xFB:
        return first, pos + 1
    if first == 0xFC:
        return struct.unpack_from("<H", buf, pos + 1)[0], pos + 3
    if first == 0xFD:
        return int.from_bytes(buf[pos + 1 : pos + 4], "little"), pos + 4
    if first == 0xFE:
        return struct.unpack_from("<Q", buf, pos + 1)[0], pos + 9
    raise ValueError("invalid lenenc int prefix")


def write_lenenc_int(value: int) -> bytes:
    if value < 0xFB:
        return struct.pack("<B", value)
    if value < (1 << 16):
        return b"\xfc" + struct.pack("<H", value)
    if value < (1 << 24):
        return b"\xfd" + value.to_bytes(3, "little")
    return b"\xfe" + struct.pack("<Q", value)


def write_lenenc_str(s: bytes) -> bytes:
    return write_lenenc_int(len(s)) + s


def read_null_terminated(buf: bytes, pos: int) -> tuple[bytes, int]:
    end = buf.index(b"\x00", pos)
    return buf[pos:end], end + 1


# ---------------------------------------------------------------------
# Capability flags (only the ones we actually need to set/check)
# ---------------------------------------------------------------------

CLIENT_LONG_PASSWORD = 0x00000001
CLIENT_PROTOCOL_41 = 0x00000200
CLIENT_SECURE_CONNECTION = 0x00008000
CLIENT_PLUGIN_AUTH = 0x00080000
CLIENT_CONNECT_WITH_DB = 0x00000008
CLIENT_CONNECT_ATTRS = 0x00100000
CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000

SERVER_CAPS = (
    CLIENT_LONG_PASSWORD
    | CLIENT_PROTOCOL_41
    | CLIENT_SECURE_CONNECTION
    | CLIENT_PLUGIN_AUTH
    | CLIENT_CONNECT_WITH_DB
)

CHARSET_UTF8_GENERAL_CI = 0x21
SERVER_STATUS_AUTOCOMMIT = 0x0002

# MySQL 8.x defaults to caching_sha2_password. We never do real password
# verification either way (see userdb.check_login), so this only needs
# to match the *choreography* the plugin expects, not the real crypto
# behind it — advertise it, and answer its post-handshake exchange
# correctly so modern clients don't hang waiting for a phase-2 round
# trip that's never coming.
AUTH_PLUGIN_NAME = "caching_sha2_password"

# caching_sha2_password AuthMoreData status byte (server -> client):
# 0x03 = "fast auth succeeded, proceed as normal" (no phase-2 needed).
AUTH_MORE_DATA_FAST_AUTH_SUCCESS = 0x03


# ---------------------------------------------------------------------
# Server -> Client: initial handshake (protocol version 10)
# ---------------------------------------------------------------------


def build_handshake_v10(connection_id: int, server_version: str, salt: bytes) -> bytes:
    """
    salt must be exactly 20 bytes; MySQL splits it into an 8-byte part
    and a 12-byte part (13th byte is a null terminator) across the
    packet, per protocol.
    """
    assert len(salt) == 20

    payload = bytearray()
    payload += struct.pack("<B", 10)  # protocol version
    payload += server_version.encode("utf-8") + b"\x00"
    payload += struct.pack("<I", connection_id)
    payload += salt[:8]
    payload += b"\x00"  # filler
    payload += struct.pack("<H", SERVER_CAPS & 0xFFFF)  # capability flags lower
    payload += struct.pack("<B", CHARSET_UTF8_GENERAL_CI)
    payload += struct.pack("<H", SERVER_STATUS_AUTOCOMMIT)
    payload += struct.pack("<H", (SERVER_CAPS >> 16) & 0xFFFF)  # capability flags upper
    payload += struct.pack("<B", 21)  # auth plugin data length (fixed for mysql_native_password)
    payload += b"\x00" * 10  # reserved
    payload += salt[8:20] + b"\x00"  # remaining 12 salt bytes + null terminator
    payload += AUTH_PLUGIN_NAME.encode("ascii") + b"\x00"
    return bytes(payload)


@dataclass
class HandshakeResponse:
    client_flags: int
    max_packet_size: int
    charset: int
    username: str
    auth_response: bytes
    database: Optional[str] = None
    client_plugin: Optional[str] = None


def parse_handshake_response(payload: bytes) -> HandshakeResponse:
    """
    Lenient parser covering the common case emitted by the real `mysql`
    CLI, most client libraries, and connection-testing tools (nmap
    service probes etc.) — CLIENT_PROTOCOL_41 with a 1-byte-length-
    prefixed auth response (CLIENT_SECURE_CONNECTION), optionally with
    a database name and/or plugin name appended.
    """
    pos = 0
    client_flags = struct.unpack_from("<I", payload, pos)[0]
    pos += 4
    max_packet_size = struct.unpack_from("<I", payload, pos)[0]
    pos += 4
    charset = payload[pos]
    pos += 1
    pos += 23  # reserved

    username_bytes, pos = read_null_terminated(payload, pos)
    username = username_bytes.decode("utf-8", errors="replace")

    if client_flags & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA:
        auth_len, pos = read_lenenc_int(payload, pos)
        auth_response = payload[pos : pos + auth_len]
        pos += auth_len
    elif client_flags & CLIENT_SECURE_CONNECTION:
        auth_len = payload[pos]
        pos += 1
        auth_response = payload[pos : pos + auth_len]
        pos += auth_len
    else:
        auth_response, pos = read_null_terminated(payload, pos)

    database = None
    if client_flags & CLIENT_CONNECT_WITH_DB and pos < len(payload):
        db_bytes, pos = read_null_terminated(payload, pos)
        database = db_bytes.decode("utf-8", errors="replace")

    client_plugin = None
    if client_flags & CLIENT_PLUGIN_AUTH and pos < len(payload):
        try:
            plugin_bytes, pos = read_null_terminated(payload, pos)
            client_plugin = plugin_bytes.decode("utf-8", errors="replace")
        except ValueError:
            pass  # no null terminator present, tolerate and move on

    return HandshakeResponse(
        client_flags=client_flags,
        max_packet_size=max_packet_size,
        charset=charset,
        username=username,
        auth_response=bytes(auth_response),
        database=database,
        client_plugin=client_plugin,
    )


# ---------------------------------------------------------------------
# Server -> Client: OK / ERR packets
# ---------------------------------------------------------------------


def build_ok_packet(affected_rows: int = 0, last_insert_id: int = 0) -> bytes:
    payload = bytearray()
    payload += b"\x00"  # OK header
    payload += write_lenenc_int(affected_rows)
    payload += write_lenenc_int(last_insert_id)
    payload += struct.pack("<H", SERVER_STATUS_AUTOCOMMIT)
    payload += struct.pack("<H", 0)  # warnings
    return bytes(payload)


def build_auth_more_data(status: int = AUTH_MORE_DATA_FAST_AUTH_SUCCESS) -> bytes:
    """
    caching_sha2_password's AuthMoreData packet: header byte 0x01
    followed by a single plugin-specific status byte. We only ever
    send the "fast auth succeeded" status (0x03) — we never do real
    verification, so there is no phase-2 (full auth / RSA) branch to
    implement here.
    """
    payload = bytearray()
    payload += b"\x01"  # AuthMoreData packet header
    payload += struct.pack("<B", status)
    return bytes(payload)


def build_err_packet(code: int, message: str, sql_state: str = "28000") -> bytes:
    payload = bytearray()
    payload += b"\xff"  # ERR header
    payload += struct.pack("<H", code)
    payload += b"#" + sql_state.encode("ascii")
    payload += message.encode("utf-8")
    return bytes(payload)


# ---------------------------------------------------------------------
# Server -> Client: a simple text result set (columns + rows + EOF)
# ---------------------------------------------------------------------


def build_column_def(name: str, table: str = "") -> bytes:
    payload = bytearray()
    payload += write_lenenc_str(b"def")  # catalog
    payload += write_lenenc_str(table.encode())  # schema
    payload += write_lenenc_str(table.encode())  # table
    payload += write_lenenc_str(table.encode())  # org_table
    payload += write_lenenc_str(name.encode())  # name
    payload += write_lenenc_str(name.encode())  # org_name
    payload += write_lenenc_int(0x0C)  # length of fixed fields
    payload += struct.pack("<H", CHARSET_UTF8_GENERAL_CI)
    payload += struct.pack("<I", 255)  # column length
    payload += struct.pack("<B", 0xFD)  # type: VAR_STRING
    payload += struct.pack("<H", 0)  # flags
    payload += struct.pack("<B", 0)  # decimals
    payload += b"\x00\x00"  # filler
    return bytes(payload)


def build_eof_packet() -> bytes:
    payload = bytearray()
    payload += b"\xfe"
    payload += struct.pack("<H", 0)  # warnings
    payload += struct.pack("<H", SERVER_STATUS_AUTOCOMMIT)
    return bytes(payload)


def build_row_packet(values: list[str]) -> bytes:
    payload = bytearray()
    for v in values:
        if v is None:
            payload += b"\xfb"  # NULL
        else:
            payload += write_lenenc_str(str(v).encode("utf-8"))
    return bytes(payload)


def build_text_resultset(columns: list[str], rows: list[list[str]], table: str = "") -> list[bytes]:
    """
    Returns a list of raw packet PAYLOADS (not yet framed/sequenced) that
    together form a full text-protocol result set: column count, column
    defs, EOF, rows, final EOF. Caller assigns sequence numbers.
    """
    packets = [write_lenenc_int(len(columns))]
    for c in columns:
        packets.append(build_column_def(c, table))
    packets.append(build_eof_packet())
    for r in rows:
        packets.append(build_row_packet(r))
    packets.append(build_eof_packet())
    return packets
