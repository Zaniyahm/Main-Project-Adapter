"""
mysql_adapter/userdb.py
========================
Deliberately weak, honeypot-style credential acceptance — the MySQL
equivalent of Cowrie's userdb.txt. We are NOT authenticating against any
real account. We are deciding, for deception purposes, which fake
username/password combinations this fake server "accepts" so that
credential-brute-forcers get a plausible login success and keep
interacting (generating richer session data) instead of a database
that always rejects everything and gets abandoned after one probe.

All logic here is self-contained and fake. Nothing touches a real MySQL
instance, a real OS user table, or any real secret.
"""

from __future__ import annotations

import hashlib

# (username, password) pairs this fake server will "accept".
# Deliberately the most common weak/default MySQL credentials attackers
# actually try, so brute-force sessions look successful and continue.
ACCEPTED_CREDENTIALS = {
    ("root", ""),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("root", "123456"),
    ("admin", "admin"),
    ("admin", "password"),
    ("mysql", "mysql"),
    ("test", "test"),
}


def _scramble_native(password: bytes, salt: bytes) -> bytes:
    """
    mysql_native_password's scramble algorithm:
    SHA1(password) XOR SHA1(salt + SHA1(SHA1(password)))
    """
    if not password:
        return b""
    stage1 = hashlib.sha1(password).digest()
    stage2 = hashlib.sha1(stage1).digest()
    stage3 = hashlib.sha1(salt + stage2).digest()
    return bytes(a ^ b for a, b in zip(stage1, stage3))


def _scramble_caching_sha2(password: bytes, salt: bytes) -> bytes:
    """
    caching_sha2_password's "fast auth" scramble: same structure as
    mysql_native_password above, with SHA-256 in place of SHA1, and
    the final hash order matching what real MySQL 8 clients compute.

    SHA256(password) XOR SHA256(SHA256(SHA256(password)) + salt)
    """
    if not password:
        return b""
    stage1 = hashlib.sha256(password).digest()
    stage2 = hashlib.sha256(stage1).digest()
    stage3 = hashlib.sha256(stage2 + salt).digest()
    return bytes(a ^ b for a, b in zip(stage1, stage3))


def check_login(username: str, auth_response: bytes, salt: bytes,
                 client_plugin: str | None = None) -> bool:
    """
    Returns True if (username, <whatever plaintext password produced
    auth_response for this salt>) matches one of our accepted fake
    credentials. This never sees or stores a real plaintext password —
    it just checks candidates from our own small accepted list.

    client_plugin tells us which scramble algorithm the connecting
    client actually used, since protocol.py advertises
    caching_sha2_password (MySQL 8's default) but must still correctly
    verify clients that explicitly request the legacy
    mysql_native_password plugin too.
    """
    if not auth_response:
        # Empty auth response = client tried an empty password,
        # regardless of which plugin was in play.
        return (username, "") in ACCEPTED_CREDENTIALS

    scramble_fn = (
        _scramble_caching_sha2
        if client_plugin == "caching_sha2_password"
        else _scramble_native
    )

    for (u, p) in ACCEPTED_CREDENTIALS:
        if u != username:
            continue
        candidate = scramble_fn(p.encode("utf-8"), salt)
        if candidate == auth_response:
            return True
    return False
