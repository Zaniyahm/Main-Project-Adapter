"""
postgres_adapter/pg_userdb.py
================================
Deliberately weak, honeypot-style credential acceptance — the Postgres
equivalent of mysql_adapter/userdb.py. Not authenticating against any
real account; deciding which fake username/password combinations this
fake server "accepts" so credential-brute-forcers get a plausible login
success and keep interacting.

All logic here is self-contained and fake. Nothing touches a real
Postgres instance, OS user, or real secret.
"""

from __future__ import annotations

import hashlib

# (username, password) pairs this fake server will "accept". The most
# common weak/default Postgres credentials attackers actually try.
ACCEPTED_CREDENTIALS = {
    ("postgres", ""),
    ("postgres", "postgres"),
    ("postgres", "password"),
    ("postgres", "admin"),
    ("admin", "admin"),
    ("app_db", "app_db"),
}


def _md5_auth_response(username: str, password: str, salt: bytes) -> str:
    """
    Reimplementation of Postgres's MD5 auth response algorithm, used
    ONLY to compute what a client's response WOULD look like for a
    candidate plaintext password — so we can compare it against what
    the client actually sent, without ever needing a real password
    store.

    "md5" + MD5( MD5(password + username) + salt )
    """
    inner = hashlib.md5((password + username).encode("utf-8")).hexdigest()
    outer = hashlib.md5(inner.encode("utf-8") + salt).hexdigest()
    return "md5" + outer


def check_login(username: str, auth_response: str, salt: bytes) -> bool:
    """
    Returns True if (username, <whatever plaintext password produced
    auth_response for this salt>) matches one of our accepted fake
    credentials.
    """
    for (u, p) in ACCEPTED_CREDENTIALS:
        if u != username:
            continue
        if _md5_auth_response(username, p, salt) == auth_response:
            return True
    return False
