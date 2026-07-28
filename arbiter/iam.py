"""Built-in IAM: local accounts, two signed-in roles, stdlib-only crypto.

Per ADR-001:
- Public tier = no session (handled by the absence of a valid cookie).
- Signed-in roles: `analyst` (see + act) and `admin` (+ configure/manage).
- Passwords hashed with hashlib.scrypt; sessions are HMAC-signed cookies.
  No third-party crypto dependency.

This is deliberately small. SSO/OIDC and a read-only viewer role are
deferred; the session payload is a dict so an OIDC assertion can later slot
in without reworking role checks.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path

ROLES = ("analyst", "admin")
_SCRYPT = dict(n=16384, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=32)
SESSION_TTL = 8 * 3600          # 8-hour shift
MAX_FAILED = 5
LOCKOUT_SECONDS = 300

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT UNIQUE NOT NULL,
    role         TEXT NOT NULL,
    salt         BLOB NOT NULL,
    pw_hash      BLOB NOT NULL,
    created_at   TEXT NOT NULL,
    last_login   TEXT,
    failed       INTEGER NOT NULL DEFAULT 0,
    locked_until REAL NOT NULL DEFAULT 0
);
"""


def _hash(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)


def load_or_create_secret(path: str | Path) -> bytes:
    """Persist the HMAC session-signing secret across restarts.

    Without this, `IAM(secret=None)` falls back to a fresh random value
    every process start, silently invalidating every issued session cookie
    on restart or upgrade. Written once, 0600, next to wherever the caller
    keeps it (typically alongside the IAM database).
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        data = path.read_bytes()
        if len(data) == 32:
            return data
    secret = secrets.token_bytes(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    # Without O_BINARY, Windows' CRT opens in text mode and silently
    # rewrites any 0x0A byte in the random secret to 0x0D 0x0A — corrupting
    # roughly one in eight secrets so the next load's length check fails
    # and a new one gets generated, defeating persistence intermittently.
    flags |= getattr(os, "O_BINARY", 0)
    fd = os.open(str(path), flags, 0o600)
    try:
        os.write(fd, secret)
    finally:
        os.close(fd)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # best-effort on platforms without POSIX permission bits
    return secret


class IAM:
    def __init__(self, db_path: str | Path = "arbiter_iam.db",
                 secret: bytes | None = None) -> None:
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        # Server secret for cookie signing; regenerated per boot unless given.
        self._secret = secret or secrets.token_bytes(32)

    # -- accounts -----------------------------------------------------------
    def create_user(self, username: str, password: str, role: str) -> None:
        if role not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        from datetime import datetime, timezone
        salt = secrets.token_bytes(16)
        self.conn.execute(
            "INSERT INTO users (username,role,salt,pw_hash,created_at) "
            "VALUES (?,?,?,?,?)",
            (username, role, salt, _hash(password, salt),
             datetime.now(timezone.utc).isoformat()))
        self.conn.commit()

    def any_users(self) -> bool:
        return self.conn.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None

    def authenticate(self, username: str, password: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if row is None:
            return None
        if row["locked_until"] > time.time():
            return None  # locked out
        if hmac.compare_digest(row["pw_hash"], _hash(password, row["salt"])):
            from datetime import datetime, timezone
            self.conn.execute(
                "UPDATE users SET failed=0, locked_until=0, last_login=? "
                "WHERE id=?",
                (datetime.now(timezone.utc).isoformat(), row["id"]))
            self.conn.commit()
            return {"username": row["username"], "role": row["role"]}
        # wrong password → count toward lockout
        failed = row["failed"] + 1
        locked = time.time() + LOCKOUT_SECONDS if failed >= MAX_FAILED else 0
        self.conn.execute(
            "UPDATE users SET failed=?, locked_until=? WHERE id=?",
            (failed, locked, row["id"]))
        self.conn.commit()
        return None

    # -- sessions (HMAC-signed cookie, stateless) ---------------------------
    def issue_session(self, user: dict) -> str:
        payload = {"u": user["username"], "r": user["role"],
                   "exp": int(time.time()) + SESSION_TTL}
        raw = json.dumps(payload, separators=(",", ":")).encode()
        body = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        sig = hmac.new(self._secret, body.encode(), hashlib.sha256).hexdigest()
        return f"{body}.{sig}"

    def verify_session(self, cookie: str | None) -> dict | None:
        if not cookie or "." not in cookie:
            return None
        body, _, sig = cookie.partition(".")
        expected = hmac.new(self._secret, body.encode(),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        pad = "=" * (-len(body) % 4)
        try:
            payload = json.loads(base64.urlsafe_b64decode(body + pad))
        except Exception:
            return None
        if payload.get("exp", 0) < time.time():
            return None
        return {"username": payload["u"], "role": payload["r"]}

    def close(self) -> None:
        self.conn.close()
