"""Web accounts: password hashing, sessions, CSRF, login rate limiting."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time

ROLES = ("admin", "viewer")
MIN_PASSWORD = 10
SESSION_DAYS = 7
MAX_FAILURES = 5
FAILURE_WINDOW = 15 * 60
SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1}


class AuthError(ValueError):
    """A user-facing account error (bad input, forbidden change...)."""


# --- passwords -------------------------------------------------------------

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, dklen=32, **SCRYPT)
    return f"scrypt${SCRYPT['n']}${SCRYPT['r']}${SCRYPT['p']}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        computed = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n),
                                  r=int(r), p=int(p), dklen=len(digest) // 2)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(computed.hex(), digest)


# --- users -----------------------------------------------------------------

def check_new_user(username: str, password: str, role: str) -> str:
    username = username.strip()
    if not 1 <= len(username) <= 64 or not username.replace("-", "").replace("_", "") \
            .replace(".", "").replace("@", "").isalnum():
        raise AuthError("bad_username")
    if len(password) < MIN_PASSWORD:
        raise AuthError("short_password")
    if role not in ROLES:
        raise AuthError("bad_role")
    return username


def user_count(db) -> int:
    return db.execute("SELECT COUNT(*) FROM users").fetchone()[0]


def admin_count(db) -> int:
    return db.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]


def create_user(db, username: str, password: str, role: str = "viewer") -> int:
    username = check_new_user(username, password, role)
    try:
        with db:
            cur = db.execute("INSERT INTO users (username, pw_hash, role) VALUES (?, ?, ?)",
                             (username, hash_password(password), role))
    except Exception as exc:
        if "UNIQUE" in str(exc):
            raise AuthError("user_exists") from exc
        raise
    return cur.lastrowid


def get_user(db, user_id: int):
    return db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()


def find_user(db, username: str):
    return db.execute("SELECT * FROM users WHERE username=?", (username.strip(),)).fetchone()


def list_users(db):
    return db.execute("SELECT * FROM users ORDER BY username").fetchall()


def set_password(db, user_id: int, password: str) -> None:
    if len(password) < MIN_PASSWORD:
        raise AuthError("short_password")
    with db:
        db.execute("UPDATE users SET pw_hash=? WHERE id=?", (hash_password(password), user_id))
        db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))


def set_role(db, user_id: int, role: str) -> None:
    if role not in ROLES:
        raise AuthError("bad_role")
    user = get_user(db, user_id)
    if user is None:
        raise AuthError("no_user")
    if user["role"] == "admin" and role != "admin" and admin_count(db) <= 1:
        raise AuthError("last_admin")
    with db:
        db.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))


def delete_user(db, user_id: int) -> None:
    user = get_user(db, user_id)
    if user is None:
        raise AuthError("no_user")
    if user["role"] == "admin" and admin_count(db) <= 1:
        raise AuthError("last_admin")
    with db:
        db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        db.execute("DELETE FROM users WHERE id=?", (user_id,))


def set_lang(db, user_id: int, lang: str) -> None:
    with db:
        db.execute("UPDATE users SET lang=? WHERE id=?", (lang, user_id))


# --- first run -------------------------------------------------------------

def setup_code(db) -> str | None:
    """One-time code required to create the first admin. None once a user exists."""
    from .. import store
    if user_count(db):
        return None
    code = store.get_setting(db, "setup_code")
    if not code:
        code = "-".join(secrets.token_hex(2).upper() for _ in range(3))
        store.set_setting(db, "setup_code", code)
    return code


def finish_setup(db, code: str, username: str, password: str) -> int:
    from .. import store
    expected = setup_code(db)
    if expected is None:
        raise AuthError("setup_done")
    if not hmac.compare_digest(code.strip().upper(), expected):
        raise AuthError("bad_code")
    user_id = create_user(db, username, password, "admin")
    store.set_setting(db, "setup_code", None)
    return user_id


# --- sessions --------------------------------------------------------------

def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(db, user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    now = time.time()
    with db:
        db.execute("DELETE FROM sessions WHERE expires < ?", (now,))
        db.execute("INSERT INTO sessions (token_hash, user_id, csrf, expires) VALUES (?,?,?,?)",
                   (_token_hash(token), user_id, secrets.token_urlsafe(24),
                    now + SESSION_DAYS * 86400))
        db.execute("UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id=?", (user_id,))
    return token


def load_session(db, token: str | None):
    """Return (user row, csrf token) for a valid session cookie, else None."""
    if not token:
        return None
    row = db.execute("SELECT s.csrf, s.expires, u.* FROM sessions s JOIN users u "
                     "ON u.id = s.user_id WHERE s.token_hash=?", (_token_hash(token),)).fetchone()
    if row is None or row["expires"] < time.time():
        return None
    return row, row["csrf"]


def end_session(db, token: str | None) -> None:
    if token:
        with db:
            db.execute("DELETE FROM sessions WHERE token_hash=?", (_token_hash(token),))


def check_csrf(expected: str, given: str | None) -> bool:
    return bool(given) and hmac.compare_digest(expected, given)


# --- brute force -----------------------------------------------------------

def too_many_failures(db, ip: str) -> bool:
    since = time.time() - FAILURE_WINDOW
    with db:
        db.execute("DELETE FROM login_attempts WHERE ts < ?", (since,))
    count = db.execute("SELECT COUNT(*) FROM login_attempts WHERE ip=?", (ip,)).fetchone()[0]
    return count >= MAX_FAILURES


def record_failure(db, ip: str) -> None:
    with db:
        db.execute("INSERT INTO login_attempts (ip, ts) VALUES (?, ?)", (ip, time.time()))


def login(db, username: str, password: str, ip: str):
    """Return the user row, or raise AuthError."""
    if too_many_failures(db, ip):
        raise AuthError("locked")
    user = find_user(db, username)
    # Hash anyway so timing does not reveal whether the user exists
    stored = user["pw_hash"] if user else hash_password("timing-equaliser")
    if not verify_password(password, stored) or user is None:
        record_failure(db, ip)
        raise AuthError("bad_login")
    with db:
        db.execute("DELETE FROM login_attempts WHERE ip=?", (ip,))
    return user
