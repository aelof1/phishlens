"""SQLite storage: mailbox scan results, web accounts and settings.

No email body is ever stored.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from pathlib import Path

SERVER_DIR = Path("/var/lib/phishlens")

SCHEMA = """
CREATE TABLE IF NOT EXISTS results (
    mailbox TEXT, uidvalidity TEXT, uid INTEGER,
    scanned TEXT DEFAULT CURRENT_TIMESTAMP,
    subject TEXT, sender TEXT, score INTEGER, verdict TEXT,
    findings TEXT, ai TEXT,
    PRIMARY KEY (mailbox, uidvalidity, uid));
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    pw_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
    lang TEXT,
    created TEXT DEFAULT CURRENT_TIMESTAMP,
    last_login TEXT);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf TEXT NOT NULL,
    expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS login_attempts (ip TEXT, ts REAL);
"""


def default_path() -> Path:
    """Database location: PHISHLENS_DB, else a per-OS data folder."""
    if os.environ.get("PHISHLENS_DB"):
        return Path(os.environ["PHISHLENS_DB"])
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        return base / "phishlens" / "phishlens.db"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "phishlens" / "phishlens.db"
    if SERVER_DIR.is_dir():  # created by deploy/install.sh
        return SERVER_DIR / "phishlens.db"
    base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "phishlens" / "phishlens.db"


def connect(path: str | None = None) -> sqlite3.Connection:
    target = Path(path) if path else default_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(target, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript(SCHEMA)
    return db


# --- mailbox results -------------------------------------------------------

def seen(db, mailbox: str, uidvalidity: str) -> set[int]:
    rows = db.execute("SELECT uid FROM results WHERE mailbox=? AND uidvalidity=?",
                      (mailbox, uidvalidity))
    return {row["uid"] for row in rows}


def save(db, mailbox, uidvalidity, uid, report, ai_text) -> None:
    with db:
        db.execute(
            "INSERT OR IGNORE INTO results (mailbox, uidvalidity, uid, subject, sender,"
            " score, verdict, findings, ai) VALUES (?,?,?,?,?,?,?,?,?)",
            (mailbox, uidvalidity, uid, report.subject, report.sender, report.score,
             report.verdict, json.dumps([f.message for f in report.findings]), ai_text))


def latest(db, limit: int = 100, verdict: str | None = None) -> list[sqlite3.Row]:
    if verdict:
        return db.execute("SELECT * FROM results WHERE verdict=? "
                          "ORDER BY scanned DESC, uid DESC LIMIT ?", (verdict, limit)).fetchall()
    return db.execute("SELECT * FROM results ORDER BY scanned DESC, uid DESC LIMIT ?",
                      (limit,)).fetchall()


def stats(db) -> dict:
    counts = {row["verdict"]: row["n"] for row in
              db.execute("SELECT verdict, COUNT(*) AS n FROM results GROUP BY verdict")}
    return {"total": sum(counts.values()), "PHISHING": counts.get("PHISHING", 0),
            "SUSPICIOUS": counts.get("SUSPICIOUS", 0),
            "PROBABLY SAFE": counts.get("PROBABLY SAFE", 0)}


# --- settings --------------------------------------------------------------

def get_setting(db, key: str, default: str | None = None) -> str | None:
    row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(db, key: str, value: str | None) -> None:
    with db:
        if value is None:
            db.execute("DELETE FROM settings WHERE key=?", (key,))
        else:
            db.execute("INSERT INTO settings (key, value) VALUES (?, ?) "
                       "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
