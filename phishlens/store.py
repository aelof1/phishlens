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
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts TEXT DEFAULT CURRENT_TIMESTAMP,
    source TEXT NOT NULL CHECK (source IN ('mailbox', 'upload')),
    score INTEGER, verdict TEXT, country TEXT);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
"""
# Columns added after 1.1, created on existing databases by connect()
MIGRATIONS = {"results": {"origin_ip": "TEXT", "country": "TEXT"}}


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
    for table, columns in MIGRATIONS.items():
        existing = {row["name"] for row in db.execute(f"PRAGMA table_info({table})")}
        for name, kind in columns.items():
            if name not in existing:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {kind}")
    return db


# --- mailbox results -------------------------------------------------------

def seen(db, mailbox: str, uidvalidity: str) -> set[int]:
    rows = db.execute("SELECT uid FROM results WHERE mailbox=? AND uidvalidity=?",
                      (mailbox, uidvalidity))
    return {row["uid"] for row in rows}


def save(db, mailbox, uidvalidity, uid, report, ai_text, country: str | None = None) -> None:
    with db:
        cur = db.execute(
            "INSERT OR IGNORE INTO results (mailbox, uidvalidity, uid, subject, sender,"
            " score, verdict, findings, ai, origin_ip, country) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (mailbox, uidvalidity, uid, report.subject, report.sender, report.score,
             report.verdict, json.dumps([f.message for f in report.findings]), ai_text,
             getattr(report, "origin_ip", "") or None, country))
        if cur.rowcount:
            db.execute("INSERT INTO events (source, score, verdict, country) VALUES ('mailbox', ?, ?, ?)",
                       (report.score, report.verdict, country))


def record_upload(db, report, country: str | None) -> None:
    """Anonymous statistic for an email analysed in the web interface: no content, no IP."""
    with db:
        db.execute("INSERT INTO events (source, score, verdict, country) VALUES ('upload', ?, ?, ?)",
                   (report.score, report.verdict, country))


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


def live_stats(db, hours: int = 24) -> dict:
    """Numbers for the dashboard: totals, last `hours` per hour, countries, latest messages."""
    def by_verdict(where: str = "", args=()):
        counts = {r["verdict"]: r["n"] for r in db.execute(
            f"SELECT verdict, COUNT(*) AS n FROM events {where} GROUP BY verdict", args)}
        return {"total": sum(counts.values()), "PHISHING": counts.get("PHISHING", 0),
                "SUSPICIOUS": counts.get("SUSPICIOUS", 0), "PROBABLY SAFE": counts.get("PROBABLY SAFE", 0)}

    since = f"-{int(hours)} hours"
    per_hour = {}
    for r in db.execute("SELECT substr(ts, 1, 13) AS h, verdict, COUNT(*) AS n FROM events "
                        "WHERE ts >= datetime('now', ?) GROUP BY h, verdict", (since,)):
        per_hour.setdefault(r["h"], {"PHISHING": 0, "SUSPICIOUS": 0, "PROBABLY SAFE": 0})[r["verdict"]] = r["n"]
    now = db.execute("SELECT strftime('%Y-%m-%d %H', 'now') AS h").fetchone()["h"]
    buckets = [r["h"] for r in db.execute(
        "WITH RECURSIVE k(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM k WHERE i < ?) "
        "SELECT strftime('%Y-%m-%d %H', 'now', '-' || i || ' hours') AS h FROM k ORDER BY h",
        (hours - 1,))]
    countries = [{"country": r["country"], "total": r["n"], "phishing": r["p"]} for r in db.execute(
        "SELECT country, COUNT(*) AS n, SUM(verdict = 'PHISHING') AS p FROM events "
        "WHERE country IS NOT NULL GROUP BY country ORDER BY n DESC")]
    latest = [dict(r) for r in db.execute(
        "SELECT subject, sender, score, verdict, country, scanned FROM results "
        "ORDER BY scanned DESC, uid DESC LIMIT 10")]
    last = db.execute("SELECT MAX(id) AS m FROM events").fetchone()["m"] or 0
    return {
        "all": by_verdict(),
        "today": by_verdict("WHERE ts >= date('now')"),
        "hours": [{"hour": h, **per_hour.get(h, {"PHISHING": 0, "SUSPICIOUS": 0, "PROBABLY SAFE": 0})}
                  for h in buckets],
        "now": now,
        "countries": countries,
        "unknown_country": db.execute("SELECT COUNT(*) FROM events WHERE country IS NULL").fetchone()[0],
        "latest": latest,
        "last_event": last,
    }


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
