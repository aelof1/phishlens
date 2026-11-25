"""SQLite storage for mailbox scan results (no email body is stored)."""

from __future__ import annotations

import json
import os
import sqlite3

DEFAULT_DB = "/var/lib/phishlens/phishlens.db"


def connect(path: str | None = None) -> sqlite3.Connection:
    db = sqlite3.connect(path or os.environ.get("PHISHLENS_DB", DEFAULT_DB), timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("""CREATE TABLE IF NOT EXISTS results (
        mailbox TEXT, uidvalidity TEXT, uid INTEGER,
        scanned TEXT DEFAULT CURRENT_TIMESTAMP,
        subject TEXT, sender TEXT, score INTEGER, verdict TEXT,
        findings TEXT, ai TEXT,
        PRIMARY KEY (mailbox, uidvalidity, uid))""")
    return db


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


def latest(db, limit: int = 100) -> list[sqlite3.Row]:
    return db.execute("SELECT * FROM results ORDER BY scanned DESC, uid DESC LIMIT ?",
                      (limit,)).fetchall()
