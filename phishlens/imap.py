"""IMAP connector: scan new messages of one mailbox, strictly read-only.

Run with: python3 -m phishlens.imap
"""

from __future__ import annotations

import email
import imaplib
import os
import re
import ssl
import sys
from email import policy

from . import ai, store
from .analyzer import analyze_message

MAX_SIZE = 10 * 1024 * 1024


def scan(client, db, mailbox: str, folder: str, limit: int) -> int:
    """Analyse up to `limit` recent unseen-by-us messages. Returns how many."""
    status, _ = client.select(f'"{folder}"', readonly=True)
    if status != "OK":
        raise RuntimeError(f"cannot open folder {folder}")
    uidvalidity = client.response("UIDVALIDITY")[1][0].decode()
    key = f"{mailbox}/{folder}"
    status, data = client.uid("search", None, "ALL")
    if status != "OK":
        raise RuntimeError("IMAP search failed")
    known = store.seen(db, key, uidvalidity)
    ai_cfg = ai.config(db)
    recent = [int(u) for u in data[0].split()][-limit:]
    count = 0
    for uid in recent:
        if uid in known:
            continue
        try:
            _, info = client.uid("fetch", str(uid), "(RFC822.SIZE)")
            size = int(re.search(rb"RFC822\.SIZE (\d+)", info[0]).group(1))
            if size > MAX_SIZE:
                print(f"uid {uid}: skipped, too big ({size} bytes)", file=sys.stderr)
                continue
            # BODY.PEEK does not mark the message as read
            _, parts = client.uid("fetch", str(uid), "(BODY.PEEK[])")
            msg = email.message_from_bytes(parts[0][1], policy=policy.default)
            report = analyze_message(msg)
            opinion = ""
            if ai_cfg["url"]:
                try:
                    opinion = ai.ask_ai(msg, report, cfg=ai_cfg)
                except Exception as exc:
                    print(f"uid {uid}: AI unavailable ({exc})", file=sys.stderr)
            store.save(db, key, uidvalidity, uid, report, opinion)
            count += 1
        except (imaplib.IMAP4.abort, OSError):
            raise
        except Exception as exc:  # one broken email must not stop the scan
            print(f"uid {uid}: analysis failed ({type(exc).__name__})", file=sys.stderr)
    return count


def main() -> int:
    try:
        host = os.environ["PHISHLENS_IMAP_HOST"]
        user = os.environ["PHISHLENS_IMAP_USER"]
        password = os.environ["PHISHLENS_IMAP_PASSWORD"]
    except KeyError as exc:
        print(f"error: missing setting {exc}", file=sys.stderr)
        return 2
    port = int(os.environ.get("PHISHLENS_IMAP_PORT", "993"))
    context = ssl.create_default_context(cafile=os.environ.get("PHISHLENS_IMAP_CAFILE") or None)
    db = store.connect()
    with imaplib.IMAP4_SSL(host, port, ssl_context=context, timeout=60) as client:
        client.login(user, password)
        count = scan(client, db, user,
                     os.environ.get("PHISHLENS_IMAP_FOLDER", "INBOX"),
                     int(os.environ.get("PHISHLENS_IMAP_LIMIT", "50")))
    print(f"{count} new message(s) analysed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
