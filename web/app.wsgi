"""Web version of phishlens (WSGI, standard library only).

The email is analysed in memory: nothing is written to disk and no link is opened.
"""

import json
import os
import re
import sys
from email import message_from_bytes, policy
from email.message import Message
from html import escape
from pathlib import Path

# Make the phishlens package (parent folder) importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from phishlens import ai, store  # noqa: E402
from phishlens.analyzer import analyze_bytes  # noqa: E402

AI_ENV = Path(os.environ.get("PHISHLENS_AI_ENV", "/etc/phishlens/ai.env"))
if AI_ENV.is_file():
    for line in AI_ENV.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            name, value = line.split("=", 1)
            os.environ.setdefault(name.strip(), value.strip())

MAX_SIZE = 2 * 1024 * 1024  # 2 MB

CSS = """
body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:16px}
*{box-sizing:border-box}main{max-width:760px;margin:auto}
h1{margin-top:0}h2{font-size:1.2rem;margin-top:0}ul{padding-left:18px}li{margin-bottom:4px}
input[type=file]{width:100%;margin-top:6px;padding:8px 0}
textarea{border:1px solid #475569;border-radius:6px;padding:8px;font-size:16px;margin-top:6px}
details{border-top:1px solid #334155;padding:4px 0}summary{cursor:pointer;padding:10px 0}
@media(max-width:600px){body{padding:8px}section,form{padding:12px}button{width:100%;min-height:48px}}
section,form{background:#1e293b;border-radius:10px;padding:16px;margin-bottom:16px;overflow-wrap:anywhere}
textarea{width:100%;box-sizing:border-box;min-height:180px;background:#0f172a;color:inherit}
button{background:#38bdf8;border:0;border-radius:6px;padding:10px 18px;font-weight:bold}
.safe{color:#4ade80}.warn{color:#facc15}.bad{color:#f87171}
"""

HEADERS = [
    ("Content-Type", "text/html; charset=utf-8"),
    ("Content-Security-Policy",
     "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
     "frame-ancestors 'none'; base-uri 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
]


def page(content: str = "") -> bytes:
    html = f"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>phishlens</title><style>{CSS}</style></head><body><main>
<h1>phishlens</h1>
<p>Analyse un e-mail suspect. Les messages envoyés ici ne sont pas enregistrés. Aucun lien n'est ouvert.</p>
<form method="post" enctype="multipart/form-data">
<p><label>Fichier .eml<br><input type="file" name="file" accept=".eml,message/rfc822"></label></p>
<p><label>ou colle la source complète du message<br><textarea name="source"></textarea></label></p>
<button>Analyser</button></form>{content}{dashboard()}</main></body></html>"""
    return html.encode("utf-8", errors="replace")


def dashboard() -> str:
    """Latest results of the mailbox connector."""
    try:
        db = store.connect()
        try:
            rows = store.latest(db)
        finally:
            db.close()
    except Exception:
        return "<section>Aucune boîte mail connectée.</section>"
    out = []
    for r in rows:
        css = {"PHISHING": "bad", "SUSPICIOUS": "warn"}.get(r["verdict"], "safe")
        opinion = f"<p><b>Avis IA :</b> {escape(r['ai'])}</p>" if r["ai"] else ""
        out.append(f"""<details><summary><span class="{css}">{r['score']}/100</span>
{escape(r['subject'] or '(sans sujet)')}</summary><p>De : {escape(r['sender'])}<br>
Analysé le {escape(r['scanned'])} UTC</p>{items(json.loads(r['findings']))}{opinion}</details>""")
    return "<section><h2>Boîte mail</h2>" + ("".join(out) or "<p>Aucun message analysé.</p>") + "</section>"


def read_form(content_type: str, body: bytes) -> bytes:
    """Return the uploaded file, or the pasted text, from a multipart body.

    Split by hand: browsers label .eml files message/rfc822, and the email
    parser would treat such a part as a nested message instead of raw bytes.
    """
    header = Message()
    header["Content-Type"] = content_type
    boundary = header.get_boundary()
    if not boundary:
        return b""
    fields = {}
    delimiter = b"\r\n--" + boundary.encode("latin-1")
    for chunk in (b"\r\n" + body).split(delimiter)[1:]:
        head, separator, data = chunk.partition(b"\r\n\r\n")
        name = re.search(rb'\bname="([^"]*)"', head)
        if separator and name:
            fields[name.group(1)] = data
    return fields.get(b"file") or fields.get(b"source", b"").strip()


def items(values) -> str:
    return "<ul>" + "".join(f"<li>{escape(v)}</li>" for v in values) + "</ul>" if values else "<p>Aucun</p>"


def render(report) -> str:
    css = {"PHISHING": "bad", "SUSPICIOUS": "warn"}.get(report.verdict, "safe")
    headers = [f"Sujet : {report.subject}", f"De : {report.sender}",
               f"Répondre à : {report.reply_to or '-'}",
               "  ".join(f"{k.upper()}={v}" for k, v in report.auth.items())]
    findings = [f"+{f.points} [{f.category}] {f.message}"
                for f in sorted(report.findings, key=lambda f: -f.points)]
    # Links are shown as plain text on purpose: nobody should click them
    links = [link.url for link in report.links]
    files = [f"{a.filename} ({a.content_type}, {a.size} octets) SHA-256 : {a.sha256}"
             for a in report.attachments]
    return f"""<section><h2 class="{css}">{report.verdict} : {report.score}/100</h2>{items(headers)}</section>
<section><h2>Alertes</h2>{items(findings)}</section>
<section><h2>Liens</h2>{items(links)}</section>
<section><h2>Pièces jointes</h2>{items(files)}</section>"""


def error(message: str) -> str:
    return f'<section class="bad">{escape(message)}</section>'


def opinion(raw: bytes) -> str:
    if not ai.enabled():
        return ""
    msg = message_from_bytes(raw, policy=policy.default)
    try:
        text = ai.ask_ai(msg, analyze_bytes(raw))
    except Exception:
        return error("IA indisponible : seul le résultat des règles est affiché.")
    return f"<section><h2>Avis IA (indicatif)</h2><p>{escape(text)}</p></section>"


def application(environ, start_response):
    status, content = "200 OK", ""
    if environ["REQUEST_METHOD"] == "POST":
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = -1
        if not 0 < length <= MAX_SIZE:
            status = "413 Content Too Large" if length > MAX_SIZE else "400 Bad Request"
            content = error("Message vide ou trop gros (2 Mo maximum).")
        else:
            try:
                raw = read_form(environ.get("CONTENT_TYPE", ""),
                                environ["wsgi.input"].read(length))
                if raw:
                    content = render(analyze_bytes(raw)) + opinion(raw)
                else:
                    content = error("Ajoute un fichier ou colle un message.")
            except Exception:  # hostile input must never leak a traceback
                print("phishlens: analysis failed", file=environ["wsgi.errors"])
                status, content = "400 Bad Request", error("Impossible d'analyser ce message.")
    body = page(content)
    start_response(status, HEADERS + [("Content-Length", str(len(body)))])
    return [body]
