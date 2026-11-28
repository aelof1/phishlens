"""Command line interface.

  phishlens <file.eml>... [--json]      analyse emails
  phishlens web [--host] [--port]       start the web interface
  phishlens user add|reset-password|list|delete
"""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import os
import sys

from . import __version__
from .analyzer import analyze_file

COLORS = {"PHISHING": "\033[91m", "SUSPICIOUS": "\033[93m", "PROBABLY SAFE": "\033[92m"}
RESET = "\033[0m"


def print_report(path: str, report, color: bool) -> None:
    c = COLORS.get(report.verdict, "") if color else ""
    r = RESET if color else ""
    print(f"\n=== {path} ===")
    print(f"Subject    : {report.subject}")
    print(f"From       : {report.sender}")
    if report.reply_to:
        print(f"Reply-To   : {report.reply_to}")
    print("Auth       : " + "  ".join(f"{k.upper()}={v}" for k, v in report.auth.items()))
    print(f"Links      : {len(report.links)}")
    for link in report.links[:10]:
        print(f"   - {link.url}")
    print(f"Attachments: {len(report.attachments)}")
    for att in report.attachments:
        print(f"   - {att.filename} ({att.content_type}, {att.size} bytes) sha256={att.sha256[:16]}...")
    print("\nFindings:")
    if not report.findings:
        print("   nothing suspicious found")
    for f in sorted(report.findings, key=lambda x: -x.points):
        print(f"   [+{f.points:>2}] {f.category:<10} {f.message}")
    print(f"\nScore: {report.score}/100  ->  {c}{report.verdict}{r}\n")


def analyze_main(argv: list[str] | None) -> int:
    parser = argparse.ArgumentParser(
        prog="phishlens",
        description="Analyse .eml files and estimate how likely they are to be phishing. "
                    "Other commands: 'phishlens web' (web interface), 'phishlens user' (accounts).",
    )
    parser.add_argument("files", nargs="+", help="one or more .eml files")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    results = {}
    worst = 0
    for path in args.files:
        try:
            report = analyze_file(path)
        except OSError as exc:
            print(f"error: cannot read {path}: {exc}", file=sys.stderr)
            return 2
        worst = max(worst, report.score)
        if args.json:
            results[path] = report.to_dict()
        else:
            print_report(path, report, color=not args.no_color and sys.stdout.isatty())

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    # exit code is useful in scripts: 0 safe, 1 suspicious/phishing
    return 1 if worst >= 30 else 0


# --- web -------------------------------------------------------------------

def _is_local(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def web_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="phishlens web", description="Start the web interface.")
    parser.add_argument("--host", default=os.environ.get("PHISHLENS_HOST", "127.0.0.1"),
                        help="address to listen on (default 127.0.0.1; 0.0.0.0 for the whole network)")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PHISHLENS_PORT", "8000")))
    parser.add_argument("--db", help="SQLite database file (default: per-OS data folder)")
    parser.add_argument("--env-file", help="KEY=VALUE settings file, for example the AI settings")
    args = parser.parse_args(argv)

    from . import ai, config, store
    if args.db:
        os.environ["PHISHLENS_DB"] = args.db
    if args.env_file:
        if not config.load_env_file(args.env_file) and not os.path.isfile(args.env_file):
            print(f"error: cannot read {args.env_file}", file=sys.stderr)
            return 2

    from socketserver import ThreadingMixIn
    from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

    from .web import auth
    from .web.app import application

    class Server(ThreadingMixIn, WSGIServer):
        daemon_threads = True

    class Handler(WSGIRequestHandler):
        def log_message(self, fmt, *values):
            sys.stderr.write(f"{self.address_string()} - {fmt % values}\n")

    db = store.connect()
    code = auth.setup_code(db)
    db.close()
    try:
        httpd = make_server(args.host, args.port, application, Server, Handler)
    except OSError as exc:
        print(f"error: cannot listen on {args.host}:{args.port} ({exc})", file=sys.stderr)
        return 2
    shown = "localhost" if args.host in ("0.0.0.0", "::") else args.host
    print(f"phishlens {__version__} web interface: http://{shown}:{args.port}")
    print(f"  database : {store.default_path()}")
    print(f"  AI       : {ai.model_name() + ' via ' + os.environ['PHISHLENS_AI_URL'] if ai.enabled() else 'off'}")
    if code:
        print(f"\n  First start: open the page and create the admin account.\n  Setup code: {code}\n")
    if not _is_local(args.host):
        print("  Warning: reachable from the network over plain HTTP. Put it behind a reverse proxy "
              "with HTTPS (Caddy, Traefik, nginx) before exposing it.")
    print("Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()
    return 0


# --- users -----------------------------------------------------------------

def _ask_password() -> str:
    password = getpass.getpass("Password (10+ characters): ")
    if password != getpass.getpass("Confirm: "):
        raise SystemExit("error: passwords do not match")
    return password


def user_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="phishlens user", description="Manage web accounts.")
    parser.add_argument("--db", help="SQLite database file (default: per-OS data folder)")
    sub = parser.add_subparsers(dest="command", required=True)
    add = sub.add_parser("add", help="create an account")
    add.add_argument("username")
    add.add_argument("--role", choices=("admin", "viewer"), default="viewer")
    reset = sub.add_parser("reset-password", help="set a new password")
    reset.add_argument("username")
    sub.add_parser("list", help="list accounts")
    delete = sub.add_parser("delete", help="delete an account")
    delete.add_argument("username")
    args = parser.parse_args(argv)

    from . import store
    from .web import auth
    db = store.connect(args.db)
    try:
        if args.command == "list":
            for u in auth.list_users(db):
                print(f"{u['username']:<24} {u['role']:<7} last login: {u['last_login'] or 'never'}")
            return 0
        if args.command == "add":
            auth.create_user(db, args.username, _ask_password(), args.role)
            print(f"user {args.username} created ({args.role})")
            return 0
        user = auth.find_user(db, args.username)
        if user is None:
            print(f"error: no user {args.username}", file=sys.stderr)
            return 1
        if args.command == "reset-password":
            auth.set_password(db, user["id"], _ask_password())
            print("password updated, sessions signed out")
        else:
            auth.delete_user(db, user["id"])
            print(f"user {args.username} deleted")
        return 0
    except auth.AuthError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "web":
        return web_main(argv[1:])
    if argv and argv[0] == "user":
        return user_main(argv[1:])
    return analyze_main(argv)


if __name__ == "__main__":
    sys.exit(main())
