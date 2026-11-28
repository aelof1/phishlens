"""phishlens web application (WSGI, standard library only).

Uploaded emails are analysed in memory: nothing is written to disk and no link is opened.
Runs under Apache mod_wsgi (web/app.wsgi), `phishlens web`, or Docker.
"""

from __future__ import annotations

import json
import os
import re
import sys
import traceback
from email import message_from_bytes, policy
from email.message import Message
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .. import ai, config, store
from ..analyzer import analyze_bytes
from . import auth, views
from .i18n import LANGS, Translator, from_accept_language

config.load_default_env()

MAX_SIZE = 2 * 1024 * 1024  # 2 MB
STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_FILES = {"app.css": "text/css; charset=utf-8", "app.js": "text/javascript; charset=utf-8",
                "theme.js": "text/javascript; charset=utf-8", "logo.svg": "image/svg+xml"}
SESSION_COOKIE = "phishlens_session"

SECURITY_HEADERS = [
    ("Content-Security-Policy",
     "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
     "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Frame-Options", "DENY"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
]


# --- request / response ----------------------------------------------------

class Request:
    def __init__(self, environ):
        self.environ = environ
        self.method = environ.get("REQUEST_METHOD", "GET").upper()
        self.path = environ.get("PATH_INFO") or "/"
        self.query = {k: v[0] for k, v in parse_qs(environ.get("QUERY_STRING", "")).items()}
        cookies = SimpleCookie()
        try:
            cookies.load(environ.get("HTTP_COOKIE", ""))
        except CookieError:
            pass
        self.cookies = {k: m.value for k, m in cookies.items()}
        self.errors = environ.get("wsgi.errors", sys.stderr)
        self._body = None

    def header(self, name: str) -> str:
        return self.environ.get("HTTP_" + name.upper().replace("-", "_"), "")

    @property
    def length(self) -> int:
        try:
            return int(self.environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            return -1

    def body(self) -> bytes:
        if self._body is None:
            length = self.length
            stream = self.environ.get("wsgi.input")
            self._body = stream.read(length) if stream and 0 < length <= MAX_SIZE else b""
        return self._body

    def form(self) -> dict[str, str]:
        ctype = self.environ.get("CONTENT_TYPE", "")
        if ctype.startswith("multipart/form-data"):
            return {k.decode("latin-1"): v.decode("utf-8", "replace")
                    for k, v in parse_multipart(ctype, self.body()).items()}
        return {k: v[0] for k, v in parse_qs(self.body().decode("utf-8", "replace")).items()}

    @property
    def trust_proxy(self) -> bool:
        return os.environ.get("PHISHLENS_TRUST_PROXY") == "1"

    @property
    def https(self) -> bool:
        if self.trust_proxy and self.header("X-Forwarded-Proto").lower() == "https":
            return True
        return self.environ.get("wsgi.url_scheme") == "https"

    @property
    def ip(self) -> str:
        if self.trust_proxy and self.header("X-Forwarded-For"):
            return self.header("X-Forwarded-For").split(",")[0].strip()
        return self.environ.get("REMOTE_ADDR", "")

    def same_origin(self) -> bool:
        """Reject cross-site POSTs (CSRF defence in depth, on top of tokens)."""
        origin = self.header("Origin") or self.header("Referer")
        if not origin:
            return True
        host = self.header("X-Forwarded-Host") if self.trust_proxy and self.header("X-Forwarded-Host") \
            else self.header("Host")
        return urlparse(origin).netloc.lower() == host.lower()


class Response:
    def __init__(self, body: bytes | str = b"", status: str = "200 OK",
                 ctype: str = "text/html; charset=utf-8"):
        self.body = body.encode() if isinstance(body, str) else body
        self.status = status
        self.headers = [("Content-Type", ctype)]

    def cookie(self, name, value, req, max_age, http_only=True, same_site="Strict"):
        parts = [f"{name}={value}", "Path=/", f"Max-Age={max_age}", f"SameSite={same_site}"]
        if http_only:
            parts.append("HttpOnly")
        if req.https:
            parts.append("Secure")
        self.headers.append(("Set-Cookie", "; ".join(parts)))
        return self


def redirect(location: str, status: str = "303 See Other") -> Response:
    resp = Response(b"", status)
    resp.headers.append(("Location", location))
    return resp


def json_response(data, status: str = "200 OK") -> Response:
    return Response(json.dumps(data, ensure_ascii=False), status, "application/json; charset=utf-8")


def safe_next(value: str | None) -> str:
    """Only local paths, to avoid open redirects."""
    if value and value.startswith("/") and not value.startswith("//") and "\\" not in value:
        return value
    return "/"


# --- multipart -------------------------------------------------------------

def parse_multipart(content_type: str, body: bytes) -> dict[bytes, bytes]:
    """Split a multipart body by hand: browsers label .eml files message/rfc822,
    and the email parser would treat such a part as a nested message instead of raw bytes."""
    header = Message()
    header["Content-Type"] = content_type
    boundary = header.get_boundary()
    if not boundary:
        return {}
    fields = {}
    delimiter = b"\r\n--" + boundary.encode("latin-1")
    for chunk in (b"\r\n" + body).split(delimiter)[1:]:
        head, separator, data = chunk.partition(b"\r\n\r\n")
        name = re.search(rb'\bname="([^"]*)"', head)
        if separator and name:
            fields[name.group(1)] = data
    return fields


def read_form(content_type: str, body: bytes) -> bytes:
    """Return the uploaded file, or the pasted text, from a multipart body."""
    fields = parse_multipart(content_type, body)
    return fields.get(b"file") or fields.get(b"source", b"").strip()


# --- context ---------------------------------------------------------------

class Context:
    def __init__(self, req, db, user, csrf, t):
        self.req, self.db, self.user, self.csrf, self.t = req, db, user, csrf, t
        self.path = req.path
        self.ok = req.query.get("ok")
        self.err = req.query.get("err")
        self.ai = ai.config(db)
        self.ai_model = self.ai["model"] if self.ai["url"] else None


def pick_lang(req, user=None) -> str:
    if user is not None and user["lang"] in LANGS:
        return user["lang"]
    if req.cookies.get("lang") in LANGS:
        return req.cookies["lang"]
    return from_accept_language(req.header("Accept-Language")) or "en"


# --- analysis --------------------------------------------------------------

def run_analysis(raw: bytes, lang: str, ai_cfg: dict):
    report = analyze_bytes(raw)
    ai_text, ai_failed = None, False
    if ai_cfg["url"]:
        try:
            msg = message_from_bytes(raw, policy=policy.default)
            ai_text = ai.ask_ai(msg, report, lang=lang, cfg=ai_cfg)
        except Exception as exc:
            print(f"phishlens: AI unavailable ({type(exc).__name__})", file=sys.stderr)
            ai_failed = True
    return report, ai_text, ai_failed


def analyze(ctx) -> Response:
    req, t = ctx.req, ctx.t
    partial = req.header("X-Partial") == "1"
    status, content = "200 OK", ""
    if not 0 < req.length <= MAX_SIZE:
        status = "413 Content Too Large" if req.length > MAX_SIZE else "400 Bad Request"
        content = views.error_box(t("file_too_big") if req.length > MAX_SIZE else t("empty_input"))
    else:
        ctype = req.environ.get("CONTENT_TYPE", "")
        fields = parse_multipart(ctype, req.body())
        if not auth.check_csrf(ctx.csrf, fields.get(b"csrf", b"").decode("latin-1")):
            status, content = "403 Forbidden", views.error_box(t("err_csrf"))
        else:
            raw = fields.get(b"file") or fields.get(b"source", b"").strip()
            if not raw:
                status, content = "400 Bad Request", views.error_box(t("empty_input"))
            else:
                try:
                    content = views.report_html(t, *run_analysis(raw, t.lang, ctx.ai))
                except Exception:  # hostile input must never leak a traceback
                    print("phishlens: analysis failed", file=req.errors)
                    status, content = "400 Bad Request", views.error_box(t("parse_failed"))
    if partial:
        resp = Response(content, status)
    else:
        resp = Response(views.analyze_page(ctx, content), status)
    resp.headers.append(("Cache-Control", "no-store"))
    return resp


def api_analyze(ctx) -> Response:
    req = ctx.req
    if not auth.check_csrf(ctx.csrf, req.header("X-CSRF-Token")):
        return json_response({"error": "csrf"}, "403 Forbidden")
    if not 0 < req.length <= MAX_SIZE:
        return json_response({"error": "size"}, "413 Content Too Large" if req.length > MAX_SIZE
                             else "400 Bad Request")
    raw = req.body()
    if req.environ.get("CONTENT_TYPE", "").startswith("multipart/form-data"):
        raw = read_form(req.environ["CONTENT_TYPE"], raw)
    if not raw:
        return json_response({"error": "empty"}, "400 Bad Request")
    try:
        report, ai_text, ai_failed = run_analysis(raw, ctx.t.lang, ctx.ai)
    except Exception:
        print("phishlens: analysis failed", file=req.errors)
        return json_response({"error": "parse"}, "400 Bad Request")
    return json_response({"report": report.to_dict(), "ai": ai_text, "ai_error": ai_failed})


# --- pages -----------------------------------------------------------------

def mailbox(ctx) -> Response:
    verdict = ctx.req.query.get("verdict")
    if verdict not in {"PHISHING", "SUSPICIOUS", "PROBABLY SAFE"}:
        verdict = None
    body = views.mailbox_page(ctx, store.stats(ctx.db), store.latest(ctx.db, 200, verdict), verdict)
    return Response(body)


def admin_users(ctx) -> Response:
    if ctx.user["role"] != "admin":
        return Response(views.error_page(ctx.t, "err_forbidden"), "403 Forbidden")
    if ctx.req.method == "GET":
        return Response(views.users_page(ctx, auth.list_users(ctx.db)))
    form = ctx.req.form()
    action = form.get("action")
    try:
        if action == "add":
            auth.create_user(ctx.db, form.get("username", ""), form.get("password", ""),
                             form.get("role", "viewer"))
            return redirect("/admin/users?ok=ok_user_created")
        user_id = int(form.get("id", "0"))
        if action == "role":
            auth.set_role(ctx.db, user_id, form.get("role", ""))
            return redirect("/admin/users?ok=ok_role_changed")
        if action == "password":
            auth.set_password(ctx.db, user_id, form.get("password", ""))
            return redirect("/admin/users?ok=ok_password_reset")
        if action == "delete":
            auth.delete_user(ctx.db, user_id)
            if user_id == ctx.user["id"]:
                return redirect("/login")
            return redirect("/admin/users?ok=ok_user_deleted")
    except auth.AuthError as exc:
        return redirect(f"/admin/users?err=err_{exc}")
    except ValueError:
        pass
    return redirect("/admin/users?err=err_no_user")


def account(ctx) -> Response:
    if ctx.req.method == "GET":
        return Response(views.account_page(ctx))
    form = ctx.req.form()
    if not auth.verify_password(form.get("current", ""), ctx.user["pw_hash"]):
        return redirect("/account?err=err_bad_login")
    if form.get("password") != form.get("confirm"):
        return redirect("/account?err=err_mismatch")
    try:
        auth.set_password(ctx.db, ctx.user["id"], form.get("password", ""))
    except auth.AuthError as exc:
        return redirect(f"/account?err=err_{exc}")
    token = auth.create_session(ctx.db, ctx.user["id"])  # others were signed out
    return redirect("/account?ok=ok_password_changed").cookie(
        SESSION_COOKIE, token, ctx.req, auth.SESSION_DAYS * 86400)


def setup(req, db, t) -> Response:
    if auth.user_count(db):
        return redirect("/login")
    code = auth.setup_code(db)
    if req.method == "GET":
        print(f"phishlens: no account yet. Setup code: {code}", file=req.errors)
        return Response(views.setup_page(t, None))
    form = req.form()
    username = form.get("username", "")
    if auth.too_many_failures(db, req.ip):
        return Response(views.setup_page(t, "err_locked", username), "429 Too Many Requests")
    if form.get("password") != form.get("confirm"):
        return Response(views.setup_page(t, "err_mismatch", username), "400 Bad Request")
    try:
        user_id = auth.finish_setup(db, form.get("code", ""), username, form.get("password", ""))
    except auth.AuthError as exc:
        if str(exc) == "bad_code":
            auth.record_failure(db, req.ip)
        return Response(views.setup_page(t, f"err_{exc}", username), "400 Bad Request")
    token = auth.create_session(db, user_id)
    return redirect("/").cookie(SESSION_COOKIE, token, req, auth.SESSION_DAYS * 86400)


def login(req, db, t) -> Response:
    next_path = safe_next(req.query.get("next"))
    if req.method == "GET":
        return Response(views.login_page(t, None, next_path))
    form = req.form()
    username = form.get("username", "")
    next_path = safe_next(form.get("next"))
    try:
        user = auth.login(db, username, form.get("password", ""), req.ip)
    except auth.AuthError as exc:
        status = "429 Too Many Requests" if str(exc) == "locked" else "401 Unauthorized"
        return Response(views.login_page(t, f"err_{exc}", next_path, username), status)
    token = auth.create_session(db, user["id"])
    return redirect(next_path).cookie(SESSION_COOKIE, token, req, auth.SESSION_DAYS * 86400)


def static(req) -> Response:
    name = req.path[len("/static/"):]
    if name not in STATIC_FILES:  # whitelist: no path is ever built from the URL
        return Response(b"not found", "404 Not Found", "text/plain")
    resp = Response((STATIC_DIR / name).read_bytes(), ctype=STATIC_FILES[name])
    resp.headers.append(("Cache-Control", "public, max-age=31536000"))
    return resp


def set_lang(req, db, session) -> Response:
    lang = req.query.get("l")
    resp = redirect(safe_next(req.query.get("next")))
    if lang in LANGS:
        if session:
            auth.set_lang(db, session[0]["id"], lang)
        resp.cookie("lang", lang, req, 365 * 86400, http_only=False, same_site="Lax")
    return resp


def admin_settings(ctx) -> Response:
    if ctx.user["role"] != "admin":
        return Response(views.error_page(ctx.t, "err_forbidden"), "403 Forbidden")
    stored = ctx.ai
    if ctx.req.method == "GET":
        return Response(views.settings_page(ctx, stored))
    if stored["source"] == "env":
        return redirect("/admin/settings?err=err_ai_env")
    form = ctx.req.form()
    action = form.get("action", "save")
    if action == "disable":
        for field in ("provider", "url", "model", "key"):
            store.set_setting(ctx.db, "ai_" + field, None)
        return redirect("/admin/settings?ok=ok_ai_disabled")

    provider = form.get("provider", "")
    if provider not in ai.PROVIDERS:
        return redirect("/admin/settings?err=err_ai_provider")
    url = form.get("url", "").strip() or ai.PROVIDERS[provider]["url"]
    model = form.get("model", "").strip() or ai.PROVIDERS[provider]["model"]
    key = form.get("key", "").strip()
    # Reuse the saved key only for the same endpoint: never send it to another host
    if not key and form.get("clear_key") != "1" and stored["url"].rstrip("/") == url.rstrip("/"):
        key = stored["key"]
    cfg = {"source": "db", "provider": provider, "url": url, "model": model, "key": key}
    if not url.startswith(("http://", "https://")) or not model:
        return Response(views.settings_page(ctx, cfg, error_key="err_ai_fields"), "400 Bad Request")

    if action == "test":
        try:
            reply = ai.test_connection(cfg)
            result = (True, reply)
        except ai.AIError as exc:
            result = (False, str(exc))
        return Response(views.settings_page(ctx, cfg, test=result))

    for field in ("provider", "url", "model", "key"):
        store.set_setting(ctx.db, "ai_" + field, cfg[field] or None)
    return redirect("/admin/settings?ok=ok_ai_saved")


ROUTES = {
    ("GET", "/admin/settings"): admin_settings,
    ("POST", "/admin/settings"): admin_settings,
    ("GET", "/"): lambda ctx: Response(views.analyze_page(ctx)),
    ("POST", "/"): analyze,
    ("POST", "/api/analyze"): api_analyze,
    ("GET", "/mailbox"): mailbox,
    ("GET", "/admin/users"): admin_users,
    ("POST", "/admin/users"): admin_users,
    ("GET", "/account"): account,
    ("POST", "/account"): account,
}


def dispatch(req: Request) -> Response:
    if req.path == "/healthz":
        return Response(b"ok", ctype="text/plain")
    if req.path.startswith("/static/"):
        return static(req)
    if req.method == "POST" and not req.same_origin():
        return Response(b"cross-site request refused", "403 Forbidden", "text/plain")

    try:
        db = store.connect()
    except Exception as exc:
        print(f"phishlens: database unavailable ({exc})", file=req.errors)
        return Response(views.error_page(Translator(pick_lang(req)), "err_db"),
                        "503 Service Unavailable")
    try:
        token = req.cookies.get(SESSION_COOKIE)
        session = auth.load_session(db, token)
        user = session[0] if session else None
        t = Translator(pick_lang(req, user))

        if req.path == "/lang":
            return set_lang(req, db, session)
        if not auth.user_count(db):
            if req.path == "/setup":
                return setup(req, db, t)
            if req.path.startswith("/api/"):
                return json_response({"error": "setup required"}, "401 Unauthorized")
            return redirect("/setup")
        if req.path == "/setup":
            return redirect("/")
        if req.path == "/login":
            return redirect("/") if session and req.method == "GET" else login(req, db, t)
        if req.path == "/logout" and req.method == "POST":
            form = req.form() if session else {}
            if session and auth.check_csrf(session[1], form.get("csrf")):
                auth.end_session(db, token)
            return redirect("/login").cookie(SESSION_COOKIE, "", req, 0)

        route = ROUTES.get((req.method, req.path))
        if session is None:
            if req.path.startswith("/api/"):
                return json_response({"error": "login required"}, "401 Unauthorized")
            if route and req.method == "GET":
                nxt = req.path + ("?" + req.environ["QUERY_STRING"] if req.environ.get("QUERY_STRING") else "")
                return redirect("/login" + ("" if nxt == "/" else "?next=" + _quote(nxt)))
            return redirect("/login")
        if route is None:
            return Response(views.error_page(t, "err_not_found"), "404 Not Found")

        ctx = Context(req, db, user, session[1], t)
        # Classic form posts carry the CSRF token in a field; the analyze routes check it themselves
        if req.method == "POST" and req.path not in ("/", "/api/analyze"):
            if not auth.check_csrf(ctx.csrf, req.form().get("csrf")):
                return Response(views.error_page(t, "err_csrf"), "403 Forbidden")
        return route(ctx)
    finally:
        db.close()


def _quote(path: str) -> str:
    from urllib.parse import quote
    return quote(path, safe="/")


def application(environ, start_response):
    req = Request(environ)
    try:
        resp = dispatch(req)
    except Exception:
        traceback.print_exc(file=req.errors)
        resp = Response(views.error_page(Translator(pick_lang(req)), "err_server"),
                        "500 Internal Server Error")
    headers = resp.headers + SECURITY_HEADERS + [("Content-Length", str(len(resp.body)))]
    if not any(name == "Cache-Control" for name, _ in headers):
        headers.append(("Cache-Control", "no-store"))
    start_response(resp.status, headers)
    return [resp.body]
