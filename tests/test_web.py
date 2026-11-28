"""Web interface: first-run setup, accounts, CSRF, analysis, static files."""

import io
import json
import re
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlencode

import pytest

from phishlens import store
from phishlens.web import auth
from phishlens.web.app import MAX_SIZE, application

ROOT = Path(__file__).resolve().parent.parent
RAW = (ROOT / "samples" / "phishing.eml").read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
PASSWORD = "correct-horse-1"


class Response:
    def __init__(self, status, headers, body):
        self.status, self.headers, self.body = status, headers, body
        self.code = int(status.split()[0])
        self.text = body.decode("utf-8", "replace")

    def header(self, name):
        return next((v for k, v in self.headers if k.lower() == name.lower()), None)

    def csrf(self):
        return re.search(r'name="csrf" value="([^"]+)"', self.text).group(1)


class Client:
    def __init__(self):
        self.cookies = {}

    def request(self, method, path, body=b"", ctype="", headers=None):
        path, _, query = path.partition("?")
        environ = {
            "REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": query,
            "wsgi.input": io.BytesIO(body), "CONTENT_LENGTH": str(len(body)), "CONTENT_TYPE": ctype,
            "HTTP_HOST": "localhost", "REMOTE_ADDR": "10.0.0.1", "wsgi.errors": io.StringIO(),
            "HTTP_COOKIE": "; ".join(f"{k}={v}" for k, v in self.cookies.items()),
        }
        for name, value in (headers or {}).items():
            environ["HTTP_" + name.upper().replace("-", "_")] = value
        result = {}

        def start_response(status, response_headers):
            result["status"], result["headers"] = status, response_headers

        data = b"".join(application(environ, start_response))
        for name, value in result["headers"]:
            if name == "Set-Cookie":
                for key, morsel in SimpleCookie(value).items():
                    if morsel.value:
                        self.cookies[key] = morsel.value
                    else:
                        self.cookies.pop(key, None)
        return Response(result["status"], result["headers"], data)

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, data, **kw):
        return self.request("POST", path, urlencode(data).encode(),
                            "application/x-www-form-urlencoded", **kw)


def multipart(fields, boundary="testboundary"):
    out = b""
    for name, (filename, data) in fields.items():
        disposition = f'form-data; name="{name}"' + (f'; filename="{filename}"' if filename else "")
        out += f"--{boundary}\r\nContent-Disposition: {disposition}\r\n\r\n".encode() + data + b"\r\n"
    return out + f"--{boundary}--\r\n".encode(), f"multipart/form-data; boundary={boundary}"


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISHLENS_DB", str(tmp_path / "web.db"))
    monkeypatch.delenv("PHISHLENS_AI_URL", raising=False)
    monkeypatch.delenv("PHISHLENS_TRUST_PROXY", raising=False)
    conn = store.connect()
    yield conn
    conn.close()


def signed_in(db, username, role):
    client = Client()
    user_id = auth.create_user(db, username, PASSWORD, role)
    client.cookies["phishlens_session"] = auth.create_session(db, user_id)
    return client


@pytest.fixture
def admin(db):
    return signed_in(db, "admin", "admin")


# --- first run -------------------------------------------------------------

def test_everything_redirects_to_setup_without_users(db):
    client = Client()
    for path in ("/", "/mailbox", "/login", "/admin/users"):
        resp = client.get(path)
        assert resp.code == 303 and resp.header("Location") == "/setup"
    assert client.get("/setup").code == 200


def test_setup_requires_the_code_then_locks(db):
    client = Client()
    form = {"code": "WRONG", "username": "boss", "password": PASSWORD, "confirm": PASSWORD}
    assert client.post("/setup", form).code == 400
    assert auth.user_count(db) == 0

    form["code"] = auth.setup_code(db)
    resp = client.post("/setup", form)
    assert resp.code == 303 and "phishlens_session" in client.cookies
    assert auth.find_user(db, "boss")["role"] == "admin"
    assert auth.setup_code(db) is None
    # A second setup is impossible
    assert Client().post("/setup", form).header("Location") == "/"
    assert auth.user_count(db) == 1


def test_setup_password_mismatch(db):
    form = {"code": auth.setup_code(db), "username": "boss", "password": PASSWORD,
            "confirm": "other-password"}
    assert Client().post("/setup", form).code == 400


# --- login -----------------------------------------------------------------

def test_login_logout_and_cookie_flags(db):
    auth.create_user(db, "alice", PASSWORD, "viewer")
    client = Client()
    assert client.get("/mailbox").header("Location") == "/login?next=/mailbox"
    resp = client.post("/login", {"username": "alice", "password": PASSWORD, "next": "/mailbox"})
    assert resp.code == 303 and resp.header("Location") == "/mailbox"
    cookie = resp.header("Set-Cookie")
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie and "Secure" not in cookie
    page = client.get("/")
    assert page.code == 200
    client.post("/logout", {"csrf": page.csrf()})
    assert client.get("/").header("Location") == "/login"


def test_secure_cookie_behind_https_proxy(db, monkeypatch):
    monkeypatch.setenv("PHISHLENS_TRUST_PROXY", "1")
    auth.create_user(db, "alice", PASSWORD, "viewer")
    resp = Client().post("/login", {"username": "alice", "password": PASSWORD},
                         headers={"X-Forwarded-Proto": "https"})
    assert "Secure" in resp.header("Set-Cookie")


def test_login_rejects_open_redirect(db):
    auth.create_user(db, "alice", PASSWORD, "viewer")
    resp = Client().post("/login", {"username": "alice", "password": PASSWORD, "next": "//evil.example"})
    assert resp.header("Location") == "/"


def test_login_lockout_after_failures(db):
    auth.create_user(db, "alice", PASSWORD, "viewer")
    client = Client()
    for _ in range(auth.MAX_FAILURES):
        assert client.post("/login", {"username": "alice", "password": "nope"}).code == 401
    assert client.post("/login", {"username": "alice", "password": PASSWORD}).code == 429


def test_password_hashing():
    first, second = auth.hash_password(PASSWORD), auth.hash_password(PASSWORD)
    assert first != second and first.startswith("scrypt$")
    assert auth.verify_password(PASSWORD, first)
    assert not auth.verify_password("wrong", first)
    assert not auth.verify_password(PASSWORD, "garbage")


# --- CSRF and roles --------------------------------------------------------

def test_post_without_csrf_is_refused(db, admin):
    resp = admin.post("/admin/users", {"action": "add", "username": "x", "password": PASSWORD})
    assert resp.code == 403 and auth.find_user(db, "x") is None


def test_cross_site_post_is_refused(db, admin):
    csrf = admin.get("/admin/users").csrf()
    resp = admin.post("/admin/users", {"csrf": csrf, "action": "add", "username": "x",
                                       "password": PASSWORD},
                      headers={"Origin": "https://evil.example"})
    assert resp.code == 403 and auth.find_user(db, "x") is None


def test_browser_form_posts_with_origin_header(db):
    """Real browsers send Origin on form posts: same host, or "null" with strict privacy settings."""
    form = {"code": auth.setup_code(db), "username": "boss", "password": PASSWORD, "confirm": PASSWORD}
    resp = Client().post("/setup", form, headers={"Origin": "http://localhost"})
    assert resp.code == 303 and auth.find_user(db, "boss")
    for origin in ("http://localhost", "null"):
        resp = Client().post("/login", {"username": "boss", "password": PASSWORD}, headers={"Origin": origin})
        assert resp.code == 303 and resp.header("Location") == "/"
    resp = Client().post("/login", {"username": "boss", "password": PASSWORD},
                         headers={"Origin": "null", "Referer": "https://evil.example/page"})
    assert resp.code == 403


def test_referrer_policy_keeps_origin(db):
    assert Client().get("/healthz").header("Referrer-Policy") == "same-origin"


def test_admin_manages_users(db, admin):
    csrf = admin.get("/admin/users").csrf()
    resp = admin.post("/admin/users", {"csrf": csrf, "action": "add", "username": "bob",
                                       "password": PASSWORD, "role": "viewer"})
    assert resp.header("Location") == "/admin/users?ok=ok_user_created"
    bob = auth.find_user(db, "bob")
    admin.post("/admin/users", {"csrf": csrf, "action": "role", "id": bob["id"], "role": "admin"})
    assert auth.find_user(db, "bob")["role"] == "admin"
    admin.post("/admin/users", {"csrf": csrf, "action": "delete", "id": bob["id"]})
    assert auth.find_user(db, "bob") is None


def test_last_admin_cannot_be_removed(db, admin):
    csrf = admin.get("/admin/users").csrf()
    me = auth.find_user(db, "admin")
    resp = admin.post("/admin/users", {"csrf": csrf, "action": "delete", "id": me["id"]})
    assert resp.header("Location") == "/admin/users?err=err_last_admin"
    resp = admin.post("/admin/users", {"csrf": csrf, "action": "role", "id": me["id"], "role": "viewer"})
    assert resp.header("Location") == "/admin/users?err=err_last_admin"
    assert auth.find_user(db, "admin")["role"] == "admin"


def test_viewer_cannot_open_admin_pages(db, admin):
    viewer = signed_in(db, "viewer", "viewer")
    assert viewer.get("/admin/users").code == 403
    assert viewer.get("/mailbox").code == 200
    assert "/admin/users" not in viewer.get("/").text


def test_change_own_password(db, admin):
    csrf = admin.get("/account").csrf()
    resp = admin.post("/account", {"csrf": csrf, "current": PASSWORD, "password": "new-password-22",
                                   "confirm": "new-password-22"})
    assert resp.header("Location") == "/account?ok=ok_password_changed"
    assert auth.verify_password("new-password-22", auth.find_user(db, "admin")["pw_hash"])
    assert admin.get("/account").code == 200  # current session was renewed


def test_flash_only_shows_known_messages(db, admin):
    assert "alert(1)" not in admin.get("/admin/users?err=<script>alert(1)</script>").text


# --- analysis --------------------------------------------------------------

def test_analyze_upload_like_a_browser(db, admin):
    csrf = admin.get("/").csrf()
    body, ctype = multipart({"csrf": (None, csrf.encode()), "file": ("a.eml", RAW), "source": (None, b"")})
    resp = admin.request("POST", "/", body, ctype)
    assert resp.code == 200
    assert "badge-bad" in resp.text and "185.220.101.4" in resp.text
    assert '<a href="http' not in resp.text  # links are never clickable


def test_analyze_partial_fragment_for_javascript(db, admin):
    csrf = admin.get("/").csrf()
    body, ctype = multipart({"csrf": (None, csrf.encode()), "source": (None, RAW)})
    resp = admin.request("POST", "/", body, ctype, headers={"X-Partial": "1"})
    assert resp.code == 200 and "<html" not in resp.text and "gauge" in resp.text


def test_analyze_needs_csrf_and_content(db, admin):
    body, ctype = multipart({"file": ("a.eml", RAW)})
    assert admin.request("POST", "/", body, ctype).code == 403
    csrf = admin.get("/").csrf()
    body, ctype = multipart({"csrf": (None, csrf.encode()), "source": (None, b"  ")})
    assert admin.request("POST", "/", body, ctype).code == 400


def test_too_big_is_refused(db, admin):
    big = b"x" * (MAX_SIZE + 1)
    assert admin.request("POST", "/", big, "multipart/form-data; boundary=x").code == 413


def test_api_analyze_json(db, admin):
    csrf = admin.get("/").csrf()
    resp = admin.request("POST", "/api/analyze", RAW, "message/rfc822", headers={"X-CSRF-Token": csrf})
    data = json.loads(resp.text)
    assert resp.code == 200 and data["report"]["verdict"] == "PHISHING" and data["ai"] is None
    assert admin.request("POST", "/api/analyze", RAW, "message/rfc822").code == 403
    assert Client().request("POST", "/api/analyze", RAW, "message/rfc822").code == 401


def test_ai_failure_is_reported_not_fatal(db, admin, monkeypatch):
    from phishlens import ai

    def boom(*args, **kwargs):
        raise OSError("down")

    monkeypatch.setenv("PHISHLENS_AI_URL", "http://127.0.0.1:9/v1")
    monkeypatch.setattr(ai.urllib.request, "urlopen", boom)
    csrf = admin.get("/").csrf()
    body, ctype = multipart({"csrf": (None, csrf.encode()), "source": (None, RAW)})
    resp = admin.request("POST", "/", body, ctype, headers={"X-Partial": "1"})
    assert resp.code == 200 and "ai-card" in resp.text and "badge-bad" in resp.text


# --- misc ------------------------------------------------------------------

def test_languages(db, admin):
    assert "Analyser un e-mail" in admin.get("/", headers={"Accept-Language": "fr-FR,fr;q=0.9"}).text
    assert "Analyze an email" in admin.get("/", headers={"Accept-Language": "de,en;q=0.5"}).text
    assert admin.get("/lang?l=fr&next=/mailbox").header("Location") == "/mailbox"
    # The account preference wins over the browser language
    assert "Boîte mail" in admin.get("/mailbox", headers={"Accept-Language": "en"}).text


def test_static_whitelist_and_health(db):
    client = Client()
    css = client.get("/static/app.css")
    assert css.code == 200 and css.header("Content-Type").startswith("text/css")
    for path in ("/static/../store.py", "/static/missing.js", "/static/"):
        assert client.get(path).code == 404
    assert client.get("/healthz").text == "ok"


def test_security_headers_everywhere(db, admin):
    for resp in (admin.get("/"), admin.get("/nope"), Client().get("/healthz")):
        csp = resp.header("Content-Security-Policy")
        assert "script-src 'self'" in csp and "unsafe-inline" not in csp
        assert resp.header("X-Content-Type-Options") == "nosniff"
    assert admin.get("/nope").code == 404
