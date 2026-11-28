import io
import json
import runpy
from pathlib import Path

from phishlens import ai, imap, store
from phishlens.analyzer import analyze_bytes

ROOT = Path(__file__).resolve().parent.parent
RAW = (ROOT / "samples" / "phishing.eml").read_bytes()
RAW = RAW.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")  # same bytes on every OS


class FakeIMAP:
    def select(self, folder, readonly=False):
        assert readonly
        return "OK", [b"1"]

    def response(self, code):
        return code, [b"42"]

    def uid(self, command, *args):
        if command == "search":
            return "OK", [b"7"]
        if "SIZE" in args[1]:
            return "OK", [b"1 (UID 7 RFC822.SIZE %d)" % len(RAW)]
        assert "PEEK" in args[1]
        return "OK", [(b"1 (BODY[] {1}", RAW), b")"]


def test_scan_once(tmp_path, monkeypatch):
    monkeypatch.delenv("PHISHLENS_AI_URL", raising=False)
    db = store.connect(str(tmp_path / "t.db"))
    assert imap.scan(FakeIMAP(), db, "me", "INBOX", 50) == 1
    assert imap.scan(FakeIMAP(), db, "me", "INBOX", 50) == 0
    assert store.latest(db)[0]["verdict"] == "PHISHING"


def test_ai_request(monkeypatch):
    def fake(request, timeout):
        assert request.full_url == "http://ai/v1/chat/completions"
        return io.BytesIO(json.dumps({"choices": [{"message": {"content": " ok "}}]}).encode())

    monkeypatch.setenv("PHISHLENS_AI_URL", "http://ai/v1")
    monkeypatch.setattr(ai.urllib.request, "urlopen", fake)
    from email import message_from_bytes, policy
    msg = message_from_bytes(RAW, policy=policy.default)
    assert ai.ask_ai(msg, analyze_bytes(RAW)) == "ok"


def test_web_dashboard_escapes(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISHLENS_DB", str(tmp_path / "t.db"))
    from phishlens.web import auth
    report = analyze_bytes(b"Subject: <script>x</script>\r\n\r\nhi")
    db = store.connect()
    store.save(db, "me", "1", 1, report, "<img>")
    token = auth.create_session(db, auth.create_user(db, "admin", "long-password-1", "admin"))
    app = runpy.run_path(str(ROOT / "web" / "app.wsgi"))["application"]
    environ = {"REQUEST_METHOD": "GET", "PATH_INFO": "/mailbox",
               "HTTP_COOKIE": f"phishlens_session={token}"}
    page = b"".join(app(environ, lambda s, h: None)).decode()
    assert "&lt;script&gt;" in page and "<script>x" not in page and "<img>" not in page


def test_web_upload_like_a_browser():
    app = runpy.run_path(str(ROOT / "web" / "app.wsgi"))
    body = (b'--zz9form\r\nContent-Disposition: form-data; name="file"; filename="a.eml"\r\n'
            b"Content-Type: message/rfc822\r\n\r\n" + RAW + b"\r\n"
            b'--zz9form\r\nContent-Disposition: form-data; name="source"\r\n\r\n\r\n--zz9form--\r\n')
    assert app["read_form"]("multipart/form-data; boundary=zz9form", body) == RAW
