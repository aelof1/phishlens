"""AI providers (OpenAI-compatible and Anthropic), settings page, scan command."""

import io
import json
import urllib.error

import pytest

from phishlens import ai, cli, store
from phishlens.analyzer import analyze_bytes
from tests.test_web import RAW, multipart, signed_in


def fake_urlopen(answer, calls):
    def fake(request, timeout):
        calls.append({"url": request.full_url, "headers": dict(request.header_items()),
                      "body": json.loads(request.data)})
        return io.BytesIO(json.dumps(answer).encode())
    return fake


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISHLENS_DB", str(tmp_path / "ai.db"))
    for name in ("PHISHLENS_AI_URL", "PHISHLENS_AI_MODEL", "PHISHLENS_AI_KEY", "PHISHLENS_AI_PROVIDER"):
        monkeypatch.delenv(name, raising=False)
    conn = store.connect()
    yield conn
    conn.close()


def save_ai(db, **values):
    for key, value in values.items():
        store.set_setting(db, "ai_" + key, value)


# --- configuration ---------------------------------------------------------

def test_config_off_by_default(db):
    assert ai.config(db)["url"] == "" and not ai.enabled(db)


def test_config_from_database(db):
    save_ai(db, provider="mistral", url="https://api.mistral.ai/v1", model="mistral-small-latest", key="k")
    cfg = ai.config(db)
    assert cfg["source"] == "db" and cfg["provider"] == "mistral" and ai.enabled(db)


def test_environment_wins_over_database(db, monkeypatch):
    save_ai(db, provider="mistral", url="https://api.mistral.ai/v1", model="m", key="k")
    monkeypatch.setenv("PHISHLENS_AI_URL", "https://api.anthropic.com/v1")
    cfg = ai.config(db)
    assert cfg["source"] == "env" and cfg["provider"] == "anthropic" and cfg["model"] == "claude-opus-5-5"


def test_empty_environment_variable_does_not_override(db, monkeypatch):
    monkeypatch.setenv("PHISHLENS_AI_URL", "")  # what an untouched ai.env produces
    save_ai(db, provider="ollama", url="http://127.0.0.1:11434/v1", model="llama3.1")
    assert ai.config(db)["source"] == "db"


def test_cloud_detection():
    assert not ai.is_cloud({"provider": "ollama", "url": "http://127.0.0.1:11434/v1"})
    assert ai.is_cloud({"provider": "openai", "url": "https://api.openai.com/v1"})
    assert not ai.is_cloud({"provider": "custom", "url": "http://192.168.1.20:8080/v1"})
    assert ai.is_cloud({"provider": "custom", "url": "https://llm.example.com/v1"})


# --- wire formats ----------------------------------------------------------

def test_openai_compatible_request(monkeypatch):
    calls = []
    monkeypatch.setattr(ai.urllib.request, "urlopen",
                        fake_urlopen({"choices": [{"message": {"content": " Phishing. "}}]}, calls))
    cfg = {"provider": "openai", "url": "https://api.openai.com/v1/", "model": "gpt-4o-mini", "key": "sk-1"}
    assert ai.chat(cfg, "sys", "hello") == "Phishing."
    call = calls[0]
    assert call["url"] == "https://api.openai.com/v1/chat/completions"
    assert call["headers"]["Authorization"] == "Bearer sk-1"
    assert call["body"]["messages"][0] == {"role": "system", "content": "sys"}


def test_anthropic_messages_request(monkeypatch):
    calls = []
    answer = {"stop_reason": "end_turn",
              "content": [{"type": "thinking", "thinking": ""}, {"type": "text", "text": "Likely phishing."}]}
    monkeypatch.setattr(ai.urllib.request, "urlopen", fake_urlopen(answer, calls))
    cfg = {"provider": "anthropic", "url": "https://api.anthropic.com/v1", "model": "claude-opus-5-5",
           "key": "sk-ant-1"}
    assert ai.chat(cfg, "sys", "hello") == "Likely phishing."
    call = calls[0]
    headers = {k.lower(): v for k, v in call["headers"].items()}
    assert call["url"] == "https://api.anthropic.com/v1/messages"
    assert headers["x-api-key"] == "sk-ant-1" and headers["anthropic-version"] == ai.ANTHROPIC_VERSION
    assert "authorization" not in headers
    assert call["body"]["system"] == "sys" and "temperature" not in call["body"]
    assert call["body"]["fallbacks"] == "default"
    assert headers["anthropic-beta"] == "server-side-fallback-2026-07-01"


def test_anthropic_model_without_fallbacks(monkeypatch):
    calls = []
    monkeypatch.setattr(ai.urllib.request, "urlopen",
                        fake_urlopen({"stop_reason": "end_turn", "content": [{"type": "text", "text": "ok"}]},
                                     calls))
    ai.chat({"provider": "anthropic", "url": "https://api.anthropic.com/v1", "model": "claude-haiku-5-5",
             "key": "k"}, "s", "u")
    assert "fallbacks" not in calls[0]["body"]


def test_anthropic_refusal_and_missing_key(monkeypatch):
    monkeypatch.setattr(ai.urllib.request, "urlopen",
                        fake_urlopen({"stop_reason": "refusal", "content": []}, []))
    cfg = {"provider": "anthropic", "url": "https://api.anthropic.com/v1", "model": "claude-opus-5-5", "key": "k"}
    with pytest.raises(ai.AIError, match="declined"):
        ai.chat(cfg, "s", "u")
    with pytest.raises(ai.AIError, match="key"):
        ai.chat({**cfg, "key": ""}, "s", "u")


def test_http_error_is_readable_and_hides_key(monkeypatch):
    def fail(request, timeout):
        body = io.BytesIO(json.dumps({"error": {"message": "invalid api key"}}).encode())
        raise urllib.error.HTTPError(request.full_url, 401, "Unauthorized", {}, body)
    monkeypatch.setattr(ai.urllib.request, "urlopen", fail)
    with pytest.raises(ai.AIError) as exc:
        ai.chat({"provider": "openai", "url": "https://api.openai.com/v1", "model": "m", "key": "sk-secret"},
                "s", "u")
    assert "401" in str(exc.value) and "invalid api key" in str(exc.value) and "sk-secret" not in str(exc.value)


def test_ask_ai_uses_language(monkeypatch):
    calls = []
    monkeypatch.setattr(ai.urllib.request, "urlopen",
                        fake_urlopen({"choices": [{"message": {"content": "ok"}}]}, calls))
    from email import message_from_bytes, policy
    msg = message_from_bytes(RAW, policy=policy.default)
    cfg = {"provider": "ollama", "url": "http://127.0.0.1:11434/v1", "model": "llama3.1", "key": ""}
    ai.ask_ai(msg, analyze_bytes(RAW), lang="en", cfg=cfg)
    assert "Reply in English" in calls[0]["body"]["messages"][0]["content"]
    assert "Authorization" not in calls[0]["headers"]


# --- settings page ---------------------------------------------------------

def test_settings_page_is_admin_only(db):
    assert signed_in(db, "viewer", "viewer").get("/admin/settings").code == 403
    page = signed_in(db, "admin", "admin").get("/admin/settings")
    assert page.code == 200 and "Anthropic (Claude)" in page.text and "/admin/settings" in page.text


def test_save_keep_and_clear_key(db):
    admin = signed_in(db, "admin", "admin")
    csrf = admin.get("/admin/settings").csrf()
    form = {"csrf": csrf, "action": "save", "provider": "openai", "url": "https://api.openai.com/v1",
            "model": "gpt-4o-mini", "key": "sk-abcd1234"}
    assert admin.post("/admin/settings", form).header("Location") == "/admin/settings?ok=ok_ai_saved"
    assert ai.config(db)["key"] == "sk-abcd1234"

    page = admin.get("/admin/settings")
    assert "sk-abcd1234" not in page.text and "1234" in page.text  # masked

    form["key"] = ""  # empty: keep the saved key
    admin.post("/admin/settings", form)
    assert ai.config(db)["key"] == "sk-abcd1234"

    form["clear_key"] = "1"
    admin.post("/admin/settings", form)
    assert ai.config(db)["key"] == ""


def test_saved_key_is_not_sent_to_another_host(db):
    save_ai(db, provider="openai", url="https://api.openai.com/v1", model="gpt-4o-mini", key="sk-secret")
    admin = signed_in(db, "admin", "admin")
    csrf = admin.get("/admin/settings").csrf()
    admin.post("/admin/settings", {"csrf": csrf, "action": "save", "provider": "custom",
                                   "url": "https://evil.example/v1", "model": "x", "key": ""})
    assert ai.config(db)["key"] == ""


def test_test_connection_shows_result(db, monkeypatch):
    calls = []
    monkeypatch.setattr(ai.urllib.request, "urlopen",
                        fake_urlopen({"choices": [{"message": {"content": "OK"}}]}, calls))
    admin = signed_in(db, "admin", "admin")
    csrf = admin.get("/admin/settings").csrf()
    page = admin.post("/admin/settings", {"csrf": csrf, "action": "test", "provider": "ollama",
                                          "url": "http://127.0.0.1:11434/v1", "model": "llama3.1"})
    assert page.code == 200 and "flash-ok" in page.text and calls
    assert ai.config(db)["url"] == ""  # testing does not save


def test_invalid_settings_and_disable(db):
    admin = signed_in(db, "admin", "admin")
    csrf = admin.get("/admin/settings").csrf()
    bad = admin.post("/admin/settings", {"csrf": csrf, "action": "save", "provider": "custom",
                                         "url": "file:///etc/passwd", "model": "x"})
    assert bad.code == 400 and ai.config(db)["url"] == ""
    assert admin.post("/admin/settings", {"csrf": csrf, "provider": "nope"}).header("Location") \
        .endswith("err=err_ai_provider")
    save_ai(db, provider="ollama", url="http://127.0.0.1:11434/v1", model="llama3.1")
    admin.post("/admin/settings", {"csrf": csrf, "action": "disable"})
    assert not ai.enabled(db)


def test_settings_read_only_with_environment(db, monkeypatch):
    monkeypatch.setenv("PHISHLENS_AI_URL", "http://127.0.0.1:11434/v1")
    admin = signed_in(db, "admin", "admin")
    page = admin.get("/admin/settings")
    assert 'id="ai-form"' not in page.text
    resp = admin.post("/admin/settings", {"csrf": page.csrf(), "action": "disable"})
    assert resp.header("Location").endswith("err=err_ai_env")


def test_analysis_uses_settings_from_database(db, monkeypatch):
    calls = []
    monkeypatch.setattr(ai.urllib.request, "urlopen",
                        fake_urlopen({"choices": [{"message": {"content": "Avis du modèle"}}]}, calls))
    save_ai(db, provider="ollama", url="http://127.0.0.1:11434/v1", model="llama3.1")
    admin = signed_in(db, "admin", "admin")
    csrf = admin.get("/").csrf()
    body, ctype = multipart({"csrf": (None, csrf.encode()), "source": (None, RAW)})
    resp = admin.request("POST", "/", body, ctype, headers={"X-Partial": "1", "Accept-Language": "fr"})
    assert "Avis du modèle" in resp.text and "Reply in French" in calls[0]["body"]["messages"][0]["content"]


# --- scan command ----------------------------------------------------------

def test_scan_without_settings_fails_fast(db, monkeypatch, capsys):
    for name in ("PHISHLENS_IMAP_HOST", "PHISHLENS_IMAP_USER", "PHISHLENS_IMAP_PASSWORD"):
        monkeypatch.delenv(name, raising=False)
    assert cli.main(["scan", "--every", "60"]) == 2
    assert "missing setting" in capsys.readouterr().err
