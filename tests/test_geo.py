"""GeoIP lookup, Received IP extraction, dashboard statistics and pages."""

import gzip
import json
import sqlite3

import pytest

from phishlens import cli, geoip, store
from phishlens.analyzer import analyze_bytes
from tests.test_web import RAW, Client, multipart, signed_in

CSV = """0.0.0.0,0.255.255.255,ZZ
8.8.8.0,8.8.8.255,US
80.12.0.0,80.12.255.255,FR
185.220.100.0,185.220.101.255,DE
2a01:cb00::,2a01:cbff:ffff:ffff:ffff:ffff:ffff:ffff,FR
2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US
"""


@pytest.fixture
def geo(tmp_path, monkeypatch):
    path = tmp_path / "geoip.bin"
    monkeypatch.setenv("PHISHLENS_GEOIP", str(path))
    geoip.convert(CSV.splitlines(), path, "2026-11")
    return path


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISHLENS_DB", str(tmp_path / "geo.db"))
    monkeypatch.delenv("PHISHLENS_AI_URL", raising=False)
    conn = store.connect()
    yield conn
    conn.close()


# --- GeoIP -----------------------------------------------------------------

def test_lookup_ipv4_ipv6_and_private(geo):
    db = geoip.load(geo)
    assert db.version == "2026-11"
    assert db.country("8.8.8.8") == "US"
    assert db.country("185.220.101.4") == "DE"
    assert db.country("80.12.0.0") == "FR" and db.country("80.12.255.255") == "FR"
    assert db.country("80.13.0.0") is None  # between ranges
    assert db.country("2a01:cb00::1") == "FR"
    assert db.country("2001:4860:4860::8888") == "US"
    assert db.country("192.168.1.1") is None and db.country("not an ip") is None
    assert geoip.country("8.8.8.8") == "US"


def test_missing_database_is_harmless(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISHLENS_GEOIP", str(tmp_path / "missing.bin"))
    assert geoip.load() is None and geoip.country("8.8.8.8") is None


def test_update_from_gzip_file_and_reload(geo, tmp_path):
    source = tmp_path / "dbip.csv.gz"
    with gzip.open(source, "wt") as fh:
        fh.write("9.9.9.0,9.9.9.255,CH\n")
    assert geoip.update(source=str(source))[0] == 1
    assert geoip.country("9.9.9.9") == "CH"  # cache reloaded after the file changed


def test_bad_file_is_rejected(tmp_path):
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"nope")
    assert geoip.load(bad) is None


# --- Received headers ------------------------------------------------------

def test_origin_ip_from_received_headers():
    raw = (b"Received: from relay.isp.net (relay.isp.net [80.12.0.1]) by mx.me.com (8.8.8.8)\r\n"
           b"Received: from [192.168.1.4] (laptop [IPv6:2a01:cb00::1]) by relay.isp.net\r\n"
           b"Received: by localhost\r\n"
           b"Subject: x\r\n\r\nhi")
    report = analyze_bytes(raw)
    assert report.received_ips == ["80.12.0.1", "2a01:cb00::1"]  # "by" part and private IP ignored
    assert report.origin_ip == "2a01:cb00::1"
    assert report.to_dict()["origin_ip"] == "2a01:cb00::1"


def test_no_received_header():
    assert analyze_bytes(b"Subject: x\r\n\r\nhi").origin_ip == ""


# --- storage ---------------------------------------------------------------

def test_old_database_is_migrated(tmp_path):
    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.execute("CREATE TABLE results (mailbox TEXT, uidvalidity TEXT, uid INTEGER, "
                "scanned TEXT DEFAULT CURRENT_TIMESTAMP, subject TEXT, sender TEXT, score INTEGER, "
                "verdict TEXT, findings TEXT, ai TEXT, PRIMARY KEY (mailbox, uidvalidity, uid))")
    old.execute("INSERT INTO results (mailbox, uidvalidity, uid, subject) VALUES ('m', '1', 1, 'old')")
    old.commit()
    old.close()
    db = store.connect(str(path))
    columns = {r["name"] for r in db.execute("PRAGMA table_info(results)")}
    assert {"origin_ip", "country"} <= columns
    assert db.execute("SELECT subject FROM results").fetchone()[0] == "old"


def test_live_stats(db):
    report = analyze_bytes(RAW)
    store.save(db, "me", "1", 1, report, "", "DE")
    store.save(db, "me", "1", 1, report, "", "DE")  # same message again: not counted twice
    store.record_upload(db, analyze_bytes(b"Subject: hi\r\n\r\nhello"), None)
    stats = store.live_stats(db)
    assert stats["all"]["total"] == 2 and stats["all"]["PHISHING"] == 1
    assert stats["today"]["total"] == 2
    assert len(stats["hours"]) == 24 and sum(sum(h[v] for v in ("PHISHING", "SUSPICIOUS", "PROBABLY SAFE"))
                                             for h in stats["hours"]) == 2
    assert stats["countries"] == [{"country": "DE", "total": 1, "phishing": 1}]
    assert stats["unknown_country"] == 1
    assert stats["latest"][0]["country"] == "DE" and stats["last_event"] == 2


# --- web -------------------------------------------------------------------

def test_upload_records_anonymous_event(db, geo):
    admin = signed_in(db, "admin", "admin")
    csrf = admin.get("/").csrf()
    body, ctype = multipart({"csrf": (None, csrf.encode()), "source": (None, RAW)})
    resp = admin.request("POST", "/", body, ctype, headers={"X-Partial": "1"})
    assert 'data-cc="DE"' in resp.text and "185.220.101.4" in resp.text
    rows = [dict(r) for r in db.execute("SELECT * FROM events")]
    assert len(rows) == 1 and rows[0]["source"] == "upload" and rows[0]["country"] == "DE"
    assert set(rows[0]) == {"id", "ts", "source", "score", "verdict", "country"}  # no content, no IP
    assert db.execute("SELECT COUNT(*) FROM results").fetchone()[0] == 0


def test_dashboard_pages(db, geo):
    store.save(db, "me", "1", 1, analyze_bytes(RAW), "", "DE")
    viewer = signed_in(db, "viewer", "viewer")
    page = viewer.get("/dashboard")
    assert page.code == 200 and 'id="dash-live"' in page.text and "DB-IP" in page.text
    partial = viewer.get("/dashboard?partial=1")
    assert "<html" not in partial.text and 'id="dash-data"' in partial.text
    stats = json.loads(viewer.get("/api/stats").text)
    assert stats["countries"][0]["country"] == "DE" and stats["geoip"] == "2026-11"
    assert Client().get("/api/stats").code == 401
    assert Client().get("/static/world.svg").code == 200


def test_dashboard_without_geoip(db, tmp_path, monkeypatch):
    monkeypatch.setenv("PHISHLENS_GEOIP", str(tmp_path / "none.bin"))
    page = signed_in(db, "admin", "admin").get("/dashboard")
    assert page.code == 200 and "phishlens geoip update" in page.text


def test_dashboard_escapes_subjects(db, geo):
    store.save(db, "me", "1", 1, analyze_bytes(b"Subject: <img src=x onerror=alert(1)>\r\n\r\nhi"), "", None)
    text = signed_in(db, "admin", "admin").get("/dashboard?partial=1").text
    assert "<img src=x" not in text and "&lt;img" in text


def test_admin_can_update_geoip_from_settings(db, monkeypatch):
    calls = []
    monkeypatch.setattr(geoip, "update", lambda: calls.append(1) or (10, "2026-11"))
    admin = signed_in(db, "admin", "admin")
    csrf = admin.get("/admin/settings").csrf()
    resp = admin.post("/admin/settings", {"csrf": csrf, "action": "geoip_update"})
    assert resp.header("Location").endswith("ok=ok_geoip_updated") and calls

    def fail():
        raise RuntimeError("offline")
    monkeypatch.setattr(geoip, "update", fail)
    resp = admin.post("/admin/settings", {"csrf": csrf, "action": "geoip_update"})
    assert resp.header("Location").endswith("err=err_geoip")
    assert signed_in(db, "bob", "viewer").post("/admin/settings", {"csrf": "x", "action": "geoip_update"}).code == 403


def test_cli_geoip(geo, capsys):
    assert cli.main(["geoip", "lookup", "185.220.101.4"]) == 0
    assert capsys.readouterr().out.strip() == "DE"
