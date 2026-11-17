from pathlib import Path

from phishlens.analyzer import analyze_bytes, analyze_file, base_domain, domain_of

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def test_phishing_sample_is_flagged():
    report = analyze_file(str(SAMPLES / "phishing.eml"))
    assert report.verdict == "PHISHING"
    assert report.auth["spf"] == "fail"
    assert report.auth["dmarc"] == "fail"
    messages = " ".join(f.message for f in report.findings)
    assert "raw IP" in messages
    assert "Double extension" in messages
    assert "Reply-To" in messages
    assert "Link text shows www.paypal.com" in messages


def test_legit_sample_is_safe():
    report = analyze_file(str(SAMPLES / "legit.eml"))
    assert report.verdict == "PROBABLY SAFE"
    assert report.auth == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
    assert any("github.com/settings/keys" in l.url for l in report.links)


def test_attachment_hash():
    report = analyze_file(str(SAMPLES / "phishing.eml"))
    assert len(report.attachments) == 1
    assert len(report.attachments[0].sha256) == 64


def test_helpers():
    assert domain_of('"Bob" <bob@mail.example.org>') == "mail.example.org"
    assert base_domain("a.b.example.org") == "example.org"


def test_shortener_detected():
    raw = (
        b"From: a@example.com\r\nSubject: hi\r\nContent-Type: text/plain\r\n\r\n"
        b"see https://bit.ly/abc123\r\n"
    )
    report = analyze_bytes(raw)
    assert any("shortener" in f.message for f in report.findings)
