"""Core analysis logic for phishlens.

Everything here works offline: we only look at what is inside the .eml file.
"""

from __future__ import annotations

import email
import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

RISKY_EXTENSIONS = {
    ".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".bat", ".cmd", ".ps1",
    ".hta", ".iso", ".img", ".lnk", ".jar", ".msi", ".docm", ".xlsm", ".pptm",
    ".one", ".wsf", ".zip", ".rar", ".7z",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "tiny.cc",
}

SUSPICIOUS_TLDS = {
    ".zip", ".mov", ".xyz", ".top", ".click", ".country", ".gq", ".tk",
    ".ml", ".cf", ".ga", ".work", ".support", ".rest", ".cam",
}

URGENCY_WORDS = [
    "urgent", "immediately", "suspended", "verify your account", "password expires",
    "unusual activity", "confirm your identity", "within 24 hours", "final notice",
    "action required", "account locked", "click here",
    # French
    "urgent", "immédiatement", "suspendu", "vérifiez votre compte",
    "activité inhabituelle", "confirmez votre identité", "sous 24 heures",
    "dernier avertissement", "compte bloqué", "cliquez ici",
]

URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
# IP literal in a Received header: [1.2.3.4], [IPv6:2001:db8::1], (1.2.3.4)
RECEIVED_IP_RE = re.compile(r"[\[(](?:IPv6:)?([0-9a-fA-F:.]{7,45})[\])]")


@dataclass
class Finding:
    category: str
    message: str
    points: int

    def to_dict(self) -> dict:
        return {"category": self.category, "message": self.message, "points": self.points}


@dataclass
class Link:
    url: str
    text: str = ""

    @property
    def host(self) -> str:
        return (urlparse(self.url).hostname or "").lower()


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str


@dataclass
class Report:
    subject: str = ""
    sender: str = ""
    reply_to: str = ""
    return_path: str = ""
    auth: dict = field(default_factory=dict)
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    received_ips: list[str] = field(default_factory=list)  # public relay IPs, newest first
    origin_ip: str = ""  # closest public IP to the sender

    @property
    def score(self) -> int:
        return min(100, sum(f.points for f in self.findings))

    @property
    def verdict(self) -> str:
        if self.score >= 60:
            return "PHISHING"
        if self.score >= 30:
            return "SUSPICIOUS"
        return "PROBABLY SAFE"

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "from": self.sender,
            "reply_to": self.reply_to,
            "return_path": self.return_path,
            "authentication": self.auth,
            "links": [{"url": l.url, "text": l.text} for l in self.links],
            "attachments": [a.__dict__ for a in self.attachments],
            "findings": [f.to_dict() for f in self.findings],
            "score": self.score,
            "verdict": self.verdict,
            "origin_ip": self.origin_ip,
            "received_ips": self.received_ips,
        }


class _LinkExtractor(HTMLParser):
    """Collects <a href> links together with their visible text."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[Link] = []
        self._current: Link | None = None

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href") or ""
            if href.lower().startswith(("http://", "https://")):
                self._current = Link(url=href.strip())

    def handle_data(self, data):
        if self._current is not None:
            self._current.text += data

    def handle_endtag(self, tag):
        if tag == "a" and self._current is not None:
            self._current.text = self._current.text.strip()
            self.links.append(self._current)
            self._current = None


def domain_of(address: str) -> str:
    _, addr = parseaddr(address or "")
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def base_domain(host: str) -> str:
    """Very rough 'registrable domain' (last two labels). Good enough for comparisons."""
    parts = host.strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def parse_auth_results(msg: EmailMessage) -> dict:
    """Read SPF / DKIM / DMARC verdicts written by the receiving mail server."""
    results = {"spf": "none", "dkim": "none", "dmarc": "none"}
    headers = msg.get_all("Authentication-Results") or []
    headers += msg.get_all("ARC-Authentication-Results") or []
    blob = " ".join(str(h) for h in headers).lower()
    for mech in results:
        m = re.search(rf"\b{mech}=(\w+)", blob)
        if m:
            results[mech] = m.group(1)
    if results["spf"] == "none":
        received_spf = str(msg.get("Received-SPF", "")).lower()
        if received_spf:
            results["spf"] = received_spf.split()[0]
    return results


def _bodies(msg: EmailMessage) -> tuple[str, str]:
    text, html = "", ""
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        try:
            content = part.get_content()
        except Exception:  # broken encodings are common in phishing
            payload = part.get_payload(decode=True) or b""
            content = payload.decode("utf-8", errors="replace")
        if ctype == "text/plain":
            text += content
        elif ctype == "text/html":
            html += content
    return text, html


def extract_links(text: str, html: str) -> list[Link]:
    parser = _LinkExtractor()
    parser.feed(html)
    links = parser.links
    seen = {l.url for l in links}
    for url in URL_RE.findall(text + " " + re.sub(r"<[^>]+>", " ", html)):
        url = url.rstrip(".,;")
        if url not in seen:
            links.append(Link(url=url))
            seen.add(url)
    return links


def extract_attachments(msg: EmailMessage) -> list[Attachment]:
    found = []
    for part in msg.walk():
        filename = part.get_filename()
        if not filename and part.get_content_disposition() != "attachment":
            continue
        payload = part.get_payload(decode=True) or b""
        found.append(Attachment(
            filename=filename or "(no name)",
            content_type=part.get_content_type(),
            size=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
        ))
    return found


def _check_link(link: Link) -> list[Finding]:
    out = []
    host = link.host
    if not host:
        return out
    try:
        ipaddress.ip_address(host)
        out.append(Finding("link", f"Link points to a raw IP address: {link.url}", 20))
    except ValueError:
        pass
    if host in URL_SHORTENERS:
        out.append(Finding("link", f"URL shortener hides the real destination: {host}", 10))
    if host.startswith("xn--") or ".xn--" in host:
        out.append(Finding("link", f"Punycode domain (possible look-alike): {host}", 20))
    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        out.append(Finding("link", f"Domain uses a TLD often abused by phishers: {host}", 10))
    if "@" in urlparse(link.url).netloc:
        out.append(Finding("link", f"URL contains '@' to disguise the host: {link.url}", 20))
    if host.count(".") >= 4:
        out.append(Finding("link", f"Unusually deep subdomain: {host}", 5))
    # Visible text looks like a URL but points somewhere else
    shown = URL_RE.search(link.text or "")
    if shown:
        shown_host = (urlparse(shown.group(0)).hostname or "").lower()
        if shown_host and base_domain(shown_host) != base_domain(host):
            out.append(Finding(
                "link",
                f"Link text shows {shown_host} but really goes to {host}",
                30,
            ))
    return out


def received_ips(msg: EmailMessage) -> list[str]:
    """Public IPs from the "from" part of each Received header, newest hop first.

    Headers are prepended by each server, so the last public IP is the closest to the sender.
    Only the "from ..." part is read: the "by ..." part names the receiving server.
    """
    out: list[str] = []
    for header in msg.get_all("Received") or []:
        text = " ".join(str(header).split())
        if not text.lower().startswith("from "):
            continue
        sender_part = re.split(r"\sby\s", text, maxsplit=1, flags=re.IGNORECASE)[0]
        for candidate in RECEIVED_IP_RE.findall(sender_part):
            try:
                addr = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if addr.is_global and str(addr) not in out:
                out.append(str(addr))
    return out


def analyze_message(msg: EmailMessage) -> Report:
    report = Report(
        subject=str(msg.get("Subject", "")),
        sender=str(msg.get("From", "")),
        reply_to=str(msg.get("Reply-To", "")),
        return_path=str(msg.get("Return-Path", "")),
    )

    report.received_ips = received_ips(msg)
    report.origin_ip = report.received_ips[-1] if report.received_ips else ""

    # 1. Authentication
    report.auth = parse_auth_results(msg)
    for mech, weight in (("spf", 15), ("dkim", 15), ("dmarc", 20)):
        verdict = report.auth[mech]
        if verdict in {"fail", "softfail", "permerror"}:
            report.findings.append(Finding("auth", f"{mech.upper()} = {verdict}", weight))
        elif verdict == "none":
            report.findings.append(Finding("auth", f"No {mech.upper()} result found", 5))

    # 2. Header consistency
    from_dom = domain_of(report.sender)
    reply_dom = domain_of(report.reply_to)
    return_dom = domain_of(report.return_path)
    if reply_dom and from_dom and base_domain(reply_dom) != base_domain(from_dom):
        report.findings.append(Finding(
            "headers", f"Reply-To domain ({reply_dom}) differs from From ({from_dom})", 20))
    if return_dom and from_dom and base_domain(return_dom) != base_domain(from_dom):
        report.findings.append(Finding(
            "headers", f"Return-Path domain ({return_dom}) differs from From ({from_dom})", 10))
    display_name, _ = parseaddr(report.sender)
    embedded = re.search(r"[\w.+-]+@([\w-]+\.[\w.-]+)", display_name or "")
    if embedded and from_dom and base_domain(embedded.group(1).lower()) != base_domain(from_dom):
        report.findings.append(Finding(
            "headers", f"Display name contains another address ({embedded.group(0)})", 20))

    # 3. Body
    text, html = _bodies(msg)
    lowered = (report.subject + " " + text + " " + html).lower()
    hits = sorted({w for w in URGENCY_WORDS if w in lowered})
    if hits:
        report.findings.append(Finding(
            "content", "Pressure / urgency wording: " + ", ".join(hits[:5]), min(20, 5 * len(hits))))
    if re.search(r"<form\b", html, re.IGNORECASE):
        report.findings.append(Finding("content", "HTML form inside the email (credential harvesting)", 20))

    # 4. Links
    report.links = extract_links(text, html)
    for link in report.links:
        report.findings.extend(_check_link(link))

    # 5. Attachments
    report.attachments = extract_attachments(msg)
    for att in report.attachments:
        name = att.filename.lower()
        ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""
        if ext in RISKY_EXTENSIONS:
            report.findings.append(Finding("attachment", f"Risky attachment type: {att.filename}", 25))
        if re.search(r"\.(pdf|docx?|xlsx?|jpg|png)\.(exe|js|scr|vbs|bat|cmd|lnk)$", name):
            report.findings.append(Finding("attachment", f"Double extension: {att.filename}", 30))

    return report


def analyze_bytes(raw: bytes) -> Report:
    msg = email.message_from_bytes(raw, policy=policy.default)
    return analyze_message(msg)  # type: ignore[arg-type]


def analyze_file(path: str) -> Report:
    with open(path, "rb") as fh:
        return analyze_bytes(fh.read())
