"""HTML rendering. Every value coming from an email or a user goes through esc()."""

from __future__ import annotations

import json
from html import escape as esc

from .. import __version__
from .i18n import JS_KEYS, LANGS

V = __version__  # cache-busting for static files

ICONS = {
    "shield": '<path d="M12 3l7 3v5c0 4.5-3 8.4-7 10-4-1.6-7-5.5-7-10V6l7-3z"/><path d="M9 12l2 2 4-4"/>',
    "scan": '<circle cx="11" cy="11" r="6"/><path d="M20 20l-4.5-4.5"/>',
    "inbox": '<path d="M3 13l3-8h12l3 8v6H3z"/><path d="M3 13h5l1 2h6l1-2h5"/>',
    "users": '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c.8-3.6 3.4-5.5 6.5-5.5s5.7 1.9 6.5 5.5"/>'
             '<path d="M16 4.6a3.5 3.5 0 010 6.8M18 14.8c1.8.8 3 2.6 3.5 5.2"/>',
    "user": '<circle cx="12" cy="8" r="4"/><path d="M4 21c1-4.4 4.2-6.5 8-6.5s7 2.1 8 6.5"/>',
    "logout": '<path d="M15 4h4v16h-4"/><path d="M10 8l-4 4 4 4"/><path d="M6 12h10"/>',
    "theme": '<circle cx="12" cy="12" r="8"/><path d="M12 4a8 8 0 000 16z" fill="currentColor"/>',
    "upload": '<path d="M12 16V4"/><path d="M7 9l5-5 5 5"/><path d="M4 16v4h16v-4"/>',
    "copy": '<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V4H4v12h4"/>',
    "alert": '<path d="M12 3l10 18H2z"/><path d="M12 10v5M12 18v.01"/>',
    "link": '<path d="M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1 1"/>'
            '<path d="M14 10a4 4 0 00-5.7 0l-3 3a4 4 0 005.7 5.7l1-1"/>',
    "clip": '<path d="M20 11l-8.5 8.5a5 5 0 01-7-7L13 4a3.5 3.5 0 015 5l-8.5 8.5a2 2 0 01-3-3L14 7"/>',
    "spark": '<path d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8z"/><path d="M19 16l.8 2.2L22 19l-2.2.8L19 22l-.8-2.2L16 19l2.2-.8z"/>',
    "mail": '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>',
    "check": '<path d="M5 12l5 5 9-10"/>',
    "gear": '<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3'
            'M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1"/>',
}

VERDICT_CLASS = {"PHISHING": "bad", "SUSPICIOUS": "warn", "PROBABLY SAFE": "ok"}
GAUGE = 326.73  # circumference of r=52


def icon(name: str, cls: str = "icon") -> str:
    return (f'<svg class="{cls}" viewBox="0 0 24 24" aria-hidden="true" fill="none" '
            f'stroke="currentColor" stroke-width="1.8" stroke-linecap="round" '
            f'stroke-linejoin="round">{ICONS[name]}</svg>')


def csrf_field(csrf: str) -> str:
    return f'<input type="hidden" name="csrf" value="{esc(csrf)}">'


def flash(t, ok: str | None, err: str | None) -> str:
    out = ""
    for kind, key in (("ok", ok), ("bad", err)):
        if key and t.has(key):  # only known keys: never echo raw query text
            out += f'<div class="flash flash-{kind}" role="status">{esc(t(key))}</div>'
    return out


def _js_strings(t) -> str:
    data = json.dumps({k: t(k) for k in JS_KEYS}, ensure_ascii=False)
    return data.replace("<", "\\u003c")


def _head(t, title: str) -> str:
    return f"""<!doctype html>
<html lang="{t.lang}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="light dark">
<title>{esc(title)} · phishlens</title>
<link rel="icon" href="/static/logo.svg?v={V}" type="image/svg+xml">
<link rel="stylesheet" href="/static/app.css?v={V}">
<script src="/static/theme.js?v={V}"></script>
<script src="/static/app.js?v={V}" defer></script>
</head>"""


def _lang_switch(t, path: str) -> str:
    links = []
    for lang in LANGS:
        cur = ' aria-current="true"' if lang == t.lang else ""
        links.append(f'<a href="/lang?l={lang}&amp;next={esc(path)}"{cur}>{lang.upper()}</a>')
    return f'<div class="lang" role="group" aria-label="{esc(t("language"))}">{"".join(links)}</div>'


def _theme_button(t) -> str:
    return (f'<button type="button" class="icon-btn js-only" data-theme-toggle '
            f'title="{esc(t("theme"))}" aria-label="{esc(t("theme"))}">{icon("theme")}</button>')


def layout(ctx, title: str, body: str, active: str = "") -> bytes:
    t, user = ctx.t, ctx.user
    nav = [("/", "scan", "nav_analyze"), ("/mailbox", "inbox", "nav_mailbox")]
    if user["role"] == "admin":
        nav.append(("/admin/users", "users", "nav_users"))
        nav.append(("/admin/settings", "gear", "nav_settings"))
    nav.append(("/account", "user", "nav_account"))
    current = ' class="nav-link active" aria-current="page"'
    links = "".join(
        f'<a href="{href}"{current if href == active else " class=nav-link"}>'
        f'{icon(ic)}<span>{esc(t(key))}</span></a>'
        for href, ic, key in nav)
    role = t("role_" + user["role"])
    ai_cls = "on" if ctx.ai_model else "off"
    ai_text = t("ai_on", model=ctx.ai_model) if ctx.ai_model else t("ai_off")
    html = f"""{_head(t, title)}
<body>
<div class="shell">
<aside class="sidebar">
  <a class="brand" href="/">{icon("shield", "brand-icon")}<span><b>phishlens</b><small>{esc(t("tagline"))}</small></span></a>
  <nav class="nav">{links}</nav>
  <div class="sidebar-foot">
    <div class="who">{icon("user")}<span><b>{esc(user["username"])}</b><small>{esc(role)}</small></span></div>
    <form method="post" action="/logout">{csrf_field(ctx.csrf)}<button class="nav-link as-button">{icon("logout")}<span>{esc(t("logout"))}</span></button></form>
  </div>
</aside>
<div class="main">
  <header class="topbar">
    <a class="brand brand-mobile" href="/">{icon("shield", "brand-icon")}<b>phishlens</b></a>
    <h1>{esc(title)}</h1>
    <div class="tools">
      <span class="pill ai-{ai_cls}" title="{esc(ai_text)}">{icon("spark")}<span>{esc(ai_text)}</span></span>
      {_lang_switch(t, ctx.path)}
      {_theme_button(t)}
    </div>
  </header>
  <main class="content">{flash(t, ctx.ok, ctx.err)}{body}</main>
  <footer class="footer">{esc(t("footer", version=__version__))}</footer>
</div>
</div>
<nav class="bottombar">{links}</nav>
<div class="toasts" aria-live="polite"></div>
<script type="application/json" id="i18n">{_js_strings(t)}</script>
</body></html>"""
    return html.encode("utf-8", errors="replace")


def bare_layout(t, title: str, body: str, path: str = "/") -> bytes:
    """Centered card for sign-in, setup and error pages."""
    html = f"""{_head(t, title)}
<body class="bare">
<div class="bare-tools">{_lang_switch(t, path)}{_theme_button(t)}</div>
<main class="bare-card card">
  <div class="brand brand-center">{icon("shield", "brand-icon big")}<span><b>phishlens</b><small>{esc(t("tagline"))}</small></span></div>
  {body}
</main>
<div class="toasts" aria-live="polite"></div>
<script type="application/json" id="i18n">{_js_strings(t)}</script>
</body></html>"""
    return html.encode("utf-8", errors="replace")


# --- sign-in pages ---------------------------------------------------------

def login_page(t, error: str | None, next_path: str, username: str = "") -> bytes:
    body = f"""<h2>{esc(t("login_title"))}</h2><p class="muted">{esc(t("login_intro"))}</p>
{flash(t, None, error)}
<form method="post" action="/login" class="stack">
  <input type="hidden" name="next" value="{esc(next_path)}">
  <label>{esc(t("username"))}<input name="username" value="{esc(username)}" autocomplete="username" required autofocus></label>
  <label>{esc(t("password"))}<input type="password" name="password" autocomplete="current-password" required></label>
  <button class="btn primary wide">{esc(t("login_btn"))}</button>
</form>"""
    return bare_layout(t, t("login_title"), body, "/login")


def setup_page(t, error: str | None, username: str = "") -> bytes:
    body = f"""<h2>{esc(t("setup_title"))}</h2><p class="muted">{esc(t("setup_intro"))}</p>
{flash(t, None, error)}
<form method="post" action="/setup" class="stack" data-password-check>
  <label>{esc(t("setup_code"))}<input name="code" class="mono" autocomplete="off" placeholder="XXXX-XXXX-XXXX" required autofocus></label>
  <label>{esc(t("username"))}<input name="username" value="{esc(username or "admin")}" autocomplete="username" required></label>
  <label>{esc(t("password"))}<input type="password" name="password" minlength="10" autocomplete="new-password" required>
    <small class="muted">{esc(t("password_hint"))}</small></label>
  <label>{esc(t("password_confirm"))}<input type="password" name="confirm" minlength="10" autocomplete="new-password" required></label>
  <button class="btn primary wide">{esc(t("setup_btn"))}</button>
</form>"""
    return bare_layout(t, t("setup_title"), body, "/setup")


def error_page(t, status_key: str) -> bytes:
    body = (f'<h2>{esc(t(status_key))}</h2>'
            f'<p><a class="btn" href="/">{esc(t("back_home"))}</a></p>')
    return bare_layout(t, t(status_key), body)


# --- analysis --------------------------------------------------------------

def analyze_page(ctx, result_html: str = "") -> bytes:
    t = ctx.t
    body = f"""<section class="card">
<p class="muted">{esc(t("analyze_intro"))}</p>
<form method="post" action="/" enctype="multipart/form-data" id="analyze-form" class="stack">
  {csrf_field(ctx.csrf)}
  <label class="dropzone" data-dropzone>
    <input type="file" name="file" accept=".eml,message/rfc822" class="visually-hidden">
    {icon("upload", "drop-icon")}
    <b data-drop-title>{esc(t("drop_title"))}</b>
    <small class="muted">{esc(t("drop_hint"))}</small>
  </label>
  <label>{esc(t("paste_label"))}
    <textarea name="source" spellcheck="false" placeholder="{esc(t("paste_placeholder"))}"></textarea></label>
  <div class="row">
    <button class="btn primary" data-submit>{icon("scan")}<span>{esc(t("analyze_btn"))}</span></button>
    <button type="reset" class="btn ghost">{esc(t("clear"))}</button>
  </div>
  <p class="hint">{esc(t("how_get_eml"))}</p>
</form>
</section>
<div id="result">{result_html}</div>"""
    return layout(ctx, t("analyze_title"), body, "/")


def error_box(message: str) -> str:
    return f'<div class="flash flash-bad" role="alert">{esc(message)}</div>'


def _auth_class(value: str) -> str:
    if value == "pass":
        return "ok"
    if value in {"fail", "softfail", "permerror", "temperror"}:
        return "bad"
    return "neutral"


def _empty(text: str) -> str:
    return f'<p class="muted empty">{esc(text)}</p>'


def report_html(t, report, ai_text: str | None = None, ai_failed: bool = False) -> str:
    v = report.verdict
    cls = VERDICT_CLASS.get(v, "ok")
    offset = GAUGE * (1 - report.score / 100)
    pills = "".join(
        f'<span class="auth auth-{_auth_class(val)}"><b>{esc(mech.upper())}</b>{esc(val)}</span>'
        for mech, val in report.auth.items())

    findings = sorted(report.findings, key=lambda f: -f.points)
    finding_rows = "".join(
        f"""<li class="finding">
  <span class="pts pts-{"bad" if f.points >= 20 else "warn" if f.points >= 10 else "neutral"}">+{f.points}</span>
  <div><span class="tag">{esc(f.category)}</span> {esc(f.message)}
  <svg class="bar" viewBox="0 0 100 4" preserveAspectRatio="none" aria-hidden="true"><rect width="100" height="4" rx="2" class="bar-bg"/><rect width="{min(100, f.points * 100 // 30)}" height="4" rx="2" class="bar-fg"/></svg></div>
</li>""" for f in findings) or ""
    findings_block = f'<ul class="findings">{finding_rows}</ul>' if finding_rows else _empty(t("no_findings"))

    rows = [("h_subject", report.subject), ("h_from", report.sender),
            ("h_reply_to", report.reply_to), ("h_return_path", report.return_path)]
    headers = "".join(f"<dt>{esc(t(k))}</dt><dd>{esc(val) if val else '—'}</dd>" for k, val in rows)

    link_items = []
    for link in report.links:
        shown = ""
        if link.text and link.text.strip() and link.text.strip() != link.url:
            shown = f'<small class="muted">{esc(t("link_text"))}{t("colon")}{esc(link.text.strip()[:200])}</small>'
        link_items.append(f'<li><code class="url">{esc(link.url)}</code>{shown}</li>')
    links_block = (f'<p class="hint">{icon("alert")} {esc(t("links_note"))}</p>'
                   f'<ul class="links">{"".join(link_items)}</ul>') if link_items else _empty(t("no_links"))

    att_items = "".join(
        f"""<li class="attachment"><div><b>{esc(a.filename)}</b>
  <small class="muted">{esc(a.content_type)} · {a.size:,} {esc(t("bytes"))}</small></div>
  <div class="hash"><code>{esc(a.sha256)}</code>
  <button type="button" class="icon-btn js-only" data-copy="{esc(a.sha256)}" title="{esc(t("copy"))}" aria-label="{esc(t("copy"))}">{icon("copy")}</button></div></li>"""
        for a in report.attachments)
    att_block = f'<ul class="attachments">{att_items}</ul>' if att_items else _empty(t("no_attachments"))

    ai_block = ""
    if ai_text or ai_failed:
        inner = error_box(t("ai_error")) if ai_failed else f'<p class="ai-text">{esc(ai_text)}</p>'
        ai_block = f"""<section class="card ai-card span-2">
<h3>{icon("spark")} {esc(t("ai_title"))} <span class="tag">{esc(t("ai_badge"))}</span></h3>
{inner}<p class="hint">{esc(t("ai_note"))}</p></section>"""

    return f"""<div class="report" data-verdict="{cls}">
<section class="card verdict verdict-{cls}">
  <svg class="gauge" viewBox="0 0 120 120" role="img" aria-label="{esc(t("score"))} {report.score}/100">
    <circle class="gauge-bg" cx="60" cy="60" r="52"/>
    <circle class="gauge-fg" cx="60" cy="60" r="52" stroke-dasharray="{GAUGE}" stroke-dashoffset="{offset:.2f}" transform="rotate(-90 60 60)"/>
    <text x="60" y="62" class="gauge-num" data-count="{report.score}">{report.score}</text>
    <text x="60" y="82" class="gauge-unit">/ 100</text>
  </svg>
  <div class="verdict-body">
    <span class="badge badge-{cls}">{esc(t("verdict_" + v))}</span>
    <h2>{esc(report.subject) or esc(t("no_subject"))}</h2>
    <p class="muted from">{esc(report.sender)}</p>
    <div class="auths" aria-label="{esc(t("auth_title"))}">{pills}</div>
  </div>
</section>
<div class="grid">
  <section class="card span-2"><h3>{icon("alert")} {esc(t("findings_title"))} <span class="count">{len(findings)}</span></h3>{findings_block}</section>
  <section class="card"><h3>{icon("mail")} {esc(t("headers_title"))}</h3><dl class="kv">{headers}</dl></section>
  <section class="card"><h3>{icon("clip")} {esc(t("attachments_title"))} <span class="count">{len(report.attachments)}</span></h3>{att_block}</section>
  <section class="card span-2"><h3>{icon("link")} {esc(t("links_title"))} <span class="count">{len(report.links)}</span></h3>{links_block}</section>
  {ai_block}
</div>
</div>"""


# --- mailbox ---------------------------------------------------------------

def mailbox_page(ctx, stats: dict, rows, verdict: str | None) -> bytes:
    t = ctx.t
    tiles = [("mb_total", stats["total"], "neutral", None), ("verdict_PHISHING", stats["PHISHING"], "bad", "PHISHING"),
             ("verdict_SUSPICIOUS", stats["SUSPICIOUS"], "warn", "SUSPICIOUS"),
             ("verdict_PROBABLY SAFE", stats["PROBABLY SAFE"], "ok", "PROBABLY SAFE")]
    tile_html = "".join(
        f'<a class="stat stat-{cls}{" active" if v == verdict else ""}" href="/mailbox{"?verdict=" + v.replace(" ", "+") if v else ""}">'
        f'<span>{esc(t(key))}</span><b data-count="{n}">{n}</b></a>'
        for key, n, cls, v in tiles)

    if not stats["total"]:
        listing = f"""<section class="card empty-state">{icon("inbox", "empty-icon")}
<h3>{esc(t("mb_empty_title"))}</h3><p class="muted">{esc(t("mb_empty_text"))}</p></section>"""
    elif not rows:
        listing = f'<section class="card">{_empty(t("mb_none_filter"))}</section>'
    else:
        items = []
        for r in rows:
            cls = VERDICT_CLASS.get(r["verdict"], "ok")
            try:
                found = json.loads(r["findings"] or "[]")
            except ValueError:
                found = []
            details = "".join(f"<li>{esc(str(x))}</li>" for x in found) or f"<li>{esc(t('no_findings'))}</li>"
            ai = (f'<div class="ai-inline">{icon("spark")}<p>{esc(r["ai"])}</p></div>' if r["ai"] else "")
            items.append(f"""<details class="mail">
<summary><span class="score score-{cls}">{r["score"]}</span>
<span class="mail-main"><b>{esc(r["subject"] or t("no_subject"))}</b><small class="muted">{esc(r["sender"])}</small></span>
<span class="badge badge-{cls}">{esc(t("verdict_" + r["verdict"]) if t.has("verdict_" + r["verdict"]) else esc(r["verdict"]))}</span>
<time class="muted">{esc(r["scanned"])}</time></summary>
<div class="mail-body"><p class="muted">{esc(t("scanned_at", date=r["scanned"]))}</p><ul>{details}</ul>{ai}</div>
</details>""")
        listing = f'<section class="card list">{"".join(items)}</section>'

    body = f"""<p class="muted">{esc(t("mailbox_intro"))}</p>
<div class="stats">{tile_html}</div>
{listing}"""
    return layout(ctx, t("mailbox_title"), body, "/mailbox")


# --- users -----------------------------------------------------------------

def _role_select(t, current: str = "viewer") -> str:
    opts = "".join(f'<option value="{r}"{" selected" if r == current else ""}>{esc(t("role_" + r))}</option>'
                   for r in ("viewer", "admin"))
    return f'<select name="role">{opts}</select>'


def users_page(ctx, users) -> bytes:
    t = ctx.t
    rows = []
    for u in users:
        me = f' <span class="tag">{esc(t("you"))}</span>' if u["id"] == ctx.user["id"] else ""
        rows.append(f"""<div class="user-row">
  <div class="user-id">{icon("user")}<div><b>{esc(u["username"])}</b>{me}
    <small class="muted">{esc(t("last_login"))}{t("colon")}{esc(u["last_login"] or t("never"))}</small></div></div>
  <form method="post" action="/admin/users" class="inline">{csrf_field(ctx.csrf)}
    <input type="hidden" name="action" value="role"><input type="hidden" name="id" value="{u["id"]}">
    {_role_select(t, u["role"])}<button class="btn small">{esc(t("save"))}</button></form>
  <form method="post" action="/admin/users" class="inline">{csrf_field(ctx.csrf)}
    <input type="hidden" name="action" value="password"><input type="hidden" name="id" value="{u["id"]}">
    <input type="password" name="password" minlength="10" placeholder="{esc(t("new_password"))}" autocomplete="new-password" required>
    <button class="btn small">{esc(t("set_password"))}</button></form>
  <form method="post" action="/admin/users" class="inline" data-confirm>{csrf_field(ctx.csrf)}
    <input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="{u["id"]}">
    <button class="btn small danger">{esc(t("delete"))}</button></form>
</div>""")
    body = f"""<p class="muted">{esc(t("users_intro"))}</p>
<section class="card list">{"".join(rows)}</section>
<section class="card"><h3>{icon("users")} {esc(t("add_user"))}</h3>
<form method="post" action="/admin/users" class="form-grid">{csrf_field(ctx.csrf)}
  <input type="hidden" name="action" value="add">
  <label>{esc(t("username"))}<input name="username" required autocomplete="off"></label>
  <label>{esc(t("password"))}<input type="password" name="password" minlength="10" required autocomplete="new-password"></label>
  <label>{esc(t("role"))}{_role_select(t)}</label>
  <button class="btn primary">{esc(t("create"))}</button>
</form></section>"""
    return layout(ctx, t("users_title"), body, "/admin/users")


def account_page(ctx) -> bytes:
    t = ctx.t
    body = f"""<section class="card narrow">
<p>{esc(t("signed_in_as", name=ctx.user["username"], role=t("role_" + ctx.user["role"])))}</p>
<h3>{esc(t("change_password"))}</h3>
<form method="post" action="/account" class="stack" data-password-check>{csrf_field(ctx.csrf)}
  <label>{esc(t("current_password"))}<input type="password" name="current" autocomplete="current-password" required></label>
  <label>{esc(t("new_password"))}<input type="password" name="password" minlength="10" autocomplete="new-password" required>
    <small class="muted">{esc(t("password_hint"))}</small></label>
  <label>{esc(t("password_confirm"))}<input type="password" name="confirm" minlength="10" autocomplete="new-password" required></label>
  <button class="btn primary">{esc(t("change_password"))}</button>
</form></section>"""
    return layout(ctx, t("account_title"), body, "/account")


# --- settings --------------------------------------------------------------

def settings_page(ctx, cfg: dict, test=None, error_key: str | None = None) -> bytes:
    from .. import ai
    t = ctx.t
    current = ctx.ai
    if current["url"]:
        host = current["url"].split("//")[-1].split("/")[0]
        status = (f'<p class="status status-on">{icon("spark")} '
                  f'{esc(t("ai_status_on", model=current["model"], host=host))}</p>')
    else:
        status = f'<p class="status">{esc(t("ai_status_off"))}</p>'

    notice = ""
    if test is not None:
        ok, text = test
        key = "ai_test_ok" if ok else "ai_test_fail"
        notice = (f'<div class="flash flash-{"ok" if ok else "bad"}" role="status">'
                  f'{esc(t(key, reply=text[:300], error=text[:300]))}</div>')
    elif error_key:
        notice = flash(t, None, error_key)

    if current["source"] == "env":
        body = f"""<section class="card narrow"><h3>{icon("spark")} {esc(t("ai_title"))}</h3>{status}
<p class="muted">{esc(t("ai_env_note"))}</p></section>"""
        return layout(ctx, t("settings_title"), body, "/admin/settings")

    selected = cfg.get("provider") or "ollama"
    options = "".join(
        f'<option value="{k}" data-url="{esc(p["url"])}" data-model="{esc(p["model"])}" '
        f'data-cloud="{int(p["cloud"])}"{" selected" if k == selected else ""}>{esc(p["label"])}</option>'
        for k, p in ai.PROVIDERS.items())
    preset = ai.PROVIDERS[selected]
    saved_key = current["key"] if current["url"].rstrip("/") == (cfg.get("url") or "").rstrip("/") else ""
    if saved_key:
        key_hint = t("ai_key_keep", last=saved_key[-4:])
        clear = (f'<label class="check"><input type="checkbox" name="clear_key" value="1"> '
                 f'{esc(t("ai_clear_key"))}</label>')
    else:
        key_hint, clear = t("ai_key_placeholder"), ""
    cloud_hidden = "" if ai.is_cloud({**cfg, "provider": selected}) else " hidden"
    disable = ""
    if current["url"]:
        disable = f"""<form method="post" action="/admin/settings" class="inline">{csrf_field(ctx.csrf)}
<input type="hidden" name="action" value="disable"><button class="btn ghost danger">{esc(t("ai_disable"))}</button></form>"""

    body = f"""<p class="muted">{esc(t("settings_intro"))}</p>
<section class="card narrow">
<h3>{icon("spark")} {esc(t("ai_title"))}</h3>
{status}{notice}
<form method="post" action="/admin/settings" class="stack" id="ai-form">{csrf_field(ctx.csrf)}
  <label>{esc(t("ai_provider"))}<select name="provider" data-provider>{options}</select></label>
  <div class="flash flash-warn" data-cloud-warning{cloud_hidden}>{icon("alert")} {esc(t("ai_cloud_warning"))}</div>
  <label>{esc(t("ai_url"))}<input name="url" value="{esc(cfg.get("url") or preset["url"])}" placeholder="https://…/v1" class="mono" data-url required></label>
  <label>{esc(t("ai_model"))}<input name="model" value="{esc(cfg.get("model") or preset["model"])}" class="mono" data-model required></label>
  <label>{esc(t("ai_key"))}<input type="password" name="key" autocomplete="off" placeholder="{esc(key_hint)}">
    <small class="muted">{esc(t("ai_key_storage"))}</small></label>
  {clear}
  <div class="row">
    <button class="btn primary" name="action" value="save">{esc(t("save"))}</button>
    <button class="btn" name="action" value="test">{esc(t("ai_test"))}</button>
  </div>
</form>
<p class="hint">{esc(t("ai_docker_hint"))}</p>
{disable}
</section>"""
    return layout(ctx, t("settings_title"), body, "/admin/settings")
