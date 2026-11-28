# phishlens reference

Everything you can type or set, in one place. For a guided tour, start with the [README](../README.md).

## Commands

| Command | What it does |
|---|---|
| `phishlens mail.eml [more.eml…]` | Analyze files and print a report |
| `phishlens mail.eml --json` | Same, as JSON (fields below) |
| `phishlens mail.eml --no-color` | No terminal colors |
| `phishlens --version` | Version |
| `phishlens web [--host H] [--port P] [--db FILE] [--env-file FILE]` | Start the web interface (default `127.0.0.1:8000`) |
| `phishlens scan [--every SECONDS] [--db FILE]` | Scan the mailbox set in `PHISHLENS_IMAP_*` once, or in a loop (minimum 30 s) |
| `phishlens geoip update [--file CSV] [--db FILE]` | Download this month's DB-IP Lite database, or convert a `.csv` / `.csv.gz` downloaded by hand |
| `phishlens geoip lookup IP` | Country of an IP address |
| `phishlens user list` | List web accounts |
| `phishlens user add NAME [--role admin\|viewer]` | Create an account (asks for the password) |
| `phishlens user reset-password NAME` | New password; signs out that user's sessions |
| `phishlens user delete NAME` | Delete an account (the last admin cannot be deleted) |

`python -m phishlens …` works everywhere instead of `phishlens …`. `python -m phishlens.imap` is the older form of `phishlens scan`.

**Exit codes**: `0` safe (score below 30), `1` suspicious or phishing, or an error in `user` / `geoip` commands, `2` unreadable file, missing setting, or port already in use.

## Environment variables

All are optional. In Docker, put them in `.env` ([.env.example](../.env.example)). With `phishlens web`, use `--env-file`.
On an Apache server, AI variables go in `/etc/phishlens/ai.env` and mailbox variables in `/etc/phishlens/mail.env`.

### Storage and network

| Variable | Default | Meaning |
|---|---|---|
| `PHISHLENS_DB` | per-OS data folder (below) | SQLite file: accounts, mailbox results, statistics, settings |
| `PHISHLENS_GEOIP` | `geoip.bin` next to the database | GeoIP file created by `phishlens geoip update` |
| `PHISHLENS_HOST` | `127.0.0.1` (`0.0.0.0` in Docker) | Address `phishlens web` listens on |
| `PHISHLENS_PORT` | `8000` | Port of `phishlens web` |
| `PHISHLENS_TRUST_PROXY` | off | `1` behind a reverse proxy: trust `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`. Never set it when clients reach phishlens directly |

Default data folder: `%LOCALAPPDATA%\phishlens\` (Windows), `~/Library/Application Support/phishlens/` (macOS),
`/var/lib/phishlens/` when it exists (server installed with the script), else `~/.local/share/phishlens/` (Linux), `/data` (Docker).

### Mailbox scanner

| Variable | Default | Meaning |
|---|---|---|
| `PHISHLENS_IMAP_HOST` | required | IMAP server, for example `imap.gmail.com` |
| `PHISHLENS_IMAP_USER` | required | Login, usually the email address |
| `PHISHLENS_IMAP_PASSWORD` | required | Password; use an application password |
| `PHISHLENS_IMAP_PORT` | `993` | IMAP over TLS |
| `PHISHLENS_IMAP_FOLDER` | `INBOX` | Folder to scan |
| `PHISHLENS_IMAP_LIMIT` | `50` | How many of the most recent messages to look at per scan |
| `PHISHLENS_IMAP_CAFILE` | system store | CA file for a server with a private certificate authority |

The folder is opened read-only and messages are fetched with `BODY.PEEK`: they stay unread. Messages above 10 MB are skipped.

### AI opinion

| Variable | Default | Meaning |
|---|---|---|
| `PHISHLENS_AI_URL` | empty | Base URL. Empty: use the Settings page. Set: overrides the Settings page |
| `PHISHLENS_AI_PROVIDER` | guessed from the URL | `ollama`, `openai`, `anthropic`, `mistral`, `groq`, `custom` |
| `PHISHLENS_AI_MODEL` | provider default | Model name |
| `PHISHLENS_AI_KEY` | empty | API key |
| `PHISHLENS_AI_TIMEOUT` | `120` | Seconds per request |
| `PHISHLENS_AI_ENV` | `/etc/phishlens/ai.env` | `KEY=VALUE` file the web app reads at start |
| `PHISHLENS_LANG` | `fr` | Language of the scanner's AI answers (`fr`, `en`). The web interface uses the reader's language |

## Web interface

| Page | Who | What |
|---|---|---|
| `/setup` | first visitor, with the setup code | Create the first admin (only while no account exists) |
| `/login` | everyone | Sign in |
| `/` | signed in | Analyze an email |
| `/dashboard` | signed in | Live counters, map, last 24 hours, latest emails |
| `/mailbox` | signed in | Mailbox results, `?verdict=PHISHING` / `SUSPICIOUS` / `PROBABLY SAFE` |
| `/account` | signed in | Change your password |
| `/admin/users` | admins | Add, delete, change role, set password |
| `/admin/settings` | admins | AI provider, GeoIP database |
| `/lang?l=fr` | everyone | Switch language (`en`, `fr`) |

**Roles**: *viewer* analyzes emails and reads the dashboard and mailbox; *admin* also manages users and settings.

### HTTP endpoints

| Endpoint | Auth | Returns |
|---|---|---|
| `GET /healthz` | none | `ok` (for Docker, Uptime Kuma…) |
| `GET /api/stats` | session cookie | Dashboard numbers as JSON |
| `POST /api/analyze` | session cookie + `X-CSRF-Token` header | `{"report": …, "country": …, "ai": …, "ai_error": …}`; body: raw `.eml` or multipart (`file` / `source`), 2 MB maximum |

## JSON report fields

`phishlens mail.eml --json` and `/api/analyze` return, for each email:

| Field | Meaning |
|---|---|
| `subject`, `from`, `reply_to`, `return_path` | Headers |
| `authentication` | `{"spf": …, "dkim": …, "dmarc": …}` from `Authentication-Results` (`pass`, `fail`, `none`…) |
| `links` | `[{"url": …, "text": …}]` |
| `attachments` | `[{"filename": …, "content_type": …, "size": …, "sha256": …}]` |
| `findings` | `[{"category": …, "message": …, "points": …}]` |
| `score` | 0 to 100 |
| `verdict` | `PROBABLY SAFE` (0–29), `SUSPICIOUS` (30–59), `PHISHING` (60+) |
| `origin_ip` | Public IP closest to the sender, from `Received` headers (empty if none) |
| `received_ips` | Public relay IPs, newest hop first |

## What is stored

| Data | Where | Content |
|---|---|---|
| Accounts | `users` | Username, scrypt password hash, role, language, last sign-in |
| Sessions | `sessions` | SHA-256 of the session token, CSRF token, expiry (7 days) |
| Mailbox results | `results` | Subject, sender, score, verdict, findings, origin IP, country, AI opinion. **No message body** |
| Statistics | `events` | Time, source (`mailbox` / `upload`), score, verdict, country. Nothing else |
| Settings | `settings` | AI provider, URL, model, API key; one-time setup code until the first admin exists |
| Failed sign-ins | `login_attempts` | IP and time, kept 15 minutes |

Back up the database file to keep accounts and history. It contains the AI API key: protect it like a password.

## Building the map

`phishlens/web/static/world.svg` is generated, not hand-drawn:

```bash
curl -L -o ne.geojson https://cdn.jsdelivr.net/gh/nvkelso/natural-earth-vector@v5.1.2/geojson/ne_110m_admin_0_countries.geojson
python tools/build_world_svg.py ne.geojson
```
