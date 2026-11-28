# Security policy

## Reporting a vulnerability

Please do not publish exploit details or real emails in a public issue.
Use GitHub's private vulnerability reporting (Security tab) if it is enabled,
otherwise open an issue asking for a private contact, without any detail.

## Design choices

**Emails are hostile input**
- All output is HTML-escaped; links are shown as text, never clickable and never fetched.
- Uploaded emails are analyzed in memory and never written to disk (2 MB limit).
- The mailbox is opened read-only and messages are fetched without marking them as read.
- The AI opinion is advisory and never changes the score: an email can try to manipulate a model.

**Web interface**
- Accounts with admin and viewer roles. Passwords are hashed with scrypt; the first admin needs a one-time setup code
  printed on the server, so nobody else on the network can claim a fresh instance.
- Session cookies are `HttpOnly`, `SameSite=Strict`, and `Secure` over HTTPS; only a hash of the token is stored.
- Every form and API call carries a CSRF token, and cross-site POSTs are refused (Origin check).
- Five failed sign-ins from one address lock it out for 15 minutes.
- Strict Content Security Policy (`script-src 'self'`, no inline script or style), `frame-ancestors 'none'`,
  `nosniff`, `Referrer-Policy: same-origin` (no URL is ever sent to another site). No CDN: every script and style is served by phishlens.
- Static files come from a fixed list; no path is built from the URL. Redirects only go to local paths.

**Privacy**
- GeoIP lookups use a local database: no IP address is sent to an online service.
- Emails analyzed on the Analyze page leave only an anonymous statistic (time, score, verdict, country).
- With a cloud AI provider, the content of each analyzed email is sent to that provider. The Settings page warns
  about it; a local Ollama keeps everything on your network.
- The AI API key is stored in the database, never shown back, and not reused when the API URL changes.

## Deployment advice

- Use HTTPS (Apache with Let's Encrypt, or a reverse proxy). Without it, passwords travel in clear text.
- Keep phishlens on your LAN or VPN; public exposure is not recommended.
- Set `PHISHLENS_TRUST_PROXY=1` only behind a reverse proxy, never when clients reach phishlens directly.
- Protect the database file and its backups: it holds password hashes, mailbox metadata and the AI API key.

## Known limits

- `phishlens web` uses Python's built-in HTTP server: fine for a homelab or a small team behind a reverse proxy,
  not tuned for heavy public traffic.
- The lockout counts failures per IP address; behind a proxy without `PHISHLENS_TRUST_PROXY=1`, all clients share
  the proxy's address.
- The rule engine trusts the `Authentication-Results` header written by your mail server.
