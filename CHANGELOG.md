# Changelog

## 1.2.0

- New web interface: drag and drop, analysis without page reload, score gauge, light and dark themes, phone layout
- English and French interface (browser language, switch in the top bar)
- User accounts: admin created on first start with a one-time setup code, admin and viewer roles,
  scrypt password hashing, CSRF protection, login lockout after 5 failures
- `phishlens web`: run the web interface on Windows, macOS or Linux without Apache
- `phishlens user add | reset-password | list | delete`
- AI opinion in the interface language; `PHISHLENS_LANG` for the scanner
- Database in a per-OS data folder by default (`PHISHLENS_DB` still wins)
- Apache: the `htpasswd` password is now optional (the installer no longer creates it)
- `/healthz` endpoint for monitoring
- README: Windows PATH and offline install troubleshooting, AI setup on every OS

## 1.1.0

- Web interface (WSGI, responsive)
- Read-only IMAP connector with SQLite results
- Optional AI opinion (OpenAI-compatible API)
- Installer for Debian and Ubuntu

## 1.0.0

- Command line analyzer
