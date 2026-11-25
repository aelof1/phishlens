# Security policy

## Reporting a vulnerability

Please do not publish exploit details or real emails in a public issue.
Use GitHub's private vulnerability reporting (Security tab) if it is enabled,
otherwise open an issue asking for a private contact, without any detail.

## Design choices

- Emails are treated as hostile input: all output is HTML-escaped and links are never clickable or fetched.
- The mailbox is opened read-only.
- The web interface requires a password; use it over HTTPS only.
- The AI opinion is advisory and never changes the score.

## Known limits

- No built-in rate limiting.
- With a remote AI API, email content is sent to that provider.
