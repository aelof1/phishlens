# phishlens on a server: Apache, mailbox connector and AI

Runs on a Debian or Ubuntu server (Python 3.10+), on premises or in a VPC.
To try the web interface on your own computer (Windows, macOS or Linux), you don't need any of this:
run `phishlens web` (see the [main README](../README.md#web-interface)).

## Install

```bash
sudo apt install git
git clone https://github.com/aelof1/phishlens.git
cd phishlens
sudo ./deploy/install.sh
```

Then follow the steps printed at the end. If you see the default Apache page:
`sudo a2dissite 000-default && sudo systemctl reload apache2`.

## Create the admin account

Open the site: it asks for a one-time **setup code**. Read it from the Apache log:

```bash
sudo grep "Setup code" /var/log/apache2/phishlens_error.log
```

Or create the account from the command line instead:

```bash
cd /opt/phishlens && sudo -u phishlens python3 -m phishlens user add admin --role admin
```

The same `user` command resets a lost password (`user reset-password admin`) and lists accounts (`user list`).
Accounts live in `/var/lib/phishlens/phishlens.db`, next to the mailbox results.

Upgrading from 1.1: your existing site file still asks for the Apache password first.
That is fine, or comment out the `Auth*` and `Require valid-user` lines in
`/etc/apache2/sites-available/phishlens.conf` and use the phishlens accounts only.

## Connect a mailbox

Fill in `/etc/phishlens/mail.env`, then test:

```bash
sudo systemctl start phishlens-scan
journalctl -u phishlens-scan -n 20
```

- Gmail: `imap.gmail.com` with an app password (2-Step Verification required).
- Microsoft 365: not supported, because it requires OAuth.
- Other servers: IMAP over TLS (port 993).

Results appear on the **Mailbox** page.

## Countries and world map

Download the GeoIP database once, from **Settings → GeoIP database** or on the server:

```bash
cd /opt/phishlens && sudo -u phishlens python3 -m phishlens geoip update
```

It needs outbound HTTPS to `download.db-ip.com`. DB-IP publishes a new file every month: update it from time to time
(the button in Settings is enough). Emails analyzed before the download have no country.

## AI opinion (optional)

Sign in as an admin, open **Settings**, choose a provider (local Ollama, OpenAI, Claude, Mistral, Groq or any
OpenAI-compatible API), then **Test connection** and **Save**. The mailbox scanner uses the same settings.

For a local model: install [Ollama](https://ollama.com/download), run `ollama pull llama3.1`, and keep the default
URL `http://127.0.0.1:11434/v1`. Without a GPU, answers can be slow.

`/etc/phishlens/ai.env` still works: when `PHISHLENS_AI_URL` is set there, it overrides the Settings page
(restart Apache after a change). More details: [main README](../README.md#ai-opinion-optional).

The AI opinion is advisory: a malicious email can try to manipulate it. The score comes from the rules only.
With a cloud provider, the content of each analyzed email is sent to that provider.

## Network and security

- Inbound: 443 (and 80 for Let's Encrypt), limited to your network or VPN. Public exposure is not recommended.
- Outbound: 993 to the mail server, plus 443 for a remote AI API and the GeoIP download.
- HTTPS: `sudo apt install certbot python3-certbot-apache && sudo certbot --apache -d your-domain.com`
  (needs a public domain name; otherwise use a certificate from your internal authority).
- Without HTTPS, passwords travel in clear text. Over HTTPS, session cookies are marked `Secure` automatically.
- Behind another reverse proxy (Traefik, Caddy, nginx), set `PHISHLENS_TRUST_PROXY=1` so the app trusts
  `X-Forwarded-For` / `X-Forwarded-Proto`. Never set it when clients reach the app directly.
- Passwords are hashed with scrypt. Five failed logins from one address lock it out for 15 minutes.
- The database keeps subject, sender, findings, origin IP, country and AI opinion of mailbox emails, not message bodies.
  Emails analyzed on the Analyze page leave only an anonymous statistic (time, score, verdict, country).

Troubleshooting: `sudo tail /var/log/apache2/phishlens_error.log`
