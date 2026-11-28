#!/usr/bin/env bash
# Install phishlens (web + mailbox connector) on Debian / Ubuntu.
# Usage, from the repository folder: sudo ./deploy/install.sh
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo." >&2; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"

apt-get update
apt-get install -y apache2 libapache2-mod-wsgi-py3 python3
python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' || { echo "Python 3.10+ required." >&2; exit 1; }

id phishlens >/dev/null 2>&1 || useradd --system --home-dir /var/lib/phishlens --shell /usr/sbin/nologin phishlens
install -d -m 755 /opt/phishlens
cp -r "$SRC/phishlens" "$SRC/web" /opt/phishlens/
chmod -R a+rX,go-w /opt/phishlens
install -d -o phishlens -g phishlens -m 700 /var/lib/phishlens
install -d -o root -g phishlens -m 750 /etc/phishlens
[ -f /etc/phishlens/ai.env ] || install -o root -g phishlens -m 640 "$SRC/deploy/ai.env.example" /etc/phishlens/ai.env
[ -f /etc/phishlens/mail.env ] || install -o root -g root -m 600 "$SRC/deploy/mail.env.example" /etc/phishlens/mail.env

install -m 644 "$SRC"/deploy/phishlens-scan.{service,timer} /etc/systemd/system/
[ -f /etc/apache2/sites-available/phishlens.conf ] || install -m 644 "$SRC/web/phishlens.conf" /etc/apache2/sites-available/
a2ensite phishlens
apache2ctl configtest
systemctl daemon-reload
systemctl restart apache2

cat <<'MSG'

Installed. Next:
  1. sudo nano /etc/apache2/sites-available/phishlens.conf   (ServerName)
     sudo systemctl reload apache2
  2. Open the site and create the admin account. The setup code is in the log:
     sudo grep "Setup code" /var/log/apache2/phishlens_error.log
     (or: cd /opt/phishlens && sudo -u phishlens python3 -m phishlens user add admin --role admin)
  3. sudo nano /etc/phishlens/mail.env
  4. sudo nano /etc/phishlens/ai.env        (optional)
  5. sudo systemctl enable --now phishlens-scan.timer
  Logs: journalctl -u phishlens-scan
MSG
