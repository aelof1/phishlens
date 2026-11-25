# phishlens : interface web, IA et connecteur e-mail

Fonctionne sur un serveur Linux Debian / Ubuntu (Python 3.10+), sur site ou dans un VPC.

```
Boîte mail --IMAP (TLS, lecture seule)--> scan toutes les 5 min --> SQLite --> Apache (mot de passe)
                                              \--> IA (facultative, Ollama en local)
```

## Installation

```bash
sudo apt install git
git clone https://github.com/aelof1/phishlens
cd phishlens
sudo ./deploy/install.sh
```

Puis suis les étapes affichées à la fin.

Si la page par défaut d'Apache s'affiche : `sudo a2dissite 000-default && sudo systemctl reload apache2`.

## Connecter sa boîte mail

Remplis `/etc/phishlens/mail.env`, puis teste :

```bash
sudo systemctl start phishlens-scan
journalctl -u phishlens-scan -n 20
```

- Gmail : `imap.gmail.com`, avec un mot de passe d'application (validation en deux étapes requise).
- Microsoft 365 : non pris en charge, car il exige OAuth.
- Autres serveurs : IMAP sur TLS (port 993).

## IA locale (facultatif)

Installe [Ollama](https://ollama.com/download), puis `ollama pull llama3.1`.
Décommente la ligne `PHISHLENS_AI_URL` dans `/etc/phishlens/ai.env`, puis `sudo systemctl restart apache2`.
Sans carte graphique, les réponses peuvent être lentes.

L'avis de l'IA est indicatif : un e-mail piégé peut tenter de la manipuler. Le score vient uniquement des règles.

## Réseau et sécurité

- Entrant : 443 (et 80 pour Let's Encrypt), limité à ton réseau ou VPN. Pas d'exposition publique conseillée.
- Sortant : 993 vers le serveur mail.
- HTTPS : `sudo apt install certbot python3-certbot-apache && sudo certbot --apache -d ton-domaine.fr`
  (nom de domaine public requis ; sinon utilise le certificat de ton autorité interne).
- Sans HTTPS, le mot de passe circule en clair.
- La base garde sujet, expéditeur, alertes et avis IA, pas le corps des messages.
