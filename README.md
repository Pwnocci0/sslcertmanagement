# SSL Cert Management

Interne Webanwendung zur Verwaltung von SSL-Zertifikaten für einen MSP.

**Stack:** Python · FastAPI · Jinja2 · SQLite · systemd · Nginx (optional)

---

## Installation (Debian / Ubuntu / LXC auf Proxmox)

### Voraussetzungen

- Debian 11+ / Ubuntu 22.04+
- Root-Zugang (sudo)
- Eine Domain (DNS-A-Record auf den Server zeigt, wenn Let's Encrypt genutzt wird)
- Internetverbindung (für Pakete)

### Schritt-für-Schritt

**1. Projekt auf den Server kopieren**

```bash
git clone <repo-url> /tmp/certmgr-src
cd /tmp/certmgr-src
# Alternativ: scp/SFTP, dann ins Verzeichnis wechseln.
```

**2. Installer ausführen**

```bash
sudo ./install.sh
```

Der Installer fragt interaktiv ab:

| Frage | Beispiel | Standard |
|---|---|---|
| Domain | `ssl.example.de` | – (Pflicht) |
| **Modus** | `1` oder `2` | – (Pflicht) |
| E-Mail (nur Modus 1) | `admin@example.de` | – (Pflicht) |
| App-Port (nur Modus 2) | `8000` | `8000` |
| Bind-Adresse (nur Modus 2) | `1` = 127.0.0.1 / `2` = 0.0.0.0 | `1` |
| Installationspfad | `/opt/certmgr` | `/opt/certmgr` |

---

## Modus 1: Lokaler Nginx + Let's Encrypt

Für Server, auf denen Nginx direkt installiert wird.

```
./install.sh
→ Domain eingeben
→ Modus 1 wählen
→ E-Mail eingeben
→ kurze Wartezeit
→ https://ssl.example.de + Login-Daten
```

Der Installer:
- installiert Nginx und Certbot lokal
- konfiguriert eine Nginx-Site als Reverse Proxy
- holt ein Let's Encrypt-Zertifikat
- aktiviert automatische Erneuerung
- testet `certbot renew --dry-run`

Wenn DNS noch nicht auf den Server zeigt: Certbot wird übersprungen, die App ist per HTTP erreichbar. Let's Encrypt kann jederzeit nachgeholt werden:

```bash
certbot --nginx -d ssl.example.de --email admin@example.de --agree-tos --non-interactive
```

---

## Modus 2: Externer Reverse Proxy

Für Umgebungen mit einem zentralen Nginx oder Traefik auf einem anderen Server (z. B. in einem separaten LXC-Container oder VM).

```
./install.sh
→ Domain eingeben
→ Modus 2 wählen
→ App-Port + Bind-Adresse eingeben
→ kurze Wartezeit
→ interne Adresse + Login-Daten + Nginx-Beispielconfig
```

Der Installer:
- installiert **kein** lokales Nginx / Certbot
- startet die App auf der konfigurierten internen Adresse (`127.0.0.1:8000` oder `0.0.0.0:8000`)
- erzeugt eine fertige Nginx-Beispielkonfiguration und speichert sie unter:
  `/opt/certmgr/deploy/external-nginx-example.conf`

### Externe Nginx-Config einbinden

```bash
# Auf dem externen Nginx-Server:
scp app-server:/opt/certmgr/deploy/external-nginx-example.conf \
    /etc/nginx/sites-available/certmgr

# SSL-Zertifikat-Pfade in der Config anpassen, dann:
ln -s /etc/nginx/sites-available/certmgr /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx

# Optional: Let's Encrypt auf dem Proxy-Server:
certbot --nginx -d ssl.example.de --email admin@example.de --agree-tos --non-interactive
```

### Bind-Adresse: 127.0.0.1 vs. 0.0.0.0

| Option | Bedeutung |
|---|---|
| `127.0.0.1` | App nur lokal erreichbar – Proxy muss auf demselben Host laufen |
| `0.0.0.0` | App auf allen Interfaces – Proxy kann auf anderem Host sein |

Bei `0.0.0.0`: Firewall-Regeln oder Netzsegmentierung sicherstellen! Port darf nur für den Proxy-Server erreichbar sein.

### Proxy-Header

Die App verarbeitet die folgenden Proxy-Header korrekt:
- `X-Real-IP` – echte Client-IP
- `X-Forwarded-For` – IP-Kette
- `X-Forwarded-Proto` – http/https (für korrekte Umleitungen)
- `X-Forwarded-Host` – Original-Host

uvicorn wird mit `--proxy-headers --forwarded-allow-ips` gestartet und vertraut nur Headern vom konfigurierten Proxy.

---

Die Zugangsdaten werden außerdem gespeichert unter:
`/opt/certmgr/data/initial_admin_credentials.txt` (Rechte: 600)

---

## Was der Installer automatisch erledigt

| Schritt | Modus 1 | Modus 2 |
|---|---|---|
| Systempakete | Python 3, Nginx, Certbot, rsync | Python 3, rsync |
| System-Benutzer `certmgr` | ✓ | ✓ |
| Python-Umgebung `.venv` | ✓ | ✓ |
| `.env` mit Secrets | ✓ | ✓ |
| Datenbank + Admin-User | ✓ | ✓ |
| systemd-Service | ✓ | ✓ |
| Lokaler Nginx | ✓ | – |
| Let's Encrypt | ✓ | – |
| Externe Nginx-Beispielconfig | – | ✓ |

### Idempotenz

`install.sh` kann mehrfach ausgeführt werden:

- Vorhandene `.env` wird **nicht** überschrieben
- Bestehendes Admin-Konto wird **nicht** neu angelegt
- Vorhandenes Let's-Encrypt-Zertifikat wird **nicht** neu angefordert
- Erkannte bestehende Installation wird beim Start angezeigt

---

## Verzeichnisstruktur (nach Installation)

```
/opt/certmgr/
├── app/                        # Anwendungscode (FastAPI)
│   ├── main.py
│   ├── models.py
│   ├── auth.py
│   ├── crypto.py
│   ├── audit.py
│   ├── database.py
│   └── routers/
│       ├── auth.py
│       ├── dashboard.py
│       ├── customers.py
│       ├── domains.py
│       ├── csrs.py
│       └── certificates.py
├── static/                     # CSS, JS
├── deploy/                     # Service- und Nginx-Templates
│   ├── certmgr.service
│   └── nginx.conf.template
├── data/                       # Datenbank + Credentials (außerhalb Webroot)
│   ├── sslcertmanagement.db
│   └── initial_admin_credentials.txt
├── .venv/                      # Python-Umgebung
├── .env                        # Konfiguration (Rechte: 640)
├── init_db.py
├── requirements.txt
└── install.sh
```

---

## Konfiguration (.env)

| Variable | Standard | Beschreibung |
|---|---|---|
| `APP_SECRET_KEY` | *(auto-generiert)* | Zufälliger Secret für Session-Cookies |
| `APP_HOST` | `127.0.0.1` | Bind-Adresse (nur lokal, Nginx als Proxy) |
| `APP_PORT` | `8000` | Port |
| `DATABASE_URL` | `sqlite:///./data/sslcertmanagement.db` | Datenbankpfad |
| `ADMIN_USERNAME` | `admin` | Benutzername des ersten Admins |
| `ADMIN_EMAIL` | *(E-Mail aus Installer)* | E-Mail des ersten Admins |
| `ADMIN_PASSWORD` | *(auto-generiert)* | Nur beim ersten `init_db.py`-Aufruf verwendet |
| `CSR_KEY_PASSPHRASE` | *(auto-generiert)* | **Nicht ändern nach erster Einrichtung!** |

---

## Betrieb

### Dienst-Verwaltung

```bash
# Status
systemctl status certmgr

# Logs (live)
journalctl -u certmgr -f

# Neustart
systemctl restart certmgr

# Stoppen
systemctl stop certmgr
```

### HTTPS-Zertifikat erneuern

Certbot erneuert Zertifikate automatisch via systemd-Timer. Manuell:

```bash
certbot renew
systemctl reload nginx
```

### Update einspielen

```bash
cd /tmp/certmgr-src
git pull
sudo ./install.sh
# Gibt dieselbe Domain/E-Mail ein – Installer erkennt bestehende Installation.
```

---

## Entwicklung (lokal)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# .env bearbeiten (APP_SECRET_KEY, CSR_KEY_PASSPHRASE setzen)

python init_db.py
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

---

## Zwei-Faktor-Authentifizierung (MFA)

Die Anwendung verwendet **TOTP-basierte MFA** (RFC 6238), kompatibel mit allen gängigen Authenticator-Apps.

### Erster Login

1. URL aufrufen und mit Benutzername + Passwort anmelden
2. Sie werden automatisch zur MFA-Einrichtungsseite weitergeleitet
3. QR-Code mit Ihrer Authenticator-App scannen (oder Secret manuell eingeben)
4. Einmal-Code aus der App eingeben → MFA ist eingerichtet
5. **Recovery Codes sicher speichern** (werden nur einmalig angezeigt!)

Ohne abgeschlossene MFA-Einrichtung sind alle App-Seiten gesperrt.

### Kompatible Authenticator-Apps

| App | Android | iOS |
|---|---|---|
| Aegis | ✓ | – |
| Google Authenticator | ✓ | ✓ |
| Microsoft Authenticator | ✓ | ✓ |
| Authy | ✓ | ✓ |

### Login-Ablauf (täglich)

```
Benutzername + Passwort → TOTP-Code aus App → Zugang
```

### Recovery Codes

- 8 Codes werden bei der MFA-Einrichtung einmalig erzeugt
- Jeder Code ist einmal verwendbar (ersetzt den TOTP-Code)
- Verwendete Codes werden automatisch ungültig
- Download als .txt-Datei direkt auf der Einrichtungsseite möglich
- **Empfehlung:** In einem Passwort-Manager oder ausgedruckt im Safe aufbewahren

### Gerät verloren / Authenticator-App gelöscht

1. Einen **Recovery Code** auf der MFA-Verify-Seite eingeben (Button „Recovery Code verwenden")
2. Nach erfolgreichem Login in den Account-Einstellungen MFA zurücksetzen und neu einrichten

Wenn alle Recovery Codes verbraucht sind und kein Gerät verfügbar ist, muss ein Administrator
die MFA des betroffenen Nutzers in der Datenbank direkt zurücksetzen:

```bash
cd /opt/certmgr
source .venv/bin/activate
python3 -c "
from app.database import SessionLocal
from app.models import User
db = SessionLocal()
u = db.query(User).filter(User.username == 'admin').first()
u.mfa_secret_encrypted = None
u.mfa_setup_completed = False
u.recovery_codes_json = None
db.commit()
print('MFA zurückgesetzt.')
"
```

Beim nächsten Login wird die MFA-Einrichtung erneut gestartet.

---

## Sicherheitshinweise

- `.env` hat Rechte **640** (root:certmgr) – nicht im Webroot
- `data/` hat Rechte **750** – nur für den `certmgr`-Benutzer
- `initial_admin_credentials.txt` hat Rechte **600** – nur für root
- Private Keys werden AES-verschlüsselt mit `CSR_KEY_PASSPHRASE` in der DB gespeichert
- Der systemd-Service läuft mit `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem`
- Passwörter werden nicht in der Shell-History gespeichert (kein `-e` Flag bei `read`)
- TOTP-Secrets werden Fernet-verschlüsselt (AES-128-CBC, abgeleitet aus `APP_SECRET_KEY`) gespeichert
- Recovery Codes werden als HMAC-SHA256-Hashes gespeichert – nie im Klartext in der DB
- TOTP-Secrets und Recovery-Code-Klartexte werden nicht geloggt

---

## Datenmodell

| Tabelle | Wichtige Felder |
|---|---|
| `users` | id, username, email, hashed_password, is_active, is_admin |
| `customers` | id, name, contact_name, contact_email, notes, is_archived |
| `domains` | id, customer_id, fqdn, notes |
| `certificates` | id, customer_id, domain_id, csr_request_id, common_name, san, issuer, serial_number, valid_from, valid_until, status, cert_pem, chain_pem |
| `csr_requests` | id, common_name, sans, key_size, csr_pem, private_key_encrypted, created_by |
| `audit_logs` | id, user_id, action, entity_type, entity_id, details, ip_address |

**Zertifikat-Status:** `pending` · `active` · `expiring_soon` · `expired` · `revoked`
