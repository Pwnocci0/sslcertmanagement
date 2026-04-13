# SSL Cert Management

Interne Webanwendung zur Verwaltung von SSL-Zertifikaten für einen MSP.

**Stack:** Python · FastAPI · Jinja2 · SQLite · systemd · Nginx (optional)

**Repository:** [github.com/Pwnocci0/sslcertmanagement](https://github.com/Pwnocci0/sslcertmanagement)

---

## Inhaltsverzeichnis

1. [Installation](#installation-debian--ubuntu--lxc-auf-proxmox)
   - [Modus A: Lokaler Nginx + Let's Encrypt](#modus-a-lokaler-nginx--lets-encrypt)
   - [Modus B: Externer Reverse Proxy](#modus-b-externer-reverse-proxy)
   - [Was der Installer erledigt](#was-der-installer-automatisch-erledigt)
   - [Verzeichnisstruktur](#verzeichnisstruktur-nach-installation)
2. [Konfiguration (.env)](#konfiguration-env)
3. [Betrieb](#betrieb)
4. [Entwicklung (lokal)](#entwicklung-lokal)
5. [Zwei-Faktor-Authentifizierung (MFA)](#zwei-faktor-authentifizierung-mfa)
6. [Sicherheitshinweise](#sicherheitshinweise)
7. [Datenmodell](#datenmodell)
8. [Menüstruktur](#menüstruktur)
9. [Einstellungen](#einstellungen)
10. [Integrationen](#integrationen)
11. [Zertifikats-Workflow](#zertifikats-workflow)
12. [E-Mail-Benachrichtigungen](#e-mail-benachrichtigungen)

---

## Installation (Debian / Ubuntu / LXC auf Proxmox)

### Voraussetzungen

- Debian 11+ / Ubuntu 22.04+
- Root-Zugang (sudo)
- Eine Domain (DNS-A-Record auf den Server zeigt, wenn Let's Encrypt genutzt wird)
- Internetverbindung (für Pakete)

### System vorbereiten

Vor der Installation sicherstellen, dass das System aktuell ist und die benötigten Pakete installiert sind:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-venv python3-pip git
```

### Schritt-für-Schritt

**1. Projekt auf den Server kopieren**

```bash
git clone https://github.com/Pwnocci0/sslcertmanagement /tmp/certmgr-src
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
| Anwendungsname | `Mein SSL Manager` | `SSL Cert Management` |
| **Modus** | `A` oder `B` | – (Pflicht) |
| E-Mail (nur Modus A) | `admin@example.de` | – (Pflicht) |
| App-Port (nur Modus B) | `8000` | `8000` |
| Bind-Adresse (nur Modus B) | `1` = 127.0.0.1 / `2` = 0.0.0.0 | `1` |
| Installationspfad | `/opt/certmgr` | `/opt/certmgr` |

---

## Modus A: Lokaler Nginx + Let's Encrypt

Für Server, auf denen Nginx direkt installiert wird.

```
./install.sh
→ Domain eingeben
→ Modus A wählen
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

## Modus B: Externer Reverse Proxy

Für Umgebungen mit einem zentralen Nginx oder Traefik auf einem anderen Server (z. B. in einem separaten LXC-Container oder VM).

```
./install.sh
→ Domain eingeben
→ Modus B wählen
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

| Schritt | Modus A | Modus B |
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

---

## Menüstruktur

### Operative Navigation (alle Benutzer)
| Menüpunkt | Beschreibung |
|---|---|
| Dashboard | Übersicht, ablaufende Zertifikate, offene Aufgaben |
| Kunden | Kundenstammdaten, Domains und Zertifikate je Kunde |
| Domains | Alle verwalteten Domains |
| Zertifikate | Alle Zertifikate (gefiltert nach Zugriff bei Technikern) |
| Aufgaben | Offene Handlungsbedarfe |

### Einstellungen (nur Admins)
Erreichbar über den **Einstellungen**-Link in der Navigationsleiste.

| Bereich | URL | Beschreibung |
|---|---|---|
| Allgemein & Sicherheit | `/settings` | App-Name, Base-URL, MFA-Pflicht, Session-Timeout, Passwortregeln |
| Benutzer | `/admin/users` | Benutzer anlegen, bearbeiten, deaktivieren, MFA zurücksetzen |
| Kundengruppen | `/customer-groups` | Techniker-Zuordnung, Benachrichtigungsregeln |
| Mail / SMTP | `/mail-settings` | SMTP-Relay konfigurieren, Test-Mail senden |
| Mailtemplates | `/mailtemplates` | E-Mail-Vorlagen mit `{{Platzhalter}}`-Syntax |
| Versandhistorie | `/notifications` | Alle gesendeten Benachrichtigungen |
| Integrationen | `/settings/integrations` | TheSSLStore ein-/ausschalten |
| CSR-Vorlagen | `/csrtemplates` | Vorlagen für CSR-Erstellung |
| System-Status | `/admin` | DB, Scheduler, Zertifikats-Statistiken |
| Anwendungslogs | `/admin/logs` | Gefilterte Log-Ausgabe |

---

## Einstellungen

Alle Einstellungen werden in der Tabelle `app_settings` (Key-Value) gespeichert.
Sensible Werte (API-Tokens, SMTP-Passwort) werden Fernet-verschlüsselt abgelegt.

Kategorien: `general` · `security` · `network` · `certificates` · `thesslstore` · `smtp`

---

## Integrationen

### TheSSLStore
Aktiviert unter **Einstellungen → Integrationen**.

- **Deaktiviert (Standard):** Keine API-Aufrufe, keine UI-Elemente für TheSSLStore.
- **Aktiviert:** Produkt-Sync, Bestellverwaltung, Sandbox/Live-Toggle.

Technisch: Jede TheSSLStore-Route prüft `is_integration_enabled("thesslstore", db)` serverseitig und leitet bei Deaktivierung zu `/settings/integrations` weiter.

---

## Zertifikats-Workflow

### Aus dem Kontext erstellen
Beim Anlegen eines Zertifikats werden Kunde und Domain vorausgewählt, wenn man aus dem Kontext kommt:

| Einstiegspunkt | Vorauswahl |
|---|---|
| Kunden-Detailseite → „+" | Kunde vorausgewählt |
| Domain-Detailseite → „Zertifikat" | Kunde + Domain vorausgewählt |
| `/certificates/new` direkt | Keine Vorauswahl |

URL-Parameter: `/certificates/new?customer_id=5&domain_id=12`

Das Backend validiert den Zugriff auf Kunde/Domain vor der Vorauswahl.

---

## E-Mail-Benachrichtigungen

Konfiguration unter **Einstellungen → Mail / SMTP**.

**SMTP2GO** (empfohlen): Host `mail.smtp2go.com`, Port `587`, STARTTLS.

### Mailtemplates
Verwaltet unter **Einstellungen → Mailtemplates**.

Verfügbare Platzhalter: `{{customer_name}}` · `{{certificate_common_name}}` · `{{days_remaining}}` · `{{certificate_valid_to}}` · `{{severity}}` · `{{portal_url}}` u.a.

Standard-Templates (automatisch angelegt):
- `certificate_expiring_30_days` – Ablauf in 30 Tagen (Warnung)
- `certificate_expiring_14_days` – Ablauf in 14 Tagen (Kritisch)
- `certificate_expired` – Abgelaufen
- `certificate_invalid` – Ungültig
- `certificate_missing_chain` – Fehlende Intermediate-Chain

### Automatische Prüfung
Der Scheduler prüft stündlich alle Kundengruppen mit aktivierten Benachrichtigungen.
Duplikatschutz: Gleiche Benachrichtigung wird nicht mehrfach innerhalb eines konfigurierten Zeitfensters verschickt.

---

## MFA-Reset durch Admin

Admins können die MFA eines Benutzers zurücksetzen unter **Einstellungen → Benutzer**.

**Auswirkung:**
- TOTP-Secret wird gelöscht
- `mfa_setup_completed` wird auf `false` gesetzt
- Recovery Codes werden gelöscht
- Der Benutzer muss beim nächsten Login MFA neu einrichten (kann sich ohne abgeschlossene MFA-Einrichtung nicht anmelden)

Die Aktion wird im Audit-Log erfasst (wer, wen, wann).
