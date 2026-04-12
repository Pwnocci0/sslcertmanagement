#!/usr/bin/env bash
# =============================================================================
# install.sh – SSL Cert Management
# Unterstützt zwei Betriebsmodi:
#   A) Lokaler Nginx + Let's Encrypt (HTTPS direkt auf diesem Server)
#   B) Externer Reverse Proxy        (App lauscht intern, Proxy bringt HTTPS)
#
# Aufruf: sudo ./install.sh
# =============================================================================
set -euo pipefail

# ─── Farben & Logging ────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }
step()    { echo -e "\n${CYAN}${BOLD}▶ $*${NC}"; }
divider() { echo -e "${CYAN}──────────────────────────────────────────────────────────${NC}"; }

# ─── Root-Check ──────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    error "Bitte als root oder mit sudo ausführen: sudo ./install.sh"
fi

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── Banner ──────────────────────────────────────────────────────────────────
clear
echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║          SSL Cert Management – Installer                 ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ─── Vorhandene Installation erkennen ────────────────────────────────────────
EXISTING_INSTALL=false
EXISTING_MODE=""
DEFAULT_INSTALL_DIR="/opt/certmgr"

# Versuche Modus aus bestehender .env zu lesen
for dir in "$DEFAULT_INSTALL_DIR" "$SOURCE_DIR"; do
    if [[ -f "$dir/.env" ]]; then
        EXISTING_INSTALL=true
        EXISTING_MODE=$(grep -E "^APP_INSTALL_MODE=" "$dir/.env" 2>/dev/null \
            | cut -d= -f2 | tr -d '[:space:]' || echo "")
        break
    fi
done

if [[ "$EXISTING_INSTALL" == "true" ]]; then
    echo -e "  ${YELLOW}${BOLD}Vorhandene Installation erkannt.${NC}"
    [[ -n "$EXISTING_MODE" ]] && \
        echo -e "  Bisheriger Modus: ${BOLD}${EXISTING_MODE}${NC}"
    echo -e "  Bestehende Daten (Datenbank, .env, Passwörter) werden nicht überschrieben.\n"
fi

divider

# ─── 1. Domain ───────────────────────────────────────────────────────────────
echo ""
read -r -p "  Bitte Domain für die Anwendung eingeben (z. B. ssl.example.de): " DOMAIN
DOMAIN="${DOMAIN// /}"
[[ -z "$DOMAIN" ]] && error "Domain darf nicht leer sein."

# ─── 1b. Anwendungsname ──────────────────────────────────────────────────────
echo ""
read -r -p "  Anwendungsname [Standard: SSL Cert Management]: " APP_NAME_INPUT
APP_NAME="${APP_NAME_INPUT:-SSL Cert Management}"

# ─── 2. Betriebsmodus ────────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}Betriebsmodus wählen:${NC}"
echo -e "    ${CYAN}1${NC}) Lokaler Nginx + Let's Encrypt"
echo -e "       (Nginx und Certbot werden auf diesem Server installiert)"
echo -e "    ${CYAN}2${NC}) Externer Nginx / Reverse Proxy"
echo -e "       (App lauscht intern; HTTPS übernimmt ein vorgelagerter Proxy)"
echo ""

DEFAULT_MODE=""
if [[ "$EXISTING_MODE" == "A" ]]; then DEFAULT_MODE=" [aktuell: 1]"
elif [[ "$EXISTING_MODE" == "B" ]]; then DEFAULT_MODE=" [aktuell: 2]"
fi

read -r -p "  Modus wählen${DEFAULT_MODE} [1/2]: " MODE_INPUT
MODE_INPUT="${MODE_INPUT// /}"

case "$MODE_INPUT" in
    1|"")
        if [[ -z "$MODE_INPUT" && "$EXISTING_MODE" == "B" ]]; then
            error "Ungültige Eingabe. Bitte 1 oder 2 eingeben."
        fi
        INSTALL_MODE="A"
        ;;
    2)
        INSTALL_MODE="B"
        ;;
    *)
        error "Ungültige Eingabe. Bitte 1 oder 2 eingeben."
        ;;
esac

# ─── 3a. Modus A: E-Mail für Let's Encrypt ───────────────────────────────────
LE_EMAIL=""
if [[ "$INSTALL_MODE" == "A" ]]; then
    echo ""
    read -r -p "  E-Mail-Adresse für Let's Encrypt: " LE_EMAIL
    LE_EMAIL="${LE_EMAIL// /}"
    [[ -z "$LE_EMAIL" ]] && error "E-Mail-Adresse darf nicht leer sein."
    ADMIN_EMAIL="$LE_EMAIL"
fi

# ─── 3b. Modus B: Port und Bind-Adresse ──────────────────────────────────────
APP_PORT=8000
APP_BIND="127.0.0.1"

if [[ "$INSTALL_MODE" == "B" ]]; then
    echo ""
    read -r -p "  App-Port (Standard: 8000): " PORT_INPUT
    PORT_INPUT="${PORT_INPUT// /}"
    if [[ -n "$PORT_INPUT" ]]; then
        if ! [[ "$PORT_INPUT" =~ ^[0-9]+$ ]] || [[ "$PORT_INPUT" -lt 1024 ]] || [[ "$PORT_INPUT" -gt 65535 ]]; then
            error "Ungültiger Port. Bitte eine Zahl zwischen 1024 und 65535 eingeben."
        fi
        APP_PORT="$PORT_INPUT"
    fi

    echo ""
    echo -e "  ${BOLD}Bind-Adresse wählen:${NC}"
    echo -e "    ${CYAN}1${NC}) 127.0.0.1  – nur lokal (sicher, Proxy muss auf gleichem Host sein)"
    echo -e "    ${CYAN}2${NC}) 0.0.0.0    – alle Interfaces (für externen Proxy in anderem Netz)"
    echo ""
    read -r -p "  Bind-Adresse [1/2, Standard: 1]: " BIND_INPUT
    BIND_INPUT="${BIND_INPUT// /}"

    case "${BIND_INPUT:-1}" in
        1) APP_BIND="127.0.0.1" ;;
        2)
            APP_BIND="0.0.0.0"
            echo ""
            echo -e "  ${YELLOW}${BOLD}Sicherheitshinweis:${NC}"
            echo -e "  ${YELLOW}Die App ist auf 0.0.0.0:${APP_PORT} erreichbar.${NC}"
            echo -e "  ${YELLOW}Stellen Sie sicher, dass Firewall-Regeln oder${NC}"
            echo -e "  ${YELLOW}Netzsegmentierung den Zugriff auf vertrauenswürdige${NC}"
            echo -e "  ${YELLOW}Systeme (Ihren Proxy) beschränken!${NC}"
            ;;
        *) error "Ungültige Eingabe. Bitte 1 oder 2 eingeben." ;;
    esac

    ADMIN_EMAIL="admin@${DOMAIN}"
fi

# ─── 4. Admin-E-Mail (nur Modus B, Fallback) ─────────────────────────────────
# Modus A: ADMIN_EMAIL = LE_EMAIL (bereits gesetzt)
# Modus B: ADMIN_EMAIL = admin@DOMAIN (bereits gesetzt)

# ─── 5. Installationspfad ────────────────────────────────────────────────────
echo ""
read -r -p "  Installationspfad [Standard: /opt/certmgr]: " INSTALL_DIR_INPUT
INSTALL_DIR="${INSTALL_DIR_INPUT:-/opt/certmgr}"
INSTALL_DIR="${INSTALL_DIR%/}"

# ─── Zusammenfassung ─────────────────────────────────────────────────────────
echo ""
divider
echo ""
info "Domain        : $DOMAIN"
info "Anwendungsname: $APP_NAME"
if [[ "$INSTALL_MODE" == "A" ]]; then
    info "Modus         : A – Lokaler Nginx + Let's Encrypt"
    info "LE-E-Mail     : $LE_EMAIL"
else
    info "Modus         : B – Externer Reverse Proxy"
    info "Bind-Adresse  : ${APP_BIND}:${APP_PORT}"
fi
info "Install-Pfad  : $INSTALL_DIR"
echo ""
read -r -p "  Installation starten? [J/n]: " CONFIRM
CONFIRM="${CONFIRM:-J}"
if [[ ! "$CONFIRM" =~ ^[JjYy]$ ]]; then
    echo "  Abgebrochen."
    exit 0
fi

# ─── Konstanten ──────────────────────────────────────────────────────────────
APP_USER="certmgr"
SERVICE_NAME="certmgr"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
NGINX_SITE="/etc/nginx/sites-available/${SERVICE_NAME}"
NGINX_ENABLED="/etc/nginx/sites-enabled/${SERVICE_NAME}"
CREDS_FILE="$INSTALL_DIR/data/initial_admin_credentials.txt"
EXTERNAL_CONF_FILE="$INSTALL_DIR/deploy/external-nginx-example.conf"
HTTPS_ENABLED=false

# Forwarded-IPs für uvicorn --forwarded-allow-ips
if [[ "$INSTALL_MODE" == "A" ]]; then
    FORWARDED_IPS="127.0.0.1"
elif [[ "$APP_BIND" == "127.0.0.1" ]]; then
    FORWARDED_IPS="127.0.0.1"
else
    FORWARDED_IPS="*"
fi

# ─── Systempakete installieren ───────────────────────────────────────────────
step "Systempakete installieren"

apt-get update -qq

if [[ "$INSTALL_MODE" == "A" ]]; then
    apt-get install -y --no-install-recommends \
        python3 python3-venv python3-pip \
        libffi-dev libssl-dev gcc \
        nginx certbot python3-certbot-nginx \
        rsync curl >/dev/null
else
    # Modus B: kein Nginx, kein Certbot
    apt-get install -y --no-install-recommends \
        python3 python3-venv python3-pip \
        libffi-dev libssl-dev gcc \
        rsync curl >/dev/null
fi

# Python ermitteln
PYTHON_BIN=""
for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$candidate" &>/dev/null; then
        V=$("$candidate" --version 2>&1 | awk '{print $2}')
        MAJOR=$(echo "$V" | cut -d. -f1)
        MINOR=$(echo "$V" | cut -d. -f2)
        if [[ $MAJOR -ge 3 && $MINOR -ge 10 ]]; then
            PYTHON_BIN="$candidate"
            break
        fi
    fi
done
[[ -z "$PYTHON_BIN" ]] && error "Python 3.10+ nicht gefunden."
info "Python: $($PYTHON_BIN --version)"

# ─── System-User anlegen ─────────────────────────────────────────────────────
step "System-Benutzer '$APP_USER' anlegen"

if id "$APP_USER" &>/dev/null; then
    info "Benutzer '$APP_USER' existiert bereits."
else
    useradd --system --no-create-home --shell /bin/false "$APP_USER"
    info "Benutzer '$APP_USER' angelegt."
fi

# ─── App-Dateien kopieren ────────────────────────────────────────────────────
step "App-Dateien nach $INSTALL_DIR kopieren"

mkdir -p "$INSTALL_DIR"

if [[ "$SOURCE_DIR" != "$INSTALL_DIR" ]]; then
    rsync -a \
        --exclude='.venv' \
        --exclude='data' \
        --exclude='.env' \
        --exclude='.git' \
        --exclude='__pycache__' \
        --exclude='*.pyc' \
        "$SOURCE_DIR/" "$INSTALL_DIR/"
    info "Dateien synchronisiert."
else
    info "Quell- und Zielverzeichnis identisch – kein Kopieren nötig."
fi

# ─── Verzeichnisse & Rechte ──────────────────────────────────────────────────
step "Verzeichnisse anlegen"

mkdir -p "$INSTALL_DIR/data" "$INSTALL_DIR/deploy" "$INSTALL_DIR/static/uploads"
chown root:root "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR"
chown "$APP_USER:$APP_USER" "$INSTALL_DIR/data"
chmod 750 "$INSTALL_DIR/data"
chown "$APP_USER:$APP_USER" "$INSTALL_DIR/static/uploads"
chmod 755 "$INSTALL_DIR/static/uploads"
info "Verzeichnisse angelegt."

# ─── Virtuelle Umgebung ──────────────────────────────────────────────────────
step "Python-Umgebung einrichten"

if [[ ! -d "$INSTALL_DIR/.venv" ]]; then
    "$PYTHON_BIN" -m venv "$INSTALL_DIR/.venv"
    info "Virtuelle Umgebung angelegt."
else
    info "Virtuelle Umgebung bereits vorhanden."
fi

"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip -q
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q
info "Python-Abhängigkeiten installiert."

# ─── Konfiguration erzeugen ──────────────────────────────────────────────────
step "Konfiguration erstellen"

# Admin-Passwort nur generieren wenn noch kein Admin angelegt wurde
CREATE_ADMIN=false
ADMIN_PASS=""

if [[ ! -f "$CREDS_FILE" ]]; then
    CREATE_ADMIN=true
    ADMIN_PASS=$("$INSTALL_DIR/.venv/bin/python" \
        -c "import secrets; print(secrets.token_urlsafe(16))")
fi

if [[ ! -f "$INSTALL_DIR/.env" ]]; then
    APP_SECRET=$("$INSTALL_DIR/.venv/bin/python" \
        -c "import secrets; print(secrets.token_hex(32))")
    CSR_PASSPHRASE=$("$INSTALL_DIR/.venv/bin/python" \
        -c "import secrets; print(secrets.token_hex(32))")

    cat > "$INSTALL_DIR/.env" << ENVEOF
# SSL Cert Management – Konfiguration
# Generiert von install.sh am $(date '+%Y-%m-%d %H:%M:%S')

APP_SECRET_KEY=${APP_SECRET}
APP_HOST=${APP_BIND}
APP_PORT=${APP_PORT}
APP_DEBUG=false
APP_INSTALL_MODE=${INSTALL_MODE}

DATABASE_URL=sqlite:///./data/sslcertmanagement.db

ADMIN_USERNAME=admin
ADMIN_EMAIL=${ADMIN_EMAIL}
ADMIN_PASSWORD=${ADMIN_PASS}

# WICHTIG: Dieser Wert darf nach der ersten Einrichtung NIE geändert werden.
# Verlust bedeutet Verlust aller gespeicherten Private Keys!
CSR_KEY_PASSPHRASE=${CSR_PASSPHRASE}
ENVEOF

    chmod 640 "$INSTALL_DIR/.env"
    chown "root:$APP_USER" "$INSTALL_DIR/.env"
    info ".env erstellt."

elif [[ "$CREATE_ADMIN" == "true" ]]; then
    if grep -q "^ADMIN_PASSWORD=" "$INSTALL_DIR/.env"; then
        sed -i "s|^ADMIN_PASSWORD=.*|ADMIN_PASSWORD=${ADMIN_PASS}|" "$INSTALL_DIR/.env"
    else
        echo "ADMIN_PASSWORD=${ADMIN_PASS}" >> "$INSTALL_DIR/.env"
    fi
    info ".env bereits vorhanden – ADMIN_PASSWORD aktualisiert."
else
    info ".env bereits vorhanden – wird nicht verändert."
fi

# ─── Datenbank initialisieren ────────────────────────────────────────────────
step "Datenbank initialisieren"

cd "$INSTALL_DIR"
sudo -u "$APP_USER" "$INSTALL_DIR/.venv/bin/python" init_db.py
info "Datenbank initialisiert."

# ─── Zugangsdaten speichern ──────────────────────────────────────────────────
if [[ "$INSTALL_MODE" == "A" ]]; then
    CREDS_URL_PLACEHOLDER="https://${DOMAIN}"
else
    CREDS_URL_PLACEHOLDER="http://${DOMAIN} (via externem Proxy)"
fi

if [[ "$CREATE_ADMIN" == "true" ]]; then
    cat > "$CREDS_FILE" << CREDSEOF
SSL Cert Management – Initiale Admin-Zugangsdaten
Erstellt am: $(date '+%Y-%m-%d %H:%M:%S')
Modus: ${INSTALL_MODE}

URL         : ${CREDS_URL_PLACEHOLDER}
Benutzername: admin
Passwort    : ${ADMIN_PASS}

WICHTIG: Passwort nach dem ersten Login in der Anwendung ändern!
CREDSEOF
    chmod 600 "$CREDS_FILE"
    chown "root:root" "$CREDS_FILE"
    info "Zugangsdaten gespeichert in $CREDS_FILE"
fi

# ─── systemd-Service installieren ────────────────────────────────────────────
step "systemd-Service einrichten"

DEPLOY_SERVICE="$INSTALL_DIR/deploy/certmgr.service"

if [[ -f "$DEPLOY_SERVICE" ]]; then
    sed \
        -e "s|%%INSTALL_DIR%%|$INSTALL_DIR|g" \
        -e "s|%%APP_USER%%|$APP_USER|g" \
        -e "s|%%APP_HOST%%|$APP_BIND|g" \
        -e "s|%%APP_PORT%%|$APP_PORT|g" \
        -e "s|%%FORWARDED_IPS%%|$FORWARDED_IPS|g" \
        "$DEPLOY_SERVICE" > "$SERVICE_FILE"
else
    cat > "$SERVICE_FILE" << SVCEOF
[Unit]
Description=SSL Cert Management
After=network.target

[Service]
Type=simple
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env
ExecStart=${INSTALL_DIR}/.venv/bin/uvicorn app.main:app \
    --host ${APP_BIND} --port ${APP_PORT} --workers 1 \
    --proxy-headers --forwarded-allow-ips=${FORWARDED_IPS}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=certmgr
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=${INSTALL_DIR}/data ${INSTALL_DIR}/static/uploads

[Install]
WantedBy=multi-user.target
SVCEOF
fi

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" --quiet
info "Service '$SERVICE_NAME' registriert."

# =============================================================================
# MODUS A: Lokaler Nginx + Let's Encrypt
# =============================================================================
if [[ "$INSTALL_MODE" == "A" ]]; then

    # ─── Nginx konfigurieren ─────────────────────────────────────────────────
    step "Nginx konfigurieren (HTTP)"

    DEPLOY_NGINX="$INSTALL_DIR/deploy/nginx.conf.template"

    if [[ -f "$DEPLOY_NGINX" ]]; then
        sed \
            -e "s|%%DOMAIN%%|$DOMAIN|g" \
            -e "s|%%APP_PORT%%|$APP_PORT|g" \
            -e "s|%%INSTALL_DIR%%|$INSTALL_DIR|g" \
            "$DEPLOY_NGINX" > "$NGINX_SITE"
    else
        cat > "$NGINX_SITE" << NGXEOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    location / {
        proxy_pass         http://127.0.0.1:${APP_PORT};
        proxy_http_version 1.1;
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_set_header   Connection        "";
        proxy_read_timeout 60s;
        client_max_body_size 20M;
    }

    location /static/ {
        alias ${INSTALL_DIR}/static/;
        expires 7d;
    }
}
NGXEOF
    fi

    if [[ -L "/etc/nginx/sites-enabled/default" ]]; then
        rm -f /etc/nginx/sites-enabled/default
    fi
    ln -sf "$NGINX_SITE" "$NGINX_ENABLED"
    nginx -t -q && nginx -s reload
    info "Nginx konfiguriert und neu gestartet."

    # ─── App-Service starten ─────────────────────────────────────────────────
    step "App-Service starten"
    systemctl restart "$SERVICE_NAME"
    sleep 2
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        info "Service '$SERVICE_NAME' läuft."
    else
        warn "Service konnte nicht gestartet werden."
        warn "Logs: journalctl -u $SERVICE_NAME -n 30"
    fi

    # ─── DNS-Überprüfung ─────────────────────────────────────────────────────
    step "DNS-Auflösung prüfen"

    CERTBOT_POSSIBLE=true
    RESOLVED_IP=$(getent hosts "$DOMAIN" 2>/dev/null | awk '{print $1; exit}' || true)

    if [[ -z "$RESOLVED_IP" ]]; then
        warn "Domain '$DOMAIN' konnte nicht aufgelöst werden."
        warn "Stellen Sie sicher, dass der DNS-A-Record auf diesen Server zeigt."
        warn "Let's-Encrypt-Zertifikat wird übersprungen."
        CERTBOT_POSSIBLE=false
    else
        SERVER_IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null \
            || hostname -I | awk '{print $1}')
        if [[ "$RESOLVED_IP" == "$SERVER_IP" ]]; then
            info "DNS korrekt: $DOMAIN → $RESOLVED_IP"
        else
            warn "DNS zeigt auf $RESOLVED_IP, Server-IP ist $SERVER_IP."
            warn "Certbot könnte fehlschlagen – es wird trotzdem versucht."
        fi
    fi

    # ─── Let's Encrypt / Certbot ─────────────────────────────────────────────
    step "HTTPS / Let's Encrypt einrichten"

    if [[ "$CERTBOT_POSSIBLE" == "false" ]]; then
        warn "Certbot übersprungen (DNS-Problem)."
        warn "Nachholen: certbot --nginx -d $DOMAIN --email $LE_EMAIL --agree-tos --non-interactive"
    elif [[ -d "/etc/letsencrypt/live/$DOMAIN" ]]; then
        info "Let's-Encrypt-Zertifikat für $DOMAIN existiert bereits."
        HTTPS_ENABLED=true
    else
        info "Fordere Let's-Encrypt-Zertifikat an ..."
        if certbot --nginx \
            -d "$DOMAIN" \
            --email "$LE_EMAIL" \
            --agree-tos \
            --non-interactive \
            --redirect \
            2>&1; then
            info "Zertifikat erfolgreich ausgestellt."
            HTTPS_ENABLED=true
        else
            warn "Certbot fehlgeschlagen."
            warn "App ist per HTTP erreichbar: http://$DOMAIN"
            warn "Nachholen: certbot --nginx -d $DOMAIN --email $LE_EMAIL --agree-tos --non-interactive"
        fi
    fi

    if [[ "$HTTPS_ENABLED" == "true" ]]; then
        step "Zertifikat-Erneuerung testen"
        if certbot renew --dry-run --quiet 2>&1; then
            info "Automatische Erneuerung funktioniert (dry-run ok)."
        else
            warn "Dry-run fehlgeschlagen. Bitte manuell prüfen."
        fi
    fi

    nginx -t -q && nginx -s reload 2>/dev/null || true

    if [[ "$HTTPS_ENABLED" == "true" ]]; then
        APP_URL="https://${DOMAIN}"
    else
        APP_URL="http://${DOMAIN}"
    fi

    if [[ -f "$CREDS_FILE" ]]; then
        sed -i "s|^URL.*|URL         : ${APP_URL}|" "$CREDS_FILE"
    fi

fi  # Ende Modus A

# =============================================================================
# MODUS B: Externer Reverse Proxy
# =============================================================================
if [[ "$INSTALL_MODE" == "B" ]]; then

    # ─── App-Service starten ─────────────────────────────────────────────────
    step "App-Service starten"
    systemctl restart "$SERVICE_NAME"
    sleep 2
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        info "Service '$SERVICE_NAME' läuft auf ${APP_BIND}:${APP_PORT}."
    else
        warn "Service konnte nicht gestartet werden."
        warn "Logs: journalctl -u $SERVICE_NAME -n 30"
    fi

    # ─── Externe Nginx-Beispielkonfiguration erzeugen ────────────────────────
    step "Externe Nginx-Beispielkonfiguration erzeugen"

    # Backend-Adresse für den Proxy
    if [[ "$APP_BIND" == "0.0.0.0" ]]; then
        SERVER_IP=$(hostname -I | awk '{print $1}')
        BACKEND_ADDR="${SERVER_IP}:${APP_PORT}"
    else
        BACKEND_ADDR="127.0.0.1:${APP_PORT}"
    fi

    DEPLOY_EXT_TEMPLATE="$INSTALL_DIR/deploy/external-nginx-example.conf.template"

    if [[ -f "$DEPLOY_EXT_TEMPLATE" ]]; then
        sed \
            -e "s|%%DOMAIN%%|$DOMAIN|g" \
            -e "s|%%BACKEND_ADDR%%|$BACKEND_ADDR|g" \
            -e "s|%%INSTALL_DIR%%|$INSTALL_DIR|g" \
            "$DEPLOY_EXT_TEMPLATE" > "$EXTERNAL_CONF_FILE"
    else
        cat > "$EXTERNAL_CONF_FILE" << EXTEOF
# Externe Nginx-Beispielkonfiguration – generiert von install.sh

upstream certmgr_backend {
    server ${BACKEND_ADDR};
    keepalive 16;
}

server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name ${DOMAIN};

    ssl_certificate     /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    location / {
        proxy_pass         http://certmgr_backend;
        proxy_http_version 1.1;
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_set_header   X-Forwarded-Host  \$host;
        proxy_set_header   Connection        "";
        proxy_set_header   Upgrade           \$http_upgrade;
        proxy_read_timeout 60s;
        client_max_body_size 20M;
    }
}
EXTEOF
    fi

    chmod 644 "$EXTERNAL_CONF_FILE"
    info "Beispielkonfiguration gespeichert: $EXTERNAL_CONF_FILE"

    APP_URL="http://${DOMAIN} (via externem Proxy)"

fi  # Ende Modus B

# ─── Initiale App-Einstellungen in DB schreiben ───────────────────────────────
step "App-Einstellungen initialisieren"

# Basis-URL ableiten
if [[ "$INSTALL_MODE" == "A" ]]; then
    if [[ "$HTTPS_ENABLED" == "true" ]]; then
        FINAL_BASE_URL="https://${DOMAIN}"
    else
        FINAL_BASE_URL="http://${DOMAIN}"
    fi
else
    FINAL_BASE_URL="https://${DOMAIN}"
fi

cd "$INSTALL_DIR"
sudo -u "$APP_USER" "$INSTALL_DIR/.venv/bin/python" - <<PYEOF
import os, sys
sys.path.insert(0, '$INSTALL_DIR')
os.chdir('$INSTALL_DIR')
from dotenv import load_dotenv
load_dotenv('$INSTALL_DIR/.env')
from app.database import SessionLocal
from app.settings_service import get_settings_service, _invalidate_cache
_invalidate_cache()
db = SessionLocal()
try:
    svc = get_settings_service(db)
    svc.set_many({
        'app.name': '$APP_NAME',
        'app.base_url': '$FINAL_BASE_URL',
    }, user_id=None)
    print('  app.name    = $APP_NAME')
    print('  app.base_url = $FINAL_BASE_URL')
finally:
    db.close()
PYEOF
info "Einstellungen gespeichert."

# =============================================================================
# Abschlussblock
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║           Installation abgeschlossen!                    ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ─── Zugangsdaten ────────────────────────────────────────────────────────────
if [[ "$INSTALL_MODE" == "A" ]]; then
    echo -e "  ${BOLD}URL         :${NC} ${CYAN}${APP_URL}${NC}"
else
    echo -e "  ${BOLD}Interne App :${NC} ${CYAN}http://${APP_BIND}:${APP_PORT}${NC}"
    echo -e "  ${BOLD}Domain      :${NC} ${CYAN}${DOMAIN}${NC} (via externem Proxy)"
fi

echo -e "  ${BOLD}Benutzername:${NC} admin"

if [[ "$CREATE_ADMIN" == "true" ]]; then
    echo -e "  ${BOLD}Passwort    :${NC} ${YELLOW}${ADMIN_PASS}${NC}"
    echo ""
    echo -e "  ${YELLOW}Zugangsdaten gespeichert unter:${NC}"
    echo -e "  ${CREDS_FILE}"
else
    echo -e "  ${BOLD}Passwort    :${NC} (bereits gesetzt – siehe $CREDS_FILE)"
fi

echo ""
echo -e "  ${CYAN}${BOLD}Zwei-Faktor-Authentifizierung (MFA):${NC}"
echo -e "  Beim ersten Login muss MFA eingerichtet werden."
echo -e "  Authenticator-App erforderlich (Aegis, Google Authenticator, Authy, ...)"

# ─── Modus-spezifische Ausgabe ────────────────────────────────────────────────
echo ""
if [[ "$INSTALL_MODE" == "A" ]]; then
    if [[ "$HTTPS_ENABLED" == "true" ]]; then
        echo -e "  ${GREEN}✓ HTTPS ist aktiv (Let's Encrypt).${NC}"
    else
        echo -e "  ${YELLOW}! Nur HTTP aktiv. HTTPS konnte nicht eingerichtet werden.${NC}"
        echo -e "  ${YELLOW}  Nachholen:${NC}"
        echo -e "    certbot --nginx -d $DOMAIN --email $LE_EMAIL --agree-tos --non-interactive"
    fi
else
    echo -e "  ${YELLOW}${BOLD}Modus B – Nächste Schritte auf dem externen Proxy:${NC}"
    echo ""
    echo -e "  1. Beispielkonfiguration auf den Proxy-Server kopieren:"
    echo -e "     ${CYAN}$EXTERNAL_CONF_FILE${NC}"
    echo ""
    echo -e "  2. Auf dem Proxy-Server einbinden:"
    echo -e "     cp <datei> /etc/nginx/sites-available/certmgr"
    echo -e "     ln -s /etc/nginx/sites-available/certmgr /etc/nginx/sites-enabled/"
    echo -e "     certbot --nginx -d $DOMAIN --email <email> --agree-tos --non-interactive"
    echo -e "     systemctl reload nginx"
    echo ""
    if [[ "$APP_BIND" == "127.0.0.1" ]]; then
        echo -e "  ${YELLOW}Hinweis: App lauscht auf 127.0.0.1 – Proxy muss auf diesem Host laufen.${NC}"
    else
        SERVER_IP=$(hostname -I | awk '{print $1}')
        echo -e "  ${YELLOW}App erreichbar unter: ${SERVER_IP}:${APP_PORT}${NC}"
        echo -e "  ${YELLOW}Firewall-Regeln sicherstellen!${NC}"
    fi
    echo ""
    echo -e "  HTTPS und Zertifikatsmanagement werden vollständig"
    echo -e "  auf dem externen Proxy erledigt."
fi

echo ""
echo -e "  ${BOLD}Hilfreiche Befehle:${NC}"
echo -e "  systemctl status  $SERVICE_NAME"
echo -e "  journalctl -u     $SERVICE_NAME -f"
echo -e "  systemctl restart $SERVICE_NAME"
echo ""
divider
echo -e "  ${YELLOW}${BOLD}Wichtig: Passwort nach dem ersten Login ändern!${NC}"
divider
echo ""
