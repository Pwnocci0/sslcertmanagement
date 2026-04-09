"""
Zentrale Settings-Verwaltung.

Metadaten (Typ, Kategorie, Label, Beschreibung, Default) sind im Code definiert.
Werte werden in der DB-Tabelle ``app_settings`` gespeichert.
Sensible Werte (is_sensitive=True) werden Fernet-verschlüsselt abgelegt.

Modul-globaler Cache wird bei jeder Änderung invalidiert und beim nächsten
Zugriff automatisch neu geladen.
"""
from __future__ import annotations

import base64
import hashlib
import os
from typing import Any, NamedTuple

from cryptography.fernet import Fernet
from sqlalchemy.orm import Session

from . import models


# ── Verschlüsselung ───────────────────────────────────────────────────────────

def _fernet() -> Fernet:
    key_material = os.getenv(
        "APP_SECRET_KEY", "dev-secret-key-CHANGE-IN-PRODUCTION"
    ).encode()
    raw = hashlib.sha256(key_material).digest()
    return Fernet(base64.urlsafe_b64encode(raw))


def _encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def _decrypt(ciphertext: str) -> str:
    return _fernet().decrypt(ciphertext.encode()).decode()


# ── Setting-Definition ────────────────────────────────────────────────────────

class SettingDef(NamedTuple):
    default: str          # immer als String gespeichert
    value_type: str       # string | int | bool | json
    category: str         # general | security | network | certificates | thesslstore
    is_sensitive: bool    # True → Fernet-verschlüsselt in DB
    label: str
    description: str


# ── Alle bekannten Settings mit Defaults ──────────────────────────────────────

CATEGORY_LABELS = {
    "general":      "Allgemein",
    "security":     "Sicherheit",
    "network":      "Netzwerk",
    "certificates": "Zertifikate",
    "thesslstore":  "TheSSLStore API",
    "smtp":         "E-Mail / SMTP",
    "maintenance":  "Wartung",
}

# Sichtbare Kategorien für Techniker (read-only; Admins sehen alle)
TECHNICIAN_VISIBLE_CATEGORIES: set[str] = set()  # Techniker sehen keine Settings-Seite

DEFINITIONS: dict[str, SettingDef] = {
    # ── Allgemein ─────────────────────────────────────────────────────────────
    "app.name": SettingDef(
        default="SSL Cert Management",
        value_type="string", category="general", is_sensitive=False,
        label="Anwendungsname",
        description="Wird in der Oberfläche und in MFA-QR-Codes verwendet.",
    ),
    "app.timezone": SettingDef(
        default="Europe/Berlin",
        value_type="string", category="general", is_sensitive=False,
        label="Zeitzone",
        description="IANA-Zeitzone für alle Zeitanzeigen (z. B. Europe/Berlin, UTC, America/New_York).",
    ),
    "app.favicon_path": SettingDef(
        default="",
        value_type="string", category="general", is_sensitive=False,
        label="Favicon-Pfad",
        description="Dateiname des Favicons unter /static/uploads/ (z. B. favicon.png).",
    ),
    "app.logo_path": SettingDef(
        default="",
        value_type="string", category="general", is_sensitive=False,
        label="Logo-Pfad",
        description="Dateiname des Logos unter /static/uploads/ (z. B. logo.png). Empfohlen: ca. 32 px Höhe, max. 200 px Breite, transparentes PNG.",
    ),
    "app.base_url": SettingDef(
        default="",
        value_type="string", category="general", is_sensitive=False,
        label="Basis-URL",
        description="Öffentliche URL der Anwendung (z. B. https://ssl.example.de).",
    ),
    "app.logging_level": SettingDef(
        default="INFO",
        value_type="string", category="general", is_sensitive=False,
        label="Log-Level",
        description="DEBUG, INFO, WARNING oder ERROR.",
    ),

    # ── Sicherheit ────────────────────────────────────────────────────────────
    "security.mfa_required": SettingDef(
        default="true",
        value_type="bool", category="security", is_sensitive=False,
        label="MFA verpflichtend",
        description="Alle Benutzer müssen MFA einrichten, bevor sie die App nutzen können.",
    ),
    "security.session_timeout_hours": SettingDef(
        default="8",
        value_type="int", category="security", is_sensitive=False,
        label="Session-Timeout (Stunden)",
        description="Nach wie vielen Stunden wird die Session automatisch beendet.",
    ),
    "security.max_login_attempts": SettingDef(
        default="0",
        value_type="int", category="security", is_sensitive=False,
        label="Max. Login-Versuche (0 = deaktiviert)",
        description="Anzahl fehlgeschlagener Versuche vor temporärer Account-Sperre.",
    ),
    "security.min_password_length": SettingDef(
        default="12",
        value_type="int", category="security", is_sensitive=False,
        label="Mindest-Passwortlänge",
        description="",
    ),
    "security.allow_recovery_regen": SettingDef(
        default="false",
        value_type="bool", category="security", is_sensitive=False,
        label="Recovery Codes regenerieren erlauben",
        description="Erlaubt Benutzern, ihre MFA-Recovery Codes selbst neu zu erzeugen.",
    ),

    # ── Netzwerk ──────────────────────────────────────────────────────────────
    "network.trust_proxy": SettingDef(
        default="true",
        value_type="bool", category="network", is_sensitive=False,
        label="Reverse Proxy vertrauen",
        description="Aktiviert Auswertung von X-Forwarded-For, X-Forwarded-Proto etc.",
    ),
    "network.external_url": SettingDef(
        default="",
        value_type="string", category="network", is_sensitive=False,
        label="Externe URL",
        description="Für Links und Weiterleitungen, falls von Basis-URL abweichend.",
    ),

    # ── Zertifikate ───────────────────────────────────────────────────────────
    "certs.default_key_size": SettingDef(
        default="2048",
        value_type="int", category="certificates", is_sensitive=False,
        label="Standard-Schlüssellänge (Bit)",
        description="2048 oder 4096.",
    ),
    "certs.default_validity_days": SettingDef(
        default="365",
        value_type="int", category="certificates", is_sensitive=False,
        label="Standard-Laufzeit (Tage)",
        description="",
    ),
    "certs.default_country": SettingDef(
        default="DE",
        value_type="string", category="certificates", is_sensitive=False,
        label="Standard-Land (CSR, ISO 3166-1 Alpha-2)",
        description="z. B. DE, US, AT, CH.",
    ),
    "certs.default_state": SettingDef(
        default="",
        value_type="string", category="certificates", is_sensitive=False,
        label="Standard-Bundesland (CSR)",
        description="",
    ),
    "certs.default_locality": SettingDef(
        default="",
        value_type="string", category="certificates", is_sensitive=False,
        label="Standard-Ort (CSR)",
        description="",
    ),
    "certs.default_org": SettingDef(
        default="",
        value_type="string", category="certificates", is_sensitive=False,
        label="Standard-Organisation (CSR)",
        description="",
    ),
    "certs.default_ou": SettingDef(
        default="",
        value_type="string", category="certificates", is_sensitive=False,
        label="Standard-Organisationseinheit (CSR)",
        description="",
    ),

    # ── TheSSLStore ───────────────────────────────────────────────────────────
    "thesslstore.enabled": SettingDef(
        default="false",
        value_type="bool", category="thesslstore", is_sensitive=False,
        label="TheSSLStore-Integration aktiviert",
        description="Aktiviert die TheSSLStore-Integration. Bei Deaktivierung sind keine API-Aufrufe möglich.",
    ),
    "thesslstore.sandbox": SettingDef(
        default="true",
        value_type="bool", category="thesslstore", is_sensitive=False,
        label="Sandbox-Modus",
        description="Wenn aktiv, werden alle API-Anfragen an die Sandbox gesendet.",
    ),
    "thesslstore.api_url_live": SettingDef(
        default="https://api.thesslstore.com/rest/",
        value_type="string", category="thesslstore", is_sensitive=False,
        label="API Base URL (Live)",
        description="Offizielle Live-URL laut TheSSLStore API-Dokumentation.",
    ),
    "thesslstore.api_url_sandbox": SettingDef(
        default="https://sandbox-wbapi.thesslstore.com/rest/",
        value_type="string", category="thesslstore", is_sensitive=False,
        label="API Base URL (Sandbox)",
        description="Offizielle Sandbox-URL laut TheSSLStore API-Dokumentation.",
    ),
    "thesslstore.partner_code_live": SettingDef(
        default="",
        value_type="string", category="thesslstore", is_sensitive=False,
        label="Partner Code (Live)",
        description="Partner Code aus dem TheSSLStore-Portal für den Live-Modus.",
    ),
    "thesslstore.auth_token_live": SettingDef(
        default="",
        value_type="string", category="thesslstore", is_sensitive=True,
        label="Auth Token (Live)",
        description="API-Token aus dem TheSSLStore-Portal für den Live-Modus. Wird verschlüsselt gespeichert.",
    ),
    "thesslstore.partner_code_sandbox": SettingDef(
        default="",
        value_type="string", category="thesslstore", is_sensitive=False,
        label="Partner Code (Sandbox)",
        description="Partner Code aus dem TheSSLStore-Portal für den Sandbox-Modus.",
    ),
    "thesslstore.auth_token_sandbox": SettingDef(
        default="",
        value_type="string", category="thesslstore", is_sensitive=True,
        label="Auth Token (Sandbox)",
        description="API-Token aus dem TheSSLStore-Portal für den Sandbox-Modus. Wird verschlüsselt gespeichert.",
    ),
    "thesslstore.user_agent": SettingDef(
        default="CertMgr/1.0",
        value_type="string", category="thesslstore", is_sensitive=False,
        label="User Agent",
        description="",
    ),

    # ── E-Mail / SMTP ─────────────────────────────────────────────────────────
    "smtp.enabled": SettingDef(
        default="false",
        value_type="bool", category="smtp", is_sensitive=False,
        label="E-Mail-Versand aktiv",
        description="Muss aktiviert sein, damit Benachrichtigungen verschickt werden.",
    ),
    "smtp.host": SettingDef(
        default="",
        value_type="string", category="smtp", is_sensitive=False,
        label="SMTP Host",
        description="Hostname des SMTP-Relay, z. B. mail.smtp2go.com.",
    ),
    "smtp.port": SettingDef(
        default="587",
        value_type="int", category="smtp", is_sensitive=False,
        label="SMTP Port",
        description="Standard: 587 (STARTTLS), 465 (SSL), 25 (unverschlüsselt).",
    ),
    "smtp.username": SettingDef(
        default="",
        value_type="string", category="smtp", is_sensitive=False,
        label="SMTP Benutzername",
        description="",
    ),
    "smtp.password": SettingDef(
        default="",
        value_type="string", category="smtp", is_sensitive=True,
        label="SMTP Passwort",
        description="Wird verschlüsselt in der Datenbank gespeichert.",
    ),
    "smtp.use_tls": SettingDef(
        default="true",
        value_type="bool", category="smtp", is_sensitive=False,
        label="STARTTLS verwenden",
        description="Empfohlen für Port 587.",
    ),
    "smtp.use_ssl": SettingDef(
        default="false",
        value_type="bool", category="smtp", is_sensitive=False,
        label="SSL verwenden",
        description="Für Port 465.",
    ),
    "smtp.from_email": SettingDef(
        default="",
        value_type="string", category="smtp", is_sensitive=False,
        label="Absenderadresse",
        description="z. B. noreply@example.com.",
    ),
    "smtp.from_name": SettingDef(
        default="SSL Cert Manager",
        value_type="string", category="smtp", is_sensitive=False,
        label="Absendername (optional)",
        description="",
    ),
    "smtp.reply_to": SettingDef(
        default="",
        value_type="string", category="smtp", is_sensitive=False,
        label="Reply-To (optional)",
        description="",
    ),

    # ── Logs & Wartung ────────────────────────────────────────────────────────
    "backup.encryption_password": SettingDef(
        default="",
        value_type="string", category="maintenance", is_sensitive=True,
        label="Backup-Verschlüsselungspasswort",
        description=(
            "Passwort zur AES-256-Verschlüsselung von Backup-Archiven (Fernet/AES-128-CBC mit SHA-256-Ableitung). "
            "Leer = Backups werden unverschlüsselt gespeichert. "
            "Achtung: Bei Passwortänderung können vorherige Backups nicht mehr entschlüsselt werden."
        ),
    ),
    "logs.retention_days": SettingDef(
        default="365",
        value_type="int", category="maintenance", is_sensitive=False,
        label="Log-Aufbewahrungsdauer (Tage)",
        description=(
            "Audit-Log-Einträge älter als dieser Wert werden täglich automatisch gelöscht. "
            "Minimum: 1, Maximum: 3650."
        ),
    ),
}


# ── Modul-globaler Cache ──────────────────────────────────────────────────────

_cache: dict[str, str | None] = {}
_cache_valid: bool = False


def _invalidate_cache() -> None:
    global _cache_valid
    _cache_valid = False


# ── SettingsService ───────────────────────────────────────────────────────────

class SettingsService:
    """Zugriffs-Service für App-Einstellungen.

    Instanzen per Request via Depends(get_settings_service).
    Cache ist modul-global und wird bei jeder Änderung invalidiert.
    """

    def __init__(self, db: Session):
        self.db = db

    # ── Cache-Verwaltung ──────────────────────────────────────────────────────

    def _ensure_cache(self) -> None:
        global _cache, _cache_valid
        if _cache_valid:
            return
        rows = self.db.query(models.AppSetting).all()
        new_cache: dict[str, str | None] = {}

        # Defaults für alle bekannten Keys setzen
        for key, defn in DEFINITIONS.items():
            new_cache[key] = defn.default

        # DB-Werte überschreiben Defaults
        for row in rows:
            defn = DEFINITIONS.get(row.key)
            if defn and defn.is_sensitive and row.value:
                try:
                    new_cache[row.key] = _decrypt(row.value)
                except Exception:
                    new_cache[row.key] = None
            else:
                new_cache[row.key] = row.value

        _cache = new_cache
        _cache_valid = True

    # ── Lesezugriff ───────────────────────────────────────────────────────────

    def get_raw(self, key: str) -> str | None:
        """Gibt den Rohwert (String) zurück."""
        self._ensure_cache()
        return _cache.get(key)

    def get(self, key: str, default: Any = None) -> Any:
        """Gibt den typisierten Wert zurück (gemäß DEFINITIONS.value_type)."""
        raw = self.get_raw(key)
        if raw is None:
            return default
        defn = DEFINITIONS.get(key)
        if not defn:
            return raw
        return _coerce(raw, defn.value_type)

    def get_bool(self, key: str, default: bool = False) -> bool:
        v = self.get_raw(key)
        if v is None:
            return default
        return v.lower() in ("true", "1", "yes", "on")

    def get_int(self, key: str, default: int = 0) -> int:
        v = self.get_raw(key)
        try:
            return int(v) if v is not None else default
        except (ValueError, TypeError):
            return default

    def get_str(self, key: str, default: str = "") -> str:
        v = self.get_raw(key)
        return v if v is not None else default

    # ── Schreibzugriff ────────────────────────────────────────────────────────

    def set(self, key: str, value: str, user_id: int | None = None) -> None:
        """Speichert einen Wert in der DB; invalidiert den Cache."""
        defn = DEFINITIONS.get(key)
        stored_value = _encrypt(value) if (defn and defn.is_sensitive and value) else value

        row = self.db.query(models.AppSetting).filter(
            models.AppSetting.key == key
        ).first()

        if row:
            row.value = stored_value
            row.updated_by = user_id
            from datetime import datetime
            row.updated_at = datetime.utcnow()
        else:
            row = models.AppSetting(
                key=key,
                value=stored_value,
                updated_by=user_id,
            )
            self.db.add(row)

        self.db.commit()
        _invalidate_cache()

    def set_many(
        self, values: dict[str, str], user_id: int | None = None
    ) -> None:
        """Speichert mehrere Werte in einer Transaktion."""
        from datetime import datetime

        for key, value in values.items():
            defn = DEFINITIONS.get(key)
            stored_value = (
                _encrypt(value) if (defn and defn.is_sensitive and value) else value
            )
            row = self.db.query(models.AppSetting).filter(
                models.AppSetting.key == key
            ).first()
            if row:
                row.value = stored_value
                row.updated_by = user_id
                row.updated_at = datetime.utcnow()
            else:
                self.db.add(models.AppSetting(
                    key=key,
                    value=stored_value,
                    updated_by=user_id,
                ))

        self.db.commit()
        _invalidate_cache()

    # ── UI-Hilfsfunktionen ────────────────────────────────────────────────────

    def get_all_by_category(self) -> dict[str, list[dict]]:
        """Gibt alle Settings gruppiert nach Kategorie für das UI zurück."""
        self._ensure_cache()
        result: dict[str, list[dict]] = {cat: [] for cat in CATEGORY_LABELS}

        for key, defn in DEFINITIONS.items():
            raw = _cache.get(key, defn.default)
            result.setdefault(defn.category, []).append({
                "key": key,
                "label": defn.label,
                "description": defn.description,
                "value_type": defn.value_type,
                "is_sensitive": defn.is_sensitive,
                "value": raw,
                # Für den Input-Wert sensitive Werte maskieren:
                "display_value": "••••••••" if (defn.is_sensitive and raw) else (raw or ""),
            })

        return result


# ── FastAPI Dependency ────────────────────────────────────────────────────────

def get_settings_service(db: Session) -> SettingsService:
    """Erzeugt einen SettingsService für den Request."""
    return SettingsService(db)


# ── Typkonvertierung ──────────────────────────────────────────────────────────

def _coerce(value: str, value_type: str) -> Any:
    if value_type == "bool":
        return value.lower() in ("true", "1", "yes", "on")
    if value_type == "int":
        try:
            return int(value)
        except (ValueError, TypeError):
            return 0
    return value


def is_integration_enabled(name: str, db: Session) -> bool:
    """Prüft ob eine Integration aktiviert ist.

    Aktuell unterstützte Namen: 'thesslstore'.
    """
    svc = get_settings_service(db)
    return svc.get_bool(f"{name}.enabled", default=False)
