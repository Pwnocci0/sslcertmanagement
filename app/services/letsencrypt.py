"""Let's-Encrypt-Zertifikatsstatus und Renewal-Trigger.

Liest Zertifikatsstatus direkt aus dem Dateisystem (/etc/letsencrypt/live/).
Die eigentliche Zertifikatsausstellung erfolgt durch Certbot, das per
install.sh als Root-Dienst eingerichtet wird.
Trigger-Mechanismus: App schreibt eine Anforderungsdatei, die ein
Root-Cron-Job/Timer stündlich auswertet.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta
from pathlib import Path

_LE_LIVE_DIR = Path("/etc/letsencrypt/live")
_TRIGGER_FILE = Path("/var/lib/certmgr-le/renew-requested")


def is_local_nginx() -> bool:
    """True wenn Modus A (interner NGINX + Let's Encrypt) aktiv ist."""
    return os.getenv("APP_INSTALL_MODE", "").strip().upper() == "A"


def get_cert_status(domain: str) -> dict:
    """
    Liest Let's-Encrypt-Zertifikatsstatus für die Domain aus dem Dateisystem.

    Rückgabe:
        dict mit: found, domain, valid_from, valid_until, days_remaining,
                  issuer, last_renewed, error
    """
    empty: dict = {
        "found": False, "domain": domain,
        "valid_from": None, "valid_until": None,
        "days_remaining": None, "issuer": None,
        "last_renewed": None, "error": None,
    }

    if not domain:
        return {**empty, "error": "Keine Domain konfiguriert."}

    cert_path: Path | None = None
    for variant in [domain, f"www.{domain}", domain.removeprefix("www.")]:
        p = _LE_LIVE_DIR / variant / "cert.pem"
        if p.exists():
            cert_path = p
            break

    if cert_path is None:
        return {**empty, "error": f"Kein Zertifikat in /etc/letsencrypt/live/ für {domain}."}

    try:
        from cryptography import x509

        cert_data = cert_path.read_bytes()
        cert = x509.load_pem_x509_certificate(cert_data)

        now = datetime.utcnow()
        valid_from = cert.not_valid_before_utc.replace(tzinfo=None)
        valid_until = cert.not_valid_after_utc.replace(tzinfo=None)
        days_remaining = (valid_until - now).days

        try:
            issuer = cert.issuer.get_attributes_for_oid(
                x509.NameOID.ORGANIZATION_NAME
            )[0].value
        except Exception:
            issuer = "Let's Encrypt"

        last_renewed = datetime.utcfromtimestamp(cert_path.stat().st_mtime)

        return {
            "found": True, "domain": domain,
            "valid_from": valid_from, "valid_until": valid_until,
            "days_remaining": days_remaining, "issuer": issuer,
            "last_renewed": last_renewed, "error": None,
        }
    except Exception as exc:
        return {**empty, "error": str(exc)}


def next_scheduled_renewal(valid_until: datetime | None) -> datetime | None:
    """Berechnet den nächsten Verlängerungszeitpunkt (30 Tage vor Ablauf)."""
    if valid_until is None:
        return None
    return valid_until - timedelta(days=30)


def request_renewal(domain: str) -> tuple[bool, str]:
    """
    Schreibt eine Trigger-Datei für das externe Root-Renewal-Skript.

    Das Skript wird stündlich von einem Root-Cron-Job ausgeführt und prüft,
    ob die Trigger-Datei vorhanden ist.
    """
    try:
        _TRIGGER_FILE.parent.mkdir(parents=True, exist_ok=True)
        _TRIGGER_FILE.write_text(
            f"{domain}\n{datetime.utcnow().isoformat()}\n"
        )
        return True, (
            "Erneuerungsanforderung gespeichert. "
            "Das Zertifikat wird beim nächsten Lauf des Renewal-Skripts ausgestellt."
        )
    except PermissionError:
        return False, (
            "Trigger-Datei konnte nicht geschrieben werden. "
            "Berechtigungen von /var/lib/certmgr-le/ prüfen."
        )
    except Exception as exc:
        return False, str(exc)


def get_nginx_status() -> dict:
    """Prüft NGINX-Status anhand der PID-Datei (ohne Root-Rechte)."""
    for pid_file in [Path("/run/nginx.pid"), Path("/var/run/nginx.pid")]:
        try:
            if pid_file.exists():
                pid_str = pid_file.read_text().strip()
                if pid_str.isdigit() and Path(f"/proc/{pid_str}").exists():
                    return {"running": True, "pid": int(pid_str), "error": None}
        except Exception:
            pass
    return {"running": False, "pid": None, "error": None}
