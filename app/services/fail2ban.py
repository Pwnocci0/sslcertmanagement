"""Schreibgeschützte fail2ban-Status-Abfrage.

Kommuniziert direkt mit dem fail2ban Unix-Socket via Python (kein Subprocess).
Voraussetzung: certmgr-User hat Lesezugriff auf /var/run/fail2ban/fail2ban.sock
(via Gruppenberechtigungen – wird durch install.sh eingerichtet).

Keine modifizierenden Aktionen (kein Ban/Unban über die App).
"""
from __future__ import annotations

import os
import pickle
import re
import socket as _socket

_SOCK_PATH = "/var/run/fail2ban/fail2ban.sock"
_JAIL_RE = re.compile(r"^[a-zA-Z0-9_-]+$")
_TIMEOUT = 5  # Sekunden


def is_available() -> bool:
    """Gibt True zurück wenn der fail2ban-Socket existiert und erreichbar ist."""
    return os.path.exists(_SOCK_PATH)


def _send(cmd: list) -> tuple[object, str | None]:
    """
    Sendet einen Befehl an den fail2ban-Socket und gibt (result, error) zurück.
    Protokoll: pickle-serialisiert, Verbindung über Unix-Socket.
    """
    try:
        s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        s.settimeout(_TIMEOUT)
        s.connect(_SOCK_PATH)
        try:
            s.sendall(pickle.dumps(cmd, protocol=2))
            s.shutdown(_socket.SHUT_WR)
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        finally:
            s.close()

        result = pickle.loads(data)  # noqa: S301 – lokaler Unix-Socket, vertrauenswürdig
        # fail2ban antwortet mit [return_code, payload]
        if isinstance(result, list) and len(result) == 2 and result[0] == 0:
            return result[1], None
        return None, f"fail2ban Fehlercode: {result}"

    except PermissionError:
        return None, (
            "Kein Zugriff auf den fail2ban-Socket. "
            "Stelle sicher, dass der certmgr-User Mitglied der fail2ban-Gruppe ist "
            "und der systemd Drop-in eingerichtet wurde (install.sh ausführen)."
        )
    except _socket.timeout:
        return None, "Timeout beim Verbinden mit fail2ban."
    except FileNotFoundError:
        return None, "fail2ban-Socket nicht gefunden (/var/run/fail2ban/fail2ban.sock)."
    except Exception as exc:
        return None, str(exc)


def get_status() -> dict:
    """
    Gibt globalen fail2ban-Status zurück.
    Rückgabe: {"jails": [...], "error": str|None}
    """
    if not is_available():
        return {"jails": [], "error": "fail2ban läuft nicht (Socket nicht gefunden)."}

    payload, err = _send(["status"])
    if err:
        return {"jails": [], "error": err}

    # payload: [("Number of jail", N), ("Jail list", "sshd, nginx-http-auth")]
    jails: list[str] = []
    try:
        for key, val in payload:
            if "jail list" in key.lower():
                jails = [j.strip() for j in str(val).split(",") if j.strip()]
    except Exception as exc:
        return {"jails": [], "error": f"Antwort konnte nicht geparst werden: {exc}"}

    return {"jails": jails, "error": None}


def get_jail_status(jail: str) -> dict:
    """
    Gibt Status eines einzelnen Jails zurück.
    Rückgabe: {"banned_ips": [...], "total_failed": int, "total_banned": int, "error": str|None}
    """
    _empty = {"banned_ips": [], "total_failed": 0, "total_banned": 0, "error": None}

    if not _JAIL_RE.match(jail):
        return {**_empty, "error": "Ungültiger Jail-Name."}

    if not is_available():
        return {**_empty, "error": "fail2ban läuft nicht."}

    payload, err = _send(["status", jail])
    if err:
        return {**_empty, "error": err}

    # payload: [("Filter", [...]), ("Actions", [...])]
    banned_ips: list[str] = []
    total_failed = 0
    total_banned = 0

    try:
        for section_name, section_data in payload:
            for key, val in section_data:
                k = key.lower()
                if "currently banned" in k:
                    total_banned = int(val)
                elif "total failed" in k:
                    total_failed = int(val)
                elif "banned ip list" in k:
                    if isinstance(val, list):
                        banned_ips = [str(ip) for ip in val if ip]
                    elif val:
                        banned_ips = [ip.strip() for ip in str(val).split() if ip.strip()]
    except Exception as exc:
        return {**_empty, "error": f"Antwort konnte nicht geparst werden: {exc}"}

    return {
        "banned_ips": banned_ips,
        "total_failed": total_failed,
        "total_banned": total_banned,
        "error": None,
    }
