"""Schreibgeschützte fail2ban-Status-Abfrage via SQLite-Datenbank.

Liest direkt aus der fail2ban-Datenbank – kein Subprocess, kein Socket,
kein sudo erforderlich. Die Datei muss für die fail2ban-Gruppe lesbar sein
(wird durch install.sh eingerichtet).
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
from datetime import datetime

_DB_PATH = "/var/lib/fail2ban/fail2ban.sqlite3"
_JAIL_RE = re.compile(r"^[a-zA-Z0-9_-]+$")
_DEFAULT_BANTIME = 600  # Sekunden – fail2ban-Standard


def is_available() -> bool:
    """True wenn die fail2ban-Datenbank existiert und lesbar ist."""
    return os.path.isfile(_DB_PATH) and os.access(_DB_PATH, os.R_OK)


def _connect() -> sqlite3.Connection:
    return sqlite3.connect(f"file:{_DB_PATH}?mode=ro", uri=True, timeout=3)


def _now() -> int:
    return int(datetime.utcnow().timestamp())


def get_status() -> dict:
    """
    Gibt Liste der konfigurierten Jails zurück.
    Rückgabe: {"jails": [...], "error": str|None}
    """
    if not is_available():
        return {
            "jails": [],
            "error": (
                "fail2ban-Datenbank nicht gefunden oder nicht lesbar. "
                "fail2ban installiert? (install.sh)"
            ),
        }
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT name FROM jails WHERE enabled = 1 ORDER BY name"
            ).fetchall()
        return {"jails": [r[0] for r in rows], "error": None}
    except sqlite3.OperationalError as exc:
        return {"jails": [], "error": f"Datenbankfehler: {exc}"}
    except Exception as exc:
        return {"jails": [], "error": str(exc)}


def get_jail_status(jail: str) -> dict:
    """
    Gibt Status eines einzelnen Jails zurück.
    Rückgabe: {"banned_ips": [...], "total_banned": int, "total_failed": int, "error": str|None}
    """
    _empty = {"banned_ips": [], "total_banned": 0, "total_failed": 0, "error": None}

    if not _JAIL_RE.match(jail):
        return {**_empty, "error": "Ungültiger Jail-Name."}

    if not is_available():
        return {**_empty, "error": "fail2ban-Datenbank nicht zugänglich."}

    try:
        now = _now()
        with _connect() as conn:
            rows = conn.execute(
                "SELECT ip, timeofban, data FROM bans WHERE jail = ?",
                (jail,),
            ).fetchall()
    except sqlite3.OperationalError as exc:
        return {**_empty, "error": f"Datenbankfehler: {exc}"}
    except Exception as exc:
        return {**_empty, "error": str(exc)}

    banned_ips: list[str] = []
    total_failed = 0

    for ip, timeofban, data_raw in rows:
        try:
            data: dict = json.loads(data_raw) if data_raw else {}
        except (json.JSONDecodeError, TypeError):
            data = {}

        bantime: int = data.get("bantime", _DEFAULT_BANTIME)
        total_failed += data.get("failures", 0)

        # Permanente Bans (bantime < 0) oder noch nicht abgelaufen
        if bantime < 0 or timeofban + bantime > now:
            banned_ips.append(ip)

    return {
        "banned_ips": banned_ips,
        "total_banned": len(banned_ips),
        "total_failed": total_failed,
        "error": None,
    }
