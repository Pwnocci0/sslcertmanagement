"""Schreibgeschützte fail2ban-Status-Abfrage.

Führt ausschließlich lesende fail2ban-client-Befehle aus.
Keine modifizierenden Aktionen (kein Ban/Unban über die App).
"""
from __future__ import annotations

import re
import shutil
import subprocess


_JAIL_RE = re.compile(r"^[a-zA-Z0-9_-]+$")
_TIMEOUT = 5  # Sekunden


def _fail2ban_bin() -> str | None:
    """Gibt den Pfad zu fail2ban-client zurück oder None."""
    return shutil.which("fail2ban-client")


def is_available() -> bool:
    """Gibt True zurück wenn fail2ban-client im PATH verfügbar ist."""
    return _fail2ban_bin() is not None


def _run(args: list[str]) -> subprocess.CompletedProcess:
    """Führt fail2ban-client via sudo aus (Sudoers-Regel erforderlich)."""
    bin_path = _fail2ban_bin() or "fail2ban-client"
    return subprocess.run(
        ["sudo", bin_path] + args,
        capture_output=True,
        text=True,
        timeout=_TIMEOUT,
    )


def get_status() -> dict:
    """
    Gibt globalen fail2ban-Status zurück.
    Rückgabe: {"jails": [...], "error": str|None}
    """
    if not is_available():
        return {"jails": [], "error": "fail2ban-client nicht gefunden."}

    try:
        result = _run(["status"])
        if result.returncode != 0:
            return {
                "jails": [],
                "error": result.stderr.strip() or "fail2ban-client Fehler.",
            }

        jails: list[str] = []
        for line in result.stdout.splitlines():
            if "Jail list:" in line:
                raw = line.split(":", 1)[1].strip()
                jails = [j.strip() for j in raw.split(",") if j.strip()]
                break

        return {"jails": jails, "error": None}

    except subprocess.TimeoutExpired:
        return {"jails": [], "error": "Timeout beim Abfragen von fail2ban."}
    except Exception as exc:
        return {"jails": [], "error": str(exc)}


def get_jail_status(jail: str) -> dict:
    """
    Gibt Status eines einzelnen Jails zurück.
    Rückgabe: {"banned_ips": [...], "total_failed": int, "total_banned": int, "raw": str, "error": str|None}
    """
    if not _JAIL_RE.match(jail):
        return {"banned_ips": [], "total_failed": 0, "total_banned": 0, "raw": "", "error": "Ungültiger Jail-Name."}

    if not is_available():
        return {"banned_ips": [], "total_failed": 0, "total_banned": 0, "raw": "", "error": "fail2ban-client nicht gefunden."}

    try:
        result = _run(["status", jail])
        if result.returncode != 0:
            return {
                "banned_ips": [],
                "total_failed": 0,
                "total_banned": 0,
                "raw": "",
                "error": result.stderr.strip() or f"Fehler bei Jail '{jail}'.",
            }

        raw = result.stdout
        banned_ips: list[str] = []
        total_failed = 0
        total_banned = 0

        for line in raw.splitlines():
            line = line.strip()
            if "Currently banned:" in line:
                try:
                    total_banned = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif "Total failed:" in line:
                try:
                    total_failed = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif "Banned IP list:" in line:
                ip_part = line.split(":", 1)[1].strip()
                banned_ips = [ip.strip() for ip in ip_part.split() if ip.strip()]

        return {
            "banned_ips": banned_ips,
            "total_failed": total_failed,
            "total_banned": total_banned,
            "raw": raw,
            "error": None,
        }

    except subprocess.TimeoutExpired:
        return {"banned_ips": [], "total_failed": 0, "total_banned": 0, "raw": "", "error": "Timeout."}
    except Exception as exc:
        return {"banned_ips": [], "total_failed": 0, "total_banned": 0, "raw": "", "error": str(exc)}
