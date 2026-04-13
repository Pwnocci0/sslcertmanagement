"""Step-up-Authentifizierung für besonders sensible Aktionen.

Vor dem Export von Private Keys oder PFX-Dateien muss der Benutzer
zusätzlich zu seiner bestehenden Session Passwort + TOTP bestätigen.
Das Step-up-Token ist maximal STEPUP_DURATION Sekunden gültig.
"""
from __future__ import annotations

import time

from fastapi import Request
from fastapi.responses import RedirectResponse

STEPUP_DURATION = 300  # Fallback-Wert (5 Minuten)


def _get_stepup_duration() -> int:
    """Liest die Step-up-Dauer aus dem Settings-Cache (kein DB-Zugriff nötig)."""
    try:
        from .settings_service import _cache, _cache_valid  # noqa: PLC0415
        if _cache_valid:
            v = _cache.get("security.stepup_duration_seconds")
            if v:
                return max(60, min(3600, int(v)))
    except Exception:
        pass
    return STEPUP_DURATION

# Bekannte sensible Aktionen und ihre Bezeichnungen
ACTIONS: dict[str, str] = {
    "key_export_plain": "Unverschlüsselter Private-Key-Export",
    "key_export_pfx":   "PFX/PKCS#12-Export",
    "zip_export_key":   "ZIP-Export mit Private Key",
}


def check_stepup(request: Request, action: str) -> bool:
    """Gibt True zurück wenn ein gültiger Step-up-Token für die Aktion vorliegt."""
    token = request.session.get("stepup")
    if not token:
        return False
    if token.get("action") != action:
        return False
    if time.time() > token.get("expires", 0):
        request.session.pop("stepup", None)
        return False
    return True


def require_stepup(request: Request, action: str, next_url: str) -> RedirectResponse | None:
    """Gibt RedirectResponse zur Step-up-Seite zurück wenn nötig, sonst None."""
    if check_stepup(request, action):
        return None
    return RedirectResponse(
        url=f"/stepup/verify?action={action}&next={next_url}",
        status_code=302,
    )


def grant_stepup(request: Request, action: str, reason: str = "") -> None:
    """Speichert einen Step-up-Token in der Session."""
    request.session["stepup"] = {
        "action": action,
        "expires": int(time.time()) + _get_stepup_duration(),
        "reason": reason,
    }


def clear_stepup(request: Request) -> None:
    """Widerruft den Step-up-Token."""
    request.session.pop("stepup", None)
