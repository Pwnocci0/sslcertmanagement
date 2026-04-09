"""Zentraler Jinja2-Templates-Instance für die gesamte App.

Alle Router importieren `templates` aus diesem Modul, damit Jinja2-Globals
(app_name, app_timezone, app_favicon, app_logo) und Filter (localtime)
nur einmal registriert werden müssen und für alle Antworten gelten.
"""
from __future__ import annotations

from zoneinfo import ZoneInfo

from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="app/templates")

# ── Zeitzone-Filter ───────────────────────────────────────────────────────────

def _localtime(dt, tz_name: str | None = None) -> str:
    """Wandelt ein UTC-datetime in die konfigurierte lokale Zeitzone um."""
    if dt is None:
        return "–"
    tz_str = tz_name or templates.env.globals.get("app_timezone", "Europe/Berlin")
    try:
        tz = ZoneInfo(tz_str)
    except Exception:
        tz = ZoneInfo("Europe/Berlin")
    # naive datetimes in der DB werden als UTC behandelt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo("UTC"))
    return dt.astimezone(tz).strftime("%d.%m.%Y %H:%M")


def _localdate(dt, tz_name: str | None = None) -> str:
    """Wie localtime, aber nur Datum."""
    if dt is None:
        return "–"
    tz_str = tz_name or templates.env.globals.get("app_timezone", "Europe/Berlin")
    try:
        tz = ZoneInfo(tz_str)
    except Exception:
        tz = ZoneInfo("Europe/Berlin")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo("UTC"))
    return dt.astimezone(tz).strftime("%d.%m.%Y")


templates.env.filters["localtime"] = _localtime
templates.env.filters["localdate"] = _localdate

# ── Defaults (werden beim App-Start in main.py überschrieben) ─────────────────

templates.env.globals.setdefault("app_name", "SSL Cert Management")
templates.env.globals.setdefault("app_timezone", "Europe/Berlin")
templates.env.globals.setdefault("app_favicon", "")
templates.env.globals.setdefault("app_logo", "")
