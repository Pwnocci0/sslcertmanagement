"""Admin-Wartungs- und Systemstatusseite."""
from __future__ import annotations

import collections
import os
import platform
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from ..auth import login_required, pop_flash
from ..database import get_db
from ..settings_service import get_settings_service
from .. import models

# Pfad zur Log-Datei (identisch mit main.py)
_LOG_FILE = Path(__file__).parent.parent.parent / "data" / "app.log"

# Regex zum Parsen einer Log-Zeile:
# 2024-01-01 12:00:00 INFO     app.services.thesslstore.client   TheSSLStore API …
_LOG_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(\w+)\s+(\S+)\s+(.*)$"
)

# Bekannte Filter-Kategorien
LOG_CATEGORIES = {
    "all":         "Alle",
    "thesslstore": "TheSSLStore API",
    "app":         "App allgemein",
    "uvicorn":     "HTTP-Requests",
}

LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

router = APIRouter(prefix="/admin")
templates = Jinja2Templates(directory="app/templates")

APP_VERSION = "1.0.0"


def _require_admin(request, db):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user, None
    if not user.is_admin:
        return RedirectResponse(url="/", status_code=302), None
    return None, user


def _db_status(db: Session) -> dict:
    try:
        db.execute(__import__("sqlalchemy").text("SELECT 1"))
        return {"ok": True, "msg": "Verbindung OK"}
    except Exception as exc:
        return {"ok": False, "msg": str(exc)}


def _collect_status(db: Session) -> dict:
    now = datetime.utcnow()

    # DB
    db_status = _db_status(db)

    # Pfade
    db_url = os.getenv("DATABASE_URL", "sqlite:///./data/sslcertmanagement.db")
    db_path = db_url.replace("sqlite:///", "")
    data_dir = os.path.abspath(os.path.dirname(db_path))
    cwd = os.path.abspath(".")

    # Letzter Produkt-Sync
    last_sync = db.query(
        __import__("sqlalchemy").func.max(models.TheSSLStoreProduct.synced_at)
    ).scalar()

    # Letzter Order-Status-Sync
    last_order_sync = db.query(
        __import__("sqlalchemy").func.max(models.TheSSLStoreOrder.updated_at)
    ).scalar()

    # Zertifikats-Statistiken
    total_certs = db.query(models.Certificate).filter(models.Certificate.is_archived == False).count()
    active_certs = db.query(models.Certificate).filter(
        models.Certificate.status == "active",
        models.Certificate.is_archived == False,
    ).count()

    from datetime import timedelta
    expiring_30 = db.query(models.Certificate).filter(
        models.Certificate.valid_until != None,
        models.Certificate.valid_until <= now + timedelta(days=30),
        models.Certificate.valid_until >= now,
        models.Certificate.is_archived == False,
    ).count()

    open_orders = db.query(models.TheSSLStoreOrder).filter(
        models.TheSSLStoreOrder.status.in_(["pending", "processing"])
    ).count()

    # CSR-Vault
    csr_count = db.query(models.CsrRequest).filter(
        models.CsrRequest.is_archived == False
    ).count()

    # Konfigurationswarnungen
    svc = get_settings_service(db)
    sandbox = svc.get_bool("thesslstore.sandbox", default=True)
    suffix = "sandbox" if sandbox else "live"
    warnings = []
    if not svc.get_str(f"thesslstore.partner_code_{suffix}"):
        warnings.append(f"TheSSLStore Partner Code ({suffix.capitalize()}) nicht konfiguriert.")
    if not svc.get_str(f"thesslstore.auth_token_{suffix}"):
        warnings.append(f"TheSSLStore Auth Token ({suffix.capitalize()}) nicht konfiguriert.")
    if not os.getenv("CSR_KEY_PASSPHRASE", "").strip():
        warnings.append("CSR_KEY_PASSPHRASE nicht gesetzt – Key-Vault nicht nutzbar!")
    secret = os.getenv("APP_SECRET_KEY", "")
    if not secret or "dev-secret" in secret or "CHANGE" in secret:
        warnings.append("APP_SECRET_KEY ist noch der Entwicklungs-Standardwert!")

    return {
        "app_version":      APP_VERSION,
        "python_version":   platform.python_version(),
        "platform":         platform.system(),
        "db_status":        db_status,
        "db_path":          os.path.abspath(db_path),
        "data_dir":         data_dir,
        "install_dir":      cwd,
        "last_product_sync": last_sync,
        "last_order_sync":  last_order_sync,
        "install_mode":     os.getenv("APP_INSTALL_MODE", "nicht gesetzt"),
        "sandbox_mode":     sandbox,
        "total_certs":      total_certs,
        "active_certs":     active_certs,
        "expiring_30":      expiring_30,
        "open_orders":      open_orders,
        "csr_count":        csr_count,
        "config_warnings":  warnings,
        "now":              now,
    }


@router.get("", response_class=HTMLResponse)
async def admin_status(request: Request, db: Session = Depends(get_db)):
    redirect, user = _require_admin(request, db)
    if redirect:
        return redirect

    status = _collect_status(db)

    return templates.TemplateResponse(
        "admin/status.html",
        {
            "request": request,
            "user":    user,
            "status":  status,
            "flash":   pop_flash(request),
        },
    )


# ── Log-Viewer ────────────────────────────────────────────────────────────────

def _read_log_lines(
    category: str,
    min_level: str,
    limit: int,
) -> list[dict]:
    """Liest die letzten ``limit`` Log-Zeilen aus der Datei und filtert sie."""
    if not _LOG_FILE.exists():
        return []

    level_order = {l: i for i, l in enumerate(LOG_LEVELS)}
    min_idx = level_order.get(min_level.upper(), 0)

    # Datei von hinten lesen (effizient für große Dateien)
    with _LOG_FILE.open("r", encoding="utf-8", errors="replace") as fh:
        raw_lines = fh.readlines()

    entries = []
    for line in reversed(raw_lines):
        line = line.rstrip("\n")
        m = _LOG_RE.match(line)
        if not m:
            # Continuation line (z.B. Traceback) → an letzten Eintrag anhängen
            if entries:
                entries[-1]["message"] += "\n" + line
            continue

        ts, level, logger, message = m.groups()

        # Level-Filter
        if level_order.get(level.upper(), 0) < min_idx:
            continue

        # Kategorie-Filter
        if category == "thesslstore" and "thesslstore" not in logger.lower():
            continue
        elif category == "uvicorn" and not logger.startswith("uvicorn"):
            continue
        elif category == "app" and (
            logger.startswith("uvicorn") or "thesslstore" in logger.lower()
        ):
            continue

        entries.append({
            "ts":      ts,
            "level":   level.upper(),
            "logger":  logger,
            "message": message,
        })

        if len(entries) >= limit:
            break

    return entries  # already newest-first because we reversed


@router.get("/logs", response_class=HTMLResponse)
async def admin_logs(
    request: Request,
    db: Session = Depends(get_db),
    category: str = Query(default="all"),
    level: str = Query(default="DEBUG"),
    limit: int = Query(default=200, ge=50, le=2000),
):
    redirect, user = _require_admin(request, db)
    if redirect:
        return redirect

    if category not in LOG_CATEGORIES:
        category = "all"
    if level.upper() not in LOG_LEVELS:
        level = "DEBUG"

    entries = _read_log_lines(category, level, limit)
    log_file_exists = _LOG_FILE.exists()

    return templates.TemplateResponse(
        "admin/logs.html",
        {
            "request":         request,
            "user":            user,
            "entries":         entries,
            "category":        category,
            "level":           level.upper(),
            "limit":           limit,
            "categories":      LOG_CATEGORIES,
            "levels":          LOG_LEVELS,
            "log_file_exists": log_file_exists,
            "log_file_path":   str(_LOG_FILE),
        },
    )
