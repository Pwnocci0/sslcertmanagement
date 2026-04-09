"""Admin-Wartungs-, Systemstatus- und Benutzerverwaltungsseite."""
from __future__ import annotations

import collections
import os
import platform
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from .. import audit, models
from ..auth import hash_password, login_required, pop_flash, set_flash
from ..database import get_db
from ..services.system_status import (
    get_backup_summary,
    get_database_info,
    get_log_summary,
    get_storage_breakdown,
    run_log_cleanup,
)
from ..settings_service import get_settings_service, is_integration_enabled

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
from ..templates_config import templates

APP_VERSION = "1.0.0"


def _require_admin(request, db):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user, None
    if not user.is_admin:
        return RedirectResponse(url="/", status_code=302), None
    return None, user


def _ip(r: Request) -> str:
    return r.headers.get("X-Forwarded-For", r.client.host if r.client else "unknown")


def _db_status(db: Session) -> dict:
    try:
        db.execute(__import__("sqlalchemy").text("SELECT 1"))
        return {"ok": True, "msg": "Verbindung OK"}
    except Exception as exc:
        return {"ok": False, "msg": str(exc)}


def _collect_status(db: Session) -> dict:
    from datetime import timedelta
    import sqlalchemy

    now = datetime.utcnow()

    # ── Basisinfos ────────────────────────────────────────────────────────────
    db_status = _db_status(db)
    cwd = os.path.abspath(".")

    # ── Settings ──────────────────────────────────────────────────────────────
    svc = get_settings_service(db)
    retention_days = max(1, min(3650, svc.get_int("logs.retention_days", default=365)))

    # ── TheSSLStore (nur wenn aktiviert) ──────────────────────────────────────
    thesslstore_enabled = is_integration_enabled("thesslstore", db)
    sandbox = svc.get_bool("thesslstore.sandbox", default=True)

    last_sync = last_order_sync = None
    open_orders = 0
    if thesslstore_enabled:
        last_sync = db.query(
            sqlalchemy.func.max(models.TheSSLStoreProduct.synced_at)
        ).scalar()
        last_order_sync = db.query(
            sqlalchemy.func.max(models.TheSSLStoreOrder.updated_at)
        ).scalar()
        open_orders = db.query(models.TheSSLStoreOrder).filter(
            models.TheSSLStoreOrder.status.in_(["pending", "processing"])
        ).count()

    # ── Zertifikats-Statistiken ───────────────────────────────────────────────
    total_certs = db.query(models.Certificate).filter(
        models.Certificate.is_archived == False
    ).count()
    active_certs = db.query(models.Certificate).filter(
        models.Certificate.status == "active",
        models.Certificate.is_archived == False,
    ).count()
    expiring_30 = db.query(models.Certificate).filter(
        models.Certificate.valid_until != None,
        models.Certificate.valid_until <= now + timedelta(days=30),
        models.Certificate.valid_until >= now,
        models.Certificate.is_archived == False,
    ).count()

    csr_count = db.query(models.CsrRequest).filter(
        models.CsrRequest.is_archived == False
    ).count()

    # ── Konfigurationswarnungen ───────────────────────────────────────────────
    warnings = []
    if thesslstore_enabled:
        suffix = "sandbox" if sandbox else "live"
        if not svc.get_str(f"thesslstore.partner_code_{suffix}"):
            warnings.append(f"TheSSLStore Partner Code ({suffix.capitalize()}) nicht konfiguriert.")
        if not svc.get_str(f"thesslstore.auth_token_{suffix}"):
            warnings.append(f"TheSSLStore Auth Token ({suffix.capitalize()}) nicht konfiguriert.")
    if not os.getenv("CSR_KEY_PASSPHRASE", "").strip():
        warnings.append("CSR_KEY_PASSPHRASE nicht gesetzt – Key-Vault nicht nutzbar!")
    secret = os.getenv("APP_SECRET_KEY", "")
    if not secret or "dev-secret" in secret or "CHANGE" in secret:
        warnings.append("APP_SECRET_KEY ist noch der Entwicklungs-Standardwert!")

    # ── Neue Status-Abschnitte (caching-fähig) ────────────────────────────────
    db_info   = get_database_info()
    storage   = get_storage_breakdown()
    backups   = get_backup_summary(db)
    log_info  = get_log_summary(db, retention_days=retention_days)

    return {
        # System
        "app_version":       APP_VERSION,
        "python_version":    platform.python_version(),
        "platform":          platform.system(),
        "install_dir":       cwd,
        "install_mode":      os.getenv("APP_INSTALL_MODE", "nicht gesetzt"),
        "db_status":         db_status,
        "config_warnings":   warnings,
        "now":               now,
        # Zertifikate
        "total_certs":       total_certs,
        "active_certs":      active_certs,
        "expiring_30":       expiring_30,
        "csr_count":         csr_count,
        # TheSSLStore (bedingt)
        "thesslstore_enabled": thesslstore_enabled,
        "sandbox_mode":      sandbox,
        "last_product_sync": last_sync,
        "last_order_sync":   last_order_sync,
        "open_orders":       open_orders,
        # Neue Abschnitte
        "db_info":           db_info,
        "storage":           storage,
        "backups":           backups,
        "log_info":          log_info,
        "retention_days":    retention_days,
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


@router.post("/save-retention")
async def save_retention(
    request: Request,
    db: Session = Depends(get_db),
    retention_days: int = Form(...),
):
    """Speichert die Log-Aufbewahrungsdauer direkt von der Status-Seite."""
    redirect, user = _require_admin(request, db)
    if redirect:
        return redirect

    days = max(1, min(3650, retention_days))
    svc = get_settings_service(db)
    svc.set("logs.retention_days", str(days), user_id=user.id)
    audit.log(
        db, "admin.retention_updated", "system", user_id=user.id,
        details={"retention_days": days},
        ip=_ip(request),
    )
    set_flash(request, "success", f"Log-Aufbewahrung auf {days} Tage gesetzt.")
    return RedirectResponse(url="/admin", status_code=302)


@router.post("/cleanup-logs")
async def trigger_log_cleanup(request: Request, db: Session = Depends(get_db)):
    """Manueller Auslöser für den Log-Cleanup."""
    redirect, user = _require_admin(request, db)
    if redirect:
        return redirect

    svc = get_settings_service(db)
    retention_days = max(1, min(3650, svc.get_int("logs.retention_days", default=365)))

    try:
        deleted = run_log_cleanup(db, retention_days)
        audit.log(
            db, "admin.log_cleanup", "system", user_id=user.id,
            details={"deleted": deleted, "retention_days": retention_days},
            ip=_ip(request),
        )
        set_flash(request, "success", f"Log-Cleanup abgeschlossen: {deleted} Einträge gelöscht.")
    except Exception as exc:
        set_flash(request, "danger", f"Log-Cleanup fehlgeschlagen: {exc}")

    return RedirectResponse(url="/admin", status_code=302)


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


# ── Benutzerverwaltung ────────────────────────────────────────────────────────

@router.get("/users", response_class=HTMLResponse)
async def user_list(request: Request, db: Session = Depends(get_db)):
    redir, user = _require_admin(request, db)
    if redir:
        return redir

    users = db.query(models.User).order_by(models.User.username).all()
    return templates.TemplateResponse(
        "admin/users/list.html",
        {"request": request, "user": user, "users": users, "flash": pop_flash(request)},
    )


@router.get("/users/new", response_class=HTMLResponse)
async def user_new(request: Request, db: Session = Depends(get_db)):
    redir, user = _require_admin(request, db)
    if redir:
        return redir

    groups = db.query(models.CustomerGroup).order_by(models.CustomerGroup.name).all()
    return templates.TemplateResponse(
        "admin/users/form.html",
        {
            "request": request, "user": user, "edit_user": None,
            "groups": groups, "selected_group_ids": [],
            "error": None, "flash": None,
        },
    )


@router.post("/users/new")
async def user_create(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form("technician"),
    group_ids: list[int] = Form(default=[]),
    db: Session = Depends(get_db),
):
    redir, user = _require_admin(request, db)
    if redir:
        return redir

    def render_error(msg: str, status: int = 422):
        groups = db.query(models.CustomerGroup).order_by(models.CustomerGroup.name).all()
        return templates.TemplateResponse(
            "admin/users/form.html",
            {
                "request": request, "user": user, "edit_user": None,
                "groups": groups, "selected_group_ids": group_ids,
                "error": msg, "flash": None,
            },
            status_code=status,
        )

    username = username.strip()
    email = email.strip()
    if not username or not email or not password:
        return render_error("Benutzername, E-Mail und Passwort sind Pflichtfelder.")
    if role not in ("admin", "technician"):
        return render_error("Ungültige Rolle.")
    if len(password) < 8:
        return render_error("Passwort muss mindestens 8 Zeichen lang sein.")

    if db.query(models.User).filter(models.User.username == username).first():
        return render_error(f'Benutzername "{username}" ist bereits vergeben.')
    if db.query(models.User).filter(models.User.email == email).first():
        return render_error(f'E-Mail "{email}" ist bereits vergeben.')

    new_user = models.User(
        username=username,
        email=email,
        hashed_password=hash_password(password),
        is_active=True,
        is_admin=(role == "admin"),
        role=role,
    )

    # Kundengruppen zuweisen (nur für Techniker sinnvoll)
    if group_ids and role == "technician":
        new_user.customer_groups = db.query(models.CustomerGroup).filter(
            models.CustomerGroup.id.in_(group_ids)
        ).all()

    db.add(new_user)
    db.flush()

    audit.log(db, "user.created", "user", user.id,
              entity_id=new_user.id,
              details={"username": username, "role": role, "group_ids": group_ids},
              ip=_ip(request))

    db.commit()
    set_flash(request, "success", f'Benutzer "{username}" wurde angelegt.')
    return RedirectResponse(url="/admin/users", status_code=302)


@router.get("/users/{user_id}/edit", response_class=HTMLResponse)
async def user_edit(user_id: int, request: Request, db: Session = Depends(get_db)):
    redir, user = _require_admin(request, db)
    if redir:
        return redir

    edit_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not edit_user:
        set_flash(request, "warning", "Benutzer nicht gefunden.")
        return RedirectResponse(url="/admin/users", status_code=302)

    groups = db.query(models.CustomerGroup).order_by(models.CustomerGroup.name).all()
    selected_group_ids = [g.id for g in edit_user.customer_groups]

    return templates.TemplateResponse(
        "admin/users/form.html",
        {
            "request": request, "user": user, "edit_user": edit_user,
            "groups": groups, "selected_group_ids": selected_group_ids,
            "error": None, "flash": None,
        },
    )


@router.post("/users/{user_id}/edit")
async def user_update(
    user_id: int,
    request: Request,
    email: str = Form(...),
    password: str = Form(""),
    role: str = Form("technician"),
    group_ids: list[int] = Form(default=[]),
    db: Session = Depends(get_db),
):
    redir, user = _require_admin(request, db)
    if redir:
        return redir

    edit_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not edit_user:
        return RedirectResponse(url="/admin/users", status_code=302)

    def render_error(msg: str, status: int = 422):
        groups = db.query(models.CustomerGroup).order_by(models.CustomerGroup.name).all()
        return templates.TemplateResponse(
            "admin/users/form.html",
            {
                "request": request, "user": user, "edit_user": edit_user,
                "groups": groups, "selected_group_ids": group_ids,
                "error": msg, "flash": None,
            },
            status_code=status,
        )

    email = email.strip()
    if not email:
        return render_error("E-Mail darf nicht leer sein.")
    if role not in ("admin", "technician"):
        return render_error("Ungültige Rolle.")
    if password and len(password) < 8:
        return render_error("Neues Passwort muss mindestens 8 Zeichen lang sein.")

    # E-Mail-Duplikat prüfen (eigene E-Mail ausschließen)
    existing = db.query(models.User).filter(
        models.User.email == email,
        models.User.id != user_id,
    ).first()
    if existing:
        return render_error(f'E-Mail "{email}" ist bereits vergeben.')

    # Letzten Admin schützen: Falls dieser User der letzte Admin ist, Rolle nicht ändern
    if edit_user.is_admin and role == "technician":
        admin_count = db.query(models.User).filter(
            models.User.is_admin == True,
            models.User.id != user_id,
        ).count()
        if admin_count == 0:
            return render_error("Der letzte Administrator kann nicht zum Techniker werden.")

    old_role = edit_user.role
    edit_user.email = email
    edit_user.role = role
    edit_user.is_admin = (role == "admin")
    if password:
        edit_user.hashed_password = hash_password(password)

    # Kundengruppen aktualisieren
    if group_ids and role == "technician":
        edit_user.customer_groups = db.query(models.CustomerGroup).filter(
            models.CustomerGroup.id.in_(group_ids)
        ).all()
    else:
        edit_user.customer_groups = []

    audit.log(db, "user.updated", "user", user.id,
              entity_id=user_id,
              details={
                  "username": edit_user.username,
                  "old_role": old_role, "new_role": role,
                  "password_changed": bool(password),
                  "group_ids": group_ids,
              },
              ip=_ip(request))

    db.commit()
    set_flash(request, "success", f'Benutzer "{edit_user.username}" gespeichert.')
    return RedirectResponse(url="/admin/users", status_code=302)


@router.post("/users/{user_id}/reset-mfa")
async def user_reset_mfa(user_id: int, request: Request, db: Session = Depends(get_db)):
    redir, user = _require_admin(request, db)
    if redir:
        return redir

    edit_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not edit_user:
        set_flash(request, "warning", "Benutzer nicht gefunden.")
        return RedirectResponse(url="/admin/users", status_code=302)

    if edit_user.id == user.id:
        set_flash(request, "warning", "Sie können Ihre eigene MFA nicht zurücksetzen.")
        return RedirectResponse(url="/admin/users", status_code=302)

    edit_user.mfa_secret_encrypted = None
    edit_user.mfa_setup_completed = False
    edit_user.recovery_codes_json = None
    edit_user.last_mfa_at = None

    audit.log(db, "user.mfa_reset", "user", user.id,
              entity_id=user_id,
              details={"username": edit_user.username, "reset_by": user.username},
              ip=_ip(request))

    db.commit()
    set_flash(request, "success",
              f'MFA für Benutzer "{edit_user.username}" wurde zurückgesetzt. '
              f'Der Benutzer muss sich beim nächsten Login neu registrieren.')
    return RedirectResponse(url="/admin/users", status_code=302)


@router.post("/users/{user_id}/toggle-active")
async def user_toggle_active(user_id: int, request: Request, db: Session = Depends(get_db)):
    redir, user = _require_admin(request, db)
    if redir:
        return redir

    edit_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not edit_user:
        return RedirectResponse(url="/admin/users", status_code=302)

    # Eigenes Konto nicht deaktivieren
    if edit_user.id == user.id:
        set_flash(request, "warning", "Sie können Ihr eigenes Konto nicht deaktivieren.")
        return RedirectResponse(url="/admin/users", status_code=302)

    # Letzten Admin schützen
    if edit_user.is_admin and edit_user.is_active:
        admin_count = db.query(models.User).filter(
            models.User.is_admin == True,
            models.User.is_active == True,
            models.User.id != user_id,
        ).count()
        if admin_count == 0:
            set_flash(request, "danger", "Der letzte aktive Administrator kann nicht deaktiviert werden.")
            return RedirectResponse(url="/admin/users", status_code=302)

    edit_user.is_active = not edit_user.is_active
    action = "aktiviert" if edit_user.is_active else "deaktiviert"

    audit.log(db, "user.toggled_active", "user", user.id,
              entity_id=user_id,
              details={"username": edit_user.username, "is_active": edit_user.is_active},
              ip=_ip(request))

    db.commit()
    set_flash(request, "success" if edit_user.is_active else "warning",
              f'Benutzer "{edit_user.username}" wurde {action}.')
    return RedirectResponse(url="/admin/users", status_code=302)
