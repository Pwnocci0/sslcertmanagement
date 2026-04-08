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
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from .. import audit, models
from ..auth import hash_password, login_required, pop_flash, set_flash
from ..database import get_db
from ..settings_service import get_settings_service

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


def _ip(r: Request) -> str:
    return r.headers.get("X-Forwarded-For", r.client.host if r.client else "unknown")


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
