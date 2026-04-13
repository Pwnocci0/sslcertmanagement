"""Routen für die zentrale Settings-Verwaltung (nur Admins)."""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from .. import audit
from ..auth import login_required, pop_flash, set_flash
from ..database import get_db
from ..settings_service import CATEGORY_LABELS, DEFINITIONS, get_settings_service

router = APIRouter(prefix="/settings", tags=["settings"])
from ..templates_config import templates

_UPLOAD_DIR = Path(__file__).resolve().parent.parent.parent / "static" / "uploads"
_FAVICON_ALLOWED = {".ico", ".png", ".svg"}
_LOGO_ALLOWED = {".png", ".svg", ".jpg", ".jpeg"}
_MAX_UPLOAD_BYTES = 2 * 1024 * 1024  # 2 MB

# Keys managed via upload — excluded from the generic text-field form
_UPLOAD_MANAGED_KEYS = {"app.favicon_path", "app.logo_path"}


def _require_admin(request: Request, db: Session):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user, None
    if not user.is_admin:
        return RedirectResponse(url="/", status_code=302), None
    return None, user


def _ip(request: Request) -> str:
    return request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown")


# ── GET /settings ─────────────────────────────────────────────────────────────

@router.get("", response_class=HTMLResponse)
async def settings_index(
    request: Request,
    db: Session = Depends(get_db),
):
    redirect, user = _require_admin(request, db)
    if redirect:
        return redirect

    svc = get_settings_service(db)
    grouped_all = svc.get_all_by_category()
    # SMTP → /mail-settings, TheSSLStore → /settings/integrations, Security → /security
    excluded = {"smtp", "thesslstore", "security"}
    grouped = {k: v for k, v in grouped_all.items() if k not in excluded}
    category_labels = {k: v for k, v in CATEGORY_LABELS.items() if k not in excluded}

    # Current branding paths for preview
    favicon_path = svc.get_str("app.favicon_path", "")
    logo_path = svc.get_str("app.logo_path", "")

    return templates.TemplateResponse(
        "settings/index.html",
        {
            "request": request,
            "user": user,
            "grouped": grouped,
            "category_labels": category_labels,
            "flash": pop_flash(request),
            "favicon_path": favicon_path,
            "logo_path": logo_path,
            "upload_managed_keys": _UPLOAD_MANAGED_KEYS,
        },
    )


# ── POST /settings/save ───────────────────────────────────────────────────────

@router.post("/save", response_class=HTMLResponse)
async def settings_save(
    request: Request,
    db: Session = Depends(get_db),
):
    redirect, user = _require_admin(request, db)
    if redirect:
        return redirect

    form = await request.form()
    svc = get_settings_service(db)
    referer = request.headers.get("referer", "/settings")
    redirect_to = "/settings/integrations" if "integrations" in referer else "/settings"

    values: dict[str, str] = {}
    for key in DEFINITIONS:
        defn = DEFINITIONS[key]
        if defn.category == "smtp":
            continue  # SMTP wird über /mail-settings verwaltet
        if defn.category == "security":
            continue  # Security wird über /security verwaltet
        if key in _UPLOAD_MANAGED_KEYS:
            continue  # Favicon/Logo werden über Upload-Endpunkte verwaltet
        if defn.value_type == "bool":
            values[key] = "true" if form.get(key) else "false"
        elif key in form:
            raw = str(form[key]).strip()
            if defn.is_sensitive and not raw:
                continue
            values[key] = raw

    svc.set_many(values, user_id=user.id)
    audit.log(db, "settings.saved", "settings", user.id, ip=_ip(request))

    # Jinja2-Globals aktualisieren
    try:
        from ..templates_config import templates as _tmpl
        _tmpl.env.globals["app_name"] = svc.get_str("app.name", "SSL Cert Management")
        _tmpl.env.globals["app_timezone"] = svc.get_str("app.timezone", "Europe/Berlin")
        _tmpl.env.globals["app_favicon"] = svc.get_str("app.favicon_path", "")
        _tmpl.env.globals["app_logo"] = svc.get_str("app.logo_path", "")
    except Exception:
        pass

    set_flash(request, "success", "Einstellungen gespeichert.")
    return RedirectResponse(url=redirect_to, status_code=303)


# ── POST /settings/upload-favicon ────────────────────────────────────────────

def _save_upload(file: UploadFile, data: bytes, allowed_exts: set[str], prefix: str) -> str:
    """Validiert und speichert die Datei; gibt den relativen Pfad zurück."""
    original = Path(file.filename or "upload")
    ext = original.suffix.lower()
    if ext not in allowed_exts:
        raise ValueError(f"Dateityp nicht erlaubt. Erlaubt: {', '.join(sorted(allowed_exts))}")
    if len(data) > _MAX_UPLOAD_BYTES:
        raise ValueError("Datei zu groß (max. 2 MB).")
    # Sicherer, fixer Dateiname — kein Pfad aus dem Original
    safe_name = f"{prefix}{ext}"
    dest = _UPLOAD_DIR / safe_name
    _UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    return f"static/uploads/{safe_name}"


def _update_branding_globals(svc) -> None:
    from ..templates_config import templates as _tmpl
    _tmpl.env.globals["app_favicon"] = svc.get_str("app.favicon_path", "")
    _tmpl.env.globals["app_logo"] = svc.get_str("app.logo_path", "")


@router.post("/upload-favicon")
async def settings_upload_favicon(
    request: Request,
    favicon: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    redirect, user = _require_admin(request, db)
    if redirect:
        return redirect

    data = await favicon.read()
    svc = get_settings_service(db)
    try:
        path = _save_upload(favicon, data, _FAVICON_ALLOWED, "favicon")
        svc.set_many({"app.favicon_path": path}, user_id=user.id)
        _update_branding_globals(svc)
        audit.log(db, "settings.favicon_uploaded", "settings", user.id,
                  details={"path": path}, ip=_ip(request))
        set_flash(request, "success", "Favicon erfolgreich hochgeladen.")
    except ValueError as exc:
        set_flash(request, "danger", str(exc))

    return RedirectResponse(url="/settings", status_code=303)


@router.post("/upload-favicon/remove")
async def settings_remove_favicon(request: Request, db: Session = Depends(get_db)):
    redirect, user = _require_admin(request, db)
    if redirect:
        return redirect

    svc = get_settings_service(db)
    old_path = svc.get_str("app.favicon_path", "")
    if old_path:
        try:
            Path(old_path).unlink(missing_ok=True)
        except Exception:
            pass
    svc.set_many({"app.favicon_path": ""}, user_id=user.id)
    _update_branding_globals(svc)
    audit.log(db, "settings.favicon_removed", "settings", user.id, ip=_ip(request))
    set_flash(request, "success", "Favicon entfernt.")
    return RedirectResponse(url="/settings", status_code=303)


@router.post("/upload-logo")
async def settings_upload_logo(
    request: Request,
    logo: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    redirect, user = _require_admin(request, db)
    if redirect:
        return redirect

    data = await logo.read()
    svc = get_settings_service(db)
    try:
        path = _save_upload(logo, data, _LOGO_ALLOWED, "logo")
        svc.set_many({"app.logo_path": path}, user_id=user.id)
        _update_branding_globals(svc)
        audit.log(db, "settings.logo_uploaded", "settings", user.id,
                  details={"path": path}, ip=_ip(request))
        set_flash(request, "success", "Logo erfolgreich hochgeladen.")
    except ValueError as exc:
        set_flash(request, "danger", str(exc))

    return RedirectResponse(url="/settings", status_code=303)


@router.post("/upload-logo/remove")
async def settings_remove_logo(request: Request, db: Session = Depends(get_db)):
    redirect, user = _require_admin(request, db)
    if redirect:
        return redirect

    svc = get_settings_service(db)
    old_path = svc.get_str("app.logo_path", "")
    if old_path:
        try:
            Path(old_path).unlink(missing_ok=True)
        except Exception:
            pass
    svc.set_many({"app.logo_path": ""}, user_id=user.id)
    _update_branding_globals(svc)
    audit.log(db, "settings.logo_removed", "settings", user.id, ip=_ip(request))
    set_flash(request, "success", "Logo entfernt.")
    return RedirectResponse(url="/settings", status_code=303)


# ── GET /settings/integrations ────────────────────────────────────────────────

@router.get("/integrations", response_class=HTMLResponse)
async def integrations_index(
    request: Request,
    db: Session = Depends(get_db),
):
    redirect, user = _require_admin(request, db)
    if redirect:
        return redirect

    svc = get_settings_service(db)
    grouped_all = svc.get_all_by_category()
    thesslstore_settings = grouped_all.get("thesslstore", [])
    thesslstore_enabled = svc.get_bool("thesslstore.enabled", default=False)

    return templates.TemplateResponse(
        "settings/integrations.html",
        {
            "request": request,
            "user": user,
            "thesslstore_settings": thesslstore_settings,
            "thesslstore_enabled": thesslstore_enabled,
            "flash": pop_flash(request),
        },
    )


# ── POST /settings/test-connection (AJAX) ─────────────────────────────────────

@router.post("/test-connection", response_class=JSONResponse)
async def test_connection(
    request: Request,
    db: Session = Depends(get_db),
):
    redirect, user = _require_admin(request, db)
    if redirect:
        return JSONResponse({"ok": False, "message": "Nicht angemeldet."}, status_code=401)

    from ..services.thesslstore.service import TheSSLStoreService

    svc = get_settings_service(db)
    tsvc = TheSSLStoreService(db, svc)
    ok, msg = tsvc.validate_credentials()
    return JSONResponse({"ok": ok, "message": msg or "Verbindung erfolgreich."})
