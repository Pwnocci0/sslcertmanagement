"""Routen für die zentrale Settings-Verwaltung (nur Admins)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from .. import audit
from ..auth import login_required, pop_flash, set_flash
from ..database import get_db
from ..settings_service import CATEGORY_LABELS, DEFINITIONS, get_settings_service

router = APIRouter(prefix="/settings", tags=["settings"])
templates = Jinja2Templates(directory="app/templates")


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
    # SMTP → /mail-settings, TheSSLStore → /settings/integrations
    excluded = {"smtp", "thesslstore"}
    grouped = {k: v for k, v in grouped_all.items() if k not in excluded}
    category_labels = {k: v for k, v in CATEGORY_LABELS.items() if k not in excluded}

    return templates.TemplateResponse(
        "settings/index.html",
        {
            "request": request,
            "user": user,
            "grouped": grouped,
            "category_labels": category_labels,
            "flash": pop_flash(request),
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
        if defn.value_type == "bool":
            values[key] = "true" if form.get(key) else "false"
        elif key in form:
            raw = str(form[key]).strip()
            if defn.is_sensitive and not raw:
                continue
            values[key] = raw

    svc.set_many(values, user_id=user.id)
    audit.log(db, "settings.saved", "settings", user.id, ip=_ip(request))
    set_flash(request, "success", "Einstellungen gespeichert.")
    return RedirectResponse(url=redirect_to, status_code=303)


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
