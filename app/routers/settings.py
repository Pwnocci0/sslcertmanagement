"""Routen für die zentrale Settings-Verwaltung (nur Admins)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from ..auth import login_required
from ..database import get_db
from ..settings_service import CATEGORY_LABELS, DEFINITIONS, SettingsService, get_settings_service

router = APIRouter(prefix="/settings", tags=["settings"])
templates = Jinja2Templates(directory="app/templates")


def _require_admin(request: Request, db: Session):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user, None
    if not user.is_admin:
        return RedirectResponse(url="/", status_code=302), None
    return None, user


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
    grouped = svc.get_all_by_category()

    flash = request.session.pop("flash", None)

    return templates.TemplateResponse(
        "settings/index.html",
        {
            "request": request,
            "user": user,
            "grouped": grouped,
            "category_labels": CATEGORY_LABELS,
            "flash": flash,
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

    values: dict[str, str] = {}
    for key in DEFINITIONS:
        defn = DEFINITIONS[key]
        if defn.value_type == "bool":
            # Checkboxen werden nur gesendet wenn aktiviert
            values[key] = "true" if form.get(key) else "false"
        elif key in form:
            raw = str(form[key]).strip()
            # Sensitive Felder: Leerstring = nicht überschreiben
            if defn.is_sensitive and not raw:
                continue
            values[key] = raw

    svc.set_many(values, user_id=user.id)
    request.session["flash"] = {"type": "success", "msg": "Einstellungen gespeichert."}
    return RedirectResponse(url="/settings", status_code=303)


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
