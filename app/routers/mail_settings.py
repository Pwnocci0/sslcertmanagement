"""SMTP-Relay-Konfiguration und Testmail-Funktion (nur Admins)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from .. import audit
from ..auth import login_required, pop_flash, set_flash
from ..database import get_db
from ..settings_service import DEFINITIONS, get_settings_service

router = APIRouter(prefix="/mail-settings")
templates = Jinja2Templates(directory="app/templates")

_SMTP_KEYS = [k for k in DEFINITIONS if k.startswith("smtp.")]


def _require_admin(request: Request, db: Session):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user, None
    if not user.is_admin:
        return RedirectResponse(url="/", status_code=302), None
    return None, user


def _ip(r: Request) -> str:
    return r.headers.get("X-Forwarded-For", r.client.host if r.client else "unknown")


@router.get("", response_class=HTMLResponse)
async def mail_settings_index(request: Request, db: Session = Depends(get_db)):
    redir, user = _require_admin(request, db)
    if redir:
        return redir

    svc = get_settings_service(db)
    settings: list[dict] = []
    for key in _SMTP_KEYS:
        defn = DEFINITIONS[key]
        raw = svc.get_raw(key) or defn.default
        settings.append({
            "key": key,
            "label": defn.label,
            "description": defn.description,
            "value_type": defn.value_type,
            "is_sensitive": defn.is_sensitive,
            "value": raw,
            "display_value": "••••••••" if (defn.is_sensitive and raw) else (raw or ""),
        })

    from ..routers.notifications import _last_dispatches
    last_dispatches = _last_dispatches(db, limit=5)

    return templates.TemplateResponse(
        "mail_settings/index.html",
        {
            "request": request,
            "user": user,
            "settings": settings,
            "last_dispatches": last_dispatches,
            "flash": pop_flash(request),
        },
    )


@router.post("/save")
async def mail_settings_save(request: Request, db: Session = Depends(get_db)):
    redir, user = _require_admin(request, db)
    if redir:
        return redir

    form = await request.form()
    svc = get_settings_service(db)

    values: dict[str, str] = {}
    for key in _SMTP_KEYS:
        defn = DEFINITIONS[key]
        if defn.value_type == "bool":
            values[key] = "true" if form.get(key) else "false"
        else:
            raw = str(form.get(key, "")).strip()
            if defn.is_sensitive and not raw:
                continue  # Leerstring = nicht überschreiben
            values[key] = raw

    svc.set_many(values, user_id=user.id)

    audit.log(db, "smtp.settings_saved", "smtp", user.id,
              details={"keys": list(values.keys())},
              ip=_ip(request))

    set_flash(request, "success", "SMTP-Einstellungen gespeichert.")
    return RedirectResponse(url="/mail-settings", status_code=303)


@router.post("/test-mail", response_class=JSONResponse)
async def send_test_mail(
    request: Request,
    to_email: str = Form(...),
    db: Session = Depends(get_db),
):
    redir, user = _require_admin(request, db)
    if redir:
        return JSONResponse({"ok": False, "message": "Nicht angemeldet."}, status_code=401)

    from ..services.mail import MailService

    mail = MailService(db)
    if not mail.is_configured():
        return JSONResponse({
            "ok": False,
            "message": "SMTP nicht konfiguriert. Bitte Host, Absenderadresse und 'Aktiv' prüfen.",
        })

    ok, err = mail.send_test(to_email.strip())

    audit.log(db, "smtp.test_mail_sent", "smtp", user.id,
              details={"to": to_email, "ok": ok, "error": err or None},
              ip=_ip(request))

    if ok:
        return JSONResponse({"ok": True, "message": f"Testmail erfolgreich an {to_email} gesendet."})
    return JSONResponse({"ok": False, "message": f"Versand fehlgeschlagen: {err}"})


@router.post("/trigger-check", response_class=JSONResponse)
async def trigger_notification_check(request: Request, db: Session = Depends(get_db)):
    """Löst den Notification-Check sofort aus (ohne Warten auf Scheduler)."""
    redir, user = _require_admin(request, db)
    if redir:
        return JSONResponse({"ok": False, "message": "Nicht angemeldet."}, status_code=401)

    try:
        from ..services.notification import NotificationService
        svc = NotificationService(db)
        sent, failed = svc.run_checks()
        return JSONResponse({
            "ok": True,
            "message": f"Check abgeschlossen: {sent} gesendet, {failed} fehlgeschlagen.",
        })
    except Exception as exc:
        return JSONResponse({"ok": False, "message": str(exc)})
