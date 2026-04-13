"""Sicherheits-Dashboard: Sitzungen, Login-Schutz, fail2ban-Status."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from .. import audit, models
from ..auth import login_required, pop_flash, set_flash, forbidden_response
from ..database import get_db
from ..settings_service import get_settings_service, DEFINITIONS

router = APIRouter(prefix="/security")
from ..templates_config import templates

# Settings-Keys, die auf dieser Seite bearbeitbar sind
_SECURITY_KEYS = {
    "security.max_login_attempts",
    "security.lockout_window_minutes",
    "security.session_timeout_hours",
    "security.min_password_length",
    "security.mfa_required",
    "security.allow_recovery_regen",
    "security.stepup_duration_seconds",
}


def _client_ip(request: Request) -> str:
    ff = request.headers.get("X-Forwarded-For")
    return ff.split(",")[0].strip() if ff else (request.client.host if request.client else "")


@router.get("", response_class=HTMLResponse)
async def security_index(request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user
    if not user.is_admin:
        return forbidden_response("Diese Seite ist nur für Administratoren zugänglich.")

    from ..services.login_protection import get_recent_stats, get_recent_attempts
    from ..services.session_manager import get_active_sessions
    from ..services import fail2ban as fb

    svc = get_settings_service(db)

    # Statistiken
    stats_24h = get_recent_stats(db, hours=24)
    recent_attempts = get_recent_attempts(db, limit=50)
    active_sessions = get_active_sessions(db)
    current_token = request.session.get("session_id", "")

    # fail2ban
    fb_available = fb.is_available()
    fb_status = fb.get_status() if fb_available else {"jails": [], "error": None}

    # Security-Settings
    security_settings = []
    for key in sorted(_SECURITY_KEYS):
        defn = DEFINITIONS.get(key)
        if defn:
            security_settings.append({
                "key": key,
                "label": defn.label,
                "description": defn.description,
                "value_type": defn.value_type,
                "value": svc.get_raw(key) or defn.default,
            })

    return templates.TemplateResponse(
        "security/index.html",
        {
            "request": request,
            "user": user,
            "flash": pop_flash(request),
            "stats_24h": stats_24h,
            "recent_attempts": recent_attempts,
            "active_sessions": active_sessions,
            "current_token": current_token,
            "fb_available": fb_available,
            "fb_status": fb_status,
            "security_settings": security_settings,
        },
    )


@router.get("/fail2ban/jail/{jail}", response_class=HTMLResponse)
async def fail2ban_jail_detail(jail: str, request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user
    if not user.is_admin:
        return forbidden_response()

    from ..services import fail2ban as fb
    jail_data = fb.get_jail_status(jail)

    return templates.TemplateResponse(
        "security/fail2ban_jail.html",
        {
            "request": request,
            "user": user,
            "jail": jail,
            "jail_data": jail_data,
        },
    )


@router.post("/sessions/{session_id}/revoke")
async def revoke_session(
    session_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user
    if not user.is_admin:
        return forbidden_response()

    from ..services.session_manager import revoke_session as _revoke
    sess = db.query(models.UserSession).filter(models.UserSession.id == session_id).first()
    if sess:
        _revoke(db, session_id)
        audit.log(
            db,
            action="security.session_revoked",
            entity_type="user_session",
            user_id=user.id,
            entity_id=session_id,
            details={"target_user_id": sess.user_id},
            ip=_client_ip(request),
        )
        set_flash(request, "success", f"Sitzung #{session_id} wurde widerrufen.")
    else:
        set_flash(request, "danger", "Sitzung nicht gefunden.")

    return RedirectResponse(url="/security#sessions", status_code=302)


@router.post("/sessions/revoke-all-for-user/{user_id}")
async def revoke_all_sessions_for_user(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user
    if not user.is_admin:
        return forbidden_response()

    from ..services.session_manager import revoke_all_for_user
    current_token = request.session.get("session_id", "")
    # Eigene Session nicht widerrufen falls es die eigene ist
    except_token = current_token if user.id == user_id else None
    count = revoke_all_for_user(db, user_id, except_token=except_token)
    audit.log(
        db,
        action="security.sessions_revoked_all",
        entity_type="user",
        user_id=user.id,
        entity_id=user_id,
        details={"count": count},
        ip=_client_ip(request),
    )
    set_flash(request, "success", f"{count} Sitzung(en) für Benutzer #{user_id} widerrufen.")
    return RedirectResponse(url="/security#sessions", status_code=302)


@router.post("/settings")
async def save_security_settings(
    request: Request,
    db: Session = Depends(get_db),
):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user
    if not user.is_admin:
        return forbidden_response()

    form = await request.form()
    svc = get_settings_service(db)

    updates: dict[str, str] = {}
    for key in _SECURITY_KEYS:
        defn = DEFINITIONS.get(key)
        if not defn:
            continue
        if defn.value_type == "bool":
            updates[key] = "true" if form.get(key) == "on" else "false"
        else:
            val = form.get(key, "")
            updates[key] = str(val).strip()

    svc.set_many(updates, user_id=user.id)
    audit.log(
        db,
        action="security.settings_updated",
        entity_type="settings",
        user_id=user.id,
        details={"keys": list(updates.keys())},
        ip=_client_ip(request),
    )
    set_flash(request, "success", "Sicherheitseinstellungen wurden gespeichert.")
    return RedirectResponse(url="/security#settings", status_code=302)
