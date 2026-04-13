from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from ..auth import verify_password
from ..database import get_db
from .. import models, audit

router = APIRouter()
from ..templates_config import templates


def _client_ip(request: Request) -> str:
    ff = request.headers.get("X-Forwarded-For")
    return ff.split(",")[0].strip() if ff else (request.client.host if request.client else "")


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, db: Session = Depends(get_db)):
    # Bereits vollständig eingeloggt
    if request.session.get("user_id"):
        return RedirectResponse(url="/", status_code=302)
    # Passwort bereits ok, MFA steht noch aus
    pre_mfa_id = request.session.get("pre_mfa_user_id")
    if pre_mfa_id:
        user = db.query(models.User).filter(models.User.id == pre_mfa_id).first()
        if user:
            target = "/mfa/setup" if not user.mfa_setup_completed else "/mfa/verify"
            return RedirectResponse(url=target, status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@router.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    from ..settings_service import get_settings_service
    from ..services.login_protection import (
        is_locked_out, record_attempt, clear_attempts_for_user,
    )

    ip = _client_ip(request)
    svc = get_settings_service(db)
    max_attempts = svc.get_int("security.max_login_attempts", default=0)
    window = svc.get_int("security.lockout_window_minutes", default=15)

    # Aussperrung prüfen
    if is_locked_out(db, username, ip, max_attempts, window):
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": (
                    f"Zu viele fehlgeschlagene Versuche. "
                    f"Bitte warte {window} Minuten und versuche es erneut."
                ),
            },
            status_code=429,
        )

    user = db.query(models.User).filter(models.User.username == username).first()

    if not user or not verify_password(password, user.hashed_password):
        record_attempt(db, username, ip, success=False)
        audit.log(
            db, action="auth.login_failed", entity_type="user",
            details={"username": username}, ip=ip,
        )
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Benutzername oder Passwort ungültig."},
            status_code=401,
        )

    if not user.is_active:
        record_attempt(db, username, ip, success=False)
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Dieses Konto ist deaktiviert."},
            status_code=403,
        )

    # Passwort korrekt
    record_attempt(db, username, ip, success=True)
    clear_attempts_for_user(db, username)

    # MFA-Schritt einleiten
    request.session.clear()
    request.session["pre_mfa_user_id"] = user.id

    if user.mfa_setup_completed:
        return RedirectResponse(url="/mfa/verify", status_code=302)
    else:
        return RedirectResponse(url="/mfa/setup", status_code=302)


@router.get("/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    # Session in DB invalidieren wenn vorhanden
    session_token = request.session.get("session_id")
    if session_token:
        from ..services.session_manager import validate_session
        sess = validate_session(db, session_token)
        if sess:
            sess.is_active = False
            db.commit()
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)
