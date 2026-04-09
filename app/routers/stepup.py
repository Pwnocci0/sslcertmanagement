"""Router für Step-up-Authentifizierung bei sensiblen Aktionen."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from .. import audit, mfa as mfa_module
from ..auth import login_required, verify_password
from ..database import get_db
from ..stepup import ACTIONS, grant_stepup

router = APIRouter(prefix="/stepup")
from ..templates_config import templates


def _ip(request: Request) -> str:
    return request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown")


@router.get("/verify", response_class=HTMLResponse)
async def stepup_form(request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    action   = request.query_params.get("action", "")
    next_url = request.query_params.get("next", "/")

    return templates.TemplateResponse(
        "stepup/verify.html",
        {
            "request":      request,
            "user":         user,
            "action":       action,
            "action_label": ACTIONS.get(action, action),
            "next_url":     next_url,
            "error":        None,
        },
    )


@router.post("/verify", response_class=HTMLResponse)
async def stepup_submit(
    request: Request,
    db: Session = Depends(get_db),
    action:   str = Form(...),
    next_url: str = Form("/"),
    password: str = Form(...),
    totp_code: str = Form(...),
    reason:   str = Form(""),
):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    def render_error(msg: str):
        return templates.TemplateResponse(
            "stepup/verify.html",
            {
                "request":      request,
                "user":         user,
                "action":       action,
                "action_label": ACTIONS.get(action, action),
                "next_url":     next_url,
                "error":        msg,
            },
            status_code=422,
        )

    # 1. Passwort prüfen
    if not verify_password(password, user.hashed_password):
        audit.log(db, "stepup.failed", "user", user.id,
                  details={"reason": "wrong_password", "stepup_action": action},
                  ip=_ip(request))
        return render_error("Passwort falsch.")

    # 2. TOTP prüfen
    if not user.mfa_secret_encrypted:
        return render_error("Kein MFA-Secret hinterlegt – bitte MFA-Setup durchführen.")

    try:
        secret = mfa_module.decrypt_totp_secret(user.mfa_secret_encrypted)
    except Exception:
        return render_error("MFA-Konfiguration fehlerhaft.")

    if not mfa_module.verify_totp(secret, totp_code.strip()):
        audit.log(db, "stepup.failed", "user", user.id,
                  details={"reason": "wrong_totp", "stepup_action": action},
                  ip=_ip(request))
        return render_error("TOTP-Code ungültig oder abgelaufen.")

    # 3. Step-up gewähren
    grant_stepup(request, action, reason=reason.strip())

    audit.log(db, "stepup.granted", "user", user.id,
              details={"stepup_action": action, "reason": reason.strip()},
              ip=_ip(request))

    return RedirectResponse(url=next_url, status_code=302)
