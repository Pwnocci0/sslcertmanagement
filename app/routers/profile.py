"""Benutzerprofil – Passwort ändern, MFA-Link."""
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from .. import models
from ..auth import hash_password, login_required, pop_flash, set_flash, verify_password
from ..database import get_db
from ..settings_service import get_settings_service

router = APIRouter(prefix="/profile")
from ..templates_config import templates


@router.get("", response_class=HTMLResponse)
async def profile_view(request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    return templates.TemplateResponse(
        "profile/index.html",
        {"request": request, "user": user, "error": None, "flash": pop_flash(request)},
    )


@router.post("/change-password")
async def profile_change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    new_password2: str = Form(...),
    db: Session = Depends(get_db),
):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    def _err(msg: str):
        return templates.TemplateResponse(
            "profile/index.html",
            {"request": request, "user": user, "error": msg, "flash": None},
            status_code=422,
        )

    if not verify_password(current_password, user.hashed_password):
        return _err("Aktuelles Passwort ist falsch.")

    if new_password != new_password2:
        return _err("Neue Passwörter stimmen nicht überein.")

    svc = get_settings_service(db)
    min_len = svc.get_int("security.min_password_length", default=12)
    if len(new_password) < min_len:
        return _err(f"Das neue Passwort muss mindestens {min_len} Zeichen lang sein.")

    user.hashed_password = hash_password(new_password)
    db.commit()
    set_flash(request, "success", "Passwort wurde geändert.")
    return RedirectResponse(url="/profile", status_code=302)
