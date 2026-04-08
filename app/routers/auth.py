from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from ..auth import verify_password
from ..database import get_db
from .. import models

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


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
    user = db.query(models.User).filter(models.User.username == username).first()

    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Benutzername oder Passwort ungültig."},
            status_code=401,
        )

    if not user.is_active:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Dieses Konto ist deaktiviert."},
            status_code=403,
        )

    # Passwort korrekt – MFA-Schritt einleiten
    request.session.clear()
    request.session["pre_mfa_user_id"] = user.id

    if user.mfa_setup_completed:
        return RedirectResponse(url="/mfa/verify", status_code=302)
    else:
        return RedirectResponse(url="/mfa/setup", status_code=302)


@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)
