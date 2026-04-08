import bcrypt
from fastapi import Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from . import models


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def get_current_user(request: Request, db: Session) -> models.User | None:
    """Gibt den vollständig authentifizierten User zurück (Passwort + MFA)."""
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return db.query(models.User).filter(
        models.User.id == user_id,
        models.User.is_active == True,
    ).first()


def login_required(request: Request, db: Session):
    """
    Gibt den vollständig authentifizierten User zurück oder eine RedirectResponse.

    Hat ein Benutzer Passwort-Schritt bereits erledigt, aber MFA noch nicht,
    wird er zur passenden MFA-Seite weitergeleitet statt zum Login.
    """
    user = get_current_user(request, db)
    if user is not None:
        return user

    # Benutzer hat Passwort korrekt eingegeben, aber MFA-Schritt noch offen
    pre_mfa_id = request.session.get("pre_mfa_user_id")
    if pre_mfa_id:
        pre_user = db.query(models.User).filter(
            models.User.id == pre_mfa_id,
            models.User.is_active == True,
        ).first()
        if pre_user:
            target = "/mfa/setup" if not pre_user.mfa_setup_completed else "/mfa/verify"
            return RedirectResponse(url=target, status_code=302)

    return RedirectResponse(url="/login", status_code=302)


def set_flash(request: Request, msg_type: str, message: str) -> None:
    """Speichert eine Flash-Nachricht in der Session (vor einem Redirect)."""
    request.session["flash"] = {"type": msg_type, "msg": message}


def pop_flash(request: Request) -> dict | None:
    """Liest und entfernt die Flash-Nachricht aus der Session."""
    return request.session.pop("flash", None)
