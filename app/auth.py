import bcrypt
from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse
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

    Hat ein Benutzer den Passwort-Schritt bereits erledigt, aber MFA noch nicht,
    wird er zur passenden MFA-Seite weitergeleitet statt zum Login.
    """
    user = get_current_user(request, db)
    if user is not None:
        return user

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


# ── Zugriffssteuerung ─────────────────────────────────────────────────────────

def get_accessible_customer_ids(user: models.User, db: Session) -> list[int] | None:
    """Gibt None für Admins (unbeschränkt) oder eine Liste zugänglicher Kunden-IDs zurück.

    Für Techniker: Kunden aus allen zugewiesenen Kundengruppen.
    Leere Liste wenn keine Gruppen zugewiesen sind.
    """
    if user.is_admin:
        return None

    accessible: set[int] = set()
    for group in user.customer_groups:
        for customer in group.customers:
            accessible.add(customer.id)
    return list(accessible)


def check_customer_access(user: models.User, customer_id: int, db: Session) -> bool:
    """Gibt True zurück wenn der User Zugriff auf den angegebenen Kunden hat."""
    if user.is_admin:
        return True
    ids = get_accessible_customer_ids(user, db)
    return customer_id in ids


def forbidden_response(message: str = "Kein Zugriff auf diese Ressource.") -> HTMLResponse:
    """Gibt eine einfache 403-Antwort zurück."""
    body = f"""<!DOCTYPE html>
<html lang="de"><head><meta charset="UTF-8"><title>403 Forbidden</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
</head><body class="bg-light">
<div class="container py-5 text-center">
  <h1 class="display-4 text-danger"><i class="bi bi-shield-x"></i> 403</h1>
  <p class="lead">{message}</p>
  <a href="/" class="btn btn-primary">Zum Dashboard</a>
</div>
</body></html>"""
    return HTMLResponse(content=body, status_code=403)


# ── Flash-Nachrichten ─────────────────────────────────────────────────────────

def set_flash(request: Request, msg_type: str, message: str) -> None:
    """Speichert eine Flash-Nachricht in der Session (vor einem Redirect)."""
    request.session["flash"] = {"type": msg_type, "msg": message}


def pop_flash(request: Request) -> dict | None:
    """Liest und entfernt die Flash-Nachricht aus der Session."""
    return request.session.pop("flash", None)
