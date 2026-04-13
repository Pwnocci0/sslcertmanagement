"""
MFA-Router: Setup und Verifikation.

Alle Routen prüfen session["pre_mfa_user_id"]. Erst nach erfolgreichem
MFA-Schritt wird session["user_id"] gesetzt (vollständige Authentifizierung).
"""
from datetime import datetime

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from .. import models
from ..audit import log as audit_log
from ..database import get_db
from ..mfa import (
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_qr_svg,
    generate_recovery_codes,
    generate_totp_secret,
    get_totp_uri,
    verify_and_consume_recovery_code,
    verify_totp,
)

router = APIRouter(prefix="/mfa")
from ..templates_config import templates


def _get_pre_mfa_user(
    request: Request, db: Session
) -> models.User | RedirectResponse:
    """Gibt den User aus der pre-MFA-Session zurück oder RedirectResponse."""
    uid = request.session.get("pre_mfa_user_id")
    if not uid:
        return RedirectResponse(url="/login", status_code=302)
    user = db.query(models.User).filter(
        models.User.id == uid,
        models.User.is_active == True,
    ).first()
    if not user:
        request.session.clear()
        return RedirectResponse(url="/login", status_code=302)
    return user


def _client_ip(request: Request) -> str:
    ff = request.headers.get("X-Forwarded-For")
    return ff.split(",")[0].strip() if ff else (request.client.host if request.client else "")


# ── MFA-Einrichtung ───────────────────────────────────────────────────────────

@router.get("/setup", response_class=HTMLResponse)
async def mfa_setup_get(request: Request, db: Session = Depends(get_db)):
    user = _get_pre_mfa_user(request, db)
    if isinstance(user, RedirectResponse):
        return user

    # MFA bereits eingerichtet → direkt zur Verifikation
    if user.mfa_setup_completed:
        return RedirectResponse(url="/mfa/verify", status_code=302)

    # TOTP-Secret erzeugen und verschlüsselt speichern (falls noch nicht vorhanden)
    if not user.mfa_secret_encrypted:
        secret = generate_totp_secret()
        user.mfa_secret_encrypted = encrypt_totp_secret(secret)
        db.commit()
    else:
        secret = decrypt_totp_secret(user.mfa_secret_encrypted)

    uri = get_totp_uri(secret, user.username)
    qr_svg = generate_qr_svg(uri)

    return templates.TemplateResponse(
        "mfa/setup.html",
        {
            "request": request,
            "user": user,
            "qr_svg": qr_svg,
            "totp_secret": secret,
            "error": None,
        },
    )


@router.post("/setup")
async def mfa_setup_post(
    request: Request,
    totp_code: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _get_pre_mfa_user(request, db)
    if isinstance(user, RedirectResponse):
        return user

    if user.mfa_setup_completed:
        return RedirectResponse(url="/mfa/verify", status_code=302)

    if not user.mfa_secret_encrypted:
        return RedirectResponse(url="/mfa/setup", status_code=302)

    secret = decrypt_totp_secret(user.mfa_secret_encrypted)

    if not verify_totp(secret, totp_code):
        uri = get_totp_uri(secret, user.username)
        qr_svg = generate_qr_svg(uri)
        return templates.TemplateResponse(
            "mfa/setup.html",
            {
                "request": request,
                "user": user,
                "qr_svg": qr_svg,
                "totp_secret": secret,
                "error": "Ungültiger Code. Bitte erneut versuchen.",
            },
            status_code=422,
        )

    # Code korrekt → MFA einrichten
    plain_codes, hashed_json = generate_recovery_codes()
    user.mfa_setup_completed = True
    user.recovery_codes_json = hashed_json
    user.last_mfa_at = datetime.utcnow()
    db.commit()

    audit_log(
        db,
        action="mfa.setup_completed",
        entity_type="user",
        user_id=user.id,
        entity_id=user.id,
        ip=_client_ip(request),
    )

    # Recovery Codes einmalig in der Session für Anzeige hinterlegen
    request.session["mfa_recovery_codes"] = plain_codes

    return RedirectResponse(url="/mfa/recovery-codes", status_code=302)


# ── Recovery Codes anzeigen ──────────────────────────────────────────────────

@router.get("/recovery-codes", response_class=HTMLResponse)
async def recovery_codes_get(request: Request, db: Session = Depends(get_db)):
    user = _get_pre_mfa_user(request, db)
    if isinstance(user, RedirectResponse):
        return user

    plain_codes = request.session.get("mfa_recovery_codes")
    if not plain_codes:
        # Codes wurden bereits angezeigt oder Seite direkt aufgerufen
        return RedirectResponse(url="/mfa/verify", status_code=302)

    return templates.TemplateResponse(
        "mfa/recovery_codes.html",
        {
            "request": request,
            "user": user,
            "recovery_codes": plain_codes,
        },
    )


@router.post("/recovery-codes/confirm")
async def recovery_codes_confirm(
    request: Request,
    db: Session = Depends(get_db),
):
    user = _get_pre_mfa_user(request, db)
    if isinstance(user, RedirectResponse):
        return user

    # Recovery Codes aus Session entfernen
    request.session.pop("mfa_recovery_codes", None)

    # Vollständige Authentifizierung abschließen
    uid = request.session.pop("pre_mfa_user_id", None)
    request.session["user_id"] = uid
    request.session["username"] = user.username

    # UserSession anlegen
    from ..services.session_manager import create_session as _create_session
    ip = _client_ip(request)
    ua = request.headers.get("User-Agent", "")
    token = _create_session(db, uid, ip, ua)
    request.session["session_id"] = token

    return RedirectResponse(url="/", status_code=302)


# ── MFA-Verifikation (2. Faktor) ─────────────────────────────────────────────

@router.get("/verify", response_class=HTMLResponse)
async def mfa_verify_get(request: Request, db: Session = Depends(get_db)):
    user = _get_pre_mfa_user(request, db)
    if isinstance(user, RedirectResponse):
        return user

    # MFA noch nicht eingerichtet → zurück zum Setup
    if not user.mfa_setup_completed:
        return RedirectResponse(url="/mfa/setup", status_code=302)

    return templates.TemplateResponse(
        "mfa/verify.html",
        {"request": request, "user": user, "error": None, "use_recovery": False},
    )


@router.post("/verify")
async def mfa_verify_post(
    request: Request,
    totp_code: str = Form(""),
    recovery_code: str = Form(""),
    db: Session = Depends(get_db),
):
    user = _get_pre_mfa_user(request, db)
    if isinstance(user, RedirectResponse):
        return user

    if not user.mfa_setup_completed or not user.mfa_secret_encrypted:
        return RedirectResponse(url="/mfa/setup", status_code=302)

    authenticated = False
    used_recovery = False

    # ① TOTP prüfen
    if totp_code.strip():
        secret = decrypt_totp_secret(user.mfa_secret_encrypted)
        authenticated = verify_totp(secret, totp_code)

    # ② Recovery Code prüfen (nur wenn kein gültiger TOTP)
    elif recovery_code.strip() and user.recovery_codes_json:
        valid, updated_json = verify_and_consume_recovery_code(
            recovery_code, user.recovery_codes_json
        )
        if valid:
            user.recovery_codes_json = updated_json
            db.commit()
            authenticated = True
            used_recovery = True

    if not authenticated:
        return templates.TemplateResponse(
            "mfa/verify.html",
            {
                "request": request,
                "user": user,
                "error": "Ungültiger Code. Bitte erneut versuchen.",
                "use_recovery": bool(recovery_code.strip()),
            },
            status_code=422,
        )

    # Vollständig authentifiziert
    user.last_mfa_at = datetime.utcnow()
    db.commit()

    audit_log(
        db,
        action="mfa.recovery_code_used" if used_recovery else "mfa.login",
        entity_type="user",
        user_id=user.id,
        entity_id=user.id,
        ip=_client_ip(request),
    )

    uid = request.session.pop("pre_mfa_user_id", None)
    request.session["user_id"] = uid
    request.session["username"] = user.username

    # UserSession anlegen für Sitzungsverwaltung
    from ..services.session_manager import create_session as _create_session
    ip = _client_ip(request)
    ua = request.headers.get("User-Agent", "")
    token = _create_session(db, uid, ip, ua)
    request.session["session_id"] = token

    return RedirectResponse(url="/", status_code=302)
