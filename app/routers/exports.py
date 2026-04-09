"""Export-Funktionen: ZIP-Paket und PFX/PKCS#12."""
from __future__ import annotations

import io
import re
import zipfile
from datetime import datetime

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from .. import audit, mfa as mfa_module, models
from ..auth import (
    check_customer_access, forbidden_response,
    login_required, pop_flash, set_flash, verify_password,
)
from ..crypto import decrypt_private_key, generate_pfx
from ..database import get_db
from ..stepup import require_stepup

router = APIRouter(prefix="/exports")
from ..templates_config import templates


def _ip(r): return r.headers.get("X-Forwarded-For", r.client.host if r.client else "unknown")


def _safe_name(cn: str) -> str:
    return re.sub(r"[^\w\.\-]", "_", cn)[:60]


# ── ZIP-Export: Zertifikatspaket ──────────────────────────────────────────────

@router.get("/certificate/{cert_id}/zip", response_class=HTMLResponse)
async def zip_export_form(cert_id: int, request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    cert = db.query(models.Certificate).filter(models.Certificate.id == cert_id).first()
    if not cert:
        set_flash(request, "warning", "Zertifikat nicht gefunden.")
        return RedirectResponse(url="/certificates", status_code=302)

    if not check_customer_access(user, cert.customer_id, db):
        return forbidden_response()

    has_key = bool(cert.csr_request_id and cert.csr_request)

    return templates.TemplateResponse(
        "exports/zip_form.html",
        {"request": request, "user": user, "cert": cert,
         "has_key": has_key, "flash": pop_flash(request)},
    )


@router.post("/certificate/{cert_id}/zip")
async def zip_export_download(
    cert_id: int,
    request: Request,
    db: Session = Depends(get_db),
    include_key: str = Form("off"),
    include_chain: str = Form("on"),
    include_meta: str = Form("on"),
):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    cert = db.query(models.Certificate).filter(models.Certificate.id == cert_id).first()
    if not cert:
        return RedirectResponse(url="/certificates", status_code=302)

    if not check_customer_access(user, cert.customer_id, db):
        return forbidden_response()

    want_key = (include_key == "on")

    # Step-up prüfen wenn Key gewünscht
    if want_key:
        redir = require_stepup(
            request, "zip_export_key",
            next_url=f"/exports/certificate/{cert_id}/zip?include_key=on",
        )
        if redir:
            return redir

    fname_base = _safe_name(cert.common_name)
    buf = io.BytesIO()

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Zertifikat
        if cert.cert_pem:
            zf.writestr(f"{fname_base}.crt", cert.cert_pem)

        # Chain
        if include_chain == "on" and cert.chain_pem:
            zf.writestr(f"{fname_base}.chain.crt", cert.chain_pem)
            # Fullchain (Leaf + Chain in einer Datei, nginx-Standard)
            zf.writestr(f"{fname_base}.fullchain.crt", cert.cert_pem + cert.chain_pem)

        # Private Key (nur mit Step-up)
        if want_key and cert.csr_request:
            try:
                plain_key = decrypt_private_key(cert.csr_request.private_key_encrypted)
                zf.writestr(f"{fname_base}.key", plain_key)
            except Exception as exc:
                set_flash(request, "danger", f"Key-Entschlüsselung fehlgeschlagen: {exc}")
                return RedirectResponse(url=f"/exports/certificate/{cert_id}/zip", status_code=302)

        # Metadaten
        if include_meta == "on":
            meta_lines = [
                f"Common Name:    {cert.common_name}",
                f"SANs:           {cert.san or '–'}",
                f"Issuer:         {cert.issuer or '–'}",
                f"Serial:         {cert.serial_number or '–'}",
                f"Gültig von:     {cert.valid_from.strftime('%d.%m.%Y') if cert.valid_from else '–'}",
                f"Gültig bis:     {cert.valid_until.strftime('%d.%m.%Y') if cert.valid_until else '–'}",
                f"Status:         {cert.status}",
                f"Exportiert am:  {datetime.utcnow().strftime('%d.%m.%Y %H:%M')} UTC",
                f"Exportiert von: {user.username}",
            ]
            if cert.notes:
                meta_lines.append(f"\nHinweise:\n{cert.notes}")
            zf.writestr(f"{fname_base}_info.txt", "\n".join(meta_lines))

    buf.seek(0)

    action_detail = "zip_export_with_key" if want_key else "zip_export"
    audit.log(db, f"cert.{action_detail}", "certificate", user.id,
              entity_id=cert_id,
              details={"cn": cert.common_name, "include_key": want_key},
              ip=_ip(request))

    return Response(
        content=buf.read(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{fname_base}_export.zip"'},
    )


# ── PFX-Export ────────────────────────────────────────────────────────────────

def _pfx_form_response(request, user, cert, errors: list[str], status_code: int = 200):
    """Rendert das PFX-Formular mit optionaler Fehlerliste (kein Redirect)."""
    return templates.TemplateResponse(
        "exports/pfx_form.html",
        {
            "request": request,
            "user": user,
            "cert": cert,
            "errors": errors,
            "has_chain": bool(cert.chain_pem),
            "flash": None,
        },
        status_code=status_code,
    )


@router.get("/certificate/{cert_id}/pfx", response_class=HTMLResponse)
async def pfx_export_form(cert_id: int, request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    cert = db.query(models.Certificate).filter(models.Certificate.id == cert_id).first()
    if not cert:
        set_flash(request, "warning", "Zertifikat nicht gefunden.")
        return RedirectResponse(url="/certificates", status_code=302)

    if not check_customer_access(user, cert.customer_id, db):
        return forbidden_response()

    if not cert.cert_pem or not cert.csr_request_id:
        set_flash(request, "danger",
                  "PFX-Export erfordert ein hochgeladenes Zertifikat und einen verknüpften Private Key.")
        return RedirectResponse(url=f"/certificates/{cert_id}", status_code=302)

    return _pfx_form_response(request, user, cert, errors=[], status_code=200)


@router.post("/certificate/{cert_id}/pfx")
async def pfx_export_download(
    cert_id: int,
    request: Request,
    db: Session = Depends(get_db),
    export_password: str = Form(...),
    export_password2: str = Form(...),
    user_password: str = Form(...),
    totp_code: str = Form(...),
):
    """PFX-Export: validiert Eingaben und Step-up in einem einzigen Schritt.

    Kein Redirect zur /stepup/verify-Seite – Passwort und TOTP werden direkt
    hier geprüft, damit das Export-Passwort nicht doppelt eingegeben werden muss.
    """
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    cert = db.query(models.Certificate).filter(models.Certificate.id == cert_id).first()
    if not cert:
        set_flash(request, "warning", "Zertifikat nicht gefunden.")
        return RedirectResponse(url="/certificates", status_code=302)

    if not cert.cert_pem or not cert.csr_request:
        set_flash(request, "danger", "Zertifikat oder Private Key nicht gefunden.")
        return RedirectResponse(url=f"/certificates/{cert_id}", status_code=302)

    errors: list[str] = []

    # ── 1. Export-Passwort validieren ─────────────────────────────────────────
    if not export_password:
        errors.append("Export-Passwort darf nicht leer sein.")
    elif export_password != export_password2:
        errors.append("Passwörter stimmen nicht überein.")

    # ── 2. Step-up: Benutzerpasswort prüfen ───────────────────────────────────
    if not verify_password(user_password, user.hashed_password):
        audit.log(db, "cert.pfx_export.failed", "certificate", user.id,
                  entity_id=cert_id,
                  details={"reason": "wrong_password", "cn": cert.common_name},
                  ip=_ip(request))
        errors.append("Benutzerpasswort falsch.")

    # ── 3. Step-up: TOTP prüfen ───────────────────────────────────────────────
    if not user.mfa_secret_encrypted:
        errors.append("MFA nicht eingerichtet – bitte zunächst MFA konfigurieren.")
    else:
        try:
            secret = mfa_module.decrypt_totp_secret(user.mfa_secret_encrypted)
        except Exception:
            errors.append("MFA-Konfiguration fehlerhaft.")
        else:
            if not mfa_module.verify_totp(secret, totp_code.strip()):
                audit.log(db, "cert.pfx_export.failed", "certificate", user.id,
                          entity_id=cert_id,
                          details={"reason": "wrong_totp", "cn": cert.common_name},
                          ip=_ip(request))
                errors.append("TOTP-Code ungültig oder abgelaufen.")

    if errors:
        return _pfx_form_response(request, user, cert, errors, status_code=422)

    # ── 4. PFX erzeugen ───────────────────────────────────────────────────────
    try:
        pfx_bytes = generate_pfx(
            cert_pem=cert.cert_pem,
            encrypted_key_pem=cert.csr_request.private_key_encrypted,
            chain_pem=cert.chain_pem or "",
            export_password=export_password,
            friendly_name=cert.common_name,
        )
    except Exception as exc:
        return _pfx_form_response(
            request, user, cert,
            [f"PFX-Erzeugung fehlgeschlagen: {exc}"],
            status_code=500,
        )

    audit.log(db, "cert.pfx_export", "certificate", user.id,
              entity_id=cert_id,
              details={
                  "cn": cert.common_name,
                  "severity": "HIGH",
                  "chain_included": bool(cert.chain_pem),
              },
              ip=_ip(request))

    fname = _safe_name(cert.common_name)
    return Response(
        content=pfx_bytes,
        media_type="application/x-pkcs12",
        headers={"Content-Disposition": f'attachment; filename="{fname}.pfx"'},
    )
