"""Let's Encrypt Verwaltung – nur bei lokalem NGINX (Modus A), nur Admins."""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from .. import audit
from ..auth import login_required, pop_flash, set_flash
from ..database import get_db
from ..services.letsencrypt import (
    get_cert_status, get_nginx_status, is_local_nginx,
    next_scheduled_renewal, request_renewal,
)
from ..settings_service import get_settings_service

router = APIRouter(prefix="/letsencrypt")
from ..templates_config import templates

_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$")
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def _require_admin(request, db):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user, None
    if not user.is_admin:
        return RedirectResponse(url="/", status_code=302), None
    return None, user


def _ip(r: Request) -> str:
    return r.headers.get("X-Forwarded-For", r.client.host if r.client else "unknown")


def _build_context(request, user, svc, flash=None):
    enabled = svc.get_bool("letsencrypt.enabled", default=False)
    domain = svc.get_str("letsencrypt.domain", default="")
    email = svc.get_str("letsencrypt.email", default="")
    staging = svc.get_bool("letsencrypt.staging", default=True)
    auto_renew = svc.get_bool("letsencrypt.auto_renew", default=True)

    local_nginx = is_local_nginx()
    cert_status = get_cert_status(domain) if domain else None
    nginx_status = get_nginx_status()

    next_renewal = None
    if cert_status and cert_status.get("valid_until"):
        next_renewal = next_scheduled_renewal(cert_status["valid_until"])

    return {
        "request": request, "user": user,
        "enabled": enabled, "domain": domain, "email": email,
        "staging": staging, "auto_renew": auto_renew,
        "local_nginx": local_nginx,
        "cert_status": cert_status,
        "nginx_status": nginx_status,
        "next_renewal": next_renewal,
        "flash": flash,
    }


@router.get("", response_class=HTMLResponse)
async def le_index(request: Request, db: Session = Depends(get_db)):
    redirect, user = _require_admin(request, db)
    if redirect:
        return redirect

    svc = get_settings_service(db)
    ctx = _build_context(request, user, svc, flash=pop_flash(request))
    return templates.TemplateResponse("letsencrypt/index.html", ctx)


@router.post("/settings")
async def le_save_settings(
    request: Request,
    db: Session = Depends(get_db),
    enabled: str = Form("off"),
    domain: str = Form(""),
    email: str = Form(""),
    staging: str = Form("off"),
    auto_renew: str = Form("off"),
):
    redirect, user = _require_admin(request, db)
    if redirect:
        return redirect

    domain = domain.strip().lower()
    email = email.strip()
    is_enabled = enabled == "on"

    # Validierung nur wenn aktiviert
    if is_enabled:
        if not domain or not _DOMAIN_RE.match(domain):
            set_flash(request, "danger", "Ungültige oder fehlende Domain.")
            return RedirectResponse(url="/letsencrypt", status_code=302)
        if not email or not _EMAIL_RE.match(email):
            set_flash(request, "danger", "Ungültige oder fehlende E-Mail-Adresse.")
            return RedirectResponse(url="/letsencrypt", status_code=302)

    svc = get_settings_service(db)
    svc.set("letsencrypt.enabled", "true" if is_enabled else "false", user_id=user.id)
    svc.set("letsencrypt.domain", domain, user_id=user.id)
    svc.set("letsencrypt.email", email, user_id=user.id)
    svc.set("letsencrypt.staging", "true" if staging == "on" else "false", user_id=user.id)
    svc.set("letsencrypt.auto_renew", "true" if auto_renew == "on" else "false", user_id=user.id)

    audit.log(
        db, "letsencrypt.settings_updated", "letsencrypt", user_id=user.id,
        details={"enabled": is_enabled, "domain": domain, "staging": staging == "on"},
        ip=_ip(request),
    )

    set_flash(request, "success", "Let's Encrypt Einstellungen gespeichert.")
    return RedirectResponse(url="/letsencrypt", status_code=302)


@router.post("/request")
async def le_request_cert(request: Request, db: Session = Depends(get_db)):
    redirect, user = _require_admin(request, db)
    if redirect:
        return redirect

    if not is_local_nginx():
        set_flash(request, "danger", "Let's Encrypt ist nur bei lokalem NGINX (Modus A) verfügbar.")
        return RedirectResponse(url="/letsencrypt", status_code=302)

    svc = get_settings_service(db)
    domain = svc.get_str("letsencrypt.domain", default="")
    if not domain:
        set_flash(request, "danger", "Keine Domain konfiguriert.")
        return RedirectResponse(url="/letsencrypt", status_code=302)

    ok, msg = request_renewal(domain)
    audit.log(
        db, "letsencrypt.renewal_requested", "letsencrypt", user_id=user.id,
        details={"domain": domain, "ok": ok, "msg": msg},
        ip=_ip(request),
    )

    set_flash(request, "success" if ok else "danger", msg)
    return RedirectResponse(url="/letsencrypt", status_code=302)
