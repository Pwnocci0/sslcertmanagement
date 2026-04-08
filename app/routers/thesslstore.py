"""Routen für die TheSSLStore-Integration (nur Admins)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from ..auth import login_required, set_flash
from ..database import get_db
from .. import models
from ..settings_service import get_settings_service, is_integration_enabled
from ..services.thesslstore.service import TheSSLStoreService
from ..services.thesslstore.exceptions import TheSSLStoreError

router = APIRouter(prefix="/thesslstore", tags=["thesslstore"])
templates = Jinja2Templates(directory="app/templates")


def _require_admin(request: Request, db: Session):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user, None
    if not user.is_admin:
        return RedirectResponse(url="/", status_code=302), None
    return None, user


def _require_integration(request: Request, db: Session):
    """Gibt None zurück wenn Integration aktiv, sonst einen Redirect."""
    if not is_integration_enabled("thesslstore", db):
        set_flash(request, "warning",
                  "TheSSLStore-Integration ist deaktiviert. "
                  "Bitte aktivieren Sie die Integration unter Einstellungen → Integrationen.")
        return RedirectResponse(url="/settings/integrations", status_code=302)
    return None


def _get_service(db: Session) -> TheSSLStoreService:
    svc = get_settings_service(db)
    return TheSSLStoreService(db, svc)


# ── GET /thesslstore ──────────────────────────────────────────────────────────

@router.get("", response_class=HTMLResponse)
async def index(
    request: Request,
    db: Session = Depends(get_db),
):
    redirect, user = _require_admin(request, db)
    if redirect:
        return redirect
    if redir := _require_integration(request, db):
        return redir

    tsvc = _get_service(db)
    products = tsvc.get_products()
    orders = tsvc.get_orders()
    flash = request.session.pop("flash", None)

    return templates.TemplateResponse(
        "thesslstore/index.html",
        {
            "request": request,
            "user": user,
            "products": products,
            "orders": orders,
            "flash": flash,
        },
    )


# ── POST /thesslstore/sync-products ──────────────────────────────────────────

@router.post("/sync-products", response_class=HTMLResponse)
async def sync_products(
    request: Request,
    db: Session = Depends(get_db),
):
    redirect, user = _require_admin(request, db)
    if redirect:
        return redirect
    if redir := _require_integration(request, db):
        return redir

    tsvc = _get_service(db)
    try:
        count = tsvc.sync_products()
        request.session["flash"] = {
            "type": "success",
            "msg": f"{count} Produkte synchronisiert.",
        }
    except TheSSLStoreError as exc:
        request.session["flash"] = {"type": "danger", "msg": str(exc)}

    return RedirectResponse(url="/thesslstore", status_code=303)


# ── GET /thesslstore/orders/{order_id} ───────────────────────────────────────

@router.get("/orders/{order_id}", response_class=HTMLResponse)
async def order_detail(
    order_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    redirect, user = _require_admin(request, db)
    if redirect:
        return redirect

    tsvc = _get_service(db)
    order = tsvc.get_order_by_id(order_id)
    if not order:
        request.session["flash"] = {"type": "warning", "msg": "Bestellung nicht gefunden."}
        return RedirectResponse(url="/thesslstore", status_code=302)

    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(
        "thesslstore/order_detail.html",
        {
            "request": request,
            "user": user,
            "order": order,
            "flash": flash,
        },
    )


# ── POST /thesslstore/orders/{order_id}/refresh ───────────────────────────────

@router.post("/orders/{order_id}/refresh", response_class=HTMLResponse)
async def refresh_order(
    order_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    redirect, user = _require_admin(request, db)
    if redirect:
        return redirect

    tsvc = _get_service(db)
    order = tsvc.get_order_by_id(order_id)
    if not order:
        request.session["flash"] = {"type": "warning", "msg": "Bestellung nicht gefunden."}
        return RedirectResponse(url="/thesslstore", status_code=302)

    try:
        tsvc.refresh_order_status(order)
        request.session["flash"] = {"type": "success", "msg": "Status aktualisiert."}
    except TheSSLStoreError as exc:
        request.session["flash"] = {"type": "danger", "msg": str(exc)}

    return RedirectResponse(url=f"/thesslstore/orders/{order_id}", status_code=303)


# ── GET /thesslstore/new-order (Formular) ─────────────────────────────────────

@router.get("/new-order", response_class=HTMLResponse)
async def new_order_form(
    request: Request,
    certificate_id: int | None = None,
    db: Session = Depends(get_db),
):
    redirect, user = _require_admin(request, db)
    if redirect:
        return redirect

    tsvc = _get_service(db)
    products = tsvc.get_products()

    cert = None
    csr = None
    approver_emails: list[str] = []

    if certificate_id:
        cert = db.query(models.Certificate).filter(
            models.Certificate.id == certificate_id
        ).first()
        if cert and cert.csr_request_id:
            csr = db.query(models.CsrRequest).filter(
                models.CsrRequest.id == cert.csr_request_id
            ).first()
            if csr:
                try:
                    approver_emails = tsvc.get_approver_emails(csr.common_name)
                except TheSSLStoreError:
                    approver_emails = []

    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(
        "thesslstore/new_order.html",
        {
            "request": request,
            "user": user,
            "products": products,
            "cert": cert,
            "csr": csr,
            "approver_emails": approver_emails,
            "flash": flash,
        },
    )


# ── POST /thesslstore/new-order ───────────────────────────────────────────────

@router.post("/new-order", response_class=HTMLResponse)
async def new_order_submit(
    request: Request,
    db: Session = Depends(get_db),
    certificate_id: int = Form(...),
    sku: str = Form(...),
    approver_email: str = Form(""),
    validity_period: int = Form(12),
    san_count: int = Form(0),
    server_count: int = Form(1),
    dcv_method: str = Form("EMAIL"),    # EMAIL | HTTP | HTTPS | CNAME
):
    redirect, user = _require_admin(request, db)
    if redirect:
        return redirect

    cert = db.query(models.Certificate).filter(
        models.Certificate.id == certificate_id
    ).first()
    if not cert or not cert.csr_request_id:
        request.session["flash"] = {
            "type": "danger",
            "msg": "Kein CSR mit diesem Zertifikat verknüpft.",
        }
        return RedirectResponse(
            url=f"/thesslstore/new-order?certificate_id={certificate_id}",
            status_code=303,
        )

    csr = db.query(models.CsrRequest).filter(
        models.CsrRequest.id == cert.csr_request_id
    ).first()

    tsvc = _get_service(db)
    try:
        order = tsvc.new_order(
            certificate_id=certificate_id,
            sku=sku,
            csr_pem=csr.csr_pem,
            domain_name=csr.common_name,
            approver_email=approver_email,
            validity_period=validity_period,
            san_count=san_count,
            server_count=server_count,
            dcv_method=dcv_method,
        )
        request.session["flash"] = {
            "type": "success",
            "msg": f"Bestellung angelegt: {order.thessl_order_id}",
        }
        return RedirectResponse(url=f"/thesslstore/orders/{order.id}", status_code=303)
    except TheSSLStoreError as exc:
        request.session["flash"] = {"type": "danger", "msg": f"Bestellung fehlgeschlagen: {exc}"}
        return RedirectResponse(
            url=f"/thesslstore/new-order?certificate_id={certificate_id}",
            status_code=303,
        )


# ── AJAX: Approver-E-Mails für eine Domain ───────────────────────────────────

@router.get("/approver-emails", response_class=JSONResponse)
async def approver_emails(
    domain: str,
    product_code: str = "",
    request: Request = None,
    db: Session = Depends(get_db),
):
    tsvc = _get_service(db)
    try:
        emails = tsvc.get_approver_emails(domain, product_code)
        return JSONResponse({"ok": True, "emails": emails})
    except TheSSLStoreError as exc:
        return JSONResponse({"ok": False, "message": str(exc)})
