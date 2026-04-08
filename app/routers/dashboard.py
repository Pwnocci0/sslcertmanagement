from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from ..auth import login_required, pop_flash
from ..database import get_db
from .. import models

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

# Ablauf-Schwellen in Tagen
_THRESHOLDS = (14, 30, 60)


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    now = datetime.utcnow()

    # ── Filter-Parameter aus Query-String ────────────────────────────────
    f_customer = request.query_params.get("customer_id", "")
    f_status   = request.query_params.get("status", "")
    f_days     = request.query_params.get("days", "60")

    try:
        days_window = int(f_days)
    except (ValueError, TypeError):
        days_window = 60

    # ── Zeitgrenzen ──────────────────────────────────────────────────────
    dt = {d: now + timedelta(days=d) for d in _THRESHOLDS}

    # ── Globale Statistiken (ungefiltert) ────────────────────────────────
    def _count(q):
        return q.count()

    cq = db.query(models.Certificate).filter(models.Certificate.is_archived == False)
    stats = {
        # Infrastruktur
        "customers":       _count(db.query(models.Customer).filter(models.Customer.is_archived == False)),
        "domains":         _count(db.query(models.Domain)),
        # Zertifikate nach Status
        "certs_total":     _count(cq),
        "certs_active":    _count(cq.filter(models.Certificate.status == "active")),
        "certs_expiring":  _count(cq.filter(models.Certificate.status == "expiring_soon")),
        "certs_pending":   _count(cq.filter(models.Certificate.status == "pending")),
        "certs_expired":   _count(cq.filter(models.Certificate.status == "expired")),
        "certs_revoked":   _count(cq.filter(models.Certificate.status == "revoked")),
        "certs_no_key":    _count(cq.filter(models.Certificate.csr_request_id == None)),
        # Ablauf-Schwellen (gültige Certs die innerhalb des Fensters ablaufen)
        "exp_14": _count(cq.filter(models.Certificate.valid_until > now, models.Certificate.valid_until <= dt[14])),
        "exp_30": _count(cq.filter(models.Certificate.valid_until > now, models.Certificate.valid_until <= dt[30])),
        "exp_60": _count(cq.filter(models.Certificate.valid_until > now, models.Certificate.valid_until <= dt[60])),
        # CSRs
        "csrs_total": _count(db.query(models.CsrRequest)),
    }

    # ── Offene Vorgänge ──────────────────────────────────────────────────
    # Jeder Eintrag: type (Bootstrap-Farbe), icon, label, link
    open_items = []

    if stats["exp_14"]:
        n = stats["exp_14"]
        open_items.append({
            "type": "danger", "icon": "bi-exclamation-octagon-fill",
            "label": f"{n} Zertifikat{'e' if n != 1 else ''} laufen in weniger als 14 Tagen ab",
            "link": "/?days=14",
        })

    between_14_30 = stats["exp_30"] - stats["exp_14"]
    if between_14_30 > 0:
        n = between_14_30
        open_items.append({
            "type": "warning", "icon": "bi-exclamation-triangle-fill",
            "label": f"{n} Zertifikat{'e' if n != 1 else ''} laufen in 14–30 Tagen ab",
            "link": "/?days=30",
        })

    if stats["certs_expired"]:
        n = stats["certs_expired"]
        open_items.append({
            "type": "danger", "icon": "bi-x-circle-fill",
            "label": f"{n} abgelaufen{'es' if n == 1 else 'e'} Zertifikat{'e' if n != 1 else ''}",
            "link": "/certificates",
        })

    if stats["certs_pending"]:
        n = stats["certs_pending"]
        open_items.append({
            "type": "info", "icon": "bi-hourglass-split",
            "label": f"{n} ausstehend{'es' if n == 1 else 'e'} Zertifikat{'e' if n != 1 else ''} (pending)",
            "link": "/certificates",
        })

    if stats["certs_no_key"]:
        n = stats["certs_no_key"]
        open_items.append({
            "type": "secondary", "icon": "bi-key",
            "label": f"{n} Zertifikat{'e' if n != 1 else ''} ohne verknüpften Private Key",
            "link": "/certificates",
        })

    # ── Zertifikate-Tabelle (gefiltert) ──────────────────────────────────
    cert_q = db.query(models.Certificate).join(models.Customer).filter(models.Certificate.is_archived == False)

    # Ablauf-Fenster
    window_dt = now + timedelta(days=days_window)
    cert_q = cert_q.filter(
        models.Certificate.valid_until > now,
        models.Certificate.valid_until <= window_dt,
    )

    if f_customer.isdigit():
        cert_q = cert_q.filter(models.Certificate.customer_id == int(f_customer))

    if f_status and f_status in models.CERT_STATUS_CHOICES:
        cert_q = cert_q.filter(models.Certificate.status == f_status)

    expiring_certs = cert_q.order_by(models.Certificate.valid_until).all()

    # Kunden für Filter-Dropdown
    customers = (
        db.query(models.Customer)
        .filter(models.Customer.is_archived == False)
        .order_by(models.Customer.name)
        .all()
    )

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "stats": stats,
            "open_items": open_items,
            "expiring_certs": expiring_certs,
            "customers": customers,
            "status_choices": models.CERT_STATUS_CHOICES,
            "f_customer": f_customer,
            "f_status": f_status,
            "f_days": str(days_window),
            "flash": pop_flash(request),
        },
    )
