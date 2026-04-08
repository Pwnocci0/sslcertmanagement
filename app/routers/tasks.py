"""Aufgaben- und Handlungsbedarfs-Ansicht."""
from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from ..auth import get_accessible_customer_ids, login_required, pop_flash
from ..database import get_db
from .. import models

router = APIRouter(prefix="/tasks")
templates = Jinja2Templates(directory="app/templates")

# Ablauf-Schwellen
_THRESHOLDS = [7, 14, 30, 60, 90]


def _severity(days: int) -> str:
    if days <= 7:
        return "critical"
    if days <= 14:
        return "danger"
    if days <= 30:
        return "warning"
    if days <= 60:
        return "info"
    return "secondary"


def build_tasks(db: Session, accessible_customer_ids: list[int] | None = None) -> list[dict]:
    """Sammelt alle offenen Aufgaben / Handlungsbedarfe."""
    now = datetime.utcnow()
    tasks: list[dict] = []

    def _cert_filter(q):
        if accessible_customer_ids is not None:
            q = q.filter(models.Certificate.customer_id.in_(accessible_customer_ids))
        return q

    # ── Ablaufende Zertifikate ────────────────────────────────────────────────
    horizon = now + timedelta(days=_THRESHOLDS[-1])
    expiring = (
        _cert_filter(db.query(models.Certificate))
        .filter(
            models.Certificate.valid_until != None,
            models.Certificate.valid_until <= horizon,
            models.Certificate.valid_until >= now,
            models.Certificate.status != "revoked",
            models.Certificate.is_archived == False,
        )
        .order_by(models.Certificate.valid_until)
        .all()
    )
    for cert in expiring:
        days = (cert.valid_until - now).days
        tasks.append({
            "severity": _severity(days),
            "icon": "bi-clock-history",
            "title": f'Zertifikat läuft ab: {cert.common_name}',
            "detail": f'Gültig bis {cert.valid_until.strftime("%d.%m.%Y")} – noch {days} Tag(e)',
            "url": f"/certificates/{cert.id}",
            "category": "expiry",
            "days": days,
        })

    # ── Abgelaufene Zertifikate (aktiv im System) ─────────────────────────────
    expired = (
        _cert_filter(db.query(models.Certificate))
        .filter(
            models.Certificate.valid_until != None,
            models.Certificate.valid_until < now,
            models.Certificate.status != "revoked",
            models.Certificate.is_archived == False,
        )
        .order_by(models.Certificate.valid_until.desc())
        .all()
    )
    for cert in expired:
        tasks.append({
            "severity": "critical",
            "icon": "bi-x-circle-fill",
            "title": f'Zertifikat ABGELAUFEN: {cert.common_name}',
            "detail": f'Seit {cert.valid_until.strftime("%d.%m.%Y")} abgelaufen – bitte erneuern oder archivieren',
            "url": f"/certificates/{cert.id}",
            "category": "expired",
            "days": 0,
        })

    # ── Zertifikate ohne Chain ────────────────────────────────────────────────
    no_chain = (
        _cert_filter(db.query(models.Certificate))
        .filter(
            models.Certificate.cert_pem != None,
            models.Certificate.cert_pem != "",
            (models.Certificate.chain_pem == None) | (models.Certificate.chain_pem == ""),
            models.Certificate.is_archived == False,
        )
        .all()
    )
    for cert in no_chain:
        tasks.append({
            "severity": "warning",
            "icon": "bi-link-45deg",
            "title": f'Kein Chain-Zertifikat: {cert.common_name}',
            "detail": "Zertifikat ist hochgeladen, aber ohne Intermediate-Chain.",
            "url": f"/certificates/{cert.id}",
            "category": "no_chain",
            "days": None,
        })

    # ── Zertifikate ohne verknüpften CSR (kein Schlüssel im Vault) ───────────
    no_key = (
        _cert_filter(db.query(models.Certificate))
        .filter(
            models.Certificate.csr_request_id == None,
            models.Certificate.is_archived == False,
        )
        .all()
    )
    for cert in no_key:
        tasks.append({
            "severity": "info",
            "icon": "bi-key",
            "title": f'Kein Private Key: {cert.common_name}',
            "detail": "Diesem Zertifikat ist kein CSR / Private Key zugeordnet.",
            "url": f"/certificates/{cert.id}",
            "category": "no_key",
            "days": None,
        })

    # ── Zertifikate mit Status "pending" ──────────────────────────────────────
    pending_certs = (
        _cert_filter(db.query(models.Certificate))
        .filter(
            models.Certificate.status == "pending",
            models.Certificate.is_archived == False,
        )
        .all()
    )
    for cert in pending_certs:
        tasks.append({
            "severity": "info",
            "icon": "bi-hourglass-split",
            "title": f'Ausstehend: {cert.common_name}',
            "detail": "Status ist 'pending' – Zertifikat noch nicht hochgeladen oder bestellt.",
            "url": f"/certificates/{cert.id}",
            "category": "pending_cert",
            "days": None,
        })

    # ── TheSSLStore-Bestellungen mit offenem Status ───────────────────────────
    open_orders = (
        db.query(models.TheSSLStoreOrder)
        .filter(models.TheSSLStoreOrder.status.in_(["pending", "processing"]))
        .all()
    )
    for order in open_orders:
        age = (now - order.created_at).days
        sev = "danger" if age > 7 else "warning"
        tasks.append({
            "severity": sev,
            "icon": "bi-receipt",
            "title": f'Offene Bestellung: {order.thessl_order_id or f"#{ order.id }"}',
            "detail": f'Status: {order.status} – offen seit {age} Tag(en). DCV-Methode: {order.domain_control_method}',
            "url": f"/thesslstore/orders/{order.id}",
            "category": "open_order",
            "days": None,
        })

    # ── Nach Schwere sortieren ────────────────────────────────────────────────
    priority = {"critical": 0, "danger": 1, "warning": 2, "info": 3, "secondary": 4}
    tasks.sort(key=lambda t: (priority.get(t["severity"], 9), t.get("days") or 999))

    return tasks


@router.get("", response_class=HTMLResponse)
async def tasks_index(request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    accessible_ids = get_accessible_customer_ids(user, db)
    tasks = build_tasks(db, accessible_customer_ids=accessible_ids)

    counts = {
        "critical": sum(1 for t in tasks if t["severity"] == "critical"),
        "danger":   sum(1 for t in tasks if t["severity"] == "danger"),
        "warning":  sum(1 for t in tasks if t["severity"] == "warning"),
        "info":     sum(1 for t in tasks if t["severity"] == "info"),
        "total":    len(tasks),
    }

    return templates.TemplateResponse(
        "tasks/index.html",
        {
            "request": request,
            "user":    user,
            "tasks":   tasks,
            "counts":  counts,
            "flash":   pop_flash(request),
        },
    )
