"""Analytics und Reporting – Zertifikats- und Sicherheitsberichte."""
from __future__ import annotations

import csv
import io
import json
from collections import Counter
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from .. import models
from ..auth import get_accessible_customer_ids, login_required, pop_flash
from ..database import get_db
from ..services import fail2ban as fb_svc

router = APIRouter(prefix="/analytics")
from ..templates_config import templates


def _ip(r: Request) -> str:
    return r.headers.get("X-Forwarded-For", r.client.host if r.client else "unknown")


def _cert_stats(db: Session, accessible_ids) -> dict:
    """Zertifikats-Statistiken für Charts und Tabellen."""
    now = datetime.utcnow()

    q = db.query(models.Certificate).filter(models.Certificate.is_archived == False)
    if accessible_ids is not None:
        q = q.filter(models.Certificate.customer_id.in_(accessible_ids))

    all_certs = q.all()

    status_counts = Counter(c.status for c in all_certs)
    issuer_counts = Counter((c.issuer or "Unbekannt") for c in all_certs)

    # Pro Kunde (top 10)
    cust_map: dict[str, int] = {}
    for c in all_certs:
        name = c.customer.name if c.customer else "Kein Kunde"
        cust_map[name] = cust_map.get(name, 0) + 1
    top_customers = sorted(cust_map.items(), key=lambda x: -x[1])[:10]

    # Ablauf-Buckets
    buckets = {"Abgelaufen": 0, "< 14 Tage": 0, "14–30 Tage": 0,
               "30–60 Tage": 0, "60–90 Tage": 0, "> 90 Tage": 0, "Unbekannt": 0}
    for c in all_certs:
        if c.valid_until is None:
            buckets["Unbekannt"] += 1
        elif c.valid_until < now:
            buckets["Abgelaufen"] += 1
        else:
            d = (c.valid_until - now).days
            if d < 14:
                buckets["< 14 Tage"] += 1
            elif d < 30:
                buckets["14–30 Tage"] += 1
            elif d < 60:
                buckets["30–60 Tage"] += 1
            elif d < 90:
                buckets["60–90 Tage"] += 1
            else:
                buckets["> 90 Tage"] += 1

    return {
        "total": len(all_certs),
        "status_counts": dict(status_counts),
        "issuer_counts": dict(issuer_counts.most_common(8)),
        "top_customers": top_customers,
        "expiry_buckets": buckets,
    }


def _security_stats(db: Session) -> dict:
    """Sicherheits-Statistiken (nur Admins)."""
    now = datetime.utcnow()
    since_30 = now - timedelta(days=30)
    since_14 = now - timedelta(days=14)

    total_users = db.query(models.User).filter(models.User.is_active == True).count()
    mfa_users = db.query(models.User).filter(
        models.User.is_active == True, models.User.mfa_setup_completed == True,
    ).count()
    mfa_pct = round(mfa_users / total_users * 100) if total_users else 0

    # Login-Statistiken (30 Tage)
    login_total = db.query(models.LoginAttempt).filter(
        models.LoginAttempt.created_at >= since_30
    ).count()
    login_failed = db.query(models.LoginAttempt).filter(
        models.LoginAttempt.created_at >= since_30,
        models.LoginAttempt.success == False,
    ).count()

    # Kritische Audit-Ereignisse
    critical_actions = [
        "csr.download_key_plain", "cert.export_pfx",
        "backup.restored", "user.admin_granted",
    ]
    critical_events = db.query(models.AuditLog).filter(
        models.AuditLog.created_at >= since_30,
        models.AuditLog.action.in_(critical_actions),
    ).count()

    # Audit-Events pro Tag (letzte 14 Tage)
    events_per_day: dict[str, int] = {}
    for i in range(14):
        day = (now - timedelta(days=13 - i)).date()
        events_per_day[str(day)] = 0

    rows = db.query(
        func.date(models.AuditLog.created_at).label("day"),
        func.count().label("cnt"),
    ).filter(
        models.AuditLog.created_at >= since_14
    ).group_by(func.date(models.AuditLog.created_at)).all()

    for row in rows:
        k = str(row.day)
        if k in events_per_day:
            events_per_day[k] = row.cnt

    fail2ban_status = fb_svc.get_status()

    return {
        "total_users": total_users,
        "mfa_users": mfa_users,
        "mfa_pct": mfa_pct,
        "login_total": login_total,
        "login_failed": login_failed,
        "login_success": login_total - login_failed,
        "critical_events": critical_events,
        "events_per_day": events_per_day,
        "fail2ban": fail2ban_status,
    }


def _backup_stats(db: Session) -> dict:
    """Backup-Statistiken für den Infra-Bereich."""
    from ..services.system_status import get_backup_summary
    return get_backup_summary(db)


@router.get("", response_class=HTMLResponse)
async def analytics_index(request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    accessible_ids = get_accessible_customer_ids(user, db)
    cert_data = _cert_stats(db, accessible_ids)
    security_data = _security_stats(db) if user.is_admin else None
    backup_data = _backup_stats(db) if user.is_admin else None

    # LE-Status für Infra-Tab (nur Admin + Modus A)
    le_status = None
    if user.is_admin:
        from ..services.letsencrypt import get_cert_status, is_local_nginx
        from ..settings_service import get_settings_service
        svc = get_settings_service(db)
        if svc.get_bool("letsencrypt.enabled", default=False) and is_local_nginx():
            domain = svc.get_str("letsencrypt.domain", default="")
            le_status = get_cert_status(domain) if domain else None

    return templates.TemplateResponse(
        "analytics/index.html",
        {
            "request": request, "user": user,
            "cert_data": cert_data,
            "security_data": security_data,
            "backup_data": backup_data,
            "le_status": le_status,
            "flash": pop_flash(request),
        },
    )


@router.get("/export/certs.csv")
async def export_certs_csv(request: Request, db: Session = Depends(get_db)):
    """Exportiert Zertifikats-Daten als CSV."""
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    accessible_ids = get_accessible_customer_ids(user, db)
    q = db.query(models.Certificate).filter(models.Certificate.is_archived == False)
    if accessible_ids is not None:
        q = q.filter(models.Certificate.customer_id.in_(accessible_ids))
    certs = q.order_by(models.Certificate.valid_until).all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ID", "Domain", "Kunde", "Status", "Aussteller", "Gültig von", "Gültig bis", "Tage bis Ablauf"])
    now = datetime.utcnow()
    for c in certs:
        days = (c.valid_until - now).days if c.valid_until else ""
        writer.writerow([
            c.id,
            c.common_name or "",
            c.customer.name if c.customer else "",
            c.status or "",
            c.issuer or "",
            c.valid_from.strftime("%Y-%m-%d") if c.valid_from else "",
            c.valid_until.strftime("%Y-%m-%d") if c.valid_until else "",
            days,
        ])

    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=zertifikate.csv"},
    )


@router.get("/export/security.csv")
async def export_security_csv(request: Request, db: Session = Depends(get_db)):
    """Exportiert Audit-Log als CSV (nur Admins)."""
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user
    if not user.is_admin:
        return RedirectResponse(url="/analytics", status_code=302)

    entries = db.query(models.AuditLog).order_by(
        models.AuditLog.created_at.desc()
    ).limit(5000).all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Zeitstempel", "Benutzer", "Aktion", "Entität", "Entität-ID", "IP-Adresse", "Details"])
    for e in entries:
        writer.writerow([
            e.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            e.user.username if e.user else "",
            e.action,
            e.entity_type,
            e.entity_id or "",
            e.ip_address or "",
            e.details or "",
        ])

    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sicherheitsbericht.csv"},
    )


@router.get("/data.json", response_class=JSONResponse)
async def analytics_data(request: Request, db: Session = Depends(get_db)):
    """Chart-Daten als JSON für Client-seitige Visualisierungen."""
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return JSONResponse({"error": "Nicht angemeldet."}, status_code=401)

    accessible_ids = get_accessible_customer_ids(user, db)
    cert_data = _cert_stats(db, accessible_ids)

    result: dict = {
        "cert_status": cert_data["status_counts"],
        "cert_issuers": cert_data["issuer_counts"],
        "cert_expiry_buckets": cert_data["expiry_buckets"],
        "top_customers": [{"name": k, "count": v} for k, v in cert_data["top_customers"]],
    }

    if user.is_admin:
        sec = _security_stats(db)
        result["security"] = {
            "mfa_pct": sec["mfa_pct"],
            "login_failed": sec["login_failed"],
            "critical_events": sec["critical_events"],
            "events_per_day": sec["events_per_day"],
        }

    return JSONResponse(result)
