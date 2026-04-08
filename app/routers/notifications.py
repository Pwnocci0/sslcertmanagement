"""Benachrichtigungs-Historie und -Übersicht (nur Admins)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from .. import models
from ..auth import login_required, pop_flash
from ..database import get_db
from ..services.notification import NOTIFICATION_SEVERITIES, NOTIFICATION_TYPES

router = APIRouter(prefix="/notifications")
templates = Jinja2Templates(directory="app/templates")


def _require_admin(request: Request, db: Session):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user, None
    if not user.is_admin:
        return RedirectResponse(url="/", status_code=302), None
    return None, user


def _last_dispatches(db: Session, limit: int = 50) -> list[models.NotificationDispatch]:
    return (
        db.query(models.NotificationDispatch)
        .order_by(models.NotificationDispatch.created_at.desc())
        .limit(limit)
        .all()
    )


@router.get("", response_class=HTMLResponse)
async def notifications_history(request: Request, db: Session = Depends(get_db)):
    redir, user = _require_admin(request, db)
    if redir:
        return redir

    # Filter
    f_status = request.query_params.get("status", "")
    f_event = request.query_params.get("event_type", "")

    q = db.query(models.NotificationDispatch)
    if f_status:
        q = q.filter(models.NotificationDispatch.status == f_status)
    if f_event:
        q = q.filter(models.NotificationDispatch.event_type == f_event)

    dispatches = q.order_by(models.NotificationDispatch.created_at.desc()).limit(200).all()

    stats = {
        "total": db.query(models.NotificationDispatch).count(),
        "sent": db.query(models.NotificationDispatch).filter(
            models.NotificationDispatch.status == "sent"
        ).count(),
        "failed": db.query(models.NotificationDispatch).filter(
            models.NotificationDispatch.status == "failed"
        ).count(),
    }

    return templates.TemplateResponse(
        "notifications/history.html",
        {
            "request": request,
            "user": user,
            "dispatches": dispatches,
            "stats": stats,
            "notification_types": NOTIFICATION_TYPES,
            "notification_severities": NOTIFICATION_SEVERITIES,
            "f_status": f_status,
            "f_event": f_event,
            "flash": pop_flash(request),
        },
    )
