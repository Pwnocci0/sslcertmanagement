"""Verwaltung von Kundengruppen (nur für Administratoren)."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from .. import audit, models
from ..auth import login_required, pop_flash, set_flash
from ..database import get_db
from ..services.notification import NOTIFICATION_SEVERITIES, NOTIFICATION_TYPES

router = APIRouter(prefix="/customer-groups")
templates = Jinja2Templates(directory="app/templates")


def _ip(r: Request) -> str:
    return r.headers.get("X-Forwarded-For", r.client.host if r.client else "unknown")


def _require_admin(request: Request, db: Session):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user, None
    if not user.is_admin:
        return RedirectResponse(url="/", status_code=302), None
    return None, user


# ── Liste ─────────────────────────────────────────────────────────────────────

@router.get("", response_class=HTMLResponse)
async def group_list(request: Request, db: Session = Depends(get_db)):
    redir, user = _require_admin(request, db)
    if redir:
        return redir

    groups = db.query(models.CustomerGroup).order_by(models.CustomerGroup.name).all()
    return templates.TemplateResponse(
        "customer_groups/list.html",
        {"request": request, "user": user, "groups": groups, "flash": pop_flash(request)},
    )


# ── Neu anlegen ───────────────────────────────────────────────────────────────

@router.get("/new", response_class=HTMLResponse)
async def group_new(request: Request, db: Session = Depends(get_db)):
    redir, user = _require_admin(request, db)
    if redir:
        return redir

    all_customers = (
        db.query(models.Customer)
        .filter(models.Customer.is_archived == False)
        .order_by(models.Customer.name)
        .all()
    )
    technicians = (
        db.query(models.User)
        .filter(models.User.is_active == True, models.User.is_admin == False)
        .order_by(models.User.username)
        .all()
    )
    return templates.TemplateResponse(
        "customer_groups/form.html",
        {
            "request": request, "user": user, "group": None,
            "all_customers": all_customers, "technicians": technicians,
            "selected_customer_ids": [], "selected_user_ids": [],
            "notification_types": NOTIFICATION_TYPES,
            "notification_severities": NOTIFICATION_SEVERITIES,
            "selected_types": list(NOTIFICATION_TYPES.keys()),
            "selected_severities": list(NOTIFICATION_SEVERITIES.keys()),
            "error": None, "flash": None,
        },
    )


@router.post("/new")
async def group_create(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    customer_ids: list[int] = Form(default=[]),
    user_ids: list[int] = Form(default=[]),
    notification_enabled: str = Form("off"),
    notify_admins: str = Form("off"),
    notification_type_ids: list[str] = Form(default=[]),
    notification_severity_ids: list[str] = Form(default=[]),
    db: Session = Depends(get_db),
):
    redir, user = _require_admin(request, db)
    if redir:
        return redir

    name = name.strip()
    if not name:
        all_customers = (
            db.query(models.Customer).filter(models.Customer.is_archived == False)
            .order_by(models.Customer.name).all()
        )
        technicians = (
            db.query(models.User)
            .filter(models.User.is_active == True, models.User.is_admin == False)
            .order_by(models.User.username).all()
        )
        return templates.TemplateResponse(
            "customer_groups/form.html",
            {
                "request": request, "user": user, "group": None,
                "all_customers": all_customers, "technicians": technicians,
                "selected_customer_ids": customer_ids, "selected_user_ids": user_ids,
                "notification_types": NOTIFICATION_TYPES,
                "notification_severities": NOTIFICATION_SEVERITIES,
                "selected_types": notification_type_ids,
                "selected_severities": notification_severity_ids,
                "error": "Name darf nicht leer sein.", "flash": None,
            },
            status_code=422,
        )

    existing = db.query(models.CustomerGroup).filter(models.CustomerGroup.name == name).first()
    if existing:
        all_customers = (
            db.query(models.Customer).filter(models.Customer.is_archived == False)
            .order_by(models.Customer.name).all()
        )
        technicians = (
            db.query(models.User)
            .filter(models.User.is_active == True, models.User.is_admin == False)
            .order_by(models.User.username).all()
        )
        return templates.TemplateResponse(
            "customer_groups/form.html",
            {
                "request": request, "user": user, "group": None,
                "all_customers": all_customers, "technicians": technicians,
                "selected_customer_ids": customer_ids, "selected_user_ids": user_ids,
                "notification_types": NOTIFICATION_TYPES,
                "notification_severities": NOTIFICATION_SEVERITIES,
                "selected_types": notification_type_ids,
                "selected_severities": notification_severity_ids,
                "error": f'Gruppe "{name}" existiert bereits.', "flash": None,
            },
            status_code=422,
        )

    group = models.CustomerGroup(
        name=name,
        description=description.strip() or None,
        notification_enabled=(notification_enabled == "on"),
        notify_admins=(notify_admins == "on"),
        notification_types=json.dumps(notification_type_ids) if notification_type_ids else None,
        notification_severities=json.dumps(notification_severity_ids) if notification_severity_ids else None,
    )

    # Kunden zuordnen
    if customer_ids:
        customers = db.query(models.Customer).filter(models.Customer.id.in_(customer_ids)).all()
        group.customers = customers

    # Techniker zuordnen (nur Nicht-Admins)
    if user_ids:
        techs = db.query(models.User).filter(
            models.User.id.in_(user_ids),
            models.User.is_admin == False,
        ).all()
        group.users = techs

    db.add(group)
    db.flush()

    audit.log(db, "customer_group.created", "customer_group", user.id,
              entity_id=group.id,
              details={
                  "name": group.name,
                  "customer_count": len(group.customers),
                  "user_count": len(group.users),
                  "notification_enabled": group.notification_enabled,
              },
              ip=_ip(request))

    db.commit()
    set_flash(request, "success", f'Kundengruppe "{group.name}" wurde angelegt.')
    return RedirectResponse(url=f"/customer-groups/{group.id}", status_code=302)


# ── Detail ────────────────────────────────────────────────────────────────────

@router.get("/{group_id}", response_class=HTMLResponse)
async def group_detail(group_id: int, request: Request, db: Session = Depends(get_db)):
    redir, user = _require_admin(request, db)
    if redir:
        return redir

    group = db.query(models.CustomerGroup).filter(models.CustomerGroup.id == group_id).first()
    if not group:
        set_flash(request, "warning", "Kundengruppe nicht gefunden.")
        return RedirectResponse(url="/customer-groups", status_code=302)

    recent_backups = (
        db.query(models.Backup)
        .filter(
            models.Backup.backup_type == "customer_group",
            models.Backup.customer_group_id == group_id,
        )
        .order_by(models.Backup.created_at.desc())
        .limit(3)
        .all()
    )

    return templates.TemplateResponse(
        "customer_groups/detail.html",
        {
            "request": request,
            "user": user,
            "group": group,
            "recent_backups": recent_backups,
            "flash": pop_flash(request),
        },
    )


# ── Bearbeiten ────────────────────────────────────────────────────────────────

@router.get("/{group_id}/edit", response_class=HTMLResponse)
async def group_edit(group_id: int, request: Request, db: Session = Depends(get_db)):
    redir, user = _require_admin(request, db)
    if redir:
        return redir

    group = db.query(models.CustomerGroup).filter(models.CustomerGroup.id == group_id).first()
    if not group:
        return RedirectResponse(url="/customer-groups", status_code=302)

    all_customers = (
        db.query(models.Customer)
        .filter(models.Customer.is_archived == False)
        .order_by(models.Customer.name)
        .all()
    )
    technicians = (
        db.query(models.User)
        .filter(models.User.is_active == True, models.User.is_admin == False)
        .order_by(models.User.username)
        .all()
    )
    selected_customer_ids = [c.id for c in group.customers]
    selected_user_ids = [u.id for u in group.users]

    import json as _json
    selected_types = _json.loads(group.notification_types) if group.notification_types else list(NOTIFICATION_TYPES.keys())
    selected_severities = _json.loads(group.notification_severities) if group.notification_severities else list(NOTIFICATION_SEVERITIES.keys())

    return templates.TemplateResponse(
        "customer_groups/form.html",
        {
            "request": request, "user": user, "group": group,
            "all_customers": all_customers, "technicians": technicians,
            "selected_customer_ids": selected_customer_ids,
            "selected_user_ids": selected_user_ids,
            "notification_types": NOTIFICATION_TYPES,
            "notification_severities": NOTIFICATION_SEVERITIES,
            "selected_types": selected_types,
            "selected_severities": selected_severities,
            "error": None, "flash": None,
        },
    )


@router.post("/{group_id}/edit")
async def group_update(
    group_id: int,
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    customer_ids: list[int] = Form(default=[]),
    user_ids: list[int] = Form(default=[]),
    notification_enabled: str = Form("off"),
    notify_admins: str = Form("off"),
    notification_type_ids: list[str] = Form(default=[]),
    notification_severity_ids: list[str] = Form(default=[]),
    db: Session = Depends(get_db),
):
    redir, user = _require_admin(request, db)
    if redir:
        return redir

    group = db.query(models.CustomerGroup).filter(models.CustomerGroup.id == group_id).first()
    if not group:
        return RedirectResponse(url="/customer-groups", status_code=302)

    name = name.strip()
    if not name:
        all_customers = (
            db.query(models.Customer).filter(models.Customer.is_archived == False)
            .order_by(models.Customer.name).all()
        )
        technicians = (
            db.query(models.User)
            .filter(models.User.is_active == True, models.User.is_admin == False)
            .order_by(models.User.username).all()
        )
        return templates.TemplateResponse(
            "customer_groups/form.html",
            {
                "request": request, "user": user, "group": group,
                "all_customers": all_customers, "technicians": technicians,
                "selected_customer_ids": customer_ids, "selected_user_ids": user_ids,
                "notification_types": NOTIFICATION_TYPES,
                "notification_severities": NOTIFICATION_SEVERITIES,
                "selected_types": notification_type_ids,
                "selected_severities": notification_severity_ids,
                "error": "Name darf nicht leer sein.", "flash": None,
            },
            status_code=422,
        )

    old_name = group.name
    group.name = name
    group.description = description.strip() or None
    group.notification_enabled = (notification_enabled == "on")
    group.notify_admins = (notify_admins == "on")
    group.notification_types = json.dumps(notification_type_ids) if notification_type_ids else None
    group.notification_severities = json.dumps(notification_severity_ids) if notification_severity_ids else None

    # Kunden-Zuordnung aktualisieren
    if customer_ids:
        group.customers = db.query(models.Customer).filter(
            models.Customer.id.in_(customer_ids)
        ).all()
    else:
        group.customers = []

    # Techniker-Zuordnung aktualisieren
    if user_ids:
        group.users = db.query(models.User).filter(
            models.User.id.in_(user_ids),
            models.User.is_admin == False,
        ).all()
    else:
        group.users = []

    audit.log(db, "customer_group.updated", "customer_group", user.id,
              entity_id=group_id,
              details={
                  "old_name": old_name, "new_name": name,
                  "customer_count": len(group.customers),
                  "user_count": len(group.users),
                  "notification_enabled": group.notification_enabled,
              },
              ip=_ip(request))

    db.commit()
    set_flash(request, "success", f'Kundengruppe "{group.name}" gespeichert.')
    return RedirectResponse(url=f"/customer-groups/{group_id}", status_code=302)


# ── Löschen ───────────────────────────────────────────────────────────────────

@router.post("/{group_id}/delete")
async def group_delete(group_id: int, request: Request, db: Session = Depends(get_db)):
    redir, user = _require_admin(request, db)
    if redir:
        return redir

    group = db.query(models.CustomerGroup).filter(models.CustomerGroup.id == group_id).first()
    if group:
        audit.log(db, "customer_group.deleted", "customer_group", user.id,
                  entity_id=group_id,
                  details={"name": group.name},
                  ip=_ip(request))
        db.delete(group)
        db.commit()
        set_flash(request, "warning", f'Kundengruppe "{group.name}" wurde gelöscht.')
    return RedirectResponse(url="/customer-groups", status_code=302)
