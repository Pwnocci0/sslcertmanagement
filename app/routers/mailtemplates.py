"""Verwaltung von Mailtemplates für Benachrichtigungen (nur Admins)."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from .. import audit, models
from ..auth import login_required, pop_flash, set_flash
from ..database import get_db
from ..services.notification import TEMPLATE_KEYS, TEMPLATE_PLACEHOLDERS

router = APIRouter(prefix="/mailtemplates")
templates = Jinja2Templates(directory="app/templates")


def _require_admin(request: Request, db: Session):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user, None
    if not user.is_admin:
        return RedirectResponse(url="/", status_code=302), None
    return None, user


def _ip(r: Request) -> str:
    return r.headers.get("X-Forwarded-For", r.client.host if r.client else "unknown")


@router.get("", response_class=HTMLResponse)
async def template_list(request: Request, db: Session = Depends(get_db)):
    redir, user = _require_admin(request, db)
    if redir:
        return redir

    tmplts = (
        db.query(models.MailTemplate)
        .order_by(models.MailTemplate.template_key)
        .all()
    )
    return templates.TemplateResponse(
        "mailtemplates/list.html",
        {
            "request": request,
            "user": user,
            "tmplts": tmplts,
            "template_keys": TEMPLATE_KEYS,
            "flash": pop_flash(request),
        },
    )


@router.get("/new", response_class=HTMLResponse)
async def template_new(request: Request, db: Session = Depends(get_db)):
    redir, user = _require_admin(request, db)
    if redir:
        return redir

    return templates.TemplateResponse(
        "mailtemplates/form.html",
        {
            "request": request,
            "user": user,
            "tmpl": None,
            "template_keys": TEMPLATE_KEYS,
            "placeholders": TEMPLATE_PLACEHOLDERS,
            "error": None,
        },
    )


@router.post("/new")
async def template_create(
    request: Request,
    name: str = Form(...),
    template_key: str = Form(...),
    subject: str = Form(...),
    text_body: str = Form(...),
    html_body: str = Form(""),
    is_active: str = Form("off"),
    db: Session = Depends(get_db),
):
    redir, user = _require_admin(request, db)
    if redir:
        return redir

    def render_error(msg: str):
        return templates.TemplateResponse(
            "mailtemplates/form.html",
            {
                "request": request, "user": user, "tmpl": None,
                "template_keys": TEMPLATE_KEYS,
                "placeholders": TEMPLATE_PLACEHOLDERS,
                "error": msg,
            },
            status_code=422,
        )

    name = name.strip()
    template_key = template_key.strip()
    subject = subject.strip()
    text_body = text_body.strip()

    if not name or not template_key or not subject or not text_body:
        return render_error("Name, Template-Key, Betreff und Text-Body sind Pflichtfelder.")

    if db.query(models.MailTemplate).filter(models.MailTemplate.template_key == template_key).first():
        return render_error(f'Template-Key "{template_key}" ist bereits vergeben.')

    tmpl = models.MailTemplate(
        name=name,
        template_key=template_key,
        subject=subject,
        text_body=text_body,
        html_body=html_body.strip() or None,
        is_active=(is_active == "on"),
    )
    db.add(tmpl)
    db.flush()

    audit.log(db, "mailtemplate.created", "mailtemplate", user.id,
              entity_id=tmpl.id,
              details={"key": template_key, "name": name},
              ip=_ip(request))
    db.commit()

    set_flash(request, "success", f'Template "{name}" angelegt.')
    return RedirectResponse(url="/mailtemplates", status_code=302)


@router.get("/{tmpl_id}/edit", response_class=HTMLResponse)
async def template_edit(tmpl_id: int, request: Request, db: Session = Depends(get_db)):
    redir, user = _require_admin(request, db)
    if redir:
        return redir

    tmpl = db.query(models.MailTemplate).filter(models.MailTemplate.id == tmpl_id).first()
    if not tmpl:
        set_flash(request, "warning", "Template nicht gefunden.")
        return RedirectResponse(url="/mailtemplates", status_code=302)

    return templates.TemplateResponse(
        "mailtemplates/form.html",
        {
            "request": request,
            "user": user,
            "tmpl": tmpl,
            "template_keys": TEMPLATE_KEYS,
            "placeholders": TEMPLATE_PLACEHOLDERS,
            "error": None,
        },
    )


@router.post("/{tmpl_id}/edit")
async def template_update(
    tmpl_id: int,
    request: Request,
    name: str = Form(...),
    template_key: str = Form(...),
    subject: str = Form(...),
    text_body: str = Form(...),
    html_body: str = Form(""),
    is_active: str = Form("off"),
    db: Session = Depends(get_db),
):
    redir, user = _require_admin(request, db)
    if redir:
        return redir

    tmpl = db.query(models.MailTemplate).filter(models.MailTemplate.id == tmpl_id).first()
    if not tmpl:
        return RedirectResponse(url="/mailtemplates", status_code=302)

    def render_error(msg: str):
        return templates.TemplateResponse(
            "mailtemplates/form.html",
            {
                "request": request, "user": user, "tmpl": tmpl,
                "template_keys": TEMPLATE_KEYS,
                "placeholders": TEMPLATE_PLACEHOLDERS,
                "error": msg,
            },
            status_code=422,
        )

    name = name.strip()
    template_key = template_key.strip()
    subject = subject.strip()
    text_body = text_body.strip()

    if not name or not template_key or not subject or not text_body:
        return render_error("Name, Template-Key, Betreff und Text-Body sind Pflichtfelder.")

    duplicate = (
        db.query(models.MailTemplate)
        .filter(
            models.MailTemplate.template_key == template_key,
            models.MailTemplate.id != tmpl_id,
        )
        .first()
    )
    if duplicate:
        return render_error(f'Template-Key "{template_key}" ist bereits vergeben.')

    old_key = tmpl.template_key
    tmpl.name = name
    tmpl.template_key = template_key
    tmpl.subject = subject
    tmpl.text_body = text_body
    tmpl.html_body = html_body.strip() or None
    tmpl.is_active = (is_active == "on")
    tmpl.updated_at = datetime.utcnow()

    audit.log(db, "mailtemplate.updated", "mailtemplate", user.id,
              entity_id=tmpl_id,
              details={"old_key": old_key, "new_key": template_key, "active": tmpl.is_active},
              ip=_ip(request))
    db.commit()

    set_flash(request, "success", f'Template "{name}" gespeichert.')
    return RedirectResponse(url="/mailtemplates", status_code=302)


@router.post("/{tmpl_id}/toggle-active")
async def template_toggle_active(tmpl_id: int, request: Request, db: Session = Depends(get_db)):
    redir, user = _require_admin(request, db)
    if redir:
        return redir

    tmpl = db.query(models.MailTemplate).filter(models.MailTemplate.id == tmpl_id).first()
    if tmpl:
        tmpl.is_active = not tmpl.is_active
        tmpl.updated_at = datetime.utcnow()
        status = "aktiviert" if tmpl.is_active else "deaktiviert"
        audit.log(db, "mailtemplate.toggled", "mailtemplate", user.id,
                  entity_id=tmpl_id,
                  details={"key": tmpl.template_key, "is_active": tmpl.is_active},
                  ip=_ip(request))
        db.commit()
        set_flash(request, "success" if tmpl.is_active else "warning",
                  f'Template "{tmpl.name}" {status}.')
    return RedirectResponse(url="/mailtemplates", status_code=302)
