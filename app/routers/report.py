"""Problemformular – sendet eine E-Mail an den Support."""
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from .. import audit
from ..auth import login_required, pop_flash, set_flash
from ..database import get_db
from ..services.mail import MailService

router = APIRouter(prefix="/report")
from ..templates_config import templates

_SUPPORT_EMAIL = "edv@slash-k.com"


@router.get("", response_class=HTMLResponse)
async def report_view(request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    return templates.TemplateResponse(
        "report/index.html",
        {"request": request, "user": user, "error": None, "flash": pop_flash(request)},
    )


@router.post("")
async def report_send(
    request: Request,
    subject: str = Form(...),
    body: str = Form(...),
    db: Session = Depends(get_db),
):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    subject = subject.strip()
    body = body.strip()

    if not subject or not body:
        return templates.TemplateResponse(
            "report/index.html",
            {"request": request, "user": user,
             "error": "Bitte Betreff und Beschreibung ausfüllen.", "flash": None},
            status_code=422,
        )

    mail = MailService(db)
    text = (
        f"Gemeldet von: {user.username} ({user.email or 'keine E-Mail'})\n\n"
        f"{body}"
    )
    ok, err = mail.send(
        to_email=_SUPPORT_EMAIL,
        subject=f"[SSL Manager] Problem: {subject}",
        text_body=text,
    )

    ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown")
    audit.log(db, "report.sent", "report", user_id=user.id,
              details={"subject": subject, "smtp_ok": ok, "smtp_err": err}, ip=ip)

    if ok:
        set_flash(request, "success", "Problembericht wurde gesendet. Wir melden uns.")
    else:
        set_flash(request, "warning",
                  f"Bericht konnte nicht per E-Mail gesendet werden ({err}). Bitte direkt an {_SUPPORT_EMAIL} wenden.")

    return RedirectResponse(url="/report", status_code=302)
