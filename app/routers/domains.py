from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..auth import (
    check_customer_access, forbidden_response,
    get_accessible_customer_ids, login_required, pop_flash, set_flash,
)
from ..database import get_db
from .. import models

router = APIRouter(prefix="/domains")
templates = Jinja2Templates(directory="app/templates")


def _accessible_customers(user, db: Session):
    """Gibt aktive Kunden zurück, auf die der User Zugriff hat."""
    q = db.query(models.Customer).filter(models.Customer.is_archived == False)
    ids = get_accessible_customer_ids(user, db)
    if ids is not None:
        q = q.filter(models.Customer.id.in_(ids))
    return q.order_by(models.Customer.name).all()


@router.get("", response_class=HTMLResponse)
async def domain_list(request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    q = request.query_params.get("q", "").strip()
    filter_customer_id = request.query_params.get("customer_id", "")

    accessible_ids = get_accessible_customer_ids(user, db)

    query = db.query(models.Domain).join(models.Customer)
    if accessible_ids is not None:
        query = query.filter(models.Domain.customer_id.in_(accessible_ids))
    if q:
        query = query.filter(
            or_(
                models.Domain.fqdn.ilike(f"%{q}%"),
                models.Customer.name.ilike(f"%{q}%"),
            )
        )
    if filter_customer_id.isdigit():
        cid = int(filter_customer_id)
        if accessible_ids is None or cid in accessible_ids:
            query = query.filter(models.Domain.customer_id == cid)

    domains = query.order_by(models.Domain.fqdn).all()
    customers = _accessible_customers(user, db)

    return templates.TemplateResponse(
        "domains/list.html",
        {
            "request": request,
            "user": user,
            "domains": domains,
            "customers": customers,
            "q": q,
            "filter_customer_id": filter_customer_id,
            "flash": pop_flash(request),
        },
    )


@router.get("/new", response_class=HTMLResponse)
async def domain_new(request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    preselect_customer = request.query_params.get("customer_id", "")
    customers = _accessible_customers(user, db)
    return templates.TemplateResponse(
        "domains/form.html",
        {
            "request": request, "user": user, "domain": None,
            "customers": customers, "preselect_customer": preselect_customer,
            "error": None, "flash": None,
        },
    )


@router.post("/new")
async def domain_create(
    request: Request,
    customer_id: int = Form(...),
    fqdn: str = Form(...),
    notes: str = Form(""),
    db: Session = Depends(get_db),
):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    if not check_customer_access(user, customer_id, db):
        return forbidden_response()

    fqdn = fqdn.strip().lower()
    customers = _accessible_customers(user, db)

    if not fqdn:
        return templates.TemplateResponse(
            "domains/form.html",
            {"request": request, "user": user, "domain": None, "customers": customers,
             "preselect_customer": str(customer_id), "error": "FQDN darf nicht leer sein.", "flash": None},
            status_code=422,
        )

    existing = db.query(models.Domain).filter(models.Domain.fqdn == fqdn).first()
    if existing:
        return templates.TemplateResponse(
            "domains/form.html",
            {"request": request, "user": user, "domain": None, "customers": customers,
             "preselect_customer": str(customer_id), "error": f'Domain "{fqdn}" ist bereits vorhanden.', "flash": None},
            status_code=422,
        )

    domain = models.Domain(customer_id=customer_id, fqdn=fqdn, notes=notes.strip() or None)
    db.add(domain)
    db.commit()
    set_flash(request, "success", f'Domain "{domain.fqdn}" wurde angelegt.')
    return RedirectResponse(url=f"/domains/{domain.id}", status_code=302)


@router.get("/{domain_id}", response_class=HTMLResponse)
async def domain_detail(domain_id: int, request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    domain = db.query(models.Domain).filter(models.Domain.id == domain_id).first()
    if not domain:
        set_flash(request, "warning", "Domain nicht gefunden.")
        return RedirectResponse(url="/domains", status_code=302)

    if not check_customer_access(user, domain.customer_id, db):
        return forbidden_response()

    return templates.TemplateResponse(
        "domains/detail.html",
        {"request": request, "user": user, "domain": domain, "flash": pop_flash(request)},
    )


@router.get("/{domain_id}/edit", response_class=HTMLResponse)
async def domain_edit(domain_id: int, request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    domain = db.query(models.Domain).filter(models.Domain.id == domain_id).first()
    if not domain:
        return RedirectResponse(url="/domains", status_code=302)

    if not check_customer_access(user, domain.customer_id, db):
        return forbidden_response()

    customers = _accessible_customers(user, db)
    return templates.TemplateResponse(
        "domains/form.html",
        {
            "request": request, "user": user, "domain": domain,
            "customers": customers, "preselect_customer": str(domain.customer_id),
            "error": None, "flash": None,
        },
    )


@router.post("/{domain_id}/edit")
async def domain_update(
    domain_id: int,
    request: Request,
    customer_id: int = Form(...),
    fqdn: str = Form(...),
    notes: str = Form(""),
    db: Session = Depends(get_db),
):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    domain = db.query(models.Domain).filter(models.Domain.id == domain_id).first()
    if not domain:
        return RedirectResponse(url="/domains", status_code=302)

    if not check_customer_access(user, domain.customer_id, db):
        return forbidden_response()
    if not check_customer_access(user, customer_id, db):
        return forbidden_response()

    fqdn = fqdn.strip().lower()
    customers = _accessible_customers(user, db)

    if not fqdn:
        return templates.TemplateResponse(
            "domains/form.html",
            {"request": request, "user": user, "domain": domain, "customers": customers,
             "preselect_customer": str(customer_id), "error": "FQDN darf nicht leer sein.", "flash": None},
            status_code=422,
        )

    existing = db.query(models.Domain).filter(
        models.Domain.fqdn == fqdn, models.Domain.id != domain_id,
    ).first()
    if existing:
        return templates.TemplateResponse(
            "domains/form.html",
            {"request": request, "user": user, "domain": domain, "customers": customers,
             "preselect_customer": str(customer_id), "error": f'Domain "{fqdn}" ist bereits vorhanden.', "flash": None},
            status_code=422,
        )

    domain.customer_id = customer_id
    domain.fqdn = fqdn
    domain.notes = notes.strip() or None
    db.commit()
    set_flash(request, "success", f'Domain "{domain.fqdn}" wurde gespeichert.')
    return RedirectResponse(url=f"/domains/{domain_id}", status_code=302)
