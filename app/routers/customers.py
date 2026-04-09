from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..auth import (
    check_customer_access, forbidden_response,
    get_accessible_customer_ids, login_required, pop_flash, set_flash,
)
from ..database import get_db
from .. import models

router = APIRouter(prefix="/customers")
from ..templates_config import templates


@router.get("", response_class=HTMLResponse)
async def customer_list(request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    q = request.query_params.get("q", "").strip()
    show_archived = request.query_params.get("archived", "0") == "1"

    query = db.query(models.Customer)

    # Techniker sehen nur ihre Kundengruppen
    accessible_ids = get_accessible_customer_ids(user, db)
    if accessible_ids is not None:
        query = query.filter(models.Customer.id.in_(accessible_ids))

    if not show_archived:
        query = query.filter(models.Customer.is_archived == False)
    if q:
        query = query.filter(
            or_(
                models.Customer.name.ilike(f"%{q}%"),
                models.Customer.contact_name.ilike(f"%{q}%"),
                models.Customer.contact_email.ilike(f"%{q}%"),
            )
        )
    customers = query.order_by(models.Customer.name).all()

    # Archivzähler: nur für accessible Kunden
    archived_q = db.query(models.Customer).filter(models.Customer.is_archived == True)
    if accessible_ids is not None:
        archived_q = archived_q.filter(models.Customer.id.in_(accessible_ids))
    archived_count = archived_q.count()

    return templates.TemplateResponse(
        "customers/list.html",
        {
            "request": request,
            "user": user,
            "customers": customers,
            "q": q,
            "show_archived": show_archived,
            "archived_count": archived_count,
            "flash": pop_flash(request),
        },
    )


@router.get("/new", response_class=HTMLResponse)
async def customer_new(request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    # Technicians can create customers but must assign a group
    available_groups = None
    if not user.is_admin:
        available_groups = user.customer_groups  # only their own groups
        if not available_groups:
            set_flash(request, "danger", "Sie sind keiner Kundengruppe zugewiesen. Bitte einen Administrator kontaktieren.")
            return RedirectResponse(url="/customers", status_code=302)

    return templates.TemplateResponse(
        "customers/form.html",
        {"request": request, "user": user, "customer": None, "error": None,
         "flash": pop_flash(request), "available_groups": available_groups},
    )


@router.post("/new")
async def customer_create(
    request: Request,
    name: str = Form(...),
    contact_name: str = Form(""),
    contact_email: str = Form(""),
    notes: str = Form(""),
    group_id: str = Form(""),
    db: Session = Depends(get_db),
):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    available_groups = None if user.is_admin else user.customer_groups

    # Technicians must select one of their groups
    selected_group = None
    if not user.is_admin:
        if not group_id.isdigit():
            return templates.TemplateResponse(
                "customers/form.html",
                {"request": request, "user": user, "customer": None,
                 "error": "Bitte eine Kundengruppe auswählen.", "flash": None,
                 "available_groups": available_groups},
                status_code=422,
            )
        gid = int(group_id)
        allowed_ids = [g.id for g in user.customer_groups]
        if gid not in allowed_ids:
            return forbidden_response()
        selected_group = db.query(models.CustomerGroup).filter(models.CustomerGroup.id == gid).first()

    name = name.strip()
    if not name:
        return templates.TemplateResponse(
            "customers/form.html",
            {"request": request, "user": user, "customer": None, "error": "Name darf nicht leer sein.", "flash": None,
             "available_groups": available_groups},
            status_code=422,
        )

    customer = models.Customer(
        name=name,
        contact_name=contact_name.strip() or None,
        contact_email=contact_email.strip() or None,
        notes=notes.strip() or None,
    )
    db.add(customer)
    db.flush()  # get customer.id before commit
    if selected_group:
        selected_group.customers.append(customer)
    db.commit()
    set_flash(request, "success", f'Kunde "{customer.name}" wurde angelegt.')
    return RedirectResponse(url=f"/customers/{customer.id}", status_code=302)


@router.get("/{customer_id}", response_class=HTMLResponse)
async def customer_detail(customer_id: int, request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    customer = db.query(models.Customer).filter(models.Customer.id == customer_id).first()
    if not customer:
        set_flash(request, "warning", "Kunde nicht gefunden.")
        return RedirectResponse(url="/customers", status_code=302)

    if not check_customer_access(user, customer_id, db):
        return forbidden_response()

    return templates.TemplateResponse(
        "customers/detail.html",
        {"request": request, "user": user, "customer": customer, "flash": pop_flash(request)},
    )


@router.get("/{customer_id}/edit", response_class=HTMLResponse)
async def customer_edit(customer_id: int, request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    customer = db.query(models.Customer).filter(models.Customer.id == customer_id).first()
    if not customer:
        return RedirectResponse(url="/customers", status_code=302)

    if not check_customer_access(user, customer_id, db):
        return forbidden_response()

    return templates.TemplateResponse(
        "customers/form.html",
        {"request": request, "user": user, "customer": customer, "error": None, "flash": None},
    )


@router.post("/{customer_id}/edit")
async def customer_update(
    customer_id: int,
    request: Request,
    name: str = Form(...),
    contact_name: str = Form(""),
    contact_email: str = Form(""),
    notes: str = Form(""),
    db: Session = Depends(get_db),
):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    customer = db.query(models.Customer).filter(models.Customer.id == customer_id).first()
    if not customer:
        return RedirectResponse(url="/customers", status_code=302)

    if not check_customer_access(user, customer_id, db):
        return forbidden_response()

    name = name.strip()
    if not name:
        return templates.TemplateResponse(
            "customers/form.html",
            {"request": request, "user": user, "customer": customer, "error": "Name darf nicht leer sein.", "flash": None},
            status_code=422,
        )

    customer.name = name
    customer.contact_name = contact_name.strip() or None
    customer.contact_email = contact_email.strip() or None
    customer.notes = notes.strip() or None
    db.commit()
    set_flash(request, "success", f'Kunde "{customer.name}" wurde gespeichert.')
    return RedirectResponse(url=f"/customers/{customer_id}", status_code=302)


@router.post("/{customer_id}/archive")
async def customer_archive(customer_id: int, request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    if not user.is_admin:
        return forbidden_response("Nur Administratoren können Kunden archivieren.")

    customer = db.query(models.Customer).filter(models.Customer.id == customer_id).first()
    if customer:
        customer.is_archived = True
        db.commit()
        set_flash(request, "warning", f'Kunde "{customer.name}" wurde archiviert.')
    return RedirectResponse(url="/customers", status_code=302)


@router.post("/{customer_id}/unarchive")
async def customer_unarchive(customer_id: int, request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    if not user.is_admin:
        return forbidden_response("Nur Administratoren können Kunden wiederherstellen.")

    customer = db.query(models.Customer).filter(models.Customer.id == customer_id).first()
    if customer:
        customer.is_archived = False
        db.commit()
        set_flash(request, "success", f'Kunde "{customer.name}" wurde wiederhergestellt.')
    return RedirectResponse(url=f"/customers/{customer_id}", status_code=302)


# ── Kunden-Defaults ───────────────────────────────────────────────────────────

@router.get("/{customer_id}/defaults/edit", response_class=HTMLResponse)
async def customer_defaults_edit(customer_id: int, request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    customer = db.query(models.Customer).filter(models.Customer.id == customer_id).first()
    if not customer:
        return RedirectResponse(url="/customers", status_code=302)

    if not check_customer_access(user, customer_id, db):
        return forbidden_response()

    return templates.TemplateResponse(
        "customers/defaults_form.html",
        {"request": request, "user": user, "customer": customer,
         "defaults": customer.defaults, "flash": pop_flash(request)},
    )


@router.post("/{customer_id}/defaults/edit")
async def customer_defaults_save(
    customer_id: int,
    request: Request,
    default_country: str = Form(""),
    default_state: str = Form(""),
    default_locality: str = Form(""),
    default_org: str = Form(""),
    default_ou: str = Form(""),
    preferred_validity_days: str = Form(""),
    preferred_product_sku: str = Form(""),
    validation_notes: str = Form(""),
    technical_notes: str = Form(""),
    db: Session = Depends(get_db),
):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    customer = db.query(models.Customer).filter(models.Customer.id == customer_id).first()
    if not customer:
        return RedirectResponse(url="/customers", status_code=302)

    if not check_customer_access(user, customer_id, db):
        return forbidden_response()

    defaults = customer.defaults
    if not defaults:
        defaults = models.CustomerDefaults(customer_id=customer_id)
        db.add(defaults)

    defaults.default_country = default_country.strip().upper()[:2] or None
    defaults.default_state = default_state.strip() or None
    defaults.default_locality = default_locality.strip() or None
    defaults.default_org = default_org.strip() or None
    defaults.default_ou = default_ou.strip() or None
    defaults.preferred_validity_days = int(preferred_validity_days) if preferred_validity_days.isdigit() else None
    defaults.preferred_product_sku = preferred_product_sku.strip() or None
    defaults.validation_notes = validation_notes.strip() or None
    defaults.technical_notes = technical_notes.strip() or None

    db.commit()
    set_flash(request, "success", "Kunden-Defaults gespeichert.")
    return RedirectResponse(url=f"/customers/{customer_id}", status_code=302)
