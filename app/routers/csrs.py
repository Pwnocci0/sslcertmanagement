import json
import re

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from .. import audit, models
from ..auth import (
    check_customer_access, forbidden_response,
    get_accessible_customer_ids, login_required, pop_flash, set_flash,
)
from ..crypto import decrypt_private_key, generate_csr_and_key
from ..database import get_db
from ..stepup import require_stepup

router = APIRouter(prefix="/csrs")
from ..templates_config import templates

# Erlaubte Key-Größen
_VALID_KEY_SIZES = {2048, 3072, 4096}


def _safe_filename(cn: str) -> str:
    """Wandelt einen CN in einen sicheren Dateinamen um."""
    return re.sub(r"[^\w\.\-]", "_", cn)[:80]


def _client_ip(request: Request) -> str:
    return request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown")


@router.get("", response_class=HTMLResponse)
async def csr_list(request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    q = request.query_params.get("q", "").strip()
    show_archived = request.query_params.get("archived", "0") == "1"

    accessible_ids = get_accessible_customer_ids(user, db)

    query = db.query(models.CsrRequest)
    if accessible_ids is not None:
        # Techniker: nur CSRs mit zugänglichem Kunden ODER ohne Kunden (eigene CSRs)
        query = query.filter(
            (models.CsrRequest.customer_id.in_(accessible_ids)) |
            (models.CsrRequest.customer_id == None)
        )
    if not show_archived:
        query = query.filter(models.CsrRequest.is_archived == False)
    if q:
        query = query.filter(models.CsrRequest.common_name.ilike(f"%{q}%"))
    csrs = query.order_by(models.CsrRequest.created_at.desc()).all()

    archived_q = db.query(models.CsrRequest).filter(models.CsrRequest.is_archived == True)
    if accessible_ids is not None:
        archived_q = archived_q.filter(
            (models.CsrRequest.customer_id.in_(accessible_ids)) |
            (models.CsrRequest.customer_id == None)
        )
    archived_count = archived_q.count()

    return templates.TemplateResponse(
        "csrs/list.html",
        {
            "request": request, "user": user, "csrs": csrs, "q": q,
            "show_archived": show_archived, "archived_count": archived_count,
            "flash": pop_flash(request),
        },
    )


@router.get("/new", response_class=HTMLResponse)
async def csr_new(request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    accessible_ids = get_accessible_customer_ids(user, db)
    cust_q = db.query(models.Customer).filter(models.Customer.is_archived == False)
    if accessible_ids is not None:
        cust_q = cust_q.filter(models.Customer.id.in_(accessible_ids))
    customers = cust_q.order_by(models.Customer.name).all()

    dom_q = db.query(models.Domain)
    if accessible_ids is not None:
        dom_q = dom_q.filter(models.Domain.customer_id.in_(accessible_ids))
    domains = dom_q.order_by(models.Domain.fqdn).all()

    csr_templates_list = db.query(models.CsrTemplate).order_by(
        models.CsrTemplate.is_default.desc(), models.CsrTemplate.name
    ).all()

    # Determine selected template (explicit > default)
    selected_template = None
    tid = request.query_params.get("template_id", "")
    if tid.isdigit():
        selected_template = db.query(models.CsrTemplate).filter(
            models.CsrTemplate.id == int(tid)
        ).first()
    if selected_template is None:
        selected_template = next((t for t in csr_templates_list if t.is_default), None)

    # Pre-fill form from template
    form: dict = {}
    if selected_template:
        form = {
            "country": selected_template.country or "",
            "state": selected_template.state or "",
            "locality": selected_template.locality or "",
            "organization": selected_template.organization or "",
            "ou": selected_template.organizational_unit or "",
            "key_size": selected_template.key_size,
            "sans": selected_template.san_pattern or "",
        }

    # Allow pre-selecting customer/domain via query params
    if request.query_params.get("customer_id", "").isdigit():
        form["customer_id"] = request.query_params["customer_id"]
    if request.query_params.get("domain_id", "").isdigit():
        form["domain_id"] = request.query_params["domain_id"]

    return templates.TemplateResponse(
        "csrs/form.html",
        {
            "request": request,
            "user": user,
            "customers": customers,
            "domains": domains,
            "key_sizes": models.KEY_SIZE_CHOICES,
            "csr_templates": csr_templates_list,
            "selected_template_id": selected_template.id if selected_template else None,
            "error": None,
            "form": form,
            "flash": None,
        },
    )


@router.post("/new")
async def csr_create(
    request: Request,
    # Zuordnung
    customer_id: str = Form(""),
    domain_id: str = Form(""),
    # Subject-Felder
    common_name: str = Form(...),
    sans: str = Form(""),
    country: str = Form(""),
    state: str = Form(""),
    locality: str = Form(""),
    organization: str = Form(""),
    ou: str = Form(""),
    email: str = Form(""),
    # Key
    key_size: int = Form(2048),
    db: Session = Depends(get_db),
):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    # Formwerte für Re-Render im Fehlerfall sammeln
    form_data = {
        "customer_id": customer_id, "domain_id": domain_id,
        "common_name": common_name, "sans": sans, "country": country,
        "state": state, "locality": locality, "organization": organization,
        "ou": ou, "email": email, "key_size": key_size,
    }

    # Kundenzugriff prüfen (falls ein Kunde ausgewählt wurde)
    if customer_id.isdigit() and not check_customer_access(user, int(customer_id), db):
        return forbidden_response()

    accessible_ids = get_accessible_customer_ids(user, db)

    def render_error(msg: str):
        cust_q = db.query(models.Customer).filter(models.Customer.is_archived == False)
        if accessible_ids is not None:
            cust_q = cust_q.filter(models.Customer.id.in_(accessible_ids))
        customers = cust_q.order_by(models.Customer.name).all()

        dom_q = db.query(models.Domain)
        if accessible_ids is not None:
            dom_q = dom_q.filter(models.Domain.customer_id.in_(accessible_ids))
        domains = dom_q.order_by(models.Domain.fqdn).all()

        csr_templates = db.query(models.CsrTemplate).order_by(
            models.CsrTemplate.is_default.desc(), models.CsrTemplate.name
        ).all()
        return templates.TemplateResponse(
            "csrs/form.html",
            {
                "request": request, "user": user,
                "customers": customers, "domains": domains,
                "key_sizes": models.KEY_SIZE_CHOICES,
                "csr_templates": csr_templates,
                "selected_template_id": None,
                "error": msg, "form": form_data, "flash": None,
            },
            status_code=422,
        )

    # Validierung
    common_name = common_name.strip()
    if not common_name:
        return render_error("Common Name (CN) ist Pflichtfeld.")
    if key_size not in _VALID_KEY_SIZES:
        return render_error(f"Ungueltiger Key-Size: {key_size}")
    if country and len(country.strip()) != 2:
        return render_error("Country muss genau 2 Zeichen haben (z.B. DE).")

    # CSR + Key generieren
    try:
        csr_pem, key_pem_encrypted = generate_csr_and_key(
            cn=common_name,
            sans_raw=sans,
            country=country.strip().upper(),
            state=state.strip(),
            locality=locality.strip(),
            organization=organization.strip(),
            ou=ou.strip(),
            email=email.strip(),
            key_size=key_size,
        )
    except RuntimeError as exc:
        return render_error(str(exc))

    # In DB speichern
    csr_obj = models.CsrRequest(
        customer_id=int(customer_id) if customer_id.isdigit() else None,
        domain_id=int(domain_id) if domain_id.isdigit() else None,
        created_by=user.id,
        common_name=common_name,
        sans=sans.strip() or None,
        country=country.strip().upper() or None,
        state=state.strip() or None,
        locality=locality.strip() or None,
        organization=organization.strip() or None,
        organizational_unit=ou.strip() or None,
        email=email.strip() or None,
        key_size=key_size,
        csr_pem=csr_pem,
        private_key_encrypted=key_pem_encrypted,
    )
    db.add(csr_obj)
    db.flush()  # ID wird benötigt für Audit-Log

    audit.log(
        db,
        action="csr.created",
        entity_type="csr",
        user_id=user.id,
        entity_id=csr_obj.id,
        details={"cn": common_name, "key_size": key_size, "sans": sans},
        ip=_client_ip(request),
    )

    db.commit()
    set_flash(request, "success", f'CSR für "{common_name}" wurde erfolgreich erstellt.')
    return RedirectResponse(url=f"/csrs/{csr_obj.id}", status_code=302)


@router.get("/{csr_id}", response_class=HTMLResponse)
async def csr_detail(csr_id: int, request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    csr = db.query(models.CsrRequest).filter(models.CsrRequest.id == csr_id).first()
    if not csr:
        set_flash(request, "warning", "CSR nicht gefunden.")
        return RedirectResponse(url="/csrs", status_code=302)

    if csr.customer_id and not check_customer_access(user, csr.customer_id, db):
        return forbidden_response()

    # Letzte 20 Audit-Einträge zu diesem CSR
    audit_entries = (
        db.query(models.AuditLog)
        .filter(
            models.AuditLog.entity_type == "csr",
            models.AuditLog.entity_id == csr_id,
        )
        .order_by(models.AuditLog.created_at.desc())
        .limit(20)
        .all()
    )
    # Details-JSON für Anzeige parsen
    for e in audit_entries:
        try:
            e._details_parsed = json.loads(e.details or "{}")
        except Exception:
            e._details_parsed = {}

    return templates.TemplateResponse(
        "csrs/detail.html",
        {
            "request": request,
            "user": user,
            "csr": csr,
            "audit_entries": audit_entries,
            "flash": pop_flash(request),
        },
    )


@router.get("/{csr_id}/download/csr")
async def download_csr(csr_id: int, request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    csr = db.query(models.CsrRequest).filter(models.CsrRequest.id == csr_id).first()
    if not csr:
        return RedirectResponse(url="/csrs", status_code=302)

    audit.log(
        db,
        action="csr.download_csr",
        entity_type="csr",
        user_id=user.id,
        entity_id=csr_id,
        details={"cn": csr.common_name},
        ip=_client_ip(request),
    )

    fname = _safe_filename(csr.common_name)
    return Response(
        content=csr.csr_pem,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f'attachment; filename="{fname}.csr.pem"'},
    )


@router.get("/{csr_id}/download/key")
async def download_key_encrypted(csr_id: int, request: Request, db: Session = Depends(get_db)):
    """Verschlüsselter Private Key (AES-256-CBC, Passphrase = CSR_KEY_PASSPHRASE)."""
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    csr = db.query(models.CsrRequest).filter(models.CsrRequest.id == csr_id).first()
    if not csr:
        return RedirectResponse(url="/csrs", status_code=302)

    audit.log(
        db,
        action="csr.download_key_encrypted",
        entity_type="csr",
        user_id=user.id,
        entity_id=csr_id,
        details={"cn": csr.common_name},
        ip=_client_ip(request),
    )

    fname = _safe_filename(csr.common_name)
    return Response(
        content=csr.private_key_encrypted,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f'attachment; filename="{fname}.key.encrypted.pem"'},
    )


@router.post("/{csr_id}/archive")
async def csr_archive(csr_id: int, request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    csr = db.query(models.CsrRequest).filter(models.CsrRequest.id == csr_id).first()
    if csr:
        csr.is_archived = True
        audit.log(db, "csr.archived", "csr", user.id, entity_id=csr_id,
                  details={"cn": csr.common_name}, ip=_client_ip(request))
        db.commit()
        set_flash(request, "warning", f'CSR "{csr.common_name}" wurde archiviert.')
    return RedirectResponse(url="/csrs", status_code=302)


@router.post("/{csr_id}/unarchive")
async def csr_unarchive(csr_id: int, request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    csr = db.query(models.CsrRequest).filter(models.CsrRequest.id == csr_id).first()
    if csr:
        csr.is_archived = False
        audit.log(db, "csr.unarchived", "csr", user.id, entity_id=csr_id,
                  details={"cn": csr.common_name}, ip=_client_ip(request))
        db.commit()
        set_flash(request, "success", f'CSR "{csr.common_name}" wurde wiederhergestellt.')
    return RedirectResponse(url=f"/csrs/{csr_id}", status_code=302)


@router.get("/{csr_id}/download/key/plain")
async def download_key_plain(csr_id: int, request: Request, db: Session = Depends(get_db)):
    """Unverschlüsselter Private Key – Step-up (Passwort + TOTP) erforderlich."""
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    redir = require_stepup(request, "key_export_plain", next_url=f"/csrs/{csr_id}/download/key/plain")
    if redir:
        return redir

    csr = db.query(models.CsrRequest).filter(models.CsrRequest.id == csr_id).first()
    if not csr:
        return RedirectResponse(url="/csrs", status_code=302)

    try:
        plain_pem = decrypt_private_key(csr.private_key_encrypted)
    except Exception as exc:
        set_flash(request, "danger", f"Entschlüsselung fehlgeschlagen: {exc}")
        return RedirectResponse(url=f"/csrs/{csr_id}", status_code=302)

    audit.log(
        db,
        action="csr.download_key_plain",
        entity_type="csr",
        user_id=user.id,
        entity_id=csr_id,
        details={"cn": csr.common_name, "severity": "HIGH"},
        ip=_client_ip(request),
    )

    fname = _safe_filename(csr.common_name)
    return Response(
        content=plain_pem,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f'attachment; filename="{fname}.key.pem"'},
    )
