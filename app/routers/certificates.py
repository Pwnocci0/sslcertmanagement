import io
import re
import zipfile
from datetime import datetime

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from cryptography import x509

from .. import audit, models
from ..auth import (
    check_customer_access, forbidden_response,
    get_accessible_customer_ids, login_required, pop_flash, set_flash,
)
from ..crypto import parse_certificate_pem, split_pem_chain
from ..database import get_db

router = APIRouter(prefix="/certificates")
templates = Jinja2Templates(directory="app/templates")


def _client_ip(request: Request) -> str:
    return request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown")


def _parse_date(value: str) -> datetime | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%d", "%d.%m.%Y"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def _cert_form_context(user, db: Session) -> dict:
    """Gemeinsame Kontext-Daten für das Zertifikats-Formular, gefiltert nach Zugriffsrechten."""
    accessible_ids = get_accessible_customer_ids(user, db)

    cust_q = db.query(models.Customer).filter(models.Customer.is_archived == False)
    if accessible_ids is not None:
        cust_q = cust_q.filter(models.Customer.id.in_(accessible_ids))

    dom_q = db.query(models.Domain)
    if accessible_ids is not None:
        dom_q = dom_q.filter(models.Domain.customer_id.in_(accessible_ids))

    csr_q = db.query(models.CsrRequest)
    if accessible_ids is not None:
        csr_q = csr_q.filter(
            (models.CsrRequest.customer_id.in_(accessible_ids)) |
            (models.CsrRequest.customer_id == None)
        )

    return {
        "customers": cust_q.order_by(models.Customer.name).all(),
        "domains": dom_q.order_by(models.Domain.fqdn).all(),
        "csrs": csr_q.order_by(models.CsrRequest.common_name).all(),
        "status_choices": models.CERT_STATUS_CHOICES,
    }


# ── AJAX: PEM parsen ──────────────────────────────────────────────────────────

@router.post("/parse-pem")
async def parse_pem_ajax(
    request: Request,
    pem: str = Form(""),
    db: Session = Depends(get_db),
):
    """
    AJAX-Endpunkt: Parst ein PEM-Bundle und gibt die extrahierten Felder als JSON zurück.
    Trennt Leaf-Zertifikat und Chain automatisch.
    """
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return JSONResponse({"error": "Nicht angemeldet."}, status_code=401)

    pem = pem.strip()
    if not pem:
        return JSONResponse({"error": "Kein PEM-Text übergeben."}, status_code=422)

    try:
        leaf_pem, chain_pem = split_pem_chain(pem)

        # Prüfen ob das erste Zertifikat eine CA ist (z.B. nur Chain-Datei hochgeladen)
        leaf_cert = x509.load_pem_x509_certificate(leaf_pem.encode())
        try:
            bc = leaf_cert.extensions.get_extension_for_class(x509.BasicConstraints)
            is_ca = bc.value.ca
        except x509.ExtensionNotFound:
            is_ca = False

        if is_ca:
            return JSONResponse(
                {
                    "error": (
                        "Die hochgeladene Datei enthält nur CA-/Intermediate-Zertifikate, "
                        "aber kein End-Entity-Zertifikat. Bitte zuerst das eigentliche "
                        "Serverzertifikat (.crt) hochladen und danach das Bundle "
                        "(.ca-bundle) anhängen – oder beide Dateien zusammen einfügen."
                    )
                },
                status_code=422,
            )

        parsed = parse_certificate_pem(leaf_pem)
        parsed["cert_pem"] = leaf_pem
        parsed["chain_pem"] = chain_pem
        return JSONResponse(parsed)
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=422)


# ── AJAX: ZIP importieren ────────────────────────────────────────────────────

_PEM_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)
_ZIP_CERT_EXTS = {".pem", ".crt", ".cer", ".txt", ".ca-bundle", ".bundle", ".chain"}


def _is_ca_cert(cert: x509.Certificate) -> bool:
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        return bc.value.ca
    except x509.ExtensionNotFound:
        return False


@router.post("/parse-zip")
async def parse_zip_ajax(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """AJAX-Endpunkt: Liest alle Zertifikate aus einer ZIP-Datei, trennt
    End-Entity-Zertifikat und Chain automatisch und gibt die Felder als JSON zurück."""
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return JSONResponse({"error": "Nicht angemeldet."}, status_code=401)

    content = await file.read()
    try:
        zf = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile:
        return JSONResponse({"error": "Ungültige ZIP-Datei."}, status_code=422)

    # Alle PEM-Blöcke aus relevanten Dateien extrahieren (dedupliziert)
    seen: set[str] = set()
    all_pems: list[str] = []
    for name in zf.namelist():
        ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if ext not in _ZIP_CERT_EXTS:
            continue
        try:
            raw = zf.read(name).decode("utf-8", errors="ignore")
        except Exception:
            continue
        for block in _PEM_RE.findall(raw):
            norm = block.strip() + "\n"
            if norm not in seen:
                seen.add(norm)
                all_pems.append(norm)

    if not all_pems:
        return JSONResponse(
            {"error": "Keine PEM-Zertifikate in der ZIP-Datei gefunden."},
            status_code=422,
        )

    # Leaf-Cert und Chain trennen
    leaf_pem: str | None = None
    ca_certs: list[tuple[x509.Certificate, str]] = []

    for pem in all_pems:
        try:
            cert = x509.load_pem_x509_certificate(pem.encode())
        except Exception:
            continue
        if _is_ca_cert(cert):
            ca_certs.append((cert, pem))
        elif leaf_pem is None:
            leaf_pem = pem

    if leaf_pem is None:
        return JSONResponse(
            {"error": "Kein End-Entity-Zertifikat in der ZIP-Datei gefunden."},
            status_code=422,
        )

    # Chain in Reihenfolge sortieren: direkter Aussteller des Leaf zuerst
    chain_ordered: list[str] = []
    by_subject: dict[bytes, tuple[x509.Certificate, str]] = {
        c.subject.public_bytes(): (c, p) for c, p in ca_certs
    }
    current = x509.load_pem_x509_certificate(leaf_pem.encode())
    while True:
        issuer_key = current.issuer.public_bytes()
        if issuer_key not in by_subject:
            break
        next_cert, next_pem = by_subject.pop(issuer_key)
        chain_ordered.append(next_pem)
        current = next_cert
    # Verbleibende (z.B. Root) anhängen
    chain_ordered.extend(p for _, p in by_subject.values())

    chain_pem = "\n".join(chain_ordered)

    try:
        parsed = parse_certificate_pem(leaf_pem)
        parsed["cert_pem"] = leaf_pem
        parsed["chain_pem"] = chain_pem
        return JSONResponse(parsed)
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=422)


# ── Liste ─────────────────────────────────────────────────────────────────────

@router.get("", response_class=HTMLResponse)
async def certificate_list(request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    show_archived = request.query_params.get("archived", "0") == "1"
    accessible_ids = get_accessible_customer_ids(user, db)

    query = db.query(models.Certificate).join(models.Customer)
    if accessible_ids is not None:
        query = query.filter(models.Certificate.customer_id.in_(accessible_ids))
    if not show_archived:
        query = query.filter(models.Certificate.is_archived == False)
    certs = query.order_by(models.Certificate.valid_until).all()

    archived_q = db.query(models.Certificate).filter(models.Certificate.is_archived == True)
    if accessible_ids is not None:
        archived_q = archived_q.filter(models.Certificate.customer_id.in_(accessible_ids))
    archived_count = archived_q.count()
    return templates.TemplateResponse(
        "certificates/list.html",
        {
            "request": request, "user": user, "certificates": certs,
            "show_archived": show_archived, "archived_count": archived_count,
            "flash": pop_flash(request),
        },
    )


# ── Neu anlegen ───────────────────────────────────────────────────────────────

@router.get("/new", response_class=HTMLResponse)
async def certificate_new(
    request: Request,
    db: Session = Depends(get_db),
    customer_id: int | None = None,
    domain_id: int | None = None,
):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    # Validate prefill access
    if customer_id and not check_customer_access(user, customer_id, db):
        customer_id = None
    if domain_id and customer_id:
        dom = db.query(models.Domain).filter(models.Domain.id == domain_id).first()
        if not dom or dom.customer_id != customer_id:
            domain_id = None

    return templates.TemplateResponse(
        "certificates/form.html",
        {
            "request": request,
            "user": user,
            "cert": None,
            "error": None,
            "flash": pop_flash(request),
            "prefill_customer_id": customer_id,
            "prefill_domain_id": domain_id,
            **_cert_form_context(user, db),
        },
    )


@router.post("/new")
async def certificate_create(
    request: Request,
    customer_id: int = Form(...),
    domain_id: str = Form(""),
    csr_request_id: str = Form(""),
    common_name: str = Form(...),
    san: str = Form(""),
    issuer: str = Form(""),
    serial_number: str = Form(""),
    valid_from: str = Form(""),
    valid_until: str = Form(""),
    status: str = Form("pending"),
    auto_renew: str = Form("off"),
    notes: str = Form(""),
    cert_pem: str = Form(""),
    chain_pem: str = Form(""),
    db: Session = Depends(get_db),
):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    if not check_customer_access(user, customer_id, db):
        return forbidden_response()

    cert = models.Certificate(
        customer_id=customer_id,
        domain_id=int(domain_id) if domain_id.isdigit() else None,
        csr_request_id=int(csr_request_id) if csr_request_id.isdigit() else None,
        common_name=common_name.strip(),
        san=san.strip() or None,
        issuer=issuer.strip() or None,
        serial_number=serial_number.strip() or None,
        valid_from=_parse_date(valid_from),
        valid_until=_parse_date(valid_until),
        status=status if status in models.CERT_STATUS_CHOICES else "pending",
        auto_renew=(auto_renew == "on"),
        notes=notes.strip() or None,
        cert_pem=cert_pem.strip() or None,
        chain_pem=chain_pem.strip() or None,
    )
    db.add(cert)
    db.commit()
    return RedirectResponse(url=f"/certificates/{cert.id}", status_code=302)


# ── Bearbeiten ───────────────────────────────────────────────────────────────

@router.get("/{cert_id}/edit", response_class=HTMLResponse)
async def certificate_edit(cert_id: int, request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    cert = db.query(models.Certificate).filter(models.Certificate.id == cert_id).first()
    if not cert:
        return RedirectResponse(url="/certificates", status_code=302)

    if not check_customer_access(user, cert.customer_id, db):
        return forbidden_response()

    return templates.TemplateResponse(
        "certificates/form.html",
        {
            "request": request,
            "user": user,
            "cert": cert,
            "error": None,
            "flash": pop_flash(request),
            "prefill_customer_id": None,
            "prefill_domain_id": None,
            **_cert_form_context(user, db),
        },
    )


@router.post("/{cert_id}/edit")
async def certificate_update(
    cert_id: int,
    request: Request,
    customer_id: int = Form(...),
    domain_id: str = Form(""),
    csr_request_id: str = Form(""),
    common_name: str = Form(...),
    san: str = Form(""),
    issuer: str = Form(""),
    serial_number: str = Form(""),
    valid_from: str = Form(""),
    valid_until: str = Form(""),
    status: str = Form("pending"),
    auto_renew: str = Form("off"),
    notes: str = Form(""),
    cert_pem: str = Form(""),
    chain_pem: str = Form(""),
    db: Session = Depends(get_db),
):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    cert = db.query(models.Certificate).filter(models.Certificate.id == cert_id).first()
    if not cert:
        return RedirectResponse(url="/certificates", status_code=302)

    if not check_customer_access(user, cert.customer_id, db):
        return forbidden_response()
    if not check_customer_access(user, customer_id, db):
        return forbidden_response()

    cert.customer_id = customer_id
    cert.domain_id = int(domain_id) if domain_id.isdigit() else None
    cert.csr_request_id = int(csr_request_id) if csr_request_id.isdigit() else None
    cert.common_name = common_name.strip()
    cert.san = san.strip() or None
    cert.issuer = issuer.strip() or None
    cert.serial_number = serial_number.strip() or None
    cert.valid_from = _parse_date(valid_from)
    cert.valid_until = _parse_date(valid_until)
    cert.status = status if status in models.CERT_STATUS_CHOICES else cert.status
    cert.auto_renew = (auto_renew == "on")
    cert.notes = notes.strip() or None
    cert.cert_pem = cert_pem.strip() or None
    cert.chain_pem = chain_pem.strip() or None
    db.commit()

    audit.log(db, "cert.updated", "certificate", user.id, entity_id=cert_id,
              details={"cn": cert.common_name}, ip=_client_ip(request))
    set_flash(request, "success", "Zertifikat gespeichert.")
    return RedirectResponse(url=f"/certificates/{cert_id}", status_code=302)


# ── Detail ────────────────────────────────────────────────────────────────────

@router.get("/{cert_id}", response_class=HTMLResponse)
async def certificate_detail(cert_id: int, request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    cert = db.query(models.Certificate).filter(models.Certificate.id == cert_id).first()
    if not cert:
        return RedirectResponse(url="/certificates", status_code=302)

    if not check_customer_access(user, cert.customer_id, db):
        return forbidden_response()

    return templates.TemplateResponse(
        "certificates/detail.html",
        {"request": request, "user": user, "cert": cert, "flash": pop_flash(request)},
    )


# ── Notiz hinzufügen ──────────────────────────────────────────────────────────

@router.post("/{cert_id}/notes")
async def certificate_add_note(
    cert_id: int,
    request: Request,
    note: str = Form(...),
    db: Session = Depends(get_db),
):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    cert = db.query(models.Certificate).filter(models.Certificate.id == cert_id).first()
    if not cert:
        return RedirectResponse(url="/certificates", status_code=302)

    note = note.strip()
    if note:
        entry = models.CertificateNote(certificate_id=cert_id, user_id=user.id, note=note)
        db.add(entry)
        audit.log(db, "cert.note_added", "certificate", user.id, entity_id=cert_id,
                  details={"cn": cert.common_name}, ip=_client_ip(request))
        db.commit()
        set_flash(request, "success", "Notiz gespeichert.")
    return RedirectResponse(url=f"/certificates/{cert_id}", status_code=302)


# ── Archivieren ───────────────────────────────────────────────────────────────

@router.post("/{cert_id}/archive")
async def certificate_archive(cert_id: int, request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    cert = db.query(models.Certificate).filter(models.Certificate.id == cert_id).first()
    if cert:
        cert.is_archived = True
        audit.log(db, "cert.archived", "certificate", user.id, entity_id=cert_id,
                  details={"cn": cert.common_name}, ip=_client_ip(request))
        db.commit()
        set_flash(request, "warning", f'Zertifikat "{cert.common_name}" wurde archiviert.')
    return RedirectResponse(url="/certificates", status_code=302)


@router.post("/{cert_id}/delete")
async def certificate_delete(cert_id: int, request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    cert = db.query(models.Certificate).filter(models.Certificate.id == cert_id).first()
    if cert:
        if not cert.is_archived:
            set_flash(request, "danger", "Nur archivierte Zertifikate können gelöscht werden.")
            return RedirectResponse(url=f"/certificates/{cert_id}", status_code=302)
        cn = cert.common_name
        audit.log(db, "cert.deleted", "certificate", user.id, entity_id=cert_id,
                  details={"cn": cn}, ip=_client_ip(request))
        db.delete(cert)
        db.commit()
        set_flash(request, "warning", f'Zertifikat „{cn}" wurde gelöscht.')
    return RedirectResponse(url="/certificates?archived=1", status_code=302)


@router.post("/{cert_id}/unarchive")
async def certificate_unarchive(cert_id: int, request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    cert = db.query(models.Certificate).filter(models.Certificate.id == cert_id).first()
    if cert:
        cert.is_archived = False
        audit.log(db, "cert.unarchived", "certificate", user.id, entity_id=cert_id,
                  details={"cn": cert.common_name}, ip=_client_ip(request))
        db.commit()
        set_flash(request, "success", f'Zertifikat "{cert.common_name}" wurde wiederhergestellt.')
    return RedirectResponse(url=f"/certificates/{cert_id}", status_code=302)


# ── Anhänge ───────────────────────────────────────────────────────────────────

@router.post("/{cert_id}/attachments")
async def attachment_upload(
    cert_id: int,
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    cert = db.query(models.Certificate).filter(models.Certificate.id == cert_id).first()
    if not cert:
        return RedirectResponse(url="/certificates", status_code=302)

    data = await file.read()
    if not data:
        set_flash(request, "danger", "Leere Datei – Upload abgebrochen.")
        return RedirectResponse(url=f"/certificates/{cert_id}", status_code=302)

    attachment = models.CertificateAttachment(
        certificate_id=cert_id,
        user_id=user.id,
        filename=file.filename or "attachment",
        content_type=file.content_type or "application/octet-stream",
        file_size=len(data),
        data=data,
    )
    db.add(attachment)
    audit.log(db, "cert.attachment_uploaded", "certificate", user.id, entity_id=cert_id,
              details={"cn": cert.common_name, "filename": attachment.filename}, ip=_client_ip(request))
    db.commit()
    set_flash(request, "success", f'Anhang „{attachment.filename}" gespeichert.')
    return RedirectResponse(url=f"/certificates/{cert_id}", status_code=302)


@router.get("/{cert_id}/attachments/{attachment_id}")
async def attachment_download(
    cert_id: int,
    attachment_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    from fastapi.responses import Response as FastAPIResponse
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    att = db.query(models.CertificateAttachment).filter(
        models.CertificateAttachment.id == attachment_id,
        models.CertificateAttachment.certificate_id == cert_id,
    ).first()
    if not att:
        return RedirectResponse(url=f"/certificates/{cert_id}", status_code=302)

    return FastAPIResponse(
        content=att.data,
        media_type=att.content_type,
        headers={"Content-Disposition": f'attachment; filename="{att.filename}"'},
    )


@router.post("/{cert_id}/attachments/{attachment_id}/delete")
async def attachment_delete(
    cert_id: int,
    attachment_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user

    att = db.query(models.CertificateAttachment).filter(
        models.CertificateAttachment.id == attachment_id,
        models.CertificateAttachment.certificate_id == cert_id,
    ).first()
    if att:
        audit.log(db, "cert.attachment_deleted", "certificate", user.id, entity_id=cert_id,
                  details={"filename": att.filename}, ip=_client_ip(request))
        db.delete(att)
        db.commit()
        set_flash(request, "warning", f'Anhang „{att.filename}" gelöscht.')
    return RedirectResponse(url=f"/certificates/{cert_id}", status_code=302)
