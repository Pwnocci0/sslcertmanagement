"""CSR-Vorlagen verwalten (nur Admins)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from .. import audit, models
from ..auth import login_required, pop_flash, set_flash
from ..database import get_db

router = APIRouter(prefix="/csrtemplates")
from ..templates_config import templates


def _require_admin(request, db):
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return user, None
    if not user.is_admin:
        set_flash(request, "danger", "Nur Administratoren können CSR-Vorlagen verwalten.")
        return RedirectResponse(url="/csrs", status_code=302), None
    return None, user


def _ip(r): return r.headers.get("X-Forwarded-For", r.client.host if r.client else "unknown")


@router.get("", response_class=HTMLResponse)
async def template_list(request: Request, db: Session = Depends(get_db)):
    redirect, user = _require_admin(request, db)
    if redirect:
        return redirect

    tmpl_list = db.query(models.CsrTemplate).order_by(
        models.CsrTemplate.is_default.desc(), models.CsrTemplate.name
    ).all()

    return templates.TemplateResponse(
        "csrtemplates/list.html",
        {"request": request, "user": user, "templates": tmpl_list, "flash": pop_flash(request)},
    )


@router.get("/new", response_class=HTMLResponse)
async def template_new(request: Request, db: Session = Depends(get_db)):
    redirect, user = _require_admin(request, db)
    if redirect:
        return redirect

    return templates.TemplateResponse(
        "csrtemplates/form.html",
        {"request": request, "user": user, "tmpl": None, "error": None},
    )


@router.post("/new")
async def template_create(
    request: Request,
    db: Session = Depends(get_db),
    name: str = Form(...),
    country: str = Form(""),
    state: str = Form(""),
    locality: str = Form(""),
    organization: str = Form(""),
    organizational_unit: str = Form(""),
    key_size: int = Form(2048),
    san_pattern: str = Form(""),
    is_default: str = Form("off"),
):
    redirect, user = _require_admin(request, db)
    if redirect:
        return redirect

    if not name.strip():
        return templates.TemplateResponse(
            "csrtemplates/form.html",
            {"request": request, "user": user, "tmpl": None, "error": "Name ist Pflichtfeld."},
            status_code=422,
        )

    # Wenn als Standard gesetzt: bestehenden Standard entfernen
    if is_default == "on":
        db.query(models.CsrTemplate).filter(
            models.CsrTemplate.is_default == True
        ).update({"is_default": False})

    tmpl = models.CsrTemplate(
        name=name.strip(),
        country=country.strip().upper()[:2] or None,
        state=state.strip() or None,
        locality=locality.strip() or None,
        organization=organization.strip() or None,
        organizational_unit=organizational_unit.strip() or None,
        key_size=key_size if key_size in {2048, 3072, 4096} else 2048,
        san_pattern=san_pattern.strip() or None,
        is_default=(is_default == "on"),
        created_by=user.id,
    )
    db.add(tmpl)
    db.flush()

    audit.log(db, "csr_template.created", "csr_template", user.id,
              entity_id=tmpl.id, details={"name": name}, ip=_ip(request))
    db.commit()

    set_flash(request, "success", f'Vorlage "{tmpl.name}" wurde angelegt.')
    return RedirectResponse(url="/csrtemplates", status_code=302)


@router.get("/{tmpl_id}/edit", response_class=HTMLResponse)
async def template_edit(tmpl_id: int, request: Request, db: Session = Depends(get_db)):
    redirect, user = _require_admin(request, db)
    if redirect:
        return redirect

    tmpl = db.query(models.CsrTemplate).filter(models.CsrTemplate.id == tmpl_id).first()
    if not tmpl:
        return RedirectResponse(url="/csrtemplates", status_code=302)

    return templates.TemplateResponse(
        "csrtemplates/form.html",
        {"request": request, "user": user, "tmpl": tmpl, "error": None},
    )


@router.post("/{tmpl_id}/edit")
async def template_update(
    tmpl_id: int,
    request: Request,
    db: Session = Depends(get_db),
    name: str = Form(...),
    country: str = Form(""),
    state: str = Form(""),
    locality: str = Form(""),
    organization: str = Form(""),
    organizational_unit: str = Form(""),
    key_size: int = Form(2048),
    san_pattern: str = Form(""),
    is_default: str = Form("off"),
):
    redirect, user = _require_admin(request, db)
    if redirect:
        return redirect

    tmpl = db.query(models.CsrTemplate).filter(models.CsrTemplate.id == tmpl_id).first()
    if not tmpl:
        return RedirectResponse(url="/csrtemplates", status_code=302)

    if is_default == "on":
        db.query(models.CsrTemplate).filter(
            models.CsrTemplate.is_default == True,
            models.CsrTemplate.id != tmpl_id,
        ).update({"is_default": False})

    tmpl.name = name.strip()
    tmpl.country = country.strip().upper()[:2] or None
    tmpl.state = state.strip() or None
    tmpl.locality = locality.strip() or None
    tmpl.organization = organization.strip() or None
    tmpl.organizational_unit = organizational_unit.strip() or None
    tmpl.key_size = key_size if key_size in {2048, 3072, 4096} else 2048
    tmpl.san_pattern = san_pattern.strip() or None
    tmpl.is_default = (is_default == "on")

    audit.log(db, "csr_template.updated", "csr_template", user.id,
              entity_id=tmpl_id, details={"name": name}, ip=_ip(request))
    db.commit()

    set_flash(request, "success", f'Vorlage "{tmpl.name}" wurde gespeichert.')
    return RedirectResponse(url="/csrtemplates", status_code=302)


@router.post("/{tmpl_id}/delete")
async def template_delete(tmpl_id: int, request: Request, db: Session = Depends(get_db)):
    redirect, user = _require_admin(request, db)
    if redirect:
        return redirect

    tmpl = db.query(models.CsrTemplate).filter(models.CsrTemplate.id == tmpl_id).first()
    if tmpl:
        audit.log(db, "csr_template.deleted", "csr_template", user.id,
                  entity_id=tmpl_id, details={"name": tmpl.name}, ip=_ip(request))
        db.delete(tmpl)
        db.commit()
        set_flash(request, "warning", f'Vorlage "{tmpl.name}" wurde gelöscht.')

    return RedirectResponse(url="/csrtemplates", status_code=302)


# ── AJAX: Vorlagen-Daten für JS-Prefill ──────────────────────────────────────

@router.get("/api/list", response_class=JSONResponse)
async def templates_api(request: Request, db: Session = Depends(get_db)):
    """Gibt alle Vorlagen als JSON zurück (für CSR-Formular-Prefill via JS)."""
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return JSONResponse({"error": "Nicht angemeldet."}, status_code=401)

    result = []
    for t in db.query(models.CsrTemplate).order_by(
        models.CsrTemplate.is_default.desc(), models.CsrTemplate.name
    ).all():
        result.append({
            "id": t.id,
            "name": t.name,
            "country": t.country or "",
            "state": t.state or "",
            "locality": t.locality or "",
            "organization": t.organization or "",
            "organizational_unit": t.organizational_unit or "",
            "key_size": t.key_size,
            "san_pattern": t.san_pattern or "",
            "is_default": t.is_default,
        })
    return JSONResponse(result)


# ── AJAX: Kunden-Defaults für JS-Prefill ─────────────────────────────────────

@router.get("/api/customer-defaults/{customer_id}", response_class=JSONResponse)
async def customer_defaults_api(customer_id: int, request: Request, db: Session = Depends(get_db)):
    """Gibt kundenspezifische Standardwerte zurück (für CSR-Formular-Prefill via JS)."""
    user = login_required(request, db)
    if isinstance(user, RedirectResponse):
        return JSONResponse({"error": "Nicht angemeldet."}, status_code=401)

    defaults = db.query(models.CustomerDefaults).filter(
        models.CustomerDefaults.customer_id == customer_id
    ).first()

    if not defaults:
        return JSONResponse({})

    return JSONResponse({
        "country":      defaults.default_country or "",
        "state":        defaults.default_state or "",
        "locality":     defaults.default_locality or "",
        "organization": defaults.default_org or "",
        "ou":           defaults.default_ou or "",
    })
