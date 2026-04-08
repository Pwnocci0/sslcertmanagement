"""Backup- und Restore-Routen."""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from .. import audit, models
from ..auth import login_required
from ..database import get_db
from ..services.backup import (
    CustomerGroupBackupService,
    GlobalBackupService,
    human_size,
)

logger = logging.getLogger(__name__)
router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


def _ip(r: Request) -> str:
    return r.headers.get("X-Forwarded-For", r.client.host if r.client else "unknown")


def _flash(request: Request, msg: str, kind: str = "success") -> None:
    request.session["flash"] = {"msg": msg, "type": kind}


# ── Globale Backups (Admin-only) ──────────────────────────────────────────────

@router.get("/backups")
def global_backup_list(request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if not isinstance(user, models.User):
        return user
    if not user.is_admin:
        return RedirectResponse(url="/", status_code=302)

    svc = GlobalBackupService(db)
    backups = svc.list_backups()

    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(
        "backups/global.html",
        {
            "request": request,
            "user": user,
            "backups": backups,
            "flash": flash,
            "human_size": human_size,
        },
    )


@router.post("/backups/global/create")
def global_backup_create(request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if not isinstance(user, models.User):
        return user
    if not user.is_admin:
        return RedirectResponse(url="/", status_code=302)

    svc = GlobalBackupService(db)
    try:
        backup = svc.create_backup(user_id=user.id)
        audit.log(
            db, "backup.global.created", "backup",
            user_id=user.id, entity_id=backup.id,
            details={"label": backup.label, "size_bytes": backup.size_bytes},
            ip=_ip(request),
        )
        _flash(request, f"Backup '{backup.label}' erfolgreich erstellt.")
    except Exception as exc:
        logger.exception("Globales Backup fehlgeschlagen.")
        _flash(request, f"Backup fehlgeschlagen: {exc}", "danger")

    return RedirectResponse(url="/backups", status_code=302)


@router.post("/backups/{backup_id}/restore-global")
def global_backup_restore(
    backup_id: int, request: Request, db: Session = Depends(get_db)
):
    user = login_required(request, db)
    if not isinstance(user, models.User):
        return user
    if not user.is_admin:
        return RedirectResponse(url="/", status_code=302)

    backup = db.query(models.Backup).filter(
        models.Backup.id == backup_id,
        models.Backup.backup_type == "global",
    ).first()
    if not backup:
        _flash(request, "Backup nicht gefunden.", "danger")
        return RedirectResponse(url="/backups", status_code=302)

    svc = GlobalBackupService(db)
    try:
        svc.restore_backup(backup)
        audit.log(
            db, "backup.global.restored", "backup",
            user_id=user.id, entity_id=backup.id,
            details={"label": backup.label},
            ip=_ip(request),
        )
        _flash(
            request,
            "Datenbank erfolgreich wiederhergestellt. "
            "Bitte starten Sie die Anwendung neu, damit alle Änderungen wirksam werden.",
            "warning",
        )
    except Exception as exc:
        logger.exception("Globales Restore fehlgeschlagen.")
        _flash(request, f"Restore fehlgeschlagen: {exc}", "danger")

    return RedirectResponse(url="/backups", status_code=302)


@router.get("/backups/{backup_id}/download")
def backup_download(backup_id: int, request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if not isinstance(user, models.User):
        return user
    if not user.is_admin:
        return RedirectResponse(url="/", status_code=302)

    backup = db.query(models.Backup).filter(models.Backup.id == backup_id).first()
    if not backup or not backup.archive_path:
        _flash(request, "Backup nicht gefunden.", "danger")
        return RedirectResponse(url="/backups", status_code=302)

    path = Path(backup.archive_path)
    if not path.exists():
        _flash(request, "Archiv-Datei existiert nicht mehr auf dem Server.", "danger")
        return RedirectResponse(url="/backups", status_code=302)

    filename = path.name
    media_type = "application/gzip" if filename.endswith(".gz") else "application/octet-stream"
    return FileResponse(path=str(path), filename=filename, media_type=media_type)


@router.post("/backups/{backup_id}/delete")
def backup_delete(backup_id: int, request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if not isinstance(user, models.User):
        return user
    if not user.is_admin:
        return RedirectResponse(url="/", status_code=302)

    backup = db.query(models.Backup).filter(models.Backup.id == backup_id).first()
    if not backup:
        _flash(request, "Backup nicht gefunden.", "danger")
        return RedirectResponse(url="/backups", status_code=302)

    backup_type = backup.backup_type
    group_id = backup.customer_group_id
    label = backup.label

    try:
        if backup_type == "global":
            GlobalBackupService(db).delete_backup(backup)
        else:
            CustomerGroupBackupService(db).delete_backup(backup)
        audit.log(
            db, "backup.deleted", "backup",
            user_id=user.id, entity_id=backup_id,
            details={"label": label, "type": backup_type},
            ip=_ip(request),
        )
        _flash(request, f"Backup '{label}' wurde gelöscht.")
    except Exception as exc:
        _flash(request, f"Löschen fehlgeschlagen: {exc}", "danger")

    if backup_type == "customer_group" and group_id:
        return RedirectResponse(url=f"/backups/group/{group_id}", status_code=302)
    return RedirectResponse(url="/backups", status_code=302)


# ── Kundengruppen-Backups ─────────────────────────────────────────────────────

@router.get("/backups/group/{group_id}")
def group_backup_list(group_id: int, request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if not isinstance(user, models.User):
        return user
    if not user.is_admin:
        return RedirectResponse(url="/", status_code=302)

    group = db.query(models.CustomerGroup).filter(
        models.CustomerGroup.id == group_id
    ).first()
    if not group:
        return RedirectResponse(url="/customer-groups", status_code=302)

    svc = CustomerGroupBackupService(db)
    backups = svc.list_backups_for_group(group_id)

    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(
        "backups/customer_group.html",
        {
            "request": request,
            "user": user,
            "group": group,
            "backups": backups,
            "flash": flash,
            "human_size": human_size,
        },
    )


@router.post("/backups/group/{group_id}/create")
def group_backup_create(group_id: int, request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if not isinstance(user, models.User):
        return user
    if not user.is_admin:
        return RedirectResponse(url="/", status_code=302)

    group = db.query(models.CustomerGroup).filter(
        models.CustomerGroup.id == group_id
    ).first()
    if not group:
        return RedirectResponse(url="/customer-groups", status_code=302)

    svc = CustomerGroupBackupService(db)
    try:
        backup = svc.create_backup(group=group, user_id=user.id)
        audit.log(
            db, "backup.group.created", "backup",
            user_id=user.id, entity_id=backup.id,
            details={
                "label": backup.label,
                "group_id": group_id,
                "group_name": group.name,
                "size_bytes": backup.size_bytes,
            },
            ip=_ip(request),
        )
        _flash(request, f"Backup '{backup.label}' erfolgreich erstellt.")
    except Exception as exc:
        logger.exception("Kundengruppen-Backup fehlgeschlagen.")
        _flash(request, f"Backup fehlgeschlagen: {exc}", "danger")

    return RedirectResponse(url=f"/backups/group/{group_id}", status_code=302)


@router.post("/backups/{backup_id}/restore-group")
def group_backup_restore(backup_id: int, request: Request, db: Session = Depends(get_db)):
    user = login_required(request, db)
    if not isinstance(user, models.User):
        return user
    if not user.is_admin:
        return RedirectResponse(url="/", status_code=302)

    backup = db.query(models.Backup).filter(
        models.Backup.id == backup_id,
        models.Backup.backup_type == "customer_group",
    ).first()
    if not backup:
        _flash(request, "Backup nicht gefunden.", "danger")
        return RedirectResponse(url="/backups", status_code=302)

    group_id = backup.customer_group_id
    svc = CustomerGroupBackupService(db)
    try:
        stats = svc.restore_backup(backup, created_by_user_id=user.id)
        audit.log(
            db, "backup.group.restored", "backup",
            user_id=user.id, entity_id=backup.id,
            details={"label": backup.label, "stats": stats},
            ip=_ip(request),
        )
        parts = []
        if stats.get("customers_created"):
            parts.append(f"{stats['customers_created']} Kunden angelegt")
        if stats.get("customers_updated"):
            parts.append(f"{stats['customers_updated']} Kunden aktualisiert")
        if stats.get("domains_created"):
            parts.append(f"{stats['domains_created']} Domains")
        if stats.get("certs_created"):
            parts.append(f"{stats['certs_created']} Zertifikate")
        if stats.get("csrs_created"):
            parts.append(f"{stats['csrs_created']} CSRs")
        summary = ", ".join(parts) or "keine Änderungen"
        _flash(request, f"Backup wiederhergestellt: {summary}.")
    except Exception as exc:
        logger.exception("Kundengruppen-Restore fehlgeschlagen.")
        _flash(request, f"Restore fehlgeschlagen: {exc}", "danger")

    return RedirectResponse(url=f"/backups/group/{group_id}", status_code=302)
