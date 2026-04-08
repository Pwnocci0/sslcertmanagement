"""
Audit-Log-Helper.
Alle sicherheitsrelevanten Aktionen werden hier zentral protokolliert.
"""
import json
from sqlalchemy.orm import Session

from . import models


def log(
    db: Session,
    action: str,
    entity_type: str,
    user_id: int | None = None,
    entity_id: int | None = None,
    details: dict | None = None,
    ip: str | None = None,
) -> None:
    """
    Schreibt einen Audit-Log-Eintrag.

    action:      z.B. "csr.created", "csr.key_downloaded_plain"
    entity_type: z.B. "csr", "customer"
    details:     beliebige dict-Daten (werden als JSON gespeichert)
    """
    entry = models.AuditLog(
        user_id=user_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details=json.dumps(details or {}, ensure_ascii=False),
        ip_address=ip,
    )
    db.add(entry)
    db.commit()
