"""Verwaltung aktiver Benutzersitzungen.

Jede authentifizierte Session erhält ein zufälliges Token, dessen SHA-256-Hash
in der DB gespeichert wird. Bei jedem Request wird das Token validiert.
Dies ermöglicht die administrative Verwaltung und gezielte Invalidierung von Sessions.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from .. import models


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(
    db: Session,
    user_id: int,
    ip: str | None,
    user_agent: str | None,
) -> str:
    """Erstellt eine neue UserSession. Gibt den Klartext-Token zurück."""
    token = secrets.token_urlsafe(32)
    record = models.UserSession(
        user_id=user_id,
        session_token_hash=_hash_token(token),
        ip_address=ip,
        user_agent=(user_agent or "")[:255],
        is_active=True,
    )
    db.add(record)
    db.commit()
    return token


def validate_session(db: Session, token: str) -> models.UserSession | None:
    """Validiert ein Session-Token. Gibt UserSession zurück oder None."""
    token_hash = _hash_token(token)
    session = (
        db.query(models.UserSession)
        .filter(
            models.UserSession.session_token_hash == token_hash,
            models.UserSession.is_active == True,
        )
        .first()
    )
    if session:
        session.last_seen_at = datetime.utcnow()
        db.commit()
    return session


def revoke_session(db: Session, session_id: int) -> bool:
    """Widerruft eine Session anhand ihrer DB-ID. Gibt True bei Erfolg zurück."""
    session = db.query(models.UserSession).filter(
        models.UserSession.id == session_id
    ).first()
    if session:
        session.is_active = False
        db.commit()
        return True
    return False


def revoke_all_for_user(db: Session, user_id: int, except_token: str | None = None) -> int:
    """Widerruft alle Sessions eines Benutzers. Gibt Anzahl zurück."""
    q = db.query(models.UserSession).filter(
        models.UserSession.user_id == user_id,
        models.UserSession.is_active == True,
    )
    if except_token:
        except_hash = _hash_token(except_token)
        q = q.filter(models.UserSession.session_token_hash != except_hash)
    count = q.update({"is_active": False}, synchronize_session=False)
    db.commit()
    return count


def get_active_sessions(
    db: Session, user_id: int | None = None
) -> list[models.UserSession]:
    """Gibt aktive Sessions zurück. None = alle User (Admin)."""
    q = db.query(models.UserSession).filter(models.UserSession.is_active == True)
    if user_id is not None:
        q = q.filter(models.UserSession.user_id == user_id)
    return q.order_by(models.UserSession.last_seen_at.desc()).all()


def cleanup_old_sessions(db: Session, older_than_days: int = 30) -> int:
    """Löscht inaktive oder alte Sessions. Gibt Anzahl gelöschter Einträge zurück."""
    cutoff = datetime.utcnow() - timedelta(days=older_than_days)
    deleted = (
        db.query(models.UserSession)
        .filter(
            (models.UserSession.is_active == False)
            | (models.UserSession.last_seen_at < cutoff)
        )
        .delete(synchronize_session=False)
    )
    db.commit()
    return deleted
