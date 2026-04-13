"""Login-Schutz: Rate-Limiting und Aussperr-Logik.

Verfolgt fehlgeschlagene Login-Versuche pro Benutzername und IP-Adresse.
Sperrt nach Erreichen des konfigurierten Limits für ein Zeitfenster aus.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from .. import models


def record_attempt(db: Session, username: str, ip: str, success: bool) -> None:
    """Schreibt einen Login-Versuch in die Datenbank."""
    attempt = models.LoginAttempt(
        username=username,
        ip_address=ip,
        success=success,
    )
    db.add(attempt)
    db.commit()


def is_locked_out(
    db: Session,
    username: str,
    ip: str,
    max_attempts: int,
    window_minutes: int = 15,
) -> bool:
    """
    Gibt True zurück wenn Benutzername oder IP gesperrt sind.
    max_attempts <= 0 deaktiviert die Sperre.
    """
    if max_attempts <= 0:
        return False

    since = datetime.utcnow() - timedelta(minutes=window_minutes)

    count_user = (
        db.query(models.LoginAttempt)
        .filter(
            models.LoginAttempt.username == username,
            models.LoginAttempt.success == False,
            models.LoginAttempt.created_at >= since,
        )
        .count()
    )
    if count_user >= max_attempts:
        return True

    count_ip = (
        db.query(models.LoginAttempt)
        .filter(
            models.LoginAttempt.ip_address == ip,
            models.LoginAttempt.success == False,
            models.LoginAttempt.created_at >= since,
        )
        .count()
    )
    return count_ip >= max_attempts


def clear_attempts_for_user(db: Session, username: str) -> None:
    """Löscht alle fehlgeschlagenen Versuche für einen Benutzernamen (nach Erfolg)."""
    db.query(models.LoginAttempt).filter(
        models.LoginAttempt.username == username,
        models.LoginAttempt.success == False,
    ).delete(synchronize_session=False)
    db.commit()


def cleanup_old_attempts(db: Session, older_than_days: int = 7) -> int:
    """Löscht alte Login-Versuche. Gibt Anzahl gelöschter Einträge zurück."""
    cutoff = datetime.utcnow() - timedelta(days=older_than_days)
    deleted = (
        db.query(models.LoginAttempt)
        .filter(models.LoginAttempt.created_at < cutoff)
        .delete(synchronize_session=False)
    )
    db.commit()
    return deleted


def get_recent_stats(db: Session, hours: int = 24) -> dict:
    """Gibt Statistiken zu Login-Versuchen der letzten N Stunden zurück."""
    since = datetime.utcnow() - timedelta(hours=hours)
    total = (
        db.query(models.LoginAttempt)
        .filter(models.LoginAttempt.created_at >= since)
        .count()
    )
    failed = (
        db.query(models.LoginAttempt)
        .filter(
            models.LoginAttempt.created_at >= since,
            models.LoginAttempt.success == False,
        )
        .count()
    )
    return {"total": total, "failed": failed, "success": total - failed}


def get_recent_attempts(
    db: Session, limit: int = 50
) -> list[models.LoginAttempt]:
    """Gibt die letzten N Login-Versuche zurück."""
    return (
        db.query(models.LoginAttempt)
        .order_by(models.LoginAttempt.created_at.desc())
        .limit(limit)
        .all()
    )
