"""Hintergrundjob-Scheduler für automatische Benachrichtigungen.

Verwendet APScheduler mit BackgroundScheduler. Wird beim App-Start initialisiert
und läuft im Hintergrund. Führt stündlich den Notification-Check durch.
"""
from __future__ import annotations

import logging

from apscheduler.schedulers.background import BackgroundScheduler

logger = logging.getLogger(__name__)

_scheduler: BackgroundScheduler | None = None


def _run_log_cleanup() -> None:
    """Löscht Audit-Log-Einträge gemäß konfigurierter Retention-Dauer."""
    logger.info("Log-Cleanup gestartet.")
    try:
        from .database import SessionLocal
        from .services.system_status import run_log_cleanup
        from .settings_service import get_settings_service

        db = SessionLocal()
        try:
            svc = get_settings_service(db)
            retention_days = svc.get_int("logs.retention_days", default=365)
            retention_days = max(1, min(3650, retention_days))
            deleted = run_log_cleanup(db, retention_days)
            if deleted:
                logger.info("Log-Cleanup: %d Audit-Log-Einträge gelöscht (Retention: %d Tage).", deleted, retention_days)
            else:
                logger.debug("Log-Cleanup: keine fälligen Einträge.")
        finally:
            db.close()
    except Exception:
        logger.exception("Unerwarteter Fehler beim Log-Cleanup.")


def _run_daily_backup() -> None:
    """Erstellt täglich um Mitternacht UTC ein globales Backup."""
    logger.info("Automatisches tägliches Backup gestartet.")
    try:
        from .database import SessionLocal
        from .services.backup import GlobalBackupService

        db = SessionLocal()
        try:
            svc = GlobalBackupService(db)
            backup = svc.create_backup(label="Automatisches tägliches Backup")
            logger.info(
                "Automatisches Backup erstellt: %s (%d Bytes)",
                backup.archive_path, backup.size_bytes or 0,
            )
        finally:
            db.close()
    except Exception:
        logger.exception("Unerwarteter Fehler beim automatischen Backup.")


def _run_cert_status_update() -> None:
    """Aktualisiert Certificate-Status täglich anhand des Ablaufdatums."""
    logger.info("Zertifikat-Status-Update gestartet.")
    try:
        from datetime import datetime, timedelta
        from .database import SessionLocal
        from . import models

        db = SessionLocal()
        try:
            now = datetime.utcnow()
            threshold = now + timedelta(days=30)

            # Abgelaufen
            expired = db.query(models.Certificate).filter(
                models.Certificate.valid_until < now,
                models.Certificate.status.in_(["active", "expiring_soon"]),
            ).update({"status": "expired"}, synchronize_session=False)

            # Bald ablaufend (innerhalb 30 Tage)
            expiring = db.query(models.Certificate).filter(
                models.Certificate.valid_until >= now,
                models.Certificate.valid_until <= threshold,
                models.Certificate.status == "active",
            ).update({"status": "expiring_soon"}, synchronize_session=False)

            # Wieder aktiv (falls Ablaufdatum korrigiert)
            reactivated = db.query(models.Certificate).filter(
                models.Certificate.valid_until > threshold,
                models.Certificate.status == "expiring_soon",
            ).update({"status": "active"}, synchronize_session=False)

            db.commit()
            logger.info(
                "Zertifikat-Status-Update: %d abgelaufen, %d bald ablaufend, %d reaktiviert.",
                expired, expiring, reactivated,
            )
        finally:
            db.close()
    except Exception:
        logger.exception("Unerwarteter Fehler beim Zertifikat-Status-Update.")


def _run_notification_check() -> None:
    """Führt den Notification-Check durch (wird vom Scheduler aufgerufen)."""
    logger.info("Notification-Check gestartet.")
    try:
        from .database import SessionLocal
        from .services.notification import NotificationService

        db = SessionLocal()
        try:
            svc = NotificationService(db)
            sent, failed = svc.run_checks()
            if sent or failed:
                logger.info(
                    "Notification-Check abgeschlossen: %d gesendet, %d fehlgeschlagen.",
                    sent, failed,
                )
            else:
                logger.debug("Notification-Check abgeschlossen: keine fälligen Benachrichtigungen.")
        finally:
            db.close()
    except Exception:
        logger.exception("Unerwarteter Fehler im Notification-Check.")


def start_scheduler() -> None:
    """Startet den Hintergrund-Scheduler."""
    global _scheduler
    if _scheduler and _scheduler.running:
        return

    _scheduler = BackgroundScheduler(timezone="UTC")
    _scheduler.add_job(
        _run_notification_check,
        trigger="interval",
        hours=1,
        id="notification_check",
        replace_existing=True,
        misfire_grace_time=300,
    )
    _scheduler.add_job(
        _run_daily_backup,
        trigger="cron",
        hour=0,
        minute=5,
        id="daily_backup",
        replace_existing=True,
        misfire_grace_time=3600,
    )
    _scheduler.add_job(
        _run_log_cleanup,
        trigger="cron",
        hour=1,
        minute=0,
        id="log_cleanup",
        replace_existing=True,
        misfire_grace_time=3600,
    )
    _scheduler.add_job(
        _run_cert_status_update,
        trigger="cron",
        hour=0,
        minute=30,
        id="cert_status_update",
        replace_existing=True,
        misfire_grace_time=3600,
    )
    _scheduler.start()
    logger.info(
        "Scheduler gestartet ("
        "stündlicher Notification-Check, "
        "tägliches Backup 00:05 UTC, "
        "täglicher Log-Cleanup 01:00 UTC, "
        "tägliches Zertifikat-Status-Update 00:30 UTC)."
    )


def shutdown_scheduler() -> None:
    """Stoppt den Scheduler sauber."""
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("Scheduler gestoppt.")
    _scheduler = None


def trigger_now() -> None:
    """Löst den Notification-Check sofort aus (für Tests/manuelles Auslösen)."""
    _run_notification_check()


def trigger_cert_status_update() -> None:
    """Löst den Zertifikat-Status-Update sofort aus."""
    _run_cert_status_update()
