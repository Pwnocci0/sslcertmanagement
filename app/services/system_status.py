"""Utility-Funktionen für die System-Status-Seite.

Alle teuren Berechnungen (Verzeichnisgrößen, DB-Größe) werden hier
gekapselt. Das Ergebnis kann der Router optional cachen.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from sqlalchemy.orm import Session

from .. import models
from ..database import DATABASE_URL

_PROJECT_ROOT = Path(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
_DATA_DIR = _PROJECT_ROOT / "data"


# ── Hilfsfunktionen ──────────────────────────────────────────────────────────

def human_readable(size_bytes: int | None) -> str:
    """Gibt Bytes als lesbare Größe zurück (B, KB, MB, GB)."""
    if size_bytes is None:
        return "–"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def get_directory_size(path: Path) -> int:
    """Rekursive Gesamtgröße eines Verzeichnisses in Bytes."""
    total = 0
    try:
        for entry in path.rglob("*"):
            if entry.is_file():
                try:
                    total += entry.stat().st_size
                except OSError:
                    pass
    except OSError:
        pass
    return total


def _sqlite_path() -> Optional[Path]:
    if DATABASE_URL.startswith("sqlite:///"):
        raw = DATABASE_URL.replace("sqlite:///", "")
        p = Path(raw)
        return p if p.is_absolute() else _PROJECT_ROOT / p
    return None


# ── Datenbankgröße ────────────────────────────────────────────────────────────

def get_database_info() -> dict:
    """Gibt Informationen über die SQLite-Datenbank zurück."""
    path = _sqlite_path()
    if path is None or not path.exists():
        return {
            "path": str(path) if path else "–",
            "size_bytes": 0,
            "size_human": "–",
            "last_modified": None,
            "table_count": None,
            "available": False,
        }

    stat = path.stat()
    size_bytes = stat.st_size
    last_modified = datetime.fromtimestamp(stat.st_mtime)

    table_count: Optional[int] = None
    try:
        conn = sqlite3.connect(str(path))
        cur = conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
        )
        table_count = cur.fetchone()[0]
        conn.close()
    except Exception:
        pass

    return {
        "path": str(path),
        "size_bytes": size_bytes,
        "size_human": human_readable(size_bytes),
        "last_modified": last_modified,
        "table_count": table_count,
        "available": True,
    }


# ── Speicherbelegung ──────────────────────────────────────────────────────────

def get_storage_breakdown() -> dict:
    """Aufschlüsselung der Speicherbelegung nach Bereich."""
    backup_dir = _DATA_DIR / "backups"
    log_file = _DATA_DIR / "app.log"

    db_bytes = 0
    db_path = _sqlite_path()
    if db_path and db_path.exists():
        db_bytes = db_path.stat().st_size

    backup_bytes = get_directory_size(backup_dir) if backup_dir.exists() else 0

    # Log-Dateien (app.log + rotierte)
    log_bytes = 0
    try:
        for f in _DATA_DIR.glob("app.log*"):
            try:
                log_bytes += f.stat().st_size
            except OSError:
                pass
    except OSError:
        pass

    # Sonstiges: alles in data/ minus die oben gezählten
    total_data_bytes = get_directory_size(_DATA_DIR)
    other_bytes = max(0, total_data_bytes - db_bytes - backup_bytes - log_bytes)

    # Partition
    free_bytes: Optional[int] = None
    partition_bytes: Optional[int] = None
    try:
        usage = shutil.disk_usage(_DATA_DIR)
        free_bytes = usage.free
        partition_bytes = usage.total
    except Exception:
        pass

    return {
        "db_bytes": db_bytes,
        "backup_bytes": backup_bytes,
        "log_bytes": log_bytes,
        "other_bytes": other_bytes,
        "total_data_bytes": total_data_bytes,
        "free_bytes": free_bytes,
        "partition_bytes": partition_bytes,
        # human-readable
        "db_human": human_readable(db_bytes),
        "backup_human": human_readable(backup_bytes),
        "log_human": human_readable(log_bytes),
        "other_human": human_readable(other_bytes),
        "total_data_human": human_readable(total_data_bytes),
        "free_human": human_readable(free_bytes),
        "partition_human": human_readable(partition_bytes),
    }


# ── Backup-Zusammenfassung ────────────────────────────────────────────────────

def get_backup_summary(db: Session) -> dict:
    """Aggregierte Backup-Infos aus der Datenbank."""
    from ..services.backup import human_size

    total_count = db.query(models.Backup).count()
    global_count = db.query(models.Backup).filter(
        models.Backup.backup_type == "global"
    ).count()
    group_count = db.query(models.Backup).filter(
        models.Backup.backup_type == "customer_group"
    ).count()

    last_global_ok = (
        db.query(models.Backup)
        .filter(
            models.Backup.backup_type == "global",
            models.Backup.status == "completed",
        )
        .order_by(models.Backup.created_at.desc())
        .first()
    )
    last_global_fail = (
        db.query(models.Backup)
        .filter(
            models.Backup.backup_type == "global",
            models.Backup.status == "failed",
        )
        .order_by(models.Backup.created_at.desc())
        .first()
    )
    last_group = (
        db.query(models.Backup)
        .filter(
            models.Backup.backup_type == "customer_group",
            models.Backup.status == "completed",
        )
        .order_by(models.Backup.created_at.desc())
        .first()
    )

    return {
        "total_count": total_count,
        "global_count": global_count,
        "group_count": group_count,
        "last_global_ok": last_global_ok,
        "last_global_fail": last_global_fail,
        "last_group": last_group,
        "next_scheduled": "Täglich 00:05 UTC",
        "human_size": human_size,
    }


# ── Log-Zusammenfassung ───────────────────────────────────────────────────────

def get_log_summary(db: Session, retention_days: int = 365) -> dict:
    """Informationen über Audit-Logs und System-Logdatei."""
    from sqlalchemy import func

    audit_count = db.query(models.AuditLog).count()

    oldest_audit: Optional[datetime] = None
    newest_audit: Optional[datetime] = None
    oldest_row = (
        db.query(models.AuditLog.created_at)
        .order_by(models.AuditLog.created_at.asc())
        .first()
    )
    if oldest_row:
        oldest_audit = oldest_row[0]

    newest_row = (
        db.query(models.AuditLog.created_at)
        .order_by(models.AuditLog.created_at.desc())
        .first()
    )
    if newest_row:
        newest_audit = newest_row[0]

    # Logdatei-Größe
    log_bytes = 0
    try:
        for f in _DATA_DIR.glob("app.log*"):
            try:
                log_bytes += f.stat().st_size
            except OSError:
                pass
    except OSError:
        pass

    cutoff = datetime.utcnow() - timedelta(days=retention_days)
    entries_due_cleanup = (
        db.query(models.AuditLog)
        .filter(models.AuditLog.created_at < cutoff)
        .count()
    )

    return {
        "audit_count": audit_count,
        "oldest_audit": oldest_audit,
        "newest_audit": newest_audit,
        "log_file_bytes": log_bytes,
        "log_file_human": human_readable(log_bytes),
        "retention_days": retention_days,
        "entries_due_cleanup": entries_due_cleanup,
    }


# ── Log-Cleanup ───────────────────────────────────────────────────────────────

def run_log_cleanup(db: Session, retention_days: int) -> int:
    """Löscht Audit-Log-Einträge älter als ``retention_days`` Tage.

    Gibt die Anzahl gelöschter Einträge zurück.
    Nutzt einen indizierten Datumsfilter, kein Full-Table-Scan.
    """
    if retention_days < 1:
        raise ValueError("retention_days muss mindestens 1 sein.")

    cutoff = datetime.utcnow() - timedelta(days=retention_days)

    deleted = (
        db.query(models.AuditLog)
        .filter(models.AuditLog.created_at < cutoff)
        .delete(synchronize_session=False)
    )
    db.commit()
    return deleted
