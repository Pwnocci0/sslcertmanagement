"""Tests für System-Status-Utilities und Log-Retention."""
from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("APP_SECRET_KEY", "test-secret-key-for-testing-only-32chars")
os.environ.setdefault("CSR_KEY_PASSPHRASE", "test-passphrase")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from app import models
from app.services.system_status import (
    get_backup_summary,
    get_database_info,
    get_directory_size,
    get_log_summary,
    get_storage_breakdown,
    human_readable,
    run_log_cleanup,
)


# ── Datenbank-Hilfsfunktionen ─────────────────────────────────────────────────

def _make_db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.database import Base
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


def _make_audit(db, created_at: datetime) -> models.AuditLog:
    entry = models.AuditLog(
        action="test.action",
        entity_type="test",
        entity_id=1,
        created_at=created_at,
    )
    db.add(entry)
    db.flush()
    return entry


def _make_backup(db, backup_type="global", status="completed", group_id=None) -> models.Backup:
    b = models.Backup(
        backup_type=backup_type,
        status=status,
        customer_group_id=group_id,
        size_bytes=1024,
        checksum="a" * 64,
    )
    db.add(b)
    db.flush()
    return b


# ── human_readable ────────────────────────────────────────────────────────────

class TestHumanReadable(unittest.TestCase):
    def test_none(self):
        self.assertEqual(human_readable(None), "–")

    def test_bytes(self):
        self.assertIn("B", human_readable(100))

    def test_kilobytes(self):
        self.assertIn("KB", human_readable(2048))

    def test_megabytes(self):
        self.assertIn("MB", human_readable(2 * 1024 * 1024))

    def test_gigabytes(self):
        self.assertIn("GB", human_readable(3 * 1024 ** 3))

    def test_zero(self):
        self.assertIn("0.0", human_readable(0))


# ── get_directory_size ────────────────────────────────────────────────────────

class TestGetDirectorySize(unittest.TestCase):
    def test_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            size = get_directory_size(Path(tmp))
        self.assertEqual(size, 0)

    def test_nonexistent(self):
        self.assertEqual(get_directory_size(Path("/nonexistent/path")), 0)

    def test_counts_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "a.txt").write_bytes(b"hello")
            (p / "b.txt").write_bytes(b"world!")
            size = get_directory_size(p)
        self.assertEqual(size, 11)

    def test_recursive(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            sub = p / "sub"
            sub.mkdir()
            (sub / "file.txt").write_bytes(b"x" * 100)
            size = get_directory_size(p)
        self.assertEqual(size, 100)


# ── get_database_info ─────────────────────────────────────────────────────────

class TestGetDatabaseInfo(unittest.TestCase):
    def test_returns_dict_with_expected_keys(self):
        info = get_database_info()
        for key in ("path", "size_bytes", "size_human", "last_modified", "table_count", "available"):
            self.assertIn(key, info)

    def test_nonexistent_db_returns_available_false(self):
        with patch("app.services.system_status._sqlite_path", return_value=Path("/nonexistent/db.sqlite")):
            info = get_database_info()
        self.assertFalse(info["available"])
        self.assertEqual(info["size_bytes"], 0)

    def test_existing_db_has_positive_size(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            f.write(b"SQLite format 3\x00" + b"\x00" * 4080)
            path = Path(f.name)
        try:
            with patch("app.services.system_status._sqlite_path", return_value=path):
                info = get_database_info()
            self.assertTrue(info["available"])
            self.assertGreater(info["size_bytes"], 0)
            self.assertIsNotNone(info["last_modified"])
        finally:
            path.unlink(missing_ok=True)

    def test_size_human_is_string(self):
        info = get_database_info()
        self.assertIsInstance(info["size_human"], str)


# ── get_storage_breakdown ─────────────────────────────────────────────────────

class TestGetStorageBreakdown(unittest.TestCase):
    def test_returns_expected_keys(self):
        storage = get_storage_breakdown()
        expected = (
            "db_bytes", "backup_bytes", "log_bytes", "other_bytes",
            "total_data_bytes", "db_human", "backup_human", "log_human",
            "other_human", "total_data_human",
        )
        for key in expected:
            self.assertIn(key, storage)

    def test_all_sizes_non_negative(self):
        storage = get_storage_breakdown()
        for key in ("db_bytes", "backup_bytes", "log_bytes", "other_bytes", "total_data_bytes"):
            self.assertGreaterEqual(storage[key], 0, f"{key} should be >= 0")

    def test_human_strings_are_strings(self):
        storage = get_storage_breakdown()
        for key in ("db_human", "backup_human", "log_human", "total_data_human"):
            self.assertIsInstance(storage[key], str)


# ── get_backup_summary ────────────────────────────────────────────────────────

class TestGetBackupSummary(unittest.TestCase):
    def setUp(self):
        self.db = _make_db()

    def tearDown(self):
        self.db.close()

    def test_empty_returns_zeros(self):
        summary = get_backup_summary(self.db)
        self.assertEqual(summary["total_count"], 0)
        self.assertEqual(summary["global_count"], 0)
        self.assertEqual(summary["group_count"], 0)
        self.assertIsNone(summary["last_global_ok"])

    def test_counts_by_type(self):
        _make_backup(self.db, "global", "completed")
        _make_backup(self.db, "global", "completed")
        _make_backup(self.db, "customer_group", "completed")
        self.db.commit()

        summary = get_backup_summary(self.db)
        self.assertEqual(summary["total_count"], 3)
        self.assertEqual(summary["global_count"], 2)
        self.assertEqual(summary["group_count"], 1)

    def test_last_global_ok_is_most_recent(self):
        now = datetime.utcnow()
        b1 = models.Backup(backup_type="global", status="completed",
                           created_at=now - timedelta(hours=2))
        b2 = models.Backup(backup_type="global", status="completed",
                           created_at=now - timedelta(hours=1))
        self.db.add_all([b1, b2])
        self.db.commit()

        summary = get_backup_summary(self.db)
        self.assertIsNotNone(summary["last_global_ok"])
        self.assertEqual(summary["last_global_ok"].id, b2.id)

    def test_last_global_fail_detected(self):
        _make_backup(self.db, "global", "completed")
        fail = _make_backup(self.db, "global", "failed")
        self.db.commit()

        summary = get_backup_summary(self.db)
        self.assertIsNotNone(summary["last_global_fail"])
        self.assertEqual(summary["last_global_fail"].id, fail.id)

    def test_next_scheduled_is_string(self):
        summary = get_backup_summary(self.db)
        self.assertIsInstance(summary["next_scheduled"], str)
        self.assertTrue(len(summary["next_scheduled"]) > 0)


# ── get_log_summary ───────────────────────────────────────────────────────────

class TestGetLogSummary(unittest.TestCase):
    def setUp(self):
        self.db = _make_db()

    def tearDown(self):
        self.db.close()

    def test_empty_db(self):
        summary = get_log_summary(self.db, retention_days=365)
        self.assertEqual(summary["audit_count"], 0)
        self.assertIsNone(summary["oldest_audit"])
        self.assertEqual(summary["retention_days"], 365)
        self.assertEqual(summary["entries_due_cleanup"], 0)

    def test_counts_audit_entries(self):
        now = datetime.utcnow()
        _make_audit(self.db, now - timedelta(days=10))
        _make_audit(self.db, now - timedelta(days=5))
        _make_audit(self.db, now)
        self.db.commit()

        summary = get_log_summary(self.db, retention_days=365)
        self.assertEqual(summary["audit_count"], 3)

    def test_oldest_audit_is_correct(self):
        now = datetime.utcnow()
        old_date = now - timedelta(days=100)
        _make_audit(self.db, old_date)
        _make_audit(self.db, now)
        self.db.commit()

        summary = get_log_summary(self.db, retention_days=365)
        self.assertIsNotNone(summary["oldest_audit"])
        # Should be close to old_date (within 1 second)
        diff = abs((summary["oldest_audit"] - old_date).total_seconds())
        self.assertLess(diff, 1.0)

    def test_entries_due_cleanup_counts_old_entries(self):
        now = datetime.utcnow()
        _make_audit(self.db, now - timedelta(days=400))  # should be counted
        _make_audit(self.db, now - timedelta(days=200))  # within retention
        _make_audit(self.db, now)                        # recent
        self.db.commit()

        summary = get_log_summary(self.db, retention_days=365)
        self.assertEqual(summary["entries_due_cleanup"], 1)

    def test_log_file_human_is_string(self):
        summary = get_log_summary(self.db, retention_days=30)
        self.assertIsInstance(summary["log_file_human"], str)


# ── run_log_cleanup ───────────────────────────────────────────────────────────

class TestRunLogCleanup(unittest.TestCase):
    def setUp(self):
        self.db = _make_db()

    def tearDown(self):
        self.db.close()

    def test_deletes_old_entries(self):
        now = datetime.utcnow()
        _make_audit(self.db, now - timedelta(days=400))  # old → delete
        _make_audit(self.db, now - timedelta(days=100))  # within retention → keep
        _make_audit(self.db, now)                        # current → keep
        self.db.commit()

        deleted = run_log_cleanup(self.db, retention_days=365)
        self.assertEqual(deleted, 1)
        remaining = self.db.query(models.AuditLog).count()
        self.assertEqual(remaining, 2)

    def test_keeps_recent_entries(self):
        now = datetime.utcnow()
        _make_audit(self.db, now - timedelta(days=1))
        _make_audit(self.db, now)
        self.db.commit()

        deleted = run_log_cleanup(self.db, retention_days=365)
        self.assertEqual(deleted, 0)
        self.assertEqual(self.db.query(models.AuditLog).count(), 2)

    def test_deletes_all_when_retention_very_short(self):
        now = datetime.utcnow()
        _make_audit(self.db, now - timedelta(days=10))
        _make_audit(self.db, now - timedelta(days=5))
        self.db.commit()

        # retention = 1 day → both entries are older than 1 day
        deleted = run_log_cleanup(self.db, retention_days=1)
        self.assertEqual(deleted, 2)
        self.assertEqual(self.db.query(models.AuditLog).count(), 0)

    def test_empty_table_returns_zero(self):
        deleted = run_log_cleanup(self.db, retention_days=365)
        self.assertEqual(deleted, 0)

    def test_invalid_retention_raises(self):
        with self.assertRaises(ValueError):
            run_log_cleanup(self.db, retention_days=0)

    def test_returns_int_count(self):
        now = datetime.utcnow()
        _make_audit(self.db, now - timedelta(days=500))
        _make_audit(self.db, now - timedelta(days=400))
        self.db.commit()

        result = run_log_cleanup(self.db, retention_days=365)
        self.assertIsInstance(result, int)
        self.assertEqual(result, 2)

    def test_retention_boundary_exclusive(self):
        """Einträge genau an der Grenze (heute - retention_days) werden NICHT gelöscht."""
        now = datetime.utcnow()
        # exakt 365 Tage alt → cutoff = now - 365 days → entry ist NOT < cutoff
        boundary = now - timedelta(days=365)
        _make_audit(self.db, boundary + timedelta(seconds=1))  # within → keep
        _make_audit(self.db, boundary - timedelta(seconds=1))  # just outside → delete
        self.db.commit()

        deleted = run_log_cleanup(self.db, retention_days=365)
        self.assertEqual(deleted, 1)
        self.assertEqual(self.db.query(models.AuditLog).count(), 1)


# ── settings: logs.retention_days in DEFINITIONS ─────────────────────────────

class TestRetentionSetting(unittest.TestCase):
    def test_definition_exists(self):
        from app.settings_service import DEFINITIONS
        self.assertIn("logs.retention_days", DEFINITIONS)

    def test_definition_defaults_to_365(self):
        from app.settings_service import DEFINITIONS
        defn = DEFINITIONS["logs.retention_days"]
        self.assertEqual(defn.default, "365")

    def test_definition_is_int_type(self):
        from app.settings_service import DEFINITIONS
        defn = DEFINITIONS["logs.retention_days"]
        self.assertEqual(defn.value_type, "int")

    def test_definition_category_is_maintenance(self):
        from app.settings_service import DEFINITIONS
        defn = DEFINITIONS["logs.retention_days"]
        self.assertEqual(defn.category, "maintenance")

    def test_maintenance_in_category_labels(self):
        from app.settings_service import CATEGORY_LABELS
        self.assertIn("maintenance", CATEGORY_LABELS)


if __name__ == "__main__":
    unittest.main()
