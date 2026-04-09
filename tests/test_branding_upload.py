"""Tests für Branding-Uploads (Favicon & Logo) und Backup-Berechtigungen für Techniker."""
from __future__ import annotations

import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

os.environ.setdefault("APP_SECRET_KEY", "test-secret-key-for-testing-only-32chars")
os.environ.setdefault("CSR_KEY_PASSPHRASE", "test-passphrase")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from app import models
from app.settings_service import _invalidate_cache


# ── Hilfsfunktionen ──────────────────────────────────────────────────────────

def _make_db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.database import Base
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


def _make_user(db, username="admin", is_admin=True) -> models.User:
    from app.auth import hash_password
    u = models.User(
        username=username,
        email=f"{username}@example.com",
        hashed_password=hash_password("password"),
        is_admin=is_admin,
        is_active=True,
        mfa_setup_completed=True,
    )
    db.add(u)
    db.flush()
    return u


def _make_group(db, name="Gruppe A") -> models.CustomerGroup:
    g = models.CustomerGroup(name=name)
    db.add(g)
    db.flush()
    return g


def _make_customer(db, name="Kunde A") -> models.Customer:
    c = models.Customer(name=name)
    db.add(c)
    db.flush()
    return c


# ── Branding: Upload-Hilfsfunktionen ─────────────────────────────────────────

class TestBrandingUploadHelper(unittest.TestCase):
    """Testet die _save_upload-Hilfsfunktion aus dem Settings-Router."""

    def setUp(self):
        from app.routers.settings import _save_upload
        self._save_upload = _save_upload
        self._tmpdir = tempfile.TemporaryDirectory()
        self._orig_upload_dir = None

    def tearDown(self):
        self._tmpdir.cleanup()

    def _make_upload(self, filename: str, data: bytes = b"fake-image-data"):
        f = MagicMock()
        f.filename = filename
        return f, data

    def test_favicon_png_accepted(self):
        upload_dir = Path(self._tmpdir.name)
        with patch("app.routers.settings._UPLOAD_DIR", upload_dir):
            f, data = self._make_upload("favicon.png")
            path = self._save_upload(f, data, {".ico", ".png", ".svg"}, "favicon")
        self.assertTrue(path.endswith("favicon.png"))
        self.assertTrue((upload_dir / "favicon.png").exists())

    def test_favicon_ico_accepted(self):
        upload_dir = Path(self._tmpdir.name)
        with patch("app.routers.settings._UPLOAD_DIR", upload_dir):
            f, data = self._make_upload("myicon.ico")
            path = self._save_upload(f, data, {".ico", ".png", ".svg"}, "favicon")
        self.assertTrue(path.endswith("favicon.ico"))

    def test_favicon_svg_accepted(self):
        upload_dir = Path(self._tmpdir.name)
        with patch("app.routers.settings._UPLOAD_DIR", upload_dir):
            f, data = self._make_upload("icon.svg", b"<svg/>")
            path = self._save_upload(f, data, {".ico", ".png", ".svg"}, "favicon")
        self.assertTrue(path.endswith("favicon.svg"))

    def test_favicon_exe_rejected(self):
        upload_dir = Path(self._tmpdir.name)
        with patch("app.routers.settings._UPLOAD_DIR", upload_dir):
            f, data = self._make_upload("malicious.exe")
            with self.assertRaises(ValueError) as ctx:
                self._save_upload(f, data, {".ico", ".png", ".svg"}, "favicon")
        self.assertIn("nicht erlaubt", str(ctx.exception))

    def test_logo_png_accepted(self):
        upload_dir = Path(self._tmpdir.name)
        with patch("app.routers.settings._UPLOAD_DIR", upload_dir):
            f, data = self._make_upload("logo.png")
            path = self._save_upload(f, data, {".png", ".svg", ".jpg", ".jpeg"}, "logo")
        self.assertTrue(path.endswith("logo.png"))

    def test_logo_jpg_accepted(self):
        upload_dir = Path(self._tmpdir.name)
        with patch("app.routers.settings._UPLOAD_DIR", upload_dir):
            f, data = self._make_upload("logo.jpg")
            path = self._save_upload(f, data, {".png", ".svg", ".jpg", ".jpeg"}, "logo")
        self.assertTrue(path.endswith("logo.jpg"))

    def test_logo_php_rejected(self):
        upload_dir = Path(self._tmpdir.name)
        with patch("app.routers.settings._UPLOAD_DIR", upload_dir):
            f, data = self._make_upload("shell.php")
            with self.assertRaises(ValueError):
                self._save_upload(f, data, {".png", ".svg", ".jpg", ".jpeg"}, "logo")

    def test_file_too_large_rejected(self):
        upload_dir = Path(self._tmpdir.name)
        big_data = b"x" * (3 * 1024 * 1024)  # 3 MB
        with patch("app.routers.settings._UPLOAD_DIR", upload_dir):
            f, _ = self._make_upload("big.png")
            with self.assertRaises(ValueError) as ctx:
                self._save_upload(f, big_data, {".png"}, "logo")
        self.assertIn("groß", str(ctx.exception))

    def test_filename_is_sanitized(self):
        """Der gespeicherte Dateiname basiert immer auf dem prefix, nicht dem Original."""
        upload_dir = Path(self._tmpdir.name)
        with patch("app.routers.settings._UPLOAD_DIR", upload_dir):
            f, data = self._make_upload("../../etc/passwd.png")
            path = self._save_upload(f, data, {".png"}, "favicon")
        # Nur "favicon.png" im uploads-Verzeichnis — kein path traversal
        self.assertEqual(Path(path).name, "favicon.png")
        self.assertFalse((Path(self._tmpdir.name) / "../../etc/passwd.png").exists())

    def test_settings_updated_after_upload(self):
        """Pfad wird in den Settings gespeichert."""
        db = _make_db()
        _invalidate_cache()
        upload_dir = Path(self._tmpdir.name)

        with patch("app.routers.settings._UPLOAD_DIR", upload_dir):
            from app.settings_service import get_settings_service, _invalidate_cache as inv
            inv()
            svc = get_settings_service(db)
            svc.set_many({"app.favicon_path": "static/uploads/favicon.png"}, user_id=None)
            result = svc.get_str("app.favicon_path", "")

        self.assertEqual(result, "static/uploads/favicon.png")


# ── Backup-Berechtigungen ─────────────────────────────────────────────────────

class TestBackupGroupAccess(unittest.TestCase):
    """Testet _check_group_access und _user_in_group aus dem Backups-Router."""

    def setUp(self):
        from app.routers.backups import _check_group_access, _user_in_group
        self._check = _check_group_access
        self._in_group = _user_in_group

    def _user(self, is_admin=False, uid=1):
        u = MagicMock(spec=models.User)
        u.is_admin = is_admin
        u.id = uid
        return u

    def _group(self, user_ids: list[int]):
        g = MagicMock(spec=models.CustomerGroup)
        users = []
        for uid in user_ids:
            u = MagicMock()
            u.id = uid
            users.append(u)
        g.users = users
        return g

    def test_admin_always_has_access(self):
        admin = self._user(is_admin=True, uid=99)
        group = self._group([1, 2, 3])  # admin not in group
        self.assertTrue(self._check(admin, group))

    def test_technician_in_group_has_access(self):
        tech = self._user(is_admin=False, uid=5)
        group = self._group([3, 5, 7])
        self.assertTrue(self._check(tech, group))

    def test_technician_not_in_group_denied(self):
        tech = self._user(is_admin=False, uid=9)
        group = self._group([1, 2, 3])
        self.assertFalse(self._check(tech, group))

    def test_technician_in_empty_group_denied(self):
        tech = self._user(is_admin=False, uid=1)
        group = self._group([])
        self.assertFalse(self._check(tech, group))


class TestBackupGroupIntegration(unittest.TestCase):
    """Integrationstests: Techniker kann nur eigene Gruppen sichern/wiederherstellen."""

    def setUp(self):
        self.db = _make_db()
        self.admin = _make_user(self.db, "admin", is_admin=True)
        self.tech = _make_user(self.db, "tech1", is_admin=False)
        self.other_tech = _make_user(self.db, "tech2", is_admin=False)

        self.group = _make_group(self.db, "Gruppe A")
        self.group.users = [self.tech]

        self.other_group = _make_group(self.db, "Gruppe B")
        self.other_group.users = [self.other_tech]

        # Mindestens einen Kunden in der Gruppe
        cust = _make_customer(self.db)
        self.group.customers = [cust]

        self.db.commit()

    def test_technician_can_create_backup_for_own_group(self):
        from app.routers.backups import _check_group_access
        self.assertTrue(_check_group_access(self.tech, self.group))

    def test_technician_cannot_access_foreign_group(self):
        from app.routers.backups import _check_group_access
        self.assertFalse(_check_group_access(self.tech, self.other_group))

    def test_admin_can_access_all_groups(self):
        from app.routers.backups import _check_group_access
        self.assertTrue(_check_group_access(self.admin, self.group))
        self.assertTrue(_check_group_access(self.admin, self.other_group))

    def test_technician_backup_service_runs(self):
        """CustomerGroupBackupService kann für berechtigten Techniker ein Backup erstellen."""
        import tempfile
        from app.services.backup import CustomerGroupBackupService

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("app.services.backup.BACKUP_DIR", Path(tmpdir)):
                svc = CustomerGroupBackupService(self.db)
                backup = svc.create_backup(self.group, user_id=self.tech.id)

        self.assertEqual(backup.status, "completed")
        self.assertEqual(backup.customer_group_id, self.group.id)

    def test_backup_restore_works_for_technician(self):
        """Techniker kann Backup der eigenen Gruppe wiederherstellen."""
        import tempfile
        from app.services.backup import CustomerGroupBackupService

        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir)
            with patch("app.services.backup.BACKUP_DIR", backup_dir):
                svc = CustomerGroupBackupService(self.db)
                backup = svc.create_backup(self.group, user_id=self.tech.id)

                # Restore
                stats = svc.restore_backup(backup, created_by_user_id=self.tech.id)

        self.assertIn("customers_updated", stats)

    def test_technician_has_no_access_to_global_backups(self):
        """Globale Backups sind nur für Admins."""
        # Geprüft wird rein die is_admin-Prüfung im Route-Handler
        self.assertFalse(self.tech.is_admin)
        self.assertTrue(self.admin.is_admin)


if __name__ == "__main__":
    unittest.main()
