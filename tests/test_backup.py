"""Tests für den Backup- und Restore-Service."""
from __future__ import annotations

import gzip
import json
import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

os.environ.setdefault("APP_SECRET_KEY", "test-secret-key-for-testing-only-32chars")
os.environ.setdefault("CSR_KEY_PASSPHRASE", "test-passphrase")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")


from app import models
from app.services.backup import (
    CustomerGroupBackupService,
    GlobalBackupService,
    _sha256_file,
    human_size,
)


# ── Hilfsfunktionen ──────────────────────────────────────────────────────────

def _make_db():
    """Erstellt eine In-Memory-SQLAlchemy-Session."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.database import Base

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    return Session()


def _make_customer(db, name: str = "Test GmbH") -> models.Customer:
    c = models.Customer(name=name, contact_email="test@example.com")
    db.add(c)
    db.flush()
    return c


def _make_domain(db, customer: models.Customer, fqdn: str = "example.com") -> models.Domain:
    d = models.Domain(customer_id=customer.id, fqdn=fqdn)
    db.add(d)
    db.flush()
    return d


def _make_cert(
    db,
    customer: models.Customer,
    domain: models.Domain | None = None,
    cn: str = "example.com",
) -> models.Certificate:
    cert = models.Certificate(
        customer_id=customer.id,
        domain_id=domain.id if domain else None,
        common_name=cn,
        status="active",
        valid_until=datetime(2026, 1, 1),
    )
    db.add(cert)
    db.flush()
    return cert


def _make_group(db, name: str = "Testgruppe") -> models.CustomerGroup:
    g = models.CustomerGroup(name=name)
    db.add(g)
    db.flush()
    return g


def _make_user(db, username: str = "admin") -> models.User:
    u = models.User(
        username=username,
        email=f"{username}@example.com",
        hashed_password="hashed",
        is_admin=True,
    )
    db.add(u)
    db.flush()
    return u


# ── Tests: human_size ────────────────────────────────────────────────────────

class TestHumanSize(unittest.TestCase):
    def test_none_returns_dash(self):
        self.assertEqual(human_size(None), "–")

    def test_bytes(self):
        self.assertIn("B", human_size(512))

    def test_kilobytes(self):
        result = human_size(2048)
        self.assertIn("KB", result)

    def test_megabytes(self):
        result = human_size(5 * 1024 * 1024)
        self.assertIn("MB", result)


# ── Tests: SHA-256 ───────────────────────────────────────────────────────────

class TestSha256(unittest.TestCase):
    def test_checksum_consistent(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"hello world")
            path = Path(f.name)
        try:
            c1 = _sha256_file(path)
            c2 = _sha256_file(path)
            self.assertEqual(c1, c2)
            self.assertEqual(len(c1), 64)
        finally:
            path.unlink(missing_ok=True)

    def test_different_content_different_checksum(self):
        with tempfile.NamedTemporaryFile(delete=False) as f1, \
             tempfile.NamedTemporaryFile(delete=False) as f2:
            f1.write(b"hello")
            f2.write(b"world")
            p1, p2 = Path(f1.name), Path(f2.name)
        try:
            self.assertNotEqual(_sha256_file(p1), _sha256_file(p2))
        finally:
            p1.unlink(missing_ok=True)
            p2.unlink(missing_ok=True)


# ── Tests: GlobalBackupService ───────────────────────────────────────────────

class TestGlobalBackupService(unittest.TestCase):
    def setUp(self):
        self.db = _make_db()

    def tearDown(self):
        self.db.close()

    def _make_svc(self, tmp_dir: Path) -> GlobalBackupService:
        svc = GlobalBackupService(self.db)
        svc.backup_dir = tmp_dir / "global"
        svc.backup_dir.mkdir(parents=True, exist_ok=True)
        return svc

    def test_create_backup_requires_sqlite(self):
        """Backup schlägt fehl wenn keine SQLite-Datenbank."""
        with tempfile.TemporaryDirectory() as tmp:
            svc = self._make_svc(Path(tmp))
            with patch("app.services.backup._get_sqlite_path", return_value=None):
                with self.assertRaises(ValueError):
                    svc.create_backup()

    def test_create_backup_creates_archive(self):
        """Backup erstellt eine .tar.gz-Datei und einen Backup-Datensatz."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # Erstelle eine temporäre SQLite-DB als "Quelle"
            fake_db = tmp_path / "test.db"
            import sqlite3
            conn = sqlite3.connect(str(fake_db))
            conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
            conn.close()

            svc = self._make_svc(tmp_path)
            with patch("app.services.backup._get_sqlite_path", return_value=fake_db):
                backup = svc.create_backup(label="Test-Backup", user_id=None)

            self.assertEqual(backup.status, "completed")
            self.assertIsNotNone(backup.archive_path)
            self.assertIsNotNone(backup.checksum)
            self.assertGreater(backup.size_bytes or 0, 0)
            self.assertTrue(Path(backup.archive_path).exists())

    def test_create_backup_checksum_matches(self):
        """Gespeicherte Prüfsumme stimmt mit der Archiv-Datei überein."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_db = tmp_path / "test.db"
            import sqlite3
            sqlite3.connect(str(fake_db)).close()

            svc = self._make_svc(tmp_path)
            with patch("app.services.backup._get_sqlite_path", return_value=fake_db):
                backup = svc.create_backup()

            actual = _sha256_file(Path(backup.archive_path))
            self.assertEqual(actual, backup.checksum)

    def test_create_backup_writes_manifest(self):
        """manifest.json wird neben dem Archiv angelegt."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_db = tmp_path / "test.db"
            import sqlite3
            sqlite3.connect(str(fake_db)).close()

            svc = self._make_svc(tmp_path)
            with patch("app.services.backup._get_sqlite_path", return_value=fake_db):
                backup = svc.create_backup()

            manifest = Path(backup.archive_path).parent / "manifest.json"
            self.assertTrue(manifest.exists())
            data = json.loads(manifest.read_text())
            self.assertEqual(data["backup_type"], "global")

    def test_list_backups_returns_only_global(self):
        """list_backups() gibt nur globale Backups zurück."""
        # Lege gemischte Backups an
        b_global = models.Backup(backup_type="global", status="completed")
        b_group = models.Backup(backup_type="customer_group", status="completed")
        self.db.add_all([b_global, b_group])
        self.db.commit()

        with tempfile.TemporaryDirectory() as tmp:
            svc = self._make_svc(Path(tmp))
            result = svc.list_backups()

        self.assertTrue(all(b.backup_type == "global" for b in result))
        self.assertEqual(len(result), 1)

    def test_delete_backup_removes_record_and_file(self):
        """delete_backup() löscht DB-Eintrag und Archiv-Datei."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_db = tmp_path / "test.db"
            import sqlite3
            sqlite3.connect(str(fake_db)).close()

            svc = self._make_svc(tmp_path)
            with patch("app.services.backup._get_sqlite_path", return_value=fake_db):
                backup = svc.create_backup()

            archive_path = Path(backup.archive_path)
            self.assertTrue(archive_path.exists())

            svc.delete_backup(backup)

            self.assertFalse(archive_path.exists())
            remaining = self.db.query(models.Backup).filter(
                models.Backup.id == backup.id
            ).first()
            self.assertIsNone(remaining)

    def test_restore_checksum_mismatch_raises(self):
        """Restore schlägt fehl wenn Prüfsumme nicht passt."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_db = tmp_path / "source.db"
            import sqlite3
            sqlite3.connect(str(fake_db)).close()

            svc = self._make_svc(tmp_path)
            with patch("app.services.backup._get_sqlite_path", return_value=fake_db):
                backup = svc.create_backup()

            # Manipuliere die gespeicherte Prüfsumme
            backup.checksum = "0" * 64
            self.db.commit()

            with patch("app.services.backup._get_sqlite_path", return_value=fake_db):
                with self.assertRaises(ValueError):
                    svc.restore_backup(backup)

    def test_restore_missing_file_raises(self):
        """Restore schlägt fehl wenn Archiv-Datei fehlt."""
        backup = models.Backup(
            backup_type="global",
            status="completed",
            archive_path="/nonexistent/path/backup.tar.gz",
            checksum="abc123",
        )
        self.db.add(backup)
        self.db.commit()

        with tempfile.TemporaryDirectory() as tmp:
            svc = self._make_svc(Path(tmp))
            with self.assertRaises(FileNotFoundError):
                svc.restore_backup(backup)


# ── Tests: CustomerGroupBackupService ────────────────────────────────────────

class TestCustomerGroupBackupService(unittest.TestCase):
    def setUp(self):
        self.db = _make_db()
        self.user = _make_user(self.db)
        self.group = _make_group(self.db)
        self.customer = _make_customer(self.db)
        self.group.customers.append(self.customer)
        self.db.flush()

    def tearDown(self):
        self.db.close()

    def _make_svc(self, tmp_dir: Path) -> CustomerGroupBackupService:
        svc = CustomerGroupBackupService(self.db)
        svc.backup_dir = tmp_dir / "groups"
        svc.backup_dir.mkdir(parents=True, exist_ok=True)
        return svc

    def test_create_backup_creates_compressed_json(self):
        """Backup erstellt eine .json.gz-Datei mit customer-Daten."""
        with tempfile.TemporaryDirectory() as tmp:
            svc = self._make_svc(Path(tmp))
            backup = svc.create_backup(group=self.group, user_id=self.user.id)

            self.assertEqual(backup.status, "completed")
            self.assertIsNotNone(backup.archive_path)
            archive = Path(backup.archive_path)
            self.assertTrue(archive.exists())
            self.assertTrue(archive.name.endswith(".json.gz"))

    def test_create_backup_json_contains_customers(self):
        """Die exportierte JSON enthält die Kunden der Gruppe."""
        with tempfile.TemporaryDirectory() as tmp:
            svc = self._make_svc(Path(tmp))
            backup = svc.create_backup(group=self.group)

            with gzip.open(backup.archive_path, "rt", encoding="utf-8") as f:
                data = json.load(f)

        self.assertEqual(data["group_id"], self.group.id)
        self.assertEqual(data["customer_count"], 1)
        self.assertEqual(len(data["customers"]), 1)
        self.assertEqual(data["customers"][0]["name"], self.customer.name)

    def test_create_backup_checksum_valid(self):
        """Gespeicherte Prüfsumme stimmt mit Archiv überein."""
        with tempfile.TemporaryDirectory() as tmp:
            svc = self._make_svc(Path(tmp))
            backup = svc.create_backup(group=self.group)

            actual = _sha256_file(Path(backup.archive_path))
        self.assertEqual(actual, backup.checksum)

    def test_create_backup_includes_domains_and_certs(self):
        """Backup enthält Domains und Zertifikate des Kunden."""
        domain = _make_domain(self.db, self.customer)
        _make_cert(self.db, self.customer, domain)
        self.db.commit()

        with tempfile.TemporaryDirectory() as tmp:
            svc = self._make_svc(Path(tmp))
            backup = svc.create_backup(group=self.group)

            with gzip.open(backup.archive_path, "rt", encoding="utf-8") as f:
                data = json.load(f)

        cust_data = data["customers"][0]
        self.assertEqual(len(cust_data["domains"]), 1)
        self.assertEqual(cust_data["domains"][0]["fqdn"], domain.fqdn)
        self.assertEqual(len(cust_data["certificates"]), 1)

    def test_list_backups_for_group_filters_by_group(self):
        """list_backups_for_group() gibt nur Backups der angegebenen Gruppe zurück."""
        other_group = _make_group(self.db, "Andere Gruppe")
        b1 = models.Backup(backup_type="customer_group", customer_group_id=self.group.id, status="completed")
        b2 = models.Backup(backup_type="customer_group", customer_group_id=other_group.id, status="completed")
        self.db.add_all([b1, b2])
        self.db.commit()

        with tempfile.TemporaryDirectory() as tmp:
            svc = self._make_svc(Path(tmp))
            result = svc.list_backups_for_group(self.group.id)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].customer_group_id, self.group.id)

    def test_restore_creates_new_customer_when_not_found(self):
        """Restore legt einen neuen Kunden an wenn ID nicht existiert."""
        with tempfile.TemporaryDirectory() as tmp:
            svc = self._make_svc(Path(tmp))
            backup = svc.create_backup(group=self.group, user_id=self.user.id)

            # Entferne den Kunden und starte Restore
            self.db.delete(self.customer)
            self.db.commit()

            stats = svc.restore_backup(backup, created_by_user_id=self.user.id)

        # Kunde wurde neu angelegt
        self.assertGreaterEqual(stats["customers_created"], 1)

    def test_restore_updates_existing_customer(self):
        """Restore aktualisiert vorhandene Kunden anstatt sie zu duplizieren."""
        with tempfile.TemporaryDirectory() as tmp:
            svc = self._make_svc(Path(tmp))
            backup = svc.create_backup(group=self.group, user_id=self.user.id)

            # Verändere Kunden-Daten
            self.customer.name = "Geänderter Name"
            self.db.commit()

            stats = svc.restore_backup(backup, created_by_user_id=self.user.id)

        self.assertGreaterEqual(stats["customers_updated"], 1)
        # Name wurde wiederhergestellt
        self.db.refresh(self.customer)
        self.assertEqual(self.customer.name, "Test GmbH")

    def test_restore_rollback_on_error(self):
        """Restore rollt bei Fehler zurück und lässt keine Teildaten zurück."""
        with tempfile.TemporaryDirectory() as tmp:
            svc = self._make_svc(Path(tmp))
            backup = svc.create_backup(group=self.group, user_id=self.user.id)

            # Manipuliere Prüfsumme → Restore schlägt fehl
            backup.checksum = "f" * 64
            self.db.commit()

            initial_count = self.db.query(models.Customer).count()

            with self.assertRaises(ValueError):
                svc.restore_backup(backup, created_by_user_id=self.user.id)

        # Kein neuer Kunde angelegt
        self.assertEqual(self.db.query(models.Customer).count(), initial_count)

    def test_restore_missing_archive_raises(self):
        """Restore schlägt fehl wenn Archiv-Datei fehlt."""
        backup = models.Backup(
            backup_type="customer_group",
            status="completed",
            archive_path="/nonexistent/backup.json.gz",
            checksum="abc123",
        )
        self.db.add(backup)
        self.db.commit()

        with tempfile.TemporaryDirectory() as tmp:
            svc = self._make_svc(Path(tmp))
            with self.assertRaises(FileNotFoundError):
                svc.restore_backup(backup, created_by_user_id=self.user.id)

    def test_delete_backup_removes_file(self):
        """delete_backup() entfernt Datei und DB-Eintrag."""
        with tempfile.TemporaryDirectory() as tmp:
            svc = self._make_svc(Path(tmp))
            backup = svc.create_backup(group=self.group)
            archive = Path(backup.archive_path)
            self.assertTrue(archive.exists())

            svc.delete_backup(backup)
            self.assertFalse(archive.exists())

        remaining = self.db.query(models.Backup).filter(
            models.Backup.id == backup.id
        ).first()
        self.assertIsNone(remaining)

    def test_backup_with_attachments_serializes_binary(self):
        """Anhänge werden als base64 in das JSON-Backup kodiert."""
        import base64
        cert = _make_cert(self.db, self.customer)
        att = models.CertificateAttachment(
            certificate_id=cert.id,
            user_id=self.user.id,
            filename="test.pdf",
            content_type="application/pdf",
            file_size=5,
            data=b"hello",
        )
        self.db.add(att)
        self.db.commit()

        with tempfile.TemporaryDirectory() as tmp:
            svc = self._make_svc(Path(tmp))
            backup = svc.create_backup(group=self.group)

            with gzip.open(backup.archive_path, "rt", encoding="utf-8") as f:
                data = json.load(f)

        certs = data["customers"][0]["certificates"]
        self.assertEqual(len(certs), 1)
        attachments = certs[0]["attachments"]
        self.assertEqual(len(attachments), 1)
        self.assertEqual(attachments[0]["filename"], "test.pdf")
        decoded = base64.b64decode(attachments[0]["data_b64"])
        self.assertEqual(decoded, b"hello")

    def test_backup_empty_group(self):
        """Backup einer leeren Gruppe (ohne Kunden) gelingt ohne Fehler."""
        empty_group = _make_group(self.db, "Leere Gruppe")
        self.db.commit()

        with tempfile.TemporaryDirectory() as tmp:
            svc = self._make_svc(Path(tmp))
            backup = svc.create_backup(group=empty_group, user_id=self.user.id)

            self.assertEqual(backup.status, "completed")

            with gzip.open(backup.archive_path, "rt", encoding="utf-8") as f:
                data = json.load(f)
        self.assertEqual(data["customer_count"], 0)
        self.assertEqual(data["customers"], [])


# ── Tests: Backup-Modell ─────────────────────────────────────────────────────

class TestBackupModel(unittest.TestCase):
    def setUp(self):
        self.db = _make_db()

    def tearDown(self):
        self.db.close()

    def test_backup_model_fields(self):
        """Backup-Modell kann mit allen Feldern angelegt werden."""
        b = models.Backup(
            backup_type="global",
            label="Test",
            status="completed",
            archive_path="/tmp/backup.tar.gz",
            size_bytes=1024,
            checksum="a" * 64,
            restore_count=0,
        )
        self.db.add(b)
        self.db.commit()

        stored = self.db.query(models.Backup).filter(models.Backup.id == b.id).first()
        self.assertIsNotNone(stored)
        self.assertEqual(stored.backup_type, "global")
        self.assertEqual(stored.label, "Test")
        self.assertEqual(stored.status, "completed")
        self.assertEqual(stored.size_bytes, 1024)

    def test_backup_repr(self):
        b = models.Backup(backup_type="global", status="pending")
        self.assertIn("global", repr(b))
        self.assertIn("pending", repr(b))


if __name__ == "__main__":
    unittest.main()
