"""Backup- und Restore-Service für globale Datenbank-Backups und Kundengruppen-Exporte."""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import logging
import os
import sqlite3
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet
from sqlalchemy.orm import Session

from .. import models
from ..database import DATABASE_URL

logger = logging.getLogger(__name__)


# ── Verschlüsselung ───────────────────────────────────────────────────────────

def _fernet_from_password(password: str) -> Fernet:
    """Leitet einen Fernet-Schlüssel aus dem Passwort via SHA-256 ab."""
    key = hashlib.sha256(password.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def _encrypt_bytes(data: bytes, password: str) -> bytes:
    return _fernet_from_password(password).encrypt(data)


def _decrypt_bytes(data: bytes, password: str) -> bytes:
    return _fernet_from_password(password).decrypt(data)


def _get_encryption_password(db: Session) -> str | None:
    """Gibt das Backup-Verschlüsselungspasswort aus den Einstellungen zurück."""
    try:
        from ..settings_service import get_settings_service
        svc = get_settings_service(db)
        pw = svc.get_str("backup.encryption_password", default="")
        return pw if pw else None
    except Exception:
        return None

# Backup-Verzeichnis relativ zum Projekt-Root
_PROJECT_ROOT = Path(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
BACKUP_DIR = _PROJECT_ROOT / "data" / "backups"


# ── Hilfsfunktionen ──────────────────────────────────────────────────────────

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _get_sqlite_path() -> Optional[Path]:
    """Extrahiert den SQLite-Dateipfad aus der DATABASE_URL."""
    if DATABASE_URL.startswith("sqlite:///"):
        raw = DATABASE_URL.replace("sqlite:///", "")
        p = Path(raw)
        if not p.is_absolute():
            p = _PROJECT_ROOT / p
        return p
    return None


def _fmt_ts() -> str:
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S")


def human_size(size_bytes: int | None) -> str:
    if not size_bytes:
        return "–"
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


# ── Globaler Backup-Service ──────────────────────────────────────────────────

class GlobalBackupService:
    """Erstellt und stellt ein vollständiges SQLite-Datenbank-Backup wieder her."""

    def __init__(self, db: Session):
        self.db = db
        self.backup_dir = BACKUP_DIR / "global"
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def create_backup(
        self,
        label: str | None = None,
        user_id: int | None = None,
    ) -> models.Backup:
        ts = _fmt_ts()
        slot_dir = self.backup_dir / ts
        slot_dir.mkdir(parents=True, exist_ok=True)

        backup = models.Backup(
            backup_type="global",
            label=label or f"Globales Backup {datetime.utcnow().strftime('%d.%m.%Y %H:%M')} UTC",
            status="pending",
            created_by_user_id=user_id,
        )
        self.db.add(backup)
        self.db.flush()

        try:
            db_path = _get_sqlite_path()
            if db_path is None:
                raise ValueError(
                    "Nur SQLite-Datenbanken werden für globale Backups unterstützt."
                )

            archive_path = slot_dir / "backup.tar.gz"
            tmp_db = slot_dir / "backup.db"

            # Konsistentes SQLite-Backup via offizieller Backup-API
            src = sqlite3.connect(str(db_path))
            dst = sqlite3.connect(str(tmp_db))
            try:
                src.backup(dst)
            finally:
                dst.close()
                src.close()

            with tarfile.open(archive_path, "w:gz") as tar:
                tar.add(tmp_db, arcname="backup.db")
            tmp_db.unlink(missing_ok=True)

            # Optionale Verschlüsselung
            enc_password = _get_encryption_password(self.db)
            encrypted = False
            if enc_password:
                raw = archive_path.read_bytes()
                archive_path.write_bytes(_encrypt_bytes(raw, enc_password))
                encrypted = True

            checksum = _sha256_file(archive_path)
            size_bytes = archive_path.stat().st_size

            meta = {
                "created_at": datetime.utcnow().isoformat(),
                "backup_type": "global",
                "label": backup.label,
                "db_path": str(db_path),
                "checksum": checksum,
                "size_bytes": size_bytes,
                "encrypted": encrypted,
            }
            (slot_dir / "manifest.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False))

            backup.status = "completed"
            backup.archive_path = str(archive_path)
            backup.size_bytes = size_bytes
            backup.checksum = checksum
            backup.metadata_json = json.dumps(meta, ensure_ascii=False)
            self.db.commit()

            logger.info("Globales Backup erstellt: %s (%d Bytes)", archive_path, size_bytes)
            return backup

        except Exception as exc:
            backup.status = "failed"
            backup.error_message = str(exc)
            self.db.commit()
            logger.exception("Globales Backup fehlgeschlagen.")
            raise

    def restore_backup(self, backup: models.Backup) -> None:
        """Stellt ein globales Backup wieder her (überschreibt die aktuelle DB)."""
        archive_path = Path(backup.archive_path)
        if not archive_path.exists():
            raise FileNotFoundError(f"Archiv-Datei nicht gefunden: {archive_path}")

        actual = _sha256_file(archive_path)
        if actual != backup.checksum:
            raise ValueError(
                f"Prüfsummen-Fehler – Archiv beschädigt. "
                f"Erwartet: {backup.checksum}, erhalten: {actual}"
            )

        db_path = _get_sqlite_path()
        if db_path is None:
            raise ValueError("Nur SQLite-Datenbanken werden für globale Restores unterstützt.")

        # Ggf. entschlüsseln
        meta = {}
        manifest_path = archive_path.parent / "manifest.json"
        if manifest_path.exists():
            try:
                meta = json.loads(manifest_path.read_text())
            except Exception:
                pass
        is_encrypted = meta.get("encrypted", False)

        with tempfile.TemporaryDirectory() as tmpdir:
            raw_data = archive_path.read_bytes()
            if is_encrypted:
                enc_password = _get_encryption_password(self.db)
                if not enc_password:
                    raise ValueError("Backup ist verschlüsselt, aber kein Entschlüsselungspasswort konfiguriert.")
                raw_data = _decrypt_bytes(raw_data, enc_password)
            # tar.gz aus Bytes extrahieren
            import io
            with tarfile.open(fileobj=io.BytesIO(raw_data), mode="r:gz") as tar:
                tar.extractall(tmpdir)
            extracted = Path(tmpdir) / "backup.db"

            src = sqlite3.connect(str(extracted))
            dst = sqlite3.connect(str(db_path))
            try:
                src.backup(dst)
            finally:
                dst.close()
                src.close()

        backup.restore_count = (backup.restore_count or 0) + 1
        backup.last_restored_at = datetime.utcnow()
        self.db.commit()

        logger.info("Globales Backup wiederhergestellt von: %s", archive_path)

    def delete_backup(self, backup: models.Backup) -> None:
        if backup.archive_path:
            p = Path(backup.archive_path)
            p.unlink(missing_ok=True)
            # Verzeichnis entfernen wenn leer
            try:
                p.parent.rmdir()
            except OSError:
                pass
        self.db.delete(backup)
        self.db.commit()

    def list_backups(self) -> list[models.Backup]:
        return (
            self.db.query(models.Backup)
            .filter(models.Backup.backup_type == "global")
            .order_by(models.Backup.created_at.desc())
            .all()
        )


# ── Kundengruppen-Backup-Service ─────────────────────────────────────────────

class CustomerGroupBackupService:
    """JSON-basiertes Backup einer Kundengruppe (alle Kunden inkl. aller Relationen)."""

    def __init__(self, db: Session):
        self.db = db
        self.backup_dir = BACKUP_DIR / "groups"
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    # ── Serialisierung ───────────────────────────────────────────────────────

    @staticmethod
    def _serialize_customer(customer: models.Customer) -> dict:
        data: dict = {
            "id": customer.id,
            "name": customer.name,
            "contact_name": customer.contact_name,
            "contact_email": customer.contact_email,
            "notes": customer.notes,
            "is_archived": customer.is_archived,
            "created_at": customer.created_at.isoformat() if customer.created_at else None,
            "defaults": None,
            "domains": [],
            "certificates": [],
            "csr_requests": [],
        }

        if customer.defaults:
            d = customer.defaults
            data["defaults"] = {
                "default_country": d.default_country,
                "default_state": d.default_state,
                "default_locality": d.default_locality,
                "default_org": d.default_org,
                "default_ou": d.default_ou,
                "preferred_validity_days": d.preferred_validity_days,
                "preferred_product_sku": d.preferred_product_sku,
                "validation_notes": d.validation_notes,
                "technical_notes": d.technical_notes,
            }

        for dom in customer.domains:
            data["domains"].append({
                "id": dom.id,
                "fqdn": dom.fqdn,
                "notes": dom.notes,
                "created_at": dom.created_at.isoformat() if dom.created_at else None,
            })

        for cert in customer.certificates:
            cert_data: dict = {
                "id": cert.id,
                "domain_id": cert.domain_id,
                "common_name": cert.common_name,
                "san": cert.san,
                "issuer": cert.issuer,
                "serial_number": cert.serial_number,
                "valid_from": cert.valid_from.isoformat() if cert.valid_from else None,
                "valid_until": cert.valid_until.isoformat() if cert.valid_until else None,
                "status": cert.status,
                "auto_renew": cert.auto_renew,
                "notes": cert.notes,
                "is_archived": cert.is_archived,
                "cert_pem": cert.cert_pem,
                "chain_pem": cert.chain_pem,
                "created_at": cert.created_at.isoformat() if cert.created_at else None,
                "notes_history": [],
                "attachments": [],
            }
            for note in cert.notes_history:
                cert_data["notes_history"].append({
                    "note": note.note,
                    "created_at": note.created_at.isoformat() if note.created_at else None,
                })
            for att in cert.attachments:
                cert_data["attachments"].append({
                    "filename": att.filename,
                    "content_type": att.content_type,
                    "file_size": att.file_size,
                    "data_b64": base64.b64encode(att.data).decode("ascii"),
                    "created_at": att.created_at.isoformat() if att.created_at else None,
                })
            data["certificates"].append(cert_data)

        for csr in customer.csr_requests:
            data["csr_requests"].append({
                "id": csr.id,
                "domain_id": csr.domain_id,
                "common_name": csr.common_name,
                "sans": csr.sans,
                "country": csr.country,
                "state": csr.state,
                "locality": csr.locality,
                "organization": csr.organization,
                "organizational_unit": csr.organizational_unit,
                "email": csr.email,
                "key_size": csr.key_size,
                "csr_pem": csr.csr_pem,
                "private_key_encrypted": csr.private_key_encrypted,
                "is_archived": csr.is_archived,
                "created_at": csr.created_at.isoformat() if csr.created_at else None,
            })

        return data

    # ── Backup erstellen ─────────────────────────────────────────────────────

    def create_backup(
        self,
        group: models.CustomerGroup,
        label: str | None = None,
        user_id: int | None = None,
    ) -> models.Backup:
        ts = _fmt_ts()
        slot_dir = self.backup_dir / str(group.id) / ts
        slot_dir.mkdir(parents=True, exist_ok=True)

        backup = models.Backup(
            backup_type="customer_group",
            customer_group_id=group.id,
            label=label or f"Backup {group.name} {datetime.utcnow().strftime('%d.%m.%Y %H:%M')} UTC",
            status="pending",
            created_by_user_id=user_id,
        )
        self.db.add(backup)
        self.db.flush()

        try:
            customers_data = [self._serialize_customer(c) for c in group.customers]

            export = {
                "backup_type": "customer_group",
                "format_version": 1,
                "group_id": group.id,
                "group_name": group.name,
                "created_at": datetime.utcnow().isoformat(),
                "customer_count": len(customers_data),
                "customers": customers_data,
            }

            archive_path = slot_dir / "backup.json.gz"
            with gzip.open(archive_path, "wt", encoding="utf-8") as fh:
                json.dump(export, fh, ensure_ascii=False, indent=2)

            # Optionale Verschlüsselung
            enc_password = _get_encryption_password(self.db)
            encrypted = False
            if enc_password:
                raw = archive_path.read_bytes()
                archive_path.write_bytes(_encrypt_bytes(raw, enc_password))
                encrypted = True

            checksum = _sha256_file(archive_path)
            size_bytes = archive_path.stat().st_size

            manifest = {
                "created_at": datetime.utcnow().isoformat(),
                "backup_type": "customer_group",
                "group_id": group.id,
                "group_name": group.name,
                "customer_count": len(customers_data),
                "checksum": checksum,
                "size_bytes": size_bytes,
                "label": backup.label,
                "encrypted": encrypted,
            }
            (slot_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False))

            backup.status = "completed"
            backup.archive_path = str(archive_path)
            backup.size_bytes = size_bytes
            backup.checksum = checksum
            backup.metadata_json = json.dumps(manifest, ensure_ascii=False)
            self.db.commit()

            logger.info(
                "Kundengruppen-Backup erstellt: %s (%d Kunden, %d Bytes)",
                archive_path, len(customers_data), size_bytes,
            )
            return backup

        except Exception as exc:
            backup.status = "failed"
            backup.error_message = str(exc)
            self.db.commit()
            logger.exception("Kundengruppen-Backup fehlgeschlagen.")
            raise

    # ── Restore ──────────────────────────────────────────────────────────────

    def restore_backup(
        self,
        backup: models.Backup,
        created_by_user_id: int,
    ) -> dict:
        """Stellt das Backup einer Kundengruppe wieder her. Gibt Statistik-Dict zurück."""
        archive_path = Path(backup.archive_path)
        if not archive_path.exists():
            raise FileNotFoundError(f"Archiv-Datei nicht gefunden: {archive_path}")

        actual = _sha256_file(archive_path)
        if actual != backup.checksum:
            raise ValueError(
                f"Prüfsummen-Fehler – Archiv beschädigt. "
                f"Erwartet: {backup.checksum}, erhalten: {actual}"
            )

        # Ggf. entschlüsseln
        cg_meta = {}
        cg_manifest = archive_path.parent / "manifest.json"
        if cg_manifest.exists():
            try:
                cg_meta = json.loads(cg_manifest.read_text())
            except Exception:
                pass
        cg_encrypted = cg_meta.get("encrypted", False)

        raw_gz = archive_path.read_bytes()
        if cg_encrypted:
            enc_password = _get_encryption_password(self.db)
            if not enc_password:
                raise ValueError("Backup ist verschlüsselt, aber kein Entschlüsselungspasswort konfiguriert.")
            raw_gz = _decrypt_bytes(raw_gz, enc_password)

        import io as _io
        with gzip.open(_io.BytesIO(raw_gz), "rt", encoding="utf-8") as fh:
            export = json.load(fh)

        stats: dict[str, int] = {
            "customers_created": 0,
            "customers_updated": 0,
            "domains_created": 0,
            "certs_created": 0,
            "csrs_created": 0,
        }

        try:
            for cust_data in export.get("customers", []):
                self._restore_customer(cust_data, created_by_user_id, stats)

            backup.restore_count = (backup.restore_count or 0) + 1
            backup.last_restored_at = datetime.utcnow()
            self.db.commit()

        except Exception:
            self.db.rollback()
            raise

        logger.info("Kundengruppen-Backup wiederhergestellt: %s → %s", archive_path, stats)
        return stats

    def _restore_customer(
        self,
        data: dict,
        user_id: int,
        stats: dict,
    ) -> models.Customer:
        # Versuche zuerst per Original-ID, dann per Name
        customer = self.db.query(models.Customer).filter(
            models.Customer.id == data["id"]
        ).first()

        if customer:
            customer.name = data["name"]
            customer.contact_name = data.get("contact_name")
            customer.contact_email = data.get("contact_email")
            customer.notes = data.get("notes")
            customer.is_archived = data.get("is_archived", False)
            stats["customers_updated"] += 1
        else:
            customer = models.Customer(
                name=data["name"],
                contact_name=data.get("contact_name"),
                contact_email=data.get("contact_email"),
                notes=data.get("notes"),
                is_archived=data.get("is_archived", False),
            )
            self.db.add(customer)
            self.db.flush()
            stats["customers_created"] += 1

        # Defaults
        if data.get("defaults"):
            d = data["defaults"]
            defaults = customer.defaults or models.CustomerDefaults(customer_id=customer.id)
            if not customer.defaults:
                self.db.add(defaults)
            defaults.default_country = d.get("default_country")
            defaults.default_state = d.get("default_state")
            defaults.default_locality = d.get("default_locality")
            defaults.default_org = d.get("default_org")
            defaults.default_ou = d.get("default_ou")
            defaults.preferred_validity_days = d.get("preferred_validity_days")
            defaults.preferred_product_sku = d.get("preferred_product_sku")
            defaults.validation_notes = d.get("validation_notes")
            defaults.technical_notes = d.get("technical_notes")

        # Domains – alte ID → neues Objekt
        domain_id_map: dict[int, models.Domain] = {}
        for dom_data in data.get("domains", []):
            dom = self.db.query(models.Domain).filter(
                models.Domain.id == dom_data["id"]
            ).first()
            if dom:
                dom.fqdn = dom_data["fqdn"]
                dom.notes = dom_data.get("notes")
            else:
                dom = models.Domain(
                    customer_id=customer.id,
                    fqdn=dom_data["fqdn"],
                    notes=dom_data.get("notes"),
                )
                self.db.add(dom)
                self.db.flush()
                stats["domains_created"] += 1
            domain_id_map[dom_data["id"]] = dom

        # Zertifikate
        for cert_data in data.get("certificates", []):
            new_domain_id = None
            if cert_data.get("domain_id") is not None:
                mapped = domain_id_map.get(cert_data["domain_id"])
                if mapped:
                    new_domain_id = mapped.id

            cert = self.db.query(models.Certificate).filter(
                models.Certificate.id == cert_data["id"]
            ).first()

            def _parse_dt(v: str | None) -> datetime | None:
                return datetime.fromisoformat(v) if v else None

            if cert:
                cert.domain_id = new_domain_id
                cert.common_name = cert_data["common_name"]
                cert.san = cert_data.get("san")
                cert.issuer = cert_data.get("issuer")
                cert.serial_number = cert_data.get("serial_number")
                cert.valid_from = _parse_dt(cert_data.get("valid_from"))
                cert.valid_until = _parse_dt(cert_data.get("valid_until"))
                cert.status = cert_data.get("status", "pending")
                cert.auto_renew = cert_data.get("auto_renew", False)
                cert.notes = cert_data.get("notes")
                cert.is_archived = cert_data.get("is_archived", False)
                cert.cert_pem = cert_data.get("cert_pem")
                cert.chain_pem = cert_data.get("chain_pem")
            else:
                cert = models.Certificate(
                    customer_id=customer.id,
                    domain_id=new_domain_id,
                    common_name=cert_data["common_name"],
                    san=cert_data.get("san"),
                    issuer=cert_data.get("issuer"),
                    serial_number=cert_data.get("serial_number"),
                    valid_from=_parse_dt(cert_data.get("valid_from")),
                    valid_until=_parse_dt(cert_data.get("valid_until")),
                    status=cert_data.get("status", "pending"),
                    auto_renew=cert_data.get("auto_renew", False),
                    notes=cert_data.get("notes"),
                    is_archived=cert_data.get("is_archived", False),
                    cert_pem=cert_data.get("cert_pem"),
                    chain_pem=cert_data.get("chain_pem"),
                )
                self.db.add(cert)
                self.db.flush()
                stats["certs_created"] += 1

                for n in cert_data.get("notes_history", []):
                    self.db.add(models.CertificateNote(
                        certificate_id=cert.id,
                        user_id=user_id,
                        note=n["note"],
                    ))
                for att in cert_data.get("attachments", []):
                    self.db.add(models.CertificateAttachment(
                        certificate_id=cert.id,
                        user_id=user_id,
                        filename=att["filename"],
                        content_type=att.get("content_type", "application/octet-stream"),
                        file_size=att.get("file_size", 0),
                        data=base64.b64decode(att["data_b64"]),
                    ))

        # CSR-Requests
        for csr_data in data.get("csr_requests", []):
            if self.db.query(models.CsrRequest).filter(
                models.CsrRequest.id == csr_data["id"]
            ).first():
                continue  # vorhandene CSRs nicht überschreiben

            new_domain_id = None
            if csr_data.get("domain_id") is not None:
                mapped = domain_id_map.get(csr_data["domain_id"])
                if mapped:
                    new_domain_id = mapped.id

            self.db.add(models.CsrRequest(
                customer_id=customer.id,
                domain_id=new_domain_id,
                created_by=user_id,
                common_name=csr_data["common_name"],
                sans=csr_data.get("sans"),
                country=csr_data.get("country"),
                state=csr_data.get("state"),
                locality=csr_data.get("locality"),
                organization=csr_data.get("organization"),
                organizational_unit=csr_data.get("organizational_unit"),
                email=csr_data.get("email"),
                key_size=csr_data.get("key_size", 2048),
                csr_pem=csr_data["csr_pem"],
                private_key_encrypted=csr_data["private_key_encrypted"],
                is_archived=csr_data.get("is_archived", False),
            ))
            stats["csrs_created"] += 1

        self.db.flush()
        return customer

    # ── Hilfsmethoden ────────────────────────────────────────────────────────

    def delete_backup(self, backup: models.Backup) -> None:
        if backup.archive_path:
            p = Path(backup.archive_path)
            p.unlink(missing_ok=True)
            try:
                p.parent.rmdir()
            except OSError:
                pass
        self.db.delete(backup)
        self.db.commit()

    def list_backups_for_group(self, group_id: int) -> list[models.Backup]:
        return (
            self.db.query(models.Backup)
            .filter(
                models.Backup.backup_type == "customer_group",
                models.Backup.customer_group_id == group_id,
            )
            .order_by(models.Backup.created_at.desc())
            .all()
        )
