"""
Import/Export-Service für CSRs und Zertifikate.

Exportformat: JSON (ohne Private Key) oder ZIP (mit Private Key).
ZIP-Struktur: manifest.json + optionale PEM-Dateien.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import zipfile
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from .. import models

EXPORT_VERSION = "1.0"
_SUPPORTED_VERSIONS = {"1.0"}


# ── Hilfsfunktionen ───────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fingerprint_sha256(cert_pem: str) -> str:
    """SHA-256-Fingerprint eines PEM-Zertifikats als XX:YY:ZZ-Hex."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes as _hashes
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        fp = cert.fingerprint(_hashes.SHA256())
        return ":".join(f"{b:02X}" for b in fp)
    except Exception:
        raw = cert_pem.encode()
        h = hashlib.sha256(raw).hexdigest()
        return ":".join(h[i : i + 2].upper() for i in range(0, min(len(h), 64), 2))


def _encrypt_key(plain_pem: str) -> str:
    """Verschlüsselt einen plaintext Private Key mit dem lokalen CSR_KEY_PASSPHRASE."""
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key, Encoding, PrivateFormat, BestAvailableEncryption,
    )
    from ..crypto import _passphrase
    key_obj = load_pem_private_key(plain_pem.encode(), password=None)
    return key_obj.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=BestAvailableEncryption(_passphrase()),
    ).decode("utf-8")


# ── Export ────────────────────────────────────────────────────────────────────

def export_csr(csr: models.CsrRequest, include_key: bool = False) -> dict[str, Any]:
    """Erstellt das Export-Manifest für einen CSR."""
    from ..crypto import decrypt_private_key

    data: dict[str, Any] = {
        "common_name": csr.common_name,
        "csr_pem": csr.csr_pem,
        "key_type": "RSA",
        "key_size": csr.key_size,
        "sans": csr.sans or "",
        "country": csr.country or "",
        "state": csr.state or "",
        "locality": csr.locality or "",
        "organization": csr.organization or "",
        "organizational_unit": csr.organizational_unit or "",
        "email": csr.email or "",
        "customer": csr.customer.name if csr.customer else "",
        "customer_group": (
            csr.customer.customer_groups[0].name
            if csr.customer and csr.customer.customer_groups
            else ""
        ),
        "domain": csr.domain.fqdn if csr.domain else "",
        "created_at": csr.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_id": csr.id,
    }

    if include_key and csr.private_key_encrypted:
        try:
            data["private_key_pem"] = decrypt_private_key(csr.private_key_encrypted).decode("utf-8")
        except Exception:
            pass

    return {
        "type": "csr",
        "version": EXPORT_VERSION,
        "exported_at": _now_iso(),
        "data": data,
    }


def export_certificate(
    cert: models.Certificate, include_key: bool = False
) -> dict[str, Any]:
    """Erstellt das Export-Manifest für ein Zertifikat."""
    from ..crypto import decrypt_private_key

    fingerprint = fingerprint_sha256(cert.cert_pem) if cert.cert_pem else ""

    data: dict[str, Any] = {
        "common_name": cert.common_name,
        "certificate_pem": cert.cert_pem or "",
        "chain_pem": cert.chain_pem or "",
        "csr_pem": cert.csr_request.csr_pem if cert.csr_request else "",
        "issuer": cert.issuer or "",
        "serial_number": cert.serial_number or "",
        "fingerprint_sha256": fingerprint,
        "san": cert.san or "",
        "valid_from": cert.valid_from.strftime("%Y-%m-%d") if cert.valid_from else "",
        "valid_until": cert.valid_until.strftime("%Y-%m-%d") if cert.valid_until else "",
        "status": cert.status,
        "notes": cert.notes or "",
        "customer": cert.customer.name if cert.customer else "",
        "customer_group": (
            cert.customer.customer_groups[0].name
            if cert.customer and cert.customer.customer_groups
            else ""
        ),
        "domain": cert.domain.fqdn if cert.domain else "",
        "key_size": cert.csr_request.key_size if cert.csr_request else 0,
        "created_at": cert.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_id": cert.id,
    }

    if include_key and cert.csr_request and cert.csr_request.private_key_encrypted:
        try:
            data["private_key_pem"] = decrypt_private_key(
                cert.csr_request.private_key_encrypted
            ).decode("utf-8")
        except Exception:
            pass

    return {
        "type": "certificate",
        "version": EXPORT_VERSION,
        "exported_at": _now_iso(),
        "data": data,
    }


def build_export_zip(manifest: dict, pem_files: dict[str, str]) -> bytes:
    """Baut eine ZIP-Datei aus manifest.json + optionalen PEM-Dateien."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False))
        for filename, content in pem_files.items():
            if content:
                zf.writestr(filename, content)
    buf.seek(0)
    return buf.read()


# ── Import: Datei parsen ──────────────────────────────────────────────────────

def parse_import_file(filename: str, content: bytes) -> tuple[dict | None, str]:
    """
    Parst eine JSON- oder ZIP-Import-Datei.
    Gibt (manifest_dict, fehler_text) zurück — fehler_text ist "" bei Erfolg.
    """
    fname_lower = filename.lower()

    if fname_lower.endswith(".json"):
        try:
            manifest = json.loads(content.decode("utf-8"))
            return manifest, ""
        except Exception as exc:
            return None, f"JSON-Parsing fehlgeschlagen: {exc}"

    elif fname_lower.endswith(".zip"):
        try:
            buf = io.BytesIO(content)
            with zipfile.ZipFile(buf, "r") as zf:
                names = zf.namelist()
                if "manifest.json" not in names:
                    return None, "ZIP enthält keine manifest.json."
                manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
                data = manifest.setdefault("data", {})

                # PEM-Dateien automatisch zuordnen
                for name in names:
                    if name == "manifest.json":
                        continue
                    file_content = zf.read(name).decode("utf-8", errors="replace")
                    n = name.lower()
                    if (n.endswith("private_key.pem") or n.endswith(".key")) and not data.get("private_key_pem"):
                        data["private_key_pem"] = file_content
                    elif (n.endswith(".csr") or n == "csr.pem") and not data.get("csr_pem"):
                        data["csr_pem"] = file_content
                    elif "chain" in n and n.endswith(".pem") and not data.get("chain_pem"):
                        data["chain_pem"] = file_content
                    elif (n.endswith(".crt") or n == "certificate.pem") and not data.get("certificate_pem"):
                        data["certificate_pem"] = file_content

                return manifest, ""
        except zipfile.BadZipFile:
            return None, "Keine gültige ZIP-Datei."
        except Exception as exc:
            return None, f"ZIP-Parsing fehlgeschlagen: {exc}"

    else:
        return None, "Nicht unterstütztes Format. Erlaubt: .json, .zip"


# ── Import: Validierung ───────────────────────────────────────────────────────

def validate_csr_import(manifest: dict) -> list[str]:
    """Validiert ein CSR-Import-Manifest. Leere Liste = kein Fehler."""
    errors: list[str] = []

    if manifest.get("type") != "csr":
        errors.append(f"Unerwarteter Typ: '{manifest.get('type')}' (erwartet: 'csr').")
        return errors

    if manifest.get("version") not in _SUPPORTED_VERSIONS:
        errors.append(f"Nicht unterstützte Version: {manifest.get('version')}.")

    data = manifest.get("data", {})
    if not data.get("common_name"):
        errors.append("common_name fehlt.")
    csr_pem = data.get("csr_pem", "")
    if not csr_pem.strip().startswith("-----BEGIN CERTIFICATE REQUEST-----"):
        errors.append("csr_pem ist kein gültiges PEM-Format (BEGIN CERTIFICATE REQUEST erwartet).")

    return errors


def validate_cert_import(manifest: dict) -> list[str]:
    """Validiert ein Zertifikat-Import-Manifest. Leere Liste = kein Fehler."""
    errors: list[str] = []

    if manifest.get("type") != "certificate":
        errors.append(f"Unerwarteter Typ: '{manifest.get('type')}' (erwartet: 'certificate').")
        return errors

    if manifest.get("version") not in _SUPPORTED_VERSIONS:
        errors.append(f"Nicht unterstützte Version: {manifest.get('version')}.")

    data = manifest.get("data", {})
    if not data.get("common_name"):
        errors.append("common_name fehlt.")

    cert_pem = data.get("certificate_pem", "").strip()
    if cert_pem and not cert_pem.startswith("-----BEGIN CERTIFICATE-----"):
        errors.append("certificate_pem ist kein gültiges PEM-Format.")

    return errors


# ── Import: Duplikatprüfung ───────────────────────────────────────────────────

def find_duplicate_csr(csr_pem: str, db: Session) -> models.CsrRequest | None:
    normalized = csr_pem.strip()
    return db.query(models.CsrRequest).filter(
        models.CsrRequest.csr_pem == normalized
    ).first()


def find_duplicate_certificate(serial_number: str, db: Session) -> models.Certificate | None:
    if serial_number:
        return db.query(models.Certificate).filter(
            models.Certificate.serial_number == serial_number,
            models.Certificate.serial_number != "",
        ).first()
    return None


# ── Import: Datensätze anlegen ────────────────────────────────────────────────

def import_csr(
    data: dict,
    customer_id: int | None,
    domain_id: int | None,
    created_by_user_id: int,
    db: Session,
) -> models.CsrRequest:
    """Legt einen neuen CsrRequest aus Import-Daten an."""
    plain_key = data.get("private_key_pem", "").strip()
    encrypted_key = ""
    if plain_key:
        try:
            encrypted_key = _encrypt_key(plain_key)
        except Exception:
            # Schlüssel lässt sich nicht mit lokalem Passphrase verschlüsseln
            # (z.B. bereits verschlüsselt) – leer lassen
            pass

    csr = models.CsrRequest(
        customer_id=customer_id,
        domain_id=domain_id,
        created_by=created_by_user_id,
        common_name=data["common_name"],
        sans=data.get("sans", "") or "",
        country=data.get("country", "") or "",
        state=data.get("state", "") or "",
        locality=data.get("locality", "") or "",
        organization=data.get("organization", "") or "",
        organizational_unit=data.get("organizational_unit", "") or "",
        email=data.get("email", "") or "",
        key_size=int(data.get("key_size") or 2048),
        csr_pem=data["csr_pem"].strip(),
        private_key_encrypted=encrypted_key,
    )
    db.add(csr)
    db.flush()
    return csr


def import_certificate(
    data: dict,
    customer_id: int,
    domain_id: int | None,
    csr_request_id: int | None,
    db: Session,
) -> models.Certificate:
    """Legt ein neues Certificate aus Import-Daten an."""
    from ..crypto import parse_certificate_pem

    cert_pem = data.get("certificate_pem", "").strip() or None
    chain_pem = data.get("chain_pem", "").strip() or None

    # Metadaten aus PEM ableiten wenn vorhanden
    parsed: dict = {}
    if cert_pem:
        try:
            parsed = parse_certificate_pem(cert_pem)
        except Exception:
            pass

    def _parse_date(s: str | None) -> datetime | None:
        if not s:
            return None
        for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(s, fmt)
            except (ValueError, TypeError):
                continue
        return None

    valid_from = _parse_date(parsed.get("valid_from") or data.get("valid_from"))
    valid_until = _parse_date(parsed.get("valid_until") or data.get("valid_until"))

    cert = models.Certificate(
        customer_id=customer_id,
        domain_id=domain_id,
        csr_request_id=csr_request_id,
        common_name=parsed.get("common_name") or data.get("common_name", ""),
        san=parsed.get("san") or data.get("san", "") or "",
        issuer=parsed.get("issuer") or data.get("issuer", "") or "",
        serial_number=parsed.get("serial_number") or data.get("serial_number", "") or "",
        valid_from=valid_from,
        valid_until=valid_until,
        status=data.get("status", "active"),
        notes=data.get("notes", "") or "",
        cert_pem=cert_pem,
        chain_pem=chain_pem,
    )
    db.add(cert)
    db.flush()
    return cert


# ── Hilfsfunktion für 2-Schritt-Import (Base64-Encoding) ─────────────────────

def encode_manifest(manifest: dict) -> str:
    """Kodiert ein Manifest als URL-sicheren Base64-String für Hidden-Fields."""
    return base64.urlsafe_b64encode(
        json.dumps(manifest, ensure_ascii=False).encode("utf-8")
    ).decode("ascii")


def decode_manifest(b64: str) -> dict:
    """Dekodiert ein Base64-kodiertes Manifest."""
    return json.loads(base64.urlsafe_b64decode(b64.encode("ascii")).decode("utf-8"))
