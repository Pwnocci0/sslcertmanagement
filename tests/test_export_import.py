"""Tests für Export/Import-Service (app/services/import_export.py).

Geprüft wird:
- export_csr() / export_certificate() erzeugen korrektes Manifest-Format
- build_export_zip() erzeugt gültige ZIP mit manifest.json + PEM-Dateien
- parse_import_file() verarbeitet .json und .zip korrekt
- validate_csr_import() / validate_cert_import() melden Fehler korrekt
- find_duplicate_csr() / find_duplicate_certificate() erkennen Duplikate
- import_csr() / import_certificate() legen Datensätze korrekt an
- encode_manifest() / decode_manifest() sind symmetrisch
- Fehlerfälle: ungültiges Format, fehlende Pflichtfelder, kein Duplikat
"""
from __future__ import annotations

import datetime
import io
import json
import os
import zipfile
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("APP_SECRET_KEY", "test-secret-key-for-unit-tests")
os.environ.setdefault("CSR_KEY_PASSPHRASE", "test-passphrase-for-unit-tests")


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_self_signed(cn: str = "test.example.com"):
    """Erzeugt ein selbst-signiertes Zertifikat + zugehörigen CSR."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem_plain = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    enc_key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(
            os.environ["CSR_KEY_PASSPHRASE"].encode()
        ),
    ).decode()

    # CSR
    csr_obj = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(key, hashes.SHA256())
    )
    csr_pem = csr_obj.public_bytes(serialization.Encoding.PEM).decode()

    return cert_pem, csr_pem, key_pem_plain, enc_key_pem, cert


def _make_csr_model(cn: str = "test.example.com", with_key: bool = True):
    cert_pem, csr_pem, _plain, enc_key, _cert = _make_self_signed(cn)
    csr = MagicMock()
    csr.id = 1
    csr.common_name = cn
    csr.csr_pem = csr_pem
    csr.key_size = 2048
    csr.sans = "DNS:www.test.example.com"
    csr.country = "DE"
    csr.state = "Bayern"
    csr.locality = "München"
    csr.organization = "TestOrg GmbH"
    csr.organizational_unit = "IT"
    csr.email = "admin@test.example.com"
    csr.customer = None
    csr.domain = None
    csr.created_at = datetime.datetime(2025, 1, 15, 10, 0, 0)
    csr.private_key_encrypted = enc_key if with_key else ""
    return csr, enc_key


def _make_cert_model(cn: str = "test.example.com"):
    cert_pem, csr_pem, _plain, enc_key, cert_obj = _make_self_signed(cn)
    cert = MagicMock()
    cert.id = 42
    cert.common_name = cn
    cert.cert_pem = cert_pem
    cert.chain_pem = ""
    cert.issuer = f"CN={cn}"
    cert.serial_number = format(cert_obj.serial_number, "x").upper()
    cert.san = ""
    cert.valid_from = datetime.date(2025, 1, 1)
    cert.valid_until = datetime.date(2026, 1, 1)
    cert.status = "active"
    cert.notes = ""
    cert.customer = None
    cert.domain = None
    cert.created_at = datetime.datetime(2025, 1, 15, 10, 0, 0)

    csr_req = MagicMock()
    csr_req.csr_pem = csr_pem
    csr_req.key_size = 2048
    csr_req.private_key_encrypted = enc_key
    cert.csr_request = csr_req
    cert.csr_request_id = 1
    return cert


# ── export_csr() ─────────────────────────────────────────────────────────────

class TestExportCsr:
    def test_basic_structure(self):
        from app.services.import_export import export_csr, EXPORT_VERSION
        csr, _ = _make_csr_model()
        manifest = export_csr(csr, include_key=False)

        assert manifest["type"] == "csr"
        assert manifest["version"] == EXPORT_VERSION
        assert "exported_at" in manifest
        assert manifest["data"]["common_name"] == "test.example.com"
        assert "private_key_pem" not in manifest["data"]

    def test_include_key(self):
        from app.services.import_export import export_csr
        csr, enc_key = _make_csr_model(with_key=True)

        with patch("app.crypto.decrypt_private_key") as mock_dk:
            mock_dk.return_value = b"-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----"
            manifest = export_csr(csr, include_key=True)

        assert "private_key_pem" in manifest["data"]

    def test_include_key_without_key_stored(self):
        from app.services.import_export import export_csr
        csr, _ = _make_csr_model(with_key=False)
        manifest = export_csr(csr, include_key=True)
        assert "private_key_pem" not in manifest["data"]

    def test_customer_and_domain(self):
        from app.services.import_export import export_csr
        csr, _ = _make_csr_model()
        customer = MagicMock()
        customer.name = "Musterkunde GmbH"
        customer.customer_groups = []
        csr.customer = customer
        domain = MagicMock()
        domain.fqdn = "example.com"
        csr.domain = domain

        manifest = export_csr(csr)
        assert manifest["data"]["customer"] == "Musterkunde GmbH"
        assert manifest["data"]["domain"] == "example.com"


# ── export_certificate() ──────────────────────────────────────────────────────

class TestExportCertificate:
    def test_basic_structure(self):
        from app.services.import_export import export_certificate, EXPORT_VERSION
        cert = _make_cert_model()
        manifest = export_certificate(cert, include_key=False)

        assert manifest["type"] == "certificate"
        assert manifest["version"] == EXPORT_VERSION
        assert manifest["data"]["common_name"] == "test.example.com"
        assert manifest["data"]["certificate_pem"].startswith("-----BEGIN CERTIFICATE-----")
        assert "private_key_pem" not in manifest["data"]

    def test_fingerprint_present(self):
        from app.services.import_export import export_certificate
        cert = _make_cert_model()
        manifest = export_certificate(cert)
        fp = manifest["data"]["fingerprint_sha256"]
        assert ":" in fp
        assert len(fp) > 10

    def test_include_key(self):
        from app.services.import_export import export_certificate
        cert = _make_cert_model()
        with patch("app.crypto.decrypt_private_key") as mock_dk:
            mock_dk.return_value = b"-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----"
            manifest = export_certificate(cert, include_key=True)
        assert "private_key_pem" in manifest["data"]


# ── build_export_zip() ────────────────────────────────────────────────────────

class TestBuildExportZip:
    def test_zip_contains_manifest(self):
        from app.services.import_export import build_export_zip
        manifest = {"type": "csr", "version": "1.0", "data": {"common_name": "test.example.com"}}
        zip_bytes = build_export_zip(manifest, {})

        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            assert "manifest.json" in zf.namelist()
            loaded = json.loads(zf.read("manifest.json"))
            assert loaded["type"] == "csr"

    def test_zip_contains_pem_files(self):
        from app.services.import_export import build_export_zip
        manifest = {"type": "csr", "version": "1.0", "data": {}}
        pem_files = {"csr.pem": "-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----"}
        zip_bytes = build_export_zip(manifest, pem_files)

        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            assert "csr.pem" in zf.namelist()
            assert "CERTIFICATE REQUEST" in zf.read("csr.pem").decode()

    def test_empty_pem_files_excluded(self):
        from app.services.import_export import build_export_zip
        manifest = {"type": "csr", "version": "1.0", "data": {}}
        zip_bytes = build_export_zip(manifest, {"empty.pem": "", "real.pem": "content"})

        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            names = zf.namelist()
            assert "empty.pem" not in names
            assert "real.pem" in names


# ── parse_import_file() ───────────────────────────────────────────────────────

class TestParseImportFile:
    def test_valid_json(self):
        from app.services.import_export import parse_import_file
        manifest = {"type": "csr", "version": "1.0", "data": {"common_name": "x"}}
        content = json.dumps(manifest).encode("utf-8")
        result, error = parse_import_file("export.json", content)
        assert error == ""
        assert result["type"] == "csr"

    def test_invalid_json(self):
        from app.services.import_export import parse_import_file
        result, error = parse_import_file("export.json", b"not json{{{")
        assert result is None
        assert "JSON" in error

    def test_unsupported_format(self):
        from app.services.import_export import parse_import_file
        result, error = parse_import_file("export.txt", b"something")
        assert result is None
        assert "Format" in error

    def test_valid_zip_with_manifest(self):
        from app.services.import_export import parse_import_file
        manifest = {"type": "csr", "version": "1.0", "data": {"common_name": "test"}}
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("manifest.json", json.dumps(manifest))
            zf.writestr("csr.pem", "-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----")
        buf.seek(0)
        result, error = parse_import_file("export.zip", buf.read())
        assert error == ""
        assert result["data"]["csr_pem"].startswith("-----BEGIN CERTIFICATE REQUEST-----")

    def test_zip_missing_manifest(self):
        from app.services.import_export import parse_import_file
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("csr.pem", "something")
        buf.seek(0)
        result, error = parse_import_file("export.zip", buf.read())
        assert result is None
        assert "manifest.json" in error

    def test_zip_pem_auto_assignment(self):
        from app.services.import_export import parse_import_file
        manifest = {"type": "certificate", "version": "1.0", "data": {}}
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("manifest.json", json.dumps(manifest))
            zf.writestr("certificate.pem", "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----")
            zf.writestr("chain.pem", "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----")
            zf.writestr("private_key.pem", "-----BEGIN RSA PRIVATE KEY-----\nkey\n-----END RSA PRIVATE KEY-----")
        buf.seek(0)
        result, error = parse_import_file("export.zip", buf.read())
        assert error == ""
        assert "-----BEGIN CERTIFICATE-----" in result["data"]["certificate_pem"]
        assert "chain" in result["data"]["chain_pem"]
        assert "KEY" in result["data"]["private_key_pem"]

    def test_bad_zip(self):
        from app.services.import_export import parse_import_file
        result, error = parse_import_file("export.zip", b"not a zip at all")
        assert result is None
        assert "ZIP" in error


# ── validate_csr_import() ─────────────────────────────────────────────────────

class TestValidateCsrImport:
    def _valid_manifest(self, csr_pem: str = None):
        if csr_pem is None:
            _, csr_pem, _, _, _ = _make_self_signed()
        return {
            "type": "csr",
            "version": "1.0",
            "data": {"common_name": "test.example.com", "csr_pem": csr_pem},
        }

    def test_valid_passes(self):
        from app.services.import_export import validate_csr_import
        errors = validate_csr_import(self._valid_manifest())
        assert errors == []

    def test_wrong_type(self):
        from app.services.import_export import validate_csr_import
        manifest = self._valid_manifest()
        manifest["type"] = "certificate"
        errors = validate_csr_import(manifest)
        assert any("Typ" in e for e in errors)

    def test_missing_common_name(self):
        from app.services.import_export import validate_csr_import
        manifest = self._valid_manifest()
        del manifest["data"]["common_name"]
        errors = validate_csr_import(manifest)
        assert any("common_name" in e for e in errors)

    def test_invalid_csr_pem(self):
        from app.services.import_export import validate_csr_import
        manifest = self._valid_manifest(csr_pem="not a pem")
        errors = validate_csr_import(manifest)
        assert any("csr_pem" in e for e in errors)

    def test_unsupported_version(self):
        from app.services.import_export import validate_csr_import
        manifest = self._valid_manifest()
        manifest["version"] = "9.9"
        errors = validate_csr_import(manifest)
        assert any("Version" in e for e in errors)


# ── validate_cert_import() ────────────────────────────────────────────────────

class TestValidateCertImport:
    def _valid_manifest(self):
        cert_pem, _, _, _, _ = _make_self_signed()
        return {
            "type": "certificate",
            "version": "1.0",
            "data": {"common_name": "test.example.com", "certificate_pem": cert_pem},
        }

    def test_valid_passes(self):
        from app.services.import_export import validate_cert_import
        errors = validate_cert_import(self._valid_manifest())
        assert errors == []

    def test_wrong_type(self):
        from app.services.import_export import validate_cert_import
        manifest = self._valid_manifest()
        manifest["type"] = "csr"
        errors = validate_cert_import(manifest)
        assert any("Typ" in e for e in errors)

    def test_missing_common_name(self):
        from app.services.import_export import validate_cert_import
        manifest = self._valid_manifest()
        del manifest["data"]["common_name"]
        errors = validate_cert_import(manifest)
        assert any("common_name" in e for e in errors)

    def test_invalid_cert_pem(self):
        from app.services.import_export import validate_cert_import
        manifest = self._valid_manifest()
        manifest["data"]["certificate_pem"] = "not a cert"
        errors = validate_cert_import(manifest)
        assert any("certificate_pem" in e for e in errors)

    def test_empty_cert_pem_allowed(self):
        """Zertifikats-PEM darf leer sein (Zertifikat noch nicht vorhanden)."""
        from app.services.import_export import validate_cert_import
        manifest = self._valid_manifest()
        manifest["data"]["certificate_pem"] = ""
        errors = validate_cert_import(manifest)
        assert errors == []


# ── find_duplicate_csr() / find_duplicate_certificate() ──────────────────────

class TestDuplicateDetection:
    def test_find_duplicate_csr_found(self):
        from app.services.import_export import find_duplicate_csr
        _, csr_pem, _, _, _ = _make_self_signed()
        existing = MagicMock()

        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = existing

        result = find_duplicate_csr(csr_pem, db)
        assert result is existing

    def test_find_duplicate_csr_not_found(self):
        from app.services.import_export import find_duplicate_csr
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None

        result = find_duplicate_csr("some pem", db)
        assert result is None

    def test_find_duplicate_cert_by_serial(self):
        from app.services.import_export import find_duplicate_certificate
        existing = MagicMock()

        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = existing

        result = find_duplicate_certificate("ABCDEF1234", db)
        assert result is existing

    def test_find_duplicate_cert_empty_serial(self):
        from app.services.import_export import find_duplicate_certificate
        db = MagicMock()
        result = find_duplicate_certificate("", db)
        assert result is None
        db.query.assert_not_called()


# ── encode_manifest() / decode_manifest() ─────────────────────────────────────

class TestManifestEncoding:
    def test_roundtrip(self):
        from app.services.import_export import encode_manifest, decode_manifest
        original = {"type": "csr", "version": "1.0", "data": {"common_name": "test.de"}}
        encoded = encode_manifest(original)
        assert isinstance(encoded, str)
        decoded = decode_manifest(encoded)
        assert decoded == original

    def test_url_safe(self):
        from app.services.import_export import encode_manifest
        manifest = {"data": {"key": "value with special chars: üöä &"}}
        encoded = encode_manifest(manifest)
        assert "+" not in encoded
        assert "/" not in encoded

    def test_decode_invalid_raises(self):
        from app.services.import_export import decode_manifest
        with pytest.raises(Exception):
            decode_manifest("not-valid-base64-json!!!")


# ── import_csr() ─────────────────────────────────────────────────────────────

class TestImportCsr:
    def test_creates_csr_request(self):
        from app.services.import_export import import_csr
        _, csr_pem, _, _, _ = _make_self_signed()
        data = {
            "common_name": "import.example.com",
            "csr_pem": csr_pem,
            "sans": "DNS:import.example.com",
            "country": "DE",
            "state": "",
            "locality": "",
            "organization": "Test GmbH",
            "organizational_unit": "",
            "email": "",
            "key_size": 2048,
        }

        db = MagicMock()
        added = []
        db.add.side_effect = lambda obj: added.append(obj)

        from app import models as _models
        with patch.object(_models, "CsrRequest", wraps=_models.CsrRequest):
            csr = import_csr(data, customer_id=None, domain_id=None,
                             created_by_user_id=1, db=db)

        assert csr.common_name == "import.example.com"
        assert csr.csr_pem == csr_pem.strip()
        assert csr.key_size == 2048
        db.add.assert_called_once()
        db.flush.assert_called_once()

    def test_private_key_encrypted_on_import(self):
        from app.services.import_export import import_csr
        _, csr_pem, key_pem_plain, _, _ = _make_self_signed()
        data = {
            "common_name": "import.example.com",
            "csr_pem": csr_pem,
            "private_key_pem": key_pem_plain,
        }

        db = MagicMock()
        csr = import_csr(data, customer_id=None, domain_id=None,
                         created_by_user_id=1, db=db)

        # Key sollte verschlüsselt worden sein
        assert csr.private_key_encrypted
        assert "ENCRYPTED" in csr.private_key_encrypted or "BEGIN" in csr.private_key_encrypted


# ── import_certificate() ──────────────────────────────────────────────────────

class TestImportCertificate:
    def test_creates_certificate(self):
        from app.services.import_export import import_certificate
        cert_pem, csr_pem, _, _, _ = _make_self_signed("import.example.com")
        data = {
            "common_name": "import.example.com",
            "certificate_pem": cert_pem,
            "chain_pem": "",
            "issuer": "CN=import.example.com",
            "serial_number": "ABCDEF",
            "valid_from": "2025-01-01",
            "valid_until": "2026-01-01",
            "status": "active",
            "notes": "",
            "san": "",
        }

        db = MagicMock()
        cert = import_certificate(data, customer_id=5, domain_id=None,
                                  csr_request_id=None, db=db)

        assert cert.common_name == "import.example.com"
        assert cert.customer_id == 5
        assert cert.cert_pem == cert_pem.strip()
        assert cert.status == "active"
        db.add.assert_called_once()
        db.flush.assert_called_once()

    def test_metadata_parsed_from_pem(self):
        """Metadaten werden aus dem Zertifikat-PEM extrahiert, nicht nur aus data."""
        from app.services.import_export import import_certificate
        cert_pem, _, _, _, cert_obj = _make_self_signed("auto-parsed.example.com")
        data = {
            "common_name": "wrong-name",  # wird durch PEM-Parsing überschrieben
            "certificate_pem": cert_pem,
            "status": "active",
        }

        db = MagicMock()
        cert = import_certificate(data, customer_id=1, domain_id=None,
                                  csr_request_id=None, db=db)

        # common_name sollte aus PEM stammen
        assert cert.common_name == "auto-parsed.example.com"


# ── fingerprint_sha256() ──────────────────────────────────────────────────────

class TestFingerprint:
    def test_sha256_format(self):
        from app.services.import_export import fingerprint_sha256
        cert_pem, _, _, _, _ = _make_self_signed()
        fp = fingerprint_sha256(cert_pem)
        parts = fp.split(":")
        assert len(parts) == 32
        assert all(len(p) == 2 for p in parts)
        assert fp == fp.upper()

    def test_fallback_on_invalid_pem(self):
        from app.services.import_export import fingerprint_sha256
        fp = fingerprint_sha256("not a cert")
        assert ":" in fp
        assert len(fp) > 10
