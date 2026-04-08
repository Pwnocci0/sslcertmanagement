"""Tests für den PFX/PKCS#12-Export.

Geprüft wird:
- generate_pfx() erzeugt eine valide PKCS#12-Datei (Zertifikat + Key + Chain)
- Das gesetzte Passwort schützt die Datei korrekt
- Die Datei ist Windows-kompatibel (PBESv1 SHA1+3DES, nicht PBES2/AES)
- Der HTTP-Workflow fragt Export-Passwort nur einmal ab (kein Redirect-Loop)
- Validierungsfehler werden inline gemeldet (kein Redirect zur Flash-Seite)
- Fehlerfälle: leeres Passwort, falsche Bestätigung, falsches Benutzerpasswort,
  ungültiger TOTP, fehlender Key, fehlendes Zertifikat
"""
from __future__ import annotations

import datetime
import os
import json
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("APP_SECRET_KEY", "test-secret-key-for-unit-tests")
os.environ.setdefault("CSR_KEY_PASSPHRASE", "test-passphrase-for-unit-tests")

# ── Hilfsfunktionen ──────────────────────────────────────────────────────────

def _make_rsa_key_and_cert(cn: str = "test.example.com"):
    """Erzeugt ein selbst-signiertes RSA-2048-Schlüsselpaar + Zertifikat."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography import x509

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

    # Key verschlüsselt speichern (wie die App es tut)
    from cryptography.hazmat.primitives import serialization as ser
    enc_key_pem = key.private_bytes(
        encoding=ser.Encoding.PEM,
        format=ser.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=ser.BestAvailableEncryption(
            os.environ["CSR_KEY_PASSPHRASE"].encode()
        ),
    ).decode()

    return cert_pem, enc_key_pem, key, cert


# ── generate_pfx(): Kerntests ─────────────────────────────────────────────────

class TestGeneratePfx:

    def test_roundtrip_correct_password(self):
        """PFX kann mit korrektem Passwort geladen werden."""
        from app.crypto import generate_pfx
        from cryptography.hazmat.primitives.serialization.pkcs12 import load_pkcs12

        cert_pem, enc_key_pem, _, _ = _make_rsa_key_and_cert("roundtrip.test")
        pfx = generate_pfx(cert_pem, enc_key_pem, "", "GoodPass123!", "roundtrip.test")

        loaded = load_pkcs12(pfx, b"GoodPass123!")
        assert loaded.cert is not None
        assert loaded.key is not None
        cn = loaded.cert.certificate.subject.get_attributes_for_oid(
            __import__("cryptography").x509.oid.NameOID.COMMON_NAME
        )[0].value
        assert cn == "roundtrip.test"

    def test_wrong_password_raises(self):
        """Eine falsch entschlüsselte PFX-Datei erzeugt einen Fehler."""
        from app.crypto import generate_pfx
        from cryptography.hazmat.primitives.serialization.pkcs12 import load_pkcs12

        cert_pem, enc_key_pem, _, _ = _make_rsa_key_and_cert()
        pfx = generate_pfx(cert_pem, enc_key_pem, "", "CorrectPass!", "test")

        with pytest.raises(Exception):
            load_pkcs12(pfx, b"WrongPass!")

    def test_windows_compatible_encryption(self):
        """PFX muss PBESv1-SHA1-3DES-Verschlüsselung verwenden (Windows-kompatibel)."""
        from app.crypto import generate_pfx
        import subprocess, tempfile

        cert_pem, enc_key_pem, _, _ = _make_rsa_key_and_cert()
        pfx = generate_pfx(cert_pem, enc_key_pem, "", "WinTest123!", "test")

        # openssl pkcs12 -info zeigt den Algorithmus im stderr
        with tempfile.NamedTemporaryFile(suffix=".pfx", delete=False) as f:
            f.write(pfx)
            fn = f.name
        try:
            r = subprocess.run(
                ["openssl", "pkcs12", "-info", "-in", fn,
                 "-passin", "pass:WinTest123!", "-noout", "--legacy"],
                capture_output=True, text=True,
            )
            # Muss SHA1+3DES (PBESv1) verwenden, nicht AES/PBES2
            assert "pbeWithSHA1And3-KeyTripleDES-CBC" in r.stderr, (
                f"Unexpected encryption algorithm. openssl output:\n{r.stderr}"
            )
            assert "sha1" in r.stderr.lower()
            assert "PBES2" not in r.stderr
        finally:
            os.unlink(fn)

    def test_mac_is_sha1(self):
        """MAC-Algorithmus muss SHA-1 sein (Windows-Anforderung)."""
        from app.crypto import generate_pfx
        import subprocess, tempfile

        cert_pem, enc_key_pem, _, _ = _make_rsa_key_and_cert()
        pfx = generate_pfx(cert_pem, enc_key_pem, "", "MacTest!", "test")

        with tempfile.NamedTemporaryFile(suffix=".pfx", delete=False) as f:
            f.write(pfx)
            fn = f.name
        try:
            r = subprocess.run(
                ["openssl", "pkcs12", "-info", "-in", fn,
                 "-passin", "pass:MacTest!", "-noout", "--legacy"],
                capture_output=True, text=True,
            )
            assert "MAC: sha1" in r.stderr, f"Expected SHA-1 MAC:\n{r.stderr}"
        finally:
            os.unlink(fn)

    def test_chain_included_in_pfx(self):
        """Chain-Zertifikate landen als additional_certs im PFX."""
        from app.crypto import generate_pfx
        from cryptography.hazmat.primitives.serialization.pkcs12 import load_pkcs12

        leaf_pem, enc_key_pem, _, _ = _make_rsa_key_and_cert("leaf.test")
        chain_pem, _, _, _ = _make_rsa_key_and_cert("ca.test")

        pfx = generate_pfx(leaf_pem, enc_key_pem, chain_pem, "ChainTest!", "leaf.test")
        loaded = load_pkcs12(pfx, b"ChainTest!")
        assert len(loaded.additional_certs) == 1

    def test_no_chain_no_additional_certs(self):
        """Ohne Chain enthält das PFX keine additional_certs."""
        from app.crypto import generate_pfx
        from cryptography.hazmat.primitives.serialization.pkcs12 import load_pkcs12

        cert_pem, enc_key_pem, _, _ = _make_rsa_key_and_cert()
        pfx = generate_pfx(cert_pem, enc_key_pem, "", "NoChain!", "test")
        loaded = load_pkcs12(pfx, b"NoChain!")
        assert loaded.additional_certs == []

    def test_friendly_name_set(self):
        """Friendly Name wird korrekt in der PFX-Datei gesetzt."""
        from app.crypto import generate_pfx
        from cryptography.hazmat.primitives.serialization.pkcs12 import load_pkcs12

        cert_pem, enc_key_pem, _, _ = _make_rsa_key_and_cert("friendly.test")
        pfx = generate_pfx(cert_pem, enc_key_pem, "", "FriendlyPass!", "friendly.test")
        loaded = load_pkcs12(pfx, b"FriendlyPass!")
        assert loaded.cert.friendly_name == b"friendly.test"

    def test_special_chars_in_cn_dont_crash(self):
        """Sonderzeichen im CN (Umlaute etc.) dürfen generate_pfx nicht zum Absturz bringen."""
        from app.crypto import generate_pfx

        cert_pem, enc_key_pem, _, _ = _make_rsa_key_and_cert("test.example.com")
        # friendly_name mit Umlauten – wird ASCII-escaped
        pfx = generate_pfx(cert_pem, enc_key_pem, "", "Sonderzeichen!", "Müller GmbH")
        assert len(pfx) > 0


# ── HTTP-Route: POST /exports/certificate/{id}/pfx ───────────────────────────

def _make_user(username="testuser", password_plain="UserPass123!"):
    """Erstellt ein User-Mock-Objekt mit bcrypt-gehastem Passwort."""
    import bcrypt
    from app import models

    user = MagicMock(spec=models.User)
    user.id = 1
    user.username = username
    user.is_active = True
    user.is_admin = False
    user.hashed_password = bcrypt.hashpw(
        password_plain.encode(), bcrypt.gensalt()
    ).decode()
    # Gültiges TOTP-Secret (verschlüsselt)
    from app import mfa as mfa_module
    import pyotp
    plain_secret = pyotp.random_base32()
    user.mfa_secret_encrypted = mfa_module.encrypt_totp_secret(plain_secret)
    user.mfa_setup_completed = True
    user._totp_plain = plain_secret  # für Tests zugänglich
    return user


def _make_cert(with_csr=True, has_chain=False):
    """Erstellt ein Certificate-Mock-Objekt mit optionalem CSR/Key."""
    cert_pem, enc_key_pem, _, _ = _make_rsa_key_and_cert("mock.example.com")

    cert = MagicMock()
    cert.id = 42
    cert.common_name = "mock.example.com"
    cert.cert_pem = cert_pem
    cert.chain_pem = cert_pem if has_chain else None  # chain = zweites Cert (vereinfacht)

    if with_csr:
        csr = MagicMock()
        csr.private_key_encrypted = enc_key_pem
        cert.csr_request = csr
        cert.csr_request_id = 1
    else:
        cert.csr_request = None
        cert.csr_request_id = None

    return cert


def _post_pfx(
    client,
    cert_id: int,
    export_password: str = "ExportPass123!",
    export_password2: str = "ExportPass123!",
    user_password: str = "UserPass123!",
    totp_code: str = "",
):
    return client.post(
        f"/exports/certificate/{cert_id}/pfx",
        data={
            "export_password": export_password,
            "export_password2": export_password2,
            "user_password": user_password,
            "totp_code": totp_code,
        },
        follow_redirects=False,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Integrationstests über TestClient
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def app_client():
    """FastAPI TestClient mit gemockter DB und Session."""
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app, raise_server_exceptions=False)
    return client


class TestPfxWorkflow:
    """Tests des HTTP-Endpunkts mit gemockten Abhängigkeiten."""

    def _run(
        self,
        export_password="ExportPass123!",
        export_password2="ExportPass123!",
        user_password="UserPass123!",
        totp_override: str | None = None,
        with_csr=True,
        has_chain=False,
    ):
        """Führt den PFX-POST-Request durch und gibt Response zurück."""
        import pyotp
        from fastapi.testclient import TestClient
        from app.main import app
        from app import models
        from app.routers import exports as exports_router

        user = _make_user(password_plain=user_password)
        cert = _make_cert(with_csr=with_csr, has_chain=has_chain)
        totp = totp_override if totp_override is not None else pyotp.TOTP(user._totp_plain).now()

        db_mock = MagicMock()
        db_mock.query.return_value.filter.return_value.first.return_value = cert

        with (
            patch("app.routers.exports.login_required", return_value=user),
            patch("app.routers.exports.get_db", return_value=db_mock),
            patch("app.database.get_db", return_value=db_mock),
            patch("app.audit.log"),
        ):
            client = TestClient(app, raise_server_exceptions=True)
            # Session-Cookie setzen damit login_required nicht blockiert
            with client.session_transaction() as sess:
                sess["user_id"] = user.id

            resp = client.post(
                f"/exports/certificate/{cert.id}/pfx",
                data={
                    "export_password": export_password,
                    "export_password2": export_password2,
                    "user_password": user_password,
                    "totp_code": totp,
                },
                follow_redirects=False,
            )
        return resp

    def test_kein_redirect_loop_kein_stepup_redirect(self):
        """POST darf NICHT auf /stepup/verify weiterleiten (Problem 1)."""
        resp = self._run()
        # Entweder direkter Download (200) oder Inline-Fehler (422) – nie 302 zu /stepup
        if resp.status_code == 302:
            assert "/stepup" not in resp.headers.get("location", ""), (
                "PFX-Export leitet fälschlicherweise zu /stepup/verify weiter!"
            )

    def test_erfolgreicher_export_gibt_pfx_zurueck(self):
        """Bei korrekten Eingaben wird eine PFX-Datei zurückgegeben."""
        resp = self._run()
        assert resp.status_code == 200, f"Erwartet 200, bekommen {resp.status_code}. Body: {resp.text[:300]}"
        assert resp.headers["content-type"] == "application/x-pkcs12"
        assert ".pfx" in resp.headers.get("content-disposition", "")
        assert len(resp.content) > 100

    def test_pfx_inhalt_mit_korrektem_passwort_ladbar(self):
        """Die zurückgegebene PFX-Datei kann mit dem gesetzten Passwort entschlüsselt werden."""
        from cryptography.hazmat.primitives.serialization.pkcs12 import load_pkcs12

        resp = self._run(export_password="MyExport99!", export_password2="MyExport99!")
        assert resp.status_code == 200
        loaded = load_pkcs12(resp.content, b"MyExport99!")
        assert loaded.cert is not None
        assert loaded.key is not None

    def test_leeres_export_passwort_liefert_422(self):
        """Leeres Export-Passwort → 422, Fehlermeldung im Body."""
        resp = self._run(export_password="", export_password2="")
        assert resp.status_code == 422
        assert "Export-Passwort darf nicht leer sein" in resp.text

    def test_passwort_bestätigung_stimmt_nicht_ueberein(self):
        """Nicht übereinstimmende Passwörter → 422."""
        resp = self._run(export_password="Pass1!", export_password2="Pass2!")
        assert resp.status_code == 422
        assert "stimmen nicht überein" in resp.text

    def test_falsches_benutzerpasswort_liefert_422(self):
        """Falsches Benutzerpasswort → 422, Fehlermeldung."""
        resp = self._run(user_password="WrongUserPassword!")
        assert resp.status_code == 422
        assert "Benutzerpasswort falsch" in resp.text

    def test_ungültiger_totp_liefert_422(self):
        """Ungültiger TOTP-Code → 422, Fehlermeldung."""
        resp = self._run(totp_override="000000")
        assert resp.status_code == 422
        assert "TOTP-Code ungültig" in resp.text

    def test_fehlender_private_key_kein_download(self):
        """Fehlendes CSR/Key-Objekt → kein PFX-Download."""
        resp = self._run(with_csr=False)
        # Soll entweder Redirect zur Zertifikatsseite oder Fehlerseite sein
        assert resp.status_code in (302, 422, 500)
        if resp.status_code == 200:
            # Falls doch 200: darf kein PFX content-type sein
            assert "pkcs12" not in resp.headers.get("content-type", "")

    def test_formular_fragt_passwort_nicht_zweimal_ab(self):
        """GET-Formular enthält alle Felder in einem Schritt (kein separates Step-up-Formular)."""
        from fastapi.testclient import TestClient
        from app.main import app

        user = _make_user()
        cert = _make_cert()
        db_mock = MagicMock()
        db_mock.query.return_value.filter.return_value.first.return_value = cert

        with (
            patch("app.routers.exports.login_required", return_value=user),
            patch("app.routers.exports.get_db", return_value=db_mock),
            patch("app.database.get_db", return_value=db_mock),
        ):
            client = TestClient(app)
            resp = client.get(f"/exports/certificate/{cert.id}/pfx", follow_redirects=False)

        assert resp.status_code == 200
        body = resp.text
        # Alle vier Felder müssen im Formular vorhanden sein
        assert 'name="export_password"' in body, "Kein Export-Passwort-Feld im Formular"
        assert 'name="export_password2"' in body, "Kein Bestätigungs-Feld im Formular"
        assert 'name="user_password"' in body, "Kein Benutzerpasswort-Feld im Formular"
        assert 'name="totp_code"' in body, "Kein TOTP-Feld im Formular"
        # Es darf kein Redirect zu /stepup geben
        assert "/stepup/verify" not in body
