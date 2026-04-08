"""
MFA-Hilfsfunktionen (TOTP + Recovery Codes).

Verschlüsselung des TOTP-Secrets über Fernet, abgeleitet aus APP_SECRET_KEY.
HMAC-Hashing der Recovery Codes (SHA-256, keyed mit APP_SECRET_KEY).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import os
import secrets

import pyotp
import segno
from cryptography.fernet import Fernet

APP_ISSUER = "SSL Cert Mgmt"
RECOVERY_CODE_COUNT = 8


# ── Fernet-Verschlüsselung ────────────────────────────────────────────────────

def _get_fernet() -> Fernet:
    """Leitet einen Fernet-Schlüssel aus APP_SECRET_KEY ab."""
    key_material = os.getenv(
        "APP_SECRET_KEY", "dev-secret-key-CHANGE-IN-PRODUCTION"
    ).encode()
    raw = hashlib.sha256(key_material).digest()   # 32 Bytes
    return Fernet(base64.urlsafe_b64encode(raw))


def encrypt_totp_secret(plaintext: str) -> str:
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt_totp_secret(ciphertext: str) -> str:
    return _get_fernet().decrypt(ciphertext.encode()).decode()


# ── TOTP ─────────────────────────────────────────────────────────────────────

def generate_totp_secret() -> str:
    """Erzeugt ein zufälliges Base32-TOTP-Secret."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str) -> str:
    """Erzeugt die otpauth://-URI für Authenticator-Apps."""
    return pyotp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name=APP_ISSUER,
    )


def verify_totp(secret: str, code: str) -> bool:
    """Prüft einen TOTP-Code (±1 Zeitfenster für Uhrversatz)."""
    return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)


# ── QR-Code ──────────────────────────────────────────────────────────────────

def generate_qr_svg(uri: str) -> str:
    """Gibt einen Inline-SVG-String für den QR-Code zurück."""
    qr = segno.make_qr(uri)
    buf = io.BytesIO()
    qr.save(buf, kind="svg", scale=6, xmldecl=False, nl=False)
    return buf.getvalue().decode()


# ── Recovery Codes ───────────────────────────────────────────────────────────

def _hmac_code(code: str) -> str:
    """HMAC-SHA256 eines Codes, geseeded mit APP_SECRET_KEY."""
    key = os.getenv(
        "APP_SECRET_KEY", "dev-secret-key-CHANGE-IN-PRODUCTION"
    ).encode()
    return hmac.new(key, code.upper().encode(), hashlib.sha256).hexdigest()


def generate_recovery_codes() -> tuple[list[str], str]:
    """
    Erzeugt RECOVERY_CODE_COUNT Recovery Codes.
    Gibt (Klartextliste, JSON-String mit HMAC-Hashes) zurück.
    Die Klartexte werden NIE in der DB gespeichert.
    """
    plain: list[str] = []
    hashed: list[str] = []
    for _ in range(RECOVERY_CODE_COUNT):
        code = f"{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"
        plain.append(code)
        hashed.append(_hmac_code(code))
    return plain, json.dumps(hashed)


def verify_and_consume_recovery_code(
    entered: str,
    hashed_json: str,
) -> tuple[bool, str | None]:
    """
    Prüft einen eingegebenen Recovery Code gegen die gespeicherten Hashes.
    Bei Erfolg: Entfernt den verbrauchten Code, gibt aktualisierten JSON-String zurück.
    Bei Misserfolg: Gibt (False, None) zurück.
    """
    clean = entered.strip().upper().replace(" ", "")
    hashed_list: list[str] = json.loads(hashed_json)
    entered_hash = _hmac_code(clean)
    for i, stored in enumerate(hashed_list):
        if hmac.compare_digest(entered_hash, stored):
            hashed_list.pop(i)
            return True, json.dumps(hashed_list)
    return False, None
