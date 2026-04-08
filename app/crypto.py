"""
Kryptografische Hilfsfunktionen für CSR- und Key-Verwaltung.
Nutzt ausschließlich die `cryptography`-Bibliothek.
"""
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _passphrase() -> bytes:
    phrase = os.getenv("CSR_KEY_PASSPHRASE", "").strip()
    if not phrase:
        raise RuntimeError(
            "CSR_KEY_PASSPHRASE ist nicht in der .env gesetzt. "
            "Bitte einen sicheren Wert eintragen."
        )
    return phrase.encode("utf-8")


def generate_csr_and_key(
    cn: str,
    sans_raw: str,
    country: str,
    state: str,
    locality: str,
    organization: str,
    ou: str,
    email: str,
    key_size: int,
) -> tuple[str, str]:
    """
    Erzeugt RSA Private Key + CSR.
    Gibt (csr_pem, encrypted_key_pem) als Strings zurück.
    Der Private Key ist mit CSR_KEY_PASSPHRASE verschlüsselt (AES-256-CBC).
    """
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    # Subject-Name aufbauen
    attrs = []
    if country:
        attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country.upper()[:2]))
    if state:
        attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
    if locality:
        attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
    if organization:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    if ou:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    if email:
        attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))

    # SANs parsen – CN wird immer zuerst eingefügt (RFC 5280 / CA/Browser-Forum)
    san_entries: list[x509.GeneralName] = []
    seen: set[str] = set()

    def _add_san(val: str) -> None:
        val = val.strip()
        if not val or val in seen:
            return
        seen.add(val)
        try:
            ip = ipaddress.ip_address(val)
            san_entries.append(x509.IPAddress(ip))
        except ValueError:
            san_entries.append(x509.DNSName(val))

    _add_san(cn)
    for s in sans_raw.split(","):
        _add_san(s)

    # CSR bauen und signieren
    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name(attrs))
    )
    if san_entries:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
    csr = builder.sign(key, hashes.SHA256())

    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    # Private Key verschlüsselt als PEM (traditionelles OpenSSL-Format, AES-256-CBC)
    key_pem_encrypted = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(_passphrase()),
    ).decode("utf-8")

    return csr_pem, key_pem_encrypted


def split_pem_chain(pem_text: str) -> tuple[str, str]:
    """
    Trennt ein PEM-Bundle in Leaf-Zertifikat und Chain.
    Gibt (leaf_pem, chain_pem) zurück.
    chain_pem ist leer wenn nur ein Zertifikat vorhanden.
    """
    import re
    certs = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        pem_text,
        re.DOTALL,
    )
    if not certs:
        raise ValueError("Kein gültiges PEM-Zertifikat gefunden.")
    leaf = certs[0].strip() + "\n"
    chain = "\n".join(c.strip() for c in certs[1:])
    if chain:
        chain += "\n"
    return leaf, chain


def parse_certificate_pem(pem_text: str) -> dict:
    """
    Parst ein einzelnes PEM-Zertifikat (Leaf) und gibt ein dict zurück mit:
    common_name, issuer, serial_number, valid_from, valid_until, san
    Datumsfelder als ISO-String (YYYY-MM-DD).
    """
    cert = x509.load_pem_x509_certificate(pem_text.encode("utf-8"))

    def _attr(name_obj, oid: NameOID, default: str = "") -> str:
        attrs = name_obj.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else default

    cn = _attr(cert.subject, NameOID.COMMON_NAME)

    # Issuer als lesbare DN-Kurzform
    issuer_parts = []
    for oid, label in (
        (NameOID.COMMON_NAME, "CN"),
        (NameOID.ORGANIZATION_NAME, "O"),
        (NameOID.COUNTRY_NAME, "C"),
    ):
        val = _attr(cert.issuer, oid)
        if val:
            issuer_parts.append(f"{label}={val}")
    issuer_str = ", ".join(issuer_parts) or "–"

    # Seriennummer als Hex mit Doppelpunkten (OpenSSL-Format)
    serial_hex = format(cert.serial_number, "x")
    if len(serial_hex) % 2:
        serial_hex = "0" + serial_hex
    serial_str = ":".join(
        serial_hex[i : i + 2].upper() for i in range(0, len(serial_hex), 2)
    )

    # SANs
    san_list: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                san_list.append(name.value)
            elif isinstance(name, x509.IPAddress):
                san_list.append(str(name.value))
            elif isinstance(name, x509.RFC822Name):
                san_list.append(name.value)
    except x509.ExtensionNotFound:
        pass

    # Gültigkeitsdaten (cryptography ≥ 42 liefert timezone-aware datetimes)
    try:
        valid_from = cert.not_valid_before_utc
        valid_until = cert.not_valid_after_utc
    except AttributeError:          # < 42
        valid_from = cert.not_valid_before
        valid_until = cert.not_valid_after

    return {
        "common_name": cn,
        "issuer": issuer_str,
        "serial_number": serial_str,
        "valid_from": valid_from.strftime("%Y-%m-%d"),
        "valid_until": valid_until.strftime("%Y-%m-%d"),
        "san": ", ".join(san_list),
    }


def decrypt_private_key(encrypted_pem: str) -> bytes:
    """
    Entschlüsselt den gespeicherten Private Key und gibt unverschlüsseltes
    PKCS#1-PEM zurück (verwendbar mit openssl, nginx, apache, …).
    """
    key = serialization.load_pem_private_key(
        encrypted_pem.encode("utf-8"),
        password=_passphrase(),
    )
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def generate_pfx(
    cert_pem: str,
    encrypted_key_pem: str,
    chain_pem: str,
    export_password: str,
    friendly_name: str = "",
) -> bytes:
    """Erzeugt eine PFX/PKCS#12-Datei aus Zertifikat + Private Key + Chain.

    Der gespeicherte (verschlüsselte) Private Key wird intern entschlüsselt
    und mit dem Export-Passwort des Benutzers neu gesichert.

    Gibt rohe PFX-Bytes zurück. Die Verschlüsselung verwendet PBESv1 mit
    SHA-1 und 3DES (pbeWithSHA1And3-KeyTripleDES-CBC), das von Windows Server
    (MMC-Zertifikatsimport / PFXImportCertStore) zuverlässig unterstützt wird.
    """
    import re
    from cryptography.hazmat.primitives.serialization import PrivateFormat
    from cryptography.hazmat.primitives.serialization.pkcs12 import (
        PBES,
        serialize_key_and_certificates,
    )

    # Private Key mit App-Passphrase entschlüsseln
    key = serialization.load_pem_private_key(
        encrypted_key_pem.encode("utf-8"),
        password=_passphrase(),
    )

    # Leaf-Zertifikat laden
    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))

    # Chain laden (optional)
    cas: list[x509.Certificate] = []
    if chain_pem and chain_pem.strip():
        for c_pem in re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            chain_pem,
            re.DOTALL,
        ):
            cas.append(x509.load_pem_x509_certificate(c_pem.encode("utf-8")))

    # Friendly Name: ASCII kodieren für maximale Windows-Kompatibilität
    name_bytes = friendly_name.encode("ascii", errors="replace") if friendly_name else None

    # Windows-kompatible Verschlüsselung:
    # PBESv1 SHA1+3DES für Key/Cert-Bags, SHA-1-MAC
    # (PBES2/AES-256 wird vom Windows-Zertifikatimport nicht unterstützt)
    password_bytes = export_password.encode("utf-8")
    enc = (
        PrivateFormat.PKCS12
        .encryption_builder()
        .key_cert_algorithm(PBES.PBESv1SHA1And3KeyTripleDESCBC)
        .hmac_hash(hashes.SHA1())
        .build(password_bytes)
    )

    return serialize_key_and_certificates(
        name=name_bytes,
        key=key,
        cert=cert,
        cas=cas or None,
        encryption_algorithm=enc,
    )
