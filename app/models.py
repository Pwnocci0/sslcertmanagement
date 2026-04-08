from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from .database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)

    # MFA
    mfa_secret_encrypted = Column(Text, nullable=True)      # TOTP-Secret (Fernet-verschlüsselt)
    mfa_setup_completed = Column(Boolean, default=False, nullable=False)
    recovery_codes_json = Column(Text, nullable=True)       # JSON-Array mit HMAC-Hashes
    last_mfa_at = Column(DateTime, nullable=True)

    def __repr__(self):
        return f"<User {self.username}>"


class Customer(Base):
    __tablename__ = "customers"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(150), nullable=False)
    contact_name = Column(String(100))
    contact_email = Column(String(100))
    notes = Column(Text)
    is_archived = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)

    domains = relationship("Domain", back_populates="customer", cascade="all, delete-orphan")
    certificates = relationship("Certificate", back_populates="customer", cascade="all, delete-orphan")
    csr_requests = relationship("CsrRequest", back_populates="customer")
    defaults = relationship("CustomerDefaults", back_populates="customer", uselist=False, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Customer {self.name}>"


class Domain(Base):
    __tablename__ = "domains"

    id = Column(Integer, primary_key=True, index=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)
    fqdn = Column(String(255), nullable=False, index=True)
    notes = Column(Text)
    created_at = Column(DateTime, default=func.now(), nullable=False)

    customer = relationship("Customer", back_populates="domains")
    certificates = relationship("Certificate", back_populates="domain")
    csr_requests = relationship("CsrRequest", back_populates="domain")

    def __repr__(self):
        return f"<Domain {self.fqdn}>"


# Gültige Status-Werte für Certificates
CERT_STATUS_CHOICES = ["pending", "active", "expiring_soon", "expired", "revoked"]


class Certificate(Base):
    __tablename__ = "certificates"

    id = Column(Integer, primary_key=True, index=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=True)

    common_name = Column(String(255), nullable=False)
    san = Column(Text)           # kommagetrennte Subject Alternative Names
    issuer = Column(String(255))
    serial_number = Column(String(255))

    valid_from = Column(DateTime, nullable=True)
    valid_until = Column(DateTime, nullable=True)

    # pending | active | expiring_soon | expired | revoked
    status = Column(String(20), default="pending", nullable=False)
    auto_renew = Column(Boolean, default=False, nullable=False)
    notes = Column(Text)
    is_archived = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)

    # Hochgeladene PEM-Daten
    cert_pem = Column(Text, nullable=True)   # Leaf-Zertifikat PEM
    chain_pem = Column(Text, nullable=True)  # Intermediate/Root Chain PEM

    # Verknüpfung mit dem CSR aus dem Private-Key-Vault
    csr_request_id = Column(Integer, ForeignKey("csr_requests.id"), nullable=True)

    customer = relationship("Customer", back_populates="certificates")
    domain = relationship("Domain", back_populates="certificates")
    csr_request = relationship("CsrRequest", foreign_keys=[csr_request_id])
    thesslstore_order = relationship(
        "TheSSLStoreOrder", back_populates="certificate", uselist=False
    )
    notes_history = relationship(
        "CertificateNote", back_populates="certificate",
        cascade="all, delete-orphan", order_by="CertificateNote.created_at.desc()",
    )
    attachments = relationship(
        "CertificateAttachment", back_populates="certificate",
        cascade="all, delete-orphan", order_by="CertificateAttachment.created_at.desc()",
    )

    @property
    def days_until_expiry(self):
        if not self.valid_until:
            return None
        delta = self.valid_until - datetime.utcnow()
        return delta.days

    @property
    def status_badge_class(self):
        mapping = {
            "active": "success",
            "expiring_soon": "warning",
            "expired": "danger",
            "revoked": "secondary",
            "pending": "info",
        }
        return mapping.get(self.status, "light")

    def __repr__(self):
        return f"<Certificate {self.common_name}>"


KEY_SIZE_CHOICES = [2048, 3072, 4096]


class CsrRequest(Base):
    """Gespeicherter CSR inklusive verschlüsseltem Private Key."""
    __tablename__ = "csr_requests"

    id = Column(Integer, primary_key=True, index=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Zertifikats-Subject-Felder
    common_name = Column(String(255), nullable=False, index=True)
    sans = Column(Text)                  # kommagetrennte SANs (ohne CN)
    country = Column(String(2))
    state = Column(String(128))
    locality = Column(String(128))
    organization = Column(String(200))
    organizational_unit = Column(String(200))
    email = Column(String(100))
    key_size = Column(Integer, default=2048, nullable=False)

    # Generierte Daten
    csr_pem = Column(Text, nullable=False)
    private_key_encrypted = Column(Text, nullable=False)  # AES-256-CBC via cryptography

    is_archived = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)

    customer = relationship("Customer", back_populates="csr_requests")
    domain = relationship("Domain", back_populates="csr_requests")
    creator = relationship("User", foreign_keys=[created_by])

    @property
    def sans_list(self) -> list[str]:
        if not self.sans:
            return []
        return [s.strip() for s in self.sans.split(",") if s.strip()]

    def __repr__(self):
        return f"<CsrRequest {self.common_name}>"


class AppSetting(Base):
    """Zentrale Key-Value-Konfigurationstabelle.

    Metadaten (Typ, Kategorie, Label, Beschreibung) sind in
    SettingsService.DEFINITIONS definiert. Die DB speichert nur Schlüssel
    und Wert (ggf. Fernet-verschlüsselt für sensitive Settings).
    """
    __tablename__ = "app_settings"

    id = Column(Integer, primary_key=True)
    key = Column(String(100), unique=True, nullable=False, index=True)
    value = Column(Text, nullable=True)          # bei is_sensitive=True: Fernet-verschlüsselt
    updated_at = Column(DateTime, default=func.now(), nullable=False)
    updated_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    def __repr__(self):
        return f"<AppSetting {self.key}>"


class TheSSLStoreProduct(Base):
    """Lokaler Cache der bei TheSSLStore verfügbaren Produkte."""
    __tablename__ = "thesslstore_products"

    id = Column(Integer, primary_key=True)
    sku = Column(String(100), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    product_code = Column(String(100))
    validity_period = Column(Integer, default=12)   # Monate
    max_san = Column(Integer, default=0)
    is_wildcard = Column(Boolean, default=False)
    is_dv = Column(Boolean, default=False)
    is_ov = Column(Boolean, default=False)
    is_ev = Column(Boolean, default=False)
    vendor_name = Column(String(100))
    raw_json = Column(Text)                          # vollständige API-Antwort
    synced_at = Column(DateTime, default=func.now(), nullable=False)

    def __repr__(self):
        return f"<TheSSLStoreProduct {self.sku}>"


class TheSSLStoreOrder(Base):
    """Verknüpfung eines lokalen Zertifikats mit einer TheSSLStore-Bestellung."""
    __tablename__ = "thesslstore_orders"

    id = Column(Integer, primary_key=True)
    certificate_id = Column(
        Integer, ForeignKey("certificates.id"), nullable=True, unique=True
    )
    thessl_order_id = Column(String(100), nullable=True, index=True)
    vendor_order_id = Column(String(100), nullable=True)
    sku = Column(String(100), nullable=False)
    status = Column(String(50), default="pending", nullable=False)
    san_count = Column(Integer, default=0)
    server_count = Column(Integer, default=1)
    validity_period = Column(Integer, default=12)   # Monate
    approver_email = Column(String(200), nullable=True)
    domain_control_method = Column(String(20), default="EMAIL")
    raw_status_json = Column(Text, nullable=True)    # letzter API-Status als JSON
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), nullable=False)

    certificate = relationship("Certificate", back_populates="thesslstore_order")

    @property
    def status_badge_class(self):
        return {
            "active": "success",
            "pending": "warning",
            "cancelled": "secondary",
            "rejected": "danger",
        }.get(self.status.lower(), "info")

    def __repr__(self):
        return f"<TheSSLStoreOrder {self.thessl_order_id or 'new'}>"


class CsrTemplate(Base):
    """Wiederverwendbare Vorlage für die CSR-Erstellung."""
    __tablename__ = "csr_templates"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    country = Column(String(2))
    state = Column(String(128))
    locality = Column(String(128))
    organization = Column(String(200))
    organizational_unit = Column(String(200))
    key_size = Column(Integer, default=2048, nullable=False)
    san_pattern = Column(Text)          # Muster z. B. "*.{cn},{cn}"
    is_default = Column(Boolean, default=False, nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)

    creator = relationship("User", foreign_keys=[created_by])

    def __repr__(self):
        return f"<CsrTemplate {self.name}>"


class CustomerDefaults(Base):
    """Kundenspezifische Standardwerte für CSR/Zertifikatsvorgänge."""
    __tablename__ = "customer_defaults"

    id = Column(Integer, primary_key=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), unique=True, nullable=False)
    default_country = Column(String(2))
    default_state = Column(String(128))
    default_locality = Column(String(128))
    default_org = Column(String(200))
    default_ou = Column(String(200))
    preferred_validity_days = Column(Integer)
    preferred_product_sku = Column(String(100))
    validation_notes = Column(Text)
    technical_notes = Column(Text)
    updated_at = Column(DateTime, default=func.now(), nullable=False)

    customer = relationship("Customer", back_populates="defaults")

    def __repr__(self):
        return f"<CustomerDefaults customer_id={self.customer_id}>"


class CertificateNote(Base):
    """Interner Verlaufseintrag / Kommentar zu einem Zertifikatsvorgang."""
    __tablename__ = "certificate_notes"

    id = Column(Integer, primary_key=True)
    certificate_id = Column(Integer, ForeignKey("certificates.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    note = Column(Text, nullable=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)

    certificate = relationship("Certificate", back_populates="notes_history")
    author = relationship("User")

    def __repr__(self):
        return f"<CertificateNote cert={self.certificate_id}>"


class CertificateAttachment(Base):
    """Datei-Anhang zu einem Zertifikat (z. B. Original-ZIP vom CA)."""
    __tablename__ = "certificate_attachments"

    id = Column(Integer, primary_key=True)
    certificate_id = Column(Integer, ForeignKey("certificates.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    filename = Column(String(255), nullable=False)
    content_type = Column(String(100), nullable=False, default="application/octet-stream")
    file_size = Column(Integer, nullable=False)
    data = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)

    certificate = relationship("Certificate", back_populates="attachments")
    uploader = relationship("User")

    def __repr__(self):
        return f"<CertificateAttachment {self.filename}>"


class AuditLog(Base):
    """Protokolliert sicherheitsrelevante Aktionen."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False, index=True)
    entity_type = Column(String(50), nullable=False)
    entity_id = Column(Integer, nullable=True, index=True)
    details = Column(Text)       # JSON-kodierte Zusatzdaten
    ip_address = Column(String(45))
    created_at = Column(DateTime, default=func.now(), nullable=False)

    user = relationship("User")

    def __repr__(self):
        return f"<AuditLog {self.action} by user_id={self.user_id}>"
