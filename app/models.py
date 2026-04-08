from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Table,
    Text,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from .database import Base


# ── Assoziationstabellen (Many-to-Many) ──────────────────────────────────────

user_customer_groups = Table(
    "user_customer_groups",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id"), primary_key=True),
    Column("group_id", Integer, ForeignKey("customer_groups.id"), primary_key=True),
)

customer_customer_groups = Table(
    "customer_customer_groups",
    Base.metadata,
    Column("customer_id", Integer, ForeignKey("customers.id"), primary_key=True),
    Column("group_id", Integer, ForeignKey("customer_groups.id"), primary_key=True),
)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    # Rolle: "admin" oder "technician"
    role = Column(String(20), default="admin", nullable=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)

    # MFA
    mfa_secret_encrypted = Column(Text, nullable=True)
    mfa_setup_completed = Column(Boolean, default=False, nullable=False)
    recovery_codes_json = Column(Text, nullable=True)
    last_mfa_at = Column(DateTime, nullable=True)

    # Kundengruppen-Zuordnung (nur relevant für Techniker)
    customer_groups = relationship(
        "CustomerGroup",
        secondary=user_customer_groups,
        back_populates="users",
    )

    def __repr__(self):
        return f"<User {self.username}>"


class CustomerGroup(Base):
    """Gruppe von Kunden – wird Technikern zugeordnet, um Datenzugriff zu steuern."""
    __tablename__ = "customer_groups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=func.now(), nullable=False)

    # Benachrichtigungs-Einstellungen
    notification_enabled = Column(Boolean, default=False, nullable=False)
    notify_admins = Column(Boolean, default=False, nullable=False)
    notification_types = Column(Text, nullable=True)    # JSON-Array, NULL = alle
    notification_severities = Column(Text, nullable=True)  # JSON-Array, NULL = alle

    customers = relationship(
        "Customer",
        secondary=customer_customer_groups,
        back_populates="customer_groups",
    )
    users = relationship(
        "User",
        secondary=user_customer_groups,
        back_populates="customer_groups",
    )

    def __repr__(self):
        return f"<CustomerGroup {self.name}>"


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
    customer_groups = relationship(
        "CustomerGroup",
        secondary=customer_customer_groups,
        back_populates="customers",
    )

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
    san = Column(Text)
    issuer = Column(String(255))
    serial_number = Column(String(255))

    valid_from = Column(DateTime, nullable=True)
    valid_until = Column(DateTime, nullable=True)

    status = Column(String(20), default="pending", nullable=False)
    auto_renew = Column(Boolean, default=False, nullable=False)
    notes = Column(Text)
    is_archived = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)

    cert_pem = Column(Text, nullable=True)
    chain_pem = Column(Text, nullable=True)

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

    common_name = Column(String(255), nullable=False, index=True)
    sans = Column(Text)
    country = Column(String(2))
    state = Column(String(128))
    locality = Column(String(128))
    organization = Column(String(200))
    organizational_unit = Column(String(200))
    email = Column(String(100))
    key_size = Column(Integer, default=2048, nullable=False)

    csr_pem = Column(Text, nullable=False)
    private_key_encrypted = Column(Text, nullable=False)

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
    __tablename__ = "app_settings"

    id = Column(Integer, primary_key=True)
    key = Column(String(100), unique=True, nullable=False, index=True)
    value = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=func.now(), nullable=False)
    updated_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    def __repr__(self):
        return f"<AppSetting {self.key}>"


class TheSSLStoreProduct(Base):
    __tablename__ = "thesslstore_products"

    id = Column(Integer, primary_key=True)
    sku = Column(String(100), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    product_code = Column(String(100))
    validity_period = Column(Integer, default=12)
    max_san = Column(Integer, default=0)
    is_wildcard = Column(Boolean, default=False)
    is_dv = Column(Boolean, default=False)
    is_ov = Column(Boolean, default=False)
    is_ev = Column(Boolean, default=False)
    vendor_name = Column(String(100))
    raw_json = Column(Text)
    synced_at = Column(DateTime, default=func.now(), nullable=False)

    def __repr__(self):
        return f"<TheSSLStoreProduct {self.sku}>"


class TheSSLStoreOrder(Base):
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
    validity_period = Column(Integer, default=12)
    approver_email = Column(String(200), nullable=True)
    domain_control_method = Column(String(20), default="EMAIL")
    raw_status_json = Column(Text, nullable=True)
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
    __tablename__ = "csr_templates"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    country = Column(String(2))
    state = Column(String(128))
    locality = Column(String(128))
    organization = Column(String(200))
    organizational_unit = Column(String(200))
    key_size = Column(Integer, default=2048, nullable=False)
    san_pattern = Column(Text)
    is_default = Column(Boolean, default=False, nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)

    creator = relationship("User", foreign_keys=[created_by])

    def __repr__(self):
        return f"<CsrTemplate {self.name}>"


class CustomerDefaults(Base):
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


class MailTemplate(Base):
    """Vorlage für automatische E-Mail-Benachrichtigungen."""
    __tablename__ = "mail_templates"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    template_key = Column(String(100), unique=True, nullable=False, index=True)
    subject = Column(String(255), nullable=False)
    text_body = Column(Text, nullable=False)
    html_body = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), nullable=False)

    def __repr__(self):
        return f"<MailTemplate {self.template_key}>"


class NotificationDispatch(Base):
    """Protokoll aller versendeten (oder fehlgeschlagenen) Benachrichtigungen."""
    __tablename__ = "notification_dispatches"

    id = Column(Integer, primary_key=True)
    event_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=True)
    customer_group_id = Column(Integer, ForeignKey("customer_groups.id"), nullable=True)
    certificate_id = Column(Integer, ForeignKey("certificates.id"), nullable=True)
    recipient_email = Column(String(200), nullable=False)
    template_key = Column(String(100), nullable=True)
    subject_rendered = Column(String(255), nullable=True)
    body_rendered = Column(Text, nullable=True)
    sent_at = Column(DateTime, nullable=True)
    status = Column(String(20), default="pending", nullable=False)  # pending | sent | failed | skipped
    error_message = Column(Text, nullable=True)
    dedup_key = Column(String(200), nullable=True, index=True)
    created_at = Column(DateTime, default=func.now(), nullable=False)

    customer = relationship("Customer")
    customer_group = relationship("CustomerGroup")
    certificate = relationship("Certificate")

    def __repr__(self):
        return f"<NotificationDispatch {self.event_type} → {self.recipient_email} [{self.status}]>"


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False, index=True)
    entity_type = Column(String(50), nullable=False)
    entity_id = Column(Integer, nullable=True, index=True)
    details = Column(Text)
    ip_address = Column(String(45))
    created_at = Column(DateTime, default=func.now(), nullable=False)

    user = relationship("User")

    def __repr__(self):
        return f"<AuditLog {self.action} by user_id={self.user_id}>"


class Backup(Base):
    """Metadaten zu erstellten Backups (global oder pro Kundengruppe)."""
    __tablename__ = "backups"

    id = Column(Integer, primary_key=True, index=True)
    backup_type = Column(String(20), nullable=False)   # "global" | "customer_group"
    customer_group_id = Column(Integer, ForeignKey("customer_groups.id"), nullable=True)
    label = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    created_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    status = Column(String(20), default="pending", nullable=False)  # pending | completed | failed
    archive_path = Column(String(500), nullable=True)
    size_bytes = Column(Integer, nullable=True)
    checksum = Column(String(64), nullable=True)        # SHA-256 hex
    metadata_json = Column(Text, nullable=True)
    restore_count = Column(Integer, default=0, nullable=False)
    last_restored_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)

    created_by = relationship("User", foreign_keys=[created_by_user_id])
    customer_group = relationship("CustomerGroup")

    def __repr__(self):
        return f"<Backup {self.backup_type} [{self.status}]>"
