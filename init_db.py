#!/usr/bin/env python3
"""
Initialisiert die Datenbank und legt einen Admin-Benutzer an.
Führt auch einfache Schema-Migrationen durch (neue Spalten).
Aufruf: python init_db.py
"""
import os
import sys

from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, os.path.dirname(__file__))

from sqlalchemy import inspect, text
from app.database import Base, engine, SessionLocal
from app.models import User
from app.auth import hash_password


_DEFAULT_TEMPLATES = [
    {
        "name": "Zertifikat läuft in 30 Tagen ab",
        "template_key": "certificate_expiring_30_days",
        "subject": "[Warnung] Zertifikat läuft in {{days_remaining}} Tagen ab: {{certificate_common_name}}",
        "text_body": (
            "SSL Cert Manager – Automatische Benachrichtigung\n"
            "================================================\n\n"
            "Schweregrad: {{severity}}\n"
            "Ereignis:    Zertifikat läuft bald ab\n\n"
            "Zertifikat:  {{certificate_common_name}}\n"
            "Kunde:       {{customer_name}}\n"
            "Gruppe:      {{customer_group_name}}\n"
            "Gültig bis:  {{certificate_valid_to}}\n"
            "Verbleibend: {{days_remaining}} Tage\n"
            "SANs:        {{certificate_sans}}\n\n"
            "Bitte erneuern Sie dieses Zertifikat zeitnah.\n\n"
            "Portal: {{portal_url}}\n"
        ),
    },
    {
        "name": "Zertifikat läuft in 14 Tagen ab",
        "template_key": "certificate_expiring_14_days",
        "subject": "[KRITISCH] Zertifikat läuft in {{days_remaining}} Tagen ab: {{certificate_common_name}}",
        "text_body": (
            "SSL Cert Manager – DRINGENDE Benachrichtigung\n"
            "==============================================\n\n"
            "Schweregrad: {{severity}}\n"
            "Ereignis:    Zertifikat läuft in Kürze ab!\n\n"
            "Zertifikat:  {{certificate_common_name}}\n"
            "Kunde:       {{customer_name}}\n"
            "Gruppe:      {{customer_group_name}}\n"
            "Gültig bis:  {{certificate_valid_to}}\n"
            "Verbleibend: {{days_remaining}} Tage\n"
            "SANs:        {{certificate_sans}}\n\n"
            "HANDLUNGSBEDARF: Bitte erneuern Sie dieses Zertifikat SOFORT.\n\n"
            "Portal: {{portal_url}}\n"
        ),
    },
    {
        "name": "Zertifikat abgelaufen",
        "template_key": "certificate_expired",
        "subject": "[KRITISCH] Zertifikat abgelaufen: {{certificate_common_name}}",
        "text_body": (
            "SSL Cert Manager – KRITISCHE Benachrichtigung\n"
            "==============================================\n\n"
            "Schweregrad: {{severity}}\n"
            "Ereignis:    Zertifikat ist abgelaufen!\n\n"
            "Zertifikat:  {{certificate_common_name}}\n"
            "Kunde:       {{customer_name}}\n"
            "Gruppe:      {{customer_group_name}}\n"
            "Abgelaufen:  {{certificate_valid_to}}\n"
            "SANs:        {{certificate_sans}}\n\n"
            "Das Zertifikat ist abgelaufen und muss sofort erneuert werden.\n\n"
            "Portal: {{portal_url}}\n"
        ),
    },
    {
        "name": "Zertifikat ungültig",
        "template_key": "certificate_invalid",
        "subject": "[Warnung] Zertifikat ungültig: {{certificate_common_name}}",
        "text_body": (
            "SSL Cert Manager – Automatische Benachrichtigung\n"
            "================================================\n\n"
            "Schweregrad: {{severity}}\n"
            "Ereignis:    Zertifikat ungültig\n\n"
            "Zertifikat:  {{certificate_common_name}}\n"
            "Kunde:       {{customer_name}}\n"
            "Gruppe:      {{customer_group_name}}\n"
            "Status:      {{status}}\n"
            "SANs:        {{certificate_sans}}\n\n"
            "Portal: {{portal_url}}\n"
        ),
    },
    {
        "name": "Fehlende Chain",
        "template_key": "certificate_missing_chain",
        "subject": "[Warnung] Fehlende Chain: {{certificate_common_name}}",
        "text_body": (
            "SSL Cert Manager – Automatische Benachrichtigung\n"
            "================================================\n\n"
            "Schweregrad: {{severity}}\n"
            "Ereignis:    Zertifikat ohne Intermediate-Chain\n\n"
            "Zertifikat:  {{certificate_common_name}}\n"
            "Kunde:       {{customer_name}}\n"
            "Gruppe:      {{customer_group_name}}\n"
            "SANs:        {{certificate_sans}}\n\n"
            "Das Zertifikat ist hochgeladen, aber ohne Intermediate-Chain.\n"
            "Bitte laden Sie die Chain-Datei nach.\n\n"
            "Portal: {{portal_url}}\n"
        ),
    },
]


def _seed_default_templates(eng) -> None:
    """Legt Standard-Mailtemplates an (nur wenn noch nicht vorhanden)."""
    from datetime import datetime
    with eng.connect() as conn:
        for tpl in _DEFAULT_TEMPLATES:
            existing = conn.execute(
                text("SELECT id FROM mail_templates WHERE template_key = :k"),
                {"k": tpl["template_key"]},
            ).first()
            if not existing:
                conn.execute(
                    text("""
                        INSERT INTO mail_templates (name, template_key, subject, text_body, is_active, created_at, updated_at)
                        VALUES (:name, :key, :subject, :body, 1, :now, :now)
                    """),
                    {
                        "name": tpl["name"],
                        "key": tpl["template_key"],
                        "subject": tpl["subject"],
                        "body": tpl["text_body"],
                        "now": datetime.utcnow().isoformat(),
                    },
                )
        conn.commit()
    print("Standard-Mailtemplates angelegt.")


def run_migrations():
    """Fügt fehlende Spalten zu bestehenden Tabellen hinzu."""
    inspector = inspect(engine)

    # customers.is_archived
    if "customers" in inspector.get_table_names():
        existing_cols = [c["name"] for c in inspector.get_columns("customers")]
        if "is_archived" not in existing_cols:
            with engine.connect() as conn:
                conn.execute(text(
                    "ALTER TABLE customers ADD COLUMN is_archived BOOLEAN NOT NULL DEFAULT 0"
                ))
                conn.commit()
            print("Migration: Spalte 'is_archived' zu 'customers' hinzugefügt.")

    # certificates: cert_pem, chain_pem, csr_request_id
    if "certificates" in inspector.get_table_names():
        existing_cols = [c["name"] for c in inspector.get_columns("certificates")]
        with engine.connect() as conn:
            changed = False
            if "cert_pem" not in existing_cols:
                conn.execute(text("ALTER TABLE certificates ADD COLUMN cert_pem TEXT"))
                changed = True
            if "chain_pem" not in existing_cols:
                conn.execute(text("ALTER TABLE certificates ADD COLUMN chain_pem TEXT"))
                changed = True
            if "csr_request_id" not in existing_cols:
                conn.execute(text(
                    "ALTER TABLE certificates ADD COLUMN csr_request_id INTEGER"
                    " REFERENCES csr_requests(id)"
                ))
                changed = True
            if changed:
                conn.commit()
                print("Migration: Spalten 'cert_pem', 'chain_pem', 'csr_request_id' zu 'certificates' hinzugefügt.")

    # users: MFA-Spalten
    if "users" in inspector.get_table_names():
        existing_cols = [c["name"] for c in inspector.get_columns("users")]
        with engine.connect() as conn:
            changed = False
            if "mfa_secret_encrypted" not in existing_cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN mfa_secret_encrypted TEXT"))
                changed = True
            if "mfa_setup_completed" not in existing_cols:
                conn.execute(text(
                    "ALTER TABLE users ADD COLUMN mfa_setup_completed BOOLEAN NOT NULL DEFAULT 0"
                ))
                changed = True
            if "recovery_codes_json" not in existing_cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN recovery_codes_json TEXT"))
                changed = True
            if "last_mfa_at" not in existing_cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN last_mfa_at DATETIME"))
                changed = True
            if changed:
                conn.commit()
                print("Migration: MFA-Spalten zu 'users' hinzugefügt.")

    # app_settings
    if "app_settings" not in inspector.get_table_names():
        with engine.connect() as conn:
            conn.execute(text("""
                CREATE TABLE app_settings (
                    id INTEGER PRIMARY KEY,
                    key VARCHAR(100) UNIQUE NOT NULL,
                    value TEXT,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                    updated_by INTEGER REFERENCES users(id)
                )
            """))
            conn.commit()
        print("Migration: Tabelle 'app_settings' angelegt.")

    # thesslstore_products
    if "thesslstore_products" not in inspector.get_table_names():
        with engine.connect() as conn:
            conn.execute(text("""
                CREATE TABLE thesslstore_products (
                    id INTEGER PRIMARY KEY,
                    sku VARCHAR(100) UNIQUE NOT NULL,
                    name VARCHAR(255) NOT NULL,
                    product_code VARCHAR(100),
                    validity_period INTEGER DEFAULT 12,
                    max_san INTEGER DEFAULT 0,
                    is_wildcard BOOLEAN DEFAULT 0,
                    is_dv BOOLEAN DEFAULT 0,
                    is_ov BOOLEAN DEFAULT 0,
                    is_ev BOOLEAN DEFAULT 0,
                    vendor_name VARCHAR(100),
                    raw_json TEXT,
                    synced_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
                )
            """))
            conn.commit()
        print("Migration: Tabelle 'thesslstore_products' angelegt.")

    # csr_requests: is_archived
    if "csr_requests" in inspector.get_table_names():
        existing_cols = [c["name"] for c in inspector.get_columns("csr_requests")]
        if "is_archived" not in existing_cols:
            with engine.connect() as conn:
                conn.execute(text(
                    "ALTER TABLE csr_requests ADD COLUMN is_archived BOOLEAN NOT NULL DEFAULT 0"
                ))
                conn.commit()
            print("Migration: Spalte 'is_archived' zu 'csr_requests' hinzugefügt.")

    # certificates: is_archived
    if "certificates" in inspector.get_table_names():
        existing_cols = [c["name"] for c in inspector.get_columns("certificates")]
        if "is_archived" not in existing_cols:
            with engine.connect() as conn:
                conn.execute(text(
                    "ALTER TABLE certificates ADD COLUMN is_archived BOOLEAN NOT NULL DEFAULT 0"
                ))
                conn.commit()
            print("Migration: Spalte 'is_archived' zu 'certificates' hinzugefügt.")

    # csr_templates
    if "csr_templates" not in inspector.get_table_names():
        with engine.connect() as conn:
            conn.execute(text("""
                CREATE TABLE csr_templates (
                    id INTEGER PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    country VARCHAR(2),
                    state VARCHAR(128),
                    locality VARCHAR(128),
                    organization VARCHAR(200),
                    organizational_unit VARCHAR(200),
                    key_size INTEGER NOT NULL DEFAULT 2048,
                    san_pattern TEXT,
                    is_default BOOLEAN NOT NULL DEFAULT 0,
                    created_by INTEGER NOT NULL REFERENCES users(id),
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))
            conn.commit()
        print("Migration: Tabelle 'csr_templates' angelegt.")

    # customer_defaults
    if "customer_defaults" not in inspector.get_table_names():
        with engine.connect() as conn:
            conn.execute(text("""
                CREATE TABLE customer_defaults (
                    id INTEGER PRIMARY KEY,
                    customer_id INTEGER NOT NULL UNIQUE REFERENCES customers(id),
                    default_country VARCHAR(2),
                    default_state VARCHAR(128),
                    default_locality VARCHAR(128),
                    default_org VARCHAR(200),
                    default_ou VARCHAR(200),
                    preferred_validity_days INTEGER,
                    preferred_product_sku VARCHAR(100),
                    validation_notes TEXT,
                    technical_notes TEXT,
                    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))
            conn.commit()
        print("Migration: Tabelle 'customer_defaults' angelegt.")

    # users: role-Spalte
    if "users" in inspector.get_table_names():
        existing_cols = [c["name"] for c in inspector.get_columns("users")]
        if "role" not in existing_cols:
            with engine.connect() as conn:
                # Bestehende Benutzer: is_admin=True → role='admin', sonst 'technician'
                conn.execute(text(
                    "ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'admin'"
                ))
                conn.execute(text(
                    "UPDATE users SET role = CASE WHEN is_admin = 1 THEN 'admin' ELSE 'technician' END"
                ))
                conn.commit()
            print("Migration: Spalte 'role' zu 'users' hinzugefügt (bestehende Admins → 'admin').")

    # customer_groups
    if "customer_groups" not in inspector.get_table_names():
        with engine.connect() as conn:
            conn.execute(text("""
                CREATE TABLE customer_groups (
                    id INTEGER PRIMARY KEY,
                    name VARCHAR(100) NOT NULL UNIQUE,
                    description TEXT,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))
            conn.commit()
        print("Migration: Tabelle 'customer_groups' angelegt.")

    # user_customer_groups (Techniker ↔ Kundengruppen)
    if "user_customer_groups" not in inspector.get_table_names():
        with engine.connect() as conn:
            conn.execute(text("""
                CREATE TABLE user_customer_groups (
                    user_id INTEGER NOT NULL REFERENCES users(id),
                    group_id INTEGER NOT NULL REFERENCES customer_groups(id),
                    PRIMARY KEY (user_id, group_id)
                )
            """))
            conn.commit()
        print("Migration: Tabelle 'user_customer_groups' angelegt.")

    # customer_customer_groups (Kunden ↔ Kundengruppen)
    if "customer_customer_groups" not in inspector.get_table_names():
        with engine.connect() as conn:
            conn.execute(text("""
                CREATE TABLE customer_customer_groups (
                    customer_id INTEGER NOT NULL REFERENCES customers(id),
                    group_id INTEGER NOT NULL REFERENCES customer_groups(id),
                    PRIMARY KEY (customer_id, group_id)
                )
            """))
            conn.commit()
        print("Migration: Tabelle 'customer_customer_groups' angelegt.")

    # customer_groups: Benachrichtigungs-Spalten
    if "customer_groups" in inspector.get_table_names():
        existing_cols = [c["name"] for c in inspector.get_columns("customer_groups")]
        with engine.connect() as conn:
            changed = False
            if "notification_enabled" not in existing_cols:
                conn.execute(text(
                    "ALTER TABLE customer_groups ADD COLUMN notification_enabled BOOLEAN NOT NULL DEFAULT 0"
                ))
                changed = True
            if "notify_admins" not in existing_cols:
                conn.execute(text(
                    "ALTER TABLE customer_groups ADD COLUMN notify_admins BOOLEAN NOT NULL DEFAULT 0"
                ))
                changed = True
            if "notification_types" not in existing_cols:
                conn.execute(text(
                    "ALTER TABLE customer_groups ADD COLUMN notification_types TEXT"
                ))
                changed = True
            if "notification_severities" not in existing_cols:
                conn.execute(text(
                    "ALTER TABLE customer_groups ADD COLUMN notification_severities TEXT"
                ))
                changed = True
            if changed:
                conn.commit()
                print("Migration: Benachrichtigungs-Spalten zu 'customer_groups' hinzugefügt.")

    # mail_templates
    if "mail_templates" not in inspector.get_table_names():
        with engine.connect() as conn:
            conn.execute(text("""
                CREATE TABLE mail_templates (
                    id INTEGER PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    template_key VARCHAR(100) NOT NULL UNIQUE,
                    subject VARCHAR(255) NOT NULL,
                    text_body TEXT NOT NULL,
                    html_body TEXT,
                    is_active BOOLEAN NOT NULL DEFAULT 1,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))
            conn.commit()
        print("Migration: Tabelle 'mail_templates' angelegt.")
        _seed_default_templates(engine)

    # notification_dispatches
    if "notification_dispatches" not in inspector.get_table_names():
        with engine.connect() as conn:
            conn.execute(text("""
                CREATE TABLE notification_dispatches (
                    id INTEGER PRIMARY KEY,
                    event_type VARCHAR(50) NOT NULL,
                    severity VARCHAR(20) NOT NULL,
                    customer_id INTEGER REFERENCES customers(id),
                    customer_group_id INTEGER REFERENCES customer_groups(id),
                    certificate_id INTEGER REFERENCES certificates(id),
                    recipient_email VARCHAR(200) NOT NULL,
                    template_key VARCHAR(100),
                    subject_rendered VARCHAR(255),
                    body_rendered TEXT,
                    sent_at DATETIME,
                    status VARCHAR(20) NOT NULL DEFAULT 'pending',
                    error_message TEXT,
                    dedup_key VARCHAR(200),
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))
            conn.execute(text(
                "CREATE INDEX ix_notif_dedup ON notification_dispatches (dedup_key)"
            ))
            conn.execute(text(
                "CREATE INDEX ix_notif_event ON notification_dispatches (event_type)"
            ))
            conn.commit()
        print("Migration: Tabelle 'notification_dispatches' angelegt.")

    # certificate_notes
    if "certificate_notes" not in inspector.get_table_names():
        with engine.connect() as conn:
            conn.execute(text("""
                CREATE TABLE certificate_notes (
                    id INTEGER PRIMARY KEY,
                    certificate_id INTEGER NOT NULL REFERENCES certificates(id),
                    user_id INTEGER NOT NULL REFERENCES users(id),
                    note TEXT NOT NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))
            conn.commit()
        print("Migration: Tabelle 'certificate_notes' angelegt.")

    # thesslstore_orders
    if "thesslstore_orders" not in inspector.get_table_names():
        with engine.connect() as conn:
            conn.execute(text("""
                CREATE TABLE thesslstore_orders (
                    id INTEGER PRIMARY KEY,
                    certificate_id INTEGER UNIQUE REFERENCES certificates(id),
                    thessl_order_id VARCHAR(100),
                    vendor_order_id VARCHAR(100),
                    sku VARCHAR(100) NOT NULL,
                    status VARCHAR(50) DEFAULT 'pending' NOT NULL,
                    san_count INTEGER DEFAULT 0,
                    server_count INTEGER DEFAULT 1,
                    validity_period INTEGER DEFAULT 12,
                    approver_email VARCHAR(200),
                    domain_control_method VARCHAR(20) DEFAULT 'EMAIL',
                    raw_status_json TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
                )
            """))
            conn.commit()
        print("Migration: Tabelle 'thesslstore_orders' angelegt.")

    # backups
    if "backups" not in inspector.get_table_names():
        with engine.connect() as conn:
            conn.execute(text("""
                CREATE TABLE backups (
                    id INTEGER PRIMARY KEY,
                    backup_type VARCHAR(20) NOT NULL,
                    customer_group_id INTEGER REFERENCES customer_groups(id),
                    label VARCHAR(255),
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    created_by_user_id INTEGER REFERENCES users(id),
                    status VARCHAR(20) NOT NULL DEFAULT 'pending',
                    archive_path VARCHAR(500),
                    size_bytes INTEGER,
                    checksum VARCHAR(64),
                    metadata_json TEXT,
                    restore_count INTEGER NOT NULL DEFAULT 0,
                    last_restored_at DATETIME,
                    error_message TEXT
                )
            """))
            conn.execute(text(
                "CREATE INDEX ix_backups_type ON backups (backup_type)"
            ))
            conn.execute(text(
                "CREATE INDEX ix_backups_group ON backups (customer_group_id)"
            ))
            conn.commit()
        print("Migration: Tabelle 'backups' angelegt.")


def main():
    print("Erstelle Datenbankschema ...")
    Base.metadata.create_all(bind=engine)
    print("Schema erstellt.")

    run_migrations()

    db = SessionLocal()
    try:
        admin_username = os.getenv("ADMIN_USERNAME", "admin")
        existing = db.query(User).filter(User.username == admin_username).first()
        if existing:
            print(f"Admin-Benutzer '{admin_username}' existiert bereits – übersprungen.")
            return

        admin_password = os.getenv("ADMIN_PASSWORD", "changeme123")
        admin_email = os.getenv("ADMIN_EMAIL", "admin@example.com")

        user = User(
            username=admin_username,
            email=admin_email,
            hashed_password=hash_password(admin_password),
            is_active=True,
            is_admin=True,
            role="admin",
        )
        db.add(user)
        db.commit()
        print(f"Admin-Benutzer '{admin_username}' angelegt.")
        print(f"  E-Mail: {admin_email}")
        print(f"  Passwort: {admin_password}")
        print("WICHTIG: Passwort nach dem ersten Login ändern!")
    finally:
        db.close()


if __name__ == "__main__":
    main()
