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
