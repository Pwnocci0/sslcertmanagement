"""Tests: Kundengruppen-Berechtigungen für Techniker."""
from __future__ import annotations

import os
import unittest

os.environ.setdefault("APP_SECRET_KEY", "test-secret-key-for-testing-only-32chars")
os.environ.setdefault("CSR_KEY_PASSPHRASE", "test-passphrase")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from app import models
from app.settings_service import _invalidate_cache


# ── DB-Fixtures ───────────────────────────────────────────────────────────────

def _make_db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.database import Base
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


def _make_user(db, username, is_admin=False) -> models.User:
    from app.auth import hash_password
    u = models.User(
        username=username,
        email=f"{username}@example.com",
        hashed_password=hash_password("password"),
        is_admin=is_admin,
        is_active=True,
        mfa_setup_completed=True,
    )
    db.add(u)
    db.flush()
    return u


def _make_customer(db, name) -> models.Customer:
    c = models.Customer(name=name)
    db.add(c)
    db.flush()
    return c


def _make_group(db, name, customers=(), users=()) -> models.CustomerGroup:
    g = models.CustomerGroup(name=name)
    g.customers = list(customers)
    g.users = list(users)
    db.add(g)
    db.flush()
    return g


# ── Tests: _accessible_customers ─────────────────────────────────────────────

class TestAccessibleCustomers(unittest.TestCase):
    """_accessible_customers gibt Admins alle, Technikern nur eigene."""

    def setUp(self):
        self.db = _make_db()
        self.admin = _make_user(self.db, "admin", is_admin=True)
        self.tech = _make_user(self.db, "tech")
        self.c_allowed = _make_customer(self.db, "Erlaubter Kunde")
        self.c_foreign = _make_customer(self.db, "Fremder Kunde")
        self.group = _make_group(self.db, "Gruppe A",
                                 customers=[self.c_allowed], users=[self.tech])
        self.db.commit()

    def test_admin_sees_all_customers(self):
        from app.routers.customer_groups import _accessible_customers
        result = _accessible_customers(self.admin, self.db)
        ids = {c.id for c in result}
        self.assertIn(self.c_allowed.id, ids)
        self.assertIn(self.c_foreign.id, ids)

    def test_technician_sees_only_own_customers(self):
        from app.routers.customer_groups import _accessible_customers
        result = _accessible_customers(self.tech, self.db)
        ids = {c.id for c in result}
        self.assertIn(self.c_allowed.id, ids)
        self.assertNotIn(self.c_foreign.id, ids)

    def test_technician_without_groups_sees_nothing(self):
        tech_no_groups = _make_user(self.db, "loner")
        from app.routers.customer_groups import _accessible_customers
        result = _accessible_customers(tech_no_groups, self.db)
        self.assertEqual(result, [])


# ── Tests: _filter_allowed_customer_ids ──────────────────────────────────────

class TestFilterAllowedCustomerIds(unittest.TestCase):
    """_filter_allowed_customer_ids blockiert fremde IDs für Techniker."""

    def setUp(self):
        self.db = _make_db()
        self.admin = _make_user(self.db, "admin", is_admin=True)
        self.tech = _make_user(self.db, "tech")
        self.c1 = _make_customer(self.db, "Kunde 1")
        self.c2 = _make_customer(self.db, "Kunde 2")
        self.c_foreign = _make_customer(self.db, "Fremder")
        self.group = _make_group(self.db, "G", customers=[self.c1, self.c2], users=[self.tech])
        self.db.commit()

    def test_admin_gets_all_ids_through(self):
        from app.routers.customer_groups import _filter_allowed_customer_ids
        ids = [self.c1.id, self.c2.id, self.c_foreign.id]
        result = _filter_allowed_customer_ids(ids, self.admin, self.db)
        self.assertEqual(set(result), set(ids))

    def test_technician_gets_only_own_ids(self):
        from app.routers.customer_groups import _filter_allowed_customer_ids
        ids = [self.c1.id, self.c2.id, self.c_foreign.id]
        result = _filter_allowed_customer_ids(ids, self.tech, self.db)
        self.assertIn(self.c1.id, result)
        self.assertIn(self.c2.id, result)
        self.assertNotIn(self.c_foreign.id, result)

    def test_technician_with_all_foreign_ids_gets_empty(self):
        from app.routers.customer_groups import _filter_allowed_customer_ids
        result = _filter_allowed_customer_ids([self.c_foreign.id], self.tech, self.db)
        self.assertEqual(result, [])

    def test_empty_input_returns_empty(self):
        from app.routers.customer_groups import _filter_allowed_customer_ids
        result = _filter_allowed_customer_ids([], self.tech, self.db)
        self.assertEqual(result, [])

    def test_technician_cannot_escalate_via_manipulated_ids(self):
        """Manipulierte POST-IDs kommen nicht durch."""
        from app.routers.customer_groups import _filter_allowed_customer_ids
        # Techniker sendet nur fremde IDs
        malicious = [self.c_foreign.id, 99999, -1]
        result = _filter_allowed_customer_ids(malicious, self.tech, self.db)
        self.assertEqual(result, [])


# ── Tests: Neue Gruppe — kein Rechtegewinn durch neue Gruppe ─────────────────

class TestNoPrivilegeEscalationViaNewGroup(unittest.TestCase):
    """Techniker kann sich durch neue Gruppe keine fremden Kunden erschleichen."""

    def setUp(self):
        self.db = _make_db()
        self.tech = _make_user(self.db, "tech")
        self.c_own = _make_customer(self.db, "Eigener")
        self.c_foreign = _make_customer(self.db, "Fremder")
        self.group = _make_group(self.db, "Bestehend",
                                 customers=[self.c_own], users=[self.tech])
        self.db.commit()

    def test_foreign_id_filtered_on_new_group_creation(self):
        from app.routers.customer_groups import _filter_allowed_customer_ids
        submitted = [self.c_own.id, self.c_foreign.id]
        result = _filter_allowed_customer_ids(submitted, self.tech, self.db)
        self.assertIn(self.c_own.id, result)
        self.assertNotIn(self.c_foreign.id, result)

    def test_technician_with_no_groups_cannot_assign_any_customer(self):
        """Techniker ohne Gruppen darf keine Kunden zuordnen."""
        tech_new = _make_user(self.db, "new_tech")
        from app.routers.customer_groups import _filter_allowed_customer_ids
        result = _filter_allowed_customer_ids([self.c_own.id, self.c_foreign.id], tech_new, self.db)
        self.assertEqual(result, [])


# ── Tests: Bearbeiten einer Gruppe ───────────────────────────────────────────

class TestGroupEditCustomerFilter(unittest.TestCase):
    """Beim Bearbeiten einer Gruppe werden ebenfalls nur erlaubte Kunden akzeptiert."""

    def setUp(self):
        self.db = _make_db()
        self.admin = _make_user(self.db, "admin", is_admin=True)
        self.c1 = _make_customer(self.db, "K1")
        self.c2 = _make_customer(self.db, "K2")
        self.c_foreign = _make_customer(self.db, "Fremd")
        self.db.commit()

    def test_admin_can_assign_any_customer_on_edit(self):
        from app.routers.customer_groups import _filter_allowed_customer_ids
        ids = [self.c1.id, self.c2.id, self.c_foreign.id]
        result = _filter_allowed_customer_ids(ids, self.admin, self.db)
        self.assertEqual(set(result), {self.c1.id, self.c2.id, self.c_foreign.id})

    def test_technician_cannot_add_foreign_customer_on_edit(self):
        tech = _make_user(self.db, "tech")
        group = _make_group(self.db, "G", customers=[self.c1], users=[tech])
        self.db.commit()

        from app.routers.customer_groups import _filter_allowed_customer_ids
        # Techniker versucht c_foreign hinzuzufügen
        result = _filter_allowed_customer_ids([self.c1.id, self.c_foreign.id], tech, self.db)
        self.assertIn(self.c1.id, result)
        self.assertNotIn(self.c_foreign.id, result)


# ── Tests: get_accessible_customer_ids aus auth.py ───────────────────────────

class TestGetAccessibleCustomerIds(unittest.TestCase):
    """get_accessible_customer_ids liefert None für Admins, IDs für Techniker."""

    def setUp(self):
        self.db = _make_db()
        self.admin = _make_user(self.db, "admin", is_admin=True)
        self.tech = _make_user(self.db, "tech")
        self.c1 = _make_customer(self.db, "K1")
        self.c2 = _make_customer(self.db, "K2")
        self.c_foreign = _make_customer(self.db, "Fremd")
        self.group = _make_group(self.db, "G", customers=[self.c1, self.c2], users=[self.tech])
        self.db.commit()

    def test_admin_returns_none(self):
        from app.auth import get_accessible_customer_ids
        result = get_accessible_customer_ids(self.admin, self.db)
        self.assertIsNone(result)

    def test_technician_returns_own_customer_ids(self):
        from app.auth import get_accessible_customer_ids
        result = get_accessible_customer_ids(self.tech, self.db)
        self.assertIsInstance(result, list)
        self.assertIn(self.c1.id, result)
        self.assertIn(self.c2.id, result)
        self.assertNotIn(self.c_foreign.id, result)

    def test_technician_without_groups_returns_empty_list(self):
        from app.auth import get_accessible_customer_ids
        lonely = _make_user(self.db, "lonely")
        result = get_accessible_customer_ids(lonely, self.db)
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
