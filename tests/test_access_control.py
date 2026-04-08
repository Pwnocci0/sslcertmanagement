"""Tests für rollenbasierte Zugriffskontrolle (Admin vs. Techniker).

Geprüft wird:
- get_accessible_customer_ids(): None für Admins, gefilterte Liste für Techniker
- check_customer_access(): Admin darf alles, Techniker nur zugewiesene Kunden
- forbidden_response(): gibt HTTP 403 zurück
- Techniker ohne Gruppen haben auf keine Kunden Zugriff
- Techniker mit Gruppen haben Zugriff auf alle Kunden in diesen Gruppen
"""
from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("APP_SECRET_KEY", "test-secret-key-for-unit-tests")
os.environ.setdefault("CSR_KEY_PASSPHRASE", "test-passphrase-for-unit-tests")


# ── Test-Fixtures ─────────────────────────────────────────────────────────────

def _make_customer(customer_id: int, name: str = "Testkunde"):
    c = MagicMock()
    c.id = customer_id
    c.name = name
    c.is_archived = False
    return c


def _make_group(group_id: int, customer_ids: list[int], name: str = "Testgruppe"):
    group = MagicMock()
    group.id = group_id
    group.name = name
    group.customers = [_make_customer(cid) for cid in customer_ids]
    return group


def _make_admin():
    from app import models
    user = MagicMock(spec=models.User)
    user.id = 1
    user.username = "admin"
    user.is_admin = True
    user.is_active = True
    user.role = "admin"
    user.customer_groups = []
    return user


def _make_technician(group_customer_ids: list[list[int]] | None = None):
    """Erstellt einen Techniker-User.

    group_customer_ids: Liste von Kunden-ID-Listen pro Gruppe.
    Z.B. [[1, 2], [3]] → 2 Gruppen, Gruppe 1 mit Kunden 1+2, Gruppe 2 mit Kunde 3.
    """
    from app import models
    user = MagicMock(spec=models.User)
    user.id = 2
    user.username = "techniker"
    user.is_admin = False
    user.is_active = True
    user.role = "technician"

    if group_customer_ids is None:
        user.customer_groups = []
    else:
        user.customer_groups = [
            _make_group(i + 1, ids)
            for i, ids in enumerate(group_customer_ids)
        ]
    return user


# ── get_accessible_customer_ids() ────────────────────────────────────────────

class TestGetAccessibleCustomerIds:

    def test_admin_liefert_none(self):
        """Admin bekommt None (= unbeschränkter Zugriff)."""
        from app.auth import get_accessible_customer_ids

        user = _make_admin()
        result = get_accessible_customer_ids(user, db=MagicMock())
        assert result is None

    def test_techniker_ohne_gruppen_liefert_leere_liste(self):
        """Techniker ohne zugewiesene Gruppen bekommt leere Liste."""
        from app.auth import get_accessible_customer_ids

        user = _make_technician(group_customer_ids=[])
        result = get_accessible_customer_ids(user, db=MagicMock())
        assert result == []

    def test_techniker_eine_gruppe(self):
        """Techniker mit einer Gruppe bekommt Kunden dieser Gruppe."""
        from app.auth import get_accessible_customer_ids

        user = _make_technician(group_customer_ids=[[1, 2, 3]])
        result = get_accessible_customer_ids(user, db=MagicMock())
        assert set(result) == {1, 2, 3}

    def test_techniker_mehrere_gruppen(self):
        """Mehrere Gruppen werden zu einer eindeutigen Menge zusammengeführt."""
        from app.auth import get_accessible_customer_ids

        user = _make_technician(group_customer_ids=[[1, 2], [2, 3]])
        result = get_accessible_customer_ids(user, db=MagicMock())
        assert set(result) == {1, 2, 3}

    def test_techniker_duplikate_werden_dedupliziert(self):
        """Kunden in mehreren Gruppen erscheinen nur einmal."""
        from app.auth import get_accessible_customer_ids

        user = _make_technician(group_customer_ids=[[5, 6], [5, 7]])
        result = get_accessible_customer_ids(user, db=MagicMock())
        assert len(result) == len(set(result)), "Duplikate in der Ergebnisliste!"
        assert set(result) == {5, 6, 7}


# ── check_customer_access() ──────────────────────────────────────────────────

class TestCheckCustomerAccess:

    def test_admin_hat_zugriff_auf_jeden_kunden(self):
        """Admin darf auf beliebige customer_id zugreifen."""
        from app.auth import check_customer_access

        user = _make_admin()
        for cid in [1, 100, 99999]:
            assert check_customer_access(user, cid, db=MagicMock()) is True

    def test_techniker_hat_zugriff_auf_eigene_kunden(self):
        """Techniker darf auf Kunden in seinen Gruppen zugreifen."""
        from app.auth import check_customer_access

        user = _make_technician(group_customer_ids=[[10, 20]])
        assert check_customer_access(user, 10, db=MagicMock()) is True
        assert check_customer_access(user, 20, db=MagicMock()) is True

    def test_techniker_hat_keinen_zugriff_auf_fremde_kunden(self):
        """Techniker darf nicht auf Kunden zugreifen, die nicht in seinen Gruppen sind."""
        from app.auth import check_customer_access

        user = _make_technician(group_customer_ids=[[10, 20]])
        assert check_customer_access(user, 30, db=MagicMock()) is False
        assert check_customer_access(user, 99, db=MagicMock()) is False

    def test_techniker_ohne_gruppen_hat_keinen_zugriff(self):
        """Techniker ohne Gruppen hat auf keinen Kunden Zugriff."""
        from app.auth import check_customer_access

        user = _make_technician(group_customer_ids=[])
        assert check_customer_access(user, 1, db=MagicMock()) is False


# ── forbidden_response() ─────────────────────────────────────────────────────

class TestForbiddenResponse:

    def test_gibt_403_zurueck(self):
        """forbidden_response liefert HTTP 403."""
        from app.auth import forbidden_response

        resp = forbidden_response()
        assert resp.status_code == 403

    def test_standardmeldung(self):
        """Standardmeldung ist vorhanden."""
        from app.auth import forbidden_response

        resp = forbidden_response()
        assert "Kein Zugriff" in resp.body.decode()

    def test_eigene_meldung(self):
        """Benutzerdefinierte Meldung erscheint im Body."""
        from app.auth import forbidden_response

        resp = forbidden_response("Spezieller Fehlertext")
        assert "Spezieller Fehlertext" in resp.body.decode()


# ── HTTP-Routen: Zugriffsschutz ───────────────────────────────────────────────

class TestRouteAccessControl:
    """Prüft, dass HTTP-Routen Techniker bei fremden Ressourcen mit 403 abweisen."""

    def _make_db_mock(self, cert=None, customer=None):
        db = MagicMock()
        q = db.query.return_value
        q.filter.return_value.first.return_value = cert or customer
        return db

    def test_export_pfx_get_fremder_kunde_gibt_403(self):
        """GET /exports/certificate/{id}/pfx → 403 wenn Techniker keinen Zugriff hat."""
        from fastapi.testclient import TestClient
        from app.main import app

        technician = _make_technician(group_customer_ids=[[1, 2]])

        cert = MagicMock()
        cert.id = 99
        cert.customer_id = 999  # Kein Zugriff
        cert.cert_pem = "---cert---"
        cert.csr_request_id = 1

        db = self._make_db_mock(cert=cert)

        with (
            patch("app.routers.exports.login_required", return_value=technician),
            patch("app.routers.exports.get_db", return_value=db),
            patch("app.database.get_db", return_value=db),
        ):
            client = TestClient(app, raise_server_exceptions=True)
            resp = client.get("/exports/certificate/99/pfx", follow_redirects=False)

        assert resp.status_code == 403

    def test_export_zip_get_fremder_kunde_gibt_403(self):
        """GET /exports/certificate/{id}/zip → 403 wenn Techniker keinen Zugriff hat."""
        from fastapi.testclient import TestClient
        from app.main import app

        technician = _make_technician(group_customer_ids=[[1]])

        cert = MagicMock()
        cert.id = 10
        cert.customer_id = 50  # Kein Zugriff
        cert.csr_request_id = None
        cert.csr_request = None

        db = self._make_db_mock(cert=cert)

        with (
            patch("app.routers.exports.login_required", return_value=technician),
            patch("app.routers.exports.get_db", return_value=db),
            patch("app.database.get_db", return_value=db),
        ):
            client = TestClient(app, raise_server_exceptions=True)
            resp = client.get("/exports/certificate/10/zip", follow_redirects=False)

        assert resp.status_code == 403

    def test_export_pfx_get_eigener_kunde_gibt_200(self):
        """GET /exports/certificate/{id}/pfx → 200 wenn Techniker Zugriff hat."""
        from fastapi.testclient import TestClient
        from app.main import app

        technician = _make_technician(group_customer_ids=[[7]])

        cert = MagicMock()
        cert.id = 55
        cert.customer_id = 7  # Zugriff erlaubt
        cert.cert_pem = "---cert---"
        cert.csr_request_id = 1
        cert.common_name = "test.example.com"
        cert.chain_pem = None

        db = self._make_db_mock(cert=cert)

        with (
            patch("app.routers.exports.login_required", return_value=technician),
            patch("app.routers.exports.get_db", return_value=db),
            patch("app.database.get_db", return_value=db),
        ):
            client = TestClient(app, raise_server_exceptions=True)
            resp = client.get("/exports/certificate/55/pfx", follow_redirects=False)

        assert resp.status_code == 200

    def test_admin_hat_zugriff_auf_jeden_export(self):
        """Admin hat Zugriff auf Exporte beliebiger Kunden."""
        from fastapi.testclient import TestClient
        from app.main import app

        admin = _make_admin()

        cert = MagicMock()
        cert.id = 77
        cert.customer_id = 999
        cert.cert_pem = "---cert---"
        cert.csr_request_id = 1
        cert.common_name = "admin-test.example.com"
        cert.chain_pem = None

        db = self._make_db_mock(cert=cert)

        with (
            patch("app.routers.exports.login_required", return_value=admin),
            patch("app.routers.exports.get_db", return_value=db),
            patch("app.database.get_db", return_value=db),
        ):
            client = TestClient(app, raise_server_exceptions=True)
            resp = client.get("/exports/certificate/77/pfx", follow_redirects=False)

        assert resp.status_code == 200
