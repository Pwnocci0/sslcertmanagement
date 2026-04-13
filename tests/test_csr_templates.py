"""Tests für CSR-Vorlagen: server-seitiges Prefill, Standardvorlage, API."""
from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("APP_SECRET_KEY", "test-secret-key-for-csr-template-tests")
os.environ.setdefault("CSR_KEY_PASSPHRASE", "test-passphrase")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app import models


# ── Test-DB-Setup ────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def engine():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    return eng


@pytest.fixture
def db(engine):
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.rollback()
    session.close()


@pytest.fixture(scope="module")
def module_db(engine):
    """Separate Session für modul-weite Fixtures."""
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture(scope="module")
def admin_user(module_db):
    u = models.User(
        username="tmpl_admin_mod",
        email="tmpl_admin_mod@example.com",
        hashed_password="hashed",
        is_active=True,
        is_admin=True,
        mfa_setup_completed=True,
    )
    module_db.add(u)
    module_db.commit()
    return u


@pytest.fixture(scope="module")
def template(module_db, admin_user):
    t = models.CsrTemplate(
        name="Testvorlage",
        country="DE",
        state="Bayern",
        locality="München",
        organization="Muster GmbH",
        organizational_unit="IT",
        key_size=4096,
        san_pattern="{cn}",
        is_default=False,
        created_by=admin_user.id,
    )
    module_db.add(t)
    module_db.commit()
    return t


@pytest.fixture(scope="module")
def default_template(module_db, admin_user):
    t = models.CsrTemplate(
        name="Standard-Vorlage",
        country="AT",
        state="Wien",
        locality="Wien",
        organization="Default Org",
        organizational_unit="Ops",
        key_size=2048,
        san_pattern="",
        is_default=True,
        created_by=admin_user.id,
    )
    module_db.add(t)
    module_db.commit()
    return t


# ── Hilfsfunktionen ──────────────────────────────────────────────────────────

def _make_request(query_params: dict | None = None):
    """Erzeugt einen minimalen Request-Mock für den Router."""
    req = MagicMock()
    req.query_params = query_params or {}
    req.session = {}
    req.headers = {}
    req.client = MagicMock()
    req.client.host = "127.0.0.1"
    return req


# ── Tests: Template-Logik im Router ──────────────────────────────────────────

class TestTemplatePreFill:
    """Tests für die server-seitige Vorlagen-Vorausfüllung."""

    def test_explicit_template_id_loads_template(self, db, template):
        """GET /csrs/new?template_id=N füllt Felder aus der Vorlage."""
        from app.routers.csrs import csr_new
        import asyncio

        req = _make_request(query_params={"template_id": str(template.id)})

        with patch("app.routers.csrs.login_required") as mock_login, \
             patch("app.routers.csrs.get_accessible_customer_ids", return_value=None), \
             patch("app.routers.csrs.templates") as mock_tmpl:
            mock_login.return_value = MagicMock(is_admin=True)
            mock_tmpl.TemplateResponse.return_value = MagicMock()

            asyncio.get_event_loop().run_until_complete(csr_new(req, db))

            call_kwargs = mock_tmpl.TemplateResponse.call_args[0][1]
            assert call_kwargs["selected_template_id"] == template.id
            form = call_kwargs["form"]
            assert form["country"] == "DE"
            assert form["state"] == "Bayern"
            assert form["locality"] == "München"
            assert form["organization"] == "Muster GmbH"
            assert form["ou"] == "IT"
            assert form["key_size"] == 4096
            assert form["sans"] == "{cn}"

    def test_invalid_template_id_ignored(self, db, default_template):
        """GET /csrs/new?template_id=abc → kein Fehler, fällt auf Standard zurück."""
        from app.routers.csrs import csr_new
        import asyncio

        req = _make_request(query_params={"template_id": "abc"})

        with patch("app.routers.csrs.login_required") as mock_login, \
             patch("app.routers.csrs.get_accessible_customer_ids", return_value=None), \
             patch("app.routers.csrs.templates") as mock_tmpl:
            mock_login.return_value = MagicMock(is_admin=True)
            mock_tmpl.TemplateResponse.return_value = MagicMock()

            asyncio.get_event_loop().run_until_complete(csr_new(req, db))

            call_kwargs = mock_tmpl.TemplateResponse.call_args[0][1]
            # Fällt auf Standardvorlage zurück
            assert call_kwargs["selected_template_id"] == default_template.id

    def test_nonexistent_template_id_falls_back_to_default(self, db, default_template):
        """GET /csrs/new?template_id=99999 → fällt auf Standardvorlage zurück."""
        from app.routers.csrs import csr_new
        import asyncio

        req = _make_request(query_params={"template_id": "99999"})

        with patch("app.routers.csrs.login_required") as mock_login, \
             patch("app.routers.csrs.get_accessible_customer_ids", return_value=None), \
             patch("app.routers.csrs.templates") as mock_tmpl:
            mock_login.return_value = MagicMock(is_admin=True)
            mock_tmpl.TemplateResponse.return_value = MagicMock()

            asyncio.get_event_loop().run_until_complete(csr_new(req, db))

            call_kwargs = mock_tmpl.TemplateResponse.call_args[0][1]
            assert call_kwargs["selected_template_id"] == default_template.id
            assert call_kwargs["form"]["country"] == "AT"

    def test_default_template_auto_applied(self, db, default_template):
        """Ohne template_id wird die Standardvorlage automatisch angewendet."""
        from app.routers.csrs import csr_new
        import asyncio

        req = _make_request(query_params={})

        with patch("app.routers.csrs.login_required") as mock_login, \
             patch("app.routers.csrs.get_accessible_customer_ids", return_value=None), \
             patch("app.routers.csrs.templates") as mock_tmpl:
            mock_login.return_value = MagicMock(is_admin=True)
            mock_tmpl.TemplateResponse.return_value = MagicMock()

            asyncio.get_event_loop().run_until_complete(csr_new(req, db))

            call_kwargs = mock_tmpl.TemplateResponse.call_args[0][1]
            assert call_kwargs["selected_template_id"] == default_template.id
            assert call_kwargs["form"]["organization"] == "Default Org"

    def test_customer_id_query_param_prefilled(self, db, template):
        """GET /csrs/new?template_id=N&customer_id=5 → form.customer_id gesetzt."""
        from app.routers.csrs import csr_new
        import asyncio

        req = _make_request(query_params={
            "template_id": str(template.id),
            "customer_id": "5",
        })

        with patch("app.routers.csrs.login_required") as mock_login, \
             patch("app.routers.csrs.get_accessible_customer_ids", return_value=None), \
             patch("app.routers.csrs.templates") as mock_tmpl:
            mock_login.return_value = MagicMock(is_admin=True)
            mock_tmpl.TemplateResponse.return_value = MagicMock()

            asyncio.get_event_loop().run_until_complete(csr_new(req, db))

            call_kwargs = mock_tmpl.TemplateResponse.call_args[0][1]
            assert call_kwargs["form"]["customer_id"] == "5"

    def test_no_templates_no_prefill(self, db):
        """Ohne Vorlagen in der DB: leeres Formular, kein Fehler."""
        from app.routers.csrs import csr_new
        import asyncio

        # Separaten leeren DB-Mock verwenden
        empty_db = MagicMock()
        empty_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = []
        empty_db.query.return_value.order_by.return_value.all.return_value = []

        req = _make_request(query_params={})

        with patch("app.routers.csrs.login_required") as mock_login, \
             patch("app.routers.csrs.get_accessible_customer_ids", return_value=None), \
             patch("app.routers.csrs.templates") as mock_tmpl:
            mock_login.return_value = MagicMock(is_admin=True)
            mock_tmpl.TemplateResponse.return_value = MagicMock()

            asyncio.get_event_loop().run_until_complete(csr_new(req, empty_db))

            call_kwargs = mock_tmpl.TemplateResponse.call_args[0][1]
            assert call_kwargs["selected_template_id"] is None
            assert call_kwargs["form"] == {}


# ── Tests: Template-API ───────────────────────────────────────────────────────

class TestTemplatesApi:
    """Tests für /csrtemplates/api/list."""

    def test_api_returns_all_templates(self, db, template, admin_user):
        from app.routers.csrtemplates import templates_api
        import asyncio

        req = _make_request()

        with patch("app.routers.csrtemplates.login_required") as mock_login:
            mock_login.return_value = MagicMock(is_admin=True)

            result = asyncio.get_event_loop().run_until_complete(templates_api(req, db))

        import json
        data = json.loads(result.body)
        ids = [t["id"] for t in data]
        assert template.id in ids

        # Prüfe Felder einer Vorlage
        tmpl_data = next(t for t in data if t["id"] == template.id)
        assert tmpl_data["country"] == "DE"
        assert tmpl_data["organization"] == "Muster GmbH"
        assert tmpl_data["key_size"] == 4096
        assert tmpl_data["san_pattern"] == "{cn}"

    def test_api_unauthenticated_returns_401(self, db):
        from app.routers.csrtemplates import templates_api
        from fastapi.responses import RedirectResponse
        import asyncio

        req = _make_request()

        with patch("app.routers.csrtemplates.login_required") as mock_login:
            mock_login.return_value = RedirectResponse(url="/login")

            result = asyncio.get_event_loop().run_until_complete(templates_api(req, db))

        assert result.status_code == 401
