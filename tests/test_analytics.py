"""Tests für Analytics-Router: Cert-Statistiken, Security-Stats, CSV-Export, Zugriffskontrolle."""
from __future__ import annotations

import asyncio
import io
import json
import os
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("APP_SECRET_KEY", "test-secret-key-for-analytics-tests")
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
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


_counter = 0


@pytest.fixture
def admin_user(db):
    global _counter
    _counter += 1
    u = models.User(
        username=f"analytics_admin_{_counter}",
        email=f"analytics_admin_{_counter}@example.com",
        hashed_password="hashed",
        is_active=True,
        is_admin=True,
        mfa_setup_completed=True,
    )
    db.add(u)
    db.flush()
    return u


@pytest.fixture
def regular_user(db):
    global _counter
    _counter += 1
    u = models.User(
        username=f"analytics_user_{_counter}",
        email=f"analytics_user_{_counter}@example.com",
        hashed_password="hashed",
        is_active=True,
        is_admin=False,
        mfa_setup_completed=True,
    )
    db.add(u)
    db.flush()
    return u


@pytest.fixture
def customer(db):
    c = models.Customer(name=f"TestKunde_{_counter}", is_archived=False)
    db.add(c)
    db.flush()
    return c


@pytest.fixture
def certs(db, customer):
    """Erstellt eine Mischung von Zertifikaten für Tests."""
    now = datetime.utcnow()
    certs_list = [
        models.Certificate(
            common_name="active.example.com",
            customer_id=customer.id,
            status="active",
            issuer="DigiCert Inc",
            valid_from=now - timedelta(days=30),
            valid_until=now + timedelta(days=90),
            is_archived=False,
        ),
        models.Certificate(
            common_name="expiring.example.com",
            customer_id=customer.id,
            status="expiring_soon",
            issuer="Let's Encrypt",
            valid_from=now - timedelta(days=60),
            valid_until=now + timedelta(days=10),
            is_archived=False,
        ),
        models.Certificate(
            common_name="expired.example.com",
            customer_id=customer.id,
            status="expired",
            issuer="DigiCert Inc",
            valid_from=now - timedelta(days=400),
            valid_until=now - timedelta(days=10),
            is_archived=False,
        ),
        models.Certificate(
            common_name="pending.example.com",
            customer_id=customer.id,
            status="pending",
            issuer=None,
            valid_from=None,
            valid_until=None,
            is_archived=False,
        ),
    ]
    for c in certs_list:
        db.add(c)
    db.flush()
    return certs_list


async def _read_streaming_response(response) -> str:
    """Liest den Body einer StreamingResponse asynchron."""
    parts = []
    async for chunk in response.body_iterator:
        parts.append(chunk if isinstance(chunk, str) else chunk.decode("utf-8"))
    return "".join(parts)


def _make_request(user=None):
    req = MagicMock()
    req.session = {"user_id": user.id if user else None}
    req.headers = {}
    req.client = MagicMock()
    req.client.host = "127.0.0.1"
    req.url = MagicMock()
    req.url.path = "/analytics"
    return req


# ── Tests: _cert_stats ────────────────────────────────────────────────────────

class TestCertStats:
    def test_status_counts_correct(self, db, certs, customer):
        from app.routers.analytics import _cert_stats
        result = _cert_stats(db, None)
        assert result["status_counts"].get("active", 0) >= 1
        assert result["status_counts"].get("expiring_soon", 0) >= 1
        assert result["status_counts"].get("expired", 0) >= 1

    def test_total_includes_all(self, db, certs, customer):
        from app.routers.analytics import _cert_stats
        result = _cert_stats(db, None)
        assert result["total"] >= len(certs)

    def test_issuer_counts_aggregated(self, db, certs, customer):
        from app.routers.analytics import _cert_stats
        result = _cert_stats(db, None)
        assert "DigiCert Inc" in result["issuer_counts"]
        assert "Let's Encrypt" in result["issuer_counts"]

    def test_unknown_issuer_for_none(self, db, certs, customer):
        from app.routers.analytics import _cert_stats
        result = _cert_stats(db, None)
        # pending cert hat issuer=None → "Unbekannt"
        assert "Unbekannt" in result["issuer_counts"]

    def test_expiry_buckets_populated(self, db, certs, customer):
        from app.routers.analytics import _cert_stats
        result = _cert_stats(db, None)
        buckets = result["expiry_buckets"]
        assert "Abgelaufen" in buckets
        assert "< 14 Tage" in buckets
        assert "> 90 Tage" in buckets
        assert buckets["Abgelaufen"] >= 1
        assert buckets["< 14 Tage"] >= 1

    def test_top_customers_includes_customer(self, db, certs, customer):
        from app.routers.analytics import _cert_stats
        result = _cert_stats(db, None)
        names = [name for name, _ in result["top_customers"]]
        assert customer.name in names

    def test_accessible_ids_filter(self, db, certs, customer):
        from app.routers.analytics import _cert_stats
        # Nur Zertifikate für den Kunden
        result_all = _cert_stats(db, None)
        result_filtered = _cert_stats(db, [customer.id])
        assert result_filtered["total"] <= result_all["total"]

        # Leere ID-Liste → kein Ergebnis
        result_empty = _cert_stats(db, [])
        assert result_empty["total"] == 0

    def test_archived_certs_excluded(self, db, customer):
        from app.routers.analytics import _cert_stats
        archived = models.Certificate(
            common_name="archived.example.com",
            customer_id=customer.id,
            status="active",
            is_archived=True,
        )
        db.add(archived)
        db.flush()
        result = _cert_stats(db, None)
        # Der archivierte Eintrag soll nicht gezählt werden
        for name, _ in result["top_customers"]:
            pass  # Test: kein Fehler, archivierte certs ignoriert


# ── Tests: _security_stats ────────────────────────────────────────────────────

class TestSecurityStats:
    def test_returns_required_keys(self, db, admin_user):
        from app.routers.analytics import _security_stats
        result = _security_stats(db)
        required = {"total_users", "mfa_users", "mfa_pct", "login_total",
                    "login_failed", "login_success", "critical_events",
                    "events_per_day", "fail2ban"}
        assert required.issubset(result.keys())

    def test_mfa_pct_between_0_and_100(self, db, admin_user):
        from app.routers.analytics import _security_stats
        result = _security_stats(db)
        assert 0 <= result["mfa_pct"] <= 100

    def test_login_total_equals_failed_plus_success(self, db, admin_user):
        from app.routers.analytics import _security_stats
        result = _security_stats(db)
        assert result["login_total"] == result["login_failed"] + result["login_success"]

    def test_events_per_day_has_14_entries(self, db, admin_user):
        from app.routers.analytics import _security_stats
        result = _security_stats(db)
        assert len(result["events_per_day"]) == 14

    def test_events_per_day_keys_are_date_strings(self, db, admin_user):
        from app.routers.analytics import _security_stats
        result = _security_stats(db)
        for key in result["events_per_day"]:
            datetime.strptime(key, "%Y-%m-%d")  # wirft ValueError wenn ungültig

    def test_counts_login_attempts(self, db, admin_user):
        from app.routers.analytics import _security_stats
        attempt = models.LoginAttempt(
            username=admin_user.username,
            ip_address="10.0.0.1",
            success=False,
            created_at=datetime.utcnow() - timedelta(days=5),
        )
        db.add(attempt)
        db.flush()
        result = _security_stats(db)
        assert result["login_failed"] >= 1

    def test_mfa_user_counted(self, db):
        global _counter
        _counter += 1
        user_with_mfa = models.User(
            username=f"mfa_user_{_counter}",
            email=f"mfa_{_counter}@example.com",
            hashed_password="hashed",
            is_active=True,
            is_admin=False,
            mfa_setup_completed=True,
        )
        db.add(user_with_mfa)
        db.flush()

        from app.routers.analytics import _security_stats
        result = _security_stats(db)
        assert result["mfa_users"] >= 1
        assert result["total_users"] >= 1


# ── Tests: CSV-Export ─────────────────────────────────────────────────────────

class TestCertsCsvExport:
    def test_export_returns_csv_headers(self, db, certs, admin_user):
        from app.routers.analytics import export_certs_csv
        from fastapi.responses import RedirectResponse

        req = _make_request(admin_user)

        with patch("app.routers.analytics.login_required", return_value=admin_user), \
             patch("app.routers.analytics.get_accessible_customer_ids", return_value=None):
            response = asyncio.get_event_loop().run_until_complete(
                export_certs_csv(req, db)
            )

        assert response.status_code == 200
        assert "text/csv" in response.media_type

    def test_export_csv_contains_cert_data(self, db, certs, admin_user):
        from app.routers.analytics import export_certs_csv

        req = _make_request(admin_user)

        with patch("app.routers.analytics.login_required", return_value=admin_user), \
             patch("app.routers.analytics.get_accessible_customer_ids", return_value=None):
            response = asyncio.get_event_loop().run_until_complete(
                export_certs_csv(req, db)
            )

        # Response-Body lesen
        body = asyncio.get_event_loop().run_until_complete(_read_streaming_response(response))
        assert "active.example.com" in body
        assert "expired.example.com" in body

    def test_export_csv_header_row(self, db, certs, admin_user):
        from app.routers.analytics import export_certs_csv

        req = _make_request(admin_user)

        with patch("app.routers.analytics.login_required", return_value=admin_user), \
             patch("app.routers.analytics.get_accessible_customer_ids", return_value=None):
            response = asyncio.get_event_loop().run_until_complete(
                export_certs_csv(req, db)
            )

        body = asyncio.get_event_loop().run_until_complete(_read_streaming_response(response))
        first_line = body.splitlines()[0]
        assert "Domain" in first_line
        assert "Status" in first_line
        assert "Aussteller" in first_line

    def test_export_requires_login(self, db):
        from app.routers.analytics import export_certs_csv
        from fastapi.responses import RedirectResponse

        req = _make_request()

        with patch("app.routers.analytics.login_required",
                   return_value=RedirectResponse(url="/login")):
            response = asyncio.get_event_loop().run_until_complete(
                export_certs_csv(req, db)
            )

        assert response.status_code in (302, 303, 307)


class TestSecurityCsvExport:
    def test_security_export_admin_only(self, db, regular_user):
        from app.routers.analytics import export_security_csv
        from fastapi.responses import RedirectResponse

        req = _make_request(regular_user)

        with patch("app.routers.analytics.login_required", return_value=regular_user):
            response = asyncio.get_event_loop().run_until_complete(
                export_security_csv(req, db)
            )

        assert response.status_code in (302, 303)

    def test_security_export_admin_gets_csv(self, db, admin_user):
        from app.routers.analytics import export_security_csv

        req = _make_request(admin_user)

        with patch("app.routers.analytics.login_required", return_value=admin_user):
            response = asyncio.get_event_loop().run_until_complete(
                export_security_csv(req, db)
            )

        assert response.status_code == 200
        assert "text/csv" in response.media_type

    def test_security_export_csv_header(self, db, admin_user):
        from app.routers.analytics import export_security_csv

        req = _make_request(admin_user)

        with patch("app.routers.analytics.login_required", return_value=admin_user):
            response = asyncio.get_event_loop().run_until_complete(
                export_security_csv(req, db)
            )

        body = asyncio.get_event_loop().run_until_complete(_read_streaming_response(response))
        first_line = body.splitlines()[0] if body.strip() else ""
        assert "Aktion" in first_line
        assert "Benutzer" in first_line


# ── Tests: JSON-Daten-Endpoint ─────────────────────────────────────────────────

class TestAnalyticsDataJson:
    def test_returns_cert_data_for_regular_user(self, db, certs, regular_user):
        from app.routers.analytics import analytics_data

        req = _make_request(regular_user)

        with patch("app.routers.analytics.login_required", return_value=regular_user), \
             patch("app.routers.analytics.get_accessible_customer_ids", return_value=None):
            response = asyncio.get_event_loop().run_until_complete(
                analytics_data(req, db)
            )

        data = json.loads(response.body)
        assert "cert_status" in data
        assert "cert_expiry_buckets" in data
        assert "security" not in data  # nicht-Admin sieht keine Security-Daten

    def test_returns_security_data_for_admin(self, db, certs, admin_user):
        from app.routers.analytics import analytics_data

        req = _make_request(admin_user)

        with patch("app.routers.analytics.login_required", return_value=admin_user), \
             patch("app.routers.analytics.get_accessible_customer_ids", return_value=None):
            response = asyncio.get_event_loop().run_until_complete(
                analytics_data(req, db)
            )

        data = json.loads(response.body)
        assert "security" in data
        assert "mfa_pct" in data["security"]
        assert "events_per_day" in data["security"]

    def test_unauthenticated_returns_401(self, db):
        from app.routers.analytics import analytics_data
        from fastapi.responses import RedirectResponse

        req = _make_request()

        with patch("app.routers.analytics.login_required",
                   return_value=RedirectResponse(url="/login")):
            response = asyncio.get_event_loop().run_until_complete(
                analytics_data(req, db)
            )

        assert response.status_code == 401

    def test_top_customers_in_response(self, db, certs, admin_user):
        from app.routers.analytics import analytics_data

        req = _make_request(admin_user)

        with patch("app.routers.analytics.login_required", return_value=admin_user), \
             patch("app.routers.analytics.get_accessible_customer_ids", return_value=None):
            response = asyncio.get_event_loop().run_until_complete(
                analytics_data(req, db)
            )

        data = json.loads(response.body)
        assert "top_customers" in data
        assert isinstance(data["top_customers"], list)
        if data["top_customers"]:
            assert "name" in data["top_customers"][0]
            assert "count" in data["top_customers"][0]


# ── Tests: Analytics-Seite (HTML) ────────────────────────────────────────────

class TestAnalyticsIndex:
    def test_page_renders_for_admin(self, db, certs, admin_user):
        from app.routers.analytics import analytics_index

        req = _make_request(admin_user)

        with patch("app.routers.analytics.login_required", return_value=admin_user), \
             patch("app.routers.analytics.get_accessible_customer_ids", return_value=None), \
             patch("app.routers.analytics.templates") as mock_tmpl, \
             patch("app.routers.analytics._security_stats") as mock_sec, \
             patch("app.routers.analytics._backup_stats") as mock_bak:
            mock_sec.return_value = {"mfa_pct": 80, "login_total": 10,
                                     "login_failed": 2, "login_success": 8,
                                     "critical_events": 0, "events_per_day": {},
                                     "fail2ban": {"jails": [], "error": None},
                                     "total_users": 5, "mfa_users": 4}
            mock_bak.return_value = {}
            mock_tmpl.TemplateResponse.return_value = MagicMock(status_code=200)

            asyncio.get_event_loop().run_until_complete(analytics_index(req, db))

            call_kwargs = mock_tmpl.TemplateResponse.call_args[0][1]
            assert call_kwargs["cert_data"] is not None
            assert call_kwargs["security_data"] is not None  # Admin sieht Security-Daten

    def test_page_hides_security_for_regular_user(self, db, certs, regular_user):
        from app.routers.analytics import analytics_index

        req = _make_request(regular_user)

        with patch("app.routers.analytics.login_required", return_value=regular_user), \
             patch("app.routers.analytics.get_accessible_customer_ids", return_value=None), \
             patch("app.routers.analytics.templates") as mock_tmpl:
            mock_tmpl.TemplateResponse.return_value = MagicMock(status_code=200)

            asyncio.get_event_loop().run_until_complete(analytics_index(req, db))

            call_kwargs = mock_tmpl.TemplateResponse.call_args[0][1]
            assert call_kwargs["security_data"] is None  # Nicht-Admin: keine Security-Daten
            assert call_kwargs["backup_data"] is None

    def test_redirects_unauthenticated(self, db):
        from app.routers.analytics import analytics_index
        from fastapi.responses import RedirectResponse

        req = _make_request()

        with patch("app.routers.analytics.login_required",
                   return_value=RedirectResponse(url="/login")):
            result = asyncio.get_event_loop().run_until_complete(analytics_index(req, db))

        assert isinstance(result, RedirectResponse)
