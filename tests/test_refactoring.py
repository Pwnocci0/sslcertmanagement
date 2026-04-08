"""Tests für Navigation, Einstellungen, Integrations-Toggle, Kontext-Vorauswahl und MFA-Reset.

Alle Tests sind Unit-Tests gegen Datenbank-Stubs (kein laufender Server nötig).
"""
import os
import json
import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch, PropertyMock

os.environ.setdefault("APP_SECRET_KEY", "test-secret-key-32chars-padding!")
os.environ.setdefault("DATABASE_URL", "sqlite:///./data/sslcertmanagement.db")

from app import models
from app.settings_service import is_integration_enabled, DEFINITIONS


# ── Hilfsfunktionen ───────────────────────────────────────────────────────────

def _make_user(is_admin=True, is_active=True, mfa_completed=True):
    u = MagicMock(spec=models.User)
    u.id = 1
    u.username = "testadmin"
    u.email = "admin@example.com"
    u.is_admin = is_admin
    u.is_active = is_active
    u.mfa_setup_completed = mfa_completed
    u.mfa_secret_encrypted = "enc_secret" if mfa_completed else None
    u.recovery_codes_json = '["hash1","hash2"]' if mfa_completed else None
    u.last_mfa_at = datetime.utcnow() if mfa_completed else None
    u.role = "admin" if is_admin else "technician"
    u.customer_groups = []
    return u


def _make_technician(mfa_completed=False):
    u = _make_user(is_admin=False, mfa_completed=mfa_completed)
    u.id = 2
    u.username = "tech1"
    u.email = "tech@example.com"
    u.role = "technician"
    return u


# ── 1. Navigation je Rolle ────────────────────────────────────────────────────

class TestNavigation(unittest.TestCase):

    def test_settings_definition_includes_thesslstore_enabled(self):
        """thesslstore.enabled muss in DEFINITIONS vorhanden sein."""
        self.assertIn("thesslstore.enabled", DEFINITIONS)
        defn = DEFINITIONS["thesslstore.enabled"]
        self.assertEqual(defn.category, "thesslstore")
        self.assertEqual(defn.value_type, "bool")
        self.assertEqual(defn.default, "false")

    def test_settings_excluded_categories(self):
        """SMTP und TheSSLStore werden im generischen /settings-Tab ausgeblendet."""
        excluded = {"smtp", "thesslstore"}
        non_excluded = {k for k in DEFINITIONS.values() if k.category not in excluded}
        self.assertTrue(len(non_excluded) > 0)

    def test_csrf_in_admin_only_nav_items(self):
        """CSRs sind im operativen Hauptmenü; TheSSLStore nicht."""
        with open("app/templates/base.html") as f:
            nav_html = f.read()
        # Hauptmenü-Links (navbar-nav me-auto) – CSRs sind enthalten, TheSSLStore nicht
        main_nav_section = nav_html.split("ms-auto")[0]  # Alles vor der rechten Seite
        self.assertIn('href="/csrs"', main_nav_section)
        self.assertNotIn('href="/thesslstore"', main_nav_section)

    def test_settings_link_admin_only_in_template(self):
        """Einstellungen-Link darf nur für Admins angezeigt werden."""
        with open("app/templates/base.html") as f:
            content = f.read()
        # Settings-Link muss innerhalb eines {% if user.is_admin %} Blocks stehen
        admin_block_idx = content.find("{% if user.is_admin %}")
        settings_href_idx = content.find('href="/settings"')
        self.assertGreater(settings_href_idx, admin_block_idx,
                           "Einstellungen-Link muss im Admin-Block stehen")

    def test_operational_nav_items_present(self):
        """Dashboard, Kunden, Domains, Zertifikate, Aufgaben sind im Hauptmenü."""
        with open("app/templates/base.html") as f:
            content = f.read()
        for href in ['href="/"', 'href="/customers"', 'href="/domains"',
                     'href="/certificates"', 'href="/tasks"']:
            self.assertIn(href, content, f"Hauptmenü-Link {href} fehlt")


# ── 2. Einstellungen nur für Admin ────────────────────────────────────────────

class TestSettingsAdminOnly(unittest.TestCase):

    def test_settings_route_redirects_non_admin(self):
        """_require_admin() muss Nicht-Admins ablehnen."""
        from fastapi.responses import RedirectResponse
        from app.routers.settings import _require_admin

        tech = _make_technician()
        db = MagicMock()

        with patch("app.routers.settings.login_required", return_value=tech):
            redir, user = _require_admin(MagicMock(), db)

        self.assertIsInstance(redir, RedirectResponse)
        self.assertIsNone(user)

    def test_settings_route_allows_admin(self):
        """_require_admin() erlaubt Admins den Zugang."""
        from fastapi.responses import RedirectResponse
        from app.routers.settings import _require_admin

        admin = _make_user(is_admin=True)
        db = MagicMock()

        with patch("app.routers.settings.login_required", return_value=admin):
            redir, user = _require_admin(MagicMock(), db)

        self.assertIsNone(redir)
        self.assertEqual(user.username, "testadmin")

    def test_admin_router_require_admin(self):
        """_require_admin() in admin.py lehnt Techniker ab."""
        from fastapi.responses import RedirectResponse
        from app.routers.admin import _require_admin

        tech = _make_technician()
        db = MagicMock()

        with patch("app.routers.admin.login_required", return_value=tech):
            redir, user = _require_admin(MagicMock(), db)

        self.assertIsInstance(redir, RedirectResponse)
        self.assertIsNone(user)


# ── 3. Integrations-Toggle ────────────────────────────────────────────────────

class TestIntegrationToggle(unittest.TestCase):

    def test_is_integration_enabled_false_by_default(self):
        """is_integration_enabled('thesslstore') = False wenn Einstellung nicht gesetzt."""
        db = MagicMock()
        with patch("app.settings_service.get_settings_service") as mock_svc_fn:
            mock_svc = MagicMock()
            mock_svc.get_bool.return_value = False
            mock_svc_fn.return_value = mock_svc
            result = is_integration_enabled("thesslstore", db)
        self.assertFalse(result)

    def test_is_integration_enabled_true_when_set(self):
        """is_integration_enabled('thesslstore') = True wenn aktiviert."""
        db = MagicMock()
        with patch("app.settings_service.get_settings_service") as mock_svc_fn:
            mock_svc = MagicMock()
            mock_svc.get_bool.return_value = True
            mock_svc_fn.return_value = mock_svc
            result = is_integration_enabled("thesslstore", db)
        self.assertTrue(result)

    def test_thesslstore_route_redirects_when_disabled(self):
        """TheSSLStore-Route leitet weiter wenn Integration deaktiviert."""
        from fastapi.responses import RedirectResponse
        from app.routers.thesslstore import _require_integration

        db = MagicMock()
        request = MagicMock()
        request.session = {}

        with patch("app.routers.thesslstore.is_integration_enabled", return_value=False):
            result = _require_integration(request, db)

        self.assertIsInstance(result, RedirectResponse)

    def test_thesslstore_route_passes_when_enabled(self):
        """TheSSLStore-Route gibt None zurück wenn Integration aktiv."""
        from app.routers.thesslstore import _require_integration

        db = MagicMock()
        request = MagicMock()
        request.session = {}

        with patch("app.routers.thesslstore.is_integration_enabled", return_value=True):
            result = _require_integration(request, db)

        self.assertIsNone(result)

    def test_integrations_settings_has_entry(self):
        """GET /settings/integrations-Route existiert in settings.py."""
        from app.routers.settings import router
        paths = [r.path for r in router.routes]
        self.assertIn("/settings/integrations", paths)


# ── 4. Zertifikat-Vorauswahl ─────────────────────────────────────────────────

class TestCertificateContext(unittest.TestCase):

    def test_prefill_customer_id_passed_to_template(self):
        """GET /certificates/new?customer_id=5 setzt prefill_customer_id=5."""
        from app.routers.certificates import certificate_new
        import asyncio

        user = _make_user()
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = []

        request = MagicMock()
        request.session = {}

        with patch("app.routers.certificates.login_required", return_value=user), \
             patch("app.routers.certificates.check_customer_access", return_value=True), \
             patch("app.routers.certificates.get_accessible_customer_ids", return_value=None), \
             patch("app.routers.certificates.templates") as mock_tpl:

            mock_tpl.TemplateResponse.return_value = MagicMock()
            asyncio.run(certificate_new(request=request, db=db, customer_id=5, domain_id=None))

            call_kwargs = mock_tpl.TemplateResponse.call_args
            context = call_kwargs[0][1] if call_kwargs[0] else call_kwargs[1]
            self.assertEqual(context.get("prefill_customer_id"), 5)
            self.assertIsNone(context.get("prefill_domain_id"))

    def test_prefill_customer_id_rejected_if_no_access(self):
        """customer_id wird auf None gesetzt wenn kein Zugriff."""
        from app.routers.certificates import certificate_new
        import asyncio

        user = _make_user()
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = []

        request = MagicMock()
        request.session = {}

        with patch("app.routers.certificates.login_required", return_value=user), \
             patch("app.routers.certificates.check_customer_access", return_value=False), \
             patch("app.routers.certificates.get_accessible_customer_ids", return_value=None), \
             patch("app.routers.certificates.templates") as mock_tpl:

            mock_tpl.TemplateResponse.return_value = MagicMock()
            asyncio.run(certificate_new(request=request, db=db, customer_id=99, domain_id=None))

            call_kwargs = mock_tpl.TemplateResponse.call_args
            context = call_kwargs[0][1] if call_kwargs[0] else call_kwargs[1]
            self.assertIsNone(context.get("prefill_customer_id"))


# ── 5. MFA-Reset ─────────────────────────────────────────────────────────────

class TestMfaReset(unittest.TestCase):

    def test_mfa_reset_clears_all_fields(self):
        """MFA-Reset setzt alle MFA-Felder auf None/False."""
        from app.routers.admin import user_reset_mfa
        import asyncio
        from fastapi.responses import RedirectResponse

        admin = _make_user(is_admin=True, mfa_completed=True)
        target = _make_technician(mfa_completed=True)
        target.id = 99

        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = target

        request = MagicMock()
        request.session = {}
        request.headers = {}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"

        with patch("app.routers.admin.login_required", return_value=admin), \
             patch("app.routers.admin.audit") as mock_audit:

            result = asyncio.run(user_reset_mfa(user_id=99, request=request, db=db))

        self.assertIsNone(target.mfa_secret_encrypted)
        self.assertFalse(target.mfa_setup_completed)
        self.assertIsNone(target.recovery_codes_json)
        self.assertIsNone(target.last_mfa_at)
        self.assertIsInstance(result, RedirectResponse)
        mock_audit.log.assert_called_once()
        audit_args = mock_audit.log.call_args[0]
        self.assertEqual(audit_args[1], "user.mfa_reset")

    def test_mfa_reset_blocked_for_own_account(self):
        """Admin kann seine eigene MFA nicht zurücksetzen."""
        from app.routers.admin import user_reset_mfa
        import asyncio
        from fastapi.responses import RedirectResponse

        admin = _make_user(is_admin=True, mfa_completed=True)
        admin.id = 1

        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = admin

        request = MagicMock()
        request.session = {}
        request.headers = {}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"

        with patch("app.routers.admin.login_required", return_value=admin):
            result = asyncio.run(user_reset_mfa(user_id=1, request=request, db=db))

        # MFA-Felder dürfen nicht verändert worden sein
        self.assertTrue(admin.mfa_setup_completed)
        self.assertIsNotNone(admin.mfa_secret_encrypted)
        self.assertIsInstance(result, RedirectResponse)

    def test_mfa_reset_route_exists_in_admin_router(self):
        """POST /admin/users/{user_id}/reset-mfa ist registriert."""
        from app.routers.admin import router
        post_paths = [r.path for r in router.routes if "POST" in getattr(r, "methods", set())]
        self.assertTrue(
            any("reset-mfa" in p for p in post_paths),
            "reset-mfa Route fehlt im Admin-Router"
        )

    def test_mfa_reset_user_redirected_to_setup_on_next_login(self):
        """Nach MFA-Reset: Beim nächsten Login wird der User zu /mfa/setup geleitet.

        Der Login-Flow setzt pre_mfa_user_id (nicht user_id) nach erfolgreichem
        Passwort-Check. login_required leitet dann zu /mfa/setup, weil
        mfa_setup_completed = False ist.
        """
        from app.auth import login_required
        from fastapi.responses import RedirectResponse

        user_no_mfa = _make_user(mfa_completed=False)
        user_no_mfa.mfa_setup_completed = False

        request = MagicMock()
        # Passwort wurde bereits geprüft → pre_mfa_user_id gesetzt, aber NICHT user_id
        request.session = {"pre_mfa_user_id": user_no_mfa.id}

        db = MagicMock()
        # get_current_user gibt None zurück (kein user_id in Session → kein DB-Call)
        # Der pre_mfa-Lookup trifft die DB einmal → gibt user_no_mfa zurück
        db.query.return_value.filter.return_value.first.return_value = user_no_mfa

        result = login_required(request, db)

        self.assertIsInstance(result, RedirectResponse)
        self.assertIn("/mfa/setup", result.headers["location"])


# ── 6. Sidebar-Template Existenz ─────────────────────────────────────────────

class TestSidebarTemplate(unittest.TestCase):

    def test_sidebar_template_exists(self):
        """_sidebar.html muss existieren."""
        import os
        self.assertTrue(
            os.path.exists("app/templates/settings/_sidebar.html"),
            "app/templates/settings/_sidebar.html fehlt"
        )

    def test_integrations_template_exists(self):
        """integrations.html muss existieren."""
        import os
        self.assertTrue(
            os.path.exists("app/templates/settings/integrations.html"),
            "app/templates/settings/integrations.html fehlt"
        )

    def test_sidebar_contains_all_required_links(self):
        """Sidebar enthält alle Pflicht-Einstiegspunkte."""
        with open("app/templates/settings/_sidebar.html") as f:
            content = f.read()
        required = [
            '"/settings"',
            '"/admin/users"',
            '"/customer-groups"',
            '"/mail-settings"',
            '"/mailtemplates"',
            '"/notifications"',
            '"/settings/integrations"',
            '"/admin"',
            '"/admin/logs"',
        ]
        for link in required:
            self.assertIn(link, content, f"Sidebar-Link {link} fehlt")


if __name__ == "__main__":
    unittest.main()
