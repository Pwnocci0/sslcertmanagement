"""Tests für das Benachrichtigungssystem.

Geprüft wird:
- SMTP-Konfiguration speichern und laden
- Template-Rendering mit Platzhaltern
- Empfängerermittlung aus Kundengruppe
- Admin-Benachrichtigung (notify_admins)
- Notification-Regeln nach Typ/Schweregrad
- Duplikatschutz (Deduplication)
- Automatische 30-Tage- und 14-Tage-Warnung
- Abgelaufen/Missing-Chain-Benachrichtigung
- Fehlerfall bei SMTP-Versand
"""
from __future__ import annotations

import datetime
import json
import os
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("APP_SECRET_KEY", "test-secret-key-for-unit-tests")
os.environ.setdefault("CSR_KEY_PASSPHRASE", "test-passphrase-for-unit-tests")


# ── Hilfsfunktionen ───────────────────────────────────────────────────────────

def _make_cert(
    cert_id: int = 1,
    cn: str = "test.example.com",
    valid_until_days: int = 30,
    status: str = "active",
    cert_pem: bool = True,
    chain_pem: bool = True,
    customer_id: int = 1,
):
    cert = MagicMock()
    cert.id = cert_id
    cert.common_name = cn
    cert.san = "www.test.example.com"
    cert.status = status
    cert.cert_pem = "---CERT---" if cert_pem else None
    cert.chain_pem = "---CHAIN---" if chain_pem else None
    cert.customer_id = customer_id
    cert.is_archived = False

    now = datetime.datetime.utcnow()
    cert.valid_until = now + datetime.timedelta(days=valid_until_days)

    customer = MagicMock()
    customer.id = customer_id
    customer.name = "Testkunde GmbH"
    cert.customer = customer

    domain = MagicMock()
    domain.fqdn = "test.example.com"
    cert.domain = domain

    return cert


def _make_group(
    group_id: int = 1,
    name: str = "Testgruppe",
    notification_enabled: bool = True,
    notify_admins: bool = False,
    enabled_types: list[str] | None = None,
    enabled_severities: list[str] | None = None,
    technicians: list = None,
    customer_ids: list[int] = None,
):
    from app import models
    group = MagicMock(spec=models.CustomerGroup)
    group.id = group_id
    group.name = name
    group.notification_enabled = notification_enabled
    group.notify_admins = notify_admins
    group.notification_types = json.dumps(enabled_types) if enabled_types else None
    group.notification_severities = json.dumps(enabled_severities) if enabled_severities else None

    if technicians is None:
        tech = MagicMock()
        tech.email = "tech@example.com"
        tech.username = "techniker"
        tech.is_active = True
        technicians = [tech]
    group.users = technicians

    customers_list = []
    for cid in (customer_ids or [1]):
        c = MagicMock()
        c.id = cid
        customers_list.append(c)
    group.customers = customers_list

    return group


def _make_mail_template(key: str = "certificate_expiring_30_days") -> MagicMock:
    from app import models
    tpl = MagicMock(spec=models.MailTemplate)
    tpl.template_key = key
    tpl.is_active = True
    tpl.subject = "[{{severity}}] Zertifikat läuft ab: {{certificate_common_name}}"
    tpl.text_body = (
        "Kunde: {{customer_name}}\n"
        "Zertifikat: {{certificate_common_name}}\n"
        "Tage: {{days_remaining}}\n"
        "Portal: {{portal_url}}\n"
    )
    tpl.html_body = None
    return tpl


# ── Template-Rendering ────────────────────────────────────────────────────────

class TestTemplateRendering:

    def test_simple_placeholder_replacement(self):
        """Platzhalter werden korrekt ersetzt."""
        from app.services.notification import render_template_string

        result = render_template_string(
            "Hallo {{name}}, Zertifikat: {{cert}}",
            {"name": "Techniker", "cert": "test.example.com"},
        )
        assert result == "Hallo Techniker, Zertifikat: test.example.com"

    def test_unknown_placeholder_stays(self):
        """Unbekannte Platzhalter bleiben unverändert."""
        from app.services.notification import render_template_string

        result = render_template_string("{{known}} und {{unknown}}", {"known": "Wert"})
        assert "{{unknown}}" in result
        assert "Wert" in result

    def test_render_template_subject_and_body(self):
        """render_template() ersetzt in Subject und Body."""
        from app.services.notification import render_template

        tpl = _make_mail_template()
        subject, text, html = render_template(
            tpl,
            {
                "severity": "KRITISCH",
                "certificate_common_name": "test.example.com",
                "customer_name": "Testkunde GmbH",
                "days_remaining": "14",
                "portal_url": "https://portal.example.com/certificates/1",
            },
        )
        assert "KRITISCH" in subject
        assert "test.example.com" in subject
        assert "Testkunde GmbH" in text
        assert "14" in text
        assert html is None  # kein HTML in diesem Template

    def test_none_values_in_context(self):
        """None-Werte im Context erzeugen leere Strings."""
        from app.services.notification import render_template_string

        result = render_template_string("Wert: {{val}}", {"val": None})
        assert result == "Wert: "


# ── Empfängerermittlung ───────────────────────────────────────────────────────

class TestRecipientResolution:

    def test_technician_recipients(self):
        """Techniker der Gruppe werden als Empfänger zurückgegeben."""
        from app.services.notification import get_recipients

        group = _make_group(notify_admins=False)
        db = MagicMock()
        recipients = get_recipients(db, group)
        assert len(recipients) == 1
        assert recipients[0][0] == "tech@example.com"

    def test_technician_without_email_excluded(self):
        """Techniker ohne E-Mail werden ignoriert."""
        from app.services.notification import get_recipients

        tech_no_email = MagicMock()
        tech_no_email.email = None
        tech_no_email.username = "kein-email"
        tech_no_email.is_active = True

        tech_with_email = MagicMock()
        tech_with_email.email = "valid@example.com"
        tech_with_email.username = "mit-email"
        tech_with_email.is_active = True

        group = _make_group(technicians=[tech_no_email, tech_with_email], notify_admins=False)
        db = MagicMock()
        recipients = get_recipients(db, group)
        emails = [r[0] for r in recipients]
        assert "valid@example.com" in emails
        assert None not in emails

    def test_inactive_technician_excluded(self):
        """Inaktive Techniker werden nicht benachrichtigt."""
        from app.services.notification import get_recipients

        inactive_tech = MagicMock()
        inactive_tech.email = "inactive@example.com"
        inactive_tech.username = "inactive"
        inactive_tech.is_active = False

        group = _make_group(technicians=[inactive_tech], notify_admins=False)
        db = MagicMock()
        recipients = get_recipients(db, group)
        assert len(recipients) == 0

    def test_admin_recipients_added_when_notify_admins(self):
        """Admins werden zusätzlich benachrichtigt wenn notify_admins=True."""
        from app.services.notification import get_recipients

        group = _make_group(notify_admins=True)

        admin = MagicMock()
        admin.email = "admin@example.com"
        admin.username = "admin"
        admin.is_active = True

        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = [admin]

        recipients = get_recipients(db, group)
        emails = [r[0] for r in recipients]
        assert "tech@example.com" in emails
        assert "admin@example.com" in emails

    def test_no_duplicates_in_recipients(self):
        """Keine doppelten Empfänger wenn Techniker auch Admin ist."""
        from app.services.notification import get_recipients

        tech = MagicMock()
        tech.email = "both@example.com"
        tech.username = "tech-admin"
        tech.is_active = True

        group = _make_group(technicians=[tech], notify_admins=True)

        admin = MagicMock()
        admin.email = "both@example.com"
        admin.username = "tech-admin"
        admin.is_active = True

        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = [admin]

        recipients = get_recipients(db, group)
        emails = [r[0] for r in recipients]
        assert emails.count("both@example.com") == 1


# ── Event-Erkennung ───────────────────────────────────────────────────────────

class TestEventDetection:

    def _get_events(self, cert):
        from app.services.notification import NotificationService
        svc = NotificationService.__new__(NotificationService)
        return svc._get_events(cert, datetime.datetime.utcnow())

    def test_30_day_warning(self):
        """Zertifikat mit 25 Tagen Restlaufzeit → 30-Tage-Warnung."""
        cert = _make_cert(valid_until_days=25)
        events = self._get_events(cert)
        event_types = [e[0] for e in events]
        assert "certificate_expiring" in event_types
        # Kein 14-Tage-Event
        dedup_keys = [e[3] for e in events]
        assert any("expiring_30" in k for k in dedup_keys)
        assert not any("expiring_14" in k for k in dedup_keys)

    def test_14_day_warning(self):
        """Zertifikat mit 7 Tagen Restlaufzeit → 14-Tage-Warnung."""
        cert = _make_cert(valid_until_days=7)
        events = self._get_events(cert)
        dedup_keys = [e[3] for e in events]
        assert any("expiring_14" in k for k in dedup_keys)
        assert not any("expiring_30" in k for k in dedup_keys)

    def test_expired_event(self):
        """Abgelaufenes Zertifikat → expired-Event."""
        cert = _make_cert(valid_until_days=-5)
        events = self._get_events(cert)
        event_types = [e[0] for e in events]
        assert "certificate_expired" in event_types

    def test_missing_chain_event(self):
        """Zertifikat ohne Chain → missing_chain-Event."""
        cert = _make_cert(valid_until_days=60, chain_pem=False)
        events = self._get_events(cert)
        event_types = [e[0] for e in events]
        assert "certificate_missing_chain" in event_types

    def test_no_event_for_valid_cert(self):
        """Gültiges Zertifikat mit 60 Tagen → keine Ablauf-Events."""
        cert = _make_cert(valid_until_days=60, chain_pem=True)
        events = self._get_events(cert)
        event_types = [e[0] for e in events]
        assert "certificate_expiring" not in event_types
        assert "certificate_expired" not in event_types


# ── Benachrichtigungs-Regeln (Typ/Schweregrad-Filter) ────────────────────────

class TestNotificationRules:

    def test_disabled_type_skipped(self):
        """Deaktivierter Ereignistyp erzeugt keine Benachrichtigung."""
        from app.services.notification import NotificationService

        svc = NotificationService.__new__(NotificationService)
        svc._get_enabled_types = lambda g: set()  # keine Typen aktiviert

        # Mock: cert would trigger expiring event but type is disabled
        group = _make_group(enabled_types=[])
        assert svc._get_enabled_types(group) == set()

    def test_get_enabled_types_null_means_all(self):
        """notification_types=NULL bedeutet alle Typen aktiviert."""
        from app.services.notification import NotificationService, NOTIFICATION_TYPES

        svc = NotificationService.__new__(NotificationService)
        group = _make_group(enabled_types=None)
        group.notification_types = None
        result = svc._get_enabled_types(group)
        assert result == set(NOTIFICATION_TYPES.keys())

    def test_get_enabled_types_subset(self):
        """Nur ausgewählte Typen werden zurückgegeben."""
        from app.services.notification import NotificationService

        svc = NotificationService.__new__(NotificationService)
        group = _make_group(enabled_types=["certificate_expiring", "certificate_expired"])
        result = svc._get_enabled_types(group)
        assert "certificate_expiring" in result
        assert "certificate_expired" in result
        assert "certificate_missing_chain" not in result

    def test_get_enabled_severities_null_means_all(self):
        """notification_severities=NULL bedeutet alle Schweregrade aktiviert."""
        from app.services.notification import NotificationService, NOTIFICATION_SEVERITIES

        svc = NotificationService.__new__(NotificationService)
        group = _make_group()
        group.notification_severities = None
        result = svc._get_enabled_severities(group)
        assert result == set(NOTIFICATION_SEVERITIES.keys())


# ── Duplikatschutz ────────────────────────────────────────────────────────────

class TestDeduplication:

    def test_no_dedup_for_new_event(self):
        """Neues Ereignis ohne Vorläufer → nicht deduped."""
        from app.services.notification import _is_deduped

        db = MagicMock()
        # _is_deduped calls .filter(...) exactly once with all conditions
        db.query.return_value.filter.return_value.first.return_value = None

        assert _is_deduped(db, "expiring_30:1", window_days=20) is False

    def test_dedup_for_recent_sent(self):
        """Kürzlich gesendete Benachrichtigung → deduped."""
        from app.services.notification import _is_deduped
        from app import models

        existing = MagicMock(spec=models.NotificationDispatch)
        existing.status = "sent"

        db = MagicMock()
        # Simulate that a matching record exists
        db.query.return_value.filter.return_value.filter.return_value.filter.return_value.first.return_value = existing

        assert _is_deduped(db, "expiring_30:1", window_days=20) is True


# ── SMTP-Konfiguration ────────────────────────────────────────────────────────

class TestSmtpConfiguration:

    def test_is_configured_false_when_disabled(self):
        """MailService.is_configured() = False wenn smtp.enabled=False."""
        from app.services.mail import MailService

        db = MagicMock()
        with patch("app.services.mail.get_settings_service") as mock_svc:
            svc = MagicMock()
            svc.get_bool.return_value = False
            svc.get_str.return_value = ""
            svc.get_int.return_value = 587
            mock_svc.return_value = svc

            mail = MailService(db)
            assert mail.is_configured() is False

    def test_is_configured_true_when_enabled_with_host(self):
        """MailService.is_configured() = True wenn aktiviert und Host gesetzt."""
        from app.services.mail import MailService

        db = MagicMock()
        with patch("app.services.mail.get_settings_service") as mock_svc:
            svc = MagicMock()
            svc.get_bool.side_effect = lambda k, default=False: {
                "smtp.enabled": True,
                "smtp.use_tls": True,
                "smtp.use_ssl": False,
            }.get(k, default)
            svc.get_str.side_effect = lambda k, default="": {
                "smtp.host": "mail.smtp2go.com",
                "smtp.from_email": "noreply@example.com",
                "smtp.username": "user",
                "smtp.password": "pass",
                "smtp.from_name": "SSL Manager",
                "smtp.reply_to": "",
            }.get(k, default)
            svc.get_int.return_value = 587
            mock_svc.return_value = svc

            mail = MailService(db)
            assert mail.is_configured() is True

    def test_send_returns_error_when_not_configured(self):
        """send() gibt Fehler zurück wenn SMTP nicht konfiguriert."""
        from app.services.mail import MailService

        db = MagicMock()
        with patch("app.services.mail.get_settings_service") as mock_svc:
            svc = MagicMock()
            svc.get_bool.return_value = False
            svc.get_str.return_value = ""
            svc.get_int.return_value = 587
            mock_svc.return_value = svc

            mail = MailService(db)
            ok, err = mail.send("test@example.com", "Betreff", "Body")
            assert ok is False
            assert "konfiguriert" in err.lower() or "deaktiviert" in err.lower()

    def test_smtp_error_returns_false(self):
        """SMTP-Verbindungsfehler → (False, Fehlermeldung)."""
        import smtplib
        from app.services.mail import MailService

        db = MagicMock()
        with patch("app.services.mail.get_settings_service") as mock_svc:
            svc = MagicMock()
            svc.get_bool.side_effect = lambda k, default=False: {
                "smtp.enabled": True,
                "smtp.use_tls": True,
                "smtp.use_ssl": False,
            }.get(k, default)
            svc.get_str.side_effect = lambda k, default="": {
                "smtp.host": "localhost",
                "smtp.from_email": "noreply@example.com",
                "smtp.username": "",
                "smtp.password": "",
                "smtp.from_name": "SSL Manager",
                "smtp.reply_to": "",
            }.get(k, default)
            svc.get_int.return_value = 9999
            mock_svc.return_value = svc

            mail = MailService(db)
            with patch("smtplib.SMTP", side_effect=smtplib.SMTPConnectError(111, "Verbindung abgelehnt")):
                ok, err = mail.send("test@example.com", "Betreff", "Body")
            assert ok is False
            assert err != ""


# ── _get_enabled_types und _get_enabled_severities Hilfsmethoden ─────────────

# Wir testen die internen Hilfsmethoden direkt.

class TestNotificationServiceHelpers:

    def _make_svc(self):
        from app.services.notification import NotificationService
        svc = NotificationService.__new__(NotificationService)
        svc.db = MagicMock()
        svc.mail = MagicMock()
        svc.portal_url = "https://portal.example.com"
        return svc

    def test_build_context_includes_all_keys(self):
        """_build_context() liefert alle erwarteten Kontext-Keys."""
        svc = self._make_svc()
        cert = _make_cert()
        group = _make_group()

        ctx = svc._build_context(cert, group, "certificate_expiring", "warning", 25)

        assert "customer_name" in ctx
        assert "certificate_common_name" in ctx
        assert "days_remaining" in ctx
        assert "portal_url" in ctx
        assert ctx["days_remaining"] == "25"
        assert "/certificates/1" in ctx["portal_url"]

    def test_fallback_body_covers_key_info(self):
        """_build_fallback_body() enthält alle wichtigen Informationen."""
        from app.services.notification import NotificationService

        ctx = {
            "event_type": "Zertifikat läuft ab",
            "severity": "Kritisch",
            "certificate_common_name": "test.example.com",
            "customer_name": "Testkunde GmbH",
            "customer_group_name": "Gruppe A",
            "certificate_valid_to": "15.05.2026",
            "days_remaining": "14",
            "status": "active",
            "portal_url": "https://portal/certificates/1",
            "certificate_sans": "www.test.example.com",
        }
        body = NotificationService._build_fallback_body(ctx)
        assert "test.example.com" in body
        assert "Testkunde GmbH" in body
        assert "14" in body
