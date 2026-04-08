"""Automatische Benachrichtigungslogik für Zertifikats-Events.

Wird vom Scheduler stündlich aufgerufen. Prüft alle Zertifikate in aktivierten
Kundengruppen auf Ablauf, Ungültigkeit etc. und versendet E-Mail-Benachrichtigungen.

Duplikatschutz: Jede Benachrichtigung bekommt einen dedup_key; innerhalb eines
konfigurierten Zeitfensters wird keine zweite Nachricht für dieselbe Kombination
aus Ereignis und Zertifikat verschickt.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from .. import models
from ..settings_service import get_settings_service
from .mail import MailService

logger = logging.getLogger(__name__)

# ── Konstanten (werden auch in Routers und Templates verwendet) ───────────────

NOTIFICATION_TYPES: dict[str, str] = {
    "certificate_expiring": "Zertifikat läuft ab",
    "certificate_expired": "Zertifikat abgelaufen",
    "certificate_invalid": "Zertifikat ungültig",
    "certificate_missing_chain": "Fehlende Chain",
    "certificate_status_warning": "Status-Warnung",
    "other_warning": "Sonstige Warnung",
}

NOTIFICATION_SEVERITIES: dict[str, str] = {
    "info": "Info",
    "warning": "Warnung",
    "critical": "Kritisch",
}

TEMPLATE_KEYS: dict[str, str] = {
    "certificate_expiring_30_days": "Zertifikat läuft in 30 Tagen ab",
    "certificate_expiring_14_days": "Zertifikat läuft in 14 Tagen ab",
    "certificate_expired": "Zertifikat abgelaufen",
    "certificate_invalid": "Zertifikat ungültig",
    "certificate_missing_chain": "Fehlende Chain",
}

TEMPLATE_PLACEHOLDERS: list[tuple[str, str]] = [
    ("customer_name", "Kundenname"),
    ("customer_group_name", "Kundengruppe"),
    ("certificate_id", "Zertifikats-ID"),
    ("certificate_common_name", "Common Name"),
    ("certificate_sans", "SANs"),
    ("certificate_valid_to", "Gültig bis"),
    ("days_remaining", "Verbleibende Tage"),
    ("severity", "Schweregrad"),
    ("event_type", "Ereignistyp"),
    ("portal_url", "Portal-URL zum Zertifikat"),
    ("domain_name", "Domain"),
    ("technician_names", "Techniker-Namen"),
    ("status", "Zertifikatsstatus"),
]

# Dedup-Fenster pro Event-Typ (Tage)
_DEDUP_WINDOWS: dict[str, int] = {
    "expiring_30": 20,
    "expiring_14": 10,
    "expired": 7,
    "invalid": 7,
    "missing_chain": 7,
}


# ── Template-Rendering ────────────────────────────────────────────────────────

def render_template_string(template: str, context: dict) -> str:
    """Ersetzt {{placeholder}}-Tokens im Template sicher (kein Jinja2, kein Code)."""
    for key, value in context.items():
        template = template.replace("{{" + key + "}}", str(value or ""))
    return template


def render_template(
    tpl: models.MailTemplate, context: dict
) -> tuple[str, str, Optional[str]]:
    """Rendert Subject, Text-Body und optionalen HTML-Body.

    Gibt (subject, text_body, html_body) zurück.
    """
    subject = render_template_string(tpl.subject, context)
    text_body = render_template_string(tpl.text_body, context)
    html_body = render_template_string(tpl.html_body, context) if tpl.html_body else None
    return subject, text_body, html_body


# ── Deduplication ─────────────────────────────────────────────────────────────

def _is_deduped(db: Session, dedup_key: str, window_days: int) -> bool:
    """Gibt True zurück, wenn in den letzten window_days bereits eine erfolgreiche
    Benachrichtigung mit diesem dedup_key verschickt wurde."""
    cutoff = datetime.utcnow() - timedelta(days=window_days)
    return (
        db.query(models.NotificationDispatch)
        .filter(
            models.NotificationDispatch.dedup_key == dedup_key,
            models.NotificationDispatch.status == "sent",
            models.NotificationDispatch.sent_at >= cutoff,
        )
        .first()
        is not None
    )


# ── Empfängerermittlung ───────────────────────────────────────────────────────

def get_recipients(
    db: Session,
    group: models.CustomerGroup,
) -> list[tuple[str, str]]:
    """Gibt eine Liste von (email, username) für alle Empfänger zurück.

    Empfänger = Techniker der Gruppe (mit gültiger E-Mail)
              + Admins (wenn notify_admins=True).
    Duplikate werden entfernt.
    """
    seen: set[str] = set()
    recipients: list[tuple[str, str]] = []

    for tech in group.users:
        if tech.email and tech.email not in seen and tech.is_active:
            seen.add(tech.email)
            recipients.append((tech.email, tech.username))

    if group.notify_admins:
        admins = (
            db.query(models.User)
            .filter(models.User.is_admin == True, models.User.is_active == True)
            .all()
        )
        for admin in admins:
            if admin.email and admin.email not in seen:
                seen.add(admin.email)
                recipients.append((admin.email, admin.username))

    return recipients


# ── NotificationService ───────────────────────────────────────────────────────

class NotificationService:
    """Prüft alle aktivierten Gruppen und versendet fällige Benachrichtigungen."""

    def __init__(self, db: Session):
        self.db = db
        self.mail = MailService(db)
        svc = get_settings_service(db)
        base_url = svc.get_str("app.base_url") or svc.get_str("network.external_url") or ""
        self.portal_url = base_url.rstrip("/")

    def run_checks(self) -> tuple[int, int]:
        """Führt alle Prüfungen durch. Gibt (sent_count, failed_count) zurück."""
        if not self.mail.is_configured():
            logger.info("SMTP nicht konfiguriert – Notification-Check übersprungen.")
            return 0, 0

        sent = failed = 0
        groups = (
            self.db.query(models.CustomerGroup)
            .filter(models.CustomerGroup.notification_enabled == True)
            .all()
        )

        for group in groups:
            s, f = self._check_group(group)
            sent += s
            failed += f

        return sent, failed

    def _check_group(self, group: models.CustomerGroup) -> tuple[int, int]:
        """Prüft alle Zertifikate einer Gruppe."""
        enabled_types = self._get_enabled_types(group)
        enabled_severities = self._get_enabled_severities(group)
        recipients = get_recipients(self.db, group)

        if not recipients:
            logger.debug("Gruppe '%s': keine Empfänger gefunden.", group.name)
            return 0, 0

        now = datetime.utcnow()
        sent = failed = 0

        # Alle Kunden der Gruppe, alle ihre Zertifikate
        customer_ids = [c.id for c in group.customers]
        if not customer_ids:
            return 0, 0

        certs = (
            self.db.query(models.Certificate)
            .filter(
                models.Certificate.customer_id.in_(customer_ids),
                models.Certificate.is_archived == False,
                models.Certificate.status != "revoked",
            )
            .all()
        )

        for cert in certs:
            events = self._get_events(cert, now)
            for event in events:
                etype, severity, template_key, dedup_key, dedup_window, days_remaining = event

                if etype not in enabled_types:
                    continue
                if severity not in enabled_severities:
                    continue
                if _is_deduped(self.db, dedup_key, dedup_window):
                    logger.debug("Dedup: %s für cert %s übersprungen.", dedup_key, cert.id)
                    continue

                context = self._build_context(cert, group, etype, severity, days_remaining)
                s, f = self._dispatch(
                    cert=cert,
                    group=group,
                    recipients=recipients,
                    event_type=etype,
                    severity=severity,
                    template_key=template_key,
                    dedup_key=dedup_key,
                    context=context,
                )
                sent += s
                failed += f

        return sent, failed

    def _get_events(
        self, cert: models.Certificate, now: datetime
    ) -> list[tuple[str, str, str, str, int, Optional[int]]]:
        """Ermittelt alle zutreffenden Events für ein Zertifikat.

        Gibt Liste von (event_type, severity, template_key, dedup_key, dedup_window_days, days_remaining).
        """
        events = []
        if cert.valid_until:
            days = (cert.valid_until - now).days

            # 30-Tage-Warnung (nur wenn nicht auch 14-Tage-Fenster zutrifft)
            if 14 < days <= 30:
                events.append((
                    "certificate_expiring", "warning",
                    "certificate_expiring_30_days",
                    f"expiring_30:{cert.id}", _DEDUP_WINDOWS["expiring_30"], days,
                ))

            # 14-Tage-Warnung
            if 0 < days <= 14:
                events.append((
                    "certificate_expiring", "critical",
                    "certificate_expiring_14_days",
                    f"expiring_14:{cert.id}", _DEDUP_WINDOWS["expiring_14"], days,
                ))

            # Abgelaufen
            if days <= 0:
                events.append((
                    "certificate_expired", "critical",
                    "certificate_expired",
                    f"expired:{cert.id}", _DEDUP_WINDOWS["expired"], 0,
                ))

        # Fehlende Chain
        if cert.cert_pem and not cert.chain_pem:
            events.append((
                "certificate_missing_chain", "warning",
                "certificate_missing_chain",
                f"missing_chain:{cert.id}", _DEDUP_WINDOWS["missing_chain"], None,
            ))

        # Ungültig (Status-basiert)
        if cert.status in ("expired", "revoked"):
            if not cert.valid_until or (cert.valid_until - now).days > 0:
                # Manuell als abgelaufen/widerrufen markiert
                events.append((
                    "certificate_invalid", "warning",
                    "certificate_invalid",
                    f"invalid:{cert.id}", _DEDUP_WINDOWS["invalid"], None,
                ))

        return events

    def _build_context(
        self,
        cert: models.Certificate,
        group: models.CustomerGroup,
        event_type: str,
        severity: str,
        days_remaining: Optional[int],
    ) -> dict:
        tech_names = ", ".join(
            u.username for u in group.users if u.is_active
        ) or "–"
        return {
            "customer_name": cert.customer.name if cert.customer else "–",
            "customer_group_name": group.name,
            "certificate_id": str(cert.id),
            "certificate_common_name": cert.common_name,
            "certificate_sans": cert.san or "–",
            "certificate_valid_to": (
                cert.valid_until.strftime("%d.%m.%Y") if cert.valid_until else "–"
            ),
            "days_remaining": str(days_remaining) if days_remaining is not None else "–",
            "severity": NOTIFICATION_SEVERITIES.get(severity, severity),
            "event_type": NOTIFICATION_TYPES.get(event_type, event_type),
            "portal_url": f"{self.portal_url}/certificates/{cert.id}",
            "domain_name": cert.domain.fqdn if cert.domain else "–",
            "technician_names": tech_names,
            "status": cert.status,
        }

    def _dispatch(
        self,
        cert: models.Certificate,
        group: models.CustomerGroup,
        recipients: list[tuple[str, str]],
        event_type: str,
        severity: str,
        template_key: str,
        dedup_key: str,
        context: dict,
    ) -> tuple[int, int]:
        """Versendet Benachrichtigungen an alle Empfänger und protokolliert den Versand."""
        tpl = (
            self.db.query(models.MailTemplate)
            .filter(
                models.MailTemplate.template_key == template_key,
                models.MailTemplate.is_active == True,
            )
            .first()
        )

        sent = failed = 0
        now = datetime.utcnow()

        for email, username in recipients:
            dispatch = models.NotificationDispatch(
                event_type=event_type,
                severity=severity,
                customer_id=cert.customer_id,
                customer_group_id=group.id,
                certificate_id=cert.id,
                recipient_email=email,
                template_key=template_key,
                dedup_key=dedup_key,
                status="pending",
            )

            if not tpl:
                # Fallback: einfache Textnachricht ohne Template
                subject = f"[SSL Manager] {NOTIFICATION_TYPES.get(event_type, event_type)}: {cert.common_name}"
                text_body = self._build_fallback_body(context)
                html_body = None
            else:
                subject, text_body, html_body = render_template(tpl, context)

            dispatch.subject_rendered = subject[:255]
            dispatch.body_rendered = text_body

            ok, err = self.mail.send(email, subject, text_body, html_body)

            if ok:
                dispatch.status = "sent"
                dispatch.sent_at = now
                sent += 1
            else:
                dispatch.status = "failed"
                dispatch.error_message = err
                failed += 1
                logger.warning(
                    "Notification an %s fehlgeschlagen (%s): %s", email, dedup_key, err
                )

            self.db.add(dispatch)

        self.db.commit()
        return sent, failed

    def _get_enabled_types(self, group: models.CustomerGroup) -> set[str]:
        if not group.notification_types:
            return set(NOTIFICATION_TYPES.keys())
        return set(json.loads(group.notification_types))

    def _get_enabled_severities(self, group: models.CustomerGroup) -> set[str]:
        if not group.notification_severities:
            return set(NOTIFICATION_SEVERITIES.keys())
        return set(json.loads(group.notification_severities))

    @staticmethod
    def _build_fallback_body(context: dict) -> str:
        return (
            f"SSL Cert Manager – Automatische Benachrichtigung\n"
            f"{'=' * 50}\n\n"
            f"Ereignis:       {context.get('event_type', '')}\n"
            f"Schweregrad:    {context.get('severity', '')}\n"
            f"Zertifikat:     {context.get('certificate_common_name', '')}\n"
            f"Kunde:          {context.get('customer_name', '')}\n"
            f"Gruppe:         {context.get('customer_group_name', '')}\n"
            f"Gültig bis:     {context.get('certificate_valid_to', '')}\n"
            f"Verbleibend:    {context.get('days_remaining', '')} Tage\n"
            f"Status:         {context.get('status', '')}\n\n"
            f"Portal: {context.get('portal_url', '')}\n\n"
            f"SANs: {context.get('certificate_sans', '')}\n"
        )
