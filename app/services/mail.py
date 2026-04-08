"""E-Mail-Versand über SMTP-Relay.

Der MailService liest die Konfiguration zur Laufzeit aus der Datenbank,
sodass Änderungen ohne Neustart wirksam werden.
"""
from __future__ import annotations

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from sqlalchemy.orm import Session

from ..settings_service import get_settings_service

logger = logging.getLogger(__name__)


class MailService:
    """Kapselt den SMTP-Versand. Konfiguration kommt aus app_settings."""

    def __init__(self, db: Session):
        svc = get_settings_service(db)
        self.enabled = svc.get_bool("smtp.enabled", default=False)
        self.host = svc.get_str("smtp.host", default="")
        self.port = svc.get_int("smtp.port", default=587)
        self.username = svc.get_str("smtp.username", default="")
        self.password = svc.get_str("smtp.password", default="")
        self.use_tls = svc.get_bool("smtp.use_tls", default=True)
        self.use_ssl = svc.get_bool("smtp.use_ssl", default=False)
        self.from_email = svc.get_str("smtp.from_email", default="")
        self.from_name = svc.get_str("smtp.from_name", default="SSL Cert Manager")
        self.reply_to = svc.get_str("smtp.reply_to", default="")

    def is_configured(self) -> bool:
        return bool(self.enabled and self.host and self.from_email)

    def send(
        self,
        to_email: str,
        subject: str,
        text_body: str,
        html_body: Optional[str] = None,
    ) -> tuple[bool, str]:
        """Versendet eine E-Mail. Gibt (success, error_message) zurück."""
        if not self.is_configured():
            return False, "SMTP nicht konfiguriert oder deaktiviert."

        try:
            from_addr = (
                f"{self.from_name} <{self.from_email}>"
                if self.from_name
                else self.from_email
            )

            if html_body:
                msg: MIMEMultipart | MIMEText = MIMEMultipart("alternative")
                msg["Subject"] = subject
                msg["From"] = from_addr
                msg["To"] = to_email
                if self.reply_to:
                    msg["Reply-To"] = self.reply_to
                msg.attach(MIMEText(text_body, "plain", "utf-8"))
                msg.attach(MIMEText(html_body, "html", "utf-8"))
            else:
                msg = MIMEText(text_body, "plain", "utf-8")
                msg["Subject"] = subject
                msg["From"] = from_addr
                msg["To"] = to_email
                if self.reply_to:
                    msg["Reply-To"] = self.reply_to

            if self.use_ssl:
                smtp = smtplib.SMTP_SSL(self.host, self.port, timeout=15)
            else:
                smtp = smtplib.SMTP(self.host, self.port, timeout=15)
                if self.use_tls:
                    smtp.starttls()

            if self.username:
                smtp.login(self.username, self.password)  # nosec – password from encrypted DB

            smtp.sendmail(self.from_email, [to_email], msg.as_string())
            smtp.quit()

            logger.info("Mail gesendet an %s: %s", to_email, subject)
            return True, ""

        except smtplib.SMTPAuthenticationError:
            logger.error("SMTP-Authentifizierung fehlgeschlagen für %s", self.username)
            return False, "SMTP-Authentifizierung fehlgeschlagen. Bitte Benutzername und Passwort prüfen."
        except smtplib.SMTPConnectError as exc:
            logger.error("SMTP-Verbindung fehlgeschlagen zu %s:%s – %s", self.host, self.port, exc)
            return False, f"Verbindung zu {self.host}:{self.port} fehlgeschlagen."
        except Exception as exc:
            logger.error("SMTP-Fehler beim Senden an %s: %s", to_email, exc)
            return False, str(exc)

    def send_test(self, to_email: str) -> tuple[bool, str]:
        """Sendet eine Testmail an die angegebene Adresse."""
        subject = "SSL Cert Manager – Testmail"
        text = (
            "Das ist eine Testmail vom SSL Cert Manager.\n\n"
            f"SMTP-Host: {self.host}:{self.port}\n"
            f"Absender: {self.from_email}\n"
            f"STARTTLS: {'Ja' if self.use_tls else 'Nein'}\n"
            f"SSL: {'Ja' if self.use_ssl else 'Nein'}\n\n"
            "Diese Mail bestätigt, dass die SMTP-Konfiguration korrekt ist."
        )
        return self.send(to_email, subject, text)
