"""Business-Logik für die TheSSLStore-Integration.

Orchestriert Client-Calls (alle gegen dokumentierte Endpunkte) und
DB-Persistierung. Wird per FastAPI-Dependency injiziert.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime

from sqlalchemy.orm import Session

from ... import models
from ...settings_service import SettingsService
from .client import TheSSLStoreClient
from .exceptions import TheSSLStoreAPIError, TheSSLStoreOrderError
from .schemas import ContactInfo, OrgInfo

log = logging.getLogger(__name__)


class TheSSLStoreService:
    """Fachliche Operationen rund um TheSSLStore.

    Instanz wird pro Request erzeugt (via Depends).
    """

    def __init__(self, db: Session, settings: SettingsService):
        self.db = db
        self.settings = settings
        self.client = TheSSLStoreClient(settings)

    # ── Credentials ───────────────────────────────────────────────────────────

    def validate_credentials(self) -> tuple[bool, str]:
        """Prüft Zugangsdaten über POST /health/validate/.

        Gibt (True, nutzerfrl. Meldung) oder (False, Fehlerbeschreibung) zurück.
        Unterscheidet zwischen Konfigurationsfehler, Netzwerkfehler und
        API-Fehler für verständliche Frontend-Rückmeldungen.
        """
        from .exceptions import TheSSLStoreConfigError

        try:
            self.client.validate_credentials()
            sandbox = self.settings.get_bool("thesslstore.sandbox", default=True)
            modus = "Sandbox" if sandbox else "Live"
            return True, f"API erreichbar, Zugangsdaten gültig ({modus}-Modus)."
        except TheSSLStoreConfigError as exc:
            return False, f"Konfiguration unvollständig: {exc}"
        except TheSSLStoreAPIError as exc:
            msg = str(exc)
            raw_msgs = " ".join(exc.api_messages).lower()
            # -9002: Pflichtfeld fehlt → Zugangsdaten leer oder nicht gespeichert
            if "-9002" in msg or "partnercode" in raw_msgs or "required field" in raw_msgs:
                return False, (
                    "API meldet fehlendes Pflichtfeld (PartnerCode). "
                    "Bitte Partner Code und Auth Token unter Einstellungen → TheSSLStore API erneut speichern."
                )
            if "401" in msg or "autorisiert" in msg.lower() or "ungültig" in msg.lower():
                return False, "API erreichbar, aber Zugangsdaten ungültig. Partner Code / Auth Token prüfen."
            if "404" in msg or "Endpunkt" in msg:
                return False, f"Konfigurierter API-Endpunkt laut Dokumentation ungültig. {msg}"
            if "Timeout" in msg or "Verbindungsfehler" in msg or "Netzwerk" in msg:
                return False, f"Netzwerk-/Timeout-Fehler: {msg}"
            return False, f"API-Fehler: {msg}"
        except Exception as exc:
            return False, f"Unbekannter Fehler: {exc}"

    # ── Produkte ──────────────────────────────────────────────────────────────

    def sync_products(self) -> int:
        """Synchronisiert Produkte via POST /product/query/ in die lokale DB.

        Gibt Anzahl aktualisierter/eingefügter Produkte zurück.
        """
        response = self.client.product_query()
        products = response.ProductList
        count = 0

        for item in products:
            # ProductCode ist der primäre Identifikator laut API-Doku
            sku = item.ProductCode
            if not sku:
                continue

            row = (
                self.db.query(models.TheSSLStoreProduct)
                .filter(models.TheSSLStoreProduct.sku == sku)
                .first()
            )
            raw = item.model_dump()

            if row:
                row.name = item.ProductName or sku
                row.product_code = item.ProductCode
                row.validity_period = item.ValidityPeriod
                row.max_san = item.MaxSan
                row.is_wildcard = item.isWildCard
                row.is_dv = item.isDVProduct
                row.is_ov = item.isOVProduct
                row.is_ev = item.isEVProduct
                row.vendor_name = item.VendorName
                row.raw_json = json.dumps(raw)
                row.synced_at = datetime.utcnow()
            else:
                row = models.TheSSLStoreProduct(
                    sku=sku,
                    name=item.ProductName or sku,
                    product_code=item.ProductCode,
                    validity_period=item.ValidityPeriod,
                    max_san=item.MaxSan,
                    is_wildcard=item.isWildCard,
                    is_dv=item.isDVProduct,
                    is_ov=item.isOVProduct,
                    is_ev=item.isEVProduct,
                    vendor_name=item.VendorName,
                    raw_json=json.dumps(raw),
                )
                self.db.add(row)
            count += 1

        self.db.commit()
        log.info("TheSSLStore: %d Produkte über /product/query/ synchronisiert", count)
        return count

    def get_products(self) -> list[models.TheSSLStoreProduct]:
        return (
            self.db.query(models.TheSSLStoreProduct)
            .order_by(models.TheSSLStoreProduct.name)
            .all()
        )

    def get_product_by_sku(self, sku: str) -> models.TheSSLStoreProduct | None:
        return (
            self.db.query(models.TheSSLStoreProduct)
            .filter(models.TheSSLStoreProduct.sku == sku)
            .first()
        )

    # ── Bestellungen ──────────────────────────────────────────────────────────

    def get_orders(self) -> list[models.TheSSLStoreOrder]:
        return (
            self.db.query(models.TheSSLStoreOrder)
            .order_by(models.TheSSLStoreOrder.created_at.desc())
            .all()
        )

    def get_order_by_id(self, order_id: int) -> models.TheSSLStoreOrder | None:
        return (
            self.db.query(models.TheSSLStoreOrder)
            .filter(models.TheSSLStoreOrder.id == order_id)
            .first()
        )

    def new_order(
        self,
        certificate_id: int,
        sku: str,
        csr_pem: str,
        domain_name: str,
        approver_email: str,
        validity_period: int = 12,
        san_count: int = 0,
        server_count: int = 1,
        dcv_method: str = "EMAIL",      # EMAIL | HTTP | HTTPS | CNAME
        dns_names: list[str] | None = None,
        admin_contact: dict | None = None,
        tech_contact: dict | None = None,
    ) -> models.TheSSLStoreOrder:
        """Legt eine Bestellung via POST /order/neworder/ an.

        DCV-Methode wird über boolesche Flags im Request gesteuert
        (nicht über einen DomainControlMethod-String), entsprechend der API-Doku:
            EMAIL  → keine Flags setzen, ApproverEmail angeben
            HTTP   → FileAuthDVIndicator=true
            HTTPS  → HTTPSFileAuthDVIndicator=true
            CNAME  → CNAMEAuthDVIndicator=true
        """
        product = self.get_product_by_sku(sku)
        if not product:
            raise TheSSLStoreOrderError(f"Unbekannte SKU: {sku}")

        cert = (
            self.db.query(models.Certificate)
            .filter(models.Certificate.id == certificate_id)
            .first()
        )
        if not cert:
            raise TheSSLStoreOrderError(f"Zertifikat {certificate_id} nicht gefunden.")

        def _build_contact(d: dict | None) -> ContactInfo:
            return ContactInfo(**(d or {}))

        # DCV-Flags setzen
        dcv = dcv_method.upper()
        payload = self.client._payload_nested(
            ProductCode=product.product_code or sku,
            ValidityPeriod=validity_period,
            ServerCount=server_count,
            CSR=csr_pem,
            DomainName=domain_name,
            DNSNames=dns_names or [],
            ApproverEmail=approver_email if dcv == "EMAIL" else None,
            FileAuthDVIndicator=(dcv == "HTTP") or None,
            HTTPSFileAuthDVIndicator=(dcv == "HTTPS") or None,
            CNAMEAuthDVIndicator=(dcv == "CNAME") or None,
            ReserveSANCount=san_count if san_count else None,
            AdminContact=_build_contact(admin_contact),
            TechnicalContact=_build_contact(tech_contact),
        )

        response = self.client.new_order(payload)

        order = models.TheSSLStoreOrder(
            certificate_id=certificate_id,
            thessl_order_id=response.TheSSLStoreOrderID,
            vendor_order_id=response.VendorOrderID,
            sku=sku,
            status=response.OrderStatus.MajorStatus.lower() or "pending",
            san_count=san_count,
            server_count=server_count,
            validity_period=validity_period,
            approver_email=approver_email,
            domain_control_method=dcv_method,
        )
        self.db.add(order)
        self.db.commit()
        self.db.refresh(order)
        log.info(
            "TheSSLStore Bestellung angelegt: %s (lokal ID %d)",
            response.TheSSLStoreOrderID,
            order.id,
        )
        return order

    def refresh_order_status(self, order: models.TheSSLStoreOrder) -> models.TheSSLStoreOrder:
        """Aktualisiert den Bestellstatus via POST /order/query/."""
        if not order.thessl_order_id:
            raise TheSSLStoreOrderError("Keine TheSSLStore Order ID vorhanden.")

        response = self.client.order_query(thessl_order_id=order.thessl_order_id)
        api_status = response.OrderStatus.MajorStatus.lower() or "pending"

        order.status = api_status
        order.raw_status_json = json.dumps(response.model_dump())
        order.updated_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(order)
        return order

    # ── CSR-Hilfsmethoden ─────────────────────────────────────────────────────

    def decode_csr(self, csr_pem: str, product_code: str = "") -> dict:
        """Dekodiert einen CSR via POST /csr/."""
        response = self.client.csr_decode(csr_pem, product_code)
        return response.model_dump()

    def get_approver_emails(self, domain: str, product_code: str = "") -> list[str]:
        """Liefert Approver-E-Mails via POST /order/approverlist/."""
        response = self.client.approver_email_list(domain, product_code)
        return response.ApproverEmailList

    def download_certificate(self, thessl_order_id: str) -> tuple[str, str]:
        """Lädt das ausgestellte Zertifikat via POST /order/download/.

        Gibt (leaf_cert_pem, ca_chain_pem) zurück.
        """
        response = self.client.order_download(thessl_order_id)
        return response.Certificate, response.CACertificate


# ── FastAPI Dependency ────────────────────────────────────────────────────────

def get_thesslstore_service(db: Session, settings: SettingsService) -> TheSSLStoreService:
    return TheSSLStoreService(db, settings)
