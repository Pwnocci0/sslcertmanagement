"""HTTP-Client für die TheSSLStore REST-API (v2).

Alle Endpunkte und Request-Strukturen entsprechen der offiziellen Dokumentation:
https://www.thesslstore.com/api/

Auth-Strukturen laut Doku:
  - POST /health/validate/  → Auth FLACH im Root (PartnerCode, AuthToken, …)
  - ALLE anderen Endpunkte  → Auth verschachtelt unter "AuthRequest": { … }
"""
from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Type, TypeVar

import requests
from pydantic import BaseModel

from ...settings_service import SettingsService
from .exceptions import (
    TheSSLStoreAPIError,
    TheSSLStoreConfigError,
)

log = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

_TIMEOUT = 30  # Sekunden


# ── Dokumentierte API-Endpunkt-Pfade ─────────────────────────────────────────

class _EP(str, Enum):
    """Zentrale Definition aller genutzten Endpunkt-Pfade."""
    HEALTH_VALIDATE  = "health/validate/"    # POST – flache Auth
    HEALTH_STATUS    = "health/status/"      # GET

    PRODUCT_QUERY    = "product/query/"      # POST – nested AuthRequest
    ORDER_NEWORDER   = "order/neworder/"     # POST – nested AuthRequest
    ORDER_QUERY      = "order/query/"        # POST – nested AuthRequest
    ORDER_VALIDATE   = "order/validate/"     # POST – nested AuthRequest
    ORDER_DOWNLOAD   = "order/download/"     # POST – nested AuthRequest
    ORDER_APPROVER   = "order/approverlist/" # POST – nested AuthRequest
    CSR_DECODE       = "csr/"               # POST – nested AuthRequest


class TheSSLStoreClient:
    """HTTP-Client für TheSSLStore."""

    def __init__(self, settings: SettingsService):
        self._settings = settings

    # ── Konfiguration ─────────────────────────────────────────────────────────

    def _get_base_url(self) -> str:
        sandbox = self._settings.get_bool("thesslstore.sandbox", default=True)
        key = "thesslstore.api_url_sandbox" if sandbox else "thesslstore.api_url_live"
        return self._settings.get_str(key).rstrip("/") + "/"

    def _get_auth_fields(self) -> dict[str, str]:
        """Gibt Auth-Felder als Dict zurück (non-empty only)."""
        sandbox = self._settings.get_bool("thesslstore.sandbox", default=True)
        suffix = "sandbox" if sandbox else "live"
        modus  = "Sandbox" if sandbox else "Live"

        partner_code = self._settings.get_str(f"thesslstore.partner_code_{suffix}").strip()
        auth_token   = self._settings.get_str(f"thesslstore.auth_token_{suffix}").strip()

        if not partner_code:
            raise TheSSLStoreConfigError(
                f"TheSSLStore Partner Code ({modus}) nicht konfiguriert. "
                "Bitte unter Einstellungen → TheSSLStore API eintragen."
            )
        if not auth_token:
            raise TheSSLStoreConfigError(
                f"TheSSLStore Auth Token ({modus}) nicht konfiguriert. "
                "Bitte unter Einstellungen → TheSSLStore API eintragen."
            )
        user_agent = self._settings.get_str("thesslstore.user_agent", "CertMgr/1.0")
        log.debug(
            "TheSSLStore auth [%s]: PartnerCode=%s*** (len=%d), AuthToken present=%s",
            modus,
            partner_code[:4] if len(partner_code) > 4 else "***",
            len(partner_code),
            bool(auth_token),
        )
        fields: dict[str, str] = {"PartnerCode": partner_code, "AuthToken": auth_token}
        if user_agent:
            fields["UserAgent"] = user_agent
        return fields

    def _get_headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json",
        }

    # ── Payload-Builder ───────────────────────────────────────────────────────

    def _payload_flat(self, **extra: Any) -> dict[str, Any]:
        """Flat-Auth-Payload: PartnerCode/AuthToken im Root (nur /health/validate/)."""
        payload = dict(self._get_auth_fields())
        for k, v in extra.items():
            if v is not None and v != "":
                payload[k] = v
        return payload

    def _payload_nested(self, **extra: Any) -> dict[str, Any]:
        """Nested-Auth-Payload: Auth unter AuthRequest-Key (alle anderen Endpunkte).

        Leere Strings und None-Werte werden herausgefiltert.
        Pydantic-Modelle werden automatisch per model_dump() serialisiert.
        """
        payload: dict[str, Any] = {"AuthRequest": self._get_auth_fields()}
        for k, v in extra.items():
            if v is None or v == "":
                continue
            if hasattr(v, "model_dump"):
                v = v.model_dump(exclude_none=True)
            payload[k] = v
        return payload

    # ── Interne Request-Methode ───────────────────────────────────────────────

    def _post(
        self,
        endpoint: _EP,
        payload: dict[str, Any],
        response_model: Type[T],
        list_items_field: str | None = None,
    ) -> T:
        """POST an einem dokumentierten Endpunkt.

        list_items_field: Wenn die API eine flache Liste von Items zurückgibt
        (z.B. product/query), wird die Liste in dieses Feld der response_model
        gemappt. Das erste Element kann AuthResponse + Produktfelder enthalten.
        """
        url = self._get_base_url() + endpoint.value
        log.info("TheSSLStore API POST → %s", url)
        log.debug("TheSSLStore payload keys: %s", list(payload.keys()))

        try:
            resp = requests.post(
                url,
                json=payload,
                headers=self._get_headers(),
                timeout=_TIMEOUT,
            )
        except requests.exceptions.Timeout:
            raise TheSSLStoreAPIError(
                f"Timeout nach {_TIMEOUT}s beim Aufruf von {endpoint.value}. "
                "Bitte Netzwerkverbindung und API-URL prüfen."
            )
        except requests.exceptions.ConnectionError as exc:
            raise TheSSLStoreAPIError(
                f"Verbindungsfehler bei {endpoint.value}: "
                "API nicht erreichbar – Netzwerk oder URL prüfen."
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise TheSSLStoreAPIError(
                f"Netzwerkfehler bei {endpoint.value}: {exc}"
            ) from exc

        if resp.status_code >= 400:
            log.warning(
                "TheSSLStore HTTP %s bei %s – Body: %s",
                resp.status_code, endpoint.value, resp.text[:500],
            )
        if resp.status_code == 404:
            raise TheSSLStoreAPIError(
                f"HTTP 404 bei {endpoint.value} – Endpunkt nicht gefunden. "
                "Bitte API-Basis-URL in den Einstellungen prüfen."
            )
        if resp.status_code == 401:
            raise TheSSLStoreAPIError(
                f"HTTP 401 bei {endpoint.value} – Nicht autorisiert."
            )
        if resp.status_code == 400:
            raise TheSSLStoreAPIError(
                f"HTTP 400 bei {endpoint.value} – Ungültige Anfrage. "
                f"API-Antwort: {resp.text[:300]}"
            )
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as exc:
            raise TheSSLStoreAPIError(
                f"HTTP {resp.status_code} bei {endpoint.value}: {exc}"
            ) from exc

        try:
            data = resp.json()
        except ValueError as exc:
            raise TheSSLStoreAPIError(
                f"Ungültige JSON-Antwort von {endpoint.value}: {resp.text[:300]}"
            ) from exc

        # Flache Listen-Antwort (z.B. product/query liefert Liste von Produkten)
        if isinstance(data, list) and list_items_field:
            if not data:
                log.debug("TheSSLStore %s → leere Liste", endpoint.value)
                return response_model(**{list_items_field: []})
            # Erstes Element enthält AuthResponse → auf Fehler prüfen
            auth_resp = data[0].get("AuthResponse", {}) if isinstance(data[0], dict) else {}
            if auth_resp.get("isError"):
                msgs = auth_resp.get("Message") or []
                log.warning("TheSSLStore API-Fehler bei %s: %s", endpoint.value, msgs)
                raise TheSSLStoreAPIError(
                    f"API-Fehler bei {endpoint.value}", api_messages=msgs
                )
            log.debug(
                "TheSSLStore %s → flache Produktliste, %d Elemente",
                endpoint.value, len(data),
            )
            return response_model(**{list_items_field: data})
        elif isinstance(data, list):
            if not data:
                raise TheSSLStoreAPIError(f"Leere Listen-Antwort von {endpoint.value}.")
            data = data[0]

        parsed: T = response_model.model_validate(data)

        # API-Level-Fehler prüfen (isError im Body oder in AuthResponse)
        auth_resp = getattr(parsed, "AuthResponse", None)
        if auth_resp is not None:
            is_err = getattr(auth_resp, "isError", False)
            messages = getattr(auth_resp, "Message", []) or []
        else:
            is_err = getattr(parsed, "isError", False)
            messages = getattr(parsed, "Message", []) or []

        if is_err:
            log.warning(
                "TheSSLStore API-Fehler bei %s: %s",
                endpoint.value, "; ".join(messages),
            )
            raise TheSSLStoreAPIError(
                f"API-Fehler bei {endpoint.value}",
                api_messages=messages,
            )

        log.debug("TheSSLStore %s → OK", endpoint.value)
        return parsed

    # ── Öffentliche API-Methoden ──────────────────────────────────────────────

    # POST /health/validate/ – FLACHE Auth (Sonderfall laut Doku)
    def validate_credentials(self) -> bool:
        from .schemas import HealthValidateResponse
        payload = self._payload_flat()
        self._post(_EP.HEALTH_VALIDATE, payload, HealthValidateResponse)
        return True

    # POST /product/query/ – nested AuthRequest
    def product_query(
        self,
        product_code: str | None = None,
        product_type: int | None = None,
    ):
        from .schemas import ProductQueryResponse
        extra: dict[str, Any] = {}
        if product_code:
            extra["ProductCode"] = product_code
        if product_type is not None:
            extra["ProductType"] = product_type
        payload = self._payload_nested(**extra)
        return self._post(
            _EP.PRODUCT_QUERY, payload, ProductQueryResponse,
            list_items_field="ProductList",
        )

    # POST /order/neworder/ – nested AuthRequest
    def new_order(self, payload: dict[str, Any]):
        from .schemas import NewOrderResponse
        return self._post(_EP.ORDER_NEWORDER, payload, NewOrderResponse)

    # POST /order/query/ – nested AuthRequest
    def order_query(self, thessl_order_id: str = "", domain_name: str = ""):
        from .schemas import OrderQueryResponse
        payload = self._payload_nested(
            TheSSLStoreOrderID=thessl_order_id,
            DomainName=domain_name,
        )
        return self._post(_EP.ORDER_QUERY, payload, OrderQueryResponse)

    # POST /csr/ – nested AuthRequest
    def csr_decode(self, csr_pem: str, product_code: str = ""):
        from .schemas import CSRDecodeResponse
        payload = self._payload_nested(CSR=csr_pem, ProductCode=product_code)
        return self._post(_EP.CSR_DECODE, payload, CSRDecodeResponse)

    # POST /order/approverlist/ – nested AuthRequest
    def approver_email_list(self, domain: str, product_code: str = ""):
        from .schemas import ApproverEmailResponse
        payload = self._payload_nested(DomainName=domain, ProductCode=product_code)
        return self._post(_EP.ORDER_APPROVER, payload, ApproverEmailResponse)

    # POST /order/download/ – nested AuthRequest
    def order_download(self, thessl_order_id: str, return_pkcs7: bool = False):
        from .schemas import OrderDownloadResponse
        extra: dict[str, Any] = {"TheSSLStoreOrderID": thessl_order_id}
        if return_pkcs7:
            extra["ReturnPKCS7Cert"] = True
        payload = self._payload_nested(**extra)
        return self._post(_EP.ORDER_DOWNLOAD, payload, OrderDownloadResponse)
