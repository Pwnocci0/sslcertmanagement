"""Pydantic-Schemas für TheSSLStore REST-API (v2).

Feldnamen entsprechen der offiziellen API-Dokumentation:
https://www.thesslstore.com/api/

Auth-Struktur laut Doku:
  POST /health/validate/  → PartnerCode/AuthToken FLACH im Root
  Alle anderen Endpunkte  → Auth verschachtelt unter "AuthRequest": { … }

In nahezu allen Antworten ist die Auth-Info unter "AuthResponse": { … }
verschachtelt. Nur /health/validate/ antwortet flach.
"""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field, model_validator


# ── Basis-Antwortmodell ───────────────────────────────────────────────────────

class _ApiResponse(BaseModel):
    """Basisklasse für alle API-Antworten.

    Die TheSSLStore-API liefert für viele String- und List-Felder null.
    Dieser Validator konvertiert None → "" (str) bzw. None → [] (list),
    damit Pydantic v2 keine Validation-Errors wirft.
    """
    model_config = {"extra": "allow"}

    @model_validator(mode="before")
    @classmethod
    def _coerce_none_fields(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        for klass in cls.__mro__:
            if klass in (BaseModel, object):
                continue
            for field_name, annotation in getattr(klass, "__annotations__", {}).items():
                if field_name not in data or data[field_name] is not None:
                    continue
                ann = annotation if isinstance(annotation, str) else getattr(annotation, "__name__", "")
                if ann == "str" or annotation is str:
                    data[field_name] = ""
                elif ann.startswith("list") or (
                    hasattr(annotation, "__origin__") and annotation.__origin__ is list
                ):
                    data[field_name] = []
        return data


# ── Auth-Antwort (in fast allen Endpunkt-Antworten verschachtelt) ─────────────

class AuthResponse(_ApiResponse):
    """Kommt in API-Antworten als verschachteltes {"AuthResponse": {…}}."""
    isError: bool = False
    Message: list[str] = Field(default_factory=list)
    Timestamp: str = ""
    ReplayToken: str = ""
    InvokingPartnerCode: str = ""


# ── Health / Credentials ──────────────────────────────────────────────────────
# Endpoint: POST /health/validate/
# Besonderheit: Antwort OHNE AuthResponse-Wrapper (flache Struktur).

class HealthValidateResponse(_ApiResponse):
    isError: bool = False
    Message: list[str] = Field(default_factory=list)
    Timestamp: str = ""
    ReplayToken: str = ""
    InvokingPartnerCode: str = ""


# ── Produkt-Liste ─────────────────────────────────────────────────────────────
# Endpoint: POST /product/query/
# Antwort: Flache Liste von Produkten (jedes Element ist ein Produkt;
# das erste enthält zusätzlich "AuthResponse").

class ProductItem(BaseModel):
    """Einzelnes Produkt aus der API-Antwort."""
    ProductCode: str = ""
    ProductName: str = ""
    ProductType: str = ""               # String in Antworten ("DV", "OV", "EV")
    VendorName: str = ""
    isDVProduct: bool = False
    isEVProduct: bool = False
    isOVProduct: bool = False
    isCodeSigning: bool = False
    isSanProduct: bool = False
    IsSanEnable: bool = False
    isWildCard: bool = False
    isWlidcard: bool = False            # API-Tippfehler, beide Varianten absichern
    MaxSan: int = 0
    MinSan: int = 0
    NumberOfDomains: int = 0
    ValidityPeriod: int = 12
    AuthResponse: Optional[AuthResponse] = None  # nur im ersten Listenelement

    @property
    def isDV(self) -> bool:
        return self.isDVProduct

    @property
    def isOV(self) -> bool:
        return self.isOVProduct

    @property
    def isEV(self) -> bool:
        return self.isEVProduct

    @property
    def is_wildcard(self) -> bool:
        return self.isWildCard or self.isWlidcard

    model_config = {"extra": "allow"}


class ProductQueryResponse(_ApiResponse):
    """Enthält die Produktliste – wird vom Client aus der Listenauflösung befüllt."""
    isError: bool = False
    ProductList: list[ProductItem] = Field(default_factory=list)


# ── Kontakt- und Organisations-Strukturen ────────────────────────────────────
# Werden für POST /order/neworder/ verwendet.

class ContactInfo(BaseModel):
    FirstName: str = ""
    LastName: str = ""
    Phone: str = ""
    Fax: str = ""
    Email: str = ""
    Title: str = ""
    OrganizationName: str = ""
    AddressLine1: str = ""
    AddressLine2: str = ""
    City: str = ""
    Region: str = ""
    PostalCode: str = ""
    Country: str = "DE"


class OrgAddress(BaseModel):
    AddressLine1: str = ""
    AddressLine2: str = ""
    AddressLine3: str = ""
    City: str = ""
    Region: str = ""
    PostalCode: str = ""
    Country: str = "DE"
    Phone: str = ""
    Fax: str = ""


class OrgInfo(BaseModel):
    OrganizationName: str = ""
    DUNS: str = ""
    Division: str = ""
    OrganizationAddress: OrgAddress = Field(default_factory=OrgAddress)


# ── Bestellungen ──────────────────────────────────────────────────────────────
# Endpoint: POST /order/neworder/ und POST /order/query/

class OrderStatusInfo(_ApiResponse):
    MajorStatus: str = ""
    MinorStatus: str = ""
    OrderStatusName: str = ""
    Timestamp: str = ""


class NewOrderResponse(_ApiResponse):
    AuthResponse: Optional[AuthResponse] = None
    isError: bool = False
    PartnerOrderID: str = ""
    TheSSLStoreOrderID: str = ""
    VendorOrderID: str = ""
    OrderStatus: OrderStatusInfo = Field(default_factory=OrderStatusInfo)
    Message: list[str] = Field(default_factory=list)


class OrderQueryResponse(_ApiResponse):
    AuthResponse: Optional[AuthResponse] = None
    isError: bool = False
    PartnerOrderID: str = ""
    TheSSLStoreOrderID: str = ""
    VendorOrderID: str = ""
    OrderStatus: OrderStatusInfo = Field(default_factory=OrderStatusInfo)
    CertificateStartDate: str = ""
    CertificateEndDate: str = ""
    CommonName: str = ""
    DNSNames: list[str] = Field(default_factory=list)
    ApproverEmail: str = ""
    AuthFileName: str = ""
    AuthFileContent: str = ""
    CNAMEAuthName: str = ""
    CNAMEAuthValue: str = ""
    Message: list[str] = Field(default_factory=list)


# ── CSR dekodieren / validieren ───────────────────────────────────────────────
# Endpoint: POST /csr/

class CSRDecodeResponse(_ApiResponse):
    AuthResponse: Optional[AuthResponse] = None
    isError: bool = False
    DomainName: str = ""
    DNSNames: list[str] = Field(default_factory=list)
    Organization: str = ""
    OrganizationUnit: str = ""
    Locality: str = ""
    State: str = ""
    Country: str = ""
    Email: str = ""
    isWildcardCSR: bool = False
    isValidDomainName: bool = False
    hasBadExtensions: bool = False
    MD5Hash: str = ""
    SHA1Hash: str = ""
    Message: list[str] = Field(default_factory=list)


# ── Approver-E-Mail-Liste ─────────────────────────────────────────────────────
# Endpoint: POST /order/approverlist/

class ApproverEmailResponse(_ApiResponse):
    AuthResponse: Optional[AuthResponse] = None
    isError: bool = False
    ApproverEmailList: list[str] = Field(default_factory=list)
    Message: list[str] = Field(default_factory=list)


# ── Zertifikat herunterladen ──────────────────────────────────────────────────
# Endpoint: POST /order/download/

class OrderDownloadResponse(_ApiResponse):
    AuthResponse: Optional[AuthResponse] = None
    isError: bool = False
    CACertificate: str = ""
    Certificate: str = ""
    Message: list[str] = Field(default_factory=list)
