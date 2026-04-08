"""Tests für den TheSSLStore-Client.

Alle Tests prüfen ausschließlich gegen die in _EP definierten,
dokumentierten Endpunkt-Pfade aus der offiziellen TheSSLStore API-Doku:
https://www.thesslstore.com/api/api-reference
"""
import os
import pytest
from unittest.mock import MagicMock, patch

os.environ.setdefault("APP_SECRET_KEY", "test-secret-key-for-unit-tests")

from app.services.thesslstore.client import TheSSLStoreClient, _EP
from app.services.thesslstore.exceptions import (
    TheSSLStoreAPIError,
    TheSSLStoreConfigError,
)
from app.services.thesslstore.service import TheSSLStoreService
from app.settings_service import SettingsService, _invalidate_cache


# ── Test-Helpers ──────────────────────────────────────────────────────────────

def _make_settings(overrides: dict | None = None) -> SettingsService:
    defaults = {
        "thesslstore.partner_code_sandbox": "TEST_PARTNER_SANDBOX",
        "thesslstore.auth_token_sandbox":   "TEST_TOKEN_SANDBOX",
        "thesslstore.partner_code_live":    "TEST_PARTNER_LIVE",
        "thesslstore.auth_token_live":      "TEST_TOKEN_LIVE",
        "thesslstore.sandbox":      "true",
        "thesslstore.api_url_sandbox": "https://sandbox-wbapi.thesslstore.com/rest/",
        "thesslstore.api_url_live":    "https://api.thesslstore.com/rest/",
        "thesslstore.user_agent":   "TestAgent/1.0",
    }
    if overrides:
        defaults.update(overrides)

    svc = MagicMock(spec=SettingsService)
    svc.get_bool.side_effect = lambda key, default=False: (
        defaults.get(key, str(default)).lower() in ("true", "1", "yes", "on")
    )
    svc.get_str.side_effect = lambda key, default="": defaults.get(key, default)
    return svc


def _make_client(settings=None) -> TheSSLStoreClient:
    return TheSSLStoreClient(settings or _make_settings())


def _mock_response(json_data: dict, status_code: int = 200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    if status_code >= 400:
        import requests as req
        resp.raise_for_status.side_effect = req.exceptions.HTTPError(
            f"{status_code} Error"
        )
    else:
        resp.raise_for_status.return_value = None
    return resp


# ── Endpunkt-Definitionen ─────────────────────────────────────────────────────

class TestEndpointConstants:
    """Prüft dass alle Endpunkt-Konstanten den dokumentierten Pfaden entsprechen."""

    def test_health_validate_path(self):
        assert _EP.HEALTH_VALIDATE.value == "health/validate/"

    def test_product_query_path(self):
        # Nicht "order/product/list" – das ist nicht dokumentiert
        assert _EP.PRODUCT_QUERY.value == "product/query/"
        assert "order" not in _EP.PRODUCT_QUERY.value

    def test_order_neworder_path(self):
        assert _EP.ORDER_NEWORDER.value == "order/neworder/"

    def test_order_query_path(self):
        assert _EP.ORDER_QUERY.value == "order/query/"

    def test_csr_decode_path(self):
        # Nicht "csr/decode/" – der dokumentierte Pfad ist /csr/
        assert _EP.CSR_DECODE.value == "csr/"
        assert _EP.CSR_DECODE.value != "csr/decode/"

    def test_approver_list_path(self):
        assert _EP.ORDER_APPROVER.value == "order/approverlist/"


# ── Basis-URL / Konfiguration ─────────────────────────────────────────────────

class TestBaseURL:
    def test_sandbox_uses_correct_documented_url(self):
        client = _make_client()
        url = client._get_base_url()
        # Korrekte Sandbox-URL laut Dokumentation: sandbox-wbapi (nicht sandbox)
        assert "sandbox-wbapi.thesslstore.com" in url
        assert url.endswith("/")

    def test_live_uses_correct_documented_url(self):
        client = _make_client(_make_settings({"thesslstore.sandbox": "false"}))
        url = client._get_base_url()
        assert "api.thesslstore.com" in url
        assert "sandbox" not in url

    def test_missing_partner_code_raises_config_error(self):
        client = _make_client(
            _make_settings({"thesslstore.partner_code_sandbox": "", "thesslstore.auth_token_sandbox": "tok"})
        )
        with pytest.raises(TheSSLStoreConfigError):
            client._get_auth_fields()

    def test_missing_auth_token_raises_config_error(self):
        client = _make_client(
            _make_settings({"thesslstore.partner_code_sandbox": "p", "thesslstore.auth_token_sandbox": ""})
        )
        with pytest.raises(TheSSLStoreConfigError):
            client._get_auth_fields()


# ── validate_credentials → POST /health/validate/ ────────────────────────────

class TestValidateCredentials:
    def test_calls_health_validate_endpoint(self):
        client = _make_client()
        resp_data = {
            "isError": False,
            "Message": [],
            "Timestamp": "2024-01-01T00:00:00",
            "ReplayToken": "",
            "InvokingPartnerCode": "TEST_PARTNER",
        }
        with patch("app.services.thesslstore.client.requests.post") as mock_post:
            mock_post.return_value = _mock_response(resp_data)
            result = client.validate_credentials()

        assert result is True
        called_url = mock_post.call_args[0][0]
        assert "health/validate/" in called_url
        # Sicherstellen dass KEIN anderer Endpunkt für den Credentials-Test
        # verwendet wird (z.B. nicht product/query)
        assert "product" not in called_url

    def test_invalid_credentials_raises_api_error(self):
        client = _make_client()
        resp_data = {
            "isError": True,
            "Message": ["Invalid partner code or auth token"],
        }
        with patch("app.services.thesslstore.client.requests.post") as mock_post:
            mock_post.return_value = _mock_response(resp_data)
            with pytest.raises(TheSSLStoreAPIError):
                client.validate_credentials()

    def test_service_returns_friendly_success_message(self):
        settings = _make_settings()
        tsvc = TheSSLStoreService(MagicMock(), settings)
        with patch.object(tsvc.client, "validate_credentials", return_value=True):
            ok, msg = tsvc.validate_credentials()
        assert ok is True
        assert "gültig" in msg.lower()
        assert "Sandbox" in msg

    def test_service_returns_friendly_config_error(self):
        settings = _make_settings({"thesslstore.partner_code_sandbox": ""})
        tsvc = TheSSLStoreService(MagicMock(), settings)
        ok, msg = tsvc.validate_credentials()
        assert ok is False
        assert "Konfiguration" in msg

    def test_service_returns_friendly_network_error(self):
        import requests as req
        settings = _make_settings()
        tsvc = TheSSLStoreService(MagicMock(), settings)
        with patch.object(tsvc.client, "validate_credentials",
                          side_effect=TheSSLStoreAPIError("Timeout nach 30s")):
            ok, msg = tsvc.validate_credentials()
        assert ok is False
        assert "Timeout" in msg or "Netzwerk" in msg


# ── product_query → POST /product/query/ ─────────────────────────────────────

class TestProductQuery:
    def test_calls_product_query_endpoint(self):
        client = _make_client()
        resp_data = {
            "isError": False,
            "Message": [],
            "ProductList": [
                {
                    "ProductCode": "COMODO_DV",
                    "ProductName": "Comodo DV SSL",
                    "ProductType": "DV",
                    "VendorName": "Comodo",
                    "isDVProduct": True,
                    "isEVProduct": False,
                    "isOVProduct": False,
                    "isCodeSigning": False,
                    "isSanProduct": False,
                    "isWildCard": False,
                    "MaxSan": 0,
                    "ValidityPeriod": 12,
                }
            ],
        }
        with patch("app.services.thesslstore.client.requests.post") as mock_post:
            mock_post.return_value = _mock_response(resp_data)
            result = client.product_query()

        called_url = mock_post.call_args[0][0]
        # Muss /product/query/ sein, NICHT /order/product/list
        assert "product/query/" in called_url
        assert "order/product/list" not in called_url
        assert len(result.ProductList) == 1
        assert result.ProductList[0].ProductCode == "COMODO_DV"
        assert result.ProductList[0].isDVProduct is True

    def test_product_flags_mapped_correctly(self):
        client = _make_client()
        resp_data = {
            "isError": False,
            "Message": [],
            "ProductList": [{
                "ProductCode": "EV_CERT",
                "ProductName": "EV SSL",
                "isDVProduct": False,
                "isEVProduct": True,
                "isOVProduct": False,
                "isCodeSigning": False,
                "isSanProduct": False,
                "isWildCard": False,
            }],
        }
        with patch("app.services.thesslstore.client.requests.post",
                   return_value=_mock_response(resp_data)):
            result = client.product_query()

        p = result.ProductList[0]
        assert p.isEVProduct is True
        assert p.isDVProduct is False


# ── csr_decode → POST /csr/ ──────────────────────────────────────────────────

class TestCSRDecode:
    def test_calls_csr_endpoint_not_csr_decode(self):
        """Stellt sicher dass /csr/ verwendet wird, nicht das falsche /csr/decode/."""
        client = _make_client()
        resp_data = {
            "isError": False,
            "Message": [],
            "DomainName": "example.com",
            "DNSNames": [],
            "Organization": "Test Org",
            "Country": "DE",
            "isWildcardCSR": False,
            "isValidDomainName": True,
            "hasBadExtensions": False,
        }
        csr_pem = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBxxx\n-----END CERTIFICATE REQUEST-----"

        with patch("app.services.thesslstore.client.requests.post") as mock_post:
            mock_post.return_value = _mock_response(resp_data)
            result = client.csr_decode(csr_pem)

        called_url = mock_post.call_args[0][0]
        assert called_url.endswith("csr/")
        # NICHT csr/decode/
        assert "csr/decode" not in called_url
        assert result.DomainName == "example.com"
        assert result.isValidDomainName is True


# ── order_query → POST /order/query/ ─────────────────────────────────────────

class TestOrderQuery:
    def test_calls_order_query_endpoint(self):
        client = _make_client()
        resp_data = {
            "isError": False,
            "Message": [],
            "TheSSLStoreOrderID": "TSS-123",
            "VendorOrderID": "VEN-456",
            "PartnerOrderID": "",
            "OrderStatus": {"MajorStatus": "Active", "MinorStatus": ""},
            "CertificateStartDate": "2024-01-01",
            "CertificateEndDate": "2025-01-01",
            "CommonName": "example.com",
        }
        with patch("app.services.thesslstore.client.requests.post") as mock_post:
            mock_post.return_value = _mock_response(resp_data)
            result = client.order_query(thessl_order_id="TSS-123")

        called_url = mock_post.call_args[0][0]
        assert "order/query/" in called_url
        assert result.TheSSLStoreOrderID == "TSS-123"
        assert result.OrderStatus.MajorStatus == "Active"


# ── HTTP-Fehlerbehandlung ─────────────────────────────────────────────────────

class TestHTTPErrors:
    def test_timeout_raises_api_error_with_message(self):
        import requests as req
        client = _make_client()
        with patch("app.services.thesslstore.client.requests.post") as mock_post:
            mock_post.side_effect = req.exceptions.Timeout()
            with pytest.raises(TheSSLStoreAPIError, match="Timeout"):
                client.validate_credentials()

    def test_connection_error_raises_api_error(self):
        import requests as req
        client = _make_client()
        with patch("app.services.thesslstore.client.requests.post") as mock_post:
            mock_post.side_effect = req.exceptions.ConnectionError()
            with pytest.raises(TheSSLStoreAPIError, match="Verbindungsfehler"):
                client.product_query()

    def test_http_404_gives_endpoint_hint(self):
        """404 soll explizit auf möglichen Endpunkt-Fehler hinweisen."""
        client = _make_client()
        resp = _mock_response({}, status_code=404)
        with patch("app.services.thesslstore.client.requests.post", return_value=resp):
            with pytest.raises(TheSSLStoreAPIError, match="404"):
                client.product_query()

    def test_http_401_gives_credential_hint(self):
        client = _make_client()
        resp = _mock_response({}, status_code=401)
        with patch("app.services.thesslstore.client.requests.post", return_value=resp):
            with pytest.raises(TheSSLStoreAPIError, match="401"):
                client.validate_credentials()

    def test_invalid_json_raises_api_error(self):
        client = _make_client()
        resp = MagicMock()
        resp.status_code = 200
        resp.raise_for_status.return_value = None
        resp.json.side_effect = ValueError("no JSON")
        resp.text = "not json at all"
        with patch("app.services.thesslstore.client.requests.post", return_value=resp):
            with pytest.raises(TheSSLStoreAPIError, match="JSON"):
                client.product_query()

    def test_is_error_true_raises_with_messages(self):
        client = _make_client()
        resp_data = {
            "isError": True,
            "Message": ["Invalid credentials", "PartnerCode not found"],
            "ProductList": [],
        }
        with patch("app.services.thesslstore.client.requests.post",
                   return_value=_mock_response(resp_data)):
            with pytest.raises(TheSSLStoreAPIError) as exc_info:
                client.product_query()
        assert "Invalid credentials" in str(exc_info.value)


# ── Exceptions ────────────────────────────────────────────────────────────────

class TestExceptions:
    def test_api_error_combines_messages(self):
        err = TheSSLStoreAPIError("Fehler", api_messages=["Msg1", "Msg2"])
        s = str(err)
        assert "Msg1" in s
        assert "Msg2" in s
        assert "Fehler" in s

    def test_api_error_without_messages(self):
        err = TheSSLStoreAPIError("Nur Fehlertext")
        assert str(err) == "Nur Fehlertext"
        assert err.api_messages == []
