"""Exceptions für TheSSLStore-API-Integration."""


class TheSSLStoreError(Exception):
    """Basis-Exception für alle TheSSLStore-Fehler."""


class TheSSLStoreConfigError(TheSSLStoreError):
    """Partner Code oder Auth Token nicht konfiguriert."""


class TheSSLStoreAPIError(TheSSLStoreError):
    """HTTP-Fehler oder API-Level-Fehler (isError=true)."""

    def __init__(self, message: str, api_messages: list[str] | None = None):
        super().__init__(message)
        self.api_messages = api_messages or []

    def __str__(self) -> str:
        if self.api_messages:
            return f"{super().__str__()} – {'; '.join(self.api_messages)}"
        return super().__str__()


class TheSSLStoreOrderError(TheSSLStoreError):
    """Fehler beim Anlegen oder Validieren einer Bestellung."""
