from __future__ import annotations


class WGDeskError(Exception):
    """Base application error."""


class ValidationFailedError(WGDeskError):
    """Raised when validation returns hard errors."""


class ConnectionFailedError(WGDeskError):
    """Raised when local or SSH session creation fails."""


class AgentTransportError(WGDeskError):
    """Raised when the agent transport cannot complete a request."""


class SecretStoreError(WGDeskError):
    """Raised for secret storage failures."""


class RepositoryError(WGDeskError):
    """Raised for persistence failures."""


class NotConnectedError(WGDeskError):
    """Raised when an operation requires an active session."""

