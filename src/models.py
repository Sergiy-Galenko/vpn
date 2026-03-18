from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class VPNManagerError(Exception):
    """Raised for expected application-level errors."""


class ClientStatus(StrEnum):
    """Supported lifecycle states for WireGuard clients."""

    ACTIVE = "active"
    DISABLED = "disabled"
    EXPIRED = "expired"
    IMPORTED = "imported"


class AuthMethod(StrEnum):
    """Supported SSH authentication methods."""

    SSH_KEY = "ssh_key"
    PASSWORD = "password"


class SeverityLevel(StrEnum):
    """Validation message severity."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(slots=True)
class ClientRecord:
    """Stored client metadata."""

    name: str
    address: str
    public_key: str
    config_path: str | None = None
    private_key_path: str | None = None
    created_at: str = ""
    email: str | None = None
    device: str | None = None
    comment: str | None = None
    status: ClientStatus = ClientStatus.ACTIVE
    expiry_at: str | None = None
    updated_at: str | None = None
    last_used_at: str | None = None
    imported: bool = False
    qr_code_path: str | None = None
    config_revision: int = 1

    def __post_init__(self) -> None:
        if not self.updated_at:
            self.updated_at = self.created_at


@dataclass(slots=True)
class ConnectedClient:
    """Runtime WireGuard peer status."""

    public_key: str
    name: str | None
    address: str | None
    endpoint: str
    latest_handshake: int
    transfer_rx: int
    transfer_tx: int


@dataclass(slots=True)
class RemoteProfileRecord:
    """Stored SSH profile for remote Ubuntu control."""

    name: str
    host: str
    port: int
    username: str
    auth_method: AuthMethod
    private_key_path: str | None = None
    password_secret_key: str | None = None
    sudo_password_secret_key: str | None = None
    known_host_fingerprint: str | None = None
    connect_timeout_seconds: int = 10
    enabled: bool = True
    use_sudo: bool = True
    created_at: str = ""
    updated_at: str = ""


@dataclass(slots=True)
class AuditLogRecord:
    """Structured audit event stored in SQLite."""

    timestamp: str
    action: str
    target: str
    result: str
    details: str
    actor: str = "desktop"
    source: str = "local"
    error_details: str | None = None
    log_id: int | None = None


@dataclass(slots=True)
class BackupRecord:
    """Stored metadata for a created backup archive."""

    archive_path: str
    created_at: str
    manifest_json: str
    scope: str = "local"
    note: str | None = None
    backup_id: int | None = None


@dataclass(slots=True)
class ImportedPeerRecord:
    """Raw imported peer block preserved during config import."""

    imported_at: str
    source_path: str
    public_key: str
    address: str | None
    inferred_name: str | None
    raw_block: str
    peer_id: int | None = None


@dataclass(slots=True)
class ValidationIssue:
    """Human-readable validation issue."""

    code: str
    message: str
    severity: SeverityLevel
