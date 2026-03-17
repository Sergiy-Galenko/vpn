from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from wgdesk.domain.enums import (
    ActionResult,
    AuthMethod,
    ClientStatus,
    ServerMode,
    SeverityLevel,
    SudoMode,
)


@dataclass(slots=True)
class ValidationIssueDTO:
    code: str
    message: str
    severity: SeverityLevel


@dataclass(slots=True)
class CreateServerProfileInput:
    name: str
    mode: ServerMode
    interface_name: str
    endpoint: str
    listen_port: int
    subnet_cidr: str
    public_interface: str
    dns_servers: list[str]
    host: str | None = None
    port: int = 22
    username: str | None = None
    auth_method: AuthMethod = AuthMethod.NONE
    private_key_path: str | None = None
    known_host_fingerprint: str | None = None
    password: str | None = None
    private_key_passphrase: str | None = None
    sudo_mode: SudoMode = SudoMode.NONE
    sudo_password: str | None = None
    is_default: bool = False


@dataclass(slots=True)
class ConnectionStateDTO:
    profile_id: str
    profile_name: str
    mode: ServerMode
    connected: bool
    host_label: str
    service_state: str
    endpoint: str
    interface_name: str
    active_peers: int
    uptime_seconds: int | None
    last_error: str | None = None


@dataclass(slots=True)
class ServerStatusDTO:
    hostname: str
    platform: str
    python_version: str
    service_state: str
    interface_name: str
    endpoint: str
    listen_port: int
    active_peers: int
    uptime_seconds: int | None
    firewall_backend: str
    last_error: str | None
    capabilities: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AddClientInput:
    name: str
    email: str | None = None
    device: str | None = None
    comment: str | None = None
    expiry_at: datetime | None = None


@dataclass(slots=True)
class ClientViewDTO:
    id: str
    name: str
    email: str | None
    device: str | None
    comment: str | None
    address_cidr: str
    status: ClientStatus
    expiry_at: datetime | None
    created_at: datetime
    updated_at: datetime
    last_used_at: datetime | None
    config_available: bool
    qr_png_path: str | None


@dataclass(slots=True)
class ClientConfigExportDTO:
    client_id: str
    config_text: str
    qr_png_path: str


@dataclass(slots=True)
class AuditLogDTO:
    id: str
    timestamp: datetime
    action: str
    actor: str
    source: str
    target_type: str
    target_id: str | None
    result: ActionResult
    message: str
    error_code: str | None
    error_details: str | None
