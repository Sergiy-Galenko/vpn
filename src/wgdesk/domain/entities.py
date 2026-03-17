from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from wgdesk.domain.enums import ActionResult, AuthMethod, ClientStatus, ServerMode, SudoMode


@dataclass(slots=True)
class ServerProfile:
    id: str
    name: str
    mode: ServerMode
    host: str | None
    port: int
    username: str | None
    auth_method: AuthMethod
    private_key_path: str | None
    password_secret_ref: str | None
    private_key_passphrase_ref: str | None
    sudo_mode: SudoMode
    sudo_password_secret_ref: str | None
    known_host_fingerprint: str | None
    connect_timeout_sec: int
    is_default: bool
    last_connected_at: datetime | None
    last_error: str | None
    created_at: datetime
    updated_at: datetime


@dataclass(slots=True)
class ServerConfig:
    id: str
    server_profile_id: str
    interface_name: str
    endpoint: str
    listen_port: int
    subnet_cidr: str
    public_interface: str
    dns_servers: list[str]
    allowed_ips: list[str]
    firewall_backend: str | None
    config_source: str
    version: int
    created_at: datetime
    updated_at: datetime


@dataclass(slots=True)
class Client:
    id: str
    server_profile_id: str
    name: str
    email: str | None
    device: str | None
    comment: str | None
    address_cidr: str
    public_key: str
    preshared_key_secret_ref: str | None
    private_key_secret_ref: str | None
    status: ClientStatus
    expiry_at: datetime | None
    created_at: datetime
    updated_at: datetime
    last_used_at: datetime | None
    disabled_at: datetime | None
    imported: bool
    latest_config_revision: int


@dataclass(slots=True)
class ClientConfigRevision:
    id: str
    client_id: str
    revision: int
    config_secret_ref: str | None
    qr_png_path: str | None
    reason: str
    is_active: bool
    created_at: datetime


@dataclass(slots=True)
class AuditLogEntry:
    id: str
    timestamp: datetime
    actor: str
    source: str
    action: str
    target_type: str
    target_id: str | None
    result: ActionResult
    message: str
    error_code: str | None
    error_details_json: str | None


@dataclass(slots=True)
class ServerSession:
    profile: ServerProfile
    config: ServerConfig
    connected_at: datetime
    hostname: str
    service_state: str
    last_error: str | None = None
    capabilities: list[str] = field(default_factory=list)

