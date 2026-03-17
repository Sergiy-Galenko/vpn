from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class ServerProfileModel(Base):
    __tablename__ = "server_profiles"
    __table_args__ = (UniqueConstraint("name", name="uq_server_profiles_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    mode: Mapped[str] = mapped_column(String(32), nullable=False)
    host: Mapped[str | None] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=22)
    username: Mapped[str | None] = mapped_column(String(255))
    auth_method: Mapped[str] = mapped_column(String(32), nullable=False)
    private_key_path: Mapped[str | None] = mapped_column(String(1024))
    password_secret_ref: Mapped[str | None] = mapped_column(String(255))
    private_key_passphrase_ref: Mapped[str | None] = mapped_column(String(255))
    sudo_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    sudo_password_secret_ref: Mapped[str | None] = mapped_column(String(255))
    known_host_fingerprint: Mapped[str | None] = mapped_column(String(255))
    connect_timeout_sec: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_connected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class ServerConfigModel(Base):
    __tablename__ = "server_configs"
    __table_args__ = (
        UniqueConstraint(
            "server_profile_id",
            name="uq_server_configs_server_profile_id",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    server_profile_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    interface_name: Mapped[str] = mapped_column(String(64), nullable=False)
    endpoint: Mapped[str] = mapped_column(String(255), nullable=False)
    listen_port: Mapped[int] = mapped_column(Integer, nullable=False)
    subnet_cidr: Mapped[str] = mapped_column(String(64), nullable=False)
    public_interface: Mapped[str] = mapped_column(String(64), nullable=False)
    dns_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    allowed_ips_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    firewall_backend: Mapped[str | None] = mapped_column(String(32))
    config_source: Mapped[str] = mapped_column(String(32), nullable=False, default="managed")
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class ClientModel(Base):
    __tablename__ = "clients"
    __table_args__ = (
        UniqueConstraint("server_profile_id", "name", name="uq_clients_profile_name"),
        UniqueConstraint(
            "server_profile_id",
            "public_key",
            name="uq_clients_profile_public_key",
        ),
        UniqueConstraint(
            "server_profile_id",
            "address_cidr",
            name="uq_clients_profile_address_cidr",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    server_profile_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    email: Mapped[str | None] = mapped_column(String(255))
    device: Mapped[str | None] = mapped_column(String(255))
    comment: Mapped[str | None] = mapped_column(Text)
    address_cidr: Mapped[str] = mapped_column(String(64), nullable=False)
    public_key: Mapped[str] = mapped_column(String(255), nullable=False)
    preshared_key_secret_ref: Mapped[str | None] = mapped_column(String(255))
    private_key_secret_ref: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    expiry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    imported: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    latest_config_revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class ClientConfigRevisionModel(Base):
    __tablename__ = "client_config_revisions"
    __table_args__ = (
        UniqueConstraint("client_id", "revision", name="uq_client_config_revisions_client_revision"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    config_secret_ref: Mapped[str | None] = mapped_column(String(255))
    qr_png_path: Mapped[str | None] = mapped_column(String(1024))
    reason: Mapped[str] = mapped_column(String(64), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class AuditLogModel(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    server_profile_id: Mapped[str | None] = mapped_column(String(36), index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    target_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_id: Mapped[str | None] = mapped_column(String(36))
    result: Mapped[str] = mapped_column(String(32), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(128))
    error_details_json: Mapped[str | None] = mapped_column(Text)


class BackupModel(Base):
    __tablename__ = "backups"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    server_profile_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    archive_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    manifest_sha256: Mapped[str] = mapped_column(String(128), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    includes_logs: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    includes_secrets: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    restore_tested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    metadata_json: Mapped[dict[str, Any] | None] = mapped_column(JSON)


class KeyRotationModel(Base):
    __tablename__ = "key_rotations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    server_profile_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    client_id: Mapped[str | None] = mapped_column(String(36), index=True)
    scope: Mapped[str] = mapped_column(String(32), nullable=False)
    previous_revision: Mapped[int | None] = mapped_column(Integer)
    new_revision: Mapped[int | None] = mapped_column(Integer)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    result: Mapped[str] = mapped_column(String(64), nullable=False)
    backup_id: Mapped[str | None] = mapped_column(String(36))
    notes: Mapped[str | None] = mapped_column(Text)


class ImportedPeerModel(Base):
    __tablename__ = "imported_peers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    server_profile_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    imported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    source_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    peer_public_key: Mapped[str] = mapped_column(String(255), nullable=False)
    parsed_name: Mapped[str | None] = mapped_column(String(255))
    inferred_address: Mapped[str | None] = mapped_column(String(64))
    matched_client_id: Mapped[str | None] = mapped_column(String(36))
    import_status: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_block_text: Mapped[str] = mapped_column(Text, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)


class HealthSnapshotModel(Base):
    __tablename__ = "health_snapshots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    server_profile_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    service_state: Mapped[str] = mapped_column(String(32), nullable=False)
    uptime_seconds: Mapped[int | None] = mapped_column(Integer)
    active_peers: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rx_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tx_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    recent_error_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    metrics_json: Mapped[dict[str, Any] | None] = mapped_column(JSON)


class SettingModel(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(255), primary_key=True)
    value_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )
