from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import func, select, update

from wgdesk.application.dto import CreateServerProfileInput
from wgdesk.domain.entities import ServerConfig, ServerProfile
from wgdesk.domain.enums import AuthMethod, ServerMode, SudoMode
from wgdesk.infrastructure.db.models import ServerConfigModel, ServerProfileModel


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ServerProfileRepository:
    def __init__(self, session_factory) -> None:
        self.session_factory = session_factory

    def list_all(self) -> list[ServerProfile]:
        with self.session_factory() as session:
            rows = session.scalars(
                select(ServerProfileModel).order_by(ServerProfileModel.is_default.desc(), ServerProfileModel.name)
            ).all()
            return [self._to_entity(row) for row in rows]

    def get(self, profile_id: str) -> ServerProfile | None:
        with self.session_factory() as session:
            row = session.get(ServerProfileModel, profile_id)
            return self._to_entity(row) if row is not None else None

    def save(
        self,
        data: CreateServerProfileInput,
        *,
        password_secret_ref: str | None,
        private_key_passphrase_ref: str | None,
        sudo_password_secret_ref: str | None,
    ) -> ServerProfile:
        now = utcnow()
        with self.session_factory() as session:
            existing = session.scalar(
                select(ServerProfileModel).where(ServerProfileModel.name == data.name)
            )
            if existing is None:
                total_profiles = session.scalar(select(func.count()).select_from(ServerProfileModel))
                make_default = data.is_default or total_profiles == 0
            else:
                make_default = data.is_default or existing.is_default
            if make_default:
                session.execute(update(ServerProfileModel).values(is_default=False))
            if existing is None:
                existing = ServerProfileModel(
                    id=str(uuid4()),
                    created_at=now,
                )
                session.add(existing)

            existing.name = data.name
            existing.mode = data.mode.value
            existing.host = data.host
            existing.port = data.port
            existing.username = data.username
            existing.auth_method = data.auth_method.value
            existing.private_key_path = data.private_key_path
            existing.known_host_fingerprint = data.known_host_fingerprint
            existing.password_secret_ref = password_secret_ref
            existing.private_key_passphrase_ref = private_key_passphrase_ref
            existing.sudo_mode = data.sudo_mode.value
            existing.sudo_password_secret_ref = sudo_password_secret_ref
            existing.connect_timeout_sec = 10
            existing.is_default = make_default
            existing.updated_at = now
            session.commit()
            session.refresh(existing)
            return self._to_entity(existing)

    def mark_connected(self, profile_id: str) -> None:
        with self.session_factory() as session:
            row = session.get(ServerProfileModel, profile_id)
            if row is None:
                return
            row.last_connected_at = utcnow()
            row.last_error = None
            session.commit()

    def mark_error(self, profile_id: str, message: str) -> None:
        with self.session_factory() as session:
            row = session.get(ServerProfileModel, profile_id)
            if row is None:
                return
            row.last_error = message
            row.updated_at = utcnow()
            session.commit()

    @staticmethod
    def _to_entity(row: ServerProfileModel) -> ServerProfile:
        return ServerProfile(
            id=row.id,
            name=row.name,
            mode=ServerMode(row.mode),
            host=row.host,
            port=row.port,
            username=row.username,
            auth_method=AuthMethod(row.auth_method),
            private_key_path=row.private_key_path,
            password_secret_ref=row.password_secret_ref,
            private_key_passphrase_ref=row.private_key_passphrase_ref,
            sudo_mode=SudoMode(row.sudo_mode),
            sudo_password_secret_ref=row.sudo_password_secret_ref,
            known_host_fingerprint=row.known_host_fingerprint,
            connect_timeout_sec=row.connect_timeout_sec,
            is_default=row.is_default,
            last_connected_at=row.last_connected_at,
            last_error=row.last_error,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )


class ServerConfigRepository:
    def __init__(self, session_factory) -> None:
        self.session_factory = session_factory

    def get_for_profile(self, profile_id: str) -> ServerConfig | None:
        with self.session_factory() as session:
            row = session.scalar(
                select(ServerConfigModel).where(ServerConfigModel.server_profile_id == profile_id)
            )
            return self._to_entity(row) if row is not None else None

    def save(self, profile_id: str, data: CreateServerProfileInput) -> ServerConfig:
        now = utcnow()
        with self.session_factory() as session:
            row = session.scalar(
                select(ServerConfigModel).where(ServerConfigModel.server_profile_id == profile_id)
            )
            if row is None:
                row = ServerConfigModel(
                    id=str(uuid4()),
                    server_profile_id=profile_id,
                    created_at=now,
                )
                session.add(row)

            row.interface_name = data.interface_name
            row.endpoint = data.endpoint
            row.listen_port = data.listen_port
            row.subnet_cidr = data.subnet_cidr
            row.public_interface = data.public_interface
            row.dns_json = data.dns_servers
            row.allowed_ips_json = ["0.0.0.0/0", "::/0"]
            row.firewall_backend = None
            row.config_source = "managed"
            row.updated_at = now
            session.commit()
            session.refresh(row)
            return self._to_entity(row)

    @staticmethod
    def _to_entity(row: ServerConfigModel) -> ServerConfig:
        return ServerConfig(
            id=row.id,
            server_profile_id=row.server_profile_id,
            interface_name=row.interface_name,
            endpoint=row.endpoint,
            listen_port=row.listen_port,
            subnet_cidr=row.subnet_cidr,
            public_interface=row.public_interface,
            dns_servers=list(row.dns_json or []),
            allowed_ips=list(row.allowed_ips_json or []),
            firewall_backend=row.firewall_backend,
            config_source=row.config_source,
            version=row.version,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )
