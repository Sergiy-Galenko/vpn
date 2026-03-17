from __future__ import annotations

from dataclasses import dataclass

from wgdesk.application.services.audit_service import AuditService
from wgdesk.application.services.client_service import ClientService
from wgdesk.application.services.server_service import ServerService
from wgdesk.application.services.session_service import SessionService
from wgdesk.config import AppConfig, load_config
from wgdesk.infrastructure.db.engine import build_engine, build_session_factory, upgrade_database
from wgdesk.infrastructure.db.repositories.audit_repository import AuditLogRepository
from wgdesk.infrastructure.db.repositories.client_repository import ClientRepository
from wgdesk.infrastructure.db.repositories.server_repository import (
    ServerConfigRepository,
    ServerProfileRepository,
)
from wgdesk.infrastructure.db.repositories.settings_repository import SettingsRepository
from wgdesk.infrastructure.qr.generator import QRCodeGenerator
from wgdesk.infrastructure.secret_store.encrypted_vault import EncryptedVaultSecretStore
from wgdesk.infrastructure.secret_store.keyring_store import KeyringSecretStore


@dataclass(slots=True)
class RepositoryContainer:
    server_profiles: ServerProfileRepository
    server_configs: ServerConfigRepository
    clients: ClientRepository
    audits: AuditLogRepository
    settings: SettingsRepository


@dataclass(slots=True)
class ServiceContainer:
    audit: AuditService
    session: SessionService
    server: ServerService
    client: ClientService


@dataclass(slots=True)
class BootstrapContext:
    config: AppConfig
    repositories: RepositoryContainer
    services: ServiceContainer


def bootstrap() -> BootstrapContext:
    config = load_config()
    upgrade_database(
        config.sqlite_path,
        alembic_ini_path=config.alembic_ini_path,
        migrations_dir=config.migrations_dir,
    )
    engine = build_engine(config.sqlite_path)
    session_factory = build_session_factory(engine)

    repositories = RepositoryContainer(
        server_profiles=ServerProfileRepository(session_factory),
        server_configs=ServerConfigRepository(session_factory),
        clients=ClientRepository(session_factory),
        audits=AuditLogRepository(session_factory),
        settings=SettingsRepository(session_factory),
    )

    secret_store = KeyringSecretStore(config.app_name)
    if not secret_store.is_available():
        secret_store = EncryptedVaultSecretStore(config.vault_dir)

    audit_service = AuditService(repositories.audits)
    session_service = SessionService(
        repositories.server_profiles,
        repositories.server_configs,
        secret_store,
        audit_service,
        agent_timeout_sec=config.agent_timeout_sec,
    )
    server_service = ServerService(session_service)
    client_service = ClientService(
        session_service,
        repositories.clients,
        audit_service,
        secret_store,
        QRCodeGenerator(config.export_dir),
    )
    services = ServiceContainer(
        audit=audit_service,
        session=session_service,
        server=server_service,
        client=client_service,
    )
    return BootstrapContext(config=config, repositories=repositories, services=services)
