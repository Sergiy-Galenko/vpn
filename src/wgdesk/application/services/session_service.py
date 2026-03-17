from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from wgdesk.application.dto import ConnectionStateDTO, CreateServerProfileInput, ServerStatusDTO
from wgdesk.application.errors import ConnectionFailedError, NotConnectedError
from wgdesk.domain.entities import ServerConfig, ServerProfile
from wgdesk.domain.enums import ActionResult, ServerMode, TargetType
from wgdesk.infrastructure.agent.transport import AgentTransport
from wgdesk.infrastructure.db.repositories.server_repository import (
    ServerConfigRepository,
    ServerProfileRepository,
)
from wgdesk.infrastructure.executors.local import LocalCommandExecutor, LocalExecutorOptions
from wgdesk.infrastructure.executors.ssh import SSHCommandExecutor, SSHExecutorOptions
from wgdesk.infrastructure.secret_store.base import SecretStore


@dataclass(slots=True)
class ActiveSession:
    profile: ServerProfile
    config: ServerConfig
    transport: AgentTransport
    connected_at: datetime
    last_status: ServerStatusDTO


class SessionService:
    def __init__(
        self,
        profile_repository: ServerProfileRepository,
        config_repository: ServerConfigRepository,
        secret_store: SecretStore,
        audit_service,
        *,
        agent_timeout_sec: int,
    ) -> None:
        self.profile_repository = profile_repository
        self.config_repository = config_repository
        self.secret_store = secret_store
        self.audit_service = audit_service
        self.agent_timeout_sec = agent_timeout_sec
        self._active_session: ActiveSession | None = None

    def list_profiles(self) -> list[ServerProfile]:
        return self.profile_repository.list_all()

    def save_profile(self, data: CreateServerProfileInput) -> ServerProfile:
        password_secret_ref = (
            self.secret_store.put(data.password) if data.password else None
        )
        private_key_passphrase_ref = (
            self.secret_store.put(data.private_key_passphrase)
            if data.private_key_passphrase
            else None
        )
        sudo_password_secret_ref = (
            self.secret_store.put(data.sudo_password) if data.sudo_password else None
        )
        profile = self.profile_repository.save(
            data,
            password_secret_ref=password_secret_ref,
            private_key_passphrase_ref=private_key_passphrase_ref,
            sudo_password_secret_ref=sudo_password_secret_ref,
        )
        self.config_repository.save(profile.id, data)
        self.audit_service.log(
            server_profile_id=profile.id,
            action="save_profile",
            actor="desktop",
            source="gui",
            target_type=TargetType.SERVER.value,
            target_id=profile.id,
            result=ActionResult.SUCCESS,
            message=f"Saved profile {profile.name}",
        )
        return profile

    def connect(self, profile_id: str) -> tuple[ConnectionStateDTO, ServerStatusDTO]:
        profile = self.profile_repository.get(profile_id)
        if profile is None:
            raise ConnectionFailedError(f"Unknown profile: {profile_id}")
        config = self.config_repository.get_for_profile(profile_id)
        if config is None:
            raise ConnectionFailedError(f"Missing server config for profile: {profile.name}")

        try:
            executor = self._build_executor(profile)
            executor.test_connection()
            transport = AgentTransport(executor, timeout_sec=self.agent_timeout_sec)
            transport.ping()
            status_payload = transport.execute(
                "server_status",
                {
                    "interface_name": config.interface_name,
                    "endpoint": config.endpoint,
                    "listen_port": config.listen_port,
                },
            )
            status = ServerStatusDTO(
                hostname=status_payload["hostname"],
                platform=status_payload["platform"],
                python_version=status_payload["python_version"],
                service_state=status_payload["service_state"],
                interface_name=status_payload["interface_name"],
                endpoint=status_payload["endpoint"],
                listen_port=int(status_payload["listen_port"]),
                active_peers=int(status_payload["active_peers"]),
                uptime_seconds=status_payload.get("uptime_seconds"),
                firewall_backend=status_payload.get("firewall_backend", "unknown"),
                last_error=status_payload.get("last_error"),
                capabilities=list(status_payload.get("capabilities", [])),
            )
        except Exception as exc:
            self.profile_repository.mark_error(profile_id, str(exc))
            self.audit_service.log(
                server_profile_id=profile.id,
                action="connect",
                actor="desktop",
                source="gui",
                target_type=TargetType.SESSION.value,
                target_id=profile.id,
                result=ActionResult.FAILURE,
                message=f"Failed to connect to {profile.name}",
                error_code=exc.__class__.__name__,
                error_details={"message": str(exc)},
            )
            raise ConnectionFailedError(str(exc)) from exc

        self.profile_repository.mark_connected(profile_id)
        state = ConnectionStateDTO(
            profile_id=profile.id,
            profile_name=profile.name,
            mode=profile.mode,
            connected=True,
            host_label=profile.host or "local-agent",
            service_state=status.service_state,
            endpoint=status.endpoint,
            interface_name=status.interface_name,
            active_peers=status.active_peers,
            uptime_seconds=status.uptime_seconds,
            last_error=status.last_error,
        )
        self._active_session = ActiveSession(
            profile=profile,
            config=config,
            transport=transport,
            connected_at=datetime.now(timezone.utc),
            last_status=status,
        )
        self.audit_service.log(
            server_profile_id=profile.id,
            action="connect",
            actor="desktop",
            source="gui",
            target_type=TargetType.SESSION.value,
            target_id=profile.id,
            result=ActionResult.SUCCESS,
            message=f"Connected to {profile.name}",
        )
        return state, status

    def disconnect(self) -> None:
        if self._active_session is None:
            return
        self.audit_service.log(
            server_profile_id=self._active_session.profile.id,
            action="disconnect",
            actor="desktop",
            source="gui",
            target_type=TargetType.SESSION.value,
            target_id=self._active_session.profile.id,
            result=ActionResult.SUCCESS,
            message=f"Disconnected from {self._active_session.profile.name}",
        )
        self._active_session = None

    def require_session(self) -> ActiveSession:
        if self._active_session is None:
            raise NotConnectedError("Connect to a server first.")
        return self._active_session

    def current_connection_state(self) -> ConnectionStateDTO | None:
        if self._active_session is None:
            return None
        session = self._active_session
        return ConnectionStateDTO(
            profile_id=session.profile.id,
            profile_name=session.profile.name,
            mode=session.profile.mode,
            connected=True,
            host_label=session.profile.host or "local-agent",
            service_state=session.last_status.service_state,
            endpoint=session.last_status.endpoint,
            interface_name=session.last_status.interface_name,
            active_peers=session.last_status.active_peers,
            uptime_seconds=session.last_status.uptime_seconds,
            last_error=session.last_status.last_error,
        )

    def _build_executor(self, profile: ServerProfile):
        if profile.mode == ServerMode.LOCAL:
            sudo_password = (
                self.secret_store.get(profile.sudo_password_secret_ref)
                if profile.sudo_password_secret_ref
                else None
            )
            return LocalCommandExecutor(LocalExecutorOptions(sudo_password=sudo_password))

        if profile.host is None or profile.username is None:
            raise ConnectionFailedError("SSH profile requires host and username.")

        password = (
            self.secret_store.get(profile.password_secret_ref)
            if profile.password_secret_ref
            else None
        )
        private_key_passphrase = (
            self.secret_store.get(profile.private_key_passphrase_ref)
            if profile.private_key_passphrase_ref
            else None
        )
        sudo_password = (
            self.secret_store.get(profile.sudo_password_secret_ref)
            if profile.sudo_password_secret_ref
            else None
        )
        return SSHCommandExecutor(
            SSHExecutorOptions(
                host=profile.host,
                port=profile.port,
                username=profile.username,
                password=password,
                private_key_path=profile.private_key_path,
                private_key_passphrase=private_key_passphrase,
                sudo_password=sudo_password,
                known_host_fingerprint=profile.known_host_fingerprint,
                timeout_sec=profile.connect_timeout_sec,
            )
        )
