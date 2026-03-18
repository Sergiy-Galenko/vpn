from __future__ import annotations

import base64
import ipaddress
import json
import logging
import os
import re
import shutil
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.config import AppConfig
from src.models import (
    AuditLogRecord,
    AuthMethod,
    BackupRecord,
    ClientRecord,
    ClientStatus,
    ConnectedClient,
    ImportedPeerRecord,
    RemoteProfileRecord,
    SeverityLevel,
    ValidationIssue,
    VPNManagerError,
)
from src.qr_export import generate_qr_code
from src.remote_control import SSHRemoteController
from src.secret_store import SecretStore
from src.storage import ClientStorage
from src.utils import (
    ensure_linux,
    ensure_root,
    is_linux,
    is_root,
    replace_file_atomically,
    run_command,
    utc_now_iso,
    validate_client_name,
    write_text_file,
)
from src.wireguard_parser import parse_wireguard_peers

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import x25519
except ImportError:  # pragma: no cover - optional dependency at runtime
    x25519 = None
    serialization = None


PLACEHOLDER_ENDPOINT = "your.server.ip.or.dns"


class WireGuardManager:
    """High-level WireGuard management workflow for local and SSH-backed control."""

    def __init__(self, config: AppConfig, storage: ClientStorage) -> None:
        self.config = config
        self.storage = storage
        self.secret_store = SecretStore(config.data_dir)
        self.logger = logging.getLogger(self.__class__.__name__)

        self.config.data_dir.mkdir(parents=True, exist_ok=True)
        self.config.server_configs_dir.mkdir(parents=True, exist_ok=True)
        self.config.client_configs_dir.mkdir(parents=True, exist_ok=True)
        self.config.keys_dir.mkdir(parents=True, exist_ok=True)
        self.config.client_private_keys_dir.mkdir(parents=True, exist_ok=True)
        self.backups_dir.mkdir(parents=True, exist_ok=True)
        self.qr_codes_dir.mkdir(parents=True, exist_ok=True)
        self.storage.initialize()

    def update_config(self, config: AppConfig) -> None:
        """Replace runtime config after the user updates editable VPN settings."""

        self.config = config
        self.storage.database_path = config.database_path
        self.storage.client_private_keys_dir = config.client_private_keys_dir
        self.config.data_dir.mkdir(parents=True, exist_ok=True)
        self.config.server_configs_dir.mkdir(parents=True, exist_ok=True)
        self.config.client_configs_dir.mkdir(parents=True, exist_ok=True)
        self.config.keys_dir.mkdir(parents=True, exist_ok=True)
        self.config.client_private_keys_dir.mkdir(parents=True, exist_ok=True)
        self.backups_dir.mkdir(parents=True, exist_ok=True)
        self.qr_codes_dir.mkdir(parents=True, exist_ok=True)
        self.storage.initialize()
        self.logger.info("Runtime VPN configuration updated.")

    @property
    def service_name(self) -> str:
        return f"wg-quick@{self.config.interface_name}"

    @property
    def server_private_key_path(self) -> Path:
        return self.config.keys_dir / "server_private.key"

    @property
    def server_public_key_path(self) -> Path:
        return self.config.keys_dir / "server_public.key"

    @property
    def backups_dir(self) -> Path:
        return self.config.data_dir / "backups"

    @property
    def qr_codes_dir(self) -> Path:
        return self.config.client_configs_dir / "qr"

    @property
    def remote_profile(self) -> RemoteProfileRecord | None:
        profile = self.storage.get_remote_profile()
        if profile is None or not profile.enabled:
            return None
        return profile

    def has_remote_control(self) -> bool:
        return self.remote_profile is not None

    def can_control_vpn(self) -> bool:
        return is_linux() or self.has_remote_control()

    def control_target_summary(self) -> str:
        if self.remote_profile is not None:
            return f"Remote SSH ({self.remote_profile.username}@{self.remote_profile.host})"
        if is_linux():
            return "Local Linux host"
        return "No active control channel"

    def needs_first_run_wizard(self) -> bool:
        return (
            self.config.endpoint == PLACEHOLDER_ENDPOINT
            and self.remote_profile is None
            and not self.storage.list_clients()
        )

    def save_remote_profile(
        self,
        *,
        host: str,
        username: str,
        port: int = 22,
        auth_method: AuthMethod = AuthMethod.SSH_KEY,
        private_key_path: str | None = None,
        password: str | None = None,
        sudo_password: str | None = None,
        known_host_fingerprint: str | None = None,
        connect_timeout_seconds: int = 10,
        enabled: bool = True,
        use_sudo: bool = True,
        profile_name: str = "default",
    ) -> RemoteProfileRecord:
        if not host.strip():
            raise VPNManagerError("Remote host cannot be empty.")
        if not username.strip():
            raise VPNManagerError("Remote username cannot be empty.")
        if port < 1 or port > 65535:
            raise VPNManagerError("Remote SSH port must be between 1 and 65535.")
        if auth_method == AuthMethod.SSH_KEY and not (private_key_path or "").strip():
            raise VPNManagerError("SSH key authentication requires a private key path.")
        if auth_method == AuthMethod.PASSWORD and not (password or "").strip():
            raise VPNManagerError("Password authentication requires a password.")

        timestamp = utc_now_iso()
        password_secret_key = None
        sudo_secret_key = None

        if password:
            password_secret_key = f"remote:{profile_name}:ssh_password"
            self.secret_store.set(password_secret_key, password)
        if sudo_password:
            sudo_secret_key = f"remote:{profile_name}:sudo_password"
            self.secret_store.set(sudo_secret_key, sudo_password)

        profile = RemoteProfileRecord(
            name=profile_name,
            host=host.strip(),
            port=port,
            username=username.strip(),
            auth_method=auth_method,
            private_key_path=private_key_path.strip() if private_key_path else None,
            password_secret_key=password_secret_key,
            sudo_password_secret_key=sudo_secret_key,
            known_host_fingerprint=known_host_fingerprint.strip() if known_host_fingerprint else None,
            connect_timeout_seconds=connect_timeout_seconds,
            enabled=enabled,
            use_sudo=use_sudo,
            created_at=timestamp,
            updated_at=timestamp,
        )
        self.storage.save_remote_profile(profile)
        self._audit(
            "save_remote_profile",
            "remote-profile",
            "success",
            f"Saved remote profile for {profile.username}@{profile.host}.",
            source="settings",
        )
        return profile

    def clear_remote_profile(self) -> None:
        profile = self.storage.get_remote_profile()
        if profile is None:
            return
        if profile.password_secret_key:
            self.secret_store.delete(profile.password_secret_key)
        if profile.sudo_password_secret_key:
            self.secret_store.delete(profile.sudo_password_secret_key)
        self.storage.clear_remote_profile()
        self._audit(
            "clear_remote_profile",
            "remote-profile",
            "success",
            "Remote SSH profile removed.",
            source="settings",
        )

    def test_remote_connection(self) -> dict[str, object]:
        controller = self._remote_controller()
        try:
            payload = controller.ping()
            status = controller.execute(
                "server_status",
                {
                    "service_name": self.service_name,
                    "interface_name": self.config.interface_name,
                },
                sudo=self.remote_profile.use_sudo if self.remote_profile else False,
            )
        finally:
            controller.close()

        merged = {**payload, **status}
        self._audit(
            "test_remote_connection",
            "remote-profile",
            "success",
            f"Remote host {self.remote_profile.host if self.remote_profile else 'unknown'} is reachable.",
            source="remote",
        )
        return merged

    def install_wireguard(self) -> None:
        """Install packages, enable forwarding, and write the server config."""

        issues = self.validate_environment()
        blocking = [issue for issue in issues if issue.severity == SeverityLevel.ERROR]
        if blocking:
            raise VPNManagerError(
                "Environment validation failed:\n"
                + "\n".join(f"- {issue.message}" for issue in blocking)
            )

        if self.remote_profile is not None:
            controller = self._remote_controller()
            try:
                controller.execute(
                    "install_wireguard",
                    {
                        "server_port": self.config.server_port,
                        "sysctl_config_path": str(self.config.sysctl_config_path),
                        "service_name": self.service_name,
                    },
                    sudo=True,
                )
                self._sync_remote_config(self.create_server_config(), service_action="none")
                controller.execute(
                    "service_action",
                    {"service_name": self.service_name, "action": "enable"},
                    sudo=True,
                )
            finally:
                controller.close()
            self._audit(
                "install_wireguard",
                "server",
                "success",
                f"Installed WireGuard on remote host {self.remote_profile.host}.",
                source="remote",
            )
            self.logger.info("Remote WireGuard installation completed.")
            return

        ensure_linux("Installing WireGuard locally")
        ensure_root()

        run_command(["apt-get", "update"])
        run_command(["apt-get", "install", "-y", "wireguard", "wireguard-tools"])
        self.enable_ip_forwarding()
        self.ensure_server_keys()
        self._configure_local_firewall()
        self.sync_server_config()
        run_command(["systemctl", "enable", self.service_name])
        self._audit("install_wireguard", "server", "success", "Installed WireGuard locally.")
        self.logger.info("WireGuard installation and configuration completed.")

    def enable_ip_forwarding(self) -> None:
        """Enable IPv4 and IPv6 forwarding through sysctl."""

        ensure_linux("Enabling IP forwarding locally")
        ensure_root()

        content = (
            "net.ipv4.ip_forward = 1\n"
            "net.ipv6.conf.all.forwarding = 1\n"
        )
        write_text_file(self.config.sysctl_config_path, content, mode=0o644)
        run_command(["sysctl", "--system"])

    def generate_keypair(self) -> tuple[str, str]:
        """Generate a WireGuard private and public key pair."""

        if shutil.which("wg"):
            private_key = run_command(["wg", "genkey"]).stdout.strip()
            if private_key:
                public_key = run_command(
                    ["wg", "pubkey"],
                    input_text=f"{private_key}\n",
                ).stdout.strip()
                if public_key:
                    return private_key, public_key

        if x25519 is None or serialization is None:
            raise VPNManagerError(
                "Unable to generate WireGuard keys. Install wireguard-tools or cryptography."
            )

        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return (
            base64.b64encode(private_bytes).decode("ascii"),
            base64.b64encode(public_bytes).decode("ascii"),
        )

    def ensure_server_keys(self) -> tuple[str, str]:
        """Load existing server keys or generate them once."""

        if self.server_private_key_path.exists() and self.server_public_key_path.exists():
            return (
                self.server_private_key_path.read_text(encoding="utf-8").strip(),
                self.server_public_key_path.read_text(encoding="utf-8").strip(),
            )

        private_key, public_key = self.generate_keypair()
        write_text_file(self.server_private_key_path, f"{private_key}\n")
        write_text_file(self.server_public_key_path, f"{public_key}\n")
        return private_key, public_key

    def create_server_config(self) -> Path:
        """Rebuild the full local server config from current storage."""

        self._expire_clients_if_needed()
        server_private_key, _ = self.ensure_server_keys()
        clients = self._renderable_clients()

        lines = [
            "[Interface]",
            f"Address = {self.config.server_interface}",
            f"ListenPort = {self.config.server_port}",
            f"PrivateKey = {server_private_key}",
            "SaveConfig = false",
            (
                "PostUp = "
                f"iptables -t nat -A POSTROUTING -s {self.config.network} "
                f"-o {self.config.public_interface} -j MASQUERADE"
            ),
            (
                "PostDown = "
                f"iptables -t nat -D POSTROUTING -s {self.config.network} "
                f"-o {self.config.public_interface} -j MASQUERADE"
            ),
            "",
        ]

        for client in clients:
            lines.extend(
                [
                    "[Peer]",
                    f"PublicKey = {client.public_key}",
                    f"AllowedIPs = {client.address}",
                    "",
                ]
            )

        content = "\n".join(lines).rstrip() + "\n"
        write_text_file(self.config.server_config_path, content)
        self.logger.info("Local server config written to %s", self.config.server_config_path)
        return self.config.server_config_path

    def sync_server_config(self, local_config_path: Path | None = None) -> None:
        """Apply the generated server config locally or to the remote Ubuntu host."""

        if self.remote_profile is not None:
            self._sync_remote_config(local_config_path or self.create_server_config(), service_action="none")
            return

        ensure_linux("Syncing the server config locally")
        ensure_root()

        local_config = local_config_path or self.create_server_config()
        replace_file_atomically(local_config, self.config.system_server_config)
        self.logger.info("Server config synced to %s", self.config.system_server_config)

    def add_client(
        self,
        name: str,
        *,
        email: str | None = None,
        device: str | None = None,
        comment: str | None = None,
        expiry_at: str | None = None,
    ) -> ClientRecord:
        """Generate a client, save it in SQLite, rebuild config, and export QR."""

        client_name = validate_client_name(name)
        if self.storage.get_client(client_name):
            raise VPNManagerError(f"Client '{client_name}' already exists.")
        if self.config.endpoint == PLACEHOLDER_ENDPOINT:
            raise VPNManagerError("Set WG_ENDPOINT before creating ready-to-use client configs.")

        private_key, public_key = self.generate_keypair()
        _, server_public_key = self.ensure_server_keys()
        client_address = self._allocate_client_address()
        client_config_path = self.config.client_configs_dir / f"{client_name}.conf"
        private_key_path = self.config.client_private_keys_dir / f"{client_name}.key"
        qr_code_path = self.qr_codes_dir / f"{client_name}.png"
        now = utc_now_iso()
        client = ClientRecord(
            name=client_name,
            address=client_address,
            public_key=public_key,
            config_path=str(client_config_path),
            private_key_path=str(private_key_path),
            created_at=now,
            email=email,
            device=device,
            comment=comment,
            expiry_at=expiry_at,
            updated_at=now,
            status=ClientStatus.ACTIVE,
            imported=False,
            qr_code_path=str(qr_code_path),
            config_revision=1,
        )

        client_config = self._build_client_config(
            private_key=private_key,
            client_address=client_address,
            server_public_key=server_public_key,
        )
        write_text_file(private_key_path, f"{private_key}\n")
        write_text_file(client_config_path, client_config)
        generate_qr_code(client_config, qr_code_path)

        try:
            self.storage.add_client(client)
            local_config_path = self.create_server_config()
            self._sync_runtime_config(local_config_path)
        except VPNManagerError as exc:
            self._rollback_added_client(client_name, client_config_path, private_key_path, qr_code_path)
            self._audit("add_client", client_name, "failure", f"Failed to add client '{client_name}'.", error=str(exc))
            raise
        except OSError as exc:
            self._rollback_added_client(client_name, client_config_path, private_key_path, qr_code_path)
            self._audit("add_client", client_name, "failure", f"Failed to add client '{client_name}'.", error=str(exc))
            raise VPNManagerError(
                f"Failed to create client files for '{client_name}'."
            ) from exc

        self._audit("add_client", client_name, "success", f"Client '{client_name}' created.")
        self.logger.info("Client '%s' created at %s", client_name, client_config_path)
        return client

    def remove_client(self, name: str) -> None:
        """Remove a client from SQLite and rebuild the server config."""

        client_name = validate_client_name(name)
        existing = self.storage.get_client(client_name)
        if existing is None:
            raise VPNManagerError(f"Client '{client_name}' was not found.")

        config_path = Path(existing.config_path) if existing.config_path else None
        private_key_path = Path(existing.private_key_path) if existing.private_key_path else None
        qr_code_path = Path(existing.qr_code_path) if existing.qr_code_path else None
        config_backup = (
            config_path.read_text(encoding="utf-8")
            if config_path is not None and config_path.exists()
            else None
        )
        private_key_backup = (
            private_key_path.read_text(encoding="utf-8")
            if private_key_path is not None and private_key_path.exists()
            else None
        )
        qr_backup = qr_code_path.read_bytes() if qr_code_path is not None and qr_code_path.exists() else None

        self.storage.remove_client(client_name)
        try:
            if config_path is not None:
                config_path.unlink(missing_ok=True)
            if private_key_path is not None:
                private_key_path.unlink(missing_ok=True)
            if qr_code_path is not None:
                qr_code_path.unlink(missing_ok=True)
            local_config_path = self.create_server_config()
            self._sync_runtime_config(local_config_path)
        except VPNManagerError as exc:
            self._restore_removed_client(existing, config_backup, private_key_backup, qr_backup)
            self._audit("remove_client", client_name, "failure", f"Failed to remove client '{client_name}'.", error=str(exc))
            raise
        except OSError as exc:
            self._restore_removed_client(existing, config_backup, private_key_backup, qr_backup)
            self._audit("remove_client", client_name, "failure", f"Failed to remove client '{client_name}'.", error=str(exc))
            raise VPNManagerError(
                f"Failed to remove client files for '{client_name}'."
            ) from exc

        self._audit("remove_client", client_name, "success", f"Client '{client_name}' removed.")
        self.logger.info("Client '%s' removed.", client_name)

    def disable_client(self, name: str) -> ClientRecord:
        client = self.storage.get_client(validate_client_name(name))
        if client is None:
            raise VPNManagerError(f"Client '{name}' was not found.")

        if client.status == ClientStatus.DISABLED:
            return client

        previous_status = client.status
        updated = self.storage.set_client_status(client.name, ClientStatus.DISABLED)
        try:
            local_config_path = self.create_server_config()
            self._sync_runtime_config(local_config_path)
        except VPNManagerError as exc:
            self.storage.set_client_status(client.name, previous_status)
            self.create_server_config()
            self._audit("disable_client", client.name, "failure", f"Failed to disable client '{client.name}'.", error=str(exc))
            raise

        self._audit("disable_client", client.name, "success", f"Client '{client.name}' disabled.")
        return updated

    def enable_client(self, name: str) -> ClientRecord:
        client = self.storage.get_client(validate_client_name(name))
        if client is None:
            raise VPNManagerError(f"Client '{name}' was not found.")
        if client.status == ClientStatus.EXPIRED:
            raise VPNManagerError(
                f"Client '{client.name}' is expired. Update its expiry date before enabling it again."
            )
        if client.status == ClientStatus.ACTIVE:
            return client

        previous_status = client.status
        updated = self.storage.set_client_status(client.name, ClientStatus.ACTIVE)
        try:
            local_config_path = self.create_server_config()
            self._sync_runtime_config(local_config_path)
        except VPNManagerError as exc:
            self.storage.set_client_status(client.name, previous_status)
            self.create_server_config()
            self._audit("enable_client", client.name, "failure", f"Failed to enable client '{client.name}'.", error=str(exc))
            raise

        self._audit("enable_client", client.name, "success", f"Client '{client.name}' enabled.")
        return updated

    def list_clients(self) -> list[ClientRecord]:
        """Return all stored clients."""

        self._expire_clients_if_needed()
        return self.storage.list_clients()

    def update_client_metadata(
        self,
        name: str,
        *,
        email: str | None,
        device: str | None,
        comment: str | None,
        expiry_at: str | None,
    ) -> ClientRecord:
        """Update editable client metadata and re-apply config if lifecycle changed."""

        client_name = validate_client_name(name)
        existing = self.storage.get_client(client_name)
        if existing is None:
            raise VPNManagerError(f"Client '{client_name}' was not found.")

        snapshot = ClientRecord(
            name=existing.name,
            address=existing.address,
            public_key=existing.public_key,
            config_path=existing.config_path,
            private_key_path=existing.private_key_path,
            created_at=existing.created_at,
            email=existing.email,
            device=existing.device,
            comment=existing.comment,
            status=existing.status,
            expiry_at=existing.expiry_at,
            updated_at=existing.updated_at,
            last_used_at=existing.last_used_at,
            imported=existing.imported,
            qr_code_path=existing.qr_code_path,
            config_revision=existing.config_revision,
        )
        previous_status = existing.status
        previous_renderable = self._should_render_client(existing)
        updated = self.storage.update_client_metadata(
            client_name,
            email=email,
            device=device,
            comment=comment,
            expiry_at=expiry_at,
        )

        status_changed = False
        if self._is_client_expired(updated) and updated.status == ClientStatus.ACTIVE:
            updated = self.storage.set_client_status(client_name, ClientStatus.EXPIRED)
            status_changed = True
        elif (
            not self._is_client_expired(updated)
            and previous_status == ClientStatus.EXPIRED
            and updated.status == ClientStatus.EXPIRED
        ):
            # Keep the client disabled after expiry until the operator explicitly enables it.
            updated = self.storage.set_client_status(client_name, ClientStatus.DISABLED)
            status_changed = True

        try:
            if previous_renderable != self._should_render_client(updated) or status_changed:
                local_config_path = self.create_server_config()
                self._sync_runtime_config(local_config_path)
        except VPNManagerError as exc:
            self.storage.update_client(snapshot)
            self.create_server_config()
            self._audit(
                "update_client_metadata",
                client_name,
                "failure",
                f"Failed to update metadata for client '{client_name}'.",
                error=str(exc),
            )
            raise

        self._audit(
            "update_client_metadata",
            client_name,
            "success",
            f"Updated metadata for client '{client_name}'.",
        )
        return updated

    def list_clients_with_status(self) -> list[tuple[ClientRecord, bool]]:
        """Return stored clients with a best-effort connected flag."""

        self._expire_clients_if_needed()
        connected_keys: set[str] = set()
        if self.can_control_vpn():
            try:
                connected_keys = {peer.public_key for peer in self.get_connected_clients()}
            except VPNManagerError as exc:
                self.logger.debug("Connected peer lookup skipped: %s", exc)

        return [
            (client, client.public_key in connected_keys)
            for client in self.storage.list_clients()
        ]

    def get_client_config_text(self, name: str) -> str:
        client = self.storage.get_client(validate_client_name(name))
        if client is None:
            raise VPNManagerError(f"Client '{name}' was not found.")
        if not client.config_path:
            raise VPNManagerError(
                f"Client '{name}' does not have an exported config yet. Imported peers need re-issue before export."
            )
        path = Path(client.config_path)
        if not path.exists():
            raise VPNManagerError(f"Client config does not exist: {path}")
        return path.read_text(encoding="utf-8")

    def get_connected_clients(self) -> list[ConnectedClient]:
        """
        Return peers with a recent handshake.

        WireGuard does not expose a strict online/offline state, so this uses the
        latest handshake time as a practical approximation.
        """

        if self.remote_profile is not None:
            controller = self._remote_controller()
            try:
                payload = controller.execute(
                    "show_connected",
                    {
                        "interface_name": self.config.interface_name,
                        "connected_window_seconds": self.config.connected_window_seconds,
                    },
                    sudo=self.remote_profile.use_sudo,
                )
            finally:
                controller.close()

            peers = payload.get("peers", [])
            if not isinstance(peers, list):
                raise VPNManagerError("Remote peer lookup returned invalid data.")

            connected_clients: list[ConnectedClient] = []
            for item in peers:
                if not isinstance(item, dict):
                    continue
                public_key = str(item["public_key"])
                stored_client = self.storage.get_client_by_public_key(public_key)
                last_used_at = utc_now_iso()
                self.storage.mark_client_last_used(public_key, last_used_at)
                connected_clients.append(
                    ConnectedClient(
                        public_key=public_key,
                        name=stored_client.name if stored_client else None,
                        address=stored_client.address if stored_client else None,
                        endpoint=str(item.get("endpoint") or ""),
                        latest_handshake=int(item.get("latest_handshake") or 0),
                        transfer_rx=int(item.get("transfer_rx") or 0),
                        transfer_tx=int(item.get("transfer_tx") or 0),
                    )
                )
            return connected_clients

        ensure_linux("Connected peer lookup")

        result = run_command(
            ["wg", "show", self.config.interface_name, "dump"],
            check=False,
        )
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            if stderr:
                raise VPNManagerError(stderr)
            return []

        lines = [line for line in result.stdout.splitlines() if line.strip()]
        if len(lines) <= 1:
            return []

        known_clients = {
            client.public_key: client for client in self.storage.list_clients()
        }
        current_time = int(time.time())
        connected_clients: list[ConnectedClient] = []

        for line in lines[1:]:
            parts = line.split("\t")
            if len(parts) < 8:
                continue

            public_key = parts[0]
            endpoint = parts[2]
            latest_handshake = int(parts[4])
            transfer_rx = int(parts[5])
            transfer_tx = int(parts[6])

            if latest_handshake == 0:
                continue

            if current_time - latest_handshake > self.config.connected_window_seconds:
                continue

            stored_client = known_clients.get(public_key)
            self.storage.mark_client_last_used(public_key, utc_now_iso())
            connected_clients.append(
                ConnectedClient(
                    public_key=public_key,
                    name=stored_client.name if stored_client else None,
                    address=stored_client.address if stored_client else None,
                    endpoint=endpoint,
                    latest_handshake=latest_handshake,
                    transfer_rx=transfer_rx,
                    transfer_tx=transfer_tx,
                )
            )

        return connected_clients

    def start_vpn(self) -> None:
        """Start the WireGuard service."""

        if self.remote_profile is not None:
            self._sync_remote_config(self.create_server_config(), service_action="start")
            self._audit("start_vpn", "server", "success", f"Started VPN on remote host {self.remote_profile.host}.", source="remote")
            self.logger.info("Remote VPN started.")
            return

        ensure_linux("Starting the VPN locally")
        ensure_root()
        self._apply_config_and_service_action("start")
        self._audit("start_vpn", "server", "success", "Started VPN locally.")
        self.logger.info("VPN started.")

    def stop_vpn(self) -> None:
        """Stop the WireGuard service."""

        if self.remote_profile is not None:
            controller = self._remote_controller()
            try:
                controller.execute(
                    "service_action",
                    {"service_name": self.service_name, "action": "stop"},
                    sudo=self.remote_profile.use_sudo,
                )
            finally:
                controller.close()
            self._audit("stop_vpn", "server", "success", f"Stopped VPN on remote host {self.remote_profile.host}.", source="remote")
            self.logger.info("Remote VPN stopped.")
            return

        ensure_linux("Stopping the VPN locally")
        ensure_root()
        run_command(["systemctl", "stop", self.service_name])
        self._audit("stop_vpn", "server", "success", "Stopped VPN locally.")
        self.logger.info("VPN stopped.")

    def restart_vpn(self) -> None:
        """Restart the WireGuard service."""

        if self.remote_profile is not None:
            self._sync_remote_config(self.create_server_config(), service_action="restart")
            self._audit("restart_vpn", "server", "success", f"Restarted VPN on remote host {self.remote_profile.host}.", source="remote")
            self.logger.info("Remote VPN restarted.")
            return

        ensure_linux("Restarting the VPN locally")
        ensure_root()
        self._apply_config_and_service_action("restart")
        self._audit("restart_vpn", "server", "success", "Restarted VPN locally.")
        self.logger.info("VPN restarted.")

    def validate_environment(self) -> list[ValidationIssue]:
        """Run local and remote validation checks before applying configuration."""

        issues: list[ValidationIssue] = []

        if self.config.endpoint == PLACEHOLDER_ENDPOINT:
            issues.append(
                ValidationIssue(
                    code="placeholder_endpoint",
                    message="WG_ENDPOINT is still set to the placeholder value.",
                    severity=SeverityLevel.ERROR,
                )
            )

        try:
            ipaddress.ip_interface(str(self.config.server_interface))
        except ValueError:
            issues.append(
                ValidationIssue(
                    code="invalid_server_address",
                    message="WG_SERVER_ADDRESS must be a valid IPv4 CIDR, for example 10.8.0.1/24.",
                    severity=SeverityLevel.ERROR,
                )
            )

        for dns_value in [item.strip() for item in self.config.dns.split(",") if item.strip()]:
            if not self._looks_like_ip_or_hostname(dns_value):
                issues.append(
                    ValidationIssue(
                        code="invalid_dns",
                        message=f"DNS value '{dns_value}' is not a valid IP address or hostname.",
                        severity=SeverityLevel.ERROR,
                    )
                )

        if self.remote_profile is not None:
            controller = self._remote_controller()
            try:
                payload = controller.execute(
                    "validate_environment",
                    {
                        "server_port": self.config.server_port,
                        "public_interface": self.config.public_interface,
                        "interface_name": self.config.interface_name,
                    },
                    sudo=self.remote_profile.use_sudo,
                )
            finally:
                controller.close()

            for item in payload.get("issues", []):
                if not isinstance(item, dict):
                    continue
                issues.append(
                    ValidationIssue(
                        code=str(item.get("code") or "remote_issue"),
                        message=str(item.get("message") or "Remote validation issue."),
                        severity=SeverityLevel(str(item.get("severity") or "warning")),
                    )
                )
            return issues

        if not is_linux():
            issues.append(
                ValidationIssue(
                    code="non_linux_host",
                    message="Local WireGuard service control requires a Linux host or a configured remote SSH profile.",
                    severity=SeverityLevel.ERROR,
                )
            )
            return issues

        for command in ("wg", "systemctl", "wg-quick"):
            if shutil.which(command) is None:
                issues.append(
                    ValidationIssue(
                        code=f"missing_{command}",
                        message=f"Required command '{command}' is not installed.",
                        severity=SeverityLevel.ERROR,
                    )
                )

        interface_result = run_command(
            ["ip", "link", "show", self.config.public_interface],
            check=False,
        )
        if interface_result.returncode != 0:
            issues.append(
                ValidationIssue(
                    code="missing_public_interface",
                    message=f"Public interface '{self.config.public_interface}' does not exist.",
                    severity=SeverityLevel.ERROR,
                )
            )

        service_active = False
        try:
            service_active = self.is_service_active()
        except VPNManagerError:
            service_active = False

        port_result = run_command(
            ["ss", "-H", "-lun", f"sport = :{self.config.server_port}"],
            check=False,
        )
        if port_result.stdout.strip() and not service_active:
            issues.append(
                ValidationIssue(
                    code="port_busy",
                    message=f"UDP port {self.config.server_port} already appears to be in use.",
                    severity=SeverityLevel.WARNING,
                )
            )

        if not is_root():
            issues.append(
                ValidationIssue(
                    code="not_root",
                    message="Some local actions require sudo/root privileges on Ubuntu.",
                    severity=SeverityLevel.WARNING,
                )
            )

        return issues

    def create_backup(self, *, note: str | None = None, include_logs: bool = True) -> BackupRecord:
        """Create a timestamped tar.gz archive containing local state and optional remote config."""

        created_at = utc_now_iso()
        safe_stamp = re.sub(r"[^0-9T]", "-", created_at).replace(":", "-")
        archive_path = self.backups_dir / f"vpn-backup-{safe_stamp}.tar.gz"
        remote_system_config_text: str | None = None

        if self.remote_profile is not None:
            controller = self._remote_controller()
            try:
                remote_system_config_text = controller.read_text_file(str(self.config.system_server_config))
            except VPNManagerError as exc:
                self.logger.warning("Remote config was not included in backup: %s", exc)
            finally:
                controller.close()

        manifest = {
            "created_at": created_at,
            "interface_name": self.config.interface_name,
            "endpoint": self.config.endpoint,
            "scope": "remote" if self.remote_profile is not None else "local",
            "includes_logs": include_logs,
            "includes_remote_system_config": remote_system_config_text is not None,
            "remote_host": self.remote_profile.host if self.remote_profile is not None else None,
        }

        with tarfile.open(archive_path, "w:gz") as archive:
            self._add_path_to_archive(archive, self.config.project_root / ".env", ".env")
            self._add_path_to_archive(archive, self.config.database_path, "data/vpn.sqlite3")
            if include_logs:
                self._add_path_to_archive(archive, self.config.log_path, "data/vpn_manager.log")
            self._add_path_to_archive(archive, self.config.configs_dir, "configs")

            if remote_system_config_text is not None:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".conf") as handle:
                    temp_path = Path(handle.name)
                    temp_path.write_text(remote_system_config_text, encoding="utf-8")
                archive.add(temp_path, arcname=f"remote/{self.config.interface_name}.conf")
                temp_path.unlink(missing_ok=True)

            manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
            info = tarfile.TarInfo(name="manifest.json")
            info.size = len(manifest_bytes)
            archive.addfile(info, fileobj=_BytesReader(manifest_bytes))

        record = BackupRecord(
            archive_path=str(archive_path),
            created_at=created_at,
            manifest_json=json.dumps(manifest, sort_keys=True),
            scope="remote" if self.remote_profile is not None else "local",
            note=note,
        )
        self.storage.add_backup(record)
        self._audit("create_backup", str(archive_path), "success", f"Backup created at {archive_path}.")
        return record

    def list_backups(self) -> list[BackupRecord]:
        return self.storage.list_backups()

    def restore_backup(self, archive_path: Path, *, apply_remote: bool = False) -> BackupRecord:
        """Restore local state from a previously created backup."""

        if not archive_path.exists():
            raise VPNManagerError(f"Backup archive does not exist: {archive_path}")

        pre_restore_backup = self.create_backup(note="pre-restore snapshot")
        del pre_restore_backup

        with tarfile.open(archive_path, "r:gz") as archive:
            members = archive.getmembers()
            self._validate_archive_members(members)
            member_names = {member.name for member in members}
            if "manifest.json" not in member_names:
                raise VPNManagerError("Backup archive is missing manifest.json.")

            with tempfile.TemporaryDirectory() as temp_dir:
                extract_root = Path(temp_dir)
                archive.extractall(extract_root)

                for relative_name in (".env", "data", "configs"):
                    source = extract_root / relative_name
                    destination = self.config.project_root / relative_name
                    if not source.exists():
                        continue
                    if destination.is_dir():
                        shutil.rmtree(destination)
                    elif destination.exists():
                        destination.unlink()
                    if source.is_dir():
                        shutil.copytree(source, destination)
                    else:
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(source, destination)

                if apply_remote and self.remote_profile is not None:
                    remote_path = extract_root / "remote" / f"{self.config.interface_name}.conf"
                    if remote_path.exists():
                        self._sync_remote_config(remote_path, service_action="restart")

        self.update_config(self.config)
        record = BackupRecord(
            archive_path=str(archive_path),
            created_at=utc_now_iso(),
            manifest_json="{}",
            scope="restore",
        )
        self._audit("restore_backup", str(archive_path), "success", f"Backup restored from {archive_path}.")
        return record

    def list_audit_logs(self, limit: int = 200) -> list[AuditLogRecord]:
        return self.storage.list_audit_logs(limit=limit)

    def import_existing_config(self, path: Path | None = None) -> int:
        """Import existing peers from a WireGuard config into local SQLite."""

        source_path = path or self.config.system_server_config
        if self.remote_profile is not None and path is None:
            controller = self._remote_controller()
            try:
                config_text = controller.read_text_file(str(self.config.system_server_config))
            finally:
                controller.close()
        else:
            if not source_path.exists():
                raise VPNManagerError(f"Config does not exist: {source_path}")
            config_text = source_path.read_text(encoding="utf-8")

        parsed_peers = parse_wireguard_peers(config_text)
        self.storage.clear_imported_peers()
        imported_count = 0

        for index, peer in enumerate(parsed_peers, start=1):
            inferred_name = self._normalize_imported_name(peer.inferred_name, index)
            address = None
            if peer.allowed_ips:
                address = peer.allowed_ips.split(",")[0].strip()

            self.storage.add_imported_peer(
                ImportedPeerRecord(
                    imported_at=utc_now_iso(),
                    source_path=str(source_path),
                    public_key=peer.public_key,
                    address=address,
                    inferred_name=inferred_name,
                    raw_block=peer.raw_block,
                )
            )

            existing = self.storage.get_client_by_public_key(peer.public_key)
            if existing is not None:
                existing.address = address or existing.address
                existing.status = (
                    existing.status if existing.status in {ClientStatus.ACTIVE, ClientStatus.DISABLED, ClientStatus.EXPIRED}
                    else ClientStatus.IMPORTED
                )
                existing.imported = True
                existing.updated_at = utc_now_iso()
                self.storage.update_client(existing)
                imported_count += 1
                continue

            unique_name = self._ensure_unique_client_name(inferred_name)
            self.storage.add_client(
                ClientRecord(
                    name=unique_name,
                    address=address or f"imported-{index}",
                    public_key=peer.public_key,
                    config_path=None,
                    private_key_path=None,
                    created_at=utc_now_iso(),
                    updated_at=utc_now_iso(),
                    status=ClientStatus.IMPORTED,
                    imported=True,
                    comment="Imported from existing WireGuard config.",
                )
            )
            imported_count += 1

        self.create_server_config()
        self._audit(
            "import_config",
            str(source_path),
            "success",
            f"Imported {imported_count} peer(s) from {source_path}.",
        )
        return imported_count

    def is_service_active(self) -> bool:
        """Check whether the WireGuard service is active locally or remotely."""

        if self.remote_profile is not None:
            controller = self._remote_controller()
            try:
                payload = controller.execute(
                    "server_status",
                    {
                        "service_name": self.service_name,
                        "interface_name": self.config.interface_name,
                    },
                    sudo=self.remote_profile.use_sudo,
                )
            finally:
                controller.close()
            return str(payload.get("service_state") or "") == "active"

        ensure_linux("Checking the local VPN service state")
        result = run_command(
            ["systemctl", "is-active", self.service_name],
            check=False,
        )
        return result.returncode == 0 and result.stdout.strip() == "active"

    def _renderable_clients(self) -> list[ClientRecord]:
        return [client for client in self.storage.list_clients() if self._should_render_client(client)]

    def _should_render_client(self, client: ClientRecord) -> bool:
        if client.status not in {ClientStatus.ACTIVE, ClientStatus.IMPORTED}:
            return False
        if self._is_client_expired(client):
            return False
        if not client.address or "/" not in client.address:
            return False
        try:
            ipaddress.ip_interface(client.address)
        except ValueError:
            return False
        return True

    def _expire_clients_if_needed(self) -> None:
        changed = False
        for client in self.storage.list_clients():
            if self._is_client_expired(client) and client.status == ClientStatus.ACTIVE:
                self.storage.set_client_status(client.name, ClientStatus.EXPIRED)
                changed = True
        if changed:
            local_config_path = self.create_server_config()
            try:
                self._sync_runtime_config(local_config_path)
            except VPNManagerError as exc:
                self.logger.warning("Failed to re-sync config after client expiry update: %s", exc)

    def _allocate_client_address(self) -> str:
        used_addresses = {
            ipaddress.ip_interface(address).ip
            for address in self.storage.used_addresses()
            if "/" in address
        }
        server_ip = self.config.server_interface.ip

        for host_ip in self.config.network.hosts():
            if host_ip == server_ip or host_ip in used_addresses:
                continue
            return f"{host_ip}/32"

        raise VPNManagerError("No free client IP addresses remain in the configured subnet.")

    def _build_client_config(
        self,
        *,
        private_key: str,
        client_address: str,
        server_public_key: str,
    ) -> str:
        return (
            "[Interface]\n"
            f"PrivateKey = {private_key}\n"
            f"Address = {client_address}\n"
            f"DNS = {self.config.dns}\n"
            "\n"
            "[Peer]\n"
            f"PublicKey = {server_public_key}\n"
            f"Endpoint = {self.config.endpoint}:{self.config.server_port}\n"
            f"AllowedIPs = {self.config.client_allowed_ips}\n"
            "PersistentKeepalive = 25\n"
        )

    def _sync_runtime_config(self, local_config_path: Path) -> None:
        if self.remote_profile is not None:
            remote_state = self._remote_service_state()
            desired_action = "restart" if remote_state == "active" else "none"
            self._sync_remote_config(local_config_path, service_action=desired_action)
            return

        try:
            ensure_linux()
        except VPNManagerError:
            self.logger.info("Skipping system sync because the host is not Linux.")
            return

        if not is_root():
            self.logger.warning(
                "Local config was updated, but /etc/wireguard was not synced because the process is not running as root."
            )
            return

        if self.is_service_active():
            self._apply_config_and_service_action("restart", local_config_path)
            return

        self.sync_server_config(local_config_path)

    def _apply_config_and_service_action(
        self,
        action: str,
        local_config_path: Path | None = None,
    ) -> None:
        had_existing_config, backup_path = self._apply_system_config(local_config_path)

        try:
            run_command(["systemctl", action, self.service_name])
        except VPNManagerError as exc:
            self.logger.error(
                "Failed to %s service with the updated config. Rolling back system config.",
                action,
            )
            self._rollback_service_config(action, had_existing_config, backup_path, exc)
        else:
            self._cleanup_system_config_backup(backup_path)

    def _apply_system_config(
        self,
        local_config_path: Path | None = None,
    ) -> tuple[bool, Path | None]:
        local_config = local_config_path or self.create_server_config()
        system_config = self.config.system_server_config
        system_config.parent.mkdir(parents=True, exist_ok=True)

        had_existing_config = system_config.exists()
        backup_path = Path(f"{system_config}.bak") if had_existing_config else None

        if backup_path is not None:
            shutil.copyfile(system_config, backup_path)
            backup_path.chmod(0o600)

        try:
            replace_file_atomically(local_config, system_config)
        except OSError:
            if backup_path is not None:
                backup_path.unlink(missing_ok=True)
            raise

        self.logger.info("Server config synced to %s", system_config)
        return had_existing_config, backup_path

    def _rollback_service_config(
        self,
        action: str,
        had_existing_config: bool,
        backup_path: Path | None,
        original_error: VPNManagerError,
    ) -> None:
        try:
            self._restore_system_config(had_existing_config, backup_path)
        except OSError as rollback_error:
            raise VPNManagerError(
                f"Failed to {action} VPN and failed to restore the previous config: {rollback_error}"
            ) from original_error

        if action == "restart" and had_existing_config:
            try:
                run_command(["systemctl", "restart", self.service_name])
            except VPNManagerError as restart_error:
                raise VPNManagerError(
                    "The new config failed to restart WireGuard. "
                    "The previous config was restored, but restarting with the restored config also failed.\n"
                    f"{restart_error}"
                ) from original_error

        raise VPNManagerError(
            f"Failed to {action} VPN with the updated config. Previous config was restored.\n{original_error}"
        ) from original_error

    def _restore_system_config(
        self,
        had_existing_config: bool,
        backup_path: Path | None,
    ) -> None:
        system_config = self.config.system_server_config

        if had_existing_config and backup_path is not None and backup_path.exists():
            replace_file_atomically(backup_path, system_config)
            backup_path.unlink(missing_ok=True)
            self.logger.warning("System config rolled back to the previous version.")
            return

        system_config.unlink(missing_ok=True)
        self.logger.warning("System config removed because there was no previous version to restore.")

    @staticmethod
    def _cleanup_system_config_backup(backup_path: Path | None) -> None:
        if backup_path is not None:
            backup_path.unlink(missing_ok=True)

    def _rollback_added_client(
        self,
        client_name: str,
        client_config_path: Path,
        private_key_path: Path,
        qr_code_path: Path,
    ) -> None:
        client_config_path.unlink(missing_ok=True)
        private_key_path.unlink(missing_ok=True)
        qr_code_path.unlink(missing_ok=True)

        if self.storage.get_client(client_name) is not None:
            self.storage.remove_client(client_name)

        self.create_server_config()

    def _restore_removed_client(
        self,
        client: ClientRecord,
        config_backup: str | None,
        private_key_backup: str | None,
        qr_backup: bytes | None,
    ) -> None:
        self.storage.add_client(client)

        if config_backup is not None and client.config_path:
            write_text_file(Path(client.config_path), config_backup)

        if private_key_backup is not None and client.private_key_path:
            write_text_file(Path(client.private_key_path), private_key_backup)

        if qr_backup is not None and client.qr_code_path:
            Path(client.qr_code_path).parent.mkdir(parents=True, exist_ok=True)
            Path(client.qr_code_path).write_bytes(qr_backup)

        self.create_server_config()

    def _configure_local_firewall(self) -> None:
        if shutil.which("ufw"):
            run_command(["ufw", "allow", f"{self.config.server_port}/udp"], check=False)
            return
        if shutil.which("nft"):
            ruleset = run_command(["nft", "list", "ruleset"], check=False).stdout
            if f"udp dport {self.config.server_port} accept" in ruleset:
                return
            nft_file = self.config.data_dir / "wgdesk-firewall.nft"
            nft_file.write_text(
                (
                    "table inet wgdesk {\n"
                    "  chain input {\n"
                    "    type filter hook input priority 0; policy accept;\n"
                    f"    udp dport {self.config.server_port} accept\n"
                    "  }\n"
                    "}\n"
                ),
                encoding="utf-8",
            )
            run_command(["nft", "-f", str(nft_file)], check=False)

    def _remote_controller(self) -> SSHRemoteController:
        profile = self.remote_profile
        if profile is None:
            raise VPNManagerError("Remote SSH profile is not configured.")
        return SSHRemoteController(profile, self.secret_store)

    def _remote_service_state(self) -> str:
        controller = self._remote_controller()
        try:
            payload = controller.execute(
                "server_status",
                {
                    "service_name": self.service_name,
                    "interface_name": self.config.interface_name,
                },
                sudo=self.remote_profile.use_sudo if self.remote_profile else False,
            )
        finally:
            controller.close()
        return str(payload.get("service_state") or "inactive")

    def _sync_remote_config(self, local_config_path: Path, *, service_action: str) -> None:
        controller = self._remote_controller()
        try:
            controller.execute(
                "sync_server_config",
                {
                    "config_text": local_config_path.read_text(encoding="utf-8"),
                    "system_config_path": str(self.config.system_server_config),
                    "interface_name": self.config.interface_name,
                    "service_name": self.service_name,
                    "service_action": service_action,
                    "prefer_sync": True,
                },
                sudo=self.remote_profile.use_sudo if self.remote_profile else False,
            )
        except VPNManagerError as exc:
            raise VPNManagerError(f"Failed to sync config to remote host: {exc}") from exc
        finally:
            controller.close()

    def _audit(
        self,
        action: str,
        target: str,
        result: str,
        details: str,
        *,
        error: str | None = None,
        source: str = "local",
    ) -> None:
        self.storage.add_audit_log(
            AuditLogRecord(
                timestamp=utc_now_iso(),
                action=action,
                actor="desktop",
                source=source,
                target=target,
                result=result,
                details=details,
                error_details=error,
            )
        )

    @staticmethod
    def _looks_like_ip_or_hostname(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            pass

        return bool(
            re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9.-]{0,251}[A-Za-z0-9]",
                value,
            )
        )

    def _ensure_unique_client_name(self, preferred_name: str) -> str:
        candidate = preferred_name
        counter = 1
        while self.storage.get_client(candidate) is not None:
            counter += 1
            candidate = f"{preferred_name}-{counter}"
        return candidate

    @staticmethod
    def _normalize_imported_name(name: str | None, index: int) -> str:
        if not name:
            return f"imported-peer-{index}"
        normalized = re.sub(r"[^A-Za-z0-9_-]+", "-", name.strip()).strip("-")
        return normalized[:32] or f"imported-peer-{index}"

    @staticmethod
    def _is_client_expired(client: ClientRecord) -> bool:
        if not client.expiry_at:
            return False
        try:
            expiry_at = datetime.fromisoformat(client.expiry_at.replace("Z", "+00:00"))
        except ValueError:
            return False
        if expiry_at.tzinfo is None:
            expiry_at = expiry_at.replace(tzinfo=timezone.utc)
        return expiry_at <= datetime.now(timezone.utc)

    @staticmethod
    def _validate_archive_members(members: list[tarfile.TarInfo]) -> None:
        for member in members:
            normalized = Path(member.name)
            if normalized.is_absolute() or ".." in normalized.parts:
                raise VPNManagerError("Backup archive contains an unsafe path.")

    @staticmethod
    def _add_path_to_archive(archive: tarfile.TarFile, path: Path, arcname: str) -> None:
        if not path.exists():
            return
        archive.add(path, arcname=arcname)


class _BytesReader:
    """Minimal file-like object for tarfile.addfile."""

    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.offset = 0

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self.payload) - self.offset
        chunk = self.payload[self.offset : self.offset + size]
        self.offset += len(chunk)
        return chunk
