from __future__ import annotations

import ipaddress
import logging
import shutil
import time
from pathlib import Path

from src.config import AppConfig
from src.models import ClientRecord, ConnectedClient, VPNManagerError
from src.storage import ClientStorage
from src.utils import (
    ensure_linux,
    ensure_root,
    is_root,
    run_command,
    utc_now_iso,
    validate_client_name,
    write_text_file,
)


class WireGuardManager:
    """High-level WireGuard management workflow."""

    def __init__(self, config: AppConfig, storage: ClientStorage) -> None:
        self.config = config
        self.storage = storage
        self.logger = logging.getLogger(self.__class__.__name__)

        self.config.data_dir.mkdir(parents=True, exist_ok=True)
        self.config.server_configs_dir.mkdir(parents=True, exist_ok=True)
        self.config.client_configs_dir.mkdir(parents=True, exist_ok=True)
        self.config.keys_dir.mkdir(parents=True, exist_ok=True)
        self.storage.initialize()

    @property
    def service_name(self) -> str:
        return f"wg-quick@{self.config.interface_name}"

    @property
    def server_private_key_path(self) -> Path:
        return self.config.keys_dir / "server_private.key"

    @property
    def server_public_key_path(self) -> Path:
        return self.config.keys_dir / "server_public.key"

    def install_wireguard(self) -> None:
        """Install packages, enable forwarding, and write the server config."""

        ensure_linux()
        ensure_root()

        run_command(["apt-get", "update"])
        run_command(["apt-get", "install", "-y", "wireguard", "wireguard-tools"])
        self.enable_ip_forwarding()
        self.ensure_server_keys()
        self.create_server_config()
        self.sync_server_config()
        run_command(["systemctl", "enable", self.service_name])

        self.logger.info("WireGuard installation and configuration completed.")

    def enable_ip_forwarding(self) -> None:
        """Enable IPv4 and IPv6 forwarding through sysctl."""

        ensure_linux()
        ensure_root()

        content = (
            "net.ipv4.ip_forward = 1\n"
            "net.ipv6.conf.all.forwarding = 1\n"
        )
        write_text_file(self.config.sysctl_config_path, content, mode=0o644)
        run_command(["sysctl", "--system"])

    def generate_keypair(self) -> tuple[str, str]:
        """Generate a WireGuard private and public key pair."""

        private_key = run_command(["wg", "genkey"]).stdout.strip()
        if not private_key:
            raise VPNManagerError("wg genkey returned an empty private key.")

        public_key = run_command(
            ["wg", "pubkey"],
            input_text=f"{private_key}\n",
        ).stdout.strip()
        if not public_key:
            raise VPNManagerError("wg pubkey returned an empty public key.")

        return private_key, public_key

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

        server_private_key, _ = self.ensure_server_keys()
        clients = self.storage.list_clients()

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

    def sync_server_config(self) -> None:
        """Copy the generated local server config into /etc/wireguard."""

        ensure_linux()
        ensure_root()

        local_config = self.create_server_config()
        self.config.system_server_config.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(local_config, self.config.system_server_config)
        self.config.system_server_config.chmod(0o600)
        self.logger.info("Server config synced to %s", self.config.system_server_config)

    def add_client(self, name: str) -> ClientRecord:
        """Generate a client, save it in SQLite, and rebuild the server config."""

        client_name = validate_client_name(name)
        if self.storage.get_client(client_name):
            raise VPNManagerError(f"Client '{client_name}' already exists.")

        private_key, public_key = self.generate_keypair()
        _, server_public_key = self.ensure_server_keys()
        client_address = self._allocate_client_address()
        client_config_path = self.config.client_configs_dir / f"{client_name}.conf"
        client = ClientRecord(
            name=client_name,
            address=client_address,
            public_key=public_key,
            private_key=private_key,
            config_path=str(client_config_path),
            created_at=utc_now_iso(),
        )

        client_config = self._build_client_config(
            private_key=private_key,
            client_address=client_address,
            server_public_key=server_public_key,
        )
        write_text_file(client_config_path, client_config)

        try:
            self.storage.add_client(client)
            self.create_server_config()
            self._sync_runtime_config()
        except Exception:
            client_config_path.unlink(missing_ok=True)
            existing = self.storage.get_client(client_name)
            if existing is not None:
                self.storage.remove_client(client_name)
            self.create_server_config()
            raise

        self.logger.info("Client '%s' created at %s", client_name, client_config_path)
        return client

    def remove_client(self, name: str) -> None:
        """Remove a client from SQLite and rebuild the server config."""

        client_name = validate_client_name(name)
        existing = self.storage.get_client(client_name)
        if existing is None:
            raise VPNManagerError(f"Client '{client_name}' was not found.")

        config_path = Path(existing.config_path)
        config_backup = config_path.read_text(encoding="utf-8") if config_path.exists() else None

        self.storage.remove_client(client_name)
        try:
            config_path.unlink(missing_ok=True)
            self.create_server_config()
            self._sync_runtime_config()
        except Exception:
            self.storage.add_client(existing)
            if config_backup is not None:
                write_text_file(config_path, config_backup)
            self.create_server_config()
            raise

        self.logger.info("Client '%s' removed.", client_name)

    def list_clients(self) -> list[ClientRecord]:
        """Return all stored clients."""

        return self.storage.list_clients()

    def list_clients_with_status(self) -> list[tuple[ClientRecord, bool]]:
        """Return stored clients with a best-effort connected flag."""

        connected_keys: set[str] = set()
        try:
            connected_keys = {peer.public_key for peer in self.get_connected_clients()}
        except VPNManagerError as exc:
            self.logger.debug("Connected peer lookup skipped: %s", exc)

        return [
            (client, client.public_key in connected_keys)
            for client in self.storage.list_clients()
        ]

    def get_connected_clients(self) -> list[ConnectedClient]:
        """
        Return peers with a recent handshake.

        WireGuard does not expose a strict online/offline state, so this uses the
        latest handshake time as a practical approximation.
        """

        ensure_linux()

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

        ensure_linux()
        ensure_root()
        self.sync_server_config()
        run_command(["systemctl", "start", self.service_name])
        self.logger.info("VPN started.")

    def stop_vpn(self) -> None:
        """Stop the WireGuard service."""

        ensure_linux()
        ensure_root()
        run_command(["systemctl", "stop", self.service_name])
        self.logger.info("VPN stopped.")

    def restart_vpn(self) -> None:
        """Restart the WireGuard service."""

        ensure_linux()
        ensure_root()
        self.sync_server_config()
        run_command(["systemctl", "restart", self.service_name])
        self.logger.info("VPN restarted.")

    def _allocate_client_address(self) -> str:
        """Pick the next free IP in the configured subnet."""

        used_addresses = {
            ipaddress.ip_interface(address).ip for address in self.storage.used_addresses()
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
        """Create the text content for a client config file."""

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

    def _sync_runtime_config(self) -> None:
        """Best-effort sync after local config changes."""

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

        self.sync_server_config()
        if self.is_service_active():
            run_command(["systemctl", "restart", self.service_name])
            self.logger.info("Service restarted to apply the updated peer list.")

    def is_service_active(self) -> bool:
        """Check whether the WireGuard service is active."""

        ensure_linux()
        result = run_command(
            ["systemctl", "is-active", self.service_name],
            check=False,
        )
        return result.returncode == 0 and result.stdout.strip() == "active"
