from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from src.models import VPNManagerError

MANAGED_ENV_KEYS = (
    "WG_ENDPOINT",
    "WG_INTERFACE_NAME",
    "WG_SERVER_ADDRESS",
    "WG_SERVER_PORT",
    "WG_PUBLIC_INTERFACE",
    "WG_DNS",
    "WG_CLIENT_ALLOWED_IPS",
    "WG_CONNECTED_WINDOW_SECONDS",
)


@dataclass(slots=True)
class AppConfig:
    """Application settings loaded from environment variables."""

    project_root: Path
    data_dir: Path
    configs_dir: Path
    server_configs_dir: Path
    client_configs_dir: Path
    keys_dir: Path
    client_private_keys_dir: Path
    database_path: Path
    log_path: Path
    interface_name: str
    server_interface: ipaddress.IPv4Interface
    server_port: int
    endpoint: str
    public_interface: str
    dns: str
    client_allowed_ips: str
    connected_window_seconds: int
    system_server_config: Path
    sysctl_config_path: Path

    @property
    def server_config_path(self) -> Path:
        return self.server_configs_dir / f"{self.interface_name}.conf"

    @property
    def server_ip(self) -> str:
        return str(self.server_interface.ip)

    @property
    def network(self) -> ipaddress.IPv4Network:
        return self.server_interface.network


@dataclass(slots=True)
class EditableVPNSettings:
    """User-editable VPN parameters persisted in .env."""

    endpoint: str
    interface_name: str
    server_address: str
    server_port: int
    public_interface: str
    dns: str
    client_allowed_ips: str
    connected_window_seconds: int


def _read_int(name: str, default: int) -> int:
    value = os.getenv(name, str(default)).strip()
    try:
        return int(value)
    except ValueError as exc:
        raise VPNManagerError(f"Environment variable {name} must be an integer.") from exc


def _build_config(
    project_root: Path,
    *,
    interface_name: str,
    server_address: str,
    server_port: int,
    endpoint: str,
    public_interface: str,
    dns: str,
    client_allowed_ips: str,
    connected_window_seconds: int,
) -> AppConfig:
    try:
        server_interface = ipaddress.ip_interface(server_address)
    except ValueError as exc:
        raise VPNManagerError(
            "WG_SERVER_ADDRESS must look like 10.8.0.1/24."
        ) from exc

    if not isinstance(server_interface, ipaddress.IPv4Interface):
        raise VPNManagerError("Only IPv4 server addresses are supported in this project.")

    if server_port < 1 or server_port > 65535:
        raise VPNManagerError("WG_SERVER_PORT must be between 1 and 65535.")

    if connected_window_seconds < 1:
        raise VPNManagerError("WG_CONNECTED_WINDOW_SECONDS must be greater than 0.")

    if server_interface.network.num_addresses < 4:
        raise VPNManagerError("WG_SERVER_ADDRESS network is too small for client allocation.")

    if not interface_name.strip():
        raise VPNManagerError("WG_INTERFACE_NAME cannot be empty.")
    if not public_interface.strip():
        raise VPNManagerError("WG_PUBLIC_INTERFACE cannot be empty.")
    if not dns.strip():
        raise VPNManagerError("WG_DNS cannot be empty.")
    if not client_allowed_ips.strip():
        raise VPNManagerError("WG_CLIENT_ALLOWED_IPS cannot be empty.")
    if not endpoint.strip():
        raise VPNManagerError("WG_ENDPOINT cannot be empty.")

    data_dir = project_root / "data"
    configs_dir = project_root / "configs"
    server_configs_dir = configs_dir / "server"
    client_configs_dir = configs_dir / "clients"
    keys_dir = configs_dir / "keys"
    client_private_keys_dir = keys_dir / "clients"

    system_server_config = Path(
        os.getenv(
            "WG_SYSTEM_CONFIG",
            f"/etc/wireguard/{interface_name}.conf",
        ).strip()
    )
    sysctl_config_path = Path(
        os.getenv(
            "WG_SYSCTL_CONFIG",
            "/etc/sysctl.d/99-wireguard-personal-vpn.conf",
        ).strip()
    )

    return AppConfig(
        project_root=project_root,
        data_dir=data_dir,
        configs_dir=configs_dir,
        server_configs_dir=server_configs_dir,
        client_configs_dir=client_configs_dir,
        keys_dir=keys_dir,
        client_private_keys_dir=client_private_keys_dir,
        database_path=data_dir / "vpn.sqlite3",
        log_path=data_dir / "vpn_manager.log",
        interface_name=interface_name,
        server_interface=server_interface,
        server_port=server_port,
        endpoint=endpoint,
        public_interface=public_interface,
        dns=dns,
        client_allowed_ips=client_allowed_ips,
        connected_window_seconds=connected_window_seconds,
        system_server_config=system_server_config,
        sysctl_config_path=sysctl_config_path,
    )


def editable_settings_from_config(config: AppConfig) -> EditableVPNSettings:
    """Create an editable settings object from the current app config."""

    return EditableVPNSettings(
        endpoint=config.endpoint,
        interface_name=config.interface_name,
        server_address=str(config.server_interface),
        server_port=config.server_port,
        public_interface=config.public_interface,
        dns=config.dns,
        client_allowed_ips=config.client_allowed_ips,
        connected_window_seconds=config.connected_window_seconds,
    )


def save_editable_settings(
    project_root: Path,
    settings: EditableVPNSettings,
) -> AppConfig:
    """Validate, persist, and return updated VPN settings."""

    normalized = _build_config(
        project_root,
        interface_name=settings.interface_name.strip(),
        server_address=settings.server_address.strip(),
        server_port=int(settings.server_port),
        endpoint=settings.endpoint.strip(),
        public_interface=settings.public_interface.strip(),
        dns=settings.dns.strip(),
        client_allowed_ips=settings.client_allowed_ips.strip(),
        connected_window_seconds=int(settings.connected_window_seconds),
    )
    env_values = {
        "WG_ENDPOINT": normalized.endpoint,
        "WG_INTERFACE_NAME": normalized.interface_name,
        "WG_SERVER_ADDRESS": str(normalized.server_interface),
        "WG_SERVER_PORT": str(normalized.server_port),
        "WG_PUBLIC_INTERFACE": normalized.public_interface,
        "WG_DNS": normalized.dns,
        "WG_CLIENT_ALLOWED_IPS": normalized.client_allowed_ips,
        "WG_CONNECTED_WINDOW_SECONDS": str(normalized.connected_window_seconds),
    }
    _write_env_file(project_root / ".env", env_values)
    return normalized


def _write_env_file(env_path: Path, values: dict[str, str]) -> None:
    """Persist managed .env keys while preserving unrelated lines."""

    existing_lines = []
    if env_path.exists():
        existing_lines = env_path.read_text(encoding="utf-8").splitlines()

    updated_lines: list[str] = []
    seen_keys: set[str] = set()

    for line in existing_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            updated_lines.append(line)
            continue

        key, _, _ = line.partition("=")
        if key in values:
            updated_lines.append(f"{key}={values[key]}")
            seen_keys.add(key)
        else:
            updated_lines.append(line)

    for key in MANAGED_ENV_KEYS:
        if key not in seen_keys:
            updated_lines.append(f"{key}={values[key]}")

    env_path.write_text("\n".join(updated_lines).rstrip() + "\n", encoding="utf-8")


def load_config(base_dir: Path | None = None) -> AppConfig:
    """Load configuration from .env and environment variables."""

    project_root = base_dir or Path(__file__).resolve().parent.parent
    load_dotenv(project_root / ".env", override=True)

    interface_name = os.getenv("WG_INTERFACE_NAME", "wg0").strip() or "wg0"
    server_address = os.getenv("WG_SERVER_ADDRESS", "10.8.0.1/24").strip()
    server_port = _read_int("WG_SERVER_PORT", 51820)
    endpoint = os.getenv("WG_ENDPOINT", "your.server.ip.or.dns").strip()
    public_interface = os.getenv("WG_PUBLIC_INTERFACE", "eth0").strip() or "eth0"
    dns = os.getenv("WG_DNS", "1.1.1.1").strip() or "1.1.1.1"
    client_allowed_ips = os.getenv("WG_CLIENT_ALLOWED_IPS", "0.0.0.0/0, ::/0").strip()
    connected_window_seconds = _read_int("WG_CONNECTED_WINDOW_SECONDS", 180)
    return _build_config(
        project_root,
        interface_name=interface_name,
        server_address=server_address,
        server_port=server_port,
        endpoint=endpoint,
        public_interface=public_interface,
        dns=dns,
        client_allowed_ips=client_allowed_ips,
        connected_window_seconds=connected_window_seconds,
    )
