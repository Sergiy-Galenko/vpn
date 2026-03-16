from __future__ import annotations

import ipaddress
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from src.config import AppConfig
from src.models import ClientRecord, VPNManagerError
from src.storage import ClientStorage
from src.wireguard_manager import WireGuardManager


def make_config(project_root: Path) -> AppConfig:
    configs_dir = project_root / "configs"

    return AppConfig(
        project_root=project_root,
        data_dir=project_root / "data",
        configs_dir=configs_dir,
        server_configs_dir=configs_dir / "server",
        client_configs_dir=configs_dir / "clients",
        keys_dir=configs_dir / "keys",
        client_private_keys_dir=configs_dir / "keys" / "clients",
        database_path=project_root / "data" / "vpn.sqlite3",
        log_path=project_root / "data" / "vpn_manager.log",
        interface_name="wg0",
        server_interface=ipaddress.ip_interface("10.8.0.1/29"),
        server_port=51820,
        endpoint="vpn.example.com",
        public_interface="eth0",
        dns="1.1.1.1",
        client_allowed_ips="0.0.0.0/0, ::/0",
        connected_window_seconds=180,
        system_server_config=project_root / "system" / "wg0.conf",
        sysctl_config_path=project_root / "system" / "99-wireguard.conf",
    )


class WireGuardManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.project_root = Path(self.temp_dir.name)
        self.config = make_config(self.project_root)
        self.storage = ClientStorage(
            self.config.database_path,
            self.config.client_private_keys_dir,
        )
        self.manager = WireGuardManager(self.config, self.storage)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_allocate_client_address_skips_server_and_used_addresses(self) -> None:
        self.storage.add_client(
            ClientRecord(
                name="phone",
                address="10.8.0.2/32",
                public_key="pubkey-1",
                config_path=str(self.config.client_configs_dir / "phone.conf"),
                private_key_path=str(self.config.client_private_keys_dir / "phone.key"),
                created_at="2026-03-16T00:00:00+00:00",
            )
        )
        self.storage.add_client(
            ClientRecord(
                name="laptop",
                address="10.8.0.3/32",
                public_key="pubkey-2",
                config_path=str(self.config.client_configs_dir / "laptop.conf"),
                private_key_path=str(self.config.client_private_keys_dir / "laptop.key"),
                created_at="2026-03-16T00:00:01+00:00",
            )
        )

        self.assertEqual(self.manager._allocate_client_address(), "10.8.0.4/32")

    def test_restart_vpn_restores_previous_system_config_on_failure(self) -> None:
        self.manager.server_private_key_path.write_text("server-private\n", encoding="utf-8")
        self.manager.server_public_key_path.write_text("server-public\n", encoding="utf-8")

        self.config.system_server_config.parent.mkdir(parents=True, exist_ok=True)
        original_config = "old-system-config\n"
        self.config.system_server_config.write_text(original_config, encoding="utf-8")

        successful_restart = subprocess.CompletedProcess(
            ["systemctl", "restart", self.manager.service_name],
            0,
            "",
            "",
        )

        with (
            mock.patch("src.wireguard_manager.ensure_linux"),
            mock.patch("src.wireguard_manager.ensure_root"),
            mock.patch(
                "src.wireguard_manager.run_command",
                side_effect=[
                    VPNManagerError("restart failed"),
                    successful_restart,
                ],
            ),
        ):
            with self.assertRaises(VPNManagerError):
                self.manager.restart_vpn()

        self.assertEqual(
            self.config.system_server_config.read_text(encoding="utf-8"),
            original_config,
        )
        self.assertFalse(Path(f"{self.config.system_server_config}.bak").exists())

    def test_storage_schema_uses_private_key_path_instead_of_private_key(self) -> None:
        with self.storage._connect() as connection:
            columns = self.storage._get_client_columns(connection)

        self.assertIn("private_key_path", columns)
        self.assertNotIn("private_key", columns)


if __name__ == "__main__":
    unittest.main()
