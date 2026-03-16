from __future__ import annotations

import argparse
import ipaddress
import tempfile
import tkinter as tk
import unittest
from pathlib import Path
from unittest import mock

from src.config import AppConfig
from src.main import execute_command
from src.models import VPNManagerError
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


class MainEntryPointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.project_root = Path(self.temp_dir.name)
        config = make_config(self.project_root)
        storage = ClientStorage(config.database_path, config.client_private_keys_dir)
        self.manager = WireGuardManager(config, storage)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_execute_command_uses_gui_by_default(self) -> None:
        args = argparse.Namespace(command=None)

        with mock.patch("src.gui_app.run_gui_app") as run_gui_app:
            result = execute_command(args, self.manager)

        self.assertEqual(result, 0)
        run_gui_app.assert_called_once_with(self.manager)

    def test_execute_command_wraps_tk_error_for_gui(self) -> None:
        args = argparse.Namespace(command="gui")

        with mock.patch(
            "src.gui_app.run_gui_app",
            side_effect=tk.TclError("no display"),
        ):
            with self.assertRaises(VPNManagerError) as context:
                execute_command(args, self.manager)

        self.assertIn("desktop UI could not be started", str(context.exception))


if __name__ == "__main__":
    unittest.main()
