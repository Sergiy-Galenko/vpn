from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.config import EditableVPNSettings, load_config, save_editable_settings


class ConfigEditingTests(unittest.TestCase):
    def test_save_editable_settings_writes_env_and_returns_updated_config(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            project_root = Path(temp_dir)
            (project_root / ".env").write_text("WG_ENDPOINT=old.example.com\n", encoding="utf-8")

            config = save_editable_settings(
                project_root,
                EditableVPNSettings(
                    endpoint="vpn.example.com",
                    interface_name="wg99",
                    server_address="10.20.30.1/24",
                    server_port=55321,
                    public_interface="ens18",
                    dns="1.1.1.1,8.8.8.8",
                    client_allowed_ips="10.0.0.0/8, 192.168.0.0/16",
                    connected_window_seconds=300,
                ),
            )

            self.assertEqual(config.endpoint, "vpn.example.com")
            self.assertEqual(config.interface_name, "wg99")
            self.assertEqual(str(config.server_interface), "10.20.30.1/24")
            self.assertEqual(config.server_port, 55321)
            env_text = (project_root / ".env").read_text(encoding="utf-8")
            self.assertIn("WG_INTERFACE_NAME=wg99", env_text)
            self.assertIn("WG_SERVER_PORT=55321", env_text)

    def test_load_config_reads_saved_env_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            project_root = Path(temp_dir)
            (project_root / ".env").write_text(
                "\n".join(
                    [
                        "WG_ENDPOINT=my-vpn.example.com",
                        "WG_INTERFACE_NAME=wg10",
                        "WG_SERVER_ADDRESS=10.9.0.1/24",
                        "WG_SERVER_PORT=51234",
                        "WG_PUBLIC_INTERFACE=en0",
                        "WG_DNS=9.9.9.9",
                        "WG_CLIENT_ALLOWED_IPS=0.0.0.0/0",
                        "WG_CONNECTED_WINDOW_SECONDS=222",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            config = load_config(project_root)

            self.assertEqual(config.endpoint, "my-vpn.example.com")
            self.assertEqual(config.interface_name, "wg10")
            self.assertEqual(config.server_port, 51234)
            self.assertEqual(config.public_interface, "en0")
            self.assertEqual(config.connected_window_seconds, 222)


if __name__ == "__main__":
    unittest.main()
