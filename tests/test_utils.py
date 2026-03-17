from __future__ import annotations

import unittest
from unittest import mock

from src.utils import detect_host_platform, linux_host_requirement_message


class HostPlatformDetectionTests(unittest.TestCase):
    def test_detect_host_platform_normalizes_macos(self) -> None:
        with (
            mock.patch("src.utils.platform.system", return_value="Darwin"),
            mock.patch("src.utils.platform.release", return_value="24.0.0"),
            mock.patch("src.utils.platform.version", return_value="Darwin Kernel Version"),
            mock.patch("src.utils.platform.machine", return_value="arm64"),
            mock.patch("src.utils.platform.mac_ver", return_value=("15.3.1", ("", "", ""), "")),
        ):
            info = detect_host_platform()

        self.assertEqual(info.system, "Darwin")
        self.assertEqual(info.display_name, "macOS")
        self.assertEqual(info.release, "15.3.1")
        self.assertEqual(info.machine, "arm64")
        self.assertFalse(info.local_wireguard_supported)

    def test_linux_host_requirement_message_uses_normalized_name(self) -> None:
        with (
            mock.patch("src.utils.platform.system", return_value="Darwin"),
            mock.patch("src.utils.platform.release", return_value="24.0.0"),
            mock.patch("src.utils.platform.version", return_value="Darwin Kernel Version"),
            mock.patch("src.utils.platform.machine", return_value="arm64"),
            mock.patch("src.utils.platform.mac_ver", return_value=("15.3.1", ("", "", ""), "")),
        ):
            message = linux_host_requirement_message("Starting the VPN locally")

        self.assertIn("Current host: macOS 15.3.1", message)


if __name__ == "__main__":
    unittest.main()
