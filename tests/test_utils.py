from __future__ import annotations

import unittest
from collections import namedtuple
from unittest import mock

from src.utils import (
    detect_host_location,
    detect_host_hardware,
    detect_host_platform,
    format_bytes_binary,
    linux_host_requirement_message,
)


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


class HostHardwareDetectionTests(unittest.TestCase):
    def test_detect_host_hardware_reads_macos_cpu_memory_and_gpu_cores(self) -> None:
        profiler_output = """
Hardware:

    Hardware Overview:

      Chip: Apple M1
      Total Number of Cores: 8 (4 Performance and 4 Efficiency)
      Memory: 8 GB

Graphics/Displays:

    Apple M1:

      Chipset Model: Apple M1
      Type: GPU
      Total Number of Cores: 7
"""
        disk_usage = namedtuple("disk_usage", ["total", "used", "free"])(1, 1, 1)

        def fake_run(command: list[str], **_: object) -> mock.Mock:
            outputs = {
                ("sysctl", "-n", "machdep.cpu.brand_string"): "Apple M1\n",
                ("sysctl", "-n", "hw.memsize"): "8589934592\n",
                ("sysctl", "-n", "hw.physicalcpu"): "8\n",
                ("sysctl", "-n", "hw.logicalcpu"): "8\n",
                ("system_profiler", "SPHardwareDataType", "SPDisplaysDataType"): profiler_output,
            }
            key = tuple(command)
            stdout = outputs.get(key, "")
            return mock.Mock(returncode=0 if stdout else 1, stdout=stdout, stderr="")

        with (
            mock.patch("src.utils.platform.system", return_value="Darwin"),
            mock.patch("src.utils.shutil.disk_usage", return_value=disk_usage),
            mock.patch("src.utils.subprocess.run", side_effect=fake_run),
        ):
            hardware = detect_host_hardware()

        self.assertEqual(hardware.cpu_name, "Apple M1")
        self.assertEqual(hardware.memory_total_bytes, 8589934592)
        self.assertEqual(hardware.cpu_physical_cores, 8)
        self.assertEqual(hardware.cpu_logical_cores, 8)
        self.assertEqual(hardware.gpu_cores, 7)
        self.assertEqual(hardware.storage_total_bytes, 1)

    def test_format_bytes_binary_returns_human_friendly_size(self) -> None:
        self.assertEqual(format_bytes_binary(8589934592), "8.0 GiB")
        self.assertEqual(format_bytes_binary(None), "Unavailable")


class HostLocationDetectionTests(unittest.TestCase):
    def tearDown(self) -> None:
        detect_host_location.cache_clear()

    def test_detect_host_location_parses_ipwhois_payload(self) -> None:
        payload = (
            '{"success":true,"ip":"203.0.113.9","city":"Kyiv","region":"Kyiv City",'
            '"country":"Ukraine","latitude":50.45,"longitude":30.523,"timezone":{"id":"Europe/Kyiv"}}'
        ).encode("utf-8")

        response = mock.MagicMock()
        response.read.return_value = payload
        response.__enter__.return_value = response
        response.__exit__.return_value = False

        with mock.patch("src.utils.urllib_request.urlopen", return_value=response):
            location = detect_host_location()

        self.assertTrue(location.available)
        self.assertEqual(location.city, "Kyiv")
        self.assertEqual(location.country, "Ukraine")
        self.assertEqual(location.timezone, "Europe/Kyiv")
        self.assertEqual(location.public_ip, "203.0.113.9")
        self.assertEqual(location.summary, "Kyiv, Kyiv City, Ukraine")
        self.assertEqual(location.latitude_summary, "50.450000")
        self.assertEqual(location.longitude_summary, "30.523000")
        self.assertEqual(location.coordinates_summary, "50.4500, 30.5230")

    def test_detect_host_location_returns_unavailable_on_network_error(self) -> None:
        with mock.patch(
            "src.utils.urllib_request.urlopen",
            side_effect=OSError("network unreachable"),
        ):
            location = detect_host_location()

        self.assertFalse(location.available)
        self.assertEqual(location.summary, "Unavailable")


if __name__ == "__main__":
    unittest.main()
