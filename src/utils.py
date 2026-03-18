from __future__ import annotations

import json
import logging
import os
import platform
import re
import shlex
import shutil
import ssl
import subprocess
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request

from src.models import VPNManagerError

try:
    import certifi
except ImportError:  # pragma: no cover - optional dependency fallback
    certifi = None


CLIENT_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")


@dataclass(slots=True, frozen=True)
class HostPlatformInfo:
    """Normalized information about the host operating system."""

    system: str
    display_name: str
    release: str
    version: str
    machine: str
    local_wireguard_supported: bool

    @property
    def summary(self) -> str:
        return f"{self.display_name} {self.release} | {self.machine}"


@dataclass(slots=True, frozen=True)
class HostHardwareInfo:
    """Best-effort hardware information for the current host."""

    cpu_name: str
    memory_total_bytes: int | None
    storage_total_bytes: int | None
    cpu_physical_cores: int | None
    cpu_logical_cores: int | None
    gpu_cores: int | None


@dataclass(slots=True, frozen=True)
class HostLocationInfo:
    """Best-effort public IP geolocation for the current host."""

    available: bool
    city: str | None
    region: str | None
    country: str | None
    timezone: str | None
    public_ip: str | None
    latitude: float | None
    longitude: float | None
    source: str
    error: str | None = None

    @property
    def summary(self) -> str:
        if not self.available:
            return "Unavailable"

        parts = _dedupe_location_parts([self.city, self.region, self.country])
        return ", ".join(parts) if parts else "Approximate location detected"

    @property
    def short_summary(self) -> str:
        if not self.available:
            return "Location unavailable"

        parts = _dedupe_location_parts([self.city, self.country])
        return ", ".join(parts) if parts else self.summary

    @property
    def coordinates_summary(self) -> str:
        if self.latitude is None or self.longitude is None:
            return "Unavailable"
        return f"{self.latitude:.4f}, {self.longitude:.4f}"

    @property
    def latitude_summary(self) -> str:
        if self.latitude is None:
            return "Unavailable"
        return f"{self.latitude:.6f}"

    @property
    def longitude_summary(self) -> str:
        if self.longitude is None:
            return "Unavailable"
        return f"{self.longitude:.6f}"


def detect_host_platform() -> HostPlatformInfo:
    """Detect the current host OS and normalize user-facing metadata."""

    system = platform.system() or "Unknown"
    release = platform.release() or "unknown"
    version = platform.version() or "unknown"
    machine = platform.machine() or "unknown"

    if system == "Darwin":
        display_name = "macOS"
        mac_release = platform.mac_ver()[0]
        if mac_release:
            release = mac_release
    elif system == "Linux":
        display_name = "Linux"
    elif system == "Windows":
        display_name = "Windows"
    else:
        display_name = system

    return HostPlatformInfo(
        system=system,
        display_name=display_name,
        release=release,
        version=version,
        machine=machine,
        local_wireguard_supported=system == "Linux",
    )


@lru_cache(maxsize=1)
def detect_host_location(timeout_sec: float = 1.5) -> HostLocationInfo:
    """Detect host location using best-effort public IP geolocation."""

    url = "https://ipwho.is/"
    request = urllib_request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "WGDesk/0.1",
        },
    )
    ssl_context = _build_ssl_context()

    try:
        with urllib_request.urlopen(
            request,
            timeout=timeout_sec,
            context=ssl_context,
        ) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (
        TimeoutError,
        OSError,
        ValueError,
        UnicodeDecodeError,
        urllib_error.URLError,
    ) as exc:
        return HostLocationInfo(
            available=False,
            city=None,
            region=None,
            country=None,
            timezone=None,
            public_ip=None,
            latitude=None,
            longitude=None,
            source="ipwho.is",
            error=str(exc),
        )

    success = bool(payload.get("success", True))
    if not success:
        return HostLocationInfo(
            available=False,
            city=None,
            region=None,
            country=None,
            timezone=None,
            public_ip=None,
            latitude=None,
            longitude=None,
            source="ipwho.is",
            error=str(payload.get("message") or payload.get("reason") or "Lookup failed."),
        )

    timezone_value = payload.get("timezone")
    timezone_name = None
    if isinstance(timezone_value, dict):
        timezone_name = timezone_value.get("id") or timezone_value.get("name")
    elif isinstance(timezone_value, str):
        timezone_name = timezone_value

    return HostLocationInfo(
        available=True,
        city=_clean_optional_text(payload.get("city")),
        region=_clean_optional_text(payload.get("region")),
        country=_clean_optional_text(payload.get("country")),
        timezone=_clean_optional_text(timezone_name),
        public_ip=_clean_optional_text(payload.get("ip")),
        latitude=_parse_optional_float(payload.get("latitude")),
        longitude=_parse_optional_float(payload.get("longitude")),
        source="ipwho.is",
        error=None,
    )


def detect_host_hardware() -> HostHardwareInfo:
    """Detect host hardware details for CLI and GUI status views."""

    system = platform.system() or "Unknown"
    storage_total_bytes = _detect_storage_total_bytes()

    if system == "Darwin":
        return _detect_macos_hardware(storage_total_bytes)
    if system == "Linux":
        return _detect_linux_hardware(storage_total_bytes)
    if system == "Windows":
        return _detect_windows_hardware(storage_total_bytes)

    logical_cores = os.cpu_count()
    return HostHardwareInfo(
        cpu_name=platform.processor() or "Unknown CPU",
        memory_total_bytes=None,
        storage_total_bytes=storage_total_bytes,
        cpu_physical_cores=logical_cores,
        cpu_logical_cores=logical_cores,
        gpu_cores=None,
    )


def format_bytes_binary(value: int | None) -> str:
    """Render bytes with binary units for human-readable status output."""

    if value is None or value < 0:
        return "Unavailable"

    units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    size = float(value)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PiB"


def is_linux() -> bool:
    """Return True when the current host is Linux."""

    return detect_host_platform().local_wireguard_supported


def linux_host_requirement_message(operation: str = "This action") -> str:
    """Return a clear cross-platform message for Linux-only operations."""

    host = detect_host_platform()
    return (
        f"{operation} is available only on the Linux host where WireGuard is running. "
        f"Current host: {host.display_name} {host.release}. Run it on your Ubuntu VPN server."
    )


def setup_logging(log_path: Path, verbose: bool = False) -> None:
    """Configure console and file logging once for the application."""

    log_path.parent.mkdir(parents=True, exist_ok=True)
    if not log_path.exists():
        log_path.touch()
        os.chmod(log_path, 0o640)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)

    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)

    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)


def run_command(
    command: Sequence[str],
    *,
    input_text: str | None = None,
    check: bool = True,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess without using the shell."""

    logger = logging.getLogger("subprocess")
    command_display = " ".join(shlex.quote(part) for part in command)
    logger.debug("Running command: %s", command_display)

    try:
        result = subprocess.run(
            list(command),
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
            cwd=cwd,
        )
    except FileNotFoundError as exc:
        raise VPNManagerError(
            f"Required command not found: {command[0]}. Install the needed package first."
        ) from exc
    except OSError as exc:
        raise VPNManagerError(f"Could not run command: {command_display}") from exc

    if check and result.returncode != 0:
        stderr = (result.stderr or "").strip() or "No error output was returned."
        raise VPNManagerError(f"Command failed: {command_display}\n{stderr}")

    return result


def write_text_file(path: Path, content: str, mode: int = 0o600) -> None:
    """Write text to disk and apply predictable permissions."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    os.chmod(path, mode)


def replace_file_atomically(source: Path, destination: Path, mode: int = 0o600) -> None:
    """Copy a file into place using an atomic replace within the target directory."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None

    try:
        with tempfile.NamedTemporaryFile(
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as temp_file:
            temp_path = Path(temp_file.name)

        shutil.copyfile(source, temp_path)
        os.chmod(temp_path, mode)
        os.replace(temp_path, destination)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def validate_client_name(name: str) -> str:
    """Validate client names used in SQLite and config filenames."""

    clean_name = name.strip()
    if not clean_name:
        raise VPNManagerError("Client name cannot be empty.")

    if not CLIENT_NAME_PATTERN.fullmatch(clean_name):
        raise VPNManagerError(
            "Client name may contain only letters, numbers, hyphens, and underscores."
        )

    return clean_name


def ensure_linux(operation: str = "This action") -> None:
    """Limit privileged operations to Linux hosts."""

    if not is_linux():
        raise VPNManagerError(linux_host_requirement_message(operation))


def is_root() -> bool:
    """Return True when the current process is running as root."""

    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid and geteuid() == 0)


def ensure_root() -> None:
    """Guard operations that must write into system paths or use systemctl."""

    if not is_root():
        raise VPNManagerError("This action must be run as root. Use sudo on Ubuntu.")


def utc_now_iso() -> str:
    """Return a stable UTC timestamp string."""

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _detect_storage_total_bytes() -> int | None:
    try:
        return shutil.disk_usage(Path.home()).total
    except OSError:
        return None


def _detect_macos_hardware(storage_total_bytes: int | None) -> HostHardwareInfo:
    profiler_output = _run_optional_command(
        ["system_profiler", "SPHardwareDataType", "SPDisplaysDataType"]
    )
    cpu_name = _run_optional_command(["sysctl", "-n", "machdep.cpu.brand_string"])
    memory_total_bytes = _parse_optional_int(_run_optional_command(["sysctl", "-n", "hw.memsize"]))
    physical_cores = _parse_optional_int(
        _run_optional_command(["sysctl", "-n", "hw.physicalcpu"])
    )
    logical_cores = _parse_optional_int(_run_optional_command(["sysctl", "-n", "hw.logicalcpu"]))
    gpu_cores: int | None = None

    if profiler_output:
        parsed_cpu_name, parsed_memory_bytes, parsed_cpu_cores, parsed_gpu_cores = (
            _parse_macos_system_profiler_output(profiler_output)
        )
        cpu_name = cpu_name or parsed_cpu_name
        memory_total_bytes = memory_total_bytes or parsed_memory_bytes
        physical_cores = physical_cores or parsed_cpu_cores
        gpu_cores = parsed_gpu_cores

    fallback_cores = os.cpu_count()
    return HostHardwareInfo(
        cpu_name=cpu_name or "Apple Silicon / Intel CPU",
        memory_total_bytes=memory_total_bytes,
        storage_total_bytes=storage_total_bytes,
        cpu_physical_cores=physical_cores or fallback_cores,
        cpu_logical_cores=logical_cores or fallback_cores,
        gpu_cores=gpu_cores,
    )


def _detect_linux_hardware(storage_total_bytes: int | None) -> HostHardwareInfo:
    cpu_name = platform.processor() or "Unknown CPU"
    memory_total_bytes: int | None = None
    physical_cores: int | None = None
    logical_cores = os.cpu_count()

    try:
        cpuinfo = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="ignore")
    except OSError:
        cpuinfo = ""

    model_match = re.search(r"^model name\s*:\s*(.+)$", cpuinfo, flags=re.MULTILINE)
    if model_match:
        cpu_name = model_match.group(1).strip()

    core_pairs = {
        (physical_id, core_id)
        for physical_id, core_id in re.findall(
            r"physical id\s*:\s*(\d+).*?core id\s*:\s*(\d+)",
            cpuinfo,
            flags=re.DOTALL,
        )
    }
    if core_pairs:
        physical_cores = len(core_pairs)
    else:
        cores_match = re.search(r"^cpu cores\s*:\s*(\d+)$", cpuinfo, flags=re.MULTILINE)
        if cores_match:
            physical_cores = int(cores_match.group(1))

    try:
        meminfo = Path("/proc/meminfo").read_text(encoding="utf-8", errors="ignore")
    except OSError:
        meminfo = ""

    memory_match = re.search(r"^MemTotal:\s*(\d+)\s+kB$", meminfo, flags=re.MULTILINE)
    if memory_match:
        memory_total_bytes = int(memory_match.group(1)) * 1024

    return HostHardwareInfo(
        cpu_name=cpu_name,
        memory_total_bytes=memory_total_bytes,
        storage_total_bytes=storage_total_bytes,
        cpu_physical_cores=physical_cores or logical_cores,
        cpu_logical_cores=logical_cores,
        gpu_cores=None,
    )


def _detect_windows_hardware(storage_total_bytes: int | None) -> HostHardwareInfo:
    cpu_name = (
        platform.processor()
        or os.getenv("PROCESSOR_IDENTIFIER")
        or "Unknown CPU"
    )
    logical_cores = os.cpu_count()
    physical_cores = _parse_optional_int(
        _run_optional_command(["wmic", "cpu", "get", "NumberOfCores", "/value"])
        or ""
    )
    memory_total_bytes = _detect_windows_memory_total()

    name_output = _run_optional_command(["wmic", "cpu", "get", "Name", "/value"])
    if name_output:
        match = re.search(r"Name=(.+)", name_output)
        if match:
            cpu_name = match.group(1).strip()

    return HostHardwareInfo(
        cpu_name=cpu_name,
        memory_total_bytes=memory_total_bytes,
        storage_total_bytes=storage_total_bytes,
        cpu_physical_cores=physical_cores or logical_cores,
        cpu_logical_cores=logical_cores,
        gpu_cores=None,
    )


def _detect_windows_memory_total() -> int | None:
    try:
        import ctypes

        class MemoryStatusEx(ctypes.Structure):
            _fields_: list[tuple[str, Any]] = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        status = MemoryStatusEx()
        status.dwLength = ctypes.sizeof(MemoryStatusEx)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return int(status.ullTotalPhys)
    except (AttributeError, ImportError, OSError):
        return None
    return None


def _parse_macos_system_profiler_output(
    profiler_output: str,
) -> tuple[str | None, int | None, int | None, int | None]:
    cpu_name: str | None = None
    memory_total_bytes: int | None = None
    cpu_cores: int | None = None
    gpu_cores: int | None = None

    cpu_match = re.search(
        r"^\s*(?:Chip|Processor Name):\s*(.+)$",
        profiler_output,
        flags=re.MULTILINE,
    )
    if cpu_match:
        cpu_name = cpu_match.group(1).strip()

    memory_match = re.search(r"^\s*Memory:\s*(.+)$", profiler_output, flags=re.MULTILINE)
    if memory_match:
        memory_total_bytes = _parse_size_to_bytes(memory_match.group(1).strip())

    cores_matches = [
        int(match)
        for match in re.findall(
            r"^\s*Total Number of Cores:\s*(\d+)",
            profiler_output,
            flags=re.MULTILINE,
        )
    ]
    if cores_matches:
        cpu_cores = cores_matches[0]
    if len(cores_matches) >= 2:
        gpu_cores = cores_matches[1]

    return cpu_name, memory_total_bytes, cpu_cores, gpu_cores


def _parse_size_to_bytes(value: str) -> int | None:
    match = re.match(r"^\s*(\d+(?:\.\d+)?)\s*([KMGTP]?B)\s*$", value, flags=re.IGNORECASE)
    if not match:
        return None

    number = float(match.group(1))
    unit = match.group(2).upper()
    multipliers = {
        "KB": 1024,
        "MB": 1024**2,
        "GB": 1024**3,
        "TB": 1024**4,
        "PB": 1024**5,
        "B": 1,
    }
    return int(number * multipliers[unit])


def _parse_optional_int(value: str | None) -> int | None:
    if not value:
        return None
    match = re.search(r"(\d+)", value)
    if not match:
        return None
    return int(match.group(1))


def _parse_optional_float(value: object) -> float | None:
    if value in {None, ""}:
        return None
    try:
        return float(str(value))
    except ValueError:
        return None


def _clean_optional_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _dedupe_location_parts(parts: Sequence[str | None]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()

    for part in parts:
        if not part:
            continue
        key = part.casefold()
        if key in seen:
            continue
        seen.add(key)
        normalized.append(part)

    return normalized


def _run_optional_command(command: Sequence[str]) -> str | None:
    try:
        result = subprocess.run(
            list(command),
            text=True,
            capture_output=True,
            check=False,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
        )
    except OSError:
        return None

    if result.returncode != 0:
        return None
    output = result.stdout.strip()
    return output or None


def _build_ssl_context() -> ssl.SSLContext | None:
    if certifi is None:
        return None

    try:
        return ssl.create_default_context(cafile=certifi.where())
    except (OSError, ssl.SSLError):
        return None
