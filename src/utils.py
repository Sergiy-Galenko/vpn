from __future__ import annotations

import logging
import os
import platform
import re
import shlex
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from src.models import VPNManagerError


CLIENT_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")


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


def ensure_linux() -> None:
    """Limit privileged operations to Linux hosts."""

    if platform.system() != "Linux":
        raise VPNManagerError("WireGuard service operations in this project require Linux.")


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
