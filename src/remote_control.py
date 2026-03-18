from __future__ import annotations

import base64
import json
import shlex
import time
from dataclasses import dataclass
from pathlib import Path

from src.models import RemoteProfileRecord, VPNManagerError
from src.secret_store import SecretStore

try:
    import paramiko
except ImportError:  # pragma: no cover - runtime dependency
    paramiko = None


@dataclass(slots=True)
class RemoteExecutionResult:
    stdout: str
    stderr: str
    exit_status: int
    duration_ms: int


class SSHRemoteController:
    """Execute bundled Python agent actions on a remote Ubuntu host over SSH."""

    def __init__(self, profile: RemoteProfileRecord, secret_store: SecretStore) -> None:
        self.profile = profile
        self.secret_store = secret_store
        self._client: paramiko.SSHClient | None = None if paramiko is not None else None
        self.agent_script = (Path(__file__).resolve().parent / "remote_agent.py").read_text(
            encoding="utf-8"
        )

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def ping(self) -> dict[str, object]:
        return self.execute("ping", {})

    def execute(
        self,
        action: str,
        payload: dict[str, object],
        *,
        sudo: bool = False,
        timeout_sec: int | None = None,
    ) -> dict[str, object]:
        request = {
            "action": action,
            "payload": payload,
        }
        encoded = base64.b64encode(json.dumps(request).encode("utf-8")).decode("ascii")
        result = self._run_command(
            ["python3", "-", encoded],
            sudo=sudo and self.profile.use_sudo,
            timeout_sec=timeout_sec or self.profile.connect_timeout_seconds,
        )

        try:
            response = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise VPNManagerError(
                f"Remote agent returned invalid JSON:\n{result.stdout[:400]}"
            ) from exc

        if not response.get("ok"):
            raise VPNManagerError(str(response.get("error_message") or "Unknown remote agent error."))

        data = response.get("data")
        if not isinstance(data, dict):
            raise VPNManagerError("Remote agent returned an unexpected response payload.")
        return data

    def test_connection(self) -> None:
        self.ping()

    def read_text_file(self, remote_path: str) -> str:
        payload = self.execute("read_file", {"path": remote_path}, sudo=self.profile.use_sudo)
        content = payload.get("content")
        if not isinstance(content, str):
            raise VPNManagerError(f"Remote file '{remote_path}' returned invalid content.")
        return content

    def _run_command(
        self,
        argv: list[str],
        *,
        sudo: bool,
        timeout_sec: int,
    ) -> RemoteExecutionResult:
        if paramiko is None:
            raise VPNManagerError(
                "Remote SSH mode requires the 'paramiko' package. Install dependencies from requirements.txt."
            )

        client = self._ensure_client()
        command = self._build_remote_command(argv, sudo=sudo)
        started = time.perf_counter()

        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout_sec)
        except paramiko.AuthenticationException as exc:
            raise VPNManagerError("SSH authentication failed.") from exc
        except OSError as exc:
            raise VPNManagerError(f"SSH network error: {exc}") from exc

        if sudo:
            sudo_password = self._sudo_password
            if sudo_password is None:
                raise VPNManagerError(
                    "Remote profile requires sudo, but no sudo password is configured."
                )
            stdin.write(f"{sudo_password}\n")

        stdin.write(self.agent_script)
        stdin.flush()
        stdin.channel.shutdown_write()

        exit_status = stdout.channel.recv_exit_status()
        result = RemoteExecutionResult(
            stdout=stdout.read().decode("utf-8", errors="replace"),
            stderr=stderr.read().decode("utf-8", errors="replace"),
            exit_status=exit_status,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

        if exit_status != 0:
            raise VPNManagerError(result.stderr.strip() or result.stdout.strip() or "Remote command failed.")
        return result

    def _ensure_client(self) -> "paramiko.SSHClient":
        if self._client is not None:
            return self._client

        if paramiko is None:
            raise VPNManagerError("paramiko is not installed.")

        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

        connect_kwargs: dict[str, object] = {
            "hostname": self.profile.host,
            "port": self.profile.port,
            "username": self.profile.username,
            "timeout": self.profile.connect_timeout_seconds,
            "banner_timeout": self.profile.connect_timeout_seconds,
            "auth_timeout": self.profile.connect_timeout_seconds,
            "look_for_keys": False,
            "allow_agent": False,
        }

        if self.profile.auth_method.value == "ssh_key":
            if not self.profile.private_key_path:
                raise VPNManagerError("SSH key authentication requires a private key path.")
            connect_kwargs["key_filename"] = self.profile.private_key_path
        else:
            password = self._password
            if not password:
                raise VPNManagerError("Password authentication requires a saved SSH password.")
            connect_kwargs["password"] = password

        try:
            client.connect(**connect_kwargs)
        except paramiko.BadHostKeyException as exc:
            raise VPNManagerError(f"SSH host key mismatch for {exc.hostname}.") from exc
        except paramiko.AuthenticationException as exc:
            raise VPNManagerError("SSH authentication failed.") from exc
        except OSError as exc:
            raise VPNManagerError(f"SSH connection failed: {exc}") from exc

        self._verify_host_fingerprint(client)
        self._client = client
        return client

    def _verify_host_fingerprint(self, client: "paramiko.SSHClient") -> None:
        expected = (self.profile.known_host_fingerprint or "").strip()
        if not expected:
            return

        transport = client.get_transport()
        if transport is None:
            raise VPNManagerError("SSH transport is unavailable.")

        actual = transport.get_remote_server_key().get_fingerprint().hex()
        if actual.lower() != expected.lower():
            raise VPNManagerError(
                f"Remote host fingerprint mismatch: expected {expected}, got {actual}."
            )

    def _build_remote_command(self, argv: list[str], *, sudo: bool) -> str:
        command_argv = list(argv)
        if sudo:
            command_argv = ["sudo", "-S", "-p", ""] + command_argv
        return shlex.join(command_argv)

    @property
    def _password(self) -> str | None:
        if not self.profile.password_secret_key:
            return None
        return self.secret_store.get(self.profile.password_secret_key)

    @property
    def _sudo_password(self) -> str | None:
        if not self.profile.sudo_password_secret_key:
            return None
        return self.secret_store.get(self.profile.sudo_password_secret_key)
