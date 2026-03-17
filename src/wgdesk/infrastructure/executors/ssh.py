from __future__ import annotations

import os
import shlex
import time
from dataclasses import dataclass
from pathlib import Path

from wgdesk.infrastructure.executors.base import (
    CommandErrorKind,
    CommandExecutionError,
    CommandExecutor,
    CommandRequest,
    CommandResult,
)

try:
    import paramiko
except ImportError:  # pragma: no cover - dependency injected at runtime
    paramiko = None


@dataclass(slots=True)
class SSHExecutorOptions:
    host: str
    port: int
    username: str
    password: str | None = None
    private_key_path: str | None = None
    private_key_passphrase: str | None = None
    sudo_password: str | None = None
    known_host_fingerprint: str | None = None
    timeout_sec: int = 10


class SSHCommandExecutor(CommandExecutor):
    def __init__(self, options: SSHExecutorOptions) -> None:
        if paramiko is None:
            raise CommandExecutionError(
                CommandErrorKind.NOT_FOUND,
                "paramiko is not installed",
            )
        self.options = options
        self._client: paramiko.SSHClient | None = None

    def execute(self, request: CommandRequest) -> CommandResult:
        attempts = max(1, request.retry_policy.attempts)
        last_error: CommandExecutionError | None = None
        for attempt in range(1, attempts + 1):
            try:
                return self._run_once(request)
            except CommandExecutionError as exc:
                last_error = exc
                if attempt >= attempts or request.retry_policy.backoff_sec <= 0:
                    break
                time.sleep(request.retry_policy.backoff_sec)
        assert last_error is not None
        raise last_error

    def upload(self, local: Path, remote: str, mode: int = 0o600) -> None:
        client = self._ensure_client()
        with client.open_sftp() as sftp:
            self._ensure_remote_dirs(sftp, remote)
            sftp.put(str(local), remote)
            sftp.chmod(remote, mode)

    def download(self, remote: str, local: Path) -> None:
        client = self._ensure_client()
        local.parent.mkdir(parents=True, exist_ok=True)
        with client.open_sftp() as sftp:
            sftp.get(remote, str(local))

    def test_connection(self) -> None:
        self._ensure_client()

    def _run_once(self, request: CommandRequest) -> CommandResult:
        client = self._ensure_client()
        command = self._build_remote_command(request)
        started = time.perf_counter()

        try:
            stdin, stdout, stderr = client.exec_command(
                command,
                timeout=request.timeout_sec,
                environment=request.env or None,
            )
        except paramiko.AuthenticationException as exc:
            raise CommandExecutionError(CommandErrorKind.AUTH, "SSH authentication failed") from exc
        except OSError as exc:
            raise CommandExecutionError(CommandErrorKind.NETWORK, str(exc)) from exc

        if request.stdin:
            stdin.write(request.stdin)
            stdin.flush()
        stdin.channel.shutdown_write()

        exit_status = stdout.channel.recv_exit_status()
        duration_ms = int((time.perf_counter() - started) * 1000)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")

        if exit_status != 0:
            kind = CommandErrorKind.NON_ZERO_EXIT
            if "Permission denied" in err:
                kind = CommandErrorKind.PERMISSION
            raise CommandExecutionError(
                kind,
                f"Remote command failed with exit code {exit_status}",
                stderr=err,
                stdout=out,
            )

        return CommandResult(
            exit_code=exit_status,
            stdout=out,
            stderr=err,
            duration_ms=duration_ms,
            remote_host=self.options.host,
        )

    def _ensure_client(self) -> "paramiko.SSHClient":
        if self._client is not None:
            return self._client

        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

        connect_kwargs: dict[str, object] = {
            "hostname": self.options.host,
            "port": self.options.port,
            "username": self.options.username,
            "timeout": self.options.timeout_sec,
            "banner_timeout": self.options.timeout_sec,
            "auth_timeout": self.options.timeout_sec,
            "look_for_keys": False,
            "allow_agent": False,
        }
        if self.options.private_key_path:
            connect_kwargs["key_filename"] = self.options.private_key_path
            if self.options.private_key_passphrase:
                connect_kwargs["passphrase"] = self.options.private_key_passphrase
        if self.options.password:
            connect_kwargs["password"] = self.options.password

        try:
            client.connect(**connect_kwargs)
        except paramiko.AuthenticationException as exc:
            raise CommandExecutionError(CommandErrorKind.AUTH, "SSH authentication failed") from exc
        except paramiko.BadHostKeyException as exc:
            raise CommandExecutionError(CommandErrorKind.AUTH, f"Bad host key for {exc.hostname}") from exc
        except OSError as exc:
            raise CommandExecutionError(CommandErrorKind.NETWORK, str(exc)) from exc

        self._verify_host_fingerprint(client)
        self._client = client
        return client

    def _build_remote_command(self, request: CommandRequest) -> str:
        argv = request.argv
        if request.sudo:
            if self.options.sudo_password:
                argv = ["sudo", "-S", "-p", ""] + argv
            else:
                argv = ["sudo"] + argv
        return shlex.join(argv)

    def _verify_host_fingerprint(self, client: "paramiko.SSHClient") -> None:
        expected = self.options.known_host_fingerprint
        if not expected:
            return

        transport = client.get_transport()
        if transport is None:
            raise CommandExecutionError(CommandErrorKind.PROTOCOL, "SSH transport unavailable")
        key = transport.get_remote_server_key()
        actual = key.get_fingerprint().hex()
        if actual.lower() != expected.lower():
            raise CommandExecutionError(
                CommandErrorKind.AUTH,
                f"Host fingerprint mismatch: expected {expected}, got {actual}",
            )

    @staticmethod
    def _ensure_remote_dirs(sftp: "paramiko.SFTPClient", remote: str) -> None:
        directory = os.path.dirname(remote)
        if not directory:
            return
        parts = directory.strip("/").split("/")
        current = "/"
        for part in parts:
            current = os.path.join(current, part)
            try:
                sftp.stat(current)
            except FileNotFoundError:
                sftp.mkdir(current)

