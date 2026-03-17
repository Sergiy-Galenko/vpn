from __future__ import annotations

import os
import subprocess
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


@dataclass(slots=True)
class LocalExecutorOptions:
    sudo_password: str | None = None


class LocalCommandExecutor(CommandExecutor):
    def __init__(self, options: LocalExecutorOptions | None = None) -> None:
        self.options = options or LocalExecutorOptions()

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
        destination = Path(remote)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(local.read_bytes())
        os.chmod(destination, mode)

    def download(self, remote: str, local: Path) -> None:
        source = Path(remote)
        if not source.exists():
            raise CommandExecutionError(CommandErrorKind.NOT_FOUND, f"Missing file: {remote}")
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_bytes(source.read_bytes())

    def test_connection(self) -> None:
        self.execute(CommandRequest(argv=["python3", "--version"], timeout_sec=10))

    def _run_once(self, request: CommandRequest) -> CommandResult:
        argv = self._build_argv(request)
        stdin = request.stdin
        if request.sudo and self.options.sudo_password:
            stdin = f"{self.options.sudo_password}\n{request.stdin or ''}"

        started = time.perf_counter()
        try:
            completed = subprocess.run(
                argv,
                input=stdin,
                text=True,
                capture_output=True,
                timeout=request.timeout_sec,
                cwd=request.cwd,
                env={**os.environ, **(request.env or {})},
                check=False,
            )
        except FileNotFoundError as exc:
            raise CommandExecutionError(
                CommandErrorKind.NOT_FOUND,
                f"Command not found: {argv[0]}",
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise CommandExecutionError(
                CommandErrorKind.TIMEOUT,
                f"Command timed out after {request.timeout_sec}s",
                stderr=(exc.stderr or ""),
                stdout=(exc.stdout or ""),
            ) from exc
        except OSError as exc:
            raise CommandExecutionError(CommandErrorKind.UNKNOWN, str(exc)) from exc

        duration_ms = int((time.perf_counter() - started) * 1000)
        if completed.returncode != 0:
            raise CommandExecutionError(
                CommandErrorKind.NON_ZERO_EXIT,
                f"Command failed with exit code {completed.returncode}",
                stderr=completed.stderr,
                stdout=completed.stdout,
            )

        return CommandResult(
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            duration_ms=duration_ms,
        )

    def _build_argv(self, request: CommandRequest) -> list[str]:
        if not request.sudo:
            return request.argv

        if os.name != "posix":
            raise CommandExecutionError(
                CommandErrorKind.PERMISSION,
                "sudo execution is supported only on POSIX hosts",
            )

        if self.options.sudo_password:
            return ["sudo", "-S", "-p", ""] + request.argv
        return ["sudo"] + request.argv

