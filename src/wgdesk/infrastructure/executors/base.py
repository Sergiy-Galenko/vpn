from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Protocol


class CommandErrorKind(StrEnum):
    AUTH = "auth"
    TIMEOUT = "timeout"
    NETWORK = "network"
    PERMISSION = "permission"
    NOT_FOUND = "not_found"
    NON_ZERO_EXIT = "non_zero_exit"
    PROTOCOL = "protocol"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class RetryPolicy:
    attempts: int = 1
    backoff_sec: float = 0.0


@dataclass(slots=True)
class CommandRequest:
    argv: list[str]
    stdin: str | None = None
    env: dict[str, str] | None = None
    cwd: str | None = None
    timeout_sec: int = 30
    sudo: bool = False
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)


@dataclass(slots=True)
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    remote_host: str | None = None


class CommandExecutionError(Exception):
    def __init__(
        self,
        kind: CommandErrorKind,
        message: str,
        *,
        stderr: str = "",
        stdout: str = "",
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.stderr = stderr
        self.stdout = stdout


class CommandExecutor(Protocol):
    def execute(self, request: CommandRequest) -> CommandResult: ...

    def upload(self, local: Path, remote: str, mode: int = 0o600) -> None: ...

    def download(self, remote: str, local: Path) -> None: ...

    def test_connection(self) -> None: ...

