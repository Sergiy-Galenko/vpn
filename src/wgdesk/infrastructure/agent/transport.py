from __future__ import annotations

import base64
import json
import uuid
from pathlib import Path
from typing import Any

from wgdesk.application.errors import AgentTransportError
from wgdesk.infrastructure.agent.protocol import (
    AGENT_PROTOCOL_VERSION,
    AgentRequest,
    AgentResponse,
)
from wgdesk.infrastructure.executors.base import (
    CommandExecutionError,
    CommandExecutor,
    CommandRequest,
    RetryPolicy,
)


class AgentTransport:
    READ_ONLY_ACTIONS = frozenset({"ping", "server_status", "list_clients"})

    def __init__(self, executor: CommandExecutor, *, timeout_sec: int = 20) -> None:
        self.executor = executor
        self.timeout_sec = timeout_sec
        self.inline_agent_script = (
            Path(__file__).resolve().parents[2] / "agent_runtime" / "main.py"
        ).read_text(encoding="utf-8")

    def ping(self) -> dict[str, Any]:
        return self.execute("ping", {})

    def execute(
        self,
        action: str,
        payload: dict[str, Any],
        *,
        timeout_sec: int | None = None,
        sudo: bool = False,
    ) -> dict[str, Any]:
        request = AgentRequest(
            action=action,
            payload=payload,
            request_id=str(uuid.uuid4()),
        )
        encoded = base64.b64encode(request.to_json().encode("utf-8")).decode("ascii")
        command = CommandRequest(
            argv=["python3", "-", encoded],
            stdin=self.inline_agent_script,
            timeout_sec=timeout_sec or self.timeout_sec,
            sudo=sudo,
            retry_policy=RetryPolicy(
                attempts=2 if action in self.READ_ONLY_ACTIONS else 1,
                backoff_sec=0.25 if action in self.READ_ONLY_ACTIONS else 0.0,
            ),
        )
        try:
            result = self.executor.execute(command)
        except CommandExecutionError as exc:
            raise AgentTransportError(f"Agent request failed: {exc}") from exc

        try:
            response = AgentResponse.from_json(result.stdout)
        except json.JSONDecodeError as exc:
            raise AgentTransportError(
                f"Agent returned invalid JSON response: {result.stdout[:400]}"
            ) from exc

        if response.protocol_version != AGENT_PROTOCOL_VERSION:
            raise AgentTransportError(
                f"Agent protocol mismatch: expected {AGENT_PROTOCOL_VERSION}, "
                f"got {response.protocol_version}"
            )
        if not response.ok:
            raise AgentTransportError(response.error_message or "Unknown agent failure")

        return response.data
