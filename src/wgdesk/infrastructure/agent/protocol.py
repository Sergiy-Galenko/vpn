from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any


AGENT_PROTOCOL_VERSION = 1


@dataclass(slots=True)
class AgentRequest:
    action: str
    payload: dict[str, Any] = field(default_factory=dict)
    request_id: str = ""
    protocol_version: int = AGENT_PROTOCOL_VERSION

    def to_json(self) -> str:
        return json.dumps(asdict(self))


@dataclass(slots=True)
class AgentResponse:
    ok: bool
    data: dict[str, Any]
    error_code: str | None = None
    error_message: str | None = None
    protocol_version: int = AGENT_PROTOCOL_VERSION

    @classmethod
    def from_json(cls, raw: str) -> "AgentResponse":
        parsed = json.loads(raw)
        return cls(
            ok=bool(parsed["ok"]),
            data=dict(parsed.get("data", {})),
            error_code=parsed.get("error_code"),
            error_message=parsed.get("error_message"),
            protocol_version=int(parsed.get("protocol_version", AGENT_PROTOCOL_VERSION)),
        )

