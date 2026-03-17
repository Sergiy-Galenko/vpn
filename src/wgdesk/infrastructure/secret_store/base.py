from __future__ import annotations

from typing import Protocol


class SecretStore(Protocol):
    def put(self, secret_value: str) -> str: ...

    def get(self, secret_ref: str) -> str: ...

    def delete(self, secret_ref: str) -> None: ...

    def is_available(self) -> bool: ...

