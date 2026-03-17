from __future__ import annotations

from uuid import uuid4

from wgdesk.application.errors import SecretStoreError

try:
    import keyring
except ImportError:  # pragma: no cover - runtime dependency
    keyring = None


class KeyringSecretStore:
    def __init__(self, service_name: str) -> None:
        self.service_name = service_name

    def put(self, secret_value: str) -> str:
        if keyring is None:
            raise SecretStoreError("keyring is not installed")
        secret_ref = str(uuid4())
        try:
            keyring.set_password(self.service_name, secret_ref, secret_value)
        except Exception as exc:  # pragma: no cover - backend-specific failures
            raise SecretStoreError(f"Failed to store secret in keyring: {exc}") from exc
        return secret_ref

    def get(self, secret_ref: str) -> str:
        if keyring is None:
            raise SecretStoreError("keyring is not installed")
        try:
            value = keyring.get_password(self.service_name, secret_ref)
        except Exception as exc:  # pragma: no cover - backend-specific failures
            raise SecretStoreError(f"Failed to read secret from keyring: {exc}") from exc
        if value is None:
            raise SecretStoreError(f"Secret not found: {secret_ref}")
        return value

    def delete(self, secret_ref: str) -> None:
        if keyring is None:
            return
        try:
            keyring.delete_password(self.service_name, secret_ref)
        except Exception:
            return

    def is_available(self) -> bool:
        if keyring is None:
            return False
        try:
            backend = keyring.get_keyring()
        except Exception:
            return False
        return getattr(backend, "priority", 0) > 0
