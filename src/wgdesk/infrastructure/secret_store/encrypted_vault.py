from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from cryptography.fernet import Fernet

from wgdesk.application.errors import SecretStoreError


class EncryptedVaultSecretStore:
    def __init__(self, vault_dir: Path) -> None:
        self.vault_dir = vault_dir
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.key_path = self.vault_dir / "vault.key"
        self.secrets_dir = self.vault_dir / "secrets"
        self.secrets_dir.mkdir(parents=True, exist_ok=True)

    def put(self, secret_value: str) -> str:
        fernet = self._fernet()
        secret_ref = str(uuid4())
        encrypted = fernet.encrypt(secret_value.encode("utf-8"))
        path = self.secrets_dir / f"{secret_ref}.bin"
        path.write_bytes(encrypted)
        path.chmod(0o600)
        return secret_ref

    def get(self, secret_ref: str) -> str:
        path = self.secrets_dir / f"{secret_ref}.bin"
        if not path.exists():
            raise SecretStoreError(f"Secret not found: {secret_ref}")
        return self._fernet().decrypt(path.read_bytes()).decode("utf-8")

    def delete(self, secret_ref: str) -> None:
        path = self.secrets_dir / f"{secret_ref}.bin"
        path.unlink(missing_ok=True)

    def is_available(self) -> bool:
        return True

    def _fernet(self) -> Fernet:
        if not self.key_path.exists():
            self.key_path.write_bytes(Fernet.generate_key())
            self.key_path.chmod(0o600)
        try:
            return Fernet(self.key_path.read_bytes())
        except ValueError as exc:  # pragma: no cover - corruption guard
            raise SecretStoreError("Vault key is invalid") from exc

