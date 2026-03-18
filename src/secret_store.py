from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from src.models import VPNManagerError
from src.utils import write_text_file

try:
    import keyring
    from keyring.errors import KeyringError
except ImportError:  # pragma: no cover - optional dependency at runtime
    keyring = None

    class KeyringError(Exception):
        pass

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:  # pragma: no cover - optional dependency at runtime
    Fernet = None

    class InvalidToken(Exception):
        pass


class SecretStore:
    """Store small secrets in keyring with encrypted-file fallback."""

    def __init__(self, data_dir: Path, *, service_name: str = "wgdesk-personal-vpn") -> None:
        self.data_dir = data_dir
        self.service_name = service_name
        self.vault_path = data_dir / "secrets.vault"
        self.key_path = data_dir / "secrets.key"
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def set(self, name: str, value: str) -> None:
        if keyring is not None:
            try:
                keyring.set_password(self.service_name, name, value)
                return
            except KeyringError:
                pass

        vault = self._load_vault()
        vault[name] = value
        self._save_vault(vault)

    def get(self, name: str) -> str | None:
        if keyring is not None:
            try:
                value = keyring.get_password(self.service_name, name)
            except KeyringError:
                value = None
            if value is not None:
                return value

        vault = self._load_vault()
        return vault.get(name)

    def delete(self, name: str) -> None:
        if keyring is not None:
            try:
                keyring.delete_password(self.service_name, name)
            except Exception:
                pass

        vault = self._load_vault()
        if name in vault:
            del vault[name]
            self._save_vault(vault)

    def _load_vault(self) -> dict[str, str]:
        if not self.vault_path.exists():
            return {}
        if Fernet is None:
            raise VPNManagerError(
                "Secret fallback vault requires 'cryptography'. Install dependencies from requirements.txt."
            )

        try:
            token = self.vault_path.read_bytes()
            payload = self._fernet().decrypt(token)
            data = json.loads(payload.decode("utf-8"))
        except (OSError, InvalidToken, ValueError, json.JSONDecodeError) as exc:
            raise VPNManagerError("Could not read encrypted secrets vault.") from exc

        if not isinstance(data, dict):
            raise VPNManagerError("Encrypted secrets vault has an invalid format.")

        return {str(key): str(value) for key, value in data.items()}

    def _save_vault(self, data: dict[str, str]) -> None:
        if Fernet is None:
            raise VPNManagerError(
                "Secret fallback vault requires 'cryptography'. Install dependencies from requirements.txt."
            )

        payload = json.dumps(data, sort_keys=True).encode("utf-8")
        token = self._fernet().encrypt(payload)
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        self.vault_path.write_bytes(token)
        os.chmod(self.vault_path, 0o600)

    def _fernet(self) -> Fernet:
        if Fernet is None:
            raise VPNManagerError("cryptography is not available for encrypted secret storage.")

        key = self._load_or_create_key()
        return Fernet(key)

    def _load_or_create_key(self) -> bytes:
        if self.key_path.exists():
            return self.key_path.read_bytes().strip()

        key = base64.urlsafe_b64encode(os.urandom(32))
        write_text_file(self.key_path, key.decode("ascii") + "\n")
        return key
