from __future__ import annotations

from dataclasses import dataclass


class VPNManagerError(Exception):
    """Raised for expected application-level errors."""


@dataclass(slots=True)
class ClientRecord:
    """Stored client metadata."""

    name: str
    address: str
    public_key: str
    private_key: str
    config_path: str
    created_at: str


@dataclass(slots=True)
class ConnectedClient:
    """Runtime WireGuard peer status."""

    public_key: str
    name: str | None
    address: str | None
    endpoint: str
    latest_handshake: int
    transfer_rx: int
    transfer_tx: int
