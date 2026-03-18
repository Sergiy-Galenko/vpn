from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(slots=True)
class ParsedPeer:
    """Parsed peer block from a WireGuard configuration."""

    public_key: str
    allowed_ips: str | None
    inferred_name: str | None
    raw_block: str


PEER_NAME_PATTERNS = [
    re.compile(r"^\s*#\s*client\s*:\s*(.+?)\s*$", flags=re.IGNORECASE),
    re.compile(r"^\s*#\s*name\s*:\s*(.+?)\s*$", flags=re.IGNORECASE),
    re.compile(r"^\s*#\s*(.+?)\s*$"),
]


def parse_wireguard_peers(config_text: str) -> list[ParsedPeer]:
    """Parse peer blocks from a WireGuard config and infer names from comments."""

    blocks = re.split(r"(?=^\[Peer\]\s*$)", config_text, flags=re.MULTILINE)
    peers: list[ParsedPeer] = []

    for block in blocks:
        if "[Peer]" not in block:
            continue

        public_key = _extract_setting(block, "PublicKey")
        if not public_key:
            continue

        peers.append(
            ParsedPeer(
                public_key=public_key,
                allowed_ips=_extract_setting(block, "AllowedIPs"),
                inferred_name=_infer_name_from_block(block),
                raw_block=block.strip(),
            )
        )

    return peers


def _extract_setting(block: str, key: str) -> str | None:
    match = re.search(
        rf"^\s*{re.escape(key)}\s*=\s*(.+?)\s*$",
        block,
        flags=re.MULTILINE,
    )
    if not match:
        return None
    return match.group(1).strip()


def _infer_name_from_block(block: str) -> str | None:
    for line in block.splitlines():
        if not line.lstrip().startswith("#"):
            continue
        for pattern in PEER_NAME_PATTERNS:
            match = pattern.match(line)
            if match:
                name = match.group(1).strip()
                return name or None
    return None
