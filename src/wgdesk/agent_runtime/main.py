from __future__ import annotations

import base64
import json
import platform
import secrets
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = 1


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def state_dir() -> Path:
    return Path.home() / ".wgdesk-agent"


def state_file() -> Path:
    return state_dir() / "server_state.json"


def ensure_state() -> dict[str, Any]:
    directory = state_dir()
    directory.mkdir(parents=True, exist_ok=True)
    path = state_file()
    if not path.exists():
        default_state = {
            "hostname": socket.gethostname(),
            "interface_name": "wg0",
            "endpoint": "",
            "listen_port": 51820,
            "subnet_cidr": "10.8.0.0/24",
            "public_interface": "eth0",
            "service_state": "inactive",
            "firewall_backend": "unknown",
            "last_error": None,
            "created_at": utc_now(),
            "updated_at": utc_now(),
            "clients": [],
        }
        path.write_text(json.dumps(default_state, indent=2), encoding="utf-8")
    return json.loads(path.read_text(encoding="utf-8"))


def save_state(state: dict[str, Any]) -> None:
    state["updated_at"] = utc_now()
    state_file().write_text(json.dumps(state, indent=2), encoding="utf-8")


def detect_capabilities() -> list[str]:
    capabilities: list[str] = []
    for command in ("wg", "systemctl", "ufw", "nft"):
        if shutil.which(command):
            capabilities.append(command)
    return capabilities


def run_command(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        check=False,
    )


def generate_keypair() -> tuple[str, str]:
    if shutil.which("wg"):
        private_key = run_command(["wg", "genkey"]).stdout.strip()
        if private_key:
            out = subprocess.run(
                ["wg", "pubkey"],
                input=f"{private_key}\n",
                capture_output=True,
                text=True,
                check=False,
            ).stdout.strip()
            if out:
                return private_key, out
    private_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
    public_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
    return private_key, public_key


class CommandDispatcher:
    def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        action = request["action"]
        payload = request.get("payload", {})
        handler = {
            "ping": self.ping,
            "server_status": self.server_status,
            "list_clients": self.list_clients,
            "add_client": self.add_client,
            "disable_client": self.disable_client,
            "enable_client": self.enable_client,
        }.get(action)

        if handler is None:
            raise ValueError(f"Unsupported agent action: {action}")
        return handler(payload)

    def ping(self, payload: dict[str, Any]) -> dict[str, Any]:
        del payload
        return {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "protocol_version": PROTOCOL_VERSION,
            "capabilities": detect_capabilities(),
        }

    def server_status(self, payload: dict[str, Any]) -> dict[str, Any]:
        state = ensure_state()
        interface_name = payload.get("interface_name") or state.get("interface_name", "wg0")
        state["interface_name"] = interface_name

        service_state = state.get("service_state", "inactive")
        uptime_seconds: int | None = None
        if shutil_which("systemctl"):
            unit = f"wg-quick@{interface_name}"
            result = run_command(["systemctl", "is-active", unit])
            if result.returncode == 0:
                service_state = result.stdout.strip() or "active"
            elif result.stdout.strip():
                service_state = result.stdout.strip()

        active_peers = len([client for client in state["clients"] if client["status"] == "active"])
        save_state(state)
        return {
            "hostname": state["hostname"],
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "service_state": service_state,
            "interface_name": state["interface_name"],
            "endpoint": payload.get("endpoint") or state.get("endpoint", ""),
            "listen_port": int(payload.get("listen_port") or state.get("listen_port", 51820)),
            "active_peers": active_peers,
            "uptime_seconds": uptime_seconds,
            "firewall_backend": state.get("firewall_backend", "unknown"),
            "last_error": state.get("last_error"),
            "capabilities": detect_capabilities(),
        }

    def list_clients(self, payload: dict[str, Any]) -> dict[str, Any]:
        del payload
        state = ensure_state()
        return {"clients": state["clients"]}

    def add_client(self, payload: dict[str, Any]) -> dict[str, Any]:
        state = ensure_state()
        name = payload["name"].strip()
        if any(client["name"] == name for client in state["clients"]):
            raise ValueError(f"Client '{name}' already exists on the agent.")

        private_key, public_key = generate_keypair()
        address_cidr = payload["address_cidr"]
        state["endpoint"] = payload.get("endpoint", state.get("endpoint", ""))
        state["listen_port"] = int(payload.get("listen_port", state.get("listen_port", 51820)))
        state["interface_name"] = payload.get("interface_name", state.get("interface_name", "wg0"))
        state["public_interface"] = payload.get(
            "public_interface", state.get("public_interface", "eth0")
        )
        state["subnet_cidr"] = payload.get("subnet_cidr", state.get("subnet_cidr", "10.8.0.0/24"))

        client = {
            "id": payload["client_id"],
            "name": name,
            "email": payload.get("email"),
            "device": payload.get("device"),
            "comment": payload.get("comment"),
            "address_cidr": address_cidr,
            "public_key": public_key,
            "status": "active",
            "expiry_at": payload.get("expiry_at"),
            "created_at": utc_now(),
            "updated_at": utc_now(),
            "last_used_at": None,
        }
        state["clients"].append(client)
        save_state(state)

        dns_servers = payload.get("dns_servers", ["1.1.1.1"])
        allowed_ips = payload.get("allowed_ips", ["0.0.0.0/0", "::/0"])
        endpoint = payload.get("endpoint") or state.get("endpoint") or "vpn.example.com"
        client_config = (
            "[Interface]\n"
            f"PrivateKey = {private_key}\n"
            f"Address = {address_cidr}\n"
            f"DNS = {', '.join(dns_servers)}\n\n"
            "[Peer]\n"
            f"PublicKey = {payload.get('server_public_key', 'server-public-key')}\n"
            f"Endpoint = {endpoint}:{state['listen_port']}\n"
            f"AllowedIPs = {', '.join(allowed_ips)}\n"
            "PersistentKeepalive = 25\n"
        )

        return {
            "client": client,
            "private_key": private_key,
            "client_config": client_config,
            "address_cidr": address_cidr,
            "public_key": public_key,
        }

    def disable_client(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._toggle_client(payload["client_name"], "disabled")

    def enable_client(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._toggle_client(payload["client_name"], "active")

    def _toggle_client(self, client_name: str, status: str) -> dict[str, Any]:
        state = ensure_state()
        for client in state["clients"]:
            if client["name"] == client_name:
                client["status"] = status
                client["updated_at"] = utc_now()
                save_state(state)
                return {"client": client}
        raise ValueError(f"Client '{client_name}' not found on the agent.")


def build_response(ok: bool, data: dict[str, Any], error_message: str | None = None) -> str:
    payload = {
        "ok": ok,
        "data": data,
        "error_code": None if ok else "agent_error",
        "error_message": error_message,
        "protocol_version": PROTOCOL_VERSION,
    }
    return json.dumps(payload)


def main() -> int:
    if len(sys.argv) < 2:
        sys.stdout.write(build_response(False, {}, "Missing base64-encoded request payload"))
        return 1

    try:
        raw_request = base64.b64decode(sys.argv[1]).decode("utf-8")
        request = json.loads(raw_request)
        dispatcher = CommandDispatcher()
        response = dispatcher.handle(request)
        sys.stdout.write(build_response(True, response))
        return 0
    except Exception as exc:  # pragma: no cover - agent boundary
        sys.stdout.write(build_response(False, {}, str(exc)))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
