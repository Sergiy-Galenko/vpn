from __future__ import annotations

import base64
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def run_command(argv: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        input=input_text,
        capture_output=True,
        text=True,
        check=False,
    )


def ensure_directory(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def write_text_atomic(path: Path, content: str, mode: int = 0o600) -> None:
    ensure_directory(path)
    with tempfile.NamedTemporaryFile(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        temp_path = Path(handle.name)
        temp_path.write_text(content, encoding="utf-8")
    os.chmod(temp_path, mode)
    os.replace(temp_path, path)


def detect_firewall_backend() -> str:
    if shutil.which("ufw"):
        return "ufw"
    if shutil.which("nft"):
        return "nftables"
    return "unknown"


def configure_firewall(port: int) -> dict[str, str]:
    backend = detect_firewall_backend()
    if backend == "ufw":
        result = run_command(["ufw", "allow", f"{port}/udp"])
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "ufw allow failed")
        return {"backend": backend, "state": f"allowed {port}/udp"}

    if backend == "nftables":
        ruleset = run_command(["nft", "list", "ruleset"]).stdout
        if "table inet wgdesk" not in ruleset:
            create_result = run_command(
                ["nft", "-f", "-"],
                input_text=(
                    "table inet wgdesk {\n"
                    "  chain input {\n"
                    "    type filter hook input priority 0; policy accept;\n"
                    "  }\n"
                    "}\n"
                ),
            )
            if create_result.returncode != 0:
                raise RuntimeError(create_result.stderr.strip() or "nft table creation failed")
        if f"udp dport {port} accept" not in ruleset:
            result = run_command(
                [
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    "wgdesk",
                    "input",
                    "udp",
                    "dport",
                    str(port),
                    "accept",
                ]
            )
            if result.returncode != 0 and "File exists" not in result.stderr:
                raise RuntimeError(result.stderr.strip() or "nft add rule failed")
        return {"backend": backend, "state": f"allowed udp/{port}"}

    return {"backend": backend, "state": "no supported firewall backend detected"}


def enable_ip_forwarding(sysctl_path: Path) -> None:
    write_text_atomic(
        sysctl_path,
        "net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n",
        mode=0o644,
    )
    result = run_command(["sysctl", "--system"])
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "sysctl --system failed")


def service_state(service_name: str) -> str:
    if not shutil.which("systemctl"):
        return "systemctl-unavailable"
    result = run_command(["systemctl", "is-active", service_name])
    if result.returncode == 0:
        return result.stdout.strip() or "active"
    return result.stdout.strip() or "inactive"


def system_uptime_seconds(service_name: str) -> int | None:
    if not shutil.which("systemctl"):
        return None
    result = run_command(
        ["systemctl", "show", service_name, "--property=ActiveEnterTimestampMonotonic", "--value"]
    )
    if result.returncode != 0:
        return None
    raw = result.stdout.strip()
    if not raw.isdigit():
        return None
    microseconds = int(raw)
    if microseconds <= 0:
        return None
    now = time.monotonic()
    return max(0, int(now - (microseconds / 1_000_000)))


def validate_environment(payload: dict[str, object]) -> dict[str, object]:
    listen_port = int(payload["server_port"])
    public_interface = str(payload["public_interface"])
    interface_name = str(payload["interface_name"])
    issues: list[dict[str, str]] = []

    for command in ("python3", "systemctl", "wg", "wg-quick"):
        if not shutil.which(command):
            issues.append(
                {
                    "code": f"missing_{command}",
                    "severity": "error",
                    "message": f"Required command '{command}' is not installed on the remote host.",
                }
            )

    ip_result = run_command(["ip", "link", "show", public_interface])
    if ip_result.returncode != 0:
        issues.append(
            {
                "code": "missing_public_interface",
                "severity": "error",
                "message": f"Public interface '{public_interface}' does not exist on the remote host.",
            }
        )

    service_name = f"wg-quick@{interface_name}"
    state = service_state(service_name)
    port_result = run_command(["ss", "-H", "-lun", f"sport = :{listen_port}"])
    port_busy = bool(port_result.stdout.strip())
    if port_busy and state not in {"active", "activating"}:
        issues.append(
            {
                "code": "port_busy",
                "severity": "warning",
                "message": f"UDP port {listen_port} already appears to be in use.",
            }
        )

    return {
        "issues": issues,
        "service_state": state,
        "capabilities": [name for name in ("wg", "systemctl", "ufw", "nft") if shutil.which(name)],
    }


def install_wireguard(payload: dict[str, object]) -> dict[str, object]:
    result = run_command(["apt-get", "update"])
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "apt-get update failed")

    result = run_command(["apt-get", "install", "-y", "wireguard", "wireguard-tools"])
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "apt-get install failed")

    enable_ip_forwarding(Path(str(payload["sysctl_config_path"])))
    firewall = configure_firewall(int(payload["server_port"]))
    return {
        "firewall_backend": firewall["backend"],
        "firewall_state": firewall["state"],
    }


def sync_server_config(payload: dict[str, object]) -> dict[str, object]:
    config_text = str(payload["config_text"])
    system_config_path = Path(str(payload["system_config_path"]))
    interface_name = str(payload["interface_name"])
    service_name = str(payload["service_name"])
    desired_action = str(payload.get("service_action") or "restart")
    prefer_sync = bool(payload.get("prefer_sync", True))

    ensure_directory(system_config_path)
    previous_content = system_config_path.read_text(encoding="utf-8") if system_config_path.exists() else None
    write_text_atomic(system_config_path, config_text)

    try:
        state = service_state(service_name)
        if state == "active" and prefer_sync and shutil.which("wg") and shutil.which("wg-quick"):
            with tempfile.NamedTemporaryFile(delete=False, suffix=".conf") as raw_config:
                raw_path = Path(raw_config.name)
                raw_path.write_text(config_text, encoding="utf-8")

            strip_result = run_command(["wg-quick", "strip", str(raw_path)])
            if strip_result.returncode == 0:
                stripped_path = raw_path.with_suffix(".stripped.conf")
                stripped_path.write_text(strip_result.stdout, encoding="utf-8")
                sync_result = run_command(["wg", "syncconf", interface_name, str(stripped_path)])
                raw_path.unlink(missing_ok=True)
                stripped_path.unlink(missing_ok=True)
                if sync_result.returncode != 0:
                    raise RuntimeError(sync_result.stderr.strip() or "wg syncconf failed")
                return {"applied_via": "syncconf", "service_state": state}
            raw_path.unlink(missing_ok=True)

        if desired_action != "none":
            action_result = run_command(["systemctl", desired_action, service_name])
            if action_result.returncode != 0:
                raise RuntimeError(
                    action_result.stderr.strip() or f"systemctl {desired_action} failed"
                )
        return {"applied_via": desired_action, "service_state": service_state(service_name)}
    except Exception:
        if previous_content is None:
            system_config_path.unlink(missing_ok=True)
        else:
            write_text_atomic(system_config_path, previous_content)
            if desired_action == "restart":
                run_command(["systemctl", "restart", service_name])
        raise


def service_action(payload: dict[str, object]) -> dict[str, object]:
    service_name = str(payload["service_name"])
    action = str(payload["action"])
    result = run_command(["systemctl", action, service_name])
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"systemctl {action} failed")
    return {"service_state": service_state(service_name)}


def server_status(payload: dict[str, object]) -> dict[str, object]:
    service_name = str(payload["service_name"])
    interface_name = str(payload["interface_name"])
    status = show_connected({"interface_name": interface_name})
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "service_state": service_state(service_name),
        "interface_name": interface_name,
        "active_peers": len(status["peers"]),
        "uptime_seconds": system_uptime_seconds(service_name),
        "firewall_backend": detect_firewall_backend(),
        "capabilities": [name for name in ("wg", "systemctl", "ufw", "nft") if shutil.which(name)],
    }


def show_connected(payload: dict[str, object]) -> dict[str, object]:
    interface_name = str(payload["interface_name"])
    if not shutil.which("wg"):
        return {"peers": []}

    result = run_command(["wg", "show", interface_name, "dump"])
    if result.returncode != 0:
        stderr = result.stderr.strip()
        if stderr:
            raise RuntimeError(stderr)
        return {"peers": []}

    peers: list[dict[str, object]] = []
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    current_time = int(time.time())
    window_seconds = int(payload.get("connected_window_seconds", 180))

    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        latest_handshake = int(parts[4])
        if latest_handshake == 0 or current_time - latest_handshake > window_seconds:
            continue
        peers.append(
            {
                "public_key": parts[0],
                "endpoint": parts[2],
                "latest_handshake": latest_handshake,
                "transfer_rx": int(parts[5]),
                "transfer_tx": int(parts[6]),
            }
        )

    return {"peers": peers}


def read_file(payload: dict[str, object]) -> dict[str, object]:
    path = Path(str(payload["path"]))
    if not path.exists():
        raise RuntimeError(f"File does not exist: {path}")
    return {"content": path.read_text(encoding="utf-8")}


def dispatch(action: str, payload: dict[str, object]) -> dict[str, object]:
    if action == "ping":
        return {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "capabilities": [name for name in ("wg", "systemctl", "ufw", "nft") if shutil.which(name)],
        }
    if action == "validate_environment":
        return validate_environment(payload)
    if action == "install_wireguard":
        return install_wireguard(payload)
    if action == "sync_server_config":
        return sync_server_config(payload)
    if action == "service_action":
        return service_action(payload)
    if action == "server_status":
        return server_status(payload)
    if action == "show_connected":
        return show_connected(payload)
    if action == "read_file":
        return read_file(payload)
    raise RuntimeError(f"Unsupported remote action: {action}")


def build_response(ok: bool, data: dict[str, object], error_message: str | None = None) -> str:
    return json.dumps(
        {
            "ok": ok,
            "data": data,
            "error_message": error_message,
        }
    )


def main() -> int:
    if len(sys.argv) < 2:
        sys.stdout.write(build_response(False, {}, "Missing base64 request payload"))
        return 1

    try:
        request = json.loads(base64.b64decode(sys.argv[1]).decode("utf-8"))
        action = str(request["action"])
        payload = dict(request.get("payload", {}))
        response = dispatch(action, payload)
        sys.stdout.write(build_response(True, response))
        return 0
    except Exception as exc:  # pragma: no cover - remote boundary
        sys.stdout.write(build_response(False, {}, str(exc)))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
