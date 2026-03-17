from __future__ import annotations

import os
import shutil
import sys
from datetime import datetime, timezone
from typing import Callable

from src.config import EditableVPNSettings, editable_settings_from_config, save_editable_settings
from src.models import ConnectedClient, VPNManagerError
from src.utils import detect_host_platform
from src.wireguard_manager import WireGuardManager


ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "ink": "\033[38;5;24m",
    "teal": "\033[38;5;37m",
    "mint": "\033[38;5;79m",
    "amber": "\033[38;5;214m",
    "coral": "\033[38;5;203m",
    "paper": "\033[38;5;255m",
}


def _supports_ansi() -> bool:
    return sys.stdout.isatty() and os.getenv("TERM", "") not in {"", "dumb"}


def _format_iso(value: str) -> str:
    try:
        return datetime.fromisoformat(value).astimezone().strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return value


def _format_unix(value: int) -> str:
    if value <= 0:
        return "Never"
    return datetime.fromtimestamp(value, tz=timezone.utc).astimezone().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


class ConsoleApp:
    """Modern terminal interface for the WireGuard manager."""

    def __init__(
        self,
        manager: WireGuardManager,
        *,
        open_gui_callback: Callable[[], int] | None = None,
    ) -> None:
        self.manager = manager
        self.open_gui_callback = open_gui_callback
        self.host = detect_host_platform()
        self.use_ansi = _supports_ansi()

    def run(self) -> int:
        while True:
            self._clear()
            self._render_home()
            choice = input("\nSelect action: ").strip().lower()

            if choice in {"0", "q", "quit", "exit"}:
                self._print_message("Console session closed.", tone="teal")
                return 0
            if choice == "1":
                self._show_dashboard()
            elif choice == "2":
                self._show_system_info()
            elif choice == "3":
                self._show_vpn_config()
            elif choice == "4":
                self._edit_vpn_settings()
            elif choice == "5":
                self._add_client()
            elif choice == "6":
                self._remove_client()
            elif choice == "7":
                self._list_clients()
            elif choice == "8":
                self._show_connected_clients()
            elif choice == "9":
                self._run_linux_action("Install VPN", self.manager.install_wireguard)
            elif choice == "10":
                self._run_linux_action("Start VPN", self.manager.start_vpn)
            elif choice == "11":
                self._run_linux_action("Stop VPN", self.manager.stop_vpn)
            elif choice == "12":
                self._run_linux_action("Restart VPN", self.manager.restart_vpn)
            elif choice == "13":
                self._open_gui()
            else:
                self._pause("Unknown option.")

    def _render_home(self) -> None:
        width = min(shutil.get_terminal_size((110, 30)).columns, 110)
        title = "WGDesk Console"
        subtitle = f"{self.host.display_name} {self.host.release} | {self.host.machine}"
        rule = "═" * max(32, width - 4)
        print(self._style(f"╔{rule}╗", "ink", bold=True))
        print(self._style(f"║ {title:<{width - 4}} ║", "paper", bold=True))
        print(self._style(f"║ {subtitle:<{width - 4}} ║", "mint"))
        print(self._style(f"╚{rule}╝", "ink", bold=True))

        service_state = self._safe_service_state()
        settings = editable_settings_from_config(self.manager.config)
        clients = self.manager.list_clients_with_status()
        summary_lines = [
            f"Host summary      : {self.host.summary}",
            f"Endpoint          : {settings.endpoint}",
            f"Interface         : {settings.interface_name}",
            f"Server subnet     : {settings.server_address}",
            f"Service state     : {service_state}",
            f"Total clients     : {len(clients)}",
            (
                "Local control     : supported"
                if self.host.local_wireguard_supported
                else "Local control     : use Ubuntu host or future SSH mode"
            ),
        ]
        self._panel("Status", summary_lines, tone="teal")

        menu_lines = [
            "1  Dashboard",
            "2  System info",
            "3  Show VPN settings",
            "4  Edit VPN settings",
            "5  Add client",
            "6  Remove client",
            "7  List clients",
            "8  Show connected peers",
            f"9  Install VPN{' (Linux host only)' if not self.host.local_wireguard_supported else ''}",
            f"10 Start VPN{' (Linux host only)' if not self.host.local_wireguard_supported else ''}",
            f"11 Stop VPN{' (Linux host only)' if not self.host.local_wireguard_supported else ''}",
            f"12 Restart VPN{' (Linux host only)' if not self.host.local_wireguard_supported else ''}",
            "13 Open graphical interface",
            "0  Exit",
        ]
        self._panel("Actions", menu_lines, tone="amber")

    def _show_dashboard(self) -> None:
        clients = self.manager.list_clients_with_status()
        connected_total = sum(1 for _, is_connected in clients if is_connected)
        self._clear()
        self._panel(
            "Dashboard",
            [
                f"Host platform     : {self.host.summary}",
                f"Service state     : {self._safe_service_state()}",
                f"Interface         : {self.manager.config.interface_name}",
                f"Endpoint          : {self.manager.config.endpoint}",
                f"Server address    : {self.manager.config.server_interface}",
                f"Public interface  : {self.manager.config.public_interface}",
                f"Client count      : {len(clients)}",
                f"Connected peers   : {connected_total}",
                f"DNS               : {self.manager.config.dns}",
                f"Allowed IPs       : {self.manager.config.client_allowed_ips}",
            ],
            tone="teal",
        )
        self._pause()

    def _show_system_info(self) -> None:
        self._clear()
        self._panel(
            "System Info",
            [
                f"Host OS           : {self.host.display_name}",
                f"System            : {self.host.system}",
                f"Release           : {self.host.release}",
                f"Version           : {self.host.version}",
                f"Architecture      : {self.host.machine}",
                (
                    "Local control     : supported"
                    if self.host.local_wireguard_supported
                    else "Local control     : not available on this host"
                ),
            ],
            tone="mint",
        )
        self._pause()

    def _show_vpn_config(self) -> None:
        settings = editable_settings_from_config(self.manager.config)
        self._clear()
        self._panel(
            "VPN Settings",
            [
                f"WG_ENDPOINT                 = {settings.endpoint}",
                f"WG_INTERFACE_NAME           = {settings.interface_name}",
                f"WG_SERVER_ADDRESS           = {settings.server_address}",
                f"WG_SERVER_PORT              = {settings.server_port}",
                f"WG_PUBLIC_INTERFACE         = {settings.public_interface}",
                f"WG_DNS                      = {settings.dns}",
                f"WG_CLIENT_ALLOWED_IPS       = {settings.client_allowed_ips}",
                f"WG_CONNECTED_WINDOW_SECONDS = {settings.connected_window_seconds}",
            ],
            tone="amber",
        )
        self._pause()

    def _edit_vpn_settings(self) -> None:
        current = editable_settings_from_config(self.manager.config)
        self._clear()
        self._panel(
            "Edit VPN Settings",
            [
                "Press Enter to keep the current value.",
                "Updated values are saved into .env and applied immediately.",
            ],
            tone="coral",
        )
        try:
            updated = EditableVPNSettings(
                endpoint=self._prompt_with_default("Endpoint", current.endpoint),
                interface_name=self._prompt_with_default("Interface name", current.interface_name),
                server_address=self._prompt_with_default("Server address", current.server_address),
                server_port=int(
                    self._prompt_with_default("Server port", str(current.server_port))
                ),
                public_interface=self._prompt_with_default(
                    "Public interface",
                    current.public_interface,
                ),
                dns=self._prompt_with_default("DNS", current.dns),
                client_allowed_ips=self._prompt_with_default(
                    "Client allowed IPs",
                    current.client_allowed_ips,
                ),
                connected_window_seconds=int(
                    self._prompt_with_default(
                        "Connected window (seconds)",
                        str(current.connected_window_seconds),
                    )
                ),
            )
        except ValueError:
            self._pause("Server port and connected window must be integers.")
            return

        try:
            new_config = save_editable_settings(self.manager.config.project_root, updated)
            self.manager.update_config(new_config)
        except VPNManagerError as exc:
            self._pause(str(exc))
            return

        self._pause("VPN settings saved.")

    def _add_client(self) -> None:
        client_name = input("Client name: ").strip()
        if not client_name:
            self._pause("Client name is required.")
            return

        try:
            client = self.manager.add_client(client_name)
        except VPNManagerError as exc:
            self._pause(str(exc))
            return

        self._pause(f"Client created: {client.name}\nConfig: {client.config_path}")

    def _remove_client(self) -> None:
        client_name = input("Client name to remove: ").strip()
        if not client_name:
            self._pause("Client name is required.")
            return
        confirmation = input(f"Remove '{client_name}'? [y/N]: ").strip().lower()
        if confirmation not in {"y", "yes"}:
            self._pause("Removal cancelled.")
            return

        try:
            self.manager.remove_client(client_name)
        except VPNManagerError as exc:
            self._pause(str(exc))
            return

        self._pause(f"Client removed: {client_name}")

    def _list_clients(self) -> None:
        clients = self.manager.list_clients_with_status()
        self._clear()
        if not clients:
            self._panel("Clients", ["No clients have been created yet."], tone="amber")
            self._pause()
            return

        lines = [
            (
                f"{client.name:<18} {client.address:<16} "
                f"{'connected' if is_connected else 'idle':<10} "
                f"{_format_iso(client.created_at)}"
            )
            for client, is_connected in clients
        ]
        self._panel("Clients", lines, tone="teal")
        self._pause()

    def _show_connected_clients(self) -> None:
        self._clear()
        if not self.host.local_wireguard_supported:
            self._panel(
                "Connected Peers",
                ["Connected peer lookup is available only on the Ubuntu WireGuard host."],
                tone="coral",
            )
            self._pause()
            return

        try:
            peers = self.manager.get_connected_clients()
        except VPNManagerError as exc:
            self._panel("Connected Peers", [str(exc)], tone="coral")
            self._pause()
            return

        if not peers:
            self._panel("Connected Peers", ["No connected clients were detected."], tone="amber")
            self._pause()
            return

        lines = [self._format_connected_peer(peer) for peer in peers]
        self._panel("Connected Peers", lines, tone="mint")
        self._pause()

    def _run_linux_action(self, label: str, action: Callable[[], None]) -> None:
        if not self.host.local_wireguard_supported:
            self._pause(
                f"{label} is available only on the Ubuntu WireGuard host. "
                "Use the graphical client on macOS only for local file/config tasks."
            )
            return

        try:
            action()
        except VPNManagerError as exc:
            self._pause(str(exc))
            return

        self._pause(f"{label} completed.")

    def _open_gui(self) -> None:
        if self.open_gui_callback is None:
            self._pause("Graphical interface is not available in this launch mode.")
            return

        try:
            self.open_gui_callback()
        except VPNManagerError as exc:
            self._pause(str(exc))
            return

    def _safe_service_state(self) -> str:
        if not self.host.local_wireguard_supported:
            return "Managed from Ubuntu host"
        try:
            return "Active" if self.manager.is_service_active() else "Stopped"
        except VPNManagerError as exc:
            return f"Unavailable ({exc})"

    @staticmethod
    def _format_connected_peer(peer: ConnectedClient) -> str:
        return (
            f"{peer.name or peer.public_key:<18} "
            f"{(peer.address or 'unknown'):<16} "
            f"{_format_unix(peer.latest_handshake)} | {peer.endpoint}"
        )

    def _style(self, text: str, tone: str, *, bold: bool = False) -> str:
        if not self.use_ansi:
            return text
        prefix = ANSI[tone]
        if bold:
            prefix = ANSI["bold"] + prefix
        return f"{prefix}{text}{ANSI['reset']}"

    def _panel(self, title: str, lines: list[str], *, tone: str) -> None:
        width = min(shutil.get_terminal_size((110, 30)).columns, 110)
        content_width = max(len(title) + 2, *(len(line) for line in lines), 32)
        content_width = min(content_width, width - 4)
        horizontal = "─" * (content_width + 2)
        print(self._style(f"┌{horizontal}┐", tone, bold=True))
        print(self._style(f"│ {title:<{content_width}} │", tone, bold=True))
        print(self._style(f"├{horizontal}┤", tone, bold=True))
        for line in lines:
            clipped = line[:content_width]
            print(f"│ {clipped:<{content_width}} │")
        print(self._style(f"└{horizontal}┘", tone, bold=True))

    @staticmethod
    def _prompt_with_default(label: str, default: str) -> str:
        value = input(f"{label} [{default}]: ").strip()
        return value or default

    def _pause(self, message: str | None = None) -> None:
        if message:
            self._print_message(message, tone="amber")
        input("\nPress Enter to continue...")

    def _print_message(self, message: str, *, tone: str) -> None:
        print()
        print(self._style(message, tone, bold=tone in {"teal", "coral"}))

    @staticmethod
    def _clear() -> None:
        if sys.stdout.isatty():
            print("\033[2J\033[H", end="")


def run_console_app(
    manager: WireGuardManager,
    *,
    open_gui_callback: Callable[[], int] | None = None,
) -> int:
    """Run the modern terminal interface."""

    app = ConsoleApp(manager, open_gui_callback=open_gui_callback)
    return app.run()
