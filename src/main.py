from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone

if __package__ in {None, ""}:
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config import load_config
from src.models import ConnectedClient, VPNManagerError
from src.storage import ClientStorage
from src.utils import setup_logging
from src.wireguard_manager import WireGuardManager


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser."""

    parser = argparse.ArgumentParser(
        description="Manage a personal WireGuard VPN service on Ubuntu."
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging.")

    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("menu", help="Open the interactive terminal menu.")
    subparsers.add_parser("install-vpn", help="Install and configure WireGuard.")

    add_client_parser = subparsers.add_parser("add-client", help="Create a new client.")
    add_client_parser.add_argument("--name", required=True, help="Client name.")

    remove_client_parser = subparsers.add_parser(
        "remove-client", help="Delete an existing client."
    )
    remove_client_parser.add_argument("--name", required=True, help="Client name.")

    subparsers.add_parser("list-clients", help="List all stored clients.")
    subparsers.add_parser(
        "show-connected",
        help="Show peers with a recent WireGuard handshake.",
    )
    subparsers.add_parser("start-vpn", help="Start the WireGuard service.")
    subparsers.add_parser("stop-vpn", help="Stop the WireGuard service.")
    subparsers.add_parser("restart-vpn", help="Restart the WireGuard service.")
    return parser


def create_manager(verbose: bool) -> WireGuardManager:
    """Load config, initialize logging, and build the main manager object."""

    config = load_config()
    setup_logging(config.log_path, verbose=verbose)
    storage = ClientStorage(config.database_path, config.client_private_keys_dir)
    return WireGuardManager(config=config, storage=storage)


def print_clients(manager: WireGuardManager) -> None:
    """Print stored clients and whether they look recently connected."""

    clients = manager.list_clients_with_status()
    if not clients:
        print("No clients have been created yet.")
        return

    for client, is_connected in clients:
        status = "connected" if is_connected else "not connected"
        print(
            f"- {client.name} | {client.address} | {status} | created {client.created_at}"
        )


def print_connected_clients(connected_clients: list[ConnectedClient]) -> None:
    """Print connected peer details."""

    if not connected_clients:
        print("No connected clients were detected.")
        return

    for client in connected_clients:
        last_seen = datetime.fromtimestamp(
            client.latest_handshake,
            tz=timezone.utc,
        ).isoformat()
        print(
            f"- {client.name or client.public_key} | {client.address or 'unknown'} | "
            f"{client.endpoint} | last handshake {last_seen} | "
            f"rx={client.transfer_rx} tx={client.transfer_tx}"
        )


def print_connected_clients_safe(manager: WireGuardManager) -> None:
    """Best-effort runtime peer output for the interactive menu."""

    try:
        print_connected_clients(manager.get_connected_clients())
    except VPNManagerError as exc:
        print(f"Connected client status is unavailable: {exc}")


def run_interactive_menu(manager: WireGuardManager) -> int:
    """Run the numbered terminal menu requested for this project."""

    while True:
        print("\nWireGuard VPN Manager")
        print("1. Install VPN")
        print("2. Add client")
        print("3. Remove client")
        print("4. List clients")
        print("5. Start VPN")
        print("6. Stop VPN")
        print("7. Restart VPN")
        print("8. Exit")

        choice = input("Select an option: ").strip()

        try:
            if choice == "1":
                manager.install_wireguard()
                print("WireGuard installation and configuration completed.")
            elif choice == "2":
                client_name = input("Client name: ").strip()
                client = manager.add_client(client_name)
                print(f"Client created: {client.name}")
                print(f"Config file: {client.config_path}")
            elif choice == "3":
                client_name = input("Client name to remove: ").strip()
                manager.remove_client(client_name)
                print(f"Client removed: {client_name}")
            elif choice == "4":
                print_clients(manager)
                print("\nRecent connected peers:")
                print_connected_clients_safe(manager)
            elif choice == "5":
                manager.start_vpn()
                print("VPN started.")
            elif choice == "6":
                manager.stop_vpn()
                print("VPN stopped.")
            elif choice == "7":
                manager.restart_vpn()
                print("VPN restarted.")
            elif choice == "8":
                print("Exiting.")
                return 0
            else:
                print("Invalid option. Please choose a number from 1 to 8.")
        except VPNManagerError as exc:
            logging.getLogger("cli").error("%s", exc)
            print(f"Error: {exc}")


def execute_command(args: argparse.Namespace, manager: WireGuardManager) -> int:
    """Execute a subcommand or open the interactive menu by default."""

    command = args.command or "menu"

    if command == "menu":
        return run_interactive_menu(manager)
    if command == "install-vpn":
        manager.install_wireguard()
        print("WireGuard installation and configuration completed.")
        return 0
    if command == "add-client":
        client = manager.add_client(args.name)
        print(f"Client created: {client.name}")
        print(f"Config file: {client.config_path}")
        return 0
    if command == "remove-client":
        manager.remove_client(args.name)
        print(f"Client removed: {args.name}")
        return 0
    if command == "list-clients":
        print_clients(manager)
        return 0
    if command == "show-connected":
        print_connected_clients(manager.get_connected_clients())
        return 0
    if command == "start-vpn":
        manager.start_vpn()
        print("VPN started.")
        return 0
    if command == "stop-vpn":
        manager.stop_vpn()
        print("VPN stopped.")
        return 0
    if command == "restart-vpn":
        manager.restart_vpn()
        print("VPN restarted.")
        return 0

    raise VPNManagerError(f"Unknown command: {command}")


def main() -> int:
    """Program entrypoint."""

    parser = build_parser()
    args = parser.parse_args()

    try:
        manager = create_manager(verbose=args.verbose)
        return execute_command(args, manager)
    except VPNManagerError as exc:
        logging.getLogger("main").error("%s", exc)
        print(f"Error: {exc}")
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
