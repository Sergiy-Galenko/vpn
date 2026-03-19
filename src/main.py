from __future__ import annotations

import argparse
import json
import logging
import sys
import tkinter as tk
from datetime import datetime, timezone
from pathlib import Path

if __package__ in {None, ""}:
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config import (
    editable_settings_from_config,
    load_app_language,
    load_config,
    save_app_language,
    save_editable_settings,
)
from src.i18n import LANGUAGE_LABELS, translate
from src.models import ConnectedClient, VPNManagerError
from src.storage import ClientStorage
from src.utils import (
    detect_host_location,
    detect_host_platform,
    detect_local_ip_address,
    setup_logging,
)
from src.wireguard_manager import WireGuardManager


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _t(language: str, en: str, uk: str) -> str:
    return translate(language, en=en, uk=uk)


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
    add_client_parser.add_argument("--email", help="Optional client email.")
    add_client_parser.add_argument("--device", help="Optional device label.")
    add_client_parser.add_argument("--comment", help="Optional comment.")
    add_client_parser.add_argument("--expiry-at", help="Optional ISO expiry timestamp.")

    remove_client_parser = subparsers.add_parser(
        "remove-client", help="Delete an existing client."
    )
    remove_client_parser.add_argument("--name", required=True, help="Client name.")
    toggle_disable = subparsers.add_parser("disable-client", help="Disable an existing client.")
    toggle_disable.add_argument("--name", required=True, help="Client name.")
    toggle_enable = subparsers.add_parser("enable-client", help="Enable an existing client.")
    toggle_enable.add_argument("--name", required=True, help="Client name.")

    subparsers.add_parser("list-clients", help="List all stored clients.")
    subparsers.add_parser(
        "show-connected",
        help="Show peers with a recent WireGuard handshake.",
    )
    export_client_parser = subparsers.add_parser(
        "export-client",
        help="Show config and QR export paths for a client.",
    )
    export_client_parser.add_argument("--name", required=True, help="Client name.")
    subparsers.add_parser("start-vpn", help="Start the WireGuard service.")
    subparsers.add_parser("stop-vpn", help="Stop the WireGuard service.")
    subparsers.add_parser("restart-vpn", help="Restart the WireGuard service.")
    subparsers.add_parser("system-info", help="Show detected host operating system information.")
    subparsers.add_parser("show-config", help="Show current editable VPN settings.")
    subparsers.add_parser("validate-vpn", help="Run local or remote validation checks.")
    subparsers.add_parser("list-backups", help="List created backup archives.")
    backup_parser = subparsers.add_parser("backup-vpn", help="Create a backup archive.")
    backup_parser.add_argument("--note", help="Optional backup note.")
    restore_parser = subparsers.add_parser("restore-backup", help="Restore from a backup archive.")
    restore_parser.add_argument("--archive", required=True, help="Path to a .tar.gz backup archive.")
    restore_parser.add_argument(
        "--apply-remote",
        action="store_true",
        help="If remote data exists in the backup, apply the remote server config after restore.",
    )
    audit_parser = subparsers.add_parser("audit-log", help="Show recent audit log entries.")
    audit_parser.add_argument("--limit", type=int, default=20, help="Number of entries to print.")
    import_parser = subparsers.add_parser("import-config", help="Import peers from an existing WireGuard config.")
    import_parser.add_argument("--path", help="Optional path to a local WireGuard config file.")
    subparsers.add_parser("console", help="Open the modern console interface.")
    subparsers.add_parser("test-remote", help="Test the saved remote SSH profile.")
    subparsers.add_parser("show-remote", help="Show the saved remote SSH profile.")
    subparsers.add_parser("clear-remote", help="Delete the saved remote SSH profile.")
    subparsers.add_parser("wizard", help="Run the first-run setup wizard in the terminal.")
    set_language_parser = subparsers.add_parser(
        "set-language",
        help="Persist the UI language for GUI and console.",
    )
    set_language_parser.add_argument(
        "--language",
        required=True,
        choices=["uk", "en"],
        help="Application language.",
    )

    configure_parser = subparsers.add_parser(
        "configure-vpn",
        help="Update editable VPN settings and save them into .env.",
    )
    configure_parser.add_argument("--endpoint", help="Public endpoint or DNS name.")
    configure_parser.add_argument("--interface", dest="interface_name", help="WireGuard interface name.")
    configure_parser.add_argument("--server-address", help="Server address CIDR, for example 10.8.0.1/24.")
    configure_parser.add_argument("--port", dest="server_port", type=int, help="WireGuard listen port.")
    configure_parser.add_argument("--public-interface", help="Outgoing network interface, for example eth0.")
    configure_parser.add_argument("--dns", help="Client DNS servers, for example 1.1.1.1,8.8.8.8.")
    configure_parser.add_argument("--allowed-ips", dest="client_allowed_ips", help="Client allowed IPs.")
    configure_parser.add_argument(
        "--connected-window",
        dest="connected_window_seconds",
        type=int,
        help="Seconds used to classify recent connected peers.",
    )
    remote_parser = subparsers.add_parser(
        "configure-remote",
        help="Save remote Ubuntu SSH profile settings.",
    )
    remote_parser.add_argument("--host", required=True, help="Remote Ubuntu host or IP.")
    remote_parser.add_argument("--username", required=True, help="SSH username.")
    remote_parser.add_argument("--port", type=int, default=22, help="SSH port.")
    remote_parser.add_argument(
        "--auth-method",
        choices=["ssh_key", "password"],
        default="ssh_key",
        help="SSH authentication method.",
    )
    remote_parser.add_argument("--private-key-path", help="Private key path for SSH key auth.")
    remote_parser.add_argument("--password", help="Password for SSH password auth.")
    remote_parser.add_argument("--sudo-password", help="Optional sudo password for remote sudo.")
    remote_parser.add_argument("--fingerprint", help="Expected remote host fingerprint hex string.")
    remote_parser.add_argument("--timeout", type=int, default=10, help="SSH connect timeout in seconds.")
    remote_parser.add_argument("--no-sudo", action="store_true", help="Disable sudo for remote operations.")
    remote_parser.add_argument("--name", default="default", help="Logical profile name.")
    subparsers.add_parser("gui", help="Open the desktop GUI application.")
    subparsers.add_parser("app", help="Alias for the desktop GUI application.")
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
        status = f"{client.status.value}, connected" if is_connected else client.status.value
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


def print_host_platform_info() -> None:
    """Print normalized host OS information for the current machine."""

    host = detect_host_platform()
    location = detect_host_location()
    local_ip_address = detect_local_ip_address()
    print(f"Host OS: {host.display_name}")
    print(f"System: {host.system}")
    print(f"Release: {host.release}")
    print(f"Version: {host.version}")
    print(f"Architecture: {host.machine}")
    print(f"Location: {location.summary}")
    print(f"Local IP: {local_ip_address or 'Unavailable'}")
    print(f"Timezone: {location.timezone or 'Unavailable'}")
    print(f"Public IP: {location.public_ip or 'Unavailable'}")
    print(f"Latitude: {location.latitude_summary}")
    print(f"Longitude: {location.longitude_summary}")
    print(f"Coordinates: {location.coordinates_summary}")
    print(
        "Local WireGuard control: "
        + ("supported" if host.local_wireguard_supported else "not supported on this host")
    )


def print_vpn_config(manager: WireGuardManager) -> None:
    """Print editable VPN settings."""

    settings = editable_settings_from_config(manager.config)
    print(f"WG_ENDPOINT={settings.endpoint}")
    print(f"WG_INTERFACE_NAME={settings.interface_name}")
    print(f"WG_SERVER_ADDRESS={settings.server_address}")
    print(f"WG_SERVER_PORT={settings.server_port}")
    print(f"WG_PUBLIC_INTERFACE={settings.public_interface}")
    print(f"WG_DNS={settings.dns}")
    print(f"WG_CLIENT_ALLOWED_IPS={settings.client_allowed_ips}")
    print(f"WG_CONNECTED_WINDOW_SECONDS={settings.connected_window_seconds}")


def print_remote_profile(manager: WireGuardManager) -> None:
    profile = manager.remote_profile
    if profile is None:
        print("No remote SSH profile is configured.")
        return

    print(f"Profile: {profile.name}")
    print(f"Host: {profile.host}")
    print(f"Port: {profile.port}")
    print(f"Username: {profile.username}")
    print(f"Auth method: {profile.auth_method.value}")
    print(f"Private key path: {profile.private_key_path or 'None'}")
    print(f"Use sudo: {'yes' if profile.use_sudo else 'no'}")
    print(f"Enabled: {'yes' if profile.enabled else 'no'}")
    print(f"Fingerprint: {profile.known_host_fingerprint or 'not set'}")


def print_validation_issues(manager: WireGuardManager) -> None:
    issues = manager.validate_environment()
    if not issues:
        print("Validation passed with no issues.")
        return

    for issue in issues:
        print(f"- [{issue.severity.value}] {issue.code}: {issue.message}")


def print_backups(manager: WireGuardManager, limit: int = 50) -> None:
    backups = manager.list_backups()[:limit]
    if not backups:
        print("No backups have been created yet.")
        return

    for backup in backups:
        print(
            f"- {backup.archive_path} | created {backup.created_at} | scope={backup.scope}"
            + (f" | note={backup.note}" if backup.note else "")
        )


def print_audit_logs(manager: WireGuardManager, limit: int) -> None:
    entries = manager.list_audit_logs(limit=limit)
    if not entries:
        print("Audit log is empty.")
        return

    for entry in entries:
        print(
            f"- {entry.timestamp} | {entry.result.upper()} | {entry.action} | "
            f"{entry.target} | {entry.details}"
        )
        if entry.error_details:
            print(f"  error: {entry.error_details}")


def print_client_export_info(manager: WireGuardManager, client_name: str) -> None:
    client = manager.storage.get_client(client_name)
    if client is None:
        raise VPNManagerError(f"Client '{client_name}' was not found.")

    print(f"Client: {client.name}")
    print(f"Config path: {client.config_path or 'Unavailable'}")
    print(f"QR path: {client.qr_code_path or 'Unavailable'}")
    if client.config_path:
        print()
        print(manager.get_client_config_text(client_name))


def configure_vpn(manager: WireGuardManager, args: argparse.Namespace) -> None:
    """Update editable VPN settings from CLI arguments."""

    current = editable_settings_from_config(manager.config)
    updates_applied = False

    for field_name in (
        "endpoint",
        "interface_name",
        "server_address",
        "server_port",
        "public_interface",
        "dns",
        "client_allowed_ips",
        "connected_window_seconds",
    ):
        value = getattr(args, field_name, None)
        if value is None:
            continue
        setattr(current, field_name, value)
        updates_applied = True

    if not updates_applied:
        raise VPNManagerError("Provide at least one configure-vpn option to update.")

    new_config = save_editable_settings(manager.config.project_root, current)
    manager.update_config(new_config)
    print("VPN settings saved.")
    print_vpn_config(manager)


def configure_remote(manager: WireGuardManager, args: argparse.Namespace) -> None:
    auth_method = args.auth_method
    profile = manager.save_remote_profile(
        host=args.host,
        username=args.username,
        port=args.port,
        auth_method=AuthMethod(auth_method),
        private_key_path=args.private_key_path,
        password=args.password,
        sudo_password=args.sudo_password,
        known_host_fingerprint=args.fingerprint,
        connect_timeout_seconds=args.timeout,
        use_sudo=not args.no_sudo,
        profile_name=args.name,
    )
    print(f"Remote profile saved for {profile.username}@{profile.host}:{profile.port}")


def run_first_run_wizard(manager: WireGuardManager) -> None:
    print("First-run setup wizard")
    print("Press Enter to keep the current value.")
    current = editable_settings_from_config(manager.config)
    updated = current
    updated.endpoint = input(f"Endpoint [{current.endpoint}]: ").strip() or current.endpoint
    updated.interface_name = input(f"Interface [{current.interface_name}]: ").strip() or current.interface_name
    updated.server_address = input(f"Server address [{current.server_address}]: ").strip() or current.server_address
    updated.server_port = int(input(f"Server port [{current.server_port}]: ").strip() or str(current.server_port))
    updated.public_interface = input(f"Public interface [{current.public_interface}]: ").strip() or current.public_interface
    updated.dns = input(f"DNS [{current.dns}]: ").strip() or current.dns
    updated.client_allowed_ips = (
        input(f"Allowed IPs [{current.client_allowed_ips}]: ").strip() or current.client_allowed_ips
    )
    updated.connected_window_seconds = int(
        input(
            f"Connected window seconds [{current.connected_window_seconds}]: "
        ).strip()
        or str(current.connected_window_seconds)
    )
    new_config = save_editable_settings(manager.config.project_root, updated)
    manager.update_config(new_config)

    use_remote = input("Configure remote Ubuntu over SSH? [y/N]: ").strip().lower()
    if use_remote in {"y", "yes"}:
        configure_remote(
            manager,
            argparse.Namespace(
                host=input("Remote host: ").strip(),
                username=input("Remote username: ").strip(),
                port=int(input("SSH port [22]: ").strip() or "22"),
                auth_method=input("Auth method [ssh_key/password] [ssh_key]: ").strip() or "ssh_key",
                private_key_path=input("Private key path [~/.ssh/id_ed25519]: ").strip() or None,
                password=input("SSH password (optional): ").strip() or None,
                sudo_password=input("Sudo password (optional): ").strip() or None,
                fingerprint=input("Host fingerprint (optional): ").strip() or None,
                timeout=int(input("SSH timeout seconds [10]: ").strip() or "10"),
                no_sudo=False,
                name="default",
            ),
        )


def run_interactive_menu(manager: WireGuardManager) -> int:
    """Run the numbered terminal menu requested for this project."""

    host = detect_host_platform()
    location = detect_host_location()
    local_ip_address = detect_local_ip_address()
    while True:
        print("\nWireGuard VPN Manager")
        print(f"Host: {host.summary}")
        print(f"Location: {location.summary}")
        print(f"Local IP: {local_ip_address or 'Unavailable'}")
        print(f"Latitude: {location.latitude_summary}")
        print(f"Longitude: {location.longitude_summary}")
        print(f"Control target: {manager.control_target_summary()}")
        if not manager.can_control_vpn():
            print("Note: local WireGuard service control is disabled on this host.")
        print("1. Install VPN")
        print("2. Add client")
        print("3. Remove client")
        print("4. List clients")
        print("5. Start VPN")
        print("6. Stop VPN")
        print("7. Restart VPN")
        print("8. Disable client")
        print("9. Enable client")
        print("10. Validate")
        print("11. Backups")
        print("12. Audit log")
        print("13. Import config")
        print("14. Exit")

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
                client_name = input("Client name to disable: ").strip()
                manager.disable_client(client_name)
                print(f"Client disabled: {client_name}")
            elif choice == "9":
                client_name = input("Client name to enable: ").strip()
                manager.enable_client(client_name)
                print(f"Client enabled: {client_name}")
            elif choice == "10":
                print_validation_issues(manager)
            elif choice == "11":
                print_backups(manager)
            elif choice == "12":
                print_audit_logs(manager, 20)
            elif choice == "13":
                path_value = input("Config path (leave empty for current system config): ").strip()
                imported_count = manager.import_existing_config(Path(path_value) if path_value else None)
                print(f"Imported peers: {imported_count}")
            elif choice == "14":
                print("Exiting.")
                return 0
            else:
                print("Invalid option.")
        except VPNManagerError as exc:
            logging.getLogger("cli").error("%s", exc)
            print(f"Error: {exc}")


def run_gui_command(manager: WireGuardManager, language: str | None = None) -> int:
    """Start the Tk desktop GUI."""

    from src.gui_app import run_gui_app

    try:
        run_gui_app(manager, language=language or load_app_language(manager.config.project_root))
    except tk.TclError as exc:
        raise VPNManagerError(
            "The desktop UI could not be started. "
            "If you are on a server without a graphical session, use the console interface instead:\n"
            "python3 src/main.py console"
        ) from exc
    return 0


def choose_launch_mode(language: str | None = None) -> str:
    """Prompt the user to choose GUI or console when no command was provided."""

    host = detect_host_platform()
    current_language = language or load_app_language(PROJECT_ROOT)
    print()
    print(_t(current_language, "WireGuard Manager", "Менеджер WireGuard"))
    print(f"{_t(current_language, 'Host', 'Хост')}: {host.summary}")
    print(_t(current_language, "Choose interface:", "Оберіть інтерфейс:"))
    print(f"1. {_t(current_language, 'Graphical interface', 'Графічний інтерфейс')}")
    print(f"2. {_t(current_language, 'Console interface', 'Консольний інтерфейс')}")
    print(
        f"3. {_t(current_language, 'Change language', 'Змінити мову')}"
        f" ({' / '.join(f'{code.upper()}={label}' for code, label in LANGUAGE_LABELS.items())})"
    )

    while True:
        choice = input(_t(current_language, "Enter 1, 2, or 3: ", "Введіть 1, 2 або 3: ")).strip()
        if choice == "1":
            return "gui"
        if choice == "2":
            return "console"
        if choice == "3":
            selected = input(_t(current_language, "Choose language [uk/en]: ", "Оберіть мову [uk/en]: ")).strip().lower()
            current_language = save_app_language(PROJECT_ROOT, selected)
            print(_t(current_language, "Language saved.", "Мову збережено."))
            print()
            print(_t(current_language, "Choose interface:", "Оберіть інтерфейс:"))
            print(f"1. {_t(current_language, 'Graphical interface', 'Графічний інтерфейс')}")
            print(f"2. {_t(current_language, 'Console interface', 'Консольний інтерфейс')}")
            print(
                f"3. {_t(current_language, 'Change language', 'Змінити мову')}"
                f" ({' / '.join(f'{code.upper()}={label}' for code, label in LANGUAGE_LABELS.items())})"
            )
            continue
        print(_t(current_language, "Invalid choice. Enter 1, 2, or 3.", "Неправильний вибір. Введіть 1, 2 або 3."))


def should_prompt_for_launch_mode() -> bool:
    """Return True when the process can ask the user to choose an interface."""

    return sys.stdin.isatty() and sys.stdout.isatty()


def execute_command(args: argparse.Namespace, manager: WireGuardManager) -> int:
    """Execute a subcommand or open the interactive menu by default."""

    command = args.command or "gui"
    language = load_app_language(manager.config.project_root)

    if command in {"menu", "console"}:
        from src.console_app import run_console_app

        return run_console_app(
            manager,
            open_gui_callback=lambda: run_gui_command(
                manager,
                language=load_app_language(manager.config.project_root),
            ),
            language=language,
        )
    if command == "install-vpn":
        manager.install_wireguard()
        print("WireGuard installation and configuration completed.")
        return 0
    if command == "add-client":
        client = manager.add_client(
            args.name,
            email=getattr(args, "email", None),
            device=getattr(args, "device", None),
            comment=getattr(args, "comment", None),
            expiry_at=getattr(args, "expiry_at", None),
        )
        print(f"Client created: {client.name}")
        print(f"Config file: {client.config_path}")
        print(f"QR file: {client.qr_code_path}")
        return 0
    if command == "remove-client":
        manager.remove_client(args.name)
        print(f"Client removed: {args.name}")
        return 0
    if command == "disable-client":
        manager.disable_client(args.name)
        print(f"Client disabled: {args.name}")
        return 0
    if command == "enable-client":
        manager.enable_client(args.name)
        print(f"Client enabled: {args.name}")
        return 0
    if command == "list-clients":
        print_clients(manager)
        return 0
    if command == "show-connected":
        print_connected_clients(manager.get_connected_clients())
        return 0
    if command == "export-client":
        print_client_export_info(manager, args.name)
        return 0
    if command == "system-info":
        print_host_platform_info()
        return 0
    if command == "show-config":
        print_vpn_config(manager)
        return 0
    if command == "show-remote":
        print_remote_profile(manager)
        return 0
    if command == "clear-remote":
        manager.clear_remote_profile()
        print("Remote profile cleared.")
        return 0
    if command == "test-remote":
        status = manager.test_remote_connection()
        print(json.dumps(status, indent=2, sort_keys=True))
        return 0
    if command == "configure-vpn":
        configure_vpn(manager, args)
        return 0
    if command == "configure-remote":
        configure_remote(manager, args)
        return 0
    if command == "validate-vpn":
        print_validation_issues(manager)
        return 0
    if command == "backup-vpn":
        backup = manager.create_backup(note=args.note)
        print(f"Backup created: {backup.archive_path}")
        return 0
    if command == "list-backups":
        print_backups(manager)
        return 0
    if command == "restore-backup":
        manager.restore_backup(Path(args.archive), apply_remote=args.apply_remote)
        print("Backup restored.")
        return 0
    if command == "audit-log":
        print_audit_logs(manager, args.limit)
        return 0
    if command == "import-config":
        imported_count = manager.import_existing_config(Path(args.path) if args.path else None)
        print(f"Imported peers: {imported_count}")
        return 0
    if command == "wizard":
        run_first_run_wizard(manager)
        print("Wizard completed.")
        return 0
    if command == "set-language":
        normalized = save_app_language(manager.config.project_root, args.language)
        print(f"Language saved: {normalized}")
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
    if command in {"gui", "app"}:
        return run_gui_command(manager, language=language)

    raise VPNManagerError(f"Unknown command: {command}")


def main() -> int:
    """Program entrypoint."""

    parser = build_parser()
    args = parser.parse_args()

    try:
        host = detect_host_platform()
        app_language = load_app_language(PROJECT_ROOT)
        if args.command is None and should_prompt_for_launch_mode():
            args.command = choose_launch_mode(app_language)
        manager = create_manager(verbose=args.verbose)
        logging.getLogger("main").info("Detected host platform: %s", host.summary)
        return execute_command(args, manager)
    except VPNManagerError as exc:
        logger = logging.getLogger("main")
        message = str(exc)
        if "available only on the Linux host where WireGuard is running" in message:
            logger.warning("%s", message)
        else:
            logger.error("%s", message)
        print(f"Error: {exc}")
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
