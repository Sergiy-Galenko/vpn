from __future__ import annotations

import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from src.config import (
    EditableVPNSettings,
    editable_settings_from_config,
    save_app_language,
    save_editable_settings,
)
from src.i18n import LANGUAGE_LABELS, normalize_language, translate
from src.models import AuthMethod, ConnectedClient, VPNManagerError
from src.utils import (
    detect_host_hardware,
    detect_host_location,
    detect_host_platform,
    detect_local_ip_address,
    format_bytes_binary,
)
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
        language: str = "uk",
    ) -> None:
        self.manager = manager
        self.open_gui_callback = open_gui_callback
        self.language = normalize_language(language)
        self.host = detect_host_platform()
        self.hardware = detect_host_hardware()
        self.location = detect_host_location()
        self.local_ip_address = detect_local_ip_address()
        self.use_ansi = _supports_ansi()

    def _t(self, en: str, uk: str) -> str:
        return translate(self.language, en=en, uk=uk)

    def run(self) -> int:
        while True:
            self._clear()
            self._render_home()
            choice = input(
                self._t("\nSelect action: ", "\nОберіть дію: ")
            ).strip().lower()

            if choice in {"0", "q", "quit", "exit"}:
                self._print_message(self._t("Console session closed.", "Консольну сесію завершено."), tone="teal")
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
                self._disable_client()
            elif choice == "7":
                self._enable_client()
            elif choice == "8":
                self._remove_client()
            elif choice == "9":
                self._list_clients()
            elif choice == "10":
                self._show_client_export()
            elif choice == "11":
                self._show_connected_clients()
            elif choice == "12":
                self._validate_environment()
            elif choice == "13":
                self._create_backup()
            elif choice == "14":
                self._restore_backup()
            elif choice == "15":
                self._list_backups()
            elif choice == "16":
                self._show_audit_log()
            elif choice == "17":
                self._import_existing_config()
            elif choice == "18":
                self._configure_remote_profile()
            elif choice == "19":
                self._test_remote_connection()
            elif choice == "20":
                self._clear_remote_profile()
            elif choice == "21":
                self._run_control_action("Install VPN", self.manager.install_wireguard)
            elif choice == "22":
                self._run_control_action("Start VPN", self.manager.start_vpn)
            elif choice == "23":
                self._run_control_action("Stop VPN", self.manager.stop_vpn)
            elif choice == "24":
                self._run_control_action("Restart VPN", self.manager.restart_vpn)
            elif choice == "25":
                self._open_gui()
            elif choice == "26":
                self._run_setup_wizard()
            elif choice == "27":
                self._change_language()
            else:
                self._pause(self._t("Unknown option.", "Невідома опція."))

    def _render_home(self) -> None:
        width = min(shutil.get_terminal_size((110, 30)).columns, 110)
        title = self._t("WGDesk Console", "WGDesk Консоль")
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
            f"{self._t('Host summary', 'Опис хоста'):<18}: {self.host.summary}",
            f"{self._t('Control target', 'Ціль керування'):<18}: {self.manager.control_target_summary()}",
            f"{self._t('Location', 'Локація'):<18}: {self.location.summary}",
            f"{self._t('Local IP', 'Локальний IP'):<18}: {self.local_ip_address or self._t('Unavailable', 'Недоступно')}",
            f"{self._t('Public IP', 'Публічний IP'):<18}: {self.location.public_ip or self._t('Unavailable', 'Недоступно')}",
            f"{self._t('Latitude', 'Широта'):<18}: {self.location.latitude_summary}",
            f"{self._t('Longitude', 'Довгота'):<18}: {self.location.longitude_summary}",
            f"{self._t('Processor', 'Процесор'):<18}: {self.hardware.cpu_name}",
            f"RAM               : {format_bytes_binary(self.hardware.memory_total_bytes)}",
            f"{self._t('Storage', 'Сховище'):<18}: {format_bytes_binary(self.hardware.storage_total_bytes)}",
            f"{self._t('CPU cores', 'Ядер CPU'):<18}: {self._cpu_cores_summary()}",
            f"{self._t('GPU cores', 'Ядер GPU'):<18}: {self._gpu_cores_summary()}",
            f"{self._t('Endpoint', 'Endpoint'):<18}: {settings.endpoint}",
            f"{self._t('Interface', 'Інтерфейс'):<18}: {settings.interface_name}",
            f"{self._t('Server subnet', 'Підмережа сервера'):<18}: {settings.server_address}",
            f"{self._t('Service state', 'Стан сервісу'):<18}: {service_state}",
            f"{self._t('Total clients', 'Всього клієнтів'):<18}: {len(clients)}",
            (
                f"{self._t('Control available', 'Керування доступне'):<18}: {self._t('yes', 'так')}"
                if self.manager.can_control_vpn()
                else f"{self._t('Control available', 'Керування доступне'):<18}: {self._t('no', 'ні')}"
            ),
            f"{self._t('Language', 'Мова'):<18}: {LANGUAGE_LABELS[self.language]}",
        ]
        self._panel(self._t("Status", "Статус"), summary_lines, tone="teal")

        menu_lines = [
            f"1  {self._t('Dashboard', 'Дашборд')}",
            f"2  {self._t('System info', 'Системна інформація')}",
            f"3  {self._t('Show VPN settings', 'Показати налаштування VPN')}",
            f"4  {self._t('Edit VPN settings', 'Редагувати налаштування VPN')}",
            f"5  {self._t('Add client', 'Додати клієнта')}",
            f"6  {self._t('Disable client', 'Вимкнути клієнта')}",
            f"7  {self._t('Enable client', 'Увімкнути клієнта')}",
            f"8  {self._t('Remove client', 'Видалити клієнта')}",
            f"9  {self._t('List clients', 'Список клієнтів')}",
            f"10 {self._t('Show client export', 'Показати експорт клієнта')}",
            f"11 {self._t('Show connected peers', 'Показати підключені peer-и')}",
            f"12 {self._t('Validate environment', 'Перевірити середовище')}",
            f"13 {self._t('Create backup', 'Створити backup')}",
            f"14 {self._t('Restore backup', 'Відновити backup')}",
            f"15 {self._t('List backups', 'Список backup-ів')}",
            f"16 {self._t('Show audit log', 'Показати аудит-лог')}",
            f"17 {self._t('Import existing config', 'Імпортувати існуючий config')}",
            f"18 {self._t('Configure remote SSH', 'Налаштувати remote SSH')}",
            f"19 {self._t('Test remote connection', 'Перевірити remote-зʼєднання')}",
            f"20 {self._t('Clear remote profile', 'Очистити remote-профіль')}",
            f"21 {self._t('Install VPN', 'Встановити VPN')}",
            f"22 {self._t('Start VPN', 'Запустити VPN')}",
            f"23 {self._t('Stop VPN', 'Зупинити VPN')}",
            f"24 {self._t('Restart VPN', 'Перезапустити VPN')}",
            f"25 {self._t('Open graphical interface', 'Відкрити графічний інтерфейс')}",
            f"26 {self._t('Run setup wizard', 'Запустити майстер налаштування')}",
            f"27 {self._t('Change language', 'Змінити мову')}",
            f"0  {self._t('Exit', 'Вихід')}",
        ]
        self._panel(self._t("Actions", "Дії"), menu_lines, tone="amber")

    def _show_dashboard(self) -> None:
        clients = self.manager.list_clients_with_status()
        connected_total = sum(1 for _, is_connected in clients if is_connected)
        self._clear()
        self._panel(
            self._t("Dashboard", "Дашборд"),
            [
                f"{self._t('Host platform', 'Платформа хоста'):<18}: {self.host.summary}",
                f"{self._t('Control target', 'Ціль керування'):<18}: {self.manager.control_target_summary()}",
                f"{self._t('Location', 'Локація'):<18}: {self.location.summary}",
                f"{self._t('Local IP', 'Локальний IP'):<18}: {self.local_ip_address or self._t('Unavailable', 'Недоступно')}",
                f"{self._t('Public IP', 'Публічний IP'):<18}: {self.location.public_ip or self._t('Unavailable', 'Недоступно')}",
                f"{self._t('Latitude', 'Широта'):<18}: {self.location.latitude_summary}",
                f"{self._t('Longitude', 'Довгота'):<18}: {self.location.longitude_summary}",
                f"{self._t('Processor', 'Процесор'):<18}: {self.hardware.cpu_name}",
                f"RAM               : {format_bytes_binary(self.hardware.memory_total_bytes)}",
                f"{self._t('Storage', 'Сховище'):<18}: {format_bytes_binary(self.hardware.storage_total_bytes)}",
                f"{self._t('CPU cores', 'Ядер CPU'):<18}: {self._cpu_cores_summary()}",
                f"{self._t('GPU cores', 'Ядер GPU'):<18}: {self._gpu_cores_summary()}",
                f"{self._t('Service state', 'Стан сервісу'):<18}: {self._safe_service_state()}",
                f"{self._t('Interface', 'Інтерфейс'):<18}: {self.manager.config.interface_name}",
                f"{self._t('Endpoint', 'Endpoint'):<18}: {self.manager.config.endpoint}",
                f"{self._t('Server address', 'Адреса сервера'):<18}: {self.manager.config.server_interface}",
                f"{self._t('Public interface', 'Публічний інтерфейс'):<18}: {self.manager.config.public_interface}",
                f"{self._t('Client count', 'Кількість клієнтів'):<18}: {len(clients)}",
                f"{self._t('Connected peers', 'Підключені peer-и'):<18}: {connected_total}",
                f"DNS               : {self.manager.config.dns}",
                f"{self._t('Allowed IPs', 'Allowed IPs'):<18}: {self.manager.config.client_allowed_ips}",
            ],
            tone="teal",
        )
        self._pause()

    def _show_system_info(self) -> None:
        self._clear()
        self._panel(
            self._t("System Info", "Системна інформація"),
            [
                f"{self._t('Host OS', 'ОС хоста'):<18}: {self.host.display_name}",
                f"System            : {self.host.system}",
                f"{self._t('Release', 'Реліз'):<18}: {self.host.release}",
                f"{self._t('Version', 'Версія'):<18}: {self.host.version}",
                f"{self._t('Architecture', 'Архітектура'):<18}: {self.host.machine}",
                f"{self._t('Control target', 'Ціль керування'):<18}: {self.manager.control_target_summary()}",
                f"{self._t('Location', 'Локація'):<18}: {self.location.summary}",
                f"{self._t('Local IP', 'Локальний IP'):<18}: {self.local_ip_address or self._t('Unavailable', 'Недоступно')}",
                f"{self._t('Timezone', 'Часовий пояс'):<18}: {self.location.timezone or self._t('Unavailable', 'Недоступно')}",
                f"{self._t('Public IP', 'Публічний IP'):<18}: {self.location.public_ip or self._t('Unavailable', 'Недоступно')}",
                f"{self._t('Latitude', 'Широта'):<18}: {self.location.latitude_summary}",
                f"{self._t('Longitude', 'Довгота'):<18}: {self.location.longitude_summary}",
                f"{self._t('Coordinates', 'Координати'):<18}: {self.location.coordinates_summary}",
                f"{self._t('Processor', 'Процесор'):<18}: {self.hardware.cpu_name}",
                f"RAM               : {format_bytes_binary(self.hardware.memory_total_bytes)}",
                f"{self._t('Storage', 'Сховище'):<18}: {format_bytes_binary(self.hardware.storage_total_bytes)}",
                f"{self._t('CPU cores', 'Ядер CPU'):<18}: {self._cpu_cores_summary()}",
                f"{self._t('GPU cores', 'Ядер GPU'):<18}: {self._gpu_cores_summary()}",
                (
                    f"{self._t('Control available', 'Керування доступне'):<18}: {self._t('yes', 'так')}"
                    if self.manager.can_control_vpn()
                    else f"{self._t('Control available', 'Керування доступне'):<18}: {self._t('no', 'ні')}"
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
                server_port=int(self._prompt_with_default("Server port", str(current.server_port))),
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

        email = input("Email (optional): ").strip() or None
        device = input("Device (optional): ").strip() or None
        comment = input("Comment (optional): ").strip() or None
        expiry_at = input("Expiry ISO timestamp (optional): ").strip() or None

        try:
            client = self.manager.add_client(
                client_name,
                email=email,
                device=device,
                comment=comment,
                expiry_at=expiry_at,
            )
        except VPNManagerError as exc:
            self._pause(str(exc))
            return

        self._pause(
            f"Client created: {client.name}\n"
            f"Config: {client.config_path}\n"
            f"QR: {client.qr_code_path or 'Unavailable'}"
        )

    def _disable_client(self) -> None:
        client_name = input("Client name to disable: ").strip()
        if not client_name:
            self._pause("Client name is required.")
            return

        try:
            self.manager.disable_client(client_name)
        except VPNManagerError as exc:
            self._pause(str(exc))
            return

        self._pause(f"Client disabled: {client_name}")

    def _enable_client(self) -> None:
        client_name = input("Client name to enable: ").strip()
        if not client_name:
            self._pause("Client name is required.")
            return

        try:
            self.manager.enable_client(client_name)
        except VPNManagerError as exc:
            self._pause(str(exc))
            return

        self._pause(f"Client enabled: {client_name}")

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
                f"{client.name:<16} {client.address:<16} "
                f"{client.status.value:<10} {'connected' if is_connected else 'idle':<10} "
                f"{_format_iso(client.created_at)}"
            )
            for client, is_connected in clients
        ]
        self._panel("Clients", lines, tone="teal")
        self._pause()

    def _show_client_export(self) -> None:
        client_name = input("Client name: ").strip()
        if not client_name:
            self._pause("Client name is required.")
            return

        try:
            client = self.manager.storage.get_client(client_name)
            if client is None:
                raise VPNManagerError(f"Client '{client_name}' was not found.")
            config_text = self.manager.get_client_config_text(client_name)
        except VPNManagerError as exc:
            self._pause(str(exc))
            return

        lines = [
            f"Client            : {client.name}",
            f"Config path       : {client.config_path or 'Unavailable'}",
            f"QR path           : {client.qr_code_path or 'Unavailable'}",
            "",
            *config_text.splitlines(),
        ]
        self._clear()
        self._panel("Client Export", lines, tone="mint")
        self._pause()

    def _show_connected_clients(self) -> None:
        self._clear()
        if not self.manager.can_control_vpn():
            self._panel(
                "Connected Peers",
                ["Connected peer lookup requires a Linux host or configured remote SSH mode."],
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

    def _validate_environment(self) -> None:
        issues = self.manager.validate_environment()
        self._clear()
        if not issues:
            self._panel("Validation", ["Validation passed with no issues."], tone="mint")
            self._pause()
            return
        lines = [f"[{issue.severity.value}] {issue.code}: {issue.message}" for issue in issues]
        self._panel("Validation", lines, tone="amber")
        self._pause()

    def _create_backup(self) -> None:
        note = input("Backup note (optional): ").strip() or None
        try:
            backup = self.manager.create_backup(note=note)
        except VPNManagerError as exc:
            self._pause(str(exc))
            return
        self._pause(f"Backup created:\n{backup.archive_path}")

    def _restore_backup(self) -> None:
        archive_path = input("Backup archive path: ").strip()
        if not archive_path:
            self._pause("Backup archive path is required.")
            return

        apply_remote = input("Apply remote config from backup if present? [y/N]: ").strip().lower()
        try:
            self.manager.restore_backup(
                Path(archive_path),
                apply_remote=apply_remote in {"y", "yes"},
            )
        except VPNManagerError as exc:
            self._pause(str(exc))
            return
        self._pause("Backup restored.")

    def _list_backups(self) -> None:
        backups = self.manager.list_backups()
        self._clear()
        if not backups:
            self._panel("Backups", ["No backups have been created yet."], tone="amber")
            self._pause()
            return
        lines = [
            f"{Path(backup.archive_path).name:<34} {backup.scope:<8} {backup.created_at}"
            for backup in backups
        ]
        self._panel("Backups", lines, tone="teal")
        self._pause()

    def _show_audit_log(self) -> None:
        entries = self.manager.list_audit_logs(40)
        self._clear()
        if not entries:
            self._panel("Audit Log", ["Audit log is empty."], tone="amber")
            self._pause()
            return
        lines: list[str] = []
        for entry in entries:
            lines.append(
                f"{entry.timestamp} | {entry.result.upper():<7} | {entry.action:<20} | {entry.target}"
            )
            if entry.error_details:
                lines.append(f"  error: {entry.error_details}")
        self._panel("Audit Log", lines, tone="mint")
        self._pause()

    def _import_existing_config(self) -> None:
        path_value = input("Config path (leave empty for current system config): ").strip()
        try:
            count = self.manager.import_existing_config(Path(path_value) if path_value else None)
        except VPNManagerError as exc:
            self._pause(str(exc))
            return
        self._pause(f"Imported peers: {count}")

    def _configure_remote_profile(self) -> None:
        self._clear()
        self._panel(
            "Remote SSH Profile",
            [
                "Configure Ubuntu remote management over SSH.",
                "Host key verification uses system known_hosts and optional fingerprint pinning.",
            ],
            tone="coral",
        )
        host = input("Remote host: ").strip()
        username = input("SSH username: ").strip()
        port = int(input("SSH port [22]: ").strip() or "22")
        auth_method = (input("Auth method [ssh_key/password] [ssh_key]: ").strip() or "ssh_key").lower()
        private_key_path = None
        password = None
        if auth_method == "ssh_key":
            private_key_path = input("Private key path [~/.ssh/id_ed25519]: ").strip() or "~/.ssh/id_ed25519"
        else:
            password = input("SSH password: ").strip()
        sudo_password = input("Sudo password (optional): ").strip() or None
        fingerprint = input("Known host fingerprint (optional hex): ").strip() or None
        use_sudo = input("Use sudo on remote host? [Y/n]: ").strip().lower() not in {"n", "no"}

        try:
            self.manager.save_remote_profile(
                host=host,
                username=username,
                port=port,
                auth_method=AuthMethod(auth_method),
                private_key_path=private_key_path,
                password=password,
                sudo_password=sudo_password,
                known_host_fingerprint=fingerprint,
                use_sudo=use_sudo,
            )
        except (ValueError, VPNManagerError) as exc:
            self._pause(str(exc))
            return

        self._pause(f"Remote profile saved for {username}@{host}:{port}")

    def _test_remote_connection(self) -> None:
        try:
            payload = self.manager.test_remote_connection()
        except VPNManagerError as exc:
            self._pause(str(exc))
            return
        self._clear()
        lines = [f"{key:<18}: {value}" for key, value in sorted(payload.items())]
        self._panel("Remote Connection", lines, tone="mint")
        self._pause()

    def _clear_remote_profile(self) -> None:
        self.manager.clear_remote_profile()
        self._pause("Remote profile cleared.")

    def _run_control_action(self, label: str, action: Callable[[], None]) -> None:
        if not self.manager.can_control_vpn():
            self._pause(f"{label} requires a Linux host or a configured remote SSH profile.")
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

    def _run_setup_wizard(self) -> None:
        from src.main import run_first_run_wizard

        try:
            run_first_run_wizard(self.manager)
        except VPNManagerError as exc:
            self._pause(str(exc))
            return
        self._refresh_host_snapshot()
        self._pause(self._t("Setup wizard completed.", "Майстер налаштування завершено."))

    def _change_language(self) -> None:
        selected = input(self._t("Choose language [uk/en]: ", "Оберіть мову [uk/en]: ")).strip().lower()
        self.language = save_app_language(self.manager.config.project_root, selected)
        self._pause(
            self._t(
                f"Language changed to {LANGUAGE_LABELS[self.language]}.",
                f"Мову змінено на {LANGUAGE_LABELS[self.language]}.",
            )
        )

    def _refresh_host_snapshot(self) -> None:
        self.host = detect_host_platform()
        self.hardware = detect_host_hardware()
        detect_host_location.cache_clear()
        self.location = detect_host_location()
        self.local_ip_address = detect_local_ip_address()

    def _safe_service_state(self) -> str:
        if not self.manager.can_control_vpn():
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

    def _cpu_cores_summary(self) -> str:
        physical = self.hardware.cpu_physical_cores
        logical = self.hardware.cpu_logical_cores

        if physical and logical and physical != logical:
            return f"{physical} physical / {logical} logical"
        if physical:
            return f"{physical}"
        if logical:
            return f"{logical} logical"
        return "Unavailable"

    def _gpu_cores_summary(self) -> str:
        if self.hardware.gpu_cores is None:
            return "Unavailable"
        return str(self.hardware.gpu_cores)

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
        input(self._t("\nPress Enter to continue...", "\nНатисніть Enter, щоб продовжити..."))

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
    language: str = "uk",
) -> int:
    """Run the modern terminal interface."""

    app = ConsoleApp(manager, open_gui_callback=open_gui_callback, language=language)
    return app.run()
