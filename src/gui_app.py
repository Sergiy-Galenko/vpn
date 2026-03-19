from __future__ import annotations

import os
import queue
import shutil
import subprocess
import threading
import tkinter as tk
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from tkinter.scrolledtext import ScrolledText
from typing import Callable

from src.config import (
    EditableVPNSettings,
    editable_settings_from_config,
    load_app_language,
    save_app_language,
    save_editable_settings,
)
from src.i18n import LANGUAGE_LABELS, normalize_language, translate
from src.models import (
    AuditLogRecord,
    AuthMethod,
    BackupRecord,
    ClientRecord,
    ClientStatus,
    ConnectedClient,
    RemoteProfileRecord,
    ValidationIssue,
    VPNManagerError,
)
from src.utils import (
    HostHardwareInfo,
    HostLocationInfo,
    HostPlatformInfo,
    detect_host_hardware,
    detect_host_location,
    detect_host_platform,
    detect_local_ip_address,
    format_bytes_binary,
    is_root,
    linux_host_requirement_message,
)
from src.wireguard_manager import WireGuardManager


PALETTE = {
    "ink": "#14213D",
    "navy": "#203A43",
    "teal": "#2C7A7B",
    "sand": "#F3EFE4",
    "paper": "#FFFDFC",
    "amber": "#F4A261",
    "coral": "#D65A4A",
    "mint": "#A8DADC",
    "line": "#D6D0C4",
    "text": "#22313F",
    "muted": "#607080",
    "success": "#2A9D8F",
}


def format_bytes(value: int) -> str:
    """Render byte counters in a compact human-readable format."""

    size = float(value)
    units = ["B", "KB", "MB", "GB", "TB"]
    unit_index = 0

    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1

    if unit_index == 0:
        return f"{int(size)} {units[unit_index]}"
    return f"{size:.1f} {units[unit_index]}"


def format_iso_datetime(value: str | None) -> str:
    """Format stored ISO timestamps for the desktop UI."""

    if not value:
        return "—"
    try:
        return datetime.fromisoformat(value).astimezone().strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return value


def format_unix_timestamp(value: int) -> str:
    """Format handshake timestamps for the UI."""

    if value <= 0:
        return "Never"
    return datetime.fromtimestamp(value, tz=timezone.utc).astimezone().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def read_log_tail(path: Path, lines: int = 50) -> str:
    """Read the last N lines from the application log file."""

    if not path.exists():
        return "Log file has not been created yet."

    content = path.read_text(encoding="utf-8", errors="replace").splitlines()
    tail = content[-lines:]
    return "\n".join(tail) if tail else "Log file is empty."


def open_path_in_system(path: Path) -> None:
    """Open a file or directory in the host operating system."""

    target = path.expanduser().resolve()
    host = detect_host_platform()

    try:
        if host.system == "Darwin":
            subprocess.run(["open", str(target)], check=False)
            return
        if host.system == "Linux":
            subprocess.run(["xdg-open", str(target)], check=False)
            return
        if host.system == "Windows":
            os.startfile(target)  # type: ignore[attr-defined]
            return
    except OSError as exc:
        raise VPNManagerError(f"Could not open path: {target}") from exc

    raise VPNManagerError("Opening files is not supported on this platform.")


class VPNDesktopApp(tk.Tk):
    """Desktop UI wrapper around the WireGuard manager."""

    def __init__(self, manager: WireGuardManager, *, language: str = "uk") -> None:
        super().__init__()
        self.manager = manager
        self.language = normalize_language(language)
        self.host_platform: HostPlatformInfo = detect_host_platform()
        self.host_location: HostLocationInfo = detect_host_location()
        self.host_hardware: HostHardwareInfo = detect_host_hardware()
        self.local_ip_address: str | None = detect_local_ip_address()
        self.task_queue: queue.Queue[
            tuple[str, str, object | None, Callable[[object | None], None] | None]
        ] = queue.Queue()
        self.busy_widgets: list[tk.Widget] = []
        self.control_widgets: list[tk.Widget] = []
        self.client_rows: dict[str, ClientRecord] = {}
        self.backup_rows: dict[str, BackupRecord] = {}
        self.audit_rows: dict[str, AuditLogRecord] = {}
        self.qr_image_refs: list[tk.PhotoImage] = []

        self.title(self._t("WireGuard Control Room", "Панель керування WireGuard"))
        self.geometry("1520x980")
        self.minsize(1240, 780)
        self.configure(bg=PALETTE["sand"])
        self.option_add("*tearOff", False)

        self.status_var = tk.StringVar(value="Ready.")
        self.hero_status_var = tk.StringVar()
        self.hero_counts_var = tk.StringVar()
        self.hero_environment_var = tk.StringVar()
        self.overview_note_var = tk.StringVar()
        self.connected_note_var = tk.StringVar()
        self.remote_summary_var = tk.StringVar()
        self.imported_summary_var = tk.StringVar()
        self.language_var = tk.StringVar(value=self.language)

        self.settings_vars = {
            "endpoint": tk.StringVar(),
            "interface_name": tk.StringVar(),
            "server_address": tk.StringVar(),
            "server_port": tk.StringVar(),
            "public_interface": tk.StringVar(),
            "dns": tk.StringVar(),
            "client_allowed_ips": tk.StringVar(),
            "connected_window_seconds": tk.StringVar(),
        }
        self.add_client_vars = {
            "name": tk.StringVar(),
            "email": tk.StringVar(),
            "device": tk.StringVar(),
            "comment": tk.StringVar(),
            "expiry_at": tk.StringVar(),
        }

        self._build_styles()
        self._build_shell()
        self._load_settings_form()
        self._refresh_all()
        self._refresh_control_capabilities()
        self.after(160, self._poll_task_queue)
        self.after(240, self._maybe_open_first_run_wizard)

    def _t(self, en: str, uk: str) -> str:
        return translate(self.language, en=en, uk=uk)

    def _build_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("App.TFrame", background=PALETTE["sand"])
        style.configure("Panel.TFrame", background=PALETTE["paper"])
        style.configure(
            "Sidebar.TButton",
            background=PALETTE["ink"],
            foreground=PALETTE["paper"],
            font=("Avenir Next", 11, "bold"),
            padding=(14, 12),
            borderwidth=0,
        )
        style.map(
            "Sidebar.TButton",
            background=[("active", PALETTE["teal"]), ("disabled", PALETTE["muted"])],
            foreground=[("disabled", PALETTE["paper"])],
        )
        style.configure(
            "Accent.TButton",
            background=PALETTE["teal"],
            foreground=PALETTE["paper"],
            font=("Avenir Next", 11, "bold"),
            padding=(14, 10),
            borderwidth=0,
        )
        style.map(
            "Accent.TButton",
            background=[("active", PALETTE["ink"]), ("disabled", PALETTE["muted"])],
            foreground=[("disabled", PALETTE["paper"])],
        )
        style.configure(
            "Danger.TButton",
            background=PALETTE["coral"],
            foreground=PALETTE["paper"],
            font=("Avenir Next", 11, "bold"),
            padding=(14, 10),
            borderwidth=0,
        )
        style.map(
            "Danger.TButton",
            background=[("active", "#B44739"), ("disabled", PALETTE["muted"])],
            foreground=[("disabled", PALETTE["paper"])],
        )
        style.configure(
            "Notebook.TNotebook",
            background=PALETTE["sand"],
            borderwidth=0,
            tabmargins=(8, 0, 0, 0),
        )
        style.configure(
            "Notebook.TNotebook.Tab",
            background=PALETTE["paper"],
            foreground=PALETTE["muted"],
            font=("Avenir Next", 11, "bold"),
            padding=(18, 12),
            borderwidth=0,
        )
        style.map(
            "Notebook.TNotebook.Tab",
            background=[("selected", PALETTE["ink"]), ("active", PALETTE["teal"])],
            foreground=[("selected", PALETTE["paper"]), ("active", PALETTE["paper"])],
        )
        style.configure(
            "Treeview",
            background=PALETTE["paper"],
            foreground=PALETTE["text"],
            fieldbackground=PALETTE["paper"],
            bordercolor=PALETTE["line"],
            rowheight=30,
            font=("Avenir Next", 10),
        )
        style.configure(
            "Treeview.Heading",
            background=PALETTE["ink"],
            foreground=PALETTE["paper"],
            font=("Avenir Next", 10, "bold"),
            padding=(10, 8),
        )

    def _build_shell(self) -> None:
        root = tk.Frame(self, bg=PALETTE["sand"])
        root.pack(fill="both", expand=True)
        root.columnconfigure(1, weight=1)
        root.rowconfigure(0, weight=1)

        sidebar = tk.Frame(root, bg=PALETTE["ink"], width=290)
        sidebar.grid(row=0, column=0, sticky="ns")
        sidebar.grid_propagate(False)

        content = tk.Frame(root, bg=PALETTE["sand"])
        content.grid(row=0, column=1, sticky="nsew", padx=(0, 18), pady=18)
        content.columnconfigure(0, weight=1)
        content.rowconfigure(1, weight=1)

        self._build_sidebar(sidebar)
        self._build_header(content)
        self._build_notebook(content)
        self._build_status_bar(root)

    def _build_sidebar(self, parent: tk.Frame) -> None:
        logo = tk.Canvas(
            parent,
            width=220,
            height=110,
            bg=PALETTE["ink"],
            highlightthickness=0,
        )
        logo.pack(padx=26, pady=(26, 10))
        self._draw_logo_mark(logo)

        tk.Label(
            parent,
            text=self._t("Control Room", "Панель керування"),
            bg=PALETTE["ink"],
            fg=PALETTE["paper"],
            font=("Iowan Old Style", 24, "bold"),
        ).pack(anchor="w", padx=28)
        tk.Label(
            parent,
            text=self._t(
                "Desktop console for your personal WireGuard VPN",
                "Десктопна консоль для вашого персонального WireGuard VPN",
            ),
            bg=PALETTE["ink"],
            fg="#B6C2CF",
            wraplength=220,
            justify="left",
            font=("Avenir Next", 11),
        ).pack(anchor="w", padx=28, pady=(6, 20))

        for label, command, control_required in [
            (self._t("Refresh Dashboard", "Оновити дашборд"), self._refresh_all, False),
            (self._t("System Info", "Системна інформація"), self._open_system_info_dialog, False),
            (self._t("Refresh Location", "Оновити локацію"), self._refresh_location_info, False),
            (self._t("Set Server IP", "Встановити IP сервера"), self._open_endpoint_quick_dialog, False),
            (self._t("Connect to Server", "Підключитися до сервера"), self._open_remote_profile_dialog, False),
            (self._t("Validate Environment", "Перевірити середовище"), self._show_validation_results, False),
            (self._t("Run Setup Wizard", "Запустити майстер"), self._open_first_run_wizard, False),
            (self._t("Create Backup", "Створити backup"), self._prompt_create_backup, False),
            (self._t("Import Existing Config", "Імпортувати config"), self._prompt_import_existing_config, False),
            (self._t("Install VPN", "Встановити VPN"), lambda: self._run_task("Installing VPN", self.manager.install_wireguard), True),
            (self._t("Start VPN", "Запустити VPN"), lambda: self._run_task("Starting VPN", self.manager.start_vpn), True),
            (self._t("Stop VPN", "Зупинити VPN"), lambda: self._run_task("Stopping VPN", self.manager.stop_vpn), True),
            (self._t("Restart VPN", "Перезапустити VPN"), lambda: self._run_task("Restarting VPN", self.manager.restart_vpn), True),
            (self._t("Open Configs Folder", "Відкрити configs"), lambda: self._open_path(self.manager.config.configs_dir), False),
            (self._t("Open Data Folder", "Відкрити data"), lambda: self._open_path(self.manager.config.data_dir), False),
        ]:
            button = ttk.Button(parent, text=label, command=command, style="Sidebar.TButton")
            button.pack(fill="x", padx=24, pady=5)
            self.busy_widgets.append(button)
            if control_required:
                self.control_widgets.append(button)

        info_card = tk.Frame(parent, bg="#19314F", bd=0, highlightthickness=0)
        info_card.pack(fill="x", padx=24, pady=(24, 0))

        self.sidebar_info = tk.Label(
            info_card,
            text="",
            bg="#19314F",
            fg="#DDE7F0",
            justify="left",
            anchor="nw",
            font=("Avenir Next", 10),
            padx=16,
            pady=16,
        )
        self.sidebar_info.pack(fill="both")

    def _build_header(self, parent: tk.Frame) -> None:
        hero = tk.Frame(parent, bg=PALETTE["paper"], padx=26, pady=24)
        hero.grid(row=0, column=0, sticky="ew", pady=(0, 18))
        hero.columnconfigure(0, weight=1)

        tk.Label(
            hero,
            text=self._t("WireGuard Operations Deck", "Панель операцій WireGuard"),
            bg=PALETTE["paper"],
            fg=PALETTE["ink"],
            font=("Iowan Old Style", 30, "bold"),
        ).grid(row=0, column=0, sticky="w")
        tk.Label(
            hero,
            text=self._t(
                "Desktop control panel for local Ubuntu or remote SSH-backed WireGuard management.",
                "Десктопна панель для локального Ubuntu або remote SSH-керування WireGuard.",
            ),
            bg=PALETTE["paper"],
            fg=PALETTE["muted"],
            font=("Avenir Next", 12),
        ).grid(row=1, column=0, sticky="w", pady=(6, 16))

        chips = tk.Frame(hero, bg=PALETTE["paper"])
        chips.grid(row=2, column=0, sticky="ew")

        for variable, background in [
            (self.hero_status_var, PALETTE["ink"]),
            (self.hero_counts_var, PALETTE["mint"]),
            (self.hero_environment_var, PALETTE["amber"]),
        ]:
            label = tk.Label(
                chips,
                textvariable=variable,
                bg=background,
                fg=PALETTE["paper"] if background == PALETTE["ink"] else PALETTE["ink"],
                font=("Avenir Next", 11, "bold"),
                padx=14,
                pady=8,
            )
            label.pack(side="left", padx=(0, 10))

        actions = tk.Frame(hero, bg=PALETTE["paper"])
        actions.grid(row=0, column=1, rowspan=3, sticky="ne")
        for label, command in [
            (self._t("System Info", "Системна інформація"), self._open_system_info_dialog),
            (self._t("Set Server IP", "Встановити IP сервера"), self._open_endpoint_quick_dialog),
            (self._t("Connect to Server", "Підключитися до сервера"), self._open_remote_profile_dialog),
            (self._t("Validate", "Перевірити"), self._show_validation_results),
            (self._t("Backup", "Backup"), self._prompt_create_backup),
        ]:
            button = ttk.Button(actions, text=label, command=command, style="Accent.TButton")
            button.pack(anchor="e", pady=4)
            self.busy_widgets.append(button)

    def _build_notebook(self, parent: tk.Frame) -> None:
        notebook = ttk.Notebook(parent, style="Notebook.TNotebook")
        notebook.grid(row=1, column=0, sticky="nsew")

        self.overview_tab = tk.Frame(notebook, bg=PALETTE["sand"])
        self.clients_tab = tk.Frame(notebook, bg=PALETTE["sand"])
        self.connected_tab = tk.Frame(notebook, bg=PALETTE["sand"])
        self.maintenance_tab = tk.Frame(notebook, bg=PALETTE["sand"])
        self.audit_tab = tk.Frame(notebook, bg=PALETTE["sand"])
        self.settings_tab = tk.Frame(notebook, bg=PALETTE["sand"])

        notebook.add(self.overview_tab, text=self._t("Overview", "Огляд"))
        notebook.add(self.clients_tab, text=self._t("Clients", "Клієнти"))
        notebook.add(self.connected_tab, text=self._t("Connected", "Підключення"))
        notebook.add(self.maintenance_tab, text=self._t("Maintenance", "Обслуговування"))
        notebook.add(self.audit_tab, text=self._t("Audit Log", "Аудит-лог"))
        notebook.add(self.settings_tab, text=self._t("Settings", "Налаштування"))

        self._build_overview_tab()
        self._build_clients_tab()
        self._build_connected_tab()
        self._build_maintenance_tab()
        self._build_audit_tab()
        self._build_settings_tab()

    def _build_overview_tab(self) -> None:
        container = tk.Frame(self.overview_tab, bg=PALETTE["sand"])
        container.pack(fill="both", expand=True)
        container.columnconfigure((0, 1), weight=1, uniform="overview")
        container.rowconfigure(1, weight=1)

        self.metric_labels: dict[str, tk.Label] = {}
        metric_specs = [
            ("total_clients", "Total Clients", PALETTE["ink"]),
            ("connected_clients", "Connected Now", PALETTE["teal"]),
            ("service_state", "Service State", PALETTE["amber"]),
            ("endpoint", "Endpoint", PALETTE["coral"]),
        ]

        metrics_row = tk.Frame(container, bg=PALETTE["sand"])
        metrics_row.grid(row=0, column=0, columnspan=2, sticky="ew")
        metrics_row.columnconfigure((0, 1, 2, 3), weight=1, uniform="metrics")

        for index, (key, title, color) in enumerate(metric_specs):
            card = tk.Frame(metrics_row, bg=color, padx=18, pady=18)
            card.grid(row=0, column=index, sticky="nsew", padx=(0 if index == 0 else 10, 0), pady=(0, 12))
            tk.Label(
                card,
                text=title,
                bg=color,
                fg=PALETTE["paper"],
                font=("Avenir Next", 10, "bold"),
            ).pack(anchor="w")
            value_label = tk.Label(
                card,
                text="—",
                bg=color,
                fg=PALETTE["paper"],
                wraplength=220,
                justify="left",
                font=("Iowan Old Style", 24, "bold"),
            )
            value_label.pack(anchor="w", pady=(10, 0))
            self.metric_labels[key] = value_label

        notes_card = tk.Frame(container, bg=PALETTE["paper"], padx=22, pady=20)
        notes_card.grid(row=1, column=0, sticky="nsew", padx=(0, 10))

        tk.Label(
            notes_card,
            text="Operational Notes",
            bg=PALETTE["paper"],
            fg=PALETTE["ink"],
            font=("Iowan Old Style", 20, "bold"),
        ).pack(anchor="w")
        tk.Label(
            notes_card,
            textvariable=self.overview_note_var,
            bg=PALETTE["paper"],
            fg=PALETTE["muted"],
            justify="left",
            wraplength=520,
            font=("Avenir Next", 11),
        ).pack(anchor="w", pady=(12, 0))

        quick_actions = tk.Frame(container, bg=PALETTE["paper"], padx=22, pady=20)
        quick_actions.grid(row=1, column=1, sticky="nsew", padx=(10, 0))

        tk.Label(
            quick_actions,
            text="Quick Actions",
            bg=PALETTE["paper"],
            fg=PALETTE["ink"],
            font=("Iowan Old Style", 20, "bold"),
        ).pack(anchor="w")
        tk.Label(
            quick_actions,
            text="Use the action deck to manage remote/local runtime state, exports and safety operations without leaving the app.",
            bg=PALETTE["paper"],
            fg=PALETTE["muted"],
            justify="left",
            wraplength=520,
            font=("Avenir Next", 11),
        ).pack(anchor="w", pady=(10, 14))

        button_row = tk.Frame(quick_actions, bg=PALETTE["paper"])
        button_row.pack(anchor="w")

        for label, command, style, control_required in [
            ("Install", lambda: self._run_task("Installing VPN", self.manager.install_wireguard), "Accent.TButton", True),
            ("Start", lambda: self._run_task("Starting VPN", self.manager.start_vpn), "Accent.TButton", True),
            ("Stop", lambda: self._run_task("Stopping VPN", self.manager.stop_vpn), "Danger.TButton", True),
            ("Restart", lambda: self._run_task("Restarting VPN", self.manager.restart_vpn), "Accent.TButton", True),
            ("Validate", self._show_validation_results, "Accent.TButton", False),
            ("Backup", self._prompt_create_backup, "Accent.TButton", False),
        ]:
            button = ttk.Button(button_row, text=label, command=command, style=style)
            button.pack(side="left", padx=(0, 10), pady=(0, 8))
            self.busy_widgets.append(button)
            if control_required:
                self.control_widgets.append(button)

        hardware_card = tk.Frame(container, bg=PALETTE["paper"], padx=22, pady=20)
        hardware_card.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(12, 0))
        hardware_card.columnconfigure((0, 1, 2, 3), weight=1, uniform="hardware")

        tk.Label(
            hardware_card,
            text="PC Characteristics",
            bg=PALETTE["paper"],
            fg=PALETTE["ink"],
            font=("Iowan Old Style", 20, "bold"),
        ).grid(row=0, column=0, columnspan=4, sticky="w")
        tk.Label(
            hardware_card,
            text="Detected host hardware and network identity for the current desktop client.",
            bg=PALETTE["paper"],
            fg=PALETTE["muted"],
            justify="left",
            font=("Avenir Next", 11),
        ).grid(row=1, column=0, columnspan=4, sticky="w", pady=(8, 14))

        self.location_detail_var = tk.StringVar()
        tk.Label(
            hardware_card,
            textvariable=self.location_detail_var,
            bg=PALETTE["paper"],
            fg=PALETTE["muted"],
            justify="left",
            wraplength=1200,
            font=("Avenir Next", 10),
        ).grid(row=2, column=0, columnspan=4, sticky="w", pady=(0, 14))

        self.hardware_value_labels: dict[str, tk.Label] = {}
        for index, (key, title) in enumerate(
            [
                ("host_os", "Host OS"),
                ("processor", "Processor"),
                ("ram", "RAM"),
                ("storage", "Storage"),
                ("cpu_cores", "CPU Cores"),
                ("gpu_cores", "GPU Cores"),
                ("local_ip", "Local IP"),
                ("public_ip", "Public IP"),
                ("coordinates", "Coordinates"),
                ("timezone", "Timezone"),
                ("location_source", "Location Source"),
                ("vpn_endpoint", "VPN Endpoint"),
            ]
        ):
            row = 3 + (index // 4) * 2
            column = index % 4
            cell = tk.Frame(hardware_card, bg="#FBFAF7", padx=14, pady=12)
            cell.grid(row=row, column=column, sticky="nsew", padx=(0 if column == 0 else 10, 0), pady=(0, 10))
            tk.Label(
                cell,
                text=title,
                bg="#FBFAF7",
                fg=PALETTE["muted"],
                font=("Avenir Next", 9, "bold"),
            ).pack(anchor="w")
            value_label = tk.Label(
                cell,
                text="—",
                bg="#FBFAF7",
                fg=PALETTE["ink"],
                wraplength=250,
                justify="left",
                font=("Avenir Next", 11, "bold"),
            )
            value_label.pack(anchor="w", pady=(8, 0))
            self.hardware_value_labels[key] = value_label

    def _build_clients_tab(self) -> None:
        container = tk.Frame(self.clients_tab, bg=PALETTE["sand"])
        container.pack(fill="both", expand=True)
        container.rowconfigure(1, weight=1)
        container.columnconfigure(0, weight=1)

        add_card = tk.Frame(container, bg=PALETTE["paper"], padx=20, pady=18)
        add_card.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        add_card.columnconfigure(1, weight=1)
        add_card.columnconfigure(3, weight=1)

        tk.Label(
            add_card,
            text="Add Client",
            bg=PALETTE["paper"],
            fg=PALETTE["ink"],
            font=("Iowan Old Style", 20, "bold"),
        ).grid(row=0, column=0, columnspan=4, sticky="w")
        tk.Label(
            add_card,
            text="Create a client, generate keys, export ready-to-use config and QR, and persist metadata.",
            bg=PALETTE["paper"],
            fg=PALETTE["muted"],
            justify="left",
            font=("Avenir Next", 11),
        ).grid(row=1, column=0, columnspan=4, sticky="w", pady=(8, 14))

        fields = [
            ("Name", "name"),
            ("Email", "email"),
            ("Device", "device"),
            ("Expiry ISO", "expiry_at"),
            ("Comment", "comment"),
        ]
        positions = [(2, 0), (2, 2), (3, 0), (3, 2), (4, 0)]
        for (label, key), (row, col) in zip(fields, positions, strict=False):
            tk.Label(
                add_card,
                text=label,
                bg=PALETTE["paper"],
                fg=PALETTE["ink"],
                font=("Avenir Next", 10, "bold"),
            ).grid(row=row, column=col, sticky="w", pady=5, padx=(0, 10))
            entry = ttk.Entry(add_card, textvariable=self.add_client_vars[key], width=36)
            entry.grid(row=row, column=col + 1, sticky="ew", pady=5)
            self.busy_widgets.append(entry)

        add_button = ttk.Button(
            add_card,
            text="Add Client",
            command=self._submit_add_client,
            style="Accent.TButton",
        )
        add_button.grid(row=4, column=3, sticky="e", pady=(10, 0))
        self.busy_widgets.append(add_button)

        table_card = tk.Frame(container, bg=PALETTE["paper"], padx=18, pady=18)
        table_card.grid(row=1, column=0, sticky="nsew")
        table_card.rowconfigure(1, weight=1)
        table_card.columnconfigure(0, weight=1)

        tk.Label(
            table_card,
            text="Client Inventory",
            bg=PALETTE["paper"],
            fg=PALETTE["ink"],
            font=("Iowan Old Style", 20, "bold"),
        ).grid(row=0, column=0, sticky="w")

        tree_frame = tk.Frame(table_card, bg=PALETTE["paper"])
        tree_frame.grid(row=1, column=0, sticky="nsew", pady=(14, 12))
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        self.clients_tree = ttk.Treeview(
            tree_frame,
            columns=("address", "status", "email", "device", "expiry", "updated"),
            show="headings",
        )
        for column, title, width, anchor in [
            ("address", "Address", 130, "center"),
            ("status", "Status", 110, "center"),
            ("email", "Email", 180, "w"),
            ("device", "Device", 140, "w"),
            ("expiry", "Expiry", 150, "center"),
            ("updated", "Updated", 160, "center"),
        ]:
            self.clients_tree.heading(column, text=title)
            self.clients_tree.column(column, width=width, anchor=anchor)
        self.clients_tree.grid(row=0, column=0, sticky="nsew")
        self.clients_tree.tag_configure(ClientStatus.DISABLED.value, foreground=PALETTE["muted"])
        self.clients_tree.tag_configure(ClientStatus.EXPIRED.value, foreground=PALETTE["coral"])
        self.clients_tree.tag_configure(ClientStatus.IMPORTED.value, foreground=PALETTE["amber"])
        self.clients_tree.bind("<Double-1>", lambda _event: self._open_client_details_dialog())

        client_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.clients_tree.yview)
        client_scroll.grid(row=0, column=1, sticky="ns")
        self.clients_tree.configure(yscrollcommand=client_scroll.set)

        action_row = tk.Frame(table_card, bg=PALETTE["paper"])
        action_row.grid(row=2, column=0, sticky="w")
        for label, command, style in [
            ("Refresh", self._refresh_all, "Accent.TButton"),
            ("Details", self._open_client_details_dialog, "Accent.TButton"),
            ("Export", self._open_selected_client_export, "Accent.TButton"),
            ("Disable", self._disable_selected_client, "Danger.TButton"),
            ("Enable", self._enable_selected_client, "Accent.TButton"),
            ("Remove", self._remove_selected_client, "Danger.TButton"),
        ]:
            button = ttk.Button(action_row, text=label, command=command, style=style)
            button.pack(side="left", padx=(0, 10))
            self.busy_widgets.append(button)

    def _build_connected_tab(self) -> None:
        container = tk.Frame(self.connected_tab, bg=PALETTE["sand"])
        container.pack(fill="both", expand=True)
        container.rowconfigure(1, weight=1)
        container.columnconfigure(0, weight=1)

        header = tk.Frame(container, bg=PALETTE["paper"], padx=20, pady=18)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        tk.Label(
            header,
            text="Recent Handshakes",
            bg=PALETTE["paper"],
            fg=PALETTE["ink"],
            font=("Iowan Old Style", 20, "bold"),
        ).pack(anchor="w")
        tk.Label(
            header,
            textvariable=self.connected_note_var,
            bg=PALETTE["paper"],
            fg=PALETTE["muted"],
            justify="left",
            font=("Avenir Next", 11),
        ).pack(anchor="w", pady=(8, 12))

        refresh_button = ttk.Button(
            header,
            text="Refresh Connected Peers",
            command=self._refresh_all,
            style="Accent.TButton",
        )
        refresh_button.pack(anchor="w")
        self.busy_widgets.append(refresh_button)
        self.control_widgets.append(refresh_button)

        table_card = tk.Frame(container, bg=PALETTE["paper"], padx=18, pady=18)
        table_card.grid(row=1, column=0, sticky="nsew")
        table_card.rowconfigure(0, weight=1)
        table_card.columnconfigure(0, weight=1)

        tree_frame = tk.Frame(table_card, bg=PALETTE["paper"])
        tree_frame.grid(row=0, column=0, sticky="nsew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        self.connected_tree = ttk.Treeview(
            tree_frame,
            columns=("name", "address", "endpoint", "handshake", "rx", "tx"),
            show="headings",
        )
        for column, title, width, anchor in [
            ("name", "Client", 180, "w"),
            ("address", "Address", 140, "center"),
            ("endpoint", "Endpoint", 250, "w"),
            ("handshake", "Last Handshake", 180, "center"),
            ("rx", "RX", 110, "center"),
            ("tx", "TX", 110, "center"),
        ]:
            self.connected_tree.heading(column, text=title)
            self.connected_tree.column(column, width=width, anchor=anchor)
        self.connected_tree.grid(row=0, column=0, sticky="nsew")

        connected_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.connected_tree.yview)
        connected_scroll.grid(row=0, column=1, sticky="ns")
        self.connected_tree.configure(yscrollcommand=connected_scroll.set)

    def _build_maintenance_tab(self) -> None:
        container = tk.Frame(self.maintenance_tab, bg=PALETTE["sand"])
        container.pack(fill="both", expand=True)
        container.columnconfigure((0, 1), weight=1, uniform="maintenance")
        container.rowconfigure(0, weight=1)

        operations_card = tk.Frame(container, bg=PALETTE["paper"], padx=20, pady=20)
        operations_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        operations_card.columnconfigure(1, weight=1)

        tk.Label(
            operations_card,
            text="Maintenance & Files",
            bg=PALETTE["paper"],
            fg=PALETTE["ink"],
            font=("Iowan Old Style", 20, "bold"),
        ).grid(row=0, column=0, columnspan=2, sticky="w")

        self.path_labels: dict[str, tk.Label] = {}
        for row_index, (title, key) in enumerate(
            [
                ("Configs Directory", "configs"),
                ("Data Directory", "data"),
                ("Server Config", "server_config"),
                ("System Config", "system_config"),
                ("Log File", "log_file"),
            ],
            start=1,
        ):
            tk.Label(
                operations_card,
                text=title,
                bg=PALETTE["paper"],
                fg=PALETTE["muted"],
                anchor="w",
                font=("Avenir Next", 10, "bold"),
            ).grid(row=row_index, column=0, sticky="w", pady=8, padx=(0, 10))
            label = tk.Label(
                operations_card,
                text="",
                bg=PALETTE["paper"],
                fg=PALETTE["text"],
                wraplength=340,
                justify="left",
                anchor="w",
                font=("Avenir Next", 10),
            )
            label.grid(row=row_index, column=1, sticky="w")
            self.path_labels[key] = label

        button_row = tk.Frame(operations_card, bg=PALETTE["paper"])
        button_row.grid(row=6, column=0, columnspan=2, sticky="w", pady=(14, 10))
        for label, command, style in [
            ("Validate", self._show_validation_results, "Accent.TButton"),
            ("Setup Wizard", self._open_first_run_wizard, "Accent.TButton"),
            ("Create Backup", self._prompt_create_backup, "Accent.TButton"),
            ("Restore Backup", self._prompt_restore_backup, "Danger.TButton"),
            ("Import Config", self._prompt_import_existing_config, "Accent.TButton"),
        ]:
            button = ttk.Button(button_row, text=label, command=command, style=style)
            button.pack(side="left", padx=(0, 10), pady=4)
            self.busy_widgets.append(button)

        remote_row = tk.Frame(operations_card, bg=PALETTE["paper"])
        remote_row.grid(row=7, column=0, columnspan=2, sticky="w", pady=(4, 10))
        for label, command, style in [
            ("Configure Remote", self._open_remote_profile_dialog, "Accent.TButton"),
            ("Test Remote", self._test_remote_profile, "Accent.TButton"),
            ("Clear Remote", self._clear_remote_profile, "Danger.TButton"),
        ]:
            button = ttk.Button(remote_row, text=label, command=command, style=style)
            button.pack(side="left", padx=(0, 10), pady=4)
            self.busy_widgets.append(button)

        open_row = tk.Frame(operations_card, bg=PALETTE["paper"])
        open_row.grid(row=8, column=0, columnspan=2, sticky="w", pady=(4, 0))
        for label, path_getter in [
            ("Open Configs", lambda: self.manager.config.configs_dir),
            ("Open Data", lambda: self.manager.config.data_dir),
            ("Open Log", lambda: self.manager.config.log_path),
        ]:
            button = ttk.Button(
                open_row,
                text=label,
                command=lambda getter=path_getter: self._open_path(getter()),
                style="Accent.TButton",
            )
            button.pack(side="left", padx=(0, 10), pady=4)
            self.busy_widgets.append(button)

        self.imported_label = tk.Label(
            operations_card,
            textvariable=self.imported_summary_var,
            bg=PALETTE["paper"],
            fg=PALETTE["muted"],
            justify="left",
            anchor="w",
            font=("Avenir Next", 10),
        )
        self.imported_label.grid(row=9, column=0, columnspan=2, sticky="w", pady=(16, 0))

        right_column = tk.Frame(container, bg=PALETTE["sand"])
        right_column.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        right_column.rowconfigure(0, weight=1)
        right_column.rowconfigure(1, weight=1)
        right_column.columnconfigure(0, weight=1)

        backups_card = tk.Frame(right_column, bg=PALETTE["paper"], padx=18, pady=18)
        backups_card.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
        backups_card.rowconfigure(1, weight=1)
        backups_card.columnconfigure(0, weight=1)

        tk.Label(
            backups_card,
            text="Backups",
            bg=PALETTE["paper"],
            fg=PALETTE["ink"],
            font=("Iowan Old Style", 20, "bold"),
        ).grid(row=0, column=0, sticky="w")

        backups_tree_frame = tk.Frame(backups_card, bg=PALETTE["paper"])
        backups_tree_frame.grid(row=1, column=0, sticky="nsew", pady=(12, 10))
        backups_tree_frame.rowconfigure(0, weight=1)
        backups_tree_frame.columnconfigure(0, weight=1)

        self.backups_tree = ttk.Treeview(
            backups_tree_frame,
            columns=("created", "scope", "note"),
            show="headings",
        )
        for column, title, width, anchor in [
            ("created", "Created", 160, "center"),
            ("scope", "Scope", 90, "center"),
            ("note", "Note", 280, "w"),
        ]:
            self.backups_tree.heading(column, text=title)
            self.backups_tree.column(column, width=width, anchor=anchor)
        self.backups_tree.grid(row=0, column=0, sticky="nsew")

        backup_scroll = ttk.Scrollbar(backups_tree_frame, orient="vertical", command=self.backups_tree.yview)
        backup_scroll.grid(row=0, column=1, sticky="ns")
        self.backups_tree.configure(yscrollcommand=backup_scroll.set)

        backup_actions = tk.Frame(backups_card, bg=PALETTE["paper"])
        backup_actions.grid(row=2, column=0, sticky="w")
        for label, command, style in [
            ("Refresh", self._refresh_all, "Accent.TButton"),
            ("Open", self._open_selected_backup, "Accent.TButton"),
            ("Restore", self._restore_selected_backup, "Danger.TButton"),
        ]:
            button = ttk.Button(backup_actions, text=label, command=command, style=style)
            button.pack(side="left", padx=(0, 10))
            self.busy_widgets.append(button)

        logs_card = tk.Frame(right_column, bg=PALETTE["paper"], padx=18, pady=18)
        logs_card.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        tk.Label(
            logs_card,
            text="Recent Logs",
            bg=PALETTE["paper"],
            fg=PALETTE["ink"],
            font=("Iowan Old Style", 20, "bold"),
        ).pack(anchor="w")
        self.log_text = ScrolledText(
            logs_card,
            wrap="word",
            height=18,
            bg="#FBFAF7",
            fg=PALETTE["text"],
            insertbackground=PALETTE["ink"],
            relief="flat",
            font=("Menlo", 11),
        )
        self.log_text.pack(fill="both", expand=True, pady=(12, 0))
        self.log_text.configure(state="disabled")

    def _build_audit_tab(self) -> None:
        container = tk.Frame(self.audit_tab, bg=PALETTE["sand"])
        container.pack(fill="both", expand=True)
        container.columnconfigure(0, weight=1)
        container.rowconfigure(1, weight=1)

        header = tk.Frame(container, bg=PALETTE["paper"], padx=20, pady=18)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        tk.Label(
            header,
            text="Audit Trail",
            bg=PALETTE["paper"],
            fg=PALETTE["ink"],
            font=("Iowan Old Style", 20, "bold"),
        ).pack(side="left")
        refresh_button = ttk.Button(header, text="Refresh", command=self._refresh_all, style="Accent.TButton")
        refresh_button.pack(side="right")
        self.busy_widgets.append(refresh_button)

        split = tk.Frame(container, bg=PALETTE["sand"])
        split.grid(row=1, column=0, sticky="nsew")
        split.columnconfigure(0, weight=3)
        split.columnconfigure(1, weight=2)
        split.rowconfigure(0, weight=1)

        table_card = tk.Frame(split, bg=PALETTE["paper"], padx=18, pady=18)
        table_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        table_card.rowconfigure(0, weight=1)
        table_card.columnconfigure(0, weight=1)

        table_frame = tk.Frame(table_card, bg=PALETTE["paper"])
        table_frame.grid(row=0, column=0, sticky="nsew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        self.audit_tree = ttk.Treeview(
            table_frame,
            columns=("timestamp", "action", "target", "result", "source"),
            show="headings",
        )
        for column, title, width, anchor in [
            ("timestamp", "Timestamp", 170, "center"),
            ("action", "Action", 140, "w"),
            ("target", "Target", 180, "w"),
            ("result", "Result", 90, "center"),
            ("source", "Source", 100, "center"),
        ]:
            self.audit_tree.heading(column, text=title)
            self.audit_tree.column(column, width=width, anchor=anchor)
        self.audit_tree.grid(row=0, column=0, sticky="nsew")
        self.audit_tree.bind("<<TreeviewSelect>>", self._on_audit_selected)

        audit_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.audit_tree.yview)
        audit_scroll.grid(row=0, column=1, sticky="ns")
        self.audit_tree.configure(yscrollcommand=audit_scroll.set)

        details_card = tk.Frame(split, bg=PALETTE["paper"], padx=18, pady=18)
        details_card.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        tk.Label(
            details_card,
            text="Audit Details",
            bg=PALETTE["paper"],
            fg=PALETTE["ink"],
            font=("Iowan Old Style", 20, "bold"),
        ).pack(anchor="w")
        self.audit_detail_text = ScrolledText(
            details_card,
            wrap="word",
            bg="#FBFAF7",
            fg=PALETTE["text"],
            insertbackground=PALETTE["ink"],
            relief="flat",
            font=("Menlo", 11),
        )
        self.audit_detail_text.pack(fill="both", expand=True, pady=(12, 0))
        self.audit_detail_text.configure(state="disabled")

    def _build_settings_tab(self) -> None:
        container = tk.Frame(self.settings_tab, bg=PALETTE["sand"])
        container.pack(fill="both", expand=True)
        container.columnconfigure(0, weight=1)

        vpn_card = tk.Frame(container, bg=PALETTE["paper"], padx=20, pady=20)
        vpn_card.pack(fill="x", pady=(0, 12))
        vpn_card.columnconfigure(1, weight=1)

        tk.Label(
            vpn_card,
            text=self._t("VPN Settings", "Налаштування VPN"),
            bg=PALETTE["paper"],
            fg=PALETTE["ink"],
            font=("Iowan Old Style", 22, "bold"),
        ).grid(row=0, column=0, columnspan=2, sticky="w")
        tk.Label(
            vpn_card,
            text=self._t(
                "Customize endpoint, interface, subnet, DNS and related parameters. Values are saved into .env.",
                "Налаштовуйте endpoint, інтерфейс, підмережу, DNS та інші параметри. Значення зберігаються в .env.",
            ),
            bg=PALETTE["paper"],
            fg=PALETTE["muted"],
            justify="left",
            wraplength=760,
            font=("Avenir Next", 11),
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(8, 18))

        row_specs = [
            (self._t("Endpoint", "Endpoint"), "endpoint"),
            (self._t("Interface name", "Назва інтерфейсу"), "interface_name"),
            (self._t("Server address", "Адреса сервера"), "server_address"),
            (self._t("Server port", "Порт сервера"), "server_port"),
            (self._t("Public interface", "Публічний інтерфейс"), "public_interface"),
            ("DNS", "dns"),
            (self._t("Client allowed IPs", "Client allowed IPs"), "client_allowed_ips"),
            (self._t("Connected window", "Вікно підключення"), "connected_window_seconds"),
        ]
        for row_index, (label, key) in enumerate(row_specs, start=2):
            tk.Label(
                vpn_card,
                text=label,
                bg=PALETTE["paper"],
                fg=PALETTE["ink"],
                anchor="w",
                font=("Avenir Next", 10, "bold"),
            ).grid(row=row_index, column=0, sticky="w", pady=7, padx=(0, 14))
            entry = ttk.Entry(vpn_card, textvariable=self.settings_vars[key], width=48)
            entry.grid(row=row_index, column=1, sticky="ew", pady=7)
            self.busy_widgets.append(entry)

        tk.Label(
            vpn_card,
            text=self._t("Application language", "Мова застосунку"),
            bg=PALETTE["paper"],
            fg=PALETTE["ink"],
            anchor="w",
            font=("Avenir Next", 10, "bold"),
        ).grid(row=10, column=0, sticky="w", pady=7, padx=(0, 14))
        language_box = ttk.Combobox(
            vpn_card,
            textvariable=self.language_var,
            values=("uk", "en"),
            state="readonly",
            width=10,
        )
        language_box.grid(row=10, column=1, sticky="w", pady=7)
        self.busy_widgets.append(language_box)

        vpn_buttons = tk.Frame(vpn_card, bg=PALETTE["paper"])
        vpn_buttons.grid(row=11, column=0, columnspan=2, sticky="w", pady=(18, 0))
        for label, command in [
            (self._t("Save Settings", "Зберегти налаштування"), self._save_settings),
            (self._t("Reload Settings", "Перезавантажити налаштування"), self._load_settings_form),
            (self._t("Apply Language", "Застосувати мову"), self._apply_language_selection),
            (self._t("Open .env", "Відкрити .env"), lambda: self._open_path(self.manager.config.project_root / ".env")),
        ]:
            button = ttk.Button(vpn_buttons, text=label, command=command, style="Accent.TButton")
            button.pack(side="left", padx=(0, 10))
            self.busy_widgets.append(button)

        remote_card = tk.Frame(container, bg=PALETTE["paper"], padx=20, pady=20)
        remote_card.pack(fill="both", expand=True)

        tk.Label(
            remote_card,
            text=self._t("Remote SSH Profile", "Remote SSH профіль"),
            bg=PALETTE["paper"],
            fg=PALETTE["ink"],
            font=("Iowan Old Style", 22, "bold"),
        ).pack(anchor="w")
        tk.Label(
            remote_card,
            textvariable=self.remote_summary_var,
            bg=PALETTE["paper"],
            fg=PALETTE["muted"],
            justify="left",
            wraplength=920,
            font=("Avenir Next", 11),
        ).pack(anchor="w", pady=(10, 18))

        remote_buttons = tk.Frame(remote_card, bg=PALETTE["paper"])
        remote_buttons.pack(anchor="w")
        for label, command, style in [
            (self._t("Connect to Server", "Підключитися до сервера"), self._open_remote_profile_dialog, "Accent.TButton"),
            (self._t("Test Connection", "Перевірити зʼєднання"), self._test_remote_profile, "Accent.TButton"),
            (self._t("Clear Remote Profile", "Очистити remote-профіль"), self._clear_remote_profile, "Danger.TButton"),
        ]:
            button = ttk.Button(remote_buttons, text=label, command=command, style=style)
            button.pack(side="left", padx=(0, 10))
            self.busy_widgets.append(button)

    def _build_status_bar(self, parent: tk.Frame) -> None:
        status_bar = tk.Frame(parent, bg=PALETTE["ink"], height=38)
        status_bar.grid(row=1, column=0, columnspan=2, sticky="ew")
        tk.Label(
            status_bar,
            textvariable=self.status_var,
            bg=PALETTE["ink"],
            fg=PALETTE["paper"],
            anchor="w",
            padx=18,
            font=("Avenir Next", 10, "bold"),
        ).pack(fill="both")

    def _draw_logo_mark(self, canvas: tk.Canvas) -> None:
        canvas.create_oval(18, 18, 92, 92, fill=PALETTE["amber"], outline="")
        canvas.create_polygon(
            58,
            22,
            102,
            38,
            102,
            72,
            58,
            94,
            14,
            72,
            14,
            38,
            fill=PALETTE["teal"],
            outline="",
        )
        canvas.create_oval(34, 40, 82, 88, fill=PALETTE["paper"], outline="")
        canvas.create_oval(44, 50, 72, 78, fill=PALETTE["ink"], outline="")
        canvas.create_line(58, 16, 58, 34, fill=PALETTE["paper"], width=5, capstyle="round")
        canvas.create_line(82, 58, 124, 58, fill=PALETTE["paper"], width=5, capstyle="round")
        canvas.create_text(
            154,
            45,
            text="WG",
            fill=PALETTE["paper"],
            font=("Iowan Old Style", 28, "bold"),
        )
        canvas.create_text(
            154,
            75,
            text="DESKTOP",
            fill="#AFC3D6",
            font=("Avenir Next", 11, "bold"),
        )

    def _run_task(
        self,
        label: str,
        task: Callable[[], object | None],
        *,
        success_message: str | None = None,
        on_success: Callable[[object | None], None] | None = None,
    ) -> None:
        """Run manager operations in a worker thread so the UI stays responsive."""

        self._set_busy(True)
        self.status_var.set(f"{label}...")

        def worker() -> None:
            try:
                result = task()
            except VPNManagerError as exc:
                self.task_queue.put(("error", str(exc), None, None))
            except Exception as exc:  # pragma: no cover - defensive UI guard
                self.task_queue.put(("error", str(exc), None, None))
            else:
                self.task_queue.put(
                    ("success", success_message or f"{label} completed.", result, on_success)
                )

        threading.Thread(target=worker, daemon=True).start()

    def _poll_task_queue(self) -> None:
        try:
            while True:
                status, message, result, callback = self.task_queue.get_nowait()
                self._set_busy(False)
                self.status_var.set(message)

                if status == "error":
                    messagebox.showerror("WireGuard Control Room", message, parent=self)
                else:
                    self._refresh_all()
                    if callback is not None:
                        try:
                            callback(result)
                        except VPNManagerError as exc:
                            messagebox.showerror("WireGuard Control Room", str(exc), parent=self)
                        except Exception as exc:  # pragma: no cover - defensive UI guard
                            messagebox.showerror("WireGuard Control Room", str(exc), parent=self)
        except queue.Empty:
            pass

        self.after(160, self._poll_task_queue)

    def _set_busy(self, busy: bool) -> None:
        state = "disabled" if busy else "normal"
        for widget in self.busy_widgets:
            try:
                widget_state = state
                if not busy and widget in self.control_widgets and not self.manager.can_control_vpn():
                    widget_state = "disabled"
                widget.configure(state=widget_state)
            except tk.TclError:
                continue

    def _refresh_control_capabilities(self) -> None:
        self._set_busy(False)
        if self.manager.can_control_vpn():
            self.status_var.set(f"Control target ready: {self.manager.control_target_summary()}")
            return
        self.status_var.set(
            "Local runtime control is unavailable on this host. Configure a remote Ubuntu server over SSH or work from Ubuntu locally."
        )

    def _maybe_open_first_run_wizard(self) -> None:
        if not self.manager.needs_first_run_wizard():
            return
        if not messagebox.askyesno(
            "First-run setup",
            "This project still uses placeholder VPN settings.\n\nOpen the setup wizard now?",
            parent=self,
        ):
            return
        self._open_first_run_wizard()

    def _open_first_run_wizard(self) -> None:
        dialog = tk.Toplevel(self)
        dialog.title("First-run Setup Wizard")
        dialog.configure(bg=PALETTE["paper"])
        dialog.transient(self)
        dialog.grab_set()
        dialog.geometry("760x760")
        dialog.columnconfigure(1, weight=1)

        current = editable_settings_from_config(self.manager.config)
        vpn_vars = {
            "endpoint": tk.StringVar(value=current.endpoint),
            "interface_name": tk.StringVar(value=current.interface_name),
            "server_address": tk.StringVar(value=current.server_address),
            "server_port": tk.StringVar(value=str(current.server_port)),
            "public_interface": tk.StringVar(value=current.public_interface),
            "dns": tk.StringVar(value=current.dns),
            "client_allowed_ips": tk.StringVar(value=current.client_allowed_ips),
            "connected_window_seconds": tk.StringVar(value=str(current.connected_window_seconds)),
        }
        profile = self.manager.remote_profile
        remote_vars = {
            "enable_remote": tk.BooleanVar(value=profile is not None),
            "host": tk.StringVar(value=profile.host if profile else ""),
            "username": tk.StringVar(value=profile.username if profile else ""),
            "port": tk.StringVar(value=str(profile.port if profile else 22)),
            "auth_method": tk.StringVar(value=(profile.auth_method.value if profile else AuthMethod.SSH_KEY.value)),
            "private_key_path": tk.StringVar(value=profile.private_key_path if profile and profile.private_key_path else str(Path.home() / ".ssh" / "id_ed25519")),
            "password": tk.StringVar(value=""),
            "sudo_password": tk.StringVar(value=""),
            "fingerprint": tk.StringVar(value=profile.known_host_fingerprint if profile and profile.known_host_fingerprint else ""),
            "use_sudo": tk.BooleanVar(value=True if profile is None else profile.use_sudo),
        }

        tk.Label(
            dialog,
            text="First-run Setup Wizard",
            bg=PALETTE["paper"],
            fg=PALETTE["ink"],
            font=("Iowan Old Style", 24, "bold"),
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=24, pady=(24, 8))
        tk.Label(
            dialog,
            text="Define the WireGuard server settings and optionally attach a remote Ubuntu server over SSH.",
            bg=PALETTE["paper"],
            fg=PALETTE["muted"],
            justify="left",
            wraplength=680,
            font=("Avenir Next", 11),
        ).grid(row=1, column=0, columnspan=2, sticky="w", padx=24, pady=(0, 18))

        row = 2
        for title, key in [
            ("Endpoint", "endpoint"),
            ("Interface name", "interface_name"),
            ("Server address", "server_address"),
            ("Server port", "server_port"),
            ("Public interface", "public_interface"),
            ("DNS", "dns"),
            ("Client allowed IPs", "client_allowed_ips"),
            ("Connected window", "connected_window_seconds"),
        ]:
            tk.Label(dialog, text=title, bg=PALETTE["paper"], fg=PALETTE["ink"], font=("Avenir Next", 10, "bold")).grid(
                row=row, column=0, sticky="w", padx=24, pady=6
            )
            ttk.Entry(dialog, textvariable=vpn_vars[key], width=48).grid(
                row=row, column=1, sticky="ew", padx=(0, 24), pady=6
            )
            row += 1

        remote_card = tk.LabelFrame(dialog, text="Remote SSH (optional)", bg=PALETTE["paper"], fg=PALETTE["ink"], padx=16, pady=14)
        remote_card.grid(row=row, column=0, columnspan=2, sticky="ew", padx=24, pady=(18, 0))
        remote_card.columnconfigure(1, weight=1)
        row += 1

        ttk.Checkbutton(remote_card, text="Enable remote Ubuntu management", variable=remote_vars["enable_remote"]).grid(
            row=0, column=0, columnspan=2, sticky="w"
        )
        remote_fields = [
            ("Host", "host"),
            ("Username", "username"),
            ("Port", "port"),
            ("Auth method", "auth_method"),
            ("Private key path", "private_key_path"),
            ("Password", "password"),
            ("Sudo password", "sudo_password"),
            ("Fingerprint", "fingerprint"),
        ]
        for field_row, (title, key) in enumerate(remote_fields, start=1):
            tk.Label(remote_card, text=title, bg=PALETTE["paper"], fg=PALETTE["ink"], font=("Avenir Next", 10, "bold")).grid(
                row=field_row, column=0, sticky="w", pady=5
            )
            if key == "auth_method":
                widget = ttk.Combobox(
                    remote_card,
                    textvariable=remote_vars[key],
                    values=(AuthMethod.SSH_KEY.value, AuthMethod.PASSWORD.value),
                    state="readonly",
                    width=28,
                )
            else:
                widget = ttk.Entry(remote_card, textvariable=remote_vars[key], width=44, show="*" if "password" in key else "")
            widget.grid(row=field_row, column=1, sticky="ew", pady=5, padx=(10, 0))

        ttk.Checkbutton(remote_card, text="Use sudo on remote host", variable=remote_vars["use_sudo"]).grid(
            row=len(remote_fields) + 1,
            column=0,
            columnspan=2,
            sticky="w",
            pady=(6, 0),
        )

        def save_wizard(*, test_remote_after_save: bool) -> None:
            try:
                new_config = save_editable_settings(
                    self.manager.config.project_root,
                    EditableVPNSettings(
                        endpoint=vpn_vars["endpoint"].get().strip(),
                        interface_name=vpn_vars["interface_name"].get().strip(),
                        server_address=vpn_vars["server_address"].get().strip(),
                        server_port=int(vpn_vars["server_port"].get().strip()),
                        public_interface=vpn_vars["public_interface"].get().strip(),
                        dns=vpn_vars["dns"].get().strip(),
                        client_allowed_ips=vpn_vars["client_allowed_ips"].get().strip(),
                        connected_window_seconds=int(vpn_vars["connected_window_seconds"].get().strip()),
                    ),
                )
                self.manager.update_config(new_config)

                if remote_vars["enable_remote"].get():
                    self.manager.save_remote_profile(
                        host=remote_vars["host"].get().strip(),
                        username=remote_vars["username"].get().strip(),
                        port=int(remote_vars["port"].get().strip() or "22"),
                        auth_method=AuthMethod(remote_vars["auth_method"].get()),
                        private_key_path=remote_vars["private_key_path"].get().strip() or None,
                        password=remote_vars["password"].get().strip() or None,
                        sudo_password=remote_vars["sudo_password"].get().strip() or None,
                        known_host_fingerprint=remote_vars["fingerprint"].get().strip() or None,
                        use_sudo=remote_vars["use_sudo"].get(),
                    )
                    if test_remote_after_save:
                        payload = self.manager.test_remote_connection()
                        messagebox.showinfo(
                            "Remote connection",
                            f"Remote agent reachable.\n\nService state: {payload.get('service_state', 'unknown')}",
                            parent=dialog,
                        )
                self._load_settings_form()
                self._refresh_all()
                self._refresh_control_capabilities()
                dialog.destroy()
            except (ValueError, VPNManagerError) as exc:
                messagebox.showerror("Setup wizard", str(exc), parent=dialog)

        buttons = tk.Frame(dialog, bg=PALETTE["paper"])
        buttons.grid(row=row, column=0, columnspan=2, sticky="e", padx=24, pady=24)
        ttk.Button(
            buttons,
            text="Save",
            command=lambda: save_wizard(test_remote_after_save=False),
            style="Accent.TButton",
        ).pack(side="left", padx=(0, 10))
        ttk.Button(
            buttons,
            text="Save & Test Remote",
            command=lambda: save_wizard(test_remote_after_save=True),
            style="Accent.TButton",
        ).pack(side="left", padx=(0, 10))
        ttk.Button(buttons, text="Cancel", command=dialog.destroy, style="Danger.TButton").pack(side="left")

        dialog.wait_window()

    def _open_remote_profile_dialog(self) -> None:
        dialog = tk.Toplevel(self)
        dialog.title("Connect to Server")
        dialog.configure(bg=PALETTE["paper"])
        dialog.transient(self)
        dialog.grab_set()
        dialog.geometry("700x600")
        dialog.columnconfigure(1, weight=1)

        profile = self.manager.remote_profile
        vars_map = {
            "host": tk.StringVar(value=profile.host if profile else ""),
            "username": tk.StringVar(value=profile.username if profile else ""),
            "port": tk.StringVar(value=str(profile.port if profile else 22)),
            "auth_method": tk.StringVar(value=(profile.auth_method.value if profile else AuthMethod.SSH_KEY.value)),
            "private_key_path": tk.StringVar(value=profile.private_key_path if profile and profile.private_key_path else str(Path.home() / ".ssh" / "id_ed25519")),
            "password": tk.StringVar(value=""),
            "sudo_password": tk.StringVar(value=""),
            "fingerprint": tk.StringVar(value=profile.known_host_fingerprint if profile and profile.known_host_fingerprint else ""),
            "use_sudo": tk.BooleanVar(value=True if profile is None else profile.use_sudo),
            "profile_name": tk.StringVar(value=profile.name if profile else "default"),
        }

        tk.Label(
            dialog,
            text="Connect to Server",
            bg=PALETTE["paper"],
            fg=PALETTE["ink"],
            font=("Iowan Old Style", 24, "bold"),
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=24, pady=(24, 8))
        tk.Label(
            dialog,
            text="Save an SSH profile for a remote Ubuntu WireGuard server. Credentials are stored in the secret store, not SQLite.",
            bg=PALETTE["paper"],
            fg=PALETTE["muted"],
            justify="left",
            wraplength=620,
            font=("Avenir Next", 11),
        ).grid(row=1, column=0, columnspan=2, sticky="w", padx=24, pady=(0, 18))

        row_specs = [
            ("Profile name", "profile_name"),
            ("Host", "host"),
            ("Username", "username"),
            ("Port", "port"),
            ("Auth method", "auth_method"),
            ("Private key path", "private_key_path"),
            ("Password", "password"),
            ("Sudo password", "sudo_password"),
            ("Fingerprint", "fingerprint"),
        ]
        widgets: dict[str, tk.Widget] = {}
        for row_index, (title, key) in enumerate(row_specs, start=2):
            tk.Label(
                dialog,
                text=title,
                bg=PALETTE["paper"],
                fg=PALETTE["ink"],
                font=("Avenir Next", 10, "bold"),
            ).grid(row=row_index, column=0, sticky="w", padx=24, pady=7)
            if key == "auth_method":
                widget: tk.Widget = ttk.Combobox(
                    dialog,
                    textvariable=vars_map[key],
                    values=(AuthMethod.SSH_KEY.value, AuthMethod.PASSWORD.value),
                    state="readonly",
                    width=28,
                )
            else:
                widget = ttk.Entry(
                    dialog,
                    textvariable=vars_map[key],
                    width=46,
                    show="*" if "password" in key else "",
                )
            widget.grid(row=row_index, column=1, sticky="ew", padx=(0, 24), pady=7)
            widgets[key] = widget

        ttk.Checkbutton(dialog, text="Use sudo on remote host", variable=vars_map["use_sudo"]).grid(
            row=11, column=0, columnspan=2, sticky="w", padx=24, pady=(8, 0)
        )

        def update_auth_fields(*_args: object) -> None:
            auth_method = vars_map["auth_method"].get()
            widgets["private_key_path"].configure(
                state="normal" if auth_method == AuthMethod.SSH_KEY.value else "disabled"
            )
            widgets["password"].configure(
                state="normal" if auth_method == AuthMethod.PASSWORD.value else "disabled"
            )

        vars_map["auth_method"].trace_add("write", update_auth_fields)
        update_auth_fields()

        def save_profile(*, test_after_save: bool) -> None:
            try:
                self.manager.save_remote_profile(
                    host=vars_map["host"].get().strip(),
                    username=vars_map["username"].get().strip(),
                    port=int(vars_map["port"].get().strip() or "22"),
                    auth_method=AuthMethod(vars_map["auth_method"].get()),
                    private_key_path=vars_map["private_key_path"].get().strip() or None,
                    password=vars_map["password"].get().strip() or None,
                    sudo_password=vars_map["sudo_password"].get().strip() or None,
                    known_host_fingerprint=vars_map["fingerprint"].get().strip() or None,
                    use_sudo=vars_map["use_sudo"].get(),
                    profile_name=vars_map["profile_name"].get().strip() or "default",
                )
                if test_after_save:
                    payload = self.manager.test_remote_connection()
                    messagebox.showinfo(
                        "Remote connection",
                        f"Connected successfully.\n\nService state: {payload.get('service_state', 'unknown')}",
                        parent=dialog,
                    )
                self._refresh_all()
                self._refresh_control_capabilities()
                dialog.destroy()
            except (ValueError, VPNManagerError) as exc:
                messagebox.showerror("Connect to server", str(exc), parent=dialog)

        button_row = tk.Frame(dialog, bg=PALETTE["paper"])
        button_row.grid(row=12, column=0, columnspan=2, sticky="e", padx=24, pady=24)
        ttk.Button(button_row, text="Save", command=lambda: save_profile(test_after_save=False), style="Accent.TButton").pack(
            side="left", padx=(0, 10)
        )
        ttk.Button(
            button_row,
            text="Save & Test",
            command=lambda: save_profile(test_after_save=True),
            style="Accent.TButton",
        ).pack(side="left", padx=(0, 10))
        ttk.Button(button_row, text="Cancel", command=dialog.destroy, style="Danger.TButton").pack(side="left")

        dialog.wait_window()

    def _submit_add_client(self) -> None:
        client_name = self.add_client_vars["name"].get().strip()
        if not client_name:
            messagebox.showwarning(
                "Client name required",
                "Enter a client name before creating a configuration.",
                parent=self,
            )
            return

        self._run_task(
            f"Adding client {client_name}",
            lambda: self.manager.add_client(
                client_name,
                email=self.add_client_vars["email"].get().strip() or None,
                device=self.add_client_vars["device"].get().strip() or None,
                comment=self.add_client_vars["comment"].get().strip() or None,
                expiry_at=self.add_client_vars["expiry_at"].get().strip() or None,
            ),
            success_message=f"Client '{client_name}' created.",
            on_success=lambda result: self._after_client_created(result),
        )

    def _after_client_created(self, result: object | None) -> None:
        for variable in self.add_client_vars.values():
            variable.set("")
        if isinstance(result, ClientRecord):
            self._open_client_export_dialog(result)

    def _selected_client_name(self) -> str | None:
        selection = self.clients_tree.selection()
        if not selection:
            return None
        return selection[0]

    def _selected_client(self) -> ClientRecord | None:
        name = self._selected_client_name()
        if name is None:
            return None
        return self.client_rows.get(name)

    def _ensure_selected_client(self) -> ClientRecord | None:
        client = self._selected_client()
        if client is None:
            messagebox.showinfo("No selection", "Select a client in the table first.", parent=self)
            return None
        return client

    def _remove_selected_client(self) -> None:
        client = self._ensure_selected_client()
        if client is None:
            return
        if not messagebox.askyesno(
            "Remove client",
            f"Delete client '{client.name}' and remove its generated files?",
            parent=self,
        ):
            return
        self._run_task(
            f"Removing client {client.name}",
            lambda: self.manager.remove_client(client.name),
            success_message=f"Client '{client.name}' removed.",
        )

    def _disable_selected_client(self) -> None:
        client = self._ensure_selected_client()
        if client is None:
            return
        self._run_task(
            f"Disabling client {client.name}",
            lambda: self.manager.disable_client(client.name),
            success_message=f"Client '{client.name}' disabled.",
        )

    def _enable_selected_client(self) -> None:
        client = self._ensure_selected_client()
        if client is None:
            return
        self._run_task(
            f"Enabling client {client.name}",
            lambda: self.manager.enable_client(client.name),
            success_message=f"Client '{client.name}' enabled.",
        )

    def _open_client_details_dialog(self) -> None:
        client = self._ensure_selected_client()
        if client is None:
            return

        dialog = tk.Toplevel(self)
        dialog.title(f"Client Details: {client.name}")
        dialog.configure(bg=PALETTE["paper"])
        dialog.transient(self)
        dialog.grab_set()
        dialog.geometry("720x580")
        dialog.columnconfigure(1, weight=1)

        refreshed = self.manager.storage.get_client(client.name) or client
        email_var = tk.StringVar(value=refreshed.email or "")
        device_var = tk.StringVar(value=refreshed.device or "")
        comment_var = tk.StringVar(value=refreshed.comment or "")
        expiry_var = tk.StringVar(value=refreshed.expiry_at or "")
        status_var = tk.StringVar(value=refreshed.status.value)

        tk.Label(
            dialog,
            text=refreshed.name,
            bg=PALETTE["paper"],
            fg=PALETTE["ink"],
            font=("Iowan Old Style", 24, "bold"),
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=24, pady=(24, 8))

        info_lines = [
            ("Address", refreshed.address),
            ("Status", status_var.get()),
            ("Created", format_iso_datetime(refreshed.created_at)),
            ("Updated", format_iso_datetime(refreshed.updated_at)),
            ("Last used", format_iso_datetime(refreshed.last_used_at)),
            ("Config", refreshed.config_path or "Not exported"),
            ("QR code", refreshed.qr_code_path or "Not exported"),
        ]
        for row_index, (title, value) in enumerate(info_lines, start=1):
            tk.Label(
                dialog,
                text=title,
                bg=PALETTE["paper"],
                fg=PALETTE["muted"],
                font=("Avenir Next", 10, "bold"),
            ).grid(row=row_index, column=0, sticky="w", padx=24, pady=6)
            tk.Label(
                dialog,
                text=value,
                bg=PALETTE["paper"],
                fg=PALETTE["text"],
                justify="left",
                wraplength=460,
                anchor="w",
                font=("Avenir Next", 10),
            ).grid(row=row_index, column=1, sticky="w", padx=(0, 24), pady=6)

        form_start = len(info_lines) + 1
        for row_index, (title, variable) in enumerate(
            [
                ("Email", email_var),
                ("Device", device_var),
                ("Comment", comment_var),
                ("Expiry ISO", expiry_var),
            ],
            start=form_start,
        ):
            tk.Label(
                dialog,
                text=title,
                bg=PALETTE["paper"],
                fg=PALETTE["ink"],
                font=("Avenir Next", 10, "bold"),
            ).grid(row=row_index, column=0, sticky="w", padx=24, pady=6)
            ttk.Entry(dialog, textvariable=variable, width=52).grid(
                row=row_index, column=1, sticky="ew", padx=(0, 24), pady=6
            )

        def save_metadata() -> None:
            try:
                updated = self.manager.update_client_metadata(
                    refreshed.name,
                    email=email_var.get().strip() or None,
                    device=device_var.get().strip() or None,
                    comment=comment_var.get().strip() or None,
                    expiry_at=expiry_var.get().strip() or None,
                )
            except VPNManagerError as exc:
                messagebox.showerror("Client metadata", str(exc), parent=dialog)
                return
            status_var.set(updated.status.value)
            self._refresh_all()
            messagebox.showinfo(
                "Client metadata",
                f"Metadata for '{updated.name}' was updated.",
                parent=dialog,
            )

        action_row = tk.Frame(dialog, bg=PALETTE["paper"])
        action_row.grid(row=form_start + 4, column=0, columnspan=2, sticky="w", padx=24, pady=24)
        for label, command, style in [
            ("Save Metadata", save_metadata, "Accent.TButton"),
            ("Open Export", lambda: self._open_client_export_dialog(refreshed), "Accent.TButton"),
            ("Disable", lambda: self._run_task(f"Disabling client {refreshed.name}", lambda: self.manager.disable_client(refreshed.name)), "Danger.TButton"),
            ("Enable", lambda: self._run_task(f"Enabling client {refreshed.name}", lambda: self.manager.enable_client(refreshed.name)), "Accent.TButton"),
            ("Remove", lambda: (dialog.destroy(), self._remove_selected_client()), "Danger.TButton"),
        ]:
            ttk.Button(action_row, text=label, command=command, style=style).pack(side="left", padx=(0, 10))

        dialog.wait_window()

    def _open_selected_client_export(self) -> None:
        client = self._ensure_selected_client()
        if client is None:
            return
        self._open_client_export_dialog(client)

    def _open_client_export_dialog(self, client: ClientRecord) -> None:
        dialog = tk.Toplevel(self)
        dialog.title(f"Client Export: {client.name}")
        dialog.configure(bg=PALETTE["paper"])
        dialog.transient(self)
        dialog.geometry("980x720")

        dialog.columnconfigure(0, weight=1)
        dialog.columnconfigure(1, weight=1)
        dialog.rowconfigure(1, weight=1)

        tk.Label(
            dialog,
            text=f"Client Export: {client.name}",
            bg=PALETTE["paper"],
            fg=PALETTE["ink"],
            font=("Iowan Old Style", 24, "bold"),
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=24, pady=(24, 8))

        left = tk.Frame(dialog, bg=PALETTE["paper"], padx=24, pady=12)
        left.grid(row=1, column=0, sticky="nsew")
        right = tk.Frame(dialog, bg=PALETTE["paper"], padx=24, pady=12)
        right.grid(row=1, column=1, sticky="nsew")

        config_text_box = ScrolledText(
            left,
            wrap="word",
            bg="#FBFAF7",
            fg=PALETTE["text"],
            insertbackground=PALETTE["ink"],
            relief="flat",
            font=("Menlo", 11),
        )
        config_text_box.pack(fill="both", expand=True)

        config_text = ""
        try:
            config_text = self.manager.get_client_config_text(client.name)
        except VPNManagerError as exc:
            config_text = str(exc)
        config_text_box.insert("1.0", config_text)
        config_text_box.configure(state="disabled")

        tk.Label(
            right,
            text="QR Export",
            bg=PALETTE["paper"],
            fg=PALETTE["ink"],
            font=("Iowan Old Style", 20, "bold"),
        ).pack(anchor="w")

        qr_path = Path(client.qr_code_path) if client.qr_code_path else None
        qr_frame = tk.Frame(right, bg=PALETTE["paper"])
        qr_frame.pack(fill="both", expand=True, pady=(12, 12))
        if qr_path is not None and qr_path.exists():
            try:
                image = tk.PhotoImage(file=str(qr_path))
                self.qr_image_refs.append(image)
                qr_label = tk.Label(qr_frame, image=image, bg=PALETTE["paper"])
                qr_label.image = image
                qr_label.pack(anchor="center", pady=(0, 12))
            except tk.TclError:
                tk.Label(
                    qr_frame,
                    text=f"QR code image exists but could not be rendered.\n{qr_path}",
                    bg=PALETTE["paper"],
                    fg=PALETTE["muted"],
                    justify="left",
                    font=("Avenir Next", 11),
                ).pack(anchor="w")
        else:
            tk.Label(
                qr_frame,
                text="No QR export is available for this client yet.\nImported peers need re-issue before QR export.",
                bg=PALETTE["paper"],
                fg=PALETTE["muted"],
                justify="left",
                font=("Avenir Next", 11),
            ).pack(anchor="w")

        buttons = tk.Frame(right, bg=PALETTE["paper"])
        buttons.pack(anchor="w", pady=(0, 12))

        def save_config_copy() -> None:
            if not config_text.strip():
                return
            destination = filedialog.asksaveasfilename(
                parent=dialog,
                title="Save WireGuard config",
                defaultextension=".conf",
                initialfile=f"{client.name}.conf",
                filetypes=[("WireGuard config", "*.conf"), ("All files", "*.*")],
            )
            if destination:
                Path(destination).write_text(config_text, encoding="utf-8")
                self.status_var.set(f"Saved config to {destination}")

        def save_qr_copy() -> None:
            if qr_path is None or not qr_path.exists():
                messagebox.showerror("QR export", "QR file does not exist.", parent=dialog)
                return
            destination = filedialog.asksaveasfilename(
                parent=dialog,
                title="Save QR image",
                defaultextension=".png",
                initialfile=f"{client.name}.png",
                filetypes=[("PNG image", "*.png"), ("All files", "*.*")],
            )
            if destination:
                shutil.copy2(qr_path, destination)
                self.status_var.set(f"Saved QR image to {destination}")

        for label, command, style in [
            ("Copy Config", lambda: self._copy_to_clipboard(config_text), "Accent.TButton"),
            ("Save .conf", save_config_copy, "Accent.TButton"),
            ("Save QR as PNG", save_qr_copy, "Accent.TButton"),
            ("Open Config", lambda: self._open_path(Path(client.config_path)) if client.config_path else None, "Accent.TButton"),
            ("Open QR", lambda: self._open_path(qr_path) if qr_path else None, "Accent.TButton"),
        ]:
            ttk.Button(buttons, text=label, command=command, style=style).pack(side="left", padx=(0, 10), pady=4)

    def _copy_to_clipboard(self, text: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update_idletasks()
        self.status_var.set("Copied config to clipboard.")

    def _refresh_location_info(self) -> None:
        detect_host_location.cache_clear()
        self.host_location = detect_host_location()
        self._refresh_all()
        self.status_var.set("Location data refreshed.")

    def _open_system_info_dialog(self) -> None:
        dialog = tk.Toplevel(self)
        dialog.title("System Info")
        dialog.configure(bg=PALETTE["paper"])
        dialog.transient(self)
        dialog.geometry("860x640")

        tk.Label(
            dialog,
            text="System Info",
            bg=PALETTE["paper"],
            fg=PALETTE["ink"],
            font=("Iowan Old Style", 24, "bold"),
        ).pack(anchor="w", padx=24, pady=(24, 8))
        tk.Label(
            dialog,
            text="Best-effort host diagnostics. Location is determined from public IP geolocation and is approximate unless the provider can resolve it more precisely.",
            bg=PALETTE["paper"],
            fg=PALETTE["muted"],
            justify="left",
            wraplength=780,
            font=("Avenir Next", 11),
        ).pack(anchor="w", padx=24, pady=(0, 12))

        text_box = ScrolledText(
            dialog,
            wrap="word",
            bg="#FBFAF7",
            fg=PALETTE["text"],
            insertbackground=PALETTE["ink"],
            relief="flat",
            font=("Menlo", 11),
        )
        text_box.pack(fill="both", expand=True, padx=24, pady=(0, 24))
        text_box.insert(
            "1.0",
            "\n".join(
                [
                    f"Host OS          : {self.host_platform.display_name}",
                    f"System           : {self.host_platform.system}",
                    f"Release          : {self.host_platform.release}",
                    f"Version          : {self.host_platform.version}",
                    f"Architecture     : {self.host_platform.machine}",
                    f"Processor        : {self.host_hardware.cpu_name}",
                    f"RAM              : {format_bytes_binary(self.host_hardware.memory_total_bytes)}",
                    f"Storage          : {format_bytes_binary(self.host_hardware.storage_total_bytes)}",
                    f"CPU cores        : {self._cpu_summary()}",
                    f"GPU cores        : {self._gpu_summary()}",
                    f"Local IP         : {self.local_ip_address or 'Unavailable'}",
                    f"Public IP        : {self.host_location.public_ip or 'Unavailable'}",
                    f"Location         : {self.host_location.summary}",
                    f"Latitude         : {self.host_location.latitude_summary}",
                    f"Longitude        : {self.host_location.longitude_summary}",
                    f"Coordinates      : {self.host_location.coordinates_summary}",
                    f"Timezone         : {self.host_location.timezone or 'Unavailable'}",
                    f"Source           : {self.host_location.source}",
                    f"Lookup status    : {'available' if self.host_location.available else 'unavailable'}",
                    f"Lookup error     : {self.host_location.error or 'None'}",
                    f"VPN endpoint     : {self.manager.config.endpoint}",
                    f"Control target   : {self.manager.control_target_summary()}",
                ]
            ),
        )
        text_box.configure(state="disabled")

        button_row = tk.Frame(dialog, bg=PALETTE["paper"])
        button_row.pack(anchor="e", padx=24, pady=(0, 18))
        ttk.Button(
            button_row,
            text="Refresh Location",
            command=lambda: (dialog.destroy(), self._refresh_location_info(), self._open_system_info_dialog()),
            style="Accent.TButton",
        ).pack(side="left", padx=(0, 10))
        ttk.Button(
            button_row,
            text="Set Server IP",
            command=lambda: (dialog.destroy(), self._open_endpoint_quick_dialog()),
            style="Accent.TButton",
        ).pack(side="left")

    def _open_endpoint_quick_dialog(self) -> None:
        current = editable_settings_from_config(self.manager.config)
        value = simpledialog.askstring(
            "Set VPN Endpoint / Server IP",
            "Enter the server public IP or DNS name for WG_ENDPOINT.\n\nThis changes the VPN server endpoint used in generated client configs. It does not change or spoof your local device IP.",
            initialvalue=current.endpoint,
            parent=self,
        )
        if value is None:
            return

        endpoint = value.strip()
        if not endpoint:
            messagebox.showerror("Set VPN Endpoint", "Server IP / endpoint cannot be empty.", parent=self)
            return

        try:
            updated = EditableVPNSettings(
                endpoint=endpoint,
                interface_name=current.interface_name,
                server_address=current.server_address,
                server_port=current.server_port,
                public_interface=current.public_interface,
                dns=current.dns,
                client_allowed_ips=current.client_allowed_ips,
                connected_window_seconds=current.connected_window_seconds,
            )
            new_config = save_editable_settings(self.manager.config.project_root, updated)
            self.manager.update_config(new_config)
            self._load_settings_form()
            self._refresh_all()
            self.status_var.set(f"VPN endpoint updated to {endpoint}")
        except VPNManagerError as exc:
            messagebox.showerror("Set VPN Endpoint", str(exc), parent=self)

    def _show_validation_results(self) -> None:
        self._run_task(
            "Validating environment",
            self.manager.validate_environment,
            success_message="Validation completed.",
            on_success=lambda result: self._open_validation_dialog(result),
        )

    def _open_validation_dialog(self, result: object | None) -> None:
        issues = [item for item in (result or []) if isinstance(item, ValidationIssue)]
        dialog = tk.Toplevel(self)
        dialog.title("Validation Results")
        dialog.configure(bg=PALETTE["paper"])
        dialog.transient(self)
        dialog.geometry("820x520")

        tk.Label(
            dialog,
            text="Validation Results",
            bg=PALETTE["paper"],
            fg=PALETTE["ink"],
            font=("Iowan Old Style", 24, "bold"),
        ).pack(anchor="w", padx=24, pady=(24, 8))
        text_box = ScrolledText(
            dialog,
            wrap="word",
            bg="#FBFAF7",
            fg=PALETTE["text"],
            insertbackground=PALETTE["ink"],
            relief="flat",
            font=("Menlo", 11),
        )
        text_box.pack(fill="both", expand=True, padx=24, pady=(0, 24))
        if not issues:
            text_box.insert("1.0", "Validation passed with no issues.")
        else:
            text_box.insert(
                "1.0",
                "\n".join(
                    f"[{issue.severity.value}] {issue.code}: {issue.message}"
                    for issue in issues
                ),
            )
        text_box.configure(state="disabled")

    def _prompt_create_backup(self) -> None:
        include_logs = messagebox.askyesno(
            "Create backup",
            "Include the log file in the backup archive?",
            parent=self,
        )
        note = simpledialog.askstring(
            "Backup note",
            "Optional note for this backup:",
            parent=self,
        )
        self._run_task(
            "Creating backup",
            lambda: self.manager.create_backup(note=note or None, include_logs=include_logs),
            success_message="Backup created.",
            on_success=lambda result: self._after_backup_created(result),
        )

    def _after_backup_created(self, result: object | None) -> None:
        if not isinstance(result, BackupRecord):
            return
        messagebox.showinfo(
            "Backup created",
            f"Backup created at:\n{result.archive_path}",
            parent=self,
        )

    def _prompt_restore_backup(self) -> None:
        archive = filedialog.askopenfilename(
            parent=self,
            title="Restore backup",
            initialdir=self.manager.backups_dir,
            filetypes=[("Gzip archive", "*.tar.gz"), ("All files", "*.*")],
        )
        if not archive:
            return
        apply_remote = False
        if self.manager.remote_profile is not None:
            apply_remote = messagebox.askyesno(
                "Apply remote config",
                "If the archive contains remote server config, apply it after restore?",
                parent=self,
            )
        if not messagebox.askyesno(
            "Confirm restore",
            "Restoring will overwrite local project data and first create a pre-restore snapshot. Continue?",
            parent=self,
        ):
            return
        self._run_task(
            "Restoring backup",
            lambda: self.manager.restore_backup(Path(archive), apply_remote=apply_remote),
            success_message="Backup restored.",
        )

    def _selected_backup(self) -> BackupRecord | None:
        selection = self.backups_tree.selection()
        if not selection:
            return None
        return self.backup_rows.get(selection[0])

    def _open_selected_backup(self) -> None:
        backup = self._selected_backup()
        if backup is None:
            messagebox.showinfo("No selection", "Select a backup first.", parent=self)
            return
        self._open_path(Path(backup.archive_path))

    def _restore_selected_backup(self) -> None:
        backup = self._selected_backup()
        if backup is None:
            messagebox.showinfo("No selection", "Select a backup first.", parent=self)
            return
        apply_remote = False
        if self.manager.remote_profile is not None:
            apply_remote = messagebox.askyesno(
                "Apply remote config",
                "If the archive contains remote config, apply it after restore?",
                parent=self,
            )
        if not messagebox.askyesno(
            "Confirm restore",
            f"Restore backup '{Path(backup.archive_path).name}'?\nA pre-restore snapshot will be created first.",
            parent=self,
        ):
            return
        self._run_task(
            "Restoring backup",
            lambda: self.manager.restore_backup(Path(backup.archive_path), apply_remote=apply_remote),
            success_message="Backup restored.",
        )

    def _prompt_import_existing_config(self) -> None:
        if self.manager.remote_profile is not None:
            choice = messagebox.askyesnocancel(
                "Import config",
                "Import from the remote system WireGuard config?\n\nYes: use remote /etc/wireguard config\nNo: choose a local file\nCancel: abort",
                parent=self,
            )
            if choice is None:
                return
            if choice:
                self._run_task(
                    "Importing existing config",
                    lambda: self.manager.import_existing_config(),
                    success_message="Config import completed.",
                    on_success=lambda result: self._after_config_import(result),
                )
                return

        file_path = filedialog.askopenfilename(
            parent=self,
            title="Select a WireGuard config",
            filetypes=[("WireGuard config", "*.conf"), ("All files", "*.*")],
        )
        if not file_path:
            return
        self._run_task(
            "Importing existing config",
            lambda: self.manager.import_existing_config(Path(file_path)),
            success_message="Config import completed.",
            on_success=lambda result: self._after_config_import(result),
        )

    def _after_config_import(self, result: object | None) -> None:
        imported_count = int(result or 0)
        messagebox.showinfo(
            "Config import",
            f"Imported {imported_count} peer(s) from the existing WireGuard config.",
            parent=self,
        )

    def _test_remote_profile(self) -> None:
        if self.manager.remote_profile is None:
            messagebox.showinfo("Remote profile", "No remote SSH profile is configured.", parent=self)
            return
        self._run_task(
            "Testing remote connection",
            self.manager.test_remote_connection,
            success_message="Remote connection is healthy.",
            on_success=lambda result: self._show_remote_test_result(result),
        )

    def _show_remote_test_result(self, result: object | None) -> None:
        payload = result if isinstance(result, dict) else {}
        messagebox.showinfo(
            "Remote connection",
            "\n".join(
                [
                    f"Host: {self.manager.remote_profile.host if self.manager.remote_profile else 'unknown'}",
                    f"Agent: {'reachable' if payload else 'unknown'}",
                    f"Service state: {payload.get('service_state', 'unknown')}",
                    f"Interface: {payload.get('interface_name', self.manager.config.interface_name)}",
                ]
            ),
            parent=self,
        )

    def _clear_remote_profile(self) -> None:
        if self.manager.remote_profile is None:
            messagebox.showinfo("Remote profile", "No remote SSH profile is configured.", parent=self)
            return
        if not messagebox.askyesno(
            "Clear remote profile",
            "Delete the saved remote SSH profile and secret references?",
            parent=self,
        ):
            return
        self.manager.clear_remote_profile()
        self._refresh_all()
        self._refresh_control_capabilities()
        messagebox.showinfo("Remote profile", "Remote SSH profile removed.", parent=self)

    def _open_path(self, path: Path) -> None:
        try:
            open_path_in_system(path)
        except VPNManagerError as exc:
            messagebox.showerror("Open path failed", str(exc), parent=self)

    def _load_settings_form(self) -> None:
        settings = editable_settings_from_config(self.manager.config)
        self.settings_vars["endpoint"].set(settings.endpoint)
        self.settings_vars["interface_name"].set(settings.interface_name)
        self.settings_vars["server_address"].set(settings.server_address)
        self.settings_vars["server_port"].set(str(settings.server_port))
        self.settings_vars["public_interface"].set(settings.public_interface)
        self.settings_vars["dns"].set(settings.dns)
        self.settings_vars["client_allowed_ips"].set(settings.client_allowed_ips)
        self.settings_vars["connected_window_seconds"].set(str(settings.connected_window_seconds))
        self.language_var.set(self.language)

    def _save_settings(self) -> None:
        try:
            settings = EditableVPNSettings(
                endpoint=self.settings_vars["endpoint"].get().strip(),
                interface_name=self.settings_vars["interface_name"].get().strip(),
                server_address=self.settings_vars["server_address"].get().strip(),
                server_port=int(self.settings_vars["server_port"].get().strip()),
                public_interface=self.settings_vars["public_interface"].get().strip(),
                dns=self.settings_vars["dns"].get().strip(),
                client_allowed_ips=self.settings_vars["client_allowed_ips"].get().strip(),
                connected_window_seconds=int(self.settings_vars["connected_window_seconds"].get().strip()),
            )
            new_config = save_editable_settings(self.manager.config.project_root, settings)
            self.manager.update_config(new_config)
            self._load_settings_form()
            self._refresh_all()
            self.status_var.set("VPN settings saved.")
            messagebox.showinfo(
                "Settings saved",
                "VPN settings were saved to .env and applied to the application.",
                parent=self,
            )
        except ValueError:
            messagebox.showerror(
                "Invalid settings",
                "Server port and connected window must be integers.",
                parent=self,
            )
        except VPNManagerError as exc:
            messagebox.showerror("Invalid settings", str(exc), parent=self)

    def _apply_language_selection(self) -> None:
        new_language = save_app_language(
            self.manager.config.project_root,
            self.language_var.get(),
        )
        if new_language == self.language:
            self.status_var.set(
                self._t("Language is already active.", "Ця мова вже активна.")
            )
            return
        self.language = new_language
        self._rebuild_interface()
        self.status_var.set(
            self._t(
                f"Language changed to {LANGUAGE_LABELS[self.language]}.",
                f"Мову змінено на {LANGUAGE_LABELS[self.language]}.",
            )
        )

    def _rebuild_interface(self) -> None:
        self.busy_widgets.clear()
        self.control_widgets.clear()
        self.client_rows.clear()
        self.backup_rows.clear()
        self.audit_rows.clear()
        self.qr_image_refs.clear()
        for child in self.winfo_children():
            child.destroy()
        self.title(self._t("WireGuard Control Room", "Панель керування WireGuard"))
        self._build_styles()
        self._build_shell()
        self._load_settings_form()
        self._refresh_all()
        self._refresh_control_capabilities()

    def _refresh_all(self) -> None:
        self.host_platform = detect_host_platform()
        self.host_location = detect_host_location()
        self.host_hardware = detect_host_hardware()
        self.local_ip_address = detect_local_ip_address()

        clients = self.manager.list_clients_with_status()
        connected_clients, connected_note = self._get_connected_peers()
        service_text = self._service_state_text()
        backups = self.manager.list_backups()
        audits = self.manager.list_audit_logs(limit=200)
        imported_peers = self.manager.storage.list_imported_peers(limit=20)

        self._populate_clients_tree(clients)
        self._populate_connected_tree(connected_clients, connected_note)
        self._populate_backups_tree(backups)
        self._populate_audit_tree(audits)
        self._update_header(clients, connected_clients, service_text)
        self._update_overview(clients, connected_clients, service_text, connected_note)
        self._update_hardware_card()
        self._update_sidebar(service_text)
        self._update_remote_summary()
        self._update_imported_summary(imported_peers)
        self._update_paths()
        self._update_logs()

    def _get_connected_peers(self) -> tuple[list[ConnectedClient], str]:
        if not self.manager.can_control_vpn():
            return [], linux_host_requirement_message("Connected peer lookup")

        try:
            peers = self.manager.get_connected_clients()
        except VPNManagerError as exc:
            return [], f"Connected peer status is unavailable: {exc}"
        return peers, "Peers shown below had a recent WireGuard handshake."

    def _service_state_text(self) -> str:
        if not self.manager.can_control_vpn():
            return "Managed from Ubuntu host"
        try:
            return "Active" if self.manager.is_service_active() else "Stopped"
        except VPNManagerError as exc:
            return f"Unavailable ({exc})"

    def _populate_clients_tree(self, clients: list[tuple[ClientRecord, bool]]) -> None:
        self.client_rows.clear()
        self.clients_tree.delete(*self.clients_tree.get_children())
        for client, is_connected in clients:
            self.client_rows[client.name] = client
            status_text = client.status.value
            if is_connected:
                status_text = f"{status_text} / connected"
            self.clients_tree.insert(
                "",
                "end",
                iid=client.name,
                tags=(client.status.value,),
                values=(
                    client.address,
                    status_text,
                    client.email or "—",
                    client.device or "—",
                    format_iso_datetime(client.expiry_at),
                    format_iso_datetime(client.updated_at),
                ),
            )

    def _populate_connected_tree(self, clients: list[ConnectedClient], note: str) -> None:
        self.connected_tree.delete(*self.connected_tree.get_children())
        self.connected_note_var.set(note)
        for index, client in enumerate(clients, start=1):
            label = client.name or f"Peer {index}"
            self.connected_tree.insert(
                "",
                "end",
                values=(
                    label,
                    client.address or "unknown",
                    client.endpoint,
                    format_unix_timestamp(client.latest_handshake),
                    format_bytes(client.transfer_rx),
                    format_bytes(client.transfer_tx),
                ),
            )

    def _populate_backups_tree(self, backups: list[BackupRecord]) -> None:
        self.backup_rows.clear()
        self.backups_tree.delete(*self.backups_tree.get_children())
        for backup in backups:
            iid = backup.archive_path
            self.backup_rows[iid] = backup
            self.backups_tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    format_iso_datetime(backup.created_at),
                    backup.scope,
                    backup.note or "—",
                ),
            )

    def _populate_audit_tree(self, audits: list[AuditLogRecord]) -> None:
        self.audit_rows.clear()
        self.audit_tree.delete(*self.audit_tree.get_children())
        for entry in audits:
            iid = str(entry.log_id or f"{entry.timestamp}:{entry.action}")
            self.audit_rows[iid] = entry
            self.audit_tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    format_iso_datetime(entry.timestamp),
                    entry.action,
                    entry.target,
                    entry.result,
                    entry.source,
                ),
            )
        self._set_audit_detail_text("Select an audit entry to inspect details.")

    def _on_audit_selected(self, _event: tk.Event[tk.Misc] | None = None) -> None:
        selection = self.audit_tree.selection()
        if not selection:
            self._set_audit_detail_text("Select an audit entry to inspect details.")
            return
        entry = self.audit_rows.get(selection[0])
        if entry is None:
            self._set_audit_detail_text("Audit entry not found.")
            return
        detail_lines = [
            f"Timestamp: {entry.timestamp}",
            f"Action: {entry.action}",
            f"Target: {entry.target}",
            f"Result: {entry.result}",
            f"Actor: {entry.actor}",
            f"Source: {entry.source}",
            "",
            "Details:",
            entry.details,
        ]
        if entry.error_details:
            detail_lines.extend(["", "Error details:", entry.error_details])
        self._set_audit_detail_text("\n".join(detail_lines))

    def _set_audit_detail_text(self, text: str) -> None:
        self.audit_detail_text.configure(state="normal")
        self.audit_detail_text.delete("1.0", "end")
        self.audit_detail_text.insert("1.0", text)
        self.audit_detail_text.configure(state="disabled")

    def _update_header(
        self,
        clients: list[tuple[ClientRecord, bool]],
        connected_clients: list[ConnectedClient],
        service_text: str,
    ) -> None:
        self.hero_status_var.set(f"Service: {service_text}")
        self.hero_counts_var.set(f"Clients: {len(clients)} | Connected: {len(connected_clients)}")
        self.hero_environment_var.set(
            f"{self.host_platform.display_name} {self.host_platform.release} | "
            f"{self.host_platform.machine} | {self.manager.control_target_summary()}"
        )

    def _update_overview(
        self,
        clients: list[tuple[ClientRecord, bool]],
        connected_clients: list[ConnectedClient],
        service_text: str,
        connected_note: str,
    ) -> None:
        endpoint_ready = self.manager.config.endpoint != "your.server.ip.or.dns"
        endpoint_text = self.manager.config.endpoint if endpoint_ready else "Set WG_ENDPOINT in .env"
        self.metric_labels["total_clients"].configure(text=str(len(clients)))
        self.metric_labels["connected_clients"].configure(text=str(len(connected_clients)))
        self.metric_labels["service_state"].configure(text=service_text)
        self.metric_labels["endpoint"].configure(text=endpoint_text)

        self.overview_note_var.set(
            "\n".join(
                [
                    f"Control target: {self.manager.control_target_summary()}",
                    f"Location: {self.host_location.summary} | Public IP: {self.host_location.public_ip or 'Unavailable'}",
                    f"CPU: {self.host_hardware.cpu_name}",
                    f"RAM: {format_bytes_binary(self.host_hardware.memory_total_bytes)} | Storage: {format_bytes_binary(self.host_hardware.storage_total_bytes)}",
                    f"Interface: {self.manager.config.interface_name}",
                    f"Server address: {self.manager.config.server_interface}",
                    f"Public interface: {self.manager.config.public_interface}",
                    connected_note,
                    (
                        "Remote/local runtime control is ready."
                        if self.manager.can_control_vpn()
                        else "No control channel is configured yet. Use the setup wizard or connect a remote Ubuntu host."
                    ),
                ]
            )
        )

    def _update_hardware_card(self) -> None:
        self.location_detail_var.set(
            "Location is determined by public IP geolocation. "
            f"Provider: {self.host_location.source}. "
            + (
                f"Approximate place: {self.host_location.summary}."
                if self.host_location.available
                else f"Lookup unavailable: {self.host_location.error or 'unknown error'}."
            )
        )
        self.hardware_value_labels["host_os"].configure(
            text=f"{self.host_platform.display_name} {self.host_platform.release} | {self.host_platform.machine}"
        )
        self.hardware_value_labels["processor"].configure(text=self.host_hardware.cpu_name)
        self.hardware_value_labels["ram"].configure(
            text=format_bytes_binary(self.host_hardware.memory_total_bytes)
        )
        self.hardware_value_labels["storage"].configure(
            text=format_bytes_binary(self.host_hardware.storage_total_bytes)
        )
        self.hardware_value_labels["cpu_cores"].configure(text=self._cpu_summary())
        self.hardware_value_labels["gpu_cores"].configure(text=self._gpu_summary())
        self.hardware_value_labels["local_ip"].configure(
            text=self.local_ip_address or "Unavailable"
        )
        self.hardware_value_labels["public_ip"].configure(
            text=self.host_location.public_ip or "Unavailable"
        )
        self.hardware_value_labels["coordinates"].configure(
            text=self.host_location.coordinates_summary
        )
        self.hardware_value_labels["timezone"].configure(
            text=self.host_location.timezone or "Unavailable"
        )
        self.hardware_value_labels["location_source"].configure(
            text=self.host_location.source
        )
        self.hardware_value_labels["vpn_endpoint"].configure(
            text=self.manager.config.endpoint
        )

    def _update_sidebar(self, service_text: str) -> None:
        control_summary = "available" if self.manager.can_control_vpn() else "requires Ubuntu local host or SSH remote profile"
        self.sidebar_info.configure(
            text="\n".join(
                [
                    f"Platform: {self.host_platform.display_name}",
                    f"Release: {self.host_platform.release}",
                    f"Architecture: {self.host_platform.machine}",
                    f"Location: {self.host_location.summary}",
                    f"Local IP: {self.local_ip_address or 'Unavailable'}",
                    f"Public IP: {self.host_location.public_ip or 'Unavailable'}",
                    f"Timezone: {self.host_location.timezone or 'Unavailable'}",
                    f"Latitude: {self.host_location.latitude_summary}",
                    f"Longitude: {self.host_location.longitude_summary}",
                    f"CPU: {self.host_hardware.cpu_name}",
                    f"CPU cores: {self._cpu_summary()}",
                    f"GPU cores: {self._gpu_summary()}",
                    f"Root mode: {'yes' if is_root() else 'no'}",
                    f"Control target: {self.manager.control_target_summary()}",
                    f"Interface: {self.manager.config.interface_name}",
                    f"Server subnet: {self.manager.config.network}",
                    f"Listen port: {self.manager.config.server_port}",
                    f"Endpoint: {self.manager.config.endpoint}",
                    f"Service state: {service_text}",
                    f"Control: {control_summary}",
                ]
            )
        )

    def _update_remote_summary(self) -> None:
        profile = self.manager.remote_profile
        if profile is None:
            self.remote_summary_var.set(
                "No remote SSH profile is configured. Use 'Connect to Server' to manage an Ubuntu host from macOS."
            )
            return
        self.remote_summary_var.set(
            "\n".join(
                [
                    f"Profile: {profile.name}",
                    f"Host: {profile.username}@{profile.host}:{profile.port}",
                    f"Auth method: {profile.auth_method.value}",
                    f"Private key: {profile.private_key_path or 'not set'}",
                    f"Use sudo: {'yes' if profile.use_sudo else 'no'}",
                    f"Fingerprint: {profile.known_host_fingerprint or 'not pinned'}",
                    f"Updated: {format_iso_datetime(profile.updated_at)}",
                ]
            )
        )

    def _update_imported_summary(self, imported_peers: list[object]) -> None:
        if not imported_peers:
            self.imported_summary_var.set("Imported peers cache is empty.")
            return
        self.imported_summary_var.set(f"Imported peer records cached: {len(imported_peers)}")

    def _update_paths(self) -> None:
        self.path_labels["configs"].configure(text=str(self.manager.config.configs_dir))
        self.path_labels["data"].configure(text=str(self.manager.config.data_dir))
        self.path_labels["server_config"].configure(text=str(self.manager.config.server_config_path))
        self.path_labels["system_config"].configure(text=str(self.manager.config.system_server_config))
        self.path_labels["log_file"].configure(text=str(self.manager.config.log_path))

    def _update_logs(self) -> None:
        log_tail = read_log_tail(self.manager.config.log_path, lines=80)
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.insert("1.0", log_tail)
        self.log_text.configure(state="disabled")

    def _cpu_summary(self) -> str:
        physical = self.host_hardware.cpu_physical_cores
        logical = self.host_hardware.cpu_logical_cores
        if physical and logical and physical != logical:
            return f"{physical} physical / {logical} logical"
        if logical:
            return str(logical)
        return "Unavailable"

    def _gpu_summary(self) -> str:
        if self.host_hardware.gpu_cores is None:
            return "Unavailable"
        return str(self.host_hardware.gpu_cores)


def run_gui_app(manager: WireGuardManager, *, language: str | None = None) -> None:
    """Start the desktop GUI event loop."""

    resolved_language = language or load_app_language(manager.config.project_root)
    app = VPNDesktopApp(manager, language=resolved_language)
    app.mainloop()
