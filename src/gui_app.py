from __future__ import annotations

import os
import queue
import subprocess
import threading
import tkinter as tk
from datetime import datetime, timezone
from pathlib import Path
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from typing import Callable

from src.config import EditableVPNSettings, editable_settings_from_config, save_editable_settings
from src.models import ClientRecord, ConnectedClient, VPNManagerError
from src.utils import (
    HostPlatformInfo,
    detect_host_platform,
    is_linux,
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


def format_iso_datetime(value: str) -> str:
    """Format stored ISO timestamps for the desktop UI."""

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
    """Desktop UI wrapper around the existing WireGuard manager."""

    def __init__(self, manager: WireGuardManager) -> None:
        super().__init__()
        self.manager = manager
        self.host_platform: HostPlatformInfo = detect_host_platform()
        self.task_queue: queue.Queue[tuple[str, str]] = queue.Queue()
        self.busy_widgets: list[tk.Widget] = []
        self.linux_only_widgets: list[tk.Widget] = []
        self.client_rows: dict[str, ClientRecord] = {}

        self.title("WireGuard Control Room")
        self.geometry("1420x920")
        self.minsize(1180, 760)
        self.configure(bg=PALETTE["sand"])
        self.option_add("*tearOff", False)

        self.status_var = tk.StringVar(value="Ready.")
        self.hero_status_var = tk.StringVar()
        self.hero_counts_var = tk.StringVar()
        self.hero_environment_var = tk.StringVar()
        self.overview_note_var = tk.StringVar()
        self.connected_note_var = tk.StringVar()
        self.client_name_var = tk.StringVar()
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

        self._build_styles()
        self._build_shell()
        self._load_settings_form()
        self._update_platform_capabilities()
        self._refresh_all()
        self.after(160, self._poll_task_queue)

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
            font=("Avenir Next", 11),
        )
        style.configure(
            "Treeview.Heading",
            background=PALETTE["ink"],
            foreground=PALETTE["paper"],
            font=("Avenir Next", 10, "bold"),
            padding=(10, 8),
        )
        style.map(
            "Treeview",
            background=[("selected", PALETTE["mint"])],
            foreground=[("selected", PALETTE["ink"])],
        )

    def _build_shell(self) -> None:
        root = tk.Frame(self, bg=PALETTE["sand"])
        root.pack(fill="both", expand=True)
        root.columnconfigure(1, weight=1)
        root.rowconfigure(0, weight=1)

        sidebar = tk.Frame(root, bg=PALETTE["ink"], width=280)
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
            text="Control Room",
            bg=PALETTE["ink"],
            fg=PALETTE["paper"],
            font=("Iowan Old Style", 24, "bold"),
        ).pack(anchor="w", padx=28)
        tk.Label(
            parent,
            text="Desktop console for your personal WireGuard VPN",
            bg=PALETTE["ink"],
            fg="#B6C2CF",
            wraplength=220,
            justify="left",
            font=("Avenir Next", 11),
        ).pack(anchor="w", padx=28, pady=(6, 24))

        for label, command, style in [
            ("Refresh Dashboard", self._refresh_all, "Sidebar.TButton"),
            ("Install VPN", lambda: self._run_task("Installing VPN", self.manager.install_wireguard), "Sidebar.TButton"),
            ("Start VPN", lambda: self._run_task("Starting VPN", self.manager.start_vpn), "Sidebar.TButton"),
            ("Stop VPN", lambda: self._run_task("Stopping VPN", self.manager.stop_vpn), "Sidebar.TButton"),
            ("Restart VPN", lambda: self._run_task("Restarting VPN", self.manager.restart_vpn), "Sidebar.TButton"),
            ("Open Configs Folder", lambda: self._open_path(self.manager.config.configs_dir), "Sidebar.TButton"),
            ("Open Data Folder", lambda: self._open_path(self.manager.config.data_dir), "Sidebar.TButton"),
        ]:
            button = ttk.Button(parent, text=label, command=command, style=style)
            button.pack(fill="x", padx=24, pady=6)
            self.busy_widgets.append(button)
            if label in {"Install VPN", "Start VPN", "Stop VPN", "Restart VPN"}:
                self.linux_only_widgets.append(button)

        info_card = tk.Frame(parent, bg="#19314F", bd=0, highlightthickness=0)
        info_card.pack(fill="x", padx=24, pady=(28, 0))

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
            text="WireGuard Operations Deck",
            bg=PALETTE["paper"],
            fg=PALETTE["ink"],
            font=("Iowan Old Style", 30, "bold"),
        ).grid(row=0, column=0, sticky="w")
        tk.Label(
            hero,
            text="Visual control panel for installation, client management, runtime state and diagnostics.",
            bg=PALETTE["paper"],
            fg=PALETTE["muted"],
            font=("Avenir Next", 12),
        ).grid(row=1, column=0, sticky="w", pady=(6, 16))

        chips = tk.Frame(hero, bg=PALETTE["paper"])
        chips.grid(row=2, column=0, sticky="ew")

        self.hero_status_label = tk.Label(
            chips,
            textvariable=self.hero_status_var,
            bg=PALETTE["ink"],
            fg=PALETTE["paper"],
            font=("Avenir Next", 11, "bold"),
            padx=14,
            pady=8,
        )
        self.hero_status_label.pack(side="left")

        self.hero_counts_label = tk.Label(
            chips,
            textvariable=self.hero_counts_var,
            bg=PALETTE["mint"],
            fg=PALETTE["ink"],
            font=("Avenir Next", 11, "bold"),
            padx=14,
            pady=8,
        )
        self.hero_counts_label.pack(side="left", padx=(10, 0))

        self.hero_environment_label = tk.Label(
            chips,
            textvariable=self.hero_environment_var,
            bg=PALETTE["amber"],
            fg=PALETTE["ink"],
            font=("Avenir Next", 11, "bold"),
            padx=14,
            pady=8,
        )
        self.hero_environment_label.pack(side="left", padx=(10, 0))

    def _build_notebook(self, parent: tk.Frame) -> None:
        notebook = ttk.Notebook(parent, style="Notebook.TNotebook")
        notebook.grid(row=1, column=0, sticky="nsew")

        self.overview_tab = tk.Frame(notebook, bg=PALETTE["sand"])
        self.clients_tab = tk.Frame(notebook, bg=PALETTE["sand"])
        self.connected_tab = tk.Frame(notebook, bg=PALETTE["sand"])
        self.files_tab = tk.Frame(notebook, bg=PALETTE["sand"])
        self.settings_tab = tk.Frame(notebook, bg=PALETTE["sand"])

        notebook.add(self.overview_tab, text="Overview")
        notebook.add(self.clients_tab, text="Clients")
        notebook.add(self.connected_tab, text="Connected")
        notebook.add(self.files_tab, text="Files & Logs")
        notebook.add(self.settings_tab, text="Settings")

        self._build_overview_tab()
        self._build_clients_tab()
        self._build_connected_tab()
        self._build_files_tab()
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

        for index, (key, label, color) in enumerate(metric_specs):
            card = tk.Frame(metrics_row, bg=color, padx=18, pady=18)
            card.grid(row=0, column=index, sticky="nsew", padx=(0 if index == 0 else 10, 0), pady=(0, 12))
            tk.Label(
                card,
                text=label,
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
        self.overview_note_label = tk.Label(
            notes_card,
            textvariable=self.overview_note_var,
            bg=PALETTE["paper"],
            fg=PALETTE["muted"],
            justify="left",
            wraplength=520,
            font=("Avenir Next", 11),
        )
        self.overview_note_label.pack(anchor="w", pady=(12, 0))

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
            text="Use the action deck to apply the most common VPN operations without opening the terminal.",
            bg=PALETTE["paper"],
            fg=PALETTE["muted"],
            justify="left",
            wraplength=520,
            font=("Avenir Next", 11),
        ).pack(anchor="w", pady=(10, 14))

        button_row = tk.Frame(quick_actions, bg=PALETTE["paper"])
        button_row.pack(anchor="w")

        for label, command, style in [
            ("Install", lambda: self._run_task("Installing VPN", self.manager.install_wireguard), "Accent.TButton"),
            ("Start", lambda: self._run_task("Starting VPN", self.manager.start_vpn), "Accent.TButton"),
            ("Stop", lambda: self._run_task("Stopping VPN", self.manager.stop_vpn), "Danger.TButton"),
            ("Restart", lambda: self._run_task("Restarting VPN", self.manager.restart_vpn), "Accent.TButton"),
        ]:
            button = ttk.Button(button_row, text=label, command=command, style=style)
            button.pack(side="left", padx=(0, 10))
            self.busy_widgets.append(button)
            self.linux_only_widgets.append(button)

    def _build_clients_tab(self) -> None:
        container = tk.Frame(self.clients_tab, bg=PALETTE["sand"])
        container.pack(fill="both", expand=True)
        container.rowconfigure(1, weight=1)
        container.columnconfigure(0, weight=1)

        add_card = tk.Frame(container, bg=PALETTE["paper"], padx=20, pady=18)
        add_card.grid(row=0, column=0, sticky="ew", pady=(0, 12))

        tk.Label(
            add_card,
            text="Add Client",
            bg=PALETTE["paper"],
            fg=PALETTE["ink"],
            font=("Iowan Old Style", 20, "bold"),
        ).pack(anchor="w")
        tk.Label(
            add_card,
            text="Create a new WireGuard client, generate keys, and build a ready-to-use .conf file.",
            bg=PALETTE["paper"],
            fg=PALETTE["muted"],
            font=("Avenir Next", 11),
        ).pack(anchor="w", pady=(8, 14))

        form_row = tk.Frame(add_card, bg=PALETTE["paper"])
        form_row.pack(fill="x")
        self.client_name_entry = ttk.Entry(form_row, textvariable=self.client_name_var, width=34)
        self.client_name_entry.pack(side="left", padx=(0, 12))
        self.busy_widgets.append(self.client_name_entry)

        add_button = ttk.Button(
            form_row,
            text="Add Client",
            command=self._submit_add_client,
            style="Accent.TButton",
        )
        add_button.pack(side="left")
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
            columns=("address", "status", "created", "config"),
            show="headings",
        )
        self.clients_tree.heading("address", text="Address")
        self.clients_tree.heading("status", text="Status")
        self.clients_tree.heading("created", text="Created")
        self.clients_tree.heading("config", text="Config")
        self.clients_tree.column("address", width=140, anchor="center")
        self.clients_tree.column("status", width=120, anchor="center")
        self.clients_tree.column("created", width=170, anchor="center")
        self.clients_tree.column("config", width=380, anchor="w")
        self.clients_tree.grid(row=0, column=0, sticky="nsew")

        client_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.clients_tree.yview)
        client_scroll.grid(row=0, column=1, sticky="ns")
        self.clients_tree.configure(yscrollcommand=client_scroll.set)

        action_row = tk.Frame(table_card, bg=PALETTE["paper"])
        action_row.grid(row=2, column=0, sticky="w")

        for label, command, style in [
            ("Refresh", self._refresh_all, "Accent.TButton"),
            ("Remove Selected", self._remove_selected_client, "Danger.TButton"),
            ("Open Config", self._open_selected_client_config, "Accent.TButton"),
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
        self.linux_only_widgets.append(refresh_button)

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
            ("endpoint", "Endpoint", 260, "w"),
            ("handshake", "Last Handshake", 170, "center"),
            ("rx", "RX", 110, "center"),
            ("tx", "TX", 110, "center"),
        ]:
            self.connected_tree.heading(column, text=title)
            self.connected_tree.column(column, width=width, anchor=anchor)

        self.connected_tree.grid(row=0, column=0, sticky="nsew")
        connected_scroll = ttk.Scrollbar(
            tree_frame,
            orient="vertical",
            command=self.connected_tree.yview,
        )
        connected_scroll.grid(row=0, column=1, sticky="ns")
        self.connected_tree.configure(yscrollcommand=connected_scroll.set)

    def _build_files_tab(self) -> None:
        container = tk.Frame(self.files_tab, bg=PALETTE["sand"])
        container.pack(fill="both", expand=True)
        container.columnconfigure((0, 1), weight=1, uniform="files")
        container.rowconfigure(0, weight=1)

        files_card = tk.Frame(container, bg=PALETTE["paper"], padx=20, pady=20)
        files_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        tk.Label(
            files_card,
            text="Project Paths",
            bg=PALETTE["paper"],
            fg=PALETTE["ink"],
            font=("Iowan Old Style", 20, "bold"),
        ).pack(anchor="w")

        self.path_labels: dict[str, tk.Label] = {}
        for title, key in [
            ("Configs Directory", "configs"),
            ("Data Directory", "data"),
            ("Server Config", "server_config"),
            ("System Config", "system_config"),
            ("Log File", "log_file"),
        ]:
            row = tk.Frame(files_card, bg=PALETTE["paper"])
            row.pack(fill="x", pady=10)
            tk.Label(
                row,
                text=title,
                bg=PALETTE["paper"],
                fg=PALETTE["muted"],
                width=16,
                anchor="w",
                font=("Avenir Next", 10, "bold"),
            ).pack(side="left")
            value = tk.Label(
                row,
                text="",
                bg=PALETTE["paper"],
                fg=PALETTE["text"],
                wraplength=320,
                justify="left",
                anchor="w",
                font=("Avenir Next", 10),
            )
            value.pack(side="left", fill="x", expand=True, padx=(12, 12))
            self.path_labels[key] = value

        path_buttons = tk.Frame(files_card, bg=PALETTE["paper"])
        path_buttons.pack(anchor="w", pady=(14, 0))

        for label, command in [
            ("Open Configs", lambda: self._open_path(self.manager.config.configs_dir)),
            ("Open Data", lambda: self._open_path(self.manager.config.data_dir)),
            ("Open Log File", lambda: self._open_path(self.manager.config.log_path)),
        ]:
            button = ttk.Button(path_buttons, text=label, command=command, style="Accent.TButton")
            button.pack(side="left", padx=(0, 10))
            self.busy_widgets.append(button)

        logs_card = tk.Frame(container, bg=PALETTE["paper"], padx=20, pady=20)
        logs_card.grid(row=0, column=1, sticky="nsew", padx=(10, 0))

        tk.Label(
            logs_card,
            text="Recent Logs",
            bg=PALETTE["paper"],
            fg=PALETTE["ink"],
            font=("Iowan Old Style", 20, "bold"),
        ).pack(anchor="w")
        tk.Label(
            logs_card,
            text="Tail of data/vpn_manager.log. Useful for quick diagnostics without leaving the app.",
            bg=PALETTE["paper"],
            fg=PALETTE["muted"],
            justify="left",
            font=("Avenir Next", 11),
        ).pack(anchor="w", pady=(8, 12))

        self.log_text = ScrolledText(
            logs_card,
            wrap="word",
            height=20,
            bg="#FBFAF7",
            fg=PALETTE["text"],
            insertbackground=PALETTE["ink"],
            relief="flat",
            font=("Menlo", 11),
        )
        self.log_text.pack(fill="both", expand=True)
        self.log_text.configure(state="disabled")

    def _build_settings_tab(self) -> None:
        container = tk.Frame(self.settings_tab, bg=PALETTE["sand"])
        container.pack(fill="both", expand=True)
        container.columnconfigure(0, weight=1)

        card = tk.Frame(container, bg=PALETTE["paper"], padx=20, pady=20)
        card.pack(fill="both", expand=True)

        tk.Label(
            card,
            text="VPN Settings",
            bg=PALETTE["paper"],
            fg=PALETTE["ink"],
            font=("Iowan Old Style", 22, "bold"),
        ).grid(row=0, column=0, columnspan=2, sticky="w")
        tk.Label(
            card,
            text=(
                "Customize endpoint, interface, subnet, DNS and related parameters. "
                "Values are saved into .env and applied to new configs immediately."
            ),
            bg=PALETTE["paper"],
            fg=PALETTE["muted"],
            justify="left",
            wraplength=760,
            font=("Avenir Next", 11),
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(8, 18))

        row_specs = [
            ("Endpoint", "endpoint"),
            ("Interface name", "interface_name"),
            ("Server address", "server_address"),
            ("Server port", "server_port"),
            ("Public interface", "public_interface"),
            ("DNS", "dns"),
            ("Client allowed IPs", "client_allowed_ips"),
            ("Connected window", "connected_window_seconds"),
        ]

        for row_index, (label, key) in enumerate(row_specs, start=2):
            tk.Label(
                card,
                text=label,
                bg=PALETTE["paper"],
                fg=PALETTE["ink"],
                anchor="w",
                font=("Avenir Next", 10, "bold"),
            ).grid(row=row_index, column=0, sticky="w", pady=7, padx=(0, 14))
            entry = ttk.Entry(card, textvariable=self.settings_vars[key], width=48)
            entry.grid(row=row_index, column=1, sticky="ew", pady=7)
            self.busy_widgets.append(entry)

        card.columnconfigure(1, weight=1)

        button_row = tk.Frame(card, bg=PALETTE["paper"])
        button_row.grid(row=10, column=0, columnspan=2, sticky="w", pady=(18, 0))

        for label, command in [
            ("Save Settings", self._save_settings),
            ("Reload Settings", self._load_settings_form),
            ("Open .env", lambda: self._open_path(self.manager.config.project_root / ".env")),
        ]:
            button = ttk.Button(button_row, text=label, command=command, style="Accent.TButton")
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
    ) -> None:
        """Run manager operations in a worker thread so the UI stays responsive."""

        self._set_busy(True)
        self.status_var.set(f"{label}...")

        def worker() -> None:
            try:
                task()
            except VPNManagerError as exc:
                self.task_queue.put(("error", str(exc)))
            except Exception as exc:  # pragma: no cover - defensive UI guard
                self.task_queue.put(("error", str(exc)))
            else:
                self.task_queue.put(("success", f"{label} completed."))

        threading.Thread(target=worker, daemon=True).start()

    def _update_platform_capabilities(self) -> None:
        if self.host_platform.local_wireguard_supported:
            return

        for widget in self.linux_only_widgets:
            try:
                widget.configure(state="disabled")
            except tk.TclError:
                continue

        self.status_var.set(linux_host_requirement_message("Local VPN control"))

    def _poll_task_queue(self) -> None:
        try:
            while True:
                status, message = self.task_queue.get_nowait()
                self._set_busy(False)
                self.status_var.set(message)

                if status == "error":
                    messagebox.showerror("WireGuard Control Room", message, parent=self)

                self._refresh_all()
        except queue.Empty:
            pass

        self.after(160, self._poll_task_queue)

    def _set_busy(self, busy: bool) -> None:
        state = "disabled" if busy else "normal"
        for widget in self.busy_widgets:
            try:
                widget_state = state
                if (
                    not busy
                    and not self.host_platform.local_wireguard_supported
                    and widget in self.linux_only_widgets
                ):
                    widget_state = "disabled"
                widget.configure(state=widget_state)
            except tk.TclError:
                continue

    def _submit_add_client(self) -> None:
        client_name = self.client_name_var.get().strip()
        if not client_name:
            messagebox.showwarning(
                "Client name required",
                "Enter a client name before creating a configuration.",
                parent=self,
            )
            return

        self._run_task(
            f"Adding client {client_name}",
            lambda: self.manager.add_client(client_name),
        )
        self.client_name_var.set("")

    def _remove_selected_client(self) -> None:
        client_name = self._selected_client_name()
        if client_name is None:
            messagebox.showinfo(
                "No selection",
                "Select a client in the table first.",
                parent=self,
            )
            return

        confirmed = messagebox.askyesno(
            "Remove client",
            f"Delete client '{client_name}' and remove its generated files?",
            parent=self,
        )
        if not confirmed:
            return

        self._run_task(
            f"Removing client {client_name}",
            lambda: self.manager.remove_client(client_name),
        )

    def _open_selected_client_config(self) -> None:
        client_name = self._selected_client_name()
        if client_name is None:
            messagebox.showinfo(
                "No selection",
                "Select a client in the table first.",
                parent=self,
            )
            return

        client = self.client_rows.get(client_name)
        if client is None:
            messagebox.showerror("Missing client", "The selected client could not be resolved.", parent=self)
            return

        config_path = Path(client.config_path)
        if not config_path.exists():
            messagebox.showerror(
                "Missing config",
                f"The config file does not exist:\n{config_path}",
                parent=self,
            )
            return

        self._open_path(config_path)

    def _selected_client_name(self) -> str | None:
        selection = self.clients_tree.selection()
        if not selection:
            return None
        return selection[0]

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
        self.settings_vars["connected_window_seconds"].set(
            str(settings.connected_window_seconds)
        )

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
                connected_window_seconds=int(
                    self.settings_vars["connected_window_seconds"].get().strip()
                ),
            )
            new_config = save_editable_settings(self.manager.config.project_root, settings)
            self.manager.update_config(new_config)
            self.host_platform = detect_host_platform()
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

    def _refresh_all(self) -> None:
        clients = self.manager.list_clients_with_status()
        connected_clients, connected_note = self._get_connected_peers()
        service_text = self._service_state_text()

        self._populate_clients_tree(clients)
        self._populate_connected_tree(connected_clients, connected_note)
        self._update_header(clients, connected_clients, service_text)
        self._update_overview(clients, connected_clients, service_text, connected_note)
        self._update_sidebar(service_text)
        self._update_paths()
        self._update_logs()

    def _get_connected_peers(self) -> tuple[list[ConnectedClient], str]:
        if not self.host_platform.local_wireguard_supported:
            return [], linux_host_requirement_message("Connected peer lookup")

        try:
            peers = self.manager.get_connected_clients()
        except VPNManagerError as exc:
            return [], f"Connected peer status is unavailable: {exc}"
        return peers, "Peers shown below had a recent WireGuard handshake."

    def _service_state_text(self) -> str:
        if not self.host_platform.local_wireguard_supported:
            return "Manage on Ubuntu host"

        try:
            return "Active" if self.manager.is_service_active() else "Stopped"
        except VPNManagerError as exc:
            return f"Unavailable ({exc})"

    def _populate_clients_tree(self, clients: list[tuple[ClientRecord, bool]]) -> None:
        self.client_rows.clear()
        self.clients_tree.delete(*self.clients_tree.get_children())

        for client, is_connected in clients:
            self.client_rows[client.name] = client
            self.clients_tree.insert(
                "",
                "end",
                iid=client.name,
                values=(
                    client.address,
                    "Connected" if is_connected else "Idle",
                    format_iso_datetime(client.created_at),
                    client.config_path,
                ),
            )

    def _populate_connected_tree(
        self,
        clients: list[ConnectedClient],
        note: str,
    ) -> None:
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

    def _update_header(
        self,
        clients: list[tuple[ClientRecord, bool]],
        connected_clients: list[ConnectedClient],
        service_text: str,
    ) -> None:
        self.hero_status_var.set(f"Service: {service_text}")
        self.hero_counts_var.set(
            f"Clients: {len(clients)} | Connected: {len(connected_clients)}"
        )
        self.hero_environment_var.set(
            f"{self.host_platform.display_name} {self.host_platform.release} | "
            f"{self.host_platform.machine} | {'root' if is_root() else 'non-root'}"
        )

    def _update_overview(
        self,
        clients: list[tuple[ClientRecord, bool]],
        connected_clients: list[ConnectedClient],
        service_text: str,
        connected_note: str,
    ) -> None:
        endpoint_ready = self.manager.config.endpoint != "your.server.ip.or.dns"
        endpoint_text = (
            self.manager.config.endpoint
            if endpoint_ready
            else "Set WG_ENDPOINT in .env"
        )

        self.metric_labels["total_clients"].configure(text=str(len(clients)))
        self.metric_labels["connected_clients"].configure(text=str(len(connected_clients)))
        self.metric_labels["service_state"].configure(text=service_text)
        self.metric_labels["endpoint"].configure(text=endpoint_text)

        self.overview_note_var.set(
            "\n".join(
                [
                    f"Interface: {self.manager.config.interface_name}",
                    f"Server address: {self.manager.config.server_interface}",
                    f"Public interface: {self.manager.config.public_interface}",
                    connected_note,
                    (
                        "This desktop is acting as a control client. "
                        "Run local VPN service operations on Ubuntu."
                        if not self.host_platform.local_wireguard_supported
                        else "Local WireGuard operations are available on this host."
                    ),
                ]
            )
        )

    def _update_sidebar(self, service_text: str) -> None:
        self.sidebar_info.configure(
            text="\n".join(
                [
                    f"Platform: {self.host_platform.display_name}",
                    f"Release: {self.host_platform.release}",
                    f"Architecture: {self.host_platform.machine}",
                    f"Root mode: {'yes' if is_root() else 'no'}",
                    f"Interface: {self.manager.config.interface_name}",
                    f"Server subnet: {self.manager.config.network}",
                    f"Listen port: {self.manager.config.server_port}",
                    f"Endpoint: {self.manager.config.endpoint}",
                    f"Service state: {service_text}",
                    (
                        "Local service control: available"
                        if self.host_platform.local_wireguard_supported
                        else "Local service control: use Ubuntu host"
                    ),
                ]
            )
        )

    def _update_paths(self) -> None:
        self.path_labels["configs"].configure(text=str(self.manager.config.configs_dir))
        self.path_labels["data"].configure(text=str(self.manager.config.data_dir))
        self.path_labels["server_config"].configure(text=str(self.manager.config.server_config_path))
        self.path_labels["system_config"].configure(text=str(self.manager.config.system_server_config))
        self.path_labels["log_file"].configure(text=str(self.manager.config.log_path))

    def _update_logs(self) -> None:
        log_tail = read_log_tail(self.manager.config.log_path, lines=60)
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.insert("1.0", log_tail)
        self.log_text.configure(state="disabled")


def run_gui_app(manager: WireGuardManager) -> None:
    """Start the desktop GUI event loop."""

    app = VPNDesktopApp(manager)
    app.mainloop()
