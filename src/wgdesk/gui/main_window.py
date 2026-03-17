from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from wgdesk.application.dto import AddClientInput, ClientConfigExportDTO, ConnectionStateDTO
from wgdesk.gui.dialogs.connect_server_dialog import ConnectServerDialog
from wgdesk.gui.dialogs.qr_export_dialog import QRExportDialog
from wgdesk.gui.event_bus import AppEventBus
from wgdesk.gui.pages.audit_page import AuditPage
from wgdesk.gui.pages.clients_page import ClientsPage
from wgdesk.gui.pages.dashboard_page import DashboardPage
from wgdesk.gui.task_runner import TaskRunner, TaskSpec


class MainWindow(QMainWindow):
    def __init__(self, context) -> None:
        super().__init__()
        self.context = context
        self.services = context.services
        self.event_bus = AppEventBus()
        self.task_runner = TaskRunner()

        self.setWindowTitle("WGDesk")
        self.resize(1280, 820)

        self.profile_combo = QComboBox()
        self.new_profile_button = QPushButton("Connect to server")
        self.connect_button = QPushButton("Connect")
        self.disconnect_button = QPushButton("Disconnect")
        self.refresh_button = QPushButton("Refresh")
        self.connection_chip = QLabel("Disconnected")
        self.connection_chip.setStyleSheet("font-weight: bold; padding: 6px 10px;")

        self.dashboard_page = DashboardPage()
        self.clients_page = ClientsPage()
        self.audit_page = AuditPage()
        self.server_page = QLabel("Server page scaffold is ready.")
        self.backups_page = QLabel("Backups page scaffold is ready.")
        self.settings_page = QLabel("Settings page scaffold is ready.")

        self.stack = QStackedWidget()
        self.stack.addWidget(self.dashboard_page)
        self.stack.addWidget(self.clients_page)
        self.stack.addWidget(self.server_page)
        self.stack.addWidget(self.backups_page)
        self.stack.addWidget(self.audit_page)
        self.stack.addWidget(self.settings_page)

        self._build_ui()
        self._connect_signals()
        self._load_profiles()

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        connection_bar = QHBoxLayout()
        connection_bar.addWidget(QLabel("Profile"))
        connection_bar.addWidget(self.profile_combo, 1)
        connection_bar.addWidget(self.new_profile_button)
        connection_bar.addWidget(self.connect_button)
        connection_bar.addWidget(self.disconnect_button)
        connection_bar.addWidget(self.refresh_button)
        connection_bar.addWidget(self.connection_chip)
        root.addLayout(connection_bar)

        body = QHBoxLayout()
        nav = QVBoxLayout()
        for index, title in enumerate(
            ["Dashboard", "Clients", "Server", "Backups", "Audit Log", "Settings"]
        ):
            button = QPushButton(title)
            button.clicked.connect(lambda checked=False, idx=index: self.stack.setCurrentIndex(idx))
            nav.addWidget(button)
        nav.addStretch(1)

        body.addLayout(nav)
        body.addWidget(self.stack, 1)
        root.addLayout(body, 1)

        status_bar = QStatusBar()
        self.setStatusBar(status_bar)
        self.statusBar().showMessage("Ready.")

    def _connect_signals(self) -> None:
        self.new_profile_button.clicked.connect(self._open_profile_dialog)
        self.connect_button.clicked.connect(self._connect_selected_profile)
        self.disconnect_button.clicked.connect(self._disconnect)
        self.refresh_button.clicked.connect(self._refresh_status)
        self.dashboard_page.refresh_button.clicked.connect(self._refresh_status)

        self.clients_page.add_client_requested.connect(self._add_client)
        self.clients_page.disable_client_requested.connect(self._disable_client)
        self.clients_page.enable_client_requested.connect(self._enable_client)
        self.clients_page.refresh_requested.connect(self._refresh_clients)
        self.clients_page.show_qr_requested.connect(self._show_qr_for_client)

        self.event_bus.connection_changed.connect(self._on_connection_changed)
        self.event_bus.server_status_changed.connect(self.dashboard_page.update_status)
        self.event_bus.clients_changed.connect(self.clients_page.update_clients)
        self.event_bus.audit_logged.connect(self.audit_page.prepend_entry)
        self.event_bus.error_raised.connect(self._show_error)
        self.event_bus.busy_changed.connect(self._set_busy)
        self.audit_page.refresh_requested.connect(self._refresh_audits)

    def _load_profiles(self) -> None:
        self.profile_combo.clear()
        profiles = self.services.session.list_profiles()
        for profile in profiles:
            label = profile.name if profile.mode.value == "local" else f"{profile.name} ({profile.host})"
            self.profile_combo.addItem(label, profile.id)
        if not profiles:
            self.statusBar().showMessage("Create your first server profile to begin.")

    def _open_profile_dialog(self) -> None:
        dialog = ConnectServerDialog(self)
        if dialog.exec() != dialog.Accepted:
            return

        try:
            profile = self.services.session.save_profile(dialog.profile_input())
        except Exception as exc:
            self._show_error(str(exc))
            return

        self._load_profiles()
        index = self.profile_combo.findData(profile.id)
        if index >= 0:
            self.profile_combo.setCurrentIndex(index)
        self._connect_selected_profile()

    def _connect_selected_profile(self) -> None:
        profile_id = self.profile_combo.currentData()
        if not profile_id:
            self._show_error("Create or select a server profile first.")
            return

        self.event_bus.emit_busy(True, "Connecting to server...")
        self.task_runner.submit(
            TaskSpec(
                callback=lambda: self.services.session.connect(profile_id),
                on_success=self._handle_connected,
                on_error=self._handle_error,
            )
        )

    def _handle_connected(self, result) -> None:
        state, status = result
        self.event_bus.emit_busy(False, "Connected.")
        self.event_bus.emit_connection_changed(state)
        self.event_bus.emit_server_status_changed(status)
        self._refresh_clients()

    def _disconnect(self) -> None:
        self.services.session.disconnect()
        self.event_bus.emit_connection_changed(None)
        self.event_bus.emit_server_status_changed(None)
        self.event_bus.emit_clients_changed([])
        self._refresh_audits()
        self.statusBar().showMessage("Disconnected.")

    def _refresh_status(self) -> None:
        self.event_bus.emit_busy(True, "Refreshing server status...")
        self.task_runner.submit(
            TaskSpec(
                callback=self.services.server.refresh_status,
                on_success=self._handle_status_refreshed,
                on_error=self._handle_error,
            )
        )

    def _handle_status_refreshed(self, status) -> None:
        self.event_bus.emit_busy(False, "Status refreshed.")
        self.event_bus.emit_server_status_changed(status)
        self._on_connection_changed(self.services.session.current_connection_state())

    def _refresh_clients(self) -> None:
        self.event_bus.emit_busy(True, "Refreshing clients...")
        self.task_runner.submit(
            TaskSpec(
                callback=self.services.client.refresh_from_server,
                on_success=self._handle_clients_loaded,
                on_error=self._handle_error,
            )
        )

    def _handle_clients_loaded(self, clients) -> None:
        self.event_bus.emit_busy(False, "Clients refreshed.")
        self.event_bus.emit_clients_changed(clients)

    def _add_client(self, data: AddClientInput) -> None:
        self.event_bus.emit_busy(True, f"Creating client {data.name}...")
        self.task_runner.submit(
            TaskSpec(
                callback=lambda: self.services.client.add_client(data),
                on_success=self._handle_client_created,
                on_error=self._handle_error,
            )
        )

    def _handle_client_created(self, export: ClientConfigExportDTO) -> None:
        self.event_bus.emit_busy(False, "Client created.")
        self._refresh_clients()
        self._refresh_status()
        self._refresh_audits()
        QRExportDialog(export, self).exec()

    def _disable_client(self, client_id: str) -> None:
        self.event_bus.emit_busy(True, "Disabling client...")
        self.task_runner.submit(
            TaskSpec(
                callback=lambda: self.services.client.disable_client(client_id),
                on_success=lambda _: self._handle_client_status_changed("Client disabled."),
                on_error=self._handle_error,
            )
        )

    def _enable_client(self, client_id: str) -> None:
        self.event_bus.emit_busy(True, "Enabling client...")
        self.task_runner.submit(
            TaskSpec(
                callback=lambda: self.services.client.enable_client(client_id),
                on_success=lambda _: self._handle_client_status_changed("Client enabled."),
                on_error=self._handle_error,
            )
        )

    def _handle_client_status_changed(self, message: str) -> None:
        self.event_bus.emit_busy(False, message)
        self._refresh_clients()
        self._refresh_status()
        self._refresh_audits()

    def _show_qr_for_client(self, client_id: str) -> None:
        export = self.services.client.latest_export(client_id)
        if export is None:
            self._show_error("Client config export is not available for this entry.")
            return
        QRExportDialog(export, self).exec()

    def _on_connection_changed(self, state: ConnectionStateDTO | None) -> None:
        self.dashboard_page.update_connection(state)
        if state is None:
            self.connection_chip.setText("Disconnected")
            self.connection_chip.setStyleSheet("background:#D65A4A;color:white;padding:6px 10px;")
        else:
            self.connection_chip.setText(f"Connected: {state.profile_name}")
            self.connection_chip.setStyleSheet("background:#2C7A7B;color:white;padding:6px 10px;")
            self._refresh_audits()

    def _set_busy(self, busy: bool, message: str) -> None:
        self.statusBar().showMessage(message)
        self.connect_button.setEnabled(not busy)
        self.new_profile_button.setEnabled(not busy)
        self.refresh_button.setEnabled(not busy)
        self.disconnect_button.setEnabled(not busy)
        self.clients_page.setEnabled(not busy)
        self.dashboard_page.refresh_button.setEnabled(not busy)

    def _handle_error(self, message: str) -> None:
        self.event_bus.emit_busy(False, "Operation failed.")
        self._refresh_audits()
        self._show_error(message)

    def _show_error(self, message: str) -> None:
        self.statusBar().showMessage(message)
        QMessageBox.critical(self, "WGDesk", message)

    def show_initial_setup_if_needed(self) -> None:
        if self.profile_combo.count() == 0:
            self._open_profile_dialog()

    def _refresh_audits(self) -> None:
        try:
            entries = self.services.audit.recent(100)
        except Exception:
            return
        self.audit_page.set_entries(entries)
