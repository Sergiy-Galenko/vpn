from __future__ import annotations

from PySide6.QtWidgets import QFormLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from wgdesk.application.dto import ConnectionStateDTO, ServerStatusDTO


class DashboardPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.refresh_button = QPushButton("Refresh status")
        self.hostname_label = QLabel("—")
        self.platform_label = QLabel("—")
        self.service_label = QLabel("Disconnected")
        self.interface_label = QLabel("—")
        self.endpoint_label = QLabel("—")
        self.active_peers_label = QLabel("—")
        self.firewall_label = QLabel("—")
        self.uptime_label = QLabel("—")
        self.connection_label = QLabel("Not connected")
        self.capabilities_label = QLabel("—")
        self.error_label = QLabel("—")

        layout = QVBoxLayout(self)
        layout.addWidget(self.refresh_button)
        form = QFormLayout()
        form.addRow("Connection", self.connection_label)
        form.addRow("Hostname", self.hostname_label)
        form.addRow("Platform", self.platform_label)
        form.addRow("Service", self.service_label)
        form.addRow("Interface", self.interface_label)
        form.addRow("Endpoint", self.endpoint_label)
        form.addRow("Active peers", self.active_peers_label)
        form.addRow("Firewall", self.firewall_label)
        form.addRow("Uptime", self.uptime_label)
        form.addRow("Capabilities", self.capabilities_label)
        form.addRow("Last error", self.error_label)
        layout.addLayout(form)
        layout.addStretch(1)

    def update_connection(self, state: ConnectionStateDTO | None) -> None:
        if state is None:
            self.connection_label.setText("Not connected")
            self.service_label.setText("Disconnected")
            return
        self.connection_label.setText(f"{state.profile_name} ({state.host_label})")
        self.service_label.setText(state.service_state)
        self.interface_label.setText(state.interface_name)
        self.endpoint_label.setText(state.endpoint)
        self.active_peers_label.setText(str(state.active_peers))
        self.uptime_label.setText(
            str(state.uptime_seconds) if state.uptime_seconds is not None else "n/a"
        )
        self.error_label.setText(state.last_error or "—")

    def update_status(self, status: ServerStatusDTO | None) -> None:
        if status is None:
            return
        self.hostname_label.setText(status.hostname)
        self.platform_label.setText(status.platform)
        self.service_label.setText(status.service_state)
        self.interface_label.setText(status.interface_name)
        self.endpoint_label.setText(status.endpoint)
        self.active_peers_label.setText(str(status.active_peers))
        self.firewall_label.setText(status.firewall_backend)
        self.uptime_label.setText(
            str(status.uptime_seconds) if status.uptime_seconds is not None else "n/a"
        )
        self.capabilities_label.setText(", ".join(status.capabilities) or "—")
        self.error_label.setText(status.last_error or "—")
