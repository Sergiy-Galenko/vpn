from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from wgdesk.application.dto import AddClientInput, ClientViewDTO
from wgdesk.domain.enums import ClientStatus


class ClientsPage(QWidget):
    add_client_requested = Signal(object)
    disable_client_requested = Signal(str)
    enable_client_requested = Signal(str)
    refresh_requested = Signal()
    show_qr_requested = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        self.clients_by_row: dict[int, ClientViewDTO] = {}

        layout = QVBoxLayout(self)
        form = QFormLayout()

        self.name_edit = QLineEdit()
        self.email_edit = QLineEdit()
        self.device_edit = QLineEdit()
        self.comment_edit = QLineEdit()
        self.expiry_edit = QLineEdit()
        self.expiry_edit.setPlaceholderText("YYYY-MM-DD or empty")

        form.addRow("Name", self.name_edit)
        form.addRow("Email", self.email_edit)
        form.addRow("Device", self.device_edit)
        form.addRow("Comment", self.comment_edit)
        form.addRow("Expiry", self.expiry_edit)
        layout.addLayout(form)

        button_row = QHBoxLayout()
        self.add_button = QPushButton("Add client")
        self.disable_button = QPushButton("Disable")
        self.enable_button = QPushButton("Enable")
        self.refresh_button = QPushButton("Refresh")
        self.qr_button = QPushButton("Show QR")

        button_row.addWidget(self.add_button)
        button_row.addWidget(self.disable_button)
        button_row.addWidget(self.enable_button)
        button_row.addWidget(self.refresh_button)
        button_row.addWidget(self.qr_button)
        layout.addLayout(button_row)

        self.info_label = QLabel("No clients loaded.")
        layout.addWidget(self.info_label)

        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels(
            ["Name", "Email", "Device", "Address", "Status", "Expiry", "Updated", "Config"]
        )
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.table, 1)

        self.add_button.clicked.connect(self._emit_add)
        self.disable_button.clicked.connect(self._emit_disable)
        self.enable_button.clicked.connect(self._emit_enable)
        self.refresh_button.clicked.connect(self.refresh_requested.emit)
        self.qr_button.clicked.connect(self._emit_qr)

    def update_clients(self, clients: list[ClientViewDTO]) -> None:
        self.clients_by_row.clear()
        self.table.setRowCount(len(clients))
        self.info_label.setText(f"Loaded {len(clients)} clients.")

        for row_index, client in enumerate(clients):
            self.clients_by_row[row_index] = client
            values = [
                client.name,
                client.email or "",
                client.device or "",
                client.address_cidr,
                client.status.value,
                client.expiry_at.date().isoformat() if client.expiry_at else "",
                client.updated_at.isoformat(timespec="seconds"),
                "yes" if client.config_available else "no",
            ]
            for column_index, value in enumerate(values):
                item = QTableWidgetItem(value)
                if client.status == ClientStatus.DISABLED:
                    item.setBackground("#F6D1C1")
                elif client.status == ClientStatus.EXPIRED:
                    item.setBackground("#F7B2B7")
                elif client.status == ClientStatus.ACTIVE:
                    item.setBackground("#D7F1E3")
                self.table.setItem(row_index, column_index, item)

    def _emit_add(self) -> None:
        expiry_text = self.expiry_edit.text().strip()
        expiry = None
        if expiry_text:
            expiry = datetime.fromisoformat(f"{expiry_text}T00:00:00")
        self.add_client_requested.emit(
            AddClientInput(
                name=self.name_edit.text().strip(),
                email=self.email_edit.text().strip() or None,
                device=self.device_edit.text().strip() or None,
                comment=self.comment_edit.text().strip() or None,
                expiry_at=expiry,
            )
        )
        self.name_edit.clear()
        self.email_edit.clear()
        self.device_edit.clear()
        self.comment_edit.clear()
        self.expiry_edit.clear()

    def _selected_client(self) -> ClientViewDTO | None:
        row = self.table.currentRow()
        return self.clients_by_row.get(row)

    def _emit_disable(self) -> None:
        client = self._selected_client()
        if client is not None:
            self.disable_client_requested.emit(client.id)

    def _emit_enable(self) -> None:
        client = self._selected_client()
        if client is not None:
            self.enable_client_requested.emit(client.id)

    def _emit_qr(self) -> None:
        client = self._selected_client()
        if client is not None:
            self.show_qr_requested.emit(client.id)

