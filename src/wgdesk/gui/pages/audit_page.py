from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QHeaderView,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from wgdesk.application.dto import AuditLogDTO


class AuditPage(QWidget):
    refresh_requested = Signal()

    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)

        self.refresh_button = QPushButton("Refresh audit log")
        self.refresh_button.clicked.connect(self.refresh_requested.emit)
        layout.addWidget(self.refresh_button)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["Timestamp", "Action", "Result", "Target", "Message", "Error"]
        )
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.table, 1)

    def set_entries(self, entries: list[AuditLogDTO]) -> None:
        self.table.setRowCount(len(entries))
        for row_index, entry in enumerate(entries):
            values = [
                entry.timestamp.isoformat(timespec="seconds"),
                entry.action,
                entry.result.value,
                entry.target_id or entry.target_type,
                entry.message,
                entry.error_code or "",
            ]
            for column_index, value in enumerate(values):
                self.table.setItem(row_index, column_index, QTableWidgetItem(value))

    def prepend_entry(self, entry: AuditLogDTO) -> None:
        self.table.insertRow(0)
        values = [
            entry.timestamp.isoformat(timespec="seconds"),
            entry.action,
            entry.result.value,
            entry.target_id or entry.target_type,
            entry.message,
            entry.error_code or "",
        ]
        for column_index, value in enumerate(values):
            self.table.setItem(0, column_index, QTableWidgetItem(value))
