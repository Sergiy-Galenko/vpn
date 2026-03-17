from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication, QPixmap
from PySide6.QtWidgets import (
    QFileDialog,
    QDialog,
    QDialogButtonBox,
    QLabel,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
)

from wgdesk.application.dto import ClientConfigExportDTO


class QRExportDialog(QDialog):
    def __init__(self, export: ClientConfigExportDTO, parent=None) -> None:
        super().__init__(parent)
        self.export = export
        self.setWindowTitle("Client export")
        self.setMinimumSize(520, 620)

        layout = QVBoxLayout(self)
        self.qr_label = QLabel()
        self.qr_label.setAlignment(Qt.AlignCenter)
        pixmap = QPixmap(export.qr_png_path)
        self.qr_label.setPixmap(pixmap.scaledToWidth(300, Qt.SmoothTransformation))

        self.config_text = QTextEdit()
        self.config_text.setReadOnly(True)
        self.config_text.setPlainText(export.config_text)

        save_config_button = QPushButton("Save .conf")
        save_qr_button = QPushButton("Save QR as PNG")
        copy_button = QPushButton("Copy config")

        save_config_button.clicked.connect(self._save_config)
        save_qr_button.clicked.connect(self._save_qr)
        copy_button.clicked.connect(self._copy_config)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)

        layout.addWidget(self.qr_label)
        layout.addWidget(save_config_button)
        layout.addWidget(save_qr_button)
        layout.addWidget(copy_button)
        layout.addWidget(self.config_text, 1)
        layout.addWidget(buttons)

    def _save_config(self) -> None:
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save WireGuard config",
            f"client-{self.export.client_id}.conf",
            "WireGuard config (*.conf)",
        )
        if not file_path:
            return
        Path(file_path).write_text(self.export.config_text, encoding="utf-8")
        Path(file_path).chmod(0o600)
        QMessageBox.information(self, "Saved", f"Config written to {file_path}")

    def _save_qr(self) -> None:
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save QR image",
            f"client-{self.export.client_id}.png",
            "PNG image (*.png)",
        )
        if not file_path:
            return
        Path(file_path).write_bytes(Path(self.export.qr_png_path).read_bytes())
        Path(file_path).chmod(0o600)
        QMessageBox.information(self, "Saved", f"QR image written to {file_path}")

    def _copy_config(self) -> None:
        QGuiApplication.clipboard().setText(self.export.config_text)
        QMessageBox.information(self, "Copied", "WireGuard config copied to clipboard.")

