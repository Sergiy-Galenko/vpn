from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLineEdit,
    QMessageBox,
    QSpinBox,
    QVBoxLayout,
)

from wgdesk.application.dto import CreateServerProfileInput
from wgdesk.domain.enums import AuthMethod, ServerMode, SudoMode


class ConnectServerDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Connect to server")
        self.setMinimumWidth(520)

        layout = QVBoxLayout(self)
        form = QFormLayout()
        layout.addLayout(form)

        self.name_edit = QLineEdit()
        self.mode_combo = QComboBox()
        self.mode_combo.addItem("Local Ubuntu", ServerMode.LOCAL)
        self.mode_combo.addItem("Remote Ubuntu over SSH", ServerMode.SSH)
        self.mode_combo.currentIndexChanged.connect(self._update_mode)

        self.host_edit = QLineEdit()
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(22)
        self.username_edit = QLineEdit()

        self.auth_combo = QComboBox()
        self.auth_combo.addItem("No auth", AuthMethod.NONE)
        self.auth_combo.addItem("SSH key", AuthMethod.SSH_KEY)
        self.auth_combo.addItem("Password", AuthMethod.PASSWORD)

        self.private_key_edit = QLineEdit()
        self.host_fingerprint_edit = QLineEdit()
        self.host_fingerprint_edit.setPlaceholderText("Optional trusted SHA256/hex fingerprint")
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.key_passphrase_edit = QLineEdit()
        self.key_passphrase_edit.setEchoMode(QLineEdit.Password)

        self.sudo_combo = QComboBox()
        self.sudo_combo.addItem("No sudo", SudoMode.NONE)
        self.sudo_combo.addItem("sudo NOPASSWD", SudoMode.SUDO_NOPASSWD)
        self.sudo_combo.addItem("sudo with password", SudoMode.SUDO_PASSWORD)

        self.sudo_password_edit = QLineEdit()
        self.sudo_password_edit.setEchoMode(QLineEdit.Password)

        self.interface_edit = QLineEdit("wg0")
        self.endpoint_edit = QLineEdit()
        self.listen_port_spin = QSpinBox()
        self.listen_port_spin.setRange(1, 65535)
        self.listen_port_spin.setValue(51820)
        self.subnet_edit = QLineEdit("10.8.0.0/24")
        self.public_interface_edit = QLineEdit("eth0")
        self.dns_edit = QLineEdit("1.1.1.1,8.8.8.8")
        self.default_checkbox = QCheckBox("Make default profile")

        form.addRow("Profile name", self.name_edit)
        form.addRow("Mode", self.mode_combo)
        form.addRow("Host", self.host_edit)
        form.addRow("SSH port", self.port_spin)
        form.addRow("Username", self.username_edit)
        form.addRow("Auth", self.auth_combo)
        form.addRow("Private key path", self.private_key_edit)
        form.addRow("Host fingerprint", self.host_fingerprint_edit)
        form.addRow("Password", self.password_edit)
        form.addRow("Key passphrase", self.key_passphrase_edit)
        form.addRow("Sudo mode", self.sudo_combo)
        form.addRow("Sudo password", self.sudo_password_edit)
        form.addRow("Interface name", self.interface_edit)
        form.addRow("Endpoint", self.endpoint_edit)
        form.addRow("Listen port", self.listen_port_spin)
        form.addRow("Subnet", self.subnet_edit)
        form.addRow("Public interface", self.public_interface_edit)
        form.addRow("DNS servers", self.dns_edit)
        form.addRow("", self.default_checkbox)

        self.buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel,
            parent=self,
        )
        self.buttons.accepted.connect(self._accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
        self._update_mode()

    def profile_input(self) -> CreateServerProfileInput:
        dns_servers = [item.strip() for item in self.dns_edit.text().split(",") if item.strip()]
        return CreateServerProfileInput(
            name=self.name_edit.text().strip(),
            mode=self.mode_combo.currentData(),
            interface_name=self.interface_edit.text().strip() or "wg0",
            endpoint=self.endpoint_edit.text().strip(),
            listen_port=self.listen_port_spin.value(),
            subnet_cidr=self.subnet_edit.text().strip(),
            public_interface=self.public_interface_edit.text().strip() or "eth0",
            dns_servers=dns_servers or ["1.1.1.1"],
            host=self.host_edit.text().strip() or None,
            port=self.port_spin.value(),
            username=self.username_edit.text().strip() or None,
            auth_method=self.auth_combo.currentData(),
            private_key_path=self.private_key_edit.text().strip() or None,
            known_host_fingerprint=self.host_fingerprint_edit.text().strip() or None,
            password=self.password_edit.text() or None,
            private_key_passphrase=self.key_passphrase_edit.text() or None,
            sudo_mode=self.sudo_combo.currentData(),
            sudo_password=self.sudo_password_edit.text() or None,
            is_default=self.default_checkbox.isChecked(),
        )

    def _update_mode(self) -> None:
        is_ssh = self.mode_combo.currentData() == ServerMode.SSH
        for widget in (
            self.host_edit,
            self.port_spin,
            self.username_edit,
            self.auth_combo,
            self.private_key_edit,
            self.host_fingerprint_edit,
            self.password_edit,
            self.key_passphrase_edit,
        ):
            widget.setEnabled(is_ssh)

        if not is_ssh:
            self.host_edit.setText("")
            self.username_edit.setText("")

    def _accept(self) -> None:
        data = self.profile_input()
        if not data.name:
            self._error("Profile name is required.")
            return
        if data.mode == ServerMode.SSH and (not data.host or not data.username):
            self._error("SSH profiles require host and username.")
            return
        if data.mode == ServerMode.SSH and data.auth_method == AuthMethod.SSH_KEY and not data.private_key_path:
            self._error("SSH key authentication requires a private key path.")
            return
        if data.mode == ServerMode.SSH and data.auth_method == AuthMethod.PASSWORD and not data.password:
            self._error("Password authentication requires a password.")
            return
        if data.endpoint in {"", "your.server.ip.or.dns"}:
            self._error("Set a real endpoint. Placeholder values are not allowed.")
            return
        if not data.endpoint:
            self._error("Endpoint is required for client config generation.")
            return
        self.accept()

    def _error(self, message: str) -> None:
        QMessageBox.critical(self, "Invalid profile", message)
