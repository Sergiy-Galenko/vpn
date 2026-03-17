from __future__ import annotations

from PySide6.QtCore import QObject, Signal

from wgdesk.application.dto import AuditLogDTO, ClientViewDTO, ConnectionStateDTO, ServerStatusDTO


class AppEventBus(QObject):
    connection_changed = Signal(object)
    server_status_changed = Signal(object)
    clients_changed = Signal(list)
    audit_logged = Signal(object)
    error_raised = Signal(str)
    busy_changed = Signal(bool, str)

    def emit_connection_changed(self, state: ConnectionStateDTO | None) -> None:
        self.connection_changed.emit(state)

    def emit_server_status_changed(self, status: ServerStatusDTO | None) -> None:
        self.server_status_changed.emit(status)

    def emit_clients_changed(self, clients: list[ClientViewDTO]) -> None:
        self.clients_changed.emit(clients)

    def emit_audit_logged(self, entry: AuditLogDTO) -> None:
        self.audit_logged.emit(entry)

    def emit_error(self, message: str) -> None:
        self.error_raised.emit(message)

    def emit_busy(self, busy: bool, message: str) -> None:
        self.busy_changed.emit(busy, message)

