from __future__ import annotations

from wgdesk.application.dto import ServerStatusDTO


class ServerService:
    def __init__(self, session_service) -> None:
        self.session_service = session_service

    def refresh_status(self) -> ServerStatusDTO:
        session = self.session_service.require_session()
        payload = session.transport.execute(
            "server_status",
            {
                "interface_name": session.config.interface_name,
                "endpoint": session.config.endpoint,
                "listen_port": session.config.listen_port,
            },
        )
        status = ServerStatusDTO(
            hostname=payload["hostname"],
            platform=payload["platform"],
            python_version=payload["python_version"],
            service_state=payload["service_state"],
            interface_name=payload["interface_name"],
            endpoint=payload["endpoint"],
            listen_port=int(payload["listen_port"]),
            active_peers=int(payload["active_peers"]),
            uptime_seconds=payload.get("uptime_seconds"),
            firewall_backend=payload.get("firewall_backend", "unknown"),
            last_error=payload.get("last_error"),
            capabilities=list(payload.get("capabilities", [])),
        )
        session.last_status = status
        return status

