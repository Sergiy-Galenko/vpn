from __future__ import annotations

import ipaddress
from uuid import uuid4

from wgdesk.application.dto import AddClientInput, ClientConfigExportDTO, ClientViewDTO
from wgdesk.application.errors import ValidationFailedError
from wgdesk.domain.enums import ActionResult, ClientStatus, TargetType


class ClientService:
    def __init__(
        self,
        session_service,
        client_repository,
        audit_service,
        secret_store,
        qr_generator,
    ) -> None:
        self.session_service = session_service
        self.client_repository = client_repository
        self.audit_service = audit_service
        self.secret_store = secret_store
        self.qr_generator = qr_generator

    def list_clients(self) -> list[ClientViewDTO]:
        session = self.session_service.require_session()
        clients = self.client_repository.list_for_profile(session.profile.id)
        return [self._to_view(client) for client in clients]

    def refresh_from_server(self) -> list[ClientViewDTO]:
        session = self.session_service.require_session()
        payload = session.transport.execute("list_clients", {})
        clients = self.client_repository.sync_from_agent(
            session.profile.id,
            list(payload.get("clients", [])),
        )
        return [self._to_view(client) for client in clients]

    def add_client(self, data: AddClientInput) -> ClientConfigExportDTO:
        if not data.name.strip():
            raise ValidationFailedError("Client name is required.")
        session = self.session_service.require_session()
        client_id = str(uuid4())
        address_cidr = self._allocate_address(
            session.config.subnet_cidr,
            self.client_repository.list_for_profile(session.profile.id),
        )

        payload = session.transport.execute(
            "add_client",
            {
                "client_id": client_id,
                "name": data.name,
                "email": data.email,
                "device": data.device,
                "comment": data.comment,
                "expiry_at": data.expiry_at.isoformat() if data.expiry_at else None,
                "address_cidr": address_cidr,
                "interface_name": session.config.interface_name,
                "endpoint": session.config.endpoint,
                "listen_port": session.config.listen_port,
                "subnet_cidr": session.config.subnet_cidr,
                "public_interface": session.config.public_interface,
                "dns_servers": session.config.dns_servers,
                "allowed_ips": session.config.allowed_ips,
            },
        )
        private_key_ref = self.secret_store.put(payload["private_key"])
        config_ref = self.secret_store.put(payload["client_config"])
        client = self.client_repository.create(
            client_id=client_id,
            server_profile_id=session.profile.id,
            name=data.name,
            email=data.email,
            device=data.device,
            comment=data.comment,
            address_cidr=payload["address_cidr"],
            public_key=payload["public_key"],
            private_key_secret_ref=private_key_ref,
            status=ClientStatus.ACTIVE,
            expiry_at=data.expiry_at,
        )
        qr_path = self.qr_generator.generate_png(client.id, payload["client_config"])
        self.client_repository.create_revision(
            client_id=client.id,
            revision=1,
            config_secret_ref=config_ref,
            qr_png_path=str(qr_path),
            reason="created",
        )
        self.audit_service.log(
            server_profile_id=session.profile.id,
            action="add_client",
            actor="desktop",
            source="gui",
            target_type=TargetType.CLIENT.value,
            target_id=client.id,
            result=ActionResult.SUCCESS,
            message=f"Created client {client.name}",
        )
        return ClientConfigExportDTO(
            client_id=client.id,
            config_text=payload["client_config"],
            qr_png_path=str(qr_path),
        )

    def disable_client(self, client_id: str) -> ClientViewDTO:
        client = self.client_repository.get(client_id)
        if client is None:
            raise ValueError("Client not found")
        session = self.session_service.require_session()
        session.transport.execute("disable_client", {"client_name": client.name})
        updated = self.client_repository.update_status(client_id, ClientStatus.DISABLED)
        self.audit_service.log(
            server_profile_id=session.profile.id,
            action="disable_client",
            actor="desktop",
            source="gui",
            target_type=TargetType.CLIENT.value,
            target_id=client_id,
            result=ActionResult.SUCCESS,
            message=f"Disabled client {client.name}",
        )
        return self._to_view(updated)

    def enable_client(self, client_id: str) -> ClientViewDTO:
        client = self.client_repository.get(client_id)
        if client is None:
            raise ValueError("Client not found")
        session = self.session_service.require_session()
        session.transport.execute("enable_client", {"client_name": client.name})
        updated = self.client_repository.update_status(client_id, ClientStatus.ACTIVE)
        self.audit_service.log(
            server_profile_id=session.profile.id,
            action="enable_client",
            actor="desktop",
            source="gui",
            target_type=TargetType.CLIENT.value,
            target_id=client_id,
            result=ActionResult.SUCCESS,
            message=f"Enabled client {client.name}",
        )
        return self._to_view(updated)

    def latest_export(self, client_id: str) -> ClientConfigExportDTO | None:
        client = self.client_repository.get(client_id)
        if client is None or client.private_key_secret_ref is None:
            return None
        revision = self.client_repository.latest_revision(client_id)
        if revision is None or revision.config_secret_ref is None or revision.qr_png_path is None:
            return None
        return ClientConfigExportDTO(
            client_id=client.id,
            config_text=self.secret_store.get(revision.config_secret_ref),
            qr_png_path=revision.qr_png_path,
        )

    @staticmethod
    def _allocate_address(subnet_cidr: str, clients) -> str:
        network = ipaddress.ip_network(subnet_cidr, strict=False)
        used = {ipaddress.ip_interface(client.address_cidr).ip for client in clients}
        hosts = list(network.hosts())
        if not hosts:
            raise ValueError("Subnet does not provide usable client addresses")
        reserved_server_ip = hosts[0]
        for host_ip in hosts[1:]:
            if host_ip not in used and host_ip != reserved_server_ip:
                return f"{host_ip}/32"
        raise ValueError("No free client addresses available")

    def _to_view(self, client) -> ClientViewDTO:
        revision = self.client_repository.latest_revision(client.id)
        return ClientViewDTO(
            id=client.id,
            name=client.name,
            email=client.email,
            device=client.device,
            comment=client.comment,
            address_cidr=client.address_cidr,
            status=client.status,
            expiry_at=client.expiry_at,
            created_at=client.created_at,
            updated_at=client.updated_at,
            last_used_at=client.last_used_at,
            config_available=revision is not None and revision.config_secret_ref is not None,
            qr_png_path=revision.qr_png_path if revision is not None else None,
        )
