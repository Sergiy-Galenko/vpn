from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import select

from wgdesk.domain.entities import Client, ClientConfigRevision
from wgdesk.domain.enums import ClientStatus
from wgdesk.infrastructure.db.models import ClientConfigRevisionModel, ClientModel


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ClientRepository:
    def __init__(self, session_factory) -> None:
        self.session_factory = session_factory

    def list_for_profile(self, profile_id: str) -> list[Client]:
        with self.session_factory() as session:
            rows = session.scalars(
                select(ClientModel)
                .where(ClientModel.server_profile_id == profile_id)
                .order_by(ClientModel.name)
            ).all()
            return [self._to_entity(row) for row in rows]

    def get(self, client_id: str) -> Client | None:
        with self.session_factory() as session:
            row = session.get(ClientModel, client_id)
            return self._to_entity(row) if row is not None else None

    def get_by_name(self, profile_id: str, client_name: str) -> Client | None:
        with self.session_factory() as session:
            row = session.scalar(
                select(ClientModel).where(
                    ClientModel.server_profile_id == profile_id,
                    ClientModel.name == client_name,
                )
            )
            return self._to_entity(row) if row is not None else None

    def create(
        self,
        *,
        client_id: str,
        server_profile_id: str,
        name: str,
        email: str | None,
        device: str | None,
        comment: str | None,
        address_cidr: str,
        public_key: str,
        private_key_secret_ref: str | None,
        status: ClientStatus,
        expiry_at: datetime | None,
    ) -> Client:
        now = utcnow()
        with self.session_factory() as session:
            row = ClientModel(
                id=client_id,
                server_profile_id=server_profile_id,
                name=name,
                email=email,
                device=device,
                comment=comment,
                address_cidr=address_cidr,
                public_key=public_key,
                private_key_secret_ref=private_key_secret_ref,
                status=status.value,
                expiry_at=expiry_at,
                created_at=now,
                updated_at=now,
                latest_config_revision=1,
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return self._to_entity(row)

    def update_status(self, client_id: str, status: ClientStatus) -> Client:
        with self.session_factory() as session:
            row = session.get(ClientModel, client_id)
            if row is None:
                raise ValueError(f"Client {client_id} not found")
            row.status = status.value
            row.updated_at = utcnow()
            row.disabled_at = utcnow() if status == ClientStatus.DISABLED else None
            session.commit()
            session.refresh(row)
            return self._to_entity(row)

    def create_revision(
        self,
        *,
        client_id: str,
        revision: int,
        config_secret_ref: str | None,
        qr_png_path: str | None,
        reason: str,
    ) -> ClientConfigRevision:
        now = utcnow()
        with self.session_factory() as session:
            row = ClientConfigRevisionModel(
                id=str(uuid4()),
                client_id=client_id,
                revision=revision,
                config_secret_ref=config_secret_ref,
                qr_png_path=qr_png_path,
                reason=reason,
                is_active=True,
                created_at=now,
            )
            session.add(row)
            client = session.get(ClientModel, client_id)
            if client is not None:
                client.latest_config_revision = revision
                client.updated_at = now
            session.commit()
            session.refresh(row)
            return self._to_revision_entity(row)

    def latest_revision(self, client_id: str) -> ClientConfigRevision | None:
        with self.session_factory() as session:
            row = session.scalar(
                select(ClientConfigRevisionModel)
                .where(ClientConfigRevisionModel.client_id == client_id)
                .order_by(ClientConfigRevisionModel.revision.desc())
            )
            return self._to_revision_entity(row) if row is not None else None

    def sync_from_agent(
        self,
        server_profile_id: str,
        agent_clients: list[dict[str, Any]],
    ) -> list[Client]:
        now = utcnow()
        with self.session_factory() as session:
            rows = session.scalars(
                select(ClientModel).where(ClientModel.server_profile_id == server_profile_id)
            ).all()
            existing_by_name = {row.name: row for row in rows}

            for item in agent_clients:
                name = str(item["name"]).strip()
                if not name:
                    continue

                row = existing_by_name.get(name)
                if row is None:
                    row = ClientModel(
                        id=str(item.get("id") or uuid4()),
                        server_profile_id=server_profile_id,
                        name=name,
                        created_at=self._parse_datetime(item.get("created_at")) or now,
                        latest_config_revision=0,
                        imported=True,
                    )
                    session.add(row)
                    existing_by_name[name] = row

                row.email = item.get("email") or row.email
                row.device = item.get("device") or row.device
                row.comment = item.get("comment") or row.comment
                row.address_cidr = item.get("address_cidr") or row.address_cidr
                row.public_key = item.get("public_key") or row.public_key or f"unknown-{row.id}"
                row.status = item.get("status", ClientStatus.ACTIVE.value)
                row.expiry_at = self._parse_datetime(item.get("expiry_at")) or row.expiry_at
                row.last_used_at = self._parse_datetime(item.get("last_used_at")) or row.last_used_at
                row.created_at = self._parse_datetime(item.get("created_at")) or row.created_at
                row.updated_at = self._parse_datetime(item.get("updated_at")) or now
                row.disabled_at = now if row.status == ClientStatus.DISABLED.value else None

            session.commit()
            refreshed_rows = session.scalars(
                select(ClientModel)
                .where(ClientModel.server_profile_id == server_profile_id)
                .order_by(ClientModel.name)
            ).all()
            return [self._to_entity(row) for row in refreshed_rows]

    @staticmethod
    def _parse_datetime(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None

    @staticmethod
    def _to_entity(row: ClientModel) -> Client:
        return Client(
            id=row.id,
            server_profile_id=row.server_profile_id,
            name=row.name,
            email=row.email,
            device=row.device,
            comment=row.comment,
            address_cidr=row.address_cidr,
            public_key=row.public_key,
            preshared_key_secret_ref=row.preshared_key_secret_ref,
            private_key_secret_ref=row.private_key_secret_ref,
            status=ClientStatus(row.status),
            expiry_at=row.expiry_at,
            created_at=row.created_at,
            updated_at=row.updated_at,
            last_used_at=row.last_used_at,
            disabled_at=row.disabled_at,
            imported=row.imported,
            latest_config_revision=row.latest_config_revision,
        )

    @staticmethod
    def _to_revision_entity(row: ClientConfigRevisionModel) -> ClientConfigRevision:
        return ClientConfigRevision(
            id=row.id,
            client_id=row.client_id,
            revision=row.revision,
            config_secret_ref=row.config_secret_ref,
            qr_png_path=row.qr_png_path,
            reason=row.reason,
            is_active=row.is_active,
            created_at=row.created_at,
        )
