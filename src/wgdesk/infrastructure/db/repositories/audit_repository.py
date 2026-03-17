from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select

from wgdesk.domain.entities import AuditLogEntry
from wgdesk.domain.enums import ActionResult
from wgdesk.infrastructure.db.models import AuditLogModel


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuditLogRepository:
    def __init__(self, session_factory) -> None:
        self.session_factory = session_factory

    def append(
        self,
        *,
        server_profile_id: str | None,
        actor: str,
        source: str,
        action: str,
        target_type: str,
        target_id: str | None,
        result: ActionResult,
        message: str,
        error_code: str | None = None,
        error_details_json: str | None = None,
    ) -> AuditLogEntry:
        row = AuditLogModel(
            id=str(uuid4()),
            server_profile_id=server_profile_id,
            timestamp=utcnow(),
            actor=actor,
            source=source,
            action=action,
            target_type=target_type,
            target_id=target_id,
            result=result.value,
            message=message,
            error_code=error_code,
            error_details_json=error_details_json,
        )
        with self.session_factory() as session:
            session.add(row)
            session.commit()
            session.refresh(row)
            return self._to_entity(row)

    def recent(self, limit: int = 100) -> list[AuditLogEntry]:
        with self.session_factory() as session:
            rows = session.scalars(
                select(AuditLogModel).order_by(AuditLogModel.timestamp.desc()).limit(limit)
            ).all()
            return [self._to_entity(row) for row in rows]

    @staticmethod
    def _to_entity(row: AuditLogModel) -> AuditLogEntry:
        return AuditLogEntry(
            id=row.id,
            timestamp=row.timestamp,
            actor=row.actor,
            source=row.source,
            action=row.action,
            target_type=row.target_type,
            target_id=row.target_id,
            result=ActionResult(row.result),
            message=row.message,
            error_code=row.error_code,
            error_details_json=row.error_details_json,
        )

