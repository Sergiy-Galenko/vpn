from __future__ import annotations

import json

from wgdesk.application.dto import AuditLogDTO
from wgdesk.domain.enums import ActionResult
from wgdesk.infrastructure.db.repositories.audit_repository import AuditLogRepository


class AuditService:
    def __init__(self, repository: AuditLogRepository) -> None:
        self.repository = repository

    def log(
        self,
        *,
        server_profile_id: str | None,
        action: str,
        actor: str,
        source: str,
        target_type: str,
        target_id: str | None,
        result: ActionResult,
        message: str,
        error_code: str | None = None,
        error_details: dict | None = None,
    ) -> AuditLogDTO:
        entity = self.repository.append(
            server_profile_id=server_profile_id,
            actor=actor,
            source=source,
            action=action,
            target_type=target_type,
            target_id=target_id,
            result=result,
            message=message,
            error_code=error_code,
            error_details_json=json.dumps(error_details or {}) if error_details else None,
        )
        return AuditLogDTO(
            id=entity.id,
            timestamp=entity.timestamp,
            actor=entity.actor,
            source=entity.source,
            action=entity.action,
            target_type=entity.target_type,
            target_id=entity.target_id,
            result=entity.result,
            message=entity.message,
            error_code=entity.error_code,
            error_details=entity.error_details_json,
        )

    def recent(self, limit: int = 100) -> list[AuditLogDTO]:
        return [
            AuditLogDTO(
                id=entry.id,
                timestamp=entry.timestamp,
                actor=entry.actor,
                source=entry.source,
                action=entry.action,
                target_type=entry.target_type,
                target_id=entry.target_id,
                result=entry.result,
                message=entry.message,
                error_code=entry.error_code,
                error_details=entry.error_details_json,
            )
            for entry in self.repository.recent(limit)
        ]

