from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select

from wgdesk.infrastructure.db.models import SettingModel


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SettingsRepository:
    def __init__(self, session_factory) -> None:
        self.session_factory = session_factory

    def get(self, key: str) -> dict | None:
        with self.session_factory() as session:
            row = session.get(SettingModel, key)
            return dict(row.value_json) if row is not None else None

    def set(self, key: str, value: dict) -> None:
        with self.session_factory() as session:
            row = session.get(SettingModel, key)
            if row is None:
                row = SettingModel(key=key, value_json=value, updated_at=utcnow())
                session.add(row)
            else:
                row.value_json = value
                row.updated_at = utcnow()
            session.commit()

