from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from wgdesk.infrastructure.db.models import Base


def build_engine(sqlite_path: Path):
    sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    return create_engine(
        f"sqlite+pysqlite:///{sqlite_path}",
        future=True,
        echo=False,
    )


def build_session_factory(engine) -> Callable[[], Session]:
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)
    return factory


def initialize_database(engine) -> None:
    Base.metadata.create_all(bind=engine)


def upgrade_database(
    sqlite_path: Path,
    *,
    alembic_ini_path: Path,
    migrations_dir: Path,
) -> None:
    sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        from alembic import command
        from alembic.config import Config
    except ImportError:
        initialize_database(build_engine(sqlite_path))
        return

    config = Config(str(alembic_ini_path) if alembic_ini_path.exists() else None)
    config.set_main_option("script_location", str(migrations_dir))
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{sqlite_path}")
    command.upgrade(config, "head")
