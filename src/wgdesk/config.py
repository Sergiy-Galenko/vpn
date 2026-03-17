from __future__ import annotations

import os
import platform
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


def _default_state_dir() -> Path:
    home = Path.home()
    system = platform.system()
    if system == "Darwin":
        return home / "Library" / "Application Support" / "WGDesk"
    if system == "Windows":
        appdata = Path(os.getenv("APPDATA", home))
        return appdata / "WGDesk"
    return home / ".wgdesk"


@dataclass(slots=True)
class AppConfig:
    project_root: Path
    state_dir: Path
    data_dir: Path
    log_dir: Path
    export_dir: Path
    backup_dir: Path
    vault_dir: Path
    sqlite_path: Path
    alembic_ini_path: Path
    migrations_dir: Path
    assets_dir: Path
    icons_dir: Path
    qss_dir: Path
    fonts_dir: Path
    log_level: str
    agent_timeout_sec: int
    dashboard_poll_interval_ms: int
    app_name: str = "WGDesk"
    organization_name: str = "WGDesk"

    def ensure_directories(self) -> None:
        for directory in (
            self.state_dir,
            self.data_dir,
            self.log_dir,
            self.export_dir,
            self.backup_dir,
            self.vault_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)


def load_config(base_dir: Path | None = None) -> AppConfig:
    package_root = Path(__file__).resolve().parent
    project_root = base_dir or package_root.parents[1]
    load_dotenv(project_root / ".env")
    assets_dir = project_root / "assets"
    if not assets_dir.exists():
        assets_dir = package_root / "assets"

    state_dir = Path(os.getenv("WGDESK_STATE_DIR", _default_state_dir()))
    data_dir = state_dir / "data"
    log_dir = state_dir / "logs"
    export_dir = state_dir / "exports"
    backup_dir = state_dir / "backups"
    vault_dir = state_dir / "vault"

    config = AppConfig(
        project_root=project_root,
        state_dir=state_dir,
        data_dir=data_dir,
        log_dir=log_dir,
        export_dir=export_dir,
        backup_dir=backup_dir,
        vault_dir=vault_dir,
        sqlite_path=data_dir / "wgdesk.sqlite3",
        alembic_ini_path=project_root / "alembic.ini",
        migrations_dir=package_root / "infrastructure" / "db" / "migrations",
        assets_dir=assets_dir,
        icons_dir=assets_dir / "icons",
        qss_dir=assets_dir / "qss",
        fonts_dir=assets_dir / "fonts",
        log_level=os.getenv("WGDESK_LOG_LEVEL", "INFO"),
        agent_timeout_sec=int(os.getenv("WGDESK_AGENT_TIMEOUT_SEC", "20")),
        dashboard_poll_interval_ms=int(
            os.getenv("WGDESK_DASHBOARD_POLL_MS", "10000")
        ),
    )
    config.ensure_directories()
    return config
