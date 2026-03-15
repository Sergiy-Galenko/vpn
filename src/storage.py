from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from src.models import ClientRecord, VPNManagerError


class ClientStorage:
    """Simple SQLite storage for generated client data."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path

    def initialize(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.database_path.exists():
            self.database_path.touch()
            os.chmod(self.database_path, 0o600)

        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS clients (
                    name TEXT PRIMARY KEY,
                    address TEXT NOT NULL UNIQUE,
                    public_key TEXT NOT NULL UNIQUE,
                    private_key TEXT NOT NULL,
                    config_path TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.commit()

    def add_client(self, client: ClientRecord) -> None:
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO clients (
                        name,
                        address,
                        public_key,
                        private_key,
                        config_path,
                        created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        client.name,
                        client.address,
                        client.public_key,
                        client.private_key,
                        client.config_path,
                        client.created_at,
                    ),
                )
                connection.commit()
        except sqlite3.IntegrityError as exc:
            raise VPNManagerError(
                f"Client '{client.name}' already exists or its address/key is already in use."
            ) from exc

    def get_client(self, name: str) -> ClientRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM clients WHERE name = ?",
                (name,),
            ).fetchone()
        return self._row_to_client(row) if row else None

    def get_client_by_public_key(self, public_key: str) -> ClientRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM clients WHERE public_key = ?",
                (public_key,),
            ).fetchone()
        return self._row_to_client(row) if row else None

    def list_clients(self) -> list[ClientRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM clients ORDER BY name ASC"
            ).fetchall()
        return [self._row_to_client(row) for row in rows]

    def remove_client(self, name: str) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM clients WHERE name = ?",
                (name,),
            )
            connection.commit()

        if cursor.rowcount == 0:
            raise VPNManagerError(f"Client '{name}' was not found.")

    def used_addresses(self) -> set[str]:
        with self._connect() as connection:
            rows = connection.execute("SELECT address FROM clients").fetchall()
        return {row["address"] for row in rows}

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _row_to_client(row: sqlite3.Row) -> ClientRecord:
        return ClientRecord(
            name=row["name"],
            address=row["address"],
            public_key=row["public_key"],
            private_key=row["private_key"],
            config_path=row["config_path"],
            created_at=row["created_at"],
        )
