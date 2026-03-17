from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import os
import sqlite3
from pathlib import Path

from src.models import ClientRecord, VPNManagerError
from src.utils import write_text_file


class ClientStorage:
    """Simple SQLite storage for generated client data."""

    def __init__(self, database_path: Path, client_private_keys_dir: Path) -> None:
        self.database_path = database_path
        self.client_private_keys_dir = client_private_keys_dir

    def initialize(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.client_private_keys_dir.mkdir(parents=True, exist_ok=True)
        if not self.database_path.exists():
            self.database_path.touch()
        os.chmod(self.database_path, 0o600)

        with self._connection() as connection:
            columns = self._get_client_columns(connection)
            if not columns:
                self._create_schema(connection)
            elif columns == {
                "name",
                "address",
                "public_key",
                "config_path",
                "private_key_path",
                "created_at",
            }:
                pass
            elif columns == {
                "name",
                "address",
                "public_key",
                "private_key",
                "config_path",
                "created_at",
            }:
                self._migrate_legacy_private_keys(connection)
            else:
                raise VPNManagerError(
                    "Unsupported clients table schema. Back up data/vpn.sqlite3 and recreate the database."
                )
            connection.commit()

    def add_client(self, client: ClientRecord) -> None:
        try:
            with self._connection() as connection:
                connection.execute(
                    """
                    INSERT INTO clients (
                        name,
                        address,
                        public_key,
                        config_path,
                        private_key_path,
                        created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        client.name,
                        client.address,
                        client.public_key,
                        client.config_path,
                        client.private_key_path,
                        client.created_at,
                    ),
                )
                connection.commit()
        except sqlite3.IntegrityError as exc:
            raise VPNManagerError(
                f"Client '{client.name}' already exists or its address/key is already in use."
            ) from exc

    def get_client(self, name: str) -> ClientRecord | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM clients WHERE name = ?",
                (name,),
            ).fetchone()
        return self._row_to_client(row) if row else None

    def get_client_by_public_key(self, public_key: str) -> ClientRecord | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM clients WHERE public_key = ?",
                (public_key,),
            ).fetchone()
        return self._row_to_client(row) if row else None

    def list_clients(self) -> list[ClientRecord]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM clients ORDER BY name ASC"
            ).fetchall()
        return [self._row_to_client(row) for row in rows]

    def remove_client(self, name: str) -> None:
        with self._connection() as connection:
            cursor = connection.execute(
                "DELETE FROM clients WHERE name = ?",
                (name,),
            )
            connection.commit()

        if cursor.rowcount == 0:
            raise VPNManagerError(f"Client '{name}' was not found.")

    def used_addresses(self) -> set[str]:
        with self._connection() as connection:
            rows = connection.execute("SELECT address FROM clients").fetchall()
        return {row["address"] for row in rows}

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    @staticmethod
    def _row_to_client(row: sqlite3.Row) -> ClientRecord:
        return ClientRecord(
            name=row["name"],
            address=row["address"],
            public_key=row["public_key"],
            config_path=row["config_path"],
            private_key_path=row["private_key_path"],
            created_at=row["created_at"],
        )

    def _create_schema(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS clients (
                name TEXT PRIMARY KEY,
                address TEXT NOT NULL UNIQUE,
                public_key TEXT NOT NULL UNIQUE,
                config_path TEXT NOT NULL,
                private_key_path TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )

    def _migrate_legacy_private_keys(self, connection: sqlite3.Connection) -> None:
        rows = connection.execute(
            """
            SELECT
                name,
                address,
                public_key,
                private_key,
                config_path,
                created_at
            FROM clients
            ORDER BY name ASC
            """
        ).fetchall()

        connection.execute("DROP TABLE IF EXISTS clients_new")
        self._create_schema_for_table(connection, "clients_new")

        for row in rows:
            private_key = (row["private_key"] or "").strip()
            if not private_key:
                raise VPNManagerError(
                    f"Legacy client '{row['name']}' has an empty private key and cannot be migrated safely."
                )

            private_key_path = self._client_private_key_path(row["name"])
            if private_key_path.exists():
                existing_key = private_key_path.read_text(encoding="utf-8").strip()
                if existing_key != private_key:
                    raise VPNManagerError(
                        f"Private key file mismatch for migrated client '{row['name']}'."
                    )
            else:
                write_text_file(private_key_path, f"{private_key}\n")

            connection.execute(
                """
                INSERT INTO clients_new (
                    name,
                    address,
                    public_key,
                    config_path,
                    private_key_path,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    row["name"],
                    row["address"],
                    row["public_key"],
                    row["config_path"],
                    str(private_key_path),
                    row["created_at"],
                ),
            )

        connection.execute("DROP TABLE clients")
        connection.execute("ALTER TABLE clients_new RENAME TO clients")

    @staticmethod
    def _create_schema_for_table(connection: sqlite3.Connection, table_name: str) -> None:
        connection.execute(
            f"""
            CREATE TABLE {table_name} (
                name TEXT PRIMARY KEY,
                address TEXT NOT NULL UNIQUE,
                public_key TEXT NOT NULL UNIQUE,
                config_path TEXT NOT NULL,
                private_key_path TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )

    @staticmethod
    def _get_client_columns(connection: sqlite3.Connection) -> set[str]:
        rows = connection.execute("PRAGMA table_info(clients)").fetchall()
        return {row["name"] for row in rows}

    def _client_private_key_path(self, client_name: str) -> Path:
        return self.client_private_keys_dir / f"{client_name}.key"
