from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import os
import sqlite3
from pathlib import Path

from src.models import (
    AuditLogRecord,
    AuthMethod,
    BackupRecord,
    ClientRecord,
    ClientStatus,
    ImportedPeerRecord,
    RemoteProfileRecord,
    VPNManagerError,
)
from src.utils import utc_now_iso, write_text_file


CLIENT_TABLE_COLUMNS = {
    "name",
    "address",
    "public_key",
    "config_path",
    "private_key_path",
    "created_at",
    "email",
    "device",
    "comment",
    "status",
    "expiry_at",
    "updated_at",
    "last_used_at",
    "imported",
    "qr_code_path",
    "config_revision",
}


class ClientStorage:
    """SQLite storage for clients, remote settings, audit log, and backups."""

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
            self._ensure_clients_schema(connection)
            self._create_audit_schema(connection)
            self._create_backups_schema(connection)
            self._create_remote_profile_schema(connection)
            self._create_imported_peers_schema(connection)
            connection.commit()

    def add_client(self, client: ClientRecord) -> None:
        client = self._normalize_client(client)
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
                        created_at,
                        email,
                        device,
                        comment,
                        status,
                        expiry_at,
                        updated_at,
                        last_used_at,
                        imported,
                        qr_code_path,
                        config_revision
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        client.name,
                        client.address,
                        client.public_key,
                        client.config_path,
                        client.private_key_path,
                        client.created_at,
                        client.email,
                        client.device,
                        client.comment,
                        client.status.value,
                        client.expiry_at,
                        client.updated_at,
                        client.last_used_at,
                        int(client.imported),
                        client.qr_code_path,
                        client.config_revision,
                    ),
                )
                connection.commit()
        except sqlite3.IntegrityError as exc:
            raise VPNManagerError(
                f"Client '{client.name}' already exists or its address/key is already in use."
            ) from exc

    def update_client(self, client: ClientRecord) -> None:
        client = self._normalize_client(client)
        with self._connection() as connection:
            cursor = connection.execute(
                """
                UPDATE clients
                SET
                    address = ?,
                    public_key = ?,
                    config_path = ?,
                    private_key_path = ?,
                    email = ?,
                    device = ?,
                    comment = ?,
                    status = ?,
                    expiry_at = ?,
                    updated_at = ?,
                    last_used_at = ?,
                    imported = ?,
                    qr_code_path = ?,
                    config_revision = ?
                WHERE name = ?
                """,
                (
                    client.address,
                    client.public_key,
                    client.config_path,
                    client.private_key_path,
                    client.email,
                    client.device,
                    client.comment,
                    client.status.value,
                    client.expiry_at,
                    client.updated_at,
                    client.last_used_at,
                    int(client.imported),
                    client.qr_code_path,
                    client.config_revision,
                    client.name,
                ),
            )
            connection.commit()

        if cursor.rowcount == 0:
            raise VPNManagerError(f"Client '{client.name}' was not found.")

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

    def set_client_status(self, name: str, status: ClientStatus) -> ClientRecord:
        updated_at = utc_now_iso()
        with self._connection() as connection:
            cursor = connection.execute(
                """
                UPDATE clients
                SET status = ?, updated_at = ?
                WHERE name = ?
                """,
                (status.value, updated_at, name),
            )
            connection.commit()

        if cursor.rowcount == 0:
            raise VPNManagerError(f"Client '{name}' was not found.")
        client = self.get_client(name)
        if client is None:
            raise VPNManagerError(f"Client '{name}' could not be reloaded.")
        return client

    def update_client_export_paths(
        self,
        name: str,
        *,
        config_path: str | None = None,
        private_key_path: str | None = None,
        qr_code_path: str | None = None,
        config_revision: int | None = None,
    ) -> ClientRecord:
        client = self.get_client(name)
        if client is None:
            raise VPNManagerError(f"Client '{name}' was not found.")

        if config_path is not None:
            client.config_path = config_path
        if private_key_path is not None:
            client.private_key_path = private_key_path
        if qr_code_path is not None:
            client.qr_code_path = qr_code_path
        if config_revision is not None:
            client.config_revision = config_revision
        client.updated_at = utc_now_iso()
        self.update_client(client)
        return client

    def update_client_metadata(
        self,
        name: str,
        *,
        email: str | None,
        device: str | None,
        comment: str | None,
        expiry_at: str | None,
    ) -> ClientRecord:
        client = self.get_client(name)
        if client is None:
            raise VPNManagerError(f"Client '{name}' was not found.")

        client.email = email
        client.device = device
        client.comment = comment
        client.expiry_at = expiry_at
        client.updated_at = utc_now_iso()
        self.update_client(client)
        return client

    def mark_client_last_used(self, public_key: str, timestamp: str) -> None:
        with self._connection() as connection:
            connection.execute(
                """
                UPDATE clients
                SET last_used_at = ?, updated_at = ?
                WHERE public_key = ?
                """,
                (timestamp, timestamp, public_key),
            )
            connection.commit()

    def used_addresses(self) -> set[str]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT address
                FROM clients
                """,
            ).fetchall()
        return {row["address"] for row in rows}

    def save_remote_profile(self, profile: RemoteProfileRecord) -> None:
        profile.updated_at = profile.updated_at or utc_now_iso()
        profile.created_at = profile.created_at or profile.updated_at
        with self._connection() as connection:
            connection.execute("DELETE FROM remote_profiles")
            connection.execute(
                """
                INSERT INTO remote_profiles (
                    name,
                    host,
                    port,
                    username,
                    auth_method,
                    private_key_path,
                    password_secret_key,
                    sudo_password_secret_key,
                    known_host_fingerprint,
                    connect_timeout_seconds,
                    enabled,
                    use_sudo,
                    created_at,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    profile.name,
                    profile.host,
                    profile.port,
                    profile.username,
                    profile.auth_method.value,
                    profile.private_key_path,
                    profile.password_secret_key,
                    profile.sudo_password_secret_key,
                    profile.known_host_fingerprint,
                    profile.connect_timeout_seconds,
                    int(profile.enabled),
                    int(profile.use_sudo),
                    profile.created_at,
                    profile.updated_at,
                ),
            )
            connection.commit()

    def get_remote_profile(self) -> RemoteProfileRecord | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM remote_profiles ORDER BY updated_at DESC LIMIT 1"
            ).fetchone()
        return self._row_to_remote_profile(row) if row else None

    def clear_remote_profile(self) -> None:
        with self._connection() as connection:
            connection.execute("DELETE FROM remote_profiles")
            connection.commit()

    def add_audit_log(self, record: AuditLogRecord) -> None:
        with self._connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO audit_logs (
                    timestamp,
                    action,
                    actor,
                    source,
                    target,
                    result,
                    details,
                    error_details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.timestamp,
                    record.action,
                    record.actor,
                    record.source,
                    record.target,
                    record.result,
                    record.details,
                    record.error_details,
                ),
            )
            connection.commit()
        record.log_id = cursor.lastrowid

    def list_audit_logs(self, limit: int = 200) -> list[AuditLogRecord]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM audit_logs
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._row_to_audit_log(row) for row in rows]

    def add_backup(self, record: BackupRecord) -> None:
        with self._connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO backups (
                    archive_path,
                    created_at,
                    manifest_json,
                    scope,
                    note
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    record.archive_path,
                    record.created_at,
                    record.manifest_json,
                    record.scope,
                    record.note,
                ),
            )
            connection.commit()
        record.backup_id = cursor.lastrowid

    def list_backups(self, limit: int = 200) -> list[BackupRecord]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM backups
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._row_to_backup(row) for row in rows]

    def add_imported_peer(self, record: ImportedPeerRecord) -> None:
        with self._connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO imported_peers (
                    imported_at,
                    source_path,
                    public_key,
                    address,
                    inferred_name,
                    raw_block
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    record.imported_at,
                    record.source_path,
                    record.public_key,
                    record.address,
                    record.inferred_name,
                    record.raw_block,
                ),
            )
            connection.commit()
        record.peer_id = cursor.lastrowid

    def clear_imported_peers(self) -> None:
        with self._connection() as connection:
            connection.execute("DELETE FROM imported_peers")
            connection.commit()

    def list_imported_peers(self, limit: int = 500) -> list[ImportedPeerRecord]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM imported_peers
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._row_to_imported_peer(row) for row in rows]

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
    def _normalize_client(client: ClientRecord) -> ClientRecord:
        client.created_at = client.created_at or utc_now_iso()
        client.updated_at = client.updated_at or client.created_at
        return client

    @staticmethod
    def _row_to_client(row: sqlite3.Row) -> ClientRecord:
        return ClientRecord(
            name=row["name"],
            address=row["address"],
            public_key=row["public_key"],
            config_path=row["config_path"],
            private_key_path=row["private_key_path"],
            created_at=row["created_at"],
            email=row["email"],
            device=row["device"],
            comment=row["comment"],
            status=ClientStatus(row["status"]),
            expiry_at=row["expiry_at"],
            updated_at=row["updated_at"],
            last_used_at=row["last_used_at"],
            imported=bool(row["imported"]),
            qr_code_path=row["qr_code_path"],
            config_revision=row["config_revision"],
        )

    @staticmethod
    def _row_to_remote_profile(row: sqlite3.Row) -> RemoteProfileRecord:
        return RemoteProfileRecord(
            name=row["name"],
            host=row["host"],
            port=row["port"],
            username=row["username"],
            auth_method=AuthMethod(row["auth_method"]),
            private_key_path=row["private_key_path"],
            password_secret_key=row["password_secret_key"],
            sudo_password_secret_key=row["sudo_password_secret_key"],
            known_host_fingerprint=row["known_host_fingerprint"],
            connect_timeout_seconds=row["connect_timeout_seconds"],
            enabled=bool(row["enabled"]),
            use_sudo=bool(row["use_sudo"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    @staticmethod
    def _row_to_audit_log(row: sqlite3.Row) -> AuditLogRecord:
        return AuditLogRecord(
            log_id=row["id"],
            timestamp=row["timestamp"],
            action=row["action"],
            actor=row["actor"],
            source=row["source"],
            target=row["target"],
            result=row["result"],
            details=row["details"],
            error_details=row["error_details"],
        )

    @staticmethod
    def _row_to_backup(row: sqlite3.Row) -> BackupRecord:
        return BackupRecord(
            backup_id=row["id"],
            archive_path=row["archive_path"],
            created_at=row["created_at"],
            manifest_json=row["manifest_json"],
            scope=row["scope"],
            note=row["note"],
        )

    @staticmethod
    def _row_to_imported_peer(row: sqlite3.Row) -> ImportedPeerRecord:
        return ImportedPeerRecord(
            peer_id=row["id"],
            imported_at=row["imported_at"],
            source_path=row["source_path"],
            public_key=row["public_key"],
            address=row["address"],
            inferred_name=row["inferred_name"],
            raw_block=row["raw_block"],
        )

    def _ensure_clients_schema(self, connection: sqlite3.Connection) -> None:
        columns = self._get_client_columns(connection)
        if not columns:
            self._create_client_schema(connection)
            return

        if columns != CLIENT_TABLE_COLUMNS:
            self._migrate_clients_table(connection)

    def _create_client_schema(self, connection: sqlite3.Connection, table_name: str = "clients") -> None:
        connection.execute(
            f"""
            CREATE TABLE {table_name} (
                name TEXT PRIMARY KEY,
                address TEXT NOT NULL UNIQUE,
                public_key TEXT NOT NULL UNIQUE,
                config_path TEXT,
                private_key_path TEXT,
                created_at TEXT NOT NULL,
                email TEXT,
                device TEXT,
                comment TEXT,
                status TEXT NOT NULL,
                expiry_at TEXT,
                updated_at TEXT NOT NULL,
                last_used_at TEXT,
                imported INTEGER NOT NULL DEFAULT 0,
                qr_code_path TEXT,
                config_revision INTEGER NOT NULL DEFAULT 1
            )
            """
        )

    def _create_audit_schema(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                source TEXT NOT NULL,
                target TEXT NOT NULL,
                result TEXT NOT NULL,
                details TEXT NOT NULL,
                error_details TEXT
            )
            """
        )

    def _create_backups_schema(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS backups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                archive_path TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                manifest_json TEXT NOT NULL,
                scope TEXT NOT NULL,
                note TEXT
            )
            """
        )

    def _create_remote_profile_schema(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS remote_profiles (
                name TEXT PRIMARY KEY,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                username TEXT NOT NULL,
                auth_method TEXT NOT NULL,
                private_key_path TEXT,
                password_secret_key TEXT,
                sudo_password_secret_key TEXT,
                known_host_fingerprint TEXT,
                connect_timeout_seconds INTEGER NOT NULL DEFAULT 10,
                enabled INTEGER NOT NULL DEFAULT 1,
                use_sudo INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )

    def _create_imported_peers_schema(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS imported_peers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                imported_at TEXT NOT NULL,
                source_path TEXT NOT NULL,
                public_key TEXT NOT NULL,
                address TEXT,
                inferred_name TEXT,
                raw_block TEXT NOT NULL
            )
            """
        )

    def _migrate_clients_table(self, connection: sqlite3.Connection) -> None:
        rows = connection.execute("SELECT * FROM clients ORDER BY name ASC").fetchall()
        connection.execute("DROP TABLE IF EXISTS clients_new")
        self._create_client_schema(connection, "clients_new")

        for row in rows:
            row_keys = set(row.keys())
            name = row["name"]
            private_key_path = row["private_key_path"] if "private_key_path" in row_keys else None
            if not private_key_path and "private_key" in row_keys:
                private_key = (row["private_key"] or "").strip()
                if private_key:
                    private_key_path = str(self._client_private_key_path(name))
                    write_text_file(Path(private_key_path), f"{private_key}\n")

            created_at = row["created_at"] if "created_at" in row_keys else utc_now_iso()
            updated_at = row["updated_at"] if "updated_at" in row_keys else created_at

            connection.execute(
                """
                INSERT INTO clients_new (
                    name,
                    address,
                    public_key,
                    config_path,
                    private_key_path,
                    created_at,
                    email,
                    device,
                    comment,
                    status,
                    expiry_at,
                    updated_at,
                    last_used_at,
                    imported,
                    qr_code_path,
                    config_revision
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name,
                    row["address"],
                    row["public_key"],
                    row["config_path"] if "config_path" in row_keys else None,
                    private_key_path,
                    created_at,
                    row["email"] if "email" in row_keys else None,
                    row["device"] if "device" in row_keys else None,
                    row["comment"] if "comment" in row_keys else None,
                    row["status"] if "status" in row_keys else ClientStatus.ACTIVE.value,
                    row["expiry_at"] if "expiry_at" in row_keys else None,
                    updated_at,
                    row["last_used_at"] if "last_used_at" in row_keys else None,
                    int(row["imported"]) if "imported" in row_keys else 0,
                    row["qr_code_path"] if "qr_code_path" in row_keys else None,
                    int(row["config_revision"]) if "config_revision" in row_keys else 1,
                ),
            )

        connection.execute("DROP TABLE clients")
        connection.execute("ALTER TABLE clients_new RENAME TO clients")

    @staticmethod
    def _get_client_columns(connection: sqlite3.Connection) -> set[str]:
        rows = connection.execute("PRAGMA table_info(clients)").fetchall()
        return {row["name"] for row in rows}

    def _client_private_key_path(self, client_name: str) -> Path:
        return self.client_private_keys_dir / f"{client_name}.key"
