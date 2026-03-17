from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "server_profiles",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("mode", sa.String(length=32), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=True),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=255), nullable=True),
        sa.Column("auth_method", sa.String(length=32), nullable=False),
        sa.Column("private_key_path", sa.String(length=1024), nullable=True),
        sa.Column("password_secret_ref", sa.String(length=255), nullable=True),
        sa.Column("private_key_passphrase_ref", sa.String(length=255), nullable=True),
        sa.Column("sudo_mode", sa.String(length=32), nullable=False),
        sa.Column("sudo_password_secret_ref", sa.String(length=255), nullable=True),
        sa.Column("known_host_fingerprint", sa.String(length=255), nullable=True),
        sa.Column("connect_timeout_sec", sa.Integer(), nullable=False),
        sa.Column("is_default", sa.Boolean(), nullable=False),
        sa.Column("last_connected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", name="uq_server_profiles_name"),
    )

    op.create_table(
        "server_configs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("server_profile_id", sa.String(length=36), nullable=False),
        sa.Column("interface_name", sa.String(length=64), nullable=False),
        sa.Column("endpoint", sa.String(length=255), nullable=False),
        sa.Column("listen_port", sa.Integer(), nullable=False),
        sa.Column("subnet_cidr", sa.String(length=64), nullable=False),
        sa.Column("public_interface", sa.String(length=64), nullable=False),
        sa.Column("dns_json", sa.JSON(), nullable=False),
        sa.Column("allowed_ips_json", sa.JSON(), nullable=False),
        sa.Column("firewall_backend", sa.String(length=32), nullable=True),
        sa.Column("config_source", sa.String(length=32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("server_profile_id", name="uq_server_configs_server_profile_id"),
    )
    op.create_index(
        "ix_server_configs_server_profile_id",
        "server_configs",
        ["server_profile_id"],
        unique=False,
    )

    op.create_table(
        "clients",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("server_profile_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=True),
        sa.Column("device", sa.String(length=255), nullable=True),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("address_cidr", sa.String(length=64), nullable=False),
        sa.Column("public_key", sa.String(length=255), nullable=False),
        sa.Column("preshared_key_secret_ref", sa.String(length=255), nullable=True),
        sa.Column("private_key_secret_ref", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("expiry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("imported", sa.Boolean(), nullable=False),
        sa.Column("latest_config_revision", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("server_profile_id", "address_cidr", name="uq_clients_profile_address_cidr"),
        sa.UniqueConstraint("server_profile_id", "name", name="uq_clients_profile_name"),
        sa.UniqueConstraint("server_profile_id", "public_key", name="uq_clients_profile_public_key"),
    )
    op.create_index("ix_clients_name", "clients", ["name"], unique=False)
    op.create_index("ix_clients_server_profile_id", "clients", ["server_profile_id"], unique=False)

    op.create_table(
        "client_config_revisions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("client_id", sa.String(length=36), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("config_secret_ref", sa.String(length=255), nullable=True),
        sa.Column("qr_png_path", sa.String(length=1024), nullable=True),
        sa.Column("reason", sa.String(length=64), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("client_id", "revision", name="uq_client_config_revisions_client_revision"),
    )
    op.create_index(
        "ix_client_config_revisions_client_id",
        "client_config_revisions",
        ["client_id"],
        unique=False,
    )

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("server_profile_id", sa.String(length=36), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(length=255), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("target_type", sa.String(length=64), nullable=False),
        sa.Column("target_id", sa.String(length=36), nullable=True),
        sa.Column("result", sa.String(length=32), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("error_code", sa.String(length=128), nullable=True),
        sa.Column("error_details_json", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_logs_server_profile_id", "audit_logs", ["server_profile_id"], unique=False)

    op.create_table(
        "backups",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("server_profile_id", sa.String(length=36), nullable=False),
        sa.Column("archive_path", sa.String(length=1024), nullable=False),
        sa.Column("manifest_sha256", sa.String(length=128), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("includes_logs", sa.Boolean(), nullable=False),
        sa.Column("includes_secrets", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("restore_tested", sa.Boolean(), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_backups_server_profile_id", "backups", ["server_profile_id"], unique=False)

    op.create_table(
        "key_rotations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("server_profile_id", sa.String(length=36), nullable=False),
        sa.Column("client_id", sa.String(length=36), nullable=True),
        sa.Column("scope", sa.String(length=32), nullable=False),
        sa.Column("previous_revision", sa.Integer(), nullable=True),
        sa.Column("new_revision", sa.Integer(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result", sa.String(length=64), nullable=False),
        sa.Column("backup_id", sa.String(length=36), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_key_rotations_client_id", "key_rotations", ["client_id"], unique=False)
    op.create_index("ix_key_rotations_server_profile_id", "key_rotations", ["server_profile_id"], unique=False)

    op.create_table(
        "imported_peers",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("server_profile_id", sa.String(length=36), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_path", sa.String(length=1024), nullable=False),
        sa.Column("peer_public_key", sa.String(length=255), nullable=False),
        sa.Column("parsed_name", sa.String(length=255), nullable=True),
        sa.Column("inferred_address", sa.String(length=64), nullable=True),
        sa.Column("matched_client_id", sa.String(length=36), nullable=True),
        sa.Column("import_status", sa.String(length=64), nullable=False),
        sa.Column("raw_block_text", sa.Text(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_imported_peers_server_profile_id", "imported_peers", ["server_profile_id"], unique=False)

    op.create_table(
        "health_snapshots",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("server_profile_id", sa.String(length=36), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("service_state", sa.String(length=32), nullable=False),
        sa.Column("uptime_seconds", sa.Integer(), nullable=True),
        sa.Column("active_peers", sa.Integer(), nullable=False),
        sa.Column("rx_bytes", sa.Integer(), nullable=False),
        sa.Column("tx_bytes", sa.Integer(), nullable=False),
        sa.Column("recent_error_count", sa.Integer(), nullable=False),
        sa.Column("metrics_json", sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_health_snapshots_server_profile_id",
        "health_snapshots",
        ["server_profile_id"],
        unique=False,
    )

    op.create_table(
        "settings",
        sa.Column("key", sa.String(length=255), nullable=False),
        sa.Column("value_json", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )


def downgrade() -> None:
    op.drop_table("settings")
    op.drop_index("ix_health_snapshots_server_profile_id", table_name="health_snapshots")
    op.drop_table("health_snapshots")
    op.drop_index("ix_imported_peers_server_profile_id", table_name="imported_peers")
    op.drop_table("imported_peers")
    op.drop_index("ix_key_rotations_server_profile_id", table_name="key_rotations")
    op.drop_index("ix_key_rotations_client_id", table_name="key_rotations")
    op.drop_table("key_rotations")
    op.drop_index("ix_backups_server_profile_id", table_name="backups")
    op.drop_table("backups")
    op.drop_index("ix_audit_logs_server_profile_id", table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_index("ix_client_config_revisions_client_id", table_name="client_config_revisions")
    op.drop_table("client_config_revisions")
    op.drop_index("ix_clients_server_profile_id", table_name="clients")
    op.drop_index("ix_clients_name", table_name="clients")
    op.drop_table("clients")
    op.drop_index("ix_server_configs_server_profile_id", table_name="server_configs")
    op.drop_table("server_configs")
    op.drop_table("server_profiles")
