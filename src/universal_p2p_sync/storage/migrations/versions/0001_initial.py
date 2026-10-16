"""Initial synchronization store (identity trust, groups, change log).

Revision ID: 0001
Revises:
Create Date: 2026-10-15
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    schema = context.config.attributes["schema"]
    op.create_table(
        "node_meta",
        sa.Column("key", sa.Text, primary_key=True),
        sa.Column("value", sa.Text, nullable=False),
        schema=schema,
    )
    op.create_table(
        "trusted_devices",
        sa.Column("device_id", sa.Text, primary_key=True),
        sa.Column("public_key", sa.LargeBinary, nullable=False),
        sa.Column("device_name", sa.Text, nullable=False),
        sa.Column("paired_at", TS, nullable=False),
        sa.Column("revoked_at", TS),
        sa.Column("last_seen_at", TS),
        sa.Column("last_address", sa.Text),
        sa.Column("last_port", sa.Integer),
        schema=schema,
    )
    op.create_table(
        "groups",
        sa.Column("group_id", sa.Text, primary_key=True),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("next_seq", sa.BigInteger, nullable=False, server_default="1"),
        schema=schema,
    )
    op.create_table(
        "membership_ops",
        sa.Column("op_id", sa.Text, primary_key=True),
        sa.Column("group_id", sa.Text, nullable=False),
        sa.Column("author", sa.Text, nullable=False),
        sa.Column("lamport", sa.BigInteger, nullable=False),
        sa.Column("kind", sa.Text, nullable=False),
        sa.Column("op", JSONB, nullable=False),
        sa.Column("signature", sa.Text, nullable=False),
        sa.Column("received_at", TS, nullable=False),
        schema=schema,
    )
    op.create_index(
        "ix_membership_ops_group_id", "membership_ops", ["group_id"], schema=schema
    )
    op.create_table(
        "group_keys",
        sa.Column("group_id", sa.Text, nullable=False),
        sa.Column("key_id", sa.Text, nullable=False),
        sa.Column("key", sa.LargeBinary, nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.PrimaryKeyConstraint("group_id", "key_id"),
        schema=schema,
    )
    op.create_table(
        "invites",
        sa.Column("invite_id", sa.Text, primary_key=True),
        sa.Column("direction", sa.Text, nullable=False),
        sa.Column("group_id", sa.Text, nullable=False),
        sa.Column("group_name", sa.Text, nullable=False),
        sa.Column("role", sa.Text, nullable=False),
        sa.Column("inviter_device_id", sa.Text, nullable=False),
        sa.Column("invitee_device_id", sa.Text),
        sa.Column("token_hash", sa.Text),
        sa.Column("secret", sa.Text),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("max_uses", sa.Integer, nullable=False),
        sa.Column("uses", sa.Integer, nullable=False, server_default="0"),
        sa.Column("status", sa.Text, nullable=False),
        sa.Column("delivered", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("created_at", TS, nullable=False),
        schema=schema,
    )
    op.create_table(
        "changes",
        sa.Column("change_id", sa.Text, primary_key=True),
        sa.Column("group_id", sa.Text, nullable=False),
        sa.Column("author", sa.Text, nullable=False),
        sa.Column("seq", sa.BigInteger, nullable=False),
        sa.Column("hlc", sa.BigInteger, nullable=False),
        sa.Column("collection", sa.Text, nullable=False),
        sa.Column("record_id", sa.Text, nullable=False),
        sa.Column("op", sa.Text, nullable=False),
        sa.Column("body", JSONB, nullable=False),
        sa.Column("valid", sa.Boolean, nullable=False),
        sa.Column("received_at", TS, nullable=False),
        sa.UniqueConstraint("group_id", "author", "seq", name="uq_changes_author_seq"),
        schema=schema,
    )
    op.create_index(
        "ix_changes_record", "changes", ["group_id", "collection", "record_id"], schema=schema
    )
    op.create_table(
        "records",
        sa.Column("group_id", sa.Text, nullable=False),
        sa.Column("collection", sa.Text, nullable=False),
        sa.Column("record_id", sa.Text, nullable=False),
        sa.Column("data", JSONB),
        sa.Column("deleted", sa.Boolean, nullable=False),
        sa.Column("version", sa.Text, nullable=False),
        sa.Column("heads", JSONB, nullable=False),
        sa.Column("hlc", sa.BigInteger, nullable=False),
        sa.Column("author", sa.Text, nullable=False),
        sa.Column("in_conflict", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("updated_at", TS, nullable=False),
        sa.PrimaryKeyConstraint("group_id", "collection", "record_id"),
        schema=schema,
    )
    op.create_table(
        "conflicts",
        sa.Column("conflict_id", sa.Text, primary_key=True),
        sa.Column("group_id", sa.Text, nullable=False),
        sa.Column("collection", sa.Text, nullable=False),
        sa.Column("record_id", sa.Text, nullable=False),
        sa.Column("heads", JSONB, nullable=False),
        sa.Column("versions", JSONB, nullable=False),
        sa.Column("winner", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False),
        sa.Column("resolution", sa.Text),
        sa.Column("detected_at", TS, nullable=False),
        sa.Column("resolved_at", TS),
        schema=schema,
    )
    op.create_index(
        "ix_conflicts_record", "conflicts", ["group_id", "collection", "record_id"], schema=schema
    )
    op.create_table(
        "checkpoints",
        sa.Column("group_id", sa.Text, nullable=False),
        sa.Column("device_id", sa.Text, nullable=False),
        sa.Column("vector", JSONB, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.PrimaryKeyConstraint("group_id", "device_id"),
        schema=schema,
    )
    op.create_table(
        "outbox",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("group_id", sa.Text, nullable=False),
        sa.Column("collection", sa.Text, nullable=False),
        sa.Column("record_id", sa.Text, nullable=False),
        sa.Column("op", sa.Text, nullable=False),
        sa.Column("data", JSONB),
        sa.Column("created_at", TS, nullable=False),
        schema=schema,
    )


def downgrade() -> None:
    schema = context.config.attributes["schema"]
    for table in (
        "outbox",
        "checkpoints",
        "conflicts",
        "records",
        "changes",
        "invites",
        "group_keys",
        "membership_ops",
        "groups",
        "trusted_devices",
        "node_meta",
    ):
        op.drop_table(table, schema=schema)
