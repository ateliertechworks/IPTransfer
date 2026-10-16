"""SQLAlchemy Core table definitions for the synchronization store.

Tables are declared without a schema; every connection maps them into the
application's own PostgreSQL schema (``up2p_<app_id>`` by default) through
``schema_translate_map``. Applications therefore never share sync tables, even
in one database. Schema changes are made only through Alembic migrations in
``storage/migrations`` - keep this file and the latest migration in step.
"""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    PrimaryKeyConstraint,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB

metadata = MetaData()

#: Key/value facts about this node (e.g. the device ID that owns the schema).
node_meta = Table(
    "node_meta",
    metadata,
    Column("key", Text, primary_key=True),
    Column("value", Text, nullable=False),
)

#: Devices paired with this one. Revoked devices keep their row (revoked_at set)
#: so their connections are refused.
trusted_devices = Table(
    "trusted_devices",
    metadata,
    Column("device_id", Text, primary_key=True),
    Column("public_key", LargeBinary, nullable=False),
    Column("device_name", Text, nullable=False),
    Column("paired_at", DateTime(timezone=True), nullable=False),
    Column("revoked_at", DateTime(timezone=True)),
    Column("last_seen_at", DateTime(timezone=True)),
    Column("last_address", Text),
    Column("last_port", Integer),
)

#: Groups this device knows about. ``status``: active | left | removed.
groups = Table(
    "groups",
    metadata,
    Column("group_id", Text, primary_key=True),
    Column("name", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    #: Next sequence number for changes authored by this device in the group.
    Column("next_seq", BigInteger, nullable=False, server_default="1"),
)

#: Signed membership operations (the group's authoritative log).
membership_ops = Table(
    "membership_ops",
    metadata,
    Column("op_id", Text, primary_key=True),
    Column("group_id", Text, nullable=False, index=True),
    Column("author", Text, nullable=False),
    Column("lamport", BigInteger, nullable=False),
    Column("kind", Text, nullable=False),
    Column("op", JSONB, nullable=False),
    Column("signature", Text, nullable=False),
    Column("received_at", DateTime(timezone=True), nullable=False),
)

#: Symmetric group keys this device has unsealed.
group_keys = Table(
    "group_keys",
    metadata,
    Column("group_id", Text, nullable=False),
    Column("key_id", Text, nullable=False),
    Column("key", LargeBinary, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    PrimaryKeyConstraint("group_id", "key_id"),
)

#: Invitations created here (outgoing) or received here (incoming).
invites = Table(
    "invites",
    metadata,
    Column("invite_id", Text, primary_key=True),
    Column("direction", Text, nullable=False),  # outgoing | incoming
    Column("group_id", Text, nullable=False),
    Column("group_name", Text, nullable=False),
    Column("role", Text, nullable=False),
    Column("inviter_device_id", Text, nullable=False),
    Column("invitee_device_id", Text),
    #: SHA-256 of the secret (outgoing); the secret itself is never stored.
    Column("token_hash", Text),
    #: Secret presented when accepting (incoming only).
    Column("secret", Text),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("max_uses", Integer, nullable=False),
    Column("uses", Integer, nullable=False, server_default="0"),
    #: pending | accepted | rejected | revoked | expired | joined
    Column("status", Text, nullable=False),
    Column("delivered", Boolean, nullable=False, server_default="false"),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

#: The change log: every signed record change from every author.
changes = Table(
    "changes",
    metadata,
    Column("change_id", Text, primary_key=True),
    Column("group_id", Text, nullable=False),
    Column("author", Text, nullable=False),
    Column("seq", BigInteger, nullable=False),
    Column("hlc", BigInteger, nullable=False),
    Column("collection", Text, nullable=False),
    Column("record_id", Text, nullable=False),
    Column("op", Text, nullable=False),  # put | delete
    #: The complete signed change as sent on the wire (data is encrypted).
    Column("body", JSONB, nullable=False),
    #: Authorized under the current membership view.
    Column("valid", Boolean, nullable=False),
    Column("received_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("group_id", "author", "seq", name="uq_changes_author_seq"),
    Index("ix_changes_record", "group_id", "collection", "record_id"),
)

#: Materialized current state of each record (derived from ``changes``).
records = Table(
    "records",
    metadata,
    Column("group_id", Text, nullable=False),
    Column("collection", Text, nullable=False),
    Column("record_id", Text, nullable=False),
    Column("data", JSONB),
    Column("deleted", Boolean, nullable=False),
    Column("version", Text, nullable=False),
    Column("heads", JSONB, nullable=False),
    Column("hlc", BigInteger, nullable=False),
    Column("author", Text, nullable=False),
    Column("in_conflict", Boolean, nullable=False, server_default="false"),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    PrimaryKeyConstraint("group_id", "collection", "record_id"),
)

#: Detected concurrent modifications and how they were resolved.
conflicts = Table(
    "conflicts",
    metadata,
    Column("conflict_id", Text, primary_key=True),
    Column("group_id", Text, nullable=False),
    Column("collection", Text, nullable=False),
    Column("record_id", Text, nullable=False),
    Column("heads", JSONB, nullable=False),
    Column("versions", JSONB, nullable=False),
    Column("winner", Text, nullable=False),
    Column("status", Text, nullable=False),  # open | resolved | superseded
    Column("resolution", Text),
    Column("detected_at", DateTime(timezone=True), nullable=False),
    Column("resolved_at", DateTime(timezone=True)),
    Index("ix_conflicts_record", "group_id", "collection", "record_id"),
)

#: What each peer has acknowledged per group (per-author contiguous seq vector).
checkpoints = Table(
    "checkpoints",
    metadata,
    Column("group_id", Text, nullable=False),
    Column("device_id", Text, nullable=False),
    Column("vector", JSONB, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    PrimaryKeyConstraint("group_id", "device_id"),
)

#: Transactional outbox: applications insert here in their own transaction.
outbox = Table(
    "outbox",
    metadata,
    Column("id", BigInteger, primary_key=True, autoincrement=True),
    Column("group_id", Text, nullable=False),
    Column("collection", Text, nullable=False),
    Column("record_id", Text, nullable=False),
    Column("op", Text, nullable=False),
    Column("data", JSONB),
    Column("created_at", DateTime(timezone=True), nullable=False),
)
