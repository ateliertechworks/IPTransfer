"""Public, immutable result types returned by the node API."""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class TrustedDevice:
    device_id: str
    device_name: str
    fingerprint: str
    paired_at: datetime.datetime
    revoked_at: datetime.datetime | None
    last_seen_at: datetime.datetime | None
    connected: bool = False


@dataclass(frozen=True)
class PairingRequest:
    """A pairing in progress. Both users must see the same ``code``."""

    session_id: str
    device_id: str
    device_name: str
    fingerprint: str
    #: Six-digit comparison code (None until both nonces are exchanged).
    code: str | None
    #: True if this device started the pairing.
    initiator: bool
    expires_at: float
    local_approved: bool = False
    remote_approved: bool = False


@dataclass(frozen=True)
class Member:
    device_id: str
    user_id: str
    device_name: str
    role: str
    permissions: tuple[str, ...]
    connected: bool = False


@dataclass(frozen=True)
class Group:
    id: str
    name: str
    #: active | left | removed
    status: str
    #: This device's role (None if no longer a member).
    role: str | None
    permissions: tuple[str, ...]
    member_count: int
    roles: dict[str, tuple[str, ...]] = field(default_factory=dict)


@dataclass(frozen=True)
class Invite:
    id: str
    group_id: str
    group_name: str
    role: str
    #: outgoing (created here) or incoming (received here)
    direction: str
    inviter_device_id: str
    invitee_device_id: str | None
    expires_at: datetime.datetime
    #: pending | accepted | rejected | revoked | expired | joined
    status: str
    max_uses: int
    uses: int
    #: Shareable invitation code (outgoing invites, only when just created).
    token: str | None = None


@dataclass(frozen=True)
class Record:
    group_id: str
    collection: str
    record_id: str
    data: dict[str, Any] | None
    deleted: bool
    #: Change ID of the version currently shown.
    version: str
    author_device_id: str
    updated_at: datetime.datetime
    in_conflict: bool = False


@dataclass(frozen=True)
class ConflictVersion:
    change_id: str
    author_device_id: str
    deleted: bool
    data: dict[str, Any] | None
    timestamp_ms: int


@dataclass(frozen=True)
class Conflict:
    id: str
    group_id: str
    collection: str
    record_id: str
    versions: tuple[ConflictVersion, ...]
    #: Change ID chosen by the default policy (shown until resolved).
    winner: str
    #: open | resolved | superseded
    status: str
    detected_at: datetime.datetime
    resolved_at: datetime.datetime | None = None


@dataclass(frozen=True)
class PeerSyncStatus:
    device_id: str
    device_name: str
    connected: bool
    #: Changes held here that this peer has not acknowledged yet.
    pending_changes: int
    last_ack_at: datetime.datetime | None


@dataclass(frozen=True)
class SyncStatus:
    group_id: str
    #: Changes authored on this device.
    local_changes: int
    #: Changes stored here in total (all authors).
    total_changes: int
    #: Local changes not yet acknowledged by every other member.
    pending_changes: int
    #: Rows waiting in the transactional outbox.
    outbox_pending: int
    open_conflicts: int
    #: Changes stored but not readable yet (group key not received).
    undecryptable_changes: int
    peers: tuple[PeerSyncStatus, ...]
