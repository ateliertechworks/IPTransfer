"""Group, membership and invitation persistence (database-thread code).

Every method takes an open SQLAlchemy connection inside a transaction and is
called only from the node's single database thread. Methods that change
state append ``(event_name, payload)`` tuples to an ``events`` list; the node
emits them after the transaction commits, so applications never see events
for changes that were rolled back.
"""

from __future__ import annotations

import datetime
import hashlib
import logging
import secrets
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import Connection, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from . import events as ev
from .crypto import b64d, b64e, canonical_json, new_symmetric_key, random_id, seal
from .errors import (
    GroupError,
    IdentityError,
    InviteError,
    MalformedMessageError,
    NotFoundError,
    PermissionDeniedError,
)
from .groups import (
    KEY_MANAGERS,
    MEMBER_INVITE,
    MEMBER_REMOVE,
    MEMBER_ROLE,
    GROUP_MANAGE,
    GroupState,
    SignedOp,
    build_op,
    compute_state,
    group_id_of_genesis,
    key_box_aad,
    normalize_roles,
    op_group_id,
    parse_op,
)
from .models import Group, Invite, Member
from .storage import schema as t
from .sync_engine import SyncStore, utcnow

log = logging.getLogger(__name__)

Events = list[tuple[str, dict[str, Any]]]


@dataclass
class OpsResult:
    new_ops: list[SignedOp] = field(default_factory=list)
    joined: bool = False
    state: GroupState | None = None


def _member_payload(identity: Any, user_id: str, device_name: str) -> dict[str, str]:
    return {
        "device_id": identity.device_id,
        "public_key": b64e(identity.public_key),
        "exchange_key": b64e(identity.exchange_public_key),
        "user_id": user_id,
        "device_name": device_name,
    }


def token_hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


class GroupStore:
    def __init__(
        self, identity: Any, app_id: str, user_id: str, device_name: str, store: SyncStore
    ) -> None:
        self.identity = identity
        self.device_id: str = identity.device_id
        self.app_id = app_id
        self.user_id = user_id
        self.device_name = device_name
        self.store = store
        #: group_id -> evaluated state; replaced (never mutated) on change so
        #: the event-loop thread can read it without locks.
        self.states: dict[str, GroupState] = {}
        self.status: dict[str, str] = {}

    # ------------------------------------------------------------------ loading

    def load(self, conn: Connection) -> None:
        for row in conn.execute(select(t.groups)):
            state = compute_state(row.group_id, self.app_id, self._load_ops(conn, row.group_id))
            if state is not None:
                self.states[row.group_id] = state
                self.status[row.group_id] = row.status

    @staticmethod
    def _load_ops(conn: Connection, group_id: str) -> list[SignedOp]:
        ops = []
        for row in conn.execute(
            select(t.membership_ops.c.op, t.membership_ops.c.signature).where(
                t.membership_ops.c.group_id == group_id
            )
        ):
            ops.append(parse_op({"op": row.op, "sig": row.signature}))
        return ops

    def wire_ops(self, conn: Connection, group_id: str, exclude: set[str]) -> list[dict[str, Any]]:
        return [op.to_wire() for op in self._load_ops(conn, group_id) if op.op_id not in exclude]

    # ------------------------------------------------------------------ public views

    def group_view(self, group_id: str) -> Group:
        state = self.states.get(group_id)
        if state is None:
            raise NotFoundError(f"group {group_id} not found")
        me = state.members.get(self.device_id)
        return Group(
            id=group_id,
            name=state.name,
            status=self.status.get(group_id, "active"),
            role=me.role if me else None,
            permissions=tuple(sorted(state.permissions(self.device_id))),
            member_count=len(state.members),
            roles={r: tuple(sorted(p)) for r, p in state.roles.items()},
        )

    def member_views(self, group_id: str, connected: set[str]) -> list[Member]:
        state = self.require_state(group_id)
        return [
            Member(
                device_id=m.device_id,
                user_id=m.user_id,
                device_name=m.device_name,
                role=m.role,
                permissions=tuple(sorted(state.roles.get(m.role, ()))),
                connected=m.device_id in connected or m.device_id == self.device_id,
            )
            for m in sorted(state.members.values(), key=lambda m: (m.role, m.device_name))
        ]

    def require_state(self, group_id: str) -> GroupState:
        state = self.states.get(group_id)
        if state is None:
            raise NotFoundError(f"group {group_id} not found")
        return state

    def require_member(self, group_id: str, permission: str | None = None) -> GroupState:
        state = self.require_state(group_id)
        if not state.is_member(self.device_id):
            raise PermissionDeniedError("this device is not a member of the group")
        if permission is not None and not state.has_permission(self.device_id, permission):
            raise PermissionDeniedError(f"this device lacks {permission!r} in the group")
        return state

    # ------------------------------------------------------------------ op plumbing

    def _new_op(
        self, state: GroupState | None, group_id: str | None, kind: str, body: dict[str, Any]
    ) -> SignedOp:
        lamport = 0 if state is None else state.max_lamport + 1
        deps = [] if state is None else state.heads
        return build_op(
            identity=self.identity,
            app_id=self.app_id,
            group_id=group_id,
            kind=kind,
            lamport=lamport,
            deps=deps,
            body=body,
        )

    def _store_ops(self, conn: Connection, ops: list[SignedOp]) -> list[SignedOp]:
        stored = []
        for op in ops:
            result = conn.execute(
                pg_insert(t.membership_ops)
                .values(
                    op_id=op.op_id,
                    group_id=op_group_id(op),
                    author=op.author,
                    lamport=op.lamport,
                    kind=op.kind,
                    op=op.op,
                    signature=b64e(op.signature),
                    received_at=utcnow(),
                )
                .on_conflict_do_nothing()
            )
            if result.rowcount:
                stored.append(op)
        return stored

    def _refresh(self, conn: Connection, group_id: str, events: Events) -> GroupState:
        """Re-evaluate a group after its op log changed and apply consequences."""
        old = self.states.get(group_id)
        new = compute_state(group_id, self.app_id, self._load_ops(conn, group_id))
        if new is None:
            raise GroupError(f"group {group_id} has no valid genesis")
        was_member = old is not None and old.is_member(self.device_id)
        is_member = new.is_member(self.device_id)
        status = self.status.get(group_id, "active")
        if is_member:
            status = "active"
        elif was_member or status == "active":
            removal = next(
                (new.all_ops[o] for o in reversed(new.valid_ops)
                 if new.all_ops[o].kind == "remove_member"
                 and new.all_ops[o].body.get("device_id") == self.device_id),
                None,
            )
            status = "left" if removal is not None and removal.author == self.device_id else "removed"
        conn.execute(
            update(t.groups)
            .where(t.groups.c.group_id == group_id)
            .values(name=new.name, status=status)
        )
        self.states[group_id] = new
        self.status[group_id] = status

        # Unseal group keys addressed to this device.
        for key_id in new.key_order:
            box = new.key_boxes.get(key_id, {}).get(self.device_id)
            if box is None or self.store.has_key(group_id, key_id):
                continue
            try:
                key = self.identity.open_sealed(box, key_box_aad(key_id, self.device_id))
            except IdentityError:
                log.warning("cannot open group key %s for %s", key_id, group_id)
                continue
            self.store.store_key(conn, group_id, key_id, key)
            self.store.rematerialize_key(conn, new, key_id, events)

        if old is None or old.timeline != new.timeline or old.roles != new.roles:
            self.store.revalidate(conn, new, events)
        self._diff_events(group_id, old, new, events)
        return new

    def _diff_events(
        self, group_id: str, old: GroupState | None, new: GroupState, events: Events
    ) -> None:
        old_members = old.members if old is not None else {}
        for device_id, member in new.members.items():
            previous = old_members.get(device_id)
            if previous is None:
                events.append(
                    (
                        ev.MEMBER_JOINED,
                        {
                            "group_id": group_id,
                            "device_id": device_id,
                            "user_id": member.user_id,
                            "device_name": member.device_name,
                            "role": member.role,
                            "is_self": device_id == self.device_id,
                        },
                    )
                )
            elif previous.role != member.role:
                events.append(
                    (
                        ev.MEMBER_ROLE_CHANGED,
                        {
                            "group_id": group_id,
                            "device_id": device_id,
                            "old_role": previous.role,
                            "role": member.role,
                            "is_self": device_id == self.device_id,
                        },
                    )
                )
        for device_id, member in old_members.items():
            if device_id not in new.members:
                events.append(
                    (
                        ev.MEMBER_REMOVED,
                        {
                            "group_id": group_id,
                            "device_id": device_id,
                            "user_id": member.user_id,
                            "device_name": member.device_name,
                            "left": self._left_voluntarily(new, device_id),
                            "is_self": device_id == self.device_id,
                        },
                    )
                )
        if old is not None and old.name != new.name:
            events.append((ev.GROUP_UPDATED, {"group_id": group_id, "name": new.name}))

    @staticmethod
    def _left_voluntarily(state: GroupState, device_id: str) -> bool:
        for op_id in reversed(state.valid_ops):
            op = state.all_ops[op_id]
            if op.kind == "remove_member" and op.body.get("device_id") == device_id:
                return op.author == device_id
        return False

    def commit_local_ops(
        self, conn: Connection, group_id: str, ops: list[SignedOp], events: Events
    ) -> GroupState:
        """Store ops created on this device and verify they were accepted."""
        self._store_ops(conn, ops)
        state = self._refresh(conn, group_id, events)
        for op in ops:
            if op.op_id in state.invalid_ops:
                raise GroupError(f"operation rejected: {state.invalid_ops[op.op_id]}")
        return state

    # ------------------------------------------------------------------ remote ops

    def ingest_ops(
        self,
        conn: Connection,
        group_id: str,
        wires: list[Any],
        sender: str,
        events: Events,
    ) -> OpsResult:
        """Store membership ops received from ``sender``.

        For a group this device does not know yet, the ops are accepted only
        if this device accepted an invitation to that group from ``sender``
        and the ops make it a member (no one can be pushed into a group).
        """
        ops: list[SignedOp] = []
        for wire in wires:
            try:
                op = parse_op(wire)
            except MalformedMessageError as exc:
                log.warning("dropping malformed membership op from %s: %s", sender[:12], exc)
                continue
            if op.op["app_id"] != self.app_id or op_group_id(op) != group_id:
                continue
            ops.append(op)
        result = OpsResult()
        if group_id not in self.states:
            invite = conn.execute(
                select(t.invites).where(
                    t.invites.c.group_id == group_id,
                    t.invites.c.direction == "incoming",
                    t.invites.c.status == "accepted",
                    t.invites.c.inviter_device_id == sender,
                )
            ).first()
            if invite is None:
                log.info("ignoring ops for unknown group %s from %s", group_id, sender[:12])
                return result
            state = compute_state(group_id, self.app_id, ops)
            if state is None or not state.is_member(self.device_id):
                return result
            conn.execute(
                pg_insert(t.groups)
                .values(group_id=group_id, name=state.name, status="active", created_at=utcnow())
                .on_conflict_do_nothing()
            )
            conn.execute(
                update(t.invites)
                .where(t.invites.c.group_id == group_id, t.invites.c.direction == "incoming",
                       t.invites.c.status == "accepted")
                .values(status="joined")
            )
            self.status[group_id] = "active"
            result.joined = True
        result.new_ops = self._store_ops(conn, ops)
        if result.new_ops or result.joined:
            result.state = self._refresh(conn, group_id, events)
        else:
            result.state = self.states.get(group_id)
        return result

    # ------------------------------------------------------------------ group operations

    def create_group(
        self,
        conn: Connection,
        name: str,
        roles: dict[str, Any],
        owner_role: str,
        events: Events,
    ) -> GroupState:
        normalized = normalize_roles(roles, owner_role)
        if not isinstance(name, str) or not 0 < len(name.strip()) <= 200:
            raise GroupError("group name must be 1-200 characters")
        key = new_symmetric_key()
        key_id = random_id(16)
        body = {
            "name": name.strip(),
            "roles": normalized,
            "owner_role": owner_role,
            "creator": _member_payload(self.identity, self.user_id, self.device_name),
            "key": {
                "key_id": key_id,
                "box": seal(
                    self.identity.exchange_public_key, key, key_box_aad(key_id, self.device_id)
                ),
            },
            "nonce": secrets.token_hex(16),
        }
        genesis = self._new_op(None, None, "genesis", body)
        group_id = group_id_of_genesis(genesis.op_id)
        conn.execute(
            t.groups.insert().values(
                group_id=group_id, name=body["name"], status="active", created_at=utcnow()
            )
        )
        self.status[group_id] = "active"
        state = self.commit_local_ops(conn, group_id, [genesis], events)
        events.append(
            (
                ev.GROUP_CREATED,
                {"group_id": group_id, "name": state.name, "role": owner_role},
            )
        )
        return state

    def rename(self, conn: Connection, group_id: str, name: str, events: Events) -> list[SignedOp]:
        state = self.require_member(group_id, GROUP_MANAGE)
        op = self._new_op(state, group_id, "rename", {"name": name})
        self.commit_local_ops(conn, group_id, [op], events)
        return [op]

    def _target_seq(self, conn: Connection, group_id: str, device_id: str) -> int:
        return int(
            conn.execute(
                select(func.coalesce(func.max(t.changes.c.seq), 0)).where(
                    t.changes.c.group_id == group_id, t.changes.c.author == device_id
                )
            ).scalar_one()
        )

    def remove_member(
        self, conn: Connection, group_id: str, device_id: str, events: Events
    ) -> list[SignedOp]:
        state = self.require_member(group_id)
        if device_id != self.device_id and not state.has_permission(self.device_id, MEMBER_REMOVE):
            raise PermissionDeniedError("this device lacks 'member.remove'")
        if device_id not in state.members:
            raise NotFoundError("device is not a member of the group")
        op = self._new_op(
            state,
            group_id,
            "remove_member",
            {"device_id": device_id, "target_seq": self._target_seq(conn, group_id, device_id)},
        )
        new_state = self.commit_local_ops(conn, group_id, [op], events)
        ops = [op]
        if new_state.is_member(self.device_id):
            ops += self.rotate_key(conn, group_id, events)
        return ops

    def change_role(
        self, conn: Connection, group_id: str, device_id: str, role: str, events: Events
    ) -> list[SignedOp]:
        state = self.require_member(group_id, MEMBER_ROLE)
        if device_id not in state.members:
            raise NotFoundError("device is not a member of the group")
        if role not in state.roles:
            raise GroupError(f"unknown role {role!r}")
        op = self._new_op(
            state,
            group_id,
            "change_role",
            {
                "device_id": device_id,
                "role": role,
                "target_seq": self._target_seq(conn, group_id, device_id),
            },
        )
        self.commit_local_ops(conn, group_id, [op], events)
        return [op]

    def rotate_key(self, conn: Connection, group_id: str, events: Events) -> list[SignedOp]:
        """Issue a fresh group key sealed only to the current members."""
        state = self.require_member(group_id)
        if not state.permissions(self.device_id) & KEY_MANAGERS:
            return []
        key = new_symmetric_key()
        key_id = random_id(16)
        boxes = {
            m.device_id: seal(m.exchange_key, key, key_box_aad(key_id, m.device_id))
            for m in state.members.values()
        }
        op = self._new_op(state, group_id, "key_rotation", {"key_id": key_id, "boxes": boxes})
        self.commit_local_ops(conn, group_id, [op], events)
        return [op]

    def maintain_keys(self, conn: Connection, group_id: str, events: Events) -> list[SignedOp]:
        """Repair key distribution after concurrent membership changes."""
        state = self.states.get(group_id)
        if state is None or not state.is_member(self.device_id):
            return []
        if not state.permissions(self.device_id) & KEY_MANAGERS:
            return []
        if state.stale_key_recipients():
            return self.rotate_key(conn, group_id, events)
        grants: dict[str, dict[str, Any]] = {}
        for device_id, key_ids in state.members_missing_keys().items():
            member = state.members[device_id]
            for key_id in key_ids:
                key = self.store.key(group_id, key_id)
                if key is not None:
                    grants.setdefault(device_id, {})[key_id] = seal(
                        member.exchange_key, key, key_box_aad(key_id, device_id)
                    )
        if not grants:
            return []
        op = self._new_op(state, group_id, "key_grant", {"grants": grants})
        self.commit_local_ops(conn, group_id, [op], events)
        return [op]

    # ------------------------------------------------------------------ invitations

    @staticmethod
    def _invite_view(row: Any, token: str | None = None) -> Invite:
        status = row.status
        if status == "pending" and row.expires_at < utcnow():
            status = "expired"
        return Invite(
            id=row.invite_id,
            group_id=row.group_id,
            group_name=row.group_name,
            role=row.role,
            direction=row.direction,
            inviter_device_id=row.inviter_device_id,
            invitee_device_id=row.invitee_device_id,
            expires_at=row.expires_at,
            status=status,
            max_uses=row.max_uses,
            uses=row.uses,
            token=token,
        )

    def create_invite(
        self,
        conn: Connection,
        group_id: str,
        role: str,
        invitee: str | None,
        ttl: float,
        max_uses: int,
    ) -> tuple[Invite, str]:
        state = self.require_member(group_id, MEMBER_INVITE)
        if role not in state.roles:
            raise GroupError(f"unknown role {role!r}; defined roles: {sorted(state.roles)}")
        if not state.roles[role] <= state.permissions(self.device_id):
            raise PermissionDeniedError(f"cannot invite into role {role!r}: it has more permissions")
        if invitee is not None and invitee in state.members:
            raise GroupError("device is already a member")
        if not 1 <= max_uses <= 1000:
            raise InviteError("max_uses must be between 1 and 1000")
        invite_id = random_id(16)
        secret = secrets.token_urlsafe(24)
        expires = utcnow() + datetime.timedelta(seconds=ttl)
        conn.execute(
            t.invites.insert().values(
                invite_id=invite_id,
                direction="outgoing",
                group_id=group_id,
                group_name=state.name,
                role=role,
                inviter_device_id=self.device_id,
                invitee_device_id=invitee,
                token_hash=token_hash(secret),
                # Kept only until a directed invitation is delivered.
                secret=secret if invitee is not None else None,
                expires_at=expires,
                max_uses=max_uses,
                uses=0,
                status="pending",
                created_at=utcnow(),
            )
        )
        token = "up2p1." + b64e(
            canonical_json(
                {
                    "a": self.app_id,
                    "i": invite_id,
                    "s": secret,
                    "g": group_id,
                    "d": self.device_id,
                    "n": state.name,
                    "r": role,
                    "e": int(expires.timestamp()),
                }
            )
        )
        row = conn.execute(select(t.invites).where(t.invites.c.invite_id == invite_id)).one()
        return self._invite_view(row, token), secret

    def get_invite(self, conn: Connection, invite_id: str) -> Any:
        row = conn.execute(select(t.invites).where(t.invites.c.invite_id == invite_id)).first()
        if row is None:
            raise NotFoundError(f"invitation {invite_id} not found")
        return row

    def undelivered_invites(self, conn: Connection, device_id: str) -> list[Any]:
        return list(
            conn.execute(
                select(t.invites).where(
                    t.invites.c.direction == "outgoing",
                    t.invites.c.invitee_device_id == device_id,
                    t.invites.c.status == "pending",
                    t.invites.c.delivered.is_(False),
                    t.invites.c.expires_at > utcnow(),
                )
            )
        )

    def mark_delivered(self, conn: Connection, invite_id: str) -> None:
        conn.execute(
            update(t.invites)
            .where(t.invites.c.invite_id == invite_id)
            .values(delivered=True, secret=None)
        )

    def record_incoming_invite(
        self,
        conn: Connection,
        *,
        invite_id: str,
        group_id: str,
        group_name: str,
        role: str,
        inviter: str,
        secret: str,
        expires_at: datetime.datetime,
    ) -> tuple[Invite, bool]:
        existing = conn.execute(
            select(t.invites).where(t.invites.c.invite_id == invite_id)
        ).first()
        if existing is not None:
            if existing.direction == "incoming" and existing.status in ("pending", "accepted"):
                # The code being presented now is authoritative (an earlier
                # attempt may have used a mistyped or forged secret).
                conn.execute(
                    update(t.invites)
                    .where(t.invites.c.invite_id == invite_id)
                    .values(secret=secret)
                )
            return self._invite_view(existing), False
        conn.execute(
            t.invites.insert().values(
                invite_id=invite_id,
                direction="incoming",
                group_id=group_id,
                group_name=group_name,
                role=role,
                inviter_device_id=inviter,
                invitee_device_id=self.device_id,
                secret=secret,
                expires_at=expires_at,
                max_uses=1,
                uses=0,
                status="pending",
                created_at=utcnow(),
            )
        )
        row = conn.execute(select(t.invites).where(t.invites.c.invite_id == invite_id)).one()
        return self._invite_view(row), True

    def set_invite_status(self, conn: Connection, invite_id: str, status: str) -> None:
        conn.execute(
            update(t.invites).where(t.invites.c.invite_id == invite_id).values(status=status)
        )

    def list_invites(
        self, conn: Connection, group_id: str | None, direction: str | None
    ) -> list[Invite]:
        query = select(t.invites).order_by(t.invites.c.created_at)
        if group_id is not None:
            query = query.where(t.invites.c.group_id == group_id)
        if direction is not None:
            query = query.where(t.invites.c.direction == direction)
        return [self._invite_view(r) for r in conn.execute(query)]

    def admit(
        self,
        conn: Connection,
        *,
        invite_id: str,
        secret: str,
        peer_id: str,
        peer_public_key: bytes,
        member: dict[str, Any],
        events: Events,
    ) -> tuple[str, list[SignedOp]]:
        """Validate an invitation acceptance from ``peer_id`` and add it to the group."""
        row = conn.execute(
            select(t.invites)
            .where(t.invites.c.invite_id == invite_id, t.invites.c.direction == "outgoing")
            .with_for_update()
        ).first()
        if row is None or row.token_hash is None:
            raise InviteError("unknown invitation")
        if row.status != "pending":
            raise InviteError(f"invitation is {row.status}")
        if row.expires_at < utcnow():
            self.set_invite_status(conn, invite_id, "expired")
            raise InviteError("invitation expired")
        if not secrets.compare_digest(row.token_hash, token_hash(secret)):
            raise InviteError("invalid invitation secret")
        if row.invitee_device_id is not None and row.invitee_device_id != peer_id:
            raise InviteError("invitation was issued to another device")
        if member.get("device_id") != peer_id or member.get("public_key") != b64e(peer_public_key):
            raise InviteError("member identity does not match the authenticated connection")
        state = self.require_member(row.group_id, MEMBER_INVITE)
        if peer_id in state.members:
            raise InviteError("device is already a member")
        keys = {}
        try:
            exchange_key = b64d(member.get("exchange_key", ""), expected_len=32)
        except ValueError as exc:
            raise InviteError("invalid exchange key") from exc
        for key_id in state.key_order:
            key = self.store.key(row.group_id, key_id)
            if key is not None:
                keys[key_id] = seal(exchange_key, key, key_box_aad(key_id, peer_id))
        clean_member = {
            k: member.get(k)
            for k in ("device_id", "public_key", "exchange_key", "user_id", "device_name")
        }
        op = self._new_op(
            state,
            row.group_id,
            "add_member",
            {
                "member": clean_member,
                "role": row.role,
                "target_seq": self._target_seq(conn, row.group_id, peer_id),
                "invite_id": invite_id,
                "keys": keys,
            },
        )
        try:
            self.commit_local_ops(conn, row.group_id, [op], events)
        except GroupError as exc:
            raise InviteError(str(exc)) from exc
        uses = row.uses + 1
        conn.execute(
            update(t.invites)
            .where(t.invites.c.invite_id == invite_id)
            .values(uses=uses, status="pending" if uses < row.max_uses else "accepted")
        )
        return row.group_id, [op]

    def member_payload(self) -> dict[str, str]:
        return _member_payload(self.identity, self.user_id, self.device_name)
