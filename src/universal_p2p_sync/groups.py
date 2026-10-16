"""Decentralized group membership: signed operations and their evaluation.

A group is defined entirely by a log of signed membership operations. The
first one (``genesis``) is signed by the creator and fixes the group ID (a
hash of the genesis operation), the application ID and the group's
role/permission model. Every later operation (add/remove member, change role,
rename, key rotation, key grant) is signed by the device that made it.

Every device evaluates the same deterministic function over the set of
operations it holds: operations are ordered by ``(lamport, op_id)`` and each
one is checked against the state produced by the operations before it.
Operations that fail a check are kept but ignored. Devices holding the same
set of operations therefore always agree on the membership.

Authorization rules (enforced here, not in any UI):

* Only members holding ``member.invite`` may add members, and only into roles
  whose permissions are a subset of their own.
* Only members holding ``member.remove`` may remove others, and only members
  whose role permissions are a subset of their own. Anyone may leave.
* Only members holding ``member.role`` may change *another* member's role,
  again limited to subsets of their own permissions. Nobody can change their
  own role, so self-promotion is impossible.
* ``group.manage`` is required to rename the group. The last member holding
  ``group.manage`` cannot leave or be demoted while others remain.

Data changes are authorized by the author's role *at the change's sequence
number*: each membership operation that affects a device records
``target_seq``, the highest change sequence of that device its author had
seen. The operation applies to the target's changes with a higher sequence
number, so changes made under a previous role stay valid and every device
reaches the same verdict regardless of arrival order.
"""

from __future__ import annotations

import re
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .crypto import b64d, b64e, canonical_json, device_id_for, sha256_hex, verify_signature
from .errors import ConfigurationError, MalformedMessageError

OP_VERSION = 1
MAX_OP_SIZE = 256 * 1024
MAX_NAME_LENGTH = 200
MAX_LABEL_LENGTH = 256
ROLE_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
PERMISSION_PATTERN = re.compile(r"^[a-z][a-z0-9_.:-]{0,95}$")
HEX_ID = re.compile(r"^[0-9a-f]{32}$")
DEVICE_ID = re.compile(r"^[0-9a-f]{64}$")
OP_KINDS = frozenset(
    {"genesis", "add_member", "remove_member", "change_role", "rename", "key_rotation", "key_grant"}
)

# Permissions with meaning inside the library. Applications may define more
# (e.g. ``task.assign``) and check them with ``has_permission``.
GROUP_MANAGE = "group.manage"
MEMBER_INVITE = "member.invite"
MEMBER_REMOVE = "member.remove"
MEMBER_ROLE = "member.role"
DATA_READ = "data.read"
DATA_WRITE = "data.write"
KEY_MANAGERS = frozenset({GROUP_MANAGE, MEMBER_INVITE, MEMBER_REMOVE})

DEFAULT_ROLES: dict[str, list[str]] = {
    "owner": [GROUP_MANAGE, MEMBER_INVITE, MEMBER_REMOVE, MEMBER_ROLE, DATA_READ, DATA_WRITE],
    "admin": [MEMBER_INVITE, MEMBER_REMOVE, DATA_READ, DATA_WRITE],
    "member": [DATA_READ, DATA_WRITE],
    "viewer": [DATA_READ],
}
DEFAULT_OWNER_ROLE = "owner"


def normalize_roles(roles: Mapping[str, Iterable[str]], owner_role: str) -> dict[str, list[str]]:
    """Validate an application role model; returns it with sorted permissions."""
    if not isinstance(roles, Mapping) or not 0 < len(roles) <= 32:
        raise ConfigurationError("roles must be a mapping with 1-32 roles")
    result: dict[str, list[str]] = {}
    for role, perms in roles.items():
        if not isinstance(role, str) or not ROLE_PATTERN.fullmatch(role):
            raise ConfigurationError(f"invalid role name {role!r}")
        if isinstance(perms, str) or not isinstance(perms, Iterable):
            raise ConfigurationError(f"permissions of role {role!r} must be a list")
        perm_list = sorted(set(perms))
        if len(perm_list) > 64:
            raise ConfigurationError(f"role {role!r} has too many permissions")
        for perm in perm_list:
            if not isinstance(perm, str) or not PERMISSION_PATTERN.fullmatch(perm):
                raise ConfigurationError(f"invalid permission {perm!r} in role {role!r}")
        result[role] = perm_list
    if owner_role not in result:
        raise ConfigurationError(f"owner role {owner_role!r} is not defined in roles")
    if GROUP_MANAGE not in result[owner_role]:
        raise ConfigurationError(f"owner role {owner_role!r} must include {GROUP_MANAGE!r}")
    return result


def has_data_permission(perms: frozenset[str], base: str, collection: str | None) -> bool:
    """``data.write`` covers every collection; ``data.write:<collection>`` one."""
    return base in perms or (collection is not None and f"{base}:{collection}" in perms)


# ---------------------------------------------------------------- signed operations


@dataclass(frozen=True)
class SignedOp:
    op_id: str
    op: dict[str, Any]
    signature: bytes

    @property
    def kind(self) -> str:
        return self.op["kind"]

    @property
    def author(self) -> str:
        return self.op["author"]

    @property
    def lamport(self) -> int:
        return self.op["lamport"]

    @property
    def body(self) -> dict[str, Any]:
        return self.op["body"]

    def to_wire(self) -> dict[str, Any]:
        return {"op": self.op, "sig": b64e(self.signature)}


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def parse_op(wire: Any) -> SignedOp:
    """Structural validation of a wire operation (signatures are checked later)."""
    if not isinstance(wire, dict) or not isinstance(wire.get("op"), dict):
        raise MalformedMessageError("membership op must be an object with 'op' and 'sig'")
    op = wire["op"]
    try:
        signature = b64d(wire.get("sig"), expected_len=64)
    except ValueError as exc:
        raise MalformedMessageError(f"invalid op signature: {exc}") from exc
    encoded = canonical_json(op)
    if len(encoded) > MAX_OP_SIZE:
        raise MalformedMessageError("membership op too large")
    if op.get("v") != OP_VERSION or op.get("kind") not in OP_KINDS:
        raise MalformedMessageError("unsupported membership op")
    if not isinstance(op.get("app_id"), str) or not isinstance(op.get("body"), dict):
        raise MalformedMessageError("invalid membership op fields")
    if not isinstance(op.get("author"), str) or not DEVICE_ID.fullmatch(op["author"]):
        raise MalformedMessageError("invalid op author")
    if not _is_int(op.get("lamport")) or not 0 <= op["lamport"] < 2**62:
        raise MalformedMessageError("invalid op lamport")
    if not _is_int(op.get("ts")):
        raise MalformedMessageError("invalid op timestamp")
    deps = op.get("deps")
    if not isinstance(deps, list) or len(deps) > 256 or not all(
        isinstance(d, str) and len(d) == 64 for d in deps
    ):
        raise MalformedMessageError("invalid op deps")
    group_id = op.get("group_id")
    if op["kind"] == "genesis":
        if group_id is not None or op["lamport"] != 0:
            raise MalformedMessageError("genesis must have no group_id and lamport 0")
    elif not isinstance(group_id, str) or not HEX_ID.fullmatch(group_id):
        raise MalformedMessageError("invalid op group_id")
    return SignedOp(sha256_hex(encoded), op, signature)


def group_id_of_genesis(op_id: str) -> str:
    return op_id[:32]


def op_group_id(op: SignedOp) -> str:
    return group_id_of_genesis(op.op_id) if op.kind == "genesis" else op.op["group_id"]


def build_op(
    *,
    identity: Any,
    app_id: str,
    group_id: str | None,
    kind: str,
    lamport: int,
    deps: Iterable[str],
    body: dict[str, Any],
) -> SignedOp:
    op = {
        "v": OP_VERSION,
        "app_id": app_id,
        "group_id": group_id,
        "kind": kind,
        "author": identity.device_id,
        "lamport": lamport,
        "deps": sorted(deps),
        "ts": int(time.time() * 1000),
        "body": body,
    }
    encoded = canonical_json(op)
    return SignedOp(sha256_hex(encoded), op, identity.sign(encoded))


def key_box_aad(key_id: str, device_id: str) -> bytes:
    return canonical_json({"ctx": "up2p-group-key", "key_id": key_id, "device_id": device_id})


# ---------------------------------------------------------------- state


@dataclass
class Member:
    device_id: str
    public_key: bytes
    exchange_key: bytes
    user_id: str
    device_name: str
    role: str
    added_by: str


@dataclass
class GroupState:
    group_id: str
    app_id: str
    name: str = ""
    owner_role: str = DEFAULT_OWNER_ROLE
    roles: dict[str, frozenset[str]] = field(default_factory=dict)
    #: Current members.
    members: dict[str, Member] = field(default_factory=dict)
    #: Every device that was ever a member (needed to verify old signatures).
    known: dict[str, Member] = field(default_factory=dict)
    #: device -> [(target_seq, role or None)] in evaluation order.
    timeline: dict[str, list[tuple[int, str | None]]] = field(default_factory=dict)
    #: key_id -> {device_id: sealed box}
    key_boxes: dict[str, dict[str, dict[str, str]]] = field(default_factory=dict)
    key_order: list[str] = field(default_factory=list)
    valid_ops: list[str] = field(default_factory=list)
    invalid_ops: dict[str, str] = field(default_factory=dict)
    all_ops: dict[str, SignedOp] = field(default_factory=dict)
    max_lamport: int = 0
    creator: str = ""

    # ---- queries

    @property
    def current_key_id(self) -> str | None:
        return self.key_order[-1] if self.key_order else None

    @property
    def heads(self) -> list[str]:
        referenced = {d for op in self.all_ops.values() for d in op.op["deps"]}
        return sorted(op_id for op_id in self.all_ops if op_id not in referenced)

    def is_member(self, device_id: str) -> bool:
        return device_id in self.members

    def was_member(self, device_id: str) -> bool:
        return device_id in self.known

    def permissions(self, device_id: str) -> frozenset[str]:
        member = self.members.get(device_id)
        return self.roles.get(member.role, frozenset()) if member else frozenset()

    def has_permission(self, device_id: str, permission: str) -> bool:
        return permission in self.permissions(device_id)

    def can_read(self, device_id: str) -> bool:
        return DATA_READ in self.permissions(device_id)

    def role_at(self, device_id: str, seq: int) -> str | None:
        role: str | None = None
        for target_seq, new_role in self.timeline.get(device_id, ()):
            if seq > target_seq:
                role = new_role
        return role

    def can_write_at(self, device_id: str, seq: int, collection: str) -> bool:
        role = self.role_at(device_id, seq)
        if role is None:
            return False
        return has_data_permission(self.roles.get(role, frozenset()), DATA_WRITE, collection)

    def members_missing_keys(self) -> dict[str, list[str]]:
        """Current members lacking a sealed copy of some group key."""
        missing: dict[str, list[str]] = {}
        for device_id in self.members:
            lacking = [k for k in self.key_order if device_id not in self.key_boxes.get(k, {})]
            if lacking:
                missing[device_id] = lacking
        return missing

    def stale_key_recipients(self) -> bool:
        """True if the current key was sealed to a device that is no longer a member."""
        key_id = self.current_key_id
        if key_id is None:
            return False
        return any(dev not in self.members for dev in self.key_boxes.get(key_id, {}))

    def managers(self) -> list[str]:
        return [d for d in self.members if GROUP_MANAGE in self.permissions(d)]


class _Invalid(Exception):
    pass


def _check(condition: bool, reason: str) -> None:
    if not condition:
        raise _Invalid(reason)


def _parse_member(data: Any) -> Member:
    _check(isinstance(data, dict), "member must be an object")
    try:
        public_key = b64d(data["public_key"], expected_len=32)
        exchange_key = b64d(data["exchange_key"], expected_len=32)
    except (KeyError, ValueError) as exc:
        raise _Invalid(f"invalid member keys: {exc}") from exc
    device_id = data.get("device_id")
    _check(device_id == device_id_for(public_key), "member device_id does not match key")
    user_id = data.get("user_id")
    name = data.get("device_name")
    _check(isinstance(user_id, str) and 0 < len(user_id) <= MAX_LABEL_LENGTH, "invalid user_id")
    _check(isinstance(name, str) and 0 < len(name) <= MAX_LABEL_LENGTH, "invalid device_name")
    return Member(device_id, public_key, exchange_key, user_id, name, "", "")


def _check_box(box: Any) -> None:
    _check(
        isinstance(box, dict)
        and set(box) == {"epk", "n", "ct"}
        and all(isinstance(v, str) and len(v) < 1024 for v in box.values()),
        "invalid sealed key box",
    )


def _check_target_seq(value: Any) -> int:
    _check(_is_int(value) and 0 <= value < 2**62, "invalid target_seq")
    return int(value)


def _subset(state: GroupState, role: str, actor_perms: frozenset[str]) -> bool:
    return state.roles.get(role, frozenset()) <= actor_perms


def _keeps_a_manager(state: GroupState, target: str, new_role: str | None) -> bool:
    managers = set(state.managers())
    if target not in managers:
        return True
    if new_role is not None and GROUP_MANAGE in state.roles.get(new_role, frozenset()):
        return True
    remaining_members = len(state.members) - (1 if new_role is None else 0)
    return len(managers) > 1 or remaining_members == 0


def _apply_genesis(state: GroupState, op: SignedOp) -> None:
    body = op.body
    creator = _parse_member(body.get("creator"))
    _check(creator.device_id == op.author, "genesis author must be the creator")
    _check(verify_signature(creator.public_key, op.signature, canonical_json(op.op)),
           "bad signature")
    name = body.get("name")
    _check(isinstance(name, str) and 0 < len(name) <= MAX_NAME_LENGTH, "invalid group name")
    owner_role = body.get("owner_role")
    try:
        roles = normalize_roles(body.get("roles"), owner_role)  # type: ignore[arg-type]
    except ConfigurationError as exc:
        raise _Invalid(str(exc)) from exc
    key = body.get("key")
    _check(isinstance(key, dict) and isinstance(key.get("key_id"), str)
           and HEX_ID.fullmatch(key["key_id"]) is not None, "invalid genesis key")
    _check_box(key.get("box"))
    state.name = name
    state.owner_role = owner_role
    state.roles = {r: frozenset(p) for r, p in roles.items()}
    state.creator = creator.device_id
    creator.role = owner_role
    creator.added_by = creator.device_id
    state.members[creator.device_id] = creator
    state.known[creator.device_id] = creator
    state.timeline[creator.device_id] = [(0, owner_role)]
    state.key_boxes[key["key_id"]] = {creator.device_id: key["box"]}
    state.key_order.append(key["key_id"])


def _apply(state: GroupState, op: SignedOp) -> None:
    _check(op.op["app_id"] == state.app_id, "app_id mismatch")
    _check(op.op["group_id"] == state.group_id, "group_id mismatch")
    actor = state.members.get(op.author)
    _check(actor is not None, "author is not a current member")
    assert actor is not None
    _check(verify_signature(actor.public_key, op.signature, canonical_json(op.op)),
           "bad signature")
    perms = state.permissions(op.author)
    body = op.body
    kind = op.kind

    if kind == "add_member":
        _check(MEMBER_INVITE in perms, "author lacks member.invite")
        member = _parse_member(body.get("member"))
        role = body.get("role")
        _check(isinstance(role, str) and role in state.roles, "unknown role")
        _check(_subset(state, role, perms), "cannot grant a role with more permissions")
        _check(member.device_id not in state.members, "already a member")
        target_seq = _check_target_seq(body.get("target_seq"))
        keys = body.get("keys")
        _check(isinstance(keys, dict) and len(keys) <= 1024, "invalid keys")
        for key_id, box in keys.items():
            _check(key_id in state.key_boxes, "unknown key id")
            _check_box(box)
        previous = state.known.get(member.device_id)
        if previous is not None:
            _check(previous.public_key == member.public_key, "device key changed")
        member.role = role
        member.added_by = op.author
        state.members[member.device_id] = member
        state.known[member.device_id] = member
        state.timeline.setdefault(member.device_id, []).append((target_seq, role))
        for key_id, box in keys.items():
            state.key_boxes[key_id].setdefault(member.device_id, box)

    elif kind == "remove_member":
        target = body.get("device_id")
        _check(isinstance(target, str) and target in state.members, "target is not a member")
        if target != op.author:
            _check(MEMBER_REMOVE in perms, "author lacks member.remove")
            _check(_subset(state, state.members[target].role, perms),
                   "cannot remove a member with more permissions")
        _check(_keeps_a_manager(state, target, None), "cannot remove the last manager")
        target_seq = _check_target_seq(body.get("target_seq"))
        del state.members[target]
        state.timeline.setdefault(target, []).append((target_seq, None))

    elif kind == "change_role":
        target = body.get("device_id")
        role = body.get("role")
        _check(isinstance(target, str) and target in state.members, "target is not a member")
        _check(target != op.author, "members cannot change their own role")
        _check(MEMBER_ROLE in perms, "author lacks member.role")
        _check(isinstance(role, str) and role in state.roles, "unknown role")
        _check(_subset(state, role, perms), "cannot grant a role with more permissions")
        _check(_subset(state, state.members[target].role, perms),
               "cannot change the role of a member with more permissions")
        _check(_keeps_a_manager(state, target, role), "cannot demote the last manager")
        target_seq = _check_target_seq(body.get("target_seq"))
        state.members[target].role = role
        state.timeline.setdefault(target, []).append((target_seq, role))

    elif kind == "rename":
        _check(GROUP_MANAGE in perms, "author lacks group.manage")
        name = body.get("name")
        _check(isinstance(name, str) and 0 < len(name) <= MAX_NAME_LENGTH, "invalid name")
        state.name = name

    elif kind == "key_rotation":
        _check(bool(perms & KEY_MANAGERS), "author may not rotate keys")
        key_id = body.get("key_id")
        boxes = body.get("boxes")
        _check(isinstance(key_id, str) and HEX_ID.fullmatch(key_id) is not None, "invalid key id")
        _check(key_id not in state.key_boxes, "duplicate key id")
        _check(isinstance(boxes, dict) and 0 < len(boxes) <= 4096, "invalid boxes")
        for device_id, box in boxes.items():
            _check(device_id in state.members, "key sealed to a non-member")
            _check_box(box)
        state.key_boxes[key_id] = dict(boxes)
        state.key_order.append(key_id)

    elif kind == "key_grant":
        _check(bool(perms & KEY_MANAGERS), "author may not grant keys")
        grants = body.get("grants")
        _check(isinstance(grants, dict) and 0 < len(grants) <= 4096, "invalid grants")
        for device_id, boxes in grants.items():
            _check(device_id in state.members, "key granted to a non-member")
            _check(isinstance(boxes, dict), "invalid grant")
            for key_id, box in boxes.items():
                _check(key_id in state.key_boxes, "unknown key id")
                _check_box(box)
        for device_id, boxes in grants.items():
            for key_id, box in boxes.items():
                state.key_boxes[key_id].setdefault(device_id, box)
    else:  # genesis twice
        raise _Invalid("unexpected operation kind")


def compute_state(group_id: str, app_id: str, ops: Iterable[SignedOp]) -> GroupState | None:
    """Evaluate a group's operation log. Returns None without a valid genesis."""
    all_ops = {op.op_id: op for op in ops}
    genesis = [
        op for op in all_ops.values()
        if op.kind == "genesis" and group_id_of_genesis(op.op_id) == group_id
    ]
    if len(genesis) != 1 or genesis[0].op["app_id"] != app_id:
        return None
    state = GroupState(group_id=group_id, app_id=app_id, all_ops=all_ops)
    try:
        _apply_genesis(state, genesis[0])
    except _Invalid:
        return None
    state.valid_ops.append(genesis[0].op_id)
    rest = sorted(
        (op for op in all_ops.values() if op is not genesis[0]),
        key=lambda o: (o.lamport, o.op_id),
    )
    for op in rest:
        state.max_lamport = max(state.max_lamport, op.lamport)
        try:
            _apply(state, op)
        except _Invalid as exc:
            state.invalid_ops[op.op_id] = str(exc)
            continue
        state.valid_ops.append(op.op_id)
    return state
