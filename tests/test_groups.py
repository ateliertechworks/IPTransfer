"""Milestone 3: groups, invitations, signed membership and authorization."""

from __future__ import annotations

import asyncio
import itertools
import json

import pytest

from universal_p2p_sync import InviteError, NotFoundError, PermissionDeniedError
from universal_p2p_sync.crypto import DeviceIdentity, b64d, b64e, new_symmetric_key, seal
from universal_p2p_sync.group_store import _member_payload
from universal_p2p_sync.groups import (
    DEFAULT_ROLES,
    build_op,
    compute_state,
    group_id_of_genesis,
    key_box_aad,
)

from .conftest import connect, join, pair, wait_until

ECHO_ROLES = {
    "leader": ["group.manage", "member.invite", "member.remove", "data.read", "data.write"],
    "member": ["data.read", "data.write"],
}


# ---------------------------------------------------------------- signed op log (unit)


class LogBuilder:
    """Builds signed membership logs with real device keys, without a database."""

    def __init__(self, tmp_path, roles=None, owner_role="owner"):
        self.ids = {n: DeviceIdentity.load_or_create(tmp_path / n) for n in "OABCX"}
        owner = self.ids["O"]
        key_id = "0" * 32
        box = seal(owner.exchange_public_key, new_symmetric_key(), key_box_aad(key_id, owner.device_id))
        self.genesis = build_op(
            identity=owner, app_id="echo", group_id=None, kind="genesis", lamport=0, deps=[],
            body={"name": "G", "roles": roles or DEFAULT_ROLES, "owner_role": owner_role,
                  "creator": _member_payload(owner, "o", "O"),
                  "key": {"key_id": key_id, "box": box}, "nonce": "n"},
        )
        self.group_id = group_id_of_genesis(self.genesis.op_id)
        self.ops = [self.genesis]
        self.lamport = 0

    def op(self, author, kind, body, lamport=None):
        self.lamport += 1
        op = build_op(identity=self.ids[author], app_id="echo", group_id=self.group_id,
                      kind=kind, lamport=lamport or self.lamport, deps=[], body=body)
        self.ops.append(op)
        return op

    def add(self, author, who, role):
        return self.op(author, "add_member", {
            "member": _member_payload(self.ids[who], who.lower(), who), "role": role,
            "target_seq": 0, "keys": {}})

    def state(self, ops=None):
        return compute_state(self.group_id, "echo", ops or self.ops)

    def did(self, name):
        return self.ids[name].device_id


def test_forged_and_escalating_operations_are_ignored(tmp_path) -> None:
    log = LogBuilder(tmp_path)
    log.add("O", "A", "admin")
    log.add("O", "B", "member")
    rejected = [
        log.op("B", "change_role", {"device_id": log.did("B"), "role": "owner", "target_seq": 0}),
        log.add("B", "C", "member"),                       # lacks member.invite
        log.add("A", "C", "owner"),                        # cannot grant more than it has
        log.add("X", "C", "member"),                       # author is not a member
        log.op("A", "change_role", {"device_id": log.did("B"), "role": "admin", "target_seq": 0}),
        log.op("A", "remove_member", {"device_id": log.did("O"), "target_seq": 0}),
        log.op("O", "remove_member", {"device_id": log.did("O"), "target_seq": 0}),  # last manager
    ]
    state = log.state()
    for op in rejected:
        assert op.op_id in state.invalid_ops, op.kind
    assert state.members[log.did("B")].role == "member"
    assert log.did("C") not in state.members and log.did("O") in state.members

    # An op whose body was altered after signing, or re-signed by someone else
    # while claiming another author, fails signature verification.
    good = log.add("O", "C", "member")
    tampered = dict(good.op, body={**good.op["body"], "role": "owner"})
    from universal_p2p_sync.groups import SignedOp, parse_op

    forged = parse_op({"op": tampered, "sig": b64e(good.signature)})
    impostor = parse_op({"op": dict(good.op, lamport=99),
                         "sig": b64e(log.ids["B"].sign(json.dumps({}).encode()))})
    state = log.state(log.ops[:-1] + [forged, impostor])
    assert forged.op_id in state.invalid_ops and impostor.op_id in state.invalid_ops
    assert isinstance(good, SignedOp)


def test_membership_evaluation_is_order_independent(tmp_path) -> None:
    """Concurrent changes made while devices were offline converge everywhere."""
    log = LogBuilder(tmp_path)
    log.add("O", "A", "admin")
    # Concurrent: O and A both act at lamport 2 without seeing each other.
    log.op("O", "change_role", {"device_id": log.did("A"), "role": "member", "target_seq": 0},
           lamport=2)
    log.add("A", "B", "member").op  # noqa: B018 - A still believes it is admin
    log.ops[-1] = log.ops[-1]
    results = set()
    for perm in itertools.permutations(log.ops):
        state = log.state(list(perm))
        results.add((tuple(sorted((d, m.role) for d, m in state.members.items())),
                     tuple(sorted(state.invalid_ops))))
    assert len(results) == 1


def test_role_timeline_keeps_old_writes_valid(tmp_path) -> None:
    log = LogBuilder(tmp_path)
    log.add("O", "B", "member")
    log.op("O", "remove_member", {"device_id": log.did("B"), "target_seq": 5})
    state = log.state()
    assert state.can_write_at(log.did("B"), 5, "notes")
    assert not state.can_write_at(log.did("B"), 6, "notes")
    assert not state.is_member(log.did("B")) and state.was_member(log.did("B"))


def test_custom_role_model_requires_a_manager_role(tmp_path) -> None:
    from universal_p2p_sync import ConfigurationError
    from universal_p2p_sync.groups import normalize_roles

    assert normalize_roles(ECHO_ROLES, "leader")["leader"][0] == "data.read"
    with pytest.raises(ConfigurationError):
        normalize_roles(ECHO_ROLES, "member")
    with pytest.raises(ConfigurationError):
        normalize_roles({"Bad Role": []}, "Bad Role")


# ---------------------------------------------------------------- node integration


async def team(make_secure_node, n: int, app: str = "echo", **kw):
    nodes = [await make_secure_node(app, f"dev{i}", **kw) for i in range(n)]
    owner, _ = nodes[0]
    for node, _ in nodes[1:]:
        await pair(owner, node)
    return nodes


async def test_create_list_rename_and_join(make_secure_node) -> None:
    (a, ra), (b, rb) = await team(make_secure_node, 2, roles=ECHO_ROLES)
    group = await a.create_group("Development Team")
    assert len(group.id) == 32 and group.role == "leader"
    assert (await ra.wait_for("group_created"))[0]["group_id"] == group.id
    await join(a, b, rb, group.id, "member")
    joined = [e for e in rb.of("member_joined") if e["is_self"]]
    assert joined and joined[0]["role"] == "member"
    assert {m.role for m in b.list_members(group.id)} == {"leader", "member"}
    assert [g.id for g in b.list_groups()] == [group.id]
    await a.rename_group(group.id, "Core Team")
    await rb.wait_for("group_updated")
    assert b.get_group(group.id).name == "Core Team"
    response = (await ra.wait_for("invitation_response"))[0]
    assert response["accepted"] and response["device_id"] == b.device_id


async def test_invitation_permissions(make_secure_node) -> None:
    (a, _), (b, rb) = await team(make_secure_node, 2, roles=ECHO_ROLES)
    group = await a.create_group("Team")
    await join(a, b, rb, group.id, "member")
    with pytest.raises(PermissionDeniedError):
        await b.create_invite(group.id, "member")
    with pytest.raises(PermissionDeniedError):
        await b.remove_member(group.id, a.device_id)
    with pytest.raises(PermissionDeniedError):
        await b.rename_group(group.id, "Mine now")
    with pytest.raises(NotFoundError):
        await b.publish("team_001", "notes", "n", {})  # arbitrary group IDs grant nothing


async def test_token_invitations_expire_are_revocable_and_single_use(make_secure_node) -> None:
    (a, _), (b, _), (c, _) = [await make_secure_node("todo", n) for n in "abc"]
    ws = await a.create_group("Workspace")
    await connect(b, a)
    await connect(c, a)

    expired = await a.create_invite(ws.id, "member", ttl=0.5)
    await asyncio.sleep(1.0)
    with pytest.raises(InviteError, match="expired"):
        await b.accept_invite(expired.token)

    revoked = await a.create_invite(ws.id, "member")
    await a.revoke_invite(revoked.id)
    with pytest.raises(InviteError):
        await b.accept_invite(revoked.token)

    good = await a.create_invite(ws.id, "member")
    data = json.loads(b64d(good.token[6:]))
    data["s"] = "x" * len(data["s"])
    forged = "up2p1." + b64e(json.dumps(data).encode())
    with pytest.raises(InviteError, match="secret"):
        await b.accept_invite(forged)
    assert (await b.accept_invite(good.token)).id == ws.id
    with pytest.raises(InviteError):
        await c.accept_invite(good.token)  # max_uses=1 already used
    with pytest.raises(InviteError):
        await b.accept_invite(good.token)  # already a member


async def test_rejecting_an_invitation(make_secure_node) -> None:
    (a, ra), (b, rb) = await team(make_secure_node, 2)
    group = await a.create_group("Team")
    invite = await a.create_invite(group.id, "member", device_id=b.device_id)
    received = (await rb.wait_for("group_invitation_received"))[0]
    assert received["role"] == "member" and received["inviter_device_id"] == a.device_id
    await b.reject_invite(invite.id)
    response = (await ra.wait_for("invitation_response"))[0]
    assert response["accepted"] is False
    statuses = {i.id: i.status for i in await a.list_invites(group.id)}
    assert statuses[invite.id] == "rejected"


async def test_invitation_delivered_when_invitee_comes_online(make_secure_node) -> None:
    (a, _), (b, rb) = await team(make_secure_node, 2)
    group = await a.create_group("Team")
    await a.disconnect(b.device_id)
    await wait_until(lambda: not a.peers())
    await a.create_invite(group.id, "member", device_id=b.device_id)
    await asyncio.sleep(0.3)
    assert rb.of("group_invitation_received") == []
    await connect(b, a)
    await rb.wait_for("group_invitation_received")


async def test_member_removal_rotates_keys_and_cuts_off_new_data(make_secure_node) -> None:
    (a, ra), (b, rb), (c, rc) = await team(make_secure_node, 3)
    group = await a.create_group("Team")
    await join(a, b, rb, group.id, "member")
    await join(a, c, rc, group.id, "member")
    key_before = a.get_group(group.id)
    await a.publish(group.id, "notes", "old", {"v": 1})
    await rb.wait_for("record_received")
    await a.remove_member(group.id, b.device_id)
    removed = [e for e in (await rb.wait_for("member_removed")) if e["is_self"]]
    assert removed and removed[0]["left"] is False
    await wait_until(lambda: b.get_group(group.id).status == "removed")
    state = a._groups.states[group.id]
    assert len(state.key_order) == 2 and b.device_id not in state.key_boxes[state.key_order[-1]]
    await a.publish(group.id, "notes", "new", {"v": 2})
    await rc.wait_for("record_received", 2)
    await asyncio.sleep(1.5)
    assert await b.get_record(group.id, "notes", "new") is None
    with pytest.raises(PermissionDeniedError):
        await b.publish(group.id, "notes", "x", {})
    assert key_before.member_count == 3 and a.get_group(group.id).member_count == 2


async def test_offline_member_learns_removal_and_gets_no_new_records(make_secure_node) -> None:
    (a, ra), (b, rb) = await team(make_secure_node, 2)
    group = await a.create_group("Team")
    await join(a, b, rb, group.id, "member")
    await a.disconnect(b.device_id)
    await wait_until(lambda: not b.peers())
    await a.remove_member(group.id, b.device_id)
    await a.publish(group.id, "notes", "after-removal", {"secret": 1})
    await connect(b, a)
    await wait_until(lambda: b.get_group(group.id).status == "removed")
    await asyncio.sleep(1.5)
    assert await b.get_record(group.id, "notes", "after-removal") is None


async def test_role_change_and_leaving(make_secure_node) -> None:
    (a, _), (b, rb), (c, rc) = await team(make_secure_node, 3)
    group = await a.create_group("Team")
    await join(a, b, rb, group.id, "member")
    await a.change_member_role(group.id, b.device_id, "admin")
    await wait_until(lambda: b.get_group(group.id).role == "admin")
    assert b.has_permission(group.id, "member.invite")
    await pair(b, c)
    await join(b, c, rc, group.id, "member")  # the new admin can invite now
    await c.leave_group(group.id)
    await wait_until(lambda: c.get_group(group.id).status == "left")
    await wait_until(lambda: a.get_group(group.id).member_count == 2)
    with pytest.raises(PermissionDeniedError):
        await b.change_member_role(group.id, b.device_id, "owner")


async def test_membership_changes_propagate_through_other_members(make_secure_node) -> None:
    """B is offline while A adds C; B learns about C from C itself later."""
    (a, ra), (b, rb), (c, rc) = await team(make_secure_node, 3)
    group = await a.create_group("Team")
    await join(a, b, rb, group.id, "member")
    await a.disconnect(b.device_id)
    await join(a, c, rc, group.id, "member")
    await a.publish(group.id, "notes", "n1", {"from": "a"})
    await rc.wait_for("record_received")
    await a.stop()  # A goes away entirely
    await connect(b, c)  # B and C never paired; their shared group authorizes them
    await wait_until(lambda: b.get_group(group.id).member_count == 3)
    await rb.wait_for("record_received")
    assert (await b.get_record(group.id, "notes", "n1")).data == {"from": "a"}
