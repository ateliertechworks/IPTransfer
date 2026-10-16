# Groups, invitations and permissions

A **group** (an Echo "team", a To-Do "workspace") is the unit of sharing:
records belong to exactly one group, and only the group's members receive
them.

## Roles and permissions

Applications define their own roles as a mapping *role → permissions*:

```python
roles = {
    "leader": ["group.manage", "member.invite", "member.remove", "data.read", "data.write"],
    "member": ["data.read", "data.write"],
}
sync = SyncNode(..., roles=roles, owner_role="leader")
```

The role model is fixed per group at creation (it is part of the signed
genesis operation), so every member applies the same rules. Without `roles`,
groups use the default model:

| role | permissions |
|---|---|
| `owner` | `group.manage`, `member.invite`, `member.remove`, `member.role`, `data.read`, `data.write` |
| `admin` | `member.invite`, `member.remove`, `data.read`, `data.write` |
| `member` | `data.read`, `data.write` |
| `viewer` | `data.read` |

Permissions the library enforces:

| permission | allows |
|---|---|
| `group.manage` | renaming the group; the owner role must include it |
| `member.invite` | inviting/adding members, into roles whose permissions are a subset of the inviter's |
| `member.remove` | removing members whose role permissions are a subset of the remover's |
| `member.role` | changing *another* member's role (target role and current role must be subsets of the author's permissions) |
| `data.read` | receiving the group's records |
| `data.write` | publishing records in every collection; `data.write:<collection>` limits it to one collection |

Any other permission string (e.g. `task.assign`) is application-defined: the
library stores and propagates it, and the app checks it with
`sync.has_permission(group_id, "task.assign")` (or for another device with
`device_id=`).

Role names: `^[a-z][a-z0-9_-]{0,31}$`, up to 32 roles, 64 permissions each.

### Rules that cannot be bypassed

* Nobody can change their own role, so nobody can promote themselves.
* Nobody can grant a role with permissions they do not have.
* The last member holding `group.manage` cannot leave or be demoted while
  other members remain.
* Every member may leave (`leave_group`).

These rules are checked by the library on the acting device **and** by every
other device when it evaluates the signed log. A modified client that skips
the local check only produces operations that everyone else ignores.

## Lifecycle

```python
group = sync.create_group("Development Team")      # creator gets owner_role
sync.rename_group(group.id, "Core Team")           # group.manage
inv = sync.create_invite(group.id, "member", device_id=peer_id)   # member.invite
# invitee: event group_invitation_received, then
sync.accept_invite(inv_id)                          # or reject_invite(inv_id)
sync.change_member_role(group.id, peer_id, "admin") # member.role
sync.remove_member(group.id, peer_id)               # member.remove (+ key rotation)
sync.leave_group(group.id)
sync.revoke_invite(inv.id)
sync.list_groups(); sync.list_members(group.id); sync.list_invites(group.id)
```

`Group.status` is `active`, `left` (you left) or `removed` (someone removed
you). Data received before leaving stays readable locally; nothing new arrives.

## Invitations

| kind | created with | usable by | delivery |
|---|---|---|---|
| directed | `create_invite(gid, role, device_id=…)` | that paired device only | pushed automatically when it is connected (now or later) |
| token | `create_invite(gid, role)` → `invite.token` | anyone presenting the code, up to `max_uses` | you share the `up2p1.…` code (chat, QR code…) |

Both expire (`ttl`, default `invite_ttl` = 7 days) and can be revoked. To
accept, the inviting device must be online and connected: the invitee sends
the secret over the authenticated connection, the inviter validates it,
signs an `add_member` operation with the invitee's verified keys, and sends
the group's operation log to the new member. Possible refusals (`InviteError`):
expired, revoked, already used, wrong secret, issued to another device,
inviter no longer allowed to invite, already a member.

## The signed membership log

Every change to a group is an operation signed by its author:
`genesis`, `add_member`, `remove_member`, `change_role`, `rename`,
`key_rotation`, `key_grant`. Each carries a Lamport counter and the IDs of the
operations its author had seen. The group ID is derived from the hash of the
genesis operation, so it cannot be chosen or reused.

Every device holding the same set of operations computes the same state:
operations are sorted by `(lamport, op_id)` and each is checked against the
state produced by the ones before it; invalid ones are ignored (but kept, so
the outcome never depends on arrival order).

Operations spread by gossip: they are sent to connected members when created,
forwarded when new, and compared (by their DAG heads) at every sync round.
A device that has never seen another member can still learn about it from any
other member, so members who never paired with each other still synchronize.

### Offline membership changes

* Removing or demoting a member records `target_seq`: the highest change
  sequence number of that member the remover had seen. Changes by that member
  up to `target_seq` stay valid; later ones need the new role. Every device
  reaches the same verdict whatever the arrival order.
* If two administrators make conflicting changes while disconnected, the
  `(lamport, op_id)` order decides; the "losing" operation may become invalid
  (for example, adding a member by an admin who was concurrently removed).
* Group keys: see [security.md](security.md#decentralized-revocation-what-it-can-and-cannot-do)
  for rotation and the limits of revocation.

## Pairing vs. membership

Pairing (device trust) and membership (data access) are independent. Pairing
is needed for directed invitations and direct messages; token invitations and
synchronization between members do not need pairing. Revoking a paired device
(`revoke_device`) by default also removes it from the groups where you hold
`member.remove`.
