# Integration guide

This guide is for application developers embedding `universal-p2p-sync`. It
covers installation, configuration, the public API, events, GUI integration,
the PostgreSQL adapter and outbox, error handling, and desktop packaging.

* Architecture: [architecture.md](architecture.md)
* Worked examples: [echo-integration.md](echo-integration.md), [todo-integration.md](todo-integration.md)

## 1. Install

Python 3.11+ on Linux or Windows.

```bash
pip install "universal-p2p-sync @ git+https://github.com/<owner>/universal-p2p-sync.git@<tag-or-commit>"
```

Pin a tag or commit in production. Dependencies are `zeroconf`, `ifaddr`,
`cryptography`, `SQLAlchemy` 2.x, `psycopg` 3 (binary) and `alembic`.

Each device also needs **its own local PostgreSQL server** (14 or newer).
See [postgresql.md](postgresql.md).

## 2. Start a node

```python
import os
from universal_p2p_sync import SyncNode

sync = SyncNode(
    app_id="echo",                      # isolates this app from all others
    user_id="user_001",                 # an application label, NOT proof of identity
    device_name="My Laptop",            # shown to other users
    database_url=os.environ["ECHO_SYNC_DATABASE_URL"],
    roles={                             # optional: your own role model
        "leader": ["group.manage", "member.invite", "member.remove", "data.read", "data.write"],
        "member": ["data.read", "data.write"],
    },
    owner_role="leader",
)
sync.start()       # loads/creates the device keys, migrates the schema, starts networking
...
sync.stop()        # graceful: pending changes stay in PostgreSQL
```

`SyncNode` runs the network on a background thread and offers blocking
methods. `AsyncSyncNode` has the same methods as coroutines for asyncio
applications (`sync.aio` is the `AsyncSyncNode` inside a `SyncNode`).

On the first start the node:

1. creates the device identity in the key directory (see [security.md](security.md));
2. creates the PostgreSQL schema `up2p_<app_id>` and runs Alembic migrations;
3. listens on `listen_port` (0 = any free port) and advertises itself over mDNS.

### Configuration

Pass options as keyword arguments, or build a `NodeConfig` (for example from
environment variables with `NodeConfig.from_env(app_id, device_name)` and
`SyncNode(app_id, user_id, device_name, config=cfg)`).

| option | default | meaning |
|---|---|---|
| `database_url` | env `UP2P_<APP>_DATABASE_URL` / `UP2P_DATABASE_URL` | local PostgreSQL URL (`postgresql+psycopg://…`); required |
| `db_schema` | `up2p_<app_id>` | schema for the sync tables |
| `auto_migrate` | `True` | run migrations on start |
| `data_dir` | per-user app-data dir | key directory parent (`<data_dir>/<app_id>/`) |
| `key_passphrase` | `None` | encrypt the private key files |
| `listen_host` / `listen_port` | `0.0.0.0` / `0` | TCP listen address |
| `enable_discovery` | `True` | mDNS advertise and browse |
| `auto_connect_discovered` | `True` | dial discovered peers of the same app |
| `advertise_addresses` | all LAN IPv4 | addresses announced over mDNS |
| `roles` / `owner_role` | `owner/admin/member/viewer` | role model for groups created by this node |
| `invite_ttl` | 7 days | default invitation lifetime (seconds) |
| `pairing_timeout` | 300 | seconds a pairing request stays valid |
| `sync_interval` | 30 | seconds between background sync rounds |
| `outbox_poll_interval` | 1 | seconds between outbox polls |
| `max_record_size` | 256 KiB | max JSON size of one record |
| `max_frame_size` | 1 MiB | max wire message size |
| `max_connections`, `max_pending_handshakes` | 128, 32 | connection limits |
| `connection_rate_limit` / `connection_rate_window` | 30 / 10 s | new inbound connections per IP |
| `connect_timeout`, `handshake_timeout` | 10 s | connection timeouts |
| `keepalive_interval`, `idle_timeout` | 15 s, 45 s | liveness |
| `allow_insecure_transport` | `False` | plaintext development mode (direct messages only, never in production) |

Environment variables read by `NodeConfig.from_env` (app-scoped
`UP2P_ECHO_LISTEN_PORT` beats global `UP2P_LISTEN_PORT`): `LISTEN_HOST`,
`LISTEN_PORT`, `ENABLE_DISCOVERY`, `AUTO_CONNECT_DISCOVERED`,
`ADVERTISE_ADDRESSES`, `MAX_FRAME_SIZE`, `CONNECT_TIMEOUT`,
`HANDSHAKE_TIMEOUT`, `KEEPALIVE_INTERVAL`, `IDLE_TIMEOUT`, `DATABASE_URL`,
`DB_SCHEMA`, `DATA_DIR`, `KEY_PASSPHRASE`, `SYNC_INTERVAL`,
`ALLOW_INSECURE_TRANSPORT`.

**Credentials.** Never hard-code the database password. Use the environment
variables, a `.pgpass` / `pgpass.conf` file (then the URL needs no password),
or your OS keyring. The URL is excluded from `repr(config)`.

## 3. Devices: discovery, connections, pairing

Nodes of the same `app_id` on the LAN find each other via mDNS and connect
automatically over TLS 1.3. If multicast is blocked, connect manually:

```python
peer = sync.connect("192.168.1.20", 47801)           # once
sync.add_peer_address("192.168.1.20", 47801)          # keep reconnecting
```

A connected device is **authenticated** (its device ID is proven) but not
**trusted** until the users pair the devices once:

```python
request = sync.request_pairing(peer.device_id)   # both sides get "pairing_requested"
print("Compare this code with the other screen:", request.code)
sync.approve_pairing(peer.device_id)              # the other user does the same
```

Pairing completes when both users approve (`pairing_completed`). It survives
restarts, and paired devices reconnect to each other automatically. **Pairing
grants no group or data access.** Manage trust with `list_trusted_devices()`,
`revoke_device(device_id)` (blocks the device, and by default removes it from
groups where you may remove members) and `forget_device(device_id)`.

## 4. Groups, invitations, roles

```python
group = sync.create_group(name="Development Team")             # you get owner_role
invite = sync.create_invite(group_id=group.id, role="member", device_id=peer.device_id)
# On the invited device ("group_invitation_received" event):
sync.accept_invite(invite_id)              # the inviter must be online
```

Without `device_id`, `invite.token` is a shareable code (`up2p1.…`) that any
device can redeem with `accept_invite(token)` until it expires or is used
`max_uses` times. Treat it like a password. More: `list_groups()`,
`get_group()`, `rename_group()`, `list_members()`, `change_member_role()`,
`remove_member()` / `revoke_group_access()`, `leave_group()`,
`list_invites()`, `reject_invite()`, `revoke_invite()`,
`has_permission(group_id, "task.assign")`. Details: [groups.md](groups.md).

## 5. Records

```python
sync.publish(group_id=group.id, collection="shared_notes", record_id="note_001",
             data={"title": "Meeting", "content": "Tomorrow at 10 AM"})   # create / update
sync.delete(group_id=group.id, collection="shared_notes", record_id="note_001")
sync.get_record(group.id, "shared_notes", "note_001")    # -> Record | None
sync.list_records(group.id, "shared_notes")
sync.get_sync_status(group_id=group.id)                   # -> SyncStatus
sync.sync_now(group.id)                                   # optional: sync immediately
```

* `collection`: 1-64 chars `[A-Za-z0-9_.-]`; `record_id`: 1-256 printable chars;
  `data`: a JSON object up to `max_record_size` bytes.
* Only data you publish is shared. The library never reads your own tables.
* Writes require `data.write` (or `data.write:<collection>`) in the group.
  Group IDs are random 128-bit values; inventing one (`"team_001"`) grants
  nothing and raises `NotFoundError`.
* Publishing works offline: the change is committed locally and delivered
  when members reconnect ([offline-sync.md](offline-sync.md)).

`SyncStatus` fields: `local_changes`, `total_changes`, `pending_changes`
(your changes not yet acknowledged by every member), `outbox_pending`,
`open_conflicts`, `undecryptable_changes`, `peers` (per member: `connected`,
`pending_changes`, `last_ack_at`).

## 6. Receiving updates and updating your UI

```python
def on_record(event):
    print(event["collection"], event["record_id"], event["data"])

sync.on("record_received", on_record)
sync.on("record_updated", on_record)
sync.on("record_deleted", on_record)
```

Handlers run on the node's thread by default. **GUI applications** pass a
dispatcher that runs each handler call on the UI thread:

```python
# tkinter
sync = SyncNode(..., callback_dispatcher=lambda fn: root.after(0, fn))

# PySide6 / PyQt
class Bridge(QObject):
    call = Signal(object)
bridge = Bridge(); bridge.call.connect(lambda fn: fn(), Qt.QueuedConnection)
sync = SyncNode(..., callback_dispatcher=bridge.call.emit)
```

Do not call blocking `SyncNode` methods from inside a handler that runs on the
node thread (it raises `NodeStateError`); with a dispatcher, handlers run on
your UI thread and may call them, but prefer `sync.submit(sync.aio.publish(...))`
(returns a `concurrent.futures.Future`) for anything slow so the UI stays
responsive. The SDK never touches UI objects itself.

### Events

Every event is an `Event` with `name`, `timestamp` and read-only `data`;
`event["key"]` and `event.get("key")` read `data`. Subscribe with
`sync.on(name, handler)` or `sync.on("*", handler)`; `on` returns an
unsubscribe function.

| event | payload |
|---|---|
| `peer_discovered` | `device_id`, `device_name`, `addresses` (list), `port`, `trusted` |
| `peer_lost` | `device_id` |
| `peer_connected` | `device_id`, `device_name`, `address`, `outbound`, `secure`, `trusted`, `fingerprint` |
| `peer_disconnected` | `device_id`, `device_name` |
| `message_received` | `device_id`, `device_name`, `message_id`, `payload` (direct, non-durable messages) |
| `pairing_requested` | `device_id`, `device_name`, `fingerprint`, `code` (6 digits), `initiator`, `expires_at` (epoch s) |
| `pairing_completed` | `device_id`, `device_name`, `fingerprint` |
| `pairing_rejected` | `device_id`, `device_name`, `reason`, `by_peer` |
| `device_revoked` | `device_id`, `device_name` |
| `group_created` | `group_id`, `name`, `role` |
| `group_updated` | `group_id`, `name` |
| `group_invitation_received` | `invite_id`, `group_id`, `group_name`, `role`, `inviter_device_id`, `inviter_device_name`, `expires_at` (ISO 8601) |
| `invitation_response` | `invite_id`, `group_id`, `device_id`, `device_name`, `accepted` |
| `member_joined` | `group_id`, `device_id`, `user_id`, `device_name`, `role`, `is_self` |
| `member_removed` | `group_id`, `device_id`, `user_id`, `device_name`, `left` (left voluntarily), `is_self` |
| `member_role_changed` | `group_id`, `device_id`, `old_role`, `role`, `is_self` |
| `sync_started` | `group_id`, `device_id` (the peer) |
| `sync_progress` | `group_id`, `device_id`, `received`, `applied`, `duplicates`, `rejected` |
| `sync_completed` | `group_id`, `device_id`, `received`, `applied`, `duplicates` |
| `sync_failed` | `group_id`, `device_id` (None for outbox rows), `reason`; for outbox rows also `outbox_id`, `collection`, `record_id` |
| `record_received` | see below; a record became visible here (new, or re-created) |
| `record_updated` | see below; the visible content changed |
| `record_deleted` | see below; `data` is `None`, `deleted` is `True` |
| `conflict_detected` | `conflict_id`, `group_id`, `collection`, `record_id`, `versions` (list of `{change_id, author, hlc, op, data}`), `winner` (change ID shown meanwhile) |
| `conflict_resolved` | `conflict_id`, `group_id`, `collection`, `record_id`, `resolution` (change ID), `deleted`, `data` |

Record event payload: `group_id`, `collection`, `record_id`, `data`
(dict or None), `deleted`, `version` (change ID), `author_device_id`,
`author_user_id`, `origin` (`remote`, `membership` when a membership change
altered what is visible, or `resolver`), `in_conflict`.

Record events are emitted only for changes that came from *other* devices (or
your conflict resolver), never for your own `publish`/`delete` calls, and only
after the PostgreSQL transaction storing them has committed.

## 7. Conflicts

Concurrent edits of one record are detected, persisted and reported
(`conflict_detected`); a deterministic winner is shown meanwhile and no
version is discarded. Resolve them automatically or manually:

```python
from universal_p2p_sync import DELETE

sync.register_conflict_resolver("tasks", lambda conflict: merged_dict_or_DELETE_or_None)
for c in sync.list_conflicts(group.id):
    sync.resolve_conflict(c.id, {"title": "merged"})      # or DELETE
```

Full rules: [conflicts.md](conflicts.md).

## 8. Integrating existing PostgreSQL tables

If your application keeps its data in PostgreSQL tables, use the **same
database** for the sync node (it uses its own schema) and connect the two with
the outbox and an adapter.

**Outbox (your writes → peers), atomically with your own transaction:**

```python
from universal_p2p_sync import enqueue_change

with app_engine.begin() as conn:                      # your transaction
    conn.execute(text("UPDATE tasks SET done = true WHERE id = :id"), {"id": tid})
    enqueue_change(conn, schema=sync.schema, group_id=ws_id, collection="tasks",
                   record_id=tid, data={"title": title, "completed": True})  # data=None deletes
sync.notify_outbox()     # optional: publish now instead of within outbox_poll_interval
```

If the transaction rolls back, nothing is shared; if it commits, the change is
published even if the application crashes right after. Rows that turn out
invalid (unknown group, no permission, bad data) are dropped with a
`sync_failed` event. Without SQLAlchemy, insert directly:
`INSERT INTO up2p_todo.outbox (group_id, collection, record_id, op, data, created_at) VALUES (…, 'put', '{…}'::jsonb, now())`.

**Adapter (peers' writes → your tables), in the sync transaction:**

```python
class TaskAdapter:
    def apply(self, conn, event, payload):     # conn: SQLAlchemy Connection, same DB
        if event == "record_deleted":
            conn.execute(text("DELETE FROM tasks WHERE id = :id"), {"id": payload["record_id"]})
        else:
            conn.execute(text("INSERT INTO tasks (id, title, done) VALUES (:id, :t, :d) "
                              "ON CONFLICT (id) DO UPDATE SET title = :t, done = :d"),
                         {"id": payload["record_id"], "t": payload["data"]["title"],
                          "d": payload["data"]["completed"]})

sync.register_adapter("tasks", TaskAdapter())   # or "*" for every collection
```

The adapter runs inside the transaction that stores the remote change: if it
raises, nothing is committed and the change is fetched again on the next
synchronization (`sync_failed` with reason `apply_failed: …`).

**Avoiding synchronization loops.** An adapter must write your tables
*directly*; it must not call `publish` or `enqueue_change` for the change it is
applying (that would echo the change back as a new edit). Likewise, if you use
database triggers to fill the outbox, disable them for adapter writes (e.g.
check a session variable `SET LOCAL app.applying_remote = 'on'` in the
trigger). Your own `publish` calls never produce record events or adapter
calls, so UI code that reacts to events cannot loop either.

## 9. Error handling

All library errors derive from `P2PSyncError`:

| exception | typical cause |
|---|---|
| `ConfigurationError` | invalid option, missing/unsupported `database_url` |
| `StorageError` | PostgreSQL unreachable, schema owned by another device, schema locked by another running instance |
| `IdentityError` | unreadable key file, wrong key passphrase |
| `NodeStateError` | node not started; blocking call from the node thread |
| `PeerNotConnectedError` | operation needs a connected device (pairing, accepting an invite) |
| `NotTrustedError` | direct message or directed invite to an unpaired device |
| `PairingError` | pairing timed out, rejected or already paired |
| `NotFoundError` | unknown group/record/invite/conflict (or this device is not a member) |
| `PermissionDeniedError` | missing permission in the group, not a member, removed |
| `InviteError` | invitation expired, revoked, used up, wrong secret, wrong device |
| `GroupError` | invalid membership operation (e.g. removing the last manager) |
| `InvalidPayloadError` | data not a JSON object, too large, invalid collection/record ID |
| `HandshakeError` (`.code`) | `app_mismatch`, `device_revoked`, `identity_mismatch`, `authentication_failed`, `tls_failed`, … |

Background failures (a peer sent bad data, an adapter failed) never raise in
your code: they are logged (`logging.getLogger("universal_p2p_sync")`) and
reported with `sync_failed` where relevant. If PostgreSQL becomes unavailable
at runtime, calls raise `StorageError`; the node keeps running and recovers
when the database is back.

## 10. Packaging desktop applications

The package is pure Python plus binary wheels (`cryptography`,
`psycopg-binary`). With PyInstaller, include the migration scripts (data
files) and zeroconf's lazily imported modules:

```bash
pyinstaller --name Echo \
  --collect-data universal_p2p_sync \
  --collect-submodules universal_p2p_sync \
  --collect-submodules zeroconf \
  --collect-all psycopg_binary \
  echo_main.py
```

Notes: the PostgreSQL *server* is not bundled; install it separately (or ship
the official installer alongside your app). Allow the app through the
firewall (TCP listen port, UDP 5353). The key directory lives in the user's
profile, not inside the bundle, so updates keep the device identity.
These PyInstaller flags are guidance and have not been verified in this
repository's CI; test the built bundle on each OS.

## 11. Limits of local-network P2P

* Devices synchronize only when they can reach each other directly (same LAN,
  or a VPN that routes between them). There is no relay, NAT traversal or
  internet rendezvous.
* Two devices that are never online at the same time synchronize only through
  a third member that meets both.
* mDNS does not cross routers/VLANs and is blocked on "Public" Windows
  networks; use manual addresses there.
* Group size: membership operations carry one encrypted key box per member;
  the design targets teams of up to roughly 100 devices.
