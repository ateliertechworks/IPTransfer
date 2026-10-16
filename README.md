# universal-p2p-sync

An embedded, serverless peer-to-peer data synchronization SDK for Python
applications on a local Wi-Fi/LAN. Each application (for example Echo or a
To-Do app) embeds the library directly. There is no central server, no cloud
database and no separate background service. Every device can both accept and
initiate connections, and keeps its data in **its own local PostgreSQL**.

GitHub hosts **only the source code** of this library. Application data never
goes through GitHub or any other server: it moves directly between devices on
the local network, encrypted and authenticated.

## Status

| Milestone | Scope | Status |
|---|---|---|
| 1 | Packaging, peer connection, mDNS discovery, JSON exchange | implemented & tested |
| 2 | Persistent device identity, TLS 1.3 mutual auth, pairing, revocation | implemented & tested |
| 3 | Groups, invitations, signed membership, app-defined roles, authorization, key rotation | implemented & tested |
| 4 | PostgreSQL sync engine, offline queues, catch-up, tombstones, conflicts, outbox/adapters | implemented & tested |
| 5 | Echo & To-Do examples, documentation, CI with PostgreSQL | implemented; Windows is covered by CI configuration but has not been run by the maintainers yet |

Version `0.1.0.dev1` - alpha. APIs may still change before 1.0. See
[Limitations](#limitations).

## Features

* **Discovery & connections**: mDNS (`zeroconf`) per application ID, manual
  `host:port`, automatic reconnection to paired devices.
* **Security**: persistent Ed25519/X25519 device keys, TLS 1.3 with device-key
  authentication, 6-digit pairing-code comparison, trusted-device management
  and revocation, rate limiting, strict size-limited message parsing.
* **Groups**: create/rename, directed or shareable invitations (expiring,
  revocable, use-limited), join/leave/remove, role changes, **application-defined
  roles and permissions** enforced by the library via signed membership logs,
  group key rotation on removal.
* **Synchronization**: create/update/delete of JSON records in collections;
  end-to-end encrypted and signed changes; persistent change log, checkpoints
  and acknowledgements in PostgreSQL; offline queues; duplicate detection;
  deletion tombstones; resumable catch-up after reconnects or crashes; relay
  through other members.
* **Conflicts**: causal (version DAG) detection, deterministic default policy
  that never discards concurrent edits, persisted conflicts, application
  resolvers, manual resolution, events.
* **Integration**: `SyncNode` (blocking, GUI-friendly, callbacks dispatched to
  your UI thread) and `AsyncSyncNode` (asyncio); transactional outbox and
  adapters for existing PostgreSQL tables; 25 documented events.

## Install

Requires Python ≥ 3.11 on Linux or Windows, and a local PostgreSQL ≥ 14 per
device ([docs/postgresql.md](docs/postgresql.md)).

```bash
pip install "universal-p2p-sync @ git+https://github.com/<owner>/universal-p2p-sync.git@<tag>"
pip install -e ".[test]"        # development checkout
```

## Quick start

```python
import os
from universal_p2p_sync import SyncNode

sync = SyncNode(
    app_id="echo",
    user_id="user_001",              # app-level label only; never proof of identity
    device_name="My Laptop",
    database_url=os.environ["UP2P_ECHO_DATABASE_URL"],   # this device's own PostgreSQL
)
sync.on("pairing_requested", lambda e: print("Pairing code:", e["code"]))
sync.on("record_received", lambda e: print("Got", e["collection"], e["record_id"], e["data"]))
sync.start()

# 1. Pair once with a discovered/connected device (both users approve the same code)
peer = sync.peers()[0]
sync.request_pairing(peer.device_id)
sync.approve_pairing(peer.device_id)

# 2. Create a group and invite the paired device
group = sync.create_group(name="Development Team")
sync.create_invite(group_id=group.id, role="member", device_id=peer.device_id)
# ... on the other device: sync.accept_invite(invite_id) after "group_invitation_received"

# 3. Share data - stored locally first, delivered now or when members reconnect
sync.publish(group_id=group.id, collection="shared_notes", record_id="note_001",
             data={"title": "Meeting", "content": "Tomorrow at 10 AM"})
sync.delete(group_id=group.id, collection="shared_notes", record_id="note_001")
print(sync.get_sync_status(group_id=group.id))
sync.stop()
```

**GUI applications**: `SyncNode(..., callback_dispatcher=lambda fn: root.after(0, fn))`
(tkinter) runs event handlers on the UI thread; see
[docs/integration.md](docs/integration.md#6-receiving-updates-and-updating-your-ui)
for Qt.

## Documentation

| | |
|---|---|
| [integration.md](docs/integration.md) | API, configuration, environment variables, **event payloads**, GUI, outbox/adapters, errors, PyInstaller |
| [architecture.md](docs/architecture.md) | components, threads, data flow |
| [security.md](docs/security.md) | threat model, identity, TLS, pairing, encryption, revocation limits |
| [groups.md](docs/groups.md) | roles, permissions, invitations, membership log |
| [offline-sync.md](docs/offline-sync.md) | change log, checkpoints, guarantees, backups |
| [conflicts.md](docs/conflicts.md) | detection, default policy, resolvers |
| [postgresql.md](docs/postgresql.md) | setup on Linux/Windows, schema, migrations, backup & recovery |
| [protocol.md](docs/protocol.md) | language-independent wire protocol |
| [echo-integration.md](docs/echo-integration.md), [todo-integration.md](docs/todo-integration.md) | the two example applications, two-laptop walkthroughs |
| [troubleshooting.md](docs/troubleshooting.md) | firewall, discovery, errors |
| [release-checklist.md](docs/release-checklist.md) | steps before tagging a release |

## Try it on two laptops

On **each** laptop (same Wi-Fi, local PostgreSQL with an `echo_sync` database):

```bash
pip install -e .
export UP2P_ECHO_DATABASE_URL=postgresql+psycopg://echo:PASSWORD@localhost/echo_sync
python examples/echo_app.py --name "Laptop A"      # on A ("Laptop B" on B)
```

Then type `peers`, `pair 1`, compare the codes, `approve` on both, `team Dev`
and `invite 1` on A, `accept <id>` on B, and `note n1 hello` on either side.
The full script is in [docs/echo-integration.md](docs/echo-integration.md);
the To-Do equivalent is `examples/todo_app.py`
([docs/todo-integration.md](docs/todo-integration.md)). If discovery is
blocked, add `--connect <other IP>:47801`.

Firewall: allow inbound **TCP 47801** (Echo example) / **47802** (To-Do
example) and **UDP 5353** (mDNS).
- Linux (ufw): `sudo ufw allow 47801/tcp && sudo ufw allow 5353/udp`
- Windows: allow Python through Windows Defender Firewall when prompted, on
  *Private* networks, and set the Wi-Fi profile to *Private* (discovery is
  blocked on *Public* networks).

`examples/basic_peer.py` is the Milestone 1 plaintext demo (direct messages
only, `allow_insecure_transport=True`); use it only for transport debugging.

## Tests

```bash
pip install -e ".[test]"
docker run -d --name up2p-test-pg -e POSTGRES_USER=up2p -e POSTGRES_PASSWORD=up2p \
  -p 127.0.0.1:5441:5432 postgres:16-alpine
export UP2P_TEST_DATABASE_URL=postgresql+psycopg://up2p:up2p@127.0.0.1:5441/postgres
pytest                                # all tests (each node gets its own database)
UP2P_SKIP_MDNS_TESTS=1 pytest         # on hosts without working multicast
```

Without `UP2P_TEST_DATABASE_URL`, PostgreSQL-backed tests are skipped. CI
(GitHub Actions) runs the suite on Ubuntu and Windows with Python 3.11-3.13
against a real PostgreSQL, and installs the package from its Git URL.

## Limitations

* LAN only: no relay or NAT traversal; devices must reach each other directly
  (or over a VPN). Members that are never online together sync only via a
  third member.
* Decentralized revocation: removed members keep what they already received;
  removal takes effect on each device once the signed removal reaches it (see
  [security.md](docs/security.md)).
* The materialized `records` table and the group keys are stored unencrypted
  in the local database; protect it with PostgreSQL access control and disk
  encryption.
* The change log is never compacted; tombstones and history are kept.
* Designed for small teams (up to roughly 100 devices per group).
* Windows support is implemented with portable APIs and configured in CI, but
  has not yet been verified on real Windows machines by the maintainers.
* PyInstaller packaging guidance is documented but not tested in CI.

## License

MIT. See [LICENSE](LICENSE).
