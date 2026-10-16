# Architecture

`universal-p2p-sync` is a library embedded in each application process. There
is no server, cloud service or background daemon: every running application
instance is a full peer that both accepts and initiates connections.

```text
 Laptop A                                         Laptop B
 ┌──────────────────────────────┐                ┌──────────────────────────────┐
 │ Echo application (UI, model) │                │ Echo application (UI, model) │
 │   publish() ▲ events         │                │   publish() ▲ events         │
 │ ┌───────────┴──────────────┐ │   TLS 1.3 +    │ ┌───────────┴──────────────┐ │
 │ │ universal_p2p_sync node  │◄├── device auth ─┤►│ universal_p2p_sync node  │ │
 │ └───────────┬──────────────┘ │   (LAN only)   │ └───────────┬──────────────┘ │
 │   local PostgreSQL A         │                │   local PostgreSQL B         │
 │   schema up2p_echo           │                │   schema up2p_echo           │
 └──────────────────────────────┘                └──────────────────────────────┘
```

PostgreSQL is never exposed to the network; only the authenticated P2P
protocol carries data between devices.

## Components

| module | responsibility |
|---|---|
| `node.py` | Public API (`AsyncSyncNode`, `SyncNode`). Wires everything together; implements the group/sync wire handlers; owns the database worker thread. |
| `config.py` | `NodeConfig` validation and environment loading. |
| `crypto.py` | Device identity (Ed25519 + X25519), self-signed TLS certificate, sealed boxes, ChaCha20-Poly1305, pairing code. Only standard primitives from `cryptography`. |
| `network/transport.py` | Length-prefixed strict-JSON framing, size limits. |
| `network/connection.py` | Listener + dialer, TLS 1.3 contexts, handshake with key proof, duplicate-connection resolution, keepalive, rate limiting, reconnection. |
| `network/discovery.py` | mDNS/DNS-SD advertise/browse (`_up2p-sync._tcp`), filtered by `app_id`. |
| `pairing.py` | Commit/reveal numeric-comparison pairing state machine. |
| `groups.py` | Pure, deterministic evaluation of a group's signed membership log (roles, permissions, key distribution). No I/O. |
| `group_store.py` | Persistence of membership ops, invitations, group keys; creates local ops. |
| `sync_engine.py` | Signed+encrypted change log, materialized records, conflicts, checkpoints/vectors. |
| `storage/` | SQLAlchemy Core schema, engine, Alembic migrations, single-instance lock. |
| `adapters.py` | Transactional outbox helper and adapter protocol for application tables. |
| `events.py` | Ordered event queue and dispatcher. |

## Threads and transactions

* **Event loop thread** (the caller's loop for `AsyncSyncNode`, a private
  daemon thread for `SyncNode`): networking, discovery, protocol handlers.
* **Database thread** (one per node): every PostgreSQL transaction, one at a
  time. Group state objects are replaced, never mutated in place, so the loop
  can read them without locks.
* **Event dispatcher** (a task on the loop): delivers events in order. With
  `callback_dispatcher`, each handler call is forwarded to the UI thread.

Every logical operation (publishing a change, ingesting a batch, applying a
membership op, admitting a member) is one PostgreSQL transaction. Events are
collected during the transaction and emitted only after it commits.

## Data model

Three append-only logs, each entry signed by its author device:

1. **Trust records** (`trusted_devices`): local only, never synchronized.
2. **Membership operations** (`membership_ops`): per group; the group state is
   a deterministic function of the set of ops ([groups.md](groups.md)).
3. **Changes** (`changes`): per group; every record create/update/delete
   ([offline-sync.md](offline-sync.md)).

Derived tables (`records`, `conflicts`, `checkpoints`) are rebuilt from the
logs and can always be recomputed. `outbox` holds application changes not yet
turned into signed changes.

## Flow of one change

1. The application calls `publish()` (or commits an outbox row).
2. Database thread: check membership and `data.write`; encrypt the JSON with
   the current group key; assign the next per-device sequence number; sign;
   insert into `changes`; materialize `records`; commit.
3. Event loop: send the change to every connected member with `data.read`.
4. Receiver: verify the signature against the author's key from the signed
   membership log; check the author's role at that sequence number; store;
   materialize; detect conflicts; run the adapter; commit; emit
   `record_received`/`record_updated`/`record_deleted`; acknowledge
   (`sync_ack`) with its checkpoint vector; relay to its other connected
   members.
5. Members that were offline receive the change during the next sync round
   (on reconnect and every `sync_interval`) by exchanging checkpoint vectors.

## Isolation between applications

* `app_id` is part of the TLS handshake (other apps are refused with
  `app_mismatch`) and of the mDNS TXT record (other apps are not even dialed).
* Every app has its own PostgreSQL schema, its own device key pair (keys live
  in `<data_dir>/<app_id>/`), and its own group IDs; membership ops and changes
  are bound to their `app_id`/group by signature.
* Echo and To-Do can share one PostgreSQL database and one machine without
  seeing each other's data.
