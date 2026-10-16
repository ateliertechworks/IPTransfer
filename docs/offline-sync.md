# Offline synchronization

Applications keep working while devices are disconnected: every write is
committed to the local PostgreSQL database first, and devices exchange what
the other is missing whenever they meet.

## The change log

Each `publish`/`delete` creates an immutable **change**:

| field | meaning |
|---|---|
| `group_id`, `collection`, `record_id` | what is changed |
| `op` | `put` (create/update with a JSON object) or `delete` (tombstone) |
| `author`, `seq` | author device and its per-group sequence number (1, 2, 3, …, no gaps) |
| `hlc` | hybrid logical clock (milliseconds << 16 \| counter) for deterministic tie-breaks |
| `parents` | the record versions this change replaces (causal history) |
| `key_id`, `nonce`, `data` | encrypted JSON (group key, ChaCha20-Poly1305) |
| signature | Ed25519 by the author over the canonical JSON |

The change ID is the SHA-256 of the canonical change. Changes are stored in
`changes`; the current state of each record is materialized in `records`.

## Checkpoints and catch-up

A device's **vector** for a group maps each author to the highest `seq` such
that changes `1..seq` of that author are all stored locally. On every
connection (and every `sync_interval`, default 30 s) each side sends
`sync_req` with its vector and its membership-log heads; the other side
answers with:

1. its membership operations, if the heads differ (so new members' keys and
   roles are known before their changes arrive);
2. every change the requester's vector does not cover, in batches that fit
   the frame size (`sync_progress` events), the last one marked `final`
   (`sync_completed`).

After applying a batch the receiver replies `sync_ack` with its new vector;
the sender stores it in `checkpoints`. `get_sync_status()` uses these
checkpoints to report, per member, how many of your changes it has not
acknowledged yet.

Live changes are also pushed immediately to connected members and relayed by
them to their other connected members. If a pushed change reveals a gap
(a missing earlier `seq`), the receiver starts a catch-up round at once.

## Guarantees

| situation | behaviour |
|---|---|
| peer offline | changes stay in PostgreSQL; delivered on the next contact with that peer **or any other member who has them** (changes are signed, so any member can relay) |
| application restart | nothing is lost: the log, vectors and outbox are in PostgreSQL; trusted peers are redialed at their last known address |
| duplicate delivery | ignored (same `author`+`seq` and same change ID); no events |
| transfer interrupted | each batch is its own transaction; the vector only advances over contiguous sequences, so the next round resumes exactly where data is missing |
| crash mid-write | a change and its materialization commit atomically (tested by killing a writer process with SIGKILL) |
| deletion | a `delete` change is a tombstone and is synchronized like any edit; an older or equal version arriving later cannot resurrect the record because the tombstone names it as parent |
| concurrent edits | detected and persisted as conflicts, see [conflicts.md](conflicts.md) |
| member removed while offline | learns it on next contact; data published after the removal is not sent to it (see [groups.md](groups.md)) |

## Pending queues

* **Unacknowledged changes**: your changes beyond the lowest acknowledged
  `seq` among members (`SyncStatus.pending_changes`, per-peer in
  `SyncStatus.peers`). They are retransmitted automatically.
* **Outbox**: rows written by your application with `enqueue_change` and not
  yet signed (`SyncStatus.outbox_pending`). Drained every
  `outbox_poll_interval` and on `flush_outbox()`/`notify_outbox()`.
* **Undecryptable changes**: changes encrypted with a group key this device
  has not received yet (`SyncStatus.undecryptable_changes`). They become
  visible as soon as the key arrives.

## Restoring a backup

Back up the **key directory and the database together** (see
[postgresql.md](postgresql.md#backup-and-recovery)). After restoring an older
database, start the node and let it synchronize with at least one other member
**before** publishing: peers send this device's own newer changes back, which
also moves its sequence counter forward. Publishing first would reuse sequence
numbers that peers already hold with different content; they reject such
"forked" changes.

## Retention

The change log is append-only; tombstones and superseded versions are kept
(they are needed for late-joining or long-offline members). Compaction is not
implemented yet; plan disk space for the full history of shared data.
