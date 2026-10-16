# Conflict detection and resolution

## Causal metadata

Every change lists the versions it replaces (`parents` = the record's *heads*
at the time of writing). The changes of one record therefore form a DAG. The
**heads** of a record are its valid changes that no other valid change lists
as a parent.

* One head → no conflict; the record shows that version.
* Several heads with identical content (same op and data) → no conflict (for
  example, two devices made the same edit, or a resolver ran on both).
* Several heads with different content → **conflict**.

Clocks never decide whether something is a conflict; they only break ties.

## Default policy (deterministic, nothing discarded)

While a conflict is open, every device shows the same winner:

1. a `put` beats a `delete` (an edit made concurrently with a deletion is not
   silently lost);
2. otherwise the highest `(hlc, author device ID, change ID)`.

All conflicting versions are kept in the log and in the `conflicts` table, and
the record has `in_conflict = True` until the conflict is resolved.

## Exact behaviour

| situation | result |
|---|---|
| A updates, B later updates the version it saw from A | B's change has A's as parent → normal update, no conflict |
| A and B update the same version while disconnected | conflict; winner by the default policy; `conflict_detected` on both |
| A deletes, B concurrently updates | conflict; B's update is shown (put beats delete) |
| A and B both delete | same content → no conflict; record stays deleted |
| A deletes; B (who had seen the deletion) re-creates it | B's put has the tombstone as parent → record re-created, no conflict |
| a stale copy of an old version arrives later | it is an ancestor of the current head → ignored for display |
| three-way concurrent edits | one conflict with three versions |
| a new edit made while a conflict is open | it has all current heads as parents → it resolves the conflict (`conflict_resolved`) |
| a change becomes invalid (author lost write permission at that seq) | it is excluded from the heads; the record is re-materialized |

## Resolving

**Automatically** - register a resolver per collection (or `"*"`):

```python
from universal_p2p_sync import DELETE

def merge_tasks(conflict):
    versions = [v for v in conflict.versions if v.data is not None]
    if not versions:
        return None                       # leave as is (default policy)
    newest = max(versions, key=lambda v: v.timestamp_ms)
    return {**newest.data, "completed": any(v.data["completed"] for v in versions)}

sync.register_conflict_resolver("tasks", merge_tasks)
```

The resolver receives a `Conflict` (`id`, `group_id`, `collection`,
`record_id`, `versions` (each with `change_id`, `author_device_id`, `deleted`,
`data`, `timestamp_ms`), `winner`, `status`, `detected_at`) and returns a dict
(the merged data), `DELETE`, or `None` (leave the conflict open). It runs on
the database thread inside the transaction that detected the conflict, only
on devices that have `data.write`. Its result is published as a normal change
whose parents are all conflicting heads, which resolves the conflict
everywhere.

Write **deterministic** resolvers (same input → same output on every device):
several devices may resolve the same conflict at the same time, and identical
results merge without a new conflict. Non-deterministic results create a new,
smaller conflict that is again handled by the default policy.

**Manually** - for example, by asking the user:

```python
for conflict in sync.list_conflicts(group_id):          # status "open" by default
    choice = ask_user(conflict.versions)
    sync.resolve_conflict(conflict.id, choice)          # dict or DELETE
```

`list_conflicts(group_id, status=None)` also returns `resolved` and
`superseded` conflicts (history).

## Events

* `conflict_detected`: `conflict_id`, `group_id`, `collection`, `record_id`,
  `versions`, `winner`.
* `conflict_resolved`: `conflict_id`, `group_id`, `collection`, `record_id`,
  `resolution` (change ID), `deleted`, `data`.
* Record events (`record_updated`, …) carry `in_conflict`.
