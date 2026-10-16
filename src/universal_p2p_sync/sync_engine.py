"""Record synchronization engine (runs on the node's database thread).

Data model
----------
Every write is an immutable, signed **change**: ``put`` (create/update with a
JSON object) or ``delete`` (tombstone). A change names the record versions it
replaces in ``parents`` (the record's *heads* when it was written), which gives
each record a causal history (a DAG). Changes carry:

* ``author`` + ``seq``: per-device, per-group sequence numbers used for
  checkpoints, duplicate detection and catch-up after disconnects;
* ``hlc``: a hybrid logical clock timestamp used only to break ties
  deterministically;
* the data, encrypted with the group key (ChaCha20-Poly1305) and bound to the
  change metadata as associated data;
* an Ed25519 signature by the author, so changes can be relayed through any
  member and still be verified.

The ``records`` table is a materialization of the change log: for each record
it shows the *heads* - valid changes not superseded by another valid change.
One head means no conflict. Several heads with different contents are a
**conflict**: it is persisted, reported, a deterministic winner is shown
(``put`` beats ``delete``; then the highest ``(hlc, author, change_id)``),
and all versions are kept until a later change supersedes them all (an
application resolver, :meth:`resolve_conflict`, or any ordinary edit).
"""

from __future__ import annotations

import datetime
import json
import logging
import re
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import Connection, and_, delete, func, not_, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from . import events as ev
from .crypto import b64d, b64e, canonical_json, decrypt, encrypt, sha256_hex, verify_signature
from .errors import (
    IdentityError,
    InvalidPayloadError,
    MalformedMessageError,
    NotFoundError,
    PermissionDeniedError,
)
from .groups import DATA_WRITE, DEVICE_ID, GroupState, has_data_permission
from .models import Conflict, ConflictVersion, Record
from .storage import schema as t

log = logging.getLogger(__name__)

CHANGE_VERSION = 1
COLLECTION_PATTERN = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")
MAX_RECORD_ID_LENGTH = 256
MAX_PARENTS = 64
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class _DeleteSentinel:
    _instance: _DeleteSentinel | None = None

    def __new__(cls) -> _DeleteSentinel:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "DELETE"


#: Return this from a conflict resolver to resolve a conflict by deleting the record.
DELETE = _DeleteSentinel()

ConflictResolver = Callable[[Conflict], "dict[str, Any] | _DeleteSentinel | None"]


def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def validate_collection(collection: Any) -> str:
    if not isinstance(collection, str) or not COLLECTION_PATTERN.fullmatch(collection):
        raise InvalidPayloadError(
            f"invalid collection {collection!r}: use 1-64 letters, digits, '_', '.', '-'"
        )
    return collection


def validate_record_id(record_id: Any) -> str:
    if (
        not isinstance(record_id, str)
        or not 0 < len(record_id) <= MAX_RECORD_ID_LENGTH
        or _CONTROL.search(record_id)
    ):
        raise InvalidPayloadError("record_id must be 1-256 printable characters")
    return record_id


class HybridClock:
    """Hybrid logical clock: ``(milliseconds << 16) | counter``."""

    def __init__(self) -> None:
        self._last = 0
        self._lock = threading.Lock()

    def now(self) -> int:
        with self._lock:
            physical = int(time.time() * 1000) << 16
            self._last = max(self._last + 1, physical)
            return self._last

    def observe(self, remote: int) -> None:
        with self._lock:
            # Ignore absurd future timestamps (> 1 day ahead) from skewed peers.
            limit = (int(time.time() * 1000) + 86_400_000) << 16
            if remote < limit:
                self._last = max(self._last, remote)


@dataclass(frozen=True)
class ParsedChange:
    change_id: str
    change: dict[str, Any]
    signature: bytes
    wire: dict[str, Any]

    @property
    def author(self) -> str:
        return self.change["author"]

    @property
    def seq(self) -> int:
        return self.change["seq"]


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def change_aad(change: dict[str, Any]) -> bytes:
    return canonical_json(
        {
            "ctx": "up2p-change",
            "group_id": change["group_id"],
            "author": change["author"],
            "seq": change["seq"],
            "collection": change["collection"],
            "record_id": change["record_id"],
            "op": change["op"],
        }
    )


def parse_change(wire: Any, max_size: int) -> ParsedChange:
    """Structural validation of a wire change (signature checked separately)."""
    if not isinstance(wire, dict) or not isinstance(wire.get("change"), dict):
        raise MalformedMessageError("change must be an object with 'change' and 'sig'")
    change = wire["change"]
    try:
        signature = b64d(wire.get("sig"), expected_len=64)
    except ValueError as exc:
        raise MalformedMessageError(f"invalid change signature: {exc}") from exc
    encoded = canonical_json(change)
    if len(encoded) > max_size:
        raise MalformedMessageError("change too large")
    try:
        if change.get("v") != CHANGE_VERSION:
            raise MalformedMessageError("unsupported change version")
        if not isinstance(change.get("group_id"), str) or len(change["group_id"]) != 32:
            raise MalformedMessageError("invalid group_id")
        if not isinstance(change.get("author"), str) or not DEVICE_ID.fullmatch(change["author"]):
            raise MalformedMessageError("invalid author")
        for key in ("seq", "hlc"):
            if not _is_int(change.get(key)) or not 0 < change[key] < 2**63:
                raise MalformedMessageError(f"invalid {key}")
        validate_collection(change.get("collection"))
        validate_record_id(change.get("record_id"))
        op = change.get("op")
        if op not in ("put", "delete"):
            raise MalformedMessageError("invalid op")
        parents = change.get("parents")
        if (
            not isinstance(parents, list)
            or len(parents) > MAX_PARENTS
            or not all(isinstance(p, str) and len(p) == 64 for p in parents)
        ):
            raise MalformedMessageError("invalid parents")
        if op == "put":
            for key in ("key_id", "nonce", "data"):
                if not isinstance(change.get(key), str):
                    raise MalformedMessageError(f"put change requires {key}")
        elif any(change.get(k) is not None for k in ("key_id", "nonce", "data")):
            raise MalformedMessageError("delete change must not carry data")
    except InvalidPayloadError as exc:
        raise MalformedMessageError(str(exc)) from exc
    return ParsedChange(sha256_hex(encoded), change, signature, wire)


@dataclass
class IngestResult:
    stored: int = 0
    duplicates: int = 0
    rejected: int = 0
    unknown_authors: int = 0
    events: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    #: Wire form of the newly stored changes (for relaying to other members).
    stored_wires: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class _Version:
    change_id: str
    author: str
    hlc: int
    op: str
    data: dict[str, Any] | None

    @property
    def content(self) -> tuple[str, bytes]:
        return self.op, canonical_json(self.data)


class SyncStore:
    """Change log, materialized records and conflicts for one node."""

    def __init__(self, identity: Any, max_record_size: int) -> None:
        self.identity = identity
        self.device_id: str = identity.device_id
        self.max_record_size = max_record_size
        self.max_change_size = max_record_size * 2 + 4096
        self.clock = HybridClock()
        self.resolvers: dict[str, ConflictResolver] = {}
        self.adapters: dict[str, Any] = {}
        self._keys: dict[tuple[str, str], bytes] = {}

    # ------------------------------------------------------------------ keys

    def load_keys(self, conn: Connection) -> None:
        for row in conn.execute(select(t.group_keys)):
            self._keys[(row.group_id, row.key_id)] = bytes(row.key)
        max_hlc = conn.execute(select(func.max(t.changes.c.hlc))).scalar()
        if max_hlc:
            self.clock.observe(int(max_hlc))

    def has_key(self, group_id: str, key_id: str) -> bool:
        return (group_id, key_id) in self._keys

    def key(self, group_id: str, key_id: str) -> bytes | None:
        return self._keys.get((group_id, key_id))

    def store_key(self, conn: Connection, group_id: str, key_id: str, key: bytes) -> bool:
        if (group_id, key_id) in self._keys:
            return False
        conn.execute(
            pg_insert(t.group_keys)
            .values(group_id=group_id, key_id=key_id, key=key, created_at=utcnow())
            .on_conflict_do_nothing()
        )
        self._keys[(group_id, key_id)] = key
        return True

    # ------------------------------------------------------------------ local writes

    def publish(
        self,
        conn: Connection,
        state: GroupState,
        collection: str,
        record_id: str,
        data: dict[str, Any] | None,
        *,
        origin: str = "local",
        events: list[tuple[str, dict[str, Any]]] | None = None,
        parents: list[str] | None = None,
    ) -> tuple[Record, dict[str, Any]]:
        """Create, sign and apply a local change. ``data=None`` deletes."""
        group_id = state.group_id
        validate_collection(collection)
        validate_record_id(record_id)
        if not state.is_member(self.device_id):
            raise PermissionDeniedError("this device is not a member of the group")
        if not has_data_permission(state.permissions(self.device_id), DATA_WRITE, collection):
            raise PermissionDeniedError(f"this device lacks data.write for {collection!r}")
        op = "delete" if data is None else "put"
        if data is not None:
            if not isinstance(data, dict):
                raise InvalidPayloadError("record data must be a JSON object (dict)")
            try:
                plaintext = canonical_json(data)
            except (TypeError, ValueError) as exc:
                raise InvalidPayloadError(f"record data is not JSON serializable: {exc}") from exc
            if len(plaintext) > self.max_record_size:
                raise InvalidPayloadError(
                    f"record data is {len(plaintext)} bytes; limit is {self.max_record_size}"
                )
            data = json.loads(plaintext)  # normalized copy, detached from the caller
        if parents is None:
            row = conn.execute(
                select(t.records.c.heads).where(
                    t.records.c.group_id == group_id,
                    t.records.c.collection == collection,
                    t.records.c.record_id == record_id,
                )
            ).first()
            parents = sorted(row.heads) if row else []
        if op == "delete" and not parents:
            raise NotFoundError(f"record {collection}/{record_id} does not exist")
        seq = conn.execute(
            update(t.groups)
            .where(t.groups.c.group_id == group_id)
            .values(next_seq=t.groups.c.next_seq + 1)
            .returning(t.groups.c.next_seq - 1)
        ).scalar_one()
        change: dict[str, Any] = {
            "v": CHANGE_VERSION,
            "group_id": group_id,
            "author": self.device_id,
            "seq": seq,
            "hlc": self.clock.now(),
            "collection": collection,
            "record_id": record_id,
            "op": op,
            "parents": sorted(parents),
            "key_id": None,
            "nonce": None,
            "data": None,
        }
        if data is not None:
            key_id = state.current_key_id
            key = self.key(group_id, key_id) if key_id else None
            if key_id is None or key is None:
                raise PermissionDeniedError("the current group key is not available here yet")
            nonce, ciphertext = encrypt(key, canonical_json(data), change_aad(change))
            change.update(key_id=key_id, nonce=b64e(nonce), data=b64e(ciphertext))
        encoded = canonical_json(change)
        wire = {"change": change, "sig": b64e(self.identity.sign(encoded))}
        change_id = sha256_hex(encoded)
        self._insert(conn, change_id, change, wire, valid=True)
        own_events: list[tuple[str, dict[str, Any]]] = [] if events is None else events
        self.materialize(conn, state, collection, record_id, origin, own_events)
        record = self.get_record(conn, group_id, collection, record_id, include_deleted=True)
        assert record is not None
        return record, wire

    def _insert(
        self,
        conn: Connection,
        change_id: str,
        change: dict[str, Any],
        wire: dict[str, Any],
        *,
        valid: bool,
    ) -> bool:
        result = conn.execute(
            pg_insert(t.changes)
            .values(
                change_id=change_id,
                group_id=change["group_id"],
                author=change["author"],
                seq=change["seq"],
                hlc=change["hlc"],
                collection=change["collection"],
                record_id=change["record_id"],
                op=change["op"],
                body=wire,
                valid=valid,
                received_at=utcnow(),
            )
            .on_conflict_do_nothing()
        )
        return bool(result.rowcount)

    # ------------------------------------------------------------------ remote changes

    def ingest(
        self, conn: Connection, state: GroupState, wires: Iterable[Any]
    ) -> IngestResult:
        """Validate and store remote changes, then rematerialize affected records."""
        result = IngestResult()
        affected: set[tuple[str, str]] = set()
        for wire in wires:
            try:
                parsed = parse_change(wire, self.max_change_size)
            except MalformedMessageError as exc:
                log.warning("dropping malformed change: %s", exc)
                result.rejected += 1
                continue
            change = parsed.change
            if change["group_id"] != state.group_id:
                result.rejected += 1
                continue
            author = state.known.get(parsed.author)
            if author is None:
                result.unknown_authors += 1
                continue
            if not verify_signature(author.public_key, parsed.signature, canonical_json(change)):
                log.warning("dropping change with bad signature from %s", parsed.author[:12])
                result.rejected += 1
                continue
            exists = conn.execute(
                select(t.changes.c.change_id, t.changes.c.seq).where(
                    t.changes.c.group_id == state.group_id,
                    t.changes.c.author == parsed.author,
                    t.changes.c.seq == parsed.seq,
                )
            ).first()
            if exists is not None:
                if exists.change_id != parsed.change_id:
                    # Same author+seq, different content: the author forked its
                    # log (e.g. restored an old backup). Keep the first version.
                    log.warning("conflicting change for %s seq %d", parsed.author[:12], parsed.seq)
                    result.rejected += 1
                else:
                    result.duplicates += 1
                continue
            valid = state.can_write_at(parsed.author, parsed.seq, change["collection"])
            self._insert(conn, parsed.change_id, change, parsed.wire, valid=valid)
            self.clock.observe(change["hlc"])
            if parsed.author == self.device_id:
                # Our own change came back (e.g. after restoring a DB backup).
                conn.execute(
                    update(t.groups)
                    .where(t.groups.c.group_id == state.group_id, t.groups.c.next_seq <= parsed.seq)
                    .values(next_seq=parsed.seq + 1)
                )
            result.stored += 1
            result.stored_wires.append(parsed.wire)
            affected.add((change["collection"], change["record_id"]))
        for collection, record_id in sorted(affected):
            self.materialize(conn, state, collection, record_id, "remote", result.events)
        return result

    def revalidate(
        self, conn: Connection, state: GroupState, events: list[tuple[str, dict[str, Any]]]
    ) -> None:
        """Re-check every change's authorization after the membership changed."""
        rows = conn.execute(
            select(
                t.changes.c.change_id,
                t.changes.c.author,
                t.changes.c.seq,
                t.changes.c.collection,
                t.changes.c.record_id,
                t.changes.c.valid,
            ).where(t.changes.c.group_id == state.group_id)
        ).all()
        affected: set[tuple[str, str]] = set()
        for row in rows:
            valid = state.can_write_at(row.author, row.seq, row.collection)
            if valid != row.valid:
                conn.execute(
                    update(t.changes)
                    .where(t.changes.c.change_id == row.change_id)
                    .values(valid=valid)
                )
                affected.add((row.collection, row.record_id))
        for collection, record_id in sorted(affected):
            self.materialize(conn, state, collection, record_id, "membership", events)

    def rematerialize_key(
        self,
        conn: Connection,
        state: GroupState,
        key_id: str,
        events: list[tuple[str, dict[str, Any]]],
    ) -> None:
        """A group key became available: show records encrypted with it."""
        rows = conn.execute(
            select(t.changes.c.collection, t.changes.c.record_id)
            .where(
                t.changes.c.group_id == state.group_id,
                t.changes.c.body["change"]["key_id"].astext == key_id,
            )
            .distinct()
        ).all()
        for row in rows:
            self.materialize(conn, state, row.collection, row.record_id, "remote", events)

    # ------------------------------------------------------------------ materialization

    def _decode(self, group_id: str, change: dict[str, Any]) -> dict[str, Any] | None:
        key = self.key(group_id, change["key_id"])
        if key is None:
            raise LookupError("key unavailable")
        plaintext = decrypt(
            key, b64d(change["nonce"]), b64d(change["data"]), change_aad(change)
        )
        data = json.loads(plaintext)
        if not isinstance(data, dict):
            raise IdentityError("decrypted record data is not an object")
        return data

    def materialize(
        self,
        conn: Connection,
        state: GroupState,
        collection: str,
        record_id: str,
        origin: str,
        events: list[tuple[str, dict[str, Any]]],
    ) -> None:
        group_id = state.group_id
        rows = conn.execute(
            select(
                t.changes.c.change_id,
                t.changes.c.author,
                t.changes.c.hlc,
                t.changes.c.op,
                t.changes.c.valid,
                t.changes.c.body,
            ).where(
                t.changes.c.group_id == group_id,
                t.changes.c.collection == collection,
                t.changes.c.record_id == record_id,
            )
        ).all()
        parents = {r.change_id: r.body["change"]["parents"] for r in rows}
        versions: dict[str, _Version] = {}
        for r in rows:
            if not r.valid:
                continue
            change = r.body["change"]
            data = None
            if r.op == "put":
                try:
                    data = self._decode(group_id, change)
                except LookupError:
                    continue  # group key not received yet
                except (IdentityError, ValueError) as exc:
                    log.warning("cannot decrypt change %s: %s", r.change_id[:12], exc)
                    continue
            versions[r.change_id] = _Version(r.change_id, r.author, r.hlc, r.op, data)

        covered: set[str] = set()
        for change_id in versions:
            stack = list(parents.get(change_id, ()))
            while stack:
                parent = stack.pop()
                if parent in covered:
                    continue
                covered.add(parent)
                stack.extend(parents.get(parent, ()))
        heads = sorted(v for v in versions if v not in covered)

        key_cond = (
            (t.records.c.group_id == group_id)
            & (t.records.c.collection == collection)
            & (t.records.c.record_id == record_id)
        )
        previous = conn.execute(select(t.records).where(key_cond)).first()

        if not heads:
            if previous is not None:
                conn.execute(delete(t.records).where(key_cond))
                if not previous.deleted and origin != "local":
                    self._record_event(
                        conn, events, ev.RECORD_DELETED, group_id, collection, record_id,
                        None, previous.version, previous.author, origin, state,
                    )
            return

        head_versions = [versions[h] for h in heads]
        distinct = {v.content for v in head_versions}
        puts = [v for v in head_versions if v.op == "put"]
        winner = max(puts or head_versions, key=lambda v: (v.hlc, v.author, v.change_id))
        in_conflict = len(distinct) > 1
        values = dict(
            group_id=group_id,
            collection=collection,
            record_id=record_id,
            data=winner.data,
            deleted=winner.op == "delete",
            version=winner.change_id,
            heads=heads,
            hlc=winner.hlc,
            author=winner.author,
            in_conflict=in_conflict,
            updated_at=utcnow(),
        )
        unchanged = (
            previous is not None
            and previous.version == winner.change_id
            and list(previous.heads) == heads
            and previous.in_conflict == in_conflict
        )
        if not unchanged:
            conn.execute(
                pg_insert(t.records)
                .values(**values)
                .on_conflict_do_update(
                    index_elements=["group_id", "collection", "record_id"],
                    set_={k: v for k, v in values.items()
                          if k not in ("group_id", "collection", "record_id")},
                )
            )

        if in_conflict:
            self._on_conflict(conn, state, collection, record_id, head_versions, winner, events)
        else:
            self._close_conflicts(conn, group_id, collection, record_id, winner, events)

        if origin == "local" or unchanged:
            return
        was_visible = previous is not None and not previous.deleted
        now_visible = winner.op == "put"
        if now_visible and not was_visible:
            name = ev.RECORD_RECEIVED
        elif now_visible and (
            previous is None
            or previous.version != winner.change_id
            and canonical_json(previous.data) != canonical_json(winner.data)
        ):
            name = ev.RECORD_UPDATED
        elif not now_visible and was_visible:
            name = ev.RECORD_DELETED
        else:
            return
        self._record_event(
            conn, events, name, group_id, collection, record_id, winner.data,
            winner.change_id, winner.author, origin, state, in_conflict=in_conflict,
        )

    def _record_event(
        self,
        conn: Connection,
        events: list[tuple[str, dict[str, Any]]],
        name: str,
        group_id: str,
        collection: str,
        record_id: str,
        data: dict[str, Any] | None,
        version: str,
        author: str,
        origin: str,
        state: GroupState,
        *,
        in_conflict: bool = False,
    ) -> None:
        member = state.known.get(author)
        payload = {
            "group_id": group_id,
            "collection": collection,
            "record_id": record_id,
            "data": data,
            "deleted": name == ev.RECORD_DELETED,
            "version": version,
            "author_device_id": author,
            "author_user_id": member.user_id if member else None,
            "origin": origin,
            "in_conflict": in_conflict,
        }
        adapter = self.adapters.get(collection) or self.adapters.get("*")
        if adapter is not None:
            # Same transaction: the application's tables and the sync store
            # commit (or roll back) together.
            options = conn.get_execution_options()
            conn.execution_options(schema_translate_map=None)
            try:
                adapter.apply(conn, name, payload)
            finally:
                conn.execution_options(**options)
        events.append((name, payload))

    def _on_conflict(
        self,
        conn: Connection,
        state: GroupState,
        collection: str,
        record_id: str,
        heads: list[_Version],
        winner: _Version,
        events: list[tuple[str, dict[str, Any]]],
    ) -> None:
        group_id = state.group_id
        head_ids = sorted(v.change_id for v in heads)
        conflict_id = sha256_hex(
            canonical_json([group_id, collection, record_id, head_ids])
        )[:32]
        if conn.execute(
            select(t.conflicts.c.conflict_id).where(t.conflicts.c.conflict_id == conflict_id)
        ).first():
            return
        conn.execute(
            update(t.conflicts)
            .where(
                t.conflicts.c.group_id == group_id,
                t.conflicts.c.collection == collection,
                t.conflicts.c.record_id == record_id,
                t.conflicts.c.status == "open",
            )
            .values(status="superseded", resolved_at=utcnow())
        )
        versions_json = [
            {"change_id": v.change_id, "author": v.author, "hlc": v.hlc, "op": v.op,
             "data": v.data}
            for v in sorted(heads, key=lambda v: v.change_id)
        ]
        now = utcnow()
        conn.execute(
            t.conflicts.insert().values(
                conflict_id=conflict_id,
                group_id=group_id,
                collection=collection,
                record_id=record_id,
                heads=head_ids,
                versions=versions_json,
                winner=winner.change_id,
                status="open",
                detected_at=now,
            )
        )
        conflict = self._conflict_from_values(
            conflict_id, group_id, collection, record_id, versions_json, winner.change_id,
            "open", now, None,
        )
        events.append(
            (
                ev.CONFLICT_DETECTED,
                {
                    "conflict_id": conflict_id,
                    "group_id": group_id,
                    "collection": collection,
                    "record_id": record_id,
                    "versions": versions_json,
                    "winner": winner.change_id,
                },
            )
        )
        resolver = self.resolvers.get(collection) or self.resolvers.get("*")
        if resolver is None or not state.is_member(self.device_id):
            return
        if not has_data_permission(state.permissions(self.device_id), DATA_WRITE, collection):
            return
        try:
            outcome = resolver(conflict)
        except Exception:
            log.exception("conflict resolver for %r failed; conflict stays open", collection)
            return
        if outcome is None:
            return
        data = None if outcome is DELETE else outcome
        if data is not None and not isinstance(data, dict):
            log.error("conflict resolver returned %r; expected dict, DELETE or None", outcome)
            return
        self.publish(
            conn, state, collection, record_id, data,  # type: ignore[arg-type]
            origin="resolver", events=events, parents=head_ids,
        )

    def _close_conflicts(
        self,
        conn: Connection,
        group_id: str,
        collection: str,
        record_id: str,
        winner: _Version,
        events: list[tuple[str, dict[str, Any]]],
    ) -> None:
        resolved = conn.execute(
            update(t.conflicts)
            .where(
                t.conflicts.c.group_id == group_id,
                t.conflicts.c.collection == collection,
                t.conflicts.c.record_id == record_id,
                t.conflicts.c.status == "open",
            )
            .values(status="resolved", resolution=winner.change_id, resolved_at=utcnow())
            .returning(t.conflicts.c.conflict_id)
        ).scalars().all()
        for conflict_id in resolved:
            events.append(
                (
                    ev.CONFLICT_RESOLVED,
                    {
                        "conflict_id": conflict_id,
                        "group_id": group_id,
                        "collection": collection,
                        "record_id": record_id,
                        "resolution": winner.change_id,
                        "deleted": winner.op == "delete",
                        "data": winner.data,
                    },
                )
            )

    # ------------------------------------------------------------------ queries

    @staticmethod
    def _record_from_row(row: Any) -> Record:
        return Record(
            group_id=row.group_id,
            collection=row.collection,
            record_id=row.record_id,
            data=row.data,
            deleted=row.deleted,
            version=row.version,
            author_device_id=row.author,
            updated_at=row.updated_at,
            in_conflict=row.in_conflict,
        )

    def get_record(
        self,
        conn: Connection,
        group_id: str,
        collection: str,
        record_id: str,
        *,
        include_deleted: bool = False,
    ) -> Record | None:
        row = conn.execute(
            select(t.records).where(
                t.records.c.group_id == group_id,
                t.records.c.collection == collection,
                t.records.c.record_id == record_id,
            )
        ).first()
        if row is None or (row.deleted and not include_deleted):
            return None
        return self._record_from_row(row)

    def list_records(
        self,
        conn: Connection,
        group_id: str,
        collection: str | None,
        include_deleted: bool,
    ) -> list[Record]:
        query = select(t.records).where(t.records.c.group_id == group_id)
        if collection is not None:
            query = query.where(t.records.c.collection == collection)
        if not include_deleted:
            query = query.where(t.records.c.deleted.is_(False))
        query = query.order_by(t.records.c.collection, t.records.c.record_id)
        return [self._record_from_row(r) for r in conn.execute(query)]

    @staticmethod
    def _conflict_from_values(
        conflict_id: str,
        group_id: str,
        collection: str,
        record_id: str,
        versions: list[dict[str, Any]],
        winner: str,
        status: str,
        detected_at: datetime.datetime,
        resolved_at: datetime.datetime | None,
    ) -> Conflict:
        return Conflict(
            id=conflict_id,
            group_id=group_id,
            collection=collection,
            record_id=record_id,
            versions=tuple(
                ConflictVersion(
                    change_id=v["change_id"],
                    author_device_id=v["author"],
                    deleted=v["op"] == "delete",
                    data=v["data"],
                    timestamp_ms=v["hlc"] >> 16,
                )
                for v in versions
            ),
            winner=winner,
            status=status,
            detected_at=detected_at,
            resolved_at=resolved_at,
        )

    def list_conflicts(
        self, conn: Connection, group_id: str | None, status: str | None
    ) -> list[Conflict]:
        query = select(t.conflicts).order_by(t.conflicts.c.detected_at)
        if group_id is not None:
            query = query.where(t.conflicts.c.group_id == group_id)
        if status is not None:
            query = query.where(t.conflicts.c.status == status)
        return [
            self._conflict_from_values(
                r.conflict_id, r.group_id, r.collection, r.record_id, r.versions, r.winner,
                r.status, r.detected_at, r.resolved_at,
            )
            for r in conn.execute(query)
        ]

    def get_conflict(self, conn: Connection, conflict_id: str) -> Any:
        row = conn.execute(
            select(t.conflicts).where(t.conflicts.c.conflict_id == conflict_id)
        ).first()
        if row is None:
            raise NotFoundError(f"conflict {conflict_id} not found")
        return row

    # ------------------------------------------------------------------ catch-up

    @staticmethod
    def vector(conn: Connection, group_id: str) -> dict[str, int]:
        """Per author, the highest seq such that 1..seq are all stored here."""
        # Built with Core (not raw SQL) so schema_translate_map applies.
        gap = t.changes.c.seq - func.row_number().over(
            partition_by=t.changes.c.author, order_by=t.changes.c.seq
        )
        numbered = (
            select(t.changes.c.author, t.changes.c.seq, gap.label("gap"))
            .where(t.changes.c.group_id == group_id)
            .subquery()
        )
        rows = conn.execute(
            select(numbered.c.author, func.max(numbered.c.seq).label("seq"))
            .where(numbered.c.gap == 0)
            .group_by(numbered.c.author)
        ).all()
        return {r.author: int(r.seq) for r in rows}

    @staticmethod
    def _beyond(group_id: str, vector: dict[str, int]) -> Any:
        conds = [and_(t.changes.c.author == a, t.changes.c.seq > s) for a, s in vector.items()]
        if vector:
            conds.append(not_(t.changes.c.author.in_(list(vector))))
        cond = or_(*conds) if conds else True
        return and_(t.changes.c.group_id == group_id, cond)

    def changes_after(
        self, conn: Connection, group_id: str, vector: dict[str, int]
    ) -> list[dict[str, Any]]:
        rows = conn.execute(
            select(t.changes.c.body)
            .where(self._beyond(group_id, vector))
            .order_by(t.changes.c.author, t.changes.c.seq)
        )
        return [r.body for r in rows]

    def count_after(
        self,
        conn: Connection,
        group_id: str,
        vector: dict[str, int],
        author: str | None = None,
    ) -> int:
        query = select(func.count()).select_from(t.changes).where(self._beyond(group_id, vector))
        if author is not None:
            query = query.where(t.changes.c.author == author)
        return int(conn.execute(query).scalar_one())

    def undecryptable(self, conn: Connection, group_id: str) -> int:
        key_ids = [k for (g, k) in self._keys if g == group_id]
        key_col = t.changes.c.body["change"]["key_id"].astext
        query = select(func.count()).select_from(t.changes).where(
            t.changes.c.group_id == group_id, t.changes.c.op == "put"
        )
        if key_ids:
            query = query.where(not_(key_col.in_(key_ids)))
        return int(conn.execute(query).scalar_one())
