"""Integration points for applications that keep their own PostgreSQL tables.

Two mechanisms connect an application's data model to the sync engine:

* **Transactional outbox** (local -> peers). The application inserts a row
  into the node's ``outbox`` table *in the same transaction* that changes its
  own tables (:func:`enqueue_change`). Either both commit or neither does, so
  no update is lost between the application's commit and the sync log. The
  node drains the outbox in the background (and on :meth:`flush_outbox`),
  turning each row into a signed change.

* **Record adapters** (peers -> local). An adapter registered for a collection
  is called inside the transaction that stores a remote change, so the
  application's tables and the sync store commit or roll back together.

Avoiding synchronization loops: adapters write the application's tables
directly and must **not** insert into the outbox or call ``publish`` for the
change they are applying. Changes coming from the outbox are applied locally
with origin ``"local"`` and never reach adapters or ``record_*`` events.
"""

from __future__ import annotations

import datetime
from typing import Any, Protocol, runtime_checkable

from sqlalchemy import Connection, MetaData, Table

from .config import SCHEMA_PATTERN
from .errors import ConfigurationError, InvalidPayloadError
from .storage import schema as t
from .sync_engine import validate_collection, validate_record_id


@runtime_checkable
class RecordAdapter(Protocol):
    """Applies remote record changes to application tables.

    ``event`` is ``record_received``, ``record_updated`` or ``record_deleted``;
    ``payload`` has the same fields as the corresponding event (see
    docs/integration.md). ``conn`` is a SQLAlchemy connection inside the sync
    transaction with no schema translation, so unqualified table names resolve
    through the normal ``search_path``. Raising aborts the whole transaction;
    the change is fetched again on the next synchronization.
    """

    def apply(self, conn: Connection, event: str, payload: dict[str, Any]) -> None: ...


_outbox_tables: dict[str, Table] = {}


def outbox_table(schema: str) -> Table:
    """The outbox table of a node's schema (``node.schema``)."""
    if not SCHEMA_PATTERN.fullmatch(schema):
        raise ConfigurationError(f"invalid schema {schema!r}")
    table = _outbox_tables.get(schema)
    if table is None:
        table = t.outbox.to_metadata(MetaData(), schema=schema)
        _outbox_tables[schema] = table
    return table


def enqueue_change(
    conn: Connection,
    *,
    schema: str,
    group_id: str,
    collection: str,
    record_id: str,
    data: dict[str, Any] | None,
) -> None:
    """Queue a record change in the caller's open transaction.

    ``data=None`` queues a deletion. ``conn`` must be connected to the same
    PostgreSQL database as the node. The change is validated and signed when
    the node drains the outbox; invalid or unauthorized rows are dropped and
    reported with a ``sync_failed`` event.
    """
    validate_collection(collection)
    validate_record_id(record_id)
    if data is not None and not isinstance(data, dict):
        raise InvalidPayloadError("record data must be a JSON object (dict)")
    conn.execute(
        outbox_table(schema)
        .insert()
        .values(
            group_id=group_id,
            collection=collection,
            record_id=record_id,
            op="delete" if data is None else "put",
            data=data,
            created_at=datetime.datetime.now(datetime.timezone.utc),
        )
    )
