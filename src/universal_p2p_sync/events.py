"""Event bus used to notify the embedding application.

Events are queued and delivered in order by a single dispatcher task running
on the node's event loop, so network code never waits on application handlers
beyond the queue. Handlers may be plain functions or coroutine functions.
Exceptions raised by handlers are logged and never break the node.

Handlers run on the node's event-loop thread. Keep them fast; GUI applications
should marshal work to their UI thread (see ``SyncNode(callback_dispatcher=...)``).
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

log = logging.getLogger(__name__)

PEER_DISCOVERED = "peer_discovered"
PEER_LOST = "peer_lost"
PEER_CONNECTED = "peer_connected"
PEER_DISCONNECTED = "peer_disconnected"
MESSAGE_RECEIVED = "message_received"
PAIRING_REQUESTED = "pairing_requested"
PAIRING_COMPLETED = "pairing_completed"
PAIRING_REJECTED = "pairing_rejected"
DEVICE_REVOKED = "device_revoked"
GROUP_CREATED = "group_created"
GROUP_UPDATED = "group_updated"
GROUP_INVITATION_RECEIVED = "group_invitation_received"
INVITATION_RESPONSE = "invitation_response"
MEMBER_JOINED = "member_joined"
MEMBER_REMOVED = "member_removed"
MEMBER_ROLE_CHANGED = "member_role_changed"
SYNC_STARTED = "sync_started"
SYNC_PROGRESS = "sync_progress"
RECORD_RECEIVED = "record_received"
RECORD_UPDATED = "record_updated"
RECORD_DELETED = "record_deleted"
SYNC_COMPLETED = "sync_completed"
SYNC_FAILED = "sync_failed"
CONFLICT_DETECTED = "conflict_detected"
CONFLICT_RESOLVED = "conflict_resolved"

#: Payload schemas are documented in docs/integration.md ("Events").
ALL_EVENTS = frozenset(
    {
        PEER_DISCOVERED,
        PEER_LOST,
        PEER_CONNECTED,
        PEER_DISCONNECTED,
        MESSAGE_RECEIVED,
        PAIRING_REQUESTED,
        PAIRING_COMPLETED,
        PAIRING_REJECTED,
        DEVICE_REVOKED,
        GROUP_CREATED,
        GROUP_UPDATED,
        GROUP_INVITATION_RECEIVED,
        INVITATION_RESPONSE,
        MEMBER_JOINED,
        MEMBER_REMOVED,
        MEMBER_ROLE_CHANGED,
        SYNC_STARTED,
        SYNC_PROGRESS,
        RECORD_RECEIVED,
        RECORD_UPDATED,
        RECORD_DELETED,
        SYNC_COMPLETED,
        SYNC_FAILED,
        CONFLICT_DETECTED,
        CONFLICT_RESOLVED,
    }
)
WILDCARD = "*"


@dataclass(frozen=True)
class Event:
    name: str
    data: Mapping[str, Any]
    timestamp: float

    def __getitem__(self, key: str) -> Any:
        return self.data[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)


Handler = Callable[[Event], Any]


class EventBus:
    def __init__(self) -> None:
        self._handlers: dict[str, list[Handler]] = {}
        self._lock = threading.Lock()
        self._queue: asyncio.Queue[Event | None] | None = None
        self._task: asyncio.Task[None] | None = None

    def on(self, name: str, handler: Handler) -> Callable[[], None]:
        """Subscribe ``handler`` to ``name`` (or ``"*"``). Returns an unsubscribe function.

        Safe to call from any thread.
        """
        if name != WILDCARD and name not in ALL_EVENTS:
            raise ValueError(f"unknown event {name!r}")
        if not callable(handler):
            raise TypeError("handler must be callable")
        with self._lock:
            self._handlers.setdefault(name, []).append(handler)
        return lambda: self.off(name, handler)

    def off(self, name: str, handler: Handler) -> None:
        with self._lock:
            handlers = self._handlers.get(name, [])
            if handler in handlers:
                handlers.remove(handler)

    async def start(self) -> None:
        if self._task is not None:
            return
        self._queue = asyncio.Queue()
        self._task = asyncio.create_task(self._dispatch_loop(), name="up2p-events")

    async def stop(self, timeout: float = 5.0) -> None:
        """Deliver already-queued events, then stop the dispatcher."""
        if self._task is None or self._queue is None:
            return
        self._queue.put_nowait(None)
        try:
            await asyncio.wait_for(asyncio.shield(self._task), timeout)
        except TimeoutError:
            log.warning("event handlers did not finish within %.1fs; cancelling", timeout)
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._task = None
        self._queue = None

    def emit(self, name: str, /, **data: Any) -> None:
        """Queue an event. Must be called on the node's event-loop thread."""
        if name not in ALL_EVENTS:
            raise ValueError(f"unknown event {name!r}")
        if self._queue is None:
            log.debug("dropping event %s: bus not running", name)
            return
        self._queue.put_nowait(Event(name, MappingProxyType(dict(data)), time.time()))

    async def _dispatch_loop(self) -> None:
        assert self._queue is not None
        while True:
            event = await self._queue.get()
            if event is None:
                return
            with self._lock:
                handlers = list(self._handlers.get(event.name, ()))
                handlers += self._handlers.get(WILDCARD, ())
            for handler in handlers:
                try:
                    result = handler(event)
                    if inspect.isawaitable(result):
                        await result
                except Exception:
                    log.exception("event handler %r failed for %s", handler, event.name)
