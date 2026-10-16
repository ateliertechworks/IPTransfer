"""Public node API.

:class:`AsyncSyncNode` is the asyncio implementation. :class:`SyncNode` wraps
it for synchronous (e.g. desktop GUI) applications by running the node's event
loop on a dedicated background thread; networking never runs on the caller's
thread.

A node normally runs in **secure mode**: it loads (or creates) the device's
persistent Ed25519 identity, opens its own PostgreSQL schema, accepts only
TLS 1.3 connections with authenticated device keys, and offers pairing,
groups and record synchronization.

The plaintext development transport from Milestone 1 is still available with
``allow_insecure_transport=True``. It supports direct messages only (no
pairing, groups or synchronization) and must never be used in production.

Threading model: all networking runs on the node's event loop. All database
work runs on one dedicated worker thread, one transaction at a time, so the
sync store never sees concurrent writers inside one node. Events produced by a
transaction are emitted only after it commits.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import datetime
import functools
import json
import logging
import os
import threading
import time
import uuid
from collections.abc import Callable, Coroutine, Iterator
from dataclasses import dataclass
from typing import Any, TypeVar

from sqlalchemy import Connection, delete, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import SQLAlchemyError

from . import events as ev
from .config import NodeConfig
from .crypto import (
    DeviceIdentity,
    b64d,
    canonical_json,
    format_fingerprint,
    identity_directory,
)
from .errors import (
    ConfigurationError,
    InvalidPayloadError,
    InviteError,
    MalformedMessageError,
    NodeStateError,
    NotFoundError,
    NotTrustedError,
    P2PSyncError,
    PairingError,
    PeerNotConnectedError,
    PermissionDeniedError,
    ProtocolError,
    StorageError,
)
from .group_store import GroupStore
from .groups import (
    DEFAULT_OWNER_ROLE,
    DEFAULT_ROLES,
    DEVICE_ID,
    GROUP_MANAGE,
    HEX_ID,
    MEMBER_REMOVE,
    SignedOp,
    normalize_roles,
)
from .models import (
    Conflict,
    Group,
    Invite,
    Member,
    PairingRequest,
    PeerSyncStatus,
    Record,
    SyncStatus,
    TrustedDevice,
)
from .network.connection import ConnectionManager, PeerInfo, TransportSecurity
from .network.discovery import DiscoveredPeer, PeerDiscovery, local_ipv4_addresses
from .pairing import PAIRING_TYPES, PairingManager
from .storage import schema as t
from .storage.database import Database, normalize_database_url
from .sync_engine import DELETE, ConflictResolver, SyncStore, utcnow

log = logging.getLogger(__name__)

T = TypeVar("T")
MAX_USER_ID_LENGTH = 256
INVITE_TOKEN_PREFIX = "up2p1."
#: Upper bound on list items accepted in one group/sync message.
MAX_ITEMS_PER_MESSAGE = 10_000
#: A sync round that gets no final answer within this time is reported failed.
SYNC_ROUND_TIMEOUT = 120.0
JOIN_TIMEOUT = 30.0

Events = list[tuple[str, dict[str, Any]]]


@dataclass
class _Trust:
    public_key: bytes
    device_name: str
    revoked: bool


def _env_database_url(app_id: str) -> str | None:
    return os.environ.get(f"UP2P_{app_id.upper()}_DATABASE_URL") or os.environ.get(
        "UP2P_DATABASE_URL"
    )


def _resolve_roles(config: NodeConfig) -> tuple[dict[str, list[str]], str]:
    if config.roles is None:
        owner = config.owner_role or DEFAULT_OWNER_ROLE
        return normalize_roles(DEFAULT_ROLES, owner), owner
    owner = config.owner_role
    if owner is None:
        managers = [r for r, perms in config.roles.items() if GROUP_MANAGE in perms]
        if len(managers) != 1:
            raise ConfigurationError(
                "owner_role is required when roles define zero or several "
                f"roles holding {GROUP_MANAGE!r}"
            )
        owner = managers[0]
    return normalize_roles(config.roles, owner), owner


# ---------------------------------------------------------------- wire validation


def _field_str(msg: dict[str, Any], key: str, max_len: int = 256) -> str:
    value = msg.get(key)
    if not isinstance(value, str) or not 0 < len(value) <= max_len:
        raise MalformedMessageError(f"field {key!r} must be a 1-{max_len} character string")
    return value


def _field_hex32(msg: dict[str, Any], key: str) -> str:
    value = msg.get(key)
    if not isinstance(value, str) or not HEX_ID.fullmatch(value):
        raise MalformedMessageError(f"field {key!r} must be a 32-character hex id")
    return value


def _field_list(msg: dict[str, Any], key: str) -> list[Any]:
    value = msg.get(key)
    if not isinstance(value, list) or len(value) > MAX_ITEMS_PER_MESSAGE:
        raise MalformedMessageError(f"field {key!r} must be a list (max {MAX_ITEMS_PER_MESSAGE})")
    return value


def _field_bool(msg: dict[str, Any], key: str) -> bool:
    value = msg.get(key, False)
    if not isinstance(value, bool):
        raise MalformedMessageError(f"field {key!r} must be a boolean")
    return value


def _field_vector(msg: dict[str, Any], key: str = "vector") -> dict[str, int]:
    value = msg.get(key)
    if not isinstance(value, dict) or len(value) > 4096:
        raise MalformedMessageError("invalid sync vector")
    for author, seq in value.items():
        if (
            not DEVICE_ID.fullmatch(author)
            or not isinstance(seq, int)
            or isinstance(seq, bool)
            or not 0 <= seq < 2**63
        ):
            raise MalformedMessageError("invalid sync vector entry")
    return value


def _batches(items: list[Any], budget: int) -> Iterator[list[Any]]:
    """Split ``items`` into lists whose JSON size stays below ``budget`` bytes."""
    batch: list[Any] = []
    size = 0
    for item in items:
        item_size = len(canonical_json(item)) + 1
        if batch and size + item_size > budget:
            yield batch
            batch, size = [], 0
        batch.append(item)
        size += item_size
    yield batch


def parse_invite_token(token: str) -> dict[str, Any]:
    """Decode a shareable invitation code (no signature: the secret is the proof)."""
    if not isinstance(token, str) or not token.startswith(INVITE_TOKEN_PREFIX):
        raise InviteError("not an invitation code")
    try:
        data = json.loads(b64d(token[len(INVITE_TOKEN_PREFIX):].strip()))
    except (ValueError, UnicodeDecodeError) as exc:
        raise InviteError("malformed invitation code") from exc
    if not isinstance(data, dict):
        raise InviteError("malformed invitation code")
    try:
        for key in ("a", "s", "n", "r"):
            _field_str(data, key)
        _field_hex32(data, "i")
        _field_hex32(data, "g")
        if not isinstance(data.get("d"), str) or not DEVICE_ID.fullmatch(data["d"]):
            raise MalformedMessageError("d")
        if not isinstance(data.get("e"), int):
            raise MalformedMessageError("e")
    except MalformedMessageError as exc:
        raise InviteError("malformed invitation code") from exc
    return data


class AsyncSyncNode:
    """An embedded P2P node for one application on one device."""

    def __init__(
        self,
        app_id: str,
        user_id: str,
        device_name: str,
        *,
        config: NodeConfig | None = None,
        **config_overrides: Any,
    ) -> None:
        if config is None:
            config = NodeConfig(app_id=app_id, device_name=device_name, **config_overrides)
        else:
            if config_overrides:
                config = config.replace(**config_overrides)
            if config.app_id != app_id or config.device_name != device_name:
                raise ConfigurationError("config.app_id/device_name do not match arguments")
        if not isinstance(user_id, str) or not 0 < len(user_id) <= MAX_USER_ID_LENGTH:
            raise ConfigurationError("user_id must be 1-256 characters")
        if not config.allow_insecure_transport and config.database_url is None:
            env_url = _env_database_url(config.app_id)
            if env_url:
                config = config.replace(database_url=env_url)
        self.config = config
        self.app_id = config.app_id
        #: Application-supplied label. It is never treated as proof of identity
        #: or authority by the library.
        self.user_id = user_id
        self.events = ev.EventBus()
        self.secure = not config.allow_insecure_transport
        self.identity: DeviceIdentity | None = None
        security: TransportSecurity | None = None
        if self.secure:
            if config.database_url is None:
                raise ConfigurationError(
                    "database_url is required: pass database_url=... or set UP2P_DATABASE_URL "
                    "(each device needs its own local PostgreSQL database)"
                )
            normalize_database_url(config.database_url)
            self._roles, self._owner_role = _resolve_roles(config)
            self.identity = DeviceIdentity.load_or_create(
                identity_directory(config.data_dir, config.app_id), config.key_passphrase
            )
            self.device_id = self.identity.device_id
            security = TransportSecurity(self.identity, is_blocked=self._is_blocked)
        else:
            # Development transport: ephemeral, self-asserted identity.
            self.device_id = uuid.uuid4().hex
        self._connections = ConnectionManager(
            app_id=config.app_id,
            device_id=self.device_id,
            device_name=config.device_name,
            listen_host=config.listen_host,
            listen_port=config.listen_port,
            max_frame_size=config.max_frame_size,
            connect_timeout=config.connect_timeout,
            handshake_timeout=config.handshake_timeout,
            keepalive_interval=config.keepalive_interval,
            idle_timeout=config.idle_timeout,
            reconnect_initial_delay=config.reconnect_initial_delay,
            reconnect_max_delay=config.reconnect_max_delay,
            on_peer_connected=self._on_peer_connected,
            on_peer_disconnected=self._on_peer_disconnected,
            security=security,
            max_connections=config.max_connections,
            max_pending_handshakes=config.max_pending_handshakes,
            connection_rate_limit=config.connection_rate_limit,
            connection_rate_window=config.connection_rate_window,
        )
        self._connections.register_handler("message", self._handle_direct_message)
        if self.secure:
            for msg_type in PAIRING_TYPES:
                self._connections.register_handler(msg_type, self._handle_pairing)
            handlers = {
                "invite_offer": self._handle_invite_offer,
                "invite_accept": self._handle_invite_accept,
                "invite_result": self._handle_invite_result,
                "invite_reject": self._handle_invite_reject,
                "invite_revoked": self._handle_invite_revoked,
                "group_ops": self._handle_group_ops,
                "sync_req": self._handle_sync_req,
                "changes": self._handle_changes,
                "sync_ack": self._handle_sync_ack,
            }
            for msg_type, handler in handlers.items():
                self._connections.register_handler(msg_type, handler)
        self._discovery: PeerDiscovery | None = None
        self._discovery_tasks: dict[str, asyncio.Task[None]] = {}
        self._running = False

        # secure-mode state
        self._executor: concurrent.futures.ThreadPoolExecutor | None = None
        self._db: Database | None = None
        self._store: SyncStore | None = None
        self._groups: GroupStore | None = None
        self._pairing: PairingManager | None = None
        self._trusted: dict[str, _Trust] = {}
        self._resolvers: dict[str, ConflictResolver] = {}
        self._adapters: dict[str, Any] = {}
        self._tasks: set[asyncio.Task[Any]] = set()
        #: (peer, group) -> counters of the sync round in progress
        self._inflight: dict[tuple[str, str], dict[str, Any]] = {}
        self._join_waiters: dict[str, asyncio.Future[str]] = {}
        self._join_buffer: dict[str, list[Any]] = {}
        self._invite_results: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self._outbox_wakeup: asyncio.Event | None = None

    # ------------------------------------------------------------------ lifecycle

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def listen_address(self) -> tuple[str, int] | None:
        return self._connections.listen_address

    @property
    def fingerprint(self) -> str:
        """Human-comparable fingerprint of this device's identity key."""
        return format_fingerprint(self.device_id)

    @property
    def schema(self) -> str:
        """The PostgreSQL schema holding this application's sync tables."""
        return self.config.schema

    def on(self, name: str, handler: ev.Handler) -> Callable[[], None]:
        """Subscribe to an event; returns an unsubscribe function."""
        return self.events.on(name, handler)

    async def start(self) -> None:
        if self._running:
            raise NodeStateError("node already running")
        if not self.secure:
            log.warning(
                "INSECURE: app %r is running without transport encryption or peer "
                "authentication (development mode)",
                self.app_id,
            )
        await self.events.start()
        try:
            if self.secure:
                await self._open_storage()
            host, port = await self._connections.start()
            if self.config.enable_discovery:
                self._discovery = PeerDiscovery(
                    app_id=self.app_id,
                    device_id=self.device_id,
                    device_name=self.config.device_name,
                    port=port,
                    addresses=self._advertise_addresses(host),
                    on_discovered=self._on_discovered,
                    on_lost=self._on_lost,
                )
                await self._discovery.start()
            if self.secure:
                self._pairing = PairingManager(
                    app_id=self.app_id,
                    my_public_key=self.identity.public_key,  # type: ignore[union-attr]
                    send=self._connections.send,
                    emit=self.events.emit,
                    store_trust=self._store_trust,
                    timeout=self.config.pairing_timeout,
                    max_pending=self.config.max_pending_pairings,
                )
                self._pairing.start()
                self._outbox_wakeup = asyncio.Event()
                self._spawn(self._outbox_loop(), "up2p-outbox")
                self._spawn(self._sync_loop(), "up2p-sync")
                await self._reconnect_trusted()
        except BaseException:
            await self._teardown()
            raise
        self._running = True

    async def stop(self) -> None:
        """Close all connections, withdraw the mDNS advertisement and stop.

        Pending changes stay in PostgreSQL and are synchronized after the next
        start. A database transaction that is in progress completes first.
        """
        if not self._running:
            return
        self._running = False
        await self._teardown()

    async def _teardown(self) -> None:
        tasks = list(self._discovery_tasks.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._discovery_tasks.clear()
        if self._discovery is not None:
            try:
                await self._discovery.stop()
            except Exception:
                log.exception("error stopping discovery")
            self._discovery = None
        current = asyncio.current_task()
        pending = [task for task in self._tasks if task is not current]
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        self._tasks.clear()
        if self._pairing is not None:
            await self._pairing.stop()
            self._pairing = None
        await self._connections.stop()
        for fut in (*self._join_waiters.values(), *self._invite_results.values()):
            if not fut.done():
                fut.set_exception(NodeStateError("node stopped"))
                fut.exception()
        self._join_waiters.clear()
        self._invite_results.clear()
        self._inflight.clear()
        self._join_buffer.clear()
        await self._close_storage()
        await self.events.stop()

    async def __aenter__(self) -> AsyncSyncNode:
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.stop()

    # ------------------------------------------------------------------ storage plumbing

    async def _open_storage(self) -> None:
        assert self.identity is not None and self.config.database_url is not None
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=1, thread_name_prefix=f"up2p-db-{self.app_id}"
        )
        db = Database(self.config.database_url, self.config.schema)
        self._db = db
        await self._in_db(
            functools.partial(db.open, migrate=self.config.auto_migrate, device_id=self.device_id)
        )
        store = SyncStore(self.identity, self.config.max_record_size)
        store.resolvers = self._resolvers
        store.adapters = self._adapters
        groups = GroupStore(
            self.identity, self.app_id, self.user_id, self.config.device_name, store
        )
        self._store, self._groups = store, groups

        def load(conn: Connection, events: Events) -> list[Any]:
            store.load_keys(conn)
            groups.load(conn)
            return list(conn.execute(select(t.trusted_devices)))

        rows = await self._tx(load)
        self._trusted = {
            r.device_id: _Trust(bytes(r.public_key), r.device_name, r.revoked_at is not None)
            for r in rows
        }

    async def _close_storage(self) -> None:
        db, executor = self._db, self._executor
        self._db = self._executor = None
        self._store = self._groups = None
        if db is not None and executor is not None:
            try:
                await asyncio.get_running_loop().run_in_executor(executor, db.close)
            except Exception:
                log.exception("error closing database")
        if executor is not None:
            executor.shutdown(wait=False)

    async def _in_db(self, fn: Callable[[], T]) -> T:
        if self._executor is None:
            raise NodeStateError("node is not running; call start() first")
        return await asyncio.get_running_loop().run_in_executor(self._executor, fn)

    async def _tx(self, fn: Callable[[Connection, Events], T]) -> T:
        """Run ``fn`` in one database transaction; emit its events after commit."""
        db = self._db
        if db is None:
            raise NodeStateError("node is not running; call start() first")
        events: Events = []

        def run() -> T:
            with db.transaction() as conn:
                return fn(conn, events)

        try:
            result = await self._in_db(run)
        except SQLAlchemyError as exc:
            raise StorageError(f"PostgreSQL operation failed: {exc}") from exc
        for name, payload in events:
            self.events.emit(name, **payload)
        return result

    def _require_secure(self) -> tuple[GroupStore, SyncStore]:
        if not self.secure:
            raise NodeStateError(
                "pairing, groups and synchronization need the secure transport "
                "(remove allow_insecure_transport)"
            )
        # Storage is open from early in start() until late in stop(), so
        # protocol handlers also work while the node is starting up.
        if self._groups is None or self._store is None:
            raise NodeStateError("node is not running; call start() first")
        return self._groups, self._store

    def _spawn(self, coro: Coroutine[Any, Any, Any], name: str = "up2p-task") -> None:
        task = asyncio.create_task(coro, name=name)
        self._tasks.add(task)

        def done(task: asyncio.Task[Any]) -> None:
            self._tasks.discard(task)
            if not task.cancelled() and task.exception() is not None:
                exc = task.exception()
                if isinstance(exc, (P2PSyncError, OSError)):
                    log.info("background task %s failed: %s", task.get_name(), exc)
                else:
                    log.error("background task %s failed", task.get_name(), exc_info=exc)

        task.add_done_callback(done)

    # ------------------------------------------------------------------ peers

    def peers(self) -> list[PeerInfo]:
        """Currently connected peers."""
        return self._connections.peers()

    def discovered_peers(self) -> list[DiscoveredPeer]:
        return list(self._discovery.peers.values()) if self._discovery else []

    async def connect(self, host: str, port: int) -> PeerInfo:
        """Connect once to a peer by IP/hostname and port (manual connection)."""
        self._require_running()
        return await self._connections.connect(host, port)

    def add_peer_address(self, host: str, port: int) -> None:
        """Keep reconnecting to ``host:port`` in the background until removed."""
        self._require_running()
        self._connections.add_persistent_peer(host, port)

    def remove_peer_address(self, host: str, port: int) -> None:
        self._connections.remove_persistent_peer(host, port)

    async def disconnect(self, device_id: str) -> None:
        await self._connections.disconnect(device_id)

    def _peer(self, device_id: str) -> PeerInfo:
        for peer in self._connections.peers():
            if peer.device_id == device_id:
                return peer
        raise PeerNotConnectedError(f"not connected to {device_id[:16]}")

    # ------------------------------------------------------------------ messages

    async def send_message(self, device_id: str, payload: dict[str, Any]) -> str:
        """Send a JSON object to one connected peer. Returns the message ID.

        Delivery is at-most-once; there is no persistence or retry. Use
        :meth:`publish` for durable, authorized data exchange. In secure mode
        the peer must be paired or share a group with this device.
        """
        self._require_running()
        if not isinstance(payload, dict):
            raise InvalidPayloadError("payload must be a JSON object (dict)")
        if self.secure and not self._may_talk(device_id):
            raise NotTrustedError("the device is not paired and shares no group with this device")
        message_id = uuid.uuid4().hex
        await self._connections.send(
            device_id, {"type": "message", "id": message_id, "payload": payload}
        )
        return message_id

    async def broadcast_message(self, payload: dict[str, Any]) -> int:
        """Send ``payload`` to every connected (and, in secure mode, trusted) peer."""
        self._require_running()
        if not isinstance(payload, dict):
            raise InvalidPayloadError("payload must be a JSON object (dict)")
        sent = 0
        for peer in self.peers():
            try:
                await self.send_message(peer.device_id, payload)
                sent += 1
            except (PeerNotConnectedError, NotTrustedError):
                pass
        return sent

    # ------------------------------------------------------------------ pairing & trust

    def _is_blocked(self, device_id: str) -> bool:
        trust = self._trusted.get(device_id)
        return trust is not None and trust.revoked

    def is_trusted(self, device_id: str) -> bool:
        trust = self._trusted.get(device_id)
        return trust is not None and not trust.revoked

    def _shared_groups(self, device_id: str) -> list[str]:
        if self._groups is None:
            return []
        return [
            gid
            for gid, state in list(self._groups.states.items())
            if state.is_member(self.device_id) and state.was_member(device_id)
        ]

    def _may_talk(self, device_id: str) -> bool:
        return self.is_trusted(device_id) or bool(self._shared_groups(device_id))

    async def request_pairing(self, device_id: str) -> PairingRequest:
        """Start pairing with a connected device.

        Returns once both devices have computed the 6-digit comparison code
        (also delivered to both sides as a ``pairing_requested`` event). The
        users must check that both screens show the same code and then call
        :meth:`approve_pairing` on both devices.
        """
        self._require_secure()
        if self.is_trusted(device_id):
            raise PairingError("device is already paired")
        assert self._pairing is not None
        return await self._pairing.request(self._peer(device_id))

    async def approve_pairing(self, device_id: str) -> None:
        """Confirm that the codes match. Pairing completes when both sides approve."""
        self._require_secure()
        assert self._pairing is not None
        await self._pairing.approve(device_id)

    async def reject_pairing(self, device_id: str, reason: str = "rejected") -> None:
        self._require_secure()
        assert self._pairing is not None
        await self._pairing.reject(device_id, reason)

    async def wait_for_pairing(self, device_id: str, timeout: float = 60.0) -> bool:
        """Wait until a pairing in progress completes (True) or fails (False)."""
        self._require_secure()
        assert self._pairing is not None
        try:
            return await self._pairing.wait_completed(device_id, timeout)
        except NotFoundError:
            return self.is_trusted(device_id)  # already finished (or never started)

    def pairing_requests(self) -> list[PairingRequest]:
        return self._pairing.requests() if self._pairing is not None else []

    async def _store_trust(self, peer: PeerInfo) -> None:
        assert peer.public_key is not None

        def store(conn: Connection, events: Events) -> None:
            values = dict(
                public_key=peer.public_key,
                device_name=peer.device_name,
                paired_at=utcnow(),
                revoked_at=None,
                last_seen_at=utcnow(),
                last_address=peer.remote_host,
                last_port=peer.listen_port,
            )
            conn.execute(
                pg_insert(t.trusted_devices)
                .values(device_id=peer.device_id, **values)
                .on_conflict_do_update(index_elements=["device_id"], set_=values)
            )

        await self._tx(store)
        self._trusted[peer.device_id] = _Trust(peer.public_key, peer.device_name, False)
        self._spawn(self._after_contact(peer), "up2p-after-pairing")

    async def list_trusted_devices(self, include_revoked: bool = True) -> list[TrustedDevice]:
        self._require_secure()
        connected = {p.device_id for p in self.peers()}

        def query(conn: Connection, events: Events) -> list[Any]:
            return list(conn.execute(select(t.trusted_devices).order_by(t.trusted_devices.c.paired_at)))

        return [
            TrustedDevice(
                device_id=r.device_id,
                device_name=r.device_name,
                fingerprint=format_fingerprint(r.device_id),
                paired_at=r.paired_at,
                revoked_at=r.revoked_at,
                last_seen_at=r.last_seen_at,
                connected=r.device_id in connected,
            )
            for r in await self._tx(query)
            if include_revoked or r.revoked_at is None
        ]

    async def revoke_device(self, device_id: str, *, remove_from_groups: bool = True) -> None:
        """Stop trusting a paired device and refuse its future connections.

        With ``remove_from_groups`` the device is also removed from every group
        in which this device holds ``member.remove`` (which rotates the group
        keys). In other groups, ask an administrator to remove it.
        """
        groups, _ = self._require_secure()
        trust = self._trusted.get(device_id)
        if trust is None:
            raise NotFoundError("device is not paired")

        def revoke(conn: Connection, events: Events) -> None:
            conn.execute(
                update(t.trusted_devices)
                .where(t.trusted_devices.c.device_id == device_id)
                .values(revoked_at=utcnow())
            )

        await self._tx(revoke)
        trust.revoked = True
        await self._connections.disconnect(device_id)
        self.events.emit(ev.DEVICE_REVOKED, device_id=device_id, device_name=trust.device_name)
        if remove_from_groups:
            for gid, state in list(groups.states.items()):
                if (
                    device_id in state.members
                    and state.is_member(self.device_id)
                    and state.has_permission(self.device_id, MEMBER_REMOVE)
                ):
                    try:
                        await self.remove_member(gid, device_id)
                    except P2PSyncError as exc:
                        log.warning("could not remove revoked device from %s: %s", gid, exc)

    async def forget_device(self, device_id: str) -> None:
        """Delete a trust record entirely (allows pairing again after revocation)."""
        self._require_secure()

        def forget(conn: Connection, events: Events) -> None:
            conn.execute(delete(t.trusted_devices).where(t.trusted_devices.c.device_id == device_id))

        await self._tx(forget)
        self._trusted.pop(device_id, None)

    async def _reconnect_trusted(self) -> None:
        def query(conn: Connection, events: Events) -> list[Any]:
            return list(
                conn.execute(
                    select(t.trusted_devices.c.last_address, t.trusted_devices.c.last_port).where(
                        t.trusted_devices.c.revoked_at.is_(None),
                        t.trusted_devices.c.last_address.is_not(None),
                        t.trusted_devices.c.last_port.is_not(None),
                    )
                )
            )

        for row in await self._tx(query):
            self._connections.add_persistent_peer(row.last_address, row.last_port)

    # ------------------------------------------------------------------ groups

    async def create_group(
        self,
        name: str,
        *,
        roles: dict[str, list[str]] | None = None,
        owner_role: str | None = None,
    ) -> Group:
        """Create a group owned by this device. Roles default to the node's role model."""
        groups, _ = self._require_secure()
        if roles is None:
            roles, owner = self._roles, owner_role or self._owner_role
        else:
            roles, owner = _resolve_roles(
                self.config.replace(roles=roles, owner_role=owner_role)
            )
        state = await self._tx(lambda c, e: groups.create_group(c, name, roles, owner, e))
        return groups.group_view(state.group_id)

    def list_groups(self, include_inactive: bool = False) -> list[Group]:
        groups, _ = self._require_secure()
        views = [groups.group_view(gid) for gid in list(groups.states)]
        return [g for g in views if include_inactive or g.status == "active"]

    def get_group(self, group_id: str) -> Group:
        groups, _ = self._require_secure()
        return groups.group_view(group_id)

    def list_members(self, group_id: str) -> list[Member]:
        groups, _ = self._require_secure()
        return groups.member_views(group_id, {p.device_id for p in self.peers()})

    def has_permission(self, group_id: str, permission: str, device_id: str | None = None) -> bool:
        """Check a (library- or application-defined) permission in a group."""
        groups, _ = self._require_secure()
        state = groups.require_state(group_id)
        return state.has_permission(device_id or self.device_id, permission)

    async def rename_group(self, group_id: str, name: str) -> Group:
        groups, _ = self._require_secure()
        ops = await self._tx(lambda c, e: groups.rename(c, group_id, name, e))
        await self._after_local_ops(group_id, ops)
        return groups.group_view(group_id)

    async def remove_member(self, group_id: str, device_id: str) -> None:
        """Remove a member (requires ``member.remove``) and rotate the group key."""
        groups, _ = self._require_secure()
        ops = await self._tx(lambda c, e: groups.remove_member(c, group_id, device_id, e))
        await self._after_local_ops(group_id, ops)

    #: Revoking a member's group access is the same operation as removing it.
    revoke_group_access = remove_member

    async def leave_group(self, group_id: str) -> None:
        await self.remove_member(group_id, self.device_id)

    async def change_member_role(self, group_id: str, device_id: str, role: str) -> None:
        groups, _ = self._require_secure()
        ops = await self._tx(lambda c, e: groups.change_role(c, group_id, device_id, role, e))
        await self._after_local_ops(group_id, ops)

    async def _after_local_ops(self, group_id: str, ops: list[SignedOp]) -> None:
        if ops:
            await self._gossip_ops(group_id, [op.to_wire() for op in ops], exclude=None)

    async def _gossip_ops(self, group_id: str, wires: list[Any], exclude: str | None) -> None:
        groups = self._groups
        state = groups.states.get(group_id) if groups is not None else None
        if state is None:
            return
        for peer in self.peers():
            if peer.device_id == exclude or not state.was_member(peer.device_id):
                continue
            await self._send_batched(peer.device_id, "group_ops", group_id, "ops", wires)
            if state.is_member(peer.device_id) and state.is_member(self.device_id):
                self._spawn(self._sync_with(peer.device_id, [group_id]), "up2p-sync-peer")

    # ------------------------------------------------------------------ invitations

    async def create_invite(
        self,
        group_id: str,
        role: str,
        *,
        device_id: str | None = None,
        ttl: float | None = None,
        max_uses: int = 1,
    ) -> Invite:
        """Invite a device into ``group_id`` with ``role``.

        With ``device_id`` (a paired device) the invitation is delivered to
        that device automatically (now or when it next connects) and can only
        be used by it. Without it, share ``invite.token`` over a channel you
        trust; any device presenting it can join until it expires or is used
        ``max_uses`` times.
        """
        groups, _ = self._require_secure()
        if device_id is not None and not self.is_trusted(device_id):
            raise NotTrustedError("directed invitations require a paired device")
        lifetime = self.config.invite_ttl if ttl is None else float(ttl)
        if lifetime <= 0:
            raise InviteError("ttl must be positive")
        invite, _secret = await self._tx(
            lambda c, e: groups.create_invite(c, group_id, role, device_id, lifetime, max_uses)
        )
        if device_id is not None and self._connections.is_connected(device_id):
            await self._deliver_invites(device_id)
        return invite

    async def list_invites(
        self, group_id: str | None = None, direction: str | None = None
    ) -> list[Invite]:
        groups, _ = self._require_secure()
        return await self._tx(lambda c, e: groups.list_invites(c, group_id, direction))

    async def _deliver_invites(self, device_id: str) -> None:
        groups, _ = self._require_secure()
        rows = await self._tx(lambda c, e: groups.undelivered_invites(c, device_id))
        for row in rows:
            if row.secret is None:
                continue
            await self._connections.send(
                device_id,
                {
                    "type": "invite_offer",
                    "invite_id": row.invite_id,
                    "group_id": row.group_id,
                    "group_name": row.group_name,
                    "role": row.role,
                    "secret": row.secret,
                    "expires_at": int(row.expires_at.timestamp()),
                },
            )
            await self._tx(lambda c, e, i=row.invite_id: groups.mark_delivered(c, i))

    async def accept_invite(self, invite: str, timeout: float = JOIN_TIMEOUT) -> Group:
        """Accept an invitation (its ID, or a shareable invitation code) and join.

        The inviting device must be connected. Returns the joined group.
        """
        groups, _ = self._require_secure()
        if invite.startswith(INVITE_TOKEN_PREFIX):
            data = parse_invite_token(invite)
            if data["a"] != self.app_id:
                raise InviteError("the invitation belongs to another application")
            if data["d"] == self.device_id:
                raise InviteError("cannot accept your own invitation")
            expires = datetime.datetime.fromtimestamp(data["e"], datetime.timezone.utc)
            await self._tx(
                lambda c, e: groups.record_incoming_invite(
                    c,
                    invite_id=data["i"],
                    group_id=data["g"],
                    group_name=data["n"][:200],
                    role=data["r"][:32],
                    inviter=data["d"],
                    secret=data["s"],
                    expires_at=expires,
                )
            )
            invite_id = data["i"]
        else:
            invite_id = invite
        row = await self._tx(lambda c, e: groups.get_invite(c, invite_id))
        if row.direction != "incoming":
            raise InviteError("only received invitations can be accepted")
        if row.group_id in groups.states and groups.states[row.group_id].is_member(self.device_id):
            raise InviteError("already a member of this group")
        if row.status not in ("pending", "accepted"):
            raise InviteError(f"invitation is {row.status}")
        if row.expires_at < utcnow():
            await self._tx(lambda c, e: groups.set_invite_status(c, invite_id, "expired"))
            raise InviteError("invitation expired")
        if not self._connections.is_connected(row.inviter_device_id):
            raise PeerNotConnectedError(
                "the inviting device must be online and connected to accept its invitation"
            )
        await self._tx(lambda c, e: groups.set_invite_status(c, invite_id, "accepted"))
        loop = asyncio.get_running_loop()
        joined = self._join_waiters.get(row.group_id)
        if joined is None or joined.done():
            joined = loop.create_future()
            self._join_waiters[row.group_id] = joined
        result = loop.create_future()
        self._invite_results[invite_id] = result
        try:
            await self._connections.send(
                row.inviter_device_id,
                {
                    "type": "invite_accept",
                    "invite_id": invite_id,
                    "secret": row.secret,
                    "member": groups.member_payload(),
                },
            )
            done, _ = await asyncio.wait(
                {joined, result}, timeout=timeout, return_when=asyncio.FIRST_COMPLETED
            )
            if result in done and not result.result().get("ok"):
                error = str(result.result().get("error", "rejected"))[:200]
                status = "expired" if "expired" in error else "pending"
                await self._tx(lambda c, e: groups.set_invite_status(c, invite_id, status))
                raise InviteError(f"invitation refused by the inviter: {error}")
            await asyncio.wait_for(asyncio.shield(joined), timeout)
        except TimeoutError as exc:
            raise InviteError("timed out waiting for the group membership") from exc
        finally:
            self._invite_results.pop(invite_id, None)
        return groups.group_view(row.group_id)

    #: Joining a group means accepting an invitation to it.
    join_group = accept_invite

    async def reject_invite(self, invite_id: str) -> None:
        groups, _ = self._require_secure()
        row = await self._tx(lambda c, e: groups.get_invite(c, invite_id))
        if row.direction != "incoming":
            raise InviteError("only received invitations can be rejected")
        await self._tx(lambda c, e: groups.set_invite_status(c, invite_id, "rejected"))
        try:
            await self._connections.send(
                row.inviter_device_id, {"type": "invite_reject", "invite_id": invite_id}
            )
        except PeerNotConnectedError:
            pass

    async def revoke_invite(self, invite_id: str) -> None:
        """Invalidate an outgoing invitation that has not been used up yet."""
        groups, _ = self._require_secure()
        row = await self._tx(lambda c, e: groups.get_invite(c, invite_id))
        if row.direction != "outgoing":
            raise InviteError("only invitations created here can be revoked")
        await self._tx(lambda c, e: groups.set_invite_status(c, invite_id, "revoked"))
        if row.invitee_device_id and self._connections.is_connected(row.invitee_device_id):
            try:
                await self._connections.send(
                    row.invitee_device_id, {"type": "invite_revoked", "invite_id": invite_id}
                )
            except PeerNotConnectedError:
                pass

    # ------------------------------------------------------------------ records

    async def publish(
        self, group_id: str, collection: str, record_id: str, data: dict[str, Any]
    ) -> Record:
        """Create or update a shared record and send it to the group's members.

        The change is committed to PostgreSQL first; members that are offline
        receive it when they reconnect.
        """
        if not isinstance(data, dict):
            raise InvalidPayloadError("record data must be a JSON object (dict)")
        return await self._write(group_id, collection, record_id, data)

    async def delete(self, group_id: str, collection: str, record_id: str) -> Record:
        """Delete a shared record (a tombstone is kept and synchronized)."""
        return await self._write(group_id, collection, record_id, None)

    async def _write(
        self,
        group_id: str,
        collection: str,
        record_id: str,
        data: dict[str, Any] | None,
        parents: list[str] | None = None,
    ) -> Record:
        groups, store = self._require_secure()

        def write(conn: Connection, events: Events) -> tuple[Record, dict[str, Any]]:
            state = groups.require_member(group_id)
            return store.publish(
                conn, state, collection, record_id, data, events=events, parents=parents
            )

        record, wire = await self._tx(write)
        await self._push(group_id, [wire], exclude=None)
        return record

    async def get_record(
        self, group_id: str, collection: str, record_id: str, *, include_deleted: bool = False
    ) -> Record | None:
        groups, store = self._require_secure()
        groups.require_state(group_id)
        return await self._tx(
            lambda c, e: store.get_record(
                c, group_id, collection, record_id, include_deleted=include_deleted
            )
        )

    async def list_records(
        self, group_id: str, collection: str | None = None, *, include_deleted: bool = False
    ) -> list[Record]:
        groups, store = self._require_secure()
        groups.require_state(group_id)
        return await self._tx(
            lambda c, e: store.list_records(c, group_id, collection, include_deleted)
        )

    def register_conflict_resolver(self, collection: str, resolver: ConflictResolver) -> None:
        """Resolve conflicts in ``collection`` (or ``"*"``) automatically.

        ``resolver(conflict)`` runs on the database thread when a conflict is
        detected and returns the merged data (dict), :data:`DELETE`, or None
        to leave the conflict open for manual resolution.
        """
        if not callable(resolver):
            raise TypeError("resolver must be callable")
        self._resolvers[collection] = resolver

    def register_adapter(self, collection: str, adapter: Any) -> None:
        """Apply remote changes of ``collection`` (or ``"*"``) to application tables.

        See :class:`universal_p2p_sync.adapters.RecordAdapter`.
        """
        if not callable(getattr(adapter, "apply", None)):
            raise TypeError("adapter must have an apply(conn, event, payload) method")
        self._adapters[collection] = adapter

    async def list_conflicts(
        self, group_id: str | None = None, status: str | None = "open"
    ) -> list[Conflict]:
        _, store = self._require_secure()
        return await self._tx(lambda c, e: store.list_conflicts(c, group_id, status))

    async def resolve_conflict(self, conflict_id: str, data: Any) -> Record:
        """Resolve a conflict with merged ``data`` (dict) or :data:`DELETE`."""
        _, store = self._require_secure()
        row = await self._tx(lambda c, e: store.get_conflict(c, conflict_id))
        if row.status != "open":
            raise NotFoundError(f"conflict {conflict_id} is {row.status}")
        if data is not DELETE and not isinstance(data, dict):
            raise InvalidPayloadError("resolution must be a dict or DELETE")
        return await self._write(
            row.group_id,
            row.collection,
            row.record_id,
            None if data is DELETE else data,
            parents=list(row.heads),
        )

    # ------------------------------------------------------------------ outbox

    async def flush_outbox(self) -> int:
        """Publish every change queued in the transactional outbox now."""
        groups, store = self._require_secure()
        total = 0
        while True:

            def drain(conn: Connection, events: Events) -> tuple[list[Any], list[Any], int]:
                rows = conn.execute(
                    select(t.outbox).order_by(t.outbox.c.id).limit(200).with_for_update(
                        skip_locked=True
                    )
                ).all()
                published: list[tuple[str, dict[str, Any]]] = []
                failures: list[tuple[Any, str]] = []
                for row in rows:
                    savepoint = conn.begin_nested()
                    row_events: Events = []
                    try:
                        if row.op not in ("put", "delete"):
                            raise InvalidPayloadError(f"invalid outbox op {row.op!r}")
                        state = groups.require_member(row.group_id)
                        _, wire = store.publish(
                            conn,
                            state,
                            row.collection,
                            row.record_id,
                            row.data if row.op == "put" else None,
                            events=row_events,
                        )
                        savepoint.commit()
                        events.extend(row_events)
                        published.append((row.group_id, wire))
                    except P2PSyncError as exc:
                        savepoint.rollback()
                        failures.append((row, str(exc)))
                    conn.execute(delete(t.outbox).where(t.outbox.c.id == row.id))
                return published, failures, len(rows)

            published, failures, count = await self._tx(drain)
            for row, reason in failures:
                log.warning("dropping outbox row %s: %s", row.id, reason)
                self.events.emit(
                    ev.SYNC_FAILED,
                    group_id=row.group_id,
                    device_id=None,
                    reason=f"outbox: {reason}"[:300],
                    outbox_id=row.id,
                    collection=row.collection,
                    record_id=row.record_id,
                )
            by_group: dict[str, list[dict[str, Any]]] = {}
            for gid, wire in published:
                by_group.setdefault(gid, []).append(wire)
            for gid, wires in by_group.items():
                await self._push(gid, wires, exclude=None)
            total += len(published)
            if count < 200:
                return total

    def notify_outbox(self) -> None:
        """Wake the outbox worker (call after committing outbox rows)."""
        if self._outbox_wakeup is not None:
            self._outbox_wakeup.set()

    async def _outbox_loop(self) -> None:
        assert self._outbox_wakeup is not None
        while True:
            try:
                await asyncio.wait_for(
                    self._outbox_wakeup.wait(), self.config.outbox_poll_interval
                )
            except TimeoutError:
                pass
            self._outbox_wakeup.clear()
            try:
                await self.flush_outbox()
            except (StorageError, NodeStateError) as exc:
                log.warning("outbox flush failed: %s", exc)

    # ------------------------------------------------------------------ sync status

    async def get_sync_status(self, group_id: str) -> SyncStatus:
        groups, store = self._require_secure()
        state = groups.require_state(group_id)
        connected = {p.device_id for p in self.peers()}
        me = self.device_id

        def status(conn: Connection, events: Events) -> SyncStatus:
            def count(*conds: Any, table: Any = t.changes) -> int:
                return int(
                    conn.execute(select(func.count()).select_from(table).where(*conds)).scalar_one()
                )

            local = count(t.changes.c.group_id == group_id, t.changes.c.author == me)
            total = count(t.changes.c.group_id == group_id)
            outbox = count(t.outbox.c.group_id == group_id, table=t.outbox)
            conflicts = count(
                t.conflicts.c.group_id == group_id, t.conflicts.c.status == "open",
                table=t.conflicts,
            )
            checkpoints = {
                r.device_id: r
                for r in conn.execute(
                    select(t.checkpoints).where(t.checkpoints.c.group_id == group_id)
                )
            }
            peers = []
            acked: list[int] = []
            for member in state.members.values():
                if member.device_id == me:
                    continue
                cp = checkpoints.get(member.device_id)
                vector = dict(cp.vector) if cp is not None else {}
                acked.append(int(vector.get(me, 0)))
                peers.append(
                    PeerSyncStatus(
                        device_id=member.device_id,
                        device_name=member.device_name,
                        connected=member.device_id in connected,
                        pending_changes=store.count_after(conn, group_id, vector, author=me),
                        last_ack_at=cp.updated_at if cp is not None else None,
                    )
                )
            pending = (
                count(
                    t.changes.c.group_id == group_id,
                    t.changes.c.author == me,
                    t.changes.c.seq > min(acked),
                )
                if acked
                else 0
            )
            return SyncStatus(
                group_id=group_id,
                local_changes=local,
                total_changes=total,
                pending_changes=pending,
                outbox_pending=outbox,
                open_conflicts=conflicts,
                undecryptable_changes=store.undecryptable(conn, group_id),
                peers=tuple(peers),
            )

        return await self._tx(status)

    async def sync_now(self, group_id: str | None = None) -> None:
        """Start a synchronization round with every connected member now."""
        self._require_secure()
        for peer in self.peers():
            groups = self._shared_groups(peer.device_id)
            if group_id is not None:
                groups = [g for g in groups if g == group_id]
            if groups:
                await self._sync_with(peer.device_id, groups)

    # ------------------------------------------------------------------ sync protocol

    def _frame_budget(self) -> int:
        return int(self.config.max_frame_size * 0.75)

    async def _send_batched(
        self, device_id: str, msg_type: str, group_id: str, key: str, items: list[Any],
        **extra: Any,
    ) -> None:
        batches = list(_batches(items, self._frame_budget()))
        for index, batch in enumerate(batches):
            message = {"type": msg_type, "group_id": group_id, key: batch, **extra}
            if "final" in extra:
                message["final"] = extra["final"] and index == len(batches) - 1
            await self._connections.send(device_id, message)

    async def _push(self, group_id: str, wires: list[dict[str, Any]], exclude: str | None) -> None:
        """Send new changes to every connected member allowed to read them."""
        groups = self._groups
        state = groups.states.get(group_id) if groups is not None else None
        if state is None or not wires:
            return
        for peer in self.peers():
            if peer.device_id == exclude or not state.can_read(peer.device_id):
                continue
            try:
                await self._send_batched(peer.device_id, "changes", group_id, "changes", wires)
            except PeerNotConnectedError:
                pass

    async def _sync_with(self, device_id: str, group_ids: list[str] | None = None) -> None:
        groups, store = self._require_secure()
        for group_id in group_ids if group_ids is not None else self._shared_groups(device_id):
            key = (device_id, group_id)
            state = groups.states.get(group_id)
            if key in self._inflight or state is None or not state.is_member(self.device_id):
                continue
            vector = await self._tx(lambda c, e, g=group_id: store.vector(c, g))
            self._inflight[key] = {
                "received": 0, "applied": 0, "duplicates": 0, "started": time.monotonic(),
            }
            self.events.emit(ev.SYNC_STARTED, group_id=group_id, device_id=device_id)
            try:
                await self._connections.send(
                    device_id,
                    {"type": "sync_req", "group_id": group_id, "heads": state.heads,
                     "vector": vector},
                )
            except PeerNotConnectedError:
                self._fail_sync(device_id, group_id, "disconnected")

    def _fail_sync(self, device_id: str, group_id: str, reason: str) -> None:
        if self._inflight.pop((device_id, group_id), None) is not None:
            self.events.emit(ev.SYNC_FAILED, group_id=group_id, device_id=device_id, reason=reason)

    async def _sync_loop(self) -> None:
        while True:
            await asyncio.sleep(self.config.sync_interval)
            now = time.monotonic()
            for (device_id, group_id), entry in list(self._inflight.items()):
                if now - entry["started"] > SYNC_ROUND_TIMEOUT:
                    self._fail_sync(device_id, group_id, "timeout")
            groups = self._groups
            if groups is None:
                continue
            for group_id in list(groups.states):
                try:
                    ops = await self._tx(
                        lambda c, e, g=group_id, gs=groups: gs.maintain_keys(c, g, e)
                    )
                    await self._after_local_ops(group_id, ops)
                except P2PSyncError as exc:
                    log.warning("key maintenance for %s failed: %s", group_id, exc)
            for peer in self.peers():
                try:
                    await self._sync_with(peer.device_id)
                except P2PSyncError as exc:
                    log.info("periodic sync with %s failed: %s", peer.device_id[:12], exc)

    async def _handle_sync_req(self, peer: PeerInfo, msg: dict[str, Any]) -> None:
        groups, store = self._require_secure()
        group_id = _field_hex32(msg, "group_id")
        vector = _field_vector(msg)
        heads = _field_list(msg, "heads")
        state = groups.states.get(group_id)
        if state is None or not state.is_member(self.device_id) or not state.was_member(
            peer.device_id
        ):
            await self._connections.send(
                peer.device_id,
                {"type": "changes", "group_id": group_id, "changes": [], "sync": True,
                 "final": True, "denied": True},
            )
            return
        if sorted(h for h in heads if isinstance(h, str)) != state.heads:
            wires = await self._tx(lambda c, e: groups.wire_ops(c, group_id, set()))
            await self._send_batched(peer.device_id, "group_ops", group_id, "ops", wires)
        if not state.can_read(peer.device_id):
            await self._connections.send(
                peer.device_id,
                {"type": "changes", "group_id": group_id, "changes": [], "sync": True,
                 "final": True, "denied": True},
            )
            return
        wires = await self._tx(lambda c, e: store.changes_after(c, group_id, vector))
        await self._send_batched(
            peer.device_id, "changes", group_id, "changes", wires, sync=True, final=True
        )

    async def _handle_changes(self, peer: PeerInfo, msg: dict[str, Any]) -> None:
        groups, store = self._require_secure()
        group_id = _field_hex32(msg, "group_id")
        wires = _field_list(msg, "changes")
        is_sync = _field_bool(msg, "sync")
        final = _field_bool(msg, "final")
        denied = _field_bool(msg, "denied")
        key = (peer.device_id, group_id)
        state = groups.states.get(group_id)
        if state is None or not state.is_member(self.device_id) or not state.was_member(
            peer.device_id
        ):
            if is_sync:
                self._fail_sync(peer.device_id, group_id, "not_a_member")
            return
        if denied:
            self._fail_sync(peer.device_id, group_id, "denied")
            # The peer may not know yet that we are members: show it the log.
            wires = await self._tx(lambda c, e: groups.wire_ops(c, group_id, set()))
            await self._send_batched(peer.device_id, "group_ops", group_id, "ops", wires)
            return

        def ingest(conn: Connection, events: Events) -> tuple[Any, dict[str, int]]:
            current = groups.states[group_id]
            result = store.ingest(conn, current, wires)
            events.extend(result.events)
            return result, store.vector(conn, group_id)

        try:
            result, vector = await self._tx(ingest)
        except Exception as exc:
            # Nothing was committed (e.g. an adapter or PostgreSQL failed); the
            # changes are fetched again by the next synchronization round.
            log.warning("applying changes from %s failed: %s", peer.device_id[:12], exc)
            if is_sync:
                self._fail_sync(peer.device_id, group_id, f"apply_failed: {exc}"[:300])
            else:
                self.events.emit(
                    ev.SYNC_FAILED, group_id=group_id, device_id=peer.device_id,
                    reason=f"apply_failed: {exc}"[:300],
                )
            return
        if result.stored_wires:
            await self._push(group_id, result.stored_wires, exclude=peer.device_id)
        if is_sync:
            entry = self._inflight.get(key)
            if entry is not None:
                entry["received"] += len(wires)
                entry["applied"] += result.stored
                entry["duplicates"] += result.duplicates
                self.events.emit(
                    ev.SYNC_PROGRESS,
                    group_id=group_id,
                    device_id=peer.device_id,
                    received=entry["received"],
                    applied=entry["applied"],
                    duplicates=entry["duplicates"],
                    rejected=result.rejected,
                )
            if final:
                await self._send_ack(peer.device_id, group_id, vector)
                entry = self._inflight.pop(key, None)
                if entry is not None:
                    self.events.emit(
                        ev.SYNC_COMPLETED,
                        group_id=group_id,
                        device_id=peer.device_id,
                        received=entry["received"],
                        applied=entry["applied"],
                        duplicates=entry["duplicates"],
                    )
            return
        await self._send_ack(peer.device_id, group_id, vector)
        gap = any(
            w["change"]["seq"] > vector.get(w["change"]["author"], 0)
            for w in result.stored_wires
        )
        if result.unknown_authors or gap:
            self._spawn(self._sync_with(peer.device_id, [group_id]), "up2p-catch-up")

    async def _send_ack(self, device_id: str, group_id: str, vector: dict[str, int]) -> None:
        try:
            await self._connections.send(
                device_id, {"type": "sync_ack", "group_id": group_id, "vector": vector}
            )
        except PeerNotConnectedError:
            pass

    async def _handle_sync_ack(self, peer: PeerInfo, msg: dict[str, Any]) -> None:
        groups, _ = self._require_secure()
        group_id = _field_hex32(msg, "group_id")
        vector = _field_vector(msg)
        state = groups.states.get(group_id)
        if state is None or not state.was_member(peer.device_id):
            return

        def save(conn: Connection, events: Events) -> None:
            values = dict(vector=vector, updated_at=utcnow())
            conn.execute(
                pg_insert(t.checkpoints)
                .values(group_id=group_id, device_id=peer.device_id, **values)
                .on_conflict_do_update(index_elements=["group_id", "device_id"], set_=values)
            )

        await self._tx(save)

    async def _handle_group_ops(self, peer: PeerInfo, msg: dict[str, Any]) -> None:
        groups, _ = self._require_secure()
        group_id = _field_hex32(msg, "group_id")
        wires = _field_list(msg, "ops")
        state = groups.states.get(group_id)
        if state is None and group_id in self._join_waiters:
            # The group we are joining; its log may arrive in several batches.
            buffer = self._join_buffer.setdefault(group_id, [])
            if len(buffer) + len(wires) > MAX_ITEMS_PER_MESSAGE:
                self._join_buffer.pop(group_id, None)
                return
            buffer.extend(wires)
            wires = list(buffer)
        # For a known group, ops are accepted from any authenticated peer:
        # each one is verified against the signed log, so the sender's
        # identity does not matter (this lets members introduce each other).
        result = await self._tx(
            lambda c, e: groups.ingest_ops(c, group_id, wires, peer.device_id, e)
        )
        if result.joined:
            self._join_buffer.pop(group_id, None)
            waiter = self._join_waiters.pop(group_id, None)
            if waiter is not None and not waiter.done():
                waiter.set_result(group_id)
        if not result.new_ops:
            return
        await self._gossip_ops(
            group_id, [op.to_wire() for op in result.new_ops], exclude=peer.device_id
        )
        repaired = await self._tx(lambda c, e: groups.maintain_keys(c, group_id, e))
        await self._after_local_ops(group_id, repaired)
        if result.joined:
            self._spawn(self._sync_with(peer.device_id, [group_id]), "up2p-sync-joined")

    # ------------------------------------------------------------------ invitation protocol

    async def _handle_invite_offer(self, peer: PeerInfo, msg: dict[str, Any]) -> None:
        groups, _ = self._require_secure()
        if not self.is_trusted(peer.device_id):
            await self._not_trusted(peer, msg)
            return
        invite_id = _field_hex32(msg, "invite_id")
        group_id = _field_hex32(msg, "group_id")
        group_name = _field_str(msg, "group_name", 200)
        role = _field_str(msg, "role", 32)
        secret = _field_str(msg, "secret", 128)
        expires_raw = msg.get("expires_at")
        if not isinstance(expires_raw, int) or isinstance(expires_raw, bool):
            raise MalformedMessageError("invalid expires_at")
        try:
            expires = datetime.datetime.fromtimestamp(expires_raw, datetime.timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise MalformedMessageError("invalid expires_at") from exc
        state = groups.states.get(group_id)
        if state is not None and state.is_member(self.device_id):
            return
        invite, created = await self._tx(
            lambda c, e: groups.record_incoming_invite(
                c,
                invite_id=invite_id,
                group_id=group_id,
                group_name=group_name,
                role=role,
                inviter=peer.device_id,
                secret=secret,
                expires_at=expires,
            )
        )
        if created:
            self.events.emit(
                ev.GROUP_INVITATION_RECEIVED,
                invite_id=invite_id,
                group_id=group_id,
                group_name=group_name,
                role=role,
                inviter_device_id=peer.device_id,
                inviter_device_name=peer.device_name,
                expires_at=invite.expires_at.isoformat(),
            )

    async def _handle_invite_accept(self, peer: PeerInfo, msg: dict[str, Any]) -> None:
        groups, _ = self._require_secure()
        invite_id = _field_hex32(msg, "invite_id")
        secret = _field_str(msg, "secret", 128)
        member = msg.get("member")
        if not isinstance(member, dict):
            raise MalformedMessageError("invite_accept requires a member object")
        assert peer.public_key is not None
        try:
            group_id, ops = await self._tx(
                lambda c, e: groups.admit(
                    c,
                    invite_id=invite_id,
                    secret=secret,
                    peer_id=peer.device_id,
                    peer_public_key=peer.public_key,  # type: ignore[arg-type]
                    member=member,
                    events=e,
                )
            )
        except (InviteError, PermissionDeniedError, NotFoundError) as exc:
            await self._connections.send(
                peer.device_id,
                {"type": "invite_result", "invite_id": invite_id, "ok": False,
                 "error": str(exc)[:200]},
            )
            return
        await self._connections.send(
            peer.device_id,
            {"type": "invite_result", "invite_id": invite_id, "ok": True, "group_id": group_id},
        )
        wires = await self._tx(lambda c, e: groups.wire_ops(c, group_id, set()))
        await self._send_batched(peer.device_id, "group_ops", group_id, "ops", wires)
        self.events.emit(
            ev.INVITATION_RESPONSE,
            invite_id=invite_id,
            group_id=group_id,
            device_id=peer.device_id,
            device_name=peer.device_name,
            accepted=True,
        )
        await self._gossip_ops(group_id, [op.to_wire() for op in ops], exclude=peer.device_id)

    async def _handle_invite_result(self, peer: PeerInfo, msg: dict[str, Any]) -> None:
        invite_id = _field_hex32(msg, "invite_id")
        ok = _field_bool(msg, "ok")
        error = msg.get("error") if isinstance(msg.get("error"), str) else None
        future = self._invite_results.get(invite_id)
        if future is not None and not future.done():
            future.set_result({"ok": ok, "error": error})

    async def _handle_invite_reject(self, peer: PeerInfo, msg: dict[str, Any]) -> None:
        groups, _ = self._require_secure()
        invite_id = _field_hex32(msg, "invite_id")

        def reject(conn: Connection, events: Events) -> Any:
            row = conn.execute(
                select(t.invites).where(
                    t.invites.c.invite_id == invite_id,
                    t.invites.c.direction == "outgoing",
                    t.invites.c.invitee_device_id == peer.device_id,
                    t.invites.c.status == "pending",
                )
            ).first()
            if row is not None:
                groups.set_invite_status(conn, invite_id, "rejected")
            return row

        row = await self._tx(reject)
        if row is not None:
            self.events.emit(
                ev.INVITATION_RESPONSE,
                invite_id=invite_id,
                group_id=row.group_id,
                device_id=peer.device_id,
                device_name=peer.device_name,
                accepted=False,
            )

    async def _handle_invite_revoked(self, peer: PeerInfo, msg: dict[str, Any]) -> None:
        self._require_secure()
        invite_id = _field_hex32(msg, "invite_id")

        def revoke(conn: Connection, events: Events) -> None:
            conn.execute(
                update(t.invites)
                .where(
                    t.invites.c.invite_id == invite_id,
                    t.invites.c.direction == "incoming",
                    t.invites.c.inviter_device_id == peer.device_id,
                    t.invites.c.status == "pending",
                )
                .values(status="revoked")
            )

        await self._tx(revoke)

    # ------------------------------------------------------------------ internals

    def _require_running(self) -> None:
        if not self._running:
            raise NodeStateError("node is not running; call start() first")

    def _advertise_addresses(self, listen_host: str) -> list[str]:
        if self.config.advertise_addresses:
            return list(self.config.advertise_addresses)
        if listen_host in ("0.0.0.0", ""):
            return local_ipv4_addresses() or ["127.0.0.1"]
        return [listen_host]

    async def _not_trusted(self, peer: PeerInfo, msg: dict[str, Any]) -> None:
        await self._connections.send(
            peer.device_id,
            {
                "type": "error",
                "code": "not_trusted",
                "message": f"{msg['type']!r} requires a paired device",
                "ref": msg.get("id") if isinstance(msg.get("id"), str) else None,
            },
        )

    async def _handle_pairing(self, peer: PeerInfo, msg: dict[str, Any]) -> None:
        if self._pairing is None:
            return
        if self._is_blocked(peer.device_id):
            return
        await self._pairing.handle(peer, msg)

    async def _handle_direct_message(self, peer: PeerInfo, msg: dict[str, Any]) -> None:
        if self.secure and not self._may_talk(peer.device_id):
            await self._not_trusted(peer, msg)
            return
        payload = msg.get("payload")
        if not isinstance(payload, dict):
            raise ProtocolError("message.payload must be an object", "malformed_message")
        message_id = msg.get("id")
        self.events.emit(
            ev.MESSAGE_RECEIVED,
            device_id=peer.device_id,
            device_name=peer.device_name,
            message_id=message_id if isinstance(message_id, str) else None,
            payload=payload,
        )

    async def _on_peer_connected(self, peer: PeerInfo) -> None:
        self.events.emit(
            ev.PEER_CONNECTED,
            device_id=peer.device_id,
            device_name=peer.device_name,
            address=peer.remote_host,
            outbound=peer.outbound,
            secure=peer.secure,
            trusted=self.is_trusted(peer.device_id) if self.secure else False,
            fingerprint=format_fingerprint(peer.device_id) if self.secure else None,
        )
        if self.secure and self._db is not None:
            self._spawn(self._after_contact(peer), "up2p-peer-connected")

    async def _after_contact(self, peer: PeerInfo) -> None:
        """Bring a trusted or fellow-member peer up to date after (re)connecting."""
        if self.is_trusted(peer.device_id):
            if peer.listen_port is not None:

                def seen(conn: Connection, events: Events) -> None:
                    conn.execute(
                        update(t.trusted_devices)
                        .where(t.trusted_devices.c.device_id == peer.device_id)
                        .values(
                            last_seen_at=utcnow(),
                            last_address=peer.remote_host,
                            last_port=peer.listen_port,
                        )
                    )

                await self._tx(seen)
            await self._deliver_invites(peer.device_id)
        if self._connections.is_connected(peer.device_id):
            await self._sync_with(peer.device_id)

    async def _on_peer_disconnected(self, peer: PeerInfo) -> None:
        if self._pairing is not None:
            self._pairing.peer_disconnected(peer.device_id)
        for device_id, group_id in list(self._inflight):
            if device_id == peer.device_id:
                self._fail_sync(device_id, group_id, "disconnected")
        self.events.emit(
            ev.PEER_DISCONNECTED, device_id=peer.device_id, device_name=peer.device_name
        )

    async def _on_discovered(self, peer: DiscoveredPeer) -> None:
        self.events.emit(
            ev.PEER_DISCOVERED,
            device_id=peer.device_id,
            device_name=peer.device_name,
            addresses=list(peer.addresses),
            port=peer.port,
            trusted=self.is_trusted(peer.device_id) if self.secure else False,
        )
        if not self.config.auto_connect_discovered or self._is_blocked(peer.device_id):
            return
        task = self._discovery_tasks.get(peer.device_id)
        if task is None or task.done():
            self._discovery_tasks[peer.device_id] = asyncio.create_task(
                self._discovered_peer_loop(peer.device_id),
                name=f"up2p-discovered-{peer.device_id[:8]}",
            )

    async def _on_lost(self, device_id: str) -> None:
        task = self._discovery_tasks.pop(device_id, None)
        if task is not None:
            task.cancel()
        self.events.emit(ev.PEER_LOST, device_id=device_id)

    async def _discovered_peer_loop(self, device_id: str) -> None:
        """Keep a connection to a discovered peer while it stays advertised.

        Only the side with the smaller device ID dials immediately; the other
        waits ``discovery_connect_delay`` first, which avoids most simultaneous
        dials (any remaining duplicates are resolved by the connection layer).
        """
        delay = self.config.reconnect_initial_delay
        if self.device_id > device_id:
            await asyncio.sleep(self.config.discovery_connect_delay)
        while self._running and self._discovery is not None:
            if self._connections.is_connected(device_id):
                await self._connections.wait_disconnected(device_id)
                delay = self.config.reconnect_initial_delay
                continue
            peer = self._discovery.peers.get(device_id)
            if peer is None:
                return
            for address in peer.addresses:
                try:
                    info = await self._connections.connect(
                        address, peer.port, expected_device_id=device_id if self.secure else None
                    )
                except (OSError, ProtocolError, asyncio.IncompleteReadError) as exc:
                    log.debug("dial %s at %s:%d failed: %s", device_id, address, peer.port, exc)
                    continue
                if info.device_id != device_id:
                    log.warning(
                        "address advertised for %s answered as %s", device_id, info.device_id
                    )
                break
            if not self._connections.is_connected(device_id):
                await asyncio.sleep(delay)
                delay = min(delay * 2, self.config.reconnect_max_delay)


class SyncNode:
    """Thread-backed synchronous facade over :class:`AsyncSyncNode`.

    The node's asyncio loop runs on a private daemon thread. Blocking methods
    wait (up to ``timeout``) for the result; never call them from the GUI main
    thread for operations that may take long - use :meth:`submit` (returns a
    ``concurrent.futures.Future``) or :meth:`start_in_background` instead.

    Event handlers registered with :meth:`on` run on the node thread unless a
    ``callback_dispatcher`` is given, in which case each handler invocation is
    passed to it as a zero-argument callable. For example with tkinter:
    ``SyncNode(..., callback_dispatcher=lambda fn: root.after(0, fn))``.
    """

    def __init__(
        self,
        app_id: str,
        user_id: str,
        device_name: str,
        *,
        callback_dispatcher: Callable[[Callable[[], None]], Any] | None = None,
        config: NodeConfig | None = None,
        **config_overrides: Any,
    ) -> None:
        self.aio = AsyncSyncNode(app_id, user_id, device_name, config=config, **config_overrides)
        self._dispatcher = callback_dispatcher
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------ properties

    @property
    def app_id(self) -> str:
        return self.aio.app_id

    @property
    def user_id(self) -> str:
        return self.aio.user_id

    @property
    def device_id(self) -> str:
        return self.aio.device_id

    @property
    def fingerprint(self) -> str:
        return self.aio.fingerprint

    @property
    def schema(self) -> str:
        return self.aio.schema

    @property
    def config(self) -> NodeConfig:
        return self.aio.config

    @property
    def is_running(self) -> bool:
        return self.aio.is_running

    @property
    def listen_address(self) -> tuple[str, int] | None:
        return self.aio.listen_address

    # ------------------------------------------------------------------ lifecycle

    def start_in_background(self) -> concurrent.futures.Future[None]:
        """Start the node without blocking; returns a Future for completion."""
        with self._lock:
            if self._thread is not None:
                raise NodeStateError("node already started")
            loop = asyncio.new_event_loop()
            thread = threading.Thread(
                target=self._run_loop, args=(loop,), name=f"up2p-{self.app_id}", daemon=True
            )
            self._loop, self._thread = loop, thread
            thread.start()
        future = asyncio.run_coroutine_threadsafe(self.aio.start(), loop)
        future.add_done_callback(self._after_start)
        return future

    def start(self, timeout: float = 60.0) -> None:
        self._check_not_loop_thread()
        self.start_in_background().result(timeout)

    def stop(self, timeout: float = 30.0) -> None:
        """Stop the node and its background thread. Idempotent."""
        self._check_not_loop_thread()
        with self._lock:
            loop, thread = self._loop, self._thread
            self._loop = self._thread = None
        if loop is None or thread is None:
            return
        try:
            if not loop.is_closed():
                asyncio.run_coroutine_threadsafe(self.aio.stop(), loop).result(timeout)
        finally:
            if not loop.is_closed():
                loop.call_soon_threadsafe(loop.stop)
            thread.join(timeout)

    def __enter__(self) -> SyncNode:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # ------------------------------------------------------------------ operations

    def submit(self, coro: Coroutine[Any, Any, T]) -> concurrent.futures.Future[T]:
        """Run a coroutine (typically from ``node.aio``) on the node thread."""
        loop = self._loop
        if loop is None:
            coro.close()
            raise NodeStateError("node is not running; call start() first")
        return asyncio.run_coroutine_threadsafe(coro, loop)

    def on(self, name: str, handler: Callable[[ev.Event], Any]) -> Callable[[], None]:
        """Subscribe to an event. Safe to call before or after start()."""
        dispatcher = self._dispatcher
        if dispatcher is None:
            return self.aio.events.on(name, handler)

        def marshalled(event: ev.Event) -> None:
            dispatcher(functools.partial(handler, event))

        return self.aio.events.on(name, marshalled)

    # connections and messages
    def connect(self, host: str, port: int, timeout: float = 30.0) -> PeerInfo:
        return self._call(self.aio.connect(host, port), timeout)

    def add_peer_address(self, host: str, port: int) -> None:
        self._call(self._as_coro(self.aio.add_peer_address, host, port), 10.0)

    def remove_peer_address(self, host: str, port: int) -> None:
        self._call(self._as_coro(self.aio.remove_peer_address, host, port), 10.0)

    def disconnect(self, device_id: str, timeout: float = 10.0) -> None:
        self._call(self.aio.disconnect(device_id), timeout)

    def peers(self) -> list[PeerInfo]:
        return self._call(self._as_coro(self.aio.peers), 10.0)

    def discovered_peers(self) -> list[DiscoveredPeer]:
        return self._call(self._as_coro(self.aio.discovered_peers), 10.0)

    def send_message(self, device_id: str, payload: dict[str, Any], timeout: float = 30.0) -> str:
        return self._call(self.aio.send_message(device_id, payload), timeout)

    def broadcast_message(self, payload: dict[str, Any], timeout: float = 30.0) -> int:
        return self._call(self.aio.broadcast_message(payload), timeout)

    # pairing and trust
    def request_pairing(self, device_id: str, timeout: float = 330.0) -> PairingRequest:
        return self._call(self.aio.request_pairing(device_id), timeout)

    def approve_pairing(self, device_id: str, timeout: float = 30.0) -> None:
        self._call(self.aio.approve_pairing(device_id), timeout)

    def reject_pairing(self, device_id: str, reason: str = "rejected", timeout: float = 30.0) -> None:
        self._call(self.aio.reject_pairing(device_id, reason), timeout)

    def wait_for_pairing(self, device_id: str, timeout: float = 60.0) -> bool:
        return self._call(self.aio.wait_for_pairing(device_id, timeout), timeout + 5.0)

    def pairing_requests(self) -> list[PairingRequest]:
        return self._call(self._as_coro(self.aio.pairing_requests), 10.0)

    def is_trusted(self, device_id: str) -> bool:
        return self.aio.is_trusted(device_id)

    def list_trusted_devices(self, include_revoked: bool = True) -> list[TrustedDevice]:
        return self._call(self.aio.list_trusted_devices(include_revoked), 30.0)

    def revoke_device(self, device_id: str, *, remove_from_groups: bool = True) -> None:
        self._call(self.aio.revoke_device(device_id, remove_from_groups=remove_from_groups), 60.0)

    def forget_device(self, device_id: str) -> None:
        self._call(self.aio.forget_device(device_id), 30.0)

    # groups
    def create_group(
        self, name: str, *, roles: dict[str, list[str]] | None = None,
        owner_role: str | None = None,
    ) -> Group:
        return self._call(self.aio.create_group(name, roles=roles, owner_role=owner_role), 30.0)

    def list_groups(self, include_inactive: bool = False) -> list[Group]:
        return self._call(self._as_coro(self.aio.list_groups, include_inactive), 10.0)

    def get_group(self, group_id: str) -> Group:
        return self._call(self._as_coro(self.aio.get_group, group_id), 10.0)

    def list_members(self, group_id: str) -> list[Member]:
        return self._call(self._as_coro(self.aio.list_members, group_id), 10.0)

    def has_permission(self, group_id: str, permission: str, device_id: str | None = None) -> bool:
        return self._call(
            self._as_coro(self.aio.has_permission, group_id, permission, device_id), 10.0
        )

    def rename_group(self, group_id: str, name: str) -> Group:
        return self._call(self.aio.rename_group(group_id, name), 30.0)

    def remove_member(self, group_id: str, device_id: str) -> None:
        self._call(self.aio.remove_member(group_id, device_id), 30.0)

    revoke_group_access = remove_member

    def leave_group(self, group_id: str) -> None:
        self._call(self.aio.leave_group(group_id), 30.0)

    def change_member_role(self, group_id: str, device_id: str, role: str) -> None:
        self._call(self.aio.change_member_role(group_id, device_id, role), 30.0)

    def create_invite(
        self, group_id: str, role: str, *, device_id: str | None = None,
        ttl: float | None = None, max_uses: int = 1,
    ) -> Invite:
        return self._call(
            self.aio.create_invite(group_id, role, device_id=device_id, ttl=ttl, max_uses=max_uses),
            30.0,
        )

    def list_invites(self, group_id: str | None = None, direction: str | None = None) -> list[Invite]:
        return self._call(self.aio.list_invites(group_id, direction), 30.0)

    def accept_invite(self, invite: str, timeout: float = JOIN_TIMEOUT) -> Group:
        return self._call(self.aio.accept_invite(invite, timeout), timeout + 10.0)

    join_group = accept_invite

    def reject_invite(self, invite_id: str) -> None:
        self._call(self.aio.reject_invite(invite_id), 30.0)

    def revoke_invite(self, invite_id: str) -> None:
        self._call(self.aio.revoke_invite(invite_id), 30.0)

    # records
    def publish(
        self, group_id: str, collection: str, record_id: str, data: dict[str, Any],
        timeout: float = 30.0,
    ) -> Record:
        return self._call(self.aio.publish(group_id, collection, record_id, data), timeout)

    def delete(self, group_id: str, collection: str, record_id: str, timeout: float = 30.0) -> Record:
        return self._call(self.aio.delete(group_id, collection, record_id), timeout)

    def get_record(
        self, group_id: str, collection: str, record_id: str, *, include_deleted: bool = False
    ) -> Record | None:
        return self._call(
            self.aio.get_record(group_id, collection, record_id, include_deleted=include_deleted),
            30.0,
        )

    def list_records(
        self, group_id: str, collection: str | None = None, *, include_deleted: bool = False
    ) -> list[Record]:
        return self._call(
            self.aio.list_records(group_id, collection, include_deleted=include_deleted), 30.0
        )

    def register_conflict_resolver(self, collection: str, resolver: ConflictResolver) -> None:
        self.aio.register_conflict_resolver(collection, resolver)

    def register_adapter(self, collection: str, adapter: Any) -> None:
        self.aio.register_adapter(collection, adapter)

    def list_conflicts(self, group_id: str | None = None, status: str | None = "open") -> list[Conflict]:
        return self._call(self.aio.list_conflicts(group_id, status), 30.0)

    def resolve_conflict(self, conflict_id: str, data: Any) -> Record:
        return self._call(self.aio.resolve_conflict(conflict_id, data), 30.0)

    def flush_outbox(self, timeout: float = 60.0) -> int:
        return self._call(self.aio.flush_outbox(), timeout)

    def notify_outbox(self) -> None:
        loop = self._loop
        if loop is not None:
            loop.call_soon_threadsafe(self.aio.notify_outbox)

    def get_sync_status(self, group_id: str) -> SyncStatus:
        return self._call(self.aio.get_sync_status(group_id), 30.0)

    def sync_now(self, group_id: str | None = None) -> None:
        self._call(self.aio.sync_now(group_id), 30.0)

    # ------------------------------------------------------------------ internals

    @staticmethod
    async def _as_coro(fn: Callable[..., T], *args: Any) -> T:
        return fn(*args)

    def _call(self, coro: Coroutine[Any, Any, T], timeout: float) -> T:
        try:
            self._check_not_loop_thread()
        except NodeStateError:
            coro.close()
            raise
        return self.submit(coro).result(timeout)

    def _check_not_loop_thread(self) -> None:
        if self._thread is not None and threading.current_thread() is self._thread:
            raise NodeStateError(
                "blocking SyncNode methods cannot be called from the node thread "
                "(e.g. inside an event handler); use node.submit(node.aio.<method>(...))"
            )

    def _after_start(self, future: concurrent.futures.Future[None]) -> None:
        if future.cancelled() or future.exception() is not None:
            with self._lock:
                loop, self._loop, self._thread = self._loop, None, None
            if loop is not None and not loop.is_closed():
                loop.call_soon_threadsafe(loop.stop)

    @staticmethod
    def _run_loop(loop: asyncio.AbstractEventLoop) -> None:
        asyncio.set_event_loop(loop)
        try:
            loop.run_forever()
        finally:
            try:
                pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                loop.run_until_complete(loop.shutdown_asyncgens())
            finally:
                loop.close()
