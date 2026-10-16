"""Symmetric peer connection manager.

Every node both listens for and initiates connections; there is no designated
server. After TCP connect, the initiator sends ``hello`` and the responder
answers ``hello_ack`` or ``error``. Only peers with the same ``app_id`` and a
common protocol version are accepted.

In secure mode (protocol version 2, the default) the TCP connection is first
upgraded to TLS 1.3. The responder proves possession of its device key through
the TLS handshake (its certificate carries the Ed25519 identity key); the
initiator proves possession of its key with an ``auth`` signature over a
transcript bound to the responder's certificate and fresh nonces from both
sides. Device IDs are the SHA-256 of the public key, so they cannot be claimed
without the private key.

At most one live connection is kept per remote device. If two connections to
the same device exist (typically because both sides dialed at once), both
sides deterministically keep the connection initiated by the lexicographically
smaller device ID and close the other with reason ``duplicate_connection``.

Delivery on a single connection is in-order and at-most-once. Messages
in flight when a connection drops are lost; the synchronization layer is
responsible for recovering them (pull-based catch-up after reconnect).
"""

from __future__ import annotations

import asyncio
import collections
import hashlib
import logging
import os
import random
import re
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from ..config import validate_app_id
from ..crypto import (
    DeviceIdentity,
    b64d,
    b64e,
    canonical_json,
    device_id_for,
    public_key_from_cert,
    verify_signature,
)
from ..errors import (
    ConfigurationError,
    HandshakeError,
    IdentityError,
    MalformedMessageError,
    NodeStateError,
    PeerNotConnectedError,
    ProtocolError,
)
from .transport import (
    DEFAULT_MAX_FRAME_SIZE,
    INSECURE_VERSIONS,
    PROTOCOL_NAME,
    SUPPORTED_VERSIONS,
    FramedStream,
)

log = logging.getLogger(__name__)

DEVICE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
MAX_DEVICE_NAME_LENGTH = 256
MAX_ADVERTISED_VERSIONS = 16

NONCE_SIZE = 32

#: Message types handled by the connection layer itself.
RESERVED_TYPES = frozenset(
    {"hello", "hello_ack", "auth", "auth_ok", "ping", "pong", "close", "error"}
)


def make_tls_contexts(identity: DeviceIdentity) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    """Server and client TLS 1.3 contexts presenting the device certificate.

    Certificate chains are not validated (there is no CA); instead the peer's
    certificate key is pinned to its device ID by the handshake code.
    """
    password = identity.passphrase
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = ssl.TLSVersion.TLSv1_3
    server.load_cert_chain(str(identity.cert_path), str(identity.key_path), password=password)
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.minimum_version = ssl.TLSVersion.TLSv1_3
    client.check_hostname = False
    client.verify_mode = ssl.CERT_NONE  # pinned by device ID after the handshake
    client.load_cert_chain(str(identity.cert_path), str(identity.key_path), password=password)
    return server, client


@dataclass
class TransportSecurity:
    """Everything the connection layer needs for authenticated TLS connections."""

    identity: DeviceIdentity
    #: Returns True for devices whose connections must be refused (revoked).
    is_blocked: Callable[[str], bool] = lambda device_id: False

    def __post_init__(self) -> None:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        self.server_context, self.client_context = make_tls_contexts(self.identity)
        cert = x509.load_pem_x509_certificate(self.identity.cert_path.read_bytes())
        self.cert_der = cert.public_bytes(serialization.Encoding.DER)


class _RateLimiter:
    """Sliding-window limit on new inbound connections per remote address."""

    def __init__(self, limit: int, window: float) -> None:
        self.limit = limit
        self.window = window
        self._events: dict[str, collections.deque[float]] = {}

    def allow(self, key: str, now: float) -> bool:
        events = self._events.setdefault(key, collections.deque())
        while events and now - events[0] > self.window:
            events.popleft()
        if len(events) >= self.limit:
            return False
        events.append(now)
        if len(self._events) > 4096:  # bound memory under address churn
            for stale in [k for k, v in self._events.items() if not v]:
                del self._events[stale]
        return True


def _auth_transcript(
    app_id: str, initiator: str, responder: str, cert_der: bytes, ni: bytes, nr: bytes
) -> bytes:
    return canonical_json(
        {
            "ctx": "up2p-auth-v2",
            "app_id": app_id,
            "initiator": initiator,
            "responder": responder,
            "responder_cert": hashlib.sha256(cert_der).hexdigest(),
            "initiator_nonce": b64e(ni),
            "responder_nonce": b64e(nr),
        }
    )


@dataclass(frozen=True)
class PeerInfo:
    """A connected remote device.

    In secure mode ``device_id`` and ``public_key`` are cryptographically
    verified; in insecure development mode they are self-asserted.
    """

    device_id: str
    device_name: str
    app_id: str
    remote_host: str
    remote_port: int
    #: The TCP port the peer listens on (from its handshake), if any.
    listen_port: int | None
    #: True if this node dialed the connection.
    outbound: bool
    #: Raw Ed25519 public key (secure mode only).
    public_key: bytes | None = None
    #: True if the connection is TLS-encrypted and the identity verified.
    secure: bool = False


MessageHandler = Callable[[PeerInfo, dict[str, Any]], Awaitable[None]]
PeerCallback = Callable[[PeerInfo], Awaitable[None]]


class _Connection:
    def __init__(self, stream: FramedStream, peer: PeerInfo, initiator_id: str) -> None:
        self.stream = stream
        self.peer = peer
        self.initiator_id = initiator_id
        self.last_rx = asyncio.get_running_loop().time()
        self.closed_event = asyncio.Event()

    @property
    def closed(self) -> bool:
        return self.closed_event.is_set()

    async def send(self, message: dict[str, Any]) -> None:
        await self.stream.send(message)

    async def close(self, reason: str | None = None) -> None:
        if self.closed:
            return
        self.closed_event.set()
        if reason and not self.stream.closed:
            try:
                await asyncio.wait_for(self.stream.send({"type": "close", "reason": reason}), 1.0)
            except Exception:  # best effort; the peer may already be gone
                pass
        await self.stream.close()


def _require_str(msg: dict[str, Any], key: str) -> str:
    value = msg.get(key)
    if not isinstance(value, str):
        raise HandshakeError(f"handshake field {key!r} must be a string", "invalid_handshake")
    return value


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _parse_handshake(
    msg: dict[str, Any], *, is_ack: bool, supported: tuple[int, ...], secure: bool
) -> dict[str, Any]:
    if msg.get("protocol") != PROTOCOL_NAME:
        raise HandshakeError("unknown protocol", "unsupported_protocol")
    app_id = _require_str(msg, "app_id")
    device_id = _require_str(msg, "device_id")
    device_name = _require_str(msg, "device_name")
    try:
        validate_app_id(app_id)
    except ConfigurationError as exc:
        raise HandshakeError("invalid app_id", "invalid_handshake") from exc
    if not DEVICE_ID_PATTERN.fullmatch(device_id):
        raise HandshakeError("invalid device_id", "invalid_handshake")
    if not 0 < len(device_name) <= MAX_DEVICE_NAME_LENGTH:
        raise HandshakeError("invalid device_name", "invalid_handshake")
    listen_port = msg.get("listen_port")
    if listen_port is not None and not (_is_int(listen_port) and 1 <= listen_port <= 65535):
        raise HandshakeError("invalid listen_port", "invalid_handshake")
    if is_ack:
        version = msg.get("version")
        if not _is_int(version) or version not in supported:
            raise HandshakeError("peer selected an unsupported version", "unsupported_version")
    else:
        versions = msg.get("versions")
        if (
            not isinstance(versions, list)
            or not 0 < len(versions) <= MAX_ADVERTISED_VERSIONS
            or not all(_is_int(v) for v in versions)
        ):
            raise HandshakeError("invalid versions list", "invalid_handshake")
        common = set(versions) & set(supported)
        if not common:
            raise HandshakeError("no common protocol version", "unsupported_version")
        version = max(common)
    public_key = nonce = None
    if secure:
        try:
            public_key = b64d(_require_str(msg, "public_key"), expected_len=32)
            nonce = b64d(_require_str(msg, "nonce"), expected_len=NONCE_SIZE)
        except ValueError as exc:
            raise HandshakeError(f"invalid key material: {exc}", "invalid_handshake") from exc
        if device_id_for(public_key) != device_id:
            raise HandshakeError("device_id does not match public key", "identity_mismatch")
    return {
        "app_id": app_id,
        "device_id": device_id,
        "device_name": device_name,
        "listen_port": listen_port,
        "version": version,
        "public_key": public_key,
        "nonce": nonce,
    }


class ConnectionManager:
    """Owns the listening socket and all live peer connections of one node."""

    def __init__(
        self,
        *,
        app_id: str,
        device_id: str,
        device_name: str,
        listen_host: str = "0.0.0.0",
        listen_port: int = 0,
        max_frame_size: int = DEFAULT_MAX_FRAME_SIZE,
        connect_timeout: float = 10.0,
        handshake_timeout: float = 10.0,
        keepalive_interval: float = 15.0,
        idle_timeout: float = 45.0,
        reconnect_initial_delay: float = 0.5,
        reconnect_max_delay: float = 30.0,
        on_peer_connected: PeerCallback | None = None,
        on_peer_disconnected: PeerCallback | None = None,
        security: TransportSecurity | None = None,
        max_connections: int = 128,
        max_pending_handshakes: int = 32,
        connection_rate_limit: int = 30,
        connection_rate_window: float = 10.0,
    ) -> None:
        if not DEVICE_ID_PATTERN.fullmatch(device_id):
            raise ConfigurationError("invalid device_id")
        if security is not None and security.identity.device_id != device_id:
            raise ConfigurationError("device_id does not match the security identity")
        self._security = security
        self._versions = SUPPORTED_VERSIONS if security is not None else INSECURE_VERSIONS
        self._max_connections = max_connections
        self._max_pending_handshakes = max_pending_handshakes
        self._pending_handshakes = 0
        self._rate_limiter = _RateLimiter(connection_rate_limit, connection_rate_window)
        self.app_id = validate_app_id(app_id)
        self.device_id = device_id
        self.device_name = device_name
        self._listen_host = listen_host
        self._listen_port = listen_port
        self._max_frame_size = max_frame_size
        self._connect_timeout = connect_timeout
        self._handshake_timeout = handshake_timeout
        self._keepalive_interval = keepalive_interval
        self._idle_timeout = idle_timeout
        self._reconnect_initial = reconnect_initial_delay
        self._reconnect_max = reconnect_max_delay
        self._on_peer_connected = on_peer_connected
        self._on_peer_disconnected = on_peer_disconnected
        self._handlers: dict[str, MessageHandler] = {}

        self._server: asyncio.Server | None = None
        self._conns: dict[str, _Connection] = {}
        self._tasks: set[asyncio.Task[Any]] = set()
        self._persistent: dict[tuple[str, int], asyncio.Task[None]] = {}
        self._address_peer: dict[tuple[str, int], str] = {}
        self._running = False
        self.listen_address: tuple[str, int] | None = None

    # ------------------------------------------------------------------ lifecycle

    @property
    def running(self) -> bool:
        return self._running

    @property
    def secure(self) -> bool:
        return self._security is not None

    def register_handler(self, msg_type: str, handler: MessageHandler) -> None:
        """Route incoming messages of ``msg_type`` to ``handler``.

        A handler raising ProtocolError closes the connection with an error
        frame; any other exception is logged and the connection stays open.
        """
        if msg_type in RESERVED_TYPES:
            raise ValueError(f"message type {msg_type!r} is reserved")
        self._handlers[msg_type] = handler

    async def start(self) -> tuple[str, int]:
        if self._running:
            raise NodeStateError("connection manager already running")
        self._server = await asyncio.start_server(
            self._on_incoming, self._listen_host, self._listen_port
        )
        sockname = self._server.sockets[0].getsockname()
        self.listen_address = (str(sockname[0]), int(sockname[1]))
        self._running = True
        log.info("listening on %s:%d", *self.listen_address)
        return self.listen_address

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        assert self._server is not None
        self._server.close()
        for task in self._persistent.values():
            task.cancel()
        await asyncio.gather(
            *(conn.close("shutdown") for conn in list(self._conns.values())),
            return_exceptions=True,
        )
        current = asyncio.current_task()
        pending = [t for t in (*self._tasks, *self._persistent.values()) if t is not current]
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        try:
            await asyncio.wait_for(self._server.wait_closed(), 5.0)
        except TimeoutError:
            log.warning("listening socket did not close within 5s")
        self._server = None
        self._persistent.clear()
        self._address_peer.clear()
        self._conns.clear()
        self.listen_address = None

    # ------------------------------------------------------------------ queries

    def peers(self) -> list[PeerInfo]:
        return [c.peer for c in self._conns.values() if not c.closed]

    def is_connected(self, device_id: str) -> bool:
        conn = self._conns.get(device_id)
        return conn is not None and not conn.closed

    async def wait_disconnected(self, device_id: str) -> None:
        """Return once no connection to ``device_id`` remains."""
        # A superseding connection is installed before the old one is closed,
        # so after a wake-up the map already points at the replacement.
        while self._running:
            conn = self._conns.get(device_id)
            if conn is None or conn.closed:
                return
            await conn.closed_event.wait()

    # ------------------------------------------------------------------ sending

    async def send(self, device_id: str, message: dict[str, Any]) -> None:
        conn = self._conns.get(device_id)
        if conn is None or conn.closed:
            raise PeerNotConnectedError(f"not connected to {device_id}")
        try:
            await conn.send(message)
        except (ConnectionError, OSError) as exc:
            raise PeerNotConnectedError(f"connection to {device_id} failed: {exc}") from exc

    async def disconnect(self, device_id: str) -> None:
        for addr, dev in list(self._address_peer.items()):
            if dev == device_id:
                self.remove_persistent_peer(*addr)
        conn = self._conns.get(device_id)
        if conn is not None:
            await conn.close("disconnect_requested")

    # ------------------------------------------------------------------ outbound

    async def connect(
        self, host: str, port: int, expected_device_id: str | None = None
    ) -> PeerInfo:
        """Dial ``host:port``, perform the handshake and register the connection.

        Raises OSError/TimeoutError for network failures and HandshakeError if
        the peer is incompatible or rejects us. If ``expected_device_id`` is
        given (secure mode), a peer with any other verified identity is
        rejected with code ``identity_mismatch``.
        """
        self._require_running()
        if self._security is not None:
            open_coro = asyncio.open_connection(
                host,
                port,
                ssl=self._security.client_context,
                server_hostname="",
                ssl_handshake_timeout=self._handshake_timeout,
            )
        else:
            open_coro = asyncio.open_connection(host, port)
        try:
            reader, writer = await asyncio.wait_for(open_coro, self._connect_timeout)
        except ssl.SSLError as exc:
            raise HandshakeError(f"TLS handshake failed: {exc}", "tls_failed") from exc
        stream = FramedStream(reader, writer, max_frame_size=self._max_frame_size)
        try:
            fields = await asyncio.wait_for(
                self._handshake_as_initiator(stream), self._handshake_timeout
            )
            if expected_device_id is not None and fields["device_id"] != expected_device_id:
                raise HandshakeError(
                    f"expected device {expected_device_id[:12]}, got {fields['device_id'][:12]}",
                    "identity_mismatch",
                )
        except BaseException:
            await stream.close()
            raise
        remote = stream.remote_address or (host, port)
        peer = PeerInfo(
            device_id=fields["device_id"],
            device_name=fields["device_name"],
            app_id=fields["app_id"],
            remote_host=remote[0],
            remote_port=remote[1],
            listen_port=fields["listen_port"],
            outbound=True,
            public_key=fields["public_key"],
            secure=self._security is not None,
        )
        conn = _Connection(stream, peer, initiator_id=self.device_id)
        winner = await self._register(conn)
        if winner is conn:
            self._spawn(self._serve(conn), f"up2p-conn-{peer.device_id[:8]}")
        self._address_peer[(host, port)] = peer.device_id
        return winner.peer

    def add_persistent_peer(self, host: str, port: int) -> None:
        """Keep a connection to ``host:port`` alive, reconnecting with backoff."""
        self._require_running()
        key = (host, port)
        task = self._persistent.get(key)
        if task is None or task.done():
            self._persistent[key] = asyncio.create_task(
                self._persistent_loop(host, port), name=f"up2p-reconnect-{host}:{port}"
            )

    def remove_persistent_peer(self, host: str, port: int) -> None:
        task = self._persistent.pop((host, port), None)
        if task is not None:
            task.cancel()

    async def _persistent_loop(self, host: str, port: int) -> None:
        delay = self._reconnect_initial
        while self._running:
            device_id = self._address_peer.get((host, port))
            if device_id is not None and self.is_connected(device_id):
                await self.wait_disconnected(device_id)
                delay = self._reconnect_initial
                continue
            try:
                await self.connect(host, port)
                delay = self._reconnect_initial
                continue
            except asyncio.CancelledError:
                raise
            except (OSError, ProtocolError, asyncio.IncompleteReadError) as exc:
                log.debug("reconnect to %s:%d failed: %s", host, port, exc)
            await asyncio.sleep(delay * random.uniform(0.8, 1.2))
            delay = min(delay * 2, self._reconnect_max)

    async def _handshake_as_initiator(self, stream: FramedStream) -> dict[str, Any]:
        my_nonce = os.urandom(NONCE_SIZE)
        await stream.send(self._handshake_message("hello", nonce=my_nonce))
        reply = await self._expect(stream, "hello_ack")
        fields = _parse_handshake(
            reply, is_ack=True, supported=self._versions, secure=self._security is not None
        )
        if fields["app_id"] != self.app_id:
            raise HandshakeError("peer belongs to a different application", "app_mismatch")
        if fields["device_id"] == self.device_id:
            raise HandshakeError("connected to self", "self_connection")
        if self._security is None:
            return fields
        # The responder's key was proven by TLS; it must match what it claims.
        cert_der = self._peer_certificate(stream)
        try:
            cert_key = public_key_from_cert(cert_der)
        except (IdentityError, ValueError) as exc:
            raise HandshakeError(str(exc), "identity_mismatch") from exc
        if cert_key != fields["public_key"]:
            raise HandshakeError("TLS certificate does not match device key", "identity_mismatch")
        if self._security.is_blocked(fields["device_id"]):
            raise HandshakeError("peer device has been revoked", "device_revoked")
        transcript = _auth_transcript(
            self.app_id, self.device_id, fields["device_id"], cert_der, my_nonce, fields["nonce"]
        )
        signature = self._security.identity.sign(transcript)
        await stream.send({"type": "auth", "signature": b64e(signature)})
        await self._expect(stream, "auth_ok")
        return fields

    @staticmethod
    async def _expect(stream: FramedStream, msg_type: str) -> dict[str, Any]:
        reply = await stream.receive()
        if reply["type"] == "error":
            code = reply.get("code") if isinstance(reply.get("code"), str) else "rejected"
            raise HandshakeError(f"peer rejected handshake: {reply.get('message', '')}", code)
        if reply["type"] != msg_type:
            raise HandshakeError(
                f"expected {msg_type}, got {reply['type']!r}", "unexpected_message"
            )
        return reply

    @staticmethod
    def _peer_certificate(stream: FramedStream) -> bytes:
        ssl_object = stream.ssl_object
        der = ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
        if not der:
            raise HandshakeError("peer presented no TLS certificate", "identity_mismatch")
        return bytes(der)

    # ------------------------------------------------------------------ inbound

    async def _on_incoming(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        stream = FramedStream(reader, writer, max_frame_size=self._max_frame_size)
        task = asyncio.current_task()
        if not self._running or task is None:
            await stream.close()
            return
        remote_ip = (stream.remote_address or ("?", 0))[0]
        now = asyncio.get_running_loop().time()
        if (
            len(self._conns) >= self._max_connections
            or self._pending_handshakes >= self._max_pending_handshakes
            or not self._rate_limiter.allow(remote_ip, now)
        ):
            log.warning("refusing connection from %s: rate or connection limit", remote_ip)
            await stream.close()
            return
        self._tasks.add(task)
        self._pending_handshakes += 1
        try:
            try:
                fields = await asyncio.wait_for(
                    self._accept_handshake(reader, writer, stream), self._handshake_timeout
                )
            except TimeoutError:
                log.info("handshake timeout from %s", stream.remote_address)
                await stream.close()
                return
            except ProtocolError as exc:
                log.info("rejected connection from %s: %s", stream.remote_address, exc)
                await self._send_error_and_close(stream, exc)
                return
            except (OSError, asyncio.IncompleteReadError, ssl.SSLError):
                await stream.close()
                return
            finally:
                self._pending_handshakes -= 1
            remote = stream.remote_address or ("?", 0)
            peer = PeerInfo(
                device_id=fields["device_id"],
                device_name=fields["device_name"],
                app_id=fields["app_id"],
                remote_host=remote[0],
                remote_port=remote[1],
                listen_port=fields["listen_port"],
                outbound=False,
                public_key=fields["public_key"],
                secure=self._security is not None,
            )
            conn = _Connection(stream, peer, initiator_id=peer.device_id)
            if await self._register(conn) is conn:
                await self._serve(conn)
        finally:
            self._tasks.discard(task)

    async def _accept_handshake(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, stream: FramedStream
    ) -> dict[str, Any]:
        if self._security is not None:
            await writer.start_tls(self._security.server_context)
        return await self._handshake_as_responder(stream)

    async def _handshake_as_responder(self, stream: FramedStream) -> dict[str, Any]:
        hello = await stream.receive()
        if hello["type"] != "hello":
            raise HandshakeError(f"expected hello, got {hello['type']!r}", "unexpected_message")
        secure = self._security is not None
        fields = _parse_handshake(hello, is_ack=False, supported=self._versions, secure=secure)
        if fields["app_id"] != self.app_id:
            raise HandshakeError("application mismatch", "app_mismatch")
        if fields["device_id"] == self.device_id:
            raise HandshakeError("connection to self", "self_connection")
        if self._security is not None and self._security.is_blocked(fields["device_id"]):
            raise HandshakeError("device has been revoked", "device_revoked")
        my_nonce = os.urandom(NONCE_SIZE)
        await stream.send(
            self._handshake_message("hello_ack", version=fields["version"], nonce=my_nonce)
        )
        if self._security is None:
            return fields
        auth = await stream.receive()
        if auth["type"] != "auth":
            raise HandshakeError(f"expected auth, got {auth['type']!r}", "unexpected_message")
        try:
            signature = b64d(_require_str(auth, "signature"), expected_len=64)
        except ValueError as exc:
            raise HandshakeError("invalid signature encoding", "invalid_handshake") from exc
        transcript = _auth_transcript(
            self.app_id,
            fields["device_id"],
            self.device_id,
            self._security.cert_der,
            fields["nonce"],
            my_nonce,
        )
        if not verify_signature(fields["public_key"], signature, transcript):
            raise HandshakeError("device authentication failed", "authentication_failed")
        await stream.send({"type": "auth_ok"})
        return fields

    # ------------------------------------------------------------------ internals

    def _handshake_message(
        self, msg_type: str, version: int | None = None, nonce: bytes | None = None
    ) -> dict[str, Any]:
        msg: dict[str, Any] = {
            "type": msg_type,
            "protocol": PROTOCOL_NAME,
            "app_id": self.app_id,
            "device_id": self.device_id,
            "device_name": self.device_name,
            "listen_port": self.listen_address[1] if self.listen_address else None,
        }
        if msg_type == "hello":
            msg["versions"] = list(self._versions)
        else:
            msg["version"] = version if version is not None else max(self._versions)
        if self._security is not None:
            assert nonce is not None
            msg["public_key"] = b64e(self._security.identity.public_key)
            msg["nonce"] = b64e(nonce)
        return msg

    def _require_running(self) -> None:
        if not self._running:
            raise NodeStateError("connection manager is not running")

    def _spawn(self, coro: Awaitable[Any], name: str) -> asyncio.Task[Any]:
        task = asyncio.ensure_future(coro)
        task.set_name(name)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    async def _register(self, conn: _Connection) -> _Connection:
        """Install ``conn`` as the connection for its peer, resolving duplicates."""
        if not self._running:
            await conn.close("shutdown")
            return conn
        peer_id = conn.peer.device_id
        existing = self._conns.get(peer_id)
        if existing is None or existing.closed:
            self._conns[peer_id] = conn
            log.info("connected to %s (%s)", conn.peer.device_name, peer_id)
            if self._on_peer_connected is not None:
                await self._on_peer_connected(conn.peer)
            return conn
        preferred = min(self.device_id, peer_id)
        new_preferred = conn.initiator_id == preferred
        old_preferred = existing.initiator_id == preferred
        # Keep the connection dialed by the smaller device ID; if both were
        # dialed by the same side, the newer one wins (the old one may be stale).
        if new_preferred or not old_preferred:
            self._conns[peer_id] = conn
            await existing.close("duplicate_connection")
            return conn
        await conn.close("duplicate_connection")
        return existing

    async def _send_error_and_close(self, stream: FramedStream, exc: ProtocolError) -> None:
        try:
            await asyncio.wait_for(
                stream.send({"type": "error", "code": exc.code, "message": str(exc)}), 1.0
            )
        except Exception:
            pass
        await stream.close()

    async def _serve(self, conn: _Connection) -> None:
        loop = asyncio.get_running_loop()
        keepalive = asyncio.create_task(self._keepalive(conn))
        try:
            while True:
                msg = await conn.stream.receive()
                conn.last_rx = loop.time()
                msg_type = msg["type"]
                if msg_type == "ping":
                    await conn.send({"type": "pong"})
                elif msg_type == "pong":
                    pass
                elif msg_type == "close":
                    log.info("peer %s closed: %s", conn.peer.device_id, msg.get("reason"))
                    break
                elif msg_type == "error":
                    log.warning(
                        "peer %s reported error %s: %s",
                        conn.peer.device_id,
                        msg.get("code"),
                        msg.get("message"),
                    )
                elif msg_type in ("hello", "hello_ack", "auth", "auth_ok"):
                    raise MalformedMessageError("unexpected handshake message", "unexpected_message")
                else:
                    await self._dispatch(conn, msg)
        except ProtocolError as exc:
            log.warning("protocol error from %s: %s", conn.peer.device_id, exc)
            conn.closed_event.set()
            await self._send_error_and_close(conn.stream, exc)
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            keepalive.cancel()
            await conn.close()
            if self._conns.get(conn.peer.device_id) is conn:
                del self._conns[conn.peer.device_id]
                log.info("disconnected from %s", conn.peer.device_id)
                if self._on_peer_disconnected is not None:
                    try:
                        await self._on_peer_disconnected(conn.peer)
                    except Exception:
                        log.exception("peer_disconnected callback failed")

    async def _dispatch(self, conn: _Connection, msg: dict[str, Any]) -> None:
        handler = self._handlers.get(msg["type"])
        if handler is None:
            await conn.send(
                {
                    "type": "error",
                    "code": "unsupported_message_type",
                    "message": f"unsupported message type {msg['type']!r}",
                    "ref": msg.get("id") if isinstance(msg.get("id"), str) else None,
                }
            )
            return
        try:
            await handler(conn.peer, msg)
        except ProtocolError:
            raise
        except PeerNotConnectedError as exc:
            log.debug("handler for %r: peer went away: %s", msg["type"], exc)
        except Exception:
            log.exception("handler for %r failed", msg["type"])

    async def _keepalive(self, conn: _Connection) -> None:
        loop = asyncio.get_running_loop()
        try:
            while not conn.closed:
                await asyncio.sleep(self._keepalive_interval)
                if loop.time() - conn.last_rx > self._idle_timeout:
                    log.info("idle timeout for %s", conn.peer.device_id)
                    await conn.close("idle_timeout")
                    return
                await conn.send({"type": "ping"})
        except (ConnectionError, OSError):
            await conn.close()
