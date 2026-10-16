"""Connection manager tests over real localhost TCP sockets."""

from __future__ import annotations

import asyncio
import struct
import uuid
from typing import Any

import pytest

from universal_p2p_sync import (
    AsyncSyncNode,
    ConfigurationError,
    HandshakeError,
    InvalidPayloadError,
    NodeStateError,
    PayloadTooLargeError,
    PeerNotConnectedError,
)
from universal_p2p_sync.network.transport import FramedStream, decode_body, encode_frame

from .conftest import wait_until


def addr(node: AsyncSyncNode) -> tuple[str, int]:
    assert node.listen_address is not None
    return node.listen_address


class RawClient:
    """Speaks the wire protocol by hand to exercise the server side."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer
        self.stream = FramedStream(reader, writer, max_frame_size=1 << 20)

    @classmethod
    async def connect(cls, node: AsyncSyncNode) -> RawClient:
        reader, writer = await asyncio.open_connection(*addr(node))
        return cls(reader, writer)

    async def handshake(self, app_id: str = "echo", **overrides: Any) -> dict[str, Any]:
        hello = {
            "type": "hello",
            "protocol": "up2p",
            "versions": [1],
            "app_id": app_id,
            "device_id": uuid.uuid4().hex,
            "device_name": "raw",
            "listen_port": None,
        }
        hello.update(overrides)
        await self.stream.send(hello)
        return await asyncio.wait_for(self.stream.receive(), 3)

    async def send_raw(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()

    async def read_until_eof(self, timeout: float = 5) -> list[dict[str, Any]]:
        messages = []
        try:
            while True:
                messages.append(await asyncio.wait_for(self.stream.receive(), timeout))
        except (asyncio.IncompleteReadError, ConnectionError):
            await self.close()
            return messages

    async def close(self) -> None:
        await self.stream.close()


# ---------------------------------------------------------------- configuration


def test_insecure_transport_is_never_the_default(monkeypatch, tmp_path) -> None:
    # Without the explicit opt-in a node runs in secure mode, which needs its
    # own PostgreSQL database; it never silently falls back to plaintext.
    monkeypatch.delenv("UP2P_DATABASE_URL", raising=False)
    monkeypatch.delenv("UP2P_ECHO_DATABASE_URL", raising=False)
    with pytest.raises(ConfigurationError, match="database_url"):
        AsyncSyncNode("echo", "u", "dev", data_dir=str(tmp_path))
    node = AsyncSyncNode("echo", "u", "dev", data_dir=str(tmp_path),
                         database_url="postgresql://u@127.0.0.1:1/x")
    assert node.secure and node.config.allow_insecure_transport is False


@pytest.mark.parametrize("app_id", ["", "Echo", "1todo", "to do", "a" * 64, "echo;drop"])
def test_invalid_app_id_rejected(app_id: str) -> None:
    with pytest.raises(ConfigurationError):
        AsyncSyncNode(app_id, "u", "dev", allow_insecure_transport=True)


async def test_operations_require_running_node(make_node) -> None:
    node, _ = await make_node(start=False)
    with pytest.raises(NodeStateError):
        await node.connect("127.0.0.1", 1)
    with pytest.raises(NodeStateError):
        await node.send_message("x" * 32, {})


# ---------------------------------------------------------------- manual connection + JSON


async def test_manual_connection_and_bidirectional_json_exchange(make_node) -> None:
    a, rec_a = await make_node(name="alpha")
    b, rec_b = await make_node(name="beta")

    info = await a.connect(*addr(b))
    assert info.device_id == b.device_id
    assert info.device_name == "beta"
    assert info.outbound is True

    await rec_a.wait_for("peer_connected")
    await rec_b.wait_for("peer_connected")
    assert rec_b.of("peer_connected")[0]["device_id"] == a.device_id

    payload = {"text": "Project meeting tomorrow", "tags": ["x", "y"], "n": 3, "ok": True}
    await a.send_message(b.device_id, payload)
    (received,) = await rec_b.wait_for("message_received")
    assert received["payload"] == payload
    assert received["device_id"] == a.device_id

    await b.send_message(a.device_id, {"reply": "ack"})
    (back,) = await rec_a.wait_for("message_received")
    assert back["payload"] == {"reply": "ack"}


async def test_broadcast_reaches_all_connected_peers(make_node) -> None:
    hub, _ = await make_node(name="hub")
    leaves = [await make_node(name=f"leaf{i}") for i in range(3)]
    for leaf, _ in leaves:
        await leaf.connect(*addr(hub))
    await wait_until(lambda: len(hub.peers()) == 3)
    assert await hub.broadcast_message({"hello": "all"}) == 3
    for _, rec in leaves:
        (msg,) = await rec.wait_for("message_received")
        assert msg["payload"] == {"hello": "all"}


async def test_send_to_unknown_peer_raises(make_node) -> None:
    a, _ = await make_node()
    with pytest.raises(PeerNotConnectedError):
        await a.send_message("0" * 32, {"x": 1})


async def test_payload_must_be_json_object(make_node) -> None:
    a, _ = await make_node(name="a")
    b, _ = await make_node(name="b")
    await a.connect(*addr(b))
    with pytest.raises(InvalidPayloadError):
        await a.send_message(b.device_id, ["not", "a", "dict"])  # type: ignore[arg-type]
    with pytest.raises(InvalidPayloadError):
        await a.send_message(b.device_id, {"bad": {1, 2}})


async def test_oversized_outgoing_payload_rejected_and_connection_survives(make_node) -> None:
    a, _ = await make_node(name="a", max_frame_size=4096)
    b, rec_b = await make_node(name="b", max_frame_size=4096)
    await a.connect(*addr(b))
    with pytest.raises(PayloadTooLargeError):
        await a.send_message(b.device_id, {"blob": "x" * 10_000})
    await a.send_message(b.device_id, {"small": True})
    (msg,) = await rec_b.wait_for("message_received")
    assert msg["payload"] == {"small": True}


# ---------------------------------------------------------------- isolation / handshake


async def test_different_applications_cannot_connect(make_node) -> None:
    echo, rec_echo = await make_node("echo", "echo-dev")
    todo, rec_todo = await make_node("todo", "todo-dev")
    with pytest.raises(HandshakeError) as excinfo:
        await echo.connect(*addr(todo))
    assert excinfo.value.code == "app_mismatch"
    with pytest.raises(HandshakeError):
        await todo.connect(*addr(echo))
    await asyncio.sleep(0.2)
    assert echo.peers() == [] and todo.peers() == []
    assert not rec_echo.of("peer_connected") and not rec_todo.of("peer_connected")


async def test_connecting_to_self_is_rejected(make_node) -> None:
    a, _ = await make_node()
    with pytest.raises(HandshakeError) as excinfo:
        await a.connect(*addr(a))
    assert excinfo.value.code == "self_connection"
    assert a.peers() == []


@pytest.mark.parametrize(
    "overrides, code",
    [
        ({"protocol": "other"}, "unsupported_protocol"),
        ({"versions": [99]}, "unsupported_version"),
        ({"versions": "1"}, "invalid_handshake"),
        ({"device_id": "short"}, "invalid_handshake"),
        ({"device_id": "../../etc/passwd"}, "invalid_handshake"),
        ({"device_name": ""}, "invalid_handshake"),
        ({"listen_port": 70000}, "invalid_handshake"),
        ({"listen_port": True}, "invalid_handshake"),
        ({"app_id": "todo"}, "app_mismatch"),
    ],
)
async def test_invalid_handshakes_are_rejected(make_node, overrides, code) -> None:
    node, rec = await make_node()
    client = await RawClient.connect(node)
    reply = await client.handshake(**overrides)
    assert reply["type"] == "error" and reply["code"] == code
    assert await client.read_until_eof() == []
    assert node.peers() == [] and not rec.of("peer_connected")


async def test_first_message_must_be_hello(make_node) -> None:
    node, _ = await make_node()
    client = await RawClient.connect(node)
    await client.stream.send({"type": "message", "payload": {}})
    (reply,) = await client.read_until_eof()
    assert reply["code"] == "unexpected_message"


async def test_silent_client_is_dropped_after_handshake_timeout(make_node) -> None:
    node, _ = await make_node(handshake_timeout=0.3)
    client = await RawClient.connect(node)
    loop = asyncio.get_running_loop()
    started = loop.time()
    assert await client.read_until_eof(timeout=5) == []
    assert loop.time() - started < 3


# ---------------------------------------------------------------- malformed traffic after handshake


async def test_malformed_frame_closes_connection_but_node_stays_healthy(make_node) -> None:
    node, rec = await make_node()
    client = await RawClient.connect(node)
    assert (await client.handshake())["type"] == "hello_ack"
    await rec.wait_for("peer_connected")

    body = b"{this is not json"
    await client.send_raw(struct.pack(">I", len(body)) + body)
    replies = await client.read_until_eof()
    assert replies[-1]["type"] == "error" and replies[-1]["code"] == "malformed_message"
    await rec.wait_for("peer_disconnected")

    # The node keeps accepting well-formed peers.
    other, _ = await make_node(name="other")
    await other.connect(*addr(node))
    await wait_until(lambda: len(node.peers()) == 1)


async def test_oversized_incoming_frame_closes_connection(make_node) -> None:
    node, rec = await make_node(max_frame_size=1024)
    client = await RawClient.connect(node)
    assert (await client.handshake())["type"] == "hello_ack"
    await client.send_raw(struct.pack(">I", 10_000_000))
    replies = await client.read_until_eof()
    assert replies[-1]["code"] == "payload_too_large"
    await rec.wait_for("peer_disconnected")
    assert node.peers() == []


async def test_message_with_non_object_payload_is_rejected(make_node) -> None:
    node, rec = await make_node()
    client = await RawClient.connect(node)
    await client.handshake()
    await client.stream.send({"type": "message", "payload": [1, 2]})
    replies = await client.read_until_eof()
    assert replies[-1]["code"] == "malformed_message"
    assert not rec.of("message_received")


async def test_repeated_hello_after_handshake_is_a_protocol_error(make_node) -> None:
    node, _ = await make_node()
    client = await RawClient.connect(node)
    await client.handshake()
    reply = await client.handshake()  # second hello on an established connection
    assert reply["type"] == "error" and reply["code"] == "unexpected_message"
    assert await client.read_until_eof() == []


async def test_unknown_message_type_gets_error_but_connection_stays_open(make_node) -> None:
    node, _ = await make_node()
    client = await RawClient.connect(node)
    await client.handshake()
    await client.stream.send({"type": "x-future-feature", "id": "m1"})
    reply = await asyncio.wait_for(client.stream.receive(), 3)
    assert reply == {
        "type": "error",
        "code": "unsupported_message_type",
        "message": "unsupported message type 'x-future-feature'",
        "ref": "m1",
    }
    await client.stream.send({"type": "ping"})
    assert (await asyncio.wait_for(client.stream.receive(), 3))["type"] == "pong"
    await client.close()


# ---------------------------------------------------------------- liveness


async def test_unresponsive_peer_is_dropped_after_idle_timeout(make_node) -> None:
    node, rec = await make_node(keepalive_interval=0.2, idle_timeout=0.6)
    client = await RawClient.connect(node)
    await client.handshake()
    await rec.wait_for("peer_connected")
    # Never answer pings: the node must give up on its own.
    await rec.wait_for("peer_disconnected", timeout=5)
    assert node.peers() == []
    await client.close()


async def test_keepalive_keeps_healthy_connection_open(make_node) -> None:
    a, rec_a = await make_node(name="a", keepalive_interval=0.2, idle_timeout=0.6)
    b, _ = await make_node(name="b", keepalive_interval=0.2, idle_timeout=0.6)
    await a.connect(*addr(b))
    await asyncio.sleep(2.0)  # several idle timeouts' worth
    assert [p.device_id for p in a.peers()] == [b.device_id]
    assert not rec_a.of("peer_disconnected")


# ---------------------------------------------------------------- duplicates & reconnection


async def test_simultaneous_connections_collapse_to_one(make_node) -> None:
    a, rec_a = await make_node(name="a")
    b, rec_b = await make_node(name="b")
    results = await asyncio.gather(a.connect(*addr(b)), b.connect(*addr(a)))
    assert {r.device_id for r in results} == {a.device_id, b.device_id}
    await asyncio.sleep(0.5)
    assert len(a.peers()) == 1 and len(b.peers()) == 1
    # Both sides agree on the surviving connection: the one dialed by min(device_id).
    dialer = min(a.device_id, b.device_id)
    assert a.peers()[0].outbound == (dialer == a.device_id)
    assert b.peers()[0].outbound == (dialer == b.device_id)
    # Replacing a duplicate is not reported as a disconnect.
    assert not rec_a.of("peer_disconnected") and not rec_b.of("peer_disconnected")
    await a.send_message(b.device_id, {"after": "dedupe"})
    (msg,) = await rec_b.wait_for("message_received")
    assert msg["payload"] == {"after": "dedupe"}


async def test_persistent_peer_reconnects_after_restart(make_node) -> None:
    b, _ = await make_node(name="b")
    host, port = addr(b)
    a, rec_a = await make_node(name="a")
    a.add_peer_address(host, port)
    await rec_a.wait_for("peer_connected")

    await b.stop()
    await rec_a.wait_for("peer_disconnected")

    # A new instance comes back on the same port; A must find it again.
    b2, rec_b2 = await make_node(name="b2", listen_port=port)
    await rec_a.wait_for("peer_connected", count=2, timeout=10)
    assert [p.device_id for p in a.peers()] == [b2.device_id]
    await a.send_message(b2.device_id, {"again": 1})
    await rec_b2.wait_for("message_received")


async def test_disconnect_closes_connection_and_cancels_reconnect(make_node) -> None:
    a, rec_a = await make_node(name="a")
    b, rec_b = await make_node(name="b")
    a.add_peer_address(*addr(b))
    await rec_a.wait_for("peer_connected")
    await a.disconnect(b.device_id)
    await rec_a.wait_for("peer_disconnected")
    await rec_b.wait_for("peer_disconnected")
    await asyncio.sleep(0.8)  # longer than the reconnect backoff
    assert a.peers() == [] and b.peers() == []


# ---------------------------------------------------------------- shutdown


async def test_clean_shutdown(make_node) -> None:
    a, _ = await make_node(name="a")
    b, rec_b = await make_node(name="b")
    host, port = addr(a)
    await b.connect(host, port)
    b.add_peer_address(host, port)  # a reconnect loop must also be cancelled
    await wait_until(lambda: len(a.peers()) == 1)

    await a.stop()
    await a.stop()  # idempotent
    assert not a.is_running and a.listen_address is None
    await rec_b.wait_for("peer_disconnected")

    # The port is released and can be rebound immediately.
    server = await asyncio.start_server(lambda r, w: None, host, port)
    server.close()
    await server.wait_closed()

    await b.stop()
    await asyncio.sleep(0)
    leftover = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    assert leftover == [], leftover


async def test_node_can_restart_after_stop(make_node) -> None:
    a, _ = await make_node(name="a")
    b, rec_b = await make_node(name="b")
    await a.stop()
    await a.start()
    await a.connect(*addr(b))
    await rec_b.wait_for("peer_connected")
