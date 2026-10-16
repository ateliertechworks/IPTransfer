"""Milestone 2: device identity, TLS 1.3 mutual authentication, pairing, revocation."""

from __future__ import annotations

import asyncio
import os
import socket
import sys

import pytest

from universal_p2p_sync import (
    AsyncSyncNode,
    ConfigurationError,
    HandshakeError,
    IdentityError,
    InvalidPayloadError,
    NotFoundError,
    NotTrustedError,
)
from universal_p2p_sync.crypto import DeviceIdentity, b64d, b64e, device_id_for
from universal_p2p_sync.network.connection import (
    NONCE_SIZE,
    TransportSecurity,
    _auth_transcript,
)
from universal_p2p_sync.network.transport import FramedStream

from .conftest import connect, join, pair, wait_until


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------- identity


def test_identity_is_persistent_and_key_derived(tmp_path) -> None:
    first = DeviceIdentity.load_or_create(tmp_path / "echo")
    second = DeviceIdentity.load_or_create(tmp_path / "echo")
    assert first.device_id == second.device_id == device_id_for(first.public_key)
    assert len(first.fingerprint.replace(" ", "")) == 40
    if sys.platform != "win32":
        for name in ("device_ed25519.pem", "device_x25519.pem"):
            assert (tmp_path / "echo" / name).stat().st_mode & 0o077 == 0
    other = DeviceIdentity.load_or_create(tmp_path / "todo")
    assert other.device_id != first.device_id


def test_passphrase_protected_keys(tmp_path) -> None:
    identity = DeviceIdentity.load_or_create(tmp_path / "k", passphrase="correct horse")
    assert b"ENCRYPTED" in (tmp_path / "k" / "device_ed25519.pem").read_bytes()
    again = DeviceIdentity.load_or_create(tmp_path / "k", passphrase="correct horse")
    assert again.device_id == identity.device_id
    with pytest.raises(IdentityError):
        DeviceIdentity.load_or_create(tmp_path / "k", passphrase="wrong")


def test_secure_mode_requires_postgresql(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("UP2P_DATABASE_URL", raising=False)
    monkeypatch.delenv("UP2P_ECHO_DATABASE_URL", raising=False)
    with pytest.raises(ConfigurationError, match="database_url"):
        AsyncSyncNode("echo", "u", "d", data_dir=str(tmp_path))
    with pytest.raises(ConfigurationError, match="PostgreSQL"):
        AsyncSyncNode("echo", "u", "d", data_dir=str(tmp_path), database_url="sqlite:///x.db")


def test_database_url_from_environment(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("UP2P_ECHO_DATABASE_URL", "postgresql://u:secret@localhost/echo_sync")
    node = AsyncSyncNode("echo", "u", "d", data_dir=str(tmp_path))
    assert node.config.database_url.endswith("/echo_sync")
    assert "secret" not in repr(node.config)


# ---------------------------------------------------------------- transport


async def test_connections_use_tls13_with_verified_identities(make_secure_node) -> None:
    a, ra = await make_secure_node(name="a")
    b, rb = await make_secure_node(name="b")
    await connect(a, b)
    peer = next(p for p in a.peers() if p.device_id == b.device_id)
    assert peer.secure and device_id_for(peer.public_key) == b.device_id
    stream = a._connections._conns[b.device_id].stream
    assert stream.ssl_object.version() == "TLSv1.3"
    event = (await rb.wait_for("peer_connected"))[0]
    assert event["trusted"] is False and event["fingerprint"] == a.fingerprint


async def test_plaintext_client_cannot_talk_to_secure_node(make_secure_node, make_node) -> None:
    secure, _ = await make_secure_node(name="s")
    insecure, _ = await make_node("echo", "plain")
    with pytest.raises((HandshakeError, OSError, asyncio.IncompleteReadError, TimeoutError)):
        await insecure.connect("127.0.0.1", secure.listen_address[1])
    assert secure.peers() == []


async def _raw_hello(port: int, identity: DeviceIdentity, claimed: DeviceIdentity):
    security = TransportSecurity(identity)
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", port, ssl=security.client_context, server_hostname=""
    )
    stream = FramedStream(reader, writer)
    nonce = os.urandom(NONCE_SIZE)
    await stream.send(
        {
            "type": "hello", "protocol": "up2p", "versions": [2], "app_id": "echo",
            "device_id": claimed.device_id, "device_name": "mallory", "listen_port": None,
            "public_key": b64e(claimed.public_key), "nonce": b64e(nonce),
        }
    )
    ack = await stream.receive()
    return stream, nonce, ack


async def test_impersonation_and_replayed_authentication_are_rejected(
    make_secure_node, tmp_path
) -> None:
    victim_node, _ = await make_secure_node(name="victim")
    target, _ = await make_secure_node(name="target")
    port = target.listen_address[1]
    attacker = DeviceIdentity.load_or_create(tmp_path / "attacker")
    victim = victim_node.identity

    # Claiming someone else's key without holding it fails authentication.
    stream, nonce, ack = await _raw_hello(port, attacker, claimed=victim)
    cert = stream.ssl_object.getpeercert(binary_form=True)
    transcript = _auth_transcript(
        "echo", victim.device_id, target.device_id, cert, nonce, b64d(ack["nonce"])
    )
    await stream.send({"type": "auth", "signature": b64e(attacker.sign(transcript))})
    reply = await stream.receive()
    assert reply["type"] == "error" and reply["code"] == "authentication_failed"
    await stream.close()

    # A valid signature recorded from one session is useless in the next one,
    # because the responder contributes a fresh nonce to every transcript.
    stream, nonce, ack = await _raw_hello(port, attacker, claimed=attacker)
    cert = stream.ssl_object.getpeercert(binary_form=True)
    good = attacker.sign(
        _auth_transcript("echo", attacker.device_id, target.device_id, cert, nonce,
                         b64d(ack["nonce"]))
    )
    await stream.send({"type": "auth", "signature": b64e(good)})
    assert (await stream.receive())["type"] == "auth_ok"
    await stream.close()
    stream, nonce, ack = await _raw_hello(port, attacker, claimed=attacker)
    await stream.send({"type": "auth", "signature": b64e(good)})
    reply = await stream.receive()
    assert reply["type"] == "error" and reply["code"] == "authentication_failed"
    await stream.close()

    # A device_id that does not match the presented key is rejected outright.
    security = TransportSecurity(attacker)
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", port, ssl=security.client_context, server_hostname=""
    )
    raw = FramedStream(reader, writer)
    await raw.send(
        {
            "type": "hello", "protocol": "up2p", "versions": [2], "app_id": "echo",
            "device_id": victim.device_id, "device_name": "m", "listen_port": None,
            "public_key": b64e(attacker.public_key), "nonce": b64e(os.urandom(32)),
        }
    )
    reply = await raw.receive()
    assert reply["type"] == "error" and reply["code"] == "identity_mismatch"
    await raw.close()
    assert target.peers() == []


async def test_connection_rate_limit(make_secure_node) -> None:
    node, _ = await make_secure_node(name="n", connection_rate_limit=2, connection_rate_window=30)
    port = node.listen_address[1]
    closed_fast = 0
    for _ in range(5):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            data = await asyncio.wait_for(reader.read(1), 0.5)
            closed_fast += data == b""
        except TimeoutError:
            pass
        writer.close()
    assert closed_fast >= 3


# ---------------------------------------------------------------- trust and pairing


async def test_untrusted_devices_cannot_message_or_synchronize(make_secure_node) -> None:
    a, ra = await make_secure_node(name="a")
    b, rb = await make_secure_node(name="b")
    group = await a.create_group("Private")
    await a.publish(group.id, "notes", "n1", {"secret": True})
    await connect(b, a)
    with pytest.raises(NotTrustedError):
        await b.send_message(a.device_id, {"hi": 1})
    # Bypass the client-side check: the receiver must refuse on its own.
    await b._connections.send(a.device_id, {"type": "message", "id": "x", "payload": {}})
    await b._connections.send(
        a.device_id, {"type": "sync_req", "group_id": group.id, "heads": [], "vector": {}}
    )
    await asyncio.sleep(0.5)
    assert ra.of("message_received") == []
    assert b.list_groups() == []
    assert rb.of("record_received") == []


async def test_pairing_flow_codes_match_and_grant_no_group_access(make_secure_node) -> None:
    a, ra = await make_secure_node(name="a")
    b, rb = await make_secure_node(name="b")
    group = await a.create_group("Team")
    await pair(a, b)
    codes = {e["code"] for e in ra.of("pairing_requested") + rb.of("pairing_requested")}
    assert len(codes) == 1 and len(next(iter(codes))) == 6
    await ra.wait_for("pairing_completed")
    await rb.wait_for("pairing_completed")
    devices = await a.list_trusted_devices()
    assert [d.device_id for d in devices] == [b.device_id]
    assert devices[0].fingerprint == b.fingerprint
    # Pairing alone gives no group membership or data.
    await asyncio.sleep(1.5)
    assert b.list_groups() == []
    with pytest.raises(NotFoundError):
        await b.publish(group.id, "notes", "x", {"a": 1})


async def test_pairing_rejection(make_secure_node) -> None:
    a, ra = await make_secure_node(name="a")
    b, rb = await make_secure_node(name="b")
    await connect(a, b)
    await a.request_pairing(b.device_id)
    await wait_until(lambda: b.pairing_requests())
    await b.reject_pairing(a.device_id, "codes differ")
    await ra.wait_for("pairing_rejected")
    assert ra.of("pairing_rejected")[0]["by_peer"] is True
    assert not a.is_trusted(b.device_id) and not b.is_trusted(a.device_id)


async def test_pairing_survives_restart_and_peers_reconnect(make_secure_node, tmp_path,
                                                             pg_database) -> None:
    url_a, url_b = pg_database(), pg_database()
    port_b = free_port()
    a, _ = await make_secure_node(name="a", database_url=url_a, data_dir=tmp_path / "a")
    b, _ = await make_secure_node(name="b", database_url=url_b, data_dir=tmp_path / "b",
                                  listen_port=port_b)
    await pair(a, b)
    a_id, b_id = a.device_id, b.device_id
    await a.stop()
    await b.stop()

    a2, ra2 = await make_secure_node(name="a", database_url=url_a, data_dir=tmp_path / "a")
    b2, _ = await make_secure_node(name="b", database_url=url_b, data_dir=tmp_path / "b",
                                   listen_port=port_b)
    assert (a2.device_id, b2.device_id) == (a_id, b_id)
    assert a2.is_trusted(b_id) and b2.is_trusted(a_id)
    # a2 redials b's last known address automatically.
    await wait_until(lambda: any(p.device_id == b_id for p in a2.peers()), 15)
    event = (await ra2.wait_for("peer_connected"))[0]
    assert event["trusted"] is True


async def test_revoked_device_is_disconnected_refused_and_removed(make_secure_node) -> None:
    a, ra = await make_secure_node(name="a")
    b, rb = await make_secure_node(name="b")
    await pair(a, b)
    group = await a.create_group("Team")
    await join(a, b, rb, group.id, "member")
    await a.revoke_device(b.device_id)
    await ra.wait_for("device_revoked")
    await wait_until(lambda: not a.peers())
    assert b.device_id not in {m.device_id for m in a.list_members(group.id)}
    with pytest.raises(HandshakeError) as info:
        await b.connect("127.0.0.1", a.listen_address[1])
    assert info.value.code == "device_revoked"
    with pytest.raises(HandshakeError):
        await a.connect("127.0.0.1", b.listen_address[1])
    # Forgetting the record allows pairing again later.
    await a.forget_device(b.device_id)
    await connect(a, b)


async def test_malformed_and_oversized_input_is_rejected(make_secure_node) -> None:
    a, _ = await make_secure_node(name="a", max_record_size=2048)
    b, rb = await make_secure_node(name="b")
    await pair(a, b)
    group = await a.create_group("Team")
    with pytest.raises(InvalidPayloadError):
        await a.publish(group.id, "notes", "big", {"x": "y" * 5000})
    with pytest.raises(InvalidPayloadError):
        await a.publish(group.id, "bad collection!", "r", {})
    with pytest.raises(InvalidPayloadError):
        await a.publish(group.id, "notes", "r", ["not", "an", "object"])  # type: ignore[arg-type]
    with pytest.raises(NotFoundError):  # b is paired but not a member
        await b.publish(group.id, "notes", "r", {})
    # A malformed sync message from an authenticated peer closes that connection only.
    await a._connections.send(b.device_id, {"type": "sync_req", "group_id": "zz"})
    await wait_until(lambda: not b.peers())
    await connect(a, b)
    assert b.is_running
