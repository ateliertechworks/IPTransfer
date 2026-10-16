"""mDNS discovery tests (real multicast on this host's interfaces)."""

from __future__ import annotations

import asyncio

import pytest

from .conftest import mdns_disabled, wait_until

pytestmark = [
    pytest.mark.mdns,
    pytest.mark.skipif(mdns_disabled(), reason="UP2P_SKIP_MDNS_TESTS is set"),
]

MDNS = dict(
    enable_discovery=True,
    advertise_addresses=("127.0.0.1",),
    discovery_connect_delay=0.5,
)


async def test_two_peers_discover_and_auto_connect(make_node) -> None:
    a, rec_a = await make_node("echo", "alpha", **MDNS)
    b, rec_b = await make_node("echo", "beta", **MDNS)

    await rec_a.wait_for("peer_discovered", timeout=20)
    await rec_b.wait_for("peer_discovered", timeout=20)
    assert rec_a.of("peer_discovered")[0]["device_id"] == b.device_id
    assert rec_b.of("peer_discovered")[0]["device_id"] == a.device_id

    await wait_until(lambda: len(a.peers()) == 1 and len(b.peers()) == 1, timeout=20)
    await asyncio.sleep(0.5)
    assert len(a.peers()) == 1 and len(b.peers()) == 1  # no duplicate links

    await a.send_message(b.device_id, {"via": "mdns"})
    (msg,) = await rec_b.wait_for("message_received")
    assert msg["payload"] == {"via": "mdns"}


async def test_other_applications_are_not_discovered(make_node) -> None:
    echo1, rec1 = await make_node("echo", "echo-1", **MDNS)
    echo2, rec2 = await make_node("echo", "echo-2", **MDNS)
    todo, rec_todo = await make_node("todo", "todo-1", **MDNS)

    await wait_until(lambda: len(echo1.peers()) == 1 and len(echo2.peers()) == 1, timeout=20)
    await asyncio.sleep(2.0)  # give the todo node ample time to (wrongly) see anything

    assert {e["device_id"] for e in rec1.of("peer_discovered")} == {echo2.device_id}
    assert {e["device_id"] for e in rec2.of("peer_discovered")} == {echo1.device_id}
    assert rec_todo.of("peer_discovered") == []
    assert todo.peers() == [] and todo.discovered_peers() == []


async def test_stopped_peer_is_reported_lost(make_node) -> None:
    a, rec_a = await make_node("echo", "alpha", **MDNS)
    b, _ = await make_node("echo", "beta", **MDNS)
    await rec_a.wait_for("peer_discovered", timeout=20)
    await rec_a.wait_for("peer_connected", timeout=20)
    await b.stop()
    await rec_a.wait_for("peer_lost", timeout=20)
    await rec_a.wait_for("peer_disconnected", timeout=20)
    assert a.discovered_peers() == []
