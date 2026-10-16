"""Tests for the thread-backed SyncNode used by desktop/GUI applications."""

from __future__ import annotations

import queue
import threading
import time

import pytest

from universal_p2p_sync import NodeStateError, StorageError, SyncNode

from .conftest import FAST_TIMEOUTS

OPTIONS = dict(
    listen_host="127.0.0.1",
    listen_port=0,
    enable_discovery=False,
    allow_insecure_transport=True,
    **FAST_TIMEOUTS,
)


def wait(predicate, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "condition not met within timeout"
        time.sleep(0.02)


def test_sync_node_exchanges_json_and_marshals_callbacks() -> None:
    ui_queue: queue.Queue = queue.Queue()  # stands in for a GUI event loop
    main_thread = threading.current_thread()

    a = SyncNode("echo", "user_001", "Laptop A", **OPTIONS)
    b = SyncNode("echo", "user_002", "Laptop B", callback_dispatcher=ui_queue.put, **OPTIONS)
    received: list = []
    threads: list = []

    def on_message(event) -> None:
        threads.append(threading.current_thread())
        received.append(event["payload"])

    b.on("message_received", on_message)
    with a, b:
        assert a.is_running and b.is_running
        peer = a.connect(*b.listen_address)
        assert peer.device_name == "Laptop B"
        a.send_message(b.device_id, {"text": "Project meeting tomorrow"})

        # Pump the fake UI loop on the "main thread".
        deadline = time.monotonic() + 10
        while not received and time.monotonic() < deadline:
            try:
                ui_queue.get(timeout=0.1)()
            except queue.Empty:
                pass
        assert received == [{"text": "Project meeting tomorrow"}]
        assert threads == [main_thread]
        assert [p.device_id for p in b.peers()] == [a.device_id]
    assert not a.is_running and not b.is_running


def test_start_in_background_does_not_block() -> None:
    node = SyncNode("todo", "u", "dev", **OPTIONS)
    future = node.start_in_background()
    try:
        future.result(10)
        assert node.is_running and node.listen_address is not None
    finally:
        node.stop()
    node.stop()  # idempotent


def test_blocking_call_from_event_handler_is_refused() -> None:
    a = SyncNode("echo", "u1", "a", **OPTIONS)
    b = SyncNode("echo", "u2", "b", **OPTIONS)
    errors: list = []

    def handler(event) -> None:
        try:
            b.peers()  # would deadlock if allowed
        except NodeStateError as exc:
            errors.append(exc)

    b.on("peer_connected", handler)
    with a, b:
        a.connect(*b.listen_address)
        wait(lambda: errors)
    assert isinstance(errors[0], NodeStateError)


def test_failed_start_releases_thread(tmp_path) -> None:
    # Secure mode with an unreachable PostgreSQL server: start() must fail cleanly.
    node = SyncNode("echo", "u", "dev", **{**OPTIONS, "allow_insecure_transport": False},
                    database_url="postgresql://u:p@127.0.0.1:1/none", data_dir=str(tmp_path))
    with pytest.raises(StorageError):
        node.start()
    wait(lambda: not any(t.name == "up2p-echo" and t.is_alive() for t in threading.enumerate()))
    with pytest.raises(NodeStateError):
        node.connect("127.0.0.1", 1)


def test_submit_returns_future_for_non_blocking_ui_use() -> None:
    a = SyncNode("echo", "u1", "a", **OPTIONS)
    b = SyncNode("echo", "u2", "b", **OPTIONS)
    with a, b:
        future = a.submit(a.aio.connect(*b.listen_address))
        assert future.result(10).device_id == b.device_id
