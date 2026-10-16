"""Cross-process test: the example peer runs as a separate OS process."""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from pathlib import Path

import pytest

from .conftest import wait_until

pytestmark = pytest.mark.multiprocess

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "basic_peer.py"


async def read_json_line(stream: asyncio.StreamReader, timeout: float = 15) -> dict:
    line = await asyncio.wait_for(stream.readline(), timeout)
    assert line, "peer process exited early"
    return json.loads(line)


async def test_json_exchange_with_peer_in_another_process(make_node) -> None:
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        str(EXAMPLE),
        "--app-id", "echo",
        "--name", "subprocess-peer",
        "--host", "127.0.0.1",
        "--port", "0",
        "--no-discovery",
        "--echo",
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdin and proc.stdout
    try:
        ready = await read_json_line(proc.stdout)
        assert ready["event"] == "listening"

        node, rec = await make_node("echo", "test-runner")
        info = await node.connect("127.0.0.1", ready["port"])
        assert info.device_id == ready["device_id"]

        await node.send_message(info.device_id, {"text": "ping across processes", "n": 42})
        (reply,) = await rec.wait_for("message_received", timeout=15)
        assert reply["payload"] == {"echo": {"text": "ping across processes", "n": 42}}

        # Lines typed into the peer are broadcast to us.
        proc.stdin.write("hello from stdin\n".encode())
        await proc.stdin.drain()
        await rec.wait_for("message_received", count=2, timeout=15)
        assert rec.of("message_received")[1]["payload"] == {
            "text": "hello from stdin",
            "from": "subprocess-peer",
        }

        # EOF on stdin makes the peer shut down cleanly; we see the disconnect.
        proc.stdin.close()
        assert await asyncio.wait_for(proc.wait(), 20) == 0
        await rec.wait_for("peer_disconnected", timeout=10)
        await wait_until(lambda: node.peers() == [])
    finally:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()
        if proc.returncode not in (0, None):
            assert proc.stderr is not None
            print((await proc.stderr.read()).decode(errors="replace"))
