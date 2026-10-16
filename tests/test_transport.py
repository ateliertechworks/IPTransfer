"""Framing and codec tests: malformed and oversized frames must be rejected."""

from __future__ import annotations

import asyncio
import struct

import pytest

from universal_p2p_sync.errors import (
    InvalidPayloadError,
    MalformedMessageError,
    PayloadTooLargeError,
)
from universal_p2p_sync.network.transport import (
    FramedStream,
    decode_body,
    encode_frame,
)


def test_roundtrip_preserves_unicode_and_nesting() -> None:
    msg = {"type": "message", "payload": {"text": "வணக்கம் 👋", "n": [1, 2.5, None, True]}}
    frame = encode_frame(msg)
    (length,) = struct.unpack(">I", frame[:4])
    assert length == len(frame) - 4
    assert decode_body(frame[4:]) == msg


@pytest.mark.parametrize(
    "bad",
    [
        ["not", "an", "object"],
        {"no_type": 1},
        {"type": ""},
        {"type": 5},
        {"type": "x", "v": float("nan")},
        {"type": "x", "v": object()},
        {"type": "x", "v": "\ud800"},  # lone surrogate is not valid UTF-8
    ],
)
def test_encode_rejects_invalid_messages(bad: object) -> None:
    with pytest.raises(InvalidPayloadError):
        encode_frame(bad)  # type: ignore[arg-type]


def test_encode_rejects_oversized_message() -> None:
    with pytest.raises(PayloadTooLargeError):
        encode_frame({"type": "x", "blob": "a" * 2000}, max_frame_size=1000)


@pytest.mark.parametrize(
    "body",
    [
        b"\xff\xfe\x00",  # invalid UTF-8
        b"{not json}",
        b"[1,2,3]",  # not an object
        b'"string"',
        b'{"type":"x","type":"y"}',  # duplicate key
        b'{"type":"x","v":NaN}',  # non-standard constant
        b'{"type":"x","v":Infinity}',
        b'{"payload":{}}',  # missing type
        b"[" * 100_000 + b"]" * 100_000,  # pathological nesting
    ],
)
def test_decode_rejects_malformed_bodies(body: bytes) -> None:
    with pytest.raises(MalformedMessageError):
        decode_body(body)


async def _stream_pair(max_frame_size: int = 1024) -> tuple[FramedStream, asyncio.StreamWriter, asyncio.Server]:
    accepted: asyncio.Future[FramedStream] = asyncio.get_running_loop().create_future()

    async def on_conn(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        accepted.set_result(FramedStream(reader, writer, max_frame_size=max_frame_size))

    server = await asyncio.start_server(on_conn, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    _, raw_writer = await asyncio.open_connection("127.0.0.1", port)
    stream = await asyncio.wait_for(accepted, 5)
    return stream, raw_writer, server


async def test_oversized_header_rejected_before_body_is_read() -> None:
    stream, raw, server = await _stream_pair(max_frame_size=1024)
    try:
        # Claim a 2 GiB body but never send it: the reader must fail immediately.
        raw.write(struct.pack(">I", 2**31))
        await raw.drain()
        with pytest.raises(PayloadTooLargeError):
            await asyncio.wait_for(stream.receive(), 2)
    finally:
        raw.close()
        await stream.close()
        server.close()


async def test_zero_length_frame_rejected() -> None:
    stream, raw, server = await _stream_pair()
    try:
        raw.write(struct.pack(">I", 0))
        await raw.drain()
        with pytest.raises(MalformedMessageError):
            await asyncio.wait_for(stream.receive(), 2)
    finally:
        raw.close()
        await stream.close()
        server.close()


async def test_frames_split_across_writes_are_reassembled() -> None:
    stream, raw, server = await _stream_pair()
    try:
        frame = encode_frame({"type": "message", "payload": {"k": "v"}})
        for i in range(len(frame)):
            raw.write(frame[i : i + 1])
            await raw.drain()
        assert await asyncio.wait_for(stream.receive(), 2) == {
            "type": "message",
            "payload": {"k": "v"},
        }
    finally:
        raw.close()
        await stream.close()
        server.close()
