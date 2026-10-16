"""Wire framing and message codec (protocol versions 1 and 2).

A frame is a 4-byte unsigned big-endian length followed by that many bytes of
UTF-8 encoded JSON. The JSON value must be an object with a non-empty string
``type`` member. See docs/protocol.md for the language-independent definition.
"""

from __future__ import annotations

import asyncio
import json
import struct
from typing import Any

from ..errors import InvalidPayloadError, MalformedMessageError, PayloadTooLargeError

PROTOCOL_NAME = "up2p"
#: Version 2: the protocol runs inside TLS 1.3 with authenticated device keys.
PROTOCOL_VERSION = 2
SUPPORTED_VERSIONS = (2,)
#: Version 1: plaintext development transport (explicit opt-in only).
INSECURE_VERSIONS = (1,)

FRAME_HEADER = struct.Struct(">I")
DEFAULT_MAX_FRAME_SIZE = 1 << 20  # 1 MiB
ABSOLUTE_MAX_FRAME_SIZE = 64 << 20  # upper bound accepted by configuration
MAX_TYPE_LENGTH = 64


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise MalformedMessageError(f"duplicate JSON key {key!r}")
        obj[key] = value
    return obj


def _reject_constant(name: str) -> Any:
    raise MalformedMessageError(f"non-standard JSON constant {name}")


def encode_json(value: Any) -> bytes:
    """Serialize ``value`` as compact, strict (RFC 8259) UTF-8 JSON."""
    try:
        text = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        return text.encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise InvalidPayloadError(f"value is not strict-JSON serializable: {exc}") from exc


def _validate_envelope(obj: Any) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise MalformedMessageError("top-level JSON value must be an object")
    msg_type = obj.get("type")
    if not isinstance(msg_type, str) or not 0 < len(msg_type) <= MAX_TYPE_LENGTH:
        raise MalformedMessageError("message 'type' must be a non-empty string")
    return obj


def encode_frame(message: dict[str, Any], max_frame_size: int = DEFAULT_MAX_FRAME_SIZE) -> bytes:
    """Encode a protocol message into a length-prefixed frame."""
    if not isinstance(message, dict):
        raise InvalidPayloadError("protocol messages must be JSON objects")
    try:
        _validate_envelope(message)
    except MalformedMessageError as exc:
        raise InvalidPayloadError(str(exc)) from exc
    body = encode_json(message)
    if len(body) > max_frame_size:
        raise PayloadTooLargeError(
            f"encoded message is {len(body)} bytes; limit is {max_frame_size}"
        )
    return FRAME_HEADER.pack(len(body)) + body


def decode_body(body: bytes) -> dict[str, Any]:
    """Decode a frame body, rejecting anything that is not a valid message."""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MalformedMessageError("frame body is not valid UTF-8") from exc
    try:
        obj = json.loads(
            text, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant
        )
    except MalformedMessageError:
        raise
    except (ValueError, RecursionError) as exc:
        raise MalformedMessageError(f"frame body is not valid JSON: {exc}") from exc
    return _validate_envelope(obj)


class FramedStream:
    """Bidirectional message stream over an asyncio StreamReader/StreamWriter pair."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        max_frame_size: int = DEFAULT_MAX_FRAME_SIZE,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._max_frame_size = max_frame_size
        self._write_lock = asyncio.Lock()
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def ssl_object(self) -> Any:
        return self._writer.get_extra_info("ssl_object")

    @property
    def remote_address(self) -> tuple[str, int] | None:
        peername = self._writer.get_extra_info("peername")
        if isinstance(peername, tuple) and len(peername) >= 2:
            return str(peername[0]), int(peername[1])
        return None

    async def send(self, message: dict[str, Any]) -> None:
        frame = encode_frame(message, self._max_frame_size)
        async with self._write_lock:
            if self._closed:
                raise ConnectionResetError("stream is closed")
            self._writer.write(frame)
            await self._writer.drain()

    async def receive(self) -> dict[str, Any]:
        """Read one message.

        Raises ``asyncio.IncompleteReadError`` on EOF, ``PayloadTooLargeError``
        *before* reading an oversized body, and ``MalformedMessageError`` for
        undecodable frames. After a ProtocolError the stream is desynchronized
        and must be closed.
        """
        header = await self._reader.readexactly(FRAME_HEADER.size)
        (length,) = FRAME_HEADER.unpack(header)
        if length == 0:
            raise MalformedMessageError("empty frame")
        if length > self._max_frame_size:
            raise PayloadTooLargeError(
                f"incoming frame is {length} bytes; limit is {self._max_frame_size}"
            )
        body = await self._reader.readexactly(length)
        return decode_body(body)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._writer.close()
        try:
            await asyncio.wait_for(self._writer.wait_closed(), timeout=2.0)
        except (OSError, TimeoutError):
            pass
