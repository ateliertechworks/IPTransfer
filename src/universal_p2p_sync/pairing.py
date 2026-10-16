"""Device pairing: numeric comparison over an authenticated TLS connection.

Pairing turns an authenticated-but-unknown device into a trusted one. Both
devices already know each other's public keys from the connection handshake;
pairing makes the *users* confirm that those keys belong to the device they
see in front of them:

1. A -> B ``pair_request``: commitment ``SHA-256(nonce_A)``.
2. B -> A ``pair_nonce``:   ``nonce_B``.
3. A -> B ``pair_reveal``:  ``nonce_A`` (B checks the commitment).
4. Both compute a 6-digit code from both public keys and both nonces and show
   it (event ``pairing_requested``). A man in the middle would have different
   keys on each side and, because A committed to its nonce before seeing
   B's, cannot steer the two codes to match (1-in-a-million chance).
5. Each user approves locally (``approve_pairing``) which sends ``pair_confirm``.
   When a device has approved *and* received the peer's confirmation, it
   stores the peer as trusted (event ``pairing_completed``).

Either side can reject at any time (``pair_reject``). Sessions expire after
``pairing_timeout`` seconds. Pairing grants no group access by itself.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from . import events as ev
from .crypto import b64d, b64e, format_fingerprint, pairing_code
from .errors import MalformedMessageError, NotFoundError, PairingError
from .models import PairingRequest
from .network.connection import PeerInfo

log = logging.getLogger(__name__)

NONCE_SIZE = 32
PAIRING_TYPES = ("pair_request", "pair_nonce", "pair_reveal", "pair_confirm", "pair_reject")


@dataclass
class _Session:
    session_id: str
    peer: PeerInfo
    initiator: bool
    expires_at: float
    my_nonce: bytes
    commitment: bytes | None = None
    peer_nonce: bytes | None = None
    code: str | None = None
    local_approved: bool = False
    remote_approved: bool = False
    completed: bool = False
    code_ready: asyncio.Future[str] = field(
        default_factory=lambda: asyncio.get_running_loop().create_future()
    )
    done: asyncio.Future[bool] = field(
        default_factory=lambda: asyncio.get_running_loop().create_future()
    )

    def __post_init__(self) -> None:
        for future in (self.code_ready, self.done):
            # Mark exceptions as retrieved: nobody may be awaiting them.
            future.add_done_callback(lambda f: f.cancelled() or f.exception())

    def view(self) -> PairingRequest:
        return PairingRequest(
            session_id=self.session_id,
            device_id=self.peer.device_id,
            device_name=self.peer.device_name,
            fingerprint=format_fingerprint(self.peer.device_id),
            code=self.code,
            initiator=self.initiator,
            expires_at=self.expires_at,
            local_approved=self.local_approved,
            remote_approved=self.remote_approved,
        )


class PairingManager:
    def __init__(
        self,
        *,
        app_id: str,
        my_public_key: bytes,
        send: Callable[[str, dict[str, Any]], Awaitable[None]],
        emit: Callable[..., None],
        store_trust: Callable[[PeerInfo], Awaitable[None]],
        timeout: float,
        max_pending: int,
    ) -> None:
        self._app_id = app_id
        self._my_key = my_public_key
        self._send = send
        self._emit = emit
        self._store_trust = store_trust
        self._timeout = timeout
        self._max_pending = max_pending
        self._sessions: dict[str, _Session] = {}  # by peer device id
        self._expiry_task: asyncio.Task[None] | None = None

    def start(self) -> None:
        self._expiry_task = asyncio.create_task(self._expire_loop(), name="up2p-pairing-expiry")

    async def stop(self) -> None:
        if self._expiry_task is not None:
            self._expiry_task.cancel()
            await asyncio.gather(self._expiry_task, return_exceptions=True)
            self._expiry_task = None
        for session in list(self._sessions.values()):
            self._finish(session, False)
        self._sessions.clear()

    def requests(self) -> list[PairingRequest]:
        return [s.view() for s in self._sessions.values() if not s.completed]

    # ------------------------------------------------------------------ local API

    async def request(self, peer: PeerInfo) -> PairingRequest:
        """Start pairing with a connected peer; returns once the code is known."""
        existing = self._sessions.get(peer.device_id)
        if existing is not None and not existing.completed:
            if existing.code is not None:
                return existing.view()
        elif len(self._sessions) >= self._max_pending:
            raise PairingError("too many pairing requests in progress")
        if existing is None or existing.completed:
            session = _Session(
                session_id=secrets.token_hex(16),
                peer=peer,
                initiator=True,
                expires_at=time.time() + self._timeout,
                my_nonce=os.urandom(NONCE_SIZE),
            )
            self._sessions[peer.device_id] = session
            await self._send(
                peer.device_id,
                {
                    "type": "pair_request",
                    "session": session.session_id,
                    "commitment": b64e(hashlib.sha256(session.my_nonce).digest()),
                },
            )
        else:
            session = existing
        future = session.code_ready
        try:
            await asyncio.wait_for(asyncio.shield(future), self._timeout)
        except TimeoutError as exc:
            self._fail(session, "timeout", by_peer=False)
            raise PairingError("pairing peer did not respond") from exc
        current = self._sessions.get(peer.device_id)
        if current is None or current.code is None:
            raise PairingError("pairing was rejected")
        return current.view()

    async def approve(self, device_id: str) -> None:
        session = self._require(device_id)
        if session.code is None:
            raise PairingError("pairing code not established yet")
        if session.local_approved:
            return
        session.local_approved = True
        await self._send(device_id, {"type": "pair_confirm", "session": session.session_id})
        await self._maybe_complete(session)

    async def reject(self, device_id: str, reason: str = "rejected") -> None:
        session = self._require(device_id)
        try:
            await self._send(
                device_id, {"type": "pair_reject", "session": session.session_id, "reason": reason}
            )
        except Exception:  # the peer may be gone; rejection is local anyway
            pass
        self._fail(session, reason, by_peer=False)

    async def wait_completed(self, device_id: str, timeout: float) -> bool:
        # A completed session stays registered until its trust record is stored.
        session = self._sessions.get(device_id)
        if session is None:
            raise NotFoundError(f"no pairing in progress with {device_id[:16]}")
        return await asyncio.wait_for(asyncio.shield(session.done), timeout)

    def peer_disconnected(self, device_id: str) -> None:
        session = self._sessions.get(device_id)
        if session is not None and not session.completed:
            self._fail(session, "disconnected", by_peer=True)

    # ------------------------------------------------------------------ messages

    async def handle(self, peer: PeerInfo, msg: dict[str, Any]) -> None:
        session_id = msg.get("session")
        if not isinstance(session_id, str) or not 0 < len(session_id) <= 64:
            raise MalformedMessageError("pairing message requires a session id")
        msg_type = msg["type"]
        session = self._sessions.get(peer.device_id)
        if msg_type == "pair_request":
            await self._on_request(peer, session_id, msg)
            return
        if session is None or session.session_id != session_id or session.completed:
            return  # stale or unknown session: ignore
        try:
            if msg_type == "pair_nonce" and session.initiator and session.peer_nonce is None:
                session.peer_nonce = b64d(msg.get("nonce"), expected_len=NONCE_SIZE)
                await self._send(
                    peer.device_id,
                    {"type": "pair_reveal", "session": session_id,
                     "nonce": b64e(session.my_nonce)},
                )
                self._establish(session)
            elif (
                msg_type == "pair_reveal"
                and not session.initiator
                and session.code is None
            ):
                nonce = b64d(msg.get("nonce"), expected_len=NONCE_SIZE)
                if hashlib.sha256(nonce).digest() != session.commitment:
                    await self.reject(peer.device_id, "commitment_mismatch")
                    return
                session.peer_nonce = nonce
                self._establish(session)
            elif msg_type == "pair_confirm":
                if session.code is None:
                    return
                session.remote_approved = True
                await self._maybe_complete(session)
            elif msg_type == "pair_reject":
                reason = msg.get("reason")
                self._fail(session, reason if isinstance(reason, str) else "rejected", by_peer=True)
        except ValueError as exc:
            raise MalformedMessageError(f"invalid pairing message: {exc}") from exc

    async def _on_request(self, peer: PeerInfo, session_id: str, msg: dict[str, Any]) -> None:
        try:
            commitment = b64d(msg.get("commitment"), expected_len=32)
        except ValueError as exc:
            raise MalformedMessageError("invalid pairing commitment") from exc
        existing = self._sessions.get(peer.device_id)
        inherited: dict[str, Any] = {}
        if existing is not None and not existing.completed:
            if existing.initiator and peer.device_id < self._my_id():
                # Both sides started at once: the smaller device ID's request
                # wins; our caller keeps waiting on the surviving session.
                existing.completed = True
                self._sessions.pop(peer.device_id, None)
                inherited = {"code_ready": existing.code_ready, "done": existing.done}
            else:
                return
        if len([s for s in self._sessions.values() if not s.completed]) >= self._max_pending:
            await self._send(
                peer.device_id,
                {"type": "pair_reject", "session": session_id, "reason": "busy"},
            )
            return
        session = _Session(
            session_id=session_id,
            peer=peer,
            initiator=False,
            expires_at=time.time() + self._timeout,
            my_nonce=os.urandom(NONCE_SIZE),
            commitment=commitment,
            **inherited,
        )
        self._sessions[peer.device_id] = session
        await self._send(
            peer.device_id,
            {"type": "pair_nonce", "session": session_id, "nonce": b64e(session.my_nonce)},
        )

    def _my_id(self) -> str:
        return hashlib.sha256(self._my_key).hexdigest()

    # ------------------------------------------------------------------ internals

    def _establish(self, session: _Session) -> None:
        assert session.peer_nonce is not None and session.peer.public_key is not None
        if session.initiator:
            code = pairing_code(
                self._app_id, self._my_key, session.peer.public_key,
                session.my_nonce, session.peer_nonce,
            )
        else:
            code = pairing_code(
                self._app_id, session.peer.public_key, self._my_key,
                session.peer_nonce, session.my_nonce,
            )
        session.code = code
        if not session.code_ready.done():
            session.code_ready.set_result(code)
        self._emit(
            ev.PAIRING_REQUESTED,
            device_id=session.peer.device_id,
            device_name=session.peer.device_name,
            fingerprint=format_fingerprint(session.peer.device_id),
            code=code,
            initiator=session.initiator,
            expires_at=session.expires_at,
        )

    async def _maybe_complete(self, session: _Session) -> None:
        if not (session.local_approved and session.remote_approved) or session.completed:
            return
        session.completed = True
        await self._store_trust(session.peer)
        self._sessions.pop(session.peer.device_id, None)
        self._emit(
            ev.PAIRING_COMPLETED,
            device_id=session.peer.device_id,
            device_name=session.peer.device_name,
            fingerprint=format_fingerprint(session.peer.device_id),
        )
        self._finish(session, True)

    def _fail(self, session: _Session, reason: str, *, by_peer: bool) -> None:
        if session.completed:
            return
        session.completed = True
        self._sessions.pop(session.peer.device_id, None)
        self._emit(
            ev.PAIRING_REJECTED,
            device_id=session.peer.device_id,
            device_name=session.peer.device_name,
            reason=reason[:64],
            by_peer=by_peer,
        )
        self._finish(session, False)

    @staticmethod
    def _finish(session: _Session, ok: bool) -> None:
        if not session.code_ready.done():
            session.code_ready.set_exception(PairingError("pairing was rejected or expired"))
        if not session.done.done():
            session.done.set_result(ok)

    def _require(self, device_id: str) -> _Session:
        session = self._sessions.get(device_id)
        if session is None or session.completed:
            raise NotFoundError(f"no pairing in progress with {device_id[:16]}")
        return session

    async def _expire_loop(self) -> None:
        while True:
            await asyncio.sleep(1.0)
            now = time.time()
            for session in list(self._sessions.values()):
                if not session.completed and session.expires_at < now:
                    try:
                        await self._send(
                            session.peer.device_id,
                            {"type": "pair_reject", "session": session.session_id,
                             "reason": "expired"},
                        )
                    except Exception:
                        pass
                    self._fail(session, "expired", by_peer=False)
