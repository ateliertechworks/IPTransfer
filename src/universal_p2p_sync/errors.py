"""Exception hierarchy for universal_p2p_sync.

Every error raised deliberately by the library derives from :class:`P2PSyncError`.
Protocol errors carry a stable machine-readable ``code`` that is also used in
``error`` frames on the wire (see docs/protocol.md).
"""

from __future__ import annotations


class P2PSyncError(Exception):
    """Base class for all library errors."""


class ConfigurationError(P2PSyncError, ValueError):
    """Invalid configuration value."""


class InsecureTransportError(ConfigurationError):
    """The node was asked to run without an encrypted transport without explicit opt-in."""


class NodeStateError(P2PSyncError, RuntimeError):
    """An operation was attempted in the wrong node state (e.g. before start())."""


class InvalidPayloadError(P2PSyncError, ValueError):
    """An application payload cannot be encoded for the wire."""


class PeerNotConnectedError(P2PSyncError):
    """No live connection exists to the requested peer."""


class ProtocolError(P2PSyncError):
    """A peer violated the wire protocol."""

    code = "protocol_error"

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code


class MalformedMessageError(ProtocolError):
    """A frame could not be decoded into a valid protocol message."""

    code = "malformed_message"


class PayloadTooLargeError(ProtocolError):
    """A frame exceeds the configured maximum size."""

    code = "payload_too_large"


class HandshakeError(ProtocolError):
    """The connection handshake failed or was rejected."""

    code = "handshake_failed"


class IdentityError(P2PSyncError):
    """A device identity, key file or cryptographic proof is invalid."""


class StorageError(P2PSyncError):
    """The PostgreSQL storage is unavailable, misconfigured or inconsistent."""


class NotFoundError(P2PSyncError, LookupError):
    """A group, invitation, record, device or conflict does not exist."""


class PermissionDeniedError(P2PSyncError, PermissionError):
    """The local device lacks the group permission an operation requires."""


class NotTrustedError(P2PSyncError):
    """The remote device is not paired (or has been revoked)."""


class PairingError(P2PSyncError):
    """A pairing request failed, expired or was rejected."""


class InviteError(P2PSyncError):
    """An invitation is invalid, expired, revoked or was rejected."""


class GroupError(P2PSyncError):
    """A group operation violates the membership rules."""
