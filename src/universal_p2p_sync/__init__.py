"""universal_p2p_sync - embedded, serverless P2P data synchronization for LAN apps."""

from ._version import __version__
from .adapters import RecordAdapter, enqueue_change
from .config import NodeConfig
from .errors import (
    ConfigurationError,
    GroupError,
    HandshakeError,
    IdentityError,
    InsecureTransportError,
    InvalidPayloadError,
    InviteError,
    MalformedMessageError,
    NodeStateError,
    NotFoundError,
    NotTrustedError,
    P2PSyncError,
    PairingError,
    PayloadTooLargeError,
    PeerNotConnectedError,
    PermissionDeniedError,
    ProtocolError,
    StorageError,
)
from .events import Event, EventBus
from .groups import DEFAULT_ROLES
from .models import (
    Conflict,
    ConflictVersion,
    Group,
    Invite,
    Member,
    PairingRequest,
    PeerSyncStatus,
    Record,
    SyncStatus,
    TrustedDevice,
)
from .network.connection import PeerInfo
from .network.discovery import DiscoveredPeer
from .node import AsyncSyncNode, SyncNode
from .sync_engine import DELETE

__all__ = [
    "DEFAULT_ROLES",
    "DELETE",
    "AsyncSyncNode",
    "ConfigurationError",
    "Conflict",
    "ConflictVersion",
    "DiscoveredPeer",
    "Event",
    "EventBus",
    "Group",
    "GroupError",
    "HandshakeError",
    "IdentityError",
    "InsecureTransportError",
    "InvalidPayloadError",
    "Invite",
    "InviteError",
    "MalformedMessageError",
    "Member",
    "NodeConfig",
    "NodeStateError",
    "NotFoundError",
    "NotTrustedError",
    "P2PSyncError",
    "PairingError",
    "PairingRequest",
    "PayloadTooLargeError",
    "PeerInfo",
    "PeerNotConnectedError",
    "PeerSyncStatus",
    "PermissionDeniedError",
    "ProtocolError",
    "Record",
    "RecordAdapter",
    "StorageError",
    "SyncNode",
    "SyncStatus",
    "TrustedDevice",
    "__version__",
    "enqueue_change",
]
