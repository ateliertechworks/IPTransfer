"""Node configuration.

Configuration is per application: values can come from code or from
environment variables. Application-scoped variables (``UP2P_<APP>_<NAME>``)
take precedence over global ones (``UP2P_<NAME>``), so Echo and To-Do running
on the same machine can use different ports, for example::

    UP2P_ECHO_LISTEN_PORT=47801
    UP2P_TODO_LISTEN_PORT=47802
"""

from __future__ import annotations

import dataclasses
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import ConfigurationError
from .network.transport import ABSOLUTE_MAX_FRAME_SIZE, DEFAULT_MAX_FRAME_SIZE

#: Application IDs are lowercase identifiers so they are safe to use as
#: PostgreSQL schema names, mDNS TXT values and file names.
APP_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
SCHEMA_PATTERN = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
MAX_DEVICE_NAME_LENGTH = 256

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def validate_app_id(app_id: str) -> str:
    if not isinstance(app_id, str) or not APP_ID_PATTERN.fullmatch(app_id):
        raise ConfigurationError(
            f"invalid app_id {app_id!r}: must match {APP_ID_PATTERN.pattern}"
        )
    return app_id


@dataclass(frozen=True)
class NodeConfig:
    """Settings for one embedded node. All durations are in seconds."""

    app_id: str
    device_name: str
    listen_host: str = "0.0.0.0"
    listen_port: int = 0
    enable_discovery: bool = True
    auto_connect_discovered: bool = True
    #: Extra delay before the peer with the *higher* device ID dials a
    #: discovered peer, so both sides don't dial each other simultaneously.
    discovery_connect_delay: float = 2.0
    #: Addresses announced over mDNS. ``None`` means "all non-loopback IPv4
    #: interface addresses" when listening on 0.0.0.0, else the listen host.
    advertise_addresses: tuple[str, ...] | None = None
    max_frame_size: int = DEFAULT_MAX_FRAME_SIZE
    connect_timeout: float = 10.0
    handshake_timeout: float = 10.0
    keepalive_interval: float = 15.0
    idle_timeout: float = 45.0
    reconnect_initial_delay: float = 0.5
    reconnect_max_delay: float = 30.0
    #: Use the plaintext, unauthenticated development transport (protocol v1)
    #: instead of TLS 1.3. Only direct messages work in this mode; pairing,
    #: groups and synchronization require the secure transport. Never use in
    #: production.
    allow_insecure_transport: bool = False

    # ---- security (Milestone 2)
    #: PostgreSQL URL (``postgresql+psycopg://user:pass@host:5432/dbname``).
    #: Required unless ``allow_insecure_transport`` is set.
    database_url: str | None = field(default=None, repr=False)
    #: PostgreSQL schema for this application's sync tables. Default
    #: ``up2p_<app_id>``.
    db_schema: str | None = None
    #: Run Alembic migrations automatically on start.
    auto_migrate: bool = True
    #: Directory holding device keys; ``<data_dir>/<app_id>/``. Default is a
    #: per-user platform directory (see docs/security.md).
    data_dir: str | None = None
    #: Optional passphrase encrypting the private key files.
    key_passphrase: str | None = field(default=None, repr=False)
    max_connections: int = 128
    max_pending_handshakes: int = 32
    #: Max new inbound connections per remote IP per ``connection_rate_window``.
    connection_rate_limit: int = 30
    connection_rate_window: float = 10.0
    #: Seconds a pairing request stays valid.
    pairing_timeout: float = 300.0
    max_pending_pairings: int = 8

    # ---- groups (Milestone 3)
    #: Role -> permission list used for new groups. ``None`` uses the default
    #: model (``owner``/``admin``/``member``/``viewer``).
    roles: Mapping[str, Any] | None = None
    #: Role given to the creator of a group (must hold ``group.manage``).
    owner_role: str | None = None
    #: Default invitation lifetime in seconds.
    invite_ttl: float = 7 * 24 * 3600.0

    # ---- synchronization (Milestone 4)
    #: Seconds between anti-entropy sync rounds with connected peers.
    sync_interval: float = 30.0
    #: Seconds between outbox polls (the outbox is also flushed on demand).
    outbox_poll_interval: float = 1.0
    #: Maximum size of one record's JSON data in bytes.
    max_record_size: int = 256 * 1024

    def __post_init__(self) -> None:
        validate_app_id(self.app_id)
        if not isinstance(self.device_name, str) or not (
            0 < len(self.device_name) <= MAX_DEVICE_NAME_LENGTH
        ):
            raise ConfigurationError("device_name must be 1-256 characters")
        if not isinstance(self.listen_port, int) or not 0 <= self.listen_port <= 65535:
            raise ConfigurationError("listen_port must be in 0..65535")
        if not 64 <= self.max_frame_size <= ABSOLUTE_MAX_FRAME_SIZE:
            raise ConfigurationError(
                f"max_frame_size must be between 64 and {ABSOLUTE_MAX_FRAME_SIZE}"
            )
        for name in (
            "connect_timeout",
            "handshake_timeout",
            "keepalive_interval",
            "idle_timeout",
            "reconnect_initial_delay",
            "reconnect_max_delay",
        ):
            if getattr(self, name) <= 0:
                raise ConfigurationError(f"{name} must be positive")
        if self.discovery_connect_delay < 0:
            raise ConfigurationError("discovery_connect_delay must be >= 0")
        if self.idle_timeout <= self.keepalive_interval:
            raise ConfigurationError("idle_timeout must be greater than keepalive_interval")
        if self.reconnect_max_delay < self.reconnect_initial_delay:
            raise ConfigurationError("reconnect_max_delay must be >= reconnect_initial_delay")
        if self.advertise_addresses is not None:
            object.__setattr__(self, "advertise_addresses", tuple(self.advertise_addresses))
        for name in ("max_connections", "max_pending_handshakes", "connection_rate_limit",
                     "max_pending_pairings"):
            if not isinstance(getattr(self, name), int) or getattr(self, name) < 1:
                raise ConfigurationError(f"{name} must be a positive integer")
        for name in ("connection_rate_window", "pairing_timeout", "invite_ttl",
                     "sync_interval", "outbox_poll_interval"):
            if getattr(self, name) <= 0:
                raise ConfigurationError(f"{name} must be positive")
        if self.database_url is not None and not (
            1024 <= self.max_record_size <= self.max_frame_size // 3
        ):
            # Encryption + base64 + metadata expand a record by up to ~1.4x.
            raise ConfigurationError("max_record_size must be between 1024 and max_frame_size / 3")
        if self.db_schema is not None and not SCHEMA_PATTERN.fullmatch(self.db_schema):
            raise ConfigurationError(f"invalid db_schema {self.db_schema!r}")
        if self.data_dir is not None:
            object.__setattr__(self, "data_dir", str(Path(self.data_dir)))
        if self.database_url is not None and not isinstance(self.database_url, str):
            raise ConfigurationError("database_url must be a string")
        if self.allow_insecure_transport and self.database_url is not None:
            raise ConfigurationError(
                "the insecure development transport supports direct messages only; "
                "remove database_url or allow_insecure_transport"
            )

    @property
    def schema(self) -> str:
        return self.db_schema or f"up2p_{self.app_id}"

    def replace(self, **changes: Any) -> NodeConfig:
        return dataclasses.replace(self, **changes)

    @classmethod
    def from_env(
        cls,
        app_id: str,
        device_name: str,
        environ: Mapping[str, str] | None = None,
        **overrides: Any,
    ) -> NodeConfig:
        """Build a config from environment variables; keyword overrides win."""
        validate_app_id(app_id)
        env = os.environ if environ is None else environ
        app_prefix = f"UP2P_{app_id.upper()}_"

        def lookup(name: str) -> str | None:
            return env.get(app_prefix + name, env.get("UP2P_" + name))

        values: dict[str, Any] = {}
        converters = {
            "LISTEN_HOST": ("listen_host", str),
            "LISTEN_PORT": ("listen_port", int),
            "ENABLE_DISCOVERY": ("enable_discovery", _parse_bool),
            "AUTO_CONNECT_DISCOVERED": ("auto_connect_discovered", _parse_bool),
            "ADVERTISE_ADDRESSES": ("advertise_addresses", _parse_list),
            "MAX_FRAME_SIZE": ("max_frame_size", int),
            "CONNECT_TIMEOUT": ("connect_timeout", float),
            "HANDSHAKE_TIMEOUT": ("handshake_timeout", float),
            "KEEPALIVE_INTERVAL": ("keepalive_interval", float),
            "IDLE_TIMEOUT": ("idle_timeout", float),
            "DATABASE_URL": ("database_url", str),
            "DB_SCHEMA": ("db_schema", str),
            "DATA_DIR": ("data_dir", str),
            "KEY_PASSPHRASE": ("key_passphrase", str),
            "SYNC_INTERVAL": ("sync_interval", float),
            "ALLOW_INSECURE_TRANSPORT": ("allow_insecure_transport", _parse_bool),
        }
        for env_name, (attr, convert) in converters.items():
            raw = lookup(env_name)
            if raw is None:
                continue
            try:
                values[attr] = convert(raw)
            except ValueError as exc:
                raise ConfigurationError(f"invalid value for UP2P_{env_name}: {raw!r}") from exc
        values.update(overrides)
        return cls(app_id=app_id, device_name=device_name, **values)


def _parse_bool(raw: str) -> bool:
    value = raw.strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise ValueError(raw)


def _parse_list(raw: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in raw.split(",") if part.strip())
