"""Engine management, migrations and the single-instance lock."""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import Connection, create_engine, select, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import ArgumentError, SQLAlchemyError

from ..errors import ConfigurationError, StorageError
from . import schema as t

log = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


def normalize_database_url(url: str) -> str:
    """Accept ``postgresql://`` URLs and route them to the psycopg 3 driver.

    Only PostgreSQL is supported; any other dialect is rejected.
    """
    try:
        parsed = make_url(url)
    except ArgumentError as exc:
        raise ConfigurationError("database_url is not a valid SQLAlchemy URL") from exc
    backend = parsed.get_backend_name()
    if backend not in ("postgresql", "postgres"):
        raise ConfigurationError(
            f"unsupported database backend {backend!r}: universal-p2p-sync requires PostgreSQL"
        )
    driver = parsed.get_driver_name()
    if driver not in ("psycopg", "postgresql", "postgres", ""):
        raise ConfigurationError("use the psycopg 3 driver: postgresql+psycopg://...")
    return parsed.set(drivername="postgresql+psycopg").render_as_string(hide_password=False)


def _lock_key(schema: str) -> int:
    digest = hashlib.sha256(f"up2p-instance:{schema}".encode()).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


def run_migrations(engine: Engine, schema: str) -> None:
    """Upgrade ``schema`` to the latest revision (creating it if needed)."""
    from alembic import command
    from alembic.config import Config

    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.attributes["schema"] = schema
    with engine.begin() as conn:
        # Serialize concurrent migrations of the same schema across processes.
        conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _lock_key("migrate:" + schema)})
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "head")


class Database:
    """Synchronous SQLAlchemy access to one application schema.

    All calls are made from the node's single database worker thread, so
    operations are serialized within one node. A PostgreSQL advisory lock
    held for the node's lifetime prevents two running instances from sharing
    the same schema.
    """

    def __init__(self, url: str, schema: str) -> None:
        self.schema = schema
        self._raw_engine = create_engine(
            normalize_database_url(url), pool_pre_ping=True, pool_size=4, max_overflow=4
        )
        self.engine = self._raw_engine.execution_options(schema_translate_map={None: schema})
        self._lock_conn: Connection | None = None

    def open(self, *, migrate: bool, device_id: str) -> None:
        try:
            if migrate:
                run_migrations(self._raw_engine, self.schema)
            self._acquire_instance_lock()
            self._check_schema_version()
            self._claim_owner(device_id)
        except SQLAlchemyError as exc:
            self.close()
            raise StorageError(f"cannot open PostgreSQL storage: {exc}") from exc
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if self._lock_conn is not None:
            try:
                self._lock_conn.close()  # releases the session-level advisory lock
            except SQLAlchemyError:
                pass
            self._lock_conn = None
        self._raw_engine.dispose()

    @contextmanager
    def transaction(self) -> Iterator[Connection]:
        with self.engine.begin() as conn:
            yield conn

    def _acquire_instance_lock(self) -> None:
        conn = self._raw_engine.connect()
        got = conn.execute(
            text("SELECT pg_try_advisory_lock(:k)"), {"k": _lock_key(self.schema)}
        ).scalar()
        conn.commit()
        if not got:
            conn.close()
            raise StorageError(
                f"another running node already uses schema {self.schema!r}; "
                "each running application instance needs its own schema or database"
            )
        self._lock_conn = conn

    def _check_schema_version(self) -> None:
        with self._raw_engine.connect() as conn:
            exists = conn.execute(
                text("SELECT to_regclass(:name)"), {"name": f'"{self.schema}".alembic_version'}
            ).scalar()
            if exists is None:
                raise StorageError(
                    f"schema {self.schema!r} is not initialized; enable auto_migrate or run "
                    "'python -m universal_p2p_sync db-upgrade'"
                )
            current = conn.execute(
                text(f'SELECT version_num FROM "{self.schema}".alembic_version')
            ).scalar()
        from alembic.config import Config
        from alembic.script import ScriptDirectory

        cfg = Config()
        cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
        head = ScriptDirectory.from_config(cfg).get_current_head()
        if current != head:
            raise StorageError(
                f"schema {self.schema!r} is at revision {current}, library expects {head}; "
                "run migrations"
            )

    def _claim_owner(self, device_id: str) -> None:
        """Bind the schema to this device identity (detects mixed-up key/DB pairs)."""
        with self.transaction() as conn:
            owner = conn.execute(
                select(t.node_meta.c.value).where(t.node_meta.c.key == "device_id")
            ).scalar()
            if owner is None:
                conn.execute(t.node_meta.insert().values(key="device_id", value=device_id))
            elif owner != device_id:
                raise StorageError(
                    f"schema {self.schema!r} belongs to device {owner[:16]}..., but the loaded "
                    f"identity is {device_id[:16]}...; use the matching data_dir or another schema"
                )
