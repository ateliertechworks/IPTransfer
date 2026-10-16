from __future__ import annotations

import asyncio
import os
from collections import defaultdict
from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest

from universal_p2p_sync import AsyncSyncNode, Event

FAST_TIMEOUTS = dict(
    connect_timeout=3.0,
    handshake_timeout=2.0,
    keepalive_interval=1.0,
    idle_timeout=3.0,
    reconnect_initial_delay=0.1,
    reconnect_max_delay=0.5,
)


async def wait_until(predicate: Callable[[], bool], timeout: float = 10.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not predicate():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("condition not met within timeout")
        await asyncio.sleep(0.02)


class EventRecorder:
    def __init__(self, node: AsyncSyncNode) -> None:
        self.events: dict[str, list[Event]] = defaultdict(list)
        node.on("*", self._record)

    def _record(self, event: Event) -> None:
        self.events[event.name].append(event)

    def of(self, name: str) -> list[Event]:
        return self.events[name]

    async def wait_for(self, name: str, count: int = 1, timeout: float = 10.0) -> list[Event]:
        await wait_until(lambda: len(self.events[name]) >= count, timeout)
        return self.events[name]


@pytest.fixture
async def make_node() -> AsyncIterator[Callable[..., Any]]:
    created: list[AsyncSyncNode] = []

    async def factory(
        app_id: str = "echo", name: str = "node", *, start: bool = True, **overrides: Any
    ) -> tuple[AsyncSyncNode, EventRecorder]:
        options: dict[str, Any] = dict(
            listen_host="127.0.0.1",
            listen_port=0,
            enable_discovery=False,
            allow_insecure_transport=True,
            **FAST_TIMEOUTS,
        )
        options.update(overrides)
        node = AsyncSyncNode(app_id, f"user-{name}", name, **options)
        recorder = EventRecorder(node)
        created.append(node)
        if start:
            await node.start()
        return node, recorder

    yield factory
    for node in created:
        await node.stop()


def mdns_disabled() -> bool:
    return os.environ.get("UP2P_SKIP_MDNS_TESTS", "") not in ("", "0")


# ---------------------------------------------------------------- PostgreSQL fixtures

#: Admin URL of a PostgreSQL server for integration tests, for example
#: ``postgresql+psycopg://up2p:up2p@127.0.0.1:5441/postgres``. Each test node
#: gets its own freshly created database, like separate laptops would.
PG_ADMIN_URL = os.environ.get("UP2P_TEST_DATABASE_URL")

SECURE_DEFAULTS = dict(
    listen_host="127.0.0.1",
    listen_port=0,
    enable_discovery=False,
    sync_interval=1.0,
    outbox_poll_interval=0.1,
    pairing_timeout=10.0,
    **FAST_TIMEOUTS,
)


def requires_postgres() -> Any:
    return pytest.mark.skipif(
        not PG_ADMIN_URL, reason="set UP2P_TEST_DATABASE_URL to run PostgreSQL tests"
    )


@pytest.fixture
def pg_database() -> Any:
    """Factory creating empty PostgreSQL databases (dropped after the test)."""
    if not PG_ADMIN_URL:
        pytest.skip("set UP2P_TEST_DATABASE_URL to run PostgreSQL tests")
    import uuid

    from sqlalchemy import create_engine
    from sqlalchemy.engine import make_url

    from universal_p2p_sync.storage.database import normalize_database_url

    admin_url = normalize_database_url(PG_ADMIN_URL)
    engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    created: list[str] = []

    def make() -> str:
        name = "up2p_test_" + uuid.uuid4().hex[:12]
        with engine.connect() as conn:
            conn.exec_driver_sql(f'CREATE DATABASE "{name}"')
        created.append(name)
        return make_url(admin_url).set(database=name).render_as_string(hide_password=False)

    yield make
    with engine.connect() as conn:
        for name in created:
            conn.exec_driver_sql(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
    engine.dispose()


@pytest.fixture
async def make_secure_node(tmp_path, pg_database) -> AsyncIterator[Callable[..., Any]]:
    """Factory for secure nodes, each with its own key directory and database."""
    created: list[AsyncSyncNode] = []

    async def factory(
        app_id: str = "echo",
        name: str = "node",
        *,
        database_url: str | None = None,
        data_dir: Any = None,
        start: bool = True,
        **overrides: Any,
    ) -> tuple[AsyncSyncNode, EventRecorder]:
        options: dict[str, Any] = dict(SECURE_DEFAULTS)
        options.update(overrides)
        node = AsyncSyncNode(
            app_id,
            f"user-{name}",
            name,
            database_url=database_url or pg_database(),
            data_dir=str(data_dir or tmp_path / name),
            **options,
        )
        recorder = EventRecorder(node)
        created.append(node)
        if start:
            await node.start()
        return node, recorder

    yield factory
    for node in created:
        await node.stop()


async def connect(a: AsyncSyncNode, b: AsyncSyncNode) -> None:
    assert b.listen_address is not None
    await a.connect("127.0.0.1", b.listen_address[1])
    await wait_until(lambda: any(p.device_id == a.device_id for p in b.peers()))


async def pair(a: AsyncSyncNode, b: AsyncSyncNode) -> None:
    """Connect and pair two nodes, approving the comparison code on both sides."""
    if not any(p.device_id == b.device_id for p in a.peers()):
        await connect(a, b)
    request = await a.request_pairing(b.device_id)
    await wait_until(lambda: any(r.code for r in b.pairing_requests()))
    assert b.pairing_requests()[0].code == request.code
    await a.approve_pairing(b.device_id)
    await b.approve_pairing(a.device_id)
    await wait_until(lambda: a.is_trusted(b.device_id) and b.is_trusted(a.device_id))


async def join(owner: AsyncSyncNode, member: AsyncSyncNode, member_rec: EventRecorder,
               group_id: str, role: str) -> None:
    """Directed invitation from ``owner`` to ``member`` (already paired) and acceptance."""
    before = len(member_rec.of("group_invitation_received"))
    invite = await owner.create_invite(group_id, role, device_id=member.device_id)
    await member_rec.wait_for("group_invitation_received", before + 1)
    await member.accept_invite(invite.id)
    await wait_until(lambda: owner.get_group(group_id).member_count
                     == member.get_group(group_id).member_count)
