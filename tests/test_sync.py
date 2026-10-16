"""Milestone 4: PostgreSQL-backed record synchronization."""

from __future__ import annotations

import asyncio
import queue
import threading
import time

import pytest
from sqlalchemy import create_engine, text

from universal_p2p_sync import DELETE, StorageError, SyncNode, enqueue_change
from universal_p2p_sync.storage.database import Database, normalize_database_url, run_migrations

from .conftest import SECURE_DEFAULTS, connect, join, pair, wait_until

TODO_ROLES = {
    "administrator": ["group.manage", "member.invite", "member.remove", "member.role",
                      "data.read", "data.write", "task.assign"],
    "task_user": ["data.read", "data.write"],
}


async def team(make_secure_node, n: int = 2, app: str = "echo", **kw):
    nodes = [await make_secure_node(app, f"{app}{i}", **kw) for i in range(n)]
    (owner, _) = nodes[0]
    group = await owner.create_group("Team")
    for node, rec in nodes[1:]:
        await pair(owner, node)
        role = "task_user" if app == "todo" and "roles" in kw else "member"
        await join(owner, node, rec, group.id, role)
    return group, nodes


async def go_offline(a, b) -> None:
    await a.disconnect(b.device_id)
    await b.disconnect(a.device_id)
    await wait_until(lambda: not any(p.device_id == b.device_id for p in a.peers()))


async def data_of(node, group_id, collection, record_id):
    record = await node.get_record(group_id, collection, record_id)
    return None if record is None else record.data


# ---------------------------------------------------------------- basic synchronization


async def test_echo_records_synchronize_both_ways(make_secure_node) -> None:
    group, [(a, ra), (b, rb)] = await team(make_secure_node)
    await a.publish(group.id, "shared_notes", "note_001",
                    {"title": "Meeting", "content": "Tomorrow at 10 AM"})
    event = (await rb.wait_for("record_received"))[0]
    assert event["collection"] == "shared_notes" and event["record_id"] == "note_001"
    assert event["data"]["content"] == "Tomorrow at 10 AM"
    assert event["author_device_id"] == a.device_id and event["author_user_id"] == "user-echo0"
    await b.publish(group.id, "shared_notes", "note_001",
                    {"title": "Meeting", "content": "Tomorrow at 11 AM"})
    updated = (await ra.wait_for("record_updated"))[0]
    assert updated["data"]["content"] == "Tomorrow at 11 AM"
    assert ra.of("record_received") == []  # own writes never come back as events
    assert (await a.get_record(group.id, "shared_notes", "note_001")).version == (
        await b.get_record(group.id, "shared_notes", "note_001")).version


async def test_todo_task_lifecycle(make_secure_node) -> None:
    group, [(a, ra), (b, rb)] = await team(make_secure_node, app="todo", roles=TODO_ROLES)
    assert a.get_group(group.id).role == "administrator"
    assert b.get_group(group.id).role == "task_user"
    assert a.has_permission(group.id, "task.assign")
    assert not b.has_permission(group.id, "task.assign")
    await a.publish(group.id, "tasks", "task_001", {"title": "Finish docs", "completed": False})
    await rb.wait_for("record_received")
    await b.publish(group.id, "tasks", "task_001", {"title": "Finish docs", "completed": True})
    await ra.wait_for("record_updated")
    assert (await data_of(a, group.id, "tasks", "task_001"))["completed"] is True
    await a.delete(group.id, "tasks", "task_001")
    deleted = (await rb.wait_for("record_deleted"))[0]
    assert deleted["deleted"] is True and deleted["data"] is None
    assert await b.get_record(group.id, "tasks", "task_001") is None
    tomb = await b.get_record(group.id, "tasks", "task_001", include_deleted=True)
    assert tomb.deleted


async def test_echo_and_todo_are_isolated_in_one_database(make_secure_node, pg_database) -> None:
    url = pg_database()
    echo, _ = await make_secure_node("echo", "e", database_url=url)
    todo, _ = await make_secure_node("todo", "t", database_url=url)
    assert echo.schema != todo.schema
    team_ = await echo.create_group("Echo team")
    await echo.publish(team_.id, "shared_chat_notes", "n", {"m": "hi"})
    from universal_p2p_sync import HandshakeError, NotFoundError

    with pytest.raises(HandshakeError) as info:
        await echo.connect("127.0.0.1", todo.listen_address[1])
    assert info.value.code == "app_mismatch"
    with pytest.raises(NotFoundError):
        await todo.publish(team_.id, "tasks", "x", {})
    engine = create_engine(normalize_database_url(url))
    with engine.connect() as conn:
        assert conn.execute(text(f'SELECT count(*) FROM "{todo.schema}".changes')).scalar() == 0
        assert conn.execute(text(f'SELECT count(*) FROM "{echo.schema}".changes')).scalar() == 1
    engine.dispose()


async def test_private_data_stays_local(make_secure_node) -> None:
    group, [(a, _), (b, rb)] = await team(make_secure_node)
    private = await a.create_group("Only me")
    await a.publish(private.id, "private_chats", "c1", {"text": "secret"})
    await a.publish(group.id, "shared_notes", "n1", {"text": "shared"})
    await rb.wait_for("record_received")
    await asyncio.sleep(1.5)
    assert [r.record_id for r in await b.list_records(group.id)] == ["n1"]
    assert [g.id for g in b.list_groups()] == [group.id]


# ---------------------------------------------------------------- offline and recovery


async def test_offline_changes_synchronize_after_reconnection(make_secure_node) -> None:
    group, [(a, ra), (b, rb)] = await team(make_secure_node)
    await go_offline(a, b)
    for i in range(5):
        await a.publish(group.id, "notes", f"a{i}", {"i": i})
    await b.publish(group.id, "notes", "b0", {"offline": True})
    status = await a.get_sync_status(group.id)
    assert status.pending_changes == 5 and status.peers[0].connected is False
    await connect(b, a)
    await wait_until(lambda: len(rb.of("record_received")) >= 5 and ra.of("record_received"))
    await rb.wait_for("sync_completed")
    assert len(await b.list_records(group.id)) == len(await a.list_records(group.id)) == 6
    await wait_until(lambda: True)
    status = await a.get_sync_status(group.id)
    await wait_until(lambda: True)
    assert status.total_changes == 6 and status.local_changes == 5


async def test_pending_changes_survive_restart(make_secure_node, tmp_path, pg_database) -> None:
    url = pg_database()
    group, [(a, _), (b, rb)] = await team(make_secure_node)
    c, rc = await make_secure_node("echo", "c", database_url=url, data_dir=tmp_path / "c")
    await pair(a, c)
    await join(a, c, rc, group.id, "member")
    await go_offline(a, b)
    await c.publish(group.id, "notes", "from-c", {"queued": True})
    await c.stop()
    await go_offline(a, c) if any(p.device_id == c.device_id for p in a.peers()) else None
    await wait_until(lambda: not any(p.device_id == c.device_id for p in a.peers()))
    c2, rc2 = await make_secure_node("echo", "c", database_url=url, data_dir=tmp_path / "c")
    assert (await c2.get_sync_status(group.id)).local_changes == 1
    await connect(c2, b)  # b never paired with c; the group authorizes them
    await wait_until(lambda: any(e["record_id"] == "from-c" for e in rb.of("record_received")))


async def test_duplicates_and_replays_are_ignored(make_secure_node) -> None:
    group, [(a, _), (b, rb)] = await team(make_secure_node)
    await a.publish(group.id, "notes", "n", {"v": 1})
    await rb.wait_for("record_received")
    wires = await a._tx(lambda c, e: a._store.changes_after(c, group.id, {}))
    for _ in range(3):
        await a._push(group.id, wires, exclude=None)
        await a._connections.send(
            b.device_id, {"type": "group_ops", "group_id": group.id,
                          "ops": await a._tx(lambda c, e: a._groups.wire_ops(c, group.id, set()))})
    await asyncio.sleep(0.5)
    assert len(rb.of("record_received")) == 1 and rb.of("record_updated") == []
    status = await b.get_sync_status(group.id)
    assert status.total_changes == 1


async def test_deletions_synchronize_and_never_reappear(make_secure_node) -> None:
    group, [(a, ra), (b, rb)] = await team(make_secure_node)
    await a.publish(group.id, "notes", "n", {"v": 1})
    await rb.wait_for("record_received")
    await go_offline(a, b)
    await a.delete(group.id, "notes", "n")
    await connect(b, a)
    await rb.wait_for("record_deleted")
    await b.sync_now(group.id)
    await rb.wait_for("sync_completed", 2)
    assert await b.get_record(group.id, "notes", "n") is None
    assert await a.get_record(group.id, "notes", "n") is None


async def test_interrupted_transfer_resumes_without_duplicates(make_secure_node) -> None:
    small = dict(max_frame_size=8192, max_record_size=2048)
    group, [(a, _), (b, rb)] = await team(make_secure_node, **small)
    await go_offline(a, b)
    for i in range(60):
        await a.publish(group.id, "notes", f"r{i:03}", {"text": "x" * 500, "i": i})
    progress = asyncio.Event()
    b.on("sync_progress", lambda e: progress.set())
    await connect(b, a)
    await asyncio.wait_for(progress.wait(), 10)
    await go_offline(a, b)  # cut the transfer
    partial = len(await b.list_records(group.id))
    await connect(b, a)
    await wait_until(lambda: len(rb.of("record_received")) >= 60, 20)
    assert len(await b.list_records(group.id)) == 60
    assert (await b.get_sync_status(group.id)).total_changes == 60
    assert partial <= 60


# ---------------------------------------------------------------- conflicts


async def test_concurrent_edits_are_detected_and_resolved(make_secure_node) -> None:
    group, [(a, ra), (b, rb)] = await team(make_secure_node)
    await a.publish(group.id, "notes", "n", {"text": "base"})
    await rb.wait_for("record_received")
    await go_offline(a, b)
    await a.publish(group.id, "notes", "n", {"text": "from a"})
    await b.publish(group.id, "notes", "n", {"text": "from b"})
    await connect(b, a)
    ca = (await ra.wait_for("conflict_detected"))[0]
    cb = (await rb.wait_for("conflict_detected"))[0]
    assert ca["conflict_id"] == cb["conflict_id"] and ca["winner"] == cb["winner"]
    assert {v["data"]["text"] for v in ca["versions"]} == {"from a", "from b"}
    rec_a, rec_b = (await a.get_record(group.id, "notes", "n"),
                    await b.get_record(group.id, "notes", "n"))
    assert rec_a.in_conflict and rec_a.data == rec_b.data  # same deterministic winner
    conflicts = await a.list_conflicts(group.id)
    assert len(conflicts) == 1 and len(conflicts[0].versions) == 2
    await a.resolve_conflict(conflicts[0].id, {"text": "merged"})
    await rb.wait_for("conflict_resolved")
    await wait_until(lambda: True)
    assert (await data_of(b, group.id, "notes", "n")) == {"text": "merged"}
    assert not (await b.get_record(group.id, "notes", "n")).in_conflict
    assert await a.list_conflicts(group.id) == []
    assert len(await a.list_conflicts(group.id, status=None)) == 1


async def test_update_beats_concurrent_delete_and_resolvers_merge(make_secure_node) -> None:
    group, [(a, ra), (b, rb)] = await team(make_secure_node, app="todo")
    for node in (a, b):
        node.register_conflict_resolver(
            "tasks",
            lambda c: {"title": max(v.data["title"] for v in c.versions if v.data),
                       "completed": any(v.data and v.data["completed"] for v in c.versions)},
        )
    await a.publish(group.id, "notes", "d", {"v": 1})
    await a.publish(group.id, "tasks", "t", {"title": "a", "completed": False})
    await rb.wait_for("record_received", 2)
    await go_offline(a, b)
    await a.delete(group.id, "notes", "d")
    await b.publish(group.id, "notes", "d", {"v": 2})
    await a.publish(group.id, "tasks", "t", {"title": "b", "completed": False})
    await b.publish(group.id, "tasks", "t", {"title": "a", "completed": True})
    await connect(b, a)
    await wait_until(lambda: len(ra.of("conflict_resolved")) >= 1 and
                     len(rb.of("conflict_resolved")) >= 1, 15)
    await asyncio.sleep(1.5)
    for node in (a, b):
        assert await data_of(node, group.id, "notes", "d") == {"v": 2}  # put wins over delete
        assert await data_of(node, group.id, "tasks", "t") == {"title": "b", "completed": True}
    # The resolver may run on both devices; equal results never conflict again.
    assert not (await a.get_record(group.id, "tasks", "t")).in_conflict


async def test_resolving_by_deletion(make_secure_node) -> None:
    group, [(a, ra), (b, rb)] = await team(make_secure_node)
    await a.publish(group.id, "notes", "n", {"v": 0})
    await rb.wait_for("record_received")
    await go_offline(a, b)
    await a.publish(group.id, "notes", "n", {"v": 1})
    await b.publish(group.id, "notes", "n", {"v": 2})
    await connect(b, a)
    await ra.wait_for("conflict_detected")
    conflict = (await a.list_conflicts(group.id))[0]
    await a.resolve_conflict(conflict.id, DELETE)
    await rb.wait_for("record_deleted")


# ---------------------------------------------------------------- PostgreSQL integration


async def test_transactional_outbox(make_secure_node, pg_database) -> None:
    url = pg_database()
    group, [(a, _), (b, rb)] = await team(make_secure_node)
    a2_url = a.config.database_url
    engine = create_engine(normalize_database_url(a2_url))
    with engine.begin() as conn:  # the application's own transaction
        conn.execute(text("CREATE TABLE app_notes (id text primary key, body text)"))
        conn.execute(text("INSERT INTO app_notes VALUES ('o1', 'hello')"))
        enqueue_change(conn, schema=a.schema, group_id=group.id, collection="notes",
                       record_id="o1", data={"body": "hello"})
    with pytest.raises(RuntimeError):
        with engine.begin() as conn:
            enqueue_change(conn, schema=a.schema, group_id=group.id, collection="notes",
                           record_id="rolled-back", data={"x": 1})
            raise RuntimeError("application error -> rollback")
    with engine.begin() as conn:
        enqueue_change(conn, schema=a.schema, group_id="f" * 32, collection="notes",
                       record_id="bad-group", data={"x": 1})
    a.notify_outbox()
    await rb.wait_for("record_received")
    failures = [e for e in await _events(a, "sync_failed") if e.get("outbox_id")]
    assert failures and "bad-group" == failures[0]["record_id"]
    assert await data_of(b, group.id, "notes", "o1") == {"body": "hello"}
    assert await b.get_record(group.id, "notes", "rolled-back") is None
    assert (await a.get_sync_status(group.id)).outbox_pending == 0
    engine.dispose()
    assert url


async def _events(node, name):
    recorder = next(h.__self__ for h in node.events._handlers.get("*", []))
    await wait_until(lambda: recorder.of(name), 5)
    return recorder.of(name)


class NotesAdapter:
    def __init__(self) -> None:
        self.fail = False

    def apply(self, conn, event, payload) -> None:
        if self.fail:
            raise RuntimeError("application table unavailable")
        if event == "record_deleted":
            conn.execute(text("DELETE FROM app_notes WHERE id = :i"), {"i": payload["record_id"]})
        else:
            conn.execute(
                text("INSERT INTO app_notes VALUES (:i, :b) "
                     "ON CONFLICT (id) DO UPDATE SET body = excluded.body"),
                {"i": payload["record_id"], "b": payload["data"]["body"]},
            )


async def test_adapter_applies_in_the_same_transaction(make_secure_node) -> None:
    group, [(a, _), (b, rb)] = await team(make_secure_node)
    engine = create_engine(normalize_database_url(b.config.database_url))
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE app_notes (id text primary key, body text)"))
    adapter = NotesAdapter()
    b.register_adapter("notes", adapter)
    adapter.fail = True
    await a.publish(group.id, "notes", "n1", {"body": "v1"})
    await asyncio.sleep(1.0)
    # The failed adapter rolled back the whole sync transaction.
    assert await b.get_record(group.id, "notes", "n1") is None
    adapter.fail = False
    await b.sync_now(group.id)
    await rb.wait_for("record_received")
    with engine.connect() as conn:
        assert conn.execute(text("SELECT body FROM app_notes WHERE id='n1'")).scalar() == "v1"
    await a.delete(group.id, "notes", "n1")
    await rb.wait_for("record_deleted")
    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM app_notes")).scalar() == 0
    engine.dispose()


def test_migrations_upgrade_downgrade_and_version_check(pg_database, tmp_path) -> None:
    from alembic import command
    from alembic.config import Config

    from universal_p2p_sync.storage.database import MIGRATIONS_DIR

    url = pg_database()
    db = Database(url, "up2p_migtest")
    with pytest.raises(StorageError, match="not initialized"):
        db.open(migrate=False, device_id="d" * 64)
    db = Database(url, "up2p_migtest")
    db.open(migrate=True, device_id="d" * 64)
    other = Database(url, "up2p_migtest")
    with pytest.raises(StorageError, match="another running node"):
        other.open(migrate=False, device_id="d" * 64)
    db.close()
    wrong_owner = Database(url, "up2p_migtest")
    with pytest.raises(StorageError, match="belongs to device"):
        wrong_owner.open(migrate=True, device_id="e" * 64)
    engine = create_engine(normalize_database_url(url))
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.attributes["schema"] = "up2p_migtest"
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.downgrade(cfg, "base")
    with engine.connect() as conn:
        assert conn.execute(text("SELECT to_regclass('up2p_migtest.changes')")).scalar() is None
    run_migrations(engine, "up2p_migtest")
    run_migrations(engine, "up2p_migtest")  # idempotent
    with engine.connect() as conn:
        assert conn.execute(text("SELECT to_regclass('up2p_migtest.changes')")).scalar()
    engine.dispose()


def test_cli_db_upgrade(pg_database, tmp_path) -> None:
    from universal_p2p_sync.__main__ import main

    url = pg_database()
    assert main(["db-upgrade", "--app-id", "echo", "--database-url", url]) == 0
    assert main(["identity", "--app-id", "echo", "--data-dir", str(tmp_path)]) == 0


def test_gui_dispatcher_and_blocking_api(pg_database, tmp_path) -> None:
    ui_queue: queue.Queue = queue.Queue()
    options = dict(SECURE_DEFAULTS)
    a = SyncNode("echo", "ua", "A", database_url=pg_database(), data_dir=str(tmp_path / "a"),
                 callback_dispatcher=ui_queue.put, **options)
    b = SyncNode("echo", "ub", "B", database_url=pg_database(), data_dir=str(tmp_path / "b"),
                 **options)
    seen: list[tuple[str, str]] = []
    a.on("record_received", lambda e: seen.append((threading.current_thread().name,
                                                   e["record_id"])))
    a.start()
    b.start()
    try:
        b.connect("127.0.0.1", a.listen_address[1])
        b.request_pairing(a.device_id)
        deadline = time.time() + 10
        while not a.pairing_requests() and time.time() < deadline:
            time.sleep(0.05)
        a.approve_pairing(b.device_id)
        b.approve_pairing(a.device_id)
        assert b.wait_for_pairing(a.device_id, 10) is True
        group = b.create_group("Team")
        invite = b.create_invite(group.id, "member")
        a.accept_invite(invite.token)
        b.publish(group.id, "notes", "gui", {"x": 1})
        fn = ui_queue.get(timeout=10)
        while True:
            fn()  # the "UI thread" (this test's main thread) runs the handler
            if seen:
                break
            fn = ui_queue.get(timeout=10)
        assert seen == [(threading.current_thread().name, "gui")]
        assert a.get_sync_status(group.id).total_changes == 1
    finally:
        a.stop()
        b.stop()


async def test_secure_shutdown_and_reconnection(make_secure_node, tmp_path, pg_database) -> None:
    url = pg_database()
    group, [(a, ra), (b, rb)] = await team(make_secure_node)
    a.add_peer_address("127.0.0.1", b.listen_address[1])
    # Kill the connection: the persistent address reconnects and catches up.
    await b._connections.disconnect(a.device_id)
    await a.publish(group.id, "notes", "during-outage", {"v": 1})
    await wait_until(lambda: any(e["record_id"] == "during-outage"
                                 for e in rb.of("record_received")), 15)
    await b.stop()
    await ra.wait_for("peer_disconnected")
    assert not b.is_running and b._db is None
    # The schema lock is released: the same database can be opened again.
    b2, _ = await make_secure_node("echo", "echo1", database_url=b.config.database_url,
                                   data_dir=tmp_path / "echo1")
    assert (await b2.get_record(group.id, "notes", "during-outage")).data == {"v": 1}
    assert url


async def test_three_members_relay_through_each_other(make_secure_node) -> None:
    group, [(a, _), (b, rb), (c, rc)] = await team(make_secure_node, 3)
    await connect(b, c)
    await go_offline(a, c)
    await a.publish(group.id, "notes", "relay", {"via": "b"})
    await rc.wait_for("record_received")
    assert await data_of(c, group.id, "notes", "relay") == {"via": "b"}
