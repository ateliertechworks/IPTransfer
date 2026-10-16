"""Section 14 acceptance scenarios, driven through the real example applications.

The Echo and To-Do examples only use the public API, so passing these tests
also shows that both applications work without modifying the library.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

from universal_p2p_sync import HandshakeError, NotFoundError, PermissionDeniedError
from universal_p2p_sync.storage.database import normalize_database_url

from .conftest import SECURE_DEFAULTS

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "examples"))

from echo_app import SHARED_NOTES, EchoApp  # noqa: E402
from todo_app import TodoApp  # noqa: E402

OPTIONS = {k: v for k, v in SECURE_DEFAULTS.items()}


def eventually(predicate, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("condition not met within timeout")
        time.sleep(0.05)


def pair(a, b) -> None:
    """Both users compare the code and approve (what the shell's 'pair' does)."""
    a.sync.connect("127.0.0.1", b.sync.listen_address[1])
    request = a.sync.request_pairing(b.sync.device_id)
    eventually(lambda: any(r.code for r in b.sync.pairing_requests()))
    assert b.sync.pairing_requests()[0].code == request.code
    a.sync.approve_pairing(b.sync.device_id)
    b.sync.approve_pairing(a.sync.device_id)
    eventually(lambda: a.sync.is_trusted(b.sync.device_id) and b.sync.is_trusted(a.sync.device_id))


def wait_invite(app) -> str:
    eventually(lambda: app.sync.list_invites(direction="incoming"))
    return app.sync.list_invites(direction="incoming")[-1].id


@pytest.fixture
def apps(pg_database, tmp_path):
    started = []

    def make(cls, name, url=None, **kw):
        app = cls(name, database_url=url or pg_database(), data_dir=str(tmp_path / name),
                  **{**OPTIONS, **kw})
        app.start()
        started.append(app)
        return app

    yield make
    for app in started:
        app.stop()


def test_scenario_a_echo(apps, pg_database, tmp_path) -> None:
    url_b = pg_database()
    laptop_a = apps(EchoApp, "Laptop A")
    laptop_b = apps(EchoApp, "Laptop B", url=url_b)
    pair(laptop_a, laptop_b)
    team = laptop_a.create_team("Development Team")
    assert team.role == "leader"
    laptop_a.invite(team.id, laptop_b.sync.device_id)
    joined = laptop_b.join(wait_invite(laptop_b))
    assert joined.id == team.id and joined.role == "member"

    laptop_a.chat("what is the deadline?")  # private, never shared
    laptop_a.share_note(team.id, "note_001", "Project update")
    eventually(lambda: (team.id, "note_001") in laptop_b.shared_notes)
    laptop_b.share_note(team.id, "note_001", "Project update - deadline moved")
    eventually(lambda: laptop_a.shared_notes[(team.id, "note_001")]["message"].endswith("moved"))

    laptop_b.stop()  # Laptop B goes offline
    laptop_a.share_note(team.id, "note_002", "Written while B was away")
    laptop_a.delete_note(team.id, "note_001")
    laptop_b2 = apps(EchoApp, "Laptop B", url=url_b)  # restart: reconnects on its own
    eventually(lambda: (team.id, "note_002") in laptop_b2.shared_notes, 20)
    eventually(lambda: (team.id, "note_001") not in laptop_b2.shared_notes)

    engine = create_engine(normalize_database_url(url_b))
    with engine.connect() as conn:
        dump = conn.execute(text(f'SELECT string_agg(body::text, \'\') FROM '
                                 f'"{laptop_b2.sync.schema}".changes')).scalar()
    engine.dispose()
    assert "deadline?" not in dump and laptop_b2.private_history == []
    assert "Project update" not in dump  # stored encrypted, not in plaintext form


def test_scenario_b_todo(apps) -> None:
    office = apps(TodoApp, "Office Laptop")
    home = apps(TodoApp, "Home Laptop")
    stranger = apps(TodoApp, "Stranger")
    pair(office, home)
    ws = office.create_workspace("Workspace")
    assert ws.role == "administrator"
    office.invite(ws.id, home.sync.device_id)
    assert home.join(wait_invite(home)).role == "task_user"

    task = office.add_task(ws.id, "Finish documentation", assignee="todo_user_001")
    eventually(lambda: (ws.id, task) in home.tasks)
    with pytest.raises(PermissionDeniedError):
        home.add_task(ws.id, "Assign me", assignee="someone")
    home.complete_task(ws.id, task)
    eventually(lambda: office.tasks[(ws.id, task)]["completed"] is True)

    # Offline edits on both sides, then reconnection.
    office.sync.disconnect(home.sync.device_id)
    home.sync.disconnect(office.sync.device_id)
    eventually(lambda: not office.sync.peers())
    second = home.add_task(ws.id, "Added offline")
    office.edit_task(ws.id, task, title="Finish documentation v2", completed=False)
    home.edit_task(ws.id, task, title="Finish docs", completed=True)
    home.sync.connect("127.0.0.1", office.sync.listen_address[1])
    eventually(lambda: (ws.id, second) in office.tasks, 20)
    # The app's resolver merged the concurrent edits identically on both laptops.
    eventually(lambda: office.tasks[(ws.id, task)] == home.tasks[(ws.id, task)]
               and office.tasks[(ws.id, task)]["completed"] is True, 20)
    eventually(lambda: not office.sync.list_conflicts(ws.id) and
               not home.sync.list_conflicts(ws.id))
    office.delete_task(ws.id, second)
    eventually(lambda: (ws.id, second) not in home.tasks)

    # Unauthorized users cannot access the workspace, even when connected.
    stranger.sync.connect("127.0.0.1", office.sync.listen_address[1])
    time.sleep(1.5)
    assert stranger.workspaces() == [] and stranger.tasks == {}
    with pytest.raises(NotFoundError):
        stranger.sync.publish(ws.id, "tasks", "x", {"title": "intrusion"})


def test_scenario_c_reusability_and_isolation(apps, pg_database) -> None:
    shared_url = pg_database()  # both apps on one laptop, one PostgreSQL database
    echo = apps(EchoApp, "Laptop", url=shared_url)
    todo = apps(TodoApp, "Laptop", url=shared_url)
    assert echo.sync.schema == "up2p_echo" and todo.sync.schema == "up2p_todo"
    team = echo.create_team("Echo team")
    ws = todo.create_workspace("Todo workspace")
    assert set(team.roles) == {"leader", "member"}
    assert set(ws.roles) == {"administrator", "task_user"}
    echo.share_note(team.id, "n", "echo data")
    todo.add_task(ws.id, "todo data")
    assert [r.collection for r in echo.sync.list_records(team.id)] == [SHARED_NOTES]
    with pytest.raises(NotFoundError):
        todo.sync.list_records(team.id)
    with pytest.raises(NotFoundError):
        echo.sync.list_records(ws.id)
    with pytest.raises(HandshakeError):
        echo.sync.connect("127.0.0.1", todo.sync.listen_address[1])
    other_echo = apps(EchoApp, "Laptop 2")
    with pytest.raises(HandshakeError):
        todo.sync.connect("127.0.0.1", other_echo.sync.listen_address[1])
