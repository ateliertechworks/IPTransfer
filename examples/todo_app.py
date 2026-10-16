"""To-Do - a shared task list built on universal-p2p-sync.

What this example demonstrates (without changing the library):

* Its own application ID (``todo``), so it never sees Echo's devices or data.
* Its own role model: an *administrator* manages the workspace, invites users
  and may assign tasks (an application-defined permission, ``task.assign``,
  checked with ``sync.has_permission``); a *task user* reads and edits tasks.
* Task creation, update, completion and deletion synchronized automatically,
  including edits made while a laptop was offline.
* A conflict resolver: if two people edit the same task while disconnected,
  the task counts as completed if either of them completed it, and the newer
  title wins. The library calls the resolver; the app never sees a half-merge.

    export UP2P_TODO_DATABASE_URL=postgresql+psycopg://todo:secret@localhost/todo_sync
    python examples/todo_app.py --name "Office Laptop"

See docs/todo-integration.md for a two-laptop walkthrough.
"""

from __future__ import annotations

import argparse
import logging
import uuid
from collections.abc import Callable
from typing import Any

from common import SHARED_HELP, PeerCommands, UiLoop, common_arguments, parse_hostport, run_shell

from universal_p2p_sync import Conflict, Event, Group, PermissionDeniedError, SyncNode

APP_ID = "todo"
TASKS = "tasks"
ROLES = {
    "administrator": ["group.manage", "member.invite", "member.remove", "member.role",
                      "data.read", "data.write", "task.assign"],
    "task_user": ["data.read", "data.write"],
}


def merge_tasks(conflict: Conflict) -> dict[str, Any] | None:
    """Conflict resolver: completed if anyone completed it; the newest title wins."""
    versions = [v for v in conflict.versions if v.data is not None]
    if not versions:
        return None  # only deletions: keep the default (deleted)
    newest = max(versions, key=lambda v: v.timestamp_ms)
    merged = dict(newest.data)
    merged["completed"] = any(v.data.get("completed") for v in versions)
    return merged


class TodoApp:
    def __init__(
        self,
        name: str,
        *,
        database_url: str,
        user_id: str | None = None,
        data_dir: str | None = None,
        callback_dispatcher: Callable[[Callable[[], None]], Any] | None = None,
        on_change: Callable[[str], None] = lambda message: None,
        **node_options: Any,
    ) -> None:
        self.sync = SyncNode(
            APP_ID,
            user_id or f"todo_{name.lower().replace(' ', '_')}",
            name,
            database_url=database_url,
            data_dir=data_dir,
            roles=ROLES,
            owner_role="administrator",
            callback_dispatcher=callback_dispatcher,
            **node_options,
        )
        self.on_change = on_change
        #: The UI model: (workspace_id, task_id) -> task.
        self.tasks: dict[tuple[str, str], dict[str, Any]] = {}
        self.sync.register_conflict_resolver(TASKS, merge_tasks)
        for name_ in ("record_received", "record_updated", "record_deleted"):
            self.sync.on(name_, self._remote_task)
        self.sync.on("conflict_resolved", self._remote_task)

    def start(self) -> None:
        self.sync.start()
        for ws in self.workspaces():
            for record in self.sync.list_records(ws.id, TASKS):
                self.tasks[(ws.id, record.record_id)] = record.data or {}

    def stop(self) -> None:
        self.sync.stop()

    # -- workspaces
    def create_workspace(self, name: str) -> Group:
        return self.sync.create_group(name)

    def workspaces(self) -> list[Group]:
        return self.sync.list_groups()

    def invite(self, workspace_id: str, device_id: str, role: str = "task_user") -> str:
        return self.sync.create_invite(workspace_id, role, device_id=device_id).id

    def join(self, invite: str) -> Group:
        return self.sync.accept_invite(invite)

    # -- tasks
    def add_task(self, workspace_id: str, title: str, assignee: str | None = None) -> str:
        if assignee is not None and not self.sync.has_permission(workspace_id, "task.assign"):
            raise PermissionDeniedError("only administrators can assign tasks")
        task_id = uuid.uuid4().hex[:8]
        self._save(workspace_id, task_id, {"title": title, "completed": False,
                                           "assignee": assignee})
        return task_id

    def edit_task(self, workspace_id: str, task_id: str, **changes: Any) -> None:
        task = dict(self.tasks[(workspace_id, task_id)])
        task.update(changes)
        self._save(workspace_id, task_id, task)

    def complete_task(self, workspace_id: str, task_id: str) -> None:
        self.edit_task(workspace_id, task_id, completed=True)

    def delete_task(self, workspace_id: str, task_id: str) -> None:
        self.sync.delete(workspace_id, TASKS, task_id)
        self.tasks.pop((workspace_id, task_id), None)

    def _save(self, workspace_id: str, task_id: str, task: dict[str, Any]) -> None:
        self.sync.publish(workspace_id, TASKS, task_id, task)
        self.tasks[(workspace_id, task_id)] = task

    # -- remote changes -> model and UI
    def _remote_task(self, event: Event) -> None:
        if event["collection"] != TASKS:
            return
        key = (event["group_id"], event["record_id"])
        if event["deleted"]:
            self.tasks.pop(key, None)
        else:
            self.tasks[key] = dict(event["data"])
        self.on_change(f"[tasks] {event.name.replace('_', ' ')}: {event['record_id']}")


HELP = f"""To-Do commands:
  workspace NAME        create a workspace (you become administrator)
  workspaces            list workspaces             use N               select workspace N
  invite N [ROLE]       invite peer N (role: task_user or administrator)
  add TITLE             add a task                  done ID             complete a task
  edit ID TITLE         rename a task               rm ID               delete a task
  tasks                 list tasks                  status              sync status
{SHARED_HELP}"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    common_arguments(parser, APP_ID, 47802)
    args = parser.parse_args()
    if not args.database_url:
        raise SystemExit("set UP2P_TODO_DATABASE_URL or pass --database-url")
    logging.basicConfig(level=logging.WARNING)
    ui = UiLoop()
    app = TodoApp(
        args.name, database_url=args.database_url, user_id=args.user, data_dir=args.data_dir,
        callback_dispatcher=ui.dispatch, on_change=print,
        listen_host=args.host, listen_port=args.port, enable_discovery=not args.no_discovery,
    )
    app.start()
    for value in args.connect:
        app.sync.add_peer_address(*parse_hostport(value))
    peers = PeerCommands(app.sync, print)
    current: dict[str, str | None] = {"ws": app.workspaces()[0].id if app.workspaces() else None}

    def ws() -> str:
        if current["ws"] is None:
            spaces = app.workspaces()
            if not spaces:
                raise ValueError("create or join a workspace first")
            current["ws"] = spaces[0].id
        return current["ws"]

    def handle(cmd: str, arg: str) -> bool:
        if cmd == "workspace":
            current["ws"] = app.create_workspace(arg or "Workspace").id
            print("workspace created; you are its administrator")
        elif cmd == "workspaces":
            for i, g in enumerate(app.workspaces(), 1):
                print(f" {'*' if g.id == current['ws'] else ' '}{i}. {g.name} (you: {g.role})")
        elif cmd == "use":
            current["ws"] = app.workspaces()[int(arg) - 1].id
        elif cmd == "invite":
            index, _, role = arg.partition(" ")
            peer = peers.peer_by_index(index)
            app.invite(ws(), peer.device_id, role or "task_user")
            print(f"invitation sent to {peer.device_name}")
        elif cmd == "add":
            print(f"task {app.add_task(ws(), arg)} added")
        elif cmd == "done":
            app.complete_task(ws(), arg)
        elif cmd == "edit":
            task_id, _, title = arg.partition(" ")
            app.edit_task(ws(), task_id, title=title)
        elif cmd == "rm":
            app.delete_task(ws(), arg)
        elif cmd == "tasks":
            for (gid, tid), task in sorted(app.tasks.items()):
                if gid == current["ws"]:
                    print(f"  [{'x' if task.get('completed') else ' '}] {tid} {task['title']}")
        elif cmd == "status":
            s = app.sync.get_sync_status(ws())
            print(f"  changes {s.total_changes}, waiting for ack {s.pending_changes}")
            for p in s.peers:
                print(f"  {p.device_name}: {'online' if p.connected else 'offline'}")
        else:
            return False
        return True

    try:
        print(f"To-Do on port {app.sync.listen_address[1]} - device {app.sync.fingerprint}")
        run_shell(app.sync, ui, peers, handle, HELP)
    finally:
        app.stop()


if __name__ == "__main__":
    main()
