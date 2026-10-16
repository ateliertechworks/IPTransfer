"""Echo - a (tiny) desktop chatbot that shares selected notes with its team.

This example shows how a real application embeds universal-p2p-sync:

* Echo's **private** data (the chat history with the bot) never leaves the
  device: it is kept by Echo itself and is never published.
* Notes the user explicitly shares go to the team through ``sync.publish``.
  They are encrypted, signed, stored in the local PostgreSQL database and sent
  to the team members' devices, immediately or when they come back online.
* Remote changes arrive as ``record_*`` events. Echo updates its own model
  (``self.shared_notes``) and refreshes the UI from the event handler, which
  the SDK runs on the UI thread through ``callback_dispatcher``.
* Echo defines its own roles: a *leader* manages the team and invites
  members; *members* read and write shared notes.

Run on two laptops on the same Wi-Fi (each with its own local PostgreSQL):

    export UP2P_ECHO_DATABASE_URL=postgresql+psycopg://echo:secret@localhost/echo_sync
    python examples/echo_app.py --name "Laptop A"
    python examples/echo_app.py --name "Laptop B"

then follow docs/echo-integration.md.
"""

from __future__ import annotations

import argparse
import datetime
import logging
from collections.abc import Callable
from typing import Any

from common import SHARED_HELP, PeerCommands, UiLoop, common_arguments, parse_hostport, run_shell

from universal_p2p_sync import Event, Group, SyncNode

APP_ID = "echo"
SHARED_NOTES = "shared_chat_notes"
#: Echo's own role model; the library has no built-in notion of "leader".
ROLES = {
    "leader": ["group.manage", "member.invite", "member.remove", "member.role",
               "data.read", "data.write"],
    "member": ["data.read", "data.write"],
}


class EchoApp:
    """Echo's application model. The UI (shell or GUI) calls these methods."""

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
            user_id or f"echo_{name.lower().replace(' ', '_')}",
            name,
            database_url=database_url,
            data_dir=data_dir,
            roles=ROLES,
            owner_role="leader",
            callback_dispatcher=callback_dispatcher,
            **node_options,
        )
        self.on_change = on_change
        #: Private, local-only chat history (never published).
        self.private_history: list[tuple[str, str]] = []
        #: Echo's view of the team's shared notes: (team_id, note_id) -> note.
        self.shared_notes: dict[tuple[str, str], dict[str, Any]] = {}
        self.sync.on("record_received", self._remote_note)
        self.sync.on("record_updated", self._remote_note)
        self.sync.on("record_deleted", self._remote_note)
        self.sync.on("conflict_detected", lambda e: self.on_change(
            f"[conflict] note {e['record_id']} was edited on two devices; showing the newest"))

    # -- lifecycle
    def start(self) -> None:
        self.sync.start()
        for team in self.teams():  # load what was synchronized earlier
            for record in self.sync.list_records(team.id, SHARED_NOTES):
                self.shared_notes[(team.id, record.record_id)] = record.data or {}

    def stop(self) -> None:
        self.sync.stop()

    # -- private chatbot (local only)
    def chat(self, text: str) -> str:
        reply = f"Echo: {text}" if not text.endswith("?") else "Echo: good question!"
        self.private_history.append((text, reply))
        return reply

    # -- teams
    def create_team(self, name: str) -> Group:
        return self.sync.create_group(name)

    def teams(self) -> list[Group]:
        return self.sync.list_groups()

    def invite(self, team_id: str, device_id: str, role: str = "member") -> str:
        return self.sync.create_invite(team_id, role, device_id=device_id).id

    def join(self, invite: str) -> Group:
        return self.sync.accept_invite(invite)

    # -- shared notes
    def share_note(self, team_id: str, note_id: str, message: str) -> None:
        note = {
            "message": message,
            "author": self.sync.user_id,
            "saved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        self.sync.publish(team_id, SHARED_NOTES, note_id, note)
        self.shared_notes[(team_id, note_id)] = note

    def share_last_answer(self, team_id: str, note_id: str) -> None:
        """Explicitly share one private exchange as a team note."""
        question, answer = self.private_history[-1]
        self.share_note(team_id, note_id, f"Q: {question}\nA: {answer}")

    def delete_note(self, team_id: str, note_id: str) -> None:
        self.sync.delete(team_id, SHARED_NOTES, note_id)
        self.shared_notes.pop((team_id, note_id), None)

    # -- remote changes -> Echo's model and UI
    def _remote_note(self, event: Event) -> None:
        if event["collection"] != SHARED_NOTES:
            return
        key = (event["group_id"], event["record_id"])
        if event.name == "record_deleted":
            self.shared_notes.pop(key, None)
            self.on_change(f"[note] {event['record_id']} deleted by a team member")
        else:
            self.shared_notes[key] = dict(event["data"])
            self.on_change(f"[note] {event['record_id']}: {event['data']['message']}")


HELP = f"""Echo commands:
  chat TEXT             talk to the bot (stays on this device)
  team NAME             create a team (you become its leader)
  teams                 list teams                  use N               select team N
  invite N [ROLE]       invite peer N (role: member or leader)
  members               list team members
  note ID TEXT          save/update a shared note   share ID            share last bot answer
  notes                 list shared notes           delete ID           delete a note
  status                synchronization status
{SHARED_HELP}"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    common_arguments(parser, APP_ID, 47801)
    args = parser.parse_args()
    if not args.database_url:
        raise SystemExit("set UP2P_ECHO_DATABASE_URL or pass --database-url")
    logging.basicConfig(level=logging.WARNING)
    ui = UiLoop()
    app = EchoApp(
        args.name, database_url=args.database_url, user_id=args.user, data_dir=args.data_dir,
        callback_dispatcher=ui.dispatch, on_change=print,
        listen_host=args.host, listen_port=args.port, enable_discovery=not args.no_discovery,
    )
    app.start()
    for value in args.connect:
        app.sync.add_peer_address(*parse_hostport(value))
    peers = PeerCommands(app.sync, print)
    current: dict[str, str | None] = {"team": app.teams()[0].id if app.teams() else None}

    def team() -> str:
        if current["team"] is None:
            teams = app.teams()
            if not teams:
                raise ValueError("create or join a team first")
            current["team"] = teams[0].id
        return current["team"]

    def handle(cmd: str, arg: str) -> bool:
        if cmd == "chat":
            print(app.chat(arg))
        elif cmd == "team":
            current["team"] = app.create_team(arg or "My team").id
            print("team created; you are its leader")
        elif cmd == "teams":
            for i, g in enumerate(app.teams(), 1):
                mark = "*" if g.id == current["team"] else " "
                print(f" {mark}{i}. {g.name} ({g.member_count} members, you: {g.role})")
        elif cmd == "use":
            current["team"] = app.teams()[int(arg) - 1].id
        elif cmd == "invite":
            index, _, role = arg.partition(" ")
            peer = peers.peer_by_index(index)
            app.invite(team(), peer.device_id, role or "member")
            print(f"invitation sent to {peer.device_name}")
        elif cmd == "members":
            for m in app.sync.list_members(team()):
                print(f"  {m.device_name} ({m.user_id}) {m.role}{' online' if m.connected else ''}")
        elif cmd == "note":
            note_id, _, text = arg.partition(" ")
            app.share_note(team(), note_id, text)
        elif cmd == "share":
            app.share_last_answer(team(), arg)
        elif cmd == "notes":
            for (gid, nid), note in sorted(app.shared_notes.items()):
                if gid == current["team"]:
                    print(f"  {nid}: {note['message']}  ({note['author']})")
        elif cmd == "delete":
            app.delete_note(team(), arg)
        elif cmd == "status":
            s = app.sync.get_sync_status(team())
            print(f"  changes {s.total_changes}, waiting for ack {s.pending_changes}, "
                  f"conflicts {s.open_conflicts}")
            for p in s.peers:
                print(f"  {p.device_name}: {'online' if p.connected else 'offline'}, "
                      f"{p.pending_changes} change(s) not yet delivered")
        else:
            return False
        return True

    try:
        print(f"Echo on port {app.sync.listen_address[1]} - device {app.sync.fingerprint}")
        run_shell(app.sync, ui, peers, handle, HELP)
    finally:
        app.stop()


if __name__ == "__main__":
    main()
