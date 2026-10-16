"""Shared helpers for the Echo and To-Do example shells.

These helpers are only about the *example* user interface (a line-based
shell). Everything about networking, security, groups and synchronization is
done by ``universal_p2p_sync``; the examples never touch its internals.
"""

from __future__ import annotations

import argparse
import os
import queue
import threading
from collections.abc import Callable
from typing import Any

from universal_p2p_sync import P2PSyncError, SyncNode


def common_arguments(parser: argparse.ArgumentParser, app_id: str, default_port: int) -> None:
    parser.add_argument("--name", required=True, help="device name shown to other users")
    parser.add_argument("--user", default=None, help="application user id (label only)")
    parser.add_argument(
        "--database-url",
        default=os.environ.get(f"UP2P_{app_id.upper()}_DATABASE_URL")
        or os.environ.get("UP2P_DATABASE_URL"),
        help=f"local PostgreSQL URL (default: $UP2P_{app_id.upper()}_DATABASE_URL)",
    )
    parser.add_argument("--data-dir", default=None, help="key directory (default: per-user)")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=default_port)
    parser.add_argument("--connect", action="append", default=[], metavar="HOST:PORT",
                        help="also dial this address (repeatable)")
    parser.add_argument("--no-discovery", action="store_true")


def parse_hostport(value: str) -> tuple[str, int]:
    host, _, port = value.rpartition(":")
    if not host or not port.isdigit():
        raise SystemExit(f"expected HOST:PORT, got {value!r}")
    return host, int(port)


class UiLoop:
    """A minimal "UI thread": runs queued callbacks and reads commands.

    ``dispatch`` is passed to ``SyncNode(callback_dispatcher=...)`` so event
    handlers run here, on the main thread, exactly like a tkinter
    ``root.after(0, fn)`` or a Qt queued signal would run them.
    """

    def __init__(self) -> None:
        self.calls: queue.Queue[Callable[[], None]] = queue.Queue()
        self.lines: queue.Queue[str | None] = queue.Queue()

    def dispatch(self, fn: Callable[[], None]) -> None:
        self.calls.put(fn)

    def run(self, handle_line: Callable[[str], bool]) -> None:
        threading.Thread(target=self._read_stdin, daemon=True).start()
        while True:
            while not self.calls.empty():
                self.calls.get_nowait()()
            try:
                line = self.lines.get(timeout=0.1)
            except queue.Empty:
                continue
            if line is None or not handle_line(line.strip()):
                return

    def _read_stdin(self) -> None:
        while True:
            try:
                self.lines.put(input())
            except EOFError:
                self.lines.put(None)
                return


class PeerCommands:
    """Shell commands shared by both examples: peers, pairing, invitations."""

    def __init__(self, sync: SyncNode, say: Callable[[str], None]) -> None:
        self.sync = sync
        self.say = say
        sync.on("peer_discovered", lambda e: say(f"[lan] found {e['device_name']}"))
        sync.on("peer_connected", self._on_connected)
        sync.on("peer_disconnected", lambda e: say(f"[net] {e['device_name']} disconnected"))
        sync.on("pairing_requested", self._on_pairing)
        sync.on("pairing_completed", lambda e: say(f"[pair] paired with {e['device_name']}"))
        sync.on("pairing_rejected",
                lambda e: say(f"[pair] pairing with {e['device_name']} failed: {e['reason']}"))
        sync.on("group_invitation_received", self._on_invite)
        sync.on("member_joined", lambda e: say(
            f"[group] {e['device_name']} joined as {e['role']}" if not e["is_self"]
            else "[group] you joined the group"))
        sync.on("member_removed", lambda e: say(
            "[group] you were removed" if e["is_self"] else f"[group] {e['device_name']} left"))
        sync.on("sync_completed", lambda e: e["applied"] and say(
            f"[sync] {e['applied']} change(s) received"))

    def _on_connected(self, event: Any) -> None:
        trust = "paired" if event["trusted"] else "NOT paired - use 'pair'"
        self.say(f"[net] connected to {event['device_name']} ({trust})")

    def _on_pairing(self, event: Any) -> None:
        self.say(
            f"[pair] {event['device_name']} - compare this code on both screens: "
            f"{event['code']}\n       fingerprint {event['fingerprint']}\n"
            "       type 'approve' if they match, 'reject' otherwise"
        )

    def _on_invite(self, event: Any) -> None:
        self.say(
            f"[invite] {event['inviter_device_name']} invites you to "
            f"'{event['group_name']}' as {event['role']} - type 'accept {event['invite_id'][:8]}'"
        )

    def peer_by_index(self, arg: str) -> Any:
        peers = self.sync.peers()
        if not arg.isdigit() or not 1 <= int(arg) <= len(peers):
            raise ValueError("give a peer number from 'peers'")
        return peers[int(arg) - 1]

    def handle(self, cmd: str, arg: str) -> bool:
        """Returns True if the command was one of the shared ones."""
        sync = self.sync
        if cmd == "peers":
            for i, p in enumerate(sync.peers(), 1):
                state = "paired" if sync.is_trusted(p.device_id) else "unpaired"
                self.say(f"  {i}. {p.device_name} {p.remote_host} [{state}]")
        elif cmd == "connect":
            host, port = parse_hostport(arg)
            peer = sync.connect(host, port)
            self.say(f"connected to {peer.device_name}")
        elif cmd == "pair":
            peer = self.peer_by_index(arg)
            future = sync.submit(sync.aio.request_pairing(peer.device_id))
            future.add_done_callback(
                lambda f: f.exception() and self.say(f"pairing failed: {f.exception()}"))
        elif cmd in ("approve", "reject"):
            pending = sync.pairing_requests()
            if not pending:
                raise ValueError("no pairing in progress")
            if cmd == "approve":
                sync.approve_pairing(pending[0].device_id)
                self.say("approved - waiting for the other device")
            else:
                sync.reject_pairing(pending[0].device_id, "codes did not match")
        elif cmd == "trusted":
            for d in sync.list_trusted_devices():
                state = "revoked" if d.revoked_at else ("online" if d.connected else "offline")
                self.say(f"  {d.device_name} {d.fingerprint} [{state}]")
        elif cmd == "invites":
            for inv in sync.list_invites(direction="incoming"):
                self.say(f"  {inv.id[:8]} '{inv.group_name}' as {inv.role} [{inv.status}]")
        elif cmd == "accept":
            match = [i for i in sync.list_invites(direction="incoming") if i.id.startswith(arg)]
            invite = match[0].id if arg and match else arg
            group = sync.accept_invite(invite)
            self.say(f"joined '{group.name}' as {group.role}")
            return True
        elif cmd == "id":
            self.say(f"device {sync.device_id}\nfingerprint {sync.fingerprint}\n"
                     f"listening on {sync.listen_address}")
        else:
            return False
        return True


def run_shell(sync: SyncNode, ui: UiLoop, peer_cmds: PeerCommands,
              app_handle: Callable[[str, str], bool], help_text: str) -> None:
    def handle_line(line: str) -> bool:
        if not line:
            return True
        cmd, _, arg = line.partition(" ")
        if cmd in ("quit", "exit"):
            return False
        if cmd == "help":
            print(help_text)
            return True
        try:
            if not (peer_cmds.handle(cmd, arg.strip()) or app_handle(cmd, arg.strip())):
                print("unknown command; type 'help'")
        except (P2PSyncError, ValueError, TimeoutError) as exc:
            print(f"error: {exc}")
        return True

    print(help_text)
    ui.run(handle_line)


SHARED_HELP = """\
  peers                 list connected devices      connect HOST:PORT   dial a device
  pair N                pair with peer number N     approve / reject    answer a pairing
  trusted               list paired devices         id                  show this device
  invites               list received invitations   accept ID|CODE      join a group
  quit"""
