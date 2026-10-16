# Echo integration

[`examples/echo_app.py`](../examples/echo_app.py) is a small Echo chatbot that
embeds the SDK. The `EchoApp` class is the part a real Echo would copy; the
shell around it is just a stand-in for Echo's desktop UI.

## What Echo shares and what stays private

| data | where it lives | shared? |
|---|---|---|
| chat history with the bot | `EchoApp.private_history` (Echo's own storage) | **never**: it is never passed to the SDK |
| shared notes | collection `shared_chat_notes` in a team | yes, with the team's members |
| an exchange the user chooses to share | `share_last_answer()` → a note | only that one, explicitly |

## Integration points

```python
self.sync = SyncNode("echo", user_id, device_name, database_url=url,
                     roles={"leader": [...], "member": ["data.read", "data.write"]},
                     owner_role="leader",
                     callback_dispatcher=ui.dispatch)          # e.g. root.after(0, fn)
self.sync.on("record_received", self._remote_note)            # update model + UI
self.sync.on("record_updated", self._remote_note)
self.sync.on("record_deleted", self._remote_note)
self.sync.start()                                             # at Echo launch
```

* **Teams**: `create_team()` → `sync.create_group()`; the creator becomes
  *leader*. `invite()` → `sync.create_invite(team_id, "member", device_id=…)`.
  Members cannot invite or remove anyone (enforced by the library).
* **Saving a shared note**: `sync.publish(team_id, "shared_chat_notes", note_id, {...})`.
  Works offline; delivered when teammates reconnect.
* **Remote notes**: the event handler updates `self.shared_notes` and calls
  `on_change` to refresh the UI. It runs on Echo's UI thread because of
  `callback_dispatcher`.
* **Startup**: `start()` loads previously synchronized notes with
  `sync.list_records()`, so the UI is complete even before peers connect.

## Two-laptop walkthrough

Prerequisites on **each** laptop: Python 3.11+, this package installed,
PostgreSQL running locally with a database for Echo
([postgresql.md](postgresql.md)), both laptops on the same Wi-Fi, firewall
allowing TCP 47801 and UDP 5353 ([troubleshooting.md](troubleshooting.md)).

```bash
export UP2P_ECHO_DATABASE_URL=postgresql+psycopg://echo:PASSWORD@localhost/echo_sync
python examples/echo_app.py --name "Laptop A"        # on laptop A
python examples/echo_app.py --name "Laptop B"        # on laptop B
```

| step | Laptop A | Laptop B |
|---|---|---|
| 1-3 | sees `[lan] found Laptop B` and `[net] connected … NOT paired` | same |
| 4 | `peers`, then `pair 1` → a 6-digit code is shown | the same code is shown |
| | `approve` (only if the codes match) | `approve` |
| 5 | `team Development` | |
| 6 | `invite 1` | `[invite] … type 'accept xxxxxxxx'` |
| 7 | `[group] Laptop B joined as member` | `accept xxxxxxxx` → `joined 'Development' as member` |
| 8 | `note n1 Project update` | |
| 9 | | `[note] n1: Project update` (automatically) |
| 10 | | `note n1 Project update - moved to Friday` |
| 11 | `[note] n1: Project update - moved to Friday` | |
| 12 | | `quit` (or turn off Wi-Fi) |
| 13 | `note n2 Written while B was offline`; `status` shows 1 change waiting | |
| 14-15 | | start Echo again → `[note] n2: …` arrives by itself |
| 16 | `chat secret question?` - never appears on B | `notes` shows only shared notes |

If discovery does not work on your network, start B with
`--connect <A's IP>:47801` (A's IP: `ip addr` / `ipconfig`).

## Tests

`tests/test_acceptance.py::test_scenario_a_echo` runs this whole scenario
against two real nodes with separate PostgreSQL databases, including the
restart of Laptop B and a check that private chat text never reaches B's
database.
