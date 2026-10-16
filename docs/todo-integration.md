# To-Do integration

[`examples/todo_app.py`](../examples/todo_app.py) is a shared task list built
on the same library as Echo, with nothing changed in the library: it uses its
own `app_id`, roles, collections and conflict resolver.

## Design

| aspect | To-Do's choice |
|---|---|
| application ID | `todo` (Echo devices are never discovered or accepted) |
| group | a *workspace* |
| roles | `administrator` (manage, invite, remove, change roles, `task.assign`) and `task_user` (read/write tasks) |
| collection | `tasks`, one record per task: `{"title", "completed", "assignee"}` |
| app-defined permission | `task.assign`, checked with `sync.has_permission(ws_id, "task.assign")` |
| conflicts | `merge_tasks`: completed if anyone completed it; the newest title wins |

```python
sync = SyncNode("todo", user_id, device_name, database_url=url,
                roles=ROLES, owner_role="administrator",
                callback_dispatcher=ui.dispatch)
sync.register_conflict_resolver("tasks", merge_tasks)
for name in ("record_received", "record_updated", "record_deleted"):
    sync.on(name, self._remote_task)          # update self.tasks and refresh the list
```

Task operations map directly to SDK calls:

| To-Do action | SDK call |
|---|---|
| create task | `publish(ws, "tasks", task_id, {...})` |
| edit / complete | `publish(...)` with the updated task |
| delete | `delete(ws, "tasks", task_id)` |
| list on startup | `list_records(ws, "tasks")` |

If To-Do kept tasks in its own PostgreSQL table, it would write that table and
call `enqueue_change(conn, schema=sync.schema, ...)` in the same transaction,
and register an adapter to apply remote changes to the table
([integration.md §8](integration.md#8-integrating-existing-postgresql-tables)).

## Two-laptop walkthrough

```bash
export UP2P_TODO_DATABASE_URL=postgresql+psycopg://todo:PASSWORD@localhost/todo_sync
python examples/todo_app.py --name "Office Laptop"    # laptop A
python examples/todo_app.py --name "Home Laptop"      # laptop B
```

| step | Laptop A (administrator) | Laptop B |
|---|---|---|
| 1-3 | `pair 1`, compare code, `approve` | `approve` |
| 4 | `workspace Q3 Plan` | |
| 5-6 | `invite 1` | `accept <id>` → joined as task_user |
| 7 | `add Finish documentation` → `task 1a2b3c4d added` | |
| 8 | | `tasks` shows it (arrived automatically) |
| 9 | | `done 1a2b3c4d` |
| 10 | `tasks` → `[x] 1a2b3c4d Finish documentation` | |
| 11 | disconnect Wi-Fi on both; A: `edit 1a2b3c4d Finish docs v2`; B: `add Buy milk`; reconnect | |
| | both lists converge; concurrent edits of one task are merged by `merge_tasks` | |
| 12 | a third laptop running To-Do that was not invited sees no workspace and cannot publish into it | |

## Tests

`tests/test_acceptance.py::test_scenario_b_todo` covers this scenario,
including offline edits on both laptops, a concurrent edit merged by the
resolver on both sides, and an uninvited device that is refused.
`test_scenario_c_reusability_and_isolation` runs Echo and To-Do side by side
on one PostgreSQL database and checks they stay isolated.
