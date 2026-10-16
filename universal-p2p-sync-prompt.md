# Complete Universal P2P Sync — Production-Oriented Reusable Python SDK

You are a senior Python software architect, distributed-systems engineer, security engineer, and PostgreSQL specialist.

I already have an existing GitHub project named **`universal-p2p-sync`**.

**Do not create a new project from scratch. Continue developing my existing repository.**

The existing project has completed Milestone 1, including:

- Python packaging.
- `AsyncSyncNode` and `SyncNode`.
- LAN discovery using zeroconf and mDNS.
- Automatic peer connections.
- Manual IP connections.
- JSON message exchange.
- Application ID isolation.
- Connection management.
- Keepalive and reconnection.
- Event callbacks.
- Basic tests.
- A working `examples/basic_peer.py`.

The current version uses insecure networking for development.

Your task is to **complete the remaining milestones and make this a reusable, secure, automatic P2P data synchronization library for multiple independent applications**.

The final package must work with:

1. Echo — a Python desktop chatbot application.
2. To-Do — a Python task management application.
3. Future Python applications without modifying the library's internal source code.

The package distribution name must remain `universal-p2p-sync`, and the Python import must remain `universal_p2p_sync`.

---

# 0. Rule for Existing Work (Read This First)

**If something described in this prompt already exists in the repository, ignore it. If it does not exist, add it. The end result must be a complete implementation of everything in this prompt.**

Apply this rule to every feature, module, test, migration, example, document, and CI file:

1. **Audit first.** Before writing any code, scan the whole repository and build a checklist of every requirement in this prompt, marking each one as:
   - **Done** — already implemented and verified by a passing test or a working run.
   - **Partial** — present but incomplete, broken, insecure, or untested.
   - **Missing** — not present at all.
2. **Done items:** leave them untouched. Do not rewrite, rename, move, or re-implement them. Do not duplicate them.
3. **Partial items:** complete or fix only the missing or broken portion. Keep the existing public API and behavior compatible.
4. **Missing items:** implement them fully, with tests and documentation.
5. **Never create duplicate files, classes, tables, migrations, tests, or docs** for something that already exists. Extend the existing one instead.
6. **Do not overwrite working files** (README, docs, tests, examples, CI) wholesale. Merge in only what is missing and correct what is inaccurate.
7. **Verify, don't assume.** Mark an item "Done" only if you have confirmed it works (by reading the code and running its tests). If you cannot confirm it, treat it as Partial.
8. **Report the audit.** Start your work by printing the checklist (Done / Partial / Missing). At the end, print an updated checklist showing everything is Done, along with any limitations that remain.

The final result must be one **complete** project that satisfies every section below, regardless of how much was already in place.

---

# 1. Main Objective

Build a complete peer-to-peer synchronization SDK that allows multiple devices running the same application to securely share authorized application data automatically over the same Wi-Fi or LAN.

Requirements:

- No central synchronization server.
- No cloud synchronization service.
- No GitHub involvement during data synchronization.
- No separate P2P application or daemon.
- The P2P SDK runs inside each application.
- Every device can initiate and accept connections.
- Linux and Windows support.
- Secure device pairing.
- Encrypted peer-to-peer communication.
- Groups, invitations, and membership management.
- Application-defined administrators and permissions.
- Automatic synchronization of authorized data.
- PostgreSQL-only persistent storage.
- Offline change tracking and synchronization after reconnection.
- Conflict detection and resolution.
- Data isolation between different applications.
- A clean, reusable Python API.
- Production-oriented testing and documentation.

The library must not contain hardcoded Echo or To-Do business logic.

Important: PostgreSQL is a separate database service. Each participating device must have access to its own PostgreSQL instance. Do not use a shared central PostgreSQL server, SQLite, Firebase, Supabase, or another database engine.

---

# 2. Preserve the Existing Codebase

Before making changes:

1. Read the entire existing repository.
2. Inspect `README.md`, `pyproject.toml`, public APIs, tests, and examples.
3. Identify which Milestone 1 components already work.
4. Preserve compatible public APIs wherever possible.
5. Refactor existing modules only when necessary.
6. Do not remove working functionality without replacing it.
7. Add database migrations for persistent schema changes.
8. Update tests as functionality evolves.
9. Update documentation to reflect actual implementation status.

Do not claim features are complete unless they are implemented and verified.

---

# 3. Milestone 2 — Secure Device Identity and Connections

Implement production-oriented device security.

## Device identity

Each device must have:

- A unique persistent device ID.
- A cryptographic public/private key pair.
- A verified device fingerprint.
- Secure private-key storage.
- Trusted-device records.

The identity must survive application restarts.

Do not rely on device names or user-provided IDs for authentication.

## Secure transport

Implement:

- TLS 1.3.
- Mutual peer authentication.
- Secure certificate or key verification.
- Connection authentication.
- Replay protection.
- Message integrity.
- Connection timeout handling.
- Secure reconnection.

Remove insecure networking from normal production operation.

If development-only insecure transport remains, it must require explicit opt-in and must never be the default.

## Pairing

Implement one-time device pairing.

Suggested flow:

1. Device A discovers Device B.
2. Device A requests pairing.
3. Device B receives a pairing request.
4. Both users verify a matching pairing code or fingerprint.
5. Both users approve the pairing.
6. The devices store authenticated trust records.
7. Future connections can authenticate automatically.

Pairing must not automatically grant access to all groups or application data.

Implement device revocation and trusted-device management.

---

# 4. Milestone 3 — Groups, Invitations, and Permissions

Implement reusable group management.

Required functionality:

- Create a group.
- Generate a unique group ID.
- List groups.
- Rename groups.
- Create invitations.
- Accept invitations.
- Reject invitations.
- Join groups.
- Leave groups.
- Remove members.
- List group members.
- Change member roles.
- Revoke invitations.
- Revoke group access.

## Application-defined roles

The SDK must not hardcode a single administrator model.

Example for Echo:

- Leader.
- Member.

Example for To-Do:

- Administrator.
- Task user.

Future applications must be able to define additional roles.

Example permission model:

```python
permissions = {
    "leader": [
        "group.manage",
        "member.invite",
        "member.remove",
        "data.read",
        "data.write"
    ],
    "member": [
        "data.read",
        "data.write"
    ]
}
```

Implement authorization checks in the library, not just in the application UI.

Use authenticated identities, signed membership records, and securely verified role assignments.

Prevent users from granting themselves administrator permissions.

Handle membership updates while some peers are offline.

Document the limits of decentralized revocation and prevent removed members from receiving future authorized updates once the relevant membership changes and keys have propagated.

Use appropriate group key rotation when membership changes.

---

# 5. Milestone 4 — PostgreSQL Automatic Synchronization Engine

This is the most important part of the project.

Implement a complete record-based synchronization engine backed by PostgreSQL.

**Do not use SQLite anywhere.**

Use:

- PostgreSQL.
- SQLAlchemy 2.x.
- psycopg 3.
- Alembic migrations.

## PostgreSQL architecture

Each laptop must have its own local PostgreSQL instance.

Example:

Device A:

```text
Echo Application
    |
Universal P2P Sync
    |
Local PostgreSQL A
```

Device B:

```text
Echo Application
    |
Universal P2P Sync
    |
Local PostgreSQL B
```

Synchronization must happen directly between the P2P libraries over the LAN.

Never use a central database for synchronization.

## Data synchronization

Support:

- Create records.
- Update records.
- Delete records.
- JSON-compatible payloads.
- Collections.
- Record identifiers.
- Change IDs.
- Record versioning.
- Change timestamps.
- Device identifiers.
- Group identifiers.
- Change acknowledgments.
- Persistent change logs.
- Synchronization checkpoints.
- Pending change queues.
- Duplicate detection.
- Deletion tombstones.

## Automatic synchronization

When an application saves shared data:

1. The application publishes the changed record through the SDK or a configured adapter.
2. The SDK persists the change in PostgreSQL.
3. The SDK identifies authorized group peers.
4. The SDK transmits the change over encrypted P2P connections.
5. The receiving SDK validates the sender and permissions.
6. The receiving SDK applies the change to its local PostgreSQL synchronization storage.
7. The receiving application receives an event or callback.
8. The receiving application updates its own data model and UI through a documented integration mechanism.

No manual file selection or repeated user approval should be required after initial authorization.

Do not synchronize all PostgreSQL tables automatically.

Only explicitly registered or published application data may be shared.

## PostgreSQL adapter

Provide an optional adapter interface so applications can integrate their existing PostgreSQL data models.

Support transactional publishing through an outbox pattern or equivalent mechanism to avoid losing updates between an application's database transaction and the SDK's synchronization log.

Document how to avoid synchronization loops when remote changes are applied.

## Offline synchronization

When a device is offline:

- The application continues working locally as long as its PostgreSQL database is available.
- Shared changes remain stored in PostgreSQL.
- Pending changes survive restarts.
- When peers reconnect, the SDK exchanges synchronization checkpoints.
- Missing changes are transmitted.
- Duplicates are ignored.
- Conflicts are detected.
- Deletions do not unexpectedly reappear.

Implement recovery from interrupted transfers and partially completed synchronization.

## Conflict resolution

Handle simultaneous updates from different devices.

Implement:

- Version or causal metadata.
- Conflict detection.
- A deterministic default policy that does not silently discard concurrent edits.
- Application-defined conflict resolvers.
- Conflict events.
- Conflict persistence.
- Tests for concurrent updates.

Document the exact behavior for updates, deletions, and concurrent modifications.

---

# 6. Reusable Public SDK

The library must expose a simple public interface.

The following examples are API design targets. Adapt them to the existing implementation where necessary.

## Starting the library

```python
from universal_p2p_sync import SyncNode

sync = SyncNode(
    app_id="echo",
    user_id="user_001",
    device_name="My Laptop",
    database_url="postgresql+psycopg://user:password@localhost:5432/echo_sync"
)

sync.start()
```

Credentials must be provided securely through configuration or environment variables in real applications.

The `user_id` is an application identity reference, not proof of authentication.

## Creating a group

```python
group = sync.create_group(
    name="Development Team"
)
```

## Inviting members

```python
invite = sync.create_invite(
    group_id=group.id,
    role="member"
)
```

## Publishing data

```python
sync.publish(
    group_id=group.id,
    collection="shared_notes",
    record_id="note_001",
    data={
        "title": "Meeting",
        "content": "Tomorrow at 10 AM"
    }
)
```

## Updating data

```python
sync.publish(
    group_id=group.id,
    collection="shared_notes",
    record_id="note_001",
    data={
        "title": "Meeting",
        "content": "Tomorrow at 11 AM"
    }
)
```

## Deleting data

```python
sync.delete(
    group_id=group.id,
    collection="shared_notes",
    record_id="note_001"
)
```

## Receiving updates

```python
def on_record_received(event):
    print("Collection:", event["collection"])
    print("Record:", event["record_id"])
    print("Data:", event["data"])

sync.on("record_received", on_record_received)
```

## Getting synchronization status

```python
status = sync.get_sync_status(
    group_id=group.id
)
```

Support both asynchronous and GUI-friendly synchronous interfaces.

Ensure callbacks can be dispatched safely to tkinter, PySide, PyQt, or other desktop UI threads.

---

# 7. Echo Application Integration

Create a working Echo integration example.

Echo is a Python desktop chatbot application.

The SDK should allow Echo to:

- Start the P2P synchronization engine when Echo launches.
- Discover other Echo devices on the LAN.
- Pair devices securely.
- Create teams.
- Allow team leaders to invite members.
- Authenticate and authorize members.
- Synchronize selected shared chatbot data.
- Keep private chatbot data local.
- Receive synchronized notes, shared conversations, or other explicitly selected records.
- Update Echo's UI when remote data arrives.
- Queue changes while peers are offline.
- Synchronize queued changes after reconnection.

Example:

```python
from universal_p2p_sync import SyncNode

sync = SyncNode(
    app_id="echo",
    user_id="echo_user_001",
    device_name="Echo Laptop",
    database_url="postgresql+psycopg://localhost/echo_sync"
)

sync.start()

sync.publish(
    group_id="team_001",
    collection="shared_chat_notes",
    record_id="note_001",
    data={
        "message": "Project update",
        "author": "echo_user_001"
    }
)
```

The example must use a real, authorized group ID rather than assuming an arbitrary string grants access.

Do not require changes to the SDK's internal implementation for Echo.

---

# 8. To-Do Application Integration

Create a separate working To-Do integration example.

The To-Do application should be able to:

- Start the same P2P library.
- Create workspaces.
- Use administrator-defined permissions.
- Invite users.
- Share tasks.
- Synchronize task creation.
- Synchronize task updates.
- Synchronize task completion.
- Synchronize task deletion.
- Handle offline edits.
- Resolve task conflicts.
- Update the UI when remote changes arrive.

Example:

```python
sync = SyncNode(
    app_id="todo",
    user_id="todo_user_001",
    device_name="Office Laptop",
    database_url="postgresql+psycopg://localhost/todo_sync"
)

sync.start()

sync.publish(
    group_id="workspace_001",
    collection="tasks",
    record_id="task_001",
    data={
        "title": "Finish documentation",
        "completed": False
    }
)
```

Again, the example must use an actual authorized workspace ID.

The To-Do application must not share records with Echo, even when both use the same library.

Both applications must work without changing the library's source code.

---

# 9. Events

Implement and document these events:

- `peer_discovered`
- `peer_connected`
- `peer_disconnected`
- `pairing_requested`
- `pairing_completed`
- `pairing_rejected`
- `group_created`
- `group_invitation_received`
- `member_joined`
- `member_removed`
- `sync_started`
- `sync_progress`
- `record_received`
- `record_updated`
- `record_deleted`
- `sync_completed`
- `sync_failed`
- `conflict_detected`
- `conflict_resolved`

Document the payload schema of every event.

The SDK must never directly manipulate application-specific UI components.

---

# 10. Security Requirements

Implement:

- Persistent cryptographic identities.
- Mutual peer authentication.
- TLS 1.3 encryption.
- Explicit pairing.
- Secure invitation tokens.
- Signed membership records.
- Permission enforcement.
- Group-level access control.
- Key rotation where necessary.
- Replay protection.
- Input validation.
- Payload size limits.
- Safe message parsing.
- Connection rate limiting.
- Secure credential handling.
- Protection against unauthorized synchronization.

Do not implement custom cryptographic primitives.

Do not expose PostgreSQL directly to other devices.

Only the authenticated P2P protocol may exchange authorized synchronization records.

Include tests for unauthorized devices, forged roles, expired invitations, revoked members, malformed messages, and replay attempts.

---

# 11. Testing

Use pytest and PostgreSQL integration tests.

Test the following:

1. Two devices connect on the same LAN.
2. Untrusted devices cannot synchronize.
3. Pairing works.
4. Pairing survives restarts.
5. Invalid identities are rejected.
6. Groups can be created.
7. Invitations work.
8. Unauthorized invitations fail.
9. Member removal works.
10. Echo records synchronize.
11. To-Do records synchronize.
12. Echo and To-Do remain isolated.
13. Offline changes synchronize after reconnection.
14. Duplicate updates are ignored.
15. Concurrent edits are detected.
16. Deletions synchronize correctly.
17. Pending changes survive application restarts.
18. PostgreSQL transactions work.
19. Database migrations work.
20. GUI-friendly callbacks work.
21. Secure shutdown works.
22. Reconnection works.
23. Revoked members cannot obtain newly authorized changes.
24. Synchronization state remains consistent after crashes.
25. The package installs correctly from a Git checkout.

Include integration tests with two or more peer instances using separate PostgreSQL databases.

Add GitHub Actions to run tests with PostgreSQL.

---

# 12. Documentation

Update the existing README and create or complete:

- `docs/architecture.md`
- `docs/integration.md`
- `docs/security.md`
- `docs/protocol.md`
- `docs/postgresql.md`
- `docs/groups.md`
- `docs/offline-sync.md`
- `docs/conflicts.md`
- `docs/echo-integration.md`
- `docs/todo-integration.md`
- `docs/troubleshooting.md`

Include:

- Installation instructions.
- PostgreSQL setup on Linux and Windows.
- Environment variable configuration.
- Peer discovery.
- Manual connections.
- Secure pairing.
- Group creation.
- Invitations.
- Permissions.
- Automatic synchronization.
- Offline synchronization.
- Conflict handling.
- Error handling.
- GUI integration.
- Two-laptop testing.
- GitHub installation.
- Packaging with PyInstaller or equivalent desktop packaging tools.
- Limitations of local-network-only P2P.
- Backup and recovery guidance.

Keep the README's milestone status accurate.

---

# 13. Development Milestones

Complete the existing project in this order. For each milestone, apply the rule in Section 0: skip what already exists and is verified, fix what is partial, and add what is missing.

## Milestone 2 — Security

- Implement device identities.
- Implement TLS 1.3 mutual authentication.
- Implement pairing.
- Implement trusted-device storage.
- Implement revocation.
- Add security tests.

## Milestone 3 — Groups

- Implement group creation.
- Implement invitations.
- Implement group joining.
- Implement membership records.
- Implement configurable roles and permissions.
- Implement authorization enforcement.
- Add group and authorization tests.

## Milestone 4 — Synchronization

- Implement PostgreSQL persistence.
- Implement database migrations.
- Implement change logs.
- Implement record synchronization.
- Implement offline queues.
- Implement reconnection synchronization.
- Implement deletion tombstones.
- Implement conflict detection and resolution.
- Add synchronization tests.

## Milestone 5 — Integration and Release

- Complete Echo integration example.
- Complete To-Do integration example.
- Complete documentation.
- Complete GitHub Actions.
- Verify installation.
- Verify Linux and Windows compatibility.
- Run integration tests.
- Prepare a release-ready package.

For each milestone:

1. Implement actual working code.
2. Write tests.
3. Run tests.
4. Fix failures.
5. Document completed features.
6. Document remaining limitations.
7. Preserve existing working functionality.

Do not fake test results, create placeholder security implementations, or label incomplete features as production-ready.

---

# 14. Final Acceptance Criteria

The project is complete only when the following end-to-end workflow works:

### Scenario A — Echo

1. Laptop A starts Echo.
2. Laptop B starts Echo.
3. Both discover each other on the same Wi-Fi.
4. Users securely pair their devices.
5. Laptop A creates a team.
6. Laptop A invites Laptop B.
7. Laptop B joins the team.
8. Laptop A saves an authorized shared note.
9. Laptop B receives the note automatically.
10. Laptop B updates the note.
11. Laptop A receives the update automatically.
12. Laptop B disconnects.
13. Laptop A makes additional changes.
14. Laptop B reconnects.
15. Missing changes synchronize.
16. Private Echo data remains private.

### Scenario B — To-Do

1. Laptop A starts To-Do.
2. Laptop B starts To-Do.
3. Devices pair securely.
4. An administrator creates a workspace.
5. The administrator invites another user.
6. Both join the workspace.
7. Laptop A creates a task.
8. Laptop B receives it automatically.
9. Laptop B marks it completed.
10. Laptop A receives the update.
11. Offline task edits synchronize after reconnection.
12. Unauthorized users cannot access the workspace.

### Scenario C — Reusability

1. Echo installs `universal-p2p-sync`.
2. To-Do installs the same package.
3. Both configure their own application IDs.
4. Both define their own permissions.
5. Both publish their own data types.
6. Neither application modifies the library's internal source code.
7. The library handles networking, security, groups, and synchronization for both.
8. Echo and To-Do data remain isolated.

---

# 15. Final Deliverables

Provide:

- Complete updated source code.
- Working public SDK.
- Secure networking implementation.
- PostgreSQL database models and migrations.
- Group and membership management.
- Automatic synchronization engine.
- Offline synchronization.
- Conflict handling.
- Echo integration example.
- To-Do integration example.
- Automated tests.
- GitHub Actions configuration.
- Updated README.
- Complete documentation.
- Installation instructions.
- Two-laptop testing instructions.
- Release checklist.
- Audit checklist (Done / Partial / Missing) from the start and the final verified version at the end.
- Summary of implemented and unimplemented functionality.

**Begin by inspecting the existing repository and printing the audit checklist from Section 0. Then complete Milestone 2 (only what is not already done). Continue through Milestones 3–5, verifying each milestone before proceeding. Do not replace the existing repository with an unrelated implementation.**

The final goal is a single reusable Python package that future applications can install and use for secure, automatic P2P data synchronization without building their own networking or synchronization systems.
