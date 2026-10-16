# PostgreSQL

Every device runs **its own local PostgreSQL** (version 14 or newer). There is
no shared or central database: devices exchange data only through the
authenticated P2P protocol. SQLite and other engines are not supported (the
library refuses non-PostgreSQL URLs).

## Install

### Linux (Debian/Ubuntu)

```bash
sudo apt install postgresql
sudo -u postgres createuser --pwprompt echo        # choose a strong password
sudo -u postgres createdb --owner echo echo_sync
```

Fedora: `sudo dnf install postgresql-server && sudo postgresql-setup --initdb && sudo systemctl enable --now postgresql`.
The default configuration listens on `localhost` only; keep it that way.

### Windows

1. Install PostgreSQL with the EDB installer from
   <https://www.postgresql.org/download/windows/> (the service starts
   automatically; remember the `postgres` password).
2. Open *SQL Shell (psql)* and run:

   ```sql
   CREATE ROLE echo LOGIN PASSWORD 'choose-a-strong-password';
   CREATE DATABASE echo_sync OWNER echo;
   ```

3. Keep `listen_addresses = 'localhost'` in `postgresql.conf` and do not open
   port 5432 in the firewall.

### Docker (development)

```bash
docker run -d --name echo-pg -e POSTGRES_USER=echo -e POSTGRES_PASSWORD=secret \
  -e POSTGRES_DB=echo_sync -p 127.0.0.1:5432:5432 postgres:16-alpine
```

## Connect the library

```bash
# Linux/macOS
export UP2P_ECHO_DATABASE_URL='postgresql+psycopg://echo:PASSWORD@localhost:5432/echo_sync'
# Windows PowerShell
$env:UP2P_ECHO_DATABASE_URL = 'postgresql+psycopg://echo:PASSWORD@localhost:5432/echo_sync'
```

`postgresql://` URLs are accepted and routed to the psycopg 3 driver. To keep
the password out of the environment, put it in `~/.pgpass`
(`%APPDATA%\postgresql\pgpass.conf` on Windows) and omit it from the URL.

The application's own data may live in the same database: the library uses a
separate schema, `up2p_<app_id>` (override with `db_schema`). Echo and To-Do
can share one database without seeing each other's tables.

## Schema and migrations

Tables are created and upgraded by Alembic migrations shipped in the package
(`universal_p2p_sync/storage/migrations`). With `auto_migrate=True` (the
default) this happens on `start()`, serialized by an advisory lock. To run them
separately (for example with a privileged role during installation):

```bash
python -m universal_p2p_sync db-upgrade --app-id echo --database-url postgresql+psycopg://…
```

and start nodes with `auto_migrate=False`. A node refuses to start if the
schema is missing or at a different revision than the library expects.

| table | contents |
|---|---|
| `node_meta` | the device ID that owns the schema |
| `trusted_devices` | paired devices, revocation, last address |
| `groups` | known groups, status, next local change sequence |
| `membership_ops` | signed membership operations |
| `group_keys` | unsealed group keys |
| `invites` | incoming and outgoing invitations (outgoing store only a hash of the secret) |
| `changes` | the signed, encrypted change log |
| `records` | materialized current state (plaintext JSONB, queryable) |
| `conflicts` | detected conflicts and their resolution |
| `checkpoints` | what each peer has acknowledged |
| `outbox` | transactional outbox for application writes |

Only rows written through `publish`/`delete`/the outbox are synchronized. The
library never reads or synchronizes your own tables.

### One running instance per schema

A node holds a PostgreSQL advisory lock on its schema while running; a second
process using the same schema fails with `StorageError` ("another running node
already uses schema …"). The schema also records the owning device ID, so a
different key directory cannot be used with an existing schema.

## Transactions

Every sync operation is a single transaction: a published change and its
materialization; an ingested batch with its record updates, conflicts and
adapter writes; an outbox row and the change made from it. See
[integration.md](integration.md#8-integrating-existing-postgresql-tables) for
the outbox and adapters.

## Backup and recovery

* Back up the **database** (`pg_dump -Fc -n up2p_echo echo_sync > echo_sync.dump`,
  or the whole database together with your application tables) **and the key
  directory** (`~/.local/share/universal-p2p-sync/echo/` or
  `%LOCALAPPDATA%\universal-p2p-sync\echo\`). They belong together: the schema
  is bound to the device identity. Store key backups securely; they are the
  device's credentials.
* Restore: `pg_restore -d echo_sync echo_sync.dump` and copy the key directory
  back, then start the app and let it synchronize before writing (see
  [offline-sync.md](offline-sync.md#restoring-a-backup)).
* Lost database without a backup, but other members still have the data:
  drop the schema (`DROP SCHEMA up2p_echo CASCADE`), start the app, pair
  again, and ask an administrator to **remove** the device from each group and
  **invite it again** (a device never accepts a group it did not request, so
  memberships are not restored automatically). After rejoining it receives the
  group's full history from the members.
* Lost keys: the device gets a new identity. Pair again and have an
  administrator invite the new device; remove the old one.
