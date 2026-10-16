# Troubleshooting

Enable logs first:

```python
import logging
logging.basicConfig(level=logging.INFO)
logging.getLogger("universal_p2p_sync").setLevel(logging.DEBUG)
```

## Devices do not find each other

* Both must run the **same `app_id`** (Echo never sees To-Do).
* Same subnet: mDNS does not cross routers, guest networks, or Wi-Fi
  "client isolation" (common on public/hotel/corporate Wi-Fi).
* Firewall: allow inbound **TCP on the listen port** (examples: 47801 Echo,
  47802 To-Do) and **UDP 5353** (mDNS).
  * Linux (ufw): `sudo ufw allow 47801/tcp && sudo ufw allow 5353/udp`
  * Windows: allow Python (or your packaged app) when prompted, on *Private*
    networks; set the Wi-Fi profile to **Private** (discovery is blocked on
    *Public* networks).
* VPN clients may capture multicast; pause them or use manual addresses.
* Workaround: connect manually (`sync.add_peer_address(ip, port)` or
  `--connect IP:PORT` in the examples). Several network interfaces? Set
  `advertise_addresses=("192.168.1.20",)`.

## Connection errors (`HandshakeError.code`)

| code | meaning / fix |
|---|---|
| `app_mismatch` | the other device runs a different application ID |
| `device_revoked` | one side revoked the other; `forget_device()` then pair again if intended |
| `identity_mismatch` | the address now belongs to a different device (DHCP reuse) or someone is impersonating; check fingerprints |
| `authentication_failed` | the peer could not prove its key; possible attack or corrupted key |
| `tls_failed` | the other side is not a secure node (e.g. development mode) or not this protocol |
| `unsupported_version` | update both devices to compatible library versions |
| `self_connection` | you dialed your own address |

`not_trusted` errors in the log mean an unpaired, non-member device sent a
request that needs trust; pair the devices or invite the device.

## Pairing

* Codes differ → **reject**: someone may be intercepting. Retry on a trusted network.
* `PairingError: pairing peer did not respond` → the other app is not running,
  the devices disconnected, or the other user did not approve within
  `pairing_timeout` (5 minutes).
* Both approved but nothing happens → both sides must approve; check
  `sync.pairing_requests()`.

## Invitations

* `PeerNotConnectedError` when accepting → the inviting device must be online
  and connected.
* `InviteError: invitation expired / revoked / is accepted` → ask for a new one.
* `PermissionDeniedError` when inviting → your role lacks `member.invite`, or
  the target role has permissions you do not have.

## Data does not arrive

* `sync.get_sync_status(group_id)`: is the peer `connected`? Are changes
  `pending`? Is `undecryptable_changes` > 0 (key not received yet: a member
  holding `member.invite`/`member.remove` must come online to grant it)?
* The receiver must be a member with `data.read`; the writer needs `data.write`.
* `sync_failed` events carry a `reason`, e.g. `apply_failed: …` when your
  adapter raised (the change is retried at the next sync), or `outbox: …` for
  rejected outbox rows.
* Changes made by a member after it was removed or demoted are rejected by
  design ([groups.md](groups.md#offline-membership-changes)).

## PostgreSQL

| error | fix |
|---|---|
| `database_url is required` | set `UP2P_<APP>_DATABASE_URL` or pass `database_url` |
| `unsupported database backend` | only PostgreSQL URLs are accepted |
| `cannot open PostgreSQL storage: … connection refused` | start the PostgreSQL service; check host/port |
| `password authentication failed` | check the role's password / `pg_hba.conf` |
| `another running node already uses schema …` | the app is already running (or a crashed process still holds the connection; it is released when the process ends). Use a different `db_schema` for a second instance on the same machine |
| `schema … belongs to device …` | the key directory does not match the database; use the right `data_dir` or another schema |
| `schema … is not initialized` / `is at revision …` | run `python -m universal_p2p_sync db-upgrade --app-id …` or enable `auto_migrate` |
| `permission denied for database` | the role needs `CREATE` on the database (to create its schema) |

## Running two instances on one machine (testing)

Give each its own `listen_port`, `data_dir` (different device identity) and
database or `db_schema`:

```bash
python examples/echo_app.py --name A --port 47801 --data-dir /tmp/a --database-url …/echo_a
python examples/echo_app.py --name B --port 47811 --data-dir /tmp/b --database-url …/echo_b --connect 127.0.0.1:47801
```

## Resetting a device (development only)

Stop the app, `DROP SCHEMA up2p_echo CASCADE;`, delete the key directory.
The device gets a new identity and must be paired and invited again.
