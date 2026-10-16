# Security

This document describes what the library protects, how, and where its limits
are. Cryptography uses only standard primitives from the `cryptography`
package and Python's `ssl` module (OpenSSL); nothing is implemented by hand.

## Threat model

Protected against:

* other devices on the LAN that are not paired and not group members
  (eavesdropping, impersonation, injection, replay);
* paired devices that are not members of a group (pairing grants no data
  access);
* members exceeding their role (self-promotion, inviting into higher roles,
  removing more privileged members, forging other members' changes);
* removed members obtaining data published after their removal has
  propagated;
* malformed, oversized or duplicated messages, connection floods from one
  address.

Not protected against:

* a compromised device or OS account (it holds the device keys and the local
  database);
* members leaking data they are allowed to read;
* denial of service by a device that floods the LAN at the network level;
* traffic analysis (who talks to whom, message sizes and timing).

## Device identity

* Each application on each device has an **Ed25519 signing key** and an
  **X25519 key-agreement key**, created on first start in
  `<data_dir>/<app_id>/` (default `~/.local/share/universal-p2p-sync/<app_id>`
  on Linux, `%LOCALAPPDATA%\universal-p2p-sync\<app_id>` on Windows).
* The **device ID** is the hex SHA-256 of the Ed25519 public key. It cannot be
  claimed without the private key. Device names and `user_id` are display
  labels only and are never used for authentication or authorization.
* The **fingerprint** shown to users is the first 160 bits of the device ID in
  groups of four hex digits.
* Key files are PKCS#8 PEM, written atomically with mode `0600` (on Windows the
  per-user profile ACL applies). Pass `key_passphrase` (or
  `UP2P_<APP>_KEY_PASSPHRASE`) to encrypt them.
* The PostgreSQL schema records the device ID that created it; starting with a
  different key directory against the same schema fails (prevents mixing up
  identities and data).

## Transport: TLS 1.3 with mutual device authentication

* Every connection is TLS 1.3 (`minimum_version = TLSv1_3`). Both sides present
  a self-signed certificate over their Ed25519 identity key.
* **Responder** authentication: the TLS handshake proves the responder holds
  the private key of its certificate. The initiator checks that the
  certificate key equals the `public_key` in `hello_ack` and that the device ID
  is its hash (`identity_mismatch` otherwise).
* **Initiator** authentication: Python's `ssl` module cannot pin self-signed
  client certificates, so the initiator proves its key inside the encrypted
  channel by signing a transcript
  `{ctx, app_id, initiator, responder, SHA-256(responder certificate), initiator_nonce, responder_nonce}`.
  The responder verifies it (`authentication_failed` otherwise). The
  responder's fresh nonce makes each signature valid for one connection only,
  and the certificate hash binds it to the responder, so a recorded signature
  cannot be replayed or relayed elsewhere (tested).
* Revoked devices are refused during the handshake on both sides
  (`device_revoked`).
* TLS provides confidentiality, integrity and replay protection for every
  message on the connection.
* The plaintext development transport exists only with
  `allow_insecure_transport=True`. It never interoperates with secure nodes and
  offers no pairing, groups or synchronization.

## Pairing

Numeric comparison with a commitment (as in Bluetooth Secure Simple Pairing):

1. A sends `SHA-256(nonce_A)` (commitment); 2. B sends `nonce_B`;
3. A reveals `nonce_A`; B verifies the commitment.
4. Both show a 6-digit code derived from both public keys and both nonces.

A man in the middle has different keys toward each side and, because A
commits before seeing `nonce_B`, can make the codes match only with
probability 10⁻⁶ per attempt. Users must compare the codes and approve on both
devices. The result is a local **trust record**; it can be revoked
(`revoke_device`) or deleted (`forget_device`).

**Pairing grants no data access.** It allows direct messages and directed
invitations. Data access comes only from group membership.

## Groups, invitations and authorization

* A group is a log of **signed membership operations**; every device evaluates
  it with the same deterministic rules (see [groups.md](groups.md)). Forged or
  unauthorized operations (self-promotion, granting roles with more
  permissions than the author has, removing more privileged members, ops by
  non-members, tampered or re-signed ops) are kept but ignored by everyone.
* Authorization is enforced by the library on both sides: locally before a
  write, and by every receiver for every change and operation, using the
  author's role at the change's sequence number.
* **Invitations**: a 192-bit random secret; only its SHA-256 is stored by the
  inviter. Directed invitations are bound to one device ID; token invitations
  are bearer secrets (share them over a trusted channel). Both expire
  (default 7 days), can be revoked, and have a use limit. Acceptance happens
  over an authenticated connection, and the new member's keys are taken from
  that connection, not from the token.
* **Data encryption**: record contents are encrypted end-to-end with a
  symmetric group key (ChaCha20-Poly1305, metadata bound as associated data)
  and signed by the author (Ed25519). Members can therefore relay changes for
  each other without being able to alter them.
* **Group keys** are delivered in "sealed boxes" (ephemeral X25519 + HKDF-SHA256
  + ChaCha20-Poly1305) inside signed membership operations, one box per member.
* **Key rotation**: removing a member (or a member leaving) rotates the group
  key; the new key is sealed only to the remaining members. Devices holding
  `member.invite`, `member.remove` or `group.manage` also repair key
  distribution after concurrent membership changes (stale recipients cause
  another rotation).

## Decentralized revocation: what it can and cannot do

* A removed member keeps everything it received before its removal.
* Once a device has applied the removal op, it stops sending changes to the
  removed device and rejects its sync requests. It still shares the membership
  log with it, so the removed device learns that it was removed (this reveals
  later membership changes, such as who joined, but no record data).
  Once the key rotation has been applied, new records are encrypted with a key
  the removed device never receives, even if a not-yet-updated member relays
  them.
* Until the removal has propagated, members that have not heard about it may
  still exchange data with the removed device. Changes the removed device
  authors *after* the removal point (`target_seq`) are rejected by every device
  once the removal is known, regardless of arrival order.
* Concurrent conflicting membership operations are resolved deterministically
  by `(lamport, op_id)` order; every device converges to the same membership.

## Input validation and limits

* Frames: 4-byte length prefix, rejected before reading if above
  `max_frame_size` (1 MiB default); UTF-8 strict JSON, duplicate keys, NaN and
  non-object messages rejected.
* Every protocol field is type-, length- and format-checked; list sizes are
  bounded; records are limited to `max_record_size`; collection and record IDs
  have strict formats.
* A connection that violates the protocol is closed; the node keeps running.
* Rate limits: `connection_rate_limit` new inbound connections per IP per
  `connection_rate_window`, `max_pending_handshakes`, `max_connections`,
  `max_pending_pairings`, handshake/connect timeouts and idle timeouts.
* Duplicates and replays: changes are identified by content hash and
  `(author, seq)`; membership ops by content hash; invitation secrets are
  single-use (or `max_uses`); pairing sessions use fresh nonces. Replayed items
  are ignored without side effects (tested).

## Data at rest

* The `changes` log stores record contents encrypted; but `records` (the
  materialized current state, used by `get_record`) and `group_keys` are
  plaintext in your local database, protected by PostgreSQL access control
  and OS permissions. Use a dedicated PostgreSQL role, a strong password,
  `listen_addresses = 'localhost'`, and disk encryption on laptops.
* Do not expose PostgreSQL on the LAN (keep the default `localhost` binding and
  firewall port 5432). The library never needs remote database access.

## Credential handling

Pass the database URL through `UP2P_<APP>_DATABASE_URL` / `UP2P_DATABASE_URL`,
a `.pgpass` file or the OS keyring, never in source code. `NodeConfig` hides
the URL and passphrase from `repr()`.

## Reporting

Please report vulnerabilities privately to the maintainers rather than in a
public issue.
