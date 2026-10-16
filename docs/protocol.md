# Universal P2P Sync wire protocol — version 2

This document defines the protocol independently of the Python implementation
so that JavaScript, Rust or other implementations can interoperate.

* **Version 2** (default, production): everything runs inside TLS 1.3 with
  authenticated device keys; supports pairing, groups and synchronization.
* **Version 1** (development only): the same framing and handshake over plain
  TCP without keys. It supports only `message` and must be explicitly enabled
  (`allow_insecure_transport=True`). v1 and v2 nodes never interoperate.

All binary values are encoded as unpadded URL-safe base64 ("b64" below). All
hashed or signed JSON uses the canonical encoding: UTF-8, keys sorted,
separators `,` and `:` without spaces, no NaN/Infinity.

## 1. Transport

* TCP, IPv4. Each node listens on one port (configurable; `0` = OS-assigned;
  the examples use 47801 for Echo and 47802 for To-Do) and may also dial other
  nodes. There is no client/server role beyond "initiator" and "responder" of a
  single connection.
* v2: TLS 1.3 (no lower version is accepted) wraps everything below. Each side
  presents a self-signed X.509 certificate whose public key is its Ed25519
  identity key. Certificate chains are not validated; the key is pinned to the
  device ID by the handshake (§4).

## 2. Framing

```
+----------------------+-------------------------------+
| length: uint32, BE   | body: `length` bytes          |
+----------------------+-------------------------------+
```

* `length` is an unsigned 32-bit big-endian integer counting body bytes only.
* `length` MUST be ≥ 1. A zero-length frame is a protocol error.
* Each side has a maximum frame size (reference default 1 MiB = 1 048 576).
  A receiver MUST reject a frame whose `length` exceeds its limit **without
  reading the body**, send an `error` with code `payload_too_large` (best effort)
  and close the connection.
* Senders MUST NOT send frames larger than the peer can accept. Frame limits
  are not negotiated; keep frames ≤ 1 MiB (the reference implementation splits
  `group_ops` and `changes` into batches of at most 75 % of its frame limit).

## 3. Message body

The body is a single JSON value (RFC 8259) encoded as UTF-8, with these
additional strictness rules. Violations are `malformed_message` errors:

* Must be valid UTF-8 (no lone surrogates).
* The top-level value MUST be an object.
* Object keys MUST be unique at every nesting level.
* `NaN`, `Infinity` and `-Infinity` are not allowed.
* The object MUST contain `"type"`: a string of 1–64 characters.
* For cross-language safety, integers SHOULD stay within ±(2^53 − 1).

Receivers MUST ignore unknown *fields* in known message types (forward
compatibility). Unknown message *types* are answered as described in §6.

## 4. Handshake

The first frame on a connection MUST be `hello` from the initiator. The
responder replies with exactly one `hello_ack` or `error`. No other message may
be sent before the handshake completes. The reference implementation aborts
handshakes that take longer than 10 seconds.

### `hello` (initiator → responder)

| field         | type              | rules                                         |
|---------------|-------------------|-----------------------------------------------|
| `type`        | `"hello"`         |                                               |
| `protocol`    | `"up2p"`          | exact match                                   |
| `versions`    | array of integers | 1–16 entries; protocol versions supported     |
| `app_id`      | string            | `^[a-z][a-z0-9_]{0,62}$`                      |
| `device_id`   | string            | `^[A-Za-z0-9_-]{8,128}$`                      |
| `device_name` | string            | 1–256 characters, display only                |
| `listen_port` | integer or `null` | 1–65535; the port the initiator listens on    |
| `public_key`  | b64 (32 bytes)    | v2 only: Ed25519 identity key                 |
| `nonce`       | b64 (32 bytes)    | v2 only: fresh random value                   |

### `hello_ack` (responder → initiator)

Same fields as `hello`, except `versions` is replaced by `version`: the highest
version present in both sides' supported lists.

### Rejection

The responder sends `error` and closes the connection when:

| code                   | condition                                           |
|------------------------|-----------------------------------------------------|
| `unexpected_message`   | first frame is not `hello`                          |
| `unsupported_protocol` | `protocol` ≠ `"up2p"`                               |
| `unsupported_version`  | no common version                                   |
| `invalid_handshake`    | a field is missing or violates its rule             |
| `app_mismatch`         | `app_id` differs from the responder's application   |
| `self_connection`      | `device_id` equals the responder's own device ID    |
| `identity_mismatch`    | v2: `device_id` ≠ hex SHA-256(`public_key`), or the TLS certificate key ≠ `public_key` |
| `device_revoked`       | v2: the device's trust record is revoked            |
| `authentication_failed`| v2: the `auth` signature does not verify            |

The initiator applies the same `app_mismatch` / `self_connection` checks to
`hello_ack`, and closes the connection if either one fails.

### Device authentication (v2)

* `device_id` MUST equal the lowercase hex SHA-256 of `public_key`.
* The initiator checks that the responder's TLS certificate carries
  `public_key` (the TLS handshake proved possession of its private key).
* After `hello_ack` the initiator sends `{"type":"auth","signature":b64}`: an
  Ed25519 signature over the canonical JSON

  ```json
  {"ctx":"up2p-auth-v2","app_id":…,"initiator":<initiator device_id>,
   "responder":<responder device_id>,"responder_cert":<hex SHA-256 of responder cert DER>,
   "initiator_nonce":<b64>,"responder_nonce":<b64>}
  ```

  The responder verifies it with the `public_key` from `hello` and replies
  `{"type":"auth_ok"}` or `error` `authentication_failed`. Only then may other
  messages be sent.
* In v1 the device ID is self-asserted and untrusted.

## 5. Duplicate connections

A node keeps at most one live connection per remote `device_id`. When a
second connection to the same device completes its handshake, both nodes
independently keep:

1. the connection whose **initiator** has the lexicographically smaller
   `device_id` (compared as byte strings), or
2. if both connections have the same initiator, the newer connection.

The node sends `close` with reason `duplicate_connection` on the other
connection and closes it. Replacing a duplicate is not a disconnect from the
application's point of view.

## 6. Post-handshake messages

| type      | fields                                     | semantics                                           |
|-----------|--------------------------------------------|-----------------------------------------------------|
| `ping`    | —                                          | receiver MUST reply `pong`                          |
| `pong`    | —                                          | liveness only                                       |
| `close`   | `reason`: string (optional)                | sender is closing; receiver closes too              |
| `error`   | `code`: string, `message`: string, `ref`: string\|null (optional) | non-fatal unless followed by close |
| `message` | `id`: string, `payload`: object            | direct application message (at-most-once)           |

* A receiver of an **unknown type** MUST reply with
  `{"type":"error","code":"unsupported_message_type","message":…,"ref":<id or null>}`
  and keep the connection open.
* A repeated `hello`/`hello_ack` after the handshake is a protocol error
  (`unexpected_message`): the receiver sends `error` and closes the connection.
* `message.payload` that is not an object is a `malformed_message` protocol error.

### Liveness

Each side sends `ping` every *keepalive interval* (reference default 15 s). It closes
the connection with reason `idle_timeout` if nothing has been received for the
*idle timeout* (default 45 s). Any received frame counts as activity.

### Delivery guarantees

Frames on one connection arrive in order. Delivery is at-most-once: messages in
flight when a connection breaks are lost. Durable synchronization (§11) must
recover these messages through checkpoint-based catch-up, not through the transport.

## 7. Discovery (mDNS / DNS-SD)

* Service type: `_up2p-sync._tcp.local.`
* Instance name: `up2p-<app_id[:20]>-<device_id[:24]>`, with collisions resolved
  as specified by mDNS.
* SRV port: the node's TCP listen port. A/AAAA records: its advertised addresses.
* TXT record keys:

| key    | value                                         |
|--------|-----------------------------------------------|
| `app`  | application ID                                |
| `dev`  | device ID                                     |
| `name` | device display name (≤ 200 characters)        |
| `pv`   | comma-separated supported protocol versions   |

Browsers MUST ignore services whose `app` differs from their own app ID.
Everything in discovery is an **unauthenticated hint**. The handshake (and,
in v2, TLS and the key proof) decides who a peer really is.

## 8. Versioning and compatibility

* `versions` / `version` carry the protocol **major** version. Incompatible
  changes increment it. Nodes may support several versions at once and select
  the highest common one.
* Within one major version, changes are additive only: new optional fields
  (ignored by old receivers) and new message types (answered with
  `unsupported_message_type` by old receivers). Senders MUST tolerate that error.
* Error codes are stable identifiers. New codes may be added.

## 9. Pairing (v2)

All pairing messages carry `session` (string, ≤ 64 chars). Pairing works
between any two authenticated devices; it creates trust, not group access.

| type | fields | sender |
|---|---|---|
| `pair_request` | `commitment`: b64 SHA-256(`nonce_A`) | initiator A |
| `pair_nonce` | `nonce`: b64 32 bytes (`nonce_B`) | responder B |
| `pair_reveal` | `nonce`: b64 (`nonce_A`); B MUST check it against the commitment | A |
| `pair_confirm` | — (the local user approved) | both |
| `pair_reject` | `reason` | either |

Code shown to both users: `int(SHA-256("up2p-pair-v1\0" ‖ app_id ‖ "\0" ‖ pk_A ‖ pk_B ‖ nonce_A ‖ nonce_B)[0:8]) mod 10^6`,
zero-padded to 6 digits. A device stores the peer as trusted after it has
sent and received `pair_confirm`. If both sides send `pair_request`
simultaneously, the request of the device with the smaller device ID wins.

## 10. Groups (v2)

### Membership operation

```json
{"op": {"v":1, "app_id":…, "group_id":<32 hex or null for genesis>, "kind":…,
        "author":<device_id>, "lamport":int, "deps":[op_id…], "ts":ms, "body":{…}},
 "sig": b64 Ed25519(canonical(op))}
```

`op_id` = hex SHA-256(canonical(op)); a group's ID is the first 32 hex digits
of its genesis `op_id`. Kinds and bodies:

| kind | body |
|---|---|
| `genesis` | `name`, `roles` {role: [perm]}, `owner_role`, `creator` (member), `key` {`key_id`, `box`}, `nonce` |
| `add_member` | `member`, `role`, `target_seq`, `invite_id`, `keys` {key_id: box} |
| `remove_member` | `device_id`, `target_seq` |
| `change_role` | `device_id`, `role`, `target_seq` |
| `rename` | `name` |
| `key_rotation` | `key_id`, `boxes` {device_id: box} |
| `key_grant` | `grants` {device_id: {key_id: box}} |

`member` = {`device_id`, `public_key`, `exchange_key` (X25519), `user_id`,
`device_name`}. `box` = {`epk`, `n`, `ct`}: ephemeral X25519 public key, nonce
and ChaCha20-Poly1305 ciphertext of the 32-byte group key under
HKDF-SHA256(shared secret, info=`"up2p-seal-v1"‖epk‖recipient_pk`), with
associated data canonical {`ctx`:"up2p-group-key", `key_id`, `device_id`}.
Evaluation rules: [groups.md](groups.md).

### Messages

| type | fields | notes |
|---|---|---|
| `group_ops` | `group_id`, `ops`: [operation] | accepted for known groups from any peer (ops are self-verifying); for an unknown group only from the inviter of an invitation this device accepted |
| `invite_offer` | `invite_id` (32 hex), `group_id`, `group_name`, `role`, `secret`, `expires_at` (Unix s) | only from paired devices |
| `invite_accept` | `invite_id`, `secret`, `member` | inviter validates, signs `add_member`, answers `invite_result`, then sends `group_ops` |
| `invite_result` | `invite_id`, `ok`, `group_id` or `error` | |
| `invite_reject` | `invite_id` | |
| `invite_revoked` | `invite_id` | |

Invitation code: `"up2p1." + b64(canonical {"a":app_id,"i":invite_id,"s":secret,"g":group_id,"d":inviter device_id,"n":group name,"r":role,"e":expiry Unix s})`.

## 11. Synchronization (v2)

### Change

```json
{"change": {"v":1, "group_id":…, "author":…, "seq":int≥1, "hlc":int,
            "collection":…, "record_id":…, "op":"put"|"delete",
            "parents":[change_id…], "key_id":…|null, "nonce":b64|null, "data":b64|null},
 "sig": b64 Ed25519(canonical(change))}
```

`change_id` = hex SHA-256(canonical(change)). For `put`, `data` is
ChaCha20-Poly1305(group key `key_id`, `nonce`, canonical(JSON object)) with
associated data canonical {`ctx`:"up2p-change", `group_id`, `author`, `seq`,
`collection`, `record_id`, `op`}. `delete` carries no key, nonce or data.
A receiver accepts a change only if the author is (or was) a member, the
signature verifies, and the author's role at `seq` grants `data.write` for the
collection; `(group_id, author, seq)` is unique.

### Messages

| type | fields | semantics |
|---|---|---|
| `sync_req` | `group_id`, `heads` (membership op DAG heads), `vector` {author: seq} | ask for everything beyond `vector` |
| `changes` | `group_id`, `changes`: [change], `sync` bool, `final` bool, `denied` bool | answer batches (`sync`=true, last has `final`); live pushes have `sync`=false; `denied` = the sender refuses (not a member / no `data.read`) |
| `sync_ack` | `group_id`, `vector` | receiver's vector after applying; stored as the peer's checkpoint |

A `sync_req` responder first sends `group_ops` if `heads` differ from its own.
A device that receives `denied` sends its own `group_ops` to the peer (the peer
may not know about it yet). `vector[author]` is the largest `s` such that
changes `1..s` by `author` are all present.

## 12. Error codes added in v2

`not_trusted` (non-fatal: the request needs a paired device or a shared
group), `identity_mismatch`, `authentication_failed`, `device_revoked`,
`tls_failed` (reported locally by the initiator).
