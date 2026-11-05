# Identity and pairing

Exact formats are in [spec/protocol.md](spec/protocol.md) §2 and §3.

## Identities

| Who | Identity |
|---|---|
| Center | A random id (UUID-shaped) and a name, both made on its first start. A TLS key and a self-signed certificate. Its **pin** is the base64url SHA-256 of the certificate's public key info (43 characters) |
| Node | One Ed25519 key pair **per center**, made at pairing and kept in `keys/<name>.key` (mode 0600), or in the system keyring with `machine.secret_storage = "keyring"`. The **node id** is the base32 of the first 16 bytes of the SHA-256 of the public key (26 characters). The node name is 1 to 32 characters of `a-z`, `0-9` and `-`, starting and ending with a letter or digit, from the host name by default |
| Harness | A token, from `--harness-token` or made in the web UI. It is local to the center host, and opens the HTTP MCP endpoint only |
| Owner (center web UI) | The owner token in `owner-token` in the center's state folder, made at its first start. It logs in to the web UI and opens nothing else; no harness token logs in there. A backup does not carry it |

Because the key is per center, two centers see two unrelated ids for the same
machine. They cannot link the machine across trust domains.

A node has no bearer token. A config copied without its private key cannot
connect. A copied key is caught by the [one-link rule](node-link.md#one-live-link).

The center may give a node a display name. That name never goes back to the
node.

## Pairing

1. In the center's web UI, **Pair a machine** makes a one-time code and shows
   the link. The code lasts 10 minutes by default (up to 24 hours), allows 10
   tries and works once.
   `nerve://pair?center=<percent-encoded URL>&code=<code>&pin=<pin>`
2. On the node: `nerve-node center add '<link>'`. The node parses the link
   strictly and shows the center's address, plus the policy the new pairing
   starts with (mode `folder`, no folder, the guard's deny rules
   `nerve_policy::rules::GUARD`, settings grant `off`). Before it asks, it
   checks the link (`nerve_node::pair::check`): it opens the way the pairing
   will (proxy or relay, pin) and sends `POST <center>/nerve/v0/pair/check`
   `{code}`, which answers `open`, `used`, `gone` or `busy` without using the
   code or counting a try (`nerve_center::pairing::Codes::probe`: a check
   with a code that is not open costs one of 10 checks per 10 minutes, after
   which every check gets `busy`, so it is no cheaper a way to guess). It
   asks only when the pairing can work, and stores nothing before the owner
   confirms.
3. The node makes a key pair for this center and sends
   `POST <center>/nerve/v0/pair` with `{code, name, platform, arch,
   public_key}` over TLS, checked against the pin.
4. The center answers `{center_id, center_name, node_id}` and stores the public
   key. The node stores the pairing.

The center computes the `node_id` from the public key itself.

### The link

- `center` is an `https://` URL, or `http://` to a loopback address. It has no
  user info, query or fragment and no `.` or `..` path segments.
- `pin` is optional. Without it the node checks the certificate against the
  system roots.
- The parser refuses unknown keys, a key given twice, bad percent escapes, a
  fragment and a link over 4096 bytes.
- Over plain `http`, the node on Linux checks that the listening socket belongs
  to its own user.

### Answers to a pair request

| Status | Meaning |
|---|---|
| 200 | Paired |
| 400 | Malformed request or name |
| 403 | Code unknown, used, expired or out of tries |
| 409 | Another node has this name, or this key is paired |

## Key rotation

Both keys of a pairing can be replaced without pairing again
([spec/protocol.md](spec/protocol.md) §4.10). The side whose
key changes starts it on its owner's command; the new key goes over the
live link, signed by the old one, and the old key stays valid for a grace of
7 days.

| Key | Started by | Code |
|---|---|---|
| The node's key for a center | `nerve-node center rotate-key` | `crates/nerve-node/src/rotate.rs`, `Center::rotate_node_key` |
| The center's TLS key | the web UI (Settings, Center key) | `Center::rotate_key`, `crate::rotate::center_rotated` on the node |

- The node id stays the one of the first key. The center keeps the node's
  old key beside the new one (`old_key` in `state.json`) until the grace
  ends or the node ends it (`key.retire`).
- The node keeps its new key aside (`keys/<name>.next.key`, or its keyring
  entry) until the center answered; no answer sends it again on the next
  link, so a rotation the center took is never lost.
- The center keeps its new key in `tls.next.pem`, serves the old one during
  the grace so that nodes away for a while can still be told, then moves the
  new one to `tls.pem`. A start that finds a half-made rotation keeps the
  old key. The node keeps the old pin as `old_pin` until the grace ends.
- Each rotation is in the node's audit log and the center's log.

## Unpairing

Both sides can end a pairing.

- **From the node.** `nerve-node center rm` sends `bye {reason: "unpaired"}` if
  a link is up, and deletes the key. The center forgets the node when it sees
  that.
- **From the center.** Removing the node in the web UI sends
  `bye {reason: "revoked"}` and closes the link. The node stops dialling that
  center and keeps the key until `center rm`, so the owner can see what
  happened.
