# Nerve Protocol, version "0"

This is the wire protocol between a **node** (a machine that offers
capabilities) and a **center** (the server harnesses plug into). The
implementations in this repository are `nerve-node` and `nerve-center`. The
conformance suite in `crates/nerve-conformance` checks the rules below; each
check names the section it tests.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Versions

- The protocol version is the string `"0"`. A node lists the versions it
  speaks in `hello.versions`; the center picks one it speaks too and names it in
  `welcome.version`. Version `"0"` matches only `"0"` exactly.
- If no version matches, the center sends `bye {reason: "unsupported_version"}`
  and closes. The node stops dialling that center.
- The descriptor carries `nerve: "0"`.

### 1.1 Features

Additive parts of version `"0"` are named features. A side uses a feature's
messages only when both sides named it; a peer older than a feature keeps
working without it.

- A node lists the features it speaks in `hello.features` (§4.2). A node
  older than features sends no such field.
- The center answers in `welcome.features` with those of them it speaks too,
  and only when the hello had the field: a node is strict about the welcome
  (§5.2), and an older one would refuse a field it does not know.
- A feature name a side does not know is ignored.

| Feature | Since | Section |
|---|---|---|
| `rotate` | nerve 0.0.4 | key rotation, §4.10 |

## 2. Identity

### 2.1 Center

- The center holds a TLS key and a self-signed certificate. Its **pin** is the
  base64url (no padding) SHA-256 of the certificate's SubjectPublicKeyInfo, 43
  characters.
- The center has an id (a UUID-shaped random string) and a name.

### 2.2 Node

- A node holds one Ed25519 key per center it is paired with.
- The **node id** is the lowercase base32 (RFC 4648 alphabet, no padding) of the
  first 16 bytes of SHA-256 of the 32-byte raw public key it paired with: 26
  characters. It stays when the key is rotated (§4.10).
- A **node name** is 1 to 32 characters of `a-z`, `0-9` and `-`, starting and
  ending with a letter or digit (like a DNS label). The default is
  derived from the host name.

## 3. Pairing

### 3.1 Pairing link

```
nerve://pair?center=<percent-encoded center URL>&code=<code>&pin=<pin>
```

- `center` is an `https://` URL, or `http://` to a loopback address. No user
  info, query or fragment; the path MUST NOT contain `.` or `..` segments.
- `code` is 1 to 64 characters `A-Za-z0-9`. `pin` is optional; without it the
  node checks the certificate against the system roots.
- A parser MUST refuse: unknown keys, a key given twice, bad percent escapes, a
  fragment, a link longer than 4096 bytes.
- The node MUST show the owner the center URL and the defaults it will store
  (mode `allowlist` with no rule, so every call is refused until the owner
  allows something; settings grant `off`) and store nothing before the
  owner confirms.

### 3.2 Pair request

`POST <center>/nerve/v0/pair` with `Content-Type: application/json`:

```json
{"code": "…", "name": "laptop", "platform": "linux", "arch": "x86_64",
 "public_key": "<64 hex chars>"}
```

Unknown fields are refused. Answers:

| Status | Body | Meaning |
|---|---|---|
| 200 | `{"center_id", "center_name", "node_id"}` | paired |
| 400 | `{"error"}` | malformed request or name |
| 403 | `{"error"}` | code unknown, used, expired or out of tries |
| 409 | `{"error"}` | another node already has this name or key, the name is a node's id, or another node is named like this node's id |

- A code is valid for the lifetime the owner set when it was made (10 minutes
  by default, at most 24 hours), for one successful pairing, and for 10 tries
  in all; a wrong code counts against every open code.
- The center MUST compute `node_id` from `public_key` itself.

Before it asks the owner, a node MAY check the code without using it:
`POST <center>/nerve/v0/pair/check` with `{"code": "…"}`, over the same TLS
(and pin) as the pair request. The answer is `200 {"code": "open" | "used" |
"gone" | "busy"}`: it could pair now; a node paired with it; unknown,
expired or out of tries; or the center says nothing now. A check MUST NOT use
the code up or count as a try. A check with a code that is not open counts
against a budget of the center's (10 in 10 minutes, for every code alike);
once it is spent, the center answers `busy` to every check, a right code's
too, until the window ends, so checks are no cheaper way to guess a code than
pair requests. A center without the path answers `404`; the node then pairs
without knowing.

### 3.3 Unpairing

- The node owner unpairs: the node sends `bye {reason: "unpaired"}` if a link
  is up, deletes its key, and the center forgets the node when it sees that bye.
- The center owner removes a node: the center sends `bye {reason: "revoked"}`
  and closes; the node stops dialling that center (it keeps its key so the
  owner can see what happened, until `center rm`).

## 4. Link

### 4.1 Connect

- The node opens `GET <center>/nerve/v0/connect` as a WebSocket, with the
  header `Nerve-Node: <node id>`. Over `https` the node checks the pin (or
  system roots). Over `http` only loopback is allowed, and on Linux the node
  MUST check that the listening socket belongs to its own user.
- An unknown node id is answered with HTTP 401. The node stops dialling and
  tells the owner the center no longer knows it.

### 4.2 Handshake

1. Center → node, notification `challenge {nonce, center_id}`: `nonce` is 32
   random bytes as 64 hex characters.
2. Node → center, notification `hello`:
   ```json
   {"node_id": "…", "auth": {"sig": "<128 hex>"}, "versions": ["0"],
    "software": {"name": "nerve-node", "version": "…"},
    "limits": {"message_bytes": 4194304, "blob_bytes": 67108864, "calls": 64, "streams": 16},
    "rev": 7, "features": ["rotate"], "resume": {"link": "<32 hex>", "got": 0}}
   ```
   `sig` is the Ed25519 signature over the bytes
   `"nerve-connect/0" || center_id (UTF-8) || nonce (32 raw bytes)`, with
   the node's key for this center, or with its old key while the grace of a
   rotation runs (§4.10). `features` is optional (§1.1). `resume` is
   optional; a node that can resume links sends it (§4.9).
3. Center → node, notification `welcome {version, limits, features?, resume?}`.
   `features` is sent only when the hello had it (§1.1). `resume {resumed,
   got}` answers the hello's `resume` and is sent only when the hello had one
   (§4.9).

Before `welcome`, any other message is a protocol error: the receiver sends
`bye {reason: "protocol_error"}` and closes. A wrong signature or a `node_id`
that differs from the header closes with `protocol_error`. Each side has 15
seconds for its handshake step.

After `welcome` the center fetches the descriptor with `describe {detail:
"full"}`.

### 4.3 One live link per node

When a second link authenticates for a node that already has one, the center
sends a WebSocket ping on the held link and waits 3 seconds. If the held link
answers, the new link is refused with `bye {reason: "duplicate"}` and the
center raises an alert (a copied key). If not, the held link is closed with
`bye {reason: "replaced"}` and the new link takes its place.

### 4.4 Liveness

The node pings every 20 seconds. Either side treats 45 seconds without any
frame as a dead link.

### 4.5 Ending a link

`bye {reason}` is the last message on a link. Reasons: `shutdown`, `paused`,
`unpaired`, `revoked`, `duplicate`, `replaced`, `unsupported_version`,
`protocol_error`. The node MUST stop dialling after `revoked`, `unpaired` and
`unsupported_version`. A node that knows it is about to lose the network (a
suspend, an address change) sends the event `node/going_away {reason}` first,
so the center can show why it dropped.

When a link ends with a `bye`, or drops and is not resumed (§4.9), calls in
flight on it fail with `connection_lost`, and commands it started are killed.

### 4.6 Reconnect

The node redials with a back-off starting at 1 second and doubling to 60
seconds; each wait loses a random part of up to 10 %. The back-off resets once
a link has lasted 60 seconds.

### 4.7 Proxies

A node MAY reach a center over an HTTP `CONNECT` proxy (`connection.proxy` in
its config, else `HTTPS_PROXY`/`NO_PROXY`). The inner TLS is still pinned. If
the proxy fails the node does not fall back to a direct connection. The pair
request (§3.2) to an `https` center goes through the same proxy.

An `http://` proxy takes the `CONNECT` in plain HTTP. An `https://` proxy is
reached over TLS of its own first, checked against `connection.pin` as a
center's certificate is against its pin (§2.1), else against the system
roots; the `CONNECT` and its `Proxy-Authorization` travel inside that TLS,
and the link's own TLS to the center inside the tunnel.

### 4.8 Relays

A node in a network that reaches no center MAY reach one through another
node, its **relay** (a jump node). This is a transport binding below the
message layer: the relay carries bytes, never messages.

- The relayed node names the relay as its `https://` proxy (§4.7) with the
  pin of the relay's certificate, and authenticates with
  `Proxy-Authorization: Basic base64(<name>:<token>)`, the relay node name and
  token the relay's owner gave it. Everything above the tunnel is the relayed
  node's link as without a relay: TLS to the center with its pin, the
  `Nerve-Node` header and the signed `hello`, end to end.
- A relay is off unless its owner turns it on. It speaks TLS only, with a
  certificate of its own (its key kept as the node's other keys are). A
  connection that does not start with a TLS handshake is answered `400` in
  plain HTTP and closed; nothing it sent is used. Over TLS it answers
  `CONNECT host:port` only:
  - `407` with `Proxy-Authenticate: Basic` unless the name and token are
    those of a node it knows. It MUST check this before it looks at the
    target, so a peer without a token learns nothing of its centers;
  - `403` unless `host:port` is the host (without case) and port of an
    `https` center the relay itself is paired with, that has not revoked it
    and still knows it (no `bye revoked`, no 401), and, when the owner gave
    the node a list of centers, every such center at that host and port is
    on the list (centers behind one reverse proxy share it; the relay cannot
    tell them apart, so it grants them together or not at all). A center off
    the list MUST get the same answer as one the relay does not have. The
    relay MUST NOT
    open a tunnel anywhere else: not to an `http` center (it is on the
    relay's loopback), not to any other port of its machine or network. An
    `https` center the relay is paired with at a loopback address (or
    `localhost`) is a target; a center paired at a name is not reached on
    this machine: when the relay dials it directly and the name resolves to
    a loopback or unspecified address, the tunnel is refused with `502`.
    Through the relay's own proxy the next hop resolves the name;
  - `503` when it is off, when its node is locked, or when a limit is reached
    (tunnels at once over all nodes and per node, tunnels a node opens a
    minute);
  - `502` when it cannot reach the center;
  - `200` once it has a connection to the center. From then on it copies
    bytes both ways and nothing else.
- The relay dials the center as its own link would, through its own proxy if
  it has one (§4.7). A chain of relays follows the same rules at each hop:
  each one tunnels only to centers it is paired with itself.
- What a tunnel reaches is the center's host and port, from the relay's
  address: whatever is served there (other names and paths of a reverse
  proxy) as much as the center, since what goes inside the tunnel (the TLS
  server name, the HTTP `Host`, the path) is the relayed node's. An owner
  judges a token by that.
- A relay keeps at most a few undecided connections per peer address, a
  larger share per IPv6 /64 (which the machines of one LAN share), and a
  bounded number in all; one over any is closed unread. A machine with
  enough addresses in a /64 can take that /64's share. The first byte, TLS
  and the `CONNECT` head share one deadline of 15 seconds. A granted
  connection is a tunnel from then on, counted by the tunnel limits, and
  gives its undecided slot back before the relay dials, which has a deadline
  of its own. Refusals are not logged one by one but counted, with a token or
  without, so no peer can flood the relay's log; a count is told when its
  minute is over even if no refusal follows, and when the relay stops
  listening, and a node's refusals are counted apart from other nodes'. The
  relay's dial fits every address of the center into its deadline. A node opens a bounded
  number of tunnels a minute, so one with a token and the relay's limits
  cannot rotate the audit log either. These limits hold for every node; a relay behind this one,
  which carries many nodes, gets limits of its own as a node, so raising
  them for it raises them for no other token.
- Hosts are compared as a URL can tell them apart: without case or a
  trailing dot, and an address in any of its spellings. A name and the
  address it resolves to are not told apart.
- A relay MUST end a tunnel when its owner turns the relay off, takes the
  node's token away or the center off the node's list, unpairs the center or
  locks the node, and when the tunnel carried nothing either way for 90
  seconds by the monotonic clock (a link pings every 20 seconds, §4.4).
- A relay keeps no token in clear at rest. `nerve-node` keeps the SHA-256 of
  each token in `node.toml`. The relayed node keeps its token with its own
  keys.
- The relay writes one audit entry per tunnel when it ends: the node, the
  center, the peer's address, start, end, why it ended and the bytes each
  way; never a token.
- The relay can cut a relayed node off but cannot read or alter its link:
  an altered byte fails the TLS record, and the link ends before any message
  of it counts. The relayed node's policy is its own; the relay's policy is
  not asked, and no call runs on the relay for a tunnel.

### 4.9 Resume

A link that drops without a `bye` MAY be resumed on a new connection within a
grace of 30 seconds: calls in flight on it go on, and their results and the
events sent meanwhile arrive. Both sides must be able to; otherwise the link
ends as in §4.5. A resume sends a frame again only when the other side's count
shows it never read it, so a call that may have run never runs twice.

Link ids and counts:

- A node that can resume links sends `hello.resume {link, got}` on every
  connection. `link` names the link the connection carries: 16 random bytes
  as 32 lowercase hex characters, new for a new link. `got` is how many
  counted frames of that link the node read (0 for a new link).
- A center that can resume links answers `welcome.resume {resumed, got}`,
  and only to a hello with `resume` (a node is strict about `welcome`).
  `resumed: true` carries the named link on, and `got` is how many counted
  frames of it the center read. `resumed: false` starts a new link with that
  id, with `got` 0. A welcome without `resume` means the center cannot resume
  links; the node then treats the link as one that cannot resume.
- A hello whose `resume.link` is not 32 lowercase hex characters is refused
  with `bye {reason: "protocol_error"}`.
- **Counted frames** are the text frames a side sends after `welcome`, except
  `ack` and `bye`. Each side numbers the counted frames it sends from 1 over
  the whole link, across resumes, and counts the counted frames it reads.
  Binary frames are not counted; version "0" sends none a resume needs.

Keeping and acknowledging, on a link that can resume:

- Each side keeps the counted frames it sent until the other side
  acknowledges them. The notification `ack {got}` (either direction) says the
  sender read the first `got` counted frames of the link. A side sends one at
  most every 5 seconds, when its count moved since its last `ack` or
  handshake. An `ack` whose `got` is below an earlier one or above what was
  sent ends the link with `bye {reason: "protocol_error"}`; on a link that
  cannot resume an `ack` is ignored.
- A side keeps at most 16 MiB of frames the other side has not acknowledged,
  dropping the oldest past that. While it lacks a frame the other side has
  not acknowledged, the link cannot resume.

Drop and grace:

- A link that ends without a `bye` (the connection closed or failed, or §4.4's
  45 seconds passed) is kept by each side for 30 seconds from when that side
  noticed: its calls stay in flight, its commands run on, and what the side
  sends meanwhile is kept as above. The center shows the node offline and
  answers new calls with `unavailable`. A link that ends with a `bye`, from
  either side, ends at once (§4.5). So does a connection that ends because
  the receiver cannot take a frame (over its message limit, or not a valid
  WebSocket frame): the frame would be sent again on every resume, so the
  receiver ends the link with `bye {reason: "protocol_error"}`. That `bye`
  may not arrive: the receiver closes with the rest of the frame unread, and
  the reset this makes can drop it (Windows does). The sender, center or
  node, then sees a dropped connection and keeps the link like any dropped
  one. The node's next hello ends it on both sides: the node names a new link
  (it ended the link itself) or is answered `resumed: false` (the center
  did). Without a next hello, the grace ends it.
- The node offers the link in the hello of its next connection while the
  grace lasts and it still keeps every frame the center may lack. Once it
  sent that hello it keeps the link until the `welcome` comes (at most the
  15 seconds of §4.2), even past the grace. A welcome that does not carry the
  link on ends it; a handshake that fails leaves it to the next connection
  while the grace lasts.
- The center carries the link on when it still holds the link the hello names
  for that node, it has read at least one counted frame of it, `got` lies
  between what the node acknowledged and what the center sent, and the center
  keeps every frame after `got`. The node sends nothing counted before it
  reads the `welcome`, so a link of which the center read nothing may be one
  whose `resumed: false` the node never got; the node then still holds the
  older link of that id, which must not be taken for the new one. Otherwise it
  answers `resumed: false` and ends the link it held: its calls fail with
  `connection_lost`. A held link that does not answer the ping of §4.3 is
  replaced, and may be carried on the same way. A frame that arrives later on
  the replaced connection is not the link's and is dropped.
- After the grace, a link not resumed ends as in §4.5: the center fails its
  calls with `connection_lost`, the node kills its commands.

Replay:

- After `welcome`, each side first sends again, in order and unchanged, the
  counted frames after the other side's `got`, then new frames. The node
  checks the center's `got` like an `ack`.
- A request the node read is never sent again: an `invoke` the node read may
  have run. Its result comes from the node's kept frames, or when the call
  finishes. An `invoke` the node did not read has not run, and is sent again
  with its id, unless no one waits for it any more (its caller timed out or
  cancelled): then the center sends the notification `withdrawn {id}` in its
  place, which keeps the count, and the node ignores it.
- `seq` of events and state goes on counting on the resumed link.
- After a resume the center fetches the descriptor again, as it may have
  changed while the link was down.

### 4.10 Key rotation

Feature `rotate` (§1.1). Either key of a pairing can be replaced without
pairing again: the node's key for the center, and the center's TLS key that
nodes pin. The side whose key changes starts it, when its owner asks;
nothing rotates on its own. The new key travels over the paired,
authenticated link, signed by the key it replaces. The replaced key stays
valid for a **grace** of 7 days (604800000 ms) after the rotation, then it is
refused; the owner of the side whose key changed can end the grace earlier.
There is at most one old key per side. A node key rotation in the grace of
another one ends that other grace at once; the center refuses a rotation of
its own key while one is in its grace, until the owner ends that grace. When
the grace of a node's old key ends, in whatever way, a link that was opened
with that key ends with `bye {reason: "replaced"}`.

A peer that does not speak `rotate` cannot rotate. A node that does not
speak it is not told of a center's new key, and after the center's grace it
has to pair again.

#### Node key

1. Node → center, notification `key.rotate {public_key, sig, proof}`:
   `public_key` is the new Ed25519 key (64 hex), `sig` the signature of the
   node's current key and `proof` the one of the new key, both hex, over
   `"nerve-rotate-node/0" || center_id (UTF-8) || new public key (32 raw bytes)`.
2. The center takes the new key only when `proof` verifies under it and
   `sig` verifies under the key it holds for the node now, and no other
   node holds the new key (as its key or its old one). The key it held
   becomes the old key, valid until the grace ends. The node id does not
   change. A `key.rotate` for the key the center holds already (sent again)
   changes nothing and is answered as taken.
3. Center → node, notification `key.rotated {public_key, error?}`: without
   `error` the center took `public_key`; with it, it refused and keeps the
   key it had.

A center saves the new key before it answers that it took it: the node
deletes its old key on that answer. A center that cannot save it answers
with an `error` and keeps the key it had.

The node keeps the new key aside before it sends it, and makes it its key
only when `key.rotated` says it was taken, also when that answer comes after
the node stopped waiting for it. On a refusal it drops it. Without an answer
it keeps both, signs with the old one, and sends the same `key.rotate` again
on its next link. A `hello` may be signed with the old key until the grace
ends (§4.2). While the new key waits for an answer, a node whose handshake
fails tries the next one with the new key: a center that took the new key
and whose grace for the old one has ended still links it; a link that comes
up so settles the rotation as taken.

To end the grace early, node → center `key.retire {public_key, sig}`:
`public_key` is the node's current key, `sig` its signature (hex) over
`"nerve-retire-node/0" || center_id || that public key (32 raw bytes)`. The
center drops the old key and answers `key.retired {error?}`. A link that was
opened with the old key then ends with `bye {reason: "replaced"}`; the node
dials again with its key.

#### Center key

1. The center makes a new key and signs it with the old one. It keeps
   serving the old key, so that every node can still link and be told.
2. Center → node, notification `center.rotate {old_spki, new_spki, sig,
   grace_ms}`, on every link up now and on every link made later while the
   rotation is told: `old_spki` and `new_spki` are the SubjectPublicKeyInfo
   of the old and the new key in DER, `sig` the old key's signature over
   `"nerve-rotate-center/0" || center_id (UTF-8) || new pin (its 32 raw
   bytes)`, all three base64url without padding. The signature is ECDSA
   with SHA-256 (P-256) or SHA-384 (P-384) in ASN.1 form, or Ed25519, as the
   old key is. `grace_ms` is how long the center still serves the old key.
3. A node that pins the center checks that the pin of `old_spki` is the pin
   it holds and that `sig` verifies under `old_spki`. Then it pins the new
   key and takes the old pin as well until `min(grace_ms, 7 days)` from now.
   A rotation that does not verify changes nothing. A node that checks the
   center against system roots (no pin) ignores it. Once the old pin's time
   is over, new connections no longer take it. A connection the node opened
   under the old pin ends 15 seconds after that time (longer than the
   center takes to serve its new key at the end of its grace), or at once
   when the center tells `grace_ms: 0`; then the node drops the old pin from
   its config and dials again with the pins it still takes (a link that can
   resume, resumes). Pins are compared by their 32 bytes: a pin written
   with base64 padding is the same pin.
4. At the end of the grace, or when the owner ends it earlier, the center
   serves the new key for every new connection; links up then go on. It
   goes on telling the rotation with `grace_ms: 0` until 7 days after it
   started, and a node that is told so drops the old pin at once.

Pairing links carry the pin of the key the center serves. A node that
paired during the grace is told on its first link.

With resume (§4.9): the key messages are counted frames, so one that a drop
cut off goes out again when the link resumes. A resumed link goes on under
the key its resuming hello was signed with. A link the center ends because
its key's grace ended ends with a `bye` and is not resumed.

## 5. Messages

Text frames carry JSON-RPC 2.0. No batches; `params` is always an object.
Errors carry a string code in `error.data.code` (§5.3).

### 5.1 Methods

| Method | Kind | Direction | Params | Result |
|---|---|---|---|---|
| `challenge` | notification | C→N | `{nonce, center_id}` | |
| `hello` | notification | N→C | see §4.2 | |
| `welcome` | notification | C→N | `{version, limits}` | |
| `describe` | request | C→N | `{detail, cap?}` | descriptor (§6) |
| `invoke` | request | C→N | `{cap, action, args, ctx, deadline_ms?, blobs?}` | action result |
| `progress` | notification | N→C | `{id, data}` | |
| `cancel` | notification | C→N | `{id}` | |
| `get` | request | C→N | `{cap, keys}` | `{key: value}` |
| `sub` / `unsub` | request | C→N | `{topics}` | `{}` |
| `event` | notification | N→C | `{cap, name, seq, ts, data}` | |
| `state` | notification | N→C | `{cap, seq, ts, changed}` | |
| `stream.open` | request | C→N | `{cap, stream, params}` | `{sid}` |
| `stream.close` | request | either | `{sid, reason}` | `{}` |
| `session.end` | notification | C→N | `{session}` | |
| `bye` | notification | either | `{reason}` | |
| `ack` | notification | either | `{got}` | (§4.9) |
| `withdrawn` | notification | C→N | `{id}` | (§4.9) |
| `key.rotate` | notification | N→C | `{public_key, sig, proof}` (§4.10) | |
| `key.rotated` | notification | C→N | `{public_key, error?}` | |
| `key.retire` | notification | N→C | `{public_key, sig}` | |
| `key.retired` | notification | C→N | `{error?}` | |
| `center.rotate` | notification | C→N | `{old_spki, new_spki, sig, grace_ms}` | |

- `detail` is `summary`, `capability` (needs `cap`) or `full`.
- `ctx` is `{session?}`: `session` is at most 256 bytes. Other fields are
  refused. There is no field for "allowed", a mode or a folder.
- `deadline_ms` is a duration in milliseconds from receipt; past it the node
  fails the call with `timeout`.
- `progress.id` and `cancel.id` are the `invoke` request id. An `invoke` id
  is an integer of 0 or more, since `exec.signal` and the `exec/exit` event
  name a call by it (§7.3); a node refuses an `invoke` with a string id
  (`invalid_request`). Other requests may use either.
- Topics are `<cap>/<event>`, `<cap>/state` or `<cap>/*`. Events of the `node`
  and `settings` capabilities are implicit: they are sent without
  `sub`. Everything else needs one.
- `seq` counts per capability from 1 within a link, across its resumes
  (§4.9); `ts` is milliseconds since the Unix epoch.

### 5.2 Strictness

A node MUST be strict about what a center sends: unknown fields in `invoke`,
`ctx`, `challenge`, `welcome`, `key.rotated`, `key.retired` and
`center.rotate`, and unknown methods, are refused. A center SHOULD be
tolerant of unknown fields a node sends, so newer nodes keep working.

### 5.3 Error codes

| Code | JSON-RPC code | Meaning |
|---|---|---|
| `invalid_args` | -32602 | arguments do not match the action (§6.1) |
| `forbidden` | -32001 | policy refuses: no rule allows the call, or a rule forbids it |
| `disabled` | -32004 | the capability or action is off |
| `unavailable` | -32005 | the node or capability is not reachable now |
| `busy` | -32006 | too many calls or commands running |
| `timeout` | -32007 | the deadline passed |
| `cancelled` | -32008 | cancelled by the caller |
| `too_large` | -32009 | over a size limit |
| `unknown_capability` | -32010 | no such capability (or hidden) |
| `unknown_member` | -32011 | no such action, event or stream |
| `connection_lost` | -32012 | the link ended during the call |
| `internal` | -32603 | a bug or an unexpected failure |

Profiles add codes of their own: `conflict` (stale `if_match`/`if_version`),
`bad_path`, `io`. Their JSON-RPC code is -32000. `parse`, `invalid_request` and
`method_not_found` use the JSON-RPC codes -32700, -32600 and -32601.

### 5.4 Binary frames

Binary WebSocket frames have a 10-byte header, big-endian:

```
u8 kind | u8 flags | u32 id | u32 seq | payload (at most 65536 bytes)
```

- kind 1: blob chunk. `id` is the blob id named as `{"$blob": id}` in a JSON
  message and listed in `invoke.blobs`; `seq` counts from 0; flag bit 0 marks
  the last chunk. A blob larger than `limits.blob_bytes` fails with `too_large`.
- kind 2: reliable stream data; `id` is the stream's `sid`.
- kind 3: media, reserved. In version "0" it is refused (`protocol_error`).

Each side keeps at most 64 frames queued for sending; a full queue pushes back
on the producer.

### 5.5 Limits

`limits` in `hello` and `welcome` announce what each side accepts: message
bytes (default 4 MiB), blob bytes (64 MiB), concurrent calls (64), streams (16).
A message over the receiver's limit closes the link with `protocol_error`; a
call over the call limit fails with `busy`. A node does not send an answer
over the center's message limit: the call fails with `too_large` instead.

## 6. Descriptor

```json
{"nerve": "0",
 "node": {"id": "…", "name": "laptop", "platform": "linux", "arch": "x86_64",
          "software": {"name": "nerve-node", "version": "…"}},
 "rev": 7,
 "summary": "Linux laptop of the owner (under 60 words)",
 "capabilities": [
   {"id": "fs", "profile": "fs", "provider": "node", "exposure": "on",
    "summary": "…",
    "actions": {"read": {"effect": "read", "summary": "…",
                         "params": {JSON Schema}, "result": {JSON Schema}},
                "write": {"effect": "write", "exposure": "off", …}},
    "events": {}, "state": null, "streams": {}}],
 "access": {"mode": "folder", "until_ms": 1792936800000, "account": "nerve-run",
            "confined": true,
            "folders": [{"path": "/home/me/proj", "access": "rw"},
                        {"path": "/tmp", "access": "rwx"}]}}
```

- Capability ids and action names are 1 to 64 bytes of ASCII letters,
  digits, `-` and `_`, never `.`: the harness side names an action
  `<cap>.<action>` (`docs/dev/spec/harness.md` §4.1), and a `.` inside a part
  would make that name ambiguous. Ids are unique within a descriptor. A node
  refuses a provider that declares another name (node-local.md §7), and
  `schemas/descriptor.schema.json` says the same. A center leaves out every
  action of a capability whose id is outside that set, is longer than 64
  bytes or is given twice, and an action whose name is outside that set or
  longer than 64 bytes; it keeps the rest of the descriptor.
- Effects: `read`, `sense`, `write`, `actuate`, `execute`.
- `provider` names what serves a capability: `node`, or a local program
  attached to the node (node-local.md §7). A center treats both alike; the
  node decides every call either way.
- Exposure: `on`, `off`. A capability that is `hidden` for a center is
  absent from that center's descriptor; `off` is listed with exposure `off`.
  An action the owner switched off while its capability stays on carries
  `"exposure": "off"` itself (absent means on); a call of it fails
  `disabled`. The actions of a capability that is `off` carry it too.
- `access` says what this center may do on the node now (§6.2). It is
  for that center alone, like the rest of the descriptor.
- The descriptor is filtered per center. `rev` changes whenever that center's
  view changes; the node then sends `node/descriptor_changed {rev}` and the
  center fetches the descriptor again.
- `detail: "summary"` drops `params`, `result` and schemas;
  `"capability"` returns only `cap`, in full; `"full"` returns everything.
  `access` is in every detail.

### 6.1 Schemas

`params` (an action's arguments), `result`, an event's `data` and `state`
are JSON Schemas of a small subset of JSON Schema 2020-12. A center shows
them to a model and checks each call's arguments against them, and the node
checks them again, so a schema must mean the same at every end. A schema is
in the subset when:

- Each schema object names `type`, `enum` or `const`. `type` is one of
  `null`, `boolean`, `object`, `array`, `number`, `integer`, `string`, or a
  pair of one of them and `"null"` (`["integer", "null"]`).
- It uses only these keywords: `type`, `properties`, `required`,
  `additionalProperties` (`true` or `false`), `items` (one schema), `enum`,
  `const`, `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`,
  `minLength`, `maxLength`, `minItems`, `maxItems`, `default`,
  `description`, `title`, `examples`, `$schema` (only
  `https://json-schema.org/draft/2020-12/schema`, only at the root) and
  `x-nerve-path` (`"read"` or `"write"`: the string is a path the action
  reads or writes; only its value is checked for now).
- A keyword fits its type: `properties`, `required` and
  `additionalProperties` need `object`; `items`, `minItems` and `maxItems`
  `array`; `minLength`, `maxLength` and `x-nerve-path` `string`; the
  numeric bounds `integer` or `number`. `required` names each property once,
  and only properties that `properties` names. `enum` is not empty, and its
  values and `const` fit the type. No pair of bounds leaves nothing between
  them: of `minimum` and `exclusiveMinimum` the tighter counts (the same for
  the upper pair), and for `integer` there must be a whole number between
  them. Each value of `enum` and the `const` keeps to the schema's bounds.
  With both, the `const` is one of the `enum`; the other `enum` values need
  not equal it.
- The arguments schema's root is `{"type": "object", …}`. It nests at most 3
  levels deep, a result, event data or state at most 4: the root is level 1,
  and a property's or an array's items schema is one level below its
  parent's.
- One object names at most 32 properties, one `enum` lists at most 256
  values, and the schema takes at most 16 KiB as compact JSON.

Everything else is refused, among it `$ref` and `$defs`, `oneOf`, `anyOf`,
`allOf` and `not`, `if`, `then` and `else`, `patternProperties`, `pattern`
and `format`, and any keyword the list does not name. What a text must look
like goes into `description`; a choice of values is an `enum`.

An action without `params` takes any object of arguments, as
`{"type": "object"}`; without `result` (or an event without `data`) the
descriptor says nothing of it. A center leaves out an action whose schemas
are outside the subset, with the reason, and offers the rest; it leaves out
every action of a capability whose `state` or an event's `data` is outside
it. The owner sees what was left out (harness.md §7). A node does not attach a provider's action
whose schemas are outside it (node-local.md §7).

Arguments fit a schema when their value has its type, takes a value of
`enum` or the `const`, keeps to its bounds, has every `required` field, and,
with `additionalProperties: false`, no field `properties` does not name; the
same holds for each field and item. An `integer` is a number without a
fraction or an exponent, so `5.0` is not one. `enum` and `const` compare
numbers by value, as JSON Schema does: `1.0` is one of `[0.5, 1, 2]` (but
still not an `integer`). `default` is a hint for the caller; neither end
fills it in. An argument that may be left out and whose
`null` the node reads as left out says so with `null` in its type
(`["integer", "null"]`), as the node's own do. Arguments that do not fit are refused with
`invalid_args` whose `data` holds `field`, the dotted path to what does not
fit (`sudo.sealed`, `entries[2].name`, empty for the arguments as a whole),
and `expected`, in words (`an integer from 1 to 600`).

### 6.2 What the center may do (`access`)

The node tells each center its own mode and folders, so the agent behind it
does not have to guess paths and collect refusals. The block is built from
that center's pairing alone: no other center's mode, account or folders are
ever in it.

| Field | |
|---|---|
| `mode` | `allowlist`, `folder` or `user`: the mode in force now (a `folder` or `user` mode whose `until` has passed is `allowlist`) |
| `until_ms` | when a `folder` or `user` mode ends, in milliseconds since the epoch; absent when it does not end, and in `allowlist` mode |
| `account` | the account this center's commands run as: `nerve-run` or the owner on the installed node, the node's own user on a node run by hand; absent when the node cannot name it |
| `confined` | in `folder` mode: whether the machine holds commands to the folders (Landlock, a Windows AppContainer, or `nerve-run` held by its own account), so `exec.run` is offered; always `false` in the other modes |
| `folders` | in `folder` mode only: the folders the center's file calls and commands may use, each `{path, access}`. `path` is absolute in the center's form (`/c/Users/me` for `C:\Users\me`), `access` is one to three of `r` (read), `w` (write) and `x` (run commands) in that order. Where the commands run as `nerve-run`, its built-in folders (`/tmp`, `/var/tmp` and its home, all `rwx`) are among them. A place is named once, with the flags of all its grants together; a folder without a flag is left out. Absent or empty in the other modes, where folders decide nothing |

A grant, a mode or its end, or another account changes the block and so
`rev` (§6). It describes the policy as it is now; the node still decides
every call (§5). A center reads the block tolerantly: one it cannot read is
taken as absent, and the rest of the descriptor stays.

## 7. Profiles

Shapes are given as `params → result`. Paths are absolute; on Windows they use
the wire form `/c/Users/…`.

### 7.1 `node` (always present)

- state: `{status: "online" | "busy" | "paused"}`.
- events (implicit): `descriptor_changed {rev}`, `going_away {reason}`,
  `capability_changed {cap}`.

### 7.2 `fs`

| Action | Effect | Params → result |
|---|---|---|
| `stat` | read | `{path}` → `{type: "file"|"dir"|"link"|"other", size, mtime_ms}` |
| `list` | read | `{path}` → `{entries: [{name, type, size}]}` |
| `read` | read | `{path, offset?, length?}` → `{content, encoding: "utf8"|"base64", size, etag}` |
| `grep` | read | `{path, pattern, glob?, max?}` → `{matches: [{path, line, text}], truncated}` |
| `find` | read | `{path, glob, max?}` → `{paths, truncated}` |
| `write` | write | `{path, content, encoding?, if_match?}` → `{etag, size}` |

`etag` is the hex SHA-256 of the file's bytes. A `write` with an `if_match`
that no longer matches fails with `conflict`. fs and exec calls run
concurrently.

### 7.3 `exec`

| Action | Effect | Params → result |
|---|---|---|
| `run` | execute | `{command, cwd?, timeout_ms?, memory_mb?, cpu_percent?, processes?}` → `{exit_code, signal?, stdout, stderr, truncated, killed?, reason?}` |
| `signal` | actuate | `{call, signal: "term"|"kill"|"int"}` → `{}` |

- `command` is a string run by the node's shell. `call` is the `invoke` id of a
  running `run`, an integer (§5.1).
- `timeout_ms` is the longest the command may run; 0 is the same as none.
  A node ends every command: one without `timeout_ms` gets the node's
  default, one with a larger value gets the node's maximum, and past its limit
  the command is killed and the call fails with `timeout`. Both numbers are
  the owner's (`limits` of `node.toml`, node-local §2). The descriptor states
  them in the action's text, as the `default` of the `timeout_ms`
  parameter and in its `description`, in milliseconds; it has no `maximum`,
  as a larger value is cut to the most and not refused. A change of either
  changes `exec.run`'s schema, so a harness lists it again before its next
  run (harness.md §4.3).
- state: `{shell, confinement}`; event `exit {call, exit_code}` (needs `sub`).
- Output is capped at `limits.output_cap_bytes` of the node's config;
  `truncated` says it was cut.
- `memory_mb`, `cpu_percent` (100 is one CPU) and `processes` are the
  limits of the command (node-local §2, Commands). Each one left out is the
  node's default; one above the node's most, or 0, fails with
  `invalid_args`, whose message names the most. The descriptor gives each
  default and most as the parameter's `default` and `maximum`. A command
  the node killed because it went past its own memory limit has `killed:
  "memory"` and a `reason` in its result (and `signal: "kill"`); one an OOM
  of the machine killed has only `signal: "kill"`. Output comes in the result; the
  `output` reliable stream is declared for later.

### 7.4 `settings` (only with the settings grant `write`)

- `get {cap: "settings", keys: ["document", "version"]}` → `{document,
  version}`; `document` is this center's entry of the node config (policy,
  folders, caps, command rules).
- actions: `set {document, if_version}` → `{version}` (effect `write`); a stale
  `if_version` fails with `conflict`; a change to a client-only field refuses
  the whole document with `forbidden` and names the field. One field of the
  document is the owner's without being refused: `policy.places`, the node's
  record of the folders it recorded at their real place. A `set` keeps it as
  it was (less the entries of folders the document removes), whatever the
  document says there. `pause {}` → `{}`.
- `get` key `sudo` → `{sudo: "on" | "off"}`: the node's sudo switch.
- event (implicit): `changed {version}`.

### 7.4.1 The sudo switch

A center with the settings grant `write` may switch the node's sudo switch
(node-local §4) on and off; it is the only machine setting a center may
change. The password travels sealed end to end from the client (the owner's
browser or tool) to the node; the center only relays it.

- `sudo-offer {}` → `{offer, key, ts, sig}` (effect `write`): `offer` is 16
  random bytes and `key` a fresh X25519 public key, both base64; `ts` is the
  node's clock in ms; `sig` is the hex Ed25519 signature, with the node's key
  for this center (§2.2), of the UTF-8 bytes
  `"nerve-sudo-offer\n" + center_id + "\n" + offer + "\n" + key + "\n" + ts`.
  A client checks it against the key the node paired with. A new offer
  replaces the center's open one.
- The client makes its own X25519 key, derives a key with HKDF-SHA256 (salt
  `"nerve-sudo-v1"`, info `offer`) from the shared secret, and seals the JSON
  `{password, offer, ts}` (its own clock in `ts`) with AES-256-GCM, a random
  12-byte nonce `iv` and `offer` as associated data.
- `sudo {on: true, sealed: {offer, key, iv, ct}}` → `{sudo: "on"}` (effect
  `write`; `key`, `iv` and `ct` base64). The node opens an offer at most once,
  right or wrong, and only within 60 s of making it; the inner `offer` must
  match and the inner `ts` be within 60 s of the node's clock. A replayed,
  late, tampered or foreign box is `invalid_args`, and so is a password that
  `sudo -v` refuses, or on Windows the account's logon (the message says the
  password is wrong; node-local §4); the switch then stays as it was.
- `sudo {on: false}` → `{sudo: "off"}` drops the password.
- The password never appears in a frame the node sends.

### 7.5 `audit`

- event `decision {ts, cap, action, target, decision, code?, session?}`
  (needs `sub`); `decision` is `allowed` or `forbidden`, or `killed` with
  `code: "memory"` for a command the node killed for its memory limit,
  after that call's `allowed`.

## 8. Center side

The center serves harnesses. `nerve-center` is an MCP server ([harness.md](harness.md)). It offers capabilities through two tools, `list` and `execute`, holds sessions, may refuse a call with its action checker before it reaches the node, and never stores file contents or command output; its one secret is the token of the checker's model endpoint.
