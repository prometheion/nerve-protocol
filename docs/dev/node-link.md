# The node link

The node dials the center and keeps one link open. Exact rules:
[spec/protocol.md](spec/protocol.md) §4 and §5.

## Connect

The node opens a WebSocket to `GET <center>/nerve/v0/connect` over TLS, checked
against the pin, with the header `Nerve-Node: <node_id>`. An unknown node id
gets HTTP 401. The node then stops dialling that center.

## Handshake

1. The center sends `challenge {nonce, center_id}`. The nonce is 32 random
   bytes.
2. The node answers `hello` with its versions, software, limits, descriptor
   `rev`, the features it speaks (possibly none) and the link it carries for a
   [resume](#resume). It signs `"nerve-connect/0" || center_id || nonce` with its Ed25519
   key for this center.
3. The center checks the signature and sends `welcome` with the version it
   picked, its limits, the features of the hello it speaks too, and whether
   it carries the link on. Both sides refuse a hello or a welcome without
   `features` or the resume: [key rotation](identity-and-pairing.md#key-rotation)
   and the resume are part of every link, and only later additions are named
   features.

No other message is valid before `welcome`. Each side has 15 seconds per step.
After `welcome` the center asks for the descriptor with `describe`.

## One live link

A node has one live link. When a second link authenticates for the same node id,
the center pings the held link and waits 3 seconds.

- If it answers, the new link is refused (`bye duplicate`) and the center raises
  an alert: the key exists twice.
- If it does not answer, the held link is closed (`bye replaced`) and the new
  one takes over.

## Liveness

The node sends a WebSocket ping every 20 seconds. A link on which nothing
arrived for 45 seconds is dead.

## Closing

`bye {reason}` is the last message. Reasons: `shutdown`, `paused`, `unpaired`,
`revoked`, `duplicate`, `replaced`, `unsupported_version`, `protocol_error`.

The node stops dialling after `revoked`, `unpaired` and `unsupported_version`.
It dials again after anything else. Before it shuts down, the node sends the
event `node/going_away {reason}`, so the center can tell "going away" from
"lost".

## Reconnect

The wait starts at 1 second and doubles up to 60 seconds. Up to 10 % is taken
off each wait at random. A link that lasted 60 seconds resets the wait.

## Resume

A link that drops without a bye is kept by both sides for 30 seconds, so an
address change or a short outage loses no output. Exact rules:
[spec/protocol.md](spec/protocol.md) §4.9.

- The node names its link in every hello (`resume {link, got}`); the center
  answers `welcome.resume {resumed, got}`. Each `got` counts the
  text frames that side read of the link, `ack` and `bye` aside.
- Both sides keep what they sent until the other side acknowledges it
  (`ack {got}`, every 5 seconds at most), up to 16 MiB.
- While the link is down, its commands run on and their results and events
  are kept. The center shows the node offline; the calls wait.
- On the resume each side sends again only what the other side's count shows
  it never read. A call the node read is never sent again, so nothing runs
  twice; one it did not read has not run and is sent again.
- The center carries on only a link of which it read something: the node
  sends nothing before it reads the welcome, so a link whose welcome may have
  been lost is never taken for an older link of the same id.
- A request the center no longer waits for (timed out or cancelled while the
  link was down) goes as `withdrawn {id}` instead, so it does not run late.
- What a frame carries of the sudo password is taken out once, when the frame
  is numbered; a kept frame does not wait for a later scrub.
- A link not resumed within 30 seconds, one that ended with a bye, and one
  whose kept frames passed 16 MiB end at once: the center fails the
  calls with `connection_lost`, and the node kills the commands started on
  that link.
- A frame the receiver cannot take (over its limit, or broken) would come
  again on every resume, so the receiver ends the link at once with
  `bye protocol_error`. That bye can be lost, as the receiver closes with the
  frame unread (Windows drops it on the reset). The sender then keeps the link
  as dropped, until the node's next hello ends it (a new link id, or
  `resumed: false`) or the grace does.

The node keeps its side in `LinkHandle` (`crates/nerve-node/src/daemon.rs`)
and the dropped link in `Parked` (`link.rs`); the center keeps it in its
`Link` (`crates/nerve-center/src/link.rs`), parked in its links map. The counts
and the kept frames are `nerve_proto::resume::Replay`, shared by both.

## HTTP proxy

A node can dial through an HTTP `CONNECT` proxy. The TLS link to the center
runs inside the tunnel, and the pin applies to it, so the proxy sees only TLS
records. If a configured proxy is down, the node does not dial directly.
Secrets of the proxy are in the system keyring, never in `node.toml`. See the
[proxy page](../user/proxy.md). The pair request goes through the proxy too.

## Relay

A node that reaches no center can dial through another node, its relay
([spec/protocol.md](spec/protocol.md) §4.8). The relayed node sets the relay
as its `https://` proxy with the relay's pin, with its relay token as the
proxy's user name and password; the token is kept with the node's keys. The
relay speaks TLS only, checks the token, tunnels only to its own `https`
centers (those the owner picked for that node, when it did), copies bytes,
and writes one audit entry per tunnel. TLS, the pin and the signed `hello` stay end to end: the relay can cut
the link but not read or change it. Code: `crates/nerve-node/src/relay.rs`;
its tests run the conformance node part through a relay, and a proxy below
the relay that reads and alters the bytes. See the
[relay page](../user/relay.md).

## Several centers

Each pairing has its own key, link, back-off, policy and grants. A node keeps
these apart per center:

- policy and its grants
- sessions
- audit entries (each names its center)
- the descriptor the center sees
- settings reads and writes

The limits that protect the machine are shared: running commands, output caps
and the audit log. `panic` and `unlock` act on every center at once.

## Messages and limits

The messages are JSON-RPC 2.0 text frames. Binary frames carry reliable
streams, with a 10-byte header and at most 64 KiB of payload.

| Limit | Default |
|---|---|
| Message | 4 MiB |
| Calls at once | 64 |
| Streams | 16 |
| Frames queued for sending | 64 per side |

Each side announces the limits for what it receives: the node in `hello`, the
center in `welcome`. A message over the limit closes the link with
`protocol_error`. A call over the call limit fails with `busy`. An answer
over the center's message limit is not sent: its call fails with
`too_large`.

A node parses what a center sends strictly: unknown fields and methods are
errors. A center reads what a node sends with tolerance, so newer nodes keep
working.
