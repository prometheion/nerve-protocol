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

## A relay, as the owner sets it up

A machine in a closed network may reach no center, while another machine
that runs a node reaches both that network and the center. That node can be
the first one's **relay** (a jump node): the first node dials its center
through it.

```
 relayed node ── TLS to the relay, pinned ──> relay (jump node) ── TCP ──> center
             └──────────── TLS to the center, pinned, end to end ────────┘
```

The relay carries bytes only. The relayed node's link is TLS to the center,
checked against the center's pin, and signed with the relayed node's own key,
as without a relay. The relay can cut a node off, but it cannot read the link
or change it: a changed byte breaks the TLS link, and the center never gets a
message from it.

The way to the relay is TLS too, with a certificate of the relay's own that
the relayed node pins. So nobody on the network between the two sees the
relayed node's token or where it goes. The relay speaks nothing else: a
node that tries plain HTTP is told so and gets no tunnel.

What the relayed node allows is its own business: its rules, folders and
mode decide every call, as on any node. The relay's rules play no part, and
no call runs on the relay for a node it carries.

### On the relay

Turn the relay on and give the other node a link:

```sh
nerve-node relay on 0.0.0.0:7490
nerve-node relay add lab-pc --address relay.example
```

`relay on` makes the relay's certificate the first time and shows its pin.
The relay's port, 7490, is not the [web UI](web-uis.md#the-nodes-web-ui)'s, 7470, and the
two have certificates of their own.
`relay add` makes the node's token and shows it once, in a link that holds
all the other node needs: the relay's address, the node's name and token,
and the pin.

```
relay node lab-pc added; its link, shown only now:
  nerve://relay?address=relay.example%3A7490&node=lab-pc&token=0123…&pin=q1Q3tvgE…
on lab-pc, paste it in the desktop app (Relay, Connect), or run:
  nerve-node proxy set 'nerve://relay?address=relay.example%3A7490&node=lab-pc&token=0123…&pin=q1Q3tvgE…'
it may reach every https center of this node
```

`--address` is where the other node reaches this machine, a host name or
address, with `:PORT` when it is not the port the relay listens on. Without
it the link names the address the relay listens on, or, when that is every
address (`0.0.0.0`), this machine's host name, and says so. In the desktop
app, the Relay page does the same: **Add a node** shows the link with a Copy
button.

The relay keeps only a hash of the token in `node.toml`, so it cannot show
the link again. If you lose the link, or think it leaked, give the node a new
one: `nerve-node relay token lab-pc` (with `--address` as for `relay add`).
The other node pastes the new link. The old token stops working, its tunnels
end, and the node keeps its centers and its limits. (`relay rm`, then
`relay add`, makes the node anew, without them.) On Windows the running
relay takes the new token only when it starts again: restart it, or the old
token goes on working ([On Windows](windows.md#a-relay-on-windows)).

The certificate's key is kept with the node's own keys, where
`machine.secret_storage` says: a file in the config folder by default, or
the system keyring ([config](settings-and-config.md#settings-as-the-owner-changes-them)). `relay on` keeps the same
certificate when you change the address. If its key is lost, `relay on`
makes a new one and says so; the relayed nodes then need the new pin.

The relay is off until you turn it on. A center cannot turn it on, change
it or see it, settings grant or not.

### Limit a node to some centers

Without `--to`, a relayed node may reach every https center of the relay
(see [below](#where-a-tunnel-may-go)). To let it reach only some:

```sh
nerve-node relay add lab-pc --to home
nerve-node relay set lab-pc --to home --to work
nerve-node relay set lab-pc --to '*'     # every center again
```

A tunnel to a center off the list is refused with the same answer as one to
a center the relay does not have, so the node learns nothing of the others.
`relay set --to` ends the node's tunnels to a center it takes away. `relay`
shows each node's list.

### On the relayed node

Paste the link: in the desktop app on the Relay page (**Connect through a
relay**), or in a terminal. Then pair as usual:

```sh
nerve-node proxy set 'nerve://relay?address=...&node=lab-pc&token=...&pin=...'
nerve-node center add 'nerve://pair?center=...&code=...&pin=...'
```

The link is the relay as this node's proxy: the same as `proxy set
'https://lab-pc:<token>@relay.example:7490' --pin=<pin>`.

The pairing goes through the relay too. The center's URL in the pairing link
must be the one the relay is paired with, the same host name or address and
port, or the relay refuses the tunnel. The center must be reached over
`https`.

The token is kept with the node's own keys, where `machine.secret_storage`
says: a file in the config folder by default (only the node's user can read
it, as its center keys), or the system keyring. It moves with the other keys
when you change that setting. On a Linux machine without a desktop session
there is no Secret Service: with `machine.secret_storage = "keyring"`,
`proxy set` refuses with the keyring's error and changes nothing, as storing
any key of the node does, and a node whose keys are there does not start.
Keep the keys in files there (the default), or install a keyring
(`nerve-node setup` can). The node installed as a service on Windows keeps
its keys in files, so it can be a relayed node.

### Where a tunnel may go

The relay tunnels only to the centers it is paired with itself, over
`https`, and not to one that removed it (`bye revoked`) or no longer knows
it, and only to the ones on the node's list when it has one. No other port of
the relay's machine or network can be reached through it, and no `http`
center on its own loopback; what a center's host and port serve besides the
center is reached too ([below](#what-to-know)). An `https` center the relay is
paired with at `127.0.0.1`, `[::1]` or `localhost` (a center on the relay's
own machine) is reached. A center paired at a name is not reached on the
relay's own loopback: if the name resolves to a loopback address there, the
tunnel is refused. A paused center is still reached: pausing stops the
relay's own link, not the links it carries.

If the relay itself reaches its centers through a proxy or another relay, it
dials through that one too. Each relay in such a chain follows the same
rules. To the outer relay, the inner one is a single relay node: its own
links and every tunnel of the nodes behind it count against that one node's
limits there. Give the inner relay limits of its own on the outer relay
with `relay set`, or its fifth link at once is refused
([limits](#limits)). All of the inner relay's connections come from one
address, so at most 4 of them can wait for the outer relay's answer at
once: when many of its nodes redial at the same moment (after a center
restarts), a few are closed unread, counted in the outer relay's log as
connections without a valid token, and retried at the next step of their
back-off.

### Limits

```sh
nerve-node relay on 0.0.0.0:7490 --max-links 16 --max-links-per-node 4
```

`--max-links` is the number of tunnels at once over all relayed nodes, 16
unless you set it. `--max-links-per-node` is the number per node, 4 unless
you set it; a node needs one per center it is paired with. A tunnel that
carries nothing for 90 seconds is closed (a live link sends something every
20 seconds).

`--max-opens-per-minute` is the number of tunnels a node may open a minute,
30 unless you set it. That is far more than a node needs.

These three hold for every relayed node and every token. Do not raise
`--max-links-per-node` or `--max-opens-per-minute` for one node: every token
would get the same, and could hold that many of the relay's tunnels or fill
its logs that much faster. A relay behind this one is one node here, whose
links and whose nodes' tunnels all count as its own. Give that one node
limits of its own:

```sh
nerve-node relay set inner-relay --max-links 12 --max-opens-per-minute 300
nerve-node relay set inner-relay --max-links 20   # the opens stay at 300
nerve-node relay set inner-relay --max-links default --max-opens-per-minute default   # the relay's again
```

`--max-links` there counts its own links to its centers plus one per center
for each node behind it; raise the relay's `--max-links` too if the total
needs it (`relay set` says when the relay's total is lower). `relay`
shows a node's own limits. A relayed node that hits the
outer relay's limits sees `502` from its own relay.

At most 4 connections from one address may wait for the relay's answer at
once, and 16 from one IPv6 /64, each 15 seconds at most; once the relay
grants a tunnel, its connection counts as a tunnel instead. So a machine
with one address cannot keep the other machines of its network out. Over
IPv6 the relay cannot tell one machine with several addresses from several
machines: a machine with four or more addresses in your LAN's /64 (privacy
addresses count, and many systems make one a day) can take the /64's 16 and
keep the other machines of that /64 out over IPv6, though not those that
reach the relay over IPv4 or from elsewhere.

### Who is connected

```sh
nerve-node relay
```

```
relay on 0.0.0.0:7490: listening on 0.0.0.0:7490
at most 16 tunnels, 4 per node, 30 opened a minute per node
pin q1Q3tvgEmVkvsjsZTEOBtG9Rb12pM9iyCOVCTVwjz4A
node lab-pc: the centers home
tunnel lab-pc from 10.0.0.7:51544 to center home for 2 h 5 min
```

`nerve-node status` shows the relay in one line and `relay` names the
tunnels; on Windows both ask the node over its
[control pipe](windows.md#the-control-pipe). Every tunnel is one entry
in the [audit log](logging.md#the-audit-log-as-the-owner-reads-it) when it ends: the node, its address, the
center, when it started and ended, why it ended and how much it carried;
never a token. The node's [log](logging.md#the-log-as-the-owner-reads-it) also has a line for every tunnel
that opens or closes. Refusals are counted: the first is told at once, and
the rest in one line a minute with how many came, over how long, and the
last of them, also when nothing comes after them, and at once when the relay
stops listening or the node stops. Each node has its own
count, so the line names the node whose refusals it counts; one more count
names a node whose token came in plain HTTP, so you know to give it a new
one. Connections without a valid token share one count.

### Cut a node off

Each of these ends the tunnels it concerns at once:

| Command | Ends |
|---|---|
| `nerve-node relay rm lab-pc` | The tunnels of `lab-pc`; its token no longer works |
| `nerve-node relay set lab-pc --to work` | The tunnels of `lab-pc` to its other centers |
| `nerve-node center rm home` | The tunnels to `home` |
| `nerve-node relay off` | Every tunnel; the relay stops listening and keeps its nodes |
| `nerve-node panic` | Every tunnel, and the relay does not listen until `unlock` |

### What to know

- The relay sees who connects, when, to which center and how much they
  send, but none of what they send.
- A token reaches the host and port of the relay's centers (those on the
  node's list), and what reaches them comes from the relay's address. If a
  center sits behind a reverse proxy that serves other sites on the same
  host and port, a token reaches those sites too, as the relay's machine
  would: the relay cannot see which name or path a node asks for inside the
  tunnel. Give a token only where that is acceptable, and take it away with
  `relay rm` if you think it leaked.
- Centers behind one address (`https://h.example/a`, `https://h.example/b`)
  are reached together: `relay add --to a` is refused there unless you
  name `b` too. The relay tells an address in any spelling apart from
  others, but not a name from the address it resolves to: pair the relay's
  centers at one name or address each.
- The link holds the token, and so does the `proxy set` line: your shell
  keeps it in its history (fish, bash, PowerShell's `ConsoleHost_history.txt`). Delete it
  from there after you ran it.

## A proxy, as the owner sets it up

A node can dial its centers through an HTTP proxy. The proxy is one setting
for the whole node, for every center.

```sh
nerve-node proxy set http://proxy.example:3128
nerve-node proxy
nerve-node proxy off
```

The node opens the TLS link to the center inside a `CONNECT` tunnel. The
center's pin is still checked on that inner link, so the proxy sees only TLS
records. `center add` pairs through the proxy too.

Another node can be the proxy: see [relay](#a-relay-as-the-owner-sets-it-up).

### A proxy over TLS

An `https://` proxy is reached over TLS of its own, and the `CONNECT` and its
login travel inside it. A relay is one: paste the link `relay add` on the
relay shows, which holds the relay's address, this node's name and token,
and the pin of the relay's certificate:

```sh
nerve-node proxy set 'nerve://relay?address=relay.example%3A7490&node=lab-pc&token=...&pin=...'
```

It is the same as the URL with the login and the pin:
`proxy set 'https://lab-pc:<token>@relay.example:7490' --pin=<pin>`.

Give the pin as `--pin=<pin>`: a pin can start with `-`, which would be read
as an option after a space.

Without `--pin` the proxy's certificate must be one this machine trusts. The
user name and password of an `https://` proxy are kept with the node's own
keys, where `machine.secret_storage` says: a file in the config folder by
default, or the system keyring ([config](settings-and-config.md#settings-as-the-owner-changes-them)). `proxy` shows the
pin and the user name, never the password.

### A proxy that wants a login

Put the user name and password in the URL, or send extra header lines on the
`CONNECT` request:

```sh
nerve-node proxy set 'http://user:password@proxy.example:3128'
nerve-node proxy set http://proxy.example:3128 --header 'X-Proxy-Token: abc'
```

Write special characters of the password as `%XX`. `--header` can be given
more than once.

An argument shows in the process list while the command runs. To keep the
secrets out of it, give the user name alone in the URL and the password on
stdin, and the headers after it, one a line (the desktop app does this):

```sh
printf '%s\n' "$PASSWORD" 'X-Proxy-Token: abc' |
  nerve-node proxy set http://user@proxy.example:3128 --header -
```

The values are secrets. The node keeps them in the system keyring (Keychain,
Credential Manager, Secret Service), in one entry named `proxy:<config folder>`
under the service `nerve`. `node.toml` keeps the URL without the login and the
header names. The values never reach a file, the audit log, a log line or an
error. `proxy` prints header names only.

A user name and password in the URL become a `Proxy-Authorization: Basic`
header. Do not give that header yourself in the same call.

### Environment variables

Without `proxy set`, the node uses `HTTPS_PROXY` and `NO_PROXY`. A user name or
password in `HTTPS_PROXY` is refused. Use `proxy set` for those.

### When the proxy fails

The node does not fall back to a direct connection. If the proxy is down, the
link stays down. If a keyring entry is missing or unreadable, the link stays
down and `nerve-node status` shows `bad proxy:` with the reason (on Windows the
app's **Overview**, which asks the node over its
[control pipe](windows.md#the-control-pipe)). `proxy` and
the node's [log](logging.md#the-log-as-the-owner-reads-it) have the reason too.

On a Linux machine with no Secret Service (no desktop session), `proxy set`
with a header or a password refuses and changes nothing. A proxy without
either works there. The same holds for the node installed as a service on
Windows ([above](windows.md#a-proxy-for-the-service-on-windows)).

A `node.toml` that holds header values or a login in the file is refused when
it loads. Take the values out of the file, run `nerve-node config accept`,
then run `proxy set` again.
