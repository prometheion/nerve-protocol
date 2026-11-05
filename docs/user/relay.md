# Reach the center through another node

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

## On the relay

Turn the relay on and give the other node a link:

```sh
nerve-node relay on 0.0.0.0:7490
nerve-node relay add lab-pc --address relay.example
```

`relay on` makes the relay's certificate the first time and shows its pin.
The relay's port, 7490, is not the [web UI](node-web-ui.md)'s, 7470, and the
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
token goes on working ([On Windows](#on-windows)).

The certificate's key is kept with the node's own keys, where
`machine.secret_storage` says: a file in the config folder by default, or
the system keyring ([config](config.md)). `relay on` keeps the same
certificate when you change the address. If its key is lost, `relay on`
makes a new one and says so; the relayed nodes then need the new pin.

The relay is off until you turn it on. A center cannot turn it on, change
it or see it, settings grant or not.

## Limit a node to some centers

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

## On the relayed node

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

## Where a tunnel may go

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

## Limits

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

## Who is connected

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
[control pipe](platforms.md#the-control-pipe). Every tunnel is one entry
in the [audit log](audit.md) when it ends: the node, its address, the
center, when it started and ended, why it ended and how much it carried;
never a token. The node's [log](logs.md) also has a line for every tunnel
that opens or closes. Refusals are counted: the first is told at once, and
the rest in one line a minute with how many came, over how long, and the
last of them, also when nothing comes after them, and at once when the relay
stops listening or the node stops. Each node has its own
count, so the line names the node whose refusals it counts; one more count
names a node whose token came in plain HTTP, so you know to give it a new
one. Connections without a valid token share one count.

## Cut a node off

Each of these ends the tunnels it concerns at once:

| Command | Ends |
|---|---|
| `nerve-node relay rm lab-pc` | The tunnels of `lab-pc`; its token no longer works |
| `nerve-node relay set lab-pc --to work` | The tunnels of `lab-pc` to its other centers |
| `nerve-node center rm home` | The tunnels to `home` |
| `nerve-node relay off` | Every tunnel; the relay stops listening and keeps its nodes |
| `nerve-node panic` | Every tunnel, and the relay does not listen until `unlock` |

## On Windows

On Windows the [desktop app](desktop.md)'s **Relay** page does the relay's
commands. Windows has no control socket, so a relay change is in `node.toml`
and takes effect at the next start of the node, for which the app restarts
the service. Until then the running node works by its old relay settings,
for new tunnels as well as the ones it carries: a token taken away or
replaced still opens tunnels, a node off its center list still reaches the
center, a relay turned off still listens, and a new token or node gets
`407`. Should the restart fail, **Restart** on the app's **Overview** applies
the change, above all when a token may have leaked. The **Relay** page asks
the running node who is connected. Windows Firewall must let other machines
reach the relay's port.

## What to know

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
