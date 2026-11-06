# Pair a machine

Pairing links a machine to a center. Do it once per machine and center.

1. In the center's web UI, on the Overview, press **Pair a machine**. It
   shows a command and the pairing link, each with a Copy button.
2. On the machine, run the command. Keep the quotes: the link has `&` in it.

   ```sh
   nerve-node center add 'nerve://pair?center=...&code=...&pin=...'
   ```

   While `center add` asks, the link is in the process list, which any
   account can read. On a machine where that matters, run
   `nerve-node center add -` and paste the link on the next line: `-` reads
   it from stdin instead.

3. The node shows the center's address and what it may do at first, and asks
   before it stores anything. Then check the link:

   ```sh
   nerve-node status
   ```

The machine shows as online in the web UI. With the desktop app, paste the
link under **Centers › Pair a center** instead. `sudo nerve-node install`
and `nerve-node setup` ask for the link too.

A new pairing is in `folder` mode, with no folder of yours, and the center
may not change settings. Give it a folder next:
`nerve-node folder add ~/project rwx` ([folders and
modes](folders-and-modes.md)). Its deny list holds the built-in
[guard](rules.md#the-guard).

## The code

- It is valid for 10 minutes and for one machine. **Settings › Center**
  changes the time (1 to 1440 minutes).
- It allows 10 tries in all, and a wrong code counts against every open code.
- `center add` checks the link before it asks: the center answers, its
  certificate is the one the link pins, and the code is valid. If one fails,
  it says why and stores nothing.

## Several centers

A node can pair with any number of centers. Each has its own key, mode,
folders, rules and audit entries. A center cannot tell whether others
exist.

With more than one center, a command that works on one takes
`--center <name>`; it refuses to guess.

```sh
nerve-node center                       # the paired centers
nerve-node mode folder --center lab
```

## Unpair

| From | How | Effect |
|---|---|---|
| The machine | `nerve-node center rm lab` | Tells the center, forgets it and deletes its key |
| The center | **Remove** at the machine on the Overview | Ends the link; the node shows `revoked` until `center rm` |

To pair again, remove the old pairing on both sides, then make a new link.

## Rotate the machine's key

```sh
nerve-node center rotate-key lab
```

The node must run and be linked. It sends the new key signed with the old
one; the center takes the old key for 7 more days. `--end-grace` ends that
at once. [Key rotation](../dev/identity-and-pairing.md#rotate-the-machines-key).

When the center rotates its own key, a machine that does not link within 7
days must be paired again ([center](center.md#rotate-the-key)).

## Pause

```sh
nerve-node center pause lab
nerve-node center resume lab
```

A paused center gets no link until you resume it.

## Behind a proxy

The node can dial its centers through an HTTP proxy, one setting for every
center:

```sh
nerve-node proxy set http://proxy.example:3128
nerve-node proxy set http://user@proxy.example:3128   # asks for the password
nerve-node proxy                                      # shows it
nerve-node proxy off
```

The center's pin is still checked inside the proxy's tunnel, so the proxy
sees only TLS. The login is kept with the node's keys, never in `node.toml`.
Without `proxy set`, the node uses `HTTPS_PROXY` and `NO_PROXY`. It never
falls back to a direct connection
([proxy](../dev/node-link.md#a-proxy-as-the-owner-sets-it-up)).

## Through another node

A machine in a closed network can reach its center through a node that
reaches both, its **relay**. The relay carries bytes only: the link stays
TLS to the center, end to end, and the relayed node's own rules decide
every call.

On the relay:

```sh
nerve-node relay on 0.0.0.0:7490
nerve-node relay add lab-pc --address relay.example
```

`relay add` shows a link once. The link holds the relay token: delete the
`proxy set` line from your shell's history, and `relay rm` the node if it
leaked. On the relayed node, paste it as its proxy, then pair as usual:

```sh
nerve-node proxy set 'nerve://relay?address=...&node=lab-pc&token=...&pin=...'
nerve-node center add 'nerve://pair?...'
```

`relay add lab-pc --to home` lets it reach only that center. `relay` shows
the relayed nodes; `relay rm lab-pc` cuts one off. A relay token reaches the host and port of the relay's centers from the
relay's address, also other sites a reverse proxy serves there. A center
cannot turn the relay on or see it ([relay](../dev/node-link.md#a-relay-as-the-owner-sets-it-up)).

## Drops

When a link drops without a goodbye, both sides keep it for 30 seconds:
running commands go on. The node dials again, waiting 1 second and then up
to 60. After 30 seconds, or after a restart, the commands on the link end
with `connection_lost` ([drops](../dev/identity-and-pairing.md#drops)).
