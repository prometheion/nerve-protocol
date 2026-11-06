# Keep a center's commands off the network

`folder` mode leaves the network open: a command can connect anywhere this
machine reaches. Close it for one center's commands:

```sh
nerve-node network off
nerve-node network                     # each center's network
nerve-node network on
```

With several centers, add `--center <name>`. A command that runs when you
turn it off is ended. The agent is told that its commands have no network.

## Where it holds

| Commands run as | With the network off |
|---|---|
| `nerve-run` (`folder`, `allowlist` without `--as-owner`) | They run, with no socket but unix ones |
| you (`user`, `allowlist --as-owner`) | None of them runs |
| a node run by hand | None runs, unless `folder` mode on Linux 7.1 or later |
| a machine that cannot hold the switch | None of them runs |
| the sudo list | None of them runs |

- With the network off, none of that center's commands runs in `user` mode,
  in `allowlist --as-owner`, on most nodes run by hand, or where the machine
  cannot hold the switch. Sudo-list commands never run then
  ([no network](../dev/sandbox-linux.md#no-network-for-a-centers-commands)).

A machine holds the switch with a seccomp filter on x86_64 and aarch64.
`setup` asks for the network, and warns before it saves `user` mode with
the network off.

## What it does not stop

- A command reaches every unix socket its account may write to. On a node
  run by hand, that includes your session's (tmux, X). A program that
  listens on such a socket can reach the network for it
  ([what it does not stop](../dev/sandbox-linux.md#what-it-does-not-stop-linux)).
- A name lookup through the system's resolver still asks the name servers.
- A program a command left running before you turned it off keeps its
  network.
- Without Landlock, a command of another pairing that has the network: the
  pairings are not kept apart there, and `status` warns
  ([pairings](../dev/sandbox-linux.md#what-it-does-not-stop-linux)).
- A program's action ([capabilities](capabilities.md)) runs as you, outside
  the switch.

A center with the settings grant can turn its own network off, never on
again: only you can.
