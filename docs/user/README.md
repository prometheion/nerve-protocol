# Nerve user guide

Nerve lets an agent harness use your machines. On each machine you decide
what it may do; everything else is refused. The node always dials the
center, so a machine behind NAT needs no open port.

## Start here

1. [Install](install.md) the center as a service, and the node on each
   machine; on Windows the node is the [desktop app](windows.md).
2. Log in to the center's web UI with the owner token, and
   [connect your harness](center.md).
3. [Pair](pair.md) each machine with the center.
4. Give the pairing a [folder](folders-and-modes.md). Until then it writes
   and runs nothing of yours.

## Pages

| Page | Covers |
|---|---|
| [install.md](install.md) | Download, install, update and remove the programs |
| [windows.md](windows.md) | Nerve on Windows: each task in the app, and what differs |
| [center.md](center.md) | Run the center and connect a harness |
| [pair.md](pair.md) | Pair a machine, several centers, a proxy or a relay |
| [folders-and-modes.md](folders-and-modes.md) | The three modes, folders and their rights |
| [rules.md](rules.md) | Allow and deny commands, the guard, protected paths, sudo |
| [network.md](network.md) | Keep a center's commands off the network |
| [capabilities.md](capabilities.md) | Capabilities from programs and from `node.toml` |
| [watch-and-stop.md](watch-and-stop.md) | Status, audit, log, panic and pause |
| [web-uis.md](web-uis.md) | The center's web UI, the node's web UI, the desktop app |
| [settings.md](settings.md) | `config get` and `set`, limits per command |
| [backup.md](backup.md) | Back up, restore and move |
| [action-checker.md](action-checker.md) | The center's check of each call |
| [troubleshooting.md](troubleshooting.md) | What to do when something fails |
| [commands.md](commands.md) | The commands, by group |
| [safety.md](safety.md) | What Nerve guards and what it does not |
