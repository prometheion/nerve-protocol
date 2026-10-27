# Nerve user guide

Nerve lets an agent harness use your machines: read and write files and run
commands. On each machine you decide what is allowed. Everything else is
refused.

Three programs make it work:

| Program | Runs on | Job |
|---|---|---|
| `nerve-center` | the machine where the harness runs | Pairs machines, keeps their links, gives the harness two MCP tools, `list` and `execute`, for what they offer, serves the web UI |
| `nerve-node` | each machine the agent may use, without a desktop or run from a terminal | Links to a center and decides each call by the rules you set; its CLI sets them |
| `nerve-node-desktop` | each machine the agent may use that has a desktop (Linux x86_64 with GNOME or KDE Plasma, Windows x86_64) | The same node, with an app that installs itself and does what the CLI does in a window ([desktop app](desktop.md)) |

A machine runs one node: `nerve-node` or `nerve-node-desktop`.

The node always dials the center. A machine behind NAT or a firewall needs no
open port.

## Start here

1. [Install](install.md) the programs.
2. [Run the center](center.md) and [connect a harness](harness.md).
3. [Pair a machine](pairing.md), or [install the node as a
   service](service.md) and run `nerve-node setup` (on Windows as
   administrator), or on a desktop open the
   [desktop app](desktop.md).
4. Give the pairing a [folder](modes.md#folders): a new pairing is in `folder`
   mode, and until you do it writes and runs nothing of yours (on the
   installed node it may read what every account may read). Or choose another
   [mode](modes.md) and [rules](rules.md).

## All pages

| Page | Covers |
|---|---|
| [install.md](install.md) | Download, check, install, where files live |
| [center.md](center.md) | Start the center, its flags and ports, install it as a service on Linux |
| [harness.md](harness.md) | Connect an MCP harness, the two tools it gets |
| [pairing.md](pairing.md) | Pair a machine, start the node, unpair |
| [service.md](service.md) | Install the node as a service, set it up, update and uninstall it |
| [desktop.md](desktop.md) | The desktop app: install it by opening it, start and stop the node, update and uninstall it |
| [modes.md](modes.md) | `allowlist`, `folder` and `user` mode, folders and their rights |
| [rules.md](rules.md) | Allow and deny rules, wildcards, switching capabilities off |
| [protected-paths.md](protected-paths.md) | The files that stay closed in every mode |
| [sudo.md](sudo.md) | The sudo switch |
| [settings-grant.md](settings-grant.md) | Let a center change a machine's settings |
| [config.md](config.md) | Read and change `node.toml` by name |
| [limits.md](limits.md) | Memory, CPU and processes of one command |
| [audit.md](audit.md) | See what was allowed and refused |
| [action-checker.md](action-checker.md) | The center's gate: blocklist, allow rules, a decision model |
| [logs.md](logs.md) | The log of the center and the node: levels, what is in it, where it is |
| [stop.md](stop.md) | Panic, pause, disable, remove |
| [backup.md](backup.md) | Back up and restore a node or a center, move one to another machine |
| [proxy.md](proxy.md) | Reach the center through an HTTP proxy |
| [relay.md](relay.md) | Reach the center through another node (a jump node) |
| [providers.md](providers.md) | Let a program on the machine add capabilities |
| [web-ui.md](web-ui.md) | The center's web UI |
| [platforms.md](platforms.md) | What differs on Linux and Windows |
| [troubleshooting.md](troubleshooting.md) | Messages and what to do |
| [commands.md](commands.md) | Every `nerve-node` command in one table |
