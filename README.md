# Nerve Protocol

Nerve lets an agent harness use its owner's machines: read and write files and
run commands. On each machine the owner decides what is allowed. Everything
else is refused.

Three programs:

| Program | Job | Put it on |
|---|---|---|
| `nerve-center` | The center. A harness starts it as an MCP server. It pairs machines, keeps their links, gives the harness two tools, `list` and `execute`, for what they offer, and serves a web UI | the machine where the harness runs |
| `nerve-node` | The node. A daemon, plus a CLI for pairing, rules and the audit log, and on Linux a web UI like the app's, off unless you turn it on | each machine the agent may use, without a desktop (a server, Linux on ARM), or where you prefer a terminal |
| `nerve-node-desktop` | The node with an app: the same node and CLI, and a window that does what the CLI does. It installs itself with the node as a service; on Linux its node has the web UI too | each machine the agent may use that has a desktop: Linux x86_64 with GNOME or KDE Plasma, Windows x86_64 |

A machine runs one node: `nerve-node` or `nerve-node-desktop`.

## Quick install

On a Linux machine the agent may use, install the node as a service (use
`nerve-node-aarch64-linux` on ARM):

```sh
curl -LO https://github.com/prometheion/nerve-protocol/releases/latest/download/nerve-node-x86_64-linux
chmod +x nerve-node-x86_64-linux
sudo ./nerve-node-x86_64-linux install
nerve-node center add '<pairing link>'
nerve-node folder add ~/project +r +w +x
```

`install` puts the program at `/usr/local/bin/nerve-node` and starts it as a
service under a user of its own ([service](docs/user/service.md)), with you
as its owner. A new pairing is in `folder` mode: its commands run as
`nerve-run`, an account of their own that reaches only the folders you give
it ([modes](docs/user/modes.md#the-account-nerve-run-linux)). On Windows the
node is the desktop app ([below](#install-the-desktop-app)). The center is
`nerve-center-x86_64-linux` (or `-aarch64-linux`, `-x86_64-windows.exe`)
from the same release; `sudo ./nerve-center-x86_64-linux install` runs it as
a service and prints the owner token its web UI asks for
([center](docs/user/center.md#run-it-as-a-service)).

## Install the desktop app

1. Download `nerve-node-desktop-x86_64-linux` or
   `nerve-node-desktop-x86_64-windows.exe` from
   [Releases](https://github.com/prometheion/nerve-protocol/releases/latest).
2. On Linux, allow it to run: in the file's **Properties** switch on
   **Executable as Program** (GNOME Files) or tick **Is executable** under
   **Permissions** (KDE Dolphin).
3. Open it, and press **Install**.

It installs the node as a service and the app, with **Nerve** in the
application menu or Start menu, then walks you through naming the machine and
pairing it ([desktop app](docs/user/desktop.md)).

## Quick start

Get the programs from
[Releases](https://github.com/prometheion/nerve-protocol/releases).

1. Add the center to the harness's MCP configuration:

   ```json
   {"mcpServers": {"nerve": {"command": "nerve-center"}}}
   ```

2. Open `http://127.0.0.1:7480` and log in with the **owner token**. The
   center made it at its first start, printed it, and keeps it in a file of
   yours (mode 0600):

   ```sh
   cat ~/.local/state/nerve-center/owner-token
   ```

   It is the one secret of the web UI. The harness's own token never logs
   in there. `nerve-center owner-token --new` makes a new one
   ([web UI](docs/user/web-ui.md#log-in)). This center runs as you, so an
   agent with file or shell tools can read the file too; to keep the agent
   out of the web UI, run the center as the
   [service](docs/user/center.md#run-it-as-a-service).

3. Press **Pair a machine**, and run the command it shows on the machine:

   ```sh
   nerve-node center add 'nerve://pair?center=...&code=...&pin=...'
   nerve-node run
   ```

4. A new pairing is in `folder` mode: it writes and runs nothing of yours
   until you give it a folder (on the installed node it may read what every
   account may read). Give it one:

   ```sh
   nerve-node folder add ~/project +r +w +x
   ```

## The action checker

The center has an optional gate that checks each call before the machine gets
it: a deterministic blocklist of dangerous commands and paths (on by default),
saved allow rules, and an optional System One decision model that judges
whether a call is dangerous. It can only refuse; the machine's own rules still
decide. Set it up on the **Action checker** page of the web UI
([docs](docs/user/action-checker.md)).

## Documentation

| For | Where |
|---|---|
| Running Nerve: install, pairing, rules and modes, the web UI, troubleshooting | [docs/user/](docs/user/README.md) |
| Building, changing and releasing Nerve: architecture, policy engine, checks | [docs/dev/](docs/dev/README.md) |
| The protocol and the conformance suite | [docs/dev/spec/](docs/dev/spec/README.md), [schemas/](schemas), [crates/nerve-conformance](crates/nerve-conformance) |
