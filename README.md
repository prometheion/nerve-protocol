# Nerve Protocol

Nerve lets an agent harness use its owner's machines: read and write files and
run commands. On each machine the owner decides what is allowed. Everything
else is refused.

Three programs:

| Program | Job | Put it on |
|---|---|---|
| `nerve-center` | The center. Your harness reaches it as an MCP server and gets two tools, `list` and `execute`. It pairs machines and serves a web UI | the machine where the harness runs, or a server it reaches |
| `nerve-node` | The node: a service, a CLI for pairing, folders, rules and the audit log, and a web UI you may turn on | each machine the agent may use |
| `nerve-node-desktop` | The node with a desktop app: the same node and CLI, and a window that does what the CLI does | each machine the agent may use that has a desktop: Linux x86_64 with GNOME or KDE Plasma |

A machine runs one node: `nerve-node` or `nerve-node-desktop`. This release
is for Linux, x86_64 and aarch64; Windows comes with 0.1.0.

## Quick start

Get the programs from
[Releases](https://github.com/prometheion/nerve-protocol/releases/latest).
On ARM, take the `aarch64` files.

1. Install the center as a service, on the machine where your harness runs:

   ```sh
   curl -LO https://github.com/prometheion/nerve-protocol/releases/latest/download/nerve-center-x86_64-linux
   chmod +x nerve-center-x86_64-linux
   sudo ./nerve-center-x86_64-linux install
   ```

   It ends with three lines: the web UI's address, the **owner token** that
   logs in there, and the address for harnesses.
   `sudo nerve-center owner-token` shows the token again.

2. Open the web UI, `http://127.0.0.1:7480`, and log in with the owner token.
   Its **Connect a harness** card makes a harness token and gives you the
   entry for your harness: the JSON, or a `claude mcp add` line.

3. Install the node on each machine the agent may use:

   ```sh
   curl -LO https://github.com/prometheion/nerve-protocol/releases/latest/download/nerve-node-x86_64-linux
   chmod +x nerve-node-x86_64-linux
   sudo ./nerve-node-x86_64-linux install
   ```

   At a terminal it asks for the pairing link (**Pair a machine** in the web
   UI shows one), the mode, a folder with its rights, and the network.
   Without a terminal, pair and give a folder yourself (`-` reads the
   pairing link from the next line, [pair](docs/user/pair.md)):

   ```sh
   nerve-node center add -
   nerve-node folder add ~/project rwx
   ```

4. A new pairing is in `folder` mode. It writes and runs commands only in
   the folders you give it, as an account of its own, `nerve-run`. It may
   also read what every account on the machine may read.
   `nerve-node status` shows the node and what to do next.

The node has a web UI of its own, off until you turn it on. It listens on
`http://127.0.0.1:7470` and shows its first token once:

```sh
nerve-node ui on
```

### The desktop app

On a Linux desktop, take `nerve-node-desktop-x86_64-linux` in place of
`nerve-node`:

1. In the file's **Properties**, switch on **Executable as Program** (GNOME
   Files) or tick **Is executable** under **Permissions** (KDE Dolphin).
2. Open it, and press **Install**.

It installs the node as a service and the app, with **Nerve** in the
application menu. Then it pairs your first center
([install](docs/user/install.md#the-desktop-app)).

### A center your harness starts

A harness can also start the center itself, over stdio:

```json
{"mcpServers": {"nerve": {"command": "nerve-center"}}}
```

That center runs as you, so an agent with file or shell tools can read its
owner token (`nerve-center owner-token`) and log in to its web UI. The
service keeps the agent out ([center](docs/user/center.md)).

## The action checker

The center has an optional gate that checks each call before the machine gets
it: a blocklist of dangerous commands and paths (on by default), and an
optional decision model that judges whether a call is dangerous. It can only
refuse; the machine's own rules still decide. Set it up on the **Action
checker** page of the web UI ([docs](docs/user/action-checker.md)).

## Documentation

| For | Where |
|---|---|
| Running Nerve: install, pairing, folders and modes, rules, the web UIs, what it guards | [docs/user/](docs/user/README.md) |
| Building, changing and releasing Nerve: architecture, policy engine, sandbox, checks | [docs/dev/](docs/dev/README.md) |
| The protocol and the conformance suite | [docs/dev/spec/](docs/dev/spec/README.md), [schemas/](schemas), [crates/nerve-conformance](crates/nerve-conformance) |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md): how to build and check a change, and what a pull request brings.

## Security

Report a security hole privately, through **Report a vulnerability** on the
repository's Security tab (without that button, open an issue that says only
that you have a report, and no more). [SECURITY.md](SECURITY.md) says how, what is in
scope, what `update` trusts (the releases are not signed yet), and the known
limits.

## Licence

Nerve is under the [Apache License 2.0](LICENSE). The desktop app
`nerve-node-desktop` is drawn with [Slint](https://slint.dev), which it uses
under Slint's Royalty-free license 2.0: the app shows Slint's notice in its
About dialog ([its licence](crates/nerve-node-desktop/LICENSE.md)).
[NOTICE](NOTICE) lists the works Nerve includes.
