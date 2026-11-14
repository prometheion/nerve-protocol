# Nerve Protocol

Nerve lets an agent harness use its owner's machines: read and write files and
run commands. On each machine the owner decides what is allowed. Everything
else is refused.

Three programs:

| Program | Job | Put it on |
|---|---|---|
| `nerve-center` | The center. Your harness reaches it as an MCP server and gets two tools, `list` and `execute`. It pairs machines and serves a web UI | the machine where the harness runs, or a server it reaches |
| `nerve-node` | The node: a service, a CLI for pairing, folders, rules and the audit log, and a web UI you may turn on | each Linux machine the agent may use |
| `nerve-node-desktop` | The node with a desktop app: a window that does what the CLI does | a Linux desktop (x86_64, GNOME or KDE Plasma), and every Windows machine |

A machine runs one node. Nerve runs on Linux (x86_64, aarch64) and Windows
(x64). On Windows the node is always the desktop app, with no CLI; the
center runs there too.

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

5. To manage the machine from the center's web UI instead (its mode,
   folders, rules and capabilities), give that center the settings grant:
   `nerve-node center settings on <center>`, or the **Settings grant** switch
   on the app's **Centers** page. It is the easy way, but the center can then
   widen its own rights up to `user` mode: give it only to a center you would
   also give a shell ([the settings grant](docs/user/rules.md#the-settings-grant)).

The node has a web UI of its own, off until you turn it on. It listens on
`http://127.0.0.1:7470` and shows its first token once:

```sh
nerve-node ui on
```

### The desktop app

On a Linux desktop, take the desktop app in place of `nerve-node`: the
`.deb` (Ubuntu, Debian) or the `.rpm` (Fedora). Double-click it, install it,
then open **Nerve** and press **Install**. The plain
`nerve-node-desktop-x86_64-linux` works too
([install](docs/user/install.md#the-desktop-app)).

It installs the node as a service, and its first steps pair your first
center.

### On Windows

1. For the center, double-click `nerve-center-x86_64-windows.exe`. After the
   UAC prompt it installs itself as a service, puts itself on the `PATH`, and
   shows the web UI's address and the owner token, as on Linux. (Or run
   `.\nerve-center-x86_64-windows.exe install` in a terminal opened with
   **Run as administrator**.)
2. On each machine the agent may use, double-click
   `nerve-node-desktop-x86_64-windows.exe`. It is not signed: SmartScreen
   asks, **More info**, **Run anyway**. Its installer asks for your Windows
   password, installs the node as a service, and pairs your first center.

The owner must be a local account with a password. Everything else is in
the app ([Nerve on Windows](docs/user/windows.md)).

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
