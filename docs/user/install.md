# Install

Put `nerve-center` on the machine where your agent harness runs. Put a node
on every machine the agent may use: `nerve-node`, or on a machine with a
desktop `nerve-node-desktop`, the node with an app
([desktop app](desktop.md)). A center and a node can share a machine.

## Download

Get the programs from
[Releases](https://github.com/prometheion/nerve-protocol/releases). Each
release has eight programs and a `SHA256SUMS` file.

| System | Files |
|---|---|
| Linux, x86_64 | `nerve-center-x86_64-linux`, `nerve-node-x86_64-linux`, `nerve-node-desktop-x86_64-linux` |
| Linux, ARM 64-bit | `nerve-center-aarch64-linux`, `nerve-node-aarch64-linux` |
| Windows, x86_64 | `nerve-center-x86_64-windows.exe`, `nerve-node-x86_64-windows.exe`, `nerve-node-desktop-x86_64-windows.exe` |

`nerve-node-desktop` is the node with a desktop app, which installs itself
when you open it ([desktop app](desktop.md)).

The Linux programs except the desktop app are static and need no libraries. The Windows programs
need no Visual C++ runtime. The programs are not signed, so check them
against `SHA256SUMS`.

## Install on Linux

```sh
sha256sum --check --ignore-missing SHA256SUMS
install -m 0755 nerve-center-x86_64-linux ~/.local/bin/nerve-center
install -m 0755 nerve-node-x86_64-linux ~/.local/bin/nerve-node
nerve-node --version
```

Use the `aarch64` files on an ARM machine. `~/.local/bin` must be on your
`PATH`.

To run the node as a service that starts with the machine, download it and
let it install itself instead ([service](service.md)):

```sh
curl -LO https://github.com/prometheion/nerve-protocol/releases/latest/download/nerve-node-x86_64-linux
chmod +x nerve-node-x86_64-linux
sudo ./nerve-node-x86_64-linux install
nerve-node setup
```

`install` puts the program at `/usr/local/bin/nerve-node`, whatever the
downloaded file is called. Run as root itself, without `sudo` (a server
where you log in as root), it asks whether root is to be the node's owner,
or takes `--owner=root --accept-root-owner` without a terminal; then `user`
mode runs commands as root ([root as the owner](service.md#root-as-the-owner)).
Root stays the owner at a later `install`; `install --owner=none` takes it back.

The center installs itself as a service the same way, with MCP over HTTP
([center](center.md#run-it-as-a-service)):

```sh
curl -LO https://github.com/prometheion/nerve-protocol/releases/latest/download/nerve-center-x86_64-linux
chmod +x nerve-center-x86_64-linux
sudo ./nerve-center-x86_64-linux install
```

## Install on Windows

In PowerShell, compare each hash with its line in `SHA256SUMS`:

```powershell
(Get-FileHash .\nerve-node-x86_64-windows.exe).Hash
```

Then rename the files to `nerve-center.exe` and `nerve-node.exe` and put them
in a folder on your `PATH`.

To run the node as a service that starts with the machine, let it install
itself instead, in a terminal opened with "Run as administrator"
([service](service.md#windows)):

```powershell
.\nerve-node-x86_64-windows.exe install
```

`install` puts the program at `C:\Program Files\Nerve\nerve-node.exe`.

## Build from source

See [building](../dev/building.md).

## Where files live

| What | Linux | Windows | Change with |
|---|---|---|---|
| Node: `node.toml`, one key per center | `~/.config/nerve` | `%USERPROFILE%\.config\nerve` | `--config-dir`, `NERVE_CONFIG_DIR` |
| Node: audit log, [log](logs.md), control socket and its token (Linux), config key, the last version of `node.toml`, the record of the folder grants (Windows) | `~/.local/state/nerve` | `%USERPROFILE%\.local\state\nerve` | `--state-dir`, `NERVE_STATE_DIR` |
| Center: identity, paired machines, statistics, [log](logs.md), the [action checker](action-checker.md)'s settings and local model | `$XDG_STATE_HOME/nerve-center`, else `~/.local/state/nerve-center` | `%LOCALAPPDATA%\nerve-center` | `--state-dir`, `NERVE_STATE_DIR` |

A node [installed as a service](service.md) keeps its files in `/etc/nerve`
and `/var/lib/nerve/state`, on Windows in `C:\ProgramData\Nerve\config` and
`C:\ProgramData\Nerve\state`. Without `--config-dir` and `--state-dir` the
commands use those folders. A center installed as a service keeps its state
in `/var/lib/nerve-center` and its settings in `/etc/nerve-center`
([center](center.md#run-it-as-a-service)).

Both programs read `NERVE_STATE_DIR`. On a machine that runs both, set it per
program or use the flags. Do not set it for the whole machine.

The node keeps its own folders closed. No center can read them, whatever the
rules say.

## Next

[Run the center](center.md).
