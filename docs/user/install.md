# Install, update and remove

Put the center where your harness runs, and a node on each machine the agent
may use. A center and a node can share a machine. On Windows the node is
the desktop app: [Nerve on Windows](windows.md) has its install.

## Download

Get the programs from
[Releases](https://github.com/prometheion/nerve-protocol/releases/latest):

| Machine | Files |
|---|---|
| x86_64 | `nerve-center-x86_64-linux`, `nerve-node-x86_64-linux`; the desktop app as `nerve-node-desktop_<version>_amd64.deb`, `nerve-node-desktop-<version>.x86_64.rpm` or `nerve-node-desktop-x86_64-linux` |
| ARM 64-bit | `nerve-center-aarch64-linux`, `nerve-node-aarch64-linux` |
| Windows x64 | `nerve-center-x86_64-windows.exe`, the desktop app `nerve-node-desktop-x86_64-windows.exe` ([Windows](windows.md)) |

`nerve-center` and `nerve-node` are static and need no libraries. The
desktop app needs glibc 2.35 or newer (Ubuntu 22.04, Debian 12, Fedora 36
and later) and fontconfig.

### Check the download

Releases are not signed yet. `SHA256SUMS` in the same release catches a
broken download, not a changed release:

```sh
sha256sum --check --ignore-missing SHA256SUMS
```

On Windows, `Get-FileHash` ([Windows](windows.md#download-and-check)).

## The node as a service

```sh
curl -LO https://github.com/prometheion/nerve-protocol/releases/latest/download/nerve-node-x86_64-linux
chmod +x nerve-node-x86_64-linux
sudo ./nerve-node-x86_64-linux install
```

`install` puts the program at `/usr/local/bin/nerve-node` and starts the
service, which starts with the machine. You become its owner: you run its
commands without `sudo`. At a terminal it then asks [setup](#setup)'s
questions. Without one it says what to run (`-` reads the pairing link from
the next line, [pair](pair.md)):

```sh
nerve-node center add -
nerve-node folder add ~/project rwx
```

`install` makes two accounts: `nerve`, which runs the node and holds its
keys, and `nerve-run`, which runs a center's commands in `folder` and
`allowlist` mode. Each pairing gets a home and a temporary folder of its own
below `/var/lib/nerve-run`. Running `install` again repairs what is missing.
[What install does](../dev/service.md#what-install-does).

### Setup

`nerve-node setup` asks these, one at a time; Enter keeps what is in
brackets. `center add`, `folder add` and `network` do the same.

1. The pairing link from the center's web UI.
2. The mode: `folder`, `allowlist` or `user`. For `folder`, one folder and
   its rights (`rwx` by default). `~` is your home.
3. The network for its commands: `on` or `off`. In `user` mode nothing runs
   while it is off, and setup says so first.

The machine's name stays its host name, and the keys stay in files.
`nerve-node config set node.name lab-pc` and
`nerve-node config set machine.secret_storage keyring` change them
([settings](settings.md)).

### Root as the owner

On a server where you log in as root, `install` asks whether root is to be
the owner. Without a terminal, give `--owner=root --accept-root-owner`.

- Then `user` mode, and `allowlist --as-owner`, run commands as root.
- A center with the [settings grant](rules.md#the-settings-grant) can switch
  itself to `user` mode, and so gets root.

`install --owner=none` takes it back. [Root as the
owner](../dev/service.md#root-as-the-owner).

### Start and stop

```sh
nerve-node service stop      # the node ends its links; nothing runs
nerve-node service start
nerve-node service restart   # takes every change in node.toml
```

The owner needs no `sudo` for these at the machine itself. Over SSH, use
`sudo`. `nerve-node status` shows the service too.

A machine without systemd runs `nerve-node run` under its own service
manager. Such a node runs every command as you
([a node run by hand](../dev/service.md#a-node-you-run-by-hand)).

## The desktop app

1. Download the package: the `.deb` for Ubuntu and Debian, the `.rpm` for
   Fedora.
2. Double-click it, and press **Install** in the software installer (or
   `sudo apt install ./nerve-node-desktop_<version>_amd64.deb`,
   `sudo dnf install ./nerve-node-desktop-<version>.x86_64.rpm`).
3. Open **Nerve** from the application menu, and press **Install**. The
   system asks for an administrator's password.

The plain program works too: download `nerve-node-desktop-x86_64-linux`,
switch on **Executable as Program** in its **Properties** (GNOME Files) or
tick **Is executable** under **Permissions** (KDE Dolphin), open it, and
press **Install**.

It installs the node as a service, `nerve://` links, so a pairing link opens
in Nerve, and, for the plain program, **Nerve** in the application menu. You
become the node's owner. Its first steps pair your first center and choose its mode.
After that the app needs the password only for what changes the system
([rights](../dev/desktop.md#administrator-rights)).

A node installed before with `nerve-node install` keeps its settings,
pairings and keys; `nerve-node` keeps working. **Settings › App** updates
and uninstalls the app.

## The center as a service

```sh
curl -LO https://github.com/prometheion/nerve-protocol/releases/latest/download/nerve-center-x86_64-linux
chmod +x nerve-center-x86_64-linux
sudo ./nerve-center-x86_64-linux install --name lab
```

It runs as the account `nerve-center`, with MCP over HTTP, and ends with:

```text
Web UI:      http://127.0.0.1:7480
Owner token: nrv_owner_… (logs in to the web UI; …)
Harnesses:   http://127.0.0.1:7481/mcp, with a harness token: …
```

`--name`, `--public-url`, `--listen`, `--ui` and `--mcp` go into its
settings file, `/etc/nerve-center/center.env`, and
`sudo nerve-center set <name> <value>` changes them later. [Run the center](center.md) says what comes
next. `journalctl -u nerve-center` shows its output.

The installed center sees no GPU: its local model runs on the CPU
([the service](../dev/service.md#settings-of-the-service)). On Windows,
install it in an administrator's terminal
([Windows](windows.md#the-center-as-a-service)).

## What it needs

| | |
|---|---|
| Tested | Ubuntu 22.04, 24.04 and 26.04, Debian 12 and 13 on x86_64; Ubuntu 24.04 on aarch64 |
| Expected to work | Fedora, Arch Linux, other distributions with systemd |
| As a service | systemd, polkit, cgroup v2, a file system with ACLs (ext4, XFS, Btrfs) |
| Not as a service | Alpine with OpenRC, Void with runit, WSL 1: run the node by hand |
| Windows | Windows 11 and Server 2025, x64 ([what it needs](windows.md#what-it-needs)) |

How well pairings are kept apart depends on the kernel. On the stock
kernels of these distributions:

- below Linux 6.12 (Ubuntu 22.04, 24.04, Debian 12), one center's commands
  can signal another's and reach its abstract sockets;
- below Linux 6.2 (Ubuntu 22.04, Debian 12), a command can empty a file
  `nerve-run` may write outside its folders, and a node run by hand runs no
  `folder` mode command.

`nerve-node status` warns of both
([Landlock versions](../dev/sandbox-linux.md#landlock-versions)).

## Update

Update the center first, then the nodes: a node does not link to an older
center.

```sh
sudo nerve-center update
sudo nerve-node update
```

`update` takes the program from the latest release, checks it against that
release's `SHA256SUMS`, and restarts the service. `--from <file>` takes a
file you checked yourself. The config, the keys and the audit log stay. If
the new program does not start, the old one comes back. Changes of your own
to a unit belong in `sudo systemctl edit nerve-node`, which `update` leaves
alone. The desktop app updates under **Settings › App › Update…**, also on
Windows; from a package, it installs the release's newer package with `apt` or `dnf`, and a
newer package you install yourself updates the node's service too.

## Uninstall

```sh
sudo nerve-node uninstall           # keeps the config and state
sudo nerve-node uninstall --purge   # deletes them too, keys and audit log
sudo nerve-center uninstall [--purge]
```

`uninstall` takes `nerve-run`'s access off your folders and gives you what
it made there. Kept folders belong to root, and a later `install` takes them
up again. Where the desktop app took over the node, `nerve-node uninstall`
removes the app too. The app from a package: **Settings › App › Uninstall…**
removes the node, then `sudo apt remove nerve-node-desktop` or
`sudo dnf remove nerve-node-desktop` removes the app.

## Where the files are

| What | Where |
|---|---|
| The node's `node.toml` and keys | `/etc/nerve` |
| The node's audit log, log and state | `/var/lib/nerve/state` |
| A pairing's home and temporary folder | `/var/lib/nerve-run/<center>/home`, `…/tmp` |
| The center's state, owner token and log | `/var/lib/nerve-center` |
| The center's settings | `/etc/nerve-center/center.env` |

A node or center you run yourself keeps them in `~/.config/nerve`,
`~/.local/state/nerve` and `~/.local/state/nerve-center`
([all of them](../dev/settings-and-config.md#where-files-live)). The node
reads `NERVE_NODE_*` variables, the center `NERVE_CENTER_*`. A program does
not start while an old name such as `NERVE_STATE_DIR` is set, and names the
file to fix.
