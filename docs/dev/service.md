# Installing the node and the center

The life cycle of the installed programs on Linux: what `install` makes,
root as the owner, polkit, `update` and what it puts back, `uninstall`,
and the hand-run unit for a machine without the system service. The user
guide's [install page](../user/install.md) has the commands.

## Download and install

Put `nerve-center` on the machine where your agent harness runs. Put a node
on every machine the agent may use: `nerve-node`, or on a machine with a
desktop `nerve-node-desktop`, the node with an app
([desktop app](desktop.md)). On Windows the node is always the desktop app.
A center and a node can share a machine.

### Download

Get the programs from
[Releases](https://github.com/prometheion/nerve-protocol/releases). Each
release has these files and a `SHA256SUMS` file (seven for Linux, two more
with Windows).

| System | Files |
|---|---|
| Linux, x86_64 | `nerve-center-x86_64-linux`, `nerve-node-x86_64-linux`, `nerve-node-desktop-x86_64-linux`, which also comes as `nerve-node-desktop_<version>_amd64.deb` and `nerve-node-desktop-<version>.x86_64.rpm` |
| Linux, ARM 64-bit | `nerve-center-aarch64-linux`, `nerve-node-aarch64-linux` |
| Windows, x86_64 | `nerve-center-x86_64-windows.exe`, `nerve-node-desktop-x86_64-windows.exe` |

`nerve-node-desktop` is the node with a desktop app, which installs itself
when you open it ([desktop app](desktop.md)). Windows has no `nerve-node` of
its own: there the app is the only way to the node.

The Linux programs except the desktop app are static and need no libraries. The Windows programs
need no Visual C++ runtime. The programs are not signed, so check them
against `SHA256SUMS`.

### Install on Linux

```sh
sha256sum --check --ignore-missing SHA256SUMS
install -m 0755 nerve-center-x86_64-linux ~/.local/bin/nerve-center
install -m 0755 nerve-node-x86_64-linux ~/.local/bin/nerve-node
nerve-node --version
```

Use the `aarch64` files on an ARM machine. `~/.local/bin` must be on your
`PATH`.

To run the node as a service that starts with the machine, download it and
let it install itself instead ([service](#the-node-as-a-service)):

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
mode runs commands as root ([root as the owner](#root-as-the-owner)).
Root stays the owner at a later `install`; `install --owner=none` takes it back.

The center installs itself as a service the same way, with MCP over HTTP
([center](#the-center-as-a-service)):

```sh
curl -LO https://github.com/prometheion/nerve-protocol/releases/latest/download/nerve-center-x86_64-linux
chmod +x nerve-center-x86_64-linux
sudo ./nerve-center-x86_64-linux install
```

### Build from source

See [building](building.md).

### After the install

[Run the center](settings-and-config.md#the-centers-settings-ports-and-files).

## Linux distributions

| | Distributions |
|---|---|
| Tested | Ubuntu 22.04, 24.04 and 26.04, Debian 12 and 13. CI installs the released programs on each and runs the node's and the center's whole install, use and uninstall there, on x86_64 and on Ubuntu 24.04 also on aarch64 |
| Expected to work, not tested | Fedora, Arch Linux, and other distributions with systemd |
| Not supported as a service | Distributions without systemd (Alpine with OpenRC, Void with runit, containers without an init, WSL 1): run the node by hand ([below](#a-node-you-run-by-hand)) |

The tests run on GitHub's kernels, which are newer than the ones the
distributions ship (Ubuntu 22.04 has 5.15, Debian 12 has 6.1). How much
Landlock holds depends on the kernel ([modes](sandbox-linux.md#what-a-command-can-reach-in-folder-mode));
`nerve-node status` shows the version yours has.

`install` and the installed node need:

- systemd, to run the service;
- `useradd`, `userdel`, `getent` and `id`, for the accounts `nerve` and
  `nerve-run`;
- a file system with POSIX ACLs where you grant folders (ext4, XFS, Btrfs
  have them);
- cgroup v2, which systemd gives every current distribution, for the
  [limits per command](sandbox-linux.md#limits-per-command);
- polkit with `pkexec`, for `nerve-node service` and the desktop app to start
  and stop the service without `sudo`;
- for the keyring step of `setup` only, `apt`, `dnf` or `pacman`
  ([config](settings-and-config.md#settings-as-the-owner-changes-them)); elsewhere install GNOME Keyring yourself, or keep the
  keys in files.

### A node you run by hand

Without systemd, or for a node of your own account, run `nerve-node run`
under your service manager. Such a node runs every command as you: there is
no `nerve-run`, `folder` mode needs Landlock, and it offers no
[capabilities of `node.toml`](capabilities.md#capabilities-of-your-own-in-nodetoml). With systemd, a unit of
your own systemd keeps it running and gives it its [limits](sandbox-linux.md#limits-per-command):

```ini
# ~/.config/systemd/user/nerve-node.service
[Unit]
Description=Nerve node

[Service]
ExecStart=%h/.local/bin/nerve-node run
Restart=on-failure
RestartSec=5
# The node's own cgroup, to hold each command to its limits.
Delegate=yes

[Install]
WantedBy=default.target
```

```sh
install -m 755 nerve-node-x86_64-linux ~/.local/bin/nerve-node
systemctl --user daemon-reload
systemctl --user enable --now nerve-node
loginctl enable-linger "$USER"   # starts it at boot, before you log in
nerve-node status
```

Without systemd, start `nerve-node run` from your service manager as your
own account, not as root; its commands then run without limits, and
`nerve-node status` says why.

## The node as a service

On Linux with systemd, `nerve-node` installs itself as a service. The
service starts with the machine and runs under a user of its own, `nerve`,
which owns the node's config and state folders. `install`, `update` and
`uninstall` need root. On Linux without systemd, run `nerve-node run` under
your own service manager ([pairing](identity-and-pairing.md#keep-it-running)). A node you
start yourself as root is refused unless `machine.allow_root` is set, and
warns at start when it runs
([root and administrator](windows.md#root-and-administrator)). On Windows
the node is always the service, and the [desktop app](desktop.md) installs
and runs it; see [Windows](windows.md#the-node-as-a-service-on-windows). The center installs itself the same
way on Linux ([center](#the-center-as-a-service)).

### What `install` does

Download the program for your machine (`nerve-node-x86_64-linux` or
`nerve-node-aarch64-linux`, [install](#download-and-install)) and run it once with
`sudo` from your own account:

```sh
curl -LO https://github.com/prometheion/nerve-protocol/releases/latest/download/nerve-node-x86_64-linux
chmod +x nerve-node-x86_64-linux
sudo ./nerve-node-x86_64-linux install
```

At a terminal, `install` then asks [setup](#setup)'s questions as you (the
account that ran `sudo`, so `~` is your home): the pairing link, the mode, a
folder and its rights, and the network. Without a terminal it says what to
run instead:

```sh
nerve-node center add -     # then paste the pairing link
nerve-node folder add ~/project rwx
```

That is all: the pairing starts in `folder` mode, and its commands run as
`nerve-run` with the folder you gave it. Whatever the downloaded file is
called, `install` puts it in place as `/usr/local/bin/nerve-node`.

`install` does this, and says each step:

1. Makes the system user `nerve`, with its own group, no login and the home
   `/var/lib/nerve`. The node runs as it.
2. Makes the system user `nerve-run`, with its own group, no other group, no
   login and the home `/var/lib/nerve-run` (mode 0700), which holds a home
   and a temporary folder for each pairing. Commands of
   `folder` and `allowlist` mode run as it ([modes](sandbox-linux.md#the-account-nerve-run)).
   A `nerve` or `nerve-run` that `install` did not make is refused.
3. Makes the folders, private to `nerve` (mode 0700). Folders an earlier
   install left behind are given to the new user.
4. Takes the account that ran `sudo` (or polkit's `pkexec`, with which the
   [desktop app](desktop.md) asks) as the node's owner. Run by root without
   `sudo` (or with `sudo` from root), it keeps root where an earlier install
   made root the owner. Otherwise it asks at a terminal whether root is to
   be the owner, and says what that means and what a yes and a no do; the
   answer is no unless you type `y` or `yes`
   ([root as the owner](#root-as-the-owner)). On a no it keeps the owner an
   earlier install named, or has none: then only root changes the node and
   `user` mode runs no command. Where the owner changes, `install`, once
   the steps that can refuse are through (right before step 6), stops the
   service and takes `nerve-run`'s entries off every folder the earlier
   owner gave it, as `uninstall` does; the node gives the folders again for
   the new owner when it starts. Without a new owner it gives `nerve-run`
   no folders: `folder` still lists them, but `folder` mode and
   `allowlist` mode reach only what every account may. Where not all
   entries come off, the owner stays as it was, its node walks every
   folder again when it starts, the service runs again where it ran, and
   `install` says what failed. A later step that fails starts the stopped
   service again too.
5. Copies the program to `/usr/local/bin/nerve-node`.
6. Writes the polkit files that let the owner start and stop the service
   ([below](#start-and-stop)).
7. Writes the unit `/etc/systemd/system/nerve-node.service`, which names the
   owner (`NERVE_NODE_OWNER`), enables it and starts it. It waits until the
   node answers. The unit is `Type=notify` (`NotifyAccess=main`): the node
   sends `READY=1` once its control, provider and owner sockets are bound,
   so `systemctl start` returns only then, and fails at once for a node
   that cannot start. A unit written by hand for the installed layout needs
   `Type=notify` too. The node takes `NOTIFY_SOCKET` out of the environment
   of every program it starts. The unit hands the node its cgroup (`Delegate=cpu memory
   pids`), so each command runs held to its [limits](sandbox-linux.md#limits-per-command), and keeps
   the node running when one of them is killed for its memory
   (`OOMPolicy=continue`). It raises the soft limit of open files to 65,536 and keeps the hard one at systemd's
   default 524,288 (`LimitNOFILE=65536:524288`): the walks of a granted folder hold a file per
   level, and a command can still raise its own limit as far as it could before.

#### Root as the owner

On a server where you log in as root, there is no other account to be the
owner, and without one `user` mode and `allowlist` mode as the owner run no
command. Root may be the owner, as your own decision:

```sh
./nerve-node-x86_64-linux install          # at a terminal: answer y
./nerve-node-x86_64-linux install --owner=root --accept-root-owner   # no terminal
nerve-node install --owner=none            # root is the owner no longer
```

At a terminal `install` asks `Make root the owner of this node? [y/N]`, and
says before it what a yes and a no do on this node, and which centers have
the [settings grant](settings-and-config.md#the-settings-grant) already: with root as the owner they
can run commands as root. The flags' install says the same. It asks only where both
its input and its output are a terminal, and not with `--json`. Elsewhere (a
script, piped input, output to a file, the desktop app) nothing is asked and
the answer is no at once, unless you give both flags; `install` then says on
stderr which flags make root the owner. `--owner=root` or
`--accept-root-owner` alone is refused, and so are the flags from `sudo` by
another account, which makes that account the owner.

Once root is the owner, it stays the owner at every later `install` by root,
at a terminal or not, and is not asked again. `install --owner=none` takes
it back and leaves the node without an owner (it does so for any owner);
the node then gives `nerve-run` none of the folders you gave, so `folder`
mode reaches them no more (step 4 above);
`sudo nerve-node install` from another account makes that account the owner.
`update` keeps the owner.

With root as the owner, commands of `user` mode and of `allowlist` mode as
the owner run as root (`HOME=/root`, root's groups). They can do everything
on this machine, and change and read Nerve itself, its keys included.
Nothing in Nerve holds them back: the [guard](policy-engine.md#the-guard-against-changing-the-node)
and the center's [action checker](action-checker.md#the-checker-as-the-owner-sets-it-up) only catch mistakes.
`folder` mode and `allowlist` mode run as `nerve-run`, as on any node, and
get the folders root gives them. `~` in folders and rules is `/root`.
`status` says `owner: root is the owner: …` (`"owner_full_rights": true` with
`--json`), and so does the [desktop app](desktop.md). Root needs no polkit
files to start and stop the service, so `install` writes none. No center can
turn [sudo](policy-engine.md#sudo-as-the-owner-uses-it) on, since sudo checks no password of root's: root does,
with `nerve-node sudo on` on the machine. The node's own file actions (`fs`)
for a center in `user` mode, or in `allowlist` mode as the owner, run as
root without root's extra rights (the service holds only `CAP_SETUID` and
`CAP_SETGID`): they reach what root owns and what the modes let in; the
commands have all of root's rights. For a center in `folder` mode or plain
`allowlist` mode they run as `nerve-run`, as its commands do.

A center with the [settings grant](settings-and-config.md#the-settings-grant) may set its own mode,
and so may switch itself to `user` mode: where root is the owner, its
commands then run as root, and no password is asked. Giving that grant here
gives the center root. `center settings on` warns of it, and so does
the desktop app when you give the grant.

`nerve` and `nerve-run` are never the owner, nor another account with uid 0,
nor an account that can open the node's folders.

When the settings of an earlier install keep the keys in the system keyring
([keys](settings-and-config.md#where-the-node-keeps-its-keys)), `install` first checks
that a keyring answers for `nerve`. In a terminal it offers to install one;
otherwise, and on a no, it stops before it starts the service.

Running `install` again repairs what is missing and restarts the service.

| What | Where |
|---|---|
| `node.toml`, one key per center | `/etc/nerve` |
| Audit log, [log](logging.md#the-log-as-the-owner-reads-it), control socket and its token, config key, the last version of `node.toml`, the record of the folders' ACLs and of the pairings' own folders | `/var/lib/nerve/state` |
| The keys, with `machine.secret_storage = "keyring"` | the keyring of `nerve`, `/var/lib/nerve/.local/share/keyrings` |
| Home of `nerve` | `/var/lib/nerve` |
| Home of `nerve-run` | `/var/lib/nerve-run` |
| A pairing's home and temporary folder | `/var/lib/nerve-run/<center>/home`, `/var/lib/nerve-run/<center>/tmp` |
| The program | `/usr/local/bin/nerve-node` |
| The unit | `/etc/systemd/system/nerve-node.service` |
| The owner socket and the provider socket, made at each start, gone at the stop | `/run/nerve-node` |
| ACL entries for `nerve-run` | on the folders you grant, and the folders of yours above them |

Nothing else is written. `journalctl -u nerve-node` shows the node's output.

### Use the commands

When the node is installed, `nerve-node` without `--config-dir` and
`--state-dir` works on the installed node. Its owner, the account that ran
`install`, runs the commands without `sudo`:

```sh
nerve-node status
nerve-node rule add allow 'git status'
nerve-node service restart
```

The running node takes them on its owner socket, `/run/nerve-node/owner.sock`,
from the owner's account (and root) only, runs them as `nerve` with the CLI's
checks, and audits them with the owner's name ([who may change the
node](desktop.md#administrator-rights)). These stay root's, with `sudo`:
`install`, `update`, `uninstall`, `sudo on`, and
`machine.allow_root`, `machine.sudo_path` and `machine.shell`, also a
`restore` that would change them. `backup` and `restore` open the file as the
owner and hand it to the node ([backup](backup.md#on-a-node-installed-as-a-service)).
While the node is stopped, only root changes it. A command that root runs on
these folders runs as `nerve`, so every file it writes stays the node's.
Another user gets a message that says to use `sudo`.

Programs of the owner's and root's that add capabilities
([providers](capabilities.md#capability-providers-in-use)) attach on the provider socket beside it,
`/run/nerve-node/provider.sock`, once the owner allows them with `nerve-node
provider add`. Any other account is refused as it connects. The two
sockets have places of their own, so attached programs never keep the owner's
commands out, nor the reverse.

The [web UI](web-uis.md#the-nodes-web-ui) is part of the service too, on Linux, and off
until the owner runs `nerve-node ui on`: then the running service listens on
`127.0.0.1:7470` itself, with no change to the unit. `nerve-node ui off`
stops it at once. Off, the service listens on nothing for it.

### Setup

`nerve-node setup` asks these things, one at a time; `install` asks them at
a terminal. Enter keeps what is in brackets. It is optional: `center add`,
`folder add` and `network` do the same. The owner runs it without `sudo`.

1. A pairing link from the center's web UI. Enter skips it. The node shows
   the center and asks before it pairs, as `center add` does.
2. The mode of that center: `folder`, `allowlist` or `user`
   ([modes](policy-engine.md#modes-and-folders-as-the-owner-sets-them)). For `folder` it asks for one folder and its rights;
   Enter gives `rwx`, so that commands can work there. `~` is your home.
3. The network for its commands: `on` or `off`. In `user` mode no command
   runs while it is off, and setup says so first.

The node's name stays the host name (`nerve-node config set node.name lab-pc`
changes it), and its keys stay in files (`nerve-node config set
machine.secret_storage keyring` moves them to the system keyring
([keys](settings-and-config.md#where-the-node-keeps-its-keys)); with no keyring that
answers it offers, at a terminal, to install one where `nerve` has no
desktop, taking root by the service's own rights for that step alone).

Each answer is saved when you give it, through the running node, like every
other command. You can stop setup at any point and run it again. It works on
a node that is not installed as well.

### Start and stop

```sh
nerve-node service stop      # the node ends its links; nothing runs
nerve-node service start
nerve-node service restart   # takes every change in node.toml
nerve-node status            # the service too; anyone may ask
```

`service` does what `systemctl stop|start|restart nerve-node` does, and
waits until a node that starts answers. On Windows the app's **Overview**
does it ([start and stop](desktop.md#start-and-stop)). The owner needs no `sudo` for it at the machine. `install` writes a
helper, `/usr/local/lib/nerve-node/service-control`, that starts, stops or
restarts `nerve-node.service` and does nothing else, with a polkit action of
its own (`/usr/share/polkit-1/actions/org.nerve-protocol.node.service-control.policy`).
`service` runs it through `pkexec`, and polkit lets the owner do that without
a password from their own local session: by the rule
`/etc/polkit-1/rules.d/50-nerve-node.rules` (which also lets the owner use
`systemctl` for this service), or on polkit 0.105 (Ubuntu 22.04), which takes
no rules, by `/etc/polkit-1/localauthority/50-local.d/50-nerve-node.pkla`.
No file lets the owner manage other units. Over SSH it needs `sudo`. Root
as the owner needs none of these files, and `install` writes none for it. A
stopped service starts again with the machine. A node that ends with an error
or a signal starts again after 5 seconds (`Restart=on-failure`; on Windows
the service's failure actions, after a stop with an error too: 5 seconds,
5 seconds, then every minute, without end). The node and the
center end so on purpose when a lock is poisoned
([logging](logging.md#a-poisoned-lock)). `status` says whether
the node is installed as a service, whether it runs, whether it starts with
the machine, and the installed program's version.

### Update the node

```sh
sudo nerve-node update
```

`update` downloads the program for this machine from the latest release on
GitHub (`nerve-node-x86_64-linux` or `nerve-node-aarch64-linux`, the names
`install` takes too), checks it against the release's `SHA256SUMS`, puts it
in place as `/usr/local/bin/nerve-node` and restarts the service. `HTTPS_PROXY` is used when it is set.
`--from <file>` takes a program you downloaded and checked yourself.

`update` also writes the service unit, the polkit files and the helper that
starts and stops the service as the new program has them, for the owner the
unit names: a release that changes them needs no `install` again. It asks the
new program for them, run as root with an empty environment, before it takes
the old one's place. The same program again still brings the files it has,
so a second `update` repairs a unit that is behind.

The unit is written as a whole, so a line of your own in it is replaced.
Local changes, an `Environment=` line for a proxy for one, belong in a
drop-in, `sudo systemctl edit nerve-node`, which `update` and `install`
leave alone.

This holds for an update done by a release that has it. The update that
brings a release is done by the program already installed, which replaces
only the program; the first time after such a release (the notes say when)
run `sudo nerve-node install` once, or `update` again, for the new unit and
polkit files.

The config, the keys, the accounts and the audit log are not touched.
`update` refuses a file that is not `nerve-node` and a program older than the
installed one. If the new program does not start, the old one is put back
with the old unit and polkit files, and started again.

A program the node may just have written (the program `update` staged, the
desktop app at the hand-over of `uninstall`, the owner's program) is started
again when Linux answers "Text file busy": five tries, 50 ms apart. Why a
command for the owner did not start reaches the CLI.

### Uninstall the node

```sh
sudo nerve-node uninstall           # keeps the config and state folders
sudo nerve-node uninstall --purge   # deletes them too
```

`uninstall` stops and disables the service, removes the unit, takes every
ACL entry of `nerve-run` off your folders, gives what `nerve-run` made in
them to you (not a file with more than one name, which may also lie
outside them; it says how many it left), deletes what `nerve-run`'s commands
left in `/tmp`, `/var/tmp` and `/dev/shm` (a folder there it does not look
into, more than 64 levels deep or changed while it looked, is named, and what
is in it stays), removes `nerve-run` with its home, the polkit files and the helper, the user `nerve` and
`/usr/local/bin/nerve-node`. If an ACL entry cannot be taken off, it stops
before it removes anything and says which: a uid nobody has must not keep
them. A session that a keyring gave `nerve` is ended first. Without
`--purge`, `/etc/nerve` and `/var/lib/nerve` stay and belong to root from
then on, so no later user with the old uid gets the keys. A later `install`
takes them up again: the node comes back with its pairings, rules and audit
log. `--purge` deletes them, keys and audit log included. The
[desktop app](desktop.md)'s uninstall also removes its menu entry, its link
handler and the `nerve-node` link it made. Where the app took over the node,
`nerve-node uninstall` of a `nerve-node` downloaded on its own hands over to the app's
(`nerve-node-desktop uninstall`, with `--purge` if given), so the app goes
with the node.

### The rules for these commands

- `install`, `setup`, `update` and `uninstall` are refused from a command the
  node runs for a center, as every other change of the node's settings is.
  An agent cannot install, update or remove the node. On Windows these
  three do not go over the control pipe, which refuses every request from a
  command's process; they need an administrator, which a command gets only
  through an account in Administrators (the UAC warning above).
- Each is written to the [audit log](logging.md#the-audit-log-as-the-owner-reads-it) with the steps it did, and the
  error that stopped it, if any. `uninstall --purge` deletes the log with the
  rest.

## The center as a service

On Linux with systemd, `nerve-center` installs itself as a service, as the
node does ([service](#the-node-as-a-service)). The service starts with the machine and
runs under a user of its own, `nerve-center`, with MCP over HTTP: harnesses
connect to it with a [harness token](mcp-surface.md#tokens) instead of starting
it. `install`, `update` and `uninstall` need root and take none of the
center's flags: the service's settings are in its
[settings file](#settings-of-the-service). On Windows the same commands run
in an administrator's terminal
([Windows](windows.md#the-center-as-a-windows-service)).

### Install

Download the program for your machine (`nerve-center-x86_64-linux` or
`nerve-center-aarch64-linux`, [install](#download-and-install)) and run it once as
root:

```sh
curl -LO https://github.com/prometheion/nerve-protocol/releases/latest/download/nerve-center-x86_64-linux
chmod +x nerve-center-x86_64-linux
sudo ./nerve-center-x86_64-linux install
```

`install` does this, and says each step:

1. Makes the system user `nerve-center`, with its own group, no login and the
   home `/var/lib/nerve-center`. A `nerve-center` user that `install` did
   not make is refused.
2. Makes the state folder `/var/lib/nerve-center`, private to that user
   (mode 0700). A folder an earlier install left behind is given to the new
   user.
3. Makes the [owner token](web-uis.md#log-in) in
   `/var/lib/nerve-center/owner-token` (mode 0600), unless one is there.
4. Writes the settings file `/etc/nerve-center/center.env`, which belongs to
   root (mode 0600), with a new harness token for the HTTP MCP endpoint. A
   settings file that is there already is kept as it is.
5. Copies the program to `/usr/local/bin/nerve-center`.
6. Writes the unit `/etc/systemd/system/nerve-center.service`, enables it
   and starts it. It waits until the center answers.

Running `install` again repairs what is missing and restarts the service.

Last it prints the owner token. Open the web UI, `http://127.0.0.1:7480`,
and log in with it. To see it again, or to make a new one:

```sh
sudo cat /var/lib/nerve-center/owner-token
sudo nerve-center owner-token --new
```

Harnesses on this machine use the HTTP MCP endpoint,
`http://127.0.0.1:7481/mcp`, with the harness token of the settings file
(`sudo grep NERVE_CENTER_HARNESS_TOKEN /etc/nerve-center/center.env`) or one made
in the web UI ([harness](mcp-surface.md#what-a-harness-and-its-model-see)). A harness cannot start its own
`nerve-center` on this machine while the service runs: the node port is
taken.

| What | Where |
|---|---|
| Identity and TLS key, paired machines, statistics, the [action checker](action-checker.md#the-checker-as-the-owner-sets-it-up)'s settings and local model, [log](logging.md#the-log-as-the-owner-reads-it), harness socket | `/var/lib/nerve-center` |
| Settings | `/etc/nerve-center/center.env` |
| The program | `/usr/local/bin/nerve-center` |
| The unit | `/etc/systemd/system/nerve-center.service` |

Nothing else is written. `journalctl -u nerve-center` shows the center's
output.

The service starts with a new center. To move a center you ran yourself
into it, with its pairings, [back it up](backup.md#the-center) and restore
it into the service's state folder while the service is stopped:

```sh
nerve-center --state-dir ~/.local/state/nerve-center backup ~/nerve-center.bak   # as you, on the center you ran
sudo nerve-center restore ~/nerve-center.bak --replace   # stops the service and starts it again
```

Stop the center you ran yourself for good: the service has its key now.

### Settings of the service

The settings are the variables of the [table above](settings-and-config.md#the-centers-settings), in
`/etc/nerve-center/center.env`. Change them there and restart the service:

```sh
sudo nano /etc/nerve-center/center.env
sudo systemctl restart nerve-center
```

The service runs with `--mcp http` unless the file sets `NERVE_CENTER_MCP`;
`stdio` does not work there, as no harness gives it an input. The state
folder is fixed. The settings file belongs to root, so the center cannot
change how it is started.

The service has no privilege: no capability, and no new privileges through
a setuid program. It may write its state folder and nothing else on the
machine, and sees no home folders, no shared memory (`/dev/shm`) and no
hardware devices, so the action checker's local model runs on the CPU there. The
unit also keeps it from the kernel interfaces a center never needs: it may
not make namespaces, open other sockets than IPv4, IPv6 and Unix ones, or
make system calls outside systemd's `@system-service` set, and it cannot
see other processes or change kernel settings, the clock or the host name.
A `NERVE_CENTER_LISTEN` on a port below 1024 fails; use a higher port, or forward
one to it.

### Update

```sh
sudo nerve-center update
```

`update` downloads `nerve-center-x86_64-linux` or
`nerve-center-aarch64-linux` from the latest release on GitHub, checks it
against the release's `SHA256SUMS`, puts it in place as
`/usr/local/bin/nerve-center` and restarts the service. `HTTPS_PROXY` is used
when it is set. `--from <file>` takes a program you downloaded and checked
yourself.

`update` also writes the service unit as the new program has it, so a
release that changes it needs no `install` again, and its steps go to the
center's [log](logging.md#the-log-as-the-owner-reads-it) file. The running center reads that file only when it starts, so the entry reaches the Log page at the center's next start; the file download has it at once. It asks the new program for the unit, run as root
with an empty environment; the same program again still brings the unit it
has, so a second `update` repairs a unit that is behind. The unit is written
as a whole, so a line of your own in it is replaced: local changes belong in
a drop-in, `sudo systemctl edit nerve-center`, which `update` and `install`
leave alone. This holds for an update done by a release that has it: the
update that brings such a release is done by the program already installed,
which replaces only the program, so the first time after it (the notes say
when) run `sudo nerve-center install` once, or `update` again.

The state folder and the settings are not touched. `update` refuses a file
that is not `nerve-center` and a program older than the installed one. If the
new program does not start, the old one is put back with the old unit and
started again. Its
last line says where the owner token is: a center installed before there
was one makes it at this start, and its web UI no longer takes the harness
token (`sudo cat /var/lib/nerve-center/owner-token`).

### Uninstall

```sh
sudo nerve-center uninstall           # keeps the state and the settings
sudo nerve-center uninstall --purge   # deletes them too
```

`uninstall` stops and disables the service, removes the unit, the user
`nerve-center` and `/usr/local/bin/nerve-center`. Without `--purge`,
`/var/lib/nerve-center` and `/etc/nerve-center` stay and belong to root from
then on, so no later user with the old uid gets the center's key. A later
`install` takes them up again: the center comes back with its pairings and
its harness token and its owner token. `--purge` deletes them.

`install`, `update` and `uninstall` are refused from a command that the node
installed on the same machine runs for a center, as the node's own are
([service](#the-rules-for-these-commands)).
