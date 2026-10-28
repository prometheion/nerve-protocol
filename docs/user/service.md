# Run the node as a service

On Linux with systemd and on Windows, `nerve-node` installs itself as a
service. The service starts with the machine and runs under a user of its own,
`nerve`, which owns the node's config and state folders. `install`, `update`
and `uninstall` need root, on Windows an administrator. On Linux without
systemd, run `nerve-node run` under your own service manager
([pairing](pairing.md#keep-it-running)). A node you start yourself as root, or
elevated on Windows, is refused unless `machine.allow_root` is set, and warns
at start when it runs
([root and administrator](platforms.md#root-and-administrator)). Windows
differs in a few places; see [Windows](#windows). The center installs
itself the same way on Linux ([center](center.md#run-it-as-a-service)).

## Install

Download the program for your machine (`nerve-node-x86_64-linux` or
`nerve-node-aarch64-linux`, [install](install.md)) and run it once with
`sudo` from your own account:

```sh
curl -LO https://github.com/prometheion/nerve-protocol/releases/latest/download/nerve-node-x86_64-linux
chmod +x nerve-node-x86_64-linux
sudo ./nerve-node-x86_64-linux install
nerve-node center add '<pairing link>'
nerve-node folder add ~/project +r +w +x
```

That is all: the pairing starts in `folder` mode, and its commands run as
`nerve-run` with the folder you gave it. Whatever the downloaded file is
called, `install` puts it in place as `/usr/local/bin/nerve-node`.

`install` does this, and says each step:

1. Makes the system user `nerve`, with its own group, no login and the home
   `/var/lib/nerve`. The node runs as it.
2. Makes the system user `nerve-run`, with its own group, no other group, no
   login and the home `/var/lib/nerve-run` (mode 0700). Commands of
   `folder` and `allowlist` mode run as it ([modes](modes.md#the-account-nerve-run-linux)).
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
   no folders: `folder ls` still lists them, but `folder` mode and
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
   node answers. The unit hands the node its cgroup (`Delegate=cpu memory
   pids`), so each command runs held to its [limits](limits.md), and keeps
   the node running when one of them is killed for its memory
   (`OOMPolicy=continue`).

### Root as the owner

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
the [settings grant](settings-grant.md) already: with root as the owner they
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
Nothing in Nerve holds them back: the [guard](rules.md#the-guard-against-changing-the-node)
and the center's [action checker](action-checker.md) only catch mistakes.
`folder` mode and `allowlist` mode run as `nerve-run`, as on any node, and
get the folders root gives them. `~` in folders and rules is `/root`.
`status` says `owner: root is the owner: …` (`"owner_is_root": true` with
`--json`), and so does the [desktop app](desktop.md). Root needs no polkit
files to start and stop the service, so `install` writes none. No center can
turn [sudo](sudo.md) on, since sudo checks no password of root's: root does,
with `nerve-node sudo on` on the machine. The node's own file actions (`fs`)
for a center in `user` mode, or in `allowlist` mode as the owner, run as
root without root's extra rights (the service holds only `CAP_SETUID` and
`CAP_SETGID`): they reach what root owns and what the modes let in; the
commands have all of root's rights. For a center in `folder` mode or plain
`allowlist` mode they run as `nerve-run`, as its commands do.

A center with the [settings grant](settings-grant.md) may set its own mode,
and so may switch itself to `user` mode: where root is the owner, its
commands then run as root, and no password is asked. Giving that grant here
gives the center root. `center grant settings write` warns of it, and so does
the desktop app when you give the grant.

`nerve` and `nerve-run` are never the owner, nor another account with uid 0,
nor an account that can open the node's folders.

When the settings of an earlier install keep the keys in the system keyring
([keys](config.md#where-the-node-keeps-its-keys)), `install` first checks
that a keyring answers for `nerve`. In a terminal it offers to install one;
otherwise, and on a no, it stops before it starts the service.

Running `install` again repairs what is missing and restarts the service.

| What | Where |
|---|---|
| `node.toml`, one key per center | `/etc/nerve` |
| Audit log, [log](logs.md), control socket and its token, config key, the last version of `node.toml`, the record of the folders' ACLs | `/var/lib/nerve/state` |
| The keys, with `machine.secret_storage = "keyring"` | the keyring of `nerve`, `/var/lib/nerve/.local/share/keyrings` |
| Home of `nerve` | `/var/lib/nerve` |
| Home of `nerve-run` | `/var/lib/nerve-run` |
| The program | `/usr/local/bin/nerve-node` |
| The unit | `/etc/systemd/system/nerve-node.service` |
| The owner socket and the provider socket, made at each start, gone at the stop | `/run/nerve-node` |
| ACL entries for `nerve-run` | on the folders you grant, and the folders of yours above them |

Nothing else is written. `journalctl -u nerve-node` shows the node's output.

## Use the commands

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
([providers](providers.md)) attach on the provider socket beside it,
`/run/nerve-node/provider.sock`, once the owner allows them with `nerve-node
cap provider allow`. Any other account is refused as it connects. The two
sockets have places of their own, so attached programs never keep the owner's
commands out, nor the reverse.

## The accounts commands run as

`nerve` only holds the node's config, keys and state; no command runs as it.
A center's commands run as one of two accounts:

| Mode | Account |
|---|---|
| `folder` | `nerve-run` |
| `allowlist` | `nerve-run`, or the owner with `mode set allowlist --as-owner` |
| `user` | the owner (root, where [root is the owner](#root-as-the-owner)) |
| an allowed [sudo](sudo.md) command | root: through the owner's sudo where the pairing runs as the owner, started by the node itself where it runs as `nerve-run` |

There is no other account to choose. A command gets the account's groups,
its home as `HOME` and, when the call names no folder, as its working
folder (a sudo command starts in the owner's home). The node reads and writes files for a center (`fs`) as that account
as well: it sees what the account sees, and the files it makes belong to the
account. `~` in [folders](modes.md), [rules](rules.md) and the
[protected paths](protected-paths.md) is the owner's home.

The node's keys are private to `nerve`, and no command of `nerve-run` or
the owner can read them, except where [root is the owner](#root-as-the-owner):
root's commands read them. Before a command starts, the node checks that its
account cannot open the node's folders, and refuses to run it if it can;
root as the owner is let through.
`nerve-run` is in no group and has no sudo of its own: only a command on the
[sudo list](sudo.md), with sudo on, runs as root, started by the node, and
as root it can read what root can, the node's keys included. Put on the
list only what you would run as root yourself. The owner can become root
too, through `sudo` or a group such as `docker`: a `user` mode command runs
as the owner and can do what the owner can, which is the owner's choice of
mode ([modes](modes.md#user-mode)).

### The one privilege the service keeps

To start a command as `nerve-run` or the owner, the service keeps two
capabilities, `CAP_SETUID` and `CAP_SETGID` (`AmbientCapabilities=` in the
unit). This is the one privilege it has beyond what `nerve` may do. The node
uses it to switch to the account, and to give `nerve-run` its folders as the
owner, who owns them. Every command it starts drops both capabilities before
it runs, in every mode, so no command keeps them; a command of root as the
[owner](#root-as-the-owner) keeps all of root's rights instead.

## Setup

`nerve-node setup` asks these things, one at a time. Enter keeps what is
in brackets. It is optional: `center add` and `folder add` do the same. The
owner runs it without `sudo`: its one step that needs root, installing a
keyring, takes root by the service's own rights, for that step alone, and
only after you answer yes at a terminal.

1. The node's name, as centers show it. The host name by default.
2. Where the node keeps its keys: `file` or `keyring`
   ([keys](config.md#where-the-node-keeps-its-keys)). With `keyring` and no
   keyring that answers, it offers to install one where `nerve` has no
   desktop, when you run it at a terminal. If the node had found none when it started, it needs a
   restart: run as root, setup restarts it; run by the owner, it says so,
   and you run `nerve-node service restart` and setup again. Not
   asked on the installed node on Windows, which keeps them in files
   ([Windows](#windows)); setup warns instead.
3. A pairing link from the center's web UI. Enter skips it. The node shows
   the center and asks before it pairs, as `center add` does.
4. The mode of that center: `folder`, `allowlist` or `user`
   ([modes](modes.md)). For `folder` it asks for one folder and its rights;
   Enter gives `+rwx`, so that commands can work there.

Each answer is saved when you give it, through the running node, like every
other command. You can stop setup at any point and run it again. It works on
a node that is not installed as well.

## Start and stop

```sh
nerve-node service stop      # the node ends its links; nothing runs
nerve-node service start
nerve-node service restart   # takes every change in node.toml
nerve-node service status    # anyone may ask
```

`service` does what `systemctl stop|start|restart nerve-node` does (on
Windows, the service control manager), and waits until a node that starts
answers. The owner needs no `sudo` for it at the machine. `install` writes a
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
stopped service starts again with the machine. `service status` says whether
the node is installed as a service, whether it runs, whether it starts with
the machine, and the installed program with its version.

## Update

```sh
sudo nerve-node update
```

`update` downloads the program for this machine from the latest release on
GitHub (`nerve-node-x86_64-linux` or `nerve-node-aarch64-linux`, the names
`install` takes too), checks it against the release's `SHA256SUMS`, puts it
in place as `/usr/local/bin/nerve-node` and restarts the service. `HTTPS_PROXY` is used when it is set.
`--from <file>` takes a program you downloaded and checked yourself.

The config, the keys, the accounts and the audit log are not touched.
`update` refuses a file that is not `nerve-node` and a program older than the
installed one. If the new program does not start, the old one is put back and
started again.

## Uninstall

```sh
sudo nerve-node uninstall           # keeps the config and state folders
sudo nerve-node uninstall --purge   # deletes them too
```

`uninstall` stops and disables the service, removes the unit, takes every
ACL entry of `nerve-run` off your folders, gives what `nerve-run` made in
them to you (not a file with more than one name, which may also lie
outside them; it says how many it left), removes `nerve-run` with its home, the polkit files and the helper, the user `nerve` and
`/usr/local/bin/nerve-node`. If an ACL entry cannot be taken off, it stops
before it removes anything and says which: a uid nobody has must not keep
them. A session that a keyring gave `nerve` is ended first. Without
`--purge`, `/etc/nerve` and `/var/lib/nerve` stay and belong to root from
then on, so no later user with the old uid gets the keys. A later `install`
takes them up again: the node comes back with its pairings, rules and audit
log. `--purge` deletes them, keys and audit log included. The
[desktop app](desktop.md)'s uninstall also removes its menu entry, its link
handler and the `nerve-node` link it made. Where the app took over the node,
`nerve-node uninstall` of the downloaded CLI edition hands over to the app's
(`nerve-node-desktop uninstall`, with `--purge` if given), so the app goes
with the node.

## Windows

Run these commands in a terminal opened with "Run as administrator":

```powershell
.\nerve-node-x86_64-windows.exe install
& "C:\Program Files\Nerve\nerve-node.exe" setup
Restart-Service nerve-node
```

`install` does this, and says each step:

1. Makes the local user `nerve`, with a long random password that nobody
   types; the service manager keeps it. `nerve` may log on as a service and
   in no other way, and does not show on the sign-in screen. A `nerve` user
   that `install` did not make is refused.
2. Makes the folders and gives them an access list of their own: `nerve`,
   SYSTEM and the administrators, nothing inherited from the folders above.
3. Sets the account that commands run as: the account that runs `install`.
   An account chosen before stays. It asks once for that account's password
   and stores it with DPAPI in the config folder, so only what can open that
   folder can read it. A stored password that still works is not asked for
   again.
4. Copies the program to `C:\Program Files\Nerve\nerve-node.exe`.
5. Registers the service `nerve-node`, which runs as `nerve`, starts with the
   machine and starts again after a failure.
6. Registers the source `nerve-node` in the Windows Event Log, then starts
   the service. It waits until the node runs.

| What | Where |
|---|---|
| `node.toml`, one key per center, the stored password of the account commands run as, the sudo password while sudo is on | `C:\ProgramData\Nerve\config` |
| Audit log, [log](logs.md), config key, the last version of `node.toml`, the record of the folder grants (`grants.json`) | `C:\ProgramData\Nerve\state` |
| The program | `C:\Program Files\Nerve\nerve-node.exe` |
| Start, stop, a start that fails, a crash | The Windows Event Log, Application, source `nerve-node` ([logs](logs.md#the-windows-event-log)) |

The service writes its log to `C:\ProgramData\Nerve\state\log.jsonl`. When
it does not start, the Event Viewer says why, and the log has the rest.

`install` also makes the user who ran it an owner of the node: its SID goes
into the service's registry key
(`HKLM\SYSTEM\CurrentControlSet\Services\nerve-node\Parameters`, value
`Owners`), and the service lets it start, stop and restart the service. An
owner runs the other commands in an ordinary terminal; the service runs them
as `nerve` over a pipe open to the owners only, and audits them with the
owner's name ([who may change the node](desktop.md#administrator-rights)).
`install`, `update`, `uninstall`, `setup`, `sudo on` and the `machine.*`
settings that pick the account (also a `restore` that would change them)
still need an administrator's terminal. `uninstall` removes the service, and
the owners and their rights with it.

The other commands work on the installed node from an administrator's
terminal, or an owner's. The service takes `folder add`, `folder set` and
`folder rm` at once over its [control pipe](platforms.md#the-control-pipe),
and every other change at its next start: `Restart-Service nerve-node`, or
`nerve-node service restart`.

The installed node on Windows keeps its keys in files. The service runs as
`nerve`, and the Credential Manager is one per account: keys that `setup` or
`config set` put in the keyring would be in the Credential Manager of the
administrator who ran them, where the service does not find them. So `setup`
does not ask where the keys go, and takes keys it finds in the keyring into
files; `config set machine.secret_storage keyring` is refused and changes
nothing. A `node.toml` that keeps the keys in the keyring is refused by
`install`, before it changes anything, and the service does not start with
one. Move the keys into files first, as the account that put them in the
keyring, in a terminal opened with "Run as administrator". Name the folders:
without a registered service the commands work on your own folders, not on
the node's. Run it with the program you have, the downloaded one before a
first install:

```powershell
.\nerve-node-x86_64-windows.exe --config-dir "C:\ProgramData\Nerve\config" --state-dir "C:\ProgramData\Nerve\state" config set machine.secret_storage file
```

The same account problem keeps the proxy's values out of reach: the installed
node on Windows takes a proxy only if it needs no header and no password.
`proxy set` with either is refused and changes nothing
([proxy](proxy.md#on-the-node-installed-as-a-service-on-windows)).

To run the commands as another account, an ordinary one, name it and run
`install` again; it asks for that account's password:

```powershell
& "C:\Program Files\Nerve\nerve-node.exe" config set machine.user bob
.\nerve-node-x86_64-windows.exe install
```

### The account commands run as on Windows

Every command, and the node's file work for a center, runs as that account,
logged on with its stored password. It must be a local account that has
signed in once, so it has a profile folder. A command gets the account's
environment, its profile folder as working folder when the call names none,
and a job object that ends it with every process it started. While the
account is not signed in, its registry (`HKCU`) is not loaded: a command
then gets the usual folders of its profile (`APPDATA`, `TEMP` and so on),
but not the variables the account set itself. An
administrator's command runs as UAC gives it to a sign-in: the
Administrators group only denies. Before a command starts, the node checks
that the account can open neither the node's folders nor a file in them, and
refuses it if it can. `install` checks the same.

`folder` mode runs no command on the service yet: its AppContainer is not
started as another account ([modes](modes.md#what-a-command-can-reach-in-folder-mode-windows)).
Use `allowlist` or `user` mode for its centers.

UAC is no security boundary: a command of an administrator can get the
group's rights back and read the keys. `install` warns about an account in
Administrators or Backup Operators. Choose an ordinary account as above.
[Sudo on Windows](sudo.md#sudo-on-windows) needs an administrator: its
commands run with the account's administrator rights on purpose.

If the account's password changes, commands fail until `install` runs again
and asks for the new one. A Microsoft account works with its Microsoft
password, which can change outside the machine.

To start a process as that account, the service keeps two privileges,
`SeAssignPrimaryTokenPrivilege` and `SeIncreaseQuotaPrivilege`. Windows
takes every other privilege from it, `SeImpersonatePrivilege` included. No
command gets them.

### Update and uninstall on Windows

`update` downloads `nerve-node-x86_64-windows.exe` and checks it as above.
It stops the service, moves the old program aside, puts the new one in its
place and starts the service; if the new one does not start, the old one
goes back. The old program goes once nothing holds it, or at the next
restart of Windows when Windows still holds it: when `update` ran from it, or
when the Event Log read the text of the node's entries from it. `install`
over an installed node moves the old program aside the same way.

When the [desktop app](desktop.md) takes over a node installed with
`nerve-node.exe`, its `install` removes `C:\Program Files\Nerve\nerve-node.exe`
once the service and the Event Log source name the app's program, or moves it
aside when the Event Log still holds it, as above. The app's program has no
console; the CLI edition, downloaded on its own, is the one for a terminal.

`uninstall` stops and removes the service, the source `nerve-node` of the
Event Log (its entries stay), the user `nerve` and its profile, and the
program. It also takes off the folder grants of `folder` mode that a node
you ran yourself put on, and removes the profiles of its AppContainers
([modes](modes.md#what-a-command-can-reach-in-folder-mode-windows)); the
service puts none on. It names the profiles it removed, and those it left
because that node runs. Without `--purge` the folders and the stored password stay,
open to the administrators only; the [sudo](sudo.md#sudo-on-windows)
password goes, so sudo is off after a later `install`. A later `install`
takes them up again.
`--purge` deletes them. Run from the installed program, `uninstall` cannot
delete that file at once: it moves it aside, and Windows deletes it at its
next start. Where the [desktop app](desktop.md) took over the node,
`nerve-node.exe uninstall` hands over to the app's uninstall, which also
removes the app, its Start menu entry, its link handler and its entry in Apps
& features. Where Windows
still holds the profile of `nerve` (Windows Search can), `uninstall` says how
to remove it after a restart.

## The rules for these commands

- `install`, `setup`, `update` and `uninstall` are refused from a command the
  node runs for a center, as every other change of the node's settings is.
  An agent cannot install, update or remove the node. On Windows the control
  pipe does not take this check yet; there these commands need an
  administrator, which a command gets only through an account in
  Administrators (the UAC warning above).
- Each is written to the [audit log](audit.md) with the steps it did, and the
  error that stopped it, if any. `uninstall --purge` deletes the log with the
  rest.
