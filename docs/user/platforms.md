# Linux and Windows

The center and the node run on Linux (x86_64, aarch64) and Windows (x86_64),
the [desktop app](desktop.md) (`nerve-node-desktop`, the node with an app) on
Linux x86_64 and Windows x86_64. The node behaves the same except where this
page says so. The Linux programs are static and run on any distribution;
installing them as a service needs systemd ([distributions](#linux-distributions)).
The desktop app is not static, and needs glibc 2.35 or newer (Ubuntu 22.04,
Debian 12, Fedora 36 and later) and fontconfig.

| | Linux | Windows |
|---|---|---|
| The node's program | `nerve-node`, or the [desktop app](desktop.md) | The desktop app only |
| Shell for commands | `/bin/sh -c` | Windows PowerShell 5.1 (`powershell.exe -NoProfile -Command`) |
| `folder` mode runs commands | Yes, confined by Landlock; on the installed node as `nerve-run`, also where Landlock is missing | Yes, confined by an AppContainer; not yet on the [installed service](service.md#windows) |
| `allowlist` and `user` mode run commands | Yes | Yes, in a Job Object, not confined to folders |
| Sudo switch | Yes | On the [installed service](service.md#windows), with the administrator token of the account commands run as ([sudo on Windows](sudo.md#sudo-on-windows)) |
| Control socket | Yes | A control pipe: `status`, `center rotate-key` and folder changes, no other change |
| [Providers](providers.md) | Yes | Not yet |
| [Capabilities of `node.toml`](config-capabilities.md) | Yes: the installed node, as `nerve-run`; a node you run yourself offers none | Kept in `node.toml`, offered not yet |
| Install as a service | Yes, with systemd, the node and the [center](center.md#run-it-as-a-service) | The node |
| The center's [action checker](action-checker.md) | Yes. Its local model on x86_64 and aarch64, on the CPU or a Vulkan GPU; the installed center service runs it on the CPU only | Yes. Its local model on x86_64, on the CPU or a Vulkan GPU |
| Config folder | `~/.config/nerve` | `C:\ProgramData\Nerve\config` (the installed service) |

## Linux distributions

| | Distributions |
|---|---|
| Tested | Ubuntu 22.04 and 24.04, Debian 12. CI installs the released programs on each and runs the node's and the center's whole install, use and uninstall there, on x86_64 and on Ubuntu 24.04 also on aarch64 |
| Expected to work, not tested | Fedora, Arch Linux, and other distributions with systemd |
| Not supported as a service | Distributions without systemd (Alpine with OpenRC, Void with runit, containers without an init, WSL 1): run the node by hand ([below](#a-node-you-run-by-hand)) |

The tests run on GitHub's kernels, which are newer than the ones the
distributions ship (Ubuntu 22.04 has 5.15, Debian 12 has 6.1). How much
Landlock holds depends on the kernel ([modes](modes.md#what-a-command-can-reach-in-folder-mode-linux));
`nerve-node status` shows the version yours has.

`install` and the installed node need:

- systemd, to run the service;
- `useradd`, `userdel`, `getent` and `id`, for the accounts `nerve` and
  `nerve-run`;
- a file system with POSIX ACLs where you grant folders (ext4, XFS, Btrfs
  have them);
- cgroup v2, which systemd gives every current distribution, for the
  [limits per command](limits.md);
- polkit with `pkexec`, for `nerve-node service` and the desktop app to start
  and stop the service without `sudo`;
- for the keyring step of `setup` only, `apt`, `dnf` or `pacman`
  ([config](config.md)); elsewhere install GNOME Keyring yourself, or keep the
  keys in files.

### A node you run by hand

Without systemd, or for a node of your own account, run `nerve-node run`
under your service manager. Such a node runs every command as you: there is
no `nerve-run`, `folder` mode needs Landlock, and it offers no
[capabilities of `node.toml`](config-capabilities.md). With systemd, a unit of
your own systemd keeps it running and gives it its [limits](limits.md):

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

## Linux

- With the node running, `nerve-node status` shows `confinement landlock
  v…`, or `confinement none` when the kernel has no Landlock (some
  container hosts, older kernels; on a node you run yourself also Landlock
  below ABI 3, before Linux 6.2: the stock kernels of Ubuntu 22.04 and
  Debian 12). On the node installed as a service,
  `folder` and `allowlist` mode then run their commands as `nerve-run`
  without Landlock, held back by the account alone; `status` says `as
  nerve-run, without Landlock`. A node you run yourself refuses every
  `folder` mode command without Landlock.
- Without Landlock, `nerve-run` reads in your home what any other account
  may: when your home is open to others (`ls -ld ~` shows `drwxr-xr-x` or
  `drwx--x--x`), and when you give it a folder in your home, which it passes
  through. `install`, `status` and the app say so: for an open home until
  you close it (`chmod 750 ~`), and for a folder in your home as long as it
  is given. Give it folders outside your home, or use a kernel with
  Landlock; `umask 027` only narrows what it can read. See
  [modes](modes.md#your-home-and-other-accounts). With Landlock nothing is
  said: it holds each command to its folders.
- Landlock below ABI 6 (Linux 6.12; the stock kernels of Ubuntu 22.04 and
  24.04 and Debian 12 are older) lets a command signal other processes of its account and
  reach abstract unix sockets: the installed node's pairings, whose commands
  are all `nerve-run`'s, are kept apart from each other only from ABI 6.
  Below ABI 3 (Ubuntu 22.04's 5.15, Debian 12's 6.1) a command can also cut
  a file it may write outside its folders to nothing; the installed node
  still uses that Landlock, a node you run yourself runs no `folder` mode
  command there. `install` and `status` name what the kernel's Landlock
  lacks. See [Landlock versions](modes.md#landlock-versions).
- A `folder` mode command, and every command of `nerve-run`, has no
  controlling terminal; a node you run yourself gives its `allowlist` and
  `user` mode commands the terminal it was started in. Of the installed node's
  environment a command of `nerve-run` gets only `PATH`, `LANG`, `TERM`,
  `TMPDIR` and the names in `machine.command_env`. A node you run yourself
  gives its commands your whole environment.
- Commands run with `no_new_privs`, so setuid programs cannot gain privileges.
  Only a command on the [sudo list](sudo.md) runs without it.
- When a call ends, the node kills the command's whole process group.
- Each command runs in a cgroup of its own, held to its memory, CPU and
  processes ([limits](limits.md)), where systemd hands the node a cgroup: the
  installed service, or a node started with `systemd-run --user --scope -p
  Delegate=yes`. Windows does not hold commands to these limits yet.
- On the node [installed as a service](service.md), `folder` and `allowlist`
  mode commands run as `nerve-run`, an account of its own with no other
  groups and no way to root but the [sudo list](sudo.md)
  ([modes](modes.md#the-account-nerve-run-linux)). It reaches your files only
  where you grant a folder (POSIX ACLs), cannot open the node's files (a
  sudo command runs as root and can), is refused by the owner socket, and your session's
  programs (the service manager, the session bus, tmux) take no requests
  from it, on every kernel. Landlock holds it to its own pairing's folders on
  top, where the kernel has it.
- A `user` mode command runs as you, the owner, without a sandbox: it can do
  what you can, change the node's settings through the owner socket
  included. That is the owner's choice of mode. The node refuses the owner
  socket to processes it sees below a command, which a command can leave
  (`( … & )`, `setsid -f`): that catches mistakes, it is no boundary. The
  same holds for `allowlist` mode with `--as-owner`.
- A node you run yourself runs every command as you. Its control socket
  answers only programs that can read its token in the state folder, which
  `folder` mode's sandbox keeps from a command, but the sandbox holds the
  command's own processes only: one of your programs that runs things on
  request runs what the command asks outside it, as you. Install the node to
  run commands as `nerve-run`.
- A [sudo](sudo.md) command runs as root, whatever account the other
  commands run as. It reads the node's files and can change it. The sudo
  list is yours to choose.
- A node that runs as root is refused unless `machine.allow_root` is set
  ([root and administrator](#root-and-administrator)).
- A [capability of `node.toml`](config-capabilities.md) runs as `nerve-run`,
  held to the pairing's folders and its own, by Landlock where the kernel has
  it; a node you run yourself has no `nerve-run` and offers none.

## Windows

- The [desktop app](desktop.md) is the only way to the node: there is no
  `nerve-node` for a terminal, and the app does each of its commands.
- Commands run in Windows PowerShell 5.1. `;` chains commands. `&` does not.
- Each command runs in a Job Object. The shell starts suspended, joins the job
  and only then runs, so every process it starts is in the job. Ending the job
  ends all of them. The job closes with the node, so a node that dies leaves no
  command running.
- Windows has no signals. A timeout, `term` and `int` send Ctrl+C to the
  command's console (each command has one of its own, without a window) and
  ask its windows to close, then end the job 3 seconds later. `kill` ends the
  job at once. See [what ends a command](stop.md#what-ends-a-command). A node
  started with Ctrl+C ignored, as cmd's `start /b` starts it, stops ignoring
  it at its first command, so that its commands hear it: Ctrl+C in that
  console then stops the node too.
- A process that another program starts for the command, such as WMI, a
  service or the task scheduler, belongs to that program and is not in the job.
- A Job Object does not limit file access. It is not a sandbox. In `folder`
  mode the command also runs in an AppContainer, which is. See
  [modes](modes.md#what-a-command-can-reach-in-folder-mode-windows), and for
  what the container does not stop,
  [the list there](modes.md#what-the-appcontainer-does-not-stop).
- Output that is not UTF-8 is read in the OEM code page, the one a new
  console starts with.
- A [sudo](sudo.md#sudo-on-windows) command runs with the elevated token of
  the account commands run as, which must be an administrator. Every other
  command of that account runs with the token UAC filtered. UAC is no
  security boundary, so those commands can get the administrator rights back
  as well.
- Paths in rules and over the wire look like `/c/Users/x`.
- The node runs only as the installed service, which the
  [desktop app](desktop.md) installs and starts, as its own account `nerve`:
  never elevated, and never by hand ([root and administrator](#root-and-administrator)).
- `cap add` keeps a [capability of your own](config-capabilities.md) in
  `node.toml`, also one for `windows`, but the node offers none yet.

### Root and administrator

A node with full rights hands those rights to every command a center runs:
root on Linux. The installed node runs the commands as `nerve-run` or its
owner instead. A node you run by hand as root is refused at start unless you
allow it:

```
nerve-node config set machine.allow_root true
```

The refusal says: `refusing to run as root; set machine.allow_root = true
to allow it`.

On Windows the node runs only as the installed service, as `nerve`, and
starts commands as the account chosen for them
([Windows](service.md#windows)): it is never run by hand, elevated or not,
and `machine.allow_root` has no use there.

When the node runs with full rights because you allowed it, it says so with a
warning at start: in the stderr output and in the node's log file. The
center's Log page shows the center's own log and does not carry it. Commands
from a center then run with full rights on the machine (on Linux unless the
node is the installed one, which runs them as `nerve-run` or its owner), and
you are responsible for
what they do.

### The node's web UI

The installed node on Linux can serve a [web UI](node-web-ui.md). On Windows
there is none: the desktop app is the node's UI there.

### The control pipe

A running node on Windows answers the app's status and relay pages (with the
relay's live tunnels) over a named pipe, and takes a new key for a center
and the folder changes of **Permissions › Folders** at once. For a folder
change it brings the folders' permission entries in line before it answers.
Only the administrators, SYSTEM and the node's own account can open the
pipe; the owner's changes in the app reach it through the service, which
runs them as its own account. The node refuses every request from a process
of a command it runs. The pipe takes no other change yet: for those the
signed `node.toml` is written, and the node takes them at its next start,
for which the app restarts it. Until then the node refuses folder changes,
which would undo them: restart it first
([troubleshooting](troubleshooting.md#restart-the-node-then-change-the-folder-again-windows)).
The commands the node runs for a center run as another account than the
node's, which cannot open the node's folders unless it is an administrator:
UAC is no security boundary ([Windows](service.md#windows)).

### Windows protected paths

See [protected paths](protected-paths.md) for the Windows list. A folder that
is spelled so that it matches nothing is refused: a `..` part, an 8.3 short
name such as `NODE-S~1`, or a name that ends in a dot or a space. Use the full
name.
