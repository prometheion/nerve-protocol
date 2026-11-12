# The sandbox on Linux

How the node keeps a center's commands to what the owner gave it on Linux:
the account `nerve-run`, its access lists, a home and temporary folder per
pairing, Landlock, the network switch, the environment of commands and the
limits per command. The user guide says what the owner does and the one-line
limits ([safety](../user/safety.md)); this page is the depth behind them.
The decision itself (modes, rules, protected paths) is in
[the policy engine](policy-engine.md).

## Reading in folder mode

On the node [installed as a service](service.md#the-node-as-a-service) on Linux, the node reads a
`folder` mode center's files as `nerve-run`. Inside the folders of that center
their flags decide, as everywhere: a read needs `r`, and a folder you closed
inside one with `r` stays closed. Outside every folder of that center, a call
whose effect is `read` may read what every account on the machine may read: a file others
may read, in folders others may enter all the way down (`/etc/hostname`, most
of `/usr`), or such a folder. A device, a pipe or a socket there is refused,
and the node does not open it to check. It reads nothing of yours that is closed to other accounts, also
where the node lets `nerve-run` pass through your home to a folder you gave,
nothing another center was given unless it is open to everyone, no protected
path and none of the node's own files (its keys, config and state), which are
closed to `nerve-run`, nor the node's own process under `/proc`. Nor does it
read anything in `/var/lib/nerve-run` (the other pairings' homes and temporary
folders) or a file of `nerve-run`'s elsewhere (what another pairing's commands
made in its folders), however open their modes are: every pairing's commands
run as that account and may change those modes, which Landlock does not rule. Writing,
commands, and a path a write or a run reads stay in the folders. A program
that reads a path for a call ([provider](capabilities.md#capability-providers-in-use)) gets the call outside
the folders only for a file open to every account, never for a folder, since
it would read below it with your rights. `nerve-run`'s own folders (the
pairing's home and temporary folder, `/tmp`, `/var/tmp`, marked `own`) are
no folders for a program: it runs with
your rights, so only the folders you gave count for it. A [capability of
your `node.toml`](capabilities.md#the-account-it-runs-as) runs as
`nerve-run` and is read like a command of that account instead: its own
folders count, and a path outside the folders is read with that account's
access. With
[Landlock](#the-account-nerve-run), a command of `nerve-run` reads less
than a file call: the system's folders and its `r` and `x` folders.

A node you run yourself, and Windows, read with your own rights, so there
`folder` mode reads only in the folders with `r`. A read that names no path
(a program's action that lists the lamps it knows) runs only where you set it
`on`: the node cannot see where such a program reads.

## A folder keeps the place you added

`folder add` follows the links on the path and stores the real place, except
a link that lies inside a folder where commands may write (a `w` folder of
any pairing): a command may have put it there, and the folder would be stored
at whatever it leads to. `folder add` then refuses, changes nothing and says
which link. Look at it (`ls -l`, `dir /AL`): add the place you mean by its own
path, or remove the link. (Once no `w` folder shows the link, it cannot be
told from yours and is followed.) The path is followed and checked in one
pass: a link found inside a `w` folder is refused whenever it appears, and the
place the pass ends at must resolve to itself, so a link swapped in meanwhile
is refused too. On Windows a `subst` drive is followed through the folder it maps, name by
name, so a junction on that folder is judged like any other; a path with a
drive but no root (`C:sub`) and a path that is not on a drive letter (a share,
`\\?\GLOBALROOT\…`) are refused, and so is a link whose target is not on a drive (a share, a
device path); a link to a volume root (`\\?\Volume{…}\`), which is how Windows
spells a volume mounted at a folder, is followed as the place the volume is
mounted at; and short (8.3) names, in the path, in a junction's target or in
the folder a `subst` drive maps, are written out in full. On Windows the CLI
does that judging, as the account it runs as, and hands the place it settled
to the running node over its [control pipe](windows.md#the-control-pipe),
which stores and records it; with no node running the CLI writes `node.toml`
itself. The node records that it
stored the real place (`places` under the pairing's `policy` in `node.toml`).
A command with `w` on a folder can put a link in place of a folder inside it,
and a link would give that folder's rights in a place you never named. So the
node looks at the path again before each command: a recorded folder whose
path leads somewhere else now is left out of the command's confinement, and
the node logs a warning (`folder <path> left out of the command's sandbox: it
was added at its own place and its path leads to <place> now …`). That holds
whoever made the link, also after you took `w` off the folder above or removed
the pairing that had it. The folder is back once its path leads to the place
you added again. To take the place the path leads to now, `folder rm` the
folder and `folder add` it again. Name it with the path you gave to
`folder add`, or the one `folder` shows (a trailing slash does not matter;
on the installed node only the one `folder` shows works for a path that
went through a link, see below). `folder rm` finds the entry
also through links of your own, and where the link that replaced it cannot be
resolved (it dangles or loops), and act on that entry, not on the folder the
link leads to now.

`folder rm` and `center rm` take the record away with the folder. A center
with the [settings grant](settings-and-config.md#the-settings-grant) cannot add or change entries of
it, and one goes only with its folder.

Not every folder is recorded. Folders a center sets and folders you write into
`node.toml` with `config set` have no entry. The node follows wherever their
path leads, and the cautions about links below hold for them. To record such a
folder, first check that its path is not a link now (`ls -ld <path>`,
`dir /AL <path>`, `find <path> -type l`): `folder add` follows a link outside
the `w` folders and stores the place it leads to, and then the old entry stays
beside the new one (`folder rm` it). Then add the folder again with its rights.
`nerve-node config get center.<name>.policy.places` lists the recorded ones.

On the [installed node](service.md#the-node-as-a-service) on Linux the CLI runs as the node's own
user (`nerve`), which may not look into your home or resolve a folder there,
so it cannot judge the links on a path there. With the node running,
`folder add` is therefore done by the node, which looks as you, the owner:
it follows the path, refuses a link inside a `w` folder as
above, and stores and records the real place (the command says so when that
is not the path you gave). A folder it stored at the place a link leads to is
listed there: give `folder rm` the path `folder` shows,
since the CLI cannot see the link. Given the link, they say `is not a
folder of this center` and add that the account cannot look into the path and
which path to use, naming the folders of the center that could be it. With no
node running, or where the node cannot tell either (a `w` folder it cannot
resolve, or a node without an owner), the folder is stored as given and not recorded, a record it had stays, and
`folder add` says so (`note: … is stored as given and not recorded …`): start
the node, and add the folder again. Check for links (`find <folder> -type l`
on Linux, `dir /AL /S <folder>` on Windows) before you take `w` off the folder
above such a folder.

## What a command can reach in `folder` mode

The node confines commands with Landlock:

| A command can | Where |
|---|---|
| Read | the system folders (`/usr`, `/bin`, `/lib`, `/etc`, `/opt`, `/proc`, `/sys`, `/dev`, `/run` but `/run/nerve-node`, and similar) and the `r` and `w` folders |
| Write | the `w` folders and the null devices (`/dev/null`, `/dev/zero`, `/dev/full`) |
| Run programs | the system folders and the `x` folders |

- `w` reads too: the node reads a folder given `w` alone as `rw`, and the
  write rule carries the read rights.
- Landlock cannot run a file it may not read. So an `x` folder also lets a
  command read files there by name. It still cannot list the folder.
- The node's own folders are in none of these sets.
- A command has no controlling terminal: it runs in a session of its own.
  On a node you run yourself in a terminal that terminal is yours, and a
  command cannot write to it, type into it, or read your terminals by
  name: `/dev/pts`, `/dev/console` and every tty device the kernel lists (`tty*`, `hvc*`, serial lines) are left out of
  what it may read (the rest of `/dev` stays, but it cannot list `/dev`).
  The installed node's commands run as `nerve-run`, which may not open your
  terminals either.
- The pairing's own home and temporary folder, `/tmp` and `/var/tmp` are in
  every set of a `nerve-run` command, to read, write and run programs in
  ([below](#the-account-nerve-run)). Another pairing's home and
  temporary folder are in none.
- A command with `w` on a folder can put a link in place of a folder inside
  it, and a link would give that folder's rights in a place you never named.
  So a folder is left out of the sets, and the node logs a warning, when its
  path passes through a link that lies inside a `w` folder (of any pairing).
  That holds for a link you made yourself too, and a link of yours that
  leads into the `w` folder is followed to its end and judged on the way.
  The folder is back once its path is a plain folder again. The rules are
  applied to the folder where it is at the moment the command starts: the
  shim opens each folder without following a link, so a link that replaces a
  folder between the node's look and the start gives that folder's rights
  nowhere, and the command is told. A link that was there when the node
  looked (the system's own, such as `/etc/localtime`, or one inside a folder
  the node cuts around its own) gets no rule and no message; what it leads to
  has the rules of the folder where it is granted. A link of your
  own above the `w` folder is followed. A folder you added with `folder add`
  is also left out when a link has replaced it since, and stays out after you
  take `w` off the folder above or remove the pairing that had it
  ([above](#a-folder-keeps-the-place-you-added)). Two gaps are left, for the
  folders that are not recorded there:
  - Only the `w` folders in the config count. If a command made a link while
    the outer folder had `w`, and you then take `w` off it (narrow it to `r`,
    or remove the pairing), the node follows the link again. Before you do,
    look for links (`find <folder> -type l`).
  - A command that runs without Landlock (`user` mode, `sudo`, and what an
    `allowlist` rule allows) can make a link wherever you can write, also
    where no `w` folder is, and the folder of another pairing there follows
    it. Look for links in the folders you grant before you give a pairing one
    of those.
- On a node you run yourself, the command runs as you, with your whole
  environment: every variable of the shell you started the node from,
  tokens and `SSH_AUTH_SOCK` included. The installed node gives
  `nerve-run`'s commands only a few ([below](#the-account-nerve-run)).
- On a node you run yourself, Landlock holds the
  command's own processes, not the other programs of your account: `folder`
  mode there is no boundary against those of them that run things on
  request (a session's service manager, a terminal multiplexer and the
  like), which run what the command asks outside the sandbox, as you. Install
  the node to run commands as `nerve-run`. With the node's keys in the system
  keyring, `folder` mode on a node you run yourself runs no command: the
  command could reach the keyring over your session bus.

### What it does not stop (Linux)

Landlock holds a command to files. Without the switch below it does not
hold the network or what a command reaches through it:

- The network: a command can connect anywhere this machine reaches, the
  services on loopback (`127.0.0.1`) and your local network included, and
  listen on a port. What it may read it can send away.
- Unix sockets by path: Landlock rules connecting to one only from ABI 9,
  and the node asks for that only for a center whose [network is
  off](#no-network-for-a-centers-commands), so a command can connect to
  every socket its account may write to by its modes, wherever it lies,
  not only in its folders. On the installed node those are the sockets open
  to every account (the system bus, a service's socket in `/run` with mode
  0777) and every
  socket of `nerve-run`, other pairings' included: a program of one pairing
  that listens on a socket in its home or temporary folder (a credential
  cache, a key agent) can be reached by every other pairing's commands, so
  keep none running there. On a node you run yourself, also the sockets of
  your session (a tmux server, an X display), which take its requests as
  yours.
- Below Landlock ABI 6, abstract unix sockets and signals to the other
  processes of its account ([versions](#landlock-versions)).

### A `/proc` of its own

Every pairing's commands run as one account, `nerve-run`, and
`/proc/<pid>/cmdline` is open to every account: one pairing's command would
read another's running command lines with `ps -eo args`, call values and
all, Landlock or not. So each command held apart from you, a `folder` mode
command and one of `nerve-run` (allowlist mode, a capability of
`node.toml`), runs in a PID namespace of its own with its own `/proc`
mounted (#199, `nerve_sandbox::own_proc`). `ps`, `top` and `/proc` show its
own processes only; a process of another pairing is not there to name.

The node has no `CAP_SYS_ADMIN`, so the shim makes an unprivileged user
namespace first and the PID and mount namespaces in it. The user namespace
maps the command's own user and group to themselves and nothing else: no
one is root inside, and the kernel checks every access as the real
account. Three processes stand for a command: the shim, which the node
waits for and which ends as the command ended (by the same signal too);
the namespace's init, which mounts `/proc` before Landlock (which forbids a
mount) and reaps what is left to it; and the command. A signal to the
command's process group reaches the command as before; the shim and the init
let it pass. When the command ends, the init ends and the kernel kills what
is left in the namespace, as the node kills what is left in its cgroup.
A sudo command and root's run without it: sudo would not rise there. So does
a node that runs as root (`allow_root`): the namespace maps one id, and the
kernel gives root its override of file permissions only over ids the
namespace maps, so root's command would lose its rights over the files of
every other account. Its commands are held apart by Landlock alone, and
`status` warns of the processes they see.

What it costs, measured on Linux 7.2 (median of 30 starts): about 0.7 ms more
per command (3.2 ms instead of 2.5 ms for `true` through the shim).
`ps`, `top`, `pgrep`, `make -j`, `git` and `cargo build` work as before. A
file of another account (yours, root's) shows its owner and group as
`nobody` (`ls -l`), since only `nerve-run` is mapped; access is not changed
by it. `ps` shows the shim as PID 1 (`nerve-node __exec-shim`), the command
as its child. A program left running in the background ends with the
command, as the cgroup ends it on a node that has one. The shim and the init are two
more tasks in the command's cgroup, so the node adds two to its `processes`
limit ([limits](#limits-per-command)): a call that asks for 2 processes runs
one command and what it starts, as without the namespace.

The node tries it once at start. Where the kernel does not let the account
make a user namespace, or mount `/proc` in one (some containers), the
commands run as before, and `status` says that each pairing's commands see
the running commands of the others (`processes_warning`; also on a node run
by hand, where the pairings' commands run as you). Commands that run as you
(`user` mode, allowlist mode with `--as-owner`) are in the node's namespace
and see every process.

Ubuntu 24.04 holds user namespaces back with AppArmor
(`kernel.apparmor_restrict_unprivileged_userns`): there `install` puts the
profile `/etc/apparmor.d/nerve-node`, which confines nothing and allows its
process to make a user namespace, and loads it; `uninstall` removes it. The
profile names no program to attach to. The unit puts the service in it
(`AppArmorProfile=-nerve-node`, after `apparmor.service`; the `-` lets the
node start where the profile is not loaded), so the node and the shim it
starts make the namespace, and a program an account runs by hand is not in
it, the node's own file included: an exemption bound to the file would be
everybody's (any account could run the shim and `setns` into its namespace
with every capability, or start the program again under a preloaded library
or as a traced child). A profile in unconfined mode is passed on through
every `exec`, and the user namespaces of a program in it keep all their
capabilities, which the system holds back from every other program. So the
shim, before it starts the command (`own_proc::leave_profile`), and the
node, before it starts a command without the shim (`user` mode, sudo), have
the next `exec` leave the profile (`exec unconfined` on
`/proc/self/attr/exec`, before Landlock, which forbids the write). The
command is treated as on a machine without the profile. The profile holds
only the service and what it starts itself (`systemctl`, the keyring
tools). A node run by hand is not in it: where the
system holds user namespaces back, its commands see each other's processes
and `status` says so.

Windows: the pairings' commands run as one account without a namespace, so
they see each other's command lines until W2 (#149) adds a container for
them; `status` does not warn there yet.

### No network for a center's commands

`nerve-node network off --center lab` keeps that center's commands
off the network, in every mode: they can open no network socket, TCP, UDP,
raw or of any other kind, to this machine or any other, only unix ones. It
holds for `exec.run` and for the [capabilities of your
`node.toml`](capabilities.md#capabilities-of-your-own-in-nodetoml) that center calls, as both are
commands of its pairing, and is stored as `no_network = true` in the
center's policy in `node.toml`. `nerve-node network on` lets them on
the network again; `folder` and `status` say when it is off. The app's
and the node web UI's **Permissions** page have it as **No network for its
commands**. The agent is told, in `list`, that its commands have no network.
A center that may change its own settings ([settings grant](settings-and-config.md#the-settings-grant))
can turn its own network off, never on again: only you can. It may change
its mode while it is off, as no mode escapes the switch, but it can give
itself no new folder to write while it is off (see below). A command that is
running when you turn the switch off is ended by the node, and the audit log
says so (`killed`, `no_network`): it started with the network, and could pass
it on to the commands that follow through a socket it listens on. That holds
when you turn it off and on again quickly, and for the commands of a link
that dropped and that the center may still resume. Commands
that start afterwards run under the switch, and one that was being set up
when you turned it off does not start without it: it is ended or refused.

What holds it is a seccomp filter of the node's own, on Linux on x86_64 and
aarch64: a command under it gets "permission denied" for every socket but a
unix one, and its io_uring calls fail too (a program then makes plain calls).
It needs no Landlock, so it holds on kernels without Landlock as well. Where
Landlock has its network rules (ABI 4, Linux 6.7), they shut TCP once more
under it. Where the node cannot set the filter (another architecture, a
kernel without seccomp filters), or on Windows, it cannot hold a command to
it, so while the switch is off it runs none of that center's commands and
says why (`the owner turned the network off for this center's commands, and
this machine cannot keep them off it: …`); `network off` warns of
that there, and the agent is offered no command.

The switch holds where the center's commands run as `nerve-run` (on the
installed Linux node: `folder` mode, and `allowlist` mode without
`--as-owner`). On a node you run yourself it holds in `folder` mode only,
under the sandbox, as a user that is not root and on Linux 7.1 or later,
where Landlock tells unix sockets by path apart (below it your session's
service manager is within reach of the command; as root the system's is).
Where they run as you with nothing around them (`user` mode, `allowlist`
mode with `--as-owner`, every other mode of a node you run yourself, and
`folder` mode there as root or on an older kernel), your own programs would
reach the network for them (your session's service manager, a key agent),
so while the switch is off the node runs none of them and says why (`… in
this mode they run as the owner, which nothing keeps off the network, so the
node runs none of them …`, or for a node run by hand `… runs them as its own
user …`). `network off`, `folder` and the app say when the center
is in such a mode now. Nor does any command on your [sudo list](policy-engine.md#sudo-as-the-owner-uses-it) run for that center
while it is off: it would run outside the filter, with full rights
(`… a command on the sudo list runs outside what keeps them off it …`).
`list` tells the agent both.

With Landlock ABI 9 (Linux 7.1) or later, a command whose network is off
reaches a unix socket by its path only in its pairing's own folders and the
folders granted to it with `w` (connecting to a socket is a write, so a
folder it may only read opens none) and at these places of the system: the system bus (where
`DBUS_SYSTEM_BUS_ADDRESS` puts it, else `/run/dbus/system_bus_socket`), the
system log (`/dev/log`), and the sockets of systemd-resolved and nscd,
which look up names and accounts. Not one in the node's own folders or
another pairing's, nor one in the folders every account may write to
(`/tmp` and `/var/tmp`, which hold your tmux server and display, `/dev/shm`,
and `/run/lock`, `/var/lock` and `/var/crash` where they are open like
that), nor one in your runtime
folder (`$XDG_RUNTIME_DIR`, `/run/user/<uid>`: your session bus and service
manager), even where you granted that folder. Abstract unix sockets are closed to
it from ABI 6 (Linux 6.12).

What it does not cover:

- Below Landlock ABI 9, unix sockets by path, wherever they lie (see
  [above](#what-it-does-not-stop-linux)), and below ABI 6 abstract ones as
  well: through a program that listens on one (a local proxy, a session's
  service manager) a command can still reach the network. Without Landlock
  that is every socket its account may write to.
- The sockets kept at every ABI: through the system bus a command can ask
  the system's services, and a name lookup through systemd-resolved or nscd
  still asks the name servers for it.
- A socket another process hands to the command.
- A socket in a folder you grant with `w` that is a session's: a program that
  listens there (a terminal multiplexer, a local proxy) can reach the network
  for the command. Keep none in a folder you grant to a center whose network
  is off. A folder granted above the shared folders or the runtime folder is
  cut around them, so a grant of `/` leaves them out too; one granted inside
  them is not. A folder you grant with `r` or `x` only opens no socket by
  path (connecting to one is a write), so a read-only grant of `/` does not
  open the sockets under it. A center with the settings grant cannot give
  itself a place to write while its network is off: no new `w` folder, no
  `w` added to one, and no `w` folder inside one of yours while the folder
  above it is narrowed or dropped (a command may have put a link there).
  The node also writes in a folder only where it really is: a folder with
  `w` whose path leads elsewhere through a link of yours (a `/home` that is
  a link to `/var/home`, say) gets no write while the network is off, whoever
  added it (a center, or you by hand in `node.toml`), and the log says so.
  Its other flags stay. Add such a place with `nerve-node folder add`, which
  stores the real place.
- Without Landlock, a command that is running for another pairing of
  `nerve-run`, which has its network: nothing keeps the pairings apart
  there. `status` warns of that when two pairings share the account.
- A program that a command detached before you turned the switch off (a
  background server it started on its own, outside the command's process
  group), or that a command left running when it ended: the node ends the
  commands it tracks, not these, and they keep the network they had. If one
  listens on a socket in a folder of the pairing, the later commands can
  reach it. On the installed node, the processes of the account `nerve-run`
  are the pairings' commands and what they left, so ending them (as root)
  clears this; on a node you run yourself they are among your own, and you
  have to find them.
- A program's action ([providers](capabilities.md#capability-providers-in-use)), which runs as you.

## The account `nerve-run`

The node installed as a service runs `folder` mode commands, and
`allowlist` mode commands unless you set `--as-owner`, as `nerve-run`.
`install` makes it, with its home `/var/lib/nerve-run`, no login and no
other groups; `uninstall` removes both, and what its commands left in
`/tmp`, `/var/tmp` and `/dev/shm`. Its home is no command's home: the node
makes in it a folder for each pairing, `/var/lib/nerve-run/<center>`, with
that pairing's own `home` and `tmp` (each 0700, made as `nerve-run` when the
pairing comes or its first command runs), and deletes it with everything in
it when the pairing goes (`center rm`, or a pairing made again under the
same name). Other files in `/var/lib/nerve-run` it leaves alone, and it takes
no folder there for a pairing's that it did not make for it: where
`/var/lib/nerve-run/<center>` is there already and holds anything, that
pairing's commands do not run, and say so, until you delete it or move it
away. A command of another pairing cannot read a pairing's home under
Landlock, but it can change its modes (Landlock does not rule `chmod`), which
would open it to the other accounts on the machine; the node closes the
pairing's folders and `/var/lib/nerve-run` again before each of its commands.
Keep nothing there that the machine's other accounts must not read.

- It is not you. Your session's programs (the service manager, the session
  bus, tmux, a container engine) take requests from your own account only,
  and your folders that others may not open stay closed to it. It cannot
  change the node's settings: the owner socket refuses it.
- It gets the folders you grant as POSIX ACL entries: the folder and
  everything below it, with the rights of its flags, and a default entry, so
  that what it makes there stays yours to use as well. What you make in such
  a folder later gets the entry by the default; what you move into it (`mv`
  of a download or a clone) keeps the ACL it had, so `nerve-run` reaches it
  only as any other account would, until the node walks that folder. The
  node watches the granted folders (inotify, a watch on each folder in
  them, each added from a descriptor opened below the granted folder, so a
  link put in the way is not followed; `crate::grant_watch`): a name made or
  moved in marks its granted folder, which the node walks once the names are quiet
  for 3 seconds, and no later than 30 seconds after the first change while
  they go on, with a pause twice as long as the walk after it, as on
  Windows. A lost event (the queue ran over) walks every granted folder. A
  file made is a name as well: it gets the folder's default entries, but a
  copy that keeps its source's mode (`mv` from another file system, `cp -a`)
  has a mask that cuts them, so it is walked like a file moved in. The walk's
  own changes are attribute changes, which the watch does not ask for, so
  they do not wake it. A granted folder with more than 65,536 folders, or
  one the system's limit of watches (`fs.inotify.max_user_watches`) leaves
  out, is not watched; the log says so once, and what is moved into it gets
  its entries at the next start or change, or by `nerve-node folder sync`,
  which is a step by hand only then. A granted folder inside one left out
  is watched for itself. One that is missing (made or mounted later, or
  moved away and made again) has no watch and is looked for every 10
  seconds; once it is there it is watched and walked. A granted folder that
  is a mount point loses its watches when the drive is unmounted: it is
  walked, not watched while it is a bare folder, and watched and walked
  again once something is mounted there. A drive mounted over a granted
  folder that is watched already gives no event, so the node compares each
  watched granted folder with what its path is (device and inode) every 10
  seconds, and walks and watches it anew when it changed. That look runs
  one at a time, never while the last one runs, and does not hold the
  thread that reads the events while it waits for a path (a share that does
  not answer). The watch keeps a descriptor open for each level of the
  folder it walks (a command can make a very deep one), so the installed
  node's unit says `LimitNOFILE=65536:524288`. A folder whose
  path is 4,096 bytes or longer, and everything below it, is not watched
  (a command can make a chain deeper than any path, and each watch keeps its
  path); the walks reach it all the same. The node also walks
  every grant when it starts and on `folder add` of a folder it has. Each such walk is a pass
  over everything in the granted folder, which takes a while for large
  trees. `status` and the
  commands of `nerve-run` do not wait for it while the folders' entries are
  up to date; a change of the folders made meanwhile waits for it. The sync of a changed config
  never walks the folders the watch found due: it comes first and alone, and those
  folders are walked after it, so a command filling a folder it may write cannot hold
  back a folder taken from it. A folder of yours
  above a grant that others may not enter gets an entry that lets it pass
  through it: with Landlock that is all it does there, without Landlock its
  commands can then read what others may read inside that folder ([your
  home](#your-home-and-other-accounts)). A file call in `folder` mode never
  reads through that entry: outside the folders it reads only what every
  account may ([reading in folder mode](#reading-in-folder-mode)). Removing the grant takes the entries
  off your files again, and a default ACL of your own on a folder below it
  (one you set with `setfacl -d`) is left as you had it, with an entry you
  gave yourself there; a folder that had none has none again. `ls -l` shows a `+` on such files, and their group bits show
  the ACL's mask. The account is one for all pairings, so its entries are the
  union of the folders of every pairing whose commands run as `nerve-run`;
  Landlock holds each command to its own pairing's folders, its own home and
  temporary folder, and `/tmp` and `/var/tmp`, which all those pairings
  share (below). A file call keeps to its own pairing's
  folders by their flags, and reads another pairing's only where they are
  open to every account. A pairing in `user` mode,
  or in `allowlist` mode as you, gives `nerve-run` none of its folders.
- What `nerve-run` made in a granted folder is its own, and keeps its entries
  when you remove the grant: you cannot change another account's files, and
  `nerve-run` may do anything with its own files whatever their entries say.
  It can no longer get to them through your folders above, which lost its
  entry, unless those folders are open to everyone ([your
  home](#your-home-and-other-accounts)). Files you put into such a folder later get its entry from the
  folder's default entries. `uninstall` takes every entry off, also those,
  and gives what `nerve-run` made in your folders to you, as its account
  goes. A file of it there with more than one name (a hard link) is left
  as it is, since another name may lie outside your folders: `uninstall`
  says how many, and they keep its old uid.
- A grant that fails (a folder below it closed to you, a file system without
  ACLs) is named by `folder add` and in `nerve-node status`,
  also after a restart, and is tried again: at the node's start, with the
  next change of the folders, and at most once a minute before a command.
- Of the service's environment its commands get only `PATH`, `LANG` and
  `TERM`, and `HOME`, `TMPDIR`, `USER`, `LOGNAME` and the `XDG_*` and git
  variables the node sets for the pairing's own home and temporary folder:
  not `NERVE_NODE_OWNER`, nor what
  systemd adds, nor what you put into the unit with `Environment=` (a proxy
  URL with its password, a token). To pass one on, name it:
  `nerve-node config add machine.command_env HTTPS_PROXY`; its value is the
  service's. Do not put secrets into the unit that commands should not see.
- It always has its pairing's own home and temporary folder, `/tmp` and
  `/var/tmp`, to read, write and run programs in. Its tools keep their
  caches and configs in that home: `HOME` and the `XDG_*` folders point
  there, `TMPDIR` to the temporary folder. With Landlock no other pairing's
  command reaches their files (not a program's socket there: keep no
  credential cache or key agent running in them). `/tmp` and `/var/tmp` stay shared, for programs
  that use them whatever `TMPDIR` says: what one pairing leaves there
  another one's programs may read by themselves. Full isolation needs
  Landlock, ABI 6 or later ([versions](#landlock-versions)); without it the
  pairings' commands are one account, and each reaches every other
  pairing's home. Give a center you trust less a machine of its own where
  the kernel has no Landlock.
- What `/var/lib/nerve-run` held before the node gave each pairing its own
  home (the shared `.cache`, `.config`, `.gitconfig`, `.ssh` and the like of
  an earlier version) is no command's any more. The node leaves it; delete
  it, such as `sudo rm -rf /var/lib/nerve-run/.cache`. An entry there named
  after one of your centers (`nerve-node center`) must go as well, or that
  pairing's commands do not run: the node made none of them.
- git trusts the repositories it reaches (`safe.directory`), so it works in
  your repositories although they are not its own.
- It has no SSH keys or other credentials of yours, so `git push` and the
  like fail unless you set that up for it. That is intended. ssh does not
  go by `HOME`: it looks for its keys, its config and `known_hosts` in
  `/var/lib/nerve-run/.ssh`, which with Landlock no command may read. To give
  one pairing a key, put it into that pairing's home and name it to git there.
  As root, for the center `lab`:
  `install -d -o nerve-run -g nerve-run -m 700 /var/lib/nerve-run/lab/home/.ssh`,
  copy the key in (owner `nerve-run`, mode 0600), and run, as a command of
  that pairing, `git config --global core.sshCommand 'ssh -i "$HOME/.ssh/id_ed25519" -o UserKnownHostsFile="$HOME/.ssh/known_hosts"'`.
  The key goes with the pairing's home when the pairing goes.
- Tools you installed in your home (`~/.cargo`, `~/.rustup`, nvm, pyenv)
  are not on its way. Install them system-wide, grant their folder with `r`
  and `x`, or let a command of the pairing install them: they land in its
  own home (`HOME`) and go with it. `/var/lib/nerve-run` itself is no
  command's: with Landlock none may read it.
- The node changes only your own files: a file of another account below a
  grant, a link, and what lies on another file system below the grant get no
  entry. A file with a second name (a hard link) gets none either, and loses
  one it had. A file system without ACLs refuses them, and `nerve-node
  status` names the folder.
- A link that is put on the way to a granted folder after you gave it, or in
  place of a folder below it, is not followed: that grant fails until its
  path is a plain folder again. Where you remove such a grant inside another
  one you still give, the node takes its entries off by going through the
  outer folder, wherever the inner one lies in it now. If the outer folder
  holds another file system, or a folder you may not open, the node cannot
  tell that it reached the inner one: its entries count as not taken off
  (below) until its path is a plain folder again.
- While the node cannot take an entry off that `nerve-run` should have lost,
  no command of `nerve-run` runs, for any pairing: `folder rm`, `nerve-node
  status` and the app (**nerve-run keeps access it should have lost**) name
  the folder and why. Fix what stops it (a folder closed to you, a file
  system without ACLs); the node tries again before the next command.
- A file or folder a command makes private (mode 0600 or 0700) stays its
  own: the ACL mask hides your entry then, and you cannot read it without
  `sudo` (`sudo cat`, or `sudo chown` it to you). That is known and
  accepted: most tools make their files 0644 and 0755, and `nerve-run`
  keeps what it makes private to itself as any account does. If you narrow a file's group bits later
  (`chmod g-w`), `nerve-run` loses that right too.
- An allowed [sudo](policy-engine.md#sudo-as-the-owner-uses-it) command of a pairing whose commands run as
  `nerve-run` runs as root, started by the node: the sudo list is its only
  way to root, and your password is not used for it.

Check that your kernel supports it, with the node running:

```sh
nerve-node status
```

The first line reads `node: running (confinement landlock v…)`. With
`confinement none` the kernel has no Landlock. The installed node then runs
`folder` mode and `allowlist` mode commands as `nerve-run` without it: its
account alone holds it back, so it reaches the folders you give it and
whatever other accounts may reach ([your
home](#your-home-and-other-accounts)), and each pairing's line in `status`
says `as nerve-run, without Landlock` (the app says **Without Landlock**). What sets one pairing's folders apart from
another's is then gone, as the account is one for all of them, the
pairings' own homes and temporary folders included (they are 0700, which
keeps out other accounts, not another pairing), and so is the narrower set
Landlock gives (`x` without listing). Once a second
pairing's commands run as `nerve-run` there, `status`, `center add`, the
pairing in `setup`, the app's **Centers** page and the node web UI warn of
it (`warning: Without Landlock nothing keeps the pairings apart: …`). A
node you run yourself refuses every `folder` mode command without Landlock,
and a line `folder mode runs no command: …` says why.

### Landlock versions

Each kernel version adds guards to Landlock (its ABI). The node asks for ABI
6 and uses what the kernel has:

| ABI | Linux | What it adds |
|---|---|---|
| 1, 2 | 5.13, 5.19 | Files and folders. These do not guard truncating a file (`truncate`), so a command can cut any file it may write outside its folders to nothing. A node you run yourself takes them as no Landlock and runs no `folder` mode command; the installed node uses them |
| 3 | 6.2 | Truncating files: from here on a node you run yourself uses Landlock |
| 4 | 6.7 | Network rules: TCP connections and listening ports, which the node shuts for a center whose network you turned off, under its own filter ([no network](#no-network-for-a-centers-commands)) |
| 5 | 6.10 | Device ioctls |
| 6 | 6.12 | Signals to other processes and abstract unix sockets: the commands of the installed node's pairings, all of `nerve-run`, are kept apart from each other only from here on |
| 9 | 7.1 | Unix sockets by path, which the node shuts for a center whose network you turned off, but those in its folders and the system's ([no network](#no-network-for-a-centers-commands)) |

Below ABI 6 a command can still signal other processes of its account, reach
abstract unix sockets and (below 5) send ioctls to the devices it may open.
On the installed node that means one pairing's commands can stop another's.
`install` and `status` say so (`warning: this kernel's Landlock is ABI 4,
which does not guard device ioctls, signals to other processes of the
account, abstract unix sockets: …`). On ABI 1 or 2 they name truncating
files too: the installed node still holds each command to its folders, but
a command can cut a file `nerve-run` may write outside them to nothing. A
node you run yourself runs no `folder` mode command there and `status`
says `confinement none`. These are the stock kernels of Ubuntu 22.04 (5.15,
ABI 1) and Debian 12 (6.1, ABI 2); Ubuntu 24.04 (6.8) has ABI 4.

### Your home and other accounts

With Landlock, each command of `nerve-run` is held to its own pairing's
folders (apart from the other pairings' commands from ABI 6, see [Landlock
versions](#landlock-versions)), and nothing below is a concern for commands. File calls in `folder`
mode read, outside the folders, what every account on the machine may read,
with or without Landlock: where your home is open to others (755 or 711), that
includes the files in it that others may read, as it does for any account on
the machine. `chmod 750 ~` closes them to file calls too.

Without Landlock, `nerve-run` is an account like any other on the machine:
in your home it may read every file that you let other accounts read (most
are 644), not only the folders you give it. It gets into your home in two
ways:

- Your home is open to others (mode 755 or 711, `ls -ld ~`). `chmod 750 ~`
  (or `700`) closes it.
- You give it a folder in your home, such as `~/project`. Then it needs to
  pass through your home to get there, and the node gives it a pass-through
  entry on your home and on the folders on the way. With that it reaches
  every folder and file below your home that others may read, by name,
  whatever the mode of your home. Closing your home does not change that.

`install` (once, before any folder is given), `nerve-node status` (`warning:
Without Landlock, nerve-run can read every file in your home …`) and the app
(**nerve-run can read more of your home**) say so, and say which of the two
it is; where you give it your home itself, it says that. To keep it to its
folders: give it folders outside your home (such as `/srv/work`), make your
files readable by you and your group only (`umask 027` for new ones, `chmod
-R o-rwx` for those there), or use a kernel with Landlock. The warning stays
as long as you give it a folder in your home: the modes narrow what it can
read there, but the node cannot tell which of your files are open to others,
so only folders outside your home or Landlock end it.

## The accounts commands run as

`nerve` only holds the node's config, keys and state; no command runs as it.
A center's commands run as one of two accounts:

| Mode | Account |
|---|---|
| `folder` | `nerve-run` |
| `allowlist` | `nerve-run`, or the owner with `mode allowlist --as-owner` |
| `user` | the owner (root, where [root is the owner](service.md#root-as-the-owner)) |
| an allowed [sudo](policy-engine.md#sudo-as-the-owner-uses-it) command | root: through the owner's sudo where the pairing runs as the owner, started by the node itself where it runs as `nerve-run` |

There is no other account to choose. A command gets the account's groups,
its home as `HOME` and, when the call names no folder, as its working
folder (a sudo command starts in the owner's home). A command of `nerve-run`
gets of the service's environment only `PATH`, `LANG`, `TERM` and
the names you list in `machine.command_env` (its `HOME` and `TMPDIR` are its
pairing's own, below `/var/lib/nerve-run`), nothing the unit sets
(`NERVE_NODE_OWNER`, an `Environment=` line of yours) and nothing of
systemd's; a command as the owner gets the service's environment ([the
environment](#the-account-nerve-run)). Do not put a secret into
the unit's `Environment=` that the owner's commands should not see. The node reads and writes files for a center (`fs`) as that account
as well: it sees what the account sees, and the files it makes belong to the
account. `~` in [folders](policy-engine.md#modes-and-folders-as-the-owner-sets-them), [rules](policy-engine.md#rules-as-the-owner-writes-them) and the
[protected paths](policy-engine.md#protected-paths-as-the-owner-sees-them) is the owner's home.

The node's keys are private to `nerve`, and no command of `nerve-run` or
the owner can read them, except where [root is the owner](service.md#root-as-the-owner):
root's commands read them. Before a command starts, the node checks that its
account cannot open the node's folders, and refuses to run it if it can;
root as the owner is let through.
`nerve-run` is in no group and has no sudo of its own: only a command on the
[sudo list](policy-engine.md#sudo-as-the-owner-uses-it), with sudo on, runs as root, started by the node, and
as root it can read what root can, the node's keys included. Put on the
list only what you would run as root yourself. The owner can become root
too, through `sudo` or a group such as `docker`: a `user` mode command runs
as the owner and can do what the owner can, which is the owner's choice of
mode ([modes](policy-engine.md#user-mode)).

### The one privilege the service keeps

To start a command as `nerve-run` or the owner, the service keeps two
capabilities, `CAP_SETUID` and `CAP_SETGID` (`AmbientCapabilities=` in the
unit). This is the one privilege it has beyond what `nerve` may do. The node
uses it to switch to the account, and to give `nerve-run` its folders as the
owner, who owns them. Every command it starts drops both capabilities before
it runs, in every mode, so no command keeps them; a command of root as the
[owner](service.md#root-as-the-owner) keeps all of root's rights instead.

## Paths a command builds at run time

The node checks the paths a command line names plainly (an absolute path, or
one that starts with `~/` or `$HOME/`) against the
[protected paths](policy-engine.md#protected-paths-as-the-owner-sees-them) and its own folders. It does not see a
path the command puts together while it runs: `cd ~/.config; cat
nerve/node.toml`, where a shell joins the pieces, or a script or program that
builds the name from parts, from its environment or from a file. A command
that Landlock (Linux) or the AppContainer (Windows) confines in `folder` mode
is kept off the node's folders and the protected paths all the same, whatever
path it builds. Three kinds of command are not confined, and for them it is a
limit:

- A `user` mode command runs as your user without a sandbox, so it reaches
  whatever you reach, protected paths and the node's own folders included. It
  is why `user` mode is for a center you would trust with a shell.
- A program that an `allowlist` rule lets run is sandboxed only as
  `nerve-run`, on the installed Linux node with Landlock; as you
  (`--as-owner`, a node you run yourself, Windows) it is not
  ([rules](policy-engine.md#what-a-wildcard-covers) keeps shell syntax out of a
  wildcard rule, not what a program does).
- A [sudo](policy-engine.md#sudo-as-the-owner-uses-it) command runs as root without the sandbox, in `folder` mode
  too: a script or interpreter on the sudo list can build a path to the node's
  files at run time. Put no program on the sudo list that you would not trust
  with them. On the installed Windows node `folder` mode runs only such
  commands ([Windows](windows.md#what-a-command-can-reach-in-folder-mode-windows)).

And in `folder` mode while commands run as you (on a node you run yourself,
or on Windows), a command can hand work to the programs of yours that run
commands on request, which are outside the sandbox
([Linux](#what-a-command-can-reach-in-folder-mode)). As `nerve-run` it
cannot: they do not take requests from another account.

No rule closes these limits.

## Limits per command

Each command a center runs gets a limit on its memory, its CPU and its
number of processes. You set what a command gets and the most a call may ask
for. A call may ask for less, or for more up to that most, never beyond it.
How long a command may run has its own default and most, in
[how long a command may run](settings-and-config.md#how-long-a-command-may-run).

Linux only for now. On Windows the settings are there, but commands are not
held to them yet.

### The limit settings

```toml
[limits.command]
memory_mb = 4096         # memory of one command, in MiB
memory_max_mb = 16384    # the most a call may ask for
cpu_percent = 200        # CPU time in percent of one CPU: 200 is two CPUs
cpu_max_percent = 800
processes = 1024         # processes and threads at once
processes_max = 8192
```

These are the defaults. Change them by name:

```sh
nerve-node config set limits.command.memory_mb 2048
nerve-node config set limits.command.memory_max_mb 8192
nerve-node config unset limits.command.memory_mb      # back to the default
```

Each value is at least 1, and a default may not be above its most. Only you
set them: a center with the [settings grant](settings-and-config.md#the-settings-grant) cannot.

### What a call asks for

`exec.run` takes `memory_mb`, `cpu_percent` and `processes`, each optional:

```json
{"command": "make -j8", "memory_mb": 8192, "cpu_percent": 800}
```

A value the call leaves out is your default. A value above your most is
refused with `invalid_args`, and the error says the most. The node
describes the defaults and the most to the center, so the agent can see them
in the params `list` gives for `exec.run`. `processes` counts the command and
what it starts: a command with a [`/proc` of its own](#a-proc-of-its-own)
has the shim and the namespace's init in its cgroup besides, and the node
adds those two to what the cgroup allows.

### Calls of one agent session

Beside the limits of each command, the center bounds what one agent session
keeps busy: at most 16 calls run at once, also the ones that became jobs
([long calls](mcp-surface.md#long-calls-become-jobs-1)), and a 17th is refused with
`busy` until one ends or is stopped. Every `busy` answer to a session names
its running jobs, whatever was full, so an agent that lost their ids can stop
one. A job's `exec.signal` still goes through then. Results of finished jobs
are kept in the center's memory, at most 4 MiB per session (counted as their
JSON text, which is how they are kept) and for 10 minutes; a result past that
is not kept (a job that failed still says that it failed, and why in one
word). A command's output stream keeps at most 1 MiB that was not read, the
oldest part dropping first, and a session holds at most 16 streams, at most
8 of them open or being opened on one machine at once
([output while it runs](mcp-surface.md#a-commands-output-while-it-runs)); a
[program's stream](capabilities.md#state-events-and-streams) past those 8 is
refused with `busy` until one of them ends or is closed (an open that went
to the machine counts until the machine answered it, also when it was
cancelled or its stream closed). These
are fixed in the center.

A job that runs a command holds one of the machine's command places until the
command ends: `limits.max_running`, 16 by default, for all centers together.
One session's 16 jobs can take all of them, and then every command on that
machine is refused with `busy`, also those of other sessions and other
centers, until a command ends, times out or is stopped. Stop jobs nobody
waits for with `job.cancel`; ending the session in the web UI stops all of
its jobs.

The node's own limit of 64 calls at once per center holds for all sessions
together. The center keeps 8 of those for itself: the agents' calls take at
most 56, and one past that is refused with `busy` before it reaches the node.
A machine that announces fewer places (another implementation of the node)
keeps a quarter of them, so one with 8 leaves the agents 6.
So saving the machine's settings from the center, and a job's `exec.signal`,
still work while agents' jobs hold every other place.

### Past a limit

| Limit | What happens |
|---|---|
| Memory | The command is killed, with everything it started. Its result has `"killed": "memory"` and a `reason`, such as `the command went past its memory limit of 4096 MiB and was killed`, and `"signal": "kill"`. |
| CPU | The command is slowed down. It is not killed. |
| Processes | The command cannot start more. A shell says `Cannot fork` or `Resource temporarily unavailable`. |

Only a command that reached its own limit gets `killed`. When the machine
runs out of memory as a whole, the kernel may kill a command below its
limit: its result then has only `"signal": "kill"`, and raising `memory_mb`
does not help.

Swap does not count as room: a command past its memory is killed, not
swapped out. Files the command reads into the page cache count towards its
memory, but the kernel frees those first.

A command killed for its memory is in the [audit log](logging.md#the-audit-log-as-the-owner-reads-it) as its own
entry, `killed`, after the `allowed` one, with the reason. The
[log](logging.md#the-log-as-the-owner-reads-it) has it as a warning.

### Where the limits hold

The node puts each command in a cgroup of its own. It needs a cgroup v2 that
systemd hands to it:

- **The installed service** has one. Its unit says `Delegate=cpu memory pids`
  ([service](service.md#the-node-as-a-service)).
- **A node you start yourself** has one when you start it in a scope of its
  own:

  ```sh
  systemd-run --user --scope -p Delegate=yes nerve-node run
  ```

  Started plainly in a terminal, it shares the terminal's cgroup, which is
  not its own to divide. Run as a service of your own systemd
  (`systemctl --user`), its unit needs `Delegate=yes`. Without it systemd
  keeps the cgroup as its own and turns the limits off again at its next
  reload, so the node takes no cgroup there. A unit with
  `ProtectControlGroups=private` sees only its own cgroup, whose path names
  no unit: the node asks your systemd which unit it runs in
  (`systemctl --user whoami`, systemd 256 and later), and takes the cgroup
  when that unit has `Delegate=yes`. On an older systemd such a unit gets
  no limits; leave `ProtectControlGroups=private` out there.

Without such a cgroup (no systemd, cgroup v1, a node started in a terminal),
commands run without these limits. `nerve-node status` says so, and why:

```
limits per command: memory 4096 MiB, CPU 200 %, 1024 processes; a call may ask for up to 16384 MiB, 800 %, 8192 processes
limits held by the cgroup /system.slice/nerve-node.service: memory, cpu, processes
```

or

```
commands run WITHOUT these limits: the node's cgroup /user.slice/… is not delegated to it: …
```

When a cgroup offers only some controllers, the line names the limits that
are not held. When something else turns a controller off while the node
runs, no command runs until you start the node again, and `status` says so:

```
NO COMMAND RUNS: memory turned off in the cgroup since the node started; start the node again
```

When a command ends, everything still in its cgroup is killed: also a
process it moved out of its process group (`setsid`, `nohup … &`), which
would otherwise outlive it.

### What the limits do not cover

- A command that runs as the node's own user (a node you start yourself, in
  `allowlist` or `user` mode) can move itself out of its cgroup or raise its
  limits, as the cgroup's files are that user's. In `folder` mode Landlock
  keeps a command from writing the cgroup files.
- A command that runs as root can too: when root is the account commands
  run as, and every command on the [sudo list](policy-engine.md#sudo-as-the-owner-uses-it).
- Commands of the installed service run as another account ([the account
  commands run as](#the-accounts-commands-run-as)) and cannot write
  their cgroup. But any command, in every mode, can have work started
  outside its cgroup by a service manager of its account: `systemd-run
  --user`, `at`, cron. That work is not held to the limits and outlives the
  command. The limits bound what a command uses by itself, not what it can
  ask others to run; they are no boundary against a center you do not
  trust.
- Disk space and disk speed are not limited.
- The limits are per command. `limits.max_running` (16 by default) bounds how
  many commands run at once, so many commands together can use more.

## Stop access

From the quickest to the most thorough.

| You want | Do | Effect |
|---|---|---|
| Stop one agent session | Web UI, Overview, Sessions, **End** | The session's running commands stop, its jobs too |
| Hide a machine from the agent | Web UI, Overview, **Disable** on the machine | The machine stays paired and connected. The agent's `list` shows it as disabled with no capabilities, and calls to it are refused. The agent's calls that run there stop, its jobs too, and so do the streams and event subscriptions of a program there. **Enable** undoes it |
| Stop one center on a machine | `nerve-node center pause lab` | The node drops the link and does not dial it again |
| Stop every center on a machine | `nerve-node panic` | Every link ends. Nothing runs until `unlock` |
| End a pairing | `nerve-node center rm lab`, or **Remove** in the web UI | The pairing and its key are gone |

### Panic

```sh
nerve-node panic       # end every link; nothing runs
nerve-node status      # shows LOCKED (panic)
nerve-node unlock      # work again
```

`panic` locks the node in `node.toml`. The lock stays after a restart until you
run `unlock`. Only you can unlock. A center can never unlock.

If `panic` says the node does not take connections now, or that the config
keeps changing, the lock was not set. Try again; if it keeps failing, stop the
node itself (`systemctl stop nerve-node`, or Ctrl-C for a node you started).

### Pause

```sh
nerve-node center pause lab
nerve-node center resume lab
```

A center with the [settings grant](settings-and-config.md#the-settings-grant) can pause its own link.
Only you can resume it.

### What ends a command

A command stops when its call ends: on its timeout, when the caller cancels,
when its session ends, or when its link ends. A command that ran past the
center's call wait is a job ([long calls](mcp-surface.md#long-calls-become-jobs-1)):
the harness's cancel of its tool call no longer reaches it, and the agent
stops it with `job.cancel`, or sends it a signal with `exec.signal` where you
allowed that (`nerve-node cap set exec.signal on`; in `allowlist` mode an
allow rule `exec.signal`). Turning the machine's capabilities off, or an
`until` that passes, does not stop a running command, and the agent can still
stop it with `job.cancel`; **Disable** in the center stops it. A link that
drops without a goodbye is kept 30 seconds and its commands run on; they end
when the link is not back by then, or at once when the link ends with a goodbye (`panic`,
`center pause`, a stopped node). Taking the machine off the network for less
than 30 seconds does not stop a command; use `nerve-node panic`. On Linux the
node kills the command's whole process group, and everything in the command's
cgroup where it has one ([limits](#limits-per-command)). On Windows it ends the
command's Job Object. A command that goes past its memory limit is killed too.
Every command also has a timeout: its `timeout_ms`, or the node's default, and
never more than the node's maximum
([how long a command may run](settings-and-config.md#how-long-a-command-may-run)).

On Windows a timeout first asks the command to end: its console programs get
Ctrl+C and its windows a close request. What has not ended 3 seconds later is
ended with the Job Object.
A cancel, the end of a session and the end of its link end it at once.

## How Linux differs

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
  [modes](#your-home-and-other-accounts). With Landlock nothing is
  said: it holds each command to its folders.
- Landlock below ABI 6 (Linux 6.12; the stock kernels of Ubuntu 22.04 and
  24.04 and Debian 12 are older) lets a command signal other processes of its account and
  reach abstract unix sockets: the installed node's pairings, whose commands
  are all `nerve-run`'s, are kept apart from each other only from ABI 6.
  Below ABI 3 (Ubuntu 22.04's 5.15, Debian 12's 6.1) a command can also cut
  a file it may write outside its folders to nothing; the installed node
  still uses that Landlock, a node you run yourself runs no `folder` mode
  command there. `install` and `status` name what the kernel's Landlock
  lacks. See [Landlock versions](#landlock-versions).
- A `folder` mode command, and every command of `nerve-run`, has no
  controlling terminal; a node you run yourself gives its `allowlist` and
  `user` mode commands the terminal it was started in. Of the installed node's
  environment a command of `nerve-run` gets only `PATH`, `LANG`, `TERM`
  and the names in `machine.command_env`; its `HOME` and `TMPDIR` are its
  pairing's own. A node you run yourself
  gives its commands your whole environment.
- Commands run with `no_new_privs`, so setuid programs cannot gain privileges.
  Only a command on the [sudo list](policy-engine.md#sudo-as-the-owner-uses-it) runs without it.
- When a call ends, the node kills the command's whole process group.
- Each command runs in a cgroup of its own, held to its memory, CPU and
  processes ([limits](#limits-per-command)), where systemd hands the node a cgroup: the
  installed service, or a node started with `systemd-run --user --scope -p
  Delegate=yes`. On Windows each command's job object holds it to them
  ([Windows](windows.md#limits-per-command)).
- On the node [installed as a service](service.md#the-node-as-a-service), `folder` and `allowlist`
  mode commands run as `nerve-run`, an account of its own with no other
  groups and no way to root but the [sudo list](policy-engine.md#sudo-as-the-owner-uses-it)
  ([modes](#the-account-nerve-run)). It reaches your files only
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
- A [sudo](policy-engine.md#sudo-as-the-owner-uses-it) command runs as root, whatever account the other
  commands run as. It reads the node's files and can change it. The sudo
  list is yours to choose.
- A node that runs as root is refused unless `machine.allow_root` is set
  ([root and administrator](windows.md#root-and-administrator)).
- A [capability of `node.toml`](capabilities.md#capabilities-of-your-own-in-nodetoml) runs as `nerve-run`,
  held to the pairing's folders and its own, by Landlock where the kernel has
  it; a node you run yourself has no `nerve-run` and offers none.
