# Modes and folders

Every pairing has a mode. It sets how much that center may do on the machine.

| Mode | What is allowed | Commands on the installed Linux node |
|---|---|---|
| `allowlist` | Only what an [allow rule](rules.md) names | As `nerve-run`, held to the folders you grant; or as you, if you say so (as root where [root is the owner](service.md#root-as-the-owner)) |
| `folder` (default for a new pairing) | Writing and commands inside the folders you grant, by their rights; reading there too, and on the installed Linux node also what every account on the machine may read ([below](#what-each-mode-allows)) | As `nerve-run`, held to those folders |
| `user` | Everything you could do yourself | As you, not confined (as root where [root is the owner](service.md#root-as-the-owner)) |

From most to least locked down: `allowlist`, `folder`, `user`. On the node
[installed as a service](service.md) on Linux, `folder` and `allowlist` mode
run commands as `nerve-run`, an account of its own
([below](#the-account-nerve-run-linux)). A node you run yourself, and
Windows, run every command as the account that runs the node.

[Deny rules](rules.md#deny-a-command) and [protected paths](protected-paths.md)
apply in every mode. A call that nothing allows is refused at once. Nothing
waits for an answer.

## What each mode allows

A mode allows the same for every capability, the node's own (`fs`, `exec`),
those a [program adds](providers.md) and [your own in
`node.toml`](config-capabilities.md), by what the capability does (its
effect, which `list` shows the agent):

| Effect | `allowlist` | `folder` | `user` |
|---|---|---|---|
| `read` | an allow rule | allowed; each path it reads needs an `r` folder, or on the installed Linux node, outside every folder, one open to every account ([below](#reading-in-folder-mode)); with no path, only where you set it `on` | allowed |
| `write` | an allow rule | each path it writes in a `w` folder (and each it reads in an `r` one); with no path, only where you set it `on` | allowed |
| `execute` | an allow rule | `exec.run`: its working directory in an `x` folder. Another capability: each of its paths in a folder with `x` and the flag for what it does there; with no path, only where you set it `on` | allowed |
| `sense`, `actuate` | an allow rule | only where you set it `on`, and each of its paths in the folders as above | only where you set it `on` |

`on` (`nerve-node cap set lamp on`) never lets a call out of the folders: it
allows only what names no path, and sensing and acting on the world, whose
paths stay in the folders too. A write whose only paths are ones it reads
names no place it writes, so it counts as a write with no path. Deny rules,
`off`, `hidden`, [protected paths](protected-paths.md) and the node's own
files win in every mode, for the paths a capability names.

A capability names its paths by marking them in its schema
(`x-nerve-path`): `fs` marks its `path`, `exec.run` its `cwd`, and a program's
capability the arguments it reads or writes. Those paths count as an `fs`
call's do: the folders, the [rules](rules.md#rule-syntax), protected paths and
the node's own files judge them, and the [audit log](audit.md) names them. A
folder handed to a program counts with everything below it, since the program
may read or write there: it is refused when a protected path, the node's own
files, a place a deny rule of that capability names or, in `folder` mode, a
folder you gave less lies below it, and when a link below it leads where the
call may not go. The node sees only the paths a program
marks: an argument it does not mark is not a path to the node, so a program's
action that marks none (it may still read files where it likes, with your
rights) needs `on` in `folder` mode, whatever it does. A program that reads or
writes files should mark its path arguments; switch an action `off` that takes
a path without the marker.

### Reading in folder mode

On the node [installed as a service](service.md) on Linux, the node reads a
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
closed to `nerve-run`, nor the node's own process under `/proc`. Writing,
commands, and a path a write or a run reads stay in the folders. A program
that reads a path for a call ([provider](providers.md)) gets the call outside
the folders only for a file open to every account, never for a folder, since
it would read below it with your rights. `nerve-run`'s own folders (its home,
`/tmp`, `/var/tmp`, marked `own`) are no folders for a program: it runs with
your rights, so only the folders you gave count for it. A [capability of
your `node.toml`](config-capabilities.md#the-account-it-runs-as) that runs
as `nerve-run` is read like a command of that account instead: its own
folders count, and a path outside the folders is read with that account's
access; one that runs as you is read like a program's. With
[Landlock](#the-account-nerve-run-linux), a command of `nerve-run` reads less
than a file call: the system's folders and its `r` and `x` folders.

A node you run yourself, and Windows, read with your own rights, so there
`folder` mode reads only in the folders with `r`. A read that names no path
(a program's action that lists the lamps it knows) runs only where you set it
`on`: the node cannot see where such a program reads.

## Set the mode

```sh
nerve-node mode set allowlist
nerve-node mode set folder
nerve-node mode set user
```

`folder` and `user` stay until you change them. To set a time limit, add
`--for` with hours. When it ends, the pairing goes back to `allowlist`, not to
`folder`.

```sh
nerve-node mode set user --for 2
```

`--for` needs at least 1 and does not go with `allowlist`. Setting a mode
again without `--for` removes an earlier limit.

`allowlist` mode runs the allowed commands as `nerve-run`. To run them as
you instead, outside the folders' sandbox:

```sh
nerve-node mode set allowlist --as-owner
```

Setting the mode again without `--as-owner` goes back to `nerve-run`.

## Folders

A folder gives rights. Each right is its own flag:

| Flag | Allows |
|---|---|
| `r` | Read: `fs` stat, list, read, grep, find, and the paths another capability reads |
| `w` | Write files: `fs.write`, and the paths another capability writes |
| `x` | Run commands whose working directory is in the folder, and capabilities that run something at their paths |

The flags do not imply each other. A write needs `w` and not `r`. A read needs
`r` and not `w`. A command needs `x` and not `r`. A folder covers everything
below it. Where folders nest, the deepest one decides.

Folders count in `folder` mode. In `allowlist` mode as `nerve-run` they are
the sandbox the allowed commands run in; the allow rules decide what runs.

The agent is told each center's own mode and account, and in `folder` mode
whether it may read outside the folders what every account may read, and its folders with their
flags (the built-in ones of `nerve-run` among them,
marked as its own; a folder left without rights is not named, and the
granted folder around it is marked as having folders below it that allow
less; where the machine runs no `folder` mode command, no folder is shown
with `x`, and where your sudo list for that center names commands while
the node's [sudo switch](sudo.md) is on and `exec.run` is neither hidden
nor off for that center, the agent is told that those run
by that list alone, in any folder and outside the sandbox): `list` shows
them
([harness](harness.md#the-tools-the-model-gets)). Every center is told this
of its own pairing, with the [settings grant](settings-grant.md) or without.
A change of the folders, the mode or the account reaches the center at once.
Another center's folders are never shown. In `allowlist` mode the folders
are not shown, though they still hold the commands that run as `nerve-run`.

The folders of `nerve-run` marked as its own (its home, `/tmp`,
`/var/tmp`) are shared by every pairing whose commands run as `nerve-run`,
and so are the settings and caches its programs keep in its home. What one
such pairing writes there can change what the next command of another one
does, inside that other pairing's folders. The agent is told to keep only
throwaway files there and to change no program's settings there unless
asked, but its programs read those settings by themselves. So do not give
a center you trust less `folder` mode, or `allowlist` mode as `nerve-run`,
beside a pairing whose folders are worth more: no mode on one machine keeps
the two apart while they share that home. Give such a center a machine of
its own. The closest second best is `allowlist` mode as `nerve-run` with
exact rules, for programs that keep no settings in its home. Not
`--as-owner`: that runs the allowed commands as you (as root where root is
the owner), outside the sandbox, so they reach all your folders and
credentials ([the account `nerve-run`](#the-account-nerve-run-linux)).

| Command | Does |
|---|---|
| `nerve-node folder add ~/proj +r +w +x` | Add a folder. Name at least one right |
| `nerve-node folder set ~/proj -w` | Change rights, like `chmod`: `+x` adds, `-w` removes, `'=rx'` sets exactly. Applied left to right |
| `nerve-node folder rm ~/proj` | Remove the folder |
| `nerve-node folder ls` | List folders and rights |

Quote `'=rx'` so zsh leaves it alone. `folder add` on a path that is listed
already replaces its rights. `folder set` leaves a folder with no rights in
the list. `folder rm` removes it. Inside a granted folder, a folder with no
rights closes what lies below it to file calls and to commands that start
there, but a command started in the folder around it still reaches it: the
sandbox is built from the folders that grant something.

### A folder keeps the place you added

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
to the running node over its [control pipe](platforms.md#the-control-pipe),
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
`folder add`, or the one `folder ls` shows (a trailing slash does not matter;
on the installed node only the one `folder ls` shows works for a path that
went through a link, see below). `folder rm` and `folder set` find the entry
also through links of your own, and where the link that replaced it cannot be
resolved (it dangles or loops), and act on that entry, not on the folder the
link leads to now.

`folder rm` and `center rm` take the record away with the folder. A center
with the [settings grant](settings-grant.md) cannot add or change entries of
it, and one goes only with its folder.

Not every folder is recorded. Folders a center sets and folders you write into
`node.toml` with `config set` have no entry. The node follows wherever their
path leads, and the cautions about links below hold for them. To record such a
folder, first check that its path is not a link now (`ls -ld <path>`,
`dir /AL <path>`, `find <path> -type l`): `folder add` follows a link outside
the `w` folders and stores the place it leads to, and then the old entry stays
beside the new one (`folder rm` it). Then add the folder again with its rights.
`nerve-node config get center.<name>.policy.places` lists the recorded ones.

On the [installed node](service.md) on Linux the CLI runs as the node's own
user (`nerve`), which may not look into your home or resolve a folder there,
so it cannot judge the links on a path there. With the node running,
`folder add` is therefore done by the node, which looks as you, the owner:
it follows the path, refuses a link inside a `w` folder as
above, and stores and records the real place (the command says so when that
is not the path you gave). A folder it stored at the place a link leads to is
listed there: give `folder rm` and `folder set` the path `folder ls` shows,
since the CLI cannot see the link. Given the link, they say `is not a
folder of this center` and add that the account cannot look into the path and
which path to use, naming the folders of the center that could be it. With no
node running, or where the node cannot tell either (a `w` folder it cannot
resolve, or a node without an owner), the folder is stored as given and not recorded, a record it had stays, and
`folder add` says so (`note: … is stored as given and not recorded …`): start
the node, and add the folder again. Check for links (`find <folder> -type l`
on Linux, `dir /AL /S <folder>` on Windows) before you take `w` off the folder
above such a folder.

## What a command can reach in `folder` mode (Linux)

The node confines commands with Landlock:

| A command can | Where |
|---|---|
| Read | the system folders (`/usr`, `/bin`, `/lib`, `/etc`, `/opt`, `/proc`, `/sys`, `/dev`, `/run` but `/run/nerve-node`, and similar) and the `r` folders |
| Write | the `w` folders and the null and terminal devices |
| Run programs | the system folders and the `x` folders |

- A folder with `w` and no `r` can be written but not read or listed by a
  command.
- Landlock cannot run a file it may not read. So an `x` folder also lets a
  command read files there by name. It still cannot list the folder.
- The node's own folders are in none of these sets.
- `/tmp`, `/var/tmp` and the home of `nerve-run` are in every set of a
  `nerve-run` command, to read, write and run programs in
  ([below](#the-account-nerve-run-linux)).
- A command with `w` on a folder can put a link in place of a folder inside
  it, and a link would give that folder's rights in a place you never named.
  So a folder is left out of the sets, and the node logs a warning, when its
  path passes through a link that lies inside a `w` folder (of any pairing).
  That holds for a link you made yourself too, and a link of yours that
  leads into the `w` folder is followed to its end and judged on the way.
  The folder is back once its path is a plain folder again. A link of your
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
- On a node you run yourself, the command runs as you. Landlock holds the
  command's own processes, not the other programs of your account: `folder`
  mode there is no boundary against those of them that run things on
  request (a session's service manager, a terminal multiplexer and the
  like), which run what the command asks outside the sandbox, as you. Install
  the node to run commands as `nerve-run`. With the node's keys in the system
  keyring, `folder` mode on a node you run yourself runs no command: the
  command could reach the keyring over your session bus.

## The account `nerve-run` (Linux)

The node installed as a service runs `folder` mode commands, and
`allowlist` mode commands unless you set `--as-owner`, as `nerve-run`.
`install` makes it, with a home of its own, `/var/lib/nerve-run`, no login
and no other groups; `uninstall` removes both.

- It is not you. Your session's programs (the service manager, the session
  bus, tmux, a container engine) take requests from your own account only,
  and your folders that others may not open stay closed to it. It cannot
  change the node's settings: the owner socket refuses it.
- It gets the folders you grant as POSIX ACL entries: the folder and
  everything below it, with the rights of its flags, and a default entry, so
  that what it makes there stays yours to use as well. A folder of yours
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
  Landlock holds each command to its own pairing's folders and to
  `nerve-run`'s own ones, which all those pairings share, the settings of
  their programs included (below). A file call keeps to its own pairing's
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
  ACLs) is named by `folder add` and `folder set` and in `nerve-node status`,
  also after a restart, and is tried again: at the node's start, with the
  next change of the folders, and at most once a minute before a command.
- It always has `/tmp`, `/var/tmp` and its home, to read, write and run
  programs in. Its tools keep their caches and configs in its home: `HOME`
  and the `XDG_*` folders point there. Every pairing whose commands run as
  `nerve-run` uses the same home, so a pairing that may write there can
  change the settings the programs of another pairing's commands load, and
  through them what those commands do in that pairing's folders. Give a
  center you trust less a machine of its own rather than a pairing beside
  one with folders worth more; the closest second best is `allowlist` mode
  as `nerve-run` with exact rules, for programs that keep no settings in its
  home. `--as-owner` is no way out: it runs the allowed commands as you (as
  root where root is the owner), outside the sandbox.
- git trusts the repositories it reaches (`safe.directory`), so it works in
  your repositories although they are not its own.
- It has no SSH keys or other credentials of yours, so `git push` and the
  like fail unless you set that up for it. That is intended.
- Tools you installed in your home (`~/.cargo`, `~/.rustup`, nvm, pyenv)
  are not on its way. Install them system-wide, grant their folder with `r`
  and `x`, or install them for `nerve-run` in its home.
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
- An allowed [sudo](sudo.md) command of a pairing whose commands run as
  `nerve-run` runs as root, started by the node: the sudo list is its only
  way to root, and your password is not used for it.

Check that your kernel supports it, with the node running:

```sh
nerve-node status
```

The first line reads `daemon: running (confinement landlock v…)`. With
`confinement none` the kernel has no Landlock. The installed node then runs
`folder` mode and `allowlist` mode commands as `nerve-run` without it: its
account alone holds it back, so it reaches the folders you give it and
whatever other accounts may reach ([your
home](#your-home-and-other-accounts)), and each pairing's line in `status`
says `as nerve-run, without Landlock` (the app says **Without Landlock**). What sets one pairing's folders apart from
another's is then gone, as the account is one for all of them, and so is
the narrower set Landlock gives (`w` without `r`, `x` without listing). A
node you run yourself refuses every `folder` mode command without Landlock,
and a line `folder mode runs no command: …` says why.

### Your home and other accounts

With Landlock, each command of `nerve-run` is held to its own pairing's
folders, and nothing below is a concern for commands. File calls in `folder`
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

## What a command can reach in `folder` mode (Windows)

Each pairing's commands run in an AppContainer of their own. A new pairing
gets a new one, also when you pair the same center again under the same
name. Windows lets a
process there open only what is granted to that container, and what it opens
to every AppContainer. This holds for a node you run yourself. The
[installed service](service.md#windows) runs every command as another account,
and does not start the AppContainer as that account yet: there `folder` mode
runs no command (`confinement none`), and the service puts no grants on
folders.

| A command can | Where |
|---|---|
| Read and run programs | the Windows folder and Program Files |
| Read, write, run programs | each folder by its rights |

- The node gives each folder a permission entry for the pairing's container,
  with the folder's rights. Everything below the folder inherits it. Windows
  keeps the permissions of each file and folder, so the node writes the
  entry into each one below the folder: the first grant of a large folder,
  changing its rights and taking it off take a while. A change goes only as
  far as it changes something: putting the same entry on again changes
  nothing, a later change skips the parts of the folder it leaves as they
  are, and a folder whose permissions do not inherit keeps the change out
  of itself and of what is below it. A change that stopped part way (you
  stopped the CLI or the node, or it failed) goes through the whole folder
  again at the next sync; until it is done, the node treats the folder as
  having the flags it was heading for as well, and where the change is
  refused, the pairing's commands do not run. A change that takes more than a few seconds says
  how far it is: the CLI prints it, a running node writes it to its log,
  and a command waits for it.
- `folder rm` and `folder set` change the entry, and removing the pairing
  takes it off. That is the node's entry on the folder: permissions a
  command gave what it made there stay (see "What the AppContainer does not
  stop" below). A running node takes these changes from the CLI at once,
  over its [control pipe](platforms.md#the-control-pipe), and has changed
  the entries when the CLI answers.
- `uninstall` takes off the entries of the node in your own folders (not
  those of a folder that holds hard links the check refuses, see below)
  (`%USERPROFILE%\.config\nerve` and `.local\state\nerve`, or those you name
  with `--config-dir` and `--state-dir`). Once a service is installed, the CLI
  reaches the service, so name the folders to change the node you run
  yourself. Before you delete its folders, remove its pairings: the record of
  the entries is in its state folder.
- Each pairing's container has a profile in the account that ran the node:
  a folder `%LOCALAPPDATA%\Packages\nerve.…` and a registry key.
  `center ls` names each pairing's container (`AppContainer nerve.…`). The
  profile goes with the container's last folder entry, with `center rm`,
  and at `uninstall`, which say which profiles they removed. While the node
  runs they keep its profiles and say so, as it still serves the pairing
  until it starts again, and the other changes the CLI writes to the file
  itself keep them too; stop the node first. The running node itself removes
  a profile when the pairing's last granted folder is deleted or moved away.
  So does a `folder rm` or `folder set` that leaves a pairing with no
  granted folder: the CLI hands it to the node over the
  [control pipe](platforms.md#the-control-pipe), and the node syncs the
  grants and removes the profile, without the CLI saying so. The name comes from the
  path of the state folder and the pairing in `node.toml`, so the node
  finds the profile as long as the config folder is there, also after the
  state folder was deleted, and whether you type the folder with `\` or
  `/`. If you deleted the state folder before you removed the pairings,
  name both folders as they were and remove the pairings:
  `nerve-node --config-dir <config> --state-dir <state> config accept`,
  then `center rm` with the same folders for each pairing. Spell the state
  folder exactly as the node had it: the same upper and lower case, no
  `\` at the end, and absolute or relative as it was given (only `\` and
  `/` may differ). Each `center rm` says
  `removed the AppContainer profile nerve.…`, also when the grants of the
  other pairings do not follow. To check first, run `center ls` with the
  same folders: when the `AppContainer nerve.…` name it shows for a
  pairing is not in the `Get-ChildItem` list below, that pairing never ran
  a command in its container, or the state folder is spelled otherwise
  than the node had it.
- If the config folder is gone too, the node cannot tell which profiles
  were its own. `Get-ChildItem $env:LOCALAPPDATA\Packages -Filter nerve.*`
  lists the profiles of all nodes this account ran; those that `center ls`
  of the nodes you still run (with their folders) does not name are left
  over. Remove each, as that account, with
  `[Nerve.Profile]::DeleteAppContainerProfile('nerve.…')` after
  `Add-Type -Namespace Nerve -Name Profile -MemberDefinition '[DllImport("userenv.dll", CharSet = CharSet.Unicode)] public static extern int DeleteAppContainerProfile(string name);'`.
  It returns 0 also for a name that has no profile, so check that the
  folder is gone. A folder that stays may be held by a registry hive that is
  still loaded; it goes after a restart of Windows
  ([#94](https://github.com/prometheion/nerve-protocol/issues/94)). A node that still runs makes the profile of its
  container again at its next command, without what its commands kept
  there.
- A granted folder you move or rename on the same drive takes its entry
  along, as Windows keeps its permissions. At its next sync (at start, on a
  change, before a command, and when the CLI changes the config) the node
  finds it by its file ID and takes the entry off where it is now, also on a
  drive mounted in a folder. A granted folder you delete and make again gets
  its entry back at the next sync. One on a drive that is not connected keeps
  its entry until the drive is back; `uninstall` names those it leaves on.
- A file or folder you move out of a granted folder on the same drive keeps
  the entry it inherited. `icacls <path> /reset` gives it the permissions of
  its new place.
- The flags stay independent: `w` without `r` writes but neither reads nor
  lists, `x` runs programs and reads files by name but does not list. Hard
  links and the permissions a command gives what it makes are the
  exceptions, see the bullets on permission entries and hard links below.
- Deleting and renaming need `r` and `w`, since Windows allows a move with
  the same right as a delete: a command must not move what it cannot read
  to a folder where it can. So in a folder with `w` but not `r`, a command
  adds and changes files, but does not delete, rename or move any. A
  granted folder or file itself is deleted, renamed or moved only through
  the folder above it, with `r` and `w` there; on Linux too that needs a
  right on the folder above.
- A folder you grant inside another granted folder with `w` gets its entry
  only while it is a folder of its own there: not a junction or link to
  another place, not a file with a second name (a hard link), and with
  permissions that inherit. A command may write there, so it could put a
  junction in its place, and the entry would land on the folder it leads
  to. This holds for a folder inside a `w` folder of any pairing. The node
  names such a folder in its log (`left out of the command's sandbox: it
  passes through the link …`) and grants it once it is a plain folder again.
  A junction of yours that leads into the `w` folder is followed to its end
  and judged on the way. A folder you added with `folder add` stays out when
  a junction has replaced it since, also after you took the `w` off the
  folder above or removed the pairing that had it
  ([above](#a-folder-keeps-the-place-you-added)). A folder without that
  record (see there) is followed again once nothing shows commands could
  write there: check it for junctions and links (`dir /AL /S <folder>`)
  before you take `w` off the folder above or remove a pairing.
- The node's own folders and the [protected paths](protected-paths.md) get no
  entry, also inside a folder you grant. That folder is granted as its other
  entries instead, as on Linux.
- PowerShell starts on a drive `Work:` that is the working folder, because the
  container may not look at the folders above it. Whole paths, relative paths
  below the working folder and native programs work as usual.
- `cd` and `pushd` to the whole path of a folder the command may see, or with
  `..` up out of the working folder into one, put PowerShell on a drive of
  that folder (`Work2:`, `Work3:`, …), and native programs start in the folder
  itself. These drives open nothing; the container decides what the command
  reaches. `cd` to a folder the command may not see fails as any other access
  does, also with `..`: PowerShell stays where it was, `$?` is false, and a
  command that ends with that `cd` fails.
- Other commands keep `..` on the drive they stand on: on `Work:\`,
  `Get-Content ..\README.md` reads the working folder's own `README.md` or
  fails, but does not read the one above it. Give them a whole path for a
  folder above the one PowerShell stands in, or `cd` there first.
- The command has the network, but not `localhost`. It has its own desktop,
  so it cannot reach your windows or clipboard, and Windows gives its
  container a folder of its own for temporary files.
- What the AppContainer does not stop (the network, what Windows opens to
  every AppContainer, the environment the command starts with, and more) has
  [its own list](#what-the-appcontainer-does-not-stop) below.
- A command sets the permissions of a folder or file it makes, as every
  Windows program may, so it can give them an entry of its own, of three
  kinds: for its pairing's container (`S-1-15-2-…`), for all AppContainers
  (`ALL APPLICATION PACKAGES`, `S-1-15-2-1`), or for a capability that
  every pairing's container has (`S-1-15-3-1`, `-2` and `-3`, which
  `icacls` shows as `APPLICATION PACKAGE AUTHORITY\Your …`). The node
  neither sees nor removes these. They stay when you remove the folder,
  change its flags, remove the pairing or run `uninstall`. An entry for the
  container belongs to that pairing: no later pairing runs in that
  container, also not one of the same center or under the same name. The
  other two kinds count at once, for every pairing of the
  node and for every app on the machine that runs in an AppContainer (for
  a capability: every such app that has it). In a
  folder with `w` but not `r`, a command can make a folder that lets it
  read what you or another pairing save into it later. So do not save
  files a pairing must not read into a folder where it may write. After you
  take `w` off a pairing's folder or remove the pairing, clean the folder.
  Only `icacls <folder> /reset /T` removes all of them with certainty; it
  also resets permissions of your own below the folder. To keep those,
  find the entries with
  `icacls <folder> /T | findstr /C:"S-1-15-" /C:"APPLICATION PACKAGE"` and
  remove each with `icacls <folder> /remove *<SID> /T`: every `S-1-15-2-…`
  and `S-1-15-3-…` entry, and `ALL APPLICATION PACKAGES` as `*S-1-15-2-1`.
- A hard link is one file under two names, and both share one access list.
  When the node grants, changes or moves a folder that commands may write
  in, or a folder that holds one, the change passes to the files below it
  whose permissions it changes, and that would include hard links. Before
  such a change the node checks those files and refuses if one has more
  than one name, and it checks each file again right before it changes it,
  by the names the file has then: a link a command makes in between stops
  the change there. What it changed by then stays changed, and the folder
  itself keeps its old entry; only a link made in the folder itself while
  the change was below it is found after the folder got its new entry, and
  the message says so. The node goes through the whole folder again at its
  next sync, and refuses the change until the link is gone. A file whose permissions the change leaves as they are
  is not reached, so a link to it stops nothing. Hard links only
  work within one drive. So put a
  write-only folder whose files commands must not read on a drive where the
  pairing can write nowhere that it can also read or run programs, also
  through a folder above.
- Build tools make hard links of their own. cargo builds each program
  under two names in `target`, so a file in a folder named exactly `target`
  inside the folder passes the check when every one of its names lies in
  such a folder of the same granted folder, under the same grants, no
  pairing has `w` without `r` on that folder, one above it or one inside
  it, and the node finds no granted folder moved or renamed in that sync.
  (A command may give a folder it makes permissions of its own, and the
  change would pass them to a file it linked there; the check keeps a file
  it may only write from getting them this way.) So a built
  Rust project you rename or move needs `cargo clean` before its entry can
  come off at its new place; until then the record of the entry stays stale
  and that pairing's commands stop. Any other
  second name is still refused, also a `target` file whose other name lies
  outside the folder or under another grant, and one whose names Windows
  cannot list. Other tools' links are refused too: pnpm links
  `node_modules` to its store, uv links a `.venv` to its cache, and a local
  `git clone` links its objects. A folder that holds such links does not get
  its entry, and its entry is not changed or taken off. A refused removal
  stops that pairing's commands, and `uninstall` leaves the entry on, until
  the links are gone. Keep them out of granted folders: pnpm's
  `package-import-method=copy`, `UV_LINK_MODE=copy`, `git clone
  --no-hardlinks`. Or remove them (delete `node_modules` or `.venv`) before
  you add, change or remove the folder.

`nerve-node status` shows a running node's confinement (`daemon: running
(confinement appcontainer)`): on Windows it asks the node over its
[control pipe](platforms.md#the-control-pipe). The node also names it when it
starts, in its output and its [log](logs.md):
`node daemon running (…, confinement appcontainer, …)`. The center sees it in
the node's `exec` state, `confinement appcontainer`, or `none` on the
installed service.

### What the AppContainer does not stop

The container keeps a command out of the files you did not grant. It is not
a box around everything else. This is what a `folder` mode command can still
do on Windows, as far as the owner might expect otherwise. Each point says
how it is known. "Checked" means a command was started in an AppContainer
the way the node starts one, on Windows 11 Pro (26H2, build 10.0.26300) from an
elevated administrator session over SSH; that is one machine, and Windows
and other software may open more or less to AppContainers elsewhere. "Code"
means it follows from the node's code. What is marked "not checked" is not
known.

In short: `folder` mode keeps the command's own files and the owners' pipe
closed, but it is not shown to hold against every program of yours that
runs things on request. One that opens itself to all AppContainers runs
what the command asks as you, outside the container, and then a command
can do all you can, Nerve's settings too. On Windows commands run as you, so
that is yours to answer for; an account of their own, as on Linux, is
planned.

- **The network.** The container has the capabilities `internetClient`,
  `internetClientServer` and `privateNetworkClientServer` (code). Checked: a
  command connects to the internet, resolves names and connects to other
  machines of the local network. Nothing in the node filters by address or
  port. So whatever a command may read it can send out, and it can download
  into a folder where it may write and run what it fetched. It cannot reach
  the machine itself: `127.0.0.1`, the machine's own network address and its
  computer name all timed out (checked), so a service that listens only on
  this machine is out of reach, and one on another machine is not. A command
  can listen on a port (checked). Whether another machine gets through to it
  is the Windows Firewall's say: with the firewall on and no rule for the
  port it did not, with a rule for the port it did (checked). The node adds
  no firewall rule (code).
- **The environment.** The command starts with the node's environment: the node
  clears nothing (code). Windows replaces `TEMP`, `TMP` and
  `LOCALAPPDATA` with the container's own folder (checked). A secret in a
  variable of the process that started the node, a token say, is visible to
  every command. Start the node without such variables.
- **Files outside the folders.** Windows opens its own folder and Program
  Files to every AppContainer, and a command reads and runs programs there:
  what Windows's permissions on a file below them leave to all AppContainers
  is readable, also software settings you keep in Program Files. Checked:
  `C:\Windows`, `C:\Program Files` and `C:\Program Files (x86)` list, and
  a file below `C:\Windows` (the hosts file) reads. Refused: the listing of `C:\`, `C:\Users`, your profile and its
  `Desktop` and `AppData`, `C:\ProgramData`, `C:\Windows\Temp` and
  `C:\Windows\System32\config`, and writing to `C:\`, `C:\Users\Public`,
  `C:\ProgramData` and `C:\Windows\Temp`. A command also writes the
  container's own folder, `%LOCALAPPDATA%\Packages\<container>\AC` (it
  holds `Temp`), without any grant. It stays between the commands of the
  pairing, and Windows deletes it with the container's profile. The node
  removes that profile with the container's last grant, a running node
  too when the pairing's folders are gone at its sync, also after a
  `folder rm` or `folder set` of the last one; `center rm`, `uninstall` and
  the other changes the CLI writes to the file itself remove it only while
  the node does not run (see above) (checked, code).
- **The registry.** Checked: a command reads the machine part (`HKLM`, for
  example the Windows version), lists the keys of your `HKCU` and reads
  `HKCU\Environment`, which holds the environment variables you set for
  yourself. It was refused the `Run` key and every write it tried, to `HKCU`
  and `HKLM`. This is not a map of the registry: Windows decides per key.
- **Other processes of your user.** Checked: the container sees its own
  processes only (two, in the test), could not look up a process of yours by
  its number, and so could not stop it. Everything the command starts itself
  stays in the container and in its job. Not checked: other ways to reach a
  process, such as a window of the same desktop (it has its own).
- **Work another program does for it.** Checked with the usual tools, none
  of these got through: WMI (`Invoke-CimMethod Win32_Process Create`,
  `tasklist`), the task scheduler (`schtasks /create`), the service manager
  (`sc.exe`, `Start-Service`), `Start-Process -Verb RunAs`, `Start-Process`
  on a document or a web address, and `Shell.Application` and
  `WScript.Shell`. The node does not block these itself: a service, COM
  server or pipe that Windows or a program on the machine opens to all
  AppContainers can be used. What such a program starts is its own process,
  outside the container and outside the job ([Windows](platforms.md#windows)).
  Not checked: other interfaces, such as direct calls to a service or the
  task scheduler without these tools.
- **Named pipes.** Checked: the pipes of system services (`lsass`, `svcctl`,
  `atsvc`, `srvsvc`, `wkssvc`, `ntsvcs`, `eventlog`, `InitShutdown`) and a
  pipe a program of yours made with the default security were refused. The
  RPC endpoint mapper (`epmapper`) and a pipe made open to all AppContainers
  were opened. So a program of yours that makes a pipe open to all
  AppContainers can be talked to. Not checked: other local endpoints (COM
  servers, ALPC ports).
- **The clipboard and your windows.** The command has a window station and
  desktop of its own (code). Checked: reading the clipboard fails. Not
  checked against a signed-in desktop with something on its clipboard: the
  test session had no desktop.
- **Credentials.** Not checked: the Credential Manager, since the test
  session could not use it. The container has none of the capabilities for
  your sign-in credentials or certificates (code), so it should not reach
  network shares as you; not checked. With the node's keys in the
  Credential Manager (`machine.secret_storage = keyring`) `folder` mode runs
  no command on Windows (code, [keys](config.md#where-the-node-keeps-its-keys)).
  Checked: a blob protected with DPAPI for the machine can be opened by the
  command. A blob for your user could not be made in the test session, so
  that is not checked. The node's own keys are files in folders that get no
  grant (code).
- **The token.** Checked: low integrity level, no privileges but
  `SeChangeNotifyPrivilege` and `SeIncreaseWorkingSetPrivilege`, and
  `Start-Process -Verb RunAs` was refused. That held in a session with the
  administrator's elevated token, so a node you allowed to run elevated
  ([root and administrator](platforms.md#root-and-administrator)) does not
  hand that token to the command. The container does not limit memory, CPU,
  disk or the number of processes; the job only ends them (code).
- **What a granted folder allows.** The flags are the rights, and a command
  in the folder is in the container too. A command with `w` can leave files
  there that you, a build or an editor run later, outside the container: a
  script, a build file, a Git hook, an install script of a package. The
  container holds the command, not the files it writes. Links: a command
  made a hard link to a file in its own folder and was refused one to a file
  outside (checked). It made a junction to a folder inside its own folder and
  was refused one to `C:\Windows`, `C:\Program Files` and `C:\Users`
  (checked), and a symbolic link needs a privilege it does not have
  (checked). What that means for a folder inside another granted folder, for
  hard links and for the permission entries a command gives what it makes is
  in the bullets of the section above.
- **The sudo path.** A command on the [sudo list](sudo.md#sudo-on-windows)
  runs as the account commands run as, with that account's administrator
  token, in a job but not in an AppContainer, and in every mode (code). The
  folders do not apply to it: only the switch, the sudo list, the
  [deny rules](rules.md#deny-a-command) and the
  [protected paths](protected-paths.md) decide. On Windows sudo works on the
  node installed as a service only, and there `folder` mode runs no other
  command yet, since the AppContainer is not started for the service's
  account. So on that node a `folder` mode command runs only when the sudo
  list names it.

## `user` mode

`user` mode allows everything you could do yourself, except
[protected paths](protected-paths.md). Commands run as your user, without
confinement. A command can do what you can do, including changing the node's
own state. Use it only for a center you would trust with a shell.

On a node [installed as a service](service.md) the node runs as its own
user, `nerve`, and, unless root is the owner (below), `user` mode commands run as you, the owner, the account
that ran `install`. They can do what you can do. They cannot read the node's
keys, which are `nerve`'s, but they can change the node's settings as you
can without a password, through the owner socket (on Windows the owners'
pipe), as your own programs do. The node does not stop that: it is your
choice of mode. The center's [blocklist and action checker](action-checker.md)
and the node's [guard](rules.md#the-guard-against-changing-the-node) catch
such a command when an agent tries it by mistake, and the node refuses a
process it sees below one of its commands, but none of that is a boundary.
The same holds for `allowlist` mode with `--as-owner`.

Where root is the owner (an install that root ran itself and confirmed,
[service](service.md#root-as-the-owner)), `user` mode and `allowlist` mode
with `--as-owner` run commands as root. They can do everything on the
machine, read the node's keys and change the node itself. Nothing in Nerve
holds them back: the guard, the action checker and the refusal of the owner
socket only catch mistakes, and root needs none of them to get in. It is
your choice, as root, when you answer yes at `install`. `folder` mode and
`allowlist` mode without `--as-owner` still run as `nerve-run`. A center with
the [settings grant](settings-grant.md) can switch itself to `user` mode,
and so to root.

### Paths a command builds at run time

The node checks the paths a command line names plainly (an absolute path, or
one that starts with `~/` or `$HOME/`) against the
[protected paths](protected-paths.md) and its own folders. It does not see a
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
  ([rules](rules.md#what-a-wildcard-covers) keeps shell syntax out of a
  wildcard rule, not what a program does).
- A [sudo](sudo.md) command runs as root without the sandbox, in `folder` mode
  too: a script or interpreter on the sudo list can build a path to the node's
  files at run time. Put no program on the sudo list that you would not trust
  with them. On the installed Windows node `folder` mode runs only such
  commands ([Windows](#what-a-command-can-reach-in-folder-mode-windows)).

And in `folder` mode while commands run as you (on a node you run yourself,
or on Windows), a command can hand work to the programs of yours that run
commands on request, which are outside the sandbox
([Linux](#what-a-command-can-reach-in-folder-mode-linux)). As `nerve-run` it
cannot: they do not take requests from another account.

No rule closes these limits.

## Which mode

| You want | Use |
|---|---|
| The agent may run a few known commands | `allowlist` with [rules](rules.md) |
| The agent works freely in a project folder | `folder` (the default) with one folder `+r +w +x` |
| The agent acts as you | `user`, maybe with `--for` |
