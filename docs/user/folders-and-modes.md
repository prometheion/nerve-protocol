# Folders and modes

Every pairing has a mode: how much that center may do on the machine. In
`folder` mode, the default, you give it folders with rights.

```sh
nerve-node folder add ~/project rwx
nerve-node mode                        # each center's mode
nerve-node folder                      # the folders and their rights
```

## The three modes

| Mode | What runs | Commands run as |
|---|---|---|
| `folder` (default) | Writing and commands in the folders you give, by their rights | `nerve-run`, held to those folders |
| `allowlist` | Only what an [allow rule](rules.md) names | `nerve-run`; or you, with `--as-owner` |
| `user` | Everything you could do yourself | you, outside the sandbox |

From most to least locked down: `allowlist`, `folder`, `user`. Deny rules,
the guard and [protected paths](rules.md#protected-paths) hold in every mode.
A call that nothing allows is refused at once; nothing waits for an answer.

- `user` mode, and `allowlist` with `--as-owner`, run commands as you,
  outside the sandbox. Where root is the owner, as root. Such a command can
  change the node's settings as you can
  ([user mode](../dev/policy-engine.md#user-mode)).
- `folder` mode leaves the network open: `nerve-node network off`
  ([network](network.md)).

Choose by what the agent should do:

| You want | Use |
|---|---|
| The agent may run a few known commands | `allowlist` with [rules](rules.md) |
| The agent works freely in a project folder | `folder` with one folder `rwx` |
| The agent acts as you | `user`, maybe with `--for` |

## Set the mode

```sh
nerve-node mode allowlist
nerve-node mode folder
nerve-node mode user --for 2           # 2 hours, then the mode before
nerve-node mode allowlist --as-owner   # allowed commands run as you
```

- `--for` takes hours, at least 1. It does not go with `allowlist`.
- A timed `user` ends in the mode before it, never `user`. A timed `folder`
  ends in `allowlist`. `mode` and `status` say where a timer ends.
- Setting a mode again without `--for` removes a timer, and without
  `--as-owner` goes back to `nerve-run`.

With several centers, add `--center <name>`.

## Folders and their rights

A folder gives rights, each its own letter:

| Right | Allows |
|---|---|
| `r` | Reading: the file calls stat, list, read, grep and find |
| `w` | Writing files, and reading them as `r` does |
| `x` | Running commands whose working folder is in it |

`w` reads too, so `w` alone is `rw`. A command needs `x` and not `r`. A
command in an `x` folder can also read its files by name, not list
them ([what a command can reach](../dev/sandbox-linux.md#what-a-command-can-reach-in-folder-mode)). A
folder covers everything below it, and where folders nest the deepest one
decides.

| Command | Does |
|---|---|
| `nerve-node folder add ~/proj rwx` | Gives a folder, with its rights as one word (`r`, `rw`, `rx`, `rwx`) |
| `nerve-node folder add ~/proj rx` | Changes the rights of a folder it has |
| `nerve-node folder add ~/proj/secret none` | Closes a folder inside one it has |
| `nerve-node folder rm ~/proj` | Takes the folder away |
| `nerve-node folder` | Lists the folders and their rights |

`~` is your home, also on the installed node. Folders count in `folder`
mode. In `allowlist` mode as `nerve-run` they are the sandbox the allowed
commands run in, and the allow rules decide what runs.

- A folder with `none` is closed to file calls. A command started in the
  folder around it still reaches it
  ([folders](../dev/policy-engine.md#folders-and-rights)).
- On the installed node, a file call in `folder` mode may also read what
  every account may read, such as `/etc` and most of `/usr`. It never reads
  what is closed to other accounts
  ([reading](../dev/sandbox-linux.md#reading-in-folder-mode)).

The agent is told its own mode, its folders and their rights. It is never
told another center's.

### Keep the folders in sync

The node gives `nerve-run` its folders as access list entries (ACLs). What
you make in a folder later gets them. What you move into it (`mv` of a
download or a clone) keeps its own list for a few seconds: the node watches
the granted folders and gives it the folder's entries by itself.

You need **Sync folders** under **Permissions › Folders** only by hand, for
a folder too large to watch (the node's log says so):

```sh
nerve-node folder sync
```

The node also walks every folder when it starts, and on `folder add` of a
folder it has. On large trees a walk takes a while
([how](../dev/sandbox-linux.md#the-account-nerve-run)).

`folder add` stores the real place of a path. It refuses a link inside a
folder where commands may write, since a command may have put it there:
add the place you mean by its own path
([why](../dev/sandbox-linux.md#a-folder-keeps-the-place-you-added)).

## The account `nerve-run`

The installed node runs `folder` mode commands, and `allowlist` mode
commands without `--as-owner`, as `nerve-run`, an account of their own.

- It is not you. Your session's programs and your closed folders refuse it,
  and it cannot change the node's settings.
- Each pairing has its own home and temporary folder:
  `/var/lib/nerve-run/<center>/home` and `…/tmp`. `HOME` and `TMPDIR` point
  there. The node deletes them when the pairing goes.
- Set up what its commands need there: an `.ssh` key, a `.gitconfig`,
  caches. A `folder` mode command has no terminal, so a password prompt of
  `ssh`, `gpg` or `git` fails.

Its limits:

- All pairings share `/tmp` and `/var/tmp`. Keep no secret there, and run no
  key agent or credential cache in a pairing's home
  ([the account](../dev/sandbox-linux.md#the-account-nerve-run)).
- Without Landlock, each pairing's commands reach the homes, the folders and the
  running commands of the others, with their network, as all run as `nerve-run`. `status` warns; give a center you trust less a
  machine of its own ([the account](../dev/sandbox-linux.md#the-account-nerve-run)).
- Below Linux 6.12 (stock Ubuntu 22.04, 24.04 and Debian 12), one center's
  commands can signal another's and reach its abstract sockets. `status`
  warns ([Landlock versions](../dev/sandbox-linux.md#landlock-versions)).
- Below Linux 6.2 (stock Ubuntu 22.04 and Debian 12), a command can empty a
  file `nerve-run` may write outside its folders. A node run by hand there
  runs no `folder` mode command
  ([Landlock versions](../dev/sandbox-linux.md#landlock-versions)).
- Without Landlock, `nerve-run` can read every file in your home that other
  accounts may read, once you give it a folder there. `status` warns: give
  folders outside your home, or `chmod -R o-rwx` what you keep private
  ([your home](../dev/sandbox-linux.md#your-home-and-other-accounts)).
- Commands of `nerve-run` see only `PATH`, `LANG`, `TERM` and the variables
  you name in `machine.command_env`. Put no secret into the service unit
  ([environment](../dev/sandbox-linux.md#the-accounts-commands-run-as)).

```sh
nerve-node config add machine.command_env GOPATH
```

## A node run by hand

A node you start yourself with `nerve-node run` has no `nerve-run`: it runs
every command as you. `folder` mode then needs Landlock, and reads only in
the folders with `r`. A command reaches your session's sockets, such as
tmux and X ([what it does not stop](../dev/sandbox-linux.md#what-it-does-not-stop-linux)).
