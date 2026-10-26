# Settings and `node.toml`

Every setting of a node is in one file, `node.toml`, in the node's config
folder ([where](install.md#where-files-live)). The commands in this guide
change it for you. `nerve-node config` reaches any setting by its name.

## Read and change by name

A name is a dotted path. A center's settings are under `center.<name>`, where
`<name>` is the name from `nerve-node center ls`.

```sh
nerve-node config get center.lab.policy.mode
nerve-node config set center.lab.policy.mode folder
nerve-node config add center.lab.policy.allow 'fs.read:~/notes/*'
nerve-node config remove center.lab.policy.allow 'fs.read:~/notes/*'
nerve-node config unset limits.max_running
nerve-node config get center.lab          # a whole table
```

| Command | Does |
|---|---|
| `config get <key>` | Print one setting or a table |
| `config set <key> <value>` | Change a setting |
| `config unset <key>` | Remove it, so its default applies |
| `config add <key> <value>` | Append to a list |
| `config remove <key> <value>` | Remove a value from a list |
| `config accept` | Take a file you edited by hand |

A value that does not fit the setting is refused, and nothing changes.

## The settings

```toml
[node]
name = "laptop"             # shown to centers; the host name by default

[machine]
shell = "/bin/bash"         # runs commands; the platform shell by default
allow_root = false          # let the node run as root, or elevated as administrator on Windows
sudo_path = "/usr/bin/sudo" # optional
user = "alice"              # installed node on Windows: the account commands and sudo run as
secret_storage = "file"     # file | keyring: where the node keeps its keys

[limits]
max_running = 16            # commands at once, over all centers
output_cap_bytes = 16777216 # for stdout and for stderr each; a result carries 1 MiB at most
default_timeout_secs = 600  # how long a command runs when its call gives no timeout_ms
max_timeout_secs = 3600     # the longest any command runs; a larger timeout_ms is cut to it

[limits.command]            # what one command may use, Linux (limits.md)
memory_mb = 4096            # MiB; past it the command is killed
memory_max_mb = 16384       # the most a call may ask for
cpu_percent = 200           # of one CPU: 200 is two CPUs
cpu_max_percent = 800
processes = 1024            # processes and threads at once
processes_max = 8192

[connection]
proxy = "http://proxy:3128" # set with `nerve-node proxy set`; https://… for a relay

[relay]                     # set with `nerve-node relay`; off without listen
listen = "0.0.0.0:7490"
pin = "…"                   # the pin of the relay's certificate, made by `relay set`
max_links = 16              # tunnels at once, over all relayed nodes
max_links_per_node = 4
max_opens_per_minute = 30   # tunnels one relayed node may open a minute

[[relay.node]]              # added by `nerve-node relay add`
name = "lab-pc"
token_sha256 = "…"          # the hash of its token; the token is in no file
centers = ["home"]          # optional: the centers it may reach; every one without it
max_links = 12              # optional, `relay set-limits`: its own tunnels at once
max_opens_per_minute = 300  # optional, `relay set-limits`: its own opens a minute

[log]
level = "info"              # error | warn | info | debug: how much the node logs

[providers]                 # programs that may add capabilities (providers.md)
allowed = [{ name = "desk", exe = "/usr/lib/nerve-desktop/nerve-desktop" }]

[[center]]
name = "lab"
url = "https://lab.example:7443"
settings = "off"            # off | write: the settings grant
paused = false

[center.policy]
mode = "allowlist"          # allowlist | folder | user
until = 1790000000000       # optional end of folder or user mode, ms since the epoch
folders = [{ path = "/home/u/proj", access = "rwx" }]
places = ["/home/u/proj"]   # written by `folder add`, not by hand
caps = { "fs.write" = "off" }
allow = ["exec.run:git status", "fs.read:~/notes/*"]
deny = ["fs:~/private/*", "exec.run:rm *"]
sudo_allow = ["sudo apt update"]
protected = { extra = [], allow = [] }
```

The file also holds a `version` that grows with every write, `locked`
(set by `panic`), and per center the `url`, `pin`, `center_id` and `node_id`
the pairing filled in. Unknown keys are refused. `places` is the node's
record of the folders `folder add` stored ([modes](modes.md#a-folder-keeps-the-place-you-added)).

## How long a command may run

Every command ends. The agent can give a call a `timeout_ms`; without one the
command gets `limits.default_timeout_secs`, 10 minutes. A `timeout_ms` above
`limits.max_timeout_secs`, 1 hour, is cut to it, and so is the default when you
set the maximum below it. A command past its limit is killed with everything it
started ([what ends a command](stop.md#what-ends-a-command)), and the call
fails with `timeout`; the message says which limit it was, and whether a
larger `timeout_ms` would help.

```sh
nerve-node config set limits.max_timeout_secs 86400    # a command may run a day
nerve-node config set limits.default_timeout_secs 1800 # and gets half an hour unless it asks
```

Both are yours alone: a center, also with the [settings grant](settings-grant.md),
cannot change them. The agent sees the two numbers when it lists `exec.run` of
this machine: in its description, and in the `description` and `default` of
its `timeout_ms` (in milliseconds). Both follow a change, and after one the
agent must list `exec.run` again before its next command here. The most is
said in words, not as a `maximum`, since a larger `timeout_ms` is cut to it,
not refused. The agent lists `exec.run` per machine, so it never reads one
machine's numbers for another. A limit is at least 1 second;
for a long build, set a large maximum and not none. The settings are left out of
`node.toml` while they are the defaults, so `config get` shows them only once
you set them. A command already running keeps the limit it started with.

The agent's tool call does not wait as long as a command may run: after the
center's call wait (20 seconds unless set with `--call-wait`) the command
becomes a job, which runs on while the agent follows it up
([long calls](harness.md#long-calls-become-jobs)).

## Do not edit the file by hand

The node signs `node.toml`: the first line is a MAC. It rereads the file only
when you ask. A file with a missing or wrong MAC was changed outside
`nerve-node`, so the node refuses it:

- At start the node does not start.
- On a reload the old settings stay.

The message is:

```
node.toml is refused: its MAC does not match, so it was changed outside nerve-node; check it, then `nerve-node config accept` takes it as it is
```

Read the file first. Then take it:

```sh
nerve-node config accept
```

The node signs it and uses it.

The key for the MAC is `config.key` in the node's state folder, or in the
system keyring ([below](#where-the-node-keeps-its-keys)). A command that
runs as you (in `user` mode) can reach it in either place. The check protects against
`folder` mode commands and against centers, not against `user` mode. On a
node installed as a service, commands run as another account
([service](service.md#the-accounts-commands-run-as)) and cannot reach it,
except where [root is the owner](service.md#root-as-the-owner): there `user`
mode commands run as root.

### An older file put back

A file the node signed earlier still has a right MAC, so the MAC alone does
not show that someone put an earlier `node.toml` back in the config folder:
a folder you removed, a rule you took away, a pairing you ended. The node
therefore keeps the highest version of `node.toml` it has saved or taken in
`config.version` in the state folder, and refuses a signed file below it the
same way as a changed one:

- At start the node does not start, and the commands that read the settings
  refuse the file.
- On a reload the old settings stay.

The message is:

```
node.toml is refused: its version 3 is older than the last this node accepted (5), so an earlier file was put back; check it, then `nerve-node config accept` takes it as it is
```

You see it after you restore the config folder from a backup as well. Look at
the file, then take it with `nerve-node config accept`: the node signs it
under a version above every one before, so it is the newest file now, and the
older copies are refused in turn.

`config.version` is a number, in the state folder beside `config.key`, so it
holds as far as the key does: a `user` mode command can delete it, a `folder`
mode command cannot reach it. A node that has none (a state folder made new)
takes `node.toml` as it is and records its version. If the file is damaged, the
node does not start and says so: delete it, or take `node.toml` with
`config accept`. Take care of the two folders together when you back them up and
restore them: a config folder older than its state folder is refused.

## Where the node keeps its keys

The node has a key per center and the key for the MAC above.
`machine.secret_storage` says where they are:

- `file` (the default): files only the node's user can read, `keys/` in the
  config folder and `config.key` in the state folder.
- `keyring`: the system keyring, the Credential Manager on Windows and the
  Secret Service (GNOME Keyring, KWallet) on Linux. No copy stays in a file.
  Not on the node installed as a service on Windows: it runs as `nerve`,
  whose Credential Manager the commands you run as an administrator cannot
  reach, so it keeps its keys in files
  ([service](service.md#windows)).

```sh
nerve-node config set machine.secret_storage keyring
nerve-node config set machine.secret_storage file
```

The change moves the keys at once: each is copied, read back, and only then
deleted where it was. If the keyring cannot take them, nothing changes. On
Windows, while the node runs, the old copies stay until its next start. On
Linux, a node that runs but does not answer on its control socket (it is
still starting, say) keeps its keys in files until it is restarted, so
`config set` refuses to move them into the keyring then: stop the node, or
wait until it has started, and set it again.

A keyring hands its entries to any program of the node's user that asks,
through the user's D-Bus session. So with `keyring` on Linux the node keeps
centers out of that session's folder (`/run/user/<uid>`) and out of GNOME
Keyring's folder (`~/.local/share/keyrings`), as it does with its own
folders. On the node installed as a service the keyring is `nerve`'s, and
no command runs as `nerve`: commands run as `nerve-run` or the owner, whose
session is another, so no command of any mode reaches it, on any kernel. On
a node you run yourself the keyring is yours, and `folder` mode runs no
command while the keys are there.

A command keeps the sandbox it started with. So while a `folder` mode
command that started with the keys in files still runs, the keys do not go
into the keyring: `config set` and `setup` say how many such commands run,
and nothing changes. Wait until they end, or end every command with `nerve-node panic`,
set `keyring`, then `nerve-node unlock`. Commands that run as another
account than root do not count, as they cannot reach the session.
A process that a command takes out of its process group (`setsid`) outlives
the command where the node runs it without a cgroup ([limits](limits.md)),
and is not counted. If a center you do not trust had `folder`
mode while the keys were in files, restart the machine before you set
`keyring`.

On a node you run yourself, the keyring is kept from `folder` mode commands
only. An `allowlist` or `user` mode command runs as you without Landlock, and
a command that talks to the Secret Service needs no path to read the keys. With `keyring`, an allow
rule for `secret-tool`, `busctl --user`, `gdbus`, `dbus-send` or the like
hands a center every key of the node, which with `file` it could not read.
Do not allow such a tool to a center, or keep the keys in files.

This is a limit that stays, not one a later version closes. An allow rule
names a program that runs as you, and that mode is not a sandbox
([rules](rules.md#deny-a-command)): a rule for a keyring client is the same
kind of rule as one for a shell script that reads your files. Confining
`allowlist` commands for the keyring's sake would also stop programs a rule
is there to run when they need your session (`ssh` with its agent, `git` with a
credential helper), and it would still leave an allowed interpreter free to
read what you read. Look at what you allow with `nerve-node rule ls allow`.

With `keyring`, the node needs a keyring that answers. Without one it does
not start, and `status` and the other commands that read the settings say:

```
machine.secret_storage is "keyring", but the system keyring cannot be reached (entry …): …
```

The node never falls back to the files. Start the keyring, or on a Linux
without a desktop, let `setup` install one.

### A keyring on a Linux without a desktop

A server without a desktop usually has no keyring. When you choose `keyring`
in `nerve-node setup` (on the installed node too, without `sudo`), or
the settings say `keyring` and no keyring answers, setup asks:

```
No system keyring answers for nerve: ….
nerve-node can install GNOME Keyring: `/usr/bin/apt-get update`, `/usr/bin/apt-get install -y --no-install-recommends gnome-keyring dbus-user-session`, `/usr/bin/loginctl enable-linger nerve`, so that nerve keeps a session after a reboot, and a login keyring for nerve that opens without a password.
Where this machine's /etc/environment names another user's runtime folder or XDG folders (as a CI runner's does), keyring and bus of nerve would start in those; then nerve-node also writes /etc/systemd/user-environment-generators/99-nerve-session, which gives nerve's session its own at every start.
Without a desktop nobody types a password when the machine starts, so this keyring keeps the keys unencrypted in /var/lib/nerve/.local/share/keyrings, readable by nerve as the key files are; the node keeps centers out of it as it does out of the key files, except a command you let a center run outside folder mode that asks the keyring itself (secret-tool and the like). It becomes the default keyring of nerve: any other program of nerve that keeps a secret in the system keyring keeps it there, unencrypted too.
Install it now? [y/N]
```

Enter or `n` installs nothing, and the keys stay in their files (or the node
keeps refusing, when the settings say `keyring`). `y` installs GNOME Keyring
and what it needs (nothing it only recommends) with the system's package
manager (apt, dnf or pacman), keeps a session for the node's user from boot
on, makes a login keyring for it without a password, and checks that it
answers. If this machine's `/etc/environment` names another user's runtime
folder, bus or XDG folders (a CI runner's does), the session of the node's user
would start GNOME Keyring in those: for the installed node's user `nerve`, setup sets them right and writes
`/etc/systemd/user-environment-generators/99-nerve-session`, which keeps them
right at every start of that session (`uninstall` removes it), and the installed node
sets them right again when it starts. A node you run yourself, as your own user,
leaves your session and your XDG folders alone. These steps run as root: the programs from the system's own
folders, by their full path, with a fixed environment, in `/`, and without
your input. `install` asks the same when an earlier install's settings say
`keyring` and it runs in a terminal.

The question comes only when you run setup at a terminal. Answers piped
into setup, or a setup without a terminal, get the refusal and install
nothing, whatever they say; so does input that ends before the answer.

Setup offers this only where the user has no desktop session. On a desktop,
start the desktop's keyring instead (GNOME Keyring, or KWallet with its
Secret Service on).

A node that runs and found no keyring before does not look for one again
until it restarts. After installing one, `sudo nerve-node setup` restarts
the installed node. `nerve-node setup` without sudo runs inside the node, so
it stops and asks you to run `nerve-node service restart`, then setup again;
for a node you run yourself, it asks you to restart it, then to run setup
again.

Such a keyring survives a reboot, but as the question says, it keeps the
keys unencrypted on disk, as safe as the files. Whether a server should
keep its keys there is your call; the default stays `file`.

## When a change applies

While `nerve-node run` is running, a change applies at once. Without a running
node, the command says:

```
the change is in node.toml; it takes effect at the next start of the node
```

On Windows a running node takes `folder add`, `folder set` and `folder rm`
at once ([the control pipe](platforms.md#the-control-pipe)); every other
change it takes at its next start.
