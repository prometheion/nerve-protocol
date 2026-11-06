# Settings and config

The node has one config file and one way to change it. Details:
[spec/node-local.md](spec/node-local.md) §1, §2, §5 and §6.

## One file, one store

- The node's config is `node.toml` in the config folder. It is the same
  structure as the settings document a center reads, minus the client-only
  items below. There is no second format.
- The center has no config file. Its settings are flags and variables, plus the
  web UI's settings stored in `state.json`.
- Every writer goes through the same settings store: the CLI, and a center with
  the settings grant (through the `settings` capability). No component writes
  the file on its own.
- A write takes the whole document and its `version`. A stale version is
  `conflict`. The store validates the document against the config rules, writes
  the file atomically, applies it at once and audits each changed setting with
  its old and new value and who changed it.
- While the daemon runs, the CLI changes settings through the control socket.
  Without a daemon, the CLI uses the same store on the file.
- The daemon keeps the config in memory. It reads the file at start-up and when
  the owner asks (`SIGHUP`, or `reload` on the socket). It never rereads it on
  a timer.

## The format of stored files

The files the node and the center keep for themselves carry a `format`:
`node.toml`, `acl.json` and (on Windows) `grants.json` of the node,
`state.json` of the center. It counts the changes an earlier version cannot
read; every file is at format 1 now, and a file without it reads as format 1.

- A file with a higher format is refused, with the format and that a newer
  version wrote it: reading it could drop what that version keeps. The node or
  the center does not start, or the command stops, and the file stays as it is.
- Unknown fields are refused in all four files, so a field of a newer version
  is never dropped at the next save.
- `format` is not the `version` of `node.toml`. That one counts saves, for
  `if_version` and for `config.version`.
- Backups carry a format of their own ([backup](backup.md)).

## The signature

Every file the node writes starts with `# mac hmac-sha256 <hex> …`, an HMAC
over the rest. The key is `config.key` in the state folder (mode 0600), or an
entry in the system keyring with `machine.secret_storage = "keyring"`
([spec §1](spec/node-local.md#where-the-keys-are)). It is
not beside `node.toml`, so whatever can read the config folder does not hold
the key.

A file with a missing or wrong MAC was changed outside the owner's path. The
node refuses it and audits that:

- At start-up the node does not start.
- On a reload the old config stays.

The owner looks at the file, then runs `nerve-node config accept`. The node
signs it. A file without a MAC line (and no key) is taken
once and signed.

A file the node signed earlier passes the MAC, so the MAC alone does not stop
someone who can write the config folder from putting an older one back. The
node keeps the highest version it has saved or taken in `config.version` in
the state folder, and refuses a signed file below it the same way: at
start-up it does not start, on a reload (which also refuses a file below the
one in force) the old config stays. `config accept` takes such a file under a
new version above every one before. Details:
[spec §1](spec/node-local.md#who-writes-nodetoml).

The check holds while `config.key` and `config.version` do. A process that can
read or delete the key can make the node take another file at its next start.
A `user` mode command is such a process, because it runs as the user without a
sandbox. In `folder` mode, Landlock keeps commands out of the state folder.

## Client-only items

A center never changes these, grant or not. They are not in any document a
center reads, or the node refuses the whole change and names the field.

1. Pairing and unpairing, the node keys, the list of centers.
2. The settings grant itself.
3. `panic` and `unlock`. A center with the grant may pause. Only the owner
   unpauses or unlocks.
4. Machine settings: `machine.shell`, `machine.allow_root`,
   `machine.sudo_path`, `machine.secret_storage`, `machine.user` (Windows),
   `machine.command_env` (the installed Linux node: the variables of the
   service's environment a command of `nerve-run` gets besides `PATH`,
   `LANG` and `TERM`; its `HOME` and `TMPDIR` are its pairing's own). An owner may set `machine.command_env`
   (it is not in `owner::ROOT_ONLY`): a command as the owner gets the whole
   service environment already, so naming a variable gives `nerve-run`'s
   commands nothing the owner could not read.
5. The sudo password. The node never returns it. A center only passes it on,
   sealed, when it switches sudo on.
6. The proxy and its credentials, and the relay for other nodes with its
   tokens.
7. The local audit log.
8. Releasing a protected path: a center may add to `protected.extra`, not
   remove from it or change `protected.allow`, and its folders may not widen
   access at a protected place ([policy engine](policy-engine.md#protected-paths)).
9. Turning a `sense` or `actuate` action on, by `caps` or an allow rule, or
   by taking away an `off` or `hidden` entry or a deny rule that keeps it off;
   and doing so for a capability no attached provider offers now, or for an
   action an offered capability does not have now, which may sense or actuate
   once it comes. A center can switch these off, never on, so it cannot take
   away its own deny rule for such a capability either.
10. The programs that may attach as capability providers,
    `providers.allowed` ([node-local §7](spec/node-local.md#7-capability-providers)).
11. The owner's own capabilities, `[[capability]]` (`cap add`, `edit`, `rm`;
    [node-local §2](spec/node-local.md#capabilities-of-the-config)): each runs a
    fixed command as `nerve-run`, so none is in a center's
    document. A center with the grant may switch them by `caps` and its rules
    like any capability, within item 9.
12. Another center's capabilities, and limits on a center's own
    (`[[center.capability]]`, through `settings.cap-add`, `cap-edit` and
    `cap-rm`, not the document; [node-local §2](spec/node-local.md#capabilities-a-center-adds)):
    they always run as `nerve-run` (no account field), count as `execute`
    whatever they declare unless they sense or actuate (item 9 then holds
    for them), never take the name of a capability of the owner's or of an
    attached provider, and an `off` or `hidden` switch of one of them stays
    until the owner changes it, whoever set it, also after the center removes
    and adds it again. The center turns on or allows each of its actions by
    its `cap.action` only, an attached provider's capability of a `cap` it
    added under is not offered to it, and a removal drops its `on` and allow
    rules for that action unless the owner declares that action too; its
    sensing ones keep their `cap` owner-only whatever else offers it
    (nerve-node `config_cap`). The store checks the write
    grant and audits each change as the center's (`Writer::Center`).
13. The pairing's `policy.no_network` (every mode, #167) once it is on: a
    center cannot clear it (`settings::client_only`). It may change
    `policy.mode` and `policy.until` meanwhile, as no mode sheds the switch.
15. Adding to the pairing's `policy.sudo_allow` (#197): its commands run as
    root in every mode while the machine's sudo switch is on, and for a
    `nerve-run` pairing the node starts them as root itself, so a center that
    could add one would have root and the node's keys. A center may take an
    entry off (`policy.sudo_allow <glob>: only the owner puts a command on the
    sudo list`). The center's Audit page has no sudo button: for a sudo
    command it shows `nerve-node rule add allow --action exec.run --exact
    '<command>'` (Linux; `--exact` keeps a trailing `*` the command's own,
    and a command with a quote, a backslash or a line break gets no line to
    copy, the row names the form to type instead) or the app's Permissions, Sudo (Windows).
14. The node's web UI, `[ui]`: its address, its certificate's pin and its
    tokens. It is in no center's document, and a command the web UI runs for
    the owner may not change it either, only revoke a token
    ([web UIs](web-uis.md#the-nodes-web-ui)).

One item is in the document a center reads and is still the owner's: the
record of the folders' real places, `policy.places`
([policy engine](policy-engine.md#protected-paths)). The node does not refuse
a write that differs there; it keeps the record as it was. The center adds no
entry and changes none, and an entry goes only with its folder.

Because the grant lets a center widen its rules up to `user` mode, a center
with the grant is as strong as `user` mode on that machine, never more: the
sudo list is the owner's (item 15): `client_only` refuses an entry a center adds,
and, while the list has an entry, a deny rule of scope `exec` or `exec.*` it
takes off, since that rule narrows a wildcard entry. Entries of a 0.0.7
center stay (no migrations): `rule --center <name>` lists them. `as_owner` goes with `allowlist` mode
alone: `CenterPolicy::validate` drops it under any other mode, so a timed
mode a center saves never ends in `allowlist` as the owner.

## The node's own folders

On Linux the config and state folders are the node's own. No call of a center
reaches them, whatever its rules, folders or released paths say. A confined
command's Landlock rules leave them out, even when a granted folder holds them.

## Control socket

`<state>/run/ctl.sock`, in a 0700 folder, mode 0600. Only its own user or root
may talk to it, and only a request that carries the token the node wrote to
`<state>/run/ctl.token` at its start: the CLI reads it, a `folder` mode command
cannot, as the state folder is out of its rules. A request without the token
is refused, whatever its method. The token is as
safe as the sandbox: while the commands run as the node's own user (a node a
person runs), any other program of that user that runs commands on request
over a socket (the user's systemd session, a tmux or screen server) runs them
outside it, and reads the token too. The installed Linux node keeps that out
by its accounts: no command runs as `nerve`, which owns the socket and the
token, but as `nerve-run` or the owner ([the accounts commands run
as](sandbox-linux.md#the-accounts-commands-run-as)). A
[sudo](policy-engine.md) command is root and is not kept out.
It is the node's
only way in besides its center links. The client sends one JSON object per line,
`{"method", "params", "token"}`, and gets `{"ok": value}` or
`{"error": "text"}`. A streaming method answers with several `{"item": value}`
lines. Every connection carries one request, except a provider's, which stays
after `hello` and carries its calls.

| Method | Does |
|---|---|
| `status` | Daemon and links |
| `config.read` | Read `node.toml` and its `version` |
| `config.write` | Replace it when `if_version` matches |
| `config.accept` | Take a refused `node.toml` as it is (an action that came to sense or actuate in it held in the same write) |
| `reload` | Reread `node.toml` (only a file the node signed) |
| `sudo.status`, `sudo.on`, `sudo.off` | The sudo switch |
| `folder.add` | `folder add`, judged by the node as the owner; it stores and records the real place |
| `folder.grants` | Brings the folders' ACL entries for `nerve-run` in line with the config, and says what that left; with `every` (`folder add` of a listed folder, `folder sync`) every grant is walked |
| `caps.list` | What `cap` shows: every action, its source, and each center's access |
| `center.rotate-key` | `center rotate-key`: a new key for one center, sent over the link; it waits for the center's answer |
| `owner.check` | Nothing; the CLI asks it before `install`, `setup`, `update`, `uninstall`, `backup` and `restore` |
| `hello` | A capability provider attaches; its connection stays ([node-local §7](spec/node-local.md#7-capability-providers)) |

Every method is refused from a process that runs below a command the node
started for a center, the reading ones too. That catches the processes that
stay below the command: one that leaves the tree (`( … & )`, `setsid -f`)
is not caught, so for a command without a sandbox the socket is no boundary,
as the node's files are none. For a `folder` mode command the token also
holds, as far as the sandbox does.

Windows has no control socket. It has a control pipe with the same lines,
which serves `status`, `caps.list`, `center.rotate-key`, `folder.add` and
`folder.rm` only
([node-local.md §5](spec/node-local.md#5-control-socket)). For every other
change the CLI signs `node.toml` itself, and the change applies at the next
start.

## The owner's way in

The installed node has one owner besides root: on Linux the account that ran
`install` (through `sudo` or `pkexec`), which the unit names
(`Environment=NERVE_NODE_OWNER=<name>`, `service::owner_in_unit`; only
`install` writes it, everyone may read it, so the CLI and the app tell
whether they are the owner while the node is stopped too); on Windows the
SIDs in the service's registry value `Parameters\Owners`. `uninstall`
removes the polkit files and the service helper, and on Windows the service
with its key.

The running node serves the owner a second endpoint (`crate::owner`), and
on Linux a third, the provider socket `/run/nerve-node/provider.sock` beside
it, where the owner's and root's programs attach as capability providers
(node-local.md §7). The second endpoint: on
Linux `/run/nerve-node/owner.sock`, mode 0666 in the unit's
`RuntimeDirectory=` (0755), the account decided by the peer's credentials
(the unit's owner, looked up by name at each request, and root); on Windows
the pipe `\\.\pipe\nerve-node-owner`, whose DACL names SYSTEM, the
administrators and the owners, read at the node's start. It takes `status`
(anyone: `{"running": true}`) and `cli {args, cwd}`: the node refuses anyone
who is not the owner (`nerve-run` among them), a caller below a command it
runs, one with `no_new_privs` (Linux; every confined command keeps it) or in
a command's job (Windows), the commands that stay root's (`run`, `install`,
`update`, `uninstall`, `service`, `sudo on`, and on Windows `setup`), and a `backup` or
`restore` without the file the caller opened itself. The checks of the
caller's process read `/proc/<pid>` of the process that connected, which may
be gone by the time the request comes, so they catch mistakes, no more. Then
it runs its own program with `--config-dir`, `--state-dir` and those
arguments as its own user, with `NERVE_OWNER=<name>`, and passes the caller's
input and the program's output and exit code through the connection
(`{"in"}`/`{"eof"}` up, `{"out"}`, `{"err"}`, `{"exit"}` down). The program
is the CLI after `become_owner`: its changes go through the store as any,
and with `NERVE_OWNER` set it refuses a change of `machine.user`,
`machine.allow_root`, `machine.sudo_path` or `machine.shell`, and names the
owner in the audit (`"user"` beside `"by": "local"`). The node's log has a
line at info for each owner's command that can change something (its words,
and for `config` the setting's name, never a value); the reads (`status`,
`audit`, `log`, the `ls` and `get` commands), which the desktop app makes
every few seconds, are at debug. The CLI forwards there by itself when the
node is installed and it may not open its folders.

The owner's commands are as safe as the owner's account. A center's command
of `user` mode (or `allowlist` mode with `as_owner`) runs as the owner
without a sandbox and is the owner, as is one that gets a process started
outside the node's tree (`systemd-run --user`, tmux). That is the owner's
choice of mode, documented and not enforced (the guard's deny rules and the
center's checker catch mistakes only). A command of `nerve-run` is not the
owner: the endpoint refuses it by its uid, and the owner's session programs
take no requests from it.

## Folders for `nerve-run`

On the installed Linux node, `crate::acl` gives `nerve-run` the folders of
every pairing as POSIX ACL entries, written as the kernel keeps them
(`system.posix_acl_access`, `system.posix_acl_default`), acting with the
owner's file system ids (`account::FsAs`), so only the owner's files change.
What it gave is in `acl.json` in the state folder; it syncs at the start, on
each config version, and before each `nerve-run` call, walking only grants
that are new, changed or gone. The user guide has the rules
([modes](sandbox-linux.md#the-account-nerve-run)).

## The log level

`log.level` (`error`, `warn`, `info`, `debug`; `info` unless set) is a machine
setting of the owner: it is not in the document a center reads or writes. The
daemon applies it within a second of any change ([logging](logging.md)).

## The audit log

`audit.jsonl` in the state folder holds one JSON line per event: settings
changes, calls allowed or forbidden, and what happened to the config file. It
holds targets, never file contents or output. See
[the user guide](logging.md) for sizes and rotation. It is not the log: [logging](logging.md).

## Settings, as the owner changes them

Every setting of a node is in one file, `node.toml`, in the node's config
folder ([where](#where-files-live)). The commands in this guide
change it for you. `nerve-node config` reaches any setting by its name.

### Read and change by name

A name is a dotted path. A center's settings are under `center.<name>`, where
`<name>` is the name from `nerve-node center`.

```sh
nerve-node config get center.lab.policy.mode
nerve-node config set center.lab.policy.mode folder
nerve-node config add center.lab.policy.allow 'fs.read:~/notes/*'
nerve-node config rm center.lab.policy.allow 'fs.read:~/notes/*'
nerve-node config unset limits.max_running
nerve-node config get center.lab          # a whole table
```

| Command | Does |
|---|---|
| `config get <key>` | Print one setting or a table |
| `config set <key> <value>` | Change a setting |
| `config unset <key>` | Remove it, so its default applies |
| `config add <key> <value>` | Append to a list |
| `config rm <key> <value>` | Remove a value from a list |
| `config accept` | Take a file you edited by hand |

A value that does not fit the setting is refused, and nothing changes.

### The settings

```toml
[node]
name = "laptop"             # shown to centers; the host name by default

[machine]
shell = "/bin/bash"         # runs commands; the platform shell by default
allow_root = false          # let a node run by hand run as root (Linux)
sudo_path = "/usr/bin/sudo" # optional
user = "alice"              # installed node on Windows: the account commands and sudo run as
secret_storage = "file"     # file | keyring: where the node keeps its keys
command_env = ["HTTPS_PROXY"] # installed Linux node: variables of the service nerve-run's commands get too

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
max_links = 12              # optional, `relay set`: its own tunnels at once
max_opens_per_minute = 300  # optional, `relay set`: its own opens a minute

[ui]                        # the node's web UI, set with `nerve-node ui`; off without listen
listen = "127.0.0.1:7470"
pin = "…"                   # beyond loopback: the pin of its own certificate

[[ui.token]]                # added by `nerve-node ui token add`
label = "laptop"
token_sha256 = "…"          # the hash of its token; the token is in no file
made = "2026-11-02T10:00:00Z"

[log]
level = "info"              # error | warn | info | debug: how much the node logs

[providers]                 # programs that may add capabilities (providers.md)
allowed = [{ name = "desk", exe = "/usr/lib/nerve-desktop/nerve-desktop" }]

[[capability]]              # one of yours, added by `nerve-node cap add` (config-capabilities.md)
name = "sensors.read"       # cap.action
summary = "Temperatures of this machine."
effect = "sense"            # read | write | execute | sense | actuate
command = ["sensors", "-j"] # the program and its arguments; {field} takes a call's argument
params = '{"type": "object", "properties": {}}'  # optional: its arguments' JSON Schema, as text
result = '{"type": "object"}'                    # text (the default), or a JSON Schema as text
timeout_secs = 10           # optional, up to max_timeout_secs
platform = "linux"          # any (the default) | linux | windows

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

[[center.capability]]       # one this center added itself (config-capabilities.md)
name = "say.back"           # the same keys as [[capability]]
effect = "read"
command = ["echo", "{word}"]
```

The file also holds its `format` (1; a newer version's file is refused, see
[settings and config](settings-and-config.md#the-format-of-stored-files)),
a `version` that grows with every write, `locked`
(set by `panic`), and per center the `url`, `pin`, `center_id` and `node_id`
the pairing filled in, and the capabilities that center added with the
settings grant (`[[center.capability]]`; `cap` lists them, `cap rm NAME
--center NAME` removes one). Unknown keys are refused. `places` is the node's
record of the folders `folder add` stored ([modes](sandbox-linux.md#a-folder-keeps-the-place-you-added)).

### How long a command may run

Every command ends. The agent can give a call a `timeout_ms`; without one the
command gets `limits.default_timeout_secs`, 10 minutes. A `timeout_ms` above
`limits.max_timeout_secs`, 1 hour, is cut to it, and so is the default when you
set the maximum below it. A command past its limit is killed with everything it
started ([what ends a command](sandbox-linux.md#what-ends-a-command)), and the call
fails with `timeout`; the message says which limit it was, and whether a
larger `timeout_ms` would help.

```sh
nerve-node config set limits.max_timeout_secs 86400    # a command may run a day
nerve-node config set limits.default_timeout_secs 1800 # and gets half an hour unless it asks
```

Both are yours alone: a center, also with the [settings grant](#the-settings-grant),
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
([long calls](mcp-surface.md#long-calls-become-jobs-1)).

### Do not edit the file by hand

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
([service](sandbox-linux.md#the-accounts-commands-run-as)) and cannot reach it,
except where [root is the owner](service.md#root-as-the-owner): there `user`
mode commands run as root.

#### An older file put back

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

### Where the node keeps its keys

The node has a key per center and the key for the MAC above.
`machine.secret_storage` says where they are:

- `file` (the default): files only the node's user can read, `keys/` in the
  config folder and `config.key` in the state folder.
- `keyring`: the system keyring, the Credential Manager on Windows and the
  Secret Service (GNOME Keyring, KWallet) on Linux. No copy stays in a file.
  Not on the node installed as a service on Windows: it runs as `nerve`,
  whose Credential Manager the commands you run as an administrator cannot
  reach, so it keeps its keys in files
  ([service](windows.md#the-node-as-a-service-on-windows)).

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
the command where the node runs it without a cgroup ([limits](sandbox-linux.md#limits-per-command)),
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
([rules](policy-engine.md#deny-a-command)): a rule for a keyring client is the same
kind of rule as one for a shell script that reads your files. Confining
`allowlist` commands for the keyring's sake would also stop programs a rule
is there to run when they need your session (`ssh` with its agent, `git` with a
credential helper), and it would still leave an allowed interpreter free to
read what you read. Look at what you allow with `nerve-node rule allow`.

With `keyring`, the node needs a keyring that answers. Without one it does
not start, and `status` and the other commands that read the settings say:

```
machine.secret_storage is "keyring", but the system keyring cannot be reached (entry …): …
```

The node never falls back to the files. Start the keyring, or on a Linux
without a desktop, `nerve-node config set machine.secret_storage keyring`
offers to install one.

#### A keyring on a Linux without a desktop

A server without a desktop usually has no keyring. When you set
`nerve-node config set machine.secret_storage keyring` (on the installed node
too, without `sudo`), or the settings already say `keyring` and `nerve-node
setup` finds no keyring answering, it asks:

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

### When a change applies

While `nerve-node run` is running, a change applies at once. Without a running
node, the command says:

```
the change is in node.toml; it takes effect at the next start of the node
```

On Windows a running node takes `folder add` and `folder rm`
at once ([the control pipe](windows.md#the-control-pipe)); every other
change it takes at its next start.

## The settings grant

A center cannot change anything on a machine at first (`settings off`). The
settings grant lets it. Only you can give it, on the machine.

```sh
nerve-node center settings on
nerve-node center settings off      # take it back
nerve-node center                      # shows "settings write" or "settings off"
```

With several centers, add `--center <name>`.

Every center, with the grant or without, is told its own pairing's mode,
until when it holds, the account its commands run as and, in `folder` mode,
its folders (a folder you closed inside one is not named, only that some
folder below is closed) and whether it may read, outside the folders, what
every account on the machine may read:
the agent needs them to know where it may work
([modes](policy-engine.md#what-each-mode-allows)). It is never told another center's.

### What a center with the grant can do

- Change its own pairing's policy, and read the rest of it: mode (up to
  `user`), folders, rules, capability switches.
- Add allow and deny rules with the web UI's Audit buttons (not to the sudo list).
- Edit the machine's settings as JSON in the web UI, Settings.
- Pause the node's link.
- Turn the [sudo switch](policy-engine.md#sudo-as-the-owner-uses-it) on and off.
- Add, change and remove [capabilities of its own](capabilities.md#capabilities-a-center-adds),
  in the web UI's Capabilities page: fixed commands that run as `nerve-run`,
  count as `execute`, and are offered to it alone. One that senses or acts
  waits for your `on`.

Each change is checked, then saved. A change is audited on the machine with the
old and the new value and the name of the center.

A center with the grant can widen its own rights up to `user` mode. A center
that is taken over is then as strong as `user` mode on that machine. Give the
grant only to a center you would also give a shell.

Where root is the node's owner ([service](service.md#root-as-the-owner)),
`user` mode runs commands as root. A center with the grant can switch itself
to it, and so run commands as root, with no password asked. On such a node
the grant gives the center root: `center settings on` warns of it,
and so does the desktop app when you give the grant. Its Windows twin is an
owner (`machine.user`) in Administrators or Backup Operators
(`owner::admin_owner`): user mode's commands run as that account and can take
its rights, as UAC is no security boundary. `center settings on` and the app
warn of that too, and `status` (`owner_is_admin`) and the app's Overview say
it.

### What stays with you

No grant lets a center change:

- pairing and unpairing, the node's keys, the list of centers
- the grant itself
- `panic` and `unlock`, or an unpause (you resume with `center resume`)
- machine settings: the shell, `allow_root`, the sudo path, the account commands run as, where the keys are, the log level
- the proxy and its secrets
- another center's pairing
- the sudo password. A center only passes it on, sealed
- the sudo list: a center may take a command off it, never put one on it
- the release of a [protected path](policy-engine.md#protected-paths-as-the-owner-sees-them). A center may add paths
  to protect, never remove one, and its folders cannot open a protected place
  that yours do not
- the network of its commands once you turned it off
  ([no network](sandbox-linux.md#no-network-for-a-centers-commands)): a center may
  turn its own off, never on again; it may change its mode meanwhile, as the
  switch holds in every mode, but while it is off it can give itself no new
  folder to write, as a socket in a folder it may write is one its commands
  can reach
- the audit log
- the programs that may add capabilities ([providers](capabilities.md#capability-providers-in-use))
- turning on a [program's capability](capabilities.md#capability-providers-in-use) or a
  [capability of your `node.toml`](capabilities.md#capabilities-of-your-own-in-nodetoml) that senses (a
  camera, a microphone) or acts on the world (a lamp, a lock): an allow rule
  or an `on` switch for it, and taking away an `off` or `hidden` switch or a
  deny rule that keeps it off. The same holds for a capability no program
  offers now, or an action an offered one lacks, as the machine cannot tell
  yet what it does; a capability of `node.toml` with an action that senses or
  acts counts whether this machine offers that action now or not
- adding, changing or removing a capability of `node.toml`, or one another
  center added
- turning on again a capability it added that you, or it, turned off or
  hid, also after it removes that capability and adds it again; you turn it
  off with `cap set NAME off --center <name>` and remove it with `cap rm NAME
  --center <name>`. The `off` holds for that name only: the center may add
  the same command under another name, so to stop it from adding commands,
  take the grant back
- turning on or allowing a capability it added as a whole: it switches each
  of its actions by its full name, as a program you allow may offer more
  under that capability's name later

A change that touches one of these is refused as a whole, and the refusal names
the field.

One more field is yours, and a change to it is not refused but dropped: the
node's record of the folders it recorded at their real place (`places` in the
policy, see [modes](sandbox-linux.md#a-folder-keeps-the-place-you-added)). The
settings document shows it, and a center that saves the document with another
value there changes nothing; an entry goes only with its folder.

### Without the grant

Everything is still possible on the machine, with [`nerve-node`](../user/commands.md).
The web UI shows such a machine as keeping its settings to itself, its Audit
buttons stay off, and its Capabilities page is read only. Taking the grant back
changes only the grant: what a center set while it had it stays in force. That
is its mode, `as_owner`, folders (the `r` and `x` ones it added, and the `w`
ones it added while its network was on; `network off` does not remove them),
rules, the sudo entries it kept, capability switches and the capabilities it
added, which stay offered to it until you remove them. `center settings off`
says so and names the command that shows each: `mode`, `rule` (rules and the
sudo list), `folder` and `cap`, each with `--center <name>`; the app's toast
names its Permissions and Capabilities pages. Where a timer ends in
`allowlist` as the owner, `mode` and `status` say ", as you" for it before
it ends.

## Where files live

| What | Linux | Windows | Change with |
|---|---|---|---|
| Node: `node.toml`, one key per center | `~/.config/nerve` | `C:\ProgramData\Nerve\config` | `--config-dir`, `NERVE_NODE_CONFIG_DIR` |
| Node: audit log, [log](logging.md#the-log-as-the-owner-reads-it), control socket and its token (Linux), config key, the last version of `node.toml`, the record of the folder grants (Windows) | `~/.local/state/nerve` | `C:\ProgramData\Nerve\state` | `--state-dir`, `NERVE_NODE_STATE_DIR` |
| Center: identity, paired machines, statistics, [log](logging.md#the-log-as-the-owner-reads-it), the [action checker](action-checker.md#the-checker-as-the-owner-sets-it-up)'s settings and local model | `$XDG_STATE_HOME/nerve-center`, else `~/.local/state/nerve-center` | `%LOCALAPPDATA%\nerve-center` | `--state-dir`, `NERVE_CENTER_STATE_DIR` |

A node [installed as a service](service.md#the-node-as-a-service) keeps its files in `/etc/nerve`
and `/var/lib/nerve/state`; without `--config-dir` and `--state-dir` the
commands use those folders. On Windows the node is always the installed
service, with its files in `C:\ProgramData\Nerve\config` and
`C:\ProgramData\Nerve\state`; the app works on those folders unless
`NERVE_NODE_CONFIG_DIR` or `NERVE_NODE_STATE_DIR` is set for the account, which points it
at other folders and so away from the service. A center installed as a service keeps its state
in `/var/lib/nerve-center` and its settings in `/etc/nerve-center`
([center](service.md#the-center-as-a-service)).

The node reads `NERVE_NODE_*` variables, the center `NERVE_CENTER_*`. A program
does not start while an old name (`NERVE_STATE_DIR`, `NERVE_HARNESS_TOKEN`, …)
is set, and says what to rename.

The node keeps its own folders closed. No center can read them, whatever the
rules say.

## CLI output (`--json`)

A program that drives `nerve-node`, such as a script, adds `--json` and reads
one JSON value from stdout. Fields are only ever added: one is renamed or
removed only with a change of the format, which the changelog names under
"Breaks". A script ignores the fields it does not know.

- The read commands print their data: `status`, `center`, `mode`, `network`
  (`{"networks": [{"center", "no_network"}]}`), `folder`,
  `rule` (the lists, and `stale`: each rule whose arguments the action no
  longer takes, with why), `cap` (`capabilities`, one row per action, state key,
  event or stream with `"kind"` on all but actions, an action's arguments
  schema as `"params"`, `programs`, `config`, each capability
  of `node.toml` as declared, its schemas as JSON, `running`, and for one
  center, with `--center` or where only one is paired, `center`, `caps` and
  `known`, what `cap set` switches), `provider`, `config get`,
  `proxy`, `relay`, `sudo`, and `audit` and `log`
  (`{"entries": [...]}`, the lines as the file holds them; with `--follow`
  one a line). `status` has `"daemon"`:
  `"running"`, with what the running node says, or `"not running"`.
  It names the installed node's `"owner"` and `"owner_is_root"` (root is the
  owner, so `user` mode runs as root), each center's `"account"` (the
  account its commands run as now, `null` on a node run by hand),
  `"as_owner"`, `"no_network"` (its commands have no network),
  `"network_off"` (`"held"`, `"as_owner"` or `"not_held"` while it is on:
  whether the node holds them to it, or runs none, and why) and
  `"landlock"` (whether Landlock holds its commands now), `"network_rules"`
  (whether this machine can keep commands off the network),
  the running Linux node's `"folder_access"` (`"errors"`, `"stale"`,
  `"failed"`, `"skipped"`: what giving `nerve-run` its folders left; a failed
  grant is tried again; while `"stale"` names a folder, no command of
  `nerve-run` runs) and `"home_warning"` (on a kernel without Landlock,
  `{"home", "mode", "below", "warning"}` when `nerve-run` gets into the
  owner's home: `"mode"` when the home is open to other accounts, else
  `null`, `"below"` the folders given in it as you named them, the home
  itself where you give it whole; `null` with Landlock or where neither is
  so), and `"pairings_warning"` (on the installed Linux node without
  Landlock, once two or more pairings' commands run as `nerve-run`, or the
  config's capabilities, which run as it in every mode, are offered to them:
  that nothing keeps them apart; `null` otherwise, also for a node that does not
  run).
  `status`'s `"service"` has `"installed"`, `"state"` (`"running"`, `"stopped"`,
  `"starting"`, `"stopping"` or `"failed"`; `null` when not installed),
  `"enabled"` (it starts with the machine), `"program"` (where the program
  is installed), `"present"` (whether it is there) and `"version"`. It needs
  no root. `config get machine.secret_storage` also has `"keyring"`:
  `{"usable": true}`, or `"usable": false` with `"reason"`
  (`"windows-service"`, or `"no-answer"`: no keyring
  answers for the account the node runs as) and `"why"` in words.
- `center add` without `--yes` prints what you would confirm
  (`{"paired": false, "preview": {...}, "check": {...}}`) and pairs nothing;
  with `--yes` it pairs. `"check"` says whether pairing can work: `"ready"`,
  `"reach"` (`"ok"`, `"unreachable"` or `"certificate"`: not the pinned or a
  trusted one), `"code"` (`"open"`, `"used"`, `"gone"`, `"busy"` or
  `"unknown"`, or `null` when the center was not reached), `"problem"` in
  words when it cannot, and `"said"`, the line for people.
- Every other command prints the lines it shows as `{"messages": [...]}`,
  with `"next_start": true` when the node takes the change only at its next
  start (it does not run, or it is the installed node on Windows, which
  takes only folder changes while it runs); `center add --yes` says it the
  same way. `ui on` (with no token yet) and `ui token add` add `"token"`
  (`label`, `token`), `ui on` beyond loopback `"certificate"`
  (`fingerprint`, `made`); `ui` adds `"ui"` and `ui token`
  `"tokens"`. `relay add` and `relay token` add `"token"` (`node`, `token`,
  `address`, `link`, the `nerve://relay` link the other node pastes,
  `proxy`, the URL it sets with `proxy set`, and `pin`); `relay` has
  `"address"`, where a new link says the relay is,
  `backup` adds `"backup"` (`file`, `centers`, `saved`, and `left_out`, each
  with `what` and `why`: `keyring`, `does-not-fit` or `missing`),
  `center rotate-key` adds `"public_key"`, the new key,
  `folder add`, `folder rm` and `folder sync` on the installed Linux node add
  `"grant_errors"` (what giving `nerve-run` its folders left, each
  `<path>: <why>`) and `"grant_stale"` (folders whose access `nerve-run`
  keeps although it should have lost it) when there are any, and
  `restore` adds `"restored"` (`centers`, `kept`, `no_key`, and `notes`,
  each with `text` and, when it asks you to set something again, `fix`:
  `proxy`, `sudo`, `sudo-file`, `pin` with its `center`, or `relay`).
- An error is `{"error": "..."}`, and the exit code is 1. stderr carries the
  log's events, so read the error from stdout.

When stdin is no terminal, nothing waits for typing: a password (`sudo on`, the
account's on Windows) or a passphrase (`backup`, `restore`) is the first line
of stdin, or of the file `--passphrase-file` names. `proxy set
http://user@host:port` takes the proxy's password from the
first line of stdin, and `--header -` the headers from the lines after
it, one `Name: value` each, so neither shows in the process list. `cap add`
and `cap edit` with `--params -` or `--result -` take that schema as
all of stdin (one of the two per command). `setup` reads its answers
from stdin one line each. `center add` needs `--yes`.

## The center's settings, ports and files

The harness starts `nerve-center` itself, like any MCP server. Every setting is
a flag or an environment variable. The only subcommands are `backup` and
`restore`, which you run by hand ([backup](backup.md#back-up-restore-and-move-step-by-step)), `owner-token`
([web UI](web-uis.md#log-in)), and `install`, `update` and `uninstall`: on
Linux the center can also [run as a service](service.md#the-center-as-a-service) that
starts with the machine.

### Add it to the harness

```json
{
  "mcpServers": {
    "nerve": {
      "command": "nerve-center",
      "env": {
        "NERVE_CENTER_NAME": "lab"
      }
    }
  }
}
```

The center then listens on:

| Port | For | Flag |
|---|---|---|
| 7443 | nodes | `--listen` |
| 7480 | the [web UI](web-uis.md#the-centers-web-ui), on this machine only | `--ui` |

Open `http://127.0.0.1:7480` to [pair a machine](identity-and-pairing.md#pairing-as-the-owner-does-it). It asks for
the [owner token](web-uis.md#log-in), which the center made at its first
start and keeps in `~/.local/state/nerve-center/owner-token`:

```sh
cat ~/.local/state/nerve-center/owner-token
```

### The center's settings

| Flag | Variable | Default | Meaning |
|---|---|---|---|
| `--name` | `NERVE_CENTER_NAME` | `nerve-center` | Name shown to nodes and in the web UI |
| `--state-dir` | `NERVE_CENTER_STATE_DIR` | see [install](#where-files-live) | Identity, paired machines, statistics |
| `--listen` | `NERVE_CENTER_LISTEN` | `0.0.0.0:7443` | Where nodes connect |
| `--public-url` | `NERVE_CENTER_PUBLIC_URL` | `https://<host name>:<port>` | The address written into pairing links |
| `--plain-loopback` | `NERVE_CENTER_PLAIN_LOOPBACK` | off | Plain HTTP for nodes; only with a loopback `--listen` |
| `--ui` | `NERVE_CENTER_UI` | `127.0.0.1:7480` | Web UI address, or `off` |
| `--mcp` | `NERVE_CENTER_MCP` | `stdio` | `stdio`, `off`, `http` (HTTP MCP at `127.0.0.1:7481`) or the address of the HTTP MCP endpoint |
| `--harness-token` | `NERVE_CENTER_HARNESS_TOKEN` | none | A [harness token](mcp-surface.md#tokens) for the HTTP MCP endpoint; it does not log in to the web UI |
| `--call-wait` | `NERVE_CENTER_CALL_WAIT` | `20s` | How long a call may run before `execute` answers with a job instead ([long calls](mcp-surface.md#long-calls-become-jobs-1)): `20`, `20s` or `500ms`, 10 ms to 600 s. Keep it below the time your harness gives a tool call |
| `--log` | `NERVE_CENTER_LOG` | the level set in the web UI, `info` at first | `error`, `warn`, `info` or `debug`; wins over the stored level for this run. The [log](logging.md#the-log-as-the-owner-reads-it) goes to stderr and to `log.jsonl` |

`nerve-center --help` prints the same list.

Set `--public-url` when nodes reach the center under another name than its
host name, such as a DNS name or a forwarded port.

### TLS

Nodes connect over TLS. The center makes a self-signed certificate on its
first start. The pairing link carries the certificate's pin, so a node
trusts exactly that certificate.

The web UI and the HTTP MCP endpoint use plain HTTP on loopback. On any other
address they use TLS with the same certificate. `--plain-loopback` turns TLS
off for nodes too, but only for a loopback `--listen`.

### Connections

Each port of the center (nodes, web UI, HTTP MCP) takes at most 256
connections at once that are not settled yet: a request being read or
answered, a TLS handshake, a node's link before its signed hello, an HTTP
MCP request before its harness token is checked. Of those, one peer may
hold 16, and one IPv6 /64 64. A connection past that is closed at once, so
a peer that opens many and sends nothing keeps nobody else out. A node's
link counts no more once its hello is checked, so many nodes behind one
router link as usual, and a harness's call counts no more once its token is
checked. These numbers are fixed. A harness's request past its token check
is not undecided, so it counts against its token instead: 128 in flight at
most (until its reply has been read), more get `503`.

A peer is its address. On loopback every local program has the same one
(or any address of 127.0.0.0/8 it picks), so there a peer is the account
the connection comes from, which Linux names: another account on the
machine cannot fill your browser's places. Elsewhere, and where Linux cannot
name the account, all loopback connections count as one peer. This holds
for a port bound to every address (`0.0.0.0`, the nodes' default) too: the
peer is looked up by the address it connected to. Your own account is one
peer too: an agent running as you shares your places.

A pairing is only answered as done once the center has written it to
`state.json`. When it cannot (a full disk, a read-only state folder) the
node is told the center cannot write its state file, and the code stays
valid for another try.

### Run it without a harness

The default `--mcp stdio` ends when the harness closes its input. To keep a
center running on its own, pick another mode:

```sh
nerve-center --mcp http --harness-token "$TOKEN"   # MCP over HTTP
nerve-center --mcp off                             # nodes and web UI only
```

On Linux with systemd, let it [run as a service](service.md#the-center-as-a-service).

### One center per state folder

The first `nerve-center` on a state folder runs the center. A second one with
`--mcp stdio` finds it and attaches, so several harnesses on one machine share
one center, each with its own session. The first one keeps running until the
attached harnesses have ended too.

A second one with `--mcp http` or `--mcp off` refuses to start. On Windows a
second instance cannot attach and fails.

### Back the center up

`nerve-center backup <file>` writes `tls.pem` and `state.json` to one file
that a passphrase protects; `nerve-center restore <file>` puts them back, on
this machine or another. The nodes then find the same center by the same pin
and need not pair again ([backup](backup.md#back-up-restore-and-move-step-by-step)). The action checker's settings
come with `state.json`; its endpoint token and its local model do not.

### What the center keeps

In the state folder:

| File | Holds |
|---|---|
| `tls.pem` | The center's key and certificate |
| `tls.next.pem` | The new key, during the 7 days after a [key rotation](identity-and-pairing.md#rotate-the-centers-key) |
| `state.json` | Center id and name, paired machines with their public keys and last descriptions, hashed harness tokens, daily statistics, the settings of the [action checker](action-checker.md#the-checker-as-the-owner-sets-it-up) |
| `owner-token` | The [owner token](web-uis.md#log-in), which logs in to the web UI (mode 0600). Not in a backup |
| `log.jsonl` | The [log](logging.md#the-log-as-the-owner-reads-it): links, pairing, changes, refused and failed calls, the action checker's decisions, errors. `log.jsonl.1` is the older half |
| `checker-model.token` | The bearer token of the action checker's model endpoint, when you set one (mode 0600) |
| `checker-model.sock` | The socket the action checker's local model listens on while it runs (Linux) |
| `checker/` | The action checker's local model, when you installed it: the llama.cpp build and the model file, 1.1 or 3.0 GB |

It never stores file contents, command output or arguments. The secrets are
the owner token and the endpoint token, each in a file of its own and not in
a [backup](backup.md#the-center).
