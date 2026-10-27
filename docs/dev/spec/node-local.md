# The node's own side: config, policy, control socket

This part is not wire protocol: a center never sees it directly. It describes
how `nerve-node` decides, so that other node implementations can behave the
same way and so the owner knows what each setting does.

## 1. Folders

| What | Default | Override |
|---|---|---|
| `node.toml` and one key per center (`keys/<name>.key`), the relay's TLS key (`keys/relay-tls.pem`) and an `https://` proxy's password (`keys/proxy-login.secret`); on Windows also `sudo.dpapi` and, on the installed node, `command-account.dpapi` | `~/.config/nerve` | `--config-dir`, `NERVE_CONFIG_DIR` |
| control socket `run/ctl.sock` and its token `run/ctl.token`, audit log `audit.jsonl`, log `log.jsonl`, the config's MAC key `config.key`, the last version of the config `config.version`, `keys.lock`, `keys.moving`; on Windows the record of the folder grants `grants.json` and its lock `grants.json.lock` | `~/.local/state/nerve` | `--state-dir`, `NERVE_STATE_DIR` |

With `machine.secret_storage = "keyring"` the keys are in the system keyring
instead of `keys/` and `config.key` ([where the keys are](#where-the-keys-are)).

A node that `nerve-node install` put on a Linux machine
([service](../../user/service.md)) runs as the system user `nerve` with
`/etc/nerve` and `/var/lib/nerve/state`; without `--config-dir`,
`--state-dir` and their variables the CLI uses those two folders, and a
command root runs on them runs as their owner, so that what it writes stays
the node's.

On that node `nerve` only holds the config, keys and state; no command runs
as it. A command of `folder` mode, and of `allowlist` mode unless the
pairing's `as_owner` is set, runs as `nerve-run`; one of `user` mode, or of
`allowlist` mode with `as_owner`, runs as the owner, and so does a sudo
command of such a pairing. An allowed sudo command of a pairing whose
commands run as `nerve-run` runs as root, started by the node (§4).
`install` makes `nerve-run` (a system account with its own group and
no other, no login shell, home `/var/lib/nerve-run`, comment
`Nerve commands`) and takes the account that ran it (`SUDO_USER`,
`PKEXEC_UID`) as the owner, which it writes into the unit
(`Environment=NERVE_NODE_OWNER=<name>`); the node reads it from there. No
other account can be chosen. Run by root itself (no `SUDO_USER`, or
`SUDO_USER=root`), `install` makes root the owner only after a yes at a
terminal (default no; asked only where stdin and stdout are a terminal and
not with `--json`, else no at once, said on stderr) or with
`--owner=root --accept-root-owner`, and writes `NERVE_NODE_OWNER=root`. A
later install by root keeps a root owner without asking; `--owner=none`
leaves the node without an owner. Where an install changes the owner (or
`nerve-run`'s uid), it first stops the service and takes `nerve-run`'s
entries off every grant the ACL record names, as root (`acl::remove_all`, as
`uninstall`), after every step that can refuse, and the record goes; where
not all come off, the owner stays, the record marks every grant failed (so
the restarted node walks each again) and the service starts again where it
ran or was starting; a later failure starts it again too. `acl::sync` keeps
the grants of earlier accounts that did not come off in `Record::left`,
walks them at each sync and refuses `nerve-run`'s commands while one is
left; `remove_all` takes them off. Then what runs as the owner
runs as root (uid 0, root's groups, `HOME` root's, no `no_new_privs`, the
capabilities of root's exec), and the account check below is skipped for
it; `nerve-run`'s commands are unchanged. No other account with uid 0 is an
owner. A center cannot turn sudo on while root is the owner (`forbidden`):
`sudo -v` checks no password of root's. A command gets its account's ids and groups,
`HOME`, `USER` and `LOGNAME` set to it, and its home as the working
directory when the call names none; one of `nerve-run` also gets
`XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, `XDG_DATA_HOME` and `XDG_STATE_HOME`
below its home, `XDG_RUNTIME_DIR` and `DBUS_SESSION_BUS_ADDRESS` removed, and
git's `safe.directory = *` as command-line configuration (`GIT_CONFIG_COUNT`).
The `~` of folders, rules and the protected list is the owner's home. A
command of `nerve-run` is confined by Landlock in `allowlist` mode as well
(where the kernel has it), to its folders and the built-in `/tmp`,
`/var/tmp` and its home (§Modes), and gets its pairing's folders as POSIX
ACLs (§Folder ACLs). An account that is missing, `nerve-run` not made by
`install` (another comment), root (unless it is the owner) or `nerve` runs no command
(`unavailable`), after its call was decided and audited; without an owner,
no command that would run as the owner runs. Before a command starts, in
the child, the node checks with `access()` that the account can neither list
nor enter the config and state folders, and refuses to run it if it can.

For this the service keeps one privilege: `CAP_SETUID` and `CAP_SETGID`
(`AmbientCapabilities=` in the unit), and nothing else. It lets the
node run commands as `nerve-run` and the owner, accounts that cannot read
the node's keys, and give `nerve-run` its folders as the owner.
Every command the node starts drops every capability, ambient and
inheritable ones included, before exec; the bounding set is not narrowed,
since an allowed sudo command needs root's. The node signals a command of
another account from a child that takes that account's uid, since it has no
`CAP_KILL`; the child changes only its effective uid, so the account's
processes cannot signal it, and the node waits for it two seconds at most.
The `fs` actions of a center, and the path checks of every call (resolving
paths, the protected list, the folders), are done by the node itself, on
the calling thread under the account's file-system uid and gid and its
groups (the pairing's account; the protected list's entries are resolved as
the owner) (`setfsuid`, `setfsgid`, and `setgroups` as a plain system call, all
per thread on Linux); the audit entry is written as `nerve` again. So a
file the node makes for a center belongs to the account. The CLI, which
runs as `nerve` on the installed node, cannot judge a folder it may not look
into: with a node running, `folder add` is done by the node as the owner
(`folder.add`, §5); with none, the folder is kept in its normal form,
unresolved, and not recorded. A node not installed as a service runs every
command as its own user. The installed node is known by its folders or its
user, not by its capabilities: started without them (by hand, as `nerve`),
it runs no command at all.

`install`, `update` and `uninstall` run as root and write into folders
that belong to `nerve`: they write there as the folder's owner (the
thread's file-system ids), refuse a link in place of one of the node's
folders, and give the folders away by walking them through descriptors
opened without following links. A file with more than one name (a hard
link) is not given away: the walk stops there with an error, since its
other name may be outside the node's folders. A folder that belongs to
root already (`uninstall` without `--purge` gives the folders to root
before it writes its entry) is written as root, so the audit log there must
be a plain file with one name; a link or a hard link in its place is not
written to, and the command says so.

`node.toml` is written private to the owner (mode 0600 on Unix). The daemon
refuses to run as root, or in an elevated token on Windows, unless
`machine.allow_root = true`; when it runs that way, it logs a warning at
start (stderr and the node's log file, not the center) that commands then run
with full rights (on Unix unless it is the installed node, which runs them
as `nerve-run` or the owner; an
elevated administrator on Windows cannot start a command as another account,
so its commands keep the node's token), and the owner is responsible.

These two folders are the node's own. No call of a center reaches them, in
any mode and whatever the rules, folders or `protected.allow` say (§3), and
no Landlock rule of a command covers them (§Modes).

### Who writes `node.toml`

Only the owner's path changes the config: the CLI (through the control
socket while the daemon runs, §5, else on the file itself), and a center
through `settings.set` within its grant. The daemon keeps the config in
memory. It reads the file at start-up and when the owner asks for it
(`SIGHUP`, the socket's `reload`); nothing rereads it on a timer.

Every file the node writes is signed: its first line is
`# mac hmac-sha256 <hex> (…)`, an HMAC over the rest of the file. The key is
`<state>/config.key` (0600), made the first time the node opens its config,
or its keyring entry ([where the keys are](#where-the-keys-are)). It sits in
the state folder rather than beside `node.toml`, so whatever could read the
config folder would still not hold it.

A file whose MAC is missing or does not match was changed outside the
owner's path. It is refused and the refusal is audited (§6): at start-up the
node does not start; on a reload the old config stays in force. After looking
at a refused file, the owner takes it as it is with `nerve-node config
accept`; the node then signs it. A `node.toml` without a MAC line (no key
yet) is taken once as it is and signed.

An earlier file that the node signed itself passes the MAC, so the MAC does
not tell it from the last one. `<state>/config.version` does: the highest
`version` of `node.toml` the node has saved or taken, as a decimal number
(0600, no secret). It is written after every save of the file, never before,
and only goes up. A signed file whose version is below it was put back and is
refused like a changed one (audited, `refused`): at start-up the node does not
start, and the CLI's read-only commands refuse it; a reload also refuses a
signed file below the version in force, and the old config stays. The same
refusal is what the owner sees after a restore of the config folder from a
backup by hand. `nerve-node restore` ([backup](../backup.md)) is the owner's
way: it saves the restored config under a version above the record and the
file it replaces, so the record never goes down.

- `config accept` takes the refused file under a version above every one
  before it (the highest of the file, the config in force and the record, plus
  one), so the file taken is the newest, the record goes on from it, and an
  older copy is refused in turn.
- A node with no record (a state folder made new) takes the file as it is
  and records its version. With no `node.toml` and a record, the versions go
  on from the record, so the first file the node saves is not an older one.
- A record that holds no number is an error, not none: the node does not
  start, and the CLI's commands refuse, naming the file. `config accept`
  writes it again, or the owner deletes it.
- A save by the running node is numbered above the record as well as above
  the version in force. Another writer may have saved the file meanwhile and
  raised the record (the CLI on Windows, where a running node takes the file
  only at its next start; on Linux the CLI before the node's socket is up).
  The node's save replaces that file, as it always did, but it never lands
  below the record, so the node does not refuse its own file as an earlier
  one put back at its next start.
- A record that cannot be written after the file was saved changes nothing: it
  only lags, the audit log says `not_recorded`, and the next start records
  the version.

The check stands on `config.key` and `config.version`. A process that can
delete or read the key, and a `user` mode command is one (it runs unconfined
as the user), can make the node take another file at its next start: with the
key gone, an unsigned file counts as a first file and is signed (at a version
not below the record). The start-up audits that as `signed`. A process that
can write the state folder can delete or lower the record as well. In
`folder` mode Landlock keeps commands out of the state folder. What the record
adds is a defence against whoever can write the config folder alone: a
backup, a sync tool, a process of another account.

On Windows there is no control socket. A running node takes the folder
changes over its control pipe (§5); for every other change the CLI writes
the signed file itself, and a running node takes it at its next start. After
a change no daemon answered for, the CLI says so in one line ("takes effect
at the next start of the node").

### Where the keys are

`machine.secret_storage` says where the node keeps its own keys: the key of
the config's MAC, its key per center, the relay's TLS key (§2, Relay) and
the password of an `https://` proxy, the relay token of a relayed node (§2,
Proxy).

- `file`, the default: `<state>/config.key`, `<config>/keys/<name>.key`,
  `<config>/keys/relay-tls.pem` and `<config>/keys/proxy-login.secret`,
  each 0600.
- `keyring`: the system keyring (Credential Manager on Windows, the Secret
  Service on Linux), under the service `nerve`, one entry per key, named
  `config-key:<state folder>`, `center-key:<name>:<config folder>`,
  `relay-tls:<config folder>` and `proxy-login:<config folder>`. Each holds
  the key's text. No copy stays in a file.

While a rotation of the key for a center waits for the center's answer
(protocol §4.10), its new key is kept beside the old one, in
`<config>/keys/<name>.next.key` or the entry `center-key-next:<name>:<config
folder>`, and moves with the other keys. It replaces the key once the center
took it, and goes when the center refuses it or the pairing is removed.

The header values of a proxy, and the password of an `http://` one, are in
the keyring either way (§2), except on the installed node on Windows, which
takes none (§2, Proxy).

Two kinds of node keep their keys in files whatever is asked:

- The installed node on Windows (the service, which runs as `nerve`). The
  Credential Manager is one per account, and the CLI that writes the config
  there runs as an administrator, so a move into the keyring would put the
  keys in that administrator's Credential Manager, out of the service's
  reach. The node counts as installed on the folders `install` uses, in any
  spelling of their case, or when it runs as `nerve`.
- A Linux node whose kernel has a Landlock ABI below 9. Landlock there
  cannot keep a command off the session bus the keyring answers on (§1,
  the paragraphs on the session bus below), so with the keys in the keyring
  a `folder` mode command could not run programs from its folders: the
  sandbox cannot grant the keyring's access and execute together. This
  holds whatever account runs the commands. Only an ABI that is read
  counts: where Landlock is missing or off, so that its ABI cannot be read,
  the keyring is allowed (folder mode then runs no command anyway), and
  `setup` warns that it cannot tell.

On such a node:

- A change to `keyring` is refused before anything moves, by whatever
  writes the config (`config set`, setup, `config accept`); `node.toml` and
  the keys stay as they were. This refusal comes before the count of running
  commands below, as it holds whatever runs. A running node does not reload a
  file another writer saved with `keyring`.
- `config accept` refuses a file that says `keyring`, even when the keys are
  in the keyring already, so nothing would move.
- `setup` does not ask where the keys go. It prints a warning with the
  reason, and moves keys left in the keyring into files. On Linux it first
  checks that the keyring answers, and offers to install one as it does
  elsewhere, so that it can read the keys it moves; on the installed node on
  Windows it asks no keyring.
- `install`, and the node at its start, refuse a `node.toml` that says
  `keyring`. The message names the file and the command that moves the keys
  into files, with `--config-dir` and `--state-dir` of the folders it
  refused, so it works whether or not a service is registered yet. It is run
  as the account whose keyring holds them: on Windows the administrator
  that put them there, on Linux the node's user (sudo becomes it).

The node looks for the key that checks `node.toml` where that file says,
read before its MAC is checked. A file that names another place than the one
its key is in does not check, and is refused like any changed file.

With `keyring` and no keyring that answers, the node does not start, and a
command that reads the config refuses. The message names the entry and the
keyring's error. Nothing falls back to a file. On Linux the sudo password is
never at rest, whatever the setting; on Windows the node keeps it with DPAPI
in `sudo.dpapi` in the config folder, whatever the setting (§4).

A change of the setting moves the keys once, through the settings store, in
whatever writes the config (the running node, else the CLI):

1. `<state>/keys.moving` is written. It holds no secret.
2. Every key is copied to the new place and read back; a copy there that
   holds the same key already is left as it is. When a copy fails or reads
   back otherwise, the copies this move wrote are deleted, the failing one
   included, and the change is refused: `node.toml` stays as it was, and so
   do the keys.
3. `node.toml` is saved with the new setting.
4. Each old copy is deleted once the new place holds the same key, then
   `keys.moving` goes.

A running node holds `<state>/keys.lock` for its life. A CLI that writes
`node.toml` itself (no daemon answers: on Windows always, on Linux while a
node starts) moves the keys only while it holds that lock too. When a node
holds it, step 4 is left to that node's next start, and the running node goes
on reading its keys where they were. On Linux a move into the keyring is
refused then: that node goes on with the keys in files, so its `folder` mode
commands would get a sandbox for keys in files while they are in the keyring,
and the CLI does not see its count of such commands (below). At start-up, with `node.toml` checked
and the lock held, the node finishes a move by the config in force: a key
still in the other place moves into the configured one. That covers a move
`keys.moving` marks and one a crash stopped; with `keyring`, keys still in
files move in too. With `file` and no mark, the keyring is not asked. When
`node.toml` changed since the node read it, the move waits for the next
start. `config accept` of a file that names the other place moves the keys
there; when the place it names holds no key and the other one does, the key
is taken from there.

A CLI that writes `node.toml` itself holds `keys.lock` for each write it
can (no node holds it), and refuses a change whose file is no longer the
version it read: a change made before another CLI moved the keys would undo
that move in the file. `center rm` deletes the center's key in both places
while `keys.moving` is there, since the start that finishes the move no
longer looks for a removed center.

With `keyring` the MAC key is in no file that a process can read. The check
still stands on that key: a process that can write both folders can still
set `file` with a key of its own, and a process of the node's user can ask
the keyring for its entries over the user's D-Bus session.

So with `keyring` on Linux the node's own folders, which no policy opens
and Landlock's rules leave out, also take in the places that reach the
keys: the node's `XDG_RUNTIME_DIR`, `/run/user/<uid>`, a socket that a
`unix:path=` `DBUS_SESSION_BUS_ADDRESS` names, and `keyrings` in
`XDG_DATA_HOME` and in `~/.local/share`. On the installed node that is
`nerve`'s session, and no command runs as `nerve`: the bus folder is
`nerve`'s alone (0700), so neither `nerve-run` nor the owner reaches it, on
any kernel, in any mode. The keys may go into the keyring wherever one
answers ([where the keys are](#where-the-keys-are)).

A node a person runs runs its commands as that person, who reaches the bus.
There `folder` mode offers no `exec` while the keys are in the keyring, as
on a machine without Landlock: the node logs it, its status says it
(`folder_commands_off`), and a refused command names the keyring. The gate
and the command's Landlock rules go by one answer per call, from the same
config and account. A Landlock domain does not change while its command
runs, so a `folder` mode command of such a node that started while the keys
were in files keeps a way to the session bus for its whole life. The running
node counts these commands, and a move of the keys into the keyring is
refused while one runs: nothing moves, and the refusal says how many run.
The command is counted first and looks at the keys' place then, under the
store lock that a move holds, so a command whose config was taken before a
move that finished first does not start either. A reload (SIGHUP, `reload`)
of a file that another writer saved with `keyring` is refused the same way
while one runs, and the config in force stays. A process that a command
takes out of its process group (`setsid`) outlives its call where the node
has no cgroup for commands (Commands), and is not counted. Commands of
another account than root are not counted: they cannot reach the bus.

On a node a person runs, `allowlist` and `user` mode commands run as that
person without Landlock, so an allowed command that talks to the Secret
Service (`secret-tool`, `busctl --user`, `gdbus`, `dbus-send`) reads the
node's keys with `keyring`; it names no path the protected list could
refuse. That is an accepted limit there: the owner's rule is no allow rule
for a program that asks the keyring, or the keys stay in files. On the
installed node it does not arise.

#### A keyring on a Linux without a desktop

A Linux without a desktop usually has no Secret Service. When the keys are to
be in the keyring (the config says so, or the owner chooses it in `setup`)
and none answers for the node's user, `setup` asks whether to install one.
`install` asks the same when it runs in a terminal and the config of an
earlier install says `keyring`; without a terminal it refuses before it
starts the service. The question is asked only at a terminal: `setup` run
by the owner without sudo goes through the owner socket, whose client tells
the node whether its input is a terminal's (`terminal` in the request,
`NERVE_OWNER_TERMINAL=1` for the command), and piped answers get the
refusal. No is the default, and so is the end of the input; both keep the
refusal. Yes runs, as root, each program by the absolute path found in
`/usr/sbin`, `/usr/bin`, `/sbin` or `/bin`, with only `PATH` (those
folders), `HOME=/root`, `LC_ALL=C` and `DEBIAN_FRONTEND=noninteractive` in
its environment, in `/` and with no input:

- the package manager, for GNOME Keyring and what it needs, nothing it only
  recommends: `apt-get update` and `apt-get install -y
  --no-install-recommends gnome-keyring dbus-user-session` (Debian, Ubuntu),
  `dnf install -y --setopt=install_weak_deps=False gnome-keyring` (Fedora,
  RHEL) or `pacman -S --needed --noconfirm gnome-keyring` (Arch);
- `loginctl enable-linger <user>`: the user keeps a session with its own
  D-Bus from boot on, and D-Bus starts GNOME Keyring there when the node
  asks;
- for the installed node's own user `nerve` only (by its name and the comment
  `install` gives it; a node run by hand keeps its user's session and XDG
  folders as they are, and `setup` only sets a wrong runtime folder or bus right there),
  when the user's service manager has another user's `XDG_RUNTIME_DIR`, bus
  or XDG folders from the system-wide environment of the login
  (`/etc/environment`, which `30-systemd-environment-d-generator` hands to the
  manager): `systemctl --user set-environment` of the user's own, a restart of
  the units that took the wrong ones (`dbus.service`, GNOME Keyring's unit,
  whichever of its two names exists), and the user environment generator
  `/etc/systemd/user-environment-generators/99-nerve-session` (it runs after
  that one and prints the user's own for that user only; `uninstall` removes
  it). The node does the same `set-environment` and restart when it starts
  with its keys in the keyring, which covers a session that started again
  without the generator. The XDG folders are set, not unset: what a
  generator gave the manager is not an `unset-environment`'s to remove;
- a login keyring for the user in GNOME Keyring's plain format,
  `~/.local/share/keyrings/login.keyring`, that opens without a password. A
  login keyring that is there is left as it is.

Then it checks that the keyring answers. Whether a keyring answers is asked
by `nerve-node` itself in a process of its own, as the node's user and in
that user's session.

Nothing is offered where the user has a graphical session: the
environment of a setup run in it (`DISPLAY`, `WAYLAND_DISPLAY`,
`XDG_CURRENT_DESKTOP`, `XDG_SESSION_TYPE`), or logind's display session of
the user when its type is x11, wayland or mir. A password-less login keyring
would become the default for every program of that desktop.

The keyring crate connects once per process and keeps a failure for the
process's life. A running node reports one in its status
(`keyring_failed`); once a keyring answers setup, installed by setup or
not, setup run as root restarts the installed node (`systemctl restart`,
then waits for it); run for the owner inside the node, and on a node run by
hand, it stops with a message that asks for the restart
(`nerve-node service restart`) and for setup again.

The kernel keyring (keyutils) needs no daemon, but its keys are gone after a
reboot, and the node's with them, so it is not used. A keyring that opens
without anyone typing a password keeps its entries unencrypted on disk,
readable by the node's user like the key files, and kept from centers like
them (above); the question says so, and that it becomes the user's default
keyring. At boot the node can start before its user's session; it then
exits with the refusal, and systemd starts it again 5 seconds later.
`uninstall` ends that session (`loginctl disable-linger`).

## 2. `node.toml`

```toml
version = 1                 # bumped on every write; config.write checks it
locked = false              # `panic` sets it: no link, nothing runs

[node]
name = "laptop"             # shown to centers; the host name by default

[machine]
shell = "/bin/bash"         # for exec.run; the platform shell by default
allow_root = false
sudo = "off"                # off | on: the sudo switch (§4); off when missing
sudo_path = "/usr/bin/sudo" # optional; `sudo` from PATH by default
user = "alice"              # optional, Windows: the account commands and the sudo switch run as on the installed node (§1)
secret_storage = "file"     # file | keyring: where the node keeps its keys (§1)

[limits]
max_running = 4             # commands at once, per node
output_cap_bytes = 16777216
default_timeout_secs = 600  # optional: a command's limit when its call gives no timeout_ms
max_timeout_secs = 3600     # optional: no command runs longer, whatever timeout_ms says

[limits.command]            # one command (Commands below); these are the defaults
memory_mb = 4096            # MiB; a call may ask for less or more up to memory_max_mb
memory_max_mb = 16384
cpu_percent = 200           # of one CPU
cpu_max_percent = 800
processes = 1024            # processes and threads (pids.max)
processes_max = 8192

[connection]
proxy = "http://proxy:3128" # optional; HTTP CONNECT, never with user:password@;
                            # https://host:port for a relay (§2, Relay)
pin = "<pin>"               # optional, https:// only: the pin of its certificate
login = "lab-pc"            # optional, https:// only: the user; its password is a node key
headers = ["X-Proxy-Token"] # names of extra headers on the CONNECT request;
                            # their values are in the system keyring

[providers]                 # programs that may add capabilities (§7); none by default
allowed = [{ name = "desk", exe = "/usr/lib/nerve-desktop/nerve-desktop" }]

[[capability]]              # the owner's own (below); none by default
name = "logs.tail"          # cap.action
summary = "The end of a log file."
effect = "read"             # read | write | execute | sense | actuate
command = ["tail", "-n", "{lines}", "--", "{path}"]
params = '{"type": "object", "required": ["path", "lines"], "properties": {"path": {"type": "string", "x-nerve-path": "read"}, "lines": {"type": "integer"}}}'
result = "text"             # text | a JSON Schema as text
timeout_secs = 10           # optional, 1 to limits.max_timeout_secs
account = "nerve-run"       # nerve-run | owner
platform = "any"            # any | linux | windows

[relay]                     # optional; the relay for other nodes (protocol §4.8)
listen = "0.0.0.0:7490"     # ip:port; the relay is off without it
pin = "<pin>"               # the pin of the relay's TLS certificate; its key is a node key
max_links = 16              # tunnels at once, over every relayed node
max_links_per_node = 4      # tunnels at once of one relayed node
max_opens_per_minute = 30   # tunnels one relayed node may open a minute

[[relay.node]]
name = "lab-pc"             # the user name of its Proxy-Authorization
token_sha256 = "<hex>"      # SHA-256 of its token; the token is in no file
centers = ["home"]          # optional: the centers it may reach; all when missing
max_links = 12              # optional: its own tunnels at once (a relay behind this one)
max_opens_per_minute = 300  # optional: its own opens a minute

[[center]]
name = "home"               # the owner's name; the CLI's --center
url = "https://center.example:8443"
pin = "<sha-256 of the center certificate, base64url>"
center_id = "…"
node_id = "…"
settings = "off"            # off | write: may the center set this policy
paused = false              # the center may pause; only the owner unpauses
revoked = false             # the center sent `bye revoked`
unknown = false             # the center answered 401
public_key = "<64 hex>"     # after this node rotated its key (protocol §4.10): the key
                            # it has now; node_id stays the one of the first key
key_rotations = 1           # rotations of the node's key and of the center's it took;
pin_rotations = 1           # a restore keeps the keys and pins of the config further along
old_pin = { pin = "<pin>", until_ms = 1790000000000 }  # after the center rotated its
                            # key (protocol §4.10): its old pin, taken until then

[center.policy]
mode = "folder"             # allowlist | folder | user (a new pairing: folder; a file without it: allowlist)
as_owner = false            # allowlist only: its commands run as the owner, not as nerve-run
until = 1790000000000  # optional, folder and user: ms since the epoch; then allowlist
folders = [{ path = "/home/u/proj", access = "rwx" }]  # folder mode; r w x in any mix, "" for none
places = ["/home/u/proj"]  # folders `folder add` recorded at their real place; the owner's, a center's write keeps it
caps = { "fs.write" = "off" }   # on | off | hidden
protected = { extra = [], allow = [] }  # a center may add to extra; only the owner removes or releases,
                                        # also by a folder at or inside an entry
allow = ["exec.run:git status", "fs.read:~/notes/*"]   # allowlist mode only
deny = ["fs:~/private/*", "exec.run:rm *"]             # every mode
sudo_allow = ["sudo apt update"]                       # sudo commands, every mode
```

Unknown keys are refused, and so is a rule that does not parse. Two centers
with one name are refused. Folder paths are absolute in the platform's own
form, kept without a doubled or trailing separator or a `.` part; a path with
`..`, and one place named twice with different access, are refused. On the
wire they travel as `/c/Users/...` on Windows (protocol §7.2).

### Capabilities of the config

Each `[[capability]]` is one action, `cap.action`, that the node serves itself
by running `command` (`nerve_policy::config::ConfigCapability`; the owner's
`cap add`, `cap edit` and `cap rm` write them, and no center document holds
them). The node refuses a file where:

- the name is not `cap.action` of member names (protocol §6), its `cap` is
  built in (`node`, `fs`, `exec`, `settings`, `audit`, `job`, `stream`), or
  two entries share it; there are more than 64;
- `params` (JSON text) is not an object schema of the subset (protocol §6.1),
  or `result` is neither `text` nor a schema of the subset;
- `timeout_secs` is 0 or above `limits.max_timeout_secs`; the summary is not
  one plain line;
- `command` is empty, its first element (the program: a name looked up in
  `PATH`, or an absolute path in the form of the entry's `platform`, either
  form for `any`) is a placeholder or a relative path, it has
  more than 64 elements or a NUL, an element `{field}` (no blank or brace
  inside) names no property of `params`, or one whose schema takes more than
  a string, number, integer, boolean or null; a property appears inside a
  longer element (`--f={field}`), or no element names it;
- a placeholder whose argument a call may leave out (not in `required`, or
  its schema takes null) stands before the first literal `--`, or an element
  other than its own placeholder follows it: the elements after a dropped one
  move up, so an option before it would take the next one as its value.

A call's arguments are validated against `params` first. Each `{field}`
element becomes the argument's value as one element of the program's argv (a
string as it is, a number or boolean as JSON text); an argument left out or
null drops its element. A value that starts with `-` in an element before the
first literal `--` is refused `invalid_args`, as the program would read it as
an option. No shell reads the argv: the node starts the program itself
(through the shim where it confines it), never through sudo or as root.

Which ones a node offers, with `provider: "config"`, one capability per
`cap` (crate::config_cap): on Linux only, those whose `platform` takes it,
and on a node run by hand only those with `account = "owner"` (it has no
`nerve-run`). Windows parses them and offers none. The descriptor cuts them by
the effect table like any capability (§3), and only the owner turns one on
that senses or actuates (§5, `settings.set`). Since a center's earlier `on`
of the capability (or of the action while it read) or allow rule would cover
an action that comes to sense or actuate, `cap add` of such an action and
`cap edit` that changes one to it write `caps."cap.action" = "off"` for each
center whose `on` or allow rule covers it (a center cannot remove that), and
name those centers.

A call is decided like a provider's (§7, Paths), then runs:

| `account` | Runs as, from | Paths judged | Confinement |
|---|---|---|---|
| `nerve-run` | `nerve-run`, its home | as `nerve-run`, with the pairing's folders and, where the pairing's commands run as `nerve-run`, its built-in ones; a read outside them by `nerve-run`'s own access; the link walk as that account | Landlock where present: the pairing's folders and the built-ins where its commands run as `nerve-run`, else the built-ins alone (§1, Commands) |
| `owner` | the owner (root where root is the owner), the owner's home; a node by hand: its own user | as a program's (§7): the granted folders only, as the pairing's command account, closed folders refusing the walk | none |

An `owner` one is refused `forbidden` (and audited so) before the gate when
its program (looked up in the node's `PATH` where it is a bare name) or a fixed
element that is an absolute path lies, as written or where it leads (looked at
as the owner), at or below a place a center's commands may write: a `w` folder
of any center, `/tmp`, `/var/tmp`, `nerve-run`'s home. `cap add` and `cap edit`
warn of it.

Both count toward `limits.max_running`, run in a cgroup of their own with the
default `limits.command`, and end at `timeout_secs` (else
`limits.default_timeout_secs`, at most the maximum): `timeout` "<name> ran
past its limit of …". The result is stdout as a string (`text`; cut stdout
ends with a note), or stdout parsed as JSON and validated against the result
schema (`io` when it is not; `too_large` when stdout was cut; stderr past the
cap cuts neither). An exit code other than 0, a signal or a memory kill
(whatever the exit code; audited `killed`/`memory` as for `exec.run`) is an
`io` error naming it, with `data.exit_code` and `data.stderr` (the first 16
KiB).

### Commands

`exec.run` runs its command line with `machine.shell`: `/bin/sh -c`, on
Windows `powershell.exe -NoProfile -Command` (Windows PowerShell 5.1: `;`
chains commands, `&` does not); the action's text in the descriptor names the
shell. Output that is not UTF-8 is read in the OEM code page (Windows), which
the command's own console starts with.
Every command has a run-time limit: its `timeout_ms`, or
`limits.default_timeout_secs` (600) when the call gives none (0 counts as none),
and never more than `limits.max_timeout_secs` (3600): a larger `timeout_ms` is
cut to it, and so is the default when the maximum is lower. Both are at least
1, are the owner's alone (a center's settings document does not reach them),
and are left out of the file while they are the defaults. They are read when a
call starts: a running command keeps its limit. The `timeout` error names the
limit that ended the command, and the descriptor states both numbers in
`exec.run`'s text and in the `default` and `description` (milliseconds) of its
`timeout_ms` parameter, so a change of either changes the descriptor's rev, and
nodes with other limits have other params (a harness gets each node's
details from `list`). The parameter has no `maximum`: a larger value is cut to
the most, not refused, so a center that checks the arguments lets it through.
A command is killed with its process group when its call ends: on
`timeout_ms`, `cancel`, `session.end` of the session that started it, a
link that ended without being resumed (protocol §4.9), and when the call
returns. While a dropped link waits for its resume, its commands run on. Windows has no process groups:
there each command runs in a Job Object of its own. The shell starts
suspended, is put in the job, and only then runs, so every process it starts
is in the job, however deep and also when its parent has exited; ending the
job ends them all, and the job closes with the node, so a node that dies
leaves no command running. Where the node runs in a job already (a service,
the task scheduler), the command's job is nested in it; when Windows cannot
put the shell in its job, the command is not run and the call says why. A
process started on the command's request by another program, such as WMI
(`Win32_Process.Create`), a service or the task scheduler, is that program's
child and not in the job. Only when Windows makes no job at all does the node
fall back to recording the processes below the shell every 25 ms, best
effort. A Job Object does not restrict file access: it is no confinement
(see folder mode below).

On Linux each command runs in a cgroup v2 of its own, held to the limits
its call was granted from `limits.command`: `memory.max` (with
`memory.swap.max` 0 and `memory.oom.group` 1, so a command past its memory
is killed whole), `cpu.max` (`cpu_percent` × 1000 µs per 100 ms) and
`pids.max`. Each default and most is from 1 up to 1 PiB, 4096 CPUs and
4194304 processes, and no default is above its most; a call names a value
of its own up to the most. The node takes its own cgroup as the root
(`/proc/self/cgroup`) when systemd delegated it (`user.delegate` or
`trusted.delegate` set to `1`), or when it belongs to the node's user, who
is not root, and holds no other process: outside `user@<uid>.service` the
system's systemd gives a unit's cgroup to its `User=` only with
`Delegate=`, so that is proof enough (a system systemd before 251 sets only
`trusted.delegate`, which the node's user cannot read). Below
`user@<uid>.service` every cgroup is the user's, so there the user's
systemd, which marks none, is asked as well (`systemctl --user show -p
Delegate`, for the unit that is the last part of the path). Without the
mark the root of the visible hierarchy (`/`, the root of a cgroup namespace
such as `ProtectControlGroups=private` makes) names no unit: it is taken only
when the user's systemd names the node's unit (`systemctl --user whoami`,
systemd 256) and says it is delegated, so a system unit there needs the mark
(systemd 257 sets it), and a user unit on an older systemd gets no cgroup. A cgroup systemd did not delegate is not taken: systemd turns its controllers off at
its next reload. It moves itself into the leaf `node`, turns on
`+memory +cpu +pids` in the root's `cgroup.subtree_control` (each where the
root has it), and makes `cmd-<n>` beside the leaf per command. The forked
child writes `0` to that cgroup's `cgroup.procs` through a descriptor the
node opened, before it switches accounts and execs, so the command and all
it starts are in it. A node started in its leaf already takes the cgroup
above. `cmd-*` cgroups left from before are killed and removed at start.
Before it makes a command's cgroup the node checks that the controllers it
turned on are still on in `cgroup.subtree_control`; if one went off it
refuses the command (`unavailable`), and `status` reads them there each
time: `enforced` lists those on, `lost` those turned off since the start
(the CLI prints `NO COMMAND RUNS` for them). When the command ends the node reads `memory.events`: `oom` above 0
(its own limit was reached) with `oom_kill` or `oom_group_kill` above 0
gives the result `killed: "memory"` and a `reason`, and the audit log an
entry `killed`, code `memory`, after the call's `allowed`; a kill by an OOM
from outside (the machine's, a cgroup above) leaves `oom` at 0 and gives
only `signal: "kill"`, with no audit entry of its own. Then it writes `1` to `cgroup.kill` (Linux 5.14; before
it, SIGKILL to each pid, as the uid that owns it where that is not the
node's, `account::kill_pid_as`), which also ends what left the
process group, and removes the cgroup, from a thread when processes are
still going.

The installed unit has `Delegate=cpu memory pids` and `OOMPolicy=continue`,
so a command killed for its memory does not stop the service. A node without such a
cgroup (no systemd, cgroup v1, a terminal's session scope) runs commands
without these limits; the log says so at start (a warning on the installed
node), and `status` has `command_limits: {memory_mb, memory_max_mb,
cpu_percent, cpu_max_percent, processes, processes_max, cgroup, enforced,
lost, off}`, where `enforced` lists `memory`, `cpu` and `processes` as far as the
root passes their controllers on, and `off` says why there is no cgroup. A
cgroup that cannot be made for a command keeps it from running
(`unavailable`). A command of the node's own user can write its cgroup's
files, outside folder mode's Landlock, and so can a root one (root as the
account, a sudo command); one of another account cannot. Any command can
have work started outside its cgroup by its account's service manager
(`systemd-run --user`, `at`, cron), which the limits do not hold.
Windows does not hold commands to these limits yet.

Windows has no signals either. Each command gets a console of its own,
without a window (`CREATE_NO_WINDOW`), never the node's. On `timeout_ms`
and on `exec.signal` with `term` or `int` the node first asks the command to
end: a helper, `nerve-node __exec-stop`, sends Ctrl+C to the console of each
process in the job that still runs (but never to a console the node is on)
and posts `WM_CLOSE` to their visible top-level windows on its desktop. The
node holds those processes open while the helper runs, so their pids name no
other process. The job is ended 3 seconds later, or at once when nothing was
asked; a timeout's result waits for that. `kill`, `cancel`, `session.end`, a
link that ended without being resumed (protocol §4.9) and the call's return
end the job at once. A command of another
account (installed node) is asked by a helper started with that account's
token. The helper runs in the command's job, so it is ended with the
command and the control pipe refuses it. A command has one stop at a time:
`term` or `int` while one runs does nothing more. A command without a job
(the walk) is not asked. A process started
with Ctrl+C ignored (`start /b` in cmd, a new process group) does not hear
it. Whether a process ignores Ctrl+C passes on to the processes it starts,
so the node stops ignoring it before it starts its first command; a node
started with it ignored (over ssh, by `start /b`) hears Ctrl+C on its own
console from then on.

### Proxy

`nerve-node proxy set <url> [--header "Name: value"]...` sets the proxy. The
header values are secrets: the node keeps them in the system keyring
(Credential Manager on Windows, the Secret Service on Linux), in one entry per node under the service `nerve`, named
`proxy:<config folder>`. A user name and password in the URL
(`http://user:password@host:port`) become a `Proxy-Authorization: Basic`
header in the same entry. `node.toml` keeps only the URL without them and the
header names. No value is written to a file, the audit log, a log line, an
error text or the output of a command; `proxy set` and `proxy ls` print the
header names only, and `proxy rm` deletes the entry with the config entries.

There is no fallback to a file. Where the keyring cannot be reached (a Linux
without a desktop session has no Secret Service), `proxy set` with a header or
a password refuses and changes nothing; a proxy without either works there.
When the daemon dials through the proxy it reads the entry; a missing or
unreadable entry, or one without a value for a named header, stops the link
with a status that names the entry, and the node does not dial directly
instead (fail closed).

The installed node on Windows (§1, where the keys are: the folders `install`
uses, or the account `nerve`) takes no header value and no password either,
though its keyring answers. The service runs as `nerve`, the Credential
Manager is one per account, and `proxy set` runs as an administrator, so the
values would be in the administrator's Credential Manager, out of the
service's reach. The node keeps no proxy secret in a file, so there is nowhere
else for them. `proxy set` with a header or a password refuses before it asks
the keyring, and changes nothing (`node.toml`, the keyring); a proxy without
either works, and its `proxy set` deletes the entry of an earlier call, as it
does anywhere. Reading is as consistent: with headers named in `node.toml`
(set before the install) the link stops with `bad proxy:` and the same reason
(in the center's status and in the log; on Windows `status` asks the node over
its pipe, as on Linux), and
`proxy ls` shows it, both without asking the keyring: an entry may be in the
administrator's Credential Manager, but the service does not find it, so
`proxy ls` must not call the values good.

A `node.toml` that holds header values (`headers = { Name = "value" }`) or a
user name and password in `connection.proxy` is refused on load, without the values in the message: take them out of the
file, accept it (`nerve-node config accept`) and run `nerve-node proxy set`
again.

`center add` sends its pair request through the same proxy as the link
(`connection.proxy`, else `HTTPS_PROXY`/`NO_PROXY` of the environment it
runs in, which may differ from the daemon's), with the same values, when the
center is `https`; a proxy that fails stops the
pairing and nothing is stored.

`nerve-node proxy set https://<user>:<password>@<host>:<port> [--pin=<pin>]`
sets an `https://` proxy, a relay (§2, Relay) above all: the node reaches
it over TLS checked against `connection.pin` (else the system's roots) and
sends the `CONNECT` inside that TLS (protocol §4.7). Its password, the relay
token, is not a header value: it is one of the node's own keys, kept where
`machine.secret_storage` says, as `keys/proxy-login.secret` (0600) or the
keyring entry `proxy-login:<config folder>` (§1), and it moves with the
other keys when that setting changes. `connection.login` keeps the user
name. So the installed node on Windows, whose keys are in files, takes it,
and so does a Linux node without a keyring whose keys are in files; with
`keyring` and no keyring that answers, `proxy set` refuses with the
keyring's error and changes nothing, and a node whose keys are there does
not start, as for any key of the node. `--header` values of an `https://`
proxy stay in the keyring as above. `proxy rm` deletes the password with the
config entries; `proxy ls` shows the pin and the user name, never the
password.

### Relay

The node can be the relay of other nodes (protocol §4.8). Only the owner
turns it on, and a center reads and changes nothing of it, grant or not.

- `nerve-node relay set <ip:port> [--max-links N] [--max-links-per-node N]
  [--max-opens-per-minute N]`
  turns it on; `relay off` stops listening and ends every tunnel, and keeps
  the nodes.
- The relay speaks TLS only. The first `relay set` or `relay add` makes its
  certificate (self-signed, its names do not count): the key goes where
  `machine.secret_storage` keeps the node's keys (`keys/relay-tls.pem`, or
  the keyring entry `relay-tls:<config folder>`, §1) and moves with them;
  `relay.pin` keeps its pin. A later `relay set` keeps it, and makes a new
  one only when the key is gone or is not the one `relay.pin` names (it says
  so: the relayed nodes need the new pin). With `keyring` and no keyring
  that answers, `relay set` refuses as storing any key does, and the
  running relay does not listen (`status` says why). A connection that
  does not open with a TLS handshake gets `400` in plain HTTP, saying the
  relay speaks TLS only, and is closed; the log notes that its token, if it
  sent one, crossed the network in the clear.
- `nerve-node relay add <name> [--center <center>]...` makes a token for a
  relayed node: 43 characters of `a-z0-9`, shown once, with the line the
  relayed node runs,
  `nerve-node proxy set 'https://<name>:<token>@<relay>:<port>' --pin=<pin>`.
  `node.toml` keeps the token's SHA-256 only, and the log tells a change of
  `relay.node` without its values. `relay token <name>` gives a known node
  a new token, shown once with the same line, and keeps its centers and
  limits; the old token's tunnels end. `relay rm <name>` takes the token
  away and ends that node's tunnels; its centers and limits go with it.
- With `--center` (given more than once for more) the node's tunnels go
  only to the named centers of this node; without it, to every center a
  tunnel may go to (below). `relay set-centers <name> [--center
  <center>]...` changes the list later (without `--center`: every center
  again) and ends the node's tunnels to a center it took away. Only paired
  centers can be named; a center unpaired later stays on the list and is
  reached no more. A tunnel to a center off the list is refused with the
  same `403` as one to a center this node does not have.
- `nerve-node relay ls` shows the relay, its pin, its nodes with their
  centers and, from the running node, its tunnels: the node, its address,
  the center and since when.
  `status` carries the same under `relay` (§5); on Windows `relay ls` asks
  the control pipe's `status` for them. `relay rm`, `relay off` and `relay
  set-centers` say whether their cut is in force: "now" when a running node
  took the change; on Windows, where the CLI writes the file for the next
  start, that a running node keeps its tunnels until then and must be
  restarted to cut them now.
- A tunnel goes to one of this node's centers whose URL is `https` and
  that has not revoked it or answered 401, and is on the node's list when
  it has one, matched by host (without case)
  and port; the relayed node must have paired with the same host name or
  address. Centers that share a host and port (one reverse proxy, a path
  each) are all reached by a tunnel there: the relay grants it only when the
  node may reach every one of them, a list that splits them is refused by
  `relay add` and `set-centers`, and the log and the audit name them all
  (`a, b`). A tunnel reaches whatever is served at that host and port, seen
  from this machine's address (other names of the proxy too), since the
  relay does not read what goes inside it. A paused center is still a target: pausing stops this node's
  own link, not the tunnels of others.
- While the node is locked (`panic`) the relay does not listen. Any change
  that takes a tunnel's grant away (the relay off, the token gone or
  replaced, the center gone, revoked, unknown or off the node's list,
  `panic`) ends it at once, and a new certificate makes the relay listen
  anew.
- Each tunnel is one audit entry when it ends (§6): the node, the center,
  the peer's address, start, end, why it ended and the bytes each way. A
  refused `CONNECT` is no tunnel and only in the log.
- At most 64 connections at once wait for their `CONNECT` to be decided (15
  seconds in all for the first byte, TLS and the head), at most 4 of them
  from one address and 16 from one IPv6 /64 (link-local addresses count by
  address only, their scope is not in it); one over any is closed unread.
  A count by address cannot tell one machine with several addresses from
  several machines: a machine with four or more addresses in the /64
  (privacy addresses count) can take the /64's 16 and keep the other
  machines of that /64 out over IPv6, though not the relay's other peers.
  Once granted, a connection is a tunnel, counted by `max_links` and
  `max_links_per_node`, and gives its undecided slot back before the relay
  resolves and dials the center (12 seconds at most, less than the 15 a
  relayed node waits for the answer; each address of the center gets its
  share of the time left, so a first address that does not answer leaves
  time for the next).
- Every refusal is logged at `debug`. At `warn` the log gets a counted line:
  the first refusal at once, then at most one line a minute with how many
  came since, over how long (from the first of them to the last), and the
  last of them; a count that waits is told when its minute is over, also
  when no refusal follows (the relay looks every 5 seconds), and every count
  still waiting is told when the relay stops listening (`relay off`,
  `panic`, a new address or pin, the node stopping). There is one count for connections without a
  valid token (plain HTTP, no or a wrong token, over a limit), one per node
  for refusals of a node with its token (a target that is no center, a
  limit), and one per node for a valid token that came in plain HTTP, which
  names the node to give it a new one. So no peer, with a token or without,
  can rotate the log, and a line names the node whose refusals it counts.
- A node opens at most `relay.max_opens_per_minute` tunnels a minute (30
  unless set: a node needs one per center and redials after a second at the
  soonest; `relay set`, `relay ls` and `status` show it; a relay behind
  this one, which carries many nodes, gets more as a limit of its own,
  below); past that it gets `503`.
  `relay.max_links_per_node` and `relay.max_opens_per_minute` hold for
  every relay node; raising them raises them for every token. A node can
  have limits of its own instead (`[[relay.node]]` `max_links` and
  `max_opens_per_minute`, set with `relay set-limits <name> [--max-links N]
  [--max-opens-per-minute N]`: a limit not given stays, as with `relay
  set`, and no flag at all clears both; shown by `relay ls`). That is for a relay behind this one: in a chain the inner
  relay is one relay node of the outer one, and its own links and every
  tunnel of the nodes behind it count against that node's limits (and the
  relay's `max_links`). A refusal at the outer relay reaches the relayed
  node as the inner relay's `502`. Each tunnel is an audit entry and two `info`
  lines, so a node with the relay's limits cannot rotate the audit log or
  the log by opening and closing tunnels; a node with limits of its own,
  only as far as they allow.
- Hosts are compared without case or a trailing dot, and an address in any
  of its spellings (`[2001:db8::1]` and `[2001:db8:0:0::1]`) is one address.
  A name and the address it resolves to are not told apart.
- A tunnel quiet for 90 seconds (by the monotonic clock, so a step of the
  wall clock changes nothing) is closed.
- An `https` center paired at a loopback address or `localhost` is a
  target. A center paired at a name is dialled on the addresses the name
  resolves to, and when one of them is loopback or unspecified the tunnel
  is refused (`502`, the log says why): the relay does not reach this
  machine's own ports by a name. When the relay dials through its own
  proxy, the proxy resolves the name.
- The relay dials a center through this node's own proxy when it has one,
  so relays chain. It never reads what it carries, and no rule, folder or
  mode of this node applies to a tunnel: the relayed node's calls are
  decided by the relayed node, by its own policy.

On Windows a change made with `relay` is in the file and takes effect at
the next start of the node, as every change but the folder changes there.
Until then the running node keeps its relay settings in memory, for new
tunnels as well as open ones: a removed or replaced token still opens
tunnels, a new token or node is refused (`407`), and `relay off` leaves the
listener up. Every `relay` command that changes the file says so there
(and says nothing is "now" in force); where a running node took the
change, the commands that take something away say what ends now.

### Modes

- **allowlist**: default deny. A call runs only when an `allow` rule lets it
  through. `folders` do not decide; on the installed Linux node, where its
  commands run as `nerve-run` (unless `as_owner`), they and the built-in
  `/tmp`, `/var/tmp` and the account's home are its Landlock sandbox.
- **folder** (the mode a new pairing starts in): reading, writing and
  commands inside the `folders` and, on the installed Linux node, the
  built-in `/tmp`, `/var/tmp` and `nerve-run`'s home (and everything below
  them), by their flags; where the node reads as `nerve-run` (the installed
  Linux node), reading also, outside every folder, what every account may
  read (below).
  `access` is three independent flags, any combination
  (`"r"`, `"w"`, `"x"`, `"rw"`, `"rx"`, `"wx"`, `"rwx"`, `""` for none; the
  letters in any order, each once). `r` allows reading a path a call names
  (the read actions of `fs`, a path argument marked `read`) inside it, `w`
  writing one (`fs.write`, a path argument marked `write`), `x` commands with
  a working directory in it and an execute action of a provider at its paths.
  The flags do not imply each other: a write needs `w` and no `r`, a read
  `r` and no `w`, a command `x` and no `r`. Where folders nest, the deepest
  one that holds a path decides for it. Commands are confined where the
  platform can confine them; where it cannot (Linux without Landlock), a
  node run by hand refuses every command of folder mode and offers no `exec`
  action (unless the sudo allow list has an entry), while the installed
  Linux node runs them as `nerve-run` without Landlock, held back by that
  account alone, and offers `exec` (`daemon::folder_refusal`). On Windows a command runs in an AppContainer
  of its pairing (named from the state folder and the pairing's `node_id`,
  so a later pairing, also of the same center or under the same name, runs
  in another one and finds none of its entries), which reaches the system folders Windows opens to every
  AppContainer and the paths of the same sets as on Linux, each by a grant
  for the container on the folder with the rights of its flags; the
  installed Windows service, whose commands run as another account, has no
  such confinement and refuses them. `allow` rules do not count. On Linux a command
  reads the system folders and its `r` folders, writes its `w` folders and
  runs programs from the system folders and its `x` folders (Landlock), each
  flag with its own rule. A folder with `w` and not `r` can be written but
  not read or listed by the command: its rule carries the write rights only.
  Landlock cannot run a file it may not read, so the rule of an `x` folder
  carries the right to read files by name (no listing); the `fs` actions of
  the center stay decided by `r`. The node's own folders are in none of these
  sets: a folder that holds one is granted as its other entries, level by
  level down to it, so the command can neither list those levels nor make
  new entries right in them.
- **user**: full access as the user, protected paths aside. `allow` rules
  do not count.

Folder and user have no time limit by default: once set, they stay until the
owner changes them. A limit is opt-in (`until`, or `nerve-node mode set user
--for HOURS`). When it runs out, the center is back in `allowlist`, the default
deny mode, not in `folder`.

Reading in folder mode where the node reads as the command account: the
installed Linux node does a center's file calls as `nerve-run`
(`account::FsAs`). Inside the center's folders (its own built-in ones among
them) their flags decide as for every path, the deepest one first. A path a
read call reads in no folder of the center may be read where it is open to
every account on the machine: each folder above it lets others pass (`o+x`)
and it lets them read (`o+r`). What `nerve-run` reaches beyond that it
reaches through the ACL entries the node puts on for the folders (§1): every
pairing's grants, and the pass-through on the owner's folders above a grant;
those belong to the folders, not to the account, so they open nothing to a
file call outside them. Before such a call the node asks, as `nerve-run`,
whether the path is open to every account and whether it may open it for
reading (a path that does not exist passes). Only a file or a folder passes,
and the node asks what it is before it opens it, so a device, a FIFO or a
socket is never opened (opening one can reset the board on a serial port, or
let a waiting writer go on). The node's own entry under
`/proc` (`/proc/self`, `/proc/thread-self`, `/proc/<pid>` of the node or one
of its threads, and a `/proc/<pid>` that does not exist, which a thread the
node starts for the read may take) is refused before that: its files there
are open to all by their mode, and the kernel lets the node's threads read
them whatever account they act as, which no process of `nerve-run` could. For a provider, which reads
with the owner's rights, the path must also be no folder, as it would read
below it. The node's own folders, protected paths, deny rules and `off` and
`hidden` still win. Writes and commands keep to the folders, and a write or
execute call that also reads a path needs `r` for it. Landlock, where
present, holds a command of `nerve-run` to less (the system's folders and its
folders); a file call is not run under it. A node run by hand and Windows
read with the node's own or the owner's rights, so there every path a call
reads needs a folder with `r`. A call that names no path, a read included,
needs `on` in folder mode on every node: every `fs` action names its path,
so such a call is a program's (§7), which reads where the node cannot see,
with the owner's rights.

`deny` rules count in every mode and a matching deny always wins. A rule
matches the whole target: `exec.run:rm *` refuses `rm -rf x`, but not
`git status; rm -rf x` or `/bin/rm -rf x`. Sense and
actuate actions are allowed by no full-access mode, only by the owner's
`caps` entry `on`; in `allowlist` mode an allow rule allows them (a center
may not add one for a provider's capability that senses or actuates
itself, §7). `on` allows nothing else that a mode refuses: a call with
paths outside the folders stays refused, a sense or actuate call's too. A
write whose marked paths are all `read` names no place it writes and needs
`on` in folder mode, as a write with no path does.

### Rules

A rule in `allow` and `deny` is `<scope>` or `<scope>:<pattern>`. The scope is
a capability or `cap.action`, as in `caps`. The pattern is a glob over the
call's target: the whole command line for `exec.run`, the resolved path for
every `fs` action and for each path argument of any other action (one its
schema marks with `x-nerve-path`, protocol.md §6.1), in the center's form
(`/c/Users/x` on Windows, matched without case; `~/` is the owner's home),
and `<cap>.<action>` for any other action. `*` matches across `/` and spaces. A
rule without a pattern covers every target of its scope. A pattern ending in
` *` also matches the bare program, one ending in `/*` the folder itself.
Commands and paths never mix: `fs:/tmp/*` is no command rule.

A third form is `guard:<name>`, a rule of the guard against changing the node
(`guard:node-programs`, `guard:node-paths`, `guard:node-service`). It covers
`exec.run`, has no pattern, and matches the commands the line holds (parsed as
the node's shell reads it), not its text. It is a deny rule only: a node
refuses it on the allow list and any other `guard:` name. See the user
documentation of rules for what each refuses.

| Rule | Covers |
|---|---|
| `exec.run:git status` | that command line, exactly |
| `exec.run:git *` | `git` and anything after it |
| `fs.read:/home/u/notes/*` | reading the folder and below (the action, not `list` or `grep`) |
| `fs:~/private/*` | every fs action on the folder and below |
| `camera.snap`, `camera` | that action, or every action of the capability |
| `notes:~/private/*` | every action of `notes` with a path argument there |

The four buttons of the center's audit view and `nerve-node rule add allow|deny|sudo
<command> [--wildcard]` write exactly these forms: exact (`exec.run:git status`) or
wildcard (`exec.run:git *`, `fs.read:/home/u/notes/*` for the folder of the
path, the capability for another action). They only add a rule to a list;
rules can be written by hand as well (`nerve-node config add
center.<name>.policy.allow '<rule>'`).

In `allowlist` mode a command with `; & | $ \` ( ) < > @ { } % ' " # , \`,
a line break or another control character, or with a word that starts
another shell or runs a string as code (`powershell`, `pwsh`, `cmd`, `sh`,
`bash`, `iex`, `Invoke-Expression`, `Invoke-Command`, `start`,
`Start-Process`, `eval`, `-Command`, `-EncodedCommand`, `-File`, `/c`,
`/k`, without case and `.exe`) is covered only by an allow rule that names
the whole line, never by a wildcard: such commands run unconfined, `git *`
must not cover `git x; rm -rf ~`, and `echo *` must not cover PowerShell's
`echo @{a=<command>}`, which runs the command. A wildcard rule therefore
covers plain words only; a Windows path with `\` needs an exact rule or `/`.

## 3. Deciding a call

The default is deny. A call runs only when the mode and the rules allow it;
otherwise it is refused at once with `forbidden`, and nothing waits for an
answer. For each call the node takes the center's policy and, in this order:

0. An `exec.run` command line over 64 KiB is `forbidden` first, before
   anything is checked. A call that touches the node's own folders (§1) is
   `forbidden` before anything else is looked at; no rule, mode, folder or release lifts that.
   It looks at every path of a call (an `fs` call's, an action's marked
   path arguments; resolved, and for an action's, which its program may
   read or write below, also an own folder below it), at the working
   directory of `exec.run`, and at paths the command line names plainly
   (absolute, or from `~/`, `$HOME/`, `${HOME}/`). The line is compared
   without case, with `\` and `/` alike on Windows, with `seg/..` and
   doubled separators folded, with the home in each shell's spelling (also
   `$env:USERPROFILE`, `%USERPROFILE%` and `%HOMEDRIVE%%HOMEPATH%` on
   Windows) and with relative words taken from the working directory
   (`..\node-config`). Each path segment is matched as a shell wildcard
   (`node-st*`, `node-s?ate`, `[...]`); on Windows a segment with an 8.3
   short name (`NODE-S~1`) stands for any name, an admin share
   (`\\localhost\C$\...`, any host) for its drive, and a path without a
   drive (`\Users\...`) for that path on every drive, as does a volume or
   device path (`\\?\Volume{...}\...`); a dot at the end of a name is
   dropped as Windows drops it (`node-state.\`), and a drive-relative
   `C:name` is taken from the working directory on that drive. A path a
   command builds at run time (`cd ~/.config; cat nerve/node.toml`) is not
   seen there. In `folder` mode Landlock (the AppContainer on Windows) keeps a
   command it confines out all the same. A `user` mode command runs as the
   user, unconfined, so does a program an `allowlist` rule lets run, and a
   sudo command (§4) runs as root without the sandbox in every mode; a
   `folder` mode command can also ask a service of the user's session to run
   a program outside it (`docs/user/modes.md`).
1. A `locked` node (after `panic`) keeps no links and runs nothing; a paused,
   revoked or unknown center is not dialled.
2. The capability setting: `off` refuses (`disabled`, written to the audit
   log as any refusal), `hidden` leaves it out of the descriptor.
3. A sudo command (§4) with the sudo switch off: `forbidden`.
4. A matching `deny` rule: `forbidden`, in every mode.
5. A sudo command is allowed only when `sudo_allow` names it, in every mode.
6. Any other call in `allowlist` mode is allowed only when an `allow` rule
   matches (every path of the call needs one).
7. In `folder` and `user` mode the mode itself decides (§Modes), by the
   call's effect, the same for every capability. `allow` rules are not
   looked at. `user` mode allows read, write and execute, sense and actuate
   only with `on`. `folder` mode allows a read that names its paths (as
   §Modes says), and a write or an execute call when it names at least one
   path and every one lies in a folder with the flag for what the call does
   there (`exec.run`: its working directory in an `x` folder; another
   execute call: each path in an `x` folder as well); a read, write or
   execute call that names no path lies in no folder, so it needs `on`; sense and actuate need `on`. `on`
   allows nothing whose paths lie outside the folders.
8. Protected paths (keys, shell profiles and the built-in list) are refused
   whatever allowed the call, `user` mode too. On Windows the built-in list
   also holds `%ProgramData%\ssh` (the OpenSSH server's config, host keys
   and `administrators_authorized_keys`), `%SystemRoot%\System32\config`
   (the registry hives with the password hashes), the all-users Startup
   folder `%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp`,
   Windows PowerShell's home `%SystemRoot%\System32\WindowsPowerShell\v1.0`
   (and its SysWOW64 twin) with the all-users profiles, and the user's
   `NTUSER.DAT`. It also holds `%ProgramFiles%\PowerShell` (and
   `%ProgramFiles(x86)%\PowerShell` where that is set), PowerShell 7's home
   `$PSHOME` with its profiles and modules as the MSI and winget install it;
   a PowerShell 7 unpacked from the zip, installed as a .NET tool or into a
   folder of the user's choice is not covered. The user's PowerShell
   profiles and modules (`Documents\PowerShell`, `Documents\WindowsPowerShell`)
   are protected below `%USERPROFILE%\Documents` and below the Documents
   folder where Windows really has it (read with the known-folder API, so
   OneDrive's backup or a redirect does not move them out of the list).
   A folder spelled so that it matches nothing (a `..` segment, and on
   Windows an 8.3 short name or a name ending in a dot or space) is refused,
   from a center and in the owner's own `node.toml`; the full name is needed.
   Protected paths apply to the
   file actions and to the working directory of a command, not to what a
   command reads; in `user` mode a command runs as the user without a
   sandbox. A center's folder at or inside a protected entry is
   judged by the access the owner's folders give that place, and may set no
   flag the deepest of them lacks; the spellings of one place
   (`/home/u/.ssh/`, `/home/u/.ssh`) are compared by path, not as text.
   A folder releases a protected entry only for the access the call needs
   there, in every mode: a read needs `r`, a write `w`, a command run in it
   `x`, so an owner's `~/.ssh` with `r` lets no write through in `user`
   mode. A center's folder that is, or passes through, a link into a
   protected entry is refused unless the owner's folders release the place
   it leads to with its flags, and a folder that has become such a link
   since is left out of a command's Landlock rules, as is a folder whose path
   crosses a link that lies inside a `w` folder of any center (a command may
   have put the link there). A folder the owner added with `folder add` is
   stored by its resolved path and listed in `policy.places`; such a folder
   is also left out when its path resolves to another place now, whatever the
   `w` folders say, and a center's settings document cannot change the list.
   `folder add` itself does not follow a link that lies inside a `w` folder
   of any center: it refuses, so that a link a command made is not stored,
   and recorded, at its target. It judges and resolves in one pass
   (`exec::settle`): a link is judged by the folder that holds it as spelled
   and as it resolves, either inside a `w` folder refuses it and so does a
   holder that is not the place it was looked at as, and the place the pass
   ends at must resolve to itself, so that what is stored is what was looked
   at. A `w` folder that cannot be resolved only makes a clean walk "cannot
   tell" (the folder is stored as given, not recorded). On Windows the walk
   goes through a `subst` drive's folder name by name (`QueryDosDeviceW`),
   never through the drive resolved, writes out the short names of the
   folder it maps, and refuses a path with a drive but no root or that is not
   on a drive letter. A link target is taken the same way: a drive, a volume
   root (as the drive or folder it is mounted at), or refused.
   For a folder without an entry only the `w` folders in the config count,
   and a command that runs without Landlock can make a link elsewhere. A folder
   that holds a protected entry gives a command in `folder` mode none of it:
   its Landlock rules take the folder's other entries, level by level down
   to the protected one, in the read, write and run sets alike, so the
   command cannot list those levels or make new entries right in them.

Every refusal names its reasons in the error and in the audit log.

What the center is shown follows the same policy, so that its `list` offers
nothing the node would refuse. In `allowlist` mode an `fs` or `exec` action,
or one a provider adds (§7), is in the descriptor only when an `allow` rule
covers it by scope: `<cap>`
covers every action of the capability, `<cap>.<action>` that action, with or
without a `:<pattern>`. The pattern is not looked at there; a rule may allow
only some paths or commands, and each call is still decided as above.
`exec.run` is also shown when `sudo_allow` has an entry, since a sudo command
runs by that list alone. In `folder` and `user` mode the actions are shown as
before and allow rules do not matter, except a sense or actuate action such
as `exec.signal`, which is shown there only when the owner set it to `on`,
and in `folder` mode a read, write or execute action that names no path (a
provider's whose schema marks none), which needs `on` too (step 7); an
action that takes paths is shown where a call with its paths in the folders
would be allowed; deny rules never hide an action.
`off` actions stay listed (exposure `off`, on the capability or, for an
action switched off alone, on the action), `hidden` ones and the actions
left out here are absent, and a capability with no action left is absent.
`settings` and `audit` follow their own rules.

The descriptor also tells the center what it may do (protocol.md §6.2,
`access`): its mode now and its end, the account its commands run as, and in
`folder` mode its folders with their flags, in the center's path form. The
link builds it from that center's entry alone, with the built-in folders of
`nerve-run` added where its commands run as that account, as the gate and
the sandbox see them, and marked `own`; no other pairing's folders are in
it. A folder with no flag is never named, as the file calls hide its name
(`fs.list` leaves it out, a refusal under it reads like any other): the
deepest named folder around it is marked `closed_below` instead. A folder
whose name would read otherwise on one line (a control character, U+2028 or
U+2029, a blank at either end) is left out and counted in `unnamed`; where
it allows less than the deepest named folder around it, that one is marked
`closed_below` too. `confined` is set only where a
sandbox holds folder-mode commands: the installed Linux node without
Landlock runs them, held back by `nerve-run`'s account alone, and sends
`false`. Where the node runs no folder-mode command at all (`folder_refusal`
answers, as on the Windows service), no folder is marked `x`. `sudo` says
that the center's sudo allow list names commands, `exec.run` is neither
hidden nor off for that center (`Reach::of`) and the sudo switch is on
(`Shared::sudo_on`: set and a checked password held), so they run by that
list alone, in any folder and unconfined; with the switch off, or
`exec.run` hidden or off, none runs, and the block does not say so.
`reads_by_account` says that in folder mode the node reads as the command
account (the installed Linux node, `Shared::separate`), so a read in no
folder goes where every account may read (§Modes). A switch change moves the rev. In
`allowlist` mode as `nerve-run` the folders still hold the allowed
commands, but only `folder` mode names them. The account's name needs no
lookup of its own (the home of `nerve-run` is the last one looked up). The
descriptor's `rev` follows its content, so adding or removing a
rule that changes the set, a folder grant, a mode change or another account
sends `node/descriptor_changed`; a call naming an action that is not shown
still reaches the policy and is refused and audited.

## 4. The sudo switch

Sudo is a switch per node, not a mode, and its commands have an allow list of
their own, `sudo_allow`: globs over the whole command line (`sudo apt *`).
The normal `allow` list does not count for them.

- **Off** (the default): the node holds no sudo password, and a command whose
  first word is `sudo` (or a path ending in `/sudo`) is refused with
  `forbidden`, even when `sudo_allow` names it.
- **On**: such a command runs only when `sudo_allow` names it, in every
  mode; `deny` rules and protected paths still refuse it. A sudo command must
  be one simple command: one with `; & | $ \` ( ) < >` or a line break is
  refused. A `sudo_allow` glob covers only the plain lines a wildcard allow
  rule covers (§2, Rules); any other line runs only when an entry is that
  whole line, escaped as `rule add sudo` writes it. The node runs it as `sudo -S -k -p <prompt> …` without Landlock
  (which would stop sudo from gaining privileges), with a random prompt per
  command, started as the account the commands run as (§1), so sudo raises
  it from that account. It writes the password to stdin only after sudo
  printed that prompt; when sudo asks for none (a `NOPASSWD` entry, root), the command
  finds no password on its stdin.
- Every other command runs with `no_new_privs` (Linux), so a `sudo` later in
  a command line, or any setuid program, cannot gain privileges.

The switch is never on without a working password. Turning it on takes the
password from a client: `nerve-node sudo on` (it asks on the terminal) or a
center with the settings grant `write` (protocol §7.4.1, sealed end to end so
the center cannot read it). The node checks it with `sudo -S -k -v` (output
discarded), run as the owner (§1: on the installed Linux node the account
the unit names, on Windows `machine.user`, else the node's own user), so the
password is the owner's, and refuses a wrong one with `invalid_args`; the
switch then stays as it was. An allowed sudo command of a pairing whose
commands run as the owner runs through sudo as the owner, with that
password; one of a pairing whose commands run as `nerve-run` runs as root,
started by the node itself (`/bin/sh -c '<the command>'`, the allowed line
and nothing around it, root's group only, no Landlock), without the password
or the sudo program. The line takes no option of sudo: a leading `-n` and
`--` are dropped, and one that starts with any other option (`-E`, `-u`, …)
is refused with `invalid_args` and the reason. Its environment is fixed: `PATH`
`/usr/sbin:/usr/bin:/sbin:/bin`, and `HOME`, `USER` and `LOGNAME` of root;
nothing of the node's. Its paths are looked at as the owner's, and its
default folder is the owner's home, resolved as the owner like a given one. The node opens the working folder as
the owner, a part at a time without following a link, so a link put there
after the check fails the call; the child enters that open folder with the
owner's file system ids (`fchdir`) and only then becomes root: it holds
CAP_SETUID and CAP_SETGID only, so as root it has no right past a folder's
mode until root's program runs. The folder's name never reaches the shell.
Turning it off drops the password. On Linux the password is kept
in memory only, whatever `secret_storage` says, so a restarted node, or
a `node.toml` that says `on` without a password held, has the switch off. It
never reaches a center: the node replaces every copy in an outgoing frame
(a command's output stream too, also a copy that two reads of its output cut,
or output printed before the password was held, unless its stream had taken
it to send already)
and in the audit log with `[redacted]`. `machine.sudo` changes only through the
switch; a value written into the file is turned off at start-up, since no
password is held. The switch works on Linux and Windows.

On Windows there is no `sudo` program. The switch works on the installed
node only (§1: the service, which may start a process with another
account's token), and its password is the one of the account the commands
run as, which must be an administrator. `sudo on` checks it with a logon of
that account as a batch job (`LogonUserW`, `LOGON32_LOGON_BATCH`), which UAC
does not filter: the logon must succeed and its token must hold the
Administrators group enabled; else the switch stays as it was. The node then
keeps the password with DPAPI in the config folder (`sudo.dpapi`, like the
command account's password), and holds it in memory as on Linux. A restart
holds the kept password again when `machine.sudo` says on and the file is
the current account's. A sudo command runs what followed `sudo` in the
shell, started with a fresh batch logon's full token (`CreateProcessAsUserW`)
with the account's own environment, in a job like every command; the check
that the account cannot open the node's folders does not apply to it. The
control pipe takes folder changes only, so `nerve-node sudo on` (elevated) checks the password,
writes the file and sets `machine.sudo` in the signed file, which the service
takes at its next start; `nerve-node sudo off` removes the file, and the
running node drops a held password whose file is gone within a second and
switches off. `uninstall` removes the file.

## 5. Control socket

The node's sockets on Unix (Windows has the control pipe and the owner pipe,
below):

| Socket | Who is served | Mode | Places | For |
|---|---|---|---|---|
| `<state>/run/ctl.sock` | the node's own user and root, each request with the token | 0600, in a 0700 folder | 64 | the CLI; a provider of a node run by hand (§7) |
| `/run/nerve-node/owner.sock` (installed node, Linux) | every account; `cli` an owner's only | 0666, in the unit's runtime folder | 64 | the owner's commands (below) |
| `/run/nerve-node/provider.sock` (installed node, Linux) | an owner (root always is one), told as it connects | 0666, in the unit's runtime folder | 16 | capability providers (§7) |

Each socket has its places of its own: a connection held on one never takes
one of another's, so providers, which hold theirs while they are attached,
and the owner's commands never starve each other.

`<state>/run/ctl.sock` (Unix; Windows has the control pipe below). One
JSON object per line: the client sends
`{"method", "params", "token"}` (the token is explained below), the server answers `{"ok": value}` or
`{"error": "text"}`, or, for streaming methods, several `{"item": value}`
lines until it closes. The socket is 0600 in a 0700 folder; only its own user
or root may talk to it. That does not keep out a command the node runs as
that very user (a node a person runs) or as root: Landlock does not stop a
process connecting to a socket file, and `setsid` takes a process out of the
tree below its command. So the node makes
a token at each start,
`<state>/run/ctl.token` (0600), and answers a request only if it carries it.
The CLI reads the file and sends it. The
file lies in the node's own folders, which a `folder` mode command's rules
leave out, so such a command, and a process it left behind, are refused for
every method. `install`, `update` and `setup` send the token too when they
ask `status` to wait for the node they restarted.

The token holds as far as the sandbox does, and the sandbox holds the
command's own processes only. Any program of the commands' account that runs
things for whoever asks it runs them outside the sandbox, as the account's
own process, which reads the token (and, as the node's own user, `node.toml`
and the keys) as the CLI does; the account's session service manager and a
terminal multiplexer are such programs, and there are more. On a node a
person runs, `folder` mode is therefore no boundary against that person's
other programs: that is the owner's choice and responsibility. The installed
Linux node runs no command as `nerve`, which owns the socket, the token and
the keys: `nerve-run` and the owner pass neither the socket's uid check nor
reach the token (§1). A sudo command is root and does.

A connection the node cannot take (for want of
descriptors, memory or epoll watches, or for any other reason of that one
connection) does not end the socket: the node takes the next one once the
cause is gone. Only an error that says the listener itself is broken ends it.
A connection carries one request: the node closes it after the answer (for a
streaming method, after the last item), closes one that sends no request line
within 30 s, and serves at most 64 at once; one over that is answered with
`{"error": "the node does not take connections now; try again"}` and closed.

What a client makes of a connect that fails: only a missing socket (ENOENT)
and a refused connect (ECONNREFUSED) mean that no node runs, and only then may
the CLI write `node.toml` itself. A queue that is full (EAGAIN) means a node
runs and takes no connection now (`the node does not take connections now; try
again`): the command fails and writes nothing. Any other connect error names
itself and decides nothing about a node. A call that gets no answer in 90 s
gives up (`the node did not answer in time; try again`). A caller that maps
every connect error to "not running" would write the file and report a change
the running node never got.
Methods:

| Method | Params | |
|---|---|---|
| `status` | | daemon and links; under `relay`, the relay's state, its pin, its nodes with their centers and its tunnels (§2, Relay) |
| `config.read` | | `node.toml` and its `version` |
| `config.write` | `config`, `if_version` | replaces it when the version matches |
| `config.accept` | | takes `node.toml` as it is after it was refused, and signs it (§1) |
| `folder.add` | `center`, `path`, `access` | `folder add`, done by the node so that it is judged as the owner (`exec::settle`): the path is followed a link at a time and must resolve to itself, the folder is stored at that place with `access` (replacing the entry there) and recorded in `policy.places`; `{stored, recorded, mode, counts}` (`counts`: whether the
center's folders hold its commands, in folder mode or as `nerve-run`). An error, with nothing changed, when the path crosses a link inside a `w` folder of any center, leads nowhere, or changed while it was looked at. Where the node cannot tell either (a folder it may not look into, or a `w` folder it cannot resolve) the folder is stored as given, `recorded` is false, and a record it had stays. The CLI uses it whenever a node runs |
| `folder.grants` | | the installed Linux node brings the folder ACLs in line at once (§Folder ACLs) and answers what that left: `{errors, stale, failed, skipped}`; `null` elsewhere. `folder add`, `set` and `rm` ask it |
| `reload` | | rereads `node.toml`; only a file the node signed is applied (§1) |
| `sudo.status` | | `{sudo: "on"|"off"}` |
| `sudo.on` | `password` | checks it with `sudo -v` and turns the switch on (§4) |
| `sudo.off` | | turns the switch off and drops the password |
| `center.rotate-key` | `center`, `end_grace` | rotates the node's key for `center` over the live link, or with `end_grace` ends the grace of the old one (protocol §4.10); `{center, public_key}`, the new key once. Waits for the center's answer, at most 15 s; an error when the node has no link to it or the center does not speak `rotate`. Also served on the control pipe (Windows) |
| `owner.check` | | changes nothing; the CLI asks it before `install`, `setup`, `update`, `uninstall`, `backup` and `restore` |
| `caps.list` | | what `cap ls` shows: `{capabilities, programs, config, running}`; each capability row `{name: "cap.action", effect, source: "built-in" \| "config" \| "program <name>", summary, centers: {<center>: "on"\|"off"\|"hidden"\|"default"}, now: {<center>: "on"\|"off"}}`, `centers` the switch (`cap set`; `default` where none is set; for `settings`, which has none, `"granted"`\|`"not granted"` by the center's `settings` grant) and `now` whether the center's descriptor offers the action now and it is not off (§3: mode, rules, switches, the machine); an action a program offered that the node left out with `broken` (its reason), no effect and no `now`; a config capability's row has `account` (`"nerve-run"`\|`"owner"`), and one this node does not offer (§2) `left_out` (why) and no `now`; `config` each `[[capability]]` as declared, `{name, summary, effect, command, params, result, timeout_secs, account, platform}`, the schemas as JSON (`result` `"text"` or a schema); `programs` the entries of `providers.allowed`, each `{name, exe, attached}`. A stopped node's CLI makes the same from `node.toml`, with the node's own capabilities and the config's (no program's), no `now` and `attached` null. Also served on the control pipe (Windows), where no program attaches |
| `hello` | `role` (`provider`), `name`, `capabilities` | a capability provider attaches; the connection stays (§7); on a node run by hand only, the installed node takes it on its provider socket |

Every method is refused from a process that runs below a command the node
started for a center, the reading ones (`status`, `config.read`,
`sudo.status`) too, as they hand over the whole config. That catches the
processes that stay below the command, in any mode. A `folder` mode command
is kept out by the token as well, including a process it left behind, as far
as the sandbox holds (above). A command without a sandbox (`allowlist` and
`user` mode) of a node a person runs can read the token file as it can read
`node.toml`, and a sudo command is root and reads it and passes the uid
check. Both can leave the tree at once (`( … & )`,
`setsid -f`, a daemon fork), while the command still runs. For such a command
the socket is no boundary at any time, as the node's files are none; the
refusal stops what stays below it.

### The control pipe (Windows)

`\\.\pipe\nerve-node-<hash>`, where the hash is the first 16 bytes of the
SHA-256 of the state folder's real path in lower case, in hex: one pipe per
state folder. The lines and the connection rules are those of the socket: one
request per connection, 30 s for it, at most 64 at once, `the node does not
take connections now; try again` over that. Only a missing pipe
(`ERROR_FILE_NOT_FOUND`) means that no node runs. The CLI sets no 90 s limit
on the answer: a folder change brings the folder grants in line before it is
answered, which takes long on a large folder. Methods:

| Method | Params | |
|---|---|---|
| `status` | | as on the socket |
| `folder.add` | `center`?, `path`, `access` (`r`, `w`, `x`, at least one), `recorded` | adds the folder, or replaces its rights (the same place in another spelling is the same folder); with `recorded` the folder is also entered in `policy.places`, as the real place the CLI settled it at |
| `folder.set` | `center`?, `path`, `given`, `changes` (1 to 64 of `=rwx`, `+x`, `-w`) | changes the rights of a folder the center has |
| `folder.rm` | `center`?, `path`, `given` | takes a folder away |
| `center.rotate-key` | `center`, `end_grace` | as on the socket |
| `caps.list` | | as on the socket |

`path` is the folder as the CLI judged it: for `add` the real place it
settled the path at (`exec::settle`, as this process sees it: the pipe takes
the change, not the judging, which on Windows is the CLI's alone), for `set`
and `rm` the stored folder it found (`stored_folder`). `given` is the folder
as typed or, after that lookup, the stored path again; `set` and `rm` find the
folder by either. A `rm` takes the folder's `places` entry with it (the
config's validation drops an entry that names no folder). Without `center`
the only paired center is meant.
While `node.toml` is newer than the config in force (the CLI wrote another
change there for the next start), a folder change is refused: the node saves
its whole config and would undo that change.
A field the method does not take refuses the request. The node checks a
change as the CLI does when it writes the file, saves it, brings the folder
grants in line, and answers `{center, path, access, mode, version}`
(`access` is `null` after `rm`).

Who may write:

- The DACL (`D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;<node account>)`) lets
  SYSTEM, the administrators (elevated) and the node's account open the
  pipe. An AppContainer gets no access, nor does a command account whose
  token has the administrators deny-only. Remote clients are refused
  (`PIPE_REJECT_REMOTE_CLIENTS`).
- Every request from a process in the job object of a command the node runs
  is refused, `status` included: the node lists the processes of every job
  it holds open (`JobObjectBasicProcessIdList`, nested jobs included) and
  looks for the caller's process id (`GetNamedPipeClientProcessId`). While
  a command runs without a job, and for a caller whose id Windows does not
  tell, every request is refused.
- The node makes the first instance with `FILE_FLAG_FIRST_PIPE_INSTANCE`
  and makes the next one before it hands a connection on, so the pipe always
  has one of its own. A node that cannot make the pipe (another process made
  one of that name first) logs it and runs on without it.
- The CLI opens the pipe for identification only and sends nothing unless
  its owner is SYSTEM, the administrators or the node's account (`nerve` for
  the installed node, else the CLI's own). When the pipe is another's and no
  node holds `keys.lock` (none runs), the CLI writes the change to
  `node.toml` itself, as with no pipe at all; with a node running it stops
  with an error that says how to free the name.

Not covered: a process another program starts for a command (the task
scheduler, WMI) is in no job of the node's; it opens the pipe only if its
account may. A sudo command (an administrator token) and a command of a node
run by hand (the node's own account) pass the DACL; the job check stops them
on the pipe, but they can still change `node.toml` itself. On Windows, allow
commands only to centers you would also give `settings = write`, or install
the node as a service.

### The owner endpoint

The installed node also takes commands from its owner, who is no root: on
Linux the account the unit names (`NERVE_NODE_OWNER`, which `install` writes:
the account that ran it), looked up by name at each request, and root; on
Windows the SIDs in the service's registry value `Parameters\Owners`. It
serves them `/run/nerve-node/owner.sock` (0666 in the unit's runtime folder)
or the pipe `\\.\pipe\nerve-node-owner` (DACL: SYSTEM, the administrators, the
owners; first instance; no remote clients), with the same lines and two
methods. Who may run a command is decided by the account the kernel names
for the caller (`SO_PEERCRED`); `nerve-run` is not the owner. The pipe's DACL
names no package, so no AppContainer opens it.

| Method | Params | |
|---|---|---|
| `status` | | `{"running": true}`, to anyone |
| `cli` | `args`, `cwd` | runs `nerve-node --config-dir … --state-dir … <args>` as the node's user, with `NERVE_OWNER=<owner>`; then `{"ok": {}}`, the program's output as `{"out"}` and `{"err"}` lines and `{"exit": code}`; the caller sends `{"in": text}` and `{"eof": true}` |

`cli` is refused to a caller who is not the owner, below a command the node
runs, with `no_new_privs` (Linux), in a command's job (Windows), with
`--config-dir` or `--state-dir`, and for `run`, `install`, `update`,
`uninstall`, `service` and `sudo on`, and on Windows `setup`. The checks of the caller's
process read the process that connected, which may have ended by the time
the request comes: they catch mistakes of a command that runs as the owner,
no more.

`backup` and `restore` take the file the caller opened itself: on Linux its
descriptor, sent with the request line (SCM_RIGHTS), which the program gets
as descriptor 3; on Windows the request says `"file": "stream"` and the bytes
come as `{"file": base64}` lines and `{"file_end": true}` before the input
(restore), or go back as `{"file"}` lines before `{"exit"}` (backup), through
a file in the node's state folder. The program finds it in
`NERVE_OWNER_FILE` (`fd:3` or that file) and never opens the path it is
given. The caller asks the passphrase and sends it as the input; a backup's
new file is its own (`create_new`, 0600, a temporary name and a rename with
`--overwrite`). A `restore` runs while the node is stopped: the daemon stops,
runs it, and starts again (`Daemon::run_until`), and with `NERVE_OWNER` the
program refuses a backup that would change one of the four `machine.*`
settings above. A program
with `NERVE_OWNER` refuses a change of `machine.user`, `machine.allow_root`,
`machine.sudo_path` and `machine.shell`, and names the owner in the audit's
settings entries (`"user"`). Starting and stopping the service is the service
manager's: on Linux the service helper (`/usr/local/lib/nerve-node/service-control`,
`start|stop|restart` of the unit and nothing else) through `pkexec`, with its
own action `org.nerve-protocol.node.service-control`, which a polkit rule
(or on polkit 0.105 a `.pkla` file) gives the owner (`subject.user`,
`unix-user:`) in a local active session; the rule also gives the owner
systemd's `manage-units` for that unit and those verbs (never a `.pkla` file
for it, which could not name the unit). On Windows the service's DACL. A
command that runs as the owner (`user` mode, `allowlist` with `as_owner`) is
that owner, as is one that gets a process outside the node's tree (as
above); one of `nerve-run` is not.

### Folder ACLs

On the installed Linux node `nerve-run` gets the folders of every pairing
whose commands run as it (`acl::wanted`: not user mode, not allowlist mode
with `as_owner`; their `exec::container_grants`, the node's own folders and the protected
entries split out as for Landlock, joined over the pairings) as POSIX ACL
entries (`crate::acl`): `user:nerve-run` with the folder's rights (a folder
`r` → `r-x`, `w` → `-wx`, `x` → `--x`; a file `r`, `w`, and `x` only for a
file someone may run already) on the folder and everything below it, and on
each folder below the default entries `user:nerve-run` and `user:<owner>:rwx`
(a default entry the owner had for itself is left as it is).
The mask grows to let the entry through and is never narrowed; it goes with
the last named entry, which gives the file its mode back. A folder of the
owner's above a grant that others may not enter gets `user:nerve-run:--x`; a
folder of another account's there that `nerve-run` cannot enter makes the
grant fail. With Landlock the pass-through entry gives nothing more; without
it, `nerve-run` reaches through it whatever below is open to others, and
`status`'s `home_warning` says so for the owner's home (with a grant below
it, or the home open to others). A default ACL without an entry of
`nerve-run` is never removed; one the owner had before the grant keeps its
plain entries and the owner's own named entry when the node's come off
(`defaults` and `own_entries` in the record, and a folder made below one
later), one the node made goes, also on a folder that was there below such
a folder without one (`made_defaults`). The node writes the attributes itself
(`system.posix_acl_access`, `system.posix_acl_default`), on its thread with
the owner's file system ids, so only the owner's files change: links, files
of other accounts, files with more than one name and other file systems
below a grant are left alone. `acl.json` in the state folder records the
uid, the owner's uid, the grants, the pass-through folders, the grants that
failed and what of the default ACLs is the owner's (`defaults`,
`own_entries`, `made_defaults`); a sync walks the
grants that are new, changed, failed last time or gone (and everything when
the uid or the owner changed). A grant that went inside one still given,
whose path a link now crosses, is taken off by a walk of the outer grant,
if that walk saw all of it: one that skipped a folder on another file system
or one the owner may not list leaves the inner grant `stale`, until its own
walk goes through.
A sync runs at the start (also for failed grants), on each config version,
on `folder.grants`, and before a call of `nerve-run` (`exec.run`, `fs`),
where a failed grant is tried again at most once a minute (`ACL_RETRY`).
The call is refused while an entry that should have come off is left
(`stale`), for every pairing of `nerve-run`. `uninstall` takes every
recorded entry off as root before it removes `nerve-run`, outer grants
first (an outer walk counts for the grants inside only as above), gives what `nerve-run` owns below the grants to the owner (to root
when the owner's account is gone) but for what is no folder and has more
than one name (it may lie outside every grant, and ownership goes with the
file; counted, and `uninstall` says how many), and stops if an entry stays.

## 6. Audit log

`<state>/audit.jsonl`, one JSON line per event: settings changes (with old
and new value), calls allowed or forbidden (a refusal with its reason), commands killed
for their memory limit (`decision` `killed`, `code` `memory`, with the
reason), the relay's tunnels (`"kind": "relay"`, one per tunnel when it ends: `node`,
`center`, `from`, `start`, `end`, `reason`, `up`, `down`; never a token), and what happened to the config
file itself (`"kind": "config"`, `event` `refused`, `signed`, `accepted`, `restored` or
`not_recorded`, with the file and the reason), and what the owner did to the node
(`"kind": "node"`, `event` `install`, `setup`, `update` or `uninstall`, with
its `steps` and the `error` that stopped it), and each key rotation
(`"kind": "key"`, `center`, `event` `node-key`, `node-key-refused`,
`node-key-unanswered`, `node-key-grace-ended`, `center-key`,
`center-key-refused` or `center-key-grace-ended`, and a `detail` with the
public keys or pins; never a private key). It holds targets (paths, command lines), never
file content or output; a target longer than 512 characters is cut there
and says so; the `audit/decision` event carries the same cut target, and the
center cuts what it gets the same way and keeps at most 500 decisions and
1 MiB of them. When the file would pass 10 MiB it is moved to `audit.jsonl.1`,
replacing the older one, so the log keeps at most about 20 MiB; when the
move fails the entry is still written, past that bound, and the node logs the
failure once. Refused calls get at most half of a full file: past that the
oldest refusals are dropped instead of the file being moved, so a center
that makes refused calls cannot push out what the node allowed or changed.
`nerve-node audit [--denied] [--follow]` shows both files, `audit.jsonl.1`
first, and `--follow` finishes the old file after a move before it reads the
new one.

## 7. Capability providers

A local program, such as a desktop app, can add capabilities to the node
without talking to a center: it attaches as a **provider**, on the installed
node to its provider socket `/run/nerve-node/provider.sock`, on a node run by
hand to its control socket. Linux only for now: the node tells which program
asks from `/proc/<pid>/exe`, and Windows' pipes take no provider.

### Who may attach

Only a program the owner names in `providers.allowed` (§2), by a name and the
absolute path of its executable (`nerve-node cap provider allow desk
/usr/lib/nerve-desktop/nerve-desktop`; `cap provider rm desk` takes it off).
None is allowed by default; only the owner changes the list, as no center document
holds it. A name is 1 to 32 of `a-z`, `0-9` and `-`, starting and ending with a letter
or digit, and not `node` or `config` (the providers of the node's own capabilities
and of those in `node.toml`).

On a node run by hand the provider connects like the CLI: the socket's user
check (its own user or root) and the token hold for it too, and so does the
refusal of a process below a command of a center. On the installed node it
connects to the provider socket (§5), which takes no token: the node tells
the caller by the account the kernel names for it (`SO_PEERCRED`). An
account that is not the owner (root always is one) is told `refused: only
the owner of the installed node and root attach a provider to it` as it
connects, by its uid alone, so it holds a place only for that comparison
(the node looks the owner's account up as the socket starts, and again at
most once a minute, off the connections); a process below a command of a center
is refused as on the owner socket, and one with `no_new_privs` (every
confined command keeps it) too, told so: `refused: this program runs with
no_new_privs, …`. The node reads the process's status and parents for that
with the same rights it looks at its program with (below), so a `/proc`
mounted `hidepid` hides no command that runs as the caller's account; a
status it cannot read refuses (`refused: the node cannot tell how the
program that asks runs`). A command that runs as root (the sudo list, or
root as its account) keeps no `no_new_privs`, so a program it starts as the
owner through two or more of root's processes may pass where `/proc` hides
root's processes from the owner: the check is a guard against mistakes, as
the owner socket's is. The
provider socket takes `hello` only, and the installed node's control socket
takes no `hello` (`refused: the installed node takes a provider's hello on
/run/nerve-node/provider.sock only`): root, who may connect there too, would
meet a check that reads as the node and holds no pidfd.

The provider sends one request, `hello`, with the control socket's token on
a node run by hand (the provider socket takes none, and ignores one):

```json
{"method": "hello", "token": "…",
 "params": {"role": "provider", "name": "desk",
            "capabilities": [{"id": "lamp", "summary": "The desk lamp.",
                              "actions": {"on": {"effect": "write", "summary": "…",
                                                 "params": {"type": "object"},
                                                 "result": {"type": "object"}}}}]}}
```

The node refuses it, with nothing attached, when:

- `providers.allowed` names no provider `name`;
- the process's executable, as the kernel resolved it, is not the one the
  entry names once that is resolved (a link to the program is the program; a
  program replaced since it started is not). The node looks with the caller's
  own rights, as the kernel shows a process's program only to its own
  account: the node of root, and a caller of the node's own account, look
  themselves; for an owner the installed node takes the owner's file system
  ids (`account::FsAs`) to read `/proc/<pid>/exe` and resolve the entry; for
  root, whose processes hold more rights than the node, it starts its own
  program as root (`nerve-node __provider-check <pid> <exe>`, its environment
  cleared, as a command of root starts; it prints the program, whether it is
  the entry's, `no_new_privs` and the parents) to look, and refuses when it cannot
  (`refused: the node cannot tell which program of root asks`). It neither
  holds CAP_SYS_PTRACE nor skips the check. The provider socket takes the
  caller's pidfd as it accepts the connection (`SO_PEERPIDFD`, Linux 6.5); a
  caller whose process ended before the node looked, or while it looked, is
  refused (`refused: the program that asked has ended`), also where its pid
  reads well, so on such a kernel a reused pid is not taken for it. A kernel
  that will not give the pidfd of a process already gone refuses the same; a
  kernel without `SO_PEERPIDFD` leaves the node the pid alone, and the check
  then catches mistakes only, as on the owner socket. Between the check and
  the attachment the node reads `providers.allowed` again and refuses an
  entry removed or changed meanwhile;
- a provider of that name is attached already;
- the fragment is not 1 to 16 capabilities of 1 to 64 actions each, with
  names of 1 to 64 letters, digits, `-` and `_` (a center would leave out a
  longer name); a capability is named twice, takes the
  name or the profile of one of the node's own (`node`, `fs`, `exec`,
  `settings`, `audit`) or of the center's (`job`, `stream`: the center
  serves `job.status`, `job.cancel`, `stream.read` and `stream.close` on
  every node itself, harness.md §4.4, §4.5), is added by another attached
  provider, or is the `cap` of one of the config's capabilities (§2, any
  platform, offered or not); or a
  capability declares anything but `id`, `profile`, `summary` and `actions`
  (no events, state or streams: the node forwards calls only, and the node,
  not the provider, says `provider` and `exposure`);
- no action is left once those whose schemas are outside the subset are
  left out (below).

An action's `params` and `result` must keep to the schema subset of
protocol.md §6.1; an action without `params` takes any arguments, as
`{"type": "object"}`. The node leaves out an action whose schemas do not
keep to it, with the reason (`params: /properties/n/oneOf: oneOf:
alternatives are not supported: …`), and a capability with no action left;
the provider's other actions attach.

The check tells programs apart, not users: a process of the same user can
still make the allowed program attach for it. Allow only programs you trust.

### While it is attached

The answer is `{"ok": {"name", "capabilities": [ids], "broken": [{name,
reason}]}}`, `broken` naming each action left out as `cap.action` (the
reason is one line of at most 300 characters, since it holds the
provider's own names), and the connection stays. The node reads the provider's lines while it writes its own, so a
provider may answer one call before it reads the next. The node lists each
capability in every center's descriptor with
`provider: <name>` and cuts it by that center's policy as its own (§3): `caps`
hides it or turns it off; in `allowlist` mode an action is shown only when an
allow rule covers it; in `folder` mode by its effect and paths as any other
(a read, write or execute action that names no path only where it is set `on`);
sense and actuate only with `on`. The descriptor's `rev` changes, so every center gets
`node/descriptor_changed`. `status` lists the attached providers, each with
the actions left out and why (`provider desk: lamp.dim left out: <reason>`;
`status --json` has them as `broken`), and the node logs each one as a
warning.

A center's call to such an action is first checked against the action's
`params`: arguments that do not fit are refused with `invalid_args`, whose
`data` names the `field` and what was `expected` (protocol.md §6.1), before
the policy and without an audit entry. Then it is decided and audited by the
node like any other, deny rules and `caps` included. Its rule targets are the
arguments its schema marks with `x-nerve-path` (top-level strings, `read` or
`write`), each resolved as the command account sees it (`WirePath::parse`
under `account::FsAs`), as an `fs` call's path is. Only the folders the owner
granted count for them: the command account's own folders (its home, `/tmp`,
`/var/tmp`, marked `own` in the access block) are that account's, while the
program works with the owner's rights, so a path there is in no folder, and
its read goes only where every account may read (Modes). The folders, the rules,
the protected paths and the node's own folders judge them, and the audit
entry names them (joined by `, `); a path that does not resolve is refused
with `bad_path` and audited with the text given, once the node acts as
itself again (the command account may not write the node's log). A path argument that may hold
other paths counts with what lies below it, as the program may read or write
there. That is a folder, or a path a write names that does not exist yet (the
program may make a folder there), or one the node cannot look at; a file holds
nothing, and is judged by itself alone. For such a path, a protected
entry below it that no folder releases for its access, a place below it
that a deny rule of the action's scope may cover (the rule's pattern up to
its first wildcard lies below the path, or the path below it and a wildcard
follows), or in folder mode a folder below it without that flag, refuses the
call. An `execute` action runs where its paths are, so for it the entries
and folders below need `x` as well, as the path itself does. The refusal names the path handed over, not the protected entry, the
folder or the deny rule below it, which the center is not shown. A program
follows links, which the node's own walks never do: once the call is
allowed, the node walks each such path as the command account (and each
folder a link there leads to, once, after that link passed). Where the
program runs as another account than the walk (on the installed node: the
owner or root, while the walk is `nerve-run`'s), or as root while the node is
not root (a walk with root's file ids, `account::FsAs`, keeps the node's
rights, not root's), a folder the walk may not list refuses the call (`<path> holds a folder the node may not look into, so
it cannot tell where the links there lead`; where it is the handed folder
itself, as one granted `w` without `r` is, `<path> is a folder the node may
not list (one granted without `r`, or one only its owner may enter), so it
cannot tell where the links in it lead`), as the program could follow a
link there, and so does an entry whose type the walk cannot tell (on a
filesystem that names no types, in a folder the walk may list but not
enter); where both are one account, such a folder or entry is left out, as
the program cannot look there either. The node judges the
place each link leads to in the stead of the path it lies below, with the
same access and the call's other paths; one the call may not reach refuses
it, and the refusal names the path handed over and the link, not where it
leads. A link that leads within the path it lies below, or within the
folder it was found in (a folder a link that passed leads to), is judged as
the other names there. A link that leads nowhere counts only for a write, at
the place it names; a link the node cannot follow, or more than 200 000
entries below all the call's paths together (those of the folders the links
lead to included), refuse the call. A call dropped while the node walks (its
deadline passed, or the center cancelled it) stops the walk and is audited
`forbidden` with code `cancelled`; it never reaches the program. A marked path to write that is itself a link is refused
with `bad_path`, since the program would act on the place it leads to. The
refusal the center gets names each marked path as given, and a place below it
below the given one, never as resolved (resolved as the command account, a
link of another of its processes under `/proc` leads where that process
works); the audit entry names the resolved path. So does the refusal of an
`fs` call for its path, and of `exec.run` for a `cwd` it gives. In
folder mode, where commands cannot be confined (§2), an `execute` action
with paths is refused as `exec.run` is, and not offered. What a program writes below
a folder is not checked for the places whose writes run code later (`.git`,
`.envrc`, `.vscode`, `.idea`), as an `fs.write` is: the program may make
them anywhere below it. An argument the schema does not mark is no path to
the node, which the policy cannot judge; in folder mode an action with no
marked path needs `on` (§2, Modes). A marked argument left
out or `null` names no path; with none, the target is `<cap>.<action>`. Only an allowed
call whose arguments fit reaches the provider, with each marked path as the
node resolved it; the arguments must fit again with the resolved paths, and a
resolved path must be valid Unicode, so the program is handed the path judged
(else `bad_path`). As one line:

```json
{"id": 7, "method": "invoke", "params": {"cap": "lamp", "action": "on", "args": {}}}
```

The provider answers `{"id": 7, "ok": value}` or `{"id": 7, "error": "text",
"code": "io"}`, one line each, at most 1 MiB. Of its codes `invalid_args`,
`unavailable`, `busy`, `timeout`, `too_large`, `internal`, `conflict`,
`bad_path` and `io` reach the center; any other becomes `internal`, as
`forbidden` and `disabled` are the node's words. When the call ends before the
answer (the center cancels it, its deadline passes, its session or link ends)
the node sends `{"method": "cancel", "params": {"id": 7}}` and drops a late
answer. The provider learns nothing of the center: not its name, its session
or its policy.

The path is checked when the call comes; the provider uses it afterwards
with its own account's rights (the owner's, or root's for a program of root
on the installed node), so a link put in or swapped in between is not
caught. A provider is a program the owner allowed and trusts. For root's
program such a link reaches root's rights, also from a command of
`nerve-run` with `w` in a granted folder; the owner keeps its actions that
take paths away from the folders a center may write in. Inside a granted
folder its flags decide a program's path, not the owner's own access to the
file, so root's program on a node another account owns reads and writes
there what only root or another account may; the node does not check a
path with the owner's rights for it.

A center with the settings grant may add allow rules and `on` entries for a
provider's capability like for any other, and take away `off` and `hidden`
entries and deny rules, except for one that senses or actuates, one that no
attached provider offers now, and an action (`cap.action`) that an offered
capability does not have now: the node knows the effects only of what an
attached provider offers, so what it does not know may sense or actuate once
it comes.
Only the owner adds or takes away those entries (`settings.set` refuses the
document with `forbidden`), so a center cannot drop its own deny rule for such
a capability either. What stays open: an `on` entry or an allow rule for a
capability or for one of its actions, written while it did not sense, still
counts when a provider later offers it with a sense or actuate action under
the same name (a new version of the program that makes `screen.info` sense). The node
cannot tell a center's entry from the owner's then; the owner checks the
entries after such an update.

### Detach

The capabilities go when the connection does: the provider closes it or
exits, sends a line that is no JSON or longer than 1 MiB, the owner takes it
off `providers.allowed` or names another program for it, the owner declares
one of its capabilities in `node.toml` (`[[capability]]`, §2), or the node
stops.
The descriptor's `rev` changes again, a call that waited for an answer fails
`unavailable`, and a call that names the capability afterwards is
`unknown_capability`. A provider that comes back sends `hello` again.

A provider holds one of the socket's places for as long as it is attached:
16 on the provider socket, 64 on the control socket of a node run by hand.

