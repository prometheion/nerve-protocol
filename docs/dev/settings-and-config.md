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
   `machine.sudo_path`, `machine.secret_storage`, `machine.user` (Windows).
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
    fixed command, as `nerve-run` or as the owner, so none is in a center's
    document. A center with the grant may switch them by `caps` and its rules
    like any capability, within item 9.

One item is in the document a center reads and is still the owner's: the
record of the folders' real places, `policy.places`
([policy engine](policy-engine.md#protected-paths)). The node does not refuse
a write that differs there; it keeps the record as it was. The center adds no
entry and changes none, and an entry goes only with its folder.

Because the grant lets a center widen its rules up to `user` mode, a center
with the grant is as strong as `user` mode on that machine.

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
as](../user/service.md#the-accounts-commands-run-as)). A
[sudo](../user/sudo.md) command is root and is not kept out.
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
| `cap.refusal` | Why the node refuses calls of a capability of `node.toml` that runs as the owner, judged as before a call (`cap add` and `cap edit` warn of it) |
| `reload` | Reread `node.toml` (only a file the node signed) |
| `sudo.status`, `sudo.on`, `sudo.off` | The sudo switch |
| `folder.add` | `folder add`, judged by the node as the owner; it stores and records the real place |
| `owner.check` | Nothing; the CLI asks it before `install`, `setup`, `update`, `uninstall`, `backup` and `restore` |
| `hello` | A capability provider attaches; its connection stays ([node-local §7](spec/node-local.md#7-capability-providers)) |

Every method is refused from a process that runs below a command the node
started for a center, the reading ones too. That catches the processes that
stay below the command: one that leaves the tree (`( … & )`, `setsid -f`)
is not caught, so for a command without a sandbox the socket is no boundary,
as the node's files are none. For a `folder` mode command the token also
holds, as far as the sandbox does.

Windows has no control socket. It has a control pipe with the same lines,
which serves `status`, `folder.add`, `folder.set` and `folder.rm` only
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
([modes](../user/modes.md#the-account-nerve-run-linux)).

## The log level

`log.level` (`error`, `warn`, `info`, `debug`; `info` unless set) is a machine
setting of the owner: it is not in the document a center reads or writes. The
daemon applies it within a second of any change ([logging](logging.md)).

## The audit log

`audit.jsonl` in the state folder holds one JSON line per event: settings
changes, calls allowed or forbidden, and what happened to the config file. It
holds targets, never file contents or output. See
[the user guide](../user/audit.md) for sizes and rotation. It is not the log: [logging](logging.md).
