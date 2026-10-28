# `nerve-node` commands

Run them as a normal user on the machine. On a node
[installed as a service](service.md), the owner (the account that ran
`install`) runs them without `sudo`; `install`, `update`, `uninstall` and
`sudo on` need `sudo`, and on Windows `setup` too (there, a terminal opened
with "Run as administrator"). `nerve-node --help` and
`nerve-node <command> --help` list the same. The center's web UI has a Help
page with them too.

On Windows, `nerve-node-desktop.exe` is the desktop app. It runs these commands
itself, but a terminal does not wait for it: in a terminal use `nerve-node.exe`
from the release. Where the app took over the installed node, the installed
`nerve-node.exe` is removed, so download `nerve-node-x86_64-windows.exe` from the
release for a terminal; it works on the node the app installed
([the desktop app](desktop.md#in-a-terminal)). On Linux the installed
`nerve-node` stays a link to the app, and works in a terminal as before.

Every command takes `--config-dir` and `--state-dir`
([where files live](install.md#where-files-live)). A command that works on
one center takes `--center <name>`. You need it only when more than one
center is paired.

## Pair and connect

| Command | Does | Page |
|---|---|---|
| `center add '<link>' [--name N] [--yes]` | Pair with a center | [pairing](pairing.md) |
| `center rm` | Unpair and delete the key | [pairing](pairing.md#unpair) |
| `center rotate-key [--end-grace]` | Give this machine a new key for a center, or end the old key's 7 days | [pairing](pairing.md#rotate-the-machines-key) |
| `center ls` | List centers, their mode and grant | [pairing](pairing.md) |
| `center pause`, `center resume` | Stop or restart the link to a center | [stop](stop.md#pause) |
| `center grant settings write\|off` | Let a center change settings | [settings grant](settings-grant.md) |
| `proxy set <url> [--pin=P] [--header 'N: v'] [--password-stdin] [--headers-stdin]`, `proxy ls`, `proxy rm` | Dial centers through a proxy, or a relay (`proxy set '<nerve://relay link>'`) | [proxy](proxy.md) |
| `relay set <ip:port>`, `relay off` | Let other nodes reach this node's centers through it | [relay](relay.md) |
| `relay add <name> [--center C] [--address HOST[:PORT]]`, `relay rm <name>`, `relay ls` | Give a node a relay link (its token in it), take it away, see who is connected | [relay](relay.md) |
| `relay set-centers <name> [--center C]` | Change which centers a relayed node may reach | [relay](relay.md#limit-a-node-to-some-centers) |
| `relay set-limits <name> [--max-links N] [--max-opens-per-minute N]` | Give one relayed node (a relay behind this one) limits of its own | [relay](relay.md#limits) |
| `relay token <name> [--address HOST[:PORT]]` | Give a relayed node a new token in a new link; its centers and limits stay | [relay](relay.md#on-the-relay) |

## What a center may do

| Command | Does | Page |
|---|---|---|
| `mode set allowlist\|folder\|user [--for HOURS] [--as-owner]` | Choose the mode; with allowlist, `--as-owner` runs the allowed commands as you instead of `nerve-run` | [modes](modes.md) |
| `folder add <path> +r +w +x` | Grant a folder | [modes](modes.md#folders) |
| `folder set <path> -w` | Change a folder's rights | [modes](modes.md#folders) |
| `folder rm <path>`, `folder ls` | Remove or list folders | [modes](modes.md#folders) |
| `rule add allow\|deny\|sudo '<command>' [--wildcard] [--action A]` | Add a command rule, or with `--action` the rule of an audit entry | [rules](rules.md) |
| `rule rm allow\|deny\|sudo '<command>' [--wildcard] [--action A]` | Remove a rule | [rules](rules.md#list-change-and-remove-rules) |
| `rule edit allow\|deny\|sudo '<entry>' '<new>'` | Change a rule in place, as one change | [rules](rules.md#list-change-and-remove-rules) |
| `rule ls [allow\|deny\|sudo]` | List rules | [rules](rules.md#list-change-and-remove-rules) |
| `rule guard` | Put the guard's deny rules back that a pairing lacks, in place of its older texts | [rules](rules.md#the-guard-against-changing-the-node) |
| `cap set <cap> on\|off\|hidden` | Switch a capability or action | [rules](rules.md#switch-a-capability-off) |
| `cap ls [--center C]` | List every capability: the node's own, yours in `node.toml` and those of the programs you allow, each action with its effect, where it comes from and, per center, whether it may use it now and the switch you set (a stopped node: the switch only, `default` where the mode decides; `settings`: the grant, `center grant settings`) | [providers](providers.md#see-what-is-there) |
| `cap add <cap.action> --effect E [--summary S] [--params JSON\|--params-stdin] [--result text\|JSON\|--result-stdin] [--timeout SECS] [--platform any\|linux\|windows] -- <program> <args>` | Declare a capability of your own that runs a fixed command as `nerve-run` (the installed node), `{field}` words taking the call's arguments | [config capabilities](config-capabilities.md) |
| `cap edit <cap.action> [the options of add] [-- <program> <args>]`, `cap rm <cap.action>` | Change one of them (what you give replaces), remove it | [config capabilities](config-capabilities.md#add-one) |
| `cap provider allow <name> <exe>`, `cap provider rm <name>`, `cap provider ls` | Allow a program to add capabilities, take it off, list them | [providers](providers.md#allow-a-program) |
| `sudo on`, `sudo off`, `sudo status` | The sudo switch | [sudo](sudo.md) |
| `config get\|set\|unset\|add\|remove <key> [value]` | Read or change any setting | [config](config.md) |
| `config accept` | Take a `node.toml` you edited by hand | [config](config.md#do-not-edit-the-file-by-hand) |

## Run and watch

| Command | Does | Page |
|---|---|---|
| `run` | Run the node in the foreground | [pairing](pairing.md) |
| `status` | Show whether it runs, the links, the confinement and the [limits per command](limits.md) | [troubleshooting](troubleshooting.md) |
| `audit [--denied] [--last N] [--follow]` | Show what was allowed and refused | [audit](audit.md) |
| `audit clear` | Start the audit log afresh; the entries so far stay in its older file | [audit](audit.md#clear-it) |
| `log [--problems] [--last N] [--follow]` | Show the node's log | [logs](logs.md) |
| `log clear` | Empty the node's log | [logs](logs.md#clear-it) |
| `panic`, `unlock` | Stop everything, then allow it again | [stop](stop.md#panic) |

## Install and set up

| Command | Does | Page |
|---|---|---|
| `install [--owner=root --accept-root-owner \| --owner=none]` | Install the node as a service under its own user, make `nerve-run` and take you as the owner (Linux with sudo, Windows as administrator); run by root itself, make root the owner after its yes, or with the flags, and keep it at a later install; `--owner=none` leaves the node without an owner | [service](service.md#install) |
| `setup` | Name the node, choose where the keys are, pair the first center, choose its mode and a folder | [service](service.md#setup) |
| `update [--from FILE]` | Put the latest release in place and restart the service | [service](service.md#update) |
| `service start\|stop\|restart` | Start, stop or restart the installed service | [service](service.md#start-and-stop) |
| `service status` | Show whether the node is installed as a service, whether it runs, and its program and version | [service](service.md#start-and-stop) |
| `uninstall [--purge]` | Remove the service, `nerve-run` and its ACL entries, the node's user and the program | [service](service.md#uninstall) |
| `backup <file> [--include-keyring] [--overwrite] [--passphrase-file F]` | Write the config and keys to a file that a passphrase protects | [backup](backup.md) |
| `restore <file> [--replace] [--secret-storage file\|keyring] [--without-proxy] [--passphrase-file F]` | Put a backup in place of this node's, or on another machine | [backup](backup.md#restore) |

The center has five commands of its own, which a harness never runs:

| Command | Does | See |
|---|---|---|
| `backup <file>` | Write the center's identity and state to a file that a passphrase protects | [backup](backup.md#the-center) |
| `restore <file>` | Put a backup in place of this center's, or on another machine | [backup](backup.md#the-center) |
| `install` | Install the center as a service under a user of its own (Linux with systemd, as root) | [center](center.md#run-it-as-a-service) |
| `update [--from FILE]` | Put the latest release in place and restart the service | [center](center.md#update) |
| `uninstall [--purge]` | Remove the service, its user and the program | [center](center.md#uninstall) |

## For programs: `--json`

A program that drives `nerve-node`, such as a script, adds `--json` and reads
one JSON value from stdout:

- The read commands print their data: `status`, `center ls`, `folder ls`,
  `rule ls`, `cap ls` (`capabilities`, `programs`, `config`, each capability
  of `node.toml` as declared, its schemas as JSON, `running`, and for one
  center, with `--center` or where only one is paired, `center`, `caps` and
  `known`, what `cap set` switches), `cap provider ls`, `config get`,
  `proxy ls`, `relay ls`, `sudo status`, `service status`, and `audit` and `log`
  (`{"entries": [...]}`, the lines as the file holds them; with `--follow`
  one a line). `status` has `"daemon"`:
  `"running"`, with what the running node says, or `"not running"`.
  It names the installed node's `"owner"` and `"owner_is_root"` (root is the
  owner, so `user` mode runs as root), each center's `"account"` (the
  account its commands run as now, `null` on a node run by hand),
  `"as_owner"` and `"landlock"` (whether Landlock holds its commands now),
  the running Linux node's `"folder_grants"` (`"errors"`, `"stale"`,
  `"failed"`, `"skipped"`: what giving `nerve-run` its folders left; a failed
  grant is tried again; while `"stale"` names a folder, no command of
  `nerve-run` runs) and `"home_warning"` (on a kernel without Landlock,
  `{"home", "mode", "below", "warning"}` when `nerve-run` gets into the
  owner's home: `"mode"` when the home is open to other accounts, else
  `null`, `"below"` the folders given in it as you named them, the home
  itself where you give it whole; `null` with Landlock or where neither is
  so).
  `service status` has `"installed"`, `"state"` (`"running"`, `"stopped"`,
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
  same way. `relay add` and `relay token` add `"token"` (`node`, `token`,
  `address`, `link`, the `nerve://relay` link the other node pastes,
  `proxy`, the URL it sets with `proxy set`, and `pin`); `relay ls` has
  `"address"`, where a new link says the relay is,
  `backup` adds `"backup"` (`file`, `centers`, `saved`, and `left_out`, each
  with `what` and `why`: `keyring`, `does-not-fit` or `missing`),
  `center rotate-key` adds `"public_key"`, the new key,
  `folder add`, `folder set` and `folder rm` on the installed Linux node add
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
http://user@host:port --password-stdin` takes the proxy's password from the
first line of stdin, and `--headers-stdin` the headers from the lines after
it, one `Name: value` each, so neither shows in the process list. `cap add`
and `cap edit` with `--params-stdin` or `--result-stdin` take that schema as
all of stdin (one of the two per command). `setup` reads its answers
from stdin one line each. `center add` needs `--yes`.

## What changed with the account nerve-run

The node runs `folder` and `allowlist` mode commands as `nerve-run` on the
installed Linux node (issue #142), so a few commands went or changed:

| Before | Now |
|---|---|
| `setup --create-user <name>`, and setup's question for the account of the commands | gone: commands run as `nerve-run`, or as the owner |
| `config set machine.user <name>` (Linux) | refused: Windows only |
| `mode set …` | `mode set allowlist --as-owner` added |
| after `install`: `sudo nerve-node setup` | `nerve-node center add '<link>'`, then `nerve-node folder add <folder> +r +w +x`; setup is optional |
