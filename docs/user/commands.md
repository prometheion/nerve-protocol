# `nerve-node` commands

Run them as a normal user on the machine. On a node
[installed as a service](service.md), the owner (the account that ran
`install`) runs them without `sudo`; `install`, `update`, `uninstall` and
`sudo on` need `sudo`. `nerve-node --help` and `nerve-node <command> --help`
list the same. The center's web UI has a Help page with them too.

On Windows there is no `nerve-node` for a terminal: the
[desktop app](desktop.md) is the only way to the node, and it does each of
these commands in its pages ([in a terminal](desktop.md#in-a-terminal-linux)).
On Linux the desktop app's `nerve-node-desktop` takes the same commands, and
where the app took over the installed node, `nerve-node` stays a link to it.

Every command takes `--config-dir` and `--state-dir`
([where files live](install.md#where-files-live)). A command that works on
one center takes `--center <name>`. You need it only when more than one
center is paired.

## Pair and connect

| Command | Does | Page |
|---|---|---|
| `center add '<link>' [--name N] [--yes]` | Pair with a center | [pairing](pairing.md) |
| `center add - [--name N] [--yes]` | The same, with the link read from the first line of stdin, so it never shows in the process list | [pairing](pairing.md) |
| `center rm [<name>]` | Unpair and delete the key | [pairing](pairing.md#unpair) |
| `center rotate-key [<name>] [--end-grace]` | Give this machine a new key for a center, or end the old key's 7 days | [pairing](pairing.md#rotate-the-machines-key) |
| `center` | List centers, their mode and grant | [pairing](pairing.md) |
| `center pause [<name>]`, `center resume [<name>]` | Stop or restart the link to a center | [stop](stop.md#pause) |
| `center settings on\|off [<name>]` | Let a center change settings | [settings grant](settings-grant.md) |
| `proxy set <url> [--pin=P] [--header 'N: v'] [--header -]`, `proxy`, `proxy off` | Dial centers through a proxy, or a relay (`proxy set '<nerve://relay link>'`); a URL with a user name and no password asks for it, `--header -` reads headers from stdin | [proxy](proxy.md) |
| `relay on <ip:port>`, `relay off` | Let other nodes reach this node's centers through it | [relay](relay.md) |
| `relay add <name> [--to C] [--address HOST[:PORT]]`, `relay rm <name>`, `relay` | Give a node a relay link (its token in it), take it away, see who is connected | [relay](relay.md) |
| `relay set <name> [--to C] [--max-links N] [--max-opens-per-minute N]` | Change which centers a relayed node may reach (`--to '*'`: every one), or give it (a relay behind this one) limits of its own (`default`: the relay's) | [relay](relay.md#limit-a-node-to-some-centers) |
| `relay token <name> [--address HOST[:PORT]]` | Give a relayed node a new token in a new link; its centers and limits stay | [relay](relay.md#on-the-relay) |

## What a center may do

| Command | Does | Page |
|---|---|---|
| `mode`, `mode allowlist\|folder\|user [--for HOURS] [--as-owner]` | Show each center's mode, or choose it; with allowlist, `--as-owner` runs the allowed commands as you instead of `nerve-run` | [modes](modes.md) |
| `folder add <path> r\|rw\|rwx…\|none` | Grant a folder, change its rights, or close one inside another (`none`) | [modes](modes.md#folders) |
| `folder rm <path>`, `folder` | Remove or list folders | [modes](modes.md#folders) |
| `network off\|on` | Keep the center's commands off the network in every mode (no socket but unix ones; no command of its sudo list runs meanwhile), or let them on it again; where they would run as you, or the machine has no seccomp filter for it, none of them runs while it is off | [modes](modes.md#no-network-for-a-centers-commands) |
| `folder sync` | Give `nerve-run` its entries on everything in the granted folders again, also on what was moved in (the installed Linux node; a pass over every granted folder) | [modes](modes.md#the-account-nerve-run-linux) |
| `rule add allow\|deny '<command>' [--action A [--arg F=V]]` | Add a command rule (a trailing ` *` covers what starts so; one that starts with `sudo` goes on the sudo list), a rule on an action's arguments (`'lamp.set:room=office'`), or with `--action` the rule of an audit entry, `--arg` holding it to one argument | [rules](rules.md), [arguments](rules.md#rules-on-an-actions-arguments) |
| `rule rm [allow\|deny\|sudo] '<entry>'` | Remove a rule, as `rule` shows it or the command line that made it; the list only when it is on two | [rules](rules.md#list-change-and-remove-rules) |
| `rule edit allow\|deny\|sudo '<entry>' '<new>'` | Change a rule in place, as one change | [rules](rules.md#list-change-and-remove-rules) |
| `rule [allow\|deny\|sudo]` | List rules, and after them those whose arguments the action no longer takes | [rules](rules.md#list-change-and-remove-rules) |
| `cap set <cap> on\|off\|hidden` | Switch a capability or action | [rules](rules.md#switch-a-capability-off) |
| `cap [--center C]` | List every capability: the node's own, yours in `node.toml` and those of the programs you allow, each action (and a program's state key, event and stream, with its kind) with its effect, where it comes from and, per center, whether it may use it now and the switch you set (a stopped node: the switch only, `default` where the mode decides; `settings`: the grant, `center settings`) | [providers](providers.md#see-what-is-there) |
| `cap add <cap.action> --effect E [--summary S] [--params JSON\|--params -] [--result text\|JSON\|--result -] [--timeout SECS] [--platform any\|linux\|windows] -- <program> <args>` | Declare a capability of your own that runs a fixed command as `nerve-run` (the installed node), `{field}` words taking the call's arguments | [config capabilities](config-capabilities.md) |
| `cap edit <cap.action> [the options of add] [-- <program> <args>]`, `cap rm <cap.action>` | Change one of them (what you give replaces), remove it | [config capabilities](config-capabilities.md#add-one) |
| `cap rm <cap.action> --center <name>` | Remove a capability that center added itself | [config capabilities](config-capabilities.md#capabilities-a-center-adds) |
| `provider add <name> <exe>`, `provider rm <name>`, `provider` | Allow a program to add capabilities, take it off, list them | [providers](providers.md#allow-a-program) |
| `sudo on`, `sudo off`, `sudo` | The sudo switch | [sudo](sudo.md) |
| `config get\|set\|unset\|add\|rm <key> [value]` | Read or change any setting | [config](config.md) |
| `config accept` | Take a `node.toml` you edited by hand | [config](config.md#do-not-edit-the-file-by-hand) |

## Run and watch

| Command | Does | Page |
|---|---|---|
| `run` | Run the node in the foreground (Linux; on Windows the node runs only as the installed service, and `run` is refused) | [pairing](pairing.md) |
| `status` | Show whether it runs, the links, the confinement and the [limits per command](limits.md) | [troubleshooting](troubleshooting.md) |
| `audit [--refused] [--last N] [--follow]` | Show what was allowed and refused | [audit](audit.md) |
| `audit clear` | Start the audit log afresh; the entries so far stay in its older file | [audit](audit.md#clear-it) |
| `log [--problems] [--last N] [--follow]` | Show the node's log | [logs](logs.md) |
| `log clear` | Empty the node's log | [logs](logs.md#clear-it) |
| `panic`, `unlock` | Stop everything, then allow it again | [stop](stop.md#panic) |
| `ui`, `ui on [--listen ADDRESS] [--host HOST]… [--new-cert]`, `ui off` | The node's web UI (the installed node on Linux): show it, turn it on, turn it off | [node web UI](node-web-ui.md) |
| `ui token add <label>`, `ui token`, `ui token rm <label>` | Make, list and revoke the tokens that log in to it | [node web UI](node-web-ui.md#tokens) |

## Install and set up

| Command | Does | Page |
|---|---|---|
| `install [--owner=root --accept-root-owner \| --owner=none]` | Install the node as a service under its own user, make `nerve-run` and take you as the owner (with sudo; on Windows the desktop app's installer does it); run by root itself, make root the owner after its yes, or with the flags, and keep it at a later install; `--owner=none` leaves the node without an owner | [service](service.md#install) |
| `setup` | Name the node, choose where the keys are, pair the first center, choose its mode and a folder | [service](service.md#setup) |
| `update [--from FILE]` | Put the latest release in place and restart the service | [service](service.md#update) |
| `service start\|stop\|restart` | Start, stop or restart the installed service | [service](service.md#start-and-stop) |
| `service status` | Show whether the node is installed as a service, whether it runs, and its program and version | [service](service.md#start-and-stop) |
| `uninstall [--purge]` | Remove the service, `nerve-run` and its ACL entries, the node's user and the program | [service](service.md#uninstall) |
| `backup <file> [--include-keyring] [--overwrite] [--passphrase-file F\|-]` | Write the config and keys to a file that a passphrase protects | [backup](backup.md) |
| `restore <file> [--replace] [--secret-storage file\|keyring] [--without-proxy] [--passphrase-file F\|-]` | Put a backup in place of this node's, or on another machine | [backup](backup.md#restore) |

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
one JSON value from stdout. Fields are only ever added: one is renamed or
removed only with a change of the format, which the changelog names under
"Breaks". A script ignores the fields it does not know.

- The read commands print their data: `status`, `center`, `folder`,
  `rule` (the lists, and `stale`: each rule whose arguments the action no
  longer takes, with why), `cap` (`capabilities`, one row per action, state key,
  event or stream with `"kind"` on all but actions, an action's arguments
  schema as `"params"`, `programs`, `config`, each capability
  of `node.toml` as declared, its schemas as JSON, `running`, and for one
  center, with `--center` or where only one is paired, `center`, `caps` and
  `known`, what `cap set` switches), `provider`, `config get`,
  `proxy`, `relay`, `sudo`, `service status`, and `audit` and `log`
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

## What changed with the account nerve-run

The node runs `folder` and `allowlist` mode commands as `nerve-run` on the
installed Linux node (issue #142), so a few commands went or changed:

| Before | Now |
|---|---|
| `setup --create-user <name>`, and setup's question for the account of the commands | gone: commands run as `nerve-run`, or as the owner |
| `config set machine.user <name>` (Linux) | refused: Windows only |
| `mode …` | `mode allowlist --as-owner` added |
| after `install`: `sudo nerve-node setup` | `nerve-node center add '<link>'`, then `nerve-node folder add <folder> rwx`; setup is optional |
