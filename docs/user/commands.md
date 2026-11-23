# Commands

`nerve-node --help` lists the commands in groups, and
`nerve-node help <command>` has the rest of one. The owner of the installed
node runs them without `sudo`; `install`, `update`, `uninstall` and
`sudo on` need it. The desktop app's `nerve` takes the same
commands on Linux. On Windows the app runs them for you: `nerve.exe` with a
command is the app's way to the node, not one for a terminal, and
PowerShell neither waits for it nor gets its exit code.

## `nerve-node`

| Group | Commands |
|---|---|
| Set up | `install`, `setup`, `update [--pre\|--tag <tag>]`, `uninstall [--purge]`, `backup <file>`, `restore <file>`, `service start\|stop\|restart` |
| Centers | `center`, `center add -`, `center rm\|pause\|resume\|rotate-key [<name>]`, `center settings on\|off` |
| What a center may do | `mode [<mode>] [--for H]`, `folder`, `folder add <path> <rights>\|none`, `folder rm`, `folder sync`, `network [on\|off]` |
| | `rule`, `rule add allow\|deny '<command>'`, `rule rm '<entry>'`, `rule edit`, `sudo [on\|off]` |
| Watch and stop | `status`, `audit [--refused]`, `audit clear`, `log [--problems]`, `log clear`, `panic`, `unlock` |
| More | `cap`, `cap set\|add\|edit\|rm`, `provider`, `provider add\|rm`, `proxy`, `proxy set\|off` |
| | `relay`, `relay on\|off\|add\|set\|token\|rm`, `ui`, `ui on\|off`, `ui token [add\|rm]` |
| | `config get\|set\|unset\|add\|rm\|accept`, `run` |

`update --pre` takes the newest release, a pre-release too; `update --tag
<tag>` one release by its tag ([install](install.md)). The desktop app has a
switch for pre-releases in its settings.

A noun alone shows (`mode`, `folder`, `rule`). `add` and `rm` change a list,
`set` a value, `on` and `off` a switch. `-` as a value reads it from stdin,
such as a pairing link or a passphrase.

Every command takes `--config-dir`, `--state-dir` and `--json`. One that
works on one center takes `--center <name>`, needed only with more than one.
`nerve-node` alone prints the six everyday commands.

`--json` prints one JSON value for a program to read. Fields are only added;
a renamed or removed field is a CHANGELOG "Breaks" line
([CLI output](../dev/settings-and-config.md#cli-output---json)).

`run` runs the node in the foreground, for a machine without systemd.

## `nerve-center`

| Command | Does |
|---|---|
| `install` | Runs the center as a service (as root) |
| `set [<name> <value>]` | Shows or changes the service's settings, and restarts it |
| `service start\|stop\|restart` | Starts, stops or restarts the service |
| `status` | Whether it runs, its addresses and its machines |
| `pair` | Makes a link that pairs a new machine |
| `nodes [list\|disable\|enable\|rm\|rename\|settings\|sudo]` | Shows the machines, or turns one off, on, removes, renames it, its settings, its sudo |
| `token new\|list\|rm` | Makes, lists or removes harness tokens |
| `sessions [end <id>]` | Shows the harnesses' sessions, or ends one |
| `checker [on\|off\|block\|skip\|model\|machine]` | Shows the action checker, or changes its switches, rules and model |
| `caps <machine> [add\|rm]` | Shows a machine's capabilities, or adds or removes one (`add --params` for its arguments) |
| `stats`, `audit [allow\|deny\|skip <ID>]` | Shows the statistics, or the latest decisions and makes a rule of one |
| `key rotate\|finish`, `config [<setting> <value>]` | A new center key; the center's name, retention, pairing time, log level |
| `log [--last N] [--problems] [--follow]` | Shows the center's log |
| `owner-token [--new]` | Shows the token that logs in to the web UI |
| `update [--pre\|--tag <tag>]`, `uninstall [--purge]` | Updates or removes the service; `--pre` takes the newest pre-release, `--tag` one release |
| `backup <file>`, `restore <file>` | Saves or restores its identity and pairings |
| `nerve-center` alone | Runs the center; MCP on stdin, for a harness |

From `pair` to `config` they ask the running center, as the app and the web
UI do, also with the web UI off; run them as root for the installed center.
Nothing is only in a window. On Windows the app's center pages do them.

Its main settings are `--name`, `--public-url`, `--listen`, `--ui` and
`--mcp`, each also a `NERVE_CENTER_*` variable ([center](center.md)).
`nerve-center --help` lists the rest.
