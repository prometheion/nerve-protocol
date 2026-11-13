# Commands

`nerve-node --help` lists the commands in groups, and
`nerve-node help <command>` has the rest of one. The owner of the installed
node runs them without `sudo`; `install`, `update`, `uninstall` and
`sudo on` need it. The desktop app's `nerve-node-desktop` takes the same
commands.

## `nerve-node`

| Group | Commands |
|---|---|
| Set up | `install`, `setup`, `update`, `uninstall [--purge]`, `backup <file>`, `restore <file>`, `service start\|stop\|restart` |
| Centers | `center`, `center add -`, `center rm\|pause\|resume\|rotate-key [<name>]`, `center settings on\|off` |
| What a center may do | `mode [<mode>] [--for H]`, `folder`, `folder add <path> <rights>\|none`, `folder rm`, `folder sync`, `network [on\|off]` |
| | `rule`, `rule add allow\|deny '<command>'`, `rule rm '<entry>'`, `rule edit`, `sudo [on\|off]` |
| Watch and stop | `status`, `audit [--refused]`, `audit clear`, `log [--problems]`, `log clear`, `panic`, `unlock` |
| More | `cap`, `cap set\|add\|edit\|rm`, `provider`, `provider add\|rm`, `proxy`, `proxy set\|off` |
| | `relay`, `relay on\|off\|add\|set\|token\|rm`, `ui`, `ui on\|off`, `ui token [add\|rm]` |
| | `config get\|set\|unset\|add\|rm\|accept`, `run` |

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
| `nodes [list\|disable\|enable\|rm <name>]` | Shows the machines, or turns one off, on, or removes it |
| `token new\|list\|rm` | Makes, lists or removes harness tokens |
| `log [--last N] [--problems] [--follow]` | Shows the center's log |
| `owner-token [--new]` | Shows the token that logs in to the web UI |
| `update`, `uninstall [--purge]` | Updates or removes the service |
| `backup <file>`, `restore <file>` | Saves or restores its identity and pairings |
| `nerve-center` alone | Runs the center; MCP on stdin, for a harness |

`pair`, `nodes` and `token` ask the running center, also with its web UI
off; run them as root for the installed center (on Windows in an
administrator's terminal).

Its main settings are `--name`, `--public-url`, `--listen`, `--ui` and
`--mcp`, each also a `NERVE_CENTER_*` variable ([center](center.md)).
`nerve-center --help` lists the rest.
