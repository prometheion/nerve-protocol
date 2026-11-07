# Settings

Every setting of a node is in `node.toml`. The commands in this guide change
it for you; `nerve-node config` reaches any setting by its name.

```sh
nerve-node config get limits.max_running
nerve-node config set limits.max_running 8
nerve-node config unset limits.max_running     # back to the default
nerve-node config get center.lab               # a center's settings
```

| Command | Does |
|---|---|
| `config get <key>` | Prints one setting or a table |
| `config set <key> <value>` | Changes a setting |
| `config unset <key>` | Removes it, so its default applies |
| `config add <key> <value>` | Appends a value to a list |
| `config rm <key> <value>` | Removes a value from a list |
| `config accept` | Takes a file changed outside `nerve-node` |

A center's settings are under `center.<name>`, the name `nerve-node center`
shows. A value that does not fit is refused, and nothing changes. A running
node takes a change at once.

## The settings people change

| Setting | Default | Does |
|---|---|---|
| `node.name` | the host name | The name centers show |
| `machine.secret_storage` | `file` | `keyring` keeps the keys in the system keyring |
| `machine.command_env` | none | Variables of the service that `nerve-run`'s commands get too |
| `machine.shell` | `/bin/sh` | The shell that runs commands (root's, with `sudo`) |
| `log.level` | `info` | `error`, `warn`, `info` or `debug` |
| `limits.max_running` | 16 | Commands at once, over all centers |
| `limits.default_timeout_secs` | 600 | How long a command runs when its call names no time |
| `limits.max_timeout_secs` | 3600 | The longest any command runs |
| `limits.output_cap_bytes` | 16 MiB | Output of stdout and of stderr each; a result carries 1 MiB at most |
| `limits.command.memory_mb` | 4096 | Memory of one command, in MiB |

The full list is in [settings and config](../dev/settings-and-config.md#the-settings).

- Commands of `nerve-run` see only the variables you name in
  `machine.command_env`. Put no secret into the service unit
  ([environment](../dev/sandbox-linux.md#the-accounts-commands-run-as)).

## Limits per command

Each command gets a limit on its memory, its CPU and its processes. You set
what a command gets and the most a call may ask for:

| Setting | Default | Most a call may ask (`…_max`) |
|---|---|---|
| `limits.command.memory_mb` | 4096 MiB | 16384 |
| `limits.command.cpu_percent` | 200 (two CPUs) | 800 |
| `limits.command.processes` | 1024 | 8192 |

```sh
nerve-node config set limits.command.memory_mb 2048
nerve-node config set limits.command.memory_max_mb 8192
```

A call may ask for less, or more up to the most (`exec.run` takes
`memory_mb`, `cpu_percent` and `processes`). Past its memory a command is
killed, with all it started; past its CPU it is slowed; past its processes
it cannot start more. A center cannot change the limits.

`processes` counts the command and what it starts. A command with a
[`/proc` of its own](../dev/sandbox-linux.md#a-proc-of-its-own) has two
helpers of the node beside it, which the node allows on top: its cgroup's
`pids.max` then reads two more.

`nerve-node status` says whether this machine holds them. A node run by
hand without systemd runs its commands without limits
([where the limits hold](../dev/sandbox-linux.md#where-the-limits-hold)).

## Where the keys are

The node has a key per center, and one that signs `node.toml`:

- `file` (the default): files only the node's account can read.
- `keyring`: the system keyring (GNOME Keyring, KWallet). No copy stays in a
  file. At a terminal, `config set machine.secret_storage keyring` offers to
  install a keyring where none answers. On a node run by hand the keyring is
  yours: an allow rule for `secret-tool` or a like tool hands a center the
  node's keys ([keys](../dev/settings-and-config.md#where-the-node-keeps-its-keys)).

The change moves the keys at once. If the keyring cannot take them, nothing
changes ([keys](../dev/settings-and-config.md#where-the-node-keeps-its-keys)).

## A file changed by hand

The node signs `node.toml`. A file changed outside `nerve-node` is refused:
the node does not start with it, and a reload keeps the old settings. Read
the file, then take it:

```sh
nerve-node config accept
```

Prefer `config set`: it checks each value
([by hand](../dev/settings-and-config.md#do-not-edit-the-file-by-hand)).
