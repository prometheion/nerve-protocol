# Limits per command

Each command a center runs gets a limit on its memory, its CPU and its
number of processes. You set what a command gets and the most a call may ask
for. A call may ask for less, or for more up to that most, never beyond it.
How long a command may run has its own default and most, in
[how long a command may run](config.md#how-long-a-command-may-run).

Linux only for now. On Windows the settings are there, but commands are not
held to them yet.

## The settings

```toml
[limits.command]
memory_mb = 4096         # memory of one command, in MiB
memory_max_mb = 16384    # the most a call may ask for
cpu_percent = 200        # CPU time in percent of one CPU: 200 is two CPUs
cpu_max_percent = 800
processes = 1024         # processes and threads at once
processes_max = 8192
```

These are the defaults. Change them by name:

```sh
nerve-node config set limits.command.memory_mb 2048
nerve-node config set limits.command.memory_max_mb 8192
nerve-node config unset limits.command.memory_mb      # back to the default
```

Each value is at least 1, and a default may not be above its most. Only you
set them: a center with the [settings grant](settings-grant.md) cannot.

## What a call asks for

`exec.run` takes `memory_mb`, `cpu_percent` and `processes`, each optional:

```json
{"command": "make -j8", "memory_mb": 8192, "cpu_percent": 800}
```

A value the call leaves out is your default. A value above your most is
refused with `invalid_args`, and the error says the most. The node
describes the defaults and the most to the center, so the agent can see them
in the params `list` gives for `exec.run`.

## Calls of one agent session

Beside the limits of each command, the center bounds what one agent session
keeps busy: at most 16 calls run at once, also the ones that became jobs
([long calls](harness.md#long-calls-become-jobs)), and a 17th is refused with
`busy` until one ends or is stopped; the refusal names the session's running
jobs. A job's `exec.signal` still goes through then. Results of finished jobs
are kept in the center's memory, at most 4 MiB per session and for 10 minutes;
a result past that is not kept (a job that failed still says that it failed,
and why in one word). These are fixed in the center.

The node's own limit of 64 calls at once per center holds for all sessions
together. The center keeps 8 of those for itself: the agents' calls take at
most 56, and one past that is refused with `busy` before it reaches the node.
A machine that announces fewer places (another implementation of the node)
keeps a quarter of them, so one with 8 leaves the agents 6.
So saving the machine's settings from the center, and a job's `exec.signal`,
still work while agents' jobs hold every other place.

## Past a limit

| Limit | What happens |
|---|---|
| Memory | The command is killed, with everything it started. Its result has `"killed": "memory"` and a `reason`, such as `the command went past its memory limit of 4096 MiB and was killed`, and `"signal": "kill"`. |
| CPU | The command is slowed down. It is not killed. |
| Processes | The command cannot start more. A shell says `Cannot fork` or `Resource temporarily unavailable`. |

Only a command that reached its own limit gets `killed`. When the machine
runs out of memory as a whole, the kernel may kill a command below its
limit: its result then has only `"signal": "kill"`, and raising `memory_mb`
does not help.

Swap does not count as room: a command past its memory is killed, not
swapped out. Files the command reads into the page cache count towards its
memory, but the kernel frees those first.

A command killed for its memory is in the [audit log](audit.md) as its own
entry, `killed`, after the `allowed` one, with the reason. The
[log](logs.md) has it as a warning.

## Where the limits hold

The node puts each command in a cgroup of its own. It needs a cgroup v2 that
systemd hands to it:

- **The installed service** has one. Its unit says `Delegate=cpu memory pids`
  ([service](service.md)).
- **A node you start yourself** has one when you start it in a scope of its
  own:

  ```sh
  systemd-run --user --scope -p Delegate=yes nerve-node run
  ```

  Started plainly in a terminal, it shares the terminal's cgroup, which is
  not its own to divide. Run as a service of your own systemd
  (`systemctl --user`), its unit needs `Delegate=yes`. Without it systemd
  keeps the cgroup as its own and turns the limits off again at its next
  reload, so the node takes no cgroup there. A unit with
  `ProtectControlGroups=private` sees only its own cgroup, whose path names
  no unit: the node asks your systemd which unit it runs in
  (`systemctl --user whoami`, systemd 256 and later), and takes the cgroup
  when that unit has `Delegate=yes`. On an older systemd such a unit gets
  no limits; leave `ProtectControlGroups=private` out there.

Without such a cgroup (no systemd, cgroup v1, a node started in a terminal),
commands run without these limits. `nerve-node status` says so, and why:

```
limits per command: memory 4096 MiB, CPU 200 %, 1024 processes; a call may ask for up to 16384 MiB, 800 %, 8192 processes
limits held by the cgroup /system.slice/nerve-node.service: memory, cpu, processes
```

or

```
commands run WITHOUT these limits: the node's cgroup /user.slice/… is not delegated to it: …
```

When a cgroup offers only some controllers, the line names the limits that
are not held. When something else turns a controller off while the node
runs, no command runs until you start the node again, and `status` says so:

```
NO COMMAND RUNS: memory turned off in the cgroup since the node started; start the node again
```

When a command ends, everything still in its cgroup is killed: also a
process it moved out of its process group (`setsid`, `nohup … &`), which
would otherwise outlive it.

## What the limits do not cover

- A command that runs as the node's own user (a node you start yourself, in
  `allowlist` or `user` mode) can move itself out of its cgroup or raise its
  limits, as the cgroup's files are that user's. In `folder` mode Landlock
  keeps a command from writing the cgroup files.
- A command that runs as root can too: when root is the account commands
  run as, and every command on the [sudo list](sudo.md).
- Commands of the installed service run as another account ([the account
  commands run as](service.md#the-accounts-commands-run-as)) and cannot write
  their cgroup. But any command, in every mode, can have work started
  outside its cgroup by a service manager of its account: `systemd-run
  --user`, `at`, cron. That work is not held to the limits and outlives the
  command. The limits bound what a command uses by itself, not what it can
  ask others to run; they are no boundary against a center you do not
  trust.
- Disk space and disk speed are not limited.
- The limits are per command. `limits.max_running` (16 by default) bounds how
  many commands run at once, so many commands together can use more.
