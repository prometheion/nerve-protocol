# Watch and stop

See what the node does, what it allowed and refused, and stop it at once.

```sh
nerve-node status                      # how it is, and what to do next
nerve-node audit --refused             # what it refused
nerve-node log --problems              # what went wrong
nerve-node panic                       # stop everything
```

## Status

`nerve-node status` shows the service, each center with its mode, folders,
network and rules, the limits per command, and the next step. It warns of
what this machine cannot guard, such as an old kernel's Landlock. For the
center, `nerve-center status`.

## The audit log

The node writes down every decision about a call and every change to its
settings.

```sh
nerve-node audit                       # everything, oldest first
nerve-node audit --refused             # refused calls only
nerve-node audit --follow              # new entries as they come
nerve-node audit --last 50
```

```text
1791834106607  lab  fs.read  /etc/hostname  forbidden: no allow rule matches /etc/hostname
1791834531401  lab  fs.read  /home/u/proj/a.txt  allowed
```

A refusal names what is missing; use it to write the rule you want. The
audit log never holds file contents, command output or the sudo password.
`nerve-node audit clear` starts it afresh; the old entries become
`audit.jsonl.1`. Only you may clear it, never a center.

The center's **Audit** page shows the latest decisions of all machines, and
those of its action checker, which a machine never sees
([the audit log](../dev/logging.md#the-audit-log-as-the-owner-reads-it)).

## The log

The log is what the program did: links that drop and come back, pairing,
changes, refused and failed calls, errors.

```sh
nerve-node log                         # the node's log
nerve-node log --problems --last 50    # its newest errors and warnings
nerve-node log --follow
nerve-node log clear
journalctl -u nerve-center             # the center's
```

The center's web UI shows its log under **Log**, with a download. Raise the
level for more: `nerve-node config set log.level debug`, or the center's
**Settings**.

- The audit log (about 20 MiB) and the log (about 10 MiB) drop their oldest
  entries. Refusals take at most half of the audit log, so a center cannot
  push out what the node allowed or changed
  ([logs](../dev/logging.md#the-file)).

## Stop access

From the quickest to the most thorough:

| You want | Do |
|---|---|
| Stop one agent session | Web UI, Overview, Sessions, **End** |
| Hide a machine from the agent | Web UI, Overview, **Disable** at the machine |
| Stop one center on a machine | `nerve-node center pause lab` |
| Stop every center on a machine | `nerve-node panic` |
| End a pairing | `nerve-node center rm lab`, or **Remove** in the web UI |

```sh
nerve-node panic                       # every link ends; nothing runs
nerve-node unlock                      # work again
nerve-node center resume lab           # after a pause
```

`panic` ends every link and every web UI session, and stays after a restart
until you `unlock`. A center can never unlock it. A center with the
settings grant can pause its own link; only you resume it.

A command stops when its call ends: on its timeout, when it is cancelled,
or when its session or link ends. The node kills its process group, and
where it has a cgroup (`status` says so) all it started. A program handed to
a service manager, or detached on a node without a cgroup, keeps running: end
`nerve-run`'s leftover processes yourself
([what ends a command](../dev/sandbox-linux.md#what-ends-a-command)).
