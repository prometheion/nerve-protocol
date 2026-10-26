# Stop access

From the quickest to the most thorough.

| You want | Do | Effect |
|---|---|---|
| Stop one agent session | Web UI, Overview, Sessions, **End** | The session's running commands stop, its jobs too |
| Hide a machine from the agent | Web UI, Overview, **Disable** on the machine | The machine stays paired and connected. The agent's `list` shows it as disabled with no capabilities, and calls to it are refused. The agent's calls that run there stop, its jobs too. **Enable** undoes it |
| Stop one center on a machine | `nerve-node center pause --center lab` | The node drops the link and does not dial it again |
| Stop every center on a machine | `nerve-node panic` | Every link ends. Nothing runs until `unlock` |
| End a pairing | `nerve-node center rm --center lab`, or **Remove** in the web UI | The pairing and its key are gone |

## Panic

```sh
nerve-node panic       # end every link; nothing runs
nerve-node status      # shows LOCKED (panic)
nerve-node unlock      # work again
```

`panic` locks the node in `node.toml`. The lock stays after a restart until you
run `unlock`. Only you can unlock. A center can never unlock.

If `panic` says the node does not take connections now, or that the config
keeps changing, the lock was not set. Try again; if it keeps failing, stop the
node itself (`systemctl stop nerve-node`, or Ctrl-C for a node you started).

## Pause

```sh
nerve-node center pause --center lab
nerve-node center resume --center lab
```

A center with the [settings grant](settings-grant.md) can pause its own link.
Only you can resume it.

## What ends a command

A command stops when its call ends: on its timeout, when the caller cancels,
when its session ends, or when its link ends. A command that ran past the
center's call wait is a job ([long calls](harness.md#long-calls-become-jobs)):
the harness's cancel of its tool call no longer reaches it, and the agent
stops it with `job.cancel`, or sends it a signal with `exec.signal` where you
allowed that (`nerve-node cap set exec.signal on`; in `allowlist` mode an
allow rule `exec.signal`). Turning the machine's capabilities off, or an
`until` that passes, does not stop a running command, and the agent can still
stop it with `job.cancel`; **Disable** in the center stops it. A link that
drops without a goodbye is kept 30 seconds and its commands run on; they end
when the link is not back by then, or at once when the link ends with a goodbye (`panic`,
`center pause`, a stopped node). Taking the machine off the network for less
than 30 seconds does not stop a command; use `nerve-node panic`. On Linux the
node kills the command's whole process group, and everything in the command's
cgroup where it has one ([limits](limits.md)). On Windows it ends the
command's Job Object. A command that goes past its memory limit is killed too.
Every command also has a timeout: its `timeout_ms`, or the node's default, and
never more than the node's maximum
([how long a command may run](config.md#how-long-a-command-may-run)).

On Windows a timeout first asks the command to end: its console programs get
Ctrl+C and its windows a close request. What has not ended 3 seconds later is
ended with the Job Object.
A cancel, the end of a session and the end of its link end it at once.
