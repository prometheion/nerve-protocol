# Logs

The center and every node keep a log of what they do: links that drop and come
back, pairing, changes to settings, calls that were refused or failed, errors,
and start and stop. Use it to find out why a machine is offline or why a
call did not go through.

The log is not the [audit log](audit.md). The audit log records the node's
decision about every call, including the ones it allowed. The log does not
record a call that worked, except that the center logs every decision of its
[action checker](action-checker.md), also the calls it let through.

## Where it is

| Program | File |
|---|---|
| Center | `log.jsonl` in the center's state folder |
| Node | `log.jsonl` in the node's state folder |

The state folders are listed under [where files live](install.md#where-files-live).
A node [installed as a service](service.md) writes it to
`/var/lib/nerve/state/log.jsonl`, on Windows to
`C:\ProgramData\Nerve\state\log.jsonl`, beside its config and audit log.
A center [installed as a service](center.md#run-it-as-a-service) writes it to
`/var/lib/nerve-center/log.jsonl`.
The file is readable by its owner only. At 5 MiB the program moves it to
`log.jsonl.1`, which replaces the older copy, so a log takes at most about
10 MiB. The node writes it while `nerve-node run` is running.

`nerve-node log` shows the node's log, `--last 50` the newest 50 lines,
`--follow` the new lines as they come, `--problems` only the errors and
warnings (with `--last 50` the newest 50 of them). The center's [web UI](web-ui.md#log) shows its log, and its **Download the
file** link gives you `log.jsonl.1` and `log.jsonl` as one file. Both programs
also print every line on stderr.

### Clear it

`nerve-node log clear` empties the node's log and its older copy; the new log
begins with `the log was cleared by <account>`. Only the owner or root may: never
a center, and never a command a center runs.

Each line is a JSON object:

```json
{"ts":1791900202123,"level":"warn","node":"web-1","node_id":"4f1c…","msg":"link dropped: no frame from the node for 45 s, not even a ping (it was up for 3 h 2 min)"}
```

| Field | Is |
|---|---|
| `ts` | Milliseconds since the Unix epoch |
| `level` | `error`, `warn`, `info` or `debug` |
| `node` | In the center's log, the machine the line is about, by its name at that time |
| `node_id` | Its id, which a rename does not change |
| `msg` | What happened, in one line, at most 1000 characters |

A node that comes back says how long it was away. After a link that went quiet,
the time counts from the last frame the node sent.

## The Windows Event Log

The node installed as a service on Windows also writes four events to the
Windows Event Log, so they show in the Event Viewer under **Windows Logs >
Application**, source `nerve-node`:

| ID | Kind | When |
|---|---|---|
| 1 | Information | The node started. The entry names the log file |
| 2 | Information | The node stopped, because the service was stopped or Windows shut down |
| 3 | Error | The node did not start: it refused to (for example `refusing to run as root`, or a `node.toml` whose MAC does not match) or could not. The entry says why |
| 4 | Error | The node crashed: a panic in its main thread ended it. The service's recovery settings start it again, three times a day at most; after that it stays stopped. Or a part of the node panicked and the node runs on; the entry says which. Or the node stopped with an error after it ran |

The log file has the details. In PowerShell (Windows PowerShell or
PowerShell 7):

```powershell
Get-WinEvent -LogName Application -FilterXPath "*[System[Provider[@Name='nerve-node']]]" -MaxEvents 20 | Format-List TimeCreated, Id, Message
```

After `uninstall` the entries stay, but Windows no longer shows their text:
`Message` is empty. Their text is still in them; replace `Format-List …`
with `ForEach-Object { "$($_.TimeCreated) $($_.Id) $($_.Properties.Value)" }`.

Every user of the machine can read the Application log, so these entries are
redacted like the log ([below](#what-is-never-in-it)). A node you start
yourself with `nerve-node run` writes no events. On Linux the journal has the
service's output (`journalctl -u nerve-node`, `journalctl -u nerve-center`).

## Levels

A level includes the ones above it in this table.

| Level | Is for |
|---|---|
| `error` | Something the program could not handle and you have to act on |
| `warn` | Something wrong that the program handled: a link lost, a call that failed |
| `info` | Normal use: links, pairing, changes, refused calls. The default |
| `debug` | Detail for tracking down a problem |

A change of the level applies to the next line. The log's size is kept even if
the file cannot be moved aside because another program holds it. Then it is
copied to `log.jsonl.1` and started again in place. If it cannot be copied
either, it is left as it is, no more lines are written to it, and the program
says so once on stderr; the center's Log page still shows the lines. The move
is tried again every 10 seconds.

| Where | How |
|---|---|
| Center | **Settings** in the web UI, or `--log` (`NERVE_LOG`) |
| Node | `nerve-node config set log.level debug` |

The center keeps the level you set in the web UI for the next start. `--log`
sets the level for one run and wins over the stored one. A running node takes
a new `log.level` within a second.

## What the center logs

| Level | Lines |
|---|---|
| `error` | The state file cannot be written. A call failed inside the center or the node (`internal`) |
| `warn` | The [action checker](action-checker.md) refused a call. Its local model could not be installed, started or wholly removed, or its GPU build found no device. A blocklist entry or an allow rule could not be read and is left out. A link dropped without a bye, went quiet (no frame for 45 s), or was replaced because the node connected again and the old link did not answer a ping; the line says how many calls wait for the node to resume the link. A node did not resume its link within 30 s, and its calls failed. A link failed authentication, or the node speaks another protocol version. A second link while the first is alive (the key may be copied). A description of a node that cannot be used. A pairing was refused: the code is unknown, used, expired or out of tries (one line in ten seconds; the number left out is told on the next line, or when the refusals stop), or the name or key is taken. Pairing codes ran out of tries. A call failed: the node is offline, busy, too slow, or the link ended. A node refused a change from the web UI (a capability among them). A wrong token at the web UI sign-in, and the lock after too many |
| `info` | The center started and stopped. A link came up, with how long the node was away if it was; a node resumed its link, with the calls that waited on it; a link closed with a bye, with how long it was up. A node is going away, or changed its settings. A pairing code was made, or expired unused. A node paired, was renamed, disabled, enabled, removed or unpaired itself. A harness session started or ended. A call was refused, by the node's rules or because the node is disabled here. A call failed because of its own arguments or the node's answer (a missing file, a bad path). A harness token was made or deleted. Someone signed in to the web UI. Settings, a rule or the sudo switch were changed from the web UI, or a capability of the center's own was added, changed or removed there. The center's settings or the log level were changed. The action checker let a call through by an allow rule or a model score below the threshold, or because its model was down and set to allow-and-log. Its local model was installed, removed, or is starting |
| `debug` | A handshake that did not finish. A node that is not paired tried to connect. A pairing request in a wrong form. A node's description changed. A call was cancelled |

The line for a refused or failed call names the action and the reason the node
gave, cut at 300 characters:

```
fs.read was refused (forbidden): no allow rule matches /etc/hostname
exec.run failed (timeout) after 30 s: the node did not answer in time
```

A reason can quote the path or command line of the call. The audit log has the
whole call.

A call the action checker refused has a line of its own before that one,
which names the part that decided and the entry, rule or score, and whether it
was the one for every machine or this machine's own:

```
the action checker refused exec.run by its blocklist for every node (exec.run:rm -rf /)
exec.run was refused (forbidden): the center's action checker refused this call: it is on the center's blocklist for every node — wipes the root filesystem (exec.run:rm -rf /). …
the action checker allowed exec.run by its model for every node (score 0.03 < threshold 0.80)
```

## What the node logs

| Level | Lines |
|---|---|
| `error` | A key or the center's address or the proxy cannot be used, so the node stops dialling that center. The audit log or `node.toml` cannot be written. The control socket's listener broke, so the socket stopped. On Windows, the control pipe cannot be made (`the control pipe … is taken`, for one): the node runs on without it, and a change from the CLI takes effect at the next start of the node |
| `warn` | The node cannot reach a center (the first time after a link, the rest are `debug`). A handshake failed. A link closed without a bye, or went quiet. A dropped link was not resumed, and its calls ended. A center said bye because of a duplicate or an error, or ended the pairing, or does not know this node. A reload of `node.toml` was refused. A call failed. The control socket cannot take a connection now (it takes the next one once the cause is gone), and on Windows the same for the control pipe (`the control pipe cannot take a connection now`, `… cannot make another instance now`). A folder of a center is left out of a command's sandbox (`folder … left out of the command's sandbox: …`, see [modes](modes.md#a-folder-keeps-the-place-you-added)). `folder mode runs no command: …`, once, when the keys in the system keyring turn folder mode's commands off. A folder's grant could not be put on or taken off (`folder grants: …`): on Windows, and on the installed Linux node for the ACL entries of `nerve-run` |
| `info` | The node started and stopped. It linked to a center, and when it will dial again after a link ended, with the wait. A dropped link is kept for the center to resume, with the calls in flight on it; a link was resumed, with how many frames were sent again. A center said bye, or the node closed the link and why. A change to the settings, by whom, the new version and each setting that changed. On Windows, the progress of the folder grants (`folder grants: …`). A call was refused, with the reason. A call failed because of its own arguments or the files it named |
| `debug` | Each dial. The dials that follow a failed one. A reload that changed nothing |

The line for a change to the settings names the setting and, for a plain value,
the old and the new one. For a list it names what was added (`+`) and what was
removed (`-`). It never shows a setting of the proxy:

```
settings changed by center lab (version 7): center.lab.policy.mode: allowlist -> folder
settings changed by local (version 8): center.lab.policy.allow +fs.read:~/notes/*; machine.sudo: off -> on
```

A change made with `nerve-node` while the node is not running is not in the
log; the audit log has it.

## What is never in it

- A call that worked. That is in the node's audit log. The action checker's
  line for a call it let through names the rule or the score, not the call.
- File contents and command output.
- The sudo password, a harness token, the token typed into a wrong sign-in, a
  pairing code, the node's key, a proxy's header values, the token of the
  action checker's model endpoint.

The programs do not put a secret into a line. As a second guard, every line is
checked before it is kept. These are replaced by `[redacted]`:

- the value after a name like `password`, `token`, `secret`, `api_key`,
  `authorization` or `cookie`, written `name=value`, `name: value`, as JSON, or
  as a flag with a space (`--password x`, `--with-token x`);
- the credential after `Authorization:` and its scheme (`Bearer`, `Basic`,
  `token`, and any other);
- the user and password in a URL, the `code` of a pairing link and a harness
  token (`nrv_…`).

The center also holds back the harness token it was started with, and the node
the sudo password while sudo is on. A secret of fewer than 8 characters is
replaced only where it stands as a word of its own, so it does not cut other
words.

A secret that has no name it can be known by is not caught: `curl -u admin:pw`
and `docker login -p pw` in the reason of a refused command show it. The audit
log has the whole command line in any case.
