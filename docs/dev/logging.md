# Logging

The center and the node each keep a log of what they do, apart from the audit
log. What a user sees is in [logs](#the-log-as-the-owner-reads-it); this page is how it is
built.

## One module

`nerve_transport::log` holds everything both programs share:

| Piece | Does |
|---|---|
| `Level` | `error`, `warn`, `info`, `debug`, in that order of verbosity. `trace` is taken for `debug` |
| `Log` | The level (changeable at any time), a window of the latest 2000 entries, and the file. It also holds the secrets the program knows (`set_secret`) |
| `Entry` | One line: `ts`, `level`, `node`, `node_id`, `msg` |
| `redact` | Takes secrets out of text ([below](#redaction)) |
| `scrub` | A line as the log keeps it: control characters and U+2028/U+2029 to spaces, `redact`, cut to 1000 characters. The node's Windows Event Log entries go through it too |
| `LogLayer` | A `tracing` layer that hands every event to a `Log` |
| `install`, `global` | Make the process's `Log` once and set the layer as the global subscriber |
| `emit` | `tracing` at a level only known at run time |
| `call_line` | The level and the text of a refused or failed call, the same in both programs |

Nothing else formats a log line.

## Two ways in

- **`tracing` macros.** `nerve-center` and `nerve-node` call `install` in
  `main`. After that `tracing::info!`, `warn!` and the rest reach the `Log`.
  The fields `node` and `node_id` say what an event is about; any other field
  is put after the message as `name=value`. The layer asks the `Log` for the
  level on every event and tells `tracing` that no callsite stays disabled, so
  a changed level applies to the next event.
- **`Log::record`.** The center calls it through `Center::note` and
  `Center::log()`. A center holds its own `Log` (`Options.log`, else a private
  one), so the entries of one center are its own and a test needs no global
  subscriber.

The node uses the macros only. Its sites are in many places that have no
handle to the daemon.

## The file

`Log::attach_file` opens `log.jsonl` in the state folder (mode 0600), reads the
latest entries of both files back into the window, then writes what was logged
before the file was attached. A line is one write. At 5 MiB the file is moved
to `log.jsonl.1` and replaces the older one. When it cannot be moved (the
older file cannot be replaced, or on Windows a reader holds it open), it is
copied there and started again in place, so it never grows past its limit. If
it cannot be copied either, the file is left with its lines and nothing is
written to it; stderr says so once, and the move is tried again every 10 s
(`RETRY_AFTER`), not for each line. The same goes for a file that cannot be
started again after the copy. A file that cannot be opened or written
is told once on stderr; the program goes on with the window.

The center attaches the file in `Center::open`, after it holds the state
folder's lock, so a second `nerve-center` that only attaches to the first does
not write to it. The node attaches it in `Daemon::start`. A CLI command that is
not the daemon writes no log file.

## Levels

- **Center.** The level is in `state.json` (`log_level`), changed in the web
  UI's settings (`POST /api/center`, `Center::set_log_level`). `--log` wins for
  one run (`Options.log_level`) and leaves the stored level alone: the settings
  page is given the stored level (`log_level`; `log_level_now` is the one in
  force), so saving another setting sends the stored level back, and a level
  saved while `--log` holds is stored without changing this run. A change is
  told in the log while the more verbose of the old and the new level is in
  force, so it is always kept.
- **Node.** The level is `log.level` in `node.toml`. The supervisor sets it
  from the config it holds on every pass, so any writer (the CLI, a reload)
  is followed within a second.

## A poisoned lock

A thread that panics while it holds a std lock leaves the lock poisoned, and
what it guards may be half changed. The center and the node take every lock
through `nerve_transport::sync` (`lock`, `try_lock`, `read`, `write`,
`into_inner`): on a poisoned one it writes one error line that names the lock
(the type it holds and where it was taken), then ends the process with exit
code 70. The service starts it again with clean state: systemd's
`Restart=on-failure` on Linux, the service's failure actions on Windows
([service](service.md#start-and-stop)). It ends with an exit code, not an
abort, so no core dump holds the keys and passwords the program has in
memory. When the log's own lock is the poisoned one, the line goes to stderr
only. A lock that guards no data and only takes turns (`sync::turn`, such as
the grant walk's) holds nothing a panic could leave half changed, so its
poisoning is cleared and the program goes on. The center's `rotating` lock
looks like one but is not: it orders a key change of several steps, so it is
a `lock`. A test (`sync::tests::no_lock_of_the_programs_is_taken_around_the_rule`)
fails when production code of the center, the node, the policy or the
transport crate (test items left out) handles a std lock's poisoning itself or
takes a lock in a form that does: `PoisonError`, `clear_poison`, the `try_`
takes, and a `lock`, `read` or `write` that is unwrapped, turned into an
`Option` or an error, or matched on. It goes by the names, so a plain
`.lock().await` or an own method that returns a guard passes.

The exception is the window part of `nerve-node-desktop` (`broker.rs`,
`runner.rs`, `instance.rs`, `app/live.rs`): its locks still shrug off a
poisoning and go on, so a panic there does not end the service. They guard
the app's own windows and the elevated broker's pipes, not the node's rules or
keys. Whether they take the rule too is an open owner question.

## The Windows Event Log

The installed node and center on Windows also write their start, their stop,
a start that fails and a crash to the Application log, as the source
`nerve-node` or `nerve-center` (`nerve_service::win::dispatch::event`, ids
in `nerve_service::eventlog`). They do so only when the service control
manager started them; both run under that one dispatcher. `running()` writes the start once the
daemon runs; `run_body`, which `service_main` calls, writes the stop, or,
when the body returned an error, "did not start" before `running()` and
"stopped with an error" after it. A panic hook writes a crash and calls the hook it replaced; it does
not touch the log file, whose lock the panicking thread may hold. A panic in
the body's thread (`run_body`) is caught there and ends the program with
`abort`, so the service's failure actions start it again (as often as it
takes, as `install` sets them) and the frame of
`service_main`, which cannot unwind, adds no second panic. A panic on another
thread, such as a task tokio catches, is written as a part of the node that
panicked; the node runs on, unless the panic left a lock poisoned: the next
take of that lock ends the program ([above](#a-poisoned-lock)), and the
failure actions start it again. The text goes through `log::scrub`, as a line of
the log does: one line, redacted, cut. Every user may read the Application
log.

The Event Viewer takes an entry's text from the source's message file.
`build.rs` writes a `.res` file with one message table (`%1` for each id,
`eventlog::resource`) and links it into every program of the crate on
windows-msvc, and the desktop app's `build.rs` links the same table into
`nerve-node-desktop`, the node's program on Windows; `install` registers the
installed program (`nerve-node-desktop.exe`) as the message file under
`HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\nerve-node`,
and `uninstall` removes the key. A windows-gnu build has no table, and the
Event Viewer then shows the text with a note that the description is missing.

Once someone read the entries, the Event Log service holds the program open
as their message file. It cannot be written over or deleted then, but it can
be renamed: `install` moves an installed program aside (`remove_program`, to
`nerve-node.*.del`, deleted at the next restart) before it writes the new
one, as `update` and `uninstall` already did.

## Redaction

`redact` works on every message before it is kept:

- the value after `password`, `passwd`, `passphrase`, `pwd`, `secret`, `token`,
  `api_key`, `apikey`, `api-key`, `authorization`, `cookie`, `sealed`,
  `private_key` or `credential`, written `name=value`, `name: value` or as
  JSON, in any letter case, with spaces or tabs around the separator; or, for a
  flag (`--password x`, `--with-token x`), after a space, unless the next word
  is a placeholder (`(`, `<`, `[`, `{`, `-`, `$`);
- the credential after `Bearer` or `Basic`, and after `Authorization:` and its
  scheme, whatever the scheme. A value in quotes goes to the closing quote (one
  that opens with an escaped quote, `\"`, to the next escaped quote); a quote
  that is never closed ends no value, so only the word after it goes and the
  rest of the message stays;
- `user:password@` in a URL;
- the `code` parameter of a pairing link;
- a harness token, `nrv_` and eight or more characters.

The secrets the program holds are replaced by `[redacted]` first, as written:
the center registers the harness token from its flag, the node the sudo
password while the switch is on. One shorter than 8 characters is replaced only
as a whole word (`hide`), so a password like `in` or `1234` does not cut words
in other places. Then control characters and U+2028/U+2029 become spaces, so a tab or a line
break between a name and its value is a gap like any other, `redact` runs, and
the message is cut to 1000 characters.

A secret with no name to know it by (`curl -u user:pw`, `docker login -p pw`)
is not caught.

The scanner is by hand, since the workspace has no regex crate. It works on
bytes and cuts only at ASCII, so it cannot split a character.

The messages the programs write do not name a secret. The pairing code is never
passed to the log. Redaction is the net under text that is only passed on: the
reason of a refusal, an error from the system.

## What the center logs

The calls are logged in `Center::call`, where a result is known:

| Result | Level |
|---|---|
| `forbidden`, `disabled`, a node switched off in the center | `info`, "refused" |
| `unavailable`, `busy`, `timeout`, `too_large`, `connection_lost` | `warn`, "failed" |
| `internal` | `error`, "failed" |
| `invalid_args`, unknown members, the profiles' own codes (`io`, `bad_path`, `conflict`) | `info`, "failed" |
| `cancelled` | `debug` |

`call_outcome` in `nerve_transport::log` has the table, and the node uses the
same one for the calls it answers.

The action checker's decisions are logged in `Center::audit_checker`, beside
their audit entry: a refusal at `warn` ("the action checker refused
`<cap>.<action>` by its `<layer>` for every node|for this node (`<detail>`)"),
before the call's own `info` line, and a call it let through at `info`
("… allowed …"). The detail is the entry or allow rule, the score, or the
model's error, never the command line. Its local model logs installs, removals
and starts, and `warn` when one fails or the GPU build finds no device; a rule
the checker cannot parse is a `warn` when it is rebuilt.

Links are logged where the link task ends (`link.rs`), with the reason in
words. The center keeps when each node's link last ended in memory (`down`),
so the next link says how long the node was away. A link is closed after 45 s
without a frame (`Center::dead_after`); a test shortens it with
`set_dead_after`.

A node that connects while the center still holds its old link (a half-open
connection that does not answer the 3 s ping) replaces it: `link_replaced`
logs the old link as dropped, with how long it had been silent, and starts the
wait from its last frame. The old link's own end, later, is a debug line and
sets no wait, since it is no longer the node's link. `link_replaced` takes
the old link out of the node's links at once and says nothing if it is not
there: a link that ended during the 3 s wait has told its drop already.

A link the node can resume (protocol §4.9) that drops is parked: the drop line
(`link_parked`) says how many calls wait, and the link stays in the node's
links, offline. A connection that resumes it logs `link resumed after …`
through `link_up`, counted as no new link in the statistics; the end of an
older connection of that link is a debug line. A link not resumed within the
grace logs a warning with the calls that failed. The grace is 30 s
(`Center::grace`); a test shortens it with `set_resume_grace`, and a node's
with `NodeOptions::resume_grace`.

A pairing code that runs out unused is noticed by `Center::sweep_codes`, which
the center calls every five seconds, so its line is at most that late. The
pairing endpoint is open to anyone who reaches the port, so a refusal for a
wrong code is logged once in ten seconds, with the number left out.

## The web UI

`GET /api/log` answers from the window:

| Parameter | Is |
|---|---|
| `level` | The least severe level to show |
| `node` | A node id, or `-` for entries about no node |
| `q` | Text the message or the node's name contains |
| `after` | Only entries numbered above this one |
| `limit` | At most this many, 500 unless given, 1000 at most |

The answer has `entries` (newest first, each with `seq`, `ts`, `level`,
`node`, `node_id`, `msg`), `nodes` (every paired node, and the ones only the
log remembers, with `paired`), the `level` the log is kept at and `file`,
whether there is a file. `GET /api/log/download` sends the file, the older half
first, as `application/x-ndjson` with `Content-Disposition: attachment`. Both
need a signed-in browser like every API call.

The page polls every two seconds. The level and machine lists are the
searchable list of the Statistics page (`picker` in `app.js`); the page builds
its boxes once and fills them in place, so a poll does not cut off what is
typed.

## The node's changes

`SettingsStore::on_change` takes a callback that runs after every saved change
with who made it, the new version and the leaves that differ. The daemon sets
one that logs `describe_change`. The CLI opens the store for one command and
sets none. The paired centers are a list, so the diff names them as one leaf;
`describe_change` looks into each by name. The proxy's settings and the pins
and ids of a center are named, never shown.

## The log, as the owner reads it

The center and every node keep a log of what they do: links that drop and come
back, pairing, changes to settings, calls that were refused or failed, errors,
and start and stop. Use it to find out why a machine is offline or why a
call did not go through.

The log is not the [audit log](#the-audit-log-as-the-owner-reads-it). The audit log records the node's
decision about every call, including the ones it allowed. The log does not
record a call that worked, except that the center logs every decision of its
[action checker](action-checker.md#the-checker-as-the-owner-sets-it-up), also the calls it let through.

### Where it is

| Program | File |
|---|---|
| Center | `log.jsonl` in the center's state folder |
| Node | `log.jsonl` in the node's state folder |

The state folders are listed under [where files live](settings-and-config.md#where-files-live).
A node [installed as a service](service.md#the-node-as-a-service) writes it to
`/var/lib/nerve/state/log.jsonl`, on Windows to
`C:\ProgramData\Nerve\state\log.jsonl`, beside its config and audit log.
A center [installed as a service](service.md#the-center-as-a-service) writes it to
`/var/lib/nerve-center/log.jsonl`.
The file is readable by its owner only. At 5 MiB the program moves it to
`log.jsonl.1`, which replaces the older copy, so a log takes at most about
10 MiB. The node writes it while `nerve-node run` is running.

`nerve-node log` shows the node's log, `--last 50` the newest 50 lines,
`--follow` the new lines as they come, `--problems` only the errors and
warnings (with `--last 50` the newest 50 of them). The center's [web UI](web-uis.md#log) shows its log, and its **Download the
file** link gives you `log.jsonl.1` and `log.jsonl` as one file. Both programs
also print every line on stderr.

#### Clear it

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

### Levels

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
| Center | **Settings** in the web UI, or `--log` (`NERVE_CENTER_LOG`) |
| Node | `nerve-node config set log.level debug` |

The center keeps the level you set in the web UI for the next start. `--log`
sets the level for one run and wins over the stored one. A running node takes
a new `log.level` within a second.

### What the center logs

| Level | Lines |
|---|---|
| `error` | The state file cannot be written. A call failed inside the center or the node (`internal`) |
| `warn` | The [action checker](action-checker.md#the-checker-as-the-owner-sets-it-up) refused a call. Its local model could not be installed, started or wholly removed, or its GPU build found no device. A blocklist entry or an allow rule could not be read and is left out. A link dropped without a bye, went quiet (no frame for 45 s), or was replaced because the node connected again and the old link did not answer a ping; the line says how many calls wait for the node to resume the link. A node did not resume its link within 30 s, and its calls failed. A link failed authentication, or the node speaks another protocol version. A second link while the first is alive (the key may be copied). A description of a node that cannot be used. A pairing was refused: the code is unknown, used, expired or out of tries (one line in ten seconds; the number left out is told on the next line, or when the refusals stop), or the name or key is taken. Pairing codes ran out of tries. A call failed: the node is offline, busy, too slow, or the link ended. A node refused a change from the web UI (a capability among them). A wrong token at the web UI sign-in, and the lock after too many |
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

### What the node logs

| Level | Lines |
|---|---|
| `error` | A key or the center's address or the proxy cannot be used, so the node stops dialling that center. The audit log or `node.toml` cannot be written. The control socket's listener broke, so the socket stopped. On Windows, the control pipe cannot be made (`the control pipe … is taken`, for one): the node runs on without it, and the CLI cannot change it until it is restarted |
| `warn` | The node cannot reach a center (the first time after a link, the rest are `debug`). A handshake failed. A link closed without a bye, or went quiet. A dropped link was not resumed, and its calls ended. A center said bye because of a duplicate or an error, or ended the pairing, or does not know this node. A reload of `node.toml` was refused. A call failed. The control socket cannot take a connection now (it takes the next one once the cause is gone), and on Windows the same for the control pipe (`the control pipe cannot take a connection now`, `… cannot make another instance now`). A folder of a center is left out of a command's sandbox (`folder … left out of the command's sandbox: …`, see [modes](sandbox-linux.md#a-folder-keeps-the-place-you-added)). `folder mode runs no command: …`, once, when the keys in the system keyring turn folder mode's commands off. A folder's grant could not be put on or taken off (`folder grants: …`): on Windows, and on the installed Linux node for the ACL entries of `nerve-run` |
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

### What is never in it

- A call that worked. That is in the node's audit log. The action checker's
  line for a call it let through names the rule or the score, not the call.
- File contents and command output.
- The sudo password, a harness token, the owner token of the center's web UI,
  the token typed into a wrong sign-in, a
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

The center also holds back the harness token it was started with and its
owner token, and the node
the sudo password while sudo is on. A secret of fewer than 8 characters is
replaced only where it stands as a word of its own, so it does not cut other
words.

A secret that has no name it can be known by is not caught: `curl -u admin:pw`
and `docker login -p pw` in the reason of a refused command show it. The audit
log has the whole command line in any case.

## The audit log, as the owner reads it

The node writes down every decision about a call, and every change to its
settings. Read it on the machine, or in the center's web UI.

### On the machine

```sh
nerve-node audit               # everything, oldest first
nerve-node audit --refused      # only refused calls
nerve-node audit --follow      # keep running and print new entries
nerve-node audit --last 50     # only the newest 50
```

A call looks like this: a time in milliseconds since the epoch, the center, the
action, the target and the decision. A refusal adds its reason.

```
1791834106607  lab  fs.read  /etc/hostname  forbidden: no allow rule matches /etc/hostname
1791834531401  lab  fs.read  /home/u/proj/a.txt  allowed
```

The reason says what is missing. Use it to write the rule you want
([rules](policy-engine.md#rules-as-the-owner-writes-them)). The target of a call that names paths is its path (an
`fs` call's, or the paths a program's capability takes, joined by `, `; a
path that does not resolve is refused as given, with `bad_path`). A call that
names no path has its action as the target. A call to a
[capability of your `node.toml`](capabilities.md#capabilities-of-your-own-in-nodetoml) adds the command as
it ran, or would have run, with the values the call gave it:

```
1791834531502  lab  svc.restart  svc.restart  allowed (command: systemctl restart -- nginx)
```

That command stays in this log. The center hears of each of its own calls
(`audit/decision`, which its web UI shows) with the target, never the
command, since your command may hold words no center should see (while it
runs, though, its line is open to every account on the machine, as every
program's is: keep a secret out of it, see
[config-capabilities.md](capabilities.md#keep-secrets-out-of-the-command)). The
refusal the center gets names each path as it gave it; only the audit names
where it led, which can be another place when the path goes through a link.
A call to a capability you switched `off` is a refusal too, with the path or
command line an `fs` or `exec.run` call names as its target. An `fs` path the node did
not resolve is the target only where it is written as a resolved one
(absolute, no `.` or `..` part), since a rule made of it would match nothing
otherwise; else the target is empty and the reason names the path:

```
1791834531650  lab  notes.open  notes.open  forbidden: notes.open is off
```

A call whose folders the node was still checking for links when it ended
(its deadline passed, or the center cancelled it) is a refusal with the
code `cancelled`: it never reached the program
([providers](capabilities.md#paths-it-takes)).

A command killed for its memory limit gets a second line, `killed`, with the
reason ([limits](sandbox-linux.md#limits-per-command)):

```
1791834531877  lab  exec.run  make -j8  killed: the command went past its memory limit of 4096 MiB and was killed
```

Settings changes are lines like `1791834068828  settings v1 by local (alice)`.
They show the new version and who changed it: `local` for `nerve-node`, with
the account that ran it (the user behind `sudo`, or the owner of the installed
node, [administrator rights](desktop.md#administrator-rights)), or the name of
a center. The log holds the old and the new value of each setting.

`install`, `setup`, `update` and `uninstall` are lines like
`1791834068828  update: replaced nerve-node <old> with <new>; restarted the service nerve-node.service`,
with the steps that were done and the error that stopped the rest, if any
([service](service.md#the-node-as-a-service)).

A tunnel of the [relay](node-link.md#a-relay-as-the-owner-sets-it-up) is one line when it ends: who, from where,
to which center, why it ended, how long it lasted and how much it carried.
It never holds a token.

```
1791834106607  relay  lab-pc from 10.0.0.7:51544 to center home: cut off by the owner after 2 h 5 min (81234 bytes up, 90211 down)
```

A key rotation is one line, with the public keys or pins and never a private
key ([pairing](identity-and-pairing.md#rotate-the-machines-key)):

```
1791834106607  lab  key node-key: the center took the new key <hex> in place of <hex>, which it takes for 7 d more
```

The events are `node-key`, `node-key-refused`, `node-key-unanswered` and
`node-key-grace-ended` for the machine's key, and `center-key`,
`center-key-refused` and `center-key-grace-ended` for the center's.

### What the log holds

- Targets: paths and command lines, cut at 512 characters.
- Never file contents or command output.
- Never the sudo password.
- Refusals of a changed `node.toml`, and the owner taking it with
  `config accept`.

### Where it is and how big it gets

The log is `audit.jsonl` in the node's state folder
([where](settings-and-config.md#where-files-live)). One line is one JSON object.

At 10 MiB the node moves it to `audit.jsonl.1` and replaces the older copy, so
the log stays below about 20 MiB. A center that makes many refused calls cannot
push out what the node allowed or changed: refusals take at most half of a full
file, and the oldest refusals go first.

The node keeps the file open and writes each entry under a lock of the log's
own, so an entry never waits for the config, nor a call for the file. It
counts the bytes of refused calls as it writes them, and reads the full file
only to drop the oldest refusals, or once to count them where it did not see
the file from its start. A line another program wrote, or a move of the file
(`audit clear`), is noticed by the file's length, and the node opens the file
at its place again.

### Clear it

```sh
nerve-node audit clear
```

starts the audit log afresh. Nothing goes silently: the entries so far become
`audit.jsonl.1`, as at 10 MiB (the older copy gives way), and the new log
begins with `audit cleared by <account>`. `nerve-node audit` and the app show
the entries from there on; the cleared ones stay in `audit.jsonl.1` until the
log moves aside again. Only the owner or root may clear it: never a center,
and never a command a center runs (the node refuses it there).

### The audit log and the log

The audit log is the node's record of its decisions. The [log](#the-log-as-the-owner-reads-it) is
what the program did: links, pairing, changes, errors. They are separate files
with their own sizes. A call that worked is only in the audit log; a call that
was refused or failed is in both, in the log with its reason.

### In the web UI

The Audit page lists the latest decisions of all machines, newest first, and
those of the center's [action checker](action-checker.md#the-checker-as-the-owner-sets-it-up), which refuses some
calls before a machine sees them; those are not in the machine's audit log.
It keeps at most 500 decisions or 1 MiB, in memory. See
[the web UI](web-uis.md#audit).
