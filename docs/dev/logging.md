# Logging

The center and the node each keep a log of what they do, apart from the audit
log. What a user sees is in [logs](../user/logs.md); this page is how it is
built.

## One module

`nerve_transport::log` holds everything both programs share:

| Piece | Does |
|---|---|
| `Level` | `error`, `warn`, `info`, `debug`, in that order of verbosity. `trace` is taken for `debug` |
| `Log` | The level (changeable at any time), a window of the latest 2000 entries, and the file. It also holds the secrets the program knows (`set_secret`) |
| `Entry` | One line: `ts`, `level`, `node`, `node_id`, `msg` |
| `redact` | Takes secrets out of text ([below](#redaction)) |
| `scrub` | A line as the log keeps it: control characters to spaces, `redact`, cut to 1000 characters. The node's Windows Event Log entries go through it too |
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

## The Windows Event Log

The installed node on Windows also writes its start, its stop, a start that
fails and a crash to the Application log, as the source `nerve-node`
(`crate::win_service::event`, ids in `crate::eventlog`). It does so only when
the service control manager started it. `running()` writes the start once the
daemon runs; `run_body`, which `service_main` calls, writes the stop, or,
when the body returned an error, "did not start" before `running()` and
"stopped with an error" after it. A panic hook writes a crash and calls the hook it replaced; it does
not touch the log file, whose lock the panicking thread may hold. A panic in
the body's thread (`run_body`) is caught there and ends the program with
`abort`, so the service's failure actions start it again (three times a day
at most, as `install` sets them; the entry says so) and the frame of
`service_main`, which cannot unwind, adds no second panic. A panic on another
thread, such as a task tokio catches, is written as a part of the node that
panicked; the node runs on. The text goes through `log::scrub`, as a line of
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
in other places. Then control characters become spaces, so a tab or a line
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
