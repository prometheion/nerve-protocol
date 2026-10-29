# Capabilities of your own in `node.toml`

You can give the agent a capability of your own without writing a program:
a fixed command the node runs itself, such as `sensors.read` running
`sensors -j`. You declare it once; every center then sees it next to `fs` and
`exec`, the node decides each call to it by that center's mode and rules, as
for any other capability, and writes it to the [audit log](audit.md) (with
the command as it ran, the call's values in it, which the node sends no
center; while it runs, though, anyone on the machine can read it, see
[below](#keep-secrets-out-of-the-command)). Such a capability offers actions only: a value it
reads is an action with effect `read` or `sense` (an entry with `state`,
`events` or `streams` is refused). For a capability that keeps a connection
or state of its own, or sends events or a stream, write a
[provider](providers.md) instead.

They run on Linux, as the command account `nerve-run` of the [installed
node](service.md) (below): a node you run yourself has no such account and
offers none. Windows keeps them in `node.toml` and offers none yet.

## Add one

```sh
nerve-node cap add sensors.read --effect sense --summary "Temperatures of this machine." \
  --result '{"type": "object"}' -- sensors -j
```

In the [desktop app](desktop.md#capabilities), **Capabilities** › **Add a
capability…** does the same in a form that checks each field as you type,
and **Edit** and remove beside each one change and remove it.

The name is `cap.action`: the capability and its action, as rules, `cap set`
and the audit log name them. It may not be one of the node's own (`fs`,
`exec`, `settings`, `audit`, `node`) nor the center's (`job`, `stream`), and
each name is declared once. Two actions of one capability are two entries,
`sensors.read` and `sensors.list`.

What follows `--` is the command: the program first (a name looked up in
`PATH`, or a full path), then its arguments. The options:

| Option | What it sets |
|---|---|
| `--effect` | what it does: `read`, `write`, `execute`, `sense` or `actuate`; decides when a center may use it (below) |
| `--summary` | one line for the agent |
| `--params` | the JSON Schema of its arguments, an object (below); `none` takes none |
| `--result` | `text`, what the command prints (the default), or a JSON Schema: the node then reads what it prints as JSON that must fit it |
| `--timeout` | seconds it may run, at most `limits.max_timeout_secs`; `default` for `limits.default_timeout_secs` |
| `--platform` | `any` (the default), `linux` or `windows`: a node offers only those of its own platform |

`--params-stdin` and `--result-stdin` read the schema from stdin instead, for
one too long for the command line. Only one of them can come from stdin: add
the capability with one and `cap edit` the other.

```sh
nerve-node cap add logs.tail --effect read --params-stdin -- tail -n 50 -- {path} < tail.json
```

The node never opens a file of yours for it.

`nerve-node cap edit NAME` changes what you give and keeps the rest (a
command after `--` replaces the command); `nerve-node cap rm NAME` removes
it, and it leaves every center at once. The name is what an entry is known
by, so to rename one, remove it and add it again; a switch set for the old
name stays (below).

## Arguments

A word of the command written `{field}` is the call's argument `field`:

```sh
nerve-node cap add logs.tail --effect read \
  --params '{"type": "object", "required": ["path", "lines"],
             "properties": {"path": {"type": "string", "x-nerve-path": "read"},
                            "lines": {"type": "integer"}}}' \
  -- tail -n {lines} -- {path}
```

- Each `{field}` becomes one whole argument of the program, exactly as the
  call gave it. No shell reads the command, so `;`, `|`, `$(...)` and quotes
  in a value are just characters. A placeholder is always a word of its own:
  `--file={path}` is refused. A word in braces with no blank in it is always
  a placeholder, so a command that needs such a word as it is (`jq '{a:.x}'`)
  cannot be declared; one with a blank in it (`{ cd /srv && make; }`) is
  text of yours. That holds for the node only: a program that
  hands its arguments to a shell of its own reads a value as code again, as
  `ssh host cmd {arg}` does on the other machine and `sh -c`, `su -c` or
  `flock -c` do here. Fill no placeholder into such a command.
- An argument may be a string, a number, an integer or a boolean. One the
  call leaves out (or gives as null) is left out of the command, so the words
  after it would move up: an option before it would take the next word as its
  value. An argument the call may leave out (not in `required`, or one that
  takes null) therefore stands after a `--` word and comes last; `tail -n
  {lines}` needs `lines` in `required`.
- A value that starts with `-` would read as an option of the program. It is
  taken only after a `--` word of the command, where programs read no
  options; before one the call is refused. Put `--` before the arguments that
  name files or text.
- Every argument of `--params` must appear in the command, and every
  `{field}` must be one of them.
- The schema keeps to what a center can check: flat objects, no `oneOf`,
  `anyOf` or `$ref` ([harness.md](harness.md)). A call whose arguments do not
  fit it is refused before anything runs.

An argument marked `"x-nerve-path": "read"` or `"write"` is a path. The node
judges it as it judges an `fs` call's path ([providers.md](providers.md#paths-it-takes)
says how), and the program gets it as the node resolved it. An argument that
names a path but is not marked is passed as given: no folder, protected path
or rule on paths holds it beyond what `nerve-run` itself may reach, and in
`folder` mode the call counts as one that names no path.

## The account it runs as

Every capability of `node.toml` runs as the installed node's command account
`nerve-run`, from its home `/var/lib/nerve-run`, held like that account's
commands:

- In a `folder` or `allowlist` pairing whose commands run as `nerve-run`: that
  pairing's folders and the account's own (its home, `/tmp`, `/var/tmp`),
  held there by Landlock where the kernel has it.
- In a pairing whose commands run as you (`user` mode, `allowlist
  --as-owner`): the account's own folders alone, since your folders are not
  `nerve-run`'s.
- Without Landlock: what `nerve-run` itself may reach.

It reads a path outside the folders only where `nerve-run` may read it, never
your files closed to others nor the node's own, and where Landlock holds the
commands, only in the pairing's folders and the system's files. In a pairing
whose commands run as `nerve-run`, the agent's `list` says so: the details of
such an action read `runs as: the command account, held like its commands`.

There is no other account: a capability of `node.toml` never runs with your
rights. A command that needs them belongs in a [program you
allow](providers.md), which runs as you and whose paths count only in the
folders you grant. An entry with an `account` line, from an earlier version,
is refused: remove the line.

A node you run yourself has no `nerve-run`, so it offers none: `cap ls` shows
each one as left out, and why.

Each run counts towards `limits.max_running`, runs in a cgroup of its own
held to `[limits.command]` ([limits.md](limits.md)) and ends at its timeout.
A cancelled call ends it too. A command that does not end with exit code 0
fails: the agent gets its exit code and what it printed to stderr, marked as
content from your machine, as a result is (and, like a result, it marks the
session for the action checker).

### Keep secrets out of the command

While a command runs, its line, with the call's values in it, is there for
every account on the machine to read, as every program's is (`ps`, `/proc`):
for the centers' commands and file reads too. So a token or a password in
the command is a token any center may read while it runs, and a value one
center gives a call another may read the same way. Put a secret in a file
the program reads (`curl -H @file`, a `--config` file). Even then a
capability cannot keep a secret from the centers whose commands run as
`nerve-run`, since they read what it reads: a secret that must stay yours
belongs in a [program](providers.md).

## When a center may use it

As any capability, by what it does ([modes](modes.md#what-each-mode-allows),
[rules](rules.md)):

| Mode | It runs when |
|---|---|
| `allowlist` | an allow rule names it: `nerve-node config add center.<name>.policy.allow 'logs.tail'` |
| `folder` | a `read`: its paths are anything `nerve-run` may read (above); a `write` or `execute`: its paths lie in folders that allow them; one that takes no path needs `nerve-node cap set logs.tail on` |
| `user` | always |

One that senses or acts on the world (`sense`, `actuate`) needs you: your
`cap set NAME on` in `folder` and `user` mode, an allow rule you add in
`allowlist` mode. A center with the [settings grant](settings-grant.md) may
turn on or allow the others itself, never one that senses or acts, and cannot
add, change or remove a capability of `node.toml`.

A switch or allow rule set earlier may cover a capability you add later: `cap
set sensors on`, or an allow rule `sensors`, also covers a new
`sensors.camera`, and a center may have set it while `sensors` only read.
So when `cap add` declares an action that senses or acts, or `cap edit`
changes one to, it switches that action off for every center such a switch
or rule covers, and says which; turn it on for those you mean. `nerve-node
config accept` does the same for what you wrote into `node.toml` yourself,
while the node runs; a node that is stopped cannot see what the file had
before, so take such a change while it runs, or check `cap ls` after. A
switch you set stays when you remove a capability.

A center cannot turn on a capability of yours that has an action that senses
or acts, whether or not this node offers that action now (one for another
platform, or any on a node you run yourself).

No program may [attach](providers.md) with the name of one of your
capabilities, and one that is attached with such a name is let go when you
declare it.

## See what is there

`nerve-node cap ls` lists them with the source `config`, each with its
command:

```
sensors.read  sense  config  lab: off
logs.tail     read   config  lab: on
win.who       read   config  left out: for windows only
capability sensors.read: sensors -j
capability logs.tail: tail -n {lines} -- {path}
capability win.who: whoami; windows only
```

A capability this node does not offer says why. `nerve-node cap ls --json`
gives each one as declared under `config`.

## In `node.toml`

`cap add` writes an entry like this one. The schemas are JSON text:

```toml
[[capability]]
name = "logs.tail"
summary = "The end of a log file."
effect = "read"
command = ["tail", "-n", "{lines}", "--", "{path}"]
params = '{"type": "object", "required": ["path", "lines"], "properties": {"path": {"type": "string", "x-nerve-path": "read"}, "lines": {"type": "integer"}}}'
result = "text"         # or a JSON Schema
timeout_secs = 10       # optional
platform = "linux"      # any | linux | windows
```
