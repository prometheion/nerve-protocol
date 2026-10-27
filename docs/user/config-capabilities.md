# Capabilities of your own in `node.toml`

You can give the agent a capability of your own without writing a program:
a fixed command the node runs itself, such as `sensors.read` running
`sensors -j`. You declare it once; every center then sees it next to `fs` and
`exec`, the node decides each call to it by that center's mode and rules, as
for any other capability, and writes it to the [audit log](audit.md) (with
the command as it ran, the call's values in it, which no center sees). For a capability that keeps a connection or state of its own, write a
[provider](providers.md) instead.

They run on Linux: the [installed node](service.md) offers all of them, a node
you run yourself only those that run as you (below). Windows keeps them in
`node.toml` and offers none yet.

## Add one

```sh
nerve-node cap add sensors.read --effect sense --summary "Temperatures of this machine." \
  --result '{"type": "object"}' -- sensors -j
```

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
| `--account` | `nerve-run` (the default) or `owner` (below) |
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
  `--file={path}` is refused. That holds for the node only: a program that
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
or rule on paths holds it, and in `folder` mode the call counts as one that
names no path. For a capability that runs as you that means your whole
access, so `cap add` and `cap edit` warn of a string argument without the
mark there.

## The account it runs as

| `account` | Runs as | Folders |
|---|---|---|
| `nerve-run` (default) | the installed node's command account, from its home `/var/lib/nerve-run` | in a `folder` or `allowlist` pairing whose commands run as `nerve-run`: that pairing's folders and the account's own (its home, `/tmp`, `/var/tmp`), held there by Landlock where the kernel has it. In a pairing whose commands run as you (`user` mode, `allowlist --as-owner`): the account's own folders alone, since your folders are not `nerve-run`'s. Without Landlock, what `nerve-run` itself may reach |
| `owner` | you, with your rights, from your home (root where root is the owner; `cap add` warns of it) | like a [provider's](providers.md): only the folders you granted count for its paths, and no sandbox holds it |

A capability that runs as `nerve-run` is a command of that account: it reads
a path outside the folders only where `nerve-run` may read it, never your
files closed to others nor the node's own, and where Landlock holds the
commands, only in the pairing's folders and the system's files. In a pairing
whose commands run as `nerve-run`, the agent's `list` says so: the details of
such an action read `runs as: the command account, held like its commands`,
while those of one that runs as you are held to the folders as a program's.
Choose `owner` only for a command that needs your rights; it can do whatever
you can.

A command that runs as you must not run what a center may write: a center
with `w` on a folder could put its own code there and have it run with your
rights. A center may write in a `w` folder of its own, in `/tmp` and
`/var/tmp`, in `nerve-run`'s home, and, in `allowlist` mode (also one a
`--for` limit fell back to), wherever an allow rule lets an action of a
program of yours, or of a capability that runs as you, write at a path it
names (an argument marked `write`, whatever effect the action names), and an
allow rule for `fs` where its writes run as you (`--as-owner`, or any
pairing of a node you run yourself): `fs.write:~/site/**` counts like a `w`
folder `~/site`, a write rule with no path like your whole machine. On the
installed node a center may also write whatever belongs to `nerve-run` or
`nerve-run` may change (a file it may write, a folder it may add to, or a
folder above either): a file a center made while it had `w`, or replaced
(as `fs.write` writes a file), stays `nerve-run`'s once you take the `w`
away, and any pairing whose commands run as `nerve-run` may still change
it. So the node refuses its calls
while one of these lies in such a place:

- your home, where it starts (`make`, `npm test` or `python3 -m` read code
  from where they start, so a center with `w` on your whole home blocks every
  such command);
- its program, as found in `PATH` (the node then runs that very file; a
  program it finds none of that you may run does not start);
- a place a word of its command names: a full path, a path from your home
  (`make -C proj`, `sh proj/ci.sh`), a name of something in your home, also
  as an option's or a variable's value (`--manifest-path=proj/Cargo.toml`,
  `-Cproj`, `-I/srv/lib`, `PYTHONPATH=proj`), each part of a list of paths
  (`PYTHONPATH=lib:proj`, `-cp app.jar:proj/*`), the path of a URL
  (`file:///srv/pkg`) and the file of `@file`. A place not there yet counts
  by where the folder it would be in leads, and a link whose target is gone
  by where that target would be.

The node judges this as you, from your home, before each call; the center
is told only that the call is refused, and the node's audit log says which
place. `cap add` and `cap edit` ask the running node and warn of it (not for
a capability this node does not offer). Keep what such a command reads on its
own (its configuration, a file a script loads) out of those folders too: the
node cannot see what a program reads.

What a center wrote stays when its right to write ends. The node tells
apart what `nerve-run` made or replaced, but not:

- a file of yours that a center wrote into in place while it had `w` (a
  command's `cat > deploy.sh` or `cp new.sh deploy.sh`): it stays yours,
  with your mode, and holds what the center wrote;
- what a center wrote as you: through a program of yours, a capability that
  runs as you, `user` mode or `--as-owner`.

So before such a capability runs again once you took a center's `w`, an
allow rule or `user` mode away, look at what its command runs yourself.

A node you run yourself has no `nerve-run`: it offers only capabilities with
`account = "owner"`, run as you.

Each run counts towards `limits.max_running`, runs in a cgroup of its own
held to `[limits.command]` ([limits.md](limits.md)) and ends at its timeout.
A cancelled call ends it too. A command that does not end with exit code 0
fails: the agent gets its exit code and what it printed to stderr, marked as
content from your machine, as a result is (and, like a result, it marks the
session for the action checker).

## When a center may use it

As any capability, by what it does ([modes](modes.md#what-each-mode-allows),
[rules](rules.md)):

| Mode | It runs when |
|---|---|
| `allowlist` | an allow rule names it: `nerve-node config add center.<name>.policy.allow 'logs.tail'` |
| `folder` | a `read`: its paths are anything the account it runs as may read (above); a `write` or `execute`: its paths lie in folders that allow them; one that takes no path needs `nerve-node cap set logs.tail on` |
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
platform, or one that runs as `nerve-run` on a node you run yourself).

No program may [attach](providers.md) with the name of one of your
capabilities, and one that is attached with such a name is let go when you
declare it.

## See what is there

`nerve-node cap ls` lists them with the source `config` (`config (owner)` for
those that run as you), each with its command:

```
sensors.read  sense    config          lab: off
logs.tail     read     config          lab: on
win.who       read     config (owner)  left out: for windows only
capability sensors.read: sensors -j; as nerve-run
capability logs.tail: tail -n {lines} -- {path}; as nerve-run
capability win.who: whoami; as owner; windows only
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
account = "nerve-run"   # or "owner"
platform = "linux"      # any | linux | windows
```
