# Capabilities

A node describes what it can do in a **descriptor**. The center offers it to
the agent through its two MCP tools, `list` and `execute`
([mcp-surface](mcp-surface.md)). Exact shapes:
[spec/protocol.md](spec/protocol.md) §5 to §7.

## Capabilities

A capability is a named part of a node, with four kinds of members:

| Member | Direction | Meaning |
|---|---|---|
| Action | center to node, with a reply | Do something: read a file, run a command |
| Event | node to center, once subscribed | Something happened |
| State | read with `get`, change-notified | A value the node holds, by key |
| Stream | opened with `stream.open`, continuous | Data without a known length |

A program's capability ([node-local §7](spec/node-local.md#7-capability-providers))
may offer all four. Its state keys, events and streams each have an effect,
`read` or `sense`: they only take data in. They share one set of names with
its actions, so each is a unit `cap.name` of its own for the agent, and the
node decides and audits each like a call. A capability of the owner's config
offers actions only.

A capability may follow a **profile**, a published contract such as `fs` or
`exec`. A capability without a profile is usable from its schemas alone.
Parameters, results, event data and state are JSON Schemas of a small subset
of 2020-12 ([protocol §6.1](spec/protocol.md#61-schemas)): one type (or one
type and `null`), properties, items, enums and bounds; no `$ref`, `oneOf`,
conditions, `pattern` or `format`. `nerve_proto::schema::check` says whether
a schema keeps to it, `nerve_proto::schema::validate` whether arguments fit
one. The node runs `check` on every schema it publishes (a test covers each
built-in one), on a provider's and on those of the owner's config
capabilities, and `validate` on the arguments of both;
the center runs `check` on every schema of a descriptor it reads (event data
and state included) and `validate` before every call it sends.

## Descriptor

```json
{"nerve": "0",
 "node": {"id": "…", "name": "laptop", "platform": "linux", "arch": "x86_64",
          "software": {"name": "nerve-node", "version": "…"}},
 "rev": 7,
 "summary": "Linux laptop of the owner (under 60 words)",
 "capabilities": [
   {"id": "fs", "profile": "fs", "provider": "node", "exposure": "on",
    "summary": "…",
    "actions": {"read": {"effect": "read", "summary": "…",
                         "params": {"type": "object", …}, "result": {…}}},
    "events": {}, "state": {}, "streams": {}}]}
```

- The descriptor a center gets is filtered by that center's policy. A
  capability that is `hidden` for it is absent. One that is `off` is listed
  with `exposure: "off"`.
- In `allowlist` mode, an `fs` or `exec` action is also absent unless an allow
  rule covers its capability and action. `list` then offers nothing the node
  would refuse. `exec.run` also stays when the sudo list has an entry.
- `rev` changes whenever what this center sees changes. The node sends
  `node/descriptor_changed` and the center asks again.
- `describe` has three levels of detail: `summary` (no schemas), `capability`
  (one capability in full) and `full`.
- Capability ids and action names are 1 to 64 bytes of letters, digits, `-`
  and `_`, never `.`. The harness side names an action `<cap>.<action>`, and
  a `.` inside a name would make that name ambiguous. A node refuses a
  provider with another name. A center leaves out the actions of a
  capability with another character in its id, an id over 64 bytes or an id
  the descriptor gives twice, and an action with another character in its
  name or a name over 64 bytes, and keeps the rest.
- The center builds a catalog per node from its descriptor
  (`nerve-center` `catalog.rs`): one unit per `cap.action`, and for a
  program's capability one per state key, event and stream too, each with
  its kind. The units it left out are kept with their reasons: a bad name, a
  schema outside the subset (only that unit, for a program's capability;
  every action of one of the node's own capabilities whose event data or
  state is outside it), a name given to two kinds. The
  catalog is rebuilt from the descriptor, never stored; `list` reads it, and
  the overview shows what was left out. Each unit has a hash over its name,
  effect, description, `params` and `result`: `execute` runs a unit only
  while its hash is the one `list` gave the session
  ([harness.md](spec/harness.md) §4.3).
- `provider` says which process serves the capability: `node` for the node's
  own, `config` for one the owner declared in `node.toml` (`[[capability]]`:
  a fixed command the node runs itself, [node-local §2](spec/node-local.md#capabilities-of-the-config)),
  `center-added` for one a center with the settings grant added itself
  (`settings.cap-add`: a fixed command as in `node.toml`, kept in that
  center's entry and offered to that center alone, [node-local §2](spec/node-local.md#capabilities-a-center-adds)),
  else the name of a local program the owner allowed to attach to the
  node ([node-local §7](spec/node-local.md#7-capability-providers)). A
  config or center-added capability has actions only; a program's may add
  state, events and streams. The node decides each call, `get`, subscription and stream to
  them by the center's policy before the program or the command sees it. The names
  `node`, `fs`, `exec`, `settings`, `audit`, `job` and `stream`
  (`nerve_policy::config::BUILT_IN`) are taken by none of them, no program
  may add a capability the config declares, and no center one the config
  declares or an attached program offers.

## Effects

Every action has an effect. The node's policy maps modes and rules onto them.

| Effect | Meaning | Example |
|---|---|---|
| `read` | Returns data the node already holds | `fs.read` |
| `sense` | Captures the user or the surroundings | none built in |
| `write` | Changes data on the node | `fs.write` |
| `actuate` | Acts on the outside world | `exec.signal` |
| `execute` | Runs code the center chose | `exec.run` |

`execute` stands apart because running a command includes every other effect.
`list(node, capability)` names each capability's effect; the MCP tools'
annotations are fixed (`list` read-only, `execute` destructive), whatever
the effect. (The `execute` effect and the `execute` tool share only the
word.)

`folder` and `user` mode do not cover `sense` and `actuate` actions. They run
only when the owner set the action to `on`, or, in `allowlist` mode, when an
allow rule names them; only the owner turns them on, never a center with the
settings grant. A mode allows the same for every capability by its effect
(the table in [policy-engine](policy-engine.md)). An action names the paths
it takes by marking top-level string arguments of its `params` with
`x-nerve-path: "read"` or `"write"` ([protocol](spec/protocol.md)); `fs`
marks its `path` and `exec.run` its `cwd`. In `folder` mode a read is
allowed, each path it reads in an `r` folder (on the installed Linux node,
outside every folder, one open to every account); a write or a run is
allowed when every marked path lies in a folder with the matching flag; a
read, write or run needs `on` when it names none (a write: no path it
writes), since an argument it does not mark is no path to the node; a
`sense` or `actuate` action needs `on`, and its marked paths stay in the
folders too. A folder the node is handed for another program (or a path a
write would make) counts with what lies below it, deny rules of that
capability included; a file does not.

## Built-in profiles

| Capability | Members |
|---|---|
| `node` | State `status` (`online`, `busy`, `paused`). Implicit events `descriptor_changed`, `going_away`, `capability_changed` |
| `fs` | Actions `stat`, `list`, `read`, `grep`, `find` (effect `read`) and `write` (effect `write`, with `if_match`). Paths are absolute. On Windows they look like `/c/Users/…` |
| `exec` | Actions `run` (`execute`) and `signal` (`actuate`). Event `exit`. State `shell` and `confinement`. The `run` text names the shell |
| `settings` | State `document`. Actions `set` (with `if_version`), `pause`, `sudo-offer` and `sudo`. Only for a center with the settings grant |
| `audit` | Event `decision` (needs `sub`) |

- `fs.read` returns at most 2 MiB. `fs.write` takes at most 3 MiB. A `write`
  with an `if_match` that no longer matches fails with `conflict`.
- A command's output comes in its result, at most 1 MiB for stdout and 1 MiB
  for stderr. While it runs, `exec`'s `output` stream (params `{call}`)
  carries it as it comes, to the center and session the call came from only;
  the center opens it when the call becomes a job
  ([harness spec §4.5](spec/harness.md#45-streams-and-events)).
- `exec.signal` is offered only where the policy allows it: by an allow rule in
  `allowlist` mode, with `caps.exec.signal = on` in `folder` and `user` mode.
  On the wire its `call` is the `invoke` id of a running `exec.run`; the
  center offers it to the agent with the job's id instead and maps it
  ([harness spec §4.4](spec/harness.md#44-jobs)).
- `job` and `stream` are no capability of a node: the center serves `job.status`,
  `job.cancel`, `stream.read` and `stream.close` itself. A node's capability
  of either name is not offered, and a node refuses a provider of these names.
- Every command has a time limit: `timeout_ms`, else the node's default, and
  never more than the node's maximum (the owner's `limits` in `node.toml`).
  The schema gives the default as `default` and the most in the
  `description`, not as `maximum`, since a larger value is cut, not refused.
- `exec.run` takes `memory_mb`, `cpu_percent` and `processes`, each up to
  the most the owner set (`limits.command`); the descriptor shows the
  defaults and the most. A command killed for its memory has `killed:
  "memory"` and a `reason` in its result.
- A timeout, `cancel` or `session.end` kills the command's process group. On
  Windows they end the command's Job Object; a timeout, and `exec.signal`
  with `term` or `int`, first ask the command to end (Ctrl+C, `WM_CLOSE`) and
  end the job 3 seconds later ([node-local](spec/node-local.md#commands)).

## Messages

JSON-RPC 2.0, one object per text frame, no batches, `params` always an
object.

| Message | Direction | Does |
|---|---|---|
| `challenge`, `hello`, `welcome` | both | Handshake |
| `describe {detail, cap?}` | center to node | Get the descriptor |
| `invoke {cap, action, args, ctx, deadline_ms?}` | center to node | Run an action |
| `cancel {id}` | center to node | Stop an invoke. One final reply still follows |
| `get {cap, keys}` | center to node | Read state |
| `sub {topics}`, `unsub {topics}` | center to node | Topics `<cap>/<event>`, `<cap>/state`, `<cap>/*` |
| `event`, `state` | node to center | Something happened, state changed |
| `stream.open {cap, stream, params, ctx}`, `stream.close {sid, reason}` | center opens, either closes | Reliable streams; their data comes as binary frames |
| `session.end {session}` | center to node | A harness session ended. The node cancels that session's calls |
| `bye {reason}` | either | Clean close |

`ctx` holds only `session`, an opaque id the center chose (at most 256 bytes).
Any other field is refused. There is no field for "allowed", a mode or a
folder, so a center cannot say a call is allowed.

Events of `node` and `settings` are implicit. Everything else needs `sub`.

## Errors

Errors carry the JSON-RPC code and a string code in `data.code`:
`invalid_args`, `forbidden`, `disabled`, `unavailable`, `busy`, `timeout`,
`cancelled`, `too_large`, `unknown_capability`, `unknown_member`,
`connection_lost`, `internal`. Profiles add `conflict`, `bad_path` and `io`.
The `message` is for people and models and says what to do next. Arguments
that do not fit the action's schema are `invalid_args` with `data.field` (a
dotted path such as `sudo.sealed`) and `data.expected` (in words, such as
`an integer from 1 to 600`).

## Capability providers in use

A program on the machine, such as a desktop app, can add capabilities of its
own to the node: a lamp it switches, a window it shows. It attaches to the
running node as a **provider**, and every center then sees its capabilities
next to `fs` and `exec`. The program never talks to a center. The node decides
every call to it by that center's mode and rules, as it does for files and
commands, and writes it to the [audit log](logging.md#the-audit-log-as-the-owner-reads-it).

For a fixed command, such as `sensors -j`, no program is needed: declare it in
`node.toml` with `nerve-node cap add` ([capabilities of your own](#capabilities-of-your-own-in-nodetoml)).
Such a command runs as the node's command account `nerve-run`, held to the
folders; an action that needs your own rights, such as restarting a service of
yours or reading your files, comes from a program you allow here.

Providers work on Linux: a program of yours (or of root) attaches to the
[installed node](service.md#the-node-as-a-service) on its provider socket (its control socket
takes none), and to a node you run yourself on its control socket. Windows
takes no provider yet.

### Allow a program

No program may attach until you name it, with a name of your choice (not
`node` or `config`, which stand for the node's own capabilities and those of
[`node.toml`](#capabilities-of-your-own-in-nodetoml)) and the full path of its executable:

```sh
nerve-node provider add desk /usr/lib/nerve-desktop/nerve-desktop
```

The node checks that the program that attaches under that name runs that very
file. Allowing a name again replaces its program. A center cannot change the
list. To let a program go:

```sh
nerve-node provider rm desk
```

Its capabilities leave at once. In the [desktop app](desktop.md#capabilities)
the list is on **Capabilities** › **Programs**. `nerve-node provider` lists the
programs you allow and whether each is attached; `nerve-node status` lists the
providers that are attached:

```
provider desk attached: lamp
provider desk: lamp.dim left out: params: /properties/level/oneOf: oneOf: alternatives are not supported: use one schema, with enum for a choice of values
```

The second line is an action the node left out (below); `nerve-node status
--json` has them as `broken`. A reason is one line, cut after 300
characters, since it holds names from the program's schemas.

On the installed node only your own programs and root's attach: the node
tells who asks by the account the system names for it, refuses any other
account at once, and refuses a program that a center's command started, also
when it runs the allowed program. A program that runs with `no_new_privs`
(a unit with `NoNewPrivileges=yes`, a flatpak or another sandbox that sets it)
is refused too, as every command the node runs keeps that, and it is told
so: start it without. The node looks at which program asks with that
account's rights (for root's programs it starts a short helper as root to
look), and a program that ended while it looked is refused.

The check tells programs apart, not users: another program of your user can
still make the allowed one attach for it. Allow only programs you trust.

### See what is there

`nerve-node cap` lists every capability, one action a line (and a
program's state keys, events and streams, each with its kind after the
effect): what it does (its effect), where it comes from (`built-in`, `config` for
[your own](#capabilities-of-your-own-in-nodetoml), or `program desk`), and for
each center whether it may use it now (`on` or `off`, as its mode, rules and
switches decide), with the switch in brackets where you set one with `cap
set` (`hidden` ones say just that), for one center with `--center`. The
`settings` actions, with which a center changes its own entry, have no switch:
they say `granted` or `not granted`, as `center settings` set it. An
action the node left out says why. A switch for something no program offers now is
listed too, as it counts once one does. On a stopped node it lists the node's
own capabilities and the programs you allow, and for each center only the
switch (`on`, `off`, `hidden`, or `default`, where the mode decides):

```
fs.read       read     built-in      lab: on
fs.write      write    built-in      lab: off
settings.set  write    built-in      lab: off (not granted)
lamp.on       actuate  program desk  lab: on (set on)
lamp.dim      -        program desk  left out: params: /properties/level/oneOf: …
program desk: /usr/lib/nerve-desktop/nerve-desktop, attached
```

`on` says the center is offered the action; each call is still decided by
its paths and rules.

### Allow its capabilities

A provider's capability is decided like any other, by what it does
([modes](policy-engine.md#what-each-mode-allows), [rules](policy-engine.md#rules-as-the-owner-writes-them)):

| Mode | A provider's action runs when |
|---|---|
| `allowlist` | an allow rule names it: `nerve-node config add center.<name>.policy.allow 'lamp.on'`, or `'lamp'` for all its actions, or holds it to values of its arguments (`'lamp.set:room=office'`, [rules](policy-engine.md#rules-on-an-actions-arguments)) |
| `folder` | it reads, writes or runs something at paths it marks ([below](#paths-it-takes)) that the folders allow; or you set it on: `nerve-node cap set lamp on` (one that names no path lies in no folder, a read included, a write whose only paths are ones it reads names no place it writes, and one that senses or acts on the world needs `on` anyway, its paths in your folders too) |
| `user` | always, except one that senses or acts on the world, which needs `on` |

Deny rules and `off` and `hidden` work as for `fs` and `exec`. A call to an
action that is `off` is refused with `disabled` and written to the audit log.
A center with the [settings grant](settings-and-config.md#the-settings-grant) can allow a provider's
action itself while the provider is attached, except one that senses (a
camera, a microphone) or acts on the world (a lamp, a lock): only you turn
those on, and only you take away an `off` switch or a deny rule that keeps
one off. While no provider offers a capability or one of its actions, only
you can allow it or turn it on, as the node cannot tell yet what it does. An
entry a center wrote while the capability did neither stays when a new
version of the program makes it sense or act: after such an update, check
`nerve-node rule allow` and `nerve-node cap`. A capability a center
[added itself](#capabilities-a-center-adds) does not
count as offered for this: that center switches only its own actions, each
by its name, and while it keeps one under the name a program offers, it is
not offered the program's.

### Paths it takes

An action that reads or writes files names them as arguments its schema
marks with `x-nerve-path`, `"read"` or `"write"`:

```json
"params": {"type": "object", "required": ["path"],
           "properties": {"path": {"type": "string", "x-nerve-path": "read"}}}
```

The node then judges each such path as it judges an `fs` call's: in `folder`
mode a path read needs an `r` folder and one written a `w` folder (one that
runs something also `x`, and only where the machine can confine commands: where
it cannot, `x` lets nothing start, so `folder` mode neither offers nor runs a
program's `execute` action with paths, as it runs no command); [rules](policy-engine.md#rules-on-an-actions-arguments) match the path
(`notes.open:path~~/private/*`); protected paths and the node's own files are refused;
and the [audit log](logging.md#the-audit-log-as-the-owner-reads-it) names the path, also one that does not resolve.
On the installed Linux node a read outside every folder goes where every
account may read ([reading in folder mode](sandbox-linux.md#reading-in-folder-mode)),
and only for a file. There only the folders you granted count for a program:
the folders of `nerve-run` itself (the pairing's own home and temporary
folder, `/tmp`, `/var/tmp`, marked `own` in what the agent is told) are that account's, while the program works with
your rights, so a path there is in no folder. A path given that is a link is followed to where it
leads and judged there. A path to write that is itself a link is refused
(`bad_path`): the program would remove, rename or write the place it leads
to, which you did not name, so name that place instead. The program gets the
path as the node resolved it, links followed, so it works where the node
looked; a path that resolves to a name that is not valid Unicode, or to one
the program's own schema does not take, is refused (`bad_path`). A refusal
names each path as the center gave it, never where it led: the
[audit log](logging.md#the-audit-log-as-the-owner-reads-it) says that. The center's
[action checker](action-checker.md#the-blocklist) holds the same paths: its
`fs` blocklist entries refuse a program's call that reads or writes a path
they name, and the audit entry names the paths. Only the
top-level arguments can be marked, each a string. A call whose marked path
it leaves out names no folder: it needs `on`, as an action without paths
does.

The node sees only the marked arguments. One the program does not mark is
not a path to the node: no folder, rule, protected path or own file of the
node holds it, and the program reads or writes there with your rights. So in
`folder` mode an action that marks no path needs `on`, a read too. A program
that reads or writes files should mark every path argument; one written
before the marker existed marks none. Switch an action `off` that takes a
path without the marker, or set it `on` only if you would let it read and
write anywhere you can.

A folder given as a path counts with everything below it, since the program
may read or write anywhere in it: the call is refused when a protected path
that no folder releases, the node's own files, a place a deny rule of that
action names (`notes.open:path~~/private/*` refuses `notes.open` the folder `~` too) or,
in `folder` mode, a folder you gave less lies below it. An `execute` action
runs its program there, so for it a folder below without `x`, or a protected
path released without `x`, refuses the call too. The refusal names the
folder handed over, not what lies below it. A file holds nothing below it:
`notes.open:path~~/proj/*.env` refuses `notes.open` the folder `~/proj`, but not
`~/proj/readme.md`. A path a write names that does not exist yet counts as a
folder, since the program may make one there.

A program follows the links in a folder it is handed, which the node's own
walks never do. So before the call the node looks for them, as the command
account: each link below the folder, and below a folder a link leads to, is
judged where it leads, as if the call named that place in the folder's
stead, its other paths unchanged, and one that leads where the call may not
go (outside the folders, to a protected path, to a place a deny rule names)
refuses the call. A link that stays inside the folder handed over, or
inside the folder a link that passed leads to where it lies, is judged as
the other names there, so in `allowlist` mode a rule that covers that
folder covers it too. The node looks into a folder a link leads to only
when that link passed, and the refusal names the link, not where it leads.
On the installed node the program runs as you (or root) and the search as
`nerve-run`: a folder below that `nerve-run` may not look into, which your
program could, refuses the call, since the node cannot tell where the links
there lead. Give `nerve-run` that folder too, or hand the program a folder
that does not hold it. A folder granted `x` without `r` counts as one
`nerve-run` may not look into: it may enter it but not list it.
So a program handed such a folder, or a folder that holds one, is refused;
grant it `r` too, or hand the program a file in it. A program of root is held so whenever the node itself
does not run as root, also where root is the owner and the search runs as
root: the node still lacks root's rights to look into another account's
folder.
A link that leads nowhere counts only for a write, at the place it names. A
call whose folders hold more than 200 000 entries in all, counting those of
the folders their links lead to, is refused, since the node cannot check
them all. A call that ends (its deadline passes, or it is cancelled) while
the node looks for the links stops that search and never reaches the
program; the [audit log](logging.md#the-audit-log-as-the-owner-reads-it) has it as refused, `cancelled`. An `fs:` rule covers `fs` calls
only: to keep every capability out of a place, deny it for each action that
takes paths (`notes.open:path~~/private/*`), or make it a [protected
path](policy-engine.md#protected-paths-as-the-owner-sees-them).

A folder a program writes in is not checked for the places whose writes
run code later, as an `fs.write` is (`.git`, `.envrc`, `.vscode`, `.idea`):
the program may make them anywhere below it, so the node cannot check them
before the call. An `fs.write` there is refused; a program that unpacks or
syncs into a folder of yours can write them. Let such an action run only
where every folder with `w` can take that, or switch it `off`.

The node checks the path when the call comes; the program reads or writes it
afterwards with its own account's rights (yours, or root's for a program
root runs), so a link put in or swapped in between is not caught: a command
with `w` in a folder can make one. Allow only programs you trust. A program
root runs reaches with such a link everything root may read or write, so
let it take no paths in a folder a center may write in: switch its actions
that take paths `off` for such a center, or run the program as yourself.
Inside a folder you granted, the folder's flags decide a program's path,
not whether you yourself may read or write that file, so a program root
runs on a node you own reads and writes there with root's rights also what
only root (or another account) may: a file a root tool left there, say. Run
a program that takes paths as yourself, or grant it only folders that hold
nothing of root's or another account's.

When the program exits, its capabilities leave what `list` shows the centers,
a call that was waiting for it fails with `unavailable`, and its streams end.

### State, events and streams

Besides actions, a program's capability can offer what it only tells:

- a **state key**, a value the agent reads when it wants (`sensors.temperature`);
- an **event**, something the program reports when it happens (`door.opened`);
- a **stream**, text the program sends for as long as it runs (`camera.log`).

Each reads (`read`) or senses (`sense`); anything that changes the machine
is an action. All four share the capability's names: `sensors.temperature`
is either an action or a state key, never both, and the node refuses a
program that names one twice. The agent sees each one in `list` with its
kind (`- sensors.temperature (state): …`) and uses it with `execute`: a
state key gives its value now; an event subscribes the agent's session and
answers a stream id, which `stream.read` reads, one event a line; a stream
opens and answers a stream id the same way. There are no notifications: the
agent reads with `stream.read` when it wants, waiting a while if nothing is
there yet. A program has 30 seconds to answer the opening of a stream; the
agent's `execute` does not wait that long, but gets the stream id once the
center's call wait passed, and the stream opens when the program answers.

The node decides each one like an action that names no path, by its effect
and name: `nerve-node cap set sensors.temperature on`, an allow rule
`sensors.temperature`, `off` and deny rules work as above, and reading a
state, subscribing to an event or opening a stream is in the [audit
log](logging.md#the-audit-log-as-the-owner-reads-it). An event goes only to a center that may have it when it
happens, so a center you take `on` from gets no more of it, even while it is
still subscribed. An open stream is asked about again when you change the
config and when a mode's time limit passes: one the center may no longer
have ends, and the program is told. `nerve-node cap` lists them with
their kind after the effect (`sense state`, `read event`).

A capability of [`node.toml`](#capabilities-of-your-own-in-nodetoml) has actions only: a
value it reads is an action with effect `read` or `sense`.

### What it may name

Each capability, action, state key, event and stream has a name of 1 to 64
letters, digits, `-` and
`_`, such as `lamp` and `set_level`; the agent sees them joined,
`lamp.set_level`. An event may not be named `state`.
The node refuses a program that gives another name, or a capability that is
the node's own (`fs`, `exec`, …) or the center's (`job`, `stream`), or another
provider's already, and the program's attach fails with the reason. The
center serves `job.status`, `job.cancel`, `stream.read` and `stream.close`
on every machine itself, and
tells them by their capability, so a program you named `center` is yours like
any other
([long calls](mcp-surface.md#long-calls-become-jobs-1)).

### What its schemas may say

Each action describes its arguments and its result with a JSON Schema, a
state key its value, an event its data and a stream the arguments it opens
with (it marks no path: an open names none, so a program that reads at a
path the agent names offers that as an action). The
center hands them to the agent and checks every call's arguments against
them, so only a small, plain part of JSON Schema is allowed: one type per
value (or one type and `null`), properties, required fields, lists, a list of
allowed values (`enum`), bounds for numbers, texts and lists, and
descriptions. References (`$ref`), alternatives (`oneOf`, `anyOf`), conditions,
patterns and formats are not, nor is nesting more than three levels deep in
the arguments. What a text must look like goes into its `description`. The
exact list is in the [spec](spec/protocol.md#61-schemas).

An action (or a state key, event or stream) whose schema goes beyond that
is left out, and the program's others attach: `nerve-node status` names it
with the reason, and the node's log has a warning. If nothing is left, the
node refuses the program.

Arguments that do not fit an action's schema never reach the program: the
node answers `invalid_args`, naming the field and what it expected
(`level: expected an integer from 0 to 10`).

How a program attaches is in the
[spec](spec/node-local.md#7-capability-providers).

## Capabilities of your own in `node.toml`

You can give the agent a capability of your own without writing a program:
a fixed command the node runs itself, such as `sensors.read` running
`sensors -j`. You declare it once; every center then sees it next to `fs` and
`exec`, the node decides each call to it by that center's mode and rules, as
for any other capability, and writes it to the [audit log](logging.md#the-audit-log-as-the-owner-reads-it) (with
the command as it ran, the call's values in it, which the node sends no
center; while it runs, though, anyone on the machine can read it, see
[below](#keep-secrets-out-of-the-command)). Such a capability offers actions only: a value it
reads is an action with effect `read` or `sense` (an entry with `state`,
`events` or `streams` is refused). For a capability that keeps a connection
or state of its own, or sends events or a stream, write a
[provider](#capability-providers-in-use) instead.

They run as the command account `nerve-run` of the [installed
node](service.md#the-node-as-a-service) (below), on Windows in the pairing's
AppContainer ([Windows](windows.md#the-account-commands-run-as-on-windows)):
a node you run yourself has no such account and offers none.

### Add one

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

A summary is at most 2048 bytes, and each word of the command at most 4096
bytes. This holds for what you write into `node.toml` too.

`--params -` and `--result -` read the schema from stdin instead, for
one too long for the command line. Only one of them can come from stdin: add
the capability with one and `cap edit` the other.

```sh
nerve-node cap add logs.tail --effect read --params - -- tail -n 50 -- {path} < tail.json
```

The node never opens a file of yours for it.

`nerve-node cap edit NAME` changes what you give and keeps the rest (a
command after `--` replaces the command); `nerve-node cap rm NAME` removes
it, and it leaves every center at once. The name is what an entry is known
by, so to rename one, remove it and add it again; a switch set for the old
name stays (below).

### Arguments

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
  `anyOf` or `$ref` ([harness.md](mcp-surface.md#what-a-harness-and-its-model-see)). A call whose arguments do not
  fit it is refused before anything runs.

An argument marked `"x-nerve-path": "read"` or `"write"` is a path. The node
judges it as it judges an `fs` call's path ([providers.md](#paths-it-takes)
says how), and the program gets it as the node resolved it. An argument that
names a path but is not marked is passed as given: no folder, protected path
or rule on paths holds it beyond what `nerve-run` itself may reach, and in
`folder` mode the call counts as one that names no path.

### The account it runs as

Every capability of `node.toml` runs as the installed node's command account
`nerve-run`, from the home of the pairing that calls it
(`/var/lib/nerve-run/<center>/home`, with that pairing's `TMPDIR`), held like
that account's commands:

- In a `folder` or `allowlist` pairing whose commands run as `nerve-run`: that
  pairing's folders and the account's own (the pairing's home and temporary
  folder, `/tmp`, `/var/tmp`),
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
allow](#capability-providers-in-use), which runs as you and whose paths count only in the
folders you grant. An entry with an `account` line, from an earlier version,
is refused: remove the line.

A node you run yourself has no `nerve-run`, so it offers none: `cap` shows
each one as left out, and why.

Each run counts towards `limits.max_running`, runs in a cgroup of its own
held to `[limits.command]` ([limits.md](sandbox-linux.md#limits-per-command)) and ends at its timeout.
A cancelled call ends it too. A command that does not end with exit code 0
fails: the agent gets its exit code and what it printed to stderr, marked as
content from your machine, as a result is (and, like a result, it marks the
session for the action checker).

#### Keep secrets out of the command

While a command runs, its line, with the call's values in it, is there for
every account on the machine to read, as every program's is (`ps`, `/proc`).
Another pairing's command does not see it where the node gives each command
a [`/proc` of its own](sandbox-linux.md#a-proc-of-its-own), but every other
account, and that command on a kernel where `status` warns, does. So a
token or a password in the command is one others may read while it runs. Put a secret in a file
the program reads (`curl -H @file`, a `--config` file). Even then a
capability cannot keep a secret from the centers whose commands run as
`nerve-run`, since they read what it reads: a secret that must stay yours
belongs in a [program](#capability-providers-in-use).

### When a center may use it

As any capability, by what it does ([modes](policy-engine.md#what-each-mode-allows),
[rules](policy-engine.md#rules-as-the-owner-writes-them)):

| Mode | It runs when |
|---|---|
| `allowlist` | an allow rule names it: `nerve-node config add center.<name>.policy.allow 'logs.tail'` |
| `folder` | a `read`: its paths are anything `nerve-run` may read (above); a `write` or `execute`: its paths lie in folders that allow them; one that takes no path needs `nerve-node cap set logs.tail on` |
| `user` | always |

One that senses or acts on the world (`sense`, `actuate`) needs you: your
`cap set NAME on` in `folder` and `user` mode, an allow rule you add in
`allowlist` mode. A center with the [settings grant](settings-and-config.md#the-settings-grant) may
turn on or allow the others itself, never one that senses or acts, and cannot
change or remove a capability of `node.toml`. It may add capabilities of its
own ([below](#capabilities-a-center-adds)).

A switch or allow rule set earlier may cover a capability you add later: `cap
set sensors on`, or an allow rule `sensors`, also covers a new
`sensors.camera`, and a center may have set it while `sensors` only read.
So when `cap add` declares an action that senses or acts, or `cap edit`
changes one to, it switches that action off for every center such a switch
or rule covers, and says which; turn it on for those you mean. `nerve-node
config accept` does the same for what you wrote into `node.toml` yourself,
while the node runs; a node that is stopped cannot see what the file had
before, so take such a change while it runs, or check `cap` after. A
switch you set stays when you remove a capability.

A center cannot turn on a capability of yours that has an action that senses
or acts, whether or not this node offers that action now (one for another
platform, or any on a node you run yourself).

No program may [attach](#capability-providers-in-use) with the name of one of your
capabilities, and one that is attached with such a name is let go when you
declare it.

### Capabilities a center adds

A center with the [settings grant](settings-and-config.md#the-settings-grant) (`write`) may add
capabilities of the same kind itself, from its web UI's
[Capabilities](web-uis.md#capabilities) page. They are kept in that center's
own entry of the pairing, and only that center is offered them: another
center never sees them, cannot call them and cannot remove them. Within
these limits:

- **Always `nerve-run`.** It runs as the command account, held like that
  account's commands (above), never as you or root. There is no account to
  choose.
- **Counted as `execute`.** Whatever it says it does, the node decides it as
  a command: in `folder` mode one that takes no path needs an `on`, which that
  center may set itself, and one whose paths lie outside the folders that
  allow commands is refused. A `read` never passes for a read.
- **Switched by its full name.** The center turns on or allows each action it
  added by its name (`"caps": {"say.back": "on"}`, the allow rule
  `say.back`), not its capability as a whole (`say`): that stays yours while
  nothing else offers it, as a program you allow may offer more under that
  name later.
- **Sensing waits for you.** One that says `sense` or `actuate` stays so, and
  only you turn it on (`cap set NAME on --center <name>`), in every mode,
  also while a program or a capability of yours offers its name without
  sensing: the center sets no `on` or rule for that name meanwhile. When
  a center changes one to sense or act, or changes anything but the summary
  of one that does (its command, the arguments it takes, its time limit),
  a switch or rule that covered it is switched off, also your `on`: you turn
  on what it does now. So it is when you declare one that senses or acts
  under the name of one a center added: your `on` for the center's was
  given for its command, so `cap add` switches it off for that center too,
  and says so. It works the other way round as well. While you declare
  that capability, the center's own is left out, and an `on` you set for
  that name turns on yours. When you remove yours, the center's own is
  offered again, so `cap rm` switches that `on` off and says so. While a
  program you allow keeps the center's own out, that center is offered
  neither, and `cap set` refuses an `on` for that name with the reason: it
  would turn on the center's command once the program goes. Turn it on once
  the center is offered it. A file you take with `config accept` that has
  such an `on` gets it switched off, and `config accept` tells you to turn
  it on once the center is offered it, or to remove it.
- **Yours come first.** A center changes and removes none of your
  capabilities, and adds none under the name of a capability of yours or of
  a program you allow that is attached now. One it added is left out while
  you declare its capability or such a program offers it. The center can
  still remove that one. While it keeps it, that center is not offered the
  program's capability of that name either, and gets none of its events,
  state or streams, also where it subscribed before: its switches and rules
  were set for its own command, not for what the program does.
- **Removed with its switches.** When the center removes one, or you do,
  the node also drops that center's `on` and allow rules for that very
  action, yours too: they were given for that command. That holds however
  you remove it: `cap rm NAME --center <name>`, `nerve-node config unset
  center.<name>.capability`, or an edit of node.toml that `config accept`
  takes while the node runs, which names each switch it dropped. An `on` or
  rule you set in that same change stays yours. A stopped node cannot tell
  what the file had before, and drops none. So with the node stopped,
  remove one with `cap rm NAME --center <name>` rather than by hand, or take
  that center's `on` and allow rules for it out in the same edit. Once the
  entry is gone, `cap rm --center` finds nothing to remove; then switch it
  off with `cap set NAME off --center <name>` and take the rule away with
  `nerve-node config rm center.<name>.policy.allow 'NAME'` (and the same
  for the capability as a whole, see next). When it was the last
  one the center keeps under its capability, the `on` and allow rules for
  the capability as a whole (`cap set cam on --center <name>`, the rule
  `cam`) go as well: you gave them for the center's commands, and kept they
  would turn on what a program you allow offers under that name later. So
  a center adds none under a name while that center has an `on` or allow
  rule set for what else offers it, for that very action or, for its first
  one under that capability, for the capability as a whole (say yours for a
  program that is away for now): the add is refused with the reason, as the
  center's removal would take that switch along. You or the center take it
  away first, if you want the center's. An `off`, a `hidden` and a deny rule stay. Where you declare that very name
  yourself, they all stay, and those for the capability as a whole where
  you declare any action of it: the center's was left out, so they turn on
  yours for that center (an `on` for one of yours that senses or acts only
  where you set it after declaring it).
- **A program's capability waits for the center's.** While the center
  keeps one of its own under the name of a program's capability (one it
  added before the program attached), you cannot turn on that capability
  as a whole for that center, nor the center's own action by its name: the
  center is offered neither, and the switch would go with the center's own
  when it is removed. `cap set` refuses it and says why; `config accept`
  switches it off, and says that the center keeps its own under that name.
  The `off` stays when the center's goes. Remove the center's first (`cap rm
  NAME --center <name>`), then turn the program's on. An `on` for one of the
  program's actions by its full name (`cap set cam.snap on --center
  <name>`) is taken and stays.
- **Time limit.** Its `timeout_secs` is checked against your
  `limits.max_timeout_secs` when the center adds or changes it. You may
  lower that limit later: the command then stops at your limit.
- **Size.** A center adds at most 64, as many as you may declare, and
  together at most 256 KiB as JSON; the summary and each word of the
  command are bounded as yours are (above).
- **Audited.** Each add, change and removal is in the [audit log](logging.md#the-audit-log-as-the-owner-reads-it)
  as that center's change of the settings, under the key `center`: with the
  old and the new list of this node's centers, each with what it added.
- **You can turn it off or remove it.** `cap set NAME off --center <name>`
  turns it off, and the center cannot turn it on again: an `off` or `hidden`
  of a capability a center added stays until you change it, also one the
  center set itself, and also after the center removes the capability and
  adds it again under the same name. `cap rm NAME --center <name>` removes
  it. The desktop app lists them on that center's
  Capabilities page with their switches; removing one is `cap rm` there.
- **Only the grant stops a center.** An `off` holds for that name only: the
  center may add the same command under another name, with nothing of yours
  to undo. To stop a center from
  adding commands, take the grant back (`center settings off`). That
  leaves what it added; remove it too if you want it gone.

The installed node takes them, on Linux and Windows. A node you run
yourself has no `nerve-run`: it refuses the center's add and says why.

`cap` lists them with the source `center <name>`, and each one's
command after yours; `cap --center <name>` only that center's:

```
say.back  execute  center lab  lab: on
cam.look  sense    center lab  lab: off
capability say.back (added by center lab, counted as execute): echo {word}
capability cam.look (added by center lab, senses: only you turn it on): cam-snap
```

### See what is there

`nerve-node cap` lists them with the source `config`, each with its
command:

```
sensors.read  sense  config  lab: off
logs.tail     read   config  lab: on
win.who       read   config  left out: for windows only
capability sensors.read: sensors -j
capability logs.tail: tail -n {lines} -- {path}
capability win.who: whoami; windows only
```

A word of a command that holds a blank, a quote or a character that shows
as nothing (a control character, a zero-width or a direction mark) is shown
in double quotes, with that character written as an escape such as
`\u202e`, so the line reads as what runs. The audit writes a command the
same way.

A capability this node does not offer says why. `nerve-node cap --json`
gives each one as declared under `config`, and those the centers added under
`added`, each with its `center`.

### In `node.toml`

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
