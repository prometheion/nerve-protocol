# Capability providers

A program on the machine, such as a desktop app, can add capabilities of its
own to the node: a lamp it switches, a window it shows. It attaches to the
running node as a **provider**, and every center then sees its capabilities
next to `fs` and `exec`. The program never talks to a center. The node decides
every call to it by that center's mode and rules, as it does for files and
commands, and writes it to the [audit log](audit.md).

Providers work on Linux, with a node you run yourself. The installed node's
control socket belongs to the user `nerve`, so a program of yours cannot
attach there yet. Windows takes no provider yet.

## Allow a program

No program may attach until you name it, with a name of your choice and the
full path of its executable:

```sh
nerve-node config add providers.allowed '{ name = "desk", exe = "/usr/lib/nerve-desktop/nerve-desktop" }'
```

The node checks that the program that attaches under that name runs that very
file. A center cannot change the list. To let a program go, remove its entry:

```sh
nerve-node config remove providers.allowed '{ name = "desk", exe = "/usr/lib/nerve-desktop/nerve-desktop" }'
```

Its capabilities leave at once. `nerve-node status` lists the providers that
are attached:

```
provider desk attached: lamp
provider desk: lamp.dim left out: params: /properties/level/oneOf: oneOf: alternatives are not supported: use one schema, with enum for a choice of values
```

The second line is an action the node left out (below); `nerve-node status
--json` has them as `broken`. A reason is one line, cut after 300
characters, since it holds names from the program's schemas.

The check tells programs apart, not users: another program of your user can
still make the allowed one attach for it. Allow only programs you trust.

## Allow its capabilities

A provider's capability is decided like any other, by what it does
([modes](modes.md#what-each-mode-allows), [rules](rules.md)):

| Mode | A provider's action runs when |
|---|---|
| `allowlist` | an allow rule names it: `nerve-node config add center.<name>.policy.allow 'lamp.on'`, or `'lamp'` for all its actions |
| `folder` | it reads, writes or runs something at paths it marks ([below](#paths-it-takes)) that the folders allow; or you set it on: `nerve-node cap set lamp on` (one that names no path lies in no folder, a read included, a write whose only paths are ones it reads names no place it writes, and one that senses or acts on the world needs `on` anyway, its paths in your folders too) |
| `user` | always, except one that senses or acts on the world, which needs `on` |

Deny rules and `off` and `hidden` work as for `fs` and `exec`. A call to an
action that is `off` is refused with `disabled` and written to the audit log.
A center with the [settings grant](settings-grant.md) can allow a provider's
action itself while the provider is attached, except one that senses (a
camera, a microphone) or acts on the world (a lamp, a lock): only you turn
those on, and only you take away an `off` switch or a deny rule that keeps
one off. While no provider offers a capability or one of its actions, only
you can allow it or turn it on, as the node cannot tell yet what it does. An
entry a center wrote while the capability did neither stays when a new
version of the program makes it sense or act: after such an update, check
`nerve-node rule ls allow` and `nerve-node cap ls`.

## Paths it takes

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
program's `execute` action with paths, as it runs no command); [rules](rules.md#rule-syntax) match the path
(`notes:~/private/*`); protected paths and the node's own files are refused;
and the [audit log](audit.md) names the path, also one that does not resolve.
On the installed Linux node a read outside every folder goes where every
account may read ([reading in folder mode](modes.md#reading-in-folder-mode)),
and only for a file. A path given that is a link is followed to where it
leads and judged there. A path to write that is itself a link is refused
(`bad_path`): the program would remove, rename or write the place it leads
to, which you did not name, so name that place instead. The program gets the
path as the node resolved it, links followed, so it works where the node
looked; a path that resolves to a name that is not valid Unicode, or to one
the program's own schema does not take, is refused (`bad_path`). A refusal
names each path as the center gave it, never where it led: the
[audit log](audit.md) says that. The center's
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
capability names (`notes:~/private/*` refuses `notes` the folder `~` too) or,
in `folder` mode, a folder you gave less lies below it. An `execute` action
runs its program there, so for it a folder below without `x`, or a protected
path released without `x`, refuses the call too. The refusal names the
folder handed over, not what lies below it. A file holds nothing below it:
`notes:~/proj/*.env` refuses `notes` the folder `~/proj`, but not
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
A link that leads nowhere counts only for a write, at the place it names. A
call whose folders hold more than 200 000 entries in all, counting those of
the folders their links lead to, is refused, since the node cannot check
them all. A call that ends (its deadline passes, or it is cancelled) while
the node looks for the links stops that search and never reaches the
program; the [audit log](audit.md) has it as refused, `cancelled`. An `fs:` rule covers `fs` calls
only: to keep every capability out of a place, deny it for each one that
takes paths (`notes:~/private/*`), or make it a [protected
path](protected-paths.md).

A folder a program writes in is not checked for the places whose writes
run code later, as an `fs.write` is (`.git`, `.envrc`, `.vscode`, `.idea`):
the program may make them anywhere below it, so the node cannot check them
before the call. An `fs.write` there is refused; a program that unpacks or
syncs into a folder of yours can write them. Let such an action run only
where every folder with `w` can take that, or switch it `off`.

The node checks the path when the call comes; the program reads or writes it
afterwards with your rights, so a link put in or swapped in between is not
caught: a command with `w` in a folder can make one.
Allow only programs you trust.

When the program exits, its capabilities leave what `list` shows the centers,
and a call that was waiting for it fails with `unavailable`.

## What it may name

Each capability and action has a name of 1 to 64 letters, digits, `-` and
`_`, such as `lamp` and `set_level`; the agent sees them joined, `lamp.set_level`.
The node refuses a program that gives another name, or a capability that is
the node's own (`fs`, `exec`, …) or the center's (`job`, `stream`), or another
provider's already, and the program's attach fails with the reason. The
center serves `job.status`, `job.cancel`, `stream.read` and `stream.close`
on every machine itself, and
tells them by their capability, so a program you named `center` is yours like
any other
([long calls](harness.md#long-calls-become-jobs)).

## What its schemas may say

Each action describes its arguments and its result with a JSON Schema. The
center hands them to the agent and checks every call's arguments against
them, so only a small, plain part of JSON Schema is allowed: one type per
value (or one type and `null`), properties, required fields, lists, a list of
allowed values (`enum`), bounds for numbers, texts and lists, and
descriptions. References (`$ref`), alternatives (`oneOf`, `anyOf`), conditions,
patterns and formats are not, nor is nesting more than three levels deep in
the arguments. What a text must look like goes into its `description`. The
exact list is in the [spec](../dev/spec/protocol.md#61-schemas).

An action whose schema goes beyond that is left out, and the program's other
actions attach: `nerve-node status` names it with the reason, and the node's
log has a warning. If none of its actions is left, the node refuses the
program.

Arguments that do not fit an action's schema never reach the program: the
node answers `invalid_args`, naming the field and what it expected
(`level: expected an integer from 0 to 10`).

How a program attaches is in the
[spec](../dev/spec/node-local.md#7-capability-providers).
