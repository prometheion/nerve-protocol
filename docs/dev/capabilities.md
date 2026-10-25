# Capabilities

A node describes what it can do in a **descriptor**. The center builds tools
from it. Exact shapes: [spec/protocol.md](spec/protocol.md) §5 to §7.

## Capabilities

A capability is a named part of a node, with four kinds of members:

| Member | Direction | Meaning |
|---|---|---|
| Action | center to node, with a reply | Do something: read a file, run a command |
| Event | node to center | Something happened |
| State | readable, change-notified | A value the node holds |
| Stream | continuous | Data without a known length |

A capability may follow a **profile**, a published contract such as `fs` or
`exec`. A capability without a profile is usable from its schemas alone.
Parameters, results, event data and state are JSON Schemas of a small subset
of 2020-12 ([protocol §6.1](spec/protocol.md#61-schemas)): one type (or one
type and `null`), properties, items, enums and bounds; no `$ref`, `oneOf`,
conditions, `pattern` or `format`. `nerve_proto::schema::check` says whether
a schema keeps to it, `nerve_proto::schema::validate` whether arguments fit
one. The node runs `check` on every schema it publishes (a test covers each
built-in one) and on a provider's, and `validate` on a provider's arguments;
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
    "events": {}, "state": null, "streams": {}}]}
```

- The descriptor a center gets is filtered by that center's policy. A
  capability that is `hidden` for it is absent. One that is `off` is listed
  with `exposure: "off"`.
- In `allowlist` mode, an `fs` or `exec` action is also absent unless an allow
  rule covers its capability and action. The center then builds no tool the
  node would refuse. `exec.run` also stays when the sudo list has an entry.
- `rev` changes whenever what this center sees changes. The node sends
  `node/descriptor_changed` and the center asks again.
- `describe` has three levels of detail: `summary` (no schemas), `capability`
  (one capability in full) and `full`.
- Capability ids and action names use letters, digits and `-`, never `_`. The
  harness side joins names with `_`, and a `_` inside a name would make the tool
  name ambiguous. A center leaves out the actions of a capability with such
  an id, and an action with such a name, and keeps the rest.
- The center builds a catalog per node from its descriptor
  (`nerve-center` `catalog.rs`): one unit per `cap.action`, and the units it
  left out (a bad name, a schema outside the subset; every action of a
  capability whose event data or state is outside it) with their reasons. The
  catalog is rebuilt from the descriptor, never stored; the overview shows
  what was left out.
- `provider` says which process serves the capability: `node` for the node's
  own, else the name of a local program the owner allowed to attach to the
  node ([node-local §7](spec/node-local.md#7-capability-providers)). Such a
  capability has actions only, and the node decides each call to it by the
  center's policy before the program sees it.

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
The center sets `readOnlyHint` on MCP tools for `read` and `sense`.

`folder` and `user` mode do not cover `sense` and `actuate` actions. They run
only when the owner set the action to `on`, or, in `allowlist` mode, when an
allow rule names them. A provider's action names no folder, so `folder` mode
runs it only when it is set to `on`, whatever its effect.

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
  for stderr.
- `exec.signal` is offered only where the policy allows it: by an allow rule in
  `allowlist` mode, with `caps.exec.signal = on` in `folder` and `user` mode.
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
| `invoke {cap, action, args, ctx, deadline_ms?, blobs?}` | center to node | Run an action |
| `progress {id, data}` | node to center | Intermediate data for an invoke |
| `cancel {id}` | center to node | Stop an invoke. One final reply still follows |
| `get {cap, keys}` | center to node | Read state |
| `sub {topics}`, `unsub {topics}` | center to node | Topics `<cap>/<event>`, `<cap>/state`, `<cap>/*` |
| `event`, `state` | node to center | Something happened, state changed |
| `stream.open`, `stream.close` | either | Reliable streams |
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
