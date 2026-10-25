# Conformance

The conformance suite lives in `crates/nerve-conformance`. It has four
parts; every check names the section of [protocol.md](protocol.md) it tests
(the harness part: of [harness.md](harness.md), the provider part: of
[node-local.md](node-local.md)), so a failure points
at the rule that was broken.

| Part | Checks | Acts as | State |
|---|---|---|---|
| center | a center | the echo node | runs |
| node | a node | a fake center | runs |
| harness | the MCP server surface a harness sees | an MCP client and two echo nodes | runs |
| provider | a node's capability provider attach ([node-local.md §7](node-local.md#7-capability-providers)) | a center and a provider | runs (Unix) |

Harnesses integrate through MCP only, so the harness part checks the
MCP server surface. Native plugins are a backlog item.

## Running it

There is no runner binary. The parts are library calls that return a
report, and `cargo test -p nerve-conformance` runs them:

- `tests/self_test.rs`: the center part against the fake center and the node
  part against the echo node. These check the suite itself.
- `tests/e2e.rs`: the center part and the harness part against a real
  `nerve-center`, the node part and the provider part against a real
  `nerve-node`, and `nerve-center` with `nerve-node` against each other
  (pairing, link, tools over MCP, folders and rules, settings, audit).

The end-to-end tests start `nerve-center` and `nerve-node` from the programs
named by `NERVE_CENTER_BIN` and `NERVE_NODE_BIN`, and build them only when the
variables are not set. The release workflow sets them to the Linux binaries it
has just built, so the suite runs against what is released, on each
architecture (docs/dev/releasing.md).

To check another implementation, call `center_part::run(&pair_link)` with a
fresh pairing link of that center, `node_part::run(start)` with a closure
that pairs the node under test with the link it is handed and starts it, or
`harness_part::run(&target)` with the center's HTTP MCP address, a harness
token and two fresh pairing links (the part pairs two echo nodes, `conf-a` and
`conf-b`, so the center must have no node of those names).

The closure returns a `Setup`. With `folder` (an empty folder on the node, in
wire form) and the settings grant `write` for the fake center, the node part
also checks the profiles: it writes its own policy with `settings.set` (that
folder read-write and one exact command in `allow`, one in `sudo_allow`) and checks fs, exec, the audit
event and the sudo switch. The sudo switch must be off when the part starts.
It sends one wrong sudo password, so a node with a real `sudo` logs one failed
attempt; with `sudo_password` it also turns sudo on and off once. The e2e test
points the node at a fake `sudo` (`machine.sudo_path`) for this.

## Center part

| § | Check |
|---|---|
| 3.2 | a wrong pairing code is answered with 403 |
| 3.2 | a pair request with an unknown field is answered with 400 |
| 3.2 | a good pair request is answered with 200 |
| 2.2 | the node id is base32 of SHA-256 of the key |
| 3.2 | a used code is refused |
| 4.1 | an unknown node is answered with 401 |
| 4.2 | the first frame is a challenge |
| 4.2 | a wrong signature closes the link |
| 1 | a version mismatch closes with `unsupported_version` |
| 4.2 | a good hello gets a welcome for version "0" |
| 4.2 | the center fetches the descriptor after welcome |

## Node part

| § | Check |
|---|---|
| 3.2 | the node pairs |
| 2.2 | the node name is 1 to 32 of `a-z`, `0-9` and `-`, starting and ending with a letter or digit |
| 4.1 | the node dials the center |
| 4.1 | the `Nerve-Node` header names the paired node id |
| 4.2 | the hello is signed and names version "0" |
| 6 | describe full returns a well-formed descriptor, every schema in the subset of §6.1 |
| 5.1 | describe capability without cap is `invalid_args` |
| 5.2 | an unknown method is `method_not_found` |
| 5.3 | invoke of an unknown capability is `unknown_capability` |
| 5.2 | an unknown ctx field is `invalid_args` |
| 4.5 | after `bye revoked` the node does not dial again |

With a `Setup::folder`, before `bye revoked`:

| § | Check |
|---|---|
| 7.4 | settings get returns document and version |
| 7.4 | settings set with a stale `if_version` is `conflict` |
| 7.4 | settings set applies a document |
| 7.2 | fs read returns what fs write wrote, with the same etag |
| 7.2 | fs read outside the allowed folder is `forbidden` |
| 7.3 | exec run of a command an allow rule names runs |
| 7.3 | a deny rule wins over an allow rule from the next call on |
| 7.3 | exec run of a command nothing allows is `forbidden` |
| 7.5 | a refusal emits `audit` `decision` `forbidden` |
| 7.4.1 | sudo is off at first |
| 7.4.1 | with sudo off, a sudo command on the sudo allow list is `forbidden` |
| 7.4.1 | `sudo-offer` is signed with the node's key for this center |
| 7.4.1 | a wrong sudo password is `invalid_args` and sudo stays off |

With a `Setup::sudo_password` as well:

| § | Check |
|---|---|
| 7.4.1 | the right sudo password turns sudo on |
| 7.4.1 | with sudo on, a sudo command on the sudo allow list runs |
| 7.4.1 | with sudo on, a sudo command the sudo allow list does not name is `forbidden` |
| 7.4.1 | sudo off turns sudo off |
| 7.4.1 | a replayed sealed password is `invalid_args` and sudo stays off |
| 7.4.1 | no frame the node sent carries the sudo password |

## Harness part

The section is that of [harness.md](harness.md). The part speaks MCP over HTTP,
where a session is explicit; the rules are the same over stdio. It reads a
reply with a `Content-Length` and a chunked one alike, and a reply that is not
JSON is a failure of the check, not an empty result.

| § | Check |
|---|---|
| 3 | a request without a token, and one with a wrong token, is answered with 401 |
| 3 | a request whose `Origin` names another host is answered with 403 |
| 3 | `initialize` answers with the version asked for (`2025-06-18`, `2025-03-26`, `2024-11-05`) and with `2025-06-18` for an unknown one; it names `nerve-center` and declares `tools.listChanged` |
| 3 | `initialize` opens a session; a request without `Mcp-Session-Id` is 400 and one with an unknown id is 404; `ping` is answered with an empty result |
| 4 | the tools of both nodes are listed, and `nodes` is a tool that lists them as online |
| 4 | tool names keep `[A-Za-z0-9_-]` within 64 characters |
| 4 | a capability with a profile is one tool, `<cap>_<action>`, with `node` as first required argument and an enum of exactly the nodes that offer it |
| 4 | a capability without a profile is a tool per node, `<node>_<cap>_<action>`, with no `node` argument |
| 4 | the actions of the capabilities `node`, `settings` and `audit` are never tools |
| 4 | a read action has `readOnlyHint`, and a write action does not |
| 4 | a result is device content (marked text, the object as `structuredContent`) |
| 4 | a shared tool without `node` is `error invalid_args`; a failure on the node is `error <code>: <message>` |
| 4 | arguments that do not fit the action's schema (one missing, of another type, one too many) are `error invalid_args` and never reach the node |
| 4 | a shared tool reaches the node `node` names |
| 4 | a call to a node that is offline is `error unavailable`, and its tools stay listed |
| 5 | two sessions have two ids; a node sees one `ctx.session` per session, so a node that two sessions use sees two |
| 5 | `DELETE /mcp` ends the session (204), and the ended session is 404 |
| 5 | `session.end` goes to every node the session used (checked for a session that used two) |
| 5 | `session.end` names the session's `ctx.session` to a node it used, only for the ended session and not for another session on that node, and is not sent to a node it never used |
| 5 | the other session goes on, and still reaches the node |

Not covered: `notifications/cancelled`, the stdio transport and attach, a node
the owner disabled, exposure `off`, names cut to 64 characters and clashes (these
have unit tests in `nerve-center`).

## Provider part

`provider_part::run(start)` checks a node's provider attach on Linux. The
closure pairs the node with the link it is handed, gives that center the
settings grant `write`, allows the program that runs the part
(`std::env::current_exe()`) in `providers.allowed` under `Setup::provider`,
and starts the node; `Setup::socket` is its control socket. The part writes its
own policy with `settings.set` (`user` mode and a deny rule for `echo.shout`
before the provider comes, allow rules for `echo.say` and `echo.fail` once it
is there) and attaches an `echo` provider with the actions `say` (a string
`text`), `shout`, `fail` and `odd`, whose schema has a `oneOf` and so is
outside the subset of protocol.md §6.1. Every check names node-local §7.

| Check |
|---|
| a center may not allow a capability no provider offers |
| a program `providers.allowed` does not name is refused |
| an allowed provider attaches |
| a second provider of the same name is refused |
| the node tells the center that its descriptor changed |
| the descriptor lists the capability with its provider |
| an action whose schema is outside the subset is left out with its reason, and the others attach |
| a center may allow an offered capability that does not sense, and the descriptor follows |
| a call the policy allows reaches the provider and its answer comes back |
| a provider's error comes back with its code |
| a call the policy refuses never reaches the provider |
| a call whose arguments do not fit the action's schema is `invalid_args` and never reaches the provider |
| when the provider exits its capability leaves the descriptor |
| a call to a provider that left is `unknown_capability` |

## Not covered

Binary frames and blobs (§5.4), limits (§5.5), the duplicate-link rule (§4.3),
liveness timing (§4.4), back-off (§4.6), proxies (§4.7), relays (§4.8) and
the resume of a dropped link (§4.9) have tests in the implementations but no
conformance checks of their own. `nerve-node`'s relay tests run the node part
against a node that reaches the fake center only through a relay
(`crates/nerve-node/src/relay.rs`).
