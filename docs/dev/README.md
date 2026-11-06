# Nerve developer docs

How Nerve is built, and why. Start with [architecture](architecture.md). The
wire format and the exact rules are in the [spec](spec/README.md); these
pages explain the design and link to the spec for detail.

## Writing user docs

The user guide (`docs/user/`) and `README.md` are short; the depth lives
here. A user page keeps to these rules:

1. A page is one subject; each task on it is one heading, and the title
   names the subject.
2. Start with the shortest path: one command block, one sentence.
3. One idea per sentence; split a sentence over 25 words.
4. A table cell is one line (about 15 words); more is a link.
5. A limit is one line: what it is, what to do, a link here. Shorten a
   limit, never cut it. Every limit is in `safety.md` and again on its task
   page.
6. Say what the user does and sees. How the node does it goes here.
7. No history. A break is one CHANGELOG line.
8. Linux only until 0.1.0. Over budget means it belongs here.
9. `<details>` folds reference lists and long examples, never a limit: a
   limit stays visible.

`crates/nerve-node/tests/doc_budgets.rs` keeps the budgets: a page over its
budget by 20 %, or a table cell over 40 words, fails it.

## Design

| Page | Covers |
|---|---|
| [architecture.md](architecture.md) | Components, design rules, repo layout |
| [identity-and-pairing.md](identity-and-pairing.md) | Keys, pins, ids, the pairing flow |
| [node-link.md](node-link.md) | The link: dial, handshake, liveness, reconnect, limits |
| [capabilities.md](capabilities.md) | Descriptor, capabilities, effects, profiles, messages |
| [mcp-surface.md](mcp-surface.md) | The two MCP tools, `list` and `execute`, and how the center offers capabilities through them |
| [policy-engine.md](policy-engine.md) | How the node decides a call: modes, folders, rules, protected paths, sudo |
| [sandbox-linux.md](sandbox-linux.md) | `nerve-run`, access lists, homes per pairing, Landlock, the network switch, limits per command |
| [action-checker.md](action-checker.md) | The center's action checker: blocklist, allow rules, decision model |
| [settings-and-config.md](settings-and-config.md) | `node.toml`, the settings API, the control socket |
| [logging.md](logging.md) | The log of the center and the node: levels, redaction, the file, the web UI's data |
| [backup.md](backup.md) | The backup file: format, encryption, what a restore does |
| [service.md](service.md) | The installed node and center: install, root as the owner, update, uninstall |
| [web-uis.md](web-uis.md) | The center's and the node's web UI: login, sessions, TLS, the pages |
| [desktop.md](desktop.md) | The desktop app: installer, rights, settings, what it needs |
| [messages.md](messages.md) | The messages Nerve shows, with their causes and fixes |
| [windows.md](windows.md) | Windows, until it comes back with 0.1.0 |

## Build and release

| Page | Covers |
|---|---|
| [building.md](building.md) | Build, checks, static Linux, Windows cross-build |
| [releasing.md](releasing.md) | The release workflow |

## Spec and conformance

| Where | Covers |
|---|---|
| [spec/protocol.md](spec/protocol.md) | Versions, identity, pairing, the node link, messages, descriptor, built-in profiles |
| [spec/node-local.md](spec/node-local.md) | The node's config, policy, sudo switch, control socket, audit log |
| [spec/harness.md](spec/harness.md) | The center as an MCP server |
| [spec/conformance.md](spec/conformance.md) | What the conformance suite checks and how to run it |
| [schemas/](../../schemas) | JSON Schemas of the descriptor and the pair request |
| [crates/nerve-conformance](../../crates/nerve-conformance) | The conformance suite |
