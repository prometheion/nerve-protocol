# Nerve developer docs

How Nerve is built, and why. Start with [architecture](architecture.md). The
wire format and the exact rules are in the [spec](spec/README.md); these
pages explain the design and link to the spec for detail.

## Design

| Page | Covers |
|---|---|
| [architecture.md](architecture.md) | Components, design rules, repo layout |
| [identity-and-pairing.md](identity-and-pairing.md) | Keys, pins, ids, the pairing flow |
| [node-link.md](node-link.md) | The link: dial, handshake, liveness, reconnect, limits |
| [capabilities.md](capabilities.md) | Descriptor, capabilities, effects, profiles, messages |
| [mcp-surface.md](mcp-surface.md) | The two MCP tools, `list` and `execute`, and how the center offers capabilities through them |
| [policy-engine.md](policy-engine.md) | How the node decides a call, and the sandbox |
| [action-checker.md](action-checker.md) | The center's action checker: blocklist, allow rules, decision model |
| [settings-and-config.md](settings-and-config.md) | `node.toml`, the settings API, the control socket |
| [logging.md](logging.md) | The log of the center and the node: levels, redaction, the file, the web UI's data |
| [backup.md](backup.md) | The backup file: format, encryption, what a restore does |

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
