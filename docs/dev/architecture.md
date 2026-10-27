# Architecture

Nerve lets an agent harness use computers it does not run on. The harness
reaches a **center**. Each computer runs a **node**. The center offers what
the nodes can do to the harness through two MCP tools, `list` and `execute`,
and routes the harness's calls to the nodes. Each node decides every call by the rules its owner set.

```
   harness A ── MCP ──┐
   harness B ── MCP ──┤
                      ▼
               ┌──────────────┐
 browser ──────│ nerve-center │  pairing, links, tools, action checker, statistics, web UI
               └──────▲───────┘
                      │ node link (WebSocket over TLS), dialled by the nodes
        ┌─────────────┴─────────────┐
   ┌────┴─────┐               ┌─────┴────┐
   │ node 1   │               │ node 2   │   fs, exec, settings, audit
   └──────────┘               └──────────┘
```

## Parts

| Part | Is | Holds |
|---|---|---|
| Center | `nerve-center`, one daemon | Its TLS key and certificate, its id and name, the paired nodes (id, name, public key, last descriptor), pairing codes, hashed harness tokens, sessions, statistics, the action checker's settings, its model endpoint's token and its local model |
| Node | `nerve-node`, one daemon and a CLI | One pairing per center, the policy per center, the machine settings, the built-in capabilities, the sandbox, the sudo password while sudo is on |
| Harness | Any MCP client | Nothing of Nerve. It only speaks MCP |

The node is the only part that talks to a center. The CLI talks to the node
through its control socket, and so does a capability provider: a local program
the owner allowed, such as a desktop app, that adds capabilities to the node
([node-local §7](spec/node-local.md#7-capability-providers)). The node decides
every call to them by the calling center's policy.

## Design rules

1. **The node is the authority.** The node's policy for the calling center
   decides every call, whatever the center says. The center can make a call
   stricter. It cannot make the node more permissive, except by changing
   settings where the owner gave it the settings grant.
2. **The node dials.** A node never listens for centers. Nodes behind NAT, on
   laptops and in closed networks work without opening a port. A node whose
   owner turns on its relay listens for other nodes, and tunnels their TLS
   bytes to its own centers only ([protocol §4.8](spec/protocol.md)); the
   relayed node still dials, through it.
3. **A center is a trust domain.** A node pairs with any number of centers and
   keeps their policy, sessions, audit entries and settings apart. A center
   cannot learn whether another center exists.
4. **Default deny.** A new pairing reaches nothing of the owner's: it starts
   in `folder` mode without a folder (on the installed Linux node its commands
   have only `nerve-run`'s home, `/tmp` and `/var/tmp`, and its file calls
   may still read what every account on the machine may read: see
   [modes](../user/modes.md#reading-in-folder-mode)). A decision is
   allowed or forbidden. Nothing waits for a person to answer.
5. **MCP is the only harness interface.** No harness names, tool names,
   session formats or hooks appear in the protocol, the center or the node.
6. **The center is a gate and a router.** It has no agent loop, no memory and
   no chat history. It stores no file contents, command output or node
   secrets. Its one model is optional and narrow: the action checker may ask a
   decision model whether a call is dangerous, as a gate that can only refuse
   ([policy-engine](policy-engine.md), [action-checker](action-checker.md)); it
   is no agent loop and keeps no history. It does not relay messages between
   nodes, call one node from another or install software on a node. A node's
   relay carries bytes, not messages, and no node calls another either.
7. **Data from a node is data.** File contents, command output and tool
   results are untrusted content at the center and in the harness. The center
   marks every tool result as device content.
8. **No web UI on nodes.** A node is configured on the machine, or by a center
   whose owner gave it the settings grant.

## What the node keeps

| Where | What |
|---|---|
| Config folder | `node.toml`, signed. `keys/<name>.key`, one Ed25519 key per center, mode 0600; `keys/relay-tls.pem` (the relay's TLS key) and `keys/proxy-login.secret` (an `https://` proxy's password, a relay token), when there are. On Windows, DPAPI files: `command-account.dpapi` (the password of the account commands run as, on the installed node) and `sudo.dpapi` (the sudo password while sudo is on) |
| State folder | `audit.jsonl`, `log.jsonl`, `run/ctl.sock`, `run/ctl.token`, `acl.json` (the installed Linux node: the folders' ACL entries it gave `nerve-run`, `crate::acl`), `config.key` (the key of the config's MAC), `config.version` (the last version of `node.toml` the node saved or took), `keys.lock`, `keys.moving` (while the keys move between files and the keyring). On Windows, `grants.json` and `grants.json.lock`, the record of the folder grants |
| System keyring | With `machine.secret_storage = "keyring"`: the center keys, the config's key, the relay's TLS key and an `https://` proxy's password instead of their files. The proxy's header values, always (the installed node on Windows takes none, see node-local §2) |

No call of any center reaches these two folders. See
[settings and config](settings-and-config.md). The center keeps `tls.pem`
(and `tls.next.pem` during a key rotation), `state.json`, `log.jsonl`,
`center.lock`, `run/harness.sock` (Unix) and, for the
[action checker](action-checker.md), `checker-model.token` and the local
model in `checker/` in its state folder ([logging](logging.md),
[backup](backup.md)).

## Repo layout

| Path | Contains |
|---|---|
| `docs/dev/spec/` | The protocol, the node's local rules, the harness side, the conformance suite |
| `schemas/` | JSON Schemas of the descriptor and the pair request |
| `crates/nerve-proto` | Wire types and codecs, no I/O |
| `crates/nerve-transport` | TLS with pinning, `CONNECT` proxies, WebSocket, the node's Ed25519 identity, the sealed sudo password, a small HTTP/1.1 server, local control sockets, the streaming downloader of the node's `update` and the checker's install |
| `crates/nerve-policy` | The node's config, the decision engine, rules, protected paths, settings, the audit log |
| `crates/nerve-sandbox` | Confinement for commands: Landlock on Linux, an AppContainer on Windows |
| `crates/nerve-node` | The `nerve-node` binary: daemon and CLI |
| `crates/nerve-node-desktop` | `nerve-node-desktop`, the node with a desktop app in one binary: with arguments it is `nerve-node`, without it opens a window (Slint) that runs `nerve-node --json` for every action; on a node installed as a service through a broker it starts with the rights the desktop gives (pkexec, the UAC prompt). Started from anywhere but its installed place it is its own installer: `install`, `update` and `uninstall` of this program put its parts (menu entry, `nerve://` handler) in place with the node (`nerve_node::edition`), and the service runs it |
| `crates/nerve-center` | The `nerve-center` binary: links, MCP server, web UI, the action checker (`src/checker/`) |
| `crates/nerve-conformance` | The conformance suite: center, node and harness parts, an echo node and a fake center |

A wire change, its spec text and both ends change together.

## Read next

- [Identity and pairing](identity-and-pairing.md)
- [The node link](node-link.md)
- [Capabilities](capabilities.md)
- [The MCP surface](mcp-surface.md)
- [The policy engine](policy-engine.md)
- [The action checker](action-checker.md)
- [Settings and config](settings-and-config.md)
