# Nerve Protocol specification

| File | Covers |
|---|---|
| [protocol.md](protocol.md) | versions, identity, pairing, the node link, messages, descriptor, built-in profiles |
| [node-local.md](node-local.md) | the node's config, policy and its local control socket |
| [harness.md](harness.md) | how `nerve-center` serves harnesses over MCP |
| [conformance.md](conformance.md) | the conformance suite and what it checks |

JSON Schemas of the descriptor and the pair request are in `../../../schemas/`.

Protocol version: `"0"` (exact match; [what stays stable](#what-stays-stable-from-010)).

## What stays stable from 0.1.0

From 0.1.0 on a format may still change, but only with a migration: the
program that reads the old format converts it, and nobody edits a file, backs
up again or pairs again. What holds:

- **The wire protocol** keeps version `"0"`. Everything in
  [protocol.md](protocol.md) is its baseline. A part added later is a named
  feature ([§1.1](protocol.md#11-features)), which a side uses only when both
  sides named it. So a node and a center of different releases still speak.
- **The files the node and the center keep**: `node.toml`, `acl.json`,
  `grants.json`, the center's `state.json` and the sealed Windows files each
  carry a `format`, and so does the backup file ([stored
  files](../settings-and-config.md#the-format-of-stored-files),
  [backup](../backup.md#the-file)). A change to one raises its `format`, and
  the new program reads the old one and migrates it. A program refuses a file
  of a higher format than it knows, so an older program never rewrites a newer
  file.
- **`--json` output**: fields are only added. A renamed or removed field is a
  "Breaks" line in the CHANGELOG
  ([CLI output](../settings-and-config.md#cli-output---json)).

Nothing else is promised. The text of messages, the pages of the web UIs and
the desktop app, and the plain output of the commands (not `--json`) may
change in any release.
