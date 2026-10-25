//! The Nerve center as an MCP server (docs/dev/spec/harness.md).
//!
//! `nerve-center` is started by a harness like any MCP server. It pairs nodes,
//! holds their links, offers their capabilities to the agent through two MCP
//! tools, `list` and `execute`, and serves the center web UI. Everything is
//! set by flags or `NERVE_*` variables in the harness's MCP entry, or in the
//! web UI. Its only subcommands are the
//! owner's: `backup` and `restore` ([`backup`]), and `install`, `update` and
//! `uninstall`, which run it as a service on Linux ([`service`]).
//
// Harnesses get Nerve through MCP only: this MCP server is the whole
// integration surface. Native plugins are a backlog item.

pub mod attach;
pub mod audit;
pub mod backup;
pub mod catalog;
pub mod center;
pub mod checker;
pub mod config;
pub mod link;
pub mod listen;
pub mod listing;
pub mod mcp;
pub mod pairing;
pub mod server;
pub mod service;
pub mod store;
pub mod tools;
pub mod ui;
pub mod util;
