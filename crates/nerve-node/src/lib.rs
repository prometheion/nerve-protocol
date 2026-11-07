//! The Nerve node: links this machine to its centers and serves them what the
//! owner's policy allows (docs/dev/).
//!
//! The daemon ([`daemon::Daemon`]) keeps one link per paired center, runs the
//! `fs`, `exec`, `settings` and `audit` capabilities, serves
//! the control socket the CLI ([`cli`]) talks to, the relay for other
//! nodes and the web UI (Linux) when the owner turns them on. Tests start a daemon in
//! process with [`daemon::Daemon::start`] and pair with [`pair::pair`].

pub mod account;
#[cfg(target_os = "linux")]
pub mod acl;
pub mod backup;
mod caller_file;
pub mod cgroup;
pub mod cli;
mod config_cap;
pub mod daemon;
pub mod descriptor;
pub mod edition;
pub mod entry;
use nerve_service::eventlog;
pub mod exec;
mod folder_change;
pub mod fs;
pub mod grants;
// The job is Windows-only in use; its choices are tested everywhere.
#[cfg_attr(not(windows), allow(dead_code))]
mod job;
pub mod keyring_setup;
mod link;
#[cfg(target_os = "linux")]
pub mod own_dirs;
pub mod owner;
pub mod pair;
pub mod paths;
pub use nerve_service::prompt;
// Providers attach over the control socket, which is Unix's; the pipe on
// Windows takes none yet.
#[cfg_attr(not(unix), allow(dead_code))]
mod provider;
// The control pipe is Windows-only in use; its rules are tested everywhere.
#[cfg_attr(not(windows), allow(dead_code))]
mod pipe;
mod relay;
pub mod rights;
mod rotate;
mod secrets;
pub mod service;
mod sudo;
pub mod tap;
#[cfg(target_os = "linux")]
mod webui;
// The walk is Windows-only in use, tested everywhere.
#[cfg_attr(not(windows), allow(dead_code))]
mod tree;
#[cfg(windows)]
mod win;
#[cfg(windows)]
mod win_host;
#[cfg(windows)]
pub mod win_service;
#[cfg(windows)]
pub mod win_stop;
#[cfg(windows)]
mod win_user;
// The Windows sudo switch and install steps are Windows-only in use;
// tested everywhere.
#[cfg_attr(not(windows), allow(dead_code))]
mod winsudo;
#[cfg_attr(not(windows), allow(dead_code))]
mod winsvc;

pub use daemon::{Daemon, Event, Hold, HoldAt, NodeOptions};
pub use paths::NodePaths;

/// Milliseconds since the Unix epoch.
pub use nerve_proto::msg::now_ms;
