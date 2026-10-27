//! The node's configuration, `node.toml` (docs/dev/settings-and-config.md).
//!
//! Every table is parsed with `deny_unknown_fields`: a misspelt key in a policy
//! file must be an error, not a rule that silently does nothing.
//!
//! What one center may read and change (with the settings grant `write`) is its
//! [`CenterDocument`]: its policy and its `paused` flag. Everything else, the
//! center list, pairing, grants, machine options, proxy, relay, is
//! client-only.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::paths::within;

mod capability;
pub use capability::{
    BUILT_IN, ConfigCapability, MAX_CAPABILITIES, Output, Platform, RunsAs, validate_all,
};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// Counts every saved change; `settings.set` and the control socket check
    /// it (`if_version`) so two writers cannot overwrite each other unseen.
    #[serde(default)]
    pub version: u64,
    /// Set by `nerve-node panic`: every link is closed and nothing runs until
    /// `nerve-node unlock`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub locked: bool,
    #[serde(default)]
    pub node: NodeSection,
    #[serde(default)]
    pub machine: Machine,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub connection: Connection,
    /// The relay for other nodes (docs/dev/spec/protocol.md §4.8); off by
    /// default.
    #[serde(default, skip_serializing_if = "Relay::is_default")]
    pub relay: Relay,
    #[serde(default)]
    pub log: LogSection,
    /// The local programs that may add capabilities to the node over its
    /// control socket. Only the owner sets it.
    #[serde(default, skip_serializing_if = "Providers::is_empty")]
    pub providers: Providers,
    /// The capabilities the owner declares here (`[[capability]]`), each
    /// one action that runs a fixed command (docs/user/config-capabilities.md).
    #[serde(default, rename = "capability", skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<ConfigCapability>,
    #[serde(default, rename = "center", skip_serializing_if = "Vec::is_empty")]
    pub centers: Vec<CenterEntry>,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// The programs that may attach to the node as capability providers
/// (docs/dev/spec/node-local.md §7). None is allowed by default.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Providers {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed: Vec<AllowedProvider>,
}

impl Providers {
    pub fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }

    /// The entry named `name`.
    pub fn get(&self, name: &str) -> Option<&AllowedProvider> {
        self.allowed.iter().find(|p| p.name == name)
    }
}

/// One program the owner lets attach: the name its capabilities carry as
/// their `provider`, and the executable the attaching process must run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedProvider {
    pub name: String,
    /// The absolute path of the program, compared with the one the
    /// attaching process runs once both are resolved.
    pub exe: String,
}

/// Whether `name` can name a provider: a node name's shape (1 to 32 of
/// a-z, 0-9 and `-`, starting and ending with a letter or digit), and not `node`, which stands for the node itself.
pub fn valid_provider_name(name: &str) -> bool {
    nerve_proto::valid_node_name(name) && name != "node"
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSection {
    /// The name the node pairs with; derived from the host name when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Machine {
    /// The shell `exec.run` uses; `/bin/sh` (PowerShell on Windows) when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    /// Whether the node may run as root at all.
    #[serde(default)]
    pub allow_root: bool,
    /// The node's sudo switch (one per node, not per center). The password
    /// is never in this file. On Linux the node keeps it in memory only
    /// while the switch is on, so a restarted node starts with the switch
    /// off; the installed Windows node keeps it with DPAPI in `sudo.dpapi`
    /// and holds it again at start (docs/dev/spec/node-local.md §4).
    #[serde(default)]
    pub sudo: Sudo,
    /// The `sudo` program; `sudo` from `PATH` when unset. Only the owner
    /// sets it: a fake `sudo` would catch the password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sudo_path: Option<String>,
    #[serde(default)]
    pub secret_storage: SecretStorage,
    /// Windows: the account the installed node runs commands as, which
    /// `install` takes with its password. Unset, they run as the node's own
    /// user; the installed service then runs none. Linux does not read it:
    /// there commands run as `nerve-run` or as the owner, the account that
    /// ran `install`, and `nerve-node config set` refuses it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

/// Whether `name` can be an account name: 1 to 32 characters of a-z, A-Z,
/// 0-9, `.`, `_` and `-`, not starting with `-`.
pub fn valid_account_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// The sudo switch. Off, no command runs through `sudo`, whatever the rules
/// say. On, a `sudo` command runs only when the sudo allow list names it, in
/// every mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Sudo {
    #[default]
    Off,
    On,
}

impl Sudo {
    pub fn as_str(self) -> &'static str {
        match self {
            Sudo::Off => "off",
            Sudo::On => "on",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretStorage {
    /// 0600 files: a key file per center below the config directory, and
    /// the key of the config's MAC in the state directory.
    #[default]
    File,
    /// The system keyring (the Credential Manager on Windows, the Secret
    /// Service on Linux), one entry per key and no copy in a file. A node
    /// whose keyring does not answer refuses to start.
    Keyring,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Commands running at once, over every center.
    #[serde(default = "d_max_running")]
    pub max_running: u32,
    /// stdout and stderr of one command are each cut at this size.
    #[serde(default = "d_output_cap")]
    pub output_cap_bytes: u64,
    /// How long a command may run when its call gives no `timeout_ms`. A
    /// command past its limit is killed. Left out of the file while it is
    /// the default, so the file holds what the owner set.
    #[serde(
        default = "d_default_timeout",
        skip_serializing_if = "is_default_timeout"
    )]
    pub default_timeout_secs: u64,
    /// The longest a command may run, whatever its call asks for: a larger
    /// `timeout_ms` is cut to this. It also cuts the default above.
    #[serde(default = "d_max_timeout", skip_serializing_if = "is_max_timeout")]
    pub max_timeout_secs: u64,
    /// What one command may use (a cgroup on Linux). Written only where
    /// the owner changed it.
    #[serde(default, skip_serializing_if = "CommandLimits::is_default")]
    pub command: CommandLimits,
}

fn d_max_running() -> u32 {
    16
}
fn d_output_cap() -> u64 {
    16 * 1024 * 1024
}
fn d_default_timeout() -> u64 {
    10 * 60
}
fn d_max_timeout() -> u64 {
    60 * 60
}
fn is_default_timeout(n: &u64) -> bool {
    *n == d_default_timeout()
}
fn is_max_timeout(n: &u64) -> bool {
    *n == d_max_timeout()
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_running: d_max_running(),
            output_cap_bytes: d_output_cap(),
            default_timeout_secs: d_default_timeout(),
            max_timeout_secs: d_max_timeout(),
            command: CommandLimits::default(),
        }
    }
}

/// The memory, CPU and processes of one command: what it gets when its call
/// names none, and the most a call may ask for. Only the owner sets them; a
/// call may ask for less than the most, never for more. On Linux the node
/// holds a command to them with a cgroup of its own (docs/user/limits.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandLimits {
    /// Memory in MiB; a command past it is killed.
    #[serde(default = "d_memory_mb")]
    pub memory_mb: u64,
    #[serde(default = "d_memory_max_mb")]
    pub memory_max_mb: u64,
    /// CPU time in percent of one CPU (200 is two CPUs); a command past it
    /// is slowed down, not killed.
    #[serde(default = "d_cpu_percent")]
    pub cpu_percent: u32,
    #[serde(default = "d_cpu_max_percent")]
    pub cpu_max_percent: u32,
    /// Processes and threads at once; past it a command cannot start more.
    #[serde(default = "d_processes")]
    pub processes: u32,
    #[serde(default = "d_processes_max")]
    pub processes_max: u32,
}

fn d_memory_mb() -> u64 {
    4096
}
fn d_memory_max_mb() -> u64 {
    16384
}
fn d_cpu_percent() -> u32 {
    200
}
fn d_cpu_max_percent() -> u32 {
    800
}
fn d_processes() -> u32 {
    1024
}
fn d_processes_max() -> u32 {
    8192
}

/// The most memory a limit may name, in MiB (1 PiB): its bytes still fit a
/// u64 many times over.
pub const MEMORY_MB_MOST: u64 = 1 << 30;
/// The most CPU a limit may name: 4096 CPUs.
pub const CPU_PERCENT_MOST: u32 = 409_600;
/// The most processes a limit may name: Linux's own most of pids.
pub const PROCESSES_MOST: u32 = 4_194_304;

impl Default for CommandLimits {
    fn default() -> CommandLimits {
        CommandLimits {
            memory_mb: d_memory_mb(),
            memory_max_mb: d_memory_max_mb(),
            cpu_percent: d_cpu_percent(),
            cpu_max_percent: d_cpu_max_percent(),
            processes: d_processes(),
            processes_max: d_processes_max(),
        }
    }
}

impl CommandLimits {
    pub fn is_default(&self) -> bool {
        *self == CommandLimits::default()
    }

    /// Each value at least 1 and at most its `*_MOST`, and no default above
    /// its most.
    pub fn validate(&self) -> Result<(), String> {
        let each: [(&str, u64, u64, u64); 3] = [
            (
                "memory_mb",
                self.memory_mb,
                self.memory_max_mb,
                MEMORY_MB_MOST,
            ),
            (
                "cpu_percent",
                self.cpu_percent.into(),
                self.cpu_max_percent.into(),
                CPU_PERCENT_MOST.into(),
            ),
            (
                "processes",
                self.processes.into(),
                self.processes_max.into(),
                PROCESSES_MOST.into(),
            ),
        ];
        for (name, default, max, most) in each {
            let max_name = max_key(name);
            for (key, v) in [(name.to_string(), default), (max_name.clone(), max)] {
                if v == 0 || v > most {
                    return Err(format!(
                        "limits.command.{key} must be from 1 to {most}, not {v}"
                    ));
                }
            }
            if default > max {
                return Err(format!(
                    "limits.command.{name} ({default}) is above limits.command.{max_name} ({max})"
                ));
            }
        }
        Ok(())
    }

    /// The limits of one command whose call asked for these (each `None`
    /// where it named none): the default where it did not ask, what it
    /// asked where that is no more than the most. Asking for more, or for
    /// nothing at all (0), refuses the call with the reason.
    pub fn grant(
        &self,
        memory_mb: Option<u64>,
        cpu_percent: Option<u32>,
        processes: Option<u32>,
    ) -> Result<Granted, String> {
        fn pick(name: &str, asked: Option<u64>, default: u64, max: u64) -> Result<u64, String> {
            match asked {
                None => Ok(default),
                Some(0) => Err(format!("{name} must be at least 1")),
                Some(a) if a > max => Err(format!(
                    "{name} {a} is more than this node lets a command have: at most {max}"
                )),
                Some(a) => Ok(a),
            }
        }
        // The maxima are u32 for these two, so the picks fit back.
        Ok(Granted {
            memory_mb: pick("memory_mb", memory_mb, self.memory_mb, self.memory_max_mb)?,
            cpu_percent: pick(
                "cpu_percent",
                cpu_percent.map(Into::into),
                self.cpu_percent.into(),
                self.cpu_max_percent.into(),
            )? as u32,
            processes: pick(
                "processes",
                processes.map(Into::into),
                self.processes.into(),
                self.processes_max.into(),
            )? as u32,
        })
    }
}

/// The limits one command runs with ([`CommandLimits::grant`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Granted {
    pub memory_mb: u64,
    pub cpu_percent: u32,
    pub processes: u32,
}

/// The name of the most that goes with the default `name`.
fn max_key(name: &str) -> String {
    match name.split_once('_') {
        Some((what, unit)) => format!("{what}_max_{unit}"),
        None => format!("{name}_max"),
    }
}

/// The node's log (docs/user/logs.md). Only the owner sets it: it is a
/// machine setting, not part of what a center reads or changes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSection {
    /// What the node logs: `error`, `warn`, `info` (the default) or `debug`.
    #[serde(default)]
    pub level: nerve_transport::log::Level,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Connection {
    /// `http://host:port` or `https://host:port` (a relay, protocol §4.8),
    /// never with a user name and password; `HTTPS_PROXY`/`NO_PROXY` apply
    /// when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    /// The pin of an `https://` proxy's certificate; without it the system's
    /// roots check it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
    /// The user name of an `https://` proxy (a relay: the relay node name).
    /// Its password, the relay token, is kept with the node's own keys,
    /// where `machine.secret_storage` says, never in this file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<String>,
    /// The names of the extra header lines for the proxy's `CONNECT`
    /// request. Their values are secrets and live in the system keyring
    /// (`nerve-node proxy set`), never in this file.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<String>,
}

/// The relay: this node takes `CONNECT` requests of other nodes and tunnels
/// them to its own centers (docs/dev/spec/protocol.md §4.8). Only the owner
/// sets it: it is a machine setting, not part of what a center reads or
/// changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relay {
    /// The address the relay listens on, `ip:port`. The relay is off without
    /// it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    /// Tunnels at once, over every relayed node.
    #[serde(default = "d_relay_links")]
    pub max_links: u32,
    /// Tunnels at once of one relayed node.
    #[serde(default = "d_relay_links_per_node")]
    pub max_links_per_node: u32,
    /// Tunnels one relayed node may open a minute, every node alike. Each is
    /// an audit entry and two log lines, so this keeps a node with its token
    /// from rotating the logs; a node needs one per center and redials after
    /// a second at the soonest. A relay behind this one (a chain) needs more,
    /// and gets it as a limit of its own ([`RelayNode::max_opens_per_minute`]).
    #[serde(default = "d_relay_opens")]
    pub max_opens_per_minute: u32,
    /// The pin of the relay's TLS certificate, whose key is kept with the
    /// node's own keys; set when `nerve-node relay` makes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
    /// The nodes that may use the relay, each with the hash of its token.
    #[serde(default, rename = "node", skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<RelayNode>,
}

fn d_relay_links() -> u32 {
    16
}
fn d_relay_links_per_node() -> u32 {
    4
}
fn d_relay_opens() -> u32 {
    30
}

impl Default for Relay {
    fn default() -> Relay {
        Relay {
            listen: None,
            pin: None,
            max_links: d_relay_links(),
            max_links_per_node: d_relay_links_per_node(),
            max_opens_per_minute: d_relay_opens(),
            nodes: Vec::new(),
        }
    }
}

impl Relay {
    fn is_default(&self) -> bool {
        *self == Relay::default()
    }

    pub fn node(&self, name: &str) -> Option<&RelayNode> {
        self.nodes.iter().find(|n| n.name == name)
    }

    fn validate(&self) -> Result<(), String> {
        if let Some(p) = &self.pin {
            nerve_transport::tls::decode_pin(p).map_err(|e| format!("relay.pin: {e}"))?;
        }
        if let Some(l) = &self.listen {
            l.parse::<std::net::SocketAddr>().map_err(|_| {
                format!("relay.listen {l:?}: an address and a port, like 0.0.0.0:7490 or [::]:7490")
            })?;
        }
        if self.max_links == 0 || self.max_links_per_node == 0 || self.max_opens_per_minute == 0 {
            return Err("relay.max_links, relay.max_links_per_node and relay.max_opens_per_minute must be at least 1".into());
        }
        let mut names = std::collections::BTreeSet::new();
        for n in &self.nodes {
            if n.max_links == Some(0) || n.max_opens_per_minute == Some(0) {
                return Err(format!(
                    "relay.node {}: max_links and max_opens_per_minute must be at least 1",
                    n.name
                ));
            }
            if !nerve_proto::valid_node_name(&n.name) {
                return Err(format!(
                    "relay.node name {:?}: 1 to 32 characters of a-z, 0-9 and -, starting and ending with a letter or digit",
                    n.name
                ));
            }
            if !names.insert(n.name.as_str()) {
                return Err(format!("relay.node names {:?} twice", n.name));
            }
            let hex = n
                .token_sha256
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
            if n.token_sha256.len() != 64 || !hex {
                return Err(format!(
                    "relay.node {}: token_sha256 is 64 characters of lowercase hex",
                    n.name
                ));
            }
            let mut seen = std::collections::BTreeSet::new();
            for c in &n.centers {
                // A center that is no longer paired may stay named: the
                // node then reaches it no more, and the file still loads.
                if !valid_center_name(c) {
                    return Err(format!("relay.node {}: {c:?} is not a center name", n.name));
                }
                if !seen.insert(c.as_str()) {
                    return Err(format!("relay.node {} names the center {c} twice", n.name));
                }
            }
        }
        Ok(())
    }
}

/// A node that may use the relay. Its token is in no file: only its SHA-256
/// is kept, so whoever reads `node.toml` cannot use the relay with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayNode {
    /// The name the node gives as the user name of its `Proxy-Authorization`.
    pub name: String,
    /// The lowercase hex SHA-256 of its token.
    pub token_sha256: String,
    /// The centers its tunnels may go to, by this node's names for them;
    /// empty, every center a tunnel may go to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub centers: Vec<String>,
    /// This node's tunnels at once, in place of `relay.max_links_per_node`:
    /// a relay behind this one carries the tunnels of many nodes, and only
    /// it should get more.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_links: Option<u32>,
    /// This node's opens a minute, in place of `relay.max_opens_per_minute`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_opens_per_minute: Option<u32>,
}

impl RelayNode {
    /// This node's tunnels at once: its own limit, else the relay's.
    pub fn links(&self, relay: &Relay) -> u32 {
        self.max_links.unwrap_or(relay.max_links_per_node)
    }

    /// This node's opens a minute: its own limit, else the relay's.
    pub fn opens(&self, relay: &Relay) -> u32 {
        self.max_opens_per_minute
            .unwrap_or(relay.max_opens_per_minute)
    }

    /// Whether this node's tunnels may go to `center`.
    pub fn may_reach(&self, center: &str) -> bool {
        self.centers.is_empty() || self.centers.iter().any(|c| c == center)
    }
}

/// Why a `node.toml` that keeps proxy secrets in the file is refused.
pub const PROXY_SECRETS_IN_FILE: &str = "connection holds proxy secrets (header values, or a user name and password in the proxy URL), which belong in the system keyring, not in node.toml: run `nerve-node proxy set` again (if the file holds them already, delete them from it and take it with `nerve-node config accept` first)";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SettingsGrant {
    #[default]
    Off,
    Write,
}

/// One paired center.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CenterEntry {
    /// The owner's name for the center; the CLI's `--center`.
    pub name: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
    pub center_id: String,
    /// This node's id at the center (from its key for this center).
    pub node_id: String,
    #[serde(default)]
    pub settings: SettingsGrant,
    /// The node does not dial while paused (the center may pause, only the
    /// owner may unpause).
    #[serde(default, skip_serializing_if = "is_false")]
    pub paused: bool,
    /// The center sent `bye revoked`: the node does not dial again.
    #[serde(default, skip_serializing_if = "is_false")]
    pub revoked: bool,
    /// The center answered 401: it no longer knows this node.
    #[serde(default, skip_serializing_if = "is_false")]
    pub unknown: bool,
    /// The node's public key for this center (hex) once it was rotated
    /// (docs/dev/spec/protocol.md §4.10); without it, the key it paired
    /// with, whose hash `node_id` is. A backup checks the key by it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// How many rotations of the node's key this pairing settled, and of
    /// the center's key it took: a restore keeps the key or pin of the
    /// config that is further along, here or in the backup.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub key_rotations: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub pin_rotations: u32,
    /// The pin the center had before it rotated its key, still taken until
    /// its grace ends (docs/dev/spec/protocol.md §4.10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_pin: Option<OldPin>,
    #[serde(default)]
    pub policy: CenterPolicy,
}

/// A center's replaced pin and the end of its grace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OldPin {
    pub pin: String,
    /// Milliseconds since the Unix epoch; from then on the pin is refused.
    pub until_ms: u64,
}

impl CenterEntry {
    /// Whether the node should keep a link to this center.
    pub fn dials(&self) -> bool {
        !self.paused && !self.revoked && !self.unknown
    }

    /// The pins the center's certificate may carry at `now_ms`: the pin, and
    /// the old one while its grace runs. Empty without a pin (the system's
    /// roots, or plain HTTP on loopback).
    pub fn pins_at(&self, now_ms: u64) -> Vec<&str> {
        let Some(pin) = self.pin.as_deref() else {
            return Vec::new();
        };
        let mut pins = vec![pin];
        if let Some(old) = self.old_pin.as_ref().filter(|o| now_ms < o.until_ms) {
            pins.push(&old.pin);
        }
        pins
    }
}

/// The permission modes (docs/dev/policy-engine.md). A call no mode and no rule
/// allows is refused at once; nothing waits for an answer. Deny rules work in
/// every mode and win over everything else; allow rules count only in
/// `allowlist`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Default deny: a call runs only when an allow rule lets it through.
    /// What a pairing whose file names no mode is in, and where `folder` and
    /// `user` fall back to when their time runs out.
    #[default]
    Allowlist,
    /// Full access inside the folders, by their flags: reading where `r` is
    /// set, writing where `w` is, commands where `x` is, in the folders and
    /// everything below them; on the installed Linux node a read call may
    /// also read where every account may read. What a new pairing starts in.
    Folder,
    /// Full access as the user, protected paths aside.
    User,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Allowlist => "allowlist",
            Mode::Folder => "folder",
            Mode::User => "user",
        }
    }
}

/// What a center may do with a folder: three independent flags, every
/// combination allowed. In the config it is the string of the letters that
/// are set, `"rx"` (`""` for none).
///
/// - `read`: read the files and list the directories (fs read actions).
/// - `write`: create, change and delete (fs write actions).
/// - `execute`: run commands with a working directory in it, and run the
///   programs it holds.
///
/// A write-only folder is legal: the sandbox grants the write rights without
/// the read rights, so a command can put files there but not read them back
/// or list the folder.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Access {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl Access {
    pub const NONE: Access = Access {
        read: false,
        write: false,
        execute: false,
    };
    pub const ALL: Access = Access {
        read: true,
        write: true,
        execute: true,
    };

    /// `r`, `w` or `x`, each at most once, in any order; `""` is none.
    pub fn parse(s: &str) -> Result<Access, String> {
        let mut a = Access::NONE;
        for c in s.chars() {
            let flag = match c {
                'r' => &mut a.read,
                'w' => &mut a.write,
                'x' => &mut a.execute,
                other => {
                    return Err(format!("{s:?}: {other:?} is not a folder flag (r, w or x)"));
                }
            };
            if std::mem::replace(flag, true) {
                return Err(format!("{s:?}: {c:?} is given twice"));
            }
        }
        Ok(a)
    }

    /// One chmod-style change: `=rwx` replaces all three flags with the
    /// letters after it (`=` alone clears them), `+x` sets the flags named and
    /// `-w` clears them; the others stay.
    pub fn change(self, spec: &str) -> Result<Access, String> {
        let (op, letters) = match spec.chars().next() {
            Some(op @ ('=' | '+' | '-')) => (op, &spec[1..]),
            _ => return Err(format!("{spec:?}: start with =, + or - (=rwx, +x, -w)")),
        };
        if letters.is_empty() && op != '=' {
            return Err(format!("{spec:?}: name at least one of r, w, x after {op}"));
        }
        let named = Access::parse(letters).map_err(|e| format!("{spec:?}: {e}"))?;
        Ok(match op {
            '=' => named,
            '+' => Access {
                read: self.read || named.read,
                write: self.write || named.write,
                execute: self.execute || named.execute,
            },
            _ => Access {
                read: self.read && !named.read,
                write: self.write && !named.write,
                execute: self.execute && !named.execute,
            },
        })
    }

    pub fn is_none(self) -> bool {
        self == Access::NONE
    }

    /// The flags that are set, as `ls -l` shows them: `rw-`, `r-x`, `---`.
    pub fn to_chmod(self) -> String {
        [(self.read, 'r'), (self.write, 'w'), (self.execute, 'x')]
            .iter()
            .map(|(on, c)| if *on { *c } else { '-' })
            .collect()
    }
}

/// The config form: the letters that are set, `rwx` order.
impl std::fmt::Display for Access {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (on, c) in [(self.read, 'r'), (self.write, 'w'), (self.execute, 'x')] {
            if on {
                write!(f, "{c}")?;
            }
        }
        Ok(())
    }
}

impl TryFrom<String> for Access {
    type Error = String;
    fn try_from(s: String) -> Result<Access, String> {
        Access::parse(&s)
    }
}

impl From<Access> for String {
    fn from(a: Access) -> String {
        a.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Folder {
    /// Absolute, in this platform's form.
    pub path: String,
    /// Without it the folder grants nothing.
    #[serde(default)]
    pub access: Access,
}

/// A capability's or an action's exposure, as the owner sets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CapSetting {
    /// Allows sense and actuate actions, which no mode allows, and in
    /// `folder` mode an action that names no path (the folders cannot allow
    /// one); for the other actions the mode still decides. It never lets a
    /// call out of the folders.
    On,
    /// Refused.
    Off,
    /// Absent from this center's descriptor.
    Hidden,
}

impl CapSetting {
    pub fn parse(s: &str) -> Option<CapSetting> {
        match s {
            "on" => Some(CapSetting::On),
            "off" => Some(CapSetting::Off),
            "hidden" => Some(CapSetting::Hidden),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedOptions {
    /// More protected paths (`~/...` or absolute).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra: Vec<String>,
    /// Built-in protected paths the owner released.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
}

/// What one center may do on this node.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CenterPolicy {
    #[serde(default)]
    pub mode: Mode,
    /// An opt-in time limit for `folder` and `user`: milliseconds since the
    /// Unix epoch at which the mode runs out and the center falls back to
    /// `allowlist`. None means no limit: the mode stays until the owner
    /// changes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub folders: Vec<Folder>,
    /// The folders (by path) the node recorded at their real place when the
    /// owner added them (`folder add` stores the resolved path): they led
    /// nowhere else then. A recorded folder whose path leads elsewhere now,
    /// since something put a link in its way, is left out of a command's
    /// sandbox (`nerve-node` `exec::folder_sets`), whether or not a `w`
    /// folder still lets a command put links there. Only the owner changes
    /// the record: a center's settings keep it as it was. A folder without an
    /// entry (added before the record existed, or set by a center or by hand)
    /// is followed wherever its path leads.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub places: Vec<String>,
    /// `allowlist` mode only: its commands run as the owner's account
    /// instead of the installed node's account `nerve-run`, without the
    /// folders' sandbox ([`CenterPolicy::runs_as_owner`]).
    #[serde(default, skip_serializing_if = "is_false")]
    pub as_owner: bool,
    /// `cap` or `cap.action` → setting; `cap.action` wins over `cap`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub caps: BTreeMap<String, CapSetting>,
    #[serde(default)]
    pub protected: ProtectedOptions,
    /// Allow rules (`crate::rules`). They count only in `allowlist` mode.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// Deny rules: they refuse in every mode and win over any allow.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    /// Globs over the whole command line of a `sudo` command. A sudo command
    /// runs only when one matches, in every mode (and only with the sudo
    /// switch on); the normal allow list does not count for it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sudo_allow: Vec<String>,
}

/// Refuses a folder spelled so that it matches no path the node checks: a
/// `..` segment, and on Windows an 8.3 short name (`PROGRA~1`) or a name
/// that ends in a dot or space, which Windows drops. Folders are compared
/// as they are written, so such a folder would grant and release nothing.
fn folder_spelling(path: &str, windows: bool) -> Result<(), String> {
    let refuse = |why: String| {
        Err(format!(
            "folder {path:?} is not a folder path: {why}; use the full name"
        ))
    };
    let segs = path.split(|c| c == '/' || (windows && c == '\\'));
    for seg in segs.filter(|s| !s.is_empty()) {
        if seg == ".." {
            return refuse("it has a \"..\" segment".into());
        }
        if !windows {
            continue;
        }
        if seg.ends_with(['.', ' ']) {
            return refuse(format!(
                "{seg:?} ends in a dot or space, which Windows drops"
            ));
        }
        if short_name(seg) {
            return refuse(format!("{seg:?} is an 8.3 short name"));
        }
    }
    Ok(())
}

/// Whether `seg` has the shape of an 8.3 short name Windows makes for a
/// long one (`PROGRA~1`, `NODE-~12.TXT`): at most eight characters ending
/// in `~` and digits, then at most a three-letter extension.
fn short_name(seg: &str) -> bool {
    let (base, ext) = seg.split_once('.').unwrap_or((seg, ""));
    let Some((stem, n)) = base.rsplit_once('~') else {
        return false;
    };
    !stem.is_empty()
        && !n.is_empty()
        && n.bytes().all(|b| b.is_ascii_digit())
        && base.len() <= 8
        && ext.len() <= 3
        && !ext.contains('.')
}

/// Whether two folder paths name one place, compared as the policy does.
fn same_place(a: &str, b: &str) -> bool {
    let (a, b) = (Path::new(a), Path::new(b));
    within(a, b) && within(b, a)
}

impl CenterPolicy {
    /// The mode in force at `now_ms`: a `folder` or `user` whose limit has
    /// passed is `allowlist`.
    pub fn mode_at(&self, now_ms: u64) -> Mode {
        match self.mode {
            Mode::Folder | Mode::User if self.until.is_some_and(|u| u <= now_ms) => Mode::Allowlist,
            m => m,
        }
    }

    /// Whether the commands of this pairing run as the owner's account at
    /// `now_ms` on the installed node: in `user` mode, and in `allowlist`
    /// mode with `as_owner`. Every other command runs as `nerve-run`, in
    /// the folders' sandbox.
    pub fn runs_as_owner(&self, now_ms: u64) -> bool {
        match self.mode_at(now_ms) {
            Mode::User => true,
            Mode::Allowlist => self.as_owner,
            Mode::Folder => false,
        }
    }

    /// Whether the folder at `path` was recorded at its real place
    /// ([`CenterPolicy::places`]).
    pub fn is_placed(&self, path: &str) -> bool {
        self.places.iter().any(|p| same_place(p, path))
    }

    /// Records the folder at `path` as being at its real place, or, with
    /// `placed` false, forgets that it was.
    pub fn set_placed(&mut self, path: &str, placed: bool) {
        self.places.retain(|p| !same_place(p, path));
        if placed {
            self.places.push(path.to_string());
        }
    }

    /// The owner's setting for `cap.action`, else for `cap`.
    pub fn cap_setting(&self, cap: &str, action: Option<&str>) -> Option<CapSetting> {
        action
            .and_then(|a| self.caps.get(&format!("{cap}.{a}")))
            .or_else(|| self.caps.get(cap))
            .copied()
    }
}

/// The part of the config one center may read and set (`settings` profile).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CenterDocument {
    #[serde(default)]
    pub paused: bool,
    #[serde(default)]
    pub policy: CenterPolicy,
}

impl NodeConfig {
    /// Parses and checks `node.toml`; unknown keys are errors.
    pub fn parse(text: &str) -> Result<NodeConfig, String> {
        refuse_proxy_secrets(text)?;
        let mut c: NodeConfig = toml::from_str(text).map_err(|e| e.to_string())?;
        c.validate()?;
        Ok(c)
    }

    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("the node config serializes")
    }

    /// Reads `path`; a missing file is the default config. The MAC line the
    /// node writes is a comment here and is not checked: the daemon and the
    /// CLI read the file through `SettingsStore`, which checks it.
    pub fn load(path: &Path) -> Result<NodeConfig, String> {
        match std::fs::read_to_string(path) {
            Ok(t) => NodeConfig::parse(&t).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(NodeConfig::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    /// Writes `path` atomically, 0600, without a MAC: once the node has its
    /// key it refuses such a file. The node writes through `SettingsStore`.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(dir) = path.parent() {
            nerve_transport::files::create_private_dir(dir)
                .map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        nerve_transport::files::write_private(path, self.to_toml().as_bytes())
            .map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn center(&self, name: &str) -> Option<&CenterEntry> {
        self.centers.iter().find(|c| c.name == name)
    }

    pub fn center_mut(&mut self, name: &str) -> Option<&mut CenterEntry> {
        self.centers.iter_mut().find(|c| c.name == name)
    }

    /// The checks serde cannot do. Folder paths are put in the form the
    /// policy keeps ([`CenterPolicy::validate`]).
    pub fn validate(&mut self) -> Result<(), String> {
        if let Some(n) = &self.node.name
            && !nerve_proto::valid_node_name(n)
        {
            return Err(format!(
                "node.name {n:?}: 1 to 32 characters of a-z, 0-9 and -, starting and ending with a letter or digit"
            ));
        }
        if let Some(u) = &self.machine.user
            && !valid_account_name(u)
        {
            return Err(format!(
                "machine.user {u:?}: an account name, 1 to 32 characters of a-z, A-Z, 0-9, ., _ and -"
            ));
        }
        if self.limits.max_running == 0 {
            return Err("limits.max_running must be at least 1".into());
        }
        // 0 would kill every command at once, and read as "none" it would be
        // the way round the maximum.
        for (key, n) in [
            ("default_timeout_secs", self.limits.default_timeout_secs),
            ("max_timeout_secs", self.limits.max_timeout_secs),
        ] {
            if n == 0 {
                return Err(format!("limits.{key} must be at least 1"));
            }
        }
        self.limits.command.validate()?;
        if let Some(p) = &self.connection.proxy {
            if has_user_info(p) {
                return Err(PROXY_SECRETS_IN_FILE.into());
            }
            nerve_transport::Proxy::parse(p, Vec::new())
                .and_then(|p| p.pinned(self.connection.pin.clone()))
                .map_err(|e| format!("connection.proxy: {e}"))?;
        }
        let https = self
            .connection
            .proxy
            .as_deref()
            .is_some_and(|p| p.to_ascii_lowercase().starts_with("https://"));
        if !https && (self.connection.pin.is_some() || self.connection.login.is_some()) {
            return Err("connection.pin and connection.login are for an https:// proxy".into());
        }
        if let Some(l) = &self.connection.login {
            if !valid_login(l) {
                return Err(
                    "connection.login: 1 to 64 characters, no `:`, `@`, space or control character"
                        .into(),
                );
            }
            if self
                .connection
                .headers
                .iter()
                .any(|h| h.eq_ignore_ascii_case("proxy-authorization"))
            {
                return Err(
                    "connection.login makes the Proxy-Authorization header; connection.headers names it too"
                        .into(),
                );
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        for (i, h) in self.connection.headers.iter().enumerate() {
            // Not echoed: a value typed where the name belongs is a secret.
            if !nerve_transport::net::valid_header_name(h) {
                return Err(format!(
                    "connection.headers: entry {} is not a header name (letters, digits and -)",
                    i + 1
                ));
            }
            if !seen.insert(h.to_ascii_lowercase()) {
                return Err(format!("connection.headers names {h} twice"));
            }
        }
        let mut providers = std::collections::BTreeSet::new();
        for p in &self.providers.allowed {
            if !valid_provider_name(&p.name) {
                return Err(format!(
                    "providers.allowed name {:?}: 1 to 32 characters of a-z, 0-9 and -, starting and ending with a letter or digit, not node",
                    p.name
                ));
            }
            if !providers.insert(p.name.clone()) {
                return Err(format!("providers.allowed names {:?} twice", p.name));
            }
            if !Path::new(&p.exe).is_absolute() {
                return Err(format!(
                    "providers.allowed {}: exe {:?} is not an absolute path",
                    p.name, p.exe
                ));
            }
        }
        validate_all(&self.capabilities, self.limits.max_timeout_secs)?;
        self.relay.validate()?;
        let mut names = std::collections::BTreeSet::new();
        for c in &mut self.centers {
            if !valid_center_name(&c.name) {
                return Err(format!(
                    "center name {:?}: 1 to 64 characters of a-z, A-Z, 0-9, - and _, starting and ending with a letter or digit",
                    c.name
                ));
            }
            if !names.insert(c.name.clone()) {
                return Err(format!("two centers are named {:?}", c.name));
            }
            nerve_proto::link::CenterUrl::parse(&c.url)
                .map_err(|e| format!("center {}: {e}", c.name))?;
            if c.public_key
                .as_ref()
                .is_some_and(|k| k.len() != 64 || nerve_proto::msg::unhex(k).is_none())
            {
                return Err(format!(
                    "center {}: public_key is not 64 lowercase hex characters",
                    c.name
                ));
            }
            // Pins are kept in one form, base64url without padding, as the
            // node computes them: a pin given with `=` padding names the
            // same key, and every comparison of pins holds.
            if let Some(p) = c.pin.as_mut()
                && let Ok(raw) = nerve_transport::tls::decode_pin(p)
            {
                *p = nerve_transport::tls::b64url(&raw);
            }
            if let Some(o) = c.old_pin.as_mut()
                && let Ok(raw) = nerve_transport::tls::decode_pin(&o.pin)
            {
                o.pin = nerve_transport::tls::b64url(&raw);
            }
            if let Some(old) = &c.old_pin {
                nerve_transport::tls::decode_pin(&old.pin)
                    .map_err(|e| format!("center {}: old_pin: {e}", c.name))?;
                if c.pin.is_none() {
                    return Err(format!(
                        "center {}: old_pin needs the pin that replaced it",
                        c.name
                    ));
                }
            }
            c.policy
                .validate()
                .map_err(|e| format!("center {}: {e}", c.name))?;
        }
        Ok(())
    }
}

/// Refuses a file that keeps a proxy secret: a `connection.headers` table
/// (a table of name to value) or a proxy URL with a user name
/// and password. This runs on the raw TOML, before the typed parse, whose
/// errors quote the offending line and so would quote the secret. Anything
/// but a list of strings in `connection.headers` is refused the same way
/// without quoting it.
fn refuse_proxy_secrets(text: &str) -> Result<(), String> {
    let Ok(doc) = toml::from_str::<toml::Table>(text) else {
        // Not TOML at all: the typed parse says why.
        return Ok(());
    };
    let Some(conn) = doc.get("connection").and_then(toml::Value::as_table) else {
        return Ok(());
    };
    if let Some(p) = conn.get("proxy").and_then(toml::Value::as_str)
        && has_user_info(p)
    {
        return Err(PROXY_SECRETS_IN_FILE.into());
    }
    match conn.get("headers") {
        None => Ok(()),
        Some(toml::Value::Table(_)) => Err(PROXY_SECRETS_IN_FILE.into()),
        Some(toml::Value::Array(a)) if a.iter().all(toml::Value::is_str) => Ok(()),
        Some(_) => Err("connection.headers is a list of header names".into()),
    }
}

/// Whether a URL carries a user name or password (`http://user:pass@host`).
fn has_user_info(url: &str) -> bool {
    url.contains('@')
}

/// Whether `s` can be the user name of a proxy login: what Basic carries
/// before its `:`.
pub fn valid_login(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && !s
            .chars()
            .any(|c| c == ':' || c == '@' || c.is_whitespace() || c.is_control())
}

/// A center's name as the CLI and the key file name use it: 1 to 64 of
/// A-Z, a-z, 0-9, `-` and `_`, starting and ending with a letter or digit
/// (a name that starts with `-` would read as a flag).
pub fn valid_center_name(s: &str) -> bool {
    let edge = |b: Option<&u8>| b.is_some_and(u8::is_ascii_alphanumeric);
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        && edge(s.as_bytes().first())
        && edge(s.as_bytes().last())
}

impl CenterPolicy {
    /// Checks the policy and puts its folder paths in the one form the
    /// policy keeps ([`crate::paths::normal_folder`]): the same place spelled
    /// twice is then one folder, or refused when the two give it different
    /// access, so no spelling decides which folder holds a path.
    pub fn validate(&mut self) -> Result<(), String> {
        let mut folders: Vec<Folder> = Vec::with_capacity(self.folders.len());
        for f in &self.folders {
            folder_spelling(&f.path, cfg!(windows))?;
            if !Path::new(&f.path).is_absolute() {
                return Err(format!("folder {:?} is not absolute", f.path));
            }
            let path = crate::paths::normal_folder(&f.path)?;
            let same = |g: &&Folder| same_place(&path, &g.path);
            match folders.iter().find(same) {
                Some(g) if g.access == f.access => {}
                Some(g) => {
                    return Err(format!(
                        "folders {:?} ({}) and {:?} ({}) are the same place with different access; keep one",
                        g.path,
                        g.access.to_chmod(),
                        f.path,
                        f.access.to_chmod()
                    ));
                }
                None => folders.push(Folder {
                    path,
                    access: f.access,
                }),
            }
        }
        // The record follows the folders: an entry that names none (the
        // folder was removed) is dropped, and the others take the form of
        // the folder they name.
        self.places = folders
            .iter()
            .filter(|f| self.is_placed(&f.path))
            .map(|f| f.path.clone())
            .collect();
        self.folders = folders;
        for rule in self.allow.iter().chain(&self.deny) {
            crate::rules::validate(rule)?;
        }
        // A rule of the guard names what to refuse; on the allow list it
        // would let exactly that run.
        if let Some(rule) = self
            .allow
            .iter()
            .find(|r| crate::guard::Guard::of_rule(r).is_some())
        {
            return Err(format!(
                "allow rule {rule:?} is a rule of the guard: it belongs on the deny list"
            ));
        }
        for glob in &self.sudo_allow {
            crate::rules::validate_command_glob(glob)?;
        }
        for p in self.protected.extra.iter().chain(&self.protected.allow) {
            if !(Path::new(p).is_absolute() || p.starts_with("~/")) {
                return Err(format!(
                    "protected path {p:?} is neither absolute nor ~/..."
                ));
            }
        }
        for key in self.caps.keys() {
            if !crate::rules::valid_scope(key) {
                return Err(format!("caps key {key:?}: `cap` or `cap.action`"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_start_and_end_with_a_letter_or_digit() {
        for ok in ["lab", "Lab_2", "a", "a-b_c"] {
            assert!(valid_center_name(ok), "{ok}");
        }
        for bad in ["", "-lab", "lab-", "_lab", "lab_", "-", "a b"] {
            assert!(!valid_center_name(bad), "{bad}");
        }
        assert!(valid_provider_name("desk-2"));
        for bad in ["-desk", "desk-", "node"] {
            assert!(!valid_provider_name(bad), "{bad}");
        }
        for (key, toml) in [
            ("node.name", "[node]\nname = \"-lab\"\n"),
            (
                "center name",
                "[[center]]\nname = \"-home\"\nurl = \"https://c.example\"\ncenter_id = \"c\"\nnode_id = \"n\"\n",
            ),
        ] {
            let e = NodeConfig::parse(toml).expect_err(key);
            assert!(e.contains("starting and ending"), "{key}: {e}");
        }
    }

    const SAMPLE_TEMPLATE: &str = r#"
[node]
name = "laptop"

[machine]
shell = "/bin/bash"
sudo = "off"

[limits]
max_running = 4

[connection]
proxy = "http://127.0.0.1:3128"

[[center]]
name = "home"
url = "https://center.example:8443"
pin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
center_id = "c1"
node_id = "n1"
settings = "write"

[center.policy]
mode = "folder"
folders = [{ path = "FOLDER", access = "rwx" }]
caps = { exec = "on", "fs.write" = "off" }
allow = ["exec.run:git status", "fs.read:~/notes/*"]
deny = ["fs:~/private/*", "exec.run:rm -rf *"]
sudo_allow = ["sudo apt update"]
"#;

    /// An absolute folder on the platform the tests run on.
    const FOLDER: &str = if cfg!(windows) {
        "C:/u/proj"
    } else {
        "/home/u/proj"
    };

    fn sample() -> String {
        SAMPLE_TEMPLATE.replace("FOLDER", FOLDER)
    }

    #[test]
    fn parses_round_trips_and_defaults() {
        let c = NodeConfig::parse(&sample()).unwrap();
        assert_eq!(c.limits.max_running, 4);
        assert_eq!(c.limits.output_cap_bytes, 16 * 1024 * 1024);
        assert_eq!(c.limits.default_timeout_secs, 10 * 60);
        assert_eq!(c.limits.max_timeout_secs, 60 * 60);
        let home = c.center("home").unwrap();
        assert_eq!(home.settings, SettingsGrant::Write);
        assert_eq!(home.policy.mode, Mode::Folder);
        assert_eq!(
            home.policy.allow,
            ["exec.run:git status", "fs.read:~/notes/*"]
        );
        assert_eq!(home.policy.deny.len(), 2);
        assert_eq!(home.policy.sudo_allow, ["sudo apt update"]);
        assert_eq!(
            home.policy.cap_setting("fs", Some("write")),
            Some(CapSetting::Off)
        );
        assert_eq!(home.policy.cap_setting("fs", Some("read")), None);
        assert_eq!(
            home.policy.cap_setting("exec", Some("run")),
            Some(CapSetting::On)
        );
        let again = NodeConfig::parse(&c.to_toml()).unwrap();
        assert_eq!(again, c);
        assert_eq!(NodeConfig::parse("").unwrap(), NodeConfig::default());
    }

    #[test]
    fn the_run_time_limits_are_the_owners_and_kept_out_of_the_file_while_default() {
        let c = NodeConfig::parse("[limits]\ndefault_timeout_secs = 30\nmax_timeout_secs = 90\n")
            .unwrap();
        assert_eq!(c.limits.default_timeout_secs, 30);
        assert_eq!(c.limits.max_timeout_secs, 90);
        assert_eq!(NodeConfig::parse(&c.to_toml()).unwrap(), c);
        // One set, the other the default.
        let c = NodeConfig::parse("[limits]\nmax_timeout_secs = 90\n").unwrap();
        assert_eq!(c.limits.default_timeout_secs, 600);
        // The defaults are not written.
        let plain = NodeConfig::parse(&sample()).unwrap().to_toml();
        assert!(!plain.contains("timeout"), "{plain}");
        let mut set = NodeConfig::default();
        set.limits.max_timeout_secs = 90;
        assert!(set.to_toml().contains("max_timeout_secs = 90"));
        assert!(!set.to_toml().contains("default_timeout_secs"));
        // A center reads and changes its policy, nothing of this.
        let doc = serde_json::json!({"limits": {"max_timeout_secs": 1}});
        assert!(serde_json::from_value::<CenterDocument>(doc).is_err());
    }

    #[test]
    fn command_limits_have_defaults_and_a_call_gets_at_most_the_most() {
        let c = NodeConfig::parse(&sample()).unwrap();
        let l = c.limits.command;
        assert_eq!(l, CommandLimits::default());
        assert_eq!((l.memory_mb, l.memory_max_mb), (4096, 16384));
        assert_eq!((l.cpu_percent, l.cpu_max_percent), (200, 800));
        assert_eq!((l.processes, l.processes_max), (1024, 8192));
        let set = NodeConfig::parse(
            "[limits.command]\nmemory_mb = 512\nmemory_max_mb = 1024\ncpu_percent = 50\nprocesses_max = 2000\n",
        )
        .unwrap();
        let l = set.limits.command;
        assert_eq!(
            (l.memory_mb, l.memory_max_mb, l.cpu_percent),
            (512, 1024, 50)
        );
        assert_eq!(NodeConfig::parse(&set.to_toml()).unwrap(), set);
        // Only a changed one is written, so a node of before reads the file.
        assert!(set.to_toml().contains("[limits.command]"));
        assert!(!c.to_toml().contains("[limits.command]"), "{}", c.to_toml());

        // No call names a limit: the defaults.
        assert_eq!(
            l.grant(None, None, None).unwrap(),
            Granted {
                memory_mb: 512,
                cpu_percent: 50,
                processes: 1024
            }
        );
        // Less than the default, and more up to the most.
        assert_eq!(
            l.grant(Some(100), Some(800), Some(2000)).unwrap(),
            Granted {
                memory_mb: 100,
                cpu_percent: 800,
                processes: 2000
            }
        );
        for (asked, why) in [
            ((Some(1025), None, None), "memory_mb 1025 is more than"),
            ((None, Some(801), None), "cpu_percent 801 is more than"),
            ((None, None, Some(2001)), "processes 2001 is more than"),
            ((Some(0), None, None), "memory_mb must be at least 1"),
            ((None, Some(0), None), "cpu_percent must be at least 1"),
        ] {
            let e = l.grant(asked.0, asked.1, asked.2).unwrap_err();
            assert!(e.contains(why), "{asked:?}: {e}");
        }
        // The most is said, so the caller can ask again within it.
        assert!(
            l.grant(Some(1 << 40), None, None)
                .unwrap_err()
                .contains("at most 1024")
        );
    }

    #[test]
    fn refuses_command_limits_that_cannot_hold() {
        for (bad, why) in [
            (
                "[limits.command]\nmemory_mb = 9000\nmemory_max_mb = 8192\n",
                "limits.command.memory_mb (9000) is above limits.command.memory_max_mb (8192)",
            ),
            (
                "[limits.command]\ncpu_percent = 900\n",
                "limits.command.cpu_percent (900) is above limits.command.cpu_max_percent (800)",
            ),
            (
                "[limits.command]\nprocesses = 9000\n",
                "limits.command.processes (9000) is above limits.command.processes_max (8192)",
            ),
            (
                "[limits.command]\nmemory_mb = 0\n",
                "memory_mb must be from 1",
            ),
            (
                "[limits.command]\nprocesses_max = 0\n",
                "processes_max must be from 1",
            ),
            (
                "[limits.command]\nmemory_max_mb = 9999999999999\n",
                "memory_max_mb must be from 1 to 1073741824",
            ),
            ("[limits.command]\nmemroy_mb = 1\n", "unknown field"),
        ] {
            let e = NodeConfig::parse(bad).unwrap_err();
            assert!(e.contains(why), "{bad}: {e}");
        }
        // A center's document does not hold them.
        let doc = serde_json::json!({"limits": {"command": {"memory_mb": 1}}});
        assert!(serde_json::from_value::<CenterDocument>(doc).is_err());
    }

    #[test]
    fn the_log_level_is_info_unless_the_owner_sets_it() {
        use nerve_transport::log::Level;
        assert_eq!(NodeConfig::default().log.level, Level::Info);
        assert_eq!(NodeConfig::parse("[log]\n").unwrap().log.level, Level::Info);
        for level in Level::ALL {
            let c = NodeConfig::parse(&format!("[log]\nlevel = \"{level}\"\n")).unwrap();
            assert_eq!(c.log.level, level);
            assert_eq!(NodeConfig::parse(&c.to_toml()).unwrap().log.level, level);
        }
        // A center reads and changes its policy and `paused`, nothing of this.
        let doc = serde_json::json!({"log": {"level": "debug"}});
        assert!(serde_json::from_value::<CenterDocument>(doc).is_err());
    }

    #[test]
    fn refuses_unknown_keys_and_bad_values() {
        for (bad, why) in [
            ("[node]\nnmae = \"x\"\n", "unknown field"),
            ("[node]\nname = \"Bad Name\"\n", "node.name"),
            ("[limits]\nmax_running = 0\n", "max_running"),
            (
                "[limits]\ndefault_timeout_secs = 0\n",
                "default_timeout_secs",
            ),
            ("[limits]\nmax_timeout_secs = 0\n", "max_timeout_secs"),
            (
                "[connection]\nproxy = \"http://p:1\"\npin = \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"\n",
                "https",
            ),
            ("[connection]\nlogin = \"lab\"\n", "https"),
            (
                "[connection]\nproxy = \"https://p:1\"\nlogin = \"a:b\"\n",
                "connection.login",
            ),
            (
                "[connection]\nproxy = \"https://p:1\"\nlogin = \"lab\"\nheaders = [\"Proxy-Authorization\"]\n",
                "names it too",
            ),
            ("[machine]\nsudo = \"doas\"\n", "unknown variant"),
            ("[log]\nlevel = \"loud\"\n", "unknown variant"),
            ("[log]\nlvl = \"info\"\n", "unknown field"),
        ] {
            let e = NodeConfig::parse(bad).unwrap_err();
            assert!(e.contains(why), "{bad}: {e}");
        }
        let with = |extra: &str| format!("{}{extra}\n", sample());
        assert!(NodeConfig::parse(&with("until = 1\nfoo = 1")).is_err());
        // User mode needs no limit; none is the default.
        let user = sample().replace("mode = \"folder\"", "mode = \"user\"");
        let c = NodeConfig::parse(&user).unwrap();
        assert_eq!(c.centers[0].policy.until, None);
        assert_eq!(c.centers[0].policy.mode_at(u64::MAX), Mode::User);
        let rel = sample().replace(FOLDER, "proj");
        assert!(NodeConfig::parse(&rel).unwrap_err().contains("absolute"));
        let sample = sample();
        let two = format!(
            "{sample}\n{}",
            &sample[sample.find("[[center]]").unwrap()..]
        );
        assert!(NodeConfig::parse(&two).unwrap_err().contains("two centers"));
        // A rule must say what it is about; a bare path or command is no rule.
        for bad in [
            "deny = [\"~/private\"]",
            "allow = [\"git status\"]",
            "allow = [\"fs:/a/[\"]",
            "sudo_allow = [\"sudo [\"]",
            "caps = { \"a.b.c\" = \"on\" }",
            "deny = [\"guard:nerve\"]",
        ] {
            assert!(NodeConfig::parse(&center(bad)).is_err(), "{bad}");
        }
        assert!(NodeConfig::parse(&center("allow = [\"fs:/a/*\"]")).is_ok());
        // A rule of the guard is a deny rule; allowed, it would let through
        // what it names.
        assert!(NodeConfig::parse(&center("deny = [\"guard:node-service\"]")).is_ok());
        let e = NodeConfig::parse(&center("allow = [\"guard:node-service\"]")).unwrap_err();
        assert!(e.contains("belongs on the deny list"), "{e}");
    }

    /// The relay is off and out of the file unless the owner sets it; its
    /// nodes are kept by name and token hash, and anything else is refused.
    #[test]
    fn the_relay_is_off_until_set_and_keeps_only_token_hashes() {
        let c = NodeConfig::parse("").unwrap();
        assert_eq!(c.relay, Relay::default());
        assert_eq!(c.relay.listen, None);
        assert!(!c.to_toml().contains("relay"), "{}", c.to_toml());
        let hash = "a".repeat(64);
        let text = format!(
            "[relay]\nlisten = \"0.0.0.0:7490\"\nmax_links = 3\n\n[[relay.node]]\nname = \"lab-pc\"\ntoken_sha256 = \"{hash}\"\n"
        );
        let c = NodeConfig::parse(&text).unwrap();
        assert_eq!(c.relay.listen.as_deref(), Some("0.0.0.0:7490"));
        assert_eq!((c.relay.max_links, c.relay.max_links_per_node), (3, 4));
        assert_eq!(c.relay.node("lab-pc").unwrap().token_sha256, hash);
        assert_eq!(NodeConfig::parse(&c.to_toml()).unwrap(), c);
        let node = |name: &str, h: &str| {
            format!("[[relay.node]]\nname = \"{name}\"\ntoken_sha256 = \"{h}\"\n")
        };
        for (bad, why) in [
            (
                "[relay]\nlisten = \"relay.example:7490\"\n".to_string(),
                "relay.listen",
            ),
            (
                "[relay]\nlisten = \"0.0.0.0\"\n".to_string(),
                "relay.listen",
            ),
            ("[relay]\nmax_links = 0\n".to_string(), "at least 1"),
            (
                "[relay]\nmax_links_per_node = 0\n".to_string(),
                "at least 1",
            ),
            ("[relay]\ntoken = \"x\"\n".to_string(), "unknown field"),
            (node("Lab PC", &hash), "relay.node name"),
            (node("lab", &"A".repeat(64)), "token_sha256"),
            (node("lab", "abc"), "token_sha256"),
            (
                format!("{}{}", node("lab", &hash), node("lab", &hash)),
                "twice",
            ),
            (
                format!(
                    "[[relay.node]]\nname = \"lab\"\ntoken_sha256 = \"{hash}\"\ntoken = \"t\"\n"
                ),
                "unknown field",
            ),
        ] {
            let e = NodeConfig::parse(&bad).unwrap_err();
            assert!(e.contains(why), "{bad}: {e}");
        }
        // A center reads and changes its policy and `paused`, nothing of this.
        let doc = serde_json::json!({"relay": {"listen": "0.0.0.0:1"}});
        assert!(serde_json::from_value::<CenterDocument>(doc).is_err());
    }

    /// A config with one center whose policy is `policy`.
    fn center(policy: &str) -> String {
        format!(
            "[[center]]\nname = \"home\"\nurl = \"https://c.example:8443\"\ncenter_id = \"c\"\nnode_id = \"n\"\n[center.policy]\n{policy}\n"
        )
    }

    /// A center's pin given with base64 padding is kept without it: the same
    /// key, in the one form the node compares.
    #[test]
    fn a_padded_center_pin_is_kept_without_padding() {
        // Canonical base64url: the last character carries no stray bits.
        let pin = format!("{}E", "A".repeat(42));
        let text = format!(
            "[[center]]\nname = \"home\"\nurl = \"https://c.example:8443\"\npin = \"{pin}=\"\ncenter_id = \"c\"\nnode_id = \"n\"\n[center.old_pin]\npin = \"{}=\"\nuntil_ms = 1\n",
            "A".repeat(43)
        );
        let cfg = NodeConfig::parse(&text).unwrap();
        assert_eq!(cfg.centers[0].pin.as_deref(), Some(pin.as_str()));
        assert_eq!(cfg.centers[0].old_pin.as_ref().unwrap().pin, "A".repeat(43));
    }

    /// A rotated center's old pin round-trips through the file and is taken
    /// beside the new one until its grace ends.
    #[test]
    fn an_old_pin_is_taken_until_its_grace_ends() {
        let (new, old) = ("B".repeat(43), "A".repeat(43));
        let text = format!(
            "[[center]]\nname = \"home\"\nurl = \"https://c.example:8443\"\npin = \"{new}\"\ncenter_id = \"c\"\nnode_id = \"n\"\n[center.old_pin]\npin = \"{old}\"\nuntil_ms = 1000\n"
        );
        let cfg = NodeConfig::parse(&text).unwrap();
        let c = &cfg.centers[0];
        assert_eq!(c.pins_at(999), [new.as_str(), old.as_str()]);
        assert_eq!(c.pins_at(1000), [new.as_str()]);
        assert_eq!(NodeConfig::parse(&cfg.to_toml()).unwrap(), cfg);
        // A center without a pin has none to take.
        let mut plain = c.clone();
        plain.pin = None;
        plain.old_pin = None;
        assert!(plain.pins_at(0).is_empty());
        // A bad old pin, or one without the pin that replaced it, is refused.
        let bad = text.replace(&format!("pin = \"{old}\""), "pin = \"short\"");
        assert!(NodeConfig::parse(&bad).unwrap_err().contains("old_pin"));
        let alone = text.replace(&format!("pin = \"{new}\"\n"), "");
        assert!(NodeConfig::parse(&alone).unwrap_err().contains("old_pin"));
    }

    /// A folder spelled so that it matches nothing at call time (an 8.3
    /// name, a trailing dot or space, `x\..`) is refused, with Windows'
    /// rules tested on every platform.
    #[test]
    fn a_folder_spelling_that_names_no_folder_is_refused() {
        for (path, why) in [
            ("C:\\Users\\PIGGID~1\\.ssh", "8.3 short name"),
            ("C:\\PROGRA~1\\PowerShell", "8.3 short name"),
            ("C:\\Users\\u\\NODE-~12.TXT", "8.3 short name"),
            ("C:\\Users\\u\\.ssh.", "dot or space"),
            ("C:\\Users\\u\\.ssh \\x", "dot or space"),
            ("C:/Users/u/proj./x", "dot or space"),
            ("C:\\Users\\u\\x\\..\\.ssh", ".."),
            ("C:\\Users\\u\\.", "dot or space"),
        ] {
            let e = folder_spelling(path, true).unwrap_err();
            assert!(
                e.contains(why) && e.contains("use the full name"),
                "{path}: {e}"
            );
        }
        for path in [
            "C:\\Users\\u\\proj",
            "C:\\Users\\u\\backup~old",
            "C:\\Users\\u\\a~1b~2c~3d",
            "C:\\Users\\u\\.ssh.d\\x",
            "C:\\",
            "\\\\?\\C:\\Users\\u",
        ] {
            assert_eq!(folder_spelling(path, true), Ok(()), "{path}");
        }
        // On Unix those are plain names; `..` is no folder there either.
        for path in ["/home/u/x.", "/home/u/PROGRA~1", "/home/u/a "] {
            assert_eq!(folder_spelling(path, false), Ok(()), "{path}");
        }
        assert!(folder_spelling("/home/u/x/../.ssh", false).is_err());
        // The owner's own file is refused on load with the same message.
        let odd = if cfg!(windows) {
            "C:/Users/u/x/../.ssh"
        } else {
            "/home/u/x/../.ssh"
        };
        let text = center(&format!(
            "folders = [{{ path = \"{odd}\", access = \"r\" }}]"
        ));
        let e = NodeConfig::parse(&text).unwrap_err();
        assert!(e.contains("use the full name"), "{e}");
    }

    /// The owner names the programs that may attach as providers; a name
    /// that could not be a descriptor's `provider`, one given twice, and a
    /// program that is not an absolute path are refused.
    #[test]
    fn allowed_providers_parse_and_bad_ones_are_refused() {
        let exe = if cfg!(windows) {
            "C:/bin/echo-provider"
        } else {
            "/usr/bin/echo-provider"
        };
        let text = format!("[providers]\nallowed = [{{ name = \"echo\", exe = \"{exe}\" }}]\n");
        let c = NodeConfig::parse(&text).unwrap();
        assert_eq!(c.providers.get("echo").unwrap().exe, exe);
        assert!(c.providers.get("other").is_none());
        assert_eq!(NodeConfig::parse(&c.to_toml()).unwrap(), c);
        // None is allowed by default, and the file does not say so.
        assert!(NodeConfig::default().providers.is_empty());
        assert!(!NodeConfig::default().to_toml().contains("providers"));
        for (bad, why) in [
            ("{ name = \"node\", exe = \"EXE\" }", "not node"),
            ("{ name = \"Echo\", exe = \"EXE\" }", "a-z, 0-9"),
            ("{ name = \"echo\", exe = \"bin/echo\" }", "absolute"),
            (
                "{ name = \"echo\", exe = \"EXE\" }, { name = \"echo\", exe = \"EXE\" }",
                "twice",
            ),
            (
                "{ name = \"echo\", exe = \"EXE\", uid = 1 }",
                "unknown field",
            ),
        ] {
            let text = format!("[providers]\nallowed = [{}]\n", bad.replace("EXE", exe));
            let e = NodeConfig::parse(&text).unwrap_err();
            assert!(e.contains(why), "{bad}: {e}");
        }
        // A center's document holds none of it.
        let doc = serde_json::json!({"providers": {"allowed": []}});
        assert!(serde_json::from_value::<CenterDocument>(doc).is_err());
    }

    #[test]
    fn a_new_center_starts_in_allowlist_mode_with_no_rule() {
        let p = CenterPolicy::default();
        assert_eq!(p.mode, Mode::Allowlist);
        assert!(p.allow.is_empty() && p.deny.is_empty() && p.sudo_allow.is_empty());
        let c = NodeConfig::parse(&center("")).unwrap();
        assert_eq!(c.centers[0].policy.mode, Mode::Allowlist);
        for m in [Mode::Allowlist, Mode::Folder, Mode::User] {
            let json = serde_json::json!(m.as_str());
            assert_eq!(serde_json::from_value::<Mode>(json).unwrap(), m);
        }
    }

    #[test]
    fn a_mode_without_a_limit_never_runs_out() {
        for mode in [Mode::Allowlist, Mode::Folder, Mode::User] {
            let p = CenterPolicy {
                mode,
                ..Default::default()
            };
            assert_eq!(p.mode_at(0), mode);
            assert_eq!(p.mode_at(u64::MAX), mode);
        }
    }

    #[test]
    fn an_expired_limit_falls_back_to_allowlist() {
        for mode in [Mode::Folder, Mode::User] {
            let p = CenterPolicy {
                mode,
                until: Some(1000),
                ..Default::default()
            };
            assert_eq!(p.mode_at(999), mode);
            assert_eq!(p.mode_at(1000), Mode::Allowlist);
        }
    }

    #[test]
    fn proxy_secrets_in_the_file_are_refused_without_quoting_them() {
        // Secrets in the file: header values, or credentials in the URL.
        for old in [
            "[connection]\nproxy = \"http://p:3128\"\nheaders = { X-Key = \"s3cret\" }\n",
            "[connection]\nproxy = \"http://user:s3cret@p:3128\"\n",
            "[connection]\nheaders = { Proxy-Authorization = \"Basic s3cret\" }\n",
        ] {
            let e = NodeConfig::parse(old).unwrap_err();
            assert!(e.contains("run `nerve-node proxy set` again"), "{old}: {e}");
            assert!(!e.contains("s3cret"), "{e}");
            let d = tempfile::tempdir().unwrap();
            let path = d.path().join("node.toml");
            std::fs::write(&path, old).unwrap();
            let e = NodeConfig::load(&path).unwrap_err();
            assert!(e.contains("proxy set") && !e.contains("s3cret"), "{e}");
        }
        // Not a list of names: refused, not quoted.
        let e = NodeConfig::parse("[connection]\nheaders = \"X-Key: s3cret\"\n").unwrap_err();
        assert!(!e.contains("s3cret"), "{e}");
        let e = NodeConfig::parse("[connection]\nheaders = [\"X-Key: s3cret\"]\n").unwrap_err();
        assert!(!e.contains("s3cret"), "{e}");
    }

    #[test]
    fn the_file_keeps_the_proxy_url_and_the_header_names() {
        let e = NodeConfig::parse("[connection]\nheaders = [\"X-Key\", \"x-key\"]\n").unwrap_err();
        assert!(e.contains("twice"), "{e}");
        let c = NodeConfig::parse(
            "[connection]\nproxy = \"http://p:3128\"\nheaders = [\"Proxy-Authorization\", \"X-Key\"]\n",
        )
        .unwrap();
        assert_eq!(c.connection.headers, ["Proxy-Authorization", "X-Key"]);
        assert_eq!(NodeConfig::parse(&c.to_toml()).unwrap(), c);
        // A credential set any other way (`config set`) is refused too.
        let mut c = NodeConfig::default();
        c.connection.proxy = Some("http://u:s3cret@p:3128".into());
        let e = c.validate().unwrap_err();
        assert!(e.contains("proxy set") && !e.contains("s3cret"), "{e}");
    }

    #[test]
    fn the_account_of_the_commands_on_windows_is_an_account_name() {
        let c = NodeConfig::parse("[machine]\nuser = \"alice.b\"\n").unwrap();
        assert_eq!(c.machine.user.as_deref(), Some("alice.b"));
        assert_eq!(NodeConfig::parse(&c.to_toml()).unwrap(), c);
        assert_eq!(NodeConfig::default().machine.user, None);
        for bad in ["", "-x", "a b", "a:b", "a/b"] {
            let e = NodeConfig::parse(&format!("[machine]\nuser = {bad:?}\n")).unwrap_err();
            assert!(e.contains("machine.user"), "{bad}: {e}");
        }
    }

    #[test]
    fn a_file_without_the_sudo_switch_loads_as_off() {
        let none = NodeConfig::parse("[machine]\nshell = \"/bin/sh\"\n").unwrap();
        assert_eq!(none.machine.sudo, Sudo::Off);
        let on =
            NodeConfig::parse("[machine]\nsudo = \"on\"\nsudo_path = \"/usr/bin/sudo\"\n").unwrap();
        assert_eq!(on.machine.sudo, Sudo::On);
        assert_eq!(NodeConfig::parse(&on.to_toml()).unwrap(), on);
    }

    /// `as_owner` is written only where it is set, and only allowlist mode
    /// runs as the owner by it; user mode always does, folder mode never.
    #[test]
    fn a_pairing_runs_as_the_owner_in_user_mode_and_by_choice_in_allowlist() {
        let c = NodeConfig::parse(&center("mode = \"allowlist\"\nas_owner = true")).unwrap();
        let p = &c.centers[0].policy;
        assert!(p.as_owner && p.runs_as_owner(0));
        assert_eq!(NodeConfig::parse(&c.to_toml()).unwrap(), c);
        let mut p = CenterPolicy::default();
        assert!(!c.to_toml().contains("as_owner = false"));
        assert!(!p.runs_as_owner(0));
        p.mode = Mode::User;
        assert!(p.runs_as_owner(0));
        p.mode = Mode::Folder;
        p.as_owner = true;
        assert!(!p.runs_as_owner(0), "folder mode always runs as nerve-run");
        // A user mode whose time ran out is allowlist again.
        p.mode = Mode::User;
        p.as_owner = false;
        p.until = Some(5);
        assert!(p.runs_as_owner(4) && !p.runs_as_owner(5));
    }

    #[test]
    fn unknown_keys_and_values_are_errors() {
        for bad in [
            "mode = \"ask\"",
            "mode = \"full\"",
            "mode = \"folders\"",
            "[center.policy.commands]\npermit = [\"x\"]",
            "[center.policy.commands]\nallow = [\"x\"]",
            "approvals = \"both\"",
            "full_until = 5",
            "caps = { exec = \"ask\" }",
            "[center.policy.commands]\nalways_ask = [\"x\"]",
        ] {
            assert!(NodeConfig::parse(&center(bad)).is_err(), "{bad}");
        }
        assert!(NodeConfig::parse("[machine]\nelevation = \"off\"\n").is_err());
    }

    #[test]
    fn folder_access_is_three_independent_flags() {
        // Every combination parses, prints back as the letters in rwx order
        // and survives the config file.
        for bits in 0..8u8 {
            let a = Access {
                read: bits & 1 != 0,
                write: bits & 2 != 0,
                execute: bits & 4 != 0,
            };
            let text = a.to_string();
            assert_eq!(Access::parse(&text).unwrap(), a, "{text:?}");
            let policy = CenterPolicy {
                folders: vec![Folder {
                    path: FOLDER.into(),
                    access: a,
                }],
                ..Default::default()
            };
            let toml = toml::to_string(&policy).unwrap();
            assert!(toml.contains(&format!("access = \"{text}\"")), "{toml}");
            assert_eq!(toml::from_str::<CenterPolicy>(&toml).unwrap(), policy);
        }
        // Any order is read; the letters come back in rwx order.
        assert_eq!(Access::parse("xr").unwrap().to_string(), "rx");
        assert_eq!(Access::parse("").unwrap(), Access::NONE);
        assert_eq!(Access::ALL.to_chmod(), "rwx");
        assert_eq!(Access::parse("wx").unwrap().to_chmod(), "-wx");
        assert_eq!(Access::NONE.to_chmod(), "---");
        // A folder without the key grants nothing.
        let bare = format!("folders = [{{ path = \"{FOLDER}\" }}]");
        let p: CenterPolicy = toml::from_str(&bare).unwrap();
        assert!(p.folders[0].access.is_none());
    }

    /// Folders are kept in one form, so one place is never two folders.
    #[cfg(not(windows))]
    #[test]
    fn a_folder_list_names_each_place_once_in_one_form() {
        let folders = |list: &[(&str, &str)]| CenterPolicy {
            folders: list
                .iter()
                .map(|(p, a)| Folder {
                    path: p.to_string(),
                    access: Access::parse(a).unwrap(),
                })
                .collect(),
            ..Default::default()
        };
        let mut p = folders(&[("/home/u//proj/./", "rw"), ("/", "r")]);
        p.validate().unwrap();
        assert_eq!(p.folders[0].path, "/home/u/proj");
        assert_eq!(p.folders[1].path, "/");
        // The same place twice with other flags is refused, with both.
        let mut p = folders(&[("/home/u/.ssh", "r"), ("/home/u/.ssh/", "rw")]);
        let e = p.validate().unwrap_err();
        assert!(
            e.contains("/home/u/.ssh") && e.contains("same place"),
            "{e}"
        );
        // With the same flags it is one folder.
        let mut p = folders(&[("/home/u/proj", "r"), ("/home/u/./proj", "r")]);
        p.validate().unwrap();
        assert_eq!(p.folders.len(), 1);
        // `..` could name another place once a symlink is on the way.
        let mut p = folders(&[("/home/u/x/../.ssh", "rw")]);
        assert!(p.validate().unwrap_err().contains(".."));
        // The owner's file is held to the same.
        let twice = center(
            "folders = [{ path = \"/a\", access = \"r\" }, { path = \"/a/\", access = \"rw\" }]",
        );
        assert!(
            NodeConfig::parse(&twice)
                .unwrap_err()
                .contains("same place")
        );
        let tidy = NodeConfig::parse(&center("folders = [{ path = \"/a//b/\", access = \"r\" }]"));
        assert_eq!(tidy.unwrap().centers[0].policy.folders[0].path, "/a/b");
    }

    /// The record of the folders' real places (`places`) follows the
    /// folders: it names a folder in the form the folder has, drops what
    /// names no folder, and a config without it reads as before.
    #[cfg(not(windows))]
    #[test]
    fn the_record_of_real_places_follows_the_folders() {
        let text = center(
            "folders = [{ path = \"/a/b\", access = \"r\" }, { path = \"/c\", access = \"rw\" }]\nplaces = [\"/a//b/\", \"/gone\", \"/a/b\"]",
        );
        let cfg = NodeConfig::parse(&text).unwrap();
        let p = &cfg.centers[0].policy;
        assert_eq!(p.places, ["/a/b"]);
        assert!(p.is_placed("/a/b") && p.is_placed("/a//b/"));
        assert!(!p.is_placed("/c") && !p.is_placed("/gone"));
        // It is saved and read again as it is.
        assert_eq!(NodeConfig::parse(&cfg.to_toml()).unwrap(), cfg);

        // A config without the record has none, and writes none.
        let old = center("folders = [{ path = \"/a/b\", access = \"r\" }]");
        let old = NodeConfig::parse(&old).unwrap();
        assert!(old.centers[0].policy.places.is_empty());
        assert!(!old.to_toml().contains("places"));

        // Recording and forgetting one place; the other stays. A place
        // recorded twice, in two spellings, is one entry.
        let mut p = cfg.centers[0].policy.clone();
        p.set_placed("/c", true);
        p.set_placed("/c/", true);
        assert_eq!(p.places, ["/a/b", "/c/"]);
        assert!(p.is_placed("/c"));
        p.set_placed("/a/b", false);
        assert!(!p.is_placed("/a/b") && p.is_placed("/c"));
        // A folder taken out of the list takes its record along.
        p.folders.retain(|f| f.path != "/c");
        p.validate().unwrap();
        assert!(p.places.is_empty());
    }

    #[test]
    fn folder_access_changes_apply_in_order() {
        let start = Access::parse("r").unwrap();
        let steps = |specs: &[&str]| {
            specs
                .iter()
                .try_fold(start, |a, s| a.change(s))
                .map(|a| a.to_string())
        };
        assert_eq!(steps(&["+x"]).unwrap(), "rx");
        assert_eq!(steps(&["+rw"]).unwrap(), "rw");
        assert_eq!(steps(&["-r"]).unwrap(), "");
        assert_eq!(steps(&["=rwx"]).unwrap(), "rwx");
        assert_eq!(steps(&["="]).unwrap(), "");
        // Left to right: the later change sees the earlier one.
        assert_eq!(steps(&["=rwx", "-w"]).unwrap(), "rx");
        assert_eq!(steps(&["-w", "=w", "+x"]).unwrap(), "wx");
        assert_eq!(steps(&["+w", "-w"]).unwrap(), "r");
        assert_eq!(steps(&["=x", "+w", "-x", "+r"]).unwrap(), "rw");
        for bad in ["rw", "+", "-", "+q", "-rr", "*r", ""] {
            assert!(start.change(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn folder_access_refuses_anything_but_r_w_x_once() {
        for bad in ["ro", "rw+", "rr", "RW", "r w", "all", "true"] {
            assert!(Access::parse(bad).is_err(), "{bad:?}");
            let text = format!("folders = [{{ path = \"{FOLDER}\", access = \"{bad}\" }}]");
            assert!(toml::from_str::<CenterPolicy>(&text).is_err(), "{bad:?}");
        }
        // Separate flags next to the access string are not accepted.
        let old = format!("folders = [{{ path = \"{FOLDER}\", access = \"rw\", execute = true }}]");
        assert!(toml::from_str::<CenterPolicy>(&old).is_err());
    }

    #[test]
    fn ask_is_not_a_value() {
        let ask = serde_json::json!({"mode": "ask"});
        assert!(serde_json::from_value::<CenterPolicy>(ask).is_err());
        let cap = serde_json::json!({"caps": {"fs": "ask"}});
        assert!(serde_json::from_value::<CenterPolicy>(cap).is_err());
        assert_eq!(CapSetting::parse("ask"), None);
    }

    #[test]
    fn saves_private_and_loads_back() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("cfg/node.toml");
        assert_eq!(NodeConfig::load(&path).unwrap(), NodeConfig::default());
        let c = NodeConfig::parse(&sample()).unwrap();
        c.save(&path).unwrap();
        assert_eq!(NodeConfig::load(&path).unwrap(), c);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
