//! Where an `execute` goes (docs/dev/spec/harness.md §4).
//!
//! The center offers the agent two static tools, `list` and `execute`
//! (`mcp.rs`); what a node offers is read from its catalog (`listing.rs`).
//!
//! The built-in capabilities `node`, `settings` and `audit` are never
//! offered: they are the center's own business, and a harness that could
//! call `settings.set` would let a model change its own permissions. The
//! units of `job` are the center's own, served by the center itself.

use nerve_proto::Effect;

/// Capabilities that are never offered to the agent.
pub const RESERVED_CAPS: [&str; 3] = ["node", "settings", "audit"];

/// The center's own capabilities, which it serves itself on every node
/// (`job.status`, `job.cancel`; `stream` is kept for streams): a node's
/// capability of one of these names is left out.
pub const CENTER_CAPS: [&str; 2] = ["job", "stream"];

/// Where a call goes: one unit (`cap.action`) of one node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub node_id: String,
    pub node_name: String,
    pub cap: String,
    pub action: String,
    pub effect: Effect,
}

#[cfg(test)]
pub(crate) mod tests {
    use nerve_proto::descriptor::{Action, NodeInfo, Software};
    use nerve_proto::{Capability, Descriptor, Effect, Exposure};
    use serde_json::Value;

    pub fn cap(id: &str, profile: &str, actions: &[(&str, Effect, Value)]) -> Capability {
        Capability {
            id: id.into(),
            profile: profile.into(),
            provider: "node".into(),
            exposure: Exposure::On,
            summary: format!("{id} summary"),
            actions: actions
                .iter()
                .map(|(n, e, p)| {
                    (
                        n.to_string(),
                        Action {
                            effect: *e,
                            summary: format!("{n} it"),
                            params: p.clone(),
                            result: Value::Null,
                            exposure: None,
                            as_account: false,
                        },
                    )
                })
                .collect(),
            events: Default::default(),
            state: Default::default(),
            streams: Default::default(),
        }
    }

    /// The params of the node's `exec.signal`.
    pub fn signal_params() -> Value {
        serde_json::json!({"type": "object",
               "properties": {"call": {"type": "integer", "minimum": 0},
                              "signal": {"enum": ["term", "kill", "int"]}},
               "required": ["call", "signal"], "additionalProperties": false})
    }

    pub fn desc(name: &str, caps: Vec<Capability>) -> Descriptor {
        Descriptor {
            nerve: "0".into(),
            node: NodeInfo {
                id: format!("id-{name}"),
                name: name.into(),
                platform: "linux".into(),
                arch: "x86_64".into(),
                software: Software {
                    name: "nerve-node".into(),
                    version: "x.y.z".into(),
                },
            },
            rev: 1,
            summary: String::new(),
            capabilities: caps,
            access: None,
        }
    }
}

#[cfg(test)]
mod names {
    /// The names the center keeps for itself and from the agent are names
    /// no program and no capability of a node's config may take
    /// (nerve_policy::config::BUILT_IN), so none of theirs is ever left out
    /// or shadowed for its name.
    #[test]
    fn the_centers_own_names_are_built_in_on_every_node() {
        for name in super::CENTER_CAPS.iter().chain(&super::RESERVED_CAPS) {
            assert!(nerve_policy::config::BUILT_IN.contains(name), "{name}");
        }
    }
}
