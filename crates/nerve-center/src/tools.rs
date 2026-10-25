//! Where an `execute` goes (docs/dev/spec/harness.md §4).
//!
//! The center offers the agent two static tools, `list` and `execute`
//! (`mcp.rs`); what a node offers is read from its catalog (`listing.rs`).
//!
//! The built-in capabilities `node`, `settings` and `audit` are never
//! offered: they are the center's own business, and a harness that could
//! call `settings.set` would let a model change its own permissions.

use nerve_proto::Effect;

/// Capabilities that are never offered to the agent.
pub const RESERVED_CAPS: [&str; 3] = ["node", "settings", "audit"];

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
                        },
                    )
                })
                .collect(),
            events: Default::default(),
            state: Value::Null,
            streams: Default::default(),
        }
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
        }
    }
}
