//! The descriptor a node publishes: what it is and what it offers one center
//! (docs/dev/spec/protocol.md §6).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// What an action does to the world. The node's policy decides by effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Read,
    Sense,
    Write,
    Actuate,
    Execute,
}

impl Effect {
    pub fn as_str(self) -> &'static str {
        match self {
            Effect::Read => "read",
            Effect::Sense => "sense",
            Effect::Write => "write",
            Effect::Actuate => "actuate",
            Effect::Execute => "execute",
        }
    }
}

/// How a capability is offered to a center. Hidden capabilities are left out
/// of the descriptor altogether, so `hidden` is not a wire value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Exposure {
    On,
    Off,
}

/// How much of the descriptor `describe` returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Detail {
    /// Node, summary and capability ids with their summaries.
    #[default]
    Summary,
    /// One capability (`cap`) with its members but without schemas.
    Capability,
    /// Everything, schemas included.
    Full,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Software {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub arch: String,
    pub software: Software,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Action {
    pub effect: Effect,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub summary: String,
    /// JSON Schema of the arguments.
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub params: Value,
    /// JSON Schema of the result.
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub result: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventDecl {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub summary: String,
    /// Delivered without `sub` (D7).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub implicit: bool,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub data: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StreamKind {
    Reliable,
    /// Reserved for later; no node declares it.
    Media,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Up,
    Down,
    Both,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StreamDecl {
    pub kind: StreamKind,
    pub direction: Direction,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Capability {
    pub id: String,
    /// The profile this capability follows (`fs`, `exec`, ...) or empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub profile: String,
    #[serde(default = "provider_node")]
    pub provider: String,
    pub exposure: Exposure,
    #[serde(default)]
    pub summary: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub actions: BTreeMap<String, Action>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub events: BTreeMap<String, EventDecl>,
    /// JSON Schema of the state document, when the capability has state.
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub state: Value,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub streams: BTreeMap<String, StreamDecl>,
}

fn provider_node() -> String {
    "node".into()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Descriptor {
    pub nerve: String,
    pub node: NodeInfo,
    pub rev: u64,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
}

impl Descriptor {
    pub fn capability(&self, id: &str) -> Option<&Capability> {
        self.capabilities.iter().find(|c| c.id == id)
    }

    /// The descriptor cut to `detail`. `Capability` needs `cap` and returns
    /// only that capability; `None` when it is not there.
    pub fn at_detail(&self, detail: Detail, cap: Option<&str>) -> Option<Descriptor> {
        match detail {
            Detail::Full => match cap {
                None => Some(self.clone()),
                Some(c) => {
                    let mut d = self.clone();
                    d.capabilities.retain(|x| x.id == c);
                    (!d.capabilities.is_empty()).then_some(d)
                }
            },
            Detail::Summary => {
                let mut d = self.clone();
                for c in &mut d.capabilities {
                    c.actions.clear();
                    c.events.clear();
                    c.streams.clear();
                    c.state = Value::Null;
                }
                Some(d)
            }
            Detail::Capability => {
                let mut d = self.clone();
                d.capabilities.retain(|x| Some(x.id.as_str()) == cap);
                let c = d.capabilities.first_mut()?;
                for a in c.actions.values_mut() {
                    a.params = Value::Null;
                    a.result = Value::Null;
                }
                for e in c.events.values_mut() {
                    e.data = Value::Null;
                }
                c.state = Value::Null;
                Some(d)
            }
        }
    }

    /// The effect of `cap.action`, if the descriptor has it.
    pub fn effect(&self, cap: &str, action: &str) -> Option<Effect> {
        self.capability(cap)?.actions.get(action).map(|a| a.effect)
    }
}

/// A capability or action name as it may appear in a tool name: ASCII
/// letters, digits and `-`, at least one. A harness joins the parts of a tool name with `_`
/// (docs/dev/spec/harness.md), so a name can never hold one.
pub fn valid_member_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

impl Descriptor {
    /// Refuses a capability or action name a tool name could not carry, so a
    /// tool name can never be split wrongly.
    pub fn check_names(&self) -> Result<(), String> {
        for c in &self.capabilities {
            if !valid_member_name(&c.id) {
                return Err(format!(
                    "capability name {:?}: letters, digits and - only, no _",
                    c.id
                ));
            }
            for a in c.actions.keys() {
                if !valid_member_name(a) {
                    return Err(format!(
                        "action name {:?} of capability {}: letters, digits and - only, no _",
                        a, c.id
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Word count of a summary; the spec asks for fewer than 60.
pub fn summary_words(s: &str) -> usize {
    s.split_whitespace().count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> Descriptor {
        serde_json::from_value(json!({
            "nerve": "0",
            "node": {"id": "n1", "name": "box", "platform": "linux", "arch": "x86_64",
                     "software": {"name": "nerve-node", "version": "x.y.z"}},
            "rev": 3,
            "summary": "A test box.",
            "capabilities": [{
                "id": "fs", "profile": "fs", "exposure": "off", "summary": "Files.",
                "actions": {"read": {"effect": "read", "params": {"type": "object"},
                                      "result": {"type": "object"}}},
                "x-future": 1
            }]
        }))
        .unwrap()
    }

    #[test]
    fn member_names() {
        assert!(valid_member_name("list-files"));
        assert!(valid_member_name("fs2"));
        assert!(!valid_member_name(""));
        assert!(!valid_member_name("list_files"));
        assert!(!valid_member_name("a.b"));
        assert!(!valid_member_name("ü"));
    }

    /// schemas/descriptor.schema.json says in a pattern what
    /// `valid_member_name` checks: letters, digits and `-`, at least one, and
    /// no upper bound on the length.
    #[test]
    fn the_published_schema_names_members_as_the_code_does() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/descriptor.schema.json"
        );
        let s: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let cap = &s["$defs"]["capability"]["properties"];
        let rule = "^[A-Za-z0-9-]+$";
        assert_eq!(cap["id"]["pattern"], rule);
        assert_eq!(cap["actions"]["propertyNames"]["pattern"], rule);
        assert!(valid_member_name(&"a".repeat(33)));
        assert!(valid_member_name(&"a".repeat(200)));
    }

    #[test]
    fn underscore_in_a_name_is_refused() {
        let mut d = sample();
        assert_eq!(d.check_names(), Ok(()));
        d.capabilities[0].id = "my_fs".into();
        let e = d.check_names().unwrap_err();
        assert!(e.contains("capability name") && e.contains("my_fs"), "{e}");
        let mut d = sample();
        let a = d.capabilities[0].actions.remove("read").unwrap();
        d.capabilities[0].actions.insert("read_all".into(), a);
        let e = d.check_names().unwrap_err();
        assert!(e.contains("action name") && e.contains("read_all"), "{e}");
    }

    #[test]
    fn details() {
        let d = sample();
        assert_eq!(d.effect("fs", "read"), Some(Effect::Read));
        let s = d.at_detail(Detail::Summary, None).unwrap();
        assert!(s.capabilities[0].actions.is_empty());
        let c = d.at_detail(Detail::Capability, Some("fs")).unwrap();
        assert!(c.capabilities[0].actions["read"].params.is_null());
        assert!(d.at_detail(Detail::Capability, Some("exec")).is_none());
        assert!(d.at_detail(Detail::Capability, None).is_none());
        let f = d.at_detail(Detail::Full, None).unwrap();
        assert_eq!(f, d);
        assert_eq!(f.capabilities[0].provider, "node");
    }
}
