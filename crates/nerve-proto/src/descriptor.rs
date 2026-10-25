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
    /// `off` when the owner switched this action off while its capability
    /// stays on (`caps."fs.write" = "off"`): it is listed, and a call fails
    /// `disabled`. Absent means on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposure: Option<Exposure>,
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
    /// What this center may do on the node, and where (spec §6.2). Read
    /// tolerantly: a block the center cannot read is left out, and the
    /// rest of the descriptor stays.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lenient"
    )]
    pub access: Option<Access>,
}

/// A center's mode on a node (docs/user/modes.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessMode {
    Allowlist,
    Folder,
    User,
}

impl AccessMode {
    pub fn as_str(self) -> &'static str {
        match self {
            AccessMode::Allowlist => "allowlist",
            AccessMode::Folder => "folder",
            AccessMode::User => "user",
        }
    }
}

/// What one center may do on the node now, for that center only: its mode,
/// until when, the account its commands run as, and in `folder` mode the
/// folders it may use. No other center's grants are in it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Access {
    pub mode: AccessMode,
    /// When a `folder` or `user` mode ends and `allowlist` holds again, in
    /// milliseconds since the epoch; absent when it does not end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_ms: Option<u64>,
    /// The account this center's commands run as; absent when the node
    /// cannot name it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// In `folder` mode: whether the machine holds commands to the folders
    /// too, so `exec.run` is offered. Always false in the other modes.
    #[serde(default)]
    pub confined: bool,
    /// In `folder` mode: the folders the center's file calls and commands
    /// may use. Empty in the other modes, where folders decide nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub folders: Vec<FolderAccess>,
}

/// One folder of a center's grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderAccess {
    /// Absolute, in the center's path form (`/c/Users/x` for `C:\Users\x`).
    pub path: String,
    /// `r` (read), `w` (write) and `x` (run commands), each at most once,
    /// in that order.
    pub access: String,
}

impl FolderAccess {
    /// The flags as read, write and run, or `None` when `access` is not
    /// one to three of `r`, `w`, `x` in that order.
    pub fn flags(&self) -> Option<(bool, bool, bool)> {
        let mut rest = self.access.as_str();
        let mut take = |c: char| match rest.strip_prefix(c) {
            Some(r) => {
                rest = r;
                true
            }
            None => false,
        };
        let flags = (take('r'), take('w'), take('x'));
        (rest.is_empty() && flags != (false, false, false)).then_some(flags)
    }
}

/// An optional field read so that a value it cannot take is left out
/// rather than refusing the whole message.
fn lenient<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let v = Value::deserialize(d)?;
    Ok(serde_json::from_value(v).ok())
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

/// The longest capability or action name, in bytes. A center copies a
/// unit's name `cap.action` into every listing and a session's memory, and
/// a model has to type it.
pub const NAME_MAX: usize = 64;

/// A capability or action name: 1 to [`NAME_MAX`] ASCII letters, digits,
/// `-` and `_`. The center names a unit `cap.action`
/// (docs/dev/spec/harness.md), so a name can never hold a `.`.
pub fn valid_member_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= NAME_MAX
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Why `name` cannot name a capability or action, as `name …: …`. A long
/// name is not repeated, only its length.
pub fn bad_member_name(name: &str) -> Option<String> {
    if name.len() > NAME_MAX {
        return Some(format!("name of {} bytes: at most {NAME_MAX}", name.len()));
    }
    if !valid_member_name(name) {
        return Some(format!("name {name:?}: letters, digits, - and _ only"));
    }
    None
}

impl Descriptor {
    /// Refuses a capability or action name a unit's name could not carry,
    /// so `cap.action` can never be split wrongly.
    pub fn check_names(&self) -> Result<(), String> {
        for c in &self.capabilities {
            if let Some(why) = bad_member_name(&c.id) {
                return Err(format!("capability {why}"));
            }
            for a in c.actions.keys() {
                if let Some(why) = bad_member_name(a) {
                    return Err(format!("capability {}: action {why}", c.id));
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
        assert!(valid_member_name("list_files"));
        assert!(valid_member_name("_"));
        assert!(!valid_member_name(""));
        assert!(!valid_member_name("a.b"));
        assert!(!valid_member_name("ü"));
        assert!(valid_member_name(&"a".repeat(NAME_MAX)));
        assert!(!valid_member_name(&"a".repeat(NAME_MAX + 1)));
        assert_eq!(
            bad_member_name(&"a".repeat(1000)).unwrap(),
            "name of 1000 bytes: at most 64"
        );
        assert_eq!(bad_member_name("a_b-c"), None);
    }

    /// schemas/descriptor.schema.json says in a pattern what
    /// `valid_member_name` checks: 1 to 64 letters, digits, `-` and `_`.
    #[test]
    fn the_published_schema_names_members_as_the_code_does() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/descriptor.schema.json"
        );
        let s: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let cap = &s["$defs"]["capability"]["properties"];
        let rule = format!("^[A-Za-z0-9_-]{{1,{NAME_MAX}}}$");
        assert_eq!(cap["id"]["pattern"], rule.as_str());
        assert_eq!(cap["actions"]["propertyNames"]["pattern"], rule.as_str());
    }

    #[test]
    fn a_dot_in_a_name_is_refused_and_an_underscore_is_not() {
        let mut d = sample();
        assert_eq!(d.check_names(), Ok(()));
        d.capabilities[0].id = "my_fs".into();
        assert_eq!(d.check_names(), Ok(()));
        d.capabilities[0].id = "my.fs".into();
        let e = d.check_names().unwrap_err();
        assert!(e.contains("capability name") && e.contains("my.fs"), "{e}");
        let mut d = sample();
        let a = d.capabilities[0].actions.remove("read").unwrap();
        d.capabilities[0]
            .actions
            .insert("read_all".into(), a.clone());
        assert_eq!(d.check_names(), Ok(()));
        d.capabilities[0].actions.insert("read.all".into(), a);
        let e = d.check_names().unwrap_err();
        assert!(e.contains("action name") && e.contains("read.all"), "{e}");
        // A name over the bound is refused, and not repeated.
        let mut d = sample();
        d.capabilities[0].id = "f".repeat(NAME_MAX + 1);
        let e = d.check_names().unwrap_err();
        assert_eq!(e, "capability name of 65 bytes: at most 64");
        let mut d = sample();
        let a = d.capabilities[0].actions.remove("read").unwrap();
        d.capabilities[0]
            .actions
            .insert("r".repeat(NAME_MAX + 1), a);
        let e = d.check_names().unwrap_err();
        assert_eq!(e, "capability fs: action name of 65 bytes: at most 64");
    }

    /// The access block is read when it is well formed, and left out when
    /// it is not, with the rest of the descriptor kept.
    #[test]
    fn the_access_block_is_read_tolerantly() {
        let mut v = serde_json::to_value(sample()).unwrap();
        assert!(v.get("access").is_none());
        v["access"] = json!({"mode": "folder", "until_ms": 5, "account": "nerve-run",
                             "confined": true, "x-later": 1,
                             "folders": [{"path": "/c/Users/x", "access": "rw"}]});
        let d: Descriptor = serde_json::from_value(v.clone()).unwrap();
        let a = d.access.clone().unwrap();
        assert_eq!(a.mode, AccessMode::Folder);
        assert_eq!(a.until_ms, Some(5));
        assert_eq!(a.account.as_deref(), Some("nerve-run"));
        assert!(a.confined);
        assert_eq!(a.folders[0].flags(), Some((true, true, false)));
        let back = serde_json::to_value(&d).unwrap();
        assert_eq!(back["access"]["folders"][0]["path"], "/c/Users/x");
        for bad in [
            json!({"mode": "later"}),
            json!("folder"),
            json!({"mode": "user", "folders": 3}),
        ] {
            v["access"] = bad;
            let d: Descriptor = serde_json::from_value(v.clone()).unwrap();
            assert_eq!(d.access, None);
            assert_eq!(d.capabilities.len(), 1);
        }
        // Absent fields take their defaults.
        v["access"] = json!({"mode": "allowlist"});
        let d: Descriptor = serde_json::from_value(v).unwrap();
        let a = d.access.unwrap();
        assert_eq!((a.until_ms, a.account, a.confined), (None, None, false));
        assert!(a.folders.is_empty());
    }

    #[test]
    fn folder_flags_are_r_w_x_in_order() {
        let f = |a: &str| {
            FolderAccess {
                path: "/a".into(),
                access: a.into(),
            }
            .flags()
        };
        assert_eq!(f("rwx"), Some((true, true, true)));
        assert_eq!(f("r"), Some((true, false, false)));
        assert_eq!(f("wx"), Some((false, true, true)));
        for bad in ["", "xr", "rr", "rwxq", "R"] {
            assert_eq!(f(bad), None, "{bad}");
        }
    }

    /// An action switched off is marked so; one that is on carries nothing.
    #[test]
    fn an_action_says_when_it_is_off() {
        let mut d = sample();
        let a = d.capabilities[0].actions.get_mut("read").unwrap();
        assert!(serde_json::to_value(&*a).unwrap().get("exposure").is_none());
        a.exposure = Some(Exposure::Off);
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["capabilities"][0]["actions"]["read"]["exposure"], "off");
        let back: Descriptor = serde_json::from_value(v).unwrap();
        assert_eq!(back, d);
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
