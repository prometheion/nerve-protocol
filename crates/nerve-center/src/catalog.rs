//! What a node offers the agent, as the center checked it
//! (docs/dev/spec/protocol.md §6).
//!
//! The descriptor is the node's own word. The catalog is the center's reading
//! of it: one unit per action, named `cap.action`, whose names and schemas
//! the center can check, and the units it leaves out (broken), each with the
//! reason. One bad unit leaves out that unit only; the rest of the node stays
//! usable.
//!
//! The catalog is derived from the descriptor and never stored: it is built
//! again whenever the descriptor changes and after the state file is read.

use serde::Serialize;
use serde_json::{Value, json};

use nerve_proto::descriptor::valid_member_name;
use nerve_proto::schema::{self, Role};
use nerve_proto::{Descriptor, Effect};

use crate::tools::RESERVED_CAPS;

/// One action a node offers, with schemas that passed the subset check.
#[derive(Debug, Clone, PartialEq)]
pub struct Unit {
    /// `cap.action`.
    pub name: String,
    pub cap: String,
    pub action: String,
    pub effect: Effect,
    pub summary: String,
    /// Always an object schema: a descriptor without params takes any
    /// arguments, as the node does.
    pub params: Value,
    /// `null` when the descriptor states no result.
    pub result: Value,
    /// `node` for a built-in capability, else the provider's name.
    pub provider: String,
}

/// A unit the center leaves out, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Broken {
    /// `cap.action`, or the capability's id when a schema of a capability
    /// without actions is outside the subset.
    pub name: String,
    pub reason: String,
}

/// A node's units and the ones left out, both sorted by name. The built-in
/// capabilities `node`, `settings` and `audit` are in neither: they are the
/// center's own business, never the agent's.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Catalog {
    pub units: Vec<Unit>,
    pub broken: Vec<Broken>,
}

impl Catalog {
    pub fn build(d: &Descriptor) -> Catalog {
        let mut c = Catalog::default();
        for cap in &d.capabilities {
            if RESERVED_CAPS.contains(&cap.id.as_str()) {
                continue;
            }
            // A capability's event data and state are checked as well, so
            // every schema the node publishes keeps to the subset; one that
            // does not leaves out the whole capability.
            let whole = cap_outside_subset(cap);
            if cap.actions.is_empty()
                && let Some(reason) = whole.clone()
            {
                c.broken.push(Broken {
                    name: cap.id.clone(),
                    reason,
                });
            }
            for (action, def) in &cap.actions {
                let name = format!("{}.{action}", cap.id);
                if let Some(reason) = bad_name(&cap.id, action).or_else(|| whole.clone()) {
                    c.broken.push(Broken { name, reason });
                    continue;
                }
                let params = if def.params.is_null() {
                    json!({"type": "object"})
                } else {
                    def.params.clone()
                };
                if let Some(reason) = outside_subset(&params, &def.result) {
                    c.broken.push(Broken { name, reason });
                    continue;
                }
                c.units.push(Unit {
                    name,
                    cap: cap.id.clone(),
                    action: action.clone(),
                    effect: def.effect,
                    summary: def.summary.clone(),
                    params,
                    result: def.result.clone(),
                    provider: cap.provider.clone(),
                });
            }
        }
        c.units.sort_by(|a, b| a.name.cmp(&b.name));
        c.broken.sort_by(|a, b| a.name.cmp(&b.name));
        c
    }

    /// The unit `name` (`cap.action`); none for a broken or unknown one.
    /// Found by halving, since the tools are built by asking for each unit
    /// of every node, under the store's lock.
    pub fn unit(&self, name: &str) -> Option<&Unit> {
        self.units
            .binary_search_by(|u| u.name.as_str().cmp(name))
            .ok()
            .map(|i| &self.units[i])
    }

    /// Whether `cap.action` is a unit, so it may be offered to the agent.
    pub fn offers(&self, cap: &str, action: &str) -> bool {
        self.unit(&format!("{cap}.{action}")).is_some()
    }
}

/// Names hold letters, digits and `-`: `.` joins a unit's name and `_` a
/// tool's, so a name with either could not be split again.
fn bad_name(cap: &str, action: &str) -> Option<String> {
    if !valid_member_name(cap) {
        return Some(format!(
            "capability name {cap:?}: letters, digits and - only, no _"
        ));
    }
    if !valid_member_name(action) {
        return Some(format!(
            "action name {action:?}: letters, digits and - only, no _"
        ));
    }
    None
}

/// Why the state or an event's data of `cap` is outside the subset. Each
/// reason is brief, as on the node: it holds the node's own names, and the
/// Overview and the log repeat it.
fn cap_outside_subset(cap: &nerve_proto::Capability) -> Option<String> {
    if !cap.state.is_null()
        && let Err(e) = schema::check(&cap.state, Role::Result)
    {
        return Some(schema::brief(&format!("state: {e}")));
    }
    cap.events.iter().find_map(|(name, ev)| {
        if ev.data.is_null() {
            return None;
        }
        schema::check(&ev.data, Role::Result)
            .err()
            .map(|e| schema::brief(&format!("event {name}: {e}")))
    })
}

/// Why the schemas of an action are outside the subset the center checks
/// arguments with, in the words the node uses for its providers.
fn outside_subset(params: &Value, result: &Value) -> Option<String> {
    if let Err(e) = schema::check(params, Role::Params) {
        return Some(schema::brief(&format!("params: {e}")));
    }
    if !result.is_null()
        && let Err(e) = schema::check(result, Role::Result)
    {
        return Some(schema::brief(&format!("result: {e}")));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::tests::{cap, desc};

    fn path() -> Value {
        json!({"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]})
    }

    fn names(c: &Catalog) -> (Vec<&str>, Vec<&str>) {
        (
            c.units.iter().map(|u| u.name.as_str()).collect(),
            c.broken.iter().map(|b| b.name.as_str()).collect(),
        )
    }

    #[test]
    fn units_are_cap_dot_action_without_the_reserved_ones() {
        let d = desc(
            "box",
            vec![
                cap(
                    "fs",
                    "fs",
                    &[
                        ("read", Effect::Read, path()),
                        ("write", Effect::Write, path()),
                    ],
                ),
                cap("exec", "exec", &[("run", Effect::Execute, path())]),
                cap("settings", "settings", &[("set", Effect::Write, json!({}))]),
                cap("audit", "audit", &[("list", Effect::Read, json!({}))]),
                cap("node", "node", &[("ping", Effect::Read, json!({}))]),
            ],
        );
        let c = Catalog::build(&d);
        assert_eq!(names(&c), (vec!["exec.run", "fs.read", "fs.write"], vec![]));
        let u = c.unit("fs.read").unwrap();
        assert_eq!(
            u,
            &Unit {
                name: "fs.read".into(),
                cap: "fs".into(),
                action: "read".into(),
                effect: Effect::Read,
                summary: "read it".into(),
                params: path(),
                result: Value::Null,
                provider: "node".into(),
            }
        );
        assert!(c.offers("fs", "write"));
        assert!(!c.offers("settings", "set"));
        assert!(c.unit("settings.set").is_none());
    }

    #[test]
    fn a_bad_name_leaves_out_that_capability_only() {
        let d = desc(
            "box",
            vec![
                cap(
                    "my_fs",
                    "fs",
                    &[
                        ("read", Effect::Read, path()),
                        ("list", Effect::Read, path()),
                    ],
                ),
                cap(
                    "exec",
                    "exec",
                    &[
                        ("run", Effect::Execute, path()),
                        ("run_all", Effect::Execute, path()),
                    ],
                ),
                cap("a.b", "", &[("go", Effect::Read, path())]),
            ],
        );
        let c = Catalog::build(&d);
        assert_eq!(
            names(&c),
            (
                vec!["exec.run"],
                vec!["a.b.go", "exec.run_all", "my_fs.list", "my_fs.read"]
            )
        );
        assert_eq!(
            c.broken[2].reason,
            "capability name \"my_fs\": letters, digits and - only, no _"
        );
        assert_eq!(
            c.broken[1].reason,
            "action name \"run_all\": letters, digits and - only, no _"
        );
        assert!(!c.offers("my_fs", "read"));
    }

    #[test]
    fn a_schema_outside_the_subset_is_broken_with_its_reason() {
        let mut lamp = cap(
            "lamp",
            "",
            &[
                (
                    "dim",
                    Effect::Actuate,
                    json!({"type": "object", "properties": {"level": {"oneOf": [
                        {"type": "integer"}, {"type": "string"}]}}}),
                ),
                ("on", Effect::Actuate, Value::Null),
                ("off", Effect::Actuate, json!({"type": "object"})),
                ("state", Effect::Sense, json!({"type": "object"})),
                ("untyped", Effect::Actuate, json!({})),
            ],
        );
        lamp.actions.get_mut("off").unwrap().result = json!({"$ref": "#/x"});
        lamp.actions.get_mut("state").unwrap().result =
            json!({"type": "object", "properties": {"on": {"type": "boolean"}}});
        let c = Catalog::build(&desc("box", vec![lamp]));
        assert_eq!(
            names(&c),
            (
                vec!["lamp.on", "lamp.state"],
                vec!["lamp.dim", "lamp.off", "lamp.untyped"]
            )
        );
        let reason = |n: &str| {
            c.broken
                .iter()
                .find(|b| b.name == n)
                .unwrap()
                .reason
                .clone()
        };
        assert!(
            reason("lamp.dim").starts_with("params: /properties/level"),
            "{}",
            reason("lamp.dim")
        );
        assert!(
            reason("lamp.dim").contains("oneOf"),
            "{}",
            reason("lamp.dim")
        );
        assert!(
            reason("lamp.off").starts_with("result: "),
            "{}",
            reason("lamp.off")
        );
        assert!(
            reason("lamp.untyped").starts_with("params: "),
            "{}",
            reason("lamp.untyped")
        );
        // No params is any arguments, as on the node.
        assert_eq!(c.unit("lamp.on").unwrap().params, json!({"type": "object"}));
        assert_eq!(
            c.unit("lamp.state").unwrap().result["properties"]["on"],
            json!({"type": "boolean"})
        );
    }

    /// Event data and state are published schemas too: one outside the
    /// subset leaves out every action of its capability, and a capability
    /// without actions is named on its own.
    #[test]
    fn a_broken_event_or_state_leaves_out_its_capability() {
        let mut lamp = cap(
            "lamp",
            "",
            &[
                ("on", Effect::Actuate, json!({"type": "object"})),
                ("off", Effect::Actuate, json!({"type": "object"})),
            ],
        );
        lamp.state = json!({"$ref": "#/x"});
        let mut door = cap("door", "", &[("open", Effect::Actuate, path())]);
        door.events.insert(
            "opened".into(),
            nerve_proto::descriptor::EventDecl {
                summary: "It opened.".into(),
                implicit: false,
                data: json!({"oneOf": [{"type": "string"}]}),
            },
        );
        let mut bell = cap("bell", "", &[]);
        bell.events = door.events.clone();
        let mut fine = cap("fine", "", &[("go", Effect::Read, path())]);
        fine.state = json!({"type": "object", "properties": {"on": {"type": "boolean"}}});
        fine.events.insert(
            "went".into(),
            nerve_proto::descriptor::EventDecl {
                summary: "It went.".into(),
                implicit: false,
                data: json!({"type": "integer"}),
            },
        );
        let c = Catalog::build(&desc("box", vec![lamp, door, bell, fine]));
        assert_eq!(
            names(&c),
            (
                vec!["fine.go"],
                vec!["bell", "door.open", "lamp.off", "lamp.on"]
            )
        );
        let reason = |n: &str| {
            c.broken
                .iter()
                .find(|b| b.name == n)
                .unwrap()
                .reason
                .clone()
        };
        assert!(
            reason("lamp.on").starts_with("state: "),
            "{}",
            reason("lamp.on")
        );
        assert!(
            reason("door.open").starts_with("event opened: ")
                && reason("door.open").contains("oneOf"),
            "{}",
            reason("door.open")
        );
        assert_eq!(reason("bell"), reason("door.open"));
    }

    /// A reason holds the node's own names, so it is kept to one short line
    /// for the Overview and the log.
    #[test]
    fn a_reason_is_one_short_line() {
        let long = "/".repeat(4000);
        let mut lamp = cap(
            "lamp",
            "",
            &[(
                "dim",
                Effect::Actuate,
                json!({"type": "object", "properties": {
                    "x\nfake\u{1b}[2J": {"type": "string", "pattern": "a"}}}),
            )],
        );
        lamp.actions.insert(
            "get".into(),
            nerve_proto::descriptor::Action {
                effect: Effect::Read,
                summary: String::new(),
                params: Value::Null,
                result: json!({"type": "object", long.clone(): 1}),
            },
        );
        let mut door = cap("door", "", &[("open", Effect::Actuate, path())]);
        door.state = json!({"type": "object", long.clone(): 1});
        let mut bell = cap("bell", "", &[]);
        bell.events.insert(
            "rang".into(),
            nerve_proto::descriptor::EventDecl {
                summary: "It rang.".into(),
                implicit: false,
                data: json!({"type": "object", long: 1}),
            },
        );
        let c = Catalog::build(&desc("box", vec![lamp, door, bell]));
        assert_eq!(names(&c).1, ["bell", "door.open", "lamp.dim", "lamp.get"]);
        for b in &c.broken {
            assert!(!b.reason.chars().any(char::is_control), "{b:?}");
            assert!(
                b.reason.chars().count() <= schema::BRIEF_MAX + 1,
                "{}: {}",
                b.name,
                b.reason.len()
            );
        }
        assert!(
            c.broken[2]
                .reason
                .starts_with("params: /properties/x fake [2J/pattern"),
            "{:?}",
            c.broken
        );
    }

    /// The tools are built by asking for every unit of every node under the
    /// store's lock, so finding one must not scan them all: with a hundred
    /// thousand units a scan each would take minutes.
    #[test]
    fn many_units_are_found_without_a_scan_each() {
        let units: Vec<Unit> = (0..100_000)
            .map(|i| Unit {
                name: format!("c{i:06}.a"),
                cap: format!("c{i:06}"),
                action: "a".into(),
                effect: Effect::Read,
                summary: String::new(),
                params: Value::Null,
                result: Value::Null,
                provider: String::new(),
            })
            .collect();
        let c = Catalog {
            units,
            broken: Vec::new(),
        };
        let started = std::time::Instant::now();
        for u in &c.units {
            assert!(c.offers(&u.cap, &u.action));
        }
        assert!(!c.offers("c", "a"));
        assert!(c.unit("c050000.a").is_some());
        let took = started.elapsed();
        assert!(took < std::time::Duration::from_secs(5), "{took:?}");
    }

    /// The node's own descriptor, in every mode, is whole in the catalog: a
    /// unit the center left out of its own node would be a tool lost.
    #[test]
    fn the_nodes_own_descriptor_has_no_broken_unit() {
        use nerve_policy::{CenterEntry, NodeConfig};
        for mode in [
            nerve_policy::Mode::Allowlist,
            nerve_policy::Mode::Folder,
            nerve_policy::Mode::User,
        ] {
            let mut e: CenterEntry = serde_json::from_value(json!({
                "name": "home", "url": "https://center.example", "center_id": "c1",
                "node_id": "n1"
            }))
            .unwrap();
            e.policy.mode = mode;
            let d = nerve_node::descriptor::for_center(&NodeConfig::default(), &e, 0, true, &[]);
            let c = Catalog::build(&d);
            assert_eq!(c.broken, [], "{mode:?}");
            // In allowlist mode without rules the node offers nothing yet.
            if mode == nerve_policy::Mode::User {
                assert!(c.unit("exec.run").is_some() && c.unit("fs.read").is_some());
            }
        }
    }
}
