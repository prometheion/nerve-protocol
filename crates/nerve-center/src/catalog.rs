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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde::Serialize;
use serde_json::{Value, json};

use nerve_proto::descriptor::bad_member_name;
use nerve_proto::schema::{self, Role};
use nerve_proto::{Descriptor, Effect};

use crate::listing::one_line;
use crate::tools::RESERVED_CAPS;
use crate::util;

/// The longest description a unit keeps, in bytes. A model needs a few
/// sentences, and a node's long text is not copied into every unit.
pub const DESCRIPTION_MAX: usize = 2048;

/// The longest capability or action name, in bytes: a node refuses a
/// longer one, and the center leaves out its capability or action.
pub use nerve_proto::descriptor::NAME_MAX;

/// One action a node offers, with schemas that passed the subset check.
#[derive(Debug, Clone, PartialEq)]
pub struct Unit {
    /// `cap.action`.
    pub name: String,
    pub cap: String,
    pub action: String,
    pub effect: Effect,
    /// What `list` tells of it: the action's own summary, else its
    /// capability's, on one line and cut at [`DESCRIPTION_MAX`]. Not both: a
    /// capability's summary speaks of all its actions ("stat, list, read …
    /// and write"), and a model shown it beside one action took that action
    /// to do them all. The units without a summary of their own share their
    /// capability's text.
    pub description: Arc<str>,
    /// Always an object schema: a descriptor without params takes any
    /// arguments, as the node does.
    pub params: Value,
    /// `null` when the descriptor states no result.
    pub result: Value,
    /// `node` for a built-in capability, else the provider's name, shared by
    /// the capability's units.
    pub provider: Arc<str>,
}

impl Unit {
    /// What the model was told of this unit, as one number: SHA-256 over
    /// its name, effect, description, params and result, cut to 53 bits so it
    /// is exact as a JSON number. `execute` compares it with the one `list`
    /// gave the session: a unit that changed must be listed again, while a
    /// rule, mode or `until` change on the node leaves it alone.
    pub fn hash(&self) -> u64 {
        let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
        // Each part with its length first, so no two units run together
        // into the same bytes. The schemas' keys are sorted (serde_json's
        // map), so the same schema gives the same text.
        for part in [
            self.name.clone(),
            self.effect.as_str().to_string(),
            self.description.to_string(),
            self.params.to_string(),
            self.result.to_string(),
        ] {
            ctx.update(&(part.len() as u64).to_be_bytes());
            ctx.update(part.as_bytes());
        }
        let d = ctx.finish();
        let mut first = [0u8; 8];
        first.copy_from_slice(&d.as_ref()[..8]);
        u64::from_be_bytes(first) & ((1 << 53) - 1)
    }
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
        // A capability id given twice would make `cap.action` name two
        // actions: `list` would show one and `execute` might check the
        // other. Neither is offered.
        let mut count: HashMap<&str, usize> = HashMap::new();
        for cap in &d.capabilities {
            *count.entry(cap.id.as_str()).or_default() += 1;
        }
        let mut left_out: HashSet<&str> = HashSet::new();
        for cap in &d.capabilities {
            if RESERVED_CAPS.contains(&cap.id.as_str()) {
                continue;
            }
            // A capability whose name is not offered is one entry, however
            // many actions it has: its name is never copied into each.
            let unnamed = bad_name("capability", &cap.id).or_else(|| {
                (count[cap.id.as_str()] > 1).then(|| "named twice in the description".to_string())
            });
            if let Some(reason) = unnamed {
                if left_out.insert(cap.id.as_str()) {
                    c.broken.push(Broken {
                        name: shown_name(&cap.id),
                        reason,
                    });
                }
                continue;
            }
            // A capability's event data and state are checked as well, so
            // every schema the node publishes keeps to the subset; one that
            // does not leaves out the whole capability.
            let whole = cap_outside_subset(cap);
            let cap_description = described(&cap.summary);
            let provider: Arc<str> = cap.provider.as_str().into();
            if cap.actions.is_empty()
                && let Some(reason) = whole.clone()
            {
                c.broken.push(Broken {
                    name: cap.id.clone(),
                    reason,
                });
            }
            for (action, def) in &cap.actions {
                if let Some(reason) = bad_name("action", action) {
                    c.broken.push(Broken {
                        name: format!("{}.{}", cap.id, shown_name(action)),
                        reason,
                    });
                    continue;
                }
                let name = format!("{}.{action}", cap.id);
                if let Some(reason) = whole.clone() {
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
                    description: match described(&def.summary) {
                        own if own.is_empty() => cap_description.clone(),
                        own => own,
                    },
                    params,
                    result: def.result.clone(),
                    provider: provider.clone(),
                });
            }
        }
        c.units.sort_by(|a, b| a.name.cmp(&b.name));
        c.broken.sort_by(|a, b| a.name.cmp(&b.name));
        c
    }

    /// The unit `name` (`cap.action`); none for a broken or unknown one.
    /// Found by halving: `execute` and `list` ask for units under the
    /// store's lock, and a node may offer many.
    pub fn unit(&self, name: &str) -> Option<&Unit> {
        self.units
            .binary_search_by(|u| u.name.as_str().cmp(name))
            .ok()
            .map(|i| &self.units[i])
    }

    /// Why `name` (`cap.action`) is left out, when it or its whole
    /// capability is.
    pub fn broken(&self, name: &str) -> Option<&Broken> {
        self.broken.iter().find(|b| {
            name.strip_prefix(b.name.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
        })
    }

    /// Whether `cap.action` is a unit, so it may be offered to the agent.
    pub fn offers(&self, cap: &str, action: &str) -> bool {
        self.unit(&format!("{cap}.{action}")).is_some()
    }
}

/// `summary` as a unit's description: one line, cut.
fn described(summary: &str) -> Arc<str> {
    util::clip(&one_line(summary), DESCRIPTION_MAX).into()
}

/// Names hold letters, digits, `-` and `_`: `.` joins a unit's name, so a
/// name with one could not be split again. The reason never repeats a long
/// name whole.
fn bad_name(what: &str, name: &str) -> Option<String> {
    bad_member_name(name).map(|why| format!("{what} {why}"))
}

/// A name left out as the owner sees it: on one line and cut.
fn shown_name(name: &str) -> String {
    util::clip(&one_line(name), NAME_MAX)
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
                description: "read it".into(),
                params: path(),
                result: Value::Null,
                provider: "node".into(),
            }
        );
        assert!(c.offers("fs", "write"));
        assert!(!c.offers("settings", "set"));
        assert!(c.unit("settings.set").is_none());
    }

    /// A name with `.` could not be split again, so it leaves out its own
    /// units only; `_` is a letter like the others. A capability with a bad
    /// name is left out as one entry.
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
                        ("list_all", Effect::Read, path()),
                    ],
                ),
                cap(
                    "exec",
                    "exec",
                    &[
                        ("run", Effect::Execute, path()),
                        ("run.all", Effect::Execute, path()),
                    ],
                ),
                cap("a.b", "", &[("go", Effect::Read, path())]),
            ],
        );
        let c = Catalog::build(&d);
        assert_eq!(
            names(&c),
            (
                vec!["exec.run", "my_fs.list_all", "my_fs.read"],
                vec!["a.b", "exec.run.all"]
            )
        );
        // The capability is one entry, and its actions are found under it.
        assert_eq!(c.broken("a.b.go"), Some(&c.broken[0]));
        assert_eq!(c.broken("a.bgo"), None);
        assert_eq!(
            c.broken[0].reason,
            "capability name \"a.b\": letters, digits, - and _ only"
        );
        assert_eq!(
            c.broken[1].reason,
            "action name \"run.all\": letters, digits, - and _ only"
        );
        assert_eq!(c.broken("exec.run.all"), Some(&c.broken[1]));
        assert_eq!(c.broken("exec.run"), None);
        assert!(c.offers("my_fs", "read"));
    }

    /// The bytes of names and reasons a catalog holds.
    fn footprint(c: &Catalog) -> usize {
        c.units
            .iter()
            .map(|u| u.name.len() + u.cap.len() + u.action.len())
            .chain(c.broken.iter().map(|b| b.name.len() + b.reason.len()))
            .sum()
    }

    /// A node's long name is not copied into each of its actions: the
    /// capability or action is left out with a short reason, so the catalog
    /// stays small however long the names and however many the actions.
    #[test]
    fn a_long_name_is_left_out_and_never_copied() {
        let many: Vec<(String, Effect, Value)> = (0..2000)
            .map(|i| (format!("a{i}"), Effect::Read, Value::Null))
            .collect();
        let actions: Vec<(&str, Effect, Value)> = many
            .iter()
            .map(|(n, e, p)| (n.as_str(), *e, p.clone()))
            .collect();
        let long = "c".repeat(16 * 1024);
        let mut bad = "d".repeat(16 * 1024);
        bad.push_str(".x\nmore");
        let edge = "e".repeat(NAME_MAX);
        let over = "f".repeat(NAME_MAX + 1);
        let long_action = "g".repeat(16 * 1024);
        let mut d = desc(
            "box",
            vec![
                cap(&long, "", &actions),
                cap(&bad, "", &actions),
                cap(&edge, "", &[("go", Effect::Read, Value::Null)]),
                cap(&over, "", &[("go", Effect::Read, Value::Null)]),
                cap("q\nr", "", &[("go", Effect::Read, Value::Null)]),
                cap(
                    "fs",
                    "fs",
                    &[
                        ("read", Effect::Read, path()),
                        (long_action.as_str(), Effect::Read, path()),
                        (edge.as_str(), Effect::Read, path()),
                    ],
                ),
            ],
        );
        // A long provider name is shared by its units, not copied.
        d.capabilities[5].provider = "p".repeat(16 * 1024);
        let c = Catalog::build(&d);
        assert_eq!(
            c.units.iter().map(|u| u.name.as_str()).collect::<Vec<_>>(),
            [format!("{edge}.go"), format!("fs.{edge}"), "fs.read".into()]
        );
        assert!(Arc::ptr_eq(&c.units[1].provider, &c.units[2].provider));
        assert_eq!(c.broken.len(), 5, "{:?}", names(&c).1);
        let reasons: Vec<&str> = c.broken.iter().map(|b| b.reason.as_str()).collect();
        assert!(
            reasons.contains(&"capability name of 16384 bytes: at most 64"),
            "{reasons:?}"
        );
        assert!(
            reasons.contains(&"capability name of 16391 bytes: at most 64"),
            "{reasons:?}"
        );
        assert!(
            reasons.contains(&"capability name of 65 bytes: at most 64"),
            "{reasons:?}"
        );
        assert!(
            reasons.contains(&"action name of 16384 bytes: at most 64"),
            "{reasons:?}"
        );
        for b in &c.broken {
            assert!(b.name.len() <= 2 * NAME_MAX + 4, "{}", b.name.len());
            assert!(!b.name.chars().any(char::is_control), "{:?}", b.name);
        }
        // The owner sees the start of a long name, on one line.
        let shown: Vec<&str> = c.broken.iter().map(|b| b.name.as_str()).collect();
        assert!(
            shown.contains(&format!("{}…", &over[..NAME_MAX]).as_str()),
            "{shown:?}"
        );
        assert!(shown.contains(&format!("fs.{}…", &long_action[..NAME_MAX]).as_str()));
        assert!(shown.contains(&"q r"), "{shown:?}");
        assert!(footprint(&c) < 4096, "{}", footprint(&c));
    }

    /// A capability id given twice names two declarations with one unit
    /// name: `list` would show one and `execute` might check the other's
    /// params. Neither is offered; the owner sees one entry.
    #[test]
    fn a_capability_named_twice_is_not_offered() {
        let level = json!({"type": "object", "properties": {"level": {"type": "integer"}}});
        let percent = json!({"type": "object", "properties": {"percent": {"type": "integer"}},
                             "required": ["percent"]});
        let d = desc(
            "box",
            vec![
                cap("lamp", "", &[("dim", Effect::Actuate, level)]),
                cap("fs", "fs", &[("read", Effect::Read, path())]),
                cap("lamp", "", &[("dim", Effect::Actuate, percent)]),
            ],
        );
        let c = Catalog::build(&d);
        assert_eq!(names(&c), (vec!["fs.read"], vec!["lamp"]));
        assert_eq!(c.broken[0].reason, "named twice in the description");
        assert!(c.unit("lamp.dim").is_none());
        assert_eq!(c.broken("lamp.dim"), Some(&c.broken[0]));
    }

    /// A unit's hash follows what `list` tells of it, and only that: the
    /// node's rules, its mode and the other units leave it alone.
    #[test]
    fn a_units_hash_changes_with_what_list_tells_of_it() {
        let d = desc(
            "box",
            vec![
                cap("fs", "fs", &[("read", Effect::Read, path())]),
                cap("exec", "exec", &[("run", Effect::Execute, path())]),
            ],
        );
        let hash = |d: &Descriptor| Catalog::build(d).unit("fs.read").unwrap().hash();
        let h = hash(&d);
        assert!(h < 1 << 53, "{h}");
        assert_eq!(hash(&d), h, "the same unit, the same hash");

        // A new revision of the descriptor (a rule edit, a mode change), a
        // change of another unit, and the capability's summary beside the
        // action's own (which `list` does not show) are not this unit's
        // business; nor is text past what the description keeps.
        let mut same = d.clone();
        same.rev = 7;
        same.summary = "now in folder mode".into();
        same.capabilities[1].actions.get_mut("run").unwrap().params = json!({"type": "object"});
        same.capabilities[0].summary = "Files.".into();
        assert_eq!(hash(&same), h);
        let long = "x".repeat(DESCRIPTION_MAX);
        let mut a = d.clone();
        a.capabilities[0].actions.get_mut("read").unwrap().summary = format!("{long}a");
        let mut b = d.clone();
        b.capabilities[0].actions.get_mut("read").unwrap().summary = format!("{long}b");
        assert_eq!(hash(&a), hash(&b));

        // Each thing `list` tells of it is.
        type Edit = fn(&mut Descriptor);
        let edits: [(&str, Edit); 5] = [
            ("params", |d| {
                d.capabilities[0].actions.get_mut("read").unwrap().params = json!({
                    "type": "object", "properties": {"path": {"type": "string"},
                    "max": {"type": "integer"}}, "required": ["path"]})
            }),
            ("result", |d| {
                d.capabilities[0].actions.get_mut("read").unwrap().result =
                    json!({"type": "string"})
            }),
            ("effect", |d| {
                d.capabilities[0].actions.get_mut("read").unwrap().effect = Effect::Write
            }),
            ("summary", |d| {
                d.capabilities[0].actions.get_mut("read").unwrap().summary = "Read.".into()
            }),
            (
                "the capability's summary, which it shows for want of its own",
                |d| d.capabilities[0].actions.get_mut("read").unwrap().summary = String::new(),
            ),
        ];
        for (what, edit) in edits {
            let mut changed = d.clone();
            edit(&mut changed);
            assert_ne!(hash(&changed), h, "{what}");
        }
        let mut bare = d.clone();
        bare.capabilities[0]
            .actions
            .get_mut("read")
            .unwrap()
            .summary = String::new();
        let mut files = bare.clone();
        files.capabilities[0].summary = "Files.".into();
        assert_ne!(
            hash(&bare),
            hash(&files),
            "the capability's summary it shows"
        );
    }

    /// Text moved from the end of one part to the start of the next is
    /// another unit: the hash takes each part with its length.
    #[test]
    fn a_units_hash_tells_where_one_part_ends() {
        let unit = |description: &str, params: Value| Unit {
            name: "fs.read".into(),
            cap: "fs".into(),
            action: "read".into(),
            effect: Effect::Read,
            description: description.into(),
            params,
            result: Value::Null,
            provider: "node".into(),
        };
        assert_ne!(unit("x1", json!(2)).hash(), unit("x", json!(12)).hash());
    }

    /// The units of a capability without summaries of their own share its
    /// summary, cut: a node's long text is kept once, not once per unit.
    #[test]
    fn a_long_summary_is_kept_once_and_cut() {
        let actions: Vec<(String, Effect, Value)> = (0..50)
            .map(|i| (format!("a{i}"), Effect::Read, json!({"type": "object"})))
            .collect();
        let refs: Vec<(&str, Effect, Value)> = actions
            .iter()
            .map(|(n, e, p)| (n.as_str(), *e, p.clone()))
            .collect();
        let mut big = cap("big", "big", &refs);
        big.summary = "y".repeat(100_000);
        for a in big.actions.values_mut() {
            a.summary = String::new();
        }
        big.actions.get_mut("a7").unwrap().summary = "z\n".repeat(100_000);
        let c = Catalog::build(&desc("box", vec![big]));
        assert_eq!(c.units.len(), 50);
        let first = &c.units[0].description;
        assert!(first.starts_with("yyy") && first.ends_with('…'), "{first}");
        assert_eq!(first.len(), DESCRIPTION_MAX + '…'.len_utf8());
        for u in &c.units {
            if u.action == "a7" {
                assert!(u.description.starts_with("z z "), "{}", u.description);
                assert!(u.description.len() <= DESCRIPTION_MAX + '…'.len_utf8());
            } else {
                assert!(Arc::ptr_eq(&u.description, first), "{}", u.name);
            }
        }
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
                exposure: None,
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

    /// Units are looked up under the store's lock, so finding one must not
    /// scan them all: with a hundred thousand units a scan each would take
    /// minutes.
    #[test]
    fn many_units_are_found_without_a_scan_each() {
        let units: Vec<Unit> = (0..100_000)
            .map(|i| Unit {
                name: format!("c{i:06}.a"),
                cap: format!("c{i:06}"),
                action: "a".into(),
                effect: Effect::Read,
                description: "".into(),
                params: Value::Null,
                result: Value::Null,
                provider: "".into(),
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
    /// unit the center left out of its own node would be a capability lost.
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
            let d = nerve_node::descriptor::for_center(
                &NodeConfig::default(),
                &e,
                &nerve_node::descriptor::Reach::of(&e, 0, None, true, None),
                &[],
            );
            let c = Catalog::build(&d);
            assert_eq!(c.broken, [], "{mode:?}");
            // In allowlist mode without rules the node offers nothing yet.
            if mode == nerve_policy::Mode::User {
                assert!(c.unit("exec.run").is_some() && c.unit("fs.read").is_some());
            }
        }
    }
}
