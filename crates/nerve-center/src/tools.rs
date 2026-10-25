//! MCP tools from node descriptors (docs/dev/spec/harness.md §2).
//!
//! - One tool per action, named `<cap>_<action>`. `_` only separates: node,
//!   capability and action names hold letters, digits and `-`, never `_`
//!   (`Descriptor::check_names`).
//! - A capability with a profile that several nodes offer with the same
//!   parameter schema becomes one tool with a required `node` argument, an
//!   enum of those nodes.
//! - A capability without a profile, or one whose schema differs between
//!   nodes, gets the node name as prefix: `<node>_<cap>_<action>`.
//! - Names stay within `^[a-zA-Z0-9_-]{1,64}$`.
//!
//! The built-in capabilities `node`, `settings` and `audit` are never tools:
//! they are the center's own business, and a harness that could call
//! `settings.set` would let a model change its own permissions. Nor is an
//! action the center leaves out of the node's catalog (a bad name, or a
//! schema outside the subset): the owner sees those in the overview.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use nerve_proto::{Descriptor, Effect, Exposure};

use crate::catalog::Catalog;

/// The center's own tool listing the nodes.
pub const NODES_TOOL: &str = "nodes";
/// Capabilities that are never offered as tools.
pub const RESERVED_CAPS: [&str; 3] = ["node", "settings", "audit"];
/// The argument that picks the node of a shared tool.
pub const NODE_ARG: &str = "node";
pub const NAME_MAX: usize = 64;

/// One paired node as the tool builder sees it.
pub struct NodeView<'a> {
    pub id: &'a str,
    /// The center's name for the node.
    pub name: &'a str,
    pub descriptor: &'a Descriptor,
    /// The descriptor as the center checked it: only its units are tools.
    pub catalog: &'a Catalog,
}

/// Where a tool call goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub node_id: String,
    pub node_name: String,
    pub cap: String,
    pub action: String,
    pub profile: String,
    pub effect: Effect,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Tool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub effect: Effect,
    /// Node name to route. A tool with `selector` takes the node from its
    /// `node` argument; one without has exactly one route.
    pub routes: BTreeMap<String, Route>,
    pub selector: bool,
}

impl Tool {
    /// The tool as MCP `tools/list` shows it.
    pub fn to_mcp(&self) -> Value {
        let read_only = matches!(self.effect, Effect::Read | Effect::Sense);
        json!({
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": {
                "readOnlyHint": read_only,
                "destructiveHint": !read_only,
                "openWorldHint": false,
            },
        })
    }
}

struct Entry<'a> {
    node: &'a NodeView<'a>,
    cap: &'a nerve_proto::Capability,
    action: &'a str,
    def: &'a nerve_proto::descriptor::Action,
}

/// All tools for `nodes`, sorted by name. `nodes` is not among them.
pub fn build(nodes: &[NodeView]) -> Vec<Tool> {
    // (profile, cap, action) to the nodes that offer it.
    let mut shared: BTreeMap<(String, String, String), Vec<Entry>> = BTreeMap::new();
    let mut single: Vec<Entry> = Vec::new();
    for node in nodes {
        for cap in &node.descriptor.capabilities {
            if RESERVED_CAPS.contains(&cap.id.as_str()) || cap.exposure == Exposure::Off {
                continue;
            }
            for (action, def) in &cap.actions {
                if !node.catalog.offers(&cap.id, action) {
                    continue;
                }
                let e = Entry {
                    node,
                    cap,
                    action,
                    def,
                };
                if cap.profile.is_empty() {
                    single.push(e);
                } else {
                    shared
                        .entry((cap.profile.clone(), cap.id.clone(), action.clone()))
                        .or_default()
                        .push(e);
                }
            }
        }
    }

    let mut tools = Vec::new();
    for ((_, cap, action), entries) in shared {
        let first = &entries[0];
        let same = entries
            .iter()
            .all(|e| e.def.params == first.def.params && e.def.effect == first.def.effect);
        let takes_node = first
            .def
            .params
            .get("properties")
            .and_then(|p| p.get(NODE_ARG))
            .is_some();
        if same && !takes_node {
            tools.push(shared_tool(&cap, &action, &entries));
        } else {
            single.extend(entries);
        }
    }
    for e in &single {
        tools.push(node_tool(e));
    }

    let mut taken: BTreeSet<String> = BTreeSet::from([NODES_TOOL.to_string()]);
    tools.sort_by(|a, b| a.name.cmp(&b.name));
    for t in &mut tools {
        t.name = unique(&t.name, &taken);
        taken.insert(t.name.clone());
    }
    tools.sort_by(|a, b| a.name.cmp(&b.name));
    tools
}

fn route(e: &Entry) -> Route {
    Route {
        node_id: e.node.id.to_string(),
        node_name: e.node.name.to_string(),
        cap: e.cap.id.clone(),
        action: e.action.to_string(),
        profile: e.cap.profile.clone(),
        effect: e.def.effect,
    }
}

fn describe(e: &Entry, nodes: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    for s in [e.cap.summary.trim(), e.def.summary.trim()] {
        if !s.is_empty() {
            parts.push(s.to_string());
        }
    }
    parts.push(format!(
        "Capability {}.{} (effect {}) on {nodes}.",
        e.cap.id,
        e.action,
        e.def.effect.as_str()
    ));
    parts.join(" ")
}

fn shared_tool(cap: &str, action: &str, entries: &[Entry]) -> Tool {
    let mut routes = BTreeMap::new();
    for e in entries {
        routes.insert(e.node.name.to_string(), route(e));
    }
    let names: Vec<&String> = routes.keys().collect();
    let mut schema = object_schema(&entries[0].def.params);
    if let Some(o) = schema.as_object_mut() {
        if let Some(p) = o
            .entry("properties")
            .or_insert_with(|| json!({}))
            .as_object_mut()
        {
            p.insert(
                NODE_ARG.into(),
                json!({"type": "string", "enum": names, "description": "The node to run this on."}),
            );
        }
        let req = o.entry("required").or_insert_with(|| json!([]));
        if let Some(a) = req.as_array_mut() {
            a.insert(0, json!(NODE_ARG));
        }
    }
    let list = names
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    Tool {
        name: sanitize(&format!("{cap}_{action}")),
        description: describe(&entries[0], &format!("the nodes {list}")),
        input_schema: schema,
        effect: entries[0].def.effect,
        routes,
        selector: true,
    }
}

fn node_tool(e: &Entry) -> Tool {
    let r = route(e);
    Tool {
        name: sanitize(&format!("{}_{}_{}", e.node.name, e.cap.id, e.action)),
        description: describe(e, &format!("the node {}", e.node.name)),
        input_schema: object_schema(&e.def.params),
        effect: e.def.effect,
        routes: BTreeMap::from([(e.node.name.to_string(), r)]),
        selector: false,
    }
}

/// MCP wants an object schema; a descriptor without params gets an empty one.
fn object_schema(params: &Value) -> Value {
    match params {
        Value::Object(o)
            if o.get("type").and_then(Value::as_str).unwrap_or("object") == "object" =>
        {
            let mut o = o.clone();
            o.insert("type".into(), json!("object"));
            Value::Object(o)
        }
        _ => json!({"type": "object", "properties": {}}),
    }
}

/// Replaces what the name pattern does not allow with `-` (`_` separates the
/// parts of a name, so it is not free) and keeps it within 64
/// characters; a long name keeps a hash of its full form so two long names
/// with the same start stay apart.
pub fn sanitize(name: &str) -> String {
    let clean: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    if clean.len() <= NAME_MAX {
        return if clean.is_empty() { "_".into() } else { clean };
    }
    let h = crate::util::sha256_hex(name.as_bytes());
    format!("{}_{}", &clean[..NAME_MAX - 9], &h[..8])
}

fn unique(name: &str, taken: &BTreeSet<String>) -> String {
    if !taken.contains(name) {
        return name.to_string();
    }
    for n in 2.. {
        let suffix = format!("_{n}");
        let base = &name[..name.len().min(NAME_MAX - suffix.len())];
        let candidate = format!("{base}{suffix}");
        if !taken.contains(&candidate) {
            return candidate;
        }
    }
    unreachable!()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use nerve_proto::Capability;
    use nerve_proto::descriptor::{Action, NodeInfo, Software};

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

    fn path_schema() -> Value {
        json!({"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]})
    }

    fn names(t: &[Tool]) -> Vec<&str> {
        t.iter().map(|t| t.name.as_str()).collect()
    }

    #[test]
    fn one_node_gets_cap_action_tools_with_a_node_argument() {
        let d = desc(
            "laptop",
            vec![
                cap("fs", "fs", &[("read", Effect::Read, path_schema())]),
                cap("audit", "audit", &[("list", Effect::Read, json!({}))]),
                cap("settings", "settings", &[("set", Effect::Write, json!({}))]),
            ],
        );
        let t = build(&[NodeView {
            id: "n1",
            name: "laptop",
            descriptor: &d,
            catalog: &Catalog::build(&d),
        }]);
        assert_eq!(names(&t), ["fs_read"]);
        let s = &t[0].input_schema;
        assert_eq!(s["properties"]["node"]["enum"], json!(["laptop"]));
        assert_eq!(s["required"], json!(["node", "path"]));
        assert_eq!(t[0].to_mcp()["annotations"]["readOnlyHint"], json!(true));
    }

    #[test]
    fn a_tool_is_named_cap_underscore_action() {
        let d = desc(
            "box",
            vec![cap(
                "exec",
                "exec",
                &[("run", Effect::Execute, json!({"type": "object"}))],
            )],
        );
        let t = build(&[NodeView {
            id: "1",
            name: "box",
            descriptor: &d,
            catalog: &Catalog::build(&d),
        }]);
        assert_eq!(names(&t), ["exec_run"]);
        // With a hyphen in the action, still one `_` between the parts.
        let d = desc(
            "box",
            vec![cap(
                "fs",
                "",
                &[("list-files", Effect::Read, json!({"type": "object"}))],
            )],
        );
        let t = build(&[NodeView {
            id: "1",
            name: "box",
            descriptor: &d,
            catalog: &Catalog::build(&d),
        }]);
        assert_eq!(names(&t), ["box_fs_list-files"]);
    }

    #[test]
    fn the_same_profile_on_two_nodes_is_one_tool() {
        let a = desc(
            "a",
            vec![cap("fs", "fs", &[("read", Effect::Read, path_schema())])],
        );
        let b = desc(
            "b",
            vec![cap("fs", "fs", &[("read", Effect::Read, path_schema())])],
        );
        let t = build(&[
            NodeView {
                id: "1",
                name: "a",
                descriptor: &a,
                catalog: &Catalog::build(&a),
            },
            NodeView {
                id: "2",
                name: "b",
                descriptor: &b,
                catalog: &Catalog::build(&b),
            },
        ]);
        assert_eq!(names(&t), ["fs_read"]);
        assert_eq!(
            t[0].input_schema["properties"]["node"]["enum"],
            json!(["a", "b"])
        );
        assert_eq!(t[0].routes["b"].node_id, "2");
    }

    #[test]
    fn differing_schemas_and_profileless_caps_get_node_prefixes() {
        let a = desc(
            "a",
            vec![
                cap("fs", "fs", &[("read", Effect::Read, path_schema())]),
                cap("lamp", "", &[("on", Effect::Actuate, Value::Null)]),
            ],
        );
        let b = desc(
            "b",
            vec![cap(
                "fs",
                "fs",
                &[("read", Effect::Read, json!({"type": "object"}))],
            )],
        );
        let t = build(&[
            NodeView {
                id: "1",
                name: "a",
                descriptor: &a,
                catalog: &Catalog::build(&a),
            },
            NodeView {
                id: "2",
                name: "b",
                descriptor: &b,
                catalog: &Catalog::build(&b),
            },
        ]);
        assert_eq!(names(&t), ["a_fs_read", "a_lamp_on", "b_fs_read"]);
        assert!(!t[0].selector);
        assert_eq!(
            t[1].input_schema,
            json!({"type": "object", "properties": {}})
        );
    }

    #[test]
    fn off_capabilities_are_not_tools() {
        let mut c = cap("exec", "exec", &[("run", Effect::Execute, json!({}))]);
        c.exposure = Exposure::Off;
        let d = desc("a", vec![c]);
        assert!(
            build(&[NodeView {
                id: "1",
                name: "a",
                descriptor: &d,
                catalog: &Catalog::build(&d),
            }])
            .is_empty()
        );
    }

    #[test]
    fn names_are_cleaned_cut_and_kept_unique() {
        assert_eq!(sanitize("a.b c"), "a-b-c");
        // `_` separates the parts of a name and is kept; nothing else becomes one.
        assert_eq!(sanitize("a_b:c"), "a_b-c");
        let long = "x".repeat(80);
        let s = sanitize(&long);
        assert_eq!(s.len(), NAME_MAX);
        assert_ne!(s, sanitize(&format!("{long}y")));
        let taken = BTreeSet::from(["t".to_string(), "t_2".to_string()]);
        assert_eq!(unique("t", &taken), "t_3");
        let full = "y".repeat(64);
        let u = unique(&full, &BTreeSet::from([full.clone()]));
        assert_eq!(u.len(), 64);
        assert!(u.ends_with("_2"));
        // Caps whose names would clean to the same tool name are left out
        // of the catalog, so they never get that far.
        let d = desc(
            "a",
            vec![
                cap("x.y", "", &[("go", Effect::Read, Value::Null)]),
                cap("x:y", "", &[("go", Effect::Read, Value::Null)]),
            ],
        );
        let t = build(&[NodeView {
            id: "1",
            name: "a",
            descriptor: &d,
            catalog: &Catalog::build(&d),
        }]);
        assert_eq!(names(&t), [] as [&str; 0]);
    }

    /// An action the catalog leaves out is no tool; the rest of its node and
    /// of its capability stay tools.
    #[test]
    fn broken_units_are_not_tools() {
        let one_of = json!({"type": "object", "properties": {"level": {"anyOf": [
            {"type": "integer"}, {"type": "null"}]}}});
        let d = desc(
            "a",
            vec![
                cap("fs", "fs", &[("read", Effect::Read, path_schema())]),
                cap(
                    "lamp",
                    "",
                    &[
                        ("dim", Effect::Actuate, one_of),
                        ("on", Effect::Actuate, Value::Null),
                    ],
                ),
                cap("my_box", "", &[("go", Effect::Read, Value::Null)]),
            ],
        );
        let c = Catalog::build(&d);
        assert_eq!(c.broken.len(), 2, "{:?}", c.broken);
        let t = build(&[NodeView {
            id: "1",
            name: "a",
            descriptor: &d,
            catalog: &c,
        }]);
        assert_eq!(names(&t), ["a_lamp_on", "fs_read"]);
    }

    /// Two nodes that differ only in how long a command may run are two
    /// tools, each with its own numbers in its text: one shared `exec_run`
    /// would state the first node's limits for both.
    #[test]
    fn nodes_with_other_run_time_limits_are_not_one_tool() {
        use nerve_policy::{CenterEntry, NodeConfig};
        let view = |cfg: &NodeConfig| {
            let mut e: CenterEntry = serde_json::from_value(json!({
                "name": "home", "url": "https://center.example", "center_id": "c1",
                "node_id": "n1"
            }))
            .unwrap();
            e.policy.mode = nerve_policy::Mode::User;
            nerve_node::descriptor::for_center(cfg, &e, 0, true, &[])
        };
        let mut long = NodeConfig::default();
        long.limits.max_timeout_secs = 86_400;
        let (build_node, lab, same) = (
            view(&NodeConfig::default()),
            view(&long),
            view(&NodeConfig::default()),
        );
        // The exec tools of two nodes; the fs tools are one either way.
        let exec = |a: &Descriptor, b: &Descriptor| {
            let mut t = build(&[
                NodeView {
                    id: "1",
                    name: "build",
                    descriptor: a,
                    catalog: &Catalog::build(a),
                },
                NodeView {
                    id: "2",
                    name: "lab",
                    descriptor: b,
                    catalog: &Catalog::build(b),
                },
            ]);
            t.retain(|t| t.name.ends_with("exec_run"));
            t
        };
        let t = exec(&build_node, &lab);
        assert_eq!(names(&t), ["build_exec_run", "lab_exec_run"]);
        assert!(t[0].description.contains("never runs longer than 1 h"));
        assert!(t[1].description.contains("never runs longer than 24 h"));
        let timeout = t[1].input_schema["properties"]["timeout_ms"]["description"]
            .as_str()
            .unwrap();
        assert!(timeout.contains("at most 86400000"), "{timeout}");
        // Equal limits stay one tool.
        assert_eq!(names(&exec(&build_node, &same)), ["exec_run"]);
    }

    #[test]
    fn a_schema_with_its_own_node_argument_is_not_merged() {
        let p = json!({"type": "object", "properties": {"node": {"type": "string"}}});
        let d = desc("a", vec![cap("fs", "fs", &[("read", Effect::Read, p)])]);
        let t = build(&[NodeView {
            id: "1",
            name: "a",
            descriptor: &d,
            catalog: &Catalog::build(&d),
        }]);
        assert_eq!(names(&t), ["a_fs_read"]);
    }
}
