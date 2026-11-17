//! Changes of the checker's settings as JSON, for the pages that post the
//! whole config with the version they read (`/api/checker`): the app's
//! Action checker page and the `checker` commands in the terminal
//! (crate::owner_calls). The center refuses a config when a change came in
//! between.

use serde_json::{Value, json};

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or_default()
}

fn list(v: &Value) -> &[Value] {
    v.as_array().map(Vec::as_slice).unwrap_or_default()
}

/// A machine's own switch as the config writes it: follows the center, on,
/// off.
pub const SWITCH_WORDS: [&str; 3] = ["inherit", "on", "off"];

/// The config with one of its three switches: 0 the blocklist, 1 the
/// model, 2 taint marking.
pub fn with_switch(config: &Value, which: i32, on: bool) -> Value {
    let mut c = config.clone();
    let key = ["blocklist_on", "model_on", "taint_on"][which.clamp(0, 2) as usize];
    c[key] = json!(on);
    c
}

/// The config with a new rule: for every machine (`nodes` empty), else one
/// for each machine named.
pub fn with_rule(config: &Value, skip: bool, rule: &str, note: &str, nodes: &[String]) -> Value {
    let mut c = config.clone();
    let key = if skip { "allow_rules" } else { "blocklist" };
    let entry = |node: Option<&String>| {
        let mut e = json!({"rule": rule.trim()});
        if !skip {
            e["on"] = json!(true);
            if !note.trim().is_empty() {
                e["note"] = json!(note.trim());
            }
        }
        if let Some(n) = node {
            e["node_id"] = json!(n);
        }
        e
    };
    let new: Vec<Value> = match nodes {
        [] => vec![entry(None)],
        some => some.iter().map(|n| entry(Some(n))).collect(),
    };
    match c[key].as_array_mut() {
        Some(l) => l.extend(new),
        None => c[key] = json!(new),
    }
    c
}

/// The config without the rule at `index`.
pub fn without_rule(config: &Value, skip: bool, index: usize) -> Value {
    let mut c = config.clone();
    let key = if skip { "allow_rules" } else { "blocklist" };
    if let Some(l) = c[key].as_array_mut()
        && index < l.len()
    {
        l.remove(index);
    }
    c
}

/// The config with the blocklist entry `index` on or off.
pub fn with_rule_on(config: &Value, index: usize, on: bool) -> Value {
    let mut c = config.clone();
    if let Some(e) = c["blocklist"].get_mut(index) {
        e["on"] = json!(on);
    }
    c
}

/// The config with the blocklist entry `index` counting on the machine
/// `node`, or switched off for it.
pub fn with_rule_where(config: &Value, index: usize, node: &str, on: bool) -> Value {
    let mut c = config.clone();
    if let Some(e) = c["blocklist"].get_mut(index) {
        let mut off: Vec<String> = list(&e["off_for"])
            .iter()
            .map(|n| s(n).to_string())
            .filter(|n| n != node)
            .collect();
        if !on {
            off.push(node.to_string());
            off.sort();
        }
        e["off_for"] = json!(off);
    }
    c
}

/// The config with a machine's own switch: `which` 0 the blocklist, 1 the
/// model; `value` 0 follows the center, 1 on, 2 off.
pub fn with_machine(config: &Value, node: &str, which: i32, value: i32) -> Value {
    let mut c = config.clone();
    if !c["nodes"].is_object() {
        c["nodes"] = json!({});
    }
    let key = if which == 0 { "blocklist" } else { "model" };
    let word = SWITCH_WORDS[value.clamp(0, 2) as usize];
    let n = &mut c["nodes"][node];
    if !n.is_object() {
        *n = json!({});
    }
    n[key] = json!(word);
    c
}

/// The config with the rule at `index` of the blocklist (or of the rules
/// that skip the model, `skip`) changed to `rule`, and for the blocklist
/// its note to `note` where one is given.
pub fn with_rule_text(
    config: &Value,
    skip: bool,
    index: usize,
    rule: &str,
    note: Option<&str>,
) -> Value {
    let mut c = config.clone();
    let key = if skip { "allow_rules" } else { "blocklist" };
    if let Some(e) = c[key].get_mut(index) {
        e["rule"] = json!(rule.trim());
        if let Some(n) = note.filter(|_| !skip) {
            e["note"] = json!(n.trim());
        }
    }
    c
}
