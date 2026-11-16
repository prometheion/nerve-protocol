//! What the center role's pages show, made from the center's web UI API
//! answers (`src/ui/app.js` of the center reads the same ones), and the
//! changes of the checker's settings the pages make before they post them.

use serde_json::{Value, json};
use slint::{ModelRc, SharedString, VecModel};

use crate::view::{ago, exact};
use crate::{
    HubAudit, HubCall, HubCap, HubCount, HubFigure, HubLog, HubMachine, HubNode, HubRule,
    HubSession, HubStatRow, HubToken, HubWhere, Tone,
};

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or_default()
}

fn strings(items: Vec<String>) -> ModelRc<SharedString> {
    ModelRc::new(VecModel::from(
        items
            .into_iter()
            .map(SharedString::from)
            .collect::<Vec<_>>(),
    ))
}

/// A count with its noun: "1 call", "1,284 calls".
fn count(n: u64, one: &str, many: &str) -> String {
    let n_text = with_commas(n);
    if n == 1 {
        format!("{n_text} {one}")
    } else {
        format!("{n_text} {many}")
    }
}

/// 1284 as "1,284".
pub fn with_commas(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn list(v: &Value) -> &[Value] {
    v.as_array().map(Vec::as_slice).unwrap_or_default()
}

/// The machines of `/api/overview`'s `nodes`, by name.
pub fn nodes(all: &Value, now_ms: u64) -> Vec<HubNode> {
    let mut nodes: Vec<HubNode> = list(all).iter().map(|n| node(n, now_ms)).collect();
    nodes.sort_by_key(|n| n.name.to_lowercase());
    nodes
}

fn node(n: &Value, now_ms: u64) -> HubNode {
    let online = n["online"] == true;
    let disabled = n["disabled"] == true;
    let (state, tone) = match (disabled, online) {
        (true, _) => ("disabled", Tone::Warn),
        (false, true) => ("online", Tone::Ok),
        (false, false) => ("offline", Tone::Neutral),
    };
    let link = match (online, n["since_ms"].as_u64(), n["last_seen_ms"].as_u64()) {
        (true, Some(since), _) => format!("Linked since {}", ago(since, now_ms)),
        (false, _, Some(seen)) if seen > 0 => format!("Last seen {}", ago(seen, now_ms)),
        _ => "Not linked yet".into(),
    };
    let offers: Vec<String> = list(&n["capabilities"])
        .iter()
        .filter(|c| c["offered"] == true)
        .map(|c| s(&c["id"]).to_string())
        .collect();
    let broken: Vec<String> = list(&n["broken"])
        .iter()
        .map(|b| {
            let name = s(&b["name"]);
            match b["reason"].as_str() {
                Some(r) if !r.is_empty() => format!("{name}: {r}"),
                _ => name.to_string(),
            }
        })
        .collect();
    let platform = s(&n["platform"]);
    HubNode {
        id: s(&n["id"]).into(),
        name: s(&n["name"]).into(),
        platform: match s(&n["arch"]) {
            "" => platform.to_string(),
            arch => format!("{platform}/{arch}"),
        }
        .into(),
        state: state.into(),
        tone,
        summary: s(&n["summary"]).into(),
        link: link.into(),
        folders: n["folders"]
            .as_u64()
            .map(|f| f.to_string())
            .unwrap_or_default()
            .into(),
        software: s(&n["software"]).into(),
        offers: strings(offers),
        settings_write: n["settings_write"] == true,
        windows: platform == "windows",
        broken: broken.join("; ").into(),
    }
}

/// "2 of 4 online", or "None paired".
pub fn nodes_count(all: &Value) -> String {
    let all = list(all);
    if all.is_empty() {
        return "None paired".into();
    }
    let online = all
        .iter()
        .filter(|n| n["online"] == true && n["disabled"] != true)
        .count();
    format!("{online} of {} online", all.len())
}

/// The sessions of `/api/overview`.
pub fn sessions(all: &Value, now_ms: u64) -> Vec<HubSession> {
    list(all)
        .iter()
        .map(|x| {
            let nodes: Vec<&str> = list(&x["nodes"]).iter().map(s).collect();
            let client = match s(&x["client"]) {
                "" => "A harness",
                c => c,
            };
            HubSession {
                id: s(&x["id"]).into(),
                client: client.into(),
                transport: s(&x["transport"]).into(),
                since: ago(x["started_ms"].as_u64().unwrap_or_default(), now_ms).into(),
                calls: count(x["calls"].as_u64().unwrap_or_default(), "call", "calls").into(),
                nodes: if nodes.is_empty() {
                    "None yet".to_string()
                } else {
                    nodes.join(", ")
                }
                .into(),
                tainted: x["tainted"] == true,
            }
        })
        .collect()
}

/// The harness tokens of `/api/tokens`.
pub fn tokens(all: &Value, now_ms: u64) -> Vec<HubToken> {
    list(all)
        .iter()
        .map(|t| HubToken {
            id: s(&t["id"]).into(),
            label: s(&t["label"]).into(),
            made: t["created_ms"]
                .as_u64()
                .map(|m| format!("Made {}", ago(m, now_ms)))
                .unwrap_or_default()
                .into(),
            settings: t["settings"] == true,
        })
        .collect()
}

/// How harnesses reach the center, from `/api/overview`'s `mcp`: over HTTP
/// (with its URL), else why not.
pub fn mcp(m: &Value) -> (bool, String, String) {
    match s(&m["mode"]) {
        "http" => (true, s(&m["url"]).to_string(), String::new()),
        "off" => (
            false,
            String::new(),
            "This center serves no MCP of its own. Turn it on in Settings › Center, MCP for harnesses.".into(),
        ),
        _ => (
            false,
            String::new(),
            "This center serves MCP to the harness that starts it. For harnesses over HTTP, set MCP for harnesses in Settings › Center.".into(),
        ),
    }
}

/// The Overview's line of how harnesses reach it.
pub fn mcp_line(m: &Value) -> String {
    match mcp(m) {
        (true, url, _) => format!("Harnesses at {url}"),
        _ if s(&m["mode"]) == "off" => "No MCP for harnesses".into(),
        _ => "Harnesses start it over stdio".into(),
    }
}

/// The lines a harness takes, with `token` in clear and hidden: the JSON of
/// an MCP settings file, the URL, the header and Claude Code's command.
pub fn connect_lines(url: &str, token: &str) -> (Vec<HubFigure>, Vec<HubFigure>) {
    let lines = |t: &str| {
        // In the order a person reads it: what, where, then the token.
        let json = format!(
            r#"{{"mcpServers":{{"nerve":{{"type":"http","url":{},"headers":{{"Authorization":{}}}}}}}}}"#,
            json!(url),
            json!(format!("Bearer {t}"))
        );
        [
            ("JSON", json),
            ("URL", url.to_string()),
            ("Header", format!("Authorization: Bearer {t}")),
            (
                "Claude Code",
                format!(
                    "claude mcp add --transport http nerve {url} --header \"Authorization: Bearer {t}\""
                ),
            ),
        ]
        .into_iter()
        .map(|(label, value)| HubFigure {
            label: label.into(),
            value: value.into(),
        })
        .collect::<Vec<_>>()
    };
    (lines(token), lines(&hidden(token)))
}

/// A secret with its start kept and the rest in dots.
pub fn hidden(token: &str) -> String {
    let start: String = token.chars().take(4).collect();
    format!("{start}{}", "•".repeat(22))
}

/// The Overview's line of the checker: "Blocklist on · model off".
pub fn checker_line(v: &Value) -> String {
    let c = &v["config"];
    let on = |b: bool| if b { "on" } else { "off" };
    format!(
        "Blocklist {} · model {}",
        on(c["blocklist_on"] != false),
        on(c["model_on"] == true)
    )
}

/// The ids and names of the machines, by name, as `/api/overview` lists
/// them.
pub fn names(all: &Value) -> Vec<(String, String)> {
    let mut n: Vec<(String, String)> = list(all)
        .iter()
        .map(|n| (s(&n["id"]).to_string(), s(&n["name"]).to_string()))
        .collect();
    n.sort_by_key(|(_, name)| name.to_lowercase());
    n
}

fn name_of(names: &[(String, String)], id: &str) -> String {
    names
        .iter()
        .find(|(i, _)| i == id)
        .map(|(_, n)| n.clone())
        .unwrap_or_else(|| id.to_string())
}

/// The blocklist (`skip` false) or the rules that skip the model, of
/// `/api/checker`: each with its place in the config's list.
pub fn rules(v: &Value, skip: bool, names: &[(String, String)]) -> Vec<HubRule> {
    let c = &v["config"];
    let key = if skip { "allow_rules" } else { "blocklist" };
    let stale: Vec<&str> = list(&v["stale"])
        .iter()
        .filter_map(|x| x["rule"].as_str().or(x.as_str()))
        .collect();
    list(&c[key])
        .iter()
        .enumerate()
        .map(|(i, r)| HubRule {
            rule: s(&r["rule"]).into(),
            note: s(&r["note"]).into(),
            on: skip || r["on"] != false,
            builtin: r["builtin"] == true,
            r#where: match r["node_id"].as_str() {
                Some(id) => name_of(names, id),
                None => "All machines".into(),
            }
            .into(),
            index: i as i32,
            stale: stale.contains(&s(&r["rule"])),
        })
        .collect()
}

/// Where the blocklist entry `index` counts: each machine, on unless it is
/// switched off for it.
pub fn rule_where(v: &Value, index: usize, names: &[(String, String)]) -> Vec<HubWhere> {
    let e = &v["config"]["blocklist"][index];
    let off: Vec<&str> = list(&e["off_for"]).iter().map(s).collect();
    names
        .iter()
        .map(|(id, name)| HubWhere {
            id: id.as_str().into(),
            name: name.as_str().into(),
            on: !off.contains(&id.as_str()),
        })
        .collect()
}

/// A machine's own switch: 0 follows the center, 1 on, 2 off.
fn switch_of(v: &Value) -> i32 {
    match s(v) {
        "on" => 1,
        "off" => 2,
        _ => 0,
    }
}

/// Each machine's own checker settings, by name.
pub fn machines(v: &Value, names: &[(String, String)]) -> Vec<HubMachine> {
    let own = &v["config"]["nodes"];
    names
        .iter()
        .map(|(id, name)| {
            let n = &own[id.as_str()];
            let (blocklist, model) = (switch_of(&n["blocklist"]), switch_of(&n["model"]));
            let word = |w: i32| ["", "on", "off"][w as usize];
            let mut parts = Vec::new();
            if blocklist != 0 {
                parts.push(format!("Blocklist {} here", word(blocklist)));
            }
            if model != 0 {
                parts.push(format!("Model {} here", word(model)));
            }
            let line = match parts.is_empty() {
                true => "Follows the center".to_string(),
                false => parts.join(", "),
            };
            HubMachine {
                id: id.as_str().into(),
                name: name.as_str().into(),
                line: line.into(),
                blocklist,
                model,
                note: s(&n["note"]).into(),
            }
        })
        .collect()
}

/// The decision model as the page shows it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Model {
    pub local: bool,
    pub line: String,
    pub tone: Tone,
    pub installed: bool,
    pub installing: bool,
    pub gpu: bool,
    pub supported: bool,
    pub gpu_hint: String,
    pub has_token: bool,
}

/// The decision model of `/api/checker`.
pub fn model(v: &Value) -> Model {
    let m = &v["config"]["model"];
    let local = s(&m["source"]) != "endpoint";
    let gpu = m["local_gpu"] == true;
    let installed = v["installed"] == true;
    let install = &v["install"];
    let installing = matches!(
        s(&install["state"]),
        "running" | "downloading" | "installing"
    );
    let running = v["local"]["running"] == true || s(&v["local"]["state"]) == "running";
    let device = if gpu { "GPU" } else { "CPU" };
    let (line, tone) = if !local {
        let url = s(&m["endpoint_url"]);
        (
            if url.is_empty() {
                "A model server, not set yet.".to_string()
            } else {
                format!("A model server at {url}.")
            },
            Tone::Accent,
        )
    } else if installing {
        (
            match s(&install["message"]) {
                "" => "Installing…".to_string(),
                m => format!("Installing: {m}"),
            },
            Tone::Accent,
        )
    } else if installed && running {
        (format!("Ready · {device}"), Tone::Ok)
    } else if installed {
        (format!("Installed · {device} · not running"), Tone::Warn)
    } else if s(&install["state"]) == "failed" {
        (
            format!("The install failed: {}", s(&install["message"])),
            Tone::Danger,
        )
    } else {
        ("Not installed".to_string(), Tone::Neutral)
    };
    Model {
        local,
        line,
        tone,
        installed,
        installing,
        gpu,
        supported: v["platform_supported"] != false,
        gpu_hint: s(&v["gpu_hint"]).to_string(),
        has_token: v["has_token"] == true,
    }
}

/// Rules of the config the center refused, or that name a call no machine
/// offers: one line, "" when there are none.
pub fn checker_warning(v: &Value) -> String {
    let n = |k: &str| v[k].as_array().map_or(0, Vec::len) as u64;
    match (n("rejected"), n("unpublished")) {
        (0, 0) => String::new(),
        (r, 0) => format!(
            "{} of the checker do not parse and count for nothing.",
            count(r, "rule", "rules")
        ),
        (_, u) => format!(
            "{} name a call no machine offers now.",
            count(u, "rule", "rules")
        ),
    }
}

// ---- Changes of the checker's settings ----
//
// The page posts the whole config with the version it read
// (`/api/checker`); the center refuses it when a change came in between.

pub use nerve_center::checker::edit::{
    with_machine, with_rule, with_rule_on, with_rule_where, with_switch, without_rule,
};

// ---- Capabilities ----

/// What a unit does, in the tone of its pill: sensing and acting on the
/// world stand out, as only the owner turns them on.
fn effect_tone(effect: &str) -> Tone {
    match effect {
        "sense" | "actuate" => Tone::Warn,
        "read" => Tone::Neutral,
        _ => Tone::Accent,
    }
}

/// The capabilities of `/api/caps`: offered, added by this center, left
/// out; and how many each group has.
pub fn caps(v: &Value) -> (Vec<HubCap>, [i32; 3]) {
    let added = list(&v["added"]["entries"]);
    let added_names: Vec<&str> = added.iter().map(|e| s(&e["name"])).collect();
    let mut out = Vec::new();
    for u in list(&v["units"]) {
        // One this center added shows in its own group.
        if added_names.contains(&s(&u["name"])) {
            continue;
        }
        let effect = s(&u["effect"]);
        out.push(HubCap {
            name: s(&u["name"]).into(),
            kind: effect.into(),
            tone: effect_tone(effect),
            source: s(&u["source"]).into(),
            text: s(&u["summary"]).into(),
            command: SharedString::new(),
            group: 0,
        });
    }
    for e in added {
        let effect = match s(&e["effect"]) {
            "" => s(&e["form"]["effect"]),
            x => x,
        };
        out.push(HubCap {
            name: s(&e["name"]).into(),
            kind: effect.into(),
            tone: effect_tone(effect),
            source: "this center".into(),
            text: s(&e["form"]["summary"]).into(),
            command: s(&e["form"]["command"]).into(),
            group: 1,
        });
    }
    for b in list(&v["broken"]) {
        out.push(HubCap {
            name: s(&b["name"]).into(),
            kind: "left out".into(),
            tone: Tone::Danger,
            source: "left out".into(),
            text: s(&b["reason"]).into(),
            command: SharedString::new(),
            group: 2,
        });
    }
    let mut counts = [0; 3];
    for c in &out {
        counts[c.group as usize] += 1;
    }
    (out, counts)
}

/// What the page says above a machine's capabilities: offline, read only,
/// or that it takes no capability from a center.
pub fn caps_note(v: &Value) -> String {
    if v["online"] == false {
        return "This machine is offline: the list is what it offered when it was last linked."
            .into();
    }
    if v["settings_write"] != true {
        return if s(&v["node"]["platform"]) == "windows" {
            "Read only: this machine has not let this center change its settings. Its owner lets it in the Nerve app on it: Centers, Settings grant.".into()
        } else {
            "Read only: this machine has not let this center change its settings. Its owner lets it with nerve-node center settings on.".into()
        };
    }
    match v["added"]["refused"].as_str() {
        Some(r) if !r.is_empty() => format!("This machine takes no capability from a center: {r}."),
        _ => String::new(),
    }
}

/// The form a new capability posts (`/api/caps/save`).
pub fn cap_form(name: &str, effect: i32, command: &str, summary: &str) -> Value {
    let effect = ["read", "write", "execute", "sense", "actuate"][effect.clamp(0, 4) as usize];
    json!({"name": name.trim(), "summary": summary.trim(), "effect": effect,
           "command": command.trim(), "params": "", "result": "", "timeout": "",
           "platform": "any"})
}

// ---- Statistics ----

fn calls_in(d: &Value) -> u64 {
    d["calls"]
        .as_object()
        .map(|c| c.values().map(|x| x["count"].as_u64().unwrap_or(0)).sum())
        .unwrap_or(0)
}

/// The Statistics list: every machine first, then each by name.
pub fn stat_rows(v: &Value) -> Vec<HubStatRow> {
    let mut rows = vec![HubStatRow {
        id: SharedString::new(),
        name: "All machines".into(),
        calls: count(calls_in(&v["total"]), "call", "calls").into(),
    }];
    if let Some(nodes) = v["nodes"].as_object() {
        let mut named: Vec<(&String, &Value)> = nodes.iter().collect();
        named.sort_by_key(|(n, _)| n.to_lowercase());
        for (name, d) in named {
            rows.push(HubStatRow {
                id: name.as_str().into(),
                name: name.as_str().into(),
                calls: count(calls_in(d), "call", "calls").into(),
            });
        }
    }
    rows
}

/// A span of time in days and hours: "6 d 4 h".
fn span(ms: u64) -> String {
    let h = ms / 3_600_000;
    match h {
        0 => format!("{} min", ms / 60_000),
        1..=47 => format!("{h} h"),
        _ => format!("{} d {} h", h / 24, h % 24),
    }
}

/// A duration in ms, or in s from ten of them.
fn millis(ms: u64) -> String {
    if ms >= 10_000 {
        format!("{} s", ms / 1000)
    } else {
        format!("{ms} ms")
    }
}

/// The figures, calls and errors of a row of the Statistics list: the
/// `total` (`name` ""), or a machine by its name.
pub fn stat_detail(v: &Value, name: &str) -> (Vec<HubFigure>, Vec<HubCall>, Vec<HubCount>) {
    let d = if name.is_empty() {
        &v["total"]
    } else {
        &v["nodes"][name]
    };
    let calls_of = d["calls"].as_object().cloned().unwrap_or_default();
    let all: u64 = calls_of
        .values()
        .map(|c| c["count"].as_u64().unwrap_or(0))
        .sum();
    let failed: u64 = calls_of
        .values()
        .map(|c| c["errors"].as_u64().unwrap_or(0))
        .sum();
    let figure = |label: &str, value: String| HubFigure {
        label: label.into(),
        value: value.into(),
    };
    let figures = vec![
        figure("Online", span(d["online_ms"].as_u64().unwrap_or(0))),
        figure("Links", with_commas(d["links"].as_u64().unwrap_or(0))),
        figure("Drops", with_commas(d["drops"].as_u64().unwrap_or(0))),
        figure("Calls", with_commas(all)),
        figure("Failed calls", with_commas(failed)),
    ];
    let mut calls: Vec<(String, Value)> = calls_of.into_iter().collect();
    calls.sort_by_key(|(_, c)| std::cmp::Reverse(c["count"].as_u64().unwrap_or(0)));
    let calls = calls
        .into_iter()
        .map(|(name, c)| {
            let n = c["count"].as_u64().unwrap_or(0);
            let e = c["errors"].as_u64().unwrap_or(0);
            let avg = c["total_ms"].as_u64().unwrap_or(0) / n.max(1);
            HubCall {
                name: name.into(),
                count: if e == 0 {
                    with_commas(n)
                } else {
                    format!("{}, {} failed", with_commas(n), with_commas(e))
                }
                .into(),
                time: format!(
                    "avg {}, max {}",
                    millis(avg),
                    millis(c["max_ms"].as_u64().unwrap_or(0))
                )
                .into(),
            }
        })
        .collect();
    let mut errors: Vec<(String, u64)> = d["errors"]
        .as_object()
        .map(|e| {
            e.iter()
                .map(|(k, v)| (k.replace('_', " "), v.as_u64().unwrap_or(0)))
                .collect()
        })
        .unwrap_or_default();
    errors.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    let errors = errors
        .into_iter()
        .map(|(name, n)| HubCount {
            name: name.into(),
            count: with_commas(n).into(),
        })
        .collect();
    (figures, calls, errors)
}

// ---- Audit ----

/// What the Audit page shows of the decisions: a decision (0 all, 1
/// allowed, 2 refused), words in the target and the reason, and a machine
/// by its id (`None` every one).
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    pub decision: i32,
    pub text: String,
    pub node: Option<String>,
}

fn refused(e: &Value) -> bool {
    s(&e["decision"]) == "forbidden"
}

fn audit_text(e: &Value) -> String {
    format!(
        "{} {} {} {}",
        s(&e["target"]),
        s(&e["reason"]),
        s(&e["checker"]["detail"]),
        s(&e["node"])
    )
    .to_lowercase()
}

/// Whether a target was cut to its start, so that no rule can name it.
fn cut(e: &Value) -> bool {
    let target = s(&e["target"]);
    let names_target = s(&e["cap"]) == "fs" || (s(&e["cap"]) == "exec" && s(&e["action"]) == "run");
    names_target && target.ends_with(" characters]") && target.contains("… [cut at ")
}

/// Whether a rule could name the entry's call: a command line or a path
/// needs its target whole; any other action is its own target.
fn known(e: &Value) -> bool {
    !s(&e["cap"]).is_empty()
        && !s(&e["action"]).is_empty()
        && !cut(e)
        && (!s(&e["target"]).is_empty() || !matches!(s(&e["cap"]), "exec" | "fs"))
}

/// A sudo command: only the machine's owner puts it on its allow list.
fn sudo(e: &Value) -> bool {
    s(&e["cap"]) == "exec"
        && s(&e["action"]) == "run"
        && s(&e["target"])
            .split_whitespace()
            .next()
            .is_some_and(|w| w == "sudo" || w.ends_with("/sudo"))
}

/// The arguments of the entry a rule may pin.
pub fn pins(e: &Value) -> Vec<(String, Value)> {
    e["args"]
        .as_object()
        .map(|a| a.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default()
}

/// A pin as its rule holds it: "field=value".
fn pin_text((k, v): &(String, Value)) -> String {
    match v {
        Value::String(t) => format!("{k}={}", t.replace('\\', "\\\\").replace(',', "\\,")),
        other => format!("{k}={other}"),
    }
}

/// The entries the filter lets through, newest first, each with its place
/// in `all`; and the counts of each decision under the other filters.
/// `settings_write` says of a machine by its id whether it gave this center
/// its settings grant, `None` for one no longer paired.
pub fn audit(
    all: &[Value],
    f: &AuditFilter,
    settings_write: &dyn Fn(&str) -> Option<bool>,
    now_ms: u64,
) -> (Vec<HubAudit>, [i32; 3]) {
    let text = f.text.trim().to_lowercase();
    let mut counts = [0; 3];
    let mut rows = Vec::new();
    for (i, e) in all.iter().enumerate().rev() {
        if f.node.as_deref().is_some_and(|n| s(&e["node_id"]) != n) {
            continue;
        }
        if !text.is_empty() && !audit_text(e).contains(&text) {
            continue;
        }
        let d = if refused(e) { 2 } else { 1 };
        counts[0] += 1;
        counts[d] += 1;
        if f.decision != 0 && f.decision as usize != d {
            continue;
        }
        rows.push(audit_row(e, i, settings_write(s(&e["node_id"])), now_ms));
    }
    (rows, counts)
}

fn audit_row(e: &Value, index: usize, write: Option<bool>, now_ms: u64) -> HubAudit {
    let by_checker = s(&e["by"]) == "action checker";
    let layer = s(&e["checker"]["layer"]);
    let refused = refused(e);
    let kind = match (refused, by_checker, layer) {
        (false, _, _) => "allowed",
        (true, true, "blocklist") => "blocklist",
        (true, true, _) => "checker",
        (true, false, _) => "refused",
    };
    let badge = match kind {
        "allowed" => "Allowed".to_string(),
        "blocklist" => "On the blocklist".to_string(),
        "checker" => "Refused by the action checker".to_string(),
        _ => match s(&e["by"]) {
            "" => "Refused by the machine".to_string(),
            by => format!("Refused by {by}"),
        },
    };
    let detail = if by_checker {
        let d = s(&e["checker"]["detail"]);
        let what = match layer {
            "model" => "Decision model",
            "allow rule" => "Skip the model",
            _ => "Blocklist",
        };
        match d {
            "" => String::new(),
            d => format!("{what}: {d}"),
        }
    } else {
        s(&e["reason"]).to_string()
    };
    let known = known(e);
    // The machine's rules need its settings grant; the checker's skip
    // rules are the center's own.
    let rules = !by_checker && known && write == Some(true);
    let trust = by_checker && refused && layer != "blocklist" && known;
    let rules_why = if by_checker {
        match layer {
            "blocklist" => {
                "On the blocklist: switch the rule off on the Action checker page.".to_string()
            }
            _ => String::new(),
        }
    } else if cut(e) {
        "The target was cut to its start, so no rule can name it.".into()
    } else {
        match write {
            None => "The machine is no longer paired.".into(),
            Some(false) => "This machine did not give this center the settings grant.".into(),
            Some(true) => String::new(),
        }
    };
    let ts = e["ts"].as_u64().unwrap_or_default();
    HubAudit {
        tone: match kind {
            "allowed" => Tone::Ok,
            "checker" => Tone::Warn,
            _ => Tone::Danger,
        },
        kind: kind.into(),
        call: format!("{}.{}", s(&e["cap"]), s(&e["action"])).into(),
        target: s(&e["target"]).into(),
        node: s(&e["node"]).into(),
        badge: badge.into(),
        detail: detail.into(),
        when: ago(ts, now_ms).into(),
        when_exact: exact(ts).into(),
        rules,
        rules_why: rules_why.into(),
        sudo: sudo(e),
        trust,
        pins: strings(pins(e).iter().map(pin_text).collect()),
        index: index as i32,
    }
}

/// The body of an audit entry's rule (`/api/audit/rule`, with its `list`)
/// or trust (`/api/checker/allow`), with the argument `pin` pinned (-1
/// none).
pub fn audit_body(e: &Value, list: Option<&str>, wildcard: bool, pin: i32) -> Value {
    let mut b = json!({"cap": e["cap"], "action": e["action"], "target": s(&e["target"]),
                       "wildcard": wildcard, "node_id": e["node_id"], "pin": null});
    if let Some(l) = list {
        b["list"] = json!(l);
    }
    if pin >= 0
        && let Some((field, value)) = pins(e).into_iter().nth(pin as usize)
    {
        b["pin"] = json!({"field": field, "value": value});
        b["wildcard"] = json!(false);
    }
    b
}

// ---- Log ----

/// How many log entries the page reads.
pub const LOG_LIMIT: usize = 500;

/// The log entries of `/api/log`, newest first.
pub fn log(v: &Value, now_ms: u64) -> Vec<HubLog> {
    list(&v["entries"])
        .iter()
        .map(|e| {
            let ts = e["ts"].as_u64().unwrap_or_default();
            let level = s(&e["level"]);
            HubLog {
                tone: match level {
                    "error" => Tone::Danger,
                    "warn" => Tone::Warn,
                    "info" => Tone::Accent,
                    _ => Tone::Neutral,
                },
                level: match level {
                    "error" => "Error",
                    "warn" => "Warning",
                    "info" => "Info",
                    "debug" => "Debug",
                    other => other,
                }
                .into(),
                msg: s(&e["msg"]).into(),
                node: s(&e["node"]).into(),
                when: ago(ts, now_ms).into(),
                when_exact: exact(ts).into(),
            }
        })
        .collect()
}

/// The query of the Log page: the problems only, words to find.
pub fn log_query(problems: bool, search: &str) -> String {
    let mut q = format!("/api/log?limit={LOG_LIMIT}");
    if problems {
        q.push_str("&level=warn");
    }
    let search = search.trim();
    if !search.is_empty() {
        q.push_str("&q=");
        q.push_str(&percent(search));
    }
    q
}

fn percent(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// A query parameter's value, for an id in a URL.
pub fn query_value(text: &str) -> String {
    percent(text)
}

// ---- Pairing ----

/// What the Pair a machine overlay shows of `/api/pair`: the link, the
/// command a Linux machine runs, and how long the code works.
pub fn pair(v: &Value, now_ms: u64) -> (String, String, String) {
    let link = s(&v["link"]).to_string();
    let left = v["expires_ms"].as_u64().unwrap_or(0).saturating_sub(now_ms);
    let until = format!(
        "The code works for one machine for {}.",
        match left / 60_000 {
            0 => "less than a minute".to_string(),
            1 => "1 minute".to_string(),
            m if m < 120 => format!("{m} minutes"),
            m => format!("{} hours", m / 60),
        }
    );
    (link, "nerve-node center add -".into(), until)
}

/// What the overlay says once a machine used the code (`/api/pair/status`).
pub fn paired(v: &Value) -> Option<String> {
    let n = v.get("node").filter(|n| n.is_object())?;
    let name = s(&n["name"]);
    Some(if s(&n["platform"]) == "windows" {
        format!("{name} is paired. Its owner sets what it allows in the Nerve app on it.")
    } else {
        format!("{name} is paired. Its owner sets what it allows with nerve-node on it.")
    })
}

// ---- Settings ----

/// The center key's pin, the new one of a rotation, a line on it, and
/// whether one runs, from `/api/center`'s `key`.
pub fn key(v: &Value, now_ms: u64) -> (String, String, String, bool) {
    let k = &v["key"];
    let pin = s(&k["pin"]).to_string();
    let r = &k["rotation"];
    let rotating = r.is_object() && r["finished_ms"].is_null();
    let next = s(&r["new_pin"]).to_string();
    let line = match (rotating, r["grace_until_ms"].as_u64()) {
        (false, _) => String::new(),
        (true, Some(until)) if until > now_ms => format!(
            "The machines move to the new key; the old one counts until {}.",
            exact(until)
        ),
        (true, _) => "The machines move to the new key.".into(),
    };
    (pin, next, line, rotating)
}

/// The commands of `/api/help`'s `center`, as the Help page lists them.
pub fn commands(v: &Value) -> Vec<(String, String)> {
    list(&v["center"]["commands"])
        .iter()
        .map(|c| (s(&c["name"]).to_string(), s(&c["line"]).to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use slint::Model;

    const NOW: u64 = 1_700_000_000_000;

    #[test]
    fn a_machine_shows_its_state_platform_and_what_it_offers() {
        let all = json!([
            {"id": "n2", "name": "office-pc", "platform": "windows", "arch": "x86_64", "online": false,
             "last_seen_ms": NOW - 3 * 3_600_000, "disabled": false, "capabilities": []},
            {"id": "n1", "name": "dev", "platform": "linux", "arch": "x86_64", "online": true,
             "since_ms": NOW - 60_000, "disabled": false, "folders": 2, "settings_write": true,
             "summary": "linux machine dev",
             "capabilities": [{"id": "fs", "offered": true}, {"id": "desk", "offered": false}],
             "broken": [{"name": "desk.click", "reason": "a schema outside the subset"}]},
            {"id": "n3", "name": "nas", "platform": "linux", "online": true, "disabled": true}
        ]);
        let n = nodes(&all, NOW);
        let names: Vec<&str> = n.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, ["dev", "nas", "office-pc"]);
        assert_eq!(
            (n[0].state.as_str(), n[0].tone, n[0].platform.as_str()),
            ("online", Tone::Ok, "linux/x86_64")
        );
        assert_eq!(n[0].link, "Linked since 1 min ago");
        assert_eq!(n[0].folders, "2");
        assert_eq!(n[0].offers.iter().collect::<Vec<_>>(), ["fs"]);
        assert_eq!(n[0].broken, "desk.click: a schema outside the subset");
        assert!(n[0].settings_write && !n[0].windows);
        assert_eq!((n[1].state.as_str(), n[1].tone), ("disabled", Tone::Warn));
        assert_eq!(n[2].link, "Last seen 3 h ago");
        assert!(n[2].windows);
        // A turned-off machine does not count as online.
        assert_eq!(nodes_count(&all), "1 of 3 online");
        assert_eq!(nodes_count(&json!([])), "None paired");
    }

    /// The token is hidden in every line until it is shown; each line
    /// holds it whole for its Copy.
    #[test]
    fn a_harness_takes_its_lines_with_the_token_hidden_until_shown() {
        let (clear, masked) = connect_lines("http://127.0.0.1:7481/mcp", "nrv_secret123");
        let labels: Vec<&str> = clear.iter().map(|f| f.label.as_str()).collect();
        assert_eq!(labels, ["JSON", "URL", "Header", "Claude Code"]);
        assert!(
            clear[0]
                .value
                .contains("\"Authorization\":\"Bearer nrv_secret123\"")
        );
        assert_eq!(clear[2].value, "Authorization: Bearer nrv_secret123");
        assert!(clear[3].value.starts_with(
            "claude mcp add --transport http nerve http://127.0.0.1:7481/mcp --header"
        ));
        for m in &masked {
            assert!(!m.value.contains("secret123"), "{}", m.value);
        }
        assert!(masked[2].value.starts_with("Authorization: Bearer nrv_••"));
    }

    #[test]
    fn the_checker_s_rules_and_switches_are_changed_in_its_config() {
        let names = vec![
            ("n1".to_string(), "dev".to_string()),
            ("n2".to_string(), "nas".to_string()),
        ];
        let v = json!({"config": {
            "blocklist_on": true, "model_on": false, "taint_on": true, "version": 4,
            "blocklist": [
                {"id": "rm", "rule": "exec.run:rm -rf *", "on": true, "builtin": true, "note": "Deletes whole trees"},
                {"rule": "lamp.set:room=office", "on": true, "node_id": "n2"}],
            "allow_rules": [{"rule": "exec.run:git status"}],
            "nodes": {"n2": {"model": "off"}}}});
        let block = rules(&v, false, &names);
        assert_eq!(block.len(), 2);
        assert_eq!(block[0].r#where, "All machines");
        assert!(block[0].builtin && block[0].on);
        assert_eq!(block[1].r#where, "nas");
        assert_eq!(rules(&v, true, &names)[0].rule, "exec.run:git status");
        assert_eq!(checker_line(&v), "Blocklist on · model off");
        let c = &v["config"];
        // A rule for chosen machines is one entry for each.
        let added = with_rule(
            c,
            false,
            " exec.run:shutdown * ",
            "Turns it off",
            &["n1".into(), "n2".into()],
        );
        let l = added["blocklist"].as_array().unwrap();
        assert_eq!(l.len(), 4);
        assert_eq!(
            l[2],
            json!({"rule": "exec.run:shutdown *", "on": true, "note": "Turns it off", "node_id": "n1"})
        );
        let skip = with_rule(c, true, "exec.run:ls *", "ignored", &[]);
        assert_eq!(skip["allow_rules"][1], json!({"rule": "exec.run:ls *"}));
        assert_eq!(without_rule(c, true, 0)["allow_rules"], json!([]));
        assert_eq!(with_rule_on(c, 0, false)["blocklist"][0]["on"], false);
        let off = with_rule_where(c, 0, "n1", false);
        assert_eq!(off["blocklist"][0]["off_for"], json!(["n1"]));
        let w = rule_where(&json!({ "config": off }), 0, &names);
        assert_eq!((w[0].on, w[1].on), (false, true));
        assert_eq!(
            with_rule_where(&off, 0, "n1", true)["blocklist"][0]["off_for"],
            json!([])
        );
        assert_eq!(with_switch(c, 1, true)["model_on"], true);
        assert_eq!(with_switch(c, 1, true)["version"], 4);
        let m = machines(&v, &names);
        assert_eq!(
            (m[0].line.as_str(), m[1].line.as_str()),
            ("Follows the center", "Model off here")
        );
        assert_eq!(m[1].model, 2);
        assert_eq!(
            with_machine(c, "n1", 0, 1)["nodes"]["n1"]["blocklist"],
            "on"
        );
        assert_eq!(
            with_machine(c, "n2", 1, 0)["nodes"]["n2"]["model"],
            "inherit"
        );
    }

    #[test]
    fn a_machine_s_capabilities_come_in_three_groups() {
        let v = json!({"online": true, "settings_write": true, "node": {"platform": "linux"},
            "units": [{"name": "exec.run", "effect": "execute", "source": "built-in", "summary": "Runs a command"},
                      {"name": "backup.db", "effect": "write", "source": "this center"}],
            "broken": [{"name": "desk.click", "reason": "a schema outside the subset"}],
            "added": {"entries": [{"name": "backup.db", "form": {"effect": "write", "command": "pg_dump site", "summary": "Backs up"}}]}});
        let (c, counts) = caps(&v);
        assert_eq!(counts, [1, 1, 1]);
        assert_eq!((c[0].name.as_str(), c[0].group), ("exec.run", 0));
        assert_eq!(
            (c[1].name.as_str(), c[1].group, c[1].command.as_str()),
            ("backup.db", 1, "pg_dump site")
        );
        assert_eq!((c[2].group, c[2].tone), (2, Tone::Danger));
        assert_eq!(caps_note(&v), "");
        let read_only =
            json!({"online": true, "settings_write": false, "node": {"platform": "windows"}});
        assert!(caps_note(&read_only).contains("Nerve app"));
    }

    #[test]
    fn statistics_sum_the_calls_of_every_machine() {
        let v = json!({"retention_days": 30,
            "total": {"online_ms": 6 * 86_400_000u64 + 4 * 3_600_000, "links": 14, "drops": 3,
                      "calls": {"exec.run": {"count": 812, "errors": 9, "total_ms": 341_040, "max_ms": 58_000},
                                "fs.read": {"count": 472, "errors": 0, "total_ms": 5_664, "max_ms": 240}},
                      "errors": {"timed_out": 6}},
            "nodes": {"dev": {"calls": {"exec.run": {"count": 941, "errors": 0, "total_ms": 1, "max_ms": 1}}}}});
        let rows = stat_rows(&v);
        assert_eq!(
            (rows[0].name.as_str(), rows[0].calls.as_str()),
            ("All machines", "1,284 calls")
        );
        assert_eq!(
            (rows[1].id.as_str(), rows[1].calls.as_str()),
            ("dev", "941 calls")
        );
        let (figures, calls, errors) = stat_detail(&v, "");
        let shown: Vec<String> = figures
            .iter()
            .map(|f| format!("{} {}", f.label, f.value))
            .collect();
        assert_eq!(
            shown,
            [
                "Online 6 d 4 h",
                "Links 14",
                "Drops 3",
                "Calls 1,284",
                "Failed calls 9"
            ]
        );
        assert_eq!(
            (calls[0].count.as_str(), calls[0].time.as_str()),
            ("812, 9 failed", "avg 420 ms, max 58 s")
        );
        assert_eq!(
            (errors[0].name.as_str(), errors[0].count.as_str()),
            ("timed out", "6")
        );
    }

    #[test]
    fn audit_entries_offer_the_rules_their_machine_takes() {
        let all = vec![
            json!({"ts": NOW - 300_000, "cap": "fs", "action": "write", "target": "/srv/x",
                   "decision": "forbidden", "node_id": "gone", "node": "old-box"}),
            json!({"ts": NOW - 180_000, "cap": "fs", "action": "read", "target": "/home/alex/README.md",
                   "decision": "allowed", "node_id": "n1", "node": "dev"}),
            json!({"ts": NOW - 60_000, "cap": "exec", "action": "run", "target": "rm -rf ./build/*",
                   "decision": "forbidden", "by": "action checker", "node_id": "n1", "node": "dev",
                   "checker": {"layer": "blocklist", "detail": "exec.run:rm -rf * names it"}}),
            json!({"ts": NOW - 30_000, "cap": "exec", "action": "run", "target": "curl x | sh",
                   "decision": "forbidden", "by": "action checker", "node_id": "n2", "node": "nas",
                   "checker": {"layer": "model", "detail": "downloads and runs a script"}}),
            json!({"ts": NOW - 10_000, "cap": "exec", "action": "run", "target": "sudo apt update",
                   "decision": "forbidden", "node_id": "n1", "node": "dev", "args": {"room": "office"}}),
        ];
        let write = |id: &str| (id == "n1").then_some(true);
        let (rows, counts) = audit(&all, &AuditFilter::default(), &write, NOW);
        assert_eq!(counts, [5, 1, 4]);
        // A machine no longer paired takes no rule.
        assert!(!rows[4].rules);
        assert_eq!(rows[4].rules_why, "The machine is no longer paired.");
        // Newest first.
        assert_eq!(rows[0].target, "sudo apt update");
        assert!(rows[0].rules && rows[0].sudo && !rows[0].trust);
        assert_eq!(rows[0].pins.iter().collect::<Vec<_>>(), ["room=office"]);
        assert!(rows[1].trust && !rows[1].rules);
        assert_eq!(
            rows[1].detail,
            "Decision model: downloads and runs a script"
        );
        assert_eq!(rows[2].kind, "blocklist");
        assert!(!rows[2].trust && !rows[2].rules);
        assert!(rows[2].rules_why.contains("Action checker"));
        let f = AuditFilter {
            decision: 1,
            ..Default::default()
        };
        assert_eq!(audit(&all, &f, &write, NOW).0.len(), 1);
        let f = AuditFilter {
            text: "BUILD".into(),
            ..Default::default()
        };
        assert_eq!(audit(&all, &f, &write, NOW).1, [1, 0, 1]);
        let f = AuditFilter {
            node: Some("n2".into()),
            ..Default::default()
        };
        let (rows, _) = audit(&all, &f, &write, NOW);
        assert_eq!(rows[0].node, "nas");
        let b = audit_body(&all[4], Some("deny"), true, 0);
        assert_eq!(b["pin"], json!({"field": "room", "value": "office"}));
        assert_eq!(
            (b["wildcard"].clone(), b["list"].clone()),
            (json!(false), json!("deny"))
        );
    }

    #[test]
    fn the_log_reads_the_problems_and_the_words_asked_for() {
        assert_eq!(log_query(false, ""), "/api/log?limit=500");
        assert_eq!(
            log_query(true, " link up "),
            "/api/log?limit=500&level=warn&q=link%20up"
        );
        let v = json!({"entries": [{"ts": NOW - 120_000, "level": "warn", "msg": "link dropped", "node": "dev"}]});
        let l = log(&v, NOW);
        assert_eq!(
            (l[0].level.as_str(), l[0].tone, l[0].node.as_str()),
            ("Warning", Tone::Warn, "dev")
        );
        assert_eq!(l[0].when, "2 min ago");
    }

    #[test]
    fn the_pairing_says_its_link_and_how_long_its_code_works() {
        let v = json!({"link": "nerve://pair?center=x&code=abc", "expires_ms": NOW + 15 * 60_000});
        let (link, command, until) = pair(&v, NOW);
        assert_eq!(link, "nerve://pair?center=x&code=abc");
        assert_eq!(command, "nerve-node center add -");
        assert_eq!(until, "The code works for one machine for 15 minutes.");
        assert_eq!(paired(&json!({"open": true, "node": null})), None);
        let done = paired(&json!({"open": false, "node": {"name": "dev", "platform": "linux"}}));
        assert!(done.unwrap().starts_with("dev is paired"));
    }
}
