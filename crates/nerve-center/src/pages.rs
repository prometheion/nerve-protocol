//! The owner's commands in the terminal for the rest of what the web UI's
//! and the app's pages do (owner, 2026-11-16: nothing is GUI-only):
//! `sessions`, `checker`, `caps`, `stats`, `audit`, `key`, `config`, and
//! `nodes rename|settings|sudo`. Each asks the running center over its
//! local owner channel with the pages' own calls (crate::owner_calls), so it
//! takes the same checks and leaves the same log lines.

use std::io::Read;
use std::path::Path;

use serde_json::{Value, json};

use nerve_service::out::{Page, Tone};

use crate::checker::edit;
use crate::config::{
    AuditCmd, AuditRule, CapsCmd, CheckerCmd, CheckerSwitch, KeyCmd, ModelCmd, NodesCmd, RuleCmd,
    SessionsCmd,
};

/// The running center in a state folder, asked as its owner.
pub(crate) struct Ask<'a> {
    pub state: &'a Path,
    pub installed: bool,
}

impl Ask<'_> {
    async fn get(&self, target: &str) -> Result<Value, String> {
        crate::owner_calls::call(self.state, self.installed, "GET", target, json!({})).await
    }

    async fn post(&self, path: &str, body: Value) -> Result<Value, String> {
        crate::owner_calls::call(self.state, self.installed, "POST", path, body).await
    }

    /// The id of the paired machine `name`.
    async fn node(&self, name: &str) -> Result<String, String> {
        crate::owner_calls::node_id(&self.get("/api/overview").await?, name)
    }
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or_default()
}

fn list(v: &Value) -> &[Value] {
    v.as_array().map(Vec::as_slice).unwrap_or_default()
}

/// `text` cut to `max` characters for a column, with `…` where it was cut.
fn cut(text: &str, max: usize) -> String {
    match text.chars().count() > max {
        true => text.chars().take(max - 1).chain(['…']).collect(),
        false => text.to_string(),
    }
}

/// `n things`, one thing.
fn count(n: usize, one: &str, more: &str) -> String {
    match n {
        1 => format!("1 {one}"),
        n => format!("{n} {more}"),
    }
}

/// A value for a URL's query.
fn query(v: &str) -> String {
    v.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            b => format!("%{b:02X}"),
        })
        .collect()
}

/// Reads `-`'s value from stdin: its first line, or all of it (`whole`).
fn from_stdin(whole: bool) -> Result<String, String> {
    let mut text = String::new();
    match whole {
        true => std::io::stdin()
            .read_to_string(&mut text)
            .map_err(|e| format!("cannot read stdin: {e}"))?,
        false => std::io::stdin()
            .read_line(&mut text)
            .map_err(|e| format!("cannot read stdin: {e}"))?,
    };
    Ok(match whole {
        true => text,
        false => text.trim_end_matches(['\r', '\n']).to_string(),
    })
}

// ---- nodes rename | settings | sudo ----

/// Whether `cmd` is one of the `nodes` commands here, which change or show
/// one machine.
pub(crate) fn touches_one(cmd: &NodesCmd) -> bool {
    matches!(
        cmd,
        NodesCmd::Rename { .. } | NodesCmd::Settings { .. } | NodesCmd::Sudo { .. }
    )
}

/// `nodes rename`, `nodes settings` and `nodes sudo`: the line it says and
/// what it shows, or `None` for the other `nodes` commands.
pub(crate) async fn nodes(ask: &Ask<'_>, cmd: &NodesCmd) -> Result<Option<Page>, String> {
    match cmd {
        NodesCmd::Rename { name, new_name } => {
            let id = ask.node(name).await?;
            ask.post("/api/nodes/rename", json!({"id": id, "name": new_name}))
                .await?;
            let mut p = crate::service::page().state("renamed", Tone::Good);
            p.row("Machine", format!("{name} is now {new_name}"));
            Ok(Some(p))
        }
        NodesCmd::Settings { name, from } => {
            let id = ask.node(name).await?;
            let target = format!("/api/nodes/settings?id={}", query(&id));
            let now = ask.get(&target).await?;
            let Some(from) = from else {
                // The JSON alone, for a file to edit and give back.
                let mut p = crate::service::page().state(
                    format!("settings of {name}, version {}", now["version"]),
                    Tone::Plain,
                );
                p.note(serde_json::to_string_pretty(&now["document"]).unwrap_or_default());
                p.next(
                    "Change them",
                    format!("nerve-center nodes settings {name} --from <file>"),
                );
                return Ok(Some(p));
            };
            let text = match from.as_os_str() == "-" {
                true => from_stdin(true)?,
                false => {
                    std::fs::read_to_string(from).map_err(|e| format!("{}: {e}", from.display()))?
                }
            };
            let document: Value =
                serde_json::from_str(&text).map_err(|e| format!("not valid JSON: {e}"))?;
            let saved = ask
                .post(
                    "/api/nodes/settings",
                    json!({"id": id, "document": document, "if_version": now["version"]}),
                )
                .await?;
            let mut p = crate::service::page().state("saved", Tone::Good);
            p.row("Machine", name.as_str());
            p.row("Version", saved["version"].to_string());
            Ok(Some(p))
        }
        NodesCmd::Sudo { name, state } => {
            let id = ask.node(name).await?;
            let on = state == "on";
            let body = match on {
                false => json!({"id": id, "on": false}),
                true => {
                    let offer = ask.post("/api/nodes/sudo/offer", json!({"id": id})).await?;
                    let offer: nerve_transport::sudo::Offer = serde_json::from_value(offer)
                        .map_err(|e| format!("the machine's offer: {e}"))?;
                    let password =
                        nerve_service::prompt::secret(&format!("The sudo password of {name}: "))?;
                    let sealed =
                        nerve_transport::sudo::seal(&offer, &password, crate::util::now_ms())?;
                    json!({"id": id, "on": true, "sealed": sealed})
                }
            };
            let v = ask.post("/api/nodes/sudo", body).await?;
            let now_on = v["sudo"] == "on";
            let mut p = crate::service::page().state(
                match now_on {
                    true => "sudo on",
                    false => "sudo off",
                },
                Tone::Good,
            );
            p.row("Machine", name.as_str());
            if now_on {
                p.note("The sudo list's commands run with sudo there.");
            }
            Ok(Some(p))
        }
        _ => Ok(None),
    }
}

// ---- sessions ----

/// `sessions` and `sessions end`.
pub(crate) async fn sessions(ask: &Ask<'_>, cmd: Option<&SessionsCmd>) -> Result<Page, String> {
    let mut said = None;
    if let Some(SessionsCmd::End { id }) = cmd {
        ask.post("/api/sessions/end", json!({"id": id})).await?;
        said = Some(format!("ended the session {id}"));
    }
    let overview = ask.get("/api/overview").await?;
    let now = crate::util::now_ms();
    let rows: Vec<Vec<String>> = list(&overview["sessions"])
        .iter()
        .map(|x| {
            let since = nerve_transport::log::span(std::time::Duration::from_millis(
                now.saturating_sub(x["started_ms"].as_u64().unwrap_or(now)),
            ));
            let nodes: Vec<&str> = list(&x["nodes"]).iter().map(s).collect();
            vec![
                s(&x["id"]).to_string(),
                match s(&x["client"]) {
                    "" => "a harness".to_string(),
                    c => c.to_string(),
                },
                s(&x["transport"]).to_string(),
                format!("for {since}"),
                count(x["calls"].as_u64().unwrap_or(0) as usize, "call", "calls"),
                match nodes.is_empty() {
                    true => "no machine yet".to_string(),
                    false => nodes.join(", "),
                },
                if x["tainted"] == true { "tainted" } else { "" }.to_string(),
            ]
        })
        .collect();
    let mut p = crate::service::page().state(
        match rows.len() {
            0 => "no session".to_string(),
            n => count(n, "session", "sessions"),
        },
        Tone::Plain,
    );
    if let Some(line) = said {
        p.row("Done", line);
    }
    p.list(None, rows);
    Ok(p)
}

// ---- stats ----

/// The calls and their errors in a day's (or days') statistics.
fn calls(d: &Value) -> (u64, u64) {
    d["calls"]
        .as_object()
        .map(|c| {
            c.values().fold((0, 0), |(n, e), x| {
                (
                    n + x["count"].as_u64().unwrap_or(0),
                    e + x["errors"].as_u64().unwrap_or(0),
                )
            })
        })
        .unwrap_or((0, 0))
}

/// `stats`: every machine, then each by name.
pub(crate) async fn stats(ask: &Ask<'_>) -> Result<Page, String> {
    let v = ask.get("/api/stats").await?;
    let row = |name: &str, d: &Value| {
        let (n, e) = calls(d);
        vec![
            name.to_string(),
            count(n as usize, "call", "calls"),
            count(e as usize, "refused or failed", "refused or failed"),
            format!(
                "online {}",
                nerve_transport::log::span(std::time::Duration::from_millis(
                    d["online_ms"].as_u64().unwrap_or(0)
                ))
            ),
        ]
    };
    let mut rows = vec![row("All machines", &v["total"])];
    if let Some(nodes) = v["nodes"].as_object() {
        let mut named: Vec<(&String, &Value)> = nodes.iter().collect();
        named.sort_by_key(|(n, _)| n.to_lowercase());
        rows.extend(named.into_iter().map(|(n, d)| row(n, d)));
    }
    let mut p = crate::service::page().state(
        format!("the last {} days", v["retention_days"]),
        Tone::Plain,
    );
    p.list(None, rows);
    Ok(p)
}

// ---- audit ----

/// Whether the audit entry `e` is a refusal.
fn refused(e: &Value) -> bool {
    s(&e["decision"]) == "forbidden"
}

/// `audit`, and a rule made of one of its decisions.
pub(crate) async fn audit(
    ask: &Ask<'_>,
    last: usize,
    cmd: Option<&AuditCmd>,
) -> Result<Page, String> {
    let v = ask.get("/api/audit").await?;
    let all = list(&v["decisions"]);
    // Numbered from the newest, as `audit` shows them.
    let newest = |n: usize| -> Result<&Value, String> {
        n.checked_sub(1)
            .and_then(|i| all.len().checked_sub(i + 1))
            .and_then(|i| all.get(i))
            .ok_or_else(|| format!("no decision numbered {n}: `audit` shows them"))
    };
    let Some(cmd) = cmd else {
        let rows: Vec<Vec<String>> = all
            .iter()
            .rev()
            .take(last)
            .enumerate()
            .map(|(i, e)| {
                vec![
                    format!("{}", i + 1),
                    nerve_service::out::time(e["ts"].as_u64().unwrap_or(0)),
                    s(&e["node"]).to_string(),
                    format!("{}.{}", s(&e["cap"]), s(&e["action"])),
                    cut(s(&e["target"]), 60),
                    match refused(e) {
                        true => match s(&e["by"]) {
                            "" => "refused".to_string(),
                            by => format!("refused by {by}"),
                        },
                        false => "allowed".to_string(),
                    },
                ]
            })
            .collect();
        let mut p = crate::service::page().state(
            match all.len() {
                0 => "no decision yet".to_string(),
                n => count(n, "decision", "decisions"),
            },
            Tone::Plain,
        );
        p.list(None, rows);
        if !all.is_empty() {
            p.next(
                "Make a rule of one",
                "nerve-center audit allow|deny|skip <N>",
            );
        }
        return Ok(p);
    };
    let body = |e: &Value, r: &AuditRule| -> Result<Value, String> {
        let pin = match &r.pin {
            None => Value::Null,
            Some(field) => match e["args"].get(field) {
                Some(value) => json!({"field": field, "value": value}),
                None => return Err(format!("that call has no argument {field}")),
            },
        };
        Ok(
            json!({"cap": e["cap"], "action": e["action"], "target": s(&e["target"]),
                  "wildcard": r.wildcard, "node_id": e["node_id"], "pin": pin}),
        )
    };
    let (said, rule) = match cmd {
        AuditCmd::Allow(r) | AuditCmd::Deny(r) => {
            let e = newest(r.n)?;
            let mut b = body(e, r)?;
            let word = match cmd {
                AuditCmd::Allow(_) => "allow",
                _ => "deny",
            };
            b["list"] = json!(word);
            let made = ask.post("/api/audit/rule", b).await?;
            (
                format!("the rule is in the machine's {word} list"),
                made["rule"].clone(),
            )
        }
        AuditCmd::Skip {
            rule: r,
            this_machine,
        } => {
            let e = newest(r.n)?;
            let mut b = body(e, r)?;
            if !this_machine {
                b["node_id"] = Value::Null;
            }
            let made = ask.post("/api/checker/allow", b).await?;
            (
                "such calls skip the decision model".to_string(),
                made["rule"].clone(),
            )
        }
    };
    let mut p = crate::service::page().state("rule added", Tone::Good);
    p.row(
        "Rule",
        match &rule {
            Value::String(r) => r.clone(),
            other => other.to_string(),
        },
    );
    p.note(said);
    Ok(p)
}

// ---- key ----

/// `key rotate` and `key finish`.
pub(crate) async fn key(ask: &Ask<'_>, cmd: KeyCmd) -> Result<Page, String> {
    match cmd {
        KeyCmd::Rotate => {
            let v = ask.post("/api/center/key/rotate", json!({})).await?;
            let mut p = crate::service::page().state("new center key", Tone::Good);
            if let Some(pin) = v["pin"].as_str() {
                p.row("Pin", pin);
            }
            p.note("The paired machines take the new key while the old one still works. The pin is shown only now.");
            p.next("End the old key's grace", "nerve-center key finish");
            Ok(p)
        }
        KeyCmd::Finish => {
            ask.post("/api/center/key/finish", json!({})).await?;
            Ok(crate::service::page().state("the old key no longer works", Tone::Good))
        }
    }
}

// ---- config ----

/// `config`: the center's own settings, or one changed.
pub(crate) async fn config(
    ask: &Ask<'_>,
    setting: Option<&str>,
    value: Option<&str>,
) -> Result<Page, String> {
    if let (Some(setting), Some(value)) = (setting, value) {
        let number = || {
            value
                .trim()
                .parse::<u64>()
                .map_err(|_| format!("{setting} is a whole number"))
        };
        let body = match setting {
            "name" => json!({"name": value}),
            "retention-days" => json!({"retention_days": number()?}),
            "pair-code-minutes" => json!({"pair_code_minutes": number()?}),
            _ => json!({"log_level": value}),
        };
        ask.post("/api/center", body).await?;
    }
    let c = ask.get("/api/center").await?;
    let mut p = crate::service::page().state("the center's settings", Tone::Plain);
    p.row("name", s(&c["name"]));
    p.row("retention-days", c["retention_days"].to_string());
    p.row("pair-code-minutes", c["pair_code_minutes"].to_string());
    let level = s(&c["log_level"]);
    let now = s(&c["log_level_now"]);
    p.row(
        "log-level",
        match now != level && !now.is_empty() {
            true => format!("{level} ({now} for this run)"),
            false => level.to_string(),
        },
    );
    p.next("Change one", "nerve-center config <setting> <value>");
    Ok(p)
}

// ---- caps ----

/// `caps <machine>`, and a capability added or removed there.
pub(crate) async fn caps(ask: &Ask<'_>, name: &str, cmd: Option<&CapsCmd>) -> Result<Page, String> {
    let id = ask.node(name).await?;
    let mut said = None;
    match cmd {
        Some(CapsCmd::Add {
            cap,
            effect,
            command,
            summary,
        }) => {
            let form = json!({"name": cap.trim(), "summary": summary.trim(), "effect": effect,
                              "command": command.trim(), "params": "", "result": "",
                              "timeout": "", "platform": "any"});
            ask.post(
                "/api/caps/save",
                json!({"id": id, "form": form, "adding": true}),
            )
            .await?;
            said = Some(format!("{name} took the capability {cap}"));
        }
        Some(CapsCmd::Rm { cap }) => {
            ask.post("/api/caps/remove", json!({"id": id, "name": cap}))
                .await?;
            said = Some(format!("removed {cap} from {name}"));
        }
        Some(CapsCmd::List) | None => {}
    }
    let v = ask.get(&format!("/api/caps?id={}", query(&id))).await?;
    let added = list(&v["added"]["entries"]);
    let added_names: Vec<&str> = added.iter().map(|e| s(&e["name"])).collect();
    let mut rows: Vec<Vec<String>> = list(&v["units"])
        .iter()
        .filter(|u| !added_names.contains(&s(&u["name"])))
        .map(|u| {
            vec![
                s(&u["name"]).to_string(),
                s(&u["effect"]).to_string(),
                s(&u["source"]).to_string(),
                s(&u["summary"]).to_string(),
            ]
        })
        .collect();
    rows.extend(added.iter().map(|e| {
        let effect = match s(&e["effect"]) {
            "" => s(&e["form"]["effect"]),
            x => x,
        };
        vec![
            s(&e["name"]).to_string(),
            effect.to_string(),
            "this center".to_string(),
            s(&e["form"]["summary"]).to_string(),
        ]
    }));
    rows.extend(list(&v["broken"]).iter().map(|b| {
        vec![
            s(&b["name"]).to_string(),
            "left out".to_string(),
            String::new(),
            s(&b["reason"]).to_string(),
        ]
    }));
    let mut p = crate::service::page().state(
        format!(
            "{} on {name}",
            count(rows.len(), "capability", "capabilities")
        ),
        Tone::Plain,
    );
    if let Some(line) = said {
        p.row("Done", line);
    }
    p.list(None, rows);
    Ok(p)
}

// ---- checker ----

/// A rule's number as `checker` shows it, as an index into `rules`.
fn rule_index(rules: &[Value], n: usize) -> Result<usize, String> {
    n.checked_sub(1)
        .filter(|i| *i < rules.len())
        .ok_or_else(|| format!("no rule numbered {n}: `checker` shows them"))
}

/// The ids of the machines named, for a rule of theirs.
async fn node_ids(ask: &Ask<'_>, names: &[String]) -> Result<Vec<String>, String> {
    let overview = ask.get("/api/overview").await?;
    names
        .iter()
        .map(|n| crate::owner_calls::node_id(&overview, n))
        .collect()
}

/// The config with the decision model's `setting` at `value`.
fn with_model_setting(config: &Value, setting: &str, value: &str) -> Result<Value, String> {
    let mut c = config.clone();
    let on_off = |v: &str| match v {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err(format!("{setting} is on or off")),
    };
    let (key, v) = match setting {
        "source" => ("source", json!(value)),
        "endpoint-url" => ("endpoint_url", json!(value.trim())),
        "endpoint-model" => ("endpoint_model", json!(value.trim())),
        "gpu" => ("local_gpu", json!(on_off(value)?)),
        "local-model" => ("local_model", json!(value)),
        "threshold" => (
            "threshold",
            json!(
                value
                    .trim()
                    .parse::<f64>()
                    .map_err(|_| "threshold is a number from 0 to 1".to_string())?
            ),
        ),
        "timeout-ms" => (
            "timeout_ms",
            json!(
                value
                    .trim()
                    .parse::<u64>()
                    .map_err(|_| "timeout-ms is a whole number".to_string())?
            ),
        ),
        "scope" => ("scope", json!(value)),
        "on-error" => (
            "fail_closed",
            json!(match value {
                "refuse" => true,
                "allow" => false,
                _ => return Err("on-error is refuse or allow".into()),
            }),
        ),
        "instructions" => ("instructions", json!(value)),
        "criteria-true" => ("criteria_true", json!(value)),
        _ => ("criteria_false", json!(value)),
    };
    c["model"][key] = v;
    Ok(c)
}

/// `checker`: the checker as it is, after a change where one is asked.
pub(crate) async fn checker(ask: &Ask<'_>, cmd: Option<&CheckerCmd>) -> Result<Page, String> {
    let mut said = None;
    match cmd {
        None | Some(CheckerCmd::Show) => {}
        Some(CheckerCmd::Model(ModelCmd::Install { gpu, model })) => {
            ask.post("/api/checker/install", json!({"gpu": gpu, "model": model}))
                .await?;
            said = Some("the local model installs; it takes a few minutes".to_string());
        }
        Some(CheckerCmd::Model(ModelCmd::Remove)) => {
            ask.post("/api/checker/remove", json!({})).await?;
            said = Some("the local model is removed".to_string());
        }
        Some(CheckerCmd::Model(ModelCmd::Token)) => {
            let token = from_stdin(false)?;
            let token = token.trim();
            ask.post(
                "/api/checker/token",
                json!({"token": (!token.is_empty()).then_some(token)}),
            )
            .await?;
            said = Some(
                match token.is_empty() {
                    true => "the endpoint's token is removed",
                    false => "the endpoint's token is kept",
                }
                .to_string(),
            );
        }
        Some(change) => {
            said = Some(change_config(ask, change).await?);
        }
    }
    let v = ask.get("/api/checker").await?;
    let overview = ask.get("/api/overview").await?;
    Ok(checker_page(&v, &overview, said))
}

/// A change of the checker's config: read, changed, posted with the version
/// read; the line that says it.
async fn change_config(ask: &Ask<'_>, cmd: &CheckerCmd) -> Result<String, String> {
    let v = ask.get("/api/checker").await?;
    let c = &v["config"];
    let block = list(&c["blocklist"]);
    let skip = list(&c["allow_rules"]);
    let (config, said) = match cmd {
        CheckerCmd::On { what } | CheckerCmd::Off { what } => {
            let on = matches!(cmd, CheckerCmd::On { .. });
            let which = match what {
                CheckerSwitch::Blocklist => 0,
                CheckerSwitch::Model => 1,
                CheckerSwitch::Taint => 2,
            };
            let name = ["the blocklist", "the decision model", "taint marking"][which as usize];
            (
                edit::with_switch(c, which, on),
                format!("{name} is {}", if on { "on" } else { "off" }),
            )
        }
        CheckerCmd::Block(r) | CheckerCmd::Skip(r) => {
            let is_skip = matches!(cmd, CheckerCmd::Skip(_));
            let rules = if is_skip { skip } else { block };
            match r {
                RuleCmd::Add {
                    rule,
                    note,
                    machines,
                } => {
                    let ids = node_ids(ask, machines).await?;
                    (
                        edit::with_rule(c, is_skip, rule, note.as_deref().unwrap_or(""), &ids),
                        "the rule is added".to_string(),
                    )
                }
                RuleCmd::Edit { n, rule, note } => {
                    let i = rule_index(rules, *n)?;
                    if rules[i]["builtin"] == true {
                        return Err(
                            "a built-in rule is turned on or off, not changed: add your own".into(),
                        );
                    }
                    (
                        edit::with_rule_text(c, is_skip, i, rule, note.as_deref()),
                        "the rule is changed".to_string(),
                    )
                }
                RuleCmd::On { n, machine } | RuleCmd::Off { n, machine } => {
                    if is_skip {
                        return Err(
                            "a rule that skips the model has no switch: remove it instead".into(),
                        );
                    }
                    let on = matches!(r, RuleCmd::On { .. });
                    let i = rule_index(rules, *n)?;
                    let word = if on { "on" } else { "off" };
                    match machine {
                        None => (edit::with_rule_on(c, i, on), format!("the rule is {word}")),
                        Some(name) => {
                            let id = node_ids(ask, std::slice::from_ref(name)).await?.remove(0);
                            (
                                edit::with_rule_where(c, i, &id, on),
                                format!("the rule is {word} for {name}"),
                            )
                        }
                    }
                }
                RuleCmd::Rm { n } => {
                    let i = rule_index(rules, *n)?;
                    if rules[i]["builtin"] == true {
                        return Err("a built-in rule is turned off, not removed".into());
                    }
                    (
                        edit::without_rule(c, is_skip, i),
                        "the rule is removed".to_string(),
                    )
                }
            }
        }
        CheckerCmd::Model(ModelCmd::Set { setting, value }) => {
            let value = match value.as_str() {
                "-" => from_stdin(true)?,
                v => v.to_string(),
            };
            (
                with_model_setting(c, setting, &value)?,
                format!("the model's {setting} is changed"),
            )
        }
        CheckerCmd::Machine { name, what, state } => {
            let id = node_ids(ask, std::slice::from_ref(name)).await?.remove(0);
            let which = if what == "blocklist" { 0 } else { 1 };
            let value = match state.as_str() {
                "center" => 0,
                "on" => 1,
                _ => 2,
            };
            (
                edit::with_machine(c, &id, which, value),
                match state.as_str() {
                    "center" => format!("{name} follows the center's {what} switch"),
                    s => format!("the {what} is {s} for {name}"),
                },
            )
        }
        _ => return Ok(String::new()),
    };
    ask.post("/api/checker", json!({"config": config}))
        .await
        .map_err(|e| match e == crate::center::CHECKER_STALE {
            true => "the checker changed meanwhile: run the command again".to_string(),
            false => e,
        })?;
    Ok(format!("{said}; it counts from the next call"))
}

/// What `checker` shows: the switches, the blocklist and the rules that skip
/// the model numbered for the commands, the model, and the machines' own
/// switches.
fn checker_page(v: &Value, overview: &Value, said: Option<String>) -> Page {
    let c = &v["config"];
    let names: Vec<(String, String)> = list(&overview["nodes"])
        .iter()
        .map(|n| (s(&n["id"]).to_string(), s(&n["name"]).to_string()))
        .collect();
    let name_of = |id: &str| {
        names
            .iter()
            .find(|(i, _)| i == id)
            .map_or(id.to_string(), |(_, n)| n.clone())
    };
    let word = |b: bool| if b { "on" } else { "off" };
    let mut p = crate::service::page().state(
        format!(
            "blocklist {} · model {}",
            word(c["blocklist_on"] != false),
            word(c["model_on"] == true)
        ),
        Tone::Plain,
    );
    if let Some(line) = said {
        p.row("Done", line);
    }
    p.row("Taint marking", word(c["taint_on"] != false));
    let m = &c["model"];
    let model = match s(&m["source"]) {
        "endpoint" => format!("endpoint {}", s(&m["endpoint_url"])),
        _ => format!(
            "local {}{}{}",
            s(&m["local_model"]),
            if m["local_gpu"] == true {
                " on the GPU"
            } else {
                ""
            },
            if v["installed"] == true {
                ""
            } else {
                " (not installed)"
            }
        ),
    };
    p.row("Model", model);
    p.row(
        "Model tuning",
        format!(
            "threshold {}, timeout {} ms, scope {}, on error {}",
            m["threshold"],
            m["timeout_ms"],
            s(&m["scope"]),
            if m["fail_closed"] == false {
                "allow"
            } else {
                "refuse"
            }
        ),
    );
    let where_of = |e: &Value| match e["node_id"].as_str() {
        Some(id) => name_of(id),
        None => {
            let off: Vec<String> = list(&e["off_for"]).iter().map(|n| name_of(s(n))).collect();
            match off.is_empty() {
                true => "all machines".to_string(),
                false => format!("all machines but {}", off.join(", ")),
            }
        }
    };
    let block: Vec<Vec<String>> = list(&c["blocklist"])
        .iter()
        .enumerate()
        .map(|(i, e)| {
            vec![
                format!("{}", i + 1),
                word(e["on"] != false).to_string(),
                cut(s(&e["rule"]), 60),
                where_of(e),
                match (e["builtin"] == true, s(&e["note"])) {
                    (true, n) => format!("built-in: {n}"),
                    (false, n) => n.to_string(),
                },
            ]
        })
        .collect();
    p.list(Some("Blocklist"), block);
    let skip: Vec<Vec<String>> = list(&c["allow_rules"])
        .iter()
        .enumerate()
        .map(|(i, e)| vec![format!("{}", i + 1), s(&e["rule"]).to_string(), where_of(e)])
        .collect();
    if !skip.is_empty() {
        p.list(Some("Skip the model"), skip);
    }
    if let Some(own) = c["nodes"].as_object().filter(|o| !o.is_empty()) {
        let rows: Vec<Vec<String>> = own
            .iter()
            .map(|(id, n)| {
                let w = |k: &str| match s(&n[k]) {
                    "" | "inherit" => "center's".to_string(),
                    x => x.to_string(),
                };
                vec![
                    name_of(id),
                    format!("blocklist {}", w("blocklist")),
                    format!("model {}", w("model")),
                ]
            })
            .collect();
        p.list(Some("Per machine"), rows);
    }
    p.next("Add a rule", "nerve-center checker block add '<rule>'");
    p
}
