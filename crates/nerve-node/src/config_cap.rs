//! The capabilities the owner declares in `node.toml` (`[[capability]]`,
//! nerve_policy::config::ConfigCapability, docs/user/config-capabilities.md):
//! what the node offers of them, and what a call's run returns. The link
//! decides a call like any other and runs the command itself (crate::link).
//!
//! The installed Linux node runs one as `nerve-run` (the default), held to
//! the folders like that account's commands, or as the owner where the entry
//! says so. A node run by hand has no `nerve-run`: it offers only those that
//! run as the owner, which is its own user. Windows reads them and offers
//! none yet.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use nerve_policy::NodeConfig;
use nerve_policy::config::{ConfigCapability, Output, RunsAs};
use nerve_proto::descriptor::{Action, Capability, Exposure};
use nerve_proto::{ErrorCode, RpcError};

/// The `provider` of a config capability in the descriptor and `cap ls`.
pub const PROVIDER: &str = "config";

/// The most of a failed command's stderr its error repeats.
const STDERR_MAX: usize = 16 * 1024;

/// The config's capabilities this node offers, one capability per `cap`
/// with its actions: [`offered_on`] for this platform.
pub fn offered(cfg: &NodeConfig, installed: bool) -> Vec<Capability> {
    offered_on(cfg, std::env::consts::OS, installed)
}

/// Why a node on `os` does not offer `c`, if it does not: it offers them on
/// Linux only for now, those of its platform, and on a node run by hand
/// (not `installed`) only those that run as the owner.
pub fn left_out(c: &ConfigCapability, os: &str, installed: bool) -> Option<String> {
    if os != "linux" {
        Some(format!(
            "a node on {os} offers no capability of node.toml yet (Linux only for now)"
        ))
    } else if !c.platform.takes(os) {
        Some(format!("for {} only", c.platform.as_str()))
    } else if !installed && c.account == RunsAs::NerveRun {
        Some(format!(
            "runs as {}, which a node run by hand does not have (account = \"owner\" runs it as you)",
            crate::account::RUN_USER
        ))
    } else {
        None
    }
}

/// The config's capabilities a node on `os` offers: those [`left_out`] does
/// not leave out.
pub fn offered_on(cfg: &NodeConfig, os: &str, installed: bool) -> Vec<Capability> {
    let mut caps: BTreeMap<&str, Capability> = BTreeMap::new();
    for c in cfg
        .capabilities
        .iter()
        .filter(|c| left_out(c, os, installed).is_none())
    {
        let (cap, action) = c.split();
        let entry = caps.entry(cap).or_insert_with(|| Capability {
            id: cap.to_string(),
            profile: String::new(),
            provider: PROVIDER.into(),
            exposure: Exposure::On,
            summary: String::new(),
            actions: BTreeMap::new(),
            events: BTreeMap::new(),
            state: Value::Null,
            streams: BTreeMap::new(),
        });
        entry.actions.insert(
            action.to_string(),
            Action {
                effect: c.effect,
                summary: c.summary.clone(),
                params: c.params_schema(),
                result: c.result.schema(),
                exposure: None,
            },
        );
    }
    caps.into_values().collect()
}

/// `c` as `cap ls --json` gives it: as the owner declared it, the schemas
/// as JSON.
pub fn entry(c: &ConfigCapability) -> Value {
    json!({
        "name": c.name,
        "summary": c.summary,
        "effect": c.effect,
        "command": c.command,
        "params": c.params,
        "result": match &c.result {
            Output::Text => json!(Output::Text.to_string()),
            Output::Json(s) => s.clone(),
        },
        "timeout_secs": c.timeout_secs,
        "account": c.account.as_str(),
        "platform": c.platform.as_str(),
    })
}

/// The config's entry for `cap.action`.
pub fn find<'a>(cfg: &'a NodeConfig, cap: &str, action: &str) -> Option<&'a ConfigCapability> {
    cfg.capabilities.iter().find(|c| c.split() == (cap, action))
}

/// Whether the config declares a capability `cap` (any action, any
/// platform): no program may add one of that name.
pub fn names(cfg: &NodeConfig, cap: &str) -> bool {
    cfg.capabilities.iter().any(|c| c.split().0 == cap)
}

/// What a call of `decl` returns, from its command's result
/// (crate::exec::run): what it printed, as text or as JSON that fits the
/// result schema. A command that did not end with exit code 0 is an error
/// with its exit code (or signal) and what it printed to stderr.
pub fn result(decl: &ConfigCapability, run: &Value) -> Result<Value, RpcError> {
    let stdout = run["stdout"].as_str().unwrap_or_default();
    let stderr = run["stderr"].as_str().unwrap_or_default();
    let cut = run["truncated"] == true;
    let code = run["exit_code"].as_i64();
    if code != Some(0) {
        let how = match (code, run["signal"].as_str(), run["reason"].as_str()) {
            (_, _, Some(reason)) => reason.to_string(),
            (Some(c), _, _) => format!("exit code {c}"),
            (None, Some(s), _) => format!("signal {s}"),
            (None, None, _) => "no exit code".into(),
        };
        let shown = match stderr.char_indices().nth(STDERR_MAX) {
            Some((end, _)) => format!("{}…", &stderr[..end]),
            None => stderr.to_string(),
        };
        let text = if shown.trim().is_empty() {
            format!("{} failed: {how}", decl.name)
        } else {
            format!("{} failed: {how}; stderr: {}", decl.name, shown.trim_end())
        };
        return Err(RpcError::new(ErrorCode::Other("io".into()), text)
            .with("exit_code", run["exit_code"].clone())
            .with("stderr", Value::String(shown)));
    }
    match &decl.result {
        Output::Text if cut => Ok(Value::String(format!(
            "{stdout}\n[the output was longer and is cut here]"
        ))),
        Output::Text => Ok(Value::String(stdout.to_string())),
        Output::Json(_) if cut => Err(RpcError::new(
            ErrorCode::TooLarge,
            format!(
                "{} printed more than the node's limits.output_cap_bytes, so its JSON is cut",
                decl.name
            ),
        )),
        Output::Json(schema) => {
            let v: Value = serde_json::from_str(stdout).map_err(|e| {
                RpcError::new(
                    ErrorCode::Other("io".into()),
                    format!("{} printed no JSON: {e}", decl.name),
                )
            })?;
            nerve_proto::schema::validate(schema, &v).map_err(|e| {
                RpcError::new(
                    ErrorCode::Other("io".into()),
                    format!(
                        "{} printed JSON its result schema does not take: {e}",
                        decl.name
                    ),
                )
            })?;
            Ok(v)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nerve_proto::descriptor::Effect;

    fn cfg(entries: &str) -> NodeConfig {
        NodeConfig::parse(entries).unwrap()
    }

    const TWO: &str = r#"
[[capability]]
name = "sensors.read"
effect = "sense"
command = ["sensors", "-j"]
result = '{"type": "object"}'

[[capability]]
name = "sensors.list"
effect = "read"
summary = "The sensors."
command = ["sensors", "-l"]
account = "owner"

[[capability]]
name = "win.only"
effect = "read"
command = ["whoami"]
platform = "windows"
account = "owner"

[[capability]]
name = "lin.only"
effect = "read"
command = ["id"]
platform = "linux"
account = "owner"
"#;

    fn ids(caps: &[Capability]) -> Vec<String> {
        caps.iter()
            .flat_map(|c| c.actions.keys().map(move |a| format!("{}.{a}", c.id)))
            .collect()
    }

    #[test]
    fn what_is_offered_follows_the_platform_and_the_account() {
        let c = cfg(TWO);
        assert_eq!(
            ids(&offered_on(&c, "linux", true)),
            ["lin.only", "sensors.list", "sensors.read"]
        );
        // By hand only those that run as the owner.
        assert_eq!(
            ids(&offered_on(&c, "linux", false)),
            ["lin.only", "sensors.list"]
        );
        // Windows reads them and offers none yet.
        assert!(offered_on(&c, "windows", true).is_empty());
        let caps = offered_on(&c, "linux", true);
        let sensors = caps.iter().find(|c| c.id == "sensors").unwrap();
        assert_eq!(sensors.provider, PROVIDER);
        assert_eq!(sensors.actions["read"].effect, Effect::Sense);
        assert_eq!(sensors.actions["read"].result, json!({"type": "object"}));
        assert_eq!(sensors.actions["list"].result, json!({"type": "string"}));
        assert_eq!(sensors.actions["list"].summary, "The sensors.");
        assert_eq!(
            sensors.actions["list"].params,
            json!({"type": "object", "properties": {}, "additionalProperties": false})
        );
        assert!(names(&c, "win") && names(&c, "sensors") && !names(&c, "lamp"));
        assert_eq!(find(&c, "sensors", "list").unwrap().name, "sensors.list");
        assert!(find(&c, "sensors", "other").is_none());
    }

    #[test]
    fn a_non_zero_exit_is_an_error_and_json_must_fit() {
        let c = cfg(TWO);
        let json_cap = find(&c, "sensors", "read").unwrap();
        let text_cap = find(&c, "sensors", "list").unwrap();
        let run = |code: Value, out: &str, err: &str, cut: bool| json!({"exit_code": code, "stdout": out, "stderr": err, "truncated": cut});
        assert_eq!(
            result(text_cap, &run(json!(0), "a\nb\n", "", false)).unwrap(),
            json!("a\nb\n")
        );
        assert_eq!(
            result(json_cap, &run(json!(0), "{\"t\": 40}", "", false)).unwrap(),
            json!({"t": 40})
        );
        let e = result(text_cap, &run(json!(2), "", "no sensors found\n", false)).unwrap_err();
        assert_eq!(e.kind().as_str(), "io");
        assert!(
            e.message.contains("exit code 2") && e.message.contains("no sensors found"),
            "{}",
            e.message
        );
        let data = e.data.clone().unwrap();
        assert_eq!(data["exit_code"], 2);
        assert_eq!(data["stderr"], "no sensors found\n");
        let mut killed = run(Value::Null, "", "", false);
        killed["signal"] = json!("kill");
        assert!(
            result(text_cap, &killed)
                .unwrap_err()
                .message
                .contains("signal kill")
        );
        // JSON that is none, or does not fit, or was cut.
        assert!(result(json_cap, &run(json!(0), "40", "", false)).is_err());
        assert!(result(json_cap, &run(json!(0), "{", "", false)).is_err());
        assert_eq!(
            result(json_cap, &run(json!(0), "{}", "", true))
                .unwrap_err()
                .kind(),
            ErrorCode::TooLarge
        );
        assert!(
            result(text_cap, &run(json!(0), "abc", "", true))
                .unwrap()
                .as_str()
                .unwrap()
                .ends_with("cut here]")
        );
    }
}
