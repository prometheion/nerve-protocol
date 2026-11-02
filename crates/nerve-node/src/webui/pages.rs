//! The routes of the web UI's pages beyond the Overview: each change is one
//! command of the CLI of a fixed shape, built here, never an argument list
//! the page sends. Options go as `--name=value`, and the values the owner
//! typed go after `--`, so none can read as an option; a secret, and the
//! pairing link, go on the command's input. Reads of the audit and the log
//! come from the node's own files, in this process: the page asks them
//! every two seconds.

use std::path::Path;

use serde_json::{Value, json};

use nerve_policy::audit::AuditLog;
use nerve_transport::http::Request;

use super::{ApiResult, Ctx, command, text};

/// The newest entries a page gets of the audit or the log.
const NEWEST: usize = 500;

/// The routes of this module, or `None` for a path it does not have.
pub(super) async fn api(ctx: &Ctx, req: &Request, b: &Value) -> Option<ApiResult> {
    let query = req;
    Some(match (req.method.as_str(), req.path.as_str()) {
        // ---- Centers ----
        ("POST", "/api/centers/preview") => {
            let link = match link(b) {
                Ok(l) => l,
                Err(e) => return Some(Err(e)),
            };
            command(ctx, &["center", "add", "--link-stdin"], Some(&link)).await
        }
        ("POST", "/api/centers/pair") => {
            let link = match link(b) {
                Ok(l) => l,
                Err(e) => return Some(Err(e)),
            };
            let mut args = vec![
                "center".to_string(),
                "add".into(),
                "--link-stdin".into(),
                "--yes".into(),
            ];
            if let Some(n) = b["name"].as_str().filter(|n| !n.trim().is_empty()) {
                args.push(format!("--name={}", n.trim()));
            }
            run(ctx, args, Some(&link)).await
        }
        ("POST", "/api/centers/pause") => on_center(ctx, b, &["center", "pause"]).await,
        ("POST", "/api/centers/resume") => on_center(ctx, b, &["center", "resume"]).await,
        ("POST", "/api/centers/remove") => on_center(ctx, b, &["center", "rm"]).await,
        ("POST", "/api/centers/rotate") => on_center(ctx, b, &["center", "rotate-key"]).await,
        ("POST", "/api/centers/grant") => match (center(b), word(b, "what"), word(b, "value")) {
            (Ok(c), Ok(what), Ok(value)) => {
                run(
                    ctx,
                    args(&["center", "grant"], &[("center", c)], &[what, value]),
                    None,
                )
                .await
            }
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => Err(e),
        },
        // ---- Permissions ----
        ("GET", "/api/perm") => perm(ctx, query).await,
        ("POST", "/api/mode") => {
            let (c, mode) = match (center(b), word(b, "mode")) {
                (Ok(c), Ok(m)) => (c, m),
                (Err(e), _) | (_, Err(e)) => return Some(Err(e)),
            };
            let mut opts = vec![("center", c.to_string())];
            if let Some(h) = b["hours"].as_u64().filter(|h| *h > 0) {
                opts.push(("for", h.to_string()));
            }
            let mut a = vec!["mode".to_string(), "set".into()];
            a.extend(opts.iter().map(|(k, v)| format!("--{k}={v}")));
            if b["as_owner"] == true {
                a.push("--as-owner".into());
            }
            a.push("--".into());
            a.push(mode.into());
            run(ctx, a, None).await
        }
        ("POST", "/api/folders/add") => match (center(b), folder(b)) {
            (Ok(c), Ok(p)) => {
                let mut rights: Vec<&str> = Vec::new();
                for (key, r) in [("read", "+r"), ("write", "+w"), ("execute", "+x")] {
                    if b[key] == true {
                        rights.push(r);
                    }
                }
                if rights.is_empty() {
                    return Some(Err((400, "a folder needs at least one right".into())));
                }
                let mut values = vec![p];
                values.extend(rights);
                run(
                    ctx,
                    args(&["folder", "add"], &[("center", c)], &values),
                    None,
                )
                .await
            }
            (Err(e), _) | (_, Err(e)) => Err(e),
        },
        ("POST", "/api/folders/set") => match (center(b), folder(b)) {
            (Ok(c), Ok(p)) => {
                let rights = rights(b["read"] == true, b["write"] == true, b["execute"] == true);
                run(
                    ctx,
                    args(&["folder", "set"], &[("center", c)], &[p, &rights]),
                    None,
                )
                .await
            }
            (Err(e), _) | (_, Err(e)) => Err(e),
        },
        ("POST", "/api/folders/remove") => match (center(b), folder(b)) {
            (Ok(c), Ok(p)) => run(ctx, args(&["folder", "rm"], &[("center", c)], &[p]), None).await,
            (Err(e), _) | (_, Err(e)) => Err(e),
        },
        ("POST", "/api/rules/add") => match (center(b), list(b), rule(b)) {
            (Ok(c), Ok(l), Ok(r)) => run(ctx, rule_add(c, l, r, b["wildcard"] == true), None).await,
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => Err(e),
        },
        ("POST", "/api/rules/remove") => match (center(b), list(b), rule(b)) {
            (Ok(c), Ok(l), Ok(r)) => {
                run(ctx, args(&["rule", "rm"], &[("center", c)], &[l, r]), None).await
            }
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => Err(e),
        },
        ("POST", "/api/rules/guard") => on_center(ctx, b, &["rule", "guard"]).await,
        ("POST", "/api/sudo/off") => command(ctx, &["sudo", "off"], None).await,
        // ---- Audit ----
        ("GET", "/api/audit") => audit(ctx, flag(query, "denied")),
        ("POST", "/api/audit/rule") => match audit_rule(b) {
            Ok(a) => run(ctx, a, None).await,
            Err(e) => Err(e),
        },
        ("POST", "/api/audit/clear") => command(ctx, &["audit", "clear"], None).await,
        // ---- Log ----
        ("GET", "/api/log") => log(&ctx.shared.paths.log_file(), flag(query, "problems")),
        ("POST", "/api/log/clear") => command(ctx, &["log", "clear"], None).await,
        // ---- Capabilities ----
        ("GET", "/api/caps") => match query.query_param("center").filter(|c| !c.is_empty()) {
            Some(c) if !nerve_policy::config::valid_center_name(&c) => {
                Err((400, format!("{c:?} is not a center name")))
            }
            Some(c) => command(ctx, &["cap", "ls", &format!("--center={c}")], None).await,
            None => command(ctx, &["cap", "ls"], None).await,
        },
        ("POST", "/api/caps/set") => match (center(b), name(b, "cap"), word(b, "setting")) {
            (Ok(c), Ok(cap), Ok(setting)) => {
                run(
                    ctx,
                    args(&["cap", "set"], &[("center", c)], &[cap, setting]),
                    None,
                )
                .await
            }
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => Err(e),
        },
        ("POST", "/api/caps/save") => {
            let form: nerve_policy::config::form::CapForm =
                match serde_json::from_value(b["form"].clone()) {
                    Ok(f) => f,
                    Err(e) => return Some(Err((400, format!("the form: {e}")))),
                };
            // The fields are checked as the desktop's dialog checks them,
            // and each one's reason goes back to the form.
            let max = ctx.shared.config().limits.max_timeout_secs;
            let errors = nerve_policy::config::form::check(&form, max);
            if errors != Default::default() {
                let said: Vec<String> = serde_json::to_value(&errors)
                    .ok()
                    .and_then(|v| v.as_object().cloned())
                    .into_iter()
                    .flatten()
                    .filter_map(|(field, why)| {
                        why.as_str()
                            .filter(|w| !w.is_empty())
                            .map(|w| format!("{field}: {w}"))
                    })
                    .collect();
                return Some(Err((400, said.join("; "))));
            }
            let (a, input) = nerve_policy::config::form::cli_args(&form, b["adding"] == true);
            run(ctx, a, input.as_deref()).await
        }
        ("POST", "/api/caps/remove") => match name(b, "name") {
            Ok(n) => run(ctx, args(&["cap", "rm"], &[], &[n]), None).await,
            Err(e) => Err(e),
        },
        ("POST", "/api/programs/allow") => match (name(b, "name"), folder_like(b, "exe")) {
            (Ok(n), Ok(exe)) => {
                run(
                    ctx,
                    args(&["cap", "provider", "allow"], &[], &[n, exe]),
                    None,
                )
                .await
            }
            (Err(e), _) | (_, Err(e)) => Err(e),
        },
        ("POST", "/api/programs/remove") => match name(b, "name") {
            Ok(n) => run(ctx, args(&["cap", "provider", "rm"], &[], &[n]), None).await,
            Err(e) => Err(e),
        },
        // ---- Relay ----
        ("GET", "/api/relay") => {
            let relay = match command(ctx, &["relay", "ls"], None).await {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };
            command(ctx, &["proxy", "ls"], None)
                .await
                .map(|proxy| json!({ "relay": relay, "proxy": proxy }))
        }
        ("POST", "/api/relay/set") => match address(b) {
            Ok(a) => run(ctx, args(&["relay", "set"], &[], &[a]), None).await,
            Err(e) => Err(e),
        },
        ("POST", "/api/relay/off") => command(ctx, &["relay", "off"], None).await,
        ("POST", "/api/relay/add") => match name(b, "name") {
            Ok(n) => {
                let mut opts = Vec::new();
                if let Some(a) = b["address"].as_str().filter(|a| !a.trim().is_empty()) {
                    if a.starts_with('-') || a.contains(char::is_whitespace) {
                        return Some(Err((400, "address is HOST or HOST:PORT".into())));
                    }
                    opts.push(("address", a));
                }
                run(ctx, args(&["relay", "add"], &opts, &[n]), None).await
            }
            Err(e) => Err(e),
        },
        ("POST", "/api/relay/token") => match name(b, "name") {
            Ok(n) => run(ctx, args(&["relay", "token"], &[], &[n]), None).await,
            Err(e) => Err(e),
        },
        ("POST", "/api/relay/remove") => match name(b, "name") {
            Ok(n) => run(ctx, args(&["relay", "rm"], &[], &[n]), None).await,
            Err(e) => Err(e),
        },
        ("POST", "/api/proxy/set") => {
            let url = match b["url"].as_str().map(str::trim).filter(|u| !u.is_empty()) {
                Some(u) if !u.starts_with('-') => u,
                _ => return Some(Err((400, "url is missing".into()))),
            };
            let mut opts = Vec::new();
            if let Some(p) = b["pin"].as_str().filter(|p| !p.is_empty()) {
                opts.push(("pin", p));
            }
            // The password goes on the input, never in a command line.
            let password = b["password"].as_str().filter(|p| !p.is_empty());
            let mut a = args(&["proxy", "set"], &opts, &[]);
            if password.is_some() {
                a.push("--password-stdin".into());
            }
            a.extend(["--".to_string(), url.to_string()]);
            let input = password.map(|p| format!("{p}\n"));
            run(ctx, a, input.as_deref()).await
        }
        ("POST", "/api/proxy/remove") => command(ctx, &["proxy", "rm"], None).await,
        // ---- Settings ----
        ("GET", "/api/settings") => Ok(settings(&ctx.shared.config())),
        ("POST", "/api/settings/set") => match (setting_key(b), b["value"].as_str()) {
            (Ok(k), Some(v)) => run(ctx, args(&["config", "set"], &[], &[k, v]), None).await,
            (Err(e), _) => Err(e),
            (_, None) => Err((400, "value is missing".into())),
        },
        ("POST", "/api/settings/unset") => match setting_key(b) {
            Ok(k) => run(ctx, args(&["config", "unset"], &[], &[k]), None).await,
            Err(e) => Err(e),
        },
        ("GET", "/api/help") => Ok(json!({ "node": crate::cli::help() })),
        _ => return None,
    })
}

/// Whether the query of `req` sets `key` to 1.
fn flag(req: &Request, key: &str) -> bool {
    req.query_param(key).as_deref() == Some("1")
}

/// Runs `a` (an argument list built here) as [`command`] does.
async fn run(ctx: &Ctx, a: Vec<String>, input: Option<&str>) -> ApiResult {
    let refs: Vec<&str> = a.iter().map(String::as_str).collect();
    command(ctx, &refs, input).await
}

/// `words`, then each option as `--name=value`, then `--` and the values.
pub(super) fn args(words: &[&str], opts: &[(&str, &str)], values: &[&str]) -> Vec<String> {
    let mut a: Vec<String> = words.iter().map(|w| w.to_string()).collect();
    a.extend(opts.iter().map(|(k, v)| format!("--{k}={v}")));
    if !values.is_empty() {
        a.push("--".into());
        a.extend(values.iter().map(|v| v.to_string()));
    }
    a
}

/// A command on one center of the body's.
async fn on_center(ctx: &Ctx, b: &Value, words: &[&str]) -> ApiResult {
    let c = center(b)?;
    run(ctx, args(words, &[("center", c)], &[]), None).await
}

fn center(b: &Value) -> Result<&str, (u16, String)> {
    let c = text(b, "center")?;
    if !nerve_policy::config::valid_center_name(c) {
        return Err((400, format!("{c:?} is not a center name")));
    }
    Ok(c)
}

/// A fixed word of a command (a mode, a list, what a grant gives): letters,
/// digits and `-` only.
fn word<'a>(b: &'a Value, key: &str) -> Result<&'a str, (u16, String)> {
    let w = text(b, key)?;
    if !w.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
        return Err((400, format!("{key} {w:?} is not a word the node takes")));
    }
    Ok(w)
}

fn list(b: &Value) -> Result<&str, (u16, String)> {
    match text(b, "list")? {
        l @ ("allow" | "deny" | "sudo") => Ok(l),
        l => Err((400, format!("{l:?} is not a list: allow, deny or sudo"))),
    }
}

/// A rule as typed: any text but an empty one. It goes after `--`.
fn rule(b: &Value) -> Result<&str, (u16, String)> {
    b["rule"]
        .as_str()
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .ok_or_else(|| (400, "rule is missing".to_string()))
}

/// A folder's path: absolute, as the node has no working folder of the
/// owner's to read a relative one against.
fn folder(b: &Value) -> Result<&str, (u16, String)> {
    let p = b["path"]
        .as_str()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| (400, "path is missing".to_string()))?;
    if !Path::new(p).is_absolute() {
        return Err((400, format!("{p:?} is not a whole path: it starts at /")));
    }
    Ok(p)
}

/// A name the CLI takes (a capability, a program, a relayed node): letters,
/// digits, `.`, `_` and `-`, not starting with `-`.
fn name<'a>(b: &'a Value, key: &str) -> Result<&'a str, (u16, String)> {
    let n = text(b, key)?;
    if !n
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
    {
        return Err((400, format!("{key} {n:?} is not a name the node takes")));
    }
    Ok(n)
}

/// A whole path of a body's `key`.
fn folder_like<'a>(b: &'a Value, key: &str) -> Result<&'a str, (u16, String)> {
    let p = b[key]
        .as_str()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| (400, format!("{key} is missing")))?;
    if !Path::new(p).is_absolute() {
        return Err((400, format!("{p:?} is not a whole path: it starts at /")));
    }
    Ok(p)
}

/// An address and port to listen on.
fn address(b: &Value) -> Result<&str, (u16, String)> {
    let a = text(b, "address")?;
    a.parse::<std::net::SocketAddr>().map(|_| a).map_err(|_| {
        (
            400,
            format!("{a:?} is not an address and a port, like 0.0.0.0:7490"),
        )
    })
}

/// A setting's dotted name for `config set` or `unset`. The web UI's own
/// settings are refused here already; the command refuses them, and those
/// that stay root's, again.
fn setting_key(b: &Value) -> Result<&str, (u16, String)> {
    let k = text(b, "key")?;
    if k == "ui" || k.starts_with("ui.") {
        return Err((400, crate::owner::NOT_FROM_THE_WEB.into()));
    }
    if !k
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
    {
        return Err((400, format!("{k:?} is not a setting's name")));
    }
    Ok(k)
}

/// What the Settings page shows: the settings it changes, those that stay
/// root's (shown, not changed), and the whole file's text for Advanced,
/// without the web UI's token hashes.
fn settings(cfg: &nerve_policy::NodeConfig) -> Value {
    let mut shown = cfg.clone();
    shown.ui.tokens.clear();
    json!({
        "name": cfg.node.name,
        "log_level": cfg.log.level.to_string(),
        "secret_storage": cfg.machine.secret_storage,
        "limits": {
            "max_running": cfg.limits.max_running,
            "output_cap_bytes": cfg.limits.output_cap_bytes,
            "default_timeout_secs": cfg.limits.default_timeout_secs,
            "max_timeout_secs": cfg.limits.max_timeout_secs,
        },
        "root_only": crate::owner::ROOT_ONLY,
        "machine": {
            "shell": cfg.machine.shell,
            "allow_root": cfg.machine.allow_root,
            "sudo_path": cfg.machine.sudo_path,
        },
        "toml": shown.to_toml(),
    })
}

/// The pairing link of a body, which goes on the command's input.
fn link(b: &Value) -> Result<String, (u16, String)> {
    let l = b["link"].as_str().map(str::trim).unwrap_or_default();
    if l.is_empty() || l.contains(['\n', '\r']) {
        return Err((400, "link is missing".into()));
    }
    Ok(format!("{l}\n"))
}

/// The rights `folder set` takes: `=rwx`, the letters that are on.
fn rights(read: bool, write: bool, execute: bool) -> String {
    let mut r = String::from("=");
    for (on, c) in [(read, 'r'), (write, 'w'), (execute, 'x')] {
        if on {
            r.push(c);
        }
    }
    r
}

/// Whether a rule for the allow or deny list is in the pattern form for
/// files and other actions (`fs.read:~/notes/*`), which `rule add` refuses
/// as a command and `config add` takes. A single letter before the `:` is a
/// drive, not a capability.
fn pattern_rule(text: &str) -> bool {
    text.split_once(':').is_some_and(|(scope, _)| {
        (scope.contains('.') || scope.len() > 1) && nerve_policy::rules::valid_scope(scope)
    })
}

/// The command that adds `rule` to `list` of center `c`: a pattern goes
/// into the list as it is, as `config add` puts it there.
pub(super) fn rule_add(c: &str, list: &str, rule: &str, wildcard: bool) -> Vec<String> {
    if list != "sudo" && pattern_rule(rule) {
        let key = format!("center.{c}.policy.{list}");
        return args(&["config", "add"], &[], &[&key, rule]);
    }
    let mut a = args(&["rule", "add"], &[("center", c)], &[]);
    if wildcard {
        a.push("--wildcard".into());
    }
    a.extend(["--".to_string(), list.to_string(), rule.to_string()]);
    a
}

/// What the Permissions page shows of one center: its rules, its folders
/// and the sudo switch, as the CLI lists them.
async fn perm(ctx: &Ctx, q: &Request) -> ApiResult {
    let c = q.query_param("center").unwrap_or_default();
    if !nerve_policy::config::valid_center_name(&c) {
        return Err((400, "center is missing".into()));
    }
    let at = format!("--center={c}");
    let rules = command(ctx, &["rule", "ls", &at], None).await?;
    let folders = command(ctx, &["folder", "ls", &at], None).await?;
    let sudo = command(ctx, &["sudo", "status"], None).await?;
    Ok(json!({ "rules": rules, "folders": folders, "sudo": sudo }))
}

/// The newest audit entries, each with the rules its buttons would add as
/// they will be stored, control characters written out.
fn audit(ctx: &Ctx, denied: bool) -> ApiResult {
    let log = AuditLog::new(ctx.shared.paths.audit_log());
    let lines = log
        .lines()
        .map_err(|e| (500, format!("cannot read the audit: {e}")))?;
    let mut entries: Vec<Value> = lines
        .iter()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| !denied || v["decision"] == "forbidden" || v["event"] == "refused")
        .collect();
    entries.drain(..entries.len().saturating_sub(NEWEST));
    for e in &mut entries {
        if let Some(p) = rule_preview(e) {
            e["rule_preview"] = json!(p);
        }
    }
    Ok(json!({ "entries": entries }))
}

/// The rule an audit entry's buttons add, as `rule ls` will show it: none
/// for an entry no rule can name.
fn rule_preview(e: &Value) -> Option<String> {
    let (cap, action, target) = (
        e["cap"].as_str()?,
        e["action"].as_str()?,
        e["target"].as_str()?,
    );
    if cap.is_empty() || action.is_empty() || target.is_empty() {
        return None;
    }
    if nerve_policy::audit::is_cut_target(target) {
        return None;
    }
    Some(visible(&format!("{cap}.{action}:{target}")))
}

/// `text` with every character that would hide what it says written out:
/// tabs and line breaks as `rule ls` writes them, any other control or
/// direction mark as `\u{…}`.
fn visible(text: &str) -> String {
    nerve_policy::rules::escape_controls(text)
        .chars()
        .map(|c| {
            let bidi = matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
            if c.is_control() || bidi {
                format!("\\u{{{:x}}}", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// The `rule add` an audit entry's button runs: its action, target and
/// center, on the allow or deny list (the sudo list for a sudo command),
/// as a wildcard or held to one of its arguments.
fn audit_rule(b: &Value) -> Result<Vec<String>, (u16, String)> {
    let c = center(b)?;
    let cap = word(b, "cap")?;
    let action = word(b, "action")?;
    let target = b["target"]
        .as_str()
        .filter(|t| !t.is_empty())
        .ok_or_else(|| (400, "target is missing".to_string()))?;
    if nerve_policy::audit::is_cut_target(target) {
        return Err((
            400,
            "the target was cut to its start, so no rule can name it".into(),
        ));
    }
    let deny = b["list"] == "deny";
    let sudo = cap == "exec" && action == "run" && nerve_policy::sudo_command(target).is_some();
    let list = if deny {
        "deny"
    } else if sudo {
        "sudo"
    } else {
        "allow"
    };
    let scope = format!("{cap}.{action}");
    let mut opts = vec![("action", scope.as_str()), ("center", c)];
    let pin = b["pin"].as_str().filter(|p| !p.is_empty());
    if let Some(p) = pin {
        if !p.contains('=') {
            return Err((400, "pin is FIELD=VALUE".into()));
        }
        opts.push(("pin", p));
    }
    let mut a = args(&["rule", "add"], &opts, &[]);
    if b["wildcard"] == true {
        a.push("--wildcard".into());
    }
    a.extend(["--".to_string(), list.to_string(), target.to_string()]);
    Ok(a)
}

/// The newest lines of the node's log, the moved-aside file's first:
/// errors and warnings only with `problems`.
fn log(file: &Path, problems: bool) -> ApiResult {
    let read = |p: &Path| match std::fs::read(p) {
        Ok(b) => Ok(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err((500, format!("cannot read the log: {e}"))),
    };
    let mut old = file.as_os_str().to_owned();
    old.push(".1");
    let mut bytes = read(Path::new(&old))?;
    bytes.extend(read(file)?);
    let mut lines: Vec<Value> = String::from_utf8_lossy(&bytes)
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| !problems || matches!(v["level"].as_str(), Some("error" | "warn")))
        .collect();
    lines.drain(..lines.len().saturating_sub(NEWEST));
    Ok(json!({ "entries": lines }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_go_after_the_options_and_never_read_as_one() {
        assert_eq!(
            args(&["folder", "rm"], &[("center", "home")], &["/srv/-x"]),
            ["folder", "rm", "--center=home", "--", "/srv/-x"]
        );
        assert_eq!(
            rule_add("home", "allow", "git status", true),
            [
                "rule",
                "add",
                "--center=home",
                "--wildcard",
                "--",
                "allow",
                "git status"
            ]
        );
        // A pattern goes into the list as `config add` puts it there.
        assert_eq!(
            rule_add("home", "deny", "fs.read:~/private/*", false),
            [
                "config",
                "add",
                "--",
                "center.home.policy.deny",
                "fs.read:~/private/*"
            ]
        );
        assert_eq!(rule_add("home", "sudo", "fs.read:x", false)[1], "add");
    }

    #[test]
    fn a_body_is_checked_before_anything_runs() {
        assert!(center(&json!({"center": "home"})).is_ok());
        for bad in [
            json!({"center": "--all"}),
            json!({"center": "a b"}),
            json!({}),
        ] {
            assert_eq!(center(&bad).unwrap_err().0, 400, "{bad}");
        }
        assert!(folder(&json!({"path": "relative/dir"})).is_err());
        assert!(folder(&json!({"path": "/srv/data"})).is_ok());
        assert!(word(&json!({"mode": "folder; rm"}), "mode").is_err());
        assert!(list(&json!({"list": "other"})).is_err());
        assert!(link(&json!({"link": "nerve://pair?x\nmore"})).is_err());
        assert_eq!(
            link(&json!({"link": " nerve://pair?x "})).unwrap(),
            "nerve://pair?x\n"
        );
    }

    #[test]
    fn an_audit_entry_gives_its_rule_and_its_preview() {
        let e = json!({"center": "home", "cap": "exec", "action": "run", "target": "git\tlog", "list": "allow"});
        assert_eq!(rule_preview(&e).unwrap(), "exec.run:git\\tlog");
        assert_eq!(
            audit_rule(&e).unwrap(),
            [
                "rule",
                "add",
                "--action=exec.run",
                "--center=home",
                "--",
                "allow",
                "git\tlog"
            ]
        );
        let sudo =
            json!({"center": "home", "cap": "exec", "action": "run", "target": "sudo apt update"});
        assert_eq!(
            audit_rule(&sudo).unwrap().last().unwrap(),
            "sudo apt update"
        );
        assert!(audit_rule(&sudo).unwrap().contains(&"sudo".to_string()));
        let pinned = json!({"center": "home", "cap": "lamp", "action": "set", "target": "x", "list": "deny", "pin": "room=office"});
        let a = audit_rule(&pinned).unwrap();
        assert!(a.contains(&"--pin=room=office".to_string()), "{a:?}");
        assert!(a.contains(&"deny".to_string()));
        assert_eq!(
            rule_preview(&json!({"cap": "fs", "action": "read", "target": "/etc/\u{202e}x\u{7}"}))
                .unwrap(),
            "fs.read:/etc/\\u{202e}x\\u{7}"
        );
        assert!(audit_rule(&json!({"center": "home", "cap": "exec", "action": "run"})).is_err());
    }

    #[test]
    fn a_setting_of_the_web_ui_is_refused_before_anything_runs() {
        for k in ["ui", "ui.listen", "ui.token"] {
            assert_eq!(setting_key(&json!({"key": k})).unwrap_err().0, 400, "{k}");
        }
        assert_eq!(setting_key(&json!({"key": "log.level"})), Ok("log.level"));
        assert!(setting_key(&json!({"key": "-x"})).is_err());
        assert!(name(&json!({"name": "a b"}), "name").is_err());
        assert!(address(&json!({"address": "relay.example"})).is_err());
        // The settings shown keep no token hash of the web UI.
        let mut cfg = nerve_policy::NodeConfig::default();
        cfg.ui.tokens.push(nerve_policy::config::UiToken {
            label: "laptop".into(),
            token_sha256: "d".repeat(64),
            made: String::new(),
        });
        let v = settings(&cfg);
        assert!(!v.to_string().contains(&"d".repeat(64)), "{v}");
    }

    #[test]
    fn the_log_is_read_old_file_first_and_cut_to_the_newest() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("log.jsonl");
        std::fs::write(
            d.path().join("log.jsonl.1"),
            "{\"level\":\"warn\",\"msg\":\"old\"}\n",
        )
        .unwrap();
        std::fs::write(&f, "{\"level\":\"info\",\"msg\":\"new\"}\nnot json\n").unwrap();
        let v = log(&f, false).unwrap();
        let msgs: Vec<&str> = v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["msg"].as_str().unwrap())
            .collect();
        assert_eq!(msgs, ["old", "new"]);
        let v = log(&f, true).unwrap();
        assert_eq!(v["entries"].as_array().unwrap().len(), 1);
    }
}
