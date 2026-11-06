//! The `--json` forms of the commands (docs/user/commands.md), for programs
//! that drive the CLI, such as the desktop app: the read commands print
//! their data as one JSON object, `audit --follow` one entry a line, and the
//! other commands the lines they print as `{"messages": [...]}`. An error is
//! `{"error": "..."}` on stdout too (crate::entry), so a program never reads
//! text meant for people to know what happened.

use super::*;

/// Whether `cmd` prints data of its own with `--json`; every other command
/// gives its lines ([`lines`]).
pub(super) fn own_form(cmd: &Cmd) -> bool {
    matches!(
        cmd,
        Cmd::Status
            | Cmd::Audit { clear: None, .. }
            | Cmd::Log { clear: None, .. }
            | Cmd::Center {
                cmd: None | Some(CenterCmd::Add { .. })
            }
            | Cmd::Mode { mode: None, .. }
            | Cmd::Folder { cmd: None, .. }
            | Cmd::Rule { cmd: None, .. }
            | Cmd::Cap { cmd: None, .. }
            | Cmd::Provider { cmd: None }
            | Cmd::Config(ConfigCmd::Get { .. })
            | Cmd::Proxy { cmd: None }
            | Cmd::Relay { cmd: None }
            | Cmd::Sudo { cmd: None }
    )
}

tokio::task_local! {
    /// What a command without a form of its own says as data besides its
    /// lines ([`also`]).
    static ALSO: std::cell::RefCell<serde_json::Map<String, Value>>;
}

/// Adds `key` to the `--json` answer of the command that runs, for what its
/// lines say to people and a program needs as data (a token, what a
/// restore did); nothing without `--json`.
pub(super) fn also(key: &str, value: Value) {
    let _ = ALSO.try_with(|m| m.borrow_mut().insert(key.into(), value));
}

/// Runs a command without a form of its own: the lines it prints as
/// `{"messages": [...]}`, and what it added with [`also`], such as
/// `"next_start": true` when the node takes the change only at its next
/// start ([`waits_for_next_start`]).
pub(super) async fn changed(paths: NodePaths, cmd: Cmd, out: &mut dyn Write) -> Result<(), String> {
    let mut text = Vec::new();
    let (r, fields) = ALSO
        .scope(std::cell::RefCell::default(), async {
            let r = said(paths, cmd, &mut text).await;
            (r, ALSO.with(|m| m.take()))
        })
        .await;
    r?;
    let text = String::from_utf8_lossy(&text);
    let messages: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let mut v = json!({ "messages": messages });
    for (k, f) in fields {
        v[k] = f;
    }
    print(out, v)
}

/// Whether the command runs with `--json` and without a form of its own
/// ([`changed`]): its output is printed only once it is done, so it may not
/// ask a question on it.
#[cfg_attr(windows, allow(dead_code))]
pub(super) fn active() -> bool {
    ALSO.try_with(|_| ()).is_ok()
}

fn print(out: &mut dyn Write, v: Value) -> Result<(), String> {
    writeln!(out, "{v}").map_err(|e| format!("cannot write the answer: {e}"))
}

/// Runs a command that [`own_form`] names.
pub(super) async fn command(
    paths: &NodePaths,
    cmd: Cmd,
    out: &mut dyn Write,
) -> Result<(), String> {
    let v = match cmd {
        Cmd::Status => status(paths).await?,
        Cmd::Audit {
            clear: None,
            follow,
            refused,
            last,
        } => return audit(paths, follow, refused, last, true, out).await,
        Cmd::Log {
            clear: None,
            follow,
            last,
            problems,
        } => return log_cmd(paths, follow, last, problems, true, out).await,
        Cmd::Center { cmd: None } => centers(paths).await?,
        Cmd::Center {
            cmd: Some(CenterCmd::Add { link, name, yes }),
        } => {
            let link = given_link(&link)?;
            pair(paths, &link, name.as_deref(), yes).await?
        }
        Cmd::Mode {
            mode: None,
            for_hours,
            as_owner,
            center,
        } => {
            if for_hours.is_some() || as_owner {
                return Err("name the mode: `nerve-node mode allowlist|folder|user`".into());
            }
            let (cfg, _) = read_config(paths).await?;
            let names = match &center.center {
                Some(_) => vec![pick_center(&cfg, &center)?],
                None => cfg.centers.iter().map(|c| c.name.clone()).collect(),
            };
            let now = crate::now_ms();
            let modes: Vec<Value> = names
                .iter()
                .map(|n| mode_data(n, &cfg.center(n).expect("listed").policy, now))
                .collect();
            json!({ "modes": modes })
        }
        Cmd::Folder { cmd: None, center } => {
            let (cfg, _) = read_config(paths).await?;
            let name = pick_center(&cfg, &center)?;
            let policy = &cfg.center(&name).expect("picked").policy;
            let folders: Vec<Value> = policy
                .folders
                .iter()
                .map(|f| {
                    json!({
                        "path": f.path,
                        "rights": f.access.to_chmod(),
                        "read": f.access.read,
                        "write": f.access.write,
                        "execute": f.access.execute,
                    })
                })
                .collect();
            json!({ "center": name, "folders": folders, "no_network": policy.no_network })
        }
        Cmd::Rule {
            cmd: None,
            list,
            center,
        } => {
            let (cfg, _) = read_config(paths).await?;
            let name = pick_center(&cfg, &center)?;
            let mut policy = cfg.center(&name).expect("picked").policy.clone();
            // The guard is built in: its rules apart, and no stored copy of
            // them on the deny list.
            policy.deny.retain(|r| !rules::is_guard(r));
            let mut v = json!({ "center": name, "guard": rules::GUARD });
            let lists = match list {
                Some(l) => vec![l],
                None => vec![List::Allow, List::Deny, List::Sudo],
            };
            let mut shown = Vec::new();
            for l in lists {
                v[l.word()] = json!(l.of(&mut policy));
                if l != List::Sudo {
                    shown.extend(l.of(&mut policy).clone());
                }
            }
            // The rules whose conditions no longer fit the action's
            // arguments, each with why (`rule` says it after the rules).
            let stale = stale_rules(paths, &cfg, &name, shown.iter()).await?;
            v["stale"] = Value::Object(
                stale
                    .into_iter()
                    .map(|(r, why)| (r, Value::String(why)))
                    .collect(),
            );
            v
        }
        Cmd::Cap { cmd: None, center } => {
            let (cfg, _) = read_config(paths).await?;
            let mut v = cap_listing(paths, &cfg).await?;
            // One center's switches as the app reads them, besides: with
            // `--center`, or where only one is paired.
            let picked = match &center {
                Some(c) => Some(
                    cfg.center(c)
                        .ok_or_else(|| no_center_named(&cfg, c))?
                        .name
                        .clone(),
                ),
                None if cfg.centers.len() == 1 => Some(cfg.centers[0].name.clone()),
                None => None,
            };
            if let Some(name) = picked {
                let entry = cfg.center(&name).expect("picked");
                let caps: serde_json::Map<String, Value> = entry
                    .policy
                    .caps
                    .iter()
                    .map(|(cap, s)| (cap.clone(), json!(enum_str(s))))
                    .collect();
                // What `cap set` switches here, so a program need not know it.
                let known: serde_json::Map<String, Value> =
                    crate::descriptor::switchable(&cfg, entry)
                        .into_iter()
                        .map(|(cap, actions)| (cap, json!(actions)))
                        .collect();
                v["center"] = json!(name);
                v["caps"] = json!(caps);
                v["known"] = json!(known);
            }
            v
        }
        Cmd::Provider { cmd: None } => {
            let (cfg, _) = read_config(paths).await?;
            let v = cap_listing(paths, &cfg).await?;
            json!({"programs": v["programs"], "running": v["running"]})
        }
        Cmd::Config(ConfigCmd::Get { key }) => {
            let (cfg, _) = read_config(paths).await?;
            let v = setting(&cfg, &key)?;
            let value = serde_json::to_value(&v).map_err(|e| e.to_string())?;
            let mut v = json!({ "key": key, "value": value });
            // A program that offers the choice, as setup does, needs to know
            // whether the keyring can be one here.
            if key == "machine.secret_storage" {
                v["keyring"] = keyring_here(paths);
            }
            v
        }
        Cmd::Proxy { cmd: None } => proxy(paths).await?,
        Cmd::Relay { cmd: None } => relay(paths).await?,
        Cmd::Sudo { cmd: None } => {
            json!({ "sudo": if sudo_is_on(paths).await? { "on" } else { "off" } })
        }
        _ => return Err("this command has no JSON form of its own".into()),
    };
    print(out, v)
}

/// Whether the node's keys could go into the system keyring here: where
/// `setup` would not offer it (`reason` `windows-service`), and whether a keyring answers for the account the node
/// runs as (`no-answer`); `why` says it in words.
fn keyring_here(paths: &NodePaths) -> Value {
    if let Some(n) = crate::secrets::no_keyring(paths) {
        let reason = match n {
            crate::secrets::NoKeyring::WindowsService => "windows-service",
        };
        return json!({ "usable": false, "reason": reason, "why": n.why() });
    }
    // The installed program, which the node's user can run, asks its
    // keyring, as setup's does.
    let layout = Layout::system();
    let keyring = if layout.installed() && *paths == layout.paths {
        crate::keyring_setup::HostKeyring {
            exe: layout.bin.clone(),
        }
    } else {
        crate::keyring_setup::HostKeyring::this_program()
    };
    let answer = crate::keyring_setup::me().and_then(|me| {
        use crate::keyring_setup::Keyring;
        keyring
            .check(&me)
            .map_err(|e| format!("no system keyring answers for {} ({e})", me.name))
    });
    match answer {
        Ok(()) => json!({ "usable": true }),
        Err(why) => json!({ "usable": false, "reason": "no-answer", "why": why }),
    }
}

/// `status`: what the running node says of itself, with `"daemon":
/// "running"`; else what the config says, with `"daemon": "not running"`
/// and no link status for the centers.
pub(super) async fn status(paths: &NodePaths) -> Result<Value, String> {
    // The installed service: whether it is there, runs, starts with the
    // machine, and its program's version.
    let service = service_status(&Layout::system()).unwrap_or(Value::Null);
    let closed = crate::service::check_access(paths).is_err();
    with_service(node_status(paths).await, service, closed)
}

/// The node's status with the installed `service` in it. A stopped
/// installed node whose folders this account may not open (`closed`) still
/// says its service, which needs no rights on them (the app shows Stopped
/// and its Start button from it), and why the rest is not shown (`unread`).
/// Any other failure, a `node.toml` that does not parse too, is the answer.
pub(crate) fn with_service(
    node: Result<Value, String>,
    service: Value,
    closed: bool,
) -> Result<Value, String> {
    let mut v = match node {
        Ok(v) => v,
        Err(why) if closed && service["installed"] == true && service["state"] != "running" => {
            json!({ "daemon": "not running", "unread": why })
        }
        Err(e) => return Err(e),
    };
    v["service"] = service;
    Ok(v)
}

async fn node_status(paths: &NodePaths) -> Result<Value, String> {
    if let Some(mut v) = live_status(paths).await? {
        v["daemon"] = json!("running");
        return Ok(v);
    }
    let cfg = SettingsStore::peek_with(
        &paths.config_file(),
        &crate::secrets::NodeSecrets::for_cli(paths),
    )?;
    let now = crate::now_ms();
    let centers: Vec<Value> = cfg
        .centers
        .iter()
        .map(|c| {
            let mut v = center(paths, c, now);
            v["status"] = Value::Null;
            v
        })
        .collect();
    let sudo = sudo_is_on(paths).await?;
    let mut v = stopped(&cfg, crate::service::owner_of(paths), sudo, centers);
    // Said as the running node says it.
    v["pairings_warning"] = json!(super::pairings_warning_here(paths, &cfg));
    Ok(v)
}

/// The `status` of a node that does not run, with its `owner` as the unit
/// names it, whether `sudo` is on, and its `centers`.
fn stopped(cfg: &NodeConfig, owner: Option<String>, sudo: bool, centers: Vec<Value>) -> Value {
    json!({
        "daemon": "not running",
        "version": cfg.version,
        "locked": cfg.locked,
        "owner_is_root": crate::owner::is_root(owner.as_deref()),
        "owner": owner,
        "sudo": if sudo { "on" } else { "off" },
        "command_limits": crate::cgroup::status(
            &cfg.limits.command,
            &Err("the node does not run".into()),
        ),
        "centers": centers,
    })
}

/// One center as `center` and a stopped node's `status` show it.
fn center(paths: &NodePaths, c: &nerve_policy::CenterEntry, now: u64) -> Value {
    let mut v = json!({
        "name": c.name,
        "url": c.url,
        "mode": c.policy.mode_at(now).as_str(),
        "until": c.policy.until,
        "then": c.policy.ends(now).map(|(_, m)| m.as_str()),
        "as_owner": c.policy.as_owner,
        "no_network": c.policy.no_network,
        "folders": c.policy.folders.len(),
        "allow_rules": c.policy.allow.len(),
        "deny_rules": c.policy.deny.iter().filter(|r| !rules::is_guard(r)).count(),
        "sudo_rules": c.policy.sudo_allow.len(),
        "settings": c.settings,
        "paused": c.paused,
        "revoked": c.revoked,
        "unknown": c.unknown,
    });
    // Which `nerve.*` profile is this pairing's (docs/user/modes.md).
    if cfg!(windows) {
        v["appcontainer"] = json!(crate::grants::profile_name(paths, &c.node_id));
    }
    v
}

/// `center`.
async fn centers(paths: &NodePaths) -> Result<Value, String> {
    let (cfg, _) = read_config(paths).await?;
    let now = crate::now_ms();
    let centers: Vec<Value> = cfg.centers.iter().map(|c| center(paths, c, now)).collect();
    Ok(json!({ "centers": centers }))
}

/// `center add`: without `--yes` what the owner confirms, and nothing is
/// paired (a program asks its user, then runs it again with `--yes`); with
/// it, the new pairing.
async fn pair(
    paths: &NodePaths,
    link: &str,
    name: Option<&str>,
    yes: bool,
) -> Result<Value, String> {
    let link = PairLink::parse(link)?;
    if !yes {
        let check = crate::pair::check(paths, &link).await?;
        return Ok(json!({
            "paired": false,
            "preview": {
                "center": link.center.to_string(),
                "tls": link.center.tls,
                "pin": link.pin,
                "name": name,
            },
            "check": check.json(),
        }));
    }
    let before = std::fs::read(paths.config_file()).ok();
    let e = crate::pair::pair(paths, &link, name).await?;
    let mut v = json!({ "paired": true, "name": e.name, "url": e.url, "messages": [] });
    if std::fs::read(paths.config_file()).ok() != before && !daemon_answers(paths, false).await {
        v["messages"] = json!([in_file_line()]);
        v["next_start"] = json!(true);
    }
    Ok(v)
}

/// `proxy`: the proxy, its pin and login, the names of its headers, and
/// why the link cannot use it, when it cannot. Never a secret.
async fn proxy(paths: &NodePaths) -> Result<Value, String> {
    let (cfg, _) = read_config(paths).await?;
    let c = &cfg.connection;
    let Some(url) = &c.proxy else {
        return Ok(json!({ "proxy": null }));
    };
    let storage = cfg.machine.secret_storage;
    let mut problem = None;
    if c.login.is_some()
        && let Err(e) = crate::secrets::proxy_login(paths, storage)
    {
        problem = Some(e);
    }
    if let Err(e) = crate::secrets::proxy_headers(paths, &c.headers) {
        problem.get_or_insert(e);
    }
    Ok(json!({
        "proxy": url,
        "pin": c.pin,
        "login": c.login,
        "password_kept_in": c.login.as_ref().map(|_| keys_place(storage)),
        "headers": c.headers,
        "problem": problem,
    }))
}

/// `relay`: the relay's settings, the nodes that may use it, and on a
/// running node its state and open tunnels (`null` when none runs).
async fn relay(paths: &NodePaths) -> Result<Value, String> {
    let (cfg, _) = read_config(paths).await?;
    let r = &cfg.relay;
    let live = live_status(paths).await?.map(|v| v["relay"].clone());
    let nodes: Vec<Value> = r
        .nodes
        .iter()
        .map(|n| {
            json!({
                "name": n.name,
                "centers": n.centers,
                "max_links": n.links(r),
                "max_opens_per_minute": n.opens(r),
                "own_limits": n.max_links.is_some() || n.max_opens_per_minute.is_some(),
            })
        })
        .collect();
    Ok(json!({
        "listen": r.listen,
        // Where a new link says the relay is, unless told otherwise.
        "address": super::link_address(r.listen.as_deref(), None).ok(),
        "status": live.as_ref().map(|v| v["status"].clone()),
        "max_links": r.max_links,
        "max_links_per_node": r.max_links_per_node,
        "max_opens_per_minute": r.max_opens_per_minute,
        "pin": r.pin,
        "nodes": nodes,
        "tunnels": live.as_ref().map(|v| v["tunnels"].clone()),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A command runs with `--json` within [`changed`]'s scope, and only
    /// there does [`active`] say so.
    #[test]
    fn active_only_with_json() {
        assert!(!active());
        assert!(ALSO.sync_scope(std::cell::RefCell::default(), active));
    }

    /// A stopped node's status says when root is the owner, as the app's
    /// Overview warns of it whether the node runs or not.
    #[test]
    fn a_stopped_status_says_when_root_is_the_owner() {
        let cfg = NodeConfig::default();
        let v = stopped(&cfg, Some("root".into()), false, Vec::new());
        assert_eq!(v["owner"], "root");
        assert_eq!(v["owner_is_root"], !cfg!(windows));
        for owner in [Some("alice".to_string()), None] {
            let v = stopped(&cfg, owner.clone(), false, Vec::new());
            assert_eq!(v["owner_is_root"], false, "{owner:?}");
            assert_eq!(v["owner"], json!(owner));
        }
    }
}
