//! `nerve-node status`: how the node is, and what to do next.

use super::*;

/// What `status` says of the limits per command (crate::cgroup::status):
/// what a command gets and may ask for, then where they hold or why not.
fn limits_lines(v: &Value) -> Vec<String> {
    limits_lines_on(v, cfg!(windows))
}

/// [`limits_lines`] in the words of Linux's cgroup, or of Windows' job object
/// (`windows`), which the node names itself in `cgroup`.
fn limits_lines_on(v: &Value, windows: bool) -> Vec<String> {
    let n = |k: &str| v[k].as_u64().unwrap_or_default();
    let mut lines = vec![format!(
        "limits per command: memory {} MiB, CPU {} %, {} processes; a call may ask for up to {} MiB, {} %, {} processes",
        n("memory_mb"),
        n("cpu_percent"),
        n("processes"),
        n("memory_max_mb"),
        n("cpu_max_percent"),
        n("processes_max"),
    )];
    let list = |k: &str| -> Vec<&str> {
        v[k].as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect()
    };
    let (enforced, lost) = (list("enforced"), list("lost"));
    if let Some(cgroup) = v["cgroup"].as_str() {
        let (holder, lacks, gone) = if windows {
            (
                cgroup.to_string(),
                "it holds no limit for it",
                "its job object",
            )
        } else {
            (
                format!("the cgroup {cgroup}"),
                "the cgroup has no controller for it",
                "the cgroup",
            )
        };
        let not: Vec<&str> = ["memory", "cpu", "processes"]
            .into_iter()
            .filter(|l| !enforced.contains(l) && !lost.contains(l))
            .collect();
        let mut line = match enforced.is_empty() {
            true => format!("limits held by {holder}: none"),
            false => format!("limits held by {holder}: {}", enforced.join(", ")),
        };
        if !not.is_empty() {
            line.push_str(&format!("; not {} ({lacks})", not.join(", ")));
        }
        lines.push(line);
        // Turned off while the node ran: no command runs (crate::cgroup).
        if !lost.is_empty() {
            lines.push(format!(
                "NO COMMAND RUNS: {} turned off in {gone} since the node started; start the node again",
                lost.join(", ")
            ));
        }
    } else if let Some(why) = v["off"].as_str() {
        lines.push(format!("commands run WITHOUT these limits: {why}"));
    }
    lines
}

/// The running node's status: over the control socket, on Windows over its
/// pipe; `None` when no node runs.
pub(super) async fn live_status(paths: &NodePaths) -> Result<Option<Value>, String> {
    #[cfg(unix)]
    let r = nerve_transport::ctl::call(&paths.ctl_socket(), "status", json!({})).await;
    #[cfg(windows)]
    let r = crate::pipe::call(paths, "status", json!({})).await;
    match r {
        Ok(v) => Ok(Some(v)),
        Err(e) if crate::cli::no_node(paths, &e) => Ok(None),
        Err(e) => Err(e),
    }
}

/// `status`: how the node is, and what to do next.
pub(super) async fn status(paths: NodePaths, out: &mut dyn Write) -> Result<(), String> {
    // The same data as `status --json`, for people.
    let v = json::status(&paths).await?;
    for line in status_lines(&v) {
        w(out, line);
    }
    Ok(())
}

/// The line of `status` on the node's owner, which says plainly what root
/// as the owner means, and on Windows an administrator.
fn owner_line(owner: Option<&str>, root: bool, admin: bool) -> Option<String> {
    match (owner, root, admin) {
        (Some(_), true, _) => Some(format!("owner: {}", crate::owner::ROOT_OWNER_NOTE)),
        (Some(o), false, true) => Some(format!("owner: {}", crate::owner::admin_owner_note(o))),
        (Some(o), false, false) => Some(format!("owner: {o}")),
        (None, ..) => None,
    }
}

/// What `status` says of the node, from `status --json`'s `v` (a running
/// node's answer, or what the config says of a stopped one), a line each:
/// the node and its service, the warnings, each center, and the next step.
fn status_lines(v: &Value) -> Vec<String> {
    let running = v["daemon"] != "not running";
    let mut lines = vec![match running {
        true => format!(
            "node: running (confinement {})",
            v["confinement"].as_str().unwrap_or("?")
        ),
        false => "node: not running".to_string(),
    }];
    lines.extend(service_line(&v["service"]));
    if let Some(why) = v["unread"].as_str() {
        lines.push(format!(
            "centers: not shown while the node is stopped, its folders are not yours to read ({why})"
        ));
    }
    if let Some(why) = v["folder_commands_off"].as_str() {
        lines.push(format!("folder mode runs no command: {why}"));
    }
    // A stopped node knows only the limits it would set.
    let limits = match v["command_limits"].is_null() {
        true => Vec::new(),
        false => limits_lines(&v["command_limits"]),
    };
    match running {
        true => lines.extend(limits),
        false => lines.extend(limits.into_iter().take(1)),
    }
    if v["locked"] == true {
        lines.push("LOCKED (panic): nothing runs until `nerve-node unlock`".into());
    }
    if let Some(s) = v["sudo"].as_str() {
        lines.push(format!("sudo: {s}"));
    }
    lines.extend(owner_line(
        v["owner"].as_str(),
        v["owner_is_root"] == true,
        v["owner_is_admin"] == true,
    ));
    if let Some(h) = v["home_warning"]["warning"].as_str() {
        lines.push(format!("warning: {h}"));
    }
    if let Some(l) = v["landlock_warning"].as_str() {
        lines.push(format!("warning: {l}"));
    }
    if let Some(p) = v["pairings_warning"].as_str() {
        lines.push(format!("warning: {p}"));
    }
    if let Some(p) = v["processes_warning"].as_str() {
        lines.push(format!("warning: {p}"));
    }
    lines.extend(
        grant_lines(&v["folder_access"])
            .into_iter()
            .map(|l| format!("warning: {l}")),
    );
    for c in v["centers"].as_array().into_iter().flatten() {
        // The installed node says as whom its commands run. Where Landlock
        // is missing nerve-run runs without it.
        let whom = match c["account"].as_str() {
            Some(a) if a == crate::account::RUN_USER && c["landlock"] == false => {
                format!(", as {a}, without Landlock")
            }
            Some(a) => format!(", as {a}"),
            None => String::new(),
        };
        // A timed mode says how long it has and where it ends.
        let timer = match (
            c["until"].as_u64().filter(|u| *u > crate::now_ms()),
            c["then"].as_str(),
        ) {
            (Some(until), Some(then)) => {
                let left = until.saturating_sub(crate::now_ms());
                let then = Mode::parse(then).unwrap_or(Mode::Allowlist);
                let rules = c["allow_rules"].as_u64().unwrap_or(0) as usize;
                format!(
                    " for {} more, then {}",
                    nerve_transport::log::span(Duration::from_millis(left)),
                    then_text(then, rules, c["as_owner"] == true)
                )
            }
            _ => String::new(),
        };
        // A stopped node has no link to tell: the center's address then.
        let link = c["status"]
            .as_str()
            .or_else(|| c["url"].as_str())
            .unwrap_or_default();
        lines.push(format!(
            "{}  {link}  mode {}{timer}{whom}",
            c["name"].as_str().unwrap_or_default(),
            c["mode"].as_str().unwrap_or_default(),
        ));
        lines.extend(center_summary(c));
    }
    for p in v["providers"].as_array().into_iter().flatten() {
        let caps: Vec<&str> = p["capabilities"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let name = p["name"].as_str().unwrap_or_default();
        lines.push(format!("provider {name} attached: {}", caps.join(", ")));
        // Actions whose schemas a center cannot check are not offered.
        for b in p["broken"].as_array().into_iter().flatten() {
            lines.push(format!(
                "provider {name}: {} left out: {}",
                b["name"].as_str().unwrap_or_default(),
                b["reason"].as_str().unwrap_or_default()
            ));
        }
    }
    let relay = &v["relay"];
    if relay["listen"].is_string() {
        let tunnels = relay["tunnels"].as_array().map_or(0, Vec::len);
        lines.push(format!(
            "relay: {}, {tunnels} tunnels open (`nerve-node relay` names them)",
            relay["status"].as_str().unwrap_or_default()
        ));
    }
    lines.extend(next_steps(v).into_iter().map(|s| format!("next: {s}")));
    lines
}

/// What `status` says of the installed service, from `status --json`'s
/// `service` (`None` where there is none to tell).
fn service_line(s: &Value) -> Option<String> {
    if s.is_null() {
        return None;
    }
    let Some(state) = s["state"].as_str() else {
        return Some("service: not installed (this node runs by hand)".into());
    };
    let boot = match s["enabled"].as_bool() {
        Some(true) => ", starts with the machine",
        Some(false) => ", does not start with the machine",
        None => "",
    };
    let version = s["version"]
        .as_str()
        .map_or_else(String::new, |v| format!(", version {v}"));
    Some(format!("service: {state}{boot}{version}"))
}

/// One center's rights in a line, for `status`: its folders, its network,
/// and how many rules each list has.
fn center_summary(c: &Value) -> Option<String> {
    let n = |k: &str| c[k].as_u64();
    let (folders, allow, deny, sudo) = (
        n("folders")?,
        n("allow_rules")?,
        n("deny_rules")?,
        n("sudo_rules")?,
    );
    let network = if c["no_network"] == true { "off" } else { "on" };
    Some(format!(
        "  folders: {folders}; network: {network}; rules: {allow} allow, {deny} deny and the guard, {sudo} sudo"
    ))
}

/// What to do next, from `status --json`'s `v`: start a node that does
/// not run, pair a first center, give a folder-mode center a folder.
fn next_steps(v: &Value) -> Vec<String> {
    let mut steps = Vec::new();
    if v["daemon"] == "not running" {
        steps.push(match v["service"]["state"].as_str() {
            Some(_) => "start it: `nerve-node service start`".to_string(),
            None => "start it: `sudo nerve-node install` installs it as a service (or `nerve-node run` in the foreground)".to_string(),
        });
    }
    if v["locked"] == true {
        steps.push("let it work again: `nerve-node unlock`".into());
    }
    // Its centers were not read: none to pair or to give a folder.
    if v["unread"].is_string() {
        return steps;
    }
    let centers = v["centers"].as_array().cloned().unwrap_or_default();
    if centers.is_empty() {
        steps.push("pair a center: `nerve-node center add -`, then paste the link".into());
    }
    for c in &centers {
        if c["mode"] == "folder" && c["folders"].as_u64() == Some(0) {
            let name = c["name"].as_str().unwrap_or_default();
            let which = match centers.len() {
                1 => String::new(),
                _ => format!(" --center {name}"),
            };
            steps.push(format!(
                "give {name} a folder: `nerve-node folder add ~/project rwx{which}`"
            ));
        }
    }
    steps
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use crate::cli::tests::{run, setup};

    /// `status` of a running node: as whom each pairing runs and whether
    /// without Landlock, what nerve-run may read of the owner's home, and
    /// the folder grants, access nerve-run should have lost worded as such
    /// (#142).
    #[test]
    fn the_status_says_landlock_the_home_and_the_grants() {
        let v = json!({
            "confinement": "landlock abi 6",
            "owner": "alice",
            "home_warning": {"warning": "Without Landlock, nerve-run can read every file in your home /home/alice"},
            "landlock_warning": "this kernel's Landlock is ABI 4, which does not guard device ioctls",
            "pairings_warning": "Without Landlock nothing keeps the pairings apart: the commands of a, b all run as nerve-run",
            "folder_access": {
                "stale": ["/home/alice/gone", "/var/lib/nerve/state/acl.json"],
                "errors": [
                    "/home/alice/gone/x: Permission denied (os error 13)",
                    "/var/lib/nerve/state/acl.json: expected value at line 1",
                    "/home/alice/usb: its file system does not support POSIX ACLs",
                ],
            },
            "centers": [
                {"name": "a", "status": "connected", "mode": "folder", "account": "nerve-run", "landlock": false},
                {"name": "b", "status": "connected", "mode": "folder", "account": "nerve-run", "landlock": true},
                {"name": "c", "status": "connected", "mode": "user", "account": "alice", "landlock": false},
                {"name": "d", "status": "connected", "mode": "folder"},
            ],
        });
        let lines = status_lines(&v);
        let has = |l: &str| lines.iter().any(|x| x == l);
        assert!(has("owner: alice"), "{lines:#?}");
        assert!(
            has(
                "warning: Without Landlock, nerve-run can read every file in your home /home/alice"
            ),
            "{lines:#?}"
        );
        assert!(
            has("warning: this kernel's Landlock is ABI 4, which does not guard device ioctls"),
            "{lines:#?}"
        );
        assert!(
            has(
                "warning: Without Landlock nothing keeps the pairings apart: the commands of a, b all run as nerve-run"
            ),
            "{lines:#?}"
        );
        assert!(
            has("a  connected  mode folder, as nerve-run, without Landlock"),
            "{lines:#?}"
        );
        assert!(has("b  connected  mode folder, as nerve-run"), "{lines:#?}");
        assert!(has("c  connected  mode user, as alice"), "{lines:#?}");
        assert!(has("d  connected  mode folder"), "{lines:#?}");
        assert!(
            has(
                "warning: nerve-run keeps its access to /home/alice/gone, which it should have lost; no command of nerve-run runs until it is taken off: /home/alice/gone/x: Permission denied (os error 13)"
            ),
            "{lines:#?}"
        );
        assert!(
            has(
                "warning: nerve-run keeps its access to /var/lib/nerve/state/acl.json, which it should have lost; no command of nerve-run runs until it is taken off: /var/lib/nerve/state/acl.json: expected value at line 1"
            ),
            "{lines:#?}"
        );
        assert!(
            has(
                "warning: nerve-run did not get every folder: /home/alice/usb: its file system does not support POSIX ACLs"
            ),
            "{lines:#?}"
        );
        assert_eq!(
            lines.iter().filter(|l| l.contains("did not get")).count(),
            1,
            "{lines:#?}"
        );
        // Root as the owner is said plainly.
        let root = status_lines(&json!({"owner": "root", "owner_is_root": true}));
        assert!(
            root.iter()
                .any(|l| *l == format!("owner: {}", crate::owner::ROOT_OWNER_NOTE)),
            "{root:#?}"
        );
        assert!(crate::owner::ROOT_OWNER_NOTE.contains("run as root"));
        assert_eq!(owner_line(None, false, false), None);
        // So is a kernel that gives no command a /proc of its own (#199).
        let shared = status_lines(&json!({"processes_warning": "they see each other"}));
        assert!(
            shared.contains(&"warning: they see each other".to_string()),
            "{shared:#?}"
        );
        // An administrator as the owner on Windows is its twin (#197).
        let admin = status_lines(&json!({"owner": "alice", "owner_is_admin": true}));
        assert!(
            admin.contains(&format!(
                "owner: {}",
                crate::owner::admin_owner_note("alice")
            )),
            "{admin:#?}"
        );
        assert!(crate::owner::admin_owner_note("alice").contains("alice is an administrator"));
        // So does a stopped node's.
        let root_line = format!("owner: {}", crate::owner::ROOT_OWNER_NOTE);
        let stopped = |owner: Option<&str>| {
            status_lines(&json!({
                "daemon": "not running",
                "owner": owner,
                "owner_is_root": crate::owner::is_root(owner),
            }))
        };
        assert_eq!(stopped(Some("root"))[0], "node: not running");
        assert_eq!(
            stopped(Some("root")).contains(&root_line),
            !cfg!(windows),
            "{:#?}",
            stopped(Some("root"))
        );
        let alice = stopped(Some("alice"));
        assert!(alice.contains(&"owner: alice".to_string()), "{alice:#?}");
        assert!(!alice.contains(&root_line), "{alice:#?}");
        assert!(
            !stopped(None).iter().any(|l| l.starts_with("owner:")),
            "no owner, no line"
        );
        // Nothing of the kind on a node that has none of it.
        let plain = status_lines(&json!({"confinement": "landlock abi 6"})).join("\n");
        assert!(
            !plain.contains("warning") && !plain.contains("Landlock,"),
            "{plain}"
        );
    }

    /// A timer that ends in allowlist mode as the owner says so, as `mode`
    /// does (#197).
    #[test]
    fn the_status_says_a_timer_ends_as_the_owner() {
        let until = crate::now_ms() + 3_600_000;
        let line = |as_owner: bool| {
            let lines = status_lines(&json!({
                "daemon": "not running",
                "centers": [{"name": "lab", "url": "https://c.example", "mode": "folder",
                             "until": until, "then": "allowlist", "as_owner": as_owner,
                             "folders": 0, "allow_rules": 1, "deny_rules": 0, "sudo_rules": 0}],
            }));
            lines.into_iter().find(|l| l.starts_with("lab ")).unwrap()
        };
        assert!(
            line(true).contains(", then allowlist (1 allow rule), as you"),
            "{}",
            line(true)
        );
        assert!(!line(false).contains("as you"), "{}", line(false));
    }

    /// `status` is one place to look: the node and its service, each
    /// center's mode and what it may do, and the next step to take.
    #[test]
    fn the_status_says_the_service_each_center_and_the_next_step() {
        let lines = status_lines(&json!({
            "daemon": "not running",
            "sudo": "off",
            "service": {"installed": true, "state": "stopped", "enabled": true, "version": "0.0.7"},
            "centers": [],
        }));
        assert_eq!(
            lines,
            [
                "node: not running",
                "service: stopped, starts with the machine, version 0.0.7",
                "sudo: off",
                "next: start it: `nerve-node service start`",
                "next: pair a center: `nerve-node center add -`, then paste the link",
            ]
        );
        let by_hand = status_lines(&json!({
            "daemon": "not running",
            "service": {"installed": false, "state": null},
            "centers": [{"name": "lab", "url": "https://c.example", "mode": "allowlist",
                         "folders": 0, "allow_rules": 1, "deny_rules": 2, "sudo_rules": 0}],
        }));
        assert!(
            by_hand.contains(&"service: not installed (this node runs by hand)".to_string()),
            "{by_hand:#?}"
        );
        assert!(
            by_hand
                .iter()
                .any(|l| l.contains("`sudo nerve-node install`")),
            "{by_hand:#?}"
        );
        assert!(
            by_hand.contains(&"lab  https://c.example  mode allowlist".to_string()),
            "{by_hand:#?}"
        );
        assert!(
            by_hand.contains(
                &"  folders: 0; network: on; rules: 1 allow, 2 deny and the guard, 0 sudo"
                    .to_string()
            ),
            "{by_hand:#?}"
        );
        // A running node with a folder-mode center and no folder: give it one.
        let lines = status_lines(&json!({
            "confinement": "landlock abi 6",
            "centers": [
                {"name": "lab", "status": "connected", "mode": "folder", "no_network": true,
                 "folders": 0, "allow_rules": 0, "deny_rules": 0, "sudo_rules": 0},
                {"name": "home", "status": "the center is older than this node: update it first", "mode": "folder",
                 "folders": 1, "allow_rules": 0, "deny_rules": 0, "sudo_rules": 0},
            ],
        }));
        assert!(
            lines.contains(
                &"  folders: 0; network: off; rules: 0 allow, 0 deny and the guard, 0 sudo"
                    .to_string()
            ),
            "{lines:#?}"
        );
        assert!(
            lines.contains(
                &"next: give lab a folder: `nerve-node folder add ~/project rwx --center lab`"
                    .to_string()
            ),
            "{lines:#?}"
        );
        assert!(!lines.iter().any(|l| l.contains("give home")), "{lines:#?}");
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("home  the center is older than this node")),
            "{lines:#?}"
        );
        // `service status` is gone: `status` says it.
        assert!(Cli::try_parse_from(["nerve-node", "service", "status"]).is_err());
    }

    /// `status` shows the limits per command the owner set, and whether
    /// the running node holds commands to them, or why not.
    #[cfg(unix)]
    #[test]
    fn the_status_shows_the_limits_per_command() {
        let (d, paths) = setup(&[]);
        run(
            &paths,
            &["config", "set", "limits.command.memory_mb", "512"],
        )
        .unwrap();
        let out = run(&paths, &["status"]).unwrap();
        assert!(
            out.contains("limits per command: memory 512 MiB, CPU 200 %, 1024 processes; a call may ask for up to 16384 MiB, 800 %, 8192 processes"),
            "{out}"
        );
        let (ready_tx, ready) = std::sync::mpsc::channel();
        let (stop, stop_rx) = std::sync::mpsc::channel::<()>();
        let node = {
            let (home, paths) = (d.path().to_path_buf(), paths.clone());
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                let mut opts = NodeOptions::new(paths);
                opts.home = home;
                opts.full_rights = Some(false);
                opts.cgroups = Some(Err("no cgroup for this test".into()));
                let daemon = rt.block_on(Daemon::start(opts)).unwrap();
                ready_tx.send(()).unwrap();
                rt.block_on(async {
                    while stop_rx.try_recv().is_err() {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    daemon.stop().await;
                });
            })
        };
        ready.recv().unwrap();
        let out = run(&paths, &["status"]);
        stop.send(()).unwrap();
        node.join().unwrap();
        let out = out.unwrap();
        assert!(out.contains("limits per command: memory 512 MiB"), "{out}");
        assert!(
            out.contains("commands run WITHOUT these limits: no cgroup for this test"),
            "{out}"
        );
    }

    #[test]
    fn the_status_names_the_cgroup_and_what_it_holds() {
        let v = json!({"memory_mb": 1, "memory_max_mb": 2, "cpu_percent": 3,
                       "cpu_max_percent": 4, "processes": 5, "processes_max": 6,
                       "cgroup": "/system.slice/nerve-node.service",
                       "enforced": ["memory", "processes"], "off": null});
        assert_eq!(
            limits_lines(&v),
            [
                "limits per command: memory 1 MiB, CPU 3 %, 5 processes; a call may ask for up to 2 MiB, 4 %, 6 processes",
                "limits held by the cgroup /system.slice/nerve-node.service: memory, processes; not cpu (the cgroup has no controller for it)",
            ]
        );
        // Turned off since the start: said apart from what the cgroup never
        // had, with what follows from it.
        let v = json!({"memory_mb": 1, "memory_max_mb": 2, "cpu_percent": 3,
                       "cpu_max_percent": 4, "processes": 5, "processes_max": 6,
                       "cgroup": "/", "enforced": [], "lost": ["memory", "processes"],
                       "off": null});
        assert_eq!(
            limits_lines(&v)[1..],
            [
                "limits held by the cgroup /: none; not cpu (the cgroup has no controller for it)",
                "NO COMMAND RUNS: memory, processes turned off in the cgroup since the node started; start the node again",
            ]
        );
    }

    /// On Windows the job object holds the limits, and the status says so
    /// instead of naming a cgroup.
    #[test]
    fn the_status_names_the_job_object_on_windows() {
        let v = json!({"memory_mb": 1, "memory_max_mb": 2, "cpu_percent": 3,
                       "cpu_max_percent": 4, "processes": 5, "processes_max": 6,
                       "cgroup": "the command's job object",
                       "enforced": ["memory", "cpu", "processes"], "off": null});
        assert_eq!(
            limits_lines_on(&v, true)[1],
            "limits held by the command's job object: memory, cpu, processes"
        );
        let v = json!({"memory_mb": 1, "memory_max_mb": 2, "cpu_percent": 3,
                       "cpu_max_percent": 4, "processes": 5, "processes_max": 6,
                       "cgroup": "the command's job object",
                       "enforced": ["memory"], "lost": ["processes"], "off": null});
        assert_eq!(
            limits_lines_on(&v, true)[1..],
            [
                "limits held by the command's job object: memory; not cpu (it holds no limit for it)",
                "NO COMMAND RUNS: processes turned off in its job object since the node started; start the node again",
            ]
        );
    }

    /// The running node says in its status whether it found no keyring.
    #[cfg(unix)]
    #[test]
    fn the_status_says_whether_the_node_found_no_keyring() {
        let (d, paths) = setup(&["home"]);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut opts = NodeOptions::new(paths.clone());
        opts.home = d.path().to_path_buf();
        opts.ctl = false;
        let daemon = rt.block_on(Daemon::start(opts)).unwrap();
        assert_eq!(daemon.status()["keyring_failed"], false);
        crate::secrets::store::set_unreachable(true);
        assert!(crate::secrets::store::get("any").is_err());
        assert_eq!(daemon.status()["keyring_failed"], true);
        crate::secrets::store::set_unreachable(false);
        rt.block_on(daemon.stop());
    }

    /// A stopped installed node whose folders the owner may not open still
    /// says its service, so the app shows Stopped and its Start button, and
    /// `status` names the next step, not pairing (round 1, correctness 3).
    #[test]
    fn a_stopped_node_says_its_service_without_its_folders() {
        let service =
            json!({"installed": true, "state": "stopped", "enabled": true, "version": "0.0.7"});
        let unread = Err("cannot read /etc/nerve/node.toml: permission denied".to_string());
        let v = json::with_service(unread, service.clone(), true).unwrap();
        assert_eq!(v["service"], service);
        let lines = status_lines(&v);
        assert!(
            lines.contains(&"service: stopped, starts with the machine, version 0.0.7".to_string()),
            "{lines:#?}"
        );
        assert!(
            lines.iter().any(|l| l.starts_with("centers: not shown")),
            "{lines:#?}"
        );
        assert!(
            lines.contains(&"next: start it: `nerve-node service start`".to_string()),
            "{lines:#?}"
        );
        assert!(
            !lines.iter().any(|l| l.contains("pair a center")),
            "{lines:#?}"
        );
        // A running service, or none: the error is the answer. So it is
        // where this account may open the folders (a `node.toml` that does
        // not parse): a stopped service does not hide it (round 2).
        let running = json!({"installed": true, "state": "running"});
        assert!(json::with_service(Err("x".into()), running, true).is_err());
        assert!(json::with_service(Err("x".into()), Value::Null, true).is_err());
        assert!(json::with_service(Err("cannot parse".into()), service, false).is_err());
    }
}
