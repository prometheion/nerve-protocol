//! `nerve-node status`: how the node is, and what to do next.

use nerve_service::out::{Page, Style, Tone};

use super::*;

/// A page of the node's ([`nerve_service::out`]).
pub(crate) fn page() -> Page {
    page_of(env!("CARGO_PKG_VERSION"))
}

/// A page of the node at `version`: the installed one's, which may be
/// another than this program's.
fn page_of(version: &str) -> Page {
    Page::new("Nerve node", version)
}

/// A size in MiB as people read it: whole GiB where it is that.
fn mib(n: u64) -> String {
    match n >= 1024 && n.is_multiple_of(1024) {
        true => format!("{} GiB", n / 1024),
        false => format!("{n} MiB"),
    }
}

/// What `status` shows of the limits per command (crate::cgroup::status):
/// what a command gets, and with `all` (a running node) what it may ask for
/// and where they hold, as rows, and where they do not as warnings.
fn limits_rows(v: &Value, all: bool, p: &mut Page) {
    limits_rows_on(v, cfg!(windows), all, p)
}

/// [`limits_rows`] in the words of Linux's cgroup, or of Windows' job
/// object (`windows`), which the node names itself in `cgroup`.
fn limits_rows_on(v: &Value, windows: bool, all: bool, p: &mut Page) {
    let n = |k: &str| v[k].as_u64().unwrap_or_default();
    p.row(
        "Limits",
        format!(
            "{} · {} % CPU · {} processes per command",
            mib(n("memory_mb")),
            n("cpu_percent"),
            n("processes"),
        ),
    );
    if !all {
        return;
    }
    p.row(
        "Up to",
        format!(
            "{} · {} % CPU · {} processes when a call asks",
            mib(n("memory_max_mb")),
            n("cpu_max_percent"),
            n("processes_max"),
        ),
    );
    let list = |k: &str| -> Vec<&str> {
        v[k].as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect()
    };
    let (enforced, lost) = (list("enforced"), list("lost"));
    if let Some(cgroup) = v["held_by"].as_str() {
        let (holder, lacks, gone) = match windows {
            true => (
                cgroup.to_string(),
                "it holds no limit for",
                "its job object",
            ),
            false => (
                format!("the cgroup {cgroup}"),
                "the cgroup has no controller for",
                "the cgroup",
            ),
        };
        p.row(
            "Held by",
            match enforced.is_empty() {
                true => format!("{holder}: none"),
                false => format!("{holder}: {}", enforced.join(" · ")),
            },
        );
        let not: Vec<&str> = ["memory", "cpu", "processes"]
            .into_iter()
            .filter(|l| !enforced.contains(l) && !lost.contains(l))
            .collect();
        if !not.is_empty() {
            p.warn(format!("Not held: {} ({lacks} it).", not.join(", ")));
        }
        // Turned off while the node ran: no command runs (crate::cgroup).
        if !lost.is_empty() {
            p.warn(format!(
                "NO COMMAND RUNS: {} turned off in {gone} since the node started.",
                lost.join(", ")
            ));
            p.next("Start it again", "nerve-node service restart");
        }
    } else if let Some(why) = v["off"].as_str() {
        p.warn(format!("Commands run WITHOUT these limits: {why}"));
    }
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
    let _ = out.write_all(status_page(&v).render(Style::stdout()).as_bytes());
    Ok(())
}

/// The page `install` and `update` end with: the node as `status` shows
/// it, where it can be read.
pub async fn done_page(paths: &NodePaths) -> Option<Page> {
    json::status(paths).await.ok().map(|v| status_page(&v))
}

/// The owner on `status`'s page, and what an owner with the machine's full
/// rights means, said plainly: root on Linux, an administrator on Windows.
fn owner_row(owner: Option<&str>, full: bool, p: &mut Page) {
    let Some(o) = owner else { return };
    p.row("Owner", o);
    match full {
        true if cfg!(windows) => p.warn(crate::owner::admin_owner_note(o)),
        true => p.warn(crate::owner::ROOT_OWNER_NOTE),
        false => p,
    };
}

/// What `status` shows of the node, from `status --json`'s `v` (a running
/// node's answer, or what the config says of a stopped one): the node and
/// its service, its limits, each center, the warnings, and the next step.
fn status_page(v: &Value) -> Page {
    let running = v["daemon"] != "not running";
    let installed = v["service"]["state"].is_string();
    let (state, tone) = match (running, v["locked"] == true) {
        (_, true) => ("locked", Tone::Bad),
        (true, _) => ("running", Tone::Good),
        (false, _) if installed => ("stopped", Tone::Bad),
        (false, _) => ("not running", Tone::Plain),
    };
    // The installed node's version, which `update` just changed.
    let version = v["service"]["version"]
        .as_str()
        .unwrap_or(env!("CARGO_PKG_VERSION"));
    let mut p = page_of(version).state(state, tone);
    service_row(&v["service"], &mut p);
    if running && let Some(c) = v["confinement"].as_str() {
        p.row("Confined", c);
    }
    if let Some(s) = v["sudo"].as_str() {
        p.row("Sudo", s);
    }
    // A stopped node knows only the limits it would set.
    if !v["command_limits"].is_null() {
        limits_rows(&v["command_limits"], running, &mut p);
    }
    owner_row(v["owner"].as_str(), v["owner_full_rights"] == true, &mut p);
    let relay = &v["relay"];
    if relay["listen"].is_string() {
        let tunnels = relay["tunnels"].as_array().map_or(0, Vec::len);
        p.row(
            "Relay",
            format!(
                "{} · {tunnels} tunnels open",
                relay["status"].as_str().unwrap_or_default()
            ),
        );
    }
    if v["locked"] == true {
        p.warn("Panic: nothing runs until it is unlocked.");
    }
    if let Some(why) = v["unread"].as_str() {
        p.note(format!(
            "The centers are not shown while the node is stopped: its folders are not yours to read ({why})."
        ));
    }
    if let Some(why) = v["folder_commands_off"].as_str() {
        p.warn(format!("Folder mode runs no command: {why}"));
    }
    for w in [
        &v["home_warning"]["warning"],
        &v["landlock_warning"],
        &v["pairings_warning"],
        &v["processes_warning"],
        &v["provider_pipe_warning"],
    ] {
        if let Some(w) = w.as_str() {
            p.warn(w);
        }
    }
    for l in grant_lines(&v["folder_access"]) {
        p.warn(l);
    }
    let mut centers = Vec::new();
    for c in v["centers"].as_array().into_iter().flatten() {
        // The installed node says as whom its commands run. Where Landlock
        // is missing nerve-run runs without it.
        let whom = match c["account"].as_str() {
            Some(a) if a == crate::account::RUN_USER && c["confined"] == false => {
                format!(" · as {a}, without Landlock")
            }
            Some(a) => format!(" · as {a}"),
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
        let mut row = vec![
            c["name"].as_str().unwrap_or_default().to_string(),
            link.to_string(),
            format!(
                "{} mode{timer}{whom}",
                c["mode"].as_str().unwrap_or_default()
            ),
        ];
        row.extend(center_summary(c));
        centers.push(row);
    }
    p.list(Some("Centers"), centers);
    let mut providers = Vec::new();
    for pr in v["providers"].as_array().into_iter().flatten() {
        let caps: Vec<&str> = pr["capabilities"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let name = pr["name"].as_str().unwrap_or_default();
        providers.push(vec![name.to_string(), caps.join(", ")]);
        // Actions whose schemas a center cannot check are not offered.
        for b in pr["broken"].as_array().into_iter().flatten() {
            p.warn(format!(
                "Provider {name}: {} left out: {}",
                b["name"].as_str().unwrap_or_default(),
                b["reason"].as_str().unwrap_or_default()
            ));
        }
    }
    p.list(Some("Providers"), providers);
    for (what, command) in next_steps(v) {
        p.next(what, command);
    }
    p
}

/// What `status` shows of the installed service, from `status --json`'s
/// `service` (nothing where there is none to tell).
fn service_row(s: &Value, p: &mut Page) {
    if s.is_null() {
        return;
    }
    let Some(state) = s["state"].as_str() else {
        p.row("Service", "not installed");
        return;
    };
    let mut value = vec![state.to_string()];
    match s["enabled"].as_bool() {
        Some(true) => value.push("starts with the machine".into()),
        Some(false) => value.push("not with the machine".into()),
        None => {}
    }
    p.row("Service", value.join(" · "));
}

/// One center's rights in a column, for `status`: its folders, its network,
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
        "{folders} folders · network {network} · rules {allow} allow, {deny} deny, {sudo} sudo"
    ))
}

/// What to do next, from `status --json`'s `v`, each with its command:
/// start a node that does not run, pair a first center, give a folder-mode
/// center a folder.
fn next_steps(v: &Value) -> Vec<(String, String)> {
    let mut steps = Vec::new();
    if v["daemon"] == "not running" {
        steps.push(match v["service"]["state"].as_str() {
            Some(_) => ("Start it".into(), "nerve-node service start".into()),
            None => ("Install it".into(), "sudo nerve-node install".into()),
        });
    }
    if v["locked"] == true {
        steps.push(("Let it work again".into(), "nerve-node unlock".into()));
    }
    // Its centers were not read: none to pair or to give a folder.
    if v["unread"].is_string() {
        return steps;
    }
    let centers = v["centers"].as_array().cloned().unwrap_or_default();
    if centers.is_empty() {
        steps.push(("Pair a center".into(), "nerve-node center add -".into()));
    }
    for c in &centers {
        if c["mode"] == "folder" && c["folders"].as_u64() == Some(0) {
            let name = c["name"].as_str().unwrap_or_default();
            let which = match centers.len() {
                1 => String::new(),
                _ => format!(" --center {name}"),
            };
            steps.push((
                format!("Give {name} a folder"),
                format!("nerve-node folder add ~/project rwx{which}"),
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

    /// The status page of `v` as plain text.
    fn text(v: &Value) -> String {
        status_page(v).render(Style::PLAIN)
    }

    /// `status` of a running node: as whom each pairing runs and whether
    /// without Landlock, what nerve-run may read of the owner's home, and
    /// the folder grants, access nerve-run should have lost worded as such
    /// (#142); each warning set apart.
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
                {"name": "a", "status": "connected", "mode": "folder", "account": "nerve-run", "confined": false},
                {"name": "b", "status": "connected", "mode": "folder", "account": "nerve-run", "confined": true, "confinement": "landlock"},
                {"name": "c", "status": "connected", "mode": "user", "account": "alice", "confined": false},
                {"name": "d", "status": "connected", "mode": "folder"},
            ],
        });
        let t = text(&v);
        for want in [
            "  Owner       alice\n",
            "  Confined    landlock abi 6\n",
            "Warning  Without Landlock, nerve-run can read every file in your home /home/alice\n",
            "         this kernel's Landlock is ABI 4, which does not guard device ioctls\n",
            "         Without Landlock nothing keeps the pairings apart: the commands of a, b all run as nerve-run\n",
            "  Centers\n    a   connected   folder mode · as nerve-run, without Landlock\n",
            "    b   connected   folder mode · as nerve-run\n",
            "    c   connected   user mode · as alice\n",
            "    d   connected   folder mode\n",
            "         nerve-run keeps its access to /home/alice/gone, which it should have lost; no command of nerve-run runs until it is taken off: /home/alice/gone/x: Permission denied (os error 13)\n",
            "         nerve-run keeps its access to /var/lib/nerve/state/acl.json, which it should have lost; no command of nerve-run runs until it is taken off: /var/lib/nerve/state/acl.json: expected value at line 1\n",
            "         nerve-run did not get every folder: /home/alice/usb: its file system does not support POSIX ACLs\n",
        ] {
            assert!(t.contains(want), "{want}\n{t}");
        }
        assert_eq!(t.matches("did not get").count(), 1, "{t}");
        // An owner with the machine's full rights is said plainly: root on
        // Linux, an administrator on Windows (#197).
        let full = |o: &str| match cfg!(windows) {
            true => crate::owner::admin_owner_note(o),
            false => crate::owner::ROOT_OWNER_NOTE.to_string(),
        };
        let root = text(&json!({"owner": "root", "owner_full_rights": true}));
        assert!(
            root.contains(&format!("Warning  {}\n", full("root"))),
            "{root}"
        );
        assert!(crate::owner::ROOT_OWNER_NOTE.contains("run as root"));
        // So is a kernel that gives no command a /proc of its own (#199).
        let shared = text(&json!({"processes_warning": "they see each other"}));
        assert!(
            shared.contains("Warning  they see each other\n"),
            "{shared}"
        );
        // So is a Windows node without its provider pipe, whose name
        // another process may hold.
        let why = crate::provider::pipe_lost("access is denied");
        let pipe = text(&json!({"provider_pipe_warning": why}));
        assert!(pipe.contains(&format!("Warning  {why}\n")), "{pipe}");
        assert!(why.contains("restart the node"), "{why}");
        let admin = text(&json!({"owner": "alice", "owner_full_rights": true}));
        assert!(admin.contains(&full("alice")), "{admin}");
        assert!(crate::owner::admin_owner_note("alice").contains("alice is an administrator"));
        // So does a stopped node's.
        let stopped = |owner: Option<&str>| {
            text(&json!({
                "daemon": "not running",
                "owner": owner,
                "owner_full_rights": crate::owner::full_rights(owner),
            }))
        };
        assert!(
            stopped(Some("root")).starts_with(&format!(
                "Nerve node {} · not running\n",
                env!("CARGO_PKG_VERSION")
            )),
            "{}",
            stopped(Some("root"))
        );
        assert_eq!(
            stopped(Some("root")).contains(crate::owner::ROOT_OWNER_NOTE),
            !cfg!(windows),
            "{}",
            stopped(Some("root"))
        );
        let alice = stopped(Some("alice"));
        assert!(alice.contains("  Owner       alice\n"), "{alice}");
        assert!(!alice.contains("Warning"), "{alice}");
        assert!(!stopped(None).contains("Owner  "), "no owner, no row");
        // Nothing of the kind on a node that has none of it.
        let plain = text(&json!({"confinement": "landlock abi 6"}));
        assert!(!plain.contains("Warning"), "{plain}");
    }

    /// A timer that ends in allowlist mode as the owner says so, as `mode`
    /// does (#197).
    #[test]
    fn the_status_says_a_timer_ends_as_the_owner() {
        let until = crate::now_ms() + 3_600_000;
        let line = |as_owner: bool| {
            let t = text(&json!({
                "daemon": "not running",
                "centers": [{"name": "lab", "url": "https://c.example", "mode": "folder",
                             "until": until, "then": "allowlist", "as_owner": as_owner,
                             "folders": 0, "allow_rules": 1, "deny_rules": 0, "sudo_rules": 0}],
            }));
            t.lines()
                .find(|l| l.starts_with("    lab "))
                .unwrap()
                .to_string()
        };
        assert!(
            line(true).contains(", then allowlist (1 allow rule), as you"),
            "{}",
            line(true)
        );
        assert!(!line(false).contains("as you"), "{}", line(false));
    }

    /// `status` is one place to look: the node and its service in the head
    /// and the rows, each center's mode and what it may do as a list, and
    /// the next steps with their commands, as the owner approved it (#213).
    #[test]
    fn the_status_says_the_service_each_center_and_the_next_step() {
        let t = text(&json!({
            "daemon": "not running",
            "sudo": "off",
            "service": {"installed": true, "state": "stopped", "enabled": true, "version": "0.0.7"},
            "command_limits": {"memory_mb": 4096, "cpu_percent": 200, "processes": 1024},
            "centers": [],
        }));
        assert_eq!(
            t,
            "Nerve node 0.0.7 · stopped

  Service     stopped · starts with the machine
  Sudo        off
  Limits      4 GiB · 200 % CPU · 1024 processes per command

Next  Start it:       nerve-node service start
      Pair a center:  nerve-node center add -
"
        );
        let by_hand = text(&json!({
            "daemon": "not running",
            "service": {"installed": false, "state": null},
            "centers": [{"name": "lab", "url": "https://c.example", "mode": "allowlist",
                         "folders": 0, "allow_rules": 1, "deny_rules": 2, "sudo_rules": 0}],
        }));
        for want in [
            " · not running\n",
            "  Service     not installed\n",
            "Install it:  sudo nerve-node install\n",
            "  Centers\n    lab   https://c.example   allowlist mode   0 folders · network on · rules 1 allow, 2 deny, 0 sudo\n",
        ] {
            assert!(by_hand.contains(want), "{want}\n{by_hand}");
        }
        // A running node with a folder-mode center and no folder: give it one.
        let t = text(&json!({
            "confinement": "landlock abi 6",
            "centers": [
                {"name": "lab", "status": "connected", "mode": "folder", "no_network": true,
                 "folders": 0, "allow_rules": 0, "deny_rules": 0, "sudo_rules": 0},
                {"name": "home", "status": "the center is older than this node: update it first", "mode": "folder",
                 "folders": 1, "allow_rules": 0, "deny_rules": 0, "sudo_rules": 0},
            ],
        }));
        for want in [
            " · running\n",
            "0 folders · network off · rules 0 allow, 0 deny, 0 sudo\n",
            "Next  Give lab a folder:  nerve-node folder add ~/project rwx --center lab\n",
            "    home   the center is older than this node: update it first   folder mode",
        ] {
            assert!(t.contains(want), "{want}\n{t}");
        }
        assert!(!t.contains("Give home"), "{t}");
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
            out.contains("  Limits      512 MiB · 200 % CPU · 1024 processes per command\n"),
            "{out}"
        );
        // A stopped node knows only what it would set.
        assert!(!out.contains("Up to"), "{out}");
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
        assert!(out.contains("  Limits      512 MiB · "), "{out}");
        assert!(
            out.contains("  Up to       16 GiB · 800 % CPU · 8192 processes when a call asks\n"),
            "{out}"
        );
        assert!(
            out.contains("Warning  Commands run WITHOUT these limits: no cgroup for this test\n"),
            "{out}"
        );
    }

    /// The limits' rows and warnings, as plain text.
    fn limits_text(v: &Value, windows: bool) -> String {
        let mut p = page();
        limits_rows_on(v, windows, true, &mut p);
        p.render(Style::PLAIN)
    }

    /// On Linux the cgroup holds the limits, and the status names it; the
    /// node's data is a cgroup's, so its words are Linux's wherever this
    /// runs.
    #[test]
    fn the_status_names_the_cgroup_and_what_it_holds() {
        let v = json!({"memory_mb": 1, "memory_max_mb": 2, "cpu_percent": 3,
                       "cpu_max_percent": 4, "processes": 5, "processes_max": 6,
                       "held_by": "/system.slice/nerve-node.service",
                       "enforced": ["memory", "processes"], "off": null});
        let t = limits_text(&v, false);
        for want in [
            "  Limits      1 MiB · 3 % CPU · 5 processes per command\n",
            "  Up to       2 MiB · 4 % CPU · 6 processes when a call asks\n",
            "  Held by     the cgroup /system.slice/nerve-node.service: memory · processes\n",
            "Warning  Not held: cpu (the cgroup has no controller for it).\n",
        ] {
            assert!(t.contains(want), "{want}\n{t}");
        }
        // Turned off since the start: said apart from what the cgroup never
        // had, with what follows from it.
        let v = json!({"memory_mb": 1, "memory_max_mb": 2, "cpu_percent": 3,
                       "cpu_max_percent": 4, "processes": 5, "processes_max": 6,
                       "held_by": "/", "enforced": [], "lost": ["memory", "processes"],
                       "off": null});
        let t = limits_text(&v, false);
        for want in [
            "  Held by     the cgroup /: none\n",
            "Warning  Not held: cpu (the cgroup has no controller for it).\n",
            "         NO COMMAND RUNS: memory, processes turned off in the cgroup since the node started.\n",
            "Next  Start it again:  nerve-node service restart\n",
        ] {
            assert!(t.contains(want), "{want}\n{t}");
        }
    }

    /// On Windows the job object holds the limits, and the status says so
    /// instead of naming a cgroup.
    #[test]
    fn the_status_names_the_job_object_on_windows() {
        let v = json!({"memory_mb": 1, "memory_max_mb": 2, "cpu_percent": 3,
                       "cpu_max_percent": 4, "processes": 5, "processes_max": 6,
                       "held_by": "the command's job object",
                       "enforced": ["memory", "cpu", "processes"], "off": null});
        let t = limits_text(&v, true);
        assert!(
            t.contains("  Held by     the command's job object: memory · cpu · processes\n"),
            "{t}"
        );
        assert!(!t.contains("Warning"), "{t}");
        let v = json!({"memory_mb": 1, "memory_max_mb": 2, "cpu_percent": 3,
                       "cpu_max_percent": 4, "processes": 5, "processes_max": 6,
                       "held_by": "the command's job object",
                       "enforced": ["memory"], "lost": ["processes"], "off": null});
        let t = limits_text(&v, true);
        for want in [
            "  Held by     the command's job object: memory\n",
            "Warning  Not held: cpu (it holds no limit for it).\n",
            "         NO COMMAND RUNS: processes turned off in its job object since the node started.\n",
        ] {
            assert!(t.contains(want), "{want}\n{t}");
        }
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
        let t = text(&v);
        for want in [
            "Nerve node 0.0.7 · stopped\n",
            "  Service     stopped · starts with the machine\n",
            "Note  The centers are not shown while the node is stopped",
            "Next  Start it:  nerve-node service start\n",
        ] {
            assert!(t.contains(want), "{want}\n{t}");
        }
        assert!(!t.contains("Pair a center"), "{t}");
        // A running service, or none: the error is the answer. So it is
        // where this account may open the folders (a `node.toml` that does
        // not parse): a stopped service does not hide it (round 2).
        let running = json!({"installed": true, "state": "running"});
        assert!(json::with_service(Err("x".into()), running, true).is_err());
        assert!(json::with_service(Err("x".into()), Value::Null, true).is_err());
        assert!(json::with_service(Err("cannot parse".into()), service, false).is_err());
    }
}
