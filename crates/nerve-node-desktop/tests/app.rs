//! The app against a node of its own, end to end: each action goes through
//! the window's callbacks, runs this crate's program as `nerve-node`, and
//! lands in the node's files and audit log as the CLI's command does.
//! One test: Slint takes one platform per process.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use nerve_conformance::fake_center::FakeCenter;
use nerve_node::NodePaths;
use nerve_node_desktop::app::{Choose, Ctl, Exec};
use nerve_node_desktop::broker::Launch;
use nerve_node_desktop::headless::Screen;
use nerve_node_desktop::runner::Runner;
use nerve_node_desktop::{AppWindow, Caps, Install, Load, Logs, Page, Perm, Prefs, Store};
use nerve_policy::NodeConfig;
use serde_json::Value;
use slint::{ComponentHandle, Model};

fn config(paths: &NodePaths) -> NodeConfig {
    NodeConfig::load(&paths.config_file()).unwrap()
}

fn audit(paths: &NodePaths) -> Vec<Value> {
    std::fs::read_to_string(paths.audit_log())
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn decided(paths: &NodePaths, ts: u64, center: &str, cap: &str, action: &str, target: &str) {
    nerve_policy::audit::AuditLog::new(paths.audit_log())
        .decision(&nerve_policy::audit::Entry {
            ts,
            center: center.into(),
            cap: cap.into(),
            action: action.into(),
            target: target.into(),
            decision: "forbidden".into(),
            code: None,
            session: None,
            reason: Some("no allow rule matches it (allowlist mode)".into()),
            command: None,
        })
        .unwrap();
}

/// Waits for a command that keeps answering (`audit --follow`) to bring
/// what `done` looks for into the window. Each page starts its command
/// anew, and on a Windows machine busy with a whole test run, starting this
/// crate's program took longer than the 10 seconds given before.
fn until(ctl: &Ctl, what: &str, done: impl Fn() -> bool) {
    for _ in 0..300 {
        ctl.pump();
        if done() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("{what} did not come");
}

fn logged(paths: &NodePaths, msg: &str) {
    logged_at(paths, 1, msg);
}

fn logged_at(paths: &NodePaths, ts: u64, msg: &str) {
    logged_level(paths, ts, "warn", msg);
}

fn logged_level(paths: &NodePaths, ts: u64, level: &str, msg: &str) {
    use std::io::Write;
    std::fs::create_dir_all(&paths.state_dir).unwrap();
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(paths.log_file())
        .unwrap();
    // One write per line, as the node writes its log: a follower never
    // sees half of one.
    let line = format!(
        "{}\n",
        serde_json::json!({"ts": ts, "level": level, "msg": msg})
    );
    f.write_all(line.as_bytes()).unwrap();
}

#[test]
fn the_app_drives_the_cli_end_to_end() {
    // No keyring answers the CLI's probe: the app must not offer one.
    // SAFETY: before this test starts any thread.
    #[cfg(target_os = "linux")]
    unsafe {
        std::env::set_var("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
    };
    let _screen = Screen::install(1180, 780, 1.0).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let root: &Path = dir.path();
    let paths = NodePaths::new(root.join("config"), root.join("state"));
    let runner = Runner::new(
        env!("CARGO_BIN_EXE_nerve-node-desktop").into(),
        Some(paths.config_dir.clone()),
        Some(paths.state_dir.clone()),
    );
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let center = rt.block_on(FakeCenter::start(false)).unwrap();

    let window = AppWindow::new().unwrap();
    let ctl = Ctl::attach(&window, runner, Exec::Inline);
    let store = window.global::<Store>();
    ctl.refresh_status();
    assert_eq!(store.get_status_load(), Load::Ready);
    assert_eq!(store.get_status().state, "stopped");
    assert_eq!(store.get_centers().row_count(), 0);

    // A link that is none is refused by the CLI, and the dialog says why.
    store.invoke_pair_start();
    assert!(store.get_pair_open());
    store.invoke_pair_check("nerve://elsewhere".into(), "".into());
    assert!(
        store.get_pair_error().contains("nerve://pair?"),
        "{}",
        store.get_pair_error()
    );
    assert_eq!(store.get_pair_step(), 0);

    // The preview first, and nothing paired yet.
    let link = center.link().render();
    store.set_pair_link(link.clone().into());
    store.set_pair_name("home".into());
    store.invoke_pair_check(link.into(), "home".into());
    assert_eq!(store.get_pair_error(), "");
    assert_eq!(store.get_pair_step(), 1);
    assert_eq!(store.get_pair_preview().center, center.url.to_string());
    assert!(!store.get_pair_preview().tls);
    // The check found the center and its code open: Pair can work.
    assert!(
        store.get_pair_preview().ready,
        "{}",
        store.get_pair_preview().check
    );
    assert!(config(&paths).centers.is_empty());
    store.invoke_pair_confirm();
    assert!(!store.get_pair_open(), "{}", store.get_pair_error());
    // No node runs: it links when it starts, which the app says too.
    assert!(
        store.get_toast().contains("Paired with home")
            && store
                .get_toast()
                .contains("The node takes it when it starts."),
        "{}",
        store.get_toast()
    );
    let cfg = config(&paths);
    assert_eq!(cfg.centers.len(), 1);
    assert_eq!(cfg.centers[0].name, "home");
    assert!(center.paired().is_some());
    assert_eq!(store.get_centers().row_count(), 1);
    // The same link again: its code is used, and the preview says so
    // instead of offering Pair.
    store.invoke_pair_start();
    store.invoke_pair_check(center.link().render().into(), "".into());
    let p = store.get_pair_preview();
    assert!(
        !p.ready && p.check.contains("paired with this code"),
        "{}",
        p.check
    );
    store.set_pair_open(false);
    assert_eq!(store.get_centers().row_data(0).unwrap().name, "home");

    // Pause, the settings grant, each as the CLI makes it, and audited.
    store.invoke_center_pause("home".into(), true);
    assert!(config(&paths).centers[0].paused);
    assert_eq!(store.get_centers().row_data(0).unwrap().link, "Paused");
    store.invoke_center_pause("home".into(), false);
    assert!(!config(&paths).centers[0].paused);
    store.invoke_center_grant("home".into(), true);
    assert_eq!(
        config(&paths).centers[0].settings,
        nerve_policy::config::SettingsGrant::Write
    );
    assert!(store.get_centers().row_data(0).unwrap().settings_write);
    // No node runs, so each change counts when it starts, and the app says
    // so instead of a plain "done". With the service running (as the
    // installed node on Windows, which takes only folder changes while it
    // runs), the Overview offers the restart.
    assert_eq!(
        store.get_toast_tone(),
        nerve_node_desktop::Tone::Warn,
        "{}",
        store.get_toast()
    );
    assert!(
        store
            .get_toast()
            .starts_with("home may change this machine's settings now.")
            && store.get_toast().contains("takes it when it starts"),
        "{}",
        store.get_toast()
    );
    assert!(
        !store.get_toast().contains("run as root"),
        "{}",
        store.get_toast()
    );
    // Where root is the owner, giving the grant says that the center can
    // make itself root (#151).
    window.global::<Perm>().set_owner_is_root(true);
    store.invoke_center_grant("home".into(), true);
    assert!(
        store
            .get_toast()
            .contains("Root is the owner of this node, so home can set its own mode to user, and its commands then run as root."),
        "{}",
        store.get_toast()
    );
    window.global::<Perm>().set_owner_is_root(false);
    assert!(!store.get_restart_due());
    // With the service running, the app restarts it for such a change, a
    // moment later. The service here is none, so the restart fails, and
    // the Overview goes on offering it.
    store.set_service_state("running".into());
    store.invoke_center_pause("home".into(), true);
    assert!(store.get_restart_due());
    assert!(
        store
            .get_toast()
            .ends_with("The node restarts in a moment to take it."),
        "{}",
        store.get_toast()
    );
    ctl.tick();
    assert!(
        store.get_toast().starts_with("The node did not restart")
            && store.get_toast().contains("Restart it on the Overview"),
        "{}",
        store.get_toast()
    );
    assert!(store.get_restart_due());
    assert_eq!(ctl.end(), None, "the restart ran");
    // The app ends before that moment: its end restarts the service, or
    // the change would wait for the next start of the machine.
    store.invoke_center_pause("home".into(), false);
    let ended = ctl.end();
    assert!(
        matches!(&ended, Some(Err(e)) if e.contains("--config-dir")),
        "{ended:?}"
    );
    assert_eq!(ctl.end(), None, "once");
    // The first-run steps restart it once, at their end: a new name waits
    // for it meanwhile.
    store.set_restart_due(false);
    store.invoke_setup_start();
    store.set_setup_name("boxy".into());
    store.invoke_setup_next();
    assert_eq!(store.get_setup_step(), 1, "{}", store.get_setup_error());
    assert!(store.get_restart_due());
    store.set_toast("".into());
    store.invoke_setup_skip();
    store.invoke_setup_skip();
    store.invoke_setup_next();
    assert!(!store.get_setup_open());
    // The service's restart ran (and failed: there is none).
    assert_eq!(store.get_toast_tone(), nerve_node_desktop::Tone::Danger);
    assert!(
        store.get_toast().contains("--config-dir"),
        "{}",
        store.get_toast()
    );
    // Closed with × or Escape before their end, the steps restart it all
    // the same.
    store.set_restart_due(false);
    store.invoke_setup_start();
    store.set_setup_name("boxy-2".into());
    store.invoke_setup_next();
    assert!(store.get_restart_due(), "{}", store.get_setup_error());
    store.set_toast("".into());
    store.invoke_setup_close();
    assert!(!store.get_setup_open());
    assert!(
        store.get_toast_tone() == nerve_node_desktop::Tone::Danger
            && store.get_toast().contains("--config-dir"),
        "{}",
        store.get_toast()
    );
    store.set_service_state("".into());
    store.set_restart_due(false);
    let settings = audit(&paths)
        .iter()
        .filter(|e| e["kind"] == "settings" && e["by"] == "local")
        .count();
    assert!(
        settings >= 3,
        "every change is audited: {:?}",
        audit(&paths)
    );

    // The four buttons write the rules the CLI's `rule add --action` and
    // the center's buttons write.
    decided(&paths, 1, "home", "exec", "run", "git push origin main");
    decided(&paths, 2, "home", "fs", "write", "/srv/data/report.txt");
    decided(&paths, 3, "home", "exec", "run", "sudo apt update");
    store.invoke_show(Page::Audit);
    assert_eq!(store.get_page(), Page::Audit);
    // `audit --follow` brings the entries in.
    until(&ctl, "the audit entries", || {
        store
            .get_audit()
            .row_data(0)
            .is_some_and(|r| r.target == "sudo apt update")
    });
    assert_eq!(
        store.get_audit_load(),
        Load::Ready,
        "{}",
        store.get_audit_error()
    );
    let rows = store.get_audit();
    // Newest first: the sudo command, the file, the push.
    let row = |i: usize| rows.row_data(i).unwrap();
    assert_eq!(row(0).target, "sudo apt update");
    assert!(row(0).rules && row(1).rules && row(2).rules);
    // Each change is an entry too, so the list moves: a button is found by
    // its entry.
    let index_of = |target: &str| {
        let rows = store.get_audit();
        (0..rows.row_count())
            .find(|i| rows.row_data(*i).unwrap().target == target)
            .unwrap() as i32
    };
    let settings_shown = || {
        let rows = store.get_audit();
        (0..rows.row_count())
            .filter(|i| rows.row_data(*i).unwrap().kind == "settings")
            .count()
    };
    let before = settings_shown();
    store.invoke_audit_rule(index_of("git push origin main"), "allow".into(), true);
    // The change comes in as an entry of its own, live.
    until(&ctl, "the rule's settings entry", || {
        settings_shown() == before + 1
    });
    store.invoke_audit_rule(index_of("/srv/data/report.txt"), "deny".into(), true);
    until(&ctl, "the second rule", || settings_shown() == before + 2);
    store.invoke_audit_rule(index_of("sudo apt update"), "allow".into(), false);
    until(&ctl, "the third rule", || settings_shown() == before + 3);
    store.invoke_audit_rule(index_of("git push origin main"), "deny".into(), false);
    let policy = config(&paths).centers[0].policy.clone();
    let rule = |cap, action, target, wildcard| {
        nerve_policy::rules::rule_for(cap, action, target, wildcard).unwrap()
    };
    assert_eq!(
        policy.allow,
        [rule("exec", "run", "git push origin main", true)]
    );
    // After the guard a new pairing gets.
    let guard = nerve_policy::rules::GUARD.len();
    assert_eq!(policy.deny[..guard], *nerve_policy::rules::GUARD);
    assert_eq!(
        policy.deny[guard..],
        [
            rule("fs", "write", "/srv/data/report.txt", true),
            rule("exec", "run", "git push origin main", false)
        ]
    );
    assert_eq!(
        policy.sudo_allow,
        [nerve_policy::rules::sudo_rule_for("sudo apt update", false).unwrap()]
    );
    assert!(
        store.get_toast().contains("deny list of home"),
        "{}",
        store.get_toast()
    );

    // The filters combine, without asking the node again: refused, then
    // words in the target, an action, the oldest first; the counts follow.
    let read = store.get_audit_read();
    // Unfiltered, a row's place is its entry's index.
    let push = index_of("git push origin main");
    store.set_audit_decision(2);
    store.invoke_audit_filtered();
    let rows = store.get_audit();
    assert_eq!(rows.row_count(), 3);
    assert!(rows.iter().all(|r| r.badge == "Refused"));
    let counts: Vec<i32> = store.get_audit_counts().iter().collect();
    assert_eq!(counts[2], 3, "{counts:?}");
    assert_eq!(counts[0], read, "{counts:?}");
    store.set_audit_text("APT".into());
    store.invoke_audit_filtered();
    assert_eq!(store.get_audit().row_count(), 1);
    assert_eq!(
        store.get_audit_summary(),
        format!("1 of {read} entries match.")
    );
    store.set_audit_text("".into());
    let actions: Vec<String> = store
        .get_audit_action_options()
        .iter()
        .map(|a| a.to_string())
        .collect();
    assert_eq!(actions, ["Every action", "exec.run", "fs.write"]);
    store.set_audit_action(2);
    store.invoke_audit_filtered();
    assert_eq!(store.get_audit().row_count(), 1);
    assert_eq!(
        store.get_audit().row_data(0).unwrap().target,
        "/srv/data/report.txt"
    );
    store.set_audit_action(1);
    store.set_audit_oldest(true);
    store.invoke_audit_filtered();
    let targets: Vec<String> = store
        .get_audit()
        .iter()
        .map(|r| r.target.to_string())
        .collect();
    assert_eq!(targets, ["git push origin main", "sudo apt update"]);
    // A button names its entry also in a filtered list.
    assert_eq!(store.get_audit().row_data(0).unwrap().index, push);
    store.set_audit_decision(0);
    store.set_audit_action(0);
    store.set_audit_oldest(false);
    store.invoke_audit_filtered();
    assert_eq!(store.get_audit().row_count() as i32, read);

    // Clear, after a question that says what stays: the page starts with
    // the clearing, and the entries so far are the older file.
    let before = std::fs::read(paths.audit_log()).unwrap();
    store.invoke_audit_clear();
    assert!(store.get_confirm_open());
    assert!(
        store.get_confirm_text().contains("audit.jsonl.1"),
        "{}",
        store.get_confirm_text()
    );
    store.set_confirm_open(false);
    store.invoke_confirm_accepted();
    until(&ctl, "the cleared audit", || {
        let rows = store.get_audit();
        rows.row_count() == 1 && rows.row_data(0).unwrap().kind == "audit"
    });
    let audit_old = nerve_policy::audit::AuditLog::new(paths.audit_log()).old_path();
    assert_eq!(std::fs::read(audit_old).unwrap(), before);
    assert!(
        store.get_toast().contains("audit log is cleared"),
        "{}",
        store.get_toast()
    );

    // Permissions: the mode with a time, a folder from the system's
    // dialog (answered here), a rule.
    let work = root.join("work");
    std::fs::create_dir(&work).unwrap();
    let picked = work.clone();
    ctl.set_chooser(Arc::new(move |c| {
        Ok(match c {
            Choose::Folder => Some(picked.clone()),
            _ => None,
        })
    }));
    let perm = window.global::<Perm>();
    store.invoke_show(Page::Policy);
    assert_eq!(perm.get_center(), "home");
    assert_eq!(perm.get_load(), Load::Ready, "{}", perm.get_error());
    // A new pairing starts in folder mode.
    assert_eq!(perm.get_mode(), "folder");
    perm.invoke_mode_pick("user".into());
    assert!(perm.get_mode_open());
    perm.set_mode_timed(true);
    perm.set_mode_hours("2".into());
    perm.invoke_mode_apply();
    assert!(!perm.get_mode_open(), "{}", perm.get_mode_error());
    let p = config(&paths).centers[0].policy.clone();
    assert_eq!(p.mode, nerve_policy::Mode::User);
    assert!(p.until.is_some());
    assert_eq!(perm.get_mode(), "user");
    assert!(
        perm.get_mode_until().contains("Back to allowlist"),
        "{}",
        perm.get_mode_until()
    );
    perm.invoke_mode_pick("allowlist".into());
    assert_eq!(
        config(&paths).centers[0].policy.mode,
        nerve_policy::Mode::Allowlist
    );
    // "Run them as you" goes through the CLI and comes back with the
    // status; a click on the tile of the mode it is in keeps it.
    perm.invoke_as_owner_set(true);
    assert!(config(&paths).centers[0].policy.as_owner);
    until(&ctl, "the chip on", || perm.get_as_owner());
    perm.invoke_mode_pick("allowlist".into());
    assert!(config(&paths).centers[0].policy.as_owner);
    perm.invoke_as_owner_set(false);
    assert!(!config(&paths).centers[0].policy.as_owner);
    until(&ctl, "the chip off", || !perm.get_as_owner());

    perm.invoke_folder_choose();
    assert!(perm.get_folder_open());
    assert_eq!(perm.get_folder_path(), work.display().to_string());
    perm.set_folder_execute(true);
    perm.invoke_folder_add();
    assert!(!perm.get_folder_open(), "{}", perm.get_folder_error());
    let f = &config(&paths).centers[0].policy.folders[0];
    assert!(
        f.access.read && !f.access.write && f.access.execute,
        "{f:?}"
    );
    let path = perm.get_folders().row_data(0).unwrap().path;
    perm.invoke_folder_set(path.clone(), true, true, false);
    let f = &config(&paths).centers[0].policy.folders[0];
    assert!(
        f.access.read && f.access.write && !f.access.execute,
        "{f:?}"
    );
    // What the installed Linux node's status says of a pairing: who runs
    // its commands, nerve-run's built-in folders, and the failed grants of
    // its own folders only. Also without an owner (`install` as root alone).
    for owner in [serde_json::json!("alice"), Value::Null] {
        let mut st: Value = serde_json::from_str(
            &std::process::Command::new(env!("CARGO_BIN_EXE_nerve-node-desktop"))
                .arg("--config-dir")
                .arg(&paths.config_dir)
                .arg("--state-dir")
                .arg(&paths.state_dir)
                .args(["--json", "status"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap(),
        )
        .unwrap();
        st["owner"] = owner.clone();
        st["centers"][0]["account"] = serde_json::json!("nerve-run");
        st["centers"][0]["landlock"] = serde_json::json!(false);
        st["home_warning"] = serde_json::json!({"warning": "Without Landlock, nerve-run can read every file in your home /home/alice that other accounts may read (mode 755)"});
        // A folder no center has any more whose access did not come off,
        // and the node's record of them that could not be read: shown on
        // this center although neither is one of its folders.
        st["folder_grants"] = serde_json::json!({
            "errors": [
                format!("{}: Permission denied (os error 13)", root.join("work/closed").display()),
                "/elsewhere/proj: Permission denied (os error 13)",
                "/removed/folder/sub: Permission denied (os error 13)",
                "/var/lib/nerve/state/acl.json: expected value at line 1 column 1",
            ],
            "stale": ["/removed/folder", "/var/lib/nerve/state/acl.json"],
        });
        ctl.show_status(Ok(st));
        if cfg!(target_os = "linux") {
            assert!(perm.get_separate(), "{owner}");
            assert_eq!(perm.get_account(), "nerve-run");
            assert!(
                perm.get_built_in().contains("/var/lib/nerve-run"),
                "{owner}"
            );
            let errors = perm.get_grant_errors();
            assert!(errors.contains("work/closed"), "{errors}");
            assert!(!errors.contains("/elsewhere"), "{errors}");
            assert!(!errors.contains("/removed"), "{errors}");
            let stale = perm.get_stale();
            assert!(stale.contains("/removed/folder/sub"), "{stale}");
            assert!(stale.contains("acl.json: expected value"), "{stale}");
            assert!(!stale.contains("work/closed"), "{stale}");
            assert!(!perm.get_landlock());
            assert!(perm.get_home_warning().contains("mode 755"));
        } else {
            assert!(!perm.get_separate());
            assert_eq!(perm.get_built_in(), "");
        }
    }
    // Root as the owner (#151): the page knows, so its texts say root.
    let mut st = serde_json::json!({"daemon": "running", "owner": "root", "owner_is_root": true,
        "centers": [{"name": "home", "mode": "user", "account": "root"}]});
    ctl.show_status(Ok(st.clone()));
    assert!(perm.get_owner_is_root());
    assert_eq!(perm.get_account(), "root");
    st["owner"] = serde_json::json!("alice");
    st["owner_is_root"] = serde_json::json!(false);
    ctl.show_status(Ok(st));
    assert!(!perm.get_owner_is_root());
    ctl.refresh_status();
    until(&ctl, "the node's own status", || {
        perm.get_landlock() && perm.get_home_warning() == "" && perm.get_stale() == ""
    });
    perm.invoke_folder_remove(path);
    assert!(config(&paths).centers[0].policy.folders.is_empty());

    // The answer of a reading the page asked for before its last one (the
    // owner picked another center meanwhile) comes late: it is dropped.
    let stale = ctl.perm_asked();
    store.invoke_reload();
    assert!(ctl.perm_asked() > stale);
    let elsewhere = serde_json::json!({"center": "other", "folders": [
        {"path": "/elsewhere", "rights": "r--", "read": true, "write": false, "execute": false}
    ]});
    let rules = serde_json::json!({"center": "other", "allow": ["exec.run:elsewhere"], "deny": [], "sudo": []});
    ctl.perm_loaded(
        stale,
        (
            Ok(elsewhere),
            Ok(rules),
            Ok(serde_json::json!({"sudo": "on"})),
        ),
    );
    assert_eq!(perm.get_folders().row_count(), 0);
    assert!(perm.get_allow().iter().all(|r| r != "exec.run:elsewhere"));
    assert!(!perm.get_sudo_on());

    let allowed = |r: &str| {
        config(&paths).centers[0]
            .policy
            .allow
            .contains(&r.to_string())
    };
    perm.set_allow_text("cargo build".into());
    perm.set_allow_wild(true);
    perm.invoke_rule_add(0);
    assert!(allowed("exec.run:cargo *"));
    assert_eq!(perm.get_allow_text(), "");
    assert!(!perm.get_allow_wild());
    // Edited in place, as one change in the audit.
    let changes = || {
        audit(&paths)
            .iter()
            .filter(|e| e["kind"] == "settings")
            .count()
    };
    let before = changes();
    let at = perm
        .get_allow()
        .iter()
        .position(|r| r == "exec.run:cargo *")
        .unwrap();
    perm.set_edit_list(0);
    perm.set_edit_index(at as i32);
    perm.set_edit_text("cargo build --release".into());
    perm.invoke_rule_edit_save();
    assert!(
        allowed("exec.run:cargo build --release"),
        "{}",
        store.get_toast()
    );
    assert!(!allowed("exec.run:cargo *"));
    assert_eq!(changes(), before + 1);
    assert_eq!(perm.get_edit_list(), -1, "the row is shown again");
    perm.invoke_rule_remove(0, "exec.run:cargo build --release".into());
    assert!(!allowed("exec.run:cargo build --release"));
    // A pattern for files goes in as it is, as `config add` adds it, and
    // comes out as `rule ls` shows it.
    perm.set_allow_text("fs.read:~/notes/*".into());
    perm.invoke_rule_add(0);
    assert!(allowed("fs.read:~/notes/*"), "{}", store.get_toast());
    assert!(perm.get_allow().iter().any(|r| r == "fs.read:~/notes/*"));
    perm.invoke_rule_remove(0, "fs.read:~/notes/*".into());
    assert!(!allowed("fs.read:~/notes/*"));
    // The text `rule ls` writes for a line break is not one: refused, with
    // the field kept. A Windows path with `\\t` or `\\n` in it is a rule.
    let listed = nerve_policy::rules::escape_controls(nerve_policy::rules::GUARD_OLD[12]);
    let before = config(&paths).centers[0].policy.deny.clone();
    perm.set_deny_text(listed.clone().into());
    perm.invoke_rule_add(1);
    assert_eq!(config(&paths).centers[0].policy.deny, before);
    assert!(
        store.get_toast().contains("how `rule ls` writes a rule"),
        "{}",
        store.get_toast()
    );
    assert_eq!(perm.get_deny_text(), listed.as_str());
    perm.set_deny_text("".into());
    perm.set_allow_text("exec.run:type C:\\tools\\x.exe".into());
    perm.invoke_rule_add(0);
    assert!(
        allowed("exec.run:type C:\\tools\\x.exe"),
        "{}",
        store.get_toast()
    );
    perm.invoke_rule_remove(0, "exec.run:type C:\\tools\\x.exe".into());
    assert!(!allowed("exec.run:type C:\\tools\\x.exe"));
    // The capability switches are on the Capabilities page, for the
    // center it shows; none of them is on Permissions any more.
    let caps = window.global::<Caps>();
    store.invoke_show(Page::Capabilities);
    assert_eq!(caps.get_center(), "home");
    assert_eq!(caps.get_load(), Load::Ready, "{}", caps.get_error());
    // Why this machine offers no programs, or no capabilities of node.toml:
    // Windows offers neither yet, a Linux node run by hand none of
    // node.toml.
    if cfg!(windows) {
        assert!(caps.get_windows());
        assert!(caps.get_programs_note().contains("Windows"));
        assert!(caps.get_config_note().contains("Windows"));
    } else {
        assert!(!caps.get_windows());
        assert_eq!(caps.get_programs_note(), "");
        assert!(
            caps.get_config_note().contains("runs by hand"),
            "{}",
            caps.get_config_note()
        );
    }
    let row = |name: &str| caps.get_rows().iter().find(|c| c.name == name);
    let run = row("exec.run").expect("exec.run is listed");
    assert!(run.switchable && run.action);
    assert_eq!((run.setting, run.effect.as_str()), (-1, "execute"));
    caps.invoke_cap_set("exec.run".into(), 1);
    assert_eq!(
        config(&paths).centers[0].policy.caps.get("exec.run"),
        Some(&nerve_policy::config::CapSetting::Off)
    );
    assert_eq!(row("exec.run").unwrap().setting, 1, "{}", store.get_toast());
    caps.invoke_cap_set("exec".into(), 2);
    assert_eq!(row("exec").unwrap().setting, 2);
    // An action with no switch of its own shows its capability's, marked,
    // as the node reads it; exec.run keeps its own.
    let signal = row("exec.signal").expect("exec.signal is listed");
    assert_eq!((signal.setting, signal.inherited), (2, true));
    assert!(!row("exec.run").unwrap().inherited);
    caps.invoke_cap_set("exec".into(), 0);
    caps.invoke_cap_set("exec.run".into(), 0);
    assert_eq!(row("exec.run").unwrap().setting, 0);
    // The provider allow list is here too: a program by its full path,
    // listed without its state while the node does not run, and removed.
    let program = std::env::current_exe().unwrap().display().to_string();
    caps.set_program_name("desk".into());
    caps.set_program_exe("not/a/full/path".into());
    caps.invoke_program_allow();
    assert!(
        caps.get_program_error().contains("full path"),
        "{}",
        caps.get_program_error()
    );
    assert!(config(&paths).providers.allowed.is_empty());
    caps.set_program_exe(program.as_str().into());
    caps.invoke_program_allow();
    assert_eq!(caps.get_program_error(), "");
    assert_eq!(caps.get_program_name(), "", "the fields are not cleared");
    let allowed = &config(&paths).providers.allowed;
    assert_eq!(
        (allowed[0].name.as_str(), allowed[0].exe.as_str()),
        ("desk", program.as_str())
    );
    let listed = caps.get_programs().row_data(0).unwrap();
    assert_eq!(
        (listed.name.as_str(), listed.attached.as_str()),
        ("desk", "")
    );
    caps.invoke_program_remove("desk".into());
    assert!(config(&paths).providers.allowed.is_empty());
    assert_eq!(caps.get_programs().row_count(), 0);
    store.invoke_show(Page::Policy);

    // A pairing without the whole guard (the owner took a rule off) is
    // offered it, in one click.
    assert!(!perm.get_guard_missing());
    perm.invoke_rule_remove(1, nerve_policy::rules::GUARD[3].into());
    assert!(perm.get_guard_missing());
    perm.invoke_guard_add();
    let deny = config(&paths).centers[0].policy.deny.clone();
    assert!(
        nerve_policy::rules::guard_missing(&deny).is_empty(),
        "{deny:?} {}",
        store.get_toast()
    );
    assert!(!perm.get_guard_missing());
    assert!(!perm.get_guard_older());
    assert!(!perm.get_guard_busy());
    // A text of the guard from before is still a rule that works, and the
    // app says so instead of saying there is no guard; one click replaces it.
    let older = nerve_policy::rules::GUARD_OLD[0];
    perm.set_deny_text(older.into());
    perm.invoke_rule_add(1);
    assert!(perm.get_guard_older(), "{}", store.get_toast());
    assert!(!perm.get_guard_missing());
    perm.invoke_guard_add();
    assert!(!perm.get_guard_older(), "{}", store.get_toast());
    assert!(
        !config(&paths).centers[0]
            .policy
            .deny
            .iter()
            .any(|d| d == older)
    );

    // Sudo takes the password on stdin; without a running node it says so
    // and waits for nothing.
    perm.invoke_sudo_ask();
    perm.set_sudo_password("not a real password".into());
    perm.invoke_sudo_confirm();
    if cfg!(unix) {
        assert!(
            perm.get_sudo_error().contains("daemon"),
            "{}",
            perm.get_sudo_error()
        );
    }
    assert_eq!(perm.get_sudo_password(), "", "the password is not kept");
    perm.set_sudo_open(false);

    // The log, live.
    logged(&paths, "link dropped");
    store.invoke_show(Page::Log);
    let logs = window.global::<Logs>();
    until(&ctl, "the log line", || logs.get_rows().row_count() == 1);
    logged(&paths, "cannot connect");
    until(&ctl, "the new log line", || {
        logs.get_rows().row_count() == 2
    });
    assert_eq!(logs.get_rows().row_data(0).unwrap().msg, "cannot connect");
    // How long ago moves on while the node writes nothing new.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    logged_at(&paths, now, "link up");
    until(&ctl, "the newest log line", || {
        logs.get_rows().row_count() == 3
    });
    assert_eq!(logs.get_rows().row_data(0).unwrap().when, "just now");
    ctl.refresh_times(now + 2 * 3600 * 1000);
    assert_eq!(logs.get_rows().row_data(0).unwrap().when, "2 h ago");
    // The page shows the newest lines, and more when asked.
    logs.set_limit(2);
    store.invoke_reload();
    until(&ctl, "the two newest lines", || {
        logs.get_rows().row_count() == 2
    });
    logs.invoke_more();
    assert_eq!(logs.get_limit(), 1000);
    until(&ctl, "every line", || logs.get_rows().row_count() == 3);
    // The problems come from the whole log: a warning shows behind newer
    // lines that are none, more than the page shows.
    logged_level(&paths, now, "info", "linked");
    logged_level(&paths, now, "info", "linked again");
    logs.set_limit(1);
    logs.invoke_filter(true);
    until(&ctl, "the newest problem", || {
        logs.get_rows()
            .row_data(0)
            .is_some_and(|r| r.msg == "link up")
    });
    assert_eq!(logs.get_rows().row_count(), 1);
    logs.invoke_filter(false);
    // Clear, after its question: one line says who cleared it. The owner
    // goes to the audit before the answer: the audit keeps its own entries,
    // and the log's page follows again only when it is open again.
    until(&ctl, "the whole log", || logs.get_load() == Load::Ready);
    logs.invoke_clear();
    assert!(store.get_confirm_open());
    store.invoke_show(Page::Audit);
    until(&ctl, "the audit", || store.get_audit_load() == Load::Ready);
    let calls = || {
        store
            .get_audit()
            .iter()
            .filter(|r| r.kind == "call")
            .count()
    };
    let before = calls();
    store.set_confirm_open(false);
    store.invoke_confirm_accepted();
    assert_eq!(logs.get_load(), Load::Ready, "the log follows on the audit");
    for _ in 0..20 {
        ctl.pump();
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(calls(), before, "log lines came into the audit");
    store.invoke_show(Page::Log);
    until(&ctl, "the cleared log", || {
        logs.get_rows()
            .row_data(0)
            .is_some_and(|r| r.msg.starts_with("the log was cleared by"))
    });
    assert_eq!(logs.get_rows().row_count(), 1);

    // Settings: the name, any setting, a relay node's token, a backup and
    // its restore, the passphrase piped in.
    let prefs = window.global::<Prefs>();
    store.invoke_show(Page::Settings);
    assert_eq!(prefs.get_load(), Load::Ready, "{}", prefs.get_error());
    prefs.invoke_name_save("lab-box".into());
    assert_eq!(config(&paths).node.name.as_deref(), Some("lab-box"));
    prefs.set_raw_key("log.level".into());
    prefs.set_raw_value("debug".into());
    prefs.invoke_raw_set();
    assert_eq!(prefs.get_raw_error(), "");
    assert_eq!(prefs.get_raw_shown(), "debug");
    // A list grows and shrinks by one entry, as `config add` and `config
    // remove` change it.
    prefs.set_raw_key("center.home.policy.deny".into());
    prefs.set_raw_value("fs:~/private/*".into());
    prefs.invoke_raw_add();
    assert_eq!(prefs.get_raw_error(), "");
    // The account commands run as: Windows's alone, none here.
    assert_eq!(prefs.get_account(), "");
    let denied = |r: &str| {
        config(&paths).centers[0]
            .policy
            .deny
            .contains(&r.to_string())
    };
    assert!(denied("fs:~/private/*"));
    prefs.set_raw_value("fs:~/private/*".into());
    prefs.invoke_raw_remove();
    assert_eq!(prefs.get_raw_error(), "");
    assert!(!denied("fs:~/private/*"));
    // Typed values that start with `-` are values, not flags: a shell
    // named `-sh` is saved as typed (the CLI does not mind it), and a node
    // name `-lab` gets the CLI's own refusal instead of clap's.
    prefs.set_shell("-sh".into());
    prefs.invoke_shell_save();
    assert_eq!(config(&paths).machine.shell.as_deref(), Some("-sh"));
    prefs.set_raw_key("machine.shell".into());
    prefs.set_raw_value("-bash".into());
    prefs.invoke_raw_set();
    assert_eq!(prefs.get_raw_error(), "");
    assert_eq!(config(&paths).machine.shell.as_deref(), Some("-bash"));
    prefs.set_raw_key("node.name".into());
    prefs.set_raw_value("-lab".into());
    prefs.invoke_raw_set();
    assert!(
        prefs.get_raw_error().contains("starting and ending"),
        "{}",
        prefs.get_raw_error()
    );
    prefs.set_raw_error("".into());
    prefs.invoke_relay_add();
    prefs.set_relay_add_name("-lab".into());
    prefs.invoke_relay_add_confirm();
    assert!(
        prefs.get_relay_add_open() && prefs.get_relay_add_error().contains("starting and ending"),
        "{}",
        prefs.get_relay_add_error()
    );
    prefs.set_relay_add_open(false);
    // A node of the relay: its name, and where it reaches this machine,
    // which goes into its one link.
    prefs.invoke_relay_add();
    assert!(prefs.get_relay_add_open());
    prefs.set_relay_add_name("laptop-2".into());
    prefs.set_relay_add_address("relay.example".into());
    prefs.invoke_relay_add_confirm();
    assert!(
        !prefs.get_relay_add_open(),
        "{}",
        prefs.get_relay_add_error()
    );
    assert!(prefs.get_once_open());
    let link = nerve_proto::link::RelayLink::parse(&prefs.get_once_copy()).unwrap();
    assert_eq!(
        (link.node.as_str(), link.address.as_str()),
        ("laptop-2", "relay.example:7490")
    );
    assert!(
        prefs
            .get_once_text()
            .contains("paste this link under Relay, Connect")
            && !prefs.get_once_text().contains("run:"),
        "{}",
        prefs.get_once_text()
    );
    // A node pastes it, and goes through the relay: its proxy is the relay
    // with its name and the pin, its token kept with its keys. (This node
    // itself here: the app is the same on the other one.)
    let link_text = prefs.get_once_copy();
    prefs.set_once_open(false);
    prefs.invoke_connect_start();
    prefs.set_connect_link(link_text.clone());
    prefs.invoke_connect_read(link_text);
    assert!(
        prefs.get_connect_summary().contains("relay.example:7490"),
        "{}",
        prefs.get_connect_summary()
    );
    prefs.invoke_connect_save();
    assert!(!prefs.get_connect_open(), "{}", prefs.get_connect_error());
    let c = config(&paths).connection;
    assert_eq!(c.proxy.as_deref(), Some("https://relay.example:7490"));
    assert_eq!(c.login.as_deref(), Some("laptop-2"));
    assert_eq!(c.pin.as_deref(), Some(link.pin.as_str()));
    assert!(prefs.get_via_relay());
    assert_eq!(prefs.get_via_address(), "relay.example:7490");
    prefs.invoke_disconnect();
    assert!(config(&paths).connection.proxy.is_none());
    assert!(!prefs.get_via_relay());
    // A link that is none: refused before anything runs.
    prefs.invoke_connect_start();
    prefs.set_connect_link("nerve://relay?address=x".into());
    prefs.invoke_connect_save();
    assert!(prefs.get_connect_open() && prefs.get_connect_error() != "");
    prefs.set_connect_open(false);
    // A pin is random base64url, so about one in 64 starts with `-`: the
    // CLI must not read it as a flag. (This one is fixed, to be sure.)
    let dashed = nerve_proto::link::RelayLink {
        pin: "-AECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".into(),
        ..link.clone()
    };
    prefs.invoke_connect_start();
    prefs.set_connect_link(dashed.render().into());
    prefs.invoke_connect_read(dashed.render().into());
    prefs.invoke_connect_save();
    assert!(!prefs.get_connect_open(), "{}", prefs.get_connect_error());
    assert_eq!(
        config(&paths).connection.pin.as_deref(),
        Some(dashed.pin.as_str())
    );
    prefs.invoke_disconnect();
    assert!(config(&paths).connection.proxy.is_none());
    assert_eq!(prefs.get_relay_nodes().row_count(), 1);
    prefs.set_once_open(false);
    // Its centers and limits, in its dialog.
    prefs.invoke_relay_edit(0);
    assert!(prefs.get_relay_edit_open());
    assert_eq!(prefs.get_relay_edit_name(), "laptop-2");
    let picks = prefs.get_relay_edit_centers();
    assert_eq!(picks.row_count(), 1);
    assert!(!picks.row_data(0).unwrap().on);
    prefs.invoke_relay_edit_pick(0, true);
    prefs.set_relay_edit_own(true);
    prefs.set_relay_edit_links("3".into());
    prefs.set_relay_edit_opens("12".into());
    prefs.invoke_relay_edit_save();
    assert!(
        !prefs.get_relay_edit_open(),
        "{}",
        prefs.get_relay_edit_error()
    );
    let node = config(&paths).relay.nodes[0].clone();
    assert_eq!(node.centers, ["home"]);
    assert_eq!(
        (node.max_links, node.max_opens_per_minute),
        (Some(3), Some(12))
    );
    // Back to every center and the relay's limits.
    prefs.invoke_relay_edit(0);
    assert!(prefs.get_relay_edit_own() && prefs.get_relay_edit_centers().row_data(0).unwrap().on);
    prefs.invoke_relay_edit_pick(0, false);
    prefs.set_relay_edit_own(false);
    prefs.invoke_relay_edit_save();
    let node = config(&paths).relay.nodes[0].clone();
    assert!(
        node.centers.is_empty() && node.max_links.is_none(),
        "{node:?}"
    );
    // Without the desktop portal no file dialog opens: the button says
    // what to install instead of doing nothing.
    let no_portal = nerve_node_desktop::deps::portal(Some((false, ""))).unwrap_err();
    ctl.set_chooser(Arc::new(move |_| Err(no_portal.clone())));
    prefs.invoke_backup_choose();
    assert!(!prefs.get_backup_open());
    assert!(store.get_missing_open());
    assert_eq!(store.get_missing_title(), "No file dialog");
    assert!(store.get_missing_text().contains("xdg-desktop-portal"));
    store.set_missing_open(false);
    // The update's file the same: its dialog says it under a heading of
    // its own, since no update ran.
    let update = window.global::<Install>();
    update.invoke_ask_update();
    update.invoke_choose_file();
    assert!(update.get_error().contains("xdg-desktop-portal"));
    assert_eq!(update.get_error_title(), "No file dialog");
    update.set_update_open(false);
    let backup = root.join("node.backup");
    let file = backup.clone();
    ctl.set_chooser(Arc::new(move |_| Ok(Some(file.clone()))));
    prefs.invoke_backup_choose();
    assert!(prefs.get_backup_open());
    prefs.set_backup_pass("correct horse battery".into());
    prefs.set_backup_pass2("correct horse battery".into());
    prefs.invoke_backup_confirm();
    assert!(!prefs.get_backup_open(), "{}", prefs.get_backup_error());
    assert!(backup.is_file());
    prefs.set_once_open(false);
    prefs.invoke_restore_choose();
    assert!(prefs.get_restore_open());
    prefs.set_restore_pass("wrong passphrase!".into());
    prefs.invoke_restore_confirm();
    assert!(
        prefs.get_restore_error().contains("passphrase"),
        "{}",
        prefs.get_restore_error()
    );
    prefs.set_restore_pass("correct horse battery".into());
    prefs.invoke_restore_confirm();
    assert!(!prefs.get_restore_open(), "{}", prefs.get_restore_error());
    // What it did, in the app's words, without the CLI's next steps.
    assert!(
        prefs
            .get_once_text()
            .starts_with("The node's settings and keys are restored, with the pairing of home.")
            && !prefs.get_once_text().contains("docs/user")
            && !prefs.get_once_text().contains('`'),
        "{}",
        prefs.get_once_text()
    );
    prefs.set_once_open(false);

    // Panic and unlock.
    store.invoke_panic();
    assert!(config(&paths).locked);
    assert_eq!(store.get_status().state, "locked");
    store.invoke_unlock();
    assert!(!config(&paths).locked);

    // Unpairing asks first.
    store.invoke_center_unpair("home".into());
    assert!(store.get_confirm_open());
    assert!(!config(&paths).centers.is_empty());
    store.set_confirm_open(false);
    store.invoke_confirm_accepted();
    assert!(config(&paths).centers.is_empty());
    assert!(!paths.key_file("home").exists());
    assert_eq!(store.get_centers().row_count(), 0);

    // An error of the CLI is said, and the window stays as it was.
    store.invoke_center_pause("nobody".into(), true);
    assert_eq!(store.get_toast_tone(), nerve_node_desktop::Tone::Danger);
    assert!(
        store.get_toast().contains("center"),
        "{}",
        store.get_toast()
    );

    // The first-run steps: a name, the keys, a new center, its mode.
    let second = rt.block_on(FakeCenter::start(true)).unwrap();
    store.invoke_setup_start();
    assert!(store.get_setup_open());
    if cfg!(target_os = "linux") {
        assert!(!store.get_keyring_usable());
        assert!(
            store.get_keyring_why().contains("keyring"),
            "{}",
            store.get_keyring_why()
        );
    }
    store.set_setup_name("studio".into());
    store.invoke_setup_next();
    assert_eq!(store.get_setup_step(), 1, "{}", store.get_setup_error());
    assert_eq!(config(&paths).node.name.as_deref(), Some("studio"));
    // Back, and on again.
    store.invoke_setup_back();
    assert_eq!(store.get_setup_step(), 0);
    store.invoke_setup_back();
    assert_eq!(store.get_setup_step(), 0, "the first step has no back");
    store.invoke_setup_next();
    assert_eq!(store.get_setup_step(), 1, "{}", store.get_setup_error());
    store.invoke_setup_next();
    assert_eq!(store.get_setup_step(), 2, "{}", store.get_setup_error());
    store.set_pair_link(second.link().render().into());
    store.set_pair_name("studio-center".into());
    store.invoke_setup_next();
    assert_eq!(store.get_pair_step(), 1, "{}", store.get_pair_error());
    // Back from the confirmation to the link, and on.
    store.invoke_setup_back();
    assert_eq!((store.get_setup_step(), store.get_pair_step()), (2, 0));
    store.invoke_setup_next();
    assert_eq!(store.get_pair_step(), 1, "{}", store.get_pair_error());
    store.invoke_setup_next();
    assert_eq!(store.get_setup_step(), 3, "{}", store.get_pair_error());
    assert_eq!(store.get_setup_center(), "studio-center");
    // Back from the mode: the center stays paired, and Continue goes on to
    // its mode without pairing again.
    store.invoke_setup_back();
    assert_eq!((store.get_setup_step(), store.get_pair_step()), (2, 2));
    store.invoke_setup_next();
    assert_eq!(store.get_setup_step(), 3, "{}", store.get_pair_error());
    store.set_setup_mode("folder".into());
    store.invoke_setup_next();
    assert_eq!(store.get_setup_step(), 4, "{}", store.get_setup_error());
    assert_eq!(
        config(&paths).center("studio-center").unwrap().policy.mode,
        nerve_policy::Mode::Folder
    );
    store.invoke_setup_back();
    assert_eq!(store.get_setup_step(), 3);
    store.invoke_setup_next();
    assert_eq!(store.get_setup_step(), 4, "{}", store.get_setup_error());
    store.invoke_setup_next();
    assert!(!store.get_setup_open());

    // A nerve:// link goes straight to the pairing's confirmation.
    let third = rt.block_on(FakeCenter::start(false)).unwrap();
    ctl.open_link(third.link().render());
    assert!(store.get_pair_open());
    assert_eq!(store.get_pair_step(), 1, "{}", store.get_pair_error());
    assert_eq!(store.get_pair_preview().center, third.url.to_string());
    store.set_pair_open(false);

    // An installed node: the app says why it needs the rights, then runs
    // every command through the broker (here as this user), the ones that
    // keep answering too.
    ctl.needs_rights(Launch::Plain);
    assert!(store.get_elevate_open() && store.get_elevate_needed());
    store.invoke_elevate_allow();
    assert!(!store.get_elevate_needed(), "{}", store.get_elevate_error());
    ctl.refresh_status();
    assert_eq!(
        store.get_status_load(),
        Load::Ready,
        "{}",
        store.get_status_error()
    );
    store.invoke_panic();
    assert!(config(&paths).locked);
    store.invoke_unlock();
    // Read again, also when the Audit page is the one open.
    store.invoke_reload();
    store.invoke_show(Page::Audit);
    until(&ctl, "the audit through the broker", || {
        // The clearing and the changes after it, panic and unlock last.
        let rows = store.get_audit();
        rows.row_count() > 2 && rows.row_data(0).unwrap().kind == "settings"
    });
    store.invoke_show(Page::Overview);

    // A proxy's password goes to the CLI on stdin, out of the URL it was
    // typed in, and never into node.toml.
    prefs.invoke_proxy_edit();
    prefs.set_proxy_new_url("https://laptop:s3cret@relay.example:7490".into());
    prefs.invoke_proxy_set();
    assert!(!prefs.get_proxy_open(), "{}", prefs.get_proxy_error());
    let file = std::fs::read_to_string(paths.config_file()).unwrap();
    assert!(
        file.contains("laptop") && !file.contains("s3cret"),
        "{file}"
    );
    prefs.invoke_proxy_remove();

    // The appearance the owner chose is kept in the app's own file.
    let settings = root.join("app/settings.json");
    ctl.keep_settings(settings.clone());
    assert_eq!(store.get_appearance(), 0);
    store.invoke_set_appearance(2);
    assert_eq!(nerve_node_desktop::settings::appearance(&settings), 2);
    store.set_appearance(0);
    ctl.keep_settings(settings);
    assert_eq!(store.get_appearance(), 2);

    // A service command goes through the broker too, and says when it
    // cannot be done: here no service is installed.
    store.invoke_service("stop".into());
    assert_eq!(store.get_toast_tone(), nerve_node_desktop::Tone::Danger);
    assert!(store.get_busy().is_empty());

    // Uninstall in Apps & features (Windows) while the app is open: the
    // window opens its uninstall, which asks keep or delete first.
    let install = window.global::<Install>();
    let uninstall = nerve_node_desktop::instance::Asked {
        uninstall: true,
        ..Default::default()
    };
    ctl.started_again(uninstall.clone());
    assert!(install.get_uninstall_open());
    assert_eq!(
        (install.get_action().as_str(), install.get_step().as_str()),
        ("uninstall", "choose")
    );
    install.set_uninstall_open(false);

    // The installer, as a downloaded copy shows it: what it installs, and
    // why it did not when the system refused (here: no root).
    let bin = root.join("usr/local/bin/nerve-node-desktop");
    ctl.installer(Launch::Plain, &bin);
    assert!(install.get_shown());
    assert_eq!(install.get_program(), bin.display().to_string());
    // It has no uninstall dialog of its own to open.
    ctl.started_again(uninstall);
    assert!(!install.get_uninstall_open());
    // Install works on the machine's own places, whatever `bin` says: with
    // root or an elevated token (GitHub's Windows runner has one) it would
    // install this test's build as the machine's Nerve, or take over the
    // node installed there. Such a run leaves it out.
    if nerve_node::rights::full_rights() {
        eprintln!("not pressing Install: this test runs with the rights to install");
    } else if install.get_step() == "welcome" {
        install.invoke_install();
        assert_eq!(install.get_step(), "welcome");
        assert!(
            install.get_error().contains("install"),
            "{}",
            install.get_error()
        );
        assert!(!bin.exists());
    }
    install.invoke_close();
    assert!(install.get_closed());
    ctl.end();
    drop((rt, second, third));
}
