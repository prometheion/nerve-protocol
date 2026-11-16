//! The center role's pages against a center of their own, through the
//! window's callbacks: the log-in (typed, and read with an administrator's
//! command), the kept log-in, the pages' readings, a harness token and its
//! copy that leaves the clipboard, a rule of the checker, a setting, a
//! restore, the pairing, a center that stops and comes back, the log-out,
//! the role change both ways, an administrator's command through a real
//! broker. One test: Slint takes one platform per process.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use nerve::app::{Choose, Ctl, Exec};
use nerve::headless::Screen;
use nerve::hub::keep::{self, Keyring};
use nerve::hub::{Failed, Holder};
use nerve::runner::Runner;
use nerve::{AppWindow, Hub, HubPage};
use nerve_center::config::Args;
use serde_json::{Value, json};
use slint::{ComponentHandle, Model};

#[test]
fn the_center_s_pages_drive_its_web_ui_api() {
    let _screen = Screen::install(1440, 900, 1.0).unwrap();
    nerve_transport::init_crypto();
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let run = dir.path().join("run");
    std::fs::create_dir_all(&run).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let args = Args::from_argv([
        "nerve-center",
        "--state-dir",
        state.to_str().unwrap(),
        "--listen",
        "127.0.0.1:0",
        "--plain-loopback",
        "--mcp",
        "127.0.0.1:0",
        "--ui",
        "127.0.0.1:0",
    ])
    .unwrap();
    let lock = nerve_center::attach::try_lock(&state).unwrap().unwrap();
    let center = rt
        .block_on(nerve_center::server::start(&args, lock))
        .unwrap();
    let ui = center.ui.unwrap();
    // The address file the installed center writes into its run folder.
    nerve_center::ui_file::write(
        &nerve_center::ui_file::path_in(&run),
        &nerve_center::ui_file::UiAddress::of(Some(ui), None),
    )
    .unwrap();
    let token = nerve_center::owner::read(&state).unwrap().unwrap();

    let window = AppWindow::new().unwrap();
    let runner = Runner::new(env!("CARGO_BIN_EXE_nerve").into(), None, None);
    let ctl = Ctl::attach(&window, runner.clone(), Exec::Inline);
    // The test's center runs as the test's user: the test says it is the
    // service, while it is up.
    let up = Arc::new(AtomicBool::new(true));
    let judge: nerve::hub::Judge = {
        let up = up.clone();
        Arc::new(move |_| {
            Ok(match up.load(Ordering::SeqCst) {
                true => Holder::Service,
                false => Holder::Nobody,
            })
        })
    };
    ctl.set_hub_judge(judge.clone());
    let keyring = Arc::new(keep::Memory::default());
    ctl.set_hub_keyring(keyring.clone());
    // The administrator's commands: what they were asked, and the owner
    // token as `owner-token --json` says it.
    let asked: Arc<Mutex<Vec<Vec<String>>>> = Arc::default();
    let said = asked.clone();
    let owner = token.clone();
    // The uninstall of a role change fails while this is set.
    let refuse = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let refusing = refuse.clone();
    // A restore restarts the center: it is away when the command ends.
    let restarting = up.clone();
    ctl.set_hub_admin(Some(Arc::new(move |args, _input| {
        said.lock().unwrap().push(args.to_vec());
        match args.get(1).map(String::as_str) {
            Some("owner-token") => Ok(json!({"messages": [], "token": owner})),
            // The center's refusal of another center's backup.
            Some("restore") if !args.iter().any(|a| a == "--replace") => Err(
                "the center here is lab (c1); the backup is of old (c0). They are not the same center, and a restore would replace the one here: every node paired with it would have to pair again. If you mean that, add --replace".into(),
            ),
            Some("restore") => {
                restarting.store(false, Ordering::SeqCst);
                Ok(json!({"messages": []}))
            }
            Some("uninstall") if refusing.load(std::sync::atomic::Ordering::SeqCst) => {
                Err("the service did not stop".into())
            }
            _ => Ok(json!({"messages": []})),
        }
    })));
    // Another program of the user wrote the keyring switch on: the owner
    // never turned it on, so nothing goes to the keyring.
    let settings = dir.path().join("nerve-app/settings.json");
    nerve::settings::save_keep_login(&settings, true).unwrap();
    ctl.keep_settings(settings.clone());
    ctl.center_role(run.clone());
    let hub = window.global::<Hub>();
    assert!(!hub.get_keep_login());
    // The app closes itself to the user's other programs only once it
    // holds the token.
    #[cfg(target_os = "linux")]
    let dumpable = || unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
    #[cfg(target_os = "linux")]
    assert_eq!(dumpable(), 1);

    // The log-in first, with the check of the port said.
    assert!(hub.get_shown() && !hub.get_logged_in());
    assert!(hub.get_login_checked());
    assert_eq!(
        hub.get_login_check(),
        format!("This is the center's service on {ui}.")
    );
    hub.set_login_token("nrv_owner_not_it".into());
    hub.invoke_login();
    assert!(!hub.get_logged_in());
    assert_eq!(hub.get_login_error(), nerve::hub::WRONG_TOKEN);

    // Read from this machine: one administrator's command, then the log-in.
    hub.invoke_login_read();
    assert_eq!(
        *asked.lock().unwrap(),
        [vec!["__center".to_string(), "owner-token".into()]]
    );
    assert!(hub.get_logged_in(), "{}", hub.get_login_error());
    #[cfg(target_os = "linux")]
    assert_eq!(dumpable(), 0, "the app holds the token open to the user");
    assert_eq!(hub.get_state(), "running");
    assert_eq!(hub.get_nodes_count(), "None paired");
    assert_eq!(hub.get_checker_line(), "Blocklist on · model off");
    // Off by default: the token stays in memory only.
    assert_eq!(keyring.get().unwrap(), None);
    hub.invoke_keep_login_set(true);
    assert_eq!(keyring.get().unwrap().as_deref(), Some(token.as_str()));
    assert!(nerve::settings::keep_login(&settings));

    // Harnesses: a token made, its lines shown with the token hidden, a copy
    // that leaves the clipboard after its minute.
    hub.invoke_show(HubPage::Harnesses);
    assert!(hub.get_mcp_http());
    hub.set_token_label("claude-code".into());
    hub.invoke_token_create();
    let made = hub.get_new_token().to_string();
    assert!(made.starts_with("nrv_"), "{made}");
    assert_eq!(hub.get_tokens().row_count(), 1);
    let lines = hub.get_connect_lines();
    let masked = hub.get_connect_masked();
    let header = lines.row_data(2).unwrap().value;
    assert!(header.ends_with(&made));
    assert!(!masked.row_data(2).unwrap().value.contains(&made));
    hub.invoke_copy_secret(header.clone());
    let clipboard = || nerve::hub::clip::text(window.window());
    assert_eq!(clipboard().as_deref(), Some(header.as_str()));
    ctl.hub_clip_expired();
    assert_eq!(clipboard().as_deref(), Some(""));
    // Something copied since stays.
    hub.invoke_copy_secret(header.clone());
    nerve::hub::clip::copy(window.window(), "mine").unwrap();
    ctl.hub_clip_expired();
    assert_eq!(clipboard().as_deref(), Some("mine"));
    // The app closes within the minute: the copy leaves with it.
    hub.invoke_copy_secret(header.clone());
    ctl.end();
    assert_eq!(clipboard().as_deref(), Some(""));

    // The checker: a blocklist rule from the form, in the center's config.
    hub.invoke_show(HubPage::Checker);
    let builtins = hub.get_block_rules().row_count();
    assert!(builtins > 0);
    hub.set_chk_view(0);
    hub.invoke_rule_add();
    assert_eq!(hub.get_chk_pick(), -1);
    hub.set_rule_text("exec.run:shutdown *".into());
    hub.set_rule_note("Turns the machine off".into());
    hub.invoke_rule_save();
    assert_eq!(hub.get_block_rules().row_count(), builtins + 1);
    let added = hub.get_block_rules().row_data(builtins).unwrap();
    assert_eq!(
        (
            added.rule.as_str(),
            added.note.as_str(),
            added.r#where.as_str()
        ),
        (
            "exec.run:shutdown *",
            "Turns the machine off",
            "All machines"
        )
    );
    assert_eq!(hub.get_chk_pick(), builtins as i32);
    // Off and back on through its switch.
    hub.invoke_checker_switch(1, true);
    assert!(hub.get_model_on());
    let client = nerve::hub::Hub::new(
        nerve::hub::Address {
            url: format!("http://{ui}"),
            at: ui,
            pin: None,
        },
        Arc::new(|_| Ok(Holder::Service)),
    );
    client.login(&token).unwrap();
    let checker: Value = client.get("/api/checker").unwrap();
    assert_eq!(checker["config"]["model_on"], true);

    // Settings: a setting the API changes, without an administrator.
    hub.invoke_show(HubPage::Settings);
    assert_eq!(hub.get_set_days(), "30");
    // The addresses the center was started with: its settings file is
    // root's.
    assert_eq!(
        (hub.get_set_listen().as_str(), hub.get_set_ui().as_str()),
        ("127.0.0.1:0", "127.0.0.1:0")
    );
    let before = asked.lock().unwrap().len();
    hub.set_set_name("lab".into());
    hub.set_set_days("12".into());
    hub.invoke_settings_save();
    assert_eq!(asked.lock().unwrap().len(), before);
    let center_now = client.get("/api/center").unwrap();
    assert_eq!(
        (
            center_now["name"].clone(),
            center_now["retention_days"].clone()
        ),
        (json!("lab"), json!(12))
    );
    // An address: one administrator's command for it.
    hub.set_set_listen("127.0.0.1:7999".into());
    hub.invoke_settings_save();
    assert_eq!(
        asked.lock().unwrap()[before..],
        [vec![
            "__center".to_string(),
            "set".into(),
            "listen".into(),
            "127.0.0.1:7999".into()
        ]]
    );

    // Restore: the file read and handed over; another center's backup only
    // where the owner ticked it, the refusal naming that box.
    let backup = dir.path().join("old.nrvbak");
    std::fs::write(&backup, b"sealed").unwrap();
    hub.set_backup_file(backup.to_str().unwrap().into());
    hub.set_backup_pass("a long passphrase".into());
    hub.set_restore_open(true);
    hub.set_restore_replace(false);
    hub.invoke_restore();
    let restore = |more: &[&str]| {
        let mut a: Vec<String> = ["__center", "restore", "-", "--passphrase-file", "-"]
            .map(String::from)
            .to_vec();
        a.extend(more.iter().map(|m| m.to_string()));
        a
    };
    assert_eq!(asked.lock().unwrap().last(), Some(&restore(&[])));
    assert!(
        hub.get_backup_error()
            .ends_with("If you mean that, tick \"It is another center's backup\""),
        "{}",
        hub.get_backup_error()
    );
    assert!(hub.get_restore_open());
    hub.set_restore_replace(true);
    hub.invoke_restore();
    assert_eq!(asked.lock().unwrap().last(), Some(&restore(&["--replace"])));
    assert!(!hub.get_restore_open(), "{}", hub.get_backup_error());
    // The center was still away when the app tried to log in again: it
    // keeps the token, and logs in once the center answers.
    assert!(!hub.get_logged_in());
    up.store(true, Ordering::SeqCst);
    hub.invoke_reload();
    assert!(hub.get_logged_in(), "{}", hub.get_login_check());
    // A file larger than any backup is not read, nor handed over.
    let before = asked.lock().unwrap().len();
    std::fs::File::create(&backup)
        .unwrap()
        .set_len(nerve_transport::backup::MAX_FILE + 1)
        .unwrap();
    hub.set_restore_open(true);
    hub.invoke_restore();
    assert!(
        hub.get_backup_error().contains("larger than"),
        "{}",
        hub.get_backup_error()
    );
    assert_eq!(asked.lock().unwrap().len(), before);
    std::fs::remove_file(&backup).unwrap();
    hub.set_restore_open(false);

    // Pair a machine: the link and the command.
    hub.invoke_pair_start();
    assert!(hub.get_pair_open());
    assert!(
        hub.get_pair_link().starts_with("nerve://pair?"),
        "{}",
        hub.get_pair_link()
    );
    assert_eq!(hub.get_pair_command(), "nerve-node center add -");

    // Statistics, the log and the help read.
    hub.invoke_show(HubPage::Stats);
    assert_eq!(
        hub.get_stat_rows().row_data(0).unwrap().name,
        "All machines"
    );
    hub.invoke_show(HubPage::Log);
    assert!(hub.get_log().row_count() > 0);
    // Its download is the owner's only, as the center keeps it.
    let saved = dir.path().join("center.log");
    let to = saved.clone();
    ctl.set_chooser(Arc::new(move |what| {
        assert!(matches!(what, Choose::SaveLog));
        Ok(Some(to.clone()))
    }));
    hub.invoke_log_download();
    assert!(std::fs::metadata(&saved).unwrap().len() > 0);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&saved).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    hub.invoke_show(HubPage::Help);
    assert!(hub.get_commands().iter().any(|c| c.name == "owner-token"),);

    // Stop in Settings: the pages show the log-in, which says the center is
    // not running; once it runs again the app logs in with the token it
    // holds.
    let address_file = nerve_center::ui_file::path_in(&run);
    let address = std::fs::read(&address_file).unwrap();
    std::fs::remove_file(&address_file).unwrap();
    hub.invoke_service("stop".into());
    assert_eq!(
        asked.lock().unwrap().last().unwrap()[1..],
        ["service".to_string(), "stop".into()]
    );
    assert!(!hub.get_logged_in());
    assert!(hub.get_not_running());
    hub.invoke_reload();
    assert!(!hub.get_logged_in());
    std::fs::write(&address_file, &address).unwrap();
    hub.invoke_reload();
    assert!(hub.get_logged_in(), "{}", hub.get_login_check());
    // A reading while the center restarts: the log-in, then logged in
    // again once it answers.
    up.store(false, Ordering::SeqCst);
    hub.invoke_show(HubPage::Overview);
    assert!(!hub.get_logged_in());
    up.store(true, Ordering::SeqCst);
    hub.invoke_reload();
    assert!(hub.get_logged_in(), "{}", hub.get_login_check());
    // It restarted on a port that does not answer yet: the log-in fails,
    // and the app keeps the token for the next try.
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    nerve_center::ui_file::write(
        &address_file,
        &nerve_center::ui_file::UiAddress::of(Some(closed), None),
    )
    .unwrap();
    hub.invoke_service("restart".into());
    assert!(!hub.get_logged_in());
    std::fs::write(&address_file, &address).unwrap();
    hub.invoke_reload();
    assert!(hub.get_logged_in(), "{}", hub.get_login_check());

    // Apps & features asks to uninstall while the window is open: the
    // center's own uninstall opens, never the node's dialogs.
    let install = window.global::<nerve::Install>();
    ctl.started_again(nerve::instance::Asked {
        uninstall: true,
        ..Default::default()
    });
    assert!(hub.get_uninstall_open());
    assert!(!install.get_uninstall_open());
    hub.set_uninstall_open(false);

    // A new owner token ends the session: the old token in memory no longer
    // logs in, so the log-in shows, and the kept one is forgotten.
    nerve_center::owner::renew(&state).unwrap();
    hub.invoke_show(HubPage::Overview);
    assert!(!hub.get_logged_in());
    assert_eq!(keyring.get().unwrap(), None);
    assert_eq!(
        client.get("/api/overview").map(|_| ()),
        Err(Failed::LoggedOut)
    );

    // The new one, kept again while the switch is on; logged out here, the
    // kept log-in goes with it.
    let new = nerve_center::owner::read(&state).unwrap().unwrap();
    hub.set_login_token(new.as_str().into());
    hub.invoke_login();
    assert!(hub.get_logged_in());
    assert_eq!(keyring.get().unwrap(), Some(new));
    hub.invoke_logout();
    assert!(!hub.get_logged_in());
    assert_eq!(keyring.get().unwrap(), None);
    assert!(!nerve::settings::keep_login(&settings));

    // The role change: the backup's step first, then the center goes whole
    // with its data, the program kept; a failed uninstall stays a center.
    hub.set_login_token(nerve_center::owner::read(&state).unwrap().unwrap().into());
    hub.invoke_login();
    hub.set_role_node(false);
    hub.invoke_role_ask();
    assert!(hub.get_role_open());
    assert_eq!(hub.get_role_step(), 0);
    hub.set_role_step(1);
    hub.invoke_role_change();
    let uninstall = vec![
        "__center".to_string(),
        "uninstall".into(),
        "--purge".into(),
        "--keep-program".into(),
    ];
    assert_eq!(asked.lock().unwrap().last(), Some(&uninstall));
    assert_eq!(hub.get_role_error(), "the service did not stop");
    assert_eq!(hub.get_role_step(), 1);
    assert!(hub.get_shown());
    refuse.store(false, std::sync::atomic::Ordering::SeqCst);
    hub.invoke_role_change();
    assert_eq!(asked.lock().unwrap().last(), Some(&uninstall));
    assert!(!hub.get_shown() && !hub.get_role_open());
    assert!(install.get_shown());
    assert_eq!(install.get_role(), 0, "the node is picked");

    // The other way, a node made a center: its backup is the node's own
    // dialog, its uninstall the node's, and the installer picks the center.
    install.set_shown(false);
    hub.set_shown(true);
    let chosen = dir.path().join("node.nrvbak");
    let to = chosen.clone();
    ctl.set_chooser(Arc::new(move |what| {
        assert!(matches!(what, Choose::SaveBackup), "the node's backup");
        Ok(Some(to.clone()))
    }));
    hub.set_role_node(true);
    hub.invoke_role_ask();
    hub.invoke_role_backup();
    let prefs = window.global::<nerve::Prefs>();
    assert!(prefs.get_backup_open());
    assert_eq!(prefs.get_backup_file(), chosen.to_str().unwrap());
    prefs.set_backup_open(false);
    hub.set_role_step(1);
    hub.invoke_role_change();
    assert_eq!(
        asked.lock().unwrap().last().unwrap(),
        &["uninstall", "--purge", "--keep-program"].map(String::from)
    );
    assert!(!hub.get_shown() && install.get_shown());
    assert_eq!(install.get_role(), 1, "the center is picked");

    // The app started before the center, with the log-in the owner kept
    // in the keyring: it logs in once the center answers.
    let token = nerve_center::owner::read(&state).unwrap().unwrap();
    let window2 = AppWindow::new().unwrap();
    let ctl2 = Ctl::attach(&window2, runner, Exec::Inline);
    ctl2.set_hub_judge(judge);
    let kept = Arc::new(keep::Memory::default());
    kept.set(&token).unwrap();
    ctl2.set_hub_keyring(kept.clone());
    let settings2 = dir.path().join("nerve-app2/settings.json");
    nerve::settings::save_keep_login(&settings2, true).unwrap();
    ctl2.keep_settings(settings2);
    up.store(false, Ordering::SeqCst);
    ctl2.center_role(run.clone());
    let hub2 = window2.global::<Hub>();
    assert!(hub2.get_keep_login() && !hub2.get_logged_in());
    up.store(true, Ordering::SeqCst);
    hub2.invoke_reload();
    assert!(hub2.get_logged_in(), "{}", hub2.get_login_check());

    // An administrator's command through a real broker: it ends with the
    // command, the center role keeps none (design of #232, 3).
    #[cfg(target_os = "linux")]
    {
        ctl2.set_hub_admin(None);
        ctl2.set_hub_launch(nerve::broker::Launch::Plain);
        hub2.invoke_token_show();
        let store2 = window2.global::<nerve::Store>();
        assert!(store2.get_toast_shown(), "the broker answered nothing");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !brokers().is_empty() {
            assert!(
                std::time::Instant::now() < deadline,
                "the broker still runs: {:?}",
                brokers()
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
    rt.block_on(center.stop());
}

/// The brokers this test started that still run: children of this process
/// started as `__desktop-broker`, not yet ended.
#[cfg(target_os = "linux")]
fn brokers() -> Vec<u32> {
    let me = std::process::id().to_string();
    std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
            // pid (comm) state ppid ...
            let after = stat.rsplit_once(')').map(|(_, a)| a).unwrap_or_default();
            let mut f = after.split_whitespace();
            let (state, ppid) = (f.next(), f.next());
            let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
            ppid == Some(me.as_str())
                && state != Some("Z")
                && String::from_utf8_lossy(&cmdline).contains("__desktop-broker")
        })
        .collect()
}
