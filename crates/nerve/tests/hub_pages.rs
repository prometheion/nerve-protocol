//! The center role's pages against a center of their own, through the
//! window's callbacks: the log-in (typed, and read with an administrator's
//! command), the kept log-in, the pages' readings, a harness token and its
//! copy that leaves the clipboard, a rule of the checker, a setting, the
//! pairing, the log-out. One test: Slint takes one platform per process.

use std::sync::{Arc, Mutex};

use nerve::app::{Ctl, Exec};
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
    let ctl = Ctl::attach(&window, runner, Exec::Inline);
    // The test's center runs as the test's user: the test says it is the
    // service.
    ctl.set_hub_judge(Arc::new(|_| Ok(Holder::Service)));
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
    ctl.set_hub_admin(Arc::new(move |args, _input| {
        said.lock().unwrap().push(args.to_vec());
        match args.get(1).map(String::as_str) {
            Some("owner-token") => Ok(json!({"messages": [], "token": owner})),
            Some("uninstall") if refusing.load(std::sync::atomic::Ordering::SeqCst) => {
                Err("the service did not stop".into())
            }
            _ => Ok(json!({"messages": []})),
        }
    }));
    let settings = dir.path().join("nerve-app/settings.json");
    ctl.keep_settings(settings.clone());
    ctl.center_role(run.clone());
    let hub = window.global::<Hub>();

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
    hub.invoke_show(HubPage::Help);
    assert!(hub.get_commands().iter().any(|c| c.name == "owner-token"),);

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
    let install = window.global::<nerve::Install>();
    assert!(!hub.get_shown() && !hub.get_role_open());
    assert!(install.get_shown());
    assert_eq!(install.get_role(), 0, "the node is picked");
    rt.block_on(center.stop());
}
