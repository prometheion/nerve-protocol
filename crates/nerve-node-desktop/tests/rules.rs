//! Rules with conditions on an action's arguments (#152, C1) in the app:
//! the Permissions page's rule fields say what the action takes and what is
//! wrong with the conditions typed so far, a rule whose argument went is
//! flagged on its row, and an audit entry's pin buttons write the rule
//! `nerve-node rule add --pin` and the center's buttons write. One test:
//! Slint takes one platform per process.

#![cfg(unix)]

use std::path::Path;
use std::time::Duration;

use nerve_conformance::fake_center::FakeCenter;
use nerve_node::NodePaths;
use nerve_node_desktop::app::{Ctl, Exec};
use nerve_node_desktop::headless::Screen;
use nerve_node_desktop::runner::Runner;
use nerve_node_desktop::{AppWindow, Page, Perm, Store};
use nerve_policy::NodeConfig;
use serde_json::json;
use slint::{ComponentHandle, Model};

fn config(paths: &NodePaths) -> NodeConfig {
    NodeConfig::load(&paths.config_file()).unwrap()
}

/// Waits for a command that keeps answering (`audit --follow`) to bring
/// what `done` looks for into the window.
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

const LAMP: &str = r#"--params={"type": "object", "required": ["room", "level"], "properties": {"room": {"type": "string"}, "level": {"type": "integer"}}}"#;

/// Ends what follows the audit when the test ends, as the app does when it
/// closes, also when an assertion failed: the window and the controller
/// hold each other, so nothing drops the follow and its process would
/// outlive the test run.
struct Ends(std::rc::Rc<Ctl>);

impl Drop for Ends {
    fn drop(&mut self) {
        self.0.end();
    }
}

#[test]
fn rule_fields_offer_the_arguments_and_the_audit_pins_one() {
    let _screen = Screen::install(1180, 780, 1.0).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let root: &Path = dir.path();
    let paths = NodePaths::new(root.join("config"), root.join("state"));
    let runner = Runner::new(
        env!("CARGO_BIN_EXE_nerve-node-desktop").into(),
        Some(paths.config_dir.clone()),
        Some(paths.state_dir.clone()),
    );
    let run = |args: &[&str]| runner.run(args).unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let center = rt.block_on(FakeCenter::start(false)).unwrap();
    run(&[
        "center",
        "add",
        &center.link().render(),
        "--name",
        "home",
        "--yes",
    ]);
    run(&[
        "cap",
        "add",
        "lamp.set",
        "--effect=actuate",
        LAMP,
        "--",
        "echo",
        "{room}",
        "{level}",
    ]);
    run(&["rule", "add", "deny", "lamp.set:room=bedroom"]);

    let window = AppWindow::new().unwrap();
    let ctl = Ctl::attach(&window, runner.clone(), Exec::Inline);
    let _ends = Ends(ctl.clone());
    window.show().unwrap();
    let store = window.global::<Store>();
    let perm = window.global::<Perm>();
    ctl.refresh_status();
    store.invoke_show(Page::Policy);
    assert_eq!(perm.get_center(), "home");
    let deny: Vec<String> = perm.get_deny().iter().map(|r| r.to_string()).collect();
    assert!(
        deny.contains(&"lamp.set:room=bedroom".to_string()),
        "{deny:?}"
    );
    assert!(perm.get_deny_unfit().iter().all(|w| w.is_empty()));

    // The field says what the action takes, and what is wrong.
    perm.invoke_rule_typed(1, "lamp.set:".into());
    assert_eq!(
        perm.get_deny_hint(),
        "lamp.set takes level (an integer), room (a string). Pin them after the colon, joined by commas: lamp.set:level=…"
    );
    assert!(!perm.get_deny_hint_error());
    perm.invoke_rule_typed(1, "lamp.set:size=1".into());
    assert!(perm.get_deny_hint_error());
    assert_eq!(
        perm.get_deny_hint(),
        "lamp.set has no argument size; it takes level, room."
    );
    perm.invoke_rule_typed(0, "lamp.set:level=high".into());
    assert!(perm.get_allow_hint_error());
    assert!(perm.get_allow_hint().contains("is an integer"));
    for plain in ["git push", "fs.read:~/notes/*", "lamp.set"] {
        perm.invoke_rule_typed(1, plain.into());
        assert_eq!(perm.get_deny_hint(), "", "{plain}");
        assert!(!perm.get_deny_hint_error(), "{plain}");
    }
    // The rule being edited has its own.
    perm.invoke_rule_typed(3, "lamp.set:room>1".into());
    assert!(perm.get_edit_hint_error());
    assert!(perm.get_edit_hint().contains("which > does not compare"));

    // Added, the field and its hint clear; the node took it as it is.
    perm.invoke_rule_typed(1, "lamp.set:level>50".into());
    perm.set_deny_text("lamp.set:level>50".into());
    perm.invoke_rule_add(1);
    assert!(
        config(&paths).centers[0]
            .policy
            .deny
            .contains(&"lamp.set:level>50".to_string())
    );
    assert_eq!(perm.get_deny_text(), "");
    assert_eq!(perm.get_deny_hint(), "");

    // The capability takes no room now: that rule is flagged on its row.
    run(&[
        "cap",
        "edit",
        "lamp.set",
        r#"--params={"type": "object", "required": ["level"], "properties": {"level": {"type": "integer"}}}"#,
        "--",
        "echo",
        "{level}",
    ]);
    perm.invoke_refresh();
    let deny: Vec<String> = perm.get_deny().iter().map(|r| r.to_string()).collect();
    let unfit: Vec<String> = perm
        .get_deny_unfit()
        .iter()
        .map(|r| r.to_string())
        .collect();
    assert_eq!(deny.len(), unfit.len());
    for (rule, why) in deny.iter().zip(&unfit) {
        match rule.as_str() {
            "lamp.set:room=bedroom" => {
                assert_eq!(why, "lamp.set has no argument room; it takes level")
            }
            _ => assert_eq!(why, "", "{rule}"),
        }
    }

    // An audit entry with arguments offers each one to pin; a button
    // writes the rule rule_for writes, which the CLI and the center write.
    nerve_policy::audit::AuditLog::new(paths.audit_log())
        .decision(&nerve_policy::audit::Entry {
            ts: 1,
            center: "home".into(),
            cap: "exec".into(),
            action: "signal".into(),
            target: "exec.signal".into(),
            decision: "allowed".into(),
            code: None,
            session: None,
            reason: None,
            command: None,
            args: Some(
                json!({"call": 7, "signal": "kill"})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        })
        .unwrap();
    store.invoke_show(Page::Audit);
    let signal = || {
        let rows = store.get_audit();
        (0..rows.row_count()).find(|i| rows.row_data(*i).unwrap().title == "exec.signal")
    };
    until(&ctl, "the audit entry", || signal().is_some());
    let row = store.get_audit().row_data(signal().unwrap()).unwrap();
    assert!(row.rules);
    let pins: Vec<String> = row.pins.iter().map(|p| p.to_string()).collect();
    assert_eq!(pins, ["call=7", "signal=kill"]);
    store.invoke_audit_pin(row.index, "deny".into(), 1);
    let want = nerve_policy::rules::rule_for(
        "exec",
        "signal",
        "exec.signal",
        false,
        Some(("signal", &json!("kill"))),
    )
    .unwrap();
    assert_eq!(want, "exec.signal:signal=kill");
    until(&ctl, "the pinned rule", || {
        config(&paths).centers[0].policy.deny.contains(&want)
    });
    store.invoke_audit_pin(row.index, "allow".into(), 0);
    until(&ctl, "the allow rule", || {
        config(&paths).centers[0].policy.allow == ["exec.signal:call=7"]
    });
    assert!(
        store.get_toast().contains("allow list of home"),
        "{}",
        store.get_toast()
    );
}
