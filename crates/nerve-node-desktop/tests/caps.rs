//! The Capabilities page against a running node of its own: a capability of
//! node.toml added through the dialog lands in node.toml and in what the
//! running node offers; a schema outside the subset shows its reason in the
//! dialog while it is typed, and nothing is saved; what only the node can
//! tell it refuses on save, and the dialog says why; an edit, and a removal
//! after its question. One test: Slint takes one platform per process.

#![cfg(unix)]

use std::path::Path;
use std::time::Duration;

use nerve_conformance::fake_center::FakeCenter;
use nerve_node::{Daemon, NodeOptions, NodePaths};
use nerve_node_desktop::app::{Ctl, Exec};
use nerve_node_desktop::headless::Screen;
use nerve_node_desktop::runner::Runner;
use nerve_node_desktop::{AppWindow, Caps, Load, Page, Store};
use nerve_policy::NodeConfig;
use slint::{ComponentHandle, Model};

fn config(paths: &NodePaths) -> NodeConfig {
    NodeConfig::load(&paths.config_file()).unwrap()
}

const SAY: &str =
    r#"{"type": "object", "properties": {"word": {"type": "string"}}, "required": ["word"]}"#;

#[test]
fn a_capability_is_added_through_the_dialog() {
    let screen = Screen::install(1180, 780, 1.0).unwrap();
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
    // The node's own limit for a capability's time, lower than the default:
    // the dialog checks against it.
    run(&["config", "set", "limits.max_timeout_secs", "30"]);

    // The node runs, by hand, and offers the capabilities of node.toml as
    // a test lets it (the installed node runs them as nerve-run).
    let mut opts = NodeOptions::new(paths.clone());
    opts.home = root.to_path_buf();
    opts.full_rights = Some(false);
    opts.exe = Some(env!("CARGO_BIN_EXE_nerve-node-desktop").into());
    opts.config_caps_by_hand = true;
    let node = rt.block_on(Daemon::start(opts)).unwrap();

    let window = AppWindow::new().unwrap();
    let ctl = Ctl::attach(&window, runner.clone(), Exec::Inline);
    window.show().unwrap();
    let store = window.global::<Store>();
    let caps = window.global::<Caps>();
    ctl.refresh_status();
    store.invoke_show(Page::Capabilities);
    assert_eq!(caps.get_load(), Load::Ready, "{}", caps.get_error());
    assert!(caps.get_running());
    assert_eq!(caps.get_center(), "home");
    assert_eq!(caps.get_declared().row_count(), 0);

    // The answer of a reading the page asked for before its last one (the
    // owner picked another center meanwhile) comes late: it is dropped.
    let stale = ctl.caps_asked();
    caps.invoke_refresh();
    assert!(ctl.caps_asked() > stale);
    let elsewhere = serde_json::json!({"running": true, "capabilities": [
        {"name": "elsewhere.go", "effect": "read", "source": "built-in", "summary": "",
         "centers": {"other": "on"}, "now": {"other": "on"}}
    ], "config": [{"name": "elsewhere.go", "effect": "read", "command": ["true"]}]});
    ctl.caps_loaded(stale, "other", Ok(elsewhere));
    assert!(
        caps.get_rows()
            .iter()
            .all(|r| !r.name.starts_with("elsewhere"))
    );
    assert_eq!(caps.get_declared().row_count(), 0);

    // A new one: the dialog opens empty, without errors, its Arguments box
    // at the top whatever an earlier dialog left.
    caps.set_params_scrolled(-40.0);
    caps.invoke_add();
    assert!(caps.get_edit_open() && caps.get_edit_new());
    assert_eq!(caps.get_params_scrolled(), 0.0);
    assert_eq!(caps.get_name_error(), "");
    assert!(!caps.get_edit_ready());
    screen.draw();
    // Save is offered with nothing typed: a click shows what is missing,
    // and runs nothing.
    caps.invoke_edit_save();
    assert!(caps.get_edit_open() && caps.get_edit_error().is_empty());
    assert!(!caps.get_name_error().is_empty(), "no name asked for");
    // Typing in another field does not take the message away again.
    caps.set_edit_summary("Says a word.".into());
    caps.invoke_edit_check();
    assert!(!caps.get_name_error().is_empty(), "the name error went");
    caps.set_edit_name("say.back".into());
    caps.set_edit_summary("Says a word back.".into());
    caps.invoke_edit_save();
    assert!(caps.get_edit_open() && caps.get_edit_error().is_empty());
    assert!(!caps.get_command_error().is_empty(), "no command asked for");
    caps.invoke_edit_check();
    assert!(
        !caps.get_command_error().is_empty(),
        "the command error went"
    );
    assert!(config(&paths).capabilities.is_empty());
    caps.set_edit_command(r#"printf "[%s]" {word}"#.into());
    // A schema outside the subset: its reason at the field while it is
    // typed, Save off, and a save that tries anyway saves nothing.
    caps.set_edit_params(
        r#"{"type": "object", "properties": {"word": {"oneOf": [{"type": "string"}]}}, "required": ["word"]}"#
            .into(),
    );
    caps.invoke_edit_check();
    let why = caps.get_params_error();
    assert!(
        why.contains("/properties/word") && why.contains("oneOf"),
        "{why}"
    );
    assert!(!caps.get_edit_ready());
    caps.invoke_edit_save();
    assert!(caps.get_edit_open(), "the dialog closed on a broken schema");
    assert_eq!(caps.get_edit_error(), "", "the app ran the save");
    assert!(
        config(&paths).capabilities.is_empty(),
        "a broken schema was saved"
    );
    // A placeholder that names no argument says so at the command.
    caps.set_edit_params("".into());
    caps.invoke_edit_check();
    assert_eq!(caps.get_params_error(), "");
    assert!(
        caps.get_command_error().contains("word"),
        "{}",
        caps.get_command_error()
    );
    caps.set_edit_params(SAY.into());
    caps.invoke_edit_check();
    assert_eq!(caps.get_command_error(), "");
    assert!(caps.get_edit_ready());

    // Saved with `cap add`, the schema on stdin: in node.toml, on the page,
    // and offered by the running node, which lets home use it once it is
    // on for home (a read without a path needs that in folder mode).
    caps.invoke_edit_save();
    assert!(!caps.get_edit_open(), "{}", caps.get_edit_error());
    assert!(
        store.get_toast().contains("capability say.back added"),
        "{}",
        store.get_toast()
    );
    let declared = config(&paths).capabilities;
    assert_eq!(declared.len(), 1);
    assert_eq!(declared[0].command, ["printf", "[%s]", "{word}"]);
    assert_eq!(
        declared[0].params,
        serde_json::from_str::<serde_json::Value>(SAY).unwrap()
    );
    let listed = caps.get_declared().row_data(0).unwrap();
    assert_eq!(listed.name, "say.back");
    let row = |name: &str| caps.get_rows().iter().find(|r| r.name == name);
    let say = row("say.back").expect("the running node lists it");
    assert_eq!((say.source.as_str(), say.left_out.as_str()), ("config", ""));
    assert!(say.switchable);
    caps.invoke_cap_set("say.back".into(), 0);
    let mut offered = false;
    for _ in 0..50 {
        if row("say.back").is_some_and(|r| r.now == "on") {
            offered = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
        caps.invoke_refresh();
    }
    assert!(offered, "{:?}", row("say.back"));

    // The answer of a save belongs to the dialog that sent it. The owner
    // closed it before the node refused: the reason is a toast. Another
    // dialog is open by now: it keeps what was typed and shows nothing of
    // the old answer; its own answer comes to it.
    caps.invoke_edit("say.back".into());
    let first = ctl.cap_dialog_id();
    caps.set_edit_open(false);
    ctl.cap_saved(first, Err("the first reason".into()));
    assert!(
        store.get_toast().contains("the first reason"),
        "a refusal after Esc is lost"
    );
    assert_eq!(caps.get_edit_error(), "");
    caps.invoke_edit("say.back".into());
    assert!(ctl.cap_dialog_id() > first);
    caps.set_edit_summary("typed after".into());
    ctl.cap_saved(first, Ok(serde_json::json!({})));
    assert!(caps.get_edit_open(), "an old answer closed the new dialog");
    ctl.cap_saved(first, Err("the first reason".into()));
    assert_eq!(caps.get_edit_error(), "");
    assert_eq!(caps.get_edit_summary(), "typed after");
    ctl.cap_saved(ctl.cap_dialog_id(), Err("its own reason".into()));
    assert_eq!(caps.get_edit_error(), "its own reason");
    assert!(!caps.get_edit_busy());
    caps.set_edit_open(false);

    // An edit: the fields as declared; the name stays. A time over the
    // node's limit (30, as the page read it) is refused by the dialog
    // itself, with that number.
    caps.invoke_edit("say.back".into());
    assert!(caps.get_edit_open() && !caps.get_edit_new());
    assert_eq!(caps.get_edit_command(), "printf [%s] {word}");
    assert!(caps.get_edit_params().contains("\"word\""));
    caps.set_edit_summary("Says one word back.".into());
    caps.set_edit_timeout("100".into());
    caps.invoke_edit_check();
    assert!(!caps.get_edit_ready());
    assert!(
        caps.get_timeout_error().contains("(30)"),
        "{}",
        caps.get_timeout_error()
    );
    // What the app cannot know: the limit was lowered by hand since the
    // page read it. The node refuses the save, in the dialog, which stays
    // open.
    run(&["config", "set", "limits.max_timeout_secs", "10"]);
    caps.set_edit_timeout("20".into());
    caps.invoke_edit_check();
    assert!(caps.get_edit_ready(), "{}", caps.get_timeout_error());
    caps.invoke_edit_save();
    assert!(caps.get_edit_open());
    assert!(
        caps.get_edit_error().contains("max_timeout_secs"),
        "{}",
        caps.get_edit_error()
    );
    assert_eq!(config(&paths).capabilities[0].summary, "Says a word back.");
    // The owner raises the node's limit (Settings > Limits): the dialog
    // checks against that one, not the default 3600, so a time above that
    // is saved, and an entry declared with one opens without an error.
    run(&["config", "set", "limits.max_timeout_secs", "7200"]);
    caps.invoke_refresh();
    caps.set_edit_timeout("5400".into());
    caps.invoke_edit_check();
    assert!(caps.get_edit_ready(), "{}", caps.get_timeout_error());
    caps.invoke_edit_save();
    assert!(!caps.get_edit_open(), "{}", caps.get_edit_error());
    assert_eq!(config(&paths).capabilities[0].timeout_secs, Some(5400));
    caps.invoke_edit("say.back".into());
    assert_eq!(caps.get_edit_timeout(), "5400");
    assert_eq!(caps.get_timeout_error(), "");
    assert!(caps.get_edit_ready());
    caps.set_edit_summary("Says one word back.".into());
    caps.set_edit_timeout("20".into());
    caps.invoke_edit_save();
    assert!(!caps.get_edit_open(), "{}", caps.get_edit_error());
    let c = &config(&paths).capabilities[0];
    assert_eq!(
        (c.summary.as_str(), c.timeout_secs),
        ("Says one word back.", Some(20))
    );
    // The owner empties the field again (Settings > Limits unsets the
    // key): the node is back at its default, which the dialog checks
    // against, not the 7200 it read before.
    run(&["config", "unset", "limits.max_timeout_secs"]);
    caps.invoke_refresh();
    caps.invoke_edit("say.back".into());
    assert_eq!(caps.get_edit_timeout(), "20");
    caps.set_edit_timeout("5400".into());
    caps.invoke_edit_check();
    assert!(
        caps.get_timeout_error().contains("(3600)"),
        "{}",
        caps.get_timeout_error()
    );
    assert!(!caps.get_edit_ready());
    caps.set_edit_timeout("3000".into());
    caps.invoke_edit_check();
    assert_eq!(caps.get_timeout_error(), "");
    assert!(caps.get_edit_ready());
    caps.set_edit_open(false);
    // A field emptied in an edit is cleared, not kept.
    caps.invoke_edit("say.back".into());
    assert_eq!(caps.get_edit_timeout(), "20");
    caps.set_edit_timeout("".into());
    caps.set_edit_summary("".into());
    caps.invoke_edit_save();
    assert!(!caps.get_edit_open(), "{}", caps.get_edit_error());
    let c = &config(&paths).capabilities[0];
    assert_eq!((c.summary.as_str(), c.timeout_secs), ("", None));

    // Removed after its question.
    caps.invoke_remove("say.back".into());
    assert!(store.get_confirm_open());
    assert_eq!(config(&paths).capabilities.len(), 1);
    store.invoke_confirm_accepted();
    assert!(config(&paths).capabilities.is_empty());
    assert_eq!(caps.get_declared().row_count(), 0);
    assert!(row("say.back").is_none());

    rt.block_on(node.stop());
}
