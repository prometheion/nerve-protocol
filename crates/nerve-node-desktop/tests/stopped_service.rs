//! A stopped installed node whose folders the owner may not open answers
//! `status` with its service and no centers. The app takes that for "the
//! centers are not known": no first-run steps, the centers it has stay.
//! One test: Slint takes one platform per process.

use nerve_node::NodePaths;
use nerve_node_desktop::app::{Ctl, Exec};
use nerve_node_desktop::headless::Screen;
use nerve_node_desktop::runner::Runner;
use nerve_node_desktop::{AppWindow, Load, Store};
use slint::{ComponentHandle, Model};

#[test]
fn a_stopped_service_whose_folders_are_closed_opens_no_first_run() {
    let _screen = Screen::install(1180, 780, 1.0).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let paths = NodePaths::new(dir.path().join("config"), dir.path().join("state"));
    let runner = Runner::new(
        env!("CARGO_BIN_EXE_nerve-node-desktop").into(),
        Some(paths.config_dir.clone()),
        Some(paths.state_dir.clone()),
    );
    let window = AppWindow::new().unwrap();
    let ctl = Ctl::attach(&window, runner, Exec::Inline);
    let store = window.global::<Store>();
    ctl.offer_setup();

    let stopped = serde_json::json!({
        "daemon": "not running",
        "unread": "cannot read /etc/nerve/node.toml: permission denied",
        "service": {"installed": true, "state": "stopped", "enabled": true},
    });
    ctl.show_status(Ok(stopped.clone()));
    assert!(!store.get_setup_open(), "the first-run steps opened");
    assert_eq!(store.get_status_load(), Load::Failed);
    assert!(
        store.get_status_error().contains("Start it"),
        "{}",
        store.get_status_error()
    );

    // The centers the app knew stay, and a later answer is still the first.
    let running = serde_json::json!({"daemon": "running",
        "centers": [{"name": "home", "mode": "user"}]});
    ctl.show_status(Ok(running));
    assert_eq!(store.get_status_load(), Load::Ready);
    assert_eq!(store.get_centers().row_count(), 1);
    ctl.show_status(Ok(stopped));
    assert_eq!(
        store.get_centers().row_count(),
        1,
        "the centers were emptied"
    );
    assert!(!store.get_setup_open());
}
