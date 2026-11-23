//! The app's panic when the installed service does not take the lock: it
//! stops the service, then saves the lock for the next start. An owner who
//! is no administrator has his commands go to the node's pipe or socket,
//! which the stopped service no longer has, so the save needs the
//! administrator's rights. Unlock, and a panic while the service is
//! stopped, take the same way, and the unlock starts the service (#213
//! W3-3). Slint takes one platform per process, so this is a test of its
//! own beside `app.rs`.

#![cfg(unix)]

use nerve::app::{Ctl, Exec};
use nerve::broker::Launch;
use nerve::headless::Screen;
use nerve::runner::Runner;
use nerve::{AppWindow, Store};
use nerve_node::NodePaths;
use slint::ComponentHandle;

/// Ends what the controller follows when the test ends, as `app.rs` does.
struct Ends(std::rc::Rc<Ctl>);

impl Drop for Ends {
    fn drop(&mut self) {
        self.0.end();
    }
}

#[test]
fn the_lock_after_a_stopped_service_is_saved_with_the_rights() {
    // SAFETY: before this test starts any thread.
    #[cfg(target_os = "linux")]
    unsafe {
        std::env::set_var("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
    };
    let _screen = Screen::install(1180, 780, 1.0).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let paths = NodePaths::new(root.join("config"), root.join("state"));
    let real = env!("CARGO_BIN_EXE_nerve");
    // The node as the app finds it: a service that takes no lock and stops
    // when asked. What goes through the broker is the real program's, the
    // broker being the program itself; so only a save that goes through it
    // reaches the config.
    let fake = root.join("nerve-node");
    std::fs::write(
        &fake,
        format!(
            r#"#!/bin/sh
case "$1" in {arg}) exec {real} "$@";; esac
case " $* " in
  *" service stop "*) echo '{{"state":"stopped"}}';;
  *" service start "*) touch {started}; echo '{{"state":"running"}}';;
  *" panic "*) echo '{{"error":"the node does not answer"}}'; exit 1;;
  *" unlock "*) echo '{{"error":"the node is installed as a service and does not run"}}'; exit 1;;
  *) echo '{{}}';;
esac
"#,
            arg = nerve::broker::ARG,
            started = root.join("started").display(),
        ),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let runner = Runner::new(
        fake.clone(),
        Some(paths.config_dir.clone()),
        Some(paths.state_dir.clone()),
    );
    let window = AppWindow::new().unwrap();
    let ctl = Ctl::attach(&window, runner, Exec::Inline);
    let _ends = Ends(ctl.clone());
    // The installed node, whose owner changes it without administrator
    // rights: a command asks for them only when it needs them.
    ctl.admin_rights(Launch::Plain);
    ctl.watch_service(true, &fake);
    let store = window.global::<Store>();
    store.invoke_panic();
    assert!(
        paths.config_file().is_file()
            && nerve_policy::NodeConfig::load(&paths.config_file())
                .unwrap()
                .locked,
        "the lock was not saved: {}",
        store.get_toast()
    );
    assert!(
        store.get_toast().starts_with("Locked:"),
        "{}",
        store.get_toast()
    );

    // Unlock while the service is stopped: saved with the rights, and the
    // service starts.
    let locked = || {
        nerve_policy::NodeConfig::load(&paths.config_file())
            .unwrap()
            .locked
    };
    store.invoke_unlock();
    assert!(!locked(), "not unlocked: {}", store.get_toast());
    assert!(root.join("started").is_file(), "the service did not start");
    assert!(
        store
            .get_toast()
            .starts_with("Unlocked: the service started"),
        "{}",
        store.get_toast()
    );

    // A panic while it is stopped saves the lock without stopping it first.
    store.set_service_state("stopped".into());
    store.invoke_panic();
    assert!(locked(), "the lock was not saved: {}", store.get_toast());
    assert_eq!(store.get_toast(), nerve::view::PANIC_WHILE_STOPPED);
}
