//! An owner of the installed node opens the app without a question: the
//! commands run as the owner, and only one that needs an administrator
//! (nerve_node::owner::needs_admin) asks, that once. Commands that run as
//! the app's own user are warned about on the Overview.
//! One test: Slint takes one platform per process.

#![cfg(target_os = "linux")]

use std::path::Path;

use nerve_node::NodePaths;
use nerve_node_desktop::app::{Ctl, Exec};
use nerve_node_desktop::broker::Launch;
use nerve_node_desktop::headless::Screen;
use nerve_node_desktop::runner::Runner;
use nerve_node_desktop::{AppWindow, Load, Perm, Prefs, Store};
use slint::ComponentHandle;

/// How often the program was started as the broker, from its log.
fn brokers(log: &Path) -> usize {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter(|l| *l == nerve_node_desktop::broker::ARG)
        .count()
}

#[test]
fn an_owner_is_asked_only_for_what_needs_an_administrator() {
    let _screen = Screen::install(1180, 780, 1.0).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let root: &Path = dir.path();
    let paths = NodePaths::new(root.join("config"), root.join("state"));
    // The program, which notes each start's first argument. It stands in
    // for the service's start and stop (no service is installed here), and
    // refuses a restore as the node refuses an owner one that changes the
    // account commands run as, while `refuse` is there.
    let log = root.join("starts");
    let refuse = root.join("refuse");
    let wrapper = root.join("nerve-node-desktop");
    let script = format!(
        "#!/bin/sh\necho \"$1\" >> '{log}'\n\
         case \" $* \" in\n\
         *' service stop '* | *' service start '*) echo '{{\"messages\": [\"done\"]}}'; exit 0 ;;\n\
         *' restore '*) if [ -e '{refuse}' ]; then echo '{{\"error\": \"the backup sets machine.shell other than it is here: {by} root\"}}'; exit 1; fi ;;\n\
         esac\n\
         exec '{exe}' \"$@\"\n",
        log = log.display(),
        refuse = refuse.display(),
        by = nerve_node::owner::RESTORE_BY_ADMIN,
        exe = env!("CARGO_BIN_EXE_nerve-node-desktop")
    );
    // Written by a child, so no thread of this test holds it open for
    // writing when it runs (ETXTBSY).
    let made = std::process::Command::new("sh")
        .arg("-c")
        .arg("cat > \"$1\" && chmod 755 \"$1\"")
        .arg("sh")
        .arg(&wrapper)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            use std::io::Write;
            c.stdin.take().unwrap().write_all(script.as_bytes())?;
            c.wait()
        })
        .unwrap();
    assert!(made.success());
    let runner = Runner::new(
        wrapper.clone(),
        Some(paths.config_dir.clone()),
        Some(paths.state_dir.clone()),
    );
    let window = AppWindow::new().unwrap();
    let ctl = Ctl::attach(&window, runner, Exec::Inline);
    let store = window.global::<Store>();
    let perm = window.global::<Perm>();
    ctl.watch_service(true, &wrapper);
    ctl.admin_rights(Launch::Plain);

    // Opening and changing: no question.
    ctl.refresh_status();
    assert_eq!(
        store.get_status_load(),
        Load::Ready,
        "{}",
        store.get_status_error()
    );
    assert!(!store.get_elevate_open() && !store.get_elevate_needed());
    store.invoke_panic();
    store.invoke_unlock();
    assert_eq!(brokers(&log), 0);

    // Sudo on needs an administrator: asked for that command alone.
    perm.set_sudo_password("not the password".into());
    perm.invoke_sudo_confirm();
    assert_eq!(brokers(&log), 1);
    store.invoke_panic();
    store.invoke_unlock();
    assert_eq!(brokers(&log), 1, "the rights outlived their command");

    // Backup and restore go through the node for an owner: no question.
    let prefs = window.global::<Prefs>();
    let file = root.join("node.backup");
    let pass = "correct horse battery";
    prefs.set_backup_file(file.display().to_string().into());
    prefs.set_backup_pass(pass.into());
    prefs.set_backup_pass2(pass.into());
    prefs.invoke_backup_confirm();
    assert!(file.is_file(), "{}", prefs.get_backup_error());
    assert_eq!(brokers(&log), 1);
    store.set_service_state("running".into());
    let restore = || {
        prefs.set_restore_file(file.display().to_string().into());
        prefs.set_restore_pass(pass.into());
        prefs.set_restore_error("".into());
        prefs.invoke_restore_confirm();
        assert_eq!(prefs.get_restore_error(), "");
        assert!(!prefs.get_restore_busy());
    };
    restore();
    assert_eq!(brokers(&log), 1);
    // One the node refuses an owner is restored the administrator's way:
    // the rights are asked for it alone.
    std::fs::write(&refuse, "").unwrap();
    restore();
    assert_eq!(brokers(&log), 2);
}
