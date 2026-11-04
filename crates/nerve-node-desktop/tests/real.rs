//! The app installs, controls, updates and removes Nerve on a real machine,
//! through its own code as the windows' buttons run it: for a test machine
//! only, as root (on Windows as an elevated administrator), since it
//! installs the node as a service and the app's menu entry and link
//! handler, and removes them again.
//!
//! `NERVE_DESKTOP_REAL=<the nerve-node-desktop to install> cargo test -p
//! nerve-node-desktop --test real -- --ignored --nocapture`

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nerve_node::service::Layout;
use nerve_node_desktop::app::{Ctl, Exec};
use nerve_node_desktop::broker::Launch;
use nerve_node_desktop::headless::Screen;
use nerve_node_desktop::parts::EDITION;
use nerve_node_desktop::runner::Runner;
use nerve_node_desktop::{AppWindow, Install, Store};
use slint::{ComponentHandle, Model};

fn said(i: &Install<'_>) -> String {
    let did: Vec<String> = i.get_did().iter().map(|s| s.to_string()).collect();
    let warn: Vec<String> = i.get_warnings().iter().map(|s| s.to_string()).collect();
    format!("did {did:#?}\nwarned {warn:#?}\nerror {}", i.get_error())
}

fn service(runner: &Runner) -> serde_json::Value {
    runner.run(&["service", "status"]).unwrap()
}

#[test]
#[ignore = "installs Nerve on this machine; NERVE_DESKTOP_REAL names the program"]
fn install_control_update_and_uninstall_on_this_machine() {
    let Some(exe) = std::env::var_os("NERVE_DESKTOP_REAL").map(PathBuf::from) else {
        eprintln!("skipped: NERVE_DESKTOP_REAL is not set");
        return;
    };
    nerve_node::edition::set(&EDITION);
    let layout = Layout::system();
    let _screen = Screen::install(760, 640, 1.0).unwrap();
    let window = AppWindow::new().unwrap();
    let ctl = Ctl::attach(&window, Runner::new(exe.clone(), None, None), Exec::Inline);
    let opened = Arc::new(Mutex::new(Vec::new()));
    let o = opened.clone();
    ctl.set_launcher(Arc::new(move |bin| {
        o.lock().unwrap().push(bin.to_path_buf());
        Ok(())
    }));
    let install = window.global::<Install>();
    let store = window.global::<Store>();
    let cli = Runner::new(exe.clone(), None, None);

    // The downloaded file: what it installs, then Install.
    ctl.installer(Launch::Plain, &layout.bin);
    assert_eq!(
        install.get_step(),
        "welcome",
        "Nerve is installed here already"
    );
    install.invoke_install();
    eprintln!("install:\n{}", said(&install));
    assert_eq!(install.get_step(), "done", "{}", said(&install));
    let s = service(&cli);
    assert_eq!(s["state"], "running", "{s}");
    assert_eq!(s["present"], true, "{s}");
    assert!(layout.bin.is_file());
    install.invoke_open_app();
    assert_eq!(
        opened.lock().unwrap().as_slice(),
        std::slice::from_ref(&layout.bin)
    );

    // Started again from the download: Nerve is installed.
    ctl.installer(Launch::Plain, &layout.bin);
    assert_eq!(install.get_step(), "installed", "{}", said(&install));
    assert_eq!(install.get_installed_version(), install.get_version());

    // The installed app's overview: the service stops, starts and restarts.
    ctl.watch_service(true, &layout.bin);
    ctl.refresh_status();
    assert_eq!(store.get_service_state(), "running");
    for (what, state) in [
        ("stop", "stopped"),
        ("start", "running"),
        ("restart", "running"),
    ] {
        store.invoke_service(what.into());
        assert_eq!(
            store.get_service_state(),
            state,
            "{what}: {}",
            store.get_toast()
        );
        assert_eq!(service(&cli)["state"], state);
        eprintln!("service {what}: {}", store.get_toast());
    }

    // Settings: an update from a file, another build (here the same one
    // with a byte more, which runs all the same).
    let copy = std::env::temp_dir().join(format!("nerve-desktop-update-{}", std::process::id()));
    let mut bytes = std::fs::read(&exe).unwrap();
    bytes.push(b'\n');
    std::fs::write(&copy, &bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    install.set_shown(false);
    install.invoke_ask_update();
    install.set_source(1);
    install.set_file(copy.display().to_string().into());
    install.invoke_update();
    eprintln!("update:\n{}", said(&install));
    assert_eq!(install.get_step(), "done", "{}", said(&install));
    assert_eq!(std::fs::read(&layout.bin).unwrap(), bytes);
    assert_eq!(service(&cli)["state"], "running");
    let _ = std::fs::remove_file(&copy);
    std::thread::sleep(Duration::from_millis(500));

    // Settings: uninstall, the data deleted too; then the app closes.
    install.invoke_ask_uninstall();
    assert!(install.get_uninstall_open());
    install.set_purge(true);
    install.invoke_uninstall();
    eprintln!("uninstall:\n{}", said(&install));
    assert_eq!(install.get_step(), "done", "{}", said(&install));
    let s = service(&cli);
    assert_eq!(s["installed"], false, "{s}");
    assert_eq!(s["present"], false, "{s}");
    assert!(!layout.paths.config_dir.exists());
    install.invoke_close();
    assert!(install.get_closed());
    ctl.end();
}
