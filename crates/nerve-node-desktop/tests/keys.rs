//! The keyboard drives the app: Ctrl+1 to Ctrl+9 open the pages, Ctrl+R and
//! F5 read the open page again, Escape closes a dialog and Enter takes its
//! main button. A click on the tab of the page that is open reads nothing
//! again (it flickered on Audit and Log); only Refresh does.
//! One test: Slint takes one platform per process.

#![cfg(unix)]

use std::path::Path;

use nerve_node::NodePaths;
use nerve_node_desktop::app::{Ctl, Exec};
use nerve_node_desktop::headless::Screen;
use nerve_node_desktop::runner::Runner;
use nerve_node_desktop::{AppWindow, Page, Store};
use slint::ComponentHandle;
use slint::platform::{Key, WindowEvent};

/// The commands the app started, one line each, from the program's log.
fn started(log: &Path) -> Vec<String> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

#[test]
fn the_keyboard_drives_the_app_and_the_open_tab_stays() {
    let _screen = Screen::install(1180, 700, 1.0).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let root: &Path = dir.path();
    let paths = NodePaths::new(root.join("config"), root.join("state"));
    // The program, which notes each start's words before it runs.
    let log = root.join("starts");
    let wrapper = root.join("nerve-node-desktop");
    let script = format!(
        "#!/bin/sh\necho \"$*\" >> '{log}'\nexec '{exe}' \"$@\"\n",
        log = log.display(),
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
        wrapper,
        Some(paths.config_dir.clone()),
        Some(paths.state_dir.clone()),
    );
    let window = AppWindow::new().unwrap();
    let _ctl = Ctl::attach(&window, runner, Exec::Inline);
    window.show().unwrap();
    let store = window.global::<Store>();
    let press = |text: slint::SharedString| {
        window
            .window()
            .dispatch_event(WindowEvent::KeyPressed { text: text.clone() });
        window
            .window()
            .dispatch_event(WindowEvent::KeyReleased { text });
    };
    let ctrl = |c: &str| {
        let control: slint::SharedString = Key::Control.into();
        window.window().dispatch_event(WindowEvent::KeyPressed {
            text: control.clone(),
        });
        press(c.into());
        window
            .window()
            .dispatch_event(WindowEvent::KeyReleased { text: control });
    };

    // The open page's tab reads nothing again; Refresh, Ctrl+R and F5 do.
    store.invoke_show(Page::Settings);
    let read = started(&log).len();
    assert!(read > 0, "Settings read nothing");
    store.invoke_show(Page::Settings);
    assert_eq!(
        started(&log).len(),
        read,
        "the open tab read its page again"
    );
    store.invoke_reload();
    let again = started(&log).len();
    assert!(again > read, "Refresh read nothing");
    ctrl("r");
    let ctrl_r = started(&log).len();
    assert!(ctrl_r > again, "Ctrl+R read nothing");
    press(Key::F5.into());
    assert!(started(&log).len() > ctrl_r, "F5 read nothing");

    // Ctrl+1 to Ctrl+8: the pages in the sidebar's order, as it was before
    // Capabilities came; Ctrl+9 opens that.
    for (key, page) in [
        ("2", Page::Centers),
        ("3", Page::Relay),
        ("4", Page::Policy),
        ("9", Page::Capabilities),
        ("5", Page::Audit),
        ("6", Page::Log),
        ("7", Page::Settings),
        ("8", Page::Help),
        ("1", Page::Overview),
    ] {
        ctrl(key);
        assert_eq!(store.get_page(), page, "Ctrl+{key}");
    }

    // Escape closes a dialog, and the window's shortcuts work again after;
    // while it is open they wait.
    store.set_about_open(true);
    ctrl("2");
    assert_eq!(
        store.get_page(),
        Page::Overview,
        "a page opened behind a dialog"
    );
    press(Key::Escape.into());
    assert!(!store.get_about_open(), "Escape left About open");
    ctrl("8");
    assert_eq!(store.get_page(), Page::Help, "no shortcut after a dialog");

    // Enter takes the dialog's main button: the unpairing it asks about.
    store.invoke_center_unpair("lab".into());
    assert!(store.get_confirm_open());
    press(Key::Return.into());
    assert!(!store.get_confirm_open(), "Enter left the question open");
    assert!(
        started(&log)
            .iter()
            .any(|l| l.contains("center rm --center=lab")),
        "Enter did not unpair: {:?}",
        started(&log)
    );
}
