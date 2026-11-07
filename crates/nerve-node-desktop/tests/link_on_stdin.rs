//! A `nerve://` link the desktop opens the app with leaves the app's command
//! line at once: the start that has it hands it to a new start on stdin and
//! ends, and the new start takes it to the open window (#198).

#![cfg(target_os = "linux")]

use std::io::BufRead;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

#[test]
fn a_link_reaches_the_open_window_without_staying_on_a_command_line() {
    let d = tempfile::tempdir().unwrap();
    // Private, as $XDG_RUNTIME_DIR is; the listener stands for the open
    // window.
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let window =
        std::os::unix::net::UnixListener::bind(d.path().join("nerve-node-desktop.sock")).unwrap();
    window.set_nonblocking(true).unwrap();
    let link = "nerve://pair?center=https%3A%2F%2Fc.example%3A8443&code=c0de-c0de&pin=p1n";
    let start = Instant::now();
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_nerve-node-desktop"))
        .arg(link)
        .env("XDG_RUNTIME_DIR", d.path())
        .env("DISPLAY", ":nerve-test")
        .env_remove("WAYLAND_DISPLAY")
        .env_remove("WAYLAND_SOCKET")
        .stdin(std::process::Stdio::null())
        .status()
        .unwrap();
    // The start with the link on its command line ends at once, before the
    // window has the link.
    assert!(status.success(), "{status}");
    assert!(start.elapsed() < Duration::from_secs(10));
    let conn = loop {
        match window.accept() {
            Ok((c, _)) => break c,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(start.elapsed() < Duration::from_secs(20), "no start came");
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("{e}"),
        }
    };
    conn.set_nonblocking(false).unwrap();
    let mut line = String::new();
    std::io::BufReader::new(conn).read_line(&mut line).unwrap();
    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v["link"], link, "{line}");
}
