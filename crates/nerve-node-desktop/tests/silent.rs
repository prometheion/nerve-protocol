//! `--silent`, the install winget runs (#67), is the program's own `install`
//! without a window and without a question: it reads no input. Here, not
//! as root, it ends at once with the install's own refusal.

#![cfg(target_os = "linux")]

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn a_silent_install_runs_install_without_a_window_or_a_question() {
    // SAFETY: a plain getter.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_nerve-node-desktop"))
        .arg("--silent")
        .env("XDG_RUNTIME_DIR", d.path())
        .env("DISPLAY", ":nerve-test")
        .env_remove("WAYLAND_DISPLAY")
        .env_remove("WAYLAND_SOCKET")
        // Open and empty: a question would wait on it.
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if start.elapsed() > Duration::from_secs(30) {
            let _ = child.kill();
            panic!("--silent did not end");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    assert!(!status.success(), "{status}");
    assert!(
        err.contains("install needs root: run `sudo nerve-node install`"),
        "{err}"
    );
}
