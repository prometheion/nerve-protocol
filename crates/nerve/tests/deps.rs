//! The program itself where the desktop is missing (crate::deps): no
//! display, and a display whose window does not open, which it tries once
//! more drawing in software. Started without arguments, as the menu does,
//! with nothing of this session: no display, an empty PATH (so no desktop
//! notification goes out) and folders of its own.

#![cfg(target_os = "linux")]

use std::process::{Command, Output};

fn start(vars: &[(&str, &str)]) -> Output {
    let d = tempfile::tempdir().unwrap();
    let mut c = Command::new(env!("CARGO_BIN_EXE_nerve"));
    c.env_clear()
        .env("HOME", d.path())
        .env("XDG_RUNTIME_DIR", d.path())
        .env("PATH", d.path());
    for (k, v) in vars {
        c.env(k, v);
    }
    c.output().unwrap()
}

#[test]
fn without_a_display_it_says_so_and_ends() {
    let o = start(&[]);
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(
        err.contains("no display") && err.contains("Wayland") && err.contains("X11"),
        "{err}"
    );
}

#[test]
fn a_window_that_does_not_open_is_tried_in_software_then_said() {
    // An X11 display nobody serves: the window cannot open with either
    // renderer.
    let o = start(&[("DISPLAY", ":97")]);
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(err.contains("drawing in software"), "{err}");
    assert!(
        err.contains("the window did not open") && err.contains("SLINT_BACKEND=winit-software"),
        "{err}"
    );
}
