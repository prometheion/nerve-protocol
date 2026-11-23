//! The desktop app started through a link named `nerve-node`, as the node
//! installed alone becomes when the app takes it over
//! (nerve_node::service::node_beside): it is still the app's program, so
//! `nerve-node update` and `install` in a terminal work on the app. Linux
//! only: Windows has no node alone for the app to take over.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn link(program: &Path, dir: &Path, name: &str) -> PathBuf {
    let at = dir.join(name);
    std::os::unix::fs::symlink(program, &at).unwrap();
    at
}

fn said(program: &Path, args: &[&str]) -> String {
    let o = Command::new(program).args(args).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8(o.stdout).unwrap()
}

#[test]
fn the_app_called_nerve_node_is_the_app() {
    let d = tempfile::tempdir().unwrap();
    let app = link(
        Path::new(env!("CARGO_BIN_EXE_nerve")),
        d.path(),
        "nerve-node",
    );
    assert_eq!(
        said(&app, &["--version"]).trim(),
        format!("nerve {}", env!("CARGO_PKG_VERSION"))
    );
    let v: serde_json::Value = serde_json::from_str(&said(&app, &["--json", "status"])).unwrap();
    let program = PathBuf::from(v["service"]["program"].as_str().unwrap());
    assert_eq!(program.file_stem().unwrap(), "nerve", "{v}");
}

/// The app runs the center's command line behind its hidden word, and by
/// the terminal name `nerve-center` (a link to it): there it is the center,
/// not the window, also without arguments' help. `nerve-node` without
/// arguments is the node's command line, not the window.
#[test]
fn the_app_is_the_center_behind_its_word_and_by_its_terminal_name() {
    let d = tempfile::tempdir().unwrap();
    let exe = Path::new(env!("CARGO_BIN_EXE_nerve"));
    let state = d.path().join("state");
    let status = |program: &Path, first: &[&str]| -> serde_json::Value {
        let mut args: Vec<&str> = first.to_vec();
        args.extend(["--json", "status", "--state-dir", state.to_str().unwrap()]);
        serde_json::from_str(&said(program, &args)).unwrap()
    };
    // The center's own `status --json` answer: messages, and whether it is
    // installed, which the node's status does not say.
    let v = status(exe, &["__center"]);
    assert_eq!(v["installed"], false, "{v}");
    assert!(v["messages"].is_array(), "{v}");
    let center = link(exe, d.path(), "nerve-center");
    let v = status(&center, &[]);
    assert_eq!(v["installed"], false, "{v}");
    // The center's help names its commands.
    let help = said(&center, &["--help"]);
    assert!(help.contains("owner-token"), "{help}");
    let node = link(exe, d.path(), "nerve-node");
    let o = Command::new(&node).output().unwrap();
    let text = String::from_utf8_lossy(&o.stdout) + String::from_utf8_lossy(&o.stderr);
    assert!(text.contains("--help` lists every command"), "{text}");
}

/// A failed command of the app's program names the program, `nerve`, not
/// `nerve-node`, which Windows does not have (#213 W2-6).
#[test]
fn a_failed_command_names_the_app_s_program() {
    let d = tempfile::tempdir().unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_nerve"))
        .args(["center", "rm", "nosuch", "--config-dir"])
        .arg(d.path().join("config"))
        .arg("--state-dir")
        .arg(d.path().join("state"))
        .output()
        .unwrap();
    assert!(!o.status.success());
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.lines()
            .last()
            .unwrap_or_default()
            .starts_with("nerve: "),
        "{err}"
    );
}
