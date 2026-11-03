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
        Path::new(env!("CARGO_BIN_EXE_nerve-node-desktop")),
        d.path(),
        "nerve-node",
    );
    assert_eq!(
        said(&app, &["--version"]).trim(),
        format!("nerve-node-desktop {}", env!("CARGO_PKG_VERSION"))
    );
    let v: serde_json::Value =
        serde_json::from_str(&said(&app, &["--json", "service", "status"])).unwrap();
    let program = PathBuf::from(v["program"].as_str().unwrap());
    assert_eq!(program.file_stem().unwrap(), "nerve-node-desktop", "{v}");
}
