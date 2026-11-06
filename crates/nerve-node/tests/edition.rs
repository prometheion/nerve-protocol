//! Which program this is comes from the program itself, never from the name
//! it was started by (crate::edition): `nerve-node` started through a link
//! named `nerve-node-desktop` is still `nerve-node`, installs and updates as
//! it. The desktop app's tests/edition.rs checks the other way round.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A link named `name` in `dir` to `program`: a symbolic one, or on Windows
/// without the right to make one, a hard one.
fn link(program: &Path, dir: &Path, name: &str) -> PathBuf {
    let at = dir.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    #[cfg(unix)]
    std::os::unix::fs::symlink(program, &at).unwrap();
    #[cfg(windows)]
    if std::os::windows::fs::symlink_file(program, &at).is_err() {
        std::fs::hard_link(program, &at).unwrap();
    }
    at
}

fn said(program: &Path, args: &[&str]) -> String {
    let o = Command::new(program).args(args).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8(o.stdout).unwrap()
}

#[test]
fn the_node_called_by_another_name_is_the_node() {
    let d = tempfile::tempdir().unwrap();
    let node = link(
        Path::new(env!("CARGO_BIN_EXE_nerve-node")),
        d.path(),
        "nerve-node-desktop",
    );
    assert_eq!(
        said(&node, &["--version"]).trim(),
        format!("nerve-node {}", env!("CARGO_PKG_VERSION"))
    );
    // Its installed place is the node's, so install and update take it.
    let v: serde_json::Value = serde_json::from_str(&said(&node, &["--json", "status"])).unwrap();
    let program = PathBuf::from(v["service"]["program"].as_str().unwrap());
    assert_eq!(program.file_stem().unwrap(), "nerve-node", "{v}");
}
