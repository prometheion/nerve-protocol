//! The exec shim (`nerve-node __exec-shim`) enters the folder its spec names
//! before it starts the command: on Windows the node starts the shim of
//! another account in the program's own folder, as the node's account may
//! not look into the command's (#149).
#![cfg(target_os = "linux")]

use std::io::Write;
use std::process::{Command, Stdio};

fn shim(spec: serde_json::Value) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nerve-node"))
        .arg(nerve_sandbox::SHIM_ARG)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(spec.to_string().as_bytes()).unwrap();
    drop(stdin);
    child.wait_with_output().unwrap()
}

#[test]
fn the_shim_starts_the_command_in_the_folder_its_spec_names() {
    let d = tempfile::tempdir().unwrap();
    let there = d.path().canonicalize().unwrap();
    let o = shim(serde_json::json!({
        "program": "/bin/sh",
        "args": ["-c", "pwd -P"],
        "parent": std::process::id(),
        "cwd": there,
    }));
    assert!(o.status.success(), "{o:?}");
    assert_eq!(
        String::from_utf8_lossy(&o.stdout).trim(),
        there.to_str().unwrap()
    );

    // One it cannot enter: the command does not start.
    let o = shim(serde_json::json!({
        "program": "/bin/sh",
        "args": ["-c", "echo ran"],
        "parent": std::process::id(),
        "cwd": there.join("missing"),
    }));
    assert_eq!(o.status.code(), Some(nerve_sandbox::SHIM_FAILED), "{o:?}");
    assert!(o.stdout.is_empty(), "{o:?}");
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("cannot enter"),
        "{o:?}"
    );
}
