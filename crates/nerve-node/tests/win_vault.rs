//! The installed Windows node's secrets in the Credential Manager of its
//! service account (Q8), end to end: an administrator's CLI, as the app runs
//! it, moves the keys into it and back, and sets a proxy with a login, whose
//! password goes there too; a backup carries it in its own encryption, and a
//! restore with the node stopped puts it back there once the node starts.
//!
//! It needs a Windows test machine with Nerve installed as a service (as CI's
//! `windows-installed` job installs it) and an elevated terminal:
//!
//! ```text
//! cargo test -p nerve-node --test win_vault -- --ignored --exact the_service_keeps_its_secrets_in_its_own_credential_manager
//! ```
//!
//! It pairs the service with a center named `winvault`, and takes the
//! pairing, the proxy and the keyring away again.
#![cfg(windows)]

mod common;

use common::linked_skipping_ended;
use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use nerve_conformance::fake_center::FakeCenter;
use nerve_node::edition::{DESKTOP_PROGRAM, Edition};
use nerve_node::service::Layout;

const WAIT: Duration = Duration::from_secs(30);
const CENTER: &str = "winvault";
const PASSWORD: &str = "pa55-w0rd-vault";
const PASSPHRASE: &str = "a passphrase for the test";

static APP: Edition = Edition {
    program: DESKTOP_PROGRAM,
    parts: None,
};

/// The installed program with `args`, `input` on its stdin.
fn node(layout: &Layout, args: &[&str], input: &str) -> Output {
    let mut c = Command::new(&layout.bin)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    c.wait_with_output().unwrap()
}

fn ok(layout: &Layout, args: &[&str], input: &str) -> String {
    let o = node(layout, args, input);
    assert!(o.status.success(), "{args:?}: {o:?}");
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn service(verb: &str) {
    let ok = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-Command",
            &format!("{verb}-Service nerve-node"),
        ])
        .status()
        .unwrap()
        .success();
    assert!(ok, "{verb}-Service nerve-node");
}

/// Waits until the started service answers on its pipe.
fn answers(layout: &Layout) {
    let until = Instant::now() + WAIT;
    while !node(layout, &["status"], "").status.success() {
        assert!(Instant::now() < until, "the node does not answer");
        std::thread::sleep(Duration::from_millis(500));
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the node installed as a service on a Windows test machine"]
async fn the_service_keeps_its_secrets_in_its_own_credential_manager() {
    let layout = Layout::of(&APP);
    let paths = layout.paths.clone();
    let mut center = FakeCenter::start(false).await.unwrap();
    // What an earlier run left goes first: the keys in files, no proxy.
    ok(&layout, &["proxy", "off"], "");
    ok(
        &layout,
        &["config", "set", "machine.secret_storage", "file"],
        "",
    );
    nerve_node::cli::edit(&paths, |cfg| {
        cfg.centers.retain(|c| c.name != CENTER);
        Ok(())
    })
    .await
    .expect("the owner's edit");
    let _ = std::fs::remove_file(paths.key_file(CENTER));
    nerve_node::pair::pair(&paths, &center.link(), Some(CENTER))
        .await
        .expect("pair");
    let key = paths.key_file(CENTER);
    assert!(key.exists());

    // Into the Credential Manager: the running service moves them, so no
    // key file is left, and it still links after a restart.
    ok(
        &layout,
        &["config", "set", "machine.secret_storage", "keyring"],
        "",
    );
    assert!(!key.exists());
    service("Restart");
    answers(&layout);
    // The node links with its key in the vault.
    linked_skipping_ended(&mut center, WAIT).await;

    // A proxy with a login: its password goes there too, never into a file.
    let url = format!("http://alice:{PASSWORD}@127.0.0.1:9");
    ok(&layout, &["proxy", "set", &url], "");
    let shown = ok(&layout, &["proxy"], "");
    assert!(
        shown.contains("The header values are in the system keyring."),
        "{shown}"
    );
    assert!(!shown.contains(PASSWORD), "{shown}");
    let toml = std::fs::read_to_string(paths.config_file()).unwrap();
    assert!(!toml.contains(PASSWORD), "{toml}");

    // A backup carries it in its own encryption.
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("vault.bak");
    let file_s = file.display().to_string();
    ok(
        &layout,
        &[
            "backup",
            &file_s,
            "--include-keyring",
            "--overwrite",
            "--passphrase-file",
            "-",
        ],
        &format!("{PASSPHRASE}\n"),
    );
    let sealed = std::fs::read(&file).unwrap();
    assert!(
        !sealed
            .windows(PASSWORD.len())
            .any(|w| w == PASSWORD.as_bytes())
    );
    ok(&layout, &["proxy", "off"], "");

    // A restore with the node stopped: it waits, sealed, and the node takes
    // it into its Credential Manager as it starts.
    service("Stop");
    ok(
        &layout,
        &["restore", &file_s, "--passphrase-file", "-"],
        &format!("{PASSPHRASE}\n"),
    );
    let pending = paths.config_dir.join("keys").join("vault.pending");
    assert!(pending.exists());
    service("Start");
    answers(&layout);
    let until = Instant::now() + WAIT;
    while pending.exists() {
        assert!(Instant::now() < until, "the node did not take {pending:?}");
        std::thread::sleep(Duration::from_millis(200));
    }
    let shown = ok(&layout, &["proxy"], "");
    assert!(
        shown.contains("The header values are in the system keyring."),
        "{shown}"
    );
    assert!(shown.contains("127.0.0.1:9"), "{shown}");

    // And back into files.
    ok(&layout, &["proxy", "off"], "");
    ok(
        &layout,
        &["config", "set", "machine.secret_storage", "file"],
        "",
    );
    assert!(key.exists());
    nerve_node::cli::edit(&paths, |cfg| {
        cfg.centers.retain(|c| c.name != CENTER);
        Ok(())
    })
    .await
    .expect("the owner's edit");
}
