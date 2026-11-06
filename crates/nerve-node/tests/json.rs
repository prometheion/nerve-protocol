//! The program itself with `--json` (docs/dev/settings-and-config.md): a program that
//! drives it reads every answer from stdout, an error too, since stderr
//! also carries the log's events.

use std::process::Command;

use serde_json::json;

fn node(dir: &std::path::Path, args: &[&str]) -> (bool, serde_json::Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_nerve-node"))
        .arg("--config-dir")
        .arg(dir.join("config"))
        .arg("--state-dir")
        .arg(dir.join("state"))
        .arg("--json")
        .args(args)
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let v = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{e}: {text:?}"));
    (out.status.success(), v)
}

#[test]
fn every_answer_is_json_on_stdout() {
    let d = tempfile::tempdir().unwrap();
    let (ok, v) = node(d.path(), &["status"]);
    assert!(ok, "{v}");
    assert_eq!(v["daemon"], "not running", "{v}");
    let (ok, v) = node(d.path(), &["mode", "user"]);
    assert!(!ok, "{v}");
    let e = v["error"].as_str().unwrap();
    assert!(e.contains("center"), "{e}");
}

/// A passphrase comes on stdin when that is no terminal, unasked, so the
/// answer on stdout stays JSON.
#[test]
fn a_passphrase_on_stdin_is_taken_without_a_question() {
    use std::io::Write;
    let d = tempfile::tempdir().unwrap();
    let file = d.path().join("node.backup");
    let mut child = Command::new(env!("CARGO_BIN_EXE_nerve-node"))
        .arg("--config-dir")
        .arg(d.path().join("config"))
        .arg("--state-dir")
        .arg(d.path().join("state"))
        .args(["--json", "backup"])
        .arg(&file)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"correct horse battery\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(out.status.success(), "{text}");
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert!(!v["messages"].as_array().unwrap().is_empty(), "{v}");
    assert!(!text.contains("Passphrase"), "{text}");
    assert!(file.is_file());
}

fn with_stdin(dir: &std::path::Path, args: &[&str], input: &str) -> (bool, serde_json::Value) {
    use std::io::Write;
    let mut child = Command::new(env!("CARGO_BIN_EXE_nerve-node"))
        .arg("--config-dir")
        .arg(dir.join("config"))
        .arg("--state-dir")
        .arg(dir.join("state"))
        .arg("--json")
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let v = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{e}: {text:?}"));
    (out.status.success(), v)
}

/// A proxy's password comes on stdin, never as an argument that every
/// process could read. (An https:// proxy's: the node keeps it with its own
/// keys, so no system keyring is asked here.)
#[test]
fn a_proxy_password_comes_on_stdin() {
    let d = tempfile::tempdir().unwrap();
    // A user name without a password reads it; an empty one is refused.
    let (ok, v) = with_stdin(
        d.path(),
        &["proxy", "set", "https://laptop@relay.example:7490"],
        "\n",
    );
    assert!(!ok);
    assert!(v["error"].as_str().unwrap().contains("no password"), "{v}");
    // With `--header -` the password is the first line, the headers after
    // it: an empty first line is no password either (round 1, spec 4).
    let (ok, v) = with_stdin(
        d.path(),
        &[
            "proxy",
            "set",
            "https://laptop@relay.example:7490",
            "--header",
            "-",
        ],
        "\nX-Team: lab\n",
    );
    assert!(!ok, "{v}");
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .contains("no password given: the first line of stdin is empty"),
        "{v}"
    );
    let (ok, v) = with_stdin(
        d.path(),
        &["proxy", "set", "https://laptop@relay.example:7490"],
        "s3cret\n",
    );
    assert!(ok, "{v}");
    let (_, ls) = node(d.path(), &["proxy"]);
    assert!(ls.to_string().contains("laptop"), "{ls}");
    assert!(!ls.to_string().contains("s3cret"), "{ls}");
    let config = std::fs::read_to_string(d.path().join("config/node.toml")).unwrap();
    assert!(!config.contains("s3cret"), "{config}");
}

/// Without a session bus nothing answers for the keyring, and `config get`
/// of where the keys go says so, for a program that offers the choice.
#[cfg(target_os = "linux")]
#[test]
fn where_the_keys_go_says_whether_the_keyring_can_hold_them() {
    let d = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_nerve-node"))
        .arg("--config-dir")
        .arg(d.path().join("config"))
        .arg("--state-dir")
        .arg(d.path().join("state"))
        .args(["--json", "config", "get", "machine.secret_storage"])
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
        .env("XDG_RUNTIME_DIR", d.path())
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["value"], "file", "{v}");
    assert_eq!(v["keyring"]["usable"], false, "{v}");
    let reason = v["keyring"]["reason"].as_str().unwrap();
    assert_eq!(reason, "no-answer", "{v}");
    assert!(!v["keyring"]["why"].as_str().unwrap().is_empty());
}

/// What a restore did comes as data too, with the notes that ask for
/// something to be set again marked, for a program that says so in its own
/// words: here the proxy, left out on purpose.
#[test]
fn a_restore_says_what_it_did_as_data() {
    let d = tempfile::tempdir().unwrap();
    let (ok, v) = with_stdin(
        d.path(),
        &["proxy", "set", "https://laptop@relay.example:7490"],
        "s3cret\n",
    );
    assert!(ok, "{v}");
    let file = d.path().join("node.backup");
    let file = file.to_str().unwrap();
    let (ok, v) = with_stdin(d.path(), &["backup", file], "correct horse battery\n");
    assert!(ok, "{v}");
    // The backup says what it wrote as data too, for the desktop app.
    let b = &v["backup"];
    assert_eq!(b["file"], file, "{v}");
    assert_eq!(b["centers"], serde_json::json!([]), "{v}");
    assert!(b["saved"].is_array() && b["left_out"].is_array(), "{v}");
    let (ok, v) = with_stdin(
        d.path(),
        &["restore", file, "--replace", "--without-proxy"],
        "correct horse battery\n",
    );
    assert!(ok, "{v}");
    let r = &v["restored"];
    assert_eq!(r["centers"], serde_json::json!([]), "{v}");
    assert_eq!(r["no_key"], serde_json::json!([]), "{v}");
    let notes = r["notes"].as_array().unwrap();
    assert!(
        notes
            .iter()
            .any(|n| n["fix"] == "proxy" && n["text"].as_str().unwrap().contains("proxy")),
        "{v}"
    );
    // The lines for people are there as before.
    assert!(!v["messages"].as_array().unwrap().is_empty(), "{v}");
}

/// Before the owner says yes, `center add` checks the link: the center
/// answers and its code is open, so it can pair; once used, the preview
/// says why it cannot, and the terminal is not asked at all. The check uses
/// nothing up: the pairing after it works.
#[test]
fn center_add_checks_the_link_before_it_asks() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let center = rt
        .block_on(nerve_conformance::fake_center::FakeCenter::start(false))
        .unwrap();
    let link = center.link().render();
    let d = tempfile::tempdir().unwrap();
    for _ in 0..3 {
        let (ok, v) = node(d.path(), &["center", "add", &link]);
        assert!(ok, "{v}");
        let c = &v["check"];
        assert_eq!(
            (&c["ready"], &c["code"]),
            (&json!(true), &json!("open")),
            "{v}"
        );
    }
    let (ok, v) = node(d.path(), &["center", "add", &link, "--yes"]);
    assert!(ok && v["paired"] == true, "{v}");
    let (ok, v) = node(d.path(), &["center", "add", &link]);
    assert!(ok, "{v}");
    let c = &v["check"];
    assert_eq!(
        (&c["ready"], &c["code"]),
        (&json!(false), &json!("used")),
        "{v}"
    );
    assert!(c["problem"].as_str().unwrap().contains("used"), "{v}");
    // The terminal: refused with the reason, before the question.
    let out = Command::new(env!("CARGO_BIN_EXE_nerve-node"))
        .arg("--config-dir")
        .arg(d.path().join("config"))
        .arg("--state-dir")
        .arg(d.path().join("state"))
        .args(["center", "add", &link])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let text =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("cannot pair: the code is used"), "{text}");
    assert!(!text.contains("[y/N]"), "{text}");
    // A center nobody answers for: unreachable, nothing to pair with.
    let gone = "nerve://pair?center=http%3A%2F%2F127.0.0.1%3A9&code=abc123";
    let (ok, v) = node(d.path(), &["center", "add", gone]);
    assert!(ok, "{v}");
    assert_eq!(v["check"]["reach"], "unreachable", "{v}");
    assert_eq!(v["check"]["ready"], false, "{v}");
}

/// On Windows the node runs only as its service (#176): `run` from a
/// terminal or a script is refused, on the installed node's folders as on
/// any others, before it touches a folder, and the error says where the app
/// starts the node.
#[cfg(windows)]
#[test]
fn run_is_refused_outside_the_service_on_windows() {
    let d = tempfile::tempdir().unwrap();
    let (ok, v) = node(d.path(), &["run"]);
    assert!(!ok, "{v}");
    assert_eq!(v["error"], nerve_node::cli::BY_HAND, "{v}");
    assert!(!d.path().join("state").exists());
    let sys = nerve_node::service::Layout::system().paths;
    let out = Command::new(env!("CARGO_BIN_EXE_nerve-node"))
        .arg("--config-dir")
        .arg(&sys.config_dir)
        .arg("--state-dir")
        .arg(&sys.state_dir)
        .args(["--json", "run"])
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(!out.status.success(), "{text}");
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["error"], nerve_node::cli::BY_HAND, "{v}");
}
