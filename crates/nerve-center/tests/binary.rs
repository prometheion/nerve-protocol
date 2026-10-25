//! The `nerve-center` binary as a harness starts it: MCP over stdio, and a
//! second instance on the same state folder that attaches to the first.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

fn spawn(state: &std::path::Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_nerve-center"))
        .env_clear()
        .env("NERVE_STATE_DIR", state)
        .env("NERVE_LISTEN", "127.0.0.1:0")
        .env("NERVE_PLAIN_LOOPBACK", "true")
        .env("NERVE_UI", "off")
        .env("NERVE_LOG", "warn")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap()
}

fn ask(child: &mut Child, out: &mut BufReader<std::process::ChildStdout>, msg: Value) -> Value {
    let stdin = child.stdin.as_mut().unwrap();
    writeln!(stdin, "{msg}").unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    out.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap_or_else(|e| panic!("{e}: {line:?}"))
}

fn init(child: &mut Child, out: &mut BufReader<std::process::ChildStdout>) {
    let r = ask(
        child,
        out,
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}}),
    );
    assert_eq!(r["result"]["serverInfo"]["name"], "nerve-center", "{r}");
    let stdin = child.stdin.as_mut().unwrap();
    writeln!(
        stdin,
        "{}",
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"})
    )
    .unwrap();
}

fn wait(child: &mut Child, limit: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if child.try_wait().unwrap().is_some() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[test]
fn stdio_and_a_second_instance_that_attaches() {
    let dir = tempfile::tempdir().unwrap();
    let mut owner = spawn(dir.path());
    let mut owner_out = BufReader::new(owner.stdout.take().unwrap());
    init(&mut owner, &mut owner_out);
    let tools = ask(
        &mut owner,
        &mut owner_out,
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    );
    assert_eq!(tools["result"]["tools"][0]["name"], "list", "{tools}");

    // The second instance finds the lock held and relays to the owner.
    let mut second = spawn(dir.path());
    let mut second_out = BufReader::new(second.stdout.take().unwrap());
    init(&mut second, &mut second_out);
    let nodes = ask(
        &mut second,
        &mut second_out,
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "list", "arguments": {}}}),
    );
    assert_ne!(nodes["result"]["isError"], true, "{nodes}");

    // The owner's harness goes; the owner stays while the attached one runs.
    drop(owner.stdin.take());
    assert!(
        !wait(&mut owner, Duration::from_millis(1500)),
        "the owner left an attached harness behind"
    );
    let again = ask(
        &mut second,
        &mut second_out,
        json!({"jsonrpc": "2.0", "id": 4, "method": "ping"}),
    );
    assert_eq!(again["result"], json!({}));
    drop(second.stdin.take());
    assert!(
        wait(&mut second, Duration::from_secs(10)),
        "the attached instance did not exit"
    );
    assert!(
        wait(&mut owner, Duration::from_secs(10)),
        "the owner did not exit"
    );
    assert!(owner.wait().unwrap().success());
}

#[test]
fn a_ui_beyond_loopback_without_a_harness_token_does_not_start() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_nerve-center"))
        .env_clear()
        .env("NERVE_STATE_DIR", dir.path())
        .env("NERVE_LISTEN", "127.0.0.1:0")
        .env("NERVE_PLAIN_LOOPBACK", "true")
        .env("NERVE_UI", "0.0.0.0:0")
        .env("NERVE_LOG", "warn")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("NERVE_HARNESS_TOKEN"), "{err}");
}

/// Starts a center with the level in `NERVE_LOG`, lets one harness session
/// come and go, and gives back what the center put on stderr.
fn one_session(state: &std::path::Path, level: &str) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nerve-center"))
        .env_clear()
        .env("NERVE_STATE_DIR", state)
        .env("NERVE_LISTEN", "127.0.0.1:0")
        .env("NERVE_PLAIN_LOOPBACK", "true")
        .env("NERVE_UI", "off")
        .env("NERVE_LOG", level)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    // `ask` reads stdout as JSON, so a log line there would fail it.
    init(&mut child, &mut out);
    drop(child.stdin.take());
    assert!(wait(&mut child, Duration::from_secs(10)));
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    err
}

#[test]
fn the_log_goes_to_stderr_and_the_state_folder_and_follows_the_level() {
    let lines = |dir: &std::path::Path| -> Vec<Value> {
        std::fs::read_to_string(dir.join("log.jsonl"))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    };
    let dir = tempfile::tempdir().unwrap();
    let err = one_session(dir.path(), "info");
    let file = lines(dir.path());
    let msgs: Vec<&str> = file.iter().map(|e| e["msg"].as_str().unwrap()).collect();
    assert!(msgs[0].starts_with("nerve-center "), "{msgs:?}");
    assert!(
        msgs.iter()
            .any(|m| m.starts_with("a harness session started over stdio"))
    );
    assert_eq!(*msgs.last().unwrap(), "the center stopped", "{msgs:?}");
    assert!(
        file.iter()
            .all(|e| e["level"] == "info" && e["ts"].as_u64().unwrap() > 0)
    );
    // Stderr has the same lines, with their level.
    for m in &msgs {
        assert!(
            err.contains(m) && err.contains("INFO"),
            "{m} is not on stderr: {err}"
        );
    }

    // A higher level than the lines have: none of them is kept or shown.
    let quiet = tempfile::tempdir().unwrap();
    let err = one_session(quiet.path(), "warn");
    assert!(lines(quiet.path()).is_empty(), "{:?}", lines(quiet.path()));
    assert!(!err.contains("INFO"), "{err}");

    // The level is a word the center knows.
    let out = Command::new(env!("CARGO_BIN_EXE_nerve-center"))
        .env_clear()
        .env("NERVE_STATE_DIR", dir.path())
        .env("NERVE_LOG", "loud")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("error, warn, info or debug"));
}

/// `nerve-center backup` or `restore` as the owner runs them.
fn owner(args: &[&str], state: Option<&std::path::Path>) -> std::process::Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_nerve-center"));
    c.env_clear().args(args).stdin(Stdio::null());
    if let Some(s) = state {
        c.env("NERVE_STATE_DIR", s);
    }
    c.output().unwrap()
}

#[test]
fn a_center_is_backed_up_while_it_runs_and_restored_only_when_it_does_not() {
    let dir = tempfile::tempdir().unwrap();
    let (old, new) = (dir.path().join("old"), dir.path().join("new"));
    let pass = dir.path().join("pass");
    nerve_transport::files::write_private(&pass, b"correct horse battery\n").unwrap();
    let file = dir.path().join("c.bak");
    let (pass, file) = (pass.to_str().unwrap(), file.to_str().unwrap());

    // A center that runs; its backup is made from the state it has on disk.
    let mut center = spawn(&old);
    let mut center_out = BufReader::new(center.stdout.take().unwrap());
    init(&mut center, &mut center_out);
    let made = owner(&["backup", file, "--passphrase-file", pass], Some(&old));
    let stdout = String::from_utf8_lossy(&made.stdout);
    assert!(made.status.success(), "{made:?}");
    assert!(
        stdout.contains("backed up") && stdout.contains("pin"),
        "{stdout}"
    );
    // The private key is nowhere in what the program said.
    assert!(!stdout.contains("PRIVATE KEY"));

    // The same file, with the state folder named after the subcommand.
    let again = owner(
        &[
            "backup",
            file,
            "--passphrase-file",
            pass,
            "--state-dir",
            old.to_str().unwrap(),
        ],
        None,
    );
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("exists already"));

    // Not under a running center.
    let refused = owner(&["restore", file, "--passphrase-file", pass], Some(&old));
    assert!(!refused.status.success());
    let err = String::from_utf8_lossy(&refused.stderr);
    assert!(err.contains("a nerve-center runs on"), "{err}");

    drop(center.stdin.take());
    assert!(wait(&mut center, Duration::from_secs(10)));

    // A wrong passphrase writes nothing; the right one brings back the same
    // certificate and the same center.
    let wrong = dir.path().join("wrong");
    nerve_transport::files::write_private(&wrong, b"wrong horse battery\n").unwrap();
    let r = owner(
        &[
            "restore",
            file,
            "--passphrase-file",
            wrong.to_str().unwrap(),
        ],
        Some(&new),
    );
    assert!(!r.status.success());
    assert!(String::from_utf8_lossy(&r.stderr).contains("passphrase is wrong"));
    assert!(!new.join("tls.pem").exists() && !new.join("state.json").exists());
    let r = owner(&["restore", file, "--passphrase-file", pass], Some(&new));
    assert!(r.status.success(), "{r:?}");
    assert_eq!(
        std::fs::read(old.join("tls.pem")).unwrap(),
        std::fs::read(new.join("tls.pem")).unwrap()
    );
    let id = |d: &std::path::Path| -> Value {
        serde_json::from_slice::<Value>(&std::fs::read(d.join("state.json")).unwrap()).unwrap()
            ["center_id"]
            .clone()
    };
    assert_eq!(id(&old), id(&new));

    // And the restored center starts on what it was given.
    let mut again = spawn(&new);
    let mut again_out = BufReader::new(again.stdout.take().unwrap());
    init(&mut again, &mut again_out);
    drop(again.stdin.take());
    assert!(wait(&mut again, Duration::from_secs(10)));
    assert_eq!(id(&old), id(&new));

    // A harness still starts it without a subcommand, and nothing else is one.
    let bad = owner(&["pair"], Some(&new));
    assert!(!bad.status.success());
}
