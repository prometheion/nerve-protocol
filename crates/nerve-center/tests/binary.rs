//! The `nerve-center` binary as a harness starts it: MCP over stdio, and a
//! second instance on the same state folder that attaches to the first, on
//! Unix over its socket and on Windows over its pipe (#64).

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// A command with no environment but what a program needs to start:
/// Windows' sockets need `SystemRoot`.
fn bare(c: &mut Command) -> &mut Command {
    c.env_clear();
    if let Some(root) = std::env::var_os("SystemRoot") {
        c.env("SystemRoot", root);
    }
    c
}

fn spawn(state: &std::path::Path) -> Child {
    bare(&mut Command::new(env!("CARGO_BIN_EXE_nerve-center")))
        .env("NERVE_CENTER_STATE_DIR", state)
        .env("NERVE_CENTER_LISTEN", "127.0.0.1:0")
        .env("NERVE_CENTER_PLAIN_LOOPBACK", "true")
        .env("NERVE_CENTER_UI", "off")
        .env("NERVE_CENTER_LOG", "warn")
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

/// A harness that ends its center with SIGTERM, or a Ctrl+C (SIGINT) in its
/// terminal, while the pipe is still open gets a clean stop: the center says
/// bye to its nodes and exits with 0, not killed by the signal.
#[cfg(unix)]
#[test]
fn a_signal_stops_a_stdio_center_cleanly() {
    for sig in [libc::SIGTERM, libc::SIGINT] {
        let dir = tempfile::tempdir().unwrap();
        let mut c = spawn(dir.path());
        let mut out = BufReader::new(c.stdout.take().unwrap());
        init(&mut c, &mut out);
        // SAFETY: a signal to the child this test started.
        assert_eq!(unsafe { libc::kill(c.id() as i32, sig) }, 0);
        assert!(
            wait(&mut c, Duration::from_secs(10)),
            "signal {sig}: it still runs"
        );
        let status = c.wait().unwrap();
        assert!(status.success(), "signal {sig}: {status:?}");
    }
}

/// The first start says the owner token on stderr at once, whatever the
/// level, and where it is kept; a later start says nothing of it.
#[cfg(unix)]
#[test]
fn the_first_start_says_the_owner_token_on_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let run = || {
        let out = Command::new(env!("CARGO_BIN_EXE_nerve-center"))
            .env_clear()
            .env("NERVE_CENTER_STATE_DIR", dir.path())
            .env("NERVE_CENTER_LISTEN", "127.0.0.1:0")
            .env("NERVE_CENTER_PLAIN_LOOPBACK", "true")
            .env("NERVE_CENTER_UI", "127.0.0.1:0")
            .env("NERVE_CENTER_LOG", "warn")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stderr).into_owned()
    };
    let err = run();
    let token = nerve_center::owner::read(dir.path()).unwrap().unwrap();
    assert!(err.contains(&format!("\n{token}\n")), "{err}");
    let file = nerve_center::owner::path(dir.path());
    assert!(err.contains(&file.display().to_string()), "{err}");
    let err = run();
    assert!(!err.contains(&token), "{err}");
}

/// Under systemd stderr goes to the journal, which more accounts read than
/// the token file: there the first start keeps the token off stderr.
/// systemd names the journal's stream in `JOURNAL_STREAM`, and the variable
/// is also inherited by what a user service starts (a terminal): there
/// stderr is not the journal, and the token is shown.
#[cfg(unix)]
#[test]
fn under_systemd_the_owner_token_stays_off_stderr() {
    use std::os::unix::fs::MetadataExt;
    let start = |journal: Option<bool>| {
        let dir = tempfile::tempdir().unwrap();
        let err = std::fs::File::create(dir.path().join("stderr")).unwrap();
        let meta = err.metadata().unwrap();
        let stream = match journal {
            Some(true) => format!("{}:{}", meta.dev(), meta.ino()),
            Some(false) => format!("{}:{}", meta.dev(), meta.ino() + 1),
            None => String::new(),
        };
        let state = dir.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nerve-center"));
        cmd.env_clear()
            .env("NERVE_CENTER_STATE_DIR", &state)
            .env("NERVE_CENTER_LISTEN", "127.0.0.1:0")
            .env("NERVE_CENTER_PLAIN_LOOPBACK", "true")
            .env("NERVE_CENTER_UI", "127.0.0.1:0")
            .env("NERVE_CENTER_LOG", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(err);
        if journal.is_some() {
            cmd.env("JOURNAL_STREAM", stream).env("INVOCATION_ID", "x");
        }
        assert!(cmd.status().unwrap().success());
        let token = nerve_center::owner::read(&state).unwrap().unwrap();
        let err = std::fs::read_to_string(dir.path().join("stderr")).unwrap();
        err.contains(&token)
    };
    assert!(!start(Some(true)), "the token went to the journal");
    assert!(start(Some(false)), "a terminal under a user service");
    assert!(start(None), "no systemd");
}

/// A token file that holds no token stops a center with a web UI, and only
/// warns one without.
#[cfg(unix)]
#[test]
fn a_broken_owner_token_stops_only_a_center_with_a_web_ui() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(nerve_center::owner::path(dir.path()), "short").unwrap();
    let run = |ui: &str| {
        Command::new(env!("CARGO_BIN_EXE_nerve-center"))
            .env_clear()
            .env("NERVE_CENTER_STATE_DIR", dir.path())
            .env("NERVE_CENTER_LISTEN", "127.0.0.1:0")
            .env("NERVE_CENTER_PLAIN_LOOPBACK", "true")
            .env("NERVE_CENTER_UI", ui)
            .env("NERVE_CENTER_LOG", "warn")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let off = run("off");
    assert!(
        off.status.success(),
        "{}",
        String::from_utf8_lossy(&off.stderr)
    );
    assert!(String::from_utf8_lossy(&off.stderr).contains("owner-token --new"));
    assert!(!run("127.0.0.1:0").status.success());
    assert_eq!(
        std::fs::read_to_string(nerve_center::owner::path(dir.path())).unwrap(),
        "short"
    );
}

/// An owner token that is also the harness token of the settings stops a
/// center with a web UI: one secret for both would let the agent's own token
/// into the UI (review round 7 of the center's sign-in).
#[cfg(unix)]
#[test]
fn an_owner_token_that_is_a_harness_token_stops_a_center_with_a_web_ui() {
    let dir = tempfile::tempdir().unwrap();
    let shared = "nrv_shared-by-both-by-mistake";
    std::fs::write(nerve_center::owner::path(dir.path()), shared).unwrap();
    let run = |ui: &str, harness: &str| {
        Command::new(env!("CARGO_BIN_EXE_nerve-center"))
            .env_clear()
            .env("NERVE_CENTER_STATE_DIR", dir.path())
            .env("NERVE_CENTER_LISTEN", "127.0.0.1:0")
            .env("NERVE_CENTER_PLAIN_LOOPBACK", "true")
            .env("NERVE_CENTER_UI", ui)
            .env("NERVE_CENTER_HARNESS_TOKEN", harness)
            .env("NERVE_CENTER_LOG", "warn")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let refused = run("127.0.0.1:0", shared);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("also a harness token"));
    // A harness token of its own, or no web UI, starts.
    assert!(
        run("127.0.0.1:0", "nrv_another-one-entirely")
            .status
            .success()
    );
    assert!(run("off", shared).status.success());
    assert_eq!(
        std::fs::read_to_string(nerve_center::owner::path(dir.path())).unwrap(),
        shared
    );
}

/// Starts a center with the level in `NERVE_LOG`, lets one harness session
/// come and go, and gives back what the center put on stderr.
#[cfg(unix)]
fn one_session(state: &std::path::Path, level: &str) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nerve-center"))
        .env_clear()
        .env("NERVE_CENTER_STATE_DIR", state)
        .env("NERVE_CENTER_LISTEN", "127.0.0.1:0")
        .env("NERVE_CENTER_PLAIN_LOOPBACK", "true")
        .env("NERVE_CENTER_UI", "off")
        .env("NERVE_CENTER_LOG", level)
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
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut err).unwrap();
    err
}

#[cfg(unix)]
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
    // The first start makes the owner token and says where it is.
    assert!(msgs[0].starts_with("made the owner token"), "{msgs:?}");
    assert!(msgs[1].starts_with("nerve-center "), "{msgs:?}");
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
        .env("NERVE_CENTER_STATE_DIR", dir.path())
        .env("NERVE_CENTER_LOG", "loud")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("error, warn, info or debug"));
}

/// `nerve-center backup` or `restore` as the owner runs them. The state
/// folder is given by `--state-dir`: an administrator's command refuses it
/// from the variable (and the Windows CI runner is one), which the test
/// `an_administrators_command_does_not_take_the_state_variable` checks.
fn owner(args: &[&str], state: Option<&std::path::Path>) -> std::process::Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_nerve-center"));
    bare(&mut c).args(args).stdin(Stdio::null());
    if let Some(s) = state {
        c.arg("--state-dir").arg(s);
    }
    c.output().unwrap()
}

/// On Windows, an elevated `backup` (the hosted runners run the tests so)
/// refuses a state folder that came from `NERVE_CENTER_STATE_DIR` and writes
/// nothing; the same command from a terminal that is not elevated takes it
/// (round 8, correctness 1).
#[cfg(windows)]
#[test]
fn an_administrators_command_does_not_take_the_state_variable() {
    let dir = tempfile::tempdir().unwrap();
    let pass = dir.path().join("pass");
    nerve_transport::files::write_private(&pass, b"correct horse battery\n").unwrap();
    let file = dir.path().join("v.bak");
    let mut c = Command::new(env!("CARGO_BIN_EXE_nerve-center"));
    bare(&mut c)
        .args(["backup"])
        .arg(&file)
        .arg("--passphrase-file")
        .arg(&pass)
        .env("NERVE_CENTER_STATE_DIR", dir.path().join("state"))
        .stdin(Stdio::null());
    let out = c.output().unwrap();
    let said = String::from_utf8_lossy(&out.stderr);
    if nerve_service::win::sid::is_admin() {
        assert!(!out.status.success(), "{out:?}");
        assert!(said.contains("NERVE_CENTER_STATE_DIR"), "{said}");
    } else {
        // Taken: it fails for want of a center in that folder, not for the
        // variable.
        assert!(!said.contains("administrator's terminal"), "{said}");
    }
    assert!(!file.exists());
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
        stdout.contains(" · backed up\n") && stdout.contains("\n  Pin "),
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
    let bad = owner(&["pair"], None);
    assert!(!bad.status.success());
}

/// A center that runs a node's link and a harness over stdio, stopped by a
/// signal, and one that serves MCP over HTTP beyond loopback with port 0.
#[cfg(unix)]
mod running {
    use super::*;

    use std::path::Path;
    use std::sync::mpsc::{Receiver, channel};

    use clap::Parser;
    use futures_util::{SinkExt, StreamExt};
    use nerve_center::config::Args;
    use nerve_proto::link::{CenterUrl, PairLink};
    use nerve_proto::msg::{self, method};
    use nerve_proto::rpc::Message;
    use nerve_transport::keys::NodeKey;
    use nerve_transport::ws::{self, WsMessage};

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// Pairs a node with a center on `dir`, as a node does over the node
    /// port, and stops that center again: the state folder keeps the node.
    /// Gives the node's key and id.
    fn paired_node(dir: &Path) -> (NodeKey, String) {
        runtime().block_on(async {
            nerve_transport::init_crypto();
            let args = Args::try_parse_from([
                "nerve-center",
                "--state-dir",
                dir.to_str().unwrap(),
                "--listen",
                "127.0.0.1:0",
                "--plain-loopback",
                "--ui",
                "off",
                "--mcp",
                "off",
            ])
            .unwrap();
            let lock = nerve_center::attach::try_lock(dir).unwrap().unwrap();
            let running = nerve_center::server::start(&args, lock).await.unwrap();
            let key = NodeKey::generate().unwrap();
            let link = running.center.new_pairing()["link"]
                .as_str()
                .unwrap()
                .to_string();
            let code = PairLink::parse(&link).unwrap().code;
            let mut io = tokio::net::TcpStream::connect(running.nodes).await.unwrap();
            let resp = nerve_transport::http::post_json(
                &mut io,
                "127.0.0.1",
                nerve_proto::PAIR_PATH,
                &json!({"code": code, "name": "box", "platform": "linux", "arch": "x86_64",
                        "public_key": key.public_hex()}),
                64 * 1024,
            )
            .await
            .unwrap();
            assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
            let body: Value = serde_json::from_slice(&resp.body).unwrap();
            running.stop().await;
            (key, body["node_id"].as_str().unwrap().to_string())
        })
    }

    /// Starts `nerve-center` with `env` added and reads the port its start
    /// line names, `(listening on <addr>)`, and the line itself.
    fn start(c: &mut Command) -> (Child, u16, String) {
        let mut child = c.stderr(Stdio::piped()).spawn().unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let mut sent = false;
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                eprintln!("[nerve-center] {line}");
                if !sent && line.contains("(listening on ") {
                    let _ = tx.send(line);
                    sent = true;
                }
            }
        });
        let line = rx
            .recv_timeout(Duration::from_secs(60))
            .expect("the start line");
        let at = line.split("(listening on ").nth(1).unwrap();
        let port = at.split(')').next().unwrap().rsplit(':').next().unwrap();
        (child, port.parse().unwrap(), line)
    }

    /// A node on port `port` that answers the center like a node (a
    /// description with a `fs.read`, a result for every call), and says on
    /// the first channel that the center welcomed it, on the second how its
    /// link ended: the reason of a `bye`, or that the connection closed.
    fn node(port: u16, key: NodeKey, node_id: String) -> (Receiver<()>, Receiver<String>) {
        let (welcomed, welcome) = channel();
        let (ended, end) = channel();
        std::thread::spawn(move || {
            runtime().block_on(async {
                let url = CenterUrl::parse(&format!("http://127.0.0.1:{port}")).unwrap();
                let mut ws = ws::connect(&url, None, None, &node_id, 4 * 1024 * 1024)
                    .await
                    .unwrap();
                let text = async |ws: &mut tokio_tungstenite::WebSocketStream<_>| loop {
                    match tokio::time::timeout(Duration::from_secs(60), ws.next()).await {
                        Ok(Some(Ok(WsMessage::Text(t)))) => return Message::decode(&t).ok(),
                        Ok(Some(Ok(_))) => continue,
                        _ => return None,
                    }
                };
                let Some(Message::Notification { params, .. }) = text(&mut ws).await else {
                    panic!("no challenge")
                };
                let nonce = msg::unhex(params["nonce"].as_str().unwrap()).unwrap();
                let center_id = params["center_id"].as_str().unwrap().to_string();
                let hello = json!({
                    "node_id": node_id,
                    "auth": {"sig": key.sign_connect(&center_id, &nonce)},
                    "versions": ["0"],
                    "software": {"name": "t", "version": "1"},
                    "rev": 1,
                    "features": [],
                    "resume": {"link": msg::hex(&nerve_transport::keys::random_bytes(16)), "got": 0},
                });
                let hello = Message::notification(method::HELLO, hello);
                ws.send(WsMessage::text(hello.encode())).await.unwrap();
                let Some(Message::Notification { method: m, .. }) = text(&mut ws).await else {
                    panic!("no welcome")
                };
                assert_eq!(m, method::WELCOME);
                let _ = welcomed.send(());
                let described = json!({
                    "nerve": "0",
                    "node": {"id": node_id, "name": "box", "platform": "linux", "arch": "x86_64",
                             "software": {"name": "t", "version": "1"}},
                    "rev": 1,
                    "summary": "A test node.",
                    "capabilities": [
                        {"id": "fs", "profile": "fs", "exposure": "on", "summary": "Files.",
                         "actions": {"read": {"effect": "read", "summary": "Read a file.",
                                              "params": {"type": "object", "properties": {
                                                  "path": {"type": "string", "x-nerve-path": "read"}},
                                                         "required": ["path"]}}}}
                    ]
                });
                loop {
                    match text(&mut ws).await {
                        Some(Message::Request { id, method: m, .. }) => {
                            let result = match m.as_str() {
                                method::DESCRIBE => described.clone(),
                                method::INVOKE => json!({"content": "hi", "encoding": "utf-8"}),
                                _ => json!({}),
                            };
                            ws.send(WsMessage::text(Message::result(id, result).encode()))
                                .await
                                .unwrap();
                        }
                        Some(Message::Notification { method: m, params }) if m == method::BYE => {
                            let _ = ended.send(params["reason"].as_str().unwrap().to_string());
                            return;
                        }
                        Some(_) => {}
                        None => {
                            let _ = ended.send("closed without a bye".into());
                            return;
                        }
                    }
                }
            })
        });
        (welcome, end)
    }

    /// A SIGTERM to a center with a node linked says bye to the node and
    /// writes the statistics that were waiting for their timer: the call
    /// made just before it is in the state file (#40, center-2).
    #[test]
    fn a_signal_says_bye_to_the_nodes_and_writes_their_statistics() {
        let dir = tempfile::tempdir().unwrap();
        let (key, node_id) = paired_node(dir.path());
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nerve-center"));
        bare(&mut cmd)
            .env("NERVE_CENTER_STATE_DIR", dir.path())
            .env("NERVE_CENTER_LISTEN", "127.0.0.1:0")
            .env("NERVE_CENTER_PLAIN_LOOPBACK", "true")
            .env("NERVE_CENTER_UI", "off")
            .env("NERVE_CENTER_LOG", "info")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        let (mut c, port, _) = start(&mut cmd);
        let mut out = BufReader::new(c.stdout.take().unwrap());
        init(&mut c, &mut out);
        let (welcomed, ended) = node(port, key, node_id.clone());
        welcomed
            .recv_timeout(Duration::from_secs(30))
            .expect("the node is welcomed");
        // The node's description comes after the welcome.
        let mut id = 10;
        let listed = loop {
            id += 1;
            let r = ask(
                &mut c,
                &mut out,
                json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {
                    "name": "list", "arguments": {"node": "box", "capability": "fs.read"}}}),
            );
            if r["result"]["isError"] != json!(true) {
                break r;
            }
            assert!(id < 200, "the node never described itself: {r}");
            std::thread::sleep(Duration::from_millis(100));
        };
        assert!(listed.get("result").is_some(), "{listed}");
        let call = ask(
            &mut c,
            &mut out,
            json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
                "name": "execute",
                "arguments": {"node": "box", "capability": "fs.read", "args": {"path": "/x"}}}}),
        );
        assert_ne!(call["result"]["isError"], json!(true), "{call}");
        // SAFETY: a signal to the child this test started.
        assert_eq!(unsafe { libc::kill(c.id() as i32, libc::SIGTERM) }, 0);
        assert!(wait(&mut c, Duration::from_secs(10)), "it still runs");
        assert!(c.wait().unwrap().success());
        assert_eq!(
            ended.recv_timeout(Duration::from_secs(10)).unwrap(),
            "shutdown"
        );
        let state = nerve_center::store::Store::load(dir.path())
            .unwrap()
            .unwrap();
        let calls: usize = state.stats[&node_id]
            .days
            .values()
            .map(|d| d.calls.len())
            .sum();
        assert_eq!(
            calls, 1,
            "the call made before the signal is not in the state file"
        );
    }

    /// An HTTP MCP endpoint beyond loopback on port 0 names the port it got
    /// in the start line, where a script reads it (#40, shared-2).
    #[test]
    fn an_mcp_endpoint_beyond_loopback_with_port_0_names_its_port() {
        let dir = tempfile::tempdir().unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nerve-center"));
        bare(&mut cmd)
            .env("NERVE_CENTER_STATE_DIR", dir.path())
            .env("NERVE_CENTER_LISTEN", "127.0.0.1:0")
            .env("NERVE_CENTER_PLAIN_LOOPBACK", "true")
            .env("NERVE_CENTER_UI", "off")
            .env("NERVE_CENTER_MCP", "0.0.0.0:0")
            .env("NERVE_CENTER_LOG", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        let (mut c, _, line) = start(&mut cmd);
        let url = line.split("MCP at ").nth(1).expect("an MCP url").trim();
        let port: u16 = url
            .trim_end_matches("/mcp")
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(url.starts_with("https://"), "{url}");
        assert_ne!(port, 0, "{url}");
        // SAFETY: a signal to the child this test started.
        assert_eq!(unsafe { libc::kill(c.id() as i32, libc::SIGTERM) }, 0);
        assert!(wait(&mut c, Duration::from_secs(10)), "it still runs");
    }
}

/// The owner's commands in the terminal ask the running center over its
/// attach socket or pipe, with the web UI off (#213): `pair` makes a link,
/// `nodes` lists the machines, `token` makes, lists and removes harness
/// tokens; a center that does not run is said plainly.
#[test]
fn the_owners_commands_ask_the_running_center_with_the_web_ui_off() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let stopped = owner(&["pair"], Some(&state));
    assert!(!stopped.status.success());
    let err = String::from_utf8_lossy(&stopped.stderr);
    assert!(err.contains("no center runs in "), "{err}");

    let mut center = spawn(&state);
    let mut center_out = BufReader::new(center.stdout.take().unwrap());
    init(&mut center, &mut center_out);
    let said = |args: &[&str]| {
        let o = owner(args, Some(&state));
        let text = String::from_utf8_lossy(&o.stdout).into_owned();
        assert!(
            o.status.success(),
            "{args:?}: {text}{}",
            String::from_utf8_lossy(&o.stderr)
        );
        text
    };
    let pair = said(&["pair"]);
    assert!(pair.contains(" · pairing link\n"), "{pair}");
    assert!(pair.contains("\n  Link        nerve://"), "{pair}");
    assert!(pair.contains("nerve-node center add -"), "{pair}");
    let nodes = said(&["nodes"]);
    assert!(nodes.contains(" · no machine paired\n"), "{nodes}");
    let made = said(&["token", "new", "ci"]);
    let token = made
        .lines()
        .find_map(|l| l.strip_prefix("  Token       "))
        .unwrap_or_else(|| panic!("{made}"))
        .to_string();
    assert!(token.starts_with("nrv_"), "{made}");
    let list = said(&["token", "list"]);
    assert!(list.contains(" · 1 harness token\n"), "{list}");
    assert!(list.contains("\n  ci   made "), "{list}");
    assert!(!list.contains(&token), "{list}");
    let rm = said(&["token", "rm", "ci"]);
    assert!(rm.starts_with("removed the harness token ci\n"), "{rm}");
    assert!(rm.contains(" · no harness token\n"), "{rm}");
    let gone = owner(&["nodes", "rm", "nope"], Some(&state));
    assert!(!gone.status.success());
    assert!(String::from_utf8_lossy(&gone.stderr).contains("no machine named nope"));
    drop(center.stdin.take());
    assert!(wait(&mut center, Duration::from_secs(10)));
}
