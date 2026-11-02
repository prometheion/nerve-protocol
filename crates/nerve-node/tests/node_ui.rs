//! The node's web UI (crate::webui): served by a node with an owner
//! endpoint, as the installed node has, only while `ui.listen` is set;
//! logged in with a token made at the CLI; every change through the owner's
//! way in. Off, the node listens on nothing.

#![cfg(target_os = "linux")]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nerve_node::owner::{Endpoint, Owners};
use nerve_node::{Daemon, NodeOptions, NodePaths};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixStream};

/// The tests that turn a UI on run one at a time: one counts the listeners
/// of this whole process.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn program() -> PathBuf {
    std::env::var_os("NERVE_NODE_BIN")
        .map(Into::into)
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_nerve-node").into())
}

fn uid() -> u32 {
    // SAFETY: a plain getter.
    unsafe { libc::getuid() }
}

/// A node in `root` whose owner endpoint is `root/run/owner.sock`, with this
/// test's account as its owner.
async fn node(root: &Path) -> (Daemon, PathBuf) {
    node_running(root, program()).await
}

/// [`node`], whose owner endpoint runs its commands with `endpoint_program`.
async fn node_running(root: &Path, endpoint_program: PathBuf) -> (Daemon, PathBuf) {
    let home = std::fs::canonicalize(root).unwrap();
    let paths = NodePaths::new(home.join("config"), home.join("state"));
    let mut o = NodeOptions::new(paths);
    o.home = home.clone();
    o.exe = Some(program());
    o.cgroups = Some(Err("no cgroup for this test".into()));
    std::fs::create_dir_all(home.join("run")).unwrap();
    let at = home.join("run/owner.sock");
    o.owners = Some(Endpoint {
        at: at.clone(),
        owners: Owners::Uids(vec![uid()]),
        program: endpoint_program,
    });
    (Daemon::start(o).await.unwrap(), at)
}

/// What the owner's `args` on the owner socket `at` gave: the output with
/// the error output, and the exit code.
async fn cli(at: &Path, args: &[&str]) -> (String, i64) {
    let s = UnixStream::connect(at).await.unwrap();
    let (r, mut w) = s.into_split();
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    let req = nerve_node::owner::request_line(&args, Some("/".into()), false, false);
    w.write_all(req.as_bytes()).await.unwrap();
    let mut lines = BufReader::new(r).lines();
    let first: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    if let Some(e) = first["error"].as_str() {
        return (e.to_string(), 1);
    }
    w.write_all(b"{\"eof\": true}\n").await.unwrap();
    let mut text = String::new();
    let wait = tokio::time::timeout(Duration::from_secs(60), async {
        while let Some(l) = lines.next_line().await.unwrap() {
            let v: Value = serde_json::from_str(&l).unwrap();
            if let Some(s) = v["out"].as_str().or(v["err"].as_str()) {
                text.push_str(s);
            } else if let Some(c) = v["exit"].as_i64() {
                return c;
            }
        }
        panic!("the session ended without an exit code: {text}");
    });
    let code = wait.await.expect("the command ends");
    (text, code)
}

/// The token a `ui on` or `ui token add` showed.
fn token_in(out: &str) -> String {
    out.lines()
        .find_map(|l| {
            l.strip_prefix("token ")?
                .split_once(": ")
                .map(|(_, t)| t.to_string())
        })
        .unwrap_or_else(|| panic!("no token in {out}"))
}

/// Where the node's UI listens now.
fn ui_address(d: &Daemon) -> Option<SocketAddr> {
    d.status()["ui"]["address"]
        .as_str()
        .map(|a| a.parse().unwrap())
}

async fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    let start = Instant::now();
    while !f() {
        assert!(start.elapsed() < Duration::from_secs(10), "{what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// An answer: its status, its headers (names in lowercase) and its body.
#[derive(Debug)]
struct Answer {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Answer {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

/// One request to `addr`, with `Host` naming it unless `headers` do.
async fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Answer {
    let mut io = TcpStream::connect(addr).await.unwrap();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
        req.push_str(&format!("Host: {addr}\r\n"));
    }
    if !body.is_empty() {
        req.push_str("Content-Type: application/json\r\n");
    }
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    let _ = io.write_all(req.as_bytes()).await;
    let mut raw = Vec::new();
    // A node that never answers is a failed test, not a hung one.
    let _ = tokio::time::timeout(Duration::from_secs(30), io.read_to_end(&mut raw)).await;
    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    Answer {
        status,
        headers,
        body: body.to_string(),
    }
}

/// A post as the page sends it: with its origin and the session.
async fn post(addr: SocketAddr, path: &str, session: &str, body: Value) -> Answer {
    let origin = format!("http://{addr}");
    http(
        addr,
        "POST",
        path,
        &[("Origin", &origin), ("X-Nerve-Session", session)],
        &body.to_string(),
    )
    .await
}

async fn get(addr: SocketAddr, path: &str, session: &str) -> Answer {
    http(addr, "GET", path, &[("X-Nerve-Session", session)], "").await
}

/// Logs in with `token`: the session, or the refusal.
async fn login(addr: SocketAddr, token: &str) -> Result<String, Answer> {
    let origin = format!("http://{addr}");
    let a = http(
        addr,
        "POST",
        "/login",
        &[("Origin", &origin)],
        &json!({ "token": token }).to_string(),
    )
    .await;
    match a.json()["session"].as_str() {
        Some(s) if a.status == 200 => Ok(s.to_string()),
        _ => Err(a),
    }
}

/// The listening TCP sockets of this process: its socket descriptors that
/// the kernel's tables list as listening.
fn own_listeners() -> Vec<String> {
    let mut inodes = std::collections::BTreeSet::new();
    for fd in std::fs::read_dir("/proc/self/fd").unwrap().flatten() {
        if let Ok(target) = std::fs::read_link(fd.path()) {
            let t = target.to_string_lossy().to_string();
            if let Some(n) = t.strip_prefix("socket:[").and_then(|r| r.strip_suffix(']')) {
                inodes.insert(n.to_string());
            }
        }
    }
    let mut out = Vec::new();
    for table in ["/proc/self/net/tcp", "/proc/self/net/tcp6"] {
        let text = std::fs::read_to_string(table).unwrap_or_default();
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() > 9 && f[3] == "0A" && inodes.contains(f[9]) {
                out.push(f[1].to_string());
            }
        }
    }
    out
}

/// Off, the node listens on nothing; `ui on` gives one listener at once,
/// `ui off` takes it away at once, and its sessions with it.
#[tokio::test(flavor = "multi_thread")]
async fn off_listens_on_nothing() {
    let _one = SERIAL.lock().await;
    let d = tempfile::tempdir().unwrap();
    let (daemon, at) = node(d.path()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(own_listeners(), Vec::<String>::new());
    assert_eq!(daemon.status()["ui"]["status"], "off");
    assert_eq!(daemon.status()["ui"]["served"], true);

    let (out, code) = cli(&at, &["ui", "on", "--listen", "127.0.0.1:0"]).await;
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("the node: listening on 127.0.0.1:"), "{out}");
    let token = token_in(&out);
    let addr = ui_address(&daemon).expect("listening");
    // Loopback is held in both families (a machine without IPv6 has one).
    let held = own_listeners();
    assert!((1..=2).contains(&held.len()), "{held:?}");
    assert!(
        held.iter()
            .all(|l| l.ends_with(&format!(":{:04X}", addr.port()))),
        "{held:?}"
    );
    let session = login(addr, &token).await.unwrap();
    assert_eq!(get(addr, "/api/overview", &session).await.status, 200);

    let (out, code) = cli(&at, &["ui", "off"]).await;
    assert_eq!(code, 0, "{out}");
    wait_until("the listener goes", || own_listeners().is_empty()).await;
    assert_eq!(daemon.status()["ui"]["status"], "off");
    // On again, the old session is no more.
    let (out, code) = cli(&at, &["ui", "on", "--listen", "127.0.0.1:0"]).await;
    assert_eq!(code, 0, "{out}");
    assert!(!out.contains("token "), "a token exists already: {out}");
    let addr = ui_address(&daemon).expect("listening");
    assert_eq!(get(addr, "/api/overview", &session).await.status, 401);
    let (out, _) = cli(&at, &["ui", "off"]).await;
    assert!(out.contains("web UI off"), "{out}");
    daemon.stop().await;
}

/// The login and the session: a token made at the CLI logs in, a session
/// goes as a header and never as a cookie, a wrong token costs time and
/// never locks the login, and the page's rules hold.
#[tokio::test(flavor = "multi_thread")]
async fn a_token_logs_in_and_the_session_is_the_header() {
    let _one = SERIAL.lock().await;
    let d = tempfile::tempdir().unwrap();
    let (daemon, at) = node(d.path()).await;
    let (out, _) = cli(&at, &["ui", "on", "--listen", "127.0.0.1:0"]).await;
    let token = token_in(&out);
    let addr = ui_address(&daemon).unwrap();

    // The page is public, and holds nothing secret; the API is not.
    for path in ["/", "/app.js", "/kit.js", "/app.css", "/login", "/login.js"] {
        assert_eq!(get(addr, path, "").await.status, 200, "{path}");
    }
    for (method, path) in [
        ("GET", "/api/overview"),
        ("GET", "/api/ui"),
        ("POST", "/api/panic"),
        ("POST", "/api/unlock"),
        ("POST", "/api/ui/revoke"),
    ] {
        let a = if method == "GET" {
            get(addr, path, "").await
        } else {
            post(addr, path, "", json!({})).await
        };
        assert_eq!(a.status, 401, "{path}");
    }
    let a = get(addr, "/api/session", "").await;
    assert_eq!(a.json()["logged_in"], false);

    // Wrong tokens cost time each and never keep the right one out.
    let started = Instant::now();
    let a = login(addr, "not-the-token").await.unwrap_err();
    assert_eq!(a.status, 401);
    assert!(started.elapsed() >= Duration::from_millis(300));
    assert!(!a.body.contains("not-the-token"));
    for _ in 0..25 {
        let tries = (0..4).map(|i| login(addr, if i % 2 == 0 { "nope" } else { "" }));
        for r in futures_util::future::join_all(tries).await {
            assert_eq!(r.unwrap_err().status, 401);
        }
    }
    let session = login(addr, &format!(" {token}\n")).await.unwrap();

    // The session is the header; a cookie with it is nothing.
    let a = get(addr, "/api/overview", &session).await;
    assert_eq!(a.status, 200);
    assert_eq!(a.json()["ui"]["served"], true);
    assert_eq!(a.header("cache-control"), Some("no-store"));
    let csp = a.header("content-security-policy").unwrap();
    assert!(csp.contains("worker-src 'none'"), "{csp}");
    let cookie = format!("nerve_ui={session}; nerve.session={session}");
    let a = http(addr, "GET", "/api/overview", &[("Cookie", &cookie)], "").await;
    assert_eq!(a.status, 401);
    // The login page leaves the storage of other tabs alone.
    let a = get(addr, "/login", "").await;
    assert_eq!(a.header("clear-site-data"), None);

    // Only loopback names reach a loopback UI (DNS rebinding).
    let a = http(
        addr,
        "GET",
        "/api/overview",
        &[("Host", "evil.example"), ("X-Nerve-Session", &session)],
        "",
    )
    .await;
    assert_eq!(a.status, 403);
    // A post needs this UI's own origin: none, or another, is refused.
    for origin in [None, Some("http://evil.example"), Some("null")] {
        let mut h = vec![("X-Nerve-Session", session.as_str())];
        if let Some(o) = origin {
            h.push(("Origin", o));
        }
        let a = http(addr, "POST", "/api/unlock", &h, "{}").await;
        assert_eq!(a.status, 403, "{origin:?}");
    }

    // Sign out ends it on the node too.
    let a = post(addr, "/logout", &session, json!({})).await;
    assert_eq!(a.status, 200);
    assert_eq!(a.header("clear-site-data"), Some("\"storage\""));
    assert_eq!(get(addr, "/api/overview", &session).await.status, 401);

    // The log tells who got in, never a token.
    let log = std::fs::read_to_string(daemon.paths().log_file()).unwrap_or_default();
    assert!(!log.contains(&token), "{log}");
    daemon.stop().await;
}

/// A browser loads a page on several connections at once (every answer
/// closes its own), and each may send its request a moment after it
/// connects, as through `ssh -L` or after a TLS handshake: every one is
/// answered.
#[tokio::test(flavor = "multi_thread")]
async fn a_page_loads_on_many_connections_at_once() {
    let _one = SERIAL.lock().await;
    let d = tempfile::tempdir().unwrap();
    let (daemon, at) = node(d.path()).await;
    let (out, _) = cli(&at, &["ui", "on", "--listen", "127.0.0.1:0"]).await;
    let addr = ui_address(&daemon).unwrap();
    assert!(out.contains("token "), "{out}");
    let paths = ["/", "/app.js", "/kit.js", "/app.css", "/login", "/login.js"];
    let loads = paths.iter().chain(paths.iter()).map(|path| async move {
        let mut io = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
        let _ = io.write_all(req.as_bytes()).await;
        let mut raw = Vec::new();
        let _ = io.read_to_end(&mut raw).await;
        (
            path,
            String::from_utf8_lossy(&raw)
                .lines()
                .next()
                .unwrap_or("")
                .to_string(),
        )
    });
    for (path, status) in futures_util::future::join_all(loads).await {
        assert_eq!(status, "HTTP/1.1 200 OK", "{path}");
    }
    daemon.stop().await;
}

/// A command of the owner's account that posts wrong tokens on many
/// connections at once does not keep the owner's own login or the page out
/// while it goes on: a wrong token's answer waits holding no slot.
#[tokio::test(flavor = "multi_thread")]
async fn wrong_tokens_on_many_connections_do_not_keep_the_owner_out() {
    let _one = SERIAL.lock().await;
    let d = tempfile::tempdir().unwrap();
    let (daemon, at) = node(d.path()).await;
    let (out, _) = cli(&at, &["ui", "on", "--listen", "127.0.0.1:0"]).await;
    let token = token_in(&out);
    let addr = ui_address(&daemon).unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flood: Vec<_> = (0..100)
        .map(|_| {
            let stop = stop.clone();
            tokio::spawn(async move {
                let mut tries = 0u32;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let _ = login(addr, "not-the-token").await;
                    tries += 1;
                }
                tries
            })
        })
        .collect();
    // The flood holds its connections by now.
    tokio::time::sleep(Duration::from_millis(500)).await;
    for i in 0..8 {
        let session = login(addr, &token)
            .await
            .unwrap_or_else(|a| panic!("login {i} during the flood: {a:?}"));
        assert_eq!(get(addr, "/api/overview", &session).await.status, 200);
        assert_eq!(get(addr, "/app.css", "").await.status, 200);
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let mut tries = 0;
    for f in flood {
        tries += f.await.unwrap();
    }
    assert!(tries >= 100, "the flood made {tries} tries");
    daemon.stop().await;
}

/// Panic ends every web session, and the login still answers to unlock;
/// a revoked token's sessions end, and a restart ends them all.
#[tokio::test(flavor = "multi_thread")]
async fn panic_revoke_and_restart_end_the_sessions() {
    let _one = SERIAL.lock().await;
    let d = tempfile::tempdir().unwrap();
    let (daemon, at) = node(d.path()).await;
    let (out, _) = cli(&at, &["ui", "on", "--listen", "127.0.0.1:0"]).await;
    let first = token_in(&out);
    let (out, code) = cli(&at, &["ui", "token", "add", "laptop"]).await;
    assert_eq!(code, 0, "{out}");
    let laptop = token_in(&out);
    let (out, code) = cli(&at, &["ui", "token", "add", "laptop"]).await;
    assert_eq!(code, 1, "a label is taken once: {out}");
    let addr = ui_address(&daemon).unwrap();
    let a = login(addr, &first).await.unwrap();
    let b = login(addr, &laptop).await.unwrap();

    // Panic from the page.
    let r = post(addr, "/api/panic", &a, json!({})).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(daemon.config().locked);
    for s in [&a, &b] {
        let s = s.clone();
        let mut ended = false;
        for _ in 0..50 {
            if get(addr, "/api/overview", &s).await.status == 401 {
                ended = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(ended, "a session outlived the panic");
    }
    // The login still answers, and unlocks.
    let a = login(addr, &first).await.unwrap();
    let r = post(addr, "/api/unlock", &a, json!({})).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(!daemon.config().locked);

    // Revoked in the page: its sessions end, the other token's stay.
    let b = login(addr, &laptop).await.unwrap();
    let r = post(addr, "/api/ui/revoke", &a, json!({"label": "laptop"})).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(daemon.config().ui.token("laptop").is_none());
    wait_until("the revoked session ends", || {
        daemon.status()["ui"]["sessions"] == 1
    })
    .await;
    assert_eq!(get(addr, "/api/overview", &b).await.status, 401);
    assert_eq!(get(addr, "/api/overview", &a).await.status, 200);
    assert!(login(addr, &laptop).await.is_err());
    // A value that reads as an option is refused before anything runs.
    let r = post(addr, "/api/ui/revoke", &a, json!({"label": "--all"})).await;
    assert_eq!(r.status, 400);
    // The settings page lists the tokens by label, never a hash.
    let r = get(addr, "/api/ui", &a).await;
    assert_eq!(r.json()["tokens"][0]["label"], "first");
    assert!(!r.body.contains(&daemon.config().ui.tokens[0].token_sha256));

    // A restart ends every session: they are kept in memory only.
    let paths = daemon.paths().clone();
    daemon.stop().await;
    let (daemon, _) = node(d.path()).await;
    assert_eq!(*daemon.paths(), paths);
    wait_until("the UI listens again", || ui_address(&daemon).is_some()).await;
    let addr = ui_address(&daemon).unwrap();
    assert_eq!(get(addr, "/api/overview", &a).await.status, 401);
    assert!(login(addr, &first).await.is_ok());
    daemon.stop().await;
}

/// A session started while the node is locked may leak: the owner's next
/// `panic` ends it although the node was locked already, so it can neither
/// stay nor unlock.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_panic_ends_a_session_started_in_the_lock() {
    let _one = SERIAL.lock().await;
    let d = tempfile::tempdir().unwrap();
    let (daemon, at) = node(d.path()).await;
    let (out, _) = cli(&at, &["ui", "on", "--listen", "127.0.0.1:0"]).await;
    let token = token_in(&out);
    let addr = ui_address(&daemon).unwrap();
    let (out, code) = cli(&at, &["panic"]).await;
    assert_eq!(code, 0, "{out}");
    assert!(daemon.config().locked);
    // The way back in: a login in the lock.
    let kept = login(addr, &token).await.unwrap();
    assert_eq!(get(addr, "/api/overview", &kept).await.status, 200);
    let (out, code) = cli(&at, &["panic"]).await;
    assert_eq!(code, 0, "{out}");
    wait_until("the session ends", || {
        daemon.status()["ui"]["sessions"] == 0
    })
    .await;
    assert_eq!(get(addr, "/api/overview", &kept).await.status, 401);
    let r = post(addr, "/api/unlock", &kept, json!({})).await;
    assert_eq!(r.status, 401, "{}", r.body);
    assert!(daemon.config().locked);
    // A new login still works, and unlocks.
    let again = login(addr, &token).await.unwrap();
    let r = post(addr, "/api/unlock", &again, json!({})).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(!daemon.config().locked);
    daemon.stop().await;
}

/// A command the page started before a panic does not finish after it: an
/// unlock that was let in with the session would undo the panic.
#[tokio::test(flavor = "multi_thread")]
async fn a_command_in_flight_does_not_undo_a_panic() {
    use std::os::unix::fs::PermissionsExt;
    let _one = SERIAL.lock().await;
    let d = tempfile::tempdir().unwrap();
    // The program of the owner socket, slow to start an unlock: the panic
    // comes while the unlock has not read the config yet.
    let slow = d.path().join("slow-unlock.sh");
    std::fs::write(
        &slow,
        format!(
            "#!/bin/sh\ncase \" $* \" in *\" unlock \"*) sleep 2;; esac\nexec {} \"$@\"\n",
            program().display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&slow, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (daemon, at) = node_running(d.path(), slow).await;
    let (out, _) = cli(&at, &["ui", "on", "--listen", "127.0.0.1:0"]).await;
    let token = token_in(&out);
    let addr = ui_address(&daemon).unwrap();
    let session = login(addr, &token).await.unwrap();

    let unlocking = {
        let session = session.clone();
        tokio::spawn(async move { post(addr, "/api/unlock", &session, json!({})).await })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (out, code) = cli(&at, &["panic"]).await;
    assert_eq!(code, 0, "{out}");
    assert!(daemon.config().locked);
    // The panic ended the session before its own answer.
    assert_eq!(get(addr, "/api/overview", &session).await.status, 401);
    let r = unlocking.await.unwrap();
    // The command was stopped by the panic; the node's refusal of its write
    // (daemon::tests::a_web_write_that_a_lock_overtook_is_refused) is the
    // second line behind it.
    assert_eq!(r.status, 400, "{}", r.body);
    assert!(r.body.contains("so it was stopped"), "{}", r.body);
    // The unlock would have written by now.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(
        daemon.config().locked,
        "the unlock in flight undid the panic"
    );
    daemon.stop().await;
}

/// A port that is taken is said by `ui on` and `ui status`, and the node
/// listens once it is free.
#[tokio::test(flavor = "multi_thread")]
async fn a_taken_port_is_told() {
    let _one = SERIAL.lock().await;
    let d = tempfile::tempdir().unwrap();
    let (daemon, at) = node(d.path()).await;
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port();
    let listen = format!("127.0.0.1:{port}");
    let (out, code) = cli(&at, &["ui", "on", "--listen", &listen]).await;
    assert_eq!(code, 0, "{out}");
    assert!(out.contains(&format!("cannot listen on {listen}")), "{out}");
    let (out, _) = cli(&at, &["ui", "status"]).await;
    assert!(out.contains("cannot listen"), "{out}");
    assert!(out.contains("tokens: first"), "{out}");
    // Free again, the node listens there at its next try.
    drop(taken);
    wait_until("the node listens once the port is free", || {
        ui_address(&daemon).is_some_and(|a| a.port() == port)
    })
    .await;
    daemon.stop().await;
}

/// On `127.0.0.1` the node holds `[::1]` at the same port too, and does not
/// listen while another account has it: `localhost` would go there.
#[tokio::test(flavor = "multi_thread")]
async fn both_loopback_addresses_are_held_or_neither() {
    let _one = SERIAL.lock().await;
    let Ok(squatter) = std::net::TcpListener::bind("[::1]:0") else {
        eprintln!("no IPv6 loopback here; nothing to test");
        return;
    };
    let port = squatter.local_addr().unwrap().port();
    if std::net::TcpListener::bind(("127.0.0.1", port)).is_err() {
        eprintln!("the port is taken on 127.0.0.1 as well; nothing to test");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let (daemon, at) = node(d.path()).await;
    let listen = format!("127.0.0.1:{port}");
    let (out, code) = cli(&at, &["ui", "on", "--listen", &listen]).await;
    assert_eq!(code, 0, "{out}");
    assert!(out.contains(&format!("cannot listen on {listen}")), "{out}");
    assert!(out.contains("localhost"), "{out}");
    assert!(ui_address(&daemon).is_none());
    // Free there, the node holds both.
    drop(squatter);
    wait_until("the node listens once the port is free", || {
        ui_address(&daemon).is_some_and(|a| a.port() == port)
    })
    .await;
    for host in ["127.0.0.1", "[::1]"] {
        let r = http(
            format!("{host}:{port}").parse().unwrap(),
            "GET",
            "/login",
            &[],
            "",
        )
        .await;
        assert_eq!(r.status, 200, "{host}: {}", r.body);
    }
    daemon.stop().await;
}

/// One request over TLS to `addr`, whose certificate must have `pin`.
async fn https(
    addr: SocketAddr,
    pin: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Result<Answer, String> {
    let url = nerve_proto::link::CenterUrl::parse(&format!("https://{addr}"))?;
    let (mut io, _) = nerve_transport::net::open_pins_seen(&url, &[pin], None).await?;
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nConnection: close\r\nContent-Length: {}\r\nContent-Type: application/json\r\n",
        body.len()
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    io.write_all(req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    let _ = io.read_to_end(&mut raw).await;
    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Ok(Answer {
        status,
        headers: Vec::new(),
        body: body.to_string(),
    })
}

/// An address of this machine other than loopback, if it has one: the
/// one it would send from to a documentation address (nothing is sent).
fn own_address() -> Option<std::net::IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

/// Beyond loopback the UI is served over TLS with a certificate of its own,
/// whose fingerprint `ui on` prints; without its key it does not listen,
/// and a new certificate ends every session.
#[tokio::test(flavor = "multi_thread")]
async fn beyond_loopback_the_ui_is_tls_with_its_own_certificate() {
    let _one = SERIAL.lock().await;
    let d = tempfile::tempdir().unwrap();
    let (daemon, at) = node(d.path()).await;
    let (out, code) = cli(
        &at,
        &[
            "ui",
            "on",
            "--listen",
            "0.0.0.0:0",
            "--name",
            "node.example",
        ],
    )
    .await;
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("web UI on at https://"), "{out}");
    assert!(out.contains("reached from the network"), "{out}");
    assert!(out.contains("ssh -L 7470:127.0.0.1:7470"), "{out}");
    let token = token_in(&out);
    // The printed fingerprint is the certificate's.
    let printed = out
        .lines()
        .skip_while(|l| !l.contains("SHA-256 fingerprint"))
        .nth(1)
        .unwrap()
        .trim()
        .to_string();
    let pem = std::fs::read_to_string(daemon.paths().ui_tls_file()).unwrap();
    let id = nerve_transport::tls::ServerIdentity::from_pem(&pem).unwrap();
    assert_eq!(printed, nerve_node::cli::ui::fingerprint(&id.cert_der));
    let pin = daemon.config().ui.pin.clone().unwrap();
    assert_eq!(pin, id.pin());
    let (out, _) = cli(&at, &["ui", "status"]).await;
    assert!(out.contains(&printed), "{out}");

    let port = ui_address(&daemon).unwrap().port();
    // At this machine's own address (or loopback without one), by any
    // name: beyond loopback the Host is not checked.
    let ip = own_address().unwrap_or([127, 0, 0, 1].into());
    let addr = SocketAddr::new(ip, port);
    let host = if ip.is_loopback() {
        addr.to_string()
    } else {
        "node.example:7470".to_string()
    };
    let origin = format!("https://{host}");
    let a = https(
        addr,
        &pin,
        "POST",
        "/login",
        &[("Host", &host), ("Origin", &origin)],
        &json!({ "token": token }).to_string(),
    )
    .await
    .unwrap();
    assert_eq!(a.status, 200, "{}", a.body);
    let session = a.json()["session"].as_str().unwrap().to_string();
    let a = https(
        addr,
        &pin,
        "GET",
        "/api/overview",
        &[("Host", &host), ("X-Nerve-Session", &session)],
        "",
    )
    .await
    .unwrap();
    assert_eq!(a.status, 200);
    // At a loopback address of the machine by a name that is not loopback
    // (its own name often resolves to 127.0.1.1) the page still loads.
    let on_loopback = SocketAddr::new([127, 0, 0, 1].into(), port);
    let a = https(
        on_loopback,
        &pin,
        "GET",
        "/",
        &[("Host", "node.example:7470")],
        "",
    )
    .await
    .unwrap();
    assert_eq!(a.status, 200, "{}", a.body);
    // Plain HTTP gets nothing there, and another certificate is refused.
    assert_eq!(http(addr, "GET", "/api/session", &[], "").await.status, 0);
    let other = nerve_transport::tls::ServerIdentity::generate(&[])
        .unwrap()
        .pin();
    assert!(https(addr, &other, "GET", "/", &[], "").await.is_err());

    // A new certificate: every session ends.
    let (out, code) = cli(&at, &["ui", "on", "--listen", "0.0.0.0:0", "--new-cert"]).await;
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("made now"), "{out}");
    let new_pin = daemon.config().ui.pin.clone().unwrap();
    assert_ne!(new_pin, pin);
    wait_until("the UI listens with the new certificate", || {
        ui_address(&daemon).is_some_and(|a| a.port() != port)
    })
    .await;
    let addr = SocketAddr::new(ip, ui_address(&daemon).unwrap().port());
    let a = https(
        addr,
        &new_pin,
        "GET",
        "/api/overview",
        &[("Host", &host), ("X-Nerve-Session", &session)],
        "",
    )
    .await
    .unwrap();
    assert_eq!(a.status, 401);

    // Without its key the UI does not listen beyond loopback at all.
    std::fs::remove_file(daemon.paths().ui_tls_file()).unwrap();
    let (_, code) = cli(&at, &["ui", "off"]).await;
    assert_eq!(code, 0);
    let (out, code) = cli(&at, &["config", "set", "ui.listen", "\"0.0.0.0:0\""]).await;
    assert_eq!(code, 0, "{out}");
    wait_until("the node says why it does not listen", || {
        daemon.status()["ui"]["status"]
            .as_str()
            .is_some_and(|s| s.contains("no TLS certificate"))
    })
    .await;
    assert!(ui_address(&daemon).is_none());
    // Loopback takes no certificate flags.
    let (out, code) = cli(&at, &["ui", "on", "--new-cert"]).await;
    assert_eq!(code, 1, "{out}");
    daemon.stop().await;
}

/// A change of the address is tried afresh: while the key is read for it, the
/// status is not the last failure's. `ui on` takes the first "listening" or
/// "cannot" for the new address as its answer, and the old failure's text
/// would be told as the new try's.
#[tokio::test(flavor = "multi_thread")]
async fn a_new_try_to_listen_does_not_keep_the_last_failure_in_the_status() {
    let _one = SERIAL.lock().await;
    let d = tempfile::tempdir().unwrap();
    let (daemon, at) = node(d.path()).await;
    let (out, code) = cli(&at, &["config", "set", "ui.listen", "\"0.0.0.0:0\""]).await;
    assert_eq!(code, 0, "{out}");
    let status = || {
        daemon.status()["ui"]["status"]
            .as_str()
            .unwrap()
            .to_string()
    };
    wait_until("the node says why it does not listen", || {
        status().contains("no TLS certificate")
    })
    .await;
    // The key's file is a pipe: reading it waits for a writer, as a keyring
    // that asks to be unlocked does.
    let key = daemon.paths().ui_tls_file();
    std::fs::create_dir_all(key.parent().unwrap()).unwrap();
    let made = std::process::Command::new("mkfifo")
        .arg(&key)
        .status()
        .unwrap();
    assert!(made.success());
    // Held open for reading and writing from the start: the node's open then
    // never waits for a writer, whenever it gets there, and its read ends
    // (empty) when this is dropped. Also when the test fails: a read that
    // waits for ever would keep the runtime from ending.
    let opener = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&key)
        .unwrap();
    let (out, code) = cli(&at, &["config", "set", "ui.listen", "\"0.0.0.0:1\""]).await;
    assert_eq!(code, 0, "{out}");
    wait_until("the new try says it started", || {
        status().starts_with("starting on 0.0.0.0:1")
    })
    .await;
    // Let the read end, with nothing in it.
    drop(opener);
    wait_until("the new try fails on its own", || {
        status().starts_with("cannot listen on 0.0.0.0:1")
    })
    .await;
    daemon.stop().await;
}

/// The web UI may not change its own settings nor take node.toml whole; it
/// may revoke. And a setting that stays root's stays so for root as owner.
#[test]
fn a_command_from_the_web_may_not_change_the_web_ui() {
    let d = tempfile::tempdir().unwrap();
    let run = |env: &[(&str, &str)], args: &[&str]| {
        let o = std::process::Command::new(program())
            .arg("--config-dir")
            .arg(d.path().join("config"))
            .arg("--state-dir")
            .arg(d.path().join("state"))
            .args(args)
            .env_remove("NERVE_OWNER")
            .env_remove("NERVE_OWNER_VIA")
            .envs(env.iter().copied())
            .output()
            .unwrap();
        (
            o.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr),
        )
    };
    let me = nerve_node::account::name_of(uid()).unwrap();
    // A token to revoke, made as the CLI makes it, and set up by hand.
    let (code, out) = run(&[], &["ui", "token", "add", "laptop"]);
    assert_eq!(code, 0, "{out}");
    let (code, out) = run(&[], &["ui", "token", "add", "phone"]);
    assert_eq!(code, 0, "{out}");
    let web = [("NERVE_OWNER", me.as_str()), ("NERVE_OWNER_VIA", "web")];
    for args in [
        &["ui", "on"][..],
        &["ui", "off"],
        &["ui", "token", "add", "more"],
        &["config", "set", "ui.listen", "\"0.0.0.0:7470\""],
        &["config", "unset", "ui.token"],
        &["config", "accept"],
    ] {
        let (code, out) = run(&web, args);
        assert_eq!(code, 1, "{args:?}: {out}");
        assert!(out.contains("only at the CLI"), "{args:?}: {out}");
    }
    let (code, out) = run(&web, &["ui", "token", "rm", "laptop"]);
    assert_eq!(code, 0, "{out}");
    let (code, out) = run(&web, &["ui", "token", "ls"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("phone") && !out.contains("laptop"), "{out}");
    // Root as owner has the owner's rights here, not root's.
    let (code, out) = run(
        &[("NERVE_OWNER", "root")],
        &["config", "set", "machine.shell", "\"/bin/sh\""],
    );
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("machine.shell decides"), "{out}");
}

/// A node with its UI on, and a session of it.
async fn signed_in(root: &Path) -> (Daemon, PathBuf, SocketAddr, String) {
    signed_in_running(root, program()).await
}

/// [`signed_in`], whose owner endpoint runs its commands with `endpoint_program`.
async fn signed_in_running(
    root: &Path,
    endpoint_program: PathBuf,
) -> (Daemon, PathBuf, SocketAddr, String) {
    let (daemon, at) = node_running(root, endpoint_program).await;
    let (out, code) = cli(&at, &["ui", "on", "--listen", "127.0.0.1:0"]).await;
    assert_eq!(code, 0, "{out}");
    let addr = ui_address(&daemon).unwrap();
    let session = login(addr, &token_in(&out)).await.unwrap();
    (daemon, at, addr, session)
}

/// A change the page asks for, which must work: its answer.
async fn change(addr: SocketAddr, session: &str, path: &str, body: Value) -> Value {
    let a = post(addr, path, session, body).await;
    assert_eq!(a.status, 200, "{path}: {}", a.body);
    a.json()
}

/// The Centers page: a center is paired from a pasted link, which goes on
/// the command's input, after a check; then paused, resumed, granted and
/// removed, each one command the node runs for its owner.
#[tokio::test(flavor = "multi_thread")]
async fn the_centers_page_pairs_and_manages_a_center() {
    let _one = SERIAL.lock().await;
    let d = tempfile::tempdir().unwrap();
    let (daemon, _at, addr, s) = signed_in(d.path()).await;
    let center = nerve_conformance::fake_center::FakeCenter::start(true)
        .await
        .unwrap();
    let link = center.link().render();
    let v = change(addr, &s, "/api/centers/preview", json!({ "link": link })).await;
    assert_eq!(v["paired"], false, "{v}");
    assert_eq!(v["check"]["ready"], true, "{v}");
    assert!(daemon.config().centers.is_empty());
    let v = change(
        addr,
        &s,
        "/api/centers/pair",
        json!({ "link": link, "name": "lab" }),
    )
    .await;
    assert_eq!(v["paired"], true, "{v}");
    assert_eq!(daemon.config().centers[0].name, "lab");
    // The link was never in a command line: the log names only the words.
    let log = std::fs::read_to_string(daemon.paths().log_file()).unwrap_or_default();
    assert!(!log.contains(&center.code), "{log}");

    change(addr, &s, "/api/centers/pause", json!({"center": "lab"})).await;
    assert!(daemon.config().centers[0].paused);
    change(addr, &s, "/api/centers/resume", json!({"center": "lab"})).await;
    assert!(!daemon.config().centers[0].paused);
    change(
        addr,
        &s,
        "/api/centers/grant",
        json!({"center": "lab", "what": "settings", "value": "write"}),
    )
    .await;
    assert_eq!(
        daemon.config().centers[0].settings,
        nerve_policy::config::SettingsGrant::Write
    );
    // What the command refuses comes back as its error.
    let a = post(
        addr,
        "/api/centers/grant",
        &s,
        json!({"center": "lab", "what": "all", "value": "write"}),
    )
    .await;
    assert_eq!(a.status, 400, "{}", a.body);
    let a = post(addr, "/api/centers/pause", &s, json!({"center": "-x"})).await;
    assert_eq!(a.status, 400);
    change(addr, &s, "/api/centers/remove", json!({"center": "lab"})).await;
    assert!(daemon.config().centers.is_empty());
    daemon.stop().await;
}

/// The Permissions, Audit and Log pages: mode, folders and rules change as
/// the CLI changes them; the audit offers the rule an entry's button adds;
/// the log is read in place.
#[tokio::test(flavor = "multi_thread")]
async fn the_permissions_audit_and_log_pages_change_the_node() {
    let _one = SERIAL.lock().await;
    let d = tempfile::tempdir().unwrap();
    let (daemon, _at, addr, s) = signed_in(d.path()).await;
    let center = nerve_conformance::fake_center::FakeCenter::start(true)
        .await
        .unwrap();
    change(
        addr,
        &s,
        "/api/centers/pair",
        json!({ "link": center.link().render(), "name": "lab" }),
    )
    .await;

    change(
        addr,
        &s,
        "/api/mode",
        json!({"center": "lab", "mode": "allowlist", "as_owner": true}),
    )
    .await;
    let policy = daemon.config().centers[0].policy.clone();
    assert_eq!(policy.mode, nerve_policy::Mode::Allowlist);
    assert!(policy.as_owner);
    let dir = std::fs::canonicalize(d.path()).unwrap().join("work");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.display().to_string();
    change(
        addr,
        &s,
        "/api/folders/add",
        json!({"center": "lab", "path": path, "read": true}),
    )
    .await;
    change(
        addr,
        &s,
        "/api/folders/set",
        json!({"center": "lab", "path": path, "read": true, "write": true}),
    )
    .await;
    let v = get(addr, "/api/perm?center=lab", &s).await;
    assert_eq!(v.status, 200, "{}", v.body);
    assert_eq!(
        v.json()["folders"]["folders"][0]["rights"],
        "rw-",
        "{}",
        v.body
    );
    let a = post(
        addr,
        "/api/folders/add",
        &s,
        json!({"center": "lab", "path": "work", "read": true}),
    )
    .await;
    assert_eq!(a.status, 400, "a relative path is refused: {}", a.body);
    change(
        addr,
        &s,
        "/api/folders/remove",
        json!({"center": "lab", "path": path}),
    )
    .await;
    assert!(daemon.config().centers[0].policy.folders.is_empty());

    change(
        addr,
        &s,
        "/api/rules/add",
        json!({"center": "lab", "list": "allow", "rule": "git status"}),
    )
    .await;
    change(
        addr,
        &s,
        "/api/rules/add",
        json!({"center": "lab", "list": "deny", "rule": "fs.read:~/private/*"}),
    )
    .await;
    let v = get(addr, "/api/perm?center=lab", &s).await.json();
    assert!(
        v["rules"]["allow"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "exec.run:git status"),
        "{v}"
    );
    assert!(
        v["rules"]["deny"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "fs.read:~/private/*"),
        "{v}"
    );
    change(
        addr,
        &s,
        "/api/rules/remove",
        json!({"center": "lab", "list": "allow", "rule": "git status"}),
    )
    .await;
    let v = get(addr, "/api/perm?center=lab", &s).await.json();
    assert!(
        !v["rules"]["allow"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "exec.run:git status"),
        "{v}"
    );

    // An entry's button adds the rule its preview shows.
    let v = get(addr, "/api/audit", &s).await;
    assert_eq!(v.status, 200);
    assert!(
        !v.json()["entries"].as_array().unwrap().is_empty(),
        "the changes are audited"
    );
    change(
        addr,
        &s,
        "/api/audit/rule",
        json!({"center": "lab", "cap": "exec", "action": "run", "target": "make test", "list": "allow"}),
    )
    .await;
    let allow = daemon.config().centers[0].policy.allow.clone();
    assert!(allow.iter().any(|r| r.contains("make test")), "{allow:?}");
    change(addr, &s, "/api/audit/clear", json!({})).await;

    let v = get(addr, "/api/log", &s).await;
    assert_eq!(v.status, 200);
    assert!(v.json()["entries"].as_array().is_some(), "{}", v.body);
    let v = get(addr, "/api/log?problems=1", &s).await.json();
    for e in v["entries"].as_array().unwrap() {
        assert!(matches!(e["level"].as_str(), Some("error" | "warn")), "{e}");
    }
    change(addr, &s, "/api/log/clear", json!({})).await;
    daemon.stop().await;
}

/// `center add --link-stdin` takes the link from the first line of its
/// input, as the web UI passes it, and only then.
#[test]
fn the_pairing_link_comes_from_stdin_when_asked() {
    use std::io::Write;
    let d = tempfile::tempdir().unwrap();
    let run = |args: &[&str], input: &str| {
        let mut c = std::process::Command::new(program())
            .arg("--config-dir")
            .arg(d.path().join("config"))
            .arg("--state-dir")
            .arg(d.path().join("state"))
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
        let o = c.wait_with_output().unwrap();
        (
            o.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr),
        )
    };
    let (code, out) = run(&["center", "add", "--link-stdin", "--yes"], "\n");
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("first line of stdin is empty"), "{out}");
    // The line is the link, read as one.
    let (code, out) = run(&["center", "add", "--link-stdin", "--yes"], "not-a-link\n");
    assert_eq!(code, 1, "{out}");
    assert!(!out.contains("stdin is empty"), "{out}");
    let (code, out) = run(&["center", "add"], "");
    assert_eq!(code, 2, "a link or --link-stdin: {out}");
    let (code, out) = run(&["center", "add", "nerve://pair?x", "--link-stdin"], "");
    assert_eq!(code, 2, "not both: {out}");
}

/// The routes the other tests do not drive: each builds its one command, and
/// the proxy's password goes on the command's input, never in its arguments.
#[tokio::test(flavor = "multi_thread")]
async fn the_remaining_routes_build_their_commands_and_keep_secrets_off_the_command_line() {
    use std::os::unix::fs::PermissionsExt;
    let _one = SERIAL.lock().await;
    let d = tempfile::tempdir().unwrap();
    // The program of the owner socket, noting every command line, and for a
    // `proxy set` its input.
    let (log, input) = (d.path().join("argv.log"), d.path().join("proxy.in"));
    let wrapper = d.path().join("noting.sh");
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\necho \"$*\" >> {log}\ncase \" $* \" in\n *\" proxy set \"*) tee {input} | {real} \"$@\";;\n *) exec {real} \"$@\";;\nesac\n",
            log = log.display(),
            input = input.display(),
            real = program().display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (daemon, at, addr, s) = signed_in_running(d.path(), wrapper).await;
    // The proxy's login is kept in a file of the node's, not a keyring this
    // machine may not have.
    let (out, code) = cli(
        &at,
        &["config", "set", "machine.secret_storage", "\"file\""],
    )
    .await;
    assert_eq!(code, 0, "{out}");
    let center = nerve_conformance::fake_center::FakeCenter::start(true)
        .await
        .unwrap();
    change(
        addr,
        &s,
        "/api/centers/pair",
        json!({ "link": center.link().render(), "name": "lab" }),
    )
    .await;

    // The proxy: its password on the input.
    change(
        addr,
        &s,
        "/api/proxy/set",
        json!({"url": "https://alice@127.0.0.1:3128", "pin": "A".repeat(43), "password": "pw-0123456789"}),
    )
    .await;
    assert!(daemon.config().connection.proxy.is_some());
    let said = std::fs::read_to_string(&log).unwrap();
    let line = said.lines().find(|l| l.contains("proxy set")).unwrap();
    assert!(line.contains("--password-stdin"), "{line}");
    assert!(!said.contains("pw-0123456789"), "{said}");
    assert_eq!(std::fs::read_to_string(&input).unwrap(), "pw-0123456789\n");
    let a = post(addr, "/api/proxy/set", &s, json!({"url": "--pin=x"})).await;
    assert_eq!(a.status, 400, "{}", a.body);
    change(addr, &s, "/api/proxy/remove", json!({})).await;
    assert!(daemon.config().connection.proxy.is_none());

    // A node of the relay gets a new token.
    change(
        addr,
        &s,
        "/api/relay/set",
        json!({"address": "127.0.0.1:0"}),
    )
    .await;
    change(addr, &s, "/api/relay/add", json!({"name": "lab-pc"})).await;
    let before = daemon
        .config()
        .relay
        .node("lab-pc")
        .unwrap()
        .token_sha256
        .clone();
    let v = change(addr, &s, "/api/relay/token", json!({"name": "lab-pc"})).await;
    assert!(
        v["token"]["link"]
            .as_str()
            .unwrap()
            .starts_with("nerve://relay?"),
        "{v}"
    );
    assert_ne!(
        daemon.config().relay.node("lab-pc").unwrap().token_sha256,
        before
    );
    assert_eq!(
        post(addr, "/api/relay/token", &s, json!({"name": "-x"}))
            .await
            .status,
        400
    );

    // A center's guard: a pairing has it, and the page puts back a rule that
    // was taken away.
    let guard_rule = daemon.config().center("lab").unwrap().policy.deny[0].clone();
    let a = post(addr, "/api/rules/guard", &s, json!({"center": "lab"})).await;
    assert_eq!(a.status, 400, "the guard is there already: {}", a.body);
    change(
        addr,
        &s,
        "/api/rules/remove",
        json!({"center": "lab", "list": "deny", "rule": guard_rule}),
    )
    .await;
    assert!(
        !daemon
            .config()
            .center("lab")
            .unwrap()
            .policy
            .deny
            .contains(&guard_rule)
    );
    change(addr, &s, "/api/rules/guard", json!({"center": "lab"})).await;
    assert!(
        daemon
            .config()
            .center("lab")
            .unwrap()
            .policy
            .deny
            .contains(&guard_rule)
    );
    // The sudo list is closed, a setting taken away, a key rotated.
    change(addr, &s, "/api/sudo/off", json!({})).await;
    assert!(
        std::fs::read_to_string(&log)
            .unwrap()
            .lines()
            .any(|l| l.ends_with("sudo off")),
        "sudo off was run"
    );
    change(
        addr,
        &s,
        "/api/settings/set",
        json!({"key": "node.name", "value": "\"lab-1\""}),
    )
    .await;
    change(addr, &s, "/api/settings/unset", json!({"key": "node.name"})).await;
    assert!(daemon.config().node.name.is_none());
    let a = post(addr, "/api/settings/unset", &s, json!({"key": "ui.listen"})).await;
    assert_eq!(a.status, 400, "{}", a.body);
    let a = post(addr, "/api/centers/rotate", &s, json!({"center": "lab"})).await;
    let said = std::fs::read_to_string(&log).unwrap();
    assert!(
        said.contains("center rotate-key --center=lab") || said.contains("center rotate-key lab"),
        "{said}\n{}",
        a.body
    );
    daemon.stop().await;
}

/// The Capabilities, Relay, Settings and Help pages: each change one
/// command of the CLI; what stays root's, and the web UI's own settings,
/// are refused.
#[tokio::test(flavor = "multi_thread")]
async fn the_capabilities_relay_settings_and_help_pages_change_the_node() {
    let _one = SERIAL.lock().await;
    let d = tempfile::tempdir().unwrap();
    let (daemon, _at, addr, s) = signed_in(d.path()).await;
    let center = nerve_conformance::fake_center::FakeCenter::start(true)
        .await
        .unwrap();
    change(
        addr,
        &s,
        "/api/centers/pair",
        json!({ "link": center.link().render(), "name": "lab" }),
    )
    .await;

    // Capabilities: a switch, one of your own, a program.
    let v = get(addr, "/api/caps?center=lab", &s).await;
    assert_eq!(v.status, 200, "{}", v.body);
    assert_eq!(v.json()["center"], "lab");
    change(
        addr,
        &s,
        "/api/caps/set",
        json!({"center": "lab", "cap": "exec", "setting": "off"}),
    )
    .await;
    let caps = daemon.config().centers[0].policy.caps.clone();
    assert!(caps.contains_key("exec"), "{caps:?}");
    let form = json!({"name": "notes.count", "summary": "Counts the notes.", "effect": "read", "command": "ls /tmp", "platform": "any"});
    change(
        addr,
        &s,
        "/api/caps/save",
        json!({"adding": true, "form": form}),
    )
    .await;
    assert_eq!(daemon.config().capabilities[0].name, "notes.count");
    // The page edits it: the listing gives the form it fills, and a save
    // that is no adding changes the capability.
    let v = get(addr, "/api/caps?center=lab", &s).await.json();
    let mut form = v["config"][0]["form"].clone();
    assert_eq!(form["name"], "notes.count", "{v}");
    assert_eq!(form["command"], "ls /tmp");
    form["command"] = json!("ls /var/tmp");
    form["timeout"] = json!("30");
    form["effect"] = json!("write");
    change(
        addr,
        &s,
        "/api/caps/save",
        json!({"adding": false, "form": form}),
    )
    .await;
    let own = daemon.config().capabilities[0].clone();
    assert_eq!(own.command, ["ls", "/var/tmp"]);
    assert_eq!(own.timeout_secs, Some(30));
    assert_eq!(daemon.config().capabilities.len(), 1);
    // The form is checked as the desktop's dialog checks it.
    let bad =
        json!({"name": "", "summary": "", "effect": "read", "command": "", "platform": "any"});
    let a = post(
        addr,
        "/api/caps/save",
        &s,
        json!({"adding": true, "form": bad}),
    )
    .await;
    assert_eq!(a.status, 400);
    assert!(
        a.json()["error"].as_str().unwrap().contains("name:"),
        "{}",
        a.body
    );
    change(addr, &s, "/api/caps/remove", json!({"name": "notes.count"})).await;
    assert!(daemon.config().capabilities.is_empty());
    change(
        addr,
        &s,
        "/api/programs/allow",
        json!({"name": "lights", "exe": "/usr/bin/true"}),
    )
    .await;
    assert_eq!(daemon.config().providers.allowed[0].name, "lights");
    let a = post(
        addr,
        "/api/programs/allow",
        &s,
        json!({"name": "x", "exe": "bin/true"}),
    )
    .await;
    assert_eq!(a.status, 400);
    change(addr, &s, "/api/programs/remove", json!({"name": "lights"})).await;
    assert!(daemon.config().providers.allowed.is_empty());

    // Relay: on, a node with its link shown once, off.
    change(
        addr,
        &s,
        "/api/relay/set",
        json!({"address": "127.0.0.1:0"}),
    )
    .await;
    assert_eq!(daemon.config().relay.listen.as_deref(), Some("127.0.0.1:0"));
    let v = change(addr, &s, "/api/relay/add", json!({"name": "lab-pc"})).await;
    assert!(
        v["token"]["link"]
            .as_str()
            .unwrap()
            .starts_with("nerve://relay?"),
        "{v}"
    );
    assert!(daemon.config().relay.node("lab-pc").is_some());
    let v = get(addr, "/api/relay", &s).await.json();
    assert_eq!(v["relay"]["nodes"][0]["name"], "lab-pc", "{v}");
    assert!(!v.to_string().contains("token_sha256"), "{v}");
    change(addr, &s, "/api/relay/remove", json!({"name": "lab-pc"})).await;
    change(addr, &s, "/api/relay/off", json!({})).await;
    assert!(daemon.config().relay.listen.is_none());

    // Settings: name and log level; root's and the web UI's own refused.
    change(
        addr,
        &s,
        "/api/settings/set",
        json!({"key": "node.name", "value": "\"lab-1\""}),
    )
    .await;
    assert_eq!(daemon.config().node.name.as_deref(), Some("lab-1"));
    let v = get(addr, "/api/settings", &s).await.json();
    assert_eq!(v["name"], "lab-1");
    for (key, value, why) in [
        ("machine.shell", "\"/bin/sh\"", "machine.shell decides"),
        ("ui.listen", "\"0.0.0.0:7470\"", "only at the CLI"),
    ] {
        let a = post(
            addr,
            "/api/settings/set",
            &s,
            json!({"key": key, "value": value}),
        )
        .await;
        assert_eq!(a.status, 400, "{key}");
        assert!(
            a.json()["error"].as_str().unwrap().contains(why),
            "{key}: {}",
            a.body
        );
    }
    assert!(daemon.config().machine.shell.is_none());

    // Help: the CLI's own reference.
    let v = get(addr, "/api/help", &s).await.json();
    assert!(!v["node"]["sections"].as_array().unwrap().is_empty(), "{v}");
    daemon.stop().await;
}
