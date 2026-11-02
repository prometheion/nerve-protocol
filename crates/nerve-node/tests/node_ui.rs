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
        program: program(),
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
    let _ = io.read_to_end(&mut raw).await;
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
    assert_eq!(own_listeners().len(), 1, "{:?}", own_listeners());
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
    // The login page clears what a page that held the port left.
    let a = get(addr, "/login", "").await;
    assert_eq!(a.header("clear-site-data"), Some("\"storage\""));

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
