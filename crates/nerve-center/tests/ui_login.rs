//! The web UI's login as a started center has it: always the owner token,
//! made at the first start, on loopback too; a harness token opens `/mcp`
//! only, and the owner token never opens `/mcp`.

use clap::Parser;
use nerve_center::config::Args;
use nerve_center::server::{self, Running};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn start(dir: &std::path::Path, extra: &[&str]) -> Result<Running, String> {
    nerve_transport::init_crypto();
    let mut argv = vec![
        "nerve-center",
        "--state-dir",
        dir.to_str().unwrap(),
        "--listen",
        "127.0.0.1:0",
        "--plain-loopback",
    ];
    if !extra.contains(&"--mcp") {
        argv.extend(["--mcp", "off"]);
    }
    argv.extend_from_slice(extra);
    let args = Args::try_parse_from(argv).unwrap();
    let lock = nerve_center::attach::try_lock(dir)
        .unwrap()
        .expect("the lock is free");
    server::start(&args, lock).await
}

/// One plain request: its status and body.
async fn http(
    addr: std::net::SocketAddr,
    head: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (u16, String) {
    let mut io = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut req = format!(
        "{head} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    io.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    io.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    (
        head.split(' ').nth(1).unwrap().parse().unwrap(),
        body.into(),
    )
}

/// What `GET /api/session` tells a page without a session.
async fn session_info(r: &Running) -> serde_json::Value {
    let (status, body) = http(r.ui.expect("a UI"), "GET /api/session", &[], "").await;
    assert_eq!(status, 200, "{body}");
    serde_json::from_str(&body).unwrap()
}

/// Posts `token` to the login: the status.
async fn login(r: &Running, token: &str) -> u16 {
    let body = serde_json::json!({ "token": token }).to_string();
    let json = [("Content-Type", "application/json")];
    http(r.ui.expect("a UI"), "POST /login", &json, &body)
        .await
        .0
}

fn owner_token(dir: &std::path::Path) -> String {
    nerve_center::owner::read(dir)
        .unwrap()
        .expect("an owner token")
}

/// A fresh center makes its owner token at once, keeps it private, and its
/// UI on loopback asks for it: no session for anyone who asks without it.
#[tokio::test]
async fn a_fresh_center_asks_for_its_owner_token_on_loopback() {
    let d = tempfile::tempdir().unwrap();
    let r = start(d.path(), &["--ui", "127.0.0.1:0"]).await.unwrap();
    let token = owner_token(d.path());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file = nerve_center::owner::path(d.path());
        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let v = session_info(&r).await;
    assert_eq!(
        (v["login"].clone(), v["logged_in"].clone()),
        (true.into(), false.into())
    );
    assert!(v.get("session").is_none(), "{v}");
    let (status, _) = http(r.ui.unwrap(), "GET /api/checker", &[], "").await;
    assert_eq!(status, 401);
    assert_eq!(login(&r, &token).await, 200);
    // The log says where the token is, never the token.
    let file = std::fs::read_to_string(d.path().join("log.jsonl")).unwrap();
    assert!(file.contains("made the owner token"), "{file}");
    assert!(file.contains(nerve_center::owner::FILE), "{file}");
    assert!(!file.contains(&token), "{file}");
    // The next start keeps it, and says nothing of it.
    r.stop().await;
    let r = start(d.path(), &["--ui", "127.0.0.1:0"]).await.unwrap();
    assert_eq!(owner_token(d.path()), token);
    assert_eq!(login(&r, &token).await, 200);
    let file = std::fs::read_to_string(d.path().join("log.jsonl")).unwrap();
    assert_eq!(file.matches("made the owner token").count(), 1, "{file}");
}

/// A harness token from a flag logs in nowhere: it is the agent's, and the
/// web UI changes what the agent may do.
#[tokio::test]
async fn a_harness_token_from_a_flag_does_not_log_in() {
    let d = tempfile::tempdir().unwrap();
    let r = start(
        d.path(),
        &[
            "--ui",
            "127.0.0.1:0",
            "--harness-token",
            "nrv_secret-of-the-harness",
        ],
    )
    .await
    .unwrap();
    assert_eq!(login(&r, "nrv_secret-of-the-harness").await, 401);
    assert_eq!(login(&r, &owner_token(d.path())).await, 200);
}

/// A wrong token over a real connection waits before its 401 goes out, and
/// the right token right after it is answered at once.
#[tokio::test]
async fn a_wrong_token_over_the_socket_waits() {
    let d = tempfile::tempdir().unwrap();
    let r = start(d.path(), &["--ui", "127.0.0.1:0"]).await.unwrap();
    let t = std::time::Instant::now();
    assert_eq!(login(&r, "nrv_not-the-owner-token").await, 401);
    assert!(t.elapsed() >= nerve_transport::webui::WRONG_SECRET_DELAY);
    let t = std::time::Instant::now();
    assert_eq!(login(&r, &owner_token(d.path())).await, 200);
    assert!(t.elapsed() < nerve_transport::webui::WRONG_SECRET_DELAY);
}

/// The HTTP MCP endpoint takes harness tokens only: the owner token is not
/// one.
#[tokio::test]
async fn the_owner_token_does_not_open_mcp() {
    let d = tempfile::tempdir().unwrap();
    let r = start(
        d.path(),
        &[
            "--ui",
            "off",
            "--mcp",
            "127.0.0.1:0",
            "--harness-token",
            "nrv_secret-of-the-harness",
        ],
    )
    .await
    .unwrap();
    let addr = r.mcp.expect("an MCP endpoint");
    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#;
    let post = |token: String| async move {
        let bearer = format!("Bearer {token}");
        let headers = [
            ("Authorization", bearer.as_str()),
            ("Content-Type", "application/json"),
            ("Accept", "application/json, text/event-stream"),
        ];
        http(addr, "POST /mcp", &headers, init).await
    };
    let (status, body) = post(owner_token(d.path())).await;
    assert_eq!(status, 401);
    // The refusal says what to send, and where a token comes from.
    assert!(body.contains("Authorization: Bearer"), "{body}");
    assert!(body.contains("Connect a harness"), "{body}");
    assert_eq!(post("nrv_secret-of-the-harness".into()).await.0, 200);
}

/// Beyond loopback the UI needs no harness token to start: it logs in with
/// the owner token, over TLS.
#[tokio::test]
async fn beyond_loopback_the_owner_token_is_the_login() {
    let d = tempfile::tempdir().unwrap();
    for ui in ["0.0.0.0:0", "[::]:0"] {
        let r = start(d.path(), &["--ui", ui]).await.unwrap();
        assert!(r.ui.is_some());
        r.stop().await;
    }
}

#[tokio::test]
async fn without_a_web_ui_the_owner_token_is_made_all_the_same() {
    let d = tempfile::tempdir().unwrap();
    let r = start(d.path(), &["--ui", "off"]).await.unwrap();
    assert!(r.ui.is_none());
    owner_token(d.path());
}

/// The token from a flag is kept out of every line, also where a message
/// quotes it and no pattern would catch it.
#[tokio::test]
async fn the_harness_token_from_a_flag_stays_out_of_the_log() {
    let token = "plain-words-for-a-token";
    let d = tempfile::tempdir().unwrap();
    let r = start(d.path(), &["--ui", "127.0.0.1:0", "--harness-token", token])
        .await
        .unwrap();
    r.center.log().record(
        nerve_transport::log::Level::Warn,
        None,
        &format!("the proxy said {token} is not allowed"),
    );
    let file = std::fs::read_to_string(d.path().join("log.jsonl")).unwrap();
    assert!(
        file.contains("the proxy said [redacted] is not allowed"),
        "{file}"
    );
    assert!(!file.contains(token), "{file}");
    // The startup line is in it too, and names no token.
    assert!(file.contains("web UI at http://"), "{file}");
}
