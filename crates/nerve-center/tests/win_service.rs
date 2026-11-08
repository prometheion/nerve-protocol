//! The center as a Windows service, end to end on a Windows test machine
//! (#64): `install` registers it as its virtual account with its settings
//! and its firewall rule, `status` says it runs, its web UI logs in with the
//! owner token and opens every page in Chrome, a second center a harness
//! starts on one state folder attaches to the first, `update` takes the
//! same program, and `uninstall --purge` leaves nothing behind. It needs an
//! elevated terminal on a machine without an installed center, the program
//! to install in `NERVE_CENTER_PROGRAM`, and for the browser Node.js,
//! Chrome and `.github/scripts/web-ui-smoke.mjs` in `NERVE_UI_SMOKE_NODE`,
//! `NERVE_UI_SMOKE_CHROME` and `NERVE_UI_SMOKE_SCRIPT`, as CI's
//! `windows-installed` job runs it:
//!
//! ```text
//! cargo test -p nerve-center --test win_service -- --ignored
//! ```
#![cfg(windows)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// The node port of the installed center: not the default, so the
/// firewall rule shows it is the one the settings name.
const PORT: u16 = 7943;
const UI: &str = "127.0.0.1:7480";

fn program() -> PathBuf {
    PathBuf::from(std::env::var("NERVE_CENTER_PROGRAM").expect("NERVE_CENTER_PROGRAM is not set"))
}

/// What `nerve-center <args>` said, and whether it ended well.
fn center(args: &[&str]) -> (bool, String) {
    let o = Command::new(program())
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    eprintln!("nerve-center {}:\n{said}", args.join(" "));
    (o.status.success(), said)
}

/// One request to the web UI on loopback; its status and body.
fn http(method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> (u16, String) {
    let mut s = std::net::TcpStream::connect(UI).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {UI}\r\nConnection: close\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
    s.write_all(req.as_bytes()).unwrap();
    let mut answer = String::new();
    s.read_to_string(&mut answer).unwrap();
    let status = answer
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let body = answer
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

/// What the tools say of the installed folders: `icacls` and `netsh`.
fn system(program: &str, args: &[&str]) -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let o = Command::new(Path::new(&root).join("System32").join(program))
        .args(args)
        .output()
        .unwrap();
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// A center as a harness starts it, on `state`.
fn harness(state: &Path) -> std::process::Child {
    let mut c = Command::new(program());
    c.env_clear();
    if let Some(root) = std::env::var_os("SystemRoot") {
        c.env("SystemRoot", root);
    }
    c.env("NERVE_CENTER_STATE_DIR", state)
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

/// One MCP request on a harness's stdio, and its answer.
fn ask(child: &mut std::process::Child, out: &mut impl BufRead, msg: Value) -> Value {
    let stdin = child.stdin.as_mut().unwrap();
    writeln!(stdin, "{msg}").unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    out.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap_or_else(|e| panic!("{e}: {line:?}"))
}

fn initialize() -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "win-service-test", "version": "0"}}})
}

#[test]
#[ignore = "installs the center as a Windows service: a Windows test machine only"]
fn the_center_runs_as_a_windows_service() {
    let port = format!("0.0.0.0:{PORT}");
    let (ok, said) = center(&["install", "--name", "win-test", "--listen", &port]);
    assert!(ok, "{said}");
    assert!(said.contains("runs as NT SERVICE\\nerve-center"), "{said}");
    assert!(said.contains("the service nerve-center runs"), "{said}");
    let token = said
        .lines()
        .find_map(|l| l.strip_prefix("Owner token: "))
        .and_then(|l| l.split_whitespace().next())
        .expect("an owner token")
        .to_string();

    let r = std::panic::catch_unwind(|| {
        // The service runs, and `status` says so as the administrator asks.
        let (ok, said) = center(&["status"]);
        assert!(ok, "{said}");
        assert!(said.contains("center: running"), "{said}");
        assert!(
            said.contains("service: running, starts with the machine"),
            "{said}"
        );
        assert!(
            said.contains("in an administrator's terminal shows it"),
            "{said}"
        );
        // Its folders are its account's and the administrators', its
        // settings the administrators' (the service reads them).
        let data = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into());
        let state = Path::new(&data).join("nerve-center").join("state");
        let acl = system("icacls.exe", &[&state.display().to_string()]);
        assert!(
            acl.contains("NT SERVICE\\nerve-center:(OI)(CI)(F)"),
            "{acl}"
        );
        assert!(!acl.contains("Users") && !acl.contains("(I)"), "{acl}");
        let settings = Path::new(&data).join("nerve-center").join("settings");
        let acl = system("icacls.exe", &[&settings.display().to_string()]);
        assert!(
            acl.contains("NT SERVICE\\nerve-center:(OI)(CI)(R)"),
            "{acl}"
        );
        // The firewall lets others reach the node port, and that alone.
        let rule = system(
            "netsh.exe",
            &[
                "advfirewall",
                "firewall",
                "show",
                "rule",
                "name=Nerve center",
                "verbose",
            ],
        );
        assert!(rule.contains(&PORT.to_string()), "{rule}");
        assert!(!rule.contains("7480") && !rule.contains("7481"), "{rule}");

        // The web UI: its page, a login with the owner token, the overview.
        let until = Instant::now() + Duration::from_secs(30);
        let (status, page) = loop {
            match std::net::TcpStream::connect(UI) {
                Ok(_) => break http("GET", "/", &[], ""),
                Err(_) if Instant::now() < until => std::thread::sleep(Duration::from_millis(250)),
                Err(e) => panic!("the web UI does not answer at {UI}: {e}"),
            }
        };
        assert_eq!(status, 200, "{page}");
        let (status, wrong) = http(
            "POST",
            "/login",
            &[("Content-Type", "application/json")],
            &json!({"token": "nrv_not-the-token"}).to_string(),
        );
        assert_eq!(status, 401, "{wrong}");
        assert!(wrong.contains("in an administrator's terminal"), "{wrong}");
        let (status, login) = http(
            "POST",
            "/login",
            &[("Content-Type", "application/json")],
            &json!({"token": token}).to_string(),
        );
        assert_eq!(status, 200, "{login}");
        let session = serde_json::from_str::<Value>(&login).unwrap()["session"]
            .as_str()
            .unwrap()
            .to_string();
        let (status, overview) = http("GET", "/api/overview", &[("X-Nerve-Session", &session)], "");
        assert_eq!(status, 200, "{overview}");
        let o: Value = serde_json::from_str(&overview).unwrap();
        assert_eq!(o["center"]["name"], "win-test");
        assert_eq!(o["center"]["os"], "windows");
        assert_eq!(o["mcp"]["mode"], "http", "{o}");
        // Every page in a real browser, signed in as a person signs in.
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        match (
            var("NERVE_UI_SMOKE_NODE"),
            var("NERVE_UI_SMOKE_CHROME"),
            var("NERVE_UI_SMOKE_SCRIPT"),
        ) {
            (Some(node), Some(chrome), Some(script)) => {
                let o = Command::new(node)
                    .args([script, chrome, format!("http://{UI}"), token.clone()])
                    .output()
                    .unwrap();
                let said = String::from_utf8_lossy(&o.stdout).to_string()
                    + &String::from_utf8_lossy(&o.stderr);
                assert!(o.status.success(), "the web UI in Chrome: {said}");
            }
            _ => eprintln!(
                "skipped: the web UI in a browser, as NERVE_UI_SMOKE_NODE, NERVE_UI_SMOKE_CHROME and NERVE_UI_SMOKE_SCRIPT are not all set"
            ),
        }

        // A second center a harness starts on one state folder attaches to
        // the first over its pipe.
        let dir = tempfile::tempdir().unwrap();
        let mut first = harness(dir.path());
        let mut first_out = BufReader::new(first.stdout.take().unwrap());
        assert!(ask(&mut first, &mut first_out, initialize())["result"].is_object());
        let mut second = harness(dir.path());
        let mut second_out = BufReader::new(second.stdout.take().unwrap());
        assert!(ask(&mut second, &mut second_out, initialize())["result"].is_object());
        let list = ask(
            &mut second,
            &mut second_out,
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        );
        assert_eq!(list["result"]["tools"][0]["name"], "list", "{list}");
        drop(second.stdin.take());
        drop(first.stdin.take());
        for c in [&mut second, &mut first] {
            let until = Instant::now() + Duration::from_secs(20);
            while c.try_wait().unwrap().is_none() {
                assert!(Instant::now() < until, "a harness's center did not end");
                std::thread::sleep(Duration::from_millis(100));
            }
        }

        // The same program again: nothing to update.
        let (ok, said) = center(&["update", "--from", &program().display().to_string()]);
        assert!(ok, "{said}");
        assert!(said.contains("is that one already"), "{said}");
    });

    let (ok, said) = center(&["uninstall", "--purge"]);
    if let Err(e) = r {
        std::panic::resume_unwind(e);
    }
    assert!(ok, "{said}");
    assert!(
        said.contains("stopped and removed the service nerve-center"),
        "{said}"
    );
    assert!(said.contains("removed the Windows Firewall rule"), "{said}");
    let (_, said) = center(&["status"]);
    assert!(said.contains("service: not installed"), "{said}");
    let rule = system(
        "netsh.exe",
        &[
            "advfirewall",
            "firewall",
            "show",
            "rule",
            "name=Nerve center",
        ],
    );
    assert!(!rule.contains(&PORT.to_string()), "{rule}");
}
