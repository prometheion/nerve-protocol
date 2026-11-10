//! The sudo switch on Windows, end to end on the installed service: the
//! conformance fake center pairs with it and may not turn sudo on; the
//! installed program, as the app runs it, turns it on with the owner's
//! password; the center runs commands with and without sudo, and a restart
//! of the service turns it off. The owner's password reaches the running
//! node as the app hands it over (`password`). It needs a Windows test machine: Nerve installed as a service (the
//! app's `install`, as CI's `windows-installed` job runs it) whose owner, the
//! account that installed it, is an administrator, an elevated terminal, and
//! that account and its password in `NERVE_WIN_SUDO_ACCOUNT` and
//! `NERVE_WIN_SUDO_PASSWORD`:
//!
//! ```text
//! cargo test -p nerve-node --test win_sudo -- --ignored
//! ```
//!
//! It pairs the service with a center named `winsudo` and changes its rules,
//! which the running node takes at once, and restarts it.
#![cfg(windows)]

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use nerve_conformance::fake_center::{self, FakeCenter};
use nerve_conformance::wire::Conn;
use nerve_node::edition::{DESKTOP_PROGRAM, Edition};
use nerve_node::service::Layout;
use nerve_policy::config::{SettingsGrant, Sudo};
use nerve_policy::rules;
use nerve_proto::{ErrorCode, RpcError};
use nerve_transport::sudo::{Offer, seal};
use serde_json::{Value, json};
use tokio::net::TcpStream;

const WAIT: Duration = Duration::from_secs(30);
const CENTER: &str = "winsudo";
/// The SIDs of the integrity levels `whoami /groups` lists: an elevated
/// token is high, a filtered one medium.
const HIGH: &str = "S-1-16-12288";
const MEDIUM: &str = "S-1-16-8192";
/// A sudo command that runs for half a minute.
const PING: &str = "sudo ping -n 30 127.0.0.1";
/// The desktop app, whose program is the node's on Windows (#176): the
/// install puts it where its `Layout` says.
static APP: Edition = Edition {
    program: DESKTOP_PROGRAM,
    parts: None,
};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
}

fn restart_service() {
    let ok = Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", "Restart-Service nerve-node"])
        .status()
        .unwrap()
        .success();
    assert!(ok, "Restart-Service nerve-node");
}

/// The first link of the node's that completes the handshake. A link the
/// node opened before a restart may still wait here: the stop closed it
/// before its hello, and the node started again dials anew.
async fn linked(center: &mut FakeCenter) -> Conn<TcpStream> {
    let paired = center.paired().expect("paired");
    let until = tokio::time::Instant::now() + WAIT;
    let mut ended = Vec::new();
    while let Some(mut inc) = center
        .next_link(until.saturating_duration_since(tokio::time::Instant::now()))
        .await
    {
        match fake_center::handshake(&mut inc.conn, &center.center_id, &paired).await {
            Ok(_) => return inc.conn,
            Err(e) => ended.push(e),
        }
    }
    panic!("no link of the node completed the handshake; those that ended: {ended:?}");
}

async fn call(conn: &mut Conn<TcpStream>, method: &str, params: Value) -> Result<Value, RpcError> {
    let id = conn.request(method, params).await.unwrap();
    conn.answer(id, WAIT, &mut Vec::new()).await.unwrap()
}

async fn invoke(
    conn: &mut Conn<TcpStream>,
    cap: &str,
    action: &str,
    args: Value,
) -> Result<Value, RpcError> {
    call(
        conn,
        "invoke",
        json!({"cap": cap, "action": action, "args": args}),
    )
    .await
}

async fn run(conn: &mut Conn<TcpStream>, command: &str) -> Result<Value, RpcError> {
    invoke(conn, "exec", "run", json!({"command": command})).await
}

async fn state(conn: &mut Conn<TcpStream>) -> String {
    let v = call(conn, "get", json!({"cap": "settings", "keys": ["sudo"]}))
        .await
        .expect("settings state");
    v["sudo"].as_str().unwrap_or_default().to_string()
}

/// `sudo on` of the installed program, with the password on stdin, as the
/// app runs it.
fn cli_on(layout: &Layout, password: &str) -> std::process::Output {
    with_input(layout, &["sudo", "on"], password)
}

/// The installed program's `args`, with `password` on stdin.
fn with_input(layout: &Layout, args: &[&str], password: &str) -> std::process::Output {
    let mut child = Command::new(&layout.bin)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{password}").unwrap();
    child.wait_with_output().unwrap()
}

async fn on(conn: &mut Conn<TcpStream>, password: &str) -> Result<Value, RpcError> {
    let v = invoke(conn, "settings", "sudo-offer", json!({}))
        .await
        .expect("sudo-offer");
    let offer = Offer {
        offer: v["offer"].as_str().unwrap().into(),
        key: v["key"].as_str().unwrap().into(),
        ts: v["ts"].as_u64().unwrap(),
    };
    let now = nerve_proto::msg::now_ms();
    let sealed = seal(&offer, password, now).unwrap();
    invoke(
        conn,
        "settings",
        "sudo",
        json!({"on": true, "sealed": sealed}),
    )
    .await
}

fn refused(r: Result<Value, RpcError>, kind: ErrorCode) -> String {
    match r {
        Ok(v) => panic!("succeeded with {v}"),
        Err(e) => {
            assert_eq!(e.kind(), kind, "{}", e.message);
            e.message
        }
    }
}

fn stdout(r: &Value) -> &str {
    r["stdout"].as_str().unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the node installed as a service on a Windows test machine"]
async fn sudo_runs_a_listed_command_elevated_on_the_installed_service() {
    let account = env("NERVE_WIN_SUDO_ACCOUNT");
    let password = env("NERVE_WIN_SUDO_PASSWORD");
    let layout = Layout::of(&APP);
    let paths = layout.paths.clone();
    let mut center = FakeCenter::start(false).await.unwrap();
    // What an earlier run paired goes first.
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
    assert!(
        nerve_node::service::owner_of(&paths).is_some_and(|o| o.eq_ignore_ascii_case(&account)),
        "the owner is not {account}"
    );
    nerve_node::cli::edit(&paths, |cfg| {
        let e = cfg.center_mut(CENTER).expect("paired");
        e.settings = SettingsGrant::Write;
        // A new pairing starts in folder mode, whose commands run in its
        // AppContainer and only in a folder with `x`, and where allow rules
        // do not count: this command runs by its allow rule as the owner,
        // with the owner's own token, outside a container.
        e.policy.mode = nerve_policy::Mode::Allowlist;
        e.policy.as_owner = true;
        e.policy.allow = vec![rules::rule_for(
            "exec",
            "run",
            "whoami /groups",
            false,
            None,
        )?];
        e.policy.sudo_allow = vec![
            rules::sudo_rule_for("sudo whoami /groups", false)?,
            rules::sudo_rule_for("sudo net session", false)?,
            rules::sudo_rule_for(PING, false)?,
        ];
        Ok(())
    })
    .await
    .expect("the owner's edit");
    // The running node took the pairing and the rules at once, and dialed.
    let mut conn = linked(&mut center).await;

    // The owner's password, as the app hands it to `password` where the
    // node has none that works: the running node checks it with a logon,
    // refuses a wrong one, and stores the right one.
    let o = with_input(&layout, &["password"], "not-the-password");
    assert!(!o.status.success(), "{o:?}");
    let o = with_input(&layout, &["password"], &password);
    assert!(o.status.success(), "{o:?}");
    let said = String::from_utf8_lossy(&o.stdout).to_lowercase();
    assert!(
        said.contains(&format!(
            "the node has the password of {}",
            account.to_lowercase()
        )),
        "{said}"
    );
    let o = Command::new(&layout.bin)
        .args(["--json", "status"])
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&o.stdout).unwrap_or_default();
    assert_eq!(v["owner_password"], "stored", "{v}");

    // Off: the sudo list names the command, yet it is refused.
    assert_eq!(state(&mut conn).await, "off");
    let e = refused(
        run(&mut conn, "sudo whoami /groups").await,
        ErrorCode::Forbidden,
    );
    assert!(e.contains("sudo is off"), "{e}");

    // A center is refused before any password is checked, so a wrong one
    // learns nothing and cannot count towards locking the owner's account.
    let e = refused(
        on(&mut conn, "not-the-password").await,
        ErrorCode::Forbidden,
    );
    assert!(e.contains("in the Nerve app on this machine"), "{e}");
    assert!(!e.contains("is wrong"), "{e}");

    // A center may not turn it on, not even with the right password: it
    // is the owner's Windows password, which only the app takes.
    let e = refused(on(&mut conn, &password).await, ErrorCode::Forbidden);
    assert!(e.contains("in the Nerve app on this machine"), "{e}");
    assert_eq!(state(&mut conn).await, "off");

    // The installed program, as the app runs it: a wrong password is
    // refused and the switch stays off.
    let o = cli_on(&layout, "not-the-password");
    assert!(!o.status.success(), "{o:?}");
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("is wrong"),
        "{o:?}"
    );
    assert_eq!(state(&mut conn).await, "off");

    // The right one turns it on, held in the node's memory only.
    let o = cli_on(&layout, &password);
    assert!(o.status.success(), "{o:?}");
    assert_eq!(state(&mut conn).await, "on");
    for f in std::fs::read_dir(&paths.config_dir).unwrap() {
        let f = f.unwrap().path();
        assert_ne!(
            f.file_name().unwrap().to_string_lossy(),
            "sudo.dpapi",
            "the password is kept at rest"
        );
    }

    // A command without sudo runs with the filtered token, one with sudo
    // with the full one.
    let r = run(&mut conn, "whoami /groups").await.expect("whoami");
    assert!(
        stdout(&r).contains(MEDIUM) && !stdout(&r).contains(HIGH),
        "{r}"
    );
    let r = run(&mut conn, "sudo whoami /groups")
        .await
        .expect("sudo whoami");
    assert!(stdout(&r).contains(HIGH), "{r}");
    // `net session` needs the administrators' rights.
    let r = run(&mut conn, "sudo net session")
        .await
        .expect("net session");
    assert_eq!(r["exit_code"], 0, "{r}");
    // What the sudo list does not name is refused.
    let e = refused(run(&mut conn, "sudo net user").await, ErrorCode::Forbidden);
    assert!(e.contains("sudo allow list"), "{e}");

    // The job ends an elevated command too, at its timeout.
    let started = std::time::Instant::now();
    let r = invoke(
        &mut conn,
        "exec",
        "run",
        json!({"command": PING, "timeout_ms": 1000}),
    )
    .await;
    refused(r, ErrorCode::Timeout);
    assert!(started.elapsed() < Duration::from_secs(10));
    let o = Command::new("tasklist")
        .args(["/fi", "imagename eq PING.EXE", "/fo", "csv", "/nh"])
        .output()
        .unwrap();
    let left = String::from_utf8_lossy(&o.stdout);
    assert!(!left.to_lowercase().contains("ping.exe"), "{left}");

    // The installed program's `sudo off`, as the app runs it: the running
    // service drops the password at once.
    let o = Command::new(&layout.bin)
        .args(["sudo", "off"])
        .output()
        .unwrap();
    assert!(o.status.success(), "{o:?}");
    assert_eq!(state(&mut conn).await, "off");
    let e = refused(
        run(&mut conn, "sudo whoami /groups").await,
        ErrorCode::Forbidden,
    );
    assert!(e.contains("sudo is off"), "{e}");

    // On again, then a restart of the service: the switch is off, as on
    // Linux, since nothing kept the password.
    let o = cli_on(&layout, &password);
    assert!(o.status.success(), "{o:?}");
    assert_eq!(state(&mut conn).await, "on");
    restart_service();
    let mut conn = linked(&mut center).await;
    assert_eq!(state(&mut conn).await, "off");
    let e = refused(
        run(&mut conn, "sudo whoami /groups").await,
        ErrorCode::Forbidden,
    );
    assert!(e.contains("sudo is off"), "{e}");
    let cfg = nerve_policy::SettingsStore::peek(&paths.config_file(), &paths.config_key()).unwrap();
    assert_eq!(cfg.machine.sudo, Sudo::Off);
}
