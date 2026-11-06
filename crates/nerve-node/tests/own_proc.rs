//! A folder-mode command sees only its own processes (#199): each runs in a
//! PID namespace with a `/proc` of its own, so `ps -eo args` in one
//! pairing's command does not show the command line of another pairing's
//! running command. Without that `/proc` it does, which the test checks too,
//! so it fails where the namespace is missing rather than pass by chance.
//! Linux only; skipped where the kernel gives the shim no namespace or no
//! Landlock (the installed node's run, as `nerve-run`, is in
//! real_account.rs).
#![cfg(target_os = "linux")]

mod common;

use std::path::Path;
use std::time::Duration;

use common::{linked, owner_edit};
use nerve_conformance::fake_center::FakeCenter;
use nerve_conformance::wire::Conn;
use nerve_node::{Daemon, NodeOptions, NodePaths};
use nerve_policy::config::{Access, Folder, Mode};
use serde_json::{Value, json};
use tokio::net::TcpStream;

const WAIT: Duration = Duration::from_secs(30);

async fn run(conn: &mut Conn<TcpStream>, command: &str, cwd: &Path) -> Value {
    conn.call(
        "invoke",
        json!({"cap": "exec", "action": "run", "args": {
            "command": command, "cwd": cwd.display().to_string()}, "ctx": {}}),
        WAIT,
    )
    .await
    .unwrap()
    .expect("the command runs")
}

/// Whether a process of this machine has `text` in its command line.
fn running(text: &str) -> bool {
    std::fs::read_dir("/proc").unwrap().flatten().any(|e| {
        std::fs::read(e.path().join("cmdline"))
            .is_ok_and(|c| String::from_utf8_lossy(&c).contains(text))
    })
}

/// Two centers in folder mode on a node run by hand, each with a folder:
/// while one's command runs, what `ps` shows to the other's command, and
/// to the first one's own.
async fn seen_by_the_other(root: &Path, own_proc: bool) -> (String, String) {
    let mut a = FakeCenter::start(false).await.unwrap();
    let mut b = FakeCenter::start(false).await.unwrap();
    let mut o = NodeOptions::new(NodePaths::new(root.join("config"), root.join("state")));
    o.home = root.join("home");
    std::fs::create_dir_all(&o.home).unwrap();
    o.full_rights = Some(false);
    o.exe = Some(env!("CARGO_BIN_EXE_nerve-node").into());
    o.own_proc = Some(own_proc);
    nerve_node::pair::pair(&o.paths, &a.link(), Some("lab"))
        .await
        .expect("pair a");
    nerve_node::pair::pair(&o.paths, &b.link(), Some("work"))
        .await
        .expect("pair b");
    let (one, two) = (root.join("one"), root.join("two"));
    for d in [&one, &two] {
        std::fs::create_dir_all(d).unwrap();
    }
    let (one, two) = (one.canonicalize().unwrap(), two.canonicalize().unwrap());
    owner_edit(&o.paths, |c| {
        for (e, folder) in c.centers.iter_mut().zip([&one, &two]) {
            e.policy.mode = Mode::Folder;
            e.policy.folders = vec![Folder {
                path: folder.display().to_string(),
                access: Access::ALL,
            }];
        }
    })
    .await;
    let node = Daemon::start(o).await.expect("start");
    let mut conn_a = linked(&mut a).await;
    let mut conn_b = linked(&mut b).await;
    let marker = format!("nerve-own-proc-{}-{own_proc}", std::process::id());
    let line = format!("sleep 4; : {marker}");
    let first = {
        let one = one.clone();
        tokio::spawn(async move {
            let r = run(&mut conn_a, &line, &one).await;
            (r, conn_a)
        })
    };
    let started = std::time::Instant::now();
    while !running(&marker) {
        assert!(started.elapsed() < WAIT, "the first command did not start");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let other = run(&mut conn_b, "ps -eo args", &two).await;
    let (r, mut conn_a) = first.await.unwrap();
    assert_eq!(r["exit_code"], 0, "{r}");
    let own = run(&mut conn_a, &format!("ps -eo args; : {marker}"), &one).await;
    node.stop().await;
    (
        other["stdout"]
            .as_str()
            .unwrap_or_default()
            .replace(&marker, "MARKER"),
        own["stdout"]
            .as_str()
            .unwrap_or_default()
            .replace(&marker, "MARKER"),
    )
}

/// Whether this kernel lets an account make a PID namespace with its own
/// `/proc` in a user namespace, asked of util-linux's `unshare` where it is
/// there (so a shim that fails here fails the tests, not skips them), else
/// of the shim.
fn namespaces_here() -> bool {
    let asked = std::process::Command::new("unshare")
        .args([
            "--user",
            "--map-current-user",
            "--pid",
            "--fork",
            "--mount",
            "--mount-proc",
            "true",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    match asked {
        Ok(s) => s.success(),
        Err(_) => nerve_sandbox::own_proc::works(Path::new(env!("CARGO_BIN_EXE_nerve-node"))),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_command_of_one_pairing_does_not_see_a_running_command_of_another() {
    if !nerve_sandbox::Confinement::detect().by_hand().available() {
        eprintln!("skipped: Landlock is not available here");
        return;
    }
    if !namespaces_here() {
        eprintln!("skipped: this kernel gives the shim no PID namespace with its own /proc");
        return;
    }
    assert!(nerve_sandbox::own_proc::works(Path::new(env!(
        "CARGO_BIN_EXE_nerve-node"
    ))));
    let dir = tempfile::tempdir().unwrap();
    let (other, own) = seen_by_the_other(&dir.path().join("apart"), true).await;
    assert!(!other.contains("MARKER"), "{other}");
    // `ps` works there and shows the command's own processes.
    assert!(other.contains("ps -eo args"), "{other}");
    assert!(own.contains("MARKER"), "{own}");
    assert!(!own.contains("sleep 4"), "{own}");
    // Without its own /proc the other pairing's command line shows.
    let (other, _) = seen_by_the_other(&dir.path().join("shared"), false).await;
    assert!(other.contains("sleep 4; : MARKER"), "{other}");
}

/// A command with its own `/proc` ends as it would without: with its exit
/// code, or by its signal, which the shim takes on; what it left running
/// ends with it; a signal to its group reaches it and a trap it set.
#[tokio::test]
async fn a_command_in_its_own_namespace_ends_as_it_would_without() {
    use nerve_node::exec::{self, RunCall, RunOptions};
    if !namespaces_here() {
        eprintln!("skipped: this kernel gives the shim no PID namespace with its own /proc");
        return;
    }
    let opts = RunOptions {
        shell: None,
        landlock: None,
        container: None,
        exe: env!("CARGO_BIN_EXE_nerve-node").into(),
        output_cap: 64 * 1024,
        timeouts: Default::default(),
        sudo: None,
        account: None,
        separate: None,
        pass_env: Vec::new(),
        own: Vec::new(),
        root: None,
        limits: None,
        tap: None,
        no_network: false,
        own_proc: true,
    };
    let call = |command: &str| RunCall {
        command: command.into(),
        argv: None,
        cwd: std::env::temp_dir(),
        timeout: Some(Duration::from_secs(20)),
        limits: Default::default(),
    };
    let r = exec::run(&call("echo $$; exit 7"), &opts, |_| {})
        .await
        .unwrap();
    assert_eq!(r["exit_code"], 7, "{r}");
    // The shell is the namespace's second process, after the init.
    assert_eq!(r["stdout"], "2\n", "{r}");
    let r = exec::run(&call("kill -TERM $$"), &opts, |_| {})
        .await
        .unwrap();
    assert_eq!(r["signal"], "term", "{r}");
    // What it left running ends with it.
    let left = format!("sleep 60.{}", std::process::id() % 1000);
    let r = exec::run(&call(&format!("{left} & echo started")), &opts, |_| {})
        .await
        .unwrap();
    assert_eq!(r["stdout"], "started\n", "{r}");
    let gone = std::time::Instant::now();
    while running(&left) {
        assert!(gone.elapsed() < WAIT, "{left} outlived its command");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // A TERM to the command's group, as `exec.signal` and a stop send it,
    // reaches a trap the command set, which ends it its own way.
    let marker = format!("nerve-trap-{}", std::process::id());
    let line = format!("trap 'echo trapped; exit 3' TERM; : {marker}; sleep 30 & wait");
    let ran = {
        let line = line.clone();
        tokio::spawn(async move { exec::run(&call(&line), &opts, |_| {}).await })
    };
    let started = std::time::Instant::now();
    let shell = loop {
        if let Some(pid) = pid_of(&line) {
            break pid;
        }
        assert!(started.elapsed() < WAIT, "the command did not start");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    // The shell is in the shim's group, which the node signals.
    // SAFETY: getpgid and kill with plain integers.
    let group = unsafe { libc::getpgid(shell as i32) };
    tokio::time::sleep(Duration::from_millis(200)).await;
    unsafe { libc::kill(-group, libc::SIGTERM) };
    let r = ran.await.unwrap().unwrap();
    assert_eq!(r["exit_code"], 3, "{r}");
    assert_eq!(r["stdout"], "trapped\n", "{r}");
}

/// The process whose command line has `text` as one of its words.
fn pid_of(text: &str) -> Option<u32> {
    std::fs::read_dir("/proc").ok()?.flatten().find_map(|e| {
        let pid = e.file_name().to_str()?.parse().ok()?;
        let c = std::fs::read(e.path().join("cmdline")).ok()?;
        c.split(|b| *b == 0)
            .any(|w| w == text.as_bytes())
            .then_some(pid)
    })
}
