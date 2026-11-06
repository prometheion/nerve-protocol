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

/// The options of a command run by the node itself, as the user it is,
/// with a `/proc` of its own and nothing else.
fn run_options() -> nerve_node::exec::RunOptions {
    nerve_node::exec::RunOptions {
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
    }
}

/// A command with its own `/proc` ends as it would without: with its exit
/// code, or by its signal, which the shim takes on; what it left running
/// ends with it; a signal to its group reaches it and a trap it set.
#[tokio::test]
async fn a_command_in_its_own_namespace_ends_as_it_would_without() {
    use nerve_node::exec::{self, RunCall};
    if !namespaces_here() {
        eprintln!("skipped: this kernel gives the shim no PID namespace with its own /proc");
        return;
    }
    let opts = run_options();
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

/// A node that runs as root (run by hand with full rights) keeps root's
/// rights over the files of other accounts in the namespace of a command:
/// the namespace maps every id root sees (round 1, correctness 1). Needs
/// root, so it is skipped otherwise; the LXC run has it.
#[tokio::test]
async fn a_root_node_keeps_its_rights_over_other_accounts_files() {
    use nerve_node::exec::{self, RunCall};
    use std::os::unix::fs::{PermissionsExt, chown};
    if nerve_transport::net::euid() != 0 {
        eprintln!("skipped: needs root");
        return;
    }
    if !namespaces_here() {
        eprintln!("skipped: this kernel gives the shim no PID namespace with its own /proc");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    // 0711 above, so the test's own folder is no hurdle; the inside is
    // another account's alone.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o711)).unwrap();
    let theirs = dir.path().join("theirs");
    std::fs::create_dir(&theirs).unwrap();
    std::fs::set_permissions(&theirs, std::fs::Permissions::from_mode(0o700)).unwrap();
    chown(&theirs, Some(23456), Some(23456)).unwrap();
    let file = theirs.join("secret");
    std::fs::write(&file, "kept\n").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    chown(&file, Some(23456), Some(23456)).unwrap();
    let call = |command: String| RunCall {
        command,
        argv: None,
        cwd: dir.path().to_path_buf(),
        timeout: Some(Duration::from_secs(20)),
        limits: Default::default(),
    };
    let r = exec::run(
        &call(format!(
            "cat {} && echo more >> {}",
            file.display(),
            file.display()
        )),
        &run_options(),
        |_| {},
    )
    .await
    .unwrap();
    assert_eq!(r["exit_code"], 0, "{r}");
    assert_eq!(r["stdout"], "kept\n", "{r}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "kept\nmore\n");
}

/// A capability a center added runs in a namespace of its own as well: its
/// `ps` does not show the command line of another pairing's running command,
/// which runs in the node's namespace here (a pairing in user mode). With no
/// namespace it shows, so the test fails where the line is missing rather
/// than pass by chance (round 1, security 4).
#[tokio::test(flavor = "multi_thread")]
async fn a_capability_a_center_added_has_a_proc_of_its_own() {
    if !namespaces_here() {
        eprintln!("skipped: this kernel gives the shim no PID namespace with its own /proc");
        return;
    }
    let mut seen = Vec::new();
    for own_proc in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let mut center = FakeCenter::start(false).await.unwrap();
        let mut o = NodeOptions::new(NodePaths::new(
            dir.path().join("config"),
            dir.path().join("state"),
        ));
        o.home = dir.path().join("home");
        std::fs::create_dir_all(&o.home).unwrap();
        o.full_rights = Some(false);
        o.exe = Some(env!("CARGO_BIN_EXE_nerve-node").into());
        // The node by hand runs a center's capabilities as its own user,
        // for `nerve-run`.
        o.config_caps_by_hand = true;
        o.own_proc = Some(own_proc);
        o.confinement = Some(nerve_sandbox::Confinement {
            landlock_abi: None,
            appcontainer: false,
        });
        nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
            .await
            .expect("pair");
        let ps = nerve_policy::NodeConfig::parse(
            "[[capability]]\nname = \"proc.list\"\neffect = \"read\"\ncommand = [\"ps\", \"-eo\", \"args\"]\n",
        )
        .expect("a capability")
        .capabilities[0]
            .clone();
        owner_edit(&o.paths, |c| {
            c.capabilities = vec![ps.clone()];
            c.centers[0].policy.mode = Mode::User;
        })
        .await;
        let node = Daemon::start(o).await.expect("start");
        let mut conn = linked(&mut center).await;
        let marker = format!("nerve-cap-proc-{}-{own_proc}", std::process::id());
        let line = format!("sleep 4; : {marker}");
        // The pairing's own command runs in the node's namespace (user mode)
        // while the capability looks.
        let id = conn
            .request(
                "invoke",
                json!({"cap": "exec", "action": "run", "args": {
                    "command": line, "cwd": std::env::temp_dir().display().to_string()}, "ctx": {}}),
            )
            .await
            .unwrap();
        let started = std::time::Instant::now();
        while !running(&marker) {
            assert!(started.elapsed() < WAIT, "the command did not start");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let listing = conn
            .call(
                "invoke",
                json!({"cap": "proc", "action": "list", "args": {}, "ctx": {}}),
                WAIT,
            )
            .await
            .unwrap()
            .expect("the capability runs");
        let r = conn
            .answer(id, WAIT, &mut Vec::new())
            .await
            .unwrap()
            .expect("the command ends");
        assert_eq!(r["exit_code"], 0, "{r}");
        let text = listing
            .as_str()
            .unwrap_or_default()
            .replace(&marker, "MARKER");
        assert!(text.contains("ps -eo args"), "{text}");
        seen.push(text);
        node.stop().await;
    }
    assert!(!seen[0].contains("MARKER"), "{}", seen[0]);
    assert!(seen[1].contains("MARKER"), "{}", seen[1]);
}

/// The shim and the namespace's init are two tasks of the command's cgroup
/// besides the command, so the node adds two to the `pids.max` it sets: a
/// call that asks for 2 processes starts. A plain folder tree stands for the
/// cgroup hierarchy; the command reads the limit its own cgroup has (round 1,
/// correctness 2).
#[tokio::test]
async fn the_cgroup_has_room_for_the_shim_and_the_init() {
    use nerve_node::cgroup::Cgroups;
    use nerve_node::exec::{self, RunCall};
    use nerve_policy::config::Granted;
    use std::sync::Arc;
    if !namespaces_here() {
        eprintln!("skipped: this kernel gives the shim no PID namespace with its own /proc");
        return;
    }
    let mut said = Vec::new();
    for own_proc in [true, false] {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("app");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(t.path().join("cgroup.controllers"), "cpu memory pids io").unwrap();
        std::fs::write(dir.join("cgroup.controllers"), "cpu memory pids").unwrap();
        std::fs::write(
            dir.join("cgroup.procs"),
            format!("{}\n", std::process::id()),
        )
        .unwrap();
        let cgroups = Cgroups::at(
            t.path(),
            "/app",
            std::process::id(),
            nerve_transport::net::euid(),
            &|_| true,
        )
        .expect("a cgroup tree in folders");
        // The kernel would keep all three turned on; a plain file keeps the
        // last write only.
        std::fs::write(dir.join("cgroup.subtree_control"), "cpu memory pids").unwrap();
        let mut opts = run_options();
        opts.own_proc = own_proc;
        opts.limits = Some((
            Arc::new(cgroups),
            Granted {
                memory_mb: 512,
                cpu_percent: 100,
                processes: 2,
            },
        ));
        let call = RunCall {
            command: format!("cat {}/*/pids.max", dir.display()),
            argv: None,
            cwd: std::env::temp_dir(),
            timeout: Some(Duration::from_secs(20)),
            limits: Default::default(),
        };
        let r = exec::run(&call, &opts, |_| {}).await.unwrap();
        assert_eq!(r["exit_code"], 0, "{r}");
        said.push(r["stdout"].as_str().unwrap_or_default().trim().to_string());
    }
    assert_eq!(said, ["4", "2"]);
}
