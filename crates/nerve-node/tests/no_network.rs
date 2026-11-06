//! The owner's network switch for a pairing's folder-mode commands
//! (`network off`, docs/dev/sandbox-linux.md) on a real node daemon, in
//! process and run by hand: a command of that pairing, and a capability of
//! the config it calls, opens no TCP connection and no UDP socket, which it
//! opens without the switch, held by the node's seccomp filter whether or
//! not the kernel's Landlock has its network rules; where the node cannot
//! hold it to that (told here that it has no filter) it runs none of that
//! pairing's folder-mode commands and says why. Linux only, as the filter
//! is.
#![cfg(target_os = "linux")]

mod common;

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use common::linked;
use nerve_conformance::fake_center::{self, FakeCenter};
use nerve_conformance::wire::Conn;
use nerve_node::{Daemon, Hold, HoldAt, NodeOptions, NodePaths};
use nerve_policy::NodeConfig;
use nerve_policy::config::{Access, CapSetting, Folder, Mode};
use serde_json::{Value, json};
use tokio::net::TcpStream;

const WAIT: Duration = Duration::from_secs(15);

/// A capability of the config that connects to a TCP port on this machine.
const PROBE: &str = r#"[[capability]]
name = "probe.connect"
effect = "read"
command = ["/bin/bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/$0 && echo open", "{port}"]
params = '{"type": "object", "properties": {"port": {"type": "integer"}}, "required": ["port"]}'
"#;

/// Pairs with `center` as `lab` in `mode`, with `work` to run in and the
/// network switch `off`, and starts the daemon as `confinement` and
/// `filter` say (`None`: the kernel's own), with `hold` for its command
/// calls.
#[allow(clippy::too_many_arguments)]
async fn node_in(
    mode: Mode,
    root: &Path,
    work: &Path,
    center: &FakeCenter,
    off: bool,
    confinement: Option<nerve_sandbox::Confinement>,
    filter: Option<bool>,
    hold: Option<Hold>,
) -> Daemon {
    let mut o = NodeOptions::new(NodePaths::new(root.join("config"), root.join("state")));
    o.hold = hold;
    o.home = root.join("home");
    std::fs::create_dir_all(&o.home).unwrap();
    o.full_rights = Some(false);
    o.exe = Some(env!("CARGO_BIN_EXE_nerve-node").into());
    o.confinement = confinement;
    o.net_filter = filter;
    // The node by hand runs the config's capabilities as its own user, for
    // `nerve-run` (as config_caps.rs does).
    o.config_caps_by_hand = true;
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .expect("pair");
    nerve_node::cli::edit(&o.paths, |c| {
        c.capabilities = NodeConfig::parse(PROBE).expect("a capability").capabilities;
        let p = &mut c.centers[0].policy;
        p.caps.insert("probe".into(), CapSetting::On);
        p.mode = mode;
        p.no_network = off;
        p.sudo_allow = vec!["sudo true".into()];
        p.folders = vec![Folder {
            path: work.display().to_string(),
            access: Access::ALL,
        }];
        Ok(())
    })
    .await
    .expect("the owner's edit");
    Daemon::start(o).await.expect("start")
}

/// [`node_in`] folder mode.
async fn node(
    root: &Path,
    work: &Path,
    center: &FakeCenter,
    off: bool,
    confinement: Option<nerve_sandbox::Confinement>,
    filter: Option<bool>,
) -> Daemon {
    node_in(
        Mode::Folder,
        root,
        work,
        center,
        off,
        confinement,
        filter,
        None,
    )
    .await
}

async fn run(
    conn: &mut Conn<TcpStream>,
    command: &str,
    cwd: &Path,
) -> Result<Value, nerve_proto::RpcError> {
    conn.call(
        "invoke",
        json!({"cap": "exec", "action": "run", "args": {
            "command": command, "cwd": cwd.display().to_string()}, "ctx": {}}),
        WAIT,
    )
    .await
    .unwrap()
}

async fn invoke(
    conn: &mut Conn<TcpStream>,
    name: &str,
    args: Value,
) -> Result<Value, nerve_proto::RpcError> {
    let (cap, action) = name.split_once('.').unwrap();
    conn.call(
        "invoke",
        json!({"cap": cap, "action": action, "args": args, "ctx": {}}),
        WAIT,
    )
    .await
    .unwrap()
}

/// With the switch, a folder-mode command cannot connect to a TCP port on
/// this machine that it reaches without it, nor open a UDP socket, and the
/// descriptor tells the center that its commands have no network. A node by
/// hand holds it only where Landlock tells unix sockets by path apart (ABI
/// 9, Linux 7.1) and it is not root: below that the commands run as the
/// owner with the owner's session manager in reach, so it runs none of them
/// and says why. A capability of the config stands for `nerve-run` here and
/// runs, held by the filter alone.
#[tokio::test(flavor = "multi_thread")]
async fn a_folder_command_without_network_opens_no_tcp_connection() {
    let abi = nerve_sandbox::Confinement::detect().landlock_abi;
    if abi.is_none_or(|v| v < nerve_sandbox::LANDLOCK_FLOOR)
        || !nerve_sandbox::net_filter::available()
        || !Path::new("/bin/bash").exists()
    {
        eprintln!("skipped: no Landlock, no seccomp filters or no bash here");
        return;
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_port = udp.local_addr().unwrap().port();
    let connect = format!("/bin/bash -c 'exec 3<>/dev/tcp/127.0.0.1/{port}' && echo open");
    let send = format!("/bin/bash -c 'exec 3<>/dev/udp/127.0.0.1/{udp_port}' && echo open");
    let older = nerve_sandbox::Confinement {
        landlock_abi: Some(nerve_sandbox::LANDLOCK_FLOOR),
        appcontainer: false,
    };
    for (off, confinement) in [(false, None), (true, None), (true, Some(older))] {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let work = root.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let mut center = FakeCenter::start(false).await.unwrap();
        let daemon = node(&root, &work, &center, off, confinement, None).await;
        let mut conn = linked(&mut center).await;
        let told = confinement.map_or(abi, |c| c.landlock_abi);
        if off && told.is_none_or(|v| v < nerve_sandbox::LANDLOCK_RESOLVE_UNIX) {
            // Below ABI 9 a node by hand runs none of them.
            let e = run(&mut conn, &connect, &work).await.expect_err("refused");
            assert!(
                e.message.contains("runs them as its own user"),
                "{}",
                e.message
            );
            let d = conn
                .call("describe", json!({"detail": "full"}), WAIT)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(d["access"]["no_network"], "as_owner", "{d}");
            let r = invoke(&mut conn, "probe.connect", json!({"port": port})).await;
            assert!(
                !r.as_ref().is_ok_and(|v| v.as_str() == Some("open\n")),
                "{r:?}"
            );
            daemon.stop().await;
            continue;
        }
        for probe in [&connect, &send] {
            let r = run(&mut conn, probe, &work)
                .await
                .expect("the command runs");
            let opened = r["stdout"] == "open\n" && r["exit_code"] == 0;
            assert_eq!(opened, !off, "network off {off}, {probe}: {r}");
        }
        // A capability of the config is a command of the pairing too.
        let r = invoke(&mut conn, "probe.connect", json!({"port": port})).await;
        assert_eq!(
            r.as_ref().is_ok_and(|v| v.as_str() == Some("open\n")),
            !off,
            "network off {off}: {r:?}"
        );
        let d = conn
            .call("describe", json!({"detail": "full"}), WAIT)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            d["access"].get("no_network"),
            off.then(|| json!("held")).as_ref(),
            "{d}"
        );
        daemon.stop().await;
    }
}

/// With the switch and Landlock from ABI 9, a folder-mode command reaches a
/// unix socket by path in its folders and not one elsewhere, which it
/// reaches without the switch: a program answering there could reach the
/// network for it. Skipped below ABI 9 and without python3 to connect with.
#[tokio::test(flavor = "multi_thread")]
async fn a_folder_command_without_network_reaches_unix_sockets_in_its_folders_only() {
    let abi = nerve_sandbox::Confinement::detect().landlock_abi;
    if abi.is_none_or(|v| v < nerve_sandbox::LANDLOCK_RESOLVE_UNIX)
        || !nerve_sandbox::net_filter::available()
        || !Path::new("/usr/bin/python3").exists()
    {
        eprintln!("skipped: no Landlock rules for unix sockets, no seccomp filters or no python3");
        return;
    }
    for off in [false, true] {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let work = root.join("work");
        let elsewhere = root.join("elsewhere");
        for dir in [&work, &elsewhere] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let _in = std::os::unix::net::UnixListener::bind(work.join("s")).unwrap();
        let _out = std::os::unix::net::UnixListener::bind(elsewhere.join("s")).unwrap();
        let mut center = FakeCenter::start(false).await.unwrap();
        let daemon = node(&root, &work, &center, off, None, None).await;
        let mut conn = linked(&mut center).await;
        for (dir, reached) in [(&work, true), (&elsewhere, !off)] {
            let probe = format!(
                "/usr/bin/python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).connect(sys.argv[1]); print(\"open\")' {}",
                dir.join("s").display()
            );
            let r = run(&mut conn, &probe, &work)
                .await
                .expect("the command runs");
            let opened = r["stdout"] == "open\n" && r["exit_code"] == 0;
            assert_eq!(opened, reached, "network off {off}, {dir:?}: {r}");
        }
        daemon.stop().await;
    }
}

/// Where the node has no network filter, it runs none of the pairing's
/// folder-mode commands while its network is off, and says why; it offers
/// it no command.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_that_cannot_keep_commands_off_the_network_runs_none() {
    let d = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(d.path()).unwrap();
    let work = root.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let landlock = nerve_sandbox::Confinement {
        landlock_abi: Some(6),
        appcontainer: false,
    };
    let daemon = node(&root, &work, &center, true, Some(landlock), Some(false)).await;
    let mut conn = linked(&mut center).await;
    let e = run(&mut conn, "echo ran", &work)
        .await
        .expect_err("refused");
    assert!(
        e.message.contains("cannot keep them off it")
            && e.message.contains("seccomp filters")
            && e.message.contains("nerve-node network on"),
        "{}",
        e.message
    );
    // So is a capability of the config, which runs a command of it.
    let e = invoke(&mut conn, "probe.connect", json!({"port": 1}))
        .await
        .expect_err("refused");
    assert!(
        e.message.contains("cannot keep them off it"),
        "{}",
        e.message
    );
    let d = conn
        .call("describe", json!({"detail": "full"}), WAIT)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(d["access"]["no_network"], "not_held", "{d}");
    assert_eq!(d["access"]["confined"], false, "{d}");
    let folders = d["access"]["folders"].as_array().unwrap();
    assert!(
        folders
            .iter()
            .all(|f| !f["access"].as_str().unwrap().contains('x')),
        "{d}"
    );
    daemon.stop().await;
}

/// The switch holds in every mode, or keeps the commands from running: a
/// node run by hand runs its allowlist and user mode commands as the owner,
/// with nothing around them, so while the network is off it runs none of
/// them and says why, and the descriptor says so; a capability of the
/// config, which stands for `nerve-run` here, still runs, held. In folder
/// mode no command of the sudo list runs while it is off.
#[tokio::test(flavor = "multi_thread")]
async fn commands_that_would_run_as_the_owner_do_not_run_without_network() {
    if !nerve_sandbox::net_filter::available() || !Path::new("/bin/bash").exists() {
        eprintln!("skipped: no seccomp filters or no bash here");
        return;
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    for mode in [Mode::Allowlist, Mode::User] {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let work = root.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let mut center = FakeCenter::start(false).await.unwrap();
        let daemon = node_in(mode, &root, &work, &center, true, None, None, None).await;
        let mut conn = linked(&mut center).await;
        let e = run(&mut conn, "echo ran", &work)
            .await
            .expect_err("refused");
        assert!(
            e.message.contains("runs them as its own user")
                && e.message.contains("nerve-node network on"),
            "{mode:?}: {}",
            e.message
        );
        let d = conn
            .call("describe", json!({"detail": "full"}), WAIT)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(d["access"]["no_network"], "as_owner", "{mode:?}: {d}");
        // A capability of the config is not run as the owner: it runs, held
        // (in user mode, where no allow rule is needed), and its socket is
        // refused.
        if mode == Mode::User {
            let e = invoke(&mut conn, "probe.connect", json!({"port": port}))
                .await
                .expect_err("no connection");
            let stderr = e.data.as_ref().and_then(|d| d["stderr"].as_str());
            assert!(
                stderr.is_some_and(|t| t.contains("socket")),
                "{mode:?}: {e:?}"
            );
        }
        daemon.stop().await;
    }
    let d = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(d.path()).unwrap();
    let work = root.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(&root, &work, &center, true, None, None).await;
    let mut conn = linked(&mut center).await;
    let e = run(&mut conn, "sudo true", &work)
        .await
        .expect_err("refused");
    // A node by hand holds folder mode only with Landlock's rule for unix
    // sockets (ABI 9); below it that refuses every command first.
    let apart = nerve_sandbox::Confinement::detect()
        .landlock_abi
        .is_some_and(|v| v >= nerve_sandbox::LANDLOCK_RESOLVE_UNIX);
    if !apart {
        assert!(
            e.message.contains("runs them as its own user"),
            "{}",
            e.message
        );
        daemon.stop().await;
        return;
    }
    assert!(
        e.message
            .contains("a command on the sudo list runs outside what keeps them off it"),
        "{}",
        e.message
    );
    // Another command still runs.
    let r = run(&mut conn, "echo ran", &work).await.expect("runs");
    assert_eq!(r["stdout"], "ran\n", "{r}");
    daemon.stop().await;
}

/// Sends a command that runs for a minute; returns its call id.
async fn long(conn: &mut Conn<TcpStream>, cwd: &Path) -> u64 {
    let args = json!({"command": "sleep 60", "cwd": cwd.display().to_string()});
    conn.request(
        "invoke",
        json!({"cap": "exec", "action": "run", "args": args, "ctx": {}}),
    )
    .await
    .unwrap()
}

/// A command that started with the network does not keep it when the owner
/// turns the switch off: the node ends it (and says so in the audit log),
/// as it could hand its network to the commands that follow through a socket
/// it listens on. A command that started after the switch is not touched by
/// it going on again, and one that runs when the owner turns the network
/// back on goes on.
#[tokio::test(flavor = "multi_thread")]
async fn a_command_running_when_the_network_goes_off_is_ended() {
    if !Path::new("/bin/bash").exists() || !nerve_sandbox::net_filter::available() {
        eprintln!("skipped: no seccomp filters or no bash here");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(d.path()).unwrap();
    let work = root.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(&root, &work, &center, false, None, None).await;
    let mut conn = linked(&mut center).await;
    let paths = daemon.paths().clone();
    let set = |off: bool| {
        let paths = paths.clone();
        async move {
            nerve_node::cli::edit(&paths, |c| {
                c.centers[0].policy.no_network = off;
                Ok(())
            })
            .await
            .expect("the owner's edit");
        }
    };
    let started = std::time::Instant::now();
    // Switched off while it runs: ended.
    let call = long(&mut conn, &work).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    set(true).await;
    let mut others = Vec::new();
    let r = conn.answer(call, WAIT, &mut others).await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(30), "{r:?}");
    let log = std::fs::read_to_string(daemon.paths().audit_log()).unwrap();
    assert!(
        log.contains("\"killed\"") && log.contains("no_network"),
        "{log}"
    );
    // Back on: the switch going on is what ends commands, not its state.
    set(false).await;
    let call = long(&mut conn, &work).await;
    tokio::time::sleep(Duration::from_secs(8)).await;
    let mut others = Vec::new();
    assert!(
        conn.answer(call, Duration::from_millis(200), &mut others)
            .await
            .is_err_and(|e| e.contains("no answer")),
        "a command with the network was ended"
    );
    set(true).await;
    let r = conn.answer(call, WAIT, &mut others).await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(60), "{r:?}");
    daemon.stop().await;
}

/// The paths of the node that [`node_in`] starts under `root`.
fn paths_in(root: &Path) -> NodePaths {
    NodePaths::new(root.join("config"), root.join("state"))
}

/// A hold that turns the network off for `lab` as the owner does, the first
/// time a command's call is at `at`; it then waits until the link has looked
/// at the change, so what a test sees is the look of the call itself.
fn turns_off_at(paths: NodePaths, at: HoldAt) -> Hold {
    let armed = Arc::new(AtomicBool::new(true));
    Hold::new(move |here| {
        let (paths, armed) = (paths.clone(), armed.clone());
        Box::pin(async move {
            if here == at && armed.swap(false, Ordering::SeqCst) {
                nerve_node::cli::edit(&paths, |c| {
                    c.centers[0].policy.no_network = true;
                    Ok(())
                })
                .await
                .expect("the owner's edit");
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        })
    })
}

/// The owner turns the network off after the node decided a call and before
/// its command starts: the command does not start (it would run without the
/// filter), for a command and for a capability of the config.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_decided_before_the_switch_went_on_does_not_start_after_it() {
    if !Path::new("/bin/bash").exists() || !nerve_sandbox::net_filter::available() {
        eprintln!("skipped: no seccomp filters or no bash here");
        return;
    }
    for capability in [false, true] {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let work = root.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut center = FakeCenter::start(false).await.unwrap();
        let hold = turns_off_at(paths_in(&root), HoldAt::BeforeLastLook);
        let daemon = node_in(
            Mode::Folder,
            &root,
            &work,
            &center,
            false,
            None,
            None,
            Some(hold),
        )
        .await;
        let mut conn = linked(&mut center).await;
        let r = if capability {
            invoke(&mut conn, "probe.connect", json!({"port": port})).await
        } else {
            run(&mut conn, "touch ran", &work).await
        };
        let e = r.expect_err("refused");
        assert_eq!(
            e.message,
            nerve_node::daemon::NETWORK_SWITCHED_ON,
            "capability {capability}"
        );
        assert!(!work.join("ran").exists(), "the command ran");
        daemon.stop().await;
    }
}

/// The owner turns the network off after the last look and before the
/// command is up: the node ends it when it starts, not at its next look at
/// the switch (up to 5 s later), and says so in the audit log.
#[tokio::test(flavor = "multi_thread")]
async fn a_command_that_starts_into_the_switch_is_ended_as_it_starts() {
    if !Path::new("/bin/bash").exists() || !nerve_sandbox::net_filter::available() {
        eprintln!("skipped: no seccomp filters or no bash here");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(d.path()).unwrap();
    let work = root.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let hold = turns_off_at(paths_in(&root), HoldAt::AfterLastLook);
    let daemon = node_in(
        Mode::Folder,
        &root,
        &work,
        &center,
        false,
        None,
        None,
        Some(hold),
    )
    .await;
    let mut conn = linked(&mut center).await;
    let call = long(&mut conn, &work).await;
    let mut others = Vec::new();
    let r = conn.answer(call, WAIT, &mut others).await.unwrap();
    // `sleep 60` was killed: not an exit by itself.
    assert!(r.is_ok_and(|v| v["exit_code"] != 0), "ended by a signal");
    let log = std::fs::read_to_string(daemon.paths().audit_log()).unwrap();
    assert!(
        log.contains("(a command being started)") && log.contains("no_network"),
        "{log}"
    );
    daemon.stop().await;
}

/// Whether process `pid` runs (a zombie does not).
fn alive(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| {
        s.rsplit_once(')')
            .is_some_and(|(_, rest)| !rest.trim_start().starts_with('Z'))
    })
}

/// Waits up to `within` for process `pid` to end.
async fn ends(pid: u32, within: Duration) -> bool {
    let until = std::time::Instant::now() + within;
    while std::time::Instant::now() < until {
        if !alive(pid) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    !alive(pid)
}

/// Accepts the node's link with the handshake of a center that can resume
/// links, and offers no resume of an earlier one.
async fn resumable(center: &mut FakeCenter) -> Conn<TcpStream> {
    let paired = center.paired().expect("paired");
    let mut inc = center.next_link(WAIT).await.expect("the node dials");
    fake_center::hello(&mut inc.conn, &center.center_id, &paired)
        .await
        .expect("hello");
    fake_center::welcome(
        &mut inc.conn,
        Some(nerve_proto::msg::Resumed {
            resumed: false,
            got: 0,
        }),
    )
    .await
    .expect("welcome");
    inc.conn
}

/// A command of a link that dropped, which the center may still resume, is
/// ended when the owner turns the network off, not when the link comes back
/// or its grace (30 s) ends: the node does it while it waits to dial again
/// and while it waits for the center's answer to a dial.
#[tokio::test(flavor = "multi_thread")]
async fn a_command_of_a_dropped_link_is_ended_when_the_network_goes_off() {
    if !Path::new("/bin/bash").exists() || !nerve_sandbox::net_filter::available() {
        eprintln!("skipped: no seccomp filters or no bash here");
        return;
    }
    // The node waits 0.9 to 1 s before it dials again, and after that it
    // waits for the center, which this test never answers. The command must
    // end at once, before the node's next step would look after it: the
    // time from the drop it has is what tells the two places apart.
    for (what, after, by) in [
        (
            "waiting to dial",
            Duration::from_millis(50),
            Duration::from_millis(800),
        ),
        (
            "waiting for the center",
            Duration::from_millis(2500),
            Duration::from_millis(5500),
        ),
    ] {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let work = root.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let mut center = FakeCenter::start(false).await.unwrap();
        let daemon = node(&root, &work, &center, false, None, None).await;
        let mut conn = resumable(&mut center).await;
        let args = json!({"command": "sleep 60 & echo $! > sleep.pid; wait",
                          "cwd": work.display().to_string()});
        conn.request(
            "invoke",
            json!({"cap": "exec", "action": "run", "args": args, "ctx": {}}),
        )
        .await
        .unwrap();
        let mut pid = None;
        for _ in 0..200 {
            if let Ok(t) = std::fs::read_to_string(work.join("sleep.pid"))
                && let Ok(n) = t.trim().parse::<u32>()
            {
                pid = Some(n);
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let pid = pid.expect("the command started");
        drop(conn);
        let dropped = std::time::Instant::now();
        tokio::time::sleep(after).await;
        assert!(alive(pid), "the command went with the link, {what}");
        nerve_node::cli::edit(daemon.paths(), |c| {
            c.centers[0].policy.no_network = true;
            Ok(())
        })
        .await
        .expect("the owner's edit");
        let within = by.saturating_sub(dropped.elapsed());
        assert!(
            ends(pid, within).await,
            "the command of a dropped link, {what}"
        );
        daemon.stop().await;
    }
}
