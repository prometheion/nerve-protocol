//! The owner's network switch for a pairing's folder-mode commands
//! (`folder network off`, docs/user/modes.md) on a real node daemon, in
//! process and run by hand: a command of that pairing, and a capability of
//! the config it calls, opens no TCP connection and no UDP socket, which it
//! opens without the switch, held by the node's seccomp filter whether or
//! not the kernel's Landlock has its network rules; where the node cannot
//! hold it to that (told here that it has no filter) it runs none of that
//! pairing's folder-mode commands and says why. Linux only, as the filter
//! is.
#![cfg(target_os = "linux")]

use std::path::Path;
use std::time::Duration;

use nerve_conformance::fake_center::{self, FakeCenter};
use nerve_conformance::wire::Conn;
use nerve_node::{Daemon, NodeOptions, NodePaths};
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

/// Pairs with `center` as `lab` in folder mode, with `work` to run in and
/// the network switch `off`, and starts the daemon as `confinement` and
/// `filter` say (`None`: the kernel's own).
async fn node(
    root: &Path,
    work: &Path,
    center: &FakeCenter,
    off: bool,
    confinement: Option<nerve_sandbox::Confinement>,
    filter: Option<bool>,
) -> Daemon {
    let mut o = NodeOptions::new(NodePaths::new(root.join("config"), root.join("state")));
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
        p.mode = Mode::Folder;
        p.no_network = off;
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

async fn linked(center: &mut FakeCenter) -> Conn<TcpStream> {
    let paired = center.paired().expect("paired");
    let mut inc = center.next_link(WAIT).await.expect("the node dials");
    fake_center::handshake(&mut inc.conn, &center.center_id, &paired)
        .await
        .expect("handshake");
    inc.conn
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
/// this machine that it reaches without it, nor open a UDP socket, also
/// where the kernel's Landlock is taken to have no network rules (ABI 3,
/// a node by hand's floor), and the descriptor tells the center that its
/// commands have no network.
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
            d["access"].get("no_network").is_some_and(|v| v == true),
            off,
            "{d}"
        );
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
            && e.message.contains("nerve-node folder network on"),
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
    assert_eq!(d["access"]["no_network"], true, "{d}");
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
