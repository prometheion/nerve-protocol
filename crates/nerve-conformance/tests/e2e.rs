//! End-to-end tests: the real `nerve-center` and `nerve-node` binaries, against
//! the conformance parts and against each other.

#![cfg(unix)]

mod common;

use std::future::Future;
use std::time::{Duration, Instant};

use common::{HttpCenter, Mcp, Node, text_of};
use nerve_conformance::harness_part::{self, Target};
use nerve_conformance::{center_part, node_part};
use nerve_proto::link::PairLink;
use nerve_transport::sudo::{Offer, seal};
use serde_json::{Value, json};

fn block_on<F: Future>(f: F) -> F::Output {
    nerve_transport::init_crypto();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

fn center_part_against(tls: bool) {
    let state = tempfile::tempdir().unwrap();
    let mcp = Mcp::start(state.path(), tls, &[]);
    let link = PairLink::parse(&mcp.pair_link()).unwrap();
    assert_eq!(link.pin.is_some(), tls);
    let report = block_on(center_part::run(&link));
    assert!(report.ok(), "{report}");
    assert!(
        mcp.finish(),
        "nerve-center did not exit after its harness left"
    );
}

#[test]
fn center_part_passes_against_nerve_center_over_plain_loopback() {
    center_part_against(false);
}

#[test]
fn center_part_passes_against_nerve_center_over_pinned_tls() {
    center_part_against(true);
}

#[test]
fn harness_part_passes_against_nerve_center() {
    let state = tempfile::tempdir().unwrap();
    let center = HttpCenter::start(state.path(), "e2e-harness-token");
    let target = Target {
        mcp_addr: center.mcp_addr.clone(),
        token: center.token.clone(),
        links: [(); 2].map(|_| PairLink::parse(&center.ui.pair_link()).unwrap()),
        call_wait: HttpCenter::CALL_WAIT,
    };
    let report = block_on(harness_part::run(&target));
    assert!(report.ok(), "{report}");
    // Every check ran; a count that shrinks silently would hide a lost check.
    assert_eq!(report.outcomes.len(), 45, "{report}");
}

fn with(mut args: Value, more: Value) -> Value {
    for (k, v) in more.as_object().unwrap() {
        args[k] = v.clone();
    }
    args
}

const SUDO_PW: &str = "e2e-right-sudo-pw";

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Fails when a file below `dir` contains `secret`.
fn assert_no_file_holds(dir: &std::path::Path, secret: &str) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            assert_no_file_holds(&p, secret);
        } else if let Ok(bytes) = std::fs::read(&p) {
            let found = bytes.windows(secret.len()).any(|w| w == secret.as_bytes());
            // The fake sudo script names the right password, as /etc/shadow
            // would hold its hash.
            assert!(
                !found || p.ends_with("fake-sudo"),
                "{} holds it",
                p.display()
            );
        }
    }
}

/// The whole path through both binaries: pairing, the link, tools, the
/// the sudo switch relayed by the center, a folder and a rule on the node
/// deciding calls (allowed at once, or
/// refused at once), a rule from the audit view landing in the node's
/// settings, the node's audit log, and removing the node.
#[test]
fn nerve_center_and_nerve_node_work_together() {
    let root = tempfile::tempdir().unwrap();
    let mut mcp = Mcp::start(&root.path().join("center"), true, &[]);
    let mut node = Node::new(&root.path().join("node"));

    // Pairing from the web UI's link, confirmed on the node.
    let link = mcp.pair_link();
    let out = node.ok(&["center", "add", &link, "--yes"]);
    assert!(out.contains("e2e-center"), "{out}");
    assert!(node.ok(&["center", "ls"]).contains("e2e-center"));
    // A new pairing is in folder mode; the steps below start from allowlist.
    assert!(node.ok(&["center", "ls"]).contains("folder"));
    node.ok(&["mode", "set", "allowlist"]);
    node.use_fake_sudo(SUDO_PW);
    node.start();
    let ov = mcp.wait_overview("the node comes online", |v| {
        v["nodes"][0]["online"] == json!(true)
            && v["nodes"][0]["capabilities"]
                .as_array()
                .is_some_and(|c| !c.is_empty())
    });
    let node_id = ov["nodes"][0]["id"].as_str().unwrap().to_string();
    let node_name = ov["nodes"][0]["name"].as_str().unwrap().to_string();
    assert_eq!(ov["nodes"][0]["settings_write"], json!(false), "{ov}");

    // Capabilities: none for files and commands while no allow rule could
    // let a call through, and never one for the node's settings.
    let offered = mcp.offered(&node_name);
    assert!(!offered.iter().any(|n| n == "fs.read"), "{offered:?}");
    assert!(!offered.iter().any(|n| n == "exec.run"), "{offered:?}");
    assert!(
        !offered.iter().any(|n| n.starts_with("settings.")),
        "{offered:?}"
    );

    // The settings grant, given on the node, reaches the center.
    node.ok(&["center", "grant", "settings", "write"]);
    mcp.wait_overview("the settings grant reaches the center", |v| {
        v["nodes"][0]["settings_write"] == json!(true)
    });
    let (status, v) = mcp.api(
        "GET",
        &format!("/api/nodes/settings?id={node_id}"),
        Value::Null,
    );
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["sudo"], "off", "{v}");

    // The sudo switch from the web UI: the center checks that the node
    // signed the offer and relays a password sealed for it. The browser
    // seals; here the test does.
    let sealed_for = |mcp: &mut Mcp, password: &str| {
        let (status, v) = mcp.api("POST", "/api/nodes/sudo/offer", json!({"id": node_id}));
        assert_eq!(status, 200, "{v}");
        let offer: Offer = serde_json::from_value(v).unwrap();
        seal(&offer, password, now_ms()).unwrap()
    };
    let wrong = sealed_for(&mut mcp, "wrong");
    let (status, v) = mcp.api(
        "POST",
        "/api/nodes/sudo",
        json!({"id": node_id, "on": true, "sealed": wrong}),
    );
    assert_eq!(status, 409, "{v}");
    assert!(
        v["error"].as_str().unwrap().contains("password is wrong"),
        "{v}"
    );
    let right = sealed_for(&mut mcp, SUDO_PW);
    let (status, v) = mcp.api(
        "POST",
        "/api/nodes/sudo",
        json!({"id": node_id, "on": true, "sealed": right}),
    );
    assert_eq!((status, &v["sudo"]), (200, &json!("on")), "{v}");
    // The node says so too. Running sudo commands is the node part's and
    // nerve-node's own tests' job.
    let (_, v) = mcp.api(
        "GET",
        &format!("/api/nodes/settings?id={node_id}"),
        Value::Null,
    );
    assert_eq!(v["sudo"], "on", "{v}");
    assert!(node.ok(&["sudo", "status"]).contains("on"));
    let (status, v) = mcp.api(
        "POST",
        "/api/nodes/sudo",
        json!({"id": node_id, "on": false}),
    );
    assert_eq!((status, &v["sudo"]), (200, &json!("off")), "{v}");
    assert!(node.ok(&["sudo", "status"]).contains("off"));
    // Neither the center's files nor the node's hold the password.
    assert_no_file_holds(root.path(), SUDO_PW);

    // The four buttons of the audit view, for a command, a path and another
    // action: each one adds a rule to its list on the node and takes none off.
    let center_policy = format!("center.{}.policy", "e2e-center");
    let list =
        |name: &str| -> String { node.ok(&["config", "get", &format!("{center_policy}.{name}")]) };
    let button = |mcp: &Mcp, body: Value| mcp.api("POST", "/api/audit/rule", body);
    let click = |mcp: &Mcp, list: &str, cap: &str, action: &str, target: &str, wildcard: bool| {
        let (status, v) = button(
            mcp,
            json!({"node_id": node_id, "list": list, "cap": cap, "action": action,
                   "target": target, "wildcard": wildcard}),
        );
        assert_eq!(status, 200, "{v}");
        v["rule"].as_str().unwrap().to_string()
    };
    assert_eq!(
        click(&mcp, "allow", "exec", "run", "echo hi", false),
        "exec.run:echo hi"
    );
    assert_eq!(
        click(&mcp, "allow", "exec", "run", "echo hi", true),
        "exec.run:echo *"
    );
    assert_eq!(
        click(&mcp, "deny", "exec", "run", "rm -rf x", false),
        "exec.run:rm -rf x"
    );
    assert_eq!(
        click(&mcp, "deny", "exec", "run", "rm -rf x", true),
        "exec.run:rm *"
    );
    assert_eq!(
        click(&mcp, "allow", "fs", "read", "/nerve-e2e/a.txt", false),
        "fs.read:/nerve-e2e/a.txt"
    );
    assert_eq!(
        click(&mcp, "deny", "fs", "write", "/nerve-e2e/a.txt", true),
        "fs.write:/nerve-e2e/*"
    );
    // No provider offers `camera` on this node, so it may sense for all the
    // node knows: only the owner allows it. A deny rule is anyone's.
    let (status, v) = button(
        &mcp,
        json!({"node_id": node_id, "list": "allow", "cap": "camera", "action": "snap",
               "target": "camera.snap", "wildcard": false}),
    );
    assert_ne!(status, 200, "{v}");
    assert!(
        v.to_string().contains("only the owner can turn sensing on"),
        "{v}"
    );
    assert_eq!(
        click(&mcp, "deny", "camera", "snap", "camera.snap", true),
        "camera"
    );
    assert_eq!(
        click(&mcp, "sudo", "exec", "run", "sudo apt update", false),
        "sudo apt update"
    );
    assert_eq!(
        click(&mcp, "sudo", "exec", "run", "sudo apt update", true),
        "sudo apt *"
    );
    // A repeat adds nothing.
    click(&mcp, "allow", "exec", "run", "echo hi", false);
    let allow = list("allow");
    for want in [
        "exec.run:echo hi",
        "exec.run:echo *",
        "fs.read:/nerve-e2e/a.txt",
    ] {
        assert!(allow.contains(want), "{allow}");
    }
    assert!(!allow.contains("camera"), "{allow}");
    assert_eq!(allow.matches("exec.run:echo hi").count(), 1, "{allow}");
    assert!(!allow.contains("rm"), "{allow}");
    let deny = list("deny");
    for want in [
        "exec.run:rm -rf x",
        "exec.run:rm *",
        "fs.write:/nerve-e2e/*",
        "camera",
    ] {
        assert!(deny.contains(want), "{deny}");
    }
    assert!(!deny.contains("echo"), "{deny}");
    let sudo = list("sudo_allow");
    assert!(
        sudo.contains("sudo apt update") && sudo.contains("sudo apt *"),
        "{sudo}"
    );
    // A bad list, a missing target and a sudo list for a plain command are
    // refused before the node sees them.
    for body in [
        json!({"list": "permit", "cap": "exec", "action": "run", "target": "ls"}),
        json!({"list": "allow", "cap": "exec", "action": "run", "target": " "}),
        json!({"list": "allow", "cap": "exec", "action": "run"}),
        json!({"list": "allow", "cap": "fs", "action": "read", "target": "relative"}),
        json!({"list": "sudo", "cap": "exec", "action": "run", "target": "ls"}),
        json!({"list": "sudo", "cap": "fs", "action": "read", "target": "/a"}),
        json!({"list": "allow", "cap": "", "action": "run", "target": "ls"}),
    ] {
        let body = with(body, json!({"node_id": node_id}));
        let (status, v) = button(&mcp, body.clone());
        assert_eq!(status, 400, "{body} {v}");
    }
    assert_eq!(list("allow"), allow);

    // The allow rules above made the capabilities appear: the node
    // announced a new descriptor and the center lists them.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let offered = mcp.offered(&node_name);
        let has = |unit: &str| offered.iter().any(|n| n == unit);
        if has("fs.read") && has("exec.run") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the capabilities did not appear: {offered:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    // exec.run goes straight to the node: the center holds no call back, and
    // the node lets it run (the allow rule above).
    let r = mcp.run(&node_name, "exec.run", json!({"command": "echo hi"}));
    let text = text_of(&r);
    assert_eq!(r["isError"], json!(false), "{r}");
    assert!(
        text.contains("hi") && text.contains("device content"),
        "{text}"
    );

    // fs.read: nothing is allowed until a rule or a mode allows it, and a
    // call no rule allows is refused at once instead of waiting for anybody.
    std::fs::write(node.home.join("notes.txt"), "hello from the node").unwrap();
    let path = node.home.join("notes.txt").to_string_lossy().to_string();
    let started = Instant::now();
    let r = mcp.run(&node_name, "fs.read", json!({"path": path}));
    assert!(started.elapsed() < Duration::from_secs(10), "{r}");
    assert_eq!(r["isError"], json!(true), "{r}");
    assert!(text_of(&r).contains("forbidden"), "{r}");

    // A folder counts in folder mode only: in default deny it allows nothing.
    node.ok(&["folder", "add", &node.home.to_string_lossy(), "+r"]);
    let r = mcp.run(&node_name, "fs.read", json!({"path": path}));
    assert_eq!(r["isError"], json!(true), "{r}");
    node.ok(&["mode", "set", "folder"]);
    let r = mcp.run(&node_name, "fs.read", json!({"path": path}));
    assert_eq!(r["isError"], json!(false), "{r}");
    assert!(text_of(&r).contains("hello from the node"), "{r}");

    // A file outside every folder is refused at once.
    let outside = root.path().join("outside.txt");
    std::fs::write(&outside, "not for the model").unwrap();
    let r = mcp.run(
        &node_name,
        "fs.read",
        json!({"path": outside.to_string_lossy()}),
    );
    assert_eq!(r["isError"], json!(true), "{r}");
    assert!(text_of(&r).contains("forbidden"), "{r}");
    assert!(!text_of(&r).contains("not for the model"), "{r}");

    // The node's own audit log has the decisions.
    let audit = node.ok(&["audit"]);
    assert!(
        audit.contains("exec.run") && audit.contains("allowed"),
        "{audit}"
    );
    assert!(
        audit.contains("fs.read") && audit.contains("forbidden"),
        "{audit}"
    );
    let denied = node.ok(&["audit", "--denied"]);
    assert!(!denied.contains("exec.run"), "{denied}");

    // The center's statistics count the calls; nothing of their content.
    let (_, stats) = mcp.api("GET", "/api/stats", Value::Null);
    assert!(
        !stats.to_string().contains("hello from the node"),
        "{stats}"
    );

    // Removing the node from the web UI: it is no longer listed, and the
    // node stops.
    let (status, v) = mcp.api("POST", "/api/nodes/remove", json!({"id": node_id}));
    assert_eq!(status, 200, "{v}");
    mcp.wait_overview("the node is gone", |v| {
        v["nodes"].as_array().is_some_and(|n| n.is_empty())
    });
    let listed = mcp.list(json!({}));
    assert_eq!(
        listed["structuredContent"]["result"]["nodes"],
        json!([]),
        "{listed}"
    );
    assert!(mcp.offered(&node_name).is_empty());
    let status = node.ok(&["status"]);
    assert!(
        status.contains("revoked") || status.contains("unknown") || status.contains("stopped"),
        "{status}"
    );
    assert!(!node.daemon_exited(), "the daemon itself keeps running");
    assert!(mcp.finish());
}

/// Whether process `pid` still runs (a zombie does not count).
#[cfg(target_os = "linux")]
fn running(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| {
        s.rsplit_once(')')
            .is_some_and(|(_, rest)| !rest.trim_start().starts_with('Z'))
    })
}

/// Waits up to `secs` for `f`.
fn within(secs: u64, mut f: impl FnMut() -> bool) -> bool {
    let until = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < until {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// A command stops when its MCP call is cancelled and when its session is
/// ended in the web UI, within a few seconds, without a timeout.
#[cfg(target_os = "linux")]
#[test]
fn a_cancelled_call_and_an_ended_session_stop_their_command() {
    let root = tempfile::tempdir().unwrap();
    let mut mcp = Mcp::start(&root.path().join("center"), false, &[]);
    let mut node = Node::new(&root.path().join("node"));
    node.ok(&["center", "add", &mcp.pair_link(), "--yes"]);
    node.ok(&["mode", "set", "user"]);
    node.start();
    let ov = mcp.wait_overview("the node is online", |v| {
        v["nodes"][0]["online"] == json!(true)
    });
    let name = ov["nodes"][0]["name"].as_str().unwrap().to_string();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let offered = mcp.offered(&name);
        if offered.iter().any(|n| n == "exec.run") {
            break;
        }
        assert!(Instant::now() < deadline, "no exec.run: {offered:?}");
        std::thread::sleep(Duration::from_millis(100));
    }
    let start = |mcp: &mut Mcp, id: &str| -> u32 {
        let file = node.home.join(format!("{id}.pid"));
        let command = format!("sleep 30 & echo $! > {}; wait", file.display());
        let params = mcp.run_params(&name, "exec.run", json!({"command": command}));
        mcp.send(id, "tools/call", params);
        let mut pid = 0;
        assert!(
            within(15, || {
                pid = std::fs::read_to_string(&file)
                    .ok()
                    .and_then(|t| t.trim().parse().ok())
                    .unwrap_or(0);
                pid != 0
            }),
            "the command did not start"
        );
        pid
    };

    let pid = start(&mut mcp, "cancelled-call");
    mcp.notify(
        "notifications/cancelled",
        json!({"requestId": "cancelled-call"}),
    );
    assert!(
        within(5, || !running(pid)),
        "a cancelled call's command runs on"
    );

    let pid = start(&mut mcp, "ended-session");
    let ov = mcp.wait_overview("the session is listed", |v| {
        v["sessions"].as_array().is_some_and(|s| !s.is_empty())
    });
    let session = ov["sessions"][0]["id"].as_str().unwrap().to_string();
    let (status, v) = mcp.api("POST", "/api/sessions/end", json!({"id": session}));
    assert_eq!(status, 200, "{v}");
    assert!(
        within(5, || !running(pid)),
        "an ended session's command runs on"
    );
    assert!(mcp.finish());
}

/// A command that runs past the call wait becomes a job between the real
/// binaries: `execute` answers its id at once, `exec.signal` names the job,
/// `job.status` gives the result with the signal, and `job.cancel` ends
/// another one; no process is left.
#[cfg(target_os = "linux")]
#[test]
fn a_long_command_becomes_a_job_that_exec_signal_and_job_cancel_end() {
    let root = tempfile::tempdir().unwrap();
    let mut mcp = Mcp::start(
        &root.path().join("center"),
        false,
        &[("NERVE_CALL_WAIT", "1")],
    );
    let mut node = Node::new(&root.path().join("node"));
    node.ok(&["center", "add", &mcp.pair_link(), "--yes"]);
    node.ok(&["mode", "set", "user"]);
    // `exec.signal` actuates: the owner turns it on.
    node.ok(&["cap", "set", "exec.signal", "on"]);
    node.start();
    let ov = mcp.wait_overview("the node is online", |v| {
        v["nodes"][0]["online"] == json!(true)
    });
    let name = ov["nodes"][0]["name"].as_str().unwrap().to_string();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let offered = mcp.offered(&name);
        if ["exec.run", "exec.signal", "job.status", "job.cancel"]
            .iter()
            .all(|u| offered.iter().any(|n| n == u))
        {
            break;
        }
        assert!(Instant::now() < deadline, "not offered: {offered:?}");
        std::thread::sleep(Duration::from_millis(100));
    }
    let start = |mcp: &mut Mcp, id: &str| -> (String, u32) {
        let file = node.home.join(format!("{id}.pid"));
        let command = format!("sleep 30 & echo $! > {}; wait", file.display());
        let started = Instant::now();
        let r = mcp.run(&name, "exec.run", json!({"command": command}));
        assert!(started.elapsed() < Duration::from_secs(10), "it waited");
        assert_eq!(r["structuredContent"]["state"], "running", "{r}");
        let job = r["structuredContent"]["job"].as_str().unwrap().to_string();
        let mut pid = 0;
        assert!(
            within(15, || {
                pid = std::fs::read_to_string(&file)
                    .ok()
                    .and_then(|t| t.trim().parse().ok())
                    .unwrap_or(0);
                pid != 0
            }),
            "the command did not start"
        );
        (job, pid)
    };
    let status = |mcp: &mut Mcp, job: &str| {
        mcp.call(
            "execute",
            json!({"node": name, "capability": "job.status",
                   "args": {"job": job, "wait_ms": 1000}}),
        )
    };

    let (job, pid) = start(&mut mcp, "signalled");
    assert!(running(pid));
    let r = mcp.run(&name, "exec.signal", json!({"job": job, "signal": "term"}));
    assert_ne!(r["isError"], true, "{r}");
    assert!(within(5, || !running(pid)), "the signalled command runs on");
    let deadline = Instant::now() + Duration::from_secs(15);
    let done = loop {
        let r = status(&mut mcp, &job);
        if r["structuredContent"]["state"] != "running" {
            break r;
        }
        assert!(Instant::now() < deadline, "the job did not end: {r}");
    };
    assert_ne!(done["isError"], true, "{done}");
    assert_eq!(
        done["structuredContent"]["center"],
        json!({"job": job, "state": "done"}),
        "{done}"
    );
    assert_eq!(
        done["structuredContent"]["result"]["signal"], "term",
        "{done}"
    );

    let (job, pid) = start(&mut mcp, "cancelled");
    let r = mcp.call(
        "execute",
        json!({"node": name, "capability": "job.cancel", "args": {"job": job}}),
    );
    assert_eq!(
        r["structuredContent"],
        json!({"job": job, "state": "cancelled"}),
        "{r}"
    );
    assert!(within(5, || !running(pid)), "the cancelled command runs on");
    assert!(text_of(&status(&mut mcp, &job)).starts_with("error unknown_job: "));
    assert!(mcp.finish());
}

/// A TCP relay between the node and the center whose connections the test
/// can cut, as an address change does.
#[cfg(target_os = "linux")]
struct Relay {
    port: u16,
    target: std::sync::Arc<std::sync::Mutex<u16>>,
    open: std::sync::Arc<std::sync::Mutex<Vec<std::net::TcpStream>>>,
}

#[cfg(target_os = "linux")]
impl Relay {
    fn start() -> Relay {
        use std::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let target = std::sync::Arc::new(std::sync::Mutex::new(0u16));
        let open = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (t, o) = (target.clone(), open.clone());
        std::thread::spawn(move || {
            for near in listener.incoming().map_while(Result::ok) {
                let Ok(far) = TcpStream::connect(("127.0.0.1", *t.lock().unwrap())) else {
                    continue;
                };
                let mut open = o.lock().unwrap();
                open.push(near.try_clone().unwrap());
                open.push(far.try_clone().unwrap());
                for (mut from, mut to) in [
                    (near.try_clone().unwrap(), far.try_clone().unwrap()),
                    (far, near),
                ] {
                    std::thread::spawn(move || {
                        let _ = std::io::copy(&mut from, &mut to);
                        let _ = to.shutdown(std::net::Shutdown::Both);
                    });
                }
            }
        });
        Relay { port, target, open }
    }

    /// Cuts every connection through the relay; new ones still pass.
    fn cut(&self) {
        for s in self.open.lock().unwrap().drain(..) {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    }
}

/// The link between the real binaries drops while a command runs (spec
/// §4.9): both sides keep the link, the node dials again and resumes it,
/// and the command's output, made while the link was down, reaches the
/// harness.
#[cfg(target_os = "linux")]
#[test]
fn a_command_survives_a_dropped_link() {
    let root = tempfile::tempdir().unwrap();
    let relay = Relay::start();
    let url = format!("http://127.0.0.1:{}", relay.port);
    let mut mcp = Mcp::start(
        &root.path().join("center"),
        false,
        &[("NERVE_PUBLIC_URL", &url)],
    );
    *relay.target.lock().unwrap() = mcp.node_port;
    let mut node = Node::new(&root.path().join("node"));
    node.ok(&["center", "add", &mcp.pair_link(), "--yes"]);
    node.ok(&["mode", "set", "user"]);
    node.start();
    let ov = mcp.wait_overview("the node is online", |v| {
        v["nodes"][0]["online"] == json!(true)
    });
    let name = ov["nodes"][0]["name"].as_str().unwrap().to_string();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let offered = mcp.offered(&name);
        if offered.iter().any(|n| n == "exec.run") {
            break;
        }
        assert!(Instant::now() < deadline, "no exec.run: {offered:?}");
        std::thread::sleep(Duration::from_millis(100));
    }
    let (started, go) = (node.home.join("started"), node.home.join("go"));
    let command = format!(
        "touch {}; while [ ! -e {} ]; do sleep 0.05; done; echo resumed-output",
        started.display(),
        go.display()
    );
    let params = mcp.run_params(&name, "exec.run", json!({"command": command}));
    mcp.send("run", "tools/call", params);
    assert!(within(15, || started.exists()), "the command did not start");

    relay.cut();
    // The command ends while the link is down.
    std::thread::sleep(Duration::from_millis(200));
    std::fs::write(&go, "").unwrap();
    let r = mcp.reply("run", Duration::from_secs(30));
    let text = r["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert_ne!(r["result"]["isError"], true, "{r}");
    assert!(text.contains("resumed-output"), "{r}");
    mcp.wait_overview("the node is online again", |v| {
        v["nodes"][0]["online"] == json!(true)
    });
    assert!(mcp.finish());
}

/// The node part of the conformance runner against the real binary.
#[test]
fn node_part_passes_against_nerve_node() {
    let root = tempfile::tempdir().unwrap();
    let node = std::sync::Arc::new(std::sync::Mutex::new(Node::new(root.path())));
    let n = node.clone();
    let report = block_on(node_part::run(move |link: PairLink| async move {
        let link = link.render();
        let node = n;
        tokio::task::spawn_blocking(move || {
            let mut node = node.lock().unwrap();
            let (ok, out, err) = node.cli(&["center", "add", &link, "--yes"]);
            if !ok {
                return Err(format!("pair failed: {out}{err}"));
            }
            // The profile checks write the policy through settings.set and
            // try one wrong sudo password: on a fake sudo, not this machine's.
            let (ok, out, err) = node.cli(&["center", "grant", "settings", "write"]);
            if !ok {
                return Err(format!("grant failed: {out}{err}"));
            }
            let password = "conformance-right-password";
            node.use_fake_sudo(password);
            let folder = node.home.join("work");
            std::fs::create_dir_all(&folder).unwrap();
            node.start();
            Ok(node_part::Setup {
                folder: Some(folder.display().to_string()),
                sudo_password: Some(password.into()),
            })
        })
        .await
        .map_err(|e| e.to_string())?
    }));
    assert!(report.ok(), "{report}");
    let profiles = report
        .outcomes
        .iter()
        .filter(|o| o.section.starts_with('7'));
    assert_eq!(profiles.count(), 19, "{report}");
    drop(node);
}

/// The provider part against the real `nerve-node`: this test program
/// attaches as the provider the owner allowed with `config add`.
#[cfg(target_os = "linux")]
#[test]
fn provider_part_passes_against_nerve_node() {
    use nerve_conformance::provider_part;
    let root = tempfile::tempdir().unwrap();
    let node = std::sync::Arc::new(std::sync::Mutex::new(Node::new(root.path())));
    let n = node.clone();
    let report = block_on(provider_part::run(move |link: PairLink| async move {
        let link = link.render();
        tokio::task::spawn_blocking(move || {
            let mut node = n.lock().unwrap();
            let (ok, out, err) = node.cli(&["center", "add", &link, "--yes"]);
            if !ok {
                return Err(format!("pair failed: {out}{err}"));
            }
            let (ok, out, err) = node.cli(&["center", "grant", "settings", "write"]);
            if !ok {
                return Err(format!("grant failed: {out}{err}"));
            }
            let exe = std::env::current_exe().unwrap();
            let entry = format!("{{ name = \"conformance\", exe = \"{}\" }}", exe.display());
            let (ok, out, err) = node.cli(&["config", "add", "providers.allowed", &entry]);
            if !ok {
                return Err(format!("allowing the provider failed: {out}{err}"));
            }
            node.start();
            Ok(provider_part::Setup {
                socket: node.state.join("run").join("ctl.sock"),
                provider: "conformance".into(),
            })
        })
        .await
        .map_err(|e| e.to_string())?
    }));
    assert!(report.ok(), "{report}");
    // Every check ran; a count that shrinks silently would hide a lost check.
    assert_eq!(report.outcomes.len(), 14, "{report}");
    assert_eq!(provider_part::CHECKS.len(), 14);
    drop(node);
}

/// Key rotation through both binaries over pinned TLS
/// (docs/dev/spec/protocol.md §4.10): the node rotates its key and ends the
/// grace of the old one, the center rotates its own and serves it after its
/// grace, and the node links on through both without pairing again.
#[test]
fn both_keys_rotate_without_pairing_again() {
    let root = tempfile::tempdir().unwrap();
    let mcp = Mcp::start(&root.path().join("center"), true, &[]);
    let mut node = Node::new(&root.path().join("node"));
    node.ok(&["center", "add", &mcp.pair_link(), "--yes"]);
    node.start();
    let online = |v: &Value| v["nodes"][0]["online"] == json!(true);
    let ov = mcp.wait_overview("the node comes online", online);
    let node_id = ov["nodes"][0]["id"].clone();
    let old_pin = ov["center"]["pin"].as_str().unwrap().to_string();

    // The node's key: the center takes the new one and the old one for the
    // grace, which the owner then ends.
    let out = node.ok(&["center", "rotate-key"]);
    assert!(out.contains("took this machine's new key"), "{out}");
    let new_key = out.lines().nth(1).unwrap().trim().to_string();
    assert_eq!(new_key.len(), 64, "{out}");
    let ov = mcp.wait_overview("the old key has a grace", |v| {
        v["nodes"][0]["key_grace_until_ms"].is_u64()
    });
    let since = ov["nodes"][0]["since_ms"].clone();
    let out = node.ok(&["center", "rotate-key", "--end-grace"]);
    assert!(out.contains(&new_key), "{out}");
    // The link the old key opened ends; the node links again with its new
    // key, under the same id.
    let ov = mcp.wait_overview("the node links with its new key", |v| {
        online(v)
            && v["nodes"][0]["since_ms"] != since
            && v["nodes"][0]["key_grace_until_ms"].is_null()
    });
    assert_eq!(ov["nodes"][0]["id"], node_id);

    // The center's key: the node is told and pins the new key beside the
    // old one; at the end of the grace only the new one.
    let (status, r) = mcp.api("POST", "/api/center/key/rotate", Value::Null);
    assert_eq!(status, 200, "{r}");
    let new_pin = r["pin"].as_str().unwrap().to_string();
    assert_ne!(new_pin, old_pin);
    let toml = node.config.join("node.toml");
    let read = || std::fs::read_to_string(&toml).unwrap();
    assert!(
        within(30, || read().contains(&new_pin)
            && read().contains(&old_pin)),
        "{}",
        read()
    );
    let (status, r) = mcp.api("POST", "/api/center/key/finish", Value::Null);
    assert_eq!(status, 200, "{r}");
    assert_eq!(r["pin"], new_pin.as_str());
    assert!(within(30, || !read().contains(&old_pin)), "{}", read());
    // A new start of the node links over the new key.
    node.stop();
    mcp.wait_overview("the node is gone", |v| {
        v["nodes"][0]["online"] == json!(false)
    });
    node.start();
    mcp.wait_overview("the node links over the new key", online);
    let audit = node.ok(&["audit"]);
    for event in [
        "key node-key:",
        "key node-key-grace-ended:",
        "key center-key:",
    ] {
        assert!(audit.contains(event), "{event}: {audit}");
    }
}
