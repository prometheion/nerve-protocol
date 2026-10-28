//! Capabilities of the config (`[[capability]]`, docs/user/config-capabilities.md)
//! on a real node daemon, in process: the node offers them by its platform
//! and by the effect table, decides and audits each call like any other, and
//! runs the owner's command itself with the call's arguments as whole
//! arguments, never through a shell. They run as `nerve-run`, which a node
//! run by hand does not have, so it offers none; here the node by hand
//! stands for it with its own user (NodeOptions::config_caps_by_hand), and
//! the installed node's runs as `nerve-run` are in real_account.rs. Linux
//! only: Windows reads them and offers none yet.
#![cfg(target_os = "linux")]

use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nerve_conformance::fake_center::{self, FakeCenter};
use nerve_conformance::wire::{Conn, code_of};
use nerve_node::{Daemon, NodeOptions, NodePaths};
use nerve_policy::NodeConfig;
use nerve_policy::config::{AllowedProvider, CapSetting, ConfigCapability, SettingsGrant};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixStream};

const WAIT: Duration = Duration::from_secs(15);

fn scratch() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn options(root: &Path) -> NodeOptions {
    let mut o = NodeOptions::new(NodePaths::new(root.join("config"), root.join("state")));
    o.home = root.join("home");
    std::fs::create_dir_all(&o.home).unwrap();
    // Not the rights of whoever runs the tests: an elevated run must pass.
    o.full_rights = Some(false);
    o.exe = Some(env!("CARGO_BIN_EXE_nerve-node").into());
    // The node by hand runs the config's capabilities as its own user, for
    // `nerve-run`, on a kernel without Landlock (as on a machine that lacks
    // it): the folders of a pairing by hand are not that account's.
    o.config_caps_by_hand = true;
    o.confinement = Some(nerve_sandbox::Confinement {
        landlock_abi: None,
        appcontainer: false,
    });
    o
}

async fn owner_edit(paths: &NodePaths, f: impl Fn(&mut NodeConfig)) {
    nerve_node::cli::edit(paths, |c| {
        f(c);
        Ok(())
    })
    .await
    .expect("the owner's edit");
}

/// A config capability from its `[[capability]]` lines.
fn cap(toml: &str) -> ConfigCapability {
    let c = NodeConfig::parse(&format!("[[capability]]\n{toml}\n")).expect("a capability");
    c.capabilities[0].clone()
}

/// Pairs with `center` as `lab`, declares `caps`, lets `policy` change the
/// center's policy, and starts the daemon (a node run by hand).
async fn node(
    root: &Path,
    center: &FakeCenter,
    caps: Vec<ConfigCapability>,
    policy: impl Fn(&mut nerve_policy::CenterPolicy),
) -> Daemon {
    let o = options(root);
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .expect("pair");
    owner_edit(&o.paths, |c| {
        c.capabilities = caps.clone();
        policy(&mut c.centers[0].policy);
    })
    .await;
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

/// [`invoke`], and the `audit/decision` events the center was sent for the
/// call (it subscribed): each event's data.
async fn invoke_heard(
    conn: &mut Conn<TcpStream>,
    name: &str,
    args: Value,
) -> (Result<Value, nerve_proto::RpcError>, Vec<Value>) {
    let (cap, action) = name.split_once('.').unwrap();
    let id = conn
        .request(
            "invoke",
            json!({"cap": cap, "action": action, "args": args, "ctx": {}}),
        )
        .await
        .unwrap();
    let mut others = Vec::new();
    let r = conn.answer(id, WAIT, &mut others).await.unwrap();
    // The decision is sent before the command runs; a call after it brings
    // whatever is still on the way.
    let flush = conn.request("get", json!({"cap": "node"})).await.unwrap();
    conn.answer(flush, WAIT, &mut others)
        .await
        .unwrap()
        .unwrap();
    let heard = others
        .into_iter()
        .filter_map(|m| match m {
            nerve_proto::Message::Notification { method, params }
                if method == "event" && params["cap"] == "audit" =>
            {
                Some(params["data"].clone())
            }
            _ => None,
        })
        .collect();
    (r, heard)
}

/// The actions the center is offered now, as `cap.action`, with their
/// capability's provider.
async fn offered(conn: &mut Conn<TcpStream>) -> Vec<(String, String)> {
    let d = conn
        .call("describe", json!({"detail": "full"}), WAIT)
        .await
        .unwrap()
        .expect("describe");
    let mut out = Vec::new();
    for c in d["capabilities"].as_array().unwrap() {
        for a in c["actions"].as_object().into_iter().flat_map(|a| a.keys()) {
            out.push((
                format!("{}.{a}", c["id"].as_str().unwrap()),
                c["provider"].as_str().unwrap().to_string(),
            ));
        }
    }
    out
}

/// The audit entries of `cap`.
fn audited(paths: &NodePaths, cap: &str) -> Vec<Value> {
    std::fs::read_to_string(paths.audit_log())
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .filter(|e: &Value| e["cap"] == cap)
        .collect()
}

fn user_mode(p: &mut nerve_policy::CenterPolicy) {
    p.mode = nerve_policy::Mode::User;
}

/// What a value of an argument holds reaches the program as one argument,
/// as it is: no shell reads it, so `;`, `$( )` and backquotes run nothing.
#[tokio::test(flavor = "multi_thread")]
async fn arguments_are_data_never_shell() {
    let dir = scratch();
    let mut center = FakeCenter::start(false).await.unwrap();
    let echo = cap(r#"name = "say.back"
effect = "read"
command = ["printf", "--", "[%s]\n", "{a}", "{b}", "{c}"]
params = '{"type": "object", "properties": {"a": {"type": "string"}, "b": {"type": "string"}, "c": {"type": "integer"}}, "required": ["a", "b"]}'"#);
    let daemon = node(dir.path(), &center, vec![echo], user_mode).await;
    let home = dir.path().join("home");
    // What `; rm -rf x` would remove if a shell read it: in the folder the
    // command starts in.
    std::fs::create_dir_all(home.join("x")).unwrap();
    let mut conn = linked(&mut center).await;
    conn.call("sub", json!({"topics": ["audit/decision"]}), WAIT)
        .await
        .unwrap()
        .expect("sub");
    assert!(
        offered(&mut conn)
            .await
            .contains(&("say.back".into(), "config".into()))
    );
    let marker = dir.path().join("ran");
    let a = format!("; rm -rf x; touch {}", marker.display());
    let b = "$(id) `id` | cat > y && echo z";
    let (out, heard) = invoke_heard(&mut conn, "say.back", json!({"a": a, "b": b, "c": 7})).await;
    let out = out.expect("it runs");
    assert_eq!(out, json!(format!("[{a}]\n[{b}]\n[7]\n")));
    assert!(home.join("x").is_dir(), "nothing was removed");
    assert!(!marker.exists() && !home.join("y").exists());
    // An argument left out is no argument at all.
    let out = invoke(&mut conn, "say.back", json!({"a": "only", "b": "two"}))
        .await
        .unwrap();
    assert_eq!(out, json!("[only]\n[two]\n"));
    // Arguments outside its schema never reach it.
    let e = invoke(
        &mut conn,
        "say.back",
        json!({"a": "x", "b": "y", "c": "seven"}),
    )
    .await
    .unwrap_err();
    assert_eq!(code_of(&e), "invalid_args", "{}", e.message);
    // Decided and audited like any call. It names no path, so its target
    // is the action, which is all the center hears of it; the node's own
    // log adds the command as it ran, with what the call gave it.
    assert_eq!(heard.len(), 1, "{heard:?}");
    assert_eq!(heard[0]["target"], "say.back", "{heard:?}");
    assert!(heard[0].get("command").is_none(), "{heard:?}");
    assert!(!heard[0].to_string().contains("printf"), "{heard:?}");
    let entries = audited(daemon.paths(), "say");
    let ran = ConfigCapability::line(&[
        "printf".into(),
        "--".into(),
        "[%s]\n".into(),
        a.clone(),
        b.into(),
        "7".into(),
    ]);
    assert!(ran.contains("touch") && ran.contains("$(id)"), "{ran}");
    assert!(
        entries.iter().any(|e| e["decision"] == "allowed"
            && e["target"] == "say.back"
            && e["command"] == ran.as_str()),
        "{entries:?}"
    );
    daemon.stop().await;
}

/// A value that looks like an option is an argument after a `--` of the
/// command, where the program reads no options; before one it is refused.
#[tokio::test(flavor = "multi_thread")]
async fn an_option_like_value_after_double_dash_stays_an_argument() {
    let dir = scratch();
    let mut center = FakeCenter::start(false).await.unwrap();
    let after = cap(r#"name = "files.make"
effect = "write"
command = ["touch", "--", "{name}"]
params = '{"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}'"#);
    let before = cap(r#"name = "files.touch"
effect = "write"
command = ["touch", "{name}"]
params = '{"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}'"#);
    let daemon = node(dir.path(), &center, vec![after, before], user_mode).await;
    let home = dir.path().join("home");
    let mut conn = linked(&mut center).await;
    invoke(&mut conn, "files.make", json!({"name": "-rf"}))
        .await
        .expect("an argument after --");
    assert!(home.join("-rf").is_file(), "touch made a file of that name");
    let e = invoke(&mut conn, "files.touch", json!({"name": "--help"}))
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), "invalid_args");
    assert!(
        e.message.contains("would be read as an option"),
        "{}",
        e.message
    );
    assert!(!home.join("--help").exists());
    daemon.stop().await;
}

/// A path argument marked in the schema is held to the folders as an `fs`
/// call's path is: outside them the call is refused and its program never
/// runs; inside it runs with the path as the node resolved it.
#[tokio::test(flavor = "multi_thread")]
async fn a_path_arg_outside_the_folders_is_refused() {
    let dir = scratch();
    let root = dir.path().canonicalize().unwrap();
    let (work, outside) = (root.join("work"), root.join("outside"));
    for d in [&work, &outside] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(work.join("in.txt"), "inside\n").unwrap();
    std::fs::write(outside.join("out.txt"), "outside\n").unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let show = cap(r#"name = "files.show"
effect = "read"
command = ["cat", "--", "{path}"]
params = '{"type": "object", "properties": {"path": {"type": "string", "x-nerve-path": "read"}}, "required": ["path"]}'"#);
    let make = cap(r#"name = "files.make"
effect = "write"
command = ["touch", "--", "{path}"]
params = '{"type": "object", "properties": {"path": {"type": "string", "x-nerve-path": "write"}}, "required": ["path"]}'"#);
    let folder = nerve_policy::config::Folder {
        path: work.display().to_string(),
        access: nerve_policy::config::Access::parse("rw").unwrap(),
    };
    let daemon = node(&root, &center, vec![show, make], |p| {
        p.mode = nerve_policy::Mode::Folder;
        p.folders = vec![folder.clone()];
    })
    .await;
    let mut conn = linked(&mut center).await;
    let wire = |p: PathBuf| nerve_policy::paths::to_wire(&p);
    // Given through `..`, it reaches the program resolved.
    let given = format!("{}/../work/in.txt", wire(work.clone()));
    assert_eq!(
        invoke(&mut conn, "files.show", json!({"path": given}))
            .await
            .unwrap(),
        json!("inside\n")
    );
    let e = invoke(
        &mut conn,
        "files.show",
        json!({"path": wire(outside.join("out.txt"))}),
    )
    .await
    .unwrap_err();
    assert_eq!(code_of(&e), "forbidden");
    assert!(e.message.contains("outside the folders"), "{}", e.message);
    invoke(
        &mut conn,
        "files.make",
        json!({"path": wire(work.join("new"))}),
    )
    .await
    .expect("made inside");
    assert!(work.join("new").is_file());
    let e = invoke(
        &mut conn,
        "files.make",
        json!({"path": wire(outside.join("new"))}),
    )
    .await
    .unwrap_err();
    assert_eq!(code_of(&e), "forbidden", "{}", e.message);
    assert!(!outside.join("new").exists(), "the program never ran");
    // The audit names the paths.
    let entries = audited(daemon.paths(), "files");
    let at = |path: PathBuf, decision: &str| {
        entries
            .iter()
            .any(|e| e["target"] == wire(path.clone()) && e["decision"] == decision)
    };
    assert!(at(work.join("in.txt"), "allowed"), "{entries:?}");
    assert!(at(outside.join("out.txt"), "forbidden"), "{entries:?}");
    assert!(at(outside.join("new"), "forbidden"), "{entries:?}");
    daemon.stop().await;
}

/// Whether a process runs `sleep` with the argument `arg`.
fn sleeping(arg: &str) -> bool {
    std::fs::read_dir("/proc").unwrap().flatten().any(|e| {
        std::fs::read(e.path().join("cmdline")).is_ok_and(|c| {
            let words: Vec<&[u8]> = c.split(|b| *b == 0).collect();
            matches!(words.as_slice(), [first, a, b""]
                if Path::new(std::ffi::OsStr::from_bytes(first)).file_name() == Some("sleep".as_ref())
                    && *a == arg.as_bytes())
        })
    })
}

/// A call of a config capability counts toward `limits.max_running` as a
/// command does: while one runs, a second one is `busy`.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_counts_toward_max_running() {
    let dir = scratch();
    let mut center = FakeCenter::start(false).await.unwrap();
    let slow = cap(r#"name = "slow.wait"
effect = "read"
command = ["sleep", "41.625"]"#);
    let o = options(dir.path());
    let daemon = node(dir.path(), &center, vec![slow], user_mode).await;
    owner_edit(&o.paths, |c| c.limits.max_running = 1).await;
    daemon.reload().unwrap();
    let mut conn = linked(&mut center).await;
    let id = conn
        .request(
            "invoke",
            json!({"cap": "slow", "action": "wait", "args": {}, "ctx": {}}),
        )
        .await
        .unwrap();
    let started = Instant::now();
    while !sleeping("41.625") {
        assert!(started.elapsed() < WAIT, "the command never started");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let e = invoke(&mut conn, "slow.wait", json!({})).await.unwrap_err();
    assert_eq!(code_of(&e), "busy", "{}", e.message);
    assert!(
        e.message.contains("1 commands are running already"),
        "{}",
        e.message
    );
    conn.notify("cancel", json!({"id": id})).await.unwrap();
    let _ = conn.answer(id, WAIT, &mut Vec::new()).await;
    daemon.stop().await;
}

/// A command past its `timeout_secs` is killed and its call fails
/// `timeout`, naming its own limit.
#[tokio::test(flavor = "multi_thread")]
async fn the_timeout_ends_it() {
    let dir = scratch();
    let mut center = FakeCenter::start(false).await.unwrap();
    let slow = cap(r#"name = "slow.wait"
effect = "read"
command = ["sleep", "41.25"]
timeout_secs = 1"#);
    let daemon = node(dir.path(), &center, vec![slow], user_mode).await;
    let mut conn = linked(&mut center).await;
    let started = Instant::now();
    let e = invoke(&mut conn, "slow.wait", json!({})).await.unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(code_of(&e), "timeout");
    assert!(
        e.message.contains("slow.wait ran past its limit of 1 s"),
        "{}",
        e.message
    );
    assert!(!sleeping("41.25"), "the command was killed");
    daemon.stop().await;
}

/// A call the center cancels ends its command, as a timeout does: the call
/// fails `cancelled` and the command is gone within seconds.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_call_ends_the_command() {
    let dir = scratch();
    let mut center = FakeCenter::start(false).await.unwrap();
    let slow = cap(r#"name = "slow.wait"
effect = "read"
command = ["sleep", "41.5"]"#);
    let daemon = node(dir.path(), &center, vec![slow], user_mode).await;
    let mut conn = linked(&mut center).await;
    let id = conn
        .request(
            "invoke",
            json!({"cap": "slow", "action": "wait", "args": {}, "ctx": {}}),
        )
        .await
        .unwrap();
    let started = Instant::now();
    while !sleeping("41.5") {
        assert!(started.elapsed() < WAIT, "the command never started");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    conn.notify("cancel", json!({"id": id})).await.unwrap();
    let e = conn
        .answer(id, WAIT, &mut Vec::new())
        .await
        .unwrap()
        .expect_err("cancelled");
    assert_eq!(code_of(&e), "cancelled");
    let started = Instant::now();
    while sleeping("41.5") {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a cancelled command outlived its call"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    daemon.stop().await;
}

/// A command the kernel killed for its memory limit fails, whatever its
/// first process's exit, and the audit log says so as for `exec.run`. The
/// cgroups are plain folders here, and the command writes what the kernel
/// would into its `memory.events` (as link.rs's test of `exec.run`).
#[tokio::test(flavor = "multi_thread")]
async fn a_command_killed_for_its_memory_fails_and_is_in_the_audit() {
    use std::sync::Arc;
    let me = nerve_transport::net::euid();
    if me == 0 {
        eprintln!("skipped: root's own folders are no cgroup without systemd's mark");
        return;
    }
    let dir = scratch();
    let fake = dir.path().join("cgroup");
    let own = fake.join("node.scope");
    std::fs::create_dir_all(&own).unwrap();
    std::fs::write(fake.join("cgroup.controllers"), "cpu memory pids").unwrap();
    std::fs::write(own.join("cgroup.controllers"), "cpu memory pids").unwrap();
    std::fs::write(own.join("cgroup.procs"), "").unwrap();
    let cgroups =
        nerve_node::cgroup::Cgroups::at(&fake, "/node.scope", std::process::id(), me, &|_| true)
            .expect("plain folders of this user");
    std::fs::write(own.join("cgroup.subtree_control"), "cpu memory pids").unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let mut o = options(dir.path());
    o.cgroups = Some(Ok(Arc::new(cgroups)));
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .expect("pair");
    let script = format!(
        "for d in {}/cmd-*; do printf 'oom 1\\noom_kill 1\\n' > \"$d/memory.events\"; done; echo done",
        own.display()
    );
    let big = ConfigCapability {
        command: vec!["sh".into(), "-c".into(), script],
        ..cap(r#"name = "big.run"
effect = "read"
command = ["sh"]"#)
    };
    owner_edit(&o.paths, |c| {
        c.capabilities = vec![big.clone()];
        c.centers[0].policy.mode = nerve_policy::Mode::User;
    })
    .await;
    let node = Daemon::start(o).await.expect("start");
    let mut conn = linked(&mut center).await;
    let e = invoke(&mut conn, "big.run", json!({})).await.unwrap_err();
    assert_eq!(code_of(&e), "io", "{}", e.message);
    assert!(
        e.message
            .contains("big.run failed: the command went past its memory limit"),
        "{}",
        e.message
    );
    let entries = audited(node.paths(), "big");
    node.stop().await;
    let killed: Vec<&Value> = entries
        .iter()
        .filter(|v| v["decision"] == "killed")
        .collect();
    assert_eq!(killed.len(), 1, "{entries:?}");
    assert_eq!(killed[0]["code"], "memory", "{entries:?}");
    assert_eq!(killed[0]["target"], "big.run", "{entries:?}");
    assert_eq!(
        killed[0]["command"],
        ConfigCapability::line(&big.command),
        "{entries:?}"
    );
}

/// Only stdout's own cut counts for what a call returns: stderr past the
/// node's output cap leaves a whole JSON result whole.
#[tokio::test(flavor = "multi_thread")]
async fn stderr_past_the_cap_leaves_the_result_whole() {
    let dir = scratch();
    let mut center = FakeCenter::start(false).await.unwrap();
    let noisy = cap(r#"name = "probe.noisy"
effect = "read"
command = ["sh", "-c", "printf '{\"t\": 1}'; head -c 4096 /dev/zero | tr '\\0' x >&2"]
result = '{"type": "object"}'"#);
    let o = options(dir.path());
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .expect("pair");
    owner_edit(&o.paths, |c| {
        c.capabilities = vec![noisy.clone()];
        c.limits.output_cap_bytes = 1024;
        c.centers[0].policy.mode = nerve_policy::Mode::User;
    })
    .await;
    let daemon = Daemon::start(o).await.expect("start");
    let mut conn = linked(&mut center).await;
    assert_eq!(
        invoke(&mut conn, "probe.noisy", json!({})).await.unwrap(),
        json!({"t": 1})
    );
    daemon.stop().await;
}

/// A command that does not end with exit code 0 fails with its exit code,
/// its stderr in the error's data (the command's words, not the node's);
/// one whose result is JSON returns it parsed, and fails where it does not
/// fit the result schema.
#[tokio::test(flavor = "multi_thread")]
async fn a_failing_command_is_an_error_and_json_is_parsed() {
    let dir = scratch();
    let mut center = FakeCenter::start(false).await.unwrap();
    let fail = cap(r#"name = "probe.fail"
effect = "read"
command = ["ls", "--", "/nonexistent-b5"]"#);
    let json_cap = cap(r#"name = "probe.json"
effect = "read"
command = ["printf", "{v}"]
params = '{"type": "object", "properties": {"v": {"type": "string"}}, "required": ["v"]}'
result = '{"type": "object", "properties": {"t": {"type": "integer"}}, "required": ["t"]}'"#);
    let daemon = node(dir.path(), &center, vec![fail, json_cap], user_mode).await;
    let mut conn = linked(&mut center).await;
    let e = invoke(&mut conn, "probe.fail", json!({}))
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), "io");
    assert_eq!(e.message, "probe.fail failed: exit code 2");
    let data = e.data.as_ref().unwrap();
    assert_eq!(data["exit_code"], 2);
    assert!(
        data["stderr"]
            .as_str()
            .is_some_and(|s| s.contains("nonexistent-b5")),
        "{data}"
    );
    assert_eq!(
        invoke(&mut conn, "probe.json", json!({"v": "{\"t\": 21}"}))
            .await
            .unwrap(),
        json!({"t": 21})
    );
    let e = invoke(&mut conn, "probe.json", json!({"v": "{\"t\": \"warm\"}"}))
        .await
        .unwrap_err();
    assert!(e.message.contains("result schema"), "{}", e.message);
    daemon.stop().await;
}

/// A program may not add a capability the config declares, and one
/// attached is let go when the owner declares one of its names.
#[tokio::test(flavor = "multi_thread")]
async fn a_name_clash_with_a_provider_is_refused() {
    let dir = scratch();
    let mut center = FakeCenter::start(false).await.unwrap();
    let dim = cap(r#"name = "lamp.dim"
effect = "write"
command = ["true"]"#);
    let o = options(dir.path());
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .unwrap();
    owner_edit(&o.paths, |c| {
        c.capabilities = vec![dim.clone()];
        c.providers.allowed = vec![AllowedProvider {
            name: "desk".into(),
            exe: std::env::current_exe().unwrap().display().to_string(),
        }];
        user_mode(&mut c.centers[0].policy);
    })
    .await;
    let daemon = Daemon::start(o).await.unwrap();
    let mut conn = linked(&mut center).await;
    let socket = daemon.paths().ctl_socket();
    let lamp = json!([{"id": "lamp", "actions": {"on": {"effect": "write"}}}]);
    let (_p, first) = hello(&socket, lamp).await;
    let e = first["error"].as_str().expect("refused");
    assert!(
        e.contains("capability lamp") && e.contains("node.toml"),
        "{e}"
    );
    // The config's own stays, the program's never came.
    let now = offered(&mut conn).await;
    assert!(
        now.contains(&("lamp.dim".into(), "config".into())),
        "{now:?}"
    );
    assert!(!now.iter().any(|(n, _)| n == "lamp.on"), "{now:?}");
    // Attached under another name, it goes once the config takes the name.
    let desk = json!([{"id": "desk", "actions": {"on": {"effect": "write"}}}]);
    let (mut p, first) = hello(&socket, desk).await;
    assert_eq!(first["ok"]["capabilities"], json!(["desk"]), "{first}");
    let paths = daemon.paths().clone();
    let said = cli(
        &paths,
        &["cap", "add", "desk.off", "--effect", "write", "--", "true"],
    )
    .await;
    assert!(
        said.contains("the program desk offered desk and is let go"),
        "{said}"
    );
    assert_eq!(p.next().await, None, "the connection ends");
    assert_eq!(daemon.status()["providers"], json!([]));
    daemon.stop().await;
}

/// A capability for Windows only is not offered on Linux; a call of it
/// names an unknown capability.
#[tokio::test(flavor = "multi_thread")]
async fn a_windows_only_capability_is_not_offered_on_linux() {
    let dir = scratch();
    let mut center = FakeCenter::start(false).await.unwrap();
    let caps = vec![
        cap(r#"name = "win.who"
effect = "read"
command = ["whoami"]
platform = "windows""#),
        cap(r#"name = "lin.who"
effect = "read"
command = ["id", "-un"]
platform = "linux""#),
        cap(r#"name = "any.who"
effect = "read"
command = ["id", "-un"]"#),
    ];
    let daemon = node(dir.path(), &center, caps, user_mode).await;
    let mut conn = linked(&mut center).await;
    let now: Vec<String> = offered(&mut conn)
        .await
        .into_iter()
        .filter(|(_, p)| p == "config")
        .map(|(n, _)| n)
        .collect();
    assert_eq!(now, ["any.who", "lin.who"]);
    let e = invoke(&mut conn, "win.who", json!({})).await.unwrap_err();
    assert_eq!(code_of(&e), "unknown_capability", "{}", e.message);
    for name in ["lin.who", "any.who"] {
        invoke(&mut conn, name, json!({}))
            .await
            .expect("its own platform's runs");
    }
    daemon.stop().await;
}

/// A node run by hand has no `nerve-run`, which every capability of
/// node.toml runs as, so it offers none: a call of one names an unknown
/// capability, and `cap ls` says why each one is left out.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_run_by_hand_offers_none_and_says_why() {
    let dir = scratch();
    let mut center = FakeCenter::start(false).await.unwrap();
    let mut o = options(dir.path());
    o.config_caps_by_hand = false;
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .expect("pair");
    let who = cap(r#"name = "who.am"
effect = "read"
command = ["id"]"#);
    owner_edit(&o.paths, |c| {
        c.capabilities = vec![who.clone()];
        user_mode(&mut c.centers[0].policy);
    })
    .await;
    let daemon = Daemon::start(o).await.expect("start");
    let mut conn = linked(&mut center).await;
    let now = offered(&mut conn).await;
    assert!(!now.iter().any(|(_, p)| p == "config"), "{now:?}");
    let e = invoke(&mut conn, "who.am", json!({})).await.unwrap_err();
    assert_eq!(code_of(&e), "unknown_capability", "{}", e.message);
    let why =
        "left out: runs as nerve-run, which only the installed node has (sudo nerve-node install)";
    let paths = daemon.paths().clone();
    let ls = cli(&paths, &["cap", "ls"]).await;
    let row = ls
        .lines()
        .find(|l| l.starts_with("who.am"))
        .unwrap_or_else(|| panic!("{ls}"));
    assert!(row.ends_with(why), "{ls}");
    assert!(ls.contains("capability who.am: id\n"), "{ls}");
    // So does the CLI while no node runs.
    daemon.stop().await;
    let ls = cli(&paths, &["cap", "ls"]).await;
    assert!(ls.contains(why), "{ls}");
}

/// A capability of the config that senses is offered and runs only once
/// the owner sets it to on; a center with the settings grant cannot, though
/// it may turn on one that only reads.
#[tokio::test(flavor = "multi_thread")]
async fn sense_needs_the_owners_on() {
    let dir = scratch();
    let mut center = FakeCenter::start(false).await.unwrap();
    let temp = cap(r#"name = "probe.temp"
effect = "sense"
command = ["echo", "21"]"#);
    let list = cap(r#"name = "notes.list"
effect = "read"
command = ["echo", "temp"]"#);
    let daemon = node(dir.path(), &center, vec![temp, list], |p| {
        p.mode = nerve_policy::Mode::Folder;
    })
    .await;
    let paths = daemon.paths().clone();
    owner_edit(&paths, |c| c.centers[0].settings = SettingsGrant::Write).await;
    daemon.reload().unwrap();
    let mut conn = linked(&mut center).await;
    assert!(
        !offered(&mut conn)
            .await
            .iter()
            .any(|(n, _)| n == "probe.temp")
    );
    let e = invoke(&mut conn, "probe.temp", json!({}))
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), "forbidden");
    assert!(
        e.message
            .contains("sense is allowed only where probe.temp is set to on"),
        "{}",
        e.message
    );
    // The center may not turn it on itself.
    for doc_caps in [json!({"probe.temp": "on"}), json!({"probe": "on"})] {
        let got = conn
            .call(
                "get",
                json!({"cap": "settings", "keys": ["document", "version"]}),
                WAIT,
            )
            .await
            .unwrap()
            .unwrap();
        let mut doc = got["document"].clone();
        doc["policy"]["caps"] = doc_caps;
        let e = conn
            .call(
                "invoke",
                json!({"cap": "settings", "action": "set", "ctx": {},
                       "args": {"document": doc, "if_version": got["version"]}}),
                WAIT,
            )
            .await
            .unwrap()
            .expect_err("only the owner");
        assert_eq!(code_of(&e), "forbidden");
        assert!(
            e.message
                .contains("only the owner can turn on what senses or actuates"),
            "{}",
            e.message
        );
    }
    // One that only reads, offered now, it may turn on: in folder mode a
    // read that names no path needs it.
    assert!(
        !offered(&mut conn)
            .await
            .iter()
            .any(|(n, _)| n == "notes.list")
    );
    let got = conn
        .call(
            "get",
            json!({"cap": "settings", "keys": ["document", "version"]}),
            WAIT,
        )
        .await
        .unwrap()
        .unwrap();
    let mut doc = got["document"].clone();
    doc["policy"]["caps"] = json!({"notes.list": "on"});
    conn.call(
        "invoke",
        json!({"cap": "settings", "action": "set", "ctx": {},
               "args": {"document": doc, "if_version": got["version"]}}),
        WAIT,
    )
    .await
    .unwrap()
    .expect("a read the center may turn on");
    assert_eq!(
        invoke(&mut conn, "notes.list", json!({})).await.unwrap(),
        json!("temp\n")
    );
    owner_edit(&paths, |c| {
        c.centers[0]
            .policy
            .caps
            .insert("probe.temp".into(), CapSetting::On);
    })
    .await;
    daemon.reload().unwrap();
    assert!(
        offered(&mut conn)
            .await
            .iter()
            .any(|(n, _)| n == "probe.temp")
    );
    assert_eq!(
        invoke(&mut conn, "probe.temp", json!({})).await.unwrap(),
        json!("21\n")
    );
    // The read the center turned on comes to sense: the center's `on` was
    // for a read, so it waits for the owner's.
    let said = cli(&paths, &["cap", "edit", "notes.list", "--effect", "sense"]).await;
    assert!(said.contains("lab: a switch or allow rule"), "{said}");
    let e = invoke(&mut conn, "notes.list", json!({}))
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), "disabled", "{}", e.message);
    daemon.stop().await;
}

/// The settings document of the center on `conn` with its `caps` set to
/// `caps`, sent with `settings.set`.
async fn set_caps(conn: &mut Conn<TcpStream>, caps: Value) -> Result<Value, nerve_proto::RpcError> {
    let got = conn
        .call(
            "get",
            json!({"cap": "settings", "keys": ["document", "version"]}),
            WAIT,
        )
        .await
        .unwrap()
        .unwrap();
    let mut doc = got["document"].clone();
    doc["policy"]["caps"] = caps;
    conn.call(
        "invoke",
        json!({"cap": "settings", "action": "set", "ctx": {},
               "args": {"document": doc, "if_version": got["version"]}}),
        WAIT,
    )
    .await
    .unwrap()
}

/// A center may not turn on a capability whose action senses although this
/// node does not offer that action now (it is for another platform): once
/// the owner makes it offered, the center's `on` would cover it.
#[tokio::test(flavor = "multi_thread")]
async fn a_capability_that_senses_where_it_is_not_offered_stays_the_owners() {
    let dir = scratch();
    let mut center = FakeCenter::start(false).await.unwrap();
    let list = cap(r#"name = "probe.list"
effect = "read"
command = ["echo", "temp"]"#);
    let cam = cap(r#"name = "probe.cam"
effect = "sense"
command = ["echo", "frame"]
platform = "windows""#);
    let daemon = node(dir.path(), &center, vec![list, cam], |p| {
        p.mode = nerve_policy::Mode::Folder;
    })
    .await;
    owner_edit(daemon.paths(), |c| {
        c.centers[0].settings = SettingsGrant::Write
    })
    .await;
    daemon.reload().unwrap();
    let mut conn = linked(&mut center).await;
    let names: Vec<String> = offered(&mut conn)
        .await
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert!(!names.contains(&"probe.cam".to_string()), "{names:?}");
    let e = set_caps(&mut conn, json!({"probe": "on"}))
        .await
        .expect_err("only the owner");
    assert_eq!(code_of(&e), "forbidden", "{}", e.message);
    assert!(
        e.message
            .contains("only the owner can turn on what senses or actuates"),
        "{}",
        e.message
    );
    daemon.stop().await;
}

/// `config accept` of a node.toml the owner wrote with an action that
/// senses switches it off where an earlier switch covered it, as `cap add`
/// does, and says so; so does any other write the running node takes.
#[tokio::test(flavor = "multi_thread")]
async fn config_accept_holds_an_action_that_comes_to_sense() {
    let dir = scratch();
    let mut center = FakeCenter::start(false).await.unwrap();
    let list = cap(r#"name = "probe.list"
effect = "read"
command = ["echo", "temp"]"#);
    let daemon = node(dir.path(), &center, vec![list], |p| {
        p.mode = nerve_policy::Mode::Folder;
        p.caps.insert("probe".into(), CapSetting::On);
    })
    .await;
    let paths = daemon.paths().clone();
    let mut conn = linked(&mut center).await;
    let file = paths.config_file();
    let mut text = std::fs::read_to_string(&file).unwrap();
    text.push_str(
        "\n[[capability]]\nname = \"probe.cam\"\neffect = \"sense\"\ncommand = [\"echo\", \"frame\"]\n",
    );
    std::fs::write(&file, text).unwrap();
    let version = |paths: &NodePaths| {
        let text = std::fs::read_to_string(paths.config_file()).unwrap();
        NodeConfig::parse(&text).unwrap().version
    };
    let was = version(&paths);
    let said = cli(&paths, &["config", "accept"]).await;
    // One write carries the file and the hold: nothing in force, and no
    // node stopped between two writes, has the file without it.
    assert_eq!(version(&paths), was + 1, "{said}");
    assert!(
        said.contains("lab: a switch or allow rule set before covered probe.cam"),
        "{said}"
    );
    let mut e = None;
    for _ in 0..50 {
        match invoke(&mut conn, "probe.cam", json!({})).await {
            Err(x) if code_of(&x) == "disabled" => {
                e = Some(x);
                break;
            }
            _ => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    assert!(e.is_some(), "probe.cam waits for the owner's on");
    assert_eq!(
        invoke(&mut conn, "probe.list", json!({})).await.unwrap(),
        json!("temp\n")
    );
    // Any other write of the config the running node takes does the same.
    owner_edit(&paths, |c| {
        c.capabilities.push(cap(r#"name = "probe.mic"
effect = "sense"
command = ["echo", "sound"]"#));
    })
    .await;
    let caps = &nerve_node::cli::read_config(&paths)
        .await
        .unwrap()
        .0
        .centers[0]
        .policy
        .caps;
    assert_eq!(caps.get("probe.mic"), Some(&CapSetting::Off), "{caps:?}");
    daemon.stop().await;
}

/// The command of a config capability runs through the shim under Landlock
/// like a folder-mode command, its arguments whole: it reads in its folders
/// and nowhere else. (The installed node runs those of `nerve-run` so;
/// real_account.rs runs one there.)
#[tokio::test]
async fn a_program_runs_whole_through_the_shim_under_landlock() {
    use nerve_node::exec::{self, RunCall, RunOptions};
    use nerve_policy::config::{Access, CenterPolicy, Folder, Mode};
    if !nerve_sandbox::Confinement::detect().available() {
        eprintln!("skipped: Landlock is not available here");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(d.path()).unwrap();
    let work = root.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let inside = work.join("a b; c $(id)");
    std::fs::write(&inside, "inside\n").unwrap();
    let outside = root.join("out.txt");
    std::fs::write(&outside, "outside\n").unwrap();
    let policy = CenterPolicy {
        mode: Mode::Folder,
        folders: vec![Folder {
            path: work.display().to_string(),
            access: Access::ALL,
        }],
        ..Default::default()
    };
    let opts = RunOptions {
        shell: None,
        landlock: Some(exec::landlock_spec(&policy, &root, &[], &[])),
        container: None,
        exe: env!("CARGO_BIN_EXE_nerve-node").into(),
        output_cap: 64 * 1024,
        timeouts: Default::default(),
        sudo: None,
        account: None,
        separate: false,
        own: Vec::new(),
        root: None,
        limits: None,
        tap: None,
    };
    let run = |path: &Path| {
        let argv = vec!["cat".into(), "--".into(), path.display().to_string()];
        RunCall::program(argv, "cat".into(), work.clone(), None)
    };
    let r = exec::run(&run(&inside), &opts, |_| {}).await.unwrap();
    assert_eq!(
        (r["exit_code"].clone(), r["stdout"].clone()),
        (json!(0), json!("inside\n")),
        "{r}"
    );
    let r = exec::run(&run(&outside), &opts, |_| {}).await.unwrap();
    // Refused by Landlock (in the system's language).
    assert_ne!(r["exit_code"], 0, "{r}");
    assert_eq!(r["stdout"], "", "{r}");
}

/// A provider's connection on the control socket.
struct Provider {
    lines: tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
    /// Held: the connection stays while it is.
    _w: tokio::net::unix::OwnedWriteHalf,
}

impl Provider {
    async fn next(&mut self) -> Option<Value> {
        let line = tokio::time::timeout(WAIT, self.lines.next_line())
            .await
            .expect("a line within 15 s")
            .ok()??;
        Some(serde_json::from_str(&line).unwrap())
    }
}

/// `hello` as the provider `desk` (this test program) with `caps`.
async fn hello(socket: &Path, caps: Value) -> (Provider, Value) {
    let token = std::fs::read_to_string(socket.with_file_name("ctl.token")).unwrap();
    let (r, mut w) = UnixStream::connect(socket).await.unwrap().into_split();
    let line = json!({"method": "hello", "token": token,
                      "params": {"role": "provider", "name": "desk", "capabilities": caps}});
    w.write_all(format!("{line}\n").as_bytes()).await.unwrap();
    let mut p = Provider {
        lines: BufReader::new(r).lines(),
        _w: w,
    };
    let first = p.next().await.expect("an answer");
    (p, first)
}

/// What `nerve-node <words>` prints, run in this process.
async fn cli(paths: &NodePaths, words: &[&str]) -> String {
    use clap::Parser;
    let mut args = vec![
        "nerve-node".into(),
        "--config-dir".into(),
        paths.config_dir.clone(),
        "--state-dir".into(),
        paths.state_dir.clone(),
    ];
    args.extend(words.iter().map(PathBuf::from));
    let cli = nerve_node::cli::Cli::parse_from(args);
    let mut out = Vec::new();
    nerve_node::cli::execute(cli, &mut out).await.unwrap();
    String::from_utf8(out).unwrap()
}

/// `cap add` takes a schema on stdin, as the owner pipes it in, and the
/// running node offers what it declares at once; `cap ls` asks the node.
#[tokio::test(flavor = "multi_thread")]
async fn cap_add_takes_the_schema_on_stdin_and_the_running_node_offers_it() {
    use std::io::Write;
    let dir = scratch();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(dir.path(), &center, Vec::new(), user_mode).await;
    let mut conn = linked(&mut center).await;
    let paths = daemon.paths().clone();
    let schema =
        r#"{"type": "object", "properties": {"word": {"type": "string"}}, "required": ["word"]}"#;
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_nerve-node"))
        .arg("--config-dir")
        .arg(&paths.config_dir)
        .arg("--state-dir")
        .arg(&paths.state_dir)
        .args([
            "cap",
            "add",
            "say.word",
            "--effect",
            "read",
            "--params-stdin",
            "--",
            "printf",
            "%s",
            "{word}",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(schema.as_bytes())
        .unwrap();
    let o = child.wait_with_output().unwrap();
    let said = String::from_utf8_lossy(&o.stdout);
    assert!(
        o.status.success(),
        "{said}{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(
        said.contains("capability say.word added: printf %s {word}\n"),
        "{said}"
    );
    // The node took the change: it offers it, and the call runs.
    let mut seen = false;
    for _ in 0..100 {
        if offered(&mut conn)
            .await
            .iter()
            .any(|(n, _)| n == "say.word")
        {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(seen, "say.word is offered");
    assert_eq!(
        invoke(&mut conn, "say.word", json!({"word": "hi there"}))
            .await
            .unwrap(),
        json!("hi there")
    );
    let ls = cli(&paths, &["cap", "ls"]).await;
    let row = ls
        .lines()
        .find(|l| l.starts_with("say.word"))
        .unwrap_or_else(|| panic!("{ls}"));
    assert_eq!(
        row.split_whitespace().collect::<Vec<_>>(),
        ["say.word", "read", "config", "lab:", "on"],
        "{ls}"
    );
    assert!(
        ls.contains("capability say.word: printf %s {word}\n"),
        "{ls}"
    );
    daemon.stop().await;
}

/// A capability of node.toml is decided like any other: in `allowlist`
/// mode only an allow rule lets a call through, a deny rule or `off` stops
/// it, and `cap rm` takes it from the running node at once.
#[tokio::test(flavor = "multi_thread")]
async fn rules_switches_and_cap_rm_hold_a_config_capability() {
    let dir = scratch();
    let mut center = FakeCenter::start(false).await.unwrap();
    let list = cap(r#"name = "probe.list"
effect = "read"
command = ["echo", "temp"]"#);
    let daemon = node(dir.path(), &center, vec![list], |p| {
        p.mode = nerve_policy::Mode::Allowlist;
    })
    .await;
    let paths = daemon.paths().clone();
    let mut conn = linked(&mut center).await;
    let e = invoke(&mut conn, "probe.list", json!({}))
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), "forbidden", "{}", e.message);
    // The node takes each change before the next call; wait for it.
    async fn until(
        conn: &mut Conn<TcpStream>,
        want: impl Fn(&Result<Value, nerve_proto::RpcError>) -> bool,
    ) -> Result<Value, nerve_proto::RpcError> {
        let mut r = invoke(conn, "probe.list", json!({})).await;
        for _ in 0..50 {
            if want(&r) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            r = invoke(conn, "probe.list", json!({})).await;
        }
        r
    }
    owner_edit(&paths, |c| {
        c.centers[0].policy.allow = vec!["probe.list".into()]
    })
    .await;
    assert_eq!(
        until(&mut conn, Result::is_ok).await.unwrap(),
        json!("temp\n")
    );
    owner_edit(&paths, |c| c.centers[0].policy.deny = vec!["probe".into()]).await;
    let e = until(&mut conn, Result::is_err).await.unwrap_err();
    assert_eq!(code_of(&e), "forbidden", "{}", e.message);
    owner_edit(&paths, |c| {
        let p = &mut c.centers[0].policy;
        p.deny.clear();
        p.caps.insert("probe.list".into(), CapSetting::Off);
    })
    .await;
    let e = until(&mut conn, |r| {
        r.as_ref().is_err_and(|e| code_of(e) == "disabled")
    })
    .await
    .unwrap_err();
    assert_eq!(code_of(&e), "disabled", "{}", e.message);
    owner_edit(&paths, |c| {
        c.centers[0].policy.caps.remove("probe.list");
    })
    .await;
    assert!(until(&mut conn, Result::is_ok).await.is_ok());
    assert!(
        offered(&mut conn)
            .await
            .iter()
            .any(|(n, p)| n == "probe.list" && p == "config")
    );
    let said = cli(&paths, &["cap", "rm", "probe.list"]).await;
    assert!(said.contains("capability probe.list removed"), "{said}");
    let e = until(&mut conn, |r| {
        r.as_ref()
            .is_err_and(|e| code_of(e) == "unknown_capability")
    })
    .await
    .unwrap_err();
    assert_eq!(code_of(&e), "unknown_capability", "{}", e.message);
    assert!(
        !offered(&mut conn)
            .await
            .iter()
            .any(|(n, _)| n == "probe.list")
    );
    daemon.stop().await;
}
