//! A real node daemon against the conformance fake center, in process:
//! pairing, handshake, describe, an `fs.read` that an allow rule lets through
//! and one that no rule allows, folder mode where allow rules do not count,
//! the 401 stop, and the conformance node checks.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nerve_conformance::fake_center::{self, FakeCenter};
use nerve_conformance::wire::Conn;
use nerve_node::{Daemon, NodeOptions, NodePaths};
use nerve_policy::NodeConfig;
use serde_json::{Value, json};
use tokio::net::TcpStream;

const WAIT: Duration = Duration::from_secs(15);

fn tempdir() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn options(root: &Path) -> NodeOptions {
    let mut o = NodeOptions::new(NodePaths::new(root.join("config"), root.join("state")));
    o.home = root.join("home");
    std::fs::create_dir_all(&o.home).unwrap();
    // Not the rights of whoever runs the tests: an elevated run must pass.
    o.full_rights = Some(false);
    // NERVE_NODE_BIN lets the built tests run on another machine.
    o.exe = Some(
        std::env::var_os("NERVE_NODE_BIN")
            .map(Into::into)
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_nerve-node").into()),
    );
    o
}

/// Pairs with `center` and starts the daemon.
async fn paired_node(root: &Path, center: &FakeCenter) -> Daemon {
    paired_node_with(root, center, |_| {}).await
}

/// Like [`paired_node`], with `policy` changed before the daemon starts.
/// The tests start from allowlist mode, which their rules are written for;
/// a new pairing is in folder mode, with no folder ([`pair_in_allowlist`]).
async fn paired_node_with(
    root: &Path,
    center: &FakeCenter,
    policy: impl Fn(&mut nerve_policy::CenterPolicy),
) -> Daemon {
    let o = options(root);
    pair_in_allowlist(&o.paths, center).await;
    owner_edit(&o.paths, |c| policy(&mut c.centers[0].policy)).await;
    Daemon::start(o).await.expect("start")
}

/// Pairs the node at `paths` with `center` as `lab`, which starts the
/// pairing in folder mode with no folder (issue #142), then puts it in
/// allowlist mode.
async fn pair_in_allowlist(paths: &NodePaths, center: &FakeCenter) {
    let e = nerve_node::pair::pair(paths, &center.link(), Some("lab"))
        .await
        .expect("pair");
    assert_eq!(e.policy.mode, nerve_policy::Mode::Folder);
    assert!(e.policy.folders.is_empty());
    owner_edit(paths, |c| {
        c.centers[0].policy.mode = nerve_policy::Mode::Allowlist
    })
    .await;
}

/// Changes the config the way the owner does while no daemon runs: through
/// the CLI's settings store, which signs the file. The node refuses a file it
/// did not sign.
async fn owner_edit(paths: &NodePaths, f: impl Fn(&mut NodeConfig)) {
    nerve_node::cli::edit(paths, |c| {
        f(c);
        Ok(())
    })
    .await
    .expect("the owner's edit");
}

/// Accepts the node's link and runs the handshake.
async fn linked(center: &mut FakeCenter) -> Conn<TcpStream> {
    let paired = center.paired().expect("paired");
    let mut inc = center.next_link(WAIT).await.expect("the node dials");
    assert_eq!(inc.node_header, paired.node_id);
    let hello = fake_center::handshake(&mut inc.conn, &center.center_id, &paired)
        .await
        .expect("handshake");
    assert_eq!(hello.node_id, paired.node_id);
    assert!(hello.versions.iter().any(|v| v == "0"));
    inc.conn
}

#[tokio::test(flavor = "multi_thread")]
async fn handshake_describe_and_an_allowed_read() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let home = std::fs::canonicalize(&home).unwrap();
    // In allowlist mode an allow rule lets the read through.
    let node = paired_node_with(dir.path(), &center, |p| {
        p.allow
            .push(format!("fs.read:{}/*", nerve_policy::paths::to_wire(&home)));
    })
    .await;
    let mut conn = linked(&mut center).await;

    let d = conn
        .call("describe", json!({"detail": "full"}), WAIT)
        .await
        .unwrap()
        .expect("describe");
    let caps = d["capabilities"].as_array().expect("caps");
    let cap = |id: &str| caps.iter().find(|c| c["id"] == id);
    // Only what a rule can allow is offered: a rule for reads shows no exec.
    for c in ["node", "fs", "audit"] {
        assert!(cap(c).is_some(), "missing {c}: {d}");
    }
    assert!(cap("exec").is_none(), "no rule covers exec: {d}");
    let fs_actions = cap("fs").unwrap()["actions"].as_object().unwrap();
    assert_eq!(fs_actions.keys().collect::<Vec<_>>(), ["read"]);
    assert!(cap("settings").is_none(), "settings needs the write grant");
    assert_eq!(cap("fs").unwrap()["exposure"], "on");

    let file = home.join("note.txt");
    std::fs::write(&file, "hello center").unwrap();
    let read = conn
        .call(
            "invoke",
            json!({"cap": "fs", "action": "read", "args": {"path": nerve_policy::paths::to_wire(&file)}}),
            WAIT,
        )
        .await
        .unwrap()
        .expect("the folder allows the read");
    assert_eq!(read["content"], "hello center");
    assert_eq!(read["encoding"], "utf8");
    // The rule is for reads; the write is a call no rule allows.
    let e = conn
        .call(
            "invoke",
            json!({"cap": "fs", "action": "write",
                   "args": {"path": nerve_policy::paths::to_wire(&file), "content": "x"}}),
            WAIT,
        )
        .await
        .unwrap()
        .expect_err("no rule allows the write");
    assert_eq!(nerve_conformance::wire::code_of(&e), "forbidden");

    // The local audit log names the center and the decision.
    let log = std::fs::read_to_string(node.paths().audit_log()).unwrap();
    assert!(log.contains("\"allowed\""), "{log}");
    assert!(log.contains("lab"), "{log}");

    node.stop().await;
    assert!(
        conn.ends_within(WAIT).await.is_some(),
        "stop ends the link with bye"
    );
}

/// The next `node.descriptor_changed` on `conn`: its rev.
#[cfg(unix)]
async fn changed_rev(conn: &mut Conn<TcpStream>) -> u64 {
    use nerve_conformance::wire::Recv;
    use nerve_proto::rpc::Message;
    loop {
        match conn.recv(WAIT).await {
            Recv::Msg(Message::Notification { method: m, params }) if m == "event" => {
                if params["cap"] == "node" && params["name"] == "descriptor_changed" {
                    return params["data"]["rev"].as_u64().expect("a rev");
                }
            }
            Recv::Msg(_) => {}
            other => panic!("no descriptor_changed: {other:?}"),
        }
    }
}

/// The tools a center can build: `cap.action` of the full descriptor.
#[cfg(unix)]
async fn offered(conn: &mut Conn<TcpStream>) -> (u64, Vec<String>) {
    let d = conn
        .call("describe", json!({"detail": "full"}), WAIT)
        .await
        .unwrap()
        .expect("describe");
    let mut out = Vec::new();
    for c in d["capabilities"].as_array().unwrap() {
        if matches!(c["id"].as_str(), Some("fs" | "exec")) {
            for a in c["actions"].as_object().unwrap().keys() {
                out.push(format!("{}.{a}", c["id"].as_str().unwrap()));
            }
        }
    }
    (d["rev"].as_u64().expect("a rev"), out)
}

/// Under default deny the center is shown only the actions a rule covers;
/// an added or removed rule moves the rev and the node tells the center.
/// Unix only: the rule reaches the running daemon through its control
/// socket, and Windows has none (the CLI writes the file and the
/// node takes it at its next start, docs/dev/spec/node-local.md §1).
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_rule_edit_changes_what_the_center_is_offered() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let node = paired_node(dir.path(), &center).await;
    let mut conn = linked(&mut center).await;
    let (rev0, tools) = offered(&mut conn).await;
    assert!(tools.is_empty(), "{tools:?}");

    owner_edit(node.paths(), |c| {
        c.centers[0].policy.allow = vec!["exec.run:git *".into()];
    })
    .await;
    let rev1 = changed_rev(&mut conn).await;
    assert_ne!(rev1, rev0);
    assert_eq!(offered(&mut conn).await, (rev1, vec!["exec.run".into()]));

    owner_edit(node.paths(), |c| {
        c.centers[0].policy.allow.clear();
    })
    .await;
    assert_eq!(changed_rev(&mut conn).await, rev0);
    assert_eq!(offered(&mut conn).await, (rev0, vec![]));
    node.stop().await;
}

/// A folder the owner grants while the link is up reaches the center: the
/// node tells it the descriptor changed, and the access block names the
/// folder with its flags, the mode and the account. Unix only, as above.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_folder_grant_through_the_owner_tells_the_center() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let node = paired_node_with(dir.path(), &center, |p| {
        p.mode = nerve_policy::Mode::Folder;
    })
    .await;
    let mut conn = linked(&mut center).await;
    let access = |d: &Value| d["access"].clone();
    let d = conn
        .call("describe", json!({"detail": "summary"}), WAIT)
        .await
        .unwrap()
        .expect("describe");
    assert_eq!(access(&d)["mode"], "folder", "{d}");
    assert!(access(&d).get("folders").is_none(), "{d}");
    // A node run by hand runs its commands as its own user, and says so.
    assert!(
        access(&d)["account"]
            .as_str()
            .is_some_and(|a| !a.is_empty()),
        "{d}"
    );
    let rev0 = d["rev"].as_u64().unwrap();

    let proj = dir.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let proj = std::fs::canonicalize(&proj).unwrap();
    owner_edit(node.paths(), |c| {
        c.centers[0].policy.folders = vec![nerve_policy::config::Folder {
            path: proj.display().to_string(),
            access: nerve_policy::config::Access::parse("rw").unwrap(),
        }];
    })
    .await;
    let rev1 = changed_rev(&mut conn).await;
    assert_ne!(rev1, rev0);
    let d = conn
        .call("describe", json!({"detail": "summary"}), WAIT)
        .await
        .unwrap()
        .expect("describe");
    assert_eq!(d["rev"].as_u64(), Some(rev1));
    assert_eq!(
        access(&d)["folders"],
        json!([{"path": nerve_policy::paths::to_wire(&proj), "access": "rw"}]),
        "{d}"
    );
    node.stop().await;
}

/// Two centers paired with one node in folder mode, each with a folder of
/// its own: each one's descriptor, as its link builds it, names only that
/// center's folder.
#[tokio::test(flavor = "multi_thread")]
async fn each_center_is_told_only_its_own_folders() {
    let dir = tempdir();
    let mut a = FakeCenter::start(false).await.unwrap();
    let mut b = FakeCenter::start(false).await.unwrap();
    let o = options(dir.path());
    nerve_node::pair::pair(&o.paths, &a.link(), Some("lab"))
        .await
        .expect("pair a");
    nerve_node::pair::pair(&o.paths, &b.link(), Some("work"))
        .await
        .expect("pair b");
    let (proj, secret) = (dir.path().join("proj"), dir.path().join("secret"));
    for d in [&proj, &secret] {
        std::fs::create_dir_all(d).unwrap();
    }
    // Where the folder really is, without Windows' `\\?\` prefix.
    let real = |p: &Path| {
        std::path::PathBuf::from(nerve_policy::paths::win::strip_verbatim(
            &std::fs::canonicalize(p).unwrap().display().to_string(),
        ))
    };
    let (proj, secret) = (real(&proj), real(&secret));
    owner_edit(&o.paths, |c| {
        for (e, folder) in c.centers.iter_mut().zip([&proj, &secret]) {
            e.policy.mode = nerve_policy::Mode::Folder;
            e.policy.folders = vec![nerve_policy::config::Folder {
                path: folder.display().to_string(),
                access: nerve_policy::config::Access::parse("rw").unwrap(),
            }];
        }
    })
    .await;
    let node = Daemon::start(o).await.expect("start");
    for (center, mine, other) in [(&mut a, &proj, &secret), (&mut b, &secret, &proj)] {
        let mut conn = linked(center).await;
        let d = conn
            .call("describe", json!({"detail": "summary"}), WAIT)
            .await
            .unwrap()
            .expect("describe");
        let folders: Vec<&str> = d["access"]["folders"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|f| f["path"].as_str())
            .collect();
        assert!(
            folders.contains(&nerve_policy::paths::to_wire(mine).as_str()),
            "{d}"
        );
        let other = nerve_policy::paths::to_wire(other);
        assert!(!d.to_string().contains(&other), "{d}");
    }
    node.stop().await;
}

/// No folder and no rule allows the read, so the node refuses it at once: it
/// does not wait for anyone, and nothing is asked.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_no_rule_allows_is_refused_immediately() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let node = paired_node(dir.path(), &center).await;
    let mut conn = linked(&mut center).await;
    let file = dir.path().join("home").join("x.txt");
    std::fs::write(&file, "x").unwrap();
    // Well inside the 15 s a held call would take to time out the wait.
    let e = conn
        .call(
            "invoke",
            json!({"cap": "fs", "action": "read", "args": {"path": nerve_policy::paths::to_wire(&file)}}),
            Duration::from_secs(5),
        )
        .await
        .unwrap()
        .expect_err("no rule allows the read");
    assert_eq!(nerve_conformance::wire::code_of(&e), "forbidden");

    let log = std::fs::read_to_string(node.paths().audit_log()).unwrap();
    assert!(log.contains("\"forbidden\""), "{log}");
    assert!(!log.contains("\"asked\""), "{log}");
    node.stop().await;
}

/// An `invoke` with a text id is refused before it runs: `exec.signal` and
/// the `exec/exit` event name a call by its number. The same call with a
/// number runs.
#[tokio::test(flavor = "multi_thread")]
async fn an_invoke_with_a_text_id_is_refused() {
    use nerve_conformance::wire::Recv;
    use nerve_proto::rpc::{Id, Message};
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let node = paired_node_with(dir.path(), &center, |p| {
        p.mode = nerve_policy::Mode::User;
    })
    .await;
    let mut conn = linked(&mut center).await;
    let home = nerve_policy::paths::to_wire(&dir.path().join("home"));
    let params = json!({"cap": "fs", "action": "stat", "args": {"path": home}});
    let frame = json!({"jsonrpc": "2.0", "id": "abc", "method": "invoke", "params": params});
    conn.send_raw(&frame.to_string()).await.unwrap();
    let e = loop {
        match conn.recv(WAIT).await {
            Recv::Msg(Message::Error {
                id: Some(Id::Str(s)),
                error,
            }) if s == "abc" => break error,
            Recv::Msg(Message::Result { id, result }) => panic!("{id}: ran: {result}"),
            Recv::Msg(_) => {}
            other => panic!("no answer: {other:?}"),
        }
    };
    assert_eq!(nerve_conformance::wire::code_of(&e), "invalid_request");
    assert!(e.message.contains("whole number"), "{}", e.message);
    let stat = conn.call("invoke", params, WAIT).await.unwrap();
    assert_eq!(stat.expect("a number runs")["type"], "dir");
    node.stop().await;
}

/// A command line longer than the node checks is refused, also with no
/// grant at all, and the audit log says why.
#[tokio::test(flavor = "multi_thread")]
async fn an_overlong_command_line_is_refused_and_audited_with_the_reason() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let node = paired_node(dir.path(), &center).await;
    let mut conn = linked(&mut center).await;
    let command = "a:".repeat(nerve_policy::COMMAND_MAX_BYTES / 2 + 1);
    let e = conn
        .call(
            "invoke",
            json!({"cap": "exec", "action": "run", "args": {"command": command}}),
            Duration::from_secs(5),
        )
        .await
        .unwrap()
        .expect_err("the command line is too long");
    assert_eq!(nerve_conformance::wire::code_of(&e), "forbidden");
    let log = std::fs::read_to_string(node.paths().audit_log()).unwrap();
    let line: Value = log
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .find(|v: &Value| v["action"] == "run")
        .unwrap_or_else(|| panic!("no audit line for the run: {log}"));
    assert_eq!(line["decision"], "forbidden", "{line}");
    let reason = line["reason"].as_str().unwrap_or_default();
    assert!(reason.contains("longer than"), "{line}");
    node.stop().await;
}

/// In folder mode the folders give full access and allow rules change
/// nothing; a deny rule still refuses.
#[tokio::test(flavor = "multi_thread")]
async fn allow_rules_do_not_count_in_folder_mode_and_deny_rules_do() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let home = std::fs::canonicalize(&home).unwrap();
    let inside = home.join("in");
    let elsewhere = dir.path().join("elsewhere");
    std::fs::create_dir_all(&inside).unwrap();
    std::fs::create_dir_all(&elsewhere).unwrap();
    let elsewhere = std::fs::canonicalize(&elsewhere).unwrap();
    for (d, name) in [
        (&inside, "a.txt"),
        (&inside, "secret.txt"),
        (&elsewhere, "b.txt"),
    ] {
        std::fs::write(d.join(name), "x").unwrap();
    }
    let wire = |p: &Path| nerve_policy::paths::to_wire(p);
    let node = paired_node_with(dir.path(), &center, |p| {
        p.mode = nerve_policy::Mode::Folder;
        p.folders.push(nerve_policy::config::Folder {
            path: inside.display().to_string(),
            access: nerve_policy::config::Access::parse("r").unwrap(),
        });
        p.allow.push(format!("fs:{}/*", wire(&elsewhere)));
        p.deny
            .push(format!("fs:{}", wire(&inside.join("secret.txt"))));
    })
    .await;
    let mut conn = linked(&mut center).await;
    let mut read = async |p: &Path| {
        conn.call(
            "invoke",
            json!({"cap": "fs", "action": "read", "args": {"path": wire(p)}}),
            WAIT,
        )
        .await
        .unwrap()
    };
    assert!(read(&inside.join("a.txt")).await.is_ok(), "the folder");
    let e = read(&elsewhere.join("b.txt")).await.unwrap_err();
    assert_eq!(nerve_conformance::wire::code_of(&e), "forbidden");
    let e = read(&inside.join("secret.txt")).await.unwrap_err();
    assert_eq!(nerve_conformance::wire::code_of(&e), "forbidden");
    node.stop().await;
}

/// Starts `sleep 2` under `policy`, sends `exec.signal kill` for it and
/// returns the signal's answer, the run's answer and the audit log.
#[cfg(unix)]
async fn signal_a_sleep(
    policy: impl Fn(&mut nerve_policy::CenterPolicy),
) -> (Result<Value, String>, Value, String) {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let node = paired_node_with(dir.path(), &center, policy).await;
    let mut conn = linked(&mut center).await;
    let run = conn
        .request(
            "invoke",
            json!({"cap": "exec", "action": "run", "args": {"command": "sleep 2"}}),
        )
        .await
        .unwrap();
    // Long enough for the command to start and be known by its call id.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let signal = conn
        .call(
            "invoke",
            json!({"cap": "exec", "action": "signal", "args": {"call": run, "signal": "kill"}}),
            WAIT,
        )
        .await
        .unwrap()
        .map_err(|e| nerve_conformance::wire::code_of(&e));
    let mut others = Vec::new();
    let ran = conn
        .answer(run, WAIT, &mut others)
        .await
        .unwrap()
        .expect("the command ran");
    let log = std::fs::read_to_string(node.paths().audit_log()).unwrap();
    node.stop().await;
    (signal, ran, log)
}

/// Runs `args` as an `exec.run` that is not allowed to finish, and returns
/// the error it ends with and how long it took.
#[cfg(unix)]
async fn run_to_the_limit(conn: &mut Conn<TcpStream>, args: Value) -> (Value, Duration) {
    let started = std::time::Instant::now();
    let e = conn
        .call(
            "invoke",
            json!({"cap": "exec", "action": "run", "args": args}),
            Duration::from_secs(20),
        )
        .await
        .unwrap()
        .expect_err("the command runs past its limit");
    assert_eq!(nerve_conformance::wire::code_of(&e), "timeout", "{e:?}");
    (json!(e.message), started.elapsed())
}

/// A call without `timeout_ms` is ended at the default of the owner's
/// `limits`, one that asks for more at their maximum, and the command's
/// group with it. The `exec.run` text in the descriptor says both numbers.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_command_ends_at_the_default_and_at_the_owners_maximum() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let o = options(dir.path());
    pair_in_allowlist(&o.paths, &center).await;
    owner_edit(&o.paths, |c| {
        c.limits.default_timeout_secs = 1;
        c.limits.max_timeout_secs = 3;
        c.centers[0].policy.allow.push("exec.run:sleep *".into());
    })
    .await;
    let node = Daemon::start(o).await.unwrap();
    let mut conn = linked(&mut center).await;

    let d = conn
        .call("describe", json!({"detail": "full"}), WAIT)
        .await
        .unwrap()
        .expect("describe");
    let text = d["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "exec")
        .map(|c| c["actions"]["run"]["summary"].to_string())
        .expect("exec is offered");
    assert!(
        text.contains("after 1 s when you give none, and never runs longer than 3 s"),
        "{text}"
    );

    // Not asked: the default, 1 s.
    let (said, took) = run_to_the_limit(&mut conn, json!({"command": "sleep 30"})).await;
    assert!(
        said.as_str().unwrap().contains("default limit of 1 s"),
        "{said}"
    );
    assert!(took >= Duration::from_secs(1), "{took:?}");
    // Asked for a minute: the maximum, 3 s, so after the default's second.
    let (said, took) = run_to_the_limit(
        &mut conn,
        json!({"command": "sleep 30", "timeout_ms": 60_000}),
    )
    .await;
    assert!(said.as_str().unwrap().contains("maximum of 3 s"), "{said}");
    assert!(took >= Duration::from_secs(3), "{took:?}");
    // Asked for less than the maximum: what it asked for.
    let (said, _) =
        run_to_the_limit(&mut conn, json!({"command": "sleep 30", "timeout_ms": 500})).await;
    assert!(
        said.as_str().unwrap().contains("timeout_ms (500 ms)"),
        "{said}"
    );
    node.stop().await;
}

/// `exec.signal` goes through the policy like every other action: a deny
/// rule refuses it and the refusal is audited.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_deny_rule_refuses_exec_signal_and_the_audit_says_so() {
    let (signal, ran, log) = signal_a_sleep(|p| {
        p.allow.push("exec.run:sleep *".into());
        p.deny.push("exec.signal".into());
    })
    .await;
    assert_eq!(signal, Err("forbidden".into()), "{log}");
    assert_eq!(ran["exit_code"], 0, "the command was not killed: {ran}");
    let line = log
        .lines()
        .find(|l| l.contains("\"signal\""))
        .unwrap_or_else(|| panic!("no audit line for the signal: {log}"));
    assert!(line.contains("\"forbidden\""), "{line}");

    // An allow rule lets it through, and that is audited too.
    let (signal, ran, log) = signal_a_sleep(|p| {
        p.allow.push("exec.run:sleep *".into());
        p.allow.push("exec.signal".into());
    })
    .await;
    assert_eq!(signal, Ok(json!({})), "{log}");
    assert_eq!(ran["signal"], "kill", "{ran}");
    let line = log
        .lines()
        .find(|l| l.contains("\"signal\""))
        .unwrap_or_else(|| panic!("no audit line for the signal: {log}"));
    assert!(line.contains("\"allowed\""), "{line}");
}

/// Two centers paired in allowlist mode, each allowing the shell script
/// `text` as `sh <its path>`, the node started, and both links up: (node,
/// lab's link, work's link, the command).
#[cfg(unix)]
async fn two_centers_running(
    dir: &Path,
    text: &str,
) -> (Daemon, Conn<TcpStream>, Conn<TcpStream>, String) {
    let mut a = FakeCenter::start(false).await.unwrap();
    let mut b = FakeCenter::start(false).await.unwrap();
    let o = options(dir);
    let script = o.home.join("script.sh");
    std::fs::write(&script, text).unwrap();
    let command = format!("sh {}", script.display());
    nerve_node::pair::pair(&o.paths, &a.link(), Some("lab"))
        .await
        .expect("pair a");
    nerve_node::pair::pair(&o.paths, &b.link(), Some("work"))
        .await
        .expect("pair b");
    owner_edit(&o.paths, |c| {
        for e in c.centers.iter_mut() {
            e.policy.mode = nerve_policy::Mode::Allowlist;
            e.policy.allow.push(format!("exec.run:{command}"));
        }
    })
    .await;
    let node = Daemon::start(o).await.expect("start");
    let (lab, work) = (linked(&mut a).await, linked(&mut b).await);
    // The fake centers' listeners are not needed once linked.
    drop((a, b));
    (node, lab, work, command)
}

/// The `invoke` params that run `command` for the session `session`.
#[cfg(unix)]
fn session_run(command: &str, session: &str) -> Value {
    json!({"cap": "exec", "action": "run", "args": {"command": command},
           "ctx": {"session": session}})
}

/// `stream.open` of `exec`'s `output` for the call `call`, in `session`.
#[cfg(unix)]
fn output_of(call: u64, session: Option<&str>) -> Value {
    let mut p = json!({"cap": "exec", "stream": "output", "params": {"call": call}});
    if let Some(s) = session {
        p["ctx"] = json!({"session": s});
    }
    p
}

/// A running command's output streams only to the session (and the center)
/// its call came from: the same `stream.open` from another session, without
/// one, or from the other center is refused alike. The stream sends what the
/// command printed so far, then the rest, in order, and the node closes it
/// when the command ended.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_commands_output_streams_in_order_to_its_own_session_only() {
    use nerve_conformance::wire::Recv;
    use nerve_proto::Message;
    use nerve_proto::rpc::Id;

    let dir = tempdir();
    let script = "for i in 1 2 3 4 5; do echo line $i; sleep 0.3; done\n";
    let (node, mut lab, mut work, command) = two_centers_running(dir.path(), script).await;
    let run = lab
        .request("invoke", session_run(&command, "s1"))
        .await
        .unwrap();
    // The first line is out before the stream opens: it comes from the tail.
    tokio::time::sleep(Duration::from_millis(450)).await;
    for (on_work, p) in [
        (false, output_of(run, Some("s2"))),
        (false, output_of(run, None)),
        (false, output_of(run + 7, Some("s1"))),
        (true, output_of(run, Some("s1"))),
    ] {
        let conn = if on_work { &mut work } else { &mut lab };
        let mut others = Vec::new();
        let id = conn.request("stream.open", p.clone()).await.unwrap();
        let e = conn
            .answer(id, WAIT, &mut others)
            .await
            .unwrap()
            .expect_err("another session's or center's call");
        assert_eq!(nerve_conformance::wire::code_of(&e), "invalid_args", "{p}");
        assert!(e.message.contains("no running command"), "{e:?}");
    }
    let mut others = Vec::new();
    let id = lab
        .request("stream.open", output_of(run, Some("s1")))
        .await
        .unwrap();
    let sid = lab
        .answer(id, WAIT, &mut others)
        .await
        .unwrap()
        .expect("its own session's call")["sid"]
        .as_u64()
        .unwrap();
    let (mut data, mut seqs, mut ran, mut closed) = (Vec::new(), Vec::new(), None, None);
    while ran.is_none() || closed.is_none() {
        match lab.recv(WAIT).await {
            Recv::Frame(f) => {
                assert_eq!(u64::from(f.id), sid);
                assert_eq!(f.gap_bytes(), None, "nothing is dropped here");
                seqs.push(f.seq);
                data.extend(f.payload);
            }
            Recv::Msg(Message::Result { id, result }) if id == Id::Num(run) => ran = Some(result),
            Recv::Msg(Message::Request { id, method, params }) if method == "stream.close" => {
                assert_eq!(params["sid"].as_u64(), Some(sid));
                assert_eq!(params["reason"], "ended");
                lab.send(&Message::result(id, json!({}))).await.unwrap();
                closed = Some(data.len());
            }
            Recv::Msg(_) => {}
            other => panic!("{other:?}"),
        }
    }
    let want = "line 1\nline 2\nline 3\nline 4\nline 5\n";
    assert_eq!(String::from_utf8(data).unwrap(), want);
    assert_eq!(closed, Some(want.len()), "the close comes after the data");
    assert_eq!(seqs, (0..seqs.len() as u32).collect::<Vec<_>>());
    assert!(seqs.len() > 1, "the lines came as they were printed");
    // The result still carries the output.
    assert_eq!(ran.unwrap()["stdout"], want);
    node.stop().await;
}

/// `stream.close` from the center stops the stream at once, while its
/// command runs on; the node then sends no frame and no close of its own.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn the_centers_stream_close_stops_the_frames() {
    use nerve_conformance::wire::Recv;
    use nerve_proto::Message;

    let dir = tempdir();
    let script = "while true; do echo tick; sleep 0.1; done\n";
    let (node, mut lab, _work, command) = two_centers_running(dir.path(), script).await;
    let run = lab
        .request("invoke", session_run(&command, "s1"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let sid = lab
        .call("stream.open", output_of(run, Some("s1")), WAIT)
        .await
        .unwrap()
        .expect("opened")["sid"]
        .clone();
    // Ticks come.
    let frames = loop {
        match lab.recv(WAIT).await {
            Recv::Frame(f) => break vec![f],
            Recv::Msg(_) => {}
            other => panic!("{other:?}"),
        }
    };
    assert!(frames[0].payload.starts_with(b"tick"));
    let closed = lab
        .call("stream.close", json!({"sid": sid, "reason": "done"}), WAIT)
        .await
        .unwrap();
    assert_eq!(closed, Ok(json!({})));
    lab.take_frames();
    // A second close finds no stream.
    let again = lab
        .call("stream.close", json!({"sid": sid}), WAIT)
        .await
        .unwrap()
        .expect_err("closed already");
    assert_eq!(nerve_conformance::wire::code_of(&again), "unknown_member");
    lab.take_frames();
    let until = tokio::time::Instant::now() + Duration::from_millis(800);
    loop {
        let left = until.saturating_duration_since(tokio::time::Instant::now());
        match lab.recv(left).await {
            Recv::Timeout => break,
            Recv::Frame(f) => panic!("a frame after the close: {f:?}"),
            Recv::Msg(Message::Request { method, .. }) => panic!("the node sent {method}"),
            Recv::Msg(_) => {}
            other => panic!("{other:?}"),
        }
    }
    lab.notify("cancel", json!({"id": run})).await.unwrap();
    node.stop().await;
}

/// A stream opened after its command printed more than the tail starts
/// with a gap frame that counts what came before the tail, then the tail.
/// A link holds at most `limits::STREAMS` streams; one more is `busy`.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_late_stream_starts_with_a_gap_and_a_link_holds_16() {
    use nerve_node::tap::TAIL;

    let dir = tempdir();
    let script = "head -c 70000 /dev/zero | tr '\\0' a; sleep 3\n";
    let (node, mut lab, _work, command) = two_centers_running(dir.path(), script).await;
    let run = lab
        .request("invoke", session_run(&command, "s1"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(600)).await;
    let mut sids = Vec::new();
    for _ in 0..nerve_proto::limits::STREAMS {
        let opened = lab
            .call("stream.open", output_of(run, Some("s1")), WAIT)
            .await
            .unwrap()
            .expect("opened");
        sids.push(opened["sid"].as_u64().unwrap());
    }
    let more = lab
        .call("stream.open", output_of(run, Some("s1")), WAIT)
        .await
        .unwrap()
        .expect_err("one too many");
    assert_eq!(nerve_conformance::wire::code_of(&more), "busy");
    let first: Vec<_> = lab
        .take_frames()
        .into_iter()
        .filter(|f| u64::from(f.id) == sids[0])
        .collect();
    assert_eq!(first[0].seq, 0);
    assert_eq!(first[0].gap_bytes(), Some(70000 - TAIL as u64), "{first:?}");
    let data: Vec<u8> = first[1..].iter().flat_map(|f| f.payload.clone()).collect();
    assert_eq!(data, vec![b'a'; TAIL]);
    lab.notify("cancel", json!({"id": run})).await.unwrap();
    node.stop().await;
}

/// The node's `stream.close` comes after the stream's last frame, also when
/// frames still wait to go out as the command ends.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_streams_close_comes_after_its_last_frame() {
    use nerve_conformance::wire::Recv;
    use nerve_proto::Message;

    let dir = tempdir();
    let script = "sleep 0.5; head -c 1000000 /dev/zero | tr '\\0' b\n";
    let (node, mut lab, _work, command) = two_centers_running(dir.path(), script).await;
    let run = lab
        .request("invoke", session_run(&command, "s1"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let sid = lab
        .call("stream.open", output_of(run, Some("s1")), WAIT)
        .await
        .unwrap()
        .expect("opened")["sid"]
        .as_u64()
        .unwrap();
    // Not read while the command prints and ends: its last frames wait.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let mut got = lab
        .take_frames()
        .iter()
        .map(|f| f.payload.len())
        .sum::<usize>();
    loop {
        match lab.recv(WAIT).await {
            Recv::Frame(f) => {
                assert_eq!(f.gap_bytes(), None);
                got += f.payload.len();
            }
            Recv::Msg(Message::Request { method, params, .. }) if method == "stream.close" => {
                assert_eq!(params["sid"].as_u64(), Some(sid));
                break;
            }
            Recv::Msg(_) => {}
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(got, 1_000_000, "every frame came before the close");
    node.stop().await;
}

/// A stream whose command prints faster than the center reads waits in a
/// queue of its own: the link's own frames, here an event of another call,
/// still get out (protocol §5.5).
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_stream_that_outruns_the_link_leaves_room_for_events() {
    use nerve_conformance::wire::Recv;
    use nerve_proto::Message;
    use nerve_proto::rpc::Id;

    let dir = tempdir();
    // The first run prints without end, the next one ends at once.
    let script =
        "d=$(dirname \"$0\")\n[ -e \"$d/once\" ] && exit 0\ntouch \"$d/once\"\nexec yes streamed\n";
    let (node, mut lab, _work, command) = two_centers_running(dir.path(), script).await;
    lab.call("sub", json!({"topics": ["exec/exit"]}), WAIT)
        .await
        .unwrap()
        .expect("sub");
    let run = lab
        .request("invoke", session_run(&command, "s1"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let sid = lab
        .call("stream.open", output_of(run, Some("s1")), WAIT)
        .await
        .unwrap()
        .expect("opened")["sid"]
        .as_u64()
        .unwrap();
    lab.take_frames();
    // Nothing is read for a while: the connection and the node's queues
    // fill up with the stream.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let quick = lab
        .request("invoke", session_run(&command, "s1"))
        .await
        .unwrap();
    // It ends and its event is sent while the queues are still full.
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let mut exit = false;
    loop {
        match lab.recv(WAIT).await {
            Recv::Frame(f) => assert_eq!(u64::from(f.id), sid),
            Recv::Msg(Message::Notification { method, params })
                if method == "event" && params["data"]["call"] == quick =>
            {
                exit = true
            }
            // The event goes before the result.
            Recv::Msg(Message::Result { id, .. }) if id == Id::Num(quick) => break,
            Recv::Msg(_) => {}
            other => panic!("{other:?}"),
        }
    }
    assert!(exit, "the event of the quick call was dropped");
    lab.notify("cancel", json!({"id": run})).await.unwrap();
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_node_answer_stops_dialling() {
    let dir = tempdir();
    let center = FakeCenter::start(false).await.unwrap();
    let o = options(dir.path());
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .unwrap();
    // A second center that never paired this node answers 401.
    let stranger = FakeCenter::start(false).await.unwrap();
    let url = format!("http://{}", stranger.url.authority());
    owner_edit(&o.paths, |c| c.centers[0].url = url.clone()).await;

    let node = Daemon::start(o).await.unwrap();
    let mut marked = false;
    for _ in 0..100 {
        if node.config().centers[0].unknown {
            marked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        marked,
        "the node marks the center and stops: {}",
        node.status()
    );
    let status = node.status();
    let c: &Value = &status["centers"][0];
    assert_eq!(c["unknown"], true);
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn passes_the_conformance_node_checks() {
    let dir = tempdir();
    let root = dir.path().to_path_buf();
    let running: Arc<Mutex<Option<Daemon>>> = Arc::default();
    let keep = running.clone();
    let report = nerve_conformance::node_part::run(move |link| async move {
        let o = options(&root);
        nerve_node::pair::pair(&o.paths, &link, None).await?;
        let d = Daemon::start(o).await?;
        *keep.lock().unwrap() = Some(d);
        Ok(nerve_conformance::node_part::Setup::default())
    })
    .await;
    let d = running.lock().unwrap().take();
    if let Some(d) = d {
        d.stop().await;
    }
    assert!(report.ok(), "{report}");
}

#[tokio::test(flavor = "multi_thread")]
async fn folder_mode_confines_commands_to_their_folders() {
    // Every Windows has AppContainers; Linux may lack Landlock.
    if !cfg!(windows) && !nerve_sandbox::Confinement::detect().available() {
        eprintln!("skipped: Landlock is not available here");
        return;
    }
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let o = options(dir.path());
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .unwrap();
    let work = dir.path().join("home").join("work");
    std::fs::create_dir_all(&work).unwrap();
    let work = std::fs::canonicalize(&work).unwrap();
    // As the node keeps a folder: on Windows without the `\\?\` prefix.
    let work = PathBuf::from(nerve_policy::paths::win::strip_verbatim(
        &work.display().to_string(),
    ));
    let outside = dir.path().join("outside.txt");
    let secret = dir.path().join("secret.txt");
    std::fs::write(&secret, "the secret").unwrap();
    owner_edit(&o.paths, |c| {
        let p = &mut c.centers[0].policy;
        p.mode = nerve_policy::Mode::Folder;
        p.folders.push(nerve_policy::config::Folder {
            path: work.display().to_string(),
            access: nerve_policy::config::Access::ALL,
        });
    })
    .await;
    let node = Daemon::start(o).await.unwrap();
    let mut conn = linked(&mut center).await;

    let state = conn
        .call("get", json!({"cap": "exec", "keys": ["confinement"]}), WAIT)
        .await
        .unwrap()
        .expect("get");
    let kind = if cfg!(windows) {
        "appcontainer"
    } else {
        "landlock"
    };
    assert!(
        state["confinement"].as_str().unwrap().starts_with(kind),
        "{state}"
    );
    let command = if cfg!(windows) {
        format!(
            "Set-Content inside.txt in; Get-Content -LiteralPath '{}'; Set-Content -LiteralPath '{}' out",
            secret.display(),
            outside.display()
        )
    } else {
        format!(
            "sh -c 'echo in > inside.txt; cat {}; echo out > {}'",
            secret.display(),
            outside.display()
        )
    };
    let r = conn
        .call(
            "invoke",
            json!({"cap": "exec", "action": "run",
                   "args": {"command": command, "cwd": nerve_policy::paths::to_wire(&work)}}),
            WAIT,
        )
        .await
        .unwrap()
        .expect("the command runs");
    assert_ne!(r["exit_code"], 0, "{r}");
    assert_eq!(
        std::fs::read_to_string(work.join("inside.txt"))
            .unwrap_or_else(|e| panic!("{e}: {r}"))
            .trim_end(),
        "in"
    );
    assert!(
        !r["stdout"].as_str().unwrap().contains("the secret"),
        "the read outside the folder was blocked: {r}"
    );
    assert!(
        !outside.exists(),
        "the write outside the folder was blocked"
    );
    node.stop().await;
}

/// Windows folder mode: a command whose working folder is outside the
/// folders is refused and audited, and the folder's grant for the center's
/// AppContainer is there while the folder is, and gone with it.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn windows_folder_grants_follow_the_folders() {
    let icacls = |p: &Path| {
        let o = std::process::Command::new("icacls")
            .arg(p)
            .output()
            .unwrap();
        String::from_utf8_lossy(&o.stdout).into_owned()
    };
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let o = options(dir.path());
    let paths = o.paths.clone();
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .unwrap();
    let real = |p: &Path| {
        PathBuf::from(nerve_policy::paths::win::strip_verbatim(
            &std::fs::canonicalize(p).unwrap().display().to_string(),
        ))
    };
    std::fs::create_dir_all(dir.path().join("home").join("work")).unwrap();
    std::fs::create_dir_all(dir.path().join("elsewhere")).unwrap();
    let work = real(&dir.path().join("home").join("work"));
    let elsewhere = real(&dir.path().join("elsewhere"));
    owner_edit(&o.paths, |c| {
        let p = &mut c.centers[0].policy;
        p.mode = nerve_policy::Mode::Folder;
        p.folders.push(nerve_policy::config::Folder {
            path: work.display().to_string(),
            access: nerve_policy::config::Access::ALL,
        });
    })
    .await;
    assert!(icacls(&work).contains("S-1-15-2-"), "{}", icacls(&work));
    let node = Daemon::start(o).await.unwrap();
    let mut conn = linked(&mut center).await;
    let mut run = async |cwd: &Path| {
        conn.call(
            "invoke",
            json!({"cap": "exec", "action": "run",
                   "args": {"command": "Set-Content here.txt x",
                            "cwd": nerve_policy::paths::to_wire(cwd)}}),
            WAIT,
        )
        .await
        .unwrap()
    };
    let r = run(&work).await.expect("a command in its folder runs");
    assert_eq!(r["exit_code"], 0, "{r}");
    assert!(work.join("here.txt").exists());
    let e = run(&elsewhere).await.unwrap_err();
    assert_eq!(nerve_conformance::wire::code_of(&e), "forbidden");
    assert!(!elsewhere.join("here.txt").exists());
    node.stop().await;
    let log = std::fs::read_to_string(paths.audit_log()).unwrap();
    let refused = log
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|v| v["action"] == "run" && v["decision"] == "forbidden");
    assert!(refused.is_some(), "the refusal is audited: {log}");

    owner_edit(&paths, |c| c.centers[0].policy.folders.clear()).await;
    assert!(!icacls(&work).contains("S-1-15-2-"), "{}", icacls(&work));
}

/// Runs `command` in `cwd` as an `exec.run` and answers its result.
#[cfg(target_os = "linux")]
async fn run_in(conn: &mut Conn<TcpStream>, cwd: &Path, command: &str) -> Value {
    conn.call(
        "invoke",
        json!({"cap": "exec", "action": "run",
               "args": {"command": command, "cwd": cwd.display().to_string()}}),
        WAIT,
    )
    .await
    .unwrap()
    .expect("the command runs")
}

/// A new pairing comes with the guard's deny rules: in user mode, which
/// allows every command, one that drives the node itself is refused, and
/// others run (owner's decision of 2026-10-20).
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_new_pairing_refuses_commands_that_drive_the_node_itself() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();

    let node = paired_node_with(dir.path(), &center, |p| {
        assert_eq!(p.deny, nerve_policy::rules::GUARD.to_vec());
        p.mode = nerve_policy::Mode::User;
    })
    .await;
    let mut conn = linked(&mut center).await;
    let home = dir.path().join("home");
    let r = run_in(&mut conn, &home, "echo fine").await;
    assert_eq!(r["exit_code"], 0, "{r}");
    // A mention in another program's words is data (the text patterns of
    // before refused this one).
    let r = run_in(
        &mut conn,
        &home,
        "echo \"{ sudo systemctl stop nerve-node }\"",
    )
    .await;
    assert_eq!(r["exit_code"], 0, "{r}");
    for (command, rule) in [
        (
            "nerve-node config set machine.user root",
            "guard:node-programs",
        ),
        ("env X=1 nerve-node status", "guard:node-programs"),
        ("cat /etc/nerve/node.toml", "guard:node-paths"),
    ] {
        let r = conn
            .call(
                "invoke",
                json!({"cap": "exec", "action": "run",
                       "args": {"command": command, "cwd": home.display().to_string()}}),
                WAIT,
            )
            .await
            .unwrap();
        let e = r.expect_err(command);
        assert!(
            e.to_string().contains(&format!("is denied ({rule})")),
            "{command}: {e}"
        );
    }
    node.stop().await;
}

/// A command with `w` on a folder replaces a folder inside it, one with
/// rights of its own, by a link to a place no folder names (issue #74). The
/// next command's rules must not grant the nested folder's rights there:
/// Landlock follows a link in a rule's path, so the command would read and
/// write the place the link leads to.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn folder_mode_gives_no_rule_where_a_command_linked_a_nested_folder() {
    if !nerve_sandbox::Confinement::detect().available() {
        eprintln!("skipped: Landlock is not available here");
        return;
    }
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let home = dir.path().join("home");
    let (work, docs) = (home.join("work"), home.join("docs"));
    std::fs::create_dir_all(work.join("bin")).unwrap();
    std::fs::create_dir_all(&docs).unwrap();
    let (work, docs) = (
        std::fs::canonicalize(&work).unwrap(),
        std::fs::canonicalize(&docs).unwrap(),
    );
    let bin = work.join("bin");
    std::fs::write(bin.join("in-bin.txt"), "bin\n").unwrap();
    std::fs::write(docs.join("secret.txt"), "secret\n").unwrap();
    let node = paired_node_with(dir.path(), &center, |p| {
        p.mode = nerve_policy::Mode::Folder;
        for (path, access) in [(&work, "rwx"), (&bin, "rwx")] {
            p.folders.push(nerve_policy::config::Folder {
                path: path.display().to_string(),
                access: nerve_policy::config::Access::parse(access).unwrap(),
            });
        }
    })
    .await;
    let mut conn = linked(&mut center).await;

    // The folders as they were: `bin` is a folder like the rest.
    let r = run_in(&mut conn, &work, "cat bin/in-bin.txt").await;
    assert_eq!(r["exit_code"], 0, "{r}");
    assert_eq!(r["stdout"], "bin\n", "{r}");

    // The command swaps `bin` for a link to `docs`, which `work` allows.
    let swap = format!("rm -rf bin && ln -s {} bin", docs.display());
    let r = run_in(&mut conn, &work, &swap).await;
    assert_eq!(r["exit_code"], 0, "{r}");
    assert!(std::fs::symlink_metadata(&bin).unwrap().is_symlink());

    // The next command gets nothing for `docs` from the rights of `bin`.
    let r = run_in(&mut conn, &work, "cat bin/secret.txt").await;
    assert_ne!(r["exit_code"], 0, "{r}");
    assert!(!r["stdout"].as_str().unwrap().contains("secret"), "{r}");
    let r = run_in(&mut conn, &work, "echo planted > bin/planted.txt").await;
    assert_ne!(r["exit_code"], 0, "{r}");
    assert!(!docs.join("planted.txt").exists());
    // `work` keeps its own rights.
    let r = run_in(&mut conn, &work, "echo fine > fresh.txt").await;
    assert_eq!(r["exit_code"], 0, "{r}");
    assert_eq!(
        std::fs::read_to_string(work.join("fresh.txt")).unwrap(),
        "fine\n"
    );
    node.stop().await;
}

/// A folder mode command that started with the keys in files is counted for as
/// long as its `exec.run` runs: a move of the keys into the keyring is refused
/// meanwhile and nothing moves, and the count is 0 again once the call
/// answered. The count is checked before the move is asked for, so a node that
/// does not count the command fails here without writing to the machine's
/// keyring. The test, not a timer, ends the command, once the refusal was
/// checked: a command that ended on its own before the move was asked for (a
/// slow machine) would let the move go into the real keyring.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn the_keys_do_not_move_into_the_keyring_past_a_running_folder_command() {
    let Some(abi) = nerve_sandbox::Confinement::detect().landlock_abi else {
        eprintln!("skipped: Landlock is not available here");
        return;
    };
    // Below ABI 9 the keys never go into the keyring, whatever runs.
    if abi < 9 {
        eprintln!("skipped: Landlock ABI {abi} here, below 9, keeps the keys in files");
        return;
    }
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let work = dir.path().join("home").join("work");
    std::fs::create_dir_all(&work).unwrap();
    let work = std::fs::canonicalize(&work).unwrap();
    let node = paired_node_with(dir.path(), &center, |p| {
        p.mode = nerve_policy::Mode::Folder;
        p.folders.push(nerve_policy::config::Folder {
            path: work.display().to_string(),
            access: nerve_policy::config::Access::ALL,
        });
    })
    .await;
    let mut conn = linked(&mut center).await;
    let paths = node.paths().clone();
    // Waits for `release`, bounded to about 30 s so a broken test does not
    // hang for good; it fails if it was not released.
    let command = "sh -c 'echo > started; i=0; \
                   while [ ! -e release ] && [ $i -lt 600 ]; do sleep 0.05; i=$((i+1)); done; \
                   [ -e release ]'";
    let run = conn
        .request(
            "invoke",
            json!({"cap": "exec", "action": "run",
                   "args": {"command": command, "cwd": work.display().to_string()}}),
        )
        .await
        .unwrap();
    let started = work.join("started");
    for _ in 0..200 {
        if started.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(started.exists(), "the command did not start");
    assert_eq!(node.open_to_bus(), 1, "the running command is not counted");

    let files = || {
        [
            paths.config_file(),
            paths.config_key(),
            paths.key_file("lab"),
        ]
        .map(|f| std::fs::read(f).unwrap())
    };
    let before = files();
    let e = nerve_node::cli::edit(&paths, |c| {
        c.machine.secret_storage = nerve_policy::config::SecretStorage::Keyring;
        Ok(())
    })
    .await
    .expect_err("the keys moved past a running command");
    assert!(e.contains("1 folder mode command runs"), "{e}");
    assert!(e.contains("nothing was changed"), "{e}");
    assert_eq!(files(), before);
    assert!(!paths.keys_moving().exists());
    assert_eq!(
        node.config().machine.secret_storage,
        nerve_policy::config::SecretStorage::File
    );

    assert_eq!(
        node.open_to_bus(),
        1,
        "the command ended before its release"
    );

    std::fs::write(work.join("release"), b"").unwrap();
    let mut others = Vec::new();
    let ran = conn
        .answer(run, WAIT, &mut others)
        .await
        .unwrap()
        .expect("the command ran");
    assert_eq!(ran["exit_code"], 0, "{ran}");
    assert_eq!(
        node.open_to_bus(),
        0,
        "the command is counted after it ended"
    );
    node.stop().await;
}

/// A walk (`grep`, `find`, `list`) leaves out what a direct read would refuse:
/// a folder inside a readable one that has no `r` stays sealed, while the
/// readable files beside it are still found.
#[tokio::test(flavor = "multi_thread")]
async fn walks_skip_a_nested_folder_without_the_read_flag() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let data = dir.path().join("home").join("data");
    let private = data.join("private");
    std::fs::create_dir_all(private.join("deep")).unwrap();
    let data = std::fs::canonicalize(&data).unwrap();
    let private = data.join("private");
    std::fs::write(data.join("open.txt"), "token: public\n").unwrap();
    std::fs::write(private.join("creds.txt"), "token: classified\n").unwrap();
    std::fs::write(private.join("deep/more.txt"), "token: classified too\n").unwrap();
    let wire = |p: &Path| nerve_policy::paths::to_wire(p);
    let node = paired_node_with(dir.path(), &center, |p| {
        p.mode = nerve_policy::Mode::Folder;
        for (path, access) in [(&data, "r"), (&private, "")] {
            p.folders.push(nerve_policy::config::Folder {
                path: path.display().to_string(),
                access: nerve_policy::config::Access::parse(access).unwrap(),
            });
        }
    })
    .await;
    let mut conn = linked(&mut center).await;
    let mut call = async |action: &str, args: Value| {
        conn.call(
            "invoke",
            json!({"cap": "fs", "action": action, "args": args}),
            WAIT,
        )
        .await
        .unwrap()
    };

    // The direct read is refused, which is the decision the walks must follow.
    let e = call("read", json!({"path": wire(&private.join("creds.txt"))}))
        .await
        .unwrap_err();
    assert_eq!(nerve_conformance::wire::code_of(&e), "forbidden");

    let g = call("grep", json!({"path": wire(&data), "pattern": "token"}))
        .await
        .expect("grep");
    let text = g.to_string();
    assert!(text.contains("open.txt") && text.contains("public"), "{g}");
    assert!(
        !text.contains("classified") && !text.contains("private"),
        "grep reached the sealed folder: {g}"
    );

    let f = call("find", json!({"path": wire(&data), "glob": "**/*.txt"}))
        .await
        .expect("find");
    let text = f.to_string();
    assert!(text.contains("open.txt"), "{f}");
    assert!(
        !text.contains("creds") && !text.contains("more.txt") && !text.contains("private"),
        "find reached the sealed folder: {f}"
    );

    let l = call("list", json!({"path": wire(&data)}))
        .await
        .expect("list");
    let names: Vec<_> = l["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["open.txt"], "{l}");
    node.stop().await;
}

/// A walk passes through a sealed folder to a folder with `r` inside it and
/// finds the files there, but nothing of the sealed folder's own.
#[tokio::test(flavor = "multi_thread")]
async fn walks_reach_a_readable_folder_inside_a_sealed_one() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let data = dir.path().join("home").join("data");
    std::fs::create_dir_all(data.join("private/pub")).unwrap();
    let data = std::fs::canonicalize(&data).unwrap();
    let private = data.join("private");
    let public = private.join("pub");
    std::fs::write(private.join("creds.txt"), "token: classified\n").unwrap();
    std::fs::write(public.join("note.txt"), "token: shared\n").unwrap();
    let wire = |p: &Path| nerve_policy::paths::to_wire(p);
    let node = paired_node_with(dir.path(), &center, |p| {
        p.mode = nerve_policy::Mode::Folder;
        for (path, access) in [(&data, "r"), (&private, ""), (&public, "r")] {
            p.folders.push(nerve_policy::config::Folder {
                path: path.display().to_string(),
                access: nerve_policy::config::Access::parse(access).unwrap(),
            });
        }
    })
    .await;
    let mut conn = linked(&mut center).await;
    let mut call = async |action: &str, args: Value| {
        conn.call(
            "invoke",
            json!({"cap": "fs", "action": action, "args": args}),
            WAIT,
        )
        .await
        .unwrap()
    };

    let g = call("grep", json!({"path": wire(&data), "pattern": "token"}))
        .await
        .expect("grep");
    let paths: Vec<_> = g["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["path"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(paths, [wire(&public.join("note.txt"))], "{g}");

    let f = call("find", json!({"path": wire(&data), "glob": "**/*.txt"}))
        .await
        .expect("find");
    assert_eq!(f["paths"], json!([wire(&public.join("note.txt"))]), "{f}");

    // A listing names its folders, so the sealed one stays out of it.
    let l = call("list", json!({"path": wire(&data)}))
        .await
        .expect("list");
    assert_eq!(l["entries"], json!([]), "{l}");
    node.stop().await;
}

/// Whether process `pid` still runs (a zombie does not count).
#[cfg(target_os = "linux")]
fn running(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| {
        s.rsplit_once(')')
            .is_some_and(|(_, rest)| !rest.trim_start().starts_with('Z'))
    })
}

/// The pid a command wrote to `file`, once it is there.
#[cfg(target_os = "linux")]
async fn pid_in(file: &Path) -> u32 {
    for _ in 0..200 {
        if let Ok(t) = std::fs::read_to_string(file)
            && let Ok(pid) = t.trim().parse()
        {
            return pid;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("no pid in {}", file.display())
}

/// `session.end` stops the commands of that session the way a timeout does:
/// the call fails `cancelled` and its processes are gone within seconds. A
/// command of another session keeps running until its own cancel.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_session_end_stops_the_commands_of_that_session() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let node = paired_node_with(dir.path(), &center, |p| {
        p.mode = nerve_policy::Mode::User;
    })
    .await;
    let mut conn = linked(&mut center).await;
    let home = dir.path().join("home");
    let run = |session: &str, file: &str| {
        json!({"cap": "exec", "action": "run",
               "args": {"command": format!("sleep 30 & echo $! > {file}; wait")},
               "ctx": {"session": session}})
    };
    let ended = conn
        .request("invoke", run("s-ended", "ended.pid"))
        .await
        .unwrap();
    let other = conn
        .request("invoke", run("s-other", "other.pid"))
        .await
        .unwrap();
    let ended_pid = pid_in(&home.join("ended.pid")).await;
    let other_pid = pid_in(&home.join("other.pid")).await;

    conn.notify("session.end", json!({"session": "s-ended"}))
        .await
        .unwrap();
    let mut others = Vec::new();
    let e = conn
        .answer(ended, WAIT, &mut others)
        .await
        .unwrap()
        .expect_err("the session's call ends");
    assert_eq!(nerve_conformance::wire::code_of(&e), "cancelled");
    let gone = |pid| async move {
        for _ in 0..100 {
            if !running(pid) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    };
    assert!(gone(ended_pid).await, "the session's command outlived it");
    assert!(running(other_pid), "another session's command was stopped");

    conn.notify("cancel", json!({"id": other})).await.unwrap();
    let e = conn
        .answer(other, WAIT, &mut others)
        .await
        .unwrap()
        .expect_err("cancelled");
    assert_eq!(nerve_conformance::wire::code_of(&e), "cancelled");
    assert!(
        gone(other_pid).await,
        "a cancelled command outlived its call"
    );
    node.stop().await;
}

/// Accepts the node's link with the handshake of a center that can resume
/// links: `answer` gives the welcome's reply to the node's resume offer.
/// Returns the connection and the offer.
async fn resumable_link(
    center: &mut FakeCenter,
    answer: impl FnOnce(&nerve_proto::msg::Resume) -> nerve_proto::msg::Resumed,
) -> (Conn<TcpStream>, nerve_proto::msg::Resume) {
    let paired = center.paired().expect("paired");
    let mut inc = center.next_link(WAIT).await.expect("the node dials");
    let hello = fake_center::hello(&mut inc.conn, &center.center_id, &paired)
        .await
        .expect("hello");
    let offer = hello.resume.expect("the node offers its link for a resume");
    assert!(nerve_proto::resume::valid_link_id(&offer.link), "{offer:?}");
    fake_center::welcome(&mut inc.conn, Some(answer(&offer)))
        .await
        .expect("welcome");
    (inc.conn, offer)
}

/// A fresh link, with nothing to carry on.
fn fresh(_: &nerve_proto::msg::Resume) -> nerve_proto::msg::Resumed {
    nerve_proto::msg::Resumed {
        resumed: false,
        got: 0,
    }
}

/// Waits up to 5 s for process `pid` to end.
#[cfg(target_os = "linux")]
async fn ends(pid: u32) -> bool {
    for _ in 0..100 {
        if !running(pid) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// A link that drops while a command runs is resumed (spec §4.9): the
/// command runs on, and its result and its `exec/exit` event, sent while the
/// link was down, arrive on the new connection. Only what the center did not
/// read is sent again, and the resumed link takes new calls and acknowledges
/// what it reads.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_dropped_link_resumes_with_the_output_and_the_exit_event() {
    use nerve_conformance::wire::Recv;
    use nerve_proto::rpc::Message;
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let node = paired_node_with(dir.path(), &center, |p| {
        p.mode = nerve_policy::Mode::User;
    })
    .await;
    let home = dir.path().join("home");
    let (mut conn, first) = resumable_link(&mut center, fresh).await;
    assert_eq!(first.got, 0, "{first:?}");

    // The center's counted frames: 1 the sub, 2 the run. The node's: 1 the
    // sub's result, then what the run sends.
    conn.call("sub", json!({"topics": ["exec/exit"]}), WAIT)
        .await
        .unwrap()
        .expect("sub");
    let command = "touch started; while [ ! -e go ]; do sleep 0.05; done; echo resumed-output";
    let run = conn
        .request(
            "invoke",
            json!({"cap": "exec", "action": "run", "args": {"command": command}}),
        )
        .await
        .unwrap();
    for _ in 0..200 {
        if home.join("started").exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(home.join("started").exists(), "the command did not start");

    drop(conn);
    // The command finishes while the link is down.
    tokio::time::sleep(Duration::from_millis(300)).await;
    std::fs::write(home.join("go"), "").unwrap();

    // The center read the sub's result only.
    let (mut conn, again) = resumable_link(&mut center, |_| nerve_proto::msg::Resumed {
        resumed: true,
        got: 1,
    })
    .await;
    assert_eq!(again.link, first.link, "the same link is offered");
    assert_eq!(again.got, 2, "the node read the sub and the run");

    let mut others = Vec::new();
    let ran = conn
        .answer(run, WAIT, &mut others)
        .await
        .unwrap()
        .expect("the command's result");
    assert_eq!(ran["exit_code"], 0, "{ran}");
    assert_eq!(ran["stdout"], "resumed-output\n", "{ran}");
    let exit = |m: &Message| {
        matches!(m, Message::Notification { method, params }
            if method == "event" && params["cap"] == "exec" && params["name"] == "exit")
    };
    let mut seen = others.clone();
    if !seen.iter().any(exit) {
        loop {
            match conn.recv(WAIT).await {
                Recv::Msg(m) if exit(&m) => {
                    seen.push(m);
                    break;
                }
                Recv::Msg(m) => seen.push(m),
                other => panic!("no exec/exit event: {other:?}"),
            }
        }
    }
    let Some(Message::Notification { params: ev, .. }) = seen.iter().find(|m| exit(m)) else {
        unreachable!()
    };
    assert_eq!(ev["data"]["call"], json!(run), "{ev:?}");
    assert_eq!(ev["data"]["exit_code"], 0, "{ev:?}");
    assert_eq!(ev["seq"], 1, "{ev:?}");
    // The sub's result, which the center had read, does not come again.
    assert!(
        !seen.iter().any(|m| matches!(m, Message::Result { .. })),
        "{seen:?}"
    );

    // The resumed link takes new calls, and the node acknowledges the three
    // frames it read of the link within 5 s.
    let d = conn
        .call("describe", json!({"detail": "summary"}), WAIT)
        .await
        .unwrap()
        .expect("describe");
    assert!(d["capabilities"].is_array(), "{d}");
    let ack = loop {
        match conn.recv(Duration::from_secs(10)).await {
            Recv::Msg(Message::Notification { method, params }) if method == "ack" => {
                break params;
            }
            Recv::Msg(_) => continue,
            other => panic!("no ack: {other:?}"),
        }
    };
    assert_eq!(ack["got"], 3, "{ack:?}");
    node.stop().await;
}

/// A stream ends with its connection, also when the link is resumed
/// (spec §4.9): the old stream sends nothing on the new connection, not
/// even once its command prints again, and its sid is unknown there; a new
/// `stream.open` for the same command gets a new sid and its frames from
/// seq 0.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_resumed_link_carries_no_stream() {
    use nerve_conformance::wire::Recv;
    use nerve_proto::Message;
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let node = paired_node_with(dir.path(), &center, |p| {
        p.mode = nerve_policy::Mode::User;
    })
    .await;
    let home = dir.path().join("home");
    let (mut conn, first) = resumable_link(&mut center, fresh).await;
    let command = "touch started; echo tick; while [ ! -e go ]; do sleep 0.05; done; echo after";
    let run = conn
        .request(
            "invoke",
            json!({"cap": "exec", "action": "run", "args": {"command": command}}),
        )
        .await
        .unwrap();
    for _ in 0..200 {
        if home.join("started").exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(home.join("started").exists(), "the command did not start");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let sid = conn
        .call("stream.open", output_of(run, None), WAIT)
        .await
        .unwrap()
        .expect("opened")["sid"]
        .as_u64()
        .unwrap();
    let mut data = conn
        .take_frames()
        .into_iter()
        .flat_map(|f| f.payload)
        .collect::<Vec<u8>>();
    while data != b"tick\n" {
        match conn.recv(WAIT).await {
            Recv::Frame(f) => data.extend(f.payload),
            Recv::Msg(_) => {}
            other => panic!("{other:?}"),
        }
    }

    drop(conn);
    tokio::time::sleep(Duration::from_millis(300)).await;
    // The center read the stream.open's answer.
    let (mut conn, again) = resumable_link(&mut center, |_| nerve_proto::msg::Resumed {
        resumed: true,
        got: 1,
    })
    .await;
    assert_eq!(again.link, first.link, "the same link is offered");
    assert_eq!(again.got, 2, "the node read the run and the stream.open");

    let new = conn
        .call("stream.open", output_of(run, None), WAIT)
        .await
        .unwrap()
        .expect("opened again")["sid"]
        .as_u64()
        .unwrap();
    assert_ne!(new, sid);
    std::fs::write(home.join("go"), "").unwrap();
    let mut frames = conn.take_frames();
    let (mut ran, mut closed) = (false, false);
    while !ran || !closed {
        match conn.recv(WAIT).await {
            Recv::Frame(f) => frames.push(f),
            Recv::Msg(Message::Result { id, .. }) if id == nerve_proto::rpc::Id::Num(run) => {
                ran = true
            }
            Recv::Msg(Message::Request { id, method, params }) if method == "stream.close" => {
                assert_eq!(params["sid"].as_u64(), Some(new), "{params:?}");
                conn.send(&Message::result(id, json!({}))).await.unwrap();
                closed = true;
            }
            Recv::Msg(_) => {}
            other => panic!("{other:?}"),
        }
    }
    assert!(
        frames.iter().all(|f| u64::from(f.id) == new),
        "the old stream sent on: {:?}",
        frames.iter().map(|f| (f.id, f.seq)).collect::<Vec<_>>()
    );
    assert_eq!(frames.first().map(|f| f.seq), Some(0));
    let text: Vec<u8> = frames.into_iter().flat_map(|f| f.payload).collect();
    assert_eq!(text, b"tick\nafter\n");
    let e = conn
        .call("stream.close", json!({"sid": sid}), WAIT)
        .await
        .unwrap()
        .expect_err("the old stream is gone");
    assert_eq!(
        nerve_conformance::wire::code_of(&e),
        "unknown_member",
        "{e:?}"
    );
    node.stop().await;
}

/// A dropped link the center does not resume within the grace ends as
/// without resume: its command is killed, and the next link is a new one.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_link_not_resumed_within_the_grace_ends_its_calls() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let mut o = options(dir.path());
    o.resume_grace = Duration::from_secs(1);
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .expect("pair");
    owner_edit(&o.paths, |c| {
        c.centers[0].policy.mode = nerve_policy::Mode::User
    })
    .await;
    let node = Daemon::start(o).await.expect("start");
    let home = dir.path().join("home");
    let (mut conn, first) = resumable_link(&mut center, fresh).await;
    conn.request(
        "invoke",
        json!({"cap": "exec", "action": "run",
               "args": {"command": "sleep 30 & echo $! > sleep.pid; wait"}}),
    )
    .await
    .unwrap();
    let pid = pid_in(&home.join("sleep.pid")).await;
    drop(conn);

    // The node dials again at once; this center answers only after the
    // grace, and the command is gone by then.
    let paired = center.paired().unwrap();
    let mut inc = center.next_link(WAIT).await.expect("the node dials");
    assert!(ends(pid).await, "the command outlived the grace");
    let hello = fake_center::hello(&mut inc.conn, &center.center_id, &paired)
        .await
        .expect("hello");
    let offer = hello.resume.expect("an offer");
    assert_ne!(offer.link, first.link, "the old link is gone");
    assert_eq!(offer.got, 0, "{offer:?}");
    node.stop().await;
}

/// A center that does not carry the link on (`resumed: false`) ends it: the
/// command started on it is killed at once.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_link_the_center_does_not_resume_ends_its_calls() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let node = paired_node_with(dir.path(), &center, |p| {
        p.mode = nerve_policy::Mode::User;
    })
    .await;
    let home = dir.path().join("home");
    let (mut conn, first) = resumable_link(&mut center, fresh).await;
    let run = conn
        .request(
            "invoke",
            json!({"cap": "exec", "action": "run",
                   "args": {"command": "sleep 30 & echo $! > sleep.pid; wait"}}),
        )
        .await
        .unwrap();
    let pid = pid_in(&home.join("sleep.pid")).await;
    drop(conn);
    assert!(running(pid), "the command runs on while the link is down");

    let (mut conn, again) = resumable_link(&mut center, fresh).await;
    assert_eq!(again.link, first.link);
    assert_eq!(again.got, 1);
    assert!(ends(pid).await, "the command of a link not resumed runs on");
    // Its call is not answered on the new link.
    let mut others = Vec::new();
    conn.call("describe", json!({"detail": "summary"}), WAIT)
        .await
        .unwrap()
        .expect("describe");
    assert!(
        conn.answer(run, Duration::from_millis(500), &mut others)
            .await
            .is_err(),
        "the old call was answered: {others:?}"
    );
    node.stop().await;
}

/// On a link whose center cannot resume (its welcome says nothing of it),
/// a drop ends the calls at once, as in 0.0.1.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn without_resume_a_drop_ends_the_calls_at_once() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let node = paired_node_with(dir.path(), &center, |p| {
        p.mode = nerve_policy::Mode::User;
    })
    .await;
    let home = dir.path().join("home");
    let mut conn = linked(&mut center).await;
    conn.request(
        "invoke",
        json!({"cap": "exec", "action": "run",
               "args": {"command": "sleep 30 & echo $! > sleep.pid; wait"}}),
    )
    .await
    .unwrap();
    let pid = pid_in(&home.join("sleep.pid")).await;
    drop(conn);
    assert!(ends(pid).await, "the command outlived its link");
    node.stop().await;
}

/// An `ack` for frames the node never sent ends the link with
/// `bye protocol_error`.
#[tokio::test(flavor = "multi_thread")]
async fn an_ack_past_what_the_node_sent_is_a_protocol_error() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let node = paired_node(dir.path(), &center).await;
    let (mut conn, _) = resumable_link(&mut center, fresh).await;
    conn.notify("ack", json!({"got": 5})).await.unwrap();
    assert_eq!(
        conn.ends_within(WAIT).await.as_deref(),
        Some("protocol_error")
    );
    node.stop().await;
}

/// An answer larger than the center takes fails its call with `too_large`
/// and leaves the link up: sent, it would break the connection, and a resume
/// would send it again. Escaping makes `\0` six bytes, so 1 MiB of them is
/// over the 4 MiB message limit.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn an_answer_over_the_message_limit_fails_its_call_and_keeps_the_link() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let node = paired_node_with(dir.path(), &center, |p| {
        p.mode = nerve_policy::Mode::User;
    })
    .await;
    let (mut conn, _) = resumable_link(&mut center, fresh).await;
    let e = conn
        .call(
            "invoke",
            json!({"cap": "exec", "action": "run",
                   "args": {"command": "head -c 1048576 /dev/zero"}}),
            WAIT,
        )
        .await
        .expect("the link stays up")
        .expect_err("too large");
    assert_eq!(nerve_conformance::wire::code_of(&e), "too_large", "{e:?}");
    conn.call("describe", json!({"detail": "summary"}), WAIT)
        .await
        .expect("the link stays up")
        .expect("describe");
    node.stop().await;
}

/// A frame from the center that the node's WebSocket cannot take (here one
/// over the 4 MiB message limit) ends the link with `bye protocol_error`
/// instead of parking it: the center would send it again on every resume.
/// The command on the link is killed, and the next link is a new one.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_frame_the_node_cannot_take_ends_a_resumable_link() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let node = paired_node_with(dir.path(), &center, |p| {
        p.mode = nerve_policy::Mode::User;
    })
    .await;
    let home = dir.path().join("home");
    let (mut conn, first) = resumable_link(&mut center, fresh).await;
    conn.request(
        "invoke",
        json!({"cap": "exec", "action": "run",
               "args": {"command": "sleep 30 & echo $! > sleep.pid; wait"}}),
    )
    .await
    .unwrap();
    let pid = pid_in(&home.join("sleep.pid")).await;
    let big = format!(
        "{{\"jsonrpc\":\"2.0\",\"method\":\"x-pad\",\"params\":{{\"pad\":\"{}\"}}}}",
        "x".repeat(4 * 1024 * 1024 + 1)
    );
    // The node may close before the whole frame is written.
    let _ = conn.send_raw(&big).await;
    assert!(conn.ends_within(WAIT).await.is_some(), "the link stays up");
    assert!(ends(pid).await, "the command of the ended link runs on");
    let (_conn, again) = resumable_link(&mut center, fresh).await;
    assert_ne!(again.link, first.link, "the ended link was offered again");
    assert_eq!(again.got, 0, "{again:?}");
    node.stop().await;
}

/// A node in Mode::User whose resumable link dropped while a command ran:
/// the daemon, the dropped link's offer, the command's pid and the next
/// connection the node dialled, with no challenge sent yet.
#[cfg(target_os = "linux")]
async fn a_dropped_link_with_a_command(
    root: &Path,
    center: &mut FakeCenter,
) -> (Daemon, nerve_proto::msg::Resume, u32, fake_center::Incoming) {
    let node = paired_node_with(root, center, |p| {
        p.mode = nerve_policy::Mode::User;
    })
    .await;
    let (mut conn, first) = resumable_link(center, fresh).await;
    conn.call("describe", json!({"detail": "summary"}), WAIT)
        .await
        .unwrap()
        .expect("describe");
    conn.request(
        "invoke",
        json!({"cap": "exec", "action": "run",
               "args": {"command": "sleep 30 & echo $! > sleep.pid; wait"}}),
    )
    .await
    .unwrap();
    let pid = pid_in(&root.join("home").join("sleep.pid")).await;
    drop(conn);
    // The node dials again; the center holds back its challenge, as its
    // duplicate ping does.
    let inc = center.next_link(WAIT).await.expect("the node dials");
    (node, first, pid, inc)
}

/// A lock (`panic`) while the node waits for the challenge of a connection
/// that would resume a dropped link ends that link at once: its command is
/// killed, the hello offers a new link, and the link ends with `bye paused`.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_lock_while_the_node_dials_again_ends_the_dropped_link_at_once() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let (node, first, pid, mut inc) = a_dropped_link_with_a_command(dir.path(), &mut center).await;
    assert!(running(pid), "the parked command runs");
    owner_edit(node.paths(), |c| c.locked = true).await;
    assert!(ends(pid).await, "the command outlived the lock");
    let paired = center.paired().unwrap();
    let hello = fake_center::hello(&mut inc.conn, &center.center_id, &paired)
        .await
        .expect("hello");
    let offer = hello.resume.expect("an offer");
    assert_ne!(offer.link, first.link, "the ended link was offered");
    fake_center::welcome(&mut inc.conn, Some(fresh(&offer)))
        .await
        .expect("welcome");
    assert_eq!(inc.conn.ends_within(WAIT).await.as_deref(), Some("paused"));
    node.stop().await;
}

/// A lock while the node waits for the welcome that answers its resume
/// offer ends the dropped link at once, and a welcome that then carries it
/// on gets `bye paused`.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_lock_while_the_node_waits_for_the_welcome_ends_the_dropped_link_at_once() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let (node, first, pid, mut inc) = a_dropped_link_with_a_command(dir.path(), &mut center).await;
    let paired = center.paired().unwrap();
    let hello = fake_center::hello(&mut inc.conn, &center.center_id, &paired)
        .await
        .expect("hello");
    let offer = hello.resume.expect("an offer");
    assert_eq!(offer.link, first.link);
    assert!(running(pid), "the offered link's command runs");
    owner_edit(node.paths(), |c| c.locked = true).await;
    assert!(ends(pid).await, "the command outlived the lock");
    fake_center::welcome(
        &mut inc.conn,
        Some(nerve_proto::msg::Resumed {
            resumed: true,
            got: 1,
        }),
    )
    .await
    .expect("welcome");
    assert_eq!(inc.conn.ends_within(WAIT).await.as_deref(), Some("paused"));
    node.stop().await;
}

/// A call may ask its command for less than the owner's most, never for
/// more; `status` shows the limits and why this node does not hold them.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_asks_for_limits_up_to_the_owners_most() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let mut o = options(dir.path());
    o.cgroups = Some(Err("no cgroup for this test".into()));
    pair_in_allowlist(&o.paths, &center).await;
    owner_edit(&o.paths, |c| {
        c.centers[0].policy.allow.push("exec.run:echo *".into());
        c.limits.command.memory_mb = 512;
        c.limits.command.memory_max_mb = 1024;
    })
    .await;
    let node = Daemon::start(o).await.expect("start");
    let mut conn = linked(&mut center).await;
    let mut run = async |args: Value| {
        conn.call(
            "invoke",
            json!({"cap": "exec", "action": "run", "args": args}),
            WAIT,
        )
        .await
        .unwrap()
    };
    let r =
        run(json!({"command": "echo ok", "memory_mb": 1024, "cpu_percent": 10, "processes": 8}))
            .await
            .expect("within the most");
    // PowerShell ends the line with \r\n, sh with \n.
    assert_eq!(r["stdout"].as_str().map(str::trim_end), Some("ok"), "{r}");
    assert!(r.get("killed").is_none(), "{r}");
    let e = run(json!({"command": "echo no", "memory_mb": 1025}))
        .await
        .expect_err("more than the most");
    assert_eq!(nerve_conformance::wire::code_of(&e), "invalid_args");
    assert!(e.to_string().contains("at most 1024"), "{e}");
    let e = run(json!({"command": "echo no", "processes": 0}))
        .await
        .expect_err("no process at all");
    assert_eq!(nerve_conformance::wire::code_of(&e), "invalid_args");

    let limits = &node.status()["command_limits"];
    assert_eq!(limits["memory_mb"], 512, "{limits}");
    assert_eq!(limits["memory_max_mb"], 1024, "{limits}");
    assert_eq!(limits["cgroup"], Value::Null, "{limits}");
    assert_eq!(limits["off"], "no cgroup for this test", "{limits}");
    node.stop().await;
}

/// A command the kernel killed for its memory limit: its result says so,
/// and so does the audit log. The cgroups
/// are plain folders here, and the command writes what the kernel would
/// into its `memory.events`; a real one is in the exec tests.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_command_killed_for_its_memory_is_said_in_its_result_and_the_audit() {
    let me = nerve_transport::net::euid();
    if me == 0 {
        eprintln!("skipped: root's own folders are no cgroup without systemd's mark");
        return;
    }
    let dir = tempdir();
    let fake = dir.path().join("cgroup");
    let own = fake.join("node.scope");
    std::fs::create_dir_all(&own).unwrap();
    std::fs::write(fake.join("cgroup.controllers"), "cpu memory pids").unwrap();
    std::fs::write(own.join("cgroup.controllers"), "cpu memory pids").unwrap();
    std::fs::write(own.join("cgroup.procs"), "").unwrap();
    let cgroups =
        nerve_node::cgroup::Cgroups::at(&fake, "/node.scope", std::process::id(), me, &|_| true)
            .expect("plain folders of this user");
    // What the kernel answers once the node turned the controllers on.
    std::fs::write(own.join("cgroup.subtree_control"), "cpu memory pids").unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let mut o = options(dir.path());
    o.cgroups = Some(Ok(Arc::new(cgroups)));
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .expect("pair");
    // User mode runs any command line, unconfined.
    owner_edit(&o.paths, |c| {
        c.centers[0].policy.mode = nerve_policy::Mode::User
    })
    .await;
    let node = Daemon::start(o).await.expect("start");
    let mut conn = linked(&mut center).await;
    let command = format!(
        "for d in {}/cmd-*; do printf 'oom 1\\noom_kill 1\\n' > \"$d/memory.events\"; done; cat \"$d/memory.max\"",
        own.display()
    );
    let r = conn
        .call(
            "invoke",
            json!({"cap": "exec", "action": "run",
                   "args": {"command": command, "memory_mb": 64}}),
            WAIT,
        )
        .await
        .unwrap()
        .expect("it ran");
    // The node set the limit the call asked for.
    assert_eq!(r["stdout"], (64u64 << 20).to_string(), "{r}");
    assert_eq!(r["killed"], "memory", "{r}");
    let why = "the command went past its memory limit of 64 MiB and was killed";
    assert_eq!(r["reason"], why, "{r}");
    let status = node.status();
    assert_eq!(
        status["command_limits"]["cgroup"], "/node.scope",
        "{status}"
    );
    let audit = node.paths().audit_log();
    node.stop().await;
    let log = std::fs::read_to_string(audit).unwrap();
    let killed: Vec<Value> = log
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| v["decision"] == "killed")
        .collect();
    assert_eq!(killed.len(), 1, "{log}");
    assert_eq!(killed[0]["code"], "memory", "{log}");
    assert_eq!(killed[0]["reason"], why, "{log}");
    assert_eq!(killed[0]["target"], command, "{log}");
}
