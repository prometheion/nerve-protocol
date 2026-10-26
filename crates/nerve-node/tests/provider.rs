//! Capability providers on a real node daemon, in process
//! (docs/dev/spec/node-local.md §7): the conformance provider checks, and
//! what the node does beyond them: it refuses another program under an
//! allowed name, lets a provider go when the owner no longer allows it,
//! tells the provider of a cancelled call, and fails a call whose provider
//! left. Linux only: the node tells the attaching program from
//! `/proc/<pid>/exe`.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nerve_conformance::fake_center::{self, FakeCenter};
use nerve_conformance::wire::{Conn, Recv, code_of};
use nerve_node::{Daemon, NodeOptions, NodePaths};
use nerve_policy::NodeConfig;
use nerve_policy::config::{AllowedProvider, SettingsGrant};
use nerve_proto::rpc::Message;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixStream};

const WAIT: Duration = Duration::from_secs(15);

fn options(root: &Path) -> NodeOptions {
    let mut o = NodeOptions::new(NodePaths::new(root.join("config"), root.join("state")));
    o.home = root.join("home");
    std::fs::create_dir_all(&o.home).unwrap();
    o.full_rights = Some(false);
    o
}

/// This test program: what a provider started from here runs.
fn me() -> String {
    std::env::current_exe().unwrap().display().to_string()
}

async fn owner_edit(paths: &NodePaths, f: impl Fn(&mut NodeConfig)) {
    nerve_node::cli::edit(paths, |c| {
        f(c);
        Ok(())
    })
    .await
    .expect("the owner's edit");
}

/// Pairs with `center`, allows `exe` as the provider `desk`, lets `policy`
/// change the center's policy, and starts the daemon.
async fn node(
    root: &Path,
    center: &FakeCenter,
    exe: &str,
    policy: impl Fn(&mut nerve_policy::CenterPolicy),
) -> Daemon {
    let o = options(root);
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .expect("pair");
    owner_edit(&o.paths, |c| {
        c.providers.allowed = vec![AllowedProvider {
            name: "desk".into(),
            exe: exe.into(),
        }];
        // The rules count in allowlist mode; a new pairing is in folder mode.
        c.centers[0].policy.mode = nerve_policy::Mode::Allowlist;
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
    // Answered once the node serves the link, with the rev it compares to:
    // a provider that attaches from now on changes it.
    inc.conn
        .call("describe", json!({"detail": "summary"}), WAIT)
        .await
        .unwrap()
        .expect("describe");
    inc.conn
}

/// A provider's connection.
struct Provider {
    lines: tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
    w: tokio::net::unix::OwnedWriteHalf,
}

impl Provider {
    async fn next(&mut self) -> Option<Value> {
        let line = tokio::time::timeout(WAIT, self.lines.next_line())
            .await
            .expect("a line within 15 s")
            .ok()??;
        Some(serde_json::from_str(&line).unwrap())
    }

    async fn send(&mut self, v: Value) {
        self.w.write_all(format!("{v}\n").as_bytes()).await.unwrap();
    }
}

/// `hello` as the provider `desk` with one capability `lamp` whose
/// action `on` writes: the connection and the node's first answer.
async fn hello(socket: &Path) -> (Provider, Value) {
    let caps = json!([{"id": "lamp", "summary": "A lamp.",
                       "actions": {"on": {"effect": "write"}}}]);
    hello_with(socket, caps).await
}

/// `hello` as the provider `desk` with the capabilities `caps`.
async fn hello_with(socket: &Path, caps: Value) -> (Provider, Value) {
    let token = std::fs::read_to_string(socket.with_file_name("ctl.token")).unwrap();
    let (r, w) = UnixStream::connect(socket).await.unwrap().into_split();
    let mut p = Provider {
        lines: BufReader::new(r).lines(),
        w,
    };
    p.send(json!({"method": "hello", "token": token,
                  "params": {"role": "provider", "name": "desk", "capabilities": caps}}))
        .await;
    let first = p.next().await.expect("an answer");
    (p, first)
}

async fn descriptor_changed(conn: &mut Conn<TcpStream>) {
    loop {
        match conn.recv(WAIT).await {
            Recv::Msg(Message::Notification { method: m, params })
                if m == "event"
                    && params["cap"] == "node"
                    && params["name"] == "descriptor_changed" =>
            {
                return;
            }
            Recv::Msg(_) => {}
            other => panic!("no descriptor_changed: {other:?}"),
        }
    }
}

async fn lamp_listed(conn: &mut Conn<TcpStream>) -> bool {
    lamp(conn).await.is_some()
}

/// The `lamp` capability of the descriptor the center gets now.
async fn lamp(conn: &mut Conn<TcpStream>) -> Option<Value> {
    let d = conn
        .call("describe", json!({"detail": "full"}), WAIT)
        .await
        .unwrap()
        .expect("describe");
    d["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "lamp")
        .cloned()
}

#[tokio::test(flavor = "multi_thread")]
async fn passes_the_conformance_provider_checks() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let running: Arc<Mutex<Option<Daemon>>> = Arc::default();
    let keep = running.clone();
    let report = nerve_conformance::provider_part::run(move |link| async move {
        let o = options(&root);
        nerve_node::pair::pair(&o.paths, &link, None).await?;
        owner_edit(&o.paths, |c| {
            c.centers[0].settings = SettingsGrant::Write;
            c.providers.allowed = vec![AllowedProvider {
                name: "conformance".into(),
                exe: me(),
            }];
        })
        .await;
        let socket = o.paths.ctl_socket();
        let d = Daemon::start(o).await?;
        *keep.lock().unwrap() = Some(d);
        Ok(nerve_conformance::provider_part::Setup {
            socket,
            provider: "conformance".into(),
        })
    })
    .await;
    let d = running.lock().unwrap().take();
    if let Some(d) = d {
        d.stop().await;
    }
    assert!(report.ok(), "{report}");
    assert_eq!(
        report.outcomes.len(),
        nerve_conformance::provider_part::CHECKS.len()
    );
    // Every call to the provider is in the node's audit log: the ones it
    // forwarded as allowed, the refused one with its reason.
    let audit = NodePaths::new(dir.path().join("config"), dir.path().join("state")).audit_log();
    let entries: Vec<Value> = std::fs::read_to_string(audit)
        .unwrap()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .filter(|e: &Value| e["cap"] == "echo")
        .collect();
    let decided = |action: &str, decision: &str| {
        entries.iter().any(|e| {
            e["action"] == action
                && e["decision"] == decision
                && e["target"] == format!("echo.{action}")
        })
    };
    assert!(decided("say", "allowed"), "{entries:?}");
    assert!(decided("fail", "allowed"), "{entries:?}");
    assert!(decided("shout", "forbidden"), "{entries:?}");
}

/// The name alone does not attach: the program on the other end must be the
/// one `providers.allowed` names.
#[tokio::test(flavor = "multi_thread")]
async fn another_program_under_an_allowed_name_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let other = dir.path().join("other-program");
    std::fs::write(&other, "").unwrap();
    let daemon = node(dir.path(), &center, &other.display().to_string(), |_| {}).await;
    let _conn = linked(&mut center).await;
    let (_p, first) = hello(&daemon.paths().ctl_socket()).await;
    let e = first["error"].as_str().expect("refused");
    assert!(e.contains("must be") && e.contains("other-program"), "{e}");
    assert_eq!(daemon.status()["providers"], json!([]));
    daemon.stop().await;
}

/// A provider the owner takes off `providers.allowed` is let go: its
/// connection ends and its capability leaves the descriptor. `status`
/// shows the attached ones.
#[tokio::test(flavor = "multi_thread")]
async fn a_provider_the_owner_no_longer_allows_is_detached() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(dir.path(), &center, &me(), |p| {
        p.mode = nerve_policy::Mode::User;
    })
    .await;
    let mut conn = linked(&mut center).await;
    let (mut p, first) = hello(&daemon.paths().ctl_socket()).await;
    assert_eq!(first["ok"]["capabilities"], json!(["lamp"]), "{first}");
    descriptor_changed(&mut conn).await;
    assert!(lamp_listed(&mut conn).await);
    assert_eq!(
        daemon.status()["providers"],
        json!([{"name": "desk", "capabilities": ["lamp"], "broken": []}])
    );
    let paths = daemon.paths().clone();
    assert!(
        status(&paths)
            .await
            .contains("provider desk attached: lamp")
    );
    owner_edit(&paths, |c| c.providers.allowed.clear()).await;
    assert_eq!(p.next().await, None, "the connection ends");
    descriptor_changed(&mut conn).await;
    assert!(!lamp_listed(&mut conn).await);
    assert_eq!(daemon.status()["providers"], json!([]));
    assert!(!status(&paths).await.contains("provider"));
    daemon.stop().await;
}

/// What `nerve-node status` prints.
async fn status(paths: &NodePaths) -> String {
    status_as(paths, &[]).await
}

/// What `nerve-node status` prints with the flags `extra`.
async fn status_as(paths: &NodePaths, extra: &[&str]) -> String {
    use clap::Parser;
    let mut args = vec![
        "nerve-node".into(),
        "--config-dir".into(),
        paths.config_dir.clone(),
        "--state-dir".into(),
        paths.state_dir.clone(),
        PathBuf::from("status"),
    ];
    args.extend(extra.iter().map(PathBuf::from));
    let cli = nerve_node::cli::Cli::parse_from(args);
    let mut out = Vec::new();
    nerve_node::cli::execute(cli, &mut out).await.unwrap();
    String::from_utf8(out).unwrap()
}

/// A call the center cancels is cancelled at the provider too, and a call
/// whose provider leaves fails `unavailable` at once.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancel_reaches_the_provider_and_a_leaving_provider_fails_its_calls() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(dir.path(), &center, &me(), |p| {
        p.allow.push("lamp.on".into());
    })
    .await;
    let mut conn = linked(&mut center).await;
    let (mut p, _) = hello(&daemon.paths().ctl_socket()).await;
    descriptor_changed(&mut conn).await;

    let call = || json!({"cap": "lamp", "action": "on", "args": {"level": 3}, "ctx": {}});
    let id = conn.request("invoke", call()).await.unwrap();
    let got = p.next().await.expect("the call");
    assert_eq!(got["method"], "invoke");
    assert_eq!(
        got["params"],
        json!({"cap": "lamp", "action": "on", "args": {"level": 3}})
    );
    conn.notify("cancel", json!({"id": id})).await.unwrap();
    let cancel = p.next().await.expect("the cancel");
    assert_eq!(
        cancel,
        json!({"method": "cancel", "params": {"id": got["id"]}})
    );
    let e = conn
        .answer(id, WAIT, &mut Vec::new())
        .await
        .unwrap()
        .expect_err("cancelled");
    assert_eq!(code_of(&e), "cancelled");
    // A late answer to the cancelled call is dropped.
    p.send(json!({"id": got["id"], "ok": {}})).await;

    let id = conn.request("invoke", call()).await.unwrap();
    let _ = p.next().await.expect("the call");
    drop(p);
    let e = conn
        .answer(id, WAIT, &mut Vec::new())
        .await
        .unwrap()
        .expect_err("the provider left");
    assert_eq!(code_of(&e), "unavailable", "{}", e.message);
    daemon.stop().await;
}

/// A change the center makes to its own policy with `settings.set`, in a
/// document of its own (`allow=<rule>` or `caps=<key>` for `on`): the
/// answer.
async fn center_sets(
    conn: &mut Conn<TcpStream>,
    change: &str,
) -> Result<Value, nerve_proto::RpcError> {
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
    let (key, value) = change.split_once('=').unwrap();
    match key {
        "allow" => doc["policy"]["allow"] = json!([value]),
        _ => doc["policy"]["caps"] = json!({value: "on"}),
    }
    conn.call(
        "invoke",
        json!({"cap": "settings", "action": "set", "ctx": {},
               "args": {"document": doc, "if_version": got["version"]}}),
        WAIT,
    )
    .await
    .unwrap()
}

/// The answer of `settings.set` refuses a change only the owner may make.
fn only_the_owner(r: Result<Value, nerve_proto::RpcError>) {
    let e = r.expect_err("refused");
    assert_eq!(code_of(&e), "forbidden");
    assert!(
        e.message
            .contains("only the owner can turn on what senses or actuates"),
        "{}",
        e.message
    );
}

/// A center with the settings grant may not allow or turn on a capability
/// that senses, nor one no provider offers now, nor an action an offered
/// capability does not have now, which may sense once it comes: only the
/// owner may. One that is offered and does not sense, it may.
#[tokio::test(flavor = "multi_thread")]
async fn a_center_may_not_allow_a_sensing_provider_itself() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let o = options(dir.path());
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .unwrap();
    owner_edit(&o.paths, |c| {
        c.centers[0].settings = SettingsGrant::Write;
        c.providers.allowed = vec![AllowedProvider {
            name: "desk".into(),
            exe: me(),
        }];
    })
    .await;
    let daemon = Daemon::start(o).await.unwrap();
    let mut conn = linked(&mut center).await;

    // Nothing offers `camera` yet: a center cannot arm it before it comes.
    for change in ["allow=camera.snap", "caps=camera"] {
        only_the_owner(center_sets(&mut conn, change).await);
    }

    let token =
        std::fs::read_to_string(daemon.paths().ctl_socket().with_file_name("ctl.token")).unwrap();
    let (r, w) = UnixStream::connect(daemon.paths().ctl_socket())
        .await
        .unwrap()
        .into_split();
    let mut p = Provider {
        lines: BufReader::new(r).lines(),
        w,
    };
    let caps = json!([{"id": "camera", "actions": {"snap": {"effect": "sense"}}},
                      {"id": "lamp", "actions": {"on": {"effect": "write"}}}]);
    p.send(json!({"method": "hello", "token": token,
                  "params": {"role": "provider", "name": "desk", "capabilities": caps}}))
        .await;
    // Attached once answered; default deny shows the center nothing of it.
    assert!(p.next().await.unwrap().get("ok").is_some());
    // Nor an action the lamp does not have now: it may sense once it does.
    for change in [
        "allow=camera.snap",
        "caps=camera",
        "allow=lamp.snap",
        "caps=lamp.snap",
    ] {
        only_the_owner(center_sets(&mut conn, change).await);
    }
    let paths: PathBuf = daemon.paths().config_file();
    assert!(!std::fs::read_to_string(&paths).unwrap().contains("camera"));
    assert!(!std::fs::read_to_string(&paths).unwrap().contains("snap"));
    // The lamp is offered and does not sense: its action and the whole of it.
    center_sets(&mut conn, "allow=lamp.on")
        .await
        .expect("allowed");
    assert!(std::fs::read_to_string(&paths).unwrap().contains("lamp.on"));
    center_sets(&mut conn, "caps=lamp").await.expect("allowed");
    daemon.stop().await;
}

/// Actuating is the owner's call as sensing is: a center with the settings
/// grant may not turn on or allow a capability with an action that
/// actuates (a lamp, a lock), nor one of its actions. One that only reads,
/// it may.
#[tokio::test(flavor = "multi_thread")]
async fn a_center_may_not_turn_actuate_on() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let o = options(dir.path());
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .unwrap();
    owner_edit(&o.paths, |c| {
        c.centers[0].settings = SettingsGrant::Write;
        c.providers.allowed = vec![AllowedProvider {
            name: "desk".into(),
            exe: me(),
        }];
    })
    .await;
    let daemon = Daemon::start(o).await.unwrap();
    let mut conn = linked(&mut center).await;
    let caps = json!([{"id": "lamp", "actions": {"set": {"effect": "actuate"},
                                                 "get": {"effect": "read"}}},
                      {"id": "notes", "actions": {"get": {"effect": "read"}}}]);
    let (_p, first) = hello_with(&daemon.paths().ctl_socket(), caps).await;
    assert!(first.get("ok").is_some(), "{first}");
    for change in ["caps=lamp", "caps=lamp.set", "allow=lamp", "allow=lamp.set"] {
        only_the_owner(center_sets(&mut conn, change).await);
    }
    let config = daemon.paths().config_file();
    assert!(!std::fs::read_to_string(&config).unwrap().contains("lamp"));
    center_sets(&mut conn, "caps=notes").await.expect("allowed");
    center_sets(&mut conn, "allow=notes.get")
        .await
        .expect("allowed");
    daemon.stop().await;
}

/// A provider whose program the owner changes in `providers.allowed` is let
/// go too: it was checked against the old one.
#[tokio::test(flavor = "multi_thread")]
async fn a_provider_is_detached_when_the_owner_names_another_program() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(dir.path(), &center, &me(), |p| {
        p.mode = nerve_policy::Mode::User;
    })
    .await;
    let mut conn = linked(&mut center).await;
    let (mut p, first) = hello(&daemon.paths().ctl_socket()).await;
    assert!(first.get("ok").is_some(), "{first}");
    descriptor_changed(&mut conn).await;
    assert!(lamp_listed(&mut conn).await);
    let other = dir.path().join("other-program");
    std::fs::write(&other, "").unwrap();
    let paths = daemon.paths().clone();
    owner_edit(&paths, |c| {
        c.providers.allowed[0].exe = other.display().to_string();
    })
    .await;
    assert_eq!(p.next().await, None, "the connection ends");
    descriptor_changed(&mut conn).await;
    assert!(!lamp_listed(&mut conn).await);
    assert_eq!(daemon.status()["providers"], json!([]));
    daemon.stop().await;
}

/// Two calls with large arguments at once, to a provider that answers one
/// call before it reads the next, both come back: the node keeps reading
/// answers while it writes the next call.
#[tokio::test(flavor = "multi_thread")]
async fn large_calls_at_once_do_not_wedge_a_provider() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(dir.path(), &center, &me(), |p| {
        p.allow.push("lamp.on".into());
    })
    .await;
    let mut conn = linked(&mut center).await;
    let (mut p, _) = hello(&daemon.paths().ctl_socket()).await;
    descriptor_changed(&mut conn).await;
    let big = "x".repeat(300 * 1024);
    let mut ids = Vec::new();
    for i in 0..2 {
        let args = json!({"n": i, "pad": big});
        let call = json!({"cap": "lamp", "action": "on", "args": args, "ctx": {}});
        ids.push(conn.request("invoke", call).await.unwrap());
    }
    let provider = tokio::spawn(async move {
        for _ in 0..2 {
            let call = p.next().await.expect("a call");
            let answer = json!({"id": call["id"], "ok": call["params"]["args"]});
            p.send(answer).await;
        }
        p
    });
    // The two calls race to the provider, so their answers come in either
    // order: one that comes while the other is awaited is kept.
    let mut others = Vec::new();
    for (i, id) in ids.into_iter().enumerate() {
        let early = others.iter().position(
            |m| matches!(m, Message::Result { id: got, .. } if *got == nerve_proto::rpc::Id::Num(id)),
        );
        let v = match early {
            Some(at) => match others.remove(at) {
                Message::Result { result, .. } => result,
                _ => unreachable!(),
            },
            None => conn
                .answer(id, WAIT, &mut others)
                .await
                .unwrap()
                .expect("answered"),
        };
        assert_eq!(v["n"], i);
        assert_eq!(v["pad"].as_str().map(str::len), Some(big.len()));
    }
    drop(provider.await.unwrap());
    daemon.stop().await;
}

/// An action whose schema a center cannot check (here a `oneOf`) is left
/// out of the descriptor, and the provider's other action attaches. The
/// provider's answer, the daemon's status and `nerve-node status` (text and
/// `--json`) name it with the reason.
#[tokio::test(flavor = "multi_thread")]
async fn a_oneof_action_is_left_out_and_status_names_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(dir.path(), &center, &me(), |p| {
        p.mode = nerve_policy::Mode::User;
    })
    .await;
    let mut conn = linked(&mut center).await;
    let level = json!({"type": "object", "properties": {
        "level": {"oneOf": [{"type": "integer"}, {"type": "string"}]}}});
    let caps = json!([{"id": "lamp", "summary": "A lamp.",
                       "actions": {"on": {"effect": "write"},
                                   "dim": {"effect": "write", "params": level}}}]);
    let (_p, first) = hello_with(&daemon.paths().ctl_socket(), caps).await;
    assert_eq!(first["ok"]["capabilities"], json!(["lamp"]), "{first}");
    assert_eq!(first["ok"]["broken"][0]["name"], "lamp.dim", "{first}");
    descriptor_changed(&mut conn).await;
    let lamp = lamp(&mut conn).await.expect("the lamp is listed");
    let actions: Vec<&String> = lamp["actions"].as_object().unwrap().keys().collect();
    assert_eq!(actions, ["on"]);

    let providers = daemon.status()["providers"].clone();
    let broken = &providers[0]["broken"];
    assert_eq!(broken.as_array().map(Vec::len), Some(1), "{providers}");
    assert_eq!(broken[0]["name"], "lamp.dim");
    let reason = broken[0]["reason"].as_str().unwrap();
    assert!(
        reason.starts_with("params: /properties/level/oneOf: ") && reason.contains("alternatives"),
        "{reason}"
    );
    let paths = daemon.paths().clone();
    let text = status(&paths).await;
    assert!(text.contains("provider desk attached: lamp"), "{text}");
    assert!(
        text.contains(&format!("provider desk: lamp.dim left out: {reason}")),
        "{text}"
    );
    let json: Value = serde_json::from_str(&status_as(&paths, &["--json"]).await).unwrap();
    assert_eq!(json["providers"][0]["broken"], *broken, "{json}");
    daemon.stop().await;
}

/// Arguments that do not fit the action's schema are refused by the node
/// with `invalid_args`, naming the field and what it expects, and never
/// reach the provider: the first call it sees is the one that fits.
#[tokio::test(flavor = "multi_thread")]
async fn wrong_args_never_reach_the_provider() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(dir.path(), &center, &me(), |p| {
        p.allow.push("lamp.on".into());
    })
    .await;
    let mut conn = linked(&mut center).await;
    let params = json!({"type": "object", "additionalProperties": false, "required": ["level"],
                        "properties": {"level": {"type": "integer", "minimum": 0, "maximum": 10}}});
    let caps = json!([{"id": "lamp", "summary": "A lamp.",
                       "actions": {"on": {"effect": "write", "params": params}}}]);
    let (mut p, first) = hello_with(&daemon.paths().ctl_socket(), caps).await;
    assert_eq!(first["ok"]["broken"], json!([]), "{first}");
    descriptor_changed(&mut conn).await;

    let call = |args: Value| json!({"cap": "lamp", "action": "on", "args": args, "ctx": {}});
    for (args, field, expected) in [
        (json!({"level": "high"}), "level", "an integer from 0 to 10"),
        (json!({"level": 11}), "level", "an integer from 0 to 10"),
        (json!({}), "level", "an integer from 0 to 10 (required)"),
        (
            json!({"level": 3, "colour": "red"}),
            "colour",
            "no field of this name; known: level",
        ),
    ] {
        let e = conn
            .call("invoke", call(args.clone()), WAIT)
            .await
            .unwrap()
            .expect_err("refused");
        assert_eq!(code_of(&e), "invalid_args", "{args}: {}", e.message);
        let data = e.data.clone().unwrap();
        assert_eq!(data["field"], field, "{args}: {data}");
        assert_eq!(data["expected"], expected, "{args}: {data}");
        assert_eq!(e.message, format!("{field}: expected {expected}"));
    }
    // The first line the provider gets is the call that fits.
    let id = conn
        .request("invoke", call(json!({"level": 3})))
        .await
        .unwrap();
    let got = p.next().await.expect("the call");
    assert_eq!(got["params"]["args"], json!({"level": 3}), "{got}");
    p.send(json!({"id": got["id"], "ok": {"on": true}})).await;
    let v = conn
        .answer(id, WAIT, &mut Vec::new())
        .await
        .unwrap()
        .expect("answered");
    assert_eq!(v, json!({"on": true}));
    // The arguments are checked before the policy, so only the call that fits
    // is decided and audited: the refused ones never show up as allowed.
    let audit = std::fs::read_to_string(daemon.paths().audit_log()).unwrap();
    let decided: Vec<Value> = audit
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|e| e["cap"] == "lamp")
        .collect();
    assert_eq!(decided.len(), 1, "{decided:?}");
    assert_eq!(decided[0]["decision"], "allowed", "{decided:?}");
    daemon.stop().await;
}

/// A provider's action that takes paths (`x-nerve-path`) is held to the
/// folders in folder mode as `fs` is, on a node run by hand, which reads by
/// the folders: a path it reads needs `r`, one it writes `w`, and one left
/// out leaves a write needing `on`. The protected paths and a link that
/// leads out are refused, every decision names the path in the audit, and
/// only an allowed call reaches the provider, with the path the node
/// checked. A call to an action the owner turned off is audited too.
#[tokio::test(flavor = "multi_thread")]
async fn a_path_taking_provider_is_held_to_the_folders() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let (work, ro, outside) = (root.join("work"), root.join("ro"), root.join("outside"));
    let ssh = root.join("home/.ssh");
    for d in [&work, &ro, &outside, &ssh] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(outside.join("secret.txt"), "s").unwrap();
    std::fs::write(ssh.join("id_test"), "k").unwrap();
    std::os::unix::fs::symlink(outside.join("secret.txt"), work.join("link")).unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let folder = |p: &Path, access: &str| nerve_policy::config::Folder {
        path: p.display().to_string(),
        access: nerve_policy::config::Access::parse(access).unwrap(),
    };
    let folders = vec![
        folder(&work, "rw"),
        folder(&ro, "r"),
        folder(&root.join("home"), "rw"),
    ];
    let daemon = node(&root, &center, &me(), |p| {
        p.mode = nerve_policy::Mode::Folder;
        p.folders = folders.clone();
    })
    .await;
    let mut conn = linked(&mut center).await;
    let path = |mark: &str, ty: Value| json!({"type": ty, "x-nerve-path": mark});
    let one = |name: &str, p: Value, required: &[&str]| json!({"type": "object", "properties": {name: p}, "required": required});
    let caps = json!([{"id": "files", "summary": "Files of the desk.", "actions": {
        "open": {"effect": "read", "params": one("path", path("read", json!("string")), &["path"])},
        "save": {"effect": "write", "params": one("path", path("write", json!("string")), &["path"])},
        "tidy": {"effect": "write",
                 "params": one("path", path("write", json!(["string", "null"])), &[])},
        "peek": {"effect": "read", "params": one("path", json!({"type": "string"}), &["path"])}}}]);
    let (mut p, first) = hello_with(&daemon.paths().ctl_socket(), caps).await;
    assert_eq!(first["ok"]["broken"], json!([]), "{first}");
    descriptor_changed(&mut conn).await;
    // The marker is published, and folder mode offers three: a call with
    // its paths in the folders, or `tidy` with none and `on`, could run.
    // `peek` marks no path, so the node could not hold where the program
    // reads: like any read that names no path, it needs `on`.
    let d = conn
        .call("describe", json!({"detail": "full"}), WAIT)
        .await
        .unwrap()
        .unwrap();
    let files = d["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "files")
        .expect("files is listed")
        .clone();
    assert_eq!(
        files["actions"]["open"]["params"]["properties"]["path"]["x-nerve-path"],
        "read"
    );
    let offered: Vec<&String> = files["actions"].as_object().unwrap().keys().collect();
    assert_eq!(offered, ["open", "save", "tidy"]);

    // The provider answers with the arguments it got.
    let seen = Arc::new(Mutex::new(Vec::new()));
    let got = seen.clone();
    let served = tokio::spawn(async move {
        while let Some(call) = p.next().await {
            got.lock().unwrap().push(call["params"].clone());
            p.send(json!({"id": call["id"], "ok": call["params"]["args"]}))
                .await;
        }
    });
    let wire = |p: &Path| p.display().to_string();
    let call = |action: &str, at: Value| json!({"cap": "files", "action": action, "args": {"path": at}, "ctx": {}});
    // Given the long way round, checked and passed on as resolved.
    let given = wire(&work.join("../work/a.txt"));
    let in_work = wire(&work.join("a.txt"));
    let saved = wire(&work.join("b.txt"));
    let secret = wire(&outside.join("secret.txt"));
    let allowed = [("open", &given, &in_work), ("save", &saved, &saved)];
    let refused = [
        (
            "open",
            secret.clone(),
            "outside the folders that allow reading",
        ),
        (
            "save",
            wire(&ro.join("b")),
            "outside the folders that allow writing",
        ),
        (
            "save",
            wire(&outside.join("b")),
            "outside the folders that allow writing",
        ),
        ("open", wire(&ssh.join("id_test")), "is protected"),
        // Resolved, the link is the file it leads to.
        (
            "open",
            wire(&work.join("link")),
            "outside the folders that allow reading",
        ),
        // The provider would read below a folder it is handed, the
        // protected entries in it (`.ssh` and the like) too.
        ("open", wire(&root.join("home")), "holds a protected path"),
    ];
    for (action, at, why) in &refused {
        let e = conn
            .call("invoke", call(action, json!(at)), WAIT)
            .await
            .unwrap()
            .expect_err("refused");
        assert_eq!(code_of(&e), "forbidden", "{action} {at}: {}", e.message);
        assert!(e.message.contains(why), "{action} {at}: {}", e.message);
    }
    // A write that names no path lies in no folder: it needs `on`.
    let e = conn
        .call("invoke", call("tidy", Value::Null), WAIT)
        .await
        .unwrap()
        .expect_err("refused");
    assert!(e.message.contains("touches no folder"), "{}", e.message);
    let e = conn
        .call("invoke", call("peek", json!(secret)), WAIT)
        .await
        .unwrap()
        .expect_err("refused");
    assert!(
        e.message.contains("files.peek touches no folder"),
        "{}",
        e.message
    );
    // A path that does not resolve is refused, and in the audit as given.
    let e = conn
        .call("invoke", call("open", json!("not/absolute")), WAIT)
        .await
        .unwrap()
        .expect_err("refused");
    assert_eq!(code_of(&e), "bad_path", "{}", e.message);
    for (action, at, resolved) in allowed {
        let v = conn
            .call("invoke", call(action, json!(at)), WAIT)
            .await
            .unwrap()
            .expect("allowed");
        assert_eq!(v["path"], json!(resolved));
    }
    // Only the allowed calls reached it, with the paths the node checked.
    let reached: Vec<Value> = seen.lock().unwrap().clone();
    assert_eq!(
        reached
            .iter()
            .map(|c| (c["action"].clone(), c["args"]["path"].clone()))
            .collect::<Vec<_>>(),
        [
            (json!("open"), json!(in_work)),
            (json!("save"), json!(saved))
        ]
    );

    // The owner turns `open` off: the call is refused, and audited too.
    let paths = daemon.paths().clone();
    owner_edit(&paths, |c| {
        c.centers[0]
            .policy
            .caps
            .insert("files.open".into(), nerve_policy::config::CapSetting::Off);
    })
    .await;
    let e = conn
        .call("invoke", call("open", json!(in_work)), WAIT)
        .await
        .unwrap()
        .expect_err("off");
    assert_eq!(code_of(&e), "disabled", "{}", e.message);

    let audit: Vec<Value> = std::fs::read_to_string(paths.audit_log())
        .unwrap()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|e| e["cap"] == "files")
        .collect();
    let entries: Vec<(String, String, String)> = audit
        .iter()
        .map(|e| {
            (
                e["action"].as_str().unwrap().to_string(),
                e["target"].as_str().unwrap().to_string(),
                e["decision"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let mut want: Vec<(String, String, String)> = refused
        .iter()
        .map(|(a, at, _)| (a.to_string(), at.clone(), "forbidden".into()))
        .collect();
    // The link is named as the file it leads to.
    want[4].1 = secret.clone();
    want.push(("tidy".into(), "files.tidy".into(), "forbidden".into()));
    want.push(("peek".into(), "files.peek".into(), "forbidden".into()));
    want.push(("open".into(), "not/absolute".into(), "forbidden".into()));
    want.extend(
        allowed
            .iter()
            .map(|(a, _, at)| (a.to_string(), at.to_string(), "allowed".into())),
    );
    want.push(("open".into(), "files.open".into(), "forbidden".into()));
    assert_eq!(entries, want, "{audit:#?}");
    assert_eq!(audit.last().unwrap()["code"], "disabled");
    let unresolved = audit
        .iter()
        .find(|e| e["target"] == "not/absolute")
        .unwrap();
    assert_eq!(unresolved["code"], "bad_path", "{unresolved}");

    // An `fs` path that does not resolve is in the audit too. Its target
    // is the path where it is as plain as a resolved one, which the audit's
    // rule buttons can make a rule of; else there is none, and the reason
    // names it.
    let fs_read =
        |at: &str| json!({"cap": "fs", "action": "read", "args": {"path": at}, "ctx": {}});
    let fs_audit = || -> Vec<Value> {
        std::fs::read_to_string(paths.audit_log())
            .unwrap()
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|e| e["cap"] == "fs")
            .collect()
    };
    std::os::unix::fs::symlink(root.join("gone"), work.join("dangling")).unwrap();
    let dangling = wire(&work.join("dangling/a.txt"));
    let roundabout = wire(&work.join("missing/../a.txt"));
    for (at, target) in [
        ("not/absolute", ""),
        (roundabout.as_str(), ""),
        (dangling.as_str(), dangling.as_str()),
    ] {
        let e = conn
            .call("invoke", fs_read(at), WAIT)
            .await
            .unwrap()
            .expect_err("refused");
        assert_eq!(code_of(&e), "bad_path", "{}", e.message);
        assert!(e.message.contains(at), "{}", e.message);
        let last = fs_audit().pop().expect("the refusal is audited");
        assert_eq!(
            (&last["target"], &last["code"], &last["reason"]),
            (&json!(target), &json!("bad_path"), &json!(e.message)),
            "{last}"
        );
    }

    // An off `fs` call is in the audit with the path it names, as an
    // allowed one would be, not with the action's name, which the audit's
    // rule buttons would make a rule of.
    owner_edit(&paths, |c| {
        c.centers[0]
            .policy
            .caps
            .insert("fs.read".into(), nerve_policy::config::CapSetting::Off);
    })
    .await;
    let e = conn
        .call("invoke", fs_read(&in_work), WAIT)
        .await
        .unwrap()
        .expect_err("off");
    assert_eq!(code_of(&e), "disabled", "{}", e.message);
    let off = fs_audit().pop().unwrap();
    assert_eq!(
        (&off["action"], &off["target"], &off["code"]),
        (&json!("read"), &json!(in_work), &json!("disabled")),
        "{off}"
    );
    conn.call("invoke", fs_read(&roundabout), WAIT)
        .await
        .unwrap()
        .expect_err("off");
    let off = fs_audit().pop().unwrap();
    assert_eq!(
        (&off["target"], &off["code"]),
        (&json!(""), &json!("disabled"))
    );
    served.abort();
    daemon.stop().await;
}
