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
            attach: nerve_conformance::provider_part::Attach::Token,
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

/// The same checks on the provider socket of the installed node, which tells
/// the program by its account and process and takes no token.
#[tokio::test(flavor = "multi_thread")]
async fn passes_the_conformance_provider_checks_on_the_provider_socket() {
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let running: Arc<Mutex<Option<Daemon>>> = Arc::default();
    let keep = running.clone();
    let report = nerve_conformance::provider_part::run(move |link| async move {
        let (o, _, socket) = installed_options(&root, vec![uid()]);
        nerve_node::pair::pair(&o.paths, &link, None).await?;
        owner_edit(&o.paths, |c| {
            c.centers[0].settings = SettingsGrant::Write;
            c.providers.allowed = vec![AllowedProvider {
                name: "conformance".into(),
                exe: me(),
            }];
        })
        .await;
        let d = Daemon::start(o).await?;
        *keep.lock().unwrap() = Some(d);
        Ok(nerve_conformance::provider_part::Setup {
            socket,
            attach: nerve_conformance::provider_part::Attach::Peer,
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
    let mut words = vec!["status"];
    words.extend(extra);
    cli(paths, &words).await
}

/// What `nerve-node <words>` prints.
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
    // An off command is in the audit with its command line, which an
    // `exec` rule is written for.
    owner_edit(&paths, |c| {
        c.centers[0]
            .policy
            .caps
            .insert("exec.run".into(), nerve_policy::config::CapSetting::Off);
    })
    .await;
    let run = json!({"cap": "exec", "action": "run",
                     "args": {"command": "echo off", "cwd": in_work}, "ctx": {}});
    let e = conn
        .call("invoke", run, WAIT)
        .await
        .unwrap()
        .expect_err("off");
    assert_eq!(code_of(&e), "disabled", "{}", e.message);
    let off = std::fs::read_to_string(paths.audit_log())
        .unwrap()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .rfind(|e| e["cap"] == "exec")
        .expect("the off command is audited");
    assert_eq!(
        (&off["action"], &off["target"], &off["code"]),
        (&json!("run"), &json!("echo off"), &json!("disabled")),
        "{off}"
    );
    served.abort();
    daemon.stop().await;
}

/// A file handed to a provider holds nothing below it, so a deny rule that
/// names places below its folder (`files:**/.env`) refuses the folder and a
/// path a write may make a folder at, not the files beside those places. A
/// path given as a link is refused by the name given: the refusal does not
/// say where it leads (a link of another process under `/proc` leads where
/// that process works), and only the audit does.
#[tokio::test(flavor = "multi_thread")]
async fn a_deny_rule_below_a_folder_leaves_the_files_there_alone() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let work = root.join("work");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(work.join("readme.md"), "r").unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let folders = vec![nerve_policy::config::Folder {
        path: work.display().to_string(),
        access: nerve_policy::config::Access::parse("rw").unwrap(),
    }];
    let daemon = node(&root, &center, &me(), |p| {
        p.mode = nerve_policy::Mode::Folder;
        p.folders = folders.clone();
        p.deny = vec!["files:**/.env".into()];
    })
    .await;
    let mut conn = linked(&mut center).await;
    let path = |mark: &str| {
        json!({"type": "object", "required": ["path"],
                                   "properties": {"path": {"type": "string", "x-nerve-path": mark}}})
    };
    // A link that leads to the folder, by a name shorter than the folder's.
    let away = root.join("w");
    std::os::unix::fs::symlink(&work, &away).unwrap();
    let short = away.display().to_string().len();
    let caps = json!([{"id": "files", "summary": "Files of the desk.", "actions": {
        "open": {"effect": "read", "params": path("read")},
        "save": {"effect": "write", "params": path("write")},
        "peek": {"effect": "read", "params": {"type": "object", "required": ["path"],
                 "properties": {"path": {"type": "string", "maxLength": short,
                                         "x-nerve-path": "read"}}}}}}]);
    let (mut p, first) = hello_with(&daemon.paths().ctl_socket(), caps).await;
    assert_eq!(first["ok"]["broken"], json!([]), "{first}");
    descriptor_changed(&mut conn).await;
    let served = tokio::spawn(async move {
        while let Some(call) = p.next().await {
            p.send(json!({"id": call["id"], "ok": call["params"]["args"]}))
                .await;
        }
    });
    let call = |action: &str, at: &Path| {
        json!({"cap": "files", "action": action,
                                                "args": {"path": at.display().to_string()}, "ctx": {}})
    };
    // A file, there to read or write, and one a read finds missing.
    for (action, at) in [
        ("open", work.join("readme.md")),
        ("save", work.join("readme.md")),
        ("open", work.join("missing.md")),
    ] {
        conn.call("invoke", call(action, &at), WAIT)
            .await
            .unwrap()
            .unwrap_or_else(|e| panic!("{action} {}: {}", at.display(), e.message));
    }
    // The folder, and a new path the program may make a folder at.
    for (action, at) in [("open", work.clone()), ("save", work.join("new"))] {
        let e = conn
            .call("invoke", call(action, &at), WAIT)
            .await
            .unwrap()
            .expect_err("refused");
        assert_eq!(
            e.message,
            format!("{} holds a place that is denied", at.display()),
            "{action}"
        );
    }
    let named = |m: &str| m.contains(&*work.display().to_string());
    let e = conn
        .call("invoke", call("open", &away), WAIT)
        .await
        .unwrap()
        .expect_err("refused");
    assert_eq!(
        e.message,
        format!("{} holds a place that is denied", away.display())
    );
    // Resolved, it no longer fits the program's schema.
    let e = conn
        .call("invoke", call("peek", &away), WAIT)
        .await
        .unwrap()
        .expect_err("refused");
    assert_eq!(code_of(&e), "bad_path", "{}", e.message);
    assert!(!named(&e.message), "{}", e.message);
    let audit = std::fs::read_to_string(daemon.paths().audit_log()).unwrap();
    let last: Vec<Value> = audit
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|e| e["cap"] == "files")
        .collect();
    let (open, peek) = (&last[last.len() - 2], &last[last.len() - 1]);
    assert_eq!(open["target"], json!(work.display().to_string()), "{open}");
    assert!(
        named(peek["reason"].as_str().unwrap()),
        "the audit says where it leads: {peek}"
    );
    served.abort();
    daemon.stop().await;
}

/// A program is handed no more than the node judged. It follows the links
/// in a folder it is handed, so where they lead counts too; a path to write
/// that is itself a link is refused, since the program would act on the
/// place it leads to; the path handed must still fit the program's schema
/// and read as the one judged. A link the node cannot follow refuses the
/// call, and a link that is refused is not followed: no refusal names what
/// lies where it leads. Where folder-mode commands cannot be
/// confined (this test's node runs them unconfined), a program's execute
/// action is neither offered nor run in an `x` folder.
#[tokio::test(flavor = "multi_thread")]
async fn a_program_is_handed_no_more_than_the_node_judged() {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;
    let wire = |p: &Path| p.display().to_string();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let (work, outside) = (root.join("work"), root.join("outside"));
    let ssh = root.join("home/.ssh");
    for d in [
        work.join("plain"),
        work.join("env"),
        work.join("keys"),
        work.join("inner"),
        work.join("chain"),
        work.join("relay"),
        work.join("new"),
        work.join("loop"),
        outside.clone(),
        ssh.clone(),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(work.join("plain/a.txt"), "a").unwrap();
    std::fs::write(outside.join("secret.txt"), "s").unwrap();
    std::fs::write(ssh.join("id_test"), "k").unwrap();
    symlink(outside.join("secret.txt"), work.join("env/.env")).unwrap();
    symlink(&ssh, work.join("keys/ssh")).unwrap();
    symlink(work.join("plain"), work.join("inner/data")).unwrap();
    // A link to a folder in the folders that holds a link out.
    symlink(work.join("relay"), work.join("chain/next")).unwrap();
    symlink(&outside, work.join("relay/out")).unwrap();
    // Where the call may not go, a link the node could not follow.
    symlink(outside.join("loop"), outside.join("loop")).unwrap();
    symlink(work.join("loop/l"), work.join("loop/l")).unwrap();
    // Nothing is there to read, but a write through it makes the place.
    symlink(outside.join("made.txt"), work.join("new/made")).unwrap();
    // A name that is no Unicode, and a link to it.
    let odd = work
        .join("plain")
        .join(std::ffi::OsStr::from_bytes(b"odd\xff"));
    std::fs::write(&odd, "o").unwrap();
    symlink(&odd, work.join("odd")).unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let folders = vec![nerve_policy::config::Folder {
        path: work.display().to_string(),
        access: nerve_policy::config::Access::parse("rwx").unwrap(),
    }];
    let daemon = node(&root, &center, &me(), |p| {
        p.mode = nerve_policy::Mode::Folder;
        p.folders = folders.clone();
    })
    .await;
    let mut conn = linked(&mut center).await;
    let path = |mark: &str| {
        json!({"type": "object", "required": ["path"],
               "properties": {"path": {"type": "string", "x-nerve-path": mark}}})
    };
    let only = wire(&work.join("inner/data"));
    let caps = json!([{"id": "files", "summary": "Files of the desk.", "actions": {
        "open": {"effect": "read", "params": path("read")},
        "save": {"effect": "write", "params": path("write")},
        "build": {"effect": "execute", "params": path("read")},
        "pick": {"effect": "read", "params": {"type": "object", "required": ["path"],
            "properties": {"path": {"type": "string", "x-nerve-path": "read", "enum": [only]}}}}}}]);
    let (mut p, first) = hello_with(&daemon.paths().ctl_socket(), caps).await;
    assert_eq!(first["ok"]["broken"], json!([]), "{first}");
    descriptor_changed(&mut conn).await;
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
    let offered: Vec<&String> = files["actions"].as_object().unwrap().keys().collect();
    assert_eq!(offered, ["open", "pick", "save"]);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let got = seen.clone();
    let served = tokio::spawn(async move {
        while let Some(call) = p.next().await {
            got.lock()
                .unwrap()
                .push(call["params"]["args"]["path"].clone());
            p.send(json!({"id": call["id"], "ok": call["params"]["args"]}))
                .await;
        }
    });
    let call = |action: &str, at: &str| json!({"cap": "files", "action": action, "args": {"path": at}, "ctx": {}});
    let allowed = [
        ("open", wire(&work.join("plain"))),
        ("open", wire(&work.join("inner"))),
        ("open", wire(&work.join("new"))),
        ("save", wire(&work.join("plain"))),
        // Through a link to read it is the place it leads to.
        ("open", wire(&work.join("inner/data"))),
    ];
    for (action, at) in &allowed {
        conn.call("invoke", call(action, at), WAIT)
            .await
            .unwrap()
            .unwrap_or_else(|e| panic!("{action} {at}: {}", e.message));
    }
    let link = |dir: &str, name: &str| {
        format!(
            "{} holds a link ({}) that leads where this call may not reach",
            wire(&work.join(dir)),
            wire(&work.join(dir).join(name))
        )
    };
    let refused = [
        (
            "open",
            wire(&work.join("env")),
            "forbidden",
            link("env", ".env"),
        ),
        (
            "open",
            wire(&work.join("keys")),
            "forbidden",
            link("keys", "ssh"),
        ),
        (
            "open",
            wire(&work.join("chain")),
            "forbidden",
            format!(
                "{} holds a link ({}) that leads where this call may not reach",
                wire(&work.join("chain")),
                wire(&work.join("relay/out"))
            ),
        ),
        (
            "open",
            wire(&work.join("loop")),
            "forbidden",
            format!(
                "{} holds a link ({}) the node cannot follow",
                wire(&work.join("loop")),
                wire(&work.join("loop/l"))
            ),
        ),
        (
            "save",
            wire(&work.join("new")),
            "forbidden",
            link("new", "made"),
        ),
        (
            "save",
            wire(&work.join("inner/data")),
            "bad_path",
            format!(
                "{} is a link; name the place it leads to",
                wire(&work.join("inner/data"))
            ),
        ),
        (
            "pick",
            only.clone(),
            "bad_path",
            // Not where it leads: only the audit says that.
            format!("{only} leads to a path files.pick does not take"),
        ),
        (
            "open",
            wire(&work.join("odd")),
            "bad_path",
            format!(
                "{} leads to a name the program cannot be handed as it is",
                wire(&work.join("odd"))
            ),
        ),
        (
            "build",
            wire(&work.join("plain")),
            "forbidden",
            String::new(),
        ),
    ];
    for (action, at, code, why) in &refused {
        let e = conn
            .call("invoke", call(action, at), WAIT)
            .await
            .unwrap()
            .expect_err("refused");
        assert_eq!(code_of(&e), *code, "{action} {at}: {}", e.message);
        if why.is_empty() {
            assert!(e.message.contains("cannot be confined"), "{}", e.message);
        } else {
            assert_eq!(&e.message, why, "{action} {at}");
        }
    }
    // Only the allowed calls reached it, with the paths it was handed.
    let mut want: Vec<Value> = allowed.iter().map(|(_, at)| json!(at)).collect();
    want[4] = json!(wire(&work.join("plain")));
    assert_eq!(*seen.lock().unwrap(), want);
    // Each refusal is in the audit, with the path given.
    let audit: Vec<(String, String)> = std::fs::read_to_string(daemon.paths().audit_log())
        .unwrap()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|e| e["cap"] == "files" && e["decision"] == "forbidden")
        .map(|e| {
            (
                e["target"].as_str().unwrap().to_string(),
                e["reason"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(audit.len(), refused.len(), "{audit:#?}");
    for ((target, reason), (action, at, _, why)) in audit.iter().zip(&refused) {
        assert_eq!(target, at);
        // The audit says where a path the program does not take leads.
        let why = match *action {
            "pick" => format!(
                "{at} leads to {}, which files.pick does not take",
                wire(&work.join("plain"))
            ),
            _ => why.clone(),
        };
        assert!(why.is_empty() || *reason == why, "{reason}");
    }
    served.abort();
    daemon.stop().await;
}

/// The options of a node in `root` with the owner endpoint the installed
/// node has, for `owners`: `root/run/owner.sock` and the provider socket
/// beside it.
fn installed_options(root: &Path, owners: Vec<u32>) -> (NodeOptions, PathBuf, PathBuf) {
    use nerve_node::owner::{Endpoint, Owners};
    let mut o = options(root);
    let run = root.join("run");
    std::fs::create_dir_all(&run).unwrap();
    let endpoint = Endpoint {
        at: run.join("owner.sock"),
        owners: Owners::Uids(owners),
        program: env!("CARGO_BIN_EXE_nerve-node").into(),
    };
    let (owner_sock, provider_sock) = (endpoint.at.clone(), endpoint.provider_socket());
    o.owners = Some(endpoint);
    (o, owner_sock, provider_sock)
}

fn uid() -> u32 {
    // SAFETY: a plain getter.
    unsafe { libc::getuid() }
}

/// The real path of the `python3` this machine runs, which a test allows as
/// a provider; `None` without one.
fn python() -> Option<String> {
    let o = std::process::Command::new("python3")
        .args([
            "-c",
            "import os, sys; print(os.path.realpath(sys.executable))",
        ])
        .output()
        .ok()?;
    o.status
        .success()
        .then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

/// A python program that sends the provider `desk`'s hello on the socket
/// its first argument names and prints the first line it gets back.
const HELLO_PY: &str = r#"import json, socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
caps = [{"id": "lamp", "actions": {"on": {"effect": "write"}}}]
hello = {"method": "hello", "params": {"role": "provider", "name": "desk", "capabilities": caps}}
try:
    s.sendall((json.dumps(hello) + "\n").encode())
except OSError:
    pass
print(s.makefile().readline())
"#;

/// `hello` as the provider `desk` (one capability `lamp`) on the provider
/// socket `at`, which takes no token: the connection and the first answer.
/// A caller the socket refuses is told before it writes; what it writes then
/// may not arrive.
async fn hello_on(at: &Path) -> (Provider, Value) {
    let (r, mut w) = UnixStream::connect(at).await.unwrap().into_split();
    let caps = json!([{"id": "lamp", "summary": "A lamp.",
                       "actions": {"on": {"effect": "write"}}}]);
    let line = json!({"method": "hello",
                      "params": {"role": "provider", "name": "desk", "capabilities": caps}});
    let _ = w.write_all(format!("{line}\n").as_bytes()).await;
    let mut p = Provider {
        lines: BufReader::new(r).lines(),
        w,
    };
    let first = p.next().await.expect("an answer");
    (p, first)
}

/// On the installed node a program of the owner attaches on the provider
/// socket, which is open to every account and takes no token: the node
/// tells it by the account and the program the kernel names. The socket
/// takes nothing but a hello, and the control socket no hello.
#[tokio::test(flavor = "multi_thread")]
async fn the_owners_program_attaches_on_the_provider_socket() {
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let (o, _, at) = installed_options(&root, vec![uid()]);
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .unwrap();
    owner_edit(&o.paths, |c| {
        c.providers.allowed = vec![AllowedProvider {
            name: "desk".into(),
            exe: me(),
        }];
        c.centers[0].policy.mode = nerve_policy::Mode::User;
    })
    .await;
    let daemon = Daemon::start(o).await.unwrap();
    let mut conn = linked(&mut center).await;
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&at).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o666);
    assert!(!at.with_file_name("ctl.token").exists());
    // The control socket, where only the node's account and root connect,
    // takes no hello here, even with its token.
    let (_c, first) = hello(&daemon.paths().ctl_socket()).await;
    let e = first["error"].as_str().unwrap_or_default();
    assert!(
        e.contains("takes a provider's hello on") && e.contains("provider.sock"),
        "{first}"
    );
    assert_eq!(daemon.status()["providers"], json!([]));

    let (_p, first) = hello_on(&at).await;
    assert_eq!(first["ok"]["capabilities"], json!(["lamp"]), "{first}");
    descriptor_changed(&mut conn).await;
    assert!(lamp_listed(&mut conn).await);

    let s = UnixStream::connect(&at).await.unwrap();
    let e = nerve_transport::ctl::call_on(s, "status", json!({}))
        .await
        .unwrap_err();
    assert!(e.contains("takes a provider's hello only"), "{e}");
    daemon.stop().await;
    assert!(!at.exists(), "the socket goes with the node");
}

/// The provider socket refuses an account that is no owner as it
/// connects, a program other than the allowed one, and a process of a
/// command the node runs, also when it runs the allowed program. One with
/// `no_new_privs`, which a confined command keeps, is refused and told
/// that is why.
#[tokio::test(flavor = "multi_thread")]
async fn the_provider_socket_refuses_others_and_the_commands_of_the_node() {
    let Some(python) = python() else {
        eprintln!("skipped: no python3");
        return;
    };
    // An account that is no owner. Root always is one.
    if uid() != 0 {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let (o, _, at) = installed_options(&root, Vec::new());
        owner_edit(&o.paths, |c| {
            c.providers.allowed = vec![AllowedProvider {
                name: "desk".into(),
                exe: me(),
            }];
        })
        .await;
        let daemon = Daemon::start(o).await.unwrap();
        let (_p, first) = hello_on(&at).await;
        let e = first["error"].as_str().expect("refused");
        assert!(
            e.contains("only the owner of the installed node and root"),
            "{e}"
        );
        assert_eq!(daemon.status()["providers"], json!([]));
        daemon.stop().await;
    }

    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let (o, _, at) = installed_options(&root, vec![uid()]);
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .unwrap();
    let other = root.join("other-program");
    std::fs::write(&other, "").unwrap();
    owner_edit(&o.paths, |c| {
        c.providers.allowed = vec![AllowedProvider {
            name: "desk".into(),
            exe: other.display().to_string(),
        }];
        c.centers[0].policy.mode = nerve_policy::Mode::User;
    })
    .await;
    let paths = o.paths.clone();
    let daemon = Daemon::start(o).await.unwrap();
    let mut conn = linked(&mut center).await;
    // Another program under the allowed name.
    let (_p, first) = hello_on(&at).await;
    let e = first["error"].as_str().expect("refused");
    assert!(e.contains("must be") && e.contains("other-program"), "{e}");

    // From here on the allowed program is python, so only the caller's
    // place refuses it.
    owner_edit(&paths, |c| c.providers.allowed[0].exe = python.clone()).await;
    let script = root.join("hello.py");
    std::fs::write(&script, HELLO_PY).unwrap();
    // A command the center runs (user mode, as the owner).
    let r = conn
        .call(
            "invoke",
            json!({"cap": "exec", "action": "run", "ctx": {},
                   "args": {"command": format!("python3 {} {}", script.display(), at.display())}}),
            WAIT,
        )
        .await
        .unwrap()
        .expect("the command runs");
    let said = r["stdout"].as_str().unwrap_or_default();
    assert!(said.contains("comes from a command the node runs"), "{r}");
    // A process with no_new_privs.
    let mut c = std::process::Command::new("python3");
    c.arg(&script).arg(&at);
    use std::os::unix::process::CommandExt;
    // SAFETY: one plain system call between fork and exec.
    unsafe {
        c.pre_exec(|| {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let o = tokio::task::spawn_blocking(move || c.output())
        .await
        .unwrap()
        .unwrap();
    let said = String::from_utf8_lossy(&o.stdout);
    assert!(said.contains("runs with no_new_privs"), "{said}");
    // The same program as the owner's own process attaches.
    let script_at = (script.clone(), at.clone());
    let o = tokio::task::spawn_blocking(move || {
        std::process::Command::new("python3")
            .arg(&script_at.0)
            .arg(&script_at.1)
            .output()
    })
    .await
    .unwrap()
    .unwrap();
    let said = String::from_utf8_lossy(&o.stdout);
    assert!(said.contains("\"ok\""), "{said}");
    daemon.stop().await;
}

/// A python program that connects to the socket its first argument names,
/// leaves the connection to a child and ends; the child, once its parent
/// is gone, sends the provider `desk`'s hello and prints the answer.
const ENDED_PY: &str = r#"import json, os, socket, sys, time
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
parent = os.getpid()
if os.fork() != 0:
    os._exit(0)
while os.getppid() == parent:
    time.sleep(0.01)
caps = [{"id": "lamp", "actions": {"on": {"effect": "write"}}}]
hello = {"method": "hello", "params": {"role": "provider", "name": "desk", "capabilities": caps}}
s.sendall((json.dumps(hello) + "\n").encode())
print(s.makefile().readline())
"#;

/// A program whose process that connected has ended is refused: its pid
/// may be another process's by then. The node holds on to the process
/// that connected (its pidfd), so the hello its child sends on the same
/// connection is not taken for the allowed program's.
#[tokio::test(flavor = "multi_thread")]
async fn a_program_that_ended_after_it_connected_is_refused() {
    let Some(python) = python() else {
        eprintln!("skipped: no python3");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let (o, _, at) = installed_options(&root, vec![uid()]);
    owner_edit(&o.paths, |c| {
        c.providers.allowed = vec![AllowedProvider {
            name: "desk".into(),
            exe: python.clone(),
        }];
    })
    .await;
    let daemon = Daemon::start(o).await.unwrap();
    let script = root.join("ended.py");
    std::fs::write(&script, ENDED_PY).unwrap();
    // The parent ends at once; the output comes once the child is done.
    let o = tokio::task::spawn_blocking(move || {
        std::process::Command::new("python3")
            .arg(&script)
            .arg(&at)
            .output()
    })
    .await
    .unwrap()
    .unwrap();
    let said = String::from_utf8_lossy(&o.stdout);
    assert!(said.contains(nerve_transport::ctl::PEER_ENDED), "{said}");
    assert_eq!(daemon.status()["providers"], json!([]));
    daemon.stop().await;
}

/// The owner socket and the provider socket each have places of their
/// own: with every place of one held, the other still serves. A provider
/// over the provider socket's places is told the node is busy.
#[tokio::test(flavor = "multi_thread")]
async fn a_full_owner_socket_does_not_block_the_provider_socket_and_the_reverse() {
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let (o, owner_at, at) = installed_options(&root, vec![uid()]);
    owner_edit(&o.paths, |c| {
        c.providers.allowed = vec![AllowedProvider {
            name: "desk".into(),
            exe: me(),
        }];
    })
    .await;
    let daemon = Daemon::start(o).await.unwrap();
    let status = async |at: &Path| {
        let s = UnixStream::connect(at).await.unwrap();
        nerve_transport::ctl::call_on(s, "status", json!({})).await
    };
    let settle = || tokio::time::sleep(Duration::from_millis(300));

    let mut held = Vec::new();
    for _ in 0..nerve_transport::ctl::MAX_CONNECTIONS {
        held.push(UnixStream::connect(&owner_at).await.unwrap());
    }
    settle().await;
    assert_eq!(
        status(&owner_at).await,
        Err(nerve_transport::ctl::BUSY.to_string())
    );
    let (p, first) = hello_on(&at).await;
    assert_eq!(first["ok"]["capabilities"], json!(["lamp"]), "{first}");
    drop((p, held));

    let mut held = Vec::new();
    for _ in 0..nerve_transport::ctl::MAX_PROVIDERS {
        held.push(UnixStream::connect(&at).await.unwrap());
    }
    settle().await;
    let (_p, first) = hello_on(&at).await;
    assert_eq!(first["error"], nerve_transport::ctl::BUSY, "{first}");
    let mut answered = status(&owner_at).await;
    for _ in 0..50 {
        if answered.is_ok() {
            break;
        }
        settle().await;
        answered = status(&owner_at).await;
    }
    assert_eq!(answered, Ok(json!({"running": true})));
    drop(held);
    daemon.stop().await;
}

/// `cap ls` on a running node lists the capabilities of the attached
/// programs too, with their effects and where they come from, an action the
/// node left out with its reason, and which allowed program is attached;
/// `cap provider ls` says the same of the programs.
#[tokio::test(flavor = "multi_thread")]
async fn cap_ls_lists_what_the_attached_programs_offer() {
    let dir = tempfile::tempdir().unwrap();
    let center = FakeCenter::start(false).await.unwrap();
    // Allowlist mode: a rule lets `fs.read` in, none `fs.write`.
    let daemon = node(dir.path(), &center, &me(), |p| {
        p.caps
            .insert("lamp.on".into(), nerve_policy::config::CapSetting::Off);
        p.caps
            .insert("exec.run".into(), nerve_policy::config::CapSetting::Hidden);
        p.allow.push("fs.read".into());
    })
    .await;
    let paths = daemon.paths().clone();
    owner_edit(&paths, |c| {
        c.providers.allowed.push(AllowedProvider {
            name: "fan".into(),
            exe: "/usr/bin/fan".into(),
        });
    })
    .await;
    let caps = json!([{"id": "lamp", "summary": "A lamp.", "actions": {
        "on": {"effect": "actuate", "summary": "Switches it on."},
        "dim": {"effect": "write", "params": {"type": "object", "properties": {
            "level": {"oneOf": [{"type": "integer"}, {"type": "string"}]}}}}}}]);
    let (_p, first) = hello_with(&paths.ctl_socket(), caps).await;
    assert_eq!(first["ok"]["capabilities"], json!(["lamp"]), "{first}");

    let ls = cli(&paths, &["cap", "ls"]).await;
    let words = |name: &str| {
        ls.lines()
            .find(|l| l.split_whitespace().next() == Some(name))
            .unwrap_or_else(|| panic!("no {name}: {ls}"))
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    };
    // Each center: whether it may use the action now, and the switch.
    assert_eq!(
        words("lamp.on"),
        "lamp.on actuate program desk lab: off (set off)"
    );
    assert!(
        words("lamp.dim")
            .starts_with("lamp.dim - program desk left out: params: /properties/level/oneOf"),
        "{ls}"
    );
    assert_eq!(words("fs.read"), "fs.read read built-in lab: on");
    assert_eq!(words("fs.write"), "fs.write write built-in lab: off");
    assert_eq!(words("exec.run"), "exec.run execute built-in lab: hidden");
    assert!(!ls.contains("does not run"), "{ls}");
    assert!(
        ls.contains(&format!("program desk: {}, attached", me())),
        "{ls}"
    );
    assert!(
        ls.contains("program fan: /usr/bin/fan, not attached"),
        "{ls}"
    );

    let v: Value = serde_json::from_str(&cli(&paths, &["--json", "cap", "ls"]).await).unwrap();
    let on = v["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "lamp.on")
        .unwrap();
    assert_eq!(
        *on,
        json!({"name": "lamp.on", "effect": "actuate", "source": "program desk",
               "summary": "Switches it on.", "centers": {"lab": "off"},
               "now": {"lab": "off"}})
    );
    let read = v["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "fs.read")
        .unwrap();
    assert_eq!(read["centers"], json!({"lab": "default"}), "{v}");
    assert_eq!(read["now"], json!({"lab": "on"}), "{v}");
    assert_eq!(v["running"], true, "{v}");
    let v: Value =
        serde_json::from_str(&cli(&paths, &["--json", "cap", "provider", "ls"]).await).unwrap();
    assert_eq!(
        v,
        json!({"running": true, "programs": [
            {"name": "desk", "exe": me(), "attached": true},
            {"name": "fan", "exe": "/usr/bin/fan", "attached": false}]})
    );
    daemon.stop().await;
}

/// The helper the installed node starts as root to tell which program of
/// root asks (`__provider-check`, crate::provider::check_main): for a
/// process its account may look at it says the program, whether it is the
/// one allowed, whether it runs with no_new_privs, and its parents. The
/// node reads exactly these keys; anything else refuses root's program.
#[test]
fn the_root_helper_says_what_a_process_runs() {
    let node = env!("CARGO_BIN_EXE_nerve-node");
    let ask = |args: &[&str]| -> Value {
        let out = std::process::Command::new(node)
            .arg("__provider-check")
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        serde_json::from_slice(&out.stdout).expect("one JSON answer")
    };
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let pid = child.id().to_string();
    let sleep = std::fs::read_link(format!("/proc/{pid}/exe")).unwrap();
    let v = ask(&[&pid, sleep.to_str().unwrap()]);
    assert_eq!(v["running"], sleep.to_str().unwrap(), "{v}");
    assert_eq!(v["same"], true, "{v}");
    assert_eq!(v["nnp"], false, "{v}");
    assert_eq!(v["chain"][0], child.id(), "{v}");
    assert_eq!(v["chain"][1], std::process::id(), "{v}");
    let v = ask(&[&pid, "/bin/sh"]);
    assert_eq!(v["same"], false, "{v}");
    let v = ask(&[&pid]);
    assert!(
        v["error"].as_str().is_some_and(|e| e.starts_with("usage:")),
        "{v}"
    );
    child.kill().unwrap();
    child.wait().unwrap();
}

/// The capability `sensors` of the provider `desk`: a state key, an event
/// and a stream, each of which senses.
fn sensors() -> Value {
    json!([{"id": "sensors", "summary": "The board's sensors.",
            "state": {"temperature": {"effect": "sense", "schema": {"type": "number"}}},
            "events": {"alarm": {"effect": "sense",
                                 "data": {"type": "object", "properties": {
                                     "level": {"type": "integer"}}}}},
            "streams": {"feed": {"effect": "sense",
                                 "params": {"type": "object", "properties": {
                                     "every_ms": {"type": "integer"}},
                                     "additionalProperties": false}}}}])
}

/// Two centers, `lab` and `work`, in folder mode, each with `sensors`
/// turned on by the owner (what senses needs it), and the provider `desk`
/// attached with [`sensors`]: the node, both links and the provider.
async fn two_centers_with_sensors(
    root: &Path,
) -> (Daemon, Conn<TcpStream>, Conn<TcpStream>, Provider) {
    two_centers_with_sensors_as(options(root)).await
}

/// [`two_centers_with_sensors`] of a node started with `o`.
async fn two_centers_with_sensors_as(
    o: NodeOptions,
) -> (Daemon, Conn<TcpStream>, Conn<TcpStream>, Provider) {
    let mut a = FakeCenter::start(false).await.unwrap();
    let mut b = FakeCenter::start(false).await.unwrap();
    nerve_node::pair::pair(&o.paths, &a.link(), Some("lab"))
        .await
        .expect("pair a");
    nerve_node::pair::pair(&o.paths, &b.link(), Some("work"))
        .await
        .expect("pair b");
    owner_edit(&o.paths, |c| {
        c.providers.allowed = vec![AllowedProvider {
            name: "desk".into(),
            exe: me(),
        }];
        for e in c.centers.iter_mut() {
            e.policy
                .caps
                .insert("sensors".into(), nerve_policy::config::CapSetting::On);
        }
    })
    .await;
    let daemon = Daemon::start(o).await.expect("start");
    let (mut lab, mut work) = (linked(&mut a).await, linked(&mut b).await);
    let (p, first) = hello_with(&daemon.paths().ctl_socket(), sensors()).await;
    assert_eq!(first["ok"]["capabilities"], json!(["sensors"]), "{first}");
    descriptor_changed(&mut lab).await;
    descriptor_changed(&mut work).await;
    (daemon, lab, work, p)
}

/// The events and state changes of `cap` that came to `conn` while it
/// waited for the answer to a `describe`: what the node sent it before.
async fn notes_of(conn: &mut Conn<TcpStream>, cap: &str) -> Vec<Value> {
    let id = conn
        .request("describe", json!({"detail": "summary"}))
        .await
        .unwrap();
    let mut others = Vec::new();
    conn.answer(id, WAIT, &mut others)
        .await
        .unwrap()
        .expect("describe");
    others
        .into_iter()
        .filter_map(|m| match m {
            Message::Notification { method: m, params }
                if (m == "event" || m == "state") && params["cap"] == cap =>
            {
                Some(json!({"method": m, "params": params}))
            }
            _ => None,
        })
        .collect()
}

/// A program's state key, events and state changes go to a center whose
/// policy allows them, and never to one whose policy does not: the node
/// cuts each event as it comes (not only the subscription), so a center
/// the owner takes `on` from gets nothing more, while its subscription
/// stays. Its `get` is decided and audited like a call, and only an
/// allowed one reaches the program, which gets the keys asked for.
#[tokio::test(flavor = "multi_thread")]
async fn a_programs_events_and_state_reach_only_the_centers_that_may_have_them() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, mut lab, mut work, mut p) = two_centers_with_sensors(dir.path()).await;
    let c = lamp_or(&mut lab, "sensors")
        .await
        .expect("lab sees sensors");
    assert_eq!(c["state"]["temperature"]["effect"], "sense", "{c}");
    assert_eq!(c["events"]["alarm"]["effect"], "sense", "{c}");
    assert_eq!(c["streams"]["feed"]["effect"], "sense", "{c}");

    for conn in [&mut lab, &mut work] {
        let sub = json!({"topics": ["sensors/alarm", "sensors/state"],
                         "ctx": {"session": "s-1"}});
        conn.call("sub", sub, WAIT).await.unwrap().expect("sub");
    }
    p.send(json!({"cap": "sensors", "event": "alarm", "data": {"level": 1}}))
        .await;
    p.send(json!({"cap": "sensors", "state": {"temperature": 20.5, "made_up": 1}}))
        .await;
    for conn in [&mut lab, &mut work] {
        let mut notes = notes_of(conn, "sensors").await;
        // The node may send them after the answer; wait for the rest.
        while notes.len() < 2 {
            match conn.recv(WAIT).await {
                Recv::Msg(Message::Notification { method: m, params })
                    if params["cap"] == "sensors" =>
                {
                    notes.push(json!({"method": m, "params": params}))
                }
                Recv::Msg(_) => {}
                other => panic!("no event: {other:?}"),
            }
        }
        assert_eq!(notes[0]["params"]["name"], "alarm", "{notes:?}");
        assert_eq!(notes[0]["params"]["data"], json!({"level": 1}));
        assert_eq!(
            notes[1]["params"]["changed"],
            json!({"temperature": 20.5}),
            "only a declared key: {notes:?}"
        );
    }

    // The owner takes `on` from `work`: sensing needs it, so `work` gets
    // nothing of `sensors` from now on, though it stays subscribed.
    let paths = daemon.paths().clone();
    owner_edit(&paths, |c| {
        c.center_mut("work").unwrap().policy.caps.clear();
    })
    .await;
    descriptor_changed(&mut work).await;
    p.send(json!({"cap": "sensors", "event": "alarm", "data": {"level": 2}}))
        .await;
    p.send(json!({"cap": "sensors", "state": {"temperature": 21.0}}))
        .await;
    let mut got = Vec::new();
    while got.len() < 2 {
        match lab.recv(WAIT).await {
            Recv::Msg(Message::Notification { method: m, params })
                if params["cap"] == "sensors" =>
            {
                got.push((m, params))
            }
            Recv::Msg(_) => {}
            other => panic!("no event: {other:?}"),
        }
    }
    assert_eq!(got[0].1["data"], json!({"level": 2}));
    assert_eq!(got[1].1["changed"], json!({"temperature": 21.0}));
    assert_eq!(notes_of(&mut work, "sensors").await, Vec::<Value>::new());

    // `get`: `work` is refused before the program hears of it, `lab` gets
    // the key it asked for and no other.
    let e = work
        .call(
            "get",
            json!({"cap": "sensors", "keys": ["temperature"], "ctx": {"session": "s-2"}}),
            WAIT,
        )
        .await
        .unwrap()
        .expect_err("work may not read it");
    assert_eq!(code_of(&e), "forbidden", "{}", e.message);
    let id = lab
        .request(
            "get",
            json!({"cap": "sensors", "keys": ["temperature"], "ctx": {"session": "s-1"}}),
        )
        .await
        .unwrap();
    let asked = p.next().await.expect("the get");
    assert_eq!(asked["method"], "get", "work's get never came: {asked}");
    assert_eq!(
        asked["params"],
        json!({"cap": "sensors", "keys": ["temperature"]})
    );
    p.send(json!({"id": asked["id"], "ok": {"temperature": 21.0, "other": 3}}))
        .await;
    let got = lab
        .answer(id, WAIT, &mut Vec::new())
        .await
        .unwrap()
        .expect("lab reads it");
    assert_eq!(got, json!({"temperature": 21.0}));
    let e = lab
        .call("get", json!({"cap": "sensors", "keys": ["humidity"]}), WAIT)
        .await
        .unwrap()
        .expect_err("no such key");
    assert_eq!(code_of(&e), "unknown_member");

    // Both reads and both subscriptions are in the audit, with the session.
    let audit: Value = serde_json::from_str(&cli(&paths, &["--json", "audit"]).await).unwrap();
    let entries = audit["entries"].as_array().unwrap();
    for (center, action, decision, session) in [
        ("lab", "alarm", "allowed", "s-1"),
        ("work", "alarm", "allowed", "s-1"),
        ("work", "temperature", "forbidden", "s-2"),
        ("lab", "temperature", "allowed", "s-1"),
    ] {
        assert!(
            entries.iter().any(|e| e["center"] == center
                && e["cap"] == "sensors"
                && e["action"] == action
                && e["decision"] == decision
                && e["session"] == session),
            "{center} {action}: {audit}"
        );
    }
    daemon.stop().await;
}

/// A subscription to a program's capability is decided and audited unit by
/// unit: `cap/state` each state key, `cap/*` each event and key, and an
/// event the program does not declare is refused. An `unsub` only takes
/// away: it is taken also once the program left, so the node holds no
/// subscription the center gave up, and the program's next attach sends
/// that center nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_subscription_is_decided_unit_by_unit_and_an_unsub_is_always_taken() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, mut lab, mut work, p) = two_centers_with_sensors(dir.path()).await;
    let paths = daemon.paths().clone();
    let sub = |topic: &str, session: &str| json!({"topics": [topic], "ctx": {"session": session}});
    let e = lab
        .call("sub", sub("sensors/later", "s-0"), WAIT)
        .await
        .unwrap()
        .expect_err("no such event");
    assert_eq!(code_of(&e), "unknown_member", "{}", e.message);
    // `work` keeps the alarm only: its state key is refused.
    owner_edit(&paths, |c| {
        let caps = &mut c.center_mut("work").unwrap().policy.caps;
        caps.clear();
        caps.insert("sensors.alarm".into(), nerve_policy::config::CapSetting::On);
    })
    .await;
    descriptor_changed(&mut work).await;
    for topic in ["sensors/state", "sensors/*"] {
        let e = work
            .call("sub", sub(topic, "s-w"), WAIT)
            .await
            .unwrap()
            .expect_err("work may not have the state");
        assert_eq!(code_of(&e), "forbidden", "{topic}: {}", e.message);
    }
    work.call("sub", sub("sensors/alarm", "s-w"), WAIT)
        .await
        .unwrap()
        .expect("work may have the alarm");
    lab.call("sub", sub("sensors/*", "s-all"), WAIT)
        .await
        .unwrap()
        .expect("lab may");
    let audit: Value = serde_json::from_str(&cli(&paths, &["--json", "audit"]).await).unwrap();
    let entries = audit["entries"].as_array().unwrap();
    for action in ["alarm", "temperature"] {
        assert!(
            entries.iter().any(|e| e["center"] == "lab"
                && e["action"] == action
                && e["decision"] == "allowed"
                && e["session"] == "s-all"),
            "{action}: {audit}"
        );
    }

    // The program leaves; the center gives up its subscription, and the
    // node takes that though the capability is gone.
    drop(p);
    descriptor_changed(&mut lab).await;
    lab.call("unsub", json!({"topics": ["sensors/*"]}), WAIT)
        .await
        .unwrap()
        .expect("an unsub of a capability that went");
    let (mut p, _) = hello_with(&daemon.paths().ctl_socket(), sensors()).await;
    descriptor_changed(&mut lab).await;
    p.send(json!({"cap": "sensors", "event": "alarm", "data": {"level": 1}}))
        .await;
    // A subscription of `lab`'s made after it: the earlier event came first.
    lab.call("sub", sub("sensors/state", "s-1"), WAIT)
        .await
        .unwrap()
        .expect("sub");
    p.send(json!({"cap": "sensors", "state": {"temperature": 20.5}}))
        .await;
    loop {
        match lab.recv(WAIT).await {
            Recv::Msg(Message::Notification { method: m, params })
                if params["cap"] == "sensors" =>
            {
                assert_eq!(m, "state", "the alarm after the unsub came: {params:?}");
                break;
            }
            Recv::Msg(_) => {}
            other => panic!("no state change: {other:?}"),
        }
    }
    daemon.stop().await;
}

/// The capability's own `off` or `hidden` counts over its units' `on`, as
/// for a call: a center subscribed while it could have them gets no more
/// events or state changes once the owner turns the whole capability off
/// or hides it, though `sensors.alarm` itself is still `on`.
#[tokio::test(flavor = "multi_thread")]
async fn a_capability_turned_off_or_hidden_gives_none_though_its_units_are_on() {
    use nerve_policy::config::CapSetting;
    let dir = tempfile::tempdir().unwrap();
    let (daemon, mut lab, mut work, mut p) = two_centers_with_sensors(dir.path()).await;
    let paths = daemon.paths().clone();
    owner_edit(&paths, |c| {
        let caps = &mut c.center_mut("lab").unwrap().policy.caps;
        caps.insert("sensors.alarm".into(), CapSetting::On);
        caps.insert("sensors.temperature".into(), CapSetting::On);
    })
    .await;
    for conn in [&mut lab, &mut work] {
        let sub = json!({"topics": ["sensors/alarm", "sensors/state"],
                         "ctx": {"session": "s-1"}});
        conn.call("sub", sub, WAIT).await.unwrap().expect("sub");
    }
    for (level, setting) in [(1, CapSetting::Off), (2, CapSetting::Hidden)] {
        owner_edit(&paths, |c| {
            let caps = &mut c.center_mut("lab").unwrap().policy.caps;
            caps.insert("sensors".into(), setting);
        })
        .await;
        p.send(json!({"cap": "sensors", "event": "alarm", "data": {"level": level}}))
            .await;
        p.send(json!({"cap": "sensors", "state": {"temperature": 20.5}}))
            .await;
        // `work` gets both: the node took them before `lab`'s describe.
        let mut got = 0;
        while got < 2 {
            match work.recv(WAIT).await {
                Recv::Msg(Message::Notification { params, .. }) if params["cap"] == "sensors" => {
                    got += 1
                }
                Recv::Msg(_) => {}
                other => panic!("no event: {other:?}"),
            }
        }
        assert_eq!(
            notes_of(&mut lab, "sensors").await,
            Vec::<Value>::new(),
            "{setting:?}"
        );
    }
    daemon.stop().await;
}

/// A program's stream: `stream.open` is decided like a call of
/// `cap.stream` with its params (which must fit their schema), then
/// forwarded to the program; what it sends of the stream comes to the
/// center as the stream's frames, in order, and the stream ends when the
/// program ends it, when the center closes it (the program is told), and
/// when the program's connection ends.
#[tokio::test(flavor = "multi_thread")]
async fn a_programs_stream_is_forwarded_and_ends_with_its_connection() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, mut lab, mut work, mut p) = two_centers_with_sensors(dir.path()).await;
    let open = |params: Value| {
        json!({"cap": "sensors", "stream": "feed", "params": params,
               "ctx": {"session": "s-1"}})
    };
    let e = lab
        .call("stream.open", open(json!({"every_ms": "often"})), WAIT)
        .await
        .unwrap()
        .expect_err("params that do not fit");
    assert_eq!(code_of(&e), "invalid_args", "{}", e.message);

    // One the program ends.
    let id = lab
        .request("stream.open", open(json!({"every_ms": 100})))
        .await
        .unwrap();
    let asked = p.next().await.expect("the stream.open");
    assert_eq!(asked["method"], "stream.open");
    assert_eq!(
        asked["params"],
        json!({"cap": "sensors", "stream": "feed", "params": {"every_ms": 100}})
    );
    let n = asked["id"].clone();
    p.send(json!({"id": n, "ok": {}})).await;
    let sid = lab
        .answer(id, WAIT, &mut Vec::new())
        .await
        .unwrap()
        .unwrap()["sid"]
        .as_u64()
        .unwrap() as u32;
    p.send(json!({"stream": n, "data": "one\n"})).await;
    p.send(json!({"stream": n, "data": "two\n"})).await;
    p.send(json!({"stream": n, "end": true})).await;
    let (text, reason) = stream_of(&mut lab, sid).await;
    assert_eq!((text.as_str(), reason.as_str()), ("one\ntwo\n", "ended"));

    // One the center closes: the program is told.
    let id = lab.request("stream.open", open(json!({}))).await.unwrap();
    let asked = p.next().await.expect("the stream.open");
    p.send(json!({"id": asked["id"], "ok": {}})).await;
    let sid = lab
        .answer(id, WAIT, &mut Vec::new())
        .await
        .unwrap()
        .unwrap()["sid"]
        .as_u64()
        .unwrap();
    lab.call("stream.close", json!({"sid": sid, "reason": "done"}), WAIT)
        .await
        .unwrap()
        .expect("closed");
    assert_eq!(
        p.next().await.expect("the close"),
        json!({"method": "stream.close", "params": {"stream": asked["id"]}})
    );

    // One whose program goes: the stream ends with what it sent.
    let id = lab.request("stream.open", open(json!({}))).await.unwrap();
    let asked = p.next().await.expect("the stream.open");
    p.send(json!({"id": asked["id"], "ok": {}})).await;
    let sid = lab
        .answer(id, WAIT, &mut Vec::new())
        .await
        .unwrap()
        .unwrap()["sid"]
        .as_u64()
        .unwrap() as u32;
    p.send(json!({"stream": asked["id"], "data": "last\n"}))
        .await;
    drop(p);
    let (text, reason) = stream_of(&mut lab, sid).await;
    assert_eq!((text.as_str(), reason.as_str()), ("last\n", "ended"));

    // A center whose policy does not allow the stream never opens it.
    let paths = daemon.paths().clone();
    owner_edit(&paths, |c| {
        c.center_mut("work").unwrap().policy.caps.clear();
    })
    .await;
    descriptor_changed(&mut work).await;
    let e = work
        .call("stream.open", open(json!({})), WAIT)
        .await
        .unwrap()
        .expect_err("refused");
    assert!(
        ["forbidden", "unknown_capability", "unavailable"].contains(&code_of(&e).as_str()),
        "{}",
        e.message
    );
    daemon.stop().await;
}

/// An open program's stream was decided once; the policy is asked again
/// when it changes, and a stream the center may no longer have ends: the
/// center gets `stream.close` and the program is told, as an event of the
/// capability would no longer come.
#[tokio::test(flavor = "multi_thread")]
async fn a_programs_stream_ends_when_the_policy_no_longer_allows_it() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, mut lab, _work, mut p) = two_centers_with_sensors(dir.path()).await;
    let open = json!({"cap": "sensors", "stream": "feed", "params": {},
                      "ctx": {"session": "s-1"}});
    let id = lab.request("stream.open", open).await.unwrap();
    let asked = p.next().await.expect("the stream.open");
    p.send(json!({"id": asked["id"], "ok": {}})).await;
    let sid = lab
        .answer(id, WAIT, &mut Vec::new())
        .await
        .unwrap()
        .unwrap()["sid"]
        .as_u64()
        .unwrap() as u32;
    p.send(json!({"stream": asked["id"], "data": "one\n"}))
        .await;
    // The owner takes `on` from `lab`: sensing needs it.
    owner_edit(daemon.paths(), |c| {
        c.center_mut("lab").unwrap().policy.caps.clear();
    })
    .await;
    let (text, reason) = stream_of(&mut lab, sid).await;
    assert_eq!(text, "one\n");
    assert_eq!(reason, "not allowed any more");
    assert_eq!(
        p.next().await.expect("the close"),
        json!({"method": "stream.close", "params": {"stream": asked["id"]}})
    );
    daemon.stop().await;
}

/// Opens of a program's stream that wait for the program together keep
/// the link's limit of streams: the place is taken before the program is
/// asked, so one past it is `busy` at once. An open that still waits when
/// the connection ends ends with it, and the program is told.
#[tokio::test(flavor = "multi_thread")]
async fn waiting_opens_of_a_programs_stream_keep_the_limit_and_end_with_the_link() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, mut lab, _work, mut p) = two_centers_with_sensors(dir.path()).await;
    let open = json!({"cap": "sensors", "stream": "feed", "params": {},
                      "ctx": {"session": "s-1"}});
    let most = nerve_proto::limits::STREAMS as usize;
    let mut ids = Vec::new();
    for _ in 0..most {
        ids.push(lab.request("stream.open", open.clone()).await.unwrap());
    }
    let mut asked = Vec::new();
    for _ in 0..most {
        let a = p.next().await.expect("a stream.open");
        assert_eq!(a["method"], "stream.open", "{a}");
        asked.push(a["id"].clone());
    }
    // None answered yet: one more finds no place.
    let e = lab
        .call("stream.open", open.clone(), WAIT)
        .await
        .unwrap()
        .expect_err("past the limit");
    assert_eq!(code_of(&e), "busy", "{}", e.message);

    // The connection ends while they wait: the program hears of each.
    drop(lab);
    let mut told = std::collections::BTreeSet::new();
    while told.len() < most {
        let line = p.next().await.expect("the program is told");
        let n = &line["params"]["id"];
        let n = if n.is_null() {
            &line["params"]["stream"]
        } else {
            n
        };
        assert!(asked.contains(n), "{line}");
        told.insert(n.to_string());
    }
    daemon.stop().await;
}

/// A `get` of a program's state is one of the link's calls: a `cancel`
/// stops it (the program is told) and answers `cancelled` at once, and
/// past `limits.calls` in flight one more is `busy`.
#[tokio::test(flavor = "multi_thread")]
async fn a_programs_get_is_a_call_of_the_link() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, mut lab, _work, mut p) = two_centers_with_sensors(dir.path()).await;
    let get = json!({"cap": "sensors", "keys": ["temperature"], "ctx": {"session": "s-1"}});
    let id = lab.request("get", get.clone()).await.unwrap();
    let asked = p.next().await.expect("the get");
    assert_eq!(asked["method"], "get", "{asked}");
    lab.notify("cancel", json!({"id": id})).await.unwrap();
    let e = lab
        .answer(id, WAIT, &mut Vec::new())
        .await
        .unwrap()
        .expect_err("cancelled");
    assert_eq!(code_of(&e), "cancelled", "{}", e.message);
    assert_eq!(
        p.next().await.expect("the cancel"),
        json!({"method": "cancel", "params": {"id": asked["id"]}})
    );

    let most = nerve_proto::limits::CALLS as usize;
    for _ in 0..most {
        lab.request("get", get.clone()).await.unwrap();
    }
    for _ in 0..most {
        assert_eq!(p.next().await.expect("a get")["method"], "get");
    }
    let e = lab
        .call("get", get, WAIT)
        .await
        .unwrap()
        .expect_err("past the limit");
    assert_eq!(code_of(&e), "busy", "{}", e.message);
    daemon.stop().await;
}

/// The entries of the node's audit log for `cap` with the session
/// `session`: center, action and decision of each.
async fn audited(paths: &NodePaths, cap: &str, session: &str) -> Vec<(String, String, String)> {
    let audit: Value = serde_json::from_str(&cli(paths, &["--json", "audit"]).await).unwrap();
    audit["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["cap"] == cap && e["session"] == session)
        .map(|e| {
            let s = |k: &str| e[k].as_str().unwrap_or("").to_string();
            (s("center"), s("action"), s("decision"))
        })
        .collect()
}

/// A subscription to a program's event is decided and audited also when
/// the center is offered none of the capability: the node looks the
/// capability up with all its units, as for `get` and `stream.open`, so
/// the refusal is in the owner's audit log, not an unknown capability.
#[tokio::test(flavor = "multi_thread")]
async fn a_subscription_to_a_capability_the_center_is_not_offered_is_audited() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, _lab, mut work, _p) = two_centers_with_sensors(dir.path()).await;
    let paths = daemon.paths().clone();
    // Without `on`, `work` is offered nothing of `sensors`: each unit senses.
    owner_edit(&paths, |c| {
        c.center_mut("work").unwrap().policy.caps.clear();
    })
    .await;
    descriptor_changed(&mut work).await;
    assert!(lamp_or(&mut work, "sensors").await.is_none());
    let sub = json!({"topics": ["sensors/alarm"], "ctx": {"session": "s-cut"}});
    let e = work
        .call("sub", sub, WAIT)
        .await
        .unwrap()
        .expect_err("refused");
    assert_eq!(code_of(&e), "forbidden", "{}", e.message);
    assert_eq!(
        audited(&paths, "sensors", "s-cut").await,
        [("work".into(), "alarm".into(), "forbidden".into())]
    );
    daemon.stop().await;
}

/// A topic named more than once in one `sub`, or an event both by name
/// and under `cap/*`, is decided and audited once; so is a key named more
/// than once in a `get`, which the program is asked for once.
#[tokio::test(flavor = "multi_thread")]
async fn a_repeated_topic_or_key_is_decided_once() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, mut lab, _work, mut p) = two_centers_with_sensors(dir.path()).await;
    let paths = daemon.paths().clone();
    let topics = vec!["sensors/alarm"; 50]
        .into_iter()
        .chain(["sensors/*", "sensors/state"])
        .collect::<Vec<_>>();
    lab.call(
        "sub",
        json!({"topics": topics, "ctx": {"session": "s-twice"}}),
        WAIT,
    )
    .await
    .unwrap()
    .expect("sub");
    let mut got = audited(&paths, "sensors", "s-twice").await;
    got.sort();
    assert_eq!(
        got,
        [
            ("lab".into(), "alarm".into(), "allowed".into()),
            ("lab".into(), "temperature".into(), "allowed".into())
        ]
    );

    let get = json!({"cap": "sensors", "keys": ["temperature", "temperature"],
                     "ctx": {"session": "s-keys"}});
    let id = lab.request("get", get).await.unwrap();
    let asked = p.next().await.expect("the get");
    assert_eq!(
        asked["params"],
        json!({"cap": "sensors", "keys": ["temperature"]})
    );
    p.send(json!({"id": asked["id"], "ok": {"temperature": 20.0}}))
        .await;
    let v = lab
        .answer(id, WAIT, &mut Vec::new())
        .await
        .unwrap()
        .expect("read");
    assert_eq!(v, json!({"temperature": 20.0}));
    assert_eq!(audited(&paths, "sensors", "s-keys").await.len(), 1);
    daemon.stop().await;
}

/// A `get` or `sub` whose session is longer than 256 bytes is refused with
/// `invalid_args` before anything is decided: nothing reaches the audit
/// log or the program. 256 bytes are taken.
#[tokio::test(flavor = "multi_thread")]
async fn a_get_or_sub_with_a_session_past_its_limit_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, mut lab, _work, mut p) = two_centers_with_sensors(dir.path()).await;
    let paths = daemon.paths().clone();
    let count = |paths: NodePaths| async move {
        let audit: Value = serde_json::from_str(&cli(&paths, &["--json", "audit"]).await).unwrap();
        audit["entries"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["cap"] == "sensors")
            .count()
    };
    let long = "s".repeat(257);
    let get = json!({"cap": "sensors", "keys": ["temperature"], "ctx": {"session": long}});
    let e = lab
        .call("get", get, WAIT)
        .await
        .unwrap()
        .expect_err("too long");
    assert_eq!(code_of(&e), "invalid_args", "{}", e.message);
    let sub = json!({"topics": ["sensors/alarm"], "ctx": {"session": long}});
    let e = lab
        .call("sub", sub, WAIT)
        .await
        .unwrap()
        .expect_err("too long");
    assert_eq!(code_of(&e), "invalid_args", "{}", e.message);
    assert_eq!(count(paths.clone()).await, 0);

    let sub = json!({"topics": ["sensors/alarm"], "ctx": {"session": "s".repeat(256)}});
    lab.call("sub", sub, WAIT).await.unwrap().expect("sub");
    let get = json!({"cap": "sensors", "keys": ["temperature"],
                     "ctx": {"session": "s".repeat(256)}});
    let id = lab.request("get", get).await.unwrap();
    let asked = p.next().await.expect("the get");
    p.send(json!({"id": asked["id"], "ok": {"temperature": 20.0}}))
        .await;
    lab.answer(id, WAIT, &mut Vec::new())
        .await
        .unwrap()
        .expect("read");
    assert_eq!(count(paths).await, 2);
    daemon.stop().await;
}

/// `cap/*` and `cap/state` of a program's capability take only the units
/// they were decided for: an event or state key the program declares when
/// it attaches again later was never decided for that subscription, so it
/// does not come under it, while the units decided still do.
#[tokio::test(flavor = "multi_thread")]
async fn units_declared_later_do_not_come_under_an_earlier_subscription() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, mut lab, _work, p) = two_centers_with_sensors(dir.path()).await;
    let sub = json!({"topics": ["sensors/*"], "ctx": {"session": "s-all"}});
    lab.call("sub", sub, WAIT).await.unwrap().expect("sub");
    drop(p);
    descriptor_changed(&mut lab).await;
    let mut more = sensors();
    more[0]["events"]["motion"] = json!({"effect": "sense"});
    more[0]["state"]["humidity"] = json!({"effect": "sense", "schema": {"type": "number"}});
    let (mut p, first) = hello_with(&daemon.paths().ctl_socket(), more).await;
    assert_eq!(first["ok"]["capabilities"], json!(["sensors"]), "{first}");
    descriptor_changed(&mut lab).await;
    p.send(json!({"cap": "sensors", "event": "motion", "data": {}}))
        .await;
    p.send(json!({"cap": "sensors", "state": {"humidity": 40, "temperature": 20.5}}))
        .await;
    p.send(json!({"cap": "sensors", "event": "alarm", "data": {"level": 1}}))
        .await;
    let mut got = Vec::new();
    while got.len() < 2 {
        match lab.recv(WAIT).await {
            Recv::Msg(Message::Notification { method: m, params })
                if params["cap"] == "sensors" =>
            {
                got.push(json!({"method": m, "name": params.get("name"),
                                "changed": params.get("changed")}))
            }
            Recv::Msg(_) => {}
            other => panic!("no event: {other:?}"),
        }
    }
    assert_eq!(
        got,
        [
            json!({"method": "state", "name": null, "changed": {"temperature": 20.5}}),
            json!({"method": "event", "name": "alarm", "changed": null}),
        ]
    );
    daemon.stop().await;
}

/// An open program's stream is decided again on the link's tick, so a
/// mode whose time limit passes takes it as a change of the policy would:
/// folder mode gave `sensors` with `on`, the allowlist it falls back to
/// has no rule for it.
#[tokio::test(flavor = "multi_thread")]
async fn a_programs_stream_ends_when_a_modes_time_limit_passes() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, mut lab, _work, mut p) = two_centers_with_sensors(dir.path()).await;
    let until = nerve_proto::msg::now_ms() + 1500;
    owner_edit(daemon.paths(), |c| {
        c.center_mut("lab").unwrap().policy.until = Some(until);
    })
    .await;
    let open = json!({"cap": "sensors", "stream": "feed", "params": {},
                      "ctx": {"session": "s-1"}});
    let id = lab.request("stream.open", open).await.unwrap();
    let asked = p.next().await.expect("the stream.open");
    p.send(json!({"id": asked["id"], "ok": {}})).await;
    let sid = lab
        .answer(id, WAIT, &mut Vec::new())
        .await
        .unwrap()
        .expect("opened while the mode holds")["sid"]
        .as_u64()
        .unwrap() as u32;
    let (_, reason) = stream_of(&mut lab, sid).await;
    assert_eq!(reason, "not allowed any more");
    assert!(nerve_proto::msg::now_ms() >= until);
    assert_eq!(
        p.next().await.expect("the close"),
        json!({"method": "stream.close", "params": {"stream": asked["id"]}})
    );
    daemon.stop().await;
}

/// An open decided before the policy changed, which the program answers
/// only after, is refused then: it was not open yet when the change was
/// looked at, and the program is told.
#[tokio::test(flavor = "multi_thread")]
async fn an_open_the_policy_took_while_the_program_answered_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, mut lab, _work, mut p) = two_centers_with_sensors(dir.path()).await;
    let open = json!({"cap": "sensors", "stream": "feed", "params": {},
                      "ctx": {"session": "s-1"}});
    let id = lab.request("stream.open", open).await.unwrap();
    let asked = p.next().await.expect("the stream.open");
    owner_edit(daemon.paths(), |c| {
        c.center_mut("lab").unwrap().policy.caps.clear();
    })
    .await;
    p.send(json!({"id": asked["id"], "ok": {}})).await;
    let e = lab
        .answer(id, WAIT, &mut Vec::new())
        .await
        .unwrap()
        .expect_err("not allowed any more");
    assert_eq!(code_of(&e), "forbidden", "{}", e.message);
    assert_eq!(
        p.next().await.expect("the close"),
        json!({"method": "stream.close", "params": {"stream": asked["id"]}})
    );
    daemon.stop().await;
}

/// A program that does not answer a `get` or a `stream.open` within the
/// node's wait fails it with `timeout`, and the call's place is free again.
#[tokio::test(flavor = "multi_thread")]
async fn a_program_that_does_not_answer_times_out() {
    let dir = tempfile::tempdir().unwrap();
    let mut o = options(dir.path());
    o.program_wait = Duration::from_millis(300);
    let (daemon, mut lab, _work, mut p) = two_centers_with_sensors_as(o).await;
    let get = json!({"cap": "sensors", "keys": ["temperature"], "ctx": {"session": "s-1"}});
    let open = json!({"cap": "sensors", "stream": "feed", "params": {},
                      "ctx": {"session": "s-1"}});
    for (method, params) in [("get", get), ("stream.open", open)] {
        let e = lab
            .call(method, params, WAIT)
            .await
            .unwrap()
            .expect_err("no answer");
        assert_eq!(code_of(&e), "timeout", "{method}: {}", e.message);
        assert!(
            e.message
                .contains("the provider desk did not answer within"),
            "{}",
            e.message
        );
        // The program was asked; given up, it is told.
        let asked = p.next().await.expect("asked");
        assert_eq!(asked["method"], method, "{asked}");
        let told = p.next().await.expect("told");
        let n = told["params"]["id"]
            .as_u64()
            .or(told["params"]["stream"].as_u64());
        assert_eq!(n, asked["id"].as_u64(), "{told}");
    }
    daemon.stop().await;
}

/// `cap ls` names each of a program's state keys, events and streams with
/// its kind after its effect, as `--json` rows do with `kind`; an action
/// has none. Each center's column says whether it may have the unit now.
#[tokio::test(flavor = "multi_thread")]
async fn cap_ls_names_the_kind_of_a_programs_units() {
    use nerve_policy::config::CapSetting;
    let dir = tempfile::tempdir().unwrap();
    let center = FakeCenter::start(false).await.unwrap();
    let daemon = node(dir.path(), &center, &me(), |p| {
        p.caps.insert("sensors.temperature".into(), CapSetting::On);
        p.caps.insert("sensors.alarm".into(), CapSetting::Off);
    })
    .await;
    let paths = daemon.paths().clone();
    let mut caps = sensors();
    caps[0]["actions"] = json!({"calibrate": {"effect": "write", "summary": "Calibrates."}});
    let (_p, first) = hello_with(&paths.ctl_socket(), caps).await;
    assert_eq!(first["ok"]["capabilities"], json!(["sensors"]), "{first}");

    let ls = cli(&paths, &["cap", "ls"]).await;
    let words = |name: &str| {
        ls.lines()
            .find(|l| l.split_whitespace().next() == Some(name))
            .unwrap_or_else(|| panic!("no {name}: {ls}"))
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    };
    for (name, want) in [
        ("sensors.temperature", "sense state program desk lab: "),
        (
            "sensors.alarm",
            "sense event program desk lab: off (set off)",
        ),
        ("sensors.feed", "sense stream program desk lab: "),
        ("sensors.calibrate", "write program desk lab: "),
    ] {
        assert!(
            words(name).starts_with(&format!("{name} {want}")),
            "{name}: {ls}"
        );
    }

    let v: Value = serde_json::from_str(&cli(&paths, &["--json", "cap", "ls"]).await).unwrap();
    let row = |name: &str| {
        v["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == name)
            .cloned()
            .unwrap_or_else(|| panic!("no {name}: {v}"))
    };
    for (name, kind) in [
        ("sensors.temperature", json!("state")),
        ("sensors.alarm", json!("event")),
        ("sensors.feed", json!("stream")),
        ("sensors.calibrate", Value::Null),
    ] {
        assert_eq!(row(name)["kind"], kind, "{name}: {v}");
    }
    assert_eq!(row("sensors.alarm")["now"], json!({"lab": "off"}), "{v}");
    assert_eq!(
        row("sensors.alarm")["centers"],
        json!({"lab": "off"}),
        "{v}"
    );
    daemon.stop().await;
}

/// The text of stream `sid` as it comes to `conn`, in order from seq 0,
/// and the reason of the node's `stream.close` that ends it.
async fn stream_of(conn: &mut Conn<TcpStream>, sid: u32) -> (String, String) {
    let mut text = Vec::new();
    let mut seq = 0;
    loop {
        match conn.recv(WAIT).await {
            Recv::Frame(f) if f.id == sid => {
                assert_eq!(f.seq, seq, "in order");
                seq += 1;
                text.extend_from_slice(&f.payload);
            }
            Recv::Msg(Message::Request { id, method, params }) if method == "stream.close" => {
                assert_eq!(params["sid"], sid);
                conn.send(&Message::result(id, json!({}))).await.unwrap();
                let reason = params["reason"].as_str().unwrap_or("").to_string();
                return (String::from_utf8(text).unwrap(), reason);
            }
            Recv::Msg(_) => {}
            other => panic!("stream {sid}: {other:?}"),
        }
    }
}

/// The capability `id` of the descriptor the center gets now.
async fn lamp_or(conn: &mut Conn<TcpStream>, id: &str) -> Option<Value> {
    let d = conn
        .call("describe", json!({"detail": "full"}), WAIT)
        .await
        .unwrap()
        .expect("describe");
    d["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .cloned()
}
