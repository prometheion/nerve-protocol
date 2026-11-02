//! Capabilities a center adds itself (`settings.cap-add`, `cap-edit`,
//! `cap-rm`; docs/user/config-capabilities.md) on a real node daemon, in
//! process: a center with the settings grant `write` adds them to its own
//! entry, they are offered to it alone, counted as `execute`, and run as
//! `nerve-run`, which a node run by hand does not have; here the node by
//! hand stands for it with its own user (NodeOptions::config_caps_by_hand),
//! as in config_caps.rs. Linux only: Windows takes none yet (issue #176).
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::time::Duration;

use nerve_conformance::fake_center::{self, FakeCenter};
use nerve_conformance::wire::{Conn, Recv, code_of};
use nerve_node::{Daemon, NodeOptions, NodePaths};
use nerve_policy::NodeConfig;
use nerve_policy::config::{CapSetting, SettingsGrant};
use nerve_proto::rpc::Message;
use serde_json::{Value, json};
use tokio::net::{TcpStream, UnixStream};

const WAIT: Duration = Duration::from_secs(15);

fn options(root: &Path, by_hand: bool) -> NodeOptions {
    let mut o = NodeOptions::new(NodePaths::new(root.join("config"), root.join("state")));
    o.home = root.join("home");
    std::fs::create_dir_all(&o.home).unwrap();
    o.full_rights = Some(false);
    o.exe = Some(env!("CARGO_BIN_EXE_nerve-node").into());
    // The node by hand runs them as its own user, for `nerve-run`, on a
    // kernel without Landlock (config_caps.rs says why).
    o.config_caps_by_hand = by_hand;
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

/// Pairs with each of `centers` under its name, gives each the settings
/// grant `write` and the mode `mode`, lets `f` change the config, and
/// starts the daemon.
async fn node(
    root: &Path,
    centers: &[(&FakeCenter, &str)],
    mode: nerve_policy::Mode,
    by_hand: bool,
    f: impl Fn(&mut NodeConfig),
) -> Daemon {
    let o = options(root, by_hand);
    for (c, name) in centers {
        nerve_node::pair::pair(&o.paths, &c.link(), Some(name))
            .await
            .expect("pair");
    }
    owner_edit(&o.paths, |c| {
        for e in &mut c.centers {
            e.settings = SettingsGrant::Write;
            e.policy.mode = mode;
        }
        f(c);
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
    cap: &str,
    action: &str,
    args: Value,
) -> Result<Value, nerve_proto::RpcError> {
    conn.call(
        "invoke",
        json!({"cap": cap, "action": action, "args": args, "ctx": {}}),
        WAIT,
    )
    .await
    .unwrap()
}

/// A call of the unit `name` (`cap.action`).
async fn call(
    conn: &mut Conn<TcpStream>,
    name: &str,
    args: Value,
) -> Result<Value, nerve_proto::RpcError> {
    let (cap, action) = name.split_once('.').unwrap();
    invoke(conn, cap, action, args).await
}

async fn settings_get(conn: &mut Conn<TcpStream>, keys: &[&str]) -> Value {
    conn.call("get", json!({"cap": "settings", "keys": keys}), WAIT)
        .await
        .unwrap()
        .expect("settings get")
}

/// `settings.set` with this center's document as `f` changes it.
async fn settings_set(
    conn: &mut Conn<TcpStream>,
    f: impl Fn(&mut Value),
) -> Result<Value, nerve_proto::RpcError> {
    let got = settings_get(conn, &["document", "version"]).await;
    let mut doc = got["document"].clone();
    f(&mut doc);
    invoke(
        conn,
        "settings",
        "set",
        json!({"document": doc, "if_version": got["version"]}),
    )
    .await
}

/// The capability `id` of the descriptor the center gets now.
async fn described(conn: &mut Conn<TcpStream>, id: &str) -> Option<Value> {
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

fn say_back() -> Value {
    json!({"name": "say.back", "effect": "read", "summary": "Says the word back.",
           "command": ["echo", "{word}"],
           "params": {"type": "object", "properties": {"word": {"type": "string"}},
                      "required": ["word"], "additionalProperties": false}})
}

async fn cli(paths: &NodePaths, words: &[&str]) -> Result<String, String> {
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
    nerve_node::cli::execute(cli, &mut out).await?;
    Ok(String::from_utf8(out).unwrap())
}

/// The settings entries of the audit log written by `by`.
fn settings_audit(paths: &NodePaths, by: &str) -> Vec<Value> {
    std::fs::read_to_string(paths.audit_log())
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .filter(|e: &Value| e["kind"] == "settings" && e["by"] == by)
        .collect()
}

/// A center adds a capability, which it is offered as `center-added` and
/// runs; it edits it; each change is in the audit as that center's; `cap
/// ls` says who added it; it stays offered once the owner takes the grant
/// back, which the center then cannot remove; and the owner removes it.
#[tokio::test(flavor = "multi_thread")]
async fn a_center_adds_runs_and_edits_its_own_and_the_owner_removes_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(
        dir.path(),
        &[(&center, "lab")],
        nerve_policy::Mode::User,
        true,
        |_| {},
    )
    .await;
    let paths = daemon.paths().clone();
    let mut conn = linked(&mut center).await;
    let v = invoke(
        &mut conn,
        "settings",
        "cap-add",
        json!({"capability": say_back()}),
    )
    .await
    .expect("added");
    assert!(v["version"].is_u64(), "{v}");
    let say = described(&mut conn, "say").await.expect("offered");
    assert_eq!(say["provider"], "center-added");
    assert_eq!(say["actions"]["back"]["summary"], "Says the word back.");
    assert_eq!(
        call(&mut conn, "say.back", json!({"word": "; touch x"}))
            .await
            .unwrap(),
        json!("; touch x\n")
    );
    let got = settings_get(&mut conn, &["capabilities"]).await;
    let entries = got["capabilities"]["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "{got}");
    assert_eq!(entries[0]["command"], json!(["echo", "{word}"]));
    assert_eq!(got["capabilities"]["refused"], Value::Null);

    // An edit replaces it whole.
    let mut changed = say_back();
    changed["command"] = json!(["printf", "%s!", "{word}"]);
    invoke(
        &mut conn,
        "settings",
        "cap-edit",
        json!({"capability": changed}),
    )
    .await
    .expect("edited");
    assert_eq!(
        call(&mut conn, "say.back", json!({"word": "hi"}))
            .await
            .unwrap(),
        json!("hi!")
    );

    // Both changes are the center's in the audit.
    let audit = settings_audit(&paths, "center lab");
    assert_eq!(audit.len(), 2, "{audit:?}");
    assert!(audit[1].to_string().contains("printf"), "{audit:?}");

    // `cap ls` says who added it and how it counts.
    let ls = cli(&paths, &["cap", "ls"]).await.unwrap();
    let row = ls.lines().find(|l| l.starts_with("say.back")).unwrap();
    assert!(
        row.contains("execute") && row.contains("center lab"),
        "{ls}"
    );
    assert!(
        ls.contains("capability say.back (added by center lab, counted as execute): printf"),
        "{ls}"
    );

    // The owner takes the grant back: what the center added stays offered
    // and runs, but the center no longer changes it (it is offered no
    // `settings` then).
    owner_edit(&paths, |c| c.centers[0].settings = SettingsGrant::Off).await;
    let e = invoke(&mut conn, "settings", "cap-rm", json!({"name": "say.back"}))
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), "unknown_capability", "{}", e.message);
    assert!(described(&mut conn, "say").await.is_some());
    assert_eq!(
        call(&mut conn, "say.back", json!({"word": "hi"}))
            .await
            .unwrap(),
        json!("hi!")
    );

    // The owner removes it, naming the center.
    let e = cli(&paths, &["cap", "rm", "say.back"]).await.unwrap_err();
    assert!(
        e.contains("center lab added one: cap rm say.back --center lab"),
        "{e}"
    );
    let out = cli(&paths, &["cap", "rm", "say.back", "--center", "lab"])
        .await
        .unwrap();
    assert!(
        out.contains("capability say.back of center lab removed"),
        "{out}"
    );
    assert!(described(&mut conn, "say").await.is_none());
    assert_eq!(
        code_of(
            &call(&mut conn, "say.back", json!({"word": "x"}))
                .await
                .unwrap_err()
        ),
        "unknown_capability"
    );
    daemon.stop().await;
}

/// What a center sends names no account, and never changes or shadows a
/// capability the owner declared.
#[tokio::test(flavor = "multi_thread")]
async fn a_center_names_no_account_and_leaves_the_owners_alone() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(
        dir.path(),
        &[(&center, "lab")],
        nerve_policy::Mode::User,
        true,
        |c| {
            c.capabilities = NodeConfig::parse(
                "[[capability]]\nname = \"owner.cap\"\neffect = \"read\"\ncommand = [\"id\"]\n",
            )
            .unwrap()
            .capabilities;
        },
    )
    .await;
    let mut conn = linked(&mut center).await;
    // Always nerve-run: an account is no field of it.
    let mut owner = say_back();
    owner["account"] = json!("owner");
    let e = invoke(
        &mut conn,
        "settings",
        "cap-add",
        json!({"capability": owner}),
    )
    .await
    .unwrap_err();
    assert_eq!(code_of(&e), "invalid_args");
    assert!(e.message.contains("account"), "{}", e.message);
    // The owner's capability: neither removed nor changed, and nothing
    // added under its name.
    let e = invoke(
        &mut conn,
        "settings",
        "cap-rm",
        json!({"name": "owner.cap"}),
    )
    .await
    .unwrap_err();
    assert_eq!(code_of(&e), "forbidden");
    assert!(e.message.contains("is the owner's"), "{}", e.message);
    let mut edit = say_back();
    edit["name"] = json!("owner.cap");
    edit["command"] = json!(["echo", "{word}"]);
    let e = invoke(
        &mut conn,
        "settings",
        "cap-edit",
        json!({"capability": edit}),
    )
    .await
    .unwrap_err();
    assert_eq!(code_of(&e), "forbidden");
    let mut beside = say_back();
    beside["name"] = json!("owner.other");
    let e = invoke(
        &mut conn,
        "settings",
        "cap-add",
        json!({"capability": beside}),
    )
    .await
    .unwrap_err();
    assert_eq!(code_of(&e), "forbidden");
    assert!(
        e.message.contains("the owner declares owner in node.toml"),
        "{}",
        e.message
    );
    // The owner's still runs as it was.
    assert!(call(&mut conn, "owner.cap", json!({})).await.is_ok());
    // Twice, or an edit of none, is refused; a broken one is refused with
    // the validator's reason.
    invoke(
        &mut conn,
        "settings",
        "cap-add",
        json!({"capability": say_back()}),
    )
    .await
    .unwrap();
    let e = invoke(
        &mut conn,
        "settings",
        "cap-add",
        json!({"capability": say_back()}),
    )
    .await
    .unwrap_err();
    assert!(e.message.contains("cap-edit changes it"), "{}", e.message);
    let mut none = say_back();
    none["name"] = json!("say.other");
    let e = invoke(
        &mut conn,
        "settings",
        "cap-edit",
        json!({"capability": none}),
    )
    .await
    .unwrap_err();
    assert!(
        e.message.contains("added no capability say.other"),
        "{}",
        e.message
    );
    let mut broken = say_back();
    broken["name"] = json!("say.broken");
    broken["command"] = json!(["echo", "{nothing}"]);
    let e = invoke(
        &mut conn,
        "settings",
        "cap-add",
        json!({"capability": broken}),
    )
    .await
    .unwrap_err();
    assert_eq!(code_of(&e), "invalid_args");
    assert!(
        e.message.contains("{nothing} names no argument"),
        "{}",
        e.message
    );
    daemon.stop().await;
}

/// A center's capability counts as `execute` whatever it declares, so in
/// folder mode one that names no path needs `on`, which the center may set
/// for that action, not for its capability as a whole; one that senses
/// waits for the owner's `on` in every mode, also where an earlier `on` of
/// the center's would cover it; and an `off` the owner set stays until the
/// owner changes it, also after the center removes the capability and adds
/// it again.
#[tokio::test(flavor = "multi_thread")]
async fn a_centers_capability_counts_as_execute_and_sensing_waits_for_the_owner() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(
        dir.path(),
        &[(&center, "lab")],
        nerve_policy::Mode::Folder,
        true,
        |_| {},
    )
    .await;
    let paths = daemon.paths().clone();
    let mut conn = linked(&mut center).await;
    let show = json!({"name": "notes.show", "effect": "read", "command": ["echo", "notes"]});
    invoke(
        &mut conn,
        "settings",
        "cap-add",
        json!({"capability": show}),
    )
    .await
    .unwrap();
    let notes = described(&mut conn, "notes").await;
    // Offered only once it is on: an execute action that names no path.
    assert!(notes.is_none(), "{notes:?}");
    let e = call(&mut conn, "notes.show", json!({})).await.unwrap_err();
    assert_eq!(code_of(&e), "forbidden");
    assert!(e.message.contains("set to on"), "{}", e.message);
    // Not its capability as a whole: that would cover what a program the
    // owner allows offers under that name later.
    let e = settings_set(&mut conn, |d| d["policy"]["caps"] = json!({"notes": "on"}))
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), "forbidden");
    settings_set(&mut conn, |d| {
        d["policy"]["caps"] = json!({"notes.show": "on"})
    })
    .await
    .expect("the center turns its own on");
    let notes = described(&mut conn, "notes").await.unwrap();
    assert_eq!(notes["actions"]["show"]["effect"], "execute");
    assert_eq!(
        call(&mut conn, "notes.show", json!({})).await.unwrap(),
        json!("notes\n")
    );

    // It comes to sense: the center's own `on` for `notes.show` covered it, so
    // the node switches the action off, and the center cannot turn it on.
    let look = json!({"name": "notes.show", "effect": "sense", "command": ["echo", "seen"]});
    invoke(
        &mut conn,
        "settings",
        "cap-edit",
        json!({"capability": look}),
    )
    .await
    .unwrap();
    let e = call(&mut conn, "notes.show", json!({})).await.unwrap_err();
    assert_eq!(code_of(&e), "disabled");
    for caps in [
        json!({"notes": "on", "notes.show": "on"}),
        json!({"notes": "on"}),
    ] {
        let e = settings_set(&mut conn, |d| d["policy"]["caps"] = caps.clone())
            .await
            .unwrap_err();
        assert_eq!(code_of(&e), "forbidden");
        assert!(
            e.message
                .contains("only the owner can turn on what senses or actuates"),
            "{}",
            e.message
        );
    }
    // A new one that senses waits too, in user mode as well.
    settings_set(&mut conn, |d| d["policy"]["mode"] = json!("user"))
        .await
        .unwrap();
    let cam = json!({"name": "cam.look", "effect": "sense", "command": ["echo", "frame"]});
    invoke(&mut conn, "settings", "cap-add", json!({"capability": cam}))
        .await
        .unwrap();
    let e = call(&mut conn, "cam.look", json!({})).await.unwrap_err();
    assert_eq!(code_of(&e), "forbidden");
    let ls = cli(&paths, &["cap", "ls"]).await.unwrap();
    assert!(
        ls.contains(
            "capability cam.look (added by center lab, senses: only you turn it on): echo frame"
        ),
        "{ls}"
    );
    let e = settings_set(&mut conn, |d| d["policy"]["caps"]["cam"] = json!("on"))
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), "forbidden");
    // The owner's `on` lets it run.
    cli(&paths, &["cap", "set", "cam.look", "on", "--center", "lab"])
        .await
        .unwrap();
    daemon.reload().unwrap();
    assert_eq!(
        call(&mut conn, "cam.look", json!({})).await.unwrap(),
        json!("frame\n")
    );
    // That `on` was for this command: it goes with it, whoever removes it.
    cli(&paths, &["cap", "rm", "cam.look", "--center", "lab"])
        .await
        .unwrap();
    let cfg = nerve_node::cli::read_config(&paths).await.unwrap().0;
    assert_eq!(cfg.centers[0].policy.caps.get("cam.look"), None);
    daemon.reload().unwrap();
    // The owner turns off one that does not sense, which the center turned
    // on itself, and the center does not turn it on again. As with a
    // pause, an `off` the center set itself holds alike: the node cannot
    // tell who set it.
    let tool = json!({"name": "tool.go", "effect": "execute", "command": ["echo", "went"]});
    invoke(
        &mut conn,
        "settings",
        "cap-add",
        json!({"capability": tool}),
    )
    .await
    .unwrap();
    settings_set(&mut conn, |d| d["policy"]["caps"]["tool.go"] = json!("on"))
        .await
        .expect("the center turns on one that does not sense");
    assert_eq!(
        call(&mut conn, "tool.go", json!({})).await.unwrap(),
        json!("went\n")
    );
    cli(&paths, &["cap", "set", "tool.go", "off", "--center", "lab"])
        .await
        .unwrap();
    daemon.reload().unwrap();
    let e = call(&mut conn, "tool.go", json!({})).await.unwrap_err();
    assert_eq!(code_of(&e), "disabled");
    let lift = async |conn: &mut Conn<TcpStream>| {
        let e = settings_set(conn, |d| d["policy"]["caps"]["tool.go"] = json!("on"))
            .await
            .unwrap_err();
        assert_eq!(code_of(&e), "forbidden");
        e.message
    };
    let m = lift(&mut conn).await;
    assert!(
        m.contains("a capability this center added stays off until the owner turns it on"),
        "{m}"
    );
    // Removed and added again, it is still off: the `off` is the name's.
    // While removed, nothing offers `tool`, which only the owner turns on.
    invoke(&mut conn, "settings", "cap-rm", json!({"name": "tool.go"}))
        .await
        .unwrap();
    let m = lift(&mut conn).await;
    assert!(m.contains("only the owner can turn on"), "{m}");
    invoke(
        &mut conn,
        "settings",
        "cap-add",
        json!({"capability": tool}),
    )
    .await
    .unwrap();
    let e = call(&mut conn, "tool.go", json!({})).await.unwrap_err();
    assert_eq!(code_of(&e), "disabled");
    let m = lift(&mut conn).await;
    assert!(m.contains("stays off until the owner turns it on"), "{m}");
    let cfg = nerve_node::cli::read_config(&paths).await.unwrap().0;
    assert_eq!(
        cfg.centers[0].policy.caps.get("tool.go"),
        Some(&CapSetting::Off)
    );
    daemon.stop().await;
}

/// This test program: what a provider started from here runs.
fn me() -> String {
    std::env::current_exe().unwrap().display().to_string()
}

/// Attaches this test program as the provider `desk` with the
/// capabilities `caps`, on the node's provider socket, and waits for the
/// node's answer: the connection, which detaches it when dropped.
async fn attach(daemon: &Daemon, caps: Value) -> UnixStream {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let socket = daemon.paths().ctl_socket();
    let token = std::fs::read_to_string(socket.with_file_name("ctl.token")).unwrap();
    let mut io = UnixStream::connect(&socket).await.unwrap();
    let hello = json!({"method": "hello", "token": token,
                       "params": {"role": "provider", "name": "desk", "capabilities": caps}});
    io.write_all(format!("{hello}\n").as_bytes()).await.unwrap();
    let mut line = String::new();
    let mut r = BufReader::new(&mut io);
    tokio::time::timeout(WAIT, r.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    assert!(line.contains("\"ok\""), "{line}");
    io
}

/// A center's own switch and allow rule cover only its own action, by its
/// name: not its capability as a whole, and not what a program the owner
/// allows offers under that name once it attaches. While the center keeps
/// its own under that name, it is offered neither; once it removes its
/// own, its `on` and rule for it go too, and what the program offers waits
/// for the owner as for any center.
#[tokio::test(flavor = "multi_thread")]
async fn a_centers_own_switches_never_reach_what_a_program_offers_later() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let mut other = FakeCenter::start(false).await.unwrap();
    let daemon = node(
        dir.path(),
        &[(&center, "lab"), (&other, "ops")],
        nerve_policy::Mode::Folder,
        true,
        |c| {
            allow_desk(c);
            // The owner turns on all of `cam` for the other center.
            let ops = &mut c.center_mut("ops").unwrap().policy;
            ops.caps.insert("cam".into(), CapSetting::On);
        },
    )
    .await;
    let paths = daemon.paths().clone();
    let mut conn = linked(&mut center).await;
    let mut ops = linked(&mut other).await;
    // While the program is not attached, the center adds a harmless one
    // under the name the program offers later.
    let list = json!({"name": "cam.list", "effect": "read", "command": ["echo", "list"]});
    invoke(
        &mut conn,
        "settings",
        "cap-add",
        json!({"capability": list}),
    )
    .await
    .unwrap();
    for caps in [json!({"cam": "on"}), json!({"cam.list": "on", "cam": "on"})] {
        let e = settings_set(&mut conn, |d| d["policy"]["caps"] = caps.clone())
            .await
            .unwrap_err();
        assert_eq!(code_of(&e), "forbidden", "{caps}");
    }
    let e = settings_set(&mut conn, |d| d["policy"]["allow"] = json!(["cam"]))
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), "forbidden");
    settings_set(&mut conn, |d| {
        d["policy"]["caps"] = json!({"cam.list": "on"});
        d["policy"]["allow"] = json!(["cam.list"]);
    })
    .await
    .expect("its own action, by its name");
    assert_eq!(
        call(&mut conn, "cam.list", json!({})).await.unwrap(),
        json!("list\n")
    );

    // The program attaches: its `cam.list` senses, `cam.snap` too.
    let program = attach(
        &daemon,
        json!([{"id": "cam", "actions": {"list": {"effect": "sense"},
                                         "snap": {"effect": "sense"}}}]),
    )
    .await;
    // Neither the center's own, which the program's name leaves out, nor
    // the program's, which the center's own `on` must not cover. Another
    // center, which added nothing and has the owner's `on`, is offered the
    // program's.
    assert!(described(&mut conn, "cam").await.is_none());
    assert!(described(&mut ops, "cam").await.is_some());
    for unit in ["cam.list", "cam.snap"] {
        let e = call(&mut conn, unit, json!({})).await.unwrap_err();
        assert_eq!(code_of(&e), "unknown_capability", "{unit}: {}", e.message);
    }
    let got = settings_get(&mut conn, &["capabilities"]).await;
    assert!(
        got["capabilities"]["entries"][0]["left_out"]
            .as_str()
            .is_some_and(|w| w.contains("only once it removes its own")),
        "{got}"
    );
    let ls = cli(&paths, &["cap", "ls", "--json"]).await.unwrap();
    let ls: Value = serde_json::from_str(&ls).unwrap();
    let row = ls["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "cam.list" && r["source"] == "program desk")
        .cloned()
        .unwrap();
    assert_eq!(row["now"]["lab"], "off", "{row}");

    // The center removes its own: its `on` and its rule for it go along,
    // and the program's waits for the owner's `on`.
    invoke(&mut conn, "settings", "cap-rm", json!({"name": "cam.list"}))
        .await
        .unwrap();
    let cfg = nerve_node::cli::read_config(&paths).await.unwrap().0;
    assert_eq!(cfg.centers[0].policy.caps.get("cam.list"), None);
    assert!(cfg.centers[0].policy.allow.is_empty(), "{cfg:?}");
    for unit in ["cam.list", "cam.snap"] {
        let e = call(&mut conn, unit, json!({})).await.unwrap_err();
        assert_eq!(code_of(&e), "forbidden", "{unit}: {}", e.message);
        assert!(e.message.contains("set to on"), "{unit}: {}", e.message);
    }
    drop(program);
    daemon.stop().await;
}

/// The owner's `on` for a center's capability as a whole, given while
/// only that center offered it, was given for that center's command: it
/// goes with the last action the center keeps under it, so a program the
/// owner allows that offers that name later waits for the owner's `on`.
#[tokio::test(flavor = "multi_thread")]
async fn the_owners_on_for_a_centers_capability_goes_with_its_last_action() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(
        dir.path(),
        &[(&center, "lab")],
        nerve_policy::Mode::Folder,
        true,
        allow_desk,
    )
    .await;
    let paths = daemon.paths().clone();
    let mut conn = linked(&mut center).await;
    let snap = json!({"name": "cam.snap", "effect": "sense", "command": ["echo", "mine"]});
    invoke(
        &mut conn,
        "settings",
        "cap-add",
        json!({"capability": snap}),
    )
    .await
    .unwrap();
    cli(&paths, &["cap", "set", "cam", "on", "--center", "lab"])
        .await
        .unwrap();
    assert_eq!(
        call(&mut conn, "cam.snap", json!({})).await.unwrap(),
        json!("mine\n")
    );
    invoke(&mut conn, "settings", "cap-rm", json!({"name": "cam.snap"}))
        .await
        .unwrap();
    let cfg = nerve_node::cli::read_config(&paths).await.unwrap().0;
    assert_eq!(cfg.centers[0].policy.caps.get("cam"), None, "{cfg:?}");

    // The program attaches with a `cam.snap` that senses: it waits for the
    // owner's `on` for lab.
    let program = attach(
        &daemon,
        json!([{"id": "cam", "actions": {"snap": {"effect": "sense"}}}]),
    )
    .await;
    let ls = cli(&paths, &["cap", "ls", "--json"]).await.unwrap();
    let ls: Value = serde_json::from_str(&ls).unwrap();
    let row = ls["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "cam.snap" && r["source"] == "program desk")
        .cloned()
        .unwrap();
    assert_ne!(row["now"]["lab"], "on", "{row}");
    let e = call(&mut conn, "cam.snap", json!({})).await.unwrap_err();
    assert_eq!(code_of(&e), "forbidden", "{}", e.message);
    assert!(e.message.contains("set to on"), "{}", e.message);
    drop(program);
    daemon.stop().await;
}

/// While a center keeps its own under a program's `cap`, it is offered
/// neither, so the owner's `on` for that `cap` or for the center's own
/// action would be set for the program's, and go with the center's own
/// when the center removes it: the owner's write is refused, and a file
/// the owner takes keeps it off and says so. The program's actions by
/// their names stay the owner's, and once the center keeps none of its
/// own under `cap`, the owner turns the program's on.
#[tokio::test(flavor = "multi_thread")]
async fn the_owners_on_for_a_program_waits_while_a_center_keeps_its_own() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(
        dir.path(),
        &[(&center, "lab")],
        nerve_policy::Mode::Folder,
        true,
        allow_desk,
    )
    .await;
    let paths = daemon.paths().clone();
    let mut conn = linked(&mut center).await;
    let list = json!({"name": "cam.list", "effect": "read", "command": ["echo", "mine"]});
    invoke(
        &mut conn,
        "settings",
        "cap-add",
        json!({"capability": list}),
    )
    .await
    .unwrap();
    let program = attach(
        &daemon,
        json!([{"id": "cam", "actions": {"snap": {"effect": "sense"}}}]),
    )
    .await;
    for on in ["cam", "cam.list"] {
        let e = cli(&paths, &["cap", "set", on, "on", "--center", "lab"])
            .await
            .unwrap_err();
        assert!(
            e.contains("center lab keeps a capability of its own under cam"),
            "{on}: {e}"
        );
    }
    cli(&paths, &["cap", "set", "cam.snap", "on", "--center", "lab"])
        .await
        .unwrap();
    let file = paths.config_file();
    let mut cfg = NodeConfig::parse(&std::fs::read_to_string(&file).unwrap()).unwrap();
    let caps = &mut cfg.center_mut("lab").unwrap().policy.caps;
    caps.insert("cam".into(), CapSetting::On);
    std::fs::write(&file, cfg.to_toml()).unwrap();
    let said = cli(&paths, &["config", "accept"]).await.unwrap();
    assert!(
        said.contains("lab: keeps a capability of its own under cam,"),
        "{said}"
    );
    assert!(
        said.contains("the file's on or allow rule for cam would go with the center's own"),
        "{said}"
    );
    assert!(said.contains("remove the center's first"), "{said}");
    assert!(!said.contains("set before"), "{said}");
    invoke(&mut conn, "settings", "cap-rm", json!({"name": "cam.list"}))
        .await
        .unwrap();
    let cfg = nerve_node::cli::read_config(&paths).await.unwrap().0;
    let caps = &cfg.centers[0].policy.caps;
    assert_eq!(caps.get("cam"), Some(&CapSetting::Off), "{cfg:?}");
    assert_eq!(caps.get("cam.snap"), Some(&CapSetting::On), "{cfg:?}");
    cli(&paths, &["cap", "set", "cam", "on", "--center", "lab"])
        .await
        .unwrap();
    // That `on` is the program's. Once it leaves, the center adds nothing
    // under `cam` that would run under it, and take it along when removed.
    drop(program);
    let mut tries = 0;
    let e = loop {
        let e = invoke(
            &mut conn,
            "settings",
            "cap-add",
            json!({"capability": list}),
        )
        .await
        .unwrap_err();
        if !e.message.contains("a program the owner allows offers cam") {
            break e;
        }
        // Until the node has seen the program leave.
        tries += 1;
        assert!(tries < 100, "{}", e.message);
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(code_of(&e), "forbidden", "{}", e.message);
    assert!(
        e.message
            .contains("this center has an on or allow rule for cam,"),
        "{}",
        e.message
    );
    // The center may take its own `on` away itself, so it is told so.
    assert!(
        e.message
            .contains("take it away first: this center can, in its settings for the node,"),
        "{}",
        e.message
    );
    owner_edit(&paths, |c| {
        c.center_mut("lab").unwrap().policy.caps.remove("cam");
    })
    .await;
    invoke(
        &mut conn,
        "settings",
        "cap-add",
        json!({"capability": list}),
    )
    .await
    .unwrap();
    daemon.stop().await;
}

/// The next event of `cap` the center gets within `wait`, if one comes.
async fn event_of(conn: &mut Conn<TcpStream>, cap: &str, wait: Duration) -> Option<Value> {
    let end = tokio::time::Instant::now() + wait;
    loop {
        let left = end.saturating_duration_since(tokio::time::Instant::now());
        match conn.recv(left).await {
            Recv::Msg(Message::Notification { method, params })
                if method == "event" && params["cap"] == cap =>
            {
                return Some(Value::Object(params));
            }
            Recv::Msg(_) => {}
            Recv::Timeout => return None,
            other => panic!("the link ended: {other:?}"),
        }
    }
}

/// A center's own switch for its own `cap.action` lets through none of a
/// program's events of that name, also by a subscription it made while
/// the owner allowed them: while it keeps its own under that `cap`, it
/// gets nothing of the program's.
#[tokio::test(flavor = "multi_thread")]
async fn a_centers_own_switch_lets_through_no_event_of_a_program() {
    use tokio::io::AsyncWriteExt;
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(
        dir.path(),
        &[(&center, "lab")],
        nerve_policy::Mode::Folder,
        true,
        |c| {
            allow_desk(c);
            let lab = &mut c.center_mut("lab").unwrap().policy;
            lab.caps.insert("cam.motion".into(), CapSetting::On);
        },
    )
    .await;
    let paths = daemon.paths().clone();
    let mut conn = linked(&mut center).await;
    let cam = json!([{"id": "cam", "events": {"motion": {"effect": "sense"}}}]);
    let motion = b"{\"cap\":\"cam\",\"event\":\"motion\",\"data\":{\"level\":1}}\n";
    let mut program = attach(&daemon, cam.clone()).await;
    // With the owner's `on` the center subscribes, and gets the event.
    conn.call(
        "sub",
        json!({"topics": ["cam/motion"], "ctx": {"session": "s-1"}}),
        WAIT,
    )
    .await
    .unwrap()
    .expect("sub");
    program.write_all(motion).await.unwrap();
    assert!(event_of(&mut conn, "cam", WAIT).await.is_some());

    // The owner takes the `on` back, the program leaves, and the center
    // adds its own of that name and turns it on itself.
    owner_edit(&paths, |c| c.center_mut("lab").unwrap().policy.caps.clear()).await;
    drop(program);
    let own = json!({"name": "cam.motion", "effect": "read", "command": ["echo", "x"]});
    let mut tries = 0;
    while let Err(e) = invoke(&mut conn, "settings", "cap-add", json!({"capability": own})).await {
        // Until the node has seen the program leave.
        tries += 1;
        assert!(tries < 100, "{}", e.message);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    settings_set(&mut conn, |d| {
        d["policy"]["caps"] = json!({"cam.motion": "on"})
    })
    .await
    .expect("its own action, by its name");

    // The program attaches again: the center is offered none of it, and
    // its subscription carries none of the program's events.
    let mut program = attach(&daemon, cam).await;
    assert!(described(&mut conn, "cam").await.is_none());
    program.write_all(motion).await.unwrap();
    assert_eq!(
        event_of(&mut conn, "cam", Duration::from_secs(3)).await,
        None
    );
    drop(program);
    daemon.stop().await;
}

/// Lets the program `desk` (this test binary, [`attach`]) attach.
fn allow_desk(c: &mut NodeConfig) {
    c.providers.allowed = vec![nerve_policy::config::AllowedProvider {
        name: "desk".into(),
        exe: me(),
    }];
}

/// A center's capability that senses waits for the owner's `on` also
/// while a program, or the owner's node.toml, offers its name without
/// sensing: the center's switch or rule for that name set meanwhile would
/// cover its own once the other one goes.
#[tokio::test(flavor = "multi_thread")]
async fn a_centers_sensing_capability_waits_for_the_owner_whatever_else_offers_its_name() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(
        dir.path(),
        &[(&center, "lab")],
        nerve_policy::Mode::Folder,
        true,
        allow_desk,
    )
    .await;
    let paths = daemon.paths().clone();
    let mut conn = linked(&mut center).await;
    let look = json!({"name": "notes.look", "effect": "sense", "command": ["echo", "seen"]});
    invoke(
        &mut conn,
        "settings",
        "cap-add",
        json!({"capability": look}),
    )
    .await
    .unwrap();
    // Each switch and rule that would cover `notes.look`.
    async fn refused(conn: &mut Conn<TcpStream>, when: &str) {
        for caps in [json!({"notes": "on"}), json!({"notes.look": "on"})] {
            let e = settings_set(conn, |d| d["policy"]["caps"] = caps.clone())
                .await
                .unwrap_err();
            assert_eq!(code_of(&e), "forbidden", "{when}: {caps}");
        }
        for rule in ["notes", "notes.look"] {
            let e = settings_set(conn, |d| d["policy"]["allow"] = json!([rule]))
                .await
                .unwrap_err();
            assert_eq!(code_of(&e), "forbidden", "{when}: {rule}");
        }
    }
    async fn waits(conn: &mut Conn<TcpStream>, when: &str) {
        let e = call(conn, "notes.look", json!({})).await.unwrap_err();
        assert_eq!(code_of(&e), "forbidden", "{when}: {}", e.message);
    }
    refused(&mut conn, "alone").await;
    waits(&mut conn, "alone").await;

    // A program offers `notes` with a `look` that only reads.
    let program = attach(
        &daemon,
        json!([{"id": "notes", "actions": {"list": {"effect": "read"},
                                           "look": {"effect": "read"}}}]),
    )
    .await;
    refused(&mut conn, "with the program").await;
    drop(program);
    // Once it is gone, the center's own is no longer left out, and waits.
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let got = settings_get(&mut conn, &["capabilities"]).await;
        if got["capabilities"]["entries"][0]["left_out"].is_null() {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "{got}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    waits(&mut conn, "after the program").await;

    // The owner's node.toml offers `notes` without sensing, then not.
    cli(
        &paths,
        &["cap", "add", "notes.list", "--effect", "read", "--", "true"],
    )
    .await
    .unwrap();
    refused(&mut conn, "with the owner's").await;
    cli(&paths, &["cap", "rm", "notes.list"]).await.unwrap();
    waits(&mut conn, "after the owner's").await;
    let cfg = nerve_node::cli::read_config(&paths).await.unwrap().0;
    let p = &cfg.centers[0].policy;
    assert!(p.caps.is_empty() && p.allow.is_empty(), "{p:?}");

    // The owner declares `notes.look` too and turns it on for lab: that
    // `on` is the owner's capability's, and stays when the owner removes
    // the center's of that name.
    cli(
        &paths,
        &["cap", "add", "notes.look", "--effect", "read", "--", "true"],
    )
    .await
    .unwrap();
    cli(
        &paths,
        &["cap", "set", "notes.look", "on", "--center", "lab"],
    )
    .await
    .unwrap();
    cli(&paths, &["cap", "rm", "notes.look", "--center", "lab"])
        .await
        .unwrap();
    let cfg = nerve_node::cli::read_config(&paths).await.unwrap().0;
    assert!(cfg.centers[0].capabilities.is_empty());
    let on = cfg.centers[0].policy.caps.get("notes.look");
    assert_eq!(on, Some(&CapSetting::On), "{cfg:?}");
    daemon.stop().await;
}

/// The owner's `on` for a center's capability that senses was given for
/// the center's command: once the owner declares one of that name, the
/// center waits for the owner's `on` for the owner's, and `cap add` says
/// so; the center's removal of its own does not bring the `on` back.
#[tokio::test(flavor = "multi_thread")]
async fn the_owners_on_for_a_centers_sensing_one_never_turns_on_the_owners() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(
        dir.path(),
        &[(&center, "lab")],
        nerve_policy::Mode::Folder,
        true,
        |_| {},
    )
    .await;
    let paths = daemon.paths().clone();
    let mut conn = linked(&mut center).await;
    let snap = json!({"name": "cam.snap", "effect": "sense", "command": ["echo", "theirs"]});
    invoke(
        &mut conn,
        "settings",
        "cap-add",
        json!({"capability": snap}),
    )
    .await
    .unwrap();
    cli(&paths, &["cap", "set", "cam.snap", "on", "--center", "lab"])
        .await
        .unwrap();
    assert_eq!(
        call(&mut conn, "cam.snap", json!({})).await.unwrap(),
        json!("theirs\n")
    );
    let out = cli(
        &paths,
        &[
            "cap", "add", "cam.snap", "--effect", "sense", "--", "echo", "mine",
        ],
    )
    .await
    .unwrap();
    assert!(
        out.contains("lab: a switch or allow rule set before covered cam.snap"),
        "{out}"
    );
    for when in ["the owner's", "after the center's removal"] {
        let e = call(&mut conn, "cam.snap", json!({})).await.unwrap_err();
        assert_eq!(code_of(&e), "disabled", "{when}: {}", e.message);
        invoke(&mut conn, "settings", "cap-rm", json!({"name": "cam.snap"}))
            .await
            .ok();
    }
    let cfg = nerve_node::cli::read_config(&paths).await.unwrap().0;
    assert!(cfg.centers[0].capabilities.is_empty());
    let off = cfg.centers[0].policy.caps.get("cam.snap");
    assert_eq!(off, Some(&CapSetting::Off), "{cfg:?}");
    daemon.stop().await;
}

/// The owner's `on` for a capability of the owner's, or for a program's,
/// is given for that one: a center's own of that name that senses, left
/// out meanwhile, waits for an `on` given for its command once it is
/// offered again. The owner's `cap rm` says so; while a program keeps the
/// center's own out, the owner sets no `on` for it, and a file the owner
/// takes keeps it off.
#[tokio::test(flavor = "multi_thread")]
async fn the_owners_on_for_another_never_turns_on_a_centers_of_that_name() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(
        dir.path(),
        &[(&center, "lab")],
        nerve_policy::Mode::Folder,
        true,
        allow_desk,
    )
    .await;
    let paths = daemon.paths().clone();
    let mut conn = linked(&mut center).await;
    for name in ["cam.look", "notes.look"] {
        let look = json!({"name": name, "effect": "sense", "command": ["echo", "centers"]});
        invoke(
            &mut conn,
            "settings",
            "cap-add",
            json!({"capability": look}),
        )
        .await
        .unwrap();
    }
    // The owner's node.toml takes the name, as a read and as a sense.
    for effect in ["read", "sense"] {
        cli(
            &paths,
            &[
                "cap", "add", "cam.look", "--effect", effect, "--", "echo", "owners",
            ],
        )
        .await
        .unwrap();
        cli(&paths, &["cap", "set", "cam.look", "on", "--center", "lab"])
            .await
            .unwrap();
        assert_eq!(
            call(&mut conn, "cam.look", json!({})).await.unwrap(),
            json!("owners\n"),
            "{effect}"
        );
        // Another write of the owner's leaves that `on` alone.
        cli(&paths, &["cap", "set", "other", "off", "--center", "lab"])
            .await
            .unwrap();
        assert_eq!(
            call(&mut conn, "cam.look", json!({})).await.unwrap(),
            json!("owners\n"),
            "{effect}"
        );
        let out = cli(&paths, &["cap", "rm", "cam.look"]).await.unwrap();
        assert!(
            out.contains("lab: a switch or allow rule set before covered cam.look"),
            "{effect}: {out}"
        );
        let e = call(&mut conn, "cam.look", json!({})).await.unwrap_err();
        assert_eq!(code_of(&e), "disabled", "{effect}: {}", e.message);
    }

    // A program offers `notes`, whose `look` only reads: lab is offered
    // neither, and the owner sets no `on` that would reach lab's own.
    let program = attach(
        &daemon,
        json!([{"id": "notes", "actions": {"look": {"effect": "read"}}}]),
    )
    .await;
    for on in ["notes.look", "notes"] {
        let e = cli(&paths, &["cap", "set", on, "on", "--center", "lab"])
            .await
            .unwrap_err();
        assert!(
            e.contains("center lab keeps its own notes.look, which senses or actuates"),
            "{on}: {e}"
        );
    }
    // A file the owner takes with that `on` keeps it off, and says so.
    let file = paths.config_file();
    let mut cfg = NodeConfig::parse(&std::fs::read_to_string(&file).unwrap()).unwrap();
    let caps = &mut cfg.center_mut("lab").unwrap().policy.caps;
    caps.insert("notes.look".into(), CapSetting::On);
    std::fs::write(&file, cfg.to_toml()).unwrap();
    let said = cli(&paths, &["config", "accept"]).await.unwrap();
    assert!(
        said.contains(
            "lab: its own notes.look senses or actuates and is left out while a program offers notes,"
        ),
        "{said}"
    );
    assert!(!said.contains("set before"), "{said}");
    // An allow rule in place of the `on` is told once, the same way: it is
    // the center's own that the rule would turn on, not the program's.
    let mut cfg = NodeConfig::parse(&std::fs::read_to_string(&file).unwrap()).unwrap();
    let lab = cfg.center_mut("lab").unwrap();
    lab.policy.caps.remove("notes.look");
    lab.policy.allow.push("notes.look".into());
    std::fs::write(&file, cfg.to_toml()).unwrap();
    let said = cli(&paths, &["config", "accept"]).await.unwrap();
    assert_eq!(
        said.matches("lab: its own notes.look senses or actuates")
            .count(),
        1,
        "{said}"
    );
    assert!(!said.contains("would go with the center's own"), "{said}");
    drop(program);
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let got = settings_get(&mut conn, &["capabilities"]).await;
        let entries = got["capabilities"]["entries"].as_array().unwrap().clone();
        if entries.iter().all(|e| e["left_out"].is_null()) {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "{got}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let e = call(&mut conn, "notes.look", json!({})).await.unwrap_err();
    assert_eq!(code_of(&e), "disabled", "{}", e.message);
    daemon.stop().await;
}

/// A center's capability that takes a path is decided as a command on
/// it, in `folder` mode, whatever it says it does: the folder rule lets it
/// through on a path in a folder that allows commands, and refuses it on
/// one in a folder that only allows reading, or outside the folders, also
/// once the center turned it on. The test node cannot confine a command
/// (no Landlock, [`options`]), so one let through stops there, as the
/// installed node's would run.
#[tokio::test(flavor = "multi_thread")]
async fn a_centers_capability_takes_a_path_only_in_a_folder_that_allows_commands() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let (work, read, outside) = (root.join("work"), root.join("read"), root.join("outside"));
    for d in [&work, &read, &outside] {
        std::fs::create_dir_all(d).unwrap();
    }
    let mut center = FakeCenter::start(false).await.unwrap();
    let folder = |path: &Path, access: &str| nerve_policy::config::Folder {
        path: path.display().to_string(),
        access: nerve_policy::config::Access::parse(access).unwrap(),
    };
    let daemon = node(
        &root,
        &[(&center, "lab")],
        nerve_policy::Mode::Folder,
        true,
        |c| c.centers[0].policy.folders = vec![folder(&work, "rwx"), folder(&read, "r")],
    )
    .await;
    let mut conn = linked(&mut center).await;
    let show = json!({"name": "files.show", "effect": "read", "command": ["cat", "--", "{path}"],
                      "params": {"type": "object", "required": ["path"],
                                 "properties": {"path": {"type": "string", "x-nerve-path": "read"}}}});
    invoke(
        &mut conn,
        "settings",
        "cap-add",
        json!({"capability": show}),
    )
    .await
    .unwrap();
    let wire = |p: &Path| nerve_policy::paths::to_wire(&p.join("in.txt"));
    for on in [false, true] {
        if on {
            settings_set(&mut conn, |d| {
                d["policy"]["caps"] = json!({"files.show": "on"})
            })
            .await
            .expect("the center turns its own on");
        }
        let e = call(&mut conn, "files.show", json!({"path": wire(&work)}))
            .await
            .unwrap_err();
        assert_eq!(e.message, nerve_node::daemon::NOT_CONFINED, "on {on}");
        for at in [&read, &outside] {
            let e = call(&mut conn, "files.show", json!({"path": wire(at)}))
                .await
                .unwrap_err();
            assert_eq!(code_of(&e), "forbidden", "{at:?}, on {on}");
            assert_eq!(
                e.message, "outside the folders that allow running",
                "{at:?}, on {on}"
            );
        }
    }
    daemon.stop().await;
}

/// What one center added is that center's alone: another one is not
/// offered it, cannot call it, does not see it in its settings or in `cap
/// ls` for it, and cannot remove it.
#[tokio::test(flavor = "multi_thread")]
async fn another_center_never_sees_what_one_added() {
    let dir = tempfile::tempdir().unwrap();
    let mut lab = FakeCenter::start(false).await.unwrap();
    let mut ops = FakeCenter::start(false).await.unwrap();
    let daemon = node(
        dir.path(),
        &[(&lab, "lab"), (&ops, "ops")],
        nerve_policy::Mode::User,
        true,
        |_| {},
    )
    .await;
    let paths = daemon.paths().clone();
    let mut lab_conn = linked(&mut lab).await;
    let mut ops_conn = linked(&mut ops).await;
    invoke(
        &mut lab_conn,
        "settings",
        "cap-add",
        json!({"capability": say_back()}),
    )
    .await
    .unwrap();
    let ls = cli(&paths, &["cap", "ls", "--center", "ops"])
        .await
        .unwrap();
    assert!(!ls.contains("say.back"), "{ls}");
    let ls = cli(&paths, &["cap", "ls", "--center", "lab"])
        .await
        .unwrap();
    assert!(ls.contains("added by center lab"), "{ls}");
    assert!(described(&mut lab_conn, "say").await.is_some());
    assert!(described(&mut ops_conn, "say").await.is_none());
    let e = call(&mut ops_conn, "say.back", json!({"word": "x"}))
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), "unknown_capability");
    let got = settings_get(&mut ops_conn, &["capabilities", "document"]).await;
    assert_eq!(got["capabilities"]["entries"], json!([]), "{got}");
    assert!(!got.to_string().contains("say.back"), "{got}");
    let e = invoke(
        &mut ops_conn,
        "settings",
        "cap-rm",
        json!({"name": "say.back"}),
    )
    .await
    .unwrap_err();
    assert!(
        e.message.contains("added no capability say.back"),
        "{}",
        e.message
    );
    // The same name is free for it: its own, not the other's.
    let mut own = say_back();
    own["command"] = json!(["printf", "ops:%s", "{word}"]);
    invoke(
        &mut ops_conn,
        "settings",
        "cap-add",
        json!({"capability": own}),
    )
    .await
    .unwrap();
    assert_eq!(
        call(&mut ops_conn, "say.back", json!({"word": "x"}))
            .await
            .unwrap(),
        json!("ops:x")
    );
    assert_eq!(
        call(&mut lab_conn, "say.back", json!({"word": "x"}))
            .await
            .unwrap(),
        json!("x\n")
    );
    // Each center's view lists its own once, and not the other's.
    let ls = cli(&paths, &["cap", "ls", "--center", "lab"])
        .await
        .unwrap();
    let rows: Vec<&str> = ls.lines().filter(|l| l.starts_with("say.back")).collect();
    assert_eq!(rows.len(), 1, "{ls}");
    assert!(rows[0].contains("center lab"), "{ls}");
    assert!(!ls.contains("ops:%s"), "{ls}");
    daemon.stop().await;
}

/// A node run by hand has no `nerve-run`, which these run as: it takes
/// none, and says why.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_run_by_hand_takes_none_and_says_why() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(
        dir.path(),
        &[(&center, "lab")],
        nerve_policy::Mode::User,
        false,
        |_| {},
    )
    .await;
    let paths = daemon.paths().clone();
    let mut conn = linked(&mut center).await;
    let e = invoke(
        &mut conn,
        "settings",
        "cap-add",
        json!({"capability": say_back()}),
    )
    .await
    .unwrap_err();
    assert_eq!(code_of(&e), "unavailable");
    assert!(
        e.message
            .contains("runs as nerve-run, which only the installed node has"),
        "{}",
        e.message
    );
    let got = settings_get(&mut conn, &["capabilities"]).await;
    assert!(
        got["capabilities"]["refused"]
            .as_str()
            .is_some_and(|r| r.contains("runs by hand")),
        "{got}"
    );
    assert!(settings_audit(&paths, "center lab").is_empty());
    daemon.stop().await;
}

/// A `sudo` that takes one password, which no test gives: the conformance
/// part's wrong one is refused, whatever the machine's own sudo does.
fn fake_sudo(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join("fake-sudo");
    let body = "#!/bin/sh\nv=\nwhile [ $# -gt 0 ]; do case \"$1\" in -S|-k) shift ;; -p) p=\"$2\"; shift 2 ;; \
                -v) v=1; shift ;; *) break ;; esac; done\nprintf %s \"$p\" >&2\nIFS= read -r pw\n\
                [ \"$pw\" = 'the-one-right-password' ] || { echo 'Sorry, try again.' >&2; exit 1; }\n\
                [ -n \"$v\" ] && exit 0\nexec \"$@\"\n";
    std::fs::write(&p, body).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

/// The node part of the conformance runner, with the settings grant and a
/// node that takes capabilities from a center: its §7.4.2 checks pass, not
/// only the refusal of a node that takes none.
#[tokio::test(flavor = "multi_thread")]
async fn passes_the_conformance_checks_of_capabilities_a_center_adds() {
    use std::sync::{Arc, Mutex};
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let running: Arc<Mutex<Option<Daemon>>> = Arc::default();
    let keep = running.clone();
    let report = nerve_conformance::node_part::run(move |link| async move {
        let o = options(&root, true);
        nerve_node::pair::pair(&o.paths, &link, None).await?;
        // The part sends one wrong sudo password. A fake sudo that wants a
        // password nobody gives refuses it; the machine's own sudo may be
        // passwordless (a CI runner's is) and take any.
        let sudo = fake_sudo(&root);
        owner_edit(&o.paths, |c| {
            c.centers[0].settings = SettingsGrant::Write;
            c.machine.sudo_path = Some(sudo.display().to_string());
        })
        .await;
        let folder = root.join("home").join("work");
        std::fs::create_dir_all(&folder).unwrap();
        let d = Daemon::start(o).await?;
        *keep.lock().unwrap() = Some(d);
        Ok(nerve_conformance::node_part::Setup {
            folder: Some(folder.display().to_string()),
            sudo_password: None,
        })
    })
    .await;
    let d = running.lock().unwrap().take();
    if let Some(d) = d {
        d.stop().await;
    }
    assert!(report.ok(), "{report}");
    let caps: Vec<_> = report
        .outcomes
        .iter()
        .filter(|o| o.section == "7.4.2")
        .collect();
    assert_eq!(caps.len(), 2, "{report}");
    assert!(caps.iter().all(|o| o.result.is_ok()), "{report}");
}

/// However the owner takes a center's own out of node.toml, that center's
/// `on` and allow rules for it go along, as with `cap rm --center`: by
/// `config unset` with the node running, by a hand edit that `config
/// accept` takes, and for the owner's `on` of the capability as a whole
/// given for the center's own that senses, and by `config unset` with the
/// node stopped. Kept, they would turn on what a program the owner allows
/// offers under that name later.
#[tokio::test(flavor = "multi_thread")]
async fn a_centers_switches_go_with_its_own_however_the_owner_removes_it() {
    for route in ["unset", "accept", "owners-on", "stopped"] {
        let dir = tempfile::tempdir().unwrap();
        let mut center = FakeCenter::start(false).await.unwrap();
        let daemon = node(
            dir.path(),
            &[(&center, "lab")],
            nerve_policy::Mode::Folder,
            true,
            allow_desk,
        )
        .await;
        let paths = daemon.paths().clone();
        let mut conn = linked(&mut center).await;
        let sensing = route == "owners-on";
        let effect = if sensing { "sense" } else { "execute" };
        let snap = json!({"name": "cam.snap", "effect": effect, "command": ["echo", "list"]});
        invoke(
            &mut conn,
            "settings",
            "cap-add",
            json!({"capability": snap}),
        )
        .await
        .unwrap();
        if sensing {
            cli(&paths, &["cap", "set", "cam", "on", "--center", "lab"])
                .await
                .unwrap();
        } else {
            settings_set(&mut conn, |d| {
                d["policy"]["caps"] = json!({"cam.snap": "on"});
                d["policy"]["allow"] = json!(["cam.snap"]);
            })
            .await
            .expect("its own action, by its name");
        }
        assert_eq!(
            call(&mut conn, "cam.snap", json!({})).await.unwrap(),
            json!("list\n"),
            "{route}"
        );

        if route == "stopped" {
            daemon.stop().await;
            cli(&paths, &["config", "unset", "center.lab.capability"])
                .await
                .unwrap();
            nothing_of_lab_for_cam(&paths, route).await;
            continue;
        }
        if route == "accept" {
            let file = paths.config_file();
            let mut cfg = NodeConfig::parse(&std::fs::read_to_string(&file).unwrap()).unwrap();
            cfg.center_mut("lab").unwrap().capabilities.clear();
            std::fs::write(&file, cfg.to_toml()).unwrap();
            let said = cli(&paths, &["config", "accept"]).await.unwrap();
            assert!(
                said.contains("lab: its own capability is gone from the file, so its on and allow rules for cam.snap went with it"),
                "{said}"
            );
        } else {
            cli(&paths, &["config", "unset", "center.lab.capability"])
                .await
                .unwrap();
        }
        nothing_of_lab_for_cam(&paths, route).await;

        // The program attaches with a `cam.snap` that senses: it waits for
        // the owner's `on`.
        let program = attach(
            &daemon,
            json!([{"id": "cam", "actions": {"snap": {"effect": "sense"}}}]),
        )
        .await;
        let e = call(&mut conn, "cam.snap", json!({})).await.unwrap_err();
        assert_eq!(code_of(&e), "forbidden", "{route}: {}", e.message);
        assert!(e.message.contains("set to on"), "{route}: {}", e.message);
        let ls = cli(&paths, &["cap", "ls", "--json"]).await.unwrap();
        let ls: Value = serde_json::from_str(&ls).unwrap();
        let row = ls["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == "cam.snap" && r["source"] == "program desk")
            .cloned()
            .unwrap();
        assert_ne!(row["now"]["lab"], "on", "{route}: {row}");
        drop(program);
        daemon.stop().await;
    }
}

/// That the center `lab` has no capability of its own left, and no `on`
/// or allow rule for `cam.snap` or `cam`.
async fn nothing_of_lab_for_cam(paths: &NodePaths, route: &str) {
    let cfg = nerve_node::cli::read_config(paths).await.unwrap().0;
    let lab = cfg.center("lab").unwrap();
    assert!(lab.capabilities.is_empty(), "{route}");
    assert_eq!(lab.policy.caps.get("cam.snap"), None, "{route}");
    assert_eq!(lab.policy.caps.get("cam"), None, "{route}");
    assert!(lab.policy.allow.is_empty(), "{route}: {:?}", lab.policy);
}
