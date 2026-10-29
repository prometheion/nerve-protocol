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
use nerve_conformance::wire::{Conn, code_of};
use nerve_node::{Daemon, NodeOptions, NodePaths};
use nerve_policy::NodeConfig;
use nerve_policy::config::{CapSetting, SettingsGrant};
use serde_json::{Value, json};
use tokio::net::TcpStream;

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
/// ls` says who added it; and the owner removes it.
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
/// folder mode one that names no path needs `on`, which the center may set;
/// one that senses waits for the owner's `on` in every mode, also where
/// an earlier `on` of the center's would cover it; and an `off` the owner
/// set stays until the owner changes it.
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
    settings_set(&mut conn, |d| d["policy"]["caps"] = json!({"notes": "on"}))
        .await
        .expect("the center turns its own on");
    let notes = described(&mut conn, "notes").await.unwrap();
    assert_eq!(notes["actions"]["show"]["effect"], "execute");
    assert_eq!(
        call(&mut conn, "notes.show", json!({})).await.unwrap(),
        json!("notes\n")
    );

    // It comes to sense: the center's own `on` for `notes` covered it, so
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
            "capability cam.look (added by center lab, waits for your cap set on): echo frame"
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
    settings_set(&mut conn, |d| d["policy"]["caps"]["tool"] = json!("on"))
        .await
        .expect("the center turns on one that does not sense");
    assert_eq!(
        call(&mut conn, "tool.go", json!({})).await.unwrap(),
        json!("went\n")
    );
    cli(&paths, &["cap", "set", "tool", "off", "--center", "lab"])
        .await
        .unwrap();
    daemon.reload().unwrap();
    let e = call(&mut conn, "tool.go", json!({})).await.unwrap_err();
    assert_eq!(code_of(&e), "disabled");
    let e = settings_set(&mut conn, |d| d["policy"]["caps"]["tool"] = json!("on"))
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), "forbidden");
    assert!(
        e.message
            .contains("a capability this center added stays off until the owner turns it on"),
        "{}",
        e.message
    );
    let cfg = nerve_node::cli::read_config(&paths).await.unwrap().0;
    assert_eq!(
        cfg.centers[0].policy.caps.get("tool"),
        Some(&CapSetting::Off)
    );
    daemon.stop().await;
}

/// What one center added is that center's alone: another one is not
/// offered it, cannot call it, does not see it in its settings and cannot
/// remove it.
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
        owner_edit(&o.paths, |c| c.centers[0].settings = SettingsGrant::Write).await;
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
