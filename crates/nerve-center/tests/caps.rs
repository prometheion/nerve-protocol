//! The web UI's Capabilities tab end to end, in process: a real center and a
//! real node daemon. Through the tab's API the center adds a capability of
//! its own to a node that gave it the settings grant `write`, the node
//! offers it, the agent finds it with `list` and runs it with `execute`, the
//! center edits and removes it, and a node without the grant is shown read
//! only. The node runs by hand and stands for `nerve-run` with its own user
//! (NodeOptions::config_caps_by_hand, as nerve-node's tests do), in user mode
//! with no exec shim, so the commands run unconfined. Linux only: the
//! commands are Linux programs (`echo`, `printf`).
#![cfg(target_os = "linux")]

use std::time::Duration;

use clap::Parser;
use nerve_center::config::Args;
use nerve_center::mcp::Engine;
use nerve_center::server::{self, Running};
use nerve_node::{Daemon, NodeOptions, NodePaths};
use nerve_proto::link::PairLink;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn center(dir: &std::path::Path) -> Running {
    nerve_transport::init_crypto();
    let args = Args::try_parse_from([
        "nerve-center",
        "--state-dir",
        dir.to_str().unwrap(),
        "--name",
        "test-center",
        "--listen",
        "127.0.0.1:0",
        "--plain-loopback",
        "--ui",
        "127.0.0.1:0",
        "--mcp",
        "off",
    ])
    .unwrap();
    let lock = nerve_center::attach::try_lock(dir)
        .unwrap()
        .expect("the lock is free");
    server::start(&args, lock).await.unwrap()
}

/// The loopback web UI, as the page calls it: a session from the login
/// with the owner token, sent as a header with every call.
struct Ui {
    addr: std::net::SocketAddr,
    session: String,
}

async fn http(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (u16, String, String) {
    let mut io = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if !body.is_empty() {
        req.push_str("Content-Type: application/json\r\n");
    }
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    io.write_all(req.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    io.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, head.to_string(), body.to_string())
}

impl Ui {
    async fn open(r: &Running) -> Ui {
        let addr = r.ui.expect("a UI");
        let token = nerve_center::owner::read(r.center.dir())
            .unwrap()
            .expect("an owner token");
        let login = serde_json::json!({ "token": token }).to_string();
        let (status, _, body) = http(addr, "POST", "/login", &[], &login).await;
        assert_eq!(status, 200, "{body}");
        let v: Value = serde_json::from_str(&body).unwrap();
        let session = v["session"].as_str().expect("a session").to_string();
        Ui { addr, session }
    }

    async fn api(&self, method: &str, path: &str, body: Value) -> (u16, Value) {
        let body = if body.is_null() {
            String::new()
        } else {
            body.to_string()
        };
        let headers = [("X-Nerve-Session", self.session.as_str())];
        let (status, _, text) = http(self.addr, method, path, &headers, &body).await;
        (
            status,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        )
    }

    async fn caps(&self, node_id: &str) -> Value {
        let (status, v) = self
            .api("GET", &format!("/api/caps?id={node_id}"), Value::Null)
            .await;
        assert_eq!(status, 200, "{v}");
        v
    }
}

async fn wait_for<T>(what: &str, mut f: impl AsyncFnMut() -> Option<T>) -> T {
    for _ in 0..300 {
        if let Some(v) = f().await {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out: {what}")
}

async fn owner_edit(paths: &NodePaths, f: impl Fn(&mut nerve_policy::NodeConfig)) {
    nerve_node::cli::edit(paths, |c| {
        f(c);
        Ok(())
    })
    .await
    .expect("the owner's edit");
}

async fn rpc(e: &Engine, id: u64, method: &str, params: Value) -> Value {
    e.handle(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
        .await
        .expect("a reply")
}

async fn list_text(e: &Engine, args: Value) -> String {
    let r = rpc(
        e,
        900,
        "tools/call",
        json!({"name": "list", "arguments": args}),
    )
    .await;
    r["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// `execute` of `unit` on `node`, after `list` of its details: the result.
async fn execute(e: &Engine, node: &str, unit: &str, args: Value) -> Value {
    list_text(e, json!({"node": node, "capability": unit})).await;
    let r = rpc(
        e,
        901,
        "tools/call",
        json!({"name": "execute", "arguments": {"node": node, "capability": unit, "args": args}}),
    )
    .await;
    r["result"].clone()
}

fn form(name: &str, command: &str) -> Value {
    json!({"name": name, "summary": "Says the word back.", "effect": "read",
           "command": command,
           "params": r#"{"type": "object", "properties": {"word": {"type": "string"}}, "required": ["word"], "additionalProperties": false}"#,
           "result": "", "timeout": "", "platform": "any"})
}

/// A node by hand, paired with `r`, with the settings grant and user mode,
/// and one capability of the owner's. `takes` stands for the installed node
/// that takes a center's capabilities (NodeOptions::config_caps_by_hand).
async fn node(r: &Running, dir: &std::path::Path, takes: bool) -> (Daemon, NodePaths) {
    node_in(r, dir, takes, nerve_policy::Mode::User).await
}

/// [`node`] in the mode `mode`.
async fn node_in(
    r: &Running,
    dir: &std::path::Path,
    takes: bool,
    mode: nerve_policy::Mode,
) -> (Daemon, NodePaths) {
    let root = dir.join("node");
    let mut o = NodeOptions::new(NodePaths::new(root.join("config"), root.join("state")));
    o.home = root.join("home");
    std::fs::create_dir_all(&o.home).unwrap();
    o.full_rights = Some(false);
    o.config_caps_by_hand = takes;
    let link = PairLink::parse(r.center.new_pairing()["link"].as_str().unwrap()).unwrap();
    nerve_node::pair::pair(&o.paths, &link, Some("lab"))
        .await
        .expect("pair");
    owner_edit(&o.paths, |c| {
        let e = &mut c.centers[0];
        e.settings = nerve_policy::config::SettingsGrant::Write;
        e.policy.mode = mode;
        c.capabilities = nerve_policy::NodeConfig::parse(
            "[[capability]]\nname = \"owner.who\"\neffect = \"read\"\ncommand = [\"id\", \"-un\"]\n",
        )
        .unwrap()
        .capabilities;
    })
    .await;
    let paths = o.paths.clone();
    (Daemon::start(o).await.expect("start"), paths)
}

/// The node as the Overview shows it, once it is online with the grant.
async fn online(ui: &Ui) -> Value {
    wait_for("the node comes online with the grant", async || {
        let (_, ov) = ui.api("GET", "/api/overview", Value::Null).await;
        let n = ov["nodes"][0].clone();
        (n["online"] == true && n["settings_write"] == true).then_some(n)
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_capability_added_through_the_web_ui_is_listed_and_runs() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(&dir.path().join("center")).await;

    let (daemon, paths) = node(&r, dir.path(), true).await;
    let ui = Ui::open(&r).await;
    let node = online(&ui).await;
    let id = node["id"].as_str().unwrap().to_string();
    let name = node["name"].as_str().unwrap().to_string();

    // The tab lists the units with where they come from.
    let v = ui.caps(&id).await;
    assert_eq!(v["settings_write"], true, "{v}");
    assert_eq!(v["added"]["entries"], json!([]), "{v}");
    assert_eq!(v["added"]["refused"], Value::Null, "{v}");
    let unit = |v: &Value, n: &str| {
        v["units"]
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["name"] == n)
            .cloned()
    };
    assert_eq!(unit(&v, "fs.read").unwrap()["source"], "built-in", "{v}");
    assert_eq!(
        unit(&v, "owner.who").unwrap()["source"],
        "the owner's node.toml"
    );
    assert!(unit(&v, "settings.set").is_none(), "{v}");

    // The form is checked by the node's own rules, before anything is sent.
    let mut broken = form("say.back", "echo {nothing}");
    let (status, c) = ui
        .api("POST", "/api/caps/check", json!({"form": broken}))
        .await;
    assert_eq!(status, 200, "{c}");
    assert_eq!(c["ok"], false);
    assert!(
        c["errors"]["command"]
            .as_str()
            .unwrap()
            .contains("{nothing} names no argument"),
        "{c}"
    );
    broken["params"] = json!("{\"oneOf\": []}");
    let (status, c) = ui
        .api("POST", "/api/caps/check", json!({"form": broken}))
        .await;
    assert_eq!(status, 200);
    assert!(c["errors"]["params"].as_str().unwrap() != "", "{c}");
    let (status, e) = ui
        .api(
            "POST",
            "/api/caps/save",
            json!({"id": id, "form": broken, "adding": true}),
        )
        .await;
    assert_eq!(status, 400, "{e}");
    assert!(e["errors"]["params"].as_str().unwrap() != "", "{e}");
    assert_eq!(ui.caps(&id).await["added"]["entries"], json!([]));

    // Added: the node offers it to the agent, counted as execute.
    let (status, v) = ui
        .api(
            "POST",
            "/api/caps/save",
            json!({"id": id, "form": form("say.back", "echo {word}"), "adding": true}),
        )
        .await;
    assert_eq!(status, 200, "{v}");
    // The answer comes once the center has the node's new description.
    let v = ui.caps(&id).await;
    let say = unit(&v, "say.back").expect("offered at once");
    assert_eq!(say["source"], "this center", "{v}");
    assert_eq!(say["effect"], "execute", "{v}");
    let entry = &v["added"]["entries"][0];
    assert_eq!(entry["name"], "say.back");
    assert_eq!(entry["form"]["command"], "echo {word}");
    assert_eq!(entry["form"]["effect"], "read");

    let e = Engine::new(&r.center, "test");
    rpc(
        &e,
        1,
        "initialize",
        json!({"protocolVersion": "2025-06-18", "capabilities": {},
               "clientInfo": {"name": "test", "version": "1"}}),
    )
    .await;
    let listed = list_text(&e, json!({"node": name})).await;
    assert!(listed.contains("say.back"), "{listed}");
    let details = list_text(&e, json!({"node": name, "capability": "say.back"})).await;
    assert!(details.contains("effect: execute"), "{details}");
    let out = execute(&e, &name, "say.back", json!({"word": "hello"})).await;
    assert_ne!(out["isError"], true, "{out}");
    assert_eq!(out["structuredContent"]["result"], "hello\n", "{out}");
    // The node's settings stay out of the agent's reach.
    let out = execute(&e, &name, "settings.cap-add", json!({"capability": {}})).await;
    assert_eq!(out["isError"], true, "{out}");

    // Edited: the command changes; the name stays.
    let (status, v) = ui
        .api(
            "POST",
            "/api/caps/save",
            json!({"id": id, "form": form("say.back", "printf %s! {word}"), "adding": false}),
        )
        .await;
    assert_eq!(status, 200, "{v}");
    let out = execute(&e, &name, "say.back", json!({"word": "hi"})).await;
    assert_eq!(out["structuredContent"]["result"], "hi!", "{out}");

    // The node's own refusal reaches the tab as it said it.
    let (status, v) = ui
        .api(
            "POST",
            "/api/caps/save",
            json!({"id": id, "form": form("owner.more", "echo {word}"), "adding": true}),
        )
        .await;
    assert_eq!(status, 409, "{v}");
    assert_eq!(v["code"], "forbidden", "{v}");
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .contains("the owner declares owner in node.toml"),
        "{v}"
    );

    // The center's log says what the web UI did.
    let q = nerve_transport::log::Query {
        limit: 500,
        ..Default::default()
    };
    let log = r.center.log_json(&q).to_string();
    assert!(
        log.contains("capability say.back added from the web UI"),
        "{log}"
    );

    // Removed.
    let (status, v) = ui
        .api(
            "POST",
            "/api/caps/remove",
            json!({"id": id, "name": "say.back"}),
        )
        .await;
    assert_eq!(status, 200, "{v}");
    let v = ui.caps(&id).await;
    assert!(unit(&v, "say.back").is_none(), "{v}");
    assert_eq!(v["added"]["entries"], json!([]), "{v}");
    // Each change the web UI made is in the log, the node's refusal as a
    // warning.
    let log = r.center.log_json(&q);
    let level_of = |text: &str| -> Vec<String> {
        log["entries"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["msg"].as_str().is_some_and(|m| m.contains(text)))
            .map(|e| e["level"].as_str().unwrap_or_default().to_string())
            .collect()
    };
    for (text, level) in [
        ("capability say.back added from the web UI", "info"),
        ("capability say.back changed from the web UI", "info"),
        ("capability say.back removed from the web UI", "info"),
        (
            "the node did not add a capability from the web UI (forbidden)",
            "warn",
        ),
    ] {
        assert_eq!(level_of(text), [level], "{text}: {log}");
    }

    // Without the grant the machine is shown read only: no added list, and
    // a save is the node's refusal.
    owner_edit(&paths, |c| {
        c.centers[0].settings = nerve_policy::config::SettingsGrant::Off;
    })
    .await;
    daemon.reload().unwrap();
    let v = wait_for("the grant is gone", async || {
        let v = ui.caps(&id).await;
        (v["settings_write"] == false).then_some(v)
    })
    .await;
    assert_eq!(v["added"], Value::Null, "{v}");
    assert!(unit(&v, "owner.who").is_some(), "{v}");
    let (status, v) = ui
        .api(
            "POST",
            "/api/caps/save",
            json!({"id": id, "form": form("say.back", "echo {word}"), "adding": true}),
        )
        .await;
    assert_eq!(status, 409, "{v}");
    daemon.stop().await;
    r.stop().await;
}

/// In folder mode, which a new pairing starts in, what a center added
/// waits for an `on`: the tab gets it as added, neither left out nor among
/// the units, which the page marks "not offered". An `on` for that action
/// by its name, which the center sets in its settings, offers it; one for
/// its capability as a whole stays the owner's.
#[tokio::test(flavor = "multi_thread")]
async fn in_folder_mode_an_added_capability_waits_for_its_on() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(&dir.path().join("center")).await;
    let (daemon, _) = node_in(&r, dir.path(), true, nerve_policy::Mode::Folder).await;
    let ui = Ui::open(&r).await;
    let id = online(&ui).await["id"].as_str().unwrap().to_string();
    let (status, v) = ui
        .api(
            "POST",
            "/api/caps/save",
            json!({"id": id, "form": form("say.back", "echo {word}"), "adding": true}),
        )
        .await;
    assert_eq!(status, 200, "{v}");
    let has_unit = |v: &Value| {
        v["units"]
            .as_array()
            .unwrap()
            .iter()
            .any(|u| u["name"] == "say.back")
    };
    let v = ui.caps(&id).await;
    let entry = &v["added"]["entries"][0];
    assert_eq!(entry["name"], "say.back", "{v}");
    assert_eq!(entry["left_out"], Value::Null, "{v}");
    assert!(!has_unit(&v), "{v}");

    // The center's own settings: not all of `say`, but `say.back`.
    let set = async |caps: Value| {
        let (status, got) = ui
            .api("GET", &format!("/api/nodes/settings?id={id}"), Value::Null)
            .await;
        assert_eq!(status, 200, "{got}");
        let mut doc = got["document"].clone();
        doc["policy"]["caps"] = caps;
        ui.api(
            "POST",
            "/api/nodes/settings",
            json!({"id": id, "document": doc, "if_version": got["version"]}),
        )
        .await
    };
    let (status, e) = set(json!({"say": "on"})).await;
    assert_ne!(status, 200, "{e}");
    assert!(e.to_string().contains("only the owner can turn on"), "{e}");
    let (status, v) = set(json!({"say.back": "on"})).await;
    assert_eq!(status, 200, "{v}");
    let v = wait_for("the tab lists it once it is on", async || {
        let v = ui.caps(&id).await;
        has_unit(&v).then_some(v)
    })
    .await;
    let say = v["units"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["name"] == "say.back")
        .unwrap();
    assert_eq!(
        (&say["source"], &say["effect"]),
        (&json!("this center"), &json!("execute")),
        "{v}"
    );
    assert_eq!(v["added"]["entries"][0]["left_out"], Value::Null, "{v}");
    daemon.stop().await;
    r.stop().await;
}

/// A node that takes no capability from a center (one run by hand, which
/// has no `nerve-run`; Windows says so the same way) gives the tab its
/// reason, which the page shows in place of the form, and refuses a save.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_that_takes_none_says_why_on_the_tab() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(&dir.path().join("center")).await;
    let (daemon, _) = node(&r, dir.path(), false).await;
    let ui = Ui::open(&r).await;
    let id = online(&ui).await["id"].as_str().unwrap().to_string();
    let v = ui.caps(&id).await;
    assert_eq!(v["settings_write"], true, "{v}");
    assert!(
        v["added"]["refused"]
            .as_str()
            .is_some_and(|why| why.contains("runs by hand")),
        "{v}"
    );
    let (status, v) = ui
        .api(
            "POST",
            "/api/caps/save",
            json!({"id": id, "form": form("say.back", "echo {word}"), "adding": true}),
        )
        .await;
    assert_eq!((status, &v["code"]), (409, &json!("unavailable")), "{v}");
    assert!(v["error"].as_str().unwrap().contains("runs by hand"), "{v}");
    daemon.stop().await;
    r.stop().await;
}
