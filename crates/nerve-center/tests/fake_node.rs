//! The center against a fake node in the same process: pairing, the link
//! handshake, describe, MCP tools/call through to `invoke`, an unknown node
//! (401) and the one-link rule.

use std::time::Duration;

use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use nerve_center::config::Args;
use nerve_center::mcp::Engine;
use nerve_center::server::{self, Running};
use nerve_proto::RpcError;
use nerve_proto::link::{CenterUrl, PairLink};
use nerve_proto::msg::{self, method};
use nerve_proto::rpc::Message;
use nerve_transport::keys::NodeKey;
use nerve_transport::net::BoxIo;
use nerve_transport::ws::{self, ConnectError, WsMessage};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_tungstenite::WebSocketStream;

const MAX: usize = 4 * 1024 * 1024;

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
        "none",
    ])
    .unwrap();
    let lock = nerve_center::attach::try_lock(dir)
        .unwrap()
        .expect("the lock is free");
    server::start(&args, lock).await.unwrap()
}

fn url(r: &Running) -> CenterUrl {
    CenterUrl::parse(&format!("http://127.0.0.1:{}", r.nodes.port())).unwrap()
}

async fn pair(r: &Running, key: &NodeKey, name: &str) -> (u16, Value) {
    let (_, status, body) = pair_with_code(r, key, name).await;
    (status, body)
}

/// [`pair`], also giving the code it used.
async fn pair_with_code(r: &Running, key: &NodeKey, name: &str) -> (String, u16, Value) {
    let p = r.center.new_pairing();
    let link = PairLink::parse(p["link"].as_str().unwrap()).unwrap();
    assert!(link.pin.is_none(), "plain loopback has no pin");
    let mut io = tokio::net::TcpStream::connect(r.nodes).await.unwrap();
    let body = json!({
        "code": link.code, "name": name, "platform": "linux", "arch": "x86_64",
        "public_key": key.public_hex(),
    });
    let resp = nerve_transport::http::post_json(
        &mut io,
        "127.0.0.1",
        nerve_proto::PAIR_PATH,
        &body,
        64 * 1024,
    )
    .await
    .unwrap();
    (
        link.code,
        resp.status,
        serde_json::from_slice(&resp.body).unwrap_or(Value::Null),
    )
}

fn descriptor(key: &NodeKey, name: &str) -> Value {
    json!({
        "nerve": "0",
        "node": {"id": key.node_id(), "name": name, "platform": "linux", "arch": "x86_64",
                 "software": {"name": "fake-node", "version": "x.y.z"}},
        "rev": 1,
        "summary": "A fake node.",
        "capabilities": [
            {"id": "fs", "profile": "fs", "exposure": "on", "summary": "Files.",
             "actions": {"read": {"effect": "read", "summary": "Read a file.",
                                  "params": {"type": "object", "properties": {"path": {"type": "string"}},
                                             "required": ["path"]}}}},
            {"id": "exec", "profile": "exec", "exposure": "on", "summary": "Commands.",
             "actions": {"run": {"effect": "execute", "summary": "Run a command.",
                                 "params": {"type": "object", "properties": {"command": {"type": "string"}},
                                            "required": ["command"]}}}},
            {"id": "settings", "profile": "settings", "exposure": "on", "summary": "Settings.",
             "actions": {"set": {"effect": "write"}}}
        ]
    })
}

async fn text(ws: &mut WebSocketStream<BoxIo>) -> Option<Message> {
    loop {
        match tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .ok()??
        {
            Ok(WsMessage::Text(t)) => return Message::decode(&t).ok(),
            Ok(WsMessage::Close(_)) | Err(_) => return None,
            Ok(_) => continue,
        }
    }
}

async fn send(ws: &mut WebSocketStream<BoxIo>, m: Message) {
    ws.send(WsMessage::text(m.encode())).await.unwrap();
}

/// Connects and runs the handshake up to `welcome` (or what came instead).
async fn handshake(r: &Running, key: &NodeKey) -> (WebSocketStream<BoxIo>, Message) {
    handshake_with(r, key, json!({})).await
}

/// [`handshake`] with the fields of `more` added to the hello.
async fn handshake_with(
    r: &Running,
    key: &NodeKey,
    more: Value,
) -> (WebSocketStream<BoxIo>, Message) {
    let mut ws = ws::connect(&url(r), None, None, &key.node_id(), MAX)
        .await
        .unwrap();
    let Some(Message::Notification { method: m, params }) = text(&mut ws).await else {
        panic!("no challenge")
    };
    assert_eq!(m, method::CHALLENGE);
    let nonce = msg::unhex(params["nonce"].as_str().unwrap()).unwrap();
    let center_id = params["center_id"].as_str().unwrap().to_string();
    assert_eq!(center_id, r.center.id());
    let mut hello = json!({
        "node_id": key.node_id(),
        "auth": {"sig": key.sign_connect(&center_id, &nonce)},
        "versions": ["0"],
        "software": {"name": "fake-node", "version": "x.y.z"},
        "rev": 1,
    });
    for (k, v) in more.as_object().unwrap() {
        hello[k] = v.clone();
    }
    send(&mut ws, Message::notification(method::HELLO, hello)).await;
    let next = text(&mut ws).await.expect("a reply to hello");
    (ws, next)
}

enum Seen {
    Invoke(Value),
    /// An invoke of the command `hang`, which gets no answer: its id.
    Hang(Value),
    /// A `cancel`: the id it names.
    Cancel(Value),
    SessionEnd(String),
}

/// Answers the center like a node: describe, sub, invoke (echoing the
/// arguments; the command `hang` is never answered, `refuse` is forbidden and
/// `boom` fails), and reports what it saw.
fn serve(ws: WebSocketStream<BoxIo>, desc: Value) -> mpsc::UnboundedReceiver<Seen> {
    serve_task(ws, desc).0
}

/// [`serve`], also giving the task, which ends the link when it is aborted.
fn serve_task(
    mut ws: WebSocketStream<BoxIo>,
    desc: Value,
) -> (mpsc::UnboundedReceiver<Seen>, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        while let Some(m) = text(&mut ws).await {
            match m {
                Message::Request {
                    id,
                    method: m,
                    params,
                } => {
                    if m == method::INVOKE && params["args"]["command"] == "hang" {
                        let _ = tx.send(Seen::Hang(serde_json::to_value(&id).unwrap()));
                        continue;
                    }
                    let command = (m == method::INVOKE)
                        .then(|| params["args"]["command"].as_str())
                        .flatten();
                    let failure = match command {
                        Some("refuse") => Some(RpcError::forbidden("no allow rule matches refuse")),
                        Some("boom") => {
                            Some(RpcError::internal("the node could not start the command"))
                        }
                        _ => None,
                    };
                    if let Some(e) = failure {
                        send(&mut ws, Message::error(Some(id), e)).await;
                        continue;
                    }
                    let result = match m.as_str() {
                        method::DESCRIBE => desc.clone(),
                        method::INVOKE => {
                            let _ = tx.send(Seen::Invoke(Value::Object(params.clone())));
                            json!({"content": format!("echo {}", params["args"]), "encoding": "utf-8"})
                        }
                        _ => json!({}),
                    };
                    send(&mut ws, Message::result(id, result)).await;
                }
                Message::Notification { method: m, params } if m == method::CANCEL => {
                    let _ = tx.send(Seen::Cancel(params["id"].clone()));
                }
                Message::Notification { method: m, params } if m == method::SESSION_END => {
                    let _ = tx.send(Seen::SessionEnd(
                        params["session"].as_str().unwrap_or("").into(),
                    ));
                }
                _ => {}
            }
        }
    });
    (rx, task)
}

async fn wait_for<T>(mut f: impl FnMut() -> Option<T>) -> T {
    for _ in 0..200 {
        if let Some(v) = f() {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out")
}

async fn rpc(e: &Engine, id: u64, method: &str, params: Value) -> Value {
    e.handle(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
        .await
        .expect("a reply")
}

/// The `tools/call` params that run `unit` (`cap.action`) on `node` with the
/// arguments `args`. The tests name units, never tools: this is the one place
/// that knows how a unit is called. Today the fake node's units are the
/// profiled tools `<cap>_<action>`, which pick the node by their `node`
/// argument.
fn run_params(node: &str, unit: &str, args: Value) -> Value {
    let (cap, action) = unit.split_once('.').expect("a unit is cap.action");
    let mut arguments = json!({"node": node});
    for (k, v) in args.as_object().expect("the arguments are an object") {
        arguments[k] = v.clone();
    }
    json!({"name": format!("{cap}_{action}"), "arguments": arguments})
}

/// Runs `unit` on `node` through `e` as a harness would; the JSON-RPC reply.
async fn run(e: &Engine, node: &str, unit: &str, args: Value) -> Value {
    static ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1000);
    let id = ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    rpc(e, id, "tools/call", run_params(node, unit, args)).await
}

#[tokio::test]
async fn pair_connect_describe_and_call() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    let key = NodeKey::generate().unwrap();

    let (status, body) = pair(&r, &key, "box-1").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["node_id"], key.node_id());
    assert_eq!(body["center_name"], "test-center");
    // The same name or key again is a conflict.
    let other = NodeKey::generate().unwrap();
    assert_eq!(pair(&r, &other, "box-1").await.0, 409);
    assert_eq!(pair(&r, &key, "box-2").await.0, 409);

    let (ws, welcome) = handshake(&r, &key).await;
    let Message::Notification { method: m, params } = welcome else {
        panic!("no welcome")
    };
    assert_eq!(m, method::WELCOME);
    assert_eq!(params["version"], "0");
    // A node that offers no resume hears nothing of one: an older node
    // refuses a welcome with fields it does not know.
    assert!(params.get("resume").is_none(), "{params:?}");
    let mut seen = serve(ws, descriptor(&key, "box-1"));

    // The descriptor arrives and becomes tools; settings stays out of them.
    let c = r.center.clone();
    wait_for(|| (!c.tools().is_empty()).then_some(())).await;
    let e = Engine::new(&r.center, "test");
    let init = rpc(
        &e,
        1,
        "initialize",
        json!({"protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "test", "version": "1"}}),
    )
    .await;
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    assert!(
        e.handle(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await
            .is_none()
    );
    let list = rpc(&e, 2, "tools/list", json!({})).await;
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["nodes", "exec_run", "fs_read"]);

    // A read goes straight through and is marked as device content.
    let call = run(&e, "box-1", "fs.read", json!({"path": "/etc/hostname"})).await;
    let out = call["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        out.starts_with("[device content from node \"box-1\""),
        "{out}"
    );
    assert!(out.contains("/etc/hostname"));
    assert_ne!(call["result"]["isError"], true);
    let Some(Seen::Invoke(inv)) = seen.recv().await else {
        panic!("no invoke")
    };
    assert_eq!(inv["cap"], "fs");
    assert_eq!(inv["action"], "read");
    assert_eq!(inv["args"], json!({"path": "/etc/hostname"}));
    let session = inv["ctx"]["session"].as_str().unwrap().to_string();

    // An unknown node name is refused with the names that exist.
    let bad = run(&e, "nope", "fs.read", json!({"path": "/"})).await;
    assert_eq!(bad["result"]["isError"], true);
    assert!(
        bad["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("box-1")
    );

    // The center holds no call back: execute goes straight to the node,
    // which decides.
    let done = run(&e, "box-1", "exec.run", json!({"command": "uname"})).await;
    assert_ne!(done["result"]["isError"], true, "{done}");
    let Some(Seen::Invoke(inv)) = seen.recv().await else {
        panic!("no invoke")
    };
    assert_eq!(inv["cap"], "exec");
    assert_eq!(inv["ctx"]["session"], session.as_str());

    // Ending the session tells the node.
    e.close().await;
    let Some(Seen::SessionEnd(s)) = seen.recv().await else {
        panic!("no session.end")
    };
    assert_eq!(s, session);
    r.stop().await;
}

/// An MCP `notifications/cancelled` cancels the call on its node: the node
/// gets `cancel` with the invoke's id, and the cancelled request gets no
/// response (MCP 2025-06-18, cancellation).
#[tokio::test]
async fn a_cancelled_mcp_call_is_cancelled_on_the_node() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    let key = NodeKey::generate().unwrap();
    assert_eq!(pair(&r, &key, "box-1").await.0, 200);
    let (ws, _) = handshake(&r, &key).await;
    let mut seen = serve(ws, descriptor(&key, "box-1"));
    let c = r.center.clone();
    wait_for(|| (!c.tools().is_empty()).then_some(())).await;
    let e = std::sync::Arc::new(Engine::new(&r.center, "test"));
    rpc(
        &e,
        1,
        "initialize",
        json!({"protocolVersion": "2025-06-18"}),
    )
    .await;

    let call = tokio::spawn({
        let e = e.clone();
        async move {
            e.handle(
                json!({"jsonrpc": "2.0", "id": "run-1", "method": "tools/call",
                "params": run_params("box-1", "exec.run", json!({"command": "hang"}))}),
            )
            .await
        }
    });
    async fn next(seen: &mut mpsc::UnboundedReceiver<Seen>) -> Option<Seen> {
        tokio::time::timeout(Duration::from_secs(5), seen.recv())
            .await
            .ok()
            .flatten()
    }
    let Some(Seen::Hang(invoke_id)) = next(&mut seen).await else {
        panic!("no invoke")
    };
    let note = e
        .handle(
            json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
            "params": {"requestId": "run-1", "reason": "the user stopped it"}}),
        )
        .await;
    assert!(note.is_none(), "a notification gets no reply: {note:?}");
    let Some(Seen::Cancel(id)) = next(&mut seen).await else {
        panic!("the node got no cancel")
    };
    assert_eq!(id, invoke_id);
    let reply = tokio::time::timeout(Duration::from_secs(5), call)
        .await
        .expect("the cancelled call returns")
        .unwrap();
    assert!(
        reply.is_none(),
        "a cancelled request gets no response: {reply:?}"
    );
    r.stop().await;
}

#[tokio::test]
async fn the_pair_response_carries_the_codes_own_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    let near = |expires: u64, minutes: u64| {
        let now = nerve_center::util::now_ms();
        let want = minutes * 60_000;
        assert!(
            expires + 5_000 >= now + want && expires <= now + want + 5_000,
            "{expires} is not {minutes} minutes from {now}"
        );
    };
    // The default is ten minutes.
    near(r.center.new_pairing()["expires_ms"].as_u64().unwrap(), 10);
    r.center.update(|s| s.pair_code_minutes = 1440);
    near(r.center.new_pairing()["expires_ms"].as_u64().unwrap(), 1440);
    r.center.update(|s| s.pair_code_minutes = 1);
    near(r.center.new_pairing()["expires_ms"].as_u64().unwrap(), 1);
}

#[tokio::test]
async fn unknown_node_and_wrong_codes() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    let key = NodeKey::generate().unwrap();
    match ws::connect(&url(&r), None, None, &key.node_id(), MAX).await {
        Err(ConnectError::Unknown) => {}
        Err(e) => panic!("expected 401, got {e:?}"),
        Ok(_) => panic!("an unknown node got a link"),
    }
    // A made-up code is refused.
    let mut io = tokio::net::TcpStream::connect(r.nodes).await.unwrap();
    let body = json!({"code": "aaaaaaaaaaaa", "name": "x", "platform": "linux", "arch": "x86_64",
                      "public_key": key.public_hex()});
    let resp =
        nerve_transport::http::post_json(&mut io, "127.0.0.1", nerve_proto::PAIR_PATH, &body, 4096)
            .await
            .unwrap();
    assert_eq!(resp.status, 403);
    r.stop().await;
}

#[tokio::test]
async fn a_second_link_while_the_first_answers_is_a_duplicate() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    let key = NodeKey::generate().unwrap();
    assert_eq!(pair(&r, &key, "box-1").await.0, 200);
    let (first, _) = handshake(&r, &key).await;
    // The first link keeps reading, so it answers the center's ping.
    let _seen = serve(first, descriptor(&key, "box-1"));
    let c = r.center.clone();
    let id = key.node_id();
    wait_for(|| c.link(&id).map(|_| ())).await;

    let (_second, reply) = handshake(&r, &key).await;
    let Message::Notification { method: m, params } = reply else {
        panic!("expected bye")
    };
    assert_eq!(m, method::BYE);
    assert_eq!(params["reason"], "duplicate");
    assert!(!r.center.alerts().is_empty(), "a duplicate raises an alert");
    r.stop().await;
}

/// `/api/overview` as the web UI's page reads it.
async fn overview(r: &Running) -> Value {
    let ui = nerve_center::ui::Ui::new(&r.center, None, false, false);
    let mut req = http("GET", &[("host", "127.0.0.1:1")], Value::Null);
    req.path = "/api/session".into();
    let resp = ui.request(req).await;
    let (_, cookie) = resp
        .headers
        .iter()
        .find(|(k, _)| k == "Set-Cookie")
        .expect("a session cookie");
    let cookie = cookie.split(';').next().unwrap();
    let mut req = http(
        "GET",
        &[("host", "127.0.0.1:1"), ("cookie", cookie)],
        Value::Null,
    );
    req.path = "/api/overview".into();
    let resp = ui.request(req).await;
    assert_eq!(resp.status, 200);
    serde_json::from_slice(&resp.body).unwrap()
}

/// The center's log lines that hold `text`.
fn log_lines(c: &nerve_center::center::Center, text: &str) -> Vec<String> {
    let q = nerve_transport::log::Query {
        text: Some(text.into()),
        limit: 1000,
        ..Default::default()
    };
    c.log_json(&q)["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["msg"].as_str().unwrap().to_string())
        .collect()
}

/// A capability whose name a tool could not carry is left out on its own:
/// the node's other capabilities stay tools, and the owner sees why. The
/// agent's `nodes` tool does not name it, and the log says it once.
#[tokio::test]
async fn only_the_capability_with_a_bad_name_is_left_out() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    let key = NodeKey::generate().unwrap();
    assert_eq!(pair(&r, &key, "box-1").await.0, 200);
    let (ws, _) = handshake(&r, &key).await;
    let mut d = descriptor(&key, "box-1");
    d["capabilities"][0]["id"] = json!("my_fs");
    d["capabilities"][0]["actions"]["list"] = d["capabilities"][0]["actions"]["read"].clone();
    let _seen = serve(ws, d);
    let c = r.center.clone();
    wait_for(|| (!c.tools().is_empty()).then_some(())).await;
    let names: Vec<String> = c.tools().into_iter().map(|t| t.name).collect();
    assert_eq!(names, ["exec_run"]);
    let ov = overview(&r).await;
    let reason = "capability name \"my_fs\": letters, digits and - only, no _";
    assert_eq!(
        ov["nodes"][0]["broken"],
        json!([{"name": "my_fs.list", "reason": reason},
               {"name": "my_fs.read", "reason": reason}])
    );
    // The overview still lists it for the owner, as not offered.
    assert_eq!(ov["nodes"][0]["capabilities"][0]["id"], "my_fs");
    assert_eq!(ov["nodes"][0]["capabilities"][0]["offered"], false);
    let e = Engine::new(&r.center, "test");
    let listed = rpc(
        &e,
        1,
        "tools/call",
        json!({"name": "nodes", "arguments": {}}),
    )
    .await;
    let listed = listed["result"]["content"][0]["text"].as_str().unwrap();
    assert!(listed.contains("offers exec"), "{listed}");
    assert!(!listed.contains("my_fs"), "{listed}");
    // One line for both, however many there are.
    let lines = wait_for(|| {
        let l = log_lines(&c, "leaves out");
        (!l.is_empty()).then_some(l)
    })
    .await;
    assert_eq!(
        lines,
        [format!(
            "the center leaves out my_fs.list of the node's description: {reason} \
             (and 1 more, listed in the overview)"
        )]
    );
    r.stop().await;
}

/// A capability the node's owner turned off is no tool, so the agent's
/// `nodes` tool does not name it either; the overview lists it as not offered.
#[tokio::test]
async fn a_capability_that_is_off_is_not_named_to_the_agent() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    let key = NodeKey::generate().unwrap();
    assert_eq!(pair(&r, &key, "box-1").await.0, 200);
    let (ws, _) = handshake(&r, &key).await;
    let mut d = descriptor(&key, "box-1");
    d["capabilities"][0]["exposure"] = json!("off");
    let _seen = serve(ws, d);
    let c = r.center.clone();
    wait_for(|| (!c.tools().is_empty()).then_some(())).await;
    let names: Vec<String> = c.tools().into_iter().map(|t| t.name).collect();
    assert_eq!(names, ["exec_run"]);
    let ov = overview(&r).await;
    assert_eq!(ov["nodes"][0]["capabilities"][0]["id"], "fs");
    assert_eq!(ov["nodes"][0]["capabilities"][0]["offered"], false);
    assert_eq!(ov["nodes"][0]["capabilities"][1]["offered"], true);
    let e = Engine::new(&r.center, "test");
    let listed = rpc(
        &e,
        1,
        "tools/call",
        json!({"name": "nodes", "arguments": {}}),
    )
    .await;
    let listed = listed["result"]["content"][0]["text"].as_str().unwrap();
    assert!(listed.contains("offers exec\n"), "{listed}");
    r.stop().await;
}

/// An action whose schema is outside the subset is no tool, and the
/// overview names it with the reason; its capability's other actions stay.
#[tokio::test]
async fn a_broken_schema_is_not_a_tool_and_shows_in_the_overview() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    let key = NodeKey::generate().unwrap();
    assert_eq!(pair(&r, &key, "box-1").await.0, 200);
    let (ws, _) = handshake(&r, &key).await;
    let mut d = descriptor(&key, "box-1");
    d["capabilities"][0]["actions"]["grep"] = json!({"effect": "read", "summary": "Search.",
        "params": {"type": "object", "properties": {"pattern": {"type": "string", "pattern": "^a"}}}});
    let _seen = serve(ws, d);
    let c = r.center.clone();
    wait_for(|| (!c.tools().is_empty()).then_some(())).await;
    let names: Vec<String> = c.tools().into_iter().map(|t| t.name).collect();
    assert_eq!(names, ["exec_run", "fs_read"]);
    let ov = overview(&r).await;
    let broken = ov["nodes"][0]["broken"].as_array().unwrap();
    assert_eq!(broken.len(), 1, "{broken:?}");
    assert_eq!(broken[0]["name"], "fs.grep");
    let reason = broken[0]["reason"].as_str().unwrap();
    assert!(
        reason.starts_with("params: /properties/pattern") && reason.contains("pattern"),
        "{reason}"
    );
    // The overview still lists the capability itself.
    assert_eq!(ov["nodes"][0]["capabilities"][0]["id"], "fs");
    // And `tools/call` of the left-out unit is an unknown tool.
    let e = Engine::new(&r.center, "test");
    let call = run(&e, "box-1", "fs.grep", json!({"pattern": "a"})).await;
    assert!(call.get("error").is_some(), "{call}");
    r.stop().await;
}

/// Arguments that do not fit the unit's schema are refused by the center,
/// naming the field and what it expected; the node sees nothing of them.
#[tokio::test]
async fn wrong_args_are_refused_before_the_node() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    let key = NodeKey::generate().unwrap();
    assert_eq!(pair(&r, &key, "box-1").await.0, 200);
    let (ws, _) = handshake(&r, &key).await;
    let mut seen = serve(ws, descriptor(&key, "box-1"));
    let c = r.center.clone();
    wait_for(|| (!c.tools().is_empty()).then_some(())).await;
    let e = Engine::new(&r.center, "test");
    for (args, want) in [
        (
            json!({"path": 5}),
            "error invalid_args: path: expected a string",
        ),
        (
            json!({}),
            "error invalid_args: path: expected a string (required)",
        ),
        (
            json!({"path": null}),
            "error invalid_args: path: expected a string",
        ),
    ] {
        let call = run(&e, "box-1", "fs.read", args.clone()).await;
        assert_eq!(call["result"]["isError"], true, "{args}: {call}");
        let text = call["result"]["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, want, "{args}");
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(300), seen.recv())
            .await
            .is_err(),
        "the node received something"
    );
    // The owner sees the refusals in the log and the statistics, as when
    // the node refused them.
    let lines = log_lines(&c, "fs.read failed");
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert!(
        lines[0].starts_with("fs.read failed (invalid_args)")
            && lines[0].contains("path: expected"),
        "{lines:?}"
    );
    let stats = c.stats_json();
    let day = &stats["nodes"]["box-1"];
    assert_eq!(day["calls"]["fs.read"]["count"], 3, "{stats}");
    assert_eq!(day["calls"]["fs.read"]["errors"], 3, "{stats}");
    assert_eq!(day["errors"]["invalid_args"], 3, "{stats}");
    // Fitting arguments go through.
    let done = run(&e, "box-1", "fs.read", json!({"path": "/x"})).await;
    assert_ne!(done["result"]["isError"], true, "{done}");
    let Some(Seen::Invoke(inv)) = seen.recv().await else {
        panic!("no invoke")
    };
    assert_eq!(inv["args"], json!({"path": "/x"}));
    r.stop().await;
}

fn http(method: &str, headers: &[(&str, &str)], body: Value) -> nerve_transport::http::Request {
    nerve_transport::http::Request {
        method: method.into(),
        path: "/mcp".into(),
        query: String::new(),
        headers: headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        body: if body.is_null() {
            Vec::new()
        } else {
            body.to_string().into_bytes()
        },
    }
}

#[tokio::test]
async fn http_mcp_needs_a_token_and_a_session() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    let h = nerve_center::mcp::HttpMcp::new(&r.center, Some("secret-token".into()));
    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}});
    assert_eq!(h.request(http("POST", &[], init.clone())).await.status, 401);
    assert_eq!(
        h.request(http(
            "POST",
            &[("authorization", "Bearer wrong")],
            init.clone()
        ))
        .await
        .status,
        401
    );
    let auth = ("authorization", "Bearer secret-token");
    let evil = ("origin", "http://evil.example");
    assert_eq!(
        h.request(http(
            "POST",
            &[auth, evil, ("host", "127.0.0.1:7481")],
            init.clone()
        ))
        .await
        .status,
        403
    );

    let resp = h.request(http("POST", &[auth], init)).await;
    assert_eq!(resp.status, 200);
    let sid = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("mcp-session-id"))
        .map(|(_, v)| v.clone())
        .expect("a session id");
    let list = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
    assert_eq!(
        h.request(http("POST", &[auth], list.clone())).await.status,
        400,
        "no session id"
    );
    let resp = h
        .request(http(
            "POST",
            &[auth, ("mcp-session-id", &sid)],
            list.clone(),
        ))
        .await;
    assert_eq!(resp.status, 200);
    let v: Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(v["result"]["tools"][0]["name"], "nodes");
    assert_eq!(
        h.request(http(
            "DELETE",
            &[auth, ("mcp-session-id", &sid)],
            Value::Null
        ))
        .await
        .status,
        204
    );
    assert_eq!(
        h.request(http("POST", &[auth, ("mcp-session-id", &sid)], list))
            .await
            .status,
        404
    );
    assert_eq!(
        h.request(http("GET", &[auth], Value::Null)).await.status,
        405
    );
    r.stop().await;
}

#[tokio::test]
async fn a_disabled_node_offers_no_tools_and_gets_no_calls() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    let key = NodeKey::generate().unwrap();
    assert_eq!(pair(&r, &key, "box-1").await.0, 200);
    let (ws, _) = handshake(&r, &key).await;
    let mut seen = serve(ws, descriptor(&key, "box-1"));
    let c = r.center.clone();
    wait_for(|| (!c.tools().is_empty()).then_some(())).await;
    let e = Engine::new(&r.center, "test");
    let names = |list: &Value| -> Vec<String> {
        list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect()
    };
    let id = key.node_id();

    // Switched off: the tools are gone, `nodes` still lists the node and
    // says why, and the link stays up.
    c.set_disabled(&id, true).unwrap();
    assert!(c.tools().is_empty());
    assert_eq!(names(&rpc(&e, 1, "tools/list", json!({})).await), ["nodes"]);
    let listed = rpc(
        &e,
        2,
        "tools/call",
        json!({"name": "nodes", "arguments": {}}),
    )
    .await;
    let listed = listed["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        listed.contains("box-1") && listed.contains("online"),
        "{listed}"
    );
    assert!(listed.contains("disabled in the center"), "{listed}");
    assert!(!listed.contains("offers fs"), "{listed}");
    assert!(c.link(&id).is_some());

    // A call on a tool list read before the switch is refused by the center
    // itself, before anything goes to the node.
    let route = {
        c.set_disabled(&id, false).unwrap();
        let tools = c.tools();
        c.set_disabled(&id, true).unwrap();
        tools.iter().find(|t| t.name == "fs_read").unwrap().routes["box-1"].clone()
    };
    let sess = c.new_session("test");
    let err = c
        .call(&sess, &route, serde_json::Map::new())
        .await
        .unwrap_err();
    let nerve_center::center::CallError::Rpc(err) = err;
    assert_eq!(err.message, "the node box-1 is disabled in the center");
    // By name through MCP it is an unknown tool.
    let by_name = run(&e, "box-1", "fs.read", json!({"path": "/x"})).await;
    assert!(by_name.get("error").is_some(), "{by_name}");
    assert!(
        tokio::time::timeout(Duration::from_millis(300), seen.recv())
            .await
            .is_err(),
        "the node received something"
    );

    // Switched on again: the tools are back and a call reaches the node.
    c.set_disabled(&id, false).unwrap();
    assert_eq!(
        names(&rpc(&e, 4, "tools/list", json!({})).await),
        ["nodes", "exec_run", "fs_read"]
    );
    let done = run(&e, "box-1", "fs.read", json!({"path": "/x"})).await;
    assert_ne!(done["result"]["isError"], true, "{done}");
    let Some(Seen::Invoke(inv)) = seen.recv().await else {
        panic!("no invoke")
    };
    assert_eq!(inv["args"], json!({"path": "/x"}));
    r.stop().await;
}

/// A node's `audit/decision` events reach the center's audit feed with the
/// target cut to 512 characters, as the node's own log keeps it; and many
/// large ones neither grow the feed past its limit nor `/api/audit` with it
/// (the refused 3 MiB commands of the second LXC run grew both to 190 MB).
#[tokio::test]
async fn audit_targets_are_cut_and_the_audit_feed_is_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    let key = NodeKey::generate().unwrap();
    assert_eq!(pair(&r, &key, "box-1").await.0, 200);
    let (mut ws, _) = handshake(&r, &key).await;
    let mut d = descriptor(&key, "box-1");
    d["capabilities"].as_array_mut().unwrap().push(json!(
        {"id": "audit", "profile": "audit", "exposure": "on", "summary": "Audit.",
         "actions": {"list": {"effect": "read"}}}
    ));
    // Answer describe and wait for the subscription to the decisions.
    loop {
        let Some(Message::Request {
            id,
            method: m,
            params,
        }) = text(&mut ws).await
        else {
            continue;
        };
        let sub = m == method::SUB;
        if sub {
            assert_eq!(params["topics"], json!(["audit/decision"]));
        }
        let result = if m == method::DESCRIBE {
            d.clone()
        } else {
            json!({})
        };
        send(&mut ws, Message::result(id, result)).await;
        if sub {
            break;
        }
    }
    let event = |seq: u64, target: String| {
        Message::notification(
            method::EVENT,
            json!({"cap": "audit", "name": "decision", "seq": seq, "ts": 1, "data": {
                "ts": 1, "cap": "exec", "action": "run", "target": target,
                "decision": "forbidden", "code": "forbidden"}}),
        )
    };
    let long = format!("echo {}", "ü".repeat(3000));
    send(&mut ws, event(1, long.clone())).await;
    let c = r.center.clone();
    let first = wait_for(|| c.audit().first().cloned()).await;
    let target = first["target"].as_str().unwrap();
    let head: String = long.chars().take(512).collect();
    assert!(
        target == format!("{head}… [cut at 512 of 3005 characters]"),
        "the center keeps a target of {} characters",
        target.chars().count()
    );
    assert_eq!(first["node"], "box-1");

    // Many refused calls with large targets: the feed keeps its count and
    // its size, and the web UI's answer stays as small.
    let calls = 600;
    for seq in 2..=calls {
        send(&mut ws, event(seq, format!("{seq} {}", "x".repeat(4096)))).await;
    }
    let last = format!("{calls} ");
    wait_for(|| {
        c.audit()
            .last()
            .is_some_and(|e| e["target"].as_str().unwrap().starts_with(&last))
            .then_some(())
    })
    .await;
    let feed = c.audit();
    assert!(
        feed.len() <= nerve_center::center::AUDIT_KEEP,
        "{}",
        feed.len()
    );
    // The UI without a login hands out a session to the page.
    let ui = nerve_center::ui::Ui::new(&r.center, None, false, false);
    let mut req = http("GET", &[("host", "127.0.0.1:1")], Value::Null);
    req.path = "/api/session".into();
    let resp = ui.request(req).await;
    let (_, cookie) = resp
        .headers
        .iter()
        .find(|(k, _)| k == "Set-Cookie")
        .expect("a session cookie");
    let cookie = cookie.split(';').next().unwrap();
    let mut req = http(
        "GET",
        &[("host", "127.0.0.1:1"), ("cookie", cookie)],
        Value::Null,
    );
    req.path = "/api/audit".into();
    let resp = ui.request(req).await;
    assert_eq!(resp.status, 200);
    // The feed holds at most 1 MiB of entries (center::AUDIT_MAX_BYTES).
    assert!(
        resp.body.len() <= 1024 * 1024 + 4096,
        "/api/audit answered {} bytes",
        resp.body.len()
    );
    let served: Value = serde_json::from_slice(&resp.body).unwrap();
    let served = served["decisions"].as_array().unwrap();
    assert_eq!(served.len(), feed.len());
    assert!(
        served
            .iter()
            .all(|e| e["target"].as_str().unwrap().contains("… [cut at 512 of ")),
        "every large target is served cut"
    );
    r.stop().await;
}

/// The wait a "link up again after …" line names.
fn waited(m: &str) -> Duration {
    let t = m.strip_prefix("link up again after ").unwrap();
    let mut words = t.split(' ');
    let n: u64 = words.next().unwrap().parse().unwrap();
    match words.next().unwrap() {
        "ms" => Duration::from_millis(n),
        "s" => Duration::from_secs(n),
        unit => panic!("{unit} in {m}"),
    }
}

/// A node that drops, goes quiet and comes back is in the log: the drop, the
/// quiet period, and each reconnect with the time it took. Calls that were
/// refused or failed are there with their reasons, and no secret is.
#[tokio::test]
async fn a_node_that_drops_and_comes_back_is_in_the_log() {
    use nerve_transport::log::{Entry, Level, Query};
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    let key = NodeKey::generate().unwrap();
    let (code, status, _) = pair_with_code(&r, &key, "box-1").await;
    assert_eq!(status, 200);
    let about = |r: &Running| -> Vec<Entry> {
        let q = Query {
            node: Some(key.node_id()),
            limit: 100,
            ..Query::default()
        };
        r.center
            .log()
            .entries(&q)
            .into_iter()
            .rev()
            .map(|(_, e)| e)
            .collect()
    };
    let has = |r: &Running, part: &str| about(r).iter().any(|e| e.msg.contains(part));

    // Up, with a refused and a failed call.
    let (ws, _) = handshake(&r, &key).await;
    let (_seen, link) = serve_task(ws, descriptor(&key, "box-1"));
    let c = r.center.clone();
    wait_for(|| (!c.tools().is_empty()).then_some(())).await;
    let e = Engine::new(&r.center, "test");
    rpc(
        &e,
        1,
        "initialize",
        json!({"protocolVersion": "2025-06-18", "capabilities": {},
               "clientInfo": {"name": "test", "version": "1"}}),
    )
    .await;
    for command in ["refuse", "boom"] {
        let call = run(&e, "box-1", "exec.run", json!({"command": command})).await;
        assert_eq!(call["result"]["isError"], true, "{call}");
    }

    // The link drops without a bye, and the node dials again.
    link.abort();
    wait_for(|| has(&r, "link dropped").then_some(())).await;
    let (ws, _) = handshake(&r, &key).await;
    let (_seen, link) = serve_task(ws, descriptor(&key, "box-1"));
    wait_for(|| has(&r, "link up again after").then_some(())).await;
    link.abort();
    wait_for(|| {
        (about(&r)
            .iter()
            .filter(|e| e.msg.starts_with("link dropped"))
            .count()
            == 2)
            .then_some(())
    })
    .await;

    // The next link says nothing. The center gives up on it after the quiet
    // period (shortened here from 45 s), and the node comes back.
    r.center.set_dead_after(Duration::from_millis(300));
    let (_quiet, _) = handshake(&r, &key).await;
    wait_for(|| has(&r, "no frame from the node for 300 ms").then_some(())).await;
    let (ws, _) = handshake(&r, &key).await;
    let _seen = serve(ws, descriptor(&key, "box-1"));
    wait_for(|| {
        (about(&r)
            .iter()
            .filter(|e| e.msg.starts_with("link up"))
            .count()
            == 4)
            .then_some(())
    })
    .await;

    let got: Vec<(Level, String)> = about(&r).into_iter().map(|e| (e.level, e.msg)).collect();
    let line = |i: usize| (got[i].0, got[i].1.as_str());
    assert_eq!(
        line(0),
        (
            Level::Info,
            "the node paired (linux/x86_64); its code is used up"
        )
    );
    assert_eq!(line(1), (Level::Info, "link up (node software x.y.z)"));
    // Told by the code that came back, then what it was.
    let calls: Vec<_> = got
        .iter()
        .filter(|(_, m)| m.starts_with("exec.run"))
        .collect();
    assert_eq!(
        calls[0],
        &(
            Level::Info,
            "exec.run was refused (forbidden): no allow rule matches refuse".to_string()
        )
    );
    assert_eq!(calls[1].0, Level::Error);
    assert!(
        calls[1].1.starts_with("exec.run failed (internal) after ")
            && calls[1]
                .1
                .ends_with(": the node could not start the command"),
        "{calls:?}"
    );
    // The drops are warnings, the reconnects say how long they took.
    let drops: Vec<_> = got
        .iter()
        .filter(|(_, m)| m.starts_with("link dropped"))
        .collect();
    assert_eq!(drops.len(), 3, "{got:?}");
    assert!(drops.iter().all(|(l, _)| *l == Level::Warn));
    assert!(
        drops[0].1.starts_with("link dropped: the connection"),
        "{drops:?}"
    );
    assert!(drops[0].1.contains("(it was up for "), "{drops:?}");
    assert!(
        drops[2]
            .1
            .starts_with("link dropped: no frame from the node for 300 ms"),
        "{drops:?}"
    );
    let ups: Vec<_> = got
        .iter()
        .filter(|(_, m)| m.starts_with("link up"))
        .collect();
    assert_eq!(ups.len(), 4);
    assert_eq!(ups[0].1, "link up (node software x.y.z)");
    for (_, m) in &ups[1..] {
        assert!(
            m.starts_with("link up again after ") && m.ends_with(" (node software x.y.z)"),
            "{m}"
        );
    }
    // The wait after the quiet period counts from the last frame, so it holds
    // the 300 ms the center waited for one.
    assert!(waited(&ups[3].1) >= Duration::from_millis(300), "{ups:?}");
    // In this order: up, a drop, up again, a drop, up again (a link that then
    // says nothing), the quiet period, up again.
    let order: Vec<&str> = got
        .iter()
        .filter_map(|(_, m)| match m {
            m if m.starts_with("link up again") => Some("again"),
            m if m.starts_with("link up") => Some("up"),
            m if m.contains("no frame from the node") => Some("quiet"),
            m if m.starts_with("link dropped") => Some("drop"),
            _ => None,
        })
        .collect();
    assert_eq!(
        order,
        ["up", "drop", "again", "drop", "again", "quiet", "again"]
    );

    // The view's filter: the warnings and errors of this node.
    let q = Query {
        node: Some(key.node_id()),
        level: Some(Level::Warn),
        limit: 100,
        ..Query::default()
    };
    assert_eq!(r.center.log().entries(&q).len(), 4);
    // The pairing code is not in the log, in the window or the file.
    let file = std::fs::read_to_string(dir.path().join("log.jsonl")).unwrap();
    assert!(file.contains("link dropped") && !file.contains(&code));
    r.stop().await;
    // The stop is told: first that the links are closed, then that it is done.
    // The links close on their own tasks, so lines may follow.
    let file = std::fs::read_to_string(dir.path().join("log.jsonl")).unwrap();
    let at = |part: &str| file.find(part).unwrap_or_else(|| panic!("{part}: {file}"));
    assert!(
        at("the center is stopping; closing 1 node link") < at("the center stopped"),
        "{file}"
    );
}

/// A node that comes back while the center still holds its old link (a
/// half-open connection that does not answer a ping): the old link is told as
/// dropped before the new one comes up, with the wait, and the old link's own
/// end afterwards says nothing of a node that is online.
#[tokio::test]
async fn a_node_that_comes_back_over_a_held_link_is_logged_in_order() {
    use nerve_transport::log::{Entry, Level, Query};
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    // The end of the old link is detail, so the log keeps detail.
    r.center.log().set_level(Level::Debug);
    let key = NodeKey::generate().unwrap();
    assert_eq!(pair(&r, &key, "box-1").await.0, 200);
    let about = |r: &Running| -> Vec<Entry> {
        let q = Query {
            node: Some(key.node_id()),
            limit: 100,
            ..Query::default()
        };
        r.center
            .log()
            .entries(&q)
            .into_iter()
            .rev()
            .map(|(_, e)| e)
            .collect()
    };
    let has = |r: &Running, part: &str| about(r).iter().any(|e| e.msg.contains(part));

    // The old link is held and never read, so it does not answer the center's
    // ping when the node comes back.
    let (old, _) = handshake(&r, &key).await;
    let c = r.center.clone();
    let id = key.node_id();
    wait_for(|| c.link(&id).map(|_| ())).await;
    let (ws, _) = handshake(&r, &key).await;
    let _seen = serve(ws, descriptor(&key, "box-1"));
    wait_for(|| has(&r, "link up again after").then_some(())).await;
    // Only now does the old link end.
    drop(old);
    wait_for(|| has(&r, "a link that was replaced ended").then_some(())).await;

    let got: Vec<(Level, String)> = about(&r).into_iter().map(|e| (e.level, e.msg)).collect();
    let order: Vec<&str> = got
        .iter()
        .filter_map(|(_, m)| match m {
            m if m.starts_with("link up again") => Some("again"),
            m if m.starts_with("link up") => Some("up"),
            m if m.starts_with("link dropped") => Some("drop"),
            m if m.starts_with("a link that was replaced ended") => Some("old ended"),
            _ => None,
        })
        .collect();
    assert_eq!(order, ["up", "drop", "again", "old ended"], "{got:?}");
    let drop_line = got
        .iter()
        .find(|(_, m)| m.starts_with("link dropped"))
        .unwrap();
    assert_eq!(drop_line.0, Level::Warn);
    assert!(
        drop_line
            .1
            .contains("did not answer a ping, so it was replaced"),
        "{}",
        drop_line.1
    );
    // The wait counts from the old link's last frame: the 3 s the center gave
    // it to answer.
    let again = got
        .iter()
        .find(|(_, m)| m.starts_with("link up again"))
        .unwrap();
    assert!(waited(&again.1) >= Duration::from_secs(3), "{}", again.1);
    // The node is online, and the old link's end is detail, not a warning.
    assert!(r.center.link(&id).is_some());
    let old_ended = got
        .iter()
        .find(|(_, m)| m.starts_with("a link that was replaced"))
        .unwrap();
    assert_eq!(old_ended.0, Level::Debug);
    r.stop().await;
}

/// A node that reboots and redials on the same IP: the old link fails while
/// the center waits for its answer to the ping. That is one drop, told when it
/// happened, not a second one that says the link did not answer.
#[tokio::test]
async fn an_old_link_that_fails_during_the_ping_is_one_drop() {
    use nerve_transport::log::{Entry, Level, Query};
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    r.center.log().set_level(Level::Debug);
    let key = NodeKey::generate().unwrap();
    assert_eq!(pair(&r, &key, "box-1").await.0, 200);
    let (old, _) = handshake(&r, &key).await;
    let c = r.center.clone();
    let id = key.node_id();
    wait_for(|| c.link(&id).map(|_| ())).await;
    // The node comes back; its old connection is reset while the center is
    // waiting for the old link to answer.
    let again = handshake(&r, &key);
    let reset = async {
        tokio::time::sleep(Duration::from_millis(500)).await;
        drop(old);
    };
    let ((ws, _), ()) = tokio::join!(again, reset);
    let _seen = serve(ws, descriptor(&key, "box-1"));
    wait_for(|| r.center.link(&id).map(|_| ())).await;

    let q = Query {
        node: Some(id.clone()),
        limit: 100,
        ..Query::default()
    };
    let got: Vec<Entry> = r
        .center
        .log()
        .entries(&q)
        .into_iter()
        .rev()
        .map(|(_, e)| e)
        .collect();
    let drops: Vec<&Entry> = got
        .iter()
        .filter(|e| e.msg.starts_with("link dropped"))
        .collect();
    assert_eq!(drops.len(), 1, "{got:?}");
    assert_eq!(drops[0].level, Level::Warn);
    assert!(
        drops[0].msg.starts_with("link dropped: the connection"),
        "{}",
        drops[0].msg
    );
    assert!(
        !got.iter().any(|e| e.msg.contains("did not answer a ping")),
        "{got:?}"
    );
    // The wait counts from that drop, and the node ends up online.
    let again = got
        .iter()
        .find(|e| e.msg.starts_with("link up again"))
        .unwrap();
    assert!(
        waited(&again.msg) >= Duration::from_secs(2),
        "{}",
        again.msg
    );
    r.stop().await;
}

/// A link id for the resume tests.
fn link_id(c: char) -> String {
    c.to_string().repeat(32)
}

/// The welcome's `resume`.
fn resume_of(welcome: &Message) -> Value {
    let Message::Notification { method: m, params } = welcome else {
        panic!("no welcome: {welcome:?}")
    };
    assert_eq!(m, method::WELCOME);
    params.get("resume").cloned().unwrap_or(Value::Null)
}

/// The next request the center sends: its id, method and params.
async fn request(ws: &mut WebSocketStream<BoxIo>) -> (nerve_proto::Id, String, Value) {
    loop {
        match text(ws).await.expect("a request") {
            Message::Request { id, method, params } => {
                return (id, method, Value::Object(params));
            }
            _ => continue,
        }
    }
}

/// A node that offers its link for a resume, has the center's describe
/// answered and an `exec_run` call in flight, and then loses the connection.
/// Gives the engine, the running tools/call and the invoke's id.
async fn a_call_in_flight_on_a_dropped_link(
    r: &Running,
    key: &NodeKey,
) -> (
    std::sync::Arc<Engine>,
    tokio::task::JoinHandle<Option<Value>>,
    nerve_proto::Id,
) {
    assert_eq!(pair(r, key, "box-1").await.0, 200);
    let (mut ws, welcome) =
        handshake_with(r, key, json!({"resume": {"link": link_id('a'), "got": 0}})).await;
    assert_eq!(resume_of(&welcome), json!({"resumed": false, "got": 0}));
    // The center's frame 1, and the node's.
    let (id, m, _) = request(&mut ws).await;
    assert_eq!(m, method::DESCRIBE);
    send(&mut ws, Message::result(id, descriptor(key, "box-1"))).await;
    let c = r.center.clone();
    wait_for(|| (!c.tools().is_empty()).then_some(())).await;
    let e = std::sync::Arc::new(Engine::new(&r.center, "test"));
    rpc(
        &e,
        1,
        "initialize",
        json!({"protocolVersion": "2025-06-18"}),
    )
    .await;
    let call = tokio::spawn({
        let e = e.clone();
        async move {
            e.handle(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": run_params("box-1", "exec.run", json!({"command": "make"}))}))
                .await
        }
    });
    // The center's frame 2.
    let (invoke, m, p) = request(&mut ws).await;
    assert_eq!(m, method::INVOKE);
    assert_eq!(p["args"]["command"], "make");
    drop(ws);
    let node = key.node_id();
    wait_for(|| c.link(&node).is_none().then_some(())).await;
    (e, call, invoke)
}

/// The reply text of a tools/call.
async fn reply_text(call: tokio::task::JoinHandle<Option<Value>>) -> (String, bool) {
    let r = tokio::time::timeout(Duration::from_secs(10), call)
        .await
        .expect("the call returns")
        .unwrap()
        .expect("a reply");
    (
        r["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        r["result"]["isError"] == true,
    )
}

/// A node that resumes its dropped link (spec §4.9) answers the call that was
/// in flight, and the harness gets that answer. The node had read the invoke,
/// so it is not sent again: the first frame on the new connection is the
/// center's new describe. The center acknowledges what it read.
#[tokio::test]
async fn a_node_that_resumes_its_link_answers_the_call_in_flight() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    let key = NodeKey::generate().unwrap();
    let (_e, call, invoke) = a_call_in_flight_on_a_dropped_link(&r, &key).await;
    assert!(!call.is_finished(), "the call waits for the resume");

    let (mut ws, welcome) = handshake_with(
        &r,
        &key,
        json!({"resume": {"link": link_id('a'), "got": 2}}),
    )
    .await;
    assert_eq!(resume_of(&welcome), json!({"resumed": true, "got": 1}));
    let (id, m, _) = request(&mut ws).await;
    // The center's new describe (its third request), not its first again.
    assert_eq!(m, method::DESCRIBE, "nothing the node read is sent again");
    assert_eq!(id, nerve_proto::Id::Num(3), "the first describe came again");
    send(&mut ws, Message::result(id, descriptor(&key, "box-1"))).await;
    let out =
        json!({"exit_code": 0, "stdout": "built after the drop", "stderr": "", "truncated": false});
    send(&mut ws, Message::result(invoke, out)).await;
    let (text_out, failed) = reply_text(call).await;
    assert!(!failed, "{text_out}");
    assert!(text_out.contains("built after the drop"), "{text_out}");

    // The node's frames 2 and 3 are acknowledged, at most 5 s apart; a tick
    // between the two acknowledges frame 2 first.
    let mut last = 1;
    while last < 3 {
        match text(&mut ws).await.expect("an ack") {
            Message::Notification { method: m, params } if m == method::ACK => {
                let got = params["got"].as_u64().expect("a count");
                assert!(got > last && got <= 3, "{params:?}");
                last = got;
            }
            _ => continue,
        }
    }
    let c = r.center.clone();
    let node = key.node_id();
    wait_for(|| c.link(&node).map(|_| ())).await;
    r.stop().await;
}

/// An invoke the node did not read before the drop has not run: the resumed
/// link sends it again, with the same id, and its answer reaches the harness.
#[tokio::test]
async fn a_call_the_node_did_not_read_is_sent_again_on_the_resumed_link() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    let key = NodeKey::generate().unwrap();
    let (_e, call, invoke) = a_call_in_flight_on_a_dropped_link(&r, &key).await;

    let (mut ws, welcome) = handshake_with(
        &r,
        &key,
        json!({"resume": {"link": link_id('a'), "got": 1}}),
    )
    .await;
    assert_eq!(resume_of(&welcome), json!({"resumed": true, "got": 1}));
    let (id, m, p) = request(&mut ws).await;
    assert_eq!(m, method::INVOKE, "the unread invoke comes first");
    assert_eq!(id, invoke);
    assert_eq!(p["args"]["command"], "make");
    let out = json!({"exit_code": 0, "stdout": "built once", "stderr": "", "truncated": false});
    send(&mut ws, Message::result(invoke, out)).await;
    let (text_out, failed) = reply_text(call).await;
    assert!(!failed, "{text_out}");
    assert!(text_out.contains("built once"), "{text_out}");
    r.stop().await;
}

/// A dropped link that is not resumed within the grace fails its calls with
/// `connection_lost`, as without resume.
#[tokio::test]
async fn a_link_not_resumed_within_the_grace_fails_its_calls() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    r.center.set_resume_grace(Duration::from_millis(300));
    let key = NodeKey::generate().unwrap();
    let (_e, call, _) = a_call_in_flight_on_a_dropped_link(&r, &key).await;
    let (text_out, failed) = reply_text(call).await;
    assert!(failed, "{text_out}");
    assert!(text_out.starts_with("error connection_lost"), "{text_out}");
    // The node coming back now finds nothing to resume.
    let (_ws, welcome) = handshake_with(
        &r,
        &key,
        json!({"resume": {"link": link_id('a'), "got": 2}}),
    )
    .await;
    assert_eq!(resume_of(&welcome), json!({"resumed": false, "got": 0}));
    r.stop().await;
}

/// A node that comes back with another link (it restarted) ends the old one
/// at once: its calls fail with `connection_lost`.
#[tokio::test]
async fn a_node_that_comes_back_with_a_new_link_fails_the_old_calls() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    let key = NodeKey::generate().unwrap();
    let (_e, call, _) = a_call_in_flight_on_a_dropped_link(&r, &key).await;
    let (_ws, welcome) = handshake_with(
        &r,
        &key,
        json!({"resume": {"link": link_id('b'), "got": 0}}),
    )
    .await;
    assert_eq!(resume_of(&welcome), json!({"resumed": false, "got": 0}));
    let (text_out, failed) = reply_text(call).await;
    assert!(failed, "{text_out}");
    assert!(text_out.starts_with("error connection_lost"), "{text_out}");
    r.stop().await;
}

/// A resume offer whose link id is not 32 hex characters is refused.
#[tokio::test]
async fn a_malformed_link_id_is_a_protocol_error() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    let key = NodeKey::generate().unwrap();
    assert_eq!(pair(&r, &key, "box-1").await.0, 200);
    let (_ws, reply) =
        handshake_with(&r, &key, json!({"resume": {"link": "short", "got": 0}})).await;
    let Message::Notification { method: m, params } = reply else {
        panic!("{reply:?}")
    };
    assert_eq!(m, method::BYE);
    assert_eq!(params["reason"], "protocol_error");
    r.stop().await;
}

/// A node whose old connection the center still holds (it went quiet without
/// closing) resumes over it: the held connection does not answer the ping,
/// so it is replaced, and the link goes on on the new one. A late frame on
/// the old connection is not the link's any more.
#[tokio::test]
async fn a_node_resumes_its_link_over_a_held_connection() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    let key = NodeKey::generate().unwrap();
    assert_eq!(pair(&r, &key, "box-1").await.0, 200);
    let (mut old, _) = handshake_with(
        &r,
        &key,
        json!({"resume": {"link": link_id('c'), "got": 0}}),
    )
    .await;
    let (id, _, _) = request(&mut old).await;
    send(&mut old, Message::result(id, descriptor(&key, "box-1"))).await;
    let c = r.center.clone();
    wait_for(|| (!c.tools().is_empty()).then_some(())).await;
    let e = std::sync::Arc::new(Engine::new(&r.center, "test"));
    rpc(
        &e,
        1,
        "initialize",
        json!({"protocolVersion": "2025-06-18"}),
    )
    .await;
    let call = tokio::spawn({
        let e = e.clone();
        async move {
            e.handle(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": run_params("box-1", "exec.run", json!({"command": "make"}))}))
                .await
        }
    });
    let (invoke, _, _) = request(&mut old).await;

    // The old connection stays open but is not read: its ping goes
    // unanswered.
    let (mut ws, welcome) = handshake_with(
        &r,
        &key,
        json!({"resume": {"link": link_id('c'), "got": 2}}),
    )
    .await;
    assert_eq!(resume_of(&welcome), json!({"resumed": true, "got": 1}));
    let stale = json!({"exit_code": 0, "stdout": "stale", "stderr": "", "truncated": false});
    let _ = old
        .send(WsMessage::text(
            Message::result(invoke.clone(), stale).encode(),
        ))
        .await;
    let (id, m, _) = request(&mut ws).await;
    assert_eq!(m, method::DESCRIBE);
    send(&mut ws, Message::result(id, descriptor(&key, "box-1"))).await;
    let out = json!({"exit_code": 0, "stdout": "fresh", "stderr": "", "truncated": false});
    send(&mut ws, Message::result(invoke, out)).await;
    let (text_out, failed) = reply_text(call).await;
    assert!(!failed, "{text_out}");
    assert!(text_out.contains("fresh"), "{text_out}");
    let node = key.node_id();
    assert!(
        c.link(&node).is_some(),
        "the node is up on the new connection"
    );
    r.stop().await;
}

/// A call its harness cancelled while the link was down is not delivered
/// when the link resumes: the node never read the invoke, and it goes as
/// `withdrawn` in its place, followed by the `cancel`.
#[tokio::test]
async fn a_call_cancelled_while_the_link_was_down_is_withdrawn_on_the_resume() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    let key = NodeKey::generate().unwrap();
    let (e, call, invoke) = a_call_in_flight_on_a_dropped_link(&r, &key).await;
    let note = e
        .handle(
            json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
            "params": {"requestId": 2}}),
        )
        .await;
    assert!(note.is_none());
    let reply = tokio::time::timeout(Duration::from_secs(5), call)
        .await
        .expect("the cancelled call returns")
        .unwrap();
    assert!(reply.is_none(), "{reply:?}");
    // The cancel is queued by a task of its own.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let (mut ws, welcome) = handshake_with(
        &r,
        &key,
        json!({"resume": {"link": link_id('a'), "got": 1}}),
    )
    .await;
    assert_eq!(resume_of(&welcome), json!({"resumed": true, "got": 1}));
    let first = text(&mut ws).await.expect("a frame");
    let Message::Notification { method: m, params } = &first else {
        panic!("the invoke came again: {first:?}")
    };
    assert_eq!(m, method::WITHDRAWN);
    assert_eq!(serde_json::to_value(&invoke).unwrap(), params["id"]);
    let second = text(&mut ws).await.expect("a frame");
    assert!(
        matches!(&second, Message::Notification { method: m, .. } if m == method::CANCEL),
        "{second:?}"
    );
    let (_, m, _) = request(&mut ws).await;
    assert_eq!(m, method::DESCRIBE);
    r.stop().await;
}

/// A frame over the center's message limit ends the link with
/// `bye protocol_error` instead of parking it: the node would send it again
/// on every resume. The call in flight fails at once.
#[tokio::test]
async fn a_frame_over_the_limit_ends_a_resumable_link() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    let key = NodeKey::generate().unwrap();
    assert_eq!(pair(&r, &key, "box-1").await.0, 200);
    let (mut ws, _) = handshake_with(
        &r,
        &key,
        json!({"resume": {"link": link_id('d'), "got": 0}}),
    )
    .await;
    let (id, _, _) = request(&mut ws).await;
    send(&mut ws, Message::result(id, descriptor(&key, "box-1"))).await;
    let c = r.center.clone();
    wait_for(|| (!c.tools().is_empty()).then_some(())).await;
    let e = std::sync::Arc::new(Engine::new(&r.center, "test"));
    rpc(
        &e,
        1,
        "initialize",
        json!({"protocolVersion": "2025-06-18"}),
    )
    .await;
    let call = tokio::spawn({
        let e = e.clone();
        async move {
            e.handle(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": run_params("box-1", "exec.run", json!({"command": "make"}))}))
                .await
        }
    });
    let (invoke, _, _) = request(&mut ws).await;
    let big =
        json!({"exit_code": 0, "stdout": "x".repeat(MAX + 1), "stderr": "", "truncated": false});
    let _ = ws
        .send(WsMessage::text(Message::result(invoke, big).encode()))
        .await;
    // The center ends the connection. Its `bye` may not arrive: it closes
    // with the rest of the frame unread, and the reset that sends can drop
    // the bye before it is read (Windows does).
    let ended = loop {
        match tokio::time::timeout(Duration::from_secs(10), ws.next()).await {
            Err(_) => panic!("the center keeps the connection"),
            Ok(Some(Ok(WsMessage::Text(t)))) => match Message::decode(&t) {
                Ok(Message::Notification { method: m, params }) if m == method::BYE => {
                    break format!("bye {}", params["reason"].as_str().unwrap_or_default());
                }
                _ => continue,
            },
            Ok(Some(Ok(WsMessage::Close(_)))) | Ok(None) => break "closed".to_string(),
            Ok(Some(Err(e))) => break format!("failed: {e}"),
            Ok(Some(Ok(_))) => continue,
        }
    };
    assert!(
        !ended.starts_with("bye ") || ended == "bye protocol_error",
        "{ended}"
    );
    // Linux delivers the bye before the reset.
    #[cfg(not(windows))]
    assert_eq!(ended, "bye protocol_error");
    // The link is not parked: the call fails at once.
    let (text_out, failed) = reply_text(call).await;
    assert!(failed, "{text_out}");
    assert!(text_out.starts_with("error connection_lost"), "{text_out}");
    // Nothing is kept to resume.
    let (_ws, welcome) = handshake_with(
        &r,
        &key,
        json!({"resume": {"link": link_id('d'), "got": 2}}),
    )
    .await;
    assert_eq!(resume_of(&welcome), json!({"resumed": false, "got": 0}));
    r.stop().await;
}

/// A link whose welcome the node may never have read (the center read
/// nothing of it) is not carried on: the node may still hold an older link
/// of that id, and the two would answer each other's calls.
#[tokio::test]
async fn a_link_the_node_never_took_up_is_not_resumed() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    let key = NodeKey::generate().unwrap();
    assert_eq!(pair(&r, &key, "box-1").await.0, 200);
    // The center starts a new link under the offered id.
    let (mut ws, welcome) = handshake_with(
        &r,
        &key,
        json!({"resume": {"link": link_id('e'), "got": 3}}),
    )
    .await;
    assert_eq!(resume_of(&welcome), json!({"resumed": false, "got": 0}));
    // Its describe goes out, and the connection drops before the node sent
    // anything counted.
    let (_, m, _) = request(&mut ws).await;
    assert_eq!(m, method::DESCRIBE);
    drop(ws);
    let c = r.center.clone();
    let node = key.node_id();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(c.link(&node).is_none());
    // The node, which held an older link of that id, offers it again.
    let (_ws, welcome) = handshake_with(
        &r,
        &key,
        json!({"resume": {"link": link_id('e'), "got": 1}}),
    )
    .await;
    assert_eq!(resume_of(&welcome), json!({"resumed": false, "got": 0}));
    r.stop().await;
}
