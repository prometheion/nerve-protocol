//! Key rotation (docs/dev/spec/protocol.md §4.10) at the center, against a
//! fake node in the same process: a node's key, taken only when the key it
//! replaces signed it, the old key's grace and its end; and the center's own
//! key, told to the nodes signed by the old one and served at the end of the
//! grace.

use std::time::Duration;

use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use nerve_center::config::Args;
use nerve_center::server::{self, Running};
use nerve_proto::link::{CenterUrl, PairLink};
use nerve_proto::msg::{self, method};
use nerve_proto::rpc::Message;
use nerve_transport::keys::NodeKey;
use nerve_transport::net::BoxIo;
use nerve_transport::tls::{decode_pin, unb64url, verify_spki_signature};
use nerve_transport::ws::{self, WsMessage};
use serde_json::{Value, json};
use tokio_tungstenite::WebSocketStream;

const MAX: usize = 4 * 1024 * 1024;
const WEEK: u64 = nerve_proto::ROTATE_GRACE_MS;

/// A center in `dir`: plain HTTP for nodes on loopback, or TLS with its key.
async fn center(dir: &std::path::Path, tls: bool) -> Running {
    nerve_transport::init_crypto();
    let mut argv = vec![
        "nerve-center",
        "--state-dir",
        dir.to_str().unwrap(),
        "--name",
        "test-center",
        "--listen",
        "127.0.0.1:0",
        "--ui",
        "off",
        "--mcp",
        "off",
    ];
    if !tls {
        argv.push("--plain-loopback");
    }
    let args = Args::try_parse_from(argv).unwrap();
    let lock = nerve_center::attach::try_lock(dir)
        .unwrap()
        .expect("the lock is free");
    server::start(&args, lock).await.unwrap()
}

fn url(r: &Running, tls: bool) -> CenterUrl {
    let scheme = if tls { "https" } else { "http" };
    CenterUrl::parse(&format!("{scheme}://127.0.0.1:{}", r.nodes.port())).unwrap()
}

/// Pairs `key` as `name` over plain HTTP; the node id.
async fn pair(r: &Running, key: &NodeKey, name: &str) -> String {
    let p = r.center.new_pairing();
    let link = PairLink::parse(p["link"].as_str().unwrap()).unwrap();
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
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    let v: Value = serde_json::from_slice(&resp.body).unwrap();
    v["node_id"].as_str().unwrap().to_string()
}

/// Pairs `key` with a TLS center, as a node does over the pinned link.
async fn pair_tls(r: &Running, key: &NodeKey, name: &str) -> String {
    let p = r.center.new_pairing();
    let link = PairLink::parse(p["link"].as_str().unwrap()).unwrap();
    let mut io = nerve_transport::net::open(&url(r, true), link.pin.as_deref(), None)
        .await
        .unwrap();
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
    assert_eq!(resp.status, 200);
    let v: Value = serde_json::from_slice(&resp.body).unwrap();
    v["node_id"].as_str().unwrap().to_string()
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

/// Connects as `node_id`, signing with `key`, with `features` in the hello
/// and a new link to resume, and runs the handshake up to `welcome` (or
/// what came instead).
async fn handshake(
    url: &CenterUrl,
    pins: &[&str],
    node_id: &str,
    key: &NodeKey,
    features: &[&str],
) -> Result<(WebSocketStream<BoxIo>, Message), String> {
    let mut ws = ws::connect_pins(url, pins, None, node_id, MAX)
        .await
        .map_err(|e| e.to_string())?;
    let Some(Message::Notification { method: m, params }) = text(&mut ws).await else {
        panic!("no challenge")
    };
    assert_eq!(m, method::CHALLENGE);
    let nonce = msg::unhex(params["nonce"].as_str().unwrap()).unwrap();
    let center_id = params["center_id"].as_str().unwrap().to_string();
    let hello = json!({
        "node_id": node_id,
        "auth": {"sig": key.sign_connect(&center_id, &nonce)},
        "versions": ["0"],
        "software": {"name": "fake-node", "version": "x.y.z"},
        "rev": 1,
        "features": features,
        "resume": {"link": msg::hex(&nerve_transport::keys::random_bytes(16)), "got": 0},
    });
    send(&mut ws, Message::notification(method::HELLO, hello)).await;
    let next = text(&mut ws).await.expect("a reply to hello");
    Ok((ws, next))
}

fn method_of(m: &Message) -> &str {
    match m {
        Message::Notification { method, .. } | Message::Request { method, .. } => method,
        _ => "",
    }
}

fn params_of(m: Message) -> Value {
    match m {
        Message::Notification { params, .. } | Message::Request { params, .. } => {
            Value::Object(params)
        }
        _ => Value::Null,
    }
}

/// The next notification `want`, answering the center's requests on the way
/// (an empty descriptor); `None` when the link ends or nothing comes.
async fn next(ws: &mut WebSocketStream<BoxIo>, want: &str) -> Option<Value> {
    loop {
        let m = text(ws).await?;
        match m {
            Message::Notification { method: m, params } if m == want => {
                return Some(Value::Object(params));
            }
            Message::Notification { method: m, params } if m == method::BYE => {
                if want == method::BYE {
                    return Some(Value::Object(params));
                }
                return None;
            }
            Message::Request { id, .. } => {
                send(
                    ws,
                    Message::error(Some(id), nerve_proto::RpcError::internal("no")),
                )
                .await;
            }
            _ => {}
        }
    }
}

fn rotate_params(center_id: &str, old: &NodeKey, new: &NodeKey) -> Value {
    json!({
        "public_key": new.public_hex(),
        "sig": old.sign_rotate(center_id, &new.public_key()),
        "proof": new.sign_rotate(center_id, &new.public_key()),
    })
}

async fn welcomed(r: &Running, node_id: &str, key: &NodeKey) -> WebSocketStream<BoxIo> {
    let (ws, w) = handshake(&url(r, false), &[], node_id, key, &[])
        .await
        .unwrap();
    assert_eq!(method_of(&w), method::WELCOME, "{w:?}");
    ws
}

async fn wait_for(mut f: impl FnMut() -> bool) {
    for _ in 0..400 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out")
}

/// The welcome names the features of the hello the center speaks too:
/// none so far, whatever the node names. Key rotation needs none: it is
/// part of the baseline, so a node that names no feature rotates its key.
#[tokio::test]
async fn the_welcome_names_known_features_and_rotation_needs_none() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path(), false).await;
    let key = NodeKey::generate().unwrap();
    let id = pair(&r, &key, "box-1").await;
    let (ws, w) = handshake(&url(&r, false), &[], &id, &key, &["rotate", "x-later"])
        .await
        .unwrap();
    assert_eq!(params_of(w)["features"], json!([]));
    drop(ws);
    let c = r.center.clone();
    wait_for(|| c.link(&id).is_none()).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (mut ws, w) = handshake(&url(&r, false), &[], &id, &key, &[])
        .await
        .unwrap();
    let w = params_of(w);
    assert_eq!(w["version"], "0");
    assert_eq!(w["features"], json!([]), "{w}");
    let new = NodeKey::generate().unwrap();
    send(
        &mut ws,
        Message::notification(
            method::KEY_ROTATE,
            rotate_params(&r.center.id(), &key, &new),
        ),
    )
    .await;
    let a = next(&mut ws, method::KEY_ROTATED)
        .await
        .expect("key.rotated");
    assert_eq!(a["public_key"], new.public_hex(), "{a}");
    assert!(a.get("error").is_none(), "{a}");
    r.stop().await;
}

#[tokio::test]
async fn a_node_key_signed_by_the_key_it_replaces_is_taken_and_the_old_one_has_a_grace() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path(), false).await;
    let cid = r.center.id();
    let (old, new) = (NodeKey::generate().unwrap(), NodeKey::generate().unwrap());
    let id = pair(&r, &old, "box-1").await;
    let mut ws = welcomed(&r, &id, &old).await;

    send(
        &mut ws,
        Message::notification(method::KEY_ROTATE, rotate_params(&cid, &old, &new)),
    )
    .await;
    let a = next(&mut ws, method::KEY_ROTATED)
        .await
        .expect("key.rotated");
    assert_eq!(a, json!({"public_key": new.public_hex()}));
    assert_eq!(r.center.public_key(&id), Some(new.public_hex()));
    let until = r
        .center
        .read(|s| s.nodes[&id].old_key.clone())
        .expect("the old key")
        .until_ms;
    let now = msg::now_ms();
    assert!(
        until > now + WEEK - 60_000 && until <= now + WEEK,
        "{until}"
    );
    // Sent again (no answer reached the node): the same answer, nothing more.
    send(
        &mut ws,
        Message::notification(method::KEY_ROTATE, rotate_params(&cid, &old, &new)),
    )
    .await;
    let a = next(&mut ws, method::KEY_ROTATED)
        .await
        .expect("key.rotated");
    assert!(a.get("error").is_none(), "{a}");
    assert_eq!(
        r.center
            .read(|s| s.nodes[&id].old_key.clone())
            .unwrap()
            .public_key,
        old.public_hex()
    );
    // The node id stays; the state file keeps both keys.
    let state: Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("state.json")).unwrap()).unwrap();
    assert_eq!(state["nodes"][&id]["public_key"], new.public_hex());
    assert_eq!(
        state["nodes"][&id]["old_key"]["public_key"],
        old.public_hex()
    );
    drop(ws);

    // Both keys open a link during the grace, under the same node id.
    let c = r.center.clone();
    wait_for(|| c.link(&id).is_none()).await;
    drop(welcomed(&r, &id, &new).await);
    wait_for(|| c.link(&id).is_none()).await;
    let ws = welcomed(&r, &id, &old).await;
    drop(ws);
    wait_for(|| c.link(&id).is_none()).await;

    // Once the grace has ended, the old key is refused.
    r.center.update(|s| {
        s.nodes
            .get_mut(&id)
            .unwrap()
            .old_key
            .as_mut()
            .unwrap()
            .until_ms = 1;
    });
    let (_ws, reply) = handshake(&url(&r, false), &[], &id, &old, &[])
        .await
        .unwrap();
    assert_eq!(method_of(&reply), method::BYE);
    assert_eq!(params_of(reply)["reason"], "protocol_error");
    // The sweep drops it from the state.
    r.center.sweep().await;
    assert!(r.center.read(|s| s.nodes[&id].old_key.is_none()));
    r.stop().await;
}

#[tokio::test]
async fn a_rotation_the_current_key_did_not_sign_is_refused_and_the_key_stays() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path(), false).await;
    let cid = r.center.id();
    let key = NodeKey::generate().unwrap();
    let other = NodeKey::generate().unwrap();
    let id = pair(&r, &key, "box-1").await;
    let _other_id = pair(&r, &other, "box-2").await;
    let mut ws = welcomed(&r, &id, &key).await;
    let new = NodeKey::generate().unwrap();
    let stranger = NodeKey::generate().unwrap();

    let bad = [
        // Signed by a key that is not the node's.
        (rotate_params(&cid, &stranger, &new), "current key"),
        // The new key did not sign it.
        (
            json!({"public_key": new.public_hex(),
                   "sig": key.sign_rotate(&cid, &new.public_key()),
                   "proof": stranger.sign_rotate(&cid, &new.public_key())}),
            "new key did not sign",
        ),
        // Signed for another center.
        (
            rotate_params("another-center", &key, &new),
            "new key did not sign",
        ),
        // Another node's key.
        (rotate_params(&cid, &key, &other), "another node"),
        (
            json!({"public_key": "zz", "sig": "", "proof": ""}),
            "64 lowercase hex",
        ),
    ];
    for (p, why) in bad {
        send(&mut ws, Message::notification(method::KEY_ROTATE, p)).await;
        let a = next(&mut ws, method::KEY_ROTATED)
            .await
            .expect("key.rotated");
        let e = a["error"].as_str().unwrap_or_default();
        assert!(e.contains(why), "{why}: {a}");
        assert_eq!(r.center.public_key(&id), Some(key.public_hex()));
        assert!(r.center.read(|s| s.nodes[&id].old_key.is_none()));
    }
    // A key in the grace of another node cannot be paired either.
    send(
        &mut ws,
        Message::notification(method::KEY_ROTATE, rotate_params(&cid, &key, &new)),
    )
    .await;
    assert!(
        next(&mut ws, method::KEY_ROTATED)
            .await
            .unwrap()
            .get("error")
            .is_none()
    );
    let p = r.center.new_pairing();
    let link = PairLink::parse(p["link"].as_str().unwrap()).unwrap();
    let mut io = tokio::net::TcpStream::connect(r.nodes).await.unwrap();
    let body = json!({"code": link.code, "name": "box-3", "platform": "linux", "arch": "x86_64",
                      "public_key": key.public_hex()});
    let resp =
        nerve_transport::http::post_json(&mut io, "127.0.0.1", nerve_proto::PAIR_PATH, &body, 4096)
            .await
            .unwrap();
    assert_eq!(resp.status, 409);
    r.stop().await;
}

#[tokio::test]
async fn the_node_ends_the_grace_and_a_link_of_the_old_key_ends_with_it() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path(), false).await;
    let cid = r.center.id();
    let (old, new) = (NodeKey::generate().unwrap(), NodeKey::generate().unwrap());
    let id = pair(&r, &old, "box-1").await;
    let mut ws = welcomed(&r, &id, &old).await;
    send(
        &mut ws,
        Message::notification(method::KEY_ROTATE, rotate_params(&cid, &old, &new)),
    )
    .await;
    next(&mut ws, method::KEY_ROTATED)
        .await
        .expect("key.rotated");

    // Only the current key may end the grace.
    let retire = |k: &NodeKey| json!({"public_key": k.public_hex(), "sig": k.sign_retire(&cid)});
    send(
        &mut ws,
        Message::notification(method::KEY_RETIRE, retire(&old)),
    )
    .await;
    let a = next(&mut ws, method::KEY_RETIRED)
        .await
        .expect("key.retired");
    assert!(a["error"].as_str().is_some(), "{a}");
    assert!(r.center.read(|s| s.nodes[&id].old_key.is_some()));

    send(
        &mut ws,
        Message::notification(method::KEY_RETIRE, retire(&new)),
    )
    .await;
    let a = next(&mut ws, method::KEY_RETIRED)
        .await
        .expect("key.retired");
    assert_eq!(a, json!({}));
    assert!(r.center.read(|s| s.nodes[&id].old_key.is_none()));
    // This link was opened with the old key, which is refused now.
    let bye = next(&mut ws, method::BYE).await.expect("bye");
    assert_eq!(bye["reason"], "replaced");
    // The node closes on the bye, and dials again with its key.
    drop(ws);
    let c = r.center.clone();
    wait_for(|| c.link(&id).is_none()).await;
    let (_ws, reply) = handshake(&url(&r, false), &[], &id, &old, &[])
        .await
        .unwrap();
    assert_eq!(method_of(&reply), method::BYE);
    drop(welcomed(&r, &id, &new).await);
    r.stop().await;
}

/// Checks a `center.rotate` as a node does: the old key signed the new pin.
fn check_center_rotate(n: &Value, center_id: &str, old_pin: &str) -> String {
    let old = unb64url(n["old_spki"].as_str().unwrap()).unwrap();
    let new = unb64url(n["new_spki"].as_str().unwrap()).unwrap();
    let sig = unb64url(n["sig"].as_str().unwrap()).unwrap();
    assert_eq!(nerve_transport::tls::pin_of_spki(&old), old_pin);
    let new_pin = nerve_transport::tls::pin_of_spki(&new);
    let message = nerve_proto::rotate_center_message(center_id, &decode_pin(&new_pin).unwrap());
    assert!(verify_spki_signature(&old, &message, &sig));
    new_pin
}

#[tokio::test]
async fn the_center_rotates_its_key_tells_the_nodes_and_serves_it_after_the_grace() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path(), true).await;
    let cid = r.center.id();
    let old_pin = r.center.pin().expect("a TLS center has a pin");
    let key = NodeKey::generate().unwrap();
    let id = pair_tls(&r, &key, "box-1").await;
    let tls = url(&r, true);
    let (mut ws, w) = handshake(&tls, &[&old_pin], &id, &key, &[]).await.unwrap();
    assert_eq!(method_of(&w), method::WELCOME);
    let c = r.center.clone();
    wait_for(|| c.link(&id).is_some()).await;

    // The owner rotates: the new pin is in the answer; the linked node is
    // told, signed by the old key; the old key is still served.
    let out = r.center.rotate_key().await.unwrap();
    let new_pin = out["pin"].as_str().unwrap().to_string();
    assert_ne!(new_pin, old_pin);
    assert_eq!(out["old_pin"], old_pin.as_str());
    assert_eq!(out["told"], 1);
    let n = next(&mut ws, method::CENTER_ROTATE)
        .await
        .expect("center.rotate");
    assert_eq!(check_center_rotate(&n, &cid, &old_pin), new_pin);
    let grace = n["grace_ms"].as_u64().unwrap();
    assert!(grace > WEEK - 60_000 && grace <= WEEK, "{grace}");
    assert_eq!(r.center.pin().as_deref(), Some(old_pin.as_str()));
    assert!(dir.path().join("tls.next.pem").exists());
    // The new pin is not shown again.
    assert!(r.center.key_json().to_string().find(&new_pin).is_none());
    assert!(
        r.center
            .rotate_key()
            .await
            .unwrap_err()
            .contains("in its grace")
    );
    drop(ws);
    wait_for(|| c.link(&id).is_none()).await;

    // A node that links during the grace, with the old pin only, is told.
    let (mut ws, _) = handshake(&tls, &[&old_pin], &id, &key, &[]).await.unwrap();
    let n = next(&mut ws, method::CENTER_ROTATE)
        .await
        .expect("told on link");
    assert_eq!(check_center_rotate(&n, &cid, &old_pin), new_pin);
    // So is a node that only learns of it now; a node that does not speak
    // rotation is not.
    drop(ws);
    wait_for(|| c.link(&id).is_none()).await;

    // The grace ends: the new key is served, for every new connection.
    r.center
        .update(|s| s.key_rotation.as_mut().unwrap().until_ms = 1);
    r.center.sweep().await;
    assert_eq!(r.center.pin().as_deref(), Some(new_pin.as_str()));
    assert!(!dir.path().join("tls.next.pem").exists());
    assert!(handshake(&tls, &[&old_pin], &id, &key, &[]).await.is_err());
    let (mut ws, w) = handshake(&tls, &[&new_pin], &id, &key, &[]).await.unwrap();
    assert_eq!(method_of(&w), method::WELCOME);
    // Nodes are still told, with no grace left, so they drop the old pin.
    let n = next(&mut ws, method::CENTER_ROTATE)
        .await
        .expect("told after");
    assert_eq!(n["grace_ms"], 0);
    // New pairing links carry the new pin.
    let link = PairLink::parse(r.center.new_pairing()["link"].as_str().unwrap()).unwrap();
    assert_eq!(link.pin.as_deref(), Some(new_pin.as_str()));
    drop(ws);
    r.stop().await;

    // A restart serves the new key from tls.pem.
    let r = center(dir.path(), true).await;
    assert_eq!(r.center.pin().as_deref(), Some(new_pin.as_str()));
    r.stop().await;
}

#[tokio::test]
async fn the_owner_ends_the_grace_of_the_center_key_early() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path(), true).await;
    let old_pin = r.center.pin().unwrap();
    assert!(
        r.center
            .finish_key_rotation("test")
            .await
            .unwrap_err()
            .contains("no rotation")
    );
    let key = NodeKey::generate().unwrap();
    let id = pair_tls(&r, &key, "box-1").await;
    let tls = url(&r, true);
    let (mut ws, _) = handshake(&tls, &[&old_pin], &id, &key, &[]).await.unwrap();
    let new_pin = r.center.rotate_key().await.unwrap()["pin"]
        .as_str()
        .unwrap()
        .to_string();
    let n = next(&mut ws, method::CENTER_ROTATE).await.unwrap();
    assert!(n["grace_ms"].as_u64().unwrap() > 0);
    let out = r
        .center
        .finish_key_rotation("the owner ended its grace")
        .await
        .unwrap();
    assert_eq!(out["pin"], new_pin.as_str());
    // The link up now goes on, and hears that the grace is over.
    let n = next(&mut ws, method::CENTER_ROTATE).await.unwrap();
    assert_eq!(n["grace_ms"], 0);
    assert!(handshake(&tls, &[&old_pin], &id, &key, &[]).await.is_err());
    r.stop().await;
}

#[tokio::test]
async fn a_start_drops_a_new_key_the_state_does_not_know() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path(), true).await;
    let pin = r.center.pin().unwrap();
    r.stop().await;
    // A rotation cut short before the state file held it.
    let stray = nerve_transport::tls::ServerIdentity::generate(&[]).unwrap();
    std::fs::write(dir.path().join("tls.next.pem"), stray.to_pem()).unwrap();
    let r = center(dir.path(), true).await;
    assert_eq!(r.center.pin().as_deref(), Some(pin.as_str()));
    assert!(!dir.path().join("tls.next.pem").exists());
    assert!(r.center.read(|s| s.key_rotation.is_none()));
    r.stop().await;
}

/// When the grace of a node's old key ends, by the sweep or by a newer
/// rotation, a link opened with that key ends too.
#[tokio::test]
async fn a_link_of_the_old_node_key_ends_with_its_grace() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path(), false).await;
    let cid = r.center.id();
    let k = [(); 3].map(|_| NodeKey::generate().unwrap());
    let id = pair(&r, &k[0], "box-1").await;
    let c = r.center.clone();

    // Rotated to k1 on a link that k0 opened; the sweep ends k0's grace.
    let mut ws = welcomed(&r, &id, &k[0]).await;
    send(
        &mut ws,
        Message::notification(method::KEY_ROTATE, rotate_params(&cid, &k[0], &k[1])),
    )
    .await;
    next(&mut ws, method::KEY_ROTATED)
        .await
        .expect("key.rotated");
    r.center.sweep().await;
    assert!(c.link(&id).is_some(), "the grace still runs");
    r.center.update(|s| {
        s.nodes
            .get_mut(&id)
            .unwrap()
            .old_key
            .as_mut()
            .unwrap()
            .until_ms = 1;
    });
    r.center.sweep().await;
    assert!(c.link(&id).is_none(), "the k0 link ends with its grace");
    let bye = next(&mut ws, method::BYE).await.expect("bye");
    assert_eq!(bye["reason"], "replaced");
    drop(ws);

    // A link k1 opens; k1 → k2 on it, then on a link k1 opened during
    // that grace, k2 → k0 ends k1's grace and that link.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut ws = welcomed(&r, &id, &k[1]).await;
    send(
        &mut ws,
        Message::notification(method::KEY_ROTATE, rotate_params(&cid, &k[1], &k[2])),
    )
    .await;
    next(&mut ws, method::KEY_ROTATED)
        .await
        .expect("key.rotated");
    assert!(c.link(&id).is_some(), "k1 is in its grace");
    send(
        &mut ws,
        Message::notification(method::KEY_ROTATE, rotate_params(&cid, &k[2], &k[0])),
    )
    .await;
    let a = next(&mut ws, method::KEY_ROTATED)
        .await
        .expect("key.rotated");
    assert!(a.get("error").is_none(), "{a}");
    let bye = next(&mut ws, method::BYE).await.expect("bye");
    assert_eq!(bye["reason"], "replaced");
    assert!(c.link(&id).is_none());
    r.stop().await;
}

/// A center that cannot save the node's new key says so, and keeps the key
/// it had: the node would delete its old key on a "taken".
#[cfg(unix)]
#[tokio::test]
async fn a_node_key_the_center_cannot_save_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path(), false).await;
    let cid = r.center.id();
    let (old, new) = (NodeKey::generate().unwrap(), NodeKey::generate().unwrap());
    let id = pair(&r, &old, "box-1").await;
    let mut ws = welcomed(&r, &id, &old).await;
    let mode = |m| std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(m));
    mode(0o500).unwrap();
    // Root writes anyway; then this test says nothing.
    let writable = std::fs::write(dir.path().join("probe"), b"x").is_ok();
    send(
        &mut ws,
        Message::notification(method::KEY_ROTATE, rotate_params(&cid, &old, &new)),
    )
    .await;
    let a = next(&mut ws, method::KEY_ROTATED)
        .await
        .expect("key.rotated");
    mode(0o700).unwrap();
    if writable {
        return;
    }
    let e = a["error"].as_str().unwrap_or_default();
    assert!(e.contains("state file"), "{a}");
    assert_eq!(r.center.public_key(&id), Some(old.public_hex()));
    assert!(r.center.read(|s| s.nodes[&id].old_key.is_none()));
    r.stop().await;
}

/// A rotation sent again for the key the center took already is answered
/// as taken without a write: a failed write must not have the node drop the
/// key the center holds.
#[cfg(unix)]
#[tokio::test]
async fn a_rotation_sent_again_is_taken_without_a_write() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path(), false).await;
    let cid = r.center.id();
    let (old, new) = (NodeKey::generate().unwrap(), NodeKey::generate().unwrap());
    let id = pair(&r, &old, "box-1").await;
    let mut ws = welcomed(&r, &id, &old).await;
    let rotate = Message::notification(method::KEY_ROTATE, rotate_params(&cid, &old, &new));
    send(&mut ws, rotate.clone()).await;
    let a = next(&mut ws, method::KEY_ROTATED)
        .await
        .expect("key.rotated");
    assert!(a.get("error").is_none(), "{a}");
    let mode = |m| std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(m));
    mode(0o500).unwrap();
    send(&mut ws, rotate).await;
    let a = next(&mut ws, method::KEY_ROTATED)
        .await
        .expect("key.rotated");
    mode(0o700).unwrap();
    assert_eq!(a, json!({"public_key": new.public_hex()}));
    assert_eq!(r.center.public_key(&id), Some(new.public_hex()));
    r.stop().await;
}

/// Sends requests with long names on `ws` and reads nothing, until the
/// center stops reading too: its answers fill the link's queue. How many
/// went out.
async fn wedge(ws: WebSocketStream<BoxIo>) -> (usize, tokio::task::JoinHandle<()>) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        let mut ws = ws;
        let long = "x".repeat(100_000);
        for i in 0..2000u64 {
            let m = Message::request(i + 1000, &long, json!({}));
            let sent =
                tokio::time::timeout(Duration::from_secs(2), ws.send(WsMessage::text(m.encode())))
                    .await;
            if !matches!(sent, Ok(Ok(()))) {
                break;
            }
            let _ = tx.send(());
        }
        let _ = tx.send(());
        // Keeps the connection open, and reads nothing.
        tokio::time::sleep(Duration::from_secs(60)).await;
        drop(ws);
    });
    let mut n = 0;
    while tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .is_ok_and(|v| v.is_some())
    {
        n += 1;
    }
    (n, task)
}

/// A link whose peer reads nothing holds up neither the sweep nor the
/// owner's rotation of the center's key, and the sweep still ends it.
#[tokio::test]
async fn a_link_that_reads_nothing_holds_up_neither_the_sweep_nor_a_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path(), false).await;
    let cid = r.center.id();
    let (old, new) = (NodeKey::generate().unwrap(), NodeKey::generate().unwrap());
    let id = pair(&r, &old, "box-1").await;
    let mut ws = welcomed(&r, &id, &old).await;
    send(
        &mut ws,
        Message::notification(method::KEY_ROTATE, rotate_params(&cid, &old, &new)),
    )
    .await;
    next(&mut ws, method::KEY_ROTATED)
        .await
        .expect("key.rotated");
    let (sent, task) = wedge(ws).await;
    assert!(sent < 2000, "the center went on reading: {sent}");

    let out = tokio::time::timeout(Duration::from_secs(10), r.center.rotate_key()).await;
    assert!(out.expect("the rotation answers").is_ok());
    r.center.update(|s| {
        s.nodes
            .get_mut(&id)
            .unwrap()
            .old_key
            .as_mut()
            .unwrap()
            .until_ms = 1;
        s.key_rotation.as_mut().unwrap().until_ms = 1;
    });
    let swept = tokio::time::timeout(Duration::from_secs(10), r.center.sweep()).await;
    assert!(swept.is_ok(), "the sweep is held up");
    assert!(r.center.link(&id).is_none(), "the old key's link ended");
    assert!(
        r.center
            .read(|s| s.key_rotation.as_ref().unwrap().finished_ms.is_some())
    );
    task.abort();
    // Not `stop`: its bye to every link waits on the queue.
    drop(r);
}

/// A link the center ended, because its key's grace is over, handles
/// nothing more its peer sends.
#[tokio::test]
async fn a_link_ended_with_its_grace_handles_nothing_more() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path(), false).await;
    let cid = r.center.id();
    let (old, new) = (NodeKey::generate().unwrap(), NodeKey::generate().unwrap());
    let id = pair(&r, &old, "box-1").await;
    let mut ws = welcomed(&r, &id, &old).await;
    send(
        &mut ws,
        Message::notification(method::KEY_ROTATE, rotate_params(&cid, &old, &new)),
    )
    .await;
    next(&mut ws, method::KEY_ROTATED)
        .await
        .expect("key.rotated");
    r.center.update(|s| {
        s.nodes
            .get_mut(&id)
            .unwrap()
            .old_key
            .as_mut()
            .unwrap()
            .until_ms = 1;
    });
    r.center.sweep().await;
    // The peer does not read the bye and goes on as the node.
    let event = |seq: u64, cap: &str, name: &str, data: Value| {
        Message::notification(
            method::EVENT,
            json!({"cap": cap, "name": name, "seq": seq, "ts": msg::now_ms(), "data": data}),
        )
    };
    for seq in 1..=3 {
        let _ = ws
            .send(WsMessage::text(
                event(
                    seq,
                    "audit",
                    "decision",
                    json!({"cap": "exec", "action": "run",
                    "target": "injected", "decision": "allowed"}),
                )
                .encode(),
            ))
            .await;
        let _ = ws
            .send(WsMessage::text(
                event(seq, "node", "going_away", json!({"reason": "injected"})).encode(),
            ))
            .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !r.center.audit().iter().any(|e| e["target"] == "injected"),
        "{:?}",
        r.center.audit()
    );
    assert!(r.center.read(|s| s.nodes[&id].going_away.is_none()));
    r.stop().await;
}

/// A backup made during the grace of a center key rotation keeps the new
/// key: the restored center serves the old key until the grace ends, then
/// the new one, which the nodes it told pin.
#[tokio::test]
async fn a_backup_in_the_grace_keeps_the_new_center_key() {
    let a = tempfile::tempdir().unwrap();
    let r = center(a.path(), true).await;
    let old_pin = r.center.pin().unwrap();
    let new_pin = r.center.rotate_key().await.unwrap()["pin"]
        .as_str()
        .unwrap()
        .to_string();
    r.stop().await;
    let pass = nerve_transport::backup::Passphrase::new("correct horse battery".into());
    let d = tempfile::tempdir().unwrap();
    let file = d.path().join("c.bak");
    nerve_center::backup::backup(a.path(), &file, &pass, false, 4).unwrap();
    let parsed = nerve_center::backup::open(&std::fs::read(&file).unwrap(), &pass).unwrap();
    let b = tempfile::tempdir().unwrap();
    nerve_center::backup::restore(b.path(), &parsed, false).unwrap();
    assert!(b.path().join("tls.next.pem").exists());

    let r = center(b.path(), true).await;
    assert_eq!(r.center.pin().as_deref(), Some(old_pin.as_str()));
    assert!(r.center.read(|s| s.key_rotation.is_some()));
    r.center
        .finish_key_rotation("the owner ended its grace")
        .await
        .unwrap();
    assert_eq!(r.center.pin().as_deref(), Some(new_pin.as_str()));
    r.stop().await;
}

/// Whatever way a key stopped counting, a link opened with it ends at the
/// next sweep: here it came up after the sweep that dropped its key.
#[tokio::test]
async fn a_link_whose_key_no_longer_counts_ends_at_the_next_sweep() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path(), false).await;
    let cid = r.center.id();
    let (old, new) = (NodeKey::generate().unwrap(), NodeKey::generate().unwrap());
    let id = pair(&r, &old, "box-1").await;
    let mut ws = welcomed(&r, &id, &old).await;
    send(
        &mut ws,
        Message::notification(method::KEY_ROTATE, rotate_params(&cid, &old, &new)),
    )
    .await;
    next(&mut ws, method::KEY_ROTATED)
        .await
        .expect("key.rotated");
    // The old key's grace is over and gone from the state, but the link it
    // opened is still the node's (it came up late).
    r.center
        .update(|s| s.nodes.get_mut(&id).unwrap().old_key = None);
    assert!(r.center.link(&id).is_some());
    r.center.sweep().await;
    assert!(r.center.link(&id).is_none(), "the link of the old key ends");
    let bye = next(&mut ws, method::BYE).await.expect("bye");
    assert_eq!(bye["reason"], "replaced");
    r.stop().await;
}

/// A held link replaced because it did not answer the ping still counts as
/// a drop.
#[tokio::test]
async fn a_replaced_link_counts_as_a_drop() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path(), false).await;
    let key = NodeKey::generate().unwrap();
    let id = pair(&r, &key, "box-1").await;
    // Not read, so it answers no ping.
    let first = welcomed(&r, &id, &key).await;
    let c = r.center.clone();
    wait_for(|| c.link(&id).is_some()).await;
    let second = welcomed(&r, &id, &key).await;
    drop(first);
    let drops = || {
        c.read(|s| {
            s.stats
                .get(&id)
                .map_or(0, |st| st.days.values().map(|d| d.drops).sum::<u64>())
        })
    };
    wait_for(|| drops() == 1).await;
    drop(second);
    r.stop().await;
}

fn backup_of(state: &std::path::Path, d: &std::path::Path) -> nerve_center::backup::Parsed {
    let pass = nerve_transport::backup::Passphrase::new("correct horse battery".into());
    let file = d.join("c.bak");
    let _ = std::fs::remove_file(&file);
    nerve_center::backup::backup(state, &file, &pass, false, 4).unwrap();
    nerve_center::backup::open(&std::fs::read(&file).unwrap(), &pass).unwrap()
}

/// A restore of a backup made before a rotation of the center's key keeps
/// the new key and the rotation: the nodes were told it, in its grace and
/// after.
#[tokio::test]
async fn a_restore_from_before_a_rotation_keeps_the_new_center_key() {
    let a = tempfile::tempdir().unwrap();
    let d = tempfile::tempdir().unwrap();
    let r = center(a.path(), true).await;
    let old_pin = r.center.pin().unwrap();
    r.stop().await;
    let parsed = backup_of(a.path(), d.path());

    // In the grace.
    let r = center(a.path(), true).await;
    let new_pin = r.center.rotate_key().await.unwrap()["pin"]
        .as_str()
        .unwrap()
        .to_string();
    r.stop().await;
    let report = nerve_center::backup::restore(a.path(), &parsed, false).unwrap();
    assert!(
        report.notes.iter().any(|n| n.contains("keeps the new key")),
        "{report:?}"
    );
    assert!(a.path().join("tls.next.pem").exists());
    let r = center(a.path(), true).await;
    assert_eq!(r.center.pin().as_deref(), Some(old_pin.as_str()));
    r.center.finish_key_rotation("test").await.unwrap();
    assert_eq!(r.center.pin().as_deref(), Some(new_pin.as_str()));
    r.stop().await;

    // After the grace: the new key stays served.
    nerve_center::backup::restore(a.path(), &parsed, false).unwrap();
    let r = center(a.path(), true).await;
    assert_eq!(r.center.pin().as_deref(), Some(new_pin.as_str()));
    assert!(r.center.read(|s| s.key_rotation.is_some()));
    r.stop().await;
}

/// A restore that fails after it wrote the certificate puts back what was
/// here, the new key of a rotation in its grace too.
#[tokio::test]
async fn a_failed_restore_puts_back_the_new_center_key() {
    let a = tempfile::tempdir().unwrap();
    let d = tempfile::tempdir().unwrap();
    let r = center(a.path(), true).await;
    r.stop().await;
    let parsed = backup_of(a.path(), d.path());
    let r = center(a.path(), true).await;
    r.center.rotate_key().await.unwrap();
    r.stop().await;
    let next = std::fs::read(a.path().join("tls.next.pem")).unwrap();
    let pem = std::fs::read(a.path().join("tls.pem")).unwrap();
    // state.json cannot be replaced: a folder with something in it there.
    let state = a.path().join("state.json");
    std::fs::remove_file(&state).unwrap();
    std::fs::create_dir(&state).unwrap();
    std::fs::write(state.join("x"), b"x").unwrap();
    let e = nerve_center::backup::restore(a.path(), &parsed, true).unwrap_err();
    assert!(e.contains("nothing was restored"), "{e}");
    assert_eq!(std::fs::read(a.path().join("tls.next.pem")).unwrap(), next);
    assert_eq!(std::fs::read(a.path().join("tls.pem")).unwrap(), pem);
}

/// A backup made in the grace and restored after the grace was ended (here
/// early) keeps the new key served: the machines that were told take only
/// that one.
#[tokio::test]
async fn a_backup_from_the_grace_restored_after_its_end_keeps_the_new_key_served() {
    let a = tempfile::tempdir().unwrap();
    let d = tempfile::tempdir().unwrap();
    let r = center(a.path(), true).await;
    let new_pin = r.center.rotate_key().await.unwrap()["pin"]
        .as_str()
        .unwrap()
        .to_string();
    r.stop().await;
    let parsed = backup_of(a.path(), d.path());
    let r = center(a.path(), true).await;
    r.center.finish_key_rotation("test").await.unwrap();
    r.stop().await;
    let report = nerve_center::backup::restore(a.path(), &parsed, false).unwrap();
    assert!(
        report.notes.iter().any(|n| n.contains("keeps the new key")),
        "{report:?}"
    );
    assert!(!a.path().join("tls.next.pem").exists());
    let r = center(a.path(), true).await;
    assert_eq!(r.center.pin().as_deref(), Some(new_pin.as_str()));
    r.stop().await;
}

/// A restore of a backup made before a node rotated its key keeps the
/// node's record here: the node holds only its new key.
#[tokio::test]
async fn a_restore_from_before_a_node_rotation_keeps_the_nodes_new_key() {
    let a = tempfile::tempdir().unwrap();
    let d = tempfile::tempdir().unwrap();
    let r = center(a.path(), false).await;
    let cid = r.center.id();
    let (old, new) = (NodeKey::generate().unwrap(), NodeKey::generate().unwrap());
    let id = pair(&r, &old, "box-1").await;
    r.center.flush();
    let parsed = backup_of(a.path(), d.path());
    let mut ws = welcomed(&r, &id, &old).await;
    send(
        &mut ws,
        Message::notification(method::KEY_ROTATE, rotate_params(&cid, &old, &new)),
    )
    .await;
    next(&mut ws, method::KEY_ROTATED)
        .await
        .expect("key.rotated");
    drop(ws);
    r.stop().await;

    let report = nerve_center::backup::restore(a.path(), &parsed, false).unwrap();
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("box-1 rotated its key")),
        "{report:?}"
    );
    let r = center(a.path(), false).await;
    assert_eq!(r.center.public_key(&id), Some(new.public_hex()));
    drop(welcomed(&r, &id, &new).await);
    r.stop().await;
}

/// A restore after two rotations of the center's key since the backup keeps
/// the keys here: the newest served, and the one in the grace aside.
#[tokio::test]
async fn a_restore_after_two_center_rotations_keeps_the_keys_here() {
    let a = tempfile::tempdir().unwrap();
    let d = tempfile::tempdir().unwrap();
    let r = center(a.path(), true).await;
    r.stop().await;
    let parsed = backup_of(a.path(), d.path());
    let r = center(a.path(), true).await;
    let n = r.center.rotate_key().await.unwrap()["pin"]
        .as_str()
        .unwrap()
        .to_string();
    r.center.finish_key_rotation("test").await.unwrap();
    let m = r.center.rotate_key().await.unwrap()["pin"]
        .as_str()
        .unwrap()
        .to_string();
    r.stop().await;

    // The second in its grace: N served, M aside; the restore says N.
    let report = nerve_center::backup::restore(a.path(), &parsed, false).unwrap();
    assert_eq!(report.pin, n);
    let mut out = Vec::new();
    nerve_center::backup::print_restore(&report, &parsed, &mut out);
    let out = String::from_utf8(out).unwrap();
    assert!(out.contains(&format!("pin {n}")), "{out}");
    assert!(a.path().join("tls.next.pem").exists());
    let r = center(a.path(), true).await;
    assert_eq!(r.center.pin().as_deref(), Some(n.as_str()));
    r.center.finish_key_rotation("test").await.unwrap();
    assert_eq!(r.center.pin().as_deref(), Some(m.as_str()));
    r.stop().await;

    // Both ended: M served.
    nerve_center::backup::restore(a.path(), &parsed, false).unwrap();
    let r = center(a.path(), true).await;
    assert_eq!(r.center.pin().as_deref(), Some(m.as_str()));
    r.stop().await;
}

/// The end of a grace whose save failed (the new key served, the record
/// still unfinished on disk) counts as ended for a restore: the new key the
/// told nodes take stays.
#[tokio::test]
async fn a_restore_keeps_a_new_key_whose_end_was_not_saved() {
    let a = tempfile::tempdir().unwrap();
    let d = tempfile::tempdir().unwrap();
    let r = center(a.path(), true).await;
    r.stop().await;
    let parsed = backup_of(a.path(), d.path());
    let r = center(a.path(), true).await;
    let new_pin = r.center.rotate_key().await.unwrap()["pin"]
        .as_str()
        .unwrap()
        .to_string();
    r.stop().await;
    // What `end_rotation` leaves when its save fails: the new key moved to
    // tls.pem, the record on disk unfinished.
    std::fs::rename(a.path().join("tls.next.pem"), a.path().join("tls.pem")).unwrap();
    let report = nerve_center::backup::restore(a.path(), &parsed, false).unwrap();
    assert_eq!(report.pin, new_pin, "{report:?}");
    assert!(!a.path().join("tls.next.pem").exists());
    let r = center(a.path(), true).await;
    assert_eq!(r.center.pin().as_deref(), Some(new_pin.as_str()));
    r.stop().await;
}

/// A restore does not bring back a node's old key whose grace the node
/// ended after the backup was made.
#[tokio::test]
async fn a_restore_does_not_bring_back_a_retired_node_key() {
    let a = tempfile::tempdir().unwrap();
    let d = tempfile::tempdir().unwrap();
    let r = center(a.path(), false).await;
    let cid = r.center.id();
    let (old, new) = (NodeKey::generate().unwrap(), NodeKey::generate().unwrap());
    let id = pair(&r, &old, "box-1").await;
    let mut ws = welcomed(&r, &id, &old).await;
    send(
        &mut ws,
        Message::notification(method::KEY_ROTATE, rotate_params(&cid, &old, &new)),
    )
    .await;
    next(&mut ws, method::KEY_ROTATED)
        .await
        .expect("key.rotated");
    drop(ws);
    r.stop().await;
    let parsed = backup_of(a.path(), d.path());

    let r = center(a.path(), false).await;
    let mut ws = welcomed(&r, &id, &new).await;
    let retire = json!({"public_key": new.public_hex(), "sig": new.sign_retire(&cid)});
    send(&mut ws, Message::notification(method::KEY_RETIRE, retire)).await;
    assert_eq!(
        next(&mut ws, method::KEY_RETIRED)
            .await
            .expect("key.retired"),
        json!({})
    );
    drop(ws);
    r.stop().await;

    let report = nerve_center::backup::restore(a.path(), &parsed, false).unwrap();
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("does not bring that key back")),
        "{report:?}"
    );
    let r = center(a.path(), false).await;
    assert!(r.center.read(|s| s.nodes[&id].old_key.is_none()));
    let (_ws, reply) = handshake(&url(&r, false), &[], &id, &old, &[])
        .await
        .unwrap();
    assert_eq!(method_of(&reply), method::BYE);
    r.stop().await;
}
