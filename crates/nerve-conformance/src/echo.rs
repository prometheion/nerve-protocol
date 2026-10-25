//! The echo node: the smallest node that follows the protocol. It offers the
//! built-in `node` capability and one `echo` capability, and
//! the center part of the conformance suite drives a center with it.

use std::time::Duration;

use serde_json::{Map, Value, json};
use tokio::io::{AsyncRead, AsyncWrite};

use nerve_proto::link::{CenterUrl, PairLink, PairRequest, PairResponse};
use nerve_proto::msg::{self, Challenge, Describe, Invoke, method};
use nerve_proto::{
    Descriptor, ErrorCode, Message, PAIR_PATH, PROTOCOL_VERSION, RpcError, rpc::params,
};
use nerve_transport::keys::NodeKey;

use crate::wire::{Conn, Recv};

/// The descriptor the echo node offers.
pub fn descriptor(node_id: &str, name: &str) -> Descriptor {
    serde_json::from_value(json!({
        "nerve": PROTOCOL_VERSION,
        "node": {"id": node_id, "name": name, "platform": std::env::consts::OS,
                 "arch": std::env::consts::ARCH,
                 "software": {"name": "nerve-echo", "version": env!("CARGO_PKG_VERSION")}},
        "rev": 1,
        "summary": "Conformance echo node: answers echo.say with what it was sent and fails echo.fail.",
        "capabilities": [
            {"id": "node", "profile": "node", "exposure": "on", "summary": "The node itself.",
             "events": {"descriptor_changed": {"implicit": true}, "going_away": {"implicit": true}}},
            {"id": "echo", "exposure": "on", "summary": "Says back what it is sent.",
             "actions": {"say": {"effect": "read", "summary": "Return the text.",
                "params": {"type": "object", "properties": {"text": {"type": "string"}},
                           "required": ["text"], "additionalProperties": false},
                "result": {"type": "object", "properties": {"text": {"type": "string"}}}},
              // Arguments that fit, and still a failure on the node: a
              // center checks the arguments itself, so only an action like
              // this shows how it passes on what the node answered.
              "fail": {"effect": "read", "summary": "Fail with io, whatever it is sent.",
                "params": {"type": "object", "properties": {}, "additionalProperties": false}}}}
        ]
    }))
    .expect("the echo descriptor is well formed")
}

/// The descriptor the harness part's nodes offer: the echo node's, plus
/// `mirror`, an `echo` twin with a write action, and actions of `node`,
/// `settings` and `audit`, which a center must never offer a harness.
pub fn harness_descriptor(node_id: &str, name: &str) -> Descriptor {
    let mut d = serde_json::to_value(descriptor(node_id, name)).expect("a descriptor is JSON");
    let caps = d["capabilities"].as_array_mut().expect("capabilities");
    let say = caps[1]["actions"]["say"].clone();
    // A write action, so that `list` has another effect to tell.
    let mut set = say.clone();
    set["effect"] = json!("write");
    set["summary"] = json!("Store the text.");
    caps.push(json!({"id": "mirror", "exposure": "on",
        "summary": "Says back what it is sent, like echo.",
        "actions": {"say": say, "set": set}}));
    // The three capabilities a center must never offer, each with an action
    // that would otherwise be listed.
    caps[0]["actions"] =
        json!({"info": {"effect": "read", "summary": "Never offered to a harness."}});
    caps.push(
        json!({"id": "settings", "exposure": "on", "summary": "Not a tool.",
        "actions": {"get": {"effect": "read", "summary": "Never offered to a harness."}}}),
    );
    caps.push(
        json!({"id": "audit", "exposure": "on", "summary": "Not a tool.",
        "actions": {"list": {"effect": "read", "summary": "Never offered to a harness."}}}),
    );
    serde_json::from_value(d).expect("the harness descriptor is well formed")
}

/// A paired echo node.
pub struct Echo {
    pub key: NodeKey,
    pub name: String,
    pub url: CenterUrl,
    pub pin: Option<String>,
    pub center_id: String,
    pub node_id: String,
}

/// Sends a pair request; returns the HTTP status and body.
pub async fn post_pair(
    url: &CenterUrl,
    pin: Option<&str>,
    body: &Value,
) -> Result<(u16, Value), String> {
    let mut io = nerve_transport::net::open(url, pin, None).await?;
    let path = format!("{}{}", url.base, PAIR_PATH);
    let resp =
        nerve_transport::http::post_json(&mut io, &url.authority(), &path, body, 64 * 1024).await?;
    let v = serde_json::from_slice(&resp.body).unwrap_or(Value::Null);
    Ok((resp.status, v))
}

impl Echo {
    /// Pairs a fresh echo node through `link`.
    pub async fn pair(link: &PairLink, name: &str) -> Result<Echo, String> {
        let key = NodeKey::generate()?;
        let req = PairRequest {
            code: link.code.clone(),
            name: name.to_string(),
            platform: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
            public_key: key.public_hex(),
        };
        let body = serde_json::to_value(&req).map_err(|e| e.to_string())?;
        let (status, v) = post_pair(&link.center, link.pin.as_deref(), &body).await?;
        if status != 200 {
            return Err(format!("pairing answered {status}: {v}"));
        }
        let resp: PairResponse = serde_json::from_value(v).map_err(|e| e.to_string())?;
        Ok(Echo {
            name: name.to_string(),
            url: link.center.clone(),
            pin: link.pin.clone(),
            center_id: resp.center_id,
            node_id: resp.node_id,
            key,
        })
    }

    /// Opens the link WebSocket, naming `node_id` in the header.
    pub async fn dial(
        &self,
        node_id: &str,
    ) -> Result<Conn<nerve_transport::BoxIo>, nerve_transport::ws::ConnectError> {
        let ws = nerve_transport::ws::connect(
            &self.url,
            self.pin.as_deref(),
            None,
            node_id,
            nerve_proto::limits::MESSAGE_BYTES as usize,
        )
        .await?;
        Ok(Conn::new(ws))
    }

    /// The hello for `challenge`, signed (or with a broken signature).
    pub fn hello(&self, challenge: &Challenge, versions: &[&str], break_sig: bool) -> Value {
        let nonce = msg::unhex(&challenge.nonce).unwrap_or_default();
        let mut sig = self.key.sign_connect(&challenge.center_id, &nonce);
        if break_sig {
            // Flip the first hex digit: still well formed, no longer valid.
            let first = if sig.starts_with('0') { "1" } else { "0" };
            sig.replace_range(0..1, first);
        }
        json!({
            "node_id": self.node_id,
            "auth": {"sig": sig},
            "versions": versions,
            "software": {"name": "nerve-echo", "version": env!("CARGO_PKG_VERSION")},
            "limits": msg::Limits::default(),
            "rev": 1,
        })
    }
}

/// Reads the center's challenge.
pub async fn read_challenge<S: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut Conn<S>,
) -> Result<Challenge, String> {
    match conn.recv(Duration::from_secs(15)).await {
        Recv::Msg(Message::Notification {
            method: m,
            params: p,
        }) if m == method::CHALLENGE => {
            params::<Challenge>(&p).map_err(|e| format!("bad challenge: {}", e.message))
        }
        other => Err(format!("expected a challenge, got {other:?}")),
    }
}

/// Serves the link after `welcome` until it ends; returns the bye reason
/// ("" for a plain close). Every request is answered.
pub async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut Conn<S>,
    descriptor: &Descriptor,
    until: Duration,
) -> String {
    let deadline = tokio::time::Instant::now() + until;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match conn.recv(left).await {
            Recv::Msg(Message::Request {
                id,
                method: m,
                params: p,
            }) => {
                let reply = match handle(&m, &p, descriptor) {
                    Ok(v) => Message::result(id, v),
                    Err(e) => Message::error(Some(id), e),
                };
                if conn.send(&reply).await.is_err() {
                    return String::new();
                }
            }
            Recv::Msg(_) => {}
            Recv::Bye(r) => return r,
            Recv::Closed | Recv::Garbage(_) => return String::new(),
            Recv::Timeout => return "timeout".into(),
        }
    }
}

/// The text `say` fails with `io` on, as a node may fail a call whose
/// arguments fit.
pub const FAIL: &str = "fail";

/// The echo node's answer to one request.
pub fn handle(m: &str, p: &Map<String, Value>, d: &Descriptor) -> Result<Value, RpcError> {
    match m {
        method::DESCRIBE => {
            let req: Describe = params(p)?;
            if req.detail == nerve_proto::Detail::Capability && req.cap.is_none() {
                return Err(RpcError::invalid_args("detail capability needs cap"));
            }
            let out = d
                .at_detail(req.detail, req.cap.as_deref())
                .ok_or_else(|| RpcError::new(ErrorCode::UnknownCapability, "no such capability"))?;
            serde_json::to_value(out).map_err(|e| RpcError::internal(e.to_string()))
        }
        method::INVOKE => {
            let inv: Invoke = params(p)?;
            inv.check()?;
            match (inv.cap.as_str(), inv.action.as_str()) {
                ("echo", "say") | ("mirror", "say" | "set") => {
                    match inv.args.get("text").and_then(Value::as_str) {
                        // A call that fits the schema and still fails on the
                        // node, for the harness part.
                        Some(FAIL) => Err(RpcError::new(
                            ErrorCode::Other("io".into()),
                            "the echo node fails this text on purpose",
                        )),
                        Some(t) if inv.args.len() == 1 => Ok(json!({"text": t})),
                        _ => Err(RpcError::invalid_args("say takes {text}")),
                    }
                }
                ("echo", "fail") => Err(RpcError::new(
                    ErrorCode::Other("io".into()),
                    "the echo node fails this action on purpose",
                )),
                (cap, _) if d.capability(cap).is_none() => Err(RpcError::new(
                    ErrorCode::UnknownCapability,
                    format!("no capability {cap}"),
                )),
                _ => Err(RpcError::new(ErrorCode::UnknownMember, "no such action")),
            }
        }
        method::SUB | method::UNSUB => Ok(json!({})),
        method::GET => Ok(json!({})),
        _ => Err(RpcError::new(
            ErrorCode::MethodNotFound,
            format!("unknown method {m}"),
        )),
    }
}
