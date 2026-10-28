//! The echo node: the smallest node that follows the protocol. It offers the
//! built-in `node` capability and one `echo` capability, and
//! the center part of the conformance suite drives a center with it.

use std::time::Duration;

use serde_json::{Map, Value, json};
use tokio::io::{AsyncRead, AsyncWrite};

use nerve_proto::link::{CenterUrl, PairLink, PairRequest, PairResponse};
use nerve_proto::msg::{self, Challenge, Describe, Invoke, StreamClose, StreamOpen, method};
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
             "events": {"descriptor_changed": {"effect": "read", "implicit": true},
                        "going_away": {"effect": "read", "implicit": true}}},
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

/// The program's capability the harness nodes offer.
pub const GAUGE: &str = "gauge";
/// The value of its state key `level`.
pub const GAUGE_LEVEL: i64 = 7;
/// How many events a subscription to `gauge/tick` gets at once.
pub const GAUGE_TICKS: u64 = 2;

/// The longest `echo.wait` of the harness nodes, in milliseconds.
pub const WAIT_MAX_MS: u64 = 600_000;

/// The account the harness nodes say their commands run as.
pub const ACCESS_ACCOUNT: &str = "conformance-run";
/// The folder the harness nodes say the center may read and write.
pub const ACCESS_FOLDER: &str = "/conformance/work";

/// The descriptor the harness part's nodes offer: the echo node's with
/// `echo.wait`, which answers late, plus `mirror`, an `echo` twin with a
/// write action, and actions of `node`, `settings` and `audit`, which a
/// center must never offer a harness.
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
    // A call that takes as long as it is asked to, so that a center's call
    // wait runs out and the call becomes a job (harness.md §4.4).
    caps[1]["actions"]["wait"] = json!({"effect": "read",
        "summary": "Answer after ms milliseconds.",
        "params": {"type": "object",
                   "properties": {"ms": {"type": "integer", "minimum": 0, "maximum": WAIT_MAX_MS}},
                   "required": ["ms"], "additionalProperties": false},
        "result": {"type": "object", "properties": {"waited": {"type": "integer"}}}});
    // A result that is a string, the node's own lines, which a center puts
    // into its framing by lines (harness.md §4.3).
    let mut lines = say.clone();
    lines["summary"] = json!("Return the text as a string.");
    lines["result"] = json!({"type": "string"});
    caps[1]["actions"]["lines"] = lines;
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
    // A program's capability (node-local.md §7): a state key, an event and
    // a stream, each a unit of its own to the harness (harness.md §4.5).
    caps.push(
        json!({"id": GAUGE, "provider": "conformance-program", "exposure": "on",
        "summary": "A program's gauge.",
        "state": {"level": {"effect": "read", "summary": "Its level now.",
                            "schema": {"type": "integer"}}},
        "events": {"tick": {"effect": "read", "summary": "It ticked.",
                            "data": {"type": "object", "properties": {"n": {"type": "integer"}}}}},
        "streams": {"feed": {"kind": "reliable", "direction": "up", "effect": "read",
                             "summary": "Its readings as they come.",
                             "params": {"type": "object", "properties": {
                                 "lines": {"type": "integer", "minimum": 1, "maximum": 9}},
                                 "required": ["lines"], "additionalProperties": false}}}}),
    );
    // What the center may do there (§6.2), which `list(node)` tells.
    d["access"] = json!({"mode": "folder", "account": ACCESS_ACCOUNT,
        "folders": [{"path": ACCESS_FOLDER, "access": "rw"}]});
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
            Recv::Msg(_) | Recv::Frame(_) => {}
            Recv::Bye(r) => return r,
            Recv::Closed | Recv::Garbage(_) => return String::new(),
            Recv::Timeout => return "timeout".into(),
        }
    }
}

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
                        Some(t) if inv.args.len() == 1 => Ok(json!({"text": t})),
                        _ => Err(RpcError::invalid_args("say takes {text}")),
                    }
                }
                // The harness part's node answers it later; here it is
                // answered at once.
                ("echo", "wait")
                    if d.capability("echo")
                        .is_some_and(|c| c.actions.contains_key("wait")) =>
                {
                    match inv.args.get("ms").and_then(Value::as_u64) {
                        Some(ms) if inv.args.len() == 1 && ms <= WAIT_MAX_MS => {
                            Ok(json!({"waited": ms}))
                        }
                        _ => Err(RpcError::invalid_args("wait takes {ms}")),
                    }
                }
                ("echo", "lines")
                    if d.capability("echo")
                        .is_some_and(|c| c.actions.contains_key("lines")) =>
                {
                    match inv.args.get("text").and_then(Value::as_str) {
                        Some(t) if inv.args.len() == 1 => Ok(json!(t)),
                        _ => Err(RpcError::invalid_args("lines takes {text}")),
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
        // The echo node offers no streams, but reads the request as
        // strictly as a node must.
        method::STREAM_OPEN => {
            let o: StreamOpen = params(p)?;
            o.check()?;
            Err(match d.capability(&o.cap) {
                None => RpcError::new(
                    ErrorCode::UnknownCapability,
                    format!("no capability {}", o.cap),
                ),
                Some(_) => RpcError::new(ErrorCode::UnknownMember, "no such stream"),
            })
        }
        method::STREAM_CLOSE => {
            let _: StreamClose = params(p)?;
            Err(RpcError::new(ErrorCode::UnknownMember, "no such stream"))
        }
        _ => Err(RpcError::new(
            ErrorCode::MethodNotFound,
            format!("unknown method {m}"),
        )),
    }
}
