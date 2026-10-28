//! Typed `params` of the node link's methods (docs/dev/spec/protocol.md §4, §5).
//!
//! What a center sends to a node is parsed with `deny_unknown_fields`: a node
//! acts on these, so a field it does not understand is an error rather than
//! something it silently ignores (D2). What a node sends to a center is read
//! tolerantly.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::descriptor::Detail;

/// Method names, in one place so both ends spell them the same.
pub mod method {
    pub const CHALLENGE: &str = "challenge";
    pub const HELLO: &str = "hello";
    pub const WELCOME: &str = "welcome";
    pub const DESCRIBE: &str = "describe";
    pub const INVOKE: &str = "invoke";
    pub const PROGRESS: &str = "progress";
    pub const CANCEL: &str = "cancel";
    pub const GET: &str = "get";
    pub const SUB: &str = "sub";
    pub const UNSUB: &str = "unsub";
    pub const EVENT: &str = "event";
    pub const STATE: &str = "state";
    pub const STREAM_OPEN: &str = "stream.open";
    pub const STREAM_CLOSE: &str = "stream.close";
    pub const SESSION_END: &str = "session.end";
    pub const BYE: &str = "bye";
    // Key rotation (§4.10), only between sides that both name the feature
    // `rotate`.
    pub const KEY_ROTATE: &str = "key.rotate";
    pub const KEY_ROTATED: &str = "key.rotated";
    pub const KEY_RETIRE: &str = "key.retire";
    pub const KEY_RETIRED: &str = "key.retired";
    pub const CENTER_ROTATE: &str = "center.rotate";
    pub const ACK: &str = "ack";
    pub const WITHDRAWN: &str = "withdrawn";
}

/// Limits a side announces for what it receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    #[serde(default = "d_message")]
    pub message_bytes: u64,
    #[serde(default = "d_blob")]
    pub blob_bytes: u64,
    #[serde(default = "d_calls")]
    pub calls: u32,
    #[serde(default = "d_streams")]
    pub streams: u32,
}

fn d_message() -> u64 {
    crate::limits::MESSAGE_BYTES
}
fn d_blob() -> u64 {
    crate::limits::BLOB_BYTES
}
fn d_calls() -> u32 {
    crate::limits::CALLS
}
fn d_streams() -> u32 {
    crate::limits::STREAMS
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            message_bytes: d_message(),
            blob_bytes: d_blob(),
            calls: d_calls(),
            streams: d_streams(),
        }
    }
}

/// The center's first frame.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    /// 32 random bytes, lowercase hex.
    pub nonce: String,
    pub center_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Software {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Auth {
    /// Ed25519 signature over `connect_message(center_id, nonce)`, lowercase hex.
    pub sig: String,
}

/// The node's answer to the challenge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hello {
    pub node_id: String,
    pub auth: Auth,
    /// Protocol versions the node speaks; only "0" is known.
    pub versions: Vec<String>,
    pub software: Software,
    #[serde(default)]
    pub limits: Limits,
    /// The descriptor revision the node will describe.
    pub rev: u64,
    /// Additive features the node speaks (§1.1). Left out by nodes older
    /// than features.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    /// The link this connection carries, for a node that can resume links
    /// (§4.9).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume: Option<Resume>,
}

/// `hello.resume`: the id of the link the node wants to carry on (or a new
/// one), and how many counted frames it read of it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Resume {
    pub link: String,
    pub got: u64,
}

/// `welcome.resume`: whether the center carries on the link the node named,
/// and how many counted frames of it the center read. Sent only to a node
/// whose hello had `resume`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resumed {
    pub resumed: bool,
    pub got: u64,
}

/// `ack {got}`: the sender read the first `got` counted frames of the link.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ack {
    pub got: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Welcome {
    pub version: String,
    #[serde(default)]
    pub limits: Limits,
    /// The features of the hello the center speaks too. Sent only to a node
    /// whose hello named features: an older node refuses the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub features: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume: Option<Resumed>,
}

/// `key.rotate` (node → center): the node's new key for this center, signed
/// by the key it replaces (`sig`) and by itself (`proof`), both over
/// [`crate::rotate_node_message`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyRotate {
    /// The new Ed25519 public key, 64 lowercase hex characters.
    pub public_key: String,
    pub sig: String,
    pub proof: String,
}

/// `key.rotated` (center → node): the answer to `key.rotate`. Without
/// `error` the center takes `public_key` as the node's key from now on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRotated {
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `key.retire` (node → center): ends the grace of the node's old key now,
/// signed by its current key over [`crate::retire_node_message`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyRetire {
    /// The node's current public key, which signs, hex.
    pub public_key: String,
    pub sig: String,
}

/// `key.retired` (center → node): the answer to `key.retire`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRetired {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `center.rotate` (center → node): the center's new TLS key, signed by the
/// old one. The keys are their SubjectPublicKeyInfo in DER, base64url
/// without padding; `sig` is the old key's signature over
/// [`crate::rotate_center_message`], base64url too.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CenterRotate {
    pub old_spki: String,
    pub new_spki: String,
    pub sig: String,
    /// How long the center still serves the old key, in milliseconds; 0
    /// once it serves the new one.
    pub grace_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Describe {
    #[serde(default)]
    pub detail: Detail,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<String>,
}

/// Context a center attaches to a call: the session id and nothing else.
/// Other fields are refused (D8).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ctx {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
}

/// The longest session id a node accepts.
pub const SESSION_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invoke {
    pub cap: String,
    pub action: String,
    #[serde(default)]
    pub args: Map<String, Value>,
    #[serde(default)]
    pub ctx: Ctx,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,
    /// Blob ids this call's arguments reference, sent as binary frames first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blobs: Vec<u32>,
}

impl Invoke {
    /// Checks what serde cannot: the session's length.
    pub fn check(&self) -> Result<(), crate::RpcError> {
        check_session(&self.ctx)
    }
}

fn check_session(ctx: &Ctx) -> Result<(), crate::RpcError> {
    if let Some(s) = &ctx.session
        && (s.is_empty() || s.len() > SESSION_BYTES)
    {
        return Err(crate::RpcError::invalid_args(
            "ctx.session must be 1 to 256 bytes",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Progress {
    pub id: Value,
    pub data: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cancel {
    pub id: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Get {
    pub cap: String,
    #[serde(default)]
    pub keys: Vec<String>,
    /// The session that reads, for the audit of a program's state.
    #[serde(default)]
    pub ctx: Ctx,
}

impl Get {
    /// Checks what serde cannot: the session's length.
    pub fn check(&self) -> Result<(), crate::RpcError> {
        check_session(&self.ctx)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Topics {
    pub topics: Vec<String>,
    /// The session that subscribes, for the audit of a program's events.
    #[serde(default)]
    pub ctx: Ctx,
}

impl Topics {
    /// Checks what serde cannot: the session's length.
    pub fn check(&self) -> Result<(), crate::RpcError> {
        check_session(&self.ctx)
    }
}

/// A parsed topic: `<cap>/<event>`, `<cap>/state` or `<cap>/*`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Topic {
    Event(String, String),
    State(String),
    All(String),
}

impl Topic {
    pub fn parse(s: &str) -> Option<Topic> {
        let (cap, rest) = s.split_once('/')?;
        if cap.is_empty() || rest.is_empty() || rest.contains('/') {
            return None;
        }
        Some(match rest {
            "state" => Topic::State(cap.into()),
            "*" => Topic::All(cap.into()),
            e => Topic::Event(cap.into(), e.into()),
        })
    }

    pub fn cap(&self) -> &str {
        match self {
            Topic::Event(c, _) | Topic::State(c) | Topic::All(c) => c,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub cap: String,
    pub name: String,
    pub seq: u64,
    /// Milliseconds since the Unix epoch.
    pub ts: u64,
    #[serde(default)]
    pub data: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateChange {
    pub cap: String,
    pub seq: u64,
    pub ts: u64,
    pub changed: Map<String, Value>,
}

/// `stream.open`: the stream `stream` of the capability `cap`, for the harness
/// session in `ctx`. A node serves a stream of a call (`exec`'s `output`)
/// only to the session the call came from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamOpen {
    pub cap: String,
    pub stream: String,
    #[serde(default)]
    pub params: Map<String, Value>,
    #[serde(default)]
    pub ctx: Ctx,
}

impl StreamOpen {
    /// Checks what serde cannot: the session's length, as for `invoke`.
    pub fn check(&self) -> Result<(), crate::RpcError> {
        check_session(&self.ctx)
    }
}

/// `stream.close`, either way. A node reads it strictly, like everything a
/// center sends; a center reads a node's tolerantly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamClose {
    pub sid: u32,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionEnd {
    pub session: String,
}

/// Why a side closes the link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ByeReason {
    Shutdown,
    Paused,
    Unpaired,
    Revoked,
    Duplicate,
    Replaced,
    UnsupportedVersion,
    ProtocolError,
}

impl ByeReason {
    /// Whether a node stops dialling this center after the bye.
    pub fn stops_node(self) -> bool {
        matches!(
            self,
            ByeReason::Revoked | ByeReason::Unpaired | ByeReason::UnsupportedVersion
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ByeReason::Shutdown => "shutdown",
            ByeReason::Paused => "paused",
            ByeReason::Unpaired => "unpaired",
            ByeReason::Revoked => "revoked",
            ByeReason::Duplicate => "duplicate",
            ByeReason::Replaced => "replaced",
            ByeReason::UnsupportedVersion => "unsupported_version",
            ByeReason::ProtocolError => "protocol_error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bye {
    pub reason: ByeReason,
}

/// Lowercase hex, for nonces and signatures.
pub fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 15) as usize] as char);
    }
    s
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let v = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    s.as_bytes()
        .chunks(2)
        .map(|p| Some(v(p[0])? << 4 | v(p[1])?))
        .collect()
}

/// Milliseconds since the Unix epoch, for `ts`.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn invoke_is_strict() {
        let ok: Invoke = serde_json::from_value(json!({
            "cap": "fs", "action": "read", "args": {"path": "/x"},
            "ctx": {"session": "s1"}
        }))
        .unwrap();
        assert_eq!(ok.ctx.session.as_deref(), Some("s1"));
        assert!(ok.check().is_ok());
        assert!(
            serde_json::from_value::<Invoke>(json!({
                "cap": "fs", "action": "read", "ctx": {"mode": "full"}
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<Invoke>(json!({"cap": "fs", "action": "read", "x": 1}))
                .is_err()
        );
        let long = Invoke {
            ctx: Ctx {
                session: Some("s".repeat(257)),
            },
            ..ok
        };
        assert!(long.check().is_err());
    }

    /// `stream.open` names the session it is for, in a `ctx` as strict as
    /// `invoke`'s.
    #[test]
    fn stream_open_is_strict() {
        let ok: StreamOpen = serde_json::from_value(json!({
            "cap": "exec", "stream": "output", "params": {"call": 3},
            "ctx": {"session": "s1"}
        }))
        .unwrap();
        assert_eq!(ok.ctx.session.as_deref(), Some("s1"));
        assert!(ok.check().is_ok());
        for bad in [
            json!({"cap": "exec", "stream": "output", "ctx": {"session": "s1", "mode": "full"}}),
            json!({"cap": "exec", "stream": "output", "x": 1}),
        ] {
            assert!(serde_json::from_value::<StreamOpen>(bad).is_err());
        }
        let long = StreamOpen {
            ctx: Ctx {
                session: Some("s".repeat(257)),
            },
            ..ok
        };
        assert!(long.check().is_err());
        assert!(
            serde_json::from_value::<StreamClose>(json!({"sid": 1, "reason": "x", "y": 2}))
                .is_err()
        );
    }

    /// `get` and `sub` carry the session that reads or subscribes, as
    /// strictly as `invoke` does.
    #[test]
    fn get_and_sub_take_a_session() {
        let g: Get = serde_json::from_value(
            json!({"cap": "sensors", "keys": ["temp"], "ctx": {"session": "s1"}}),
        )
        .unwrap();
        assert_eq!(g.ctx.session.as_deref(), Some("s1"));
        assert!(g.check().is_ok());
        let t: Topics =
            serde_json::from_value(json!({"topics": ["sensors/alarm"], "ctx": {"session": "s1"}}))
                .unwrap();
        assert!(t.check().is_ok());
        assert!(
            serde_json::from_value::<Get>(json!({"cap": "x", "ctx": {"mode": "full"}})).is_err()
        );
        assert!(
            serde_json::from_value::<Topics>(json!({"topics": [], "ctx": {}, "x": 1})).is_err()
        );
        let long = Ctx {
            session: Some("s".repeat(257)),
        };
        assert!(
            Get {
                ctx: long.clone(),
                ..g
            }
            .check()
            .is_err()
        );
        assert!(Topics { ctx: long, ..t }.check().is_err());
    }

    #[test]
    fn hello_is_tolerant() {
        let h: Hello = serde_json::from_value(json!({
            "node_id": "n", "auth": {"sig": "00"}, "versions": ["0"],
            "software": {"name": "x", "version": "1"}, "rev": 1, "x-extra": true
        }))
        .unwrap();
        assert_eq!(h.limits, Limits::default());
    }

    #[test]
    fn features_are_additive() {
        // A hello without features (an older node) reads as none.
        let h: Hello = serde_json::from_value(json!({
            "node_id": "n", "auth": {"sig": "00"}, "versions": ["0"],
            "software": {"name": "x", "version": "1"}, "rev": 1
        }))
        .unwrap();
        assert!(h.features.is_empty());
        assert!(serde_json::to_value(&h).unwrap().get("features").is_none());
        // A welcome names them only for a node that asked; the node stays
        // strict about anything else.
        let w = Welcome {
            version: "0".into(),
            limits: Limits::default(),
            features: None,
            resume: None,
        };
        assert!(serde_json::to_value(&w).unwrap().get("features").is_none());
        let w: Welcome =
            serde_json::from_value(json!({"version": "0", "features": ["rotate"]})).unwrap();
        assert_eq!(w.features, Some(vec!["rotate".to_string()]));
        assert!(serde_json::from_value::<Welcome>(json!({"version": "0", "x": 1})).is_err());
        // What a center sends about keys is strict too.
        assert!(
            serde_json::from_value::<CenterRotate>(json!({
                "old_spki": "a", "new_spki": "b", "sig": "c", "grace_ms": 1, "pin": "d"
            }))
            .is_err()
        );
        assert!(serde_json::from_value::<KeyRotated>(json!({"public_key": "a", "x": 1})).is_err());
    }

    #[test]
    fn topics() {
        assert_eq!(
            Topic::parse("exec/exit"),
            Some(Topic::Event("exec".into(), "exit".into()))
        );
        assert_eq!(
            Topic::parse("node/state"),
            Some(Topic::State("node".into()))
        );
        assert_eq!(Topic::parse("fs/*"), Some(Topic::All("fs".into())));
        assert_eq!(Topic::parse("fs"), None);
        assert_eq!(Topic::parse("a/b/c"), None);
    }

    #[test]
    fn hex_round_trip() {
        assert_eq!(hex(&[0, 255, 16]), "00ff10");
        assert_eq!(unhex("00ff10"), Some(vec![0, 255, 16]));
        assert_eq!(unhex("0"), None);
        assert_eq!(unhex("zz"), None);
    }

    #[test]
    fn bye_reasons() {
        let b: Bye = serde_json::from_value(json!({"reason": "unsupported_version"})).unwrap();
        assert!(b.reason.stops_node());
        assert!(!ByeReason::Shutdown.stops_node());
    }
}
