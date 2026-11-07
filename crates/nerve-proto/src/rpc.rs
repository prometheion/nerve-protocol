//! JSON-RPC 2.0 envelopes (docs/dev/spec/protocol.md §5). Batches are not used, and
//! `params` is always an object.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{ErrorCode, RpcError};

/// A request id. Nerve sides only send integers; strings are accepted from a
/// peer and echoed back unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Id {
    Num(u64),
    Str(String),
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Id::Num(n) => write!(f, "{n}"),
            Id::Str(s) => write!(f, "{s}"),
        }
    }
}

/// One decoded text frame.
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    Request {
        id: Id,
        method: String,
        params: Map<String, Value>,
    },
    Notification {
        method: String,
        params: Map<String, Value>,
    },
    Result {
        id: Id,
        result: Value,
    },
    Error {
        id: Option<Id>,
        error: RpcError,
    },
}

impl Message {
    pub fn request(id: u64, method: &str, params: Value) -> Message {
        Message::Request {
            id: Id::Num(id),
            method: method.to_string(),
            params: object(params),
        }
    }

    pub fn notification(method: &str, params: Value) -> Message {
        Message::Notification {
            method: method.to_string(),
            params: object(params),
        }
    }

    pub fn result(id: Id, result: Value) -> Message {
        Message::Result { id, result }
    }

    pub fn error(id: Option<Id>, error: RpcError) -> Message {
        Message::Error { id, error }
    }

    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("jsonrpc".into(), Value::String("2.0".into()));
        match self {
            Message::Request { id, method, params } => {
                m.insert("id".into(), serde_json::to_value(id).unwrap_or(Value::Null));
                m.insert("method".into(), Value::String(method.clone()));
                m.insert("params".into(), Value::Object(params.clone()));
            }
            Message::Notification { method, params } => {
                m.insert("method".into(), Value::String(method.clone()));
                m.insert("params".into(), Value::Object(params.clone()));
            }
            Message::Result { id, result } => {
                m.insert("id".into(), serde_json::to_value(id).unwrap_or(Value::Null));
                m.insert("result".into(), result.clone());
            }
            Message::Error { id, error } => {
                m.insert(
                    "id".into(),
                    id.as_ref()
                        .and_then(|i| serde_json::to_value(i).ok())
                        .unwrap_or(Value::Null),
                );
                m.insert(
                    "error".into(),
                    serde_json::to_value(error).unwrap_or(Value::Null),
                );
            }
        }
        Value::Object(m)
    }

    pub fn encode(&self) -> String {
        self.to_value().to_string()
    }

    /// Decodes one text frame. A frame that is not a single JSON-RPC 2.0
    /// object fails with the error to send back (id when one was readable).
    pub fn decode(text: &str) -> Result<Message, Box<Message>> {
        let v: Value = serde_json::from_str(text).map_err(|e| {
            Box::new(Message::error(
                None,
                RpcError::new(ErrorCode::Parse, format!("not JSON: {e}")),
            ))
        })?;
        Message::from_value(v)
    }

    pub fn from_value(v: Value) -> Result<Message, Box<Message>> {
        let bad = |id: Option<Id>, why: &str| {
            Box::new(Message::error(
                id,
                RpcError::new(ErrorCode::InvalidRequest, why.to_string()),
            ))
        };
        let Value::Object(mut m) = v else {
            return Err(bad(None, "a message is one JSON object (no batches)"));
        };
        let id = match m.remove("id") {
            None => None,
            Some(Value::Null) => Some(None),
            Some(v) => match serde_json::from_value::<Id>(v) {
                Ok(i) => Some(Some(i)),
                Err(_) => return Err(bad(None, "id must be a number or a string")),
            },
        };
        let req_id = id.clone().flatten();
        if m.remove("jsonrpc") != Some(Value::String("2.0".into())) {
            return Err(bad(req_id, "jsonrpc must be \"2.0\""));
        }
        if let Some(method) = m.remove("method") {
            let Value::String(method) = method else {
                return Err(bad(req_id, "method must be a string"));
            };
            let params = match m.remove("params") {
                None => Map::new(),
                Some(Value::Object(p)) => p,
                Some(_) => return Err(bad(req_id, "params must be an object")),
            };
            if !m.is_empty() {
                return Err(bad(req_id, "unknown member in request"));
            }
            return Ok(match id {
                None => Message::Notification { method, params },
                Some(Some(id)) => Message::Request { id, method, params },
                Some(None) => return Err(bad(None, "id must not be null")),
            });
        }
        if let Some(result) = m.remove("result") {
            let Some(Some(id)) = id else {
                return Err(bad(None, "a result needs an id"));
            };
            return Ok(Message::Result { id, result });
        }
        if let Some(error) = m.remove("error") {
            let error: RpcError = serde_json::from_value(error)
                .map_err(|_| bad(req_id.clone(), "malformed error object"))?;
            return Ok(Message::Error { id: req_id, error });
        }
        Err(bad(req_id, "neither request, result nor error"))
    }
}

/// `params` must be an object; anything else becomes an empty one, since only
/// this crate's own callers build messages.
fn object(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

/// Parses `params` into `T`, mapping serde's complaints to `invalid_args`.
pub fn params<T: serde::de::DeserializeOwned>(p: &Map<String, Value>) -> Result<T, RpcError> {
    // Read from the map in place: a call's arguments may be megabytes.
    T::deserialize(p).map_err(|e| RpcError::invalid_args(format!("invalid params: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn round_trips() {
        for m in [
            Message::request(7, "describe", json!({"detail": "summary"})),
            Message::notification("bye", json!({"reason": "shutdown"})),
            Message::result(Id::Num(7), json!({"ok": true})),
            Message::error(Some(Id::Str("a".into())), RpcError::forbidden("no")),
        ] {
            assert_eq!(Message::decode(&m.encode()).unwrap(), m);
        }
    }

    #[test]
    fn refuses_batches_and_bad_params() {
        assert!(Message::decode("[]").is_err());
        assert!(Message::decode("{").is_err());
        let e =
            Message::decode(r#"{"jsonrpc":"2.0","id":1,"method":"x","params":[1]}"#).unwrap_err();
        match *e {
            Message::Error { id, error } => {
                assert_eq!(id, Some(Id::Num(1)));
                assert_eq!(error.kind(), ErrorCode::InvalidRequest);
            }
            _ => panic!(),
        }
        assert!(Message::decode(r#"{"jsonrpc":"1.0","method":"x"}"#).is_err());
        assert!(Message::decode(r#"{"jsonrpc":"2.0","method":"x","extra":1}"#).is_err());
    }
}
