//! Errors on the wire: a JSON-RPC numeric code plus a string code in `data.code`
//! (docs/dev/spec/protocol.md §5.3).

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// The codes the profiles add to the core's, carried as `Other`.
pub const PROFILE_CODES: [&str; 3] = ["conflict", "bad_path", "io"];

/// The string codes of the core spec. Profiles add their own (`conflict`,
/// `bad_path`, `io`), carried as `Other`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidArgs,
    Forbidden,
    Disabled,
    Unavailable,
    Busy,
    Timeout,
    Cancelled,
    TooLarge,
    UnknownCapability,
    UnknownMember,
    ConnectionLost,
    Internal,
    /// JSON-RPC's own: the frame was not JSON or not a valid request.
    Parse,
    InvalidRequest,
    MethodNotFound,
    Other(String),
}

impl ErrorCode {
    pub fn as_str(&self) -> &str {
        match self {
            ErrorCode::InvalidArgs => "invalid_args",
            ErrorCode::Forbidden => "forbidden",
            ErrorCode::Disabled => "disabled",
            ErrorCode::Unavailable => "unavailable",
            ErrorCode::Busy => "busy",
            ErrorCode::Timeout => "timeout",
            ErrorCode::Cancelled => "cancelled",
            ErrorCode::TooLarge => "too_large",
            ErrorCode::UnknownCapability => "unknown_capability",
            ErrorCode::UnknownMember => "unknown_member",
            ErrorCode::ConnectionLost => "connection_lost",
            ErrorCode::Internal => "internal",
            ErrorCode::Parse => "parse_error",
            ErrorCode::InvalidRequest => "invalid_request",
            ErrorCode::MethodNotFound => "method_not_found",
            ErrorCode::Other(s) => s,
        }
    }

    pub fn parse(s: &str) -> ErrorCode {
        match s {
            "invalid_args" => ErrorCode::InvalidArgs,
            "forbidden" => ErrorCode::Forbidden,
            "disabled" => ErrorCode::Disabled,
            "unavailable" => ErrorCode::Unavailable,
            "busy" => ErrorCode::Busy,
            "timeout" => ErrorCode::Timeout,
            "cancelled" => ErrorCode::Cancelled,
            "too_large" => ErrorCode::TooLarge,
            "unknown_capability" => ErrorCode::UnknownCapability,
            "unknown_member" => ErrorCode::UnknownMember,
            "connection_lost" => ErrorCode::ConnectionLost,
            "internal" => ErrorCode::Internal,
            "parse_error" => ErrorCode::Parse,
            "invalid_request" => ErrorCode::InvalidRequest,
            "method_not_found" => ErrorCode::MethodNotFound,
            other => ErrorCode::Other(other.to_string()),
        }
    }

    /// The JSON-RPC numeric code for this string code.
    pub fn numeric(&self) -> i64 {
        match self {
            ErrorCode::Parse => -32700,
            ErrorCode::InvalidRequest => -32600,
            ErrorCode::MethodNotFound => -32601,
            ErrorCode::InvalidArgs => -32602,
            ErrorCode::Internal => -32603,
            ErrorCode::Forbidden => -32001,
            ErrorCode::Disabled => -32004,
            ErrorCode::Unavailable => -32005,
            ErrorCode::Busy => -32006,
            ErrorCode::Timeout => -32007,
            ErrorCode::Cancelled => -32008,
            ErrorCode::TooLarge => -32009,
            ErrorCode::UnknownCapability => -32010,
            ErrorCode::UnknownMember => -32011,
            ErrorCode::ConnectionLost => -32012,
            ErrorCode::Other(_) => -32000,
        }
    }

    /// Whether this is a code of the protocol, the core's or a profile's
    /// (`PROFILE_CODES`), not one a peer made up.
    pub fn is_protocol(&self) -> bool {
        match self {
            ErrorCode::Other(c) => PROFILE_CODES.contains(&c.as_str()),
            _ => true,
        }
    }

    /// Whether a harness may simply try again.
    pub fn retryable(&self) -> bool {
        matches!(
            self,
            ErrorCode::ConnectionLost | ErrorCode::Busy | ErrorCode::Unavailable
        )
    }
}

/// The `error` member of a JSON-RPC response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl RpcError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> RpcError {
        let mut data = Map::new();
        data.insert("code".into(), Value::String(code.as_str().to_string()));
        RpcError {
            code: code.numeric(),
            message: message.into(),
            data: Some(Value::Object(data)),
        }
    }

    /// Adds a member to `data` (next to `code`).
    pub fn with(mut self, key: &str, value: Value) -> RpcError {
        if let Some(Value::Object(m)) = &mut self.data {
            m.insert(key.to_string(), value);
        }
        self
    }

    /// The string code, from `data.code` or, failing that, the numeric code.
    pub fn kind(&self) -> ErrorCode {
        if let Some(c) = self
            .data
            .as_ref()
            .and_then(|d| d.get("code"))
            .and_then(Value::as_str)
        {
            return ErrorCode::parse(c);
        }
        match self.code {
            -32700 => ErrorCode::Parse,
            -32600 => ErrorCode::InvalidRequest,
            -32601 => ErrorCode::MethodNotFound,
            -32602 => ErrorCode::InvalidArgs,
            _ => ErrorCode::Internal,
        }
    }

    pub fn invalid_args(msg: impl Into<String>) -> RpcError {
        RpcError::new(ErrorCode::InvalidArgs, msg)
    }
    pub fn forbidden(msg: impl Into<String>) -> RpcError {
        RpcError::new(ErrorCode::Forbidden, msg)
    }
    pub fn internal(msg: impl Into<String>) -> RpcError {
        RpcError::new(ErrorCode::Internal, msg)
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.kind().as_str())
    }
}

impl std::error::Error for RpcError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip() {
        for c in [
            ErrorCode::InvalidArgs,
            ErrorCode::ConnectionLost,
            ErrorCode::Other("conflict".into()),
        ] {
            let e = RpcError::new(c.clone(), "x");
            assert_eq!(e.kind(), c);
        }
        assert!(ErrorCode::Other("io".into()).is_protocol());
        assert!(ErrorCode::Forbidden.is_protocol());
        assert!(!ErrorCode::Other("list_first".into()).is_protocol());
        assert!(ErrorCode::ConnectionLost.retryable());
        assert!(!ErrorCode::Forbidden.retryable());
    }
}
