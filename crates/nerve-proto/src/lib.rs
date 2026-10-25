//! Types and codecs of the Nerve Protocol (docs/dev/spec/), without any I/O.
//!
//! Everything a node, a center or a harness binding puts on the wire is defined
//! here once, so both ends of a link share one definition. Parameters a center
//! sends to a node are parsed strictly (unknown fields are errors, spec D2);
//! data a node sends is read tolerantly, since a center must accept newer minor
//! versions and `x-` members.
//!
//! The crate only depends on `serde` and `serde_json`. It is not built as
//! `no_std`; nothing in it needs more than `alloc`, so that can follow
//! when a constrained node exists.

pub mod base32;
pub mod descriptor;
pub mod error;
pub mod frame;
pub mod link;
pub mod msg;
pub mod resume;
pub mod rpc;
pub mod schema;

pub use descriptor::{Capability, Descriptor, Detail, Effect, Exposure};
pub use error::{ErrorCode, RpcError};
pub use rpc::{Id, Message};
pub use schema::{ArgError, Role, SchemaError};

/// The protocol version of all of 0.0.x and 0.x (docs/dev/spec/protocol.md §1).
pub const PROTOCOL_VERSION: &str = "0";

/// The HTTP path a node pairs on.
pub const PAIR_PATH: &str = "/nerve/v0/pair";
/// The HTTP path a node asks on whether a pairing code is still open,
/// without using it (docs/dev/spec/protocol.md §3.2).
pub const PAIR_CHECK_PATH: &str = "/nerve/v0/pair/check";
/// The HTTP path a node opens its WebSocket link on.
pub const CONNECT_PATH: &str = "/nerve/v0/connect";
/// The upgrade header that names the node on `CONNECT_PATH`.
pub const NODE_HEADER: &str = "Nerve-Node";
/// What the node signs before the center id and the nonce.
pub const CONNECT_CONTEXT: &[u8] = b"nerve-connect/0";

/// The bytes a node signs to answer a challenge:
/// `"nerve-connect/0" || center_id || nonce`.
pub fn connect_message(center_id: &str, nonce: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(CONNECT_CONTEXT.len() + center_id.len() + nonce.len());
    m.extend_from_slice(CONNECT_CONTEXT);
    m.extend_from_slice(center_id.as_bytes());
    m.extend_from_slice(nonce);
    m
}

/// The feature of key rotation (docs/dev/spec/protocol.md §1.1, §4.10), named
/// in `hello.features` and `welcome.features`.
pub const FEATURE_ROTATE: &str = "rotate";
/// The features this implementation speaks.
pub const FEATURES: &[&str] = &[FEATURE_ROTATE];

/// How long a replaced key stays valid after a rotation (§4.10): seven days.
pub const ROTATE_GRACE_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// What the replaced node key signs before the center id and the new key.
pub const ROTATE_NODE_CONTEXT: &[u8] = b"nerve-rotate-node/0";
/// What the node's current key signs to end the grace of its old key.
pub const RETIRE_NODE_CONTEXT: &[u8] = b"nerve-retire-node/0";
/// What the center's old key signs before the center id and the new pin.
pub const ROTATE_CENTER_CONTEXT: &[u8] = b"nerve-rotate-center/0";

fn signed(context: &[u8], center_id: &str, tail: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(context.len() + center_id.len() + tail.len());
    m.extend_from_slice(context);
    m.extend_from_slice(center_id.as_bytes());
    m.extend_from_slice(tail);
    m
}

/// The bytes both node keys sign in `key.rotate`:
/// `"nerve-rotate-node/0" || center_id || new public key (32 raw bytes)`.
pub fn rotate_node_message(center_id: &str, new_key: &[u8]) -> Vec<u8> {
    signed(ROTATE_NODE_CONTEXT, center_id, new_key)
}

/// The bytes the node's current key signs in `key.retire`:
/// `"nerve-retire-node/0" || center_id || that current public key (32 raw
/// bytes)`.
pub fn retire_node_message(center_id: &str, current_key: &[u8]) -> Vec<u8> {
    signed(RETIRE_NODE_CONTEXT, center_id, current_key)
}

/// The bytes the center's old key signs in `center.rotate`:
/// `"nerve-rotate-center/0" || center_id || the new pin (its 32 raw bytes)`.
pub fn rotate_center_message(center_id: &str, new_pin: &[u8]) -> Vec<u8> {
    signed(ROTATE_CENTER_CONTEXT, center_id, new_pin)
}

/// Default limits (docs/dev/spec/protocol.md §5.5): what a side receives unless it
/// announces otherwise.
pub mod limits {
    pub const MESSAGE_BYTES: u64 = 4 * 1024 * 1024;
    pub const BLOB_BYTES: u64 = 64 * 1024 * 1024;
    pub const CALLS: u32 = 64;
    pub const STREAMS: u32 = 16;
    /// Frames each side queues before a reliable stream waits.
    pub const SEND_QUEUE: usize = 64;
}

/// Node names: 1 to 32 of `a-z0-9-`, starting and ending with a letter or
/// digit like a DNS label (docs/dev/spec/protocol.md §2.2). A name that
/// starts with `-` would read as a flag wherever a command line takes it.
pub fn valid_node_name(name: &str) -> bool {
    let edge = |b: Option<&u8>| b.is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    (1..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && edge(name.as_bytes().first())
        && edge(name.as_bytes().last())
}

/// A node name made from a host name: lowercased, other characters as `-`,
/// cut to 32; `node` when nothing is left.
pub fn node_name_from_host(host: &str) -> String {
    let mut s: String = host
        .chars()
        .map(|c| c.to_ascii_lowercase())
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() {
                c
            } else {
                '-'
            }
        })
        .collect();
    s.truncate(32);
    let s = s.trim_matches('-').to_string();
    if s.is_empty() { "node".into() } else { s }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_names() {
        assert!(valid_node_name("laptop-2"));
        assert!(!valid_node_name(""));
        assert!(!valid_node_name("Laptop"));
        assert!(!valid_node_name(&"a".repeat(33)));
        assert!(valid_node_name("a"));
        assert!(valid_node_name("2lab"));
        for bad in ["-", "-lab", "lab-", "-lab-", "--", "-x"] {
            assert!(!valid_node_name(bad), "{bad}");
        }
        assert_eq!(node_name_from_host("My.Host_01"), "my-host-01");
        assert_eq!(node_name_from_host("..."), "node");
    }

    #[test]
    fn connect_message_layout() {
        let m = connect_message("c1", &[1, 2]);
        assert_eq!(m, b"nerve-connect/0c1\x01\x02");
    }

    #[test]
    fn rotation_message_layouts() {
        assert_eq!(
            rotate_node_message("c1", &[7]),
            b"nerve-rotate-node/0c1\x07"
        );
        assert_eq!(
            retire_node_message("c1", &[7]),
            b"nerve-retire-node/0c1\x07"
        );
        assert_eq!(
            rotate_center_message("c1", &[7]),
            b"nerve-rotate-center/0c1\x07"
        );
        assert_eq!(ROTATE_GRACE_MS, 604_800_000);
    }
}
