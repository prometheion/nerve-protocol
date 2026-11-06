//! Transport of the Nerve Protocol: TLS with certificate pinning, the loopback
//! rule for plain HTTP, `CONNECT` proxies, the WebSocket under the node link,
//! the node's Ed25519 identity, the sealed sudo password, a small HTTP/1.1 server side, local control
//! sockets, the backup file, the log both programs write and the parts both web UIs share. Shared by `nerve-node` and `nerve-center`.

pub mod backoff;
pub mod backup;
pub mod ctl;
pub mod download;
pub mod files;
#[cfg(test)]
mod guide_ref;
pub mod http;
pub mod keys;
pub mod log;
pub mod net;
#[cfg(target_os = "linux")]
pub mod peer;
pub mod sudo;
pub mod tls;
pub mod webui;
pub mod ws;

pub use net::{BoxIo, Proxy};

/// Installs ring as rustls' process-wide crypto provider. Every config this
/// crate builds names its provider itself; this covers code that does not.
pub fn init_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
