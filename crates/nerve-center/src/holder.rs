//! Who listens where the installed center's web UI should be, asked before
//! a program of this machine sends the owner token there (the desktop app's
//! log-in, docs/dev/web-uis.md): every listener there must be the center's
//! service, the `nerve-center` account's socket on Linux, the service
//! `nerve-center`'s process on Windows ([`nerve_service::holder`]).

use std::net::SocketAddr;

pub use nerve_service::holder::Holder;

/// The center's service, as [`nerve_service::holder`] asks for it.
pub const SERVICE: nerve_service::holder::Service<'static> = nerve_service::holder::Service {
    account: crate::service::USER,
    name: crate::winsvc::SERVICE_NAME,
};

/// Who holds `at` on this machine now.
pub fn of(at: SocketAddr) -> Result<Holder, String> {
    nerve_service::holder::of(at, SERVICE)
}

/// [`of`], as a check: an error that says what holds `at` unless it is the
/// center's service.
pub fn check(at: SocketAddr) -> Result<(), String> {
    match of(at)? {
        Holder::Service => Ok(()),
        Holder::Nobody => Err(NOT_RUNNING.into()),
        Holder::Other => Err(format!(
            "another program listens on {at}, not the center's service: the owner token is not sent there"
        )),
    }
}

/// What [`check`] says when nobody listens.
pub const NOT_RUNNING: &str = "the center is not running";
