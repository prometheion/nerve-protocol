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
    verdict(of(at)?, at)
}

/// What `holder` of `at` allows: only the center's service.
fn verdict(holder: Holder, at: SocketAddr) -> Result<(), String> {
    match holder {
        Holder::Service => Ok(()),
        Holder::Nobody => Err(NOT_RUNNING.into()),
        Holder::Other => Err(format!(
            "another program listens on {at}, not the center's service: the owner token is not sent there"
        )),
    }
}

/// The address a program of this machine opens the center's web UI at, from
/// what the center's address file says, once `held` says the center's
/// service holds the port there.
pub fn open_target(
    said: &crate::ui_file::UiAddress,
    held: impl FnOnce(SocketAddr) -> Result<Holder, String>,
) -> Result<String, String> {
    let url = said.url.clone().ok_or("The center's web UI is off.")?;
    let at: SocketAddr = url
        .split_once("://")
        .map(|(_, a)| a)
        .unwrap_or_default()
        .parse()
        .map_err(|_| format!("{url} names no address"))?;
    verdict(held(at)?, at)?;
    Ok(url)
}

/// What [`check`] says when nobody listens.
pub const NOT_RUNNING: &str = "the center is not running";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui_file::UiAddress;

    fn on(at: &str, pin: Option<&str>) -> UiAddress {
        UiAddress::of(Some(at.parse().unwrap()), pin.map(String::from))
    }

    #[test]
    fn the_web_ui_opens_only_where_the_center_s_service_holds_the_port() {
        let said = on("127.0.0.1:7480", None);
        let by = |h: Holder| move |_| Ok(h);
        assert_eq!(
            open_target(&said, by(Holder::Service)).as_deref(),
            Ok("http://127.0.0.1:7480")
        );
        assert_eq!(
            open_target(&said, by(Holder::Nobody)),
            Err(NOT_RUNNING.to_string())
        );
        let other = open_target(&said, by(Holder::Other)).unwrap_err();
        assert!(other.contains("not the center's service"), "{other}");
        assert!(open_target(&said, |_| Err("no".into())).is_err());
    }

    #[test]
    fn the_web_ui_of_a_center_that_is_off_opens_nowhere() {
        let off = UiAddress::of(None, None);
        let asked = std::cell::Cell::new(false);
        let said = open_target(&off, |_| {
            asked.set(true);
            Ok(Holder::Service)
        });
        assert!(said.is_err() && !asked.get());
        // A wide address is asked for, and opened over TLS, on loopback.
        let wide = on("0.0.0.0:7480", Some("pin"));
        let at = std::cell::Cell::new(None);
        let url = open_target(&wide, |a| {
            at.set(Some(a));
            Ok(Holder::Service)
        });
        assert_eq!(url.as_deref(), Ok("https://127.0.0.1:7480"));
        assert_eq!(at.get(), Some("127.0.0.1:7480".parse().unwrap()));
    }
}
