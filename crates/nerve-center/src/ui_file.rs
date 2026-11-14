//! Where the installed center's web UI listens, in a file every account of
//! the machine may read: `/run/nerve-center/ui` on Linux (the service's
//! runtime folder) and `%ProgramData%\nerve-center\run\ui` on Windows. The
//! desktop app reads it to find the web UI it logs in to; it holds no
//! secret, only the address, or that the web UI is off.
//!
//! The file says where to look, not who listens there: a program that took
//! the port while the center was stopped could be there instead. So the app
//! checks the port's holder before it sends the owner token
//! ([`crate::holder`]).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The file's name in the run folder.
pub const FILE: &str = "ui";

/// What the file says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiAddress {
    /// The URL a program on this machine opens the web UI at; `None` while
    /// the web UI is off.
    pub url: Option<String>,
    /// The address the web UI listens on, as the center bound it.
    pub listen: Option<SocketAddr>,
    /// The SHA-256 pin of the certificate beyond loopback, where it uses
    /// TLS.
    pub pin: Option<String>,
}

impl UiAddress {
    /// The web UI bound at `at` (with TLS when `pin` is given), or off.
    pub fn of(at: Option<SocketAddr>, pin: Option<String>) -> UiAddress {
        let Some(at) = at else {
            return UiAddress {
                url: None,
                listen: None,
                pin: None,
            };
        };
        // A listener on every address is reached on this machine at its
        // loopback one, which it holds too.
        let ip = match at.ip() {
            std::net::IpAddr::V4(v4) if v4.is_unspecified() => std::net::Ipv4Addr::LOCALHOST.into(),
            std::net::IpAddr::V6(v6) if v6.is_unspecified() => std::net::Ipv6Addr::LOCALHOST.into(),
            ip => ip,
        };
        let scheme = if pin.is_some() { "https" } else { "http" };
        UiAddress {
            url: Some(format!("{scheme}://{}", SocketAddr::new(ip, at.port()))),
            listen: Some(at),
            pin,
        }
    }
}

/// The file in the run folder `run`.
pub fn path_in(run: &Path) -> PathBuf {
    run.join(FILE)
}

/// Writes `address` into `file`, readable by every account, in place of
/// what was there: written beside it first, so a reader never sees half.
pub fn write(file: &Path, address: &UiAddress) -> Result<(), String> {
    let text = serde_json::to_string(address).map_err(|e| e.to_string())? + "\n";
    nerve_service::write_file(file, text.as_bytes(), 0o644)
}

/// What `file` says; `None` when it is not there (the center does not run,
/// or is not installed).
pub fn read(file: &Path) -> Result<Option<UiAddress>, String> {
    match std::fs::read_to_string(file) {
        Ok(text) => serde_json::from_str(&text)
            .map(Some)
            .map_err(|e| format!("{}: {e}", file.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", file.display())),
    }
}

/// Removes `file`, when the center stops.
pub fn remove(file: &Path) {
    let _ = std::fs::remove_file(file);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_address_is_the_url_a_program_here_opens() {
        let at = |s: &str| Some(s.parse::<SocketAddr>().unwrap());
        assert_eq!(
            UiAddress::of(at("127.0.0.1:7480"), None).url.as_deref(),
            Some("http://127.0.0.1:7480")
        );
        // Every address: this machine reaches it on loopback, over TLS.
        let wide = UiAddress::of(at("0.0.0.0:7480"), Some("pin".into()));
        assert_eq!(wide.url.as_deref(), Some("https://127.0.0.1:7480"));
        assert_eq!(wide.listen, at("0.0.0.0:7480"));
        assert_eq!(
            UiAddress::of(at("[::]:7480"), Some("pin".into()))
                .url
                .as_deref(),
            Some("https://[::1]:7480")
        );
        // Off.
        assert_eq!(UiAddress::of(None, Some("pin".into())).url, None);
    }

    #[test]
    fn it_is_written_for_every_account_and_read_back() {
        let d = tempfile::tempdir().unwrap();
        let file = path_in(d.path());
        assert_eq!(read(&file).unwrap(), None);
        let a = UiAddress::of(Some("127.0.0.1:7480".parse().unwrap()), None);
        write(&file, &a).unwrap();
        assert_eq!(read(&file).unwrap(), Some(a));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&file).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o644);
        }
        remove(&file);
        assert_eq!(read(&file).unwrap(), None);
    }
}
