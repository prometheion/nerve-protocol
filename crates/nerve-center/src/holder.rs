//! Who listens where the installed center's web UI should be, asked before
//! a program of this machine sends the owner token there (the desktop app's
//! log-in, docs/dev/web-uis.md). Any account may listen on a free port: a
//! program that took the web UI's port while the center was stopped would
//! get the token, and with it the center. So every listener a connection to
//! the address may reach must be the center's service:
//!
//! - on Linux, a socket of the `nerve-center` account, as the kernel's
//!   tables of TCP sockets name it (`/proc/net/tcp` and `tcp6`, which every
//!   account may read);
//! - on Windows, a socket of the process the service control manager names
//!   for the service `nerve-center` (the table of TCP listeners names each
//!   one's process). The center binds its listeners for itself alone
//!   (nerve_service::listen), so no other program shares the port.

use std::net::SocketAddr;

use nerve_service::win::tcp::{Row, listening_at};

/// Who holds an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Holder {
    /// The center's service, alone.
    Center,
    /// Another program, or the center beside another program.
    Other,
    /// Nobody listens there: the center does not run.
    Nobody,
}

/// Who holds `at`, of the listeners `rows` (each with its account on Linux,
/// its process on Windows), when the center's service is `center` (`None`
/// when it is not installed or does not run).
pub fn judge(rows: &[Row], at: SocketAddr, center: Option<u32>) -> Holder {
    let found = listening_at(rows, at);
    if found.is_empty() {
        Holder::Nobody
    } else if center.is_some_and(|c| found.iter().all(|&f| f == c)) {
        Holder::Center
    } else {
        Holder::Other
    }
}

/// Who holds `at` on this machine now.
pub fn of(at: SocketAddr) -> Result<Holder, String> {
    #[cfg(target_os = "linux")]
    {
        let center = nerve_service::account::lookup(crate::service::USER)?.map(|a| a.uid);
        Ok(judge(&linux_listeners(), at, center))
    }
    #[cfg(windows)]
    {
        let rows = nerve_service::win::tcp::listeners()
            .map_err(|e| format!("cannot read the table of listeners: {e}"))?;
        Ok(judge(&rows, at, service_pid()?))
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = at;
        Err("works on Linux and Windows only".into())
    }
}

/// [`of`], as a check: an error that says what holds `at` unless it is the
/// center's service.
pub fn check(at: SocketAddr) -> Result<(), String> {
    match of(at)? {
        Holder::Center => Ok(()),
        Holder::Nobody => Err(NOT_RUNNING.into()),
        Holder::Other => Err(format!(
            "another program listens on {at}, not the center's service: the owner token is not sent there"
        )),
    }
}

/// What [`check`] says when nobody listens.
pub const NOT_RUNNING: &str = "the center is not running";

/// The listening sockets of both kernel tables, each with its account.
#[cfg(target_os = "linux")]
pub fn linux_listeners() -> Vec<Row> {
    let mut rows = Vec::new();
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let text = std::fs::read_to_string(table).unwrap_or_default();
        rows.extend(listeners_in(&text));
    }
    rows
}

/// The listening sockets of one table's text, with their accounts.
#[cfg(target_os = "linux")]
pub fn listeners_in(text: &str) -> Vec<Row> {
    // State 0A is LISTEN.
    nerve_transport::peer::parse(text)
        .into_iter()
        .filter(|e| e.state == 0x0A)
        .map(|e| Row {
            local: e.local,
            remote: e.remote,
            pid: e.uid,
        })
        .collect()
}

/// The process of the running service `nerve-center`; `None` when it is not
/// registered or does not run.
#[cfg(windows)]
pub fn service_pid() -> Result<Option<u32>, String> {
    nerve_service::win::service::pid(crate::winsvc::SERVICE_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    fn at(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    // The center's listener (uid 990) and, on another port, one of uid 1000.
    #[cfg(target_os = "linux")]
    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1D38 00000000:0000 0A 00000000:00000000 00:00000000 00000000   990        0 1001 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1D39 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1002 1 0000000000000000 100 0 0 10 0
   2: 0100007F:1D38 0100007F:C350 01 00000000:00000000 00:00000000 00000000   990        0 1003 1 0000000000000000 20 4 30 10 -1
";
    // Another account on every IPv6 address of the center's port.
    #[cfg(target_os = "linux")]
    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:1D38 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 2001 1 0000000000000000 100 0 0 10 0
";

    #[cfg(target_os = "linux")]
    #[test]
    fn only_the_center_s_own_listener_is_the_center() {
        let rows = listeners_in(TCP);
        // Only the listeners, not the connection.
        assert_eq!(rows.len(), 2);
        let ui = at("127.0.0.1:7480");
        assert_eq!(judge(&rows, ui, Some(990)), Holder::Center);
        // Another account's listener there.
        assert_eq!(judge(&rows, at("127.0.0.1:7481"), Some(990)), Holder::Other);
        // No center installed: whoever listens is another program.
        assert_eq!(judge(&rows, ui, None), Holder::Other);
        // Nobody.
        assert_eq!(
            judge(&rows, at("127.0.0.1:7482"), Some(990)),
            Holder::Nobody
        );
        // Another account beside the center, on every IPv6 address, which
        // takes IPv4 connections too.
        let mut both = rows.clone();
        both.extend(listeners_in(TCP6));
        assert_eq!(judge(&both, ui, Some(990)), Holder::Other);
    }

    /// A listener this test holds is found under this account: the center
    /// it is not, unless the center is this account.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_listener_here_is_found_under_its_account() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let ui = l.local_addr().unwrap();
        // SAFETY: plain getter.
        let me = unsafe { libc::getuid() };
        let rows = linux_listeners();
        assert_eq!(judge(&rows, ui, Some(me)), Holder::Center);
        assert_eq!(judge(&rows, ui, Some(me + 1)), Holder::Other);
        drop(l);
        assert_eq!(judge(&linux_listeners(), ui, Some(me)), Holder::Nobody);
    }

    /// On Windows a listener of this process is the center's when the
    /// service's process is this one, and another program's else.
    #[cfg(windows)]
    #[test]
    fn a_listener_here_is_found_with_its_process() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let ui = l.local_addr().unwrap();
        let me = std::process::id();
        let rows = nerve_service::win::tcp::listeners().unwrap();
        assert_eq!(judge(&rows, ui, Some(me)), Holder::Center);
        assert_eq!(judge(&rows, ui, Some(me + 4)), Holder::Other);
    }
}
