//! Who listens on an address of this machine, asked before a program sends
//! a secret there: the desktop app's log-in to the center's web UI with the
//! owner token, and its **Open the web UI** of the node's. Any account may
//! listen on a free port: a program that took a service's port while the
//! service was stopped would get what a browser or the app sends. So every
//! listener a connection to the address may reach must be the service's:
//!
//! - on Linux, a socket of the service's account, as the kernel's tables of
//!   TCP sockets name it (`/proc/net/tcp` and `tcp6`, which every account
//!   may read);
//! - on Windows, a socket of the process the service control manager names
//!   for the service (the table of TCP listeners names each one's process).
//!   The services bind their listeners for themselves alone
//!   ([`crate::listen`]), so no other program shares the port.

use std::net::SocketAddr;

use crate::win::tcp::{Row, listening_at};

/// Who holds an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Holder {
    /// The service, alone.
    Service,
    /// Another program, or the service beside another program.
    Other,
    /// Nobody listens there: the service does not run.
    Nobody,
}

/// The service a port should belong to: its account on Linux, its name on
/// Windows.
#[derive(Debug, Clone, Copy)]
pub struct Service<'a> {
    pub account: &'a str,
    pub name: &'a str,
}

/// Who holds `at`, of the listeners `rows` (each with its account on Linux,
/// its process on Windows), when the service is `service` (`None` when it
/// is not installed or does not run).
pub fn judge(rows: &[Row], at: SocketAddr, service: Option<u32>) -> Holder {
    let found = listening_at(rows, at);
    if found.is_empty() {
        Holder::Nobody
    } else if service.is_some_and(|c| found.iter().all(|&f| f == c)) {
        Holder::Service
    } else {
        Holder::Other
    }
}

/// Who holds `at` on this machine now.
pub fn of(at: SocketAddr, service: Service) -> Result<Holder, String> {
    #[cfg(target_os = "linux")]
    {
        let uid = crate::account::lookup(service.account)?.map(|a| a.uid);
        Ok(judge(&linux_listeners(), at, uid))
    }
    #[cfg(windows)]
    {
        let rows = crate::win::tcp::listeners()
            .map_err(|e| format!("cannot read the table of listeners: {e}"))?;
        Ok(judge(&rows, at, crate::win::service::pid(service.name)?))
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (at, service);
        Err("works on Linux and Windows only".into())
    }
}

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
    fn only_the_service_s_own_listener_is_the_service() {
        let rows = listeners_in(TCP);
        // Only the listeners, not the connection.
        assert_eq!(rows.len(), 2);
        let ui = at("127.0.0.1:7480");
        assert_eq!(judge(&rows, ui, Some(990)), Holder::Service);
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

    /// A listener this test holds is found under this account: the
    /// service's it is not, unless the service runs as this account.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_listener_here_is_found_under_its_account() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let ui = l.local_addr().unwrap();
        // SAFETY: plain getter.
        let me = unsafe { libc::getuid() };
        let rows = linux_listeners();
        assert_eq!(judge(&rows, ui, Some(me)), Holder::Service);
        assert_eq!(judge(&rows, ui, Some(me + 1)), Holder::Other);
        drop(l);
        assert_eq!(judge(&linux_listeners(), ui, Some(me)), Holder::Nobody);
    }

    /// On Windows a listener of this process is the service's when the
    /// service's process is this one, and another program's else.
    #[cfg(windows)]
    #[test]
    fn a_listener_here_is_found_with_its_process() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let ui = l.local_addr().unwrap();
        let me = std::process::id();
        let rows = crate::win::tcp::listeners().unwrap();
        assert_eq!(judge(&rows, ui, Some(me)), Holder::Service);
        assert_eq!(judge(&rows, ui, Some(me + 4)), Holder::Other);
    }
}
