//! The process at the other end of a loopback connection on Windows, as
//! Windows' table of TCP connections names it: the center counts a loopback
//! peer's places by its account, as Linux names the account of a socket.
//! Both ends of a loopback connection are rows of the table, each with the
//! process that holds it; the other end's row is the one whose local
//! address is the peer's.

use std::net::SocketAddr;

/// One connection of the table: its two ends and the process that holds
/// the local one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Row {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub pid: u32,
}

/// The process of the connection that `peer` opened to `local` (as the
/// listener sees it): the row whose local end is `peer` and whose remote
/// end is `local`. An IPv4 address that IPv6 carries is that address, as a
/// dual-stack listener sees an IPv4 peer.
pub fn other_end(rows: &[Row], peer: SocketAddr, local: SocketAddr) -> Option<u32> {
    let plain = |a: SocketAddr| SocketAddr::new(a.ip().to_canonical(), a.port());
    let (peer, local) = (plain(peer), plain(local));
    rows.iter()
        .find(|r| plain(r.local) == peer && plain(r.remote) == local)
        .map(|r| r.pid)
}

#[cfg(windows)]
pub use sys::{client_pid, rows};

#[cfg(windows)]
mod sys {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    use super::{Row, other_end};

    /// A port as the table holds it: in network order, in the low two
    /// bytes of a number.
    fn port(p: u32) -> u16 {
        let b = p.to_ne_bytes();
        u16::from_be_bytes([b[0], b[1]])
    }

    /// The table of `family` as Windows writes it, in a buffer aligned for
    /// its rows.
    fn table(family: u16) -> std::io::Result<Vec<u32>> {
        let mut size = 0u32;
        let mut buf: Vec<u32> = Vec::new();
        for _ in 0..8 {
            // SAFETY: a buffer of `size` bytes (none at first) and its size.
            let r = unsafe {
                GetExtendedTcpTable(
                    buf.as_mut_ptr().cast(),
                    &mut size,
                    0,
                    u32::from(family),
                    TCP_TABLE_OWNER_PID_CONNECTIONS,
                    0,
                )
            };
            match r {
                NO_ERROR => return Ok(buf),
                // Connections came meanwhile: room for them and some more.
                ERROR_INSUFFICIENT_BUFFER => {
                    size += 1024;
                    buf = vec![0u32; (size as usize).div_ceil(4)];
                    size = (buf.len() * 4) as u32;
                }
                e => return Err(std::io::Error::from_raw_os_error(e as i32)),
            }
        }
        Err(std::io::Error::other(
            "the table of connections kept growing",
        ))
    }

    /// The rows of `T` after the count that starts the table.
    fn rows_of<T: Copy>(buf: &[u32]) -> Vec<T> {
        let Some(&n) = buf.first() else {
            return Vec::new();
        };
        // The rows follow the count at their own alignment, which is that of
        // a u32 for both tables.
        let bytes = std::mem::size_of_val(buf);
        let room = (bytes - 4) / std::mem::size_of::<T>();
        let n = (n as usize).min(room);
        // SAFETY: `n` rows of `T` fit after the count in the buffer Windows
        // filled; T is plain data aligned as a u32.
        unsafe { std::slice::from_raw_parts(buf.as_ptr().add(1).cast::<T>(), n).to_vec() }
    }

    /// Every TCP connection of the machine, IPv4 and IPv6, with its process.
    pub fn rows() -> std::io::Result<Vec<Row>> {
        let mut all = Vec::new();
        for r in rows_of::<MIB_TCPROW_OWNER_PID>(&table(AF_INET)?) {
            let ip = |a: u32| IpAddr::V4(Ipv4Addr::from(a.to_ne_bytes()));
            all.push(Row {
                local: SocketAddr::new(ip(r.dwLocalAddr), port(r.dwLocalPort)),
                remote: SocketAddr::new(ip(r.dwRemoteAddr), port(r.dwRemotePort)),
                pid: r.dwOwningPid,
            });
        }
        for r in rows_of::<MIB_TCP6ROW_OWNER_PID>(&table(AF_INET6)?) {
            let ip = |a: [u8; 16]| IpAddr::V6(Ipv6Addr::from(a));
            all.push(Row {
                local: SocketAddr::new(ip(r.ucLocalAddr), port(r.dwLocalPort)),
                remote: SocketAddr::new(ip(r.ucRemoteAddr), port(r.dwRemotePort)),
                pid: r.dwOwningPid,
            });
        }
        Ok(all)
    }

    /// The process of the loopback connection `peer` opened to `local`;
    /// `None` when Windows does not list it (it closed already).
    pub fn client_pid(peer: SocketAddr, local: SocketAddr) -> Option<u32> {
        other_end(&rows().ok()?, peer, local)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// A connection this test opens is found with this process at its
        /// other end, IPv4 and IPv6.
        #[test]
        fn the_other_end_of_a_loopback_connection_is_found() {
            for at in ["127.0.0.1:0", "[::1]:0"] {
                let l = std::net::TcpListener::bind(at).unwrap();
                let local = l.local_addr().unwrap();
                let c = std::net::TcpStream::connect(local).unwrap();
                let (_s, peer) = l.accept().unwrap();
                assert_eq!(c.local_addr().unwrap(), peer);
                assert_eq!(client_pid(peer, local), Some(std::process::id()), "{at}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// The other end is the row that holds the peer's address and points at
    /// the listener's; the listener's own row of it, and other connections,
    /// are not.
    #[test]
    fn the_peer_s_row_names_its_process() {
        let local = at("127.0.0.1:7480");
        let peer = at("127.0.0.1:50000");
        let rows = [
            Row {
                local,
                remote: peer,
                pid: 1,
            },
            Row {
                local: at("127.0.0.1:50001"),
                remote: local,
                pid: 3,
            },
            Row {
                local: peer,
                remote: local,
                pid: 2,
            },
        ];
        assert_eq!(other_end(&rows, peer, local), Some(2));
        assert_eq!(other_end(&rows, at("127.0.0.1:50002"), local), None);
        // A dual-stack listener sees the IPv4 peer as IPv6 carries it.
        assert_eq!(
            other_end(
                &rows,
                at("[::ffff:127.0.0.1]:50000"),
                at("[::ffff:127.0.0.1]:7480")
            ),
            Some(2)
        );
    }
}
