//! This machine's own addresses, and the kernel's answer for one TCP
//! socket, for the web UI's check of who connects (crate::webui::peer).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::webui::peer::Entry;

/// The addresses of every interface of this machine, in the node's network
/// namespace; none when they cannot be read.
pub(crate) fn addresses() -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `list` with a list it allocated, which is
    // read while it lives and given back to freeifaddrs once.
    unsafe {
        if libc::getifaddrs(&mut list) != 0 {
            return out;
        }
        let mut at = list;
        while !at.is_null() {
            let a = (*at).ifa_addr;
            if !a.is_null() {
                match i32::from((*a).sa_family) {
                    libc::AF_INET => {
                        let v4 = &*(a as *const libc::sockaddr_in);
                        out.push(IpAddr::from(v4.sin_addr.s_addr.to_ne_bytes()));
                    }
                    libc::AF_INET6 => {
                        let v6 = &*(a as *const libc::sockaddr_in6);
                        out.push(IpAddr::from(v6.sin6_addr.s6_addr));
                    }
                    _ => {}
                }
            }
            at = (*at).ifa_next;
        }
        libc::freeifaddrs(list);
    }
    out
}

// Netlink's socket diagnostics (linux/sock_diag.h, linux/inet_diag.h).
const NETLINK_SOCK_DIAG: libc::c_int = 4;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLM_F_REQUEST: u16 = 1;
const NLMSG_ERROR: u16 = 2;
/// A netlink header, then `inet_diag_req_v2`.
const REQUEST_LEN: usize = 16 + 56;
/// A netlink header, then `inet_diag_msg`.
const ANSWER_LEN: usize = 16 + 72;

/// The TCP socket of this machine whose own end is `local` and whose other
/// end is `remote`, as the kernel finds it for a packet (netlink's socket
/// diagnostics, which `ss` asks): one lookup, however many sockets the
/// machine has. Both addresses are of one family. `Ok(None)` when there is
/// none, or when the kernel cannot answer such questions at all (both say
/// "no such entry"); an error when the question could not be asked.
pub(crate) fn tcp_socket(local: SocketAddr, remote: SocketAddr) -> Result<Option<Entry>, String> {
    let family = if local.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let words = |ip: IpAddr| -> [u8; 16] {
        let mut b = [0u8; 16];
        match ip {
            IpAddr::V4(v4) => b[..4].copy_from_slice(&v4.octets()),
            IpAddr::V6(v6) => b = v6.octets(),
        }
        b
    };
    let mut req = Vec::with_capacity(REQUEST_LEN);
    req.extend((REQUEST_LEN as u32).to_ne_bytes());
    req.extend(SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    req.extend(NLM_F_REQUEST.to_ne_bytes());
    req.extend(1u32.to_ne_bytes());
    req.extend(0u32.to_ne_bytes());
    req.extend([family as u8, libc::IPPROTO_TCP as u8, 0, 0]);
    // Every state: the caller judges the state itself.
    req.extend(u32::MAX.to_ne_bytes());
    req.extend(local.port().to_be_bytes());
    req.extend(remote.port().to_be_bytes());
    req.extend(words(local.ip()));
    req.extend(words(remote.ip()));
    // The interface of a link-local address, which a socket made with one
    // is bound to; none for any other, and no cookie to match.
    req.extend(
        match local {
            SocketAddr::V6(v6) => v6.scope_id(),
            SocketAddr::V4(_) => 0,
        }
        .to_ne_bytes(),
    );
    req.extend(u32::MAX.to_ne_bytes());
    req.extend(u32::MAX.to_ne_bytes());
    let mut answer = [0u8; 512];
    let got = {
        // SAFETY: a socket call with constant arguments; the descriptor it
        // gives is owned by `fd` at once and closed with it.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                NETLINK_SOCK_DIAG,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        // SAFETY: `raw` is a descriptor just opened and owned by nothing else.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: an all-zero sockaddr_nl is valid; the kernel is pid 0.
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        // SAFETY: `req` and `kernel` live across the call, with the lengths
        // given.
        let sent = unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                req.as_ptr().cast(),
                req.len(),
                0,
                (&kernel as *const libc::sockaddr_nl).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        // The kernel answers within the send, so the answer waits already.
        // SAFETY: `answer` is writable for its length.
        let n = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                answer.as_mut_ptr().cast(),
                answer.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        n as usize
    };
    parse_answer(&answer[..got])
}

/// The socket in an answer of the socket diagnostics, or none for "no such
/// entry".
fn parse_answer(a: &[u8]) -> Result<Option<Entry>, String> {
    let u16_at = |i: usize| u16::from_ne_bytes([a[i], a[i + 1]]);
    let u32_at = |i: usize| u32::from_ne_bytes([a[i], a[i + 1], a[i + 2], a[i + 3]]);
    if a.len() < 20 {
        return Err("a short answer".into());
    }
    match u16_at(4) {
        NLMSG_ERROR => {
            let e = -(u32_at(16) as i32);
            if e == libc::ENOENT {
                Ok(None)
            } else {
                Err(std::io::Error::from_raw_os_error(e).to_string())
            }
        }
        SOCK_DIAG_BY_FAMILY if a.len() >= ANSWER_LEN => {
            let m = &a[16..];
            let ip = |b: &[u8]| -> Option<IpAddr> {
                match i32::from(m[0]) {
                    libc::AF_INET => Some(Ipv4Addr::new(b[0], b[1], b[2], b[3]).into()),
                    libc::AF_INET6 => {
                        Some(Ipv6Addr::from(<[u8; 16]>::try_from(&b[..16]).ok()?).into())
                    }
                    _ => None,
                }
            };
            let port = |i: usize| u16::from_be_bytes([m[i], m[i + 1]]);
            let (Some(src), Some(dst)) = (ip(&m[8..24]), ip(&m[24..40])) else {
                return Err("an answer of another family".into());
            };
            Ok(Some(Entry {
                local: SocketAddr::new(src, port(4)),
                remote: SocketAddr::new(dst, port(6)),
                state: m[1],
                uid: u32_at(16 + 64),
                inode: u64::from(u32_at(16 + 68)),
            }))
        }
        t => Err(format!("an answer of type {t}")),
    }
}

#[cfg(test)]
mod tests {
    /// The socket of a peer that connected over a link-local address is found
    /// by the interface the address is scoped to. A machine without such an
    /// address has nothing to test.
    #[test]
    fn a_link_local_peer_is_found_by_its_interface() {
        use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, TcpListener, TcpStream};
        let table = std::fs::read_to_string("/proc/net/if_inet6").unwrap_or_default();
        let link = table.lines().find_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let (hex, index, scope) = (f.first()?, f.get(1)?, f.get(3)?);
            // Scope 0x20 is link-local; the flags say it is not tentative.
            if *scope != "20" || u32::from_str_radix(f.get(4)?, 16).ok()? & 0x40 != 0 {
                return None;
            }
            let ip = Ipv6Addr::from(u128::from_str_radix(hex, 16).ok()?);
            Some(SocketAddrV6::new(
                ip,
                0,
                0,
                u32::from_str_radix(index, 16).ok()?,
            ))
        });
        let Some(link) = link else {
            eprintln!("no link-local address here; nothing to test");
            return;
        };
        let Ok(listener) = TcpListener::bind(link) else {
            eprintln!("cannot listen on {link}; nothing to test");
            return;
        };
        let local = listener.local_addr().unwrap();
        let Ok(client) = TcpStream::connect(local) else {
            eprintln!("cannot connect to {local}; nothing to test");
            return;
        };
        let (_server, peer) = listener.accept().unwrap();
        assert_eq!(client.local_addr().unwrap(), peer);
        let SocketAddr::V6(v6) = peer else { panic!() };
        assert_ne!(v6.scope_id(), 0, "the peer names its interface");
        let found = super::tcp_socket(peer, local).unwrap();
        // SAFETY: a plain getter.
        let uid = unsafe { libc::getuid() };
        assert_eq!(found.map(|e| e.uid), Some(uid));
    }

    #[test]
    fn loopback_is_one_of_them() {
        let own = super::addresses();
        assert!(own.iter().any(|a| a.is_loopback()), "{own:?}");
    }
}
