//! Who is at the other end of a web UI connection, before a byte of it is
//! read. A peer on this machine has a socket in the kernel's table of TCP
//! sockets, in the node's network namespace, with the account that made it:
//! the kernel looks the one socket up ([`Lookup::Kernel`]), or, where it
//! cannot, the whole table is read (`/proc/self/net/tcp` and `tcp6`). Only
//! the owner's and root's may go on to the login: a command of a center,
//! which runs as `nerve-run` (or as the node's own account), is closed at
//! once.
//!
//! The check fails closed. A local peer whose entry is missing, or is no
//! longer a live socket of a process (it closed already, so the kernel
//! keeps only a remainder without an account), is closed as well; a peer
//! counts as local when its address is loopback, the address it connected
//! to, or one of this machine's. Any other peer is another machine (or
//! another network namespace), and goes on to the login.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// What the check decided of a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// A socket of this machine, of the account with this uid, which is
    /// one let in.
    Local(u32),
    /// Another machine.
    Remote,
    /// A socket of this machine of another account, or one the check
    /// cannot place: closed unread.
    Closed,
}

/// One line of `/proc/net/tcp{,6}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: u8,
    pub uid: u32,
    pub inode: u64,
}

/// The state of an established connection in the table.
const ESTABLISHED: u8 = 0x01;

/// The entries of one table's text; lines it cannot read are left out.
pub(crate) fn parse(text: &str) -> Vec<Entry> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 {
                return None;
            }
            Some(Entry {
                local: address(f[1])?,
                remote: address(f[2])?,
                state: u8::from_str_radix(f[3], 16).ok()?,
                uid: f[7].parse().ok()?,
                inode: f[9].parse().ok()?,
            })
        })
        .collect()
}

/// `0100007F:1F2E` (IPv4) or 32 hex digits and a port (IPv6). The kernel
/// writes each 32-bit word of the address as the number it is in memory, so
/// its bytes are those of the number in this machine's order.
fn address(text: &str) -> Option<SocketAddr> {
    let (ip, port) = text.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let words = |hex: &str| -> Option<Vec<u8>> {
        (0..hex.len() / 8)
            .map(|i| u32::from_str_radix(&hex[i * 8..i * 8 + 8], 16).ok())
            .collect::<Option<Vec<u32>>>()
            .map(|w| w.iter().flat_map(|n| n.to_ne_bytes()).collect())
    };
    let ip = match ip.len() {
        8 => {
            let b = words(ip)?;
            IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
        }
        32 => {
            let b: [u8; 16] = words(ip)?.try_into().ok()?;
            IpAddr::V6(Ipv6Addr::from(b))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// An IPv4 address that IPv6 carries (`::ffff:a.b.c.d`) as the IPv4
/// address it is: a listener on `[::]` sees an IPv4 peer so, while the
/// peer's own socket is in the IPv4 table.
fn plain(a: SocketAddr) -> SocketAddr {
    match a.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), a.port()),
            None => a,
        },
        IpAddr::V4(_) => a,
    }
}

/// Judges the peer `peer` of a connection to `local` by the table
/// `entries`. `allowed` are the accounts let in, `own` this machine's
/// addresses.
pub(crate) fn judge(
    peer: SocketAddr,
    local: SocketAddr,
    entries: &[Entry],
    allowed: &[u32],
    own: &[IpAddr],
) -> Verdict {
    let (peer, local) = (plain(peer), plain(local));
    // The peer's own socket: its local end is the peer, its remote end the
    // address it connected to. Matched on the whole pair, never on a port
    // alone, which would also find this node's end of the connection.
    let found: Vec<&Entry> = entries
        .iter()
        .filter(|e| plain(e.local) == peer && plain(e.remote) == local)
        .collect();
    match found[..] {
        // A remainder of a closed socket has no inode and shows root as
        // its account: it says nothing of who made it.
        [e] if e.state == ESTABLISHED && e.inode != 0 && allowed.contains(&e.uid) => {
            Verdict::Local(e.uid)
        }
        // Another account's, a remainder, or two that claim to be the
        // peer, which is a doubt.
        [_, ..] => Verdict::Closed,
        [] => {
            let ip = peer.ip();
            if ip.is_loopback() || ip.is_unspecified() || ip == local.ip() || own.contains(&ip) {
                Verdict::Closed
            } else {
                Verdict::Remote
            }
        }
    }
}

/// How the check finds a peer's socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lookup {
    /// The kernel looks the one socket up (crate::localnet::tcp_socket): the
    /// cost does not grow with the sockets of the machine, which a command
    /// that is closed at once can make many of, nor with how often it tries.
    Kernel,
    /// The whole tables of /proc are read, where the kernel does not answer
    /// that (no socket diagnostics for TCP in it).
    Tables,
}

impl Lookup {
    /// The way that works here, tried on the listener at `at` itself: the
    /// kernel says "no such entry" also when it cannot look sockets up, and
    /// a check that took that for a peer that left would close every one.
    pub(crate) fn for_listener(at: SocketAddr) -> Lookup {
        let any = SocketAddr::new(
            if at.is_ipv4() {
                Ipv4Addr::UNSPECIFIED.into()
            } else {
                Ipv6Addr::UNSPECIFIED.into()
            },
            0,
        );
        match crate::localnet::tcp_socket(at, any) {
            Ok(Some(e)) if e.local.port() == at.port() => Lookup::Kernel,
            _ => Lookup::Tables,
        }
    }
}

/// [`judge`] with the peer's socket and the addresses of this machine as
/// they are now.
pub(crate) fn judge_now(
    peer: SocketAddr,
    local: SocketAddr,
    allowed: &[u32],
    how: Lookup,
) -> Verdict {
    let entries = match how {
        Lookup::Kernel => match crate::localnet::tcp_socket(plain(peer), plain(local)) {
            Ok(found) => found.into_iter().collect(),
            Err(e) => {
                tracing::debug!(
                    "web UI: the kernel did not look the peer up ({e}); reading the tables"
                );
                tables()
            }
        },
        Lookup::Tables => tables(),
    };
    // A local peer is placed by its entry; the machine's addresses are
    // only needed for a peer that may be another machine.
    let found = entries
        .iter()
        .any(|e| plain(e.local) == plain(peer) && plain(e.remote) == plain(local));
    let ip = plain(peer).ip();
    let own = if found || ip.is_loopback() || ip.is_unspecified() || ip == plain(local).ip() {
        Vec::new()
    } else {
        own_addresses()
    };
    judge(peer, local, &entries, allowed, &own)
}

/// Both tables of /proc, in the node's network namespace.
fn tables() -> Vec<Entry> {
    #[cfg(test)]
    TABLE_READS.with(|n| n.set(n.get() + 1));
    let mut entries = Vec::new();
    for table in ["/proc/self/net/tcp", "/proc/self/net/tcp6"] {
        if let Ok(text) = std::fs::read_to_string(table) {
            entries.extend(parse(&text));
        }
    }
    entries
}

#[cfg(test)]
thread_local! {
    static TABLE_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// This machine's addresses, read at most once a second: another machine
/// that connects again and again must not make each connection read them.
fn own_addresses() -> Vec<IpAddr> {
    static READ: std::sync::Mutex<Option<(std::time::Instant, Vec<IpAddr>)>> =
        std::sync::Mutex::new(None);
    let mut read = READ.lock().unwrap_or_else(|e| e.into_inner());
    match &*read {
        Some((at, own)) if at.elapsed() < std::time::Duration::from_secs(1) => own.clone(),
        _ => {
            let own = crate::localnet::addresses();
            *read = Some((std::time::Instant::now(), own.clone()));
            own
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // From a machine: the listener, the node's end of one connection, the
    // owner's end of it, an IPv6 peer, and the remainder of a closed one.
    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1D2E 00000000:0000 0A 00000000:00000000 00:00000000 00000000   990        0 1001 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1D2E 0100007F:C350 01 00000000:00000000 00:00000000 00000000   990        0 1002 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:C350 0100007F:1D2E 01 00000000:00000000 00:00000000 00000000  1000        0 1003 1 0000000000000000 20 4 30 10 -1
   3: 0100007F:C351 0100007F:1D2E 01 00000000:00000000 00:00000000 00000000  1001        0 1004 1 0000000000000000 20 4 30 10 -1
   4: 0100007F:C352 0100007F:1D2E 05 00000000:00000000 00:00000000 00000000     0        0 0 1 0000000000000000 20 4 30 10 -1
";
    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:C353 00000000000000000000000001000000:1D2E 01 00000000:00000000 00:00000000 00000000  1000        0 2001 1 0000000000000000 20 4 30 10 -1
";

    fn at(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn entries() -> Vec<Entry> {
        let mut e = parse(TCP);
        e.extend(parse(TCP6));
        e
    }

    #[test]
    fn the_tables_are_read_as_the_kernel_writes_them() {
        let e = entries();
        assert_eq!(e.len(), 6);
        assert_eq!(e[0].local, at("127.0.0.1:7470"));
        assert_eq!(e[0].state, 0x0A);
        assert_eq!(
            (e[2].local, e[2].remote),
            (at("127.0.0.1:50000"), at("127.0.0.1:7470"))
        );
        assert_eq!((e[2].uid, e[2].inode), (1000, 1003));
        assert_eq!(e[5].local, at("[::1]:50003"));
        assert_eq!(e[5].remote, at("[::1]:7470"));
        // A line it cannot read is left out.
        assert!(parse("head\n 0: nonsense\n").is_empty());
    }

    #[test]
    fn a_local_peer_is_the_account_of_its_socket() {
        let e = entries();
        let local = at("127.0.0.1:7470");
        let owner = [0, 1000];
        // The owner's socket.
        assert_eq!(
            judge(at("127.0.0.1:50000"), local, &e, &owner, &[]),
            Verdict::Local(1000)
        );
        // Another account's: nerve-run, say.
        assert_eq!(
            judge(at("127.0.0.1:50001"), local, &e, &owner, &[]),
            Verdict::Closed
        );
        // Over IPv6 loopback.
        assert_eq!(
            judge(at("[::1]:50003"), at("[::1]:7470"), &e, &owner, &[]),
            Verdict::Local(1000)
        );
    }

    #[test]
    fn the_pair_is_matched_whole_and_never_by_the_port() {
        let e = entries();
        // The node's own end of the connection has the listener's address as
        // its local end and uid 990: it is not the peer's entry.
        assert_eq!(
            judge(at("127.0.0.1:50000"), at("127.0.0.1:7470"), &e, &[990], &[]),
            Verdict::Closed
        );
        // The same port on another address is another socket.
        assert_eq!(
            judge(
                at("127.0.0.2:50000"),
                at("127.0.0.1:7470"),
                &e,
                &[0, 1000],
                &[]
            ),
            Verdict::Closed
        );
    }

    #[test]
    fn a_closed_or_missing_local_peer_is_closed() {
        let e = entries();
        let owner = [0, 1000];
        // The remainder of a closed socket shows uid 0 and no inode.
        assert_eq!(
            judge(at("127.0.0.1:50002"), at("127.0.0.1:7470"), &e, &owner, &[]),
            Verdict::Closed
        );
        // No entry, and the peer is this machine: loopback, the address it
        // reached, or one of the machine's.
        for (peer, local) in [
            ("127.0.0.1:40000", "127.0.0.1:7470"),
            ("[::1]:40000", "[::1]:7470"),
            ("192.0.2.7:40000", "192.0.2.7:7470"),
            ("198.51.100.3:40000", "192.0.2.7:7470"),
            ("[::ffff:198.51.100.3]:40000", "[::ffff:192.0.2.7]:7470"),
        ] {
            let own = [IpAddr::from([198, 51, 100, 3])];
            assert_eq!(
                judge(at(peer), at(local), &e, &owner, &own),
                Verdict::Closed,
                "{peer}"
            );
        }
        // Another machine goes on to the login.
        assert_eq!(
            judge(
                at("203.0.113.9:40000"),
                at("192.0.2.7:7470"),
                &e,
                &owner,
                &[]
            ),
            Verdict::Remote
        );
    }

    #[test]
    fn two_entries_for_one_peer_are_a_doubt() {
        let mut e = entries();
        let mut twin = e[2].clone();
        twin.local = at("[::ffff:127.0.0.1]:50000");
        twin.remote = at("[::ffff:127.0.0.1]:7470");
        e.push(twin);
        assert_eq!(
            judge(
                at("127.0.0.1:50000"),
                at("127.0.0.1:7470"),
                &e,
                &[1000],
                &[]
            ),
            Verdict::Closed
        );
    }

    /// The kernel names the account of a real peer's socket at once, and
    /// the tables are not read for it.
    #[test]
    fn the_kernel_names_the_account_of_a_peer_without_the_tables() {
        use std::os::unix::fs::MetadataExt;
        let me = std::fs::metadata("/proc/self").unwrap().uid();
        let other = me.wrapping_add(1);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let at = listener.local_addr().unwrap();
        assert_eq!(Lookup::for_listener(at), Lookup::Kernel);
        let client = std::net::TcpStream::connect(at).unwrap();
        let (_server, peer) = listener.accept().unwrap();
        let reads = TABLE_READS.with(|n| n.get());
        assert_eq!(
            judge_now(peer, at, &[me], Lookup::Kernel),
            Verdict::Local(me)
        );
        assert_eq!(
            judge_now(peer, at, &[other], Lookup::Kernel),
            Verdict::Closed
        );
        assert_eq!(TABLE_READS.with(|n| n.get()), reads);
        // The tables say the same.
        assert_eq!(
            judge_now(peer, at, &[me], Lookup::Tables),
            Verdict::Local(me)
        );
        // A peer that closed is closed.
        drop(client);
        let start = std::time::Instant::now();
        while judge_now(peer, at, &[me], Lookup::Kernel) != Verdict::Closed {
            assert!(
                start.elapsed().as_secs() < 5,
                "the closed peer is still let in"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        // No socket at all on loopback: closed.
        let gone = SocketAddr::new(at.ip(), 1);
        assert_eq!(judge_now(gone, at, &[me], Lookup::Kernel), Verdict::Closed);
    }

    #[test]
    fn an_ipv4_peer_of_a_listener_on_ipv6_is_found_in_the_ipv4_table() {
        let e = entries();
        assert_eq!(
            judge(
                at("[::ffff:127.0.0.1]:50000"),
                at("[::ffff:127.0.0.1]:7470"),
                &e,
                &[1000],
                &[]
            ),
            Verdict::Local(1000)
        );
    }
}
