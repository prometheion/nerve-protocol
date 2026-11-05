//! Opening a connection to the center: TLS, except to a center on this machine.
//!
//! Plain HTTP is allowed only when every address the connection may use is a
//! loopback address, checked after name resolution, so a name that resolves to
//! another machine cannot get a plaintext link (which would hand a man in the middle
//! a shell on this device).
//!
//! Loopback is not a channel between two users: any local account may listen on a
//! free port, and gets the pairing code and the link. So a name (`localhost`)
//! takes only its IPv4 loopback addresses (the center listens on IPv4, which leaves
//! `[::1]` on its port free for anyone), and on Linux the connection's socket and
//! every socket listening where it could have arrived must belong to this user or
//! root. What remains: on Windows plain HTTP
//! trusts every local account; use https with a pinned certificate there.

use std::net::SocketAddr;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use nerve_proto::link::CenterUrl;

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub type BoxIo = Box<dyn Io>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// The addresses a connection may use. Without TLS only loopback ones, and none
/// at all if the name resolves to anything else; for a name rather than an
/// address (`named`), only its IPv4 loopback addresses.
pub fn usable_addrs(
    tls: bool,
    named: bool,
    addrs: Vec<SocketAddr>,
) -> Result<Vec<SocketAddr>, String> {
    if tls {
        return Ok(addrs);
    }
    if addrs.is_empty() || addrs.iter().any(|a| !a.ip().to_canonical().is_loopback()) {
        return Err(
            "plain http is only allowed to a center on this machine (loopback); use https".into(),
        );
    }
    if named {
        // `localhost` resolves to ::1 first; a center listening on IPv4 only
        // leaves [::1] on its port to whoever binds it.
        let v4: Vec<SocketAddr> = addrs
            .into_iter()
            .filter(|a| a.ip().to_canonical().is_ipv4())
            .collect();
        if v4.is_empty() {
            return Err(
                "plain http to a host name uses its IPv4 loopback address only, and this one has none: name the address (http://[::1]:<port>)".into(),
            );
        }
        return Ok(v4);
    }
    Ok(addrs)
}

/// Which user answers a loopback connection from `local` to `peer`, from
/// `/proc/net/tcp` and `tcp6`: another user's uid if any socket that may answer
/// is theirs, else this user's (`me`) or root's; `None` when that cannot be told.
#[cfg(target_os = "linux")]
pub fn peer_owner(local: SocketAddr, peer: SocketAddr, me: u32) -> Option<u32> {
    let read = |f: &str| std::fs::read_to_string(format!("/proc/net/{f}")).unwrap_or_default();
    owner_in_tables(&read("tcp"), &read("tcp6"), local, peer, me)
}

/// `peer_owner` on the tables' text.
///
/// The connection's server-side socket alone does not do: until it is accepted
/// (Linux 6.16 and earlier) the kernel lists it with uid 0, so another user's
/// program that has not called `accept` yet would pass as root. So every socket
/// listening where the connection could have arrived counts too (more than one
/// with `SO_REUSEPORT`), and there must be at least one, besides the
/// connection's own entry.
///
/// A socket has the family of its listener, not of the client's: a listener on
/// `[::]` (dual-stack) or `[::ffff:0.0.0.0]` takes an IPv4 connection on an
/// IPv6 socket, listed in `tcp6` under v4-mapped addresses, and a client that
/// names `[::ffff:127.0.0.1]` reaches an IPv4 listener, listed in `tcp`. So an
/// IPv4 connection, in either form, is looked up in both tables. The table its
/// entry is in says the family of the listener that took it, so only the
/// listeners in that table count (another user's IPv6-only `[::]` cannot have
/// taken a connection listed in `tcp`); an entry in both is a doubt, refused.
#[cfg(target_os = "linux")]
fn owner_in_tables(
    tcp: &str,
    tcp6: &str,
    local: SocketAddr,
    peer: SocketAddr,
    me: u32,
) -> Option<u32> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let v4 = |a: SocketAddr| SocketAddr::new(a.ip().to_canonical(), a.port());
    let mapped = |a: SocketAddr| match a.ip().to_canonical() {
        IpAddr::V4(ip) => SocketAddr::new(IpAddr::V6(ip.to_ipv6_mapped()), a.port()),
        ip => SocketAddr::new(ip, a.port()),
    };
    let port = peer.port();
    let any6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
    // Per table: the connection's addresses there, and where a listener may be.
    let mut tables = Vec::new();
    if v4(peer).is_ipv4() {
        let any4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
        tables.push((tcp, v4(peer), v4(local), vec![v4(peer), any4]));
        // An IPv6 socket on the mapped wildcard takes IPv4 connections to every
        // local address, beside an IPv6-only one on `[::]`.
        tables.push((
            tcp6,
            mapped(peer),
            mapped(local),
            vec![mapped(peer), mapped(any4), any6],
        ));
    } else {
        tables.push((tcp6, peer, local, vec![peer, any6]));
    }
    let rows = |table: &'_ str| -> Vec<(String, String, String, u32)> {
        table
            .lines()
            .skip(1)
            .filter_map(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                let uid = f.get(7)?.parse().ok()?;
                Some((
                    f.get(1)?.to_string(),
                    f.get(2)?.to_string(),
                    f.get(3)?.to_string(),
                    uid,
                ))
            })
            .collect()
    };
    let same = |a: &str, b: SocketAddr| a.eq_ignore_ascii_case(&proc_addr(b));
    // Per table: the uids of the connection's entries and of the listeners.
    let found: Vec<(Vec<u32>, Vec<u32>)> = tables
        .into_iter()
        .map(|(table, server, client, listen_at)| {
            let (mut entries, mut listeners) = (Vec::new(), Vec::new());
            for (l, r, state, uid) in rows(table) {
                if same(&l, server) && same(&r, client) {
                    entries.push(uid);
                }
                // State 0A is LISTEN.
                if state == "0A" && listen_at.iter().any(|&a| same(&l, a)) {
                    listeners.push(uid);
                }
            }
            (entries, listeners)
        })
        .filter(|(entries, _)| !entries.is_empty())
        .collect();
    let [(entries, listeners)] = found.as_slice() else {
        return None;
    };
    if listeners.is_empty() {
        return None;
    }
    let connection = entries[0];
    Some(
        entries
            .iter()
            .chain(listeners)
            .copied()
            .find(|&u| u != me && u != 0)
            .unwrap_or(connection),
    )
}

/// An address as `/proc/net/tcp` writes it: the address words in the kernel's
/// byte order, then the port.
#[cfg(target_os = "linux")]
fn proc_addr(a: SocketAddr) -> String {
    let ip = match a.ip() {
        std::net::IpAddr::V4(v4) => format!("{:08X}", u32::from_ne_bytes(v4.octets())),
        std::net::IpAddr::V6(v6) => v6
            .octets()
            .chunks(4)
            .map(|w| format!("{:08X}", u32::from_ne_bytes([w[0], w[1], w[2], w[3]])))
            .collect(),
    };
    format!("{ip}:{:04X}", a.port())
}

/// Plain http on Linux: the program that took the connection must belong to
/// this user or root, or it is not the center this user paired with, and would
/// get the pairing code and the link.
#[cfg(target_os = "linux")]
fn check_local_peer(tcp: &TcpStream) -> Result<(), String> {
    let (local, peer) = (
        tcp.local_addr().map_err(|e| e.to_string())?,
        tcp.peer_addr().map_err(|e| e.to_string())?,
    );
    // A test plays the listener of another user, which needs a second account.
    #[cfg(test)]
    if let Some(owner) = tests::FAKE_OWNER.with(std::cell::Cell::get) {
        return owner_verdict(owner, euid(), peer);
    }
    let me = euid();
    owner_verdict(peer_owner(local, peer, me), me, peer)
}

#[cfg(target_os = "linux")]
fn owner_verdict(owner: Option<u32>, me: u32, peer: SocketAddr) -> Result<(), String> {
    match owner {
        Some(uid) if uid == me || uid == 0 => Ok(()),
        Some(uid) => Err(format!(
            "{peer} is answered by a program of another user (uid {uid}), not of this user or root: plain http would hand it the pairing code and the link. If the center runs as another user, use https with its certificate pinned"
        )),
        None => Err(format!(
            "cannot tell which user's program answers on {peer}, so plain http sends nothing there; use https with a pinned certificate"
        )),
    }
}

/// An HTTP proxy the node reaches centers through with `CONNECT`
/// (docs/dev/spec/protocol.md §4.7). The tunnel only carries bytes: TLS to the center
/// runs inside it, pinned as without a proxy. An `https://` proxy, a relay
/// (§4.8) above all, is reached over TLS of its own, checked against `pin`
/// (else the system's roots), and the `CONNECT` runs inside that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proxy {
    pub host: String,
    pub port: u16,
    /// `https://`: the `CONNECT` goes over TLS to the proxy.
    pub tls: bool,
    /// The pin of the proxy's certificate, as a center's pin (§2.1).
    pub pin: Option<String>,
    /// Extra header lines for the `CONNECT` request (`Proxy-Authorization`, ...).
    pub headers: Vec<(String, String)>,
}

impl Proxy {
    /// `http://host:port` or `https://host:port`. A URL with a user name and
    /// password is refused without echoing it, since the error ends up in
    /// status lines and logs; `nerve-node proxy set` takes them out and
    /// keeps them as secrets.
    pub fn parse(s: &str, headers: Vec<(String, String)>) -> Result<Proxy, String> {
        if s.contains('@') {
            return Err("a proxy URL here holds no user name or password".into());
        }
        let u = CenterUrl::parse(s).map_err(|e| e.replace("center URL", "proxy URL"))?;
        if !u.base.is_empty() {
            return Err("a proxy URL has no path".into());
        }
        for (k, v) in &headers {
            if !valid_header_name(k) {
                return Err(format!("bad proxy header name {k:?}"));
            }
            if v.contains(['\r', '\n']) {
                return Err(format!("proxy header {k} holds a line break"));
            }
        }
        Ok(Proxy {
            host: u.host,
            port: u.port,
            tls: u.tls,
            pin: None,
            headers,
        })
    }

    /// The proxy with the pin of its certificate; only an `https://` proxy
    /// has one.
    pub fn pinned(mut self, pin: Option<String>) -> Result<Proxy, String> {
        if let Some(p) = &pin {
            if !self.tls {
                return Err("a proxy pin is for an https:// proxy".into());
            }
            crate::tls::decode_pin(p).map_err(|e| format!("bad proxy pin: {e}"))?;
        }
        self.pin = pin;
        Ok(self)
    }

    /// The proxy from `HTTPS_PROXY` (or `https_proxy`) for `host`, unless
    /// `NO_PROXY` names it; `Ok(None)` when none applies.
    pub fn from_env(host: &str) -> Result<Option<Proxy>, String> {
        let get = |k: &str| {
            std::env::var(k)
                .ok()
                .or_else(|| std::env::var(k.to_ascii_lowercase()).ok())
                .filter(|v| !v.trim().is_empty())
        };
        let Some(p) = get("HTTPS_PROXY") else {
            return Ok(None);
        };
        if no_proxy(get("NO_PROXY").as_deref().unwrap_or(""), host) {
            return Ok(None);
        }
        if p.contains('@') {
            return Err("HTTPS_PROXY holds a user name and password, which the node does not take from the environment; set the proxy with `nerve-node proxy set`".into());
        }
        Proxy::parse(p.trim(), Vec::new()).map(Some)
    }
}

/// Whether `k` can be a header name on the `CONNECT` request: letters,
/// digits and `-`.
pub fn valid_header_name(k: &str) -> bool {
    !k.is_empty() && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Whether a `NO_PROXY` list names `host`: `*`, the host itself, or a domain
/// suffix (`example.com` and `.example.com` both match `a.example.com`).
pub fn no_proxy(list: &str, host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    list.split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .any(|e| {
            let e = e.to_ascii_lowercase();
            let e = e.trim_start_matches('.');
            e == "*" || host == e || host.ends_with(&format!(".{e}"))
        })
}

async fn dial(
    host: &str,
    port: u16,
    addrs: Vec<SocketAddr>,
    until: Option<tokio::time::Instant>,
) -> Result<TcpStream, String> {
    let s = connect_first(addrs, until, TcpStream::connect)
        .await
        .map_err(|last| format!("cannot connect to {host}:{port}: {last}"))?;
    let _ = s.set_nodelay(true);
    Ok(s)
}

/// Tries `addrs` in turn until `connect` reaches one. Without `until` each
/// try has [`CONNECT_TIMEOUT`]. With it, each try has the time left divided
/// by the addresses left, so a first address that does not answer leaves
/// time for the next: a name with an AAAA record whose path drops packets
/// still reaches its A record before `until`. The error is the last try's.
pub async fn connect_first<T, F, Fut>(
    addrs: Vec<SocketAddr>,
    until: Option<tokio::time::Instant>,
    connect: F,
) -> Result<T, String>
where
    F: Fn(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<T>>,
{
    let mut last = String::from("no address");
    let n = addrs.len();
    for (i, a) in addrs.into_iter().enumerate() {
        let each = match until {
            None => CONNECT_TIMEOUT,
            Some(u) => {
                let left = u.saturating_duration_since(tokio::time::Instant::now());
                if left.is_zero() {
                    if i == 0 {
                        last = "no time left to connect".into();
                    }
                    break;
                }
                left / (n - i) as u32
            }
        };
        match tokio::time::timeout(each, connect(a)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last = format!("{a}: {e}"),
            Err(_) => last = format!("{a}: timed out"),
        }
    }
    Err(last)
}

/// Opens a `CONNECT` tunnel to `host:port` through `proxy`, over TLS to an
/// `https://` proxy. Fails closed: a proxy that refuses or answers oddly is
/// an error, never a direct connection.
async fn tunnel(
    proxy: &Proxy,
    host: &str,
    port: u16,
    until: Option<tokio::time::Instant>,
) -> Result<BoxIo, String> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((proxy.host.as_str(), proxy.port))
        .await
        .map_err(|e| format!("cannot resolve the proxy {}: {e}", proxy.host))?
        .collect();
    let tcp = dial(&proxy.host, proxy.port, addrs, until).await?;
    let mut io: BoxIo = if proxy.tls {
        let config = crate::tls::client_config(proxy.pin.as_deref())?;
        let name = ServerName::try_from(proxy.host.clone())
            .map_err(|_| format!("bad TLS server name {}", proxy.host))?;
        let tls = tokio::time::timeout(
            CONNECT_TIMEOUT,
            TlsConnector::from(config).connect(name, tcp),
        )
        .await
        .map_err(|_| {
            format!(
                "TLS handshake with the proxy {}:{} timed out",
                proxy.host, proxy.port
            )
        })?
        .map_err(|e| proxy_tls_error(proxy, &e))?;
        Box::new(tls)
    } else {
        Box::new(tcp)
    };
    ask_connect(&mut io, proxy, host, port).await?;
    Ok(io)
}

/// The `CONNECT` request and its answer on `io`.
async fn ask_connect(io: &mut BoxIo, proxy: &Proxy, host: &str, port: u16) -> Result<(), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let target = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    for (k, v) in &proxy.headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    io.write_all(req.as_bytes())
        .await
        .map_err(|e| format!("proxy: {e}"))?;
    io.flush().await.map_err(|e| format!("proxy: {e}"))?;
    // Read the answer byte by byte up to its blank line, so nothing of the
    // tunnelled stream is consumed.
    let mut head = Vec::new();
    let read = async {
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if head.len() > 8192 {
                return Err("proxy answer header over 8 KiB".to_string());
            }
            let n = io.read(&mut b).await.map_err(|e| format!("proxy: {e}"))?;
            if n == 0 {
                return Err("the proxy closed the connection".to_string());
            }
            head.push(b[0]);
        }
        Ok(())
    };
    tokio::time::timeout(CONNECT_TIMEOUT, read)
        .await
        .map_err(|_| "the proxy did not answer CONNECT in time".to_string())??;
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);
    match resp.parse(&head) {
        Ok(httparse::Status::Complete(_)) if resp.code.is_some_and(|c| (200..300).contains(&c)) => {
            Ok(())
        }
        Ok(httparse::Status::Complete(_)) => Err(format!(
            "the proxy refused the tunnel to {target}: {} {}",
            resp.code.unwrap_or(0),
            resp.reason.unwrap_or("")
        )),
        _ => Err("the proxy's answer is not HTTP".into()),
    }
}

/// A refused certificate of an `https://` proxy, in words.
fn proxy_tls_error(proxy: &Proxy, e: &std::io::Error) -> String {
    let refused = e
        .get_ref()
        .and_then(|i| i.downcast_ref::<rustls::Error>())
        .is_some_and(|r| matches!(r, rustls::Error::InvalidCertificate(_)));
    let at = format!("{}:{}", proxy.host, proxy.port);
    match (refused, proxy.pin.is_some()) {
        (true, true) => format!(
            "TLS with the proxy {at}: its certificate does not carry the pinned key; if it is a relay, `nerve-node relay` there shows its pin"
        ),
        (true, false) => format!(
            "TLS with the proxy {at}: its certificate is not one this machine trusts; give its pin with `nerve-node proxy set <url> --pin=<pin>`"
        ),
        _ => format!("TLS with the proxy {at}: {e}"),
    }
}

/// The connection under a link to `url`: through `proxy` for a TLS center,
/// else straight to the addresses [`usable_addrs`] lets it use. A relay
/// (docs/dev/spec/protocol.md §4.8) dials its centers this way too, so a relay
/// behind a proxy or another relay goes on through it.
pub async fn reach(url: &CenterUrl, proxy: Option<&Proxy>) -> Result<BoxIo, String> {
    reach_until(url, proxy, None).await
}

/// [`reach`] with every address it tries fitted into `until`
/// ([`connect_first`]): the relay, which must answer its node in time.
pub async fn reach_until(
    url: &CenterUrl,
    proxy: Option<&Proxy>,
    until: Option<tokio::time::Instant>,
) -> Result<BoxIo, String> {
    match proxy.filter(|_| url.tls) {
        Some(p) => tunnel(p, &url.host, url.port, until).await,
        None => Ok(Box::new(direct(url, until).await?)),
    }
}

/// A TCP connection straight to `url`.
async fn direct(url: &CenterUrl, until: Option<tokio::time::Instant>) -> Result<TcpStream, String> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((url.host.as_str(), url.port))
        .await
        .map_err(|e| format!("cannot resolve {}: {e}", url.host))?
        .collect();
    let named = url.host.parse::<std::net::IpAddr>().is_err();
    let addrs = usable_addrs(url.tls, named, addrs)?;
    dial(&url.host, url.port, addrs, until)
        .await
        .map_err(|e| format!("{url}: {e}"))
}

/// Opens a connection to the center: TLS (pinned when `pin` is set), or plain
/// TCP to a center on this machine. `proxy` is used for TLS centers only; a
/// loopback center is never reached through one.
pub async fn open(
    url: &CenterUrl,
    pin: Option<&str>,
    proxy: Option<&Proxy>,
) -> Result<BoxIo, String> {
    open_pins(url, pin.as_slice(), proxy).await
}

/// [`open`] for a center that may present any of `pins`: while a rotation
/// of its key is in its grace (docs/dev/spec/protocol.md §4.10) the node
/// takes the old pin and the new one. No pin: the system's roots.
pub async fn open_pins(
    url: &CenterUrl,
    pins: &[&str],
    proxy: Option<&Proxy>,
) -> Result<BoxIo, String> {
    open_pins_seen(url, pins, proxy).await.map(|(io, _)| io)
}

/// [`open_pins`], also giving the pin of the certificate the center showed
/// (`None` over plain HTTP): a link opened under an old pin ends when that
/// pin stops counting (docs/dev/spec/protocol.md §4.10).
pub async fn open_pins_seen(
    url: &CenterUrl,
    pins: &[&str],
    proxy: Option<&Proxy>,
) -> Result<(BoxIo, Option<String>), String> {
    if !url.tls {
        let tcp = direct(url, None).await?;
        #[cfg(target_os = "linux")]
        check_local_peer(&tcp)?;
        return Ok((Box::new(tcp), None));
    }
    let tcp = reach(url, proxy).await?;
    let config = crate::tls::client_config_pins(pins)?;
    let name = ServerName::try_from(url.host.clone())
        .map_err(|_| format!("bad TLS server name {}", url.host))?;
    let tls = tokio::time::timeout(
        CONNECT_TIMEOUT,
        TlsConnector::from(config).connect(name, tcp),
    )
    .await
    .map_err(|_| format!("TLS handshake with {url} timed out"))?
    .map_err(|e| tls_error(url, !pins.is_empty(), &e))?;
    let seen = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
        .and_then(|c| crate::tls::pin_of_cert(c.as_ref()));
    Ok((Box::new(tls), seen))
}

/// This process's effective user id (0 off Unix).
pub fn euid() -> u32 {
    #[cfg(unix)]
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe {
        libc::geteuid()
    }
    #[cfg(not(unix))]
    0
}

/// What a refused pinned certificate's message says, so a caller can tell
/// that refusal apart (and add what to do, which depends on how often it
/// happened: right after a rotation of the center's key the center may not
/// serve the new key yet).
pub const PIN_REFUSED: &str = "does not carry the key pinned at pairing";

/// What to do about a pinned certificate refused again and again.
pub const PIN_ADVICE: &str = "If the center got a new key and this node missed its rotation (it was away longer than the grace), pair again with a new pairing link.";

/// A refused certificate in words that say what happened and what to do; rustls
/// alone says `ApplicationVerificationFailure` or `CaUsedAsEndEntity`.
fn tls_error(url: &CenterUrl, pinned: bool, e: &std::io::Error) -> String {
    let refused = e
        .get_ref()
        .and_then(|i| i.downcast_ref::<rustls::Error>())
        .and_then(|r| match r {
            rustls::Error::InvalidCertificate(c) => Some(c),
            _ => None,
        });
    match refused {
        Some(_) if pinned => format!(
            "TLS with {url}: the center's certificate {PIN_REFUSED}. Its key changed (a new certificate), or another server answers there."
        ),
        Some(c) => {
            use rustls::CertificateError as C;
            let why = match c {
                C::Expired | C::ExpiredContext { .. } => "it has expired".to_string(),
                C::NotValidForName | C::NotValidForNameContext { .. } => {
                    "it is made out to another name".to_string()
                }
                // webpki's reason comes wrapped in `Other`, and this crate does not
                // depend on webpki to match it.
                C::UnknownIssuer => "no authority this machine knows signed it".to_string(),
                C::Other(o) if format!("{o:?}").contains("CaUsedAsEndEntity") => {
                    "it is self-signed".to_string()
                }
                other => other.to_string(),
            };
            format!(
                "TLS with {url}: the center's certificate is not one this machine trusts ({why}), and the pairing carries no pin for it. For a self-signed certificate, open the center over https once and pair with a link that carries its pin."
            )
        }
        None => format!("TLS with {url}: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    thread_local! {
        /// The owner `check_local_peer` finds instead of the real one, on this
        /// thread (a `#[tokio::test]` runs on one): `Some(None)` for an owner it
        /// cannot tell.
        pub(super) static FAKE_OWNER: std::cell::Cell<Option<Option<u32>>> =
            const { std::cell::Cell::new(None) };
    }

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn plain_http_only_reaches_loopback() {
        assert!(usable_addrs(false, false, vec![a("127.0.0.1:80")]).is_ok());
        assert!(usable_addrs(false, false, vec![a("[::1]:80")]).is_ok());
        assert!(usable_addrs(false, false, vec![a("[::ffff:127.0.0.1]:80")]).is_ok());
        // A name that resolves to loopback and to another machine is refused whole.
        assert!(usable_addrs(false, true, vec![a("127.0.0.1:80"), a("192.0.2.7:80")]).is_err());
        assert!(usable_addrs(false, true, vec![a("192.0.2.7:80")]).is_err());
        assert!(usable_addrs(false, true, vec![]).is_err());
        assert!(usable_addrs(true, true, vec![a("192.0.2.7:443")]).is_ok());
    }

    #[test]
    fn a_name_takes_only_its_ipv4_loopback_address() {
        // `localhost` as getaddrinfo gives it: ::1 first.
        assert_eq!(
            usable_addrs(false, true, vec![a("[::1]:80"), a("127.0.0.1:80")]).unwrap(),
            vec![a("127.0.0.1:80")]
        );
        assert!(usable_addrs(false, true, vec![a("[::1]:80")]).is_err());
    }

    /// With the center on 127.0.0.1 and another user's program on [::1] at
    /// the same port, `localhost` reaches the center.
    #[tokio::test]
    async fn localhost_reaches_the_ipv4_center_not_a_listener_on_ipv6() {
        let v4 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = v4.local_addr().unwrap().port();
        let Ok(v6) = tokio::net::TcpListener::bind(("::1", port)).await else {
            eprintln!("  (no IPv6 loopback here; nothing to show)");
            return;
        };
        let resolved: Vec<SocketAddr> = tokio::net::lookup_host(("localhost", port))
            .await
            .unwrap()
            .collect();
        if !resolved.iter().any(SocketAddr::is_ipv6) {
            eprintln!("  (localhost has no IPv6 address here; nothing to show)");
            return;
        }
        let url = CenterUrl::parse(&format!("http://localhost:{port}")).unwrap();
        let _io = open(&url, None, None).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), v4.accept()).await;
        assert!(got.is_ok(), "the IPv4 listener was not reached");
        let other = tokio::time::timeout(Duration::from_millis(200), v6.accept()).await;
        assert!(other.is_err(), "the IPv6 listener got the connection");
    }

    /// The owner of the far end of a loopback connection is read right: here this
    /// process, so this user.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_far_end_of_a_loopback_connection_has_an_owner() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
        let (local, peer) = (c.local_addr().unwrap(), c.peer_addr().unwrap());
        let me = euid();
        assert_eq!(peer_owner(local, peer, me), Some(me));
        assert!(check_local_peer(&c).is_ok());
        // Another connection's addresses are not this one.
        let other = SocketAddr::new(local.ip(), local.port().wrapping_add(1).max(1));
        assert_eq!(peer_owner(other, peer, me), None);
        // A program of another user is refused, one of root taken.
        assert!(owner_verdict(Some(me + 1), me, peer).is_err());
        assert!(owner_verdict(None, me, peer).is_err());
        assert!(owner_verdict(Some(0), me, peer).is_ok());
        if let Ok(l6) = tokio::net::TcpListener::bind("[::1]:0").await {
            let c = TcpStream::connect(l6.local_addr().unwrap()).await.unwrap();
            let (local, peer) = (c.local_addr().unwrap(), c.peer_addr().unwrap());
            assert_eq!(peer_owner(local, peer, me), Some(me));
        }
    }

    /// A line of `/proc/net/tcp[6]` as the kernel writes it.
    #[cfg(target_os = "linux")]
    fn row(local: &str, remote: &str, state: &str, uid: u32) -> String {
        format!(
            "   0: {} {} {state} 00000000:00000000 00:00000000 00000000 {uid:>5}        0 4242 1 0000000000000000 20 4 30 10 -1",
            proc_addr(a(local)),
            proc_addr(a(remote))
        )
    }

    #[cfg(target_os = "linux")]
    fn table(rows: &[String]) -> String {
        let head = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
        std::iter::once(head.to_string())
            .chain(rows.iter().cloned())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Up to Linux 6.16 a connection that is not accepted yet is listed with uid 0.
    /// Another user's program that holds off `accept` must not pass as root: the
    /// listeners where the connection could have arrived decide too.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_connection_not_yet_accepted_is_judged_by_its_listeners() {
        const ME: u32 = 1000;
        const OTHER: u32 = 1001;
        let (client, server) = ("127.0.0.1:50000", "127.0.0.1:8080");
        let conn = |uid| row(server, client, "01", uid);
        // The same connection taken by an IPv6 listener, listed in tcp6.
        let conn_m = |uid| {
            row(
                "[::ffff:127.0.0.1]:8080",
                "[::ffff:127.0.0.1]:50000",
                "01",
                uid,
            )
        };
        let mine = row(client, server, "01", ME);
        let listen = |at: &str, uid| row(at, "0.0.0.0:0", "0A", uid);
        let listen6 = |at: &str, uid| row(at, "[::]:0", "0A", uid);
        let owner = |tcp: &[String], tcp6: &[String]| {
            owner_in_tables(&table(tcp), &table(tcp6), a(client), a(server), ME)
        };
        // Another user's listener, on the address or on 0.0.0.0, or for an IPv6
        // socket dual-stack on [::], on the v4-mapped address or on the mapped
        // wildcard (beside this user's IPv6-only [::]).
        assert_eq!(
            owner(&[mine.clone(), conn(0), listen(server, OTHER)], &[]),
            Some(OTHER)
        );
        assert_eq!(
            owner(&[conn(0), listen("0.0.0.0:8080", OTHER)], &[]),
            Some(OTHER)
        );
        assert_eq!(
            owner(
                std::slice::from_ref(&mine),
                &[conn_m(0), listen6("[::]:8080", OTHER)]
            ),
            Some(OTHER)
        );
        assert_eq!(
            owner(&[], &[conn_m(0), listen6("[::ffff:127.0.0.1]:8080", OTHER)]),
            Some(OTHER)
        );
        assert_eq!(
            owner(
                std::slice::from_ref(&mine),
                &[
                    conn_m(0),
                    listen6("[::]:8080", ME),
                    listen6("[::ffff:0.0.0.0]:8080", OTHER)
                ]
            ),
            Some(OTHER)
        );
        // The family of the connection's entry is its listener's: another user's
        // IPv6 listener cannot have taken a connection listed in tcp.
        assert_eq!(
            owner(
                &[conn(0), listen(server, ME)],
                &[listen6("[::]:8080", OTHER)]
            ),
            Some(0)
        );
        assert_eq!(owner(&[conn(0)], &[listen6("[::]:8080", ME)]), None);
        // An entry in both tables is a doubt.
        assert_eq!(
            owner(
                &[conn(0), listen(server, ME)],
                &[conn_m(0), listen6("[::]:8080", ME)]
            ),
            None
        );
        // SO_REUSEPORT: every listener on the port counts.
        assert_eq!(
            owner(&[conn(ME), listen(server, ME), listen(server, OTHER)], &[]),
            Some(OTHER)
        );
        // No listener, or no entry for the connection: who answers is unknown.
        assert_eq!(owner(&[mine.clone(), conn(0)], &[]), None);
        assert_eq!(owner(&[mine.clone(), listen(server, ME)], &[]), None);
        // This user's or root's listener; others' elsewhere do not matter.
        let others = [
            listen("127.0.0.1:8081", OTHER),
            listen("127.0.0.2:8080", OTHER),
        ];
        let mut rows = vec![mine, conn(0), listen(server, ME)];
        rows.extend(others.iter().cloned());
        assert_eq!(owner(&rows, &[listen6("[::1]:8080", OTHER)]), Some(0));
        assert!(owner_verdict(owner(&rows, &[]), ME, a(server)).is_ok());
        assert_eq!(owner(&[conn(ME), listen(server, 0)], &[]), Some(ME));
        // Each refused by the verdict.
        for refused in [Some(OTHER), None] {
            assert!(owner_verdict(refused, ME, a(server)).is_err());
        }
        // An IPv6 connection: [::] and its own address count, IPv4 does not.
        let (c6, s6) = ("[::1]:50000", "[::1]:8080");
        let owner6 = |tcp: &[String], tcp6: &[String]| {
            owner_in_tables(&table(tcp), &table(tcp6), a(c6), a(s6), ME)
        };
        let conn6 = row(s6, c6, "01", 0);
        assert_eq!(
            owner6(&[], &[conn6.clone(), listen6(s6, OTHER)]),
            Some(OTHER)
        );
        assert_eq!(
            owner6(&[], &[conn6.clone(), listen6("[::]:8080", OTHER)]),
            Some(OTHER)
        );
        assert_eq!(
            owner6(&[listen("0.0.0.0:8080", OTHER)], &[conn6, listen6(s6, ME)]),
            Some(0)
        );
    }

    /// A center of this user that listens dual-stack on `[::]` (Node's bare
    /// `listen(port)`, Go's `":port"`) is reached over IPv4, and one on IPv4
    /// through the v4-mapped form of its address: the owner is found in the
    /// other table, and plain http goes through.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn plain_http_reaches_this_users_center_in_either_address_family() {
        let open_ok = |url: String| async move {
            let url = CenterUrl::parse(&url).unwrap();
            open(&url, None, None).await.map(|_| ())
        };
        if let Ok(dual) = tokio::net::TcpListener::bind("[::]:0").await {
            let port = dual.local_addr().unwrap().port();
            // Dual-stack unless the system set `net.ipv6.bindv6only`.
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                assert_eq!(open_ok(format!("http://127.0.0.1:{port}")).await, Ok(()));
                assert_eq!(open_ok(format!("http://localhost:{port}")).await, Ok(()));
                assert_eq!(
                    open_ok(format!("http://[::ffff:127.0.0.1]:{port}")).await,
                    Ok(())
                );
            } else {
                eprintln!("  (IPv6 sockets are IPv6 only here; no dual-stack listener)");
            }
        }
        let v4 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = v4.local_addr().unwrap().port();
        assert_eq!(
            open_ok(format!("http://[::ffff:127.0.0.1]:{port}")).await,
            Ok(())
        );
        assert_eq!(open_ok(format!("http://127.0.0.1:{port}")).await, Ok(()));
    }

    /// `open` hands out no plain-http connection that another user's program
    /// answers, or one whose owner it cannot tell; TLS is not checked.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn plain_http_is_refused_when_another_user_answers() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = CenterUrl::parse(&format!(
            "http://127.0.0.1:{}",
            l.local_addr().unwrap().port()
        ))
        .unwrap();
        let me = euid();
        for (owner, refused) in [
            (Some(me + 1), true),
            (None, true),
            (Some(me), false),
            (Some(0), false),
        ] {
            FAKE_OWNER.with(|f| f.set(Some(owner)));
            let got = open(&url, None, None).await;
            FAKE_OWNER.with(|f| f.set(None));
            assert_eq!(got.is_err(), refused, "owner {owner:?}");
        }
    }

    /// Within a deadline every address gets its share: a first one that
    /// never answers leaves time for the next, which is reached before the
    /// deadline.
    #[tokio::test]
    async fn every_address_gets_a_share_of_the_deadline() {
        let (dead, live) = (a("[2001:db8::1]:443"), a("192.0.2.1:443"));
        let connect = |addr: SocketAddr| async move {
            if addr == dead {
                std::future::pending::<()>().await;
            }
            Ok::<SocketAddr, std::io::Error>(addr)
        };
        let started = tokio::time::Instant::now();
        let until = started + Duration::from_millis(1200);
        let got = connect_first(vec![dead, live], Some(until), connect).await;
        assert_eq!(got, Ok(live));
        let took = started.elapsed();
        assert!(
            took >= Duration::from_millis(500) && took < Duration::from_millis(1200),
            "{took:?}"
        );
        // All of them dead: an error by the deadline, naming the last.
        let until = tokio::time::Instant::now() + Duration::from_millis(600);
        let both = connect_first(vec![dead, dead], Some(until), connect).await;
        assert!(both.unwrap_err().contains("timed out"));
        assert!(tokio::time::Instant::now() < until + Duration::from_millis(300));
    }

    #[test]
    fn no_proxy_lists() {
        assert!(no_proxy("*", "a"));
        assert!(no_proxy("example.com", "a.example.com"));
        assert!(no_proxy(" .example.com ,x", "example.com"));
        assert!(!no_proxy("example.com", "badexample.com"));
        assert!(!no_proxy("", "a"));
    }

    #[test]
    fn proxy_urls() {
        assert_eq!(
            Proxy::parse("http://p.example:3128", vec![]).unwrap().port,
            3128
        );
        let tls = Proxy::parse("https://p.example:7490", vec![]).unwrap();
        assert!(tls.tls);
        assert!(tls.clone().pinned(Some("A".repeat(43))).is_ok());
        assert!(tls.pinned(Some("short".into())).is_err());
        let plain = Proxy::parse("http://p.example:3128", vec![]).unwrap();
        assert!(plain.pinned(Some("A".repeat(43))).is_err());
        assert!(Proxy::parse("http://p.example/x", vec![]).is_err());
        assert!(Proxy::parse("http://p", vec![("A".into(), "b\r\nX: y".into())]).is_err());
        assert!(Proxy::parse("http://p", vec![("A B".into(), "b".into())]).is_err());
        // A user name and password are refused without being echoed.
        let e = Proxy::parse("http://u:hunter2@p.example:3128", vec![]).unwrap_err();
        assert!(!e.contains("hunter2"), "{e}");
    }

    /// An https:// proxy is reached over TLS checked against its pin, and the
    /// CONNECT with its headers travels inside that TLS; a wrong pin sends
    /// nothing.
    #[tokio::test]
    async fn an_https_proxy_takes_the_connect_inside_pinned_tls() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        crate::init_crypto();
        let id = crate::tls::ServerIdentity::generate(&["127.0.0.1".into()]).unwrap();
        let acceptor = crate::tls::Acceptor::new(&id).unwrap();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (tcp, _) = l.accept().await.unwrap();
            let mut s = acceptor.accept(tcp).await.unwrap();
            let req = crate::http::read_request_head(&mut s).await.unwrap();
            assert_eq!(
                (req.method.as_str(), req.path.as_str()),
                ("CONNECT", "c.example:443")
            );
            assert_eq!(req.header("proxy-authorization"), Some("Basic x"));
            s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\ntunnelled")
                .await
                .unwrap();
            s.flush().await.unwrap();
            // A client with the wrong pin ends the handshake.
            let (tcp, _) = l.accept().await.unwrap();
            assert!(acceptor.accept(tcp).await.is_err());
        });
        let p = Proxy::parse(
            &format!("https://127.0.0.1:{port}"),
            vec![("Proxy-Authorization".into(), "Basic x".into())],
        )
        .unwrap();
        let mut t = tunnel(
            &p.clone().pinned(Some(id.pin())).unwrap(),
            "c.example",
            443,
            None,
        )
        .await
        .unwrap();
        let mut got = [0u8; 9];
        t.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"tunnelled");
        let other = crate::tls::ServerIdentity::generate(&[]).unwrap().pin();
        let e = tunnel(&p.pinned(Some(other)).unwrap(), "c.example", 443, None)
            .await
            .err()
            .unwrap();
        assert!(e.contains("does not carry the pinned key"), "{e}");
        server.await.unwrap();
    }

    /// A proxy that grants the tunnel carries bytes; one that refuses fails
    /// closed, with nothing sent anywhere else.
    #[tokio::test]
    async fn connect_tunnels() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            for answer in [
                "HTTP/1.1 200 Connection established\r\n\r\n",
                "HTTP/1.1 407 Auth\r\n\r\n",
            ] {
                let (mut s, _) = l.accept().await.unwrap();
                let mut buf = vec![0u8; 1024];
                let n = s.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                assert!(req.starts_with("CONNECT c.example:443 HTTP/1.1\r\n"));
                assert!(req.contains("Proxy-Authorization: Basic x\r\n"));
                s.write_all(answer.as_bytes()).await.unwrap();
                s.write_all(b"tunnelled").await.unwrap();
            }
        });
        let p = Proxy::parse(
            &format!("http://127.0.0.1:{port}"),
            vec![("Proxy-Authorization".into(), "Basic x".into())],
        )
        .unwrap();
        let mut t = tunnel(&p, "c.example", 443, None).await.unwrap();
        let mut got = [0u8; 9];
        t.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"tunnelled");
        let e = tunnel(&p, "c.example", 443, None).await.err().unwrap();
        assert!(e.contains("407"), "{e}");
        server.await.unwrap();
    }
}
