//! Listening sockets: plain TCP on loopback or TLS with the center's
//! identity, and the node endpoints on them (spec §3 pairing, §4 connect).
//!
//! Every listener takes each connection at once and decides on it before a
//! byte is read: a connection that is not decided yet holds one of
//! [`UNDECIDED`] slots and one of its peer's [`PER_PEER`] places (and of its
//! IPv6 /64's [`PER_PREFIX`]), or it is closed. One peer that opens many
//! connections and sends nothing so fills only its own places, not the
//! port. A node's link gives both back once its hello is verified, so the
//! links of the paired nodes never count against a peer.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsAcceptor;

use nerve_proto::{CONNECT_PATH, NODE_HEADER, PAIR_CHECK_PATH, PAIR_PATH};
use nerve_transport::http::{self, Request, Response};
use nerve_transport::net::BoxIo;

use crate::center::Center;

/// Connections per listener that are not decided yet: a request that is
/// read or answered, a TLS handshake, a link before its hello is verified.
/// Past it a new connection is closed at once.
pub const UNDECIDED: usize = 256;
/// Of those, from one address. A browser opens six at once for a page, and
/// many nodes behind one router link one by one.
pub const PER_PEER: usize = 16;
/// Of those, from one IPv6 /64 (link-local addresses aside): a machine that
/// gives itself many addresses there cannot take them all.
pub const PER_PREFIX: usize = 64;
/// The largest pairing request body.
const PAIR_BODY: usize = 16 * 1024;

/// Binds a TCP listener.
pub async fn tcp(addr: &str) -> Result<TcpListener, String> {
    TcpListener::bind(addr)
        .await
        .map_err(|e| format!("cannot listen on {addr}: {e}"))
}

/// A bound listener that hands each accepted connection, after TLS with the
/// center's key when it has one, to a handler.
pub struct Server {
    pub listener: TcpListener,
    /// The center whose key TLS uses, taken anew for each connection: a
    /// rotation of the key (docs/dev/spec/protocol.md §4.10) changes it
    /// while the listener runs.
    tls: Option<Center>,
    /// Undecided connections at most ([`UNDECIDED`]).
    slots: usize,
}

/// The places taken now, by address and by /64.
#[derive(Default)]
struct Places {
    peers: HashMap<IpAddr, usize>,
    prefixes: HashMap<IpAddr, usize>,
}

/// An undecided connection's slot and its peer's place, given back when it
/// is dropped (or when the handler calls [`Admitted::decided`]).
pub struct Admitted {
    /// The peer's address.
    pub peer: SocketAddr,
    held: Option<(OwnedSemaphorePermit, Arc<Mutex<Places>>)>,
}

impl Admitted {
    /// The connection is decided (a node's verified link): its slot and
    /// its peer's place are free for others.
    pub fn decided(&mut self) {
        self.give_back();
    }

    fn give_back(&mut self) {
        let Some((_permit, places)) = self.held.take() else {
            return;
        };
        let ip = self.peer.ip().to_canonical();
        let mut p = places.lock().unwrap_or_else(|e| e.into_inner());
        let give = |map: &mut HashMap<IpAddr, usize>, key| {
            if let Some(n) = map.get_mut(&key) {
                *n -= 1;
                if *n == 0 {
                    map.remove(&key);
                }
            }
        };
        give(&mut p.peers, ip);
        if let Some(prefix) = prefix_of(ip) {
            give(&mut p.prefixes, prefix);
        }
    }

    /// One that holds nothing, for a test that calls a handler itself.
    #[doc(hidden)]
    pub fn for_test(peer: SocketAddr) -> Admitted {
        Admitted { peer, held: None }
    }
}

impl Drop for Admitted {
    fn drop(&mut self) {
        self.give_back();
    }
}

/// The /64 an IPv6 address is counted in besides itself; none for IPv4,
/// loopback and link-local addresses (their scope is not in the address, so
/// one /64 there would be every link).
fn prefix_of(ip: IpAddr) -> Option<IpAddr> {
    match ip.to_canonical() {
        IpAddr::V6(v6) if !v6.is_loopback() && (v6.segments()[0] & 0xffc0) != 0xfe80 => {
            let mut o = v6.octets();
            o[8..].fill(0);
            Some(IpAddr::V6(o.into()))
        }
        _ => None,
    }
}

/// A slot and a place for a connection of `peer`, if both are free.
fn admit(
    slots: &Arc<Semaphore>,
    places: &Arc<Mutex<Places>>,
    peer: SocketAddr,
) -> Option<Admitted> {
    let ip = peer.ip().to_canonical();
    let prefix = prefix_of(ip);
    let mut p = places.lock().unwrap_or_else(|e| e.into_inner());
    if p.peers.get(&ip).copied().unwrap_or(0) >= PER_PEER
        || prefix.is_some_and(|x| p.prefixes.get(&x).copied().unwrap_or(0) >= PER_PREFIX)
    {
        return None;
    }
    let permit = slots.clone().try_acquire_owned().ok()?;
    *p.peers.entry(ip).or_insert(0) += 1;
    if let Some(x) = prefix {
        *p.prefixes.entry(x).or_insert(0) += 1;
    }
    Some(Admitted {
        peer,
        held: Some((permit, places.clone())),
    })
}

impl Server {
    /// Binds `addr`. TLS is used unless `plain` is set, and plain is only
    /// allowed on a loopback address.
    pub async fn bind(addr: &str, center: &Center, plain: bool) -> Result<Server, String> {
        Server::from_listener(tcp(addr).await?, center, plain)
    }

    /// Wraps a listener bound earlier (the node port is bound before the
    /// center opens, so the public URL can carry the real port).
    pub fn from_listener(
        listener: TcpListener,
        center: &Center,
        plain: bool,
    ) -> Result<Server, String> {
        let local = listener.local_addr().map_err(|e| e.to_string())?;
        if plain && !local.ip().is_loopback() {
            return Err(format!(
                "{local} is not a loopback address; plain HTTP is only served on loopback"
            ));
        }
        let tls = (!plain).then(|| center.clone());
        Ok(Server {
            listener,
            tls,
            slots: UNDECIDED,
        })
    }

    /// Fewer undecided connections, so a test can fill them.
    #[cfg(test)]
    fn with_slots(mut self, n: usize) -> Server {
        self.slots = n;
        self
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.listener
            .local_addr()
            .expect("a bound listener has an address")
    }

    /// Accepts connections until the task is dropped. Each one is admitted
    /// first ([`UNDECIDED`], [`PER_PEER`], [`PER_PREFIX`]) or closed at once;
    /// the handler gets its slot with it, and may give it back early.
    pub async fn run<F, Fut>(self, handler: F)
    where
        F: Fn(BoxIo, Admitted) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let handler = Arc::new(handler);
        let slots = Arc::new(Semaphore::new(self.slots));
        let places = Arc::new(Mutex::new(Places::default()));
        loop {
            let (tcp, peer) = match self.listener.accept().await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("accept failed: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };
            let Some(admitted) = admit(&slots, &places, peer) else {
                tracing::debug!("closed a connection from {peer}: no free place for it");
                continue;
            };
            let _ = tcp.set_nodelay(true);
            let tls = self.tls.clone();
            let handler = handler.clone();
            tokio::spawn(async move {
                let io: BoxIo = match tls {
                    None => Box::new(tcp),
                    Some(center) => {
                        let acc = TlsAcceptor::from(center.server_config());
                        let hs = tokio::time::timeout(http::HEAD_TIMEOUT, acc.accept(tcp)).await;
                        match hs {
                            Ok(Ok(s)) => Box::new(s),
                            _ => return,
                        }
                    }
                };
                handler(io, admitted).await;
            });
        }
    }
}

/// Serves the node endpoints on `server`.
pub async fn serve_nodes(center: Center, server: Server) {
    server
        .run(move |io, admitted| {
            let center = center.clone();
            async move { node_conn(center, io, admitted).await }
        })
        .await
}

async fn node_conn(center: Center, mut io: BoxIo, admitted: Admitted) {
    let req = match http::read_request(&mut io, PAIR_BODY).await {
        Ok(r) => r,
        Err(_) => {
            let _ = Response::text(400, "bad request").write(&mut io).await;
            return;
        }
    };
    match (req.method.as_str(), req.path.as_str()) {
        ("POST", PAIR_PATH) => {
            let (status, body) = center.pair(&req.body);
            let _ = Response::json(status, &body).write(&mut io).await;
        }
        ("POST", PAIR_CHECK_PATH) => {
            let (status, body) = center.pair_check(&req.body);
            let _ = Response::json(status, &body).write(&mut io).await;
        }
        ("GET", CONNECT_PATH) if req.is_upgrade() => connect(center, io, req, admitted).await,
        _ => {
            let _ = Response::text(404, "not found").write(&mut io).await;
        }
    }
}

async fn connect(center: Center, mut io: BoxIo, req: Request, admitted: Admitted) {
    let node_id = req.header(NODE_HEADER).unwrap_or("").to_string();
    if !center.knows(&node_id) {
        // Anyone can send this, so it is detail; a node removed here and
        // still dialling stops after the answer.
        center.log().record(
            nerve_transport::log::Level::Debug,
            None,
            &format!(
                "a node that is not paired tried to connect (id {})",
                crate::util::clip(&node_id, 64)
            ),
        );
        // §4.1: an unknown node is told so before any handshake, and stops
        // dialling.
        let _ = Response::json(
            401,
            &serde_json::json!({"error": "this node is not paired with this center"}),
        )
        .write(&mut io)
        .await;
        return;
    }
    match nerve_transport::ws::accept(io, &req, nerve_proto::limits::MESSAGE_BYTES as usize).await {
        Ok(ws) => crate::link::run(center, ws, node_id, admitted).await,
        Err(e) => center.log().record(
            nerve_transport::log::Level::Debug,
            None,
            &format!("a WebSocket upgrade failed: {e}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn center(dir: &std::path::Path) -> Center {
        nerve_transport::init_crypto();
        Center::open(crate::center::Options {
            state_dir: dir.to_path_buf(),
            name: None,
            public_url: "http://127.0.0.1:7443".into(),
            log: None,
            log_level: None,
        })
        .unwrap()
    }

    /// One peer that opens more connections than the port has slots, and
    /// sends nothing on them, holds only its own places: another peer's
    /// pair check is answered at once, and the peer's extra connections are
    /// closed at once instead of waiting. Before, it held the port shut.
    #[tokio::test]
    async fn one_peer_cannot_hold_the_node_port_shut() {
        let dir = tempfile::tempdir().unwrap();
        let c = center(dir.path());
        let server = Server::bind("127.0.0.1:0", &c, true).await.unwrap();
        let addr = server.local_addr();
        let task = tokio::spawn(serve_nodes(c.clone(), server));
        let mut idle = Vec::new();
        for _ in 0..UNDECIDED + 8 {
            idle.push(tokio::net::TcpStream::connect(addr).await.unwrap());
        }
        // Past its places, a connection of that peer is closed unread.
        let mut last = idle.pop().unwrap();
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(5), last.read(&mut buf))
            .await
            .expect("the extra connection was held open")
            .unwrap_or(0);
        assert_eq!(n, 0);
        // Another address of this machine is another peer.
        let other = tokio::net::TcpSocket::new_v4().unwrap();
        other.bind("127.0.0.2:0".parse().unwrap()).unwrap();
        let mut io = other.connect(addr).await.unwrap();
        let body = r#"{"code":"nope"}"#;
        io.write_all(
            format!(
                "POST {PAIR_CHECK_PATH} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut answer = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), io.read_to_end(&mut answer))
            .await
            .expect("the pair check was not answered")
            .unwrap();
        assert!(answer.starts_with(b"HTTP/1.1 200"), "{answer:?}");
        drop(idle);
        task.abort();
    }

    /// The places of an IPv4 peer, an IPv6 peer and its /64.
    #[test]
    fn places_are_by_address_and_by_64() {
        let slots = Arc::new(Semaphore::new(UNDECIDED));
        let places = Arc::new(Mutex::new(Places::default()));
        let at = |s: &str| -> SocketAddr { s.parse().unwrap() };
        let held: Vec<Admitted> = (0..PER_PEER)
            .map(|_| admit(&slots, &places, at("192.0.2.1:1")).unwrap())
            .collect();
        assert!(admit(&slots, &places, at("192.0.2.1:2")).is_none());
        // An IPv4 address that IPv6 carries is that address.
        assert!(admit(&slots, &places, at("[::ffff:192.0.2.1]:3")).is_none());
        assert!(admit(&slots, &places, at("192.0.2.2:1")).is_some());
        // Many addresses of one /64 share its places; another /64 has its own.
        let mut prefix = Vec::new();
        for i in 0..PER_PREFIX {
            prefix.push(
                admit(
                    &slots,
                    &places,
                    at(&format!("[2001:db8:1:2::{:x}]:1", i + 1)),
                )
                .unwrap(),
            );
        }
        assert!(admit(&slots, &places, at("[2001:db8:1:2::ffff]:1")).is_none());
        assert!(admit(&slots, &places, at("[2001:db8:1:3::1]:1")).is_some());
        // A decided connection gives its place back.
        let mut one = prefix.pop().unwrap();
        one.decided();
        assert!(admit(&slots, &places, at("[2001:db8:1:2::ffff]:1")).is_some());
        drop((held, prefix, one));
        let p = places.lock().unwrap();
        assert!(p.peers.is_empty() && p.prefixes.is_empty());
    }

    /// A peer that asks for an answer and reads none of it gives its
    /// connection back after the write's timeout, so the next one is
    /// served: with every slot held by such peers the port answered
    /// nobody, for good (issue #150).
    #[tokio::test]
    async fn a_peer_that_reads_nothing_gives_its_slot_back() {
        let dir = tempfile::tempdir().unwrap();
        nerve_transport::init_crypto();
        let center = Center::open(crate::center::Options {
            state_dir: dir.path().to_path_buf(),
            name: None,
            public_url: "http://127.0.0.1:7443".into(),
            log: None,
            log_level: None,
        })
        .unwrap();
        let server = Server::bind("127.0.0.1:0", &center, true)
            .await
            .unwrap()
            .with_slots(1);
        let addr = server.local_addr();
        // More than the kernel buffers of both ends hold.
        let big = Arc::new(vec![b'x'; 32 * 1024 * 1024]);
        let task = tokio::spawn(server.run(move |mut io, _admitted| {
            let big = big.clone();
            async move {
                let Ok(req) = http::read_request(&mut io, 0).await else {
                    return;
                };
                let body = if req.path == "/big" {
                    big.to_vec()
                } else {
                    b"ok".to_vec()
                };
                let _ = Response::new(200, "text/plain", body).write(&mut io).await;
            }
        }));
        let sock = tokio::net::TcpSocket::new_v4().unwrap();
        sock.set_recv_buffer_size(4096).unwrap();
        let mut stuck = sock.connect(addr).await.unwrap();
        stuck
            .write_all(b"GET /big HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        // Let the server start its answer, which fills both buffers.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let t = Instant::now();
        let mut next = tokio::net::TcpStream::connect(addr).await.unwrap();
        next.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut answer = Vec::new();
        tokio::time::timeout(http::HEAD_TIMEOUT * 3, next.read_to_end(&mut answer))
            .await
            .expect("the next peer was never served")
            .unwrap();
        assert!(answer.starts_with(b"HTTP/1.1 200"), "{answer:?}");
        assert!(answer.ends_with(b"ok"));
        assert!(t.elapsed() < http::HEAD_TIMEOUT * 2, "{:?}", t.elapsed());
        drop(stuck);
        task.abort();
    }
}
