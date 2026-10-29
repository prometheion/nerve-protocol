//! The relay (docs/dev/spec/protocol.md §4.8): a node in a closed network
//! reaches a center through this node. The relayed node sets this node as
//! its proxy; the relay takes its `CONNECT`, checks its token, and tunnels
//! bytes to one of this node's own centers. It never reads a message: TLS,
//! the pin and the relayed node's signature run end to end inside the
//! tunnel, so the relay can cut a node off but neither read nor steer its
//! link. The relayed node's policy is its own, and this node's policy is not
//! asked: no call of a center runs here for a tunnel.
//!
//! Off unless the owner sets `relay.listen`. The relay speaks TLS only, with
//! a certificate of its own that the relayed node pins (its key is kept with
//! the node's own keys); a plain HTTP `CONNECT` is answered with a refusal
//! that says so, and nothing is tunnelled. A tunnel goes only to the host
//! and port of a center this node is paired with over https, and not to one
//! that revoked or no longer knows it, and only to the centers the owner
//! picked for that node when it has a list. What a tunnel reaches is that
//! host and port, from this machine's address: whatever is served there
//! (other names and paths of a reverse proxy, other centers behind it) as
//! much as the center, since the relay does not read what the node sends
//! inside it. So centers that share a host and port are granted together
//! or not at all. Other ports of this machine or its network are not
//! reached. A tunnel ends when the owner turns the relay off,
//! takes the node's token away or the center off its list, unpairs the
//! center, or locks the node (`panic`). Each tunnel is one entry in the
//! audit log when it ends.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use nerve_policy::NodeConfig;
use nerve_policy::config::RelayNode;
use nerve_proto::link::CenterUrl;
use nerve_transport::BoxIo;
use nerve_transport::http::{Request, Response, read_request_head};
use nerve_transport::log::span;
use nerve_transport::tls::Acceptor;

use crate::daemon::{Shared, lock};

/// Connections whose `CONNECT` is not decided yet, at once. Past it a new
/// connection is closed at once, so a peer without a token cannot hold the
/// relay's memory or descriptors.
const UNDECIDED: usize = 64;
/// Of those, from one address: a peer that holds its connections open
/// without a word cannot take the slots of every other node.
const UNDECIDED_PER_PEER: usize = 4;
/// Of those, from one IPv6 /64 (link-local addresses aside): a machine that
/// gives itself many addresses there cannot take them all, while the other
/// machines of its LAN, which share the /64, keep room.
const UNDECIDED_PER_PREFIX: usize = 16;
/// How long the relay tries to reach a center for a granted tunnel, the name
/// lookup included: less than the 15 seconds a relayed node waits for the
/// answer, so the relay does not dial on for a node that left.
const DIAL_DEADLINE: Duration = Duration::from_secs(12);
/// Connections refused without a valid token are told in the log at most
/// this often, counted: a peer that makes them as fast as it can must not
/// push the rest of the log out.
const TOKENLESS_EVERY: Duration = Duration::from_secs(60);
/// A tunnel that carries no byte either way this long is closed. A link pings
/// every 20 seconds (spec §4.4), so only a dead one stays this quiet.
const IDLE: Duration = Duration::from_secs(90);
/// How long a relay that could not listen waits before it tries again.
const RETRY: Duration = Duration::from_secs(10);
/// The realm of the `Proxy-Authenticate` answer.
const REALM: &str = "nerve relay";

/// The relay's state in the daemon: what it listens on and its tunnels.
pub(crate) struct Relays {
    status: Mutex<String>,
    /// The address it listens on now (port 0 in `relay.listen` is resolved).
    bound: Mutex<Option<SocketAddr>>,
    tunnels: Mutex<HashMap<u64, Tunnel>>,
    next: AtomicU64,
    undecided: Arc<Semaphore>,
    /// Undecided connections per peer address, and per IPv6 /64.
    peers: Mutex<HashMap<std::net::IpAddr, usize>>,
    prefixes: Mutex<HashMap<std::net::IpAddr, usize>>,
    /// Plain-HTTP connections that carried a valid token, per relay node,
    /// told counted.
    plain: Mutex<HashMap<String, Tally>>,
    /// Refusals without a valid token, told counted.
    tokenless: Tally,
    /// Refusals of a node with its token, per node, told counted.
    held_back: Mutex<HashMap<String, Tally>>,
    /// When each relay node opened its tunnels in the last minute.
    opens: Mutex<HashMap<String, std::collections::VecDeque<std::time::Instant>>>,
    /// How long a tunnel may be quiet ([`IDLE`]; a test shortens it).
    idle_ms: AtomicU64,
    /// How long a connection may stay undecided (the head timeout; a test
    /// shortens it).
    undecided_ms: AtomicU64,
}

impl Default for Relays {
    fn default() -> Relays {
        Relays {
            status: Mutex::new("off".into()),
            bound: Mutex::default(),
            tunnels: Mutex::default(),
            next: AtomicU64::new(1),
            undecided: Arc::new(Semaphore::new(UNDECIDED)),
            peers: Mutex::default(),
            prefixes: Mutex::default(),
            plain: Mutex::default(),
            tokenless: Tally::default(),
            held_back: Mutex::default(),
            opens: Mutex::default(),
            idle_ms: AtomicU64::new(IDLE.as_millis() as u64),
            undecided_ms: AtomicU64::new(nerve_transport::http::HEAD_TIMEOUT.as_millis() as u64),
        }
    }
}

/// Refusals of one kind, told in the log counted: the first at once, then
/// at most one line per [`TOKENLESS_EVERY`] with the count since the last.
/// A count left waiting is told when its minute is over
/// ([`flush_tallies`]), also when no refusal follows.
#[derive(Default)]
struct Tally(Mutex<TallyState>);

#[derive(Default)]
struct TallyState {
    /// Refusals not told yet.
    count: u64,
    /// When the first of them came, and the last.
    first: Option<std::time::Instant>,
    latest: Option<std::time::Instant>,
    /// When the last line was told.
    told: Option<std::time::Instant>,
    /// The last refusal, in words for the line.
    last: String,
}

/// A line a tally has to tell: how many refusals, over how long, and the
/// last of them.
#[derive(Debug, PartialEq, Eq)]
struct Told {
    n: u64,
    over: Duration,
    last: String,
}

impl Tally {
    /// Refusals counted since the last line.
    #[cfg(test)]
    fn pending(&self) -> u64 {
        lock(&self.0).count
    }

    /// Counts a refusal (`last` says what it was) and gives the line to tell
    /// when one is due.
    fn note(&self, now: std::time::Instant, last: String) -> Option<Told> {
        let mut t = lock(&self.0);
        t.count += 1;
        t.first.get_or_insert(now);
        t.latest = Some(now);
        t.last = last;
        if t.told
            .is_some_and(|at| now.duration_since(at) < TOKENLESS_EVERY)
        {
            return None;
        }
        Some(Tally::take(&mut t, now))
    }

    /// The line for refusals left waiting, once their minute is over, or
    /// at once with `force` (the relay stops listening).
    fn flush(&self, now: std::time::Instant, force: bool) -> Option<Told> {
        let mut t = lock(&self.0);
        if t.count == 0
            || (!force
                && t.told
                    .is_some_and(|at| now.duration_since(at) < TOKENLESS_EVERY))
        {
            return None;
        }
        Some(Tally::take(&mut t, now))
    }

    fn take(t: &mut TallyState, now: std::time::Instant) -> Told {
        let told = Told {
            n: t.count,
            // From the first refusal of the batch to its last, not to the
            // line: how long the refusals came for.
            over: match (t.first, t.latest) {
                (Some(f), Some(l)) => l.duration_since(f),
                _ => Duration::ZERO,
            },
            last: std::mem::take(&mut t.last),
        };
        t.count = 0;
        t.first = None;
        t.latest = None;
        t.told = Some(now);
        told
    }
}

/// The kinds of counted refusals, for their log line.
#[derive(Clone, Copy)]
enum Refused {
    /// Without a valid token.
    Tokenless,
    /// Of relay node `node`, with its token.
    Node,
    /// A valid token of relay node `node` that came in plain HTTP.
    Plain,
}

/// The `warn` line for a count of refusals.
fn refused_line(kind: Refused, node: &str, t: &Told) -> String {
    let (n, last) = (t.n, &t.last);
    let over = if n > 1 {
        format!(" in {}", span(t.over))
    } else {
        String::new()
    };
    match kind {
        Refused::Tokenless => format!(
            "relay: refused {n} connection(s) without a valid relay token{over}, the last {last}; such refusals are told at most once a minute"
        ),
        Refused::Node => format!(
            "relay: refused {n} tunnel(s) of relay node {node}{over}, the last {last}; such refusals are told at most once a minute"
        ),
        Refused::Plain => format!(
            "relay: relay node {node} sent its token in plain HTTP {n} time(s){over}, the last {last}, so it crossed the network in the clear; give it a new one with `nerve-node relay token {node}`"
        ),
    }
}

/// The lines for the counts that waited out their minute without a refusal
/// after them, or, with `force`, for every count still waiting: the relay's
/// tick asks for the first, the end of listening (`relay off`, `panic`, a
/// new address or pin, the node stopping) for the second, so no count is
/// left untold.
fn flush_tallies(r: &Relays, now: std::time::Instant, force: bool) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(t) = r.tokenless.flush(now, force) {
        lines.push(refused_line(Refused::Tokenless, "", &t));
    }
    for (kind, map) in [(Refused::Node, &r.held_back), (Refused::Plain, &r.plain)] {
        for (node, tally) in lock(map).iter() {
            if let Some(t) = tally.flush(now, force) {
                lines.push(refused_line(kind, node, &t));
            }
        }
    }
    lines
}

/// Logs [`flush_tallies`].
fn tell_tallies(shared: &Shared, force: bool) {
    for line in flush_tallies(&shared.relay, std::time::Instant::now(), force) {
        tracing::warn!("{line}");
    }
}

/// One tunnel, for `status` and the limits.
#[derive(Debug, Clone)]
struct Tunnel {
    node: String,
    center: String,
    from: SocketAddr,
    since_ms: u64,
}

impl Relays {
    /// What `status` shows of the relay: whether it listens and who is
    /// connected to which center.
    pub fn status(&self, cfg: &NodeConfig) -> Value {
        let mut tunnels: Vec<Tunnel> = lock(&self.tunnels).values().cloned().collect();
        tunnels.sort_by_key(|t| t.since_ms);
        json!({
            "listen": cfg.relay.listen,
            "address": lock(&self.bound).map(|a| a.to_string()),
            "status": lock(&self.status).clone(),
            "max_links": cfg.relay.max_links,
            "max_links_per_node": cfg.relay.max_links_per_node,
            "max_opens_per_minute": cfg.relay.max_opens_per_minute,
            "pin": cfg.relay.pin,
            "nodes": cfg.relay.nodes.iter().map(|n| json!({
                "name": n.name,
                "centers": n.centers,
            })).collect::<Vec<_>>(),
            "tunnels": tunnels.iter().map(|t| json!({
                "node": t.node,
                "center": t.center,
                "from": t.from.to_string(),
                "since_ms": t.since_ms,
            })).collect::<Vec<_>>(),
        })
    }

    /// Counts a connection refused without a valid token, and says how many
    /// to tell in the log when a line is due: the first, then at most one
    /// per [`TOKENLESS_EVERY`] with the count since the last.
    fn note_tokenless(&self, now: std::time::Instant, last: String) -> Option<Told> {
        self.tokenless.note(now, last)
    }

    /// Whether `node` may open another tunnel now, `limit` a minute
    /// (`relay.max_opens_per_minute`), and if so counts it.
    fn may_open(&self, node: &str, limit: usize, now: std::time::Instant) -> bool {
        let mut opens = lock(&self.opens);
        let times = opens.entry(node.to_string()).or_default();
        while times
            .front()
            .is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60))
        {
            times.pop_front();
        }
        if times.len() >= limit {
            return false;
        }
        times.push_back(now);
        true
    }

    /// Takes one of the undecided slots of `peer`, unless its address, or
    /// its IPv6 /64, holds its share.
    fn take_peer(&self, peer: std::net::IpAddr) -> bool {
        let mut peers = lock(&self.peers);
        let mut prefixes = lock(&self.prefixes);
        let prefix = prefix_of(peer);
        if peers.get(&peer).copied().unwrap_or(0) >= UNDECIDED_PER_PEER
            || prefix
                .is_some_and(|p| prefixes.get(&p).copied().unwrap_or(0) >= UNDECIDED_PER_PREFIX)
        {
            return false;
        }
        *peers.entry(peer).or_insert(0) += 1;
        if let Some(p) = prefix {
            *prefixes.entry(p).or_insert(0) += 1;
        }
        true
    }

    fn give_peer(&self, peer: std::net::IpAddr) {
        let give = |map: &mut HashMap<std::net::IpAddr, usize>, key| {
            if let Some(n) = map.get_mut(&key) {
                *n -= 1;
                if *n == 0 {
                    map.remove(&key);
                }
            }
        };
        give(&mut lock(&self.peers), peer);
        if let Some(p) = prefix_of(peer) {
            give(&mut lock(&self.prefixes), p);
        }
    }

    /// Shortens the idle span, for a test.
    #[cfg(test)]
    pub(crate) fn set_idle(&self, d: Duration) {
        self.idle_ms.store(d.as_millis() as u64, Ordering::Relaxed);
    }

    /// Shortens the time a connection may stay undecided, for a test.
    #[cfg(test)]
    pub(crate) fn set_undecided(&self, d: Duration) {
        self.undecided_ms
            .store(d.as_millis() as u64, Ordering::Relaxed);
    }

    fn set_status(&self, s: impl Into<String>, bound: Option<SocketAddr>) {
        *lock(&self.status) = s.into();
        *lock(&self.bound) = bound;
    }
}

/// A new relay token and the hash `node.toml` keeps of it. 43 characters
/// of `a-z0-9`: over 220 bits, and nothing a proxy URL must escape.
pub fn new_token() -> (String, String) {
    let token = nerve_transport::keys::random_token(43);
    let hash = token_hash(&token);
    (token, hash)
}

/// The lowercase hex SHA-256 of a relay token.
pub fn token_hash(token: &str) -> String {
    nerve_proto::msg::hex(ring::digest::digest(&ring::digest::SHA256, token.as_bytes()).as_ref())
}

/// Runs the relay while the config says so: listens on `relay.listen`
/// unless the node is locked, and listens again when that changes.
pub(crate) async fn run(shared: Arc<Shared>) {
    let mut changed = shared.changed.subscribe();
    let mut stop = shared.stop.subscribe();
    // The address the last bind failed on: the first failure there is an
    // error in the log, its retries are detail, or a port that stays taken
    // fills the log.
    let mut failed_on: Option<String> = None;
    loop {
        if *stop.borrow() {
            break;
        }
        changed.borrow_and_update();
        let cfg = shared.config();
        let want = cfg.relay.listen.clone().filter(|_| !cfg.locked);
        let wait = match want {
            None => {
                shared.relay.set_status("off", None);
                None
            }
            Some(at) => match listen(&shared, &cfg, &at).await {
                Ok((listener, acceptor)) => {
                    failed_on = None;
                    let bound = listener.local_addr().ok();
                    let shown = bound.map_or_else(|| at.clone(), |a| a.to_string());
                    tracing::info!("relay: listening on {shown}");
                    shared
                        .relay
                        .set_status(format!("listening on {shown}"), bound);
                    let pin = cfg.relay.pin.clone();
                    serve(
                        &shared,
                        listener,
                        acceptor,
                        (&at, &pin),
                        &mut changed,
                        &mut stop,
                    )
                    .await;
                    // What waited is told now, not when the relay listens
                    // again, or never when the node stops.
                    tell_tallies(&shared, true);
                    tracing::info!("relay: stopped listening on {shown}");
                    shared.relay.set_status("off", None);
                    continue;
                }
                Err(e) => {
                    if failed_on.as_deref() == Some(at.as_str()) {
                        tracing::debug!("relay: cannot listen on {at}: {e}");
                    } else {
                        tracing::error!("relay: cannot listen on {at}: {e}");
                    }
                    failed_on = Some(at.clone());
                    shared
                        .relay
                        .set_status(format!("cannot listen on {at}: {e}"), None);
                    Some(RETRY)
                }
            },
        };
        tokio::select! {
            r = changed.changed() => {
                if r.is_err() {
                    break;
                }
            }
            _ = stop.changed() => break,
            _ = async {
                match wait {
                    Some(w) => tokio::time::sleep(w).await,
                    None => std::future::pending().await,
                }
            } => {}
        }
    }
    // Refusals of connections still in flight when the relay stopped
    // listening are told before the node stops, not left for a relay that
    // listens again.
    tell_tallies(&shared, true);
    shared.relay.set_status("off", None);
}

/// The relay's listener and its TLS: the certificate's key from where the
/// node keeps its keys. Without one the relay does not listen.
async fn listen(
    shared: &Arc<Shared>,
    cfg: &NodeConfig,
    at: &str,
) -> Result<(TcpListener, Acceptor), String> {
    // The keyring may block (the Secret Service asks to unlock), so off the
    // runtime's threads.
    let (paths, storage) = (shared.paths.clone(), cfg.machine.secret_storage);
    let id = tokio::task::spawn_blocking(move || crate::secrets::relay_tls(&paths, storage))
        .await
        .map_err(|e| format!("the key read stopped: {e}"))??
        .ok_or("the relay has no TLS certificate; `nerve-node relay set <address>` makes one")?;
    if cfg.relay.pin.as_deref() != Some(id.pin().as_str()) {
        return Err(
            "the relay's TLS key is not the one relay.pin names; `nerve-node relay set <address>` makes a new one"
                .into(),
        );
    }
    let acceptor = Acceptor::new(&id)?;
    let listener = TcpListener::bind(at).await.map_err(|e| e.to_string())?;
    Ok((listener, acceptor))
}

/// Takes connections on `listener` until the relay's address or pin changes, the
/// node is locked, or the daemon stops. Running tunnels go on: each checks
/// the config itself. `changed` is the caller's, which saw the config the
/// listener was made for, so a change made while it bound is not missed.
async fn serve(
    shared: &Arc<Shared>,
    listener: TcpListener,
    acceptor: Acceptor,
    (at, pin): (&str, &Option<String>),
    changed: &mut tokio::sync::watch::Receiver<u64>,
    stop: &mut tokio::sync::watch::Receiver<bool>,
) {
    // Counts of refusals are told when their minute is over, also when
    // nothing comes after them.
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            _ = tick.tick() => tell_tallies(shared, false),
            got = listener.accept() => match got {
                Ok((io, peer)) => {
                    // A connection over the limits is closed unread.
                    let Some(slot) = Undecided::take(shared, peer) else {
                        tracing::debug!("relay: too many undecided connections; closed one from {peer}");
                        tokenless(shared, peer);
                        continue;
                    };
                    let _ = io.set_nodelay(true);
                    let (shared, acceptor) = (shared.clone(), acceptor.clone());
                    tokio::spawn(async move {
                        connection(shared, acceptor, io, peer, slot).await;
                    });
                }
                // One connection the node cannot take does not end the relay.
                Err(e) => {
                    tracing::debug!("relay: accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            r = changed.changed() => {
                if r.is_err() {
                    return;
                }
                let cfg = shared.config();
                // A new certificate is listened with anew.
                if cfg.locked || cfg.relay.listen.as_deref() != Some(at) || cfg.relay.pin != *pin {
                    return;
                }
            }
            _ = stop.changed() => return,
        }
    }
}

/// What the relay answers a `CONNECT` it does not grant.
#[derive(Debug, PartialEq, Eq)]
struct Refusal {
    status: u16,
    why: &'static str,
}

const NO_TOKEN: Refusal = Refusal {
    status: 407,
    why: "this relay wants the name and token of a node it knows",
};
const NOT_A_CENTER: Refusal = Refusal {
    status: 403,
    why: "the relay tunnels only to the https centers its node is paired with",
};
const NOT_CONNECT: Refusal = Refusal {
    status: 405,
    why: "the relay takes CONNECT host:port only",
};
const OFF: Refusal = Refusal {
    status: 503,
    why: "the relay is off",
};
const FULL: Refusal = Refusal {
    status: 503,
    why: "the relay carries as many tunnels as it may now",
};
const TOO_OFTEN: Refusal = Refusal {
    status: 503,
    why: "this node opened as many tunnels as it may in a minute",
};
/// The answer to a `CONNECT` in plain HTTP, before any TLS: the token came
/// in the clear, and nothing is tunnelled.
const PLAIN: Refusal = Refusal {
    status: 400,
    why: "the relay speaks TLS only: set it as an https:// proxy with its pin (`nerve-node relay ls` on the relay shows the pin)",
};

/// A `CONNECT` the relay grants: whose it is and where it goes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Grant {
    node: String,
    token_sha256: String,
    /// The centers it reaches, as the log and the audit name them.
    center: String,
    centers: Vec<String>,
    url: CenterUrl,
}

/// Decides a `CONNECT` by the config alone. The token is checked before the
/// target, so a peer without one learns nothing of this node's centers.
fn decide(cfg: &NodeConfig, req: &Request) -> Result<Grant, Refusal> {
    if cfg.locked || cfg.relay.listen.is_none() {
        return Err(OFF);
    }
    if !req.method.eq_ignore_ascii_case("CONNECT") {
        return Err(NOT_CONNECT);
    }
    let node = node_of(cfg, req.header("proxy-authorization")).ok_or(NO_TOKEN)?;
    let (host, port) = authority(&req.path).ok_or(NOT_CONNECT)?;
    // A center the node may not reach is refused as one that is not there,
    // so its list does not tell it what else the relay has.
    let (centers, url) = reachable(cfg, &node, &host, port).ok_or(NOT_A_CENTER)?;
    Ok(Grant {
        node: node.name,
        token_sha256: node.token_sha256,
        center: centers.join(", "),
        centers,
        url,
    })
}

/// The relay node a `Proxy-Authorization: Basic` names, when the token is
/// that node's.
fn node_of(cfg: &NodeConfig, header: Option<&str>) -> Option<RelayNode> {
    use base64::Engine;
    let (scheme, value) = header?.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .ok()?;
    let text = String::from_utf8(raw).ok()?;
    let (name, token) = text.split_once(':')?;
    let node = cfg.relay.node(name)?;
    // The hashes are of tokens of over 220 random bits: comparing them
    // plainly tells a guesser nothing about a token.
    (token_hash(token) == node.token_sha256).then(|| node.clone())
}

/// `host:port` of a `CONNECT`, with `[...]` around an IPv6 address.
fn authority(target: &str) -> Option<(String, u16)> {
    let (host, port) = match target.strip_prefix('[') {
        Some(rest) => {
            let (h, p) = rest.split_once("]:")?;
            (h, p)
        }
        None => target.rsplit_once(':')?,
    };
    if host.is_empty() || host.contains(['/', '@', '[', ']']) {
        return None;
    }
    Some((host.to_string(), port.parse().ok()?))
}

/// The centers at `host:port` that a tunnel may go to: those this node is
/// paired with over https that have not revoked it and still know it. A
/// plain http center is on this machine's loopback; a tunnel there would
/// open it to the network.
fn targets(cfg: &NodeConfig, host: &str, port: u16) -> Vec<(String, CenterUrl)> {
    cfg.centers
        .iter()
        .filter(|c| !c.revoked && !c.unknown)
        .filter_map(|c| {
            let url = CenterUrl::parse(&c.url).ok()?;
            (url.tls && url.port == port && same_host(&url.host, host))
                .then(|| (c.name.clone(), url))
        })
        .collect()
}

/// Whether two host names or addresses are the same as a URL can tell: the
/// case, a trailing dot and the spelling of an address do not count. A name
/// and the address it resolves to are not told apart here.
pub(crate) fn same_host(a: &str, b: &str) -> bool {
    let norm = |h: &str| {
        let h = h.trim_end_matches('.');
        match h.parse::<std::net::IpAddr>() {
            Ok(ip) => ip.to_canonical().to_string(),
            Err(_) => h.to_ascii_lowercase(),
        }
    };
    norm(a) == norm(b)
}

/// The centers a tunnel of `node` to `host:port` reaches, and where to dial:
/// every target at that address, and only when the node may reach each of
/// them. Centers behind one reverse proxy share a host and port and differ
/// in their path, which travels inside the TLS the relay does not read; so
/// the relay cannot keep a node to one of them, and grants all or none.
fn reachable(
    cfg: &NodeConfig,
    node: &RelayNode,
    host: &str,
    port: u16,
) -> Option<(Vec<String>, CenterUrl)> {
    let found = targets(cfg, host, port);
    let (_, url) = found.first()?.clone();
    found
        .iter()
        .all(|(name, _)| node.may_reach(name))
        .then(|| (found.into_iter().map(|(n, _)| n).collect(), url))
}

/// Whether a granted tunnel may go on under `cfg`: the relay is on, the node
/// is not locked, its token is the same and its center still a target.
fn still_granted(cfg: &NodeConfig, g: &Grant) -> bool {
    !cfg.locked
        && cfg.relay.listen.is_some()
        && cfg.relay.node(&g.node).is_some_and(|n| {
            n.token_sha256 == g.token_sha256
                && reachable(cfg, n, &g.url.host, g.url.port)
                    .is_some_and(|(names, _)| names == g.centers)
        })
}

/// Counts a tunnel while it lives, for `status` and the limits.
struct Counted<'a> {
    relays: &'a Relays,
    id: u64,
}

impl Drop for Counted<'_> {
    fn drop(&mut self) {
        lock(&self.relays.tunnels).remove(&self.id);
    }
}

/// Counts a new tunnel of `g`, unless the limits are reached.
fn count<'a>(
    relays: &'a Relays,
    cfg: &NodeConfig,
    g: &Grant,
    from: SocketAddr,
) -> Option<Counted<'a>> {
    let mut tunnels = lock(&relays.tunnels);
    let of_node = tunnels.values().filter(|t| t.node == g.node).count();
    let per_node = cfg
        .relay
        .node(&g.node)
        .map_or(cfg.relay.max_links_per_node, |n| n.links(&cfg.relay));
    if tunnels.len() >= cfg.relay.max_links as usize || of_node >= per_node as usize {
        return None;
    }
    let id = relays.next.fetch_add(1, Ordering::Relaxed);
    tunnels.insert(
        id,
        Tunnel {
            node: g.node.clone(),
            center: g.center.clone(),
            from,
            since_ms: crate::now_ms(),
        },
    );
    Some(Counted { relays, id })
}

async fn refuse<W: tokio::io::AsyncWrite + Unpin>(io: &mut W, r: &Refusal) {
    let mut resp = Response::text(r.status, r.why);
    if r.status == 407 {
        resp = resp.with_header("Proxy-Authenticate", &format!("Basic realm=\"{REALM}\""));
    }
    let _ = resp.write(io).await;
}

/// The /64 an IPv6 peer address is counted in besides itself, for the
/// undecided limit; none for IPv4, loopback and link-local addresses (their
/// scope is not in the address, so one /64 there would be every link).
fn prefix_of(ip: std::net::IpAddr) -> Option<std::net::IpAddr> {
    match ip.to_canonical() {
        std::net::IpAddr::V6(v6) if !v6.is_loopback() && (v6.segments()[0] & 0xffc0) != 0xfe80 => {
            let mut o = v6.octets();
            o[8..].fill(0);
            Some(std::net::IpAddr::V6(o.into()))
        }
        _ => None,
    }
}

/// One undecided connection: a slot of the relay's and one of its peer's,
/// both given back when it is dropped.
struct Undecided {
    _permit: tokio::sync::OwnedSemaphorePermit,
    shared: Arc<Shared>,
    peer: std::net::IpAddr,
}

impl Undecided {
    fn take(shared: &Arc<Shared>, peer: SocketAddr) -> Option<Undecided> {
        let permit = shared.relay.undecided.clone().try_acquire_owned().ok()?;
        let ip = peer.ip().to_canonical();
        shared.relay.take_peer(ip).then(|| Undecided {
            _permit: permit,
            shared: shared.clone(),
            peer: ip,
        })
    }
}

impl Drop for Undecided {
    fn drop(&mut self) {
        self.shared.relay.give_peer(self.peer);
    }
}

/// Tells a refusal of a node with its token, counted per node: whatever it
/// asks, a node gets no more than a line a minute in the log for its
/// refusals, and the line names that node.
fn held_back(shared: &Shared, node: &str, peer: SocketAddr, target: &str, r: &Refusal) {
    let last = format!("from {peer} to {}: {}", clip(target), r.why);
    tracing::debug!("relay: refused a tunnel of {node} {last}");
    let due = lock(&shared.relay.held_back)
        .entry(node.to_string())
        .or_default()
        .note(std::time::Instant::now(), last);
    if let Some(t) = due {
        tracing::warn!("{}", refused_line(Refused::Node, node, &t));
    }
}

/// Tells that relay node `node` sent its valid token in plain HTTP: once a
/// minute per node at most, counted, so the owner learns whose token to
/// replace without the log filling up.
fn plain_token(shared: &Shared, node: &str, peer: SocketAddr) {
    let due = lock(&shared.relay.plain)
        .entry(node.to_string())
        .or_default()
        .note(std::time::Instant::now(), format!("from {peer}"));
    if let Some(t) = due {
        tracing::warn!("{}", refused_line(Refused::Plain, node, &t));
    }
}

/// Tells a connection refused without a valid token in the log, counted
/// ([`Relays::note_tokenless`]).
fn tokenless(shared: &Shared, peer: SocketAddr) {
    let due = shared
        .relay
        .note_tokenless(std::time::Instant::now(), format!("from {peer}"));
    if let Some(t) = due {
        tracing::warn!("{}", refused_line(Refused::Tokenless, "", &t));
    }
}

/// One connection to the relay: TLS, its `CONNECT`, then the tunnel.
async fn connection(
    shared: Arc<Shared>,
    acceptor: Acceptor,
    mut tcp: TcpStream,
    peer: SocketAddr,
    slot: Undecided,
) {
    // A TLS handshake starts with a handshake record (22). Anything else is
    // a client that speaks plain HTTP: it is told so, and nothing it sent
    // is used.
    // One deadline for the first byte, TLS and the head together: an
    // undecided connection holds its slot this long at most.
    let deadline = tokio::time::Instant::now()
        + Duration::from_millis(shared.relay.undecided_ms.load(Ordering::Relaxed));
    let mut first = [0u8; 1];
    let peeked = tokio::time::timeout_at(deadline, tcp.peek(&mut first)).await;
    match peeked {
        Ok(Ok(1)) if first[0] == 0x16 => {}
        Ok(Ok(1)) => {
            // The request is read and dropped first: a socket closed with
            // bytes unread is reset (Windows does so at once), and the reset
            // would take the answer with it.
            let head = tokio::time::timeout_at(deadline, read_request_head(&mut tcp)).await;
            let sent = head
                .ok()
                .and_then(Result::ok)
                .and_then(|r| node_of(&shared.config(), r.header("proxy-authorization")));
            match sent {
                // A valid token crossed the network in the clear: the owner
                // is told whose, to give that node a new one.
                Some(n) => plain_token(&shared, &n.name, peer),
                None => {
                    tracing::debug!("relay: refused a plain HTTP connection from {peer}");
                    tokenless(&shared, peer);
                }
            }
            refuse(&mut tcp, &PLAIN).await;
            let _ = tcp.shutdown().await;
            let mut rest = [0u8; 512];
            let drained = async { while matches!(tcp.read(&mut rest).await, Ok(n) if n > 0) {} };
            let _ = tokio::time::timeout(Duration::from_secs(1), drained).await;
            return;
        }
        _ => return,
    }
    let accepted = tokio::time::timeout_at(deadline, acceptor.accept(tcp)).await;
    let mut io: BoxIo = match accepted {
        Ok(Ok(io)) => io,
        Ok(Err(e)) => {
            tracing::debug!("relay: TLS with {peer} failed: {e}");
            return;
        }
        Err(_) => return,
    };
    let req = match tokio::time::timeout_at(deadline, read_request_head(&mut io)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            tracing::debug!("relay: no request from {peer}: {e}");
            return;
        }
        Err(_) => {
            tracing::debug!("relay: no request from {peer} in time");
            return;
        }
    };
    let cfg = shared.config();
    let grant = match decide(&cfg, &req) {
        Ok(g) => g,
        Err(r) => {
            // A refusal costs a counted line, with a token or without.
            match node_of(&cfg, req.header("proxy-authorization")) {
                None => {
                    tracing::debug!(
                        "relay: refused a tunnel from {peer} to {}: {}",
                        clip(&req.path),
                        r.why
                    );
                    tokenless(&shared, peer);
                }
                Some(n) => held_back(&shared, &n.name, peer, &req.path, &r),
            }
            refuse(&mut io, &r).await;
            return;
        }
    };
    let Some(_counted) = count(&shared.relay, &cfg, &grant, peer) else {
        held_back(&shared, &grant.node, peer, &req.path, &FULL);
        refuse(&mut io, &FULL).await;
        return;
    };
    let limit = cfg
        .relay
        .node(&grant.node)
        .map_or(cfg.relay.max_opens_per_minute, |n| n.opens(&cfg.relay)) as usize;
    if !shared
        .relay
        .may_open(&grant.node, limit, std::time::Instant::now())
    {
        held_back(&shared, &grant.node, peer, &req.path, &TOO_OFTEN);
        refuse(&mut io, &TOO_OFTEN).await;
        return;
    }
    // Decided: from here the tunnel is counted as one of the node's, and
    // the undecided slot goes back, so a slow dial does not keep the
    // peer's other connections out.
    drop(slot);
    // The relay dials as the node's own link does: through its proxy, or
    // another relay, when it has one.
    let until = tokio::time::Instant::now() + DIAL_DEADLINE;
    let dial = async {
        match crate::link::proxy_for(&shared.paths, &cfg, &grant.url).await {
            Ok(Some(proxy)) => {
                nerve_transport::net::reach_until(&grant.url, Some(&proxy), Some(until)).await
            }
            Ok(None) => dial_center(&grant.url, until).await,
            Err(e) => Err(format!("bad proxy: {e}")),
        }
    };
    let dialled = tokio::time::timeout(DIAL_DEADLINE, dial)
        .await
        .unwrap_or_else(|_| Err(format!("no connection in {}", span(DIAL_DEADLINE))));
    let center = match dialled {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                "relay: {} from {peer} to center {}: cannot connect: {e}",
                grant.node,
                grant.center
            );
            refuse(
                &mut io,
                &Refusal {
                    status: 502,
                    why: "the relay cannot reach that center now",
                },
            )
            .await;
            return;
        }
    };
    let ok = b"HTTP/1.1 200 Connection established\r\n\r\n";
    if io.write_all(ok).await.is_err() || io.flush().await.is_err() {
        return;
    }
    tracing::info!(
        "relay: {} from {peer} to center {}: tunnel open",
        grant.node,
        grant.center
    );
    let (started, start_ms) = (std::time::Instant::now(), crate::now_ms());
    let (up, down, why) = pump(&shared, &grant, io, center).await;
    tracing::info!(
        "relay: {} from {peer} to center {}: tunnel closed after {} ({why}; {up} bytes up, {down} down)",
        grant.node,
        grant.center,
        span(started.elapsed())
    );
    let entry = nerve_policy::audit::RelayTunnel {
        node: grant.node.clone(),
        center: grant.center.clone(),
        from: peer.to_string(),
        start_ms,
        end_ms: crate::now_ms(),
        reason: why.into(),
        up,
        down,
    };
    if let Err(e) = lock(&shared.store).audit().relay(&entry) {
        tracing::warn!("relay: the audit log did not take the tunnel's entry: {e}");
    }
}

/// Whether `host` names this machine itself: a loopback address, or
/// `localhost`.
fn names_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.to_canonical().is_loopback())
}

/// The addresses a tunnel to `host` may use: all of them, unless the name
/// resolved to this machine (loopback, or the unspecified address) while it
/// does not name it. A center paired at a name is out there; when that name
/// turns to this machine, the tunnel would reach whatever listens here.
fn tunnel_addrs(host: &str, addrs: Vec<SocketAddr>) -> Result<Vec<SocketAddr>, String> {
    let here = |a: &SocketAddr| {
        let ip = a.ip().to_canonical();
        ip.is_loopback() || ip.is_unspecified()
    };
    if !names_loopback(host) && addrs.iter().any(here) {
        return Err(format!(
            "{host} resolves to this machine, where the relay tunnels only to a center paired at a loopback address"
        ));
    }
    if addrs.is_empty() {
        return Err(format!("{host} resolves to no address"));
    }
    Ok(addrs)
}

/// Dials a center of this node straight, on the addresses [`tunnel_addrs`]
/// lets a tunnel use, each with its share of the time left until `until`
/// (`net::connect_first`): a first address that does not answer leaves time
/// for the next.
async fn dial_center(url: &CenterUrl, until: tokio::time::Instant) -> Result<BoxIo, String> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((url.host.as_str(), url.port))
        .await
        .map_err(|e| format!("cannot resolve {}: {e}", url.host))?
        .collect();
    let addrs = tunnel_addrs(&url.host, addrs)?;
    let s = nerve_transport::net::connect_first(addrs, Some(until), TcpStream::connect)
        .await
        .map_err(|last| format!("cannot connect to {url}: {last}"))?;
    let _ = s.set_nodelay(true);
    Ok(Box::new(s))
}

/// A target as the log shows it: cut, since a peer chooses it.
fn clip(s: &str) -> String {
    let mut out: String = s.chars().take(80).collect();
    if s.chars().count() > 80 {
        out.push('…');
    }
    out
}

/// Carries bytes both ways between the relayed node and the center, unread,
/// until either side ends, the tunnel is quiet for [`IDLE`], or the owner
/// cuts it off. Returns the bytes each way and why it ended.
async fn pump(
    shared: &Arc<Shared>,
    g: &Grant,
    node: BoxIo,
    center: BoxIo,
) -> (u64, u64, &'static str) {
    // The time since the tunnel opened, on the monotonic clock: a step of
    // the wall clock neither keeps a dead tunnel nor ends a live one.
    let opened = std::time::Instant::now();
    let last = AtomicU64::new(0);
    let idle_ms = shared.relay.idle_ms.load(Ordering::Relaxed);
    let (up, down) = (AtomicU64::new(0), AtomicU64::new(0));
    let (nr, nw) = tokio::io::split(node);
    let (cr, cw) = tokio::io::split(center);
    let both = async {
        tokio::join!(
            copy(nr, cw, &up, (&last, opened)),
            copy(cr, nw, &down, (&last, opened))
        )
    };
    let mut changed = shared.changed.subscribe();
    let mut stop = shared.stop.subscribe();
    // A change between the grant and here is in the config already.
    if *stop.borrow() {
        return (0, 0, "the node stopped");
    }
    if !still_granted(&shared.config(), g) {
        return (0, 0, "cut off by the owner");
    }
    let cut = async {
        loop {
            tokio::select! {
                r = changed.changed() => {
                    if r.is_err() {
                        return "the node stopped";
                    }
                    if !still_granted(&shared.config(), g) {
                        return "cut off by the owner";
                    }
                }
                _ = stop.changed() => return "the node stopped",
            }
        }
    };
    let idle = async {
        let tick = Duration::from_millis((idle_ms / 3).clamp(1, 5000));
        loop {
            tokio::time::sleep(tick).await;
            let now = opened.elapsed().as_millis() as u64;
            if now.saturating_sub(last.load(Ordering::Relaxed)) >= idle_ms {
                return;
            }
        }
    };
    let why = tokio::select! {
        _ = both => "ended",
        why = cut => why,
        _ = idle => "quiet too long",
    };
    (
        up.load(Ordering::Relaxed),
        down.load(Ordering::Relaxed),
        why,
    )
}

/// Copies one way until the reader ends, then ends the writer's side.
async fn copy(
    mut from: tokio::io::ReadHalf<BoxIo>,
    mut to: tokio::io::WriteHalf<BoxIo>,
    count: &AtomicU64,
    (last, opened): (&AtomicU64, std::time::Instant),
) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if to.write_all(&buf[..n]).await.is_err() || to.flush().await.is_err() {
            break;
        }
        count.fetch_add(n as u64, Ordering::Relaxed);
        last.store(opened.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
    let _ = to.shutdown().await;
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use base64::Engine;
    use nerve_conformance::fake_center::{self, FakeCenter};
    use nerve_policy::CenterEntry;
    use nerve_proto::link::PairLink;
    use nerve_transport::tls::{Acceptor, ServerIdentity};

    use super::*;
    use crate::daemon::{Daemon, NodeOptions};
    use crate::paths::NodePaths;

    const WAIT: Duration = Duration::from_secs(15);
    const QUIET: Duration = Duration::from_millis(300);

    /// A center of the jump node. Paused, so the jump node does not dial it
    /// itself: these tests are about the tunnels of other nodes.
    fn center(name: &str, url: String) -> CenterEntry {
        CenterEntry {
            name: name.into(),
            url,
            pin: None,
            center_id: format!("id-{name}"),
            node_id: "n".into(),
            settings: Default::default(),
            paused: true,
            revoked: false,
            unknown: false,
            public_key: None,
            key_rotations: 0,
            pin_rotations: 0,
            old_pin: None,
            policy: Default::default(),
            capabilities: Vec::new(),
        }
    }

    fn basic(name: &str, token: &str) -> String {
        let b = base64::engine::general_purpose::STANDARD.encode(format!("{name}:{token}"));
        format!("Basic {b}")
    }

    fn options(root: &std::path::Path) -> NodeOptions {
        let mut o = NodeOptions::new(NodePaths::new(root.join("config"), root.join("state")));
        o.home = root.join("home");
        std::fs::create_dir_all(&o.home).unwrap();
        o.ctl = false;
        o.full_rights = Some(false);
        o
    }

    /// A jump node with `centers`, its relay on a free port of loopback with
    /// its TLS certificate (pin `pin`), and one node `lab` that may use it.
    struct Jump {
        _dir: tempfile::TempDir,
        daemon: Daemon,
        addr: SocketAddr,
        pin: String,
        token: String,
    }

    fn relay_node(name: &str, hash: String, centers: &[&str]) -> RelayNode {
        RelayNode {
            name: name.into(),
            token_sha256: hash,
            centers: centers.iter().map(|c| c.to_string()).collect(),
            max_links: None,
            max_opens_per_minute: None,
        }
    }

    /// A relay with its certificate: the key where the node keeps its keys
    /// (files here), the pin in the config.
    fn with_certificate(paths: &NodePaths, cfg: &mut NodeConfig) -> String {
        let id = ServerIdentity::generate(&["127.0.0.1".into()]).unwrap();
        crate::secrets::store_relay_tls(paths, cfg.machine.secret_storage, &id).unwrap();
        cfg.relay.pin = Some(id.pin());
        id.pin()
    }

    async fn jump(centers: Vec<CenterEntry>, more: impl FnOnce(&mut NodeConfig)) -> Jump {
        jump_with(centers, more, false).await
    }

    /// [`jump`], with its control socket (or pipe) when `ctl`.
    async fn jump_with(
        centers: Vec<CenterEntry>,
        more: impl FnOnce(&mut NodeConfig),
        ctl: bool,
    ) -> Jump {
        let dir = tempfile::tempdir().unwrap();
        let mut o = options(dir.path());
        o.ctl = ctl;
        let (token, hash) = new_token();
        let mut cfg = NodeConfig {
            centers,
            ..Default::default()
        };
        cfg.relay.listen = Some("127.0.0.1:0".into());
        cfg.relay.nodes.push(relay_node("lab", hash, &[]));
        more(&mut cfg);
        let pin = with_certificate(&o.paths, &mut cfg);
        cfg.save(&o.paths.config_file()).unwrap();
        let daemon = Daemon::start(o).await.unwrap();
        let addr = listening(&daemon).await;
        Jump {
            _dir: dir,
            daemon,
            addr,
            pin,
            token,
        }
    }

    /// The address the relay of `daemon` listens on, once it does.
    async fn listening(daemon: &Daemon) -> SocketAddr {
        for _ in 0..400 {
            if let Some(a) = daemon.status()["relay"]["address"].as_str() {
                return a.parse().unwrap();
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("the relay never listened: {}", daemon.status()["relay"]);
    }

    /// Sends `CONNECT target` with `auth` over TLS to the relay, pinned as a
    /// relayed node pins it, and returns the answer's status, the refusal's
    /// text and, when granted, the tunnel.
    async fn connect(
        relay: SocketAddr,
        pin: &str,
        target: &str,
        auth: Option<&str>,
    ) -> (u16, String, Option<BoxIo>) {
        let headers = auth
            .map(|a| vec![("Proxy-Authorization".to_string(), a.to_string())])
            .unwrap_or_default();
        let proxy = nerve_transport::Proxy::parse(&format!("https://{relay}"), headers)
            .unwrap()
            .pinned(Some(pin.into()))
            .unwrap();
        let url = CenterUrl::parse(&format!("https://{target}")).unwrap();
        match nerve_transport::net::reach(&url, Some(&proxy)).await {
            Ok(t) => (200, String::new(), Some(t)),
            Err(e) => {
                let status = e
                    .rsplit_once(": ")
                    .and_then(|(_, r)| r.split(' ').next()?.parse().ok())
                    .unwrap_or(0);
                (status, e, None)
            }
        }
    }

    /// Sends `CONNECT target` with `auth` in plain HTTP, as an `http://`
    /// proxy client does, and returns the answer's status and head.
    async fn connect_plain(
        relay: SocketAddr,
        target: &str,
        auth: Option<&str>,
    ) -> (u16, String, TcpStream) {
        let mut s = TcpStream::connect(relay).await.unwrap();
        let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
        if let Some(a) = auth {
            req.push_str(&format!("Proxy-Authorization: {a}\r\n"));
        }
        req.push_str("\r\n");
        s.write_all(req.as_bytes()).await.unwrap();
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match tokio::time::timeout(WAIT, s.read(&mut b)).await.unwrap() {
                Ok(1) => head.push(b[0]),
                _ => break,
            }
        }
        let head = String::from_utf8_lossy(&head).to_string();
        let status = head
            .split(' ')
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        (status, head, s)
    }

    /// A listener that echoes what it reads, standing in for a center.
    async fn echo() -> TcpListener {
        TcpListener::bind("127.0.0.1:0").await.unwrap()
    }

    fn serve_echo(l: TcpListener) {
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
    }

    fn port(l: &TcpListener) -> u16 {
        l.local_addr().unwrap().port()
    }

    /// Whether the tunnel `s` ends within `wait`.
    async fn ends(s: &mut BoxIo, wait: Duration) -> bool {
        let mut b = [0u8; 64];
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            match tokio::time::timeout_at(deadline, s.read(&mut b)).await {
                Err(_) => return false,
                Ok(Ok(0)) | Ok(Err(_)) => return true,
                Ok(Ok(_)) => continue,
            }
        }
    }

    async fn round_trip(s: &mut BoxIo, data: &[u8]) {
        s.write_all(data).await.unwrap();
        s.flush().await.unwrap();
        let mut got = vec![0u8; data.len()];
        tokio::time::timeout(WAIT, s.read_exact(&mut got))
            .await
            .expect("the tunnel carries bytes")
            .unwrap();
        assert_eq!(got, data);
    }

    fn get(head: &str) -> Request {
        Request {
            method: "CONNECT".into(),
            path: head.into(),
            query: String::new(),
            headers: Default::default(),
            body: Vec::new(),
        }
    }

    #[test]
    fn the_target_of_a_connect_is_host_and_port() {
        assert_eq!(
            authority("c.example:8443"),
            Some(("c.example".into(), 8443))
        );
        assert_eq!(authority("[::1]:443"), Some(("::1".into(), 443)));
        assert_eq!(authority("10.0.0.1:443"), Some(("10.0.0.1".into(), 443)));
        for bad in [
            "c.example",
            ":443",
            "c.example:x",
            "[::1]443",
            "u@c.example:443",
            "/x:1",
            "c:99999",
        ] {
            assert_eq!(authority(bad), None, "{bad}");
        }
    }

    /// The token is checked first; then only a center of this node over
    /// https that still knows it is a target; an off or locked relay grants
    /// nothing.
    #[test]
    fn a_connect_is_granted_with_a_token_and_to_a_paired_center_only() {
        let (token, hash) = new_token();
        let (other_token, _) = new_token();
        let mut cfg = NodeConfig::default();
        cfg.relay.listen = Some("127.0.0.1:7490".into());
        cfg.relay.nodes.push(relay_node("lab", hash.clone(), &[]));
        cfg.centers
            .push(center("home", "https://Center.Example:8443".into()));
        cfg.centers
            .push(center("local", "http://127.0.0.1:7480".into()));
        let mut gone = center("gone", "https://gone.example:8443".into());
        gone.revoked = true;
        cfg.centers.push(gone);
        let mut forgot = center("forgot", "https://forgot.example:8443".into());
        forgot.unknown = true;
        cfg.centers.push(forgot);
        let ask = |cfg: &NodeConfig, target: &str, auth: Option<String>| {
            let mut r = get(target);
            if let Some(a) = auth {
                r.headers.insert("proxy-authorization".into(), a);
            }
            decide(cfg, &r)
        };
        let good = || Some(basic("lab", &token));
        let g = ask(&cfg, "center.example:8443", good()).unwrap();
        assert_eq!((g.node.as_str(), g.center.as_str()), ("lab", "home"));
        assert_eq!(g.token_sha256, hash);
        for auth in [
            None,
            Some(basic("lab", &other_token)),
            Some(basic("other", &token)),
            Some(format!("Bearer {token}")),
            Some("Basic not-base64!".into()),
            Some(basic("lab", "")),
        ] {
            // Not even a center of this node is told apart without a token.
            assert_eq!(
                ask(&cfg, "center.example:8443", auth.clone()),
                Err(NO_TOKEN),
                "{auth:?}"
            );
            assert_eq!(
                ask(&cfg, "elsewhere.example:22", auth.clone()),
                Err(NO_TOKEN),
                "{auth:?}"
            );
        }
        for target in [
            "center.example:443",
            "elsewhere.example:8443",
            "127.0.0.1:7480",
            "localhost:7480",
            "gone.example:8443",
            "forgot.example:8443",
        ] {
            assert_eq!(ask(&cfg, target, good()), Err(NOT_A_CENTER), "{target}");
        }
        assert_eq!(ask(&cfg, "center.example", good()), Err(NOT_CONNECT));
        let mut r = get("center.example:8443");
        r.method = "GET".into();
        assert_eq!(decide(&cfg, &r), Err(NOT_CONNECT));
        let mut locked = cfg.clone();
        locked.locked = true;
        assert_eq!(ask(&locked, "center.example:8443", good()), Err(OFF));
        let mut off = cfg.clone();
        off.relay.listen = None;
        assert_eq!(ask(&off, "center.example:8443", good()), Err(OFF));

        // A granted tunnel holds only while all of that stays.
        assert!(still_granted(&cfg, &g));
        let changed: [&dyn Fn(&mut NodeConfig); 6] = [
            &|c| c.locked = true,
            &|c| c.relay.listen = None,
            &|c| c.relay.nodes.clear(),
            &|c| c.relay.nodes[0].token_sha256 = "b".repeat(64),
            &|c| c.centers.retain(|e| e.name != "home"),
            &|c| c.centers[0].revoked = true,
        ];
        for (i, change) in changed.iter().enumerate() {
            let mut c = cfg.clone();
            change(&mut c);
            assert!(!still_granted(&c, &g), "change {i}");
        }
    }

    /// A node with its token reaches a center of the jump node and nothing
    /// else: no other port of this machine, no plain http center, no center
    /// that revoked the jump node. Status names the tunnel.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_node_with_its_token_reaches_a_paired_center_and_nothing_else() {
        let home = echo().await;
        let (other, local, gone) = (echo().await, echo().await, echo().await);
        let mut revoked = center("gone", format!("https://127.0.0.1:{}", port(&gone)));
        revoked.revoked = true;
        let j = jump(
            vec![
                center("home", format!("https://127.0.0.1:{}", port(&home))),
                center("local", format!("http://127.0.0.1:{}", port(&local))),
                revoked,
            ],
            |_| {},
        )
        .await;
        let good = basic("lab", &j.token);
        let target = format!("127.0.0.1:{}", port(&home));

        let (status, head, _) = connect(j.addr, &j.pin, &target, None).await;
        assert_eq!(status, 407, "{head}");
        let (status, _, _) = connect(j.addr, &j.pin, &target, Some(&basic("lab", "wrong"))).await;
        assert_eq!(status, 407);
        for l in [&other, &local, &gone] {
            let (status, head, _) = connect(
                j.addr,
                &j.pin,
                &format!("127.0.0.1:{}", port(l)),
                Some(&good),
            )
            .await;
            assert_eq!(status, 403, "{head}");
            assert!(tokio::time::timeout(QUIET, l.accept()).await.is_err());
        }
        assert!(
            j.daemon.status()["relay"]["tunnels"]
                .as_array()
                .unwrap()
                .is_empty()
        );

        serve_echo(home);
        let (status, head, t) = connect(j.addr, &j.pin, &target, Some(&good)).await;
        assert_eq!(status, 200, "{head}");
        let mut t = t.unwrap();
        round_trip(&mut t, b"bytes only").await;
        let relay = j.daemon.status()["relay"].clone();
        assert_eq!(relay["status"], format!("listening on {}", j.addr));
        let tunnels = relay["tunnels"].as_array().unwrap();
        assert_eq!(tunnels.len(), 1, "{relay}");
        assert_eq!(
            (tunnels[0]["node"].as_str(), tunnels[0]["center"].as_str()),
            (Some("lab"), Some("home"))
        );
        drop(t);
        j.daemon.stop().await;
    }

    /// The owner cuts tunnels off: taking a node's token away ends that
    /// node's tunnels, unpairing a center ends the tunnels to it, `relay
    /// off` and `panic` end every tunnel and close the listener.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_owner_cuts_tunnels_off() {
        let (home, work) = (echo().await, echo().await);
        let (home_at, work_at) = (
            format!("127.0.0.1:{}", port(&home)),
            format!("127.0.0.1:{}", port(&work)),
        );
        serve_echo(home);
        serve_echo(work);
        let j = jump(
            vec![
                center("home", format!("https://{home_at}")),
                center("work", format!("https://{work_at}")),
            ],
            |_| {},
        )
        .await;
        let (token2, hash2) = new_token();
        j.daemon
            .owner_edit(|c| c.relay.nodes.push(relay_node("lab2", hash2, &[])));
        let (lab, lab2) = (basic("lab", &j.token), basic("lab2", &token2));
        let (addr, pin) = (j.addr, j.pin.clone());
        let open = |target: &str, auth: &str| {
            let (target, auth, pin) = (target.to_string(), auth.to_string(), pin.clone());
            async move {
                let (status, head, t) = connect(addr, &pin, &target, Some(&auth)).await;
                assert_eq!(status, 200, "{head}");
                let mut t = t.unwrap();
                round_trip(&mut t, b"up").await;
                t
            }
        };

        let mut a = open(&home_at, &lab).await;
        let mut b = open(&home_at, &lab2).await;
        j.daemon
            .owner_edit(|c| c.relay.nodes.retain(|n| n.name != "lab"));
        assert!(ends(&mut a, WAIT).await, "lab's tunnel outlived its token");
        assert!(
            !ends(&mut b, QUIET).await,
            "lab2's tunnel ended with lab's token"
        );
        round_trip(&mut b, b"still").await;
        let (status, _, _) = connect(j.addr, &j.pin, &home_at, Some(&lab)).await;
        assert_eq!(status, 407);

        let mut w = open(&work_at, &lab2).await;
        j.daemon
            .owner_edit(|c| c.centers.retain(|e| e.name != "home"));
        assert!(ends(&mut b, WAIT).await, "a tunnel outlived its center");
        round_trip(&mut w, b"other center").await;

        j.daemon.owner_edit(|c| c.relay.listen = None);
        assert!(ends(&mut w, WAIT).await, "a tunnel outlived the relay");
        let mut closed = false;
        for _ in 0..200 {
            if TcpStream::connect(j.addr).await.is_err() {
                closed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(closed, "the relay still listens");
        assert_eq!(j.daemon.status()["relay"]["status"], "off");

        j.daemon
            .owner_edit(|c| c.relay.listen = Some(j.addr.to_string()));
        assert_eq!(listening(&j.daemon).await, j.addr);
        let mut w = open(&work_at, &lab2).await;
        j.daemon.owner_edit(|c| c.locked = true);
        assert!(ends(&mut w, WAIT).await, "a tunnel outlived panic");

        // One audit entry per tunnel, with why it ended, and no token.
        let entries = || {
            nerve_policy::audit::AuditLog::new(j.daemon.paths().audit_log())
                .read()
                .unwrap()
                .into_iter()
                .filter(|v| v["kind"] == "relay")
                .collect::<Vec<_>>()
        };
        let mut relayed = entries();
        for _ in 0..200 {
            if relayed.len() >= 4 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
            relayed = entries();
        }
        let got: Vec<(String, String, String)> = relayed
            .iter()
            .map(|v| {
                let s = |k: &str| v[k].as_str().unwrap_or_default().to_string();
                (s("node"), s("center"), s("reason"))
            })
            .collect();
        let cut = "cut off by the owner";
        for want in [
            ("lab", "home"),
            ("lab2", "home"),
            ("lab2", "work"),
            ("lab2", "work"),
        ] {
            assert!(
                got.iter()
                    .any(|(n, c, r)| (n.as_str(), c.as_str()) == want && r == cut),
                "{want:?} in {got:?}"
            );
        }
        assert_eq!(got.len(), 4, "{got:?}");
        for v in &relayed {
            let end = v["end"].as_u64().unwrap();
            assert!(v["start"].as_u64().unwrap() <= end, "{v}");
            assert!(v["from"].as_str().unwrap().starts_with("127.0.0.1:"), "{v}");
            assert!(v["up"].as_u64().unwrap() > 0, "{v}");
        }
        let log = std::fs::read_to_string(j.daemon.paths().audit_log()).unwrap();
        for secret in [j.token.as_str(), token2.as_str()] {
            assert!(!log.contains(secret), "a token is in the audit log");
        }
        j.daemon.stop().await;
    }

    /// A relay that cannot listen says why in `status`, and listens once
    /// the owner gives it an address it can have.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_relay_that_cannot_listen_says_so() {
        let taken = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = taken.local_addr().unwrap().to_string();
        let dir = tempfile::tempdir().unwrap();
        let o = options(dir.path());
        let mut cfg = NodeConfig::default();
        cfg.relay.listen = Some(at.clone());
        with_certificate(&o.paths, &mut cfg);
        cfg.save(&o.paths.config_file()).unwrap();
        let daemon = Daemon::start(o).await.unwrap();
        let mut status = String::new();
        for _ in 0..400 {
            status = daemon.status()["relay"]["status"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            if status != "off" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            status.starts_with(&format!("cannot listen on {at}: ")),
            "{status}"
        );
        assert_eq!(daemon.status()["relay"]["address"], Value::Null);
        daemon.owner_edit(|c| c.relay.listen = Some("127.0.0.1:0".into()));
        listening(&daemon).await;
        daemon.stop().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_relay_keeps_to_its_limits() {
        let home = echo().await;
        let home_at = format!("127.0.0.1:{}", port(&home));
        serve_echo(home);
        let (token2, hash2) = new_token();
        let j = jump(vec![center("home", format!("https://{home_at}"))], |c| {
            c.relay.max_links = 2;
            c.relay.max_links_per_node = 1;
            c.relay.nodes.push(relay_node("lab2", hash2, &[]));
        })
        .await;
        let (lab, lab2) = (basic("lab", &j.token), basic("lab2", &token2));
        let (s, _, first) = connect(j.addr, &j.pin, &home_at, Some(&lab)).await;
        assert_eq!(s, 200);
        let mut first = first.unwrap();
        let (s, head, _) = connect(j.addr, &j.pin, &home_at, Some(&lab)).await;
        assert_eq!(s, 503, "a second tunnel of one node: {head}");
        let (s, _, _second) = connect(j.addr, &j.pin, &home_at, Some(&lab2)).await;
        assert_eq!(s, 200);
        round_trip(&mut first, b"x").await;
        drop(first);
        // The slot is free again once the tunnel is gone.
        let mut again = 0;
        for _ in 0..200 {
            again = connect(j.addr, &j.pin, &home_at, Some(&lab)).await.0;
            if again == 200 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(again, 200);
        j.daemon.stop().await;
    }

    /// TLS in front of the fake center, which speaks plain HTTP: the
    /// center end of the TLS link. Returns its port and pin.
    async fn tls_front(to: u16) -> (u16, String) {
        let id = ServerIdentity::generate(&["127.0.0.1".into()]).unwrap();
        let pin = id.pin();
        let acceptor = Acceptor::new(&id).unwrap();
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = port(&l);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = l.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let Ok(mut plain) = TcpStream::connect(("127.0.0.1", to)).await else {
                        return;
                    };
                    let _ = tokio::io::copy_bidirectional(&mut tls, &mut plain).await;
                });
            }
        });
        (at, pin)
    }

    /// A relayed node: its proxy is the jump node at `relay` over TLS pinned
    /// to `pin`, with the login `lab` and its token kept with the node's keys
    /// in `storage`.
    fn relayed(
        root: &std::path::Path,
        relay: SocketAddr,
        pin: &str,
        token: &str,
        storage: nerve_policy::config::SecretStorage,
    ) -> NodeOptions {
        let o = options(root);
        let mut cfg = NodeConfig::default();
        cfg.connection.proxy = Some(format!("https://{relay}"));
        cfg.connection.pin = Some(pin.into());
        cfg.connection.login = Some("lab".into());
        cfg.machine.secret_storage = storage;
        #[cfg(unix)]
        {
            cfg.machine.sudo_path = Some(fake_sudo(root, SUDO_PASSWORD).display().to_string());
        }
        cfg.save(&o.paths.config_file()).unwrap();
        crate::secrets::store_proxy_login(&o.paths, storage, token).unwrap();
        o
    }

    #[cfg(unix)]
    const SUDO_PASSWORD: &str = "conformance-right-password";

    /// The conformance suite's fake `sudo`: right password or `Sorry`.
    #[cfg(unix)]
    fn fake_sudo(root: &std::path::Path, right: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let script = root.join("fake-sudo");
        let body = format!(
            "#!/bin/sh\nv=\nwhile [ $# -gt 0 ]; do case \"$1\" in -S|-k) shift ;; -p) p=\"$2\"; shift 2 ;; \
             -v) v=1; shift ;; *) break ;; esac; done\nprintf %s \"$p\" >&2\nIFS= read -r pw\n\
             [ \"$pw\" = '{right}' ] || {{ echo 'Sorry, try again.' >&2; exit 1; }}\n\
             [ -n \"$v\" ] && exit 0\nexec \"$@\"\n"
        );
        std::fs::write(&script, body).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        script
    }

    /// The acceptance of the relay: a node whose only way to the center is a
    /// jump node pairs through it and passes the node part of the
    /// conformance suite there, the profile checks included (on Unix, where
    /// the suite's fake sudo runs).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_relayed_node_passes_the_node_part_through_a_jump_node() {
        let (jump_dir, node_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let running: Arc<Mutex<Vec<Daemon>>> = Arc::default();
        let held = running.clone();
        let (jd, nd) = (jump_dir.path().to_path_buf(), node_dir.path().to_path_buf());
        let report = nerve_conformance::node_part::run(move |link: PairLink| async move {
            let (front, pin) = tls_front(link.center.port).await;
            let url = format!("https://127.0.0.1:{front}");
            // The jump node is paired with the center at that address.
            let o = options(&jd);
            let (token, hash) = new_token();
            let mut cfg = NodeConfig::default();
            cfg.centers.push(center("home", url.clone()));
            cfg.relay.listen = Some("127.0.0.1:0".into());
            cfg.relay.nodes.push(relay_node("lab", hash, &[]));
            let relay_pin = with_certificate(&o.paths, &mut cfg);
            cfg.save(&o.paths.config_file()).unwrap();
            let jump = Daemon::start(o).await?;
            let relay = listening(&jump).await;
            lock(&held).push(jump);
            // The relayed node pairs through it over TLS, with the link's
            // code.
            let o = relayed(&nd, relay, &relay_pin, &token, Default::default());
            let link = PairLink {
                center: CenterUrl::parse(&url)?,
                code: link.code,
                pin: Some(pin),
            };
            crate::pair::pair(&o.paths, &link, Some("home")).await?;
            crate::cli::edit(&o.paths, |c| {
                c.centers[0].settings = nerve_policy::config::SettingsGrant::Write;
                Ok(())
            })
            .await?;
            let folder = o.home.join("work");
            std::fs::create_dir_all(&folder).unwrap();
            let folder = std::fs::canonicalize(&folder).unwrap();
            let node = Daemon::start(o).await?;
            lock(&held).push(node);
            // The link goes through the relay: its tunnel is there.
            let mut carried = false;
            for _ in 0..400 {
                let tunnels = lock(&held)[0].status()["relay"]["tunnels"].clone();
                if tunnels[0]["node"] == "lab" && tunnels[0]["center"] == "home" {
                    carried = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            if !carried {
                return Err("the relayed node's link does not go through the relay".into());
            }
            Ok(nerve_conformance::node_part::Setup {
                folder: cfg!(unix).then(|| nerve_policy::paths::to_wire(&folder)),
                #[cfg(unix)]
                sudo_password: Some(SUDO_PASSWORD.into()),
                #[cfg(not(unix))]
                sudo_password: None,
            })
        })
        .await;
        let daemons: Vec<Daemon> = std::mem::take(&mut *lock(&running));
        let tunnels = daemons
            .first()
            .map(|j| j.status()["relay"]["tunnels"].clone());
        for d in daemons {
            d.stop().await;
        }
        assert!(report.ok(), "{report}");
        if cfg!(unix) {
            assert!(
                report.outcomes.iter().any(|o| o.section.starts_with('7')),
                "{report}"
            );
        }
        // After `bye revoked` the node does not dial again, so no tunnel is
        // left open.
        assert_eq!(tunnels, Some(json!([])));
    }

    /// A proxy below the jump node (a chain: the jump node reaches its
    /// centers through it) that keeps every byte it carries and, when told,
    /// flips one in every chunk.
    struct Middle {
        addr: SocketAddr,
        seen: Arc<Mutex<Vec<u8>>>,
        tamper: Arc<AtomicBool>,
        tampered: Arc<AtomicU64>,
    }

    async fn middle() -> Middle {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let m = Middle {
            addr: l.local_addr().unwrap(),
            seen: Arc::default(),
            tamper: Arc::default(),
            tampered: Arc::default(),
        };
        let (seen, tamper, tampered) = (m.seen.clone(), m.tamper.clone(), m.tampered.clone());
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let (seen, tamper, tampered) = (seen.clone(), tamper.clone(), tampered.clone());
                tokio::spawn(async move {
                    let Ok(req) = read_request_head(&mut s).await else {
                        return;
                    };
                    let Ok(c) = TcpStream::connect(req.path.as_str()).await else {
                        return;
                    };
                    let _ = s
                        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await;
                    let (sr, sw) = s.into_split();
                    let (cr, cw) = c.into_split();
                    let one =
                        |mut from: tokio::net::tcp::OwnedReadHalf,
                         mut to: tokio::net::tcp::OwnedWriteHalf| {
                            let (seen, tamper, tampered) =
                                (seen.clone(), tamper.clone(), tampered.clone());
                            async move {
                                let mut buf = vec![0u8; 16 * 1024];
                                while let Ok(n) = from.read(&mut buf).await {
                                    if n == 0 {
                                        break;
                                    }
                                    lock(&seen).extend_from_slice(&buf[..n]);
                                    if tamper.load(Ordering::SeqCst) {
                                        buf[0] ^= 0x01;
                                        tampered.fetch_add(1, Ordering::SeqCst);
                                    }
                                    if to.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                                let _ = to.shutdown().await;
                            }
                        };
                    tokio::join!(one(sr, cw), one(cr, sw));
                });
            }
        });
        m
    }

    /// What the jump node passes on is TLS only: a proxy below it sees none
    /// of the link's plain text, and when it flips bits the link does not
    /// come up, with no message of it reaching the center.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_jump_node_can_neither_read_nor_alter_the_link_it_carries() {
        let mut fake = FakeCenter::start(false).await.unwrap();
        let (front, pin) = tls_front(fake.url.port).await;
        let url = format!("https://127.0.0.1:{front}");
        let m = middle().await;
        let j = jump(vec![center("home", url.clone())], |c| {
            c.connection.proxy = Some(format!("http://{}", m.addr));
        })
        .await;
        let node_dir = tempfile::tempdir().unwrap();
        let o = relayed(
            node_dir.path(),
            j.addr,
            &j.pin,
            &j.token,
            Default::default(),
        );
        let link = PairLink {
            center: CenterUrl::parse(&url).unwrap(),
            code: fake.code.clone(),
            pin: Some(pin),
        };
        crate::pair::pair(&o.paths, &link, Some("home"))
            .await
            .unwrap();
        let paired = fake.paired().expect("paired");
        // The pairing went the link's way, through the relay and below it.
        assert!(
            !lock(&m.seen).is_empty(),
            "the pairing did not go through the relay"
        );

        // Reading: the link works, and nothing of it is plain on the way.
        let node = Daemon::start(o.clone()).await.unwrap();
        let mut inc = fake
            .next_link(WAIT)
            .await
            .expect("the node dials through the relay");
        assert_eq!(inc.node_header, paired.node_id);
        fake_center::handshake(&mut inc.conn, &fake.center_id, &paired)
            .await
            .expect("handshake");
        inc.conn
            .call("describe", json!({"detail": "full"}), WAIT)
            .await
            .unwrap()
            .expect("describe");
        node.stop().await;
        let seen = String::from_utf8_lossy(&lock(&m.seen)).to_lowercase();
        assert!(seen.len() > 1000, "the link did not go through the middle");
        for plain in [
            paired.node_id.as_str(),
            paired.request.public_key.as_str(),
            fake.code.as_str(),
            "nerve-node",
            "nerve-connect",
            "/nerve/v0/",
            "\"method\"",
            "describe",
            "capabilities",
        ] {
            assert!(
                !seen.contains(&plain.to_lowercase()),
                "{plain} passed in the clear"
            );
        }

        // Altering: a flipped bit ends the link before any message counts.
        m.tamper.store(true, Ordering::SeqCst);
        let node = Daemon::start(o).await.unwrap();
        assert!(
            fake.next_link(Duration::from_secs(5)).await.is_none(),
            "an altered link reached the center"
        );
        assert!(m.tampered.load(Ordering::SeqCst) > 0, "nothing was altered");
        let status = node.status()["centers"][0]["status"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(status.starts_with("cannot connect"), "{status}");
        node.stop().await;
        j.daemon.stop().await;
    }

    /// A node limited to some centers reaches those and is refused the
    /// others with the answer a center the relay does not have gets, so its
    /// list tells it nothing of the rest; a change of the list ends its
    /// tunnels to a center it took away.
    #[test]
    fn a_node_limited_to_some_centers_is_refused_the_others_as_if_they_were_not_there() {
        let (token, hash) = new_token();
        let mut cfg = NodeConfig::default();
        cfg.relay.listen = Some("127.0.0.1:7490".into());
        cfg.relay.nodes.push(relay_node("lab", hash, &["home"]));
        cfg.centers
            .push(center("home", "https://home.example:8443".into()));
        cfg.centers
            .push(center("work", "https://work.example:8443".into()));
        let ask = |cfg: &NodeConfig, target: &str| {
            let mut r = get(target);
            r.headers
                .insert("proxy-authorization".into(), basic("lab", &token));
            decide(cfg, &r)
        };
        let g = ask(&cfg, "home.example:8443").unwrap();
        assert_eq!(g.center, "home");
        let other = ask(&cfg, "work.example:8443");
        let missing = ask(&cfg, "none.example:8443");
        assert_eq!(other, Err(NOT_A_CENTER));
        assert_eq!(other, missing);
        let mut moved = cfg.clone();
        moved.relay.nodes[0].centers = vec!["work".into()];
        assert!(!still_granted(&moved, &g));
        let mut every = cfg.clone();
        every.relay.nodes[0].centers.clear();
        assert!(still_granted(&every, &g));
        assert_eq!(ask(&every, "work.example:8443").unwrap().center, "work");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_node_limited_to_one_center_gets_a_tunnel_there_only() {
        let (home, work) = (echo().await, echo().await);
        let (home_at, work_at) = (
            format!("127.0.0.1:{}", port(&home)),
            format!("127.0.0.1:{}", port(&work)),
        );
        serve_echo(home);
        let nowhere = echo().await;
        let nowhere_at = format!("127.0.0.1:{}", port(&nowhere));
        let j = jump(
            vec![
                center("home", format!("https://{home_at}")),
                center("work", format!("https://{work_at}")),
            ],
            |c| c.relay.nodes[0].centers = vec!["home".into()],
        )
        .await;
        let lab = basic("lab", &j.token);
        let (status, head, t) = connect(j.addr, &j.pin, &home_at, Some(&lab)).await;
        assert_eq!(status, 200, "{head}");
        let mut t = t.unwrap();
        round_trip(&mut t, b"home").await;
        let (status, refused, _) = connect(j.addr, &j.pin, &work_at, Some(&lab)).await;
        let (status2, missing, _) = connect(j.addr, &j.pin, &nowhere_at, Some(&lab)).await;
        assert_eq!((status, status2), (403, 403));
        assert_eq!(
            refused.replace(&work_at, "<target>"),
            missing.replace(&nowhere_at, "<target>")
        );
        for l in [&work, &nowhere] {
            assert!(tokio::time::timeout(QUIET, l.accept()).await.is_err());
        }
        // `relay set-centers` takes home away: its tunnel ends.
        j.daemon
            .owner_edit(|c| c.relay.nodes[0].centers = vec!["work".into()]);
        assert!(
            ends(&mut t, WAIT).await,
            "a tunnel outlived its center on the list"
        );
        j.daemon.stop().await;
    }

    /// The relay hop is TLS: whoever reads the network between the relayed
    /// node and the relay sees neither the token nor the `CONNECT`, and the
    /// node's link works through it with its token in the keyring, where
    /// its keys are. A client that speaks plain HTTP to the relay is
    /// refused, and nothing is tunnelled for it.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_relay_hop_is_tls_and_a_plain_client_is_refused() {
        let mut fake = FakeCenter::start(false).await.unwrap();
        let (front, pin) = tls_front(fake.url.port).await;
        let url = format!("https://127.0.0.1:{front}");
        let j = jump(vec![center("home", url.clone())], |_| {}).await;
        let tap = middle_tap(j.addr).await;
        let node_dir = tempfile::tempdir().unwrap();
        let keyring = nerve_policy::config::SecretStorage::Keyring;
        let o = relayed(node_dir.path(), tap.0, &j.pin, &j.token, keyring);
        let link = PairLink {
            center: CenterUrl::parse(&url).unwrap(),
            code: fake.code.clone(),
            pin: Some(pin),
        };
        crate::pair::pair(&o.paths, &link, Some("home"))
            .await
            .unwrap();
        let paired = fake.paired().expect("paired");
        let node = Daemon::start(o.clone()).await.unwrap();
        let mut inc = fake
            .next_link(WAIT)
            .await
            .expect("the node dials through the relay");
        fake_center::handshake(&mut inc.conn, &fake.center_id, &paired)
            .await
            .expect("handshake");
        node.stop().await;
        // The token is where the node's keys are: the keyring here.
        let entry = crate::secrets::Entry::proxy_login(&o.paths);
        assert_eq!(
            crate::secrets::store::get(entry.account())
                .unwrap()
                .as_deref(),
            Some(j.token.as_str())
        );
        assert!(!o.paths.proxy_login_file().exists());
        let toml = std::fs::read_to_string(o.paths.config_file()).unwrap();
        assert!(!toml.contains(&j.token), "{toml}");
        // Nothing of the CONNECT crossed the tap in the clear.
        let seen = String::from_utf8_lossy(&lock(&tap.1)).to_lowercase();
        assert!(seen.len() > 1000, "the link did not go through the tap");
        let basic_value = basic("lab", &j.token).to_lowercase();
        for plain in [
            j.token.as_str(),
            basic_value.trim_start_matches("basic "),
            "connect ",
            "proxy-authorization",
            &format!("127.0.0.1:{front}"),
        ] {
            assert!(
                !seen.contains(&plain.to_lowercase()),
                "{plain} passed in the clear"
            );
        }

        // Plain HTTP to the relay: refused, the token is not taken.
        let target = format!("127.0.0.1:{front}");
        let (status, head, _) = connect_plain(j.addr, &target, Some(&basic("lab", &j.token))).await;
        assert_eq!(status, 400, "{head}");
        assert!(fake.next_link(QUIET).await.is_none());
        // A node set to the relay as an http:// proxy says why it cannot link.
        crate::cli::edit(&o.paths, |c| {
            c.connection.proxy = Some(format!("http://{}", j.addr));
            c.connection.pin = None;
            c.connection.login = None;
            Ok(())
        })
        .await
        .unwrap();
        let node = Daemon::start(o).await.unwrap();
        let mut status = String::new();
        for _ in 0..400 {
            status = node.status()["centers"][0]["status"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            if status.starts_with("cannot connect") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(status.contains("400"), "{status}");
        assert!(fake.next_link(QUIET).await.is_none());
        node.stop().await;
        assert!(
            nerve_policy::audit::AuditLog::new(j.daemon.paths().audit_log())
                .read()
                .unwrap()
                .iter()
                .filter(|v| v["kind"] == "relay")
                .count()
                == 1,
            "only the TLS tunnel is a tunnel"
        );
        j.daemon.stop().await;
    }

    /// A forwarder in front of `to` that keeps every byte it carries: what
    /// someone on the network between a relayed node and its relay sees.
    async fn middle_tap(to: SocketAddr) -> (SocketAddr, Arc<Mutex<Vec<u8>>>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = l.local_addr().unwrap();
        let seen: Arc<Mutex<Vec<u8>>> = Arc::default();
        let kept = seen.clone();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let seen = kept.clone();
                tokio::spawn(async move {
                    let Ok(c) = TcpStream::connect(to).await else {
                        return;
                    };
                    let (sr, sw) = s.into_split();
                    let (cr, cw) = c.into_split();
                    let one =
                        |mut from: tokio::net::tcp::OwnedReadHalf,
                         mut to: tokio::net::tcp::OwnedWriteHalf| {
                            let seen = seen.clone();
                            async move {
                                let mut buf = vec![0u8; 16 * 1024];
                                while let Ok(n) = from.read(&mut buf).await {
                                    if n == 0 {
                                        break;
                                    }
                                    lock(&seen).extend_from_slice(&buf[..n]);
                                    if to.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                                let _ = to.shutdown().await;
                            }
                        };
                    tokio::join!(one(sr, cw), one(cr, sw));
                });
            }
        });
        (at, seen)
    }

    /// Refusals without a valid token cost one log line a minute, with
    /// their count, however many come.
    #[test]
    fn refusals_without_a_token_are_told_counted_once_a_minute() {
        let r = Relays::default();
        let t0 = std::time::Instant::now();
        let n = |t: Option<Told>| t.map(|t| t.n);
        assert_eq!(n(r.note_tokenless(t0, "from a".into())), Some(1));
        for i in 1..10_000u64 {
            assert_eq!(
                r.note_tokenless(t0 + Duration::from_millis(i), "from b".into()),
                None
            );
        }
        let t = r
            .note_tokenless(
                t0 + TOKENLESS_EVERY + Duration::from_secs(1),
                "from c".into(),
            )
            .unwrap();
        assert_eq!((t.n, t.last.as_str()), (10_000, "from c"));
        assert_eq!(
            r.note_tokenless(t0 + TOKENLESS_EVERY * 2, "from d".into()),
            None
        );
    }

    /// A count left waiting is told once its minute is over, also when no
    /// refusal follows, with how long it took and the last refusal; a later
    /// refusal starts a count of its own.
    #[test]
    fn a_waiting_count_is_told_when_its_minute_ends() {
        let t = Tally::default();
        let t0 = std::time::Instant::now();
        let first = t.note(t0, "to x".into()).unwrap();
        assert_eq!((first.n, first.last.as_str()), (1, "to x"));
        for i in 1..=200u64 {
            assert_eq!(
                t.note(t0 + Duration::from_millis(100 * i), format!("to {i}")),
                None
            );
        }
        assert_eq!(
            t.flush(t0 + Duration::from_secs(30), false),
            None,
            "the minute is not over"
        );
        let told = t
            .flush(t0 + TOKENLESS_EVERY + Duration::from_secs(1), false)
            .unwrap();
        assert_eq!((told.n, told.last.as_str()), (200, "to 200"));
        // Over how long they came: from the first of the batch to its last,
        // not to the line.
        assert_eq!(told.over, Duration::from_millis(19_900));
        assert_eq!(
            t.flush(t0 + TOKENLESS_EVERY * 3, false),
            None,
            "nothing waits"
        );
        // An hour later, one refusal is one refusal.
        let later = t
            .note(t0 + Duration::from_secs(3600), "to y".into())
            .unwrap();
        assert_eq!((later.n, later.last.as_str()), (1, "to y"));
        let line = refused_line(Refused::Node, "lab", &told);
        assert!(
            line.contains("refused 200 tunnel(s) of relay node lab in 19 s, the last to 200"),
            "{line}"
        );
    }

    /// The relay's flush tells every kind of count that waited out its
    /// minute (without a token, each node's refusals, each node's plain
    /// token), and with `force` (the relay stops listening) every count
    /// still waiting, whatever its minute.
    #[test]
    fn the_relay_tells_every_kind_of_waiting_count() {
        let r = Relays::default();
        let t0 = std::time::Instant::now();
        let later = t0 + Duration::from_secs(1);
        let note_twice = |t: &Tally| {
            assert!(t.note(t0, "first".into()).is_some());
            assert!(t.note(later, "second".into()).is_none());
        };
        note_twice(&r.tokenless);
        note_twice(lock(&r.held_back).entry("lab".into()).or_default());
        note_twice(lock(&r.plain).entry("lab".into()).or_default());
        assert!(flush_tallies(&r, t0 + Duration::from_secs(30), false).is_empty());
        let mut lines = flush_tallies(&r, t0 + TOKENLESS_EVERY + Duration::from_secs(1), false);
        lines.sort();
        assert_eq!(lines.len(), 3, "{lines:#?}");
        assert!(
            lines[0].starts_with(
                "relay: refused 1 connection(s) without a valid relay token, the last second"
            ),
            "{lines:#?}"
        );
        assert!(
            lines[1].starts_with("relay: refused 1 tunnel(s) of relay node lab, the last second"),
            "{lines:#?}"
        );
        assert!(
            lines[2].starts_with(
                "relay: relay node lab sent its token in plain HTTP 1 time(s), the last second"
            ),
            "{lines:#?}"
        );
        assert_eq!(r.tokenless.pending(), 0);
        // Forced: told within the minute too, when the relay stops listening.
        let t1 = t0 + Duration::from_secs(200);
        assert!(lock(&r.held_back)["lab"].note(t1, "a".into()).is_some());
        assert!(lock(&r.held_back)["lab"].note(t1, "b".into()).is_none());
        assert!(flush_tallies(&r, t1, false).is_empty());
        let forced = flush_tallies(&r, t1, true);
        assert_eq!(forced.len(), 1, "{forced:#?}");
        assert!(
            forced[0].contains("relay node lab, the last b"),
            "{forced:#?}"
        );
        assert!(flush_tallies(&r, t1, true).is_empty(), "told twice");
    }

    /// A name that resolves to this machine is no way to it: only a center
    /// paired at a loopback address (or `localhost`) is reached there.
    #[test]
    fn a_tunnel_reaches_this_machine_only_at_a_center_paired_there() {
        let a = |s: &str| -> SocketAddr { s.parse().unwrap() };
        assert!(tunnel_addrs("127.0.0.1", vec![a("127.0.0.1:7443")]).is_ok());
        assert!(tunnel_addrs("::1", vec![a("[::1]:7443")]).is_ok());
        assert!(tunnel_addrs("LocalHost", vec![a("127.0.0.1:7443")]).is_ok());
        assert!(tunnel_addrs("center.example", vec![a("192.0.2.7:7443")]).is_ok());
        for addrs in [
            vec![a("127.0.0.1:7443")],
            vec![a("192.0.2.7:7443"), a("[::1]:7443")],
            vec![a("[::ffff:127.0.0.1]:7443")],
            vec![a("0.0.0.0:7443")],
        ] {
            let e = tunnel_addrs("center.example", addrs.clone()).unwrap_err();
            assert!(e.contains("resolves to this machine"), "{addrs:?}: {e}");
        }
        assert!(tunnel_addrs("center.example", vec![]).is_err());
    }

    /// A tunnel quiet for the idle span is closed and audited as such; one
    /// that carries a byte now and then stays.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_quiet_tunnel_is_closed_and_a_busy_one_stays() {
        let home = echo().await;
        let home_at = format!("127.0.0.1:{}", port(&home));
        serve_echo(home);
        let j = jump(vec![center("home", format!("https://{home_at}"))], |_| {}).await;
        j.daemon.relay().set_idle(Duration::from_millis(2000));
        let lab = basic("lab", &j.token);
        let (_, _, quiet) = connect(j.addr, &j.pin, &home_at, Some(&lab)).await;
        let (_, _, busy) = connect(j.addr, &j.pin, &home_at, Some(&lab)).await;
        let (mut quiet, mut busy) = (quiet.unwrap(), busy.unwrap());
        round_trip(&mut quiet, b"once").await;
        let started = std::time::Instant::now();
        while started.elapsed() < Duration::from_millis(4500) {
            round_trip(&mut busy, b"ping").await;
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        assert!(ends(&mut quiet, WAIT).await, "a quiet tunnel stayed open");
        assert!(!ends(&mut busy, QUIET).await, "a busy tunnel was closed");
        round_trip(&mut busy, b"still").await;
        let audited = nerve_policy::audit::AuditLog::new(j.daemon.paths().audit_log())
            .read()
            .unwrap();
        assert!(
            audited
                .iter()
                .any(|v| v["kind"] == "relay" && v["reason"] == "quiet too long"),
            "{audited:?}"
        );
        j.daemon.stop().await;
    }

    /// One address holds a few undecided connections at most: a peer that
    /// keeps its connections open without a word does not lock others out.
    #[tokio::test(flavor = "multi_thread")]
    async fn one_address_cannot_hold_the_relay_for_everyone() {
        let home = echo().await;
        let home_at = format!("127.0.0.1:{}", port(&home));
        serve_echo(home);
        let j = jump(vec![center("home", format!("https://{home_at}"))], |_| {}).await;
        let from = |ip: &str| {
            let ip: std::net::IpAddr = ip.parse().unwrap();
            let addr = j.addr;
            async move {
                let s = tokio::net::TcpSocket::new_v4().ok()?;
                s.bind(SocketAddr::new(ip, 0)).ok()?;
                s.connect(addr).await.ok()
            }
        };
        let mut held = Vec::new();
        for _ in 0..UNDECIDED_PER_PEER {
            let Some(s) = from("127.0.0.2").await else {
                eprintln!("  (no 127.0.0.2 here; nothing to show)");
                j.daemon.stop().await;
                return;
            };
            held.push(s);
        }
        // Let the relay take them all before the next one.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut over = from("127.0.0.2").await.unwrap();
        let mut b = [0u8; 1];
        let closed = tokio::time::timeout(Duration::from_secs(2), over.read(&mut b)).await;
        assert!(
            matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
            "a fifth silent connection of one address was held: {closed:?}"
        );
        // Another address goes on as before.
        let lab = basic("lab", &j.token);
        let (status, head, t) = connect(j.addr, &j.pin, &home_at, Some(&lab)).await;
        assert_eq!(status, 200, "{head}");
        round_trip(&mut t.unwrap(), b"through").await;
        drop(held);
        j.daemon.stop().await;
    }

    /// `relay ls` asks the running node (its socket, on Windows its pipe)
    /// and names the tunnels; `relay token` and `relay rm` say when the old
    /// token stops working and the tunnels end: at once where the node took
    /// the change, else at its next start (Windows), and the relay does as
    /// they say.
    #[tokio::test(flavor = "multi_thread")]
    async fn relay_ls_names_the_tunnels_and_rm_says_when_they_end() {
        use clap::Parser;
        let home = echo().await;
        let home_at = format!("127.0.0.1:{}", port(&home));
        serve_echo(home);
        let j = jump_with(
            vec![center("home", format!("https://{home_at}"))],
            |_| {},
            true,
        )
        .await;
        let paths = j.daemon.paths().clone();
        let cli = |args: &[&str]| {
            let mut argv = vec![
                "nerve-node".to_string(),
                "--config-dir".into(),
                paths.config_dir.display().to_string(),
                "--state-dir".into(),
                paths.state_dir.display().to_string(),
            ];
            argv.extend(args.iter().map(|s| s.to_string()));
            async move {
                let cli = crate::cli::Cli::try_parse_from(argv).unwrap();
                let mut out = Vec::new();
                crate::cli::execute(cli, &mut out).await.unwrap();
                String::from_utf8(out).unwrap()
            }
        };
        let lab = basic("lab", &j.token);
        let (_, _, t) = connect(j.addr, &j.pin, &home_at, Some(&lab)).await;
        let mut t = t.unwrap();
        round_trip(&mut t, b"up").await;
        let ls = cli(&["relay", "ls"]).await;
        assert!(
            ls.contains("tunnel lab from 127.0.0.1:") && ls.contains(" to center home for "),
            "{ls}"
        );
        // A new token. Where the running node took the change, the old one is
        // dead at once and its tunnels end. On Windows the running node takes
        // it at its next start, and the output says that the old token still
        // opens tunnels until then, and the new one is refused.
        let out = cli(&["relay", "token", "lab", "--address", "127.0.0.1:7490"]).await;
        let token2 = nerve_proto::link::RelayLink::parse(out.lines().nth(1).unwrap())
            .unwrap()
            .token;
        let lab2 = basic("lab", &token2);
        if cfg!(windows) {
            assert!(
                out.contains("a removed or replaced token still opens new tunnels")
                    && out.contains("Restart-Service nerve-node"),
                "{out}"
            );
            assert!(!out.contains("no longer works"), "{out}");
            assert!(!ends(&mut t, QUIET).await);
            let (old, _, _) = connect(j.addr, &j.pin, &home_at, Some(&lab)).await;
            let (new, _, _) = connect(j.addr, &j.pin, &home_at, Some(&lab2)).await;
            assert_eq!((old, new), (200, 407), "as the output says");
        } else {
            assert!(
                out.ends_with("the old token no longer works, and its tunnels end now\n"),
                "{out}"
            );
            assert!(
                ends(&mut t, WAIT).await,
                "the tunnel outlived its old token"
            );
            let (old, _, _) = connect(j.addr, &j.pin, &home_at, Some(&lab)).await;
            assert_eq!(old, 407);
            let (new, head, t2) = connect(j.addr, &j.pin, &home_at, Some(&lab2)).await;
            assert_eq!(new, 200, "{head}");
            t = t2.unwrap();
            round_trip(&mut t, b"again").await;
        }
        let rm = cli(&["relay", "rm", "lab"]).await;
        if cfg!(windows) {
            assert!(rm.contains("Restart-Service nerve-node"), "{rm}");
            assert!(!rm.contains("end now"), "{rm}");
        } else {
            assert_eq!(
                rm,
                "relay node lab removed\nits token no longer works, and its tunnels end now\n"
            );
            assert!(ends(&mut t, WAIT).await, "the tunnel outlived its token");
        }
        j.daemon.stop().await;
    }

    /// Centers behind one address (a reverse proxy with a path per center)
    /// are granted together or not at all: the path travels inside the TLS
    /// the relay does not read, so a list that splits them could not hold.
    #[test]
    fn centers_that_share_an_address_are_granted_together_or_not_at_all() {
        let (token, hash) = new_token();
        let mut cfg = NodeConfig::default();
        cfg.relay.listen = Some("127.0.0.1:7490".into());
        cfg.relay.nodes.push(relay_node("lab", hash, &[]));
        cfg.centers
            .push(center("a", "https://h.example:443/a".into()));
        cfg.centers
            .push(center("b", "https://h.example:443/b".into()));
        cfg.centers
            .push(center("c", "https://c.example:443".into()));
        let ask = |cfg: &NodeConfig, target: &str| {
            let mut r = get(target);
            r.headers
                .insert("proxy-authorization".into(), basic("lab", &token));
            decide(cfg, &r)
        };
        let with = |list: &[&str]| {
            let mut c = cfg.clone();
            c.relay.nodes[0].centers = list.iter().map(|n| n.to_string()).collect();
            c
        };
        let all = ask(&cfg, "h.example:443").unwrap();
        assert_eq!((all.center.as_str(), all.centers.len()), ("a, b", 2));
        for list in [&["a"][..], &["b"], &["c"]] {
            assert_eq!(
                ask(&with(list), "h.example:443"),
                Err(NOT_A_CENTER),
                "{list:?}"
            );
        }
        assert_eq!(ask(&with(&["a", "b"]), "h.example:443").unwrap(), all);
        assert_eq!(ask(&with(&["c"]), "c.example:443").unwrap().center, "c");
        // Taking one of them off the list ends the tunnel to both.
        assert!(still_granted(&with(&["a", "b"]), &all));
        assert!(!still_granted(&with(&["a"]), &all));
        // So does pairing another center at that address.
        let mut more = cfg.clone();
        more.centers
            .push(center("d", "https://H.example:443/d".into()));
        assert!(!still_granted(&more, &all));
    }

    /// A node opens a bounded number of tunnels a minute, so a token holder
    /// cannot rotate the audit log by opening and closing them in a loop.
    #[test]
    fn a_node_opens_a_bounded_number_of_tunnels_a_minute() {
        let r = Relays::default();
        let t0 = std::time::Instant::now();
        let limit = nerve_policy::config::Relay::default().max_opens_per_minute as usize;
        assert_eq!(limit, 30);
        for i in 0..limit {
            assert!(
                r.may_open("lab", limit, t0 + Duration::from_millis(i as u64)),
                "{i}"
            );
        }
        assert!(!r.may_open("lab", limit, t0 + Duration::from_secs(1)));
        assert!(r.may_open("lab2", limit, t0 + Duration::from_secs(1)));
        assert!(r.may_open("lab", limit, t0 + Duration::from_secs(61)));
        // A relay behind this one gets a larger share from its owner.
        assert!(r.may_open("lab", 100, t0 + Duration::from_secs(1)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_relay_refuses_a_node_that_opens_too_many_tunnels() {
        let home = echo().await;
        let home_at = format!("127.0.0.1:{}", port(&home));
        serve_echo(home);
        let j = jump(vec![center("home", format!("https://{home_at}"))], |c| {
            c.relay.max_links = 64;
            c.relay.max_links_per_node = 64;
        })
        .await;
        let lab = basic("lab", &j.token);
        let mut held = Vec::new();
        for i in 0..30 {
            let (status, head, t) = connect(j.addr, &j.pin, &home_at, Some(&lab)).await;
            assert_eq!(status, 200, "{i}: {head}");
            held.push(t.unwrap());
        }
        let (status, head, _) = connect(j.addr, &j.pin, &home_at, Some(&lab)).await;
        assert_eq!(status, 503, "{head}");
        drop(held);
        j.daemon.stop().await;
    }

    /// A peer is counted by its address, and an IPv6 one also by its /64
    /// with a larger share: the machines of one LAN share the /64, so it
    /// cannot be the only count. Link-local addresses have no /64 that
    /// means anything (their scope is not in the address).
    #[test]
    fn a_peer_counts_by_its_address_and_its_ipv6_slash_64() {
        let r = Relays::default();
        let ip = |s: &str| -> std::net::IpAddr { s.parse().unwrap() };
        for _ in 0..UNDECIDED_PER_PEER {
            assert!(r.take_peer(ip("2001:db8:1:2::10")));
        }
        assert!(!r.take_peer(ip("2001:db8:1:2::10")));
        // A neighbour on the same LAN keeps its own share.
        assert!(r.take_peer(ip("2001:db8:1:2::20")));
        r.give_peer(ip("2001:db8:1:2::20"));
        // One machine with many addresses in the /64 gets the /64's share.
        let mut taken = UNDECIDED_PER_PEER;
        for host in 0x100..0x200u16 {
            if !r.take_peer(ip(&format!("2001:db8:1:2::{host:x}"))) {
                break;
            }
            taken += 1;
        }
        assert_eq!(taken, UNDECIDED_PER_PREFIX);
        assert!(r.take_peer(ip("2001:db8:1:3::1")), "another /64");
        // Link-local and IPv4 peers count by their address alone.
        for _ in 0..UNDECIDED_PER_PEER {
            assert!(r.take_peer(ip("fe80::1")));
        }
        assert!(!r.take_peer(ip("fe80::1")));
        assert!(r.take_peer(ip("fe80::2")));
        assert_eq!(prefix_of(ip("fe80::a:b:c:d")), None);
        assert_eq!(prefix_of(ip("10.0.0.7")), None);
        assert_eq!(prefix_of(ip("::ffff:10.0.0.7")), None);
        assert_eq!(
            prefix_of(ip("2001:db8:1:2:aaaa::1")),
            prefix_of(ip("2001:db8:1:2:bbbb::9"))
        );
        // Given back, a slot is free again.
        r.give_peer(ip("2001:db8:1:2::100"));
        assert!(r.take_peer(ip("2001:db8:1:2::999")));
    }

    /// The first byte, TLS and the head share one deadline: a peer that is
    /// slow at each step holds its slot no longer than that.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_undecided_connection_has_one_deadline_for_every_step() {
        let j = jump(vec![], |_| {}).await;
        j.daemon.relay().set_undecided(Duration::from_millis(1000));
        let mut s = TcpStream::connect(j.addr).await.unwrap();
        let started = std::time::Instant::now();
        tokio::time::sleep(Duration::from_millis(900)).await;
        // The start of a TLS record, then nothing more.
        s.write_all(&[0x16]).await.unwrap();
        let mut b = [0u8; 16];
        let closed = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match s.read(&mut b).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => continue,
                }
            }
        })
        .await;
        assert!(closed.is_ok(), "the connection was held");
        let took = started.elapsed();
        assert!(
            took < Duration::from_millis(1600),
            "held for {took:?}, past the one deadline"
        );
        j.daemon.stop().await;
    }

    /// A node with its token gets a counted line a minute for its refusals,
    /// whatever it asks (a target that is no center, a token sent in plain
    /// HTTP), so it cannot rotate the log either: after the first of each,
    /// the rest are counted for the next line, not told one by one. (The
    /// counts are read rather than the log: `tracing` caches whether a line
    /// is wanted once per process, and other tests run without this one's
    /// subscriber.)
    #[tokio::test(flavor = "multi_thread")]
    async fn a_node_with_its_token_cannot_flood_the_log_with_refusals() {
        let j = jump(vec![], |_| {}).await;
        let lab = basic("lab", &j.token);
        for _ in 0..40 {
            let (status, _, _) = connect(j.addr, &j.pin, "127.0.0.1:9", Some(&lab)).await;
            assert_eq!(status, 403);
            let (status, _, _) = connect_plain(j.addr, "127.0.0.1:9", Some(&lab)).await;
            assert_eq!(status, 400);
        }
        let relays = j.daemon.relay();
        let held = lock(&relays.held_back).get("lab").map(Tally::pending);
        assert_eq!(held, Some(39), "403s told one by one");
        let plain = lock(&relays.plain).get("lab").map(Tally::pending);
        assert_eq!(plain, Some(39), "plain tokens told one by one");
        assert_eq!(
            relays.tokenless.pending(),
            0,
            "a valid token was taken for none"
        );
        j.daemon.stop().await;
    }

    /// A tunnel that is granted gives its undecided slot back before the
    /// relay dials: a slow center keeps no other connection of its peer out.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_slow_dial_keeps_no_other_connection_of_the_peer_out() {
        let home = echo().await;
        let home_at = format!("127.0.0.1:{}", port(&home));
        serve_echo(home);
        // The relay reaches its centers through a proxy that never answers
        // for `dead`.
        let dead = echo().await;
        let dead_at = format!("127.0.0.1:{}", port(&dead));
        let stall = stalling_proxy(port(&dead)).await;
        let (token2, hash2) = new_token();
        let j = jump(
            vec![
                center("home", format!("https://{home_at}")),
                center("dead", format!("https://{dead_at}")),
            ],
            |c| {
                c.relay.max_links = 64;
                c.relay.max_links_per_node = 64;
                c.relay.nodes.push(relay_node("lab2", hash2, &[]));
                c.connection.proxy = Some(format!("http://{stall}"));
            },
        )
        .await;
        let lab = basic("lab", &j.token);
        let mut stuck = Vec::new();
        for _ in 0..UNDECIDED_PER_PEER {
            let (addr, pin, target, auth) = (j.addr, j.pin.clone(), dead_at.clone(), lab.clone());
            stuck.push(tokio::spawn(async move {
                connect(addr, &pin, &target, Some(&auth)).await.0
            }));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        let started = std::time::Instant::now();
        let (status, head, t) =
            connect(j.addr, &j.pin, &home_at, Some(&basic("lab2", &token2))).await;
        assert_eq!(status, 200, "{head}");
        assert!(started.elapsed() < Duration::from_secs(5));
        round_trip(&mut t.unwrap(), b"through").await;
        for s in stuck {
            s.abort();
        }
        j.daemon.stop().await;
    }

    /// An HTTP proxy that tunnels everywhere but to `stall`, where it never
    /// answers the `CONNECT`.
    async fn stalling_proxy(stall: u16) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let Ok(req) = read_request_head(&mut s).await else {
                        return;
                    };
                    if req.path.ends_with(&format!(":{stall}")) {
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        return;
                    }
                    let Ok(mut c) = TcpStream::connect(req.path.as_str()).await else {
                        return;
                    };
                    let _ = s
                        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await;
                    let _ = tokio::io::copy_bidirectional(&mut s, &mut c).await;
                });
            }
        });
        at
    }

    /// The same address in another spelling is the same address: centers
    /// there are granted together, and a list that splits them is refused.
    #[test]
    fn one_address_in_two_spellings_is_one_address() {
        assert!(same_host("2001:db8::1", "2001:db8:0:0::1"));
        assert!(same_host("H.Example.", "h.example"));
        assert!(same_host("::ffff:10.0.0.1", "10.0.0.1"));
        assert!(!same_host("h.example", "g.example"));
        let (token, hash) = new_token();
        let mut cfg = NodeConfig::default();
        cfg.relay.listen = Some("127.0.0.1:7490".into());
        cfg.relay.nodes.push(relay_node("lab", hash, &["a"]));
        cfg.centers
            .push(center("a", "https://[2001:db8::1]/a".into()));
        cfg.centers
            .push(center("b", "https://[2001:db8:0:0::1]/b".into()));
        let mut r = get("[2001:db8::1]:443");
        r.headers
            .insert("proxy-authorization".into(), basic("lab", &token));
        assert_eq!(decide(&cfg, &r), Err(NOT_A_CENTER));
    }

    /// The owner's `relay.max_opens_per_minute` is the budget the relay
    /// applies, not the default.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_relay_applies_the_owners_budget_of_opens() {
        let home = echo().await;
        let home_at = format!("127.0.0.1:{}", port(&home));
        serve_echo(home);
        let j = jump(vec![center("home", format!("https://{home_at}"))], |c| {
            c.relay.max_opens_per_minute = 3;
        })
        .await;
        let lab = basic("lab", &j.token);
        let mut held = Vec::new();
        for i in 0..3 {
            let (status, head, t) = connect(j.addr, &j.pin, &home_at, Some(&lab)).await;
            assert_eq!(status, 200, "{i}: {head}");
            held.push(t.unwrap());
        }
        let (status, head, _) = connect(j.addr, &j.pin, &home_at, Some(&lab)).await;
        assert_eq!(status, 503, "{head}");
        assert_eq!(j.daemon.status()["relay"]["max_opens_per_minute"], 3);
        drop(held);
        j.daemon.stop().await;
    }

    /// When the relay stops listening, it tells the count that waited: an
    /// owner who turns the relay off (or stops the node) right after the
    /// first line still learns of the rest.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_relay_tells_what_waited_when_it_stops_listening() {
        let j = jump(vec![], |_| {}).await;
        for _ in 0..2 {
            let (status, _, _) = connect(j.addr, &j.pin, "127.0.0.1:9", None).await;
            assert_eq!(status, 407);
        }
        assert_eq!(j.daemon.relay().tokenless.pending(), 1, "the second waits");
        j.daemon.owner_edit(|c| c.relay.listen = None);
        for _ in 0..400 {
            if j.daemon.status()["relay"]["status"] == "off" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(j.daemon.status()["relay"]["status"], "off");
        assert_eq!(j.daemon.relay().tokenless.pending(), 0, "it was not told");
        j.daemon.stop().await;
    }

    /// Through a proxy of its own whose first address drops packets, the
    /// relay still reaches the center within its dial deadline: the next
    /// address of the proxy gets its share of the time. Linux, where a full
    /// accept queue drops new connections; skipped where `localhost` does
    /// not name `[::1]` first or the queue does not fill that way.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread")]
    async fn the_relays_own_proxy_gets_the_dial_deadline_too() {
        let home = echo().await;
        let home_at = format!("127.0.0.1:{}", port(&home));
        serve_echo(home);
        // The working proxy on IPv4, and a full queue on [::1] at its port.
        let proxy = stalling_proxy(0).await;
        let p = proxy.port();
        let first = tokio::net::lookup_host(("localhost", p))
            .await
            .ok()
            .and_then(|mut a| a.next());
        if first.map(|a| a.ip()) != Some("::1".parse().unwrap()) {
            eprintln!("  (localhost does not name [::1] first here; nothing to show)");
            return;
        }
        let Ok(sock) = tokio::net::TcpSocket::new_v6() else {
            return;
        };
        if sock
            .bind(SocketAddr::new("::1".parse().unwrap(), p))
            .is_err()
        {
            eprintln!("  (cannot bind [::1]:{p}; nothing to show)");
            return;
        }
        let full = sock.listen(0).unwrap();
        let mut queued = Vec::new();
        for _ in 0..4 {
            if let Ok(Ok(s)) =
                tokio::time::timeout(Duration::from_millis(300), TcpStream::connect(("::1", p)))
                    .await
            {
                queued.push(s);
            }
        }
        let dropped =
            tokio::time::timeout(Duration::from_millis(500), TcpStream::connect(("::1", p)))
                .await
                .is_err();
        if !dropped {
            eprintln!("  (the full queue does not drop connections here; nothing to show)");
            return;
        }
        let j = jump(vec![center("home", format!("https://{home_at}"))], |c| {
            c.connection.proxy = Some(format!("http://localhost:{p}"));
        })
        .await;
        let started = std::time::Instant::now();
        let (status, head, t) =
            connect(j.addr, &j.pin, &home_at, Some(&basic("lab", &j.token))).await;
        assert_eq!(status, 200, "{head}");
        assert!(started.elapsed() < DIAL_DEADLINE, "{:?}", started.elapsed());
        round_trip(&mut t.unwrap(), b"through").await;
        drop((full, queued));
        j.daemon.stop().await;
    }

    /// A relay node with limits of its own (a relay behind this one) gets
    /// them, while every other node keeps the relay's: raising the limits
    /// for one does not raise them for every token.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_node_with_limits_of_its_own_gets_them_and_no_other_node_does() {
        let home = echo().await;
        let home_at = format!("127.0.0.1:{}", port(&home));
        serve_echo(home);
        let (token2, hash2) = new_token();
        let j = jump(vec![center("home", format!("https://{home_at}"))], |c| {
            c.relay.max_links = 16;
            c.relay.max_links_per_node = 2;
            c.relay.max_opens_per_minute = 3;
            let mut inner = relay_node("inner", hash2, &[]);
            inner.max_links = Some(6);
            inner.max_opens_per_minute = Some(10);
            c.relay.nodes.push(inner);
        })
        .await;
        let (lab, inner) = (basic("lab", &j.token), basic("inner", &token2));
        let mut held = Vec::new();
        for i in 0..6 {
            let (status, head, t) = connect(j.addr, &j.pin, &home_at, Some(&inner)).await;
            assert_eq!(status, 200, "inner {i}: {head}");
            held.push(t.unwrap());
        }
        let (status, _, _) = connect(j.addr, &j.pin, &home_at, Some(&inner)).await;
        assert_eq!(status, 503, "inner past its own limit");
        for i in 0..2 {
            let (status, head, t) = connect(j.addr, &j.pin, &home_at, Some(&lab)).await;
            assert_eq!(status, 200, "lab {i}: {head}");
            held.push(t.unwrap());
        }
        let (status, _, _) = connect(j.addr, &j.pin, &home_at, Some(&lab)).await;
        assert_eq!(status, 503, "lab keeps the relay's limit");
        drop(held);
        j.daemon.stop().await;
    }
}
