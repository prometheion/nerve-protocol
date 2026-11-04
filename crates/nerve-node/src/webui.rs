//! The node's web UI (docs/user/node-web-ui.md): a page like the desktop
//! app's, served by the installed node on Linux while `ui.listen` is set
//! (`nerve-node ui on`). Off, the task only waits for a change of the config:
//! no listener, no timer, no file.
//!
//! - **Who gets in.** A connection from this machine is let in only from the
//!   owner's or root's account ([`peer`]); every other one, a command of
//!   `nerve-run` among them, is closed before a byte is read. Every one that
//!   is let in needs a token to log in, on loopback too: the tokens are made
//!   at the CLI (`nerve-node ui token add`), and node.toml keeps only their
//!   SHA-256. A wrong token costs [`webui::WRONG_SECRET_DELAY`] and never
//!   locks the login, which any local process could otherwise keep locked.
//! - **Sessions** are the shared header sessions (nerve_transport::webui),
//!   12 hours, in memory only. One ends with its token, with `ui off`, with
//!   a restart, and every one ends with `panic`: a session that leaked must
//!   not undo it.
//! - **Changes** go only through the owner socket's own path
//!   (crate::owner::run_for_web), as the owner, from a fixed list of command
//!   shapes: the CLI's checks hold for each, and the command is told it comes
//!   from the web UI, which may not change the UI's own settings.

#![deny(unsafe_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::OwnedSemaphorePermit;

use nerve_policy::NodeConfig;
use nerve_transport::http::{self, Request, Response};
use nerve_transport::net::BoxIo;
use nerve_transport::tls::Acceptor;
use nerve_transport::webui::{self, Sessions, host_is_address, host_is_loopback, origin_matches};

use crate::daemon::{Shared, lock};
use crate::owner::{Endpoint, Owners};

mod pages;
pub(crate) mod peer;

const INDEX: &str = include_str!("webui/index.html");
const APP_JS: &str = include_str!("webui/app.js");

/// The largest request body: the biggest form of the UI is far smaller.
const BODY_MAX: usize = 256 * 1024;
/// Connections at once, but for the wrong tokens that wait
/// ([`webui::LATE`]).
const SLOTS: usize = 64;
/// Connections at once of one local account, or of one other machine (an
/// IPv6 /64 counts as one), from the check of the peer to the answer. A
/// browser opens six at once to load a page, and every answer closes its
/// connection, so a page in two tabs fits; and no peer holds every slot.
/// On loopback every peer has the same address, so the account is what
/// tells them apart.
const PER_PEER: usize = 16;
/// How long a TLS handshake may take.
const HANDSHAKE: Duration = Duration::from_secs(10);
/// How soon a listener that could not bind tries again.
const RETRY: Duration = Duration::from_secs(5);

const WRONG_TOKEN: &str = "Wrong token.";

/// The web UI's state, for `status` and the CLI.
#[derive(Default)]
pub(crate) struct WebUi {
    /// Whether this node serves the UI at all: only one with an owner
    /// endpoint, the installed node, does.
    served: AtomicBool,
    status: Mutex<String>,
    bound: Mutex<Option<SocketAddr>>,
    pub(crate) sessions: Sessions,
    /// Whether the node was locked when the sessions were last looked at:
    /// a panic ends them all.
    locked: AtomicBool,
    /// The newest version of the config that `settle` has seen. A copy of
    /// the config that was taken before a later write settled is older than
    /// this and is passed over: it would set `locked` back to what the node
    /// was a moment ago.
    seen: Mutex<u64>,
    /// How many times the node was locked. A command the web UI runs
    /// watches it and stops when it changes: a session that was let in
    /// before a panic must not finish its command after it (an unlock
    /// would undo the panic).
    locks: tokio::sync::watch::Sender<u64>,
    /// The wrong tokens: told in the log once a minute, and their answers
    /// wait with neither a slot nor a place of their peer, so a command of
    /// the owner's account that posts them as fast as it can keeps the
    /// owner's own login free.
    wrong: webui::WrongSecrets,
    /// The connections at once, by who made them ([`PER_PEER`]).
    places: Mutex<HashMap<Who, usize>>,
}

/// Who a connection is counted for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Who {
    /// A local account.
    Uid(u32),
    /// Another machine: its address, or its /64.
    Address(std::net::IpAddr),
}

impl Who {
    fn remote(ip: std::net::IpAddr) -> Who {
        Who::Address(crate::relay::prefix_of(ip).unwrap_or(ip.to_canonical()))
    }
}

impl WebUi {
    pub(crate) fn status(&self, cfg: &NodeConfig) -> Value {
        let status = lock(&self.status).clone();
        json!({
            "served": self.served.load(Ordering::Relaxed),
            "listen": cfg.ui.listen,
            "address": lock(&self.bound).map(|a| a.to_string()),
            "status": if status.is_empty() { "off".to_string() } else { status },
            "sessions": self.sessions.len(),
        })
    }

    /// How many times the node was locked so far.
    pub(crate) fn lock_count(&self) -> u64 {
        *self.locks.borrow()
    }

    fn set_status(&self, s: impl Into<String>, bound: Option<SocketAddr>) {
        *lock(&self.status) = s.into();
        *lock(&self.bound) = bound;
    }

    /// Ends the sessions the config no longer allows: those of a revoked
    /// token, and every one when the node was locked since the last look.
    /// The daemon calls it with every change of the config (`Shared::bump`),
    /// so a panic ends the sessions and stops their commands before its own
    /// answer, and two changes that the UI task would see as one (a panic
    /// and an unlock after it) cannot hide the panic.
    pub(crate) fn settle(&self, cfg: &NodeConfig) {
        let mut seen = lock(&self.seen);
        if cfg.version < *seen {
            return;
        }
        *seen = cfg.version;
        let was = self.locked.swap(cfg.locked, Ordering::SeqCst);
        if cfg.locked && !was {
            if !self.sessions.is_empty() {
                tracing::info!("web UI: the node is locked, so every session ends");
            }
            self.sessions.end_all();
            self.locks.send_modify(|n| *n += 1);
            return;
        }
        self.sessions.retain(|s| {
            s.via
                .as_deref()
                .is_some_and(|h| token_label(cfg, h).is_some())
        });
    }

    /// [`settle`](Self::settle) for a `panic`: the node counts as locked
    /// again and every session ends even when it was locked already, so the
    /// owner's second panic (a session was started in the lock, and may have
    /// leaked) undoes what that session could still do.
    pub(crate) fn settle_panic(&self, cfg: &NodeConfig) {
        let before = self.lock_count();
        self.settle(cfg);
        if cfg.locked && self.lock_count() == before {
            self.sessions.end_all();
            self.locks.send_modify(|n| *n += 1);
        }
    }

    /// Counts a wrong token, and says how many to tell in the log.
    fn wrong_token(&self) -> Option<u32> {
        self.wrong.note()
    }

    /// Takes a place for a connection of `who`, if it has one left.
    fn place_for(self: &Arc<Self>, who: Who) -> Option<Place> {
        let mut w = lock(&self.places);
        let n = w.entry(who).or_insert(0);
        if *n >= PER_PEER {
            return None;
        }
        *n += 1;
        Some(Place {
            ui: self.clone(),
            who,
        })
    }

    /// Waits before a wrong token is answered ([`webui::WrongSecrets::wait`]).
    async fn wait_late(&self) {
        self.wrong.wait().await
    }
}

/// A connection's place among those of its peer.
struct Place {
    ui: Arc<WebUi>,
    who: Who,
}

impl Drop for Place {
    fn drop(&mut self) {
        let mut w = lock(&self.ui.places);
        if let Some(n) = w.get_mut(&self.who) {
            *n -= 1;
            if *n == 0 {
                w.remove(&self.who);
            }
        }
    }
}

/// The label of the token whose hash is `hash`.
fn token_label<'a>(cfg: &'a NodeConfig, hash: &str) -> Option<&'a str> {
    cfg.ui
        .tokens
        .iter()
        .find(|t| ct_eq(t.token_sha256.as_bytes(), hash.as_bytes()))
        .map(|t| t.label.as_str())
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// What a signed-in request runs its commands with: the UI's context, and
/// a watch on the node being locked, taken before the session was checked.
struct Call<'a> {
    ctx: &'a Ctx,
    /// None for the one command that locks the node.
    locks: Option<tokio::sync::watch::Receiver<u64>>,
    /// How many times the node was locked when the request began; none for
    /// the command that locks it.
    epoch: Option<u64>,
}

impl std::ops::Deref for Call<'_> {
    type Target = Ctx;

    fn deref(&self) -> &Ctx {
        self.ctx
    }
}

/// Who the UI runs its commands for, and whose accounts it lets in.
struct Ctx {
    shared: Arc<Shared>,
    program: PathBuf,
    owners: Owners,
    /// The uid of an owner given by name, once it was found: not looked up
    /// again for every connection.
    named_uid: OnceLock<u32>,
}

impl Ctx {
    /// The owner the commands run for, as the owner socket names them.
    fn who(&self) -> String {
        match &self.owners {
            Owners::Named(n) => n.clone(),
            Owners::Uids(u) => u
                .first()
                .map(|uid| crate::account::name_of(*uid).unwrap_or_else(|| format!("uid {uid}")))
                .unwrap_or_else(|| "root".into()),
            Owners::Sids(_) => "root".into(),
        }
    }

    /// The local accounts let in: the owner's and root's.
    fn owner_uids(&self) -> Vec<u32> {
        let mut uids = vec![0];
        match &self.owners {
            Owners::Named(n) => {
                let found = self.named_uid.get().copied().or_else(|| {
                    let uid = crate::account::lookup(n).ok().flatten()?.uid;
                    Some(*self.named_uid.get_or_init(|| uid))
                });
                uids.extend(found);
            }
            Owners::Uids(u) => uids.extend(u),
            Owners::Sids(_) => {}
        }
        uids
    }
}

/// Serves the web UI while the config says so, for the owners of
/// `endpoint`: listens on `ui.listen`, and listens again when that changes.
pub(crate) async fn run(shared: Arc<Shared>, endpoint: Endpoint) {
    shared.webui.served.store(true, Ordering::Relaxed);
    let ctx = Arc::new(Ctx {
        shared: shared.clone(),
        program: endpoint.program,
        owners: endpoint.owners,
        named_uid: OnceLock::new(),
    });
    let mut changed = shared.changed.subscribe();
    let mut stop = shared.stop.subscribe();
    shared
        .webui
        .locked
        .store(shared.config().locked, Ordering::SeqCst);
    // The address the last bind failed on: the first failure there is an
    // error in the log, its retries are detail.
    let mut failed_on: Option<String> = None;
    // Whether the loop woke for its retry and not for a change of the config.
    let mut retry = false;
    loop {
        if *stop.borrow() {
            break;
        }
        changed.borrow_and_update();
        let cfg = shared.config();
        shared.webui.settle(&cfg);
        // A change of the config is tried afresh: what the last try said (a
        // failure the change may mend) must not be taken for this one's
        // while `listen` reads the key. A retry keeps it.
        if let Some(at) = cfg.ui.listen.as_deref()
            && !retry
        {
            shared.webui.set_status(format!("starting on {at}"), None);
        }
        let wait = match cfg.ui.listen.clone() {
            None => {
                shared.webui.sessions.end_all();
                shared.webui.set_status("off", None);
                None
            }
            Some(at) => match listen(&shared, &cfg, &at).await {
                Ok((listener, also, tls)) => {
                    failed_on = None;
                    let bound = listener.local_addr().ok();
                    let shown = bound.map_or_else(|| at.clone(), |a| a.to_string());
                    tracing::info!("web UI: listening on {shown}");
                    shared
                        .webui
                        .set_status(format!("listening on {shown}"), bound);
                    let pin = cfg.ui.pin.clone();
                    serve(
                        &ctx,
                        (listener, also),
                        tls,
                        (&at, &pin),
                        &mut changed,
                        &mut stop,
                    )
                    .await;
                    tracing::info!("web UI: stopped listening on {shown}");
                    shared.webui.sessions.end_all();
                    shared.webui.set_status("off", None);
                    continue;
                }
                Err(e) => {
                    if failed_on.as_deref() == Some(at.as_str()) {
                        tracing::debug!("web UI: cannot listen on {at}: {e}");
                    } else {
                        tracing::error!("web UI: cannot listen on {at}: {e}");
                    }
                    failed_on = Some(at.clone());
                    shared
                        .webui
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
                retry = false;
            }
            _ = stop.changed() => break,
            _ = async {
                match wait {
                    Some(w) => tokio::time::sleep(w).await,
                    None => std::future::pending().await,
                }
            } => retry = true,
        }
    }
    shared.webui.sessions.end_all();
    shared.webui.set_status("off", None);
}

/// The listener for `at`, and its TLS beyond loopback: the certificate's
/// key from where the node keeps its keys. Only loopback is served without
/// TLS; without its key the UI does not listen beyond it at all.
///
/// On `127.0.0.1` (or `[::1]`) the other family's loopback address is held
/// at the same port, too: `localhost` resolves to either, and an account
/// that listened on the one the node does not would get the login that a
/// browser meant for the node. A port that is taken there is as much an
/// error as one taken here; a machine without IPv6 has nothing to hold.
async fn listen(
    shared: &Arc<Shared>,
    cfg: &NodeConfig,
    at: &str,
) -> Result<(TcpListener, Option<TcpListener>, Option<Acceptor>), String> {
    let addr: SocketAddr = at
        .parse()
        .map_err(|_| format!("{at:?} is not an address and a port"))?;
    let tls = if addr.ip().is_loopback() {
        None
    } else {
        // The keyring may block (the Secret Service asks to unlock), so off
        // the runtime's threads.
        let (paths, storage) = (shared.paths.clone(), cfg.machine.secret_storage);
        let id = tokio::task::spawn_blocking(move || crate::secrets::ui_tls(&paths, storage))
            .await
            .map_err(|e| format!("the key read stopped: {e}"))??
            .ok_or(NO_CERT)?;
        if cfg.ui.pin.as_deref() != Some(id.pin().as_str()) {
            return Err(NO_CERT.into());
        }
        Some(Acceptor::new(&id)?)
    };
    let listener = TcpListener::bind(addr).await.map_err(|e| e.to_string())?;
    let also = match other_loopback(addr.ip()) {
        None => None,
        Some(ip) => {
            let port = listener.local_addr().map_err(|e| e.to_string())?.port();
            match TcpListener::bind((ip, port)).await {
                Ok(l) => Some(l),
                // Asked for any port, the one given may be taken on the
                // other address: no one has the UI's page there.
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && addr.port() != 0 => {
                    return Err(format!("{ip}:{port}: {e} (`localhost` would reach it)"));
                }
                Err(_) => None,
            }
        }
    };
    Ok((listener, also, tls))
}

/// The loopback address of the other family, for `127.0.0.1` and `::1`.
fn other_loopback(ip: std::net::IpAddr) -> Option<std::net::IpAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    match ip {
        std::net::IpAddr::V4(v4) if v4 == Ipv4Addr::LOCALHOST => Some(Ipv6Addr::LOCALHOST.into()),
        std::net::IpAddr::V6(v6) if v6 == Ipv6Addr::LOCALHOST => Some(Ipv4Addr::LOCALHOST.into()),
        _ => None,
    }
}

/// Why the UI does not listen beyond loopback without its certificate.
const NO_CERT: &str = "the web UI has no TLS certificate for an address beyond loopback, or not the one ui.pin names; `nerve-node ui on --listen <address> --new-cert` makes one";

/// Takes connections on `listeners` until the address changes or the daemon
/// stops; sessions the config no longer allows end on the way.
async fn serve(
    ctx: &Arc<Ctx>,
    (listener, also): (TcpListener, Option<TcpListener>),
    tls: Option<Acceptor>,
    (at, pin): (&str, &Option<String>),
    changed: &mut tokio::sync::watch::Receiver<u64>,
    stop: &mut tokio::sync::watch::Receiver<bool>,
) {
    let slots = Arc::new(tokio::sync::Semaphore::new(SLOTS));
    let Ok(local) = listener.local_addr() else {
        return;
    };
    let how = peer::Lookup::for_listener(local);
    tracing::debug!("web UI: peers are looked up by {how:?}");
    let also = also.map(|l| {
        let how = l.local_addr().map_or(how, peer::Lookup::for_listener);
        (l, how)
    });
    loop {
        tokio::select! {
            (got, how) = accept_on(&listener, how, &also) => match got {
                Ok((io, peer)) => {
                    let Some((place, slot)) = admit(ctx, &io, peer, how, &slots) else {
                        continue;
                    };
                    let (ctx, tls) = (ctx.clone(), tls.clone());
                    tokio::spawn(async move {
                        connection(&ctx, io, place, slot, tls).await;
                    });
                }
                Err(e) => {
                    tracing::debug!("web UI: accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            r = changed.changed() => {
                if r.is_err() {
                    return;
                }
                let cfg = ctx.shared.config();
                ctx.shared.webui.settle(&cfg);
                // A new certificate is listened with anew, and ends the
                // sessions of the old.
                if cfg.ui.listen.as_deref() != Some(at) || cfg.ui.pin != *pin {
                    return;
                }
            }
            _ = stop.changed() => return,
        }
    }
}

/// The next connection of `listener` or of the one of the other family,
/// with the way its peers are looked up.
async fn accept_on(
    listener: &TcpListener,
    how: peer::Lookup,
    also: &Option<(TcpListener, peer::Lookup)>,
) -> (std::io::Result<(TcpStream, SocketAddr)>, peer::Lookup) {
    tokio::select! {
        got = listener.accept() => (got, how),
        (got, how) = async {
            match also {
                Some((l, how)) => (l.accept().await, *how),
                None => std::future::pending().await,
            }
        } => (got, how),
    }
}

/// Whether a connection from `peer` goes on, with its place and its slot.
/// The peer is judged here, before a byte is read and before it takes
/// anything: a peer that is closed costs one lookup.
fn admit(
    ctx: &Ctx,
    io: &TcpStream,
    peer: SocketAddr,
    how: peer::Lookup,
    slots: &Arc<tokio::sync::Semaphore>,
) -> Option<(Place, OwnedSemaphorePermit)> {
    let local = io.local_addr().ok()?;
    let who = match peer::judge_now(peer, local, &ctx.owner_uids(), how) {
        peer::Verdict::Closed => {
            tracing::debug!(
                "web UI: closed a connection from {peer}, a local account that is not the owner's"
            );
            return None;
        }
        peer::Verdict::Local(uid) => Who::Uid(uid),
        peer::Verdict::Remote => Who::remote(peer.ip()),
    };
    let Some(place) = ctx.shared.webui.place_for(who) else {
        tracing::debug!("web UI: {peer} has {PER_PEER} connections at once; closed one");
        return None;
    };
    let Ok(slot) = slots.clone().try_acquire_owned() else {
        tracing::debug!("web UI: every connection slot is taken; closed one from {peer}");
        return None;
    };
    Some((place, slot))
}

/// One connection, of a peer let in: one request is answered. A wrong
/// token's answer waits, with neither its place nor its slot.
async fn connection(
    ctx: &Arc<Ctx>,
    tcp: TcpStream,
    place: Place,
    slot: OwnedSemaphorePermit,
    tls: Option<Acceptor>,
) {
    let Ok(local) = tcp.local_addr() else { return };
    let served_over_tls = tls.is_some();
    let mut io: BoxIo = match tls {
        None => Box::new(tcp),
        Some(a) => match tokio::time::timeout(HANDSHAKE, a.accept(tcp)).await {
            Ok(Ok(io)) => io,
            _ => return,
        },
    };
    let (resp, api, late) = match http::read_request(&mut io, BODY_MAX).await {
        Ok(req) => {
            let api = webui::is_api(&req.path);
            let (resp, late) = request(ctx, req, local, served_over_tls).await;
            (resp, api, late)
        }
        Err(_) => (Response::text(400, "bad request"), false, false),
    };
    if late {
        drop(place);
        drop(slot);
        ctx.shared.webui.wait_late().await;
    }
    let _ = webui::with_security_headers(resp, api).write(&mut io).await;
}

/// Answers one request, and says whether the answer is a wrong token's,
/// which waits before it goes.
async fn request(ctx: &Ctx, req: Request, local: SocketAddr, tls: bool) -> (Response, bool) {
    if !host_allowed(req.header("host"), local, tls) {
        return (
            Response::text(403, "this UI answers only to a loopback host name"),
            false,
        );
    }
    if req.method == "GET" {
        if let Some(r) = webui::asset(&req.path) {
            return (r, false);
        }
        match req.path.as_str() {
            "/" | "/index.html" => {
                return (Response::new(200, "text/html; charset=utf-8", INDEX), false);
            }
            "/app.js" => {
                return (
                    Response::new(200, "text/javascript; charset=utf-8", APP_JS),
                    false,
                );
            }
            // No Clear-Site-Data here: a browser clears the storage of
            // every tab of the origin with it, and a tab that opens the
            // login would sign the others out.
            "/login" => {
                return (
                    webui::login_page("Web UI token", "This machine's node."),
                    false,
                );
            }
            _ => {}
        }
    }
    // Every post comes from this UI's own page: a browser always names it.
    if req.method == "POST"
        && !req
            .header("origin")
            .is_some_and(|o| origin_matches(o, req.header("host")))
    {
        return (
            Response::text(403, "cross-origin requests are refused"),
            false,
        );
    }
    if req.method == "POST" && req.path == "/login" {
        return login(ctx, &req);
    }
    (signed_in_request(ctx, &req).await, false)
}

/// Answers a request of the page but a login: Sign out, and the API.
async fn signed_in_request(ctx: &Ctx, req: &Request) -> Response {
    if req.method == "POST" && req.path == "/logout" {
        if let Some((t, _)) = ctx.shared.webui.sessions.of(req) {
            ctx.shared.webui.sessions.end(&t);
        }
        // What a page that held this port before left at this origin
        // goes with Sign out: its storage and its workers (and the
        // sessions of this browser's other tabs).
        return Response::json(200, &json!({})).with_header("Clear-Site-Data", "\"storage\"");
    }
    if !webui::is_api(&req.path) {
        return Response::text(404, "not found");
    }
    // Watched before the session is checked: a panic after the check
    // stops the commands, and one before it has ended the session.
    let locks = ctx.shared.webui.locks.subscribe();
    let epoch = *locks.borrow();
    let call = Call {
        ctx,
        epoch: Some(epoch),
        locks: Some(locks),
    };
    let cfg = ctx.shared.config();
    let signed_in = ctx.shared.webui.sessions.of(req).is_some_and(|(_, s)| {
        s.via
            .as_deref()
            .is_some_and(|h| token_label(&cfg, h).is_some())
    });
    if req.path == "/api/session" && req.method == "GET" {
        return Response::json(200, &json!({"login": true, "logged_in": signed_in}));
    }
    if !signed_in {
        return Response::json(401, &json!({"error": "log in first"}));
    }
    let body: Value = if req.body.is_empty() {
        json!({})
    } else {
        match serde_json::from_slice(&req.body) {
            Ok(v) => v,
            Err(e) => return Response::json(400, &json!({"error": format!("bad JSON: {e}")})),
        }
    };
    match api(&call, req, &body, &cfg).await {
        Ok(v) => Response::json(200, &v),
        Err((status, e)) => Response::json(status, &json!({ "error": e })),
    }
}

/// Whether a request may name `host`: on loopback only a loopback name, or
/// the address the UI listens on as a number (`ui on --listen 127.0.0.2:…`),
/// since a page of another name that resolves to this address (DNS
/// rebinding) must be refused. Over TLS (a UI beyond loopback) any name: the
/// owner may use one of their own, and the machine's own name often resolves
/// to a loopback address on the machine itself (127.0.1.1); a rebound page
/// cannot get past the UI's self-signed certificate.
fn host_allowed(host: Option<&str>, local: SocketAddr, tls: bool) -> bool {
    tls || !local.ip().is_loopback() || host_is_loopback(host) || host_is_address(host, local.ip())
}

/// Checks the token a login posted. The answer is the session for the page
/// to keep, or the reason it was refused, which waits before it goes
/// (`true`); the token never appears in a URL or a log.
fn login(ctx: &Ctx, req: &Request) -> (Response, bool) {
    let given = webui::posted_secret(req);
    let hash = crate::relay::token_hash(&given);
    let cfg = ctx.shared.config();
    let label = (!given.is_empty())
        .then(|| token_label(&cfg, &hash))
        .flatten();
    let Some(label) = label else {
        if let Some(n) = ctx.shared.webui.wrong_token() {
            if n == 1 {
                tracing::warn!("web UI: a sign-in was refused: wrong token");
            } else {
                tracing::warn!("web UI: {n} sign-ins were refused in the last minute: wrong token");
            }
        }
        return (Response::json(401, &json!({"error": WRONG_TOKEN})), true);
    };
    let token = ctx.shared.webui.sessions.start(Some(hash));
    tracing::info!("web UI: signed in (token `{label}`)");
    (Response::json(200, &json!({"session": token})), false)
}

type ApiResult = Result<Value, (u16, String)>;

/// The API of a signed-in page. Each change is one command of the CLI, of
/// a fixed shape, run as the owner (crate::owner::run_for_web).
async fn api(ctx: &Call<'_>, req: &Request, b: &Value, cfg: &NodeConfig) -> ApiResult {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/api/overview") => Ok(overview(ctx, cfg)),
        // The panic is the lock itself: it is not stopped by it.
        ("POST", "/api/panic") => {
            let own = Call {
                ctx: ctx.ctx,
                locks: None,
                epoch: None,
            };
            command(&own, &["panic"], None).await
        }
        ("POST", "/api/unlock") => command(ctx, &["unlock"], None).await,
        ("GET", "/api/ui") => Ok(ui_settings(ctx, cfg)),
        ("POST", "/api/ui/revoke") => {
            let label = text(b, "label")?;
            command(ctx, &["ui", "token", "rm", "--", label], None).await
        }
        _ => pages::api(ctx, req, b)
            .await
            .unwrap_or_else(|| Err((404, "not found".into()))),
    }
}

/// What the Overview page shows: the node's status, as `nerve-node status`
/// reads it.
fn overview(ctx: &Ctx, _cfg: &NodeConfig) -> Value {
    ctx.shared.status()
}

/// Settings › Web UI: where it listens, and the tokens by label.
fn ui_settings(ctx: &Ctx, cfg: &NodeConfig) -> Value {
    json!({
        "ui": ctx.shared.webui.status(cfg),
        "tokens": cfg.ui.tokens.iter().map(|t| json!({"label": t.label, "made": t.made})).collect::<Vec<_>>(),
    })
}

/// The text field `key` of a body; a value that would read as an option is
/// refused, though every one goes after `--` anyway.
fn text<'a>(b: &'a Value, key: &str) -> Result<&'a str, (u16, String)> {
    let v = b[key]
        .as_str()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| (400, format!("{key} is missing")))?;
    if v.starts_with('-') {
        return Err((400, format!("{key} may not start with -")));
    }
    Ok(v)
}

/// Runs `args` with `--json` for the owner, and gives what it said: its
/// messages, or its error as a 400.
async fn command(ctx: &Call<'_>, args: &[&str], input: Option<&str>) -> ApiResult {
    let mut all: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    all.insert(0, "--json".into());
    let ran = crate::owner::run_for_web(
        &ctx.shared,
        &ctx.program,
        &ctx.who(),
        &all,
        input,
        ctx.locks.clone(),
        ctx.epoch,
    )
    .await
    .map_err(|e| (400, e))?;
    answer(ran)
}

/// What a command's `--json` output says: its data, or its error.
fn answer(ran: crate::owner::Ran) -> ApiResult {
    let last = ran.out.lines().rev().find(|l| !l.trim().is_empty());
    let v: Option<Value> = last.and_then(|l| serde_json::from_str(l).ok());
    match v {
        Some(v) if v.get("error").is_some() => Err((
            400,
            v["error"]
                .as_str()
                .unwrap_or("the command failed")
                .to_string(),
        )),
        Some(v) if ran.code == 0 => Ok(v),
        _ if ran.code == 0 => Ok(json!({})),
        _ => {
            let e = ran.err.trim();
            Err((
                400,
                if e.is_empty() {
                    format!("the command failed with exit code {}", ran.code)
                } else {
                    e.to_string()
                },
            ))
        }
    }
}

#[cfg(test)]
mod tests;
