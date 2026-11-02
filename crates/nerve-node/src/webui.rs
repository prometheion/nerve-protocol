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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};

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
/// Connections at once.
const SLOTS: usize = 64;
/// Connections of one local account, or of one other machine's address, at
/// once that have not sent their request yet: on loopback every peer has
/// the same address, so this keeps one command of the owner's from holding
/// every slot; beyond it, one machine (as the relay's limit per address).
const WAITING_PER_PEER: usize = 4;
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
    /// Wrong tokens since the last line about them, and when that was.
    wrong: Mutex<(u32, Option<Instant>)>,
    /// The connections that wait for their request, by who made them.
    waiting: Mutex<HashMap<Waiter, usize>>,
}

/// Who a waiting connection is counted for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Waiter {
    /// A local account.
    Uid(u32),
    /// Another machine.
    Address(std::net::IpAddr),
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

    fn set_status(&self, s: impl Into<String>, bound: Option<SocketAddr>) {
        *lock(&self.status) = s.into();
        *lock(&self.bound) = bound;
    }

    /// Ends the sessions the config no longer allows: those of a revoked
    /// token, and every one when the node was locked since the last look.
    fn settle(&self, cfg: &NodeConfig) {
        let was = self.locked.swap(cfg.locked, Ordering::SeqCst);
        if cfg.locked && !was {
            if !self.sessions.is_empty() {
                tracing::info!("web UI: the node is locked, so every session ends");
            }
            self.sessions.end_all();
            return;
        }
        self.sessions.retain(|s| {
            s.via
                .as_deref()
                .is_some_and(|h| token_label(cfg, h).is_some())
        });
    }

    /// Counts a wrong token, and says how many to tell in the log: the
    /// first of a minute at once, the rest when the next comes after it.
    fn wrong_token(&self) -> Option<u32> {
        let mut w = lock(&self.wrong);
        w.0 += 1;
        match w.1 {
            Some(t) if t.elapsed() < Duration::from_secs(60) => None,
            _ => {
                let n = w.0;
                *w = (0, Some(Instant::now()));
                Some(n)
            }
        }
    }

    /// Takes a waiting place for `who`, if it has one left.
    fn wait_for(self: &Arc<Self>, who: Waiter) -> Option<Waiting> {
        let mut w = lock(&self.waiting);
        let n = w.entry(who).or_insert(0);
        if *n >= WAITING_PER_PEER {
            return None;
        }
        *n += 1;
        Some(Waiting {
            ui: self.clone(),
            who,
        })
    }
}

/// A connection that has not sent its request yet.
struct Waiting {
    ui: Arc<WebUi>,
    who: Waiter,
}

impl Drop for Waiting {
    fn drop(&mut self) {
        let mut w = lock(&self.ui.waiting);
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

/// Who the UI runs its commands for, and whose accounts it lets in.
struct Ctx {
    shared: Arc<Shared>,
    program: PathBuf,
    owners: Owners,
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
                if let Ok(Some(a)) = crate::account::lookup(n) {
                    uids.push(a.uid);
                }
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
    loop {
        if *stop.borrow() {
            break;
        }
        changed.borrow_and_update();
        let cfg = shared.config();
        shared.webui.settle(&cfg);
        let wait = match cfg.ui.listen.clone() {
            None => {
                shared.webui.sessions.end_all();
                shared.webui.set_status("off", None);
                None
            }
            Some(at) => match listen(&shared, &cfg, &at).await {
                Ok((listener, tls)) => {
                    failed_on = None;
                    let bound = listener.local_addr().ok();
                    let shown = bound.map_or_else(|| at.clone(), |a| a.to_string());
                    tracing::info!("web UI: listening on {shown}");
                    shared
                        .webui
                        .set_status(format!("listening on {shown}"), bound);
                    let pin = cfg.ui.pin.clone();
                    serve(&ctx, listener, tls, (&at, &pin), &mut changed, &mut stop).await;
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
    shared.webui.sessions.end_all();
    shared.webui.set_status("off", None);
}

/// The listener for `at`, and its TLS beyond loopback: the certificate's
/// key from where the node keeps its keys. Only loopback is served without
/// TLS; without its key the UI does not listen beyond it at all.
async fn listen(
    shared: &Arc<Shared>,
    cfg: &NodeConfig,
    at: &str,
) -> Result<(TcpListener, Option<Acceptor>), String> {
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
    Ok((listener, tls))
}

/// Why the UI does not listen beyond loopback without its certificate.
const NO_CERT: &str = "the web UI has no TLS certificate for an address beyond loopback, or not the one ui.pin names; `nerve-node ui on --listen <address> --new-cert` makes one";

/// Takes connections on `listener` until the address changes or the daemon
/// stops; sessions the config no longer allows end on the way.
async fn serve(
    ctx: &Arc<Ctx>,
    listener: TcpListener,
    tls: Option<Acceptor>,
    (at, pin): (&str, &Option<String>),
    changed: &mut tokio::sync::watch::Receiver<u64>,
    stop: &mut tokio::sync::watch::Receiver<bool>,
) {
    let slots = Arc::new(tokio::sync::Semaphore::new(SLOTS));
    loop {
        tokio::select! {
            got = listener.accept() => match got {
                Ok((io, peer)) => {
                    let Ok(slot) = slots.clone().try_acquire_owned() else {
                        tracing::debug!("web UI: every connection slot is taken; closed one from {peer}");
                        continue;
                    };
                    let (ctx, tls) = (ctx.clone(), tls.clone());
                    tokio::spawn(async move {
                        connection(&ctx, io, peer, tls).await;
                        drop(slot);
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

/// One connection: the peer is judged before a byte is read, then one
/// request is answered.
async fn connection(ctx: &Arc<Ctx>, tcp: TcpStream, peer: SocketAddr, tls: Option<Acceptor>) {
    let Ok(local) = tcp.local_addr() else { return };
    let who = match peer::judge_now(peer, local, &ctx.owner_uids()) {
        peer::Verdict::Closed => {
            tracing::debug!(
                "web UI: closed a connection from {peer}, a local account that is not the owner's"
            );
            return;
        }
        peer::Verdict::Local(uid) => Waiter::Uid(uid),
        peer::Verdict::Remote => Waiter::Address(peer.ip()),
    };
    let Some(waiting) = ctx.shared.webui.wait_for(who) else {
        tracing::debug!("web UI: too many connections of {peer} wait; closed one");
        return;
    };
    let mut io: BoxIo = match tls {
        None => Box::new(tcp),
        Some(a) => match tokio::time::timeout(HANDSHAKE, a.accept(tcp)).await {
            Ok(Ok(io)) => io,
            _ => return,
        },
    };
    let (resp, api) = match http::read_request(&mut io, BODY_MAX).await {
        Ok(req) => {
            drop(waiting);
            let api = webui::is_api(&req.path);
            (request(ctx, req, local).await, api)
        }
        Err(_) => (Response::text(400, "bad request"), false),
    };
    let _ = webui::with_security_headers(resp, api).write(&mut io).await;
}

/// Answers one request.
async fn request(ctx: &Ctx, req: Request, local: SocketAddr) -> Response {
    if !host_allowed(req.header("host"), local) {
        return Response::text(403, "this UI answers only to a loopback host name");
    }
    if req.method == "GET" {
        if let Some(r) = webui::asset(&req.path) {
            return r;
        }
        match req.path.as_str() {
            "/" | "/index.html" => return Response::new(200, "text/html; charset=utf-8", INDEX),
            "/app.js" => return Response::new(200, "text/javascript; charset=utf-8", APP_JS),
            // No Clear-Site-Data here: a browser clears the storage of
            // every tab of the origin with it, and a tab that opens the
            // login would sign the others out.
            "/login" => return webui::login_page("Web UI token", "This machine's node."),
            _ => {}
        }
    }
    // Every post comes from this UI's own page: a browser always names it.
    if req.method == "POST"
        && !req
            .header("origin")
            .is_some_and(|o| origin_matches(o, req.header("host")))
    {
        return Response::text(403, "cross-origin requests are refused");
    }
    match (req.method.as_str(), req.path.as_str()) {
        ("POST", "/login") => return login(ctx, &req).await,
        ("POST", "/logout") => {
            if let Some((t, _)) = ctx.shared.webui.sessions.of(&req) {
                ctx.shared.webui.sessions.end(&t);
            }
            // What a page that held this port before left at this origin
            // goes with Sign out: its storage and its workers (and the
            // sessions of this browser's other tabs).
            return Response::json(200, &json!({})).with_header("Clear-Site-Data", "\"storage\"");
        }
        _ => {}
    }
    if !webui::is_api(&req.path) {
        return Response::text(404, "not found");
    }
    let cfg = ctx.shared.config();
    let signed_in = ctx.shared.webui.sessions.of(&req).is_some_and(|(_, s)| {
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
    match api(ctx, &req, &body, &cfg).await {
        Ok(v) => Response::json(200, &v),
        Err((status, e)) => Response::json(status, &json!({ "error": e })),
    }
}

/// Whether a request may name `host`: on loopback only a loopback name, or
/// the address the UI listens on as a number (`ui on --listen 127.0.0.2:…`),
/// since a page of another name that resolves to this address (DNS
/// rebinding) must be refused. Beyond loopback any name: the owner may use
/// one of their own.
fn host_allowed(host: Option<&str>, local: SocketAddr) -> bool {
    !local.ip().is_loopback() || host_is_loopback(host) || host_is_address(host, local.ip())
}

/// Checks the token a login posted. The answer is the session for the page
/// to keep, or the reason it was refused; the token never appears in a URL
/// or a log.
async fn login(ctx: &Ctx, req: &Request) -> Response {
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
        tokio::time::sleep(webui::WRONG_SECRET_DELAY).await;
        return Response::json(401, &json!({"error": WRONG_TOKEN}));
    };
    let token = ctx.shared.webui.sessions.start(Some(hash));
    tracing::info!("web UI: signed in (token `{label}`)");
    Response::json(200, &json!({"session": token}))
}

type ApiResult = Result<Value, (u16, String)>;

/// The API of a signed-in page. Each change is one command of the CLI, of
/// a fixed shape, run as the owner (crate::owner::run_for_web).
async fn api(ctx: &Ctx, req: &Request, b: &Value, cfg: &NodeConfig) -> ApiResult {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/api/overview") => Ok(overview(ctx, cfg)),
        ("POST", "/api/panic") => command(ctx, &["panic"], None).await,
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
async fn command(ctx: &Ctx, args: &[&str], input: Option<&str>) -> ApiResult {
    let mut all: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    all.insert(0, "--json".into());
    let ran = crate::owner::run_for_web(&ctx.shared, &ctx.program, &ctx.who(), &all, input)
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
