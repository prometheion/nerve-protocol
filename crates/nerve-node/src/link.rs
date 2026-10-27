//! One center's link: dialling with backoff, the handshake, and serving the
//! center's requests (spec §4, §5, §7).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::AbortHandle;

use nerve_policy::audit::Entry;
use nerve_policy::command::Shell;
use nerve_policy::config::{Mode, SettingsGrant};
use nerve_policy::decide::Reads;
use nerve_policy::protected::Protected;
use nerve_policy::rules::RuleSet;
use nerve_policy::{Call, CenterEntry, Decision, Env, NodeConfig, PathAccess, SetError, Target};
use nerve_proto::descriptor::{Detail, Effect, Exposure};
use nerve_proto::frame::{self, Frame, FrameError};
use nerve_proto::link::CenterUrl;
use nerve_proto::msg::{
    self, Ack, Bye, ByeReason, Cancel, Challenge, Describe, Get, Hello, Invoke, Resume, Resumed,
    SessionEnd, StreamClose, StreamOpen, Topic, Topics, Welcome, method,
};
use nerve_proto::resume;
use nerve_proto::rpc::{Id, Message, params};
use nerve_proto::schema::PathMark;
use nerve_proto::{ErrorCode, PROTOCOL_VERSION, RpcError, limits};
use nerve_transport::backoff::Backoff;
use nerve_transport::keys::NodeKey;
use nerve_transport::log::{Level, call_line, span};
use nerve_transport::net::Proxy;
use nerve_transport::ws::{self, ConnectError, WsMessage};

use crate::daemon::{CenterState, LinkHandle, Shared, lock};
use crate::descriptor;
use crate::exec::{self, RunCall, RunOptions, Sig, SignalArgs};
use crate::fs::{FsCall, WirePath, conflict};

/// Each handshake step must arrive within this (spec §4.2).
const HANDSHAKE: Duration = Duration::from_secs(15);
/// Ping after this much quiet; give up after `DEAD` (spec §4.4).
const PING: Duration = Duration::from_secs(20);
const DEAD: Duration = Duration::from_secs(45);
/// The stream frames a connection's writer holds; each stream waits for
/// room here, never in the link's own queue.
const STREAM_QUEUE: usize = 4;

/// Dials in a row refused for the pin before the node says to pair again:
/// more than the few seconds a center may take to serve its new key at the
/// end of a rotation's grace.
const PIN_REFUSALS_BEFORE_ADVICE: u32 = 3;

/// How long a live link under the center's old pin outlives that pin's time
/// (spec §4.10): longer than the center takes to serve its new key at the
/// end of the grace (its sweep runs every 5 s), so a link to the real center
/// does not end before the new key is served. New dials refuse the old pin
/// at once; a center that ends its grace early says so (`grace_ms: 0`), and
/// such a link ends at once.
pub(crate) const OLD_PIN_LINK_SLACK_MS: u64 = 15_000;

/// How a link (or a dial) ended.
enum Outcome {
    /// Dial again after the backoff.
    Retry,
    /// The connection dropped without a bye: dial again, and resume the link
    /// if the center can.
    Lost,
    /// Do not dial again until the config says so.
    Stop,
}

/// A link that dropped without a bye, kept until `until` for the center to
/// resume (spec §4.9): its calls run on, and what it sends is kept. Dropped,
/// it ends like a link that cannot resume: its calls end and its commands
/// are killed.
struct Parked {
    link: Option<Arc<Link>>,
    until: Instant,
}

impl Parked {
    fn link(&self) -> &Arc<Link> {
        self.link.as_ref().expect("a parked link until it is taken")
    }

    /// The link, to carry on on a new connection.
    fn resume(mut self) -> Arc<Link> {
        self.link.take().expect("a parked link until it is taken")
    }
}

impl Drop for Parked {
    fn drop(&mut self) {
        if let Some(l) = self.link.take() {
            let n = lock(&l.calls).len();
            if n > 0 {
                tracing::warn!(
                    "center {}: the link was not resumed; ending the {} in flight on it",
                    l.name,
                    plural(n, "call")
                );
            }
            l.finish();
        }
    }
}

fn plural(n: usize, what: &str) -> String {
    if n == 1 {
        format!("1 {what}")
    } else {
        format!("{n} {what}s")
    }
}

/// Waits until `t`, or for ever without one.
async fn until(t: Option<Instant>) {
    match t {
        Some(t) => tokio::time::sleep_until(tokio::time::Instant::from_std(t)).await,
        None => std::future::pending().await,
    }
}

/// Awaits `work`, and drops what `slot` holds at `at`, or when `halt`
/// resolves, if `work` takes longer: a keyring that waits to be unlocked, a
/// dial or a handshake that hangs does not keep a parked link past its grace,
/// nor past a lock or pause.
async fn dropping_at<F: std::future::Future, T>(
    work: F,
    slot: &mut Option<T>,
    at: Option<Instant>,
    halt: impl std::future::Future<Output = ()>,
) -> F::Output {
    tokio::pin!(work);
    if slot.is_none() {
        return work.await;
    }
    tokio::select! {
        r = &mut work => r,
        _ = until(at) => {
            *slot = None;
            work.await
        }
        _ = halt => {
            *slot = None;
            work.await
        }
    }
}

/// Why the config ends center `name`'s link, if it does: the node is locked
/// or the center paused (`paused`), or the center is revoked, unknown or
/// removed (`unpaired`).
fn stop_reason(cfg: &NodeConfig, name: &str) -> Option<ByeReason> {
    match cfg.center(name) {
        None => Some(ByeReason::Unpaired),
        Some(_) if cfg.locked => Some(ByeReason::Paused),
        Some(e) if e.paused => Some(ByeReason::Paused),
        Some(e) if e.revoked || e.unknown => Some(ByeReason::Unpaired),
        Some(_) => None,
    }
}

/// Resolves once the config ends center `name`'s link ([`stop_reason`]),
/// or the daemon is going away.
async fn halted(shared: &Shared, name: &str, changed: &mut watch::Receiver<u64>) {
    while stop_reason(&shared.config(), name).is_none() {
        if changed.changed().await.is_err() {
            return;
        }
    }
}

/// Dials `name` until it is removed, paused, revoked or unknown, or the
/// daemon stops.
pub(crate) async fn run_center(shared: Arc<Shared>, name: String) {
    let cs = shared.center(&name);
    let mut backoff = Backoff::default();
    let mut stop = shared.stop.subscribe();
    let mut changed = shared.changed.subscribe();
    // Dials that failed since the link was last up: the first is a warning,
    // the rest are detail, or a center that is down fills the log.
    let mut failed_dials = 0u32;
    // The link that dropped, while the center may resume it. Leaving this
    // function drops it, which ends its calls.
    let mut parked: Option<Parked> = None;
    // While a rotation of the node's key waits for the center's answer, a
    // handshake that fails is tried next with the new key: the center may
    // have taken it, and the grace of the old one may have ended since.
    let mut sign_next = false;
    // Dials in a row whose certificate did not carry a pinned key.
    let mut pin_refusals = 0u32;
    loop {
        if *stop.borrow() {
            return;
        }
        let mut cfg = shared.config();
        let Some(mut entry) = cfg.center(&name).cloned() else {
            return;
        };
        if !entry.dials() || cfg.locked {
            return;
        }
        if crate::rotate::drop_old_pin(&shared, &name) {
            cfg = shared.config();
            let Some(e) = cfg.center(&name).cloned() else {
                return;
            };
            entry = e;
        }
        // The keyring may block (the Secret Service asks to unlock), so off
        // the runtime's threads.
        let grace = parked.as_ref().map(|p| p.until);
        let read = {
            let (s, n) = (shared.clone(), name.clone());
            let read = tokio::task::spawn_blocking(move || load_keys(&s, &n));
            let halt = halted(&shared, &name, &mut changed);
            dropping_at(read, &mut parked, grace, halt).await
        };
        let (key, next) = match read.unwrap_or_else(|e| Err(format!("the key read stopped: {e}"))) {
            Ok(k) => k,
            Err(e) => {
                tracing::error!("center {name}: {e}; dialling stopped");
                cs.set_status(e);
                return;
            }
        };
        let url = match CenterUrl::parse(&entry.url) {
            Ok(u) => u,
            Err(e) => {
                tracing::error!("center {name}: bad center url: {e}; dialling stopped");
                cs.set_status(format!("bad center url: {e}"));
                return;
            }
        };
        let grace = parked.as_ref().map(|p| p.until);
        let halt = halted(&shared, &name, &mut changed);
        let proxy = match dropping_at(
            proxy_for(&shared.paths, &cfg, &url),
            &mut parked,
            grace,
            halt,
        )
        .await
        {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("center {name}: bad proxy: {e}; dialling stopped");
                cs.set_status(format!("bad proxy: {e}"));
                return;
            }
        };
        cs.set_status("connecting");
        tracing::debug!("center {name}: dialling {url}");
        let started = Instant::now();
        let dialled = {
            // The node id stays the one of the pairing when the key is
            // rotated; while a rotation of the center's key is in its grace,
            // either of its pins is taken.
            let pins = entry.pins_at(crate::now_ms());
            let connect = ws::connect_pins_seen(
                &url,
                &pins,
                proxy.as_ref(),
                &entry.node_id,
                limits::MESSAGE_BYTES as usize,
            );
            let grace = parked.as_ref().map(|p| p.until);
            dropping_at(
                connect,
                &mut parked,
                grace,
                halted(&shared, &name, &mut changed),
            )
            .await
        };
        let outcome = match dialled {
            Err(ConnectError::Unknown) => {
                tracing::warn!("center {name} does not know this node (401); dialling stopped");
                cs.set_status("the center does not know this node (401); dialling stopped");
                shared.mark_center(&name, |e| e.unknown = true);
                return;
            }
            Err(ConnectError::Other(e)) => {
                // A refused pin right after a rotation of the center's key
                // may be a center that does not serve its new key yet: the
                // advice to pair again comes only when it goes on.
                let e = if e.contains(nerve_transport::net::PIN_REFUSED) {
                    pin_refusals += 1;
                    if pin_refusals >= PIN_REFUSALS_BEFORE_ADVICE {
                        format!("{e} {}", nerve_transport::net::PIN_ADVICE)
                    } else {
                        format!(
                            "{e} Right after a rotation of the center's key it may not serve its new key yet; the node tries again."
                        )
                    }
                } else {
                    pin_refusals = 0;
                    e
                };
                cs.set_status(format!("cannot connect: {e}"));
                if failed_dials == 0 || pin_refusals == PIN_REFUSALS_BEFORE_ADVICE {
                    tracing::warn!("center {name}: cannot connect: {e}");
                } else {
                    tracing::debug!("center {name}: cannot connect: {e}");
                }
                failed_dials += 1;
                Outcome::Retry
            }
            Ok((ws, seen_pin)) => {
                let (signer, pending) = match &next {
                    None => (&key, Pending::None),
                    Some(n) if sign_next => (n, Pending::Adopt(n.public_hex())),
                    Some(_) => (&key, Pending::Resend),
                };
                let keys = Signing {
                    key: signer,
                    pending,
                    seen_pin,
                };
                let (outcome, was_up, kept) =
                    session(&shared, &cs, &entry, keys, ws, parked.take(), &mut changed).await;
                parked = kept;
                if was_up {
                    failed_dials = 0;
                    pin_refusals = 0;
                    sign_next = false;
                } else if next.is_some() {
                    sign_next = !sign_next;
                }
                outcome
            }
        };
        if let Outcome::Stop = outcome {
            return;
        }
        backoff.link_ended(started.elapsed());
        let wait = backoff.next_wait();
        // After a link that was up this is news, in a run of failed dials it
        // is the same line every time.
        if failed_dials == 0 {
            tracing::info!("center {name}: dialling again in {}", span(wait));
        } else {
            tracing::debug!("center {name}: dialling again in {}", span(wait));
        }
        let until = tokio::time::Instant::now() + wait;
        // Wait out the backoff, but leave at once when the center goes away.
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(until) => break,
                _ = self::until(parked.as_ref().map(|p| p.until)) => parked = None,
                _ = stop.changed() => return,
                r = changed.changed() => {
                    if r.is_err() {
                        return;
                    }
                    let cfg = shared.config();
                    if cfg.locked || !cfg.center(&name).is_some_and(CenterEntry::dials) {
                        return;
                    }
                }
            }
        }
    }
}

/// The node key for center `name`, where `machine.secret_storage` keeps it.
fn load_key(shared: &Shared, name: &str) -> Result<NodeKey, String> {
    let storage = shared.config().machine.secret_storage;
    crate::secrets::center_key(&shared.paths, storage, name)
}

/// [`load_key`], and the new key of a rotation that waits for the center's
/// answer (crate::rotate).
fn load_keys(shared: &Shared, name: &str) -> Result<(NodeKey, Option<NodeKey>), String> {
    let storage = shared.config().machine.secret_storage;
    let key = crate::secrets::center_key(&shared.paths, storage, name)?;
    let next = crate::secrets::center_next_key(&shared.paths, storage, name)?;
    Ok((key, next))
}

/// The key a connection's hello is signed with, and what that means for a
/// rotation of the node's key that waits for the center's answer.
struct Signing<'a> {
    key: &'a NodeKey,
    pending: Pending,
    /// The pin of the certificate the center showed for this connection.
    seen_pin: Option<String>,
}

/// A rotation of the node's key that waits for the center's answer, as a
/// link meets it.
enum Pending {
    None,
    /// The hello is signed with the old key: the rotation is sent again.
    Resend,
    /// The hello is signed with the new key (this public key): if the link
    /// comes up, the center holds it, and the rotation is settled.
    Adopt(String),
}

/// The proxy to dial `url` through, its header values read from the system
/// keyring. An error stops the dial: a configured proxy is never bypassed.
/// The link, the pairing and the relay's own dials (crate::relay) all take
/// it from here.
pub(crate) async fn proxy_for(
    paths: &crate::paths::NodePaths,
    cfg: &NodeConfig,
    url: &CenterUrl,
) -> Result<Option<Proxy>, String> {
    let Some(p) = &cfg.connection.proxy else {
        return Proxy::from_env(&url.host);
    };
    // The keyring may block (the Secret Service asks to unlock), so off the
    // runtime's threads.
    let (paths, names) = (paths.clone(), cfg.connection.headers.clone());
    let (login, storage) = (cfg.connection.login.clone(), cfg.machine.secret_storage);
    let headers = tokio::task::spawn_blocking(move || {
        let mut headers = crate::secrets::proxy_headers(&paths, &names)?;
        // The login of an https:// proxy (a relay token) is kept with the
        // node's own keys, not with the header values.
        if let Some(user) = login {
            use base64::Engine;
            let password = crate::secrets::proxy_login(&paths, storage)?;
            let basic =
                base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
            headers.push(("Proxy-Authorization".into(), format!("Basic {basic}")));
        }
        Ok::<_, String>(headers)
    })
    .await
    .map_err(|e| format!("the keyring read stopped: {e}"))??;
    Proxy::parse(p, headers)?
        .pinned(cfg.connection.pin.clone())
        .map(Some)
}

/// What one read from the link gave.
enum Got {
    Msg(Message),
    /// A message that did not parse; the error reply to send.
    Bad(Message),
    Binary(Vec<u8>),
    /// Anything else that shows the center is alive (ping, pong).
    Alive,
    TooLarge,
    /// A frame the WebSocket could not take (over its limit, malformed).
    Broken(String),
    Closed,
}

async fn read<S>(stream: &mut S) -> Got
where
    S: futures_util::Stream<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
{
    match stream.next().await {
        // What the center sent is broken, not the connection: the link ends.
        Some(Err(e)) if ws::broken_frame(&e) => Got::Broken(e.to_string()),
        None | Some(Err(_)) => Got::Closed,
        Some(Ok(WsMessage::Text(t))) => {
            if t.len() as u64 > limits::MESSAGE_BYTES {
                return Got::TooLarge;
            }
            match Message::decode(t.as_str()) {
                Ok(m) => Got::Msg(m),
                Err(reply) => Got::Bad(*reply),
            }
        }
        Some(Ok(WsMessage::Binary(b))) => Got::Binary(b.to_vec()),
        Some(Ok(WsMessage::Close(_))) => Got::Closed,
        Some(Ok(_)) => Got::Alive,
    }
}

fn text(m: &Message) -> WsMessage {
    WsMessage::text(m.encode())
}

fn bye(reason: ByeReason) -> WsMessage {
    text(&Message::notification(
        method::BYE,
        serde_json::to_value(Bye { reason }).unwrap_or_default(),
    ))
}

/// Reads the next handshake notification named `want`.
async fn handshake_step<S, T>(stream: &mut S, want: &str) -> Result<T, (Option<ByeReason>, String)>
where
    S: futures_util::Stream<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
    T: serde::de::DeserializeOwned,
{
    let got = tokio::time::timeout(HANDSHAKE, async {
        loop {
            match read(stream).await {
                Got::Alive => continue,
                other => return other,
            }
        }
    })
    .await
    .map_err(|_| (None, format!("no {want} within 15 s")))?;
    match got {
        Got::Msg(Message::Notification {
            method: m,
            params: p,
        }) if m == want => params::<T>(&p).map_err(|e| (Some(ByeReason::ProtocolError), e.message)),
        Got::Msg(Message::Notification {
            method: m,
            params: p,
        }) if m == method::BYE => {
            let reason = params::<Bye>(&p)
                .map(|b| b.reason.as_str().to_string())
                .unwrap_or_default();
            Err((None, format!("the center said bye ({reason})")))
        }
        Got::Closed => Err((None, "the link closed during the handshake".into())),
        _ => Err((
            Some(ByeReason::ProtocolError),
            format!("expected {want} during the handshake"),
        )),
    }
}

type WsStream = tokio_tungstenite::WebSocketStream<nerve_transport::net::BoxIo>;

/// A fresh link id: 16 random bytes as hex (spec §4.9).
fn new_link_id() -> String {
    msg::hex(&nerve_transport::keys::random_bytes(16))
}

/// One connected link: handshake, then serve until it ends. `parked` is the
/// link that dropped, which this connection offers the center to resume.
/// Also says whether the handshake came through, so the link was up, and
/// gives back the link to keep for a resume.
async fn session(
    shared: &Arc<Shared>,
    cs: &Arc<CenterState>,
    entry: &CenterEntry,
    keys: Signing<'_>,
    ws: WsStream,
    parked: Option<Parked>,
    changed: &mut watch::Receiver<u64>,
) -> (Outcome, bool, Option<Parked>) {
    let Signing {
        key,
        pending,
        seen_pin,
    } = keys;
    let (mut sink, mut stream) = ws.split();
    let cfg = shared.config();
    let mut parked = parked;
    let mut offer = Resume {
        link: new_link_id(),
        got: 0,
    };

    // Handshake (spec §4.2): challenge → hello → welcome.
    let hello = async {
        // The grace, a lock or a pause may come while the challenge is
        // awaited; the parked link's calls end on time then.
        let grace = parked.as_ref().map(|p| p.until);
        let halt = halted(shared, &entry.name, &mut *changed);
        let step = handshake_step(&mut stream, method::CHALLENGE);
        let ch: Challenge = dropping_at(step, &mut parked, grace, halt).await?;
        // A parked link is offered while its grace lasts and it still keeps
        // every frame the center may not have read; otherwise it ends here.
        // Once offered, it waits for the center's answer.
        parked = parked
            .take()
            .filter(|p| Instant::now() < p.until && p.link().handle.resumable());
        if let Some(p) = &parked {
            offer = Resume {
                link: p.link().id.clone(),
                got: p.link().handle.got(),
            };
        }
        let nonce = msg::unhex(&ch.nonce).filter(|n| n.len() == 32).ok_or((
            Some(ByeReason::ProtocolError),
            "bad challenge nonce".to_string(),
        ))?;
        if ch.center_id != entry.center_id {
            return Err((
                Some(ByeReason::ProtocolError),
                "the center's id is not the paired one".to_string(),
            ));
        }
        let rev = descriptor::for_center(
            &cfg,
            entry,
            &shared.reach(&cfg, entry),
            &shared.offered_caps(&cfg, &entry.policy),
        )
        .rev;
        let hello = Hello {
            node_id: entry.node_id.clone(),
            auth: msg::Auth {
                sig: key.sign_connect(&ch.center_id, &nonce),
            },
            versions: vec![PROTOCOL_VERSION.to_string()],
            software: msg::Software {
                name: descriptor::SOFTWARE.into(),
                version: descriptor::VERSION.into(),
            },
            limits: msg::Limits::default(),
            rev,
            features: nerve_proto::FEATURES
                .iter()
                .map(|f| f.to_string())
                .collect(),
            resume: Some(offer.clone()),
        };
        let m = Message::notification(
            method::HELLO,
            serde_json::to_value(hello).unwrap_or_default(),
        );
        sink.send(text(&m))
            .await
            .map_err(|e| (None, format!("send: {e}")))?;
        // An offered link waits for the answer, but not past a lock or pause.
        let halt = halted(shared, &entry.name, &mut *changed);
        let step = handshake_step(&mut stream, method::WELCOME);
        let w: Welcome = dropping_at(step, &mut parked, None, halt).await?;
        if w.version != PROTOCOL_VERSION {
            return Err((
                Some(ByeReason::UnsupportedVersion),
                format!("the center chose version {:?}", w.version),
            ));
        }
        // A center older than features names none.
        let rotate = w
            .features
            .as_ref()
            .is_some_and(|f| f.iter().any(|f| f == nerve_proto::FEATURE_ROTATE));
        Ok((w.resume, w.limits.message_bytes, rotate))
    }
    .await;
    let (resumed, takes, rotate) = match hello {
        Ok(r) => r,
        Err((reason, why)) => {
            tracing::warn!("center {}: the handshake failed: {why}", entry.name);
            cs.set_status(format!("handshake failed: {why}"));
            if let Some(r) = reason {
                let _ = sink.send(bye(r)).await;
            }
            let _ = sink.close().await;
            // The center did not take the link up: the next dial offers it
            // again while its grace lasts.
            return (Outcome::Retry, false, parked);
        }
    };
    // A lock or pause that came during the handshake ends the link before it
    // serves, a parked one with its calls.
    if let Some(reason) = stop_reason(&shared.config(), &entry.name) {
        drop(parked);
        tracing::info!(
            "center {}: closing the link with bye {}",
            entry.name,
            reason.as_str()
        );
        if reason == ByeReason::Paused {
            cs.set_status("paused");
        }
        let _ = sink.send(bye(reason)).await;
        let _ = sink.close().await;
        return (Outcome::Stop, true, None);
    }

    // One writer owns the sink; everyone else queues (spec §5.5).
    let (tx, mut rx) = mpsc::channel::<WsMessage>(limits::SEND_QUEUE);
    // Stream frames wait in their own queue, sent while `rx` is empty.
    let (ftx, mut frx) = mpsc::channel::<crate::daemon::StreamOut>(STREAM_QUEUE);
    // The center carries on the parked link, or starts a new one; without
    // `welcome.resume` it cannot resume links at all (spec §4.9).
    let carried = match (resumed, parked) {
        (Some(Resumed { resumed: true, got }), Some(p)) => {
            match p.link().handle.attach(tx.clone(), ftx.clone(), got) {
                Ok(again) => Ok((p.resume(), Some(again))),
                Err(e) => Err(format!("the center resumed the link wrongly: {e}")),
            }
        }
        (Some(Resumed { resumed: true, .. }), None) => {
            Err("the center resumed a link the node did not offer".to_string())
        }
        (r, p) => {
            if p.is_some() {
                tracing::info!("center {}: the center did not resume the link", entry.name);
            }
            // Ends the parked link's calls before the new link is up.
            drop(p);
            // The password a frame carries is scrubbed when the frame is
            // numbered; a weak reference, as the node's state holds the link.
            let scrubber = Arc::downgrade(shared);
            let scrub: crate::daemon::Scrub = Box::new(move |t| match scrubber.upgrade() {
                Some(s) => s.scrub(t),
                None => t,
            });
            let handle = Arc::new(LinkHandle::new(tx.clone(), ftx.clone(), r.is_some(), scrub));
            let link = Arc::new(Link {
                shared: shared.clone(),
                cs: cs.clone(),
                name: entry.name.clone(),
                id: offer.link.clone(),
                takes: AtomicU64::new(takes),
                handle,
                calls: Mutex::default(),
                commands: Mutex::default(),
                taps: Mutex::default(),
                streams: Mutex::default(),
                next_sid: AtomicU32::new(1),
                last_status: Mutex::new("online"),
                seen_pin: Mutex::new(None),
            });
            Ok((link, None))
        }
    };
    let (link, again) = match carried {
        Ok(x) => x,
        Err(why) => {
            tracing::warn!("center {}: {why}", entry.name);
            cs.set_status(format!("handshake failed: {why}"));
            let _ = sink.send(bye(ByeReason::ProtocolError)).await;
            let _ = sink.close().await;
            return (Outcome::Retry, false, None);
        }
    };
    link.takes.store(takes, Ordering::Relaxed);
    *lock(&link.seen_pin) = seen_pin;
    match &again {
        None => tracing::info!("linked to center {}", entry.name),
        Some(a) => tracing::info!(
            "link to center {} resumed with {} in flight; {} sent again",
            entry.name,
            plural(lock(&link.calls).len(), "call"),
            plural(a.len(), "frame")
        ),
    }
    let again = again.unwrap_or_default();
    cs.set_status("connected");

    let (done_tx, mut done_rx) = oneshot::channel::<()>();
    // Every frame leaves through here, so the sudo password never does.
    let scrubber = shared.clone();
    let writer = tokio::spawn(async move {
        // What the center did not read of the link goes first, in order.
        for t in again {
            if sink
                .send(scrub(&scrubber, WsMessage::text(t)))
                .await
                .is_err()
            {
                return;
            }
        }
        let mut streams = true;
        loop {
            tokio::select! {
                // The link's own frames go before stream frames.
                biased;
                m = rx.recv() => match m {
                    Some(m) => if sink.send(scrub(&scrubber, m)).await.is_err() { return; },
                    None => break,
                },
                f = frx.recv(), if streams => match f {
                    Some(crate::daemon::StreamOut::Frame(m)) => {
                        if sink.send(m).await.is_err() {
                            return;
                        }
                    }
                    Some(crate::daemon::StreamOut::Flushed(done)) => {
                        let _ = done.send(());
                    }
                    None => streams = false,
                },
                _ = &mut done_rx => {
                    // Flush what is queued (the bye), then close.
                    while let Ok(m) = rx.try_recv() {
                        if sink.send(scrub(&scrubber, m)).await.is_err() {
                            return;
                        }
                    }
                    break;
                }
            }
        }
        let _ = sink.close().await;
    });

    drop((tx, ftx));
    link.handle.set_rotate(rotate);
    *lock(&cs.link) = Some(link.handle.clone());
    // A rotation of the node's key that got no answer on an earlier link is
    // sent again on this one, or settled when this hello was signed with the
    // new key and the center took it.
    match pending {
        Pending::Resend if rotate => {
            tokio::spawn(crate::rotate::resume(shared.clone(), entry.name.clone()));
        }
        Pending::Adopt(public_key) => {
            tokio::spawn(crate::rotate::adopt(
                shared.clone(),
                entry.name.clone(),
                public_key,
            ));
        }
        _ => {}
    }

    let outcome = link.serve(&mut stream).await;

    // From here what the link sends is kept for a resume (or lost).
    link.handle.detach();
    // Streams are not counted frames: they end with their connection, a
    // resumed link carries none (spec §4.9).
    link.end_streams();
    let _ = done_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
    if matches!(outcome, Outcome::Lost) && link.handle.resumable() {
        let n = lock(&link.calls).len();
        tracing::info!(
            "center {}: the link dropped; keeping it for {} for the center to resume, with {} in flight",
            entry.name,
            span(shared.grace),
            plural(n, "call")
        );
        cs.set_status("link lost; resuming");
        let parked = Parked {
            link: Some(link),
            until: Instant::now() + shared.grace,
        };
        return (Outcome::Retry, true, Some(parked));
    }
    // The link is gone (spec §4.5): calls end, commands die with their
    // process groups.
    link.finish();
    match outcome {
        Outcome::Stop => (Outcome::Stop, true, None),
        _ => {
            cs.set_status("link lost; dialling again");
            (Outcome::Retry, true, None)
        }
    }
}

/// The params of `exec`'s `output` stream: the call whose command it is,
/// by its `invoke` id, as `exec.signal` names it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputParams {
    call: u64,
}

/// A call in flight: its task, and the harness session it came from.
struct InFlight {
    abort: AbortHandle,
    session: Option<String>,
}

/// A link's state shared with its calls. A link the center resumes keeps it
/// over several connections.
struct Link {
    shared: Arc<Shared>,
    cs: Arc<CenterState>,
    name: String,
    /// The id the center knows the link by (spec §4.9).
    id: String,
    /// The largest message the center takes (its `welcome.limits`).
    takes: AtomicU64,
    handle: Arc<LinkHandle>,
    /// Calls in flight; whoever removes an entry sends its reply.
    calls: Mutex<HashMap<Id, InFlight>>,
    /// Running `exec.run` calls → what ends them.
    commands: Mutex<HashMap<Id, exec::Ender>>,
    /// Running `exec.run` calls → their output, for `exec`'s `output`
    /// stream; `None` for a sudo command, whose output is not streamed.
    taps: Mutex<HashMap<Id, Option<Arc<crate::tap::Tap>>>>,
    /// Open streams by `sid` → the task that sends them.
    streams: Mutex<HashMap<u32, AbortHandle>>,
    next_sid: AtomicU32,
    /// The `node` status the center last heard (online, busy or paused).
    last_status: Mutex<&'static str>,
    /// The pin of the certificate the center showed for the connection now.
    /// A connection under a pin that stops counting (the old pin of a
    /// rotation of the center's key, its time over) ends, and the node dials
    /// again with the pins that are left (spec §4.10).
    seen_pin: Mutex<Option<String>>,
}

impl Link {
    async fn send(&self, m: Message) {
        self.handle.send(m.encode()).await;
    }

    /// Ends the link for good: its calls end, and a running command dies
    /// with its process group.
    fn finish(&self) {
        {
            let mut held = lock(&self.cs.link);
            if held.as_ref().is_some_and(|h| Arc::ptr_eq(h, &self.handle)) {
                *held = None;
            }
        }
        self.handle.detach();
        // A key rotation stops waiting for its answer.
        self.handle.ended();
        let calls: Vec<InFlight> = lock(&self.calls).drain().map(|(_, c)| c).collect();
        for c in calls {
            c.abort.abort();
        }
    }

    /// Answers call `id`. An answer larger than the center takes would break
    /// the connection, and a resume would send it again: the call fails with
    /// `too_large` instead.
    async fn reply(&self, id: Id, r: Result<Value, RpcError>) {
        let text = match r {
            Ok(v) => Message::result(id.clone(), v),
            Err(e) => Message::error(Some(id.clone()), e),
        }
        .encode();
        let takes = self.takes.load(Ordering::Relaxed);
        if text.len() as u64 > takes {
            let e = RpcError::new(
                ErrorCode::TooLarge,
                format!(
                    "the answer is {} bytes, more than the center takes ({takes})",
                    text.len()
                ),
            );
            tracing::warn!("center {}: {}", self.name, e.message);
            return self.handle.send(Message::error(Some(id), e).encode()).await;
        }
        self.handle.send(text).await;
    }

    /// The center's entry, or `None` when it was removed meanwhile.
    fn entry(&self) -> Option<(NodeConfig, CenterEntry)> {
        let cfg = self.shared.config();
        let e = cfg.center(&self.name).cloned()?;
        Some((cfg, e))
    }

    async fn serve(
        self: &Arc<Self>,
        stream: &mut futures_util::stream::SplitStream<WsStream>,
    ) -> Outcome {
        let mut stop = self.shared.stop.subscribe();
        let mut changed = self.shared.changed.subscribe();
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        let mut heard = Instant::now();
        let mut pinged = Instant::now();
        let (cfg, entry) = match self.entry() {
            Some(x) => x,
            None => return self.end(ByeReason::Unpaired, Outcome::Stop).await,
        };
        // A lock or pause that came since the handshake is not seen by
        // `changed`, which starts now; a resumed link would carry the
        // commands it had past it.
        if let Some(reason) = stop_reason(&cfg, &self.name) {
            if reason == ByeReason::Paused {
                self.cs.set_status("paused");
            }
            return self.end(reason, Outcome::Stop).await;
        }
        let mut rev = self.descriptor(&cfg, &entry).rev;
        let mut version = cfg.version;
        loop {
            tokio::select! {
                got = read(stream) => {
                    heard = Instant::now();
                    match got {
                        Got::Msg(m) => {
                            if resume::counted(&m) {
                                self.handle.read_one();
                            }
                            if let Message::Notification { method: am, params: p } = &m
                                && am == method::ACK
                            {
                                // An ack on a link that cannot resume is
                                // ignored like any unknown notification.
                                if !self.handle.resumes() {
                                    continue;
                                }
                                let r = params::<Ack>(p)
                                    .map_err(|e| e.message)
                                    .and_then(|a| self.handle.acked(a.got));
                                if let Err(e) = r {
                                    tracing::warn!("center {}: a wrong ack: {e}", self.name);
                                    return self.end(ByeReason::ProtocolError, Outcome::Retry).await;
                                }
                                continue;
                            }
                            if let Some(o) = self.message(m).await {
                                return o;
                            }
                        }
                        Got::Bad(reply) => {
                            self.handle.read_one();
                            self.send(reply).await;
                        }
                        Got::Binary(b) => {
                            // No blobs or streams flow center → node;
                            // only reserved media frames break the link.
                            if let Err(FrameError::MediaReserved) = Frame::decode(&b) {
                                tracing::warn!("center {}: it sent a media frame, which this node does not take", self.name);
                                return self.end(ByeReason::ProtocolError, Outcome::Retry).await;
                            }
                        }
                        Got::Alive => {}
                        Got::TooLarge => {
                            tracing::warn!("center {}: it sent a message that is too large", self.name);
                            return self.end(ByeReason::ProtocolError, Outcome::Retry).await;
                        }
                        Got::Broken(e) => {
                            tracing::warn!("center {}: it sent a frame the node cannot read: {e}", self.name);
                            return self.end(ByeReason::ProtocolError, Outcome::Retry).await;
                        }
                        Got::Closed => {
                            tracing::warn!("center {}: the link closed without a bye", self.name);
                            return Outcome::Lost;
                        }
                    }
                }
                _ = tick.tick() => {
                    if heard.elapsed() >= DEAD {
                        tracing::warn!(
                            "center {} went quiet: no frame for {}; dropping the link",
                            self.name,
                            span(DEAD)
                        );
                        return Outcome::Lost;
                    }
                    if heard.elapsed() >= PING && pinged.elapsed() >= PING {
                        pinged = Instant::now();
                        self.handle.raw(WsMessage::Ping(Default::default()));
                    }
                    // Every 5 s at most (resume::ACK_EVERY).
                    self.handle.send_ack();
                    self.check_rev(&mut rev);
                    self.check_status();
                    crate::rotate::drop_old_pin(&self.shared, &self.name);
                    if self.under_a_pin_that_stopped() {
                        tracing::warn!(
                            "center {}: this connection was opened under the center's old pin, which no longer counts; dialling again with the new one",
                            self.name
                        );
                        return Outcome::Lost;
                    }
                }
                r = changed.changed() => {
                    if r.is_err() {
                        return self.end(ByeReason::Shutdown, Outcome::Stop).await;
                    }
                    let Some((cfg, entry)) = self.entry() else {
                        return self.end(ByeReason::Unpaired, Outcome::Stop).await;
                    };
                    if cfg.locked || entry.paused {
                        self.cs.set_status("paused");
                        return self.end(ByeReason::Paused, Outcome::Stop).await;
                    }
                    if entry.revoked || entry.unknown {
                        return self.end(ByeReason::Unpaired, Outcome::Stop).await;
                    }
                    // Told that the old pin no longer counts (the center
                    // serves its new key): a connection under it ends now.
                    if self.under_a_pin_that_stopped() {
                        tracing::warn!(
                            "center {}: this connection was opened under the center's old pin, which no longer counts; dialling again with the new one",
                            self.name
                        );
                        return Outcome::Lost;
                    }
                    self.check_rev(&mut rev);
                    if cfg.version != version {
                        version = cfg.version;
                        if entry.settings == SettingsGrant::Write {
                            self.handle.event("settings", "changed", json!({"version": version}));
                        }
                    }
                }
                _ = stop.changed() => {
                    self.handle.event("node", "going_away", json!({"reason": "shutdown"}));
                    self.cs.set_status("stopped");
                    return self.end(ByeReason::Shutdown, Outcome::Stop).await;
                }
            }
        }
    }

    /// Whether the connection now was opened under a pin the center's entry
    /// no longer takes: the old pin of a rotation whose time is over, or
    /// that the center ended early.
    fn under_a_pin_that_stopped(&self) -> bool {
        let Some(seen) = lock(&self.seen_pin).clone() else {
            return false;
        };
        let Some((_, entry)) = self.entry() else {
            return false;
        };
        // A pairing without a pin checks the system's roots instead.
        let Some(pin) = entry.pin.as_deref() else {
            return false;
        };
        let now = crate::now_ms();
        let taken = std::iter::once(pin).chain(
            entry
                .old_pin
                .as_ref()
                .filter(|o| now < o.until_ms.saturating_add(OLD_PIN_LINK_SLACK_MS))
                .map(|o| o.pin.as_str()),
        );
        !taken.into_iter().any(|p| crate::rotate::same_pin(p, &seen))
    }

    /// Tells the center when its view of the node changed.
    fn check_rev(&self, rev: &mut u64) {
        if let Some((cfg, entry)) = self.entry() {
            let now = self.descriptor(&cfg, &entry).rev;
            if now != *rev {
                *rev = now;
                self.handle
                    .event("node", "descriptor_changed", json!({"rev": now}));
            }
        }
    }

    /// Sends a `node` state change when the status moved (spec §7.1). Other
    /// links' commands count too, so the 5 s tick catches those.
    fn check_status(&self) {
        let Some((cfg, _)) = self.entry() else {
            return;
        };
        let now = self.status(&cfg);
        let mut last = lock(&self.last_status);
        if *last != now {
            *last = now;
            self.handle.state("node", json!({"status": now}));
        }
    }

    async fn end(&self, reason: ByeReason, o: Outcome) -> Outcome {
        let level = if reason == ByeReason::ProtocolError {
            Level::Warn
        } else {
            Level::Info
        };
        let why = format!(
            "center {}: closing the link with bye {}",
            self.name,
            reason.as_str()
        );
        nerve_transport::log::emit(level, None, &why);
        self.handle.raw_send(bye(reason)).await;
        o
    }

    /// Handles one message; `Some` ends the link.
    async fn message(self: &Arc<Self>, m: Message) -> Option<Outcome> {
        match m {
            Message::Request {
                id,
                method: m,
                params: p,
            } => {
                self.request(id, &m, p).await;
                None
            }
            Message::Notification {
                method: m,
                params: p,
            } => self.notification(&m, p),
            // The node sends no requests of its own.
            Message::Result { .. } | Message::Error { .. } => None,
        }
    }

    fn notification(&self, m: &str, p: Map<String, Value>) -> Option<Outcome> {
        match m {
            method::CANCEL => {
                let Ok(c) = params::<Cancel>(&p) else {
                    return None;
                };
                let Ok(id) = serde_json::from_value::<Id>(c.id) else {
                    return None;
                };
                self.cancel(id, "cancelled");
                None
            }
            // The calls of an ended session end like cancelled ones: a
            // command's process group is killed as on a timeout.
            // A request the center gave up while the link was down, in its
            // place in the replay (spec §4.9): nothing to do.
            method::WITHDRAWN => None,
            method::SESSION_END => {
                let Ok(end) = params::<SessionEnd>(&p) else {
                    return None;
                };
                let ids: Vec<Id> = lock(&self.calls)
                    .iter()
                    .filter(|(_, c)| c.session.as_deref() == Some(end.session.as_str()))
                    .map(|(id, _)| id.clone())
                    .collect();
                for id in ids {
                    self.cancel(id, "cancelled: the harness session ended");
                }
                None
            }
            method::BYE => {
                let reason = params::<Bye>(&p).ok().map(|b| b.reason);
                match reason {
                    Some(r) if r.stops_node() => {
                        tracing::warn!("center {} ended the pairing ({})", self.name, r.as_str());
                        self.cs.set_status(format!(
                            "the center said {}; dialling stopped",
                            r.as_str()
                        ));
                        self.shared.mark_center(&self.name, |e| e.revoked = true);
                        Some(Outcome::Stop)
                    }
                    Some(r) => {
                        let level = match r {
                            ByeReason::Duplicate | ByeReason::ProtocolError => Level::Warn,
                            _ => Level::Info,
                        };
                        let why = format!(
                            "center {} said bye ({}); dialling again",
                            self.name,
                            r.as_str()
                        );
                        nerve_transport::log::emit(level, None, &why);
                        Some(Outcome::Retry)
                    }
                    None => {
                        tracing::warn!("center {} sent a bye the node cannot read", self.name);
                        Some(Outcome::Retry)
                    }
                }
            }
            // Answers to a rotation of the node's key (crate::rotate).
            method::KEY_ROTATED | method::KEY_RETIRED => {
                if self.handle.answer(m, p.clone()) {
                    return None;
                }
                // An answer that came after the owner's command gave up
                // still settles the rotation.
                if m == method::KEY_ROTATED && self.handle.rotate() {
                    tokio::spawn(crate::rotate::late_answer(
                        self.shared.clone(),
                        self.name.clone(),
                        p,
                    ));
                } else {
                    tracing::debug!("center {}: {m} that nothing waits for; ignored", self.name);
                }
                None
            }
            method::CENTER_ROTATE => {
                crate::rotate::center_rotated(&self.shared, &self.name, &self.handle, &p);
                None
            }
            // Unknown notifications are ignored (spec §3).
            _ => None,
        }
    }

    /// Stops call `id` and answers it `cancelled`. Aborting its task drops
    /// a running command, which kills its process group (exec::Group).
    fn cancel(&self, id: Id, why: &str) {
        let c = lock(&self.calls).remove(&id);
        if let Some(c) = c {
            c.abort.abort();
            let e = Message::error(Some(id), RpcError::new(ErrorCode::Cancelled, why));
            self.handle.try_send(e.encode());
        }
    }

    async fn request(self: &Arc<Self>, id: Id, m: &str, p: Map<String, Value>) {
        let r = match m {
            method::DESCRIBE => self.describe(&p),
            method::INVOKE => {
                self.start_invoke(id, p).await;
                return;
            }
            method::GET => self.get(&p),
            method::SUB | method::UNSUB => self.sub(&p, m == method::SUB),
            method::STREAM_OPEN => {
                self.stream_open(id, p).await;
                return;
            }
            method::STREAM_CLOSE => self.stream_close(&p),
            other => Err(RpcError::new(
                ErrorCode::MethodNotFound,
                format!("unknown method {other}"),
            )),
        };
        self.reply(id, r).await;
    }

    /// `stream.open`: `exec`'s `output` of a running command of this link,
    /// for the session the command's call came from only. The stream sends
    /// the tail of what the command printed so far, then what it prints,
    /// and ends with the command (`stream.close` from the node).
    async fn stream_open(self: &Arc<Self>, id: Id, p: Map<String, Value>) {
        let opened = self.open(&p);
        let (sid, reader) = match opened {
            Ok(o) => o,
            Err(e) => return self.reply(id, Err(e)).await,
        };
        // The answer goes first, so the center knows the sid before its
        // first frame comes.
        let (go, start) = oneshot::channel::<()>();
        let link = self.clone();
        let task = tokio::spawn(async move {
            if start.await.is_ok() {
                link.pump(sid, reader).await;
            }
        });
        lock(&self.streams).insert(sid, task.abort_handle());
        self.reply(id, Ok(json!({ "sid": sid }))).await;
        let _ = go.send(());
    }

    fn open(&self, p: &Map<String, Value>) -> Result<(u32, Arc<crate::tap::Reader>), RpcError> {
        let o: StreamOpen = params(p)?;
        o.check()?;
        let view = self.view()?;
        let cap = view.capability(&o.cap).ok_or_else(|| {
            RpcError::new(
                ErrorCode::UnknownCapability,
                format!("no capability {}", o.cap),
            )
        })?;
        if !cap.streams.contains_key(&o.stream) {
            return Err(RpcError::new(
                ErrorCode::UnknownMember,
                format!("{} has no stream {}", o.cap, o.stream),
            ));
        }
        if (o.cap.as_str(), o.stream.as_str()) != ("exec", "output") {
            return Err(RpcError::new(
                ErrorCode::Unavailable,
                format!("the stream {}.{} is not served", o.cap, o.stream),
            ));
        }
        let call: OutputParams = params(&o.params)?;
        let call = Id::Num(call.call);
        // Another session's call, or no running command, reads the same:
        // the answer does not tell which calls run for other sessions.
        let tap = {
            let calls = lock(&self.calls);
            calls
                .get(&call)
                .filter(|c| c.session == o.ctx.session)
                .and_then(|_| lock(&self.taps).get(&call).cloned())
        }
        .ok_or_else(|| {
            RpcError::invalid_args(format!("no running command {call} of this session"))
        })?
        .ok_or_else(|| {
            RpcError::new(
                ErrorCode::Unavailable,
                format!("the output of command {call} is not streamed: it is a sudo command, whose output comes with its result"),
            )
        })?;
        let streams = lock(&self.streams);
        if streams.len() >= limits::STREAMS as usize {
            return Err(RpcError::new(
                ErrorCode::Busy,
                format!("{} streams are open already", limits::STREAMS),
            ));
        }
        let sid = self.next_sid.fetch_add(1, Ordering::Relaxed);
        drop(streams);
        Ok((sid, tap.reader()))
    }

    /// Sends stream `sid` until its command ended and everything went, then
    /// tells the center it ended. A link that went down ends it.
    async fn pump(&self, sid: u32, reader: Arc<crate::tap::Reader>) {
        let mut seq = 0u32;
        loop {
            let f = match reader.next(frame::MAX_PAYLOAD).await {
                crate::tap::Chunk::Data(d) => frame::stream_frame(sid, seq, d),
                crate::tap::Chunk::Gap(n) => Frame::gap(sid, seq, n),
                crate::tap::Chunk::End => break,
            };
            if !self.handle.frame(&f).await {
                lock(&self.streams).remove(&sid);
                return;
            }
            seq = seq.wrapping_add(1);
        }
        // The close goes on the link's own queue, which the writer serves
        // first: it waits until the stream's last frame went.
        let flushed = self.handle.flushed().await;
        if lock(&self.streams).remove(&sid).is_none() || !flushed {
            return;
        }
        let close = Message::request(
            u64::from(sid),
            method::STREAM_CLOSE,
            json!({"sid": sid, "reason": "ended"}),
        );
        self.handle.send(close.encode()).await;
    }

    /// `stream.close` from the center: the stream stops at once.
    fn stream_close(&self, p: &Map<String, Value>) -> Result<Value, RpcError> {
        let c: StreamClose = params(p)?;
        let task = lock(&self.streams).remove(&c.sid).ok_or_else(|| {
            RpcError::new(ErrorCode::UnknownMember, format!("no stream {}", c.sid))
        })?;
        task.abort();
        Ok(json!({}))
    }

    /// Ends every stream: the connection they went on is gone.
    fn end_streams(&self) {
        for (_, task) in lock(&self.streams).drain() {
            task.abort();
        }
    }

    fn view(&self) -> Result<nerve_proto::descriptor::Descriptor, RpcError> {
        let (cfg, entry) = self
            .entry()
            .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "this center was removed"))?;
        Ok(self.descriptor(&cfg, &entry))
    }

    /// The descriptor this center sees now. Its `access` holds the folders
    /// the gate goes by, the built-in ones of `nerve-run` among them, so a
    /// grant, a mode or an account that changes moves its rev.
    fn descriptor(
        &self,
        cfg: &NodeConfig,
        entry: &CenterEntry,
    ) -> nerve_proto::descriptor::Descriptor {
        descriptor::for_center(
            cfg,
            entry,
            &self.shared.reach(cfg, entry),
            &self.shared.offered_caps(cfg, &entry.policy),
        )
    }

    fn describe(&self, p: &Map<String, Value>) -> Result<Value, RpcError> {
        let d: Describe = params(p)?;
        if d.detail == Detail::Capability && d.cap.is_none() {
            return Err(RpcError::invalid_args("detail capability needs cap"));
        }
        let view = self.view()?;
        let out = view
            .at_detail(d.detail, d.cap.as_deref())
            .ok_or_else(|| RpcError::new(ErrorCode::UnknownCapability, "no such capability"))?;
        serde_json::to_value(out).map_err(|e| RpcError::internal(e.to_string()))
    }

    fn sub(&self, p: &Map<String, Value>, on: bool) -> Result<Value, RpcError> {
        let t: Topics = params(p)?;
        let view = self.view()?;
        let mut topics = Vec::new();
        for s in &t.topics {
            let topic = Topic::parse(s)
                .ok_or_else(|| RpcError::invalid_args(format!("bad topic {s:?}")))?;
            if view.capability(topic.cap()).is_none() {
                return Err(RpcError::new(
                    ErrorCode::UnknownCapability,
                    format!("no capability {}", topic.cap()),
                ));
            }
            topics.push(topic);
        }
        self.handle.sub(topics, on);
        Ok(json!({}))
    }

    fn get(&self, p: &Map<String, Value>) -> Result<Value, RpcError> {
        let g: Get = params(p)?;
        let view = self.view()?;
        if view.capability(&g.cap).is_none() {
            return Err(RpcError::new(
                ErrorCode::UnknownCapability,
                "no such capability",
            ));
        }
        let (cfg, _) = self
            .entry()
            .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "this center was removed"))?;
        let all: &[&str] = match g.cap.as_str() {
            "node" => &["status"],
            "exec" => &["shell", "confinement"],
            "settings" => &["document", "version", "sudo"],
            _ => &[],
        };
        let keys: Vec<String> = if g.keys.is_empty() {
            all.iter().map(|k| k.to_string()).collect()
        } else {
            g.keys
        };
        let mut out = Map::new();
        for k in keys {
            if !all.contains(&k.as_str()) {
                return Err(RpcError::new(
                    ErrorCode::UnknownMember,
                    format!("{} has no state {k}", g.cap),
                ));
            }
            let v = match k.as_str() {
                "status" => json!(self.status(&cfg)),
                "shell" => json!(exec::shell_command(cfg.machine.shell.as_deref(), "").0),
                "confinement" => json!(self.confinement()),
                "document" => {
                    let doc = lock(&self.shared.store).center_document(&self.name);
                    serde_json::to_value(doc).map_err(|e| RpcError::internal(e.to_string()))?
                }
                "sudo" => json!(if self.shared.sudo_on() { "on" } else { "off" }),
                _ => json!(lock(&self.shared.store).version()),
            };
            out.insert(k, v);
        }
        Ok(Value::Object(out))
    }

    fn status(&self, cfg: &NodeConfig) -> &'static str {
        if cfg.locked {
            "paused"
        } else if self.shared.running.load(Ordering::Relaxed) >= cfg.limits.max_running as usize {
            "busy"
        } else {
            "online"
        }
    }

    fn confinement(&self) -> String {
        let Some((cfg, entry)) = self.entry() else {
            return "none".into();
        };
        let folders = entry.policy.mode_at(crate::now_ms()) == Mode::Folder;
        if folders && self.shared.confined(&cfg) {
            self.shared.confinement.describe()
        } else {
            "none".into()
        }
    }

    /// Starts an `invoke` as its own task, so a slow call does not hold up the
    /// link.
    async fn start_invoke(self: &Arc<Self>, id: Id, p: Map<String, Value>) {
        // `exec.signal` and the `exec/exit` event name a call by its number
        // (spec §5.1), so a call with a text id could not be named there.
        if let Id::Str(_) = id {
            let e = RpcError::new(
                ErrorCode::InvalidRequest,
                "an invoke id is a whole number of 0 or more",
            );
            return self.reply(id, Err(e)).await;
        }
        let inv = match params::<Invoke>(&p).and_then(|i| i.check().map(|()| i)) {
            Ok(i) => i,
            Err(e) => return self.reply(id, Err(e)).await,
        };
        let refusal = {
            let calls = lock(&self.calls);
            if calls.len() >= limits::CALLS as usize {
                Some(RpcError::new(ErrorCode::Busy, "too many calls in flight"))
            } else if calls.contains_key(&id) {
                Some(RpcError::new(
                    ErrorCode::InvalidRequest,
                    "this id is already in flight",
                ))
            } else {
                None
            }
        };
        if let Some(e) = refusal {
            return self.reply(id, Err(e)).await;
        }
        let link = self.clone();
        let call_id = id.clone();
        let session = inv.ctx.session.clone();
        // The deadline counts from receipt (spec §5.1).
        let deadline = inv.deadline_ms.map(Duration::from_millis);
        // Held until the handle is in the map, so a call that finishes at
        // once still finds its entry and replies.
        let mut calls = lock(&self.calls);
        let task = tokio::spawn(async move {
            let settings = inv.cap == "settings";
            let what = format!("{}.{}", inv.cap, inv.action);
            let started = Instant::now();
            let work = link.invoke(&call_id, inv);
            let r = match deadline {
                Some(d) => tokio::time::timeout(d, work).await.unwrap_or_else(|_| {
                    Err(RpcError::new(ErrorCode::Timeout, "the deadline passed"))
                }),
                None => work.await,
            };
            // A call that worked is in the audit log, not here.
            if let Err(e) = &r {
                let (level, line) = call_line(&what, e, started.elapsed(), false);
                let line = format!("center {}: {line}", link.name);
                nerve_transport::log::emit(level, None, &line);
            }
            let mine = lock(&link.calls).remove(&call_id).is_some();
            if mine {
                link.reply(call_id, r).await;
            }
            if settings {
                // The reply goes first, then `settings/changed`.
                link.shared.bump();
            }
        });
        calls.insert(
            id,
            InFlight {
                abort: task.abort_handle(),
                session,
            },
        );
    }

    async fn invoke(self: &Arc<Self>, id: &Id, inv: Invoke) -> Result<Value, RpcError> {
        let (cfg, entry) = self
            .entry()
            .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "this center was removed"))?;
        // The gate and the sandbox see the built-in folders of `nerve-run`
        // too; the config keeps the owner's. A program (a provider) works
        // with the owner's rights, not that account's: its paths count by
        // the folders the owner granted alone.
        let granted = entry.clone();
        let entry = self.shared.with_built_in(&cfg, entry);
        let view =
            descriptor::for_call(&cfg, &entry, crate::now_ms(), &self.shared.added_caps(&cfg));
        let cap = view.capability(&inv.cap).ok_or_else(|| {
            RpcError::new(
                ErrorCode::UnknownCapability,
                format!("no capability {}", inv.cap),
            )
        })?;
        let action = cap.actions.get(&inv.action).ok_or_else(|| {
            RpcError::new(
                ErrorCode::UnknownMember,
                format!("{} has no action {}", inv.cap, inv.action),
            )
        })?;
        let effect = action.effect;
        let off = cap.exposure == Exposure::Off
            || entry.policy.cap_setting(&inv.cap, Some(&inv.action))
                == Some(nerve_policy::config::CapSetting::Off);
        if off {
            // Refused before anything else, and in the audit as any refusal.
            // Its target is what an allowed call's would name, as far as the
            // arguments say it without resolving anything: the audit's rule
            // buttons make a rule of it.
            let why = format!("{}.{} is off", inv.cap, inv.action);
            let target = off_target(&inv);
            self.audit(&inv, &target, "forbidden", Some("disabled"), Some(&why));
            return Err(RpcError::new(ErrorCode::Disabled, why));
        }
        // A capability of the config (crate::config_cap) runs the owner's
        // command, decided and audited like any other call.
        if cap.provider == crate::config_cap::PROVIDER {
            let decl = crate::config_cap::find(&cfg, &inv.cap, &inv.action)
                .cloned()
                .ok_or_else(|| {
                    RpcError::new(
                        ErrorCode::UnknownMember,
                        format!("{}.{} is not served", inv.cap, inv.action),
                    )
                })?;
            return self
                .config_call(id, &cfg, granted, effect, &inv, decl)
                .await;
        }
        // A provider's action (crate::provider) is decided and audited here
        // like any other; only an allowed call reaches the provider. Its
        // arguments are checked first against the schema it published, so
        // it never sees ones that do not fit, and the center learns which
        // field is wrong.
        if cap.provider != "node" {
            let provider = cap.provider.clone();
            // The call is decided for the program attached now, by its
            // account, and goes to that one only.
            let (program, serial) = self.shared.providers.held(&provider).ok_or_else(|| {
                RpcError::new(
                    ErrorCode::Unavailable,
                    format!("the provider {provider} is not attached now"),
                )
            })?;
            let entry = granted;
            nerve_proto::schema::validate(&action.params, &Value::Object(inv.args.clone()))?;
            let marked = nerve_proto::schema::path_args(&action.params);
            // The arguments its schema marks as paths are the call's rule
            // targets, resolved as the command account would see them, as an
            // `fs` call's are: the folders, the rules and the protected and
            // own paths judge them. Only one that may hold other paths (a
            // folder, or where a write may make one) is judged by what lies
            // below it too. The provider gets each path as resolved, so it
            // works where the policy looked. An action with no path
            // has `cap.action` as its target, and looks nobody up.
            let account = if marked.is_empty() {
                Ok(None)
            } else {
                self.shared.command_account(&cfg, &entry.policy)
            };
            let known = account.as_ref().ok().cloned().flatten();
            if !marked.is_empty() && self.shared.separate(&entry.policy) {
                self.acls_ready(&cfg).await?;
            }
            let (args, targets, named, target) =
                self.marked_paths(&inv, &action.params, &marked, known.as_ref())?;
            // A program's execute action runs in the folders marked `x`
            // where folder-mode commands could run: where they cannot be
            // confined, `x` lets nothing start (crate::daemon::folder_refusal).
            let unconfined = (effect == Effect::Execute)
                .then(|| self.shared.unconfined_as(&cfg, || known.clone()))
                .flatten();
            self.gate(
                &entry,
                &inv,
                effect,
                &targets,
                None,
                None,
                target,
                known.as_ref(),
                unconfined,
                Some(program),
            )
            .await
            .map_err(|e| as_given(e, &named))?;
            // A missing account stops the call once it is decided and
            // audited, as for `fs`.
            account.map_err(|e| RpcError::new(ErrorCode::Unavailable, e))?;
            return self
                .shared
                .providers
                .invoke(&provider, serial, &inv.cap, &inv.action, args)
                .await;
        }
        match (inv.cap.as_str(), inv.action.as_str()) {
            ("settings", "set") => self.settings_set(&inv.args),
            ("settings", "pause") => self.settings_pause(),
            ("settings", "sudo-offer") => self.sudo_offer(&entry),
            ("settings", "sudo") => self.settings_sudo(&inv.args).await,
            ("exec", "signal") => {
                // Decided and audited like any other action; its rule target
                // is the action itself.
                let target = format!("{}.{}", inv.cap, inv.action);
                let unconfined = self.shared.unconfined(&cfg);
                self.gate(
                    &entry,
                    &inv,
                    effect,
                    &[],
                    None,
                    None,
                    target,
                    None,
                    unconfined,
                    None,
                )
                .await?;
                self.signal(&inv.args)
            }
            ("exec", "run") => self.exec_run(id, &cfg, &entry, effect, &inv).await,
            ("fs", a) => {
                // On the installed node the node reads and writes as the
                // account the pairing's commands run as (crate::account::FsAs),
                // from the paths of the call to the files it makes. A missing
                // account stops the call once it is decided and audited.
                let account = self.shared.command_account(&cfg, &entry.policy);
                let known = account.as_ref().ok().cloned().flatten();
                // `nerve-run` sees the folders once their ACLs are on.
                if self.shared.separate(&entry.policy) {
                    self.acls_ready(&cfg).await?;
                }
                // A path that does not resolve is in the audit once the
                // switch is over, as for a provider's.
                let parsed = {
                    let _as = act_as(known.as_ref())?;
                    FsCall::parse(a, &inv.args)
                };
                let call = parsed.inspect_err(|e| {
                    if let Some(Value::String(given)) = inv.args.get("path") {
                        self.audit_bad_path(&inv, given, e);
                    }
                })?;
                // Taken before the gate: whenever the gate judged by the
                // folders, the walk below does too, even if `until` passes
                // in between. Where the node reads as the command account,
                // that account's access holds the reads in no folder
                // (nerve_policy::decide::Reads), as in the gate.
                let by_folders = entry.policy.mode_at(crate::now_ms()) == Mode::Folder;
                let by_account = by_folders && self.reads_by_account(&entry, known.as_ref());
                let unconfined = self.shared.unconfined_as(&cfg, || known.clone());
                // Its refusal names the path as given, as a program's does.
                let named = match inv.args.get("path") {
                    Some(Value::String(given)) => vec![(call.target_text(), given.clone())],
                    _ => Vec::new(),
                };
                self.gate(
                    &entry,
                    &inv,
                    effect,
                    &call.targets(),
                    None,
                    None,
                    call.target_text(),
                    known.as_ref(),
                    unconfined,
                    None,
                )
                .await
                .map_err(|e| as_given(e, &named))?;
                account.map_err(|e| RpcError::new(ErrorCode::Unavailable, e))?;
                let protected = self.protected(&entry);
                let deny = RuleSet::new(&entry.policy.deny, &self.home());
                let folders = entry.policy.folders.clone();
                let action = inv.action.clone();
                tokio::task::spawn_blocking(move || {
                    let _as = act_as(known.as_ref())?;
                    // An entry the direct read would refuse stays out of the
                    // walk, so a folder without `r` inside one with `r` is
                    // sealed to grep, find and list too. A walk still passes
                    // through such a folder to a folder with `r` inside it,
                    // and finds only the files there. In no folder, where
                    // the account holds the reads, the walk keeps to what is
                    // open to every account and out of the node's own
                    // process as the gate does; what that account may not
                    // open the walk cannot read anyway.
                    let open = |p: &std::path::Path| {
                        if crate::fs::open_to_all(p) && !crate::fs::own_process(p) {
                            Ok(())
                        } else {
                            Err(String::new())
                        }
                    };
                    let reads = if by_account {
                        Reads::Account(&open)
                    } else {
                        Reads::Folders
                    };
                    let skip = |p: &std::path::Path, through: bool| {
                        protected.check(p, false, &folders).is_some()
                            || deny
                                .find("fs", &action, &nerve_policy::paths::to_wire(p))
                                .is_some()
                            || by_folders
                                && !nerve_policy::read_reach(&folders, p, reads)
                                && !(through && nerve_policy::readable_below(&folders, p))
                    };
                    call.run(&skip)
                })
                .await
                .map_err(|e| RpcError::internal(e.to_string()))?
            }
            _ => Err(RpcError::new(
                ErrorCode::UnknownMember,
                format!("{}.{} is not served", inv.cap, inv.action),
            )),
        }
    }

    /// The paths of a call to a program or a config capability: each
    /// argument its schema `params` marks as a path (`marked`), resolved as
    /// `account` would see it, as an `fs` call's are: the folders, the rules
    /// and the protected and own paths judge them. Only one that may hold
    /// other paths (a folder, or where a write may make one) is judged by
    /// what lies below it too. Returns the arguments with each path as
    /// resolved, so the call works where the policy looked; the targets;
    /// each path as resolved and as given; and the audit target (the paths,
    /// or `cap.action` for a call that names none, which looks nobody up).
    #[allow(clippy::type_complexity)]
    fn marked_paths(
        &self,
        inv: &Invoke,
        params: &Value,
        marked: &[(String, PathMark)],
        known: Option<&crate::service::Account>,
    ) -> Result<
        (
            Map<String, Value>,
            Vec<Target>,
            Vec<(String, String)>,
            String,
        ),
        RpcError,
    > {
        let mut args = inv.args.clone();
        let mut targets = Vec::new();
        // Each path as resolved (its wire form) and as given.
        let mut named = Vec::new();
        // One that does not resolve as the account (a place it may not
        // look into, the node's own folders) is refused and in the audit
        // as any refusal, with the path given. The entry is written once
        // the switch is over: the account may not write the node's log.
        let resolved = {
            let _as = act_as(known)?;
            marked.iter().try_for_each(|(field, mark)| {
                // Left out (or null, which its schema may allow): no path.
                let Some(Value::String(given)) = inv.args.get(field) else {
                    return Ok(());
                };
                let path = WirePath::parse(given).map_err(|e| (given, e, None))?;
                let write = *mark == PathMark::Write;
                // The program gets the path resolved, so where the path
                // given is itself a link, a write there (a removal, a
                // rename) would act on the place it leads to, which the
                // agent never named.
                let own: std::path::PathBuf = path.given.components().collect();
                if write
                    && std::fs::symlink_metadata(&own).is_ok_and(|m| m.file_type().is_symlink())
                {
                    return Err((
                        given,
                        crate::fs::bad_path(format!(
                            "{given} is a link; name the place it leads to"
                        )),
                        None,
                    ));
                }
                // It is handed the path judged, character for character:
                // a name that is no Unicode would reach it as another.
                let Some(real) = path
                    .real
                    .to_str()
                    .map(|_| nerve_policy::paths::to_wire(&path.real))
                else {
                    return Err((
                        given,
                        crate::fs::bad_path(format!(
                            "{given} leads to a name the program cannot be handed as it is"
                        )),
                        None,
                    ));
                };
                args.insert(field.clone(), Value::String(real.clone()));
                // Its schema holds the path as it is handed, too. Only the
                // audit names where it leads ([`as_given`]).
                nerve_proto::schema::validate(params, &Value::Object(args.clone())).map_err(
                    |_| {
                        let (cap, act) = (&inv.cap, &inv.action);
                        (
                            given,
                            crate::fs::bad_path(format!(
                                "{given} leads to a path {cap}.{act} does not take"
                            )),
                            Some(format!(
                                "{given} leads to {real}, which {cap}.{act} does not take"
                            )),
                        )
                    },
                )?;
                named.push((real, given.clone()));
                targets.push(Target {
                    holds: crate::fs::holds(&path.real, write),
                    path: path.real,
                    access: if write {
                        PathAccess::Write
                    } else {
                        PathAccess::Read
                    },
                });
                Ok(())
            })
        };
        resolved.map_err(|(given, e, audited)| {
            let mut entry = e.clone();
            if let Some(why) = audited {
                entry.message = why;
            }
            self.audit_bad_path(inv, given, &entry);
            e
        })?;
        let target = if targets.is_empty() {
            format!("{}.{}", inv.cap, inv.action)
        } else {
            targets
                .iter()
                .map(|t| nerve_policy::paths::to_wire(&t.path))
                .collect::<Vec<_>>()
                .join(", ")
        };
        Ok((args, targets, named, target))
    }

    /// The `~` of the rules and the protected list (Shared::rules_home).
    fn home(&self) -> std::path::PathBuf {
        self.shared.rules_home(&self.shared.config())
    }

    /// The owner's account, whose view of the files the protected list
    /// is made with, when there is one to use. Not called while the store
    /// is locked: it reads the config.
    fn account(&self) -> Option<crate::service::Account> {
        self.shared
            .owner_account(&self.shared.config())
            .ok()
            .flatten()
    }

    fn protected(&self, entry: &CenterEntry) -> Protected {
        self.protected_with(
            &entry.policy.protected,
            self.account().as_ref(),
            &self.own(),
        )
    }

    /// The folders no center reaches (Shared::own). Not called while the
    /// store is locked: it reads the config.
    fn own(&self) -> Vec<std::path::PathBuf> {
        self.shared.own(&self.shared.config())
    }

    /// This node's protected list with a center's options. On the
    /// installed node its `~` is the owner's home, and its entries are
    /// looked at as the owner (crate::account::FsAs), who may see where the
    /// node's user may not.
    fn protected_with(
        &self,
        opts: &nerve_policy::config::ProtectedOptions,
        account: Option<&crate::service::Account>,
        own: &[std::path::PathBuf],
    ) -> Protected {
        let home = account.map_or(&self.shared.home, |a| &a.home);
        // Without the switch the entries are still there as written; only
        // the places they lead to through links are not found.
        let _as = act_as(account).ok().flatten();
        Protected::new(&self.shared.platform, home, own, opts)
    }

    /// The shell a command line runs in, which the guard reads it by: the
    /// configured one, and `/bin/sh` for a sudo command off Windows, which
    /// runs as root there (crate::exec::run).
    fn shell_for(&self, command: Option<&str>) -> Shell {
        let cfg = self.shared.config();
        shell_of(cfg.machine.shell.as_deref(), command)
    }

    /// Runs the policy for one call: it either runs or is refused at once.
    /// Every outcome lands in the audit log.
    #[allow(clippy::too_many_arguments)]
    async fn gate(
        &self,
        entry: &CenterEntry,
        inv: &Invoke,
        effect: Effect,
        targets: &[Target],
        command: Option<&str>,
        cwd: Option<&std::path::Path>,
        target: String,
        account: Option<&crate::service::Account>,
        unconfined: Option<&str>,
        program: Option<u32>,
    ) -> Result<(), RpcError> {
        let call = Call {
            cap: &inv.cap,
            action: &inv.action,
            effect,
            targets,
            command,
            cwd,
            now_ms: crate::now_ms(),
        };
        let judged = Judged {
            home: self.home(),
            protected: self.protected(entry),
            unconfined: unconfined.map(Into::into),
            sudo: self.shared.sudo_on(),
            shell: self.shell_for(command),
            by_account: self.reads_by_account(entry, account),
            // The node's own `fs` and the commands of a config capability
            // as `nerve-run` read with that account's rights; a program, and
            // a config capability that runs as the owner, with the owner's.
            provider: program.is_some(),
        };
        // The policy looks at the paths as the account (crate::account::FsAs);
        // the audit entry below is the node's own again.
        let decision = {
            let _as = act_as(account)?;
            judged.with(|env| nerve_policy::decide(&entry.policy, env, &call))
        };
        // A program handed a folder follows the links in it: where they
        // lead is judged too, once the call is allowed, so a folder the
        // call may not use is never walked. The walk may be long (or hang
        // on a mount that does not answer), so it runs off the link's
        // threads, where the call's deadline still answers the center.
        let decision = if decision == Decision::Allow
            && nerve_policy::works_below(&call)
            && targets.iter().any(|t| t.holds)
        {
            let policy = entry.policy.clone();
            let (cap, action) = (inv.cap.clone(), inv.action.clone());
            let targets = targets.to_vec();
            let command = command.map(str::to_string);
            let cwd = cwd.map(std::path::Path::to_path_buf);
            let walker = account.map_or_else(crate::account::own_uid, |a| a.uid);
            let closed = closed_for(program, walker, crate::account::own_uid());
            let account = account.cloned();
            let now_ms = call.now_ms;
            // A call whose deadline passes, or that is cancelled, while its
            // links are walked is dropped at the await below: the walk
            // stops then, and the call is in the audit log all the same.
            let walk = walk_off(
                move |stop| {
                    let call = Call {
                        cap: &cap,
                        action: &action,
                        effect,
                        targets: &targets,
                        command: command.as_deref(),
                        cwd: cwd.as_deref(),
                        now_ms,
                    };
                    let _as = act_as(account.as_ref())?;
                    Ok::<_, RpcError>(judged.with(|env| {
                        let check = nerve_policy::LinkCheck::new(&policy, env, &call);
                        let mut judge = |l: &nerve_policy::Link| check.refuse(l);
                        match crate::fs::links_below(
                            &targets,
                            crate::fs::LINKS_LIMIT,
                            closed,
                            stop,
                            &mut judge,
                        ) {
                            Ok(()) => Decision::Allow,
                            Err(why) => Decision::Forbidden(why),
                        }
                    }))
                },
                |decision, code, reason| self.audit(inv, &target, decision, code, reason),
            )
            .await;
            walk.map_err(|e| RpcError::internal(e.to_string()))??
        } else {
            decision
        };
        let audit = |decision: &str, code: Option<&str>, reason: Option<&str>| {
            self.audit(inv, &target, decision, code, reason)
        };
        match decision {
            Decision::Allow => {
                audit("allowed", None, None);
                Ok(())
            }
            Decision::Disabled(why) => {
                audit("forbidden", Some("disabled"), Some(&why));
                Err(RpcError::new(ErrorCode::Disabled, why))
            }
            Decision::Forbidden(why) => {
                audit("forbidden", Some("forbidden"), Some(&why));
                Err(RpcError::forbidden(why))
            }
        }
    }

    /// Writes the refusal of a call whose path `given` did not resolve
    /// (`e`, a `bad_path`) to the audit log, with the path as given: an
    /// attempt at a place the account may not look into is in the log as
    /// any refusal. Any other error is about the arguments, not a place. An
    /// `fs` entry names it only where it is as plain as a resolved path
    /// ([`plain_path`]); the reason names it either way.
    fn audit_bad_path(&self, inv: &Invoke, given: &str, e: &RpcError) {
        if e.kind().as_str() == "bad_path" {
            let target = if inv.cap == "fs" {
                plain_path(given)
            } else {
                given
            };
            self.audit(inv, target, "forbidden", Some("bad_path"), Some(&e.message));
        }
    }

    /// Writes one entry of this center's calls to the audit log.
    fn audit(
        &self,
        inv: &Invoke,
        target: &str,
        decision: &str,
        code: Option<&str>,
        reason: Option<&str>,
    ) {
        self.shared.audit(&Entry {
            ts: crate::now_ms(),
            center: self.name.clone(),
            cap: inv.cap.clone(),
            action: inv.action.clone(),
            target: target.to_string(),
            decision: decision.into(),
            code: code.map(Into::into),
            session: inv.ctx.session.clone(),
            reason: reason.map(Into::into),
        })
    }

    /// Whether the node reads this center's files as its command account,
    /// `account` as a call looked it up: on the installed Linux node, where
    /// the commands run as `nerve-run` (crate::account::FsAs). That
    /// account's own file access then holds what folder mode reads
    /// (nerve_policy::decide::Reads). A call whose account could not be
    /// found reads by the folders.
    fn reads_by_account(
        &self,
        entry: &CenterEntry,
        account: Option<&crate::service::Account>,
    ) -> bool {
        account.is_some() && self.shared.separate(&entry.policy)
    }

    fn settings_set(&self, args: &Map<String, Value>) -> Result<Value, RpcError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Set {
            document: Value,
            if_version: u64,
        }
        let s: Set = params(args)?;
        let account = self.account();
        let own = self.own();
        // Only a program's capability, or one of the config, can sense
        // (crate::provider, crate::config_cap). Every one the config
        // declares counts, also one not offered here now: a center's `on`
        // for it would cover its sensing action once the owner makes it
        // offered.
        let cfg = self.shared.config();
        let config = crate::config_cap::declared(&cfg);
        let owner_only = self.shared.providers.owner_only(&config);
        let r = lock(&self.shared.store).set_center_document(
            &self.name,
            s.document,
            s.if_version,
            owner_only,
            |opts| self.protected_with(opts, account.as_ref(), &own),
        );
        settings_result(r)
    }

    /// `settings.pause`: a center may pause itself, never unpause.
    fn settings_pause(&self) -> Result<Value, RpcError> {
        let account = self.account();
        let own = self.own();
        let mut store = lock(&self.shared.store);
        let doc = store
            .center_document(&self.name)
            .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "this center was removed"))?;
        let mut v = serde_json::to_value(doc).map_err(|e| RpcError::internal(e.to_string()))?;
        v["paused"] = Value::Bool(true);
        let version = store.version();
        // Pausing changes nothing else of the document, so no sensing turns on.
        let r = store.set_center_document(
            &self.name,
            v,
            version,
            |_| false,
            |opts| self.protected_with(opts, account.as_ref(), &own),
        );
        settings_result(r).map(|_| json!({}))
    }

    /// `settings.sudo-offer`: a fresh one-shot key for the sealed password,
    /// signed with this node's key for the center. A new offer replaces the
    /// open one.
    fn sudo_offer(&self, entry: &CenterEntry) -> Result<Value, RpcError> {
        let pending =
            nerve_transport::sudo::Pending::new(crate::now_ms()).map_err(RpcError::internal)?;
        let key = load_key(&self.shared, &self.name).map_err(RpcError::internal)?;
        let center_id = entry.center_id.clone();
        let offer = pending.offer().clone();
        let sig = key.sign_sudo_offer(&center_id, &offer);
        lock(&self.shared.sudo_offers).insert(self.name.clone(), pending);
        Ok(json!({"offer": offer.offer, "key": offer.key, "ts": offer.ts, "sig": sig}))
    }

    /// `settings.sudo`: on with a sealed password the node checks with
    /// `sudo -v`, or off.
    async fn settings_sudo(&self, args: &Map<String, Value>) -> Result<Value, RpcError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SudoArgs {
            on: bool,
            #[serde(default)]
            sealed: Option<nerve_transport::sudo::Sealed>,
        }
        let a: SudoArgs = params(args)?;
        let by = nerve_policy::Writer::Center(&self.name);
        if !a.on {
            if a.sealed.is_some() {
                return Err(RpcError::invalid_args("off takes no sealed password"));
            }
            return settings_result(self.shared.sudo_switch_off(by))
                .map(|_| json!({"sudo": "off"}));
        }
        let sealed = a
            .sealed
            .ok_or_else(|| RpcError::invalid_args("on needs a sealed password"))?;
        // Taken out before it is opened: an offer opens once, right or wrong.
        let pending = lock(&self.shared.sudo_offers)
            .remove(&self.name)
            .ok_or_else(|| {
                RpcError::invalid_args("no open sudo offer; ask settings.sudo-offer for one")
            })?;
        let password = pending
            .open(&sealed, crate::now_ms())
            .map_err(RpcError::invalid_args)?;
        settings_result(self.shared.sudo_switch_on(by, password).await)
            .map(|_| json!({"sudo": "on"}))
    }

    fn signal(&self, args: &Map<String, Value>) -> Result<Value, RpcError> {
        let s: SignalArgs = params(args)?;
        let sig = Sig::parse(&s.signal)
            .ok_or_else(|| RpcError::invalid_args("signal must be term, kill or int"))?;
        let id = Id::Num(s.call);
        let ender = lock(&self.commands)
            .get(&id)
            .cloned()
            .ok_or_else(|| RpcError::invalid_args(format!("no running command {id}")))?;
        ender.signal(sig);
        Ok(json!({}))
    }

    async fn exec_run(
        self: &Arc<Self>,
        id: &Id,
        cfg: &NodeConfig,
        entry: &CenterEntry,
        effect: Effect,
        inv: &Invoke,
    ) -> Result<Value, RpcError> {
        // The installed node runs a command as `nerve-run`, or as the owner
        // where the pairing runs as the owner (crate::account), from that
        // account's home. A sudo command of a pairing that runs as the owner
        // runs through sudo as the owner, whose password the switch holds;
        // one of a pairing that runs as `nerve-run` runs as root, started by
        // the node itself: `nerve-run` has no sudo, and the sudo allow list
        // is its only way to root. A missing account stops the command after
        // the call is decided and audited.
        let sudo_call = inv
            .args
            .get("command")
            .and_then(Value::as_str)
            .is_some_and(|c| nerve_policy::sudo_command(c).is_some());
        let as_root = sudo_call && cfg!(target_os = "linux") && self.shared.separate(&entry.policy);
        let account = if as_root {
            Ok(Some(root_account()))
        } else if sudo_call {
            self.shared.owner_account(cfg)
        } else {
            self.shared.command_account(cfg, &entry.policy)
        };
        let known = account.as_ref().ok().cloned().flatten();
        // The paths of a call are looked at as its account, but those of a
        // sudo command that runs as root as the owner's, whose sudo list
        // lets it run: the node's file system id 0 has no right past a
        // folder's mode (it holds CAP_SETUID and CAP_SETGID only), so the
        // owner's closed home would refuse it. Its default folder is the
        // owner's home then.
        let looks_as = if as_root {
            self.shared.owner_account(cfg).ok().flatten()
        } else {
            known.clone()
        };
        let start_in = looks_as
            .as_ref()
            .map_or(&self.shared.home, |a| &a.home)
            .clone();
        // `~` of the folders and rules: the owner's.
        let home = self.shared.rules_home(cfg);
        // `nerve-run` sees the folders once their ACLs are on.
        if self.shared.separate(&entry.policy) && !sudo_call {
            self.acls_ready(cfg).await?;
        }
        // The paths are looked at as the account (crate::account::FsAs).
        let rc = {
            let _as = act_as(looks_as.as_ref())?;
            RunCall::parse(&inv.args, &start_in)?
        };
        // A call may ask for less than the owner's most, never for more.
        let granted = cfg
            .limits
            .command
            .grant(
                rc.limits.memory_mb,
                rc.limits.cpu_percent,
                rc.limits.processes,
            )
            .map_err(RpcError::invalid_args)?;
        let target = rc.command.clone();
        let command = rc.command.clone();
        // The gate and the sandbox below go by one answer, from `cfg` and its
        // account, taken before the gate: a config written meanwhile or a limit
        // that passes cannot let a command the gate judged by the folders run
        // without Landlock. A limit only ever turns folder mode into allowlist,
        // which the gate then judges, so the sandbox is never less than what it
        // judged. A command of `nerve-run` is confined in every mode.
        let by_folders = entry.policy.mode_at(crate::now_ms()) == Mode::Folder;
        let separate = self.shared.separate(&entry.policy) && !sudo_call;
        let unconfined = self.shared.unconfined_as(cfg, || known.clone());
        // Its refusal names the `cwd` given as given, as a program's paths
        // are; the default one the center did not name.
        let named: Vec<(String, String)> = inv
            .args
            .get("cwd")
            .and_then(Value::as_str)
            .map(|given| (nerve_policy::paths::to_wire(&rc.cwd), given.to_string()))
            .into_iter()
            .collect();
        self.gate(
            entry,
            inv,
            effect,
            &rc.targets(),
            Some(&rc.command),
            Some(&rc.cwd),
            target,
            looks_as.as_ref(),
            unconfined,
            None,
        )
        .await
        .map_err(|e| as_given(e, &named))?;
        let account = account.map_err(|e| RpcError::new(ErrorCode::Unavailable, e))?;
        // The policy let a sudo command through only with the switch on and
        // the sudo allow list naming it. It runs the node's sudo, with the
        // password on stdin once sudo prompts for it, and without Landlock,
        // which would keep sudo from rising.
        let mut rc = rc;
        let mut sudo = None;
        let mut root = None;
        if let Some(args) = nerve_policy::sudo_command(&rc.command).filter(|_| as_root) {
            // The one simple command the sudo allow list named (the gate
            // takes no other), as root, and nothing around it; it starts in
            // the folder the gate judged, which the node opens as the
            // owner (exec::AsRoot). A leading `-n` or `--` goes, any other
            // option of sudo is refused (exec::root_line).
            if !self.shared.sudo_on() {
                return Err(RpcError::forbidden("sudo is off on this node"));
            }
            let line = exec::root_line(args)?.to_string();
            root = Some(exec::AsRoot::open(&rc.cwd, looks_as.as_ref())?);
            rc.command = line;
        } else if let Some(args) = nerve_policy::sudo_command(&rc.command) {
            let password = self
                .shared
                .sudo_password()
                .ok_or_else(|| RpcError::forbidden("sudo is off on this node"))?;
            let prompt = exec::sudo_prompt();
            rc.command = exec::sudo_line(&self.shared.sudo_path(), args, &prompt);
            sudo = Some(exec::SudoInput { password, prompt });
        }
        // Folder mode confines: Landlock on Linux, the pairing's AppContainer
        // on Windows, by the answer the gate went by; `nerve-run` is
        // confined in allowlist mode too, where Landlock is there.
        let folder = sudo.is_none() && !as_root && by_folders && unconfined.is_none();
        let container = if folder && self.shared.confinement.appcontainer {
            Some(self.container(entry, cfg, &home).await?)
        } else {
            None
        };
        let guard = Running::start(self, id.clone(), cfg.limits.max_running as usize)?;
        // A sudo command's output is not streamed (exec::run leaves it out).
        let tap = guard.tap(sudo.is_none() && root.is_none());
        let own = self.shared.own(cfg);
        let confine = folder || separate && self.shared.exe.is_some();
        let landlock = (confine && self.shared.confinement.landlock_abi.is_some()).then(|| {
            // The folders' entries are listed as the account.
            let _as = act_as(known.as_ref()).ok().flatten();
            // The folders a command of any center may write: a link it puts
            // in place of a folder inside one leads nowhere the next
            // command gets rules for.
            let writable = exec::write_folders(cfg, &home);
            exec::landlock_spec(&entry.policy, &home, &own, &writable)
        });
        // Counted while it runs, so the keys do not move into the keyring
        // meanwhile, and not started when they moved after `cfg` was taken.
        let open = crate::daemon::reaches_bus(landlock.as_ref(), || account.clone())
            .then(|| self.shared.open_to_bus())
            .transpose()
            .map_err(|e| RpcError::new(ErrorCode::Unavailable, e))?;
        let opts = RunOptions {
            shell: cfg.machine.shell.clone(),
            landlock,
            container,
            exe: self.shared.exe.clone().unwrap_or_default(),
            output_cap: (cfg.limits.output_cap_bytes as usize).min(exec::OUTPUT_HARD_CAP),
            timeouts: exec::Timeouts::from_limits(&cfg.limits),
            sudo,
            account,
            separate,
            own,
            root,
            limits: self
                .shared
                .cgroups
                .as_ref()
                .ok()
                .map(|c| (c.clone(), granted)),
            tap,
        };
        let r = exec::run(&rc, &opts, |e| guard.started(e)).await;
        drop(open);
        drop(guard);
        if let Ok(v) = &r {
            self.audit_killed(inv, command, v);
        }
        if let Ok(v) = &r {
            self.handle.event(
                "exec",
                "exit",
                json!({"call": id, "exit_code": v.get("exit_code").cloned().unwrap_or(Value::Null)}),
            );
        }
        r
    }
}

impl Link {
    /// A command killed for its memory limit is a decision of the node's
    /// too: the audit log (with `target`, as the call's entry has it) and
    /// the node's log say so, as the result `v` does.
    fn audit_killed(&self, inv: &Invoke, target: String, v: &Value) {
        if v["killed"] != "memory" {
            return;
        }
        let reason = v["reason"].as_str().unwrap_or_default();
        tracing::warn!("a command of {} was killed: {reason}", self.name);
        self.shared.audit(&Entry {
            ts: crate::now_ms(),
            center: self.name.clone(),
            cap: inv.cap.clone(),
            action: inv.action.clone(),
            target,
            decision: "killed".into(),
            code: Some("memory".into()),
            session: inv.ctx.session.clone(),
            reason: Some(reason.into()),
        });
    }

    /// A call of the config capability `decl` (crate::config_cap): its
    /// arguments checked against its schema, its marked paths resolved and
    /// the call decided and audited like a program's; then its command runs
    /// with no shell, as `nerve-run` or as the owner, from that account's
    /// home, under the node's limits on commands (the running count, the
    /// cgroup, the timeout).
    ///
    /// As `nerve-run` it is a command of that account, held like one: its
    /// paths are looked at as that account, which reads them with its own
    /// rights, and it runs under Landlock where the kernel has it, with the
    /// pairing's folders and the account's own (its home, `/tmp`,
    /// `/var/tmp`) where the pairing's commands run as `nerve-run`; where
    /// they run as the owner (user mode, a pairing set to run as the owner),
    /// the folders are not `nerve-run`'s, and it gets its own alone. As the
    /// owner it has the owner's rights, like a program (crate::provider): only
    /// the folders the owner granted count for its paths, and no sandbox
    /// holds it.
    async fn config_call(
        self: &Arc<Self>,
        id: &Id,
        cfg: &NodeConfig,
        granted: CenterEntry,
        effect: Effect,
        inv: &Invoke,
        decl: nerve_policy::config::ConfigCapability,
    ) -> Result<Value, RpcError> {
        use nerve_policy::config::RunsAs;
        let params = decl.params_schema();
        nerve_proto::schema::validate(&params, &Value::Object(inv.args.clone()))?;
        let marked = nerve_proto::schema::path_args(&params);
        let as_owner = decl.account == RunsAs::Owner;
        let (entry, runs_as, looks_as) = if as_owner {
            // A program's view: the pairing's command account looks at the
            // paths, which only the folders the owner granted hold.
            let looks = if marked.is_empty() {
                Ok(None)
            } else {
                self.shared.command_account(cfg, &granted.policy)
            };
            (granted, self.shared.owner_account(cfg), looks)
        } else {
            let run = self.shared.run_account(cfg);
            (self.shared.with_built_in(cfg, granted), run.clone(), run)
        };
        let known = looks_as.as_ref().ok().cloned().flatten();
        // `nerve-run` sees the folders once their ACLs are on; a grant that
        // should have come off and has not stops it whatever the pairing.
        if !as_owner || !marked.is_empty() && self.shared.separate(&entry.policy) {
            self.acls_ready(cfg).await?;
        }
        let (args, targets, named, target) =
            self.marked_paths(inv, &params, &marked, known.as_ref())?;
        let mut argv = decl.argv(&args).map_err(RpcError::invalid_args)?;
        // It starts in the home of the account it runs as (the node's own
        // by hand).
        let start_in = match &runs_as {
            Ok(Some(a)) => a.home.clone(),
            _ => self.shared.home.clone(),
        };
        // With the owner's rights it may not run what a center may write,
        // nor start there: the `w` folders of every center and
        // `nerve-run`'s own. Looked at as the owner, who may look into them.
        if as_owner {
            let mut writable = exec::write_folders(cfg, &self.shared.rules_home(cfg));
            writable.extend(match self.shared.run_account(cfg) {
                Ok(Some(a)) => crate::account::built_in(&a.home)
                    .into_iter()
                    .map(|f| f.path.into())
                    .collect(),
                _ => vec!["/tmp".into(), "/var/tmp".into()],
            });
            let (why, file) = {
                let owner = runs_as.as_ref().ok().cloned().flatten();
                let _as = act_as(owner.as_ref()).ok().flatten();
                let path = std::env::var_os("PATH");
                (
                    crate::config_cap::written_by_centers(
                        &decl,
                        &writable,
                        path.as_deref(),
                        &start_in,
                    ),
                    crate::config_cap::program_file(&argv[0], path.as_deref()),
                )
            };
            if let Some(why) = why {
                self.audit(inv, &target, "forbidden", Some("forbidden"), Some(&why));
                return Err(RpcError::new(ErrorCode::Forbidden, why));
            }
            // The file judged runs, not another one a second look in PATH
            // might find.
            if let Some(f) = file {
                argv[0] = f.display().to_string();
            }
        }
        // A program of the owner's account: the link walk refuses a folder
        // it may not look into, where the owner may.
        let program = as_owner.then(|| {
            runs_as
                .as_ref()
                .ok()
                .cloned()
                .flatten()
                .map_or_else(crate::account::own_uid, |a| a.uid)
        });
        let unconfined = (effect == Effect::Execute)
            .then(|| self.shared.unconfined_as(cfg, || known.clone()))
            .flatten();
        self.gate(
            &entry,
            inv,
            effect,
            &targets,
            None,
            None,
            target.clone(),
            known.as_ref(),
            unconfined,
            program,
        )
        .await
        .map_err(|e| as_given(e, &named))?;
        // A missing account stops the call once it is decided and audited.
        looks_as.map_err(|e| RpcError::new(ErrorCode::Unavailable, e))?;
        let account = runs_as.map_err(|e| RpcError::new(ErrorCode::Unavailable, e))?;
        // Only the installed Linux node has `nerve-run`, and only it offers
        // what runs as that account (crate::config_cap::offered).
        if !as_owner && account.is_none() {
            return Err(RpcError::new(
                ErrorCode::Unavailable,
                format!(
                    "{} runs as {}, which only the installed node has",
                    decl.name,
                    crate::account::RUN_USER
                ),
            ));
        }
        let home = self.shared.rules_home(cfg);
        let own = self.shared.own(cfg);
        let landlock = (!as_owner
            && self.shared.exe.is_some()
            && self.shared.confinement.landlock_abi.is_some())
        .then(|| {
            let policy = crate::config_cap::confined(
                &entry.policy,
                self.shared.separate(&entry.policy),
                account.as_ref().map(|a| a.home.as_path()),
            );
            // The folders' entries are listed as the account.
            let _as = act_as(account.as_ref()).ok().flatten();
            let writable = exec::write_folders(cfg, &home);
            exec::landlock_spec(&policy, &home, &own, &writable)
        });
        let granted = cfg
            .limits
            .command
            .grant(None, None, None)
            .map_err(RpcError::invalid_args)?;
        let rc = RunCall::program(
            argv,
            decl.command_line(),
            start_in,
            decl.timeout_secs.map(Duration::from_secs),
        );
        let guard = Running::start(self, id.clone(), cfg.limits.max_running as usize)?;
        let timeouts = exec::Timeouts::from_limits(&cfg.limits);
        let opts = RunOptions {
            shell: None,
            landlock,
            container: None,
            exe: self.shared.exe.clone().unwrap_or_default(),
            output_cap: (cfg.limits.output_cap_bytes as usize).min(exec::OUTPUT_HARD_CAP),
            timeouts,
            sudo: None,
            account,
            separate: !as_owner,
            own,
            root: None,
            limits: self
                .shared
                .cgroups
                .as_ref()
                .ok()
                .map(|c| (c.clone(), granted)),
            tap: guard.tap(true),
        };
        let r = exec::run(&rc, &opts, |e| guard.started(e)).await;
        drop(guard);
        if let Ok(v) = &r {
            self.audit_killed(inv, target, v);
        }
        let run = r.map_err(|e| match e.kind() {
            // Its own limit, not a `timeout_ms` the call never had.
            ErrorCode::Timeout => RpcError::new(
                ErrorCode::Timeout,
                format!(
                    "{} ran past its limit of {} and was killed",
                    decl.name,
                    span(timeouts.limit(rc.timeout).after)
                ),
            ),
            _ => e,
        })?;
        crate::config_cap::result(&decl, &run)
    }
}

/// The account an allowed sudo command of `nerve-run` runs as
/// (crate::account::root).
fn root_account() -> crate::service::Account {
    #[cfg(target_os = "linux")]
    return crate::account::root();
    #[cfg(not(target_os = "linux"))]
    unreachable!("only the installed Linux node runs commands as nerve-run")
}

impl Link {
    /// Waits until the folders' ACLs for `nerve-run` follow `cfg`
    /// (crate::acl), or says why its call does not run: an entry that should
    /// have come off is still there. A change that takes long holds the call.
    async fn acls_ready(&self, cfg: &NodeConfig) -> Result<(), RpcError> {
        #[cfg(target_os = "linux")]
        {
            let (s, cfg) = (self.shared.clone(), cfg.clone());
            let refusal = tokio::task::spawn_blocking(move || s.acls_refusal(&cfg))
                .await
                .map_err(|e| RpcError::internal(e.to_string()))?;
            if let Some(why) = refusal {
                return Err(RpcError::new(ErrorCode::Unavailable, why));
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = cfg;
        Ok(())
    }

    /// The AppContainer of the commands of this pairing (`entry`), once the
    /// folder grants follow `cfg` (crate::grants); `home` is the `~` of the
    /// rules. A grant of this pairing's container that its folders no longer
    /// give and that could not be taken off stops the command, and so does a
    /// record of the grants that cannot be read (`Synced::refusal`).
    async fn container(
        &self,
        entry: &CenterEntry,
        cfg: &NodeConfig,
        home: &std::path::Path,
    ) -> Result<nerve_sandbox::ContainerSpec, RpcError> {
        let (paths, cfg, home) = (self.shared.paths.clone(), cfg.clone(), home.to_path_buf());
        // A change that takes long holds the command; the log says how far
        // it is.
        let synced = tokio::task::spawn_blocking(move || {
            crate::grants::apply(&paths, &cfg, &home, &mut |m| {
                tracing::info!("folder grants: {m}")
            })
        })
        .await
        .map_err(|e| RpcError::internal(e.to_string()))?;
        for e in &synced.errors {
            tracing::warn!("folder grants: {e}");
        }
        let name = crate::grants::container(&self.shared.paths, &entry.node_id);
        if let Some(why) = synced.refusal(&name) {
            return Err(RpcError::new(ErrorCode::Unavailable, why));
        }
        Ok(nerve_sandbox::ContainerSpec { name })
    }
}

/// The audit reason of a call that ended (its deadline passed, or it was
/// cancelled) while the node walked the links below its paths. It never
/// reached the program.
const ENDED_IN_WALK: &str = "the call ended before the node had checked where the links below its paths lead; it did not run";

/// Runs `walk` on a blocking thread, off the link's threads, and waits for
/// it: [`Link::gate`]'s walk of the links below a call's paths. Dropped
/// while it waits (the call's deadline passed, or the call was cancelled),
/// it stops the walk through the flag it hands `walk`, and writes the call
/// to the audit log with `audit` (decision, code, reason) as refused,
/// `cancelled`: the gate that would have written it is gone.
async fn walk_off<T: Send + 'static>(
    walk: impl FnOnce(&AtomicBool) -> T + Send + 'static,
    audit: impl FnOnce(&str, Option<&str>, Option<&str>),
) -> Result<T, tokio::task::JoinError> {
    let stop = Arc::new(AtomicBool::new(false));
    let ended = Ended::new(stop.clone(), move || {
        audit("forbidden", Some("cancelled"), Some(ENDED_IN_WALK))
    });
    let walked = tokio::task::spawn_blocking(move || walk(&stop)).await;
    ended.waited();
    walked
}

/// Held by [`walk_off`] while it waits for the walk of a call's links.
/// Dropped before [`Ended::waited`], the call was dropped while it waited:
/// it stops the walk and writes the call to the audit log, which the gate
/// no longer does.
struct Ended<F: FnOnce()> {
    stop: Arc<AtomicBool>,
    audit: Option<F>,
}

impl<F: FnOnce()> Ended<F> {
    fn new(stop: Arc<AtomicBool>, audit: F) -> Ended<F> {
        Ended {
            stop,
            audit: Some(audit),
        }
    }

    /// The walk answered; the gate writes the outcome itself.
    fn waited(mut self) {
        self.audit = None;
    }
}

impl<F: FnOnce()> Drop for Ended<F> {
    fn drop(&mut self) {
        if let Some(audit) = self.audit.take() {
            self.stop.store(true, Ordering::Relaxed);
            audit();
        }
    }
}

/// What the policy needs to know of the node for one call
/// (nerve_policy::Env), owned, so the links below a handed folder can be
/// judged off the link's threads with the same view.
struct Judged {
    /// The `~` of the rules and the protected list.
    home: std::path::PathBuf,
    protected: Protected,
    unconfined: Option<String>,
    sudo: bool,
    shell: Shell,
    /// Whether the node reads as the command account (Link::reads_by_account).
    by_account: bool,
    /// Whether the call is a program's, not the node's own `fs`.
    provider: bool,
}

impl Judged {
    /// Runs `f` with the policy's view of the node. Where the node reads
    /// as the command account, a path read in no folder in folder mode is
    /// asked of that account (crate::fs::may_read_outside), so `f` runs
    /// under the switch to it.
    fn with<R>(&self, f: impl FnOnce(&Env) -> R) -> R {
        let may_read = |p: &std::path::Path| crate::fs::may_read_outside(p, self.provider);
        f(&Env {
            home: &self.home,
            protected: &self.protected,
            unconfined: self.unconfined.as_deref(),
            sudo: self.sudo,
            shell: self.shell,
            reads: if self.by_account {
                Reads::Account(&may_read)
            } else {
                Reads::Folders
            },
        })
    }
}

/// The node's file access as `account` on this thread while the result
/// lives ([`crate::account::FsAs`]); nothing for the node's own user.
#[cfg(target_os = "linux")]
pub(crate) fn act_as(
    account: Option<&crate::service::Account>,
) -> Result<Option<crate::account::FsAs>, RpcError> {
    account
        .map(|a| {
            crate::account::FsAs::new(a).map_err(|e| {
                RpcError::new(
                    ErrorCode::Unavailable,
                    format!("cannot act as {}: {e}", a.name),
                )
            })
        })
        .transpose()
}

/// [`act_as`] on Windows: the thread impersonates the account, logged on
/// with its stored password ([`crate::win_user::FsAs`]).
#[cfg(windows)]
fn act_as(
    account: Option<&crate::service::Account>,
) -> Result<Option<crate::win_user::FsAs>, RpcError> {
    account
        .map(|a| {
            crate::win_user::FsAs::new(a).map_err(|e| {
                RpcError::new(
                    ErrorCode::Unavailable,
                    format!("cannot act as {}: {e}", a.name),
                )
            })
        })
        .transpose()
}

#[cfg(not(any(target_os = "linux", windows)))]
pub(crate) fn act_as(account: Option<&crate::service::Account>) -> Result<Option<()>, RpcError> {
    match account {
        Some(a) => Err(RpcError::new(
            ErrorCode::Unavailable,
            format!("cannot act as {}: Linux only", a.name),
        )),
        None => Ok(None),
    }
}

/// What the link walk of a call does with a folder it may not list, when it
/// walks as the account `walker` on a node that runs as `node`, and the
/// paths go to a program that runs as `program` (none: the node's own
/// call). A program of another account may list the folder and follow a
/// link in it, so the call is refused. So is root's program unless the node
/// itself is root: a walk with root's file ids (crate::account::FsAs) still
/// has only the node's rights, and cannot list another account's closed
/// folder that root's program can.
fn closed_for(program: Option<u32>, walker: u32, node: u32) -> crate::fs::Closed {
    match program {
        Some(uid) if uid != walker || (uid == 0 && node != 0) => crate::fs::Closed::Refuse,
        _ => crate::fs::Closed::Skip,
    }
}

/// `m` without the sudo password (crate::sudo).
fn scrub(shared: &Shared, m: WsMessage) -> WsMessage {
    match m {
        WsMessage::Text(t) => WsMessage::text(shared.scrub(t.to_string())),
        other => other,
    }
}

fn settings_result(r: Result<u64, SetError>) -> Result<Value, RpcError> {
    match r {
        Ok(v) => Ok(json!({"version": v})),
        Err(SetError::Conflict { current }) => Err(conflict(format!(
            "the settings changed (version {current})"
        ))
        .with("version", json!(current))),
        Err(SetError::Forbidden(f)) => Err(RpcError::forbidden(f)),
        Err(SetError::Invalid(e)) => Err(RpcError::invalid_args(e)),
        Err(SetError::Io(e)) => Err(RpcError::internal(e)),
    }
}

/// Counts a running command and remembers its process group, so a control
/// request from below it is refused and `exec.signal` can find it.
struct Running<'a> {
    link: &'a Link,
    id: Id,
    pid: Mutex<Option<u32>>,
}

impl<'a> Running<'a> {
    fn start(link: &'a Link, id: Id, max: usize) -> Result<Running<'a>, RpcError> {
        let n = link.shared.running.fetch_add(1, Ordering::SeqCst);
        if n >= max {
            link.shared.running.fetch_sub(1, Ordering::SeqCst);
            return Err(RpcError::new(
                ErrorCode::Busy,
                format!("{max} commands are running already"),
            ));
        }
        link.check_status();
        Ok(Running {
            link,
            id,
            pid: Mutex::new(None),
        })
    }

    /// The command's output, for its `output` stream while it runs, unless
    /// it is not `streamed`. The stream is kept free of the sudo password
    /// the node holds while it runs.
    fn tap(&self, streamed: bool) -> Option<Arc<crate::tap::Tap>> {
        let tap = streamed.then(|| {
            let shared = Arc::downgrade(&self.link.shared);
            let secret: crate::tap::Held =
                Arc::new(move || shared.upgrade().and_then(|s| s.held_secret()));
            Arc::new(crate::tap::Tap::new(Some(secret), exec::other_text()))
        });
        lock(&self.link.taps).insert(self.id.clone(), tap.clone());
        tap
    }

    fn started(&self, ender: &exec::Ender) {
        let pid = ender.pid();
        *lock(&self.pid) = Some(pid);
        lock(&self.link.shared.commands).insert(pid, self.link.name.clone());
        lock(&self.link.commands).insert(self.id.clone(), ender.clone());
    }
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        if let Some(pid) = *lock(&self.pid) {
            lock(&self.link.shared.commands).remove(&pid);
        }
        lock(&self.link.commands).remove(&self.id);
        // Its streams end once they sent what it printed.
        if let Some(Some(tap)) = lock(&self.link.taps).remove(&self.id) {
            tap.end();
        }
        self.link.shared.running.fetch_sub(1, Ordering::SeqCst);
        self.link.check_status();
    }
}

/// The audit target of a call to an off action, from its arguments as
/// given: the path an `fs` call names (where it is plain, [`plain_path`])
/// and the command line of `exec.run`, as an allowed call's target names
/// them, else `cap.action`, the target of a call that names neither. An
/// `fs` or `exec.run` call without that argument has none, so the audit's
/// rule buttons make no rule of the action's name.
fn off_target(inv: &Invoke) -> String {
    let arg = |k: &str| {
        inv.args
            .get(k)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    match (inv.cap.as_str(), inv.action.as_str()) {
        ("fs", _) => plain_path(&arg("path")).to_string(),
        ("exec", "run") => arg("command"),
        _ => format!("{}.{}", inv.cap, inv.action),
    }
}

/// `e`, the refusal of a call (a program's, an `fs` call, `exec.run` for
/// its `cwd`), with each of its paths named as the center gave it, not as
/// the node resolved it: `named` holds each as
/// resolved (in its wire form) and as given, and a place below a resolved
/// path is named below the given one. Resolved as the command account,
/// which every pairing's commands share, a path given as a link of another
/// of its processes (`/proc/<n>/cwd`) leads where that process works, which
/// the center must not learn from a refusal. The audit entry names the
/// resolved path; only the owner reads it.
fn as_given(mut e: RpcError, named: &[(String, String)]) -> RpcError {
    // The longest first, so a path is not taken for one it begins with.
    let mut named: Vec<&(String, String)> = named.iter().filter(|(r, g)| r != g).collect();
    named.sort_by_key(|(real, _)| std::cmp::Reverse(real.len()));
    let text = &e.message;
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    'scan: while at < text.len() {
        // A path in a reason starts the text or follows a space, a comma or
        // a parenthesis, and ends it or comes before one of those, a colon
        // or a `/` that goes below it.
        let starts = at == 0 || text[..at].ends_with([' ', '(', ',']);
        if starts {
            for (real, given) in &named {
                if let Some(rest) = text[at..].strip_prefix(real.as_str())
                    && (rest.is_empty() || rest.starts_with([' ', '/', ')', ',', ':', ';']))
                {
                    out.push_str(given);
                    at += real.len();
                    continue 'scan;
                }
            }
        }
        let c = text[at..].chars().next().expect("inside the text");
        out.push(c);
        at += c.len_utf8();
    }
    e.message = out;
    e
}

/// `given`, an `fs` path the node did not resolve, where it is written as a
/// resolved path is (absolute, no `.` or `..` part, no empty one), else
/// nothing. The audit's rule buttons make an `fs` rule of an entry's target
/// and rules meet resolved paths only, so a rule made of `a/../b` would
/// match nothing; an entry with no target gets no buttons.
fn plain_path(given: &str) -> &str {
    let plain = given == "/"
        || given.starts_with('/')
            && given[1..]
                .split('/')
                .all(|part| !matches!(part, "" | "." | ".."))
            && !(cfg!(windows) && given.contains('\\'));
    if plain { given } else { "" }
}

/// The shell a command line runs in, by the shell the machine is set to
/// run commands in (`machine.shell`; none: the default of the platform).
fn shell_of(configured: Option<&str>, command: Option<&str>) -> Shell {
    if !cfg!(windows) && command.is_some_and(|c| nerve_policy::sudo_command(c).is_some()) {
        return Shell::Sh;
    }
    Shell::of_program(&crate::exec::shell_command(configured, "").0)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    /// Dropped when its flag says so.
    struct Held(std::sync::Arc<std::sync::Mutex<Option<std::time::Instant>>>);

    impl Drop for Held {
        fn drop(&mut self) {
            *self.0.lock().unwrap() = Some(std::time::Instant::now());
        }
    }

    /// A slow step of the dial loop (the keyring, a hanging dial) does not
    /// keep the parked link past its grace: it goes when the grace ends, and
    /// the step still finishes.
    #[tokio::test]
    async fn a_slow_step_drops_the_parked_link_when_the_grace_ends() {
        let dropped = std::sync::Arc::new(std::sync::Mutex::new(None));
        let mut slot = Some(Held(dropped.clone()));
        let started = std::time::Instant::now();
        let grace = started + Duration::from_millis(50);
        let step = async {
            tokio::time::sleep(Duration::from_millis(400)).await;
            7
        };
        let halt = std::future::pending();
        assert_eq!(
            super::dropping_at(step, &mut slot, Some(grace), halt).await,
            7
        );
        assert!(slot.is_none());
        let at = dropped.lock().unwrap().expect("dropped");
        assert!(
            at - started < Duration::from_millis(300),
            "{:?}",
            at - started
        );
        // Without a grace nothing goes.
        let mut kept = Some(1);
        let halt = std::future::pending();
        assert_eq!(
            super::dropping_at(async { 2 }, &mut kept, None, halt).await,
            2
        );
        assert_eq!(kept, Some(1));
        // A halt (a lock, a pause) drops it at once, and the step finishes.
        let dropped = std::sync::Arc::new(std::sync::Mutex::new(None));
        let mut slot = Some(Held(dropped.clone()));
        let started = std::time::Instant::now();
        let halt = tokio::time::sleep(Duration::from_millis(50));
        let step = async {
            tokio::time::sleep(Duration::from_millis(400)).await;
            8
        };
        assert_eq!(super::dropping_at(step, &mut slot, None, halt).await, 8);
        assert!(slot.is_none());
        let at = dropped.lock().unwrap().expect("dropped");
        assert!(
            at - started < Duration::from_millis(300),
            "{:?}",
            at - started
        );
    }

    /// A call dropped while the gate waits for the walk of its links (its
    /// deadline passed, or it was cancelled) stops the walk and is written
    /// to the audit log as refused, `cancelled`; one whose walk answered is
    /// left to the gate.
    #[tokio::test]
    async fn a_call_that_ends_while_its_links_are_walked_is_audited() {
        use std::sync::atomic::Ordering;
        type Entry = (String, Option<String>, Option<String>);
        let audited = std::sync::Mutex::new(Vec::<Entry>::new());
        let gate = |answer: bool| {
            let (done, finished) = std::sync::mpsc::channel();
            let (stopped, seen) = std::sync::mpsc::channel();
            let call = super::walk_off(
                move |stop: &std::sync::atomic::AtomicBool| {
                    let started = std::time::Instant::now();
                    while !answer
                        && !stop.load(Ordering::Relaxed)
                        && started.elapsed() < Duration::from_secs(5)
                    {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    let _ = stopped.send(stop.load(Ordering::Relaxed));
                    let _ = done.send(());
                },
                |decision: &str, code: Option<&str>, reason: Option<&str>| {
                    audited.lock().unwrap().push((
                        decision.into(),
                        code.map(Into::into),
                        reason.map(Into::into),
                    ))
                },
            );
            (call, seen, finished)
        };
        let deadline = Duration::from_millis(50);
        let (call, seen, _) = gate(true);
        assert!(matches!(
            tokio::time::timeout(deadline, call).await,
            Ok(Ok(()))
        ));
        assert!(!seen.recv().unwrap());
        assert!(audited.lock().unwrap().is_empty());
        let (call, seen, finished) = gate(false);
        let started = std::time::Instant::now();
        assert!(tokio::time::timeout(deadline, call).await.is_err());
        assert_eq!(
            *audited.lock().unwrap(),
            [(
                "forbidden".to_string(),
                Some("cancelled".to_string()),
                Some(super::ENDED_IN_WALK.to_string())
            )]
        );
        finished.recv().unwrap();
        assert!(seen.recv().unwrap(), "the walk was not told to stop");
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "the walk ran on"
        );
    }

    /// A folder the link walk may not list refuses a call only where its
    /// paths go to a program of another account than the walk's.
    #[test]
    fn a_closed_folder_refuses_a_program_of_another_account_only() {
        use super::closed_for;
        use crate::fs::Closed;
        assert_eq!(closed_for(None, 990, 989), Closed::Skip);
        assert_eq!(closed_for(Some(990), 990, 989), Closed::Skip);
        assert_eq!(closed_for(Some(1000), 989, 989), Closed::Refuse);
        assert_eq!(closed_for(Some(0), 989, 989), Closed::Refuse);
        // Root's program, walked with root's file ids by a node that is not
        // root: the walk lacks root's rights.
        assert_eq!(closed_for(Some(0), 0, 989), Closed::Refuse);
        // A node of root walks with root's rights itself.
        assert_eq!(closed_for(Some(0), 0, 0), Closed::Skip);
    }

    /// A program's refusal names each path as the center gave it, and a
    /// place below it below the given one; a path that only begins like a
    /// resolved one stays as it is.
    #[test]
    fn a_programs_refusal_names_its_paths_as_given() {
        let named = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
            pairs
                .iter()
                .map(|(r, g)| (r.to_string(), g.to_string()))
                .collect()
        };
        let as_given = |why: &str, pairs: &[(&str, &str)]| {
            let e = super::as_given(nerve_proto::RpcError::forbidden(why), &named(pairs));
            assert_eq!(e.kind().as_str(), "forbidden");
            e.message
        };
        let away = [("/home/u/clients/acme", "/proc/7/cwd")];
        assert_eq!(
            as_given("/home/u/clients/acme holds a place that is denied", &away),
            "/proc/7/cwd holds a place that is denied"
        );
        assert_eq!(
            as_given(
                "/home/u/clients/acme/.env is protected (/home/u/clients/acme); not allowed",
                &away
            ),
            "/proc/7/cwd/.env is protected (/proc/7/cwd); not allowed"
        );
        assert_eq!(
            as_given("/home/u/clients/acme2 is outside the folders", &away),
            "/home/u/clients/acme2 is outside the folders"
        );
        assert_eq!(
            as_given(
                "/a/b holds a protected path, /a: no",
                &[("/a", "/x"), ("/a/b", "/y")]
            ),
            "/y holds a protected path, /x: no"
        );
    }

    /// The guard reads a line by the shell that runs it: the configured
    /// one, and for a sudo command off Windows `/bin/sh`, whatever is set.
    #[test]
    fn the_guard_reads_a_line_by_the_shell_that_runs_it() {
        use super::shell_of;
        use nerve_policy::command::Shell;
        assert_eq!(shell_of(None, Some("ls")), Shell::native());
        assert_eq!(shell_of(None, None), Shell::native());
        for (shell, want) in [
            ("/bin/bash", Shell::Sh),
            ("/usr/bin/fish", Shell::Fish),
            ("pwsh", Shell::PowerShell),
            (
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                Shell::PowerShell,
            ),
            ("cmd.exe", Shell::Cmd),
            ("C:\\Windows\\System32\\cmd.exe", Shell::Cmd),
        ] {
            assert_eq!(shell_of(Some(shell), Some("ls")), want, "{shell}");
        }
        // A sudo command runs as root in /bin/sh, off Windows.
        let sudo = shell_of(Some("pwsh"), Some("sudo apt update"));
        assert_eq!(
            sudo,
            if cfg!(windows) {
                Shell::PowerShell
            } else {
                Shell::Sh
            }
        );
    }

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use crate::daemon::{Daemon, NodeOptions};
    use crate::paths::NodePaths;

    /// A node with one center behind a proxy that wants the header `X-Key`,
    /// and listeners standing in for the center and the proxy.
    async fn behind_a_proxy() -> (tempfile::TempDir, NodePaths, TcpListener, TcpListener) {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("config"), d.path().join("state"));
        let center = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut cfg = nerve_policy::NodeConfig::default();
        cfg.centers.push(nerve_policy::CenterEntry {
            name: "home".into(),
            // Only TLS goes through the proxy; the tunnel carries it.
            url: format!("https://127.0.0.1:{}", center.local_addr().unwrap().port()),
            pin: None,
            center_id: "c".into(),
            node_id: "n".into(),
            settings: Default::default(),
            paused: false,
            revoked: false,
            unknown: false,
            public_key: None,
            key_rotations: 0,
            pin_rotations: 0,
            old_pin: None,
            policy: Default::default(),
        });
        cfg.connection.proxy = Some(format!(
            "http://127.0.0.1:{}",
            proxy.local_addr().unwrap().port()
        ));
        cfg.connection.headers = vec!["X-Key".into()];
        cfg.save(&paths.config_file()).unwrap();
        let key = nerve_transport::keys::NodeKey::generate().unwrap();
        let key_file = paths.key_file("home");
        nerve_transport::files::create_private_dir(key_file.parent().unwrap()).unwrap();
        nerve_transport::files::write_private(&key_file, key.to_text().as_bytes()).unwrap();
        (d, paths, center, proxy)
    }

    async fn start(d: &tempfile::TempDir, paths: &NodePaths) -> Daemon {
        let mut opts = NodeOptions::new(paths.clone());
        opts.home = d.path().to_path_buf();
        opts.ctl = false;
        opts.full_rights = Some(false);
        Daemon::start(opts).await.unwrap()
    }

    /// The status of the center once it is no longer `connecting`.
    async fn settled_status(daemon: &Daemon) -> String {
        for _ in 0..200 {
            let s = daemon.status()["centers"][0]["status"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            if !["", "not connected", "connecting"].contains(&s.as_str()) {
                return s;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("the link never settled");
    }

    #[tokio::test]
    async fn a_missing_keyring_entry_stops_the_link_and_names_it() {
        let (d, paths, center, proxy) = behind_a_proxy().await;
        let daemon = start(&d, &paths).await;
        let status = settled_status(&daemon).await;
        let entry = crate::secrets::Entry::proxy(&paths).to_string();
        assert!(status.contains(&entry), "{status}");
        assert!(status.contains("proxy set"), "{status}");
        // Fail closed: neither the proxy nor the center was dialled.
        let quiet = Duration::from_millis(300);
        assert!(tokio::time::timeout(quiet, proxy.accept()).await.is_err());
        assert!(tokio::time::timeout(quiet, center.accept()).await.is_err());
        daemon.stop().await;
    }

    /// The installed node on Windows runs as `nerve`: a value an
    /// administrator's `proxy set` left in the Credential Manager is not
    /// found by the service, so the status says why, and neither the proxy
    /// nor the center is dialled.
    #[tokio::test]
    async fn on_the_installed_node_on_windows_header_values_stop_the_link_and_say_why() {
        let (d, paths, center, proxy) = behind_a_proxy().await;
        let headers = [("X-Key".to_string(), "s3cret-value".to_string())];
        crate::secrets::store_proxy_headers(&paths, &headers).unwrap();
        crate::secrets::for_tests::pretend_windows_service(&paths);
        let daemon = start(&d, &paths).await;
        let status = settled_status(&daemon).await;
        assert!(status.starts_with("bad proxy: "), "{status}");
        assert!(
            status.contains("not to that of nerve")
                && status.contains("`nerve-node proxy set <url>`"),
            "{status}"
        );
        assert!(!status.contains("s3cret"), "{status}");
        let quiet = Duration::from_millis(300);
        assert!(tokio::time::timeout(quiet, proxy.accept()).await.is_err());
        assert!(tokio::time::timeout(quiet, center.accept()).await.is_err());
        daemon.stop().await;
    }

    #[tokio::test]
    async fn the_link_sends_the_values_from_the_keyring_to_the_proxy() {
        let (d, paths, center, proxy) = behind_a_proxy().await;
        let headers = [("X-Key".to_string(), "s3cret-value".to_string())];
        crate::secrets::store_proxy_headers(&paths, &headers).unwrap();
        let daemon = start(&d, &paths).await;
        let (mut s, _) = tokio::time::timeout(Duration::from_secs(10), proxy.accept())
            .await
            .expect("the node dials the proxy")
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let n = s.read(&mut buf).await.unwrap();
        let req = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(req.starts_with("CONNECT 127.0.0.1:"), "{req}");
        assert!(req.contains("\r\nX-Key: s3cret-value\r\n"), "{req}");
        s.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            .await
            .unwrap();
        drop(s);
        let status = settled_status(&daemon).await;
        assert!(
            status.contains("403") && !status.contains("s3cret"),
            "{status}"
        );
        // The refused tunnel is no reason to go direct.
        let quiet = Duration::from_millis(300);
        assert!(tokio::time::timeout(quiet, center.accept()).await.is_err());
        daemon.stop().await;
    }
}
