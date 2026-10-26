//! The center's side of one node link (spec §4): the handshake, the one-link
//! rule, the resume of a dropped link, requests to the node with their
//! pending replies, and the reader that routes the node's results, events and
//! state.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio_tungstenite::WebSocketStream;

use nerve_proto::frame::{Frame, FrameError, Kind};
use nerve_proto::msg::{self, ByeReason, Hello, Limits, Resumed, method};
use nerve_proto::resume::{self, Replay};
use nerve_proto::{ErrorCode, Id, Message, PROTOCOL_VERSION, RpcError};
use nerve_transport::log::Level;
use nerve_transport::net::BoxIo;
use nerve_transport::ws::WsMessage;

use crate::center::Center;
use crate::streams::Ring;

/// Each side has this long for its handshake step (§4.2).
pub const HANDSHAKE_STEP: Duration = Duration::from_secs(15);
/// A held link must answer a ping within this when a second one arrives (§4.3).
pub const DUPLICATE_PING: Duration = Duration::from_secs(3);
/// No frame for this long is a dead link (§4.4).
pub const DEAD_AFTER: Duration = Duration::from_secs(45);
/// How long the center waits for a `describe`, `get` or `settings.set`.
pub const SHORT_CALL: Duration = Duration::from_secs(30);
/// The most of the node's call places (its `limits.calls`, 64 for
/// nerve-node) the agents' calls leave free: the owner's settings changes
/// from the center and a job's `exec.signal` find a place while jobs hold
/// all the others.
pub const CALLS_KEPT: usize = 8;

/// How many of a node's `calls` places the agents' calls leave free: a
/// quarter, at most [`CALLS_KEPT`], so a node with few places still runs
/// most of the agents' calls (64 keeps 8, 8 keeps 2, 4 keeps 1).
pub fn calls_kept(calls: usize) -> usize {
    CALLS_KEPT.min(calls / 4)
}

type Reply = Result<Value, RpcError>;

/// A request's id in `pending` that is not queued yet: dropped with the
/// id still set, it takes the id out again.
struct Unsent<'a> {
    link: &'a Link,
    id: Option<u64>,
}

impl Drop for Unsent<'_> {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            self.link.pending.lock().unwrap().remove(&id);
            self.link.opening.lock().unwrap().remove(&id);
        }
    }
}

enum Out {
    Frame(WsMessage),
    /// Sends `bye {reason}`, closes, and ends the writer.
    Bye(ByeReason),
}

/// One authenticated, welcomed link. A link the node can resume outlives a
/// dropped connection by the grace (§4.9): it is parked, its calls wait, and
/// a connection that resumes it carries it on.
pub struct Link {
    pub node_id: String,
    /// The node key the hello was signed with: its key, or its old one in
    /// the grace of a rotation (§4.10). A resume sets it to the key of the
    /// hello that resumed it.
    auth_key: Mutex<String>,
    /// Whether both sides speak key rotation; a resume sets it again.
    rotate: AtomicBool,
    pub since: Instant,
    pub since_ms: u64,
    pub limits: Limits,
    /// The id the node gave the link, when it can resume it.
    pub resume_id: Option<String>,
    wire: Mutex<Wire>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Reply>>>,
    next_id: AtomicU64,
    closed: AtomicBool,
    /// Woken when the link ends, so its reader stops at once and handles
    /// nothing more the peer sends.
    ended: Notify,
    /// The center ended the link on purpose ([`Link::end`]): its end is no
    /// drop. A link given up otherwise (replaced, its resume over) is one.
    ended_on_purpose: AtomicBool,
    /// When the last frame came, in milliseconds after `since`.
    heard: AtomicU64,
    pong: Notify,
    /// `node` state `status` (online, busy, paused).
    pub status: Mutex<String>,
    /// Sessions that called through this link, for `session.end`.
    pub sessions: Mutex<std::collections::BTreeSet<String>>,
    /// Open streams of the connection now, by the node's `sid`: where their
    /// frames go (crate::streams).
    streams: Mutex<HashMap<u32, Arc<Ring>>>,
    /// `stream.open` requests waiting for their `sid`, by request id: the
    /// answer puts the ring in `streams` before the next frame is read.
    opening: Mutex<HashMap<u64, Arc<Ring>>>,
}

/// The connection a link is on, and what it counts for a resume.
struct Wire {
    /// The writer of the connection now; `None` while parked or ended.
    out: Option<mpsc::Sender<Out>>,
    /// Which connection carries the link: a resume moves it on, and a reader
    /// of an older one stops.
    conn: u64,
    /// The counts and the kept frames, when the node can resume the link.
    replay: Option<Replay>,
    /// The connection dropped and the link waits for its resume.
    parked: bool,
}

impl Link {
    fn new(
        node_id: &str,
        auth_key: String,
        rotate: bool,
        limits: Limits,
        out: mpsc::Sender<Out>,
        resume_id: Option<String>,
    ) -> Link {
        let replay = resume_id.is_some().then(|| Replay::new(resume::KEEP_BYTES));
        Link {
            node_id: node_id.to_string(),
            auth_key: Mutex::new(auth_key),
            rotate: AtomicBool::new(rotate),
            since: Instant::now(),
            since_ms: msg::now_ms(),
            limits,
            resume_id,
            wire: Mutex::new(Wire {
                out: Some(out),
                conn: 0,
                replay,
                parked: false,
            }),
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            closed: AtomicBool::new(false),
            ended: Notify::new(),
            ended_on_purpose: AtomicBool::new(false),
            heard: AtomicU64::new(0),
            pong: Notify::new(),
            status: Mutex::new("online".into()),
            sessions: Mutex::new(Default::default()),
            streams: Mutex::default(),
            opening: Mutex::default(),
        }
    }

    /// A live link for a unit test, whose connection is already gone: it
    /// counts as online, and a call sent on it ends as `connection_lost`, so
    /// a test can tell a call that reached the send from one stopped before.
    #[cfg(test)]
    pub(crate) fn for_test(node_id: &str) -> Link {
        let (out, _) = mpsc::channel(1);
        Link::new(node_id, String::new(), false, Limits::default(), out, None)
    }

    /// The node key the hello of the connection now was signed with.
    pub fn auth_key(&self) -> String {
        self.auth_key.lock().unwrap().clone()
    }

    /// Whether both sides speak key rotation.
    pub fn rotate(&self) -> bool {
        self.rotate.load(Ordering::SeqCst)
    }

    /// Notes that a frame came.
    fn touch(&self) {
        self.heard
            .store(self.since.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    /// How long nothing has come from the node.
    pub fn silent_for(&self) -> Duration {
        self.since
            .elapsed()
            .saturating_sub(Duration::from_millis(self.heard.load(Ordering::Relaxed)))
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Whether the link is on a connection now: neither ended nor parked.
    pub fn is_live(&self) -> bool {
        !self.is_closed() && !self.wire.lock().unwrap().parked
    }

    /// How many calls wait for their reply.
    pub fn waiting(&self) -> usize {
        self.pending.lock().unwrap().len()
    }

    /// Sends a counted text frame, waiting for room in the queue. While the
    /// link is parked the frame is kept for the resume. `false` when it is
    /// lost: the link ended, or its connection did and it cannot resume.
    async fn send_text(&self, text: String) -> bool {
        loop {
            // Kept under the same lock that saw the link parked, so a resume
            // that comes in between sends it.
            let out = {
                let mut w = self.wire.lock().unwrap();
                match w.out.clone() {
                    Some(o) => o,
                    None => return w.keep(&text) && !self.is_closed(),
                }
            };
            let permit = out.reserve().await;
            let mut w = self.wire.lock().unwrap();
            // A resume moved the link to another connection meanwhile.
            if !w.out.as_ref().is_some_and(|o| o.same_channel(&out)) {
                continue;
            }
            return match permit {
                Ok(p) => {
                    if let Some(r) = &mut w.replay {
                        r.push(&text);
                    }
                    p.send(Out::Frame(WsMessage::text(text)));
                    true
                }
                Err(_) => w.keep(&text),
            };
        }
    }

    /// Sends a frame of the connection now only (a ping, a `bye`).
    async fn send_out(&self, o: Out) -> bool {
        let out = self.wire.lock().unwrap().out.clone();
        match out {
            Some(out) => out.send(o).await.is_ok(),
            None => false,
        }
    }

    /// Takes a frame read on connection `conn`, counting it when it is
    /// `counted`. `false` when a resume moved the link to a newer connection:
    /// the frame is not the link's any more.
    fn take_frame(&self, conn: u64, counted: bool) -> bool {
        let mut w = self.wire.lock().unwrap();
        if w.conn != conn {
            return false;
        }
        if counted && let Some(r) = &mut w.replay {
            r.read();
        }
        true
    }

    /// Whether connection `conn` still carries the link.
    pub(crate) fn current(&self, conn: u64) -> bool {
        self.wire.lock().unwrap().conn == conn
    }

    /// The node read the first `got` frames of the link.
    fn acked(&self, got: u64) -> Result<(), String> {
        match &mut self.wire.lock().unwrap().replay {
            Some(r) => r.acked_to(got),
            None => Ok(()),
        }
    }

    /// Sends `ack {got}` when the count moved since the last one.
    fn send_ack(&self) {
        let mut w = self.wire.lock().unwrap();
        let Wire {
            out: Some(out),
            replay: Some(r),
            ..
        } = &mut *w
        else {
            return;
        };
        if let Some(got) = r.ack_due() {
            let m = Message::notification(method::ACK, json!({ "got": got }));
            if out
                .try_send(Out::Frame(WsMessage::text(m.encode())))
                .is_ok()
            {
                r.told(got);
            }
        }
    }

    /// Parks the link after connection `conn` dropped, if the node can
    /// resume it: it still keeps every frame the node may not have read.
    fn park(&self, conn: u64) -> bool {
        let mut w = self.wire.lock().unwrap();
        let can =
            w.conn == conn && !self.is_closed() && w.replay.as_ref().is_some_and(Replay::complete);
        if can {
            w.out = None;
            w.parked = true;
        }
        drop(w);
        // Streams are not counted: they end with their connection (§4.9).
        if can {
            self.end_streams("the link to the node dropped");
        }
        can
    }

    /// Carries the link on on a new connection, the node having read `got`
    /// frames of it. Gives the new connection's number and the frames to
    /// send first; an error when the link cannot resume from there.
    fn resume(&self, out: mpsc::Sender<Out>, got: u64) -> Result<(u64, Vec<String>), String> {
        let mut w = self.wire.lock().unwrap();
        if self.is_closed() {
            return Err("the link ended".into());
        }
        let replay = w.replay.as_mut().ok_or("the link cannot resume")?;
        // The node sends nothing counted before it reads the welcome. A link
        // of which nothing was read may be one whose welcome the node never
        // got: the node then still holds the older link of that id, which
        // this one must not be taken for.
        if replay.got() == 0 {
            return Err("the node never took this link up".into());
        }
        let again = replay.resume(got)?;
        // A request nobody waits for any more (its caller timed out or
        // cancelled) is not delivered late: it goes as `withdrawn`, which
        // keeps the count and which the node ignores.
        let pending = self.pending.lock().unwrap();
        let again = again
            .into_iter()
            .map(|t| match Message::decode(&t) {
                Ok(Message::Request { id: Id::Num(n), .. }) if !pending.contains_key(&n) => {
                    Message::notification(method::WITHDRAWN, json!({ "id": n })).encode()
                }
                _ => t,
            })
            .collect();
        drop(pending);
        w.conn += 1;
        w.out = Some(out);
        w.parked = false;
        let conn = w.conn;
        drop(w);
        // The node ended the old connection's streams with it.
        self.end_streams("the link to the node dropped");
        Ok((conn, again))
    }

    /// Ends the link if it is still parked from connection `conn`: its
    /// grace is over.
    pub(crate) fn expire(&self, conn: u64) -> bool {
        {
            let mut w = self.wire.lock().unwrap();
            if !(w.parked && w.conn == conn && !self.is_closed()) {
                return false;
            }
            self.close(&mut w);
        }
        self.fail_pending();
        true
    }

    /// The count of frames read from the node, for `welcome`.
    fn got(&self) -> u64 {
        self.wire
            .lock()
            .unwrap()
            .replay
            .as_ref()
            .map_or(0, Replay::got)
    }

    /// Sends a request; `wait` bounds the wait for its reply.
    pub async fn call(&self, method: &str, params: Value, wait: Option<Duration>) -> Reply {
        let (id, rx) = self.start(method, params).await?;
        self.finish(id, rx, wait).await
    }

    /// Sends a request and hands back its id and the receiver of its reply.
    pub async fn start(
        &self,
        method: &str,
        params: Value,
    ) -> Result<(u64, oneshot::Receiver<Reply>), RpcError> {
        self.start_within(method, params, usize::MAX).await
    }

    /// [`Link::start`], refused with `busy` when `most` requests wait for
    /// their reply already.
    pub async fn start_within(
        &self,
        method: &str,
        params: Value,
        most: usize,
    ) -> Result<(u64, oneshot::Receiver<Reply>), RpcError> {
        if self.is_closed() {
            return Err(lost());
        }
        let (tx, rx) = oneshot::channel();
        let id = {
            let mut pending = self.pending.lock().unwrap();
            if pending.len() >= most {
                return Err(RpcError::new(ErrorCode::Busy, "too many calls in flight"));
            }
            let id = self.next_id.fetch_add(1, Ordering::SeqCst);
            pending.insert(id, tx);
            id
        };
        // Until the request is queued the caller may be dropped (a stop
        // while the queue is full): then no reply or cancel would ever
        // clear the id, and it would hold a call place for good.
        let mut unsent = Unsent {
            link: self,
            id: Some(id),
        };
        let text = Message::request(id, method, params).encode();
        if !self.send_text(text).await {
            return Err(lost());
        }
        unsent.id = None;
        Ok((id, rx))
    }

    pub async fn finish(
        &self,
        id: u64,
        rx: oneshot::Receiver<Reply>,
        wait: Option<Duration>,
    ) -> Reply {
        let got = match wait {
            None => rx.await,
            Some(w) => match tokio::time::timeout(w, rx).await {
                Ok(r) => r,
                Err(_) => {
                    self.pending.lock().unwrap().remove(&id);
                    self.notify(method::CANCEL, json!({"id": id})).await;
                    return Err(RpcError::new(
                        ErrorCode::Timeout,
                        "the node did not answer in time",
                    ));
                }
            },
        };
        got.unwrap_or_else(|_| Err(lost()))
    }

    /// Stops waiting for request `id` and tells the node to cancel it.
    pub async fn cancel(&self, id: u64) {
        self.pending.lock().unwrap().remove(&id);
        self.notify(method::CANCEL, json!({"id": id})).await;
    }

    pub async fn notify(&self, method: &str, params: Value) {
        let text = Message::notification(method, params).encode();
        self.send_text(text).await;
    }

    /// Ends the connection with `bye {reason}`.
    pub async fn bye(&self, reason: ByeReason) {
        self.send_out(Out::Bye(reason)).await;
    }

    /// Whether the link answers a ping within `wait`.
    async fn answers(&self, wait: Duration) -> bool {
        let notified = self.pong.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if !self
            .send_out(Out::Frame(WsMessage::Ping(b"nerve".to_vec().into())))
            .await
        {
            return false;
        }
        tokio::time::timeout(wait, notified).await.is_ok()
    }

    /// Ends the link with `bye {reason}` without waiting on its queue: the
    /// link is closed first, so no call goes to it any more and its reader
    /// stops, and the bye goes in a task of its own, so a peer that reads
    /// nothing holds up no caller.
    pub(crate) fn end(&self, reason: ByeReason) {
        self.ended_on_purpose.store(true, Ordering::SeqCst);
        let out = {
            let mut w = self.wire.lock().unwrap();
            let out = w.out.clone();
            self.close(&mut w);
            out
        };
        self.fail_pending();
        if let Some(out) = out {
            tokio::spawn(async move {
                let _ = out.send(Out::Bye(reason)).await;
            });
        }
    }

    /// Ends the link: every call waiting on it fails with `connection_lost`.
    pub(crate) fn fail_all(&self) {
        self.close(&mut self.wire.lock().unwrap());
        self.fail_pending();
    }

    /// Marks the link ended, under its wire's lock, so a resume cannot take
    /// it up any more.
    fn close(&self, w: &mut Wire) {
        self.closed.store(true, Ordering::SeqCst);
        // A permit stays for a reader that is not waiting right now.
        self.ended.notify_one();
        w.out = None;
        w.parked = false;
        w.replay = None;
        self.end_streams("the link to the node ended");
    }

    fn fail_pending(&self) {
        let pending: Vec<_> = self.pending.lock().unwrap().drain().collect();
        for (_, tx) in pending {
            let _ = tx.send(Err(lost()));
        }
    }

    fn reply(&self, id: &Id, r: Reply) {
        let Id::Num(n) = id else {
            return;
        };
        // An opened stream is known before its first frame is read, which
        // may follow the answer at once. One lock at a time: `open_stream`
        // takes them the other way round.
        let opened = self.opening.lock().unwrap().remove(n);
        let waited = self.pending.lock().unwrap().contains_key(n);
        if let Some(ring) = opened.filter(|_| waited)
            && let Ok(v) = &r
            && let Some(sid) = v.get("sid").and_then(Value::as_u64)
            && let Ok(sid) = u32::try_from(sid)
        {
            self.streams.lock().unwrap().insert(sid, ring);
        }
        if let Some(tx) = self.pending.lock().unwrap().remove(n) {
            let _ = tx.send(r);
        }
    }

    /// Opens a stream on the node (`stream.open` with `params`) whose
    /// frames go to `ring`: its `sid`.
    pub async fn open_stream(&self, params: Value, ring: Arc<Ring>) -> Result<u32, RpcError> {
        if self.is_closed() {
            return Err(lost());
        }
        let (tx, rx) = oneshot::channel();
        // The ring is in place before the request can be answered.
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.opening.lock().unwrap().insert(id, ring);
        self.pending.lock().unwrap().insert(id, tx);
        let mut unsent = Unsent {
            link: self,
            id: Some(id),
        };
        let text = Message::request(id, method::STREAM_OPEN, params).encode();
        if !self.send_text(text).await {
            return Err(lost());
        }
        unsent.id = None;
        let r = self.finish(id, rx, Some(SHORT_CALL)).await;
        self.opening.lock().unwrap().remove(&id);
        let v = r?;
        v.get("sid")
            .and_then(Value::as_u64)
            .and_then(|s| u32::try_from(s).ok())
            .ok_or_else(|| RpcError::internal("the node answered stream.open without a sid"))
    }

    /// A stream frame from the node: data or a gap for its ring. A frame
    /// of a stream the center does not hold (closed meanwhile) is dropped.
    fn stream_frame(&self, f: &Frame) {
        let ring = self.streams.lock().unwrap().get(&f.id).cloned();
        let Some(ring) = ring else {
            return;
        };
        match f.gap_bytes() {
            Some(n) => ring.gap(n),
            None => ring.push(&f.payload),
        }
    }

    /// The node closed the stream `sid` (its command ended): what it holds
    /// can still be read. Whether the center held it.
    fn stream_closed(&self, sid: u32, reason: &str) -> bool {
        let ring = self.streams.lock().unwrap().remove(&sid);
        match ring {
            Some(ring) => {
                let why = if reason == "ended" {
                    "the command ended".to_string()
                } else {
                    format!(
                        "the node closed it ({})",
                        crate::util::clip(&crate::listing::one_line(reason), 200)
                    )
                };
                ring.end(&why);
                true
            }
            None => false,
        }
    }

    /// Forgets the stream `sid` on the center's side; whether it was still
    /// open.
    pub fn forget_stream(&self, sid: u32) -> bool {
        self.streams.lock().unwrap().remove(&sid).is_some()
    }

    /// Tells the node to stop the stream `sid`.
    pub async fn close_stream(&self, sid: u32, why: &str) {
        let _ = self
            .call(
                method::STREAM_CLOSE,
                json!({"sid": sid, "reason": why}),
                Some(SHORT_CALL),
            )
            .await;
    }

    /// Ends every stream of the connection: it is gone (`why`).
    fn end_streams(&self, why: &str) {
        let rings: Vec<Arc<Ring>> = self
            .streams
            .lock()
            .unwrap()
            .drain()
            .map(|(_, r)| r)
            .collect();
        for r in rings {
            r.end(why);
        }
    }

    /// How many streams the link holds.
    pub fn stream_count(&self) -> usize {
        self.streams.lock().unwrap().len()
    }
}

impl Wire {
    /// Keeps a frame that cannot go out now for the resume; `false` on a
    /// link that cannot resume, where it is lost.
    fn keep(&mut self, text: &str) -> bool {
        match &mut self.replay {
            Some(r) => {
                r.push(text);
                true
            }
            None => false,
        }
    }
}

/// How long a node's error message, and its reason, may be: an error
/// says in a few lines what went wrong.
pub const NODE_ERROR_MAX: usize = 4096;

/// A node's error as the center passes it on. A node may answer only the
/// protocol's codes, so `list_first` and `unknown_node` stay the center's
/// own, and its words are cut and marked as the node's (`data.from`), so
/// the center can say whose they are.
fn from_node(e: RpcError) -> RpcError {
    let code = match e.kind() {
        c if c.is_protocol() => c,
        _ => ErrorCode::Internal,
    };
    let mut data = match e.data {
        Some(Value::Object(m)) => m,
        _ => Default::default(),
    };
    data.insert("code".into(), Value::String(code.as_str().to_string()));
    if let Some(Value::String(r)) = data.get_mut("reason") {
        *r = crate::util::clip(r, NODE_ERROR_MAX);
    }
    data.insert("from".into(), json!("node"));
    RpcError {
        code: code.numeric(),
        message: crate::util::clip(&e.message, NODE_ERROR_MAX),
        data: Some(Value::Object(data)),
    }
}

/// Whether the node wrote this error, not the center.
pub fn by_node(e: &RpcError) -> bool {
    e.data.as_ref().and_then(|d| d.get("from")) == Some(&json!("node"))
}

fn lost() -> RpcError {
    RpcError::new(ErrorCode::ConnectionLost, "the link to the node ended")
}

async fn send_text(ws: &mut WebSocketStream<BoxIo>, m: Message) -> Result<(), String> {
    ws.send(WsMessage::text(m.encode()))
        .await
        .map_err(|e| e.to_string())
}

async fn refuse(mut ws: WebSocketStream<BoxIo>, reason: ByeReason) {
    let bye = Message::notification(method::BYE, json!({ "reason": reason }));
    let _ = send_text(&mut ws, bye).await;
    let _ = ws.close(None).await;
}

/// The next text frame, skipping control frames, within `wait`.
async fn next_text(ws: &mut WebSocketStream<BoxIo>, wait: Duration) -> Option<String> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Ok(Some(Ok(WsMessage::Text(t)))) => return Some(t.to_string()),
            Ok(Some(Ok(WsMessage::Ping(_) | WsMessage::Pong(_)))) => continue,
            _ => return None,
        }
    }
}

/// Runs a link from the upgraded WebSocket until it ends. `node_id` is the
/// `Nerve-Node` header, already known to belong to a paired node.
pub async fn run(center: Center, mut ws: WebSocketStream<BoxIo>, node_id: String) {
    let Some((public_key, old_key)) = center.node_keys(&node_id) else {
        return refuse(ws, ByeReason::Revoked).await;
    };
    let nonce = nerve_transport::keys::random_bytes(32);
    let challenge = Message::notification(
        method::CHALLENGE,
        json!({"nonce": msg::hex(&nonce), "center_id": center.id()}),
    );
    if send_text(&mut ws, challenge).await.is_err() {
        return;
    }
    let hello = match next_text(&mut ws, HANDSHAKE_STEP).await {
        Some(t) => t,
        None => {
            center.note(
                Level::Debug,
                Some(&node_id),
                "the handshake failed: no hello within 15 s",
            );
            return refuse(ws, ByeReason::ProtocolError).await;
        }
    };
    let hello: Hello = match Message::decode(&hello) {
        Ok(Message::Notification { method: m, params }) if m == method::HELLO => {
            match nerve_proto::rpc::params(&params) {
                Ok(h) => h,
                Err(_) => {
                    center.note(
                        Level::Debug,
                        Some(&node_id),
                        "the handshake failed: the hello cannot be read",
                    );
                    return refuse(ws, ByeReason::ProtocolError).await;
                }
            }
        }
        _ => {
            center.note(
                Level::Debug,
                Some(&node_id),
                "the handshake failed: the first message was not a hello",
            );
            return refuse(ws, ByeReason::ProtocolError).await;
        }
    };
    // The node's key, or its old one while the grace of a rotation runs.
    let signed = |k: &str| {
        hello.node_id == node_id
            && nerve_transport::keys::verify_connect(k, &center.id(), &nonce, &hello.auth.sig)
    };
    let now = msg::now_ms();
    let auth_key = if signed(&public_key) {
        public_key
    } else if let Some(old) = old_key.as_ref().filter(|o| signed(&o.public_key)) {
        if now >= old.until_ms {
            center.note(
                Level::Warn,
                Some(&node_id),
                "a link was refused: the hello is signed with the node's old key, whose grace after its rotation has ended",
            );
            return refuse(ws, ByeReason::ProtocolError).await;
        }
        old.public_key.clone()
    } else {
        center.note(
            Level::Warn,
            Some(&node_id),
            "a link failed authentication: the hello is not signed with the key paired for this node",
        );
        return refuse(ws, ByeReason::ProtocolError).await;
    };
    if !hello.versions.iter().any(|v| v == PROTOCOL_VERSION) {
        center.note(
            Level::Warn,
            Some(&node_id),
            format!(
                "the node speaks protocol versions {:?}; this center speaks {PROTOCOL_VERSION}",
                hello.versions
            ),
        );
        return refuse(ws, ByeReason::UnsupportedVersion).await;
    }

    if hello
        .resume
        .as_ref()
        .is_some_and(|r| !resume::valid_link_id(&r.link))
    {
        center.note(
            Level::Debug,
            Some(&node_id),
            "the handshake failed: the hello names a link id that is not 32 hex characters",
        );
        return refuse(ws, ByeReason::ProtocolError).await;
    }

    // One live link per node (§4.3): a held link that still answers means
    // two machines hold this key.
    let before = match center.link(&node_id) {
        Some(held) => {
            if held.answers(DUPLICATE_PING).await {
                center.alert(
                    &node_id,
                    "a second link authenticated while the first was alive: the node's key may have been copied",
                );
                return refuse(ws, ByeReason::Duplicate).await;
            }
            held.bye(ByeReason::Replaced).await;
            center.link_replaced(&held);
            Some(held)
        }
        // A link that dropped and waits for its resume.
        None => center.parked(&node_id),
    };

    // A link the node names, with a count that fits, is carried on (§4.9);
    // any other link the node had ends here.
    let (tx, mut rx) = mpsc::channel::<Out>(nerve_proto::limits::SEND_QUEUE);
    let mut carried = None;
    if let (Some(offer), Some(old)) = (&hello.resume, &before)
        && old.resume_id.as_deref() == Some(offer.link.as_str())
    {
        match old.resume(tx.clone(), offer.got) {
            Ok((conn, again)) => carried = Some((old.clone(), conn, again)),
            Err(e) => center.note(
                Level::Info,
                Some(&node_id),
                format!("the node asked to resume its link, which cannot be: {e}"),
            ),
        }
    }
    if carried.is_none()
        && let Some(old) = &before
        && !old.is_closed()
    {
        let n = old.waiting();
        old.fail_all();
        if n > 0 {
            center.note(
                Level::Info,
                Some(&node_id),
                format!(
                    "the node's new link does not carry on its old one; {} on the old one failed with connection_lost",
                    crate::center::plural(n as u32, "call")
                ),
            );
        }
    }

    // Features go only to a node that named its own (§1.1): an older node
    // refuses a field it does not know in the welcome.
    let features = (!hello.features.is_empty()).then(|| {
        nerve_proto::FEATURES
            .iter()
            .filter(|f| hello.features.iter().any(|h| h == *f))
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
    });
    let rotate = features
        .as_ref()
        .is_some_and(|f| f.iter().any(|f| f == nerve_proto::FEATURE_ROTATE));
    let mut welcome = json!({"version": PROTOCOL_VERSION, "limits": Limits::default()});
    if let Some(f) = features {
        welcome["features"] = json!(f);
    }
    // Only a node that offered a resume hears of one: an older node refuses
    // a welcome with fields it does not know.
    if hello.resume.is_some() {
        let r = match &carried {
            Some((link, _, _)) => Resumed {
                resumed: true,
                got: link.got(),
            },
            None => Resumed {
                resumed: false,
                got: 0,
            },
        };
        welcome["resume"] = serde_json::to_value(r).unwrap_or_default();
    }
    if send_text(&mut ws, Message::notification(method::WELCOME, welcome))
        .await
        .is_err()
    {
        // The node may still come back and resume from what it read.
        if let Some((link, conn, _)) = &carried
            && link.park(*conn)
        {
            center.link_parked(
                link,
                true,
                "the welcome could not be sent",
                Duration::ZERO,
                *conn,
                Duration::ZERO,
            );
        }
        return;
    }

    let resumed = carried.is_some();
    let (link, conn, again) = match carried {
        Some(c) => {
            // The link goes on under the key this hello was signed with.
            *c.0.auth_key.lock().unwrap() = auth_key;
            c.0.rotate.store(rotate, Ordering::SeqCst);
            c
        }
        None => {
            let id = hello.resume.as_ref().map(|r| r.link.clone());
            (
                Arc::new(Link::new(&node_id, auth_key, rotate, hello.limits, tx, id)),
                0,
                Vec::new(),
            )
        }
    };
    let (mut sink, mut stream) = ws.split();
    let writer = tokio::spawn(async move {
        // What the node did not read of the link goes first, in order.
        for t in again {
            if sink.send(WsMessage::text(t)).await.is_err() {
                return;
            }
        }
        while let Some(o) = rx.recv().await {
            match o {
                Out::Frame(f) => {
                    if sink.send(f).await.is_err() {
                        break;
                    }
                }
                Out::Bye(reason) => {
                    let bye = Message::notification(method::BYE, json!({ "reason": reason }));
                    let _ = sink.send(WsMessage::text(bye.encode())).await;
                    let _ = sink.close().await;
                    break;
                }
            }
        }
    });
    center.link_up(link.clone(), &hello, resumed);
    let up = Instant::now();
    // The key this hello was signed with may have stopped counting while the
    // handshake waited (on the held link): checked again now that the link
    // is the node's, which the sweep sees from here on.
    if !center.key_counts(&node_id, &link.auth_key()) {
        center.note(
            Level::Warn,
            Some(&node_id),
            "the link ends at once: the key its hello was signed with no longer counts (its grace ended meanwhile)",
        );
        link.end(ByeReason::Replaced);
    }
    // A node that links while the center's key rotation is told learns of
    // it now.
    if rotate && let Some(notice) = center.rotation_notice() {
        link.notify(method::CENTER_ROTATE, notice).await;
    }

    let mut clean = false;
    // Whether a bye ended the link, from either side: such a link does not
    // wait for a resume.
    let mut said_bye = false;
    let quiet = center.dead_after();
    // What ended the link, set on every way out of the loop, and for how long
    // nothing had come when it did.
    let why: String;
    let mut silent = Duration::ZERO;
    let mut acks = tokio::time::interval(resume::ACK_EVERY);
    let mut deadline = tokio::time::Instant::now() + quiet;
    loop {
        let next = tokio::select! {
            n = tokio::time::timeout_at(deadline, stream.next()) => Some(n),
            _ = acks.tick() => {
                link.send_ack();
                continue;
            }
            _ = link.ended.notified() => None,
        };
        // A link the center ended (its key's grace is over) handles nothing
        // more: frames still in flight from the peer are not the node's any
        // more.
        let Some(next) = next.filter(|_| !link.is_closed()) else {
            said_bye = true;
            // A link the center ended with a bye closed cleanly; one it gave
            // up (replaced while it did not answer) dropped.
            if link.ended_on_purpose.load(Ordering::SeqCst) {
                clean = true;
                why = "the center ended the link".into();
            } else {
                why = "the center gave the link up".into();
            }
            break;
        };
        let frame = match next {
            Err(_) => {
                why = format!(
                    "no frame from the node for {}, not even a ping",
                    crate::util::span(quiet)
                );
                silent = quiet;
                break;
            }
            Ok(None) => {
                why = "the connection closed without a bye".into();
                break;
            }
            // A frame the WebSocket cannot take breaks the next connection
            // too, if the node sends it again: the link ends, not parks.
            Ok(Some(Err(e))) if nerve_transport::ws::broken_frame(&e) => {
                link.bye(ByeReason::ProtocolError).await;
                said_bye = true;
                why = format!("the node sent a frame the center cannot take: {e}");
                break;
            }
            Ok(Some(Err(e))) => {
                why = format!("the connection failed: {e}");
                break;
            }
            Ok(Some(Ok(f))) => f,
        };
        deadline = tokio::time::Instant::now() + quiet;
        let decoded = match &frame {
            WsMessage::Text(t) => Some(Message::decode(t)),
            _ => None,
        };
        let counted = match &decoded {
            Some(Ok(m)) => resume::counted(m),
            Some(Err(_)) => true,
            None => false,
        };
        if !link.take_frame(conn, counted) {
            why = "a newer connection resumed the link".into();
            break;
        }
        link.touch();
        match frame {
            WsMessage::Text(_) => match decoded.expect("a text frame") {
                Ok(Message::Notification { method: m, params })
                    if m == method::ACK && link.resume_id.is_some() =>
                {
                    let r = nerve_proto::rpc::params::<msg::Ack>(&params)
                        .map_err(|e| e.message)
                        .and_then(|a| link.acked(a.got));
                    if let Err(e) = r {
                        link.bye(ByeReason::ProtocolError).await;
                        said_bye = true;
                        why = format!("the node acknowledged frames wrongly: {e}");
                        break;
                    }
                }
                Ok(m) => {
                    if let Some(end) = handle(&center, &link, m).await {
                        clean = true;
                        said_bye = true;
                        why = format!("the node said bye ({})", end.as_str());
                        if end == ByeReason::Unpaired {
                            center.forget(&node_id, "the node unpaired itself (bye unpaired)");
                        }
                        break;
                    }
                }
                Err(reply) => {
                    // A malformed message from a node is answered, not fatal,
                    // so a newer node's mistake does not drop its link.
                    link.send_text(reply.encode()).await;
                }
            },
            WsMessage::Binary(b) => match Frame::decode(&b) {
                // A stream's data (crate::streams); nodes send no blobs to
                // the center.
                Ok(f) if f.kind == Kind::Stream => link.stream_frame(&f),
                Ok(_) => {}
                // Media frames are refused.
                Err(FrameError::MediaReserved) => {
                    link.bye(ByeReason::ProtocolError).await;
                    said_bye = true;
                    why = "the node sent a media frame, which the center does not take".into();
                    break;
                }
                Err(_) => {}
            },
            WsMessage::Pong(_) => link.pong.notify_waiters(),
            WsMessage::Close(_) => {
                clean = true;
                why = "the node closed the connection".into();
                break;
            }
            _ => {}
        }
    }
    drop(writer);
    // A connection that dropped without a bye parks a link the node can
    // resume; its calls wait for the grace.
    if !said_bye && link.park(conn) {
        center.link_parked(&link, clean, &why, silent, conn, up.elapsed());
        return;
    }
    // A newer connection carries the link on: only this one ended.
    if link.current(conn) {
        link.fail_all();
    }
    center.link_down(&link, clean, &why, silent, conn, up.elapsed());
}

/// Handles one message from the node. Returns the bye reason when the node
/// ended the link.
async fn handle(center: &Center, link: &Arc<Link>, m: Message) -> Option<ByeReason> {
    match m {
        Message::Result { id, result } => link.reply(&id, Ok(result)),
        Message::Error {
            id: Some(id),
            error,
        } => link.reply(&id, Err(from_node(error))),
        Message::Error { id: None, error } => {
            center.note(
                Level::Warn,
                Some(&link.node_id),
                format!("the node reported an error: {}", error.message),
            );
        }
        // The node ends a stream whose command ended.
        Message::Request {
            id,
            method: m,
            params,
        } if m == method::STREAM_CLOSE => {
            let sid = params
                .get("sid")
                .and_then(Value::as_u64)
                .and_then(|s| u32::try_from(s).ok());
            let reason = params.get("reason").and_then(Value::as_str).unwrap_or("");
            let reply = match sid {
                Some(sid) if link.stream_closed(sid, reason) => Message::result(id, json!({})),
                _ => Message::error(
                    Some(id),
                    RpcError::new(ErrorCode::UnknownMember, "no such stream"),
                ),
            };
            link.send_text(reply.encode()).await;
        }
        Message::Request { id, method: m, .. } => {
            let e = RpcError::new(
                ErrorCode::Other("method_not_found".into()),
                format!("the center serves no method {m:?}"),
            );
            let mut e = e;
            e.code = -32601;
            link.send_text(Message::error(Some(id), e).encode()).await;
        }
        Message::Notification { method: m, params } => match m.as_str() {
            method::EVENT => {
                if let Ok(ev) = nerve_proto::rpc::params::<msg::Event>(&params) {
                    center.on_event(link, ev);
                }
            }
            method::STATE => {
                if let Ok(st) = nerve_proto::rpc::params::<msg::StateChange>(&params)
                    && st.cap == "node"
                    && let Some(s) = st.changed.get("status").and_then(Value::as_str)
                {
                    *link.status.lock().unwrap() = s.to_string();
                    center.changed(crate::center::Change::Nodes);
                }
            }
            method::KEY_ROTATE if link.rotate() => {
                let (r, dropped) = center.rotate_node_key(link, &params);
                link.notify(method::KEY_ROTATED, json!(r)).await;
                // A rotation in the grace of another ends the older key's
                // grace, and a link opened with it ends too.
                if let Some(key) = dropped {
                    center.end_link_of_key(&link.node_id, &key);
                }
            }
            method::KEY_RETIRE if link.rotate() => {
                let (r, opened_with_it) = center.retire_node_key(link, &params);
                link.notify(method::KEY_RETIRED, json!(r)).await;
                // The key this link was opened with is refused from now on,
                // so the link ends; the node dials again with its key.
                if opened_with_it {
                    link.end(ByeReason::Replaced);
                }
            }
            method::BYE => {
                let reason = nerve_proto::rpc::params::<msg::Bye>(&params)
                    .map(|b| b.reason)
                    .unwrap_or(ByeReason::Shutdown);
                return Some(reason);
            }
            // Progress is not passed on to MCP clients.
            _ => {}
        },
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A quarter of the node's places is kept, at most eight, so a node
    /// with few places still runs most of the agents' calls.
    #[test]
    fn the_kept_places_scale_with_the_nodes_limit() {
        let kept: Vec<_> = [64, 16, 8, 4, 2, 0].map(calls_kept).into();
        assert_eq!(kept, [8, 4, 2, 1, 0, 0]);
        assert_eq!(calls_kept(1000), CALLS_KEPT);
    }

    /// A call dropped while its request waits for room in the send queue
    /// leaves no pending id behind: it would hold one of the node's call
    /// places for the rest of the link's life.
    #[tokio::test]
    async fn a_call_dropped_before_its_request_left_keeps_no_place() {
        let (out, mut rx) = mpsc::channel(1);
        let link = Link::new("n1", String::new(), false, Limits::default(), out, None);
        let (id, _reply) = link.start("invoke", json!({})).await.unwrap();
        assert_eq!((id, link.waiting()), (1, 1));
        // The queue holds that one frame and is full now: the next call
        // waits for room until it is dropped.
        let held =
            tokio::time::timeout(Duration::from_millis(50), link.start("invoke", json!({}))).await;
        assert!(held.is_err(), "the queue had room");
        assert_eq!(link.waiting(), 1);
        assert!(rx.try_recv().is_ok());
    }
}
