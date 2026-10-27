//! The center's core: paired nodes and their links, pairing, sessions, calls
//! to nodes, the audit feed and the statistics. The MCP server, the node listener and the web UI are thin
//! layers over this.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};
use tokio::sync::broadcast;

use nerve_proto::link::{CenterUrl, PairLink, PairRequest, PairResponse};
use nerve_proto::msg::{self, ByeReason, Event, Hello};
use nerve_proto::schema::PathMark;
use nerve_proto::{Descriptor, ErrorCode, Exposure, RpcError};
use nerve_transport::log::{Level, Log, Query, call_line};
use nerve_transport::tls::ServerIdentity;

use crate::audit::AuditFeed;
use crate::catalog;
use crate::checker::blocklist::Rule;
use crate::checker::server::LocalServer;
use crate::checker::{
    self, AllowRule, CallInfo, Checker, CheckerConfig, Decision, Endpoint, Layer, LocalModel,
    ModelSource, NodeSettings, NodeSwitch, Scope,
};
use crate::jobs::{self, Jobs, Stop};
use crate::link::{Link, SHORT_CALL, calls_kept};
use crate::listing;
use crate::pairing::{Codes, Outcome};
use crate::store::{KeyRotation, NodeRecord, OldKey, Store};
use crate::streams::{self, Ring, Streams};
use crate::tools::Route;
use crate::util::{self, now_ms};

pub const IDENTITY_FILE: &str = "tls.pem";
/// The center's new key while a rotation of it is in its grace
/// (docs/dev/spec/protocol.md §4.10); it replaces `tls.pem` at the end.
pub const NEXT_IDENTITY_FILE: &str = "tls.next.pem";
pub use crate::audit::{AUDIT_KEEP, AUDIT_MAX_BYTES};
const ALERTS_KEEP: usize = 50;

/// What changed, for whoever subscribed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Nodes,
    Audit,
    Sessions,
}

/// Everything the center needs to start.
#[derive(Debug, Clone)]
pub struct Options {
    pub state_dir: PathBuf,
    /// The center name; kept from the state file when not given.
    pub name: Option<String>,
    /// The URL nodes reach the center at, put into pairing links.
    pub public_url: String,
    /// The log to write to: the process's (`nerve_transport::log::install`),
    /// else one of the center's own. The center attaches its file to it.
    pub log: Option<Arc<Log>>,
    /// The level from `--log`, which wins over the stored one for this run.
    pub log_level: Option<Level>,
}

#[derive(Clone)]
pub struct Center(Arc<Inner>);

pub struct Inner {
    dir: PathBuf,
    public_url: CenterUrl,
    /// The pin of the key served now, with a TLS public URL.
    pin: Mutex<Option<String>>,
    /// The key served now, and its TLS configuration: a rotation replaces
    /// both at the end of its grace.
    identity: Mutex<Arc<ServerIdentity>>,
    server_config: Mutex<Arc<rustls::ServerConfig>>,
    /// Held while a rotation of the center's key starts or ends.
    rotating: Mutex<()>,
    /// The end of a rotation failed and said so; it says so again once it
    /// worked.
    rotation_failed: AtomicBool,
    /// The stored state. Code that holds it takes no other lock of the
    /// center or of a session, only ones that never take it (a link's
    /// `status` and `wire`, the log's, `saves` and `writing`): everything
    /// else is copied out before it is locked. A lock taken under it that is
    /// also held while the state is taken would deadlock two requests, and
    /// with them every runtime worker (issue #150).
    store: Mutex<Store>,
    dirty: AtomicBool,
    /// The number of the last snapshot of the state taken for its file,
    /// counted under the state's lock, so the numbers follow the changes.
    snapshots: AtomicU64,
    /// The state file's snapshots: the newest one waiting to be written and
    /// the number of the one the file holds.
    saves: Mutex<Saves>,
    /// Held while the state file is written, so writes go one at a time.
    writing: Mutex<()>,
    /// How long each write of the state file waits first, for the test of a
    /// slow disk.
    #[cfg(test)]
    save_delay_ms: AtomicU64,
    /// The writes of the state file, for the test of merged saves.
    #[cfg(test)]
    file_writes: AtomicU64,
    codes: Mutex<Codes>,
    links: Mutex<BTreeMap<String, Arc<Link>>>,
    changes: broadcast::Sender<Change>,
    audit: Mutex<AuditFeed>,
    alerts: Mutex<VecDeque<Value>>,
    sessions: Mutex<BTreeMap<String, Arc<Session>>>,
    log: Arc<Log>,
    /// `--log` was given, so the level in the settings does not hold at the
    /// next start.
    log_level_pinned: bool,
    /// When each node's last link ended, for the wait before the next one.
    down: Mutex<HashMap<String, Instant>>,
    /// Failed pairings, logged now and then (they need no secret to make).
    pair_log: Mutex<Quiet>,
    /// How long a link may be silent, in milliseconds.
    dead_after_ms: AtomicU64,
    /// How long a dropped link waits for its resume, in milliseconds.
    grace_ms: AtomicU64,
    /// How long `execute` waits for a result before the call becomes a job,
    /// in milliseconds (`--call-wait`).
    call_wait_ms: AtomicU64,
    /// How long one `stream.open` waits for its answer, and how long a
    /// job's stream is asked for while its command does not run yet
    /// ([`streams::open_on_node`]).
    stream_waits: Mutex<(Duration, Duration)>,
    /// The action checker (issue #17), rebuilt when its config changes.
    checker: Mutex<Arc<Checker>>,
    /// The local llama-server the checker runs, when the model is on and its
    /// source is local; kept across unrelated rebuilds, keyed by `local_sig`.
    local_model: Mutex<Option<Arc<LocalServer>>>,
    local_sig: Mutex<String>,
    /// The one-click install's progress (llama.cpp and the model download).
    install: checker::install::Shared,
    /// The running install's task and cancel flag, so Remove can end it and
    /// wait for it before it deletes anything.
    install_task: Mutex<Option<InstallTask>>,
    /// Where the install downloads from (a local fake in a test).
    install_from: Mutex<Arc<checker::install::Sources>>,
    /// Set while an install swaps the local model's files or Remove deletes
    /// them, so no config change starts the server from them meanwhile.
    /// `manage_local_model` holds this lock for its whole run.
    files_held: Mutex<bool>,
}

/// The state file's text as it was at one moment, numbered in the order
/// of the changes (see [`Center::update`]).
struct Snapshot {
    n: u64,
    text: std::io::Result<Vec<u8>>,
}

/// The saves of the state file (see [`Center::write_snapshot`]).
#[derive(Default)]
struct Saves {
    /// The newest snapshot not written yet, with its number.
    waiting: Option<(u64, Vec<u8>)>,
    /// The number of the snapshot the file holds.
    written: u64,
    /// Why the last write failed.
    failed: String,
}

/// Runs `f`, which blocks, so that it holds no worker of a multi-thread
/// runtime: the worker's other tasks move to another thread meanwhile.
fn off_the_workers<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}

/// A one-click install running in the background.
struct InstallTask {
    cancel: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

/// While alive, the local model's files are being replaced or deleted and
/// the server stays down; dropping it lets `rebuild_checker` start it again.
struct FilesHeld(Center);

impl Drop for FilesHeld {
    fn drop(&mut self) {
        *self.0.files_held.lock().unwrap() = false;
    }
}

/// A line that may repeat: logged at most once in `QUIET_FOR`, with the count
/// of those left out since.
#[derive(Default)]
struct Quiet {
    last: Option<Instant>,
    skipped: u32,
}

const QUIET_FOR: Duration = Duration::from_secs(10);

impl Quiet {
    /// How many were left out, once `QUIET_FOR` has passed since the last line
    /// without another to carry the count; zero before.
    fn flush(&mut self, now: Instant) -> u32 {
        match self.last {
            Some(t) if now.duration_since(t) >= QUIET_FOR => std::mem::take(&mut self.skipped),
            _ => 0,
        }
    }

    /// Whether to log now, and how many were left out before.
    fn take(&mut self, now: Instant) -> Option<u32> {
        if self.last.is_some_and(|t| now.duration_since(t) < QUIET_FOR) {
            self.skipped += 1;
            return None;
        }
        self.last = Some(now);
        Some(std::mem::take(&mut self.skipped))
    }
}

/// One harness session: an MCP client (stdio, an attached process, or an
/// HTTP session). Its id goes to the nodes as `ctx.session`.
pub struct Session {
    pub id: String,
    pub transport: String,
    pub client: Mutex<String>,
    pub started_ms: u64,
    ended: AtomicBool,
    pub calls: AtomicU64,
    /// Nodes this session called, for `session.end`.
    nodes: Mutex<BTreeSet<String>>,
    /// The session is tainted: a call of it returned outside content (a
    /// successful `read`, `sense` or `execute`). The action checker's model
    /// may be told, and its "only tainted sessions" scope acts on it.
    tainted: AtomicBool,
    /// The units `list` gave this session the details of, with each one's
    /// hash then: `execute` runs only what the model was shown as it is.
    /// Locked on its own: never while the state is held (see
    /// `Inner::store`), so the hashes are copied out of the state first.
    fetched: Mutex<Fetched>,
    /// The session's calls and the jobs they became (crate::jobs). Locked
    /// on its own, like `fetched`.
    pub jobs: Mutex<Jobs>,
    /// The output streams of its jobs (crate::streams). Locked on its own,
    /// never with `jobs`.
    pub streams: Mutex<Streams>,
}

/// The most units a session remembers having been shown; past it the one
/// shown longest ago is forgotten, and the model just lists it again.
pub const FETCHED_MAX: usize = 1024;

/// A session's shown units by (node id, `cap.action`), and the order they
/// were shown in, oldest first.
#[derive(Default)]
struct Fetched {
    hashes: HashMap<(String, String), u64>,
    order: VecDeque<(String, String)>,
}

impl Session {
    /// Notes that `list` gave this session the details of `unit` of the
    /// node `node_id`, whose hash was `hash`.
    pub fn listed(&self, node_id: &str, unit: &str, hash: u64) {
        let key = (node_id.to_string(), unit.to_string());
        let mut f = self.fetched.lock().unwrap();
        if f.hashes.insert(key.clone(), hash).is_some() {
            f.order.retain(|k| *k != key);
        }
        f.order.push_back(key);
        while f.order.len() > FETCHED_MAX {
            if let Some(old) = f.order.pop_front() {
                f.hashes.remove(&old);
            }
        }
    }

    /// The hash `unit` of the node `node_id` had when `list` gave this
    /// session its details; none when it never did (or it was forgotten).
    pub fn listed_hash(&self, node_id: &str, unit: &str) -> Option<u64> {
        let key = (node_id.to_string(), unit.to_string());
        self.fetched.lock().unwrap().hashes.get(&key).copied()
    }

    pub fn ended(&self) -> bool {
        self.ended.load(Ordering::SeqCst)
    }

    /// Whether the session is tainted (an earlier call returned content).
    pub fn tainted(&self) -> bool {
        self.tainted.load(Ordering::SeqCst)
    }

    fn set_tainted(&self) {
        self.tainted.store(true, Ordering::SeqCst);
    }
}

/// How a call of a unit (an `execute`) came out within its wait.
#[derive(Debug)]
pub enum Ran {
    Done(Result<Value, CallError>),
    /// It runs on as the job with this id.
    Job(String),
}

/// A call whose `execute` waits for it; dropped before the call ended or
/// became a job (the harness cancelled its request), it stops the call.
struct Held {
    sess: Arc<Session>,
    id: Option<String>,
}

impl Drop for Held {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            let stop = self.sess.jobs.lock().unwrap().abandon(&id);
            if let Some(stop) = stop {
                let _ = stop.send(Stop::Abandoned);
            }
        }
    }
}

/// Why a call of a unit (an `execute`) did not produce a result.
#[derive(Debug)]
pub enum CallError {
    Rpc(RpcError),
}

impl From<RpcError> for CallError {
    fn from(e: RpcError) -> CallError {
        CallError::Rpc(e)
    }
}

impl std::ops::Deref for Center {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

/// An `invoke` whose reply has not come. Dropped before it comes (the call
/// was stopped: `job.cancel`, the session's end, or the harness cancelled
/// its request before the call became a job), it tells the node to cancel
/// the request, so a command does not run on for nobody.
struct Waiting {
    link: Option<Arc<Link>>,
    id: u64,
}

impl Drop for Waiting {
    fn drop(&mut self) {
        if let Some(link) = self.link.take()
            && let Ok(rt) = tokio::runtime::Handle::try_current()
        {
            let id = self.id;
            rt.spawn(async move { link.cancel(id).await });
        }
    }
}

/// Settles a rotation of the center's key that a stop cut short, at the
/// start: a new key the state file does not know is dropped (the start was
/// cut short; the old key stays), a rotation whose new key is gone is
/// dropped, and one whose new key is in place already is marked finished.
/// Says what it did, when that is news.
fn settle_rotation(dir: &Path, identity: &ServerIdentity, store: &mut Store) -> Option<String> {
    let next_path = dir.join(NEXT_IDENTITY_FILE);
    let next = std::fs::read_to_string(&next_path)
        .ok()
        .and_then(|t| ServerIdentity::from_pem(&t).ok());
    let served = nerve_transport::tls::b64url(&identity.spki());
    let Some(r) = store.key_rotation.as_mut() else {
        let _ = std::fs::remove_file(&next_path);
        return None;
    };
    if r.finished_ms.is_some() {
        let _ = std::fs::remove_file(&next_path);
        return None;
    }
    if served == r.new_spki {
        r.finished_ms = Some(now_ms());
        let _ = std::fs::remove_file(&next_path);
        return None;
    }
    if served != r.old_spki
        || next.is_none_or(|n| nerve_transport::tls::b64url(&n.spki()) != r.new_spki)
    {
        store.key_rotation = None;
        let _ = std::fs::remove_file(&next_path);
        return Some(
            "a rotation of the center's key was dropped: its new key is gone or not the one it told; the center keeps serving its key".into(),
        );
    }
    None
}

/// The name a new center gets when no `--name` is given.
pub const DEFAULT_NAME: &str = "nerve-center";

/// This machine's host name, for defaults.
pub fn host_name() -> String {
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        // SAFETY: the buffer is valid for its length and gethostname writes
        // at most that many bytes.
        let r = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
        if r == 0 {
            let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
            if let Ok(s) = std::str::from_utf8(&buf[..end])
                && !s.is_empty()
            {
                return s.to_string();
            }
        }
    }
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "localhost".into())
}

impl Center {
    /// Opens the state folder, creating the identity and the state file on
    /// the first start.
    pub fn open(opts: Options) -> Result<Center, String> {
        let dir = opts.state_dir.clone();
        nerve_transport::files::create_private_dir(&dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        let public_url = CenterUrl::parse(&opts.public_url)?;
        let id_path = dir.join(IDENTITY_FILE);
        let identity = match std::fs::read_to_string(&id_path) {
            Ok(t) => {
                ServerIdentity::from_pem(&t).map_err(|e| format!("{}: {e}", id_path.display()))?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let names = vec![public_url.host.clone(), host_name()];
                let id = ServerIdentity::generate(&names)?;
                nerve_transport::files::write_private(&id_path, id.to_pem().as_bytes())
                    .map_err(|e| format!("cannot write {}: {e}", id_path.display()))?;
                id
            }
            Err(e) => return Err(format!("cannot read {}: {e}", id_path.display())),
        };
        let mut store = match Store::load(&dir).map_err(|e| e.to_string())? {
            Some(s) => s,
            None => Store::new(util::random_id(), DEFAULT_NAME.into()),
        };
        if let Some(n) = opts.name {
            store.center_name = n;
        }
        let settled = settle_rotation(&dir, &identity, &mut store);
        store.prune_stats(now_ms());
        store
            .save(&dir)
            .map_err(|e| format!("cannot write the state file: {e}"))?;
        let log = opts.log.unwrap_or_else(|| Log::new(Level::default()));
        log.set_level(opts.log_level.unwrap_or(store.log_level));
        // A log that cannot be written is no reason not to run: the window
        // and stderr still work.
        if let Err(e) = log.attach_file(nerve_transport::log::file_in(&dir)) {
            eprintln!(
                "cannot open the log {}: {e}",
                nerve_transport::log::file_in(&dir).display()
            );
        }
        if let Some(why) = settled {
            log.record(Level::Warn, None, &why);
        }
        let pin = public_url.tls.then(|| identity.pin());
        let server_config = identity.server_config()?;
        let (changes, _) = broadcast::channel(64);
        let center = Center(Arc::new(Inner {
            dir,
            public_url,
            pin: Mutex::new(pin),
            identity: Mutex::new(Arc::new(identity)),
            server_config: Mutex::new(server_config),
            rotating: Mutex::new(()),
            rotation_failed: AtomicBool::new(false),
            store: Mutex::new(store),
            dirty: AtomicBool::new(false),
            snapshots: AtomicU64::new(0),
            saves: Mutex::new(Saves::default()),
            writing: Mutex::new(()),
            #[cfg(test)]
            save_delay_ms: AtomicU64::new(0),
            #[cfg(test)]
            file_writes: AtomicU64::new(0),
            codes: Mutex::new(Codes::default()),
            links: Mutex::new(BTreeMap::new()),
            changes,
            audit: Mutex::new(AuditFeed::default()),
            alerts: Mutex::new(VecDeque::new()),
            sessions: Mutex::new(BTreeMap::new()),
            log,
            log_level_pinned: opts.log_level.is_some(),
            down: Mutex::new(HashMap::new()),
            pair_log: Mutex::new(Quiet::default()),
            dead_after_ms: AtomicU64::new(crate::link::DEAD_AFTER.as_millis() as u64),
            grace_ms: AtomicU64::new(nerve_proto::resume::GRACE.as_millis() as u64),
            call_wait_ms: AtomicU64::new(jobs::CALL_WAIT.as_millis() as u64),
            stream_waits: Mutex::new((streams::OPEN_WAIT, streams::START_WAIT)),
            checker: Mutex::new(Arc::new(Checker::build(CheckerConfig::default(), None))),
            local_model: Mutex::new(None),
            local_sig: Mutex::new(String::new()),
            install: Arc::new(Mutex::new(checker::install::Status::default())),
            install_task: Mutex::new(None),
            install_from: Mutex::new(Arc::new(checker::install::Sources::real())),
            files_held: Mutex::new(false),
        }));
        // Build the checker from the stored config and the endpoint token,
        // and start the local model if it is on.
        center.rebuild_checker();
        Ok(center)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The log (docs/user/logs.md): what the web UI shows and the file holds.
    pub fn log(&self) -> &Arc<Log> {
        &self.log
    }

    /// Logs `msg`, about the node `node_id` when one is given. Never called
    /// with the state locked: it reads the node's name from it.
    pub fn note(&self, level: Level, node_id: Option<&str>, msg: impl AsRef<str>) {
        // A node that is gone from the state is named by its id.
        let name = node_id.map(|id| match self.node_name(id) {
            n if n.is_empty() => id.to_string(),
            n => n,
        });
        let who = node_id.zip(name.as_deref()).map(|(id, n)| (n, id));
        self.log.record(level, who, msg.as_ref());
    }

    /// How long a link may send nothing before it is closed (spec §4.4).
    pub fn dead_after(&self) -> Duration {
        Duration::from_millis(self.dead_after_ms.load(Ordering::Relaxed))
    }

    /// Shortens the silence a link may keep, so that a test need not wait
    /// 45 s for the center to give up on a node that went quiet.
    #[doc(hidden)]
    pub fn set_dead_after(&self, d: Duration) {
        self.dead_after_ms
            .store(d.as_millis() as u64, Ordering::Relaxed);
    }

    /// How long a dropped link waits for the node to resume it (spec §4.9).
    pub fn grace(&self) -> Duration {
        Duration::from_millis(self.grace_ms.load(Ordering::Relaxed))
    }

    /// Shortens a `stream.open`'s wait for its answer and the time a job's
    /// stream is asked for while its command does not run yet, so that a
    /// test need not wait 40 s and a minute for the center to give up.
    #[doc(hidden)]
    pub fn set_stream_waits(&self, open: Duration, start: Duration) {
        *self.stream_waits.lock().unwrap() = (open, start);
    }

    /// Shortens the grace, so that a test need not wait 30 s for the calls
    /// of a link that was not resumed to end.
    #[doc(hidden)]
    pub fn set_resume_grace(&self, d: Duration) {
        self.grace_ms.store(d.as_millis() as u64, Ordering::Relaxed);
    }

    /// How long `execute` waits for a result before the call becomes a job
    /// (docs/dev/spec/harness.md §4.4).
    pub fn call_wait(&self) -> Duration {
        Duration::from_millis(self.call_wait_ms.load(Ordering::Relaxed))
    }

    /// Sets the call wait (`--call-wait`).
    pub fn set_call_wait(&self, d: Duration) {
        self.call_wait_ms
            .store(d.as_millis() as u64, Ordering::Relaxed);
    }

    /// Whether the `--log` flag was given, so that the level in the settings
    /// does not hold at the next start.
    pub fn log_level_pinned(&self) -> bool {
        self.log_level_pinned
    }

    /// The level kept for the next start, which `--log` does not change.
    pub fn stored_log_level(&self) -> Level {
        self.read(|s| s.log_level)
    }

    /// Sets the level from now on and keeps it for the next start. With
    /// `--log` the flag holds for this run: only the stored level changes.
    pub fn set_log_level(&self, level: Level) {
        let stored = self.stored_log_level();
        if stored != level {
            self.update(|s| s.log_level = level);
        }
        let old = self.log.level();
        if self.log_level_pinned {
            if stored != level {
                self.log.record(
                    Level::Info,
                    None,
                    &format!("the log level is kept as {level} for the next start; --log holds this run at {old}"),
                );
            }
            return;
        }
        if old == level {
            return;
        }
        // Said at a level that both the old and the new setting keep.
        let wide = old.max(level);
        self.log.set_level(wide);
        self.log.record(
            wide.min(Level::Info),
            None,
            &format!("the log level changes from {old} to {level}"),
        );
        self.log.set_level(level);
    }

    /// What the log view shows: the entries `q` asks for, newest first, the
    /// nodes that can be picked, and the level the log is kept at.
    pub fn log_json(&self, q: &Query) -> Value {
        let entries: Vec<Value> = self
            .log
            .entries(q)
            .into_iter()
            .map(|(seq, e)| {
                let mut v = serde_json::to_value(&e).unwrap_or_default();
                v["seq"] = json!(seq);
                v
            })
            .collect();
        // Every paired node, and those only the log remembers.
        let mut nodes: Vec<Value> = self.read(|s| {
            s.nodes
                .values()
                .map(|n| json!({"id": n.id, "name": n.name, "paired": true}))
                .collect()
        });
        for (id, name) in self.log.nodes() {
            if !nodes.iter().any(|n| n["id"] == id.as_str()) {
                nodes.push(json!({"id": id, "name": name, "paired": false}));
            }
        }
        json!({
            "level": self.log.level(),
            "entries": entries,
            "nodes": nodes,
            "file": self.log.file_path().is_some(),
        })
    }

    pub fn id(&self) -> String {
        self.store.lock().unwrap().center_id.clone()
    }

    pub fn name(&self) -> String {
        self.store.lock().unwrap().center_name.clone()
    }

    pub fn public_url(&self) -> &CenterUrl {
        &self.public_url
    }

    /// The pin of the key served now, with a TLS public URL.
    pub fn pin(&self) -> Option<String> {
        self.pin.lock().unwrap().clone()
    }

    /// The TLS configuration with the key served now, for each new
    /// connection: a rotation that ends changes it for the next one.
    pub fn server_config(&self) -> Arc<rustls::ServerConfig> {
        self.server_config.lock().unwrap().clone()
    }

    fn identity(&self) -> Arc<ServerIdentity> {
        self.identity.lock().unwrap().clone()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Change> {
        self.changes.subscribe()
    }

    pub fn changed(&self, c: Change) {
        let _ = self.changes.send(c);
    }

    /// Runs `f` on the stored state and saves it. The file is written with
    /// the state unlocked, so a slow disk holds up no reader (issue #150);
    /// it holds this change, or a later one, when this returns.
    pub fn update<T>(&self, f: impl FnOnce(&mut Store) -> T) -> T {
        let (out, snap) = {
            let mut s = self.store.lock().unwrap();
            let out = f(&mut s);
            self.dirty.store(false, Ordering::SeqCst);
            (out, self.snapshot(&s))
        };
        if let Err(e) = self.write_snapshot(snap) {
            self.log.record(
                Level::Error,
                None,
                &format!("cannot write the state file: {e}"),
            );
        }
        out
    }

    /// The state file's text for the state `s`, locked by the caller, with
    /// its number among the snapshots.
    fn snapshot(&self, s: &Store) -> Snapshot {
        Snapshot {
            n: self.snapshots.fetch_add(1, Ordering::SeqCst) + 1,
            text: s.file_bytes(),
        }
    }

    /// Returns once the state file holds `snap` or a newer snapshot, which
    /// has every change of this one. Saves that come together are merged:
    /// each write takes the newest snapshot waiting, so a burst of changes
    /// costs about two writes, not one each. The wait is taken off the
    /// runtime's workers, so a slow disk stops no other request (issue
    /// #150).
    fn write_snapshot(&self, snap: Snapshot) -> std::io::Result<()> {
        let text = snap.text?;
        {
            let mut w = self.saves.lock().unwrap();
            if w.written >= snap.n {
                return Ok(());
            }
            if w.waiting.as_ref().is_none_or(|(n, _)| *n < snap.n) {
                w.waiting = Some((snap.n, text));
            }
        }
        off_the_workers(|| {
            let _one = self.writing.lock().unwrap();
            // Only a snapshot at least as new as this one is written here, so
            // Ok always means the file holds this change. When none waits, a
            // write that took this one away has ended, and failed (else it
            // covered it). An older one that waits is left to its own save.
            let (n, text) = {
                let mut w = self.saves.lock().unwrap();
                if w.written >= snap.n {
                    return Ok(());
                }
                match w.waiting.take_if(|(n, _)| *n >= snap.n) {
                    Some(next) => next,
                    None => return Err(std::io::Error::other(w.failed.clone())),
                }
            };
            #[cfg(test)]
            {
                self.file_writes.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(
                    self.save_delay_ms.load(Ordering::SeqCst),
                ));
            }
            let r = Store::write_file(&self.dir, &text);
            let mut w = self.saves.lock().unwrap();
            match &r {
                Ok(()) => w.written = w.written.max(n),
                Err(e) => w.failed = e.to_string(),
            }
            r
        })
    }

    /// Runs `f` on the stored state and saves it, all or nothing: when `f`
    /// fails or the save does, the state stays as it was and the error is
    /// returned. For a change the center may not tell before it is kept.
    fn update_saved<T>(
        &self,
        f: impl FnOnce(&mut Store) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut s = self.store.lock().unwrap();
        let before = s.clone();
        let out = match f(&mut s) {
            Ok(v) => v,
            Err(e) => {
                *s = before;
                return Err(e);
            }
        };
        // Written under the lock: nobody sees the change before it is kept.
        if let Err(e) = self.write_snapshot(self.snapshot(&s)) {
            *s = before;
            return Err(format!("the center cannot write its state file: {e}"));
        }
        self.dirty.store(false, Ordering::SeqCst);
        Ok(out)
    }

    /// Ends the node's link, live or waiting for its resume, when it was
    /// opened with `key`, a key of the node whose grace ended: `bye
    /// replaced`, and no call goes to it any more. The node dials again with
    /// its key.
    ///
    /// It does not wait on the link ([`Link::end`]), so a peer that reads
    /// nothing cannot hold up the caller (the sweep).
    pub(crate) fn end_link_of_key(&self, node_id: &str, key: &str) {
        let link = self
            .links
            .lock()
            .unwrap()
            .get(node_id)
            .filter(|l| !l.is_closed() && l.auth_key() == key)
            .cloned();
        if let Some(l) = link {
            self.note(
                Level::Info,
                Some(node_id),
                "the link opened with the node's old key ends: that key's grace is over",
            );
            l.end(ByeReason::Replaced);
        }
    }

    /// Runs `f` on the stored state and saves it later (statistics).
    fn update_soon(&self, f: impl FnOnce(&mut Store)) {
        f(&mut self.store.lock().unwrap());
        self.dirty.store(true, Ordering::SeqCst);
    }

    pub fn read<T>(&self, f: impl FnOnce(&Store) -> T) -> T {
        f(&self.store.lock().unwrap())
    }

    /// Writes pending statistics. Called on a timer and on shutdown.
    pub fn flush(&self) {
        if self.dirty.swap(false, Ordering::SeqCst) {
            let snap = {
                let mut s = self.store.lock().unwrap();
                s.prune_stats(now_ms());
                self.snapshot(&s)
            };
            if let Err(e) = self.write_snapshot(snap) {
                self.log.record(
                    Level::Error,
                    None,
                    &format!("cannot write the state file: {e}"),
                );
            }
        }
    }

    pub fn public_key(&self, node_id: &str) -> Option<String> {
        self.read(|s| s.nodes.get(node_id).map(|n| n.public_key.clone()))
    }

    pub fn knows(&self, node_id: &str) -> bool {
        self.read(|s| s.nodes.contains_key(node_id))
    }

    /// The node's link while it is up.
    pub fn link(&self, node_id: &str) -> Option<Arc<Link>> {
        self.links
            .lock()
            .unwrap()
            .get(node_id)
            .filter(|l| l.is_live())
            .cloned()
    }

    /// The node's link that dropped and waits for its resume.
    pub(crate) fn parked(&self, node_id: &str) -> Option<Arc<Link>> {
        self.links
            .lock()
            .unwrap()
            .get(node_id)
            .filter(|l| !l.is_closed() && !l.is_live())
            .cloned()
    }

    /// The node's link, up or waiting for its resume.
    fn held(&self, node_id: &str) -> Option<Arc<Link>> {
        self.links
            .lock()
            .unwrap()
            .get(node_id)
            .filter(|l| !l.is_closed())
            .cloned()
    }

    // ---- Pairing (spec §3) ----

    /// A new pairing code and the link that carries it.
    pub fn new_pairing(&self) -> Value {
        let ttl = Duration::from_secs(u64::from(self.read(|st| st.pair_code_minutes)) * 60);
        let code = self.codes.lock().unwrap().create(Instant::now(), ttl);
        // The code is a secret until it is used, so it is not logged.
        self.log.record(
            Level::Info,
            None,
            &format!(
                "a pairing code was made; it is valid for {}",
                util::span(ttl)
            ),
        );
        let pin = self.pin();
        let link = PairLink {
            center: self.public_url.clone(),
            code: code.clone(),
            pin: pin.clone(),
        };
        json!({
            "code": code,
            "link": link.render(),
            "pin": pin,
            "center": self.public_url.to_string(),
            "expires_ms": now_ms() + ttl.as_millis() as u64,
        })
    }

    /// What became of a code from [`Center::new_pairing`], for the web UI:
    /// `open` while it can still pair a machine (a pairing in progress counts,
    /// it may fail), and once a machine used it, that machine as `node`.
    pub fn pairing_status(&self, code: &str) -> Value {
        let outcome = self.codes.lock().unwrap().outcome(code, Instant::now());
        match outcome {
            Outcome::Open => json!({"open": true, "node": null}),
            Outcome::Gone => json!({"open": false, "node": null}),
            Outcome::Paired(id) => {
                let name = self.read(|s| s.nodes.get(&id).map(|n| n.name.clone()));
                json!({"open": false, "node": name.map(|name| json!({"id": id, "name": name}))})
            }
        }
    }

    /// Answers `POST /nerve/v0/pair/check`: whether the code in the body
    /// could pair now, without using it or counting a try
    /// ([`crate::pairing::Codes::probe`]).
    pub fn pair_check(&self, body: &[u8]) -> (u16, Value) {
        let code = serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|v| v["code"].as_str().map(str::to_string))
            .filter(|c| nerve_proto::link::valid_code(c));
        let Some(code) = code else {
            return (
                400,
                json!({ "error": "the body is {\"code\": \"<pairing code>\"}" }),
            );
        };
        let probe = self.codes.lock().unwrap().probe(&code, Instant::now());
        self.log.record(
            Level::Debug,
            None,
            &format!("a node checked a pairing code: {}", probe.word()),
        );
        (200, json!({ "code": probe.word() }))
    }

    /// Answers `POST /nerve/v0/pair`: the status and the body.
    pub fn pair(&self, body: &[u8]) -> (u16, Value) {
        // A request without a code that works costs nothing to make, so a
        // refusal before the code is checked is detail, not news.
        let err = |s: u16, m: &str| {
            self.log.record(
                Level::Debug,
                None,
                &format!("a pairing request was refused ({s}): {m}"),
            );
            (s, json!({ "error": m }))
        };
        let req: PairRequest = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(e) => return err(400, &format!("bad pairing request: {e}")),
        };
        if !nerve_proto::valid_node_name(&req.name) {
            return err(
                400,
                "a node name is 1 to 32 characters of a-z, 0-9 and -, starting and ending with a letter or digit",
            );
        }
        if req.platform.is_empty()
            || req.platform.len() > 32
            || req.arch.is_empty()
            || req.arch.len() > 32
        {
            return err(400, "bad platform or arch");
        }
        let pk = match msg::unhex(&req.public_key) {
            Some(b) if b.len() == 32 => b,
            _ => {
                return err(
                    400,
                    "public_key must be 32 bytes as 64 lowercase hex characters",
                );
            }
        };
        let now = Instant::now();
        // Taken out in the same step as the check: the code is used up from
        // here on, and given back only if this pairing fails.
        let Ok(taken) = self.codes.lock().unwrap().take(&req.code, now) else {
            // Anyone who reaches the port can send these; one line now and
            // then says it happens.
            let quiet = self.pair_log.lock().unwrap().take(now);
            if let Some(more) = quiet {
                let also = if more > 0 {
                    format!(" ({more} more since the last line)")
                } else {
                    String::new()
                };
                self.log.record(
                    Level::Warn,
                    None,
                    &format!(
                        "pairing refused: the code is unknown, used, expired or out of tries{also}"
                    ),
                );
            }
            return (
                403,
                json!({ "error": "the pairing code is unknown, used, expired or out of tries" }),
            );
        };
        let node_id = nerve_transport::keys::node_id(&pk);
        let out = self.update(|s| {
            if s.nodes.contains_key(&node_id) || s.node_by_key(&req.public_key).is_some() {
                return Err("this key is already paired");
            }
            if s.node_by_name(&req.name).is_some() {
                return Err("another node already has this name");
            }
            // `list` and `execute` find a node by its id or its name, so a
            // name is never a node's id: it would point at that node.
            if s.nodes.contains_key(&req.name) || req.name == node_id {
                return Err("this name is a node's id");
            }
            if s.node_by_name(&node_id).is_some() {
                return Err("another node is named like this node's id");
            }
            s.nodes.insert(
                node_id.clone(),
                NodeRecord {
                    id: node_id.clone(),
                    name: req.name.clone(),
                    public_key: req.public_key.clone(),
                    old_key: None,
                    key_rotations: 0,
                    platform: req.platform.clone(),
                    arch: req.arch.clone(),
                    paired_ms: now_ms(),
                    last_seen_ms: 0,
                    going_away: None,
                    descriptor: None,
                    catalog: Default::default(),
                    disabled: false,
                },
            );
            Ok(PairResponse {
                center_id: s.center_id.clone(),
                center_name: s.center_name.clone(),
                node_id: node_id.clone(),
            })
        });
        match out {
            Ok(resp) => {
                self.codes
                    .lock()
                    .unwrap()
                    .done(taken, &node_id, Instant::now());
                self.log.record(
                    Level::Info,
                    Some((&req.name, &node_id)),
                    &format!(
                        "the node paired ({}/{}); its code is used up",
                        req.platform, req.arch
                    ),
                );
                self.changed(Change::Nodes);
                (200, serde_json::to_value(resp).unwrap_or_default())
            }
            Err(why) => {
                self.codes.lock().unwrap().fail(taken);
                self.log.record(
                    Level::Warn,
                    None,
                    &format!("pairing refused for the name {}: {why}", req.name),
                );
                (409, json!({ "error": why }))
            }
        }
    }

    // ---- Key rotation (spec §4.10) ----

    /// Rotates the center's TLS key: a new key is made and kept beside the
    /// old one, which signs it; every node linked now that speaks rotation
    /// is told, and the others when they link. The old key is served until
    /// the grace ends ([`Center::sweep`]) or the owner ends it
    /// ([`Center::finish_key_rotation`]): a node that missed the rotation
    /// can still link and be told. The answer carries the new pin, which
    /// the owner sees once.
    pub async fn rotate_key(&self) -> Result<Value, String> {
        let out = self.start_rotation()?;
        let told = self.tell_rotation().await;
        let mut out = out;
        out["told"] = json!(told);
        Ok(out)
    }

    fn start_rotation(&self) -> Result<Value, String> {
        let _one = self.rotating.lock().unwrap();
        if self.read(|s| {
            s.key_rotation
                .as_ref()
                .is_some_and(|r| r.finished_ms.is_none())
        }) {
            return Err(
                "a rotation of the center's key is in its grace already; end it first".into(),
            );
        }
        let old = self.identity();
        let next = ServerIdentity::generate(&[self.public_url.host.clone(), host_name()])?;
        let new_spki = next.spki();
        let new_pin = nerve_transport::tls::pin_of_spki(&new_spki);
        let new_raw = nerve_transport::tls::decode_pin(&new_pin)?;
        let sig = old.sign(&nerve_proto::rotate_center_message(&self.id(), &new_raw))?;
        let next_path = self.dir.join(NEXT_IDENTITY_FILE);
        nerve_transport::files::write_private(&next_path, next.to_pem().as_bytes()).map_err(
            |e| {
                format!(
                    "cannot write {}: {e}; nothing was changed",
                    next_path.display()
                )
            },
        )?;
        let now = now_ms();
        let until = now + nerve_proto::ROTATE_GRACE_MS;
        let record = KeyRotation {
            started_ms: now,
            until_ms: until,
            old_spki: nerve_transport::tls::b64url(&old.spki()),
            new_spki: nerve_transport::tls::b64url(&new_spki),
            sig: nerve_transport::tls::b64url(&sig),
            finished_ms: None,
        };
        // Saved before anything is told: a rotation the state file does not
        // hold is dropped at the next start, with its key.
        let saved = {
            let mut st = self.store.lock().unwrap();
            let before = st.key_rotation.replace(record);
            st.key_rotations += 1;
            let r = self.write_snapshot(self.snapshot(&st));
            if r.is_err() {
                st.key_rotation = before;
                st.key_rotations -= 1;
            }
            r
        };
        if let Err(e) = saved {
            let _ = std::fs::remove_file(&next_path);
            return Err(format!(
                "cannot write the state file: {e}; nothing was changed"
            ));
        }
        let old_pin = old.pin();
        self.log.record(
            Level::Info,
            None,
            &format!(
                "the owner rotated the center's key: the new pin is {new_pin} (it was {old_pin}). Nodes are told; the old key is served for {} more, or until the owner ends that",
                util::span(Duration::from_millis(nerve_proto::ROTATE_GRACE_MS))
            ),
        );
        self.changed(Change::Nodes);
        Ok(json!({"pin": new_pin, "old_pin": old_pin, "until_ms": until}))
    }

    /// Ends the grace of the center's key rotation: the new key is served
    /// from now on, for every connection made from here. Links up now go
    /// on, and are told; a node that was not told cannot link any more and
    /// has to pair again. `why` goes to the log.
    pub async fn finish_key_rotation(&self, why: &str) -> Result<Value, String> {
        let out = self.end_rotation(why)?;
        self.tell_rotation().await;
        Ok(out)
    }

    fn end_rotation(&self, why: &str) -> Result<Value, String> {
        let _one = self.rotating.lock().unwrap();
        let Some(r) = self
            .read(|s| s.key_rotation.clone())
            .filter(|r| r.finished_ms.is_none())
        else {
            return Err("no rotation of the center's key is in its grace".into());
        };
        let next_path = self.dir.join(NEXT_IDENTITY_FILE);
        let next = std::fs::read_to_string(&next_path)
            .map_err(|e| e.to_string())
            .and_then(|t| ServerIdentity::from_pem(&t))
            .map_err(|e| {
                format!(
                    "cannot read the new key {}: {e}; the old key stays",
                    next_path.display()
                )
            })?;
        if nerve_transport::tls::b64url(&next.spki()) != r.new_spki {
            return Err(format!(
                "{} is not the key the rotation told the nodes; the old key stays",
                next_path.display()
            ));
        }
        let config = next.server_config()?;
        // The new key takes the old one's place; the old key is gone with
        // the file it was in.
        std::fs::rename(&next_path, self.dir.join(IDENTITY_FILE))
            .map_err(|e| format!("cannot put the new key in place: {e}; the old key stays"))?;
        let pin = next.pin();
        *self.server_config.lock().unwrap() = config;
        if self.public_url.tls {
            *self.pin.lock().unwrap() = Some(pin.clone());
        }
        *self.identity.lock().unwrap() = Arc::new(next);
        let now = now_ms();
        self.update(|s| {
            if let Some(r) = s.key_rotation.as_mut() {
                r.finished_ms = Some(now);
            }
        });
        self.log.record(
            Level::Info,
            None,
            &format!("the center serves its new key now ({why}); its pin is {pin}"),
        );
        self.changed(Change::Nodes);
        Ok(json!({"pin": pin}))
    }

    /// What `center.rotate` tells a node now: the last rotation, until no
    /// node can hold the old pin any more; the grace left, 0 once the new
    /// key is served.
    pub fn rotation_notice(&self) -> Option<Value> {
        let r = self.read(|s| s.key_rotation.clone())?;
        let now = now_ms();
        if now >= r.started_ms + nerve_proto::ROTATE_GRACE_MS && r.finished_ms.is_some() {
            return None;
        }
        let grace_ms = match r.finished_ms {
            Some(_) => 0,
            None => r.until_ms.saturating_sub(now),
        };
        serde_json::to_value(msg::CenterRotate {
            old_spki: r.old_spki,
            new_spki: r.new_spki,
            sig: r.sig,
            grace_ms,
        })
        .ok()
    }

    /// Tells every live link that speaks rotation; how many it told. Each
    /// is told in a task of its own: a link whose peer reads nothing cannot
    /// hold up the owner's request or the sweep.
    async fn tell_rotation(&self) -> usize {
        let Some(notice) = self.rotation_notice() else {
            return 0;
        };
        let links: Vec<Arc<Link>> = self
            .links
            .lock()
            .unwrap()
            .values()
            .filter(|l| l.rotate() && !l.is_closed())
            .cloned()
            .collect();
        for l in &links {
            let (l, notice) = (l.clone(), notice.clone());
            tokio::spawn(async move { l.notify(msg::method::CENTER_ROTATE, notice).await });
        }
        links.len()
    }

    /// The state of the center's key for the web UI: its pin, and a
    /// rotation in its grace. The new pin is not in it: the owner saw it
    /// once, when the rotation was made, and the nodes get it signed.
    pub fn key_json(&self) -> Value {
        let r = self.read(|s| s.key_rotation.clone());
        json!({
            "pin": self.identity().pin(),
            "grace_until_ms": r.filter(|r| r.finished_ms.is_none()).map(|r| r.until_ms),
        })
    }

    /// Takes a node's new key (`key.rotate` on `link`): signed by the key
    /// it replaces and by itself. The old key is taken until the grace
    /// ends; a rotation in the grace of another drops that older key, which
    /// it also gives back so that a link opened with it ends. The new key is
    /// saved before it is told as taken: the node deletes its old key then.
    pub(crate) fn rotate_node_key(
        &self,
        link: &Link,
        p: &Map<String, Value>,
    ) -> (msg::KeyRotated, Option<String>) {
        let r: msg::KeyRotate = match nerve_proto::rpc::params(p) {
            Ok(r) => r,
            Err(e) => {
                return (
                    self.key_refused(
                        link,
                        String::new(),
                        format!("bad key.rotate: {}", e.message),
                    ),
                    None,
                );
            }
        };
        let new = r.public_key.clone();
        let Some(raw) = msg::unhex(&new).filter(|b| b.len() == 32) else {
            return (
                self.key_refused(
                    link,
                    new,
                    "public_key must be 32 bytes as 64 lowercase hex characters".into(),
                ),
                None,
            );
        };
        let message = nerve_proto::rotate_node_message(&self.id(), &raw);
        let verify = nerve_transport::keys::verify_node_signature;
        if !verify(&new, &message, &r.proof) {
            return (
                self.key_refused(link, new, "the new key did not sign the rotation".into()),
                None,
            );
        }
        let now = now_ms();
        // Sent again for the key the center took already (no answer reached
        // the node): taken, without a write, which could fail and have the
        // node drop the key the center holds. It was saved when it was taken.
        let held = self.read(|s| {
            s.nodes
                .get(&link.node_id)
                .is_some_and(|n| n.public_key == new)
        });
        let out = if held {
            Ok(None)
        } else {
            self.update_saved(|s| {
                if s.node_by_key(&new).is_some_and(|n| n.id != link.node_id) {
                    return Err("another node holds this key".to_string());
                }
                let n = s
                    .nodes
                    .get_mut(&link.node_id)
                    .ok_or("the node is no longer paired")?;
                if n.public_key == new {
                    return Ok(None);
                }
                if !verify(&n.public_key, &message, &r.sig) {
                    return Err("the rotation is not signed by the node's current key".to_string());
                }
                n.key_rotations += 1;
                let old = std::mem::replace(&mut n.public_key, new.clone());
                let dropped = n.old_key.replace(OldKey {
                    public_key: old.clone(),
                    until_ms: now + nerve_proto::ROTATE_GRACE_MS,
                });
                Ok(Some((old, dropped.map(|d| d.public_key))))
            })
        };
        match out {
            Err(why) => (self.key_refused(link, new, why), None),
            Ok(None) => {
                self.note(
                    Level::Debug,
                    Some(&link.node_id),
                    "the node sent its key rotation again; the center has its new key already",
                );
                (
                    msg::KeyRotated {
                        public_key: new,
                        error: None,
                    },
                    None,
                )
            }
            Ok(Some((old, dropped))) => {
                self.note(
                    Level::Info,
                    Some(&link.node_id),
                    format!(
                        "the node rotated its key: its new key is {new} (it was {old}); the old one is taken for {} more, or until the node ends that",
                        util::span(Duration::from_millis(nerve_proto::ROTATE_GRACE_MS))
                    ),
                );
                self.changed(Change::Nodes);
                (
                    msg::KeyRotated {
                        public_key: new,
                        error: None,
                    },
                    dropped,
                )
            }
        }
    }

    fn key_refused(&self, link: &Link, public_key: String, why: String) -> msg::KeyRotated {
        self.note(
            Level::Warn,
            Some(&link.node_id),
            format!("the node's key rotation was refused, its key stays: {why}"),
        );
        msg::KeyRotated {
            public_key,
            error: Some(why),
        }
    }

    /// Ends the grace of a node's old key (`key.retire` on `link`), signed
    /// by its current key. Also says whether `link` was opened with that old
    /// key: it ends with it.
    pub(crate) fn retire_node_key(
        &self,
        link: &Link,
        p: &Map<String, Value>,
    ) -> (msg::KeyRetired, bool) {
        let refused = |why: String| {
            self.note(
                Level::Warn,
                Some(&link.node_id),
                format!("the node's request to end the grace of its old key was refused: {why}"),
            );
            (msg::KeyRetired { error: Some(why) }, false)
        };
        let r: msg::KeyRetire = match nerve_proto::rpc::params(p) {
            Ok(r) => r,
            Err(e) => return refused(format!("bad key.retire: {}", e.message)),
        };
        let Some(raw) = msg::unhex(&r.public_key).filter(|b| b.len() == 32) else {
            return refused("public_key must be 32 bytes as 64 lowercase hex characters".into());
        };
        let message = nerve_proto::retire_node_message(&self.id(), &raw);
        let out = self.update_saved(|s| {
            let n = s
                .nodes
                .get_mut(&link.node_id)
                .ok_or("the node is no longer paired")?;
            if n.public_key != r.public_key
                || !nerve_transport::keys::verify_node_signature(&n.public_key, &message, &r.sig)
            {
                return Err("it is not signed by the node's current key".to_string());
            }
            Ok(n.old_key.take())
        });
        match out {
            Err(why) => refused(why),
            Ok(old) => {
                let opened_with_it = old
                    .as_ref()
                    .is_some_and(|o| o.public_key == link.auth_key());
                if let Some(o) = &old {
                    self.note(
                        Level::Info,
                        Some(&link.node_id),
                        format!(
                            "the node ended the grace of its old key {}; only its key {} is taken from now on",
                            o.public_key, r.public_key
                        ),
                    );
                    self.changed(Change::Nodes);
                }
                (msg::KeyRetired { error: None }, opened_with_it)
            }
        }
    }

    /// The keys a node's hello may be signed with now: its key, and its old
    /// one while the grace runs. `None` for a node that is not paired.
    pub(crate) fn node_keys(&self, node_id: &str) -> Option<(String, Option<OldKey>)> {
        self.read(|s| {
            s.nodes
                .get(node_id)
                .map(|n| (n.public_key.clone(), n.old_key.clone()))
        })
    }

    /// Ends what ran out: the grace of the center's rotation (the new key is
    /// served), the notices of a finished one, and nodes' old keys.
    pub async fn sweep(&self) {
        let now = now_ms();
        let due = self.read(|s| {
            s.key_rotation
                .as_ref()
                .is_some_and(|r| r.finished_ms.is_none() && now >= r.until_ms)
        });
        if due {
            match self.finish_key_rotation("its grace ended").await {
                Ok(_) => self.rotation_failed.store(false, Ordering::SeqCst),
                Err(e) => {
                    if !self.rotation_failed.swap(true, Ordering::SeqCst) {
                        self.log.record(
                            Level::Error,
                            None,
                            &format!("the grace of the center's key rotation ended, but the new key cannot be served: {e}"),
                        );
                    }
                }
            }
        }
        let expired: Vec<(String, String)> = self.read(|s| {
            s.nodes
                .values()
                .filter_map(|n| {
                    n.old_key
                        .as_ref()
                        .filter(|o| now >= o.until_ms)
                        .map(|o| (n.id.clone(), o.public_key.clone()))
                })
                .collect()
        });
        let stale = self.read(|s| {
            s.key_rotation.as_ref().is_some_and(|r| {
                r.finished_ms.is_some() && now >= r.started_ms + nerve_proto::ROTATE_GRACE_MS
            }) || s
                .nodes
                .values()
                .any(|n| n.old_key.as_ref().is_some_and(|o| now >= o.until_ms))
        });
        if stale {
            self.update(|s| {
                if s.key_rotation.as_ref().is_some_and(|r| {
                    r.finished_ms.is_some() && now >= r.started_ms + nerve_proto::ROTATE_GRACE_MS
                }) {
                    s.key_rotation = None;
                }
                for n in s.nodes.values_mut() {
                    if n.old_key.as_ref().is_some_and(|o| now >= o.until_ms) {
                        n.old_key = None;
                    }
                }
            });
        }
        // A link the old key opened during its grace ends with the grace.
        for (node_id, key) in expired {
            self.end_link_of_key(&node_id, &key);
        }
        // And whatever way a key stopped counting (the grace ended, the node
        // ended it, a newer rotation dropped it, or a link came up just
        // after), a link opened with it ends at the next sweep.
        let links: Vec<Arc<Link>> = self
            .links
            .lock()
            .unwrap()
            .values()
            .filter(|l| !l.is_closed())
            .cloned()
            .collect();
        for l in links {
            if !self.key_counts(&l.node_id, &l.auth_key()) {
                self.note(
                    Level::Info,
                    Some(&l.node_id),
                    "the link opened with the node's old key ends: that key no longer counts",
                );
                l.end(ByeReason::Replaced);
            }
        }
    }

    /// Whether a hello signed with `key` may hold a link of `node_id` now:
    /// the node's key, or its old one while the grace runs. A node that is
    /// not paired any more is left to its own end.
    pub(crate) fn key_counts(&self, node_id: &str, key: &str) -> bool {
        let now = now_ms();
        self.read(|s| match s.nodes.get(node_id) {
            None => true,
            Some(n) => {
                n.public_key == key
                    || n.old_key
                        .as_ref()
                        .is_some_and(|o| o.public_key == key && now < o.until_ms)
            }
        })
    }

    // ---- Nodes ----

    pub fn rename(&self, node_id: &str, name: &str) -> Result<(), String> {
        if !nerve_proto::valid_node_name(name) {
            return Err("a node name is 1 to 32 characters of a-z, 0-9 and -, starting and ending with a letter or digit".into());
        }
        let old = self.update(|s| {
            if s.nodes.values().any(|n| n.name == name && n.id != node_id) {
                return Err("another node already has this name".to_string());
            }
            // As at pairing: a node's id as a name would point at that node.
            if s.nodes.contains_key(name) {
                return Err("this name is a node's id".to_string());
            }
            let n = s.nodes.get_mut(node_id).ok_or("no such node")?;
            Ok(std::mem::replace(&mut n.name, name.to_string()))
        })?;
        self.note(
            Level::Info,
            Some(node_id),
            format!("the node was renamed from {old}"),
        );
        self.changed(Change::Nodes);
        Ok(())
    }

    /// Switches a node off or on for the agent. The link stays as it is;
    /// `list` and the call path look at the flag, and the calls that run on
    /// the node (jobs too) are stopped: the owner who disables a machine
    /// wants the agent's work there to end, not to run on unseen.
    pub fn set_disabled(&self, node_id: &str, disabled: bool) -> Result<(), String> {
        self.update(|s| {
            s.nodes.get_mut(node_id).ok_or("no such node")?.disabled = disabled;
            Ok::<(), String>(())
        })?;
        if disabled {
            let sessions: Vec<Arc<Session>> =
                self.sessions.lock().unwrap().values().cloned().collect();
            for sess in sessions {
                let stops = sess.jobs.lock().unwrap().stop_on(node_id);
                for stop in stops {
                    let _ = stop.send(Stop::Disabled);
                }
            }
        }
        self.note(
            Level::Info,
            Some(node_id),
            if disabled {
                "the node was disabled: the agent is offered none of its capabilities and calls to it are refused"
            } else {
                "the node was enabled"
            },
        );
        self.changed(Change::Nodes);
        Ok(())
    }

    /// Removes a node: `bye revoked` on its link, and its record goes.
    pub async fn remove(&self, node_id: &str) -> Result<(), String> {
        if !self.knows(node_id) {
            return Err("no such node".into());
        }
        let link = self.links.lock().unwrap().remove(node_id);
        if let Some(l) = link {
            l.bye(ByeReason::Revoked).await;
            // A parked link has no connection for the bye; its calls end.
            l.fail_all();
        }
        self.forget(node_id, "removed by the owner; its link got bye revoked");
        Ok(())
    }

    /// Drops a node's record (a remove, or the node's `bye unpaired`); `why`
    /// goes to the log.
    pub fn forget(&self, node_id: &str, why: &str) {
        let name = self.node_name(node_id);
        let had = self.update(|s| {
            s.stats.remove(node_id);
            s.nodes.remove(node_id).is_some()
        });
        if had {
            self.down.lock().unwrap().remove(node_id);
            self.log.record(
                Level::Info,
                Some((&name, node_id)),
                &format!("the node is no longer paired: {why}"),
            );
            self.changed(Change::Nodes);
        }
    }

    pub fn alert(&self, node_id: &str, text: &str) {
        self.note(Level::Warn, Some(node_id), text);
        let mut a = self.alerts.lock().unwrap();
        a.push_back(json!({"ts": now_ms(), "node": node_id, "text": text}));
        while a.len() > ALERTS_KEEP {
            a.pop_front();
        }
        drop(a);
        self.changed(Change::Nodes);
    }

    pub fn alerts(&self) -> Vec<Value> {
        self.alerts.lock().unwrap().iter().cloned().collect()
    }

    /// A link is up; `resumed` when it carries on a link that dropped.
    pub(crate) fn link_up(&self, link: Arc<Link>, hello: &Hello, resumed: bool) {
        let id = link.node_id.clone();
        self.links.lock().unwrap().insert(id.clone(), link.clone());
        let now = now_ms();
        self.update(|s| {
            if let Some(n) = s.nodes.get_mut(&id) {
                n.last_seen_ms = now;
                n.going_away = None;
            }
            if !resumed {
                s.day(&id, now).links += 1;
            }
        });
        let gap = self
            .down
            .lock()
            .unwrap()
            .remove(&id)
            .map(|t| util::span(t.elapsed()));
        let line = match (resumed, gap) {
            (true, gap) => format!(
                "link resumed{} with {} waiting on it (node software {})",
                gap.map(|g| format!(" after {g}")).unwrap_or_default(),
                plural(link.waiting() as u32, "call"),
                hello.software.version
            ),
            (false, Some(g)) => format!(
                "link up again after {g} (node software {})",
                hello.software.version
            ),
            (false, None) => format!("link up (node software {})", hello.software.version),
        };
        self.note(Level::Info, Some(&id), line);
        self.changed(Change::Nodes);
        let c = self.clone();
        tokio::spawn(async move {
            c.refresh(&link).await;
            if c.read(|s| {
                s.nodes
                    .get(&link.node_id)
                    .and_then(|n| n.descriptor.as_ref())
                    .is_some_and(|d| d.capability("audit").is_some())
            }) {
                let _ = link
                    .call(
                        msg::method::SUB,
                        json!({"topics": ["audit/decision"]}),
                        Some(SHORT_CALL),
                    )
                    .await;
            }
        });
    }

    /// The node's old link is given up because the node connected again and
    /// the old one did not answer a ping: told as the drop it is, with how long
    /// it had been silent, which the wait before the new link counts from. The
    /// old link stops being the node's here, so its own end, whenever it
    /// comes, is detail. A link that ended while the ping was waited for has
    /// told its drop already, and says nothing more.
    pub(crate) fn link_replaced(&self, old: &Arc<Link>) {
        {
            let mut links = self.links.lock().unwrap();
            let current = links.get(&old.node_id).is_some_and(|l| Arc::ptr_eq(l, old));
            if !current {
                return;
            }
            links.remove(&old.node_id);
        }
        let silent = old.silent_for();
        let gone = Instant::now()
            .checked_sub(silent)
            .unwrap_or_else(Instant::now);
        self.down.lock().unwrap().insert(old.node_id.clone(), gone);
        self.note(
            Level::Warn,
            Some(&old.node_id),
            format!(
                "link dropped: the node connected again and this link did not answer a ping, so it was replaced (it was up for {}, silent for {})",
                util::span(old.since.elapsed()),
                util::span(silent)
            ),
        );
    }

    /// The connection of a link the node can resume dropped (spec §4.9): the
    /// node is offline, and the calls on the link wait for the grace. After
    /// it, a link still parked from connection `conn` ends like any other.
    /// `up` is how long that connection was up.
    pub(crate) fn link_parked(
        &self,
        link: &Arc<Link>,
        clean: bool,
        why: &str,
        silent: Duration,
        conn: u64,
        up: Duration,
    ) {
        let id = link.node_id.clone();
        {
            // A link replaced by the connection that then failed to resume
            // it is the node's again, so that the next one finds it.
            let mut links = self.links.lock().unwrap();
            let other = links
                .get(&id)
                .is_some_and(|l| !l.is_closed() && !Arc::ptr_eq(l, link));
            if !other {
                links.insert(id.clone(), link.clone());
            }
        }
        let now = now_ms();
        let online = up.as_millis() as u64;
        self.update_soon(|s| {
            if let Some(n) = s.nodes.get_mut(&id) {
                n.last_seen_ms = now;
            }
            if s.nodes.contains_key(&id) {
                let d = s.day(&id, now);
                d.online_ms += online;
                if !clean {
                    d.drops += 1;
                }
            }
        });
        let gone = Instant::now()
            .checked_sub(silent)
            .unwrap_or_else(Instant::now);
        self.down.lock().unwrap().entry(id.clone()).or_insert(gone);
        let grace = self.grace();
        self.note(
            Level::Warn,
            Some(&id),
            format!(
                "link dropped: {why} (it was up for {}); keeping it for {} for the node to resume, with {} waiting",
                util::span(up),
                util::span(grace),
                plural(link.waiting() as u32, "call")
            ),
        );
        self.changed(Change::Nodes);
        let (c, link) = (self.clone(), link.clone());
        tokio::spawn(async move {
            tokio::time::sleep(grace).await;
            let n = link.waiting();
            if !link.expire(conn) {
                return;
            }
            {
                let mut links = c.links.lock().unwrap();
                if links.get(&id).is_some_and(|l| Arc::ptr_eq(l, &link)) {
                    links.remove(&id);
                }
            }
            c.note(
                Level::Warn,
                Some(&id),
                format!(
                    "the node did not resume its link within {}; {} on it failed with connection_lost",
                    util::span(grace),
                    plural(n as u32, "call")
                ),
            );
            c.changed(Change::Nodes);
        });
    }

    /// A link's connection `conn` ended, after it was up for `up`. `clean`
    /// is whether the node said bye; `why` is what ended it, for the log.
    /// `silent` is how long nothing had come from the node, which the wait
    /// before its next link counts from.
    pub(crate) fn link_down(
        &self,
        link: &Arc<Link>,
        clean: bool,
        why: &str,
        silent: Duration,
        conn: u64,
        up: Duration,
    ) {
        let id = &link.node_id;
        let now = now_ms();
        let online = up.as_millis() as u64;
        // A newer connection resumed the link: the node is up on it. This
        // one's time and its drop still count.
        if !link.current(conn) {
            self.update_soon(|s| {
                if s.nodes.contains_key(id) {
                    let d = s.day(id, now);
                    d.online_ms += online;
                    d.drops += 1;
                }
            });
            self.note(
                Level::Debug,
                Some(id),
                format!("an earlier connection of a resumed link ended: {why}"),
            );
            return;
        }
        // A link the node's newer one replaced is no longer the node's: its end
        // says nothing about the node, which is up.
        let current = {
            let mut links = self.links.lock().unwrap();
            let current = links.get(id).is_some_and(|l| Arc::ptr_eq(l, link));
            if current {
                links.remove(id);
            }
            current
        };
        self.update_soon(|s| {
            if current && let Some(n) = s.nodes.get_mut(id) {
                n.last_seen_ms = now;
            }
            if s.nodes.contains_key(id) {
                let d = s.day(id, now);
                d.online_ms += online;
                if !clean {
                    d.drops += 1;
                }
            }
        });
        if !current {
            self.note(
                Level::Debug,
                Some(id),
                format!(
                    "a link that was replaced ended: {why} (it was up for {})",
                    util::span(up)
                ),
            );
            self.changed(Change::Nodes);
            return;
        }
        let gone = Instant::now()
            .checked_sub(silent)
            .unwrap_or_else(Instant::now);
        self.down.lock().unwrap().insert(id.clone(), gone);
        let (level, verb) = if clean {
            (Level::Info, "closed")
        } else {
            (Level::Warn, "dropped")
        };
        self.note(
            level,
            Some(id),
            format!("link {verb}: {why} (it was up for {})", util::span(up)),
        );
        self.changed(Change::Nodes);
    }

    /// Fetches the full descriptor and keeps it.
    async fn refresh(&self, link: &Arc<Link>) {
        match link
            .call(
                msg::method::DESCRIBE,
                json!({"detail": "full"}),
                Some(SHORT_CALL),
            )
            .await
        {
            Ok(v) => match serde_json::from_value::<Descriptor>(v) {
                // A unit with a bad name or a schema the center cannot check
                // is left out on its own (`Catalog`); the rest stays usable.
                Ok(d) => {
                    let broken = self.update(|s| {
                        let n = s.nodes.get_mut(&link.node_id)?;
                        n.set_descriptor(d);
                        let first = n.catalog.broken.first()?.clone();
                        Some((first, n.catalog.broken.len()))
                    });
                    // One line however many: a node may leave out thousands,
                    // and the overview lists them all.
                    if let Some((b, count)) = broken {
                        let more = if count > 1 {
                            format!(" (and {} more, listed in the overview)", count - 1)
                        } else {
                            String::new()
                        };
                        self.note(
                            Level::Warn,
                            Some(&link.node_id),
                            format!(
                                "the center leaves out {} of the node's description: {}{more}",
                                b.name, b.reason
                            ),
                        );
                    }
                    self.changed(Change::Nodes);
                }
                Err(e) => self.note(
                    Level::Warn,
                    Some(&link.node_id),
                    format!("the node sent a description the center cannot read: {e}"),
                ),
            },
            // A link that ended meanwhile says so on its own.
            Err(e) => self.note(
                if e.kind() == ErrorCode::ConnectionLost {
                    Level::Debug
                } else {
                    Level::Warn
                },
                Some(&link.node_id),
                format!("asking the node for its description failed: {}", e.message),
            ),
        }
    }

    pub(crate) fn on_event(&self, link: &Arc<Link>, ev: Event) {
        let node = link.node_id.clone();
        match (ev.cap.as_str(), ev.name.as_str()) {
            ("node", "descriptor_changed" | "capability_changed") => {
                self.note(
                    Level::Debug,
                    Some(&node),
                    "the node's description changed; fetching it again",
                );
                let c = self.clone();
                let l = link.clone();
                tokio::spawn(async move { c.refresh(&l).await });
            }
            ("node", "going_away") => {
                let why = ev
                    .data
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                self.update(|s| {
                    if let Some(n) = s.nodes.get_mut(&node) {
                        n.going_away = Some(util::clip(&why, 200));
                    }
                });
                self.note(
                    Level::Info,
                    Some(&node),
                    format!("the node is going away: {}", util::clip(&why, 200)),
                );
                self.changed(Change::Nodes);
            }
            ("settings", "changed") => {
                let version = ev.data.get("version").and_then(Value::as_u64);
                self.note(
                    Level::Info,
                    Some(&node),
                    match version {
                        Some(v) => format!("the node's settings changed (version {v})"),
                        None => "the node's settings changed".to_string(),
                    },
                );
                self.changed(Change::Nodes);
            }
            ("audit", "decision") => {
                let name = self.node_name(&node);
                let mut e = ev.data.clone();
                if let Some(o) = e.as_object_mut() {
                    o.insert("node_id".into(), json!(node));
                    o.insert("node".into(), json!(name));
                    o.entry("ts").or_insert(json!(ev.ts));
                }
                self.audit.lock().unwrap().push(e);
                self.changed(Change::Audit);
            }
            _ => {}
        }
    }

    pub fn node_name(&self, node_id: &str) -> String {
        self.read(|s| {
            s.nodes
                .get(node_id)
                .map(|n| n.name.clone())
                .unwrap_or_default()
        })
    }

    pub fn node_id_by_name(&self, name: &str) -> Option<String> {
        self.read(|s| s.node_by_name(name).map(|n| n.id.clone()))
    }

    pub fn audit(&self) -> Vec<Value> {
        self.audit.lock().unwrap().list()
    }

    /// The nodes as the web UI shows them.
    pub fn nodes_json(&self) -> Value {
        let links: BTreeMap<String, Arc<Link>> = self.links.lock().unwrap().clone();
        // Which sessions use each node, read before the state is locked (see
        // `Inner::store`): `sessions_json` holds a session's node set while
        // it names the nodes.
        let sessions: Vec<Arc<Session>> = self.sessions.lock().unwrap().values().cloned().collect();
        let mut used: HashMap<String, Vec<String>> = HashMap::new();
        for x in &sessions {
            for n in x.nodes.lock().unwrap().iter() {
                used.entry(n.clone()).or_default().push(x.id.clone());
            }
        }
        let nodes: Vec<Value> = self.read(|s| {
            s.nodes
                .values()
                .map(|n| {
                    let link = links.get(&n.id).filter(|l| l.is_live());
                    let d = n.descriptor.as_ref();
                    // Whether the agent is offered anything of a capability:
                    // one whose every action was left out, or that the node's
                    // owner turned off, is listed for the owner, but `list`
                    // does not count it.
                    let offered: BTreeSet<&str> =
                        n.catalog.units.iter().map(|u| u.cap.as_str()).collect();
                    let caps: Vec<Value> = d
                        .map(|d| {
                            d.capabilities
                                .iter()
                                .map(|c| json!({"id": c.id, "profile": c.profile, "exposure": c.exposure, "summary": c.summary,
                                                "offered": c.exposure != Exposure::Off && offered.contains(c.id.as_str())}))
                                .collect()
                        })
                        .unwrap_or_default();
                    let used_by = used.get(&n.id).cloned().unwrap_or_default();
                    json!({
                        "id": n.id,
                        "name": n.name,
                        "platform": n.platform,
                        "arch": n.arch,
                        "online": link.is_some(),
                        "status": link.map(|l| l.status.lock().unwrap().clone()),
                        "since_ms": link.map(|l| l.since_ms),
                        "last_seen_ms": n.last_seen_ms,
                        "paired_ms": n.paired_ms,
                        "going_away": n.going_away,
                        "disabled": n.disabled,
                        "key_grace_until_ms": n.old_key.as_ref().map(|o| o.until_ms),
                        "summary": d.map(|d| d.summary.clone()).unwrap_or_default(),
                        "software": d.map(|d| d.node.software.version.clone()),
                        "capabilities": caps,
                        // Units the center leaves out, with the reason, for
                        // the owner: the agent is not offered them.
                        "broken": n.catalog.broken,
                        "sessions": used_by,
                        "settings_write": d.is_some_and(settings_write),
                    })
                })
                .collect()
        });
        json!(nodes)
    }

    // ---- What the agent is offered ----

    /// The ids of the nodes with a live link, read before the state is
    /// locked (see `Inner::store`).
    fn online_ids(&self) -> BTreeSet<String> {
        self.links
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, l)| l.is_live())
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// The nodes as `list()` shows them, each with the owner's note on it.
    pub fn listed_nodes(&self) -> Vec<listing::NodeLine> {
        let online = self.online_ids();
        self.read(|s| {
            s.nodes
                .values()
                .map(|n| {
                    let mut line = listing::line(n, online.contains(&n.id));
                    line.note = s
                        .checker
                        .nodes
                        .get(&n.id)
                        .map(|x| x.note.clone())
                        .filter(|t| !t.is_empty());
                    line
                })
                .collect()
        })
    }

    /// The node `given` (its name or id) with what it offers the agent, as
    /// `list(node)` shows it; none when there is no such node.
    pub fn offer(&self, given: &str) -> Option<listing::Offer> {
        let online = self.online_ids();
        self.read(|s| {
            let n = listing::find(&s.nodes, given)?;
            Some(listing::offer(n, online.contains(&n.id)))
        })
    }

    /// The names of the paired nodes, for an answer that names a node that
    /// is not there.
    pub fn node_names(&self) -> Vec<String> {
        self.read(|s| s.nodes.values().map(|n| n.name.clone()).collect())
    }

    /// Where `execute` of `unit` on the node `given` (its name or id) goes,
    /// with the unit to check the arguments against. `Ok(None)` when there
    /// is no such node.
    pub fn listed_unit(
        &self,
        given: &str,
        unit: &str,
    ) -> Result<Option<(Route, catalog::Unit)>, (String, listing::Miss)> {
        self.read(|s| {
            let Some(n) = listing::find(&s.nodes, given) else {
                return Ok(None);
            };
            let u = listing::unit(n, unit).map_err(|m| (n.name.clone(), m))?;
            let route = Route {
                node_id: n.id.clone(),
                node_name: n.name.clone(),
                cap: u.cap.clone(),
                action: u.action.clone(),
                effect: u.effect,
            };
            Ok(Some((route, u)))
        })
    }

    // ---- Sessions ----

    pub fn new_session(&self, transport: &str) -> Arc<Session> {
        let s = Arc::new(Session {
            id: format!("s-{}", nerve_transport::keys::random_token(20)),
            transport: transport.to_string(),
            client: Mutex::new(String::new()),
            started_ms: now_ms(),
            ended: AtomicBool::new(false),
            calls: AtomicU64::new(0),
            nodes: Mutex::new(BTreeSet::new()),
            tainted: AtomicBool::new(false),
            fetched: Mutex::new(Fetched::default()),
            jobs: Mutex::new(Jobs::default()),
            streams: Mutex::new(Streams::default()),
        });
        self.sessions
            .lock()
            .unwrap()
            .insert(s.id.clone(), s.clone());
        self.log.record(
            Level::Info,
            None,
            &format!("a harness session started over {transport} ({})", s.id),
        );
        self.changed(Change::Sessions);
        s
    }

    pub fn session(&self, id: &str) -> Option<Arc<Session>> {
        self.sessions.lock().unwrap().get(id).cloned()
    }

    /// Ends a session: every node it used gets `session.end`.
    pub async fn end_session(&self, id: &str) -> bool {
        let Some(s) = self.sessions.lock().unwrap().remove(id) else {
            return false;
        };
        s.ended.store(true, Ordering::SeqCst);
        // Its calls and jobs stop, and their results are dropped.
        let stops = s.jobs.lock().unwrap().end();
        for stop in stops {
            let _ = stop.send(Stop::SessionEnded);
        }
        // Its streams are dropped; one still running on its node stops.
        let closers = s.streams.lock().unwrap().end();
        for c in closers {
            c.close("the session ended");
        }
        self.log.record(
            Level::Info,
            None,
            &format!(
                "the harness session {} ended after {} calls",
                s.id,
                s.calls.load(Ordering::SeqCst)
            ),
        );
        let nodes: Vec<String> = s.nodes.lock().unwrap().iter().cloned().collect();
        for n in nodes {
            // A parked link gets it when it resumes.
            if let Some(l) = self.held(&n) {
                l.notify(msg::method::SESSION_END, json!({"session": s.id}))
                    .await;
            }
        }
        self.changed(Change::Sessions);
        true
    }

    pub fn sessions_json(&self) -> Value {
        let sessions: Vec<Arc<Session>> = self.sessions.lock().unwrap().values().cloned().collect();
        let list: Vec<Value> = sessions
            .iter()
            .map(|s| {
                // Copied out before the names are read: the state is never
                // locked under a session's lock (see `Inner::store`).
                let ids: Vec<String> = s.nodes.lock().unwrap().iter().cloned().collect();
                let nodes: Vec<String> = ids.iter().map(|n| self.node_name(n)).collect();
                json!({
                    "id": s.id,
                    "transport": s.transport,
                    "client": s.client.lock().unwrap().clone(),
                    "started_ms": s.started_ms,
                    "calls": s.calls.load(Ordering::SeqCst),
                    "nodes": nodes,
                    "tainted": s.tainted(),
                })
            })
            .collect();
        json!(list)
    }

    pub fn session_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    // ---- Settings (only with the node's `settings = write` grant) ----

    pub async fn node_settings(&self, node_id: &str) -> Result<Value, RpcError> {
        let link = self
            .link(node_id)
            .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "the node is offline"))?;
        link.call(
            msg::method::GET,
            json!({"cap": "settings", "keys": ["document", "version", "sudo"]}),
            Some(SHORT_CALL),
        )
        .await
    }

    pub async fn set_node_settings(
        &self,
        node_id: &str,
        document: Value,
        if_version: Value,
    ) -> Result<Value, RpcError> {
        let r = self.send_settings(node_id, document, if_version).await;
        self.log_change(node_id, "settings saved", "save the settings", &r);
        r
    }

    async fn send_settings(
        &self,
        node_id: &str,
        document: Value,
        if_version: Value,
    ) -> Result<Value, RpcError> {
        let link = self
            .link(node_id)
            .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "the node is offline"))?;
        link.call(
            msg::method::INVOKE,
            json!({"cap": "settings", "action": "set", "args": {"document": document, "if_version": if_version}, "ctx": {}}),
            Some(SHORT_CALL),
        )
        .await
    }

    /// Logs what a change to a node's settings from the web UI came to: `done`
    /// when the node took it, else that it refused to `wanted`.
    fn log_change(&self, node_id: &str, done: &str, wanted: &str, r: &Result<Value, RpcError>) {
        match r {
            Ok(v) => {
                let version = v
                    .get("version")
                    .map(|v| format!(" (version {v})"))
                    .unwrap_or_default();
                self.note(
                    Level::Info,
                    Some(node_id),
                    format!("{done} from the web UI{version}"),
                );
            }
            Err(e) => self.note(
                Level::Warn,
                Some(node_id),
                format!(
                    "the node did not {wanted} from the web UI ({}): {}",
                    e.kind().as_str(),
                    util::clip(&e.message, 300)
                ),
            ),
        }
    }

    /// A one-shot offer to seal the node's sudo password for (docs/dev/spec/protocol.md
    /// §7.4.1). The center checks that the paired node signed it for this
    /// center, so a client seals only for that node.
    pub async fn node_sudo_offer(&self, node_id: &str) -> Result<Value, RpcError> {
        let link = self
            .link(node_id)
            .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "the node is offline"))?;
        let public = self
            .public_key(node_id)
            .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "the node is not paired"))?;
        let v = link
            .call(
                msg::method::INVOKE,
                json!({"cap": "settings", "action": "sudo-offer", "args": {}, "ctx": {}}),
                Some(SHORT_CALL),
            )
            .await?;
        let offer: nerve_transport::sudo::Offer = serde_json::from_value(json!({
            "offer": v["offer"], "key": v["key"], "ts": v["ts"],
        }))
        .map_err(|e| RpcError::internal(format!("the node's sudo offer: {e}")))?;
        let sig = v["sig"].as_str().unwrap_or_default();
        if !nerve_transport::keys::verify_sudo_offer(&public, &self.id(), &offer, sig) {
            return Err(RpcError::internal(
                "the node's sudo offer is not signed with its paired key",
            ));
        }
        Ok(json!({"offer": offer.offer, "key": offer.key, "ts": offer.ts}))
    }

    /// Switches the node's sudo on (with a password sealed for one of its
    /// offers) or off. The center only relays the sealed box; it cannot
    /// open it and keeps no copy.
    pub async fn set_node_sudo(
        &self,
        node_id: &str,
        on: bool,
        sealed: Option<Value>,
    ) -> Result<Value, RpcError> {
        let link = self
            .link(node_id)
            .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "the node is offline"))?;
        let mut args = json!({"on": on});
        if let Some(sealed) = sealed {
            args["sealed"] = sealed;
        }
        let r = link
            .call(
                msg::method::INVOKE,
                json!({"cap": "settings", "action": "sudo", "args": args, "ctx": {}}),
                Some(SHORT_CALL),
            )
            .await;
        // The password is sealed for the node; the center never sees it.
        let (done, wanted) = if on {
            ("sudo switched on", "switch sudo on")
        } else {
            ("sudo switched off", "switch sudo off")
        };
        self.log_change(node_id, done, wanted, &r);
        r
    }

    /// Adds `rule` to one list of this center's policy on the node, from the
    /// audit tab (design §11 9a): `allow`, `deny`, or `sudo` for the sudo
    /// allow list. A button only adds; it never takes a rule off the other
    /// list. The node checks and may refuse the document.
    pub async fn add_rule(&self, node_id: &str, list: &str, rule: &str) -> Result<Value, RpcError> {
        let key = policy_list(list)?;
        let cur = self.node_settings(node_id).await?;
        let mut doc = cur.get("document").cloned().unwrap_or_else(|| json!({}));
        let version = cur.get("version").cloned().unwrap_or(Value::Null);
        put_rule(&mut doc, key, rule)?;
        let r = self.send_settings(node_id, doc, version).await;
        let done = format!("rule added to the {list} list ({rule})");
        self.log_change(
            node_id,
            &done,
            &format!("add a rule to the {list} list"),
            &r,
        );
        r
    }

    // ---- Calls ----

    /// Runs a call of a unit (an `execute`) on its node and waits for its
    /// result: the node's policy decides.
    pub async fn call(
        &self,
        sess: &Arc<Session>,
        route: &Route,
        args: Map<String, Value>,
    ) -> Result<Value, CallError> {
        match self.run(sess, route, args, None, None).await {
            Ran::Done(r) => r,
            Ran::Job(_) => unreachable!("a call without a wait never becomes a job"),
        }
    }

    /// Runs a call of a unit (an `execute`) on its node, waiting at most
    /// `wait` for its result (docs/dev/spec/harness.md §4.4). A call still
    /// running then becomes a job of the session, and runs on: a task of its
    /// own owns it, so the `execute` that returns the job's id does not stop
    /// it. Dropped before that (the harness cancelled its request), the call
    /// is stopped, and the node is told to cancel it. `on` is the link a
    /// job's `exec.signal` must go on: the `invoke` id it names is that
    /// link's.
    pub async fn run(
        &self,
        sess: &Arc<Session>,
        route: &Route,
        args: Map<String, Value>,
        on: Option<Arc<Link>>,
        wait: Option<Duration>,
    ) -> Ran {
        let id = jobs::new_id();
        let started = sess.jobs.lock().unwrap().start(&id, route, on.is_some());
        let (mut result, stop) = match started {
            Ok(s) => s,
            Err(e) => return Ran::Done(Err(self.refused(sess, route, e))),
        };
        sess.calls.fetch_add(1, Ordering::SeqCst);
        let mut held = Held {
            sess: sess.clone(),
            id: Some(id.clone()),
        };
        let (c, s, r, i) = (self.clone(), sess.clone(), route.clone(), id.clone());
        tokio::spawn(async move { c.run_call(&s, &r, args, &i, on, stop).await });
        let got = match wait {
            None => Some((&mut result).await),
            Some(w) => tokio::time::timeout(w, &mut result).await.ok(),
        };
        let got = match got {
            Some(got) => got,
            None => {
                let became = sess.jobs.lock().unwrap().detach(&id);
                held.id = None;
                if became {
                    return Ran::Job(id);
                }
                // The result came in between.
                result.await
            }
        };
        held.id = None;
        // The waiter goes away without a result only when the session's end
        // stopped the call.
        Ran::Done(
            got.unwrap_or_else(|_| Err(Stop::SessionEnded.error()))
                .map_err(CallError::Rpc),
        )
    }

    /// Names the output stream of the `exec.run` job `job` of `sess`, and
    /// opens it on its node once the command runs there
    /// (docs/dev/spec/harness.md §4.5, [`streams::open_on_node`]): its id,
    /// or why it has none.
    pub fn open_output(
        &self,
        sess: &Arc<Session>,
        route: &Route,
        job: &str,
    ) -> Result<String, String> {
        let (room, gone) = sess.streams.lock().unwrap().room(Instant::now());
        for c in gone {
            c.close("too many streams");
        }
        if !room {
            return Err(format!(
                "this session holds {} streams already, the most it may: close one with stream.close",
                streams::STREAMS_MAX
            ));
        }
        let ring = Arc::new(Ring::default());
        let id = streams::new_id();
        if !sess
            .streams
            .lock()
            .unwrap()
            .add(&id, &route.node_id, job, ring.clone())
        {
            return Err("the session ended".into());
        }
        let waits = *self.stream_waits.lock().unwrap();
        tokio::spawn(streams::open_on_node(
            Arc::downgrade(sess),
            route.node_id.clone(),
            job.to_string(),
            id.clone(),
            ring,
            waits,
        ));
        Ok(id)
    }

    /// The session read a command's output (`stream.read`): outside content,
    /// as the command's result is once it ends, so it taints the session.
    pub fn taint_by_output(&self, sess: &Session) {
        if self.checker().taint_on()
            && checker::taints(nerve_proto::Effect::Execute)
            && !sess.tainted()
        {
            sess.set_tainted();
            self.changed(Change::Sessions);
        }
    }

    /// The task that owns a call: it runs it until its result comes or it is
    /// stopped, counts it, and hands the result to the `execute` still
    /// waiting, or keeps it for the job's `job.status`. A stopped call drops
    /// its `invoke`, which tells the node to cancel it.
    async fn run_call(
        &self,
        sess: &Arc<Session>,
        route: &Route,
        args: Map<String, Value>,
        id: &str,
        on: Option<Arc<Link>>,
        stop: tokio::sync::oneshot::Receiver<Stop>,
    ) {
        let started = Instant::now();
        let out = tokio::select! {
            r = self.call_inner(sess, route, args, id, on.as_ref()) => r.map_err(|CallError::Rpc(e)| e),
            s = stop => Err(s.unwrap_or(Stop::Abandoned).error()),
        };
        // Stats, taint and the log of a failure come with the end of the
        // call, also of one that became a job.
        self.count_call(sess, route, out.as_ref().err(), started);
        let handed = sess.jobs.lock().unwrap().finish(id, out, Instant::now());
        match handed {
            Some((waiter, out)) => {
                let _ = waiter.send(out);
            }
            None => {
                // A result kept for its job is forgotten after a while when
                // nobody reads it; the session may be gone by then.
                let weak = Arc::downgrade(sess);
                let id = id.to_string();
                tokio::spawn(async move {
                    tokio::time::sleep(jobs::KEEP_FOR).await;
                    if let Some(s) = weak.upgrade() {
                        s.jobs.lock().unwrap().expire(&id);
                        // Its output stream goes with it.
                        let stream = s.streams.lock().unwrap().of_job(&id);
                        if let Some(c) = stream {
                            c.close("its job was forgotten");
                        }
                    }
                });
            }
        }
    }

    /// A call the MCP side refused before `call` (its arguments do not fit
    /// the unit, or the unit is gone): counted and logged as a failed call
    /// of the unit, as when the node refused it, so the owner still sees a
    /// model that keeps getting its arguments wrong.
    pub fn refused(&self, sess: &Arc<Session>, route: &Route, e: RpcError) -> CallError {
        sess.calls.fetch_add(1, Ordering::SeqCst);
        self.count_call(sess, route, Some(&e), Instant::now());
        CallError::Rpc(e)
    }

    /// The log line and statistics of a call that worked or `failed`.
    fn count_call(
        &self,
        sess: &Arc<Session>,
        route: &Route,
        failed: Option<&RpcError>,
        started: Instant,
    ) {
        let ms = started.elapsed().as_millis() as u64;
        // A call that returned outside content taints the session, so the
        // model's "only tainted sessions" scope and its state can take it in.
        if failed.is_none() && self.checker().taint_on() && checker::taints(route.effect) {
            sess.set_tainted();
            self.changed(Change::Sessions);
        }
        let code = failed.map(|e| e.kind().as_str().to_string());
        // A call that worked is in the node's audit log, not here.
        if let Some(e) = failed {
            self.log_failed_call(route, e, started.elapsed());
        }
        self.update_soon(|s| {
            if !s.nodes.contains_key(&route.node_id) {
                return;
            }
            let d = s.day(&route.node_id, now_ms());
            let c = d
                .calls
                .entry(format!("{}.{}", route.cap, route.action))
                .or_default();
            c.count += 1;
            c.total_ms += ms;
            c.max_ms = c.max_ms.max(ms);
            if let Some(code) = &code {
                c.errors += 1;
                *d.errors.entry(code.clone()).or_default() += 1;
            }
        });
    }

    async fn call_inner(
        &self,
        sess: &Arc<Session>,
        route: &Route,
        args: Map<String, Value>,
        job: &str,
        on: Option<&Arc<Link>>,
    ) -> Result<Value, CallError> {
        // Checked first: nothing is sent to a disabled node, not even the
        // session mark. `execute` refuses a disabled node before it gets
        // here, but the switch may come in between.
        if self.read(|s| s.nodes.get(&route.node_id).is_some_and(|n| n.disabled)) {
            return Err(RpcError::new(
                ErrorCode::Unavailable,
                format!("the node {} is disabled in the center", route.node_name),
            )
            .into());
        }
        // Then whether the node is there at all, before the checker: a call
        // that cannot be sent is `unavailable`, not a checker refusal (with
        // the model on and down, fail closed would say `forbidden`), and
        // costs no model call.
        let offline = || {
            RpcError::new(
                ErrorCode::Unavailable,
                format!("the node {} is offline", route.node_name),
            )
        };
        if self.link(&route.node_id).is_none() {
            return Err(offline().into());
        }
        // The action checker (issue #17): the center's own gate, before the
        // node. It can only refuse; the node's policy still decides what it
        // lets through (design rule 1).
        let checker = self.checker();
        let (os, seen) = self.read(|s| {
            let n = s.nodes.get(&route.node_id);
            let os = n.map(|n| n.platform.clone()).unwrap_or_default();
            (os, n.map(|n| CheckerUnit::of(n, route)).unwrap_or_default())
        });
        let tainted = checker.taint_on() && sess.tainted();
        let paths = seen.paths(&args);
        let target = checker_target(route, &args, &paths);
        let endpoint = self.resolved_endpoint(&checker);
        let info = CallInfo {
            cap: &route.cap,
            action: &route.action,
            effect: route.effect,
            description: &seen.description,
            target: &target,
            paths: &paths,
            args: &args,
            node_id: &route.node_id,
            os: &os,
            tainted,
        };
        match checker.check(&info, endpoint.as_ref()).await {
            Decision::Refuse {
                layer,
                scope,
                detail,
                message,
            } => {
                self.audit_checker(sess, route, &target, "forbidden", layer, scope, &detail);
                return Err(RpcError::forbidden(message).into());
            }
            Decision::Allowed {
                layer,
                scope,
                detail,
            } => {
                self.audit_checker(sess, route, &target, "allowed", layer, scope, &detail);
            }
            Decision::Pass => {}
        }
        // Looked up again: the node may have gone or come back on another
        // link while the model was asked.
        let link = self.link(&route.node_id).ok_or_else(offline)?;
        // A job's `invoke` id is its link's: on another link of the node it
        // would name some other call.
        if on.is_some_and(|on| !Arc::ptr_eq(on, &link)) {
            return Err(RpcError::invalid_args(
                "the job's call no longer runs on the node's link: the link to the node ended",
            )
            .into());
        }
        let ctx = json!({"session": sess.id});
        sess.nodes.lock().unwrap().insert(route.node_id.clone());
        link.sessions.lock().unwrap().insert(sess.id.clone());
        // The agents' calls leave a few of the node's call places free, for
        // the owner's settings changes from the center and for a job's
        // `exec.signal`: jobs of many sessions could fill them all.
        let most = link.limits.calls as usize;
        let most = if on.is_some() {
            most
        } else {
            (most - calls_kept(most)).max(1)
        };
        let (id, rx) = link
            .start_within(
                msg::method::INVOKE,
                json!({"cap": route.cap, "action": route.action, "args": args, "ctx": ctx}),
                most,
            )
            .await
            .map_err(|e| {
                if e.kind() != ErrorCode::Busy {
                    return e;
                }
                RpcError::new(
                    ErrorCode::Busy,
                    format!(
                        "node {} runs {} calls already, the most the center sends it for agents: try again when one ended, or stop a job of this session with job.cancel",
                        route.node_name, most
                    ),
                )
            })?;
        sess.jobs.lock().unwrap().sent(job, &link, id);
        let mut waiting = Waiting {
            link: Some(link),
            id,
        };
        let r = rx.await;
        waiting.link = None;
        r.unwrap_or_else(|_| {
            Err(RpcError::new(
                ErrorCode::ConnectionLost,
                "the link to the node ended",
            ))
        })
        .map_err(CallError::Rpc)
    }

    /// Logs a call that was refused or that failed, with the reason.
    fn log_failed_call(&self, route: &Route, e: &RpcError, took: Duration) {
        // A node the owner switched off answers `unavailable`.
        let disabled_here = e.kind() == ErrorCode::Unavailable
            && self.read(|s| s.nodes.get(&route.node_id).is_some_and(|n| n.disabled));
        let what = format!("{}.{}", route.cap, route.action);
        let (level, line) = call_line(&what, e, took, disabled_here);
        self.note(level, Some(&route.node_id), line);
    }

    /// Closes every link with `bye shutdown`.
    pub async fn shutdown(&self) {
        let links: Vec<Arc<Link>> = self.links.lock().unwrap().values().cloned().collect();
        self.log.record(
            Level::Info,
            None,
            &format!(
                "the center is stopping; closing {}",
                plural(links.len() as u32, "node link")
            ),
        );
        for l in links {
            l.bye(ByeReason::Shutdown).await;
            // A parked link has no connection for the bye; its calls end.
            if !l.is_live() {
                l.fail_all();
            }
        }
        self.flush();
    }

    /// Notes the pairing codes that ran out unused. The center calls this now
    /// and then, so a log line is at most a few seconds behind the expiry.
    pub fn sweep_codes(&self) {
        // The wrong codes left out of a burst are counted when it is over.
        let left_out = self.pair_log.lock().unwrap().flush(Instant::now());
        if left_out > 0 {
            self.log.record(
                Level::Warn,
                None,
                &format!(
                    "{} left out since the last line: the code was unknown, used, expired or out of tries",
                    plural(left_out, "pairing refusal")
                ),
            );
        }
        let lost = self.codes.lock().unwrap().sweep(Instant::now());
        if lost.expired > 0 {
            self.log.record(
                Level::Info,
                None,
                &format!(
                    "{} expired without being used",
                    plural(lost.expired, "pairing code")
                ),
            );
        }
        if lost.out_of_tries > 0 {
            self.log.record(
                Level::Warn,
                None,
                &format!(
                    "{} ran out of tries on wrong codes",
                    plural(lost.out_of_tries, "pairing code")
                ),
            );
        }
    }

    /// Statistics: per node (summed over the kept days) and in total.
    pub fn stats_json(&self) -> Value {
        self.read(|s| {
            let mut total = crate::store::DayStats::default();
            let mut nodes = Map::new();
            for (id, ns) in &s.stats {
                let mut sum = crate::store::DayStats::default();
                for d in ns.days.values() {
                    sum.add(d);
                }
                total.add(&sum);
                let name = s
                    .nodes
                    .get(id)
                    .map(|n| n.name.clone())
                    .unwrap_or_else(|| id.clone());
                nodes.insert(name, serde_json::to_value(&sum).unwrap_or_default());
            }
            json!({"retention_days": s.retention_days, "total": total, "nodes": nodes})
        })
    }

    // ---- Action checker (issue #17, docs/dev/action-checker.md) ----

    /// The checker as it is now.
    pub fn checker(&self) -> Arc<Checker> {
        self.checker.lock().unwrap().clone()
    }

    /// The file that holds the model endpoint's bearer token (a secret, so
    /// not in `state.json`), mode 0600 in the state folder.
    fn checker_token_path(&self) -> PathBuf {
        self.dir.join("checker-model.token")
    }

    /// The endpoint token, or `None` when none is set.
    pub fn checker_token(&self) -> Option<String> {
        std::fs::read_to_string(self.checker_token_path())
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    /// Whether an endpoint token is set (the UI never shows the token itself).
    pub fn checker_has_token(&self) -> bool {
        self.checker_token().is_some()
    }

    /// Sets or clears the endpoint token.
    pub fn set_checker_token(&self, token: Option<&str>) -> Result<(), String> {
        let path = self.checker_token_path();
        match token.map(str::trim).filter(|t| !t.is_empty()) {
            Some(t) => nerve_transport::files::write_private(&path, t.as_bytes())
                .map_err(|e| format!("cannot write the model token: {e}")),
            None => match std::fs::remove_file(&path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    Err(format!("cannot remove the model token: {e}"))
                }
                _ => Ok(()),
            },
        }
    }

    /// Rebuilds the checker from the stored config and the token, and brings
    /// the local model up or down to match. Called at start and after every
    /// change to the checker config.
    pub fn rebuild_checker(&self) {
        let cfg = self.read(|s| s.checker.clone());
        self.manage_local_model(&cfg);
        let checker = Checker::build(cfg, self.checker_token());
        for why in &checker.rejected {
            self.log.record(
                Level::Warn,
                None,
                &format!("the action checker left out a rule it could not parse: {why}"),
            );
        }
        *self.checker.lock().unwrap() = Arc::new(checker);
    }

    /// Starts, stops or keeps the local llama-server to match `cfg`. It runs
    /// only when the model is on (by the center's switch, or for a node by
    /// its own), its source is local, and the one-click
    /// install put the build and the chosen model in place. Keyed by the
    /// CPU/GPU choice and the model, so an unrelated change does not restart
    /// it.
    fn manage_local_model(&self, cfg: &CheckerConfig) {
        // Held for the whole run, so an install cannot take the files between
        // the check below and the start.
        let held = self.files_held.lock().unwrap();
        let installed = checker::install::installed(&self.dir, cfg.model.local_model);
        let want = cfg.model_wanted() && cfg.model.source == ModelSource::Local && installed;
        // An install is swapping the files (or Remove deleting them): start
        // nothing from them now. The install rebuilds when it is done, and
        // the empty signature makes that start the server.
        if want && *held {
            return;
        }
        let sig = if want {
            format!(
                "gpu={}|model={:?}",
                cfg.model.local_gpu, cfg.model.local_model
            )
        } else {
            String::new()
        };
        if *self.local_sig.lock().unwrap() == sig {
            return;
        }
        // Starting a server needs a runtime; without one (an off-runtime
        // open, as in a test) leave it for the next change inside the server.
        if want && tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        // Drop the old one (its Drop ends the process), then start the new.
        *self.local_model.lock().unwrap() = None;
        if want {
            let bin = checker::install::server_bin(&self.dir);
            let model = checker::install::model_path(&self.dir, cfg.model.local_model);
            match bin
                .ok_or_else(|| "the local model is not installed".to_string())
                .and_then(|bin| {
                    LocalServer::start(bin, model, cfg.model.local_gpu, cfg.model.timeout_ms)
                }) {
                Ok(srv) => {
                    *self.local_model.lock().unwrap() = Some(Arc::new(srv));
                    self.log.record(
                        Level::Info,
                        None,
                        &format!(
                            "the action checker is starting its local decision model on the {}",
                            if cfg.model.local_gpu { "GPU" } else { "CPU" }
                        ),
                    );
                }
                Err(e) => self.log.record(
                    Level::Warn,
                    None,
                    &format!("the action checker cannot start its local model: {e}"),
                ),
            }
        }
        *self.local_sig.lock().unwrap() = sig;
    }

    /// The model endpoint to use now: the owner's endpoint, or the local
    /// server's once it is ready. `None` when the model is on but not
    /// reachable (the checker then fails closed, or logs, by its setting).
    fn resolved_endpoint(&self, checker: &Checker) -> Option<Endpoint> {
        match checker.model_source() {
            ModelSource::Endpoint => checker.endpoint().cloned(),
            ModelSource::Local => {
                let srv = self.local_model.lock().unwrap().clone()?;
                srv.ready().then(|| srv.endpoint())
            }
        }
    }

    /// The local model's status for the UI, or `None` when there is no local
    /// server running.
    pub fn local_model_status(&self) -> Option<crate::checker::server::Status> {
        self.local_model
            .lock()
            .unwrap()
            .as_ref()
            .map(|s| s.status())
    }

    /// Replaces the checker config (after the UI validated the change),
    /// saves it, rebuilds the checker and tells the UI. `clear_taint` clears
    /// every session's taint mark, for when taint is switched off.
    pub fn set_checker_config(&self, cfg: CheckerConfig, clear_taint: bool) {
        self.update(|s| s.checker = cfg);
        if clear_taint {
            for s in self.sessions.lock().unwrap().values() {
                s.tainted.store(false, Ordering::SeqCst);
            }
        }
        self.rebuild_checker();
        self.changed(Change::Nodes);
        self.changed(Change::Sessions);
    }

    /// What the web UI's Action checker page reads: the config (no token),
    /// whether a token is set, whether the model is on anywhere (for the
    /// center or for a node, the rule that runs the local model), the
    /// default model and its licence, the one-click install's state and the
    /// running model's status, the platform/GPU support, and rules that did
    /// not parse.
    pub fn checker_json(&self) -> Value {
        let cfg = self.read(|s| s.checker.clone());
        json!({
            "config": cfg.view(),
            "model_wanted": cfg.model_wanted(),
            "has_token": self.checker_has_token(),
            "models": checker::install::MODELS,
            "default_blocklist": checker::config::default_blocklist(),
            "local": self.local_model_status(),
            "install": *self.install.lock().unwrap(),
            "installed": checker::install::installed(&self.dir, cfg.model.local_model),
            "installed_models": checker::install::installed_models(&self.dir),
            "platform_supported": checker::install::platform_supported(),
            "gpu_hint": checker::install::gpu_hint(),
            "rejected": self.checker().rejected,
            "unpublished": self.read(|s| unpublished_rules(&s.checker, &s.nodes)),
        })
    }

    /// The one-click install's current state.
    pub fn checker_install_status(&self) -> checker::install::Status {
        self.install.lock().unwrap().clone()
    }

    /// Starts the one-click install of llama.cpp and the d1-3B model on the
    /// CPU or GPU, in the background. On success it turns the local model on
    /// with the chosen device. Refused while an install is already running.
    /// Validates a posted checker config and, if it holds, saves it. Taint
    /// switched off clears every session's mark.
    pub fn apply_checker_config(&self, mut cfg: CheckerConfig) -> Result<(), String> {
        for e in &mut cfg.blocklist {
            Rule::parse(&e.rule)?;
            // An entry for one node is switched off as a whole; the
            // exceptions are for an entry of every node.
            if e.node_id.is_some() && !e.off_for.is_empty() {
                return Err(format!(
                    "the blocklist entry {} is for one node, so it cannot be switched off for single nodes; switch it off instead",
                    e.rule
                ));
            }
            e.off_for.sort();
            e.off_for.dedup();
        }
        for a in &cfg.allow_rules {
            Rule::parse(&a.rule)?;
        }
        if !(0.0..=1.0).contains(&cfg.model.threshold) {
            return Err("the threshold is between 0 and 1".into());
        }
        if cfg.model.timeout_ms < 100 {
            return Err("the model timeout is at least 100 ms".into());
        }
        if cfg.model.instructions.trim().is_empty() {
            return Err("the model question needs instructions".into());
        }
        // The owner's note is one line of a few sentences: `list()` gives it
        // to every harness on one line, and a long one would cost every
        // session the tokens.
        for (id, n) in &mut cfg.nodes {
            n.note = listing::one_line(&n.note);
            if n.note.len() > checker::config::NOTE_MAX {
                let name = Some(self.node_name(id)).filter(|n| !n.is_empty());
                return Err(format!(
                    "the note on machine {} is {} bytes long; at most {} fit",
                    name.as_deref().unwrap_or(id),
                    n.note.len(),
                    checker::config::NOTE_MAX
                ));
            }
        }
        // A node that follows the center in both and has no note is the
        // same as one with no settings: keep the state free of them.
        cfg.nodes.retain(|_, n| *n != NodeSettings::default());
        // Keep in memory what a restart reads back from the stored part.
        cfg.settle_blocklist();
        let clear_taint = self.read(|s| s.checker.taint_on) && !cfg.taint_on;
        self.set_checker_config(cfg, clear_taint);
        Ok(())
    }

    /// Adds a saved allow rule, built for an audit button's `cap.action` and
    /// `target` (exact or wildcard), for every node or one node.
    pub fn add_checker_allow(
        &self,
        cap: &str,
        action: &str,
        target: &str,
        wildcard: bool,
        node_id: Option<String>,
    ) -> Result<String, String> {
        let rule = audit_rule("allow", cap, action, target, wildcard)?;
        let mut cfg = self.read(|s| s.checker.clone());
        let entry = AllowRule {
            rule: rule.clone(),
            node_id,
        };
        if !cfg.allow_rules.contains(&entry) {
            cfg.allow_rules.push(entry);
        }
        self.set_checker_config(cfg, false);
        Ok(rule)
    }

    /// Takes the local model's files for an install's swap or a Remove: marks
    /// them held, so no config change starts the server from them, then stops
    /// the running server and waits for its process to exit, so the files are
    /// free to replace or delete (Windows refuses while it runs). The server
    /// stays down until the returned guard is dropped and the checker rebuilt.
    async fn hold_local_files(&self) -> FilesHeld {
        let server = {
            let mut held = self.files_held.lock().unwrap();
            *held = true;
            *self.local_sig.lock().unwrap() = String::new();
            self.local_model.lock().unwrap().take()
        };
        if let Some(srv) = server {
            srv.stop().await;
        }
        FilesHeld(self.clone())
    }

    /// Starts the one-click install of llama.cpp and `model` on the CPU or
    /// GPU, in the background. The running model keeps judging calls while
    /// the files download; it is stopped only for the swap at the end. On
    /// success it turns the local model on with the chosen model and device;
    /// for a GPU install it first checks the build really finds a device and
    /// falls back to the CPU with a note if not. Success or failure, the local
    /// server is then brought back in line with the config. Refused while an
    /// install is already running.
    pub async fn start_checker_install(&self, gpu: bool, model: LocalModel) -> Result<(), String> {
        if !checker::install::platform_supported() {
            return Err("this machine has no pinned local build; use the endpoint mode".into());
        }
        // Claim the install under the lock, so two requests cannot both start.
        {
            let mut st = self.install.lock().unwrap();
            if matches!(
                st.phase,
                checker::install::Phase::Downloading
                    | checker::install::Phase::Unpacking
                    | checker::install::Phase::Verifying
            ) {
                return Err("an install is already running".into());
            }
            *st = checker::install::Status {
                phase: checker::install::Phase::Downloading,
                gpu,
                model_id: model,
                ..Default::default()
            };
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let from = self.install_from.lock().unwrap().clone();
        // Keep the slot locked while spawning, so the task's own check of
        // whether it is still current waits until its handle is stored.
        let mut slot = self.install_task.lock().unwrap();
        let (me, flag) = (self.clone(), cancel.clone());
        let task = tokio::spawn(async move { me.run_install(gpu, model, flag, from).await });
        *slot = Some(InstallTask { cancel, task });
        Ok(())
    }

    /// The body of an install task (see [`Center::start_checker_install`]).
    async fn run_install(
        &self,
        gpu: bool,
        model: LocalModel,
        cancel: Arc<AtomicBool>,
        from: Arc<checker::install::Sources>,
    ) {
        let r = async {
            let prepared =
                checker::install::prepare(&self.dir, gpu, model, &self.install, &cancel, &from)
                    .await?;
            // Only now take the server down: the files it runs from are
            // about to be replaced.
            let _held = self.hold_local_files().await;
            checker::install::commit(&self.dir, prepared)
        }
        .await;
        // A Remove took over (it also ends this task): drop the result.
        let current = self
            .install_task
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|t| Arc::ptr_eq(&t.cancel, &cancel));
        if !current {
            return;
        }
        match &r {
            Ok(()) => {
                // A GPU install only counts as GPU if the build finds a
                // device; otherwise fall back to the CPU and say so.
                let mut use_gpu = gpu;
                if gpu && !checker::install::gpu_available(&self.dir).await {
                    use_gpu = false;
                    self.note(
                        Level::Warn,
                        None,
                        "the action checker's GPU build found no device; running the model on the CPU. Reinstall on CPU to keep it off the GPU.",
                    );
                }
                self.update(|s| s.checker.local_installed(use_gpu, model));
                checker::install::finish(&self.install, &r);
                if gpu && !use_gpu {
                    self.install.lock().unwrap().message =
                        "no GPU device was found; running on the CPU".into();
                }
                self.note(
                    Level::Info,
                    None,
                    format!(
                        "the action checker's local model was installed ({})",
                        if use_gpu { "GPU" } else { "CPU" }
                    ),
                );
            }
            Err(e) => {
                checker::install::finish(&self.install, &r);
                self.note(
                    Level::Warn,
                    None,
                    format!("the action checker's local model install failed: {e}"),
                );
            }
        }
        // Start the new build, or the old one again after a failed swap (a
        // failed download never stopped it).
        self.rebuild_checker();
        self.changed(Change::Nodes);
    }

    /// Removes the installed local build and model, and turns the local model
    /// off. Ends a running install first and waits for its task, so nothing it
    /// does lands after this, then stops the server, so the delete does not
    /// fail while a file is in use. The model is turned off even when a file
    /// could not be deleted: it cannot run from a half-removed install, and
    /// left on it would refuse every call as unreachable.
    pub async fn remove_checker_model(&self) -> Result<(), String> {
        let running = self.install_task.lock().unwrap().take();
        if let Some(t) = running {
            t.cancel.store(true, Ordering::Relaxed);
            // A download waiting on a silent connection only sees the flag at
            // its next read; aborting ends it at once.
            t.task.abort();
            let _ = t.task.await;
        }
        *self.install.lock().unwrap() = checker::install::Status::default();
        let held = self.hold_local_files().await;
        // The server has exited; retry a couple of times for a late handle on
        // Windows.
        let mut last = Ok(());
        for _ in 0..3 {
            last = checker::install::remove(&self.dir);
            if last.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        drop(held);
        // The model is off everywhere then: also for a node that had it on
        // by its own setting, which would otherwise refuse its every call
        // with no model to ask (fail closed).
        self.update(|s| {
            if s.checker.model.source == ModelSource::Local {
                s.checker.model_on = false;
                for n in s.checker.nodes.values_mut() {
                    if n.model == NodeSwitch::On {
                        n.model = NodeSwitch::Inherit;
                    }
                }
                s.checker.nodes.retain(|_, n| *n != NodeSettings::default());
            }
        });
        self.rebuild_checker();
        self.changed(Change::Nodes);
        match last {
            Ok(()) => {
                self.note(
                    Level::Info,
                    None,
                    "the action checker's local model was removed",
                );
                Ok(())
            }
            Err(e) => {
                let e = format!("the local model is off, but not every file could be deleted: {e}");
                self.note(Level::Warn, None, format!("the action checker: {e}"));
                Err(e)
            }
        }
    }

    /// Adds a checker audit entry (a center decision) to the feed and the log.
    /// `scope` says whether the entry, rule or switch behind it was the
    /// center's for every node or this node's own.
    #[allow(clippy::too_many_arguments)]
    fn audit_checker(
        &self,
        sess: &Arc<Session>,
        route: &Route,
        target: &str,
        decision: &str,
        layer: Layer,
        scope: Scope,
        detail: &str,
    ) {
        let node = self.node_name(&route.node_id);
        let mut e = Map::new();
        e.insert("ts".into(), json!(now_ms()));
        e.insert("cap".into(), json!(route.cap));
        e.insert("action".into(), json!(route.action));
        e.insert("target".into(), json!(target));
        e.insert("decision".into(), json!(decision));
        if decision == "forbidden" {
            e.insert("code".into(), json!("forbidden"));
        }
        e.insert("session".into(), json!(sess.id));
        e.insert("by".into(), json!("action checker"));
        e.insert("node_id".into(), json!(route.node_id));
        e.insert("node".into(), json!(node));
        e.insert(
            "checker".into(),
            json!({"layer": layer.as_str(), "scope": scope.as_str(), "detail": detail}),
        );
        self.audit.lock().unwrap().push(Value::Object(e));
        self.changed(Change::Audit);
        let (level, verb) = if decision == "forbidden" {
            (Level::Warn, "refused")
        } else {
            (Level::Info, "allowed")
        };
        self.note(
            level,
            Some(&route.node_id),
            format!(
                "the action checker {verb} {}.{} by its {} {} ({detail})",
                route.cap,
                route.action,
                layer.as_str(),
                match scope {
                    Scope::Global => "for every node",
                    Scope::Node => "for this node",
                }
            ),
        );
    }
}

/// What the checker matches on and the audit names: the command line for
/// `exec.run`, the path for an `fs` action, the path arguments of any other
/// action that takes paths (joined by `, `, as the node's audit names them),
/// else `<cap>.<action>`.
fn checker_target(
    route: &Route,
    args: &Map<String, Value>,
    paths: &[(PathMark, String)],
) -> String {
    match (route.cap.as_str(), route.action.as_str()) {
        ("exec", "run") => args
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        ("fs", _) => args
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        _ if !paths.is_empty() => paths
            .iter()
            .map(|(_, p)| p.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        _ => format!("{}.{}", route.cap, route.action),
    }
}

/// The owner's blocklist entries and allow rules that name a capability, or
/// an action of one, that no paired node publishes (the one node for a
/// rule of one node): they match no call now, which the checker page says,
/// since a misspelt name looks like a rule in force. An `fs`, `fs.read` or
/// `fs.write` blocklist entry also holds the path arguments of the other
/// capabilities, so it is in force where some capability has an argument
/// marked for it, `fs` published or not; an allow rule is matched against
/// the call's own target only, so it is not. Nothing is said while no node
/// has published anything, and the built-in entries name the node's own
/// capabilities.
fn unpublished_rules(cfg: &CheckerConfig, nodes: &BTreeMap<String, NodeRecord>) -> Vec<String> {
    if nodes.values().all(|n| n.descriptor.is_none()) {
        return Vec::new();
    }
    let publishes = |n: &NodeRecord, cap: &str, action: Option<&str>, by_path: bool| {
        let Some(d) = n.descriptor.as_ref() else {
            return false;
        };
        if d.capability(cap)
            .is_some_and(|c| action.is_none_or(|a| c.actions.contains_key(a)))
        {
            return true;
        }
        let held = |mark: PathMark| match action {
            None => true,
            Some("read") => mark == PathMark::Read,
            Some("write") => mark == PathMark::Write,
            Some(_) => false,
        };
        by_path
            && cap == "fs"
            && d.capabilities
                .iter()
                .flat_map(|c| c.actions.values())
                .flat_map(|a| nerve_proto::schema::path_args(&a.params))
                .any(|(_, mark)| held(mark))
    };
    let own = cfg.blocklist.iter().filter(|e| !e.builtin);
    let rules = own
        .map(|e| (&e.rule, &e.node_id, true))
        .chain(cfg.allow_rules.iter().map(|a| (&a.rule, &a.node_id, false)));
    let mut out: Vec<String> = Vec::new();
    for (rule, node, by_path) in rules {
        let scope = rule.split_once(':').map_or(rule.as_str(), |(s, _)| s);
        let (cap, action) = match scope.split_once('.') {
            Some((c, a)) => (c, Some(a)),
            None => (scope, None),
        };
        let known = match node {
            // A rule for a machine no longer paired is shown as such.
            Some(id) => nodes
                .get(id)
                .is_none_or(|n| publishes(n, cap, action, by_path)),
            None => nodes.values().any(|n| publishes(n, cap, action, by_path)),
        };
        if !known && !out.contains(rule) {
            out.push(rule.clone());
        }
    }
    out
}

/// What the center's catalog says of the unit a call is for, as the action
/// checker is shown it. Empty for a unit the catalog no longer has: the
/// node refuses such a call anyway.
#[derive(Default)]
struct CheckerUnit {
    /// The action's own text and the capability's summary, on one line.
    description: String,
    /// The arguments the unit's schema marks as paths.
    marked: Vec<(String, PathMark)>,
}

impl CheckerUnit {
    fn of(n: &NodeRecord, route: &Route) -> CheckerUnit {
        let Some(u) = n.catalog.unit(&format!("{}.{}", route.cap, route.action)) else {
            return CheckerUnit::default();
        };
        // The unit's own description, when it has one, tells what this
        // action does; the capability's summary what it is for. The action
        // goes first: the model's state clips the end, and a long summary
        // must not push out the part that tells `unlock` from `status`. A
        // unit without a summary of its own carries its capability's
        // already.
        let cap = n
            .descriptor
            .as_ref()
            .and_then(|d| d.capability(&route.cap))
            .map(|c| catalog::described(&c.summary).to_string())
            .unwrap_or_default();
        let description = checker::unit_description(&route.action, &u.description, &cap);
        CheckerUnit {
            description,
            marked: nerve_proto::schema::path_args(&u.params),
        }
    }

    /// The values of the call's path arguments, in the schema's order. An
    /// argument that is absent or not a string names no path.
    fn paths(&self, args: &Map<String, Value>) -> Vec<(PathMark, String)> {
        self.marked
            .iter()
            .filter_map(|(field, mark)| Some((*mark, args.get(field)?.as_str()?.to_string())))
            .collect()
    }
}

pub(crate) fn plural(n: u32, one: &str) -> String {
    if n == 1 {
        format!("{n} {one}")
    } else {
        format!("{n} {one}s")
    }
}

/// The node gave this center `settings = write`: its descriptor carries the
/// `settings` capability (spec §7.4).
pub fn settings_write(d: &Descriptor) -> bool {
    d.capability("settings")
        .is_some_and(|c| c.exposure != Exposure::Off)
}

/// The key of the policy list a button writes to. The settings document is
/// the node's center entry (nerve-policy): `policy.allow`, `policy.deny` and
/// `policy.sudo_allow`. A node with another layout refuses the document and
/// the web UI shows why.
fn policy_list(list: &str) -> Result<&'static str, RpcError> {
    match list {
        "allow" => Ok("allow"),
        "deny" => Ok("deny"),
        "sudo" => Ok("sudo_allow"),
        _ => Err(RpcError::invalid_args("the list is allow, deny or sudo")),
    }
}

/// Puts `rule` on `policy.<key>` of a settings document, unless it is there.
fn put_rule(doc: &mut Value, key: &str, rule: &str) -> Result<(), RpcError> {
    let no_room = || RpcError::invalid_args("the node's settings document has no room for rules");
    let list = doc
        .as_object_mut()
        .ok_or_else(no_room)?
        .entry("policy")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(no_room)?
        .entry(key)
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| RpcError::invalid_args("the node's rules are not lists"))?;
    if !list.iter().any(|v| v == rule) {
        list.push(json!(rule));
    }
    Ok(())
}

/// The list and the rule an audit button means: the entry's `cap`, `action`
/// and `target`, the list (`allow`, `deny`, or `sudo` for a sudo command) and
/// whether it is the wildcard form.
pub fn audit_rule(
    list: &str,
    cap: &str,
    action: &str,
    target: &str,
    wildcard: bool,
) -> Result<String, String> {
    // A cut target is no longer the call's, so no rule can be made from it.
    if nerve_policy::audit::is_cut_target(target) {
        return Err("the target was cut to its start, so a rule cannot name it".into());
    }
    match list {
        "allow" | "deny" => nerve_policy::rules::rule_for(cap, action, target, wildcard),
        "sudo" if (cap, action) == ("exec", "run") => {
            nerve_policy::rules::sudo_rule_for(target, wildcard)
        }
        "sudo" => Err("the sudo list is for sudo commands".into()),
        _ => Err("the list is allow, deny or sudo".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(dir: &Path, name: Option<&str>) -> Center {
        nerve_transport::init_crypto();
        Center::open(Options {
            state_dir: dir.to_path_buf(),
            name: name.map(str::to_string),
            public_url: "http://127.0.0.1:7443".into(),
            log: None,
            log_level: None,
        })
        .unwrap()
    }

    fn node_record(id: &str, platform: &str) -> NodeRecord {
        NodeRecord {
            id: id.into(),
            name: id.into(),
            public_key: "00".into(),
            old_key: None,
            key_rotations: 0,
            platform: platform.into(),
            arch: "x86_64".into(),
            paired_ms: 1,
            disabled: false,
            last_seen_ms: 0,
            going_away: None,
            descriptor: None,
            catalog: Default::default(),
        }
    }

    /// Puts a live link for `node` in place, so its calls get past the
    /// offline check; one that reaches the send ends as `connection_lost`.
    fn online(c: &Center, node: &str) {
        c.links
            .lock()
            .unwrap()
            .insert(node.into(), Arc::new(Link::for_test(node)));
    }

    fn exec_route(node: &str) -> Route {
        Route {
            node_id: node.into(),
            node_name: node.into(),
            cap: "exec".into(),
            action: "run".into(),
            effect: nerve_proto::Effect::Execute,
        }
    }

    /// A slow write of the state file holds up no reader: the file is
    /// written with the state unlocked, so a disk that takes seconds (an
    /// fsync under load) does not stop the web UI from answering (issue
    /// #150). The file still has the change once the save returns.
    #[test]
    fn a_slow_save_holds_up_no_reader() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        c.save_delay_ms.store(3000, Ordering::SeqCst);
        let saving = {
            let c = c.clone();
            std::thread::spawn(move || c.update(|s| s.center_name = "after".into()))
        };
        // The save is under way.
        std::thread::sleep(Duration::from_millis(300));
        let t = Instant::now();
        let name = c.name();
        let nodes = c.nodes_json();
        assert!(
            t.elapsed() < Duration::from_secs(1),
            "a read waited {:?} for the save",
            t.elapsed()
        );
        assert_eq!(name, "after");
        assert_eq!(nodes, json!([]));
        saving.join().unwrap();
        let back = Store::load(dir.path()).unwrap().unwrap();
        assert_eq!(back.center_name, "after");
    }

    /// Saves that come together are merged: eight changes at once with a
    /// disk that takes 500 ms a write are on disk in about two writes (1 s),
    /// not eight one after the other (4 s), and a read meanwhile does not
    /// wait.
    #[test]
    fn saves_that_come_together_are_merged() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        c.save_delay_ms.store(500, Ordering::SeqCst);
        let go = Arc::new(std::sync::Barrier::new(8));
        let t = Instant::now();
        let savers: Vec<_> = (0..8)
            .map(|i| {
                let (c, go) = (c.clone(), go.clone());
                std::thread::spawn(move || {
                    go.wait();
                    c.update(|s| s.pair_code_minutes = 10 + i);
                })
            })
            .collect();
        std::thread::sleep(Duration::from_millis(200));
        let r = Instant::now();
        c.name();
        assert!(
            r.elapsed() < Duration::from_millis(200),
            "a read waited {:?}",
            r.elapsed()
        );
        for s in savers {
            s.join().unwrap();
        }
        // Two writes when the threads come at once; one more is allowed
        // for a thread that starts late on a busy machine.
        let writes = c.file_writes.load(Ordering::SeqCst);
        assert!(writes <= 3, "eight saves wrote the file {writes} times");
        assert!(
            t.elapsed() < Duration::from_millis(2500),
            "eight saves took {:?}",
            t.elapsed()
        );
        let now = c.read(|s| s.pair_code_minutes);
        assert_eq!(
            Store::load(dir.path()).unwrap().unwrap().pair_code_minutes,
            now
        );
    }

    /// A save that waits for a slow disk holds no worker of the runtime: a
    /// task queued on the saving worker runs at once, not after the save,
    /// so the ports keep answering while the disk is slow (issue #150).
    #[test]
    fn a_slow_save_holds_no_runtime_worker() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        c.save_delay_ms.store(500, Ordering::SeqCst);
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let saver = rt.spawn(async move {
            let t = Instant::now();
            // Queued on this worker, which then saves.
            let other = tokio::spawn(async move { t.elapsed() });
            c.update(|s| s.pair_code_minutes = 11);
            other.await.unwrap()
        });
        let waited = rt.block_on(saver).unwrap();
        assert!(
            waited < Duration::from_millis(250),
            "a task waited {waited:?} for the save's worker"
        );
    }

    /// Runs the race of a covering write that fails (review round 2 of
    /// #150): `one` is being written (500 ms a write); `two` waits behind
    /// it; `four`, the newest, is saved by `save`; `two`'s write takes
    /// `four` and fails, as the folder is closed for it; an older snapshot
    /// (`three`, taken before `four`) reaches the queue only then. The save
    /// of `four` may not write `three` and report `four` as kept. Returns
    /// what that save returned and the name in the file.
    #[cfg(unix)]
    fn a_failed_covering_write(
        save: impl FnOnce(&Center) -> Result<(), String> + Send + 'static,
    ) -> (Result<(), String>, String) {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        c.save_delay_ms.store(500, Ordering::SeqCst);
        let t0 = Instant::now();
        let at = move |ms: u64| {
            std::thread::sleep(Duration::from_millis(ms).saturating_sub(t0.elapsed()))
        };
        let update = |name: &'static str| {
            let c = c.clone();
            std::thread::spawn(move || c.update(|s| s.center_name = name.into()))
        };
        let one = update("one");
        at(50);
        // Taken under the lock, and not at the queue yet.
        let late = {
            let mut s = c.store.lock().unwrap();
            s.center_name = "three".into();
            c.snapshot(&s)
        };
        at(100);
        let two = update("two");
        at(200);
        let q = {
            let c = c.clone();
            std::thread::spawn(move || save(&c))
        };
        at(700);
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        at(800);
        let older = {
            let c = c.clone();
            std::thread::spawn(move || c.write_snapshot(late))
        };
        at(1200);
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        one.join().unwrap();
        two.join().unwrap();
        let r = q.join().unwrap();
        let _ = older.join().unwrap();
        let on_disk = Store::load(dir.path()).unwrap().unwrap().center_name;
        (r, on_disk)
    }

    /// A save is only Ok when the file holds its snapshot or a newer one:
    /// after the write that took it away failed, it does not write an older
    /// snapshot in its place and report success.
    #[cfg(unix)]
    #[test]
    fn a_save_whose_covering_write_failed_does_not_write_an_older_one() {
        let (r, on_disk) = a_failed_covering_write(|c| {
            let mut s = c.store.lock().unwrap();
            s.center_name = "four".into();
            let snap = c.snapshot(&s);
            drop(s);
            c.write_snapshot(snap).map_err(|e| e.to_string())
        });
        assert!(
            r.is_err() || on_disk == "four",
            "the save of four returned Ok, but the file holds {on_disk:?}"
        );
    }

    /// The same race through `update_saved`: a change it reports as kept
    /// (a node's new key, say) is in the file, or it fails and is undone.
    #[cfg(unix)]
    #[test]
    fn update_saved_is_kept_before_it_is_told() {
        let (r, on_disk) = a_failed_covering_write(|c| {
            c.update_saved(|s| {
                s.center_name = "four".into();
                Ok(())
            })
        });
        assert!(
            r.is_err() || on_disk == "four",
            "update_saved returned Ok, but the file holds {on_disk:?}"
        );
    }

    /// Saves that finish out of order leave the newest state in the file:
    /// an older snapshot that comes to be written after a newer one is not.
    #[test]
    fn an_older_snapshot_never_replaces_a_newer_one() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let snap = |name: &str| {
            let mut s = c.store.lock().unwrap();
            s.center_name = name.into();
            c.snapshot(&s)
        };
        let (older, newer) = (snap("older"), snap("newer"));
        c.write_snapshot(newer).unwrap();
        c.write_snapshot(older).unwrap();
        let back = Store::load(dir.path()).unwrap().unwrap();
        assert_eq!(back.center_name, "newer");
        // A change after them is written as usual.
        c.update(|s| s.center_name = "latest".into());
        assert_eq!(
            Store::load(dir.path()).unwrap().unwrap().center_name,
            "latest"
        );
    }

    /// A session remembers at most `FETCHED_MAX` shown units: past it the
    /// one shown longest ago is forgotten, and one shown again is new again.
    #[test]
    fn a_session_forgets_the_units_it_was_shown_longest_ago() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let s = c.new_session("test");
        assert_eq!(s.listed_hash("n1", "fs.read"), None);
        s.listed("n1", "fs.read", 1);
        s.listed("n2", "fs.read", 2);
        assert_eq!(s.listed_hash("n1", "fs.read"), Some(1));
        assert_eq!(s.listed_hash("n2", "fs.read"), Some(2));
        assert_eq!(s.listed_hash("n1", "fs.write"), None);
        // Shown again, with what it is now.
        s.listed("n1", "fs.read", 3);
        for i in 0..FETCHED_MAX - 2 {
            s.listed("n3", &format!("c{i}.a"), 0);
        }
        // n2's fs.read is the oldest now, and goes first.
        assert_eq!(s.listed_hash("n2", "fs.read"), Some(2));
        s.listed("n3", "last.a", 0);
        assert_eq!(s.listed_hash("n2", "fs.read"), None);
        assert_eq!(s.listed_hash("n1", "fs.read"), Some(3));
        s.listed("n3", "after.a", 0);
        assert_eq!(s.listed_hash("n1", "fs.read"), None);
        assert_eq!(s.listed_hash("n3", "c0.a"), Some(0));
        let f = s.fetched.lock().unwrap();
        assert_eq!((f.hashes.len(), f.order.len()), (FETCHED_MAX, FETCHED_MAX));
    }

    /// The web UI's node and session lists read at the same time (two
    /// overview polls) do not deadlock: the session list held a session's
    /// node set while it named the nodes from the state, the node list held
    /// the state while it read every session's node set, and two requests
    /// that met that way stopped every runtime worker for good (issue #150).
    /// Both lists still say who uses what.
    #[test]
    fn the_node_and_session_lists_read_together_do_not_deadlock() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let ids: Vec<String> = (0..16).map(|i| format!("n{i}")).collect();
        c.update(|s| {
            for id in &ids {
                s.nodes.insert(id.clone(), node_record(id, "linux"));
            }
        });
        let sessions: Vec<Arc<Session>> = (0..16).map(|_| c.new_session("test")).collect();
        for s in &sessions {
            s.nodes.lock().unwrap().extend(ids.iter().cloned());
        }
        let (done, finished) = std::sync::mpsc::channel();
        for i in 0..4 {
            let (c, done) = (c.clone(), done.clone());
            std::thread::spawn(move || {
                for _ in 0..300 {
                    if i % 2 == 0 {
                        c.nodes_json();
                    } else {
                        c.sessions_json();
                    }
                }
                let _ = done.send(());
            });
        }
        for _ in 0..4 {
            finished
                .recv_timeout(Duration::from_secs(60))
                .expect("the node and session lists deadlocked");
        }
        let nodes = c.nodes_json();
        assert_eq!(nodes[0]["sessions"].as_array().unwrap().len(), 16);
        let list = c.sessions_json();
        assert_eq!(list[0]["nodes"].as_array().unwrap().len(), 16);
        assert_eq!(list[0]["nodes"][0], "n0");
    }

    /// The checker gate refuses a blocklisted command before the node, with a
    /// message that says the action checker did it; an ordinary command is
    /// not refused by it (it reaches the send instead, which fails on the
    /// test's link whose connection is gone). This is the whole point of the
    /// gate, so without it the blocklisted command would get the same end.
    #[tokio::test]
    async fn the_checker_refuses_a_blocklisted_command_before_the_node() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        c.update(|s| {
            s.nodes.insert("n1".into(), node_record("n1", "linux"));
        });
        online(&c, "n1");
        let sess = c.new_session("test");
        let args = |cmd: &str| {
            let mut m = Map::new();
            m.insert("command".into(), json!(cmd));
            m
        };
        // Blocklisted: refused by the checker.
        let e = c
            .call(&sess, &exec_route("n1"), args("rm -rf /"))
            .await
            .unwrap_err();
        let CallError::Rpc(e) = e;
        assert_eq!(e.kind(), ErrorCode::Forbidden);
        assert!(e.message.contains("action checker"), "{}", e.message);
        // The refusal is in the audit feed, marked as the checker's.
        let last = c.audit().pop().unwrap();
        assert_eq!(last["by"], "action checker");
        assert_eq!(last["checker"]["layer"], "blocklist");
        // Ordinary work passes the checker and is sent.
        let e = c
            .call(&sess, &exec_route("n1"), args("git status"))
            .await
            .unwrap_err();
        let CallError::Rpc(e) = e;
        assert_eq!(e.kind(), ErrorCode::ConnectionLost);
    }

    /// A program's action that takes a path is audited by the checker under
    /// that path, as the node's audit names it, not as `cap.action`; the
    /// model and the blocklist see the path too, and the model is told what
    /// the capability says it does.
    #[tokio::test]
    async fn the_audit_target_of_a_path_capability_is_its_path() {
        use crate::tools::tests::{cap, desc};
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let params = json!({"type": "object",
            "properties": {"path": {"type": "string", "x-nerve-path": "write"},
                           "text": {"type": "string"}}});
        let mut notes = cap(
            "notes",
            "notes",
            &[("save", nerve_proto::Effect::Write, params)],
        );
        notes.provider = "notesd".into();
        c.update(|s| {
            let mut n = node_record("n1", "linux");
            n.set_descriptor(desc("n1", vec![notes]));
            s.nodes.insert("n1".into(), n);
            s.checker.allow_rules.push(AllowRule {
                rule: "notes.save".into(),
                node_id: None,
            });
        });
        c.rebuild_checker();
        online(&c, "n1");
        let sess = c.new_session("test");
        let route = Route {
            node_id: "n1".into(),
            node_name: "n1".into(),
            cap: "notes".into(),
            action: "save".into(),
            effect: nerve_proto::Effect::Write,
        };
        let save = |path: &str| {
            let mut m = Map::new();
            m.insert("path".into(), json!(path));
            m.insert("text".into(), json!("hello"));
            m
        };
        // Into an ordinary file: the allow rule lets it go to the node, and
        // the audit names the file.
        let CallError::Rpc(e) = c
            .call(&sess, &route, save("/home/me/notes/today.md"))
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorCode::ConnectionLost, "{}", e.message);
        let last = c.audit().pop().unwrap();
        assert_eq!(last["checker"]["layer"], "allow rule");
        assert_eq!(last["target"], "/home/me/notes/today.md");
        // Into the SSH keys: the `fs.write` entry refuses it, under the path.
        let CallError::Rpc(e) = c
            .call(&sess, &route, save("/home/me/.ssh/authorized_keys"))
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorCode::Forbidden, "{}", e.message);
        let last = c.audit().pop().unwrap();
        assert_eq!(last["checker"]["layer"], "blocklist");
        assert_eq!(last["target"], "/home/me/.ssh/authorized_keys");
        // What the checker is shown of the unit.
        let seen = c.read(|s| CheckerUnit::of(&s.nodes["n1"], &route));
        assert_eq!(seen.description, "save: save it (notes summary)");
        assert_eq!(
            seen.paths(&save("/x")),
            vec![(PathMark::Write, "/x".to_string())]
        );
    }

    /// The model is sent what the center's catalog says of the unit and the
    /// path the call names: a real call through `Center::call` to a fake
    /// System One endpoint, and the state it received is read back.
    #[tokio::test]
    async fn the_model_is_sent_a_provider_calls_effect_description_and_path() {
        use crate::tools::tests::{cap, desc};
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let asked = std::thread::spawn(move || {
            // A call that never asks the model fails the test, not hangs it.
            let started = Instant::now();
            let mut conn = loop {
                match listener.accept() {
                    Ok((conn, _)) => break conn,
                    Err(_) if started.elapsed() < Duration::from_secs(10) => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => return Value::Null,
                }
            };
            conn.set_nonblocking(false).unwrap();
            conn.set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            let body = loop {
                let n = conn.read(&mut buf).unwrap();
                got.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&got).into_owned();
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let want = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length: ")?
                                .parse()
                                .ok()
                        })
                        .unwrap_or(0usize);
                    if body.len() >= want {
                        break body.to_string();
                    }
                }
            };
            let answer = r#"{"answers":{"danger":{"type":"noul","noul":0.01}}}"#;
            let _ = write!(
                conn,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                answer.len()
            );
            serde_json::from_str::<Value>(&body).unwrap()
        });
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let params = json!({"type": "object",
            "properties": {"path": {"type": "string", "x-nerve-path": "write"},
                           "text": {"type": "string"}}});
        let mut notes = cap(
            "notes",
            "notes",
            &[("save", nerve_proto::Effect::Write, params)],
        );
        notes.provider = "notesd".into();
        c.update(|s| {
            let mut n = node_record("n1", "linux");
            n.set_descriptor(desc("n1", vec![notes]));
            s.nodes.insert("n1".into(), n);
            s.checker.model_on = true;
            s.checker.model.source = ModelSource::Endpoint;
            s.checker.model.endpoint_url = format!("http://127.0.0.1:{port}");
        });
        c.rebuild_checker();
        online(&c, "n1");
        let sess = c.new_session("test");
        let route = Route {
            node_id: "n1".into(),
            node_name: "n1".into(),
            cap: "notes".into(),
            action: "save".into(),
            effect: nerve_proto::Effect::Write,
        };
        let mut args = Map::new();
        args.insert("path".into(), json!("/home/me/notes/today.md"));
        args.insert("text".into(), json!("hello"));
        // The fake model scores it low, so the call goes on to the (test)
        // link, which is gone.
        let CallError::Rpc(e) = c.call(&sess, &route, args).await.unwrap_err();
        assert_eq!(e.kind(), ErrorCode::ConnectionLost, "{}", e.message);
        let body = asked.join().unwrap();
        let state = &body["state"];
        assert_eq!(state["capability"], "notes");
        assert_eq!(state["action"], "save");
        assert_eq!(state["effect"], "write");
        assert_eq!(state["description"], "save: save it (notes summary)");
        assert_eq!(state["target"], "/home/me/notes/today.md");
        assert!(state["args"].as_str().unwrap().contains("hello"), "{state}");
        let last = c.audit().pop().unwrap();
        assert_eq!(last["checker"]["layer"], "model");
        assert_eq!(last["target"], "/home/me/notes/today.md");
    }

    /// An `exec.run` command's working folder is a path it reads, so an
    /// `fs.read` entry on that folder refuses the command, and the audit
    /// still names the command.
    #[tokio::test]
    async fn a_commands_working_folder_meets_the_fs_read_entries() {
        use crate::tools::tests::{cap, desc};
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let params = json!({"type": "object",
            "properties": {"command": {"type": "string"},
                           "cwd": {"type": "string", "x-nerve-path": "read"}}});
        let exec = cap(
            "exec",
            "exec",
            &[("run", nerve_proto::Effect::Execute, params)],
        );
        c.update(|s| {
            let mut n = node_record("n1", "linux");
            n.set_descriptor(desc("n1", vec![exec]));
            s.nodes.insert("n1".into(), n);
            s.checker.blocklist.push(checker::BlockEntry {
                id: String::new(),
                rule: "fs.read:/srv/secret/*".into(),
                on: true,
                builtin: false,
                note: String::new(),
                node_id: None,
                off_for: Vec::new(),
            });
        });
        c.rebuild_checker();
        online(&c, "n1");
        let sess = c.new_session("test");
        let mut args = Map::new();
        args.insert("command".into(), json!("make test"));
        args.insert("cwd".into(), json!("/srv/secret/work"));
        let CallError::Rpc(e) = c.call(&sess, &exec_route("n1"), args).await.unwrap_err();
        assert_eq!(e.kind(), ErrorCode::Forbidden, "{}", e.message);
        assert!(
            e.message.contains("path argument /srv/secret/work"),
            "{}",
            e.message
        );
        let last = c.audit().pop().unwrap();
        assert_eq!(last["checker"]["layer"], "blocklist");
        assert_eq!(last["target"], "make test");
    }

    /// A unit without a summary of its own carries its capability's, which
    /// the checker shows once, however the summary is spaced.
    #[test]
    fn a_capability_summary_is_not_repeated_for_a_unit_without_its_own() {
        use crate::tools::tests::{cap, desc};
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let mut lamp = cap(
            "lamp",
            "lamp",
            &[(
                "set",
                nerve_proto::Effect::Actuate,
                json!({"type": "object"}),
            )],
        );
        lamp.summary = "The office lamp.  Turns it on\n\nor off.".into();
        lamp.actions.get_mut("set").unwrap().summary = String::new();
        c.update(|s| {
            let mut n = node_record("n1", "linux");
            n.set_descriptor(desc("n1", vec![lamp]));
            s.nodes.insert("n1".into(), n);
        });
        let route = Route {
            node_id: "n1".into(),
            node_name: "n1".into(),
            cap: "lamp".into(),
            action: "set".into(),
            effect: nerve_proto::Effect::Actuate,
        };
        let seen = c.read(|s| CheckerUnit::of(&s.nodes["n1"], &route));
        assert_eq!(seen.description, "The office lamp.  Turns it on  or off.");
    }

    /// A capability summary longer than the model's state carries must not
    /// push out what the action itself does: that part goes first.
    #[test]
    fn a_long_capability_summary_does_not_crowd_out_the_actions_text() {
        use crate::tools::tests::{cap, desc};
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let mut door = cap(
            "door",
            "door",
            &[(
                "unlock",
                nerve_proto::Effect::Actuate,
                json!({"type": "object"}),
            )],
        );
        door.summary = "The front door. ".repeat(30);
        door.actions.get_mut("unlock").unwrap().summary = "Unlocks it for a given time.".into();
        c.update(|s| {
            let mut n = node_record("n1", "linux");
            n.set_descriptor(desc("n1", vec![door]));
            s.nodes.insert("n1".into(), n);
        });
        let route = Route {
            node_id: "n1".into(),
            node_name: "n1".into(),
            cap: "door".into(),
            action: "unlock".into(),
            effect: nerve_proto::Effect::Actuate,
        };
        let seen = c.read(|s| CheckerUnit::of(&s.nodes["n1"], &route));
        assert!(seen.description.len() > checker::STATE_DESCRIPTION_MAX);
        let args = Map::new();
        let info = checker::CallInfo {
            cap: "door",
            action: "unlock",
            effect: nerve_proto::Effect::Actuate,
            description: &seen.description,
            target: "door.unlock",
            paths: &[],
            args: &args,
            node_id: "n1",
            os: "linux",
            tainted: false,
        };
        let state = checker::model_state(&info);
        assert!(
            state["description"]
                .as_str()
                .unwrap()
                .starts_with("unlock: Unlocks it for a given time."),
            "{}",
            state["description"]
        );
    }

    /// A pattern that cannot match anything is refused when the owner saves
    /// it, and one already stored is left out of the checker and reported.
    #[test]
    fn a_rule_that_cannot_match_is_refused_on_save_and_reported_when_stored() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let entry = |rule: &str| checker::BlockEntry {
            id: String::new(),
            rule: rule.into(),
            on: true,
            builtin: false,
            note: String::new(),
            node_id: None,
            off_for: Vec::new(),
        };
        let mut cfg = c.read(|s| s.checker.clone());
        cfg.blocklist.push(entry("lamp.set:office"));
        let why = c.apply_checker_config(cfg).unwrap_err();
        assert!(why.contains("cannot match anything"), "{why}");
        let mut cfg = c.read(|s| s.checker.clone());
        cfg.allow_rules.push(AllowRule {
            rule: "exec:rm *".into(),
            node_id: None,
        });
        let why = c.apply_checker_config(cfg).unwrap_err();
        assert!(why.contains("exec.run:rm *"), "{why}");
        // Stored by an older center: out of force, and named on the page.
        c.update(|s| s.checker.blocklist.push(entry("lamp.set:office")));
        c.rebuild_checker();
        let rejected = c.checker_json()["rejected"].clone();
        assert_eq!(rejected.as_array().unwrap().len(), 1, "{rejected}");
        assert!(rejected[0].as_str().unwrap().contains("lamp.set:office"));
        assert!(c.checker().rejected[0].contains("lamp.set:office"));
    }

    /// An `fs` entry holds the path arguments of other capabilities, so it
    /// is not called dead where a program takes a path for it, `fs`
    /// published or not; a typo and an entry no path argument can meet are.
    #[test]
    fn an_fs_entry_is_in_force_where_a_program_takes_a_path() {
        use crate::tools::tests::{cap, desc};
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let entry = |rule: &str| checker::BlockEntry {
            id: String::new(),
            rule: rule.into(),
            on: true,
            builtin: false,
            note: String::new(),
            node_id: None,
            off_for: Vec::new(),
        };
        let params = json!({"type": "object",
            "properties": {"path": {"type": "string", "x-nerve-path": "write"}}});
        let mut notes = cap(
            "notes",
            "notes",
            &[("save", nerve_proto::Effect::Write, params)],
        );
        notes.provider = "notesd".into();
        c.update(|s| {
            let mut n = node_record("n1", "linux");
            n.set_descriptor(desc("n1", vec![notes]));
            s.nodes.insert("n1".into(), n);
            s.checker.blocklist.extend([
                entry("fs.write:/home/*/.config/autostart/*"),
                entry("fs:/srv/*"),
                entry("fs.read:/srv/secret/*"),
                entry("fs.wirte:/etc/*"),
            ]);
            // An allow rule is matched against a call's own target only, so
            // a path argument does not put it in force.
            s.checker.allow_rules.push(AllowRule {
                rule: "fs.write:/home/*/notes/*".into(),
                node_id: None,
            });
        });
        // The program writes a path; nothing reads one, and `fs` is not
        // published here.
        assert_eq!(
            c.checker_json()["unpublished"],
            json!([
                "fs.read:/srv/secret/*",
                "fs.wirte:/etc/*",
                "fs.write:/home/*/notes/*"
            ])
        );
    }

    /// The checker page is told which of the owner's rules name a
    /// capability or action no paired node publishes (for a rule of one
    /// node, that node), and none while no node has published anything.
    #[test]
    fn a_rule_naming_a_capability_no_node_publishes_is_warned_about() {
        use crate::tools::tests::{cap, desc};
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let rule = |r: &str, node: Option<&str>| AllowRule {
            rule: r.into(),
            node_id: node.map(str::to_string),
        };
        c.update(|s| {
            s.nodes.insert("n1".into(), node_record("n1", "linux"));
            s.nodes.insert("n2".into(), node_record("n2", "linux"));
            s.checker.allow_rules = vec![
                rule("lamp.set", None),
                rule("lamp.sett", None),
                rule("lamp", Some("n2")),
                rule("notes", None),
                rule("exec.run:make *", None),
            ];
            s.checker.blocklist.push(checker::BlockEntry {
                id: String::new(),
                rule: "fs.wirte:/etc/*".into(),
                on: true,
                builtin: false,
                note: String::new(),
                node_id: None,
                off_for: Vec::new(),
            });
        });
        assert_eq!(c.checker_json()["unpublished"], json!([]));
        let lamp = cap(
            "lamp",
            "lamp",
            &[("set", nerve_proto::Effect::Actuate, json!({}))],
        );
        let exec = cap(
            "exec",
            "exec",
            &[("run", nerve_proto::Effect::Execute, json!({}))],
        );
        c.update(|s| {
            let n1 = s.nodes.get_mut("n1").unwrap();
            n1.set_descriptor(desc("n1", vec![lamp, exec]));
        });
        assert_eq!(
            c.checker_json()["unpublished"],
            json!(["fs.wirte:/etc/*", "lamp.sett", "lamp", "notes"])
        );
    }

    /// A call to a node that is offline or disabled is `unavailable` before
    /// the checker runs: with the model on, unreachable and failing closed,
    /// it is not refused as `forbidden`, and no checker decision is audited.
    /// Once the node is online the same call reaches the checker, which
    /// refuses and audits it as before.
    #[tokio::test]
    async fn an_offline_or_disabled_node_is_unavailable_before_the_checker() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        c.update(|s| {
            s.nodes.insert("n1".into(), node_record("n1", "linux"));
            s.checker.model_on = true;
            s.checker.model.source = ModelSource::Endpoint;
            s.checker.model.endpoint_url = String::new();
        });
        c.rebuild_checker();
        let sess = c.new_session("test");
        let call = || {
            let mut args = Map::new();
            args.insert("command".into(), json!("echo hi > out.txt"));
            let (c, sess) = (&c, &sess);
            async move {
                let CallError::Rpc(e) = c.call(sess, &exec_route("n1"), args).await.unwrap_err();
                e
            }
        };
        let audited = || {
            c.audit()
                .iter()
                .filter(|e| e["by"] == "action checker")
                .count()
        };
        let e = call().await;
        assert_eq!(e.kind(), ErrorCode::Unavailable, "{}", e.message);
        assert!(e.message.contains("offline"), "{}", e.message);
        assert_eq!(audited(), 0);

        online(&c, "n1");
        c.update(|s| s.nodes.get_mut("n1").unwrap().disabled = true);
        let e = call().await;
        assert_eq!(e.kind(), ErrorCode::Unavailable, "{}", e.message);
        assert!(e.message.contains("disabled"), "{}", e.message);
        assert_eq!(audited(), 0);

        c.update(|s| s.nodes.get_mut("n1").unwrap().disabled = false);
        let e = call().await;
        assert_eq!(e.kind(), ErrorCode::Forbidden, "{}", e.message);
        assert!(e.message.contains("reach"), "{}", e.message);
        assert_eq!(audited(), 1);
    }

    /// A job's `exec.signal` goes only on the link its call runs on: the
    /// `invoke` id it names is that link's, and on the node's newer link it
    /// would name another call.
    #[tokio::test]
    async fn a_jobs_signal_goes_on_its_own_link_only() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        c.update(|s| {
            s.nodes.insert("n1".into(), node_record("n1", "linux"));
        });
        online(&c, "n1");
        let sess = c.new_session("test");
        let mut route = exec_route("n1");
        route.action = "signal".into();
        route.effect = nerve_proto::Effect::Actuate;
        let mut args = Map::new();
        args.insert("call".into(), json!(1));
        args.insert("signal".into(), json!("term"));
        let old = Arc::new(Link::for_test("n1"));
        let Ran::Done(Err(CallError::Rpc(e))) =
            c.run(&sess, &route, args.clone(), Some(old), None).await
        else {
            panic!("refused")
        };
        assert_eq!(e.kind(), ErrorCode::InvalidArgs, "{}", e.message);
        assert!(e.message.contains("no longer runs"), "{}", e.message);
        // On its own link it is sent (and this test link has lost it).
        let own = c.link("n1");
        let Ran::Done(Err(CallError::Rpc(e))) = c.run(&sess, &route, args, own, None).await else {
            panic!("sent")
        };
        assert_eq!(e.kind(), ErrorCode::ConnectionLost, "{}", e.message);
    }

    /// The result of a job nobody reads is forgotten after `KEEP_FOR` by a
    /// timer of its own: no later call of the session is needed for it. Its
    /// output stream goes with it.
    #[tokio::test(start_paused = true)]
    async fn an_unread_jobs_result_is_forgotten_without_another_call() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        c.update(|s| {
            s.nodes.insert("n1".into(), node_record("n1", "linux"));
        });
        online(&c, "n1");
        let sess = c.new_session("test");
        // With no wait the call is a job before its task runs; it ends at
        // once, since this test link has lost it.
        let ran = c
            .run(
                &sess,
                &exec_route("n1"),
                Map::new(),
                None,
                Some(Duration::ZERO),
            )
            .await;
        let Ran::Job(job) = ran else {
            panic!("{ran:?}")
        };
        let ring = Arc::new(crate::streams::Ring::default());
        assert!(
            sess.streams
                .lock()
                .unwrap()
                .add("s-1", "n1", &job, ring.clone())
        );
        while sess.jobs.lock().unwrap().running() > 0 {
            tokio::task::yield_now().await;
        }
        let held = || sess.jobs.lock().unwrap().held();
        let streams = || sess.streams.lock().unwrap().len();
        assert_eq!((held(), streams()), (1, 1), "its result is kept");
        tokio::time::sleep(jobs::KEEP_FOR - Duration::from_secs(1)).await;
        assert_eq!((held(), streams()), (1, 1), "for ten minutes");
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!((held(), streams()), (0, 0), "then forgotten");
        let r = ring.read(64);
        assert_eq!(r.why.as_deref(), Some("its job was forgotten"));
    }

    /// The owner's note on a machine is kept on one line, refused when long,
    /// shown by `list()` for that machine only, and outlives the machine's
    /// pairing like its other settings; a note of blanks is no setting.
    #[test]
    fn the_owners_note_shows_for_its_node_only_and_survives_forget() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        c.update(|s| {
            s.nodes.insert("n1".into(), node_record("n1", "linux"));
            s.nodes.insert("n2".into(), node_record("n2", "linux"));
        });
        let with = |id: &str, note: &str| {
            let mut cfg = c.read(|s| s.checker.clone());
            cfg.nodes.insert(
                id.into(),
                NodeSettings {
                    note: note.into(),
                    ..Default::default()
                },
            );
            cfg
        };
        c.apply_checker_config(with("n1", "  test VM;\nits databases hold throwaway data "))
            .unwrap();
        let notes = || -> Vec<(String, Option<String>)> {
            c.listed_nodes()
                .into_iter()
                .map(|n| (n.id, n.note))
                .collect()
        };
        let n1 = Some("test VM; its databases hold throwaway data".to_string());
        assert_eq!(
            notes(),
            [("n1".to_string(), n1.clone()), ("n2".to_string(), None)]
        );
        // Too long is refused as a whole, and names the machine.
        let e = c
            .apply_checker_config(with("n2", &"x".repeat(checker::config::NOTE_MAX + 1)))
            .unwrap_err();
        assert!(e.contains("machine n2") && e.contains("at most 400"), "{e}");
        assert_eq!(notes()[1].1, None);
        let mut both = with("n2", &"x".repeat(checker::config::NOTE_MAX));
        both.nodes.insert(
            "n3".into(),
            NodeSettings {
                note: " \n ".into(),
                ..Default::default()
            },
        );
        c.apply_checker_config(both).unwrap();
        let kept = c.read(|s| s.checker.nodes.clone());
        assert_eq!(kept.keys().collect::<Vec<_>>(), ["n1", "n2"]);
        // Unpaired and paired again, the machine has its note back.
        c.forget("n1", "test");
        assert_eq!(notes().len(), 1);
        assert_eq!(
            c.read(|s| s.checker.nodes["n1"].note.clone()),
            n1.clone().unwrap()
        );
        c.update(|s| {
            s.nodes.insert("n1".into(), node_record("n1", "linux"));
        });
        assert_eq!(notes()[0], ("n1".to_string(), n1));
    }

    /// A block entry for one node and a global entry switched off for
    /// another: each node gets what the owner set for it, and the audit says
    /// whether the entry was the global one or the node's. A posted config
    /// with an exception on a one-node entry is refused, and nodes that only
    /// inherit are not kept.
    #[tokio::test]
    async fn per_node_block_entries_are_audited_with_their_scope() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        c.update(|s| {
            s.nodes.insert("n1".into(), node_record("n1", "linux"));
            s.nodes.insert("n2".into(), node_record("n2", "linux"));
        });
        online(&c, "n1");
        online(&c, "n2");
        let mut cfg = c.read(|s| s.checker.clone());
        let mut tf = cfg.blocklist[0].clone();
        tf.rule = "exec.run:terraform destroy".into();
        tf.builtin = false;
        tf.node_id = Some("n1".into());
        cfg.blocklist.push(tf.clone());
        cfg.blocklist
            .iter_mut()
            .find(|e| e.rule == "exec.run:rm -rf /")
            .unwrap()
            .off_for = vec!["n2".into(), "n2".into()];
        cfg.nodes.insert("n2".into(), NodeSettings::default());
        // An exception on a one-node entry is refused as a whole.
        let mut bad = cfg.clone();
        bad.blocklist.last_mut().unwrap().off_for.push("n2".into());
        assert!(c.apply_checker_config(bad).is_err());
        c.apply_checker_config(cfg).unwrap();
        let kept = c.read(|s| s.checker.clone());
        assert!(kept.nodes.is_empty(), "{:?}", kept.nodes);
        assert_eq!(
            kept.blocklist
                .iter()
                .find(|e| e.rule == "exec.run:rm -rf /")
                .unwrap()
                .off_for,
            ["n2"]
        );
        let sess = c.new_session("test");
        let run = |node: &'static str, cmd: &'static str| {
            let c = &c;
            let sess = &sess;
            async move {
                let mut m = Map::new();
                m.insert("command".into(), json!(cmd));
                let CallError::Rpc(e) = c.call(sess, &exec_route(node), m).await.unwrap_err();
                e
            }
        };
        let e = run("n1", "terraform destroy").await;
        assert_eq!(e.kind(), ErrorCode::Forbidden);
        assert!(
            e.message.contains("this node's own blocklist"),
            "{}",
            e.message
        );
        let last = c.audit().pop().unwrap();
        assert_eq!(last["checker"]["scope"], "node");
        assert_eq!(last["checker"]["detail"], "exec.run:terraform destroy");
        let e = run("n1", "rm -rf /").await;
        assert_eq!(e.kind(), ErrorCode::Forbidden);
        assert_eq!(c.audit().pop().unwrap()["checker"]["scope"], "global");
        // n2: no entry of its own, and `rm -rf /` switched off for it, so
        // both are sent to the node.
        assert_eq!(
            run("n2", "terraform destroy").await.kind(),
            ErrorCode::ConnectionLost
        );
        assert_eq!(
            run("n2", "rm -rf /").await.kind(),
            ErrorCode::ConnectionLost
        );
    }

    /// What the Action checker page reads: whether the model is on anywhere,
    /// also when only one machine has it on (so the page tells "its server
    /// is not running" from "turn the model on"), and the whole blocklist
    /// with the built-ins in full. A post of that config is taken back as is
    /// and saved as the owner's part only.
    #[test]
    fn the_checker_page_reads_the_model_on_for_one_machine_and_the_whole_list() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let v = c.checker_json();
        assert_eq!(v["model_wanted"], false);
        let list = v["config"]["blocklist"].as_array().unwrap();
        assert_eq!(list.len(), checker::config::default_blocklist().len());
        assert_eq!(list[0]["id"], "rm-root");
        assert_eq!(list[0]["builtin"], true);

        c.update(|s| {
            s.checker.nodes.insert(
                "n1".into(),
                NodeSettings {
                    blocklist: NodeSwitch::Inherit,
                    model: NodeSwitch::On,
                    ..Default::default()
                },
            );
        });
        let v = c.checker_json();
        assert_eq!(v["config"]["model_on"], false);
        assert_eq!(v["model_wanted"], true);

        // The page posts the list back with one built-in switched off.
        let mut config = v["config"].clone();
        config["blocklist"][0]["on"] = json!(false);
        let cfg: CheckerConfig = serde_json::from_value(config).unwrap();
        c.apply_checker_config(cfg).unwrap();
        let v = c.checker_json();
        assert_eq!(v["config"]["blocklist"][0]["on"], false);
        let saved: Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("state.json")).unwrap()).unwrap();
        assert_eq!(
            saved["checker"]["blocklist"],
            json!({"builtins": {"rm-root": {"on": false}}})
        );
    }

    /// A command line nested too deeply for the splitter is refused by the
    /// gate (fail closed), not passed to the node (review r1, finding 1).
    #[tokio::test]
    async fn the_checker_refuses_a_command_line_it_cannot_take_apart() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        c.update(|s| {
            s.nodes.insert("n1".into(), node_record("n1", "linux"));
        });
        online(&c, "n1");
        let sess = c.new_session("test");
        let mut args = Map::new();
        args.insert(
            "command".into(),
            json!(format!("echo {}", "$(".repeat(50_000))),
        );
        let e = c.call(&sess, &exec_route("n1"), args).await.unwrap_err();
        let CallError::Rpc(e) = e;
        assert_eq!(e.kind(), ErrorCode::Forbidden);
        assert!(e.message.contains("nests more than"), "{}", e.message);
    }

    /// With the model on but no endpoint set, the checker fails closed: a
    /// write call is refused because the model is unreachable.
    #[tokio::test]
    async fn the_model_fails_closed_when_it_cannot_be_reached() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        c.update(|s| {
            s.nodes.insert("n1".into(), node_record("n1", "linux"));
            s.checker.model_on = true;
            // An endpoint source with no URL: nothing to reach.
            s.checker.model.source = ModelSource::Endpoint;
            s.checker.model.endpoint_url = String::new();
        });
        c.rebuild_checker();
        online(&c, "n1");
        let sess = c.new_session("test");
        let mut args = Map::new();
        args.insert("command".into(), json!("echo hi > out.txt"));
        let e = c.call(&sess, &exec_route("n1"), args).await.unwrap_err();
        let CallError::Rpc(e) = e;
        assert_eq!(e.kind(), ErrorCode::Forbidden);
        assert!(e.message.contains("reach"), "{}", e.message);
    }

    /// A fake release server for the install: the one connection it takes
    /// gets a head that promises 1000 bytes and ten of them, then nothing
    /// until the returned sender fires, when the connection is closed (so the
    /// download fails as cut short).
    #[cfg(unix)]
    fn held_download() -> (String, std::sync::mpsc::Sender<()>) {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            if let Some(Ok(mut c)) = l.incoming().next() {
                let mut buf = [0u8; 4096];
                let _ = c.read(&mut buf);
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n0123456789");
                let _ = rx.recv_timeout(Duration::from_secs(25));
            }
        });
        (format!("http://127.0.0.1:{port}"), tx)
    }

    /// An installed CPU build that is the fake `llama-server` (it answers as
    /// a decision model), with a d1-3B file it ignores.
    #[cfg(unix)]
    fn install_fake_build(state: &Path) {
        let bin = checker::install::llama_dir(state).join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        checker::server::fake::fake_llama_server(&bin);
        std::fs::write(bin.parent().unwrap().join("variant"), "cpu").unwrap();
        let model = checker::install::model_path(state, LocalModel::D1_3b);
        std::fs::create_dir_all(model.parent().unwrap()).unwrap();
        std::fs::write(model, b"x").unwrap();
    }

    /// Waits up to 20 s for `f`.
    #[cfg(unix)]
    async fn until(what: &str, mut f: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !f() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    #[cfg(unix)]
    fn local_ready(c: &Center) -> bool {
        c.local_model_status()
            .is_some_and(|s| s.phase == checker::server::Phase::Ready)
    }

    /// A center with the fake build installed and the local model on and
    /// ready.
    #[cfg(unix)]
    async fn center_with_a_running_model(dir: &Path) -> Center {
        install_fake_build(dir);
        let c = open(dir, None);
        c.update(|s| {
            s.checker.model_on = true;
            s.checker.model.source = ModelSource::Local;
        });
        c.rebuild_checker();
        until("the model to be ready", || local_ready(&c)).await;
        c
    }

    /// The local model runs when only a node has the model on, and Remove
    /// switches it off there too, so that node does not refuse every call
    /// for want of a model.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_node_with_the_model_on_runs_the_local_model_until_remove() {
        tokio::time::timeout(Duration::from_secs(60), async {
            let dir = tempfile::tempdir().unwrap();
            install_fake_build(dir.path());
            let c = open(dir.path(), None);
            c.update(|s| {
                s.checker.model_on = false;
                s.checker.model.source = ModelSource::Local;
                s.checker.nodes.insert(
                    "n1".into(),
                    NodeSettings {
                        blocklist: NodeSwitch::Off,
                        model: NodeSwitch::On,
                        ..Default::default()
                    },
                );
            });
            c.rebuild_checker();
            until("the model to be ready", || local_ready(&c)).await;
            c.remove_checker_model().await.unwrap();
            assert!(c.local_model_status().is_none());
            let n1 = c.read(|s| s.checker.nodes.get("n1").cloned());
            assert_eq!(
                n1,
                Some(NodeSettings {
                    blocklist: NodeSwitch::Off,
                    model: NodeSwitch::Inherit,
                    ..Default::default()
                })
            );
        })
        .await
        .expect("the test did not finish within 60 s");
    }

    /// A config save that only toggles taint.
    #[cfg(unix)]
    fn save_unrelated_change(c: &Center) {
        let mut cfg = c.read(|s| s.checker.clone());
        cfg.taint_on = !cfg.taint_on;
        c.apply_checker_config(cfg).unwrap();
    }

    /// An install keeps the running model judging calls while it downloads,
    /// a config save meanwhile does not disturb it, and a failed install
    /// leaves the working model installed and running (review r3, findings 2
    /// and 3).
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_install_keeps_the_model_running_until_its_swap() {
        tokio::time::timeout(Duration::from_secs(60), async {
            let dir = tempfile::tempdir().unwrap();
            let c = center_with_a_running_model(dir.path()).await;
            let (base, release) = held_download();
            *c.install_from.lock().unwrap() = Arc::new(checker::install::Sources::at(&base));
            // The switch to the GPU build starts downloading.
            c.start_checker_install(true, LocalModel::D1_3b)
                .await
                .unwrap();
            until("the download to start", || {
                c.checker_install_status().llama.done >= 10
            })
            .await;
            assert!(local_ready(&c), "the model was stopped for the download");
            save_unrelated_change(&c);
            assert!(local_ready(&c), "a config save disturbed the running model");
            // The download fails: the CPU build is kept and still runs.
            release.send(()).unwrap();
            until("the install to fail", || {
                c.checker_install_status().phase == checker::install::Phase::Failed
            })
            .await;
            assert_eq!(checker::install::installed_variant(dir.path()), Some(false));
            until("the model to run again", || local_ready(&c)).await;
        })
        .await
        .expect("the test did not finish within 60 s");
    }

    /// A fake Hugging Face that answers each of two downloads with `body`.
    #[cfg(unix)]
    fn serve_model(body: &'static [u8]) -> String {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for c in l.incoming().take(2) {
                let Ok(mut c) = c else { continue };
                let mut buf = [0u8; 4096];
                let _ = c.read(&mut buf);
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = c.write_all(head.as_bytes());
                let _ = c.write_all(body);
            }
        });
        format!("http://127.0.0.1:{port}")
    }

    /// An install that reaches its swap brings the local server back: after
    /// a successful switch it runs the new model, and after a swap that fails
    /// the model it had (review r4, finding 6). The install stopped the
    /// server for the swap, so only its closing rebuild starts it again.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_install_brings_the_model_back_after_its_swap() {
        tokio::time::timeout(Duration::from_secs(60), async {
            let dir = tempfile::tempdir().unwrap();
            let c = center_with_a_running_model(dir.path()).await;
            const MODEL: &[u8] = b"a small stand-in for the model file";
            let base = serve_model(MODEL);
            *c.install_from.lock().unwrap() =
                Arc::new(checker::install::Sources::with_model(&base, MODEL));
            let phase = |c: &Center| c.checker_install_status().phase;
            // The switch to Kev-4B keeps the CPU build and swaps the model.
            c.start_checker_install(false, LocalModel::Kev4b)
                .await
                .unwrap();
            until("the install to finish", || {
                phase(&c) == checker::install::Phase::Done
            })
            .await;
            assert_eq!(c.read(|s| s.checker.model.local_model), LocalModel::Kev4b);
            assert!(!checker::install::model_path(dir.path(), LocalModel::D1_3b).exists());
            until("the new model to run", || local_ready(&c)).await;
            // A swap that fails: something is in the way where d1-3B's file
            // goes.
            let d1 = checker::install::model_path(dir.path(), LocalModel::D1_3b);
            std::fs::create_dir_all(d1.join("in-the-way")).unwrap();
            c.start_checker_install(false, LocalModel::D1_3b)
                .await
                .unwrap();
            until("the install to fail", || {
                phase(&c) == checker::install::Phase::Failed
            })
            .await;
            let st = c.checker_install_status();
            assert!(
                st.message.contains("put the model in place"),
                "{}",
                st.message
            );
            assert_eq!(c.read(|s| s.checker.model.local_model), LocalModel::Kev4b);
            until("the model it had to run again", || local_ready(&c)).await;
        })
        .await
        .expect("the test did not finish within 60 s");
    }

    /// While an install swaps the files (or Remove deletes them), a config
    /// save does not start the server from them; it starts again once they
    /// are free (review r3, finding 3).
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_config_save_does_not_start_the_model_while_its_files_are_held() {
        tokio::time::timeout(Duration::from_secs(60), async {
            let dir = tempfile::tempdir().unwrap();
            let c = center_with_a_running_model(dir.path()).await;
            let held = c.hold_local_files().await;
            assert!(c.local_model_status().is_none());
            save_unrelated_change(&c);
            assert!(
                c.local_model_status().is_none(),
                "a config save started the server during the swap"
            );
            drop(held);
            c.rebuild_checker();
            until("the model to run again", || local_ready(&c)).await;
        })
        .await
        .expect("the test did not finish within 60 s");
    }

    /// Remove during a stalled download ends the install at once, and
    /// nothing of that install lands afterwards: its status stays reset and
    /// no file comes back (review r3, finding 5).
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn remove_ends_a_stalled_install_for_good() {
        tokio::time::timeout(Duration::from_secs(60), async {
            let dir = tempfile::tempdir().unwrap();
            let c = open(dir.path(), None);
            let (base, release) = held_download();
            *c.install_from.lock().unwrap() = Arc::new(checker::install::Sources::at(&base));
            c.start_checker_install(false, LocalModel::D1_3b)
                .await
                .unwrap();
            until("the download to start", || {
                c.checker_install_status().llama.done >= 10
            })
            .await;
            let t = Instant::now();
            c.remove_checker_model().await.unwrap();
            assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
            assert_eq!(
                c.checker_install_status().phase,
                checker::install::Phase::Idle
            );
            // A second install starts while the first one's connection is
            // still open and silent.
            let (base2, release2) = held_download();
            *c.install_from.lock().unwrap() = Arc::new(checker::install::Sources::at(&base2));
            c.start_checker_install(false, LocalModel::D1_3b)
                .await
                .unwrap();
            until("the second download to start", || {
                c.checker_install_status().llama.done >= 10
            })
            .await;
            // The first connection now ends. A first task still waiting on it
            // would fail, clean up the staging folder the second one is
            // using, and could write its failure into the second's status.
            let _ = release.send(());
            tokio::time::sleep(Duration::from_millis(500)).await;
            let st = c.checker_install_status();
            assert_eq!(
                st.phase,
                checker::install::Phase::Downloading,
                "{}",
                st.message
            );
            let staging = checker::install::llama_dir(dir.path()).with_extension("staging");
            assert!(
                staging.exists(),
                "the first install removed the second's files"
            );
            let _ = release2.send(());
            until("the second install to end", || {
                c.checker_install_status().phase == checker::install::Phase::Failed
            })
            .await;
        })
        .await
        .expect("the test did not finish within 60 s");
    }

    #[test]
    fn a_new_center_is_named_nerve_center_unless_told_otherwise() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(open(dir.path(), None).name(), "nerve-center");
        // The name is kept across restarts and a flag renames it.
        assert_eq!(open(dir.path(), None).name(), "nerve-center");
        assert_eq!(open(dir.path(), Some("lab")).name(), "lab");
        assert_eq!(open(dir.path(), None).name(), "lab");
    }

    /// One code is good for one pairing, also when several nodes send it at
    /// the same moment.
    #[test]
    fn one_code_pairs_one_node_however_many_send_it_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let center = open(dir.path(), None);
        let code = center.new_pairing()["code"].as_str().unwrap().to_string();
        let start = std::sync::Barrier::new(8);
        let statuses: Vec<u16> = std::thread::scope(|s| {
            let tries: Vec<_> = (0..8u8)
                .map(|i| {
                    let (center, code, start) = (&center, &code, &start);
                    s.spawn(move || {
                        let body = json!({
                            "code": code,
                            "name": format!("node-{i}"),
                            "platform": "linux",
                            "arch": "x86_64",
                            "public_key": msg::hex(&[i + 1; 32]),
                        });
                        start.wait();
                        center.pair(body.to_string().as_bytes()).0
                    })
                })
                .collect();
            tries.into_iter().map(|t| t.join().unwrap()).collect()
        });
        let paired = statuses.iter().filter(|s| **s == 200).count();
        assert_eq!(paired, 1, "statuses {statuses:?}");
        assert_eq!(center.read(|st| st.nodes.len()), 1);
        assert!(
            statuses.iter().all(|s| matches!(s, 200 | 403)),
            "{statuses:?}"
        );
    }

    /// A node's check before it pairs tells whether the code could pair,
    /// and the code stays as it was: still open, every try left.
    #[test]
    fn a_check_tells_the_code_open_and_uses_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let code = c.new_pairing()["code"].as_str().unwrap().to_string();
        let check = |code: &str| c.pair_check(json!({ "code": code }).to_string().as_bytes());
        for _ in 0..20 {
            assert_eq!(check(&code), (200, json!({"code": "open"})));
        }
        assert_eq!(check("wrongwrong12"), (200, json!({"code": "gone"})));
        assert_eq!(c.pair_check(b"{}").0, 400);
        assert_eq!(c.pair(&pair_body(&code, "box-1", 7)).0, 200);
        assert_eq!(check(&code), (200, json!({"code": "used"})));
    }

    // ---- The log ----

    use nerve_transport::log::Entry;

    /// Every entry of the log, oldest first.
    fn lines(c: &Center) -> Vec<Entry> {
        let all = Query {
            limit: usize::MAX,
            ..Query::default()
        };
        c.log()
            .entries(&all)
            .into_iter()
            .rev()
            .map(|(_, e)| e)
            .collect()
    }

    fn said(c: &Center, level: Level, part: &str) -> Vec<Entry> {
        lines(c)
            .into_iter()
            .filter(|e| e.level == level && e.msg.contains(part))
            .collect()
    }

    fn pair_body(code: &str, name: &str, key: u8) -> Vec<u8> {
        json!({
            "code": code, "name": name, "platform": "linux", "arch": "x86_64",
            "public_key": msg::hex(&[key; 32]),
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn pairing_is_logged_and_no_code_is() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let made = c.new_pairing();
        let code = made["code"].as_str().unwrap().to_string();
        let link = made["link"].as_str().unwrap().to_string();
        // Wrong codes in a row make one line, not one each.
        for _ in 0..3 {
            assert_eq!(c.pair(&pair_body("wrongwrong12", "box-1", 1)).0, 403);
        }
        assert_eq!(c.pair(&pair_body(&code, "box-1", 7)).0, 200);
        // A right code that cannot pair: told, with the name that was asked for.
        let second = c.new_pairing()["code"].as_str().unwrap().to_string();
        assert_eq!(c.pair(&pair_body(&second, "box-2", 7)).0, 409);
        let id = nerve_transport::keys::node_id(&[7; 32]);

        assert_eq!(
            said(
                &c,
                Level::Info,
                "a pairing code was made; it is valid for 10 min"
            )
            .len(),
            2
        );
        assert_eq!(
            said(&c, Level::Warn, "pairing refused: the code is unknown").len(),
            1
        );
        let paired = said(&c, Level::Info, "the node paired (linux/x86_64)");
        assert_eq!(paired.len(), 1);
        assert_eq!(paired[0].node.as_deref(), Some("box-1"));
        assert_eq!(paired[0].node_id.as_deref(), Some(id.as_str()));
        assert_eq!(
            said(
                &c,
                Level::Warn,
                "pairing refused for the name box-2: this key is already paired"
            )
            .len(),
            1
        );
        // Neither a code, the link that carries one, nor a wrong code is in
        // the window or in the file.
        let file = std::fs::read_to_string(dir.path().join("log.jsonl")).unwrap();
        let window = serde_json::to_string(&lines(&c)).unwrap();
        for secret in [&code, &second, &link, "wrongwrong12"] {
            assert!(
                !file.contains(secret) && !window.contains(secret),
                "{secret}"
            );
        }
    }

    #[test]
    fn a_code_that_runs_out_unused_is_logged_once() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let short = Duration::from_millis(1);
        c.codes.lock().unwrap().create(Instant::now(), short);
        c.codes.lock().unwrap().create(Instant::now(), short);
        std::thread::sleep(Duration::from_millis(10));
        c.sweep_codes();
        c.sweep_codes();
        let expired = said(&c, Level::Info, "expired without being used");
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].msg, "2 pairing codes expired without being used");
        // A code taken by wrong tries is a warning.
        c.codes
            .lock()
            .unwrap()
            .create(Instant::now(), Duration::from_secs(60));
        for _ in 0..crate::pairing::TRIES {
            assert_eq!(c.pair(&pair_body("wrongwrong12", "box-1", 1)).0, 403);
        }
        c.sweep_codes();
        assert_eq!(
            said(
                &c,
                Level::Warn,
                "1 pairing code ran out of tries on wrong codes"
            )
            .len(),
            1
        );
    }

    /// The wrong codes a burst leaves out of the log are counted once it is
    /// over, not only if another one comes later.
    #[test]
    fn a_burst_of_wrong_codes_is_counted_when_it_stops() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        for _ in 0..5 {
            assert_eq!(c.pair(&pair_body("wrongwrong12", "box-1", 1)).0, 403);
        }
        assert_eq!(said(&c, Level::Warn, "pairing refused").len(), 1);
        // Inside the window the count waits.
        c.sweep_codes();
        assert!(said(&c, Level::Warn, "left out").is_empty());
        // Past it, the next sweep says how many there were, once.
        c.pair_log.lock().unwrap().last = Instant::now().checked_sub(QUIET_FOR * 2);
        c.sweep_codes();
        c.sweep_codes();
        let left = said(&c, Level::Warn, "left out");
        assert_eq!(left.len(), 1);
        assert!(
            left[0]
                .msg
                .starts_with("4 pairing refusals left out since the last line"),
            "{}",
            left[0].msg
        );
        // A single refusal after the quiet is a line of its own, with no count.
        assert_eq!(c.pair(&pair_body("wrongwrong12", "box-1", 1)).0, 403);
        let lines = said(&c, Level::Warn, "pairing refused");
        assert_eq!(lines.len(), 2);
        assert!(!lines[1].msg.contains("more since"), "{}", lines[1].msg);
    }

    /// With `--log` the flag holds for the run; a level saved meanwhile is kept
    /// for the next start and does not change this one.
    #[test]
    fn a_level_saved_under_the_flag_is_kept_for_the_next_start_only() {
        let dir = tempfile::tempdir().unwrap();
        open(dir.path(), None).set_log_level(Level::Debug);
        let c = Center::open(Options {
            state_dir: dir.path().to_path_buf(),
            name: None,
            public_url: "http://127.0.0.1:7443".into(),
            log: None,
            log_level: Some(Level::Warn),
        })
        .unwrap();
        assert_eq!(
            (c.log().level(), c.stored_log_level()),
            (Level::Warn, Level::Debug)
        );
        // Saving the stored level again changes nothing.
        c.set_log_level(Level::Debug);
        assert_eq!(
            (c.log().level(), c.stored_log_level()),
            (Level::Warn, Level::Debug)
        );
        // Another one is stored; this run stays where the flag put it.
        c.set_log_level(Level::Error);
        assert_eq!(
            (c.log().level(), c.stored_log_level()),
            (Level::Warn, Level::Error)
        );
        drop(c);
        assert_eq!(open(dir.path(), None).log().level(), Level::Error);
    }

    /// `list` and `execute` find a node by its id or its name, so neither
    /// pairing nor a rename lets a name be a node's id, which would make it
    /// point at that node.
    #[test]
    fn a_name_is_never_a_nodes_id() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let pair = |name: &str, key: u8| {
            let code = c.new_pairing()["code"].as_str().unwrap().to_string();
            c.pair(&pair_body(&code, name, key))
        };
        let id = |key: u8| nerve_transport::keys::node_id(&[key; 32]);
        assert!(nerve_proto::valid_node_name(&id(7)));
        assert_eq!(pair("box-1", 7).0, 200);
        // Another node's id, or its own.
        let told = pair(&id(7), 8);
        assert_eq!(
            told,
            (409, json!({"error": "this name is a node's id"})),
            "{told:?}"
        );
        assert_eq!(pair(&id(8), 8).0, 409);
        // A node whose id is another node's name.
        assert_eq!(pair(&id(9), 8).0, 200);
        let told = pair("box-9", 9);
        assert_eq!(
            told,
            (
                409,
                json!({"error": "another node is named like this node's id"})
            )
        );
        // A rename to a node's id, its own too; another name is fine.
        assert_eq!(
            c.rename(&id(8), &id(7)).unwrap_err(),
            "this name is a node's id"
        );
        assert!(c.rename(&id(8), &id(8)).is_err());
        c.rename(&id(8), "box-2").unwrap();
        assert_eq!(pair("box-9", 9).0, 200);
    }

    #[tokio::test]
    async fn changes_to_a_node_are_logged_under_its_name_and_id() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let code = c.new_pairing()["code"].as_str().unwrap().to_string();
        assert_eq!(c.pair(&pair_body(&code, "box-1", 7)).0, 200);
        let id = nerve_transport::keys::node_id(&[7; 32]);
        c.rename(&id, "web-1").unwrap();
        c.set_disabled(&id, true).unwrap();
        c.set_disabled(&id, false).unwrap();
        c.remove(&id).await.unwrap();

        let about: Vec<(Level, Option<String>, String)> = lines(&c)
            .into_iter()
            .filter(|e| e.node_id.as_deref() == Some(id.as_str()))
            .map(|e| (e.level, e.node, e.msg))
            .collect();
        let name = |n: &str| Some(n.to_string());
        assert_eq!(
            about[1],
            (
                Level::Info,
                name("web-1"),
                "the node was renamed from box-1".into()
            )
        );
        assert_eq!(about[2].1, name("web-1"));
        assert!(about[2].2.starts_with("the node was disabled"), "{about:?}");
        assert_eq!(about[3].2, "the node was enabled");
        // Removed, it is named as it was.
        assert_eq!(about.len(), 5);
        assert_eq!(about[4].1, name("web-1"));
        assert!(about[4].2.contains("removed by the owner"), "{about:?}");
        // The log still names a node the center forgot, for the view's list.
        let v = c.log_json(&Query {
            limit: 10,
            ..Query::default()
        });
        assert_eq!(
            v["nodes"],
            json!([{"id": id, "name": "web-1", "paired": false}])
        );
    }

    #[test]
    fn the_log_level_is_a_setting_and_the_flag_wins() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        // Info unless set; debug is not kept.
        assert_eq!(c.log().level(), Level::Info);
        c.log().record(Level::Debug, None, "detail one");
        assert!(said(&c, Level::Debug, "detail").is_empty());
        c.set_log_level(Level::Debug);
        c.log().record(Level::Debug, None, "detail two");
        assert_eq!(said(&c, Level::Debug, "detail two").len(), 1);
        assert_eq!(
            said(&c, Level::Info, "the log level changes from info to debug").len(),
            1
        );
        // It lasts: the next start keeps it.
        drop(c);
        let c = open(dir.path(), None);
        assert_eq!(c.log().level(), Level::Debug);
        assert!(!c.log_level_pinned());
        // Lowering is told too, while the old level still keeps it.
        c.set_log_level(Level::Error);
        assert_eq!(
            said(&c, Level::Info, "the log level changes from debug to error").len(),
            1
        );
        c.log().record(Level::Warn, None, "not kept");
        assert!(said(&c, Level::Warn, "not kept").is_empty());
        drop(c);
        // `--log` wins for the run and leaves the stored level as it was.
        let c = Center::open(Options {
            state_dir: dir.path().to_path_buf(),
            name: None,
            public_url: "http://127.0.0.1:7443".into(),
            log: None,
            log_level: Some(Level::Warn),
        })
        .unwrap();
        assert_eq!(c.log().level(), Level::Warn);
        assert!(c.log_level_pinned());
        assert_eq!(c.read(|s| s.log_level), Level::Error);
        // The window is the file's: what an earlier run logged is still there.
        assert!(!said(&c, Level::Debug, "detail two").is_empty());
    }

    #[test]
    fn a_failed_call_says_what_it_was_and_why() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let code = c.new_pairing()["code"].as_str().unwrap().to_string();
        assert_eq!(c.pair(&pair_body(&code, "box-1", 7)).0, 200);
        let id = nerve_transport::keys::node_id(&[7; 32]);
        let route = Route {
            node_id: id.clone(),
            node_name: "box-1".into(),
            cap: "fs".into(),
            action: "read".into(),
            effect: nerve_proto::Effect::Read,
        };
        let took = Duration::from_millis(1500);
        let refusal = RpcError::forbidden("no allow rule matches /etc/hostname");
        c.log_failed_call(&route, &refusal, took);
        c.log_failed_call(
            &route,
            &RpcError::new(ErrorCode::Timeout, "the node did not answer in time"),
            Duration::from_secs(30),
        );
        c.log_failed_call(&route, &RpcError::internal("boom"), took);
        // Not a refusal, though the code is `unavailable`: the owner disabled it.
        c.set_disabled(&id, true).unwrap();
        c.log_failed_call(
            &route,
            &RpcError::new(
                ErrorCode::Unavailable,
                "the node box-1 is disabled in the center",
            ),
            took,
        );

        let got: Vec<(Level, String)> = lines(&c)
            .into_iter()
            .filter(|e| e.msg.starts_with("fs.read"))
            .map(|e| (e.level, e.msg))
            .collect();
        assert_eq!(
            got,
            [
                (
                    Level::Info,
                    "fs.read was refused (forbidden): no allow rule matches /etc/hostname"
                        .to_string()
                ),
                (
                    Level::Warn,
                    "fs.read failed (timeout) after 30 s: the node did not answer in time"
                        .to_string()
                ),
                (
                    Level::Error,
                    "fs.read failed (internal) after 1 s: boom".to_string()
                ),
                (
                    Level::Info,
                    "fs.read was refused (unavailable): the node box-1 is disabled in the center"
                        .to_string()
                ),
            ]
        );
    }

    #[test]
    fn a_button_only_adds_a_rule_to_its_list() {
        let mut d = json!({"policy": {"deny": ["exec.run:git push*"], "allow": ["exec.run:ls"]}});
        put_rule(&mut d, "allow", "exec.run:git *").unwrap();
        put_rule(&mut d, "allow", "exec.run:git *").unwrap();
        put_rule(&mut d, "deny", "exec.run:git *").unwrap();
        put_rule(&mut d, "sudo_allow", "sudo apt update").unwrap();
        // Nothing leaves the other list; a repeat adds nothing.
        assert_eq!(
            d["policy"],
            json!({
                "allow": ["exec.run:ls", "exec.run:git *"],
                "deny": ["exec.run:git push*", "exec.run:git *"],
                "sudo_allow": ["sudo apt update"],
            })
        );
        // A document without a policy gets one.
        let mut d = json!({});
        put_rule(&mut d, "deny", "camera").unwrap();
        assert_eq!(d["policy"]["deny"], json!(["camera"]));
        assert!(put_rule(&mut json!([]), "deny", "x").is_err());
        assert!(put_rule(&mut json!({"policy": {"deny": 1}}), "deny", "x").is_err());
        assert_eq!(policy_list("sudo").unwrap(), "sudo_allow");
        assert!(policy_list("permit").is_err());
    }

    #[test]
    fn audit_buttons_write_rules_for_every_action() {
        let rule = |list, cap, action, target, wild| audit_rule(list, cap, action, target, wild);
        assert_eq!(
            rule("allow", "exec", "run", "git status", false).unwrap(),
            "exec.run:git status"
        );
        assert_eq!(
            rule("allow", "exec", "run", "git status", true).unwrap(),
            "exec.run:git *"
        );
        assert_eq!(
            rule("deny", "exec", "run", "rm -rf /tmp/x", true).unwrap(),
            "exec.run:rm *"
        );
        assert_eq!(
            rule("allow", "fs", "read", "/home/u/a.txt", false).unwrap(),
            "fs.read:/home/u/a.txt"
        );
        assert_eq!(
            rule("deny", "fs", "write", "/home/u/a.txt", true).unwrap(),
            "fs.write:/home/u/*"
        );
        assert_eq!(
            rule("allow", "camera", "snap", "camera.snap", false).unwrap(),
            "camera.snap"
        );
        assert_eq!(
            rule("deny", "camera", "snap", "camera.snap", true).unwrap(),
            "camera"
        );
        assert_eq!(
            rule("sudo", "exec", "run", "sudo apt update", false).unwrap(),
            "sudo apt update"
        );
        assert_eq!(
            rule("sudo", "exec", "run", "sudo apt update", true).unwrap(),
            "sudo apt *"
        );
        for (list, cap, action, target) in [
            ("permit", "exec", "run", "ls"),
            ("allow", "exec", "run", "  "),
            ("allow", "fs", "read", ""),
            ("allow", "fs", "read", "relative/path"),
            ("sudo", "exec", "run", "ls"),
            ("sudo", "fs", "read", "/a"),
            ("allow", "", "run", "ls"),
        ] {
            assert!(
                rule(list, cap, action, target, false).is_err(),
                "{list} {cap}.{action} {target:?}"
            );
        }
        // A target the audit cut is not the command any more.
        let cut = nerve_policy::audit::cut_target(&"x".repeat(600)).into_owned();
        for list in ["allow", "deny", "sudo"] {
            assert!(rule(list, "exec", "run", &cut, false).is_err(), "{list}");
            assert!(rule(list, "exec", "run", &cut, true).is_err(), "{list}");
        }
    }
}
