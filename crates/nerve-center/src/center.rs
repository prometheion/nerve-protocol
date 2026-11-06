//! The center's core: paired nodes and their links, pairing, sessions, calls
//! to nodes, the audit feed and the statistics. The MCP server, the node listener and the web UI are thin
//! layers over this.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nerve_transport::sync::lock;
use serde_json::{Map, Value, json};
use tokio::sync::broadcast;

use nerve_proto::link::{CenterUrl, PairLink, PairRequest, PairResponse};
use nerve_proto::msg::{self, ByeReason, Event, Hello};
use nerve_proto::schema::PathMark;
use nerve_proto::{Descriptor, ErrorCode, Exposure, RpcError, UnitKind};
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

mod calls;
mod checker_glue;
mod node_settings;
mod nodes;
mod pair;
mod rotation;
mod sessions;
mod stats;

pub use calls::{CallError, Opened, Ran};
pub use checker_glue::{CHECKER_STALE, audit_rule};
pub use node_settings::settings_write;

pub const IDENTITY_FILE: &str = "tls.pem";
/// The center's new key while a rotation of it is in its grace
/// (docs/dev/spec/protocol.md §4.10); it replaces `tls.pem` at the end.
pub const NEXT_IDENTITY_FILE: &str = "tls.next.pem";
pub use crate::audit::{AUDIT_KEEP, AUDIT_MAX_BYTES};
const ALERTS_KEEP: usize = 50;

/// How the error of a save through [`Center::update_saved`] that could not
/// be written begins.
pub(crate) const UNWRITABLE: &str = "the center cannot write its state file";

/// What changed, for whoever subscribed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Nodes,
    Audit,
    Sessions,
    /// A harness token was made or deleted: the HTTP sessions it opened
    /// end with it.
    Tokens,
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
    /// Held while a rotation of the center's key starts or ends. It guards a
    /// change of several steps, so its poisoning ends the center like a
    /// data lock's.
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
        let mut f = lock(&self.fetched);
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
        lock(&self.fetched).hashes.get(&key).copied()
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

/// A call whose `execute` waits for it; dropped before the call ended or
/// became a job (the harness cancelled its request), it stops the call.
struct Held {
    sess: Arc<Session>,
    id: Option<String>,
    /// Why the call stops when it is dropped.
    why: Stop,
}

impl Drop for Held {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            let stop = lock(&self.sess.jobs).abandon(&id);
            if let Some(stop) = stop {
                let _ = stop.send(self.why);
            }
        }
    }
}

impl std::ops::Deref for Center {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

/// The node `name` has no link now.
fn offline(name: &str) -> RpcError {
    RpcError::new(
        ErrorCode::Unavailable,
        format!("the node {name} is offline"),
    )
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

    /// The log (docs/dev/logging.md): what the web UI shows and the file holds.
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
        *lock(&self.stream_waits) = (open, start);
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
        lock(&self.store).center_id.clone()
    }

    pub fn name(&self) -> String {
        lock(&self.store).center_name.clone()
    }

    pub fn public_url(&self) -> &CenterUrl {
        &self.public_url
    }

    /// The pin of the key served now, with a TLS public URL.
    pub fn pin(&self) -> Option<String> {
        lock(&self.pin).clone()
    }

    /// The TLS configuration with the key served now, for each new
    /// connection: a rotation that ends changes it for the next one.
    pub fn server_config(&self) -> Arc<rustls::ServerConfig> {
        lock(&self.server_config).clone()
    }

    fn identity(&self) -> Arc<ServerIdentity> {
        lock(&self.identity).clone()
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
        self.update_kept(f).0
    }

    /// [`update`](Self::update), and whether the state file took the change
    /// (a failed save's error starts with [`UNWRITABLE`]). For a removal the
    /// center makes at once, whatever the disk says (a token or a node that
    /// goes must stop working now), but must not answer as kept while the
    /// file still holds what it removed: that comes back at the next start.
    pub(crate) fn update_kept<T>(
        &self,
        f: impl FnOnce(&mut Store) -> T,
    ) -> (T, Result<(), String>) {
        let (out, snap) = {
            let mut s = lock(&self.store);
            let out = f(&mut s);
            self.dirty.store(false, Ordering::SeqCst);
            (out, self.snapshot(&s))
        };
        if let Err(e) = self.write_snapshot(snap) {
            // The next flush tries again, so the change is not lost once the
            // disk takes it.
            self.dirty.store(true, Ordering::SeqCst);
            self.log.record(
                Level::Error,
                None,
                &format!("cannot write the state file: {e}"),
            );
            return (out, Err(format!("{UNWRITABLE}: {e}")));
        }
        (out, Ok(()))
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
            let mut w = lock(&self.saves);
            if w.written >= snap.n {
                return Ok(());
            }
            if w.waiting.as_ref().is_none_or(|(n, _)| *n < snap.n) {
                w.waiting = Some((snap.n, text));
            }
        }
        off_the_workers(|| {
            let _one = nerve_transport::sync::turn(&self.writing);
            // Only a snapshot at least as new as this one is written here, so
            // Ok always means the file holds this change. When none waits, a
            // write that took this one away has ended, and failed (else it
            // covered it). An older one that waits is left to its own save.
            let (n, text) = {
                let mut w = lock(&self.saves);
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
            let mut w = lock(&self.saves);
            match &r {
                Ok(()) => w.written = w.written.max(n),
                Err(e) => w.failed = e.to_string(),
            }
            r
        })
    }

    /// Runs `f` on the stored state and saves it, all or nothing: when `f`
    /// fails or the save does, the state stays as it was and the error is
    /// returned (a failed save's starts with [`UNWRITABLE`]). For a change
    /// the center may not tell before it is kept.
    pub(crate) fn update_saved<T>(
        &self,
        f: impl FnOnce(&mut Store) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut s = lock(&self.store);
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
            return Err(format!("{UNWRITABLE}: {e}"));
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
        let link = lock(&self.links)
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
        f(&mut lock(&self.store));
        self.dirty.store(true, Ordering::SeqCst);
    }

    pub fn read<T>(&self, f: impl FnOnce(&Store) -> T) -> T {
        f(&lock(&self.store))
    }

    /// Writes pending statistics. Called on a timer and on shutdown.
    pub fn flush(&self) {
        if self.dirty.swap(false, Ordering::SeqCst) {
            let snap = {
                let mut s = lock(&self.store);
                s.prune_stats(now_ms());
                self.snapshot(&s)
            };
            if let Err(e) = self.write_snapshot(snap) {
                self.dirty.store(true, Ordering::SeqCst);
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
        lock(&self.links)
            .get(node_id)
            .filter(|l| l.is_live())
            .cloned()
    }

    /// The node's link that dropped and waits for its resume.
    pub(crate) fn parked(&self, node_id: &str) -> Option<Arc<Link>> {
        lock(&self.links)
            .get(node_id)
            .filter(|l| !l.is_closed() && !l.is_live())
            .cloned()
    }

    /// The node's link, up or waiting for its resume.
    fn held(&self, node_id: &str) -> Option<Arc<Link>> {
        lock(&self.links)
            .get(node_id)
            .filter(|l| !l.is_closed())
            .cloned()
    }

    /// Closes every link with `bye shutdown`.
    pub async fn shutdown(&self) {
        let links: Vec<Arc<Link>> = lock(&self.links).values().cloned().collect();
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
}

pub(crate) fn plural(n: u32, one: &str) -> String {
    if n == 1 {
        format!("{n} {one}")
    } else {
        format!("{n} {one}s")
    }
}

/// Whether the form can show `e`, an entry of a node's `get
/// settings.capabilities`: an object whose `params` and `result`, where it
/// has them, keep to the schema subset, as the node checks what it keeps.
/// A schema of another shape may nest far deeper, and the form's pretty
/// text of it would be many times the size of the answer.
fn shown(e: &Value) -> bool {
    use nerve_proto::schema::{Role, check};
    e.is_object()
        && match &e["params"] {
            Value::Null => true,
            p => check(p, Role::Params).is_ok(),
        }
        && match &e["result"] {
            Value::Null | Value::String(_) => true,
            r => check(r, Role::Result).is_ok(),
        }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(super) fn open(dir: &Path, name: Option<&str>) -> Center {
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

    pub(crate) fn node_record(id: &str, platform: &str) -> NodeRecord {
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
    pub(super) fn online(c: &Center, node: &str) {
        lock(&c.links).insert(node.into(), Arc::new(Link::for_test(node)));
    }

    pub(super) fn exec_route(node: &str) -> Route {
        Route {
            node_id: node.into(),
            node_name: node.into(),
            cap: "exec".into(),
            action: "run".into(),
            effect: nerve_proto::Effect::Execute,
            kind: nerve_proto::UnitKind::Action,
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
            let mut s = lock(&c.store);
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
            let mut s = lock(&c.store);
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

    /// A change whose write failed is written by the next flush: it is not
    /// only in memory until a later change happens to write the file.
    #[cfg(unix)]
    #[test]
    fn a_failed_write_is_tried_again_by_the_next_flush() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let mode = |m| std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(m));
        mode(0o500).unwrap();
        c.update(|s| s.center_name = "kept".into());
        c.flush();
        mode(0o700).unwrap();
        assert_ne!(
            Store::load(dir.path()).unwrap().unwrap().center_name,
            "kept"
        );
        c.flush();
        assert_eq!(
            Store::load(dir.path()).unwrap().unwrap().center_name,
            "kept"
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
            let mut s = lock(&c.store);
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

    #[test]
    fn a_new_center_is_named_nerve_center_unless_told_otherwise() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(open(dir.path(), None).name(), "nerve-center");
        // The name is kept across restarts and a flag renames it.
        assert_eq!(open(dir.path(), None).name(), "nerve-center");
        assert_eq!(open(dir.path(), Some("lab")).name(), "lab");
        assert_eq!(open(dir.path(), None).name(), "lab");
    }

    // ---- The log ----

    use nerve_transport::log::Entry;

    /// Every entry of the log, oldest first.
    pub(super) fn lines(c: &Center) -> Vec<Entry> {
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

    pub(super) fn said(c: &Center, level: Level, part: &str) -> Vec<Entry> {
        lines(c)
            .into_iter()
            .filter(|e| e.level == level && e.msg.contains(part))
            .collect()
    }

    pub(super) fn pair_body(code: &str, name: &str, key: u8) -> Vec<u8> {
        json!({
            "code": code, "name": name, "platform": "linux", "arch": "x86_64",
            "public_key": msg::hex(&[key; 32]),
        })
        .to_string()
        .into_bytes()
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
}
