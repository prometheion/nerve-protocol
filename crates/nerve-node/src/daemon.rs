//! The node daemon (`nerve-node run`): one link task per paired center and
//! the control socket the CLI talks to.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

#[cfg(unix)]
use nerve_policy::SetError;
use nerve_policy::audit::{AuditLog, Change, Entry, diff};
use nerve_policy::config::SecretStorage;
use nerve_policy::{NodeConfig, SettingsStore};
use nerve_proto::Message;
use nerve_proto::msg::{Topic, method};
use nerve_proto::resume::{self, Replay};
use nerve_sandbox::Confinement;
use nerve_transport::log::{Level, Log};
use nerve_transport::ws::WsMessage;

use crate::descriptor::IMPLICIT;
use crate::paths::{NodePaths, home_dir};

/// How a daemon runs.
#[derive(Debug, Clone)]
pub struct NodeOptions {
    pub paths: NodePaths,
    /// The `nerve-node` binary that hosts the exec shim. Without it commands
    /// run unconfined (and `folder` mode refuses them).
    pub exe: Option<PathBuf>,
    /// The owner's home: the default `cwd` and the root of the protected list.
    pub home: PathBuf,
    /// Serve the control socket (the CLI's way in).
    pub ctl: bool,
    /// The log to write to: the process's, when `nerve_transport::log::install`
    /// ran. The daemon adds the file in the state folder and sets the level
    /// from `node.toml`.
    pub log: Option<Arc<Log>>,
    /// Whether the process counts as having full rights (root, an elevated
    /// token), instead of asking the system. A test sets it: the same test
    /// must pass for a developer who runs it elevated.
    pub full_rights: Option<bool>,
    /// How commands can be confined, instead of asking the kernel. A test
    /// sets it, to stand for a kernel it does not run on.
    pub confinement: Option<Confinement>,
    /// Whether this is the installed service, instead of asking where its
    /// folders are (crate::service::is_service_node). A test sets it, to
    /// stand for the installed node.
    pub service: Option<bool>,
    /// Where commands are held to their limits, or why they are not,
    /// instead of looking for the process's cgroup (crate::cgroup), which
    /// moves the process. A test sets it.
    pub cgroups: Option<crate::cgroup::Found>,
    /// How long a dropped link is kept for the center to resume it
    /// (nerve_proto::resume::GRACE). A test shortens it.
    pub resume_grace: Duration,
    /// Where the node takes its owners' commands, besides the control
    /// socket (crate::owner): the installed node's, unless a test gives
    /// one. Served only with `ctl`.
    pub owners: Option<crate::owner::Endpoint>,
    /// Linux: the owner of the installed node, as its unit names it
    /// (crate::owner::of_service): user mode runs commands as it, and sudo.
    pub owner: Option<String>,
    /// Where work goes that runs while the node is stopped, after which it
    /// starts again: an owner's restore ([`Daemon::run_until`] sets it).
    /// Without it the node refuses such work.
    pub aside: Option<tokio::sync::mpsc::UnboundedSender<Aside>>,
}

/// Work the node runs while it is stopped ([`NodeOptions::aside`]).
pub type Aside = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

/// What [`Daemon::run_until`] is told while the node runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Read the config again (SIGHUP).
    Reload,
    Stop,
}

impl NodeOptions {
    pub fn new(paths: NodePaths) -> NodeOptions {
        NodeOptions {
            owners: crate::owner::Endpoint::of_service(&paths),
            owner: crate::owner::of_service(&paths),
            paths,
            exe: None,
            home: home_dir(),
            ctl: true,
            log: nerve_transport::log::global(),
            full_rights: None,
            confinement: None,
            service: None,
            cgroups: None,
            resume_grace: resume::GRACE,
            aside: None,
        }
    }
}

/// Locks a std mutex, shrugging off poisoning: every holder keeps its state
/// consistent before anything can panic.
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Where the params of an awaited notification go.
type Answer = tokio::sync::oneshot::Sender<serde_json::Map<String, Value>>;

/// The sending side of a link, shared with the calls running on it. A link
/// the center can resume outlives a drop (nerve_proto::resume): what the
/// node sends meanwhile is kept, and goes out when the link resumes.
pub(crate) struct LinkHandle {
    wire: Mutex<Wire>,
    subs: Mutex<Subs>,
    /// Takes the sudo password out of a frame. A counted frame is scrubbed
    /// once, before it is numbered and kept: the password it may carry is
    /// the one held then, and a frame kept for a resume can outlive it.
    scrub: Scrub,
    /// Whether the center named the feature `rotate` in its welcome
    /// (docs/dev/spec/protocol.md §4.10).
    rotate: std::sync::atomic::AtomicBool,
    /// The answer a key rotation waits for: the method, and where its
    /// params go (crate::rotate).
    waiting: Mutex<Option<(&'static str, Answer)>>,
}

/// What [`LinkHandle`] scrubs a frame with.
pub(crate) type Scrub = Box<dyn Fn(String) -> String + Send + Sync>;

/// What goes to the writer of a connection beside its queue of frames:
/// the frames of streams, which it sends only while that queue is empty.
pub(crate) enum StreamOut {
    Frame(WsMessage),
    /// Answered once every stream frame queued before it was sent.
    Flushed(tokio::sync::oneshot::Sender<()>),
}

struct Wire {
    /// The writer of the connection now; `None` while the link is down.
    tx: Option<mpsc::Sender<WsMessage>>,
    /// Its queue of stream frames, apart from `tx`: a stream that outruns
    /// the link never fills `tx`, so pings, acks, events and answers still
    /// get out.
    frames: Option<mpsc::Sender<StreamOut>>,
    /// The counts and the kept frames, when the center can resume the link.
    replay: Option<Replay>,
}

impl Wire {
    /// Keeps a frame that cannot go out now for the resume. On a link that
    /// cannot resume it is lost with the link.
    fn keep(&mut self, text: &str) {
        if let Some(r) = &mut self.replay {
            r.push(text);
        }
    }
}

#[derive(Default)]
struct Subs {
    topics: BTreeSet<Topic>,
    /// `seq` per capability, counting from 1 on this link.
    seq: HashMap<String, u64>,
}

impl LinkHandle {
    /// A link on the connection `tx` and `frames` write to; `resumable`
    /// when the center can resume it.
    pub fn new(
        tx: mpsc::Sender<WsMessage>,
        frames: mpsc::Sender<StreamOut>,
        resumable: bool,
        scrub: Scrub,
    ) -> LinkHandle {
        LinkHandle {
            wire: Mutex::new(Wire {
                tx: Some(tx),
                frames: Some(frames),
                replay: resumable.then(|| Replay::new(resume::KEEP_BYTES)),
            }),
            subs: Mutex::default(),
            scrub,
            rotate: Default::default(),
            waiting: Mutex::default(),
        }
    }

    /// Notes that the center speaks key rotation.
    pub fn set_rotate(&self, on: bool) {
        self.rotate.store(on, Ordering::SeqCst);
    }

    pub fn rotate(&self) -> bool {
        self.rotate.load(Ordering::SeqCst)
    }

    /// Waits for the next notification `method` from the center: its params,
    /// or an error when the link ended first. One waits at a time; a newer
    /// wait replaces an older one, which then ends.
    pub fn expect(
        &self,
        method: &'static str,
    ) -> tokio::sync::oneshot::Receiver<serde_json::Map<String, Value>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        *lock(&self.waiting) = Some((method, tx));
        rx
    }

    /// The link ended: a wait for an answer ends with it.
    pub fn ended(&self) {
        lock(&self.waiting).take();
    }

    /// Hands a notification to whoever waits for it; `false` when nobody
    /// does, and it is ignored.
    pub fn answer(&self, method: &str, params: serde_json::Map<String, Value>) -> bool {
        let mut w = lock(&self.waiting);
        match w.take() {
            Some((m, tx)) if m == method => tx.send(params).is_ok(),
            other => {
                *w = other;
                false
            }
        }
    }

    /// Sends a counted text frame, waiting for room in the queue.
    pub async fn send(&self, text: String) {
        let text = (self.scrub)(text);
        loop {
            // Kept under the same lock that saw the link down, so a resume
            // that comes in between replays it.
            let tx = {
                let mut w = lock(&self.wire);
                match w.tx.clone() {
                    Some(tx) => tx,
                    None => {
                        w.keep(&text);
                        return;
                    }
                }
            };
            let permit = tx.reserve().await;
            let mut w = lock(&self.wire);
            // The connection changed while this waited for room: the frame
            // goes to the one there is now.
            if !w.tx.as_ref().is_some_and(|t| t.same_channel(&tx)) {
                continue;
            }
            match permit {
                Ok(p) => {
                    if let Some(r) = &mut w.replay {
                        r.push(&text);
                    }
                    p.send(WsMessage::text(text));
                }
                // The writer is gone: the link is going down.
                Err(_) => w.keep(&text),
            }
            return;
        }
    }

    /// Sends a counted text frame if there is room; `false` when the queue
    /// is full and the frame was dropped.
    pub fn try_send(&self, text: String) -> bool {
        let text = (self.scrub)(text);
        let mut w = lock(&self.wire);
        let Some(tx) = w.tx.clone() else {
            w.keep(&text);
            return true;
        };
        match tx.try_reserve() {
            Ok(p) => {
                if let Some(r) = &mut w.replay {
                    r.push(&text);
                }
                p.send(WsMessage::text(text));
                true
            }
            Err(mpsc::error::TrySendError::Full(())) => false,
            Err(mpsc::error::TrySendError::Closed(())) => {
                w.keep(&text);
                true
            }
        }
    }

    /// Sends a binary frame of a stream, waiting for room in the stream
    /// queue. Binary frames are not counted: `false` when the link is not
    /// on a connection now, and the stream ends.
    pub async fn frame(&self, f: &nerve_proto::frame::Frame) -> bool {
        let Ok(bytes) = f.encode() else {
            return false;
        };
        let frames = lock(&self.wire).frames.clone();
        match frames {
            Some(q) => q
                .send(StreamOut::Frame(WsMessage::binary(bytes)))
                .await
                .is_ok(),
            None => false,
        }
    }

    /// Waits until the stream frames queued so far were sent, so what
    /// follows on the frame queue comes after them; `false` when the link
    /// left its connection first.
    pub async fn flushed(&self) -> bool {
        let frames = lock(&self.wire).frames.clone();
        let Some(q) = frames else {
            return false;
        };
        let (done, sent) = tokio::sync::oneshot::channel();
        q.send(StreamOut::Flushed(done)).await.is_ok() && sent.await.is_ok()
    }

    /// Sends a frame of this connection only (a ping, an `ack`), if there
    /// is room.
    pub fn raw(&self, m: WsMessage) {
        if let Some(tx) = &lock(&self.wire).tx {
            let _ = tx.try_send(m);
        }
    }

    /// Sends a frame of this connection only (a `bye`), waiting for room.
    pub async fn raw_send(&self, m: WsMessage) {
        let tx = lock(&self.wire).tx.clone();
        if let Some(tx) = tx {
            let _ = tx.send(m).await;
        }
    }

    /// Counts a counted frame read from the center.
    pub fn read_one(&self) {
        if let Some(r) = &mut lock(&self.wire).replay {
            r.read();
        }
    }

    /// Sends `ack {got}` when the count moved since the last one.
    pub fn send_ack(&self) {
        let mut w = lock(&self.wire);
        let Wire {
            tx: Some(tx),
            replay: Some(r),
            ..
        } = &mut *w
        else {
            return;
        };
        if let Some(got) = r.ack_due() {
            let m = Message::notification(method::ACK, json!({ "got": got }));
            if tx.try_send(WsMessage::text(m.encode())).is_ok() {
                r.told(got);
            }
        }
    }

    /// Whether the center can resume this link (it agreed to in `welcome`).
    pub fn resumes(&self) -> bool {
        lock(&self.wire).replay.is_some()
    }

    /// The center read the first `got` frames.
    pub fn acked(&self, got: u64) -> Result<(), String> {
        match &mut lock(&self.wire).replay {
            Some(r) => r.acked_to(got),
            None => Ok(()),
        }
    }

    /// Whether the center can resume this link now: it agreed to, and every
    /// frame it may lack is still kept.
    pub fn resumable(&self) -> bool {
        lock(&self.wire)
            .replay
            .as_ref()
            .is_some_and(Replay::complete)
    }

    /// The counted frames read from the center so far.
    pub fn got(&self) -> u64 {
        lock(&self.wire).replay.as_ref().map_or(0, Replay::got)
    }

    /// Takes the link off its connection: until it resumes, what is sent is
    /// kept, or lost on a link that cannot resume.
    pub fn detach(&self) {
        let mut w = lock(&self.wire);
        w.tx = None;
        w.frames = None;
    }

    /// Puts the resumed link on the connection `tx` and `frames` write to,
    /// the center having read `got` frames of it. Gives the frames to send
    /// first.
    pub fn attach(
        &self,
        tx: mpsc::Sender<WsMessage>,
        frames: mpsc::Sender<StreamOut>,
        got: u64,
    ) -> Result<Vec<String>, String> {
        let mut w = lock(&self.wire);
        let again = w
            .replay
            .as_mut()
            .ok_or("this link cannot resume")?
            .resume(got)?;
        w.tx = Some(tx);
        w.frames = Some(frames);
        Ok(again)
    }

    pub fn sub(&self, topics: Vec<Topic>, on: bool) {
        let mut s = lock(&self.subs);
        for t in topics {
            if on {
                s.topics.insert(t);
            } else {
                s.topics.remove(&t);
            }
        }
    }

    fn next_seq(s: &mut Subs, cap: &str) -> u64 {
        let n = s.seq.entry(cap.to_string()).or_insert(0);
        *n += 1;
        *n
    }

    /// Sends `cap/name` if it is implicit or subscribed. Events never wait
    /// for room: when the send queue is full the event is dropped and logged.
    pub fn event(&self, cap: &str, name: &str, data: Value) {
        let mut s = lock(&self.subs);
        let wanted = IMPLICIT.contains(&cap)
            || s.topics.contains(&Topic::Event(cap.into(), name.into()))
            || s.topics.contains(&Topic::All(cap.into()));
        if !wanted {
            return;
        }
        let seq = Self::next_seq(&mut s, cap);
        let m = Message::notification(
            method::EVENT,
            json!({"cap": cap, "name": name, "seq": seq, "ts": crate::now_ms(), "data": data}),
        );
        if !self.try_send(m.encode()) {
            tracing::warn!("event {cap}/{name} dropped: the link's send queue is full");
        }
    }

    /// Sends a `state` change if subscribed (implicit for the implicit caps).
    pub fn state(&self, cap: &str, changed: Value) {
        let mut s = lock(&self.subs);
        let wanted = IMPLICIT.contains(&cap)
            || s.topics.contains(&Topic::State(cap.into()))
            || s.topics.contains(&Topic::All(cap.into()));
        if !wanted {
            return;
        }
        let seq = Self::next_seq(&mut s, cap);
        let m = Message::notification(
            method::STATE,
            json!({"cap": cap, "seq": seq, "ts": crate::now_ms(), "changed": changed}),
        );
        self.try_send(m.encode());
    }
}

/// What the node keeps per center across links.
pub(crate) struct CenterState {
    pub link: Mutex<Option<Arc<LinkHandle>>>,
    pub status: Mutex<String>,
    /// Held while a rotation of the node's key for this center runs, so the
    /// owner's command and the one a new link resumes do not cross.
    pub rotating: tokio::sync::Mutex<()>,
    /// When dropping an expired old pin last failed to save; it is tried
    /// again only a while later (crate::rotate::drop_old_pin).
    pub old_pin_failed: Mutex<Option<std::time::Instant>>,
}

impl CenterState {
    pub fn set_status(&self, s: impl Into<String>) {
        *lock(&self.status) = s.into();
    }

    pub fn link(&self) -> Option<Arc<LinkHandle>> {
        lock(&self.link).clone()
    }
}

/// How this node confines the commands of folder mode. The installed
/// Windows service runs every command as another account (crate::win_user),
/// and the AppContainer is not wired for that account yet (its profile and
/// window station are made for the user the shim runs as), so there folder
/// mode has no confinement and runs no command.
fn confinement_for(detected: Confinement, service: bool) -> Confinement {
    Confinement {
        appcontainer: detected.appcontainer && !service,
        ..detected
    }
}

/// Everything the daemon's tasks share.
/// How long a looked-up account is used before it is looked up again.
const ACCOUNT_FRESH: std::time::Duration = std::time::Duration::from_secs(5);

/// How often a folder grant that failed is tried again, at most: by a
/// command of `nerve-run` or a change of the config, and at once at the
/// node's start. The owner may have fixed what stopped it (a closed folder
/// opened) without changing the config.
#[cfg(target_os = "linux")]
const ACL_RETRY: std::time::Duration = std::time::Duration::from_secs(60);

pub(crate) struct Shared {
    pub paths: NodePaths,
    /// Whether this is the installed service (crate::service::is_service_node).
    pub service: bool,
    pub exe: Option<PathBuf>,
    pub home: PathBuf,
    /// Which protected list applies, and where its system folders are.
    pub platform: nerve_policy::protected::Platform,
    pub confinement: Confinement,
    /// The cgroup that holds each command to its limits (crate::cgroup), or
    /// why there is none.
    pub cgroups: crate::cgroup::Found,
    pub store: Mutex<SettingsStore>,
    /// Ticks whenever the config may have changed; links re-check their
    /// center, the supervisor its link tasks.
    pub changed: watch::Sender<u64>,
    pub centers: Mutex<HashMap<String, Arc<CenterState>>>,
    /// pid → center of every command running now.
    pub commands: Mutex<HashMap<u32, String>>,
    /// Commands running now, over all centers (`limits.max_running`).
    pub running: AtomicUsize,
    /// The `folder` mode commands running now that Landlock does not keep
    /// off the session bus ([`Shared::open_to_bus`]); the store's secrets
    /// refuse to move the keys into the keyring while there are any.
    pub open_to_bus: Arc<AtomicUsize>,
    pub stop: watch::Sender<bool>,
    /// The log, to keep the sudo password out of it.
    pub log: Option<Arc<Log>>,
    /// The checked sudo password while the switch is on (crate::sudo).
    pub sudo: Mutex<Option<crate::sudo::Secret>>,
    /// Open sudo offers by center; each is opened at most once.
    pub sudo_offers: Mutex<HashMap<String, nerve_transport::sudo::Pending>>,
    /// The account sudo's password was checked for (crate::sudo): the
    /// switch holds only for that account.
    pub sudo_for: Mutex<Option<String>>,
    /// The accounts looked up last (the owner, `nerve-run`), and when:
    /// every call of a center needs one, and a lookup starts two programs.
    pub account_cache:
        Mutex<HashMap<String, (std::time::Instant, Option<crate::service::Account>)>>,
    /// Whether the log said that the keyring turned folder mode's commands
    /// off ([`Shared::tell_confinement`]).
    pub told_keyring: std::sync::atomic::AtomicBool,
    /// How long a dropped link is kept for its resume.
    pub grace: Duration,
    /// The capability providers attached now (crate::provider).
    pub providers: crate::provider::Providers,
    /// Linux: the installed node's provider socket, the only place it
    /// takes a provider's hello (crate::provider::serve); `None` for a node
    /// run by hand, which takes it on the control socket.
    #[cfg(target_os = "linux")]
    pub provider_socket: Option<PathBuf>,
    /// Where work goes that runs while the node is stopped
    /// ([`NodeOptions::aside`]).
    pub aside: Option<tokio::sync::mpsc::UnboundedSender<Aside>>,
    /// The relay for other nodes (crate::relay), and who is connected.
    pub relay: crate::relay::Relays,
    /// Linux: the installed node's owner ([`NodeOptions::owner`]).
    #[cfg_attr(windows, allow(dead_code))]
    pub owner: Option<String>,
    /// The name of the account this process runs as, looked up once: a
    /// node run by hand runs its commands as it.
    pub own_user: Option<String>,
    /// Linux: what the last sync of the folders' ACLs for `nerve-run` left
    /// (crate::acl); held while one runs, so that two never run at once.
    #[cfg(target_os = "linux")]
    pub acl: Mutex<crate::acl::Report>,
    /// Linux: when a sync of the ACLs last ran, for trying a grant that
    /// failed again ([`ACL_RETRY`]).
    #[cfg(target_os = "linux")]
    pub acl_tried: Mutex<Option<std::time::Instant>>,
}

impl Shared {
    pub fn config(&self) -> NodeConfig {
        lock(&self.store).config().clone()
    }

    /// The account the commands of a pairing with `policy` run as
    /// (crate::account): `nerve-run` on the installed Linux node, or the
    /// owner where the pairing runs as the owner now; `None` runs them as
    /// the node's own user.
    pub fn command_account(
        &self,
        cfg: &NodeConfig,
        policy: &nerve_policy::config::CenterPolicy,
    ) -> Result<Option<crate::service::Account>, String> {
        self.account_as(cfg, policy.runs_as_owner(crate::now_ms()))
    }

    /// The account `nerve-run` (crate::account), which the config's
    /// capabilities run as unless they say the owner, whatever a pairing's
    /// commands run as; `None` on a node run by hand, which has none.
    pub fn run_account(&self, cfg: &NodeConfig) -> Result<Option<crate::service::Account>, String> {
        self.account_as(cfg, false)
    }

    /// The capabilities offered besides the node's own: the attached
    /// programs' (crate::provider) and the config's (crate::config_cap).
    pub fn added_caps(&self, cfg: &NodeConfig) -> Vec<nerve_proto::descriptor::Capability> {
        let mut caps = self.providers.caps();
        caps.extend(crate::config_cap::offered(cfg, self.service));
        caps
    }

    /// [`Shared::added_caps`] as the pairing with `policy` is offered them:
    /// a config capability that runs as `nerve-run` is marked a command of
    /// the pairing's command account (`as_account`) only where its commands
    /// run as that account. Where they run as the owner, the command account
    /// the center knows is the owner, and that account's folders are not
    /// the capability's (crate::config_cap::confined).
    pub fn offered_caps(
        &self,
        cfg: &NodeConfig,
        policy: &nerve_policy::config::CenterPolicy,
    ) -> Vec<nerve_proto::descriptor::Capability> {
        let mut caps = self.added_caps(cfg);
        crate::config_cap::as_account_for(&mut caps, self.separate(policy));
        caps
    }

    /// The places a center may write, where a command of the config that
    /// runs with the owner's rights may neither start nor name a place
    /// (crate::config_cap::written_by_centers): the `w` folders of every
    /// center, `nerve-run`'s own folders (`/tmp` and `/var/tmp` on a node
    /// run by hand, which has no such account), and what the allow rules of
    /// a center whose writes run as the owner let it write
    /// (crate::config_cap::written_by_rules).
    pub fn center_writes(&self, cfg: &NodeConfig) -> Vec<PathBuf> {
        let home = self.rules_home(cfg);
        let mut writable = crate::exec::write_folders(cfg, &home);
        writable.extend(match self.run_account(cfg) {
            Ok(Some(a)) => crate::account::built_in(&a.home)
                .into_iter()
                .map(|f| f.path.into())
                .collect(),
            _ => vec!["/tmp".into(), "/var/tmp".into()],
        });
        let mut caps = crate::descriptor::built_in(cfg);
        caps.extend(self.added_caps(cfg));
        writable.extend(crate::config_cap::written_by_rules(
            cfg,
            &caps,
            &home,
            crate::now_ms(),
            |p| !self.separate(p),
        ));
        writable
    }

    /// How the node judges the command of `decl`, which runs with the
    /// owner's rights as `owner` (the node's own user where `None`), from
    /// where it starts, that account's home (the node's own by hand): why
    /// it may not run (crate::config_cap::written_by_centers, with what
    /// `nerve-run` owns or may change), else the
    /// program file it runs, `None` where none is found
    /// (crate::config_cap::program_file). Looked at as the owner, who may
    /// look into the owner's home and the folders where the node's own user
    /// may not.
    pub fn owner_command(
        &self,
        cfg: &NodeConfig,
        decl: &nerve_policy::config::ConfigCapability,
        owner: Option<&crate::service::Account>,
    ) -> Result<Option<PathBuf>, String> {
        let writable = self.center_writes(cfg);
        let run = self.run_account(cfg).ok().flatten();
        let start_in = owner.map_or_else(|| self.home.clone(), |a| a.home.clone());
        let _as = crate::link::act_as(owner).ok().flatten();
        let path = std::env::var_os("PATH");
        if let Some(why) = crate::config_cap::written_by_centers(
            decl,
            &writable,
            run.as_ref(),
            path.as_deref(),
            &start_in,
        ) {
            return Err(why);
        }
        Ok(decl
            .command
            .first()
            .and_then(|p| crate::config_cap::program_file(p, path.as_deref())))
    }

    /// The owner's account, which sudo runs as and whose files the folders
    /// and rules name; `None` on a node run by hand, whose own user it is.
    pub fn owner_account(
        &self,
        cfg: &NodeConfig,
    ) -> Result<Option<crate::service::Account>, String> {
        self.account_as(cfg, true)
    }

    /// Whether the commands of a pairing with `policy` run as `nerve-run`
    /// now: on the installed Linux node, in folder mode and in allowlist
    /// mode unless the pairing runs as the owner. They are confined then,
    /// in every mode.
    pub fn separate(&self, policy: &nerve_policy::config::CenterPolicy) -> bool {
        self.service && cfg!(target_os = "linux") && !policy.runs_as_owner(crate::now_ms())
    }

    /// The built-in folders of a pairing whose commands run as `nerve-run`
    /// ([`crate::account::built_in`]) added to `entry`'s, for the gate and
    /// the sandbox; the config keeps only those the owner gave.
    pub fn with_built_in(
        &self,
        cfg: &NodeConfig,
        mut entry: nerve_policy::CenterEntry,
    ) -> nerve_policy::CenterEntry {
        if self.separate(&entry.policy)
            && let Ok(Some(a)) = self.command_account(cfg, &entry.policy)
        {
            entry
                .policy
                .folders
                .extend(crate::account::built_in(&a.home));
        }
        entry
    }

    /// What the center `entry` (the config's, as it is) may do now, for its
    /// descriptor (crate::descriptor::Reach): from that entry alone, with the
    /// built-in folders as [`Shared::with_built_in`] adds them for the gate.
    /// It runs every few seconds for every link, so the account is named
    /// without a lookup, and `nerve-run`'s home is the last one looked up.
    pub fn reach(
        &self,
        cfg: &NodeConfig,
        entry: &nerve_policy::CenterEntry,
    ) -> crate::descriptor::Reach {
        let now = crate::now_ms();
        let run_home = self
            .separate(&entry.policy)
            .then(|| self.account_seen(cfg, &entry.policy))
            .flatten()
            .map(|a| a.home);
        let mut reach = crate::descriptor::Reach::of(
            entry,
            now,
            self.account_name(cfg, &entry.policy),
            self.confined(cfg),
            run_home.as_deref(),
        );
        // Without a sandbox, a folder-mode command that runs at all runs as
        // `nerve-run`, held back by that account alone ([`folder_refusal`]).
        reach.held_by_account = !self.sandboxed();
        // The node reads as that account too (crate::link), whose own
        // access then holds what folder mode reads.
        reach.reads_by_account = self.separate(&entry.policy);
        // A command on the sudo list runs only while the switch is on, which
        // it is not by default nor, on Linux, after a restart: the block
        // tells the list only then. A switch change moves the rev like a
        // grant. No store lock is held here; `sudo_on` takes it.
        reach.sudo = reach.sudo && self.sudo_on();
        reach
    }

    /// The name of the account the commands of a pairing with `policy` run
    /// as now ([`Shared::command_account`]), without looking it up: whether
    /// it exists and may be used is the call's business.
    pub fn account_name(
        &self,
        cfg: &NodeConfig,
        policy: &nerve_policy::config::CenterPolicy,
    ) -> Option<String> {
        if !self.service {
            return self.own_user.clone();
        }
        if cfg!(windows) || policy.runs_as_owner(crate::now_ms()) {
            self.owner_name(cfg)
        } else {
            Some(crate::account::RUN_USER.to_string())
        }
    }

    /// [`Shared::command_account`] as last looked up, however long ago;
    /// looked up only when it never was. Not for deciding a call.
    fn account_seen(
        &self,
        cfg: &NodeConfig,
        policy: &nerve_policy::config::CenterPolicy,
    ) -> Option<crate::service::Account> {
        if let Some(name) = self.account_name(cfg, policy)
            && let Some((_, a)) = lock(&self.account_cache).get(&name)
        {
            return a.clone();
        }
        self.command_account(cfg, policy).ok().flatten()
    }

    /// The accounts the folders' ACLs are for (crate::acl): `nerve-run` and
    /// the owner, on the installed Linux node that has both; `None`
    /// elsewhere, where no command runs as `nerve-run`.
    #[cfg(target_os = "linux")]
    fn acl_accounts(&self, cfg: &NodeConfig) -> Option<(crate::acl::Who, crate::service::Account)> {
        if !self.service {
            return None;
        }
        let run = self.account_as(cfg, false).ok().flatten()?;
        let owner = self.owner_account(cfg).ok().flatten()?;
        let who = crate::acl::Who {
            run: run.uid,
            owner: owner.uid,
        };
        Some((who, owner))
    }

    /// Brings the folders' ACLs in line with `cfg` (crate::acl), when the
    /// record is behind it, a grant failed and was not tried for
    /// [`ACL_RETRY`], or `always`; blocks while it walks. What it left is
    /// logged and kept for the commands and `status`.
    #[cfg(target_os = "linux")]
    pub fn sync_acls(&self, cfg: &NodeConfig, always: bool) {
        let Some((who, owner)) = self.acl_accounts(cfg) else {
            return;
        };
        let file = crate::acl::record_file(&self.paths);
        // The folders are resolved as the owner sees them: the node's user
        // may not look into the owner's home.
        let want = match crate::account::FsAs::new(&owner) {
            Ok(_as) => crate::acl::wanted(cfg, &self.paths, &owner.home, crate::now_ms()),
            Err(e) => {
                tracing::warn!("folder grants: cannot act as {}: {e}", owner.name);
                return;
            }
        };
        let mut last = lock(&self.acl);
        let mut tried = lock(&self.acl_tried);
        let retry = tried.is_none_or(|t| t.elapsed() >= ACL_RETRY);
        if !always && !crate::acl::behind(&file, &want, who, retry) {
            return;
        }
        *tried = Some(std::time::Instant::now());
        let act_as = || {
            crate::account::FsAs::new(&owner)
                .map(Some)
                .map_err(|e| format!("cannot act as {}: {e}", owner.name))
        };
        let report = crate::acl::sync(&file, &want, who, &act_as);
        for e in &report.errors {
            tracing::warn!("folder grants: {e}");
        }
        *last = report;
    }

    /// Why a command of `nerve-run` may not run now: the ACLs could not be
    /// brought in line with `cfg`, and it may still reach a folder no longer
    /// given ([`crate::acl::Report::refusal`]). Syncs first where they are
    /// behind. Blocks.
    #[cfg(target_os = "linux")]
    pub fn acls_refusal(&self, cfg: &NodeConfig) -> Option<String> {
        self.sync_acls(cfg, false);
        lock(&self.acl).refusal()
    }

    /// The name of the installed node's owner: on Linux the account that
    /// ran `install`, which the unit names ([`NodeOptions::owner`]); on
    /// Windows the account commands run as (`machine.user`).
    pub fn owner_name(&self, cfg: &NodeConfig) -> Option<String> {
        #[cfg(windows)]
        return cfg.machine.user.clone();
        #[cfg(not(windows))]
        {
            let _ = cfg;
            self.owner.clone()
        }
    }

    /// The account `name`, looked up at most every [`ACCOUNT_FRESH`].
    fn account_named(&self, name: &str) -> Result<Option<crate::service::Account>, String> {
        if let Some((at, a)) = lock(&self.account_cache).get(name)
            && at.elapsed() < ACCOUNT_FRESH
        {
            return Ok(a.clone());
        }
        let a = crate::account::lookup(name)?;
        lock(&self.account_cache).insert(name.to_string(), (std::time::Instant::now(), a.clone()));
        Ok(a)
    }

    fn account_as(
        &self,
        cfg: &NodeConfig,
        as_owner: bool,
    ) -> Result<Option<crate::service::Account>, String> {
        let cached = |name: &str| self.account_named(name);
        crate::account::for_commands(
            as_owner,
            self.owner_name(cfg).as_deref(),
            crate::account::own_uid(),
            self.service,
            crate::account::can_switch(),
            cached,
        )
    }

    /// The `~` of the folders, the rules and the protected list: the
    /// owner's home, whose files they name, else the node's own.
    pub fn rules_home(&self, cfg: &NodeConfig) -> PathBuf {
        match self.owner_account(cfg) {
            Ok(Some(a)) => a.home,
            _ => self.home.clone(),
        }
    }

    /// `folder add` for the CLI (`folder.add`): judges the folder at `path`
    /// (absolute, as given) as the account the commands run as, stores it at
    /// its real place with `access` and records it. The installed node's CLI
    /// runs as the node's own user, which may not look into that account's
    /// home or resolve a `w` folder there, so it cannot judge the links on the
    /// path; the node looks as the account does, as it does before a command
    /// ([`crate::exec::settle`]). Nothing changes when the path crosses a link
    /// inside a `w` folder (an error with the reason). Where the node cannot
    /// tell either, the folder is stored as given and not recorded, and a
    /// record it had stays.
    #[cfg(unix)]
    pub fn add_folder(
        &self,
        center: &str,
        path: &str,
        access: nerve_policy::config::Access,
    ) -> Result<AddedFolder, String> {
        use crate::exec::Settled;
        use crate::folder_change::{FolderChange, apply_to};
        let cfg = self.config();
        if cfg.center(center).is_none() {
            return Err(format!("no center named {center}"));
        }
        let given = nerve_policy::paths::normal_folder(path)?;
        // The folder is the owner's: judged as the owner sees it, before
        // any grant lets `nerve-run` see it at all.
        let account = self.owner_account(&cfg).unwrap_or(None);
        let home = account
            .as_ref()
            .map_or_else(|| self.home.clone(), |a| a.home.clone());
        let settled = {
            let _as = crate::link::act_as(account.as_ref()).map_err(|e| e.message)?;
            crate::exec::settle(&cfg, &home, std::path::Path::new(&given))
        };
        let (stored, recorded) = match settled {
            Settled::Refused(why) => return Err(refusal(path, &why)),
            Settled::At(place) => (place.display().to_string(), true),
            Settled::Unknown => (given, false),
        };
        let change = FolderChange::Add {
            path: stored.clone(),
            access,
            recorded,
        };
        let mut applied = None;
        lock(&self.store)
            .update(|c| {
                applied = Some(apply_to(c, Some(center), &change)?);
                Ok(())
            })
            .map_err(|e| e.to_string())?;
        self.bump();
        let counts = self.config().center(center).is_some_and(|c| {
            c.policy.mode_at(crate::now_ms()) == nerve_policy::Mode::Folder
                || self.separate(&c.policy)
        });
        Ok(AddedFolder {
            stored,
            recorded,
            mode: applied.expect("applied when update succeeds").mode,
            counts,
        })
    }

    pub fn bump(&self) {
        self.changed.send_modify(|v| *v += 1);
        self.tell_confinement(&self.config());
    }

    /// Reads the config file again because the owner asked (SIGHUP, the
    /// control socket). Nothing else rereads it: the node keeps its config
    /// in memory, and a file it did not sign is refused.
    pub fn reload(&self) -> Result<bool, String> {
        let r = lock(&self.store).reload();
        match &r {
            Ok(true) => {
                // A signed file may say sudo on without a password held.
                self.settle_sudo();
                self.bump();
                tracing::info!("node.toml was read again and has changed");
            }
            Ok(false) => tracing::debug!("node.toml was read again; nothing changed"),
            Err(e) => tracing::warn!("reload refused, the old config stays: {e}"),
        }
        r
    }

    /// The folders no center reaches, whatever its policy: the node's own,
    /// and with its keys in the keyring on Linux, the places that reach
    /// them there (crate::paths::keyring_places). Not called while the
    /// store is locked when `cfg` comes from [`Shared::config`].
    pub fn own(&self, cfg: &NodeConfig) -> Vec<PathBuf> {
        let own = self.paths.own();
        #[cfg(target_os = "linux")]
        if cfg.machine.secret_storage == SecretStorage::Keyring {
            let places =
                crate::paths::keyring_places(&self.home, nerve_transport::net::euid(), |k| {
                    std::env::var_os(k)
                });
            return [own, places].concat();
        }
        #[cfg(not(target_os = "linux"))]
        let _ = cfg;
        own
    }

    /// Whether commands of `folder` mode may run: confined (Landlock or an
    /// AppContainer, and the shim's host), and kept from the node's keys.
    /// With the keys in the keyring a command reaches them over the session
    /// bus of the node's user, which only another account than root and the
    /// node's own cannot reach: `nerve-run` on the installed node.
    pub fn confined(&self, cfg: &NodeConfig) -> bool {
        self.unconfined(cfg).is_none()
    }

    /// Why commands of `folder` mode may not run, or `None` when they may
    /// ([`Shared::confined`]).
    pub fn unconfined(&self, cfg: &NodeConfig) -> Option<&'static str> {
        self.unconfined_as(cfg, || self.account_as(cfg, false).ok().flatten())
    }

    /// [`Shared::unconfined`] for commands that run as `account`, the
    /// account a call already looked up for `cfg`: a call decides and
    /// confines its command by one answer. `account` is asked only when
    /// the answer depends on it, as a lookup may start two programs.
    pub fn unconfined_as(
        &self,
        cfg: &NodeConfig,
        account: impl FnOnce() -> Option<crate::service::Account>,
    ) -> Option<&'static str> {
        folder_refusal(
            self.sandboxed(),
            self.service,
            cfg.machine.secret_storage,
            account,
        )
    }

    /// Whether a sandbox can hold folder-mode commands to the folders here:
    /// Landlock or an AppContainer, and a program to start them through.
    fn sandboxed(&self) -> bool {
        self.confinement.available() && self.exe.is_some()
    }

    /// Whether the commands of a pairing with `policy` run under Landlock
    /// now: in folder mode, and as `nerve-run`, where the kernel has it.
    pub fn landlock_for(&self, policy: &nerve_policy::config::CenterPolicy) -> bool {
        self.confinement.landlock_abi.is_some()
            && self.exe.is_some()
            && (policy.mode_at(crate::now_ms()) == nerve_policy::Mode::Folder
                || self.separate(policy))
    }

    /// What `nerve-run` may read of the owner's home beyond its folders on
    /// the installed Linux node without Landlock
    /// (crate::account::home_warning): the home, its mode when others may
    /// look into it, the folders given in it, and what the node says. Null
    /// with Landlock, which holds it to its folders, and where neither lets
    /// it into the home.
    pub fn home_warning(&self, cfg: &NodeConfig) -> Value {
        #[cfg(target_os = "linux")]
        {
            if !self.service || self.confinement.landlock_abi.is_some() {
                return Value::Null;
            }
            let Some(name) = self.owner_name(cfg) else {
                return Value::Null;
            };
            let Ok(Some(owner)) = self.account_named(&name) else {
                return Value::Null;
            };
            let open = crate::account::home_open(&owner.home);
            // The folders are resolved as the owner sees them, as a sync
            // does: the node's user may not look into the owner's home. A
            // node that cannot act as the owner resolves them as itself.
            let _as = crate::account::FsAs::new(&owner).ok();
            let below = given_in_home(cfg, &owner.home);
            match crate::account::home_warning(&owner.home, open, &below) {
                Some(warning) => json!({
                    "home": owner.home,
                    "mode": open.map(|m| format!("{m:o}")),
                    "below": below,
                    "warning": warning,
                }),
                None => Value::Null,
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = cfg;
            Value::Null
        }
    }

    /// Counts a `folder` mode command whose Landlock domain has no connect
    /// rule, made from a config that keeps the keys in their files, while it
    /// runs: a domain does not change while its command runs, so with the keys
    /// moved into the keyring it would reach them over the session bus. A move
    /// into the keyring is refused while one is counted. A move made after the
    /// command's config was taken refuses the command: it is counted first and
    /// looks at the keys' place then, under the store lock that a move holds,
    /// so one of the two always sees the other.
    pub fn open_to_bus(&self) -> Result<OpenToBus<'_>, &'static str> {
        self.open_to_bus.fetch_add(1, Ordering::SeqCst);
        let counted = OpenToBus(self);
        if lock(&self.store).config().machine.secret_storage != SecretStorage::File {
            return Err(KEYS_MOVED);
        }
        Ok(counted)
    }

    /// Logs once when the keyring turns folder mode's commands off, at the
    /// start and after a change of the settings: otherwise only a refused call
    /// would show it.
    fn tell_confinement(&self, cfg: &NodeConfig) {
        let keyring = self.unconfined(cfg) == Some(KEYRING_NOT_CONFINED);
        if keyring && !self.told_keyring.swap(true, Ordering::Relaxed) {
            tracing::warn!("folder mode runs no command: {KEYRING_NOT_CONFINED}");
        } else if !keyring {
            self.told_keyring.store(false, Ordering::Relaxed);
        }
    }

    pub fn center(&self, name: &str) -> Arc<CenterState> {
        lock(&self.centers)
            .entry(name.to_string())
            .or_insert_with(|| {
                Arc::new(CenterState {
                    link: Mutex::new(None),
                    status: Mutex::new("not connected".into()),
                    rotating: tokio::sync::Mutex::new(()),
                    old_pin_failed: Mutex::new(None),
                })
            })
            .clone()
    }

    /// Sends an event to `center`'s link.
    pub fn emit(&self, center: &str, cap: &str, name: &str, data: Value) {
        if let Some(l) = lock(&self.centers).get(center).and_then(|c| c.link()) {
            l.event(cap, name, data);
        }
    }

    /// Records a rotation of a key in the audit log (crate::rotate).
    pub fn audit_key(&self, center: &str, event: &str, detail: &str) {
        if let Err(err) = lock(&self.store).audit().key(center, event, detail) {
            tracing::error!("the audit log cannot be written: {err}");
        }
    }

    /// Records a decision in the local log and tells the center (if it
    /// subscribed to `audit/decision`).
    pub fn audit(&self, e: &Entry) {
        let mut e = e.clone();
        e.target = self.scrub(e.target);
        e.decision = self.scrub(e.decision);
        e.command = e.command.map(|c| self.scrub(c));
        let e = &e;
        if let Err(err) = lock(&self.store).audit().decision(e) {
            tracing::error!("the audit log cannot be written: {err}");
        }
        self.emit(&e.center, "audit", "decision", e.event_data());
    }

    /// Marks bookkeeping on a center (revoked, unknown) and tells everyone.
    /// Says whether it was saved: when not, the config in force is as it
    /// was.
    pub fn mark_center(&self, name: &str, f: impl FnOnce(&mut nerve_policy::CenterEntry)) -> bool {
        let r = lock(&self.store).mark(|c| {
            if let Some(e) = c.center_mut(name) {
                f(e);
            }
        });
        let saved = match r {
            Ok(()) => true,
            Err(e) => {
                tracing::error!("cannot save the config: {e}");
                false
            }
        };
        self.bump();
        saved
    }

    // Only the Unix control socket asks this; Windows' pipe asks the jobs of
    // the commands (crate::win::from_a_command).
    /// Whether `pid` runs below a command the node started for a center: such
    /// a process must not change the node's settings.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub fn below_command(&self, pid: Option<u32>) -> bool {
        let commands = lock(&self.commands);
        if commands.is_empty() {
            return false;
        }
        match pid {
            Some(pid) => commands
                .keys()
                .any(|&c| nerve_transport::ctl::descends_from(pid, c)),
            // Without the peer's pid the node cannot tell; refuse while
            // commands run.
            None => true,
        }
    }

    /// Whether one of `chain` (a process and its parents, as far as they
    /// were read: crate::provider::Seen) is a command the node started for a
    /// center: the process descends from it.
    #[cfg(unix)]
    pub fn runs_any(&self, chain: &[u32]) -> bool {
        lock(&self.commands).keys().any(|c| chain.contains(c))
    }

    /// What the last sync of the folders' ACLs left, on the installed Linux
    /// node (crate::acl): `status`'s `folder_grants`.
    pub fn folder_grants(&self) -> Value {
        #[cfg(target_os = "linux")]
        {
            let r = lock(&self.acl);
            json!({
                "errors": r.errors,
                "stale": r.stale,
                "failed": r.failed,
                "skipped": r.skipped,
            })
        }
        #[cfg(not(target_os = "linux"))]
        Value::Null
    }

    pub fn status(&self) -> Value {
        let cfg = self.config();
        // What the last sync of the folders' ACLs left, on the installed
        // Linux node (crate::acl).
        let grants = self.folder_grants();
        let now = crate::now_ms();
        let centers: Vec<Value> = cfg
            .centers
            .iter()
            .map(|c| {
                let cs = lock(&self.centers).get(&c.name).cloned();
                let status = match &cs {
                    Some(cs) => lock(&cs.status).clone(),
                    None => "not connected".to_string(),
                };
                json!({
                    "name": c.name,
                    "url": c.url,
                    "status": status,
                    "mode": c.policy.mode_at(now).as_str(),
                    "until": c.policy.until,
                    "as_owner": c.policy.as_owner,
                    // The account its commands run as now; none on a node
                    // run by hand, which runs them as itself.
                    "account": self.command_account(&cfg, &c.policy).ok().flatten().map(|a| a.name),
                    // Whether Landlock holds its commands now; `nerve-run`
                    // runs without it where the kernel has none.
                    "landlock": self.landlock_for(&c.policy),
                    "settings": c.settings,
                    "paused": c.paused,
                    "revoked": c.revoked,
                    "unknown": c.unknown,
                })
            })
            .collect();
        json!({
            "version": cfg.version,
            "locked": cfg.locked,
            // The installed node's owner (crate::owner), and whether it is
            // root, as whom what runs as the owner then runs.
            "owner": self.owner_name(&cfg),
            "owner_is_root": crate::owner::is_root(self.owner_name(&cfg).as_deref()),
            "confinement": self.confinement.describe(),
            "running": self.running.load(Ordering::Relaxed),
            "sudo": if self.sudo_on() { "on" } else { "off" },
            // This process found no keyring and does not look again
            // (crate::secrets::store::failed): setup restarts it after it
            // installed one.
            "keyring_failed": crate::secrets::store::failed(),
            // Why folder mode runs no command, which `confinement` alone
            // does not say once the keyring is the reason.
            "folder_commands_off": self.unconfined(&cfg),
            "command_limits": crate::cgroup::status(&cfg.limits.command, &self.cgroups),
            "providers": self.providers.status(),
            "folder_grants": grants,
            // What nerve-run may read of the owner's home without Landlock.
            "home_warning": self.home_warning(&cfg),
            "centers": centers,
            "relay": self.relay.status(&cfg),
        })
    }
}

/// A command counted by [`Shared::open_to_bus`] while it runs.
pub(crate) struct OpenToBus<'a>(&'a Shared);

impl Drop for OpenToBus<'_> {
    fn drop(&mut self) {
        self.0.open_to_bus.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Why a command decided while the node's keys were in their files does
/// not start once they are in the keyring ([`Shared::open_to_bus`]).
pub const KEYS_MOVED: &str = "the node's keys moved into the system keyring while this call was decided, and its sandbox was made for keys in files; call again";

/// Why `folder` mode runs no command where Landlock or the shim's host is
/// missing.
pub const NOT_CONFINED: &str = "commands cannot be confined on this machine";

/// Why `folder` mode runs no command with the keys in the keyring where
/// [`keys_kept_from_commands`] does not hold: a node run by hand.
#[cfg(not(windows))]
pub const KEYRING_NOT_CONFINED: &str = "commands cannot be confined on this machine while the node's keys are in the system keyring: this node runs its commands as its own user, who reaches the keyring over the session bus, so folder mode runs no command; installed as a service (`sudo nerve-node install`) it runs them as nerve-run, which does not, or `nerve-node config set machine.secret_storage file` brings them back";

/// The text of [`KEYRING_NOT_CONFINED`] on Windows, where commands run in an
/// AppContainer and the keys are in the Credential Manager: neither Landlock
/// nor the session bus exist there.
#[cfg(windows)]
pub const KEYRING_NOT_CONFINED: &str = "commands cannot be confined on this machine while the node's keys are in the system keyring: the AppContainer here is not known to keep a command from the Credential Manager the keys are in, so folder mode runs no command; `nerve-node config set machine.secret_storage file` brings them back";

/// Why commands of `folder` mode may not run ([`Shared::unconfined_as`]),
/// or `None`: `sandbox` says whether the machine confines them, `service`
/// whether this is the installed node, `account` the account they run as.
/// Where Landlock is missing, `nerve-run` is held to its folders by its own
/// account and the ACLs alone, and the installed Linux node runs its
/// commands without it (docs/user/modes.md). `account` is asked only when
/// the answer depends on it.
pub fn folder_refusal(
    sandbox: bool,
    service: bool,
    storage: SecretStorage,
    account: impl FnOnce() -> Option<crate::service::Account>,
) -> Option<&'static str> {
    if sandbox && storage == SecretStorage::File {
        return None;
    }
    let account = account();
    let held = service
        && cfg!(target_os = "linux")
        && account
            .as_ref()
            .is_some_and(|a| a.name == crate::account::RUN_USER);
    if !sandbox && !held {
        return Some(NOT_CONFINED);
    }
    let kept = keys_kept_from_commands(storage, || account);
    (!kept).then_some(KEYRING_NOT_CONFINED)
}

/// Whether a confined command of `account` (`None`: the node's own user)
/// cannot reach the node's keys where `storage` keeps them. Files are out of
/// its sandbox. The keyring answers on the session bus of the node's user,
/// whose folder is open to that user (and root) alone. `account` is asked
/// only for the keyring.
pub fn keys_kept_from_commands(
    storage: SecretStorage,
    account: impl FnOnce() -> Option<crate::service::Account>,
) -> bool {
    storage == SecretStorage::File || account().is_some_and(|a| a.uid != 0)
}

/// Whether a command confined by `landlock` and run as `account` could
/// reach the keys over the session bus once they are in the keyring
/// ([`Shared::open_to_bus`]): only the node's own user (or root) does.
/// `account` is asked only for a confined command.
pub fn reaches_bus(
    landlock: Option<&nerve_sandbox::LandlockSpec>,
    account: impl FnOnce() -> Option<crate::service::Account>,
) -> bool {
    landlock.is_some() && !keys_kept_from_commands(SecretStorage::Keyring, account)
}

/// A running node daemon.
pub struct Daemon {
    shared: Arc<Shared>,
    supervisor: JoinHandle<()>,
    relay: JoinHandle<()>,
    ctl: Option<JoinHandle<()>>,
    /// The owner endpoint's task and its socket (crate::owner).
    owner: Option<(JoinHandle<()>, PathBuf)>,
    /// The provider socket's task and its path (crate::provider::serve).
    providers: Option<(JoinHandle<()>, PathBuf)>,
    /// Held while the node runs: a CLI moves the keys only while no node
    /// reads them.
    _keys: crate::secrets::KeysLock,
}

/// Whether a node runs on the control socket. One that takes no connection
/// now (its queue is full) runs all the same. A socket that cannot be
/// reached at all says neither way: its error comes back as the start's.
#[cfg(unix)]
async fn node_runs(paths: &NodePaths) -> Result<bool, String> {
    let outcome = nerve_transport::ctl::call(&paths.ctl_socket(), "status", json!({})).await;
    nerve_transport::ctl::node_is_there(&outcome)
        .map_err(|e| format!("cannot tell whether a node runs for this state directory: {e}"))
}

impl Daemon {
    /// Starts the daemon: loads the config, serves the control socket, dials
    /// every center that is not paused, revoked or unknown.
    pub async fn start(opts: NodeOptions) -> Result<Daemon, String> {
        let full = opts.full_rights.unwrap_or_else(crate::rights::full_rights);
        Daemon::start_with(opts, full).await
    }

    /// [`Daemon::start`] for a process whose rights are `full_rights`: root,
    /// or an elevated token on Windows. A test cannot be root.
    async fn start_with(opts: NodeOptions, full_rights: bool) -> Result<Daemon, String> {
        nerve_transport::init_crypto();
        let paths = opts.paths.clone();
        // Both exist before the first command runs, so Landlock can leave
        // them out by their real paths.
        for dir in [&paths.state_dir, &paths.config_dir] {
            nerve_transport::files::create_private_dir(dir)
                .map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        // Where the keys may not be in the keyring, a node.toml that keeps
        // them there is refused: the installed node on Windows would look
        // in the Credential Manager of its own account, which holds none of
        // them.
        if crate::secrets::stated_storage(&paths) == SecretStorage::Keyring
            && let Some(n) = crate::secrets::no_keyring(&paths)
        {
            let then = match n {
                crate::secrets::NoKeyring::WindowsService => {
                    "`Restart-Service nerve-node` starts it"
                }
            };
            return Err(crate::secrets::keyring_refused(
                &paths,
                n,
                "the node does not start",
                then,
            ));
        }
        // Keys in the keyring of the node's own session: the system-wide
        // environment of the login can have given that session another
        // user's folders again since `setup` put it right (a reboot).
        #[cfg(target_os = "linux")]
        if crate::secrets::stated_storage(&paths) == SecretStorage::Keyring {
            match tokio::task::spawn_blocking(crate::keyring_setup::repair_for_start).await {
                Ok(Ok(true)) => tracing::info!("set the session of the keyring right again"),
                Ok(Err(e)) => tracing::warn!("the session of the keyring: {e}"),
                _ => {}
            }
        }
        let keys = match crate::secrets::KeysLock::try_take(&paths)? {
            Some(l) => l,
            None => {
                #[cfg(unix)]
                if opts.ctl && node_runs(&paths).await? {
                    return Err("a node daemon already runs for this state directory".into());
                }
                // A command that moves the keys holds it for a moment.
                crate::secrets::KeysLock::take(&paths, Duration::from_secs(10))
                    .await?
                    .ok_or_else(|| {
                        format!(
                            "another nerve-node holds {}: a node runs for this state directory, or a command moves its keys",
                            paths.keys_lock().display()
                        )
                    })?
            }
        };
        let open_to_bus = Arc::new(AtomicUsize::new(0));
        let mut store = SettingsStore::open_with(
            paths.config_file(),
            Box::new(crate::secrets::NodeSecrets::for_node(
                &paths,
                open_to_bus.clone(),
            )),
            AuditLog::new(paths.audit_log()),
        )?;
        let cfg = store.config().clone();
        // With the config checked, a move of the keys that stopped half way
        // is finished by it.
        crate::secrets::settle(&paths, &cfg);
        if let Some(log) = &opts.log {
            log.set_level(cfg.log.level);
            // The node runs without a log file it cannot open; stderr and the
            // service manager still have the lines.
            if let Err(e) = log.attach_file(paths.log_file()) {
                eprintln!("cannot open the log {}: {e}", paths.log_file().display());
            }
        }
        store.on_change(|by, version, changes| {
            nerve_transport::log::emit(Level::Info, None, &describe_change(by, version, changes));
        });
        if let Some(warning) = crate::rights::check(full_rights, cfg.machine.allow_root)? {
            tracing::warn!("{warning}");
        }
        #[cfg(unix)]
        if opts.ctl && node_runs(&paths).await? {
            return Err("a node daemon already runs for this state directory".into());
        }
        let (changed, _) = watch::channel(0);
        let (stop, _) = watch::channel(false);
        let service = opts
            .service
            .unwrap_or_else(|| crate::service::is_service_node(&paths));
        #[cfg(unix)]
        if service && nerve_transport::net::euid() != 0 && !crate::account::can_switch() {
            tracing::warn!(
                "this is the installed node, started without CAP_SETUID and CAP_SETGID: it runs no command; start it as the service: `sudo systemctl start nerve-node`"
            );
        }
        // The stored password of the account the commands run as is in the
        // config folder (crate::win_user).
        #[cfg(windows)]
        {
            crate::win_user::init(&paths.config_dir);
            if service && crate::account::own_uid() != 0 && !crate::account::can_switch() {
                tracing::warn!(
                    "this is the installed node, started without SeAssignPrimaryTokenPrivilege: it runs no command; start it as the service: `Start-Service nerve-node`"
                );
            }
        }
        let cgroups = opts
            .cgroups
            .unwrap_or_else(|| crate::cgroup::Cgroups::find().map(Arc::new));
        let endpoint = opts.owners.filter(|_| opts.ctl);
        let shared = Arc::new(Shared {
            paths: paths.clone(),
            service,
            exe: opts.exe,
            home: opts.home,
            platform: crate::paths::platform(),
            confinement: confinement_for(
                opts.confinement.unwrap_or_else(Confinement::detect),
                service,
            ),
            cgroups,
            store: Mutex::new(store),
            changed,
            centers: Mutex::default(),
            commands: Mutex::default(),
            running: AtomicUsize::new(0),
            open_to_bus,
            stop,
            log: opts.log,
            sudo: Mutex::new(None),
            sudo_offers: Mutex::default(),
            sudo_for: Mutex::default(),
            account_cache: Mutex::default(),
            told_keyring: Default::default(),
            grace: opts.resume_grace,
            providers: Default::default(),
            #[cfg(target_os = "linux")]
            provider_socket: endpoint.as_ref().map(|e| e.provider_socket()),
            relay: Default::default(),
            aside: opts.aside,
            owner: opts.owner,
            own_user: crate::account::own_name(),
            #[cfg(target_os = "linux")]
            acl: Mutex::default(),
            #[cfg(target_os = "linux")]
            acl_tried: Mutex::default(),
        });
        shared.tell_confinement(&cfg);
        // A file that says on starts off: on Linux the password lives in
        // memory only; Windows holds the one kept with DPAPI (crate::winsudo).
        shared.settle_sudo();
        let ctl = if opts.ctl {
            Some(start_ctl(shared.clone()).await?)
        } else {
            None
        };
        // A node whose provider socket cannot be made runs on without it:
        // no program of its owner attaches then.
        #[cfg(target_os = "linux")]
        let providers = match &endpoint {
            Some(e) => {
                let at = e.provider_socket();
                match crate::provider::serve(shared.clone(), at.clone(), e.owners.clone()).await {
                    Ok(task) => Some((task, at)),
                    Err(e) => {
                        tracing::error!("{e}; no program of the owner attaches as a provider");
                        None
                    }
                }
            }
            None => None,
        };
        #[cfg(not(target_os = "linux"))]
        let providers = None;
        // A node whose owner endpoint cannot be made runs on without it:
        // its owners then need root, as before there was one.
        let owner = match endpoint {
            Some(e) => {
                let at = e.at.clone();
                match crate::owner::serve(shared.clone(), e).await {
                    Ok(task) => Some((task, at)),
                    Err(e) => {
                        tracing::error!("{e}; the node's owners need root to change it");
                        None
                    }
                }
            }
            None => None,
        };
        let supervisor = tokio::spawn(supervise(shared.clone()));
        let relay = tokio::spawn(crate::relay::run(shared.clone()));
        tracing::info!(
            "node daemon running (nerve-node {}, {} centers, confinement {}, log level {})",
            crate::descriptor::VERSION,
            cfg.centers.len(),
            shared.confinement.describe(),
            cfg.log.level
        );
        // After the start line, which opens the node's part of the log.
        match &shared.cgroups {
            Ok(c) => tracing::info!(
                "commands are held to their limits ({}) in the cgroup {}",
                c.enforced().join(", "),
                c.name()
            ),
            // The installed Linux node is meant to have them; a node of the
            // owner's own often is not.
            Err(why) if service && cfg!(target_os = "linux") => {
                tracing::warn!("commands run without their limits: {why}")
            }
            Err(why) => tracing::info!("commands run without their limits: {why}"),
        }
        Ok(Daemon {
            shared,
            supervisor,
            relay,
            ctl,
            owner,
            providers,
            _keys: keys,
        })
    }

    pub fn paths(&self) -> &NodePaths {
        &self.shared.paths
    }

    /// The log the daemon writes to, if it was given one.
    pub fn log(&self) -> Option<&Arc<Log>> {
        self.shared.log.as_ref()
    }

    /// The config as the daemon holds it now.
    pub fn config(&self) -> NodeConfig {
        self.shared.config()
    }

    /// What `nerve-node status` shows.
    pub fn status(&self) -> Value {
        self.shared.status()
    }

    /// The relay's state, for a test.
    #[cfg(test)]
    pub(crate) fn relay(&self) -> &crate::relay::Relays {
        &self.shared.relay
    }

    /// Changes the config in force as the owner's CLI does over the control
    /// socket, for tests whose daemon has none (or runs on Windows).
    #[cfg(test)]
    pub(crate) fn owner_edit(&self, f: impl FnOnce(&mut NodeConfig)) {
        lock(&self.shared.store)
            .update(|c| {
                f(c);
                Ok(())
            })
            .expect("the owner's edit");
        self.shared.bump();
    }

    /// How many `folder` mode commands run now that the keys do not move
    /// into the keyring past ([`Shared::open_to_bus`]).
    pub fn open_to_bus(&self) -> usize {
        self.shared.open_to_bus.load(Ordering::SeqCst)
    }

    /// Reads the config file again (what SIGHUP does). Only a file the node
    /// signed is applied; any other is refused and the old config stays.
    pub fn reload(&self) -> Result<bool, String> {
        self.shared.reload()
    }

    /// Ends every link with `bye shutdown` and stops.
    pub async fn stop(self) {
        tracing::info!("node daemon stopping");
        self.shared.stop.send_replace(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), self.supervisor).await;
        // Their connections outlive the socket's task otherwise.
        self.shared.providers.detach_all();
        let _ = tokio::time::timeout(Duration::from_secs(2), self.relay).await;
        if let Some(c) = self.ctl {
            c.abort();
            let socket = self.shared.paths.ctl_socket();
            let _ = std::fs::remove_file(nerve_transport::ctl::token_file(&socket));
            let _ = std::fs::remove_file(socket);
        }
        if let Some((task, _at)) = self.owner {
            task.abort();
            #[cfg(unix)]
            let _ = std::fs::remove_file(_at);
        }
        if let Some((task, _at)) = self.providers {
            task.abort();
            #[cfg(unix)]
            let _ = std::fs::remove_file(_at);
        }
        tracing::info!("node daemon stopped");
    }

    /// Runs until SIGINT or SIGTERM; SIGHUP reloads the config.
    pub async fn run(opts: NodeOptions) -> Result<(), String> {
        let (tx, events) = tokio::sync::mpsc::unbounded_channel();
        // The signals are taken for the whole run, on a task of their own: one
        // that comes while the node is stopped for an owner's restore still
        // counts after it.
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut term = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
            let mut hup = signal(SignalKind::hangup()).map_err(|e| e.to_string())?;
            tokio::spawn(async move {
                loop {
                    let e = tokio::select! {
                        _ = tokio::signal::ctrl_c() => Event::Stop,
                        _ = term.recv() => Event::Stop,
                        _ = hup.recv() => Event::Reload,
                    };
                    if tx.send(e).is_err() {
                        return;
                    }
                }
            });
        }
        // Under the service control manager, its stop request ends the node.
        #[cfg(windows)]
        {
            crate::win_service::running();
            tokio::spawn(async move {
                if crate::win_service::is_service() {
                    crate::win_service::stop_requested().await;
                } else {
                    let _ = tokio::signal::ctrl_c().await;
                }
                let _ = tx.send(Event::Stop);
            });
        }
        #[cfg(not(any(unix, windows)))]
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = tx.send(Event::Stop);
        });
        Daemon::run_until(opts, events).await
    }

    /// Runs the node until `events` says stop, or ends; a reload reads the
    /// config again. Work for while the node is stopped
    /// ([`NodeOptions::aside`]) stops it, runs, and starts it again; a
    /// start that fails then ends this with its error, and the service
    /// manager starts the node again.
    pub async fn run_until(
        mut opts: NodeOptions,
        mut events: tokio::sync::mpsc::UnboundedReceiver<Event>,
    ) -> Result<(), String> {
        let (tx, mut asides) = tokio::sync::mpsc::unbounded_channel();
        opts.aside = Some(tx);
        let mut d = Daemon::start(opts.clone()).await?;
        loop {
            let job = tokio::select! {
                e = events.recv() => match e {
                    Some(Event::Reload) => {
                        let _ = d.reload();
                        continue;
                    }
                    Some(Event::Stop) | None => break,
                },
                Some(job) = asides.recv() => job,
            };
            tracing::info!("the node stops for an owner's restore, and starts again after it");
            d.stop().await;
            job.await;
            d = Daemon::start(opts.clone()).await?;
        }
        d.stop().await;
        Ok(())
    }
}

/// Keeps one link task per center that should be linked. It works from the
/// config in memory: the file is not reread here, so a file changed behind
/// the node's back changes nothing (only the owner's reload reads it).
async fn supervise(shared: Arc<Shared>) {
    let mut tasks: HashMap<String, JoinHandle<()>> = HashMap::new();
    let mut changed = shared.changed.subscribe();
    let mut stop = shared.stop.subscribe();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut granted: Option<u64> = None;
    #[cfg(target_os = "linux")]
    let mut acl_synced: Option<u64> = None;
    loop {
        shared.settle_sudo();
        let cfg = shared.config();
        // The folder grants follow the config as it changes (crate::grants);
        // a command syncs them as well before it runs.
        if shared.confinement.appcontainer && granted != Some(cfg.version) {
            granted = Some(cfg.version);
            let (s, c) = (shared.clone(), cfg.clone());
            tokio::task::spawn_blocking(move || {
                let synced = crate::grants::apply(&s.paths, &c, &s.rules_home(&c), &mut |m| {
                    tracing::info!("folder grants: {m}")
                });
                for e in synced.errors {
                    tracing::warn!("folder grants: {e}");
                }
            });
        }
        // On the installed Linux node the folders' ACLs follow it so
        // (crate::acl); a command of `nerve-run` syncs them as well before
        // it runs.
        #[cfg(target_os = "linux")]
        if shared.service && acl_synced != Some(cfg.version) {
            acl_synced = Some(cfg.version);
            let (s, c) = (shared.clone(), cfg.clone());
            tokio::task::spawn_blocking(move || s.sync_acls(&c, false));
        }
        // The level follows the config, whoever changed it and however.
        if let Some(log) = &shared.log {
            log.set_level(cfg.log.level);
        }
        // A provider the owner no longer allows goes, and its capabilities
        // with it.
        if shared.providers.follow_config(&cfg) {
            shared.bump();
        }
        tasks.retain(|_, t| !t.is_finished());
        if !cfg.locked {
            for c in cfg.centers.iter().filter(|c| c.dials()) {
                if !tasks.contains_key(&c.name) {
                    let t = tokio::spawn(crate::link::run_center(shared.clone(), c.name.clone()));
                    tasks.insert(c.name.clone(), t);
                }
            }
        }
        lock(&shared.centers).retain(|n, _| cfg.center(n).is_some());
        changed.borrow_and_update();
        tokio::select! {
            _ = tick.tick() => {}
            _ = changed.changed() => {}
            _ = stop.changed() => break,
        }
    }
    // Each link task sends its `bye shutdown` and ends.
    for (_, t) in tasks {
        let _ = tokio::time::timeout(Duration::from_secs(3), t).await;
    }
}

#[cfg(unix)]
async fn start_ctl(shared: Arc<Shared>) -> Result<JoinHandle<()>, String> {
    let path = shared.paths.ctl_socket();
    if let Some(dir) = path.parent() {
        nerve_transport::files::create_private_dir(dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    // Fails early when another daemon holds the socket.
    let listener = nerve_transport::ctl::bind(&path)
        .await
        .map_err(|e| format!("{}: {e}", path.display()))?;
    // A command of the node's own user in `folder` mode can connect to the
    // socket where Landlock does not reach it, and a process it left behind
    // (`setsid`) is below no command the node knows. The token is in the
    // own folders, which its rules leave out.
    let token = nerve_transport::ctl::write_token(&path)
        .map_err(|e| format!("{}: {e}", nerve_transport::ctl::token_file(&path).display()))?;
    let s = shared.clone();
    let task = tokio::spawn(async move {
        let r = nerve_transport::ctl::serve_on(listener, move |req, peer| {
            let s = s.clone();
            let token = token.clone();
            async move { answer(&s, &token, req, peer).await }
        })
        .await;
        if let Err(e) = r {
            tracing::error!("the control socket stopped: {e}");
        }
    });
    // The socket is bound already, so a CLI started right after finds the
    // daemon.
    Ok(task)
}

/// Windows: the control pipe (crate::pipe). A node whose pipe cannot be
/// made runs on without it, as a node without a channel did before: the CLI
/// then writes the signed file, which the node takes at its next start.
/// Failing the start instead would let any account that takes the pipe's
/// name first keep the node from running.
#[cfg(windows)]
async fn start_ctl(shared: Arc<Shared>) -> Result<JoinHandle<()>, String> {
    match crate::pipe::serve(shared) {
        Ok(task) => Ok(task),
        Err(e) => {
            tracing::error!(
                "{e}; a change from the CLI takes effect at the next start of the node"
            );
            Ok(tokio::spawn(async {}))
        }
    }
}

#[cfg(not(any(unix, windows)))]
async fn start_ctl(_shared: Arc<Shared>) -> Result<JoinHandle<()>, String> {
    Ok(tokio::spawn(async {}))
}

/// What [`Shared::add_folder`] stored.
#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
pub struct AddedFolder {
    /// The path the folder is stored at.
    pub stored: String,
    /// Whether it is recorded at its real place (`CenterPolicy::places`).
    pub recorded: bool,
    /// The center's mode, for the CLI's note on folders that do not count.
    pub mode: nerve_policy::Mode,
    /// Whether the center's folders hold its commands now: in folder mode,
    /// and in every mode whose commands run as `nerve-run`.
    pub counts: bool,
}

/// The message of a refused `folder add`, for the CLI and the node alike.
pub fn refusal(path: &str, why: &str) -> String {
    format!(
        "{path}: {why}. A command may have put a link there: look at it (`ls -l`, `dir /AL`), add the place you mean by its own path, or remove the link"
    )
}

/// Why the pipe refuses a folder change while `node.toml` (version
/// `on_disk`) holds changes the node (version `in_force`) has not taken.
fn file_ahead(on_disk: u64, in_force: u64) -> String {
    format!(
        "node.toml holds changes the running node takes at its next start (version {on_disk} there, {in_force} in force), and this change would undo them; nothing was changed. Restart the node (`Restart-Service nerve-node` for the installed node), then change the folder again"
    )
}

/// Why a request from a process of a command the node runs is refused.
const FROM_A_COMMAND: &str =
    "refused: this request comes from a command the node runs for a center";

/// One request on Windows' control pipe (crate::pipe): the status, the
/// capabilities for `cap ls` (crate::provider::listing), and the changes to
/// a center's folders, checked and made as the CLI makes them on
/// the file (crate::folder_change). The node then brings the folder grants
/// in line before it answers, as the CLI does after it wrote the file.
/// Nothing is taken from a process of a command the node runs, not even the
/// status. The socket's other methods are not served here yet.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) async fn pipe_control(
    shared: &Arc<Shared>,
    method: &str,
    params: Value,
    from_command: bool,
) -> nerve_transport::ctl::Reply {
    use nerve_transport::ctl::Reply;
    if from_command {
        return Reply::Err(FROM_A_COMMAND.into());
    }
    match method {
        "status" => Reply::Ok(shared.status()),
        "caps.list" => Reply::Ok(crate::provider::listing(
            &shared.config(),
            Some(shared),
            shared.service,
        )),
        "center.rotate-key" => rotate_key(shared, &params).await,
        "folder.add" | "folder.set" | "folder.rm" => {
            let (center, change) =
                match crate::folder_change::FolderChange::from_request(method, params) {
                    Ok(r) => r,
                    Err(e) => return Reply::Err(e),
                };
            let mut applied = None;
            let r = {
                let mut store = lock(&shared.store);
                // On Windows the CLI writes every other change to the file
                // for the next start. The node saves its whole config, so a
                // file newer than it would lose that change: it is refused
                // instead.
                match store.version_on_disk() {
                    Ok(on_disk) if on_disk > store.version() => {
                        return Reply::Err(file_ahead(on_disk, store.version()));
                    }
                    Ok(_) => {}
                    Err(e) => return Reply::Err(format!("cannot read node.toml: {e}")),
                }
                store.update(|cfg| {
                    applied = Some(crate::folder_change::apply_to(
                        cfg,
                        center.as_deref(),
                        &change,
                    )?);
                    Ok(())
                })
            };
            let version = match r {
                Ok(v) => v,
                Err(e) => return Reply::Err(e.to_string()),
            };
            shared.bump();
            if shared.confinement.appcontainer {
                let s = shared.clone();
                let synced = tokio::task::spawn_blocking(move || {
                    let cfg = s.config();
                    crate::grants::apply(&s.paths, &cfg, &s.rules_home(&cfg), &mut |m| {
                        tracing::info!("folder grants: {m}")
                    })
                })
                .await
                .map_err(|e| e.to_string())
                .and_then(|s| s.errors.into_iter().next().map_or(Ok(()), Err));
                if let Err(e) = synced {
                    return Reply::Err(format!(
                        "the config is saved, but the folder grants do not follow it: {e}"
                    ));
                }
            }
            let mut answer = serde_json::to_value(applied).unwrap_or_default();
            answer["version"] = json!(version);
            Reply::Ok(answer)
        }
        other => Reply::Err(format!("unknown method {other}")),
    }
}

/// `center.rotate-key {center, end_grace}`: the owner rotates the node's key
/// for a center, or ends the grace of its old key (crate::rotate).
async fn rotate_key(shared: &Arc<Shared>, params: &Value) -> nerve_transport::ctl::Reply {
    use nerve_transport::ctl::Reply;
    let Some(center) = params.get("center").and_then(Value::as_str) else {
        return Reply::Err("center is missing".into());
    };
    let r = if params.get("end_grace").and_then(Value::as_bool) == Some(true) {
        crate::rotate::end_grace(shared, center).await
    } else {
        crate::rotate::rotate(shared, center).await
    };
    match r {
        Ok(v) => Reply::Ok(v),
        Err(e) => Reply::Err(e),
    }
}

/// Why a request without the control socket's token is refused.
#[cfg(unix)]
const NO_TOKEN: &str = "refused: this request does not carry the control socket's token, which only the owner's own programs can read";

/// One request that came in on the control socket, from `peer`: only one
/// that carries the socket's `token` is answered.
#[cfg(unix)]
async fn answer(
    shared: &Arc<Shared>,
    token: &str,
    req: nerve_transport::ctl::CtlRequest,
    peer: nerve_transport::ctl::Peer,
) -> nerve_transport::ctl::Reply {
    if !nerve_transport::ctl::token_ok(token, req.token.as_deref()) {
        return nerve_transport::ctl::Reply::Err(NO_TOKEN.into());
    }
    match req.method.as_str() {
        // Checking the password runs `sudo -v`, so it cannot block inside
        // `control`.
        "sudo.on" => sudo_on(shared, req.params, peer.pid).await,
        // A rotation waits for the center's answer.
        "center.rotate-key" => {
            if shared.below_command(peer.pid) {
                return nerve_transport::ctl::Reply::Err(FROM_A_COMMAND.into());
            }
            rotate_key(shared, &req.params).await
        }
        // The folders' ACLs brought in line with the config now, also a
        // grant that failed before, and what that left: the CLI tells the
        // owner after a change of the folders (crate::acl).
        "folder.grants" => {
            if shared.below_command(peer.pid) {
                return nerve_transport::ctl::Reply::Err(FROM_A_COMMAND.into());
            }
            let s = shared.clone();
            let r = tokio::task::spawn_blocking(move || {
                #[cfg(target_os = "linux")]
                s.sync_acls(&s.config(), true);
                s.folder_grants()
            })
            .await;
            match r {
                Ok(v) => nerve_transport::ctl::Reply::Ok(v),
                Err(e) => nerve_transport::ctl::Reply::Err(e.to_string()),
            }
        }
        // A capability provider attaches; its connection stays
        // (crate::provider).
        "hello" => {
            // Here the command check reads as the node and no pidfd holds
            // the caller, which the installed node's provider socket does
            // with the caller's rights; root, who may connect here too,
            // goes there as well.
            #[cfg(target_os = "linux")]
            if let Some(at) = &shared.provider_socket {
                return nerve_transport::ctl::Reply::Err(format!(
                    "refused: the installed node takes a provider's hello on {} only",
                    at.display()
                ));
            }
            if shared.below_command(peer.pid) {
                return nerve_transport::ctl::Reply::Err(FROM_A_COMMAND.into());
            }
            let caller = crate::provider::Caller {
                uid: peer.uid,
                pid: peer.pid,
                pidfd: None,
                refuse_commands: false,
            };
            crate::provider::attach(shared, req.params, caller).await
        }
        m => control(shared, m, req.params, peer.pid),
    }
}

/// `sudo.on {password}`: the CLI on this machine turns the switch on. The
/// socket is the owner's only, so the password travels in the clear here.
#[cfg(unix)]
async fn sudo_on(
    shared: &Arc<Shared>,
    params: Value,
    pid: Option<u32>,
) -> nerve_transport::ctl::Reply {
    use nerve_transport::ctl::Reply;
    if shared.below_command(pid) {
        return Reply::Err(FROM_A_COMMAND.into());
    }
    let Some(password) = params.get("password").and_then(Value::as_str) else {
        return Reply::Err("password is missing".into());
    };
    match shared
        .sudo_switch_on(nerve_policy::Writer::Local, password.to_string())
        .await
    {
        Ok(v) => Reply::Ok(json!({"sudo": "on", "version": v})),
        Err(e) => Reply::Err(e.to_string()),
    }
}

/// One control-socket request. Every method is refused from below a center's
/// command: the reading ones too, as `status` and `config.read` hand over the
/// whole config, which the command's sandbox keeps from it as a file.
/// `owner.check` changes nothing itself: the CLI asks it before `install`,
/// `setup`, `update`, `uninstall`, `backup` and `restore`, which change the
/// node or take its keys.
#[cfg(unix)]
pub(crate) fn control(
    shared: &Arc<Shared>,
    method: &str,
    params: Value,
    pid: Option<u32>,
) -> nerve_transport::ctl::Reply {
    use nerve_transport::ctl::Reply;
    if shared.below_command(pid) {
        return Reply::Err(FROM_A_COMMAND.into());
    }
    let str_of = |k: &str| params.get(k).and_then(Value::as_str).map(str::to_string);
    match method {
        "status" => Reply::Ok(shared.status()),
        // Every capability with its effect and settings, the programs'
        // too (crate::provider::listing), for `cap ls`.
        "caps.list" => Reply::Ok(crate::provider::listing(
            &shared.config(),
            Some(shared),
            shared.service,
        )),
        "owner.check" => Reply::Ok(json!({})),
        "sudo.status" => Reply::Ok(json!({"sudo": if shared.sudo_on() { "on" } else { "off" }})),
        "sudo.off" => match shared.sudo_switch_off(nerve_policy::Writer::Local) {
            Ok(v) => Reply::Ok(json!({"sudo": "off", "version": v})),
            Err(e) => Reply::Err(e.to_string()),
        },
        "config.read" => {
            let s = lock(&shared.store);
            Reply::Ok(json!({"config": s.config().to_toml(), "version": s.version()}))
        }
        "config.write" => {
            let Some(text) = str_of("config") else {
                return Reply::Err("config is missing".into());
            };
            let mut new = match NodeConfig::parse(&text) {
                Ok(c) => c,
                Err(e) => return Reply::Err(e),
            };
            let if_version = params.get("if_version").and_then(Value::as_u64);
            let mut store = lock(&shared.store);
            if new.machine.sudo != store.config().machine.sudo {
                return Reply::Err(
                    "machine.sudo changes only through nerve-node sudo on|off".into(),
                );
            }
            // An action that comes to sense waits for the owner's `on`,
            // whichever program of the owner's wrote the change.
            let held = crate::config_cap::hold_new(store.config(), &mut new);
            // Who made it, as the CLI names its user (crate::cli::invoker):
            // only the owner's programs hold the token.
            store.set_user(str_of("user"));
            let r = store.set_local(new, if_version);
            store.set_user(None);
            drop(store);
            match r {
                Ok(v) => {
                    shared.bump();
                    Reply::Ok(json!({"version": v, "held": held}))
                }
                Err(SetError::Conflict { current }) => {
                    Reply::Err(format!("conflict: the config changed (version {current})"))
                }
                Err(e) => Reply::Err(e.to_string()),
            }
        }
        "folder.add" => {
            let (Some(center), Some(path), Some(access)) =
                (str_of("center"), str_of("path"), str_of("access"))
            else {
                return Reply::Err("center, path and access are needed".into());
            };
            let access = match nerve_policy::config::Access::parse(&access) {
                Ok(a) => a,
                Err(e) => return Reply::Err(e),
            };
            match shared.add_folder(&center, &path, access) {
                Ok(a) => Reply::Ok(json!({
                    "stored": a.stored,
                    "recorded": a.recorded,
                    "mode": a.mode.as_str(),
                    "counts": a.counts,
                })),
                Err(e) => Reply::Err(e),
            }
        }
        "config.accept" => {
            let r = {
                let mut store = lock(&shared.store);
                store.set_user(str_of("user"));
                // The file as the owner wrote it, with an action that came to
                // sense in it switched off where an earlier switch covered it
                // (crate::config_cap::hold_new), in the one write that puts
                // it in force.
                let r = store.accept_with(crate::config_cap::hold_new);
                store.set_user(None);
                r
            };
            match r {
                Ok((v, held)) => {
                    shared.settle_sudo();
                    shared.bump();
                    Reply::Ok(json!({"version": v, "held": held}))
                }
                Err(e) => Reply::Err(e.to_string()),
            }
        }
        "cap.refusal" => {
            // Why the node refuses calls of the owner's command now, as it
            // judges it before a call: as the owner, from the owner's home
            // (`cap add` and `cap edit` warn of it).
            let Some(name) = str_of("name") else {
                return Reply::Err("name is missing".into());
            };
            let cfg = shared.config();
            let Some(decl) = cfg.capabilities.iter().find(|c| c.name == name) else {
                return Reply::Err(format!("no capability {name} is declared"));
            };
            // One this node does not offer has no calls here to refuse.
            if decl.account != nerve_policy::config::RunsAs::Owner
                || crate::config_cap::left_out(decl, std::env::consts::OS, shared.service).is_some()
            {
                return Reply::Ok(json!({"refusal": null}));
            }
            let owner = shared.owner_account(&cfg).ok().flatten();
            let refusal = match shared.owner_command(&cfg, decl, owner.as_ref()) {
                Err(why) => Some(why),
                Ok(None) => Some(crate::config_cap::no_program(decl)),
                Ok(Some(_)) => None,
            };
            Reply::Ok(json!({"refusal": refusal}))
        }
        "reload" => match shared.reload() {
            Ok(changed) => Reply::Ok(json!({"changed": changed})),
            Err(e) => Reply::Err(e),
        },
        other => Reply::Err(format!("unknown method {other}")),
    }
}

/// Settings whose values are not told in the log, only that they changed.
fn is_quiet_key(key: &str) -> bool {
    key.starts_with("connection")
        || key.starts_with("relay.node")
        || key.ends_with(".pin")
        || key.ends_with("_id")
}

/// A value as the log tells it: a word or a number plainly, anything longer
/// cut.
fn show_value(v: &Value) -> String {
    let text = match v {
        Value::Null => "unset".to_string(),
        // A rule of the guard holds tabs and line breaks; the log is lines.
        Value::String(s) => nerve_policy::rules::escape_controls(s),
        other => other.to_string(),
    };
    clip(&text, 80)
}

fn clip(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        Some((end, _)) => format!("{}…", &text[..end]),
        None => text.to_string(),
    }
}

/// The entries of a list setting. A list that is empty is not in the file, so
/// an unset one is an empty list.
fn list_of(v: &Value) -> Option<&[Value]> {
    match v {
        Value::Array(a) => Some(a),
        Value::Null => Some(&[]),
        _ => None,
    }
}

/// What a changed leaf of the settings says: both values of a plain setting,
/// what a list gained and lost, and for a secret-bearing one only its name.
fn describe_leaf(key: &str, old: &Value, new: &Value) -> String {
    if is_quiet_key(key) {
        return format!("{key} changed");
    }
    let is_list = |v: &Value| matches!(v, Value::Array(_));
    if is_list(old) || is_list(new) {
        let (Some(o), Some(n)) = (list_of(old), list_of(new)) else {
            return format!("{key} changed");
        };
        let mut out = key.to_string();
        for v in n.iter().filter(|v| !o.contains(v)) {
            out.push_str(&format!(" +{}", show_value(v)));
        }
        for v in o.iter().filter(|v| !n.contains(v)) {
            out.push_str(&format!(" -{}", show_value(v)));
        }
        return out;
    }
    match (old, new) {
        (Value::Object(_), _) | (_, Value::Object(_)) => format!("{key} changed"),
        (o, n) => format!("{key}: {} -> {}", show_value(o), show_value(n)),
    }
}

/// A change to the settings, for the log: who, the version it made, and each
/// setting that differs. The paired centers are a list, so one is looked into
/// by its name; a center that came or went is told by its name alone.
fn describe_change(by: &str, version: u64, changes: &[Change]) -> String {
    let named = |v: &Value| -> std::collections::BTreeMap<String, Value> {
        v.as_array()
            .into_iter()
            .flatten()
            .filter_map(|c| Some((c.get("name")?.as_str()?.to_string(), c.clone())))
            .collect()
    };
    let mut told = Vec::new();
    for c in changes {
        if c.key != "center" {
            told.push(describe_leaf(&c.key, &c.old, &c.new));
            continue;
        }
        let (old, new) = (named(&c.old), named(&c.new));
        for (name, n) in &new {
            match old.get(name) {
                None => told.push(format!("center {name} was added")),
                Some(o) => {
                    for d in diff(o, n) {
                        told.push(describe_leaf(
                            &format!("center.{name}.{}", d.key),
                            &d.old,
                            &d.new,
                        ));
                    }
                }
            }
        }
        for name in old.keys().filter(|n| !new.contains_key(*n)) {
            told.push(format!("center {name} was removed"));
        }
    }
    format!(
        "settings changed by {by} (version {version}): {}",
        told.join("; ")
    )
}

/// The folders in `home` that the pairings whose commands run as
/// `nerve-run` give it, as the owner named them (resolved, `~` the owner's
/// home), not as they are split around the protected entries: `home` itself
/// where it is given whole, also by a folder around it. The home is
/// resolved too, as the folders are: where its path runs through a link,
/// the entries go on the real one (crate::acl), and a folder in it is told
/// under the home as the account database names it.
#[cfg(target_os = "linux")]
fn given_in_home(cfg: &NodeConfig, home: &std::path::Path) -> Vec<PathBuf> {
    use nerve_policy::paths::within;
    let now = crate::now_ms();
    let real = std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
    let mut out: Vec<PathBuf> = Vec::new();
    for c in cfg.centers.iter().filter(|c| !c.policy.runs_as_owner(now)) {
        for f in &c.policy.folders {
            let Some(p) = nerve_policy::protected::expand(home, &f.path) else {
                continue;
            };
            // One that does not resolve (gone, or closed to the owner) is
            // compared as it is named.
            let p = std::fs::canonicalize(&p).unwrap_or(p);
            let p = if within(&real, &p) || within(home, &p) {
                home.to_path_buf()
            } else if let Ok(inside) = p.strip_prefix(&real).or_else(|_| p.strip_prefix(home)) {
                home.join(inside)
            } else {
                continue;
            };
            if !out.contains(&p) {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// Tests that run on every platform; the module below is Unix only.
#[cfg(test)]
mod every_platform {
    use super::*;

    /// The installed node names the account each pairing's commands run as
    /// without a lookup: on Windows always the owner (`machine.user`), whose
    /// commands run in an AppContainer, never `nerve-run`, which does not
    /// exist there; elsewhere `nerve-run` unless the pairing runs as the
    /// owner. Runs on every platform, so each half is checked where it holds.
    #[tokio::test]
    async fn the_installed_node_names_the_command_account_of_each_pairing() {
        use nerve_policy::config::{CenterPolicy, Mode};
        let d = tempfile::tempdir().unwrap();
        let mut o = NodeOptions::new(NodePaths::new(
            d.path().join("config"),
            d.path().join("state"),
        ));
        o.home = d.path().to_path_buf();
        o.ctl = false;
        o.log = Some(Log::new(Level::Info));
        o.full_rights = Some(false);
        o.service = Some(true);
        o.owner = Some("alice".into());
        let daemon = Daemon::start(o).await.unwrap();
        let s = daemon.shared.clone();
        let mut cfg = s.config();
        cfg.machine.user = Some("alice".into());
        let named = |mode: Mode, as_owner: bool| {
            s.account_name(
                &cfg,
                &CenterPolicy {
                    mode,
                    as_owner,
                    ..Default::default()
                },
            )
        };
        let run = if cfg!(windows) {
            "alice"
        } else {
            crate::account::RUN_USER
        };
        for (mode, as_owner, want) in [
            (Mode::Folder, false, run),
            (Mode::Allowlist, false, run),
            (Mode::Allowlist, true, "alice"),
            (Mode::User, false, "alice"),
        ] {
            assert_eq!(
                named(mode, as_owner).as_deref(),
                Some(want),
                "{mode:?} as owner {as_owner}"
            );
        }
        daemon.stop().await;
    }

    /// The reach tells the sudo list only while the node's sudo switch is
    /// on: set in the config and a checked password held. Off by default,
    /// a listed command is refused, so the block does not say it runs.
    #[tokio::test]
    async fn the_reach_tells_the_sudo_list_only_while_the_switch_is_on() {
        use nerve_policy::config::{CenterPolicy, Mode, Sudo};
        let d = tempfile::tempdir().unwrap();
        let mut o = NodeOptions::new(NodePaths::new(
            d.path().join("config"),
            d.path().join("state"),
        ));
        o.home = d.path().to_path_buf();
        o.ctl = false;
        o.log = Some(Log::new(Level::Info));
        // Not elevated, also where the test runs elevated (a Windows CI).
        o.full_rights = Some(false);
        o.owner = Some("alice".into());
        let daemon = Daemon::start(o).await.unwrap();
        let s = daemon.shared.clone();
        let entry = nerve_policy::CenterEntry {
            name: "c".into(),
            url: "https://center.example".into(),
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
            policy: CenterPolicy {
                mode: Mode::Folder,
                sudo_allow: vec!["sudo apt *".into()],
                ..Default::default()
            },
        };
        let told = || {
            let r = s.reach(&s.config(), &entry);
            crate::descriptor::for_center(&s.config(), &entry, &r, &[])
        };
        let off = told();
        assert!(!off.access.as_ref().unwrap().sudo);
        lock(&s.store)
            .set_sudo(nerve_policy::Writer::Local, Sudo::On)
            .unwrap();
        // Set in the config, but no password held (a restarted node).
        assert!(!told().access.unwrap().sudo);
        *lock(&s.sudo) = Some(crate::sudo::Secret::new("pw".into()));
        *lock(&s.sudo_for) = s.owner_name(&s.config());
        let on = told();
        assert!(on.access.as_ref().unwrap().sudo);
        assert_ne!(on.rev, off.rev);
        daemon.stop().await;
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// With the keys in the keyring, folder mode runs commands only where they
    /// cannot reach the session bus it answers on: Landlock ABI 9, or an
    /// account other than root and the node's own.
    #[test]
    fn folder_commands_with_the_keyring_need_the_bus_out_of_reach() {
        let account = |uid| crate::service::Account {
            name: "a".into(),
            uid,
            gid: uid,
            comment: String::new(),
            home: "/home/a".into(),
            groups: vec![uid],
        };
        let (other, root) = (account(4242), account(0));
        use SecretStorage::{File, Keyring};
        let kept = |storage, a: Option<&crate::service::Account>| {
            keys_kept_from_commands(storage, || a.cloned())
        };
        assert!(kept(File, None));
        assert!(kept(File, Some(&root)));
        assert!(!kept(Keyring, None));
        assert!(!kept(Keyring, Some(&root)));
        assert!(kept(Keyring, Some(&other)));
    }

    /// A confined command reaches the session bus for good unless it runs
    /// as another account than root.
    #[test]
    fn a_confined_command_of_the_nodes_own_user_reaches_the_bus() {
        let account = |uid| crate::service::Account {
            name: "a".into(),
            uid,
            gid: uid,
            comment: String::new(),
            home: "/home/a".into(),
            groups: vec![uid],
        };
        let open = nerve_sandbox::LandlockSpec::default();
        assert!(reaches_bus(Some(&open), || None));
        assert!(reaches_bus(Some(&open), || Some(account(0))));
        assert!(!reaches_bus(Some(&open), || Some(account(4242))));
        let asked = std::cell::Cell::new(false);
        let ask = || {
            asked.set(true);
            None
        };
        // Without Landlock (user and sudo commands) the move changes nothing
        // a command reaches.
        assert!(!reaches_bus(None, ask));
        assert!(!asked.get());
    }

    /// The keys do not move into the keyring while a folder mode command that
    /// started with them in files runs, and a command whose config was taken
    /// before a move does not start after it.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_keys_do_not_move_past_a_command_that_reaches_the_bus() {
        use nerve_transport::ctl::Reply;
        let log = Log::new(Level::Info);
        let d = tempfile::tempdir().unwrap();
        let daemon = Daemon::start(options(&d, &log)).await.unwrap();
        let s = daemon.shared.clone();
        let paths = daemon.paths().clone();
        let write = |to| {
            let Reply::Ok(v) = control(&s, "config.read", json!({}), None) else {
                panic!("config.read failed")
            };
            let mut cfg = NodeConfig::parse(v["config"].as_str().unwrap()).unwrap();
            cfg.machine.secret_storage = to;
            let params = json!({"config": cfg.to_toml(), "if_version": v["version"]});
            control(&s, "config.write", params, None)
        };
        let storage = || s.config().machine.secret_storage;
        let one = s.open_to_bus().unwrap();
        let two = s.open_to_bus().unwrap();
        let Reply::Err(e) = write(SecretStorage::Keyring) else {
            panic!("the keys moved past two commands")
        };
        assert!(e.contains("2 folder mode commands run"), "{e}");
        assert!(e.contains("nothing was changed"), "{e}");
        drop(two);
        let Reply::Err(e) = write(SecretStorage::Keyring) else {
            panic!("the keys moved past a command")
        };
        assert!(e.contains("1 folder mode command runs"), "{e}");
        assert_eq!(storage(), SecretStorage::File);
        assert!(paths.config_key().exists());
        assert!(!paths.keys_moving().exists());
        drop(one);
        assert!(matches!(write(SecretStorage::Keyring), Reply::Ok(_)));
        assert_eq!(storage(), SecretStorage::Keyring);
        // A call decided on the config from before the move.
        assert_eq!(s.open_to_bus().err(), Some(KEYS_MOVED));
        assert_eq!(s.open_to_bus.load(Ordering::SeqCst), 0);
        // Out of the keyring nothing waits for a command.
        s.open_to_bus.fetch_add(1, Ordering::SeqCst);
        assert!(matches!(write(SecretStorage::File), Reply::Ok(_)));
        assert_eq!(storage(), SecretStorage::File);
        s.open_to_bus.fetch_sub(1, Ordering::SeqCst);
        daemon.stop().await;
    }

    /// The account is looked up only where the answer depends on it: with the
    /// keys in files a link's 5 s tick starts no program.
    #[test]
    fn the_account_is_asked_only_where_it_decides() {
        use SecretStorage::{File, Keyring};
        let asked = std::cell::Cell::new(0);
        let ask = || {
            asked.set(asked.get() + 1);
            None
        };
        assert!(keys_kept_from_commands(File, ask));
        assert_eq!(asked.get(), 0);
        assert!(!keys_kept_from_commands(Keyring, ask));
        assert_eq!(asked.get(), 1);
    }

    /// The keyring's places are the node's own only while its keys are there.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_keyring_folder_is_the_nodes_own_with_the_keyring() {
        let (d, daemon) = daemon().await;
        let mut cfg = daemon.config();
        let keyrings = d.path().join(".local/share/keyrings");
        assert_eq!(daemon.shared.own(&cfg), daemon.paths().own());
        cfg.machine.secret_storage = SecretStorage::Keyring;
        let own = daemon.shared.own(&cfg);
        assert!(own.contains(&keyrings), "{own:?}");
        let bus = PathBuf::from(format!("/run/user/{}", nerve_transport::net::euid()));
        assert!(own.contains(&bus), "{own:?}");
        // A center reaches neither the plain-text keyring through the fs
        // capability nor the folder from a command, even with the whole
        // home in its folders.
        std::fs::create_dir_all(&keyrings).unwrap();
        std::fs::write(keyrings.join("login.keyring"), "[keyring]\n").unwrap();
        let home = std::fs::canonicalize(d.path()).unwrap();
        let p = nerve_policy::protected::Protected::new(
            &nerve_policy::protected::Platform::Unix,
            &home,
            &own,
            &Default::default(),
        );
        assert!(
            p.own(&home.join(".local/share/keyrings/login.keyring"))
                .is_some()
        );
        let policy = nerve_policy::CenterPolicy {
            folders: vec![nerve_policy::config::Folder {
                path: home.display().to_string(),
                access: nerve_policy::config::Access::ALL,
            }],
            ..Default::default()
        };
        let spec = crate::exec::landlock_spec(&policy, &home, &own, &[]);
        let keyrings = std::fs::canonicalize(&keyrings).unwrap();
        for set in [&spec.read, &spec.write, &spec.exec] {
            assert!(!set.iter().any(|r| keyrings.starts_with(r)), "{set:?}");
        }
        daemon.stop().await;
    }

    async fn daemon() -> (tempfile::TempDir, Daemon) {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("config"), d.path().join("state"));
        let mut opts = NodeOptions::new(paths);
        opts.home = d.path().to_path_buf();
        (d, Daemon::start(opts).await.unwrap())
    }

    /// A node.toml that keeps the keys in the keyring, made before.
    fn keys_in_the_keyring(paths: &NodePaths) {
        let mut store = SettingsStore::open_with(
            paths.config_file(),
            Box::new(crate::secrets::NodeSecrets::new(paths)),
            AuditLog::new(paths.audit_log()),
        )
        .unwrap();
        store
            .update(|c| {
                c.machine.secret_storage = SecretStorage::Keyring;
                Ok(())
            })
            .unwrap();
    }

    /// The installed node on Windows does not start with its keys in the
    /// keyring: they are in the Credential Manager of whoever moved them
    /// there, and the message says how to get them back into files.
    #[tokio::test]
    async fn the_installed_node_on_windows_refuses_keys_in_the_keyring() {
        let d = tempfile::tempdir().unwrap();
        let log = Log::new(Level::Info);
        let opts = options(&d, &log);
        let paths = opts.paths.clone();
        keys_in_the_keyring(&paths);
        crate::secrets::for_tests::pretend_windows_service(&paths);
        let Err(e) = Daemon::start(opts).await else {
            panic!("the node started");
        };
        assert!(e.contains("the node does not start"), "{e}");
        assert!(e.contains("Credential Manager"), "{e}");
        assert!(e.contains("config set machine.secret_storage file`"), "{e}");
        assert!(e.contains("Restart-Service nerve-node"), "{e}");
    }

    fn options(d: &tempfile::TempDir, log: &Arc<Log>) -> NodeOptions {
        let paths = NodePaths::new(d.path().join("config"), d.path().join("state"));
        let mut opts = NodeOptions::new(paths);
        opts.home = d.path().to_path_buf();
        opts.ctl = false;
        opts.log = Some(log.clone());
        opts
    }

    fn warnings(log: &Log) -> Vec<String> {
        let q = nerve_transport::log::Query {
            limit: usize::MAX,
            ..Default::default()
        };
        log.entries(&q)
            .into_iter()
            .filter(|(_, e)| e.level == Level::Warn)
            .map(|(_, e)| e.msg)
            .collect()
    }

    /// A node with full rights (root, or an elevated token) is refused
    /// without `machine.allow_root`, and warned about in the log with it.
    #[tokio::test]
    async fn full_rights_are_refused_without_allow_root_and_warned_about_with_it() {
        use tracing_subscriber::layer::SubscriberExt;
        let log = Log::new(Level::Info);
        let sub = tracing_subscriber::Registry::default().with(log.layer());
        let _guard = tracing::subscriber::set_default(sub);
        let d = tempfile::tempdir().unwrap();

        let err = Daemon::start_with(options(&d, &log), true).await.err();
        assert_eq!(err.as_deref(), Some(crate::rights::REFUSED));
        assert!(warnings(&log).is_empty());

        let paths = NodePaths::new(d.path().join("config"), d.path().join("state"));
        for dir in [&paths.state_dir, &paths.config_dir] {
            nerve_transport::files::create_private_dir(dir).unwrap();
        }
        let mut store = SettingsStore::open(
            paths.config_file(),
            paths.config_key(),
            AuditLog::new(paths.audit_log()),
        )
        .unwrap();
        store
            .update(|c| {
                c.machine.allow_root = true;
                Ok(())
            })
            .unwrap();
        let daemon = Daemon::start_with(options(&d, &log), true).await.unwrap();
        let w = warnings(&log);
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("full rights") && w[0].contains("You are responsible"));
        // The warning also reaches the node's log file.
        let file = std::fs::read_to_string(paths.log_file()).unwrap();
        assert!(file.contains("You are responsible"), "{file}");
        daemon.stop().await;

        // A node without full rights is not asked anything.
        let log = Log::new(Level::Info);
        let d = tempfile::tempdir().unwrap();
        let daemon = Daemon::start_with(options(&d, &log), false).await.unwrap();
        assert!(warnings(&log).is_empty());
        daemon.stop().await;
    }

    /// `Daemon::start` takes the rights from the options when a test sets
    /// them, whoever runs the test.
    #[tokio::test]
    async fn start_takes_the_rights_from_the_options() {
        let log = Log::new(Level::Info);
        let d = tempfile::tempdir().unwrap();
        let mut o = options(&d, &log);
        o.full_rights = Some(true);
        let err = Daemon::start(o).await.err();
        assert_eq!(err.as_deref(), Some(crate::rights::REFUSED));
        let mut o = options(&d, &log);
        o.full_rights = Some(false);
        Daemon::start(o).await.unwrap().stop().await;
    }

    /// With the keys moved into the keyring where Landlock cannot keep a
    /// command off the session bus, the running node says that folder mode runs
    /// no command: in its log once, and in its status.
    #[tokio::test]
    async fn the_keyring_turning_folder_commands_off_is_told() {
        use nerve_transport::ctl::Reply;
        use tracing_subscriber::layer::SubscriberExt;
        let log = Log::new(Level::Info);
        let sub = tracing_subscriber::Registry::default().with(log.layer());
        let _guard = tracing::subscriber::set_default(sub);
        let d = tempfile::tempdir().unwrap();
        let mut o = options(&d, &log);
        o.full_rights = Some(false);
        o.exe = Some("/bin/true".into());
        o.confinement = Some(Confinement {
            landlock_abi: Some(6),
            appcontainer: false,
        });
        let daemon = Daemon::start(o).await.unwrap();
        let s = daemon.shared.clone();
        let write = |f: &dyn Fn(&mut NodeConfig)| {
            let Reply::Ok(v) = control(&s, "config.read", json!({}), None) else {
                panic!("config.read failed")
            };
            let mut cfg = NodeConfig::parse(v["config"].as_str().unwrap()).unwrap();
            f(&mut cfg);
            let params = json!({"config": cfg.to_toml(), "if_version": v["version"]});
            let r = control(&s, "config.write", params, None);
            assert!(matches!(r, Reply::Ok(_)));
        };
        let told = || {
            warnings(&log)
                .iter()
                .filter(|w| w.contains(KEYRING_NOT_CONFINED))
                .count()
        };
        let storage = |to| move |c: &mut NodeConfig| c.machine.secret_storage = to;
        assert_eq!(daemon.status()["folder_commands_off"], Value::Null);
        write(&storage(SecretStorage::Keyring));
        assert_eq!(daemon.status()["folder_commands_off"], KEYRING_NOT_CONFINED);
        assert_eq!(told(), 1);
        // Told once, not at every change after.
        write(&|c| c.node.name = Some("lab-pc".into()));
        assert_eq!(told(), 1);
        write(&storage(SecretStorage::File));
        assert_eq!(daemon.status()["folder_commands_off"], Value::Null);
        write(&storage(SecretStorage::Keyring));
        assert_eq!(told(), 2);
        daemon.stop().await;
    }

    /// The status says whether the owner is root, as whom what runs as
    /// the owner then runs (#151); `false` for any other owner and none.
    #[tokio::test]
    async fn the_status_says_when_root_is_the_owner() {
        for (owner, root) in [
            (Some("root"), !cfg!(windows)),
            (Some("alice"), false),
            (None, false),
        ] {
            let log = Log::new(Level::Info);
            let d = tempfile::tempdir().unwrap();
            let mut o = options(&d, &log);
            o.full_rights = Some(false);
            o.owner = owner.map(String::from);
            let daemon = Daemon::start(o).await.unwrap();
            let st = daemon.status();
            assert_eq!(st["owner_is_root"], root, "{owner:?}: {st}");
            daemon.stop().await;
        }
    }

    /// What each pairing's descriptor tells of the account and the folders,
    /// as the link builds it: on the installed Linux node a folder pairing
    /// runs as `nerve-run`, whose home, `/tmp` and `/var/tmp` it names as
    /// that account's own; an allowlist pairing as `nerve-run` names the
    /// account and no folder; a user pairing and an allowlist pairing as
    /// the owner run as the owner, with no built-in folder. A node run by
    /// hand runs everything as its own user, with no built-in folder.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn each_pairing_is_told_its_account_and_the_accounts_own_folders() {
        use nerve_policy::config::{CenterPolicy, Folder, Mode};
        for service in [true, false] {
            let log = Log::new(Level::Info);
            let d = tempfile::tempdir().unwrap();
            let mut o = options(&d, &log);
            o.full_rights = Some(false);
            o.exe = Some("/bin/true".into());
            o.service = Some(service);
            o.owner = Some("alice".into());
            let daemon = Daemon::start(o).await.unwrap();
            let s = daemon.shared.clone();
            let run_home = d.path().join("nerve-run");
            // nerve-run and the owner as the account database has them.
            for (name, uid, home) in [
                (crate::account::RUN_USER, 4243, run_home.clone()),
                ("alice", 4242, d.path().join("alice")),
            ] {
                lock(&s.account_cache).insert(
                    name.into(),
                    (
                        std::time::Instant::now(),
                        Some(crate::service::Account {
                            name: name.into(),
                            uid,
                            gid: uid,
                            comment: String::new(),
                            home,
                            groups: vec![uid],
                        }),
                    ),
                );
            }
            let cfg = s.config();
            let told = |mode: Mode, as_owner: bool| {
                let entry = nerve_policy::CenterEntry {
                    name: "c".into(),
                    url: "https://center.example".into(),
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
                    policy: CenterPolicy {
                        mode,
                        as_owner,
                        folders: vec![Folder {
                            path: "/srv/proj".into(),
                            access: nerve_policy::config::Access::parse("rw").unwrap(),
                        }],
                        ..Default::default()
                    },
                };
                let r = s.reach(&cfg, &entry);
                let a = crate::descriptor::for_center(&cfg, &entry, &r, &[])
                    .access
                    .unwrap();
                let folders: Vec<String> = a
                    .folders
                    .iter()
                    .map(|f| format!("{} {}{}", f.path, f.access, if f.own { " own" } else { "" }))
                    .collect();
                (a.account, folders)
            };
            let what = format!("service {service}");
            let me = crate::account::own_name();
            let proj = "/srv/proj rw".to_string();
            if service {
                assert_eq!(
                    told(Mode::Folder, false),
                    (
                        Some(crate::account::RUN_USER.to_string()),
                        vec![
                            proj.clone(),
                            "/tmp rwx own".into(),
                            "/var/tmp rwx own".into(),
                            format!("{} rwx own", run_home.display()),
                        ]
                    ),
                    "{what}"
                );
                assert_eq!(
                    told(Mode::Allowlist, false),
                    (Some(crate::account::RUN_USER.to_string()), vec![]),
                    "{what}"
                );
                for (mode, as_owner) in [(Mode::User, false), (Mode::Allowlist, true)] {
                    assert_eq!(
                        told(mode, as_owner),
                        (Some("alice".to_string()), vec![]),
                        "{what}: {mode:?}"
                    );
                }
            } else {
                assert_eq!(
                    told(Mode::Folder, false),
                    (me.clone(), vec![proj]),
                    "{what}"
                );
                assert_eq!(told(Mode::User, false), (me, vec![]), "{what}");
            }
            daemon.stop().await;
        }
    }

    /// The installed node without Landlock holds folder-mode commands back
    /// by their account alone, so the reach it tells a center says so (and
    /// the block does not call them confined); with Landlock it does not.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_reach_says_where_only_the_account_holds_commands() {
        use nerve_policy::config::{CenterPolicy, Mode};
        for (landlock, held) in [(Some(6), false), (None, true)] {
            let log = Log::new(Level::Info);
            let d = tempfile::tempdir().unwrap();
            let mut o = options(&d, &log);
            o.full_rights = Some(false);
            o.exe = Some("/bin/true".into());
            o.service = Some(true);
            o.owner = Some("alice".into());
            o.confinement = Some(Confinement {
                landlock_abi: landlock,
                appcontainer: false,
            });
            let daemon = Daemon::start(o).await.unwrap();
            let s = daemon.shared.clone();
            let entry = nerve_policy::CenterEntry {
                name: "c".into(),
                url: "https://center.example".into(),
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
                policy: CenterPolicy {
                    mode: Mode::Folder,
                    ..Default::default()
                },
            };
            let r = s.reach(&s.config(), &entry);
            assert_eq!(r.held_by_account, held, "landlock {landlock:?}");
            daemon.stop().await;
        }
    }

    /// The status says of each pairing whether Landlock holds its commands,
    /// and on the installed Linux node without Landlock what nerve-run may
    /// read of the owner's home beyond its folders: with the home open to
    /// others, or a folder given in it. Nothing of the home with Landlock,
    /// nor on a node run by hand (#142).
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_status_tells_landlock_and_what_the_home_leaves_open() {
        use nerve_policy::config::{CenterPolicy, Folder, Mode};
        use std::os::unix::fs::PermissionsExt;
        for (service, landlock) in [(true, false), (true, true), (false, false)] {
            let log = Log::new(Level::Info);
            let d = tempfile::tempdir().unwrap();
            let home = std::fs::canonicalize(d.path()).unwrap().join("alice");
            std::fs::create_dir_all(home.join("proj")).unwrap();
            let chmod =
                |m| std::fs::set_permissions(&home, std::fs::Permissions::from_mode(m)).unwrap();
            chmod(0o750);
            let mut o = options(&d, &log);
            o.full_rights = Some(false);
            o.exe = Some("/bin/true".into());
            o.service = Some(service);
            o.owner = Some("alice".into());
            o.confinement = Some(Confinement {
                landlock_abi: landlock.then_some(6),
                appcontainer: false,
            });
            let daemon = Daemon::start(o).await.unwrap();
            let s = daemon.shared.clone();
            // The owner as the account database has her.
            lock(&s.account_cache).insert(
                "alice".into(),
                (
                    std::time::Instant::now(),
                    Some(crate::service::Account {
                        name: "alice".into(),
                        uid: 4242,
                        gid: 4242,
                        comment: String::new(),
                        home: home.clone(),
                        groups: vec![4242],
                    }),
                ),
            );
            // The folders of the folder pairing, then of the user pairing.
            let pairings_each = |f: Vec<Folder>, u: Vec<Folder>| {
                let mut cfg = s.config();
                cfg.centers = [("f", Mode::Folder, f), ("u", Mode::User, u)]
                    .into_iter()
                    .map(|(name, mode, folders)| nerve_policy::CenterEntry {
                        name: name.into(),
                        url: "https://center.example".into(),
                        pin: None,
                        center_id: "c".into(),
                        node_id: name.into(),
                        settings: Default::default(),
                        paused: false,
                        revoked: false,
                        unknown: false,
                        public_key: None,
                        key_rotations: 0,
                        pin_rotations: 0,
                        old_pin: None,
                        policy: CenterPolicy {
                            mode,
                            folders,
                            ..Default::default()
                        },
                    })
                    .collect();
                let r = control(
                    &s,
                    "config.write",
                    json!({"config": cfg.to_toml(), "if_version": cfg.version}),
                    None,
                );
                assert!(matches!(r, nerve_transport::ctl::Reply::Ok(_)));
            };
            let pairings = |folders: Vec<Folder>| pairings_each(folders.clone(), folders);
            let folder = |p: &std::path::Path, access: &str| Folder {
                path: p.display().to_string(),
                access: nerve_policy::config::Access::parse(access).unwrap(),
            };
            pairings(Vec::new());
            let st = daemon.status();
            let what = format!("service {service}, landlock {landlock}");
            assert_eq!(st["centers"][0]["landlock"], landlock, "{what}");
            assert_eq!(st["centers"][1]["landlock"], false, "{what}: user mode");
            // Closed, and no folder in it: nothing to say.
            assert_eq!(st["home_warning"], Value::Null, "{what}");
            chmod(0o755);
            let st = daemon.status();
            let told = service && !landlock;
            assert_eq!(st["home_warning"]["mode"] == "755", told, "{what}: {st}");
            chmod(0o750);
            pairings(vec![Folder {
                path: home.join("proj").display().to_string(),
                access: nerve_policy::config::Access::parse("rw").unwrap(),
            }]);
            let st = daemon.status();
            assert_eq!(
                st["home_warning"]["below"] == json!([home.join("proj")]),
                told,
                "{what}: {st}"
            );
            if told {
                assert_eq!(st["home_warning"]["mode"], Value::Null);
                let w = st["home_warning"]["warning"].as_str().unwrap();
                assert!(w.contains("passes through your home"), "{w}");
                assert!(w.contains("This warning stays while"), "{w}");
            }
            // The home given whole, which the sandbox splits around its
            // protected entries: told as the home, not as the folders it
            // was split into.
            std::fs::create_dir_all(home.join(".ssh")).unwrap();
            std::fs::create_dir_all(home.join("docs")).unwrap();
            pairings(vec![Folder {
                path: home.display().to_string(),
                access: nerve_policy::config::Access::parse("r").unwrap(),
            }]);
            let st = daemon.status();
            assert_eq!(
                st["home_warning"]["below"] == json!([home]),
                told,
                "{what}: {st}"
            );
            if told {
                let w = st["home_warning"]["warning"].as_str().unwrap();
                assert!(w.contains("as you give it your home itself."), "{w}");
                assert!(!w.contains("more folders"), "{w}");
            }
            // A folder around the home gives the home whole too.
            let around = home.parent().unwrap();
            pairings_each(vec![folder(around, "r")], Vec::new());
            let st = daemon.status();
            assert_eq!(
                st["home_warning"]["below"] == json!([home]),
                told,
                "{what}: {st}"
            );
            // Only the pairings whose commands run as nerve-run count: a
            // folder in the home that only the user pairing has leaves
            // nothing to say of the closed home.
            let elsewhere = around.join("elsewhere");
            std::fs::create_dir_all(&elsewhere).unwrap();
            pairings_each(
                vec![folder(&elsewhere, "rw")],
                vec![folder(&home.join("proj"), "rw")],
            );
            let st = daemon.status();
            assert_eq!(st["home_warning"], Value::Null, "{what}: {st}");
            // A home whose path runs through a link: the folders resolve to
            // the real home, and are told under the home as named.
            let data = around.join("data");
            std::fs::create_dir_all(data.join("alice/proj")).unwrap();
            std::fs::set_permissions(data.join("alice"), std::fs::Permissions::from_mode(0o750))
                .unwrap();
            std::os::unix::fs::symlink(&data, around.join("linked")).unwrap();
            let linked = around.join("linked/alice");
            lock(&s.account_cache).insert(
                "alice".into(),
                (
                    std::time::Instant::now(),
                    Some(crate::service::Account {
                        name: "alice".into(),
                        uid: 4242,
                        gid: 4242,
                        comment: String::new(),
                        home: linked.clone(),
                        groups: vec![4242],
                    }),
                ),
            );
            pairings(vec![folder(&linked.join("proj"), "rw")]);
            let st = daemon.status();
            assert_eq!(
                st["home_warning"]["below"] == json!([linked.join("proj")]),
                told,
                "{what}: {st}"
            );
            if told {
                assert_eq!(st["home_warning"]["home"], json!(linked), "{st}");
            }
            // A folder around the real home, given by a name that is not
            // around the home as named (`linked` resolves to `data`), is
            // the home too.
            pairings(vec![folder(&around.join("linked"), "r")]);
            let st = daemon.status();
            assert_eq!(
                st["home_warning"]["below"] == json!([linked]),
                told,
                "{what}: {st}"
            );
            daemon.stop().await;
        }
    }

    /// A job of a command, as the pipe asks it: the processes it holds.
    struct FakeJob(Vec<u32>);

    impl crate::job::Members for FakeJob {
        fn pids(&self) -> std::io::Result<Vec<u32>> {
            Ok(self.0.clone())
        }
    }

    /// Windows' control pipe, with a stream for the pipe and a fake job for
    /// the commands: a folder change reaches the running node, which makes
    /// it, saves it and answers; a caller in a command's job is refused
    /// whatever it asks, and the pipe serves no other change.
    #[tokio::test]
    async fn the_pipe_takes_folder_changes_and_refuses_commands() {
        use crate::folder_change::FolderChange;
        use nerve_policy::config::Access;
        use nerve_transport::ctl::{CtlRequest, call_on, serve_stream};
        let (d, daemon) = daemon().await;
        let s = daemon.shared.clone();
        lock(&s.store)
            .update(|c| {
                c.centers.push(nerve_policy::CenterEntry {
                    name: "home".into(),
                    url: "http://127.0.0.1:1".into(),
                    pin: None,
                    center_id: "id-home".into(),
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
                });
                Ok(())
            })
            .unwrap();
        let folder = d.path().join("work").display().to_string();
        // One connection of a caller with `pid`, served as crate::pipe
        // serves it, while a command runs whose job holds the process 4242.
        let call = |pid: u32, method: &'static str, params: Value| {
            let (client, server) = tokio::io::duplex(64 * 1024);
            let (s, job) = (s.clone(), Arc::new(FakeJob(vec![4242])));
            tokio::spawn(serve_stream(
                server,
                Some(pid),
                Arc::new(move |req: CtlRequest, pid: Option<u32>| {
                    let (s, job) = (s.clone(), job.clone());
                    async move {
                        let from_command = crate::job::from_a_command(pid, [Some(&*job)]);
                        pipe_control(&s, &req.method, req.params, from_command).await
                    }
                }),
            ));
            call_on(client, method, params)
        };
        let add = FolderChange::Add {
            path: folder.clone(),
            access: Access::parse("rx").unwrap(),
            recorded: true,
        };
        let before = s.config().version;
        let ticks = *s.changed.borrow();
        // From the command's job: refused, the status too, and nothing
        // changed.
        for (method, params) in [
            (add.method(), add.params(None)),
            ("status", json!({})),
            ("caps.list", json!({})),
        ] {
            let e = call(4242, method, params).await.unwrap_err();
            assert_eq!(e, FROM_A_COMMAND);
        }
        assert_eq!(s.config().version, before);
        // From the owner's CLI: made, saved and answered.
        let v = call(1000, add.method(), add.params(Some("home")))
            .await
            .unwrap();
        assert_eq!(v["center"], "home");
        assert_eq!(v["path"], folder);
        assert_eq!(v["access"], "rx");
        assert_eq!(v["mode"], "allowlist");
        assert_eq!(v["version"], before + 1);
        let folders = || {
            daemon
                .config()
                .center("home")
                .unwrap()
                .policy
                .folders
                .clone()
        };
        assert_eq!(folders().len(), 1);
        assert_eq!(folders()[0].access.to_chmod(), "r-x");
        // The place the CLI settled the folder at is recorded with it.
        let places = || {
            daemon
                .config()
                .center("home")
                .unwrap()
                .policy
                .places
                .clone()
        };
        assert_eq!(places(), std::slice::from_ref(&folder));
        assert!(*s.changed.borrow() > ticks, "the links were not told");
        let paths = daemon.paths();
        let saved = SettingsStore::peek(&paths.config_file(), &paths.config_key()).unwrap();
        assert_eq!(saved.center("home").unwrap().policy.folders, folders());
        let set = FolderChange::Set {
            path: folder.clone(),
            given: folder.clone(),
            changes: vec!["-x".into(), "+w".into()],
        };
        let v = call(1000, set.method(), set.params(None)).await.unwrap();
        assert_eq!(v["access"], "rw");
        assert_eq!(folders()[0].access.to_chmod(), "rw-");
        assert_eq!(places(), std::slice::from_ref(&folder));
        // The same checks as the CLI's: a folder the center does not have,
        // a right that is none, a path that is not absolute, and no other
        // change than a folder's.
        let rm_other = FolderChange::Rm {
            path: "/elsewhere".into(),
            given: "/elsewhere".into(),
        };
        let e = call(1000, rm_other.method(), rm_other.params(None))
            .await
            .unwrap_err();
        assert_eq!(e, "/elsewhere is not a folder of this center");
        let e = call(1000, "folder.add", json!({"path": folder, "access": ""}))
            .await
            .unwrap_err();
        assert!(e.contains("grants some right"), "{e}");
        let e = call(1000, "folder.add", json!({"path": "work", "access": "r"}))
            .await
            .unwrap_err();
        assert!(e.contains("not absolute"), "{e}");
        let e = call(1000, "config.write", json!({"config": ""}))
            .await
            .unwrap_err();
        assert_eq!(e, "unknown method config.write");
        assert_eq!(folders()[0].access.to_chmod(), "rw-");
        let rm = FolderChange::Rm {
            path: folder.clone(),
            given: folder.clone(),
        };
        let v = call(1000, rm.method(), rm.params(None)).await.unwrap();
        assert_eq!(v["access"], Value::Null);
        assert!(folders().is_empty());
        assert!(places().is_empty());
        assert!(call(1000, "status", json!({})).await.is_ok());
        daemon.stop().await;
    }

    /// On Windows the CLI writes every change but the folders' to node.toml
    /// for the next start. A folder change over the pipe after that is
    /// refused: the node would save its own config over the file and lose
    /// the CLI's change.
    #[tokio::test]
    async fn a_pipe_change_does_not_undo_a_change_waiting_in_the_file() {
        use crate::folder_change::FolderChange;
        use nerve_policy::config::Access;
        use nerve_transport::ctl::Reply;
        let (d, daemon) = daemon().await;
        let s = daemon.shared.clone();
        let paths = daemon.paths().clone();
        lock(&s.store)
            .update(|c| {
                c.centers.push(nerve_policy::CenterEntry {
                    name: "home".into(),
                    url: "http://127.0.0.1:1".into(),
                    pin: None,
                    center_id: "id-home".into(),
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
                });
                Ok(())
            })
            .unwrap();
        // The CLI's way for a change no pipe takes (cli::edit).
        let mut cli = SettingsStore::open_with(
            paths.config_file(),
            Box::new(crate::secrets::NodeSecrets::for_cli(&paths)),
            AuditLog::new(paths.audit_log()),
        )
        .unwrap();
        cli.update(|c| {
            c.center_mut("home").unwrap().policy.mode = nerve_policy::Mode::Folder;
            Ok(())
        })
        .unwrap();
        let in_force = s.config().version;
        let add = FolderChange::Add {
            path: d.path().join("work").display().to_string(),
            access: Access::parse("r").unwrap(),
            recorded: false,
        };
        let r = pipe_control(&s, add.method(), add.params(None), false).await;
        let Reply::Err(e) = r else {
            panic!("the pipe took a change over the CLI's")
        };
        assert_eq!(e, file_ahead(in_force + 1, in_force));
        assert!(e.contains("Restart the node"), "{e}");
        let saved = || {
            SettingsStore::peek(&paths.config_file(), &paths.config_key())
                .unwrap()
                .center("home")
                .unwrap()
                .policy
                .clone()
        };
        assert_eq!(saved().mode, nerve_policy::Mode::Folder);
        assert!(saved().folders.is_empty());
        assert_eq!(s.config().version, in_force);
        // Once the node has the file's change (a restart; here a reload),
        // and after a write of the node's own, the pipe takes changes again.
        s.reload().unwrap();
        s.mark_center("home", |c| c.unknown = true);
        let r = pipe_control(&s, add.method(), add.params(None), false).await;
        assert!(matches!(r, Reply::Ok(_)), "refused");
        assert_eq!(saved().mode, nerve_policy::Mode::Folder);
        assert_eq!(saved().folders.len(), 1);
        daemon.stop().await;
    }

    /// A hello the node checks while it stops (for an owner's restore, too)
    /// is not held: the stop detached every provider already, and one held
    /// after would stay with the stopped node, its program never told.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_hello_checked_while_the_node_stops_is_not_held() {
        use nerve_transport::ctl::Reply;
        let (_d, daemon) = daemon().await;
        let s = daemon.shared.clone();
        let me = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        lock(&s.store)
            .update(|c| {
                c.providers
                    .allowed
                    .push(nerve_policy::config::AllowedProvider {
                        name: "desk".into(),
                        exe: me.to_string_lossy().into(),
                    });
                Ok(())
            })
            .unwrap();
        let hello = || {
            json!({"role": "provider", "name": "desk", "capabilities": [
                {"id": "echo", "actions": {"say": {"effect": "read"}}}]})
        };
        let caller = || crate::provider::Caller {
            uid: crate::account::own_uid(),
            pid: Some(std::process::id()),
            pidfd: None,
            refuse_commands: false,
        };
        s.stop.send_replace(true);
        let Reply::Err(e) = crate::provider::attach(&s, hello(), caller()).await else {
            panic!("held while the node stops");
        };
        assert!(e.contains("the node stops"), "{e}");
        assert_eq!(s.providers.held("desk"), None);
        // The same hello is held while the node runs.
        s.stop.send_replace(false);
        let r = crate::provider::attach(&s, hello(), caller()).await;
        assert!(matches!(r, Reply::Session { .. }), "not held");
        assert!(s.providers.held("desk").is_some());
        daemon.stop().await;
    }

    /// Windows' pipe answers `cap ls` as the socket does: the running node's
    /// listing.
    #[tokio::test]
    async fn the_pipe_lists_the_capabilities_of_the_running_node() {
        use nerve_transport::ctl::Reply;
        let (_d, daemon) = daemon().await;
        let r = pipe_control(&daemon.shared, "caps.list", json!({}), false).await;
        let Reply::Ok(v) = r else {
            panic!("not listed");
        };
        assert_eq!(v["running"], true, "{v}");
        assert!(v["capabilities"].as_array().is_some_and(|c| !c.is_empty()));
        daemon.stop().await;
    }

    /// `folder.add` judges, stores and records a folder in one step, for a CLI
    /// that may not look where the node does (the installed node's CLI runs
    /// as the node's own user, not as the account): a path through a link of
    /// the account is stored at the place it leads to, one through a link
    /// inside a `w` folder is refused and nothing changes, and a dangling link
    /// is refused as it always was.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_node_judges_stores_and_records_a_folder_it_is_asked_to_add() {
        use nerve_policy::config::{Access, Folder};
        use nerve_transport::ctl::Reply;
        let (d, daemon) = daemon().await;
        let s = daemon.shared.clone();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (work, other, wdir) = (root.join("work"), root.join("other"), root.join("wdir"));
        let (link2, dangling) = (root.join("link2"), root.join("dangling"));
        for dir in [&work, &other, &wdir] {
            std::fs::create_dir(dir).unwrap();
        }
        std::os::unix::fs::symlink(&other, &link2).unwrap();
        std::os::unix::fs::symlink(root.join("nowhere"), &dangling).unwrap();
        // A link a command could have put inside a folder it may write in.
        let bin = wdir.join("bin");
        std::os::unix::fs::symlink(&other, &bin).unwrap();
        lock(&s.store)
            .update(|c| {
                c.centers.push(nerve_policy::CenterEntry {
                    name: "home".into(),
                    url: "https://center.example".into(),
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
                    policy: nerve_policy::CenterPolicy {
                        folders: vec![Folder {
                            path: wdir.display().to_string(),
                            access: Access::parse("rw").unwrap(),
                        }],
                        ..Default::default()
                    },
                });
                Ok(())
            })
            .unwrap();
        let ask = |center: &str, p: &std::path::Path, access: &str, pid| {
            let params = json!({
                "center": center,
                "path": p.display().to_string(),
                "access": access,
            });
            control(&s, "folder.add", params, pid)
        };
        let add = |p: &std::path::Path, access: &str| {
            let Reply::Ok(v) = ask("home", p, access, None) else {
                panic!("folder.add of {} failed", p.display())
            };
            (
                v["stored"].as_str().unwrap().to_string(),
                v["recorded"].as_bool().unwrap(),
                v["mode"].as_str().unwrap().to_string(),
            )
        };
        let refused = |p: &std::path::Path| {
            let Reply::Err(e) = ask("home", p, "r", None) else {
                panic!("folder.add of {} was not refused", p.display())
            };
            e
        };
        let policy = || s.config().centers[0].policy.clone();
        let listed = |p: &std::path::Path| {
            policy()
                .folders
                .iter()
                .find(|f| std::path::Path::new(&f.path) == p)
                .map(|f| f.access.to_string())
        };
        // Its own place: stored where it is, recorded, with the center's mode.
        let (work_s, other_s) = (work.display().to_string(), other.display().to_string());
        assert_eq!(add(&work, "r"), (work_s.clone(), true, "allowlist".into()));
        assert_eq!(policy().places, std::slice::from_ref(&work_s));
        // Through a link of the account: stored at the place it leads to, with
        // the access it was given, and recorded there. Never stored as given.
        assert_eq!(
            add(&link2, "rw"),
            (other_s.clone(), true, "allowlist".into())
        );
        assert_eq!(listed(&link2), None);
        assert_eq!(listed(&other).as_deref(), Some("rw"));
        assert!(policy().is_placed(&other_s));
        // Again with other rights: one entry, one record.
        add(&other, "x");
        assert_eq!(listed(&other).as_deref(), Some("x"));
        assert_eq!(policy().places.len(), 2);
        // Refused, and nothing changes: a link inside a `w` folder (a command
        // may have put it there), and a dangling link.
        let before = policy();
        let why = refused(&bin);
        assert!(why.contains("link") && why.contains("may write"), "{why}");
        assert!(refused(&dangling).contains("dangling"));
        assert_eq!(policy(), before);
        // Only a center of the node, and only the owner asks.
        assert!(matches!(ask("lab", &work, "r", None), Reply::Err(e) if e.contains("no center")));
        let me = std::process::id();
        lock(&s.commands).insert(me, "home".into());
        assert!(
            matches!(ask("home", &work, "r", Some(me)), Reply::Err(e) if e.starts_with("refused"))
        );
        daemon.stop().await;
    }

    #[tokio::test]
    async fn refuses_settings_from_below_a_command() {
        let (_d, daemon) = daemon().await;
        let s = daemon.shared.clone();
        let me = std::process::id();
        let read = control(&s, "config.read", json!({}), Some(me));
        let nerve_transport::ctl::Reply::Ok(v) = read else {
            panic!("config.read failed")
        };
        let write = json!({"config": v["config"], "if_version": v["version"]});
        // This process stands in for a command the node started.
        lock(&s.commands).insert(me, "home".into());
        let r = control(&s, "config.write", write.clone(), Some(me));
        assert!(matches!(r, nerve_transport::ctl::Reply::Err(e) if e.starts_with("refused")));
        // What reads the config is refused as well: `status` and
        // `config.read` hand it over whole, `caps.list` the programs and
        // every center's switches.
        for method in ["status", "config.read", "sudo.status", "caps.list"] {
            let r = control(&s, method, json!({}), Some(me));
            assert!(
                matches!(&r, nerve_transport::ctl::Reply::Err(e) if e.starts_with("refused")),
                "{method} answered a command"
            );
        }
        // What install, setup, update and uninstall ask first.
        let r = control(&s, "owner.check", json!({}), Some(me));
        assert!(matches!(r, nerve_transport::ctl::Reply::Err(e) if e.starts_with("refused")));
        lock(&s.commands).clear();
        let r = control(&s, "status", json!({}), Some(me));
        assert!(matches!(r, nerve_transport::ctl::Reply::Ok(_)));
        let r = control(&s, "config.write", write, Some(me));
        assert!(matches!(r, nerve_transport::ctl::Reply::Ok(_)));
        let r = control(&s, "owner.check", json!({}), Some(me));
        assert!(matches!(r, nerve_transport::ctl::Reply::Ok(_)));
        daemon.stop().await;
    }

    /// A command of a center must not take the node's keys out under a
    /// passphrase of its own, nor put keys of its choosing in: `backup` and
    /// `restore` ask `owner.check` first.
    #[tokio::test]
    async fn backup_and_restore_are_refused_from_below_a_command() {
        use clap::Parser;
        let (d, daemon) = daemon().await;
        let s = daemon.shared.clone();
        let paths = daemon.paths().clone();
        let pass = d.path().join("pass");
        nerve_transport::files::write_private(&pass, b"correct horse battery\n").unwrap();
        let file = d.path().join("n.bak");
        let run = |args: Vec<String>| {
            let mut argv: Vec<String> = vec![
                "nerve-node".into(),
                "--config-dir".into(),
                paths.config_dir.display().to_string(),
                "--state-dir".into(),
                paths.state_dir.display().to_string(),
            ];
            argv.extend(args);
            async move {
                let cli = crate::cli::Cli::try_parse_from(argv).map_err(|e| e.to_string())?;
                crate::cli::execute(cli, &mut Vec::new()).await
            }
        };
        let (f, p) = (file.display().to_string(), pass.display().to_string());
        let backup = || {
            vec![
                "backup".into(),
                f.clone(),
                "--passphrase-file".into(),
                p.clone(),
            ]
        };
        let restore = || {
            vec![
                "restore".into(),
                f.clone(),
                "--passphrase-file".into(),
                p.clone(),
            ]
        };

        // This process stands in for a command the node started.
        lock(&s.commands).insert(std::process::id(), "home".into());
        for args in [backup(), restore()] {
            let e = run(args).await.unwrap_err();
            assert!(e.starts_with("refused"), "{e}");
        }
        assert!(!file.exists(), "a command got a backup out");

        // The owner's backup works while the node runs; its restore does not,
        // as a running node holds the keys.
        lock(&s.commands).clear();
        run(backup()).await.unwrap();
        assert!(file.exists());
        let e = run(restore()).await.unwrap_err();
        assert!(e.contains("runs on these folders"), "{e}");
        daemon.stop().await;
    }

    /// A command of a center must not wipe what it did from the owner's
    /// sight: `log clear` and `audit clear` ask `owner.check` first.
    #[tokio::test]
    async fn clearing_the_log_and_the_audit_is_refused_from_below_a_command() {
        use clap::Parser;
        let (_d, daemon) = daemon().await;
        let s = daemon.shared.clone();
        let paths = daemon.paths().clone();
        let run = |args: [&str; 2]| {
            let mut argv: Vec<String> = vec![
                "nerve-node".into(),
                "--config-dir".into(),
                paths.config_dir.display().to_string(),
                "--state-dir".into(),
                paths.state_dir.display().to_string(),
            ];
            argv.extend(args.map(String::from));
            async move {
                let cli = crate::cli::Cli::try_parse_from(argv).map_err(|e| e.to_string())?;
                crate::cli::execute(cli, &mut Vec::new()).await
            }
        };
        let log = AuditLog::new(paths.audit_log());
        log.settings("local", 1, &[]).unwrap();
        let audit = std::fs::read(paths.audit_log()).unwrap();
        let logged = b"{\"ts\":1,\"level\":\"info\",\"msg\":\"node started\"}\n";
        std::fs::write(paths.log_file(), logged).unwrap();
        // This process stands in for a command the node started.
        lock(&s.commands).insert(std::process::id(), "home".into());
        for args in [["log", "clear"], ["audit", "clear"]] {
            let e = run(args).await.unwrap_err();
            assert!(e.starts_with("refused"), "{args:?}: {e}");
        }
        assert_eq!(std::fs::read(paths.audit_log()).unwrap(), audit);
        assert!(!log.old_path().exists());
        assert_eq!(std::fs::read(paths.log_file()).unwrap(), logged);
        // The owner clears them while the node runs.
        lock(&s.commands).clear();
        run(["audit", "clear"]).await.unwrap();
        run(["log", "clear"]).await.unwrap();
        assert_eq!(std::fs::read(log.old_path()).unwrap(), audit);
        let read = log.read().unwrap();
        assert_eq!(read.len(), 1);
        assert_eq!(read[0]["event"], "cleared");
        let now = std::fs::read_to_string(paths.log_file()).unwrap();
        assert_eq!(now.lines().count(), 1, "{now}");
        assert!(now.contains("the log was cleared by"), "{now}");
        daemon.stop().await;
    }

    /// What `install`, `update` and `setup` run to wait for the node they
    /// restarted, with the token. A node that does not answer it makes
    /// `update` put the old program back.
    #[tokio::test]
    async fn the_installers_find_the_node_they_restarted() {
        use crate::service::System;
        let (_d, daemon) = daemon().await;
        let p = daemon.paths().clone();
        tokio::task::spawn_blocking(move || crate::service::Host.wait_running(&p))
            .await
            .unwrap()
            .unwrap();
        daemon.stop().await;
    }

    /// A process that is no longer below a command (it left the command's
    /// tree, or the command ended) is told from the owner's by the token
    /// in the state folder, which the owner's CLI reads and a sandboxed
    /// command cannot.
    #[tokio::test]
    async fn answers_only_requests_that_carry_the_token() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        let (_d, daemon) = daemon().await;
        let socket = daemon.paths().ctl_socket();
        let token_file = nerve_transport::ctl::token_file(&socket);
        let token = std::fs::read_to_string(&token_file).unwrap();
        assert!(token.len() >= 32, "{token}");
        // The same user's own file, as the socket is.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&token_file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        // The CLI's call reads the token and is answered ...
        let v = nerve_transport::ctl::call(&socket, "status", json!({}))
            .await
            .unwrap();
        assert_eq!(v["locked"], false);
        // ... a request without it, or with another, is refused for every
        // method, though it comes from the node's own user and below no
        // command.
        let ask = |method: &'static str, given: Option<&'static str>| {
            let socket = socket.clone();
            async move {
                let mut request = json!({"method": method, "params": {}});
                if let Some(t) = given {
                    request["token"] = t.into();
                }
                let stream = tokio::net::UnixStream::connect(&socket).await.unwrap();
                let (r, mut w) = stream.into_split();
                w.write_all(format!("{request}\n").as_bytes())
                    .await
                    .unwrap();
                let mut line = String::new();
                tokio::io::BufReader::new(r)
                    .read_line(&mut line)
                    .await
                    .unwrap();
                serde_json::from_str::<Value>(&line).unwrap()
            }
        };
        for given in [None, Some("wrong"), Some("short"), Some("")] {
            for method in [
                "status",
                "config.read",
                "config.write",
                "sudo.status",
                "owner.check",
            ] {
                let reply = ask(method, given).await;
                let error = reply["error"].as_str().unwrap_or_default();
                assert!(error.starts_with("refused"), "{method} {given:?}: {reply}");
            }
        }
        // A new start makes a new token, and a stop takes the file away.
        let mut opts = NodeOptions::new(daemon.paths().clone());
        opts.home = daemon.shared.home.clone();
        daemon.stop().await;
        assert!(!token_file.exists());
        let again = Daemon::start(opts).await.unwrap();
        assert_ne!(std::fs::read_to_string(&token_file).unwrap(), token);
        again.stop().await;
    }

    #[tokio::test]
    async fn second_daemon_is_refused_and_ctl_answers() {
        let (d, daemon) = daemon().await;
        let paths = daemon.paths().clone();
        let v = nerve_transport::ctl::call(&paths.ctl_socket(), "status", json!({}))
            .await
            .unwrap();
        assert_eq!(v["locked"], false);
        let mut opts = NodeOptions::new(paths.clone());
        opts.home = d.path().to_path_buf();
        assert!(Daemon::start(opts).await.is_err());
        daemon.stop().await;
        assert!(!paths.ctl_socket().exists());
    }
}

#[cfg(test)]
mod change_tests {
    use super::*;

    /// What the log says when `old` becomes `new`, as the settings store
    /// would report it.
    fn told(old: &str, new: &str) -> String {
        let json = |t: &str| {
            let mut v = serde_json::to_value(NodeConfig::parse(t).unwrap()).unwrap();
            v.as_object_mut().unwrap().remove("version");
            v
        };
        describe_change("local", 7, &diff(&json(old), &json(new)))
    }

    const CENTER: &str = r#"
[[center]]
name = "lab"
url = "https://lab.example:7443"
pin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
center_id = "c1"
node_id = "n1"
"#;

    #[test]
    fn a_change_to_the_settings_is_told_by_what_changed() {
        let with = |policy: &str| format!("{CENTER}[center.policy]\n{policy}\n");
        // A plain value, both ways round.
        assert_eq!(
            told(&with("mode = \"allowlist\""), &with("mode = \"folder\"")),
            "settings changed by local (version 7): center.lab.policy.mode: allowlist -> folder"
        );
        // A list says what it gained and lost; an empty list is not in the file.
        assert_eq!(
            told(&with(""), &with("allow = [\"fs.read:~/notes/*\"]")),
            "settings changed by local (version 7): center.lab.policy.allow +fs.read:~/notes/*"
        );
        assert_eq!(
            told(
                &with("allow = [\"a\", \"b\"]"),
                &with("allow = [\"b\", \"c\"]")
            ),
            "settings changed by local (version 7): center.lab.policy.allow +c -a"
        );
        assert_eq!(
            told(&with("deny = [\"x\"]"), &with("")),
            "settings changed by local (version 7): center.lab.policy.deny -x"
        );
        // Several at once, and a machine setting.
        assert_eq!(
            told(
                &format!("{CENTER}[machine]\nsudo = \"off\"\n"),
                &format!("[machine]\nsudo = \"on\"\n{CENTER}[center.policy]\nuntil = 5\n")
            ),
            "settings changed by local (version 7): center.lab.policy.until: unset -> 5; machine.sudo: off -> on"
        );
    }

    #[test]
    fn a_center_that_comes_or_goes_is_named_and_nothing_else_of_it() {
        assert_eq!(
            told("", CENTER),
            "settings changed by local (version 7): center lab was added"
        );
        assert_eq!(
            told(CENTER, ""),
            "settings changed by local (version 7): center lab was removed"
        );
        let text = told(CENTER, &CENTER.replace("c1", "c2").replace("AAAA", "BBBB"));
        // Its id and pin are told as changed, never shown.
        assert_eq!(
            text,
            "settings changed by local (version 7): center.lab.center_id changed; center.lab.pin changed"
        );
    }

    #[test]
    fn the_proxy_is_never_shown() {
        let a = "[connection]\nproxy = \"http://one.example:3128\"\nheaders = [\"X-Key\"]\n";
        let b = "[connection]\nproxy = \"http://two.example:3128\"\nheaders = [\"X-Other\"]\n";
        let text = told(a, b);
        assert_eq!(
            text,
            "settings changed by local (version 7): connection.headers changed; connection.proxy changed"
        );
        assert!(!text.contains("example") && !text.contains("X-"), "{text}");
    }

    /// The relay's address is told; its nodes and their token hashes only
    /// as changed.
    #[test]
    fn a_relay_token_hash_is_never_shown() {
        let hash = "a".repeat(64);
        let a = "[relay]\nlisten = \"0.0.0.0:7490\"\n";
        let b = format!(
            "[relay]\nlisten = \"0.0.0.0:7491\"\n\n[[relay.node]]\nname = \"lab\"\ntoken_sha256 = \"{hash}\"\n"
        );
        let text = told(a, &b);
        assert_eq!(
            text,
            "settings changed by local (version 7): relay.listen: 0.0.0.0:7490 -> 0.0.0.0:7491; relay.node changed"
        );
    }

    /// An older text of the guard holds tabs and line breaks; the log line
    /// keeps them written out, so one change is one line.
    #[test]
    fn a_rule_with_line_breaks_is_one_log_line() {
        let rule = nerve_policy::rules::GUARD_OLD[0];
        assert!(rule.contains('\n'));
        let list =
            |v: &[&str]| Value::Array(v.iter().map(|s| Value::String(s.to_string())).collect());
        let text = describe_leaf("center.lab.policy.deny", &list(&[]), &list(&[rule]));
        assert!(!text.contains(['\n', '\r', '\t']), "{text:?}");
        assert!(text.contains("\\r\\n"), "{text}");
    }

    #[test]
    fn a_long_value_is_cut() {
        let long = "x".repeat(300);
        let text = describe_leaf("a.b", &Value::Null, &Value::String(long));
        assert_eq!(text.chars().count(), "a.b: unset -> ".len() + 81);
        assert!(text.ends_with('…'));
    }
}

#[cfg(test)]
mod confinement_tests {
    use super::*;

    /// The refusal for keys in the keyring names what applies on the platform:
    /// the session bus and the installed node's nerve-run on Linux, the
    /// AppContainer and the Credential Manager on Windows, and not the
    /// other's.
    #[test]
    fn the_keyring_refusal_names_the_platform_it_is_for() {
        let text = KEYRING_NOT_CONFINED;
        assert!(text.contains("`nerve-node config set machine.secret_storage file`"));
        #[cfg(windows)]
        {
            assert!(text.contains("AppContainer") && text.contains("Credential Manager"));
            assert!(!text.contains("Landlock") && !text.contains("session bus"));
        }
        #[cfg(not(windows))]
        assert!(text.contains("session bus") && text.contains("nerve-run"));
    }

    /// Without Landlock, the installed Linux node runs folder mode as
    /// `nerve-run`, which its account and the ACLs hold to its folders; a
    /// node run by hand, and any other account, still runs none (#142).
    #[test]
    fn without_landlock_only_nerve_run_runs_folder_mode() {
        let account = |name: &str, uid: u32| crate::service::Account {
            name: name.into(),
            uid,
            gid: uid,
            comment: String::new(),
            home: "/home/x".into(),
            groups: vec![uid],
        };
        let run = || Some(account(crate::account::RUN_USER, 990));
        let file = SecretStorage::File;
        let held = if cfg!(target_os = "linux") {
            None
        } else {
            Some(NOT_CONFINED)
        };
        assert_eq!(folder_refusal(false, true, file, run), held);
        assert_eq!(folder_refusal(false, false, file, run), Some(NOT_CONFINED));
        assert_eq!(
            folder_refusal(false, true, file, || Some(account("alice", 1000))),
            Some(NOT_CONFINED)
        );
        assert_eq!(
            folder_refusal(false, true, file, || None),
            Some(NOT_CONFINED)
        );
        assert_eq!(folder_refusal(true, false, file, || None), None);
        // The keys in the keyring: nerve-run does not reach it, the node's
        // own user does.
        let ring = SecretStorage::Keyring;
        assert_eq!(folder_refusal(false, true, ring, run), held);
        assert_eq!(
            folder_refusal(true, false, ring, || None),
            Some(KEYRING_NOT_CONFINED)
        );
    }

    /// The installed Windows service runs commands as another account, for
    /// which the AppContainer is not wired: folder mode is not confined there
    /// and runs no command. Landlock and a node run by hand keep theirs.
    #[test]
    fn the_installed_service_runs_no_command_in_an_appcontainer() {
        let windows = Confinement {
            landlock_abi: None,
            appcontainer: true,
        };
        assert!(confinement_for(windows, false).appcontainer);
        let installed = confinement_for(windows, true);
        assert!(!installed.available(), "{installed:?}");
        assert_eq!(installed.describe(), "none");
        let linux = Confinement {
            landlock_abi: Some(4),
            appcontainer: false,
        };
        assert_eq!(confinement_for(linux, true), linux);
        assert_eq!(confinement_for(linux, false), linux);
    }
}

#[cfg(all(test, unix))]
mod old_pin_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// An expired old pin that cannot be dropped from node.toml (a full
    /// disk) is not told as dropped, and is tried again only a while later.
    #[tokio::test]
    async fn an_old_pin_that_cannot_be_dropped_is_tried_again_later() {
        let log = Log::new(Level::Info);
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("config"), d.path().join("state"));
        let mut opts = NodeOptions::new(paths.clone());
        opts.home = d.path().to_path_buf();
        opts.ctl = false;
        opts.log = Some(log.clone());
        let daemon = Daemon::start(opts).await.unwrap();
        let s = daemon.shared.clone();
        lock(&s.store)
            .update(|c| {
                c.centers.push(nerve_policy::CenterEntry {
                    name: "lab".into(),
                    url: "http://127.0.0.1:1".into(),
                    pin: Some("B".repeat(43)),
                    center_id: "id-lab".into(),
                    node_id: "n".into(),
                    settings: Default::default(),
                    paused: true,
                    revoked: false,
                    unknown: false,
                    public_key: None,
                    key_rotations: 0,
                    pin_rotations: 0,
                    old_pin: Some(nerve_policy::OldPin {
                        pin: "A".repeat(43),
                        until_ms: 1,
                    }),
                    policy: Default::default(),
                });
                Ok(())
            })
            .unwrap();
        let old_pin = || s.config().centers[0].old_pin.clone();
        let mode = |m| {
            std::fs::set_permissions(&paths.config_dir, std::fs::Permissions::from_mode(m)).unwrap()
        };
        mode(0o500);
        // Root writes anyway; then this test says nothing.
        let writable = std::fs::write(paths.config_dir.join("probe"), b"x").is_ok();
        let dropped = crate::rotate::drop_old_pin(&s, "lab");
        mode(0o700);
        if writable {
            return;
        }
        assert!(!dropped);
        assert!(old_pin().is_some());
        assert!(lock(&s.center("lab").old_pin_failed).is_some());
        // Writable again, but within the wait: not tried yet.
        assert!(!crate::rotate::drop_old_pin(&s, "lab"));
        assert!(old_pin().is_some());
        // After the wait it is.
        *lock(&s.center("lab").old_pin_failed) =
            std::time::Instant::now().checked_sub(Duration::from_secs(601));
        assert!(crate::rotate::drop_old_pin(&s, "lab"));
        assert!(old_pin().is_none());
        drop(daemon);
    }
}
