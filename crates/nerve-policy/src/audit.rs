//! The local audit log: one JSON line per decision, per settings change, per
//! refused config file and per install, setup, update or uninstall, in the
//! node's state directory. It is the owner's record and client-only: no
//! center can read or change the file (centers see their own decisions as
//! `audit/decision` events at most).

use std::borrow::Cow;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// One decision on one call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub ts: u64,
    pub center: String,
    pub cap: String,
    pub action: String,
    pub target: String,
    /// `allowed` or `forbidden`.
    pub decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// Why a call was refused, as the error to the center says it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The command a capability of `node.toml` runs for this call, with the
    /// call's values in it. It holds the owner's own words, which no center
    /// is shown, so it stays in this log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

impl Entry {
    /// The `audit/decision` event's data (spec §7.5): the entry without the
    /// center, which is the one the event goes to. The target is cut as the
    /// log cuts it, so a huge command line never crosses the link.
    pub fn event_data(&self) -> Value {
        let mut v = serde_json::to_value(self).expect("an audit entry serializes");
        if let Some(o) = v.as_object_mut() {
            o.remove("center");
            // The center has the reason in the error already, and the
            // event's fields are fixed (docs/dev/spec/protocol.md §7.5).
            o.remove("reason");
            // The owner's command is the owner's: a center sees the
            // capability's name and summary, never what it runs.
            o.remove("command");
        }
        v["target"] = cut_target(&self.target).into();
        v
    }

    pub fn is_refusal(&self) -> bool {
        self.decision == "forbidden"
    }
}

/// One changed setting: a dotted key and its old and new value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Change {
    pub key: String,
    pub old: Value,
    pub new: Value,
}

/// The size at which `audit.jsonl` is moved aside to `audit.jsonl.1`, which
/// replaces the older one: the log never takes more than twice this.
pub const AUDIT_MAX_BYTES: u64 = 10 * 1024 * 1024;
/// The most of a full `audit.jsonl` that refused calls may take before the
/// oldest of them are dropped instead of the file being moved aside. A
/// center can make refused calls as fast as the link allows; with this it
/// never rotates the log by itself, and an entry of what the node allowed or
/// changed leaves the log only after at least this much newer such entries.
pub const REFUSED_MAX_BYTES: u64 = AUDIT_MAX_BYTES / 2;
/// How much of its newest refusals the file keeps when it drops the older.
const REFUSED_KEEP_BYTES: u64 = REFUSED_MAX_BYTES / 2;
/// The most characters of a target (a command line, a path) one decision
/// logs; a longer one is cut and says so.
pub const TARGET_MAX_CHARS: usize = 512;

/// `target` as an audit record keeps it: its first [`TARGET_MAX_CHARS`]
/// characters and how long it was. The node's log, its `audit/decision`
/// event and the center's audit feed all cut with this. A target cut once
/// stays as it is, so the center can cut what a node already cut.
pub fn cut_target(target: &str) -> Cow<'_, str> {
    let Some((end, _)) = target.char_indices().nth(TARGET_MAX_CHARS) else {
        return Cow::Borrowed(target);
    };
    if is_cut_target(target) {
        return Cow::Borrowed(target);
    }
    let n = TARGET_MAX_CHARS + target[end..].chars().count();
    Cow::Owned(format!(
        "{}… [cut at {TARGET_MAX_CHARS} of {n} characters]",
        &target[..end]
    ))
}

/// Whether `target` looks like what [`cut_target`] makes of a longer one.
/// A call's own target can look like this only at that same short length,
/// so one taken for cut is never longer than a cut one.
pub fn is_cut_target(target: &str) -> bool {
    let Some(rest) = target.strip_suffix(" characters]") else {
        return false;
    };
    let Some((head, n)) = rest.rsplit_once(&format!("… [cut at {TARGET_MAX_CHARS} of ")) else {
        return false;
    };
    head.chars().count() == TARGET_MAX_CHARS
        && n.parse::<usize>().is_ok_and(|n| n > TARGET_MAX_CHARS)
}

/// A tunnel of the relay, as [`AuditLog::relay`] writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTunnel {
    pub node: String,
    pub center: String,
    pub from: String,
    pub start_ms: u64,
    pub end_ms: u64,
    pub reason: String,
    pub up: u64,
    pub down: u64,
}

#[derive(Debug, Clone)]
pub struct AuditLog {
    path: PathBuf,
    /// Whether the log could not be kept within its bound and said so; it
    /// says so once until it can again.
    unbounded: Arc<AtomicBool>,
}

impl AuditLog {
    pub fn new(path: impl Into<PathBuf>) -> AuditLog {
        AuditLog {
            path: path.into(),
            unbounded: Arc::default(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The one older file the log keeps.
    pub fn old_path(&self) -> PathBuf {
        let mut p = self.path.clone().into_os_string();
        p.push(".1");
        p.into()
    }

    fn append(&self, v: &Value) -> std::io::Result<()> {
        if let Some(dir) = self.path.parent() {
            nerve_transport::files::create_private_dir(dir)?;
        }
        let mut line = v.to_string();
        line.push('\n');
        // A center can make refused calls as fast as the link allows, and
        // each is logged; so the log is bounded. When it cannot be (a rename
        // that fails), the entry is written all the same.
        let mut unbounded = None;
        if let Ok(m) = std::fs::metadata(&self.path)
            && m.len() > 0
            && m.len() + line.len() as u64 > AUDIT_MAX_BYTES
        {
            match self.make_room(line.len() as u64) {
                Ok(()) => self.unbounded.store(false, Ordering::SeqCst),
                Err(e) => unbounded = Some(e),
            }
        }
        let mut o = std::fs::OpenOptions::new();
        o.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&self.path)?;
        // One write per line, so concurrent appends do not interleave.
        f.write_all(line.as_bytes())?;
        match unbounded {
            Some(e) if !self.unbounded.swap(true, Ordering::SeqCst) => Err(std::io::Error::new(
                e.kind(),
                format!(
                    "the audit log could not be rotated ({e}); the entry was written, past the \
                     log's {} MiB bound, and so is every next one until it can be",
                    AUDIT_MAX_BYTES / (1024 * 1024)
                ),
            )),
            _ => Ok(()),
        }
    }

    /// Makes room in the full current file for a line of `len` bytes. When
    /// refused calls take more than [`REFUSED_MAX_BYTES`] of it, its oldest
    /// refusals are dropped, so they cannot push the older file out;
    /// otherwise, or when that is not room enough, the file is moved aside.
    fn make_room(&self, len: u64) -> std::io::Result<()> {
        let text = std::fs::read(&self.path)?;
        let refusal = |l: &[u8]| {
            serde_json::from_slice::<Value>(l)
                .is_ok_and(|v| v["decision"].as_str() == Some("forbidden"))
        };
        let refused: u64 = text
            .split_inclusive(|b| *b == b'\n')
            .filter(|l| refusal(l))
            .map(|l| l.len() as u64)
            .sum();
        if refused > REFUSED_MAX_BYTES {
            let mut extra = refused - REFUSED_KEEP_BYTES;
            let mut kept = Vec::with_capacity(text.len());
            for l in text.split_inclusive(|b| *b == b'\n') {
                if extra > 0 && refusal(l) {
                    extra = extra.saturating_sub(l.len() as u64);
                } else {
                    kept.extend_from_slice(l);
                }
            }
            nerve_transport::files::write_private(&self.path, &kept)?;
            if kept.len() as u64 + len <= AUDIT_MAX_BYTES {
                return Ok(());
            }
        }
        std::fs::rename(&self.path, self.old_path())
    }

    pub fn decision(&self, e: &Entry) -> std::io::Result<()> {
        let mut v = serde_json::to_value(e).expect("an audit entry serializes");
        v["target"] = cut_target(&e.target).into();
        if let Some(reason) = &e.reason {
            // A reason may quote the whole command line.
            v["reason"] = cut_target(reason).into();
        }
        if let Some(command) = &e.command {
            v["command"] = cut_target(command).into();
        }
        self.append(&v)
    }

    /// A settings change; `by` is `local` or `center <name>`.
    pub fn settings(&self, by: &str, version: u64, changes: &[Change]) -> std::io::Result<()> {
        self.settings_by(by, None, version, changes)
    }

    /// [`AuditLog::settings`], with the account of the person who made a
    /// local change (`user`), when it is known.
    pub fn settings_by(
        &self,
        by: &str,
        user: Option<&str>,
        version: u64,
        changes: &[Change],
    ) -> std::io::Result<()> {
        let mut entry = json!({
            "ts": nerve_proto::msg::now_ms(),
            "kind": "settings",
            "by": by,
            "version": version,
            "changes": changes,
        });
        if let Some(u) = user {
            entry["user"] = json!(u);
        }
        self.append(&entry)
    }

    /// Something that happened to the config file itself: `refused` (it was
    /// changed outside the owner's path and is not applied), `signed` (the
    /// node signed a file without a MAC line), `accepted` (the owner
    /// took a refused file as it is) or `restored` (the owner put the config
    /// of a backup in place).
    pub fn config(&self, event: &str, file: &Path, reason: &str) -> std::io::Result<()> {
        self.append(&json!({
            "ts": nerve_proto::msg::now_ms(),
            "kind": "config",
            "event": event,
            "file": file.display().to_string(),
            "reason": reason,
        }))
    }

    /// What the owner did to the node itself: `install`, `setup`, `update`
    /// or `uninstall`, with the steps that were done, in order, and the
    /// error that stopped the rest, if one did.
    pub fn node(&self, event: &str, steps: &[String], error: Option<&str>) -> std::io::Result<()> {
        let mut v = json!({
            "ts": nerve_proto::msg::now_ms(),
            "kind": "node",
            "event": event,
            "steps": steps,
        });
        if let Some(e) = error {
            v["error"] = e.into();
        }
        self.append(&v)
    }

    /// A rotation of a key between the node and `center`
    /// (docs/dev/spec/protocol.md §4.10): `event` says which and how it ended
    /// (`node-key`, `node-key-refused`, `node-key-unanswered`,
    /// `node-key-grace-ended`, `center-key`), `detail` the public keys or
    /// pins and why. Never a private key.
    pub fn key(&self, center: &str, event: &str, detail: &str) -> std::io::Result<()> {
        self.append(&json!({
            "ts": nerve_proto::msg::now_ms(),
            "kind": "key",
            "center": center,
            "event": event,
            "detail": detail,
        }))
    }

    /// One tunnel the relay carried (docs/dev/spec/protocol.md §4.8): the
    /// relayed node, the center, the peer's address, when it opened and
    /// ended (ms since the epoch), why it ended and the bytes each way. No
    /// token: the relay holds none in clear.
    pub fn relay(&self, t: &RelayTunnel) -> std::io::Result<()> {
        self.append(&json!({
            "ts": nerve_proto::msg::now_ms(),
            "kind": "relay",
            "node": t.node,
            "center": t.center,
            "from": t.from,
            "start": t.start_ms,
            "end": t.end_ms,
            "reason": t.reason,
            "up": t.up,
            "down": t.down,
        }))
    }

    /// Starts the log afresh (`nerve-node audit clear`): the current file
    /// becomes the older one, as a full log's does, which the one before
    /// gives way to, and the new file begins with an entry of who cleared
    /// it (`user`). So nothing goes silently: the cleared entries stay in
    /// the older file until the log moves aside again, and the readers
    /// ([`AuditLog::lines`]) show only what came after the clearing.
    pub fn clear(&self, user: &str) -> std::io::Result<()> {
        match std::fs::rename(&self.path, self.old_path()) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        self.append(&json!({
            "ts": nerve_proto::msg::now_ms(),
            "kind": "audit",
            "event": "cleared",
            "user": user,
        }))
    }

    /// Every line, oldest first, the older file's included; lines that do
    /// not parse are skipped.
    pub fn read(&self) -> std::io::Result<Vec<Value>> {
        Ok(self
            .lines()?
            .iter()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect())
    }

    /// Every whole line as it is written, oldest first: the older file's,
    /// then the current one's. A last line still being written is left out.
    /// A log cleared ([`AuditLog::clear`]) begins at its clearing: the older
    /// file is left out while the current one starts with it.
    pub fn lines(&self) -> std::io::Result<Vec<String>> {
        self.lines_with(|_| {})
    }

    /// [`lines`](Self::lines), with `before` called ahead of each file read
    /// with the file it is about to read, where a test moves the log aside.
    ///
    /// A move (`audit.jsonl` to `.1`, dropping the older `.1`) between the
    /// reads of the two files would leave out a whole file's entries, and
    /// `audit --follow` would never show them, since it goes on after the
    /// last line it saw. So `.1` is read before and after the current file,
    /// and the reads count only when `.1` is the same both times: then no
    /// move came in between, and the current file is the one after it.
    fn lines_with(&self, mut before: impl FnMut(&Path)) -> std::io::Result<Vec<String>> {
        let old_path = self.old_path();
        let mut read = |p: &Path| {
            before(p);
            match std::fs::read(p) {
                Ok(t) => Ok(Some(t)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        };
        let mut old = read(&old_path)?;
        // The log moves at most once per 10 MiB written, so the second try
        // finds it still; the bound only keeps a broken writer from holding
        // the reader forever.
        for _ in 0..100 {
            let current = read(&self.path)?;
            let again = read(&old_path)?;
            if again == old {
                let mut out = Vec::new();
                if current.as_deref().is_some_and(starts_cleared) {
                    old = None;
                }
                for t in [old, current].into_iter().flatten() {
                    let whole = t.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
                    out.extend(
                        String::from_utf8_lossy(&t[..whole])
                            .lines()
                            .map(str::to_string),
                    );
                }
                return Ok(out);
            }
            old = again;
        }
        Err(std::io::Error::other(
            "the audit log kept moving while it was read",
        ))
    }
}

/// Whether a log file begins with the entry of a clearing.
fn starts_cleared(text: &[u8]) -> bool {
    let first = text.split(|b| *b == b'\n').next().unwrap_or_default();
    serde_json::from_slice::<Value>(first)
        .is_ok_and(|v| v["kind"] == "audit" && v["event"] == "cleared")
}

/// The leaves that differ between `old` and `new`, as dotted keys. Arrays
/// count as leaves.
pub fn diff(old: &Value, new: &Value) -> Vec<Change> {
    let mut out = Vec::new();
    walk("", old, new, &mut out);
    out
}

fn walk(prefix: &str, old: &Value, new: &Value, out: &mut Vec<Change>) {
    match (old, new) {
        (Value::Object(a), Value::Object(b)) => {
            let mut keys: Vec<&String> = a.keys().chain(b.keys()).collect();
            keys.sort();
            keys.dedup();
            for k in keys {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                walk(
                    &key,
                    a.get(k).unwrap_or(&Value::Null),
                    b.get(k).unwrap_or(&Value::Null),
                    out,
                );
            }
        }
        (a, b) if a != b => out.push(Change {
            key: prefix.into(),
            old: a.clone(),
            new: b.clone(),
        }),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_and_reads_back() {
        let d = tempfile::tempdir().unwrap();
        let log = AuditLog::new(d.path().join("state/audit.jsonl"));
        assert!(log.read().unwrap().is_empty());
        let e = Entry {
            ts: 1,
            center: "home".into(),
            cap: "fs".into(),
            action: "read".into(),
            target: "/x".into(),
            decision: "forbidden".into(),
            code: Some("forbidden".into()),
            session: None,
            reason: None,
            command: None,
        };
        log.decision(&e).unwrap();
        log.settings(
            "center home",
            3,
            &diff(&json!({"mode": "folder"}), &json!({"mode": "user"})),
        )
        .unwrap();
        log.node("update", &["replaced nerve-node".into()], Some("no start"))
            .unwrap();
        let lines = log.read().unwrap();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[2]["kind"], "node");
        assert_eq!(lines[2]["event"], "update");
        assert_eq!(lines[2]["steps"][0], "replaced nerve-node");
        assert_eq!(lines[2]["error"], "no start");
        assert_eq!(lines[0]["center"], "home");
        assert_eq!(lines[1]["by"], "center home");
        assert_eq!(lines[1]["changes"][0]["key"], "mode");
        assert_eq!(lines[1]["changes"][0]["new"], "user");
        assert!(e.event_data().get("center").is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(log.path()).unwrap().permissions().mode();
            assert_eq!(m & 0o777, 0o600);
        }
    }

    /// A refused call with a huge command line logs only its start.
    #[test]
    fn a_long_target_is_cut() {
        let d = tempfile::tempdir().unwrap();
        let log = AuditLog::new(d.path().join("audit.jsonl"));
        let e = Entry {
            ts: 1,
            center: "home".into(),
            cap: "exec".into(),
            action: "run".into(),
            target: "ü".repeat(3000),
            decision: "forbidden".into(),
            code: Some("forbidden".into()),
            session: None,
            reason: Some(format!("the command {:?} is denied", "ü".repeat(3000))),
            command: Some(format!("tool --token=secret -- {}", "ü".repeat(3000))),
        };
        log.decision(&e).unwrap();
        let line = &log.read().unwrap()[0];
        let target = line["target"].as_str().unwrap();
        assert!(target.starts_with(&"ü".repeat(512)), "{target}");
        assert!(!target.starts_with(&"ü".repeat(513)), "{target}");
        assert!(
            target.ends_with("[cut at 512 of 3000 characters]"),
            "{target}"
        );
        // The reason is cut the same way, and the event leaves it out.
        let reason = line["reason"].as_str().unwrap();
        assert!(reason.ends_with("characters]"), "{reason}");
        assert!(e.event_data().get("reason").is_none());
        // So is the command of a capability of node.toml, which the log
        // keeps and the event to the center leaves out.
        let command = line["command"].as_str().unwrap();
        assert!(command.starts_with("tool --token=secret -- "), "{command}");
        assert!(command.ends_with("characters]"), "{command}");
        assert!(e.event_data().get("command").is_none());
        assert!(!e.event_data().to_string().contains("secret"));
        // The event to the center carries the same cut target, so the full
        // one never crosses the link.
        let sent = e.event_data()["target"].as_str().unwrap().to_string();
        assert!(
            sent == target,
            "the event carries {} characters",
            sent.chars().count()
        );
        // A short one stays as it is.
        log.decision(&Entry {
            target: "ls".into(),
            ..e
        })
        .unwrap();
        assert_eq!(log.read().unwrap()[1]["target"], "ls");
    }

    /// Cutting twice changes nothing, and only a cut target reads as one.
    #[test]
    fn a_cut_target_is_cut_once() {
        let long = "a".repeat(600);
        let cut = cut_target(&long).into_owned();
        assert!(cut.ends_with("… [cut at 512 of 600 characters]"), "{cut}");
        assert!(is_cut_target(&cut));
        assert_eq!(cut_target(&cut), cut);
        assert_eq!(cut_target(&"a".repeat(512)), "a".repeat(512));
        assert!(!is_cut_target(&"a".repeat(512)));
        assert!(!is_cut_target("ls… [cut at 512 of 600 characters]"));
        let short_head = format!("{}… [cut at 512 of 512 characters]", "a".repeat(512));
        assert!(!is_cut_target(&short_head));
    }

    /// A move of the log between the reads of its two files leaves no
    /// entry out and shows none twice, wherever it lands.
    #[test]
    fn a_move_between_the_reads_drops_no_entries() {
        let lines = |r: std::ops::Range<u64>| -> String {
            r.map(|ts| format!("{}\n", json!({"ts": ts}))).collect()
        };
        // Before each of the first three reads: `.1`, the current file, `.1`.
        for at in 0..3 {
            let d = tempfile::tempdir().unwrap();
            let log = AuditLog::new(d.path().join("audit.jsonl"));
            std::fs::write(log.old_path(), lines(0..3)).unwrap();
            std::fs::write(log.path(), lines(3..6)).unwrap();
            let mut reads = 0;
            let read = log
                .lines_with(|_| {
                    if reads == at {
                        // The writer appends, moves the file aside and
                        // starts a new one.
                        let mut f = std::fs::OpenOptions::new()
                            .append(true)
                            .open(log.path())
                            .unwrap();
                        f.write_all(lines(6..7).as_bytes()).unwrap();
                        std::fs::rename(log.path(), log.old_path()).unwrap();
                        std::fs::write(log.path(), lines(7..9)).unwrap();
                    }
                    reads += 1;
                })
                .unwrap();
            let ts: Vec<u64> = read
                .iter()
                .map(|l| {
                    serde_json::from_str::<Value>(l).unwrap()["ts"]
                        .as_u64()
                        .unwrap()
                })
                .collect();
            // The move dropped 0..3 itself; all after it is there, once.
            assert_eq!(ts, (3..9).collect::<Vec<_>>(), "a move before read {at}");
        }
    }

    /// The log moves aside at its size limit, and only one old file is kept.
    #[test]
    fn the_log_rotates_and_keeps_one_old_file() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("audit.jsonl");
        let log = AuditLog::new(&path);
        let big = json!("x".repeat(1024 * 1024));
        let lines = 25;
        for v in 0..lines {
            let change = Change {
                key: "k".into(),
                old: Value::Null,
                new: big.clone(),
            };
            log.settings("center home", v, &[change]).unwrap();
        }
        let size = |p: &Path| std::fs::metadata(p).map_or(0, |m| m.len());
        let old = d.path().join("audit.jsonl.1");
        assert!(size(&path) <= AUDIT_MAX_BYTES, "{}", size(&path));
        assert!(size(&old) <= AUDIT_MAX_BYTES, "{}", size(&old));
        assert!(size(&old) > 0, "no old file");
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 2);
        // Oldest first, newest last; the oldest lines are gone.
        let read = log.read().unwrap();
        assert!(read.len() < lines as usize, "{}", read.len());
        assert_eq!(read.last().unwrap()["version"], lines - 1);
        let versions: Vec<u64> = read
            .iter()
            .map(|l| l["version"].as_u64().unwrap())
            .collect();
        assert!(
            versions.windows(2).all(|w| w[1] == w[0] + 1),
            "{versions:?}"
        );
    }

    /// A clearing keeps the entries so far as the older file (the one
    /// before gives way), starts the new file with who cleared it, and the
    /// readers show only what came from then on, also once the log moved
    /// aside after it.
    #[test]
    fn a_clearing_keeps_the_entries_as_the_older_file() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("audit.jsonl");
        let log = AuditLog::new(&path);
        // Clearing an empty log leaves the entry only.
        log.clear("alice").unwrap();
        let read = log.read().unwrap();
        assert_eq!(read.len(), 1);
        assert_eq!(read[0]["kind"], "audit");
        assert_eq!(read[0]["event"], "cleared");
        assert_eq!(read[0]["user"], "alice");
        log.settings("local", 1, &[]).unwrap();
        std::fs::write(log.old_path(), "{\"kind\":\"settings\",\"version\":0}\n").unwrap();
        log.settings("local", 2, &[]).unwrap();
        let kept = std::fs::read(&path).unwrap();
        log.clear("bob").unwrap();
        assert_eq!(
            std::fs::read(log.old_path()).unwrap(),
            kept,
            "the older file"
        );
        let read = log.read().unwrap();
        assert_eq!(read.len(), 1, "{read:?}");
        assert_eq!(read[0]["user"], "bob");
        log.settings("local", 3, &[]).unwrap();
        // The log moved aside by its size: from the clearing on still.
        std::fs::rename(&path, log.old_path()).unwrap();
        log.settings("local", 4, &[]).unwrap();
        let read = log.read().unwrap();
        let kinds: Vec<String> = read
            .iter()
            .map(|v| format!("{} {}", v["kind"], v["version"]))
            .collect();
        assert_eq!(
            kinds,
            [r#""audit" null"#, r#""settings" 3"#, r#""settings" 4"#]
        );
    }

    fn refusal(ts: u64, target: String) -> Entry {
        Entry {
            ts,
            center: "lab".into(),
            cap: "exec".into(),
            action: "run".into(),
            target,
            decision: "forbidden".into(),
            code: Some("forbidden".into()),
            session: None,
            reason: None,
            command: None,
        }
    }

    /// A center that makes refused calls as fast as it can does not push
    /// what the node allowed or changed out of the log: refusals have half of
    /// a file, and past that the oldest refusals go first. The log stays
    /// within twice its size limit and keeps the newest refusals.
    #[test]
    fn refusals_do_not_push_out_what_was_allowed() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("audit.jsonl");
        let log = AuditLog::new(&path);
        for ts in 0..3 {
            log.decision(&Entry {
                decision: "allowed".into(),
                code: None,
                ..refusal(ts, format!("allowed {ts}"))
            })
            .unwrap();
        }
        log.settings("center lab", 7, &diff(&json!({"m": 1}), &json!({"m": 2})))
            .unwrap();
        // 30 MiB of refusals, three times the size limit.
        let long = "x".repeat(600);
        let n = 3 * AUDIT_MAX_BYTES / 700;
        for ts in 10..10 + n {
            log.decision(&refusal(ts, format!("{ts} {long}"))).unwrap();
        }
        let read = log.read().unwrap();
        let allowed: Vec<&Value> = read.iter().filter(|l| l["decision"] == "allowed").collect();
        assert_eq!(allowed.len(), 3, "allowed entries were pushed out");
        assert!(
            read.iter().any(|l| l["kind"] == "settings"),
            "the settings entry was pushed out"
        );
        let last = read.last().unwrap();
        assert!(
            last["target"]
                .as_str()
                .unwrap()
                .starts_with(&format!("{} ", 9 + n)),
            "the newest refusal is not the last line"
        );
        let refused = read.iter().filter(|l| l["decision"] == "forbidden").count() as u64;
        assert!(refused > 1000, "only {refused} refusals kept");
        let size = |p: &Path| std::fs::metadata(p).map_or(0, |m| m.len());
        let old = d.path().join("audit.jsonl.1");
        assert!(size(&path) <= AUDIT_MAX_BYTES, "{}", size(&path));
        assert!(size(&old) <= AUDIT_MAX_BYTES, "{}", size(&old));
        // The refusals kept are the newest, in order.
        let ts: Vec<u64> = read
            .iter()
            .filter(|l| l["decision"] == "forbidden")
            .filter_map(|l| l["ts"].as_u64())
            .collect();
        assert!(ts.windows(2).all(|w| w[0] < w[1]), "out of order");
    }

    /// A rotation that fails (here `audit.jsonl.1` is a directory, so the
    /// rename cannot replace it) does not drop the entry: it is written past
    /// the bound, and the failure is reported once.
    #[test]
    fn a_failed_rotation_still_writes_the_entry() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("audit.jsonl");
        let log = AuditLog::new(&path);
        let big = json!("x".repeat(1024 * 1024));
        let change = |v: u64| {
            log.settings(
                "center home",
                v,
                &[Change {
                    key: "k".into(),
                    old: Value::Null,
                    new: big.clone(),
                }],
            )
        };
        for v in 0..9 {
            change(v).unwrap();
        }
        let blocker = d.path().join("audit.jsonl.1");
        std::fs::create_dir(&blocker).unwrap();
        std::fs::write(blocker.join("x"), "").unwrap();
        let first = change(9);
        let second = change(10);
        let text = std::fs::read_to_string(&path).unwrap();
        let versions: Vec<u64> = text
            .lines()
            .map(|l| {
                serde_json::from_str::<Value>(l).unwrap()["version"]
                    .as_u64()
                    .unwrap()
            })
            .collect();
        assert_eq!(versions, (0..11).collect::<Vec<u64>>());
        let e = first.unwrap_err();
        assert!(e.to_string().contains("was written"), "{e}");
        assert!(second.is_ok(), "the failure was reported twice: {second:?}");
        // Once the rotation works again, the log is bounded again.
        std::fs::remove_dir_all(&blocker).unwrap();
        change(11).unwrap();
        assert!(std::fs::metadata(&path).unwrap().len() < AUDIT_MAX_BYTES);
        assert!(blocker.is_file());
    }

    #[test]
    fn diffs_nested_leaves() {
        let c = diff(
            &json!({"a": {"b": 1, "c": [1]}, "d": true}),
            &json!({"a": {"b": 2, "c": [1]}, "e": 1}),
        );
        let keys: Vec<&str> = c.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(keys, ["a.b", "d", "e"]);
    }
}
