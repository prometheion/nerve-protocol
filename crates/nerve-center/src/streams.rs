//! A job's command output as a stream (docs/dev/spec/harness.md §4.5).
//!
//! When `exec.run` becomes a job, the center opens the command's `output`
//! stream on the node (`stream.open`, protocol §5) and names it in the job's
//! answer. The node sends what the command printed so far and then what it
//! prints, as frames; the center keeps them in a [`Ring`] per stream, and the
//! model reads them with `stream.read`, polling: there are no MCP
//! notifications (an event subscription, B6, is a stream read the same way).
//!
//! A ring holds at most [`RING_BYTES`]; past it the oldest bytes go, and the
//! next read says how many. Rings are kept in memory only, per session, and
//! dropped on `stream.close`, when the job's result is read, when the session
//! ends, or [`KEEP_FOR`] after the stream ended unread.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use tokio::sync::watch;

use crate::link::Link;

/// The most bytes one stream keeps that the model did not read yet.
pub const RING_BYTES: usize = 1024 * 1024;
/// The most streams one session holds.
pub const STREAMS_MAX: usize = 16;
/// What `stream.read` gives when `max_bytes` is not set.
pub const READ_DEFAULT: usize = 16 * 1024;
/// The least and the most `stream.read` gives in one call.
pub const READ_MIN: usize = 64;
pub const READ_MAX: usize = crate::listing::TEXT_MAX;
/// How long an ended stream is kept when nobody reads or closes it.
pub const KEEP_FOR: Duration = crate::jobs::KEEP_FOR;

/// What one stream received and nobody read yet.
pub struct Ring {
    state: Mutex<RingState>,
    /// Moves on every push and at the end, for a read that waits.
    moved: watch::Sender<u64>,
}

#[derive(Default)]
struct RingState {
    buf: VecDeque<u8>,
    /// Bytes dropped since the last read: the ring's own, and those the node
    /// said it dropped.
    dropped: u64,
    /// Why it ended, and when.
    end: Option<(String, Instant)>,
}

/// One `stream.read`.
#[derive(Debug, PartialEq, Eq)]
pub struct Read {
    pub text: String,
    /// The stream ended and this is the last of it.
    pub eof: bool,
    /// Bytes dropped before this text.
    pub dropped: u64,
    /// Why the stream ended, once `eof`.
    pub why: Option<String>,
}

impl Default for Ring {
    fn default() -> Ring {
        Ring {
            state: Mutex::default(),
            moved: watch::channel(0).0,
        }
    }
}

impl Ring {
    fn moved(&self) {
        self.moved.send_modify(|n| *n += 1);
    }

    /// Data of the stream came.
    pub fn push(&self, data: &[u8]) {
        {
            let mut s = self.state.lock().unwrap();
            if s.end.is_some() {
                return;
            }
            s.buf.extend(data);
            let over = s.buf.len().saturating_sub(RING_BYTES);
            if over > 0 {
                s.buf.drain(..over);
                s.dropped += over as u64;
            }
        }
        self.moved();
    }

    /// The node dropped `n` bytes of the stream.
    pub fn gap(&self, n: u64) {
        self.state.lock().unwrap().dropped += n;
        self.moved();
    }

    /// The stream ended (`why`); what it holds can still be read. Only the
    /// first end counts.
    pub fn end(&self, why: &str) {
        {
            let mut s = self.state.lock().unwrap();
            if s.end.is_some() {
                return;
            }
            s.end = Some((why.to_string(), Instant::now()));
        }
        self.moved();
    }

    /// Whether the stream ended.
    pub fn ended(&self) -> bool {
        self.state.lock().unwrap().end.is_some()
    }

    /// The bytes it holds.
    pub fn held(&self) -> usize {
        self.state.lock().unwrap().buf.len()
    }

    /// Whether it ended longer than [`KEEP_FOR`] before `now`.
    fn stale(&self, now: Instant) -> bool {
        self.state
            .lock()
            .unwrap()
            .end
            .as_ref()
            .is_some_and(|(_, at)| now.saturating_duration_since(*at) >= KEEP_FOR)
    }

    /// Waits up to `wait` until there is something to read or the stream
    /// ended.
    pub async fn wait(&self, wait: Duration) {
        let mut rx = self.moved.subscribe();
        let ready = |s: &RingState| !s.buf.is_empty() || s.dropped > 0 || s.end.is_some();
        if ready(&self.state.lock().unwrap()) {
            return;
        }
        let _ = tokio::time::timeout(wait, async {
            while rx.changed().await.is_ok() {
                if ready(&self.state.lock().unwrap()) {
                    return;
                }
            }
        })
        .await;
    }

    /// Takes up to `max` bytes as text. A character the cut would split
    /// stays for the next read, unless nothing more can come.
    pub fn read(&self, max: usize) -> Read {
        let mut s = self.state.lock().unwrap();
        let n = s.buf.len().min(max);
        let mut bytes: Vec<u8> = s.buf.drain(..n).collect();
        let last = s.end.is_some() && s.buf.is_empty();
        if !last && let Err(e) = std::str::from_utf8(&bytes) {
            // Only a split at the end is held back; a bad byte elsewhere
            // reads as a replacement character, as it would anyway.
            if e.error_len().is_none() {
                let rest = bytes.split_off(e.valid_up_to());
                for b in rest.into_iter().rev() {
                    s.buf.push_front(b);
                }
            }
        }
        let eof = s.end.is_some() && s.buf.is_empty();
        Read {
            text: String::from_utf8_lossy(&bytes).into_owned(),
            eof,
            dropped: std::mem::take(&mut s.dropped),
            why: s.end.as_ref().filter(|_| eof).map(|(w, _)| w.clone()),
        }
    }
}

/// A stream of a session as `stream.read` finds it.
pub struct Found {
    pub ring: Arc<Ring>,
    /// The job whose output it is.
    pub job: String,
}

/// What closing a stream leaves to do: tell the node, if the stream still
/// runs there.
pub struct Closer {
    link: Weak<Link>,
    sid: u32,
    ring: Arc<Ring>,
}

impl Closer {
    /// Frees the stream on its link and tells the node to stop it, unless it
    /// ended already.
    pub async fn close(self, why: &str) {
        let Some(link) = self.link.upgrade() else {
            return;
        };
        let open = link.forget_stream(self.sid);
        self.ring.end(why);
        if open && !link.is_closed() {
            link.close_stream(self.sid, why).await;
        }
    }
}

struct Entry {
    node_id: String,
    job: String,
    link: Weak<Link>,
    sid: u32,
    ring: Arc<Ring>,
    opened: Instant,
}

impl Entry {
    fn closer(self) -> Closer {
        Closer {
            link: self.link,
            sid: self.sid,
            ring: self.ring,
        }
    }
}

/// A session's streams, under their own lock: nothing else is locked while
/// it is held.
#[derive(Default)]
pub struct Streams {
    entries: HashMap<String, Entry>,
    /// The session ended: no stream is added any more.
    ended: bool,
}

impl Streams {
    /// How many streams the session holds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Makes room for one more stream at `now`: streams that ended longer
    /// than [`KEEP_FOR`] ago go, and with [`STREAMS_MAX`] held the oldest
    /// ended one. `false` when there is no room: every stream still runs.
    /// The closers of what went are given back.
    pub fn room(&mut self, now: Instant) -> (bool, Vec<Closer>) {
        let mut gone = self.prune(now);
        if self.entries.len() >= STREAMS_MAX {
            let oldest = self
                .entries
                .iter()
                .filter(|(_, e)| e.ring.ended())
                .min_by_key(|(_, e)| e.opened)
                .map(|(id, _)| id.clone());
            if let Some(id) = oldest
                && let Some(e) = self.entries.remove(&id)
            {
                gone.push(e.closer());
            }
        }
        (!self.ended && self.entries.len() < STREAMS_MAX, gone)
    }

    /// Adds the stream `sid` on `link`, the output of `job` on `node_id`, as
    /// `id`. Refused (its closer given back) once the session ended.
    pub fn add(
        &mut self,
        id: &str,
        node_id: &str,
        job: &str,
        link: &Arc<Link>,
        sid: u32,
        ring: Arc<Ring>,
    ) -> Result<(), Closer> {
        let e = Entry {
            node_id: node_id.to_string(),
            job: job.to_string(),
            link: Arc::downgrade(link),
            sid,
            ring,
            opened: Instant::now(),
        };
        if self.ended {
            return Err(e.closer());
        }
        self.entries.insert(id.to_string(), e);
        Ok(())
    }

    /// The stream `id` of `node_id`; none when this session has no such
    /// stream on that node.
    pub fn get(&mut self, id: &str, node_id: &str, now: Instant) -> (Option<Found>, Vec<Closer>) {
        let gone = self.prune(now);
        let found = self
            .entries
            .get(id)
            .filter(|e| e.node_id == node_id)
            .map(|e| Found {
                ring: e.ring.clone(),
                job: e.job.clone(),
            });
        (found, gone)
    }

    /// Takes the stream `id` of `node_id` out, to close it.
    pub fn close(&mut self, id: &str, node_id: &str) -> Option<Closer> {
        if !self.entries.get(id).is_some_and(|e| e.node_id == node_id) {
            return None;
        }
        self.entries.remove(id).map(Entry::closer)
    }

    /// Takes the stream of the job `job` out: its result was read.
    pub fn of_job(&mut self, job: &str) -> Option<Closer> {
        let id = self
            .entries
            .iter()
            .find(|(_, e)| e.job == job)
            .map(|(id, _)| id.clone())?;
        self.entries.remove(&id).map(Entry::closer)
    }

    /// The session ended: every stream goes, and none is added any more.
    pub fn end(&mut self) -> Vec<Closer> {
        self.ended = true;
        self.entries.drain().map(|(_, e)| e.closer()).collect()
    }

    fn prune(&mut self, now: Instant) -> Vec<Closer> {
        let old: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, e)| e.ring.stale(now))
            .map(|(id, _)| id.clone())
            .collect();
        old.iter()
            .filter_map(|id| self.entries.remove(id))
            .map(Entry::closer)
            .collect()
    }
}

/// A new stream id.
pub fn new_id() -> String {
    format!("s-{}", nerve_transport::keys::random_token(12))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ring keeps the newest [`RING_BYTES`]: what went is counted and
    /// told once, with the next read.
    #[test]
    fn the_ring_keeps_its_newest_bytes_and_says_what_went() {
        let r = Ring::default();
        r.push(&vec![b'a'; RING_BYTES]);
        r.push(b"bc");
        r.gap(5);
        assert_eq!(r.held(), RING_BYTES);
        let first = r.read(READ_MAX);
        assert_eq!(first.dropped, 2 + 5);
        assert_eq!(first.text.len(), READ_MAX);
        assert!(!first.eof);
        let mut rest = String::new();
        loop {
            let next = r.read(READ_MAX);
            assert_eq!(next.dropped, 0, "told once");
            if next.text.is_empty() {
                break;
            }
            rest.push_str(&next.text);
        }
        assert_eq!(first.text.len() + rest.len(), RING_BYTES);
        assert!(rest.ends_with("abc"));
        r.push(b"line\n");
        r.end("the command ended");
        // Nothing comes after the end.
        r.push(b"late");
        let last = r.read(READ_MAX);
        assert_eq!(
            (last.text.as_str(), last.eof, last.why.as_deref()),
            ("line\n", true, Some("the command ended"))
        );
    }

    /// A character the read would split waits for the next one.
    #[test]
    fn a_split_character_stays_for_the_next_read() {
        let r = Ring::default();
        r.push("ab\u{e4}".as_bytes());
        let first = r.read(3);
        assert_eq!(first.text, "ab");
        r.push(b"c");
        assert_eq!(r.read(READ_MAX).text, "\u{e4}c");
        // At the end there is nothing to wait for.
        r.push(&"\u{e4}".as_bytes()[..1]);
        r.end("ended");
        let last = r.read(READ_MAX);
        assert_eq!((last.text.as_str(), last.eof), ("\u{fffd}", true));
    }

    /// A read that waits returns once something comes, or when its wait is
    /// over.
    #[tokio::test]
    async fn a_read_waits_for_data_or_its_time() {
        let r = Arc::new(Ring::default());
        let started = Instant::now();
        r.wait(Duration::from_millis(100)).await;
        assert!(started.elapsed() >= Duration::from_millis(100));
        let w = r.clone();
        let pusher = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            w.push(b"hi");
        });
        let started = Instant::now();
        r.wait(Duration::from_secs(10)).await;
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(r.read(READ_MAX).text, "hi");
        pusher.await.unwrap();
    }

    /// A session finds only its own streams, on the node they are on; the
    /// end of the session takes them all and refuses new ones.
    #[test]
    fn a_session_holds_its_own_streams_until_it_ends() {
        let link = Arc::new(Link::for_test("n1"));
        let mut s = Streams::default();
        let now = Instant::now();
        let ring = Arc::new(Ring::default());
        assert!(s.add("s-1", "n1", "j-1", &link, 1, ring).is_ok());
        assert!(s.get("s-1", "n1", now).0.is_some());
        assert!(s.get("s-1", "n2", now).0.is_none(), "another node's");
        assert!(s.get("s-2", "n1", now).0.is_none());
        assert!(s.close("s-1", "n2").is_none());
        assert!(s.of_job("j-1").is_some());
        assert!(s.is_empty());
        for i in 0..STREAMS_MAX {
            let ring = Arc::new(Ring::default());
            let added = s.add(
                &format!("s-{i}"),
                "n1",
                &format!("j-{i}"),
                &link,
                i as u32,
                ring,
            );
            assert!(added.is_ok());
        }
        // Full of running streams: no room; one that ended makes room.
        assert!(!s.room(now).0);
        s.get("s-3", "n1", now).0.unwrap().ring.end("ended");
        let (room, gone) = s.room(now);
        assert!(room && gone.len() == 1);
        assert_eq!(s.len(), STREAMS_MAX - 1);
        // Ended streams go after a while on their own.
        s.get("s-4", "n1", now).0.unwrap().ring.end("ended");
        let (_, gone) = s.get("s-5", "n1", now + KEEP_FOR + Duration::from_secs(1));
        assert_eq!(gone.len(), 1);
        assert_eq!(s.end().len(), STREAMS_MAX - 2);
        let ring = Arc::new(Ring::default());
        assert!(s.add("s-x", "n1", "j-x", &link, 99, ring).is_err());
        assert!(!s.room(now).0);
    }
}
