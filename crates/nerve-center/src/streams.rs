//! A job's command output as a stream (docs/dev/spec/harness.md §4.5).
//!
//! When `exec.run` becomes a job, the center names a stream for its output
//! in the job's answer and opens the command's `output` stream on the node
//! (`stream.open`, protocol §5) as soon as the command runs there
//! ([`open_on_node`]). The node sends what the command printed so far and
//! then what it prints, as frames; the center keeps them in a [`Ring`] per
//! stream, and the model reads them with `stream.read`, polling: there are
//! no MCP notifications (an event subscription, B6, is a stream read the
//! same way).
//!
//! A ring holds at most [`RING_BYTES`]; past it the oldest bytes go, and the
//! next read says how many. Rings are kept in memory only, per session, and
//! dropped on `stream.close`, when the job's result is read (unless that
//! result lacks output the stream holds), when the session
//! ends, or [`KEEP_FOR`] after the stream ended unread.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use nerve_proto::ErrorCode;
use serde_json::json;
use tokio::sync::watch;

use crate::center::Session;
use crate::jobs::NoSignal;
use crate::link::Link;
use crate::listing;

/// The most bytes one stream keeps that the model did not read yet.
pub const RING_BYTES: usize = 1024 * 1024;
/// The most places in one ring where the node said it dropped bytes; past
/// it a new gap takes in the last one and the text between them.
const GAPS_MAX: usize = 64;
/// The most streams one session holds.
pub const STREAMS_MAX: usize = 16;
/// What `stream.read` gives when `max_bytes` is not set.
pub const READ_DEFAULT: usize = 16 * 1024;
/// The least and the most `stream.read` gives in one call.
pub const READ_MIN: usize = 64;
pub const READ_MAX: usize = crate::listing::TEXT_MAX;
/// What one read keeps free of [`READ_MAX`] for the words around its text,
/// so its answer stays within what one answer hands the model.
pub const READ_ROOM: usize = 4 * 1024;
/// How long an ended stream is kept when nobody reads or closes it.
pub const KEEP_FOR: Duration = crate::jobs::KEEP_FOR;
/// How long one `stream.open` waits for the node's answer.
pub const OPEN_WAIT: Duration = Duration::from_secs(10);
/// How long the center keeps asking for the stream of a command its node
/// does not run yet, once the call was sent: the node may hold a command
/// before it starts (its folders' access, a sandbox to set up).
pub const START_WAIT: Duration = Duration::from_secs(60);

/// The most streams one session has open on one node: half of the node's
/// `limits.streams` (8 of 16), so the other sessions' streams find room.
pub fn node_share(streams: u32) -> usize {
    (streams as usize / 2).max(1)
}

/// What one stream received and nobody read yet.
pub struct Ring {
    state: Mutex<RingState>,
    /// Moves on every push and at the end, for a read that waits.
    moved: watch::Sender<u64>,
}

#[derive(Default)]
struct RingState {
    buf: VecDeque<u8>,
    /// Bytes dropped before the text a read gives next: the ring's own, and
    /// those the node said it dropped there.
    dropped: u64,
    /// Where in the stream `buf` starts: the bytes read or dropped before it.
    at: u64,
    /// Where the node said it dropped bytes after data still in `buf`, and
    /// how many: a read ends there, and the next one starts with the gap.
    gaps: VecDeque<(u64, u64)>,
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
                s.at += over as u64;
                s.dropped += over as u64;
                s.gaps_before_text();
            }
        }
        self.moved();
    }

    /// The node dropped `n` bytes of the stream, after what came so far.
    pub fn gap(&self, n: u64) {
        {
            let mut s = self.state.lock().unwrap();
            let pos = s.at + s.buf.len() as u64;
            if s.buf.is_empty() {
                s.dropped += n;
            } else if let Some((p, m)) = s.gaps.back_mut()
                && *p == pos
            {
                *m += n;
            } else if s.gaps.len() >= GAPS_MAX {
                // The text since the last gap goes with this one: a node
                // that drops a byte after every byte it sends must not make
                // a ring hold more than its bytes.
                let last = s.gaps.back().map_or(pos, |g| g.0);
                let since = (pos - last) as usize;
                let keep = s.buf.len() - since;
                s.buf.truncate(keep);
                if let Some(g) = s.gaps.back_mut() {
                    g.1 += since as u64 + n;
                }
            } else {
                s.gaps.push_back((pos, n));
            }
        }
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
        // Only the start of a character is nothing a read could give yet.
        let ready = |s: &RingState| {
            let part = s.buf.len() < 4
                && {
                    let head: Vec<u8> = s.buf.iter().copied().collect();
                    matches!(std::str::from_utf8(&head), Err(e) if e.valid_up_to() == 0 && e.error_len().is_none())
                };
            (!s.buf.is_empty() && !part) || s.dropped > 0 || !s.gaps.is_empty() || s.end.is_some()
        };
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

    /// Takes up to `max` bytes of text, up to the next gap: the text a read
    /// gives has nothing missing inside it. A character the cut would split
    /// stays for the next read, unless nothing more can come.
    pub fn read(&self, max: usize) -> Read {
        let mut s = self.state.lock().unwrap();
        s.gaps_before_text();
        let upto = s
            .gaps
            .front()
            .map_or(s.buf.len(), |(p, _)| (p - s.at) as usize);
        // The text is never shorter than its bytes.
        let n = upto.min(max);
        // Before a gap nothing comes that could finish a character.
        let last = (s.end.is_some() && n == s.buf.len()) || (n == upto && !s.gaps.is_empty());
        let head: Vec<u8> = s.buf.range(..n).copied().collect();
        let took = text_cut(&head, max, last);
        let bytes: Vec<u8> = s.buf.drain(..took).collect();
        s.at += bytes.len() as u64;
        let eof = s.end.is_some() && s.buf.is_empty() && s.gaps.is_empty();
        Read {
            text: String::from_utf8_lossy(&bytes).into_owned(),
            eof,
            dropped: std::mem::take(&mut s.dropped),
            why: s.end.as_ref().filter(|_| eof).map(|(w, _)| w.clone()),
        }
    }
}

/// How many of `bytes` one read takes: as many as make at most `max` bytes
/// of the text the model reads ([`listing::guarded`]: a control character
/// shown escaped counts as its escape), where each run of bytes that is not
/// UTF-8 reads as one replacement character of 3 bytes (a Unix node sends a
/// command's bytes as they are). The start of a character at the end stays
/// for the next read, unless it is the `last` that can come: the end is
/// checked on its own, so a bad byte before it does not let the character
/// be split.
fn text_cut(bytes: &[u8], max: usize, last: bool) -> usize {
    let (mut took, mut size) = (0, 0);
    // The text starts a line: it starts the framing's body.
    let (mut start, mut shown) = (true, String::new());
    let mut cost = |c: char| {
        shown.clear();
        listing::guard(c, &mut start, &mut shown);
        shown.len()
    };
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            let n = cost(c);
            if size + n > max {
                return took;
            }
            took += c.len_utf8();
            size += n;
        }
        let bad = chunk.invalid();
        if bad.is_empty() {
            continue;
        }
        let start = took + bad.len() == bytes.len()
            && std::str::from_utf8(bad).is_err_and(|e| e.error_len().is_none());
        if start && !last {
            return took;
        }
        let n = cost(char::REPLACEMENT_CHARACTER);
        if size + n > max {
            return took;
        }
        took += bad.len();
        size += n;
    }
    took
}

impl RingState {
    /// The node's gaps that no unread text comes before any more: they are
    /// before the text the next read gives.
    fn gaps_before_text(&mut self) {
        while let Some(&(p, n)) = self.gaps.front()
            && p <= self.at
        {
            self.dropped += n;
            self.gaps.pop_front();
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
    /// The link and `sid` of the stream, once the node opened it.
    node: Option<(Weak<Link>, u32)>,
    ring: Arc<Ring>,
}

impl Closer {
    /// Ends the stream, frees it on its link and tells the node to stop it,
    /// unless it ended there already. The node's answer is not waited for:
    /// it says nothing the center needs.
    pub fn close(self, why: &str) {
        self.ring.end(why);
        let Some((link, sid)) = self.node else {
            return;
        };
        let Some(link) = link.upgrade() else {
            return;
        };
        if link.forget_stream(sid) && !link.is_closed() {
            let why = why.to_string();
            tokio::spawn(async move { link.close_stream(sid, &why).await });
        }
    }
}

struct Entry {
    node_id: String,
    job: String,
    node: Option<(Weak<Link>, u32)>,
    ring: Arc<Ring>,
    opened: Instant,
}

impl Entry {
    fn closer(self) -> Closer {
        Closer {
            node: self.node,
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

    /// Adds the stream of the output of `job` on `node_id`, as `id`, before
    /// the node opened it. Refused once the session ended.
    pub fn add(&mut self, id: &str, node_id: &str, job: &str, ring: Arc<Ring>) -> bool {
        if self.ended {
            return false;
        }
        let e = Entry {
            node_id: node_id.to_string(),
            job: job.to_string(),
            node: None,
            ring,
            opened: Instant::now(),
        };
        self.entries.insert(id.to_string(), e);
        true
    }

    /// The node opened the stream `id` as `sid` on `link`; `false` when the
    /// session no longer holds it.
    pub fn opened(&mut self, id: &str, link: &Arc<Link>, sid: u32) -> bool {
        match self.entries.get_mut(id) {
            Some(e) => {
                e.node = Some((Arc::downgrade(link), sid));
                true
            }
            None => false,
        }
    }

    /// How many of the session's streams are open on `link` and still run.
    pub fn open_on(&self, link: &Arc<Link>) -> usize {
        self.entries
            .values()
            .filter(|e| {
                e.node
                    .as_ref()
                    .is_some_and(|(l, _)| std::ptr::eq(l.as_ptr(), Arc::as_ptr(link)))
                    && !e.ring.ended()
            })
            .count()
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

    /// The result of the job `job` was read: its stream goes, unless the
    /// result is not `whole` (cut, or without the output: a failure, a lost
    /// link, a result not kept) and the stream holds output or, open on the
    /// node, may still get some. Then it stays, and its id is given.
    pub fn result_read(&mut self, job: &str, whole: bool) -> (Option<String>, Option<Closer>) {
        let Some((id, e)) = self.entries.iter().find(|(_, e)| e.job == job) else {
            return (None, None);
        };
        let more = e.ring.held() > 0 || (e.node.is_some() && !e.ring.ended());
        if !whole && more {
            return (Some(id.clone()), None);
        }
        let id = id.clone();
        (None, self.entries.remove(&id).map(Entry::closer))
    }

    /// Takes the stream of the job `job` out: the job is forgotten.
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

/// Opens the stream `id` of the job `job` of `sess` on `node_id`, whose
/// frames go to `ring`: once the job's call reached the node and its
/// command runs there, which may take a while (the checker, a call place,
/// the node setting up), and once there is room for it: the session's share
/// of the node's streams ([`node_share`]) and the node's own places. Gives
/// up when the job ended, the stream was closed or the node refused it, and
/// then says why in the ring. `waits`: [`OPEN_WAIT`] and [`START_WAIT`].
pub async fn open_on_node(
    sess: Weak<Session>,
    node_id: String,
    job: String,
    id: String,
    ring: Arc<Ring>,
    waits: (Duration, Duration),
) {
    let (open_wait, start_wait) = waits;
    let mut pause = Duration::from_millis(50);
    let mut sent_at: Option<Instant> = None;
    // The last request went unanswered, or could not be sent for those.
    let mut unanswered = false;
    loop {
        // Closed meanwhile: by the agent, the job's result read, the session's end.
        if ring.ended() {
            return;
        }
        let Some(s) = sess.upgrade() else {
            return;
        };
        let target = s.jobs.lock().unwrap().signal_target(&job, &node_id);
        let session = s.id.clone();
        drop(s);
        match target {
            Err(NoSignal::NotSent) => {}
            // Ended without a stream: its command may have run and ended,
            // or never run (the checker or the node refused it, or it was
            // cancelled), so the words hold for each.
            Err(_) => {
                ring.end("its job ended before its output could be streamed; job.status gives its result");
                return;
            }
            Ok((link, call)) => {
                let mine = sess
                    .upgrade()
                    .map_or(0, |s| s.streams.lock().unwrap().open_on(&link));
                // Waiting for room is not waiting for the command to start.
                if mine >= node_share(link.limits.streams) {
                    sent_at = None;
                    tokio::time::sleep(pause).await;
                    pause = (pause * 2).min(Duration::from_secs(1));
                    continue;
                }
                let since = *sent_at.get_or_insert_with(Instant::now);
                if since.elapsed() >= start_wait {
                    ring.end(if unanswered {
                        "the node did not answer requests for a stream in time; job.status gives its output with the result"
                    } else {
                        "its command did not start on the node in time to be streamed; job.status gives its output with the result"
                    });
                    return;
                }
                // A node that left requests unanswered gets no more from the
                // link until their answers free them (a slow link may still
                // bring them): the refusal is a timeout, which counts this
                // wait as the command's start.
                let params = json!({"cap": "exec", "stream": "output", "params": {"call": call},
                                    "ctx": {"session": session}});
                let tried = link.open_stream(params, ring.clone(), open_wait).await;
                unanswered = matches!(&tried, Err(e) if e.kind() == ErrorCode::Timeout);
                match tried {
                    Ok(sid) => {
                        let kept = sess
                            .upgrade()
                            .is_some_and(|s| s.streams.lock().unwrap().opened(&id, &link, sid));
                        if !kept {
                            Closer {
                                node: Some((Arc::downgrade(&link), sid)),
                                ring,
                            }
                            .close("it was closed");
                        }
                        return;
                    }
                    // Not running there yet (or any more: the job's end tells),
                    // or the link is down for now.
                    // The command runs, and the node has no stream place free:
                    // one frees up when another stream ends.
                    Err(e) if e.kind() == ErrorCode::Busy => sent_at = None,
                    Err(e)
                        if matches!(
                            e.kind(),
                            ErrorCode::InvalidArgs | ErrorCode::Timeout | ErrorCode::ConnectionLost
                        ) => {}
                    Err(e) => {
                        ring.end(&refused(&e.kind()));
                        return;
                    }
                }
            }
        }
        tokio::time::sleep(pause).await;
        pause = (pause * 2).min(Duration::from_secs(1));
    }
}

/// Why the node did not open a stream, in the center's words: a node's own
/// text never reaches the model as the center's.
fn refused(code: &ErrorCode) -> String {
    match code {
        ErrorCode::Unavailable => {
            "the node does not stream this command's output; job.status gives it with the result"
                .into()
        }
        ErrorCode::Other(_) => "the node refused to open it".into(),
        c => format!("the node refused to open it ({})", c.as_str()),
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
        assert_eq!(r.held(), RING_BYTES);
        let first = r.read(READ_MAX);
        assert_eq!(first.dropped, 2);
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

    /// A gap the node reports lies after the data that came before it: a
    /// read ends there, and the next one starts with it, so no text a read
    /// gives has bytes missing inside it.
    #[test]
    fn a_nodes_gap_ends_a_read_where_it_is() {
        let r = Ring::default();
        r.push(b"compiling crate-a\nwarn");
        r.gap(300);
        r.push(b"ing: unused\nerror");
        r.gap(7);
        let first = r.read(8);
        assert_eq!((first.text.as_str(), first.dropped), ("compilin", 0));
        let first = r.read(READ_MAX);
        assert_eq!((first.text.as_str(), first.dropped), ("g crate-a\nwarn", 0));
        let second = r.read(READ_MAX);
        assert_eq!(
            (second.text.as_str(), second.dropped, second.eof),
            ("ing: unused\nerror", 300, false)
        );
        r.end("the command ended");
        let last = r.read(READ_MAX);
        assert_eq!((last.text.as_str(), last.dropped, last.eof), ("", 7, true));

        // A gap with nothing unread before it is before what comes next; a
        // character cut by a gap reads as it is, nothing can finish it.
        let r = Ring::default();
        r.gap(4);
        r.push(&"\u{e4}".as_bytes()[..1]);
        r.gap(1);
        r.push(b"x");
        let a = r.read(READ_MAX);
        assert_eq!((a.text.as_str(), a.dropped), ("\u{fffd}", 4));
        let b = r.read(READ_MAX);
        assert_eq!((b.text.as_str(), b.dropped), ("x", 1));
    }

    /// A node that drops a little after every byte it sends cannot make a
    /// ring hold more than its bytes: past [`GAPS_MAX`] places, the text
    /// between two gaps is dropped with them, and the reads still count
    /// every byte.
    #[test]
    fn a_ring_keeps_few_gaps() {
        let r = Ring::default();
        for _ in 0..10_000 {
            r.push(b"x");
            r.gap(1);
        }
        assert!(r.state.lock().unwrap().gaps.len() <= GAPS_MAX);
        let (mut text, mut dropped) = (0, 0);
        r.end("the command ended");
        loop {
            let got = r.read(READ_MAX);
            text += got.text.len() as u64;
            dropped += got.dropped;
            if got.eof {
                break;
            }
        }
        assert_eq!(text + dropped, 20_000);
        assert!(text >= GAPS_MAX as u64 - 1, "{text}");
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

        // A bad byte earlier in the read does not let the end be split.
        let r = Ring::default();
        r.push(b"\xffab\xc3");
        assert_eq!(r.read(READ_MAX).text, "\u{fffd}ab");
        r.push(b"\xbc rest");
        assert_eq!(r.read(READ_MAX).text, "\u{fc} rest");
    }

    /// Bytes that are not UTF-8 grow into replacement characters: a read
    /// gives at most `max` bytes of text all the same, and what it leaves
    /// stays for the next one.
    #[test]
    fn a_read_of_bytes_that_are_not_utf8_stays_within_its_max() {
        let r = Ring::default();
        r.push(&[0xff; 300]);
        r.push("ok \u{fc}".as_bytes());
        r.end("ended");
        let mut text = String::new();
        loop {
            let got = r.read(READ_MIN);
            assert!(got.text.len() <= READ_MIN, "{}", got.text.len());
            text.push_str(&got.text);
            if got.eof {
                break;
            }
        }
        assert_eq!(text, "\u{fffd}".repeat(300) + "ok \u{fc}");
        // A bad byte makes the text longer than its bytes, so the cut can
        // land inside a character that comes after it: it stays whole for
        // the next read.
        let r = Ring::default();
        r.push(&[0xff]);
        r.push(&[b'a'; READ_MIN - 4]);
        r.push("\u{fc} rest".as_bytes());
        r.end("ended");
        let first = r.read(READ_MIN);
        assert!(first.text.len() <= READ_MIN, "{}", first.text.len());
        assert!(first.text.ends_with('a'), "{}", first.text);
        assert_eq!(r.read(READ_MIN).text, "\u{fc} rest");
    }

    /// The model reads the text with its control characters escaped and a
    /// `\` before a line's `[`: a read gives at most `max` bytes of that,
    /// and what it leaves stays for the next one.
    #[test]
    fn a_read_counts_its_text_as_the_model_reads_it() {
        let r = Ring::default();
        r.push(&[0x1b; 100]);
        r.push(b"\n[x\n");
        r.end("ended");
        let mut text = String::new();
        loop {
            let got = r.read(READ_MIN);
            let shown = listing::guarded(&got.text);
            assert!(shown.len() <= READ_MIN, "{shown:?}");
            text.push_str(&got.text);
            if got.eof {
                break;
            }
        }
        assert_eq!(text, "\u{1b}".repeat(100) + "\n[x\n");
        // Each read holds as many escapes as fit: ten of 6 bytes.
        let r = Ring::default();
        r.push(&[0x1b; 100]);
        assert_eq!(r.read(READ_MIN).text.len(), 10);
        let r = Ring::default();
        r.push(b"[");
        r.push(&[b'a'; READ_MIN - 1]);
        assert_eq!(r.read(READ_MIN).text.len(), READ_MIN - 1);
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
        // The start of a character alone is nothing a read could give: the
        // wait goes on until the rest comes.
        r.push(&"\u{2713}".as_bytes()[..1]);
        let started = Instant::now();
        r.wait(Duration::from_millis(100)).await;
        assert!(started.elapsed() >= Duration::from_millis(100));
        r.push(&"\u{2713}".as_bytes()[1..]);
        r.wait(Duration::from_secs(10)).await;
        assert_eq!(r.read(READ_MAX).text, "\u{2713}");
    }

    /// A session finds only its own streams, on the node they are on; the
    /// end of the session takes them all and refuses new ones.
    #[test]
    fn a_session_holds_its_own_streams_until_it_ends() {
        let link = Arc::new(Link::for_test("n1"));
        let mut s = Streams::default();
        let now = Instant::now();
        let ring = Arc::new(Ring::default());
        assert!(s.add("s-1", "n1", "j-1", ring));
        assert!(s.opened("s-1", &link, 1));
        assert!(s.get("s-1", "n1", now).0.is_some());
        assert!(s.get("s-1", "n2", now).0.is_none(), "another node's");
        assert!(s.get("s-2", "n1", now).0.is_none());
        assert!(s.close("s-1", "n2").is_none());
        assert!(s.of_job("j-1").is_some());
        assert!(s.is_empty());
        assert!(!s.opened("s-1", &link, 1), "closed meanwhile");
        for i in 0..STREAMS_MAX {
            let ring = Arc::new(Ring::default());
            assert!(s.add(&format!("s-{i}"), "n1", &format!("j-{i}"), ring));
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
        assert!(!s.add("s-x", "n1", "j-x", ring));
        assert!(!s.room(now).0);
    }
}
