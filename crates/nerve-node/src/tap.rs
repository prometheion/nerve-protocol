//! The output of a running command for its `output` stream
//! (docs/dev/spec/protocol.md §7.3): what it printed lately, and what it
//! prints from now on, for each stream open on it.
//!
//! The command never waits for a stream. Its output is read as fast as it
//! comes ([`crate::exec`] drains its pipes whatever happens); a stream that
//! cannot keep up loses its oldest bytes and says how many
//! ([`Chunk::Gap`]), and its result still holds the output as before.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, Weak};

use tokio::sync::Notify;

use crate::daemon::lock;

/// What a stream opened on a running command gets first: the end of what
/// the command printed so far.
pub const TAIL: usize = 64 * 1024;
/// The most a stream holds that the link has not sent yet; past it the
/// oldest bytes go.
pub const PENDING: usize = 1024 * 1024;

/// One running command's output, stdout and stderr in the order the node
/// read them.
#[derive(Default)]
pub struct Tap {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    tail: VecDeque<u8>,
    printed: u64,
    readers: Vec<Weak<Reader>>,
    ended: bool,
}

/// One stream's view of a [`Tap`]: what it still has to send.
#[derive(Default)]
pub struct Reader {
    pending: Mutex<Pending>,
    more: Notify,
}

#[derive(Default)]
struct Pending {
    data: VecDeque<u8>,
    dropped: u64,
    ended: bool,
}

/// What a stream sends next.
#[derive(Debug, PartialEq, Eq)]
pub enum Chunk {
    Data(Vec<u8>),
    /// This many bytes were dropped here.
    Gap(u64),
    /// The command ended and everything was taken.
    End,
}

impl Pending {
    fn push(&mut self, b: &[u8]) {
        self.data.extend(b);
        let over = self.data.len().saturating_sub(PENDING);
        if over > 0 {
            self.data.drain(..over);
            self.dropped += over as u64;
        }
    }
}

impl std::fmt::Debug for Tap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let t = lock(&self.inner);
        f.debug_struct("Tap")
            .field("printed", &t.printed)
            .field("ended", &t.ended)
            .finish()
    }
}

impl Tap {
    /// The command printed `b`.
    pub fn push(&self, b: &[u8]) {
        if b.is_empty() {
            return;
        }
        let mut t = lock(&self.inner);
        t.printed += b.len() as u64;
        t.tail.extend(b);
        let over = t.tail.len().saturating_sub(TAIL);
        t.tail.drain(..over);
        // A stream that was closed is gone from here too.
        t.readers.retain(|r| match r.upgrade() {
            Some(r) => {
                lock(&r.pending).push(b);
                r.more.notify_one();
                true
            }
            None => false,
        });
    }

    /// The command ended: its streams end once they sent what is left.
    pub fn end(&self) {
        let mut t = lock(&self.inner);
        t.ended = true;
        for r in t.readers.drain(..).filter_map(|r| r.upgrade()) {
            lock(&r.pending).ended = true;
            r.more.notify_one();
        }
    }

    /// A new stream of the output: the tail first (what came before it is
    /// a gap), then what the command prints from now on.
    pub fn reader(&self) -> Arc<Reader> {
        let mut t = lock(&self.inner);
        let r = Arc::new(Reader::default());
        {
            let mut p = lock(&r.pending);
            p.dropped = t.printed - t.tail.len() as u64;
            p.data = t.tail.clone();
            p.ended = t.ended;
        }
        if !t.ended {
            t.readers.push(Arc::downgrade(&r));
        }
        r
    }
}

impl Reader {
    /// The next chunk to send, at most `max` bytes of data; waits until
    /// there is one.
    pub async fn next(&self, max: usize) -> Chunk {
        loop {
            {
                let mut p = lock(&self.pending);
                if p.dropped > 0 {
                    return Chunk::Gap(std::mem::take(&mut p.dropped));
                }
                if !p.data.is_empty() {
                    let n = p.data.len().min(max);
                    return Chunk::Data(p.data.drain(..n).collect());
                }
                if p.ended {
                    return Chunk::End;
                }
            }
            // A push in between left its permit: this does not miss it.
            self.more.notified().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn all(r: &Reader) -> Vec<Chunk> {
        let mut out = Vec::new();
        loop {
            let c = r.next(4).await;
            if c == Chunk::End {
                return out;
            }
            out.push(c);
        }
    }

    /// A stream opened late gets the tail, with what came before it as a
    /// gap, then the rest in order; one opened after the end gets the tail
    /// and its end.
    #[tokio::test]
    async fn a_stream_gets_the_tail_then_what_follows() {
        let t = Tap::default();
        t.push(&vec![b'a'; TAIL + 3]);
        let r = t.reader();
        t.push(b"xyz");
        t.end();
        let got = all(&r).await;
        assert_eq!(got[0], Chunk::Gap(3));
        let data: Vec<u8> = got[1..]
            .iter()
            .flat_map(|c| match c {
                Chunk::Data(d) => {
                    assert!(d.len() <= 4);
                    d.clone()
                }
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(data.len(), TAIL + 3);
        assert!(data.ends_with(b"aaxyz"));
        let late = t.reader();
        assert_eq!(late.next(TAIL).await, Chunk::Gap(6));
        assert!(matches!(late.next(TAIL).await, Chunk::Data(d) if d.ends_with(b"xyz")));
        assert_eq!(late.next(TAIL).await, Chunk::End);
    }

    /// A stream that does not keep up loses its oldest bytes and says how
    /// many; the command is never held up.
    #[tokio::test]
    async fn a_slow_stream_drops_its_oldest_bytes() {
        let t = Tap::default();
        let r = t.reader();
        t.push(&vec![b'a'; PENDING]);
        t.push(b"bc");
        assert_eq!(r.next(PENDING).await, Chunk::Gap(2));
        match r.next(PENDING).await {
            Chunk::Data(d) => {
                assert_eq!(d.len(), PENDING);
                assert!(d.ends_with(b"abc"));
            }
            other => panic!("{other:?}"),
        }
        // A closed stream is no longer fed.
        drop(r);
        t.push(b"d");
        assert!(lock(&t.inner).readers.is_empty());
    }
}
