//! The output of a running command for its `output` stream
//! (docs/dev/spec/protocol.md §7.3): what it printed lately, and what it
//! prints from now on, for each stream open on it.
//!
//! The command never waits for a stream. Its output is read as fast as it
//! comes ([`crate::exec`] drains its pipes whatever happens); a stream that
//! cannot keep up loses its oldest bytes and says how many
//! ([`Chunk::Gap`]), and its result still holds the output as before.
//!
//! What a stream carries is the text the result would hold: on Windows
//! output that is not UTF-8 is read in the console's code page, and every
//! copy of the sudo password the node holds is replaced, as in any frame
//! (crate::sudo). Both work on what each pipe printed, across its reads: a
//! character or a copy that a read cut waits for the next one. The password
//! is replaced once more as a stream sends, with the one the node holds
//! then, as text frames are: output kept for a stream may have been printed
//! before sudo was turned on.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, Weak};

use tokio::sync::Notify;

use crate::daemon::lock;
use crate::sudo::{REDACTED, Secret};

/// What a stream opened on a running command gets first: the end of what
/// the command printed so far.
pub const TAIL: usize = 64 * 1024;
/// The most a stream holds that the link has not sent yet; past it the
/// oldest bytes go.
pub const PENDING: usize = 1024 * 1024;

/// The pipe a command printed on.
#[derive(Clone, Copy, Debug)]
pub enum Pipe {
    Out = 0,
    Err = 1,
}

/// Reads output that is not UTF-8, as the command's result does: the
/// console code page on Windows (crate::exec::other_text).
#[derive(Clone, Copy)]
pub struct Decode {
    /// The text of whole characters.
    pub text: fn(&[u8]) -> Option<String>,
    /// How many bytes at the end start a character they do not finish: a
    /// lead byte of a double-byte code page, whose second byte the pipe's
    /// next read brings.
    pub cut: fn(&[u8]) -> usize,
}

impl Decode {
    /// `b` as UTF-8 text; what the code page does not read is replaced.
    fn read(&self, b: &[u8]) -> Vec<u8> {
        (self.text)(b)
            .unwrap_or_else(|| String::from_utf8_lossy(b).into_owned())
            .into_bytes()
    }

    /// The end of `b` that starts a character it does not finish, cut off.
    fn cut_off(&self, b: &mut Vec<u8>) -> Vec<u8> {
        let n = (self.cut)(b).min(b.len());
        b.split_off(b.len() - n)
    }
}

/// Gives the sudo password the node holds now.
pub(crate) type Held = Arc<dyn Fn() -> Option<Secret> + Send + Sync>;

/// One running command's output, stdout and stderr in the order the node
/// read them, as text the way its result reads it and without the sudo
/// password the node holds.
#[derive(Default)]
pub struct Tap {
    inner: Mutex<Inner>,
    secret: Option<Held>,
    other: Option<Decode>,
}

#[derive(Default)]
struct Inner {
    tail: VecDeque<u8>,
    printed: u64,
    readers: Vec<Weak<Reader>>,
    ended: bool,
    pipes: [Carry; 2],
}

/// What a pipe's last read left for its next one.
#[derive(Default)]
struct Carry {
    /// The start of a character the read cut off.
    raw: Vec<u8>,
    /// Text that may be the start of a copy of the password.
    held: Vec<u8>,
    /// Whether the pipe prints in the code page (`Some(true)`) or UTF-8,
    /// once a read told them apart; each pipe on its own, as the result
    /// reads them.
    code_page: Option<bool>,
}

/// One stream's view of a [`Tap`]: what it still has to send.
#[derive(Default)]
pub struct Reader {
    pending: Mutex<Pending>,
    more: Notify,
    secret: Option<Held>,
}

#[derive(Default)]
struct Pending {
    data: VecDeque<u8>,
    dropped: u64,
    ended: bool,
    /// Taken from `data` and scrubbed, to go next.
    ready: VecDeque<u8>,
    /// Taken from `data`, and maybe the start of a copy of the password:
    /// it waits for what follows.
    held: Vec<u8>,
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

/// Drops the bytes of a character whose start was cut off; how many.
fn skip_cut(b: &mut VecDeque<u8>) -> u64 {
    let mut n = 0;
    while n < 3 && b.front().is_some_and(|c| (0x80..0xC0).contains(c)) {
        b.pop_front();
        n += 1;
    }
    n
}

/// The end of `b` that starts a character it does not finish, cut off.
fn cut_char(b: &mut Vec<u8>) -> Vec<u8> {
    match std::str::from_utf8(b) {
        Err(e) if e.error_len().is_none() => b.split_off(e.valid_up_to()),
        _ => Vec::new(),
    }
}

/// `text`, after what `held` kept of the text before it, without any copy
/// in `copies`. Text at its end that may start a copy is kept in `held` for
/// what follows, unless this is the `last` of it.
fn scrub_held(held: &mut Vec<u8>, text: Vec<u8>, copies: &[String], last: bool) -> Vec<u8> {
    let mut data = std::mem::take(held);
    data.extend(text);
    for c in copies {
        data = replace(&data, c.as_bytes(), REDACTED.as_bytes());
    }
    if !last {
        let starts = |k: usize| {
            copies
                .iter()
                .any(|c| k < c.len() && c.as_bytes().starts_with(&data[data.len() - k..]))
        };
        let most = copies.iter().map(String::len).max().unwrap_or(1) - 1;
        if let Some(k) = (1..=most.min(data.len())).rev().find(|&k| starts(k)) {
            *held = data.split_off(data.len() - k);
        }
    }
    data
}

fn replace(hay: &[u8], needle: &[u8], with: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(hay.len());
    let mut i = 0;
    while i < hay.len() {
        if hay[i..].starts_with(needle) {
            out.extend_from_slice(with);
            i += needle.len();
        } else {
            out.push(hay[i]);
            i += 1;
        }
    }
    out
}

impl Pending {
    fn push(&mut self, b: &[u8]) {
        self.data.extend(b);
        let over = self.data.len().saturating_sub(PENDING);
        if over > 0 {
            self.data.drain(..over);
            self.dropped += over as u64 + skip_cut(&mut self.data);
        }
    }

    /// The next chunk of at most `max` bytes, without any copy in `copies`;
    /// none while there is nothing to send. What was taken from `data`
    /// before a gap goes before it.
    fn take(&mut self, max: usize, copies: &[String]) -> Option<Chunk> {
        loop {
            if !self.ready.is_empty() {
                let n = self.ready.len().min(max);
                return Some(Chunk::Data(self.ready.drain(..n).collect()));
            }
            let flush = self.dropped > 0 || (self.data.is_empty() && self.ended);
            if flush && !self.held.is_empty() {
                // What it waited for was dropped, or never comes.
                let out = scrub_held(&mut self.held, Vec::new(), copies, true);
                self.ready.extend(out);
                continue;
            }
            if self.dropped > 0 {
                return Some(Chunk::Gap(std::mem::take(&mut self.dropped)));
            }
            if !self.data.is_empty() {
                let n = self.data.len().min(max);
                let text: Vec<u8> = self.data.drain(..n).collect();
                let last = self.data.is_empty() && self.ended;
                let out = scrub_held(&mut self.held, text, copies, last);
                self.ready.extend(out);
                continue;
            }
            return self.ended.then_some(Chunk::End);
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

impl Inner {
    /// `b`, read from `pipe`, as text the way the result reads it: UTF-8,
    /// or with `other` once the output proved not to be UTF-8. A character
    /// the read cut off waits for the pipe's next read, so a chunk never
    /// starts inside one.
    fn text(&mut self, pipe: Pipe, b: &[u8], other: Option<Decode>) -> Vec<u8> {
        let carry = &mut self.pipes[pipe as usize];
        let mut data = std::mem::take(&mut carry.raw);
        data.extend_from_slice(b);
        let Some(other) = other else {
            // Elsewhere the bytes go as they are.
            carry.raw = cut_char(&mut data);
            return data;
        };
        if carry.code_page == Some(true) {
            carry.raw = other.cut_off(&mut data);
            return other.read(&data);
        }
        match std::str::from_utf8(&data) {
            Err(e) if e.error_len().is_some() => {
                if carry.code_page == Some(false) {
                    return String::from_utf8_lossy(&data).into_owned().into_bytes();
                }
                carry.code_page = Some(true);
                carry.raw = other.cut_off(&mut data);
                other.read(&data)
            }
            _ => {
                carry.raw = cut_char(&mut data);
                if !data.is_ascii() {
                    carry.code_page = Some(false);
                }
                data
            }
        }
    }

    /// `text` of `pipe` without any copy of `secret`. Text that may start a
    /// copy waits for the pipe's next read, unless it is the `last`.
    fn scrub(&mut self, pipe: Pipe, text: Vec<u8>, secret: Option<&Secret>, last: bool) -> Vec<u8> {
        let copies = secret.map_or_else(Vec::new, |s| crate::sudo::copies(s.expose()));
        scrub_held(&mut self.pipes[pipe as usize].held, text, &copies, last)
    }

    /// The command printed `b` (text, scrubbed).
    fn emit(&mut self, b: &[u8]) {
        if b.is_empty() {
            return;
        }
        self.printed += b.len() as u64;
        self.tail.extend(b);
        let over = self.tail.len().saturating_sub(TAIL);
        if over > 0 {
            self.tail.drain(..over);
            // A late stream starts at a whole character.
            skip_cut(&mut self.tail);
        }
        // A stream that was closed is gone from here too.
        self.readers.retain(|r| match r.upgrade() {
            Some(r) => {
                lock(&r.pending).push(b);
                r.more.notify_one();
                true
            }
            None => false,
        });
    }
}

impl Tap {
    /// A tap that keeps what `secret` gives out of the stream and reads
    /// output that is not UTF-8 with `other`.
    pub(crate) fn new(secret: Option<Held>, other: Option<Decode>) -> Tap {
        Tap {
            inner: Mutex::default(),
            secret,
            other,
        }
    }

    fn secret(&self) -> Option<Secret> {
        self.secret.as_ref().and_then(|f| f())
    }

    /// The command printed `b` on `pipe`.
    pub fn push(&self, pipe: Pipe, b: &[u8]) {
        if b.is_empty() {
            return;
        }
        // Taken before the tap's lock: the password has its own.
        let secret = self.secret();
        let mut t = lock(&self.inner);
        if t.ended {
            return;
        }
        let text = t.text(pipe, b, self.other);
        let out = t.scrub(pipe, text, secret.as_ref(), false);
        t.emit(&out);
    }

    /// The command ended: what its pipes left goes out, and its streams end
    /// once they sent the rest.
    pub fn end(&self) {
        let secret = self.secret();
        let mut t = lock(&self.inner);
        if t.ended {
            return;
        }
        for pipe in [Pipe::Out, Pipe::Err] {
            let carry = &mut t.pipes[pipe as usize];
            let mut raw = std::mem::take(&mut carry.raw);
            if let Some(other) = self
                .other
                .filter(|_| carry.code_page == Some(true) && !raw.is_empty())
            {
                raw = other.read(&raw);
            }
            let out = t.scrub(pipe, raw, secret.as_ref(), true);
            t.emit(&out);
        }
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
        let r = Arc::new(Reader {
            secret: self.secret.clone(),
            ..Reader::default()
        });
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
    /// The next chunk to send, at most `max` bytes of data, without the
    /// sudo password the node holds now; waits until there is one.
    pub async fn next(&self, max: usize) -> Chunk {
        loop {
            // Taken before the stream's lock: the password has its own.
            let secret = self.secret.as_ref().and_then(|f| f());
            let copies = secret.map_or_else(Vec::new, |s| crate::sudo::copies(s.expose()));
            if let Some(c) = lock(&self.pending).take(max, &copies) {
                return c;
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
        t.push(Pipe::Out, &vec![b'a'; TAIL + 3]);
        let r = t.reader();
        t.push(Pipe::Err, b"xyz");
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
        t.push(Pipe::Out, &vec![b'a'; PENDING]);
        t.push(Pipe::Out, b"bc");
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
        t.push(Pipe::Out, b"d");
        assert!(lock(&t.inner).readers.is_empty());
    }

    /// Everything a stream sends until its end: the bytes dropped, and the
    /// data as text (it must be UTF-8).
    async fn text_of(r: &Reader) -> (u64, String) {
        let (mut gap, mut data) = (0, Vec::new());
        loop {
            match r.next(PENDING).await {
                Chunk::Data(d) => data.extend(d),
                Chunk::Gap(n) => gap += n,
                Chunk::End => return (gap, String::from_utf8(data).unwrap()),
            }
        }
    }

    const PW: &str = "pw-7c1e\"x";

    fn with_password() -> Tap {
        Tap::new(Some(Arc::new(|| Some(Secret::new(PW.into())))), None)
    }

    /// No copy of the sudo password goes out, also not one that two reads
    /// cut, nor its JSON-escaped form; text that only starts like it waits
    /// for the next read and then goes as it is.
    #[tokio::test]
    async fn the_password_never_streams() {
        let t = with_password();
        let r = t.reader();
        t.push(Pipe::Out, b"a pw-7");
        t.push(Pipe::Err, b"err\n");
        t.push(Pipe::Out, b"c1e\"x b\n");
        t.push(Pipe::Out, b"esc pw-7c1e\\\"x\n");
        t.push(Pipe::Out, b"pw-");
        assert_eq!(lock(&t.inner).pipes[0].held, b"pw-", "a start of it waits");
        t.push(Pipe::Out, b"no\n");
        t.push(Pipe::Err, b"last pw-7c");
        t.end();
        let (_, text) = text_of(&r).await;
        assert_eq!(
            text,
            "a err\n[redacted] b\nesc [redacted]\npw-no\nlast pw-7c"
        );
        // The tail a late stream gets is scrubbed too.
        let (_, late) = text_of(&t.reader()).await;
        assert!(!late.contains(PW) && late.contains("[redacted]"), "{late}");
    }

    /// A password the node holds only after the command printed it does not
    /// go either: not in the tail a later stream starts with, nor in what
    /// waited for a slow stream, also where the stream's chunks cut it.
    #[tokio::test]
    async fn a_password_held_later_never_streams() {
        let pw: Arc<Mutex<Option<&str>>> = Arc::default();
        let now = pw.clone();
        let t = Tap::new(
            Some(Arc::new(move || lock(&now).map(|p| Secret::new(p.into())))),
            None,
        );
        let early = t.reader();
        t.push(Pipe::Out, b"history: echo pw-7c1e\"x | sudo -S id\n");
        *lock(&pw) = Some(PW);
        let late = t.reader();
        t.push(Pipe::Out, b"more\n");
        t.end();
        // Small chunks cut the copy: its start waits for the rest.
        let mut text = Vec::new();
        loop {
            match early.next(4).await {
                Chunk::Data(d) => {
                    assert!(d.len() <= 4);
                    text.extend(d);
                }
                Chunk::Gap(n) => panic!("gap {n}"),
                Chunk::End => break,
            }
        }
        let text = String::from_utf8(text).unwrap();
        assert_eq!(text, "history: echo [redacted] | sudo -S id\nmore\n");
        let (_, text) = text_of(&late).await;
        assert_eq!(text, "history: echo [redacted] | sudo -S id\nmore\n");
    }

    /// Each pipe is read in its own encoding, as the result reads it: one
    /// pipe in the code page leaves the other's UTF-8 as it is, and the
    /// other way round.
    #[tokio::test]
    async fn each_pipe_keeps_its_own_encoding() {
        let latin1 = LATIN1;
        let t = Tap::new(None, Some(latin1));
        let r = t.reader();
        t.push(Pipe::Err, b"ausf\xFChrbaren\n");
        t.push(Pipe::Out, "Müller ✓\n".as_bytes());
        t.push(Pipe::Err, b"Gr\xF6\xDFe\n");
        t.push(Pipe::Out, "Größe\n".as_bytes());
        t.end();
        assert_eq!(
            text_of(&r).await,
            (0, "ausführbaren\nMüller ✓\nGröße\nGröße\n".into())
        );
    }

    /// A character a read cuts waits for the rest from the same pipe; on a
    /// platform with a code page, output that is not UTF-8 is read in it
    /// from then on, and UTF-8 output stays UTF-8 whatever its reads cut.
    #[tokio::test]
    async fn characters_stay_whole_and_a_code_page_is_read() {
        let latin1 = LATIN1;
        let t = Tap::new(None, Some(latin1));
        let r = t.reader();
        t.push(Pipe::Out, b"Gr\xC3");
        t.push(Pipe::Err, b"x");
        t.push(Pipe::Out, b"\xBC\xC3");
        t.push(Pipe::Out, b"\x9Fe\n");
        t.end();
        assert_eq!(text_of(&r).await, (0, "Grxüße\n".into()));

        let t = Tap::new(None, Some(latin1));
        let r = t.reader();
        t.push(Pipe::Out, b"ok ");
        t.push(Pipe::Out, b"Gr\xFC\xDFe ");
        t.push(Pipe::Out, b"\xC3\xBC\n");
        t.end();
        assert_eq!(text_of(&r).await, (0, "ok Grüße Ã¼\n".into()));

        // Without a code page the bytes go as they are, a cut character
        // whole.
        let t = Tap::default();
        let r = t.reader();
        t.push(Pipe::Out, b"\xE2\x9C");
        t.push(Pipe::Out, b"\x93 \xFF");
        t.end();
        let mut got = Vec::new();
        while let Chunk::Data(d) = r.next(PENDING).await {
            assert!(!d.starts_with(b"\x93"), "{d:?}");
            got.extend(d);
        }
        assert_eq!(got, b"\xE2\x9C\x93 \xFF");
    }

    /// A stand-in for a single-byte code page.
    const LATIN1: Decode = Decode {
        text: |b| Some(b.iter().map(|&c| char::from(c)).collect()),
        cut: |_| 0,
    };

    /// A stand-in for a double-byte code page: a byte from 0x81 is the lead
    /// of a pair, read as one character.
    const PAIRS: Decode = Decode {
        text: |b| {
            let mut out = String::new();
            let mut i = 0;
            while i < b.len() {
                if b[i] >= 0x81 {
                    let trail = b.get(i + 1).copied()?;
                    out.push(char::from_u32(0x3000 + u32::from(trail)).unwrap());
                    i += 2;
                } else {
                    out.push(char::from(b[i]));
                    i += 1;
                }
            }
            Some(out)
        },
        cut: |b| {
            let mut i = 0;
            while i < b.len() {
                if b[i] >= 0x81 && i + 1 == b.len() {
                    return 1;
                }
                i += if b[i] >= 0x81 { 2 } else { 1 };
            }
            0
        },
    };

    /// In a double-byte code page, a character whose lead byte ends a read
    /// waits for its second byte from the pipe's next read, as the result
    /// reads it whole; a lead byte the command never finished goes at the
    /// end, read as the code page reads it.
    #[tokio::test]
    async fn a_double_byte_character_a_read_cuts_stays_whole() {
        let t = Tap::new(None, Some(PAIRS));
        let r = t.reader();
        t.push(Pipe::Out, b"\x82\x41a\x82");
        t.push(Pipe::Err, b"e\n");
        t.push(Pipe::Out, b"\x42b\n\x83");
        t.end();
        assert_eq!(
            text_of(&r).await,
            (0, "\u{3041}ae\n\u{3042}b\n\u{fffd}".into())
        );
    }

    /// A late stream whose tail would start inside a character starts at
    /// the next one, and counts the bytes before it as dropped.
    #[tokio::test]
    async fn a_late_stream_starts_at_a_whole_character() {
        let t = Tap::default();
        t.push(Pipe::Out, "ä".repeat(TAIL / 2).as_bytes());
        t.push(Pipe::Out, b"x");
        t.end();
        let (gap, text) = text_of(&t.reader()).await;
        assert_eq!(gap, 2);
        assert_eq!(text, format!("{}x", "ä".repeat(TAIL / 2 - 1)));
    }
}
