//! Binary frames (docs/dev/spec/protocol.md §5.4):
//! `u8 kind | u8 flags | u32 id | u32 seq | payload`, big-endian, payload at
//! most 64 KiB.

/// Header length in bytes.
pub const HEADER: usize = 10;
/// The largest payload one frame carries.
pub const MAX_PAYLOAD: usize = 64 * 1024;

/// Flag bit 0 on a blob chunk: this is the blob's last chunk.
pub const FLAG_LAST: u8 = 1;
/// Flag bit 1 on a stream frame: the sender dropped bytes of the stream here,
/// because the other side did not take them fast enough. The payload is
/// their count, a big-endian `u64`, and carries no data.
pub const FLAG_GAP: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A chunk of a blob an argument or result references as `{"$blob": id}`.
    Blob = 1,
    /// Data of a reliable stream (`id` = stream id).
    Stream = 2,
    /// Reserved for media streams; refused.
    Media = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: Kind,
    pub flags: u8,
    pub id: u32,
    pub seq: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    Short,
    UnknownKind(u8),
    /// Kind 3 is reserved and not accepted.
    MediaReserved,
    TooLarge(usize),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Short => write!(f, "binary frame shorter than its header"),
            FrameError::UnknownKind(k) => write!(f, "unknown binary frame kind {k}"),
            FrameError::MediaReserved => write!(f, "media frames are not supported"),
            FrameError::TooLarge(n) => write!(f, "binary frame payload of {n} bytes over 64 KiB"),
        }
    }
}

impl std::error::Error for FrameError {}

impl Frame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.payload.len() > MAX_PAYLOAD {
            return Err(FrameError::TooLarge(self.payload.len()));
        }
        let mut b = Vec::with_capacity(HEADER + self.payload.len());
        b.push(self.kind as u8);
        b.push(self.flags);
        b.extend_from_slice(&self.id.to_be_bytes());
        b.extend_from_slice(&self.seq.to_be_bytes());
        b.extend_from_slice(&self.payload);
        Ok(b)
    }

    pub fn decode(b: &[u8]) -> Result<Frame, FrameError> {
        if b.len() < HEADER {
            return Err(FrameError::Short);
        }
        let kind = match b[0] {
            1 => Kind::Blob,
            2 => Kind::Stream,
            3 => return Err(FrameError::MediaReserved),
            k => return Err(FrameError::UnknownKind(k)),
        };
        let payload = &b[HEADER..];
        if payload.len() > MAX_PAYLOAD {
            return Err(FrameError::TooLarge(payload.len()));
        }
        Ok(Frame {
            kind,
            flags: b[1],
            id: u32::from_be_bytes([b[2], b[3], b[4], b[5]]),
            seq: u32::from_be_bytes([b[6], b[7], b[8], b[9]]),
            payload: payload.to_vec(),
        })
    }

    pub fn last(&self) -> bool {
        self.flags & FLAG_LAST != 0
    }

    /// A stream frame that says `n` bytes of stream `sid` were dropped
    /// before the frame `seq`.
    pub fn gap(sid: u32, seq: u32, n: u64) -> Frame {
        Frame {
            kind: Kind::Stream,
            flags: FLAG_GAP,
            id: sid,
            seq,
            payload: n.to_be_bytes().to_vec(),
        }
    }

    /// The bytes a gap frame says were dropped; none for any other frame.
    pub fn gap_bytes(&self) -> Option<u64> {
        if self.kind != Kind::Stream || self.flags & FLAG_GAP == 0 {
            return None;
        }
        Some(u64::from_be_bytes(self.payload.as_slice().try_into().ok()?))
    }
}

/// A stream frame with `data` (at most [`MAX_PAYLOAD`] bytes) of stream
/// `sid`, the `seq`th frame of it.
pub fn stream_frame(sid: u32, seq: u32, data: Vec<u8>) -> Frame {
    Frame {
        kind: Kind::Stream,
        flags: 0,
        id: sid,
        seq,
        payload: data,
    }
}

/// Splits a blob into chunk frames, the last one flagged.
pub fn blob_frames(id: u32, data: &[u8]) -> Vec<Frame> {
    let chunks: Vec<&[u8]> = if data.is_empty() {
        vec![&[]]
    } else {
        data.chunks(MAX_PAYLOAD).collect()
    };
    let n = chunks.len();
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, c)| Frame {
            kind: Kind::Blob,
            flags: if i + 1 == n { FLAG_LAST } else { 0 },
            id,
            seq: i as u32,
            payload: c.to_vec(),
        })
        .collect()
}

/// Reassembles one blob from its frames, checking order and the size cap.
#[derive(Debug, Default)]
pub struct BlobAssembler {
    next: u32,
    data: Vec<u8>,
    done: bool,
}

impl BlobAssembler {
    /// Adds a chunk. `Ok(true)` once the last chunk arrived.
    pub fn push(&mut self, f: &Frame, cap: u64) -> Result<bool, String> {
        if self.done {
            return Err("chunk after the blob's last one".into());
        }
        if f.seq != self.next {
            return Err(format!("blob chunk {} where {} was due", f.seq, self.next));
        }
        if (self.data.len() + f.payload.len()) as u64 > cap {
            return Err("blob over the size limit".into());
        }
        self.next += 1;
        self.data.extend_from_slice(&f.payload);
        self.done = f.last();
        Ok(self.done)
    }

    pub fn into_data(self) -> Vec<u8> {
        self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let f = Frame {
            kind: Kind::Stream,
            flags: 0,
            id: 0x01020304,
            seq: 9,
            payload: b"abc".to_vec(),
        };
        let b = f.encode().unwrap();
        assert_eq!(&b[..HEADER], &[2, 0, 1, 2, 3, 4, 0, 0, 0, 9]);
        assert_eq!(Frame::decode(&b).unwrap(), f);
    }

    #[test]
    fn refuses() {
        assert_eq!(Frame::decode(&[1, 0, 0]), Err(FrameError::Short));
        assert_eq!(
            Frame::decode(&[3, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(FrameError::MediaReserved)
        );
        assert_eq!(
            Frame::decode(&[9, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(FrameError::UnknownKind(9))
        );
        let big = vec![0u8; HEADER + MAX_PAYLOAD + 1];
        let mut big = big;
        big[0] = 1;
        assert!(matches!(Frame::decode(&big), Err(FrameError::TooLarge(_))));
    }

    /// A gap frame says how many bytes went; a data frame is no gap.
    #[test]
    fn stream_gaps() {
        let g = Frame::decode(&Frame::gap(5, 2, 70_000).encode().unwrap()).unwrap();
        assert_eq!((g.id, g.seq, g.gap_bytes()), (5, 2, Some(70_000)));
        // Eight bytes of data are data, not a count.
        assert_eq!(stream_frame(5, 3, b"8 bytes!".to_vec()).gap_bytes(), None);
        let mut short = Frame::gap(5, 2, 1);
        short.payload.pop();
        assert_eq!(short.gap_bytes(), None);
    }

    #[test]
    fn blobs() {
        let data = vec![7u8; MAX_PAYLOAD * 2 + 5];
        let frames = blob_frames(4, &data);
        assert_eq!(frames.len(), 3);
        assert!(frames[2].last() && !frames[0].last());
        let mut a = BlobAssembler::default();
        for (i, f) in frames.iter().enumerate() {
            assert_eq!(a.push(f, 1 << 20).unwrap(), i == 2);
        }
        assert_eq!(a.into_data(), data);
        let mut small = BlobAssembler::default();
        assert!(small.push(&frames[0], 10).is_err());
        let mut order = BlobAssembler::default();
        assert!(order.push(&frames[1], 1 << 20).is_err());
        assert_eq!(blob_frames(1, &[]).len(), 1);
    }
}
