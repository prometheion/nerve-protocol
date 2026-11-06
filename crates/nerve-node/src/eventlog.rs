//! The installed node's entries in the Windows Event Log: its start, its
//! stop, a start that fails and a crash (docs/dev/windows.md). The program
//! carries the message table that gives each entry its text: `build.rs`
//! links the resource [`resource`] makes into `nerve-node.exe`, and `install`
//! registers the program as the message file of the source [`SOURCE`] in the
//! Application log (crate::win_host). Without that the Event Viewer still
//! shows an entry, with a note that its description is missing.
//!
//! This file is plain std, so `build.rs` includes it as it is and the tests
//! check the resource on every platform; the writing itself is
//! crate::win_service.

/// The source the entries come from: the service's name.
pub const SOURCE: &str = "nerve-node";

/// Where the source is registered, below `HKEY_LOCAL_MACHINE`.
pub const SOURCE_KEY: &str =
    "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\nerve-node";

/// An entry the node makes, by its event id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The node runs; the entry says where its log is.
    Started = 1,
    /// The service stopped as asked.
    Stopped = 2,
    /// The node refused to start, or could not: the entry says why.
    NotStarted = 3,
    /// The node panicked, or stopped with an error after it ran.
    Crashed = 4,
}

impl Event {
    pub const ALL: [Event; 4] = [
        Event::Started,
        Event::Stopped,
        Event::NotStarted,
        Event::Crashed,
    ];

    pub fn id(self) -> u32 {
        self as u32
    }

    /// Whether the Event Log shows it as an error, else as information.
    pub fn is_error(self) -> bool {
        matches!(self, Event::NotStarted | Event::Crashed)
    }
}

/// The text of every event: the one string the node gives it.
const MESSAGE: &str = "%1\r\n";
/// `RT_MESSAGETABLE`.
const MESSAGE_TABLE: u16 = 11;
/// Language neutral, which `FormatMessage` tries first whatever the
/// language of Windows is.
const NEUTRAL: u16 = 0;

/// A `.res` file with one message table: [`MESSAGE`] for each id of
/// [`Event::ALL`], in Unicode. The file starts with the empty entry every
/// `.res` file has; each entry is a header of ordinals and its data, padded
/// to four bytes.
pub fn resource() -> Vec<u8> {
    let mut out = Vec::new();
    entry(&mut out, 0, 0, 0, &[]);
    entry(&mut out, MESSAGE_TABLE, 1, NEUTRAL, &message_table());
    out
}

/// `MESSAGE_RESOURCE_DATA`: one block over the ids, then one
/// `MESSAGE_RESOURCE_ENTRY` per id.
fn message_table() -> Vec<u8> {
    let ids: Vec<u32> = Event::ALL.iter().map(|e| e.id()).collect();
    let (low, high) = (ids[0], ids[ids.len() - 1]);
    // The block covers every id from low to high, one entry each.
    assert_eq!(ids, (low..=high).collect::<Vec<_>>());
    let mut out = Vec::new();
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&low.to_le_bytes());
    out.extend_from_slice(&high.to_le_bytes());
    // From the start of the data: the count and the one block.
    out.extend_from_slice(&16u32.to_le_bytes());
    let mut text: Vec<u8> = MESSAGE
        .encode_utf16()
        .chain(Some(0))
        .flat_map(u16::to_le_bytes)
        .collect();
    // An entry is its four bytes of length and flags, then the text, and
    // ends on four bytes.
    while !text.len().is_multiple_of(4) {
        text.push(0);
    }
    for _ in &ids {
        out.extend_from_slice(&((4 + text.len()) as u16).to_le_bytes());
        // Unicode.
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&text);
    }
    out
}

/// One resource of a `.res` file: its header with the type and the name as
/// ordinals, then `data`. The desktop app's build adds its icon with it.
pub fn entry(out: &mut Vec<u8>, kind: u16, name: u16, language: u16, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&32u32.to_le_bytes());
    for ordinal in [kind, name] {
        out.extend_from_slice(&0xFFFFu16.to_le_bytes());
        out.extend_from_slice(&ordinal.to_le_bytes());
    }
    // DataVersion, then MemoryFlags as rc.exe sets them (moveable, pure,
    // discardable) for a real resource.
    out.extend_from_slice(&0u32.to_le_bytes());
    let flags: u16 = if kind == 0 { 0 } else { 0x1030 };
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&language.to_le_bytes());
    // Version and Characteristics.
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(data);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u16_at(b: &[u8], at: usize) -> u16 {
        u16::from_le_bytes([b[at], b[at + 1]])
    }

    fn u32_at(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
    }

    /// The resource file Windows' linker takes: the empty entry, then a
    /// message table whose every id says `%1`, the string the node gives.
    #[test]
    fn the_resource_is_a_message_table_of_the_events() {
        let r = resource();
        assert_eq!(r.len() % 4, 0);
        // The empty entry: no data, a header of 32 bytes, ordinals 0.
        assert_eq!(u32_at(&r, 0), 0);
        assert_eq!(u32_at(&r, 4), 32);
        assert_eq!(&r[8..16], [0xFF, 0xFF, 0, 0, 0xFF, 0xFF, 0, 0]);
        let h = &r[32..];
        let size = u32_at(h, 0) as usize;
        assert_eq!(u32_at(h, 4), 32);
        assert_eq!((u16_at(h, 8), u16_at(h, 10)), (0xFFFF, MESSAGE_TABLE));
        assert_eq!((u16_at(h, 12), u16_at(h, 14)), (0xFFFF, 1));
        assert_eq!(u16_at(h, 22), NEUTRAL);
        let data = &h[32..32 + size];
        assert_eq!(32 + 32 + size.next_multiple_of(4), r.len());
        // One block from the first id to the last.
        assert_eq!(u32_at(data, 0), 1);
        assert_eq!(u32_at(data, 4), Event::Started.id());
        assert_eq!(u32_at(data, 8), Event::Crashed.id());
        let mut at = u32_at(data, 12) as usize;
        for e in Event::ALL {
            let len = u16_at(data, at) as usize;
            assert_eq!(len % 4, 0, "{e:?}");
            assert_eq!(u16_at(data, at + 2), 1, "{e:?} is in Unicode");
            let text: Vec<u16> = data[at + 4..at + len]
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&c| c != 0)
                .collect();
            assert_eq!(String::from_utf16(&text).unwrap(), "%1\r\n", "{e:?}");
            at += len;
        }
        assert_eq!(at, data.len());
    }

    #[test]
    fn the_events_have_ids_and_kinds() {
        let ids: Vec<u32> = Event::ALL.iter().map(|e| e.id()).collect();
        assert_eq!(ids, [1, 2, 3, 4]);
        let errors: Vec<Event> = Event::ALL.into_iter().filter(|e| e.is_error()).collect();
        assert_eq!(errors, [Event::NotStarted, Event::Crashed]);
        assert_eq!(SOURCE, crate::winsvc::SERVICE_NAME);
        assert!(SOURCE_KEY.ends_with(&format!("\\Application\\{SOURCE}")));
    }
}
