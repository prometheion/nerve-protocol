//! A secret the owner copies (a harness token, the Claude Code line, a
//! pairing link with its code) leaves the clipboard after a minute, while
//! the clipboard still holds it (design of #232, section 7). On Windows the
//! copy is also marked for no clipboard history, no cloud clipboard and no
//! clipboard monitors.

use std::time::Duration;

/// How long a copied secret stays.
pub const KEEP: Duration = Duration::from_secs(60);

/// What a copy left, so that its clearing knows whether the clipboard
/// still holds it: Windows' clipboard sequence number, else the text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mark {
    Sequence(u32),
    Text(String),
}

/// Puts `text` on the clipboard as a secret.
pub fn copy(window: &slint::Window, text: &str) -> Result<Mark, String> {
    #[cfg(windows)]
    if !crate::headless::is_headless() {
        return win::copy(text).map(Mark::Sequence);
    }
    platform_set(window, text);
    Ok(Mark::Text(text.to_string()))
}

/// Clears the clipboard if it still holds the copy `mark` left; says
/// whether it did.
pub fn clear_if_still(window: &slint::Window, mark: &Mark) -> bool {
    match mark {
        #[cfg(windows)]
        Mark::Sequence(n) => win::clear_if(*n),
        #[cfg(not(windows))]
        Mark::Sequence(_) => false,
        Mark::Text(t) => {
            if platform_get(window).as_deref() == Some(t.as_str()) {
                platform_set(window, "");
                true
            } else {
                false
            }
        }
    }
}

/// What the clipboard holds now, as the window's platform says.
pub fn text(window: &slint::Window) -> Option<String> {
    platform_get(window)
}

// Slint has no public call for the clipboard: a text field's Copy reaches
// the platform's clipboard through the window's context, and so does this,
// with the platform Slint runs on (the winit backend on Linux, the headless
// one in tests). Its API is the one of the Slint version in Cargo.lock.
fn platform_set(window: &slint::Window, text: &str) {
    use slint::platform::Clipboard;
    slint::private_unstable_api::re_exports::WindowInner::from_pub(window)
        .context()
        .platform()
        .set_clipboard_text(text, Clipboard::DefaultClipboard);
}

fn platform_get(window: &slint::Window) -> Option<String> {
    use slint::platform::Clipboard;
    slint::private_unstable_api::re_exports::WindowInner::from_pub(window)
        .context()
        .platform()
        .clipboard_text(Clipboard::DefaultClipboard)
}

/// The formats that keep a copy out of the clipboard history, the cloud
/// clipboard and the programs that watch the clipboard, each with its
/// value.
const MARKS: [(&str, u32); 3] = [
    ("ExcludeClipboardContentFromMonitorProcessing", 0),
    ("CanIncludeInClipboardHistory", 0),
    ("CanUploadToCloudClipboard", 0),
];

/// Windows' format of text (CF_UNICODETEXT).
const UNICODE_TEXT: u32 = 13;

/// What a marked copy needs of an open clipboard: Windows', or a test's.
trait Board {
    fn empty(&mut self) -> Result<(), String>;
    /// The format a name registers as; 0 where it did not.
    fn register(&mut self, name: &str) -> u32;
    fn put(&mut self, format: u32, bytes: &[u8]) -> Result<(), String>;
    /// The clipboard's sequence number, which every change raises.
    fn sequence(&self) -> u32;
}

/// Puts `text` on `board` with every mark. The marks go first, and where
/// one cannot be put the clipboard is emptied: a secret is never left
/// there without them, for the history and the cloud to take.
#[cfg_attr(not(windows), allow(dead_code))]
fn put_marked(board: &mut dyn Board, text: &str) -> Result<(), String> {
    board.empty()?;
    let mut put = || {
        for (name, value) in MARKS {
            let format = board.register(name);
            if format == 0 {
                return Err(format!(
                    "cannot keep the copy out of the clipboard history: {name} is not known here"
                ));
            }
            board.put(format, &value.to_le_bytes())?;
        }
        let units: Vec<u8> = text
            .encode_utf16()
            .chain(Some(0))
            .flat_map(|u| u.to_le_bytes())
            .collect();
        board.put(UNICODE_TEXT, &units)
    };
    let done = put();
    if done.is_err() {
        let _ = board.empty();
    }
    done
}

/// Empties `board` if nothing was copied since `sequence`.
#[cfg_attr(not(windows), allow(dead_code))]
fn clear_board_if(board: &mut dyn Board, sequence: u32) -> bool {
    board.sequence() == sequence && board.empty().is_ok()
}

#[cfg(windows)]
mod win {
    use windows_sys::Win32::Foundation::{GlobalFree, HANDLE};
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardSequenceNumber, OpenClipboard,
        RegisterClipboardFormatW, SetClipboardData,
    };
    use windows_sys::Win32::System::Memory::{
        GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock,
    };

    use super::Board;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    /// The clipboard, opened for this thread; another program may hold it
    /// for a moment.
    struct Open;

    impl Open {
        fn new() -> Result<Open, String> {
            for _ in 0..20 {
                // SAFETY: no window; the clipboard is this thread's until
                // CloseClipboard.
                if unsafe { OpenClipboard(std::ptr::null_mut()) } != 0 {
                    return Ok(Open);
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err("another program holds the clipboard".into())
        }
    }

    impl Drop for Open {
        fn drop(&mut self) {
            // SAFETY: opened by Open::new on this thread.
            unsafe { CloseClipboard() };
        }
    }

    impl Board for Open {
        fn empty(&mut self) -> Result<(), String> {
            // SAFETY: the clipboard is open.
            if unsafe { EmptyClipboard() } == 0 {
                return Err(format!(
                    "cannot empty the clipboard: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(())
        }

        fn register(&mut self, name: &str) -> u32 {
            // SAFETY: a NUL-terminated name.
            unsafe { RegisterClipboardFormatW(wide(name).as_ptr()) }
        }

        fn put(&mut self, format: u32, bytes: &[u8]) -> Result<(), String> {
            let h = global(bytes)?;
            // SAFETY: the clipboard is open and emptied by this thread; on
            // success the system owns the block.
            if unsafe { SetClipboardData(format, h) }.is_null() {
                // SAFETY: the block was not taken.
                unsafe { GlobalFree(h) };
                return Err(format!(
                    "cannot put on the clipboard: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(())
        }

        fn sequence(&self) -> u32 {
            // SAFETY: no arguments.
            unsafe { GetClipboardSequenceNumber() }
        }
    }

    /// A moveable global block holding `bytes`, for SetClipboardData.
    fn global(bytes: &[u8]) -> Result<HANDLE, String> {
        // SAFETY: a fresh block of the size asked, filled before it is
        // unlocked; the clipboard owns it once SetClipboardData took it.
        unsafe {
            let h = GlobalAlloc(GMEM_MOVEABLE, bytes.len().max(1));
            if h.is_null() {
                return Err("out of memory for the clipboard".into());
            }
            let p = GlobalLock(h) as *mut u8;
            if p.is_null() {
                GlobalFree(h);
                return Err("cannot fill the clipboard".into());
            }
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
            GlobalUnlock(h);
            Ok(h)
        }
    }

    /// Copies `text` with the marks; the clipboard's sequence number after
    /// it is closed.
    pub fn copy(text: &str) -> Result<u32, String> {
        let mut open = Open::new()?;
        super::put_marked(&mut open, text)?;
        drop(open);
        // SAFETY: no arguments.
        Ok(unsafe { GetClipboardSequenceNumber() })
    }

    /// Empties the clipboard if nothing was copied since `sequence`.
    pub fn clear_if(sequence: u32) -> bool {
        let Ok(mut open) = Open::new() else {
            return false;
        };
        super::clear_board_if(&mut open, sequence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// A clipboard in memory, its formats by number, that fails where told.
    #[derive(Default)]
    struct Fake {
        held: BTreeMap<u32, Vec<u8>>,
        names: Vec<String>,
        sequence: u32,
        unknown: Option<&'static str>,
        refuses: Option<u32>,
    }

    impl Board for Fake {
        fn empty(&mut self) -> Result<(), String> {
            self.held.clear();
            self.sequence += 1;
            Ok(())
        }

        fn register(&mut self, name: &str) -> u32 {
            if self.unknown == Some(name) {
                return 0;
            }
            if !self.names.iter().any(|n| n == name) {
                self.names.push(name.into());
            }
            0xC000 + self.names.iter().position(|n| n == name).unwrap() as u32
        }

        fn put(&mut self, format: u32, bytes: &[u8]) -> Result<(), String> {
            if self.refuses == Some(format) {
                return Err("refused".into());
            }
            self.held.insert(format, bytes.to_vec());
            self.sequence += 1;
            Ok(())
        }

        fn sequence(&self) -> u32 {
            self.sequence
        }
    }

    /// A copied secret carries the three marks that keep it out of the
    /// clipboard history, the cloud clipboard and the watching programs,
    /// each 0; where one cannot be put, nothing stays on the clipboard.
    #[test]
    fn a_secret_goes_on_the_clipboard_with_its_marks_or_not_at_all() {
        let mut b = Fake::default();
        b.held.insert(UNICODE_TEXT, b"earlier".to_vec());
        put_marked(&mut b, "nrv_secret").unwrap();
        assert_eq!(b.names, MARKS.map(|(n, _)| n.to_string()));
        for i in 0..3 {
            assert_eq!(b.held[&(0xC000 + i)], 0u32.to_le_bytes());
        }
        let text: Vec<u8> = "nrv_secret\0"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert_eq!(b.held[&UNICODE_TEXT], text);
        assert_eq!(b.held.len(), 4);

        // A mark the system does not know, or one it does not take: an
        // error, and an empty clipboard.
        for (unknown, refuses) in [
            (Some("CanUploadToCloudClipboard"), None),
            (None, Some(0xC001)),
            (None, Some(UNICODE_TEXT)),
        ] {
            let mut b = Fake {
                unknown,
                refuses,
                ..Fake::default()
            };
            assert!(put_marked(&mut b, "nrv_secret").is_err());
            assert!(b.held.is_empty(), "{unknown:?} {refuses:?}: {:?}", b.held);
        }
    }

    /// The clearing takes the copy away only while it is still the latest.
    #[test]
    fn the_clearing_leaves_what_was_copied_since() {
        let mut b = Fake::default();
        put_marked(&mut b, "nrv_secret").unwrap();
        let after = b.sequence();
        b.put(UNICODE_TEXT, b"mine").unwrap();
        assert!(!clear_board_if(&mut b, after));
        assert_eq!(b.held[&UNICODE_TEXT], b"mine");
        put_marked(&mut b, "nrv_secret").unwrap();
        let after = b.sequence();
        assert!(clear_board_if(&mut b, after));
        assert!(b.held.is_empty());
    }
}
