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
    use windows_sys::Win32::System::Ole::CF_UNICODETEXT;

    /// The formats that keep a copy out of the clipboard history, the cloud
    /// clipboard and the programs that watch the clipboard.
    const MARKS: [(&str, u32); 3] = [
        ("ExcludeClipboardContentFromMonitorProcessing", 0),
        ("CanIncludeInClipboardHistory", 0),
        ("CanUploadToCloudClipboard", 0),
    ];

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

    fn put(format: u32, bytes: &[u8]) -> Result<(), String> {
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

    /// Copies `text` with the marks; the clipboard's sequence number after.
    pub fn copy(text: &str) -> Result<u32, String> {
        let open = Open::new()?;
        // SAFETY: the clipboard is open.
        if unsafe { EmptyClipboard() } == 0 {
            return Err(format!(
                "cannot empty the clipboard: {}",
                std::io::Error::last_os_error()
            ));
        }
        let units: Vec<u8> = wide(text).iter().flat_map(|u| u.to_le_bytes()).collect();
        put(CF_UNICODETEXT as u32, &units)?;
        for (name, value) in MARKS {
            // SAFETY: a NUL-terminated name.
            let format = unsafe { RegisterClipboardFormatW(wide(name).as_ptr()) };
            if format != 0 {
                put(format, &value.to_le_bytes())?;
            }
        }
        drop(open);
        // SAFETY: no arguments.
        Ok(unsafe { GetClipboardSequenceNumber() })
    }

    /// Empties the clipboard if nothing was copied since `sequence`.
    pub fn clear_if(sequence: u32) -> bool {
        let Ok(_open) = Open::new() else {
            return false;
        };
        // SAFETY: no arguments; the clipboard is open.
        unsafe { GetClipboardSequenceNumber() == sequence && EmptyClipboard() != 0 }
    }
}
