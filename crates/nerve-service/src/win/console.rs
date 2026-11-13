//! A program started by a double-click in Explorer: Windows made a console
//! for it alone, which closes with it. The center installs itself then, as
//! the desktop app does: it starts itself again with the administrators'
//! rights (the UAC prompt), and that window stays open until the person has
//! read it.

use std::io::{BufRead, Write};
use std::path::Path;

use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Console::{
    ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode, GetConsoleProcessList, GetStdHandle,
    STD_ERROR_HANDLE, STD_OUTPUT_HANDLE, SetConsoleMode,
};
use windows_sys::Win32::UI::Shell::{SEE_MASK_NOASYNC, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

use crate::win::sid::wide;

/// Whether this process is the only one on its console: Explorer made the
/// console for it, so a double-click started it. A program started in a
/// terminal shares the terminal's console with its shell.
pub fn alone() -> bool {
    let mut pids = [0u32; 2];
    // SAFETY: a buffer of two pids; the answer is how many are on the
    // console (0 when this process has none).
    let n = unsafe { GetConsoleProcessList(pids.as_mut_ptr(), pids.len() as u32) };
    n == 1
}

/// Starts `exe` with `args` again with the administrators' rights, in a
/// window of its own (the UAC prompt first); does not wait for it.
pub fn run_elevated(exe: &Path, args: &str) -> Result<(), String> {
    let (verb, file, params) = (wide("runas"), wide(exe.display().to_string()), wide(args));
    // SAFETY: a filled SHELLEXECUTEINFOW whose strings live until the call
    // returns; NOASYNC finishes the start before the call returns, as this
    // process ends right after it.
    unsafe {
        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOASYNC;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpParameters = params.as_ptr();
        info.nShow = SW_SHOWNORMAL;
        if ShellExecuteExW(&mut info) == 0 {
            // ERROR_CANCELLED: the person said no.
            return Err(if GetLastError() == 1223 {
                "the administrator rights were not given".into()
            } else {
                format!(
                    "cannot ask for administrator rights: error {}",
                    GetLastError()
                )
            });
        }
    }
    Ok(())
}

/// Keeps a window Explorer opened until the person presses Enter: it
/// closes with the program, and what it said would be gone unread.
pub fn hold(out: &mut dyn Write) {
    let _ = write!(out, "\nPress Enter to close this window.");
    let _ = out.flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
}

/// Turns colour codes on for the console of stdout (`stdout`) or stderr;
/// whether it takes them. An old console that cannot gets plain text
/// (crate::out).
pub fn virtual_terminal(stdout: bool) -> bool {
    let which = match stdout {
        true => STD_OUTPUT_HANDLE,
        false => STD_ERROR_HANDLE,
    };
    // SAFETY: the process's own standard handle, and a mode read into a
    // local before it is set with one flag more.
    unsafe {
        let h = GetStdHandle(which);
        let mut mode = 0u32;
        if h.is_null() || GetConsoleMode(h, &mut mode) == 0 {
            return false;
        }
        mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0
            || SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
}
