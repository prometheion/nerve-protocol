//! The few Win32 calls the node makes itself: the process table and ending a
//! process (crate::tree), the job object a command runs in (crate::job), and
//! the console code page that command output is written in (crate::exec),
//! whether the node's own token is elevated (crate::rights), and which
//! processes are in the jobs of its commands (crate::pipe).
//! Declared here against kernel32, which every Windows program links; only
//! the job object and the token come from windows-sys, whose structures are
//! too easy to get wrong by hand.

use std::io;

use windows_sys::Win32::Security::{
    GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcessToken, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
};

pub use nerve_service::win::job_object::{Handle, Job, from_a_command, in_job};

use crate::tree::Proc;

const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
const TH32CS_SNAPTHREAD: u32 = 0x0000_0004;
const PROCESS_TERMINATE: u32 = 0x0001;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
#[cfg(test)]
const STILL_ACTIVE: u32 = 259;
const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;

#[repr(C)]
struct ProcessEntry32W {
    size: u32,
    usage: u32,
    pid: u32,
    default_heap_id: usize,
    module_id: u32,
    threads: u32,
    ppid: u32,
    pri_class_base: i32,
    flags: u32,
    exe_file: [u16; 260],
}

#[repr(C)]
#[derive(Default)]
struct ThreadEntry32 {
    size: u32,
    usage: u32,
    tid: u32,
    owner_pid: u32,
    base_pri: i32,
    delta_pri: i32,
    flags: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct FileTime {
    low: u32,
    high: u32,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> Handle;
    fn Process32FirstW(snapshot: Handle, entry: *mut ProcessEntry32W) -> i32;
    fn Process32NextW(snapshot: Handle, entry: *mut ProcessEntry32W) -> i32;
    fn Thread32First(snapshot: Handle, entry: *mut ThreadEntry32) -> i32;
    fn Thread32Next(snapshot: Handle, entry: *mut ThreadEntry32) -> i32;
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
    fn GetProcessTimes(
        process: Handle,
        creation: *mut FileTime,
        exit: *mut FileTime,
        kernel: *mut FileTime,
        user: *mut FileTime,
    ) -> i32;
    #[cfg(test)]
    fn GetExitCodeProcess(process: Handle, code: *mut u32) -> i32;
    fn TerminateProcess(process: Handle, code: u32) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetOEMCP() -> u32;
    fn IsDBCSLeadByteEx(code_page: u32, byte: u8) -> i32;
    fn MultiByteToWideChar(
        code_page: u32,
        flags: u32,
        bytes: *const u8,
        len: i32,
        wide: *mut u16,
        wide_len: i32,
    ) -> i32;
}

/// An open process handle, closed when dropped.
struct Process(Handle);

impl Process {
    fn open(pid: u32, access: u32) -> Option<Process> {
        // SAFETY: OpenProcess takes plain values and returns null on failure.
        let h = unsafe { OpenProcess(access, 0, pid) };
        (!h.is_null()).then_some(Process(h))
    }

    fn created(&self) -> Option<u64> {
        let mut t = [FileTime::default(); 4];
        let [c, e, k, u] = &mut t;
        // SAFETY: the handle is open and the four pointers are valid.
        let ok = unsafe { GetProcessTimes(self.0, c, e, k, u) } != 0;
        ok.then(|| (u64::from(t[0].high) << 32) | u64::from(t[0].low))
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenProcess and is closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// Every process the process table lists now; empty when it cannot be read.
pub fn processes() -> Vec<Proc> {
    let mut out = Vec::new();
    // SAFETY: a process snapshot takes plain values; the result is checked.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE || snap.is_null() {
        return out;
    }
    // SAFETY: the entry is zeroed plain data with its size set, as
    // Process32FirstW requires.
    let mut e: ProcessEntry32W = unsafe { std::mem::zeroed() };
    e.size = std::mem::size_of::<ProcessEntry32W>() as u32;
    // SAFETY: the snapshot is open and the entry valid for writes.
    let mut more = unsafe { Process32FirstW(snap, &mut e) } != 0;
    while more {
        out.push(Proc {
            pid: e.pid,
            ppid: e.ppid,
        });
        // SAFETY: as above.
        more = unsafe { Process32NextW(snap, &mut e) } != 0;
    }
    // SAFETY: the snapshot handle is closed once.
    unsafe { CloseHandle(snap) };
    out
}

/// When process `pid` was created (FILETIME), if it can be opened.
pub fn start_of(pid: u32) -> Option<u64> {
    Process::open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?.created()
}

/// Ends process `pid` when it is still the one created at `start`, so a pid
/// Windows gave to another process meanwhile is left alone.
pub fn terminate(pid: u32, start: u64) -> bool {
    let Some(p) = Process::open(pid, PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION) else {
        return false;
    };
    if p.created() != Some(start) {
        return false;
    }
    // SAFETY: the handle is open with PROCESS_TERMINATE.
    unsafe { TerminateProcess(p.0, 1) != 0 }
}

/// Whether process `pid` runs.
#[cfg(test)]
pub fn running(pid: u32) -> bool {
    let Some(p) = Process::open(pid, PROCESS_QUERY_LIMITED_INFORMATION) else {
        return false;
    };
    let mut code = 0u32;
    // SAFETY: the handle is open and the pointer valid.
    unsafe { GetExitCodeProcess(p.0, &mut code) != 0 && code == STILL_ACTIVE }
}

/// Resumes the threads of process `pid`, which was started suspended: a
/// suspended new process has only its main thread. An error when none was
/// resumed.
pub fn resume(pid: u32) -> io::Result<()> {
    // SAFETY: a thread snapshot takes plain values; the result is checked.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snap == INVALID_HANDLE_VALUE || snap.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut e = ThreadEntry32 {
        size: std::mem::size_of::<ThreadEntry32>() as u32,
        ..Default::default()
    };
    let mut resumed = 0;
    let mut failed = None;
    // SAFETY: the snapshot is open and the entry valid for writes, its size
    // set as Thread32First requires.
    let mut more = unsafe { Thread32First(snap, &mut e) } != 0;
    while more {
        if e.owner_pid == pid {
            // SAFETY: OpenThread takes plain values and returns null on failure.
            let t = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, e.tid) };
            if t.is_null() {
                failed = Some(io::Error::last_os_error());
            } else {
                // SAFETY: the thread handle is open with THREAD_SUSPEND_RESUME,
                // and closed once.
                unsafe {
                    if ResumeThread(t) == u32::MAX {
                        failed = Some(io::Error::last_os_error());
                    } else {
                        resumed += 1;
                    }
                    CloseHandle(t);
                }
            }
        }
        // SAFETY: as above.
        more = unsafe { Thread32Next(snap, &mut e) } != 0;
    }
    // SAFETY: the snapshot handle is closed once.
    unsafe { CloseHandle(snap) };
    match (resumed, failed) {
        (0, Some(e)) => Err(e),
        (0, None) => Err(io::Error::other("the process has no thread")),
        _ => Ok(()),
    }
}

/// Whether this process runs in an elevated token: an administrator who
/// passed UAC, or an account like SYSTEM that always does. A token that
/// cannot be read counts as elevated, so the node errs on the side of the
/// refusal and the warning.
pub fn is_elevated() -> bool {
    let mut token = std::ptr::null_mut();
    // SAFETY: the current process pseudo-handle needs no closing, and the
    // token is written only on success.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return true;
    }
    let mut info = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut len = 0u32;
    // SAFETY: the buffer is a TOKEN_ELEVATION of the size given; the token
    // is open and closed once.
    let ok = unsafe {
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            std::ptr::from_mut(&mut info).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        );
        CloseHandle(token);
        ok
    };
    ok == 0 || info.TokenIsElevated != 0
}

/// The code page a console program started by the node writes in: the OEM
/// code page a new console gets. Every command has a console of its own
/// (crate::job::CONSOLE), also when the node runs in one.
pub fn console_code_page() -> u32 {
    // SAFETY: it takes no arguments.
    unsafe { GetOEMCP() }
}

/// How many bytes at the end of `bytes` start a character of code page `cp`
/// they do not finish: the lead byte of a double-byte code page (932, 936,
/// 949, 950) whose second byte is still to come. `bytes` starts at a whole
/// character.
pub fn code_page_cut(cp: u32, bytes: &[u8]) -> usize {
    let mut i = 0;
    while i < bytes.len() {
        // SAFETY: it takes plain values.
        if unsafe { IsDBCSLeadByteEx(cp, bytes[i]) } == 0 {
            i += 1;
        } else if i + 1 == bytes.len() {
            return 1;
        } else {
            i += 2;
        }
    }
    0
}

/// `bytes` decoded from code page `cp`; `None` when Windows cannot.
pub fn code_page_text(cp: u32, bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return Some(String::new());
    }
    let len = i32::try_from(bytes.len()).ok()?;
    // SAFETY: the input is valid for `len` bytes; a null output asks for the
    // length only.
    let n = unsafe { MultiByteToWideChar(cp, 0, bytes.as_ptr(), len, std::ptr::null_mut(), 0) };
    if n <= 0 {
        return None;
    }
    let mut wide = vec![0u16; n as usize];
    // SAFETY: the output is valid for `n` units.
    let n = unsafe { MultiByteToWideChar(cp, 0, bytes.as_ptr(), len, wide.as_mut_ptr(), n) };
    if n <= 0 {
        return None;
    }
    wide.truncate(n as usize);
    Some(String::from_utf16_lossy(&wide))
}
