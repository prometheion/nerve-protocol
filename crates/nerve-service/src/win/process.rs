//! Who runs a process: the account of its token, and its session. The
//! center asks it of the process at the other end of its attach pipe and of
//! a loopback connection; of another account's process a service that is
//! no administrator can tell the session only.

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows_sys::Wdk::System::SystemInformation::{
    NtQuerySystemInformation, SystemProcessInformation,
};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::STATUS_INFO_LENGTH_MISMATCH;
use windows_sys::Win32::Security::{
    GetLengthSid, GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// The token of the process `pid` (this one for `None`), opened with
/// `access`.
pub fn token(pid: Option<u32>, access: u32) -> io::Result<OwnedHandle> {
    let process = match pid {
        // SAFETY: a pseudo handle, valid for this process, never closed.
        None => unsafe { GetCurrentProcess() },
        Some(pid) => {
            // SAFETY: a plain call; the handle is closed when `opened` drops.
            let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
            if h.is_null() {
                return Err(io::Error::last_os_error());
            }
            h
        }
    };
    // SAFETY: an open process handle this function owns, or the pseudo
    // handle, which closing leaves alone.
    let _opened = pid.map(|_| unsafe { OwnedHandle::from_raw_handle(process) });
    let mut t: HANDLE = std::ptr::null_mut();
    // SAFETY: an open process and a place for the token.
    if unsafe { OpenProcessToken(process, access, &mut t) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the token this call opened, owned from here.
    Ok(unsafe { OwnedHandle::from_raw_handle(t) })
}

/// What the token `t` says of `class`, in a buffer aligned for its
/// structure.
pub fn token_info(t: &OwnedHandle, class: i32) -> io::Result<Vec<u64>> {
    let mut need = 0u32;
    // SAFETY: a query of the size only.
    unsafe { GetTokenInformation(t.as_raw_handle(), class, std::ptr::null_mut(), 0, &mut need) };
    let mut buf = vec![0u64; (need as usize).div_ceil(8).max(1)];
    // SAFETY: a buffer of at least `need` bytes.
    if unsafe {
        GetTokenInformation(
            t.as_raw_handle(),
            class,
            buf.as_mut_ptr().cast(),
            (buf.len() * 8) as u32,
            &mut need,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(buf)
}

/// The SID of the account the process `pid` runs as (this one's for
/// `None`). Another account's process may refuse to be asked: that is an
/// error, never an answer.
pub fn user_of(pid: Option<u32>) -> io::Result<Vec<u8>> {
    let t = token(pid, TOKEN_QUERY)?;
    let info = token_info(&t, TokenUser)?;
    // SAFETY: the buffer holds a TOKEN_USER, whose SID points into it.
    let sid = unsafe { (*info.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    // SAFETY: a valid SID in the buffer, copied while it lives.
    Ok(unsafe {
        let len = GetLengthSid(sid) as usize;
        std::slice::from_raw_parts(sid.cast::<u8>(), len).to_vec()
    })
}

/// The session of the process `pid`: each person signed in has one,
/// services and what they start share session 0. Another account's process
/// may refuse to be asked, as for its token ([`session_listed`] does not).
pub fn session_of(pid: u32) -> Option<u32> {
    let mut session = 0u32;
    // SAFETY: a plain call with a place for the answer.
    (unsafe { ProcessIdToSessionId(pid, &mut session) } != 0).then_some(session)
}

/// The session of the process `pid` as the system's list of processes
/// names it ([`super::procs`]): the list is open to every caller, also a
/// service that runs as no administrator, which can neither open another
/// account's process nor have the Terminal Services list it (that one is
/// for administrators when the process is another account's).
pub fn session_listed(pid: u32) -> Option<u32> {
    // The list grows while it is read: ask again with room for it.
    let mut buf = vec![0u64; 64 * 1024 / 8];
    for _ in 0..8 {
        let mut need = 0u32;
        // SAFETY: a buffer of the size given, and a place for the size
        // needed.
        let status = unsafe {
            NtQuerySystemInformation(
                SystemProcessInformation,
                buf.as_mut_ptr().cast(),
                (buf.len() * 8) as u32,
                &mut need,
            )
        };
        if status == STATUS_INFO_LENGTH_MISMATCH {
            buf = vec![0u64; (need as usize).div_ceil(8) + 64 * 1024 / 8];
            continue;
        }
        if status < 0 {
            return None;
        }
        // SAFETY: the bytes of the buffer the call wrote into.
        let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), buf.len() * 8) };
        return super::procs::session_in(bytes, pid);
    }
    None
}

/// The account and the session of the process `pid`, as far as they can be
/// told: from its token where this process may open it, and else only the
/// session, from the system's list of processes ([`session_listed`]), since
/// the account of another account's process stays hidden from a service
/// that is no administrator.
pub fn identity_of(pid: u32) -> (Option<Vec<u8>>, Option<u32>) {
    if let Ok(sid) = user_of(Some(pid)) {
        return (Some(sid), session_of(pid).or_else(|| session_listed(pid)));
    }
    (None, session_listed(pid).or_else(|| session_of(pid)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The system's list names this process's session as its token does
    /// (the list is what names the session of another account's process the
    /// service cannot open; round 2, correctness 1), and the offsets of
    /// the layout are those of the real structure.
    #[test]
    fn the_process_list_names_a_process_session_as_the_system_does() {
        let pid = std::process::id();
        assert_eq!(session_listed(pid), session_of(pid));
        assert!(session_listed(pid).is_some());
        // A process that is not there is not named.
        assert_eq!(session_listed(u32::MAX - 3), None);
        let (sid, session) = identity_of(pid);
        assert_eq!(sid, Some(user_of(None).unwrap()));
        assert_eq!(session, session_of(pid));
        use windows_sys::Win32::System::WindowsProgramming::SYSTEM_PROCESS_INFORMATION;
        assert_eq!(
            std::mem::offset_of!(SYSTEM_PROCESS_INFORMATION, UniqueProcessId),
            super::super::procs::ID_OFFSET
        );
        assert_eq!(
            std::mem::offset_of!(SYSTEM_PROCESS_INFORMATION, SessionId),
            super::super::procs::SESSION_OFFSET
        );
    }

    /// The first process of the machine, the System process, belongs to
    /// session 0 and is one an ordinary caller may not open: the list
    /// still names its session.
    #[test]
    fn a_process_that_cannot_be_opened_still_has_a_session() {
        assert!(user_of(Some(4)).is_err() || session_of(4).is_some());
        assert_eq!(session_listed(4), Some(0));
    }
}
