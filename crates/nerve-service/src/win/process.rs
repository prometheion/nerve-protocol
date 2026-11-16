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
use windows_sys::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTS_CURRENT_SERVER_HANDLE, WTS_INFO_CLASS, WTSDomainName, WTSFreeMemory,
    WTSQuerySessionInformationW, WTSUserName,
};
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

/// The account signed in to the session `session`: as the Terminal Services
/// name it (a name and its domain) where they answer the caller, which they
/// do for an administrator, and else as the logon screen's record of it
/// ([`logon_record_user`]), which is all the node's service gets (they
/// refuse an account that is no administrator); `None` for a session
/// without one, such as session 0, which holds the services.
pub fn session_user(session: u32) -> Option<Vec<u8>> {
    let ask = |class: WTS_INFO_CLASS| -> Option<String> {
        let mut text: *mut u16 = std::ptr::null_mut();
        let mut bytes = 0u32;
        // SAFETY: this machine's server handle, and places for the answer,
        // which is freed with WTSFreeMemory.
        let ok = unsafe {
            WTSQuerySessionInformationW(
                WTS_CURRENT_SERVER_HANDLE,
                session,
                class,
                &mut text,
                &mut bytes,
            )
        };
        if ok == 0 || text.is_null() {
            return None;
        }
        // SAFETY: a NUL-terminated string the call allocated, freed once.
        let s = unsafe {
            let s = super::sid::from_wide(text);
            WTSFreeMemory(text.cast());
            s
        };
        (!s.is_empty()).then_some(s)
    };
    let Some(user) = ask(WTSUserName) else {
        return logon_record_user(session);
    };
    let domain = ask(WTSDomainName)?;
    super::sid::sid_of_qualified(&format!("{domain}\\{user}")).ok()
}

/// The account signed in to the session `session` as the logon screen
/// records it (`LoggedOnSAMUser`): written at each logon, readable by every
/// account and writable by administrators only, so the rule that lets a
/// session in rests on a record they alone can change. A service that is no
/// administrator is refused by the Terminal Services when it asks for
/// another account's session ([`session_user`]), and this is the record that
/// is left to ask.
fn logon_record_user(session: u32) -> Option<Vec<u8>> {
    use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW};
    let key = super::sid::wide(format!(
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI\\SessionData\\{session}"
    ));
    let value = super::sid::wide("LoggedOnSAMUser");
    let mut len = 0u32;
    // SAFETY: NUL-terminated names; a null buffer asks for the size, the
    // second call fills one of that size.
    unsafe {
        if RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut len,
        ) != 0
        {
            return None;
        }
        let mut buf = vec![0u16; (len as usize).div_ceil(2) + 1];
        let mut len = (buf.len() * 2) as u32;
        if RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buf.as_mut_ptr().cast(),
            &mut len,
        ) != 0
        {
            return None;
        }
        let name = super::sid::from_wide(buf.as_ptr());
        if name.is_empty() {
            return None;
        }
        super::sid::sid_of_qualified(&name).ok()
    }
}

/// The account and the session of the process `pid`, as far as they can be
/// told: from its token where this process may open it, and else only the
/// session, from the system's list of processes ([`session_listed`]), since
/// the account of another account's process stays hidden from a service
/// that is no administrator.
pub fn identity_of(pid: u32) -> (Option<Vec<u8>>, Option<u32>) {
    super::procs::identity_from(
        user_of(Some(pid)).ok(),
        || session_of(pid),
        || session_listed(pid),
    )
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

    /// The account of a person's session is the account signed in there:
    /// this test's own where it runs in one; session 0, which holds the
    /// services, has none.
    #[test]
    fn a_session_names_the_account_signed_in_to_it() {
        assert_eq!(session_user(0), None);
        if let Some(s) = session_of(std::process::id()).filter(|&s| s != 0) {
            assert_eq!(session_user(s), Some(user_of(None).unwrap()));
        }
    }

    /// What the logon screen records of a session names the account signed in
    /// to it, which is all a service that is no administrator can learn of
    /// another account's session (the Terminal Services refuse it, found on
    /// a real machine). Where this test runs in a session the machine has no
    /// record of, nothing is asserted.
    #[test]
    fn the_logon_record_names_the_account_signed_in_to_a_session() {
        assert_eq!(logon_record_user(u32::MAX - 3), None);
        if let Some(s) = session_of(std::process::id()).filter(|&s| s != 0)
            && let Some(sid) = logon_record_user(s)
        {
            assert_eq!(Some(sid), Some(user_of(None).unwrap()));
        }
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
