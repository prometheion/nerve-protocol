//! Who runs a process: the account of its token, and its session. The
//! center asks it of the process at the other end of its attach pipe and of
//! a loopback connection.

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows_sys::Win32::Foundation::HANDLE;
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
/// services and what they start share session 0. Anyone may ask it.
pub fn session_of(pid: u32) -> Option<u32> {
    let mut session = 0u32;
    // SAFETY: a plain call with a place for the answer.
    (unsafe { ProcessIdToSessionId(pid, &mut session) } != 0).then_some(session)
}
