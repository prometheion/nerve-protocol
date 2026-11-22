//! The few Windows calls on names and SIDs that the node's and the center's
//! services both make.

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, LookupAccountNameW, LookupAccountSidW, PSID,
    SECURITY_MAX_SID_SIZE, SID_NAME_USE, WELL_KNOWN_SID_TYPE, WinBuiltinAdministratorsSid,
};

fn last() -> io::Error {
    io::Error::last_os_error()
}

/// `s` as a NUL-terminated UTF-16 string.
pub fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(Some(0)).collect()
}

/// The NUL-terminated UTF-16 string at `p`, empty for a null pointer.
///
/// # Safety
/// `p` is null or points to a NUL-terminated UTF-16 string.
pub unsafe fn from_wide(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    // SAFETY: the string ends with a NUL, which bounds the walk.
    unsafe {
        while *p.add(n) != 0 {
            n += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
    }
}

/// A well-known SID, such as the Administrators group.
pub fn well_known_sid(kind: WELL_KNOWN_SID_TYPE) -> io::Result<Vec<u8>> {
    let mut sid = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut len = SECURITY_MAX_SID_SIZE;
    // SAFETY: a buffer of the largest SID size, with that size.
    if unsafe {
        CreateWellKnownSid(
            kind,
            std::ptr::null_mut(),
            sid.as_mut_ptr().cast(),
            &mut len,
        )
    } == 0
    {
        return Err(last());
    }
    sid.truncate(len as usize);
    Ok(sid)
}

/// Whether this process runs as an administrator, elevated: the
/// Administrators group is in effect in its token.
pub fn is_admin() -> bool {
    let Ok(sid) = well_known_sid(WinBuiltinAdministratorsSid) else {
        return false;
    };
    let mut member = 0;
    // SAFETY: a null token is this thread's or process's own; a valid SID.
    let ok =
        unsafe { CheckTokenMembership(std::ptr::null_mut(), sid.as_ptr() as PSID, &mut member) };
    ok != 0 && member != 0
}

/// The SID of the local account `name`.
pub fn sid_of(name: &str) -> Result<Vec<u8>, String> {
    // The machine's name first, so a domain account of that name is not it.
    sid_of_qualified(&format!(
        "{}\\{name}",
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| ".".into())
    ))
    .map_err(|e| format!("cannot find the SID of {name}: {e}"))
}

/// The SID of the account `domain\name`, as Windows names it.
pub fn sid_of_qualified(qualified: &str) -> Result<Vec<u8>, String> {
    let mut sid = vec![0u8; 68];
    let mut len = sid.len() as u32;
    let mut domain = vec![0u16; 256];
    let mut dlen = domain.len() as u32;
    let mut kind: SID_NAME_USE = 0;
    let full = wide(qualified);
    // SAFETY: buffers of the sizes given.
    let ok = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            full.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut len,
            domain.as_mut_ptr(),
            &mut dlen,
            &mut kind,
        )
    };
    if ok == 0 {
        return Err(last().to_string());
    }
    // The call leaves `len` at the buffer's size when the SID fits, so the
    // SID's own length cuts it: a SID compared as bytes must have no tail.
    // SAFETY: a valid SID the call wrote.
    let real = unsafe { windows_sys::Win32::Security::GetLengthSid(sid.as_ptr() as PSID) };
    sid.truncate((real as usize).min(len as usize));
    Ok(sid)
}

/// The name of the account or group `sid` on this machine, as
/// `DOMAIN\name`; `None` where Windows knows none (a deleted account).
pub fn name_of(sid: &[u8]) -> Option<String> {
    let mut name = vec![0u16; 256];
    let mut domain = vec![0u16; 256];
    let (mut n, mut d) = (name.len() as u32, domain.len() as u32);
    let mut kind: SID_NAME_USE = 0;
    // SAFETY: a valid SID and two buffers of the sizes given.
    let ok = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid.as_ptr() as PSID,
            name.as_mut_ptr(),
            &mut n,
            domain.as_mut_ptr(),
            &mut d,
            &mut kind,
        )
    };
    if ok == 0 {
        return None;
    }
    // SAFETY: LookupAccountSidW wrote two NUL-terminated strings.
    let (name, domain) = unsafe { (from_wide(name.as_ptr()), from_wide(domain.as_ptr())) };
    Some(match domain.is_empty() {
        true => name,
        false => format!("{domain}\\{name}"),
    })
}

/// Whether Windows says `sid` belongs to no account (`ERROR_NONE_MAPPED`):
/// any other failure (a domain controller out of reach) says nothing.
pub fn is_unmapped(sid: &[u8]) -> bool {
    use windows_sys::Win32::Foundation::{ERROR_NONE_MAPPED, GetLastError};
    let mut name = vec![0u16; 256];
    let mut domain = vec![0u16; 256];
    let (mut n, mut d) = (name.len() as u32, domain.len() as u32);
    let mut kind: SID_NAME_USE = 0;
    // SAFETY: a valid SID and two buffers of the sizes given.
    let ok = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid.as_ptr() as PSID,
            name.as_mut_ptr(),
            &mut n,
            domain.as_mut_ptr(),
            &mut d,
            &mut kind,
        )
    };
    // SAFETY: reads the thread's last error right after the call.
    ok == 0 && unsafe { GetLastError() } == ERROR_NONE_MAPPED
}

/// A SID as text, `S-1-5-…`.
pub fn sid_text(sid: &[u8]) -> Result<String, String> {
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: a valid SID; the string is freed with LocalFree.
    if unsafe { ConvertSidToStringSidW(sid.as_ptr() as PSID, &mut text) } == 0 {
        return Err(last().to_string());
    }
    // SAFETY: a NUL-terminated string, freed once.
    unsafe {
        let s = from_wide(text);
        LocalFree(text.cast());
        Ok(s)
    }
}
