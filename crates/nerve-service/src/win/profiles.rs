//! The profile folders of the services' accounts that an uninstall could
//! not remove: Windows held them (its search, or a registry it kept
//! loaded) until its next restart. Each install and uninstall after that
//! restart removes them, so they do not pile up with every reinstall
//! (#213 W1-F10). Only the profiles of accounts that are gone, and whose
//! folder has the name of one of the services' accounts, are touched.

use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;

/// Whether the profile folder `path` is one Windows made for an account
/// named one of `names`: `nerve`, or `nerve.DESKTOP-1.040` where a folder of
/// that name was there already.
pub fn named_for(path: &Path, names: &[&str]) -> bool {
    let Some(file) = path.file_name().and_then(|f| f.to_str()) else {
        return false;
    };
    let file = file.to_lowercase();
    names.iter().any(|n| {
        let n = n.to_lowercase();
        file == n
            || file
                .strip_prefix(&n)
                .is_some_and(|rest| rest.starts_with('.'))
    })
}

/// Removes the profiles of the accounts that are gone whose folders
/// [`named_for`] `names`; the folders it removed. One Windows still holds
/// stays for a later call.
#[cfg(windows)]
pub fn sweep(names: &[&str]) -> Vec<PathBuf> {
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows_sys::Win32::Security::PSID;
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ, RegCloseKey,
        RegEnumKeyExW, RegGetValueW, RegOpenKeyExW,
    };
    use windows_sys::Win32::UI::Shell::DeleteProfileW;

    use crate::win::sid::{from_wide, wide};

    const LIST: &str = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
    let mut key: HKEY = std::ptr::null_mut();
    // SAFETY: a NUL-terminated key name and a handle to fill.
    if unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            wide(LIST).as_ptr(),
            0,
            KEY_READ,
            &mut key,
        )
    } != ERROR_SUCCESS
    {
        return Vec::new();
    }
    let mut sids = Vec::new();
    for i in 0.. {
        let mut name = [0u16; 256];
        let mut len = name.len() as u32;
        // SAFETY: an open key and a buffer of the length given.
        let r = unsafe {
            RegEnumKeyExW(
                key,
                i,
                name.as_mut_ptr(),
                &mut len,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if r != ERROR_SUCCESS {
            break;
        }
        sids.push(String::from_utf16_lossy(&name[..len as usize]));
    }
    // SAFETY: the key opened above, closed once.
    unsafe { RegCloseKey(key) };
    let mut removed = Vec::new();
    for sid in sids {
        let sub = wide(format!("{LIST}\\{sid}"));
        let value = wide("ProfileImagePath");
        let mut buf = vec![0u16; 1024];
        let mut size = (buf.len() * 2) as u32;
        // SAFETY: NUL-terminated names and a buffer of the size given.
        let r = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                sub.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if r != ERROR_SUCCESS {
            continue;
        }
        // SAFETY: RegGetValueW wrote a NUL-terminated string.
        let path = PathBuf::from(unsafe { from_wide(buf.as_ptr()) });
        if !named_for(&path, names) {
            continue;
        }
        // Only an account that is gone: Windows names every account there is.
        let mut bin: PSID = std::ptr::null_mut();
        // SAFETY: a NUL-terminated SID string; the SID is freed with
        // LocalFree.
        if unsafe { ConvertStringSidToSidW(wide(&sid).as_ptr(), &mut bin) } == 0 {
            continue;
        }
        // SAFETY: the SID just made, of the length Windows gives for it.
        let gone = unsafe {
            let len = windows_sys::Win32::Security::GetLengthSid(bin) as usize;
            let bytes = std::slice::from_raw_parts(bin as *const u8, len).to_vec();
            LocalFree(bin.cast());
            crate::win::sid::name_of(&bytes).is_none()
        };
        if !gone {
            continue;
        }
        // SAFETY: a NUL-terminated SID string.
        let ok = unsafe { DeleteProfileW(wide(&sid).as_ptr(), std::ptr::null(), std::ptr::null()) };
        if ok != 0 {
            removed.push(path);
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The folders Windows names after the services' accounts are found,
    /// and no other account's.
    #[test]
    fn the_profiles_of_the_services_accounts_are_told_by_their_name() {
        let names = ["nerve", "nerve-run", "nerve-center"];
        for ours in [
            "C:\\Users\\nerve",
            "C:\\Users\\nerve.DESKTOP-5Q8KPG8.040",
            "C:\\Users\\nerve-run.DESKTOP-5Q8KPG8",
            "C:\\Windows\\ServiceProfiles\\nerve-center",
        ] {
            assert!(
                named_for(Path::new(&ours.replace('\\', "/")), &names),
                "{ours}"
            );
        }
        for other in [
            "C:\\Users\\nervekrt",
            "C:\\Users\\Max Müller",
            "C:\\Users\\nerve-runner",
            "C:\\Users\\nerved.DESKTOP",
        ] {
            assert!(
                !named_for(Path::new(&other.replace('\\', "/")), &names),
                "{other}"
            );
        }
    }
}
