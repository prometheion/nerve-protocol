//! The protected DACL of a service's private folders: its account, SYSTEM
//! and the administrators, and nothing inherited from above.

#[cfg(windows)]
use std::path::Path;

/// The DACL in SDDL: full control for `owner` (a SID), SYSTEM and the
/// administrators, inherited by every file and folder below; `P` keeps out
/// what the folders above would hand down.
pub fn dacl_text(owner: Option<&str>) -> String {
    let mut s = String::from("D:P");
    if let Some(o) = owner {
        s.push_str(&format!("(A;OICI;FA;;;{o})"));
    }
    s.push_str("(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
    s
}

/// A protected DACL in SDDL for the folders and files of another service
/// (the center's): full control for each SID of `full`, read for each of
/// `read`, inherited by every file and folder below; nothing else, and
/// nothing from the folders above. A SID is its text (`S-1-5-…`) or an
/// SDDL abbreviation (`SY`, `BA`).
pub fn dacl_of(full: &[&str], read: &[&str]) -> String {
    let mut s = String::from("D:P");
    for sid in full {
        s.push_str(&format!("(A;OICI;FA;;;{sid})"));
    }
    for sid in read {
        s.push_str(&format!("(A;OICI;FR;;;{sid})"));
    }
    s
}

/// Gives `dir` (made when missing) the DACL of [`dacl_text`] for the
/// account `owner`, which everything below it inherits. A link in place of
/// the folder is refused, and a junction below it is not followed.
#[cfg(windows)]
pub fn secure(dir: &Path, owner: Option<&str>) -> Result<(), String> {
    use crate::win::sid::{sid_of, sid_text};
    let owner = owner
        .map(sid_of)
        .transpose()?
        .map(|s| sid_text(&s))
        .transpose()?;
    secure_with(dir, &dacl_text(owner.as_deref()))
}

/// Gives `dir` (made when missing) the DACL `sddl`, which everything below
/// it inherits where it says so. A link in place of the folder is refused,
/// and a junction below it is not followed.
#[cfg(windows)]
pub fn secure_with(dir: &Path, sddl: &str) -> Result<(), String> {
    let at = |e: String| format!("{}: {e}", dir.display());
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() => {
            return Err(at(
                "it is a link; the service's folders are folders, and install does not follow it"
                    .into(),
            ));
        }
        Ok(m) if !m.is_dir() => return Err(at("it is not a folder".into())),
        Ok(_) => {}
        Err(_) => std::fs::create_dir_all(dir).map_err(|e| at(e.to_string()))?,
    }
    set(dir, sddl).map_err(at)
}

/// Sets the DACL `sddl` on the file or folder `path`, as it is: protected
/// from what the folders above hand down where `sddl` starts with `D:P`.
#[cfg(windows)]
pub fn set(path: &Path, sddl: &str) -> Result<(), String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
        SetNamedSecurityInfoW,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, UNPROTECTED_DACL_SECURITY_INFORMATION,
    };

    use crate::win::sid::wide;
    let last = || std::io::Error::last_os_error().to_string();
    let os = |code: u32| std::io::Error::from_raw_os_error(code as i32).to_string();
    let text = wide(sddl);
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: a NUL-terminated SDDL string; the descriptor is freed below.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(last());
    }
    let protect = if sddl.starts_with("D:P") {
        PROTECTED_DACL_SECURITY_INFORMATION
    } else {
        UNPROTECTED_DACL_SECURITY_INFORMATION
    };
    let (mut present, mut defaulted) = (0, 0);
    let mut dacl = std::ptr::null_mut();
    // SAFETY: the descriptor just made; the DACL points into it.
    let r = unsafe {
        if GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) == 0 {
            Err(last())
        } else {
            // Inheritable entries go down to what is below.
            let r = SetNamedSecurityInfoW(
                wide(path).as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | protect,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null(),
            );
            if r == 0 { Ok(()) } else { Err(os(r)) }
        }
    };
    // SAFETY: the descriptor from the conversion, freed once.
    unsafe { LocalFree(sd) };
    r
}

/// Makes `dir` a private folder with the DACL `sddl`: a new one with it
/// from its first moment, so nobody puts anything in it first; one there
/// already only when SYSTEM, the administrators or this process's own
/// account own it, since its owner may always change its DACL again. A link
/// in its place is refused.
#[cfg(windows)]
pub fn private_folder(dir: &Path, sddl: &str) -> Result<(), String> {
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

    use crate::win::pipe::Descriptor;
    use crate::win::sid::wide;
    let at = |e: String| format!("{}: {e}", dir.display());
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() => {
            Err(at("it is a link, and a private folder is a folder".into()))
        }
        Ok(m) if !m.is_dir() => Err(at("it is not a folder".into())),
        Ok(_) => {
            if let Some(owner) = foreign_owner(dir).map_err(|e| at(e.to_string()))? {
                let who = crate::win::sid::sid_text(&owner).unwrap_or_else(|e| e);
                return Err(at(format!(
                    "another account ({who}) made it, and could open it again; delete it, then run this again"
                )));
            }
            set(dir, sddl).map_err(at)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(up) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(up).map_err(|e| format!("{}: {e}", up.display()))?;
            }
            let sd = Descriptor::from_sddl(sddl).map_err(|e| at(e.to_string()))?;
            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd.raw(),
                bInheritHandle: 0,
            };
            // SAFETY: a NUL-terminated path and attributes whose descriptor
            // lives through the call.
            if unsafe { CreateDirectoryW(wide(dir).as_ptr(), &sa) } == 0 {
                return Err(at(std::io::Error::last_os_error().to_string()));
            }
            Ok(())
        }
        Err(e) => Err(at(e.to_string())),
    }
}

/// The owner of `path` when it is none of SYSTEM, the administrators and
/// this process's own account.
#[cfg(windows)]
fn foreign_owner(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        GetLengthSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };

    use crate::win::sid::{well_known_sid, wide};
    let mut owner: PSID = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: a NUL-terminated path; the owner points into the descriptor,
    // which is freed below.
    let r = unsafe {
        GetNamedSecurityInfoW(
            wide(path).as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if r != 0 {
        return Err(std::io::Error::from_raw_os_error(r as i32));
    }
    // SAFETY: a valid SID in the descriptor, copied before it is freed.
    let owner = unsafe {
        let v =
            std::slice::from_raw_parts(owner.cast::<u8>(), GetLengthSid(owner) as usize).to_vec();
        LocalFree(sd);
        v
    };
    let me = crate::win::process::user_of(None)?;
    let trusted = [
        well_known_sid(WinLocalSystemSid)?,
        well_known_sid(WinBuiltinAdministratorsSid)?,
        me,
    ];
    Ok((!trusted.contains(&owner)).then_some(owner))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The DACL of the node's folders names nerve, SYSTEM and the
    /// administrators, and nothing from the folders above.
    #[test]
    fn the_folders_get_a_dacl_of_their_own() {
        assert_eq!(
            dacl_text(Some("S-1-5-21-1-2-3-1010")),
            "D:P(A;OICI;FA;;;S-1-5-21-1-2-3-1010)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        );
        assert_eq!(dacl_text(None), "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
    }

    /// Another service's folders: full control and read for the SIDs
    /// named, nothing else and nothing from above.
    #[test]
    fn a_folder_gets_full_and_read_entries_only() {
        assert_eq!(
            dacl_of(&["SY", "BA"], &["S-1-5-80-1-2-3-4-5"]),
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;S-1-5-80-1-2-3-4-5)"
        );
        assert_eq!(dacl_of(&["S-1-5-21-9"], &[]), "D:P(A;OICI;FA;;;S-1-5-21-9)");
    }
}
