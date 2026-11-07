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

/// Gives `dir` (made when missing) the DACL of [`dacl_text`] for the
/// account `owner`, which everything below it inherits. A link in place of
/// the folder is refused, and a junction below it is not followed.
#[cfg(windows)]
pub fn secure(dir: &Path, owner: Option<&str>) -> Result<(), String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
        SetNamedSecurityInfoW,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR,
    };

    use crate::win::sid::{sid_of, sid_text, wide};
    let last = || std::io::Error::last_os_error().to_string();
    let os = |code: u32| std::io::Error::from_raw_os_error(code as i32).to_string();
    let at = |e: String| format!("{}: {e}", dir.display());
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() => {
            return Err(at(
                "it is a link; the node's folders are folders, and install does not follow it"
                    .into(),
            ));
        }
        Ok(m) if !m.is_dir() => return Err(at("it is not a folder".into())),
        Ok(_) => {}
        Err(_) => std::fs::create_dir_all(dir).map_err(|e| at(e.to_string()))?,
    }
    let owner = owner
        .map(sid_of)
        .transpose()?
        .map(|s| sid_text(&s))
        .transpose()?;
    let text = wide(dacl_text(owner.as_deref()));
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
        return Err(at(last()));
    }
    let (mut present, mut defaulted) = (0, 0);
    let mut dacl = std::ptr::null_mut();
    // SAFETY: the descriptor just made; the DACL points into it.
    let r = unsafe {
        if GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) == 0 {
            Err(last())
        } else {
            // Inheritable entries go down to what is below.
            let r = SetNamedSecurityInfoW(
                wide(dir).as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
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
    r.map_err(at)
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
}
