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

/// `sddl` with the administrators as the owner of what it makes: the
/// installed service's folders, which [`private_folder`] then takes only
/// from SYSTEM or the administrators ([`mine_may_own`]). An elevated
/// administrator may name that owner.
pub fn owned_by_admins(sddl: &str) -> String {
    format!("O:BA{sddl}")
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
/// from what the folders above hand down where `sddl` says `D:P`.
#[cfg(windows)]
pub fn set(path: &Path, sddl: &str) -> Result<(), String> {
    use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SetNamedSecurityInfoW};

    use crate::win::sid::wide;
    with_dacl(sddl, |dacl, info| {
        // SAFETY: a NUL-terminated path and a DACL that lives through the
        // call. Inheritable entries go down to what is below.
        unsafe {
            SetNamedSecurityInfoW(
                wide(path).as_ptr(),
                SE_FILE_OBJECT,
                info,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null(),
            )
        }
    })
}

/// Sets the DACL `sddl` on the folder or file open as `f`, as [`set`] does
/// by name: on what was checked through the same handle, so nothing put in
/// its place in between gets it.
#[cfg(windows)]
fn set_on(f: &std::fs::File, sddl: &str) -> Result<(), String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SetSecurityInfo};
    with_dacl(sddl, |dacl, info| {
        // SAFETY: an open handle and a DACL that lives through the call.
        // Inheritable entries go down to what is below.
        unsafe {
            SetSecurityInfo(
                f.as_raw_handle(),
                SE_FILE_OBJECT,
                info,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null(),
            )
        }
    })
}

/// Calls `apply` with the DACL of `sddl` and the security information that
/// sets it (protected where `sddl` says `D:P`); its error code, 0 for none.
#[cfg(windows)]
fn with_dacl(
    sddl: &str,
    apply: impl FnOnce(*mut windows_sys::Win32::Security::ACL, u32) -> u32,
) -> Result<(), String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
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
    let protect = if sddl.contains("D:P") {
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
            match apply(dacl, DACL_SECURITY_INFORMATION | protect) {
                0 => Ok(()),
                r => Err(os(r)),
            }
        }
    };
    // SAFETY: the descriptor from the conversion, freed once.
    unsafe { LocalFree(sd) };
    r
}

/// Whether a private folder that is there already may be owned by this
/// process's own account, where `sddl` is what [`private_folder`] gives it.
/// Not where `sddl` names its owner (`O:BA`, the installed service's
/// folders): the administrator who installs and the same person's
/// unelevated programs (an agent's shell command among them) share one
/// account, and a folder such a program made first stays its owner's to
/// open again. SYSTEM and the administrators may always own it.
pub fn mine_may_own(sddl: &str) -> bool {
    !sddl.starts_with("O:")
}

/// Makes `dir` a private folder with the DACL `sddl` (and the owner it
/// names, if any): a new one with it from its first moment, so nobody puts
/// anything in it first; one there already only when SYSTEM, the
/// administrators or (see [`mine_may_own`]) this process's own account own
/// it, since its owner may always change its DACL again. A link in its
/// place is refused. The checks and the new DACL go through one handle, so
/// a folder swapped for a junction in between is not what gets the DACL.
#[cfg(windows)]
pub fn private_folder(dir: &Path, sddl: &str) -> Result<(), String> {
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{CreateDirectoryW, READ_CONTROL, WRITE_DAC};

    use crate::win::pipe::Descriptor;
    use crate::win::sid::wide;
    let at = |e: String| format!("{}: {e}", dir.display());
    if let Some(f) = open_folder(dir, READ_CONTROL | WRITE_DAC)? {
        if let Some(owner) = foreign_owner(&f, mine_may_own(sddl)).map_err(|e| at(e.to_string()))? {
            let who = crate::win::sid::sid_text(&owner).unwrap_or_else(|e| e);
            return Err(at(format!(
                "another account ({who}) made it, and could open it again; delete it, then run this again"
            )));
        }
        return set_on(&f, sddl).map_err(at);
    }
    if let Some(up) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(up).map_err(|e| format!("{}: {e}", up.display()))?;
    }
    let sd = Descriptor::from_sddl(sddl).map_err(|e| at(e.to_string()))?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.raw(),
        bInheritHandle: 0,
    };
    // SAFETY: a NUL-terminated path and attributes whose descriptor lives
    // through the call. A folder another account made since the look above
    // makes it fail.
    if unsafe { CreateDirectoryW(wide(dir).as_ptr(), &sa) } == 0 {
        return Err(at(std::io::Error::last_os_error().to_string()));
    }
    Ok(())
}

/// Refuses `dir` unless it is a folder, no link, that SYSTEM or the
/// administrators own: what the installed service checks of its folders
/// before it reads its settings, so a folder put in their place after the
/// install is not taken as its own.
#[cfg(windows)]
pub fn admins_folder(dir: &Path) -> Result<(), String> {
    use windows_sys::Win32::Storage::FileSystem::READ_CONTROL;
    let at = |e: String| format!("{}: {e}", dir.display());
    let Some(f) = open_folder(dir, READ_CONTROL)? else {
        return Err(at("it is not there; `nerve-center install` makes it".into()));
    };
    if let Some(owner) = foreign_owner(&f, false).map_err(|e| at(e.to_string()))? {
        let who = crate::win::sid::sid_text(&owner).unwrap_or_else(|e| e);
        return Err(at(format!(
            "another account ({who}) owns it, so the service does not take it as its own"
        )));
    }
    Ok(())
}

/// Opens the folder `dir` itself, not what a link there points to, for
/// `access`; `None` when nothing is there. A link or a file is refused.
#[cfg(windows)]
fn open_folder(dir: &Path, access: u32) -> Result<Option<std::fs::File>, String> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let at = |e: String| format!("{}: {e}", dir.display());
    let f = match std::fs::OpenOptions::new()
        .access_mode(access)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        // A folder opens only with the backup flag; a link opens as itself.
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(dir)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(at(e.to_string())),
    };
    let attributes = f
        .metadata()
        .map_err(|e| at(e.to_string()))?
        .file_attributes();
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(at("it is a link, and a private folder is a folder".into()));
    }
    if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(at("it is not a folder".into()));
    }
    Ok(Some(f))
}

/// The owner of the file or folder open as `f` when it is none of SYSTEM,
/// the administrators and, where `mine` says so, this process's own
/// account.
#[cfg(windows)]
fn foreign_owner(f: &std::fs::File, mine: bool) -> std::io::Result<Option<Vec<u8>>> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        GetLengthSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };

    use crate::win::sid::well_known_sid;
    let mut owner: PSID = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: an open handle; the owner points into the descriptor, which
    // is freed below.
    let r = unsafe {
        GetSecurityInfo(
            f.as_raw_handle(),
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
    let mut trusted = vec![
        well_known_sid(WinLocalSystemSid)?,
        well_known_sid(WinBuiltinAdministratorsSid)?,
    ];
    if mine {
        trusted.push(crate::win::process::user_of(None)?);
    }
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

    /// The installed service's folders name their owner, and one there
    /// already is taken from SYSTEM or the administrators only; this
    /// account's own folders (a harness center's state, the backup's hold)
    /// may be its own (round 3, security 1).
    #[test]
    fn only_a_folder_of_one_s_own_may_be_one_s_own() {
        let installed = owned_by_admins(&dacl_of(&["SY", "BA"], &[]));
        assert_eq!(installed, "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        assert!(!mine_may_own(&installed));
        assert!(mine_may_own(&dacl_of(&["S-1-5-21-9", "SY", "BA"], &[])));
        assert!(mine_may_own(&dacl_text(None)));
    }

    /// A folder there already: refused where its owner is another account,
    /// or this account where the descriptor names the administrators, or
    /// where it is a junction; a new one is made with the owner the
    /// descriptor names; the service's check takes only an
    /// administrators' folder (round 3, security 1 and 2). Setting another
    /// owner needs an administrator, as the CI runner is.
    #[cfg(windows)]
    #[test]
    fn a_folder_another_account_or_a_link_holds_is_refused() {
        use crate::win::sid::{is_admin, sid_text};
        if !is_admin() {
            eprintln!("note: not an administrator, so no owner can be set; nothing checked");
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let run = |program: &str, args: &[&str]| {
            let o = std::process::Command::new(program)
                .args(args)
                .output()
                .unwrap();
            assert!(o.status.success(), "{program} {args:?}: {o:?}");
            String::from_utf8_lossy(&o.stdout).to_string()
        };
        let set_owner = |dir: &Path, sid: &str| {
            run(
                "icacls",
                &[&dir.display().to_string(), "/setowner", &format!("*{sid}")],
            );
        };
        let me = sid_text(&crate::win::process::user_of(None).unwrap()).unwrap();
        let own = dacl_of(&[&me, "SY", "BA"], &[]);
        let installed = owned_by_admins(&dacl_of(&["SY", "BA"], &[]));

        // Made by this account (as an unelevated program of the same
        // person would make it): its own folders may take it, the
        // installed service's may not.
        let mine = d.path().join("mine");
        std::fs::create_dir(&mine).unwrap();
        set_owner(&mine, &me);
        let e = private_folder(&mine, &installed).unwrap_err();
        assert!(e.contains("another account") && e.contains(&me), "{e}");
        assert!(admins_folder(&mine).is_err());
        private_folder(&mine, &own).unwrap();

        // Made by another account: refused either way.
        let users = d.path().join("users");
        std::fs::create_dir(&users).unwrap();
        set_owner(&users, "S-1-5-32-545");
        assert!(private_folder(&users, &own).is_err());
        assert!(private_folder(&users, &installed).is_err());

        // A junction to a folder the administrators own is no folder.
        let target = d.path().join("target");
        private_folder(&target, &installed).unwrap();
        let link = d.path().join("link");
        run(
            "cmd",
            &[
                "/d",
                "/c",
                "mklink",
                "/J",
                &link.display().to_string(),
                &target.display().to_string(),
            ],
        );
        let e = private_folder(&link, &installed).unwrap_err();
        assert!(e.contains("link"), "{e}");
        assert!(admins_folder(&link).unwrap_err().contains("link"));

        // A new folder is the administrators', and the service's check
        // takes it.
        admins_folder(&target).unwrap();
        let owner = run(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                &format!("(Get-Acl -LiteralPath '{}').Owner", target.display()),
            ],
        );
        assert!(owner.contains("Administrators"), "{owner}");
        assert!(admins_folder(&d.path().join("none")).is_err());
    }
}
