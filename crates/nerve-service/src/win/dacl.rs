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

/// Why an existing private folder is refused for its owner: `own` when it
/// is this process's own account (a program of the same person, started
/// without Run as administrator, made it, an agent's shell command among
/// them), else another account, named by `who`.
pub fn foreign_text(own: bool, who: &str) -> String {
    if own {
        "a program of yours made it without Run as administrator (an agent's shell command could), and could open it again; delete it, then run this again".into()
    } else {
        format!(
            "another account ({who}) made it, and could open it again; delete it, then run this again"
        )
    }
}

/// Whether a folder with these attributes and reparse tag is a link: a
/// name-surrogate reparse point (symbolic link, junction). Other reparse
/// points are plain folders to the user, such as a OneDrive folder (cloud
/// files tag); a tag that could not be read (`None`) counts as a link.
pub fn is_link(attributes: u32, tag: Option<u32>) -> bool {
    const REPARSE_POINT: u32 = 0x400;
    const NAME_SURROGATE: u32 = 1 << 29;
    attributes & REPARSE_POINT != 0 && tag.is_none_or(|t| t & NAME_SURROGATE != 0)
}

/// Whether a volume with these file system flags keeps access lists (NTFS,
/// ReFS). One that does not (FAT32 and exFAT, as USB sticks and SD cards
/// come) answers every question with a list that lets everyone in and names
/// Everyone the owner, and takes no list it is given: there is nothing to
/// make private and no owner to check (round 6, correctness 1). Flags that
/// could not be read (`None`) count as keeping them.
pub fn keeps_lists(flags: Option<u32>) -> bool {
    const FILE_PERSISTENT_ACLS: u32 = 0x8;
    flags.is_none_or(|f| f & FILE_PERSISTENT_ACLS != 0)
}

/// Whether a buffer of `FILE_ID_BOTH_DIR_INFO` entries, as a folder's
/// listing through its handle fills it, names anything but `.` and `..`.
/// A buffer cut short counts as naming something.
pub fn names_more_than_dots(buf: &[u8]) -> bool {
    // Where the entry's next offset, its name's length in bytes and its
    // name are.
    const NAME_LEN: usize = 60;
    const NAME: usize = 104;
    let word = |at: usize| {
        buf.get(at..at + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    };
    let mut at = 0;
    loop {
        let (Some(next), Some(len)) = (word(at), word(at + NAME_LEN)) else {
            return true;
        };
        let Some(name) = buf.get(at + NAME..at + NAME + len) else {
            return true;
        };
        if name != b".\0" && name != b".\0.\0" {
            return true;
        }
        if next == 0 {
            return false;
        }
        at += next;
    }
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
    if let Some(f) = open_folder(dir, READ_CONTROL | WRITE_DAC, SHARE_ALL)? {
        if !keeps_lists(volume_flags(&f)) {
            return Ok(());
        }
        if let Some(owner) = foreign_owner(&f, mine_may_own(sddl)).map_err(|e| at(e.to_string()))? {
            let who = crate::win::sid::sid_text(&owner).unwrap_or_else(|e| e);
            let own = crate::win::process::user_of(None).is_ok_and(|me| me == owner);
            return Err(at(foreign_text(own, &who)));
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

/// The share mode of the opens that let others do what they like with the
/// folder meanwhile.
#[cfg(windows)]
const SHARE_ALL: u32 = windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
    | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE
    | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE;

/// Opens the folder `dir`, which [`private_folder`] just made, and holds it:
/// nobody can rename or delete it (share mode without delete) while the
/// returned handle lives, so a path below it keeps meaning this folder. A
/// link, or a folder that is not SYSTEM's, the administrators' or this
/// account's, is refused. The list `sddl` is set again through the held
/// handle, so the folder that is held is private whichever folder it is: one
/// swapped in by an account that may rename entries of the folder above, in
/// the moment between the two opens, gets no file made in it before that
/// (round 5, security 1). A folder with anything in it is refused before
/// its list is touched: the one just made is empty, and a folder swapped in
/// keeps its list and what is in it (round 6, correctness 2). On a volume
/// without access lists (a FAT32 stick) there is no owner to check and no
/// list to set ([`keeps_lists`]).
#[cfg(windows)]
pub fn hold_folder(dir: &Path, sddl: &str) -> Result<std::fs::File, String> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_LIST_DIRECTORY, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
    };
    let at = |e: String| format!("{}: {e}", dir.display());
    let Some(f) = open_folder(
        dir,
        FILE_LIST_DIRECTORY | READ_CONTROL | WRITE_DAC,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
    )?
    else {
        return Err(at("it is not there".into()));
    };
    let lists = keeps_lists(volume_flags(&f));
    if lists
        && foreign_owner(&f, true)
            .map_err(|e| at(e.to_string()))?
            .is_some()
    {
        return Err(at("another account owns it".into()));
    }
    if !is_empty(&f).map_err(|e| at(e.to_string()))? {
        return Err(at(
            "something is in it already, though it was made a moment ago".into(),
        ));
    }
    if lists {
        set_on(&f, sddl).map_err(at)?;
    }
    Ok(f)
}

/// The file system flags of the volume the file or folder open as `f` is
/// on; `None` when they cannot be read.
#[cfg(windows)]
fn volume_flags(f: &std::fs::File) -> Option<u32> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationByHandleW;
    let mut flags = 0u32;
    // SAFETY: an open handle; every buffer but the flags is left out.
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            f.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut flags,
            std::ptr::null_mut(),
            0,
        )
    };
    (ok != 0).then_some(flags)
}

/// Whether the folder open as `f` (with `FILE_LIST_DIRECTORY`) holds
/// nothing, listed through the handle: whatever is under its name now is
/// not what is asked.
#[cfg(windows)]
fn is_empty(f: &std::fs::File) -> std::io::Result<bool> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::ERROR_NO_MORE_FILES;
    use windows_sys::Win32::Storage::FileSystem::{
        FileIdBothDirectoryInfo, GetFileInformationByHandleEx,
    };
    // Eight-byte words: the entries are aligned so.
    let mut buf = vec![0u64; 1024];
    loop {
        // SAFETY: an open folder handle and a buffer of the size given;
        // each call goes on where the last one ended.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                f.as_raw_handle(),
                FileIdBothDirectoryInfo,
                buf.as_mut_ptr().cast(),
                (buf.len() * 8) as u32,
            )
        };
        if ok == 0 {
            let e = std::io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(c) if c == ERROR_NO_MORE_FILES as i32 => Ok(true),
                _ => Err(e),
            };
        }
        // SAFETY: the buffer's own bytes.
        let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), buf.len() * 8) };
        if names_more_than_dots(bytes) {
            return Ok(false);
        }
    }
}

/// Refuses `dir` unless it is a folder, no link, that SYSTEM or the
/// administrators own: what the installed service checks of its folders
/// before it reads its settings, so a folder put in their place after the
/// install is not taken as its own.
#[cfg(windows)]
pub fn admins_folder(dir: &Path) -> Result<(), String> {
    use windows_sys::Win32::Storage::FileSystem::READ_CONTROL;
    let at = |e: String| format!("{}: {e}", dir.display());
    let Some(f) = open_folder(dir, READ_CONTROL, SHARE_ALL)? else {
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
fn open_folder(dir: &Path, access: u32, share: u32) -> Result<Option<std::fs::File>, String> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    let at = |e: String| format!("{}: {e}", dir.display());
    let f = match std::fs::OpenOptions::new()
        .access_mode(access)
        .share_mode(share)
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
    if is_link(attributes, reparse_tag(&f)) {
        return Err(at("it is a link, and a private folder is a folder".into()));
    }
    if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(at("it is not a folder".into()));
    }
    Ok(Some(f))
}

/// The reparse tag of the file or folder open as `f`; `None` when it cannot
/// be read.
#[cfg(windows)]
fn reparse_tag(f: &std::fs::File) -> Option<u32> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_TAG_INFO, FileAttributeTagInfo, GetFileInformationByHandleEx,
    };
    // SAFETY: plain data that the call fills.
    let mut info: FILE_ATTRIBUTE_TAG_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: an open handle and a buffer of the size given.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            f.as_raw_handle() as HANDLE,
            FileAttributeTagInfo,
            (&raw mut info).cast(),
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    (ok != 0).then_some(info.ReparseTag)
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
    fn only_a_name_surrogate_reparse_point_is_a_link() {
        // A symbolic link and a junction; a cloud files placeholder; a
        // plain folder; a tag that cannot be read.
        assert!(is_link(0x410, Some(0xA000_000C)));
        assert!(is_link(0x410, Some(0xA000_0003)));
        assert!(!is_link(0x410, Some(0x9000_001A)));
        assert!(!is_link(0x10, Some(0)));
        assert!(!is_link(0x10, None));
        assert!(is_link(0x410, None));
    }

    /// A FAT32 or exFAT volume keeps no lists (its flags lack
    /// `FILE_PERSISTENT_ACLS`), so a backup there checks no owner; NTFS
    /// does, and flags that cannot be read count as NTFS's (round 6,
    /// correctness 1).
    #[test]
    fn a_volume_without_lists_has_no_owner_to_check() {
        // Flags without `FILE_PERSISTENT_ACLS` (case-preserved names,
        // Unicode on disk) and NTFS's.
        assert!(!keeps_lists(Some(0x0000_0006)));
        assert!(keeps_lists(Some(0x03E7_06FF)));
        assert!(keeps_lists(Some(0x8)));
        assert!(keeps_lists(None));
    }

    /// A folder's listing names something but `.` and `..` only where an
    /// entry does; a listing cut short counts as one that does (round 6,
    /// correctness 2).
    #[test]
    fn only_dots_are_an_empty_listing() {
        // Entries of `FILE_ID_BOTH_DIR_INFO`: the next entry's offset at 0
        // (0 for the last), the name's length in bytes at 60, the name in
        // UTF-16 at 104; each padded to eight bytes.
        let listing = |names: &[&str]| {
            let mut buf = Vec::new();
            for (i, n) in names.iter().enumerate() {
                let name: Vec<u8> = n.encode_utf16().flat_map(u16::to_le_bytes).collect();
                let size = (104 + name.len()).div_ceil(8) * 8;
                let mut e = vec![0u8; size];
                let next = if i + 1 == names.len() { 0 } else { size as u32 };
                e[..4].copy_from_slice(&next.to_le_bytes());
                e[60..64].copy_from_slice(&(name.len() as u32).to_le_bytes());
                e[104..104 + name.len()].copy_from_slice(&name);
                buf.extend(e);
            }
            buf
        };
        assert!(!names_more_than_dots(&listing(&[".", ".."])));
        assert!(!names_more_than_dots(&listing(&[".."])));
        assert!(names_more_than_dots(&listing(&[".", "..", "backup"])));
        assert!(names_more_than_dots(&listing(&["backup"])));
        assert!(names_more_than_dots(&listing(&[".", "..."])));
        let cut = listing(&[".", "..", "backup"]);
        assert!(names_more_than_dots(&cut[..cut.len() - 20]));
        assert!(names_more_than_dots(&[]));
    }

    /// The refusal says a program of the person's own made the folder, not
    /// that an intruder did, where the owner is this account (round 4,
    /// correctness 2).
    #[test]
    fn a_folder_of_one_s_own_is_not_another_account_s() {
        assert!(foreign_text(true, "S-1-5-21-1").contains("Run as administrator"));
        assert!(!foreign_text(true, "S-1-5-21-1").contains("another account"));
        let other = foreign_text(false, "S-1-5-21-1");
        assert!(other.contains("another account (S-1-5-21-1)"), "{other}");
    }

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

    /// The folder that is held gets the private list through the held
    /// handle, whatever list it came with (a folder swapped in under the
    /// name), and cannot be renamed while held (round 5, security 1).
    #[cfg(windows)]
    #[test]
    fn a_held_folder_is_made_private_and_stays_where_it_is() {
        use crate::win::sid::sid_text;
        let d = tempfile::tempdir().unwrap();
        let run = |program: &str, args: &[&str]| {
            let o = std::process::Command::new(program)
                .args(args)
                .output()
                .unwrap();
            assert!(o.status.success(), "{program} {args:?}: {o:?}");
            String::from_utf8_lossy(&o.stdout).to_string()
        };
        let dir = d.path().join("held");
        std::fs::create_dir(&dir).unwrap();
        let shown = dir.display().to_string();
        run("icacls", &[&shown, "/grant", "*S-1-1-0:(OI)(CI)F"]);
        assert!(run("icacls", &[&shown]).contains("Everyone"));
        let me = sid_text(&crate::win::process::user_of(None).unwrap()).unwrap();
        let held = hold_folder(&dir, &dacl_of(&[&me, "SY", "BA"], &[])).unwrap();
        let listed = run("icacls", &[&shown]);
        assert!(!listed.contains("Everyone"), "{listed}");
        assert!(
            std::fs::rename(&dir, d.path().join("moved")).is_err(),
            "a held folder was renamed"
        );
        drop(held);
        std::fs::rename(&dir, d.path().join("moved")).unwrap();
    }

    /// A folder with something in it is not held, and keeps its list: the
    /// folder just made is empty, and one swapped in under its name is not
    /// made private, nor what is in it deleted (round 6, correctness 2).
    #[cfg(windows)]
    #[test]
    fn a_folder_with_something_in_it_is_not_held() {
        use crate::win::sid::sid_text;
        let d = tempfile::tempdir().unwrap();
        let icacls = |args: &[&str]| {
            let o = std::process::Command::new("icacls")
                .args(args)
                .output()
                .unwrap();
            assert!(o.status.success(), "icacls {args:?}: {o:?}");
            String::from_utf8_lossy(&o.stdout).to_string()
        };
        let dir = d.path().join("held");
        std::fs::create_dir(&dir).unwrap();
        let shown = dir.display().to_string();
        icacls(&[&shown, "/grant", "*S-1-1-0:(OI)(CI)F"]);
        std::fs::write(dir.join("backup"), "the administrator's").unwrap();
        let me = sid_text(&crate::win::process::user_of(None).unwrap()).unwrap();
        let e = hold_folder(&dir, &dacl_of(&[&me, "SY", "BA"], &[])).unwrap_err();
        assert!(e.contains("something is in it"), "{e}");
        assert!(icacls(&[&shown]).contains("Everyone"));
        assert_eq!(
            std::fs::read_to_string(dir.join("backup")).unwrap(),
            "the administrator's"
        );
        // Empty, the same folder is held.
        std::fs::remove_file(dir.join("backup")).unwrap();
        drop(hold_folder(&dir, &dacl_of(&[&me, "SY", "BA"], &[])).unwrap());
    }

    /// On a FAT32 volume (what a USB stick comes with), whose folders all
    /// name Everyone their owner and take no list, the backup's folder is
    /// made, taken again and held, and a file made in it (round 6,
    /// correctness 1). Makes a virtual disk, so it needs an administrator.
    #[cfg(windows)]
    #[test]
    #[ignore = "needs an administrator: mounts a virtual disk in a folder"]
    fn a_folder_on_a_volume_without_lists_is_held() {
        use crate::win::sid::sid_text;
        let base = tempfile::tempdir().unwrap();
        let (vhd, mnt) = (base.path().join("v.vhdx"), base.path().join("mnt"));
        std::fs::create_dir(&mnt).unwrap();
        let diskpart = |script: String| {
            let file = base.path().join("diskpart.txt");
            std::fs::write(&file, script).unwrap();
            let o = std::process::Command::new("diskpart")
                .arg("/s")
                .arg(&file)
                .output()
                .unwrap();
            assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stdout));
        };
        let v = vhd.display();
        diskpart(format!(
            "create vdisk file=\"{v}\" maximum=64 type=expandable\nselect vdisk file=\"{v}\"\n\
             attach vdisk\ncreate partition primary\nformat fs=fat32 quick\n\
             assign mount=\"{}\"\n",
            mnt.display()
        ));
        // Detaches the disk however the test ends, before its folder goes.
        struct Detach(std::path::PathBuf);
        impl Drop for Detach {
            fn drop(&mut self) {
                let file = self.0.with_extension("detach.txt");
                let script = format!("select vdisk file=\"{}\"\ndetach vdisk\n", self.0.display());
                if std::fs::write(&file, script).is_ok() {
                    let _ = std::process::Command::new("diskpart")
                        .arg("/s")
                        .arg(&file)
                        .output();
                }
            }
        }
        let _detach = Detach(vhd.clone());
        let me = sid_text(&crate::win::process::user_of(None).unwrap()).unwrap();
        let own = dacl_of(&[&me, "SY", "BA"], &[]);
        let hold = mnt.join("hold");
        private_folder(&hold, &own).unwrap();
        private_folder(&hold, &own).unwrap();
        let held = hold_folder(&hold, &own).unwrap();
        assert!(!keeps_lists(volume_flags(&held)));
        std::fs::write(hold.join("backup"), "a backup").unwrap();
        drop(held);
    }
}
