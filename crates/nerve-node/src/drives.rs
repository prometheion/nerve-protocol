//! Folders a Windows node cannot hold: a network folder (`\\server\share`)
//! and a folder on a network drive. The installed node runs as its own
//! account in a session of its own, where a drive mapped at a person's
//! sign-in does not exist, and an AppContainer reaches no network folder by
//! its grants. `folder add`, the node's control pipe and the app's folder
//! picker refuse such a folder at once, with the reason, instead of a grant
//! that fails later.

/// What Windows says a drive letter is (`GetDriveTypeW`), as far as it
/// matters here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriveKind {
    /// A drive of this machine: fixed, removable, a RAM disk or a CD.
    Local,
    /// A network drive.
    Remote,
    /// No drive of that letter, for the account that asks.
    Missing,
}

/// Why the folder `path` cannot be added on Windows (`windows`), if it
/// cannot: a network folder, or one on a drive `kind_of` says is a network
/// drive or none.
pub fn refusal_for(
    path: &str,
    windows: bool,
    kind_of: impl Fn(char) -> DriveKind,
) -> Option<String> {
    if !windows {
        return None;
    }
    const OWN: &str = "Folder mode holds folders on this machine's own drives only";
    let unc = path.strip_prefix(r"\\?\UNC\").is_some()
        || ((path.starts_with(r"\\") || path.starts_with("//"))
            && !path.starts_with(r"\\?\")
            && !path.starts_with(r"\\.\"));
    if unc {
        return Some(format!("{path} is a network folder. {OWN}."));
    }
    let rest = path.strip_prefix(r"\\?\").unwrap_or(path);
    let mut chars = rest.chars();
    let (Some(letter), Some(':')) = (chars.next(), chars.next()) else {
        return None;
    };
    if !letter.is_ascii_alphabetic() {
        return None;
    }
    let drive = letter.to_ascii_uppercase();
    match kind_of(drive) {
        DriveKind::Local => None,
        DriveKind::Remote => Some(format!("{drive}: is a network drive. {OWN}.")),
        DriveKind::Missing => Some(format!(
            "{drive}: is no drive the node can see: a network drive mapped when you sign in is yours only. {OWN}."
        )),
    }
}

/// [`refusal_for`] on this machine, for the account this process runs as.
pub fn refusal(path: &str) -> Option<String> {
    refusal_for(path, cfg!(windows), kind_of)
}

#[cfg(windows)]
fn kind_of(letter: char) -> DriveKind {
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
    let root: Vec<u16> = format!("{letter}:\\")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    // SAFETY: a NUL-terminated root path.
    match unsafe { GetDriveTypeW(root.as_ptr()) } {
        // DRIVE_NO_ROOT_DIR
        1 => DriveKind::Missing,
        // DRIVE_REMOTE
        4 => DriveKind::Remote,
        _ => DriveKind::Local,
    }
}

#[cfg(not(windows))]
fn kind_of(_: char) -> DriveKind {
    DriveKind::Local
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A network folder in each spelling, and a folder on a network drive
    /// or on a drive the node cannot see, are refused with the reason; a
    /// local drive, a verbatim local path and other platforms are not.
    #[test]
    fn network_folders_and_drives_are_refused() {
        let kinds = |d: char| match d {
            'Z' => DriveKind::Remote,
            'Y' => DriveKind::Missing,
            _ => DriveKind::Local,
        };
        let refused = |p: &str| refusal_for(p, true, kinds);
        for unc in [
            r"\\server\share\work",
            "//server/share/work",
            r"\\?\UNC\server\share\work",
        ] {
            let why = refused(unc).unwrap_or_else(|| panic!("{unc} passed"));
            assert!(why.contains("is a network folder"), "{why}");
            assert!(why.contains("own drives only"), "{why}");
        }
        let why = refused(r"z:\work").unwrap();
        assert!(why.starts_with("Z: is a network drive."), "{why}");
        let why = refused(r"\\?\Z:\work").unwrap();
        assert!(why.starts_with("Z: is a network drive."), "{why}");
        let why = refused(r"Y:\work").unwrap();
        assert!(
            why.contains("mapped when you sign in is yours only"),
            "{why}"
        );
        for local in [r"C:\work", r"\\?\C:\work", r"\\.\C:\work", "work", ""] {
            assert_eq!(refused(local), None, "{local}");
        }
        assert_eq!(refusal_for(r"\\server\share", false, kinds), None);
        assert_eq!(refusal_for(r"Z:\work", false, kinds), None);
    }
}
