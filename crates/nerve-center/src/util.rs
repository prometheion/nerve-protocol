//! Small helpers shared by the center's parts.

pub use nerve_proto::msg::now_ms;
pub use nerve_proto::text::clip_bytes;
pub use nerve_transport::keys::{ct_eq, sha256_hex};
pub use nerve_transport::log::span;

/// A UUID-shaped random id (spec §2.1).
pub fn random_id() -> String {
    let h = nerve_proto::msg::hex(&nerve_transport::keys::random_bytes(16));
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// `ms` since the epoch as `2026-10-25 14:05 UTC`.
pub fn utc_minute(ms: u64) -> String {
    let mins = ms / 60_000;
    let (days, rest) = ((mins / 1440) as i64, mins % 1440);
    // Days to a civil date (Howard Hinnant's algorithm), for any day after
    // 1970.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        rest / 60,
        rest % 60
    )
}

/// A folder's path as Windows compares it: separators of one kind, no `\\?\`
/// prefix, no `.`, `..`, empty or trailing parts, and no case. Lexical, so
/// it holds for a folder that is not there; [`same_folder`] adds what the
/// disk says.
pub fn folder_key(path: &str) -> String {
    let path = path.replace('/', "\\");
    let path = path.strip_prefix("\\\\?\\").unwrap_or(&path);
    let mut parts: Vec<String> = Vec::new();
    for part in path.split('\\') {
        match part {
            "" | "." => {}
            ".." => {
                // The drive or the share is the root: nothing above it.
                if parts.len() > 1 {
                    parts.pop();
                }
            }
            p => parts.push(p.to_lowercase()),
        }
    }
    parts.join("\\")
}

/// Whether `a` and `b` are the same folder on Windows, however each is
/// spelled (forward slashes, a trailing separator, a relative path, another
/// case, a link). A path that is not there is compared as written.
pub fn same_folder(a: &std::path::Path, b: &std::path::Path) -> bool {
    let key = |p: &std::path::Path| {
        let p = std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
        folder_key(&p.to_string_lossy())
    };
    if key(a) == key(b) {
        return true;
    }
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => folder_key(&a.to_string_lossy()) == folder_key(&b.to_string_lossy()),
        _ => false,
    }
}

/// Whether a state folder keeps the access list `install` gave it instead
/// of getting its account's own: it is the installed center's folder
/// (`is_the_folder`), and that center's service is registered or this
/// process is the service. Anywhere else (a center a harness started on
/// that path before any install) the folder is made private to its account,
/// as the Linux 0700 is; the service may be installed over it later.
pub fn keeps_installed_dacl(is_the_folder: bool, registered: bool, is_the_service: bool) -> bool {
    is_the_folder && (registered || is_the_service)
}

/// Makes the state folder `state` private, as 0700 is on Unix: on Windows a
/// DACL of its own for this account, SYSTEM and the administrators, which
/// what is in it (the owner token, the TLS key, the state) inherits; a
/// folder another account made is refused. The installed center's folder
/// keeps the DACL `install` gave it, which its service and the
/// administrators share (crate::winsvc).
pub fn private_state(state: &std::path::Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        let layout = crate::service::Layout::system();
        let is_the_folder = layout.is_state(state);
        // Only where something is registered the service's account has its
        // place in the DACL to lose.
        let keep = keeps_installed_dacl(
            is_the_folder,
            is_the_folder && layout.installed(),
            nerve_service::win::dispatch::is_service(),
        );
        if !keep {
            return nerve_service::win::dacl::private_folder(state, &own_dacl()?);
        }
    }
    nerve_transport::files::create_private_dir(state)
        .map_err(|e| format!("cannot create {}: {e}", state.display()))
}

/// Makes the file `path` this account's, SYSTEM's and the administrators'
/// alone on Windows, whatever its folder hands down (a backup in the
/// downloads); elsewhere its mode did that already.
pub fn private_file(path: &std::path::Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        let dacl = own_dacl()?;
        nerve_service::win::dacl::set(path, &dacl.replace("(A;OICI;", "(A;;"))
            .map_err(|e| format!("{}: {e}", path.display()))?;
    }
    #[cfg(not(windows))]
    let _ = path;
    Ok(())
}

/// The protected DACL of what this account keeps private on Windows.
#[cfg(windows)]
fn own_dacl() -> Result<String, String> {
    let me = nerve_service::win::process::user_of(None)
        .map_err(|e| format!("cannot read this account's SID: {e}"))?;
    let me = nerve_service::win::sid::sid_text(&me)?;
    Ok(nerve_service::win::dacl::dacl_of(&[&me, "SY", "BA"], &[]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every spelling of one Windows folder is one key (round 1, correctness
    /// 2): the installed center's folder is found whichever way an
    /// administrator names it, and another folder is not it.
    #[test]
    fn a_windows_folder_has_one_key_whatever_its_spelling() {
        let key = folder_key(r"C:\ProgramData\nerve-center\state");
        assert_eq!(key, r"c:\programdata\nerve-center\state");
        for spelled in [
            "C:/ProgramData/nerve-center/state",
            r"C:\ProgramData\nerve-center\state\",
            r"c:\programdata\NERVE-CENTER\State",
            r"C:\ProgramData\\nerve-center\.\state",
            r"C:\ProgramData\other\..\nerve-center\state",
            r"\\?\C:\ProgramData\nerve-center\state",
        ] {
            assert_eq!(folder_key(spelled), key, "{spelled}");
        }
        for other in [
            r"C:\ProgramData\nerve-center",
            r"C:\ProgramData\nerve-center\state\run",
            r"D:\ProgramData\nerve-center\state",
            r"C:\ProgramData\nerve-center\states",
        ] {
            assert_ne!(folder_key(other), key, "{other}");
        }
        // Nothing is above the drive.
        assert_eq!(folder_key(r"C:\..\..\a"), r"c:\a");
    }

    /// The same folder is found by its path through the disk too.
    #[test]
    fn a_folder_is_the_same_by_another_path_to_it() {
        let d = tempfile::tempdir().unwrap();
        let state = d.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        assert!(same_folder(
            &state,
            &d.path().join("x").join("..").join("state")
        ));
        assert!(same_folder(&state, &state.join("")));
        assert!(!same_folder(&state, d.path()));
        assert!(!same_folder(&state, &d.path().join("none")));
    }

    /// A folder keeps the installed DACL only while the service is there
    /// (round 1, security 4): before an install, a center on that path gets
    /// the private DACL of its account.
    #[test]
    fn the_installed_dacl_is_kept_only_where_the_service_is() {
        assert!(keeps_installed_dacl(true, true, false));
        assert!(keeps_installed_dacl(true, false, true));
        assert!(!keeps_installed_dacl(true, false, false));
        assert!(!keeps_installed_dacl(false, true, true));
    }

    #[test]
    fn helpers() {
        let id = random_id();
        assert_eq!(id.len(), 36);
        assert_eq!(id.matches('-').count(), 4);
    }

    #[test]
    fn a_time_is_written_in_utc_to_the_minute() {
        assert_eq!(utc_minute(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc_minute(1_792_936_800_000), "2026-10-25 14:00 UTC");
        assert_eq!(
            utc_minute(1_709_251_140_000 + 59_999),
            "2024-02-29 23:59 UTC"
        );
        assert_eq!(utc_minute(4_107_542_400_000), "2100-03-01 00:00 UTC");
        // A node may send any number; it is written, not refused.
        assert!(utc_minute(u64::MAX).ends_with(" UTC"));
    }
}
