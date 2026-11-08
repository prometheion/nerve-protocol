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

/// Makes the state folder `state` private, as 0700 is on Unix: on Windows a
/// DACL of its own for this account, SYSTEM and the administrators, which
/// what is in it (the owner token, the TLS key, the state) inherits; a
/// folder another account made is refused. The installed center's folder
/// keeps the DACL `install` gave it, which its service and the
/// administrators share (crate::winsvc).
pub fn private_state(state: &std::path::Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        let installed = crate::service::Layout::system().state;
        let same = |a: &std::path::Path, b: &std::path::Path| {
            a.to_string_lossy()
                .eq_ignore_ascii_case(&b.to_string_lossy())
        };
        if !same(state, &installed) {
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
