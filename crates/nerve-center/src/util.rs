//! Small helpers shared by the center's parts.

pub use nerve_proto::msg::now_ms;
pub use nerve_transport::log::span;

/// Compares two byte strings in time that depends only on their lengths.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn sha256_hex(data: &[u8]) -> String {
    nerve_proto::msg::hex(ring::digest::digest(&ring::digest::SHA256, data).as_ref())
}

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

/// `s` cut to at most `max` bytes on a character boundary, with an ellipsis
/// when something was cut.
pub fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        let id = random_id();
        assert_eq!(id.len(), 36);
        assert_eq!(id.matches('-').count(), 4);
        assert_eq!(clip("äöü", 3), "ä…");
        assert_eq!(clip("abc", 3), "abc");
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
