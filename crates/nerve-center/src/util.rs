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

/// `s` cut to at most `max` bytes, keeping its start and its end (at most
/// `max / 2` bytes of the start, the rest from the end) with an ellipsis
/// between, on character boundaries. For text whose end matters as much as
/// its start, such as a command line.
pub fn clip_ends(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut head = max / 2;
    while !s.is_char_boundary(head) {
        head -= 1;
    }
    let mut tail = s.len() - (max - max / 2);
    while !s.is_char_boundary(tail) {
        tail += 1;
    }
    format!("{}…{}", &s[..head], &s[tail..])
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
        assert_eq!(clip_ends("abcdefgh", 8), "abcdefgh");
        assert_eq!(clip_ends("abcdefghij", 5), "ab…hij");
        // Never inside a character: the head shrinks, the tail starts later.
        assert_eq!(clip_ends("äöüß", 5), "ä…ß");
        assert_eq!(clip_ends("äöüß", 4), "ä…ß");
    }
}
