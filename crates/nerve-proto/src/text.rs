//! Text cut to a size, with an ellipsis where something was cut: what the
//! node, the center and their logs repeat of a peer's text is bounded, and
//! cut the same way everywhere.

/// `text` cut to at most `max` characters, with an ellipsis when something
/// was cut.
pub fn clip(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        Some((end, _)) => format!("{}…", &text[..end]),
        None => text.to_string(),
    }
}

/// `text` cut to at most `max` bytes on a character boundary, with an
/// ellipsis when something was cut: for a field whose limit is in bytes.
pub fn clip_bytes(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_text_is_cut_by_characters_or_by_bytes() {
        assert_eq!(clip("äöü", 2), "äö…");
        assert_eq!(clip("äöü", 3), "äöü");
        assert_eq!(clip("", 0), "");
        assert_eq!(clip("a", 0), "…");
        assert_eq!(clip_bytes("äöü", 3), "ä…");
        assert_eq!(clip_bytes("abc", 3), "abc");
        assert_eq!(clip_bytes("abcd", 3), "abc…");
    }
}
