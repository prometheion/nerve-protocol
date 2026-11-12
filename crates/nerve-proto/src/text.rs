//! Text cut to a size, with an ellipsis where something was cut: what the
//! node, the center and their logs repeat of a peer's text is bounded, and
//! cut the same way everywhere. Text put on one line is flattened the same
//! way everywhere too.

/// Whether `c` starts a line, or acts on a terminal, where text is shown:
/// a control character (C0, DEL and C1, `\n` and `\r` among them) or the
/// Unicode line and paragraph separators U+2028 and U+2029.
pub fn breaks_line(c: char) -> bool {
    c.is_control() || matches!(c, '\u{2028}' | '\u{2029}')
}

/// `text` on one line: each character that [`breaks_line`] becomes a space.
pub fn one_line(text: &str) -> String {
    text.chars()
        .map(|c| if breaks_line(c) { ' ' } else { c })
        .collect()
}

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

    /// Every character that starts a line where text is shown becomes a
    /// space, the Unicode separators too; any other stays.
    #[test]
    fn one_line_flattens_every_line_break() {
        assert_eq!(
            one_line("a\nb\rc\u{85}d\u{2028}e\u{2029}f\u{1b}g\u{7f}h\ti"),
            "a b c d e f g h i"
        );
        assert_eq!(one_line("ä\u{200b}[x]"), "ä\u{200b}[x]");
        assert!(breaks_line('\u{2028}') && breaks_line('\u{9b}'));
        assert!(!breaks_line('\u{2027}') && !breaks_line(' '));
    }
}
