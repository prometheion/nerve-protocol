//! A guard for the Slint trap of ui/widgets.slint (Reveal): an `if` element
//! is measured at its unwrapped width, so text that wraps inside one runs out
//! of the box around it. Wrapping text that comes and goes sits in a Reveal.

use std::path::Path;

/// The `if` elements of `source` that hold wrapping text, as their lines.
fn wrapping_ifs(source: &str) -> Vec<usize> {
    let lines: Vec<&str> = source.lines().collect();
    let mut found = Vec::new();
    for (at, line) in lines.iter().enumerate() {
        let code = line.trim_start();
        if !(code.starts_with("if ") && code.contains(": ") && code.ends_with('{')) {
            continue;
        }
        // The element's body, up to its closing brace.
        let mut depth = 0i32;
        for body in &lines[at..] {
            depth += body.matches('{').count() as i32 - body.matches('}').count() as i32;
            if body.contains("wrap: word-wrap")
                || body.contains("wrap: char-wrap")
                || body.contains("TextWrap.")
            {
                found.push(at + 1);
                break;
            }
            if depth <= 0 {
                break;
            }
        }
    }
    found
}

#[test]
fn no_if_holds_wrapping_text() {
    let ui = Path::new(env!("CARGO_MANIFEST_DIR")).join("ui");
    let mut bad = Vec::new();
    for entry in std::fs::read_dir(&ui).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "slint") {
            let source = std::fs::read_to_string(&path).unwrap();
            for line in wrapping_ifs(&source) {
                bad.push(format!("{}:{line}", path.display()));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "wrapping text in an `if`, use Reveal: {bad:?}"
    );
}

/// The lines of `source`, outside comments, that send the owner to a
/// terminal (a command in backticks) or to the project's source tree.
fn terminal_hints(source: &str) -> Vec<usize> {
    source
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim_start().starts_with("//"))
        .filter(|(_, l)| l.contains('`') || l.contains("docs/user/ of"))
        .map(|(at, _)| at + 1)
        .collect()
}

#[test]
fn no_text_sends_the_owner_to_a_terminal() {
    let ui = Path::new(env!("CARGO_MANIFEST_DIR")).join("ui");
    let mut bad = Vec::new();
    for entry in std::fs::read_dir(&ui).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "slint") {
            let source = std::fs::read_to_string(&path).unwrap();
            for line in terminal_hints(&source) {
                bad.push(format!("{}:{line}", path.display()));
            }
        }
    }
    assert!(bad.is_empty(), "a text that points to a terminal: {bad:?}");
}

#[test]
fn finds_wrapping_text_in_an_if() {
    let source = "VerticalLayout {\n    if a: Text {\n        wrap: word-wrap;\n    }\n    if b: Button { }\n}\n";
    assert_eq!(wrapping_ifs(source), vec![2]);
}
