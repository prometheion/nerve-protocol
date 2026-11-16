//! The app's text is easy to read in light and dark: each text colour of
//! ui/theme.slint has a contrast of at least 4.5:1 (WCAG AA for body text)
//! against every surface it stands on.

use std::collections::HashMap;
use std::path::Path;

/// The colours of the theme, light and dark, by name.
fn colours() -> HashMap<String, ([f64; 3], [f64; 3])> {
    let theme =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("ui/theme.slint"))
            .unwrap();
    let hex = |h: &str| -> [f64; 3] {
        let h = h.trim().trim_start_matches('#');
        let c = |i: usize| f64::from(u8::from_str_radix(&h[i..i + 2], 16).unwrap()) / 255.0;
        [c(0), c(2), c(4)]
    };
    let mut out = HashMap::new();
    for line in theme.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("out property <color> ") else {
            continue;
        };
        let Some((name, value)) = rest.split_once(": dark ? ") else {
            continue;
        };
        let Some((dark, light)) = value.trim_end_matches(';').split_once(" : ") else {
            continue;
        };
        out.insert(name.to_string(), (hex(light), hex(dark)));
    }
    out
}

fn luminance([r, g, b]: [f64; 3]) -> f64 {
    let f = |c: f64| {
        if c <= 0.03928 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)
}

fn contrast(a: [f64; 3], b: [f64; 3]) -> f64 {
    let (la, lb) = (luminance(a), luminance(b));
    (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
}

#[test]
fn every_text_colour_is_readable_on_every_surface() {
    let c = colours();
    let mut bad = Vec::new();
    let check = |bad: &mut Vec<String>, text: &str, under: &str| {
        let (tl, td) = c[text];
        let (ul, ud) = c[under];
        for (scheme, t, u) in [("light", tl, ul), ("dark", td, ud)] {
            let r = contrast(t, u);
            if r < 4.5 {
                bad.push(format!("{text} on {under} ({scheme}): {r:.2}"));
            }
        }
    };
    for text in [
        "text",
        "text-muted",
        "text-faint",
        "accent-text",
        "ok",
        "warn",
        "danger",
    ] {
        for under in ["window", "sidebar", "surface", "surface-alt", "inset"] {
            check(&mut bad, text, under);
        }
    }
    // Text on the soft colour of its tone: pills, banners, the selected
    // page.
    for (text, under) in [
        ("accent-text", "accent-soft"),
        ("ok", "ok-soft"),
        ("warn", "warn-soft"),
        ("danger", "danger-soft"),
        ("text", "accent-soft"),
        ("text-muted", "accent-soft"),
        ("text-muted", "ok-soft"),
        ("text-muted", "warn-soft"),
        ("text-muted", "danger-soft"),
    ] {
        check(&mut bad, text, under);
    }
    // The label of a primary button.
    for (text, under) in [("on-accent", "accent"), ("on-danger", "danger")] {
        check(&mut bad, text, under);
    }
    assert!(bad.is_empty(), "too little contrast: {bad:#?}");
}
