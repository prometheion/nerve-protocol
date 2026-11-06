//! The user guide stays short (docs/dev/README.md, "Writing user docs"):
//! each page of `docs/user/` and the README keeps its word budget, with 20 %
//! to spare, and a table cell stays one line, at most 40 words. A page that
//! needs more holds something that belongs in `docs/dev/`.

use std::path::{Path, PathBuf};

/// Each user page and its budget in words. A new page needs a line here.
const BUDGETS: &[(&str, usize)] = &[
    ("README.md", 900),
    ("docs/user/README.md", 250),
    ("docs/user/install.md", 1500),
    ("docs/user/center.md", 1200),
    ("docs/user/pair.md", 1200),
    ("docs/user/folders-and-modes.md", 1800),
    ("docs/user/network.md", 450),
    ("docs/user/rules.md", 1800),
    ("docs/user/capabilities.md", 1100),
    ("docs/user/web-uis.md", 1600),
    ("docs/user/action-checker.md", 900),
    ("docs/user/settings.md", 900),
    ("docs/user/backup.md", 600),
    ("docs/user/watch-and-stop.md", 900),
    ("docs/user/troubleshooting.md", 1500),
    ("docs/user/commands.md", 600),
    ("docs/user/safety.md", 700),
];

/// The most words a table cell may have.
const CELL_WORDS: usize = 40;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn words(text: &str) -> usize {
    text.split_whitespace().count()
}

/// The cells of a table row: the text between its unescaped `|`s.
fn cells(row: &str) -> Vec<String> {
    let mut cells = Vec::new();
    let mut cell = String::new();
    let mut chars = row.trim().trim_start_matches('|').chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&'|') => cell.push(chars.next().unwrap()),
            '|' => cells.push(std::mem::take(&mut cell)),
            c => cell.push(c),
        }
    }
    if !cell.trim().is_empty() {
        cells.push(cell);
    }
    cells
}

/// What is wrong with one page: over its budget by more than 20 %, or a
/// table cell over [`CELL_WORDS`].
fn faults(name: &str, text: &str, budget: usize) -> Vec<String> {
    let mut found = Vec::new();
    let n = words(text);
    if n * 5 > budget * 6 {
        found.push(format!(
            "{name}: {n} words, over its budget of {budget} by more than 20 %: move the depth to docs/dev/"
        ));
    }
    let mut fence = false;
    for (i, line) in text.lines().enumerate() {
        if line.starts_with("```") {
            fence = !fence;
        }
        if fence || !line.trim_start().starts_with('|') {
            continue;
        }
        for cell in cells(line) {
            if words(&cell) > CELL_WORDS {
                found.push(format!(
                    "{name}:{}: a table cell of {} words (at most {CELL_WORDS}): make it a link",
                    i + 1,
                    words(&cell)
                ));
            }
        }
    }
    found
}

#[test]
fn every_user_page_keeps_its_budget() {
    let mut found = Vec::new();
    for (name, budget) in BUDGETS {
        let text =
            std::fs::read_to_string(root().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        found.extend(faults(name, &text, *budget));
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
}

#[test]
fn every_user_page_has_a_budget() {
    let mut pages: Vec<String> = std::fs::read_dir(root().join("docs/user"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|f| f.ends_with(".md"))
        .map(|f| format!("docs/user/{f}"))
        .collect();
    pages.sort();
    let unlisted: Vec<&String> = pages
        .iter()
        .filter(|p| !BUDGETS.iter().any(|(name, _)| name == p))
        .collect();
    assert!(unlisted.is_empty(), "pages without a budget: {unlisted:?}");
}

/// The checks themselves: a page just within 20 % passes, one past it
/// fails, and a long cell fails while an escaped `|` splits none.
#[test]
fn the_budget_and_the_cell_limit_are_held() {
    let page = |n: usize| vec!["word"; n].join(" ");
    assert!(faults("p", &page(120), 100).is_empty());
    assert_eq!(faults("p", &page(121), 100).len(), 1);
    let long = format!("| a | {} |\n", page(41));
    assert_eq!(faults("p", &long, 1000).len(), 1, "{long}");
    let fine = format!("| a | {} |\n", page(40));
    assert!(faults("p", &fine, 1000).is_empty());
    let piped = format!("| `a \\| b` {} |\n", page(39));
    assert_eq!(cells(&piped).len(), 1, "{:?}", cells(&piped));
    // A table in a code block is no table.
    let fenced = format!("```\n| {} |\n```\n", page(41));
    assert!(faults("p", &fenced, 1000).is_empty());
}

/// Every page of the docs that the code names (a comment, a message, a help
/// link) is there: a page that moves takes its names in the code along.
#[test]
fn every_doc_page_the_code_names_exists() {
    fn walk(dir: &Path, found: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, found);
                continue;
            }
            let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
                continue;
            };
            if !["rs", "slint", "js", "json", "html"].contains(&ext) {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            for (i, line) in text.lines().enumerate() {
                for kind in ["docs/user/", "docs/dev/"] {
                    for (at, _) in line.match_indices(kind) {
                        let name: String = line[at..]
                            .chars()
                            .take_while(|c| c.is_ascii_alphanumeric() || "/-_.".contains(*c))
                            .collect();
                        let name = name.trim_end_matches('.');
                        if !name.ends_with(".md") {
                            continue;
                        }
                        if !root().join(name).exists() {
                            found.push(format!("{}:{}: {name}", path.display(), i + 1));
                        }
                    }
                }
            }
        }
    }
    let mut found = Vec::new();
    walk(&root().join("crates"), &mut found);
    // A test that feeds a made-up command its own path of the docs.
    found.retain(|f| !f.contains("nerve-policy/tests/guard.rs"));
    assert!(found.is_empty(), "{}", found.join("\n"));
}
