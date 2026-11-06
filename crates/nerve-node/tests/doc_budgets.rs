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

/// What a user needs to know about a limit stays on its page, shortened:
/// each line is a page and a text it keeps (the review rounds found these
/// cut). Plan: a limit is shortened, never cut.
#[test]
fn the_user_pages_keep_the_limits_a_user_needs() {
    const KEPT: &[(&str, &str)] = &[
        // A result carries 1 MiB at most, whatever the cap says.
        ("docs/user/settings.md", "a result carries 1 MiB at most"),
        // A command as you can change the node's settings.
        (
            "docs/user/safety.md",
            "A command that runs as you can change the node's settings",
        ),
        (
            "docs/user/folders-and-modes.md",
            "change the node's settings as you can",
        ),
        ("docs/user/troubleshooting.md", "One that runs as you"),
        // What a stop leaves running.
        ("docs/user/watch-and-stop.md", "keeps running"),
        // A center's own capabilities: only those that sense or act wait.
        (
            "docs/user/rules.md",
            "one that senses\nor acts waits for your `on`",
        ),
        // Without Landlock the pairings reach each other's commands.
        (
            "docs/user/network.md",
            "a command of another pairing that has the network",
        ),
        (
            "docs/user/safety.md",
            "the homes, the folders and the running commands of the others, with their network",
        ),
        (
            "docs/user/folders-and-modes.md",
            "the homes, the folders and the running commands of the others, with their network",
        ),
        // Taking the grant back leaves what the center added.
        ("docs/user/rules.md", "That leaves what it added"),
        // A stop leaves a command's own leftovers when it ran as you.
        (
            "docs/user/watch-and-stop.md",
            "or your own for a command that ran as you",
        ),
        // A panic ends sessions, not tokens.
        ("docs/user/web-uis.md", "A panic ends sessions, not tokens"),
        // A relay token reaches what the relay's centers' address serves.
        (
            "docs/user/pair.md",
            "also other sites a reverse proxy serves there",
        ),
        // The round 3 limits: the sudo form, what a mode change leaves, `x`
        // reading by name, a foreign backup, the keyring and its clients.
        (
            "docs/user/rules.md",
            "puts your password into a page the center serves",
        ),
        (
            "docs/user/watch-and-stop.md",
            "the end of a `--for` does not stop a command",
        ),
        (
            "docs/user/folders-and-modes.md",
            "can also read its files by name, not list them",
        ),
        (
            "docs/user/backup.md",
            "Restore only a backup you made yourself",
        ),
        ("docs/user/settings.md", "hands a center the node's keys"),
        ("docs/user/backup.md", "one that has its token keeps it"),
        // The relay link holds a secret.
        ("docs/user/pair.md", "The link holds the relay token"),
    ];
    let mut missing = Vec::new();
    for (name, text) in KEPT {
        let page = std::fs::read_to_string(root().join(name)).unwrap();
        // Lines wrap anywhere: compare the words.
        let flat = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
        if !flat(&page).contains(&flat(text)) {
            missing.push(format!("{name}: {text}"));
        }
    }
    assert!(missing.is_empty(), "{}", missing.join("\n"));
    // One thing a page must not say: that a center's command cannot change
    // the node, as `user` mode commands can.
    let trouble = std::fs::read_to_string(root().join("docs/user/troubleshooting.md")).unwrap();
    assert!(
        !trouble.contains("A command a center runs cannot"),
        "troubleshooting.md says a center's command cannot change the node"
    );
    let stop = std::fs::read_to_string(root().join("docs/user/watch-and-stop.md")).unwrap();
    assert!(
        !stop.contains("kills it with everything it"),
        "watch-and-stop.md says a stop kills everything the command started"
    );
}

/// Every page of the docs that the code and the dev docs name (a comment, a
/// message, a help link, a spec's reference) is there: a page that moves
/// takes its names along.
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
            if !["rs", "slint", "js", "json", "html", "md"].contains(&ext) {
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
    walk(&root().join("docs/dev"), &mut found);
    // A test that feeds a made-up command its own path of the docs.
    found.retain(|f| !f.contains("nerve-policy/tests/guard.rs"));
    assert!(found.is_empty(), "{}", found.join("\n"));
}
