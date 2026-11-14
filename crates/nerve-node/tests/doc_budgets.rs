//! The user guide stays short (docs/dev/README.md, "Writing user docs"):
//! each page of `docs/user/` and the README keeps its word budget, with 20 %
//! to spare, and a table cell stays one line, at most 40 words. A page that
//! needs more holds something that belongs in `docs/dev/`.

use std::path::{Path, PathBuf};

/// Each user page and its budget in words. A new page needs a line here.
const BUDGETS: &[(&str, usize)] = &[
    ("README.md", 900),
    ("docs/user/README.md", 300),
    ("docs/user/install.md", 1500),
    ("docs/user/windows.md", 1400),
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
    ("docs/user/safety.md", 1200),
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
        // Taking the grant back leaves what the center added; the command
        // says what (#197).
        (
            "docs/user/rules.md",
            "That leaves what it changed, still on: `center settings off` names each part",
        ),
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
        // The round 4 limits: safety.md holding every limit of the task
        // pages, and the link in the process list. Only the owner puts a
        // command on the sudo list since #197.
        (
            "docs/user/rules.md",
            "Nor\nmay it put a command on the sudo list",
        ),
        (
            "docs/user/safety.md",
            "Taking the grant back leaves what the center changed, still on.\n  `center settings off` names it",
        ),
        (
            "docs/user/safety.md",
            "puts your password into a page the center serves",
        ),
        (
            "docs/user/safety.md",
            "can also read its files by name, not list them",
        ),
        ("docs/user/safety.md", "a program a command left running"),
        ("docs/user/safety.md", "does not stop a running command"),
        (
            "docs/user/safety.md",
            "is readable by every account, and by other pairings' commands unless they have a `/proc` of their own",
        ),
        ("docs/user/safety.md", "tells programs apart, not users"),
        ("docs/user/safety.md", "the keyring is yours"),
        ("docs/user/safety.md", "restore only one you made yourself"),
        ("docs/user/safety.md", "A relay token reaches"),
        (
            "docs/user/safety.md",
            "A panic ends web UI sessions, not tokens",
        ),
        (
            "docs/user/pair.md",
            "the link is\n   in the process list, which any account can read",
        ),
        // The round 5 limits: the secrets that land in the process list or
        // the shell's history.
        (
            "docs/user/safety.md",
            "A pairing or relay link given as an argument is in the process list",
        ),
        (
            "docs/user/safety.md",
            "The `claude mcp add` line holds the harness token",
        ),
        // The round 6 limits: one center's command lines are open to the
        // others.
        (
            "docs/user/safety.md",
            "Put no secret in a command or a capability's line",
        ),
        (
            "docs/dev/settings-and-config.md",
            "`network off` does not remove them",
        ),
        // The relay link holds a secret.
        ("docs/user/pair.md", "The link holds the relay token"),
        // The Windows limits (R): each on the Windows page, in safety.md,
        // and the policy's.
        ("docs/user/safety.md", "UAC is no boundary"),
        ("docs/user/windows.md", "UAC is no boundary"),
        (
            "docs/user/safety.md",
            "Your Windows password is stored on disk, sealed for this machine (DPAPI); only the folder's access list guards it",
        ),
        (
            "docs/user/windows.md",
            "Your Windows password is stored on disk, sealed for this machine (DPAPI); only the folder's access list guards it",
        ),
        (
            "docs/user/safety.md",
            "The administrators and the Backup Operators can read the node's keys and your stored password",
        ),
        (
            "docs/user/windows.md",
            "The administrators and the Backup Operators can read the node's keys and your stored password",
        ),
        (
            "docs/user/safety.md",
            "A folder mode command reads the Windows folder and Program Files",
        ),
        (
            "docs/user/windows.md",
            "A folder mode command reads the Windows folder and Program Files",
        ),
        (
            "docs/user/safety.md",
            "Pipes, RPC and COM servers open to every AppContainer are open to the commands",
        ),
        (
            "docs/user/windows.md",
            "Pipes, RPC and COM servers open to every AppContainer are open to the commands",
        ),
        (
            "docs/user/safety.md",
            "Work started through WMI, the task scheduler or a service runs outside the command's job",
        ),
        (
            "docs/user/windows.md",
            "Work started through WMI, the task scheduler or a service runs outside the command's job",
        ),
        (
            "docs/user/safety.md",
            "Sudo commands run as you with your administrator rights, outside the container and the folders",
        ),
        (
            "docs/user/windows.md",
            "Sudo commands run as you with your administrator rights, outside the container and the folders",
        ),
        (
            "docs/user/safety.md",
            "With the Firewall service stopped, a pairing whose network is off runs no command",
        ),
        (
            "docs/user/windows.md",
            "With the Firewall service stopped, a pairing whose network is off runs no command",
        ),
        (
            "docs/user/safety.md",
            "The guard does not catch a service or task made by writing the registry or the Tasks folder directly, the Startup folder, or WMI",
        ),
        (
            "docs/user/windows.md",
            "The guard does not catch a service or task made by writing the registry or the Tasks folder directly, the Startup folder, or WMI",
        ),
        ("docs/user/safety.md", "The programs are not signed"),
        // What an uninstall that keeps the data keeps.
        (
            "docs/user/windows.md",
            "The data holds your stored Windows password too, open to the administrators: **Delete the data** deletes it",
        ),
        // The settings grant reaches an administrator owner's rights.
        (
            "docs/user/safety.md",
            "With root as the owner (on Windows an administrator), a center with the settings grant can switch itself to `user` mode",
        ),
        // A harness token in a flag is in the process list.
        (
            "docs/user/center.md",
            "`--harness-token` does too, but shows it in the process list",
        ),
        ("docs/user/windows.md", "The programs are not signed"),
        ("SECURITY.md", "UAC is no boundary"),
        (
            "SECURITY.md",
            "the config folder's access list is its only guard",
        ),
        ("SECURITY.md", "an administrator or a Backup Operator"),
        ("SECURITY.md", "The guard has named holes"),
        ("SECURITY.md", "The programs are not signed"),
        // Work done for a command leaves its job, not a folder mode
        // command's container: a way out of the container is in scope.
        (
            "SECURITY.md",
            "runs outside its job and its limits. A `folder` mode command's container keeps the usual tools from them",
        ),
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
    let pair = std::fs::read_to_string(root().join("docs/user/pair.md")).unwrap();
    assert!(
        !pair.contains("cannot tell whether others"),
        "pair.md says a center cannot tell that other centers exist"
    );
    let stop = std::fs::read_to_string(root().join("docs/user/watch-and-stop.md")).unwrap();
    assert!(
        !stop.contains("kills it with everything it"),
        "watch-and-stop.md says a stop kills everything the command started"
    );
}

/// Every page of the docs that the code and the dev docs name (a comment, a
/// message, a help link, a spec's reference) is there, and so is a heading
/// named with it: a page or section that moves takes its names along.
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
                            continue;
                        }
                        // A section named after the page, `page.md, "Heading"`
                        // (in a Rust string `\"`), whole on this line, is there,
                        // as a heading or a paragraph's bold lead: a message
                        // sends the owner to it.
                        let rest = &line[at + name.len()..];
                        let named = rest
                            .strip_prefix(", \\\"")
                            .and_then(|r| r.split_once("\\\""))
                            .or_else(|| rest.strip_prefix(", \"").and_then(|r| r.split_once('"')));
                        if let Some((heading, _)) = named {
                            let page = std::fs::read_to_string(root().join(name)).unwrap();
                            let there = page.lines().any(|l| {
                                l.starts_with('#') && l.trim_start_matches('#').trim() == heading
                            }) || page.contains(&format!("**{heading}.**"));
                            if !there {
                                found.push(format!(
                                    "{}:{}: {name} has no heading {heading:?}",
                                    path.display(),
                                    i + 1
                                ));
                            }
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

/// The anchors GitHub gives the headings of a Markdown page: the heading in
/// lower case, without its punctuation, a blank as `-`, and `-1`, `-2` after
/// a heading that came before.
fn anchors(page: &str) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    let mut out = Vec::new();
    let mut fence = false;
    for line in page.lines() {
        if line.starts_with("```") {
            fence = !fence;
        }
        let Some(heading) = line.trim_start_matches('#').strip_prefix(' ') else {
            continue;
        };
        if fence || !line.starts_with('#') {
            continue;
        }
        let slug: String = heading
            .trim()
            .to_lowercase()
            .chars()
            .filter(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | ' '))
            .map(|c| if c == ' ' { '-' } else { c })
            .collect();
        let n = seen.iter().filter(|s| **s == slug).count();
        out.push(if n == 0 {
            slug.clone()
        } else {
            format!("{slug}-{n}")
        });
        seen.push(slug);
    }
    out
}

/// Every link of the guide, the README, the policy and the dev docs to
/// another page of the repository leads to a file that is there, and to a
/// heading of it that is there: the Windows page and the limits link into
/// the dev pages by their headings, which move.
#[test]
fn every_link_of_the_docs_leads_to_a_page_and_heading_that_exist() {
    let mut pages = vec![
        root().join("README.md"),
        root().join("SECURITY.md"),
        root().join("CONTRIBUTING.md"),
    ];
    fn md(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                md(&p, out);
            } else if p.extension().is_some_and(|e| e == "md") {
                out.push(p);
            }
        }
    }
    md(&root().join("docs"), &mut pages);
    let mut found = Vec::new();
    for page in &pages {
        let text = std::fs::read_to_string(page).unwrap();
        let mut fence = false;
        for (i, line) in text.lines().enumerate() {
            if line.starts_with("```") {
                fence = !fence;
            }
            if fence {
                continue;
            }
            for (at, _) in line.match_indices("](") {
                let link: String = line[at + 2..]
                    .chars()
                    .take_while(|c| *c != ')' && !c.is_whitespace())
                    .collect();
                if link.contains(':') && !link.starts_with('#') {
                    continue;
                }
                let (file, anchor) = link.split_once('#').unwrap_or((&link, ""));
                let target = if file.is_empty() {
                    page.clone()
                } else {
                    page.parent().unwrap().join(file)
                };
                let at = format!("{}:{}: {link}", page.display(), i + 1);
                if !target.exists() {
                    found.push(format!("{at}: no such file"));
                } else if !anchor.is_empty()
                    && target.extension().is_some_and(|e| e == "md")
                    && !anchors(&std::fs::read_to_string(&target).unwrap())
                        .iter()
                        .any(|a| a == anchor)
                {
                    found.push(format!("{at}: no such heading"));
                }
            }
        }
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
    // The rule for a heading's anchor, on the forms these pages use.
    assert_eq!(
        anchors(
            "# The control pipe is not the node's (Windows)\n## `nerve-run`, a home\n## A\n## A\n"
        ),
        [
            "the-control-pipe-is-not-the-nodes-windows",
            "nerve-run-a-home",
            "a",
            "a-1"
        ]
    );
}

/// Every `.rs`, `.js`, `.md` and `.json` file below `dir`, except build
/// output and this crate's tests.
fn text_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        let name = e.file_name();
        let name = name.to_string_lossy();
        if p.is_dir() {
            if !matches!(&*name, "target" | ".git" | "node_modules" | ".reviews") {
                text_files(&p, out);
            }
        } else if matches!(
            p.extension().and_then(|e| e.to_str()),
            Some("rs" | "js" | "md" | "json")
        ) {
            out.push(p);
        }
    }
}

/// The hints and docs teach a pairing link and a relay link on stdin
/// (`center add -`, `proxy set -`), never as an argument, which every
/// process of the machine reads while the command waits (#198; round 1,
/// spec 1 and 2, security 5). A line that checks a text to be absent, as
/// an assert does, may name the argument form.
#[test]
fn no_hint_teaches_a_pairing_or_relay_link_as_an_argument() {
    // Written in parts so that this file does not match itself.
    let forms = [
        ["center", " add '"].concat(),
        ["center", " add <"].concat(),
        ["center", " add \""].concat(),
        ["proxy", " set 'https"].concat(),
        ["proxy", " set \"https"].concat(),
    ];
    let mut files = Vec::new();
    text_files(&root().join("crates"), &mut files);
    text_files(&root().join("docs"), &mut files);
    files.push(root().join("README.md"));
    let mut found = Vec::new();
    for f in files {
        let Ok(text) = std::fs::read_to_string(&f) else {
            continue;
        };
        for (n, line) in text.lines().enumerate() {
            let checks_absence = line.contains("contains(") && line.contains("assert");
            if !checks_absence && forms.iter().any(|form| line.contains(form.as_str())) {
                found.push(format!("{}:{}: {}", f.display(), n + 1, line.trim()));
            }
        }
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
}
