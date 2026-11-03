//! What the release gives Windows: the desktop app and the center, and no
//! `nerve-node` of its own, since there the app is the only way to the node
//! (docs/user/install.md).

const RELEASE: &str = include_str!("../../../.github/workflows/release.yml");

/// The release's job named `name`: its lines up to the next line at the
/// jobs' own depth (the next job, or a comment above it).
fn job(name: &str) -> String {
    let mut lines = RELEASE
        .lines()
        .skip_while(|l| *l != format!("  {name}:"))
        .skip(1);
    let first = lines.next().unwrap_or_else(|| panic!("no job {name}"));
    std::iter::once(first)
        .chain(lines.take_while(|l| l.is_empty() || l.starts_with("   ")))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn windows_gets_the_app_and_the_center_and_no_nerve_node() {
    let windows = job("windows");
    assert!(windows.contains("x86_64-pc-windows-msvc"), "{windows}");
    assert!(
        windows.contains("-p nerve-center -p nerve-node-desktop"),
        "{windows}"
    );
    for line in windows.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        assert!(
            !words.windows(2).any(|w| w == ["-p", "nerve-node"]),
            "the Windows job builds nerve-node: {line}"
        );
        if line.trim_start().starts_with("for b in") {
            assert!(!words.contains(&"nerve-node"), "{line}");
        }
    }
    // Two Linux programs on each of two machines, the Linux desktop app, and
    // Windows' two.
    assert!(RELEASE.contains("!= 7 ]"), "the checksums count 7 programs");
    let footer = RELEASE
        .lines()
        .find(|l| l.trim_start().starts_with("footer="))
        .unwrap();
    assert!(
        footer.contains("no \\`nerve-node\\` for Windows"),
        "{footer}"
    );
}

/// The user docs name no terminal command for the node on Windows (#176).
/// The rules page is left out: it lists what an agent's command may not do
/// to the node, Windows' commands among them.
#[test]
fn the_docs_send_nobody_to_a_terminal_on_windows() {
    let docs = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/user");
    let mut found = Vec::new();
    for entry in std::fs::read_dir(&docs).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "md") || path.ends_with("rules.md") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        for (i, line) in text.lines().enumerate() {
            for word in [
                "nerve-node-x86_64-windows",
                "nerve-node.exe",
                "Restart-Service nerve-node",
                "Start-Service nerve-node",
                "Stop-Service nerve-node",
                "Run as administrator",
                "administrator's terminal",
                "CLI edition",
            ] {
                if line.contains(word) {
                    found.push(format!("{}:{}: {word}", path.display(), i + 1));
                }
            }
        }
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
}
