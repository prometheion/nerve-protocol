//! What the release gives Windows: the desktop app and the center, and no
//! `nerve-node` of its own, since there the app is the only way to the node
//! (docs/user/install.md); what the released app keeps for the licence it
//! uses Slint under; and that the Linux programs are installed and tested
//! where the docs say before they are published; and that the security
//! policy names a way in that needs no repository setting.

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
                "Windows node you run yourself",
            ] {
                if line.contains(word) {
                    found.push(format!("{}:{}: {word}", path.display(), i + 1));
                }
            }
        }
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
}

/// The commands page says that `run` is refused on Windows (#176): the table
/// row of a command Windows refuses carries the note, since the scan above
/// can only look for words.
#[test]
fn the_run_row_says_windows_refuses_it() {
    let page = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/user/commands.md"),
    )
    .unwrap();
    let row = page.lines().find(|l| l.starts_with("| `run` |")).unwrap();
    assert!(row.contains("Windows") && row.contains("refused"), "{row}");
}

/// The released app keeps what Slint's Royalty-free license 2.0, under which
/// it uses Slint, asks of it (LICENSE.md): the AboutSlint widget in the About
/// dialog, which an item of the main window's sidebar opens. The crate's
/// licence names it, and NOTICE names Slint's licence.
#[test]
fn the_app_shows_slints_notice_as_its_licence_asks() {
    let dialogs = include_str!("../ui/dialogs.slint");
    let about = dialogs
        .split("export component AboutDialog inherits Dialog {")
        .nth(1)
        .expect("an About dialog")
        .split("\nexport component ")
        .next()
        .unwrap();
    assert!(about.contains("AboutSlint {"), "{about}");
    let app = include_str!("../ui/app.slint");
    let item = app
        .split("NavItem {")
        .find(|i| i.contains("text: \"About\";"))
        .expect("an About item in the sidebar");
    assert!(item.contains("Store.about-open = true;"), "{item}");
    assert!(app.contains("if Store.about-open: AboutDialog { }"));
    let licence = include_str!("../LICENSE.md");
    assert!(
        licence.contains("# Slint Royalty-free Desktop, Mobile, and Web Applications License"),
        "the crate's licence has Slint's text"
    );
    assert!(licence.contains("`AboutSlint`"));
    let notice = include_str!("../../../NOTICE");
    assert!(
        notice.contains("Slint Royalty-free Desktop, Mobile, and Web Applications License 2.0"),
        "{notice}"
    );
}

/// The release publishes no Linux program before the install test passed on
/// the very files it publishes (`installed.yml`), CI runs the same test, and
/// the machines it runs on are the ones the platforms page calls tested.
#[test]
fn the_release_installs_its_linux_programs_where_the_docs_say_they_are_tested() {
    let publish = job("publish");
    let needs = publish
        .lines()
        .find(|l| l.trim_start().starts_with("needs:"))
        .unwrap();
    assert!(needs.contains("installed"), "{needs}");
    let installed = job("installed");
    for line in [
        "uses: ./.github/workflows/installed.yml",
        "binaries: nerve-{0}-linux",
        "ref: ${{ needs.check.outputs.sha }}",
    ] {
        assert!(installed.contains(line), "{line}: {installed}");
    }
    let ci = include_str!("../../../.github/workflows/ci.yml");
    assert!(ci.contains("uses: ./.github/workflows/installed.yml"));
    let workflow = include_str!("../../../.github/workflows/installed.yml");
    let matrix = workflow
        .split("        include:\n")
        .nth(1)
        .unwrap()
        .split("\n    env:")
        .next()
        .unwrap();
    let machines: Vec<&str> = matrix
        .lines()
        .filter_map(|l| l.trim().strip_prefix("- name: "))
        .collect();
    assert_eq!(
        machines,
        [
            "Ubuntu 22.04 x86_64",
            "Ubuntu 24.04 x86_64",
            "Ubuntu 24.04 arm64",
            "Debian 12 x86_64"
        ]
    );
    let platforms = include_str!("../../../docs/user/platforms.md");
    let tested = platforms
        .lines()
        .find(|l| l.starts_with("| Tested |"))
        .unwrap();
    for name in ["Ubuntu 22.04 and 24.04, Debian 12", "aarch64"] {
        assert!(tested.contains(name), "{name}: {tested}");
    }
}

/// GitHub's private vulnerability reporting is a setting of the repository,
/// and the Security tab has no button while it is off. The policy then still
/// names a way in that is no public report of the hole.
#[test]
fn the_security_policy_names_a_way_in_without_the_reporting_button() {
    let policy = include_str!("../../../SECURITY.md");
    let readme = include_str!("../../../README.md");
    assert!(policy.contains("security/advisories/new"), "{policy}");
    for (name, text) in [("SECURITY.md", policy), ("README.md", readme)] {
        assert!(
            text.contains("open an issue") || text.contains("Open an [issue]"),
            "{name} has no way in when the Security tab has no button"
        );
    }
    assert!(
        policy.contains("nerve-protocol/issues/new")
            && policy.contains("with nothing about the hole in it"),
        "{policy}"
    );
    // The contribution guide sends a hole to the policy, and the README
    // sends a contributor to the guide.
    let guide = include_str!("../../../CONTRIBUTING.md");
    assert!(guide.contains("(SECURITY.md)"), "{guide}");
    assert!(readme.contains("(CONTRIBUTING.md)"), "{readme}");
}

/// The Debian 12 machine is a minimal image: the real tests call `pgrep`
/// (step 1c, before the node's setup brings procps in as a dependency).
#[test]
fn the_debian_machine_has_the_tools_the_real_tests_call() {
    let script = include_str!("../../../.github/scripts/systemd-container.sh");
    let list = script
        .split("apt-get install")
        .nth(1)
        .and_then(|rest| rest.split("# ").next())
        .expect("the package list");
    assert!(list.split_whitespace().any(|p| p == "procps"), "{list}");
}

/// `real()` of the end-to-end script must see a skip in the output of a run
/// with one test thread too, where the test's line follows `test <name> ... `.
#[cfg(unix)]
#[test]
fn a_real_test_that_skips_fails_the_script_with_one_test_thread_too() {
    let script = include_str!("../../../.github/scripts/keyring-end-to-end.sh");
    let start = script.find("\nreal() {").expect("real()") + 1;
    let real = &script[start..start + script[start..].find("\n}\n").expect("end of real()") + 2];
    let dir = std::env::temp_dir().join(format!("nerve-real-fn-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for (printed, fails) in [
        ("skipped: not set", true),
        ("test a_test ... skipped: not set", true),
        ("test a_test ... ok", false),
    ] {
        let run = std::process::Command::new("bash")
            .arg("-c")
            .arg(format!(
                "OUT={}; fail() {{ echo \"FAIL: $*\"; exit 1; }}\n{real}\nreal echo '{printed}'",
                dir.display()
            ))
            .output()
            .expect("bash");
        assert_eq!(!run.status.success(), fails, "{printed}: {run:?}");
    }
    std::fs::remove_dir_all(&dir).ok();
}

/// Chrome prints its DevTools line a moment before it lists its first tab:
/// the web UI smoke test must wait for it, and when it never comes it must
/// say so, end the browser and fail, not crash on a missing page.
#[cfg(unix)]
#[test]
fn the_web_ui_smoke_test_waits_for_the_browsers_first_page_and_ends_the_browser() {
    use std::os::unix::fs::PermissionsExt;
    if std::process::Command::new("node")
        .arg("--version")
        .output()
        .is_err()
    {
        println!("skipped: no node");
        return;
    }
    let smoke = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../.github/scripts/web-ui-smoke.mjs"
    );
    let dir = tempfile::tempdir().unwrap();
    let pidfile = dir.path().join("pid");
    // A browser that announces its endpoint and lists no page, ever.
    let chrome = dir.path().join("chrome");
    std::fs::write(
        &chrome,
        format!(
            "#!/usr/bin/env node\nconst http = require('http');\n\
             require('fs').writeFileSync({pid:?}, String(process.pid));\n\
             const s = http.createServer((q, r) => r.end('[]'));\n\
             s.listen(0, '127.0.0.1', () => console.error('DevTools listening on ws://127.0.0.1:' + s.address().port + '/devtools/browser/x'));\n",
            pid = pidfile.display().to_string()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&chrome, std::fs::Permissions::from_mode(0o755)).unwrap();
    let run = std::process::Command::new("node")
        .args([smoke, chrome.to_str().unwrap(), "http://127.0.0.1:1/", "t"])
        .output()
        .expect("node");
    let said = String::from_utf8_lossy(&run.stderr);
    assert!(
        !run.status.success() && said.contains("listed no page"),
        "{run:?}"
    );
    let pid = std::fs::read_to_string(&pidfile).unwrap();
    // The killed browser is reaped by init a moment after the script ends.
    let gone = (0..40).any(|_| {
        std::thread::sleep(std::time::Duration::from_millis(50));
        !std::path::Path::new(&format!("/proc/{pid}")).exists()
    });
    assert!(gone, "the browser still runs");
}
