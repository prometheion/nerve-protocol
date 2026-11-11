//! That the releases before 0.1.0 publish the Linux programs only, and what the release gives
//! Windows once its switch is on: the desktop app and the center, and no
//! `nerve-node` of its own, since there the app is the only way to the node
//! (docs/dev/windows.md); what the released app keeps for the licence it
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

/// The releases before 0.1.0 publish the Linux programs only: the input `windows`,
/// off by default, gates the Windows job, and the publish job then counts
/// seven files (five programs, the app's .deb and .rpm) and names no
/// Windows program in its footer. 0.1.0 turns it
/// on, and the Windows job builds the app and the center, no `nerve-node`.
#[test]
fn windows_waits_for_its_switch_and_gets_the_app_and_the_center() {
    let inputs = RELEASE
        .split("    inputs:\n")
        .nth(1)
        .unwrap()
        .split("\npermissions:")
        .next()
        .unwrap();
    let switch = inputs
        .split("      windows:\n")
        .nth(1)
        .expect("an input windows");
    assert!(switch.contains("type: boolean"), "{switch}");
    assert!(switch.contains("default: false"), "{switch}");
    assert!(RELEASE.contains("  WINDOWS: ${{ inputs.windows }}\n"));
    let windows = job("windows");
    assert!(
        windows
            .lines()
            .any(|l| l.trim() == "if: ${{ inputs.windows }}"),
        "{windows}"
    );
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
    // The publish job waits for a Windows job that ran with the switch, and
    // takes one that was skipped without it.
    let publish = job("publish");
    assert!(
        publish.contains("needs.windows.result == (inputs.windows && 'success' || 'skipped')"),
        "{publish}"
    );
    for need in [
        "check",
        "linux",
        "desktop-linux",
        "desktop-packages",
        "desktop-packages-test",
        "conformance",
        "installed",
    ] {
        assert!(
            publish.contains(&format!("needs.{need}.result == 'success'")),
            "{need}: {publish}"
        );
    }
    // Two Linux programs on each of two machines and the Linux desktop app,
    // also as a .deb and an .rpm; Windows' two only with the switch.
    assert!(publish.contains("want=7\n"), "{publish}");
    assert!(
        publish.contains("if [ \"$WINDOWS\" = true ]; then\n            want=9"),
        "{publish}"
    );
    let footers: Vec<&str> = publish
        .lines()
        .filter(|l| l.trim_start().starts_with("footer="))
        .collect();
    assert_eq!(footers.len(), 2, "{publish}");
    let (on, off) = (footers[0], footers[1]);
    assert!(on.contains("no \\`nerve-node\\` for Windows"), "{on}");
    assert!(
        off.contains("Windows comes with 0.1.0") && !off.contains("Windows x86_64"),
        "{off}"
    );
    let switch_on = publish
        .split("footer=")
        .next()
        .unwrap()
        .trim_end()
        .ends_with("if [ \"$WINDOWS\" = true ]; then");
    assert!(
        switch_on,
        "the first footer is the one with Windows: {publish}"
    );
}

/// The Linux desktop app comes as a .deb and an .rpm too (#212): packed
/// with the system's tools from the program the release built, with the
/// dependencies it links, installed on Ubuntu 22.04 and 24.04 and Fedora
/// before anything is published, and listed in SHA256SUMS under the names
/// the app's update looks for.
#[test]
fn the_release_lists_the_linux_app_as_a_deb_and_an_rpm() {
    use nerve_node::service::Package;
    let packages = job("desktop-packages");
    for line in [
        "needs: [check, desktop-linux]",
        "name: nerve-desktop-x86_64-linux",
        "install -y --no-install-recommends rpm libfontconfig1",
        ".github/scripts/desktop-packages.sh program/nerve-node-desktop-x86_64-linux dist",
        "name: nerve-desktop-packages",
    ] {
        assert!(packages.contains(line), "{line}: {packages}");
    }
    // The names the update finds in SHA256SUMS.
    let app = nerve_node_desktop::parts::PROGRAM;
    for (kind, name) in [
        (Package::Deb, "dist/nerve-node-desktop_${VERSION}_amd64.deb"),
        (
            Package::Rpm,
            "dist/nerve-node-desktop-${VERSION}.x86_64.rpm",
        ),
    ] {
        assert!(packages.contains(name), "{name}: {packages}");
        assert_eq!(
            format!("dist/{}", kind.asset(app, "${VERSION}")),
            name,
            "{kind:?}"
        );
    }
    let test = job("desktop-packages-test");
    for line in [
        "needs: desktop-packages",
        "- image: ubuntu:22.04\n            kind: deb",
        "- image: ubuntu:24.04\n            kind: deb",
        "kind: rpm",
        "container: ${{ matrix.image }}",
        "said=$(nerve-node-desktop --version)",
        "desktop-file-validate \"$entry\"",
        "grep -qx 'Exec=/usr/bin/nerve-node-desktop %u' \"$entry\"",
        "dnf install -y \"./dist/nerve-node-desktop-${VERSION}.x86_64.rpm\"",
    ] {
        assert!(test.contains(line), "{line}: {test}");
    }
    assert!(test.contains("- image: fedora:"), "{test}");
    // Both are released and in SHA256SUMS: the publish job takes the
    // `nerve-*` artifacts, and its list of files takes both names.
    let publish = job("publish");
    assert!(publish.contains("pattern: nerve-*"), "{publish}");
    assert!(
        publish.contains("files=(nerve-center-* nerve-node-*)"),
        "{publish}"
    );
    for kind in [Package::Deb, Package::Rpm] {
        assert!(kind.asset(app, "1.2.3").starts_with("nerve-node-"));
    }
    // The system's tools, no cargo tool; the dependencies the app links;
    // the files the program writes, and the package's script that leaves
    // the service to an update that installs the package itself.
    let script = include_str!("../../../.github/scripts/desktop-packages.sh");
    for needed in [
        "dpkg-deb -Zxz --root-owner-group --build",
        "rpmbuild -bb",
        "Depends: libc6 (>= 2.35), libfontconfig1",
        "Requires: glibc >= 2.35",
        "Requires: fontconfig",
        "Architecture: amd64",
        "--target x86_64",
        "\"$out/nerve-node-desktop_${version}_amd64.deb\"",
        "\"$out/nerve-node-desktop-$version.x86_64.rpm\"",
        "update --from=/usr/bin/nerve-node-desktop",
    ] {
        assert!(script.contains(needed), "{needed}");
    }
    assert!(script.contains(&format!(
        "\"$bin\" {} ",
        nerve_node_desktop::parts::PACKAGE_ROOT_ARG
    )));
    assert!(script.contains(&format!("${{{}:-}}", nerve_node::service::UPDATING_VAR)));
    for tool in ["cargo-deb", "cargo-generate-rpm", "cargo install"] {
        assert!(!RELEASE.contains(tool) && !script.contains(tool), "{tool}");
    }
    // The install page puts the package first for the desktop app.
    let install = include_str!("../../../docs/user/install.md");
    let app = install
        .split("\n## The desktop app\n")
        .nth(1)
        .expect("install.md has the desktop app")
        .split("\n## ")
        .next()
        .unwrap();
    let first = app.lines().find(|l| l.starts_with("1. ")).unwrap();
    assert!(
        first.contains("package") && first.contains(".deb") && first.contains(".rpm"),
        "{first}"
    );
    let deb = app.find("apt install ./nerve-node-desktop_").unwrap();
    let plain = app
        .find("nerve-node-desktop-x86_64-linux")
        .expect("install.md names the plain program");
    assert!(deb < plain, "the package comes first in install.md: {app}");
}

/// The user guide is Linux only until 0.1.0 (Q9 of the PR 6 plan): it names
/// Windows once, in "Windows comes with 0.1.0", and every Windows text is in
/// docs/dev/windows.md until then. The notes of a release name everything it
/// changed, Windows too (owner, 2026-11-07), and begin with the update order;
/// the Windows items of 0.0.7 and before wait under `## Unreleased` for the
/// release log of 0.1.0.
#[test]
fn the_user_guide_is_linux_only_and_the_notes_say_the_update_order() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut found = Vec::new();
    let mut pages = vec![root.join("README.md")];
    for entry in std::fs::read_dir(root.join("docs/user")).unwrap() {
        pages.push(entry.unwrap().path());
    }
    for path in pages {
        let text = std::fs::read_to_string(&path).unwrap();
        for (i, line) in text.lines().enumerate() {
            let rest = line.replace("Windows comes with 0.1.0", "");
            if rest.contains("Windows") || rest.contains(".exe") {
                found.push(format!("{}:{}: {line}", path.display(), i + 1));
            }
        }
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
    let changelog = include_str!("../../../CHANGELOG.md");
    // The newest release's notes: the first `## x.y.z` below `## Unreleased`.
    let notes = changelog
        .split("\n## ")
        .find(|s| s.starts_with(|c: char| c.is_ascii_digit()))
        .expect("a release section")
        .split_once('\n')
        .unwrap()
        .1;
    assert!(notes.contains("Update the center first, then the nodes."));
    let unreleased = changelog
        .split("\n## Unreleased\n")
        .nth(1)
        .unwrap()
        .split("\n## ")
        .next()
        .unwrap();
    assert!(
        unreleased.contains("### Windows (with 0.1.0)"),
        "{unreleased}"
    );
}

/// The Breaks of 0.0.7 tell a user what to change in a script or a state
/// folder from 0.0.6: the renames of the commands and options, and the
/// steps of the one change that stops a center (the local model d1-3B).
/// Each line here was missing from the notes once.
#[test]
fn the_breaks_of_the_notes_give_the_action_of_each() {
    let changelog = include_str!("../../../CHANGELOG.md");
    let breaks = changelog
        .split("\n## 0.0.7\n")
        .nth(1)
        .unwrap()
        .split("\n### Breaks\n")
        .nth(1)
        .expect("a section ### Breaks")
        .split("\n### ")
        .next()
        .unwrap();
    let flat = breaks.split_whitespace().collect::<Vec<_>>().join(" ");
    // Forms that 0.0.6 never had are no break.
    for unreleased in ["folder network", "--pin", "cap provider", "[[capability]]"] {
        assert!(!flat.contains(unreleased), "the Breaks name {unreleased}");
    }
    for needed in [
        "`relay add <n> --center C` → `--to C`",
        "`--mcp none` → `--mcp off`",
        "with no `--wildcard`",
        "`daemon:`",
        "set `threshold` to 0.75",
        "`timeout_ms` to 12000",
        "install the model again on the Action checker page",
    ] {
        assert!(flat.contains(needed), "the Breaks lack {needed}:\n{breaks}");
    }
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
/// the machines it runs on are the ones the install page calls tested.
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
    let install = include_str!("../../../docs/user/install.md");
    let tested = install
        .lines()
        .find(|l| l.starts_with("| Tested |"))
        .unwrap();
    for name in ["Ubuntu 22.04 and 24.04, Debian 12", "aarch64"] {
        assert!(tested.contains(name), "{name}: {tested}");
    }
}

/// The app's links to the user guide open the docs at the ref the build
/// names (`Store.guide-ref`: the release's tag, or `main` in a build that is
/// no release, whose tag would not exist), and a release run names its tag.
#[test]
fn the_app_opens_the_guide_of_its_release() {
    for (name, ui) in [
        ("help.slint", include_str!("../ui/help.slint")),
        ("overview.slint", include_str!("../ui/overview.slint")),
    ] {
        let links: Vec<&str> = ui
            .lines()
            .filter(|l| l.contains("nerve-protocol/") && l.contains("/docs/user"))
            .collect();
        assert!(!links.is_empty(), "{name}");
        for l in links {
            assert!(
                l.contains("/\" + Store.guide-ref + \"/docs/user"),
                "{name}: {l}"
            );
        }
    }
    let env = RELEASE
        .lines()
        .find(|l| l.starts_with("  NERVE_GUIDE_REF: "))
        .expect("the run names the guide's ref");
    assert!(
        env.contains("inputs.kind == 'release' && format('v{0}', inputs.version) || 'main'"),
        "{env}"
    );
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
