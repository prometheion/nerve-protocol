//! On Windows the desktop app is the only way to the node (#176): no message
//! of the Windows parts of the node sends the owner to a terminal. Each says
//! where in the app to do it instead.

/// The Windows parts: the service, its installer, sudo, the accounts, the
/// control pipe, and what the node shares with the center's service.
const SOURCES: &[(&str, &str)] = &[
    ("winsvc.rs", include_str!("../src/winsvc.rs")),
    ("winsudo.rs", include_str!("../src/winsudo.rs")),
    ("win_host.rs", include_str!("../src/win_host.rs")),
    ("win_service.rs", include_str!("../src/win_service.rs")),
    ("win_user.rs", include_str!("../src/win_user.rs")),
    ("win.rs", include_str!("../src/win.rs")),
    ("win_stop.rs", include_str!("../src/win_stop.rs")),
    ("pipe.rs", include_str!("../src/pipe.rs")),
    (
        "eventlog.rs",
        include_str!("../../nerve-service/src/eventlog.rs"),
    ),
];

/// What sends a person to a terminal.
const TERMINAL: &[&str] = &[
    "terminal",
    "run as administrator",
    "restart-service",
    "start-service",
    "powershell",
    "cli edition",
    "`nerve-node ",
    "nerve-node.exe ",
    "icacls",
    "get-ciminstance",
];

/// The string literals of `source` outside its tests and comments, with
/// their line numbers.
fn texts(source: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (i, line) in source.lines().enumerate() {
        if line.starts_with("mod tests") || line.starts_with("pub(crate) mod tests") {
            break;
        }
        // An escaped quote stays inside its literal.
        let code = line.trim_start().replace("\\\"", "'");
        if code.starts_with("//") {
            continue;
        }
        let mut quoted = code.split('"');
        quoted.next();
        while let Some(text) = quoted.next() {
            out.push((i + 1, text.to_string()));
            quoted.next();
        }
    }
    out
}

#[test]
fn no_windows_message_sends_the_owner_to_a_terminal() {
    let mut found = Vec::new();
    for (file, source) in SOURCES {
        for (line, text) in texts(source) {
            let lower = text.to_lowercase();
            if let Some(word) = TERMINAL.iter().find(|w| lower.contains(*w)) {
                found.push(format!("{file}:{line}: {word:?} in {text:?}"));
            }
        }
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
}

/// The texts the node chooses for Windows in the parts it shares with
/// Linux.
#[test]
fn the_shared_windows_texts_say_where_in_the_app() {
    let texts = [
        nerve_node::cli::BY_HAND,
        nerve_node::account::NO_ACCOUNT_INSTALL,
        #[cfg(windows)]
        nerve_node::account::NO_OWNER,
    ];
    for text in texts {
        let lower = text.to_lowercase();
        for word in TERMINAL {
            assert!(!lower.contains(word), "{word:?} in {text:?}");
        }
        assert!(text.contains("app"), "{text:?}");
    }
}

/// The two messages of an installed node that runs without its token
/// privilege name the app's Start button, not a service command.
#[test]
fn a_node_without_its_privilege_says_where_in_the_app_to_start_it() {
    for (file, source) in [
        ("account.rs", include_str!("../src/account.rs")),
        ("daemon.rs", include_str!("../src/daemon.rs")),
    ] {
        let lines: Vec<_> = texts(source)
            .into_iter()
            .filter(|(_, t)| t.contains("SeAssignPrimaryTokenPrivilege"))
            .collect();
        assert!(!lines.is_empty(), "{file}: no such message found");
        for (line, text) in lines {
            let lower = text.to_lowercase();
            assert!(
                !TERMINAL.iter().any(|w| lower.contains(w)),
                "{file}:{line}: {text:?}"
            );
            assert!(
                text.contains("Start on the app's Overview"),
                "{file}:{line}"
            );
        }
    }
}

/// The advice for a profile folder Windows kept names the folder to delete
/// in Explorer first: the User Profiles dialog lists every deleted account's
/// profile as Account Unknown, so it says how to tell this one by its date.
#[test]
fn a_kept_profile_is_found_by_its_folder_or_its_date() {
    let lines: Vec<_> = texts(include_str!("../src/win_host.rs"))
        .into_iter()
        .filter(|(_, t)| t.contains("Account Unknown"))
        .collect();
    assert_eq!(lines.len(), 1, "{lines:?}");
    let text = &lines[0].1;
    assert!(text.contains("in Explorer"), "{text}");
    assert!(text.contains("date of this uninstall"), "{text}");
}
