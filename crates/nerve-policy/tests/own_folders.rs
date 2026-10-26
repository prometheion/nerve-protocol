//! The node's own folders (config, keys, state) are refused before any rule
//! or mode, and nothing the owner or a center writes into a policy lifts that
//! (issue #20).
//!
//! Pure logic: the Unix and the Windows rules are both tested on every
//! platform.

use std::path::{Path, PathBuf};

use nerve_policy::command::Shell;
use nerve_policy::config::{Access, Folder, ProtectedOptions};
use nerve_policy::protected::{Platform, Protected, WinFolders};
use nerve_policy::{Call, CenterPolicy, Decision, Env, Mode, PathAccess, Target, decide};
use nerve_proto::Effect;

const NOW: u64 = 1_000_000;
const CONFIG: &str = "/h/.config/nerve";
const STATE: &str = "/h/.local/state/nerve";

/// A policy that would allow everything: folders naming the node's folders,
/// the protected list released, allow rules for every path and command, and
/// a sudo allow entry for any command.
fn wide_open(mode: Mode) -> CenterPolicy {
    let mut p = CenterPolicy {
        mode,
        ..Default::default()
    };
    for path in ["/h", CONFIG, STATE] {
        p.folders.push(Folder {
            path: path.into(),
            access: Access::ALL,
        });
    }
    p.protected.allow = vec!["~/.config/nerve".into(), "~/.local/state/nerve".into()];
    p.allow = vec!["fs:/*".into(), "exec.run:*".into()];
    p.sudo_allow = vec!["sudo *".into()];
    p
}

fn protected(p: &CenterPolicy) -> Protected {
    Protected::new(
        &Platform::Unix,
        Path::new("/h"),
        &[PathBuf::from(CONFIG), PathBuf::from(STATE)],
        &p.protected,
    )
}

fn fs(effect: Effect, targets: &[Target]) -> Call<'_> {
    Call {
        cap: "fs",
        action: if effect == Effect::Write {
            "write"
        } else {
            "read"
        },
        effect,
        targets,
        command: None,
        cwd: None,
        now_ms: NOW,
    }
}

fn run<'a>(command: &'a str, cwd: &'a [Target]) -> Call<'a> {
    Call {
        cap: "exec",
        action: "run",
        effect: Effect::Execute,
        targets: cwd,
        command: Some(command),
        cwd: Some(cwd[0].path.as_path()),
        now_ms: NOW,
    }
}

fn at(p: &str, write: bool) -> Vec<Target> {
    vec![Target {
        path: p.into(),
        access: if write {
            PathAccess::Write
        } else {
            PathAccess::Read
        },
    }]
}

/// The working directory of a command.
fn cwd_at(p: &str) -> Vec<Target> {
    vec![Target {
        path: p.into(),
        access: PathAccess::Run,
    }]
}

fn own_refusal(d: &Decision) -> bool {
    matches!(d, Decision::Forbidden(why) if why.contains("belongs to the node"))
}

/// Where the command account holds what folder mode reads, a read goes
/// as far as that account may read, and the node's own folders are
/// refused before that is asked: even an account that could read them
/// (here one that may read anything) gets nothing of them, through `fs` or
/// a provider's path argument.
#[test]
fn a_read_held_by_the_account_never_reaches_the_nodes_own_folders() {
    let p = CenterPolicy {
        mode: Mode::Folder,
        ..Default::default()
    };
    let prot = protected(&p);
    let anything = |_: &Path| true;
    let env = Env {
        home: Path::new("/h"),
        protected: &prot,
        unconfined: None,
        sudo: false,
        shell: Shell::Sh,
        reads: nerve_policy::decide::Reads::Account(&anything),
    };
    for path in [
        "/h/.config/nerve/node.toml",
        "/h/.config/nerve",
        "/h/.local/state/nerve/config.key",
    ] {
        let targets = at(path, false);
        let provided = Call {
            cap: "notes",
            action: "open",
            ..fs(Effect::Read, &targets)
        };
        for c in [fs(Effect::Read, &targets), provided] {
            let d = decide(&p, &env, &c);
            assert!(own_refusal(&d), "{c:?}: {d:?}");
        }
    }
    // Beside them the account's reach decides.
    let d = decide(&p, &env, &fs(Effect::Read, &at("/h/notes.txt", false)));
    assert_eq!(d, Decision::Allow);
}

#[test]
fn nothing_reaches_the_nodes_own_folders() {
    for mode in [Mode::Allowlist, Mode::Folder, Mode::User] {
        let p = wide_open(mode);
        let prot = protected(&p);
        let env = Env {
            home: Path::new("/h"),
            protected: &prot,
            unconfined: None,
            sudo: true,
            shell: Shell::Sh,
            reads: nerve_policy::decide::Reads::Folders,
        };
        let check = |c: &Call| {
            let d = decide(&p, &env, c);
            assert!(own_refusal(&d), "{mode:?} {c:?}: {d:?}");
        };
        check(&fs(Effect::Read, &at("/h/.config/nerve/node.toml", false)));
        check(&fs(Effect::Write, &at("/h/.config/nerve/node.toml", true)));
        check(&fs(Effect::Write, &at("/h/.config/nerve", true)));
        check(&fs(
            Effect::Read,
            &at("/h/.local/state/nerve/config.key", false),
        ));
        check(&fs(Effect::Write, &at("/h/.CONFIG/Nerve/node.toml", true)));
        let home = cwd_at("/h");
        let inside = cwd_at("/h/.config/nerve");
        check(&run("ls", &inside));
        for named in [
            "cat ~/.config/nerve/node.toml",
            "echo x >> $HOME/.config/nerve/node.toml",
            "cp evil ${HOME}/.local/state/nerve/config.key",
            "cat /h/.config/nerve",
            "sudo tee /h/.config/nerve/node.toml",
        ] {
            check(&run(named, &home));
        }
        // A name that only starts like one is not one.
        let d = decide(&p, &env, &run("cat ~/.config/nerve-notes/a", &home));
        assert!(!own_refusal(&d), "{mode:?}: {d:?}");
    }
    // The same policy still allows what lies beside them.
    let p = wide_open(Mode::User);
    let prot = protected(&p);
    let env = Env {
        home: Path::new("/h"),
        protected: &prot,
        unconfined: None,
        sudo: false,
        shell: Shell::native(),
        reads: nerve_policy::decide::Reads::Folders,
    };
    let notes = at("/h/notes/a", true);
    assert_eq!(
        decide(&p, &env, &fs(Effect::Write, &notes)),
        Decision::Allow
    );
}

/// The same folders named in ways a plain substring of the absolute path
/// misses: from the working directory, with `..`, doubled or `.` separators,
/// and quoted.
#[test]
fn the_nodes_own_folders_are_seen_in_every_plain_spelling() {
    for mode in [Mode::Allowlist, Mode::Folder, Mode::User] {
        let p = wide_open(mode);
        let prot = protected(&p);
        let env = Env {
            home: Path::new("/h"),
            protected: &prot,
            unconfined: None,
            sudo: true,
            shell: Shell::Sh,
            reads: nerve_policy::decide::Reads::Folders,
        };
        let home = cwd_at("/h");
        let proj = cwd_at("/h/proj");
        for (named, cwd) in [
            ("cat ../.config/nerve/node.toml", &proj),
            ("cat ./.config/nerve/node.toml", &home),
            ("cat .config/nerve/node.toml", &home),
            ("cat '.local/state/nerve/config.key'", &home),
            ("cat /h//.config/nerve/node.toml", &home),
            ("cat /h/./.config/nerve/node.toml", &home),
            ("cat /h/proj/../.config/nerve/node.toml", &home),
            ("cat $HOME/proj/../.config/nerve/node.toml", &home),
            ("cat \"~/.config/nerve/node.toml\"", &home),
            ("cat '~/.local/state/nerve/config.key'", &home),
            ("cp x --target=~/.config/nerve", &home),
        ] {
            let d = decide(&p, &env, &run(named, cwd));
            assert!(own_refusal(&d), "{mode:?} {named:?} in {cwd:?}: {d:?}");
        }
        // Beside them, and names that only look alike, are not theirs.
        for (named, cwd) in [
            ("cat ../notes/a", &proj),
            ("cat .config/nerve-notes/a", &home),
            ("cat /h/proj/../notes/.config/nerve", &home),
            ("cat nerve/node.toml", &home),
        ] {
            let d = decide(&p, &env, &run(named, cwd));
            assert!(!own_refusal(&d), "{mode:?} {named:?} in {cwd:?}: {d:?}");
        }
    }
}

/// A Windows node whose folders sit beside a project: the spellings a
/// PowerShell line names them by are refused in every mode, through the whole
/// decision.
#[test]
fn a_windows_command_line_reaches_no_own_folder() {
    let own = [
        PathBuf::from("C:\\Users\\u\\nerve-test\\node-config"),
        PathBuf::from("C:\\Users\\u\\nerve-test\\node-state"),
    ];
    let prot = Protected::new(
        &Platform::Windows(WinFolders::default()),
        Path::new("C:\\Users\\u"),
        &own,
        &ProtectedOptions::default(),
    );
    let env = Env {
        home: Path::new("C:\\Users\\u"),
        protected: &prot,
        unconfined: None,
        sudo: false,
        shell: Shell::native(),
        reads: nerve_policy::decide::Reads::Folders,
    };
    let proj = cwd_at("C:\\Users\\u\\nerve-test\\proj");
    for mode in [Mode::Allowlist, Mode::Folder, Mode::User] {
        let mut p = wide_open(mode);
        p.folders.push(Folder {
            path: "C:\\Users\\u".into(),
            access: Access::ALL,
        });
        for named in [
            "Get-Content C:/Users/u/nerve-test/node-state/config.key",
            "Get-Content ~/nerve-test/node-config/node.toml",
            "Get-Content $HOME/nerve-test/node-config/node.toml",
            "Get-Content ~\\nerve-test\\node-config\\node.toml",
            "Get-Content $env:USERPROFILE\\nerve-test\\node-config\\node.toml",
            "Get-Content ..\\node-config\\node.toml",
            "Get-Content \"..\\node-state\\config.key\"",
        ] {
            let d = decide(&p, &env, &run(named, &proj));
            assert!(own_refusal(&d), "{mode:?} {named:?}: {d:?}");
        }
    }
    let p = wide_open(Mode::User);
    let d = decide(&p, &env, &run("Get-Content ..\\notes\\a.txt", &proj));
    assert_eq!(d, Decision::Allow);
}

/// A Windows node checks a long command line of drive letters (`a:a:…`)
/// at once, and refuses one past the length it checks before it looks for
/// its own folders, with no grant at all.
#[test]
fn a_long_windows_command_line_is_checked_at_once() {
    let own = [PathBuf::from("C:\\Users\\u\\nerve-test\\node-config")];
    let prot = Protected::new(
        &Platform::Windows(WinFolders::default()),
        Path::new("C:\\Users\\u"),
        &own,
        &ProtectedOptions::default(),
    );
    let env = Env {
        home: Path::new("C:\\Users\\u"),
        protected: &prot,
        unconfined: None,
        sudo: false,
        shell: Shell::native(),
        reads: nerve_policy::decide::Reads::Folders,
    };
    let proj = cwd_at("C:\\Users\\u\\nerve-test\\proj");
    let open = wide_open(Mode::User);
    let d = decide(&open, &env, &run(&"a:".repeat(16 * 1024), &proj));
    assert_eq!(d, Decision::Allow);
    let named = format!(
        "{}c:/users/u/nerve-test/node-config/x",
        "a:".repeat(16 * 1024)
    );
    assert!(own_refusal(&decide(&open, &env, &run(&named, &proj))));
    for p in [CenterPolicy::default(), open] {
        let d = decide(&p, &env, &run(&"a:".repeat(64 * 1024), &proj));
        assert!(
            matches!(&d, Decision::Forbidden(why) if why.contains("longer than")),
            "{d:?}"
        );
    }
}
