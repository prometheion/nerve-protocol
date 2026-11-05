//! Root's `backup` and `restore` on a node whose folders are another user's,
//! as the installed node's are `nerve`'s: the command runs as that user, but
//! the backup file is opened as the user who asked through sudo or pkexec,
//! in a folder only that user may open, and the backup written there is that
//! user's. Where sudo's user may not, root's own folders stay root's and the
//! node's folder the node's user's; pkexec's user gets no such second try,
//! and an asker without an account is refused.
//!
//! Runs as root: as root itself (CI runs it so, with `sudo` as the runner),
//! else in a user namespace of its own (`unshare --map-root-user
//! --map-auto`), which it starts when it can; it says it skipped otherwise.

#![cfg(target_os = "linux")]

#[path = "common/ns.rs"]
mod ns;

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

/// The node's user, an id without an account.
const NODE: u32 = 4300;
/// An id without an account either.
const NOBODY_KNOWS: u32 = 4302;

/// The one who asks: a user with an account, which an asker must have.
fn asker() -> u32 {
    let o = Command::new("id").args(["-u", "nobody"]).output().unwrap();
    String::from_utf8_lossy(&o.stdout).trim().parse().unwrap()
}

/// Who asked: through sudo, or through pkexec as the desktop app's broker.
#[derive(Clone, Copy)]
enum By {
    Root,
    Sudo(u32),
    Pkexec(u32),
}

fn chown(path: &Path, id: u32) {
    let status = Command::new("chown")
        .args(["-R", &format!("{id}:{id}")])
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success());
}

/// Whether root in a namespace of `unshare` may give a file to another
/// user, as the test does. That a namespace opens is not enough: Ubuntu
/// 24.04 (GitHub's runner) gives one under AppArmor's restriction of
/// unprivileged user namespaces, and its root, without capabilities there,
/// gets EPERM from `chown`.
fn namespace_root_may_chown(unshare: &[&str]) -> bool {
    let Ok(d) = tempfile::tempdir() else {
        return false;
    };
    let probe = d.path().join("probe");
    if std::fs::write(&probe, "").is_err() {
        return false;
    }
    Command::new("unshare")
        .args(unshare)
        .args(["chown", &format!("{NODE}:{NODE}")])
        .arg(&probe)
        .output()
        .is_ok_and(|o| o.status.success())
}

fn mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn node(root: &Path, by: By, args: &[&str]) -> std::process::Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_nerve-node"));
    c.arg("--config-dir")
        .arg(root.join("config"))
        .arg("--state-dir")
        .arg(root.join("state"))
        .args(args)
        .env_remove("SUDO_UID")
        .env_remove("SUDO_GID")
        .env_remove("SUDO_USER")
        .env_remove("PKEXEC_UID");
    match by {
        By::Root => {}
        By::Sudo(id) => {
            c.env("SUDO_UID", id.to_string())
                .env("SUDO_GID", id.to_string());
        }
        By::Pkexec(id) => {
            c.env("PKEXEC_UID", id.to_string());
        }
    }
    c.output().unwrap()
}

fn ok(o: &std::process::Output) {
    assert!(
        o.status.success(),
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
}

fn failed(o: &std::process::Output) -> String {
    assert!(!o.status.success(), "{o:?}");
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn the_backup_file_is_opened_as_the_user_who_asked() {
    const NAME: &str = "the_backup_file_is_opened_as_the_user_who_asked";
    if nerve_transport::net::euid() != 0 {
        // Root in a user namespace of its own, where this machine gives one.
        assert!(
            std::env::var_os("NERVE_TEST_IN_USERNS").is_none(),
            "not root in the namespace"
        );
        let unshare = ["--map-root-user", "--map-auto"];
        if !namespace_root_may_chown(&unshare) {
            eprintln!(
                "skipped: needs root, or a user namespace whose root may change owners (unshare --map-root-user --map-auto)"
            );
            return;
        }
        ns::run_saying_skips(
            Command::new("unshare")
                .args(unshare)
                .arg(std::env::current_exe().unwrap())
                .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
                .env("NERVE_TEST_IN_USERNS", "1"),
        );
        return;
    }
    let asker = asker();
    let d = tempfile::tempdir().unwrap();
    let root = d.path();
    mode(root, 0o755);
    ok(&node(
        root,
        By::Root,
        &["config", "set", "node.name", "boxy"],
    ));
    let pass = root.join("state/pass");
    std::fs::write(&pass, "correct horse battery\n").unwrap();
    mode(&pass, 0o600);
    chown(&root.join("config"), NODE);
    chown(&root.join("state"), NODE);
    mode(&root.join("state"), 0o700);

    // The asker's home: nobody else may open it.
    let home = root.join("home");
    std::fs::create_dir(&home).unwrap();
    chown(&home, asker);
    mode(&home, 0o700);
    let file = home.join("nerve-node.backup");
    let file_arg = file.to_str().unwrap();
    let pass_arg = pass.to_str().unwrap();
    let backup = |by: By, to: &Path| {
        node(
            root,
            by,
            &[
                "backup",
                to.to_str().unwrap(),
                "--passphrase-file",
                pass_arg,
            ],
        )
    };

    ok(&backup(By::Sudo(asker), &file));
    let m = std::fs::metadata(&file).unwrap();
    assert_eq!(
        (m.uid(), m.gid()),
        (asker, asker),
        "the backup is the asker's"
    );
    assert_eq!(m.mode() & 0o777, 0o600);
    // An existing file stays without --overwrite, and is replaced with it.
    let again = backup(By::Sudo(asker), &file);
    assert!(failed(&again).contains("exists already"), "{again:?}");
    ok(&node(
        root,
        By::Sudo(asker),
        &[
            "backup",
            file_arg,
            "--overwrite",
            "--passphrase-file",
            pass_arg,
        ],
    ));
    ok(&node(
        root,
        By::Sudo(asker),
        &["restore", file_arg, "--passphrase-file", pass_arg],
    ));
    // What the restore wrote is the node's.
    let toml = std::fs::metadata(root.join("config/node.toml")).unwrap();
    assert_eq!(toml.uid(), NODE);

    // pkexec's user, as the desktop app's broker asks: the same.
    let by_app = home.join("app.backup");
    ok(&backup(By::Pkexec(asker), &by_app));
    assert_eq!(std::fs::metadata(&by_app).unwrap().uid(), asker);
    ok(&node(
        root,
        By::Pkexec(asker),
        &[
            "restore",
            by_app.to_str().unwrap(),
            "--passphrase-file",
            pass_arg,
        ],
    ));

    // Root's own folder, which the asker may not open.
    let closed = root.join("closed");
    std::fs::create_dir(&closed).unwrap();
    mode(&closed, 0o700);
    // The app's broker gets nothing there: its user may not.
    let e = failed(&backup(By::Pkexec(asker), &closed.join("app.backup")));
    assert!(e.contains("as the user who asked, nobody"), "{e}");
    assert!(!closed.join("app.backup").exists());
    // An asker without an account is refused, never taken for root.
    for by in [By::Pkexec(NOBODY_KNOWS), By::Sudo(NOBODY_KNOWS)] {
        let e = failed(&backup(by, &closed.join("unknown.backup")));
        assert!(e.contains("no account has that id"), "{e}");
        assert!(!closed.join("unknown.backup").exists());
    }
    // A root shell of sudo's user (`sudo -i` keeps SUDO_UID): root's folder
    // stays root's to write and to read.
    let in_root = closed.join("x.backup");
    ok(&backup(By::Sudo(asker), &in_root));
    assert_eq!(std::fs::metadata(&in_root).unwrap().uid(), 0);
    ok(&node(
        root,
        By::Sudo(asker),
        &[
            "restore",
            in_root.to_str().unwrap(),
            "--passphrase-file",
            pass_arg,
        ],
    ));
    let e = failed(&node(
        root,
        By::Pkexec(asker),
        &[
            "restore",
            in_root.to_str().unwrap(),
            "--passphrase-file",
            pass_arg,
        ],
    ));
    assert!(e.contains("may not read it"), "{e}");
    // The node's state folder: written there as the node's user, its
    // folder's owner.
    let old_place = root.join("state/nerve.bak");
    ok(&backup(By::Sudo(asker), &old_place));
    assert_eq!(std::fs::metadata(&old_place).unwrap().uid(), NODE);
    // Root's own command opens it as root.
    let by_root = closed.join("root.backup");
    ok(&backup(By::Root, &by_root));
    assert_eq!(std::fs::metadata(&by_root).unwrap().uid(), 0);
}
