//! An allowed sudo command of `nerve-run` runs as root, started by the node
//! (issue #142): its shell gets the allowed line and nothing around it, it
//! starts in the folder the node opened as the owner, with a fixed
//! environment, and a folder name is only ever a name.
//!
//! The first tests run as the test's own user, which stands in for root.
//! The last one needs root: as root itself, else in a user namespace of its
//! own (`unshare --map-root-user --map-auto`), which it starts when it can;
//! it says it skipped otherwise.

#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use nerve_node::exec::{self, AsRoot, RunCall, RunOptions};
use nerve_node::service::Account;

/// The owner in the namespace test, an id without an account.
const OWNER: u32 = 4301;

fn account(name: &str, uid: u32, gid: u32, home: &Path) -> Account {
    Account {
        name: name.into(),
        uid,
        gid,
        comment: String::new(),
        home: home.to_path_buf(),
        groups: vec![gid],
    }
}

/// The test's own user, standing in for root.
fn me(home: &Path) -> Account {
    // SAFETY: plain getters.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    account("root", uid, gid, home)
}

fn opts(account: &Account, root: AsRoot) -> RunOptions {
    RunOptions {
        // Root's command runs in /bin/sh whatever the owner's shell is.
        shell: Some("/nonexistent/shell".into()),
        landlock: None,
        container: None,
        exe: PathBuf::from("/nonexistent"),
        output_cap: 64 * 1024,
        timeouts: Default::default(),
        sudo: None,
        account: Some(account.clone()),
        separate: false,
        own: Vec::new(),
        root: Some(root),
        limits: None,
        tap: None,
    }
}

fn call(command: &str, cwd: &Path) -> RunCall {
    RunCall {
        command: command.into(),
        cwd: cwd.to_path_buf(),
        timeout: Some(Duration::from_secs(20)),
        limits: Default::default(),
    }
}

/// Every name below `dir`, at any depth.
fn names(dir: &Path) -> Vec<String> {
    let mut all = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        all.push(e.file_name().to_string_lossy().into_owned());
        if e.file_type().unwrap().is_dir() {
            all.extend(names(&e.path()));
        }
    }
    all
}

/// Folder names a shell would read as more than a name.
const ODD: &[&str] = &[
    "with space",
    "single'quote",
    "double\"quote",
    "$(touch ran-dollar)",
    "`touch ran-tick`",
    "semi;touch ran-semi",
    "line\ntouch ran-line",
    "and&&touch ran-and",
    "pipe|touch ran-pipe",
    "$HOME",
    "-n",
    "--",
];

#[tokio::test]
async fn a_root_command_starts_in_its_folder_and_takes_its_name_as_data() {
    let d = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(d.path()).unwrap();
    let root = me(&base);
    for name in ODD {
        let dir = base.join(name);
        std::fs::create_dir(&dir).unwrap();
        let start = AsRoot::open(&dir, None).unwrap();
        let r = exec::run(&call("pwd -P", &dir), &opts(&root, start), |_| {})
            .await
            .unwrap();
        assert_eq!(r["exit_code"], 0, "{name:?}: {r}");
        assert_eq!(r["stdout"], format!("{}\n", dir.display()), "{name:?}: {r}");
        assert_eq!(r["stderr"], "", "{name:?}: {r}");
    }
    // Nothing but the command ran: no name became a command.
    let made: Vec<_> = names(&base)
        .into_iter()
        .filter(|n| n.starts_with("ran-"))
        .collect();
    assert!(made.is_empty(), "{made:?}");
    for f in [
        "ran-dollar",
        "ran-tick",
        "ran-semi",
        "ran-line",
        "ran-and",
        "ran-pipe",
    ] {
        assert!(!Path::new(f).exists(), "{f}");
    }
}

#[tokio::test]
async fn a_root_command_gets_a_fixed_environment() {
    let d = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(d.path()).unwrap();
    let root = me(&base);
    let start = AsRoot::open(&base, None).unwrap();
    let r = exec::run(&call("env", &base), &opts(&root, start), |_| {})
        .await
        .unwrap();
    assert_eq!(r["exit_code"], 0, "{r}");
    let env = r["stdout"].as_str().unwrap();
    // What the shell itself adds aside, only what the node set.
    let shell_own = ["PWD", "OLDPWD", "SHLVL", "_"];
    for line in env.lines() {
        let (k, v) = line.split_once('=').unwrap_or((line, ""));
        match k {
            "PATH" => assert_eq!(v, exec::ROOT_PATH, "{env}"),
            "HOME" => assert_eq!(v, base.to_str().unwrap(), "{env}"),
            "USER" | "LOGNAME" => assert_eq!(v, "root", "{env}"),
            k if shell_own.contains(&k) => {}
            other => panic!("{other} came from the node's environment: {env}"),
        }
    }
    assert!(
        env.contains(&format!("PATH={}\n", exec::ROOT_PATH)),
        "{env}"
    );
}

/// An allowed line with a leading `-n` or `--` runs as the line without
/// them: the shell never sees sudo's options as its own. Another option of
/// sudo is refused before anything starts (exec::root_line).
#[tokio::test]
async fn a_root_command_runs_without_a_leading_n_and_is_refused_other_sudo_options() {
    let d = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(d.path()).unwrap();
    let root = me(&base);
    for args in ["pwd -P", "-n pwd -P", "-- pwd -P", "-n -- pwd -P"] {
        let line = exec::root_line(args).unwrap();
        let start = AsRoot::open(&base, None).unwrap();
        let r = exec::run(&call(line, &base), &opts(&root, start), |_| {})
            .await
            .unwrap();
        assert_eq!(r["exit_code"], 0, "{args:?}: {r}");
        assert_eq!(
            r["stdout"],
            format!("{}\n", base.display()),
            "{args:?}: {r}"
        );
        assert_eq!(r["stderr"], "", "{args:?}: {r}");
    }
    for args in ["-E true", "-u nobody true", "-n -i"] {
        let e = exec::root_line(args).unwrap_err();
        assert!(
            e.message.contains("no sudo option but -n and --"),
            "{args:?}: {e:?}"
        );
    }
}

/// A call without a folder starts in the owner's home, resolved: where the
/// home's path runs through a link (`/home` a link elsewhere), the root
/// start opens the real folder instead of refusing the link on the way.
#[tokio::test]
async fn a_root_command_without_a_folder_starts_in_a_home_behind_a_link() {
    let d = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(d.path()).unwrap();
    let real = base.join("data/alice");
    std::fs::create_dir_all(&real).unwrap();
    std::os::unix::fs::symlink(base.join("data"), base.join("home")).unwrap();
    let home = base.join("home/alice");
    let args = serde_json::json!({"command": "pwd -P"});
    let rc = RunCall::parse(args.as_object().unwrap(), &home).unwrap();
    assert_eq!(rc.cwd, real);
    let start = AsRoot::open(&rc.cwd, None).unwrap();
    let r = exec::run(&rc, &opts(&me(&base), start), |_| {})
        .await
        .unwrap();
    assert_eq!(r["exit_code"], 0, "{r}");
    assert_eq!(r["stdout"], format!("{}\n", real.display()), "{r}");
}

#[test]
fn a_root_command_does_not_start_behind_a_link() {
    let d = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(d.path()).unwrap();
    std::fs::create_dir_all(base.join("real/inner")).unwrap();
    std::os::unix::fs::symlink(base.join("real"), base.join("link")).unwrap();
    // The policy judged a path without links; one there now came later.
    for p in [base.join("link"), base.join("link/inner")] {
        assert!(AsRoot::open(&p, None).is_err(), "{p:?}");
    }
    assert!(AsRoot::open(&base.join("real/inner"), None).is_ok());
}

/// Whether root in a namespace of `unshare` may give a file to another
/// user, as the test does (tests/backup_caller.rs says why the namespace
/// alone is not enough).
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
        .args(["chown", &format!("{OWNER}:{OWNER}")])
        .arg(&probe)
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Keeps CAP_SETUID and CAP_SETGID only, on this thread, as the node's
/// service holds them: root's ids without a right past a folder's mode.
fn keep_only_setid_caps() {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: libc::c_int,
    }
    #[repr(C)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const V3: u32 = 0x2008_0522;
    const SETGID: u32 = 6;
    const SETUID: u32 = 7;
    let keep = (1 << SETGID) | (1 << SETUID);
    let h = Header {
        version: V3,
        pid: 0,
    };
    let data = [
        Data {
            effective: keep,
            permitted: keep,
            inheritable: 0,
        },
        Data {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    // SAFETY: capset with structs laid out as the kernel's.
    let r = unsafe { libc::syscall(libc::SYS_capset, &h as *const Header, data.as_ptr()) };
    assert_eq!(r, 0, "{}", std::io::Error::last_os_error());
}

#[test]
fn root_starts_in_a_folder_only_its_owner_may_enter() {
    const NAME: &str = "root_starts_in_a_folder_only_its_owner_may_enter";
    if nerve_transport::net::euid() != 0 {
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
        let status = Command::new("unshare")
            .args(unshare)
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
            .env("NERVE_TEST_IN_USERNS", "1")
            .status()
            .unwrap();
        assert!(status.success(), "in the namespace: {status}");
        return;
    }
    // The owner's closed home, and a folder in it with an odd name, both
    // the owner's alone.
    let d = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(d.path()).unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
    let home = base.join("home");
    let work = home.join("we ird;$(touch ran)\n-d");
    std::fs::create_dir_all(&work).unwrap();
    for p in [&home, &work] {
        std::os::unix::fs::chown(p, Some(OWNER), Some(OWNER)).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let owner = account("owner", OWNER, OWNER, &home);
    let root = account("root", 0, 0, Path::new("/root"));
    let w = work.clone();
    let r = std::thread::spawn(move || {
        keep_only_setid_caps();
        // Root's ids alone do not reach the folder: the owner's do.
        assert!(AsRoot::open(&w, None).is_err(), "root opened it itself");
        let start = AsRoot::open(&w, Some(&owner)).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(exec::run(
            &call("pwd -P && id -u && id -G", &w),
            &opts(&root, start),
            |_| {},
        ))
    })
    .join()
    .unwrap()
    .unwrap();
    assert_eq!(r["exit_code"], 0, "{r}");
    assert_eq!(
        r["stdout"],
        format!("{}\n0\n0\n", work.display()),
        "root, in the owner's folder, with root's group only: {r}"
    );
    assert!(
        !names(&base).iter().any(|n| n == "ran"),
        "{:?}",
        names(&base)
    );
}
