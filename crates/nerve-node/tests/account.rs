//! A folder-mode command runs as the account the commands run as, confined
//! by Landlock to its folders like any folder-mode command, and the node's
//! own folders are out of that account's reach (issue #21). The test runs
//! as its own user, which stands in for the chosen account; the node's
//! folders are closed to it as `nerve`'s folders are closed to the account.

#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use nerve_node::exec::{self, RunCall, RunOptions};
use nerve_node::service::Account;
use nerve_policy::config::{Access, CenterPolicy, Folder, Mode};

fn set_mode(p: &Path, mode: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn me(home: &Path) -> Account {
    // SAFETY: plain getters.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    Account {
        name: "chosen".into(),
        uid,
        gid,
        comment: String::new(),
        home: home.to_path_buf(),
        groups: vec![gid],
    }
}

fn opts(policy: &CenterPolicy, account: &Account, own: &[PathBuf]) -> RunOptions {
    RunOptions {
        shell: None,
        landlock: Some(exec::landlock_spec(policy, &account.home, own, &[])),
        container: None,
        exe: env!("CARGO_BIN_EXE_nerve-node").into(),
        output_cap: 64 * 1024,
        timeouts: Default::default(),
        sudo: None,
        account: Some(account.clone()),
        separate: false,
        own: own.to_vec(),
        root: None,
        limits: None,
        tap: None,
    }
}

#[tokio::test]
async fn a_folder_mode_command_of_the_account_stays_in_its_folders_and_off_the_keys() {
    if !nerve_sandbox::Confinement::detect().available() {
        eprintln!("skipped: Landlock is not available here");
        return;
    }
    if nerve_transport::net::euid() == 0 {
        eprintln!("skipped: root opens every folder");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(d.path()).unwrap();
    let home = root.join("home");
    let work = home.join("work");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(work.join("in.txt"), "inside\n").unwrap();
    std::fs::write(home.join("out.txt"), "outside\n").unwrap();
    // The node's folders, with a key, as install leaves them.
    let config = root.join("etc/nerve");
    let state = root.join("var/lib/nerve/state");
    nerve_transport::files::write_private(&config.join("keys/lab.key"), b"secret-key\n").unwrap();
    std::fs::create_dir_all(&state).unwrap();
    let own = vec![config.clone(), state.clone()];
    let policy = CenterPolicy {
        mode: Mode::Folder,
        folders: vec![Folder {
            path: work.display().to_string(),
            access: Access::ALL,
        }],
        ..CenterPolicy::default()
    };
    let account = me(&home);
    let call = |cmd: &str| RunCall {
        command: cmd.into(),
        argv: None,
        cwd: work.clone(),
        timeout: Some(Duration::from_secs(20)),
        limits: Default::default(),
    };
    let probe = format!(
        "id -u; echo HOME=$HOME; pwd; cat in.txt; cat {out}; cat {key}; echo end",
        out = home.join("out.txt").display(),
        key = config.join("keys/lab.key").display()
    );

    // While the account can open the node's folders, nothing runs.
    let e = exec::run(&call(&probe), &opts(&policy, &account, &own), |_| {})
        .await
        .unwrap_err();
    assert!(
        e.message.contains("can open the node's own folders"),
        "{}",
        e.message
    );

    // Closed to it, as nerve's folders are: the command runs as the
    // account, in its folder, and reaches nothing outside it.
    set_mode(&config, 0o000);
    set_mode(&root.join("var/lib/nerve"), 0o000);
    let r = exec::run(&call(&probe), &opts(&policy, &account, &own), |_| {}).await;
    set_mode(&config, 0o700);
    set_mode(&root.join("var/lib/nerve"), 0o700);
    let r = r.unwrap();
    let out = r["stdout"].as_str().unwrap();
    let err = r["stderr"].as_str().unwrap();
    assert_eq!(
        out,
        format!(
            "{}\nHOME={}\n{}\ninside\nend\n",
            account.uid,
            home.display(),
            work.display()
        ),
        "{err}"
    );
    assert!(
        !out.contains("outside") && !out.contains("secret-key"),
        "{out}"
    );
    assert!(err.contains("out.txt") && err.contains("lab.key"), "{err}");

    // The key is closed by Landlock too, not only by its folder's bits:
    // with the folders open to the check's eyes but Landlock in force, the
    // command still cannot read it. (The check refuses that case, so the
    // rules are run here without it.)
    let mut o = opts(&policy, &account, &own);
    o.own = Vec::new();
    let r = exec::run(
        &call(&format!("cat {}", config.join("keys/lab.key").display())),
        &o,
        |_| {},
    )
    .await
    .unwrap();
    assert_ne!(r["exit_code"], 0, "{r}");
    assert!(!r["stdout"].as_str().unwrap().contains("secret-key"), "{r}");
}

/// A command of `nerve-run` (the test's own account stands in for it) has
/// its built-in folders in Landlock's set as in the gate's, `/tmp`,
/// `/var/tmp` and its home, and the environment of its home: its XDG
/// folders, no session of anyone's, and git trusting the repositories it
/// reaches (issue #142).
#[tokio::test]
async fn a_command_of_nerve_run_has_its_home_and_the_temporary_folders() {
    if !nerve_sandbox::Confinement::detect().available() {
        eprintln!("skipped: Landlock is not available here");
        return;
    }
    // The owner's home lies outside `/tmp` and `/var/tmp`, as a real one
    // does, wherever this checkout and its temporary folders are: the
    // owner's protected entries (`~/.ssh` and the like) inside `/tmp` would
    // keep the command from making a file there, as from every folder that
    // holds one. It need not be there: only its protected entries count.
    let owner_home = Path::new("/nonexistent-owner-of-nerve-142");
    let d = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(d.path()).unwrap();
    let run_home = root.join("run-home");
    let work = root.join("work");
    std::fs::create_dir_all(&run_home).unwrap();
    std::fs::create_dir_all(&work).unwrap();
    let mut folders = vec![Folder {
        path: work.display().to_string(),
        access: Access::ALL,
    }];
    folders.extend(nerve_node::account::built_in(&run_home));
    let policy = CenterPolicy {
        mode: Mode::Folder,
        folders,
        ..CenterPolicy::default()
    };
    let account = me(&run_home);
    let mut o = opts(&policy, &account, &[]);
    // `~` of the folders and rules is the owner's, not the account's.
    let spec = exec::landlock_spec(&policy, owner_home, &[], &[]);
    for t in ["/tmp", "/var/tmp"] {
        assert!(spec.write.iter().any(|w| w == Path::new(t)), "{spec:?}");
    }
    o.landlock = Some(spec);
    o.separate = true;
    let tmp = format!("/tmp/nerve-142-{}", std::process::id());
    let probe = format!(
        "echo \"$HOME|$XDG_CONFIG_HOME|$XDG_CACHE_HOME|${{XDG_RUNTIME_DIR-none}}|${{DBUS_SESSION_BUS_ADDRESS-none}}\"; \
         echo t > {tmp} && cat {tmp} && rm {tmp}; \
         echo h > \"$HOME/h\" && cat \"$HOME/h\"; \
         echo $GIT_CONFIG_KEY_0=$GIT_CONFIG_VALUE_0"
    );
    let call = RunCall {
        command: probe,
        argv: None,
        cwd: work.clone(),
        timeout: Some(Duration::from_secs(20)),
        limits: Default::default(),
    };
    let r = exec::run(&call, &o, |_| {}).await.unwrap();
    let out = r["stdout"].as_str().unwrap();
    let h = run_home.display();
    assert_eq!(
        out,
        format!("{h}|{h}/.config|{h}/.cache|none|none\nt\nh\nsafe.directory=*\n"),
        "{}",
        r["stderr"]
    );
}
