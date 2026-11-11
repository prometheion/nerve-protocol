//! What the node's and the center's services share (docs/dev/service.md):
//! the accounts, systemd, the files root writes for a service, the owner's
//! passphrase prompt, and `update`, which replaces the program, writes the
//! service's files as the new program has them and puts both back when it
//! does not start. Each service names its own program, user and files. On
//! Windows they share the service control manager, the protected DACL, the
//! Event Log, the control pipe's checks and the job object ([`win`]).
//!
//! What a step does to the machine beyond the service's files (accounts,
//! systemd, running a program) goes through [`System`], so the tests run
//! every step on temporary folders.

use std::path::{Path, PathBuf};

pub mod account;
pub mod eventlog;
#[doc(hidden)]
pub mod fake;
mod files;
pub mod prompt;
mod update;
pub mod win;

pub use account::Account;
#[cfg(unix)]
pub use files::owner_to_become;
pub use files::{as_owner_of, become_owner, chown_tree, set_mode, write_file};
pub use update::{
    Place, Placed, Program, SERVICE_FILES, ServiceFile, Steps, Version, fetch_release,
    fetch_release_where, files_from, files_text, start_unit, system_account, update,
};

/// The control socket of the node `nerve-node install` put on a Linux
/// machine (its state folder `/var/lib/nerve/state`): the center's service
/// commands ask it whether a command of that node runs them.
pub const NODE_CTL_SOCKET: &str = "/var/lib/nerve/state/run/ctl.sock";

/// What install, update and uninstall do to the machine besides writing the
/// service's files. The node's and the center's services add what they ask
/// of their own service.
pub trait System {
    fn is_root(&self) -> bool;
    /// Whether systemd runs this machine.
    fn has_systemd(&self) -> bool;
    fn account(&self, name: &str) -> Result<Option<Account>, String>;
    /// Makes a system user with a group of the same name and no other, the
    /// home given (not created) and no login, marked with `mark`.
    fn add_account(&self, name: &str, home: &Path, mark: &str) -> Result<(), String>;
    /// Removes the user and its group.
    fn remove_account(&self, name: &str) -> Result<(), String>;
    fn systemctl(&self, args: &[&str]) -> Result<(), String>;
    /// Gives `path` and everything below it to `uid`:`gid`.
    fn give(&self, path: &Path, uid: u32, gid: u32) -> Result<(), String>;
    /// What `<program> <args>` prints, run with an empty environment: a
    /// program `update` staged, before it takes the installed one's place.
    /// It runs as `account`, the service's user, or as the caller (root)
    /// where there is none. Whatever root writes from what it printed must
    /// not come from a process of the service's user, which every other
    /// process of that user can reach; so the files are asked of it as root.
    fn output_of(
        &self,
        program: &Path,
        account: Option<&Account>,
        args: &[&str],
    ) -> Result<String, String>;
    /// What `<program> --version` prints, run as `account`.
    fn version_of(&self, program: &Path, account: &Account) -> Result<String, String> {
        self.output_of(program, Some(account), &["--version"])
    }
}

/// This machine.
pub struct Host;

impl System for Host {
    fn is_root(&self) -> bool {
        nerve_transport::net::euid() == 0
    }

    fn has_systemd(&self) -> bool {
        Path::new("/run/systemd/system").is_dir()
    }

    fn account(&self, name: &str) -> Result<Option<Account>, String> {
        #[cfg(not(windows))]
        {
            account::lookup(name)
        }
        #[cfg(windows)]
        {
            let _ = name;
            Err("accounts are looked up through Windows itself".into())
        }
    }

    fn add_account(&self, name: &str, home: &Path, mark: &str) -> Result<(), String> {
        run(
            "useradd",
            &[
                "--system",
                "--user-group",
                "--home-dir",
                &home.display().to_string(),
                "--no-create-home",
                "--shell",
                no_login(),
                "--comment",
                mark,
                "--",
                name,
            ],
        )
    }

    fn remove_account(&self, name: &str) -> Result<(), String> {
        run("userdel", &["--", name])?;
        // userdel takes the group along where the system makes one group per
        // user; elsewhere it stays behind.
        let group = std::process::Command::new("getent")
            .args(["group", name])
            .output()
            .is_ok_and(|o| o.status.success());
        if group {
            run("groupdel", &["--", name])?;
        }
        Ok(())
    }

    fn systemctl(&self, args: &[&str]) -> Result<(), String> {
        let mut c = std::process::Command::new("systemctl");
        c.args(args);
        // The node's setup restarts the node after it installed a keyring.
        regain_root(&mut c);
        let o = c.output().map_err(|e| format!("systemctl: {e}"))?;
        if o.status.success() {
            Ok(())
        } else {
            Err(format!("systemctl {}: {}", args.join(" "), failure(&o)))
        }
    }

    fn give(&self, path: &Path, uid: u32, gid: u32) -> Result<(), String> {
        chown_tree(path, uid, gid)
    }

    fn output_of(
        &self,
        program: &Path,
        account: Option<&Account>,
        args: &[&str],
    ) -> Result<String, String> {
        let mut c = std::process::Command::new(program);
        c.args(args).env_clear().current_dir("/");
        // A downloaded program asked for its version runs as the service's
        // user, not as root.
        #[cfg(unix)]
        if let (true, Some(account)) = (self.is_root(), account) {
            use std::os::unix::process::CommandExt;
            c.uid(account.uid).gid(account.gid);
        }
        #[cfg(not(unix))]
        let _ = account;
        // The program `update` staged a moment ago.
        let o = nerve_transport::files::retry_busy(|| c.output())
            .map_err(|e| format!("{}: {e}", program.display()))?;
        if !o.status.success() {
            return Err(format!(
                "{} {}: {}",
                program.display(),
                args.join(" "),
                failure(&o)
            ));
        }
        Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
    }
}

/// The shell of an account that does not log in.
pub fn no_login() -> &'static str {
    ["/usr/sbin/nologin", "/sbin/nologin"]
        .into_iter()
        .find(|s| Path::new(s).exists())
        .unwrap_or("/bin/false")
}

/// Lets `c` run as root where this process keeps root only as its saved id
/// (the node's setup on the installed node, [`become_owner`]); elsewhere it
/// runs as this process does.
pub fn regain_root(c: &mut std::process::Command) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        let (mut r, mut e, mut s) = (0, 0, 0);
        // SAFETY: getresuid writes the three ids it is given.
        unsafe { libc::getresuid(&mut r, &mut e, &mut s) };
        if e == 0 || s != 0 {
            return;
        }
        // SAFETY: plain system calls between fork and exec.
        unsafe {
            c.pre_exec(|| {
                if libc::setresuid(0, 0, 0) != 0
                    || libc::setresgid(0, 0, 0) != 0
                    || libc::setgroups(0, std::ptr::null()) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = c;
}

/// Runs a system tool; its error output is the error.
pub fn run(program: &str, args: &[&str]) -> Result<(), String> {
    let o = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    if o.status.success() {
        Ok(())
    } else {
        Err(format!("{program} {}: {}", args.join(" "), failure(&o)))
    }
}

/// What a tool that failed said: its error output, else its exit status.
pub fn failure(o: &std::process::Output) -> String {
    let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
    if err.is_empty() {
        o.status.to_string()
    } else {
        err
    }
}

/// Refuses a service command that a command the node runs for a center
/// runs, asking the nodes at the control sockets `sockets`: an agent cannot
/// replace or remove the node or the center that way. A node that does not
/// run, or does not know the question, runs no such command. On Windows the
/// installed node is asked on its control pipe instead ([`NODE_SERVICE_STATE`]).
pub async fn owner_check(sockets: &[PathBuf]) -> Result<(), String> {
    #[cfg(unix)]
    for s in sockets {
        let answer = nerve_transport::ctl::call(s, "owner.check", serde_json::json!({})).await;
        owner_answer(answer)?;
    }
    #[cfg(windows)]
    {
        let _ = sockets;
        owner_answer(win::pipe::node_owner_check().await)?;
    }
    #[cfg(not(any(unix, windows)))]
    let _ = sockets;
    Ok(())
}

/// What a node's answer to `owner.check` lets through.
fn owner_answer(answer: Result<serde_json::Value, String>) -> Result<(), String> {
    match answer {
        Ok(_) => Ok(()),
        // No node runs, so no command of one does.
        Err(e) if e == nerve_transport::ctl::NOT_RUNNING => Ok(()),
        // A node that does not know the method cannot answer it. It is let
        // through.
        Err(e) if e.starts_with("unknown method") => Ok(()),
        Err(e) => Err(e),
    }
}

/// The state folder of the node Nerve's installer puts on a Windows machine,
/// below `program_data` (`%ProgramData%`); the name of its control pipe
/// comes from it.
pub const NODE_SERVICE_STATE: &str = "Nerve\\state";
