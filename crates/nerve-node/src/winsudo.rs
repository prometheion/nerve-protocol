//! The sudo switch on Windows (docs/dev/windows.md, docs/dev/spec/node-local.md
//! §4). Windows has no sudo program: a sudo command starts with the full
//! token of the owner, the account that ran `install` (crate::owner). That is
//! the account's logon
//! as a batch job, which UAC does not filter, as the task scheduler logs an
//! account on for a task that runs with highest privileges; an
//! administrator then has the Administrators group in effect. It takes the
//! account's password, and the installed service, which alone may start a
//! process with another account's token (crate::win_user).
//!
//! The switch keeps that password with DPAPI in the config folder
//! ([`SUDO_FILE`]), as `install` keeps the owner's password
//! (crate::winsvc::SECRET_FILE), and a restart holds it again ([`settle`]).
//! `sudo on` and `sudo off` go to the running service over its control
//! pipe, which checks the password and keeps it ([`take`]) or drops it at
//! once, as a center with the settings grant does. With no node running,
//! `sudo off` removes the file itself.
//!
//! The steps go through [`WinSystem`], so they run on every platform in the
//! tests.

use std::io::Write;

use nerve_policy::config::Sudo;
use nerve_policy::settings::SettingsStore;
use serde_json::{Value, json};

use crate::paths::NodePaths;
use crate::service::{Account, write_file};
use crate::winsvc::{WinSystem, parse_secret, secret};

/// The file in the config folder that holds the sudo password, encrypted
/// with DPAPI, while the switch is on.
pub const SUDO_FILE: &str = "sudo.dpapi";

/// Why a node that is not the installed service has no sudo switch.
pub const INSTALLED_ONLY: &str = "on Windows the sudo switch works on the node installed as a service (Nerve's installer installs it): only the service may start a command with the administrator token of the node's owner";

/// Why `sudo on` finds no account: the service names no owner.
pub const NO_OWNER: &str = "this node has no owner, whose administrator rights sudo commands run with: install it again with Nerve's installer, as yourself";

/// Why `name`, not an administrator, cannot have the switch.
pub fn not_admin(name: &str) -> String {
    format!(
        "{name} is not an administrator: on Windows a sudo command runs with the administrator rights of the node's owner, so the owner must be in the Administrators group. Then every command that runs as {name}, not only sudo commands, can get those rights back (UAC is no security boundary) and read the node's keys"
    )
}

/// What the owner is told when the switch turns on: the account is an
/// administrator, so its other commands can rise as well
/// (crate::winsvc::admin_warning says the same at install).
pub fn warning(name: &str) -> String {
    format!(
        "Warning: sudo commands run as {name} with its administrator rights. They can change anything on this machine and read the node's keys. {name} is an administrator, and UAC is no security boundary: every other command of {name} can get these rights back too, not only the commands on the sudo list. Allow commands only to centers you trust with this machine."
    )
}

/// What `sudo off` adds while the owner is still in `groups`, the ones
/// whose members can read every file (crate::winsvc::admin_warning).
pub fn still_admin(name: &str, groups: &[String]) -> String {
    let groups = groups.join(", ");
    format!(
        "{name} is still in the group {groups}: its commands can still get those rights back (UAC is no security boundary) and read the node's keys. Take it out of {groups} to close that way too."
    )
}

/// Whether the switch may turn on for `account` (`None`: the node runs the
/// commands as its own user) with `password`: the installed node, and an
/// account whose batch logon with that password holds the Administrators
/// group. A wrong password is refused.
pub fn check(sys: &dyn WinSystem, account: Option<&Account>, password: &str) -> Result<(), String> {
    let a = account.ok_or(INSTALLED_ONLY)?;
    if sys.sudo_logon(&a.name, password)? {
        Ok(())
    } else {
        Err(not_admin(&a.name))
    }
}

/// What the running node does with the password of `sudo on`: checks it
/// for `account` ([`check`]) and keeps it ([`keep`]). The account's name.
pub fn take(
    paths: &NodePaths,
    sys: &dyn WinSystem,
    account: Option<&Account>,
    password: &str,
) -> Result<String, String> {
    check(sys, account, password)?;
    let name = &account.expect("checked").name;
    keep(paths, sys, name, password)?;
    Ok(name.clone())
}

/// Why `sudo on` asks for no password while no node runs.
pub const NEEDS_THE_NODE: &str = "sudo on needs the running node, which checks the password: start it on the app's Overview, then turn sudo on again";

/// Keeps `password`, `name`'s, with DPAPI in [`SUDO_FILE`].
pub fn keep(
    paths: &NodePaths,
    sys: &dyn WinSystem,
    name: &str,
    password: &str,
) -> Result<(), String> {
    let sealed = sys.protect(&secret(name, password))?;
    write_file(&paths.config_dir.join(SUDO_FILE), &sealed, 0o600)
}

/// Removes [`SUDO_FILE`]; one that is not there is fine.
pub fn forget(paths: &NodePaths) -> Result<(), String> {
    let file = paths.config_dir.join(SUDO_FILE);
    match std::fs::remove_file(&file) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("{}: {e}", file.display())),
    }
}

/// Whether [`SUDO_FILE`] is there.
pub fn kept(paths: &NodePaths) -> bool {
    paths.config_dir.join(SUDO_FILE).is_file()
}

/// The password [`keep`] kept, when it is `user`'s: the owner now
/// (crate::owner).
pub fn stored(paths: &NodePaths, sys: &dyn WinSystem, user: Option<&str>) -> Option<String> {
    let user = user?;
    let blob = std::fs::read(paths.config_dir.join(SUDO_FILE)).ok()?;
    let (name, password) = parse_secret(&sys.unprotect(&blob).ok()?)?;
    name.eq_ignore_ascii_case(user).then_some(password)
}

/// What the running node does with the password it holds (crate::sudo).
#[derive(Debug, PartialEq, Eq)]
pub enum Settle {
    /// The switch is on, no password is held and one is kept: a start, or
    /// `sudo on` before it. The node holds the kept one.
    Load,
    /// A password is held but none is kept any more: `sudo off` removed
    /// it. The node drops it, and the switch goes off.
    Drop,
    Nothing,
}

/// [`Settle`] for the switch `on`, whether a password is `held`, and
/// whether one is `kept`.
pub fn settle(on: bool, held: bool, kept: bool) -> Settle {
    match (on, held, kept) {
        (true, false, true) => Settle::Load,
        (true, true, false) => Settle::Drop,
        _ => Settle::Nothing,
    }
}

/// The signed config, read as the CLI reads it: its key may be in the
/// system keyring (`machine.secret_storage`).
fn read(paths: &NodePaths) -> Result<nerve_policy::NodeConfig, String> {
    SettingsStore::peek_with(
        &paths.config_file(),
        &crate::secrets::NodeSecrets::for_cli(paths),
    )
}

/// `nerve-node sudo on`: asks for the password of the account the commands
/// run as and hands it to the running node over `call` (its control pipe),
/// which checks it, keeps it ([`take`]) and turns the switch on at once.
/// `installed` says whether `paths` are the installed service's.
pub async fn on(
    sys: &dyn WinSystem,
    installed: bool,
    call: impl AsyncFn(&str, Value) -> Result<Value, String>,
    out: &mut dyn Write,
) -> Result<(), String> {
    if !sys.is_admin() {
        return Err(
            "sudo on needs an administrator: the switch under Permissions › Sudo in the app asks Windows for the rights".into(),
        );
    }
    if !installed {
        return Err(INSTALLED_ONLY.into());
    }
    // Fail before asking for the password when nothing can take it.
    match call("status", json!({})).await {
        Ok(_) => {}
        Err(e) if e == nerve_transport::ctl::NOT_RUNNING => return Err(NEEDS_THE_NODE.into()),
        Err(e) => return Err(e),
    }
    let (_, name) = sys.owner()?.ok_or(NO_OWNER)?;
    let a = sys
        .account(&name)?
        .ok_or_else(|| format!("there is no local account {name}"))?;
    let password =
        sys.read_password(&format!("Password of {}, the node's owner: ", a.name), out)?;
    call("sudo.on", json!({ "password": password })).await?;
    let _ = writeln!(
        out,
        "sudo: on (only commands the sudo allow list names run with sudo)\n{}",
        warning(&a.name),
    );
    Ok(())
}

/// `nerve-node sudo off`: the running node drops the password at once and
/// sets the switch off (`call`, its control pipe); with no node running the
/// kept password and the switch go from the files here.
pub async fn off(
    paths: &NodePaths,
    sys: &dyn WinSystem,
    call: impl AsyncFn(&str, Value) -> Result<Value, String>,
    out: &mut dyn Write,
) -> Result<(), String> {
    if !sys.is_admin() {
        return Err(
            "sudo off needs an administrator: the switch under Permissions › Sudo in the app asks Windows for the rights".into(),
        );
    }
    match call("sudo.off", json!({})).await {
        Ok(_) => {}
        Err(e) if crate::cli::no_node(paths, &e) => {
            forget(paths)?;
            crate::cli::edit(paths, |c| {
                c.machine.sudo = Sudo::Off;
                Ok(())
            })
            .await?;
        }
        Err(e) => return Err(e),
    }
    let _ = writeln!(out, "sudo: off");
    // What `sudo on` asked for stays: the account is still in the group.
    let account = sys
        .owner()
        .ok()
        .flatten()
        .and_then(|(_, n)| sys.account(&n).ok().flatten());
    if let Some(a) = account {
        let groups = sys.admin_groups(&a);
        if !groups.is_empty() {
            let _ = writeln!(out, "{}", still_admin(&a.name, &groups));
        }
    }
    Ok(())
}

/// `nerve-node sudo`: what the running node says (`call`); with no node
/// running, on when the signed config says so and the password is kept.
pub async fn status(
    paths: &NodePaths,
    call: impl AsyncFn(&str, Value) -> Result<Value, String>,
) -> Result<bool, String> {
    match call("sudo.status", json!({})).await {
        Ok(v) => Ok(v["sudo"] == "on"),
        Err(e) if crate::cli::no_node(paths, &e) => kept_on(paths),
        Err(e) => Err(e),
    }
}

/// On in the signed config, with the password kept.
fn kept_on(paths: &NodePaths) -> Result<bool, String> {
    let cfg = read(paths)?;
    Ok(cfg.machine.sudo == Sudo::On && kept(paths))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::winsvc::tests::{Fake, account, installed};

    fn sudo_of(paths: &NodePaths) -> Sudo {
        read(paths).unwrap().machine.sudo
    }

    #[test]
    fn the_switch_needs_the_installed_node_an_administrator_and_the_right_password() {
        let sys = Fake::new();
        sys.passwords
            .borrow_mut()
            .push(("bob".into(), "bob's".into()));
        let (alice, bob) = (account("alice", 1001, ""), account("bob", 1002, ""));
        assert_eq!(check(&sys, None, "x").unwrap_err(), INSTALLED_ONLY);
        // Alice logs on, but her logon has no Administrators group.
        let e = check(&sys, Some(&alice), "alice's").unwrap_err();
        assert!(e.contains("alice is not an administrator"), "{e}");
        // What making her one means is said.
        assert!(
            e.contains("not only sudo commands") && e.contains("UAC is no security boundary"),
            "{e}"
        );
        let e = check(&sys, Some(&bob), "wrong").unwrap_err();
        assert!(e.contains("password of bob is wrong"), "{e}");
        check(&sys, Some(&bob), "bob's").unwrap();
        assert_eq!(
            sys.calls()
                .iter()
                .filter(|c| c.starts_with("batch logon"))
                .count(),
            3
        );
    }

    /// The node the CLI talks to over its control pipe, as far as the switch
    /// goes: it takes the password as the daemon does ([`take`], then the
    /// switch in its config), records what it was sent, and answers
    /// [`nerve_transport::ctl::NOT_RUNNING`] while it is `down`.
    struct Node<'a> {
        paths: &'a NodePaths,
        sys: &'a dyn WinSystem,
        down: std::cell::Cell<bool>,
        sent: std::cell::RefCell<Vec<String>>,
    }

    impl Node<'_> {
        async fn call(&self, method: &str, params: Value) -> Result<Value, String> {
            if self.down.get() {
                return Err(nerve_transport::ctl::NOT_RUNNING.into());
            }
            self.sent.borrow_mut().push(format!("{method} {params}"));
            let set = |on: bool| {
                crate::cli::edit(self.paths, move |c| {
                    c.machine.sudo = if on { Sudo::On } else { Sudo::Off };
                    Ok(())
                })
            };
            match method {
                "status" => Ok(json!({})),
                "sudo.status" => {
                    Ok(json!({"sudo": if kept_on(self.paths)? { "on" } else { "off" }}))
                }
                "sudo.on" => {
                    let user = self.sys.owner()?.map(|(_, n)| n);
                    let account = user.and_then(|n| self.sys.account(&n).ok().flatten());
                    let password = params["password"].as_str().unwrap_or_default();
                    take(self.paths, self.sys, account.as_ref(), password)?;
                    set(true).await?;
                    Ok(json!({"sudo": "on"}))
                }
                "sudo.off" => {
                    forget(self.paths)?;
                    set(false).await?;
                    Ok(json!({"sudo": "off"}))
                }
                m => Err(format!("unknown method {m}")),
            }
        }
    }

    /// A pipe of the node's name that another account made, while no node
    /// runs, is no node: `sudo off` and the status work on the files, as the
    /// other commands do (cli::no_node).
    #[tokio::test]
    async fn another_accounts_pipe_is_no_node_for_the_switch() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        let p = &l.paths;
        let call = async |_: &str, _: Value| -> Result<Value, String> {
            Err(format!(
                "{}: \\\\.\\pipe\\nerve-node-1 belongs to S-1-5-21-9",
                crate::pipe::NOT_THE_NODES
            ))
        };
        keep(p, &sys, "alice", "alice's").unwrap();
        crate::cli::edit(p, |c| {
            c.machine.sudo = Sudo::On;
            Ok(())
        })
        .await
        .unwrap();
        assert!(status(p, call).await.unwrap());
        off(p, &sys, call, &mut Vec::new()).await.unwrap();
        assert_eq!(sudo_of(p), Sudo::Off);
        assert!(!status(p, call).await.unwrap());
    }

    #[tokio::test]
    async fn sudo_on_hands_the_password_to_the_node_and_sudo_off_takes_it_back() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        let p = &l.paths;
        let file = p.config_dir.join(SUDO_FILE);
        let node = Node {
            paths: p,
            sys: &sys,
            down: false.into(),
            sent: Default::default(),
        };
        let call = async |m: &str, v: Value| node.call(m, v).await;
        // Alice, who installed the node, is no administrator.
        sys.types("alice's");
        let e = on(&sys, true, call, &mut Vec::new()).await.unwrap_err();
        assert!(e.contains("alice is not an administrator"), "{e}");
        assert!(!file.exists());
        sys.put_owner("S-1-5-21-1-2-3-1002").unwrap();
        sys.passwords
            .borrow_mut()
            .push(("bob".into(), "bob's".into()));
        // Neither a node that is not installed nor a terminal without the
        // administrators' rights asks for the password, nor a node that
        // does not run, which alone takes it.
        let e = on(&sys, false, call, &mut Vec::new()).await.unwrap_err();
        assert_eq!(e, INSTALLED_ONLY);
        let mut user = Fake::new();
        user.admin = false;
        let e = on(&user, true, call, &mut Vec::new()).await.unwrap_err();
        assert!(e.contains("needs an administrator"), "{e}");
        let e = off(p, &user, call, &mut Vec::new()).await.unwrap_err();
        assert!(e.contains("needs an administrator"), "{e}");
        node.down.set(true);
        let mut out = Vec::new();
        let e = on(&sys, true, call, &mut out).await.unwrap_err();
        assert_eq!(e, NEEDS_THE_NODE);
        assert!(String::from_utf8(out).unwrap().is_empty());
        node.down.set(false);
        // A wrong password leaves the switch off and keeps nothing.
        sys.types("wrong");
        let e = on(&sys, true, call, &mut Vec::new()).await.unwrap_err();
        assert!(e.contains("password of bob is wrong"), "{e}");
        assert!(!file.exists());
        assert_eq!(sudo_of(p), Sudo::Off);
        assert!(!status(p, call).await.unwrap());
        // The right one: the node has it, keeps it sealed and is on now.
        sys.types("bob's");
        let mut out = Vec::new();
        on(&sys, true, call, &mut out).await.unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("Password of bob"), "{out}");
        assert!(out.contains("sudo: on"), "{out}");
        assert!(
            out.contains("run as bob with its administrator rights"),
            "{out}"
        );
        // Not only sudo commands: the account's others can rise too.
        assert!(
            out.contains("UAC is no security boundary")
                && out.contains("not only the commands on the sudo list"),
            "{out}"
        );
        // In force at once: no line says it waits for a restart.
        assert!(!out.contains("Restart"), "{out}");
        assert!(!out.lines().any(crate::cli::takes_at_next_start), "{out}");
        assert!(!out.contains("bob's"), "{out}");
        assert!(
            node.sent
                .borrow()
                .iter()
                .any(|c| c == r#"sudo.on {"password":"bob's"}"#),
            "{:?}",
            node.sent
        );
        let blob = std::fs::read(&file).unwrap();
        assert!(!blob.windows(5).any(|w| w == b"bob's"));
        assert_eq!(stored(p, &sys, Some("BOB")).as_deref(), Some("bob's"));
        // A password is one account's.
        assert_eq!(stored(p, &sys, Some("alice")), None);
        assert_eq!(stored(p, &sys, None), None);
        assert_eq!(sudo_of(p), Sudo::On);
        assert!(status(p, call).await.unwrap());
        // Off goes to the node.
        let mut out = Vec::new();
        off(p, &sys, call, &mut out).await.unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.starts_with("sudo: off"), "{out}");
        assert_eq!(node.sent.borrow().last().unwrap(), "sudo.off {}");
        // Bob stays an administrator; off says so, naming his group.
        assert!(
            out.contains("bob is still in the group Administrators")
                && out.contains("Take it out of Administrators"),
            "{out}"
        );
        assert!(!file.exists());
        assert_eq!(sudo_of(p), Sudo::Off);
        assert!(!status(p, call).await.unwrap());
        assert_eq!(stored(p, &sys, Some("bob")), None);
        // With no node running, off removes the kept password and the
        // switch from the files, and the status reads them.
        keep(p, &sys, "bob", "bob's").unwrap();
        crate::cli::edit(p, |c| {
            c.machine.sudo = Sudo::On;
            Ok(())
        })
        .await
        .unwrap();
        node.down.set(true);
        assert!(status(p, call).await.unwrap());
        off(p, &sys, call, &mut Vec::new()).await.unwrap();
        assert!(!file.exists());
        assert_eq!(sudo_of(p), Sudo::Off);
        assert!(!status(p, call).await.unwrap());
        node.down.set(false);
        // Another group that can read every file is named as it is; an
        // account in none gets no reminder.
        for (who, said) in [
            ("dave", Some("dave is still in the group Backup Operators")),
            ("alice", None),
        ] {
            let uid = sys.account(who).unwrap().unwrap().uid;
            sys.put_owner(&format!("S-1-5-21-1-2-3-{uid}")).unwrap();
            let mut out = Vec::new();
            off(p, &sys, call, &mut out).await.unwrap();
            let out = String::from_utf8(out).unwrap();
            match said {
                Some(s) => assert!(
                    out.contains(s) && out.contains("Take it out of Backup Operators"),
                    "{out}"
                ),
                None => assert!(!out.contains("still in the group"), "{out}"),
            }
        }
    }

    /// A node whose config key is in the system keyring (no `config.key`)
    /// reads its config there for `sudo` while it does not run.
    #[test]
    fn status_reads_a_config_whose_key_is_in_the_keyring() {
        let d = tempfile::tempdir().unwrap();
        let p = NodePaths::new(d.path().join("config"), d.path().join("state"));
        let mut s = SettingsStore::open_with(
            p.config_file(),
            Box::new(crate::secrets::NodeSecrets::new(&p)),
            nerve_policy::audit::AuditLog::new(p.audit_log()),
        )
        .unwrap();
        s.update(|c| {
            c.machine.secret_storage = nerve_policy::config::SecretStorage::Keyring;
            Ok(())
        })
        .unwrap();
        assert!(!p.config_key().exists());
        assert_eq!(kept_on(&p), Ok(false));
    }

    /// The running node holds a kept password when the switch is on, and
    /// drops the one it holds when `sudo off` removed it.
    #[test]
    fn the_running_node_follows_the_kept_password() {
        assert_eq!(settle(true, false, true), Settle::Load);
        assert_eq!(settle(true, true, false), Settle::Drop);
        for (on, held, kept) in [
            (true, true, true),
            (true, false, false),
            (false, false, true),
            (false, true, true),
            (false, true, false),
            (false, false, false),
        ] {
            assert_eq!(
                settle(on, held, kept),
                Settle::Nothing,
                "{on} {held} {kept}"
            );
        }
    }
}
