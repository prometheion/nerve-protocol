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
//! The running node holds that password in its memory only, as on Linux:
//! the switch is off after a restart of the node or of Windows. `sudo on`
//! and `sudo off` go to the running service over its control pipe, which
//! checks the password ([`take`]) or drops it at once. No center turns the
//! switch on for a Windows node (crate::sudo::center_may_turn_on): the
//! password is the owner's Windows password, which does not go through a
//! web page and the relay; only the app on the machine turns it on.
//!
//! The steps go through [`WinSystem`], so they run on every platform in the
//! tests.

use std::io::Write;

use nerve_policy::config::Sudo;
use serde_json::{Value, json};

use crate::paths::NodePaths;
use crate::service::Account;
use crate::winsvc::WinSystem;

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
/// for `account` ([`check`]); the account's name. The node then holds the
/// password in its memory only.
pub fn take(
    sys: &dyn WinSystem,
    account: Option<&Account>,
    password: &str,
) -> Result<String, String> {
    check(sys, account, password)?;
    Ok(account.expect("checked").name.clone())
}

/// Why `sudo on` asks for no password while no node runs.
pub const NEEDS_THE_NODE: &str = "sudo on needs the running node, which checks the password: start it on the app's Overview, then turn sudo on again";

/// `nerve-node sudo on`: asks for the password of the account the commands
/// run as and hands it to the running node over `call` (its control pipe),
/// which checks it ([`take`]), holds it and turns the switch on at once.
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
/// switch goes off in the config here (a node that does not run holds no
/// password).
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

/// `nerve-node sudo`: what the running node says (`call`); a node that
/// does not run holds no password, so the switch is off.
pub async fn status(
    paths: &NodePaths,
    call: impl AsyncFn(&str, Value) -> Result<Value, String>,
) -> Result<bool, String> {
    match call("sudo.status", json!({})).await {
        Ok(v) => Ok(v["sudo"] == "on"),
        Err(e) if crate::cli::no_node(paths, &e) => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::winsvc::tests::{Fake, account, installed};

    fn sudo_of(paths: &NodePaths) -> Sudo {
        nerve_policy::settings::SettingsStore::peek_with(
            &paths.config_file(),
            &crate::secrets::NodeSecrets::for_cli(paths),
        )
        .unwrap()
        .machine
        .sudo
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
        assert_eq!(take(&sys, Some(&bob), "bob's").unwrap(), "bob");
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
    /// switch in its config), holds it in memory, records what it was sent,
    /// and answers [`nerve_transport::ctl::NOT_RUNNING`] while it is `down`.
    /// A restart drops what it holds.
    struct Node<'a> {
        paths: &'a NodePaths,
        sys: &'a dyn WinSystem,
        down: std::cell::Cell<bool>,
        held: std::cell::RefCell<Option<String>>,
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
            let on = || self.held.borrow().is_some() && sudo_of(self.paths) == Sudo::On;
            match method {
                "status" => Ok(json!({})),
                "sudo.status" => Ok(json!({"sudo": if on() { "on" } else { "off" }})),
                "sudo.on" => {
                    let user = self.sys.owner()?.map(|(_, n)| n);
                    let account = user.and_then(|n| self.sys.account(&n).ok().flatten());
                    let password = params["password"].as_str().unwrap_or_default();
                    take(self.sys, account.as_ref(), password)?;
                    *self.held.borrow_mut() = Some(password.into());
                    set(true).await?;
                    Ok(json!({"sudo": "on"}))
                }
                "sudo.off" => {
                    *self.held.borrow_mut() = None;
                    set(false).await?;
                    Ok(json!({"sudo": "off"}))
                }
                m => Err(format!("unknown method {m}")),
            }
        }
    }

    /// A pipe of the node's name that another account made, while no node
    /// runs, is no node: `sudo off` works on the files and the status is
    /// off, as the other commands do (cli::no_node).
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
        crate::cli::edit(p, |c| {
            c.machine.sudo = Sudo::On;
            Ok(())
        })
        .await
        .unwrap();
        // No node holds a password, whatever the config says.
        assert!(!status(p, call).await.unwrap());
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
        let node = Node {
            paths: p,
            sys: &sys,
            down: false.into(),
            held: Default::default(),
            sent: Default::default(),
        };
        let call = async |m: &str, v: Value| node.call(m, v).await;
        // Alice, who installed the node, is no administrator.
        sys.types("alice's");
        let e = on(&sys, true, call, &mut Vec::new()).await.unwrap_err();
        assert!(e.contains("alice is not an administrator"), "{e}");
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
        // A wrong password leaves the switch off.
        sys.types("wrong");
        let e = on(&sys, true, call, &mut Vec::new()).await.unwrap_err();
        assert!(e.contains("password of bob is wrong"), "{e}");
        assert_eq!(sudo_of(p), Sudo::Off);
        assert!(!status(p, call).await.unwrap());
        // The right one: the node holds it and is on now.
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
        // Nothing in the config folder holds it: a restart forgets it.
        for f in std::fs::read_dir(&p.config_dir).unwrap() {
            let f = f.unwrap().path();
            if f.is_file() {
                let b = std::fs::read(&f).unwrap();
                assert!(!b.windows(5).any(|w| w == b"bob's"), "{}", f.display());
            }
        }
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
        assert_eq!(sudo_of(p), Sudo::Off);
        assert!(!status(p, call).await.unwrap());
        // With no node running, the status is off whatever the config
        // says, and off sets the config off.
        crate::cli::edit(p, |c| {
            c.machine.sudo = Sudo::On;
            Ok(())
        })
        .await
        .unwrap();
        node.down.set(true);
        assert!(!status(p, call).await.unwrap());
        off(p, &sys, call, &mut Vec::new()).await.unwrap();
        assert_eq!(sudo_of(p), Sudo::Off);
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
}
