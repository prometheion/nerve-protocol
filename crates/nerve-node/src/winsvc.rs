//! The node as a Windows service (docs/dev/windows.md): `install`, `update`
//! and `uninstall`, as the Linux ones in [`crate::service`] are. The service
//! `nerve-node` runs `nerve-node run` as a local account of its own, `nerve`,
//! which with SYSTEM and the administrators alone may open the node's config,
//! keys and state (a DACL of their own, inherited by nothing above). The
//! commands of a center run as the command account `nerve-run`
//! ([`crate::account::RUN_USER`]), which `install` makes with a random
//! password stored with DPAPI ([`RUN_SECRET_FILE`]); those that run as the
//! owner, the account that ran `install`, with the owner's password, asked
//! once and stored the same way ([`SECRET_FILE`]) ([`crate::win_user`]).
//!
//! What these commands do to the machine beyond the node's files (accounts,
//! the service control manager, DPAPI, a logon) goes through [`WinSystem`],
//! so the steps run on every platform in the tests; the real calls are
//! `crate::win_host`.

use std::io::Write;
use std::path::{Path, PathBuf};

use nerve_policy::config::SecretStorage;

use crate::account::{RUN_MARK, RUN_USER};
use crate::paths::NodePaths;
use crate::service::{
    Account, Layout, ServiceAction, ServiceState, Steps, USER, USER_MARK, asset_name, audit,
    fetch_release, put_parts, uninstall_parts, write_file,
};

/// The name the service is registered under.
pub const SERVICE_NAME: &str = "nerve-node";
/// Why a command for the service does nothing here, and where the node is
/// installed: the app is the only way to the node on Windows.
pub const NOT_INSTALLED: &str = "the node is not installed as a service here; Nerve's installer installs it: open the downloaded nerve-node-desktop file";
/// What puts back what the install made: the install again, which the app
/// runs when the owner's password is saved.
pub const INSTALL_AGAIN: &str = "the install makes it again: in the app, save your password under Settings › General › Account for commands, which installs the node again";
/// The file in the config folder that holds the owner's password, for the
/// commands that run as the owner, encrypted with DPAPI.
pub const SECRET_FILE: &str = "command-account.dpapi";
/// The file in the config folder that holds the password of the command
/// account [`crate::account::RUN_USER`], encrypted with DPAPI.
pub const RUN_SECRET_FILE: &str = "run-account.dpapi";
/// The service that keeps the command account's profile loaded. Windows
/// starts a command in an AppContainer only where the account's registry is
/// loaded, which a service that is no administrator cannot do; the service
/// manager loads it for a service of that account. It runs the node's
/// program, does nothing, and the node's service depends on it.
pub const PROFILE_SERVICE: &str = "nerve-run-profile";

/// The two local accounts `install` makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `nerve`, the service's: it may log on as a service, and start a
    /// process with another account's token; no other logon.
    Node,
    /// `nerve-run`, the commands': it may log on as a batch job (the
    /// commands) and as a service ([`PROFILE_SERVICE`]); no other logon.
    /// Not an administrator.
    Commands,
}

/// What `install`, `update` and `uninstall` do to a Windows machine besides
/// writing the node's files.
pub trait WinSystem {
    /// Whether this process runs as an administrator, elevated.
    fn is_admin(&self) -> bool;
    fn account(&self, name: &str) -> Result<Option<Account>, String>;
    /// Makes one of the node's local accounts with `password`, the comment
    /// of its `kind` ([`USER_MARK`], [`crate::account::RUN_MARK`]) and the
    /// rights [`Kind`] names.
    fn add_account(&self, name: &str, password: &str, kind: Kind) -> Result<(), String>;
    /// Gives one of the node's accounts a new password, and its rights again.
    fn reset_account(&self, name: &str, password: &str, kind: Kind) -> Result<(), String>;
    /// Makes the profile of `name` (a logon with `password` that loads it),
    /// where it has none; its folder.
    fn make_profile(&self, name: &str, password: &str) -> Result<PathBuf, String>;
    /// Registers [`PROFILE_SERVICE`] as `name` with `password`, or changes
    /// it, and starts it.
    fn put_profile_service(
        &self,
        layout: &Layout,
        name: &str,
        password: &str,
    ) -> Result<(), String>;
    /// Stops and removes [`PROFILE_SERVICE`]; `false` when it was not there.
    fn delete_profile_service(&self) -> Result<bool, String>;
    /// Logs `name` on with `password` as a batch job, as its commands start;
    /// then the first of what it must not open that it can: the node's
    /// folders `own` or what is below, and the registry of the owner `owner`
    /// (a SID) while it is loaded.
    fn run_reach(
        &self,
        name: &str,
        password: &str,
        own: &[PathBuf],
        owner: Option<&str>,
    ) -> Result<Option<String>, String>;
    /// Removes the account, its rights and its profile; what Windows
    /// keeps of the profile until it restarts, said.
    fn remove_account(&self, name: &str) -> Result<Option<String>, String>;
    /// Makes `dir` when it is missing and lets only `owner`, SYSTEM and the
    /// administrators open it (only the latter two for `None`); what is
    /// below inherits that. A link in place of the folder is refused.
    fn secure(&self, dir: &Path, owner: Option<&str>) -> Result<(), String>;
    /// The service: `None` when it is not registered, else whether it runs.
    fn service(&self) -> Result<Option<bool>, String>;
    /// The service's state for `status`; `None` when it is not
    /// registered.
    fn service_state(&self) -> Result<Option<ServiceState>, String>;
    /// Registers the service, or changes it: `layout.bin` with the folders,
    /// as `.\nerve` with `password`, started with the machine and again
    /// after a failure.
    fn put_service(&self, layout: &Layout, password: &str) -> Result<(), String>;
    fn start(&self) -> Result<(), String>;
    /// Stops the service and waits until it has; a stopped one is fine.
    fn stop(&self) -> Result<(), String>;
    fn delete_service(&self) -> Result<(), String>;
    /// Registers the source of the node's entries in the Windows Event Log,
    /// with `layout.bin` as the file that holds their text
    /// ([`crate::eventlog`]), or changes it.
    fn put_event_source(&self, layout: &Layout) -> Result<(), String>;
    /// Removes that source; `false` when it was not registered. The entries
    /// stay in the log.
    fn delete_event_source(&self) -> Result<bool, String>;
    /// Waits until the node the service started runs.
    fn wait_running(&self, layout: &Layout) -> Result<(), String>;
    /// Asks for a password, without echo on a console.
    fn read_password(&self, prompt: &str, out: &mut dyn Write) -> Result<String, String>;
    /// Logs `name` on with `password` (an error when that fails); then the
    /// first of `own`, or of what is below, that the logon can open.
    fn check_logon(
        &self,
        name: &str,
        password: &str,
        own: &[PathBuf],
    ) -> Result<Option<PathBuf>, String>;
    /// Logs `name` on with `password` as a batch job, as a sudo command
    /// starts (an error when that fails); whether that logon holds the
    /// Administrators group (crate::winsudo).
    fn sudo_logon(&self, name: &str, password: &str) -> Result<bool, String>;
    fn protect(&self, data: &[u8]) -> Result<Vec<u8>, String>;
    fn unprotect(&self, data: &[u8]) -> Result<Vec<u8>, String>;
    /// The groups of `account` whose members can read every file, the
    /// node's keys included.
    fn admin_groups(&self, account: &Account) -> Vec<String>;
    /// What `<program> --version` prints, run without the administrators'
    /// rights.
    fn version_of(&self, program: &Path) -> Result<String, String>;
    /// Removes the program file and its folder when that is empty; `false`
    /// when Windows holds the program (this command started from it, or the
    /// Event Log reads the text of the node's entries from it): it then
    /// moves aside to a `nerve-node.*.del` beside it and goes at the next
    /// restart.
    fn remove_program(&self, path: &Path) -> Result<bool, String>;
    /// Takes the folder grants of folder mode off, those in the record on
    /// `paths` and those of the pairings `node_ids`
    /// (crate::grants::remove_all).
    fn remove_grants(
        &self,
        paths: &crate::paths::NodePaths,
        node_ids: &[String],
    ) -> crate::grants::Synced;
    /// The account that installs, the owner of the node (crate::owner):
    /// its SID and its name. The desktop app's user when its broker names
    /// one, else the account this runs as.
    fn owner_sid(&self) -> Option<(String, String)>;
    /// The owner the service's registry key names: its SID and its name.
    fn owner(&self) -> Result<Option<(String, String)>, String>;
    /// Writes `sid` as the owner, and gives it the right to start, stop and
    /// ask the service ([`service_dacl`]).
    fn put_owner(&self, sid: &str) -> Result<(), String>;
}

/// The service's DACL in SDDL: what Windows gives a new service (SYSTEM,
/// the administrators, read for the interactive and service users), and to
/// the owner the right to start, stop and ask it, nothing more.
pub fn service_dacl(owner: Option<&str>) -> String {
    let mut s = String::from(
        "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)",
    );
    if let Some(o) = owner {
        s.push_str(&format!("(A;;CCLCSWRPWPLOCRRC;;;{o})"));
    }
    s
}

/// The owner (crate::owner): the account that installs. One that installs
/// over another's node takes its place, as `install --owner` does on Linux.
fn put_owner(sys: &dyn WinSystem, steps: &mut Steps) -> Result<(), String> {
    let Some((sid, name)) = sys.owner_sid() else {
        steps.did("no owner besides the administrators");
        return Ok(());
    };
    let before = sys.owner()?;
    sys.put_owner(&sid)?;
    match before {
        Some((old, was)) if old != sid => steps.did(format!(
            "{name} is the owner of the node now, in place of {was}: the app changes its settings, and starts and stops its service, without administrator rights"
        )),
        _ => steps.did(format!(
            "{name} is the owner of the node: the app changes its settings, and starts and stops its service, without administrator rights"
        )),
    }
    Ok(())
}

/// Takes the folder grants of the node at `paths` off, for uninstall.
/// `kept`: whether its record stays (no purge of its state folder), so that
/// another uninstall finds the grants left on a drive that is not here.
fn remove_grants(
    paths: &NodePaths,
    sys: &dyn WinSystem,
    steps: &mut Steps,
    whose: &str,
    kept: bool,
) {
    // The pairings name their containers' profiles, also those the record
    // does not, as when the state folder was deleted.
    let node_ids = crate::grants::node_ids(paths).unwrap_or_else(|e| {
        let _ = writeln!(
            steps.out,
            "warning: the profiles of the commands' AppContainers cannot be found: {e}"
        );
        Vec::new()
    });
    let synced = sys.remove_grants(paths, &node_ids);
    for e in &synced.errors {
        let _ = writeln!(steps.out, "warning: {e}");
    }
    if synced.removed > 0 {
        steps.did(format!(
            "took {} folder grants of {whose} off",
            synced.removed
        ));
    }
    if !synced.away.is_empty() {
        let at: Vec<String> = synced
            .away
            .iter()
            .map(|g| g.path.display().to_string())
            .collect();
        let then = if kept {
            "connect their drives, then install Nerve and uninstall it again to take them off"
        } else {
            "their record goes with the data, so once their drives are connected, take them off by hand (docs/dev/windows.md)"
        };
        steps.did(format!(
            "left {} folder grants of {whose} on, on drives that are not connected now ({}): {then}",
            at.len(),
            at.join(", ")
        ));
    }
    let p = &synced.profiles;
    if !p.removed.is_empty() {
        steps.did(format!(
            "removed the AppContainer profiles of {whose} ({})",
            p.removed.join(", ")
        ));
    }
    if !p.kept.is_empty() {
        let then = if kept {
            "once it stopped, install Nerve and uninstall it again to remove them"
        } else {
            "its config goes with the data, so once it stopped, remove them by hand (docs/dev/windows.md)"
        };
        steps.did(format!(
            "left the AppContainer profiles of {whose} ({}), since {}: {then}",
            p.kept.join(", "),
            p.why.as_deref().unwrap_or("its node may run")
        ));
    }
}

/// The plain text [`SECRET_FILE`] holds: the account's name and password.
pub fn secret(name: &str, password: &str) -> Vec<u8> {
    let mut b = name.as_bytes().to_vec();
    b.push(0);
    b.extend_from_slice(password.as_bytes());
    b
}

/// The name and password in what [`secret`] made.
pub fn parse_secret(b: &[u8]) -> Option<(String, String)> {
    let at = b.iter().position(|&c| c == 0)?;
    let name = std::str::from_utf8(&b[..at]).ok()?;
    let password = std::str::from_utf8(&b[at + 1..]).ok()?;
    (!name.is_empty()).then(|| (name.to_string(), password.to_string()))
}

/// A new password for `nerve`, which nobody types: the service control
/// manager keeps it. It has the four kinds of characters a complexity
/// rule asks for.
fn new_password() -> String {
    format!("Nn1-{}", nerve_transport::keys::random_token(28))
}

/// The program's name without `.exe`: `nerve-node`, or the desktop app's.
/// The start of the name a program gets when it moves aside, held by
/// Windows, until it goes at the next start ([`WinSystem::remove_program`]).
pub(crate) const ASIDE: &str = "nerve-node.";

fn stem(bin: &Path) -> String {
    bin.file_stem()
        .map_or_else(|| "nerve-node".into(), |s| s.to_string_lossy().into_owned())
}

/// Where `update` puts the new program before it replaces the old one, and
/// where the old one waits until the new one runs.
fn staged(bin: &Path) -> PathBuf {
    bin.with_file_name(format!("{}.new.exe", stem(bin)))
}

fn previous(bin: &Path) -> PathBuf {
    bin.with_file_name(format!("{}.old.exe", stem(bin)))
}

/// Whether `what` can run here: as an elevated administrator.
fn supported(sys: &dyn WinSystem, what: &str) -> Result<(), String> {
    if !sys.is_admin() {
        return Err(needs_admin(what));
    }
    Ok(())
}

/// Why `what` (install, update, uninstall) does not run without an
/// administrator, and where the app does it, asking Windows for the rights.
pub(crate) fn needs_admin(what: &str) -> String {
    let place = match what {
        "install" => "the installer, which opens with the downloaded nerve-node-desktop file,",
        "update" => "Settings › App › Update",
        _ => "Settings › App › Uninstall",
    };
    format!("{what} needs an administrator: in the app, {place} asks Windows for the rights")
}

/// `install`: the node's account, the folders, the command account, the
/// owner's password, the program, the services, in that order. `invoker` is
/// the account that ran install, the owner. Running it again puts back what
/// is missing and restarts the service.
pub fn install(
    layout: &Layout,
    sys: &dyn WinSystem,
    exe: &Path,
    invoker: &str,
    out: &mut dyn Write,
) -> Result<(), String> {
    supported(sys, "install")?;
    let mut steps = Steps {
        done: Vec::new(),
        out,
    };
    let r = install_steps(layout, sys, exe, invoker, &mut steps);
    audit(&layout.paths, "install", &steps.done, &r, steps.out);
    r?;
    let _ = writeln!(
        steps.out,
        "Next: open Nerve; its first-run steps name the node and pair it with its first center."
    );
    Ok(())
}

fn install_steps(
    layout: &Layout,
    sys: &dyn WinSystem,
    exe: &Path,
    invoker: &str,
    steps: &mut Steps,
) -> Result<(), String> {
    // The service would look for keys in the keyring in the Credential
    // Manager of nerve, and they are in that of whoever moved them there.
    if crate::secrets::stated_storage(&layout.paths) == SecretStorage::Keyring {
        return Err(crate::secrets::keyring_refused(
            &layout.paths,
            crate::secrets::NoKeyring::WindowsService,
            "install changed nothing",
            "install again with the installer, and pair the centers again",
        ));
    }
    // A running service holds the program and the folders' files.
    if sys.service()? == Some(true) {
        sys.stop()?;
        steps.did(format!(
            "stopped the service {SERVICE_NAME} to install over it"
        ));
    }
    let password = new_password();
    match sys.account(USER)? {
        Some(a) if a.comment == USER_MARK => {
            sys.reset_account(USER, &password, Kind::Node)?;
            steps.did(format!(
                "the user {USER} is there already; it has a new password"
            ));
        }
        Some(_) => {
            return Err(format!(
                "a user {USER} exists already, and Nerve's install did not make it; the node needs a user of its own"
            ));
        }
        None => {
            sys.add_account(USER, &password, Kind::Node)?;
            sys.account(USER)?
                .ok_or_else(|| format!("Windows made no user {USER}"))?;
            steps.did(format!(
                "made the user {USER}, which may log on as a service only"
            ));
        }
    }
    for dir in [
        &layout.home,
        &layout.paths.config_dir,
        &layout.paths.state_dir,
    ] {
        sys.secure(dir, Some(USER))?;
    }
    steps.did(format!(
        "{} and {} are open to {USER} and the administrators only",
        layout.paths.config_dir.display(),
        layout.paths.state_dir.display()
    ));
    let run_password = run_account(layout, sys, steps)?;
    owner_account(layout, sys, invoker, steps);
    let real = |p: &Path| std::fs::canonicalize(p).ok();
    if real(exe).is_some() && real(exe) == real(&layout.bin) {
        steps.did(format!(
            "the program is at {} already",
            layout.bin.display()
        ));
    } else {
        let program = std::fs::read(exe).map_err(|e| format!("{}: {e}", exe.display()))?;
        // Once someone read the node's entries, the Event Log holds the
        // installed program as their message file: it cannot be written
        // over then, but it can be moved aside.
        if layout.bin.exists() {
            sys.remove_program(&layout.bin)?;
        }
        write_file(&layout.bin, &program, 0o755)?;
        steps.did(format!("put the program at {}", layout.bin.display()));
    }
    put_parts(layout, steps)?;
    // What an update or an uninstall left behind when it ran from the
    // program it replaced or removed, or moved aside because the Event Log
    // held it: a name of [`ASIDE`].
    let _ = std::fs::remove_file(previous(&layout.bin));
    let _ = std::fs::remove_file(staged(&layout.bin));
    if let Some(dir) = layout.bin.parent()
        && let Ok(entries) = std::fs::read_dir(dir)
    {
        for e in entries.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(ASIDE) && name.ends_with(".del") {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    sys.put_profile_service(layout, RUN_USER, &run_password)?;
    steps.did(format!(
        "registered and started the service {PROFILE_SERVICE}, which runs as {RUN_USER} and keeps its profile loaded, where the commands' AppContainers keep theirs"
    ));
    sys.put_service(layout, &password)?;
    steps.did(format!(
        "registered the service {SERVICE_NAME}, which runs as {USER} and starts with the machine"
    ));
    sys.put_event_source(layout)?;
    steps.did(format!(
        "registered the source {} in the Windows Event Log (Application): the service's start, stop and failures go there as well as to {}",
        crate::eventlog::SOURCE,
        layout.paths.log_file().display()
    ));
    put_owner(sys, steps)?;
    sys.start()?;
    sys.wait_running(layout)?;
    steps.did(format!("the service {SERVICE_NAME} runs"));
    Ok(())
}

/// The command account `nerve-run` at install: made, or given a new
/// password when the install made it before, with that password stored with
/// DPAPI ([`RUN_SECRET_FILE`]) and its profile made. One of that name that
/// the install did not make, or that can open the node's folders or the
/// owner's registry, is refused. Its password, for [`PROFILE_SERVICE`].
fn run_account(layout: &Layout, sys: &dyn WinSystem, steps: &mut Steps) -> Result<String, String> {
    let password = new_password();
    match sys.account(RUN_USER)? {
        Some(a) if a.comment == RUN_MARK => {
            sys.reset_account(RUN_USER, &password, Kind::Commands)?;
            steps.did(format!(
                "the user {RUN_USER} is there already; it has a new password"
            ));
        }
        Some(_) => {
            return Err(format!(
                "a user {RUN_USER} exists already, and Nerve's install did not make it; the commands need a user of their own"
            ));
        }
        None => {
            sys.add_account(RUN_USER, &password, Kind::Commands)?;
            sys.account(RUN_USER)?
                .ok_or_else(|| format!("Windows made no user {RUN_USER}"))?;
            steps.did(format!(
                "made the user {RUN_USER}, which commands from centers run as: no administrator, and it may log on only as a batch job and as a service"
            ));
        }
    }
    let file = layout.paths.config_dir.join(RUN_SECRET_FILE);
    write_file(&file, &sys.protect(&secret(RUN_USER, &password))?, 0o600)?;
    let profile = sys.make_profile(RUN_USER, &password)?;
    steps.did(format!(
        "{RUN_USER}'s password is stored with DPAPI, and its profile is at {}",
        profile.display()
    ));
    let owner = sys.owner_sid().map(|(sid, _)| sid);
    if let Some(at) = sys.run_reach(RUN_USER, &password, &layout.paths.own(), owner.as_deref())? {
        return Err(format!(
            "{RUN_USER} could open {at}, which no command may: check the permissions there, then install again"
        ));
    }
    steps.did(format!(
        "{RUN_USER} cannot open the node's folders nor your registry"
    ));
    Ok(password)
}

/// The owner's password at install, for the commands that run as the owner
/// (user mode, allowlist mode as the owner, sudo): the account that ran
/// `install`, `invoker`. A stored password that still logs it on is kept;
/// else it is asked for. What fails here is said, and those commands then
/// do not run until install runs again.
fn owner_account(layout: &Layout, sys: &dyn WinSystem, invoker: &str, steps: &mut Steps) {
    let p = &layout.paths;
    let r = (|| {
        let a = usable_account(sys, invoker)?;
        let own = p.own();
        let file = p.config_dir.join(SECRET_FILE);
        let stored = std::fs::read(&file)
            .ok()
            .and_then(|b| sys.unprotect(&b).ok())
            .and_then(|b| parse_secret(&b))
            .filter(|(n, _)| n.eq_ignore_ascii_case(&a.name))
            .map(|(_, pw)| pw);
        let (reach, asked) = match stored.map(|pw| sys.check_logon(&a.name, &pw, &own)) {
            Some(Ok(reach)) => (reach, None),
            _ => {
                let pw = sys.read_password(
                    &format!("Password of {}, for the commands that run as you: ", a.name),
                    steps.out,
                )?;
                let reach = sys.check_logon(&a.name, &pw, &own)?;
                (reach, Some(pw))
            }
        };
        if let Some(at) = reach {
            return Err(format!(
                "{} could open {}, where the node keeps its keys",
                a.name,
                at.display()
            ));
        }
        if let Some(pw) = &asked {
            write_file(&file, &sys.protect(&secret(&a.name, pw))?, 0o600)?;
        }
        let groups = sys.admin_groups(&a);
        if !groups.is_empty() {
            let _ = writeln!(steps.out, "{}", admin_warning(&a.name, &groups));
        }
        let password = if asked.is_some() {
            "your password is stored with DPAPI"
        } else {
            "your stored password still works"
        };
        Ok::<_, String>(format!(
            "user mode, allowlist mode as you and sudo run commands as {}, who ran install; {password}",
            a.name
        ))
    })();
    match r {
        Ok(step) => steps.did(step),
        Err(e) => steps.did(format!(
            "{}: {e}; {}",
            crate::account::NO_COMMANDS_AS_YOU,
            crate::account::NO_ACCOUNT_INSTALL
        )),
    }
}

/// `name` as the owner whose commands run as it, or why not: it must be a
/// local account of this machine and none of the node's own.
fn usable_account(sys: &dyn WinSystem, name: &str) -> Result<Account, String> {
    if !nerve_policy::config::valid_account_name(name) {
        return Err(format!("{name:?} is not an account name"));
    }
    let a = sys
        .account(name)?
        .ok_or_else(|| format!("there is no local account {name}"))?;
    if a.name.eq_ignore_ascii_case(USER) || a.comment == USER_MARK {
        return Err(format!(
            "{name} is the node's own user, which owns its keys; install as yourself"
        ));
    }
    if a.name.eq_ignore_ascii_case(RUN_USER) || a.comment == RUN_MARK {
        return Err(format!(
            "{name} is the commands' own user; install as yourself"
        ));
    }
    Ok(a)
}

/// The warning for an owner in a group that can read every file: what runs
/// as the owner can take that group's rights.
pub fn admin_warning(name: &str, groups: &[String]) -> String {
    format!(
        "Warning: {name} is in the group {}. Commands that run as you (user mode, allowlist mode as you) run without the group's rights (UAC), but UAC is no security boundary: such a command from a center can get them back and read the node's keys. Keep centers in folder mode or allowlist mode, or you are responsible for what commands do.",
        groups.join(", ")
    )
}

/// `uninstall`: stops and removes the service, then the folders (deleted
/// with `purge`, the stored password with them, else kept and open to the
/// administrators only, without the sudo password), the user and the
/// program. The folder grants of folder mode come off: the service's, and
/// those of the node this user runs by hand at `by_hand`, the only node
/// whose commands run in a container (crate::grants).
pub fn uninstall(
    layout: &Layout,
    by_hand: &NodePaths,
    sys: &dyn WinSystem,
    purge: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    supported(sys, "uninstall")?;
    let mut steps = Steps {
        done: Vec::new(),
        out,
    };
    let r = uninstall_steps(layout, by_hand, sys, purge, &mut steps);
    // With --purge the log went with the state folder.
    audit(&layout.paths, "uninstall", &steps.done, &r, steps.out);
    if r.is_ok() && steps.done.is_empty() {
        let _ = writeln!(
            steps.out,
            "nothing to uninstall: no service, user {USER} or program of the node is here"
        );
    }
    r
}

fn uninstall_steps(
    layout: &Layout,
    by_hand: &NodePaths,
    sys: &dyn WinSystem,
    purge: bool,
    steps: &mut Steps,
) -> Result<(), String> {
    if sys.service()?.is_some() {
        sys.stop()?;
        sys.delete_service()?;
        steps.did(format!("stopped and removed the service {SERVICE_NAME}"));
    }
    if sys.delete_profile_service()? {
        steps.did(format!("stopped and removed the service {PROFILE_SERVICE}"));
    }
    // Folder mode put grants for the commands' AppContainers on the
    // owner's folders (crate::grants); none stays behind the node. Their
    // record is in the state folder, so this comes before a purge. The
    // node run by hand keeps its folders; if it runs again, it puts its
    // grants on again. Its config alone names the profiles of its
    // containers when its state folder is gone.
    remove_grants(&layout.paths, sys, steps, "the commands", !purge);
    if *by_hand != layout.paths
        && (crate::grants::record_file(by_hand).exists() || by_hand.config_file().exists())
    {
        let whose = format!("the node run by hand ({})", by_hand.state_dir.display());
        remove_grants(by_hand, sys, steps, &whose, true);
    }
    if sys.delete_event_source()? {
        steps.did(format!(
            "removed the source {} from the Windows Event Log; its entries stay",
            crate::eventlog::SOURCE
        ));
    }
    let folders = [
        &layout.paths.config_dir,
        &layout.home,
        &layout.paths.state_dir,
    ];
    // The kept folders keep no sudo password: an install over them starts
    // with sudo off.
    let sudo = layout.paths.config_dir.join(crate::winsudo::SUDO_FILE);
    if !purge && sudo.exists() {
        crate::winsudo::forget(&layout.paths)?;
        steps.did("removed the stored sudo password: sudo is off");
    }
    if purge {
        for dir in folders {
            if dir.exists() {
                std::fs::remove_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
                steps.did(format!("deleted {}", dir.display()));
            }
        }
    } else if folders.iter().any(|d| d.exists()) {
        for dir in folders.iter().filter(|d| d.exists()) {
            sys.secure(dir, None)?;
        }
        steps.did(format!(
            "kept {} with the stored password, and {} (only administrators can open them now; an uninstall that deletes the data deletes them)",
            layout.paths.config_dir.display(),
            layout.paths.state_dir.display()
        ));
    }
    for (name, mark, with) in [
        (USER, USER_MARK, "its profile"),
        (
            RUN_USER,
            RUN_MARK,
            "its profile, with those of the commands' AppContainers",
        ),
    ] {
        match sys.account(name)? {
            Some(a) if a.comment == mark => match sys.remove_account(name)? {
                None => steps.did(format!("removed the user {name} and {with}")),
                Some(left) => {
                    steps.did(format!("removed the user {name}"));
                    steps.did(left);
                }
            },
            Some(_) => {
                let _ = writeln!(
                    steps.out,
                    "left the user {name} as it is: Nerve's install did not make it"
                );
            }
            None => {}
        }
    }
    uninstall_parts(layout, steps)?;
    for left in [staged(&layout.bin), previous(&layout.bin)] {
        if left.exists() {
            sys.remove_program(&left)?;
        }
    }
    if layout.bin.exists() {
        if sys.remove_program(&layout.bin)? {
            steps.did(format!("removed the program {}", layout.bin.display()));
        } else {
            steps.did(format!(
                "removed the program {}; Windows holds it (this command runs from it, or the Event Log reads it), so Windows deletes the file at its next start",
                layout.bin.display()
            ));
        }
    }
    Ok(())
}

/// `update`: the new program (the latest release, checked against its
/// `SHA256SUMS`, or a file the owner gives) replaces the installed one, and
/// the service restarts. The config, the keys and the audit log are not
/// touched. A program that does not run here, or is older than the
/// installed one, is refused; one that does not start is replaced by the
/// old one again.
pub async fn update(
    layout: &Layout,
    sys: &dyn WinSystem,
    from: Option<&Path>,
    out: &mut dyn Write,
) -> Result<(), String> {
    supported(sys, "update")?;
    if sys.service()?.is_none() || !layout.bin.is_file() {
        return Err(NOT_INSTALLED.into());
    }
    let mut steps = Steps {
        done: Vec::new(),
        out,
    };
    let r = update_steps(layout, sys, from, &mut steps).await;
    audit(&layout.paths, "update", &steps.done, &r, steps.out);
    r
}

async fn update_steps(
    layout: &Layout,
    sys: &dyn WinSystem,
    from: Option<&Path>,
    steps: &mut Steps<'_>,
) -> Result<(), String> {
    let program = layout.edition.program;
    sys.account(USER)?
        .filter(|a| a.comment == USER_MARK)
        .ok_or_else(|| format!("the user {USER} is missing; {INSTALL_AGAIN}"))?;
    let new = match from {
        Some(f) => {
            let b = std::fs::read(f).map_err(|e| format!("{}: {e}", f.display()))?;
            steps.did(format!("read the new program from {}", f.display()));
            b
        }
        None => {
            let asset = asset_name(layout.edition.program)?;
            let b = fetch_release(&layout.release, &asset).await?;
            steps.did(format!(
                "downloaded {asset} from {} and checked it against its SHA256SUMS",
                layout.release
            ));
            b
        }
    };
    let bin = &layout.bin;
    let old = std::fs::read(bin).map_err(|e| format!("{}: {e}", bin.display()))?;
    if new == old {
        steps.did("the installed program is that one already; nothing to update");
        return Ok(());
    }
    let new_path = staged(bin);
    write_file(&new_path, &new, 0o755)?;
    let checked = (|| {
        let said = sys.version_of(&new_path)?;
        let new_v = crate::service::program_version(layout, &said)
            .ok_or_else(|| format!("the new program is not {program}: it says {said:?}"))?;
        let old_v = sys
            .version_of(bin)
            .ok()
            .and_then(|s| crate::service::program_version(layout, &s));
        if let Some(o) = old_v
            && new_v < o
        {
            return Err(format!(
                "the new program is {program} {new_v}, older than the installed {o}; nothing changed"
            ));
        }
        Ok((old_v, new_v))
    })();
    let (old_v, new_v) = match checked {
        Ok(v) => v,
        Err(e) => {
            let _ = std::fs::remove_file(&new_path);
            return Err(e);
        }
    };
    // A running program cannot be overwritten, but it can be renamed: the
    // old one moves aside, also when this command runs from it.
    if let Err(e) = sys.stop() {
        let _ = std::fs::remove_file(&new_path);
        return Err(e);
    }
    let old_path = previous(bin);
    let _ = std::fs::remove_file(&old_path);
    let swap = |from: &Path, to: &Path| {
        std::fs::rename(from, to)
            .map_err(|e| format!("{} to {}: {e}", from.display(), to.display()))
    };
    // When the new one cannot be put in place, the old one runs on.
    let moved = swap(bin, &old_path).and_then(|()| {
        swap(&new_path, bin).inspect_err(|_| {
            let _ = swap(&old_path, bin);
        })
    });
    if let Err(e) = moved {
        let _ = std::fs::remove_file(&new_path);
        let _ = sys.start();
        return Err(e);
    }
    let old_v = old_v.map_or_else(|| "?".to_string(), |v| v.to_string());
    steps.did(format!("replaced {program} {old_v} with {new_v}"));
    let started = sys.start().and_then(|()| sys.wait_running(layout));
    if let Err(e) = started {
        let _ = sys.stop();
        let back = swap(bin, &new_path)
            .and_then(|()| swap(&old_path, bin))
            .and_then(|()| sys.start())
            .and_then(|()| sys.wait_running(layout));
        let _ = std::fs::remove_file(&new_path);
        steps.did(format!("put {program} {old_v} back"));
        return Err(match back {
            Ok(()) => format!("the new program did not start ({e}); the old one runs again"),
            Err(e2) => format!(
                "the new program did not start ({e}), and the old one does not either ({e2})"
            ),
        });
    }
    steps.did(format!("restarted the service {SERVICE_NAME}"));
    // This command may run from the old program; then it goes at the next
    // restart, or with the next update or install.
    let _ = sys.remove_program(&old_path);
    put_parts(layout, steps)
}

/// `service start`, `stop` and `restart` on Windows: the installed
/// service, through the service control manager, waiting until a node that
/// starts runs.
pub fn control(
    layout: &Layout,
    sys: &dyn WinSystem,
    action: ServiceAction,
    out: &mut dyn Write,
) -> Result<(), String> {
    // The service's DACL decides: the administrators and the owners may
    // (crate::owner).
    if sys.service()?.is_none() {
        return Err(NOT_INSTALLED.into());
    }
    if action != ServiceAction::Start {
        sys.stop()?;
    }
    let said = if action == ServiceAction::Stop {
        format!(
            "stopped the service {SERVICE_NAME}: the node ended its links; it starts again with the machine"
        )
    } else {
        sys.start()?;
        sys.wait_running(layout)?;
        let did = if action == ServiceAction::Start {
            "started"
        } else {
            "restarted"
        };
        format!("{did} the service {SERVICE_NAME}, and the node runs")
    };
    let _ = writeln!(out, "{said}");
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::paths::NodePaths;
    use nerve_policy::audit::AuditLog;
    use nerve_policy::settings::SettingsStore;
    use std::cell::{Cell, RefCell};

    /// A Windows machine in a temporary folder: accounts, the service, the
    /// logons and DPAPI are recorded or played (crate::winsudo's tests use
    /// it too).
    pub(crate) struct Fake {
        pub(crate) admin: bool,
        pub(crate) accounts: RefCell<Vec<Account>>,
        /// The passwords the accounts log on with.
        pub(crate) passwords: RefCell<Vec<(String, String)>>,
        /// What the owner types, one password per question.
        typed: RefCell<Vec<String>>,
        /// The accounts that can open the node's folders.
        reaching: RefCell<Vec<String>>,
        pub(crate) calls: RefCell<Vec<String>>,
        /// `None`: not registered; else whether it runs.
        service: Cell<Option<bool>>,
        /// Whether a node started by the service runs.
        starts: Cell<bool>,
        /// What a program says that the service cannot keep running.
        broken: RefCell<Option<String>>,
        /// The program the service was registered with.
        program: RefCell<Option<PathBuf>>,
        /// What the program said each time the service started it.
        started: RefCell<Vec<String>>,
        /// The folders and whom they were opened to.
        secured: RefCell<Vec<(PathBuf, Option<String>)>>,
        /// Granted folders on drives that are not connected.
        away: RefCell<Vec<PathBuf>>,
        /// The message file of the Event Log source, while it is registered.
        event_source: RefCell<Option<PathBuf>>,
        /// The programs removed, in order.
        removed: RefCell<Vec<PathBuf>>,
        /// The programs Windows holds, as the Event Log holds the one it
        /// read: they move aside.
        held: RefCell<Vec<PathBuf>>,
        /// The state folders of nodes that run: their containers' profiles
        /// stay.
        running: RefCell<Vec<PathBuf>>,
        /// The account that installs, by SID and name.
        pub(crate) installer: RefCell<Option<(String, String)>>,
        /// The owner's SID the service's key names.
        pub(crate) owner_of: RefCell<Option<String>>,
        /// Whether the profile service is registered, and runs.
        pub(crate) profile_service: Cell<Option<bool>>,
        /// Whether the command account can read the owner's registry.
        pub(crate) hive_open: Cell<bool>,
    }

    impl Fake {
        pub(crate) fn new() -> Fake {
            Fake {
                admin: true,
                accounts: RefCell::new(vec![
                    account("alice", 1001, ""),
                    account("bob", 1002, ""),
                    account("dave", 1004, ""),
                ]),
                passwords: RefCell::new(vec![("alice".into(), "alice's".into())]),
                typed: RefCell::new(Vec::new()),
                reaching: RefCell::new(Vec::new()),
                calls: RefCell::new(Vec::new()),
                service: Cell::new(None),
                starts: Cell::new(true),
                broken: RefCell::new(None),
                program: RefCell::new(None),
                started: RefCell::new(Vec::new()),
                secured: RefCell::new(Vec::new()),
                away: RefCell::new(Vec::new()),
                event_source: RefCell::new(None),
                removed: RefCell::new(Vec::new()),
                held: RefCell::new(Vec::new()),
                running: RefCell::new(Vec::new()),
                installer: RefCell::new(Some(("S-1-5-21-1-2-3-1001".into(), "alice".into()))),
                owner_of: RefCell::new(None),
                profile_service: Cell::new(None),
                hive_open: Cell::new(false),
            }
        }

        fn call(&self, c: impl Into<String>) {
            self.calls.borrow_mut().push(c.into());
        }

        pub(crate) fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }

        pub(crate) fn types(&self, password: &str) {
            self.typed.borrow_mut().push(password.into());
        }

        /// `name` logs on with `password` from now on.
        fn knows(&self, name: &str, password: &str) {
            let mut p = self.passwords.borrow_mut();
            p.retain(|(n, _)| n != name);
            p.push((name.into(), password.into()));
        }

        fn logs_on(&self, name: &str, password: &str) -> Result<(), String> {
            if self
                .passwords
                .borrow()
                .iter()
                .any(|(n, p)| n == name && p == password)
            {
                Ok(())
            } else {
                Err(format!("the password of {name} is wrong"))
            }
        }
    }

    pub(crate) fn account(name: &str, uid: u32, comment: &str) -> Account {
        Account {
            name: name.into(),
            uid,
            gid: uid,
            comment: comment.into(),
            home: format!("C:\\Users\\{name}").into(),
            groups: Vec::new(),
        }
    }

    impl WinSystem for Fake {
        fn is_admin(&self) -> bool {
            self.admin
        }
        fn account(&self, name: &str) -> Result<Option<Account>, String> {
            Ok(self
                .accounts
                .borrow()
                .iter()
                .find(|a| a.name.eq_ignore_ascii_case(name))
                .cloned())
        }
        fn add_account(&self, name: &str, password: &str, kind: Kind) -> Result<(), String> {
            assert!(password.len() >= 16);
            self.call(format!("add {name}"));
            let (uid, mark) = match kind {
                Kind::Node => (1010, USER_MARK),
                Kind::Commands => (1011, RUN_MARK),
            };
            self.accounts.borrow_mut().push(account(name, uid, mark));
            self.knows(name, password);
            Ok(())
        }
        fn reset_account(&self, name: &str, password: &str, _: Kind) -> Result<(), String> {
            self.call(format!("reset {name}"));
            self.knows(name, password);
            Ok(())
        }
        fn make_profile(&self, name: &str, password: &str) -> Result<PathBuf, String> {
            self.logs_on(name, password)?;
            self.call(format!("profile {name}"));
            Ok(format!("C:\\Users\\{name}").into())
        }
        fn put_profile_service(
            &self,
            layout: &Layout,
            name: &str,
            password: &str,
        ) -> Result<(), String> {
            self.logs_on(name, password)?;
            self.call(format!("profile service {}", layout.bin.display()));
            self.profile_service.set(Some(true));
            Ok(())
        }
        fn delete_profile_service(&self) -> Result<bool, String> {
            self.call("no profile service");
            Ok(self.profile_service.take().is_some())
        }
        fn run_reach(
            &self,
            name: &str,
            password: &str,
            own: &[PathBuf],
            owner: Option<&str>,
        ) -> Result<Option<String>, String> {
            self.logs_on(name, password)?;
            self.call(format!("reach {name}"));
            if self.reaching.borrow().contains(&name.to_string()) {
                return Ok(Some(own[0].display().to_string()));
            }
            Ok(owner
                .filter(|_| self.hive_open.get())
                .map(|o| format!("HKEY_USERS\\{o}")))
        }
        fn remove_account(&self, name: &str) -> Result<Option<String>, String> {
            self.call(format!("remove {name}"));
            self.accounts.borrow_mut().retain(|a| a.name != name);
            Ok(None)
        }
        fn secure(&self, dir: &Path, owner: Option<&str>) -> Result<(), String> {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
            self.secured
                .borrow_mut()
                .push((dir.to_path_buf(), owner.map(str::to_string)));
            Ok(())
        }
        fn service(&self) -> Result<Option<bool>, String> {
            Ok(self.service.get())
        }
        fn service_state(&self) -> Result<Option<ServiceState>, String> {
            Ok(self.service.get().map(|runs| ServiceState {
                state: if runs { "running" } else { "stopped" }.into(),
                enabled: Some(true),
            }))
        }
        fn put_service(&self, layout: &Layout, _: &str) -> Result<(), String> {
            self.call(format!("put {}", layout.bin.display()));
            *self.program.borrow_mut() = Some(layout.bin.clone());
            if self.service.get().is_none() {
                self.service.set(Some(false));
            }
            Ok(())
        }
        /// Starts whatever is in the program's place right now, as Windows
        /// does; a later rename does not change what runs.
        fn start(&self) -> Result<(), String> {
            self.call("start");
            let program = self.program.borrow().clone().ok_or("not registered")?;
            let runs = self.version_of(&program)?;
            self.started.borrow_mut().push(runs);
            self.service.set(Some(true));
            Ok(())
        }
        fn stop(&self) -> Result<(), String> {
            self.call("stop");
            if self.service.get().is_some() {
                self.service.set(Some(false));
            }
            Ok(())
        }
        fn delete_service(&self) -> Result<(), String> {
            self.call("delete");
            self.service.set(None);
            // The service's key and DACL go with it.
            self.owner_of.borrow_mut().take();
            Ok(())
        }
        fn put_event_source(&self, layout: &Layout) -> Result<(), String> {
            self.call("event source");
            *self.event_source.borrow_mut() = Some(layout.bin.clone());
            Ok(())
        }
        fn delete_event_source(&self) -> Result<bool, String> {
            self.call("no event source");
            Ok(self.event_source.borrow_mut().take().is_some())
        }
        /// Judges the program the last start started, not what is in its
        /// place now.
        fn wait_running(&self, _: &Layout) -> Result<(), String> {
            let runs = self.started.borrow().last().cloned();
            if self.starts.get() && runs.is_some() && *self.broken.borrow() != runs {
                Ok(())
            } else {
                self.service.set(Some(false));
                Err("the service stopped at its start".into())
            }
        }
        fn read_password(&self, prompt: &str, out: &mut dyn Write) -> Result<String, String> {
            let _ = write!(out, "{prompt}");
            let mut typed = self.typed.borrow_mut();
            if typed.is_empty() {
                return Err("no password given".into());
            }
            Ok(typed.remove(0))
        }
        fn check_logon(
            &self,
            name: &str,
            password: &str,
            own: &[PathBuf],
        ) -> Result<Option<PathBuf>, String> {
            self.call(format!("logon {name}"));
            if !self
                .passwords
                .borrow()
                .iter()
                .any(|(n, p)| n == name && p == password)
            {
                return Err(format!("the password of {name} is wrong"));
            }
            Ok(self
                .reaching
                .borrow()
                .contains(&name.to_string())
                .then(|| own[0].clone()))
        }
        /// Bob is the administrator ([`Fake::admin_groups`]).
        fn sudo_logon(&self, name: &str, password: &str) -> Result<bool, String> {
            self.call(format!("batch logon {name}"));
            if !self
                .passwords
                .borrow()
                .iter()
                .any(|(n, p)| n == name && p == password)
            {
                return Err(format!("the password of {name} is wrong"));
            }
            Ok(name == "bob")
        }
        /// Not encryption: what matters is that the file is not the text.
        fn protect(&self, data: &[u8]) -> Result<Vec<u8>, String> {
            Ok(data.iter().map(|b| b ^ 0x5a).collect())
        }
        fn unprotect(&self, data: &[u8]) -> Result<Vec<u8>, String> {
            self.protect(data)
        }
        fn admin_groups(&self, account: &Account) -> Vec<String> {
            match account.name.as_str() {
                "bob" => vec!["Administrators".into()],
                "dave" => vec!["Backup Operators".into()],
                _ => Vec::new(),
            }
        }
        /// A program here is a text file whose first line is what it says.
        fn version_of(&self, program: &Path) -> Result<String, String> {
            let text = std::fs::read_to_string(program).map_err(|e| e.to_string())?;
            Ok(text.lines().next().unwrap_or_default().to_string())
        }
        fn remove_program(&self, path: &Path) -> Result<bool, String> {
            self.removed.borrow_mut().push(path.to_path_buf());
            if self.held.borrow().iter().any(|p| p == path) {
                let aside = path.with_file_name(format!("{ASIDE}held.del"));
                std::fs::rename(path, aside).map_err(|e| e.to_string())?;
                return Ok(false);
            }
            std::fs::remove_file(path).map_err(|e| e.to_string())?;
            Ok(true)
        }
        fn owner_sid(&self) -> Option<(String, String)> {
            self.installer.borrow().clone()
        }

        /// The SIDs here end in the account's number.
        fn owner(&self) -> Result<Option<(String, String)>, String> {
            // It goes with the service.
            if self.service.get().is_none() {
                return Ok(None);
            }
            Ok(self.owner_of.borrow().clone().map(|sid| {
                let name = self
                    .accounts
                    .borrow()
                    .iter()
                    .find(|a| sid.ends_with(&format!("-{}", a.uid)))
                    .map_or_else(|| sid.clone(), |a| a.name.clone());
                (sid, name)
            }))
        }

        fn put_owner(&self, sid: &str) -> Result<(), String> {
            self.call(format!("owner {sid}"));
            *self.owner_of.borrow_mut() = Some(sid.into());
            Ok(())
        }

        fn remove_grants(&self, paths: &NodePaths, node_ids: &[String]) -> crate::grants::Synced {
            // The record is in the state folder, which a purge deletes.
            let recorded = crate::grants::record_file(paths).exists();
            self.call(format!(
                "remove grants {} of {}",
                node_ids.join(","),
                paths.state_dir.display()
            ));
            let away = self
                .away
                .borrow()
                .iter()
                .filter(|_| recorded)
                .map(|p| crate::grants::Grant {
                    container: "nerve.away".into(),
                    path: p.clone(),
                    access: nerve_policy::config::Access::ALL,
                    id: None,
                    unfinished: false,
                    toward: Vec::new(),
                    closed_at: None,
                })
                .collect();
            // A profile per pairing, named after it.
            let names: Vec<String> = node_ids.iter().map(|n| format!("nerve.{n}")).collect();
            let profiles = if self.running.borrow().contains(&paths.state_dir) {
                crate::grants::Profiles {
                    why: (!names.is_empty()).then(|| "the node runs".into()),
                    kept: names,
                    ..Default::default()
                }
            } else {
                crate::grants::Profiles {
                    removed: names,
                    ..Default::default()
                }
            };
            crate::grants::Synced {
                removed: usize::from(recorded),
                away,
                profiles,
                ..Default::default()
            }
        }
    }

    pub(crate) fn layout(root: &Path) -> Layout {
        let data = root.join("ProgramData/Nerve");
        Layout {
            unit: PathBuf::new(),
            bin: root.join("Program Files/Nerve/nerve-node.exe"),
            paths: NodePaths::new(data.join("config"), data.join("state")),
            home: data,
            run_home: PathBuf::new(),
            run_temp: Vec::new(),
            release: "http://127.0.0.1:1/none".into(),
            edition: &crate::edition::NODE,
        }
    }

    /// The folders of alice's node run by hand.
    fn by_hand(root: &Path) -> NodePaths {
        let home = root.join("Users/alice");
        NodePaths::new(home.join(".config/nerve"), home.join(".local/state/nerve"))
    }

    /// Installs a "program" saying `version`, as alice with her password.
    pub(crate) fn installed(root: &Path, sys: &Fake, version: &str) -> Layout {
        let l = layout(root);
        let exe = root.join("Downloads/nerve-node-x86_64-windows.exe");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, format!("nerve-node {version}\n")).unwrap();
        sys.types("alice's");
        install(&l, sys, &exe, "alice", &mut Vec::new()).unwrap();
        l
    }

    fn audit_events(l: &Layout) -> Vec<serde_json::Value> {
        AuditLog::new(l.paths.audit_log())
            .read()
            .unwrap()
            .into_iter()
            .filter(|v| v["kind"] == "node")
            .collect()
    }

    /// The name and password `file` in the config folder holds.
    fn stored(sys: &Fake, l: &Layout, file: &str) -> Option<(String, String)> {
        let blob = std::fs::read(l.paths.config_dir.join(file)).ok()?;
        parse_secret(&sys.unprotect(&blob).ok()?)
    }

    /// The node's Event Log entries come from a source of the service's
    /// name.
    #[test]
    fn the_event_source_is_the_service() {
        assert_eq!(crate::eventlog::SOURCE, SERVICE_NAME);
    }

    #[test]
    fn the_secret_holds_name_and_password() {
        let s = secret("alice", "a\0b c");
        assert_eq!(
            parse_secret(&s),
            Some(("alice".to_string(), "a\0b c".to_string()))
        );
        assert_eq!(parse_secret(b"no separator"), None);
        assert_eq!(parse_secret(b"\0pw"), None);
        let p = new_password();
        assert!(p.len() >= 32 && p.starts_with("Nn1-"), "{p}");
        assert_ne!(p, new_password());
    }

    /// A node.toml that keeps the keys in the keyring is refused before
    /// install changes anything: the service, as nerve, would not find
    /// keys that are in another account's Credential Manager.
    #[test]
    fn install_refuses_keys_in_the_keyring() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = layout(d.path());
        // Left by a node run on these folders before.
        std::fs::create_dir_all(&l.paths.config_dir).unwrap();
        std::fs::create_dir_all(&l.paths.state_dir).unwrap();
        std::fs::write(
            l.paths.config_file(),
            "[machine]\nsecret_storage = \"keyring\"\n",
        )
        .unwrap();
        let exe = d.path().join("Downloads/nerve-node-x86_64-windows.exe");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, "nerve-node 1.0.0\n").unwrap();
        let e = install(&l, &sys, &exe, "alice", &mut Vec::new()).unwrap_err();
        assert!(e.contains("install changed nothing"), "{e}");
        assert!(e.contains("Credential Manager"), "{e}");
        // It names the folders to delete, and no command for a terminal.
        let folders = format!(
            "delete {} and {}",
            l.paths.config_dir.display(),
            l.paths.state_dir.display()
        );
        assert!(e.contains(&folders), "{e}");
        assert!(!e.contains("nerve-node "), "{e}");
        assert!(sys.calls().is_empty(), "{:?}", sys.calls());
        assert!(sys.secured.borrow().is_empty());
        assert!(!l.bin.exists());
        let a = audit_events(&l);
        assert_eq!(a.len(), 1);
        assert!(
            a[0]["error"].as_str().unwrap().contains("keyring"),
            "{}",
            a[0]
        );
    }

    #[test]
    fn install_registers_the_service_under_its_own_account() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = layout(d.path());
        let exe = d.path().join("Downloads/nerve-node-x86_64-windows.exe");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, "nerve-node 1.0.0\n").unwrap();
        sys.types("alice's");
        let mut out = Vec::new();
        install(&l, &sys, &exe, "alice", &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("made the user nerve,"), "{out}");
        assert!(out.contains("Password of alice"), "{out}");
        assert!(
            out.contains(
                "user mode, allowlist mode as you and sudo run commands as alice, who ran install; your password is stored with DPAPI"
            ),
            "{out}"
        );
        // The command account: made, its password stored, its profile
        // made and kept loaded by a service of its own, and checked.
        assert!(
            out.contains("made the user nerve-run, which commands from centers run as"),
            "{out}"
        );
        assert!(
            out.contains("nerve-run cannot open the node's folders nor your registry"),
            "{out}"
        );
        assert!(
            out.contains("registered and started the service nerve-run-profile"),
            "{out}"
        );
        assert!(!out.contains("Warning"), "{out}");
        assert!(
            out.contains("Next: open Nerve; its first-run steps"),
            "{out}"
        );
        assert_eq!(
            sys.calls(),
            [
                "add nerve".to_string(),
                "add nerve-run".into(),
                "profile nerve-run".into(),
                "reach nerve-run".into(),
                "logon alice".into(),
                format!("profile service {}", l.bin.display()),
                format!("put {}", l.bin.display()),
                "event source".into(),
                "owner S-1-5-21-1-2-3-1001".into(),
                "start".into(),
            ]
        );
        let run = sys.account(RUN_USER).unwrap().unwrap();
        assert_eq!(run.comment, RUN_MARK);
        let (name, run_password) = stored(&sys, &l, RUN_SECRET_FILE).unwrap();
        assert_eq!(name, RUN_USER);
        assert!(run_password.len() >= 32);
        let blob = std::fs::read(l.paths.config_dir.join(RUN_SECRET_FILE)).unwrap();
        assert!(
            !blob
                .windows(run_password.len())
                .any(|w| w == run_password.as_bytes())
        );
        // The one who installed is the owner: the service lets that SID
        // start and stop it.
        assert!(out.contains("alice is the owner of the node:"), "{out}");
        assert_eq!(
            sys.owner().unwrap(),
            Some(("S-1-5-21-1-2-3-1001".into(), "alice".into()))
        );
        // The Event Log takes the text of the node's entries from the
        // installed program.
        assert_eq!(*sys.event_source.borrow(), Some(l.bin.clone()));
        assert!(
            out.contains("registered the source nerve-node in the Windows Event Log"),
            "{out}"
        );
        // The folders are nerve's; the program is in place.
        let secured = sys.secured.borrow().clone();
        assert_eq!(
            secured,
            [&l.home, &l.paths.config_dir, &l.paths.state_dir]
                .map(|d| (d.clone(), Some(USER.to_string())))
        );
        assert_eq!(std::fs::read(&l.bin).unwrap(), b"nerve-node 1.0.0\n");
        // The password is stored, not in clear.
        let file = l.paths.config_dir.join(SECRET_FILE);
        let blob = std::fs::read(&file).unwrap();
        assert!(!blob.windows(7).any(|w| w == b"alice's"));
        assert_eq!(
            parse_secret(&sys.unprotect(&blob).unwrap()),
            Some(("alice".into(), "alice's".into()))
        );
        let a = audit_events(&l);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0]["event"], "install");
        assert!(a[0].get("error").is_none());
        assert_eq!(a[0]["steps"].as_array().unwrap().len(), 12, "{}", a[0]);
        // Again: the accounts get new passwords, the service is stopped and
        // started, and the owner's stored password is kept without a
        // question.
        std::fs::write(&exe, "nerve-node 1.0.1\n").unwrap();
        // What an uninstall that ran from the program moved aside goes.
        let aside = l.bin.with_file_name("nerve-node.x1y2.del");
        std::fs::write(&aside, "old").unwrap();
        let mut out = Vec::new();
        install(&l, &sys, &exe, "alice", &mut out).unwrap();
        assert!(!aside.exists());
        // The old program is removed, or moved aside where the Event Log
        // holds it, before the new one takes its place: written over, a
        // held file refuses.
        assert_eq!(
            sys.removed.borrow().as_slice(),
            std::slice::from_ref(&l.bin)
        );
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("stopped the service nerve-node"), "{out}");
        assert!(out.contains("the user nerve is there already"), "{out}");
        assert!(
            out.contains("the user nerve-run is there already; it has a new password"),
            "{out}"
        );
        assert!(out.contains("your stored password still works"), "{out}");
        assert!(!out.contains("Password of"), "{out}");
        assert_eq!(std::fs::read(&l.bin).unwrap(), b"nerve-node 1.0.1\n");
        assert!(sys.calls().contains(&"reset nerve".to_string()));
        assert!(sys.calls().contains(&"reset nerve-run".to_string()));
        let (_, again) = stored(&sys, &l, RUN_SECRET_FILE).unwrap();
        assert_ne!(again, run_password);
        assert_eq!(audit_events(&l).len(), 2);
        // Another account that installs over it is the owner from then on:
        // one owner, as on Linux.
        *sys.installer.borrow_mut() = Some(("S-1-5-21-1-2-3-1002".into(), "bob".into()));
        sys.passwords
            .borrow_mut()
            .push(("bob".into(), "bob's".into()));
        sys.types("bob's");
        let mut out = Vec::new();
        install(&l, &sys, &exe, "bob", &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("bob is the owner of the node now, in place of alice"),
            "{out}"
        );
        assert_eq!(
            sys.owner().unwrap(),
            Some(("S-1-5-21-1-2-3-1002".into(), "bob".into()))
        );
        assert_eq!(
            stored(&sys, &l, SECRET_FILE),
            Some(("bob".into(), "bob's".into()))
        );
    }

    #[test]
    fn install_asks_again_and_refuses_what_could_read_the_keys() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        // The password changed: the stored one no longer works, and the new
        // one is asked for and stored.
        sys.passwords.borrow_mut()[0].1 = "new".into();
        sys.types("new");
        let exe = l.bin.clone();
        let mut out = Vec::new();
        install(&l, &sys, &exe, "alice", &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("Password of alice"), "{out}");
        assert!(out.contains("the program is at"), "{out}");
        let blob = std::fs::read(l.paths.config_dir.join(SECRET_FILE)).unwrap();
        assert_eq!(
            parse_secret(&sys.unprotect(&blob).unwrap()).unwrap().1,
            "new"
        );
        // Each of these leaves the node without an account, and install
        // still does the rest.
        sys.passwords
            .borrow_mut()
            .push(("bob".into(), "bob's".into()));
        sys.reaching.borrow_mut().push("carol".into());
        sys.accounts.borrow_mut().push(account("carol", 1003, ""));
        sys.passwords
            .borrow_mut()
            .push(("carol".into(), "carol's".into()));
        for (who, typed, why) in [
            ("bob", "wrong", "the password of bob is wrong"),
            ("ghost", "", "there is no local account ghost"),
            ("nerve", "", "node's own user"),
            ("nerve-run", "", "the commands' own user"),
            ("carol", "carol's", "carol could open"),
            ("a:b", "", "not an account name"),
        ] {
            let l = layout(&d.path().join(who.replace(':', "_")));
            if !typed.is_empty() {
                sys.types(typed);
            }
            let mut out = Vec::new();
            install(&l, &sys, &exe, who, &mut out).unwrap();
            let out = String::from_utf8(out).unwrap();
            assert!(out.contains("no commands as you"), "{who}: {out}");
            assert!(out.contains(why), "{who}: {out}");
            assert!(!l.paths.config_dir.join(SECRET_FILE).exists(), "{who}");
            // The command account is there all the same.
            assert!(l.paths.config_dir.join(RUN_SECRET_FILE).exists(), "{who}");
        }
        // An administrator is taken, with a warning.
        let l = layout(&d.path().join("admin"));
        sys.types("bob's");
        let mut out = Vec::new();
        install(&l, &sys, &exe, "bob", &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("Warning: bob is in the group Administrators")
                && out.contains("UAC is no security boundary"),
            "{out}"
        );
        assert_eq!(
            stored(&sys, &l, SECRET_FILE),
            Some(("bob".into(), "bob's".into()))
        );
    }

    /// The command account is the install's own: one of that name it did
    /// not make is refused, and so is one that can open the node's folders
    /// or the owner's registry. Then no service is registered.
    #[test]
    fn install_refuses_a_command_account_that_is_not_its_own_or_reaches_too_far() {
        let d = tempfile::tempdir().unwrap();
        let exe = d.path().join("Downloads/nerve-node-x86_64-windows.exe");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, "nerve-node 1.0.0\n").unwrap();
        let foreign = Fake::new();
        foreign
            .accounts
            .borrow_mut()
            .push(account(RUN_USER, 1011, "someone"));
        let reaching = Fake::new();
        reaching.reaching.borrow_mut().push(RUN_USER.into());
        let hive = Fake::new();
        hive.hive_open.set(true);
        for (sys, why) in [
            (
                &foreign,
                "a user nerve-run exists already, and Nerve's install did not make it",
            ),
            (&reaching, "nerve-run could open"),
            (
                &hive,
                "nerve-run could open HKEY_USERS\\S-1-5-21-1-2-3-1001",
            ),
        ] {
            let l = layout(&d.path().join(why.len().to_string()));
            sys.types("alice's");
            let e = install(&l, sys, &exe, "alice", &mut Vec::new()).unwrap_err();
            assert!(e.contains(why), "{e}");
            assert!(!sys.calls().iter().any(|c| c.starts_with("put ")), "{e}");
            assert_eq!(sys.profile_service.get(), None, "{e}");
            assert_eq!(sys.owner().unwrap(), None, "{e}");
        }
        // The foreign account is left as it was.
        assert_eq!(
            foreign.account(RUN_USER).unwrap().unwrap().comment,
            "someone"
        );
    }

    #[test]
    fn install_refuses_a_user_it_did_not_make_and_needs_an_administrator() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        sys.accounts
            .borrow_mut()
            .push(account("nerve", 1010, "someone"));
        let l = layout(d.path());
        let e = install(&l, &sys, Path::new("x"), "alice", &mut Vec::new()).unwrap_err();
        assert!(e.contains("did not make it"), "{e}");
        assert!(!l.bin.exists());
        assert!(sys.calls().is_empty());
        let not_admin = Fake {
            admin: false,
            ..Fake::new()
        };
        for (what, e) in [
            (
                "install",
                install(&l, &not_admin, Path::new("x"), "alice", &mut Vec::new()),
            ),
            (
                "uninstall",
                uninstall(&l, &by_hand(d.path()), &not_admin, false, &mut Vec::new()),
            ),
        ] {
            let e = e.unwrap_err();
            assert!(
                e.starts_with(&format!("{what} needs an administrator")),
                "{e}"
            );
        }
        assert!(not_admin.calls().is_empty());
    }

    #[test]
    fn uninstall_leaves_no_service_user_or_program_and_keeps_the_folders() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        std::fs::write(l.paths.config_file(), "version = 3\n").unwrap();
        let sudo = l.paths.config_dir.join(crate::winsudo::SUDO_FILE);
        std::fs::write(&sudo, "sealed").unwrap();
        sys.secured.borrow_mut().clear();
        let mut out = Vec::new();
        uninstall(&l, &by_hand(d.path()), &sys, false, &mut out).unwrap();
        // No sudo password stays behind: an install over the folders
        // starts with sudo off.
        assert!(!sudo.exists());
        assert!(!l.bin.exists());
        assert_eq!(sys.service.get(), None);
        assert!(sys.account(USER).unwrap().is_none());
        assert!(
            sys.calls().ends_with(&[
                "stop".into(),
                "delete".into(),
                "no profile service".into(),
                format!("remove grants  of {}", l.paths.state_dir.display()),
                "no event source".into(),
                "remove nerve".into(),
                "remove nerve-run".into(),
            ]),
            "{:?}",
            sys.calls()
        );
        assert_eq!(*sys.event_source.borrow(), None);
        // The config, the stored password and the state stay, open to the
        // administrators only, and the audit log has both commands.
        assert_eq!(
            std::fs::read_to_string(l.paths.config_file()).unwrap(),
            "version = 3\n"
        );
        assert!(l.paths.config_dir.join(SECRET_FILE).exists());
        assert_eq!(
            sys.secured.borrow().clone(),
            [&l.paths.config_dir, &l.home, &l.paths.state_dir].map(|d| (d.clone(), None))
        );
        let events: Vec<_> = audit_events(&l)
            .iter()
            .map(|v| v["event"].clone())
            .collect();
        assert_eq!(events, ["install", "uninstall"]);
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("removed the source nerve-node from the Windows Event Log"),
            "{out}"
        );
        assert!(
            out.contains("an uninstall that deletes the data deletes them"),
            "{out}"
        );
        assert!(out.contains("removed the program"), "{out}");
        assert!(out.contains("removed the stored sudo password"), "{out}");
        // The command account goes with its profile service and its
        // profile, which holds those of the commands' AppContainers.
        assert!(sys.account(RUN_USER).unwrap().is_none());
        assert_eq!(sys.profile_service.get(), None);
        assert!(
            out.contains("stopped and removed the service nerve-run-profile"),
            "{out}"
        );
        assert!(
            out.contains("removed the user nerve-run and its profile, with those of the commands' AppContainers"),
            "{out}"
        );
    }

    /// Folder mode's grants come off at uninstall, those of every center,
    /// and before a purge deletes their record with the state folder.
    #[test]
    fn uninstall_takes_the_folder_grants_off_before_the_state_goes() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        let mut store = SettingsStore::open(
            l.paths.config_file(),
            l.paths.config_key(),
            AuditLog::new(l.paths.audit_log()),
        )
        .unwrap();
        store
            .update(|c| {
                for name in ["lab", "home"] {
                    c.centers.push(nerve_policy::CenterEntry {
                        name: name.into(),
                        url: "https://center.example".into(),
                        pin: None,
                        center_id: String::new(),
                        node_id: format!("n-{name}"),
                        settings: Default::default(),
                        paused: false,
                        revoked: false,
                        unknown: false,
                        public_key: None,
                        key_rotations: 0,
                        pin_rotations: 0,
                        old_pin: None,
                        policy: Default::default(),
                        capabilities: Vec::new(),
                    });
                }
                Ok(())
            })
            .unwrap();
        drop(store);
        std::fs::write(crate::grants::record_file(&l.paths), "[]").unwrap();
        let mut out = Vec::new();
        uninstall(&l, &by_hand(d.path()), &sys, true, &mut out).unwrap();
        let call = format!(
            "remove grants n-lab,n-home of {}",
            l.paths.state_dir.display()
        );
        assert!(sys.calls().contains(&call), "{:?}", sys.calls());
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("took 1 folder grants of the commands off"),
            "{out}"
        );
        assert!(!l.paths.state_dir.exists());
        // No node ran by hand, so it has no grants to take off.
        assert!(
            !sys.calls().iter().any(|c| c.contains(".local")),
            "{:?}",
            sys.calls()
        );
    }

    /// The grants of the node run by hand come off at uninstall too: the
    /// installed service puts none on, so those are the only ones there
    /// are. Its folders stay.
    #[test]
    fn uninstall_takes_the_grants_of_the_node_run_by_hand_off() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        let hand = by_hand(d.path());
        let mut store = SettingsStore::open(
            hand.config_file(),
            hand.config_key(),
            AuditLog::new(hand.audit_log()),
        )
        .unwrap();
        store
            .update(|c| {
                c.centers.push(nerve_policy::CenterEntry {
                    name: "lab".into(),
                    url: "https://center.example".into(),
                    pin: None,
                    center_id: String::new(),
                    node_id: "n-lab".into(),
                    settings: Default::default(),
                    paused: false,
                    revoked: false,
                    unknown: false,
                    public_key: None,
                    key_rotations: 0,
                    pin_rotations: 0,
                    old_pin: None,
                    policy: Default::default(),
                    capabilities: Vec::new(),
                });
                Ok(())
            })
            .unwrap();
        drop(store);
        std::fs::write(crate::grants::record_file(&hand), "[]").unwrap();
        let mut out = Vec::new();
        uninstall(&l, &hand, &sys, true, &mut out).unwrap();
        let call = format!("remove grants n-lab of {}", hand.state_dir.display());
        assert!(sys.calls().contains(&call), "{:?}", sys.calls());
        let out = String::from_utf8(out).unwrap();
        let did = format!(
            "took 1 folder grants of the node run by hand ({}) off",
            hand.state_dir.display()
        );
        assert!(out.contains(&did), "{out}");
        assert!(hand.config_file().exists() && hand.state_dir.exists());
    }

    /// Pairs the node at `paths` with centers named `names`, whose pairings
    /// are `n-<name>`; the config is signed with the key in its state folder.
    fn paired(paths: &NodePaths, names: &[&str]) {
        let mut store = SettingsStore::open(
            paths.config_file(),
            paths.config_key(),
            AuditLog::new(paths.audit_log()),
        )
        .unwrap();
        store
            .update(|c| {
                for name in names {
                    c.centers.push(nerve_policy::CenterEntry {
                        name: name.to_string(),
                        url: "https://center.example".into(),
                        pin: None,
                        center_id: String::new(),
                        node_id: format!("n-{name}"),
                        settings: Default::default(),
                        paused: false,
                        revoked: false,
                        unknown: false,
                        public_key: None,
                        key_rotations: 0,
                        pin_rotations: 0,
                        old_pin: None,
                        policy: Default::default(),
                        capabilities: Vec::new(),
                    });
                }
                Ok(())
            })
            .unwrap();
    }

    /// A state folder deleted without uninstall takes the record of the
    /// grants and the key of the config's MAC with it; the pairings in the
    /// config still name the profiles of their containers, so uninstall
    /// removes them.
    #[test]
    fn uninstall_finds_the_containers_without_the_state_folder() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        paired(&l.paths, &["lab", "home"]);
        std::fs::remove_dir_all(&l.paths.state_dir).unwrap();
        let mut out = Vec::new();
        uninstall(&l, &by_hand(d.path()), &sys, false, &mut out).unwrap();
        let call = format!(
            "remove grants n-lab,n-home of {}",
            l.paths.state_dir.display()
        );
        assert!(sys.calls().contains(&call), "{:?}", sys.calls());
        let out = String::from_utf8(out).unwrap();
        assert!(!out.contains("warning"), "{out}");
    }

    /// So it does for the node run by hand, whose state folder is gone
    /// while its config stays.
    #[test]
    fn uninstall_finds_the_containers_of_the_node_run_by_hand_without_its_state_folder() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        let hand = by_hand(d.path());
        paired(&hand, &["lab"]);
        std::fs::remove_dir_all(&hand.state_dir).unwrap();
        let mut out = Vec::new();
        uninstall(&l, &hand, &sys, true, &mut out).unwrap();
        let call = format!("remove grants n-lab of {}", hand.state_dir.display());
        assert!(sys.calls().contains(&call), "{:?}", sys.calls());
        assert!(hand.config_file().exists() && !hand.state_dir.exists());
        let out = String::from_utf8(out).unwrap();
        let did = format!(
            "removed the AppContainer profiles of the node run by hand ({}) (nerve.n-lab)",
            hand.state_dir.display()
        );
        assert!(out.contains(&did), "{out}");
    }

    /// Uninstall on a machine where only a node run by hand is says which
    /// of its profiles it removed, not that there was nothing to do.
    #[test]
    fn uninstall_of_only_a_node_run_by_hand_names_the_profiles_it_removed() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let hand = by_hand(d.path());
        paired(&hand, &["lab"]);
        let mut out = Vec::new();
        uninstall(&layout(d.path()), &hand, &sys, false, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("(nerve.n-lab)"), "{out}");
        assert!(!out.contains("nothing to uninstall"), "{out}");
    }

    /// The profiles of a node that runs stay, as its commands use them;
    /// uninstall says which and how they go.
    #[test]
    fn uninstall_leaves_the_profiles_of_a_node_that_runs_and_says_so() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        let hand = by_hand(d.path());
        paired(&hand, &["lab"]);
        sys.running.borrow_mut().push(hand.state_dir.clone());
        let mut out = Vec::new();
        uninstall(&l, &hand, &sys, false, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        let left = format!(
            "left the AppContainer profiles of the node run by hand ({}) (nerve.n-lab), since the node runs: once it stopped, install Nerve and uninstall it again",
            hand.state_dir.display()
        );
        assert!(out.contains(&left), "{out}");
    }

    /// A config that cannot be read names no pairing, and uninstall says
    /// so and goes on.
    #[test]
    fn uninstall_says_when_the_pairings_cannot_be_read() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        std::fs::write(l.paths.config_file(), "[[center]\n").unwrap();
        let mut out = Vec::new();
        uninstall(&l, &by_hand(d.path()), &sys, true, &mut out).unwrap();
        let call = format!("remove grants  of {}", l.paths.state_dir.display());
        assert!(sys.calls().contains(&call), "{:?}", sys.calls());
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("warning: the profiles of the commands' AppContainers cannot be found"),
            "{out}"
        );
        assert!(!l.paths.state_dir.exists());
    }

    /// Grants on a drive that is not connected stay on: uninstall says so,
    /// and how they come off, by another uninstall while their record stays.
    #[test]
    fn uninstall_names_the_grants_left_on_drives_that_are_not_here() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        let hand = by_hand(d.path());
        std::fs::create_dir_all(&hand.state_dir).unwrap();
        std::fs::write(crate::grants::record_file(&hand), "[]").unwrap();
        sys.away.borrow_mut().push(PathBuf::from(r"E:\proj"));
        let mut out = Vec::new();
        uninstall(&l, &hand, &sys, true, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        let left = format!(
            "left 1 folder grants of the node run by hand ({}) on, on drives that are not connected now (E:\\proj): connect their drives, then install Nerve and uninstall it again",
            hand.state_dir.display()
        );
        assert!(out.contains(&left), "{out}");
    }

    #[test]
    fn uninstall_purge_deletes_the_folders_and_the_password_and_leaves_a_foreign_user() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        uninstall(&l, &by_hand(d.path()), &sys, true, &mut Vec::new()).unwrap();
        for p in [
            &l.bin,
            &l.home,
            &l.paths.config_dir,
            &l.paths.state_dir,
            &l.paths.config_dir.join(SECRET_FILE),
        ] {
            assert!(!p.exists(), "{p:?}");
        }
        assert_eq!(sys.service.get(), None);
        assert_eq!(*sys.event_source.borrow(), None);
        assert!(sys.account(USER).unwrap().is_none());
        // Nothing left, the source included: nothing is said to be removed.
        let mut out = Vec::new();
        uninstall(&l, &by_hand(d.path()), &sys, true, &mut out).unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .starts_with("nothing to uninstall"),
        );
        sys.accounts
            .borrow_mut()
            .push(account("nerve", 1010, "someone"));
        let mut out = Vec::new();
        uninstall(&l, &by_hand(d.path()), &sys, true, &mut out).unwrap();
        assert!(sys.account(USER).unwrap().is_some());
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("left the user nerve")
        );
    }

    /// What update must not touch: the config, a key, the stored password
    /// and the audit log so far. The config is made here, as the service
    /// makes it at its first start.
    fn kept(l: &Layout) -> Vec<(PathBuf, Vec<u8>)> {
        SettingsStore::open(
            l.paths.config_file(),
            l.paths.config_key(),
            AuditLog::new(l.paths.audit_log()),
        )
        .unwrap()
        .update(|c| {
            c.node.name = Some("lab".into());
            Ok(())
        })
        .unwrap();
        [
            l.paths.config_file(),
            l.paths.key_file("lab"),
            l.paths.config_key(),
            l.paths.config_dir.join(SECRET_FILE),
            l.paths.audit_log(),
        ]
        .into_iter()
        .map(|p| {
            let b = std::fs::read(&p).unwrap();
            (p, b)
        })
        .collect()
    }

    #[tokio::test]
    async fn update_replaces_the_program_and_keeps_config_keys_and_audit() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        std::fs::create_dir_all(l.paths.key_file("lab").parent().unwrap()).unwrap();
        std::fs::write(l.paths.key_file("lab"), "key").unwrap();
        let before = kept(&l);
        let new = d.path().join("new.exe");
        std::fs::write(&new, "nerve-node 1.2.0\n").unwrap();
        let calls = sys.calls().len();
        let mut out = Vec::new();
        update(&l, &sys, Some(&new), &mut out).await.unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("replaced nerve-node 1.0.0 with 1.2.0"),
            "{out}"
        );
        assert_eq!(std::fs::read(&l.bin).unwrap(), b"nerve-node 1.2.0\n");
        assert_eq!(sys.calls()[calls..], ["stop", "start"]);
        assert_eq!(sys.started.borrow().last().unwrap(), "nerve-node 1.2.0");
        for (p, b) in before {
            let now = std::fs::read(&p).unwrap();
            if p == l.paths.audit_log() {
                assert!(now.starts_with(&b), "{p:?}");
            } else {
                assert_eq!(now, b, "{p:?}");
            }
        }
        assert_eq!(audit_events(&l).last().unwrap()["event"], "update");
        assert!(!staged(&l.bin).exists() && !previous(&l.bin).exists());
        // The same program again changes nothing.
        let calls = sys.calls().len();
        let mut out = Vec::new();
        update(&l, &sys, Some(&new), &mut out).await.unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("nothing to update")
        );
        assert!(sys.calls()[calls..].is_empty(), "{:?}", sys.calls());
    }

    /// The service's DACL gives each owner start, stop and asking, and
    /// keeps what Windows gives everyone else.
    #[test]
    fn the_service_lets_its_owners_start_and_stop_it() {
        let d = service_dacl(Some("S-1-5-21-1-2-3-1001"));
        assert!(
            d.starts_with("D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)"),
            "{d}"
        );
        assert!(
            d.ends_with("(A;;CCLCSWRPWPLOCRRC;;;S-1-5-21-1-2-3-1001)"),
            "{d}"
        );
        // No change of its config, its DACL or its removal for an owner.
        let owner = d.rsplit("(A;;").next().unwrap();
        for right in ["DC", "SD", "WD", "WO", "DT"] {
            assert!(
                !owner.split(";;").next().unwrap().contains(right),
                "{right}"
            );
        }
        assert_eq!(service_dacl(None).matches("(A;").count(), 4);
    }

    #[tokio::test]
    async fn update_refuses_an_older_or_foreign_program_and_puts_back_one_that_does_not_start() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.2.0");
        let new = d.path().join("new.exe");
        for (text, why) in [
            ("nerve-node 1.1.9\n", "older than the installed 1.2.0"),
            ("something else\n", "is not nerve-node"),
        ] {
            std::fs::write(&new, text).unwrap();
            let e = update(&l, &sys, Some(&new), &mut Vec::new())
                .await
                .unwrap_err();
            assert!(e.contains(why), "{e}");
            assert_eq!(std::fs::read(&l.bin).unwrap(), b"nerve-node 1.2.0\n");
            assert!(!staged(&l.bin).exists());
        }
        std::fs::write(&new, "nerve-node 2.0.0\n").unwrap();
        sys.starts.set(false);
        let calls = sys.calls().len();
        let starts = sys.started.borrow().len();
        let e = update(&l, &sys, Some(&new), &mut Vec::new())
            .await
            .unwrap_err();
        assert!(e.contains("did not start"), "{e}");
        assert!(e.contains("the old one does not either"), "{e}");
        // The old program is started again, even though here it fails too.
        assert_eq!(sys.calls()[calls..], ["stop", "start", "stop", "start"]);
        assert_eq!(
            sys.started.borrow()[starts..],
            ["nerve-node 2.0.0", "nerve-node 1.2.0"]
        );
        assert_eq!(sys.service.get(), Some(false));
        assert_eq!(std::fs::read(&l.bin).unwrap(), b"nerve-node 1.2.0\n");
        assert!(!staged(&l.bin).exists() && !previous(&l.bin).exists());
        let a = audit_events(&l);
        let last = a.last().unwrap();
        assert_eq!(last["event"], "update");
        assert!(last["error"].as_str().unwrap().contains("did not start"));
        assert!(
            last["steps"]
                .to_string()
                .contains("put nerve-node 1.2.0 back")
        );
    }

    #[tokio::test]
    async fn update_starts_the_old_program_again_when_the_new_one_does_not_start() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.2.0");
        let new = d.path().join("new.exe");
        std::fs::write(&new, "nerve-node 2.0.0\n").unwrap();
        *sys.broken.borrow_mut() = Some("nerve-node 2.0.0".into());
        let calls = sys.calls().len();
        let starts = sys.started.borrow().len();
        let e = update(&l, &sys, Some(&new), &mut Vec::new())
            .await
            .unwrap_err();
        assert!(e.contains("did not start"), "{e}");
        assert!(e.contains("the old one runs again"), "{e}");
        assert_eq!(std::fs::read(&l.bin).unwrap(), b"nerve-node 1.2.0\n");
        assert!(!staged(&l.bin).exists() && !previous(&l.bin).exists());
        // The new program was started and stopped, then the old one started
        // after it was put back: the node is up again.
        assert_eq!(sys.calls()[calls..], ["stop", "start", "stop", "start"]);
        assert_eq!(
            sys.started.borrow()[starts..],
            ["nerve-node 2.0.0", "nerve-node 1.2.0"]
        );
        assert_eq!(sys.service.get(), Some(true));
        let a = audit_events(&l);
        assert!(
            a.last().unwrap()["steps"]
                .to_string()
                .contains("put nerve-node 1.2.0 back")
        );
    }

    /// The desktop app's parts, as a file beside the program.
    struct Entry;

    impl crate::edition::Parts for Entry {
        fn install(&self, bin: &Path) -> Result<Vec<String>, String> {
            std::fs::write(bin.with_file_name("Nerve.lnk"), "link").map_err(|e| e.to_string())?;
            Ok(vec!["put the Start menu entry in place".into()])
        }
        fn uninstall(&self, bin: &Path) -> Result<Vec<String>, String> {
            std::fs::remove_file(bin.with_file_name("Nerve.lnk")).map_err(|e| e.to_string())?;
            Ok(vec!["removed the Start menu entry".into()])
        }
    }

    static DESKTOP: crate::edition::Edition = crate::edition::Edition {
        program: "nerve-node-desktop",
        parts: Some(&Entry),
    };

    #[tokio::test]
    async fn the_desktop_app_comes_and_goes_with_its_parts_and_controls_the_service() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = Layout {
            bin: d.path().join("Program Files/Nerve/nerve-node-desktop.exe"),
            edition: &DESKTOP,
            ..layout(d.path())
        };
        let e = control(&l, &sys, ServiceAction::Start, &mut Vec::new()).unwrap_err();
        assert!(e.contains("not installed as a service"), "{e}");
        let link = l.bin.with_file_name("Nerve.lnk");
        let exe = d
            .path()
            .join("Downloads/nerve-node-desktop-x86_64-windows.exe");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, "nerve-node-desktop 1.0.0\n").unwrap();
        sys.types("alice's");
        let mut out = Vec::new();
        install(&l, &sys, &exe, "alice", &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("put the Start menu entry in place"), "{out}");
        assert!(link.exists());

        for (action, calls, state) in [
            (ServiceAction::Stop, &["stop"][..], "stopped"),
            (ServiceAction::Start, &["start"][..], "running"),
            (ServiceAction::Restart, &["stop", "start"][..], "running"),
        ] {
            let before = sys.calls().len();
            control(&l, &sys, action, &mut Vec::new()).unwrap();
            assert_eq!(sys.calls()[before..], *calls, "{action:?}");
            assert_eq!(sys.service_state().unwrap().unwrap().state, state);
        }

        std::fs::remove_file(&link).unwrap();
        let new = d.path().join("new.exe");
        std::fs::write(&new, "nerve-node-desktop 1.1.0\n").unwrap();
        let mut out = Vec::new();
        update(&l, &sys, Some(&new), &mut out).await.unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("replaced nerve-node-desktop 1.0.0 with 1.1.0"),
            "{out}"
        );
        assert!(link.exists(), "{out}");
        assert_eq!(
            staged(&l.bin).file_name().unwrap(),
            "nerve-node-desktop.new.exe"
        );
        assert!(!staged(&l.bin).exists() && !previous(&l.bin).exists());

        let mut out = Vec::new();
        uninstall(&l, &by_hand(d.path()), &sys, false, &mut out).unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("removed the Start menu entry")
        );
        assert!(!link.exists());
    }

    /// Windows has no node alone to take over (#176): the app's install
    /// leaves a `nerve-node.exe` beside it as it is, and says nothing of it.
    #[test]
    fn the_app_takes_no_node_alone_over() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let node = installed(d.path(), &sys, "1.0.0").bin;
        let l = Layout {
            bin: d.path().join("Program Files/Nerve/nerve-node-desktop.exe"),
            edition: &DESKTOP,
            ..layout(d.path())
        };
        let exe = d.path().join("Downloads/nerve-node-desktop.exe");
        std::fs::write(&exe, "nerve-node-desktop 1.0.0\n").unwrap();
        let mut out = Vec::new();
        install(&l, &sys, &exe, "alice", &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(!out.contains("installed alone"), "{out}");
        assert!(!out.contains("CLI edition"), "{out}");
        assert_eq!(
            std::fs::read_to_string(&node).unwrap(),
            "nerve-node 1.0.0\n"
        );
        assert_eq!(*sys.program.borrow(), Some(l.bin.clone()));
    }

    #[tokio::test]
    async fn update_needs_an_installed_node() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let e = update(&layout(d.path()), &sys, None, &mut Vec::new())
            .await
            .unwrap_err();
        assert!(e.contains("not installed"), "{e}");
    }
}
