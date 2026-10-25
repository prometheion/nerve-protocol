//! The accounts a center's commands run as on a node installed as a service
//! (docs/user/service.md). The service runs as `nerve`, which owns the
//! node's config, keys and state; no command runs as it. On Linux a command
//! of `folder` mode, and of `allowlist` mode unless the pairing says
//! otherwise, runs as [`RUN_USER`], an account of its own that `install`
//! makes, with a home of its own and the folders the owner grants it
//! (crate::acl); a command of `user` mode runs as the owner (the account
//! that ran `install`, which the service unit names). On Windows every
//! command runs as the owner, folder mode in an AppContainer. To switch to
//! the account the service keeps CAP_SETUID and CAP_SETGID, the one
//! privilege it has, and every command it starts drops both before it runs.

use std::path::Path;

use nerve_policy::config::{Access, Folder};

use crate::service::Account;

/// The account the installed node runs commands as that do not run as the
/// owner (Linux).
pub const RUN_USER: &str = "nerve-run";

/// The comment `install` gives [`RUN_USER`]. An account of that name without
/// it was not made by `install`: no command runs as it, and `uninstall`
/// leaves it.
pub const RUN_MARK: &str = "Nerve commands";

/// The home of [`RUN_USER`], which `install` makes: its own, writable, where
/// tool caches and configs go.
pub const RUN_HOME: &str = "/var/lib/nerve-run";

/// The folders a command of [`RUN_USER`] has besides those of its pairing,
/// whatever they say: `/tmp`, `/var/tmp` and the account's home, to read,
/// write and run programs in. Under its own uid the owner's sockets and
/// folders in `/tmp` stay closed to it by their modes.
pub fn built_in(home: &Path) -> Vec<Folder> {
    let all = Access {
        read: true,
        write: true,
        execute: true,
    };
    [Path::new("/tmp"), Path::new("/var/tmp"), home]
        .iter()
        .map(|p| Folder {
            path: p.display().to_string(),
            access: all,
        })
        .collect()
}

/// What a command of the installed node gets that would run as the owner
/// while the node has none.
#[cfg(not(windows))]
pub const NO_OWNER: &str = "this node has no owner, as `install` ran as root and not through sudo: commands of user mode, and of allowlist mode as the owner, run as the owner, so none runs; run `sudo nerve-node install` again from the owner's own account, or `nerve-node install` as root with a yes to its question (or `--owner=root --accept-root-owner`) to make root the owner";
/// What a command of the installed node gets while it has no owner: on
/// Windows `install` takes it, with its password.
#[cfg(windows)]
pub const NO_OWNER: &str = "this node runs commands as its owner's account, and has none: `nerve-node install`, run again as administrator by that account, sets it (machine.user)";

/// How `install` ends the line saying that it set no account for the
/// commands on Windows; the desktop app says it in its own words.
pub const NO_ACCOUNT_INSTALL: &str = "`nerve-node install` asks again";

/// The mode of `home` when other accounts may list or enter it (`o+r` or
/// `o+x`): `nerve-run` is another account, and reads there what anyone may.
#[cfg(unix)]
pub fn home_open(home: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(home).ok()?.permissions().mode() & 0o777;
    (mode & 0o005 != 0).then_some(mode)
}

/// What a machine without Landlock leaves open of the owner's `home` to
/// `nerve-run`, which is held to its folders by its own account alone
/// there: every file in the home that other accounts may read, when the
/// home is open to them (`open`, its mode), or when a folder given to it
/// lies in the home (`below`, the folders the owner named there), as it
/// passes through the home to get there (crate::acl); `home` itself in
/// `below` is the home given whole. `None` where neither is so. With
/// Landlock nothing is said: it holds every command of `nerve-run` to its
/// own folders. While a folder in the home is given the warning stays,
/// whatever the modes of the files there, and it says so.
#[cfg(unix)]
pub fn home_warning(
    home: &Path,
    open: Option<u32>,
    below: &[std::path::PathBuf],
) -> Option<String> {
    let mut why = Vec::new();
    if let Some(mode) = open {
        why.push(format!(
            "your home is open to other accounts (mode {mode:o}; `chmod 750 {}` closes it)",
            home.display()
        ));
    }
    let whole = below.iter().any(|p| p == home);
    if whole {
        why.push("you give it your home itself".to_string());
    } else if let Some(first) = below.first() {
        why.push(format!(
            "it passes through your home to {}{}",
            first.display(),
            if below.len() > 1 {
                format!(" and {} more folders you give it there", below.len() - 1)
            } else {
                String::new()
            }
        ));
    }
    let advice = if below.is_empty() {
        LANDLOCK_ADVICE
    } else {
        GIVEN_ADVICE
    };
    (!why.is_empty()).then(|| {
        format!(
            "Without Landlock, {RUN_USER} can read every file in your home {} that other accounts may read, not only the folders you give it, as {}. {advice}",
            home.display(),
            why.join(" and ")
        )
    })
}

/// What `install` says on a machine without Landlock, before any folder
/// was given: what giving one in the home leaves open ([`home_warning`]).
#[cfg(unix)]
pub fn no_landlock_warning() -> String {
    format!(
        "this kernel has no Landlock, so the commands of {RUN_USER} run without it: once you give it a folder in your home, it can read every file in your home that other accounts may read, not only that folder. {LANDLOCK_ADVICE}"
    )
}

/// What closes the reach of [`home_warning`].
#[cfg(unix)]
const LANDLOCK_ADVICE: &str =
    "Grant folders outside your home, use umask 027, or use a kernel with Landlock.";

/// [`LANDLOCK_ADVICE`] while a folder in the home is given: the modes
/// narrow what `nerve-run` reads, but the warning stays.
#[cfg(unix)]
const GIVEN_ADVICE: &str = "This warning stays while you give it a folder in your home: umask 027 and `chmod -R o-rwx` narrow what it can read there, and only folders outside your home or a kernel with Landlock end it.";

#[cfg(all(test, unix))]
mod home_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A home others may list or enter is open to `nerve-run` too; one
    /// closed to them is not (#142).
    #[test]
    fn a_home_open_to_others_is_told() {
        let d = tempfile::tempdir().unwrap();
        let home = d.path();
        for (mode, open) in [
            (0o755, true),
            (0o711, true),
            (0o704, true),
            (0o750, false),
            (0o700, false),
        ] {
            std::fs::set_permissions(home, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(home_open(home), open.then_some(mode), "{mode:o}");
        }
    }

    /// Without Landlock the warning names both ways into the home: a home
    /// open to others, and a folder given in the home that `nerve-run`
    /// passes through to (owner's decision of 2026-10-21); with neither it
    /// says nothing.
    #[test]
    fn the_home_warning_names_what_lets_nerve_run_in() {
        let home = Path::new("/home/o");
        let open = home_warning(home, Some(0o755), &[]).unwrap();
        assert!(
            open.starts_with("Without Landlock, nerve-run can read every file in your home /home/o that other accounts may read, not only the folders you give it"),
            "{open}"
        );
        assert!(
            open.contains("mode 755; `chmod 750 /home/o` closes it"),
            "{open}"
        );
        assert!(open.ends_with(LANDLOCK_ADVICE), "{open}");
        let below = [home.join("proj"), home.join("docs")];
        let through = home_warning(home, None, &below).unwrap();
        assert!(
            through.contains("it passes through your home to /home/o/proj and 1 more folders"),
            "{through}"
        );
        assert!(!through.contains("chmod 750"), "{through}");
        // Only moving the folders or Landlock ends it, and it says so.
        assert!(through.ends_with(GIVEN_ADVICE), "{through}");
        assert!(!open.contains("This warning stays"), "{open}");
        // The home given whole: said so, not as folders it passes to.
        let whole = home_warning(home, None, &[home.to_path_buf()]).unwrap();
        assert!(
            whole.contains("as you give it your home itself.") && whole.ends_with(GIVEN_ADVICE),
            "{whole}"
        );
        assert!(
            !whole.contains("passes through") && !whole.contains("more folders"),
            "{whole}"
        );
        let both = home_warning(home, Some(0o711), &below[..1]).unwrap();
        assert!(
            both.contains("mode 711") && both.contains("to /home/o/proj."),
            "{both}"
        );
        assert_eq!(home_warning(home, None, &[]), None);
        assert!(no_landlock_warning().contains("umask 027"));
    }
}

/// Root, as an allowed sudo command of a pairing whose commands run as
/// [`RUN_USER`] runs (crate::link): the node starts it as root itself, with
/// root's own group only, since `nerve-run` has no sudo of its own.
#[cfg(target_os = "linux")]
pub fn root() -> Account {
    let home = lookup("root")
        .ok()
        .flatten()
        .map_or_else(|| std::path::PathBuf::from("/root"), |a| a.home);
    Account {
        name: "root".into(),
        uid: 0,
        gid: 0,
        comment: String::new(),
        home,
        groups: vec![0],
    }
}

/// Looks `name` up in the system's account database. `getent` and `id` ask
/// it through NSS, which the static program cannot do itself.
pub fn lookup(name: &str) -> Result<Option<Account>, String> {
    #[cfg(windows)]
    return crate::win_user::lookup(name);
    #[cfg(not(windows))]
    lookup_nss(name)
}

#[cfg(not(windows))]
fn lookup_nss(name: &str) -> Result<Option<Account>, String> {
    if !nerve_policy::config::valid_account_name(name) {
        return Err(format!("{name:?} is not an account name"));
    }
    let o = plain("getent")
        .args(["passwd", name])
        .output()
        .map_err(|e| format!("getent: {e}"))?;
    // 2: no such key.
    if o.status.code() == Some(2) {
        return Ok(None);
    }
    if !o.status.success() {
        return Err(format!("getent passwd {name}: {}", stderr_or_status(&o)));
    }
    let line = String::from_utf8_lossy(&o.stdout);
    let mut a =
        parse_passwd(&line).ok_or_else(|| format!("getent passwd {name}: cannot read {line:?}"))?;
    // The groups the account is in besides its own; without them a
    // command would lack what the account may do through a group.
    if let Ok(o) = plain("id").args(["-G", "--", name]).output()
        && o.status.success()
    {
        let groups: Vec<u32> = String::from_utf8_lossy(&o.stdout)
            .split_whitespace()
            .filter_map(|g| g.parse().ok())
            .collect();
        if !groups.is_empty() {
            a.groups = groups;
        }
    }
    Ok(Some(a))
}

/// The account with `uid`, from the system's account database.
#[cfg(not(windows))]
pub fn of_uid(uid: u32) -> Option<Account> {
    let o = plain("getent")
        .args(["passwd", &uid.to_string()])
        .output()
        .ok()?;
    if !o.status.success() {
        return None;
    }
    parse_passwd(&String::from_utf8_lossy(&o.stdout)).filter(|a| a.uid == uid)
}

/// The name of the account with `uid`, from the system's account database.
pub fn name_of(uid: u32) -> Option<String> {
    #[cfg(windows)]
    {
        let _ = uid;
        None
    }
    #[cfg(not(windows))]
    of_uid(uid).map(|a| a.name)
}

/// One line of `getent passwd`.
pub fn parse_passwd(line: &str) -> Option<Account> {
    let f: Vec<&str> = line.trim_end_matches(['\n', '\r']).split(':').collect();
    let (uid, gid) = (f.get(2)?.parse().ok()?, f.get(3)?.parse().ok()?);
    Some(Account {
        name: f.first()?.to_string(),
        uid,
        gid,
        comment: f.get(4).unwrap_or(&"").to_string(),
        home: f.get(5).unwrap_or(&"/").into(),
        groups: vec![gid],
    })
}

#[cfg(not(windows))]
fn stderr_or_status(o: &std::process::Output) -> String {
    let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
    if err.is_empty() {
        o.status.to_string()
    } else {
        err
    }
}

/// A system tool started without the capabilities of the service.
#[cfg(not(windows))]
fn plain(program: &str) -> std::process::Command {
    #[allow(unused_mut)]
    let mut c = std::process::Command::new(program);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: only plain system calls run between fork and exec.
        unsafe {
            c.pre_exec(|| {
                if nerve_transport::net::euid() != 0 {
                    drop_caps()?;
                }
                Ok(())
            });
        }
    }
    c
}

/// The account a pairing's command runs as on the node: `as_owner` for one
/// that runs as the owner (crate::daemon::Shared::command_account), with
/// `owner` the node's owner (on Linux the account the service unit names,
/// on Windows `machine.user`). `None` runs it as the node's own
/// user, as a node that a person runs does with every command. The
/// installed service (`service`: its folders or its user, however it was
/// started) runs none as itself, since it owns the keys, and none at all
/// while it cannot switch accounts. On Windows every command runs as the
/// owner (the separate account is Linux's so far).
pub fn for_commands(
    as_owner: bool,
    owner: Option<&str>,
    own_uid: u32,
    service: bool,
    can_switch: bool,
    lookup: impl Fn(&str) -> Result<Option<Account>, String>,
) -> Result<Option<Account>, String> {
    if !service {
        return Ok(None);
    }
    if !can_switch {
        // Started by hand, or by a systemd without AmbientCapabilities=.
        return Err(if cfg!(windows) {
            "this installed node runs without SeAssignPrimaryTokenPrivilege and cannot start a command as another account; start it as the service: `Start-Service nerve-node`".into()
        } else {
            format!(
                "this installed node runs as uid {own_uid} without CAP_SETUID and CAP_SETGID and cannot start a command as another account; start it as the service: `sudo systemctl start nerve-node`"
            )
        });
    }
    let as_owner = as_owner || cfg!(windows);
    let name = match (as_owner, owner) {
        (true, Some(o)) => o,
        (true, None) => return Err(NO_OWNER.into()),
        (false, _) => RUN_USER,
    };
    let a = lookup(name)?.ok_or_else(|| {
        if as_owner {
            if cfg!(windows) {
                format!("the owner's account {name} (machine.user) does not exist on this machine")
            } else {
                format!(
                    "the owner's account {name}, which the service unit names (NERVE_NODE_OWNER), does not exist on this machine; run `sudo nerve-node install` again from the owner's own account"
                )
            }
        } else {
            format!(
                "the account {name} that commands run as does not exist on this machine; `sudo nerve-node install` makes it again"
            )
        }
    })?;
    // Root runs what runs as the owner only where it is the owner, which
    // `install` made it after root confirmed it (crate::service::RootOwner).
    // No other account with uid 0 is.
    let root_owner = as_owner && !cfg!(windows) && name == crate::service::ROOT && a.uid == 0;
    if a.uid == own_uid || a.uid == 0 && !root_owner {
        return Err(format!(
            "{name} is the node's own user or root, which can read the node's keys; no command runs as it"
        ));
    }
    if !as_owner && a.comment != RUN_MARK {
        return Err(format!(
            "the account {name} here was not made by `install`, so no command runs as it; `sudo nerve-node install` makes it if it is gone"
        ));
    }
    Ok(Some(a))
}

/// The number of the account this process runs as: its uid, on Windows the
/// last part of its SID (SYSTEM is 0, as root is).
pub fn own_uid() -> u32 {
    #[cfg(windows)]
    return crate::win_user::own_uid();
    #[cfg(not(windows))]
    nerve_transport::net::euid()
}

/// The name of the account this process runs as, when it can be told.
pub fn own_name() -> Option<String> {
    #[cfg(windows)]
    return crate::win_user::current_user().ok();
    #[cfg(not(windows))]
    name_of(own_uid())
}

/// Whether this process may switch to another account: root, or a process
/// with CAP_SETUID and CAP_SETGID in effect, as the installed service. On
/// Windows: SYSTEM, or a process that holds the privileges to start a
/// process with another account's token, as the installed service.
pub fn can_switch() -> bool {
    #[cfg(windows)]
    return crate::win_user::can_switch();
    #[cfg(not(windows))]
    can_switch_unix()
}

#[cfg(not(windows))]
fn can_switch_unix() -> bool {
    if nerve_transport::net::euid() == 0 {
        return true;
    }
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        status
            .lines()
            .find_map(|l| l.strip_prefix("CapEff:"))
            .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
            .is_some_and(|caps| caps & SETID_CAPS == SETID_CAPS)
    }
    #[cfg(not(target_os = "linux"))]
    false
}

/// CAP_SETGID (6) and CAP_SETUID (7).
#[cfg(target_os = "linux")]
const SETID_CAPS: u64 = (1 << 6) | (1 << 7);

/// Whether `account` reaches `path` by its permission bits: it may search
/// every folder on the way, and read `path` (or search it, for a folder).
/// Root reaches everything. A path that is not there is not reached; one
/// whose bits cannot be read counts as reached. ACLs are not looked at:
/// the node's folders have none, and a command meets them anyway
/// ([`Switch::apply`] asks the kernel).
pub fn reaches(path: &Path, account: &Account) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if account.uid == 0 {
            return true;
        }
        let may = |m: &std::fs::Metadata, bits: u32| {
            let mode = m.mode();
            let class = if m.uid() == account.uid {
                mode >> 6
            } else if m.gid() == account.gid || account.groups.contains(&m.gid()) {
                mode >> 3
            } else {
                mode
            };
            class & bits != 0
        };
        let end = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return false,
            Err(_) => return true,
        };
        for dir in path
            .ancestors()
            .skip(1)
            .filter(|d| !d.as_os_str().is_empty())
        {
            match std::fs::metadata(dir) {
                Ok(m) if !may(&m, 0o1) => return false,
                Ok(_) => {}
                Err(_) => return true,
            }
        }
        may(&end, if end.is_dir() { 0o5 } else { 0o4 })
    }
    #[cfg(not(unix))]
    {
        let _ = (path, account);
        true
    }
}

/// The error a command gets when its account can reach the node's own
/// folders ([`Switch::apply`]).
#[cfg(target_os = "linux")]
pub const IN_REACH: i32 = libc::ENOTRECOVERABLE;

/// What a command needs to start as another account, made before the fork:
/// between fork and exec nothing may allocate.
#[cfg(target_os = "linux")]
pub struct Switch {
    uid: u32,
    gid: u32,
    groups: Vec<libc::gid_t>,
    cwd: Option<std::ffi::CString>,
    enter: Option<Enter>,
    own: Vec<std::ffi::CString>,
}

/// A folder the node opened itself, which the child enters before it takes
/// the account's ids, with the file system ids of the account it was opened
/// as (`None`: the node's own): root in the node's child holds CAP_SETUID
/// and CAP_SETGID only, so as root it has no right past a folder's mode
/// until its program runs.
#[cfg(target_os = "linux")]
struct Enter {
    folder: std::os::fd::OwnedFd,
    by: Option<(u32, u32, Vec<libc::gid_t>)>,
}

#[cfg(target_os = "linux")]
impl Enter {
    /// Enters the folder; true when it changed the ids to do so, which the
    /// switch then puts right.
    fn apply(&self) -> std::io::Result<bool> {
        use std::os::fd::AsRawFd;
        let last = std::io::Error::last_os_error;
        let mut changed = false;
        // SAFETY: plain system calls with integers or memory this struct owns.
        unsafe {
            if let Some((uid, gid, groups)) = &self.by
                && (libc::geteuid() != *uid || libc::getegid() != *gid)
            {
                changed = true;
                if libc::setgroups(groups.len(), groups.as_ptr()) != 0 {
                    return Err(last());
                }
                libc::setfsgid(*gid);
                libc::setfsuid(*uid);
                if libc::setfsuid(u32::MAX) as u32 != *uid
                    || libc::setfsgid(u32::MAX) as u32 != *gid
                {
                    return Err(std::io::Error::from_raw_os_error(libc::EPERM));
                }
            }
            if libc::fchdir(self.folder.as_raw_fd()) != 0 {
                return Err(last());
            }
        }
        Ok(changed)
    }
}

#[cfg(target_os = "linux")]
impl Switch {
    /// `cwd` is entered as the account, after the switch, since the node's
    /// user may not see into it. `own` are the node's folders.
    pub fn new(
        account: &Account,
        cwd: Option<&Path>,
        own: &[std::path::PathBuf],
    ) -> std::io::Result<Switch> {
        use std::os::unix::ffi::OsStrExt;
        let c = |p: &Path| {
            std::ffi::CString::new(p.as_os_str().as_bytes()).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "a path holds a NUL byte")
            })
        };
        let mut groups = account.groups.clone();
        if groups.is_empty() {
            groups.push(account.gid);
        }
        Ok(Switch {
            uid: account.uid,
            gid: account.gid,
            groups,
            cwd: cwd.map(c).transpose()?,
            enter: None,
            own: own.iter().map(|p| c(p)).collect::<Result<_, _>>()?,
        })
    }

    /// A switch to `account` that starts in `folder`, a folder the node
    /// opened as `by` (crate::exec::AsRoot), entered with `by`'s file system
    /// ids before the switch.
    pub fn entering(
        account: &Account,
        folder: std::os::fd::OwnedFd,
        by: Option<&Account>,
        own: &[std::path::PathBuf],
    ) -> std::io::Result<Switch> {
        let mut s = Switch::new(account, None, own)?;
        s.enter = Some(Enter {
            folder,
            by: by.map(|a| {
                let mut groups = a.groups.clone();
                if groups.is_empty() {
                    groups.push(a.gid);
                }
                (a.uid, a.gid, groups)
            }),
        });
        Ok(s)
    }

    /// In the forked child, before exec: the folder the node opened, if
    /// any; the account's groups and ids, no capability left, a check that
    /// the node's own folders are out of its reach (root aside, which the
    /// owner chose knowing), then its working folder. Plain system calls
    /// only. A process that has the account's ids already keeps its groups,
    /// unless entering the folder changed them.
    pub fn apply(&self) -> std::io::Result<()> {
        let last = std::io::Error::last_os_error;
        let entered = match &self.enter {
            Some(e) => e.apply()?,
            None => false,
        };
        // SAFETY: plain system calls on memory this struct owns.
        unsafe {
            let same = !entered
                && libc::getuid() == self.uid
                && libc::geteuid() == self.uid
                && libc::getgid() == self.gid
                && libc::getegid() == self.gid;
            if !same
                && (libc::setgroups(self.groups.len(), self.groups.as_ptr()) != 0
                    || libc::setresgid(self.gid, self.gid, self.gid) != 0
                    || libc::setresuid(self.uid, self.uid, self.uid) != 0)
            {
                return Err(last());
            }
            // The switch set the file system ids to the account's again;
            // none of those the folder was entered with is left.
            if entered
                && (libc::setfsuid(u32::MAX) as u32 != self.uid
                    || libc::setfsgid(u32::MAX) as u32 != self.gid)
            {
                return Err(std::io::Error::from_raw_os_error(libc::EPERM));
            }
        }
        if self.uid != 0 {
            drop_caps()?;
            out_of_reach(&self.own)?;
        }
        // SAFETY: a NUL-terminated path this struct owns.
        if let Some(cwd) = &self.cwd
            && unsafe { libc::chdir(cwd.as_ptr()) } != 0
        {
            return Err(last());
        }
        Ok(())
    }
}

/// Fails with [`IN_REACH`] when this process may list or enter one of
/// `own`. The kernel decides, ACLs included.
#[cfg(target_os = "linux")]
pub fn out_of_reach(own: &[std::ffi::CString]) -> std::io::Result<()> {
    for p in own {
        // SAFETY: NUL-terminated paths.
        let open = unsafe {
            libc::access(p.as_ptr(), libc::R_OK) == 0 || libc::access(p.as_ptr(), libc::X_OK) == 0
        };
        if open {
            return Err(std::io::Error::from_raw_os_error(IN_REACH));
        }
    }
    Ok(())
}

/// Drops every capability this process holds, the ambient ones too, so a
/// program it runs next starts with none. The service holds CAP_SETUID and
/// CAP_SETGID; no command may keep them.
#[cfg(target_os = "linux")]
pub fn drop_caps() -> std::io::Result<()> {
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
    // SAFETY: prctl and capset with structs laid out as the kernel's.
    unsafe {
        if libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        ) != 0
        {
            let e = std::io::Error::last_os_error();
            // A kernel before 4.3 has no ambient set, so nothing to clear.
            if e.raw_os_error() != Some(libc::EINVAL) {
                return Err(e);
            }
        }
        let h = Header {
            version: V3,
            pid: 0,
        };
        let none = [
            Data {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
            Data {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
        ];
        if libc::syscall(libc::SYS_capset, &h as *const Header, none.as_ptr()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// The node's own file access as `account`, on this thread only: the `fs`
/// actions of a center and the path checks of its calls see what the
/// account sees, and files they make belong to it. The file system ids and
/// the groups are the thread's own in Linux (the C library's calls change
/// every thread's, so plain system calls are used); the service's
/// CAP_SETUID and CAP_SETGID allow the change. Dropped, the thread is the
/// node's again. It is not `Send`, so it cannot be held across an `.await`
/// and leak to another task.
#[cfg(target_os = "linux")]
pub struct FsAs {
    uid: u32,
    gid: u32,
    groups: Vec<libc::gid_t>,
    _thread: std::marker::PhantomData<*const ()>,
}

#[cfg(target_os = "linux")]
impl FsAs {
    pub fn new(account: &Account) -> std::io::Result<FsAs> {
        let last = std::io::Error::last_os_error;
        // SAFETY: getgroups into a buffer of the size it asked for, and plain
        // system calls with integers or that buffer.
        unsafe {
            let n = libc::getgroups(0, std::ptr::null_mut());
            if n < 0 {
                return Err(last());
            }
            let mut groups = vec![0; n as usize];
            if libc::getgroups(n, groups.as_mut_ptr()) < 0 {
                return Err(last());
            }
            let me = FsAs {
                uid: libc::geteuid(),
                gid: libc::getegid(),
                groups,
                _thread: std::marker::PhantomData,
            };
            let mut want = account.groups.clone();
            if want.is_empty() {
                want.push(account.gid);
            }
            if libc::syscall(libc::SYS_setgroups, want.len(), want.as_ptr()) != 0 {
                return Err(last());
            }
            // setfsuid answers with the old id whether it worked or not; a
            // second call with an impossible id reads the one in force.
            libc::setfsgid(account.gid);
            libc::setfsuid(account.uid);
            if libc::setfsuid(u32::MAX) as u32 != account.uid
                || libc::setfsgid(u32::MAX) as u32 != account.gid
            {
                drop(me);
                return Err(std::io::Error::from_raw_os_error(libc::EPERM));
            }
            Ok(me)
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for FsAs {
    fn drop(&mut self) {
        // SAFETY: as in `new`, back to the ids and groups read there.
        unsafe {
            libc::setfsuid(self.uid);
            libc::setfsgid(self.gid);
            libc::syscall(libc::SYS_setgroups, self.groups.len(), self.groups.as_ptr());
        }
    }
}

/// Signals the process group `pgid` as `uid`: the service's own user may
/// not signal another account's processes, and it has no CAP_KILL. A child
/// process takes the account as its effective id only and sends the
/// signal, so the node itself keeps its ids, and the account's processes
/// cannot signal the child (its real and saved ids stay the node's). The
/// node waits for it a short while at most.
#[cfg(target_os = "linux")]
pub fn kill_as(uid: u32, pgid: u32, sig: libc::c_int) {
    signal_as(uid, -(pgid as libc::pid_t), sig);
}

/// [`kill_as`] for the one process `pid`: a command's process that left
/// its process group but not its cgroup (crate::cgroup).
#[cfg(target_os = "linux")]
pub fn kill_pid_as(uid: u32, pid: u32, sig: libc::c_int) {
    if pid != 0 {
        signal_as(uid, pid as libc::pid_t, sig);
    }
}

/// `kill(target, sig)` from a child that has `uid` as its effective id.
#[cfg(target_os = "linux")]
fn signal_as(uid: u32, target: libc::pid_t, sig: libc::c_int) {
    // SAFETY: the child of a process with many threads makes plain system
    // calls only and leaves with _exit.
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            if libc::syscall(libc::SYS_setresuid, u32::MAX, uid, u32::MAX) == 0 {
                libc::kill(target, sig);
            }
            libc::_exit(0);
        }
        if pid > 0 {
            let until = std::time::Instant::now() + std::time::Duration::from_secs(2);
            let mut status = 0;
            while libc::waitpid(pid, &mut status, libc::WNOHANG) == 0
                && std::time::Instant::now() < until
            {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(name: &str, uid: u32) -> Account {
        Account {
            name: name.into(),
            uid,
            gid: uid,
            comment: String::new(),
            home: format!("/home/{name}").into(),
            groups: vec![uid],
        }
    }

    fn db(name: &str) -> Result<Option<Account>, String> {
        Ok(match name {
            "alice" => Some(account("alice", 1000)),
            "root" => Some(account("root", 0)),
            "toor" => Some(account("toor", 0)),
            "nerve" => Some(account("nerve", 990)),
            RUN_USER => Some(Account {
                comment: RUN_MARK.into(),
                ..account(RUN_USER, 989)
            }),
            _ => None,
        })
    }

    /// The installed service runs a command as `nerve-run`, or as the owner
    /// when the pairing says so; a node run by hand runs every command as
    /// itself.
    #[cfg(not(windows))]
    #[test]
    fn the_account_of_the_commands() {
        let run = |as_owner, owner| for_commands(as_owner, owner, 990, true, true, db);
        let a = run(false, Some("alice")).unwrap().unwrap();
        assert_eq!((a.name.as_str(), a.uid), (RUN_USER, 989));
        let a = run(true, Some("alice")).unwrap().unwrap();
        assert_eq!((a.name.as_str(), a.uid), ("alice", 1000));
        // No owner: only what runs as the owner is refused.
        assert_eq!(run(true, None).unwrap_err(), NO_OWNER);
        assert_eq!(run(false, None).unwrap().unwrap().name, RUN_USER);
        // A node run by hand runs every command as itself.
        assert_eq!(
            for_commands(false, None, 1000, false, false, db).unwrap(),
            None
        );
        assert_eq!(
            for_commands(true, Some("alice"), 0, false, true, db).unwrap(),
            None
        );
        // Root as the owner (which install made it only after root
        // confirmed it) runs what runs as the owner; folder and allowlist
        // mode stay nerve-run's.
        let a = run(true, Some("root")).unwrap().unwrap();
        assert_eq!((a.name.as_str(), a.uid), ("root", 0));
        assert_eq!(run(false, Some("root")).unwrap().unwrap().name, RUN_USER);
        // Refused: an owner that does not exist, the node's own user, an
        // account with uid 0 other than root, and a `nerve-run` that install
        // did not make.
        let e = run(true, Some("bob")).unwrap_err();
        assert!(e.contains("bob") && e.contains("does not exist"), "{e}");
        for who in ["nerve", "toor"] {
            let e = run(true, Some(who)).unwrap_err();
            assert!(e.contains("node's own user or root"), "{e}");
        }
        let e = for_commands(true, Some("root"), 0, true, true, db).unwrap_err();
        assert!(e.contains("node's own user or root"), "{e}");
        let fake = |name: &str| {
            Ok(match name {
                RUN_USER => Some(account(RUN_USER, 989)),
                _ => None,
            })
        };
        let e = for_commands(false, None, 990, true, true, fake).unwrap_err();
        assert!(e.contains("not made by `install`"), "{e}");
        let none = |_: &str| Ok(None);
        let e = for_commands(false, None, 990, true, true, none).unwrap_err();
        assert!(e.contains("install` makes it again"), "{e}");
    }

    /// Windows keeps every command under the owner's account.
    #[cfg(windows)]
    #[test]
    fn every_command_runs_as_the_owner_on_windows() {
        for as_owner in [false, true] {
            let a = for_commands(as_owner, Some("alice"), 990, true, true, db).unwrap();
            assert_eq!(a.unwrap().name, "alice");
            let e = for_commands(as_owner, None, 990, true, true, db).unwrap_err();
            assert_eq!(e, NO_OWNER);
        }
    }

    /// The installed node started without its two capabilities (by hand, as
    /// `nerve`) runs no command, and never as itself.
    #[test]
    fn the_installed_node_without_its_capabilities_runs_nothing() {
        for as_owner in [false, true] {
            let e = for_commands(as_owner, Some("alice"), 990, true, false, db).unwrap_err();
            let start = if cfg!(windows) {
                "Start-Service nerve-node"
            } else {
                "systemctl start"
            };
            assert!(e.contains(start), "{e}");
        }
    }

    #[test]
    fn the_built_in_folders_are_the_temporary_ones_and_the_home() {
        let b = built_in(Path::new(RUN_HOME));
        let paths: Vec<&str> = b.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["/tmp", "/var/tmp", RUN_HOME]);
        assert!(
            b.iter()
                .all(|f| f.access.read && f.access.write && f.access.execute)
        );
    }

    #[test]
    fn names_and_passwd_lines() {
        let a = parse_passwd("alice:x:1000:1001:Alice A,,,:/home/alice:/bin/bash\n").unwrap();
        assert_eq!(
            a,
            Account {
                name: "alice".into(),
                uid: 1000,
                gid: 1001,
                comment: "Alice A,,,".into(),
                home: "/home/alice".into(),
                groups: vec![1001],
            }
        );
        assert!(parse_passwd("alice:x:y:1").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn reaches_follows_the_permission_bits() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("config");
        let key = dir.join("keys/lab.key");
        nerve_transport::files::write_private(&key, b"key").unwrap();
        let set = |p: &Path, m: u32| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap()
        };
        set(&dir, 0o700);
        // SAFETY: plain getters.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let owner = Account {
            gid,
            groups: vec![gid],
            ..account("me", uid)
        };
        let other = account("other", uid.wrapping_add(4242));
        assert!(reaches(&key, &owner));
        assert!(!reaches(&key, &other));
        assert!(!reaches(&dir, &other));
        assert!(reaches(&key, &account("root", 0)));
        // A folder open to others lets them in, down to a key that is too.
        set(&dir, 0o711);
        set(&dir.join("keys"), 0o711);
        assert!(!reaches(&key, &other));
        set(&key, 0o604);
        assert!(reaches(&key, &other));
        assert!(!reaches(&dir.join("none"), &other));
    }

    /// The check a command makes as its account before it runs: the
    /// kernel's answer for this process.
    #[cfg(target_os = "linux")]
    #[test]
    fn out_of_reach_asks_the_kernel() {
        use std::os::unix::fs::PermissionsExt;
        if nerve_transport::net::euid() == 0 {
            return; // root reaches every folder
        }
        let d = tempfile::tempdir().unwrap();
        let own = d.path().join("state");
        std::fs::create_dir(&own).unwrap();
        let c = vec![std::ffi::CString::new(own.to_str().unwrap()).unwrap()];
        let e = out_of_reach(&c).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(IN_REACH));
        std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o000)).unwrap();
        out_of_reach(&c).unwrap();
        std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}
