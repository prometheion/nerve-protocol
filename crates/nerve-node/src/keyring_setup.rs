//! A system keyring for a node that keeps its keys there
//! (`machine.secret_storage = "keyring"`, docs/user/config.md).
//!
//! The node never falls back to files: where no keyring answers, it refuses.
//! On a Linux without a desktop there is usually none, so `setup` (and
//! `install`, run in a terminal) offers to install one, and does so only on
//! an explicit yes: GNOME Keyring through the distribution's package
//! manager, a session of the node's user that outlives logins and reboots
//! (`loginctl enable-linger`), in which D-Bus starts the keyring when the
//! node asks, and a login keyring that opens without a password. Where the
//! node's user has a desktop session, nothing is offered: such a keyring
//! would become the default of every program in that session.
//!
//! The kernel keyring (keyutils) needs no daemon, but its keys are gone
//! after a reboot, and with them the node's: so it is not offered. A keyring
//! that opens without anyone typing a password keeps its secrets unencrypted
//! on disk; the question says so.
//!
//! Whether a keyring answers is asked in a process of its own
//! ([`PROBE_ARG`]): the keyring crate keeps its first connection, or its
//! first failure, for the life of a process, and `install` runs as root but
//! must ask the keyring of the node's user.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use crate::service::Account;

/// The hidden first argument that makes `nerve-node` check the system
/// keyring of the user it runs as and exit: 0 when it answers.
pub const PROBE_ARG: &str = "__keyring-probe";

/// The entry the probe writes, reads and deletes.
const PROBE_ACCOUNT: &str = "probe";

/// `nerve-node __keyring-probe`: stores, reads and deletes an entry; the
/// exit code says whether that worked, stderr why not.
pub fn probe_main() -> i32 {
    let value = nerve_transport::keys::random_token(16);
    let r = (|| {
        crate::secrets::store::set(PROBE_ACCOUNT, &value)?;
        let back = crate::secrets::store::get(PROBE_ACCOUNT)?;
        crate::secrets::store::delete(PROBE_ACCOUNT)?;
        if back.as_deref() == Some(value.as_str()) {
            Ok(())
        } else {
            Err("an entry written to it does not read back".to_string())
        }
    })();
    match r {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

/// How a keyring would be installed here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    /// The package manager's commands, run as root in this order, each
    /// program by its absolute path.
    pub commands: Vec<Vec<String>>,
    /// `loginctl`, by its absolute path.
    pub loginctl: String,
}

/// The folders the programs of the root step are taken from, in this
/// order, and the `PATH` they run with: the system's own, never one the
/// caller or the service's environment names.
pub const SYSTEM_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// The program `name` in the folders of [`SYSTEM_PATH`], by its absolute
/// path.
pub fn system_program(name: &str) -> Option<PathBuf> {
    SYSTEM_PATH
        .split(':')
        .map(|d| Path::new(d).join(name))
        .find(|p| p.is_file())
}

impl Offer {
    /// The package commands for the package manager `find` finds (by its
    /// absolute path): apt (Debian, Ubuntu), dnf (Fedora, RHEL) or pacman
    /// (Arch), each installing GNOME Keyring and what it needs, nothing it
    /// only recommends. On Debian and Ubuntu the user's D-Bus session comes
    /// in a package of its own; the others have it already. `None` without
    /// one of them or without `loginctl`.
    pub fn for_system(find: impl Fn(&str) -> Option<PathBuf>) -> Option<Offer> {
        let loginctl = find("loginctl")?.display().to_string();
        let (program, cmds): (PathBuf, &[&[&str]]) = if let Some(p) = find("apt-get") {
            (
                p,
                &[
                    &["update"],
                    &[
                        "install",
                        "-y",
                        "--no-install-recommends",
                        "gnome-keyring",
                        "dbus-user-session",
                    ],
                ],
            )
        } else if let Some(p) = find("dnf") {
            (
                p,
                &[&[
                    "install",
                    "-y",
                    "--setopt=install_weak_deps=False",
                    "gnome-keyring",
                ]],
            )
        } else {
            (
                find("pacman")?,
                &[&["-S", "--needed", "--noconfirm", "gnome-keyring"]],
            )
        };
        let program = program.display().to_string();
        Some(Offer {
            commands: cmds
                .iter()
                .map(|c| {
                    std::iter::once(program.clone())
                        .chain(c.iter().map(|s| s.to_string()))
                        .collect()
                })
                .collect(),
            loginctl,
        })
    }

    /// The command that keeps `who`'s session after a reboot.
    fn linger(&self, who: &str) -> Vec<String> {
        vec![self.loginctl.clone(), "enable-linger".into(), who.into()]
    }

    /// The commands as the question shows them.
    fn shown(&self, who: &str) -> String {
        self.commands
            .iter()
            .chain([&self.linger(who)])
            .map(|c| format!("`{}`", c.join(" ")))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// The system keyring as `setup` and `install` see it.
pub trait Keyring {
    /// `Ok` when the system keyring of `who` answers: an entry is stored,
    /// read back and deleted. Else why not.
    fn check(&self, who: &Account) -> Result<(), String>;
    /// How a keyring would be installed here; `None` where nerve-node cannot
    /// install one (not Linux, or no package manager it knows).
    fn offer(&self) -> Option<Offer>;
    /// Whether `who` has a graphical session: its desktop brings or chooses
    /// the keyring, and a password-less one of nerve-node's would become
    /// the default of every program there.
    fn desktop(&self, who: &Account) -> bool;
    /// Installs and starts a keyring for `who` as `offer` says.
    fn install(&self, offer: &Offer, who: &Account, out: &mut dyn Write) -> Result<(), String>;
}

/// Makes sure the system keyring of `who` answers: when it does not, says
/// why and, where nerve-node can install one, `who` has no desktop and
/// `input` is a terminal's, offers to. Anything but a yes leaves the
/// refusal. `Ok(true)` when a keyring was installed now.
pub fn ensure(
    keyring: &dyn Keyring,
    who: &Account,
    input: Option<&mut dyn BufRead>,
    out: &mut dyn Write,
) -> Result<bool, String> {
    let Err(why) = keyring.check(who) else {
        return Ok(false);
    };
    let name = &who.name;
    let refusal = format!(
        "no system keyring answers for {name} ({why}); with machine.secret_storage = \"keyring\" the node keeps its keys there and nowhere else"
    );
    let Some(offer) = keyring.offer() else {
        return Err(refusal);
    };
    if keyring.desktop(who) {
        return Err(format!(
            "{refusal}; {name} has a desktop session, so start the keyring of that desktop (GNOME Keyring, or KWallet with its Secret Service on)"
        ));
    }
    let Some(input) = input else {
        return Err(format!(
            "{refusal}; `nerve-node config set machine.secret_storage keyring`, run in a terminal, offers to install one"
        ));
    };
    let store = who.home.join(".local/share/keyrings");
    let _ = writeln!(out, "No system keyring answers for {name}: {why}.");
    let _ = writeln!(
        out,
        "nerve-node can install GNOME Keyring: {}, so that {name} keeps a session after a reboot, and a login keyring for {name} that opens without a password.",
        offer.shown(name)
    );
    if is_node_account(who) {
        let _ = writeln!(
            out,
            "Where this machine's /etc/environment names another user's runtime folder or XDG folders (as a CI runner's does), keyring and bus of {name} would start in those; then nerve-node also writes {SESSION_GENERATOR}, which gives {name}'s session its own at every start."
        );
    }
    let _ = writeln!(
        out,
        "Without a desktop nobody types a password when the machine starts, so this keyring keeps the keys unencrypted in {}, readable by {name} as the key files are; the node keeps centers out of it as it does out of the key files, except a command you let a center run outside folder mode that asks the keyring itself (secret-tool and the like). It becomes the default keyring of {name}: any other program of {name} that keeps a secret in the system keyring keeps it there, unencrypted too.",
        store.display()
    );
    // The end of the input, or no answer, is a no.
    let yes = crate::cli::ask(input, out, "Install it now? [y/N] ").unwrap_or_default();
    if !matches!(yes.as_str(), "y" | "Y" | "yes") {
        return Err(refusal);
    }
    keyring.install(&offer, who, out)?;
    keyring
        .check(who)
        .map_err(|e| format!("the keyring is installed, but it does not answer for {name}: {e}"))?;
    let _ = writeln!(out, "the system keyring answers for {name}");
    Ok(true)
}

/// The account this process runs as, from the system's account database.
pub fn me() -> Result<Account, String> {
    #[cfg(unix)]
    {
        let uid = nerve_transport::net::euid();
        let o = std::process::Command::new("getent")
            .args(["passwd", &uid.to_string()])
            .output()
            .map_err(|e| format!("getent: {e}"))?;
        let line = String::from_utf8_lossy(&o.stdout);
        crate::account::parse_passwd(&line)
            .filter(|_| o.status.success())
            .ok_or_else(|| format!("there is no account with the uid {uid}"))
    }
    #[cfg(not(unix))]
    {
        let name = std::env::var("USERNAME").unwrap_or_default();
        Ok(Account {
            name,
            uid: 0,
            gid: 0,
            comment: String::new(),
            home: crate::paths::home_dir(),
            groups: Vec::new(),
        })
    }
}

/// This machine's keyring, asked by `exe`, the program the node's user can
/// run: the installed one on the installed node.
pub struct HostKeyring {
    pub exe: PathBuf,
}

impl HostKeyring {
    /// Asked by this program.
    pub fn this_program() -> HostKeyring {
        HostKeyring {
            exe: std::env::current_exe().unwrap_or_else(|_| PathBuf::from("nerve-node")),
        }
    }
}

impl Keyring for HostKeyring {
    fn check(&self, who: &Account) -> Result<(), String> {
        // In the session of `who`, never in the caller's: `install` runs as
        // root, and `setup` runs for its owner as the node's user, with
        // whatever session variables came with either.
        let mut c = as_account(&self.exe, who, !in_own_session(who));
        c.arg(PROBE_ARG);
        let o = c.output().map_err(|e| format!("the keyring probe: {e}"))?;
        if o.status.success() {
            return Ok(());
        }
        let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
        Err(if err.is_empty() {
            o.status.to_string()
        } else {
            err
        })
    }

    fn offer(&self) -> Option<Offer> {
        if !cfg!(target_os = "linux") {
            return None;
        }
        Offer::for_system(system_program)
    }

    fn desktop(&self, who: &Account) -> bool {
        // Setup run in that user's own session: its environment says so.
        // Under sudo it is someone else's.
        #[cfg(unix)]
        if who.uid == nerve_transport::net::euid()
            && std::env::var_os("SUDO_UID").is_none()
            && graphical_env(|k| std::env::var_os(k))
        {
            return true;
        }
        display_session(who)
    }

    fn install(&self, offer: &Offer, who: &Account, out: &mut dyn Write) -> Result<(), String> {
        for cmd in &offer.commands {
            let _ = writeln!(out, "running {}", cmd.join(" "));
            as_root(cmd)?;
        }
        let linger = offer.linger(&who.name);
        let _ = writeln!(out, "running {}", linger.join(" "));
        as_root(&linger)?;
        wait_for_session(who)?;
        if repair_session(who)? {
            let _ = writeln!(
                out,
                "set the session of {} to its own runtime folder, bus and XDG folders",
                who.name
            );
            // The manager of the node's user reads the same environment at
            // its next start.
            if is_node_account(who) {
                write_session_generator(who)?;
                let _ = writeln!(out, "wrote {SESSION_GENERATOR}");
            }
        }
        if make_login_keyring(who)? {
            let _ = writeln!(
                out,
                "made a login keyring for {} without a password",
                who.name
            );
            // A keyring daemon that started before the file was there does
            // not see it; D-Bus starts it again at the next question.
            let _ = std::process::Command::new("pkill")
                .args(["-U", &who.uid.to_string(), "-x", "gnome-keyring-d"])
                .status();
        }
        Ok(())
    }
}

/// Whether logind has a graphical session of `who` (its display session,
/// when that is of type x11, wayland or mir).
fn display_session(who: &Account) -> bool {
    let loginctl = |args: &[&str]| {
        std::process::Command::new("loginctl")
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    };
    let uid = who.uid.to_string();
    let display = loginctl(&["show-user", &uid, "--property=Display", "--value"]);
    !display.is_empty()
        && graphical_type(&loginctl(&[
            "show-session",
            &display,
            "--property=Type",
            "--value",
        ]))
}

/// Whether `who` is the account `nerve-node install` made for the installed
/// node (the service user, by its name and the comment `install` gives it).
/// Only its session is the node's to put right: a node you run yourself runs
/// in your own, with your own XDG folders, wherever they are.
pub fn is_node_account(who: &Account) -> bool {
    who.name == crate::service::USER && who.comment == crate::service::USER_MARK
}

/// Whether an environment is a graphical session's.
pub fn graphical_env(var: impl Fn(&str) -> Option<std::ffi::OsString>) -> bool {
    let set = |k: &str| var(k).is_some_and(|v| !v.is_empty());
    set("DISPLAY")
        || set("WAYLAND_DISPLAY")
        || set("XDG_CURRENT_DESKTOP")
        || var("XDG_SESSION_TYPE").is_some_and(|t| graphical_type(&t.to_string_lossy()))
}

/// Whether a logind session type is a graphical one.
fn graphical_type(t: &str) -> bool {
    matches!(t, "x11" | "wayland" | "mir")
}

/// `cmd` (its program by an absolute path) as a step that runs as root
/// starts it: with a fixed `PATH` ([`SYSTEM_PATH`]) and the package
/// managers' settings for running without questions, and nothing else of
/// this process's environment, in `/`, with no input. So nothing of the
/// caller's (its folders, its input, the service's `PATH`) reaches it.
fn pinned(cmd: &[String]) -> Result<std::process::Command, String> {
    let (program, args) = cmd.split_first().ok_or("an empty command")?;
    if !Path::new(program).is_absolute() {
        return Err(format!("{program} is not an absolute path"));
    }
    let mut c = std::process::Command::new(program);
    c.args(args)
        .env_clear()
        .env("PATH", SYSTEM_PATH)
        .env("HOME", "/root")
        .env("LC_ALL", "C")
        .env("DEBIAN_FRONTEND", "noninteractive")
        .current_dir("/")
        .stdin(std::process::Stdio::null());
    Ok(c)
}

/// Runs a system command ([`pinned`]) as root: directly when this process
/// is root; on the installed node, where setup keeps root as its saved id
/// (run with sudo) or runs for the owner with the service's CAP_SETUID and
/// CAP_SETGID (crate::owner), as root by those; elsewhere through `sudo`,
/// which asks for the password at the terminal.
fn as_root(cmd: &[String]) -> Result<(), String> {
    let mut c;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        let (mut r, mut e, mut s) = (0, 0, 0);
        // SAFETY: getresuid writes the three ids it is given.
        unsafe { libc::getresuid(&mut r, &mut e, &mut s) };
        if e == 0 {
            c = pinned(cmd)?;
        } else if s == 0 || crate::account::can_switch() {
            c = pinned(cmd)?;
            // SAFETY: plain system calls between fork and exec.
            unsafe {
                c.pre_exec(|| {
                    // The user first: as root again the process has its
                    // capabilities in effect for the group and the groups.
                    if libc::setresuid(0, 0, 0) != 0
                        || libc::setresgid(0, 0, 0) != 0
                        || libc::setgroups(0, std::ptr::null()) != 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        } else {
            let sudo = system_program("sudo").ok_or("there is no sudo to run it as root")?;
            let mut with = vec![sudo.display().to_string(), "--".into()];
            with.extend(cmd.iter().cloned());
            c = pinned(&with)?;
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        c = pinned(cmd)?;
    }
    let status = c.status().map_err(|e| format!("{}: {e}", cmd.join(" ")))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{} failed: {status}", cmd.join(" ")))
    }
}

/// Waits until the session of `who`, which linger started, has its D-Bus
/// and its service manager answers.
fn wait_for_session(who: &Account) -> Result<(), String> {
    let bus = PathBuf::from(format!("/run/user/{}/bus", who.uid));
    let mut manager = String::new();
    for _ in 0..80 {
        if bus.exists() {
            // The socket is there as soon as the manager listens; the
            // manager answers a moment later.
            match user_systemctl(who, &["show-environment"]) {
                Ok(_) | Err(None) => return Ok(()),
                Err(Some(why)) => manager = why,
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    if bus.exists() {
        return Err(format!(
            "the session of {} has a D-Bus at {}, but its service manager does not answer: {manager}",
            who.name,
            bus.display()
        ));
    }
    Err(format!(
        "the session of {} has no D-Bus at {} (on Debian and Ubuntu it comes with dbus-user-session)",
        who.name,
        bus.display()
    ))
}

/// The variables that tell a program of `who` where its session is: the
/// runtime folder and the bus in it.
fn session_vars(who: &Account) -> Vec<(&'static str, String)> {
    if !cfg!(target_os = "linux") {
        return Vec::new();
    }
    let run = format!("/run/user/{}", who.uid);
    vec![
        ("DBUS_SESSION_BUS_ADDRESS", format!("unix:path={run}/bus")),
        ("XDG_RUNTIME_DIR", run),
    ]
}

/// The whole environment of a program that asks the keyring of `who`: the
/// session `who` has ([`session_vars`]), its home and name, the system's
/// `PATH`, and nothing of the process that starts it.
pub fn session_env(who: &Account) -> Vec<(&'static str, String)> {
    let mut env = vec![
        ("PATH", SYSTEM_PATH.to_string()),
        ("HOME", who.home.display().to_string()),
        ("USER", who.name.clone()),
        ("LOGNAME", who.name.clone()),
    ];
    env.extend(session_vars(who));
    env
}

/// Whether `who` is the one who started this process, in the session this
/// process's environment names: not an account root switched to, and not the
/// node's user running `setup` for its owner (crate::owner), whose
/// environment is the node's, not the owner's.
fn in_own_session(who: &Account) -> bool {
    #[cfg(unix)]
    {
        who.uid == nerve_transport::net::euid()
            && std::env::var_os("SUDO_UID").is_none()
            && crate::owner::owner_running().is_none()
    }
    #[cfg(not(unix))]
    {
        let _ = who;
        true
    }
}

/// `program` as `who`. As root it runs as `who` (std drops root's other
/// groups along with the ids), in `/`. With `clean` it gets
/// [`session_env`] and nothing else: a session bus or runtime folder of the
/// caller, which is another user's (the owner's `/run/user/<uid>`), never
/// reaches the keyring of `who`.
fn as_account(
    program: impl AsRef<std::ffi::OsStr>,
    who: &Account,
    clean: bool,
) -> std::process::Command {
    let mut c = std::process::Command::new(program);
    #[cfg(unix)]
    if nerve_transport::net::euid() == 0 && who.uid != 0 {
        use std::os::unix::process::CommandExt;
        c.uid(who.uid).gid(who.gid).current_dir("/");
    }
    if clean {
        c.env_clear().envs(session_env(who));
    }
    c
}

/// `systemctl --user args` in the session of `who`, with the environment of
/// that session ([`as_account`]): its output, or the reason it failed;
/// `Err(None)` where there is no `systemctl`.
fn user_systemctl(who: &Account, args: &[&str]) -> Result<String, Option<String>> {
    let systemctl = system_program("systemctl").ok_or(None)?;
    let o = as_account(&systemctl, who, true)
        .arg("--user")
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| Some(format!("systemctl: {e}")))?;
    if o.status.success() {
        return Ok(String::from_utf8_lossy(&o.stdout).into_owned());
    }
    Err(Some(format!(
        "{}: {}",
        o.status,
        String::from_utf8_lossy(&o.stderr).trim()
    )))
}

/// What the service manager of a session has wrong, in the
/// `show-environment` text `environment`: the variables of
/// [`session_vars`] of `who` that name another runtime folder or bus, as
/// `NAME=value` to set. The manager hands its environment to everything it
/// starts, the session bus and the keyring behind it. It can get another
/// user's from the system-wide environment of the login (`/etc/environment`
/// through PAM, as on a CI runner whose image names its own user's), and
/// still listens on its own sockets.
pub fn wrong_session_vars(environment: &str, who: &Account) -> Vec<String> {
    session_vars(who)
        .into_iter()
        .filter(|(k, v)| {
            environment.lines().any(|l| {
                l.strip_prefix(k)
                    .and_then(|r| r.strip_prefix('='))
                    .is_some_and(|x| x != v)
            })
        })
        .map(|(k, v)| format!("{k}={v}"))
        .collect()
}

/// The per-user folders the XDG specification names, with the default of
/// each below a home.
const XDG_USER_DIRS: [(&str, &str); 4] = [
    ("XDG_CONFIG_HOME", ".config"),
    ("XDG_DATA_HOME", ".local/share"),
    ("XDG_CACHE_HOME", ".cache"),
    ("XDG_STATE_HOME", ".local/state"),
];

/// The variables of [`XDG_USER_DIRS`] that the `show-environment` text
/// `environment` sets to a folder outside the home of `who` (the same
/// system-wide environment as in [`wrong_session_vars`] can name another
/// user's `~/.config`), as `NAME=value` to set to the default in the home of
/// `who`. They are set, not unset: what the login's environment generators
/// give the manager stays in `show-environment` after an `unset-environment`,
/// and GNOME Keyring looks for its keyrings in `XDG_DATA_HOME`.
pub fn wrong_user_dirs(environment: &str, who: &Account) -> Vec<String> {
    XDG_USER_DIRS
        .into_iter()
        .filter(|(k, _)| {
            environment.lines().any(|l| {
                l.strip_prefix(k)
                    .and_then(|r| r.strip_prefix('='))
                    .is_some_and(|v| !v.is_empty() && !Path::new(v).starts_with(&who.home))
            })
        })
        .map(|(k, d)| format!("{k}={}", who.home.join(d).display()))
        .collect()
}

/// The units of a session that start with its environment and are started
/// again when it changes, those of them that `exists`: the session bus and
/// GNOME Keyring, which has one name in version 40 (Ubuntu 22.04) and
/// another since 41.
fn units_to_restart(exists: impl Fn(&str) -> bool) -> Vec<&'static str> {
    [
        "dbus.service",
        "gnome-keyring-daemon.service",
        "gnome-keyring.service",
    ]
    .into_iter()
    .filter(|u| exists(u))
    .collect()
}

/// What is wrong in the manager's `environment`, as `NAME=value` to set: the
/// runtime folder and bus ([`wrong_session_vars`]) of any account, the XDG
/// folders ([`wrong_user_dirs`]) only of the node's own ([`is_node_account`]):
/// another account keeps those where it likes.
fn session_fixes(environment: &str, who: &Account) -> Vec<String> {
    let mut wrong = wrong_session_vars(environment, who);
    if is_node_account(who) {
        wrong.extend(wrong_user_dirs(environment, who));
    }
    wrong
}

/// Puts the environment of the session of `who` right in its service manager
/// ([`wrong_session_vars`], [`wrong_user_dirs`]) and starts its session bus
/// and keyring again, which began with the wrong one. `Ok(true)` when it had
/// to. It lasts as long as the manager runs: the next one reads the same
/// system-wide environment ([`write_session_generator`] is what keeps it).
fn repair_session(who: &Account) -> Result<bool, String> {
    let Ok(environment) = user_systemctl(who, &["show-environment"]) else {
        return Ok(false);
    };
    let wrong = session_fixes(&environment, who);
    if wrong.is_empty() {
        return Ok(false);
    }
    let fail = |what: &str, e: Option<String>| {
        format!("{what} for {} failed: {}", who.name, e.unwrap_or_default())
    };
    let mut set = vec!["set-environment"];
    set.extend(wrong.iter().map(String::as_str));
    user_systemctl(who, &set).map_err(|e| fail("systemctl --user set-environment", e))?;
    // The bus starts at the first program that asks, and the keyring at the
    // bus's: they may be up already. try-restart leaves a unit that does
    // not run alone; one that does not exist is not asked for.
    let mut restart = vec!["try-restart"];
    restart.extend(units_to_restart(|u| {
        user_systemctl(who, &["show", "--property=LoadState", "--value", u])
            .is_ok_and(|s| s.trim() == "loaded")
    }));
    if restart.len() > 1 {
        user_systemctl(who, &restart).map_err(|e| fail("systemctl --user try-restart", e))?;
    }
    Ok(true)
}

/// Whether the node puts the session of `who` right when it starts: only the
/// installed node's own account ([`is_node_account`]), and never a session
/// with a desktop (`graphical`: the node's environment, or logind's display
/// session of `who`), which is the desktop's.
#[cfg(target_os = "linux")]
fn start_repair_applies(who: &Account, graphical: impl Fn() -> bool) -> bool {
    is_node_account(who) && !graphical_env(|k| std::env::var_os(k)) && !graphical()
}

/// Before the node first asks its keyring: puts the session of the node's
/// user right ([`repair_session`]) when the system-wide environment of the
/// login gave its service manager another user's folders again (a reboot, a
/// restart of the session). Where the user lingers, the session may still be
/// coming up, and is waited for. `Ok(true)` when it had to.
pub fn repair_for_start() -> Result<bool, String> {
    #[cfg(target_os = "linux")]
    {
        let who = me()?;
        if !start_repair_applies(&who, || display_session(&who)) {
            return Ok(false);
        }
        let lingers = Path::new("/var/lib/systemd/linger")
            .join(&who.name)
            .exists();
        if lingers {
            wait_for_session(&who)?;
        } else if !Path::new(&format!("/run/user/{}/bus", who.uid)).exists() {
            return Ok(false);
        }
        repair_session(&who)
    }
    #[cfg(not(target_os = "linux"))]
    Ok(false)
}

/// The folder of the user environment generators, which every user's
/// service manager runs, in lexical order, as that user.
const GENERATORS: &str = "/etc/systemd/user-environment-generators";

/// The generator that keeps the session of the node's user right.
pub const SESSION_GENERATOR: &str = "/etc/systemd/user-environment-generators/99-nerve-session";

/// The text of the generator for `who`: it prints, for the session of `who`
/// and no other, its runtime folder, bus and XDG folders. It runs after
/// `30-systemd-environment-d-generator`, which reads `/etc/environment`, so
/// what it prints wins, at every start of the manager.
pub fn session_generator_text(who: &Account) -> String {
    let id = system_program("id").unwrap_or_else(|| PathBuf::from("/usr/bin/id"));
    let mut text = format!(
        "#!/bin/sh\n# Written by `nerve-node setup`; `nerve-node uninstall` removes it.\n# The session of {name} keeps its own runtime folder, bus and XDG folders\n# where /etc/environment names another user's.\n[ \"$({id} -u)\" = \"{uid}\" ] || exit 0\n",
        name = who.name,
        uid = who.uid,
        id = id.display()
    );
    let mut vars = session_vars(who);
    vars.extend(XDG_USER_DIRS.map(|(k, d)| (k, who.home.join(d).display().to_string())));
    for (k, v) in vars {
        // In single quotes, a quote in a value ended and written again.
        text.push_str(&format!("echo '{k}={}'\n", v.replace('\'', r"'\''")));
    }
    text
}

/// What writes the generator: `sh -c` with this text, then the folder, the
/// file and its text. The umask is set here because the node's own is 0077
/// ([`crate::service::Layout::unit_text`]): a folder made with it would be
/// closed to the user whose manager has to read it, and the generator would
/// silently not run.
const WRITE_GENERATOR: &str = r#"umask 022 && mkdir -p "$1" && printf '%s' "$3" > "$2.new" && chmod 755 "$2.new" && mv -f "$2.new" "$2""#;

/// Writes [`SESSION_GENERATOR`] as root, so that the session of `who` is
/// right again at every start of its manager.
fn write_session_generator(who: &Account) -> Result<(), String> {
    let sh = system_program("sh").ok_or("there is no sh")?;
    as_root(&[
        sh.display().to_string(),
        "-c".into(),
        WRITE_GENERATOR.into(),
        "nerve-node".into(),
        GENERATORS.into(),
        SESSION_GENERATOR.into(),
        session_generator_text(who),
    ])
}

/// The login keyring GNOME Keyring opens without a password: its plain text
/// format, with no item yet. A keyring that is there already is left as it
/// is. `Ok(true)` when it was made.
pub fn make_login_keyring(who: &Account) -> Result<bool, String> {
    let dir = who.home.join(".local/share/keyrings");
    let file = dir.join("login.keyring");
    if file.exists() {
        return Ok(false);
    }
    // Written as `who`, so a link in that home leads nowhere `who` could
    // not write anyway.
    #[cfg(target_os = "linux")]
    let _as = (nerve_transport::net::euid() == 0 && who.uid != 0)
        .then(|| crate::account::FsAs::new(who))
        .transpose()
        .map_err(|e| format!("cannot write as {}: {e}", who.name))?;
    let at = |p: &Path, e: std::io::Error| format!("{}: {e}", p.display());
    nerve_transport::files::create_private_dir(&dir).map_err(|e| at(&dir, e))?;
    nerve_transport::files::write_private(&file, LOGIN_KEYRING.as_bytes())
        .map_err(|e| at(&file, e))?;
    let default = dir.join("default");
    if !default.exists() {
        nerve_transport::files::write_private(&default, b"login").map_err(|e| at(&default, e))?;
    }
    Ok(true)
}

/// An empty keyring named `login` in GNOME Keyring's plain format: no
/// password, never locked.
const LOGIN_KEYRING: &str = "[keyring]
display-name=login
ctime=0
mtime=0
lock-on-idle=false
lock-after=false
";

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    /// A keyring that answers once it is installed, and records what was
    /// done.
    pub struct FakeKeyring {
        pub answers: Cell<bool>,
        pub offer: Option<Offer>,
        pub desktop: bool,
        pub installed: RefCell<Vec<String>>,
    }

    impl FakeKeyring {
        pub fn new(answers: bool) -> FakeKeyring {
            FakeKeyring {
                answers: Cell::new(answers),
                offer: Offer::for_system(found(&["apt-get", "loginctl"])),
                desktop: false,
                installed: RefCell::new(Vec::new()),
            }
        }
    }

    impl Keyring for FakeKeyring {
        fn check(&self, _who: &Account) -> Result<(), String> {
            if self.answers.get() {
                Ok(())
            } else {
                Err("no Secret Service".into())
            }
        }

        fn offer(&self) -> Option<Offer> {
            self.offer.clone()
        }

        fn desktop(&self, _who: &Account) -> bool {
            self.desktop
        }

        fn install(
            &self,
            offer: &Offer,
            who: &Account,
            _out: &mut dyn Write,
        ) -> Result<(), String> {
            self.installed.borrow_mut().push(format!(
                "{} for {}",
                offer.shown(&who.name),
                who.name
            ));
            self.answers.set(true);
            // The test keyring answers as the real one would now.
            crate::secrets::store::set_unreachable(false);
            Ok(())
        }
    }

    /// A `find` for [`Offer::for_system`] that finds `names` in /usr/bin.
    pub fn found(names: &'static [&'static str]) -> impl Fn(&str) -> Option<PathBuf> {
        // Written whole, so that it reads the same on Windows.
        move |p| {
            names
                .contains(&p)
                .then(|| PathBuf::from(format!("/usr/bin/{p}")))
        }
    }

    pub fn nerve(home: &Path) -> Account {
        Account {
            name: "nerve".into(),
            uid: 990,
            gid: 990,
            comment: String::new(),
            home: home.to_path_buf(),
            groups: vec![990],
        }
    }

    fn run(k: &FakeKeyring, typed: Option<&str>) -> (Result<bool, String>, String) {
        let mut out = Vec::new();
        let mut input = typed.map(|t| std::io::Cursor::new(t.as_bytes().to_vec()));
        let r = ensure(
            k,
            &nerve(Path::new("/var/lib/nerve")),
            input.as_mut().map(|i| i as &mut dyn BufRead),
            &mut out,
        );
        (r, String::from_utf8(out).unwrap())
    }

    #[test]
    fn a_keyring_that_answers_is_not_asked_about() {
        let k = FakeKeyring::new(true);
        let (r, out) = run(&k, Some(""));
        assert_eq!(r, Ok(false));
        assert!(out.is_empty(), "{out}");
    }

    /// The offer names each program by the absolute path it was found at,
    /// and installs the keyring's packages only, nothing they recommend.
    #[test]
    fn the_offer_names_each_package_manager_and_its_packages() {
        let apt = Offer::for_system(found(&["apt-get", "loginctl"])).unwrap();
        assert_eq!(
            apt.shown("nerve"),
            "`/usr/bin/apt-get update`, `/usr/bin/apt-get install -y --no-install-recommends gnome-keyring dbus-user-session`, `/usr/bin/loginctl enable-linger nerve`"
        );
        let dnf = Offer::for_system(found(&["dnf", "loginctl"])).unwrap();
        assert_eq!(
            dnf.commands,
            [[
                "/usr/bin/dnf",
                "install",
                "-y",
                "--setopt=install_weak_deps=False",
                "gnome-keyring"
            ]]
        );
        let pacman = Offer::for_system(found(&["pacman", "loginctl"])).unwrap();
        assert_eq!(
            pacman.commands,
            [[
                "/usr/bin/pacman",
                "-S",
                "--needed",
                "--noconfirm",
                "gnome-keyring"
            ]]
        );
        assert_eq!(Offer::for_system(found(&[])), None);
        assert_eq!(Offer::for_system(found(&["apt-get"])), None, "no loginctl");
        // The programs come from the system's own folders only.
        if cfg!(unix) {
            assert!(system_program("sh").is_some_and(|p| p.is_absolute()));
        }
        assert_eq!(system_program("no-such-program-of-nerve"), None);
    }

    /// The root step's command runs by its absolute path, with a fixed
    /// PATH and nothing else of this process's environment but the package
    /// managers' settings, in `/`, with no input (#142). Here it runs as
    /// this test's own account, which [`as_root`] does not change.
    #[cfg(unix)]
    #[test]
    fn a_root_step_runs_pinned() {
        let script = "pwd; readlink /proc/self/fd/0; env | cut -d= -f1 | sort | tr '\\n' ' '";
        let sh = system_program("sh").unwrap().display().to_string();
        // Spawned, not `output()`, which would give it no input itself.
        let o = pinned(&[sh, "-c".into(), script.into()])
            .unwrap()
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap()
            .wait_with_output()
            .unwrap();
        let text = String::from_utf8_lossy(&o.stdout);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "/", "{text}");
        if cfg!(target_os = "linux") {
            assert_eq!(lines[1], "/dev/null", "{text}");
        }
        let names: Vec<&str> = lines[2]
            .split_whitespace()
            .filter(|n| !["PWD", "SHLVL", "_", "OLDPWD"].contains(n))
            .collect();
        assert_eq!(
            names,
            ["DEBIAN_FRONTEND", "HOME", "LC_ALL", "PATH"],
            "{text}"
        );
        assert!(pinned(&["sh".into()]).is_err(), "a bare name is refused");
    }

    /// The environment a program that asks the keyring of `who` gets is
    /// made from `who`, not from the process that starts it.
    #[test]
    fn the_environment_of_the_keyring_is_the_users_own() {
        let who = Account {
            uid: 1234,
            ..nerve(Path::new("/var/lib/nerve"))
        };
        let env = session_env(&who);
        let get = |k: &str| env.iter().find(|(n, _)| *n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("HOME"), Some("/var/lib/nerve"));
        assert_eq!(get("USER"), Some("nerve"));
        assert_eq!(get("LOGNAME"), Some("nerve"));
        assert_eq!(get("PATH"), Some(SYSTEM_PATH));
        if cfg!(target_os = "linux") {
            assert_eq!(get("XDG_RUNTIME_DIR"), Some("/run/user/1234"));
            assert_eq!(
                get("DBUS_SESSION_BUS_ADDRESS"),
                Some("unix:path=/run/user/1234/bus")
            );
        }
    }

    /// The probe of the node's keyring, started for the owner's `setup` by a
    /// node whose own environment (or the caller's, through `sudo -E`) names
    /// another user's session, gets the node user's session and nothing
    /// else. Run again in a process of its own with that environment.
    #[cfg(unix)]
    #[test]
    fn a_callers_session_does_not_reach_the_keyrings_probe() {
        use std::os::unix::fs::PermissionsExt;
        // In no real path, user name or id of any host.
        const POISON: &str = "poisoned-session-4711";
        const NAME: &str =
            "keyring_setup::tests::a_callers_session_does_not_reach_the_keyrings_probe";
        let d = tempfile::tempdir().unwrap();
        let who = Account {
            uid: nerve_transport::net::euid(),
            ..nerve(Path::new("/var/lib/nerve"))
        };
        let exe = d.path().join("probe");
        if std::env::var_os("NERVE_TEST_PROBE_ENV").is_some() {
            // The probe prints what it was given and refuses, so that the
            // text comes back as the reason.
            std::fs::write(&exe, "#!/bin/sh\nenv >&2\nexit 1\n").unwrap();
            std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
            let why = HostKeyring { exe }.check(&who).unwrap_err();
            println!("probe-env-begin\n{why}\nprobe-env-end");
            return;
        }
        let mut c = std::process::Command::new(std::env::current_exe().unwrap());
        c.args(["--exact", NAME, "--nocapture", "--test-threads=1"])
            .env("NERVE_TEST_PROBE_ENV", "1")
            // The node runs `setup` for an owner (crate::owner) ...
            .env(crate::owner::OWNER_ENV, "alice")
            .env_remove("SUDO_UID")
            // ... with the session of someone else in its environment.
            .env("XDG_RUNTIME_DIR", format!("/run/user/{POISON}"))
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path=/run/user/{POISON}/bus"),
            )
            .env("XDG_CONFIG_HOME", format!("/home/{POISON}/.config"))
            .env("XDG_DATA_HOME", format!("/home/{POISON}/.local/share"))
            .env("DISPLAY", ":7")
            .env("LEAKED_SENTINEL", "1")
            .stdin(std::process::Stdio::null());
        let o = c.output().unwrap();
        let out = String::from_utf8_lossy(&o.stdout).into_owned();
        assert!(o.status.success(), "{out}");
        let text = out
            .split("probe-env-begin\n")
            .nth(1)
            .and_then(|t| t.split("\nprobe-env-end").next())
            .unwrap_or_else(|| panic!("{out}"));
        let mut got: Vec<&str> = text
            .lines()
            .filter(|l| {
                !["PWD=", "SHLVL=", "_=", "OLDPWD="]
                    .iter()
                    .any(|p| l.starts_with(p))
            })
            .collect();
        got.sort();
        let mut want: Vec<String> = session_env(&who)
            .into_iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        want.sort();
        assert_eq!(got, want, "{text}");
        // Said of the variables the probe got, not of the text: the
        // probe's `env` also prints the folder the test runs in, which may
        // be anything (a runner's `/home/runner/work/...`).
        assert!(got.iter().all(|l| !l.contains(POISON)), "{text}");
    }

    /// The service manager of a session that began with another user's
    /// runtime folder (the system-wide environment of the login) is told its
    /// own.
    #[test]
    fn a_session_manager_with_anothers_runtime_folder_is_set_right() {
        if !cfg!(target_os = "linux") {
            return;
        }
        let who = Account {
            uid: 999,
            ..nerve(Path::new("/var/lib/nerve"))
        };
        let right = "PATH=/usr/bin\nXDG_RUNTIME_DIR=/run/user/999\nDBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/999/bus\n";
        assert!(wrong_session_vars(right, &who).is_empty());
        let wrong = "PATH=/usr/bin\nXDG_RUNTIME_DIR=/run/user/1001\nDBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus\n";
        let mut set = wrong_session_vars(wrong, &who);
        set.sort();
        assert_eq!(
            set,
            [
                "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/999/bus",
                "XDG_RUNTIME_DIR=/run/user/999"
            ]
        );
        // One of them, and a variable that only starts with the name.
        let one = "XDG_RUNTIME_DIR=/run/user/1001\nXDG_RUNTIME_DIR_OTHER=x\n";
        assert_eq!(
            wrong_session_vars(one, &who),
            ["XDG_RUNTIME_DIR=/run/user/999"]
        );
        // None of them is set: nothing to correct.
        assert!(wrong_session_vars("PATH=/usr/bin\n", &who).is_empty());
    }

    /// Another user's `~/.config` in the session manager's environment (a
    /// runner image's `/etc/environment`) is set to the user's own; the
    /// user's own folders and the unset ones are left.
    #[cfg(unix)]
    #[test]
    fn a_session_manager_with_anothers_config_folder_is_set_right() {
        let who = Account {
            uid: 999,
            ..nerve(Path::new("/var/lib/nerve"))
        };
        let env = "PATH=/usr/bin\nXDG_CONFIG_HOME=/home/runner/.config\nXDG_DATA_HOME=/var/lib/nerve/.local/share\nXDG_CACHE_HOME=\nXDG_STATE_HOME=/home/runner/.local/state\nXDG_DATA_DIRS=/usr/share\n";
        assert_eq!(
            wrong_user_dirs(env, &who),
            [
                "XDG_CONFIG_HOME=/var/lib/nerve/.config",
                "XDG_STATE_HOME=/var/lib/nerve/.local/state"
            ]
        );
        assert_eq!(
            wrong_user_dirs("XDG_DATA_HOME=/home/runner/.local/share\n", &who),
            ["XDG_DATA_HOME=/var/lib/nerve/.local/share"],
            "GNOME Keyring looks for its keyrings there"
        );
        assert!(wrong_user_dirs("XDG_DATA_HOME=/var/lib/nerve/.local/share\n", &who).is_empty());
        // A folder that only starts like the home is another's.
        assert_eq!(
            wrong_user_dirs("XDG_CONFIG_HOME=/var/lib/nerve-run/.config\n", &who),
            ["XDG_CONFIG_HOME=/var/lib/nerve/.config"]
        );
        assert!(wrong_user_dirs("PATH=/usr/bin\n", &who).is_empty());
    }

    /// The generator that keeps the session right at every start of its
    /// manager prints the user's folders for that user and nothing for
    /// another.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_session_generator_speaks_for_its_user_only() {
        let run = |uid: u32| {
            let who = Account {
                uid,
                ..nerve(Path::new("/var/lib/nerve"))
            };
            let d = tempfile::tempdir().unwrap();
            let f = d.path().join("gen");
            std::fs::write(&f, session_generator_text(&who)).unwrap();
            let sh = system_program("sh").unwrap();
            let o = std::process::Command::new(sh).arg(&f).output().unwrap();
            assert!(o.status.success());
            String::from_utf8(o.stdout).unwrap()
        };
        let mine = nerve_transport::net::euid();
        let said = run(mine);
        let mut lines: Vec<&str> = said.lines().collect();
        lines.sort();
        let mut want = vec![
            format!("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{mine}/bus"),
            format!("XDG_RUNTIME_DIR=/run/user/{mine}"),
            "XDG_CONFIG_HOME=/var/lib/nerve/.config".into(),
            "XDG_DATA_HOME=/var/lib/nerve/.local/share".into(),
            "XDG_CACHE_HOME=/var/lib/nerve/.cache".into(),
            "XDG_STATE_HOME=/var/lib/nerve/.local/state".into(),
        ];
        want.sort();
        assert_eq!(lines, want, "{said}");
        // Every other user's manager runs it too, and gets nothing from it.
        assert_eq!(run(mine + 1), "");
    }

    /// The generator is written readable for the user whose manager runs it,
    /// also by a process with the node's umask 0077 and into a folder that
    /// does not exist yet.
    #[cfg(unix)]
    #[test]
    fn the_session_generator_is_written_open_to_the_user_whose_manager_runs_it() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("etc/systemd/user-environment-generators");
        let file = dir.join("99-nerve-session");
        let sh = system_program("sh").unwrap();
        let o = std::process::Command::new(sh)
            .args(["-c", "umask 077 && exec sh -c \"$0\" nerve-node \"$@\""])
            .arg(WRITE_GENERATOR)
            .arg(&dir)
            .arg(&file)
            .arg("#!/bin/sh\necho x\n")
            .output()
            .unwrap();
        assert!(o.status.success(), "{o:?}");
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o755);
        assert_eq!(mode(&file), 0o755);
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "#!/bin/sh\necho x\n"
        );
        assert!(!dir.join("99-nerve-session.new").exists());
    }

    /// Only the installed node's own account has its session put right when
    /// the node starts; a node you run yourself, and a session with a
    /// desktop, are left alone.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_start_repair_is_for_the_nodes_own_account_only() {
        let node = Account {
            comment: crate::service::USER_MARK.into(),
            ..nerve(Path::new("/var/lib/nerve"))
        };
        assert!(is_node_account(&node));
        // A user named nerve that install did not make, and another user.
        assert!(!is_node_account(&nerve(Path::new("/var/lib/nerve"))));
        let alice = Account {
            name: "alice".into(),
            comment: crate::service::USER_MARK.into(),
            ..nerve(Path::new("/home/alice"))
        };
        assert!(!is_node_account(&alice));
        if !graphical_env(|k| std::env::var_os(k)) {
            assert!(start_repair_applies(&node, || false));
        }
        assert!(!start_repair_applies(&node, || true), "a desktop's session");
        assert!(
            !start_repair_applies(&alice, || false),
            "a node run by hand"
        );
    }

    /// A user who keeps an XDG folder on another disk is not told it is
    /// wrong; the node's own account is. The runtime folder and bus are wrong
    /// for everyone.
    #[cfg(unix)]
    #[test]
    fn xdg_folders_are_set_right_for_the_nodes_own_account_only() {
        let env = "XDG_DATA_HOME=/scratch/alice/share\nXDG_CACHE_HOME=/scratch/alice/.cache\n";
        let alice = Account {
            name: "alice".into(),
            uid: 1000,
            comment: "Alice".into(),
            ..nerve(Path::new("/home/alice"))
        };
        assert!(session_fixes(env, &alice).is_empty());
        let node = Account {
            comment: crate::service::USER_MARK.into(),
            uid: 999,
            ..nerve(Path::new("/var/lib/nerve"))
        };
        assert_eq!(
            session_fixes(env, &node),
            [
                "XDG_DATA_HOME=/var/lib/nerve/.local/share",
                "XDG_CACHE_HOME=/var/lib/nerve/.cache"
            ]
        );
        if cfg!(target_os = "linux") {
            let wrong = "XDG_RUNTIME_DIR=/run/user/4711\nXDG_DATA_HOME=/scratch/alice/share\n";
            assert_eq!(
                session_fixes(wrong, &alice),
                ["XDG_RUNTIME_DIR=/run/user/1000"]
            );
        }
    }

    /// The question names the generator only for the account that gets one.
    #[test]
    fn the_question_names_the_generator_for_the_nodes_own_account_only() {
        let ask = |who: &Account| {
            let k = FakeKeyring::new(false);
            let mut out = Vec::new();
            let mut input = std::io::Cursor::new(b"n\n".to_vec());
            let _ = ensure(&k, who, Some(&mut input as &mut dyn BufRead), &mut out);
            String::from_utf8(out).unwrap()
        };
        let node = Account {
            comment: crate::service::USER_MARK.into(),
            ..nerve(Path::new("/var/lib/nerve"))
        };
        assert!(ask(&node).contains(SESSION_GENERATOR));
        let alice = Account {
            name: "alice".into(),
            ..nerve(Path::new("/home/alice"))
        };
        assert!(!ask(&alice).contains(SESSION_GENERATOR));
    }

    /// GNOME Keyring 40 (Ubuntu 22.04) has `gnome-keyring.service` and no
    /// `gnome-keyring-daemon.service`: only what exists is restarted.
    #[test]
    fn only_the_units_that_exist_are_restarted() {
        let old = units_to_restart(|u| u != "gnome-keyring-daemon.service");
        assert_eq!(old, ["dbus.service", "gnome-keyring.service"]);
        let new = units_to_restart(|u| u != "gnome-keyring.service");
        assert_eq!(new, ["dbus.service", "gnome-keyring-daemon.service"]);
        assert!(units_to_restart(|_| false).is_empty());
    }

    #[test]
    fn no_is_the_default_and_keeps_the_refusal() {
        // No answer at all (the input ends) is a no too.
        for typed in ["\n", "n\n", "no\n", ""] {
            let k = FakeKeyring::new(false);
            let (r, out) = run(&k, Some(typed));
            let err = r.unwrap_err();
            assert!(err.contains("no system keyring answers for nerve"), "{err}");
            assert!(err.contains("nowhere else"), "{err}");
            assert!(k.installed.borrow().is_empty());
            // The question says what it would do, and what that keyring is.
            assert!(
                out.contains(
                    "/usr/bin/apt-get install -y --no-install-recommends gnome-keyring dbus-user-session"
                ),
                "{out}"
            );
            assert!(
                out.contains("/usr/bin/loginctl enable-linger nerve"),
                "{out}"
            );
            let store = Path::new("/var/lib/nerve").join(".local/share/keyrings");
            assert!(
                out.contains(&format!("unencrypted in {}", store.display())),
                "{out}"
            );
            assert!(out.contains("[y/N]"), "{out}");
        }
    }

    #[test]
    fn yes_installs_the_keyring_and_checks_it_answers() {
        let k = FakeKeyring::new(false);
        let (r, out) = run(&k, Some("y\n"));
        assert_eq!(r, Ok(true), "{out}");
        assert_eq!(
            *k.installed.borrow(),
            [
                "`/usr/bin/apt-get update`, `/usr/bin/apt-get install -y --no-install-recommends gnome-keyring dbus-user-session`, `/usr/bin/loginctl enable-linger nerve` for nerve"
            ]
        );
        assert!(
            out.contains("the system keyring answers for nerve"),
            "{out}"
        );
    }

    /// On a desktop nothing is offered: the keyring would be the default of
    /// every program there. The question says that it becomes the default.
    #[test]
    fn a_user_with_a_desktop_is_offered_no_keyring() {
        let mut k = FakeKeyring::new(false);
        k.desktop = true;
        let (r, out) = run(&k, Some("y\n"));
        let e = r.unwrap_err();
        assert!(e.contains("no system keyring answers for nerve"), "{e}");
        assert!(e.contains("has a desktop session"), "{e}");
        assert!(out.is_empty(), "{out}");
        assert!(k.installed.borrow().is_empty());
        let k = FakeKeyring::new(false);
        let (_, out) = run(&k, Some("n\n"));
        assert!(out.contains("default keyring of nerve"), "{out}");
    }

    #[test]
    fn a_graphical_session_is_told_by_its_environment() {
        use std::ffi::OsString;
        let env = |vars: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                vars.iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| OsString::from(v))
            }
        };
        assert!(graphical_env(env(&[("WAYLAND_DISPLAY", "wayland-1")])));
        assert!(graphical_env(env(&[("DISPLAY", ":0")])));
        assert!(graphical_env(env(&[("XDG_CURRENT_DESKTOP", "sway")])));
        assert!(graphical_env(env(&[("XDG_SESSION_TYPE", "x11")])));
        assert!(!graphical_env(env(&[("XDG_SESSION_TYPE", "tty")])));
        assert!(!graphical_env(env(&[("DISPLAY", ""), ("HOME", "/root")])));
    }

    #[test]
    fn without_a_terminal_or_a_package_manager_nothing_is_asked() {
        let k = FakeKeyring::new(false);
        let (r, out) = run(&k, None);
        assert!(r.unwrap_err().contains("run in a terminal"));
        assert!(out.is_empty(), "{out}");
        let mut k = FakeKeyring::new(false);
        k.offer = None;
        let (r, out) = run(&k, Some("y\n"));
        assert!(r.is_err());
        assert!(out.is_empty(), "{out}");
        assert!(k.installed.borrow().is_empty());
    }

    #[test]
    fn the_login_keyring_is_made_once_and_never_replaced() {
        let d = tempfile::tempdir().unwrap();
        let who = Account {
            uid: nerve_transport::net::euid(),
            ..nerve(d.path())
        };
        assert_eq!(make_login_keyring(&who), Ok(true));
        let file = d.path().join(".local/share/keyrings/login.keyring");
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(
            text.starts_with("[keyring]\ndisplay-name=login\n"),
            "{text}"
        );
        assert!(text.contains("lock-on-idle=false"));
        assert_eq!(
            std::fs::read_to_string(d.path().join(".local/share/keyrings/default")).unwrap(),
            "login"
        );
        std::fs::write(&file, "someone's own keyring").unwrap();
        assert_eq!(make_login_keyring(&who), Ok(false));
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "someone's own keyring"
        );
    }
}
