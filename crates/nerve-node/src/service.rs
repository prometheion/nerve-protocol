//! The node as a service (docs/user/service.md): `install`, `update` and
//! `uninstall`, on Linux with systemd. The service runs `nerve-node run`
//! under a user of its own, `nerve`, which owns the node's config and state
//! folders. The owner's commands reach that node with `sudo nerve-node …`:
//! a command root runs on folders that belong to another user runs as that
//! user ([`become_owner`]), so whatever it writes stays the node's.
//!
//! The node runs a center's commands as another account than `nerve`, so
//! they cannot read the node's keys ([`crate::account`]): `nerve-run`, which
//! `install` makes with a home of its own, and in user mode the owner, the
//! account that ran `install`, which the unit names.
//!
//! What these commands do to the machine beyond the node's files (the user,
//! systemd, running a program) goes through [`System`], so the tests run
//! every step on temporary folders.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use nerve_policy::audit::AuditLog;
use nerve_policy::config::SecretStorage;

use crate::paths::NodePaths;

/// The user the service runs as.
pub const USER: &str = "nerve";
/// The comment `install` gives that user. A `nerve` user without it was not
/// made by `install`: install does not take it over, uninstall leaves it.
pub const USER_MARK: &str = "Nerve node";
/// The systemd unit.
pub const UNIT_NAME: &str = "nerve-node.service";
/// The largest program `update` downloads.
const PROGRAM_MAX: usize = 256 * 1024 * 1024;
/// The largest `SHA256SUMS` `update` downloads.
const SUMS_MAX: usize = 64 * 1024;

/// Where an installed node lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// The systemd unit file.
    pub unit: PathBuf,
    /// The program the service runs.
    pub bin: PathBuf,
    /// The home of the service's user. It holds the state folder.
    pub home: PathBuf,
    /// The home of the account commands run as, `nerve-run` (Linux).
    pub run_home: PathBuf,
    /// The folders every account may write in, where that account's files
    /// are left behind: `/tmp`, `/var/tmp` and `/dev/shm` (Linux).
    pub run_temp: Vec<PathBuf>,
    pub paths: NodePaths,
    /// Where `update` finds the programs of the latest release and their
    /// `SHA256SUMS`.
    pub release: String,
    /// The program installed: the node, or the desktop app with its parts.
    pub edition: &'static crate::edition::Edition,
}

impl Layout {
    /// The places on this machine. On Windows the program goes to
    /// `%ProgramFiles%\Nerve` and the folders to `%ProgramData%\Nerve`; the
    /// service is registered with the service control manager, so there is
    /// no unit file ([`crate::winsvc`]).
    pub fn system() -> Layout {
        Layout::of(crate::edition::get())
    }

    /// [`Layout::system`] for `edition`: the program is named after it,
    /// `/usr/local/bin/nerve-node-desktop` for the desktop app.
    pub fn of(edition: &'static crate::edition::Edition) -> Layout {
        let program = edition.program;
        let release = concat!(env!("CARGO_PKG_REPOSITORY"), "/releases/latest/download").into();
        if cfg!(windows) {
            let var = |k: &str, or: &str| {
                std::env::var_os(k)
                    .filter(|v| !v.is_empty())
                    .map_or_else(|| PathBuf::from(or), PathBuf::from)
            };
            let data = var("ProgramData", "C:\\ProgramData").join("Nerve");
            return Layout {
                unit: PathBuf::new(),
                bin: var("ProgramFiles", "C:\\Program Files")
                    .join("Nerve")
                    .join(format!("{program}.exe")),
                paths: NodePaths::new(data.join("config"), data.join("state")),
                home: data,
                run_home: PathBuf::new(),
                run_temp: Vec::new(),
                release,
                edition,
            };
        }
        Layout {
            unit: PathBuf::from("/etc/systemd/system").join(UNIT_NAME),
            bin: PathBuf::from("/usr/local/bin").join(program),
            home: "/var/lib/nerve".into(),
            run_home: crate::account::RUN_HOME.into(),
            run_temp: ["/tmp", "/var/tmp", "/dev/shm"]
                .into_iter()
                .map(PathBuf::from)
                .collect(),
            paths: NodePaths::new("/etc/nerve", "/var/lib/nerve/state"),
            release,
            edition,
        }
    }

    /// Whether `install` put the node here: its unit is in place, or on
    /// Windows its service is registered.
    /// Whether the unit file is in place: [`Layout::installed`] on Linux,
    /// for a layout of any folders (the tests').
    fn installed_at_unit(&self) -> bool {
        self.unit.is_file()
    }

    /// The polkit rule that lets the owner start and stop the service
    /// (crate::owner): `/etc/polkit-1/rules.d`, beside the unit's `/etc`.
    pub fn polkit_rule(&self) -> PathBuf {
        self.etc().join("polkit-1/rules.d").join(POLKIT_RULE)
    }

    /// The `/etc` the unit is in.
    fn etc(&self) -> &Path {
        self.unit.ancestors().nth(3).unwrap_or(Path::new("/etc"))
    }

    /// The helper that starts, stops and restarts the service and does
    /// nothing else, which the owner runs through pkexec
    /// ([`service_helper_text`]): beside the program's `bin`, in
    /// `/usr/local/lib/nerve-node`.
    pub fn service_helper(&self) -> PathBuf {
        let local = self
            .bin
            .parent()
            .and_then(Path::parent)
            .unwrap_or(Path::new("/usr/local"));
        local.join("lib/nerve-node").join(SERVICE_HELPER)
    }

    /// The polkit action of [`Layout::service_helper`]: in
    /// `/usr/share/polkit-1/actions`, the one folder polkit reads them from.
    pub fn polkit_action(&self) -> PathBuf {
        self.etc()
            .parent()
            .unwrap_or(Path::new("/"))
            .join("usr/share/polkit-1/actions")
            .join(format!("{POLKIT_ACTION}.policy"))
    }

    /// The `.pkla` file that lets the owner run the helper on a polkit
    /// without rules (0.105).
    pub fn polkit_pkla(&self) -> PathBuf {
        self.etc()
            .join("polkit-1/localauthority/50-local.d")
            .join(POLKIT_PKLA)
    }

    pub fn installed(&self) -> bool {
        #[cfg(windows)]
        {
            crate::win_host::service_registered()
        }
        #[cfg(not(windows))]
        {
            cfg!(target_os = "linux") && self.unit.is_file()
        }
    }

    /// The service unit, for the owner `owner`. The node runs as its own
    /// user with the folders given; stopping the service ends every command
    /// it runs, and a node that fails is started again. CAP_SETUID and
    /// CAP_SETGID are the one privilege it keeps: they let it start a
    /// command as `nerve-run` or the owner. Every command drops them before
    /// it runs; the bounding set stays as it is, since an allowed sudo
    /// command needs root's. The service's cgroup is the node's to divide
    /// (`Delegate=`): each command runs in one of its own below it, held to
    /// its limits (crate::cgroup). A command the kernel kills for its memory
    /// leaves the node running (`OOMPolicy=`, which `Delegate=` defaults to
    /// already). systemd makes the node's runtime folder, where its owner
    /// reaches it (crate::owner); every account may enter it. The owner is
    /// named here, where only root writes and everyone reads
    /// ([`owner_in_unit`]).
    pub fn unit_text(&self, owner: Option<&str>) -> String {
        let owner = owner.map_or_else(String::new, |o| {
            format!("Environment={}={o}\n", crate::owner::OWNER_VAR)
        });
        format!(
            "# Written by `nerve-node install`; `nerve-node uninstall` removes it.
[Unit]
Description=Nerve node
Documentation={repo}
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User={USER}
Group={USER}
Environment=HOME={home}
{owner}AmbientCapabilities=CAP_SETUID CAP_SETGID
Delegate=cpu memory pids
OOMPolicy=continue
ExecStart={bin} --config-dir {config} --state-dir {state} run
ExecReload=kill -HUP $MAINPID
RuntimeDirectory={runtime}
RuntimeDirectoryMode=0755
Restart=on-failure
RestartSec=5
UMask=0077

[Install]
WantedBy=multi-user.target
",
            repo = env!("CARGO_PKG_REPOSITORY"),
            home = self.home.display(),
            bin = self.bin.display(),
            config = self.paths.config_dir.display(),
            state = self.paths.state_dir.display(),
            runtime = Path::new(crate::owner::RUNTIME_DIR)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy(),
        )
    }
}

/// The owner of the node on `paths` when it is the installed one, as its
/// unit names it.
pub fn owner_of(paths: &NodePaths) -> Option<String> {
    let layout = Layout::system();
    if *paths != layout.paths {
        return None;
    }
    owner_in_unit(&std::fs::read_to_string(&layout.unit).ok()?)
}

/// The owner a unit's text names ([`Layout::unit_text`]).
pub fn owner_in_unit(text: &str) -> Option<String> {
    let prefix = format!("Environment={}=", crate::owner::OWNER_VAR);
    text.lines()
        .find_map(|l| l.strip_prefix(prefix.as_str()))
        .map(str::trim)
        .filter(|o| nerve_policy::config::valid_account_name(o))
        .map(String::from)
}

/// The file name of the polkit rule ([`Layout::polkit_rule`]).
pub const POLKIT_RULE: &str = "50-nerve-node.rules";

/// The file name of the `.pkla` file ([`Layout::polkit_pkla`]).
pub const POLKIT_PKLA: &str = "50-nerve-node.pkla";

/// The polkit action of the service helper ([`Layout::service_helper`]).
pub const POLKIT_ACTION: &str = "org.nerve-protocol.node.service-control";

/// The file name of the service helper.
pub const SERVICE_HELPER: &str = "service-control";

/// The service helper: a script that starts, stops or restarts the
/// installed unit and does nothing else. pkexec runs it as root for the
/// owner without a password ([`polkit_action_text`]), also on polkit 0.105,
/// which takes no rule that could limit systemd's own action to one unit.
/// It takes one word and nothing from its environment: pkexec matches an
/// action by the program's path only, never by its arguments.
pub fn service_helper_text() -> String {
    format!(
        "#!/bin/sh
# Written by `nerve-node install`; `nerve-node uninstall` removes it.
# Starts, stops or restarts the Nerve node's service {UNIT_NAME}, and does
# nothing else. The node's owner runs it through pkexec without a password
# (polkit action {POLKIT_ACTION}).
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
if [ \"$#\" -ne 1 ]; then
    echo \"usage: $0 start|stop|restart\" >&2
    exit 2
fi
case \"$1\" in
start | stop | restart) exec systemctl \"$1\" {UNIT_NAME} ;;
*)
    echo \"usage: $0 start|stop|restart\" >&2
    exit 2
    ;;
esac
"
    )
}

/// The polkit action of the service helper at `helper`: an administrator by
/// default; the owner by the rule ([`polkit_rule_text`]) or the `.pkla`
/// file ([`polkit_pkla_text`]).
pub fn polkit_action_text(helper: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<!-- Written by `nerve-node install`; `nerve-node uninstall` removes it. -->
<policyconfig>
  <vendor>Nerve</vendor>
  <action id="{POLKIT_ACTION}">
    <description>Start, stop or restart the Nerve node</description>
    <message>Authentication is required to start, stop or restart the Nerve node</message>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">{helper}</annotate>
  </action>
</policyconfig>
"#,
        helper = helper.display()
    )
}

/// The `.pkla` file for polkit 0.105: the owner `owner` may run the service
/// helper without a password from their own session at this machine
/// (`ResultActive`); anyone else, and the owner elsewhere, keeps the
/// action's default. Never one for systemd's `manage-units`, which would let
/// the owner manage every unit.
pub fn polkit_pkla_text(owner: &str) -> String {
    format!(
        "# Written by `nerve-node install`; `nerve-node uninstall` removes it.
# {owner}, the owner of the Nerve node, may start, stop and restart its
# service through its helper from their own session at this machine, and
# nothing else.
[Nerve node: start, stop and restart]
Identity=unix-user:{owner}
Action={POLKIT_ACTION}
ResultActive=yes
"
    )
}

/// The polkit rule: the owner `owner` may start, stop and restart the node's
/// service, and nothing else: through systemd, which names the unit and the
/// verb of each request (`org.freedesktop.systemd1.manage-units`), or
/// through the service helper ([`POLKIT_ACTION`]).
pub fn polkit_rule_text(owner: &str) -> String {
    format!(
        "// Written by `nerve-node install`; `nerve-node uninstall` removes it.
// {owner}, the owner of the Nerve node, may start, stop and restart its
// service {UNIT_NAME} from their own session at this machine, and nothing
// else. A program outside a session, such as a command the node runs, is
// asked for an administrator's password as before.
polkit.addRule(function(action, subject) {{
    if (subject.user != \"{owner}\" || !subject.local || !subject.active) {{
        return polkit.Result.NOT_HANDLED;
    }}
    if (action.id == \"{POLKIT_ACTION}\") {{
        return polkit.Result.YES;
    }}
    if (action.id == \"org.freedesktop.systemd1.manage-units\" &&
        action.lookup(\"unit\") == \"{UNIT_NAME}\") {{
        var verb = action.lookup(\"verb\");
        if (verb == \"start\" || verb == \"stop\" || verb == \"restart\") {{
            return polkit.Result.YES;
        }}
    }}
    return polkit.Result.NOT_HANDLED;
}});
"
    )
}

/// What polkit on this machine takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Polkit {
    /// Rules in JavaScript (polkit 0.106 and later).
    Rules,
    /// polkit without them (0.105, Ubuntu 22.04): `.pkla` files.
    Old,
    /// No polkit.
    Missing,
}

/// Which polkit `pkaction --version` names (`pkaction version 0.105`,
/// `pkaction version 124`); `None` when it names none. Rules came with
/// 0.106; from 0.120 on the versions have one number.
pub fn polkit_of_version(said: &str) -> Option<Polkit> {
    let v = said.split_whitespace().last()?;
    let mut parts = v.split('.').map(|p| p.parse::<u32>().ok());
    let major = parts.next()??;
    let minor = parts.next().flatten().unwrap_or(0);
    Some(if major == 0 && minor < 106 {
        Polkit::Old
    } else {
        Polkit::Rules
    })
}

/// Whether a node on `paths` is the installed service, however it was
/// started: on the installed folders, or as the user `install` made. Such a
/// node runs commands only as `nerve-run` or the owner, never as itself
/// ([`crate::account::for_commands`]), even without the two capabilities
/// the unit gives it.
pub fn is_service_node(paths: &NodePaths) -> bool {
    if *paths == Layout::system().paths {
        return true;
    }
    #[cfg(any(unix, windows))]
    {
        let me = crate::account::own_uid();
        me != 0
            && matches!(crate::account::lookup(USER), Ok(Some(a)) if a.uid == me && a.comment == USER_MARK)
    }
    #[cfg(not(any(unix, windows)))]
    false
}

/// A user account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    /// The comment field, where [`USER_MARK`] goes.
    pub comment: String,
    pub home: PathBuf,
    /// Every group the account is in, its own included.
    pub groups: Vec<u32>,
}

/// What install, update and uninstall do to the machine besides writing the
/// node's files.
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
    /// Waits until the node the service started answers on its control
    /// socket.
    fn wait_running(&self, paths: &NodePaths) -> Result<(), String>;
    /// What `<program> --version` prints, run as `account`.
    fn version_of(&self, program: &Path, account: &Account) -> Result<String, String>;
    /// The state of the installed unit: running, stopped, starting,
    /// stopping or failed, and whether it starts with the machine.
    fn unit_state(&self) -> Result<ServiceState, String>;
    /// Ends the session a system keyring gave `name` (`loginctl
    /// enable-linger`, [`crate::keyring_setup`]), so that the user can go;
    /// `Ok(false)` when it had none.
    fn end_session(&self, _name: &str) -> Result<bool, String> {
        Ok(false)
    }
    /// Whether the kernel has Landlock, which holds each command of
    /// `nerve-run` to its own folders.
    fn landlock(&self) -> bool {
        nerve_sandbox::Confinement::detect().landlock_abi.is_some()
    }
    /// The kernel's Landlock ABI.
    fn landlock_abi(&self) -> Option<i32> {
        nerve_sandbox::Confinement::detect().landlock_abi
    }
    /// What polkit takes here; the rules go to `rule`'s folder.
    fn polkit(&self, _rule: &Path) -> Polkit {
        Polkit::Missing
    }
    /// Whether `pkexec` is there.
    fn has_pkexec(&self) -> bool {
        false
    }
    /// Runs `program` with `args` as root through `pkexec`, which asks
    /// polkit; never through a text agent in a terminal.
    fn pkexec(&self, program: &Path, _args: &[&str]) -> Result<(), String> {
        Err(format!(
            "cannot run {} through pkexec here",
            program.display()
        ))
    }
}

/// The `pkexec` of this machine: on `PATH`, else in `/usr/bin`.
fn pkexec_program() -> Option<PathBuf> {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .chain([PathBuf::from("/usr/bin")])
        .map(|d| d.join("pkexec"))
        .find(|p| p.is_file())
}

/// This machine.
pub struct Host;

impl Host {
    /// [`System::end_session`] for the generator at `generator` and the
    /// linger files in `linger`. What setup wrote for the session of the
    /// node's user (crate::keyring_setup) goes first, whether or not the user
    /// lingers: it must not stay for the next account to get the uid.
    fn end_session_of(&self, name: &str, generator: &Path, linger: &Path) -> Result<bool, String> {
        let _ = std::fs::remove_file(generator);
        if !linger.join(name).exists() {
            return Ok(false);
        }
        run("loginctl", &["disable-linger", name])?;
        // userdel refuses a user whose processes (the keyring) still run;
        // systemctl waits until the session's manager has stopped them.
        if let Ok(Some(a)) = self.account(name) {
            let _ = run("systemctl", &["stop", &format!("user@{}.service", a.uid)]);
        }
        let _ = run("loginctl", &["terminate-user", name]);
        Ok(true)
    }
}

impl System for Host {
    fn is_root(&self) -> bool {
        nerve_transport::net::euid() == 0
    }

    fn has_systemd(&self) -> bool {
        Path::new("/run/systemd/system").is_dir()
    }

    fn account(&self, name: &str) -> Result<Option<Account>, String> {
        crate::account::lookup(name)
    }

    fn add_account(&self, name: &str, home: &Path, mark: &str) -> Result<(), String> {
        let shell = no_login();
        run(
            "useradd",
            &[
                "--system",
                "--user-group",
                "--home-dir",
                &home.display().to_string(),
                "--no-create-home",
                "--shell",
                shell,
                "--comment",
                mark,
                name,
            ],
        )
    }

    fn remove_account(&self, name: &str) -> Result<(), String> {
        run("userdel", &[name])?;
        // userdel takes the group along where the system makes one group per
        // user; elsewhere it stays behind.
        let group = std::process::Command::new("getent")
            .args(["group", name])
            .output()
            .is_ok_and(|o| o.status.success());
        if group {
            run("groupdel", &[name])?;
        }
        Ok(())
    }

    fn systemctl(&self, args: &[&str]) -> Result<(), String> {
        let mut c = std::process::Command::new("systemctl");
        c.args(args);
        // setup restarts the node after it installed a keyring.
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

    fn unit_state(&self) -> Result<ServiceState, String> {
        let o = std::process::Command::new("systemctl")
            .args(["show", "--property=ActiveState,UnitFileState", UNIT_NAME])
            .output()
            .map_err(|e| format!("systemctl: {e}"))?;
        if !o.status.success() {
            return Err(format!("systemctl show {UNIT_NAME}: {}", failure(&o)));
        }
        Ok(unit_state_of(&String::from_utf8_lossy(&o.stdout)))
    }

    fn wait_running(&self, paths: &NodePaths) -> Result<(), String> {
        #[cfg(unix)]
        {
            use std::io::{BufRead, BufReader};
            let ask = || -> std::io::Result<bool> {
                let mut s = match std::os::unix::net::UnixStream::connect(paths.ctl_socket()) {
                    // An owner without root, after `service start`: the
                    // owner socket says that the node runs too.
                    Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                        std::os::unix::net::UnixStream::connect(crate::owner::socket())?
                    }
                    r => r?,
                };
                s.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
                // The node answers a request with the token it wrote at
                // its start, which root can read.
                let request = nerve_transport::ctl::request_line(
                    &paths.ctl_socket(),
                    "status",
                    serde_json::json!({}),
                );
                s.write_all(format!("{request}\n").as_bytes())?;
                let mut line = String::new();
                BufReader::new(s).read_line(&mut line)?;
                Ok(line.contains("\"ok\""))
            };
            for _ in 0..60 {
                if ask().unwrap_or(false) {
                    return Ok(());
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
            Err(format!(
                "the service started, but the node does not answer on {}; `journalctl -u {UNIT_NAME}` says why",
                paths.ctl_socket().display()
            ))
        }
        #[cfg(not(unix))]
        {
            let _ = paths;
            Err(LINUX_ONLY.into())
        }
    }

    fn version_of(&self, program: &Path, account: &Account) -> Result<String, String> {
        let mut c = std::process::Command::new(program);
        c.arg("--version");
        // A downloaded program runs as the service's user, not as root.
        #[cfg(unix)]
        if self.is_root() {
            use std::os::unix::process::CommandExt;
            c.uid(account.uid).gid(account.gid);
        }
        #[cfg(not(unix))]
        let _ = account;
        // The program `update` staged a moment ago.
        let o = nerve_transport::files::retry_busy(|| c.output())
            .map_err(|e| format!("{}: {e}", program.display()))?;
        if !o.status.success() {
            return Err(format!("{} --version: {}", program.display(), failure(&o)));
        }
        Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
    }

    fn end_session(&self, name: &str) -> Result<bool, String> {
        self.end_session_of(
            name,
            Path::new(crate::keyring_setup::SESSION_GENERATOR),
            Path::new("/var/lib/systemd/linger"),
        )
    }

    fn has_pkexec(&self) -> bool {
        pkexec_program().is_some()
    }

    fn pkexec(&self, program: &Path, args: &[&str]) -> Result<(), String> {
        let pkexec = pkexec_program().ok_or("pkexec is not installed")?;
        let o = std::process::Command::new(pkexec)
            .arg("--disable-internal-agent")
            .arg(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| format!("pkexec: {e}"))?;
        match o.status.code() {
            Some(0) => Ok(()),
            // pkexec's own: not authorized (or no agent to ask), and
            // dismissed.
            Some(126 | 127) => Err(format!(
                "polkit did not let you {}: the owner does it without a password from their own session at this machine; elsewhere `sudo {} service {}` does ({})",
                args.join(" "),
                crate::edition::get().program,
                args.join(" "),
                failure(&o)
            )),
            _ => Err(format!(
                "{} {}: {}",
                program.display(),
                args.join(" "),
                failure(&o)
            )),
        }
    }

    fn polkit(&self, rule: &Path) -> Polkit {
        // By its version: a polkit 0.105 has the rules folders too where a
        // package put a rule there for newer ones (systemd's own does).
        let said = std::process::Command::new("pkaction")
            .arg("--version")
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output();
        if let Some(p) = said
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| polkit_of_version(&String::from_utf8_lossy(&o.stdout)))
        {
            return p;
        }
        let rules = rule.parent().unwrap_or(Path::new("/etc/polkit-1/rules.d"));
        // polkit 0.106 and later read rules from both folders; the one in
        // /usr is the package's, there whether or not /etc has one yet.
        if rules.is_dir() || Path::new("/usr/share/polkit-1/rules.d").is_dir() {
            Polkit::Rules
        } else if Path::new("/etc/polkit-1").is_dir() || Path::new("/usr/bin/pkexec").exists() {
            Polkit::Old
        } else {
            Polkit::Missing
        }
    }
}

/// The shell of an account that does not log in.
pub fn no_login() -> &'static str {
    ["/usr/sbin/nologin", "/sbin/nologin"]
        .into_iter()
        .find(|s| Path::new(s).exists())
        .unwrap_or("/bin/false")
}

const LINUX_ONLY: &str = "works on Linux with systemd only; elsewhere run `nerve-node run` under your own service manager";

/// Runs a system tool; its error output is the error.
/// Lets `c` run as root where this process keeps root only as its saved id
/// (setup on the installed node, [`become_owner`]); elsewhere it runs as
/// this process does.
fn regain_root(c: &mut std::process::Command) {
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

fn failure(o: &std::process::Output) -> String {
    let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
    if err.is_empty() {
        o.status.to_string()
    } else {
        err
    }
}

/// The steps a command did, shown as they are done and audited at its end.
pub(crate) struct Steps<'a> {
    pub(crate) done: Vec<String>,
    pub(crate) out: &'a mut dyn Write,
}

impl Steps<'_> {
    pub(crate) fn did(&mut self, step: impl Into<String>) {
        let step = step.into();
        let _ = writeln!(self.out, "{step}");
        self.done.push(step);
    }
}

/// Whether `what` can run here: Linux, root and systemd.
fn supported(sys: &dyn System, what: &str) -> Result<(), String> {
    if !sys.is_root() && cfg!(target_os = "linux") {
        return Err(format!("{what} needs root: run `sudo nerve-node {what}`"));
    }
    supported_without_root(sys, what)
}

/// Whether `what` can run here: Linux and systemd.
fn supported_without_root(sys: &dyn System, what: &str) -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err(format!("{what} {LINUX_ONLY}"));
    }
    if !sys.has_systemd() {
        return Err(format!(
            "{what} needs systemd, which does not run this machine; run `nerve-node run` under your own service manager"
        ));
    }
    Ok(())
}

/// Writes the command's audit entry, when the state folder is there to hold
/// it. It is written as the folder's owner ([`as_owner_of`]): root does not
/// write through a link that the node's user put there. A folder given to
/// root (by `uninstall`, or one an earlier uninstall left) is written as
/// root, so the log must be a plain file of one name there: a link that was
/// given away with the folder would otherwise be followed with root's rights.
pub(crate) fn audit(
    paths: &NodePaths,
    event: &str,
    steps: &[String],
    r: &Result<(), String>,
    out: &mut dyn Write,
) {
    if !paths.state_dir.is_dir() {
        return;
    }
    let log = AuditLog::new(paths.audit_log());
    let written = as_owner_of(&paths.state_dir).and_then(|_owner| {
        plain_log(log.path())?;
        log.node(event, steps, r.as_ref().err().map(String::as_str))
            .map_err(|e| e.to_string())
    });
    if let Err(e) = written {
        let _ = writeln!(out, "the audit log cannot be written: {e}");
    }
}

/// Refuses an audit log that is not a plain file with one name (one that
/// is not there yet is fine). The check holds in a folder of root's, which
/// nobody else can change between it and the write; in one of `nerve`'s,
/// the write runs as `nerve` anyway.
fn plain_log(log: &Path) -> Result<(), String> {
    let m = match std::fs::symlink_metadata(log) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("{}: {e}", log.display())),
    };
    if !m.file_type().is_file() {
        return Err(format!(
            "{} is not a plain file (a link?); root does not write through it",
            log.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if m.nlink() > 1 {
            return Err(format!(
                "{} has more than one name, and another may be outside the node's folders",
                log.display()
            ));
        }
    }
    Ok(())
}

/// `install`: the node's user, the account of the commands with its home,
/// the folders, the program, polkit, the unit, the running service, in that
/// order. `invoker` is the account that ran install (`SUDO_USER`, the
/// app's `PKEXEC_UID`, else root): it becomes the owner. Running it again
/// puts back what is missing and restarts the service; run by root alone it
/// keeps the owner the unit names, root included where root confirmed it
/// at an earlier install, and root never becomes the owner newly here, as
/// nobody is asked ([`RootOwner`]).
pub fn install(
    layout: &Layout,
    sys: &dyn System,
    exe: &Path,
    invoker: &str,
    out: &mut dyn Write,
) -> Result<(), String> {
    let keyring = crate::keyring_setup::HostKeyring {
        exe: layout.bin.clone(),
    };
    install_asking(
        layout,
        sys,
        &keyring,
        None,
        RootOwner::Ask,
        exe,
        invoker,
        out,
    )
}

/// Whether root becomes the owner of an install that root runs itself
/// ([`owner_of_install`]). Root as the owner runs the commands of `user`
/// mode, and of `allowlist` mode as the owner, as root, which nothing in
/// the node holds back; so it is the person's own explicit choice, never a
/// default. Once confirmed it stays at a later install, until
/// [`RootOwner::NoOwner`] or an install through sudo names another owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootOwner {
    /// Asked at a terminal where root would become the owner newly
    /// ([`root_question_due`]), default no; without a terminal the answer
    /// is no. An owner root confirmed at an earlier install stays.
    Ask,
    /// Chosen with `--owner=root --accept-root-owner`, for an install
    /// without a terminal.
    Accepted,
    /// Chosen with `--owner=none`: the node has no owner after the install,
    /// whichever it had.
    NoOwner,
}

/// What [`RootOwner`] comes to for the owner of an install.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Chosen {
    /// Root, confirmed now or at an earlier install.
    Root,
    /// The owner as before: the account that ran install through sudo, or
    /// the one the unit names.
    Keep,
    /// None.
    NoOwner,
}

/// Whether install asks root whether root is to be the owner: run by root
/// itself without a choice made by the flags, where root is not the owner
/// already.
pub fn root_question_due(layout: &Layout, invoker: &str, root: RootOwner) -> bool {
    root == RootOwner::Ask && invoker == ROOT && unit_owner(layout).as_deref() != Some(ROOT)
}

/// What install says on stderr where root's question is due but nobody can
/// see it: its input or its output is no terminal, or it runs with
/// `--json`. The answer is no then, at once.
pub const NO_QUESTION: &str = "install asks whether root is to be the owner of this node only where its input and its output are a terminal, and not with --json; here the answer is no. `--owner=root --accept-root-owner` makes root the owner without the question.";

/// The name of the one account with uid 0 that may be the owner, and only
/// after the confirmation of [`RootOwner`].
pub const ROOT: &str = "root";

/// What root as the owner means, said before the question and in the
/// install's steps.
pub const ROOT_OWNER_MEANS: &str = "commands of user mode, and of allowlist mode as the owner, run as root: they can do everything on this machine, change and read Nerve itself, its keys included, and nothing in Nerve can hold them back (its guard and checks only catch mistakes). Folder mode and allowlist mode run as nerve-run, as on any node, but a center with the settings grant can switch itself to user mode and so run as root";

/// The centers of the node at `paths` that have the settings grant, which
/// may switch themselves to user mode: where root is the owner, to root.
/// None where the config cannot be read.
fn settings_granted(paths: &NodePaths) -> Vec<String> {
    let secrets = crate::secrets::NodeSecrets::for_cli(paths);
    nerve_policy::settings::SettingsStore::peek_with(&paths.config_file(), &secrets)
        .map(|cfg| {
            cfg.centers
                .iter()
                .filter(|c| c.settings == nerve_policy::config::SettingsGrant::Write)
                .map(|c| c.name.clone())
                .collect()
        })
        .unwrap_or_default()
}

/// What root as the owner means for the centers that have the settings
/// grant already (`granted`), said with [`ROOT_OWNER_MEANS`]; nothing
/// without one.
fn granted_note(granted: &[String]) -> String {
    match granted {
        [] => String::new(),
        [one] => format!(
            " {one} has the settings grant already, so with root as the owner it can run commands as root."
        ),
        many => format!(
            " {} have the settings grant already, so with root as the owner they can run commands as root.",
            many.join(", ")
        ),
    }
}

/// [`install`] in a terminal: `input` answers the question whether to
/// install a system keyring, asked when the node's keys are to be in one
/// and none answers for its user ([`crate::keyring_setup`]), and, run by
/// root, whether root is to be the owner (`root`). `keyring` asks through
/// the installed program, which that user can run.
#[allow(clippy::too_many_arguments)]
pub fn install_asking(
    layout: &Layout,
    sys: &dyn System,
    keyring: &dyn crate::keyring_setup::Keyring,
    input: Option<&mut dyn BufRead>,
    root: RootOwner,
    exe: &Path,
    invoker: &str,
    out: &mut dyn Write,
) -> Result<(), String> {
    supported(sys, "install")?;
    // Root is the owner only of an install that root runs itself: through
    // sudo the account that ran it becomes the owner. Refused before
    // anything changes.
    if root != RootOwner::Ask && invoker != ROOT {
        let flag = match root {
            RootOwner::NoOwner => "--owner=none",
            _ => "--owner=root",
        };
        return Err(format!(
            "{flag} is for an install that root runs itself; this one runs for {invoker} (through sudo or pkexec), who becomes the owner: leave the flags out, or run it as root without sudo"
        ));
    }
    let mut steps = Steps {
        done: Vec::new(),
        out,
    };
    let r = install_steps(layout, sys, keyring, input, root, exe, invoker, &mut steps);
    audit(&layout.paths, "install", &steps.done, &r, steps.out);
    r?;
    let _ = writeln!(steps.out, "{NEXT}");
    Ok(())
}

/// What `install` says to do next: the headless way to a working pairing.
const NEXT: &str = "Next: `nerve-node center add '<link>'` pairs the node with a center, and `nerve-node folder add <folder> +rwx` gives it a folder to read, write and run commands in.";

#[allow(clippy::too_many_arguments)]
fn install_steps(
    layout: &Layout,
    sys: &dyn System,
    keyring: &dyn crate::keyring_setup::Keyring,
    mut input: Option<&mut dyn BufRead>,
    root: RootOwner,
    exe: &Path,
    invoker: &str,
    steps: &mut Steps,
) -> Result<(), String> {
    // Keys in the keyring where they may not be there (an old Landlock):
    // the installed node would not start, so install changes nothing.
    if crate::secrets::stated_storage(&layout.paths) == SecretStorage::Keyring
        && let Some(n) = crate::secrets::no_keyring(&layout.paths)
    {
        return Err(crate::secrets::keyring_refused(
            &layout.paths,
            n,
            "install changed nothing",
            "run `sudo nerve-node install` again, and pair the centers again",
        ));
    }
    // Asked before anything changes.
    let root = match root {
        RootOwner::Accepted => Chosen::Root,
        RootOwner::NoOwner => Chosen::NoOwner,
        RootOwner::Ask if root_question_due(layout, invoker, root) => {
            if ask_root_owner(layout, input.as_deref_mut(), steps.out) {
                Chosen::Root
            } else {
                Chosen::Keep
            }
        }
        // Run by root where root is the owner: confirmed at an earlier
        // install.
        RootOwner::Ask if invoker == ROOT => Chosen::Root,
        RootOwner::Ask => Chosen::Keep,
    };
    let account = system_account(sys, USER, &layout.home, USER_MARK, "the user", steps)?;
    let run = system_account(
        sys,
        crate::account::RUN_USER,
        &layout.run_home,
        crate::account::RUN_MARK,
        "the account commands run as,",
        steps,
    )?;
    let dirs = [
        &layout.home,
        &layout.paths.config_dir,
        &layout.paths.state_dir,
    ];
    for dir in dirs {
        nerve_transport::files::create_private_dir(dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?;
        // An earlier install's folder may hold what its user put there; it
        // is changed as that user, and a link in its place is refused.
        let _owner = as_owner_of(dir)?;
        set_mode(dir, 0o700)?;
    }
    // The folders may be left from an earlier install, whose user had
    // another uid: everything in them is given to this one.
    for dir in dirs {
        sys.give(dir, account.uid, account.gid)?;
    }
    steps.did(format!(
        "{} and {} belong to {USER}",
        layout.paths.config_dir.display(),
        layout.paths.state_dir.display()
    ));
    // The home of the commands' account: its own, closed to others, where
    // tool caches and configs go.
    nerve_transport::files::create_private_dir(&layout.run_home)
        .map_err(|e| format!("{}: {e}", layout.run_home.display()))?;
    {
        let _owner = as_owner_of(&layout.run_home)?;
        set_mode(&layout.run_home, 0o700)?;
    }
    sys.give(&layout.run_home, run.uid, run.gid)?;
    steps.did(format!(
        "{} is the home of {}",
        layout.run_home.display(),
        crate::account::RUN_USER
    ));
    let owner = owner_of_install(layout, sys, invoker, root, steps)?;
    let in_keyring = crate::secrets::stated_storage(&layout.paths) == SecretStorage::Keyring;
    let real = |p: &Path| std::fs::canonicalize(p).ok();
    if real(exe).is_some() && real(exe) == real(&layout.bin) {
        steps.did(format!(
            "the program is at {} already",
            layout.bin.display()
        ));
    } else {
        let program = std::fs::read(exe).map_err(|e| format!("{}: {e}", exe.display()))?;
        write_file(&layout.bin, &program, 0o755)?;
        steps.did(format!("put the program at {}", layout.bin.display()));
    }
    // The old program goes over at once: a running one keeps its file.
    install_parts(layout, steps)?;
    // A node whose keys are in the system keyring does not start without
    // one that answers for its user; the installed program asks it.
    if in_keyring {
        crate::keyring_setup::ensure(keyring, &account, input, steps.out)?;
        steps.did(format!(
            "the node's keys are in the system keyring of {USER}, and it answers"
        ));
    }
    // After the last step that refuses for a reason of its own: what
    // follows only writes the node's files and starts it.
    #[cfg(target_os = "linux")]
    let stopped = {
        let owner_uid = match owner.as_deref() {
            Some(name) => sys.account(name)?.map(|a| a.uid),
            None => None,
        };
        drop_earlier_grants(layout, sys, &account, run.uid, owner_uid, steps)?
    };
    #[cfg(not(target_os = "linux"))]
    let stopped = false;
    let r = start_installed(layout, sys, owner.as_deref(), steps);
    // A node stopped for the owner change runs again, whatever failed.
    if r.is_err() && stopped {
        let _ = sys.systemctl(&["start", UNIT_NAME]);
    }
    r
}

/// The last steps of `install`: the polkit files and the unit for `owner`,
/// and the service started with them.
fn start_installed(
    layout: &Layout,
    sys: &dyn System,
    owner: Option<&str>,
    steps: &mut Steps,
) -> Result<(), String> {
    put_polkit(layout, sys, owner, steps)?;
    write_file(&layout.unit, layout.unit_text(owner).as_bytes(), 0o644)?;
    steps.did(format!("wrote the service unit {}", layout.unit.display()));
    sys.systemctl(&["daemon-reload"])?;
    sys.systemctl(&["enable", UNIT_NAME])?;
    sys.systemctl(&["restart", UNIT_NAME])?;
    sys.wait_running(&layout.paths)?;
    steps.did(format!(
        "the service {UNIT_NAME} runs as {USER} and starts with the machine"
    ));
    Ok(())
}

/// Takes nerve-run's entries off every folder the record names, as root and
/// as `uninstall` does, where they were put on for another owner than the
/// one this install makes (`owner`, `None` without one) or for another
/// nerve-run than `run`. The node acts on the owner's files as the owner
/// alone (crate::acl::sync), so the new owner could not take the old one's
/// entries off, and a node without an owner keeps none at all: they would
/// stay, also on a uid freed later. The record goes with them, and the node
/// gives the grants again for the new owner when it starts. The service
/// stops first, also one that waits to start again after a failure, so that
/// no node of the earlier owner gives them again meanwhile. Where not all
/// came off, the owner stays as it was, the record marks every grant to be
/// walked again (crate::acl::retry_all), as the walk took off what it
/// could, and the node runs again where it ran. `Ok(true)` says the service
/// was stopped here and ran before. `user` is the node's user, whose the
/// record is.
#[cfg(target_os = "linux")]
fn drop_earlier_grants(
    layout: &Layout,
    sys: &dyn System,
    user: &Account,
    run: u32,
    owner: Option<u32>,
    steps: &mut Steps,
) -> Result<bool, String> {
    let record = crate::acl::record_file(&layout.paths);
    let Some((had, left)) = crate::acl::recorded(&record) else {
        return Ok(false);
    };
    if had.run == run && Some(had.owner) == owner && !left {
        return Ok(false);
    }
    let mut ran = false;
    if layout.unit.exists() {
        ran = matches!(sys.unit_state()?.state.as_str(), "running" | "starting");
        // Also cancels a start systemd waits to make after a failure.
        sys.systemctl(&["stop", UNIT_NAME])?;
        steps.did(format!(
            "stopped the service {UNIT_NAME}, as the owner of the node changes"
        ));
    }
    // What nerve-run made there goes to the earlier owner, whose folders
    // they are (to root where that account is gone).
    let r = crate::acl::remove_all(&record, &|owner| {
        crate::account::of_uid(owner).map_or((0, 0), |a| (a.uid, a.gid))
    });
    if !r.stale.is_empty() {
        // The node of the earlier owner, which runs again, puts back what
        // the walk took off.
        let retry =
            crate::acl::retry_all(&record).and_then(|()| sys.give(&record, user.uid, user.gid));
        if ran {
            let _ = sys.systemctl(&["start", UNIT_NAME]);
        }
        let retry = match retry {
            Ok(()) => String::new(),
            Err(e) => format!(" ({e}; the next change of a folder makes it give them again)"),
        };
        return Err(format!(
            "the owner of the node changes, but the access of nerve-run to the folders the earlier owner gave it could not all be taken off: {}; the owner stays as it was, and its node gives the folders again when it starts{retry}: run `{} install` again once that is fixed",
            r.errors.join("; "),
            layout.edition.program
        ));
    }
    let next = if owner.is_some() {
        "the node gives the folders again for the new owner when it starts"
    } else {
        "without an owner the node gives nerve-run no folders, so folder mode and allowlist mode reach only what every account may"
    };
    steps.did(format!(
        "the owner of the node changes, so {}; {next}",
        gave_to_owner(r.not_given)
    ));
    Ok(ran)
}

/// The system account `name` (`what` says what it is for), made with its
/// `home` and `mark` when it is not there. One of that name that `install`
/// did not make is refused: the node takes over no account.
fn system_account(
    sys: &dyn System,
    name: &str,
    home: &Path,
    mark: &str,
    what: &str,
    steps: &mut Steps,
) -> Result<Account, String> {
    match sys.account(name)? {
        Some(a) if a.comment == mark => {
            steps.did(format!("{what} {name}, is there already"));
            Ok(a)
        }
        Some(_) => Err(format!(
            "an account {name} exists already, and nerve-node install did not make it; the node needs it for itself"
        )),
        None => {
            sys.add_account(name, home, mark)?;
            let a = sys
                .account(name)?
                .ok_or_else(|| format!("useradd made no account {name}"))?;
            steps.did(format!("made {what} {name} (uid {})", a.uid));
            Ok(a)
        }
    }
}

/// The owner an earlier install named in the unit of `layout`.
fn unit_owner(layout: &Layout) -> Option<String> {
    std::fs::read_to_string(&layout.unit)
        .ok()
        .and_then(|t| owner_in_unit(&t))
}

/// Asks root, at a terminal (`input`), whether root is to be the owner of
/// the install it runs itself, after saying what that means and what a yes
/// and a no do. Only `y`, `Y` or `yes` is a yes; another answer, the end of
/// the input, or no terminal at all (piped input is none) is a no. Asked
/// only where [`root_question_due`].
fn ask_root_owner(
    layout: &Layout,
    input: Option<&mut (dyn BufRead + '_)>,
    out: &mut dyn Write,
) -> bool {
    let Some(input) = input else {
        return false;
    };
    let now = match unit_owner(layout) {
        Some(o) => format!(
            "{o} is the owner of this node now: on a yes root replaces {o} as the owner, on a no {o} stays it."
        ),
        None => "The node has no owner now: on a yes root becomes its owner; on a no it stays without one, so only root changes the node and user mode runs no command.".to_string(),
    };
    let _ = writeln!(
        out,
        "install runs as root, not through sudo from another account. Root can be the owner of this node: then {ROOT_OWNER_MEANS}.{} {now}",
        granted_note(&settings_granted(&layout.paths))
    );
    let yes =
        crate::cli::ask(input, out, "Make root the owner of this node? [y/N] ").unwrap_or_default();
    matches!(yes.as_str(), "y" | "Y" | "yes")
}

/// The owner of the install: `invoker`, the account that ran it, when that
/// is an account the node can use; run by root alone, root where `choice`
/// says root confirmed it, now or at an earlier install ([`RootOwner`]),
/// none with `--owner=none`, else the owner the unit names already.
/// Without one, user mode runs no command and only root changes the node.
fn owner_of_install(
    layout: &Layout,
    sys: &dyn System,
    invoker: &str,
    choice: Chosen,
    steps: &mut Steps,
) -> Result<Option<String>, String> {
    let p = layout.edition.program;
    let no_owner = format!(
        "Warning: no owner: install ran as root, not through sudo, so only root changes the node and user mode runs no command; `sudo {p} install` from the owner's own account makes it the owner, and root becomes it on a yes to install's question at a terminal, or with `{p} install --owner=root --accept-root-owner`"
    );
    let name = match (invoker, choice, unit_owner(layout)) {
        (ROOT, Chosen::NoOwner, before) => {
            if let Some(b) = before {
                steps.did(format!(
                    "{b} is no longer the owner of the node, as --owner=none says"
                ));
            }
            steps.did(no_owner);
            return Ok(None);
        }
        (ROOT, Chosen::Root, Some(b)) if b == ROOT => {
            steps.did(format!(
                "root stays the owner of the node, as confirmed at an earlier install; `{p} install --owner=none` takes that back"
            ));
            ROOT
        }
        (ROOT, Chosen::Root, _) => ROOT,
        (ROOT, Chosen::Keep, Some(b)) => {
            steps.did(format!("{b} stays the owner of the node"));
            return Ok(Some(b));
        }
        (ROOT, Chosen::Keep, None) => {
            steps.did(no_owner);
            return Ok(None);
        }
        (i, _, _) => i,
    };
    let account = match usable_owner(sys, &layout.paths, name, choice == Chosen::Root) {
        Ok(a) => a,
        Err(e) => {
            steps.did(format!(
                "Warning: no owner: {e}; only root changes the node and user mode runs no command"
            ));
            return Ok(None);
        }
    };
    if account.uid == 0 {
        steps.did(format!(
            "Warning: root is the owner of the node, as you confirmed: {ROOT_OWNER_MEANS}.{}",
            granted_note(&settings_granted(&layout.paths))
        ));
    } else {
        steps.did(format!(
            "{name} is the owner of the node: `{}` changes its settings and starts and stops it without sudo, and user mode runs commands as {name}",
            layout.edition.program
        ));
    }
    // nerve-run is another account: without Landlock only that keeps it
    // from the owner's files, so it reads in the owner's home what others
    // may, once it may enter the home. With Landlock nothing is said.
    #[cfg(unix)]
    if !sys.landlock() {
        steps.did(format!(
            "Warning: {}",
            crate::account::no_landlock_warning()
        ));
        let open = crate::account::home_open(&account.home);
        if let Some(w) = crate::account::home_warning(&account.home, open, &[]) {
            steps.did(format!("Warning: {w}"));
        }
    }
    // A Landlock that does not hold all the node asks for is named, with
    // what it leaves.
    #[cfg(unix)]
    if let Some(w) = crate::account::landlock_warning(sys.landlock_abi()) {
        steps.did(format!("Warning: {w}"));
    }
    #[cfg(not(unix))]
    let _ = account;
    Ok(Some(name.to_string()))
}

/// `name` as the owner, or why not: it must exist, and must not be root, one
/// of the node's own accounts nor reach the node's folders, where the keys
/// are. Root itself (the account [`ROOT`], uid 0) is the owner only where it
/// confirmed it (`root_accepted`, [`RootOwner`]): it reaches the keys, which
/// is part of what it accepted. No other account with uid 0 is.
pub fn usable_owner(
    sys: &dyn System,
    paths: &NodePaths,
    name: &str,
    root_accepted: bool,
) -> Result<Account, String> {
    let a = sys
        .account(name)?
        .ok_or_else(|| format!("there is no account {name}"))?;
    if root_accepted && name == ROOT && a.uid == 0 {
        return Ok(a);
    }
    #[cfg(unix)]
    let owner = {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(&paths.config_dir).ok().map(|m| m.uid())
    };
    #[cfg(not(unix))]
    let owner: Option<u32> = None;
    let own = [USER, crate::account::RUN_USER].contains(&name)
        || [USER_MARK, crate::account::RUN_MARK].contains(&a.comment.as_str());
    if a.uid == 0 || own || owner == Some(a.uid) {
        return Err(format!(
            "{name} is root or one of the node's own accounts, and cannot be its owner"
        ));
    }
    for dir in [&paths.config_dir, &paths.state_dir] {
        if crate::account::reaches(dir, &a) {
            return Err(format!(
                "{name} could open {}, where the node keeps its keys",
                dir.display()
            ));
        }
    }
    Ok(a)
}

/// The polkit files that let `owner` start, stop and restart the service
/// without a password: the helper and its action on every polkit, and the
/// rule, or on 0.105 the `.pkla` file; only the one this polkit reads is
/// kept. Without an owner there are none.
fn put_polkit(
    layout: &Layout,
    sys: &dyn System,
    owner: Option<&str>,
    steps: &mut Steps,
) -> Result<(), String> {
    let Some(owner) = owner else {
        return remove_polkit(layout, steps);
    };
    // Root starts and stops the service itself.
    if owner == ROOT {
        remove_polkit(layout, steps)?;
        steps.did("root needs no polkit files to start and stop the service");
        return Ok(());
    }
    let rule = layout.polkit_rule();
    let polkit = sys.polkit(&rule);
    if polkit == Polkit::Missing {
        steps.did("Warning: polkit is not installed: starting and stopping the service needs sudo");
        return Ok(());
    }
    let helper = layout.service_helper();
    let mut wrote = false;
    for (path, text, mode) in [
        (helper.clone(), service_helper_text(), 0o755),
        (layout.polkit_action(), polkit_action_text(&helper), 0o644),
        if polkit == Polkit::Rules {
            (rule.clone(), polkit_rule_text(owner), 0o644)
        } else {
            (layout.polkit_pkla(), polkit_pkla_text(owner), 0o644)
        },
    ] {
        if std::fs::read_to_string(&path).ok().as_deref() != Some(text.as_str()) {
            write_file(&path, text.as_bytes(), mode)?;
            wrote = true;
        }
    }
    let other = if polkit == Polkit::Rules {
        layout.polkit_pkla()
    } else {
        rule
    };
    remove_if_there(&other)?;
    if wrote {
        let by = match polkit {
            Polkit::Rules => format!("the rule {}", layout.polkit_rule().display()),
            _ => format!("{} (polkit 0.105)", layout.polkit_pkla().display()),
        };
        steps.did(format!(
            "polkit lets {owner} start, stop and restart the service without a password, by {by} and the helper {}",
            helper.display()
        ));
    }
    Ok(())
}

/// Removes the file at `path` when it is there.
fn remove_if_there(path: &Path) -> Result<bool, String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Removes the polkit files and the service helper again.
fn remove_polkit(layout: &Layout, steps: &mut Steps) -> Result<(), String> {
    let helper = layout.service_helper();
    for path in [
        layout.polkit_rule(),
        layout.polkit_pkla(),
        layout.polkit_action(),
        helper.clone(),
    ] {
        if remove_if_there(&path)? {
            steps.did(format!("removed {}", path.display()));
        }
    }
    // Its folder is the helper's alone.
    if let Some(dir) = helper.parent() {
        let _ = std::fs::remove_dir(dir);
    }
    Ok(())
}

/// `uninstall`: stops and removes the service, then the folders (deleted
/// with `purge`, else kept and given to root), the user and the program.
pub fn uninstall(
    layout: &Layout,
    sys: &dyn System,
    purge: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    supported(sys, "uninstall")?;
    let mut steps = Steps {
        done: Vec::new(),
        out,
    };
    let r = uninstall_steps(layout, sys, purge, &mut steps);
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

/// What `uninstall` says once nerve-run's access to its folders is off:
/// that what it made there is the owner's now, but for `not_given` files
/// with a second name (crate::acl::Report::not_given), which keep its uid.
#[cfg(target_os = "linux")]
fn gave_to_owner(not_given: usize) -> String {
    let done = "took nerve-run's access to the folders given to it off again, and gave what it made there to the owner";
    match not_given {
        0 => done.to_string(),
        n => {
            let (files, them) = if n == 1 {
                ("file", "it")
            } else {
                ("files", "them")
            };
            format!(
                "{done}, but not {n} {files} with more than one name: one may lie outside those folders, so nerve-run's uid stays on {them}, which no account has once nerve-run is removed (`sudo find <folder> -nouser` lists such files then)"
            )
        }
    }
}

fn uninstall_steps(
    layout: &Layout,
    sys: &dyn System,
    purge: bool,
    steps: &mut Steps,
) -> Result<(), String> {
    if layout.unit.exists() {
        sys.systemctl(&["disable", "--now", UNIT_NAME])?;
        steps.did(format!("stopped the service {UNIT_NAME}"));
        std::fs::remove_file(&layout.unit)
            .map_err(|e| format!("{}: {e}", layout.unit.display()))?;
        sys.systemctl(&["daemon-reload"])?;
        // Only clears a failed state systemd still shows.
        let _ = sys.systemctl(&["reset-failed", UNIT_NAME]);
        steps.did(format!(
            "removed the service unit {}",
            layout.unit.display()
        ));
    }
    // nerve-run's entries on the owner's folders come off before the
    // account goes, and its files there become the owner's: a uid nobody
    // has must not keep them, since the next account to get it would.
    #[cfg(target_os = "linux")]
    {
        let record = crate::acl::record_file(&layout.paths);
        if record.exists() {
            // What nerve-run made there goes to the owner (to root where
            // the owner's account is gone), as its uid is freed below.
            let r = crate::acl::remove_all(&record, &|owner| {
                crate::account::of_uid(owner).map_or((0, 0), |a| (a.uid, a.gid))
            });
            if !r.stale.is_empty() {
                return Err(format!(
                    "the access of nerve-run to the folders given to it could not all be taken off, so it stays and so do the node's folders: {}; run `sudo nerve-node uninstall` again once that is fixed",
                    r.errors.join("; ")
                ));
            }
            steps.did(gave_to_owner(r.not_given));
        }
    }
    let folders = [
        &layout.paths.config_dir,
        &layout.home,
        &layout.paths.state_dir,
    ];
    if purge {
        for dir in folders {
            if dir.exists() {
                std::fs::remove_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
                steps.did(format!("deleted {}", dir.display()));
            }
        }
    } else if folders.iter().any(|d| d.exists()) {
        // Their user goes; a uid nobody has must not own the keys, since
        // the next user to get it would.
        for dir in folders.iter().filter(|d| d.exists()) {
            sys.give(dir, 0, 0)?;
        }
        steps.did(format!(
            "kept {} and {} (they belong to root now; `uninstall --purge` deletes them)",
            layout.paths.config_dir.display(),
            layout.paths.state_dir.display()
        ));
    }
    remove_polkit(layout, steps)?;
    // The commands' account and its home go: a uid nobody has must not own
    // files, since the next account to get it would. Its processes ended
    // with the service.
    if layout.run_home.exists() {
        std::fs::remove_dir_all(&layout.run_home)
            .map_err(|e| format!("{}: {e}", layout.run_home.display()))?;
        steps.did(format!("deleted {}", layout.run_home.display()));
    }
    match sys.account(crate::account::RUN_USER)? {
        Some(a) if a.comment == crate::account::RUN_MARK => {
            // Also what its commands left in the folders every account may
            // write in: they outlive the service.
            #[cfg(target_os = "linux")]
            {
                let r = remove_files_of(a.uid, &layout.run_temp)?;
                let n = r.n;
                if n > 0 {
                    let places: Vec<String> = layout
                        .run_temp
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect();
                    steps.did(format!(
                        "deleted {n} {} of {} in {}",
                        if n == 1 { "file" } else { "files" },
                        crate::account::RUN_USER,
                        places.join(", ")
                    ));
                }
                if !r.left.is_empty() {
                    let more = r.left.len().saturating_sub(3);
                    let _ = writeln!(
                        steps.out,
                        "did not look into {} {}, too deep or changed meanwhile, so files of {} may be left there: {}{}",
                        r.left.len(),
                        if r.left.len() == 1 {
                            "folder"
                        } else {
                            "folders"
                        },
                        crate::account::RUN_USER,
                        r.left[..r.left.len().min(3)].join(", "),
                        if more > 0 {
                            format!(" and {more} more")
                        } else {
                            String::new()
                        }
                    );
                }
            }
            sys.remove_account(crate::account::RUN_USER)?;
            steps.did(format!("removed the account {}", crate::account::RUN_USER));
        }
        Some(_) => {
            let _ = writeln!(
                steps.out,
                "left the account {} as it is: nerve-node install did not make it",
                crate::account::RUN_USER
            );
        }
        None => {}
    }
    match sys.account(USER)? {
        Some(a) if a.comment == USER_MARK => {
            if sys.end_session(USER)? {
                steps.did(format!(
                    "ended the session of {USER} that its keyring needed"
                ));
            }
            sys.remove_account(USER)?;
            steps.did(format!("removed the user {USER}"));
        }
        Some(_) => {
            let _ = writeln!(
                steps.out,
                "left the user {USER} as it is: nerve-node install did not make it"
            );
        }
        None => {}
    }
    uninstall_parts(layout, steps)?;
    if layout.bin.exists() {
        std::fs::remove_file(&layout.bin).map_err(|e| format!("{}: {e}", layout.bin.display()))?;
        steps.did(format!("removed the program {}", layout.bin.display()));
    }
    Ok(())
}

/// A version as `nerve-node --version` prints it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(u64, u64, u64);

impl Version {
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn parse(said: &str) -> Option<Version> {
        Version::parse_of("nerve-node", said)
    }

    /// The version `layout`'s program says it has: the desktop app's line
    /// starts with its own name, so neither program takes the other's place
    /// in an update.
    pub(crate) fn of_program(layout: &Layout, said: &str) -> Option<Version> {
        Version::parse_of(layout.edition.program, said)
    }

    /// A version as `<program> --version` prints it, for another program of
    /// the release (the center's service).
    pub fn parse_of(program: &str, said: &str) -> Option<Version> {
        let v = said.trim().strip_prefix(program)?.strip_prefix(' ')?;
        let mut parts = v.split('.').map(|p| p.parse::<u64>().ok());
        let v = Version(parts.next()??, parts.next()??, parts.next()??);
        parts.next().is_none().then_some(v)
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// `update`: the new program (the latest release, checked against its
/// `SHA256SUMS`, or a file the owner gives) replaces the installed one, and
/// the service restarts. The config, the keys and the audit log are not
/// touched. A program that does not run here, or is older than the
/// installed one, is refused; one that does not start is replaced by the
/// old one again.
pub async fn update(
    layout: &Layout,
    sys: &dyn System,
    from: Option<&Path>,
    out: &mut dyn Write,
) -> Result<(), String> {
    supported(sys, "update")?;
    if !layout.installed() || !layout.bin.is_file() {
        return Err(
            "the node is not installed as a service here; `sudo nerve-node install` installs it"
                .into(),
        );
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
    sys: &dyn System,
    from: Option<&Path>,
    steps: &mut Steps<'_>,
) -> Result<(), String> {
    let program = layout.edition.program;
    let account = sys
        .account(USER)?
        .filter(|a| a.comment == USER_MARK)
        .ok_or_else(|| {
            format!("the user {USER} is missing; `sudo nerve-node install` makes it again")
        })?;
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
    let old = std::fs::read(&layout.bin).map_err(|e| format!("{}: {e}", layout.bin.display()))?;
    if new == old {
        steps.did("the installed program is that one already; nothing to update");
        return Ok(());
    }
    // Staged beside the program, so the rename that puts it in place does
    // not cross file systems.
    let staged = layout
        .bin
        .with_file_name(format!(".{}.new", layout.edition.program));
    write_file(&staged, &new, 0o755)?;
    let checked = (|| {
        let said = sys.version_of(&staged, &account)?;
        let new_v = Version::of_program(layout, &said)
            .ok_or_else(|| format!("the new program is not {program}: it says {said:?}"))?;
        let old_v = sys
            .version_of(&layout.bin, &account)
            .ok()
            .and_then(|s| Version::of_program(layout, &s));
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
            let _ = std::fs::remove_file(&staged);
            return Err(e);
        }
    };
    std::fs::rename(&staged, &layout.bin).map_err(|e| format!("{}: {e}", layout.bin.display()))?;
    let old_v = old_v.map_or_else(|| "?".to_string(), |v| v.to_string());
    steps.did(format!("replaced {program} {old_v} with {new_v}"));
    let started = sys
        .systemctl(&["restart", UNIT_NAME])
        .and_then(|()| sys.wait_running(&layout.paths));
    if let Err(e) = started {
        write_file(&layout.bin, &old, 0o755)?;
        let back = sys
            .systemctl(&["restart", UNIT_NAME])
            .and_then(|()| sys.wait_running(&layout.paths));
        steps.did(format!("put {program} {old_v} back"));
        return Err(match back {
            Ok(()) => format!("the new program did not start ({e}); the old one runs again"),
            Err(e2) => format!(
                "the new program did not start ({e}), and the old one does not either ({e2})"
            ),
        });
    }
    steps.did(format!("restarted the service {UNIT_NAME}"));
    install_parts(layout, steps)
}

/// The release file of `program` for this machine. The desktop app comes
/// for x86_64 only.
pub(crate) fn asset_name(program: &str) -> Result<String, String> {
    let node = program == crate::edition::NODE.program;
    match std::env::consts::ARCH {
        "x86_64" if cfg!(windows) => Ok(format!("{program}-x86_64-windows.exe")),
        "x86_64" if !cfg!(windows) => Ok(format!("{program}-x86_64-linux")),
        "aarch64" if !cfg!(windows) && node => Ok(format!("{program}-aarch64-linux")),
        other => Err(format!(
            "the releases have no {program} for {other}; build one (docs/dev/building.md) and give it with --from"
        )),
    }
}

/// Puts the parts of `layout`'s program beside it ([`crate::edition::Parts`]),
/// once the program is in place.
pub(crate) fn put_parts(layout: &Layout, steps: &mut Steps) -> Result<(), String> {
    if let Some(parts) = layout.edition.parts {
        for step in parts.install(&layout.bin)? {
            steps.did(step);
        }
    }
    Ok(())
}

/// [`put_parts`], and on Linux the node alone that was installed before the
/// program becomes a link to it ([`link_node`]). Windows has no node alone
/// to take over: the desktop app is the only way to the node there.
pub(crate) fn install_parts(layout: &Layout, steps: &mut Steps) -> Result<(), String> {
    put_parts(layout, steps)?;
    #[cfg(not(windows))]
    link_node(layout, steps)?;
    Ok(())
}

/// Removes them again, and on Linux that link, before the program goes.
pub(crate) fn uninstall_parts(layout: &Layout, steps: &mut Steps) -> Result<(), String> {
    // Only Linux makes the link; Windows removes the program itself.
    #[cfg(unix)]
    unlink_node(layout, steps)?;
    if let Some(parts) = layout.edition.parts {
        for step in parts.uninstall(&layout.bin)? {
            steps.did(step);
        }
    }
    Ok(())
}

/// Where `install` of the node alone put its program, beside `layout`'s
/// when that is another edition's: `nerve-node`. Not on Windows, where the
/// node alone is not released or installed.
#[cfg(not(windows))]
pub fn node_beside(layout: &Layout) -> Option<PathBuf> {
    let node = crate::edition::NODE.program;
    if layout.edition.program == node {
        return None;
    }
    Some(beside(layout, node))
}

/// The program `program` in `layout`'s folder, with its extension.
#[cfg(not(windows))]
fn beside(layout: &Layout, program: &str) -> PathBuf {
    let mut p = layout.bin.with_file_name(program);
    if let Some(ext) = layout.bin.extension() {
        p.set_extension(ext);
    }
    p
}

/// The desktop app's program beside `layout`'s, when the app is installed
/// there and `layout` is the node alone's: the app took the node over, so
/// the service, the parts and the program are the app's, and only its own
/// uninstall removes them all ([`hand_over_uninstall`]). Not on Windows,
/// where no node alone is installed beside the app.
#[cfg(not(windows))]
pub fn app_beside(layout: &Layout) -> Option<PathBuf> {
    if layout.edition.program != crate::edition::NODE.program {
        return None;
    }
    Some(beside(layout, crate::edition::DESKTOP_PROGRAM)).filter(|p| p.is_file())
}

/// `uninstall` of the node alone where the desktop app took the node over:
/// the app's program at `app` runs its own `uninstall`, which removes the
/// service, the app's parts and both programs, and what it says is passed
/// on. Its log and errors go to stderr as they come.
#[cfg(not(windows))]
pub fn hand_over_uninstall(app: &Path, purge: bool, out: &mut dyn Write) -> Result<(), String> {
    use std::io::BufReader;
    use std::process::{Command, Stdio};
    let _ = writeln!(
        out,
        "the desktop app is installed ({}): its uninstall removes the node with the app",
        app.display()
    );
    let mut cmd = Command::new(app);
    cmd.arg("uninstall");
    if purge {
        cmd.arg("--purge");
    }
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // The app may have been written a moment ago.
    let mut child = nerve_transport::files::retry_busy(|| cmd.spawn())
        .map_err(|e| format!("{}: {e}", app.display()))?;
    let stderr = child.stderr.take().expect("piped");
    let said = std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            eprintln!("{line}");
        }
    });
    for line in BufReader::new(child.stdout.take().expect("piped"))
        .lines()
        .map_while(Result::ok)
    {
        let _ = writeln!(out, "{line}");
    }
    let status = child
        .wait()
        .map_err(|e| format!("{}: {e}", app.display()))?;
    let _ = said.join();
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "`{} uninstall` did not finish ({status}); what it said is above",
            app.display()
        ))
    }
}

/// A node installed with `nerve-node` and then taken over by the desktop
/// app keeps its terminal command on Linux: the old program becomes a link
/// to the app's, which runs the CLI as `nerve-node` does, so one program
/// stays and it is never an older one. The edition comes from the program
/// the link leads to (crate::edition), so `nerve-node update` through it
/// updates the app. Nothing is made where no node alone was installed.
#[cfg(not(windows))]
fn link_node(layout: &Layout, steps: &mut Steps) -> Result<(), String> {
    let Some(node) = node_beside(layout) else {
        return Ok(());
    };
    // A link is there already (this one, or another's to leave alone).
    if !std::fs::symlink_metadata(&node).is_ok_and(|m| m.is_file()) {
        return Ok(());
    }
    let at = |e: std::io::Error| format!("{}: {e}", node.display());
    // Made beside it first and moved over it, so the command is never
    // missing.
    let name = node
        .file_name()
        .map_or_else(Default::default, |n| n.to_string_lossy());
    let tmp = node.with_file_name(format!(".{name}.link"));
    let _ = std::fs::remove_file(&tmp);
    symlink(&layout.bin, &tmp).map_err(at)?;
    let r = std::fs::rename(&tmp, &node).map_err(at);
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r?;
    steps.did(format!(
        "{} is a link to {} now, so the command {} runs it",
        node.display(),
        layout.bin.display(),
        crate::edition::NODE.program
    ));
    Ok(())
}

#[cfg(unix)]
fn symlink(target: &Path, at: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, at)
}

#[cfg(not(any(unix, windows)))]
fn symlink(_: &Path, _: &Path) -> std::io::Result<()> {
    Err(std::io::Error::other("the link is made on Linux only"))
}

/// Removes the link [`link_node`] made, and no other.
#[cfg(unix)]
fn unlink_node(layout: &Layout, steps: &mut Steps) -> Result<(), String> {
    let Some(node) = node_beside(layout) else {
        return Ok(());
    };
    let ours = std::fs::symlink_metadata(&node).is_ok_and(|m| m.file_type().is_symlink())
        && std::fs::read_link(&node).is_ok_and(|t| t == layout.bin);
    if !ours {
        return Ok(());
    }
    std::fs::remove_file(&node).map_err(|e| format!("{}: {e}", node.display()))?;
    steps.did(format!("removed the link {}", node.display()));
    Ok(())
}

/// What `service` does to the installed service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAction {
    Start,
    Stop,
    Restart,
}

impl ServiceAction {
    pub fn word(self) -> &'static str {
        match self {
            ServiceAction::Start => "start",
            ServiceAction::Stop => "stop",
            ServiceAction::Restart => "restart",
        }
    }
}

/// The installed service, as `service status` says it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceState {
    /// running, stopped, starting, stopping or failed.
    pub state: String,
    /// Whether it starts with the machine, when the system says.
    pub enabled: Option<bool>,
}

/// systemd's words for a unit, from `systemctl show`, as [`ServiceState`].
fn unit_state_of(shown: &str) -> ServiceState {
    let field = |k: &str| {
        shown
            .lines()
            .find_map(|l| l.strip_prefix(k)?.strip_prefix('='))
            .unwrap_or_default()
            .trim()
            .to_string()
    };
    let state = match field("ActiveState").as_str() {
        "active" | "reloading" | "refreshing" => "running",
        "activating" => "starting",
        "deactivating" => "stopping",
        "failed" => "failed",
        _ => "stopped",
    };
    let enabled = match field("UnitFileState").as_str() {
        "" => None,
        s => Some(s == "enabled" || s == "enabled-runtime"),
    };
    ServiceState {
        state: state.into(),
        enabled,
    }
}

/// `service status`: whether the node is installed as a service here, its
/// state (`None`: not installed), and the program it runs with its version.
/// Anyone may ask; the program says its version as the one who asks.
pub fn service_status(layout: &Layout, state: Option<&ServiceState>) -> serde_json::Value {
    let version = layout
        .bin
        .is_file()
        .then(|| {
            std::process::Command::new(&layout.bin)
                .arg("--version")
                .stdin(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .output()
                .ok()
        })
        .flatten()
        .filter(|o| o.status.success())
        .and_then(|o| Version::of_program(layout, &String::from_utf8_lossy(&o.stdout)))
        .map(|v| v.to_string());
    serde_json::json!({
        "installed": state.is_some(),
        "state": state.map(|s| s.state.as_str()),
        "enabled": state.and_then(|s| s.enabled),
        "program": layout.bin.display().to_string(),
        "present": layout.bin.is_file(),
        "version": version,
    })
}

/// The state of the unit, `None` when the node is not installed here.
pub fn unit_status(layout: &Layout, sys: &dyn System) -> Result<Option<ServiceState>, String> {
    if !layout.installed_at_unit() {
        return Ok(None);
    }
    sys.unit_state().map(Some)
}

/// `service start`, `stop` and `restart`: the installed service, as
/// systemctl does it, waiting until a node that starts answers.
pub fn control(
    layout: &Layout,
    sys: &dyn System,
    action: ServiceAction,
    out: &mut dyn Write,
) -> Result<(), String> {
    // Without root, the helper or systemctl asks polkit, whose rule or
    // `.pkla` file lets the owners do it (crate::owner); it refuses everyone
    // else.
    supported_without_root(sys, &format!("service {}", action.word()))?;
    if !layout.installed_at_unit() {
        return Err(
            "the node is not installed as a service here; `sudo nerve-node install` installs it"
                .into(),
        );
    }
    let helper = layout.service_helper();
    if !sys.is_root() && helper.is_file() && sys.has_pkexec() {
        // Through the helper's own polkit action, which the owners have
        // without a password on every polkit, 0.105 too.
        sys.pkexec(&helper, &[action.word()])?;
    } else {
        sys.systemctl(&[action.word(), UNIT_NAME])?;
    }
    let said = match action {
        ServiceAction::Stop => {
            let again = if sys.unit_state()?.enabled == Some(true) {
                "; it starts again with the machine"
            } else {
                ""
            };
            format!("stopped the service {UNIT_NAME}: the node ended its links{again}")
        }
        ServiceAction::Start | ServiceAction::Restart => {
            sys.wait_running(&layout.paths)?;
            let did = if action == ServiceAction::Start {
                "started"
            } else {
                "restarted"
            };
            format!("{did} the service {UNIT_NAME}, and the node answers")
        }
    };
    let _ = writeln!(out, "{said}");
    Ok(())
}

/// Downloads `asset` from the release at `base` and checks it against the
/// release's `SHA256SUMS`.
pub async fn fetch_release(base: &str, asset: &str) -> Result<Vec<u8>, String> {
    nerve_transport::init_crypto();
    let sums = download(&format!("{base}/SHA256SUMS"), SUMS_MAX).await?;
    let want = String::from_utf8_lossy(&sums)
        .lines()
        .find_map(|l| {
            let (hash, name) = l.split_once(char::is_whitespace)?;
            let name = name.trim_start();
            let name = name.strip_prefix('*').unwrap_or(name);
            (name == asset).then(|| hash.to_ascii_lowercase())
        })
        .ok_or_else(|| format!("the release's SHA256SUMS lists no {asset}"))?;
    let program = download(&format!("{base}/{asset}"), PROGRAM_MAX).await?;
    let got: String = ring::digest::digest(&ring::digest::SHA256, &program)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if got != want {
        return Err(format!(
            "the downloaded {asset} does not match its line in SHA256SUMS; nothing changed"
        ));
    }
    Ok(program)
}

/// `GET url`, following redirects (never from https to http), through the
/// proxy `HTTPS_PROXY` names: the download the center's one-click model
/// install shares (`nerve_transport::download`). Errors name the host, not
/// the whole address, which may hold a signed query.
async fn download(url: &str, max: usize) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    let opts = nerve_transport::download::Options {
        max: max as u64,
        idle: nerve_transport::http::HEAD_TIMEOUT,
        // Five redirects, as the node's own loop followed before.
        hops: 5,
        cancel: None,
    };
    nerve_transport::download::fetch(url, &mut body, &opts, &mut |_, _| {}).await?;
    Ok(body)
}

/// The server and the request target (path and query) of an http(s) URL.
#[cfg(all(test, target_os = "linux"))]
fn split_url(url: &str) -> Result<(nerve_proto::link::CenterUrl, String), String> {
    nerve_transport::download::split_url(url)
}

/// Writes `data` to `path` through a temporary file beside it and a rename,
/// with `mode`.
pub fn write_file(path: &Path, data: &[u8], mode: u32) -> Result<(), String> {
    let at = |e: std::io::Error| format!("{}: {e}", path.display());
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).map_err(at)?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = dir.join(format!(
        ".{name}.{}.tmp",
        nerve_transport::keys::random_token(8)
    ));
    let r = (|| {
        std::fs::write(&tmp, data)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
        }
        #[cfg(not(unix))]
        let _ = mode;
        std::fs::rename(&tmp, path)
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r.map_err(at)
}

pub fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| format!("{}: {e}", path.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

/// Root's file access as the owner of `dir`, on this thread, while the
/// result lives ([`crate::account::FsAs`]): what root writes into a folder
/// of the node's user then cannot reach through a link that user made more
/// than that user may. A link in place of `dir` is refused. Nothing changes
/// for another caller than root, or a folder of root's.
pub fn as_owner_of(dir: &Path) -> Result<Option<impl Drop>, String> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        if m.file_type().is_symlink() {
            return Err(format!(
                "{} is a link; the node's folders are folders, and root does not follow it",
                dir.display()
            ));
        }
        if nerve_transport::net::euid() != 0 || m.uid() == 0 {
            return Ok(None);
        }
        let owner = Account {
            name: format!("uid {}", m.uid()),
            uid: m.uid(),
            gid: m.gid(),
            comment: String::new(),
            home: dir.to_path_buf(),
            groups: vec![m.gid()],
        };
        crate::account::FsAs::new(&owner)
            .map(Some)
            .map_err(|e| format!("cannot write as the owner of {}: {e}", dir.display()))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = dir;
        Ok(None::<NoDrop>)
    }
}

#[cfg(not(target_os = "linux"))]
struct NoDrop;
#[cfg(not(target_os = "linux"))]
impl Drop for NoDrop {
    fn drop(&mut self) {}
}

#[cfg(not(target_os = "linux"))]
fn chown(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        std::os::unix::fs::lchown(path, Some(uid), Some(gid))
            .map_err(|e| format!("{}: {e}", path.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, uid, gid);
        Ok(())
    }
}

/// Gives `path` and everything below it to `uid`:`gid`. Links are changed
/// themselves and never followed. On Linux each folder is opened without
/// following a link and read through its descriptor, so a folder that the
/// node's user swaps for a link meanwhile is not walked.
fn chown_tree(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        chown_below(path, path, uid, gid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        chown_tree_by_path(path, uid, gid)
    }
}

/// [`chown_tree`] on Linux: `at` is the path to open (below a folder's
/// descriptor), `shown` the one errors name.
#[cfg(target_os = "linux")]
fn chown_below(at: &Path, shown: &Path, uid: u32, gid: u32) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let err = |e: std::io::Error| format!("{}: {e}", shown.display());
    let dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(at);
    let dir = match dir {
        Ok(d) => d,
        // A file or a link: changed itself, through a descriptor of the
        // entry (not followed), so the file checked is the one changed.
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTDIR | libc::ELOOP)) => {
            return chown_entry(at, uid, gid).map_err(|e| format!("{}: {e}", shown.display()));
        }
        Err(e) => return Err(err(e)),
    };
    std::os::unix::fs::fchown(&dir, Some(uid), Some(gid)).map_err(err)?;
    let fd = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
    for e in std::fs::read_dir(&fd).map_err(err)? {
        let name = e.map_err(err)?.file_name();
        chown_below(&fd.join(&name), &shown.join(&name), uid, gid)?;
    }
    Ok(())
}

/// How many folder levels [`remove_files_of`] goes down: each level holds
/// a descriptor open, and any account can make a tree in `/tmp` deeper than
/// the descriptors a process may have.
#[cfg(target_os = "linux")]
const WALK_DEPTH: usize = 64;

/// What [`remove_files_of`] did.
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
struct Removed {
    /// Files and folders deleted.
    n: usize,
    /// Folders not looked into, deeper than [`WALK_DEPTH`] or changed while
    /// they were looked at: files of the account may be left in them.
    left: Vec<String>,
    errors: Vec<String>,
}

/// Deletes what the account `uid` has in `dirs`, the folders every account
/// may write in, as its uid is about to be freed. Each folder is walked
/// through descriptors, on its own file system only, and no link below it
/// is followed: what another account swaps in meanwhile is not walked. The
/// folder itself is root's and may be a link of root's (`/var/tmp -> /tmp`,
/// `/dev/shm -> /run/shm`), so it is followed, and walked once. A folder of
/// `uid`'s that still holds another account's files is given to root.
#[cfg(target_os = "linux")]
fn remove_files_of(uid: u32, dirs: &[PathBuf]) -> Result<Removed, String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut walk = Removed::default();
    let mut seen = Vec::new();
    for dir in dirs {
        let real = match std::fs::canonicalize(dir) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                walk.errors.push(format!("{}: {e}", dir.display()));
                continue;
            }
        };
        if seen.contains(&real) {
            continue;
        }
        seen.push(real.clone());
        let f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&real);
        let f = match f {
            Ok(f) => f,
            Err(e) => {
                walk.errors.push(format!("{}: {e}", real.display()));
                continue;
            }
        };
        let dev = f
            .metadata()
            .map_err(|e| format!("{}: {e}", real.display()))?
            .dev();
        remove_below(&f, &real, uid, dev, 0, &mut walk);
    }
    if !walk.errors.is_empty() {
        return Err(format!(
            "the files {} left could not all be deleted, so the account stays: {}; run `sudo nerve-node uninstall` again once that is fixed",
            crate::account::RUN_USER,
            walk.errors.join("; ")
        ));
    }
    Ok(walk)
}

/// [`remove_files_of`] below the open folder `dir`, shown as `shown`,
/// `depth` levels below the folder it was given.
#[cfg(target_os = "linux")]
fn remove_below(
    dir: &std::fs::File,
    shown: &Path,
    uid: u32,
    dev: u64,
    depth: usize,
    walk: &mut Removed,
) {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let fd = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
    let names: Vec<std::ffi::OsString> = match std::fs::read_dir(&fd) {
        Ok(r) => r.filter_map(|e| e.ok().map(|e| e.file_name())).collect(),
        Err(e) => {
            walk.errors.push(format!("{}: {e}", shown.display()));
            return;
        }
    };
    for name in names {
        let at = fd.join(&name);
        let here = shown.join(&name);
        // Gone meanwhile: nothing to delete.
        let Ok(m) = std::fs::symlink_metadata(&at) else {
            continue;
        };
        // The folder as it was opened, its inode checked: it is given to
        // root through this descriptor, not by its name.
        let mut opened = None;
        if m.is_dir() {
            // Another file system mounted here is not this folder's.
            if m.dev() != dev {
                continue;
            }
            if depth >= WALK_DEPTH {
                walk.left.push(here.display().to_string());
                continue;
            }
            let sub = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&at);
            match sub {
                // The folder looked at, not one swapped in since.
                Ok(sub) if sub.metadata().is_ok_and(|s| s.ino() == m.ino()) => {
                    remove_below(&sub, &here, uid, dev, depth + 1, walk);
                    opened = Some(sub);
                }
                _ => {
                    walk.left.push(here.display().to_string());
                    continue;
                }
            }
        }
        if m.uid() != uid {
            continue;
        }
        let Ok(c) = std::ffi::CString::new(name.as_bytes()) else {
            continue;
        };
        let flag = if m.is_dir() { libc::AT_REMOVEDIR } else { 0 };
        // SAFETY: a valid C string, relative to the open folder `dir`.
        if unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), flag) } == 0 {
            walk.n += 1;
            continue;
        }
        let e = std::io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::ENOENT) => {}
            // Another account's files are in it: the folder is root's.
            // Whoever may rename entries in `dir` can have put something
            // else under its name by now.
            Some(libc::ENOTEMPTY | libc::EEXIST) => {
                if let Some(sub) = &opened
                    && let Err(e) = give_folder(sub, &here, (0, 0))
                {
                    walk.errors.push(e);
                }
            }
            _ => walk.errors.push(format!("{}: {e}", here.display())),
        }
    }
}

/// Gives the folder open as `folder`, shown as `shown`, to `to` (uid, gid)
/// through its descriptor: the folder that was walked, whatever its name
/// leads to now.
#[cfg(target_os = "linux")]
fn give_folder(folder: &std::fs::File, shown: &Path, to: (u32, u32)) -> Result<(), String> {
    std::os::unix::fs::fchown(folder, Some(to.0), Some(to.1))
        .map_err(|e| format!("{}: {e}", shown.display()))
}

/// Gives the file or link at `at` (not followed) to `uid`:`gid`. A file
/// with more than one name is refused: its other name can be anywhere on
/// the same file system, as a hard link the node's user made to a file of
/// root's.
#[cfg(target_os = "linux")]
fn chown_entry(at: &Path, uid: u32, gid: u32) -> Result<(), String> {
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    let path = std::ffi::CString::new(at.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    // Through libc, not `OpenOptions::custom_flags`: on musl, the C library
    // of the released programs, the standard library takes O_PATH out of
    // the flags (musl's O_ACCMODE holds it), and the entry would be opened
    // for reading, which a socket refuses, a link fails and a FIFO waits on.
    // SAFETY: a valid C string; the new descriptor is owned below.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: open returned a fresh descriptor nothing else owns.
    let f = std::fs::File::from(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) });
    let m = f.metadata().map_err(|e| e.to_string())?;
    if m.nlink() > 1 {
        return Err(
            "it has another name (a hard link), which may be outside the node's folders; remove it and run this again".into(),
        );
    }
    // SAFETY: an empty NUL-terminated path with AT_EMPTY_PATH on an open
    // descriptor: the call changes that inode.
    let r = unsafe {
        libc::fchownat(
            std::os::fd::AsRawFd::as_raw_fd(&f),
            c"".as_ptr(),
            uid,
            gid,
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if r != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn chown_tree_by_path(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    chown(path, uid, gid)?;
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.is_dir() {
        let entries = std::fs::read_dir(path).map_err(|e| format!("{}: {e}", path.display()))?;
        for e in entries {
            let e = e.map_err(|e| format!("{}: {e}", path.display()))?;
            chown_tree_by_path(&e.path(), uid, gid)?;
        }
    }
    Ok(())
}

/// A command root runs on a node whose folders belong to another user (the
/// installed node's `nerve`) runs as that user, so that what it writes stays
/// readable to the node. Called before anything else runs in the process:
/// it changes the user of the calling thread only where the C library does
/// not change every thread's. With `keep_root` (setup) root stays the saved
/// id, so the process can get it back for one thing, making an account
/// ([`System::add_user`]); a process of the node's user cannot trace or
/// read it, since its ids are not all that user's.
pub fn become_owner(paths: &NodePaths, keep_root: bool) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Some(m) = owner_to_become(paths) else {
            return Ok(());
        };
        #[cfg(target_os = "linux")]
        let (setgid, setuid) = {
            let saved = |id: u32| if keep_root { 0 } else { id };
            (
                // SAFETY: plain calls without pointers.
                move |g: u32| unsafe { libc::setresgid(g, g, saved(g)) },
                move |u: u32| unsafe { libc::setresuid(u, u, saved(u)) },
            )
        };
        #[cfg(not(target_os = "linux"))]
        let (setgid, setuid) = {
            let _ = keep_root;
            // SAFETY: plain calls without pointers.
            (
                |g: u32| unsafe { libc::setgid(g) },
                |u: u32| unsafe { libc::setuid(u) },
            )
        };
        // SAFETY: the empty group list; groups first, the user last, while
        // root may still change both.
        let failed = unsafe { libc::setgroups(0, std::ptr::null()) != 0 }
            || setgid(m.gid()) != 0
            || setuid(m.uid()) != 0;
        if failed {
            return Err(format!(
                "cannot run as the owner (uid {}) of {}: {}",
                m.uid(),
                paths.config_dir.display(),
                std::io::Error::last_os_error()
            ));
        }
        // The session bus these name is the caller's, not the owner's: the
        // system keyring is found in the owner's session (/run/user/<uid>).
        // SAFETY: `main` calls this while the process has one thread.
        unsafe {
            std::env::remove_var("DBUS_SESSION_BUS_ADDRESS");
            std::env::remove_var("XDG_RUNTIME_DIR");
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (paths, keep_root);
        Ok(())
    }
}

/// The folders whose owner root's command becomes ([`become_owner`]): the
/// first of them that is there, when this process is root and they are not
/// root's.
#[cfg(unix)]
fn owner_to_become(paths: &NodePaths) -> Option<std::fs::Metadata> {
    use std::os::unix::fs::MetadataExt;
    if nerve_transport::net::euid() != 0 {
        return None;
    }
    [&paths.config_dir, &paths.state_dir]
        .iter()
        .find_map(|d| std::fs::metadata(d).ok())
        .filter(|m| m.uid() != 0)
}

/// Whether [`become_owner`] makes this process another user.
pub fn becomes_owner(paths: &NodePaths) -> bool {
    #[cfg(unix)]
    return owner_to_become(paths).is_some();
    #[cfg(not(unix))]
    {
        let _ = paths;
        false
    }
}

/// A command on the installed node from a user who is neither root nor the
/// node's own stops here and says how to run it, instead of failing on a
/// folder it may not open.
pub fn check_access(paths: &NodePaths) -> Result<(), String> {
    let layout = Layout::system();
    if *paths != layout.paths || !layout.installed() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let me = nerve_transport::net::euid();
        let owner = std::fs::metadata(&paths.config_dir).map(|m| m.uid());
        if me != 0 && owner.is_ok_and(|o| o != me) {
            return Err(format!(
                "the node is installed as a service, and its files belong to the user {USER}: run `sudo nerve-node …`"
            ));
        }
    }
    // Only `nerve` and the administrators may open the folders.
    #[cfg(windows)]
    if !crate::win_host::is_admin() && crate::win_user::current_user().as_deref() != Ok(USER) {
        return Err(format!(
            "the node is installed as a service, and its files are open to the user {USER} and the administrators only: the app asks Windows for an administrator's rights where they are needed"
        ));
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) mod tests {
    use super::*;
    use nerve_policy::settings::SettingsStore;
    use std::cell::RefCell;

    /// A machine in a temporary folder: the user is the test's own, and
    /// systemctl and the node's start are recorded.
    pub(crate) struct Fake {
        user: RefCell<Option<Account>>,
        /// The other accounts of the machine.
        others: RefCell<Vec<Account>>,
        calls: RefCell<Vec<String>>,
        /// The folders given to another user, and to whom.
        given: RefCell<Vec<(PathBuf, u32)>>,
        /// Whether a node started by the service answers.
        starts: std::cell::Cell<bool>,
        /// Whether the node's user keeps a session (a keyring's linger).
        lingers: std::cell::Cell<bool>,
        /// What polkit takes here.
        pub(crate) polkit: std::cell::Cell<Polkit>,
        /// Whether the command runs as root, and whether pkexec is there.
        pub(crate) root: std::cell::Cell<bool>,
        pub(crate) pkexec_here: std::cell::Cell<bool>,
        /// Whether the kernel has Landlock.
        pub(crate) landlock: std::cell::Cell<bool>,
        /// The kernel's Landlock ABI, for what `install` says of it.
        pub(crate) landlock_abi: std::cell::Cell<Option<i32>>,
    }

    impl Fake {
        pub(crate) fn new() -> Fake {
            Fake {
                user: RefCell::new(None),
                others: RefCell::new(vec![other("alice", 4242), other("root", 0)]),
                calls: RefCell::new(Vec::new()),
                given: RefCell::new(Vec::new()),
                starts: std::cell::Cell::new(true),
                lingers: std::cell::Cell::new(false),
                polkit: std::cell::Cell::new(Polkit::Rules),
                root: std::cell::Cell::new(true),
                pkexec_here: std::cell::Cell::new(true),
                landlock: std::cell::Cell::new(true),
                landlock_abi: std::cell::Cell::new(None),
            }
        }

        pub(crate) fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    fn me() -> Account {
        // SAFETY: plain getters.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        Account {
            name: USER.into(),
            uid,
            gid,
            comment: USER_MARK.into(),
            home: "/var/lib/nerve".into(),
            groups: vec![gid],
        }
    }

    /// An account that is not the test's own.
    fn other(name: &str, uid: u32) -> Account {
        Account {
            name: name.into(),
            uid,
            gid: uid,
            comment: String::new(),
            home: format!("/home/{name}").into(),
            groups: vec![uid],
        }
    }

    impl System for Fake {
        fn is_root(&self) -> bool {
            self.root.get()
        }
        fn landlock(&self) -> bool {
            self.landlock.get()
        }
        fn landlock_abi(&self) -> Option<i32> {
            self.landlock_abi.get()
        }
        fn has_pkexec(&self) -> bool {
            self.pkexec_here.get()
        }
        fn pkexec(&self, program: &Path, args: &[&str]) -> Result<(), String> {
            self.calls.borrow_mut().push(format!(
                "pkexec {} {}",
                program.display(),
                args.join(" ")
            ));
            Ok(())
        }
        fn has_systemd(&self) -> bool {
            true
        }
        fn account(&self, name: &str) -> Result<Option<Account>, String> {
            if name == USER {
                return Ok(self.user.borrow().clone());
            }
            Ok(self
                .others
                .borrow()
                .iter()
                .find(|a| a.name == name)
                .cloned())
        }
        /// `nerve` is the test's own account; any other is another uid.
        fn add_account(&self, name: &str, home: &Path, mark: &str) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(format!("useradd {name} {}", home.display()));
            if name == USER {
                *self.user.borrow_mut() = Some(me());
            } else {
                let uid = 5000 + self.others.borrow().len() as u32;
                self.others.borrow_mut().push(Account {
                    comment: mark.into(),
                    home: home.into(),
                    ..other(name, uid)
                });
            }
            Ok(())
        }
        fn remove_account(&self, name: &str) -> Result<(), String> {
            self.calls.borrow_mut().push(format!("userdel {name}"));
            if name == USER {
                *self.user.borrow_mut() = None;
            } else {
                self.others.borrow_mut().retain(|a| a.name != name);
            }
            Ok(())
        }
        fn systemctl(&self, args: &[&str]) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(format!("systemctl {}", args.join(" ")));
            Ok(())
        }
        /// Running after the last start or restart, until a stop.
        fn unit_state(&self) -> Result<ServiceState, String> {
            let calls = self.calls.borrow();
            let last = calls.iter().rev().find_map(|c| {
                // The helper's word is the last of a pkexec call.
                let c = c
                    .strip_prefix("systemctl ")
                    .or_else(|| c.strip_prefix("pkexec ").and_then(|r| r.rsplit(' ').next()))?;
                if c.starts_with("start") || c.starts_with("restart") {
                    Some("running")
                } else if c.starts_with("stop") || c.starts_with("disable --now") {
                    Some("stopped")
                } else {
                    None
                }
            });
            Ok(ServiceState {
                state: last.unwrap_or("stopped").into(),
                enabled: Some(calls.iter().any(|c| c.starts_with("systemctl enable"))),
            })
        }
        /// The test may give files to itself only; giving them to anyone
        /// else is recorded.
        fn give(&self, path: &Path, uid: u32, gid: u32) -> Result<(), String> {
            if uid == me().uid {
                chown_tree(path, uid, gid)
            } else {
                self.given.borrow_mut().push((path.to_path_buf(), uid));
                Ok(())
            }
        }
        fn wait_running(&self, _paths: &NodePaths) -> Result<(), String> {
            if self.starts.get() {
                Ok(())
            } else {
                Err("the node does not answer".into())
            }
        }
        /// A program here is a text file whose first line is what it says.
        fn version_of(&self, program: &Path, account: &Account) -> Result<String, String> {
            assert_eq!(account.comment, USER_MARK);
            let text = std::fs::read_to_string(program).map_err(|e| e.to_string())?;
            Ok(text.lines().next().unwrap_or_default().to_string())
        }
        fn end_session(&self, name: &str) -> Result<bool, String> {
            if !self.lingers.replace(false) {
                return Ok(false);
            }
            self.calls
                .borrow_mut()
                .push(format!("loginctl disable-linger {name}"));
            Ok(true)
        }

        fn polkit(&self, _rule: &Path) -> Polkit {
            self.polkit.get()
        }
    }

    fn layout(root: &Path) -> Layout {
        Layout {
            unit: root.join("etc/systemd/system").join(UNIT_NAME),
            bin: root.join("usr/local/bin/nerve-node"),
            home: root.join("var/lib/nerve"),
            run_home: root.join("var/lib/nerve-run"),
            run_temp: vec![root.join("tmp"), root.join("var/tmp"), root.join("dev/shm")],
            paths: NodePaths::new(root.join("etc/nerve"), root.join("var/lib/nerve/state")),
            release: "http://127.0.0.1:1/none".into(),
            edition: &crate::edition::NODE,
        }
    }

    /// Installs a "program" saying `version` from a file in `root`.
    fn installed(root: &Path, sys: &Fake, version: &str) -> Layout {
        let l = layout(root);
        let exe = root.join("download/nerve-node-x86_64-linux");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, format!("nerve-node {version}\n")).unwrap();
        let mut out = Vec::new();
        install(&l, sys, &exe, "alice", &mut out).unwrap();
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

    fn mode(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    /// Without Landlock `install` says what nerve-run may read of the
    /// owner's home: what others may, once it is given a folder there, and
    /// at once where the home is open to others. With Landlock it says
    /// nothing of it (owner's decision of 2026-10-21).
    #[test]
    fn install_warns_of_the_home_only_without_landlock() {
        use std::os::unix::fs::PermissionsExt;
        for landlock in [false, true] {
            let d = tempfile::tempdir().unwrap();
            let sys = Fake::new();
            sys.landlock.set(landlock);
            let home = d.path().join("alice");
            std::fs::create_dir(&home).unwrap();
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o755)).unwrap();
            sys.others.borrow_mut()[0].home = home.clone();
            let l = layout(d.path());
            let exe = d.path().join("nerve-node");
            std::fs::write(&exe, "nerve-node 1.0.0\n").unwrap();
            let mut out = Vec::new();
            install(&l, &sys, &exe, "alice", &mut out).unwrap();
            let out = String::from_utf8(out).unwrap();
            assert!(out.contains("alice is the owner of the node"), "{out}");
            assert_eq!(
                out.contains(
                    "this kernel has no Landlock, so the commands of nerve-run run without it"
                ),
                !landlock,
                "{out}"
            );
            assert_eq!(
                out.contains(&format!(
                    "Without Landlock, nerve-run can read every file in your home {}",
                    home.display()
                )) && out.contains("mode 755"),
                !landlock,
                "{out}"
            );
            assert!(landlock || out.contains("umask 027"), "{out}");
        }
    }

    /// `install` names what a Landlock below ABI 6 does not guard, below
    /// ABI 3 truncating files too, which the installed node still confines
    /// its commands with; from ABI 6 on it says nothing of it.
    #[test]
    fn install_names_the_guards_an_older_landlock_lacks() {
        for (abi, landlock, said) in [
            (
                Some(4),
                true,
                Some("Landlock is ABI 4, which does not guard device ioctls"),
            ),
            (
                Some(2),
                true,
                Some("Landlock is ABI 2, which does not guard truncating files"),
            ),
            (Some(6), true, None),
        ] {
            let d = tempfile::tempdir().unwrap();
            let sys = Fake::new();
            sys.landlock.set(landlock);
            sys.landlock_abi.set(abi);
            let home = d.path().join("alice");
            std::fs::create_dir(&home).unwrap();
            sys.others.borrow_mut()[0].home = home;
            let l = layout(d.path());
            let exe = d.path().join("nerve-node");
            std::fs::write(&exe, "nerve-node 1.0.0\n").unwrap();
            let mut out = Vec::new();
            install(&l, &sys, &exe, "alice", &mut out).unwrap();
            let out = String::from_utf8(out).unwrap();
            match said {
                Some(s) => assert!(
                    out.contains(&format!("Warning: this kernel's {s}")),
                    "{out}"
                ),
                None => assert!(!out.contains("this kernel's Landlock"), "{out}"),
            }
        }
    }

    #[test]
    fn install_puts_the_service_under_its_own_user() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = layout(d.path());
        // The program as the release names it lands as nerve-node.
        let exe = d.path().join("download/nerve-node-x86_64-linux");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, "nerve-node 1.0.0\n").unwrap();
        let mut out = Vec::new();
        install(&l, &sys, &exe, "alice", &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("made the user nerve"), "{out}");
        assert!(
            out.contains("made the account commands run as, nerve-run (uid"),
            "{out}"
        );
        assert!(out.contains("alice is the owner of the node"), "{out}");
        assert!(out.contains("nerve-node center add"), "{out}");
        // The two accounts, each made once with its home; no group.
        assert_eq!(
            sys.calls(),
            [
                format!("useradd nerve {}", l.home.display()),
                format!("useradd nerve-run {}", l.run_home.display()),
                "systemctl daemon-reload".into(),
                format!("systemctl enable {UNIT_NAME}"),
                format!("systemctl restart {UNIT_NAME}"),
            ]
        );
        let run = sys.account(crate::account::RUN_USER).unwrap().unwrap();
        assert_eq!(run.comment, crate::account::RUN_MARK);
        assert_eq!(run.home, l.run_home);
        assert_eq!(run.groups, [run.gid], "no other groups");
        // Its home is its own and closed to others.
        assert_eq!(mode(&l.run_home), 0o700);
        assert!(sys.given.borrow().contains(&(l.run_home.clone(), run.uid)));
        // polkit lets the owner start and stop this unit only.
        let rule = l.polkit_rule();
        assert_eq!(
            rule,
            d.path().join("etc/polkit-1/rules.d/50-nerve-node.rules")
        );
        assert_eq!(
            std::fs::read_to_string(&rule).unwrap(),
            polkit_rule_text("alice")
        );
        assert!(polkit_rule_text("alice").contains("subject.user != \"alice\""));
        assert_eq!(mode(&rule), 0o644);
        // The program, the unit, and the folders, private to the user.
        assert_eq!(std::fs::read(&l.bin).unwrap(), b"nerve-node 1.0.0\n");
        assert_eq!(mode(&l.bin), 0o755);
        let unit = std::fs::read_to_string(&l.unit).unwrap();
        assert_eq!(unit, l.unit_text(Some("alice")));
        assert!(unit.contains("\nUser=nerve\nGroup=nerve\n"), "{unit}");
        assert!(!unit.contains("SupplementaryGroups"), "{unit}");
        // The owner is named where everyone reads and only root writes.
        assert!(
            unit.contains("\nEnvironment=NERVE_NODE_OWNER=alice\n"),
            "{unit}"
        );
        assert_eq!(owner_in_unit(&unit).as_deref(), Some("alice"));
        // The one privilege: switching to the account of the commands. Nothing
        // narrows the bounding set or sets no_new_privs, which an allowed
        // sudo command needs.
        let caps: Vec<&str> = unit
            .lines()
            .filter(|l| l.contains("Capabilit") || l.contains("NoNewPrivileges"))
            .collect();
        assert_eq!(caps, ["AmbientCapabilities=CAP_SETUID CAP_SETGID"]);
        // The cgroup of the service is the node's, for one per command.
        assert!(unit.contains("\nDelegate=cpu memory pids\n"), "{unit}");
        assert!(unit.contains("\nOOMPolicy=continue\n"), "{unit}");
        // The owner socket's folder, which every account may enter.
        assert!(
            unit.contains("\nRuntimeDirectory=nerve-node\nRuntimeDirectoryMode=0755\n"),
            "{unit}"
        );
        assert!(
            unit.contains(&format!(
                "\nExecStart={} --config-dir {} --state-dir {} run\n",
                l.bin.display(),
                l.paths.config_dir.display(),
                l.paths.state_dir.display()
            )),
            "{unit}"
        );
        for dir in [&l.home, &l.paths.config_dir, &l.paths.state_dir] {
            assert_eq!(mode(dir), 0o700, "{dir:?}");
        }
        // Audited, with each step.
        let a = audit_events(&l);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0]["event"], "install");
        assert!(a[0].get("error").is_none());
        assert_eq!(a[0]["steps"].as_array().unwrap().len(), 9, "{}", a[0]);
        // Again, by root alone: the accounts are reused, the program
        // replaced, the service restarted, the owner kept.
        std::fs::write(&exe, "nerve-node 1.0.1\n").unwrap();
        let mut out = Vec::new();
        install(&l, &sys, &exe, "root", &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("alice stays the owner of the node"), "{out}");
        assert_eq!(owner_of_unit(&l).as_deref(), Some("alice"));
        assert_eq!(std::fs::read(&l.bin).unwrap(), b"nerve-node 1.0.1\n");
        assert_eq!(
            sys.calls()
                .iter()
                .filter(|c| c.starts_with("useradd"))
                .count(),
            2
        );
        assert!(out.contains("the user nerve, is there already"), "{out}");
        assert!(out.contains("nerve-run, is there already"), "{out}");
        assert_eq!(audit_events(&l).len(), 2);
    }

    /// The owner the unit of `l` names.
    fn owner_of_unit(l: &Layout) -> Option<String> {
        owner_in_unit(&std::fs::read_to_string(&l.unit).unwrap())
    }

    /// Only two accounts: the one that ran install becomes the owner; root
    /// alone, an account that is not there or one of the node's own makes
    /// none, and install does the rest all the same. A `nerve-run` that
    /// install did not make is refused.
    #[test]
    fn install_makes_the_invoker_the_owner_and_no_other_account() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        for who in ["root", "ghost", USER, crate::account::RUN_USER] {
            let l = layout(&d.path().join(who));
            let mut out = Vec::new();
            install(&l, &sys, Path::new("/bin/true"), who, &mut out).unwrap();
            let out = String::from_utf8(out).unwrap();
            assert!(out.contains("Warning: no owner"), "{who}: {out}");
            assert_eq!(owner_of_unit(&l), None, "{who}");
            assert!(!l.unit_text(None).contains("NERVE_NODE_OWNER"));
            assert!(!l.polkit_rule().exists(), "{who}");
        }
        // Another owner installs over it: the owner changes, as the polkit
        // rule does.
        sys.others.borrow_mut().push(other("bob", 4343));
        let l = layout(&d.path().join("root"));
        install(&l, &sys, Path::new("/bin/true"), "bob", &mut Vec::new()).unwrap();
        assert_eq!(owner_of_unit(&l).as_deref(), Some("bob"));
        assert_eq!(
            std::fs::read_to_string(l.polkit_rule()).unwrap(),
            polkit_rule_text("bob")
        );
        // A nerve-run of someone else's.
        let sys = Fake::new();
        sys.others
            .borrow_mut()
            .push(other(crate::account::RUN_USER, 4444));
        let l = layout(&d.path().join("taken"));
        let e = install(&l, &sys, Path::new("/bin/true"), "alice", &mut Vec::new()).unwrap_err();
        assert!(
            e.contains("nerve-run exists already") && e.contains("did not make it"),
            "{e}"
        );
        assert!(!l.unit.exists());
    }

    /// Install by root as `who` with `root` and what is typed at a terminal
    /// (`typed`; `None` is no terminal), on the machine `sys`.
    fn install_by(
        l: &Layout,
        sys: &Fake,
        who: &str,
        root: RootOwner,
        typed: Option<&str>,
    ) -> (Result<(), String>, String) {
        let k = crate::keyring_setup::tests::FakeKeyring::new(true);
        let mut out = Vec::new();
        let mut input = typed.map(|t| std::io::Cursor::new(t.as_bytes().to_vec()));
        let r = install_asking(
            l,
            sys,
            &k,
            input.as_mut().map(|i| i as &mut dyn BufRead),
            root,
            Path::new("/bin/true"),
            who,
            &mut out,
        );
        (r, String::from_utf8(out).unwrap())
    }

    /// Run by root itself, install asks at a terminal whether root is to be
    /// the owner, and says what that means; only a yes makes it the owner.
    /// No, Enter, the end of the input and no terminal at all leave the node
    /// without one, as piped input does, which is no terminal
    /// (crate::cli::terminal_input).
    #[test]
    fn root_becomes_the_owner_only_on_a_yes_at_a_terminal() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let question = "Make root the owner of this node? [y/N]";
        for (n, typed) in [Some("y\n"), Some("yes\n"), Some("Y\n")].iter().enumerate() {
            let l = layout(&d.path().join(format!("yes{n}")));
            let (r, out) = install_by(&l, &sys, "root", RootOwner::Ask, *typed);
            r.unwrap();
            assert!(out.contains(question), "{out}");
            assert!(out.contains(ROOT_OWNER_MEANS), "{out}");
            assert!(
                out.contains("Warning: root is the owner of the node, as you confirmed"),
                "{out}"
            );
            assert!(!out.contains("Warning: no owner"), "{out}");
            assert_eq!(owner_of_unit(&l).as_deref(), Some("root"));
            // Root needs no polkit to start and stop the service.
            for p in [l.polkit_rule(), l.polkit_pkla(), l.service_helper()] {
                assert!(!p.exists(), "{p:?}");
            }
        }
        let piped = std::io::Cursor::new(b"y\n".to_vec());
        let mut piped = std::io::BufReader::new(piped);
        let piped = crate::cli::terminal_input(false, &mut piped).map(|_| "y\n");
        assert!(piped.is_none());
        for (n, typed) in [
            Some("n\n"),
            Some("\n"),
            Some(""),
            Some("yess\n"),
            piped,
            None,
        ]
        .iter()
        .enumerate()
        {
            let l = layout(&d.path().join(format!("no{n}")));
            let (r, out) = install_by(&l, &sys, "root", RootOwner::Ask, *typed);
            r.unwrap();
            assert_eq!(out.contains(question), typed.is_some(), "{typed:?}: {out}");
            assert!(out.contains("Warning: no owner"), "{typed:?}: {out}");
            assert!(
                out.contains("--owner=root --accept-root-owner"),
                "{typed:?}: {out}"
            );
            assert_eq!(owner_of_unit(&l), None, "{typed:?}");
        }
        // Through sudo the question is not asked: the account that ran sudo
        // is the owner.
        let l = layout(&d.path().join("alice"));
        let (r, out) = install_by(&l, &sys, "alice", RootOwner::Ask, Some("y\n"));
        r.unwrap();
        assert!(!out.contains(question), "{out}");
        assert_eq!(owner_of_unit(&l).as_deref(), Some("alice"));
        // Run again by root with an owner: a no keeps it, a yes makes root
        // the owner instead.
        let (r, out) = install_by(&l, &sys, "root", RootOwner::Ask, Some("\n"));
        r.unwrap();
        assert!(
            out.contains("alice is the owner of this node now: on a yes root replaces alice as the owner, on a no alice stays it."),
            "{out}"
        );
        assert!(out.contains("alice stays the owner of the node"), "{out}");
        assert_eq!(owner_of_unit(&l).as_deref(), Some("alice"));
        let (r, _) = install_by(&l, &sys, "root", RootOwner::Ask, Some("y\n"));
        r.unwrap();
        assert_eq!(owner_of_unit(&l).as_deref(), Some("root"));
        assert!(!l.polkit_rule().exists());
        // Without an owner the question says that a no keeps it so.
        let l = layout(&d.path().join("none"));
        let (r, out) = install_by(&l, &sys, "root", RootOwner::Ask, Some("n\n"));
        r.unwrap();
        assert!(
            out.contains("The node has no owner now: on a yes root becomes its owner; on a no it stays without one"),
            "{out}"
        );
    }

    /// Root confirmed as the owner stays it at a later install by root, at
    /// a terminal or not, and is not asked again; `--owner=none` takes it
    /// away, as an install through sudo names another owner.
    #[test]
    fn a_confirmed_root_owner_stays_until_it_is_taken_back() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = layout(&d.path().join("root"));
        install_by(&l, &sys, "root", RootOwner::Accepted, None)
            .0
            .unwrap();
        for typed in [None, Some("\n"), Some("n\n")] {
            let (r, out) = install_by(&l, &sys, "root", RootOwner::Ask, typed);
            r.unwrap();
            assert!(!out.contains("[y/N]"), "{typed:?}: {out}");
            assert!(!root_question_due(&l, "root", RootOwner::Ask));
            assert!(
                out.contains("root stays the owner of the node, as confirmed at an earlier install; `nerve-node install --owner=none` takes that back"),
                "{typed:?}: {out}"
            );
            assert!(!out.contains("Warning: no owner"), "{typed:?}: {out}");
            assert_eq!(owner_of_unit(&l).as_deref(), Some("root"), "{typed:?}");
        }
        // The app's install, which asks nothing, keeps it too.
        install(&l, &sys, Path::new("/bin/true"), "root", &mut Vec::new()).unwrap();
        assert_eq!(owner_of_unit(&l).as_deref(), Some("root"));
        let (r, out) = install_by(&l, &sys, "root", RootOwner::NoOwner, Some("y\n"));
        r.unwrap();
        assert!(!out.contains("[y/N]"), "{out}");
        assert!(
            out.contains("root is no longer the owner of the node, as --owner=none says"),
            "{out}"
        );
        assert!(out.contains("Warning: no owner"), "{out}");
        assert_eq!(owner_of_unit(&l), None);
        // Without an owner root is asked again.
        assert!(root_question_due(&l, "root", RootOwner::Ask));
        // --owner=none drops another owner as well, and is root's alone.
        install_by(&l, &sys, "alice", RootOwner::Ask, None)
            .0
            .unwrap();
        assert_eq!(owner_of_unit(&l).as_deref(), Some("alice"));
        let (r, out) = install_by(&l, &sys, "alice", RootOwner::NoOwner, None);
        assert!(
            r.unwrap_err()
                .contains("--owner=none is for an install that root runs itself"),
            "{out}"
        );
        assert_eq!(owner_of_unit(&l).as_deref(), Some("alice"));
        install_by(&l, &sys, "root", RootOwner::NoOwner, None)
            .0
            .unwrap();
        assert_eq!(owner_of_unit(&l), None);
        // Through sudo another account becomes the owner over root.
        install_by(&l, &sys, "root", RootOwner::Accepted, None)
            .0
            .unwrap();
        install_by(&l, &sys, "alice", RootOwner::Ask, None)
            .0
            .unwrap();
        assert_eq!(owner_of_unit(&l).as_deref(), Some("alice"));
    }

    /// A grant as the node of the owner of `l` gave it: nerve-run's entries
    /// on `folder` and its file `data.txt`, and the record of them, which
    /// names that owner. `None` where the file system has no ACLs.
    #[cfg(target_os = "linux")]
    fn granted(l: &Layout, sys: &Fake, folder: &Path) -> Option<u32> {
        use nerve_policy::config::Access;
        let run = sys.account(crate::account::RUN_USER).unwrap().unwrap().uid;
        let owner = owner_of_unit(l).map_or(0, |o| sys.account(&o).unwrap().unwrap().uid);
        std::fs::create_dir_all(folder.join("sub")).unwrap();
        std::fs::write(folder.join("data.txt"), "the owner's").unwrap();
        let record = crate::acl::record_file(&l.paths);
        let want = [crate::acl::Granted {
            path: folder.to_path_buf(),
            access: Access::ALL,
        }];
        // The test may change its own files only: they stand for the
        // owner's.
        let who = crate::acl::Who {
            run,
            owner: unsafe { libc::geteuid() },
        };
        let r = crate::acl::sync(&record, &want, who, &|| Ok(None));
        if !r.errors.is_empty() {
            eprintln!("skipped: no POSIX ACLs here ({:?})", r.errors);
            return None;
        }
        let mut v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&record).unwrap()).unwrap();
        v["owner"] = owner.into();
        std::fs::write(&record, v.to_string()).unwrap();
        assert!(crate::acl::access_entry(&folder.join("data.txt"), run).is_some());
        Some(run)
    }

    /// Where install changes the owner (root to none, alice to root), it
    /// first takes nerve-run's entries off every grant the record names, as
    /// root, with the service stopped, and the record goes; the node gives
    /// the grants again for the new owner. Where the owner stays, they stay.
    /// Where they cannot all come off, the owner stays as it was and the
    /// service runs again.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_owner_change_takes_the_earlier_grants_off_first() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        for (first, then, after) in [
            (
                (ROOT, RootOwner::Accepted),
                (ROOT, RootOwner::NoOwner),
                None,
            ),
            (
                ("alice", RootOwner::Ask),
                (ROOT, RootOwner::Accepted),
                Some(ROOT),
            ),
            (
                (ROOT, RootOwner::Accepted),
                ("alice", RootOwner::Ask),
                Some("alice"),
            ),
        ] {
            let l = layout(&d.path().join(format!("{}-{:?}", first.0, then.1)));
            install_by(&l, &sys, first.0, first.1, None).0.unwrap();
            let folder = l.home.with_file_name("granted");
            let Some(run) = granted(&l, &sys, &folder) else {
                return;
            };
            let record = crate::acl::record_file(&l.paths);
            let before = sys.calls().len();
            let (r, out) = install_by(&l, &sys, then.0, then.1, None);
            r.unwrap();
            assert_eq!(owner_of_unit(&l).as_deref(), after);
            for p in [folder.clone(), folder.join("data.txt"), folder.join("sub")] {
                assert_eq!(crate::acl::access_entry(&p, run), None, "{p:?}");
            }
            assert!(!record.exists());
            assert!(
                out.contains("the owner of the node changes, so took nerve-run's access to the folders given to it off again"),
                "{out}"
            );
            assert_eq!(
                out.contains("without an owner the node gives nerve-run no folders"),
                after.is_none(),
                "{out}"
            );
            let calls = sys.calls()[before..].to_vec();
            let at = |c: &str| calls.iter().position(|x| x == c).unwrap();
            assert!(
                at(&format!("systemctl stop {UNIT_NAME}"))
                    < at(&format!("systemctl restart {UNIT_NAME}")),
                "{calls:?}"
            );
        }
        // The owner stays: so do the entries and the record.
        let l = layout(&d.path().join("stays"));
        install_by(&l, &sys, "alice", RootOwner::Ask, None)
            .0
            .unwrap();
        let folder = l.home.with_file_name("granted");
        let run = granted(&l, &sys, &folder).unwrap();
        install_by(&l, &sys, ROOT, RootOwner::Ask, None).0.unwrap();
        install_by(&l, &sys, "alice", RootOwner::Ask, None)
            .0
            .unwrap();
        assert!(crate::acl::access_entry(&folder.join("data.txt"), run).is_some());
        assert!(crate::acl::record_file(&l.paths).exists());
        // A folder below the grant that cannot be opened: the entries do not
        // all come off, so the owner stays alice and the service runs again.
        // Root opens any folder, so only as another account.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let sub = folder.join("sub");
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o000)).unwrap();
        let before = sys.calls().len();
        let (r, out) = install_by(&l, &sys, ROOT, RootOwner::Accepted, None);
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();
        let e = r.unwrap_err();
        assert!(
            e.contains("could not all be taken off") && e.contains("the owner stays as it was"),
            "{e}"
        );
        assert!(out.contains("as the owner of the node changes"), "{out}");
        assert_eq!(owner_of_unit(&l).as_deref(), Some("alice"));
        let record = crate::acl::record_file(&l.paths);
        assert!(record.exists());
        assert_eq!(
            sys.calls()[before..],
            [
                format!("systemctl stop {UNIT_NAME}"),
                format!("systemctl start {UNIT_NAME}")
            ]
        );
        // The walk took off what it could, so alice's node walks every grant
        // again when it starts, as one that failed.
        let alice = crate::acl::Who { run, owner: 4242 };
        let want = [crate::acl::Granted {
            path: folder.clone(),
            access: nerve_policy::config::Access::ALL,
        }];
        assert!(crate::acl::behind(&record, &want, alice, true));
        // A service that does not run is stopped all the same, which also
        // ends a start systemd waits to make, and is not started after.
        sys.systemctl(&["stop", UNIT_NAME]).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o000)).unwrap();
        let before = sys.calls().len();
        let (r, _) = install_by(&l, &sys, ROOT, RootOwner::Accepted, None);
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(r.is_err());
        assert_eq!(
            sys.calls()[before..],
            [format!("systemctl stop {UNIT_NAME}")]
        );
    }

    /// The owner changes only once nothing else refuses: a keyring that
    /// does not answer stops install before the service stops and before
    /// the grants come off. Where a later step fails, the node that was
    /// stopped runs again.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_failed_owner_change_leaves_the_node_running() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = layout(&d.path().join("keyring"));
        install_by(&l, &sys, "alice", RootOwner::Ask, None)
            .0
            .unwrap();
        let folder = l.home.with_file_name("granted");
        let Some(run) = granted(&l, &sys, &folder) else {
            return;
        };
        let mut store = SettingsStore::open_with(
            l.paths.config_file(),
            Box::new(crate::secrets::NodeSecrets::new(&l.paths)),
            AuditLog::new(l.paths.audit_log()),
        )
        .unwrap();
        store
            .update(|c| {
                c.machine.secret_storage = SecretStorage::Keyring;
                Ok(())
            })
            .unwrap();
        drop(store);
        let before = sys.calls().len();
        let k = crate::keyring_setup::tests::FakeKeyring::new(false);
        let e = install_asking(
            &l,
            &sys,
            &k,
            None,
            RootOwner::Accepted,
            Path::new("/bin/true"),
            ROOT,
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(e.contains("no system keyring answers"), "{e}");
        assert!(sys.calls()[before..].is_empty(), "{:?}", sys.calls());
        assert!(crate::acl::record_file(&l.paths).exists());
        assert!(crate::acl::access_entry(&folder.join("data.txt"), run).is_some());
        assert_eq!(owner_of_unit(&l).as_deref(), Some("alice"));
        // The node does not answer after the change: it is started again.
        sys.starts.set(false);
        let before = sys.calls().len();
        let (r, _) = install_by(&l, &sys, ROOT, RootOwner::Accepted, None);
        assert!(r.is_err());
        let calls = sys.calls()[before..].to_vec();
        assert_eq!(calls[0], format!("systemctl stop {UNIT_NAME}"), "{calls:?}");
        assert_eq!(
            calls.last(),
            Some(&format!("systemctl start {UNIT_NAME}")),
            "{calls:?}"
        );
    }

    /// The question and the step that make root the owner name the centers
    /// that have the settings grant already: they can make themselves root.
    #[test]
    fn root_is_told_of_the_centers_with_the_settings_grant() {
        assert!(ROOT_OWNER_MEANS.contains(
            "a center with the settings grant can switch itself to user mode and so run as root"
        ));
        assert_eq!(granted_note(&[]), "");
        let one = granted_note(&["home".into()]);
        assert!(one.contains("home has the settings grant already"), "{one}");
        let two = granted_note(&["home".into(), "work".into()]);
        assert!(two.contains("home, work have the settings grant"), "{two}");
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = layout(d.path());
        install_by(&l, &sys, "alice", RootOwner::Ask, None)
            .0
            .unwrap();
        let mut store = SettingsStore::open_with(
            l.paths.config_file(),
            Box::new(crate::secrets::NodeSecrets::new(&l.paths)),
            AuditLog::new(l.paths.audit_log()),
        )
        .unwrap();
        store
            .update(|c| {
                for (name, settings) in [
                    ("home", nerve_policy::config::SettingsGrant::Write),
                    ("work", nerve_policy::config::SettingsGrant::Off),
                ] {
                    c.centers.push(nerve_policy::CenterEntry {
                        name: name.into(),
                        url: "http://127.0.0.1:1".into(),
                        pin: None,
                        center_id: format!("id-{name}"),
                        node_id: "n".into(),
                        settings,
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
        assert_eq!(settings_granted(&l.paths), ["home"]);
        let note = granted_note(&["home".into()]);
        let (r, out) = install_by(&l, &sys, ROOT, RootOwner::Ask, Some("y\n"));
        r.unwrap();
        assert_eq!(out.matches(note.trim()).count(), 2, "{out}");
    }

    /// Without a terminal, `--owner=root --accept-root-owner` makes root the
    /// owner, asking nothing; through sudo the flags are refused before
    /// anything changes.
    #[test]
    fn the_flags_make_root_the_owner_of_an_install_root_runs() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = layout(&d.path().join("flags"));
        let (r, out) = install_by(&l, &sys, "root", RootOwner::Accepted, None);
        r.unwrap();
        assert!(!out.contains("[y/N]"), "{out}");
        assert!(
            out.contains("Warning: root is the owner of the node, as you confirmed"),
            "{out}"
        );
        assert_eq!(owner_of_unit(&l).as_deref(), Some("root"));
        assert!(
            l.unit_text(Some("root"))
                .contains("\nEnvironment=NERVE_NODE_OWNER=root\n")
        );
        // A terminal does not ask again.
        let (r, out) = install_by(&l, &sys, "root", RootOwner::Accepted, Some("n\n"));
        r.unwrap();
        assert!(!out.contains("[y/N]"), "{out}");
        assert_eq!(owner_of_unit(&l).as_deref(), Some("root"));
        let l = layout(&d.path().join("sudo"));
        let (r, out) = install_by(&l, &sys, "alice", RootOwner::Accepted, None);
        let e = r.unwrap_err();
        assert!(
            e.contains("--owner=root is for an install that root runs itself"),
            "{e}"
        );
        assert!(out.is_empty(), "{out}");
        assert!(!l.unit.exists());
        assert!(sys.calls().iter().all(|c| !c.contains("sudo")));
    }

    /// Root is a usable owner only where it confirmed it; the node's own
    /// accounts, another account with uid 0 and one that reaches the keys
    /// are not, confirmed or not.
    #[test]
    fn root_is_a_usable_owner_only_confirmed() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        let e = usable_owner(&sys, &l.paths, "root", false).unwrap_err();
        assert!(e.contains("cannot be its owner"), "{e}");
        assert_eq!(usable_owner(&sys, &l.paths, "root", true).unwrap().uid, 0);
        sys.others.borrow_mut().push(other("toor", 0));
        for accepted in [false, true] {
            let e = usable_owner(&sys, &l.paths, "toor", accepted).unwrap_err();
            assert!(e.contains("cannot be its owner"), "{e}");
            let e = usable_owner(&sys, &l.paths, crate::account::RUN_USER, accepted);
            assert!(e.unwrap_err().contains("cannot be its owner"));
            assert!(usable_owner(&sys, &l.paths, USER, accepted).is_err());
        }
        // An account that can open the node's folders stays refused.
        for p in [&l.paths.config_dir, &l.paths.state_dir] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        for open in ["", "etc", "var", "var/lib"] {
            std::fs::set_permissions(d.path().join(open), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        let e = usable_owner(&sys, &l.paths, "alice", true).unwrap_err();
        assert!(e.contains("could open"), "{e}");
    }

    /// An earlier install's config keeps the keys in the system keyring:
    /// install checks that it answers for the node's user before it starts
    /// the service, and offers to install one only in a terminal.
    #[test]
    fn install_checks_the_keyring_the_keys_are_in() {
        use crate::keyring_setup::tests::FakeKeyring;
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = layout(d.path());
        let mut store = SettingsStore::open_with(
            l.paths.config_file(),
            Box::new(crate::secrets::NodeSecrets::new(&l.paths)),
            AuditLog::new(l.paths.audit_log()),
        )
        .unwrap();
        store
            .update(|c| {
                c.machine.secret_storage = SecretStorage::Keyring;
                Ok(())
            })
            .unwrap();
        drop(store);
        let exe = d.path().join("nerve-node");
        std::fs::write(&exe, "nerve-node 1.0.0\n").unwrap();
        let started = |sys: &Fake| sys.calls().iter().any(|c| c.contains("restart"));
        let k = FakeKeyring::new(false);
        let install = |sys: &Fake, typed: Option<&str>| {
            let mut out = Vec::new();
            let mut input = typed.map(|t| std::io::Cursor::new(t.as_bytes().to_vec()));
            let r = install_asking(
                &l,
                sys,
                &k,
                input.as_mut().map(|i| i as &mut dyn BufRead),
                RootOwner::Ask,
                &exe,
                "alice",
                &mut out,
            );
            (r, String::from_utf8(out).unwrap())
        };
        let (r, out) = install(&sys, None);
        let e = r.unwrap_err();
        assert!(e.contains("no system keyring answers for nerve"), "{e}");
        assert!(e.contains("run in a terminal"), "{e}");
        assert!(!out.contains("[y/N]"), "{out}");
        assert!(!started(&sys));
        let (r, out) = install(&sys, Some("\n"));
        assert!(r.is_err());
        assert!(out.contains("Install it now? [y/N]"), "{out}");
        assert!(k.installed.borrow().is_empty() && !started(&sys));
        let (r, out) = install(&sys, Some("y\n"));
        r.unwrap();
        assert_eq!(k.installed.borrow().len(), 1);
        assert!(started(&sys));
        assert!(out.contains("keyring of nerve, and it answers"), "{out}");
        // Once it answers, nothing is asked.
        let (r, out) = install(&sys, None);
        r.unwrap();
        assert!(!out.contains("[y/N]"), "{out}");
    }

    #[test]
    fn uninstall_ends_the_session_a_keyring_gave_the_user() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        sys.lingers.set(true);
        let mut out = Vec::new();
        uninstall(&l, &sys, true, &mut out).unwrap();
        assert!(
            sys.calls().ends_with(&[
                "loginctl disable-linger nerve".into(),
                "userdel nerve".into()
            ]),
            "{:?}",
            sys.calls()
        );
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("ended the session of nerve"), "{out}");
    }

    /// `uninstall` takes the session generator away, also from a user that
    /// does not linger (the early return must not skip it).
    #[test]
    fn ending_the_session_removes_the_generator_it_wrote() {
        let d = tempfile::tempdir().unwrap();
        let gen_file = d.path().join("99-nerve-session");
        std::fs::write(&gen_file, "#!/bin/sh\n").unwrap();
        let linger = d.path().join("linger");
        std::fs::create_dir(&linger).unwrap();
        // Nobody lingers in this folder, so nothing is run.
        assert_eq!(Host.end_session_of("nerve", &gen_file, &linger), Ok(false));
        assert!(!gen_file.exists(), "the generator is still there");
        // A generator that is not there is no error.
        assert_eq!(Host.end_session_of("nerve", &gen_file, &linger), Ok(false));
    }

    /// The installed node is known by its folders, not by how it started.
    #[test]
    fn the_installed_folders_make_the_service_node() {
        assert!(is_service_node(&Layout::system().paths));
        let d = tempfile::tempdir().unwrap();
        assert!(!is_service_node(&NodePaths::new(
            d.path().join("c"),
            d.path().join("s")
        )));
    }

    /// The owner and `nerve-run` cannot read the keys: they are 0600 in
    /// folders private to `nerve`. An owner that could open those folders
    /// is refused.
    #[test]
    fn the_accounts_of_the_commands_cannot_read_the_keys() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        // Open down to the node's folders, as / and /etc are.
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        for open in ["etc", "var", "var/lib"] {
            std::fs::set_permissions(d.path().join(open), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        let key = l.paths.key_file("lab");
        nerve_transport::files::write_private(&key, b"key").unwrap();
        // The signed config and its key, as the node's first start makes
        // them.
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
        let alice = sys.account("alice").unwrap().unwrap();
        let run = sys.account(crate::account::RUN_USER).unwrap().unwrap();
        for account in [&alice, &run] {
            assert_ne!(account.uid, me().uid);
            for p in [
                key.clone(),
                l.paths.config_key(),
                l.paths.config_file(),
                l.paths.audit_log(),
            ] {
                assert!(p.exists(), "{p:?}");
                assert!(!crate::account::reaches(&p, account), "{p:?}");
                assert!(crate::account::reaches(&p, &me()), "{p:?}");
            }
        }
        assert_eq!(mode(&key), 0o600);
        usable_owner(&sys, &l.paths, "alice", false).unwrap();
        // Root and the node's own accounts are no owner.
        for who in ["root", USER, crate::account::RUN_USER] {
            let e = usable_owner(&sys, &l.paths, who, false);
            if who == USER {
                // The fake's nerve is the test's own account.
                assert!(e.is_err());
                continue;
            }
            let e = e.unwrap_err();
            assert!(e.contains("cannot be its owner"), "{who}: {e}");
        }
        // Opened to others, the folder and the key are in its reach, and
        // the owner is refused.
        std::fs::set_permissions(&l.paths.config_dir, std::fs::Permissions::from_mode(0o755))
            .unwrap();
        std::fs::set_permissions(
            key.parent().unwrap(),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(crate::account::reaches(&key, &alice));
        let e = usable_owner(&sys, &l.paths, "alice", false).unwrap_err();
        assert!(e.contains("could open"), "{e}");
    }

    /// A link in place of one of the node's folders, as the node's user could
    /// leave one, is refused: install neither changes nor writes through it.
    #[test]
    fn install_follows_no_link_in_place_of_a_folder() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = layout(d.path());
        let elsewhere = d.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::create_dir_all(&l.home).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &l.paths.state_dir).unwrap();
        let mut out = Vec::new();
        let e = install(&l, &sys, Path::new("/bin/true"), "alice", &mut out).unwrap_err();
        assert!(e.contains("is a link"), "{e}");
        assert_eq!(mode(&elsewhere), 0o755);
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
        assert!(!l.unit.exists());
        // Nor is the audit entry written through it.
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("the audit log cannot be written"), "{out}");
    }

    /// The walk that gives the folders away changes a link itself and does
    /// not go through it.
    #[test]
    fn chown_tree_does_not_walk_through_links() {
        let d = tempfile::tempdir().unwrap();
        let tree = d.path().join("tree");
        let outside = d.path().join("outside");
        std::fs::create_dir_all(tree.join("sub")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(tree.join("sub/f"), "x").unwrap();
        std::os::unix::fs::symlink(&outside, tree.join("link")).unwrap();
        // A folder it may not read stops the walk with its name: the walk
        // reached it through `tree/sub`, and would through `link` if it
        // followed links.
        std::fs::create_dir(outside.join("closed")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            outside.join("closed"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        let me = me();
        let r = chown_tree(&tree, me.uid, me.gid);
        std::fs::set_permissions(
            outside.join("closed"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        r.unwrap();
        // The tree given as a link is changed as a link only.
        chown_tree(&tree.join("link"), me.uid, me.gid).unwrap();
    }

    /// A socket in the tree, as the control socket of a node that ran is in
    /// its state folder, and a FIFO are given away as a file is: neither is
    /// opened, which a socket refuses and a FIFO would wait on. The walk
    /// runs aside, so a FIFO that holds it fails the test instead of
    /// hanging it.
    #[test]
    fn chown_tree_gives_a_socket_and_a_fifo_away() {
        let d = tempfile::tempdir().unwrap();
        let tree = d.path().join("tree");
        std::fs::create_dir_all(tree.join("run")).unwrap();
        let _l = std::os::unix::net::UnixListener::bind(tree.join("run/ctl.sock")).unwrap();
        let fifo =
            std::ffi::CString::new(tree.join("run/fifo").into_os_string().into_encoded_bytes())
                .unwrap();
        // SAFETY: a valid C string.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let me = me();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || tx.send(chown_tree(&tree, me.uid, me.gid)));
        rx.recv_timeout(std::time::Duration::from_secs(10))
            .expect("the walk waits on the FIFO")
            .unwrap();
    }

    /// A file with a second name, which the node's user could have made to
    /// a file of root's, is not given away.
    #[cfg(target_os = "linux")]
    #[test]
    fn chown_tree_gives_no_hard_linked_file_away() {
        let d = tempfile::tempdir().unwrap();
        let tree = d.path().join("tree");
        std::fs::create_dir_all(tree.join("sub")).unwrap();
        let outside = d.path().join("shadow");
        std::fs::write(&outside, "x").unwrap();
        std::fs::hard_link(&outside, tree.join("sub/x")).unwrap();
        let me = me();
        let e = chown_tree(&tree, me.uid, me.gid).unwrap_err();
        assert!(e.contains("sub/x") && e.contains("hard link"), "{e}");
        std::fs::remove_file(&outside).unwrap();
        chown_tree(&tree, me.uid, me.gid).unwrap();
    }

    #[test]
    fn install_refuses_a_user_it_did_not_make_and_needs_root() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        *sys.user.borrow_mut() = Some(Account {
            comment: "someone".into(),
            ..me()
        });
        let l = layout(d.path());
        let e = install(&l, &sys, Path::new("/bin/true"), "alice", &mut Vec::new()).unwrap_err();
        assert!(e.contains("did not make it"), "{e}");
        assert!(!l.bin.exists() && !l.unit.exists());
        assert!(sys.calls().is_empty());

        struct NotRoot;
        impl System for NotRoot {
            fn is_root(&self) -> bool {
                false
            }
            fn has_systemd(&self) -> bool {
                true
            }
            fn account(&self, _: &str) -> Result<Option<Account>, String> {
                unreachable!()
            }
            fn add_account(&self, _: &str, _: &Path, _: &str) -> Result<(), String> {
                unreachable!()
            }
            fn remove_account(&self, _: &str) -> Result<(), String> {
                unreachable!()
            }
            fn systemctl(&self, _: &[&str]) -> Result<(), String> {
                unreachable!()
            }
            fn give(&self, _: &Path, _: u32, _: u32) -> Result<(), String> {
                unreachable!()
            }
            fn wait_running(&self, _: &NodePaths) -> Result<(), String> {
                unreachable!()
            }
            fn version_of(&self, _: &Path, _: &Account) -> Result<String, String> {
                unreachable!()
            }
            fn unit_state(&self) -> Result<ServiceState, String> {
                unreachable!()
            }
        }
        for (what, e) in [
            (
                "install",
                install(
                    &l,
                    &NotRoot,
                    Path::new("/bin/true"),
                    "alice",
                    &mut Vec::new(),
                ),
            ),
            ("uninstall", uninstall(&l, &NotRoot, false, &mut Vec::new())),
        ] {
            assert_eq!(
                e.unwrap_err(),
                format!("{what} needs root: run `sudo nerve-node {what}`")
            );
        }
        // Starting and stopping is polkit's to allow (the owner's rule), so
        // it is not refused for want of root here.
        let e = control(&l, &NotRoot, ServiceAction::Stop, &mut Vec::new()).unwrap_err();
        assert!(e.contains("not installed as a service"), "{e}");
    }

    /// `uninstall` says so where it left files of nerve-run's with more
    /// than one name as they were (crate::acl::Report::not_given).
    #[test]
    fn uninstall_tells_the_files_it_did_not_give_the_owner() {
        let done = gave_to_owner(0);
        assert!(
            done.ends_with("gave what it made there to the owner"),
            "{done}"
        );
        for (n, what) in [(1, "not 1 file with"), (3, "not 3 files with")] {
            let said = gave_to_owner(n);
            assert!(said.starts_with(&done), "{said}");
            assert!(said.contains(what), "{said}");
            assert!(said.contains("may lie outside those folders"), "{said}");
            assert!(said.contains("-nouser"), "{said}");
        }
    }

    #[test]
    fn uninstall_leaves_no_service_user_or_program_and_keeps_the_folders() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        std::fs::write(l.paths.config_file(), "version = 3\n").unwrap();
        let mut out = Vec::new();
        uninstall(&l, &sys, false, &mut out).unwrap();
        assert!(!l.unit.exists() && !l.bin.exists());
        assert!(sys.user.borrow().is_none());
        assert!(
            sys.calls().ends_with(&[
                format!("systemctl disable --now {UNIT_NAME}"),
                "systemctl daemon-reload".into(),
                format!("systemctl reset-failed {UNIT_NAME}"),
                "userdel nerve-run".into(),
                "userdel nerve".into(),
            ]),
            "{:?}",
            sys.calls()
        );
        assert!(!l.polkit_rule().exists());
        // The commands' account goes with its home, whatever --purge says.
        assert_eq!(sys.account(crate::account::RUN_USER).unwrap(), None);
        assert!(!l.run_home.exists());
        // The config and state stay, and the audit log has both commands.
        assert_eq!(
            std::fs::read_to_string(l.paths.config_file()).unwrap(),
            "version = 3\n"
        );
        let events: Vec<_> = audit_events(&l)
            .iter()
            .map(|v| v["event"].clone())
            .collect();
        assert_eq!(events, ["install", "uninstall"]);
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("uninstall --purge"), "{out}");
        // No uid that may come to another user owns them: they are root's.
        let given: Vec<_> = sys
            .given
            .borrow()
            .iter()
            .filter(|(_, uid)| *uid == 0)
            .cloned()
            .collect();
        assert_eq!(
            given,
            [
                (l.paths.config_dir.clone(), 0),
                (l.home.clone(), 0),
                (l.paths.state_dir.clone(), 0)
            ]
        );
    }

    /// What nerve-run's commands left in the folders every account may
    /// write in goes before its uid is freed: its files and folders, a link
    /// of its but not what the link names, and nothing of another file
    /// system or account.
    #[test]
    fn uninstall_deletes_what_nerve_run_left_in_the_temporary_folders() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        // The test's own files stand for nerve-run's here.
        let mine = me().uid;
        for a in sys.others.borrow_mut().iter_mut() {
            if a.name == crate::account::RUN_USER {
                a.uid = mine;
            }
        }
        let outside = d.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("kept.txt"), "k").unwrap();
        for t in &l.run_temp {
            std::fs::create_dir_all(t.join("left/deeper")).unwrap();
            std::fs::write(t.join("left/deeper/f"), "x").unwrap();
            std::fs::write(t.join("file"), "x").unwrap();
            std::os::unix::fs::symlink(&outside, t.join("link")).unwrap();
        }
        let mut out = Vec::new();
        uninstall(&l, &sys, false, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        for t in &l.run_temp {
            assert_eq!(std::fs::read_dir(t).unwrap().count(), 0, "{t:?}");
        }
        assert!(outside.join("kept.txt").exists());
        assert!(
            out.contains(&format!(
                "deleted 15 files of nerve-run in {}",
                l.run_temp[0].display()
            )),
            "{out}"
        );
        // Before the account goes.
        let calls = sys.calls();
        assert!(
            calls.contains(&"userdel nerve-run".to_string()),
            "{calls:?}"
        );
    }

    /// The walk passes over files of other accounts and does not follow a
    /// link put where a folder was.
    #[test]
    fn the_temporary_folders_lose_only_the_files_of_the_account() {
        let d = tempfile::tempdir().unwrap();
        let t = d.path().join("tmp");
        std::fs::create_dir_all(t.join("dir")).unwrap();
        std::fs::write(t.join("dir/f"), "x").unwrap();
        // Not the test's account: nothing goes.
        assert_eq!(
            remove_files_of(me().uid + 1, std::slice::from_ref(&t))
                .unwrap()
                .n,
            0
        );
        assert!(t.join("dir/f").exists());
        // A folder missing is no error.
        assert_eq!(
            remove_files_of(me().uid, &[d.path().join("none"), t.clone()])
                .unwrap()
                .n,
            2
        );
        assert!(!t.join("dir").exists());
        // The folder itself may be a link (`/var/tmp -> /tmp`): it is
        // followed, and walked once by either name.
        let elsewhere = d.path().join("elsewhere");
        std::os::unix::fs::symlink(&elsewhere, d.path().join("l")).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("f"), "x").unwrap();
        let r = remove_files_of(me().uid, &[d.path().join("l"), elsewhere.clone()]).unwrap();
        assert_eq!(r.n, 1);
        assert!(!elsewhere.join("f").exists() && elsewhere.exists());
        // A link inside a folder is deleted as a link, not walked into.
        let outside = d.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("f"), "x").unwrap();
        let inner = d.path().join("inner");
        std::fs::create_dir_all(&inner).unwrap();
        std::os::unix::fs::symlink(&outside, inner.join("trap")).unwrap();
        let r = remove_files_of(me().uid, std::slice::from_ref(&inner)).unwrap();
        assert!(r.errors.is_empty() && r.left.is_empty(), "{r:?}");
        assert!(inner.join("trap").symlink_metadata().is_err());
        assert!(outside.join("f").exists());
    }

    /// A tree deeper than the walk goes is left as it is, and so is a
    /// folder that cannot be opened; both are named, and neither keeps the
    /// account from going.
    #[test]
    fn the_temporary_folders_name_what_the_walk_did_not_look_into() {
        let d = tempfile::tempdir().unwrap();
        let t = std::fs::canonicalize(d.path()).unwrap().join("tmp");
        let mut deep = t.clone();
        for _ in 0..WALK_DEPTH + 2 {
            deep.push("a");
        }
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("f"), "x").unwrap();
        // Another account's tree: nothing of it is deleted either way. A
        // folder given twice is walked once.
        let r = remove_files_of(me().uid + 1, &[t.clone(), t.clone()]).unwrap();
        assert!(deep.join("f").exists());
        let mut limit = t.clone();
        for _ in 0..=WALK_DEPTH {
            limit.push("a");
        }
        assert_eq!(r.left, [limit.display().to_string()]);
        // Root opens every folder.
        if nerve_transport::net::euid() == 0 {
            return;
        }
        std::fs::remove_dir_all(t.join("a")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let shut = t.join("shut");
        std::fs::create_dir(&shut).unwrap();
        std::fs::write(shut.join("f"), "x").unwrap();
        std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o000)).unwrap();
        let r = remove_files_of(me().uid, std::slice::from_ref(&t));
        std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o700)).unwrap();
        let r = r.unwrap();
        assert_eq!(r.left, [shut.display().to_string()]);
        assert!(shut.join("f").exists());
    }

    /// A folder is given away through the descriptor it was walked by: what
    /// was put under its name since keeps its owner.
    #[test]
    fn a_folder_is_given_away_by_its_descriptor_not_its_name() {
        use std::os::unix::fs::MetadataExt;
        // A group of the test's account besides its own, which it may give
        // its files to without being root.
        let mut groups = vec![0 as libc::gid_t; 256];
        // SAFETY: the buffer holds as many entries as it is told.
        let n = unsafe { libc::getgroups(groups.len() as i32, groups.as_mut_ptr()) };
        let d = tempfile::tempdir().unwrap();
        let name = d.path().join("d");
        std::fs::create_dir(&name).unwrap();
        let folder = std::fs::File::open(&name).unwrap();
        // Swapped meanwhile: the folder moved, a file of the same owner in
        // its place.
        std::fs::rename(&name, d.path().join("moved")).unwrap();
        std::fs::write(&name, "x").unwrap();
        let own = std::fs::symlink_metadata(&name).unwrap().gid();
        let Some(&other) = groups[..n.max(0) as usize].iter().find(|g| **g != own) else {
            eprintln!("skipped: the test's account has no other group");
            return;
        };
        give_folder(&folder, &name, (me().uid, other)).unwrap();
        assert_eq!(
            std::fs::metadata(d.path().join("moved")).unwrap().gid(),
            other
        );
        assert_eq!(std::fs::symlink_metadata(&name).unwrap().gid(), own);
    }

    #[cfg(unix)]
    #[test]
    fn uninstall_writes_no_audit_entry_through_a_link_or_a_second_name() {
        // Without --purge the folders are root's before the entry is
        // written, so it is written as root: a link or a hard link left in
        // place of the log must not lead that write outside the folders.
        for hard in [false, true] {
            let d = tempfile::tempdir().unwrap();
            let sys = Fake::new();
            let l = installed(d.path(), &sys, "1.0.0");
            let outside = d.path().join("outside");
            std::fs::write(&outside, "kept\n").unwrap();
            std::fs::remove_file(l.paths.audit_log()).unwrap();
            if hard {
                std::fs::hard_link(&outside, l.paths.audit_log()).unwrap();
            } else {
                std::os::unix::fs::symlink(&outside, l.paths.audit_log()).unwrap();
            }
            let mut out = Vec::new();
            uninstall(&l, &sys, false, &mut out).unwrap();
            assert_eq!(std::fs::read_to_string(&outside).unwrap(), "kept\n");
            let out = String::from_utf8(out).unwrap();
            assert!(out.contains("the audit log cannot be written"), "{out}");
            assert!(!l.bin.exists() && sys.user.borrow().is_none());
        }
    }

    #[test]
    fn uninstall_purge_deletes_the_folders_and_leaves_a_foreign_user() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        uninstall(&l, &sys, true, &mut Vec::new()).unwrap();
        for p in [
            &l.unit,
            &l.bin,
            &l.home,
            &l.paths.config_dir,
            &l.paths.state_dir,
        ] {
            assert!(!p.exists(), "{p:?}");
        }
        assert!(sys.user.borrow().is_none());
        let mut out = Vec::new();
        uninstall(&l, &sys, true, &mut out).unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .starts_with("nothing to uninstall"),
        );
        // A nerve user that install did not make stays.
        *sys.user.borrow_mut() = Some(Account {
            comment: "someone".into(),
            ..me()
        });
        let mut out = Vec::new();
        uninstall(&l, &sys, true, &mut out).unwrap();
        assert!(sys.user.borrow().is_some());
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("left the user nerve")
        );
    }

    /// What update must not touch: the config, a key and the audit log so far.
    fn kept(l: &Layout) -> Vec<(PathBuf, Vec<u8>)> {
        [
            l.paths.config_file(),
            l.paths.key_file("lab"),
            l.paths.config_key(),
            l.paths.audit_log(),
        ]
        .into_iter()
        .map(|p| {
            let b = std::fs::read(&p).unwrap();
            (p, b)
        })
        .collect()
    }

    fn with_files(l: &Layout) {
        std::fs::write(l.paths.config_file(), "version = 7\n").unwrap();
        std::fs::create_dir_all(l.paths.key_file("lab").parent().unwrap()).unwrap();
        std::fs::write(l.paths.key_file("lab"), "key").unwrap();
        std::fs::write(l.paths.config_key(), "mac key").unwrap();
    }

    /// Without polkit the owner is told that starting and stopping needs
    /// sudo.
    #[test]
    fn install_says_what_polkit_is_here() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        sys.polkit.set(Polkit::Missing);
        let l = layout(d.path());
        let exe = d.path().join("nerve-node-x86_64-linux");
        std::fs::write(&exe, "nerve-node 1.0.0\n").unwrap();
        let mut out = Vec::new();
        install(&l, &sys, &exe, "alice", &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("Warning: polkit is not installed"), "{out}");
        for f in [
            l.polkit_rule(),
            l.polkit_pkla(),
            l.polkit_action(),
            l.service_helper(),
        ] {
            assert!(!f.exists(), "{}", f.display());
        }
    }

    /// On polkit 0.105, which takes no rules, the owner gets the service
    /// helper through its own action and a `.pkla` file for it, never one
    /// for systemd's `manage-units`; on a newer polkit through the rule.
    /// An install again moves from one to the other, and uninstall removes
    /// them.
    #[test]
    fn polkit_0105_gets_the_helper_and_a_pkla_file_and_newer_the_rule() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        sys.polkit.set(Polkit::Old);
        let l = installed(d.path(), &sys, "1.0.0");
        let helper = l.service_helper();
        assert_eq!(
            helper,
            d.path().join("usr/local/lib/nerve-node/service-control")
        );
        assert_eq!(
            std::fs::read_to_string(&helper).unwrap(),
            service_helper_text()
        );
        assert_eq!(mode(&helper), 0o755);
        let action = l.polkit_action();
        assert_eq!(
            action,
            d.path()
                .join("usr/share/polkit-1/actions/org.nerve-protocol.node.service-control.policy")
        );
        let policy = std::fs::read_to_string(&action).unwrap();
        assert_eq!(policy, polkit_action_text(&helper));
        assert!(
            policy.contains(&format!(
                "<annotate key=\"org.freedesktop.policykit.exec.path\">{}</annotate>",
                helper.display()
            )),
            "{policy}"
        );
        assert!(policy.contains("<allow_active>auth_admin</allow_active>"));
        let pkla = l.polkit_pkla();
        assert_eq!(
            pkla,
            d.path()
                .join("etc/polkit-1/localauthority/50-local.d/50-nerve-node.pkla")
        );
        let text = std::fs::read_to_string(&pkla).unwrap();
        assert_eq!(text, polkit_pkla_text("alice"));
        for line in [
            "Identity=unix-user:alice",
            "Action=org.nerve-protocol.node.service-control",
            "ResultActive=yes",
        ] {
            assert!(text.lines().any(|l| l == line), "{line}: {text}");
        }
        assert!(!text.contains("manage-units") && !text.contains("ResultAny"));
        assert!(!l.polkit_rule().exists());

        // The machine got a newer polkit: the rule takes the .pkla file's
        // place.
        sys.polkit.set(Polkit::Rules);
        let new = d.path().join("new");
        std::fs::write(&new, "nerve-node 1.1.0\n").unwrap();
        install(&l, &sys, &new, "root", &mut Vec::new()).unwrap();
        let rule = std::fs::read_to_string(l.polkit_rule()).unwrap();
        assert!(rule.contains(POLKIT_ACTION), "{rule}");
        assert!(!pkla.exists());
        assert!(helper.is_file() && action.is_file());

        let mut out = Vec::new();
        uninstall(&l, &sys, false, &mut out).unwrap();
        for f in [l.polkit_rule(), pkla, action, helper.clone()] {
            assert!(!f.exists(), "{}", f.display());
        }
        assert!(!helper.parent().unwrap().exists());
    }

    /// The helper does what it says and nothing else: one of the three
    /// words, or it stops before systemctl.
    #[cfg(unix)]
    #[test]
    fn the_service_helper_takes_three_words_only() {
        let d = tempfile::tempdir().unwrap();
        let helper = d.path().join("service-control");
        std::fs::write(&helper, service_helper_text()).unwrap();
        let sh = |args: &[&str]| {
            std::process::Command::new("sh")
                .arg(&helper)
                .args(args)
                .output()
                .unwrap()
        };
        let checked = std::process::Command::new("sh")
            .arg("-n")
            .arg(&helper)
            .status()
            .unwrap();
        assert!(checked.success());
        for args in [
            &[][..],
            &["status"][..],
            &["start", "other.service"][..],
            &["enable"][..],
            &["start;id"][..],
        ] {
            let o = sh(args);
            assert_eq!(o.status.code(), Some(2), "{args:?}");
            assert!(
                String::from_utf8_lossy(&o.stderr).contains("usage"),
                "{args:?}"
            );
        }
        let text = service_helper_text();
        assert!(
            text.contains(&format!("exec systemctl \"$1\" {UNIT_NAME}")),
            "{text}"
        );
    }

    #[test]
    fn polkit_is_told_by_its_version() {
        for (said, kind) in [
            ("pkaction version 0.105\n", Some(Polkit::Old)),
            ("pkaction version 0.106", Some(Polkit::Rules)),
            ("pkaction version 0.116", Some(Polkit::Rules)),
            ("pkaction version 124\n", Some(Polkit::Rules)),
            ("pkaction version 122", Some(Polkit::Rules)),
            ("", None),
            ("pkaction version x", None),
        ] {
            assert_eq!(polkit_of_version(said), kind, "{said:?}");
        }
    }

    #[tokio::test]
    async fn update_replaces_the_program_and_keeps_config_keys_and_audit() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        with_files(&l);
        let before = kept(&l);
        let new = d.path().join("new");
        std::fs::write(&new, "nerve-node 1.2.0\n").unwrap();
        let mut out = Vec::new();
        update(&l, &sys, Some(&new), &mut out).await.unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("replaced nerve-node 1.0.0 with 1.2.0"),
            "{out}"
        );
        assert_eq!(std::fs::read(&l.bin).unwrap(), b"nerve-node 1.2.0\n");
        assert_eq!(mode(&l.bin), 0o755);
        assert_eq!(
            sys.calls().last().unwrap(),
            &format!("systemctl restart {UNIT_NAME}")
        );
        // Everything else as it was; the audit log only grew.
        for (p, b) in before {
            let now = std::fs::read(&p).unwrap();
            if p == l.paths.audit_log() {
                assert!(now.starts_with(&b), "{p:?}");
            } else {
                assert_eq!(now, b, "{p:?}");
            }
        }
        let a = audit_events(&l);
        assert_eq!(a.last().unwrap()["event"], "update");
        assert!(!l.bin.with_file_name(".nerve-node.new").exists());
        // The same program again changes nothing.
        let calls = sys.calls().len();
        let mut out = Vec::new();
        update(&l, &sys, Some(&new), &mut out).await.unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("nothing to update")
        );
        assert_eq!(sys.calls().len(), calls);
    }

    #[tokio::test]
    async fn update_refuses_an_older_or_foreign_program_and_puts_back_one_that_does_not_start() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.2.0");
        let new = d.path().join("new");
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
            assert!(!l.bin.with_file_name(".nerve-node.new").exists());
        }
        std::fs::write(&new, "nerve-node 2.0.0\n").unwrap();
        sys.starts.set(false);
        let e = update(&l, &sys, Some(&new), &mut Vec::new())
            .await
            .unwrap_err();
        assert!(e.contains("did not start"), "{e}");
        assert_eq!(std::fs::read(&l.bin).unwrap(), b"nerve-node 1.2.0\n");
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
    async fn update_needs_an_installed_node() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let e = update(&layout(d.path()), &sys, None, &mut Vec::new())
            .await
            .unwrap_err();
        assert!(e.contains("not installed"), "{e}");
    }

    /// A release on a local server: `SHA256SUMS` and the program, the
    /// program behind a redirect as GitHub has it.
    async fn release(program: &'static [u8], sums: String) -> String {
        use nerve_transport::http::{Response, read_request};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let asset = asset_name("nerve-node").unwrap();
        tokio::spawn(async move {
            while let Ok((mut io, _)) = listener.accept().await {
                let req = read_request(&mut io, 0).await.unwrap();
                let r = if req.path == "/rel/SHA256SUMS" {
                    Response::text(200, &sums)
                } else if req.path == format!("/rel/{asset}") {
                    Response::new(302, "text/plain", "").with_header("Location", "/blob?sig=x")
                } else if req.path == "/blob" && req.query_param("sig").as_deref() == Some("x") {
                    Response::new(200, "application/octet-stream", program)
                } else {
                    Response::text(404, "no")
                };
                let _ = r.write(&mut io).await;
            }
        });
        format!("http://127.0.0.1:{port}/rel")
    }

    /// The release download follows five redirects, as the node's own loop
    /// did before it moved to the shared downloader, and refuses a sixth
    /// (review r3, finding 7).
    #[tokio::test]
    async fn the_download_follows_five_redirects_and_no_more() {
        use nerve_transport::http::{Response, read_request};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // `/rN` redirects to `/r(N+1)` up to `/r6`, which answers.
        tokio::spawn(async move {
            while let Ok((mut io, _)) = listener.accept().await {
                let req = read_request(&mut io, 0).await.unwrap();
                let n: u8 = req.path.trim_start_matches("/r").parse().unwrap_or(9);
                let r = if n >= 6 {
                    Response::text(200, "end")
                } else {
                    Response::new(302, "text/plain", "")
                        .with_header("Location", &format!("/r{}", n + 1))
                };
                let _ = r.write(&mut io).await;
            }
        });
        let url = |n: u8| format!("http://127.0.0.1:{port}/r{n}");
        assert_eq!(download(&url(1), 1024).await.unwrap(), b"end");
        let e = download(&url(0), 1024).await.unwrap_err();
        assert!(e.contains("too many redirects"), "{e}");
    }

    fn sha(b: &[u8]) -> String {
        ring::digest::digest(&ring::digest::SHA256, b)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    #[tokio::test]
    async fn update_downloads_the_release_and_checks_it() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let mut l = installed(d.path(), &sys, "1.0.0");
        let program: &[u8] = b"nerve-node 1.3.0\n";
        let asset = asset_name("nerve-node").unwrap();
        l.release = release(
            program,
            format!("{}  other\n{} *{asset}\n", sha(b"x"), sha(program)),
        )
        .await;
        let mut out = Vec::new();
        update(&l, &sys, None, &mut out).await.unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("checked it against its SHA256SUMS"), "{out}");
        assert_eq!(std::fs::read(&l.bin).unwrap(), program);

        // A program that does not match its line is refused.
        let mut l2 = installed(&d.path().join("two"), &sys, "1.0.0");
        l2.release = release(program, format!("{}  {asset}\n", sha(b"other"))).await;
        let e = update(&l2, &sys, None, &mut Vec::new()).await.unwrap_err();
        assert!(e.contains("does not match"), "{e}");
        assert_eq!(std::fs::read(&l2.bin).unwrap(), b"nerve-node 1.0.0\n");
        // So is a release that does not list it.
        l2.release = release(program, format!("{}  other\n", sha(program))).await;
        let e = update(&l2, &sys, None, &mut Vec::new()).await.unwrap_err();
        assert!(e.contains("lists no"), "{e}");
    }

    #[test]
    fn versions_and_addresses() {
        assert_eq!(
            Version::parse("nerve-node 0.10.2\n"),
            Some(Version(0, 10, 2))
        );
        assert!(Version(0, 10, 0) > Version(0, 9, 9));
        for bad in [
            "nerve-center 1.0.0",
            "nerve-node 1.0",
            "nerve-node 1.0.0.1",
            "nerve-node x",
        ] {
            assert_eq!(Version::parse(bad), None, "{bad}");
        }
        let (at, target) = split_url("https://example.com/a/b?x=1").unwrap();
        assert_eq!(
            (at.host.as_str(), at.port, at.tls),
            ("example.com", 443, true)
        );
        assert_eq!(target, "/a/b?x=1");
        let (at, target) = split_url("http://127.0.0.1:8080?q").unwrap();
        assert_eq!((at.port, target.as_str()), (8080, "/?q"));
        assert!(split_url("ftp://x/y").is_err());
    }

    /// The desktop app's parts, as a file beside the program.
    struct Entry;

    impl crate::edition::Parts for Entry {
        fn install(&self, bin: &Path) -> Result<Vec<String>, String> {
            std::fs::write(bin.with_file_name("menu-entry"), "Exec").map_err(|e| e.to_string())?;
            Ok(vec!["put the menu entry in place".into()])
        }
        fn uninstall(&self, bin: &Path) -> Result<Vec<String>, String> {
            let entry = bin.with_file_name("menu-entry");
            if !entry.exists() {
                return Ok(Vec::new());
            }
            std::fs::remove_file(entry).map_err(|e| e.to_string())?;
            Ok(vec!["removed the menu entry".into()])
        }
    }

    static DESKTOP: crate::edition::Edition = crate::edition::Edition {
        program: "nerve-node-desktop",
        parts: Some(&Entry),
    };

    #[tokio::test]
    async fn the_desktop_app_installs_updates_and_uninstalls_its_parts_with_the_node() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = Layout {
            bin: d.path().join("usr/local/bin/nerve-node-desktop"),
            edition: &DESKTOP,
            ..layout(d.path())
        };
        let entry = l.bin.with_file_name("menu-entry");
        let exe = d.path().join("Downloads/nerve-node-desktop-x86_64-linux");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, "nerve-node-desktop 1.0.0\n").unwrap();
        let mut out = Vec::new();
        install(&l, &sys, &exe, "alice", &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("put the menu entry in place"), "{out}");
        assert!(entry.exists());
        assert!(
            std::fs::read_to_string(&l.unit)
                .unwrap()
                .contains(&format!("ExecStart={} --config-dir", l.bin.display())),
        );
        let step = |event: &str| {
            audit_events(&l)
                .iter()
                .rev()
                .find(|e| e["event"] == event)
                .unwrap()
                .to_string()
        };
        assert!(step("install").contains("menu entry"));

        // The node's program is not the app's, and the app's own goes in,
        // its parts put back.
        let new = d.path().join("new");
        std::fs::write(&new, "nerve-node 1.1.0\n").unwrap();
        let e = update(&l, &sys, Some(&new), &mut Vec::new())
            .await
            .unwrap_err();
        assert!(e.contains("is not nerve-node-desktop"), "{e}");
        std::fs::remove_file(&entry).unwrap();
        std::fs::write(&new, "nerve-node-desktop 1.1.0\n").unwrap();
        let mut out = Vec::new();
        update(&l, &sys, Some(&new), &mut out).await.unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("replaced nerve-node-desktop 1.0.0 with 1.1.0"),
            "{out}"
        );
        assert!(entry.exists(), "{out}");
        assert!(!l.bin.with_file_name(".nerve-node-desktop.new").exists());

        let mut out = Vec::new();
        uninstall(&l, &sys, false, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("removed the menu entry"), "{out}");
        assert!(!entry.exists() && !l.bin.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_app_makes_the_node_installed_alone_a_link_to_it_and_removes_it() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        // A node installed with nerve-node.
        let node = installed(d.path(), &sys, "1.0.0");
        let l = Layout {
            bin: d.path().join("usr/local/bin/nerve-node-desktop"),
            edition: &DESKTOP,
            ..layout(d.path())
        };
        assert_eq!(node_beside(&l).as_ref(), Some(&node.bin));
        assert_eq!(node_beside(&node), None);
        let exe = d.path().join("Downloads/nerve-node-desktop-x86_64-linux");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, "nerve-node-desktop 1.0.0\n").unwrap();
        let mut out = Vec::new();
        install(&l, &sys, &exe, "alice", &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("nerve-node is a link to"), "{out}");
        assert_eq!(std::fs::read_link(&node.bin).unwrap(), l.bin);
        // The command runs the app's program.
        assert_eq!(
            std::fs::read_to_string(&node.bin).unwrap(),
            "nerve-node-desktop 1.0.0\n"
        );
        assert!(!node.bin.with_file_name(".nerve-node.link").exists());

        // Again, and after an update, the link stays as it is.
        let mut out = Vec::new();
        install(&l, &sys, &exe, "alice", &mut out).unwrap();
        assert!(!String::from_utf8(out).unwrap().contains("is a link"));
        let new = d.path().join("new");
        std::fs::write(&new, "nerve-node-desktop 1.1.0\n").unwrap();
        update(&l, &sys, Some(&new), &mut Vec::new()).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(&node.bin).unwrap(),
            "nerve-node-desktop 1.1.0\n"
        );

        let mut out = Vec::new();
        uninstall(&l, &sys, false, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("removed the link"), "{out}");
        assert!(std::fs::symlink_metadata(&node.bin).is_err());
        assert!(!l.bin.exists());

        // No node alone was there: no link is made; a link of another's
        // stays.
        install(&l, &sys, &exe, "alice", &mut Vec::new()).unwrap();
        assert!(std::fs::symlink_metadata(&node.bin).is_err());
        let other = d.path().join("other");
        std::os::unix::fs::symlink(&other, &node.bin).unwrap();
        install(&l, &sys, &exe, "alice", &mut Vec::new()).unwrap();
        uninstall(&l, &sys, false, &mut Vec::new()).unwrap();
        assert_eq!(std::fs::read_link(&node.bin).unwrap(), other);
    }

    /// A program still open for writing a moment after it was written
    /// (#168), until the closer drops it: `f` holds it so for 100 ms.
    #[cfg(unix)]
    fn held_open(path: &Path, text: &str) -> std::thread::JoinHandle<()> {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt;
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(text.as_bytes()).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            drop(f);
        })
    }

    /// The app's program, and the program `update` staged, start once they
    /// are no longer open for writing: Linux says "Text file busy" until then.
    #[cfg(unix)]
    #[test]
    fn a_program_written_a_moment_ago_starts_once_it_is_closed() {
        let d = tempfile::tempdir().unwrap();
        let app = d.path().join("nerve-node-desktop");
        let closer = held_open(&app, "#!/bin/sh\necho \"asked: $*\"\n");
        let mut out = Vec::new();
        hand_over_uninstall(&app, false, &mut out).unwrap();
        closer.join().unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("asked: uninstall"), "{out}");
        let staged = d.path().join("nerve-node.new");
        let closer = held_open(&staged, "#!/bin/sh\necho nerve-node 9.9.9\n");
        assert_eq!(
            Host.version_of(&staged, &me()).as_deref(),
            Ok("nerve-node 9.9.9")
        );
        closer.join().unwrap();
    }

    /// `nerve-node uninstall` of the node alone, after the app took the
    /// node over: the app's program, here a script that says what it was
    /// asked, does the uninstall, and what it says comes through.
    #[cfg(unix)]
    #[test]
    fn the_node_alone_hands_the_uninstall_of_a_takeover_to_the_app() {
        let d = tempfile::tempdir().unwrap();
        let node = layout(d.path());
        let app = Layout {
            bin: node.bin.with_file_name("nerve-node-desktop"),
            edition: &DESKTOP,
            ..layout(d.path())
        };
        assert_eq!(app_beside(&node), None);
        std::fs::create_dir_all(app.bin.parent().unwrap()).unwrap();
        let script = |code: u8| {
            nerve_transport::files::write_program(
                &app.bin,
                &format!(
                    "#!/bin/sh\necho \"removed the program, asked: $*\"\necho \"a log line\" >&2\nexit {code}\n"
                ),
            )
            .unwrap();
        };
        script(0);
        assert_eq!(app_beside(&node).as_ref(), Some(&app.bin));
        // The app itself does its uninstall.
        assert_eq!(app_beside(&app), None);
        let mut out = Vec::new();
        hand_over_uninstall(&app_beside(&node).unwrap(), true, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("the desktop app is installed"), "{out}");
        assert!(
            out.contains("removed the program, asked: uninstall --purge"),
            "{out}"
        );
        let mut out = Vec::new();
        hand_over_uninstall(&app.bin, false, &mut out).unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("asked: uninstall\n")
        );
        script(3);
        let e = hand_over_uninstall(&app.bin, false, &mut Vec::new()).unwrap_err();
        assert!(e.contains("did not finish"), "{e}");
    }

    #[test]
    fn the_desktop_app_has_a_place_and_a_release_file_of_its_own() {
        let l = Layout::of(&DESKTOP);
        assert_eq!(l.bin, Path::new("/usr/local/bin/nerve-node-desktop"));
        assert_eq!(l.paths, Layout::system().paths);
        assert_eq!(Layout::system().bin, Path::new("/usr/local/bin/nerve-node"));
        if std::env::consts::ARCH == "x86_64" {
            assert_eq!(
                asset_name("nerve-node-desktop").unwrap(),
                "nerve-node-desktop-x86_64-linux"
            );
        }
        assert_eq!(
            Version::of_program(&l, "nerve-node-desktop 0.2.0\n"),
            Some(Version(0, 2, 0))
        );
        assert_eq!(Version::of_program(&l, "nerve-node 0.2.0"), None);
    }

    #[test]
    fn service_starts_stops_and_restarts_the_installed_unit() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = layout(d.path());
        assert_eq!(unit_status(&l, &sys).unwrap(), None);
        let e = control(&l, &sys, ServiceAction::Start, &mut Vec::new()).unwrap_err();
        assert!(e.contains("not installed as a service"), "{e}");
        let l = installed(d.path(), &sys, "1.0.0");
        let mut out = Vec::new();
        control(&l, &sys, ServiceAction::Stop, &mut out).unwrap();
        assert_eq!(
            sys.calls().last().unwrap(),
            &format!("systemctl stop {UNIT_NAME}")
        );
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("it starts again with the machine")
        );
        let state = unit_status(&l, &sys).unwrap().unwrap();
        assert_eq!(state.state, "stopped");
        assert_eq!(state.enabled, Some(true));
        let v = service_status(&l, Some(&state));
        assert_eq!(v["installed"], true);
        assert_eq!(v["state"], "stopped");
        assert_eq!(v["present"], true);
        assert_eq!(v["program"], l.bin.display().to_string());
        for (action, call) in [
            (ServiceAction::Start, "start"),
            (ServiceAction::Restart, "restart"),
        ] {
            let mut out = Vec::new();
            control(&l, &sys, action, &mut out).unwrap();
            assert_eq!(
                sys.calls().last().unwrap(),
                &format!("systemctl {call} {UNIT_NAME}")
            );
            assert!(String::from_utf8(out).unwrap().contains("the node answers"));
            assert_eq!(unit_status(&l, &sys).unwrap().unwrap().state, "running");
        }
        // An owner, not root, goes through the helper with pkexec; without
        // pkexec through systemctl, which the rule allows on a newer polkit.
        sys.root.set(false);
        let helper = l.service_helper();
        for (action, word) in [
            (ServiceAction::Stop, "stop"),
            (ServiceAction::Start, "start"),
            (ServiceAction::Restart, "restart"),
        ] {
            control(&l, &sys, action, &mut Vec::new()).unwrap();
            assert_eq!(
                sys.calls().last().unwrap(),
                &format!("pkexec {} {word}", helper.display())
            );
        }
        sys.pkexec_here.set(false);
        control(&l, &sys, ServiceAction::Restart, &mut Vec::new()).unwrap();
        assert_eq!(
            sys.calls().last().unwrap(),
            &format!("systemctl restart {UNIT_NAME}")
        );
        sys.root.set(true);
        // A node that does not come up is said.
        sys.starts.set(false);
        assert!(control(&l, &sys, ServiceAction::Restart, &mut Vec::new()).is_err());
        let none = service_status(&layout(&d.path().join("elsewhere")), None);
        assert_eq!(none["installed"], false);
        assert_eq!(none["state"], serde_json::Value::Null);
        assert_eq!(none["present"], false);
    }

    #[test]
    fn systemd_states_read_as_the_service_states() {
        let s = unit_state_of("ActiveState=active\nUnitFileState=enabled\n");
        assert_eq!((s.state.as_str(), s.enabled), ("running", Some(true)));
        let s = unit_state_of("ActiveState=failed\nUnitFileState=disabled\n");
        assert_eq!((s.state.as_str(), s.enabled), ("failed", Some(false)));
        let s = unit_state_of("ActiveState=activating\n");
        assert_eq!((s.state.as_str(), s.enabled), ("starting", None));
        assert_eq!(unit_state_of("ActiveState=inactive").state, "stopped");
    }

    /// The folder `install` says to give is one the center's commands can
    /// run in: folder mode needs `x` on a command's working folder.
    #[test]
    fn the_folder_install_suggests_lets_commands_run() {
        let rights: Vec<String> = NEXT
            .split("folder add <folder> ")
            .nth(1)
            .unwrap()
            .split('`')
            .next()
            .unwrap()
            .split_whitespace()
            .map(str::to_string)
            .collect();
        let a = crate::folder_change::FolderChange::new_rights(&rights).unwrap();
        assert!(a.read && a.write && a.execute, "{a:?}");
    }
}
