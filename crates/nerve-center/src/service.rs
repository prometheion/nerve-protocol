//! The center as a service (docs/user/center.md, "Run it as a service"):
//! `install`, `update` and `uninstall`, on Linux with systemd, as the node
//! has them ([`nerve_node::service`]). The service runs `nerve-center` with
//! MCP over HTTP under a user of its own, `nerve-center`, which owns the
//! center's state folder and nothing else. Its settings are the `NERVE_*`
//! variables in a file of root's that the unit reads, so the center cannot
//! change how it is started.
//!
//! What these commands do to the machine beyond the center's files (the
//! user, systemd, running a program) goes through [`System`], so the tests
//! run every step on temporary folders.

use std::io::Write;
use std::path::{Path, PathBuf};

use nerve_node::service::{Account, Version, as_owner_of, set_mode, write_file};

use crate::config::Cmd;

/// The user the service runs as.
pub const USER: &str = "nerve-center";
/// The comment `install` gives that user. A `nerve-center` user without it
/// was not made by `install`: install does not take it over, uninstall
/// leaves it.
pub const USER_MARK: &str = "Nerve center";
/// The systemd unit.
pub const UNIT_NAME: &str = "nerve-center.service";
/// The settings file in the settings folder.
pub const SETTINGS_FILE: &str = "center.env";

const LINUX_ONLY: &str = "works on Linux with systemd only; elsewhere run `nerve-center --mcp http` under your own service manager";

/// Where an installed center lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// The systemd unit file.
    pub unit: PathBuf,
    /// The program the service runs.
    pub bin: PathBuf,
    /// The state folder, which is also the home of the service's user.
    pub state: PathBuf,
    /// The folder of the settings file. It is root's: the center reads its
    /// settings from the environment the unit gives it, never from here.
    pub settings_dir: PathBuf,
    /// Where `update` finds the programs of the latest release and their
    /// `SHA256SUMS`.
    pub release: String,
}

impl Layout {
    /// The places on this machine.
    pub fn system() -> Layout {
        Layout {
            unit: PathBuf::from("/etc/systemd/system").join(UNIT_NAME),
            bin: "/usr/local/bin/nerve-center".into(),
            state: "/var/lib/nerve-center".into(),
            settings_dir: "/etc/nerve-center".into(),
            release: concat!(env!("CARGO_PKG_REPOSITORY"), "/releases/latest/download").into(),
        }
    }

    /// The settings file the unit reads.
    pub fn settings(&self) -> PathBuf {
        self.settings_dir.join(SETTINGS_FILE)
    }

    /// Whether `install` put the center here.
    pub fn installed(&self) -> bool {
        cfg!(target_os = "linux") && self.unit.is_file()
    }

    /// The service unit. The center runs as its own user with MCP over
    /// HTTP, since no harness gives it a stdin; the settings file comes
    /// after that default, so it may set another mode. Unlike the node it
    /// starts no command and needs no privilege at all: it keeps no
    /// capability, gets no new privileges, and may write its state folder
    /// only. The rest keeps a center an attacker took over from the kernel
    /// paths it never needs: no namespaces (a user namespace would give it
    /// capabilities of its own there), sockets of the internet and Unix
    /// only, the system calls of an ordinary service, no shared memory.
    pub fn unit_text(&self) -> String {
        format!(
            "# Written by `nerve-center install`; `nerve-center uninstall` removes it.
[Unit]
Description=Nerve center
Documentation={repo}
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User={USER}
Group={USER}
Environment=HOME={state}
Environment=NERVE_MCP=http
EnvironmentFile=-{settings}
ExecStart={bin} --state-dir {state}
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ReadWritePaths={state}
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
InaccessiblePaths=-/dev/shm
RemoveIPC=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid

[Install]
WantedBy=multi-user.target
",
            repo = env!("CARGO_PKG_REPOSITORY"),
            state = self.state.display(),
            settings = self.settings().display(),
            bin = self.bin.display(),
        )
    }

    /// The settings file `install` writes when there is none: the harness
    /// token of the HTTP MCP endpoint, and the other settings as comments
    /// with their defaults.
    pub fn settings_text(token: &str) -> String {
        format!(
            "# The settings of the installed center, read by the service at its start:
# `sudo systemctl restart {UNIT_NAME}` after a change. `nerve-center install`
# wrote this file once and keeps it. Each variable is a flag of
# `nerve-center --help`.
#
# The harness token: harnesses send it to the HTTP MCP endpoint. It does not
# log in to the web UI, which asks for the owner token in
# /var/lib/nerve-center/owner-token. More can be made in the web UI.
NERVE_HARNESS_TOKEN={token}
#NERVE_NAME=nerve-center
#NERVE_LISTEN=0.0.0.0:7443
#NERVE_PUBLIC_URL=https://<host name>:7443
#NERVE_UI=127.0.0.1:7480
#NERVE_MCP_LISTEN=127.0.0.1:7481
#NERVE_LOG=info
"
        )
    }
}

/// What install, update and uninstall do to the machine besides writing the
/// center's files.
pub trait System {
    fn is_root(&self) -> bool;
    /// Whether systemd runs this machine.
    fn has_systemd(&self) -> bool;
    fn account(&self, name: &str) -> Result<Option<Account>, String>;
    /// Makes a system user with a group of the same name, the home given
    /// (not created) and no login, marked with [`USER_MARK`].
    fn add_account(&self, name: &str, home: &Path) -> Result<(), String>;
    /// Removes the user and its group.
    fn remove_account(&self, name: &str) -> Result<(), String>;
    fn systemctl(&self, args: &[&str]) -> Result<(), String>;
    /// Gives `path` and everything below it to `uid`:`gid`.
    fn give(&self, path: &Path, uid: u32, gid: u32) -> Result<(), String>;
    /// Waits until the center the service started answers on the harness
    /// socket of its state folder.
    fn wait_running(&self, state: &Path) -> Result<(), String>;
    /// What `<program> --version` prints, run as `account`.
    fn version_of(&self, program: &Path, account: &Account) -> Result<String, String>;
}

/// This machine. What the node's service does the same way is the node's
/// own code ([`nerve_node::service::Host`]).
pub struct Host;

impl System for Host {
    fn is_root(&self) -> bool {
        node::System::is_root(&node::Host)
    }

    fn has_systemd(&self) -> bool {
        node::System::has_systemd(&node::Host)
    }

    fn account(&self, name: &str) -> Result<Option<Account>, String> {
        node::System::account(&node::Host, name)
    }

    fn add_account(&self, name: &str, home: &Path) -> Result<(), String> {
        node::run(
            "useradd",
            &[
                "--system",
                "--user-group",
                "--home-dir",
                &home.display().to_string(),
                "--no-create-home",
                "--shell",
                node::no_login(),
                "--comment",
                USER_MARK,
                "--",
                name,
            ],
        )
    }

    fn remove_account(&self, name: &str) -> Result<(), String> {
        node::System::remove_account(&node::Host, name)
    }

    fn systemctl(&self, args: &[&str]) -> Result<(), String> {
        node::System::systemctl(&node::Host, args)
    }

    fn give(&self, path: &Path, uid: u32, gid: u32) -> Result<(), String> {
        node::System::give(&node::Host, path, uid, gid)
    }

    fn wait_running(&self, state: &Path) -> Result<(), String> {
        let socket = crate::attach::socket_path(state);
        for _ in 0..60 {
            if answers(&socket) {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        Err(format!(
            "the service started, but the center does not answer on {}; `journalctl -u {UNIT_NAME}` says why",
            socket.display()
        ))
    }

    fn version_of(&self, program: &Path, account: &Account) -> Result<String, String> {
        node::System::version_of(&node::Host, program, account)
    }
}

mod node {
    pub use nerve_node::service::{Host, System, no_login, run};
}

/// Whether a center takes a connection on the harness socket `socket`. The
/// center binds it after every other listener, and removes one an earlier
/// run left before, so one that answers belongs to a center that started.
/// The connection ends at once, before it says hello, which the center
/// drops without a session.
fn answers(socket: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::net::UnixStream::connect(socket).is_ok()
    }
    #[cfg(not(unix))]
    {
        let _ = socket;
        false
    }
}

/// Whether `what` can run here: Linux, root and systemd.
fn supported(sys: &dyn System, what: &str) -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err(format!("{what} {LINUX_ONLY}"));
    }
    if !sys.is_root() {
        return Err(format!("{what} needs root: run `sudo nerve-center {what}`"));
    }
    if !sys.has_systemd() {
        return Err(format!(
            "{what} needs systemd, which does not run this machine; run `nerve-center --mcp http` under your own service manager"
        ));
    }
    Ok(())
}

/// Run first in `main` for `backup` and `restore`, while the process has one
/// thread: root's command on a state folder that belongs to another user,
/// as the installed center's belongs to `nerve-center`, runs as that user
/// ([`nerve_node::service::become_owner`], as the node's commands do). Root
/// then follows no link that user put there, and what it writes stays the
/// center's, so the service starts on it. Says whether it switched.
pub fn settle_user(state: &Path) -> Result<bool, String> {
    let before = nerve_transport::net::euid();
    nerve_node::service::become_owner(&nerve_node::NodePaths::new(state, state), false)?;
    Ok(nerve_transport::net::euid() != before)
}

/// Says a step as it is done.
fn did(out: &mut dyn Write, step: impl std::fmt::Display) {
    let _ = writeln!(out, "{step}");
}

/// Runs `install`, `update` or `uninstall` on this machine. As the node's
/// own, none of them may be run by a command the installed node runs for a
/// center ([`nerve_node::cli::owner_check`]): an agent cannot replace or
/// remove its center either.
/// `given` are the center's settings the owner gave with the command
/// ([`crate::config::settings_given`]): none of them reaches the service,
/// whose settings are in its settings file, so they are refused.
pub async fn execute(cmd: Cmd, given: &[String], out: &mut dyn Write) -> Result<(), String> {
    let node = nerve_node::service::Layout::system().paths;
    execute_on(cmd, given, &Layout::system(), &Host, &node, out).await
}

/// [`execute`] on `layout`, with `node` the installed node's folders.
async fn execute_on(
    cmd: Cmd,
    given: &[String],
    layout: &Layout,
    sys: &dyn System,
    node: &nerve_node::NodePaths,
    out: &mut dyn Write,
) -> Result<(), String> {
    let what = match &cmd {
        Cmd::Install => "install",
        Cmd::Update { .. } => "update",
        Cmd::Uninstall { .. } => "uninstall",
        // `main` gives these to crate::backup and crate::owner.
        Cmd::Backup { .. } | Cmd::Restore { .. } | Cmd::OwnerToken { .. } => {
            return Err("backup, restore and owner-token are not service commands".into());
        }
    };
    if !given.is_empty() {
        return Err(format!(
            "{what} takes none of the center's settings ({}): the installed center reads them from {} and keeps its state in {}. Run `sudo nerve-center {what}` without them, and set them in that file",
            given.join(", "),
            layout.settings().display(),
            layout.state.display()
        ));
    }
    // Root first: a caller without it cannot reach the node's control
    // socket either, and would be told about that instead of about sudo.
    // Nothing changes before either check.
    supported(sys, what)?;
    nerve_node::cli::owner_check(&[node]).await?;
    match cmd {
        Cmd::Install => {
            let exe = std::env::current_exe().map_err(|e| format!("this program: {e}"))?;
            install(layout, sys, &exe, out)
        }
        Cmd::Update { from } => update(layout, sys, from.as_deref(), out).await,
        Cmd::Uninstall { purge } => uninstall(layout, sys, purge, out),
        Cmd::Backup { .. } | Cmd::Restore { .. } | Cmd::OwnerToken { .. } => {
            unreachable!("refused above")
        }
    }
}

/// `install`: the user, the state folder, the settings, the program, the
/// unit, the running service, in that order. Running it again puts back
/// what is missing, keeps the settings and restarts the service.
pub fn install(
    layout: &Layout,
    sys: &dyn System,
    exe: &Path,
    out: &mut dyn Write,
) -> Result<(), String> {
    supported(sys, "install")?;
    let account = match sys.account(USER)? {
        Some(a) if a.comment == USER_MARK => {
            did(out, format!("the user {USER} is there already"));
            a
        }
        Some(_) => {
            return Err(format!(
                "a user {USER} exists already, and nerve-center install did not make it; the center needs a user of its own"
            ));
        }
        None => {
            sys.add_account(USER, &layout.state)?;
            let a = sys
                .account(USER)?
                .ok_or_else(|| format!("useradd made no user {USER}"))?;
            did(out, format!("made the user {USER} (uid {})", a.uid));
            a
        }
    };
    let state = &layout.state;
    nerve_transport::files::create_private_dir(state)
        .map_err(|e| format!("{}: {e}", state.display()))?;
    // The owner token is made here, before the service first starts, so
    // that install can say it; one an earlier install made is kept.
    let owner_token = {
        // An earlier install's folder may hold what its user put there; it
        // is changed and read as that user, and a link in its place is
        // refused.
        let _owner = as_owner_of(state)?;
        set_mode(state, 0o700)?;
        crate::owner::ensure(state)?.0
    };
    // The folder may be left from an earlier install, whose user had
    // another uid: everything in it is given to this one.
    sys.give(state, account.uid, account.gid)?;
    did(out, format!("{} belongs to {USER}", state.display()));
    settings(layout, sys, out)?;
    let real = |p: &Path| std::fs::canonicalize(p).ok();
    if real(exe).is_some() && real(exe) == real(&layout.bin) {
        did(
            out,
            format!("the program is at {} already", layout.bin.display()),
        );
    } else {
        let program = std::fs::read(exe).map_err(|e| format!("{}: {e}", exe.display()))?;
        write_file(&layout.bin, &program, 0o755)?;
        did(out, format!("put the program at {}", layout.bin.display()));
    }
    write_file(&layout.unit, layout.unit_text().as_bytes(), 0o644)?;
    did(
        out,
        format!("wrote the service unit {}", layout.unit.display()),
    );
    sys.systemctl(&["daemon-reload"])?;
    sys.systemctl(&["enable", UNIT_NAME])?;
    sys.systemctl(&["restart", UNIT_NAME])?;
    sys.wait_running(state)?;
    did(
        out,
        format!("the service {UNIT_NAME} runs as {USER} and starts with the machine"),
    );
    let _ = writeln!(
        out,
        "Next: open the web UI (http://127.0.0.1:7480 unless {} says otherwise) and log in with the owner token:\n\n    {owner_token}\n\nIt is kept in {} (`sudo cat` it, or `sudo nerve-center --state-dir {} owner-token --new` makes a new one). Harnesses use the HTTP MCP endpoint with the harness token in that settings file: `sudo grep NERVE_HARNESS_TOKEN {}`.",
        layout.settings().display(),
        crate::owner::path(state).display(),
        state.display(),
        layout.settings().display()
    );
    Ok(())
}

/// The settings folder, root's and private, and the settings file in it:
/// made with a new harness token when there is none, else kept as the
/// owner left it.
fn settings(layout: &Layout, sys: &dyn System, out: &mut dyn Write) -> Result<(), String> {
    let dir = &layout.settings_dir;
    nerve_transport::files::create_private_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    let m = std::fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if m.file_type().is_symlink() {
        return Err(format!(
            "{} is a link; the settings folder is a folder, and root does not follow it",
            dir.display()
        ));
    }
    sys.give(dir, 0, 0)?;
    set_mode(dir, 0o700)?;
    let file = layout.settings();
    if std::fs::symlink_metadata(&file).is_ok() {
        did(out, format!("kept the settings in {}", file.display()));
        return Ok(());
    }
    let token = format!("nrv_{}", nerve_transport::keys::random_token(40));
    write_file(&file, Layout::settings_text(&token).as_bytes(), 0o600)?;
    did(
        out,
        format!(
            "wrote the settings to {}, with a new harness token",
            file.display()
        ),
    );
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
    let mut done = false;
    let mut step = |out: &mut dyn Write, what: String| {
        done = true;
        did(out, what);
    };
    if layout.unit.exists() {
        sys.systemctl(&["disable", "--now", UNIT_NAME])?;
        step(out, format!("stopped the service {UNIT_NAME}"));
        std::fs::remove_file(&layout.unit)
            .map_err(|e| format!("{}: {e}", layout.unit.display()))?;
        sys.systemctl(&["daemon-reload"])?;
        // Only clears a failed state systemd still shows.
        let _ = sys.systemctl(&["reset-failed", UNIT_NAME]);
        step(
            out,
            format!("removed the service unit {}", layout.unit.display()),
        );
    }
    let folders = [&layout.state, &layout.settings_dir];
    if purge {
        for dir in folders {
            if dir.exists() {
                std::fs::remove_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
                step(out, format!("deleted {}", dir.display()));
            }
        }
    } else if folders.iter().any(|d| d.exists()) {
        // Its user goes; a uid nobody has must not own the center's key,
        // since the next user to get it would. The settings are root's
        // already.
        if layout.state.exists() {
            sys.give(&layout.state, 0, 0)?;
        }
        step(
            out,
            format!(
                "kept {} and {} (they belong to root now; `uninstall --purge` deletes them)",
                layout.state.display(),
                layout.settings_dir.display()
            ),
        );
    }
    match sys.account(USER)? {
        Some(a) if a.comment == USER_MARK => {
            sys.remove_account(USER)?;
            step(out, format!("removed the user {USER}"));
        }
        Some(_) => {
            let _ = writeln!(
                out,
                "left the user {USER} as it is: nerve-center install did not make it"
            );
        }
        None => {}
    }
    if layout.bin.exists() {
        std::fs::remove_file(&layout.bin).map_err(|e| format!("{}: {e}", layout.bin.display()))?;
        step(out, format!("removed the program {}", layout.bin.display()));
    }
    if !done {
        let _ = writeln!(
            out,
            "nothing to uninstall: no service, user {USER} or program of the center is here"
        );
    }
    Ok(())
}

/// `update`: the new program (the latest release, checked against its
/// `SHA256SUMS`, or a file the owner gives) replaces the installed one, and
/// the service restarts. The state folder and the settings are not
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
            "the center is not installed as a service here; `sudo nerve-center install` installs it"
                .into(),
        );
    }
    let account = sys
        .account(USER)?
        .filter(|a| a.comment == USER_MARK)
        .ok_or_else(|| {
            format!("the user {USER} is missing; `sudo nerve-center install` makes it again")
        })?;
    let new = match from {
        Some(f) => {
            let b = std::fs::read(f).map_err(|e| format!("{}: {e}", f.display()))?;
            did(out, format!("read the new program from {}", f.display()));
            b
        }
        None => {
            let asset = asset_name()?;
            let b = nerve_node::service::fetch_release(&layout.release, &asset).await?;
            did(
                out,
                format!(
                    "downloaded {asset} from {} and checked it against its SHA256SUMS",
                    layout.release
                ),
            );
            b
        }
    };
    let old = std::fs::read(&layout.bin).map_err(|e| format!("{}: {e}", layout.bin.display()))?;
    if new == old {
        did(
            out,
            "the installed program is that one already; nothing to update",
        );
        return Ok(());
    }
    // Staged beside the program, so the rename that puts it in place does
    // not cross file systems.
    let staged = layout.bin.with_file_name(".nerve-center.new");
    write_file(&staged, &new, 0o755)?;
    let checked = (|| {
        let said = sys.version_of(&staged, &account)?;
        let new_v = Version::parse_of("nerve-center", &said)
            .ok_or_else(|| format!("the new program is not nerve-center: it says {said:?}"))?;
        let old_v = sys
            .version_of(&layout.bin, &account)
            .ok()
            .and_then(|s| Version::parse_of("nerve-center", &s));
        if let Some(o) = old_v
            && new_v < o
        {
            return Err(format!(
                "the new program is nerve-center {new_v}, older than the installed {o}; nothing changed"
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
    did(out, format!("replaced nerve-center {old_v} with {new_v}"));
    let started = sys
        .systemctl(&["restart", UNIT_NAME])
        .and_then(|()| sys.wait_running(&layout.state));
    if let Err(e) = started {
        write_file(&layout.bin, &old, 0o755)?;
        let back = sys
            .systemctl(&["restart", UNIT_NAME])
            .and_then(|()| sys.wait_running(&layout.state));
        did(out, format!("put nerve-center {old_v} back"));
        return Err(match back {
            Ok(()) => format!("the new program did not start ({e}); the old one runs again"),
            Err(e2) => format!(
                "the new program did not start ({e}), and the old one does not either ({e2})"
            ),
        });
    }
    did(out, format!("restarted the service {UNIT_NAME}"));
    // A center installed before the owner token got one at this start, and
    // its web UI no longer takes the harness token.
    let _ = writeln!(
        out,
        "The web UI logs in with the owner token kept in {} (`sudo cat` it).",
        crate::owner::path(&layout.state).display()
    );
    Ok(())
}

/// The release file of this machine's program.
fn asset_name() -> Result<String, String> {
    match std::env::consts::ARCH {
        arch @ ("x86_64" | "aarch64") if cfg!(target_os = "linux") => {
            Ok(format!("nerve-center-{arch}-linux"))
        }
        other => Err(format!(
            "the releases have no program of the center for {other}; build one (docs/dev/building.md) and give it with --from"
        )),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    /// A machine in a temporary folder: the user is the test's own, and
    /// systemctl and the center's start are recorded.
    struct Fake {
        user: RefCell<Option<Account>>,
        calls: RefCell<Vec<String>>,
        /// The folders given to another user, and to whom.
        given: RefCell<Vec<(PathBuf, u32)>>,
        /// Whether a center started by the service answers.
        starts: Cell<bool>,
        /// Whether the next start answers, before `starts` holds again:
        /// the old program that goes back starts where the new one did not.
        next_start: Cell<Option<bool>>,
    }

    impl Fake {
        fn new() -> Fake {
            Fake {
                user: RefCell::new(None),
                calls: RefCell::new(Vec::new()),
                given: RefCell::new(Vec::new()),
                starts: Cell::new(true),
                next_start: Cell::new(None),
            }
        }

        fn calls(&self) -> Vec<String> {
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
            home: "/var/lib/nerve-center".into(),
            groups: vec![gid],
        }
    }

    impl System for Fake {
        fn is_root(&self) -> bool {
            true
        }
        fn has_systemd(&self) -> bool {
            true
        }
        fn account(&self, name: &str) -> Result<Option<Account>, String> {
            assert_eq!(name, USER);
            Ok(self.user.borrow().clone())
        }
        fn add_account(&self, name: &str, home: &Path) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(format!("useradd {name} {}", home.display()));
            *self.user.borrow_mut() = Some(me());
            Ok(())
        }
        fn remove_account(&self, name: &str) -> Result<(), String> {
            self.calls.borrow_mut().push(format!("userdel {name}"));
            *self.user.borrow_mut() = None;
            Ok(())
        }
        fn systemctl(&self, args: &[&str]) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(format!("systemctl {}", args.join(" ")));
            Ok(())
        }
        /// The test may give files to itself only; giving them to anyone
        /// else is recorded.
        fn give(&self, path: &Path, uid: u32, gid: u32) -> Result<(), String> {
            if uid == me().uid {
                node::System::give(&node::Host, path, uid, gid)
            } else {
                self.given.borrow_mut().push((path.to_path_buf(), uid));
                Ok(())
            }
        }
        fn wait_running(&self, _state: &Path) -> Result<(), String> {
            let starts = self.next_start.take().unwrap_or(self.starts.get());
            if starts {
                Ok(())
            } else {
                Err("the center does not answer".into())
            }
        }
        /// A program here is a text file whose first line is what it says.
        fn version_of(&self, program: &Path, account: &Account) -> Result<String, String> {
            assert_eq!(account.comment, USER_MARK);
            let text = std::fs::read_to_string(program).map_err(|e| e.to_string())?;
            Ok(text.lines().next().unwrap_or_default().to_string())
        }
    }

    /// A machine where the caller is not root.
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
        fn add_account(&self, _: &str, _: &Path) -> Result<(), String> {
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
        fn wait_running(&self, _: &Path) -> Result<(), String> {
            unreachable!()
        }
        fn version_of(&self, _: &Path, _: &Account) -> Result<String, String> {
            unreachable!()
        }
    }

    fn layout(root: &Path) -> Layout {
        Layout {
            unit: root.join("etc/systemd/system").join(UNIT_NAME),
            bin: root.join("usr/local/bin/nerve-center"),
            state: root.join("var/lib/nerve-center"),
            settings_dir: root.join("etc/nerve-center"),
            release: "http://127.0.0.1:1/none".into(),
        }
    }

    /// Installs a "program" saying `version` from a file in `root`.
    fn installed(root: &Path, sys: &Fake, version: &str) -> Layout {
        let l = layout(root);
        let exe = root.join("download/nerve-center-x86_64-linux");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, format!("nerve-center {version}\n")).unwrap();
        install(&l, sys, &exe, &mut Vec::new()).unwrap();
        l
    }

    fn mode(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    fn token(l: &Layout) -> String {
        std::fs::read_to_string(l.settings())
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("NERVE_HARNESS_TOKEN="))
            .unwrap()
            .to_string()
    }

    #[test]
    fn install_puts_the_center_under_its_own_user() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = layout(d.path());
        // The program as the release names it lands as nerve-center.
        let exe = d.path().join("download/nerve-center-x86_64-linux");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, "nerve-center 1.0.0\n").unwrap();
        let mut out = Vec::new();
        install(&l, &sys, &exe, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("made the user nerve-center"), "{out}");
        assert!(out.contains("with a new harness token"), "{out}");
        assert!(out.contains("sudo grep NERVE_HARNESS_TOKEN"), "{out}");
        // The owner token is made before the service starts, kept private in
        // the state folder, and said with where it is.
        let owner = crate::owner::read(&l.state)
            .unwrap()
            .expect("an owner token");
        assert!(owner.starts_with(crate::owner::PREFIX), "{owner}");
        let owner_file = crate::owner::path(&l.state);
        assert_eq!(mode(&owner_file), 0o600);
        assert!(out.contains(&format!("\n    {owner}\n")), "{out}");
        assert!(out.contains(&owner_file.display().to_string()), "{out}");
        assert!(out.contains("owner-token --new"), "{out}");
        // The user, made once with the state folder as its home.
        assert_eq!(
            sys.calls(),
            [
                format!("useradd nerve-center {}", l.state.display()),
                "systemctl daemon-reload".into(),
                format!("systemctl enable {UNIT_NAME}"),
                format!("systemctl restart {UNIT_NAME}"),
            ]
        );
        // The program, the unit, the state folder private to the user, the
        // settings root's.
        assert_eq!(std::fs::read(&l.bin).unwrap(), b"nerve-center 1.0.0\n");
        assert_eq!(mode(&l.bin), 0o755);
        let unit = std::fs::read_to_string(&l.unit).unwrap();
        assert_eq!(unit, l.unit_text());
        assert_eq!(mode(&l.unit), 0o644);
        assert!(unit.contains("\nUser=nerve-center\n"), "{unit}");
        assert!(
            unit.contains(&format!(
                "\nExecStart={} --state-dir {}\n",
                l.bin.display(),
                l.state.display()
            )),
            "{unit}"
        );
        // MCP over HTTP, which the settings may change as they come later.
        let env = unit.find("Environment=NERVE_MCP=http\n").unwrap();
        let file = unit
            .find(&format!("EnvironmentFile=-{}\n", l.settings().display()))
            .unwrap();
        assert!(env < file, "{unit}");
        // No privilege, and the state folder is the one place it writes.
        for line in [
            "NoNewPrivileges=yes",
            "CapabilityBoundingSet=",
            "ProtectSystem=strict",
            &format!("ReadWritePaths={}", l.state.display()),
            "InaccessiblePaths=-/dev/shm",
            "RestrictNamespaces=yes",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            "SystemCallFilter=@system-service",
            "MemoryDenyWriteExecute=yes",
        ] {
            assert!(unit.contains(&format!("\n{line}\n")), "{line}: {unit}");
        }
        assert!(!unit.contains("AmbientCapabilities"), "{unit}");
        assert_eq!(mode(&l.state), 0o700);
        assert_eq!(mode(&l.settings_dir), 0o700);
        assert_eq!(mode(&l.settings()), 0o600);
        assert_eq!(
            sys.given.borrow().clone(),
            [(l.settings_dir.clone(), 0)],
            "the settings folder is root's"
        );
        let first = token(&l);
        assert!(first.starts_with("nrv_") && first.len() == 44, "{first}");
        // Again: the user is reused, the program replaced, the settings and
        // their token kept, the service restarted.
        std::fs::write(&exe, "nerve-center 1.0.1\n").unwrap();
        let mut out = Vec::new();
        install(&l, &sys, &exe, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("the user nerve-center is there already"),
            "{out}"
        );
        assert!(out.contains("kept the settings"), "{out}");
        assert_eq!(std::fs::read(&l.bin).unwrap(), b"nerve-center 1.0.1\n");
        assert_eq!(token(&l), first);
        assert_eq!(crate::owner::read(&l.state).unwrap(), Some(owner.clone()));
        assert!(out.contains(&owner), "{out}");
        assert_eq!(
            sys.calls()
                .iter()
                .filter(|c| c.starts_with("useradd"))
                .count(),
            1
        );
        assert_eq!(
            sys.calls().last().unwrap(),
            &format!("systemctl restart {UNIT_NAME}")
        );
    }

    /// The settings file the unit reads gives the center a harness token
    /// that its flags take, for the HTTP MCP endpoint.
    #[test]
    fn the_settings_hold_a_token_the_center_takes() {
        use clap::Parser;
        let text = Layout::settings_text("nrv_abc");
        let vars: Vec<(&str, &str)> = text
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .map(|l| l.split_once('=').unwrap())
            .collect();
        assert_eq!(vars, [("NERVE_HARNESS_TOKEN", "nrv_abc")]);
        // Every setting named in a comment is a variable of the center.
        let command = <crate::config::Args as clap::CommandFactory>::command();
        let known: Vec<String> = command
            .get_arguments()
            .filter_map(|a| a.get_env().map(|e| e.to_string_lossy().into_owned()))
            .collect();
        for l in text.lines().filter_map(|l| l.strip_prefix('#')) {
            if let Some((var, _)) = l.split_once('=') {
                assert!(known.iter().any(|k| k == var), "{var}");
            }
        }
        let a = crate::config::Args::try_parse_from(["nerve-center", "--harness-token", "nrv_abc"])
            .unwrap();
        assert_eq!(a.harness_token.as_deref(), Some("nrv_abc"));
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
        let e = install(&l, &sys, Path::new("/bin/true"), &mut Vec::new()).unwrap_err();
        assert!(e.contains("did not make it"), "{e}");
        assert!(!l.bin.exists() && !l.unit.exists() && !l.state.exists());
        assert!(sys.calls().is_empty());

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        for (what, e) in [
            (
                "install",
                install(&l, &NotRoot, Path::new("/bin/true"), &mut Vec::new()),
            ),
            ("uninstall", uninstall(&l, &NotRoot, false, &mut Vec::new())),
            (
                "update",
                rt.block_on(update(&l, &NotRoot, None, &mut Vec::new())),
            ),
        ] {
            assert_eq!(
                e.unwrap_err(),
                format!("{what} needs root: run `sudo nerve-center {what}`")
            );
        }
    }

    /// A caller without root is told so first, also where an installed
    /// node's control socket, which it may not open, is there to ask.
    #[tokio::test]
    async fn without_root_the_commands_say_so_before_they_ask_the_node() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let node = nerve_node::NodePaths::new(d.path().join("etc/nerve"), d.path().join("state"));
        let run = node.ctl_socket().parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&run).unwrap();
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o000)).unwrap();
        let l = layout(d.path());
        let mut results = Vec::new();
        for (what, cmd) in [
            ("install", Cmd::Install),
            ("update", Cmd::Update { from: None }),
            ("uninstall", Cmd::Uninstall { purge: false }),
        ] {
            let r = execute_on(cmd, &[], &l, &NotRoot, &node, &mut Vec::new()).await;
            results.push((what, r));
        }
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();
        for (what, r) in results {
            assert_eq!(
                r.unwrap_err(),
                format!("{what} needs root: run `sudo nerve-center {what}`")
            );
        }
    }

    /// A setting given with a service command would reach nothing: it is
    /// refused before anything is checked or changed, with the file it
    /// belongs in.
    #[tokio::test]
    async fn the_center_s_settings_given_to_a_service_command_are_refused() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = layout(d.path());
        let node = nerve_node::NodePaths::new(d.path().join("etc/nerve"), d.path().join("node"));
        let given = ["--public-url".to_string(), "--state-dir".to_string()];
        let e = execute_on(Cmd::Install, &given, &l, &sys, &node, &mut Vec::new())
            .await
            .unwrap_err();
        assert!(
            e.starts_with(
                "install takes none of the center's settings (--public-url, --state-dir)"
            ),
            "{e}"
        );
        assert!(e.contains(&l.settings().display().to_string()), "{e}");
        assert!(sys.calls().is_empty() && !l.state.exists() && !l.unit.exists());
        // NotRoot answers nothing but that it is not root: the refusal
        // comes first.
        let e = execute_on(
            Cmd::Uninstall { purge: true },
            &["NERVE_LISTEN".to_string()],
            &l,
            &NotRoot,
            &node,
            &mut Vec::new(),
        )
        .await
        .unwrap_err();
        assert!(e.starts_with("uninstall takes none"), "{e}");
    }

    /// A link in place of the state or the settings folder is refused:
    /// install neither changes nor writes through it.
    #[test]
    fn install_follows_no_link_in_place_of_a_folder() {
        use std::os::unix::fs::PermissionsExt;
        for which in ["state", "settings"] {
            let d = tempfile::tempdir().unwrap();
            let sys = Fake::new();
            let l = layout(d.path());
            let elsewhere = d.path().join("elsewhere");
            std::fs::create_dir_all(&elsewhere).unwrap();
            std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o755)).unwrap();
            let link = if which == "state" {
                &l.state
            } else {
                &l.settings_dir
            };
            std::fs::create_dir_all(link.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(&elsewhere, link).unwrap();
            let e = install(&l, &sys, Path::new("/bin/true"), &mut Vec::new()).unwrap_err();
            assert!(e.contains("is a link"), "{which}: {e}");
            assert_eq!(mode(&elsewhere), 0o755, "{which}");
            assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
            assert!(!l.unit.exists() && !l.bin.exists(), "{which}");
            assert!(sys.given.borrow().is_empty(), "{which}");
        }
    }

    #[test]
    fn uninstall_leaves_no_service_user_or_program_and_keeps_the_folders() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        std::fs::write(l.state.join("state.json"), "{}").unwrap();
        let settings = std::fs::read(l.settings()).unwrap();
        sys.given.borrow_mut().clear();
        let mut out = Vec::new();
        uninstall(&l, &sys, false, &mut out).unwrap();
        assert!(!l.unit.exists() && !l.bin.exists());
        assert!(sys.user.borrow().is_none());
        assert!(
            sys.calls().ends_with(&[
                format!("systemctl disable --now {UNIT_NAME}"),
                "systemctl daemon-reload".into(),
                format!("systemctl reset-failed {UNIT_NAME}"),
                "userdel nerve-center".into(),
            ]),
            "{:?}",
            sys.calls()
        );
        // The state and the settings stay; no uid that may come to another
        // user owns the state: it is root's.
        assert_eq!(
            std::fs::read_to_string(l.state.join("state.json")).unwrap(),
            "{}"
        );
        assert_eq!(std::fs::read(l.settings()).unwrap(), settings);
        assert_eq!(sys.given.borrow().clone(), [(l.state.clone(), 0)]);
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("uninstall --purge"), "{out}");
        // A later install takes them up again, the token included.
        let token_before = token(&l);
        let l = installed(d.path(), &sys, "1.0.0");
        assert_eq!(token(&l), token_before);
        assert!(l.state.join("state.json").exists());
    }

    #[test]
    fn uninstall_purge_deletes_the_folders_and_leaves_a_foreign_user() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        uninstall(&l, &sys, true, &mut Vec::new()).unwrap();
        for p in [&l.unit, &l.bin, &l.state, &l.settings_dir] {
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
        // A nerve-center user that install did not make stays.
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
                .contains("left the user nerve-center")
        );
    }

    #[tokio::test]
    async fn update_replaces_the_program_and_keeps_the_state_and_settings() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        std::fs::write(l.state.join("tls.pem"), "key").unwrap();
        let kept =
            |l: &Layout| [l.state.join("tls.pem"), l.settings()].map(|p| std::fs::read(p).unwrap());
        let before = kept(&l);
        let new = d.path().join("new");
        std::fs::write(&new, "nerve-center 1.2.0\n").unwrap();
        let mut out = Vec::new();
        update(&l, &sys, Some(&new), &mut out).await.unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("replaced nerve-center 1.0.0 with 1.2.0"),
            "{out}"
        );
        let token = crate::owner::path(&l.state).display().to_string();
        assert!(out.contains(&format!("owner token kept in {token}")), "{out}");
        assert_eq!(std::fs::read(&l.bin).unwrap(), b"nerve-center 1.2.0\n");
        assert_eq!(mode(&l.bin), 0o755);
        assert_eq!(
            sys.calls().last().unwrap(),
            &format!("systemctl restart {UNIT_NAME}")
        );
        assert_eq!(kept(&l), before);
        assert!(!l.bin.with_file_name(".nerve-center.new").exists());
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
            ("nerve-center 1.1.9\n", "older than the installed 1.2.0"),
            ("nerve-node 9.0.0\n", "is not nerve-center"),
            ("nerve-centerx 9.0.0\n", "is not nerve-center"),
        ] {
            std::fs::write(&new, text).unwrap();
            let calls = sys.calls().len();
            let e = update(&l, &sys, Some(&new), &mut Vec::new())
                .await
                .unwrap_err();
            assert!(e.contains(why), "{e}");
            assert_eq!(std::fs::read(&l.bin).unwrap(), b"nerve-center 1.2.0\n");
            assert!(!l.bin.with_file_name(".nerve-center.new").exists());
            assert_eq!(sys.calls().len(), calls, "nothing restarted");
        }
        // The new one does not start; the old one goes back and does.
        std::fs::write(&new, "nerve-center 2.0.0\n").unwrap();
        sys.next_start.set(Some(false));
        let mut out = Vec::new();
        let e = update(&l, &sys, Some(&new), &mut out).await.unwrap_err();
        assert!(e.contains("did not start"), "{e}");
        assert!(e.contains("the old one runs again"), "{e}");
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("put nerve-center 1.2.0 back")
        );
        assert_eq!(std::fs::read(&l.bin).unwrap(), b"nerve-center 1.2.0\n");
        assert_eq!(
            sys.calls()
                .iter()
                .rev()
                .take(2)
                .filter(|c| **c == format!("systemctl restart {UNIT_NAME}"))
                .count(),
            2
        );
        // Neither starts: both are said.
        sys.starts.set(false);
        let e = update(&l, &sys, Some(&new), &mut Vec::new())
            .await
            .unwrap_err();
        assert!(e.contains("the old one does not either"), "{e}");
        assert_eq!(std::fs::read(&l.bin).unwrap(), b"nerve-center 1.2.0\n");
    }

    #[tokio::test]
    async fn update_needs_an_installed_center() {
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
        let asset = asset_name().unwrap();
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

    #[tokio::test]
    async fn update_downloads_the_center_of_the_release_and_checks_it() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let mut l = installed(d.path(), &sys, "1.0.0");
        let program: &[u8] = b"nerve-center 1.3.0\n";
        let asset = asset_name().unwrap();
        assert!(asset.starts_with("nerve-center-"), "{asset}");
        let sha = crate::util::sha256_hex;
        l.release = release(
            program,
            format!(
                "{}  nerve-node-x86_64-linux\n{} *{asset}\n",
                sha(b"x"),
                sha(program)
            ),
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
        assert_eq!(std::fs::read(&l2.bin).unwrap(), b"nerve-center 1.0.0\n");
    }

    /// The center is known to run when its harness socket takes a
    /// connection: a socket file an earlier run left does not count.
    #[test]
    fn a_center_answers_on_its_harness_socket() {
        let d = tempfile::tempdir().unwrap();
        let socket = crate::attach::socket_path(d.path());
        assert!(!answers(&socket));
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        assert!(answers(&socket));
        drop(listener);
        assert!(socket.exists());
        assert!(!answers(&socket));
    }
}
