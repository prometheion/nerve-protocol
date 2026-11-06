//! The center as a service (docs/dev/service.md, "The center as a service"):
//! `install`, `update` and `uninstall`, on Linux with systemd, as the node
//! has them: what both do the same way, `update` among it, is
//! [`nerve_service`]'s. The service runs `nerve-center` with
//! MCP over HTTP under a user of its own, `nerve-center`, which owns the
//! center's state folder and nothing else. Its settings are the
//! `NERVE_CENTER_*` variables in a file of root's that the unit reads, so the
//! center cannot change how it is started.
//!
//! What these commands do to the machine beyond the center's files (the
//! user, systemd, running a program) goes through [`System`], so the tests
//! run every step on temporary folders.

use std::io::Write;
use std::path::{Path, PathBuf};

use nerve_service::{Account, Steps, as_owner_of, set_mode, write_file};

use nerve_transport::log::Level;

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
Environment=NERVE_CENTER_MCP=http
EnvironmentFile=-{settings}
ExecStart={bin} --state-dir {state}
Restart=on-failure
RestartSec=5
UMask=0077
LimitNOFILE=65536
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
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
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
    /// token of the HTTP MCP endpoint, the settings `install` was given
    /// (`set`, by variable), and the others as comments with their
    /// defaults.
    pub fn settings_text(token: &str, set: &[(&str, String)]) -> String {
        let line = |var: &str, default: &str| match set.iter().find(|(v, _)| *v == var) {
            Some((_, value)) => format!("{var}={value}"),
            None => format!("#{var}={default}"),
        };
        format!(
            "# The settings of the installed center, read by the service at its start:
# `sudo systemctl restart {UNIT_NAME}` after a change. `nerve-center install`
# wrote this file and keeps it; `install --name`, `--public-url` and
# `--listen` set those here. Each variable is a flag of `nerve-center --help`.
#
# The harness token: harnesses send it to the HTTP MCP endpoint. It does not
# log in to the web UI, which asks for the owner token in
# /var/lib/nerve-center/owner-token. More can be made in the web UI.
NERVE_CENTER_HARNESS_TOKEN={token}
{}
{}
{}
#NERVE_CENTER_UI=127.0.0.1:7480
#NERVE_CENTER_MCP=127.0.0.1:7481
#NERVE_CENTER_LOG=info
",
            line("NERVE_CENTER_NAME", "nerve-center"),
            line("NERVE_CENTER_LISTEN", "0.0.0.0:7443"),
            line("NERVE_CENTER_PUBLIC_URL", "https://<host name>:7443"),
        )
    }
}

/// What install, update and uninstall do to the machine besides writing the
/// center's files: what the node's service asks of it too
/// ([`nerve_service::System`]), and the center's own.
pub trait System: nerve_service::System {
    /// Waits until the center the service started answers on the harness
    /// socket of its state folder.
    fn wait_running(&self, state: &Path) -> Result<(), String>;
}

/// This machine.
pub struct Host;

impl nerve_service::System for Host {
    fn is_root(&self) -> bool {
        nerve_service::Host.is_root()
    }

    fn has_systemd(&self) -> bool {
        nerve_service::Host.has_systemd()
    }

    fn account(&self, name: &str) -> Result<Option<Account>, String> {
        nerve_service::Host.account(name)
    }

    fn add_account(&self, name: &str, home: &Path, mark: &str) -> Result<(), String> {
        nerve_service::Host.add_account(name, home, mark)
    }

    fn remove_account(&self, name: &str) -> Result<(), String> {
        nerve_service::Host.remove_account(name)
    }

    fn systemctl(&self, args: &[&str]) -> Result<(), String> {
        nerve_service::Host.systemctl(args)
    }

    fn give(&self, path: &Path, uid: u32, gid: u32) -> Result<(), String> {
        nerve_service::Host.give(path, uid, gid)
    }

    fn output_of(
        &self,
        program: &Path,
        account: Option<&Account>,
        args: &[&str],
    ) -> Result<String, String> {
        nerve_service::Host.output_of(program, account, args)
    }
}

impl System for Host {
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
/// ([`nerve_service::become_owner`], as the node's commands do). Root
/// then follows no link that user put there, and what it writes stays the
/// center's, so the service starts on it. Says whether it switched.
pub fn settle_user(state: &Path) -> Result<bool, String> {
    let before = nerve_transport::net::euid();
    nerve_service::become_owner(&[state], false)?;
    Ok(nerve_transport::net::euid() != before)
}

/// Runs `f` (a restore) with the installed service stopped, where `state`
/// is its folder and it runs, and starts it again after, whether `f` did
/// its work or not. Elsewhere `f` alone, which refuses a running center.
pub fn with_service_stopped(
    layout: &Layout,
    state: &Path,
    out: &mut dyn Write,
    f: &dyn Fn(&mut dyn Write) -> Result<(), String>,
) -> Result<(), String> {
    let ours = cfg!(target_os = "linux")
        && layout.installed()
        && state == layout.state
        && nerve_transport::net::euid() == 0
        && crate::attach::runs(state) == Some(true);
    if !ours {
        return f(out);
    }
    // The restore becomes the folder's owner for its work, for good: it
    // runs in a child, so that this process, root still, starts the service
    // again. The child finds no center running and restores.
    stopped_for(&Host, out, &|| {
        std::env::current_exe()
            .and_then(|exe| {
                std::process::Command::new(exe)
                    .args(std::env::args_os().skip(1))
                    .status()
            })
            .map_err(|e| format!("the restore did not start: {e}"))
            .and_then(|s| {
                s.success()
                    .then_some(())
                    .ok_or_else(|| "the restore failed".to_string())
            })
    })
}

/// Stops the service, runs `restore`, and starts the service again whether
/// the restore did its work or not; the restore's answer. A service that
/// does not stop runs no restore.
fn stopped_for(
    sys: &dyn nerve_service::System,
    out: &mut dyn Write,
    restore: &dyn Fn() -> Result<(), String>,
) -> Result<(), String> {
    sys.systemctl(&["stop", UNIT_NAME])?;
    did(out, format!("stopped {UNIT_NAME} for the restore"));
    let _ = out.flush();
    let r = restore();
    let started = sys.systemctl(&["start", UNIT_NAME]);
    match started {
        Ok(()) => did(out, format!("started {UNIT_NAME} again")),
        Err(e) => did(
            out,
            format!("{UNIT_NAME} did not start again ({e}): `sudo systemctl start {UNIT_NAME}`"),
        ),
    }
    r
}

/// `nerve-center status`: whether the center runs in `state` and as the
/// service, where its web UI and harnesses reach it, where its owner token
/// is, its machines, and where its log is. Of the installed center where it
/// is installed (crate::config::Args::owner_state_dir).
///
/// `ui` and `mcp` are what this command was given (`--ui`, `--mcp`, their
/// variables): the installed center's come from its settings file, a
/// center a harness starts has no file, so these are all that is known of it.
pub fn status(
    layout: &Layout,
    state: &Path,
    ui: &str,
    mcp: &crate::config::McpMode,
    out: &mut dyn Write,
) -> Result<(), String> {
    let installed = layout.installed() && state == layout.state;
    // Root's file: read as root, before anything else.
    let file = installed
        .then(|| std::fs::read_to_string(layout.settings()).ok())
        .flatten();
    for line in status_lines(layout, state, installed, file.as_deref(), ui, mcp) {
        let _ = writeln!(out, "{line}");
    }
    Ok(())
}

/// The lines of [`status`], with `file` the installed center's settings
/// where they could be read.
fn status_lines(
    layout: &Layout,
    state: &Path,
    installed: bool,
    file: Option<&str>,
    given_ui: &str,
    given_mcp: &crate::config::McpMode,
) -> Vec<String> {
    use crate::config::McpMode;
    let mut lines = vec![run_line(state, crate::attach::runs(state), cfg!(unix))];
    if installed {
        let ask = |verb: &str| {
            std::process::Command::new("systemctl")
                .args([verb, UNIT_NAME])
                .stderr(std::process::Stdio::null())
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .filter(|s| !s.is_empty())
        };
        let state = ask("is-active").unwrap_or_else(|| "unknown".into());
        let boot = match ask("is-enabled").as_deref() {
            Some("enabled") => ", starts with the machine",
            Some(_) => ", does not start with the machine",
            None => "",
        };
        lines.push(format!("service: {state}{boot}"));
    } else {
        lines.push("service: not installed (a harness starts this center)".into());
    }
    // Where it is reached: what the settings file sets, else the defaults;
    // for a center a harness starts (no file) what this command is given.
    let at = |var: &str| file.and_then(|f| setting_in(f, var));
    let web = crate::config::address_url;
    let ui = match installed {
        true => at("NERVE_CENTER_UI").unwrap_or_else(|| "127.0.0.1:7480".into()),
        false => given_ui.to_string(),
    };
    lines.push(match ui.as_str() {
        a if a.eq_ignore_ascii_case("off") => "web UI: off".into(),
        a => format!("web UI: {}", web(a)),
    });
    lines.push(match (installed, at("NERVE_CENTER_MCP").as_deref()) {
        (true, None | Some("http")) => format!("harnesses: {}/mcp", web(crate::config::MCP_HTTP)),
        (true, Some("off")) => "harnesses: none (MCP is off)".into(),
        (true, Some(a)) => format!("harnesses: {}/mcp", web(a)),
        (false, _) => match given_mcp {
            McpMode::Stdio => "harnesses: the one that starts it, over stdio".into(),
            McpMode::Off => "harnesses: none (MCP is off)".into(),
            McpMode::Http(a) => format!("harnesses: {}/mcp", web(a)),
        },
    });
    if !installed {
        lines.push(
            "(the web UI and harnesses are as `--ui` and `--mcp` give them to this command; a running center may have been started with others)"
                .into(),
        );
    }
    if installed && file.is_none() {
        lines.push(format!(
            "(these are the defaults: {} says more to root, `sudo nerve-center status`)",
            layout.settings().display()
        ));
    }
    // The command that finds this center's token from where it is run.
    let installed_dir = match installed {
        true => Some(state),
        false => layout.installed().then_some(layout.state.as_path()),
    };
    lines.push(format!(
        "owner token: in {}; `{}` shows it",
        crate::owner::path(state).display(),
        crate::ui::token_command_of(
            state,
            installed_dir,
            &crate::config::default_state_dir(),
            true
        )
    ));
    lines.push(match read_store(state) {
        Ok(Some(s)) if s.nodes.is_empty() => {
            "machines: none paired yet; the web UI's Overview pairs one".into()
        }
        Ok(Some(s)) => {
            let names: Vec<&str> = s.nodes.values().map(|n| n.name.as_str()).collect();
            format!("machines: {} paired: {}", names.len(), names.join(", "))
        }
        Ok(None) => "machines: none paired yet".into(),
        // Root's `status` names them where the account's cannot.
        Err(_) if crate::owner::not_yours(state) => {
            "machines: `sudo nerve-center status` names them".into()
        }
        Err(e) => format!("machines: not shown ({e})"),
    });
    lines.push(match installed {
        true => format!(
            "log: `journalctl -u {}`",
            UNIT_NAME.trim_end_matches(".service")
        ),
        false => format!("log: {}", state.join("log.jsonl").display()),
    });
    lines
}

/// The first line of `status`: whether a center runs in `state`, as
/// `runs` ([`crate::attach::runs`]) says. Only `unix` has the lock that
/// tells it; elsewhere a folder that exists says it cannot be told.
fn run_line(state: &Path, runs: Option<bool>, unix: bool) -> String {
    match runs {
        Some(true) => format!("center: running, in {}", state.display()),
        Some(false) => format!("center: not running, in {}", state.display()),
        // Root and the center's user may look into its folder, not others:
        // the service line says whether it runs.
        None if crate::owner::not_yours(state) => format!(
            "center: in {}, which only root and its user may read (`sudo nerve-center status` says more)",
            state.display()
        ),
        None if !state.exists() => format!("center: none has run in {} yet", state.display()),
        None if !unix => format!(
            "center: in {}; whether one runs there cannot be told on this system",
            state.display()
        ),
        None => format!("center: not running, in {}", state.display()),
    }
}

/// The center's store for `status`: read as the folder's owner
/// ([`as_owner_of`]), so root parses nothing the center's user could not
/// read, not through a link, and only a plain file, so it never waits on
/// one. `Ok(None)` when no center saved one.
fn read_store(state: &Path) -> Result<Option<crate::store::Store>, String> {
    // No center has run here yet: nothing to read, and nothing to fail on.
    if matches!(state.symlink_metadata(), Err(e) if e.kind() == std::io::ErrorKind::NotFound) {
        return Ok(None);
    }
    let _owner = as_owner_of(state)?;
    let path = state.join(crate::store::FILE);
    let mut open = std::fs::OpenOptions::new();
    open.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = match open.open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err(format!("{} is not a file", path.display()));
    }
    let mut text = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut text).map_err(|e| e.to_string())?;
    crate::store::Store::parse(&text).map(Some)
}

/// Says a step as it is done.
fn did(out: &mut dyn Write, step: impl std::fmt::Display) {
    let _ = writeln!(out, "{step}");
}

/// What `service-files` prints: the unit, which `update` of an earlier
/// program writes so that the new program runs under its own unit
/// ([`update`]).
pub fn service_files_text(layout: &Layout) -> String {
    nerve_service::files_text(&[("unit", Some(layout.unit_text()))])
}

/// Runs `install`, `update` or `uninstall` on this machine. As the node's
/// own, none of them may be run by a command the installed node runs for a
/// center ([`nerve_service::owner_check`]): an agent cannot replace or
/// remove its center either.
/// `given` are the center's settings the owner gave with the command
/// ([`crate::config::settings_given`]): none of them reaches the service,
/// whose settings are in its settings file, so they are refused.
/// `set` are the settings `install` takes ([`crate::config::INSTALL_SETTINGS`])
/// with their values, by variable, which it writes into the settings file.
pub async fn execute(
    cmd: Cmd,
    given: &[String],
    set: &[(&str, String)],
    out: &mut dyn Write,
) -> Result<(), String> {
    let node = PathBuf::from(nerve_service::NODE_CTL_SOCKET);
    execute_on(cmd, given, set, &Layout::system(), &Host, &node, out).await
}

/// [`execute`] on `layout`, with `node` the installed node's control socket.
async fn execute_on(
    cmd: Cmd,
    given: &[String],
    set: &[(&str, String)],
    layout: &Layout,
    sys: &dyn System,
    node: &Path,
    out: &mut dyn Write,
) -> Result<(), String> {
    let what = match &cmd {
        Cmd::Install => "install",
        Cmd::Update { .. } => "update",
        Cmd::Uninstall { .. } => "uninstall",
        // `main` gives these to crate::backup and crate::owner.
        Cmd::Backup { .. }
        | Cmd::Restore { .. }
        | Cmd::OwnerToken { .. }
        | Cmd::Status
        | Cmd::ServiceFiles => {
            return Err(
                "backup, restore, owner-token, status and service-files are not service commands"
                    .into(),
            );
        }
    };
    // `install` takes the settings it writes; nothing else reaches the
    // service, whose settings are in its file.
    let takes = |g: &String| {
        what == "install"
            && crate::config::INSTALL_SETTINGS
                .iter()
                .any(|(flag, var)| g == flag || g == var)
    };
    let refused: Vec<&String> = given.iter().filter(|g| !takes(g)).collect();
    if !refused.is_empty() {
        let names: Vec<&str> = refused.iter().map(|g| g.as_str()).collect();
        let takes = match what {
            "install" => {
                "takes only --name, --public-url and --listen of the center's settings, which it writes into its settings file"
            }
            _ => "takes none of the center's settings",
        };
        return Err(format!(
            "{what} {takes}, not {}: the installed center reads them from {} and keeps its state in {}. Set them in that file",
            names.join(", "),
            layout.settings().display(),
            layout.state.display()
        ));
    }
    // Root first: a caller without it cannot reach the node's control
    // socket either, and would be told about that instead of about sudo.
    // Nothing changes before either check.
    supported(sys, what)?;
    nerve_service::owner_check(&[node.to_path_buf()]).await?;
    match cmd {
        Cmd::Install => {
            let exe = std::env::current_exe().map_err(|e| format!("this program: {e}"))?;
            install_with(layout, sys, &exe, set, out)
        }
        Cmd::Update { from } => update(layout, sys, from.as_deref(), out).await,
        Cmd::Uninstall { purge } => uninstall(layout, sys, purge, out),
        Cmd::Backup { .. }
        | Cmd::Restore { .. }
        | Cmd::OwnerToken { .. }
        | Cmd::Status
        | Cmd::ServiceFiles => {
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
    install_with(layout, sys, exe, &[], out)
}

/// [`install`] with the settings `set` written into the settings file, by
/// variable: in a new one with the rest, or in place of the same ones in
/// the file an earlier install wrote.
pub fn install_with(
    layout: &Layout,
    sys: &dyn System,
    exe: &Path,
    set: &[(&str, String)],
    out: &mut dyn Write,
) -> Result<(), String> {
    supported(sys, "install")?;
    for (var, value) in set {
        check_setting(var, value)?;
    }
    // A settings file an earlier install kept may name an old variable,
    // which the new program refuses to start with: said before anything
    // changes, as `update` does, not after the service fails to answer.
    let kept = std::fs::read_to_string(layout.settings()).unwrap_or_default();
    crate::config::refuse_old_names(|k| setting_in(&kept, k), &layout.settings())
        .map_err(|e| format!("{e}; install changed nothing"))?;
    let mut steps = Steps::new(out);
    let account = nerve_service::system_account(
        sys,
        USER,
        &layout.state,
        USER_MARK,
        "the user",
        "nerve-center install",
        &mut steps,
    )?;
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
    steps.did(format!("{} belongs to {USER}", state.display()));
    settings(layout, sys, set, steps.out)?;
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
    nerve_service::start_unit(
        sys,
        &layout.unit,
        &layout.unit_text(),
        UNIT_NAME,
        USER,
        &|| sys.wait_running(state),
        &mut steps,
    )?;
    let file = std::fs::read_to_string(layout.settings()).unwrap_or_default();
    for line in done_lines(&file, &owner_token, &crate::owner::path(state)) {
        let _ = writeln!(steps.out, "{line}");
    }
    Ok(())
}

/// The three lines `install` ends with: the web UI, the owner token that
/// logs in to it, and where harnesses connect; from the settings `file`.
fn done_lines(file: &str, owner_token: &str, kept: &Path) -> [String; 3] {
    let ui = setting_in(file, "NERVE_CENTER_UI").unwrap_or_else(|| "127.0.0.1:7480".into());
    let mcp = match setting_in(file, "NERVE_CENTER_MCP").as_deref() {
        None | Some("http") => crate::config::MCP_HTTP.to_string(),
        Some(a) => a.to_string(),
    };
    let web = crate::config::address_url;
    // The same `off` cases as `status` shows.
    let ui_line = match ui.eq_ignore_ascii_case("off") {
        true => "off".to_string(),
        false => web(&ui),
    };
    let mcp_line = match mcp.eq_ignore_ascii_case("off") {
        true => "none (MCP is off)".to_string(),
        false => format!(
            "{}/mcp, with a harness token: the web UI's Connect a harness card makes one",
            web(&mcp)
        ),
    };
    [
        format!("Web UI:      {ui_line}"),
        format!(
            "Owner token: {owner_token} (logs in to the web UI; kept in {}, `sudo nerve-center owner-token` shows it again)",
            kept.display()
        ),
        format!("Harnesses:   {mcp_line}"),
    ]
}

/// The value of `var` in a settings file, where it is set (not as a
/// comment).
fn setting_in(file: &str, var: &str) -> Option<String> {
    file.lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix(&format!("{var}="))
                .map(str::to_string)
        })
        .filter(|v| !v.is_empty())
}

/// Refuses a setting `install` would write into the file that is not one:
/// a line break would put another variable there, and systemd reads a
/// backslash (a trailing one joins the next line), quotes and `$` in an
/// `EnvironmentFile=` as more than the characters they are.
fn check_setting(var: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.contains(['\n', '\r', '\0']) {
        return Err(format!("{var}: one line, not empty"));
    }
    if value.contains(['\\', '"', '\'', '$']) {
        return Err(format!(
            "{var} {value:?}: no backslash, quote or $, which systemd reads in its settings file"
        ));
    }
    match var {
        "NERVE_CENTER_LISTEN" if value.parse::<std::net::SocketAddr>().is_err() => Err(format!(
            "--listen {value:?}: an address and a port, like 0.0.0.0:7443"
        )),
        "NERVE_CENTER_PUBLIC_URL"
            if !(value.starts_with("https://") || value.starts_with("http://")) =>
        {
            Err(format!(
                "--public-url {value:?}: the URL nodes reach the center at, like https://center.example:7443"
            ))
        }
        _ => Ok(()),
    }
}

/// `text` with `set` in place: the lines of those variables, set or as
/// comments, give way to their new values, and one not there is added.
fn with_settings(text: &str, set: &[(&str, String)]) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut done = Vec::new();
    for line in text.lines() {
        let bare = line.trim_start().trim_start_matches('#');
        match set.iter().find(|(v, _)| bare.starts_with(&format!("{v}="))) {
            Some((var, value)) if !done.contains(var) => {
                out.push(format!("{var}={value}"));
                done.push(*var);
            }
            Some(_) => {}
            None => out.push(line.to_string()),
        }
    }
    for (var, value) in set.iter().filter(|(v, _)| !done.contains(v)) {
        out.push(format!("{var}={value}"));
    }
    out.join("\n") + "\n"
}

/// The settings folder, root's and private, and the settings file in it:
/// made with a new harness token when there is none, else kept as the
/// owner left it.
fn settings(
    layout: &Layout,
    sys: &dyn System,
    set: &[(&str, String)],
    out: &mut dyn Write,
) -> Result<(), String> {
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
        if set.is_empty() {
            did(out, format!("kept the settings in {}", file.display()));
            return Ok(());
        }
        let text =
            std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
        write_file(&file, with_settings(&text, set).as_bytes(), 0o600)?;
        let names: Vec<&str> = set.iter().map(|(v, _)| *v).collect();
        did(
            out,
            format!("set {} in {}", names.join(", "), file.display()),
        );
        return Ok(());
    }
    let token = format!("nrv_{}", nerve_transport::keys::random_token(40));
    write_file(&file, Layout::settings_text(&token, set).as_bytes(), 0o600)?;
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
/// `SHA256SUMS`, or a file the owner gives) replaces the installed one, its
/// unit is written as the new program has it, and the service restarts
/// ([`nerve_service::update`], the node's too). The state folder and the
/// settings are not touched. A program that does not run here, or is older
/// than the installed one, is refused; one that does not start is replaced
/// by the old one again, its unit too. The steps go to the center's log.
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
    // The new program does not start while the settings file names an old
    // variable: said before anything changes.
    let file = std::fs::read_to_string(layout.settings()).unwrap_or_default();
    crate::config::refuse_old_names(|k| setting_in(&file, k), &layout.settings())
        .map_err(|e| format!("{e}; update changed nothing"))?;
    let p = nerve_service::Program {
        name: "nerve-center",
        bin: &layout.bin,
        release: &layout.release,
        asset: asset_name(),
        user: USER,
        mark: USER_MARK,
        unit: UNIT_NAME,
        install: "sudo nerve-center install",
        files_args: Vec::new(),
        places: vec![nerve_service::Place {
            role: "unit",
            path: layout.unit.clone(),
            mode: 0o644,
        }],
    };
    let mut steps = Steps::new(out);
    let started = || sys.wait_running(&layout.state);
    let r = nerve_service::update(&p, sys, from, &started, &mut steps).await;
    log_update(layout, &steps.done, &r, steps.out);
    if r? {
        // A center installed before the owner token got one at this start,
        // and its web UI no longer takes the harness token.
        let _ = writeln!(
            out,
            "The web UI logs in with the owner token kept in {} (`sudo cat` it).",
            crate::owner::path(&layout.state).display()
        );
    }
    Ok(())
}

/// Writes what `update` did to the center's log, as the state folder's
/// owner ([`as_owner_of`]): root does not write through a link the center's
/// user put there.
fn log_update(layout: &Layout, steps: &[String], r: &Result<bool, String>, out: &mut dyn Write) {
    if !layout.state.is_dir() {
        return;
    }
    let (level, what) = match r {
        Ok(_) => (Level::Info, format!("update: {}", steps.join("; "))),
        Err(e) => (
            Level::Warn,
            format!("update failed ({e}): {}", steps.join("; ")),
        ),
    };
    // One line appended, nothing read: the log file is the center's
    // account's, and root must not load or wait on what it put there.
    let written = as_owner_of(&layout.state).and_then(|_owner| {
        nerve_transport::log::Log::append_entry(
            &nerve_transport::log::file_in(&layout.state),
            level,
            &what,
        )
        .map_err(|e| e.to_string())
    });
    if let Err(e) = written {
        let _ = writeln!(out, "the center's log cannot be written: {e}");
    }
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
    use crate::config::McpMode;

    /// The machine of the node's service tests too
    /// ([`nerve_service::fake::Fake`]), with the center's user.
    struct Fake(nerve_service::fake::Fake);

    impl std::ops::Deref for Fake {
        type Target = nerve_service::fake::Fake;
        fn deref(&self) -> &nerve_service::fake::Fake {
            &self.0
        }
    }

    impl Fake {
        fn new() -> Fake {
            Fake(nerve_service::fake::Fake::new(
                USER,
                USER_MARK,
                "/var/lib/nerve-center",
            ))
        }
    }

    fn me() -> Account {
        Fake::new().me()
    }

    impl nerve_service::System for Fake {
        fn is_root(&self) -> bool {
            self.0.is_root()
        }
        fn has_systemd(&self) -> bool {
            self.0.has_systemd()
        }
        fn account(&self, name: &str) -> Result<Option<Account>, String> {
            assert_eq!(name, USER);
            self.0.account(name)
        }
        fn add_account(&self, name: &str, home: &Path, mark: &str) -> Result<(), String> {
            self.0.add_account(name, home, mark)
        }
        fn remove_account(&self, name: &str) -> Result<(), String> {
            self.0.remove_account(name)
        }
        fn systemctl(&self, args: &[&str]) -> Result<(), String> {
            self.0.systemctl(args)
        }
        fn give(&self, path: &Path, uid: u32, gid: u32) -> Result<(), String> {
            self.0.give(path, uid, gid)
        }
        fn output_of(
            &self,
            program: &Path,
            account: Option<&Account>,
            args: &[&str],
        ) -> Result<String, String> {
            self.0.output_of(program, account, args)
        }
    }

    impl System for Fake {
        fn wait_running(&self, _state: &Path) -> Result<(), String> {
            self.started()
                .map_err(|_| "the center does not answer".to_string())
        }
    }

    /// A machine where the caller is not root.
    struct NotRoot;
    impl nerve_service::System for NotRoot {
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
        fn output_of(&self, _: &Path, _: Option<&Account>, _: &[&str]) -> Result<String, String> {
            unreachable!()
        }
    }
    impl System for NotRoot {
        fn wait_running(&self, _: &Path) -> Result<(), String> {
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
            .find_map(|l| l.strip_prefix("NERVE_CENTER_HARNESS_TOKEN="))
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
        assert!(
            out.contains("Harnesses:   http://127.0.0.1:7481/mcp"),
            "{out}"
        );
        // The owner token is made before the service starts, kept private in
        // the state folder, and said with where it is.
        let owner = crate::owner::read(&l.state)
            .unwrap()
            .expect("an owner token");
        assert!(owner.starts_with(crate::owner::PREFIX), "{owner}");
        let owner_file = crate::owner::path(&l.state);
        assert_eq!(mode(&owner_file), 0o600);
        assert!(out.contains(&format!("\nOwner token: {owner} (")), "{out}");
        assert!(out.contains(&owner_file.display().to_string()), "{out}");
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
        let env = unit.find("Environment=NERVE_CENTER_MCP=http\n").unwrap();
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
            // Netlink is how the kernel names the account of a loopback
            // peer; without it every connection reads the TCP tables.
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
            // A harness's waiting requests each hold a file.
            "LimitNOFILE=65536",
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
            out.contains("the user nerve-center, is there already"),
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
        let text = Layout::settings_text("nrv_abc", &[]);
        let vars: Vec<(&str, &str)> = text
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .map(|l| l.split_once('=').unwrap())
            .collect();
        assert_eq!(vars, [("NERVE_CENTER_HARNESS_TOKEN", "nrv_abc")]);
        // What install was given is set, the rest stays a comment.
        let set = [("NERVE_CENTER_NAME", "lab".to_string())];
        let text = Layout::settings_text("nrv_abc", &set);
        assert!(text.contains("\nNERVE_CENTER_NAME=lab\n"), "{text}");
        assert!(
            text.contains("\n#NERVE_CENTER_LISTEN=0.0.0.0:7443\n"),
            "{text}"
        );
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

    /// The socket the center asks whether a node's command runs it is the
    /// socket the installed node listens on: if the node's state folder or
    /// socket moved and this did not, the question would go to nobody and
    /// every command would pass.
    #[test]
    fn the_node_s_socket_is_where_the_node_listens() {
        assert_eq!(
            PathBuf::from(nerve_service::NODE_CTL_SOCKET),
            nerve_node::service::Layout::system().paths.ctl_socket()
        );
    }

    /// A caller without root is told so first, also where an installed
    /// node's control socket, which it may not open, is there to ask.
    #[tokio::test]
    async fn without_root_the_commands_say_so_before_they_ask_the_node() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let node = d.path().join("state/run/ctl.sock");
        let run = node.parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&run).unwrap();
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o000)).unwrap();
        let l = layout(d.path());
        let mut results = Vec::new();
        for (what, cmd) in [
            ("install", Cmd::Install),
            ("update", Cmd::Update { from: None }),
            ("uninstall", Cmd::Uninstall { purge: false }),
        ] {
            let r = execute_on(cmd, &[], &[], &l, &NotRoot, &node, &mut Vec::new()).await;
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
        let node = d.path().join("node/run/ctl.sock");
        let given = ["--public-url".to_string(), "--state-dir".to_string()];
        let e = execute_on(Cmd::Install, &given, &[], &l, &sys, &node, &mut Vec::new())
            .await
            .unwrap_err();
        // `install` takes --public-url, which it writes; not --state-dir.
        assert!(
            e.starts_with(
                "install takes only --name, --public-url and --listen of the center's settings, which it writes into its settings file, not --state-dir"
            ),
            "{e}"
        );
        assert!(e.contains(&l.settings().display().to_string()), "{e}");
        assert!(sys.calls().is_empty() && !l.state.exists() && !l.unit.exists());
        // NotRoot answers nothing but that it is not root: the refusal
        // comes first.
        let e = execute_on(
            Cmd::Uninstall { purge: true },
            &["NERVE_CENTER_LISTEN".to_string()],
            &[],
            &l,
            &NotRoot,
            &node,
            &mut Vec::new(),
        )
        .await
        .unwrap_err();
        assert!(e.starts_with("uninstall takes none"), "{e}");
    }

    /// `install --name --public-url --listen` writes them into the settings
    /// file: a new one, or in place of the same ones in the file it keeps;
    /// a value that would put another line there is refused. It ends with
    /// the web UI, the owner token and where harnesses connect.
    #[test]
    fn install_writes_the_settings_it_is_given() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = layout(d.path());
        let exe = d.path().join("nerve-center-x86_64-linux");
        std::fs::write(&exe, "nerve-center 1.0.0\n").unwrap();
        let set = [
            ("NERVE_CENTER_NAME", "lab".to_string()),
            (
                "NERVE_CENTER_PUBLIC_URL",
                "https://lab.example:7443".to_string(),
            ),
        ];
        let mut out = Vec::new();
        install_with(&l, &sys, &exe, &set, &mut out).unwrap();
        let file = std::fs::read_to_string(l.settings()).unwrap();
        assert_eq!(
            setting_in(&file, "NERVE_CENTER_NAME").as_deref(),
            Some("lab")
        );
        assert_eq!(
            setting_in(&file, "NERVE_CENTER_PUBLIC_URL").as_deref(),
            Some("https://lab.example:7443")
        );
        let out = String::from_utf8(out).unwrap();
        let token = crate::owner::read(&l.state).unwrap().unwrap();
        assert!(
            out.contains("Web UI:      http://127.0.0.1:7480\n"),
            "{out}"
        );
        assert!(out.contains(&format!("Owner token: {token} (")), "{out}");
        assert!(
            out.contains("Harnesses:   http://127.0.0.1:7481/mcp, with a harness token"),
            "{out}"
        );
        // Again: the file is kept, its token too, and the one setting changes.
        let before = setting_in(&file, "NERVE_CENTER_HARNESS_TOKEN");
        let set = [
            ("NERVE_CENTER_NAME", "lab-2".to_string()),
            ("NERVE_CENTER_LISTEN", "0.0.0.0:9443".to_string()),
        ];
        install_with(&l, &sys, &exe, &set, &mut Vec::new()).unwrap();
        let file = std::fs::read_to_string(l.settings()).unwrap();
        assert_eq!(
            setting_in(&file, "NERVE_CENTER_NAME").as_deref(),
            Some("lab-2")
        );
        assert_eq!(
            setting_in(&file, "NERVE_CENTER_LISTEN").as_deref(),
            Some("0.0.0.0:9443")
        );
        assert_eq!(file.matches("NERVE_CENTER_NAME=").count(), 1, "{file}");
        assert_eq!(setting_in(&file, "NERVE_CENTER_HARNESS_TOKEN"), before);
        for (var, bad) in [
            ("NERVE_CENTER_NAME", "a\nNERVE_CENTER_UI=0.0.0.0:80"),
            ("NERVE_CENTER_LISTEN", "nowhere"),
            ("NERVE_CENTER_PUBLIC_URL", "lab.example"),
            // systemd joins a line that ends in a backslash with the next,
            // and reads quotes (round 1, correctness 8).
            ("NERVE_CENTER_NAME", "lab\\"),
            ("NERVE_CENTER_NAME", "\"lab\""),
            ("NERVE_CENTER_PUBLIC_URL", "https://lab.example/$x"),
        ] {
            let e = install_with(&l, &sys, &exe, &[(var, bad.to_string())], &mut Vec::new())
                .unwrap_err();
            assert!(!e.is_empty(), "{var}");
        }
        let file = std::fs::read_to_string(l.settings()).unwrap();
        assert!(!file.contains("0.0.0.0:80"));
        assert_eq!(
            setting_in(&file, "NERVE_CENTER_NAME").as_deref(),
            Some("lab-2")
        );
        // A kept settings file with an old name is refused before anything
        // changes, as `update` refuses it (round 1, correctness 9).
        std::fs::write(l.settings(), format!("{file}NERVE_HARNESS_TOKEN=nrv_x\n")).unwrap();
        let mut out = Vec::new();
        let e = install_with(&l, &sys, &exe, &[], &mut out).unwrap_err();
        assert!(
            e.starts_with("rename NERVE_HARNESS_TOKEN to NERVE_CENTER_HARNESS_TOKEN in"),
            "{e}"
        );
        assert!(e.ends_with("; install changed nothing"), "{e}");
        assert!(out.is_empty(), "{}", String::from_utf8_lossy(&out));
    }

    /// `update` changes nothing while the settings file names an old
    /// variable, which the new program would not start with.
    #[tokio::test]
    async fn update_refuses_a_settings_file_with_an_old_name() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        std::fs::write(l.settings(), "NERVE_HARNESS_TOKEN=nrv_x\n").unwrap();
        let e = update(&l, &sys, None, &mut Vec::new()).await.unwrap_err();
        assert!(
            e.starts_with("rename NERVE_HARNESS_TOKEN to NERVE_CENTER_HARNESS_TOKEN in"),
            "{e}"
        );
        assert!(e.ends_with("update changed nothing"), "{e}");
    }

    /// `status` by another account than the center's: its folder says
    /// nothing to it, which the status says instead of "not running".
    #[cfg(unix)]
    #[test]
    fn the_status_of_another_accounts_center_names_sudo() {
        use std::os::unix::fs::PermissionsExt;
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let l = layout(d.path());
        let state = d.path().join("own");
        std::fs::create_dir_all(&state).unwrap();
        crate::store::Store::new("c1".into(), "lab".into())
            .save(&state)
            .unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o000)).unwrap();
        let lines = status_lines(&l, &state, true, None, "127.0.0.1:7480", &McpMode::Stdio);
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            lines[0].contains("only root and its user may read"),
            "{lines:?}"
        );
        assert!(lines[0].contains("`sudo nerve-center status`"), "{lines:?}");
    }

    /// A restore into the running service stops it, restores once and
    /// starts it again, also when the restore fails (a wrong passphrase),
    /// and gives the restore's answer (round 1, spec 3).
    #[test]
    fn a_restore_into_the_service_starts_it_again_whatever_happens() {
        for answer in [Ok(()), Err("the restore failed".to_string())] {
            let sys = Fake::new();
            let runs = std::cell::Cell::new(0);
            let mut out = Vec::new();
            let r = stopped_for(&sys, &mut out, &|| {
                runs.set(runs.get() + 1);
                answer.clone()
            });
            assert_eq!(r, answer);
            assert_eq!(runs.get(), 1);
            assert_eq!(
                sys.calls(),
                [
                    format!("systemctl stop {UNIT_NAME}"),
                    format!("systemctl start {UNIT_NAME}")
                ]
            );
            let out = String::from_utf8(out).unwrap();
            assert!(
                out.ends_with(&format!("started {UNIT_NAME} again\n")),
                "{out}"
            );
        }
    }

    /// Where no lock tells whether a center runs (Windows), `status` does
    /// not say a running one does not run (round 1, correctness 7).
    #[test]
    fn the_status_says_when_it_cannot_tell_whether_a_center_runs() {
        let d = tempfile::tempdir().unwrap();
        let line = run_line(d.path(), None, false);
        assert!(line.contains("cannot be told"), "{line}");
        assert!(!line.contains("not running"), "{line}");
        let gone = d.path().join("none");
        assert!(run_line(&gone, None, false).contains("none has run"));
    }

    /// Root's `status` does not wait on a FIFO the center's user put in
    /// place of its store (round 1, correctness 6).
    #[cfg(unix)]
    #[test]
    fn the_status_does_not_wait_on_a_fifo_store() {
        let d = tempfile::tempdir().unwrap();
        let l = layout(d.path());
        let state = d.path().join("own");
        std::fs::create_dir_all(&state).unwrap();
        let fifo =
            std::ffi::CString::new(state.join(crate::store::FILE).to_str().unwrap()).unwrap();
        // SAFETY: a plain call with a valid path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            tx.send(status_lines(
                &l,
                &state,
                false,
                None,
                "127.0.0.1:7480",
                &McpMode::Stdio,
            ))
            .unwrap()
        });
        let lines = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("status waited on a FIFO");
        assert!(
            lines.iter().any(|l| l.starts_with("machines: ")),
            "{lines:?}"
        );
    }

    #[test]
    fn install_ends_with_off_for_a_web_ui_and_mcp_that_are_off() {
        let lines = done_lines(
            "NERVE_CENTER_UI=off\nNERVE_CENTER_MCP=off\n",
            "tok",
            Path::new("/k"),
        );
        assert_eq!(lines[0], "Web UI:      off");
        assert_eq!(lines[2], "Harnesses:   none (MCP is off)");
        let on = done_lines("", "tok", Path::new("/k"));
        assert!(on[0].contains("127.0.0.1:7480") && on[2].contains("/mcp"));
    }

    /// `status` of a center that is not installed: where it runs, how
    /// harnesses reach it, the owner token, the machines and the log.
    #[test]
    fn the_status_says_where_the_center_is() {
        let d = tempfile::tempdir().unwrap();
        let l = layout(d.path());
        let state = d.path().join("own");
        let lines = status_lines(&l, &state, false, None, "127.0.0.1:7480", &McpMode::Stdio);
        assert_eq!(
            lines[0],
            format!("center: none has run in {} yet", state.display())
        );
        // The first thing a new person sees: no folder, no machines, and
        // no command to run for them (round 2).
        assert_eq!(lines[lines.len() - 2], "machines: none paired yet");
        std::fs::create_dir_all(&state).unwrap();
        let mut store = crate::store::Store::new("c1".into(), "lab".into());
        store.nodes.insert(
            "n1".into(),
            serde_json::from_value(serde_json::json!({
                "id": "n1", "name": "web-1", "public_key": "k",
                "platform": "linux", "arch": "x86_64", "paired_ms": 1
            }))
            .unwrap(),
        );
        store.save(&state).unwrap();
        let lines =
            status_lines(&l, &state, false, None, "127.0.0.1:7480", &McpMode::Stdio).join("\n");
        for want in [
            "service: not installed (a harness starts this center)",
            "web UI: http://127.0.0.1:7480",
            "harnesses: the one that starts it, over stdio",
            "owner-token --state-dir ",
            "machines: 1 paired: web-1",
            "log: ",
        ] {
            assert!(lines.contains(want), "{want}: {lines}");
        }
        // What this command is given is all that is known of a center a
        // harness starts, and its token is found with its folder (round 4,
        // correctness 2).
        let lines = status_lines(
            &l,
            &state,
            false,
            None,
            "127.0.0.1:7490",
            &McpMode::Http("127.0.0.1:7491".into()),
        )
        .join("\n");
        for want in [
            "web UI: http://127.0.0.1:7490",
            "harnesses: http://127.0.0.1:7491/mcp",
            &format!(
                "`nerve-center owner-token --state-dir {}` shows it",
                state.display()
            ),
        ] {
            assert!(lines.contains(want), "{want}: {lines}");
        }
        assert!(!lines.contains("7480"), "{lines}");
        let lines = status_lines(&l, &state, false, None, "off", &McpMode::Off).join("\n");
        assert!(lines.contains("web UI: off"), "{lines}");
        assert!(lines.contains("harnesses: none (MCP is off)"), "{lines}");
        // The installed center: its service, its HTTP MCP and journalctl.
        let file = "NERVE_CENTER_UI=0.0.0.0:7480\nNERVE_CENTER_MCP=0.0.0.0:7481\n";
        let lines = status_lines(
            &l,
            &state,
            true,
            Some(file),
            "127.0.0.1:7480",
            &McpMode::Stdio,
        )
        .join("\n");
        // An address on all of them is reached by the machine's name.
        let host = crate::center::host_name();
        assert!(
            lines.contains(&format!("web UI: https://{host}:7480")),
            "{lines}"
        );
        assert!(
            lines.contains(&format!("harnesses: https://{host}:7481/mcp")),
            "{lines}"
        );
        assert!(
            lines.contains("`sudo nerve-center owner-token` shows it"),
            "{lines}"
        );
        assert!(
            lines.contains("log: `journalctl -u nerve-center`"),
            "{lines}"
        );
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
        assert!(
            out.contains(&format!("owner token kept in {token}")),
            "{out}"
        );
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

    /// `update` writes the unit as the new program has it, and the old one
    /// back with the old program when the new one does not start; the
    /// steps go to the center's log.
    #[tokio::test]
    async fn update_brings_the_unit_up_to_date() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        let unit = std::fs::read_to_string(&l.unit).unwrap();
        let new_unit = unit.replace("[Service]\n", "[Service]\nNice=5\n");
        assert_ne!(new_unit, unit);
        let new = d.path().join("new");
        let files = nerve_service::files_text(&[("unit", Some(new_unit.clone()))]);
        std::fs::write(&new, format!("nerve-center 1.1.0\n{files}\n")).unwrap();
        sys.next_start.set(Some(false));
        let e = update(&l, &sys, Some(&new), &mut Vec::new())
            .await
            .unwrap_err();
        assert!(e.contains("the old one runs again"), "{e}");
        assert_eq!(std::fs::read_to_string(&l.unit).unwrap(), unit);
        update(&l, &sys, Some(&new), &mut Vec::new()).await.unwrap();
        assert_eq!(std::fs::read_to_string(&l.unit).unwrap(), new_unit);
        assert!(sys.runs.borrow().iter().any(|r| r == "service-files"));
        let log = std::fs::read_to_string(nerve_transport::log::file_in(&l.state)).unwrap();
        assert!(
            log.contains("update failed (the new program did not start"),
            "{log}"
        );
        assert!(
            log.contains("replaced nerve-center 1.0.0 with 1.1.0"),
            "{log}"
        );
        // What the program itself says is the unit `install` writes.
        let said: serde_json::Value = serde_json::from_str(&service_files_text(&l)).unwrap();
        assert_eq!(said, serde_json::json!({"unit": l.unit_text()}));
    }

    /// The entry of `update` is written after the restart, when the running
    /// center has the file open: the second writer must not move a nearly
    /// full file aside under it.
    #[test]
    fn the_update_entry_does_not_move_the_log_under_the_running_center() {
        let d = tempfile::tempdir().unwrap();
        let l = layout(d.path());
        std::fs::create_dir_all(&l.state).unwrap();
        let path = nerve_transport::log::file_in(&l.state);
        let log = nerve_transport::log::Log::new(Level::Info);
        log.attach_file(&path).unwrap();
        let line = "x".repeat(900);
        while std::fs::metadata(&path).unwrap().len() + 1200 < nerve_transport::log::MAX_BYTES {
            log.record(Level::Info, None, &line);
        }
        // Then in small steps, until the update's line no longer fits.
        while std::fs::metadata(&path).unwrap().len() + 300 < nerve_transport::log::MAX_BYTES {
            log.record(Level::Info, None, "y");
        }
        drop(log);
        let mut out = Vec::new();
        log_update(&l, &["a step".repeat(100)], &Ok(true), &mut out);
        assert!(out.is_empty(), "{}", String::from_utf8_lossy(&out));
        let mut old = path.clone().into_os_string();
        old.push(".1");
        assert!(!Path::new(&old).exists(), "the log was moved aside");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("update: a stepa step"));
    }

    #[test]
    fn the_update_entry_does_not_wait_on_a_pipe_in_place_of_the_log() {
        use std::os::unix::ffi::OsStrExt;
        let d = tempfile::tempdir().unwrap();
        let l = layout(d.path());
        std::fs::create_dir_all(&l.state).unwrap();
        let path = nerve_transport::log::file_in(&l.state);
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut out = Vec::new();
            log_update(&l, &["a step".into()], &Ok(true), &mut out);
            let _ = tx.send(out);
        });
        let out = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the update waited on the pipe");
        assert!(
            String::from_utf8_lossy(&out).contains("cannot be written"),
            "{}",
            String::from_utf8_lossy(&out)
        );
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
