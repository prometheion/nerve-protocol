//! The center as a service (docs/dev/service.md, "The center as a service"):
//! `install`, `set`, `update` and `uninstall`, on Linux with systemd, as the
//! node has them (`set` is the center's own): what both do the same way,
//! `update` among it, is [`nerve_service`]'s. On Windows the service control manager runs it
//! ([`crate::winsvc`]). The service runs `nerve-center` with
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

use nerve_service::out::{Page, Style, Tone};
use nerve_service::{Steps, as_owner_of, set_mode, write_file};

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

const LINUX_ONLY: &str = "works on Linux with systemd and on Windows only; elsewhere run `nerve-center --mcp http` under your own service manager";

/// A start that cannot go on: the reason on stderr and, for the Windows
/// service, which has no terminal, in the log in its state folder, where
/// `install` points (a value mistyped in `center.env` would otherwise end
/// the service without a trace).
pub fn refuse_start(state: &Path, is_service: bool, why: &str) {
    eprintln!(
        "{}",
        nerve_service::out::error("nerve-center", why, Style::stderr())
    );
    if is_service {
        let _ = nerve_transport::log::Log::append_entry(
            &nerve_transport::log::file_in(state),
            Level::Error,
            &format!("the service cannot start: {}", why.trim()),
        );
    }
}

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
    /// The places on this machine. On Windows the program goes to
    /// `%ProgramFiles%\Nerve` and the folders to `%ProgramData%\nerve-center`
    /// (not below the node's `%ProgramData%\Nerve`, which its uninstall may
    /// delete); the service is registered with the service control manager,
    /// so there is no unit file ([`crate::winsvc`]). Both folders are the
    /// ones Windows keeps, not what the variables say: an administrator's
    /// elevated terminal takes `ProgramData` from the account's own
    /// variables, which its unelevated programs may set, and the commands
    /// that run there write the center's key into this folder (round 6,
    /// security 1).
    pub fn system() -> Layout {
        #[cfg(windows)]
        {
            use nerve_service::win::folders::{program_data, program_files};
            let data = program_data().join("nerve-center");
            Layout {
                unit: PathBuf::new(),
                bin: program_files().join("Nerve").join("nerve-center.exe"),
                state: data.join("state"),
                settings_dir: data.join("settings"),
                release: concat!(env!("CARGO_PKG_REPOSITORY"), "/releases/latest/download").into(),
            }
        }
        #[cfg(not(windows))]
        {
            Layout {
                unit: PathBuf::from("/etc/systemd/system").join(UNIT_NAME),
                bin: "/usr/local/bin/nerve-center".into(),
                state: "/var/lib/nerve-center".into(),
                settings_dir: "/etc/nerve-center".into(),
                release: concat!(env!("CARGO_PKG_REPOSITORY"), "/releases/latest/download").into(),
            }
        }
    }

    /// The settings file the unit reads.
    pub fn settings(&self) -> PathBuf {
        self.settings_dir.join(SETTINGS_FILE)
    }

    /// Whether this is the Windows service's layout: the service control
    /// manager registers it, so it has no unit file.
    pub fn windows(&self) -> bool {
        self.unit.as_os_str().is_empty()
    }

    /// Whether `state` is this layout's state folder: on Windows by any
    /// spelling of its path (crate::util::same_folder), else as written.
    pub fn is_state(&self, state: &Path) -> bool {
        if self.windows() {
            crate::util::same_folder(state, &self.state)
        } else {
            state == self.state
        }
    }

    /// Whether `install` put the center here: its unit, or on Windows its
    /// service.
    pub fn installed(&self) -> bool {
        #[cfg(windows)]
        {
            nerve_service::win::service::registered(crate::winsvc::SERVICE_NAME)
        }
        #[cfg(not(windows))]
        {
            cfg!(target_os = "linux") && self.unit.is_file()
        }
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
    pub fn settings_text(&self, token: &str, set: &[(&str, String)]) -> String {
        let line = |var: &str, default: &str| match set.iter().find(|(v, _)| *v == var) {
            Some((_, value)) => format!("{var}={value}"),
            None => format!("#{var}={default}"),
        };
        let (set, restart) = match self.windows() {
            true => (
                "`nerve-center set <name> <value>` in an administrator's terminal",
                "`Restart-Service nerve-center` in an administrator's PowerShell".to_string(),
            ),
            false => (
                "`sudo nerve-center set <name> <value>`",
                format!("`sudo systemctl restart {UNIT_NAME}`"),
            ),
        };
        format!(
            "# The settings of the installed center, read by the service at its start.
# {set} changes name, public-url,
# listen, ui or mcp here and restarts the service; after a change by hand,
# {restart}.
# `nerve-center install` wrote this file and keeps it, and takes those five as
# flags. Each variable is a flag of `nerve-center --help`.
#
# The harness token: harnesses send it to the HTTP MCP endpoint. It does not
# log in to the web UI, which asks for the owner token in
# {owner}. More can be made in the web UI.
NERVE_CENTER_HARNESS_TOKEN={token}
{}
{}
{}
{}
{}
#NERVE_CENTER_LOG=info
",
            line("NERVE_CENTER_NAME", "nerve-center"),
            line("NERVE_CENTER_LISTEN", "0.0.0.0:7443"),
            line("NERVE_CENTER_PUBLIC_URL", "https://<host name>:7443"),
            line("NERVE_CENTER_UI", "127.0.0.1:7480"),
            line("NERVE_CENTER_MCP", "127.0.0.1:7481"),
            owner = crate::owner::path(&self.state).display(),
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
pub use nerve_service::Host;

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

/// What the restore's child is told: its parent starts the service again.
const RESTORE_RESTARTS: &str = "NERVE_CENTER_RESTORE_RESTARTS";

/// Runs `f` (a restore) with the installed service stopped, where `state`
/// is its folder and it runs, and starts it again after, whether `f` did
/// its work or not. Elsewhere `f` alone, which refuses a running center.
/// `f` is told whether the service starts again after it, so that its page
/// does not say to start it.
pub fn with_service_stopped(
    layout: &Layout,
    state: &Path,
    out: &mut dyn Write,
    f: &dyn Fn(&mut dyn Write, bool) -> Result<(), String>,
) -> Result<(), String> {
    // An administrator stops and starts the Windows service around the
    // restore, which writes the folder as an administrator: what it writes
    // takes the folder's DACL, so the service reads it.
    #[cfg(windows)]
    {
        use crate::winsvc::WinSystem;
        let sys = crate::win_host::WinHost;
        let ours = layout.is_state(state) && sys.is_admin() && sys.service()? == Some(true);
        if ours {
            return crate::winsvc::stopped_for(&sys, out, &|out| f(out, true));
        }
    }
    let ours = cfg!(target_os = "linux")
        && layout.installed()
        && layout.is_state(state)
        && nerve_transport::net::euid() == 0
        && crate::attach::runs(state) == Some(true);
    if !ours {
        // The child of the branch below finds no center running: its parent
        // starts the service again.
        return f(out, std::env::var_os(RESTORE_RESTARTS).is_some());
    }
    // The restore becomes the folder's owner for its work, for good: it
    // runs in a child, so that this process, root still, starts the service
    // again. The child finds no center running and restores.
    stopped_for(&Host, out, &|| {
        std::env::current_exe()
            .and_then(|exe| {
                std::process::Command::new(exe)
                    .args(std::env::args_os().skip(1))
                    .env(RESTORE_RESTARTS, "1")
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
    let installed = layout.installed() && layout.is_state(state);
    // Root's file: read as root, before anything else.
    let file = installed
        .then(|| std::fs::read_to_string(layout.settings()).ok())
        .flatten();
    let page = status_page(layout, state, installed, file.as_deref(), ui, mcp);
    let _ = out.write_all(page.render(Style::stdout()).as_bytes());
    Ok(())
}

/// The program's name and version on the head line of its pages.
pub const PROGRAM: &str = "Nerve center";

/// A page of the center's ([`nerve_service::out`]).
pub fn page() -> Page {
    page_of(env!("CARGO_PKG_VERSION"))
}

/// A page of the center at `version`: the installed one's, which `update`
/// just changed.
fn page_of(version: &str) -> Page {
    Page::new(PROGRAM, version)
}

/// What the service manager says of the installed service: its state, and
/// whether it starts with the machine where that is known.
struct ServiceState {
    active: bool,
    state: String,
    boot: Option<bool>,
}

/// The installed service's state, from systemd or the service control
/// manager.
fn service_state() -> ServiceState {
    #[cfg(windows)]
    {
        match nerve_service::win::service::state(crate::winsvc::SERVICE_NAME) {
            Ok(Some(st)) => ServiceState {
                active: st.state == "running",
                state: st.state.to_string(),
                boot: st.automatic,
            },
            Ok(None) => ServiceState {
                active: false,
                state: "not installed".into(),
                boot: None,
            },
            Err(e) => ServiceState {
                active: false,
                state: format!("unknown ({e})"),
                boot: None,
            },
        }
    }
    #[cfg(not(windows))]
    {
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
        ServiceState {
            active: state == "active",
            state,
            boot: ask("is-enabled").map(|e| e == "enabled"),
        }
    }
}

/// The page of [`status`], with `file` the installed center's settings
/// where they could be read.
fn status_page(
    layout: &Layout,
    state: &Path,
    installed: bool,
    file: Option<&str>,
    given_ui: &str,
    given_mcp: &crate::config::McpMode,
) -> Page {
    let service = installed.then(service_state);
    status_page_of(
        layout,
        state,
        installed,
        file,
        given_ui,
        given_mcp,
        crate::attach::runs(state),
        service,
    )
}

/// [`status_page`] with `runs` ([`crate::attach::runs`]) and the
/// installed `service`'s state given.
#[allow(clippy::too_many_arguments)]
fn status_page_of(
    layout: &Layout,
    state: &Path,
    installed: bool,
    file: Option<&str>,
    given_ui: &str,
    given_mcp: &crate::config::McpMode,
    runs: Option<bool>,
    service: Option<ServiceState>,
) -> Page {
    use crate::config::McpMode;
    let unreadable = runs.is_none() && crate::owner::not_yours(state);
    let (head, tone) = match (runs, &service) {
        (Some(true), Some(_)) => ("running as a service", Tone::Good),
        (Some(true), None) => ("running", Tone::Good),
        (_, Some(s)) if s.active => ("running as a service", Tone::Good),
        (None, _) if unreadable => ("only an administrator sees it", Tone::Warn),
        (None, None) if !state.exists() => ("not started yet", Tone::Plain),
        (_, Some(_)) => ("stopped", Tone::Bad),
        _ => ("not running", Tone::Plain),
    };
    let mut p = page().state(head, tone);
    match &service {
        // A service that runs says so in the head line.
        Some(s) if s.active => {}
        Some(s) => {
            let boot = match s.boot {
                Some(true) => ", starts with the machine",
                Some(false) => ", not with the machine",
                None => "",
            };
            p.row("Service", format!("{}{boot}", s.state));
        }
        None => {
            p.row("Service", "none, a harness starts it");
        }
    }
    // Where it is reached: what the settings file sets, else the defaults;
    // for a center a harness starts (no file) what this command is given.
    let at = |var: &str| file.and_then(|f| setting_in(f, var));
    let web = crate::config::address_url;
    let ui = match installed {
        true => at("NERVE_CENTER_UI").unwrap_or_else(|| "127.0.0.1:7480".into()),
        false => given_ui.to_string(),
    };
    p.row(
        "Web UI",
        match ui.as_str() {
            a if a.eq_ignore_ascii_case("off") => "off".into(),
            a => web(a),
        },
    );
    p.row(
        "Harnesses",
        match (installed, at("NERVE_CENTER_MCP").as_deref()) {
            (true, None | Some("http")) => format!("{}/mcp", web(crate::config::MCP_HTTP)),
            (true, Some("off")) => "off".into(),
            (true, Some(a)) => format!("{}/mcp", web(a)),
            (false, _) => match given_mcp {
                McpMode::Stdio => "the one that starts it (stdio)".into(),
                McpMode::Off => "off".into(),
                McpMode::Http(a) => format!("{}/mcp", web(a)),
            },
        },
    );
    let mut none_paired = false;
    p.row(
        "Machines",
        match read_store(state) {
            Ok(Some(s)) if s.nodes.is_empty() => {
                none_paired = true;
                "none paired yet".into()
            }
            Ok(Some(s)) => {
                let names: Vec<&str> = s.nodes.values().map(|n| n.name.as_str()).collect();
                format!("{}: {}", names.len(), names.join(", "))
            }
            Ok(None) => {
                none_paired = true;
                "none paired yet".into()
            }
            // Root's `status` names them where the account's cannot.
            Err(_) if unreadable => "only an administrator sees them".into(),
            Err(e) => format!("not shown ({e})"),
        },
    );
    if !installed {
        p.row("Folder", state.display().to_string());
        p.note("The web UI and harnesses are as --ui and --mcp give them to this command.");
    }
    if installed && file.is_none() {
        p.note(format!(
            "These are the defaults: {} has the settings.",
            layout.settings().display()
        ));
    }
    if unreadable {
        p.next("See it all", admin("status"));
    }
    if service.as_ref().is_some_and(|s| !s.active) {
        p.next("Start it", admin("service start"));
    }
    // The commands for this center from where they are run.
    let installed_dir = match installed {
        true => Some(state),
        false => layout.installed().then_some(layout.state.as_path()),
    };
    let command = |what: &str| {
        crate::ui::command_of(
            what,
            state,
            installed_dir,
            &crate::config::default_state_dir(),
            true,
            layout.windows(),
        )
    };
    // A machine is paired with the running center.
    if none_paired && (runs == Some(true) || service.as_ref().is_some_and(|s| s.active)) {
        p.next("Pair a machine", command("pair"));
    }
    p.next("Owner token", command("owner-token"));
    if installed && layout.windows() {
        p.note("Run these commands in an administrator's terminal.");
    }
    p
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
    let mut file = match nerve_transport::files::no_follow(&mut open).open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    if !nerve_transport::files::is_plain(&file).map_err(|e| e.to_string())? {
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

/// Runs `install`, `set`, `update` or `uninstall` on this machine. As the
/// node's own, none of them may be run by a command the installed node runs
/// for a center ([`nerve_service::owner_check`]): an agent cannot replace,
/// reconfigure or remove its center either.
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
    #[cfg(windows)]
    {
        let layout = Layout::system();
        let sys = crate::win_host::WinHost;
        refuse_given(service_command(&cmd)?, given, &layout)?;
        // An administrator first: no other account may ask the node's
        // control pipe. Nothing changes before either check.
        crate::winsvc::supported(&sys, service_command(&cmd)?)?;
        nerve_service::owner_check(&[]).await?;
        let exe = std::env::current_exe().map_err(|e| format!("this program: {e}"))?;
        crate::winsvc::execute(cmd, set, &layout, &sys, &exe, out).await
    }
    #[cfg(not(windows))]
    {
        let node = PathBuf::from(nerve_service::NODE_CTL_SOCKET);
        execute_on(cmd, given, set, &Layout::system(), &Host, &node, out).await
    }
}

/// The name of a service command; the others are refused.
fn service_command(cmd: &Cmd) -> Result<&'static str, String> {
    Ok(match cmd {
        Cmd::Install => "install",
        Cmd::Set { .. } => "set",
        Cmd::Update { .. } => "update",
        Cmd::Uninstall { .. } => "uninstall",
        Cmd::Service { cmd: Some(c) } => c.typed(),
        // `main` gives these to crate::backup, crate::owner and
        // crate::owner_calls.
        Cmd::Backup { .. }
        | Cmd::Restore { .. }
        | Cmd::OwnerToken { .. }
        | Cmd::Status
        | Cmd::Service { cmd: None }
        | Cmd::Pair
        | Cmd::Nodes { .. }
        | Cmd::Token(_)
        | Cmd::Log { .. }
        | Cmd::ServiceFiles => {
            return Err(
                "backup, restore, owner-token, status, pair, nodes, token, log and service-files are not service commands"
                    .into(),
            );
        }
    })
}

/// Refuses the center's settings `given` with the service command `what`
/// but those `install` takes: none of them reaches the service, whose
/// settings are in its file.
fn refuse_given(what: &str, given: &[String], layout: &Layout) -> Result<(), String> {
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
        // `set` takes its setting by name; a variable of this terminal
        // would reach nothing either.
        if what == "set" {
            let clear = match refused.iter().any(|g| !g.starts_with("--")) {
                true => "; clear the variable in this terminal",
                false => "",
            };
            return Err(format!(
                "set takes a setting by its name, as {}, not {}{clear}",
                set_command(layout, "ui 0.0.0.0:7480"),
                names.join(", "),
            ));
        }
        let takes = match what {
            "install" => {
                "takes only --name, --public-url, --listen, --ui and --mcp of the center's settings, which it writes into its settings file"
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
    Ok(())
}

/// [`execute`] on `layout`, with `node` the installed node's control socket.
#[cfg_attr(windows, allow(dead_code))]
async fn execute_on(
    cmd: Cmd,
    given: &[String],
    set: &[(&str, String)],
    layout: &Layout,
    sys: &dyn System,
    node: &Path,
    out: &mut dyn Write,
) -> Result<(), String> {
    let what = service_command(&cmd)?;
    refuse_given(what, given, layout)?;
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
        // `set` here names the settings `install` writes.
        Cmd::Set { setting, value } => {
            self::set(layout, sys, setting.as_deref(), value.as_deref(), out)
        }
        Cmd::Update { from, pre, tag } => {
            let layout = with_release(layout, pre, tag).await?;
            update(&layout, sys, from.as_deref(), out).await
        }
        Cmd::Uninstall { purge } => uninstall(layout, sys, purge, out),
        Cmd::Service { cmd: Some(c) } => service(layout, sys, c, out),
        Cmd::Backup { .. }
        | Cmd::Restore { .. }
        | Cmd::OwnerToken { .. }
        | Cmd::Status
        | Cmd::Service { cmd: None }
        | Cmd::Pair
        | Cmd::Nodes { .. }
        | Cmd::Token(_)
        | Cmd::Log { .. }
        | Cmd::ServiceFiles => {
            unreachable!("refused above")
        }
    }
}

/// `layout` with the release `update` takes in place of the latest:
/// with `pre` the newest one, a pre-release too; with `tag` that one
/// ([`nerve_service::Release`]).
pub(crate) async fn with_release(
    layout: &Layout,
    pre: bool,
    tag: Option<String>,
) -> Result<Layout, String> {
    let mut l = layout.clone();
    l.release = nerve_service::Release::of(pre, tag)
        .base(&layout.release)
        .await?;
    Ok(l)
}

/// `service start|stop|restart`: systemd does it, a start waits until the
/// center answers, and the page `status` shows ends it.
pub fn service(
    layout: &Layout,
    sys: &dyn System,
    c: crate::config::ServiceCmd,
    out: &mut dyn Write,
) -> Result<(), String> {
    use crate::config::ServiceCmd;
    supported(sys, c.typed())?;
    if !layout.installed() {
        return Err(NOT_INSTALLED.into());
    }
    let (verb, done) = match c {
        ServiceCmd::Start => ("start", "started the center"),
        ServiceCmd::Stop => ("stop", "stopped the center"),
        ServiceCmd::Restart => ("restart", "restarted the center"),
    };
    sys.systemctl(&[verb, UNIT_NAME])?;
    let runs = c != ServiceCmd::Stop;
    if runs {
        sys.wait_running(&layout.state)?;
    }
    did(out, done);
    let file = std::fs::read_to_string(layout.settings()).unwrap_or_default();
    let page = service_page(layout, &file, runs);
    let _ = write!(out, "\n{}", page.render(Style::stdout()));
    Ok(())
}

/// The page `service` ends with: the installed center as `status` shows
/// it, running or stopped (`runs`), from the settings `file`.
pub(crate) fn service_page(layout: &Layout, file: &str, runs: bool) -> Page {
    status_page_of(
        layout,
        &layout.state,
        true,
        Some(file),
        "",
        &crate::config::McpMode::Off,
        Some(runs),
        Some(ServiceState {
            active: runs,
            state: match runs {
                true => "running".into(),
                false => "stopped".into(),
            },
            boot: None,
        }),
    )
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
    let page = done_page(layout, &file, Some(&owner_token), None, true);
    let _ = write!(steps.out, "\n{}", page.render(Style::stdout()));
    Ok(())
}

/// The page `install` and `update` end with: the center as `status` shows
/// it, with the owner token that logs in to the web UI (`owner_token`)
/// once; from the settings `file`. `version` is the installed program's
/// where it is known, after an update. `started`: the command started the
/// service and saw the center answer; an update that found nothing to do
/// started nothing, and says whether the center runs.
pub(crate) fn done_page(
    layout: &Layout,
    file: &str,
    owner_token: Option<&str>,
    version: Option<&str>,
    started: bool,
) -> Page {
    let runs = match started {
        true => Some(true),
        false => crate::attach::runs(&layout.state),
    };
    let active = runs == Some(true);
    let mut p = status_page_of(
        layout,
        &layout.state,
        true,
        Some(file),
        "",
        &crate::config::McpMode::Off,
        runs,
        Some(ServiceState {
            active,
            state: match active {
                true => "running".into(),
                false => "stopped".into(),
            },
            boot: started.then_some(true),
        }),
    );
    if let Some(v) = version {
        p.set_version(v);
    }
    if let Some(token) = owner_token {
        p.row("Owner token", token);
    }
    p
}

/// The web UI's address the settings `file` give the service.
fn ui_address(file: &str) -> String {
    setting_in(file, "NERVE_CENTER_UI").unwrap_or_else(|| "127.0.0.1:7480".into())
}

/// The HTTP MCP address the settings `file` give the service, which runs
/// with `http` where they set none; `off` where it is off.
fn mcp_address(file: &str) -> String {
    match setting_in(file, "NERVE_CENTER_MCP").as_deref() {
        None | Some("http") => crate::config::MCP_HTTP.to_string(),
        Some(a) => a.to_string(),
    }
}

/// The web UI's value on a page, with the same `off` as `status` shows.
fn ui_value(file: &str) -> String {
    match ui_address(file) {
        a if a.eq_ignore_ascii_case("off") => "off".into(),
        a => crate::config::address_url(&a),
    }
}

/// The harnesses' value on a page.
fn mcp_value(file: &str) -> String {
    match mcp_address(file) {
        a if a.eq_ignore_ascii_case("off") => "off".into(),
        a => format!("{}/mcp", crate::config::address_url(&a)),
    }
}

/// `nerve-center <what>` as an administrator types it, for `Next`: with
/// `sudo` on Linux; on Windows in an administrator's terminal, which the
/// page says once.
pub fn admin(what: &str) -> String {
    match cfg!(windows) {
        true => format!("nerve-center {what}"),
        false => format!("sudo nerve-center {what}"),
    }
}

/// `nerve-center <what>` as an administrator runs it: with `sudo` on
/// Linux, in an administrator's terminal on Windows.
pub fn admin_command(what: &str) -> String {
    match cfg!(windows) {
        true => format!("`nerve-center {what}` in an administrator's terminal"),
        false => format!("`sudo nerve-center {what}`"),
    }
}

/// The value of `var` in a settings file, where it is set (not as a
/// comment).
pub(crate) fn setting_in(file: &str, var: &str) -> Option<String> {
    file.lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix(&format!("{var}="))
                .map(str::to_string)
        })
        .filter(|v| !v.is_empty())
}

/// Refuses a setting `install` or `set` would write into the file that is
/// not one: a line break would put another variable there, and systemd
/// reads a backslash (a trailing one joins the next line), quotes and `$` in
/// an `EnvironmentFile=` as more than the characters they are. An address
/// without its port, as `0.0.0.0`, is refused with one that has it: the
/// center would not start on it.
pub(crate) fn check_setting(var: &str, value: &str) -> Result<(), String> {
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
            "listen {value:?}: an address and a port, like 0.0.0.0:7443"
        )),
        "NERVE_CENTER_PUBLIC_URL"
            if !(value.starts_with("https://") || value.starts_with("http://")) =>
        {
            Err(format!(
                "public-url {value:?}: the URL nodes reach the center at, like https://center.example:7443"
            ))
        }
        "NERVE_CENTER_UI" if !(value.eq_ignore_ascii_case("off") || has_port(value)) => {
            Err(format!(
                "ui {value:?}: an address and a port, like 0.0.0.0:7480 (every address) or 127.0.0.1:7480, or off"
            ))
        }
        // The service has no stdin, so `stdio` is no mode of it.
        "NERVE_CENTER_MCP" if !matches!(value, "http" | "off") && !has_port(value) => Err(format!(
            "mcp {value:?}: http ({}), off, or an address and a port, like 0.0.0.0:7481",
            crate::config::MCP_HTTP
        )),
        _ => Ok(()),
    }
}

/// Whether `a` is an address and a port the center can listen on, as
/// `--ui` and `--mcp` take them: `0.0.0.0:7480`, `[::1]:7480` or
/// `localhost:7480`.
fn has_port(a: &str) -> bool {
    a.parse::<std::net::SocketAddr>().is_ok()
        || a.strip_prefix("localhost:")
            .is_some_and(|p| p.parse::<u16>().is_ok())
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

/// The settings folder, root's and private, and the settings file in it
/// ([`settings_file`]).
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
    settings_file(layout, set, out)
}

/// The settings file in the settings folder, which is private already:
/// made with a new harness token when there is none, else kept as the
/// owner left it, with `set` in place.
pub(crate) fn settings_file(
    layout: &Layout,
    set: &[(&str, String)],
    out: &mut dyn Write,
) -> Result<(), String> {
    let file = layout.settings();
    if std::fs::symlink_metadata(&file).is_ok() {
        if set.is_empty() {
            did(out, format!("kept the settings in {}", file.display()));
            return Ok(());
        }
        let text =
            std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
        write_file(&file, with_settings(&text, set).as_bytes(), 0o600)?;
        let lines: Vec<String> = set
            .iter()
            .map(|(v, value)| format!("{v}={value}"))
            .collect();
        did(
            out,
            format!("set {} in {}", lines.join(", "), file.display()),
        );
        return Ok(());
    }
    let token = format!("nrv_{}", nerve_transport::keys::random_token(40));
    write_file(&file, layout.settings_text(&token, set).as_bytes(), 0o600)?;
    did(
        out,
        format!(
            "wrote the settings to {}, with a new harness token",
            file.display()
        ),
    );
    Ok(())
}

/// Why `set` and `update` do nothing here.
const NOT_INSTALLED: &str =
    "the center is not installed as a service here; `sudo nerve-center install` installs it";

/// `set`: without a setting, the settings it changes and their values
/// ([`settings_lines`]). With one, its `value` checked and written into the
/// settings file in place of the old line, the other lines kept, and the
/// running service restarted until the center answers, as the owner would
/// edit the file and restart it by hand. A center that runs is one that
/// holds the lock of the service's state folder, as for the restore
/// ([`with_service_stopped`]); one that does not takes the setting at its
/// next start.
pub fn set(
    layout: &Layout,
    sys: &dyn System,
    setting: Option<&str>,
    value: Option<&str>,
    out: &mut dyn Write,
) -> Result<(), String> {
    supported(sys, "set")?;
    if !layout.installed() {
        return Err(NOT_INSTALLED.into());
    }
    let path = layout.settings();
    let kept = crate::winsvc::settings_text(std::fs::read_to_string(&path), &path)?;
    let Some((name, value)) = setting.zip(value) else {
        let page = settings_page(&kept, &path, layout);
        let _ = out.write_all(page.render(Style::stdout()).as_bytes());
        return Ok(());
    };
    let runs = crate::attach::runs(&layout.state) == Some(true);
    let Some(var) = set_checked(name, value, &kept, layout)? else {
        return said_already(name, value, &kept, layout, runs, out);
    };
    settings(layout, sys, &[(var, value.to_string())], out)?;
    if runs {
        sys.systemctl(&["restart", UNIT_NAME])
            .and_then(|()| sys.wait_running(&layout.state))
            .map_err(|e| not_running_with(&e, name, value, &kept, layout))?;
        did(out, format!("restarted {UNIT_NAME}"));
    } else {
        did(out, "the center takes it at its next start");
    }
    let file = std::fs::read_to_string(&path).unwrap_or_default();
    let page = set_page(var, &file, layout, runs);
    let _ = write!(out, "\n{}", page.render(Style::stdout()));
    Ok(())
}

/// The variable of the setting `name` that `set` gives `value`, checked
/// before anything changes as `install` checks its own: the value
/// ([`check_setting`]), and the settings file `kept`, whose old variable
/// names would keep the center from starting. `None` when the file sets
/// that value already: nothing is written, and nothing restarts.
pub(crate) fn set_checked(
    name: &str,
    value: &str,
    kept: &str,
    layout: &Layout,
) -> Result<Option<&'static str>, String> {
    let var = crate::config::set_variable(name)
        .ok_or_else(|| format!("{name:?}: set changes name, public-url, listen, ui and mcp"))?;
    check_setting(var, value)?;
    crate::config::refuse_old_names(|k| setting_in(kept, k), &layout.settings())
        .map_err(|e| format!("{e}; set changed nothing"))?;
    Ok((setting_in(kept, var).as_deref() != Some(value)).then_some(var))
}

/// What `set` says when the settings file `kept` has `name` at `value`
/// already.
pub(crate) fn said_already(
    name: &str,
    value: &str,
    kept: &str,
    layout: &Layout,
    running: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    did(out, format!("{name} is {value} already; nothing changed"));
    if let Some(var) = crate::config::set_variable(name) {
        let page = set_page(var, kept, layout, running);
        let _ = write!(out, "\n{}", page.render(Style::stdout()));
    }
    Ok(())
}

/// The error of a restart after `set` gave `name` the `value` (the center
/// did not start, or does not answer), with how to put back what the
/// settings file `kept` had before: the value stays in the file.
pub(crate) fn not_running_with(
    e: &str,
    name: &str,
    value: &str,
    kept: &str,
    layout: &Layout,
) -> String {
    let var = crate::config::set_variable(name).unwrap_or_default();
    let back = match setting_in(kept, var).or_else(|| default_of(var, kept)) {
        Some(before) => format!(
            "; {} puts back the value before",
            set_command(layout, &format!("{name} {before}"))
        ),
        None => String::new(),
    };
    format!(
        "{e}. {name} is {value} in {} now{back}",
        layout.settings().display()
    )
}

/// What the installed center does where its settings `file` sets no
/// `var`: the defaults its service runs with. `None` for the name, which
/// is then the one set in the web UI.
fn default_of(var: &str, file: &str) -> Option<String> {
    match var {
        "NERVE_CENTER_PUBLIC_URL" => Some(format!(
            "https://{}:{}",
            crate::center::host_name(),
            crate::winsvc::node_port(file)
        )),
        "NERVE_CENTER_LISTEN" => Some("0.0.0.0:7443".into()),
        "NERVE_CENTER_UI" => Some("127.0.0.1:7480".into()),
        "NERVE_CENTER_MCP" => Some("http".into()),
        _ => None,
    }
}

/// What `set` without a setting shows: each setting it changes, as the
/// settings `file` at `path` sets it or else with its default, and how to
/// change one.
pub(crate) fn settings_page(file: &str, path: &Path, layout: &Layout) -> Page {
    let mut p = page().state("settings", Tone::Plain);
    for (flag, var) in crate::config::INSTALL_SETTINGS {
        let name = flag.trim_start_matches('-');
        let (value, default) = match setting_in(file, var) {
            Some(v) => (v, ""),
            None => (
                default_of(var, file).unwrap_or_else(|| "as set in the web UI".into()),
                " (default)",
            ),
        };
        let value = match value.as_str() {
            "http" => format!("http, at {}", crate::config::MCP_HTTP),
            _ => value,
        };
        p.row(name, format!("{value}{default}"));
    }
    p.row("File", path.display().to_string());
    p.next("Change one", set_next(layout, "<name> <value>"));
    if layout.windows() {
        p.note("Run these commands in an administrator's terminal.");
    }
    p
}

/// `nerve-center set <what>` as an administrator runs it where `layout` is
/// installed: [`admin_command`] for the layout, which the tests give a
/// Windows one on Linux too.
fn set_command(layout: &Layout, what: &str) -> String {
    match layout.windows() {
        true => format!(
            "`{}` in an administrator's terminal",
            set_next(layout, what)
        ),
        false => format!("`{}`", set_next(layout, what)),
    }
}

/// [`set_command`] as `Next` names it, bare.
fn set_next(layout: &Layout, what: &str) -> String {
    match layout.windows() {
        true => format!("nerve-center set {what}"),
        false => format!("sudo nerve-center set {what}"),
    }
}

/// What `set` shows once the settings `file` give `var` its new value,
/// with the center's state (`running`): where the center is reached now and
/// what that takes. Beyond loopback the web UI and MCP use TLS; on Windows
/// the firewall rule `install` made covers the node port only, so the page
/// says how to let another port in.
pub(crate) fn set_page(var: &str, file: &str, layout: &Layout, running: bool) -> Page {
    let at = |var: &str| {
        setting_in(file, var)
            .or_else(|| default_of(var, file))
            .unwrap_or_default()
    };
    let mut p = match running {
        true => page().state("running as a service", Tone::Good),
        false => page().state("stopped", Tone::Bad),
    };
    if !running {
        p.next("Start it", admin("service start"));
    }
    let (address, what, rule, trust) = match var {
        "NERVE_CENTER_UI" => {
            p.row("Web UI", ui_value(file));
            (
                ui_address(file),
                "the web UI",
                "web UI",
                "your browser asks you to trust it",
            )
        }
        "NERVE_CENTER_MCP" => {
            p.row("Harnesses", mcp_value(file));
            (
                mcp_address(file),
                "the HTTP MCP endpoint",
                "MCP",
                "let the harness trust it (the Connect a harness card shows its fingerprint)",
            )
        }
        "NERVE_CENTER_NAME" => {
            p.row("Name", at(var));
            p.note("It replaces the name set in the web UI at each start.");
            return p;
        }
        _ => {
            p.row("Nodes", at("NERVE_CENTER_LISTEN"));
            p.row("Public URL", at("NERVE_CENTER_PUBLIC_URL"));
            p.note("New pairing links name the public URL.");
            return p;
        }
    };
    if address.eq_ignore_ascii_case("off") || crate::config::is_loopback(&address) {
        return p;
    }
    p.note(format!(
        "Beyond loopback {what} uses TLS with the center's self-signed certificate: {trust}."
    ));
    if layout.windows() {
        let port = address.rsplit_once(':').map_or("", |(_, p)| p);
        p.note(format!(
            "The Windows Firewall rule \"{}\" lets in the node port only.",
            crate::winsvc::FIREWALL_RULE,
        ));
        p.next(
            format!("Let in port {port}"),
            format!(
                "New-NetFirewallRule -DisplayName 'Nerve center {rule}' -Direction Inbound -Protocol TCP -LocalPort {port} -Program '{}' -Action Allow",
                layout.bin.display()
            ),
        );
    }
    p
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
        return Err(NOT_INSTALLED.into());
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
        before_restart: &|_| {},
        placed: None,
    };
    let mut steps = Steps::new(out);
    let started = || sys.wait_running(&layout.state);
    let r = nerve_service::update(&p, sys, from, &started, &mut steps).await;
    log_update(layout, &steps.done, &r, steps.out);
    let started = r?;
    let version = sys
        .account(USER)
        .ok()
        .flatten()
        .and_then(|a| sys.version_of(&layout.bin, &a).ok())
        .and_then(|said| nerve_service::Version::parse_of("nerve-center", &said))
        .map(|v| v.to_string());
    let page = done_page(layout, &file, None, version.as_deref(), started);
    let _ = write!(out, "\n{}", page.render(Style::stdout()));
    Ok(())
}

/// Writes what `update` did to the center's log, as the state folder's
/// owner ([`as_owner_of`]): root does not write through a link the center's
/// user put there.
pub(crate) fn log_update(
    layout: &Layout,
    steps: &[String],
    r: &Result<bool, String>,
    out: &mut dyn Write,
) {
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
pub(crate) fn asset_name() -> Result<String, String> {
    match std::env::consts::ARCH {
        arch @ ("x86_64" | "aarch64") if cfg!(target_os = "linux") => {
            Ok(format!("nerve-center-{arch}-linux"))
        }
        "x86_64" if cfg!(windows) => Ok("nerve-center-x86_64-windows.exe".into()),
        other => Err(format!(
            "the releases have no program of the center for {other}; build one (docs/dev/building.md) and give it with --from"
        )),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::config::McpMode;
    use nerve_service::Account;

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

    /// A service that cannot start says why in the log of its state
    /// folder (it has no terminal); a command run by hand does not write
    /// there (round 2, correctness 2).
    #[test]
    fn a_refused_start_of_the_service_goes_to_its_log() {
        let dir = tempfile::tempdir().unwrap();
        let log = nerve_transport::log::file_in(dir.path());
        refuse_start(dir.path(), false, "a command's refusal");
        assert!(!log.exists());
        refuse_start(dir.path(), true, "invalid value 'htttp' for '--mcp'\n");
        let text = std::fs::read_to_string(&log).unwrap();
        assert!(text.contains("the service cannot start: invalid value 'htttp'"));
    }

    fn me() -> Account {
        Fake::new().me()
    }

    impl System for Fake {
        fn wait_running(&self, _state: &Path) -> Result<(), String> {
            self.started()
                .map_err(|_| "the center does not answer".to_string())
        }
    }

    use nerve_service::fake::NotRoot;

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

    /// `service start|stop|restart` asks systemd, a start waits until the
    /// center answers, and the page `status` shows ends it (#213).
    #[test]
    fn the_service_command_starts_stops_and_restarts_the_center() {
        use crate::config::ServiceCmd;
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        for (c, verb, said, head) in [
            (
                ServiceCmd::Stop,
                "stop",
                "stopped the center",
                " · stopped\n",
            ),
            (
                ServiceCmd::Start,
                "start",
                "started the center",
                " · running as a service\n",
            ),
            (
                ServiceCmd::Restart,
                "restart",
                "restarted the center",
                " · running as a service\n",
            ),
        ] {
            sys.calls.borrow_mut().clear();
            let mut out = Vec::new();
            service(&l, &sys, c, &mut out).unwrap();
            assert_eq!(sys.calls(), [format!("systemctl {verb} {UNIT_NAME}")]);
            let out = String::from_utf8(out).unwrap();
            assert!(
                out.starts_with(&format!("{said}\n\nNerve center ")),
                "{out}"
            );
            assert!(out.contains(head), "{out}");
            assert_eq!(
                has_next(&out, "Start it: sudo nerve-center service start"),
                c == ServiceCmd::Stop,
                "{out}"
            );
        }
        // A start that does not come up is an error.
        sys.next_start.set(Some(false));
        assert!(service(&l, &sys, ServiceCmd::Start, &mut Vec::new()).is_err());
        let e = service(
            &layout(&d.path().join("none")),
            &Fake::new(),
            ServiceCmd::Start,
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(e, NOT_INSTALLED);
        // The hint names the command that was typed, not a bare `service`,
        // which is how Windows starts the center.
        for c in [ServiceCmd::Start, ServiceCmd::Stop, ServiceCmd::Restart] {
            assert_eq!(
                service(&l, &NotRoot, c, &mut Vec::new()).unwrap_err(),
                format!("{0} needs root: run `sudo nerve-center {0}`", c.typed())
            );
        }
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
            out.contains("  Harnesses     http://127.0.0.1:7481/mcp\n"),
            "{out}"
        );
        // The owner token is made before the service starts, kept private in
        // the state folder, and said with the command that shows it again.
        let owner = crate::owner::read(&l.state)
            .unwrap()
            .expect("an owner token");
        assert!(owner.starts_with(crate::owner::PREFIX), "{owner}");
        let owner_file = crate::owner::path(&l.state);
        assert_eq!(mode(&owner_file), 0o600);
        assert!(
            out.contains(&format!("\n  Owner token   {owner}\n")),
            "{out}"
        );
        assert!(
            has_next(&out, "Owner token: sudo nerve-center owner-token"),
            "{out}"
        );
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
        // A center that ends with an error or a signal is started again: one
        // that found a lock poisoned ends so (nerve_transport::sync).
        assert!(unit.contains("\nRestart=on-failure\n"), "{unit}");
        assert!(
            !unit.contains("SuccessExitStatus") && !unit.contains("RestartPrevent"),
            "{unit}"
        );
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
        let text = layout(Path::new("/")).settings_text("nrv_abc", &[]);
        let vars: Vec<(&str, &str)> = text
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .map(|l| l.split_once('=').unwrap())
            .collect();
        assert_eq!(vars, [("NERVE_CENTER_HARNESS_TOKEN", "nrv_abc")]);
        // What install was given is set, the rest stays a comment.
        let set = [("NERVE_CENTER_NAME", "lab".to_string())];
        let text = layout(Path::new("/")).settings_text("nrv_abc", &set);
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
        // `service restart` names itself, not a bare `service`, which is how
        // Windows starts the center (round 2 of #213's second pass,
        // correctness 1).
        let e = rt
            .block_on(execute_on(
                Cmd::Service {
                    cmd: Some(crate::config::ServiceCmd::Restart),
                },
                &[],
                &[],
                &l,
                &NotRoot,
                Path::new("/nonexistent"),
                &mut Vec::new(),
            ))
            .unwrap_err();
        assert_eq!(
            e,
            "service restart needs root: run `sudo nerve-center service restart`"
        );
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
            (
                "set",
                Cmd::Set {
                    setting: Some("ui".into()),
                    value: Some("0.0.0.0:7480".into()),
                },
            ),
            (
                "set",
                Cmd::Set {
                    setting: None,
                    value: None,
                },
            ),
            (
                "update",
                Cmd::Update {
                    from: None,
                    pre: false,
                    tag: None,
                },
            ),
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
                "install takes only --name, --public-url, --listen, --ui and --mcp of the center's settings, which it writes into its settings file, not --state-dir"
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
        // `set` takes a setting by its name: a flag is refused with the
        // command that sets it.
        let set = Cmd::Set {
            setting: None,
            value: None,
        };
        let e = execute_on(
            set,
            &["--ui".to_string()],
            &[],
            &l,
            &NotRoot,
            &node,
            &mut Vec::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(
            e,
            "set takes a setting by its name, as `sudo nerve-center set ui 0.0.0.0:7480`, not --ui"
        );
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
            out.contains("  Web UI        http://127.0.0.1:7480\n"),
            "{out}"
        );
        assert!(out.contains(&format!("  Owner token   {token}\n")), "{out}");
        assert!(
            out.contains("  Harnesses     http://127.0.0.1:7481/mcp\n"),
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

    /// `install --ui --mcp` writes the web UI's and MCP's addresses into
    /// a new settings file too, and ends with them; `stdio`, which the
    /// service has no input for, is refused.
    #[test]
    fn install_takes_the_web_ui_and_mcp_addresses() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = layout(d.path());
        let exe = d.path().join("nerve-center-x86_64-linux");
        std::fs::write(&exe, "nerve-center 1.0.0\n").unwrap();
        let set = [
            ("NERVE_CENTER_UI", "127.0.0.1:7490".to_string()),
            ("NERVE_CENTER_MCP", "127.0.0.1:7491".to_string()),
        ];
        let mut out = Vec::new();
        install_with(&l, &sys, &exe, &set, &mut out).unwrap();
        let file = std::fs::read_to_string(l.settings()).unwrap();
        assert!(
            file.contains("\nNERVE_CENTER_UI=127.0.0.1:7490\n"),
            "{file}"
        );
        assert!(
            file.contains("\nNERVE_CENTER_MCP=127.0.0.1:7491\n"),
            "{file}"
        );
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("  Web UI        http://127.0.0.1:7490\n"),
            "{out}"
        );
        assert!(
            out.contains("  Harnesses     http://127.0.0.1:7491/mcp\n"),
            "{out}"
        );
        for (var, bad) in [
            ("NERVE_CENTER_MCP", "stdio"),
            ("NERVE_CENTER_UI", "0.0.0.0"),
        ] {
            let e = install_with(&l, &sys, &exe, &[(var, bad.to_string())], &mut Vec::new())
                .unwrap_err();
            assert!(e.contains(bad), "{e}");
        }
        // What `install --mcp` gives is written as the owner meant it.
        let a = |m: &str| m.parse::<McpMode>().unwrap().setting();
        assert_eq!(a("off"), "off");
        assert_eq!(a("0.0.0.0:7481"), "0.0.0.0:7481");
        assert_eq!(a("http"), crate::config::MCP_HTTP);
    }

    /// `set` writes the setting in place of its line in the settings file
    /// and keeps the others, the harness token among them; the running
    /// service restarts and the center answers before it says where the
    /// web UI is now. The same value again changes nothing; a service that
    /// does not run is not started.
    #[test]
    fn set_writes_the_setting_in_place_and_restarts_the_running_service() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        let before = std::fs::read_to_string(l.settings()).unwrap();
        sys.calls.borrow_mut().clear();
        let lock = crate::attach::try_lock(&l.state).unwrap().unwrap();
        let mut out = Vec::new();
        set(&l, &sys, Some("ui"), Some("0.0.0.0:7480"), &mut out).unwrap();
        let after = std::fs::read_to_string(l.settings()).unwrap();
        let changed: Vec<(&str, &str)> = before
            .lines()
            .zip(after.lines())
            .filter(|(b, a)| b != a)
            .collect();
        assert_eq!(
            changed,
            [(
                "#NERVE_CENTER_UI=127.0.0.1:7480",
                "NERVE_CENTER_UI=0.0.0.0:7480"
            )]
        );
        assert_eq!(before.lines().count(), after.lines().count());
        assert_eq!(
            sys.calls(),
            [format!("systemctl restart {UNIT_NAME}")],
            "restarted, and nothing else"
        );
        let out = String::from_utf8(out).unwrap();
        let host = crate::center::host_name();
        for want in [
            &format!(
                "set NERVE_CENTER_UI=0.0.0.0:7480 in {}\n",
                l.settings().display()
            ),
            &format!("restarted {UNIT_NAME}\n"),
            &format!("  Web UI      https://{host}:7480\n"),
            "uses TLS with the center's self-signed certificate",
        ] {
            assert!(out.contains(want), "{want}: {out}");
        }
        assert!(!out.contains("Firewall"), "{out}");
        // The same value again: nothing written, nothing restarted.
        let mut out = Vec::new();
        set(&l, &sys, Some("ui"), Some("0.0.0.0:7480"), &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("ui is 0.0.0.0:7480 already; nothing changed\n"),
            "{out}"
        );
        assert_eq!(sys.calls().len(), 1);
        // A center that answers no more after the restart: the error says
        // what the file holds now and how to put back the value before.
        sys.next_start.set(Some(false));
        let e = set(
            &l,
            &sys,
            Some("ui"),
            Some("127.0.0.1:7490"),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(e.contains("ui is 127.0.0.1:7490 in"), "{e}");
        assert!(
            e.ends_with("`sudo nerve-center set ui 0.0.0.0:7480` puts back the value before"),
            "{e}"
        );
        // A service that does not run takes it at its next start.
        drop(lock);
        sys.calls.borrow_mut().clear();
        let mut out = Vec::new();
        set(&l, &sys, Some("mcp"), Some("off"), &mut out).unwrap();
        assert!(sys.calls().is_empty(), "{:?}", sys.calls());
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("the center takes it at its next start\n"),
            "{out}"
        );
        assert!(out.contains("  Harnesses   off\n"), "{out}");
        assert!(out.contains(" · stopped\n"), "{out}");
        let file = std::fs::read_to_string(l.settings()).unwrap();
        assert_eq!(
            setting_in(&file, "NERVE_CENTER_MCP").as_deref(),
            Some("off")
        );
        assert_eq!(
            setting_in(&file, "NERVE_CENTER_HARNESS_TOKEN"),
            setting_in(&before, "NERVE_CENTER_HARNESS_TOKEN")
        );
        assert_eq!(file.matches("NERVE_CENTER_UI=").count(), 1, "{file}");
    }

    /// A value the center would not start on, or one that would put
    /// another line into the file, is refused before anything changes: an
    /// address without its port with an example that has one.
    #[test]
    fn set_refuses_a_bad_value_and_changes_nothing() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        let before = std::fs::read_to_string(l.settings()).unwrap();
        sys.calls.borrow_mut().clear();
        let _lock = crate::attach::try_lock(&l.state).unwrap().unwrap();
        for (name, bad, says) in [
            ("ui", "0.0.0.0", "like 0.0.0.0:7480"),
            ("ui", "on", "or off"),
            ("mcp", "stdio", "http (127.0.0.1:7481), off"),
            ("mcp", "0.0.0.0", "like 0.0.0.0:7481"),
            ("listen", "7443", "like 0.0.0.0:7443"),
            ("public-url", "lab.example", "like https://"),
            ("name", "a\nNERVE_CENTER_UI=0.0.0.0:80", "one line"),
            ("name", "lab\\", "no backslash"),
            (
                "port",
                "7443",
                "set changes name, public-url, listen, ui and mcp",
            ),
        ] {
            let mut out = Vec::new();
            let e = set(&l, &sys, Some(name), Some(bad), &mut out).unwrap_err();
            assert!(e.contains(says), "{name} {bad:?}: {e}");
            assert!(out.is_empty(), "{}", String::from_utf8_lossy(&out));
        }
        assert_eq!(std::fs::read_to_string(l.settings()).unwrap(), before);
        assert!(sys.calls().is_empty(), "{:?}", sys.calls());
        // Where nothing is installed, it says so and how to install.
        let e = set(
            &layout(&d.path().join("none")),
            &sys,
            Some("ui"),
            Some("0.0.0.0:7480"),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(e, NOT_INSTALLED);
        assert!(!d.path().join("none").exists());
    }

    /// `set` alone lists the settings it changes: what the file sets, the
    /// defaults where it sets none, the file, and how to change one.
    #[test]
    fn set_without_a_setting_lists_the_settings() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = layout(d.path());
        let exe = d.path().join("nerve-center-x86_64-linux");
        std::fs::write(&exe, "nerve-center 1.0.0\n").unwrap();
        let set_at_install = [
            ("NERVE_CENTER_NAME", "lab".to_string()),
            ("NERVE_CENTER_LISTEN", "0.0.0.0:9443".to_string()),
        ];
        install_with(&l, &sys, &exe, &set_at_install, &mut Vec::new()).unwrap();
        let before = std::fs::read_to_string(l.settings()).unwrap();
        sys.calls.borrow_mut().clear();
        let mut out = Vec::new();
        set(&l, &sys, None, None, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        let host = crate::center::host_name();
        assert_eq!(
            out,
            format!(
                "Nerve center {} · settings

  name         lab
  public-url   https://{host}:9443 (default)
  listen       0.0.0.0:9443
  ui           127.0.0.1:7480 (default)
  mcp          http, at 127.0.0.1:7481 (default)
  File         {}

Next  Change one:  sudo nerve-center set <name> <value>
",
                env!("CARGO_PKG_VERSION"),
                l.settings().display()
            )
        );
        assert!(sys.calls().is_empty());
        assert_eq!(std::fs::read_to_string(l.settings()).unwrap(), before);
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

    /// Whether the page `text` names the next step `step` ("What: command"),
    /// the blanks that align it aside.
    fn has_next(text: &str, step: &str) -> bool {
        text.lines()
            .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
            .any(|l| l == step || l == format!("Next {step}"))
    }

    /// [`status_page_of`] as plain text, with what `runs` and the service
    /// say of this machine left out: an installed one runs as a service.
    fn status_text(
        l: &Layout,
        state: &Path,
        installed: bool,
        file: Option<&str>,
        ui: &str,
        mcp: &McpMode,
    ) -> String {
        let service = installed.then(|| ServiceState {
            active: true,
            state: "active".into(),
            boot: Some(true),
        });
        let runs = crate::attach::runs(state);
        status_page_of(l, state, installed, file, ui, mcp, runs, service).render(Style::PLAIN)
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
        let p = status_page_of(
            &l,
            &state,
            false,
            None,
            "127.0.0.1:7480",
            &McpMode::Stdio,
            crate::attach::runs(&state),
            None,
        )
        .render(Style::PLAIN);
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(p.contains(" · only an administrator sees it\n"), "{p}");
        assert!(
            p.contains("  Machines    only an administrator sees them\n"),
            "{p}"
        );
        assert!(
            p.contains("Next  See it all:   sudo nerve-center status\n"),
            "{p}"
        );
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

    /// `status` says whether a center runs from its lock, which every
    /// system has now (#64), in its head line.
    #[test]
    fn the_status_says_whether_a_center_runs() {
        let d = tempfile::tempdir().unwrap();
        let l = layout(d.path());
        let head = |state: &Path| {
            status_text(&l, state, false, None, "off", &McpMode::Off)
                .lines()
                .next()
                .unwrap()
                .to_string()
        };
        let v = env!("CARGO_PKG_VERSION");
        let lock = crate::attach::try_lock(d.path()).unwrap().unwrap();
        assert_eq!(head(d.path()), format!("Nerve center {v} · running"));
        drop(lock);
        assert_eq!(head(d.path()), format!("Nerve center {v} · not running"));
        assert_eq!(
            head(&d.path().join("none")),
            format!("Nerve center {v} · not started yet")
        );
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
            tx.send(status_text(
                &l,
                &state,
                false,
                None,
                "127.0.0.1:7480",
                &McpMode::Stdio,
            ))
            .unwrap()
        });
        let text = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("status waited on a FIFO");
        assert!(text.contains("  Machines    "), "{text}");
    }

    /// `install` ends with the page `status` shows, the owner token on it
    /// once, and `off` for a web UI and MCP that are off.
    #[test]
    fn install_ends_with_the_status_page_and_the_owner_token() {
        let d = tempfile::tempdir().unwrap();
        let l = layout(d.path());
        let off = done_page(
            &l,
            "NERVE_CENTER_UI=off\nNERVE_CENTER_MCP=off\n",
            Some("tok"),
            None,
            true,
        )
        .render(Style::PLAIN);
        assert!(off.contains("  Web UI        off\n"), "{off}");
        assert!(off.contains("  Harnesses     off\n"), "{off}");
        assert!(off.contains("  Owner token   tok\n"), "{off}");
        assert!(
            off.starts_with(&format!(
                "Nerve center {} · running as a service\n",
                env!("CARGO_PKG_VERSION")
            )),
            "{off}"
        );
        let on = done_page(&l, "", None, Some("1.2.0"), true).render(Style::PLAIN);
        assert!(on.starts_with("Nerve center 1.2.0 · "), "{on}");
        assert!(on.contains("  Web UI      http://127.0.0.1:7480\n"), "{on}");
        assert!(on.contains("/mcp\n"), "{on}");
        assert!(!on.contains("Owner token   "), "{on}");
        assert!(
            has_next(&on, "Owner token: sudo nerve-center owner-token"),
            "{on}"
        );
        // A running center with no machine says how to pair one.
        assert!(
            has_next(&on, "Pair a machine: sudo nerve-center pair"),
            "{on}"
        );
    }

    /// `status` of a center that is not installed: where it runs, how
    /// harnesses reach it, the machines, its folder and its owner token.
    #[test]
    fn the_status_says_where_the_center_is() {
        let d = tempfile::tempdir().unwrap();
        let l = layout(d.path());
        let state = d.path().join("own");
        let text = status_text(&l, &state, false, None, "127.0.0.1:7480", &McpMode::Stdio);
        // The first thing a new person sees: no machines, and no command
        // to run for them (round 2).
        assert!(text.contains("  Machines    none paired yet\n"), "{text}");
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
        let text = status_text(&l, &state, false, None, "127.0.0.1:7480", &McpMode::Stdio);
        for want in [
            "  Service     none, a harness starts it\n",
            "  Web UI      http://127.0.0.1:7480\n",
            "  Harnesses   the one that starts it (stdio)\n",
            "  Machines    1: web-1\n",
            &format!("  Folder      {}\n", state.display()),
        ] {
            assert!(text.contains(want), "{want}: {text}");
        }
        assert!(
            text.contains("Owner token:  nerve-center owner-token --state-dir "),
            "{text}"
        );
        // What this command is given is all that is known of a center a
        // harness starts, and its token is found with its folder (round 4,
        // correctness 2).
        let text = status_text(
            &l,
            &state,
            false,
            None,
            "127.0.0.1:7490",
            &McpMode::Http("127.0.0.1:7491".into()),
        );
        for want in [
            "  Web UI      http://127.0.0.1:7490\n",
            "  Harnesses   http://127.0.0.1:7491/mcp\n",
        ] {
            assert!(text.contains(want), "{want}: {text}");
        }
        assert!(
            has_next(
                &text,
                &format!(
                    "Owner token: nerve-center owner-token --state-dir {}",
                    state.display()
                )
            ),
            "{text}"
        );
        assert!(!text.contains("7480"), "{text}");
        let text = status_text(&l, &state, false, None, "off", &McpMode::Off);
        assert!(text.contains("  Web UI      off\n"), "{text}");
        assert!(text.contains("  Harnesses   off\n"), "{text}");
        // The installed center: its service and its HTTP MCP.
        let file = "NERVE_CENTER_UI=0.0.0.0:7480\nNERVE_CENTER_MCP=0.0.0.0:7481\n";
        let text = status_text(
            &l,
            &state,
            true,
            Some(file),
            "127.0.0.1:7480",
            &McpMode::Stdio,
        );
        // An address on all of them is reached by the machine's name.
        let host = crate::center::host_name();
        assert!(
            text.contains(&format!("  Web UI      https://{host}:7480\n")),
            "{text}"
        );
        assert!(
            text.contains(&format!("  Harnesses   https://{host}:7481/mcp\n")),
            "{text}"
        );
        assert!(text.contains(" · running as a service\n"), "{text}");
        assert!(
            has_next(&text, "Owner token: sudo nerve-center owner-token"),
            "{text}"
        );
        // A stopped service says how to start it.
        let stopped = status_page_of(
            &l,
            &state,
            true,
            Some(file),
            "",
            &McpMode::Off,
            Some(false),
            Some(ServiceState {
                active: false,
                state: "inactive".into(),
                boot: Some(true),
            }),
        )
        .render(Style::PLAIN);
        assert!(stopped.contains(" · stopped\n"), "{stopped}");
        assert!(
            stopped.contains("  Service     inactive, starts with the machine\n"),
            "{stopped}"
        );
        assert!(
            has_next(&stopped, "Start it: sudo nerve-center service start"),
            "{stopped}"
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
        // It ends with the page `status` shows, of the new program, where
        // the owner token is found.
        assert!(
            out.contains("\nNerve center 1.2.0 · running as a service\n"),
            "{out}"
        );
        assert!(
            has_next(&out, "Owner token: sudo nerve-center owner-token"),
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
        // The same program again changes nothing, and starts nothing: the
        // page says the center that does not run is stopped (round 1 of
        // #213's second pass, correctness 7).
        let calls = sys.calls().len();
        let mut out = Vec::new();
        update(&l, &sys, Some(&new), &mut out).await.unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("nothing to update"), "{out}");
        assert!(out.contains("\nNerve center 1.2.0 · stopped\n"), "{out}");
        assert!(
            has_next(&out, "Start it: sudo nerve-center service start"),
            "{out}"
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

    /// `update --tag` takes that release's center, `update --pre` the
    /// newest release's, a pre-release too, each checked against its own
    /// `SHA256SUMS` (#213).
    #[tokio::test]
    async fn update_takes_a_pre_release_or_a_tag() {
        use nerve_transport::http::{Response, read_request};
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let asset = asset_name().unwrap();
        let sha = crate::util::sha256_hex;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let files = move |tag: &str| -> Option<(String, Vec<u8>)> {
            let program = match tag {
                "pre2-v1.3.0" => b"nerve-center 1.3.0\n".to_vec(),
                "v1.3.0" => b"nerve-center 1.3.0\n{}\n".to_vec(),
                _ => return None,
            };
            Some((format!("{}  {asset}\n", sha(&program)), program))
        };
        let asset2 = asset_name().unwrap();
        tokio::spawn(async move {
            while let Ok((mut io, _)) = listener.accept().await {
                let req = read_request(&mut io, 0).await.unwrap();
                let path = req.path.clone();
                let tagged = path
                    .strip_prefix("/o/r/releases/download/")
                    .and_then(|p| p.split_once('/'));
                let r = match (path.as_str(), tagged) {
                    ("/o/r/api/releases", _) => Response::new(
                        200,
                        "application/json",
                        br#"[{"tag_name": "pre2-v1.3.0", "prerelease": true}, {"tag_name": "v1.2.0"}]"#.to_vec(),
                    ),
                    (_, Some((tag, "SHA256SUMS"))) => match files(tag) {
                        Some((sums, _)) => Response::text(200, &sums),
                        None => Response::text(404, "no"),
                    },
                    (_, Some((tag, name))) if name == asset2 => match files(tag) {
                        Some((_, program)) => Response::new(200, "application/octet-stream", program),
                        None => Response::text(404, "no"),
                    },
                    _ => Response::text(404, "no"),
                };
                let _ = r.write(&mut io).await;
            }
        });
        let mut l = installed(d.path(), &sys, "1.0.0");
        l.release = format!("http://127.0.0.1:{port}/o/r/releases/latest/download");
        let pre = with_release(&l, true, None).await.unwrap();
        let mut out = Vec::new();
        update(&pre, &sys, None, &mut out).await.unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("/o/r/releases/download/pre2-v1.3.0 and checked it"),
            "{out}"
        );
        assert_eq!(std::fs::read(&l.bin).unwrap(), b"nerve-center 1.3.0\n");
        // The release of the same version is another program, and taken.
        let tagged = with_release(&l, false, Some("v1.3.0".into()))
            .await
            .unwrap();
        let mut out = Vec::new();
        update(&tagged, &sys, None, &mut out).await.unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("replaced nerve-center 1.3.0 with 1.3.0"),
            "{out}"
        );
        assert_eq!(std::fs::read(&l.bin).unwrap(), b"nerve-center 1.3.0\n{}\n");
        // A tag that has no such release changes nothing.
        let none = with_release(&l, false, Some("v9.9.9".into()))
            .await
            .unwrap();
        let e = update(&none, &sys, None, &mut Vec::new())
            .await
            .unwrap_err();
        assert!(
            e.starts_with(&format!("no release is at {}", none.release)),
            "{e}"
        );
        assert!(with_release(&l, false, Some("../x".into())).await.is_err());
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
