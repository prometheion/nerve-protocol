//! The center as a Windows service (docs/dev/windows.md, "The center as a
//! Windows service"): `install`, `set`, `update` and `uninstall` in an
//! administrator's terminal, as the Linux ones in [`crate::service`] are.
//! The service `nerve-center` runs `nerve-center service` as its own
//! virtual account, `NT SERVICE\nerve-center`, which Windows makes and
//! removes with the service. Only that account, SYSTEM and the
//! administrators may open the state folder; the settings in `center.env`
//! are the administrators', and the service may only read them, so the
//! center cannot change how it is started. A Windows Firewall rule lets
//! other machines reach the node port, and nothing else.
//!
//! What these commands do to the machine beyond the center's files (the
//! folders' DACLs, the service control manager, the firewall, running a
//! program) goes through [`WinSystem`], so the steps run on every platform
//! in the tests; the real calls are `crate::win_host`.

use std::io::Write;
use std::path::{Path, PathBuf};

use nerve_service::eventlog::CENTER_SOURCE;
use nerve_service::win::dacl::{dacl_of, owned_by_admins};
use nerve_service::win::service::{Settings, service_sid, virtual_account};
use nerve_service::win::update::{clean_aside, previous, staged};
use nerve_service::{Steps, write_file};

use crate::service::{Layout, check_setting, done_page, setting_in};

/// The name the service is registered under, which also names its virtual
/// account.
pub const SERVICE_NAME: &str = "nerve-center";
/// The Windows Firewall rule that lets other machines reach the node port.
pub const FIREWALL_RULE: &str = "Nerve center";
/// The node port where the settings name none.
const NODE_PORT: u16 = 7443;
/// The start of the name a program gets when it moves aside, held by
/// Windows, until it goes at the next start ([`WinSystem::remove_program`]).
pub const ASIDE: &str = "nerve-center.";
/// Why `set`, `update` and the restore into the service do nothing here.
pub const NOT_INSTALLED: &str = "the center is not installed as a service here; `nerve-center install` in an administrator's terminal installs it";

/// What `install`, `update` and `uninstall` do to a Windows machine besides
/// writing the center's files.
pub trait WinSystem {
    /// Whether this process runs as an administrator, elevated.
    fn is_admin(&self) -> bool;
    /// Makes `dir` when it is missing, with the DACL `sddl` from its first
    /// moment, or gives the folder there that DACL; one another account made
    /// is refused, as is a link in its place
    /// (nerve_service::win::dacl::private_folder).
    fn secure(&self, dir: &Path, sddl: &str) -> Result<(), String>;
    /// The service: `None` when it is not registered, else whether it runs.
    fn service(&self) -> Result<Option<bool>, String>;
    /// Registers the service, or changes it: `layout.bin` as its virtual
    /// account, started with the machine and again after a failure.
    fn put_service(&self, layout: &Layout) -> Result<(), String>;
    fn start(&self) -> Result<(), String>;
    /// Stops the service and waits until it has; a stopped one is fine.
    fn stop(&self) -> Result<(), String>;
    fn delete_service(&self) -> Result<(), String>;
    /// Waits until the center the service started runs.
    fn wait_running(&self, layout: &Layout) -> Result<(), String>;
    /// Puts the firewall rule [`FIREWALL_RULE`] in place, for `layout.bin`
    /// and the TCP port `port` only, in place of one there before.
    fn put_firewall(&self, layout: &Layout, port: u16) -> Result<(), String>;
    /// Removes that rule; `false` when there was none.
    fn delete_firewall(&self) -> Result<bool, String>;
    /// Registers the source of the center's entries in the Windows Event
    /// Log ([`CENTER_SOURCE`]), with `layout.bin` as the file that holds
    /// their text (nerve_service::eventlog), or changes it.
    fn put_event_source(&self, layout: &Layout) -> Result<(), String>;
    /// Removes that source; `false` when it was not registered. The entries
    /// stay in the log.
    fn delete_event_source(&self) -> Result<bool, String>;
    /// Puts `dir` on the machine's `Path`, so that a terminal opened after
    /// it finds the center by name; `false` when it was there already
    /// (nerve_service::win::machine_path).
    fn put_on_path(&self, dir: &Path) -> Result<bool, String>;
    /// Takes `dir` off the machine's `Path`; `false` when it was not there.
    fn remove_from_path(&self, dir: &Path) -> Result<bool, String>;
    /// What `<program> --version` prints, run without the administrators'
    /// rights.
    fn version_of(&self, program: &Path) -> Result<String, String>;
    /// What `<program> service-files` prints, run so too: the settings of
    /// its service ([`service_settings`]).
    fn settings_of(&self, program: &Path) -> Result<String, String>;
    /// Gives the registered service `name` the settings `s`
    /// (nerve_service::win::service::configure).
    fn configure_service(&self, name: &str, s: &Settings) -> Result<(), String>;
    /// Removes the program file and its folder when that is empty; `false`
    /// when Windows holds the program (this command started from it): it
    /// then moves aside to a `nerve-center.*.del` beside it and goes at the
    /// next restart.
    fn remove_program(&self, path: &Path) -> Result<bool, String>;
}

/// The privileges the service keeps: to pass through folders it may not
/// list, as every account may. Windows takes every other from its token.
const PRIVILEGES: &[&str] = &["SeChangeNotifyPrivilege"];

/// The settings of the service `install` registers, by name: restarted
/// after every failure, a stop with an error too
/// (nerve_service::win::service::FAILURE), with Windows' own DACL. `update`
/// gives the service what the new program says here (`service-files`), as
/// Linux writes its unit.
pub fn service_settings() -> Vec<(&'static str, Settings)> {
    vec![(SERVICE_NAME, Settings::new(PRIVILEGES, &[], None))]
}

/// What `service-files` prints on Windows: [`service_settings`].
pub fn service_files_text() -> String {
    nerve_service::win::service::settings_text(&service_settings())
}

/// The SID of the service's virtual account.
pub fn account_sid() -> String {
    service_sid(SERVICE_NAME)
}

/// The DACLs of the center's folders: the folder that holds both, the
/// administrators' and SYSTEM's alone; the state folder, the service's
/// too; the settings folder, the service may read. The administrators own
/// each, and one there already that another owner holds is refused: also
/// one the installing administrator's own account made, which the same
/// person's unelevated programs share (round 3, security 1).
fn top_dacl() -> String {
    owned_by_admins(&dacl_of(&["SY", "BA"], &[]))
}

fn state_dacl() -> String {
    owned_by_admins(&dacl_of(&[&account_sid(), "SY", "BA"], &[]))
}

fn settings_dacl() -> String {
    owned_by_admins(&dacl_of(&["SY", "BA"], &[&account_sid()]))
}

/// The folder that holds the state and the settings folders.
fn home(layout: &Layout) -> PathBuf {
    layout
        .state
        .parent()
        .map_or_else(|| layout.state.clone(), Path::to_path_buf)
}

/// The command line the service control manager starts.
pub fn command_line(layout: &Layout) -> String {
    format!(
        "\"{}\" service --state-dir \"{}\"",
        layout.bin.display(),
        layout.state.display()
    )
}

/// The node port the settings file `file` names, else the default.
pub fn node_port(file: &str) -> u16 {
    setting_in(file, "NERVE_CENTER_LISTEN")
        .and_then(|a| a.parse::<std::net::SocketAddr>().ok())
        .map_or(NODE_PORT, |a| a.port())
}

/// Runs `check` on the folders the service trusts at each start: the
/// settings folder first (it holds `center.env`), then the state folder;
/// the first refusal ends it. `take_settings` calls this before it reads
/// any file (round 4, correctness 1).
pub fn check_folders(
    layout: &Layout,
    check: impl Fn(&Path) -> Result<(), String>,
) -> Result<(), String> {
    check(&layout.settings_dir)?;
    check(&layout.state)
}

/// The text of the settings file `path` as `read` found it. A file that is
/// not there holds no setting, as systemd's `EnvironmentFile=-` takes the
/// Linux unit: an administrator who removed it to start over gets the
/// defaults. Any other failure is an error.
pub fn settings_text(read: std::io::Result<String>, path: &Path) -> Result<String, String> {
    match read {
        Ok(t) => Ok(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// The variables the service's settings file `text` sets, as systemd
/// reads such a file: a `NAME=value` line each, blank lines and `#`
/// comments aside, the value without the blanks around it. Only `NERVE_`
/// names: an old one among them stops the center with what to rename
/// (crate::config::refuse_old_names), and no other variable of the
/// process can be set from there.
pub fn settings_env(text: &str) -> Result<Vec<(String, String)>, String> {
    let mut set = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            return Err(format!("line {}: not NAME=value", n + 1));
        };
        let name = name.trim();
        if !name.starts_with("NERVE_") || name.contains(char::is_whitespace) {
            return Err(format!(
                "line {}: {name:?} is not a setting of the center (NERVE_CENTER_…)",
                n + 1
            ));
        }
        set.push((name.to_string(), value.trim().to_string()));
    }
    Ok(set)
}

/// What `netsh` is asked to put the firewall rule in place: inbound TCP to
/// `port`, for `program` only, in every profile.
pub fn firewall_args(program: &Path, port: u16) -> Vec<String> {
    vec![
        "advfirewall".into(),
        "firewall".into(),
        "add".into(),
        "rule".into(),
        format!("name={FIREWALL_RULE}"),
        "dir=in".into(),
        "action=allow".into(),
        format!("program={}", program.display()),
        "protocol=TCP".into(),
        format!("localport={port}"),
        "profile=any".into(),
        "enable=yes".into(),
    ]
}

/// Whether `what` can run here: as an elevated administrator.
pub(crate) fn supported(sys: &dyn WinSystem, what: &str) -> Result<(), String> {
    if !sys.is_admin() {
        return Err(format!(
            "{what} needs an administrator: run `nerve-center {what}` in a terminal opened with Run as administrator"
        ));
    }
    Ok(())
}

/// Runs `install`, `set`, `update` or `uninstall` (`what`) on `layout`, as
/// [`crate::service::execute`] has them checked already.
pub async fn execute(
    cmd: crate::config::Cmd,
    set: &[(&str, String)],
    layout: &Layout,
    sys: &dyn WinSystem,
    exe: &Path,
    out: &mut dyn Write,
) -> Result<(), String> {
    use crate::config::Cmd;
    match cmd {
        Cmd::Install => install(layout, sys, exe, set, out),
        // `set` here names the settings `install` writes.
        Cmd::Set { setting, value } => {
            self::set(layout, sys, setting.as_deref(), value.as_deref(), out)
        }
        Cmd::Update { from, pre, tag } => {
            let layout = crate::service::with_release(layout, pre, tag).await?;
            update(&layout, sys, from.as_deref(), out).await
        }
        Cmd::Uninstall { purge } => uninstall(layout, sys, purge, out),
        Cmd::Service { cmd: Some(c) } => service(layout, sys, c, out),
        _ => Err("only install, set, service, update and uninstall are service commands".into()),
    }
}

/// `install`: the folders, the owner token, the settings, the program, the
/// service and its firewall rule, the running service, in that order.
/// Running it again puts back what is missing, keeps the settings (but
/// those it is given) and restarts the service.
pub fn install(
    layout: &Layout,
    sys: &dyn WinSystem,
    exe: &Path,
    set: &[(&str, String)],
    out: &mut dyn Write,
) -> Result<(), String> {
    supported(sys, "install")?;
    for (var, value) in set {
        check_setting(var, value)?;
    }
    let kept = std::fs::read_to_string(layout.settings()).unwrap_or_default();
    crate::config::refuse_old_names(|k| setting_in(&kept, k), &layout.settings())
        .map_err(|e| format!("{e}; install changed nothing"))?;
    let mut steps = Steps::new(out);
    // A running service holds the program and the state folder's files.
    if sys.service()? == Some(true) {
        sys.stop()?;
        steps.did(format!(
            "stopped the service {SERVICE_NAME} to install over it"
        ));
    }
    // The folder above first: what is made in it after is made in a folder
    // only the administrators may write.
    sys.secure(&home(layout), &top_dacl())?;
    sys.secure(&layout.state, &state_dacl())?;
    sys.secure(&layout.settings_dir, &settings_dacl())?;
    steps.did(format!(
        "{} is open to {} and the administrators only; {} to the administrators, and the service may read it",
        layout.state.display(),
        virtual_account(SERVICE_NAME),
        layout.settings_dir.display()
    ));
    // Made here, before the service first starts, so that install can say
    // it; one an earlier install made is kept.
    let owner_token = crate::owner::ensure(&layout.state)?.0;
    crate::service::settings_file(layout, set, steps.out)?;
    let real = |p: &Path| std::fs::canonicalize(p).ok();
    if real(exe).is_some() && real(exe) == real(&layout.bin) {
        steps.did(format!(
            "the program is at {} already",
            layout.bin.display()
        ));
    } else {
        let program = std::fs::read(exe).map_err(|e| format!("{}: {e}", exe.display()))?;
        if layout.bin.exists() {
            sys.remove_program(&layout.bin)?;
        }
        write_file(&layout.bin, &program, 0o755)?;
        steps.did(format!("put the program at {}", layout.bin.display()));
    }
    // What an update or an uninstall left behind when it ran from the
    // program it replaced or removed.
    clean_aside(&layout.bin, ASIDE);
    // As Linux puts the program in /usr/local/bin: found by name in a
    // terminal opened after the install, and by a harness that starts it.
    if let Some(dir) = layout.bin.parent()
        && sys.put_on_path(dir)?
    {
        steps.did(format!(
            "put {} on the machine's Path: a terminal opened from now on finds nerve-center",
            dir.display()
        ));
    }
    sys.put_service(layout)?;
    steps.did(format!(
        "registered the service {SERVICE_NAME}, which runs as {} and starts with the machine",
        virtual_account(SERVICE_NAME)
    ));
    sys.put_event_source(layout)?;
    steps.did(format!(
        "registered the source {CENTER_SOURCE} in the Windows Event Log (Application): the service's start, stop and failures go there as well as to {}",
        nerve_transport::log::file_in(&layout.state).display()
    ));
    let file = std::fs::read_to_string(layout.settings()).unwrap_or_default();
    let port = node_port(&file);
    sys.put_firewall(layout, port)?;
    steps.did(format!(
        "the Windows Firewall rule \"{FIREWALL_RULE}\" lets other machines reach the node port {port}, and no other port of the center"
    ));
    start(sys, layout)?;
    sys.wait_running(layout)?;
    steps.did(format!("the service {SERVICE_NAME} runs"));
    let page = done_page(layout, &file, Some(&owner_token), None, true);
    let _ = write!(
        steps.out,
        "\n{}",
        page.render(nerve_service::out::Style::stdout())
    );
    Ok(())
}

/// `set` on Windows, as [`crate::service::set`] on Linux: without a
/// setting the settings it changes; with one, the value written into
/// `center.env` and the service restarted when it runs. A new node port
/// takes the firewall rule along, as `install --listen` does.
pub fn set(
    layout: &Layout,
    sys: &dyn WinSystem,
    setting: Option<&str>,
    value: Option<&str>,
    out: &mut dyn Write,
) -> Result<(), String> {
    use crate::service::{not_running_with, said_already, set_checked, set_page, settings_page};
    use nerve_service::out::Style;
    supported(sys, "set")?;
    let Some(runs) = sys.service()? else {
        return Err(NOT_INSTALLED.into());
    };
    let path = layout.settings();
    let kept = settings_text(std::fs::read_to_string(&path), &path)?;
    let Some((name, value)) = setting.zip(value) else {
        let page = settings_page(&kept, &path, layout);
        let _ = out.write_all(page.render(Style::stdout()).as_bytes());
        return Ok(());
    };
    let Some(var) = set_checked(name, value, &kept, layout)? else {
        return said_already(name, value, &kept, layout, runs, out);
    };
    let mut steps = Steps::new(out);
    crate::service::settings_file(layout, &[(var, value.to_string())], steps.out)?;
    let file = std::fs::read_to_string(&path).unwrap_or_default();
    if var == "NERVE_CENTER_LISTEN" {
        let port = node_port(&file);
        sys.put_firewall(layout, port)?;
        steps.did(format!(
            "the Windows Firewall rule \"{FIREWALL_RULE}\" lets other machines reach the node port {port} now"
        ));
    }
    if runs {
        sys.stop()
            .and_then(|()| start(sys, layout))
            .and_then(|()| sys.wait_running(layout))
            .map_err(|e| not_running_with(&e, name, value, &kept, layout))?;
        steps.did(format!("restarted the service {SERVICE_NAME}"));
    } else {
        steps.did("the center takes it at its next start");
    }
    let page = set_page(var, &file, layout, runs);
    let _ = write!(steps.out, "\n{}", page.render(Style::stdout()));
    Ok(())
}

/// `uninstall`: stops and removes the service and its firewall rule, then
/// the folders (deleted with `purge`, else kept for the administrators
/// alone) and the program.
pub fn uninstall(
    layout: &Layout,
    sys: &dyn WinSystem,
    purge: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    supported(sys, "uninstall")?;
    let mut steps = Steps::new(out);
    if sys.service()?.is_some() {
        sys.stop()?;
        sys.delete_service()?;
        steps.did(format!(
            "stopped and removed the service {SERVICE_NAME}, and with it its account"
        ));
    }
    if sys.delete_firewall()? {
        steps.did(format!(
            "removed the Windows Firewall rule \"{FIREWALL_RULE}\""
        ));
    }
    if sys.delete_event_source()? {
        steps.did(format!(
            "removed the source {CENTER_SOURCE} from the Windows Event Log; its entries stay"
        ));
    }
    let top = home(layout);
    let folders = [&layout.state, &layout.settings_dir];
    if purge {
        for dir in folders {
            if dir.exists() {
                std::fs::remove_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
                steps.did(format!("deleted {}", dir.display()));
            }
        }
        // The folder above goes too once it is empty.
        let _ = std::fs::remove_dir(&top);
    } else if folders.iter().any(|d| d.exists()) {
        if layout.state.exists() {
            sys.secure(&layout.state, &top_dacl())?;
        }
        if layout.settings_dir.exists() {
            sys.secure(&layout.settings_dir, &top_dacl())?;
        }
        steps.did(format!(
            "kept {} and {} (only administrators can open them now; `uninstall --purge` deletes them)",
            layout.state.display(),
            layout.settings_dir.display()
        ));
    }
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
                "removed the program {}; this command runs from it, so Windows deletes the file at its next start",
                layout.bin.display()
            ));
        }
    }
    if let Some(dir) = layout.bin.parent()
        && sys.remove_from_path(dir)?
    {
        steps.did(format!("took {} off the machine's Path", dir.display()));
    }
    if steps.done.is_empty() {
        let _ = writeln!(
            steps.out,
            "nothing to uninstall: no service or program of the center is here"
        );
    }
    Ok(())
}

/// `update`: the new program (the latest release, checked against its
/// `SHA256SUMS`, or a file the owner gives) replaces the installed one, and
/// the service restarts. The state folder and the settings are not touched.
/// A program that is not the center, or is older than the installed one, is
/// refused; one that does not start is replaced by the old one again.
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
    // The new program does not start while the settings file names an old
    // variable: said before anything changes.
    let file = std::fs::read_to_string(layout.settings()).unwrap_or_default();
    crate::config::refuse_old_names(|k| setting_in(&file, k), &layout.settings())
        .map_err(|e| format!("{e}; update changed nothing"))?;
    let mut steps = Steps::new(out);
    let r = update_steps(layout, sys, from, &mut steps).await;
    crate::service::log_update(layout, &steps.done, &r, steps.out);
    let started = r?;
    let version = sys
        .version_of(&layout.bin)
        .ok()
        .and_then(|said| nerve_service::Version::parse_of(SERVICE_NAME, &said))
        .map(|v| v.to_string());
    let page = done_page(layout, &file, None, version.as_deref(), started);
    let _ = write!(
        steps.out,
        "\n{}",
        page.render(nerve_service::out::Style::stdout())
    );
    Ok(())
}

async fn update_steps(
    layout: &Layout,
    sys: &dyn WinSystem,
    from: Option<&Path>,
    steps: &mut Steps<'_>,
) -> Result<bool, String> {
    let p = nerve_service::win::update::Program {
        name: SERVICE_NAME,
        bin: &layout.bin,
        release: &layout.release,
        asset: crate::service::asset_name(),
        service: SERVICE_NAME,
        services: &[SERVICE_NAME],
        settings_args: Vec::new(),
        install: "`nerve-center install` in an administrator's terminal",
    };
    nerve_service::win::update::update(&p, &Machine { sys, layout }, from, steps).await
}

/// The machine as `update` sees it (nerve_service::win::update::Installed).
struct Machine<'a> {
    sys: &'a dyn WinSystem,
    layout: &'a Layout,
}

impl nerve_service::win::update::Installed for Machine<'_> {
    fn start(&self) -> Result<(), String> {
        start(self.sys, self.layout)
    }
    fn stop(&self) -> Result<(), String> {
        self.sys.stop()
    }
    fn wait_running(&self) -> Result<(), String> {
        self.sys.wait_running(self.layout)
    }
    fn version_of(&self, program: &Path) -> Result<String, String> {
        self.sys.version_of(program)
    }
    fn settings_of(&self, program: &Path, _: &[String]) -> Result<String, String> {
        self.sys.settings_of(program)
    }
    fn configure(&self, name: &str, s: &Settings) -> Result<(), String> {
        self.sys.configure_service(name, s)
    }
    fn remove_program(&self, path: &Path) -> Result<bool, String> {
        self.sys.remove_program(path)
    }
}

/// Starts the service. A center that ends before it reaches the manager (a
/// setting `center.env` gets wrong) has the start fail at once, with the
/// manager's "did not respond in time": the error names the log, where that
/// center wrote why, as [`WinSystem::wait_running`] does (round 3,
/// correctness 1).
fn start(sys: &dyn WinSystem, layout: &Layout) -> Result<(), String> {
    sys.start().map_err(|e| {
        let log = nerve_transport::log::file_in(&layout.state);
        format!("{e}; {} says why", log.display())
    })
}

/// `service start|stop|restart` on Windows, as on Linux
/// ([`crate::service::service`]): the service control manager does it.
pub fn service(
    layout: &Layout,
    sys: &dyn WinSystem,
    c: crate::config::ServiceCmd,
    out: &mut dyn Write,
) -> Result<(), String> {
    use crate::config::ServiceCmd;
    supported(sys, "service")?;
    let Some(running) = sys.service()? else {
        return Err(NOT_INSTALLED.into());
    };
    let done = match c {
        ServiceCmd::Start => "started the center",
        ServiceCmd::Stop => "stopped the center",
        ServiceCmd::Restart => "restarted the center",
    };
    if running && c != ServiceCmd::Start {
        sys.stop()?;
    }
    let runs = c != ServiceCmd::Stop;
    if runs {
        if !running || c == ServiceCmd::Restart {
            start(sys, layout)?;
        }
        sys.wait_running(layout)?;
    }
    let _ = writeln!(out, "{done}");
    let file = std::fs::read_to_string(layout.settings()).unwrap_or_default();
    let page = crate::service::service_page(layout, &file, runs);
    let _ = write!(
        out,
        "\n{}",
        page.render(nerve_service::out::Style::stdout())
    );
    Ok(())
}

/// Runs `restore` with the installed service stopped, and starts it again
/// after whether the restore did its work or not; the restore's answer. A
/// service that does not stop runs no restore.
pub fn stopped_for(
    sys: &dyn WinSystem,
    out: &mut dyn Write,
    restore: &dyn Fn(&mut dyn Write) -> Result<(), String>,
) -> Result<(), String> {
    sys.stop()?;
    let _ = writeln!(out, "stopped the service {SERVICE_NAME} for the restore");
    let _ = out.flush();
    let r = restore(out);
    match sys.start() {
        Ok(()) => {
            let _ = writeln!(out, "started the service {SERVICE_NAME} again");
        }
        Err(e) => {
            let _ = writeln!(
                out,
                "the service {SERVICE_NAME} did not start again ({e}): `Start-Service {SERVICE_NAME}` in an administrator's PowerShell"
            );
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    /// A Windows machine in a temporary folder: the service, the DACLs,
    /// the firewall and the programs' versions are recorded or played.
    struct Fake {
        admin: bool,
        calls: RefCell<Vec<String>>,
        /// `None`: not registered; else whether it runs.
        service: Cell<Option<bool>>,
        /// Whether a center the service starts runs.
        starts: Cell<bool>,
        /// Whether the manager refuses the start: the center ended before
        /// it reached the manager.
        refuses: Cell<bool>,
        /// The folders and the DACLs they were given.
        secured: RefCell<Vec<(PathBuf, String)>>,
        /// The firewall rule's port, while there is one.
        firewall: Cell<Option<u16>>,
        /// The programs Windows holds: they move aside.
        held: RefCell<Vec<PathBuf>>,
        /// What a program said each time the service started it.
        started: RefCell<Vec<String>>,
        /// Whether the Event Log source is registered.
        event_source: Cell<bool>,
        /// The machine's `Path`.
        path: RefCell<String>,
    }

    impl Fake {
        fn new() -> Fake {
            Fake {
                admin: true,
                calls: RefCell::new(Vec::new()),
                service: Cell::new(None),
                starts: Cell::new(true),
                refuses: Cell::new(false),
                secured: RefCell::new(Vec::new()),
                firewall: Cell::new(None),
                held: RefCell::new(Vec::new()),
                started: RefCell::new(Vec::new()),
                event_source: Cell::new(false),
                path: RefCell::new(r"%SystemRoot%\system32".into()),
            }
        }

        fn call(&self, c: impl Into<String>) {
            self.calls.borrow_mut().push(c.into());
        }

        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }

        fn dacl_of(&self, dir: &Path) -> Option<String> {
            self.secured
                .borrow()
                .iter()
                .rev()
                .find(|(d, _)| d == dir)
                .map(|(_, s)| s.clone())
        }
    }

    impl WinSystem for Fake {
        fn is_admin(&self) -> bool {
            self.admin
        }
        fn secure(&self, dir: &Path, sddl: &str) -> Result<(), String> {
            std::fs::create_dir_all(dir).unwrap();
            self.secured
                .borrow_mut()
                .push((dir.to_path_buf(), sddl.to_string()));
            Ok(())
        }
        fn service(&self) -> Result<Option<bool>, String> {
            Ok(self.service.get())
        }
        fn put_service(&self, layout: &Layout) -> Result<(), String> {
            self.call(format!("put_service {}", command_line(layout)));
            if self.service.get().is_none() {
                self.service.set(Some(false));
            }
            Ok(())
        }
        fn start(&self) -> Result<(), String> {
            self.call("start");
            if self.refuses.get() {
                return Err(
                    "cannot start the service nerve-center: did not respond in time".into(),
                );
            }
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
            self.call("delete_service");
            self.service.set(None);
            Ok(())
        }
        fn wait_running(&self, layout: &Layout) -> Result<(), String> {
            let said = std::fs::read_to_string(&layout.bin).unwrap_or_default();
            self.started.borrow_mut().push(said.trim().to_string());
            if self.starts.get() && !said.contains("broken") {
                Ok(())
            } else {
                Err("the service stopped at its start".into())
            }
        }
        fn put_firewall(&self, layout: &Layout, port: u16) -> Result<(), String> {
            self.call(format!("put_firewall {} {port}", layout.bin.display()));
            self.firewall.set(Some(port));
            Ok(())
        }
        fn delete_firewall(&self) -> Result<bool, String> {
            self.call("delete_firewall");
            Ok(self.firewall.take().is_some())
        }
        fn put_event_source(&self, layout: &Layout) -> Result<(), String> {
            self.call(format!("put_event_source {}", layout.bin.display()));
            self.event_source.set(true);
            Ok(())
        }
        fn delete_event_source(&self) -> Result<bool, String> {
            self.call("delete_event_source");
            Ok(self.event_source.take())
        }
        fn put_on_path(&self, dir: &Path) -> Result<bool, String> {
            self.call(format!("put_on_path {}", dir.display()));
            let next = nerve_service::win::machine_path::with_dir(
                &self.path.borrow(),
                &dir.display().to_string(),
            );
            Ok(next.map(|p| *self.path.borrow_mut() = p).is_some())
        }
        fn remove_from_path(&self, dir: &Path) -> Result<bool, String> {
            self.call(format!("remove_from_path {}", dir.display()));
            let next = nerve_service::win::machine_path::without_dir(
                &self.path.borrow(),
                &dir.display().to_string(),
            );
            Ok(next.map(|p| *self.path.borrow_mut() = p).is_some())
        }
        fn version_of(&self, program: &Path) -> Result<String, String> {
            // A program here is a text file whose first line says its
            // version.
            let said = std::fs::read_to_string(program).map_err(|e| e.to_string())?;
            let first = said.lines().next().unwrap_or_default();
            Ok(first.trim().replace(" broken", ""))
        }
        /// Its second line, where it has one; else what this build says.
        fn settings_of(&self, program: &Path) -> Result<String, String> {
            let said = std::fs::read_to_string(program).map_err(|e| e.to_string())?;
            Ok(said
                .lines()
                .nth(1)
                .map_or_else(service_files_text, String::from))
        }
        fn configure_service(&self, name: &str, s: &Settings) -> Result<(), String> {
            self.call(format!("configure {name} {}", s.privileges.join(",")));
            Ok(())
        }
        fn remove_program(&self, path: &Path) -> Result<bool, String> {
            self.call(format!(
                "remove_program {}",
                path.file_name().unwrap().to_string_lossy()
            ));
            if self.held.borrow().contains(&path.to_path_buf()) {
                let aside = path.with_file_name(format!("{ASIDE}x.del"));
                std::fs::rename(path, aside).unwrap();
                return Ok(false);
            }
            std::fs::remove_file(path).map_err(|e| e.to_string())?;
            Ok(true)
        }
    }

    fn layout(root: &Path) -> Layout {
        Layout {
            unit: PathBuf::new(),
            bin: root.join("Program Files/Nerve/nerve-center.exe"),
            state: root.join("ProgramData/nerve-center/state"),
            settings_dir: root.join("ProgramData/nerve-center/settings"),
            release: "http://127.0.0.1:1/none".into(),
        }
    }

    /// A downloaded "program" that says `version`.
    fn download(root: &Path, version: &str) -> PathBuf {
        let exe = root.join("Downloads/nerve-center-x86_64-windows.exe");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, format!("nerve-center {version}\n")).unwrap();
        exe
    }

    fn installed(root: &Path, sys: &Fake, version: &str) -> Layout {
        let l = layout(root);
        install(&l, sys, &download(root, version), &[], &mut Vec::new()).unwrap();
        l
    }

    /// The command line the service control manager starts is the
    /// service, which takes its settings first; `service start|stop|restart`
    /// is the owner's (round 1 of #213's second pass, correctness 1: a
    /// count of the arguments took the service for the owner's command).
    #[test]
    fn the_service_s_own_command_line_starts_the_service() {
        use crate::config::starts_the_service;
        let l = layout(Path::new("C:/"));
        // Split as Windows splits it: quoted parts, blanks between.
        let line = command_line(&l);
        let args: Vec<String> = line
            .split('"')
            .enumerate()
            .flat_map(|(i, part)| match i % 2 {
                1 => vec![part.to_string()],
                _ => part.split_whitespace().map(str::to_string).collect(),
            })
            .collect();
        assert_eq!(args.len(), 4, "{args:?}");
        assert!(starts_the_service(&args), "{args:?}");
        assert!(starts_the_service(["nerve-center", "service"]));
        for owners in ["start", "stop", "restart"] {
            assert!(!starts_the_service(["nerve-center", "service", owners]));
        }
        assert!(!starts_the_service(["nerve-center", "status"]));
        assert!(!starts_the_service(["nerve-center"]));
    }

    /// `service start|stop|restart` asks the service control manager, as
    /// on Linux: a stopped service is started, a running one stopped
    /// first for a restart; the page `status` shows ends it (#213).
    #[test]
    fn the_service_command_starts_stops_and_restarts_the_center() {
        use crate::config::ServiceCmd;
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        for (c, calls, said, head) in [
            (
                ServiceCmd::Stop,
                &["stop"][..],
                "stopped the center",
                " · stopped\n",
            ),
            (
                ServiceCmd::Start,
                &["start"],
                "started the center",
                " · running as a service\n",
            ),
            (
                ServiceCmd::Start,
                &[],
                "started the center",
                " · running as a service\n",
            ),
            (
                ServiceCmd::Restart,
                &["stop", "start"],
                "restarted the center",
                " · running as a service\n",
            ),
        ] {
            sys.calls.borrow_mut().clear();
            let mut out = Vec::new();
            service(&l, &sys, c, &mut out).unwrap();
            assert_eq!(sys.calls(), calls, "{c:?}");
            let out = String::from_utf8(out).unwrap();
            assert!(
                out.starts_with(&format!("{said}\n\nNerve center ")),
                "{out}"
            );
            assert!(out.contains(head), "{out}");
        }
        let none = Fake::new();
        let e = service(
            &layout(&d.path().join("none")),
            &none,
            ServiceCmd::Start,
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(e, NOT_INSTALLED);
        let mut not_admin = Fake::new();
        not_admin.admin = false;
        assert!(service(&l, &not_admin, ServiceCmd::Stop, &mut Vec::new()).is_err());
    }

    /// The install makes the folders with their own DACLs, the owner token,
    /// the settings with a harness token, the program, the service as its
    /// virtual account and the firewall rule for the node port, then waits
    /// until the center runs.
    #[test]
    fn install_puts_the_center_under_its_virtual_account() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = layout(d.path());
        let mut out = Vec::new();
        install(&l, &sys, &download(d.path(), "1.0.0"), &[], &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        let sid = account_sid();
        assert!(sid.starts_with("S-1-5-80-"), "{sid}");
        // Only the service, SYSTEM and the administrators open the state;
        // the service only reads the settings; the folder above is the
        // administrators' alone, and is made first.
        assert_eq!(
            sys.dacl_of(&l.state).unwrap(),
            format!("O:BAD:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
        );
        assert_eq!(
            sys.dacl_of(&l.settings_dir).unwrap(),
            format!("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;{sid})")
        );
        assert_eq!(
            sys.secured.borrow()[0],
            (
                d.path().join("ProgramData/nerve-center"),
                "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)".to_string()
            )
        );
        let owner = crate::owner::read(&l.state)
            .unwrap()
            .expect("an owner token");
        assert!(out.contains(&format!("  Owner token   {owner}\n")), "{out}");
        let file = std::fs::read_to_string(l.settings()).unwrap();
        assert!(file.contains("NERVE_CENTER_HARNESS_TOKEN=nrv_"), "{file}");
        // Windows texts in the file the owner edits.
        assert!(file.contains("Restart-Service nerve-center"), "{file}");
        assert!(!file.contains("systemctl"), "{file}");
        assert_eq!(
            std::fs::read_to_string(&l.bin).unwrap(),
            "nerve-center 1.0.0\n"
        );
        let calls = sys.calls();
        assert_eq!(
            calls,
            [
                format!("put_on_path {}", l.bin.parent().unwrap().display()),
                format!(
                    "put_service \"{}\" service --state-dir \"{}\"",
                    l.bin.display(),
                    l.state.display()
                ),
                format!("put_event_source {}", l.bin.display()),
                format!("put_firewall {} 7443", l.bin.display()),
                "start".to_string(),
            ]
        );
        assert!(sys.event_source.get());
        // The program's folder is on the machine's Path once, as Linux has
        // /usr/local/bin: a terminal finds nerve-center by name.
        let dir = l.bin.parent().unwrap().display().to_string();
        assert!(
            sys.path.borrow().ends_with(&format!(";{dir}")),
            "{}",
            sys.path.borrow()
        );
        assert!(out.contains("on the machine's Path"), "{out}");
        assert!(
            out.contains("registered the source nerve-center in the Windows Event Log"),
            "{out}"
        );
        assert!(out.contains("runs as NT SERVICE\\nerve-center"), "{out}");
        assert!(out.contains("the node port 7443"), "{out}");
        assert!(
            out.contains("  Web UI        http://127.0.0.1:7480\n"),
            "{out}"
        );
        assert_eq!(sys.service.get(), Some(true));
    }

    /// A second install keeps the settings and the owner token, writes the
    /// settings it is given and moves the firewall rule to the new port;
    /// it stops the running service first.
    #[test]
    fn install_again_keeps_the_settings_and_follows_the_port() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        let token = crate::owner::read(&l.state).unwrap();
        let before = std::fs::read_to_string(l.settings()).unwrap();
        sys.calls.borrow_mut().clear();
        let set = [("NERVE_CENTER_LISTEN", "0.0.0.0:9443".to_string())];
        let mut out = Vec::new();
        install(&l, &sys, &download(d.path(), "1.0.0"), &set, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert_eq!(crate::owner::read(&l.state).unwrap(), token);
        let after = std::fs::read_to_string(l.settings()).unwrap();
        assert!(
            after.contains("NERVE_CENTER_LISTEN=0.0.0.0:9443"),
            "{after}"
        );
        let harness = |f: &str| setting_in(f, "NERVE_CENTER_HARNESS_TOKEN");
        assert_eq!(harness(&after), harness(&before));
        assert_eq!(sys.firewall.get(), Some(9443));
        assert_eq!(sys.calls()[0], "stop");
        assert!(out.contains("to install over it"), "{out}");
        // A value systemd would misread is refused on Windows too: the
        // file reads the same on both.
        let e = install(
            &l,
            &sys,
            &download(d.path(), "1.0.0"),
            &[("NERVE_CENTER_NAME", "a\\b".into())],
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(e.contains("NERVE_CENTER_NAME"), "{e}");
    }

    /// `set` writes the setting in place of its line in `center.env`,
    /// keeps the others, and restarts the running service; a new node port
    /// takes the firewall rule along. Beyond loopback it says that the
    /// firewall rule covers the node port only, and how to let the other
    /// port in.
    #[test]
    fn set_writes_the_setting_restarts_the_service_and_moves_the_firewall_rule() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        let before = std::fs::read_to_string(l.settings()).unwrap();
        sys.calls.borrow_mut().clear();
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
        assert_eq!(sys.calls(), ["stop", "start"]);
        assert_eq!(sys.firewall.get(), Some(7443), "the node port's rule stays");
        assert_eq!(sys.service.get(), Some(true));
        let out = String::from_utf8(out).unwrap();
        let host = crate::center::host_name();
        for want in [
            "restarted the service nerve-center\n",
            &format!("  Web UI      https://{host}:7480\n"),
            "uses TLS with the center's self-signed certificate",
            "The Windows Firewall rule \"Nerve center\" lets in the node port only",
            "-LocalPort 7480",
            &format!("-Program '{}'", l.bin.display()),
        ] {
            assert!(out.contains(want), "{want}: {out}");
        }
        // A new node port: the firewall rule follows it.
        sys.calls.borrow_mut().clear();
        let mut out = Vec::new();
        set(&l, &sys, Some("listen"), Some("0.0.0.0:9443"), &mut out).unwrap();
        assert_eq!(
            sys.calls(),
            [
                format!("put_firewall {} 9443", l.bin.display()),
                "stop".into(),
                "start".into()
            ]
        );
        assert_eq!(sys.firewall.get(), Some(9443));
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("the node port 9443 now"), "{out}");
        // MCP on loopback needs no rule and no TLS; a stopped service is
        // not started.
        sys.service.set(Some(false));
        sys.calls.borrow_mut().clear();
        let mut out = Vec::new();
        set(&l, &sys, Some("mcp"), Some("127.0.0.1:7491"), &mut out).unwrap();
        assert!(sys.calls().is_empty(), "{:?}", sys.calls());
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("the center takes it at its next start\n"),
            "{out}"
        );
        assert!(
            out.contains("  Harnesses   http://127.0.0.1:7491/mcp\n"),
            "{out}"
        );
        assert!(!out.contains("Firewall") && !out.contains("TLS"), "{out}");
        let file = std::fs::read_to_string(l.settings()).unwrap();
        let harness = |f: &str| setting_in(f, "NERVE_CENTER_HARNESS_TOKEN");
        assert_eq!(harness(&file), harness(&before));
        // `set` alone lists them, as an administrator runs it.
        let mut out = Vec::new();
        set(&l, &sys, None, None, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("  listen       0.0.0.0:9443\n"), "{out}");
        assert!(out.contains("  mcp          127.0.0.1:7491\n"), "{out}");
        assert!(
            out.contains("Next  Change one:  nerve-center set <name> <value>\n"),
            "{out}"
        );
        assert!(
            out.contains("Note  Run these commands in an administrator's terminal.\n"),
            "{out}"
        );
    }

    /// A bad value, a caller without an administrator's rights and a
    /// machine without the service change nothing; a center that does not
    /// start again on the new value is said with how to put back the old.
    #[test]
    fn set_refuses_before_anything_changes() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        let before = std::fs::read_to_string(l.settings()).unwrap();
        sys.calls.borrow_mut().clear();
        for (name, bad) in [("ui", "0.0.0.0"), ("mcp", "stdio"), ("listen", "9443")] {
            let e = set(&l, &sys, Some(name), Some(bad), &mut Vec::new()).unwrap_err();
            assert!(e.starts_with(&format!("{name} {bad:?}: ")), "{e}");
        }
        let mut not_admin = Fake::new();
        not_admin.admin = false;
        let e = set(
            &l,
            &not_admin,
            Some("ui"),
            Some("0.0.0.0:7480"),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(e.contains("Run as administrator"), "{e}");
        assert_eq!(std::fs::read_to_string(l.settings()).unwrap(), before);
        assert!(sys.calls().is_empty() && not_admin.calls().is_empty());
        assert_eq!(sys.firewall.get(), Some(7443));
        let e = set(
            &layout(&d.path().join("none")),
            &Fake::new(),
            None,
            None,
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(e, NOT_INSTALLED);
        sys.starts.set(false);
        let e = set(&l, &sys, Some("ui"), Some("0.0.0.0:7480"), &mut Vec::new()).unwrap_err();
        assert!(
            e.ends_with(
                "`nerve-center set ui 127.0.0.1:7480` in an administrator's terminal puts back the value before"
            ),
            "{e}"
        );
    }

    /// Without an administrator's rights nothing changes, and the refusal
    /// says how to get them.
    #[test]
    fn the_service_commands_need_an_administrator() {
        let d = tempfile::tempdir().unwrap();
        let mut sys = Fake::new();
        sys.admin = false;
        let l = layout(d.path());
        let e = install(&l, &sys, &download(d.path(), "1.0.0"), &[], &mut Vec::new()).unwrap_err();
        assert!(e.contains("Run as administrator"), "{e}");
        assert!(!e.contains("sudo"), "{e}");
        assert!(uninstall(&l, &sys, false, &mut Vec::new()).is_err());
        assert!(sys.calls().is_empty());
        assert!(sys.secured.borrow().is_empty());
        assert!(!l.state.exists());
    }

    /// Uninstall removes the service, its firewall rule and the program and
    /// keeps the folders for the administrators alone; with purge they go.
    #[test]
    fn uninstall_removes_the_service_and_keeps_or_deletes_the_folders() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        let mut out = Vec::new();
        uninstall(&l, &sys, false, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert_eq!(sys.service.get(), None);
        assert_eq!(sys.firewall.get(), None);
        assert!(!l.bin.exists());
        assert!(l.state.join(crate::owner::FILE).exists());
        let admins = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)".to_string();
        assert_eq!(sys.dacl_of(&l.state), Some(admins.clone()));
        assert_eq!(sys.dacl_of(&l.settings_dir), Some(admins));
        assert!(
            out.contains("only administrators can open them now"),
            "{out}"
        );
        assert!(out.contains("removed the Windows Firewall rule"), "{out}");
        assert!(!sys.event_source.get());
        assert!(out.contains("removed the source nerve-center"), "{out}");
        let dir = l.bin.parent().unwrap().display().to_string();
        assert!(!sys.path.borrow().contains(&dir), "{}", sys.path.borrow());
        assert!(out.contains("off the machine's Path"), "{out}");
        let mut out = Vec::new();
        uninstall(&l, &sys, true, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(!l.state.exists() && !l.settings_dir.exists());
        assert!(!d.path().join("ProgramData/nerve-center").exists());
        assert!(out.contains("deleted"), "{out}");
        let mut out = Vec::new();
        uninstall(&l, &sys, true, &mut out).unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("nothing to uninstall"),
        );
    }

    /// An uninstall run from the installed program moves it aside for
    /// Windows to delete; the next install clears what is left.
    #[test]
    fn a_program_windows_holds_moves_aside() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        sys.held.borrow_mut().push(l.bin.clone());
        let mut out = Vec::new();
        uninstall(&l, &sys, false, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("Windows deletes the file at its next start"),
            "{out}"
        );
        let aside = l.bin.with_file_name(format!("{ASIDE}x.del"));
        assert!(aside.exists());
        sys.held.borrow_mut().clear();
        install(&l, &sys, &download(d.path(), "1.0.0"), &[], &mut Vec::new()).unwrap();
        assert!(!aside.exists());
    }

    /// Update replaces the program and restarts the service; an older or
    /// foreign program is refused before anything stops; one that does not
    /// start is replaced by the old one again.
    #[tokio::test]
    async fn update_replaces_the_program_and_puts_it_back_when_it_fails() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        let new = d.path().join("new.exe");
        std::fs::write(&new, "nerve-center 1.1.0\n").unwrap();
        sys.calls.borrow_mut().clear();
        let mut out = Vec::new();
        update(&l, &sys, Some(&new), &mut out).await.unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("replaced nerve-center 1.0.0 with 1.1.0"),
            "{out}"
        );
        assert_eq!(
            std::fs::read_to_string(&l.bin).unwrap(),
            "nerve-center 1.1.0\n"
        );
        assert_eq!(sys.calls()[..2], ["stop", "start"]);
        assert!(!staged(&l.bin).exists() && !previous(&l.bin).exists());
        // Older, or another program: refused, the service left running.
        std::fs::write(&new, "nerve-center 1.0.5\n").unwrap();
        sys.calls.borrow_mut().clear();
        let e = update(&l, &sys, Some(&new), &mut Vec::new())
            .await
            .unwrap_err();
        assert!(e.contains("older than the installed 1.1.0"), "{e}");
        std::fs::write(&new, "nerve-node 9.0.0\n").unwrap();
        let e = update(&l, &sys, Some(&new), &mut Vec::new())
            .await
            .unwrap_err();
        assert!(e.contains("is not nerve-center"), "{e}");
        assert!(sys.calls().is_empty());
        assert!(!staged(&l.bin).exists());
        // One that does not start: the old one runs again.
        std::fs::write(&new, "nerve-center 1.2.0 broken\n").unwrap();
        let e = update(&l, &sys, Some(&new), &mut Vec::new())
            .await
            .unwrap_err();
        assert!(e.contains("the old one runs again"), "{e}");
        assert_eq!(
            std::fs::read_to_string(&l.bin).unwrap(),
            "nerve-center 1.1.0\n"
        );
        assert_eq!(sys.service.get(), Some(true));
        // The steps reach the center's log.
        let log = std::fs::read_to_string(nerve_transport::log::file_in(&l.state)).unwrap();
        assert!(
            log.contains("replaced nerve-center 1.0.0 with 1.1.0"),
            "{log}"
        );
        // Nothing installed: nothing to update.
        let other = layout(&d.path().join("other"));
        let e = update(&other, &Fake::new(), Some(&new), &mut Vec::new())
            .await
            .unwrap_err();
        assert_eq!(e, NOT_INSTALLED);
    }

    /// A new program that names other settings for the service gives them
    /// to it before it starts, and the old ones go back with the old
    /// program (node-5); the service restarts after every failure, a stop
    /// with an error too (arch-1).
    #[tokio::test]
    async fn update_gives_the_service_the_new_program_s_settings() {
        let all = service_settings();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].0, SERVICE_NAME);
        assert_eq!(all[0].1.restart_secs, [5, 5, 60]);
        assert!(all[0].1.restart_on_error_stop);
        assert_eq!(all[0].1.privileges, ["SeChangeNotifyPrivilege"]);
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        let mut more = service_settings();
        more[0].1.privileges.push("SeBackupPrivilege".into());
        let new = d.path().join("new.exe");
        let said = nerve_service::win::service::settings_text(&more);
        let text = |v: &str| format!("nerve-center {v}\n{said}\n");
        std::fs::write(&new, text("1.1.0 broken")).unwrap();
        sys.calls.borrow_mut().clear();
        let e = update(&l, &sys, Some(&new), &mut Vec::new())
            .await
            .unwrap_err();
        assert!(e.contains("the old one runs again"), "{e}");
        let wanted = "configure nerve-center SeChangeNotifyPrivilege,SeBackupPrivilege";
        assert_eq!(
            sys.calls(),
            [
                "stop",
                wanted,
                "start",
                "stop",
                "configure nerve-center SeChangeNotifyPrivilege",
                "start"
            ]
        );
        std::fs::write(&new, text("1.1.0")).unwrap();
        sys.calls.borrow_mut().clear();
        update(&l, &sys, Some(&new), &mut Vec::new()).await.unwrap();
        assert_eq!(sys.calls()[..3], ["stop", wanted, "start"]);
    }

    /// The start checks the settings folder and the state folder, both,
    /// settings first, and stops at the first refusal (round 4,
    /// correctness 1).
    #[test]
    fn the_start_checks_both_folders_and_stops_at_a_refusal() {
        let l = layout(Path::new("/x"));
        let seen = std::cell::RefCell::new(Vec::new());
        check_folders(&l, |d| {
            seen.borrow_mut().push(d.to_path_buf());
            Ok(())
        })
        .unwrap();
        assert_eq!(*seen.borrow(), [l.settings_dir.clone(), l.state.clone()]);
        seen.borrow_mut().clear();
        let e = check_folders(&l, |d| {
            seen.borrow_mut().push(d.to_path_buf());
            Err("no".into())
        })
        .unwrap_err();
        assert_eq!(e, "no");
        assert_eq!(
            seen.borrow().as_slice(),
            std::slice::from_ref(&l.settings_dir)
        );
        assert!(
            check_folders(&l, |d| if d == l.state {
                Err("no".into())
            } else {
                Ok(())
            })
            .is_err()
        );
    }

    /// A start the manager refuses at once (the center ended on a setting
    /// before it reached the manager) names the log that says why, at the
    /// install as at an update (round 3, correctness 1).
    #[tokio::test]
    async fn a_refused_start_names_the_log() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = layout(d.path());
        let log = nerve_transport::log::file_in(&l.state)
            .display()
            .to_string();
        sys.refuses.set(true);
        let e = install(&l, &sys, &download(d.path(), "1.0.0"), &[], &mut Vec::new()).unwrap_err();
        assert!(e.contains("did not respond in time"), "{e}");
        assert!(e.ends_with(&format!("; {log} says why")), "{e}");
        sys.refuses.set(false);
        install(&l, &sys, &download(d.path(), "1.0.0"), &[], &mut Vec::new()).unwrap();
        let new = d.path().join("new.exe");
        std::fs::write(&new, "nerve-center 1.1.0\n").unwrap();
        sys.refuses.set(true);
        let e = update(&l, &sys, Some(&new), &mut Vec::new())
            .await
            .unwrap_err();
        assert!(e.contains(&format!("{log} says why")), "{e}");
    }

    /// A restore stops the service and starts it again, whether it did its
    /// work or not.
    #[test]
    fn a_restore_into_the_service_starts_it_again_whatever_happens() {
        let sys = Fake::new();
        sys.service.set(Some(true));
        let mut out = Vec::new();
        let r = stopped_for(&sys, &mut out, &|_| Err("a bad passphrase".into()));
        assert_eq!(r.unwrap_err(), "a bad passphrase");
        assert_eq!(sys.calls(), ["stop", "start"]);
        assert_eq!(sys.service.get(), Some(true));
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("started the service nerve-center again"),
            "{out}"
        );
    }

    /// The service takes the settings the file sets, as systemd reads it,
    /// and nothing but the center's.
    /// The installed folder is found whichever way an administrator names
    /// it, so a restore stops the service for it and leaves its access
    /// list alone (round 1, correctness 2).
    #[test]
    fn the_installed_state_folder_is_found_by_any_spelling() {
        let d = tempfile::tempdir().unwrap();
        let l = layout(d.path());
        std::fs::create_dir_all(&l.state).unwrap();
        let root = d.path().display().to_string();
        assert!(l.is_state(&l.state));
        assert!(l.is_state(&PathBuf::from(format!(
            "{root}/ProgramData/nerve-center/state/"
        ))));
        assert!(l.is_state(&PathBuf::from(format!(
            "{root}/ProgramData/nerve-center/../nerve-center/state"
        ))));
        assert!(!l.is_state(&PathBuf::from(format!("{root}/ProgramData/nerve-center"))));
        assert!(!l.is_state(&l.settings_dir));
    }

    /// A settings file that is not there starts the service with its
    /// defaults, as the Linux unit does; one that cannot be read does not
    /// (round 1, correctness 3).
    #[test]
    fn a_missing_settings_file_holds_no_setting() {
        let path = Path::new("center.env");
        let missing = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert_eq!(settings_text(Err(missing), path).unwrap(), "");
        let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let e = settings_text(Err(denied), path).unwrap_err();
        assert!(e.starts_with("center.env: "), "{e}");
        assert_eq!(settings_text(Ok("A=b".into()), path).unwrap(), "A=b");
    }

    #[test]
    fn the_service_takes_its_settings_from_its_file() {
        let l = layout(Path::new("C:/"));
        let text = l.settings_text("nrv_abc", &[("NERVE_CENTER_NAME", "lab".into())]);
        assert_eq!(
            settings_env(&text).unwrap(),
            [
                (
                    "NERVE_CENTER_HARNESS_TOKEN".to_string(),
                    "nrv_abc".to_string()
                ),
                ("NERVE_CENTER_NAME".to_string(), "lab".to_string()),
            ]
        );
        assert_eq!(
            settings_env("  NERVE_CENTER_UI = 127.0.0.1:7490 \n\n# x=y\n").unwrap(),
            [("NERVE_CENTER_UI".to_string(), "127.0.0.1:7490".to_string())]
        );
        // An old name is passed on, for the center to refuse by name.
        assert_eq!(settings_env("NERVE_LOG=debug").unwrap()[0].0, "NERVE_LOG");
        for bad in ["PATH=C:\\x", "NERVE_CENTER_UI", "nerve_center_ui=off"] {
            let e = settings_env(bad).unwrap_err();
            assert!(e.starts_with("line 1: "), "{bad}: {e}");
        }
    }

    /// The port of the firewall rule is the node port the settings name;
    /// the rule is for the program and that port only.
    #[test]
    fn the_firewall_rule_is_for_the_node_port_only() {
        assert_eq!(node_port(""), 7443);
        assert_eq!(node_port("#NERVE_CENTER_LISTEN=0.0.0.0:1\n"), 7443);
        assert_eq!(node_port("NERVE_CENTER_LISTEN=0.0.0.0:9443\n"), 9443);
        assert_eq!(node_port("NERVE_CENTER_LISTEN=[::]:9444\n"), 9444);
        let args = firewall_args(
            Path::new("C:\\Program Files\\Nerve\\nerve-center.exe"),
            7443,
        );
        assert!(args.contains(&"dir=in".to_string()));
        assert!(args.contains(&"localport=7443".to_string()));
        assert!(args.contains(&"protocol=TCP".to_string()));
        assert!(args.contains(&"program=C:\\Program Files\\Nerve\\nerve-center.exe".to_string()));
        // No rule for the web UI's or MCP's ports, nor for every port.
        assert_eq!(
            args.iter().filter(|a| a.starts_with("localport=")).count(),
            1
        );
    }
}
