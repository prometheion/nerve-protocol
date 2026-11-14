//! The Windows calls behind `install`, `update` and `uninstall`
//! ([`crate::winsvc::WinSystem`]), and the center as the service the
//! service control manager starts ([`serve`]). The calls themselves are
//! nerve_service's (`nerve_service::win`).

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use nerve_service::eventlog::{CENTER_SOURCE, CENTER_SOURCE_KEY};
use nerve_service::win::dispatch::{self, Events, Served};
use nerve_service::win::service::{self as svc, Settings, Spec};
use nerve_transport::log::Level;

use crate::service::Layout;
use crate::winsvc::{ASIDE, FIREWALL_RULE, SERVICE_NAME, WinSystem, firewall_args};

/// A program of Windows itself, by its whole path: a program of that name
/// in the folder this one started from (the downloads, as an administrator)
/// is never run, nor one in a folder the `SystemRoot` variable names, which
/// the account's unelevated programs may set (round 6, security 1).
pub fn system_program(name: &str) -> PathBuf {
    nerve_service::win::folders::system32().join(name)
}

/// This machine.
pub struct WinHost;

impl WinSystem for WinHost {
    fn is_admin(&self) -> bool {
        nerve_service::win::sid::is_admin()
    }

    fn secure(&self, dir: &Path, sddl: &str) -> Result<(), String> {
        nerve_service::win::dacl::private_folder(dir, sddl)
    }

    fn service(&self) -> Result<Option<bool>, String> {
        Ok(svc::state(SERVICE_NAME)?.map(|s| s.state != "stopped" && s.state != "failed"))
    }

    fn put_service(&self, layout: &Layout) -> Result<(), String> {
        let settings = crate::winsvc::service_settings();
        svc::put(&Spec {
            name: SERVICE_NAME,
            shown: "Nerve center",
            about: concat!(
                "Pairs Nerve nodes and offers their machines to agents over MCP. ",
                env!("CARGO_PKG_REPOSITORY")
            ),
            line: &crate::winsvc::command_line(layout),
            logon: None,
            settings: &settings[0].1,
        })
    }

    fn start(&self) -> Result<(), String> {
        svc::start(SERVICE_NAME)
    }

    fn stop(&self) -> Result<(), String> {
        svc::stop(SERVICE_NAME)
    }

    fn delete_service(&self) -> Result<(), String> {
        svc::delete(SERVICE_NAME)
    }

    fn wait_running(&self, layout: &Layout) -> Result<(), String> {
        let log = nerve_transport::log::file_in(&layout.state);
        svc::wait_running(SERVICE_NAME, &log.display().to_string())
    }

    fn put_firewall(&self, layout: &Layout, port: u16) -> Result<(), String> {
        let _ = self.delete_firewall()?;
        netsh(&firewall_args(&layout.bin, port)).map(|_| ())
    }

    fn delete_firewall(&self) -> Result<bool, String> {
        let name = format!("name={FIREWALL_RULE}");
        // netsh says "No rules match" and fails where there is none.
        let listed = std::process::Command::new(system_program("netsh.exe"))
            .args(["advfirewall", "firewall", "show", "rule", &name])
            .output()
            .map_err(|e| format!("netsh: {e}"))?;
        if !listed.status.success() {
            return Ok(false);
        }
        netsh(&[
            "advfirewall".into(),
            "firewall".into(),
            "delete".into(),
            "rule".into(),
            name,
        ])?;
        Ok(true)
    }

    fn put_event_source(&self, layout: &Layout) -> Result<(), String> {
        nerve_service::win::event::put_source(CENTER_SOURCE_KEY, CENTER_SOURCE, &layout.bin)
    }

    fn delete_event_source(&self) -> Result<bool, String> {
        nerve_service::win::event::delete_source(CENTER_SOURCE_KEY, CENTER_SOURCE)
    }

    fn put_on_path(&self, dir: &Path) -> Result<bool, String> {
        nerve_service::win::machine_path::add(dir)
    }

    fn remove_from_path(&self, dir: &Path) -> Result<bool, String> {
        nerve_service::win::machine_path::remove(dir)
    }

    fn version_of(&self, program: &Path) -> Result<String, String> {
        output_of(program, &["--version"])
    }

    fn settings_of(&self, program: &Path) -> Result<String, String> {
        output_of(program, &[nerve_service::SERVICE_FILES])
    }

    fn configure_service(&self, name: &str, s: &Settings) -> Result<(), String> {
        svc::configure(name, s)
    }

    fn remove_program(&self, path: &Path) -> Result<bool, String> {
        nerve_service::win::update::remove_program(path, ASIDE)
    }
}

/// What `<program> <args>` prints, run without the administrators' rights
/// and with a bare environment (nerve_service::win::restricted::output_of).
fn output_of(program: &Path, args: &[&str]) -> Result<String, String> {
    let line = format!("{} {}", program.display(), args.join(" "));
    let (code, out) =
        nerve_service::win::restricted::output_of(program, args, Duration::from_secs(30))
            .map_err(|e| format!("{line}: {e}"))?;
    if code != 0 {
        return Err(format!("{line}: exit code {code}"));
    }
    Ok(String::from_utf8_lossy(&out).trim().to_string())
}

/// Runs `netsh` with `args`; its output, or an error with what it said.
fn netsh(args: &[String]) -> Result<String, String> {
    let o = std::process::Command::new(system_program("netsh.exe"))
        .args(args)
        .output()
        .map_err(|e| format!("netsh: {e}"))?;
    let said = String::from_utf8_lossy(&o.stdout).trim().to_string();
    if !o.status.success() {
        return Err(format!("netsh {}: {said}", args.join(" ")));
    }
    Ok(said)
}

/// Puts the settings of the service's `center.env` into this process's
/// environment, in place of every `NERVE_` variable it inherited: the
/// installed center reads its settings from that file only, as systemd
/// gives the Linux one its own. MCP is over HTTP unless the file says
/// otherwise. Called first in `main`, while the process has one thread.
/// The settings and the state folder must still be the administrators'
/// folders the install made: one put in their place since (another
/// account's, or a link) is refused, not read (round 3, security 2).
pub fn take_settings(layout: &Layout) -> Result<(), String> {
    crate::winsvc::check_folders(layout, nerve_service::win::dacl::admins_folder)?;
    let path = layout.settings();
    let text = crate::winsvc::settings_text(std::fs::read_to_string(&path), &path)?;
    let set = crate::winsvc::settings_env(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let inherited: Vec<_> = std::env::vars_os()
        .map(|(k, _)| k)
        .filter(|k| {
            k.to_string_lossy()
                .to_ascii_uppercase()
                .starts_with("NERVE_")
        })
        .collect();
    // SAFETY: `main` calls this before it starts another thread.
    unsafe {
        for k in inherited {
            std::env::remove_var(k);
        }
        std::env::set_var("NERVE_CENTER_MCP", "http");
        for (k, v) in set {
            std::env::set_var(k, v);
        }
    }
    Ok(())
}

/// `nerve-center service`: the center as the service, until the service
/// control manager stops it. A center that does not start writes why to
/// its log, which the install's wait names. Its start, its stop and its
/// failures go to the Windows Event Log too, as [`CENTER_SOURCE`].
pub fn serve(args: crate::config::Args) -> ExitCode {
    nerve_transport::log::install(args.log.unwrap_or_default(), false);
    let log = nerve_transport::log::file_in(&args.state_dir());
    let events = Events {
        source: CENTER_SOURCE,
        what: "Nerve center",
        log: log.clone(),
    };
    let body = Box::new(move || {
        let r = tokio::runtime::Runtime::new()
            .map_err(|e| e.to_string())
            .and_then(|rt| rt.block_on(crate::server::run(args)));
        // Before the manager hears it stopped, so the log says why by then.
        if let Err(e) = &r {
            let _ = nerve_transport::log::Log::append_entry(
                &log,
                Level::Error,
                &format!("the service stopped: {e}"),
            );
        }
        r
    });
    match dispatch::serve(SERVICE_NAME, body, Some(events)) {
        Ok(Served::Ran(None)) => ExitCode::SUCCESS,
        Ok(Served::Ran(Some(_))) => ExitCode::FAILURE,
        Ok(Served::NotAService) => {
            eprintln!(
                "nerve-center: `service` is how Windows starts the installed center; `nerve-center status` says how it runs"
            );
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("nerve-center: {e}");
            ExitCode::FAILURE
        }
    }
}
