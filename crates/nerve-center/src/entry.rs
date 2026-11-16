//! The `nerve-center` command line (`main`): the center a harness starts,
//! and the owner's and the administrator's commands. Both programs run it:
//! `nerve-center`, and the app's `nerve` behind its hidden first word
//! `__center` ([`crate::edition`]). Logs go to stderr and to the log file in
//! the state folder, never to stdout, which carries MCP. `install`, `set`,
//! `update` and `uninstall` (as root on Linux) say their steps on stdout
//! instead, as `owner-token` says the token.

use clap::FromArgMatches;
use nerve_service::out::{Said, Style};

/// Runs `nerve-center` with the command line `args`, the program's name
/// first: the `nerve-center` program's `main`, and the app's `nerve` with
/// its hidden first word `__center` taken off (or started as the link
/// `nerve-center`).
pub fn main(argv: Vec<std::ffi::OsString>) -> std::process::ExitCode {
    use crate::config::Cmd;
    let layout = crate::service::Layout::system();
    let is_service = cfg!(windows) && crate::config::starts_the_service(&argv);
    // The Windows service reads its settings from its own file, as systemd
    // gives the Linux one its own: before anything reads the environment.
    #[cfg(windows)]
    if is_service && let Err(e) = crate::win_host::take_settings(&layout) {
        return refuse(&layout, is_service, &e.to_string());
    }
    // A setting given by an old name would be dropped without a word.
    if let Err(e) = crate::config::refuse_old_names(|k| std::env::var(k).ok(), &layout.settings()) {
        return refuse(&layout, is_service, &e.to_string());
    }
    let matches = match crate::config::command().try_get_matches_from(&argv) {
        Ok(m) => m,
        // `--help` and `--version` end here too, with their text.
        Err(e) if !is_service => e.exit(),
        Err(e) => return refuse(&layout, is_service, &e.to_string()),
    };
    let args = match crate::config::Args::from_arg_matches(&matches) {
        Ok(a) => a,
        Err(e) if !is_service => e.exit(),
        Err(e) => return refuse(&layout, is_service, &e.to_string()),
    };
    crate::attach::set_desktop_user(args.desktop_user_sid.as_deref());
    // `--json` is for the commands the desktop app runs (crate::json).
    if args.json && !crate::json::takes(args.cmd.as_ref()) {
        return answered(true, &[], Err(crate::json::ONLY_FOR.into()));
    }
    if args.json {
        crate::json::start();
    }
    if args.cmd.as_ref().is_some_and(Cmd::runs_the_service) {
        #[cfg(windows)]
        return crate::win_host::serve(args);
        #[cfg(not(windows))]
        return failed(
            "`service` is how Windows starts the installed center; on Linux systemd starts `nerve-center` itself",
        );
    }
    // A double-click in Explorer installs the center, as the desktop app
    // installs the node: it starts itself again as `install` with the
    // administrators' rights (the UAC prompt), in a window that stays open
    // until it was read (#213).
    #[cfg(windows)]
    {
        use std::io::IsTerminal;
        if args.cmd.is_none()
            && crate::config::double_clicked(
                argv.len() - 1,
                std::io::stdin().is_terminal(),
                nerve_service::win::console::alone(),
            )
        {
            return install_by_double_click(&argv);
        }
    }
    // An administrator's command takes the proxy and the trusted
    // certificates from the machine, not from the variables of the account
    // that other programs of it may set (round 7, security 2). No thread
    // runs yet.
    #[cfg(windows)]
    if args.cmd.is_some() {
        // SAFETY: nothing here has started another thread.
        unsafe { nerve_service::win::folders::take_machine_environment() };
    }
    // `backup`, `restore`, `owner-token` and `status` are the owner's, run
    // by hand: no log, no server; on the installed center's folder where it
    // is installed.
    if let Some(cmd) = args.cmd.as_ref().filter(|c| !c.is_service()) {
        #[cfg(windows)]
        let elevated = nerve_service::win::sid::is_admin();
        #[cfg(not(windows))]
        let elevated = false;
        if let Err(e) =
            crate::config::refuse_state_variable(&crate::config::settings_given(&matches), elevated)
        {
            return answered(args.json, &[], Err(e.to_string()));
        }
        let state = args.owner_state_dir();
        let settle = crate::service::settle_user;
        let mut stdout = std::io::stdout();
        let mut text = Vec::new();
        let mut said = (!args.json).then(|| Said::new(&mut stdout, Style::stdout()));
        let out: &mut dyn std::io::Write = match said.as_mut() {
            Some(s) => s,
            None => &mut text,
        };
        let done = match cmd {
            // What `update` asks the new program (or, when it is the same
            // one, the installed one), which it runs as root with an
            // empty environment: the files of its service.
            // On Windows the settings of its service, which `update` gives
            // the service (nerve_service::win::update).
            crate::config::Cmd::ServiceFiles => {
                #[cfg(windows)]
                println!("{}", crate::winsvc::service_files_text());
                #[cfg(not(windows))]
                println!(
                    "{}",
                    crate::service::service_files_text(&crate::service::Layout::system())
                );
                Ok(())
            }
            crate::config::Cmd::OwnerToken { new } => {
                settle(&state).and_then(|_| crate::owner::run(&state, *new, out))
            }
            Cmd::Status => crate::service::status(&layout, &state, &args.ui, &args.mcp, out),
            // The running center answers these over its attach socket or
            // pipe, as the folder's owner asks it.
            Cmd::Pair | Cmd::Nodes { .. } | Cmd::Token(_) => {
                let installed = layout.installed() && layout.is_state(&state);
                settle(&state).and_then(|_| {
                    owner_runtime()?.block_on(crate::owner_calls::run(&state, cmd, installed, out))
                })
            }
            Cmd::Log {
                follow,
                last,
                problems,
            } => settle(&state).and_then(|_| {
                owner_runtime()?.block_on(crate::owner_calls::log(
                    &state, *follow, *last, *problems, out,
                ))
            }),
            // A restore into the running service stops it first and starts
            // it again after (as root, before this one becomes the
            // folder's owner).
            Cmd::Restore { .. } => {
                crate::service::with_service_stopped(&layout, &state, out, &|out, restarts| {
                    crate::backup::run(&state, cmd, &settle, restarts, out)
                })
            }
            _ => crate::backup::run(&state, cmd, &settle, false, out),
        };
        if let Some(s) = said {
            let _ = s.finish(None);
        }
        let code = answered(args.json, &text, done);
        // `service-files` is asked by `update`, never by a person.
        if !matches!(cmd, Cmd::ServiceFiles) && !args.json {
            hold_own_window();
        }
        return code;
    }
    // The level of the settings replaces this one once the state is opened.
    nerve_transport::log::install(args.log.unwrap_or_default(), true);
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            return answered(args.json, &[], Err(e.to_string()));
        }
    };
    if let Some(cmd) = args.cmd.clone() {
        let mut stdout = std::io::stdout();
        let mut text = Vec::new();
        let mut said = (!args.json).then(|| Said::new(&mut stdout, Style::stdout()));
        let out: &mut dyn std::io::Write = match said.as_mut() {
            Some(s) => s,
            None => &mut text,
        };
        let given = crate::config::settings_given(&matches);
        #[cfg(windows)]
        let elevated = nerve_service::win::sid::is_admin();
        #[cfg(not(windows))]
        let elevated = false;
        if matches!(cmd, Cmd::Install)
            && let Err(e) = crate::config::refuse_install_variables(&given, elevated)
        {
            return answered(args.json, &[], Err(e.to_string()));
        }
        // What `install` writes into the service's settings.
        let set: Vec<(&str, String)> = crate::config::INSTALL_SETTINGS
            .iter()
            .filter(|(flag, var)| given.iter().any(|g| g == flag || g == var))
            .filter_map(|(flag, var)| {
                let value = match *flag {
                    "--name" => args.name.clone(),
                    "--public-url" => args.public_url.clone(),
                    "--ui" => Some(args.ui.clone()),
                    "--mcp" => Some(args.mcp.setting()),
                    _ => Some(args.listen.clone()),
                };
                value.map(|v| (*var, v))
            })
            .collect();
        let done = rt.block_on(crate::service::execute(cmd, &given, &set, out));
        if let Some(s) = said {
            let _ = s.finish(None);
        }
        let code = answered(args.json, &text, done);
        if !args.json {
            hold_own_window();
        }
        return code;
    }
    // Started by hand at a terminal, it would seem to hang: it waits for a
    // harness on stdin.
    {
        use std::io::IsTerminal;
        if let Some(say) = crate::config::terminal_notice(
            &args.mcp,
            std::io::stdin().is_terminal(),
            &crate::config::started_as(argv.first().cloned()),
        ) {
            eprintln!("{say}");
        }
    }
    let ran = rt.block_on(crate::server::run(args));
    // A center stopped by a signal while its harness still holds the pipe
    // open has a read of stdin waiting on a runtime thread, which would hold
    // up the runtime's end for as long as the pipe stays open.
    rt.shutdown_timeout(std::time::Duration::from_secs(1));
    match ran {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Keeps a window of its own open until the person has read it: the one
/// the double-click's `install` runs in, which closes with the program.
fn hold_own_window() {
    #[cfg(windows)]
    {
        use std::io::IsTerminal;
        if std::io::stdin().is_terminal() && nerve_service::win::console::alone() {
            nerve_service::win::console::hold(&mut std::io::stdout());
        }
    }
}

/// What a double-click does: `install` again with the administrators'
/// rights, in a window of its own; this window closes once that started.
#[cfg(windows)]
fn install_by_double_click(args: &[std::ffi::OsString]) -> std::process::ExitCode {
    let started = std::env::current_exe()
        .map_err(|e| format!("this program: {e}"))
        .and_then(|exe| nerve_service::win::console::run_elevated(&exe, "install"));
    match started {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            let code = failed(&format!(
                "a double-click installs the center as a service, which needs the administrator rights: {e}. Or run `{} install` in a terminal opened with Run as administrator.",
                crate::config::started_as(args.first().cloned())
            ));
            nerve_service::win::console::hold(&mut std::io::stderr());
            code
        }
    }
}

/// The runtime of an owner's command that asks the running center.
fn owner_runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("cannot start the runtime: {e}"))
}

/// The exit code of a command that ended with `done`, and with `--json`
/// its answer on stdout (crate::json), the lines it printed in `text`.
fn answered(json: bool, text: &[u8], done: Result<(), String>) -> std::process::ExitCode {
    if json {
        println!("{}", crate::json::answer(text, &done));
    }
    match done {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => failed(&e),
    }
}

/// Says why a command failed, in the style of both programs; its exit
/// code.
fn failed(e: &str) -> std::process::ExitCode {
    eprintln!(
        "{}",
        nerve_service::out::error("nerve-center", e, Style::stderr())
    );
    std::process::ExitCode::FAILURE
}

fn refuse(layout: &crate::service::Layout, is_service: bool, why: &str) -> std::process::ExitCode {
    crate::service::refuse_start(&layout.state, is_service, why);
    std::process::ExitCode::FAILURE
}
