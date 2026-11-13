//! `nerve-center`: started by a harness from its MCP configuration. Logs go to
//! stderr and to the log file in the state folder, never to stdout, which
//! carries MCP. `install`, `set`, `update` and `uninstall` (as root on
//! Linux) say their steps on stdout instead, as `owner-token` says the token.

use clap::FromArgMatches;
use nerve_service::out::{Said, Style};

fn main() -> std::process::ExitCode {
    use nerve_center::config::Cmd;
    let layout = nerve_center::service::Layout::system();
    let is_service = cfg!(windows) && nerve_center::config::starts_the_service(std::env::args_os());
    // The Windows service reads its settings from its own file, as systemd
    // gives the Linux one its own: before anything reads the environment.
    #[cfg(windows)]
    if is_service && let Err(e) = nerve_center::win_host::take_settings(&layout) {
        return refuse(&layout, is_service, &e.to_string());
    }
    // A setting given by an old name would be dropped without a word.
    if let Err(e) =
        nerve_center::config::refuse_old_names(|k| std::env::var(k).ok(), &layout.settings())
    {
        return refuse(&layout, is_service, &e.to_string());
    }
    let matches = match nerve_center::config::command().try_get_matches() {
        Ok(m) => m,
        // `--help` and `--version` end here too, with their text.
        Err(e) if !is_service => e.exit(),
        Err(e) => return refuse(&layout, is_service, &e.to_string()),
    };
    let args = match nerve_center::config::Args::from_arg_matches(&matches) {
        Ok(a) => a,
        Err(e) if !is_service => e.exit(),
        Err(e) => return refuse(&layout, is_service, &e.to_string()),
    };
    if args.cmd.as_ref().is_some_and(Cmd::runs_the_service) {
        #[cfg(windows)]
        return nerve_center::win_host::serve(args);
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
            && nerve_center::config::double_clicked(
                std::env::args_os().len() - 1,
                std::io::stdin().is_terminal(),
                nerve_service::win::console::alone(),
            )
        {
            return install_by_double_click();
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
        if let Err(e) = nerve_center::config::refuse_state_variable(
            &nerve_center::config::settings_given(&matches),
            elevated,
        ) {
            return failed(&e.to_string());
        }
        let state = args.owner_state_dir();
        let settle = nerve_center::service::settle_user;
        let mut stdout = std::io::stdout();
        let mut out = Said::new(&mut stdout, Style::stdout());
        let done = match cmd {
            // What `update` asks the new program (or, when it is the same
            // one, the installed one), which it runs as root with an
            // empty environment: the files of its service.
            // On Windows the settings of its service, which `update` gives
            // the service (nerve_service::win::update).
            nerve_center::config::Cmd::ServiceFiles => {
                #[cfg(windows)]
                println!("{}", nerve_center::winsvc::service_files_text());
                #[cfg(not(windows))]
                println!(
                    "{}",
                    nerve_center::service::service_files_text(
                        &nerve_center::service::Layout::system()
                    )
                );
                Ok(())
            }
            nerve_center::config::Cmd::OwnerToken { new } => {
                settle(&state).and_then(|_| nerve_center::owner::run(&state, *new, &mut out))
            }
            Cmd::Status => {
                nerve_center::service::status(&layout, &state, &args.ui, &args.mcp, &mut out)
            }
            // The running center answers these over its attach socket or
            // pipe, as the folder's owner asks it.
            Cmd::Pair | Cmd::Nodes { .. } | Cmd::Token(_) => {
                let installed = layout.installed() && layout.is_state(&state);
                settle(&state).and_then(|_| {
                    owner_runtime()?.block_on(nerve_center::owner_calls::run(
                        &state, cmd, installed, &mut out,
                    ))
                })
            }
            Cmd::Log {
                follow,
                last,
                problems,
            } => settle(&state).and_then(|_| {
                owner_runtime()?.block_on(nerve_center::owner_calls::log(
                    &state, *follow, *last, *problems, &mut out,
                ))
            }),
            // A restore into the running service stops it first and starts
            // it again after (as root, before this one becomes the
            // folder's owner).
            Cmd::Restore { .. } => {
                nerve_center::service::with_service_stopped(&layout, &state, &mut out, &|out| {
                    nerve_center::backup::run(&state, cmd, &settle, out)
                })
            }
            _ => nerve_center::backup::run(&state, cmd, &settle, &mut out),
        };
        let _ = out.finish(None);
        let code = match done {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(e) => failed(&e),
        };
        hold_own_window();
        return code;
    }
    // The level of the settings replaces this one once the state is opened.
    nerve_transport::log::install(args.log.unwrap_or_default(), true);
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            return failed(&e.to_string());
        }
    };
    if let Some(cmd) = args.cmd.clone() {
        let mut stdout = std::io::stdout();
        let mut out = Said::new(&mut stdout, Style::stdout());
        let given = nerve_center::config::settings_given(&matches);
        #[cfg(windows)]
        let elevated = nerve_service::win::sid::is_admin();
        #[cfg(not(windows))]
        let elevated = false;
        if matches!(cmd, Cmd::Install)
            && let Err(e) = nerve_center::config::refuse_install_variables(&given, elevated)
        {
            return failed(&e.to_string());
        }
        // What `install` writes into the service's settings.
        let set: Vec<(&str, String)> = nerve_center::config::INSTALL_SETTINGS
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
        let done = rt.block_on(nerve_center::service::execute(cmd, &given, &set, &mut out));
        let _ = out.finish(None);
        let code = match done {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(e) => failed(&e),
        };
        hold_own_window();
        return code;
    }
    // Started by hand at a terminal, it would seem to hang: it waits for a
    // harness on stdin.
    {
        use std::io::IsTerminal;
        if let Some(say) = nerve_center::config::terminal_notice(
            &args.mcp,
            std::io::stdin().is_terminal(),
            &nerve_center::config::started_as(std::env::args_os().next()),
        ) {
            eprintln!("{say}");
        }
    }
    let ran = rt.block_on(nerve_center::server::run(args));
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
fn install_by_double_click() -> std::process::ExitCode {
    let started = std::env::current_exe()
        .map_err(|e| format!("this program: {e}"))
        .and_then(|exe| nerve_service::win::console::run_elevated(&exe, "install"));
    match started {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            let code = failed(&format!(
                "a double-click installs the center as a service, which needs the administrator rights: {e}. Or run `{} install` in a terminal opened with Run as administrator.",
                nerve_center::config::started_as(std::env::args_os().next())
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

/// Says why a command failed, in the style of both programs; its exit
/// code.
fn failed(e: &str) -> std::process::ExitCode {
    eprintln!(
        "{}",
        nerve_service::out::error("nerve-center", e, Style::stderr())
    );
    std::process::ExitCode::FAILURE
}

fn refuse(
    layout: &nerve_center::service::Layout,
    is_service: bool,
    why: &str,
) -> std::process::ExitCode {
    nerve_center::service::refuse_start(&layout.state, is_service, why);
    std::process::ExitCode::FAILURE
}
