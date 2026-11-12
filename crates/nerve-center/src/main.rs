//! `nerve-center`: started by a harness from its MCP configuration. Logs go to
//! stderr and to the log file in the state folder, never to stdout, which
//! carries MCP. `install`, `update` and `uninstall` (as root on Linux) say
//! their steps on stdout instead, as `owner-token` says the token.

use clap::{CommandFactory, FromArgMatches};

fn main() -> std::process::ExitCode {
    use nerve_center::config::Cmd;
    let layout = nerve_center::service::Layout::system();
    let is_service = cfg!(windows) && std::env::args_os().nth(1).is_some_and(|a| a == "service");
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
    let matches = match nerve_center::config::Args::command().try_get_matches() {
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
    if args.cmd == Some(Cmd::Service) {
        #[cfg(windows)]
        return nerve_center::win_host::serve(args);
        #[cfg(not(windows))]
        {
            eprintln!(
                "nerve-center: `service` is how Windows starts the installed center; on Linux systemd starts `nerve-center` itself"
            );
            return std::process::ExitCode::FAILURE;
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
            eprintln!("nerve-center: {e}");
            return std::process::ExitCode::FAILURE;
        }
        let state = args.owner_state_dir();
        let settle = nerve_center::service::settle_user;
        let mut out = std::io::stdout();
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
        return match done {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("nerve-center: {e}");
                std::process::ExitCode::FAILURE
            }
        };
    }
    // The level of the settings replaces this one once the state is opened.
    nerve_transport::log::install(args.log.unwrap_or_default(), true);
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("nerve-center: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    if let Some(cmd) = args.cmd.clone() {
        let mut out = std::io::stdout();
        let given = nerve_center::config::settings_given(&matches);
        #[cfg(windows)]
        let elevated = nerve_service::win::sid::is_admin();
        #[cfg(not(windows))]
        let elevated = false;
        if matches!(cmd, Cmd::Install)
            && let Err(e) = nerve_center::config::refuse_install_variables(&given, elevated)
        {
            eprintln!("nerve-center: {e}");
            return std::process::ExitCode::FAILURE;
        }
        // What `install` writes into the service's settings.
        let set: Vec<(&str, String)> = nerve_center::config::INSTALL_SETTINGS
            .iter()
            .filter(|(flag, var)| given.iter().any(|g| g == flag || g == var))
            .filter_map(|(flag, var)| {
                let value = match *flag {
                    "--name" => args.name.clone(),
                    "--public-url" => args.public_url.clone(),
                    _ => Some(args.listen.clone()),
                };
                value.map(|v| (*var, v))
            })
            .collect();
        return match rt.block_on(nerve_center::service::execute(cmd, &given, &set, &mut out)) {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("nerve-center: {e}");
                std::process::ExitCode::FAILURE
            }
        };
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

fn refuse(
    layout: &nerve_center::service::Layout,
    is_service: bool,
    why: &str,
) -> std::process::ExitCode {
    nerve_center::service::refuse_start(&layout.state, is_service, why);
    std::process::ExitCode::FAILURE
}
