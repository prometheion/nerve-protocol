//! `nerve-center`: started by a harness from its MCP configuration. Logs go to
//! stderr and to the log file in the state folder, never to stdout, which
//! carries MCP. `install`, `update` and `uninstall` (as root on Linux) say
//! their steps on stdout instead, as `owner-token` says the token.

use clap::{CommandFactory, FromArgMatches};

fn main() -> std::process::ExitCode {
    let matches = nerve_center::config::Args::command().get_matches();
    let args = nerve_center::config::Args::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    // `backup`, `restore` and `owner-token` are the owner's, run by hand: no
    // log, no server.
    if let Some(cmd) = args.cmd.as_ref().filter(|c| !c.is_service()) {
        let state = args.state_dir();
        let settle = nerve_center::service::settle_user;
        let mut out = std::io::stdout();
        let done = match cmd {
            nerve_center::config::Cmd::OwnerToken { new } => {
                settle(&state).and_then(|_| nerve_center::owner::run(&state, *new, &mut out))
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
        return match rt.block_on(nerve_center::service::execute(cmd, &given, &mut out)) {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("nerve-center: {e}");
                std::process::ExitCode::FAILURE
            }
        };
    }
    match rt.block_on(nerve_center::server::run(args)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            std::process::ExitCode::FAILURE
        }
    }
}
