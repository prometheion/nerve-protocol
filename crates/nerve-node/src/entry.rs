//! What `nerve-node` does when it starts: the helpers it starts itself, then
//! one command line. The desktop app (crates/nerve-node-desktop) is the same
//! program with a window: started with arguments it runs this, so both
//! binaries behave alike.

use clap::{CommandFactory, FromArgMatches};

/// Runs the program with the process's arguments; the exit code.
pub fn main() -> i32 {
    // The exec shim is this same binary, started by the daemon for each
    // confined command. It is not a command the owner types, so it is checked
    // before clap (and stays out of `--help`).
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new(nerve_sandbox::SHIM_ARG))
    {
        return nerve_sandbox::shim_main();
    }
    // So is the helper that asks a stopped command's processes to end on
    // Windows (crate::win_stop).
    #[cfg(windows)]
    if std::env::args_os().nth(1).as_deref()
        == Some(std::ffi::OsStr::new(crate::win_stop::STOP_ARG))
    {
        return crate::win_stop::helper_main();
    }
    // So is the keyring probe that setup and install start
    // (docs/user/config.md): it answers whether the system keyring of the
    // user it runs as works.
    if std::env::args_os().nth(1).as_deref()
        == Some(std::ffi::OsStr::new(crate::keyring_setup::PROBE_ARG))
    {
        return crate::keyring_setup::probe_main();
    }
    // So is the helper that tells the node which program of root asks to
    // attach as a provider (crate::provider::check_main).
    if std::env::args_os().nth(1).as_deref()
        == Some(std::ffi::OsStr::new(crate::provider::CHECK_ARG))
    {
        return crate::provider::check_main();
    }
    // Events go to stderr. The daemon adds the log file in the state folder and
    // takes its level from `node.toml`.
    nerve_transport::log::install(nerve_transport::log::Level::Info, true);
    // Named after this program, so `--version` and the usage say which one
    // it is (crate::edition).
    let program = crate::edition::get().program;
    let matches = crate::cli::Cli::command()
        .name(program)
        .bin_name(program)
        .get_matches();
    let cli = crate::cli::Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    // An owner of the installed node, who may not open its folders, has
    // the running node run the command (crate::owner).
    if let Some(code) = crate::owner::forward_if_needed(&cli) {
        return code;
    }
    // The installed node on Windows runs under the service control manager,
    // which takes the main thread.
    #[cfg(windows)]
    if let Some(log) = crate::cli::service_log(&cli) {
        return crate::win_service::serve(Box::new(move || run(cli)), log);
    }
    let json = cli.json;
    match run(cli) {
        Ok(()) => 0,
        Err(e) => {
            // A program that asked for JSON reads the error from stdout too:
            // stderr also carries the log's events.
            // A closed stdout leaves only stderr to say it.
            if json {
                use std::io::Write;
                let _ = writeln!(std::io::stdout(), "{}", serde_json::json!({ "error": e }));
            }
            eprintln!("nerve-node: {e}");
            1
        }
    }
}

fn run(cli: crate::cli::Cli) -> Result<(), String> {
    // Before the runtime starts threads: root's command on the installed
    // node runs as the node's user.
    crate::cli::settle_user(&cli)?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("cannot start the runtime: {e}"))?;
    let mut out = std::io::stdout();
    rt.block_on(crate::cli::execute(cli, &mut out))
}
