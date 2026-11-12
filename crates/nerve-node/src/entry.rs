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
    // So is the service that keeps the command account's profile loaded
    // (crate::win_profile).
    #[cfg(windows)]
    if std::env::args_os().nth(1).as_deref()
        == Some(std::ffi::OsStr::new(crate::win_profile::PROFILE_ARG))
    {
        return crate::win_profile::main();
    }
    // So is the helper that makes or removes an AppContainer's profile as
    // the command account (crate::win_profile::CONTAINER_ARG).
    #[cfg(windows)]
    if std::env::args_os().nth(1).as_deref()
        == Some(std::ffi::OsStr::new(crate::win_profile::CONTAINER_ARG))
    {
        return crate::win_profile::helper_main();
    }
    // So is the keyring probe that setup and install start
    // (docs/dev/settings-and-config.md): it answers whether the system keyring of the
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
    // A folder named by an old variable would be dropped without a word.
    if let Err(e) = crate::paths::refuse_old_names(|k| std::env::var_os(k)) {
        eprintln!("{}: {e}", crate::edition::get().program);
        return 1;
    }
    // Named after this program, so `--version` and the usage say which one
    // it is (crate::edition).
    let program = crate::edition::get().program;
    // Bare, it shows the commands of every day; `--help` all of them.
    if std::env::args_os().len() == 1 {
        println!("{}", crate::cli::everyday(program));
        return 2;
    }
    let matches = crate::cli::help_pages(crate::cli::Cli::command(), program).get_matches();
    let cli = crate::cli::Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    #[cfg(windows)]
    crate::cli::set_desktop_user(cli.desktop_user_sid.clone());
    #[cfg(windows)]
    // SAFETY: nothing here has started another thread.
    if let Err(e) = unsafe { settle_environment(&cli) } {
        return failed(cli.json, &e);
    }
    // An owner of the installed node, who may not open its folders, has
    // the running node run the command (crate::owner).
    if let Some(code) = crate::owner::forward_if_needed(&cli) {
        return code;
    }
    // The installed node on Windows runs under the service control manager,
    // which takes the main thread; no other node runs there (crate::cli::BY_HAND).
    #[cfg(windows)]
    match crate::cli::service_log(&cli) {
        Some(Ok(log)) => {
            let json = cli.json;
            // The folders must still be the administrators' that install
            // made: one put in their place since (another account's, or a
            // link) is not read (security-1).
            let paths =
                crate::paths::NodePaths::from_args(cli.config_dir.clone(), cli.state_dir.clone());
            let body = move || {
                crate::winsvc::check_folders(&paths, crate::win_host::check_own_folder)?;
                run(cli)
            };
            return crate::win_service::serve(Box::new(body), log, json);
        }
        Some(Err(e)) => return failed(cli.json, &e),
        None => {}
    }
    let json = cli.json;
    match run(cli) {
        Ok(()) => 0,
        Err(e) => failed(json, &e),
    }
}

/// An administrator's command on Windows takes the proxy and the trusted
/// certificates from the machine, and no folder from the variables of the
/// account, which its unelevated programs may set (windows-2).
///
/// # Safety
///
/// Changes the environment: call it before this process starts another
/// thread.
#[cfg(windows)]
unsafe fn settle_environment(cli: &crate::cli::Cli) -> Result<(), String> {
    if crate::cli::takes_machine_environment(&cli.cmd) {
        // SAFETY: the caller's promise.
        unsafe { nerve_service::win::folders::take_machine_environment() };
    }
    crate::paths::refuse_folder_variables(|k| std::env::var_os(k), crate::win_host::is_admin())
}

/// Says the error `e` of a command; its exit code.
pub(crate) fn failed(json: bool, e: &str) -> i32 {
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

#[cfg(all(test, windows))]
mod tests {
    use clap::Parser;

    use nerve_service::win::folders::{STEERING, is_steering};

    /// Prints the steering variables that `update` keeps, for
    /// [`an_update_takes_the_machine_s_proxy`].
    #[test]
    #[ignore = "run by an_update_takes_the_machine_s_proxy, in a process of its own"]
    fn print_the_steering_variables_of_update() {
        let cli = crate::cli::Cli::try_parse_from(["nerve-node", "update"]).unwrap();
        // SAFETY: a process of its own, run with `--test-threads=1`, that
        // reads these variables nowhere else.
        let settled = unsafe { super::settle_environment(&cli) };
        println!("settled: {settled:?}");
        let left: Vec<_> = std::env::vars_os()
            .filter(|(k, _)| is_steering(k))
            .collect();
        println!("steering: {left:?}");
    }

    /// The elevated `update` downloads the program the service runs: it
    /// takes the machine's proxy and trusted certificates, never the
    /// account's variables, which its unelevated programs may set
    /// (windows-2); an elevated one also refuses the folder variables.
    /// Set for a process of its own.
    #[test]
    fn an_update_takes_the_machine_s_proxy() {
        let mut c = std::process::Command::new(std::env::current_exe().unwrap());
        c.args([
            "--exact",
            "entry::tests::print_the_steering_variables_of_update",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ]);
        for k in STEERING {
            c.env(k, "decoy-from-the-account");
        }
        c.env(crate::paths::STATE_DIR_VAR, "decoy-from-the-account");
        let o = c.output().unwrap();
        let said = String::from_utf8_lossy(&o.stdout);
        assert!(o.status.success(), "{said}");
        assert!(said.contains("steering: ["), "{said}");
        // The steering variables are the machine's, whoever runs it; the
        // folder variable is refused in an elevated process (a runner
        // is one, a developer's terminal need not be).
        assert!(!said.contains("decoy-from-the-account"), "{said}");
        if crate::win_host::is_admin() {
            assert!(
                said.contains("settled: Err(") && said.contains("NERVE_NODE_STATE_DIR is set"),
                "{said}"
            );
        } else {
            assert!(said.contains("settled: Ok("), "{said}");
        }
    }
}
