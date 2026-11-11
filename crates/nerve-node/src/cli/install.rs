//! `install`, `update`, `uninstall`, `service` and `service-files`: the node
//! as a service of the machine (crate::service, on Windows crate::winsvc).

use super::*;

/// On Windows, `run` runs only under the service control manager
/// (crate::win_service), on the installed node's folders: `Some(Ok(log))`
/// with the node's log file, where a start that fails is said, and
/// `Some(Err(why))` on any other folders, where nothing starts a node
/// (crate::win_service::BY_HAND). `None` for any other command.
pub fn service_log(cli: &Cli) -> Option<Result<PathBuf, String>> {
    if !matches!(cli.cmd, Cmd::Run) {
        return None;
    }
    let paths = NodePaths::from_args(cli.config_dir.clone(), cli.state_dir.clone());
    Some(if crate::service::is_service_node(&paths) {
        Ok(paths.log_file())
    } else {
        Err(BY_HAND.into())
    })
}

/// Whether `cmd` takes the machine's proxy and trusted certificates in place
/// of the account's variables on Windows
/// (nerve_service::win::folders::take_machine_environment): the commands an
/// administrator runs elevated, which take the account's own variables,
/// which its unelevated programs may set (windows-2). `update` downloads
/// the program the service runs with them.
pub fn takes_machine_environment(cmd: &Cmd) -> bool {
    matches!(
        cmd,
        Cmd::Install { .. } | Cmd::Update { .. } | Cmd::Uninstall { .. } | Cmd::Restore { .. }
    )
}

/// Why `run` does not start a node outside the service on Windows: there
/// the desktop app is the only way to the node, and the node runs only as
/// the service the app installs and starts.
pub const BY_HAND: &str = "on Windows the node runs only as its service: the desktop app's installer installs it, and Start on the app's Overview starts it";

/// The installed service's state as JSON (crate::service::service_status): the
/// installed service's state as this machine's service manager says it.
pub(crate) fn service_status(layout: &Layout) -> Result<serde_json::Value, String> {
    #[cfg(windows)]
    let state = {
        use crate::winsvc::WinSystem;
        crate::win_host::WinHost.service_state()?
    };
    #[cfg(not(windows))]
    let state = crate::service::unit_status(layout, &Host)?;
    Ok(crate::service::service_status(layout, state.as_ref()))
}

/// `install`: the node as a service of the machine.
pub(super) async fn install(
    paths: NodePaths,
    owner: Option<String>,
    accept_root_owner: bool,
    forget_secrets: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    let root = root_owner(owner.as_deref(), accept_root_owner, cfg!(windows))?;
    let layout = Layout::system();
    owner_check(&[&paths, &layout.paths]).await?;
    let exe = std::env::current_exe().map_err(|e| format!("this program: {e}"))?;
    #[cfg(windows)]
    let _ = root;
    #[cfg(windows)]
    return crate::winsvc::install(
        &layout,
        &crate::win_host::WinHost,
        &exe,
        &invoker(),
        forget_secrets,
        out,
    );
    #[cfg(not(windows))]
    {
        let _ = forget_secrets;
        use std::io::IsTerminal;
        let stdin = std::io::stdin();
        let mut input = std::io::BufReader::new(stdin.lock());
        let terminal = at_terminal(
            stdin.is_terminal(),
            std::io::stdout().is_terminal(),
            json::active(),
        );
        let invoker = invoker();
        if !terminal && crate::service::root_question_due(&layout, &invoker, root) {
            eprintln!("{}", crate::service::NO_QUESTION);
        }
        let keyring = crate::keyring_setup::HostKeyring {
            exe: layout.bin.clone(),
        };
        crate::service::install_asking(
            &layout,
            &Host,
            &keyring,
            terminal_input(terminal, &mut input),
            root,
            &exe,
            &invoker,
            out,
        )?;
        // One first run: at a terminal setup's questions follow.
        if terminal {
            setup_after_install(&layout, &invoker, out);
        }
        Ok(())
    }
}

/// `update`: the installed node from a newer release.
pub(super) async fn update(from: Option<PathBuf>, out: &mut dyn Write) -> Result<(), String> {
    let layout = Layout::system();
    owner_check(&[&layout.paths]).await?;
    #[cfg(windows)]
    return crate::winsvc::update(&layout, &crate::win_host::WinHost, from.as_deref(), out).await;
    #[cfg(not(windows))]
    crate::service::update(&layout, &Host, from.as_deref(), out).await
}

/// `service-files`: the files `install` writes for the service, as text.
pub(super) fn service_files(
    owner: Option<String>,
    polkit: String,
    out: &mut dyn Write,
) -> Result<(), String> {
    let text = crate::service::service_files_text(
        &Layout::system(),
        owner.as_deref(),
        &polkit,
        crate::service::System::restricts_userns(&Host),
    );
    writeln!(out, "{text}").map_err(|e| e.to_string())
}

/// `service start|stop|restart`: the installed node's service.
pub(super) async fn service(c: ServiceCmd, out: &mut dyn Write) -> Result<(), String> {
    let action = match c {
        ServiceCmd::Start => crate::service::ServiceAction::Start,
        ServiceCmd::Stop => crate::service::ServiceAction::Stop,
        ServiceCmd::Restart => crate::service::ServiceAction::Restart,
    };
    let layout = Layout::system();
    // An owner without root does not reach the control socket; the
    // service manager lets the owner's own session only, not a
    // command of the node, start and stop it (crate::owner).
    if crate::rights::full_rights() {
        owner_check(&[&layout.paths]).await?;
    }
    #[cfg(windows)]
    return crate::winsvc::control(&layout, &crate::win_host::WinHost, action, out);
    #[cfg(not(windows))]
    crate::service::control(&layout, &Host, action, out)
}

/// `uninstall`: removes the installed node, with `--purge` its files too.
#[cfg_attr(not(windows), allow(unused_variables))]
pub(super) async fn uninstall(
    paths: NodePaths,
    purge: bool,
    forget_secrets: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    let layout = Layout::system();
    // The desktop app took this node over: its service, parts and
    // program are the app's, so the app's own uninstall removes it
    // all, and its checks are its own. Not on Windows, where the app
    // is the only node.
    #[cfg(not(windows))]
    if let Some(app) = crate::service::app_beside(&layout) {
        return crate::service::hand_over_uninstall(&app, purge, out);
    }
    owner_check(&[&layout.paths]).await?;
    // The node run by hand: the one named, or the one in this
    // user's default folders.
    #[cfg(windows)]
    let by_hand = if paths == layout.paths {
        NodePaths::by_hand()
    } else {
        paths
    };
    #[cfg(windows)]
    return crate::winsvc::uninstall(
        &layout,
        &by_hand,
        &crate::win_host::WinHost,
        purge,
        forget_secrets,
        out,
    );
    #[cfg(not(windows))]
    {
        let _ = forget_secrets;
        crate::service::uninstall(&layout, &Host, purge, out)
    }
}

/// Whether `install` may ask its questions (the keyring, root as the
/// owner): only where its input (`stdin`) and its output (`stdout`) are a
/// terminal, and not with `--json` (`json`), whose output is printed only at
/// the end. Elsewhere nobody would see the question while install waits.
#[cfg_attr(windows, allow(dead_code))]
fn at_terminal(stdin: bool, stdout: bool, json: bool) -> bool {
    stdin && stdout && !json
}

/// The input `install` asks its questions on: the terminal's, and none
/// where it may not ask ([`at_terminal`]), as where the input is piped or
/// closed. A script that installs gets each question's no, or the refusal,
/// instead of a question that its input would answer.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn terminal_input(terminal: bool, input: &mut dyn BufRead) -> Option<&mut dyn BufRead> {
    terminal.then_some(input)
}

/// What `install`'s flags choose for the owner (crate::service::RootOwner):
/// root with `--owner=root` and `--accept-root-owner` together, none with
/// `--owner=none`, else install asks at a terminal. `--owner=root` or
/// `--accept-root-owner` alone is refused, with what the pair means. On
/// Windows (`windows`), where the account that installs is the owner, both
/// are refused first.
fn root_owner(
    owner: Option<&str>,
    accepted: bool,
    windows: bool,
) -> Result<crate::service::RootOwner, String> {
    use crate::service::RootOwner;
    if windows && (owner.is_some() || accepted) {
        return Err(
            "--owner and --accept-root-owner are for Linux: on Windows the account that installs is the owner".into(),
        );
    }
    match (owner, accepted) {
        (Some("root"), true) => Ok(RootOwner::Accepted),
        (Some("none"), false) => Ok(RootOwner::NoOwner),
        (Some("none"), true) => {
            Err("--accept-root-owner goes with --owner=root only, not with --owner=none".into())
        }
        (None, false) => Ok(RootOwner::Ask),
        _ => Err(format!(
            "--owner=root and --accept-root-owner go together: with both, root is the owner of the node, and {}",
            crate::service::ROOT_OWNER_MEANS
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests::{run, setup};

    /// install, update and uninstall work on the installed node only, so
    /// they take no folders; none says it is not done.
    #[test]
    fn the_service_commands_take_no_folders() {
        let (_d, paths) = setup(&[]);
        for cmd in [
            &["install"][..],
            &["update"],
            &["update", "--from", "/tmp/x"],
            &["uninstall"],
            &["uninstall", "--purge"],
        ] {
            let e = run(&paths, cmd).unwrap_err();
            assert!(e.contains("leave out --config-dir and --state-dir"), "{e}");
            assert!(!e.contains("not done"), "{e}");
        }
    }

    /// The administrator's commands on Windows take the machine's proxy
    /// and trusted certificates: install, update (which downloads the
    /// program), uninstall and restore; the others keep the account's
    /// (windows-2).
    #[test]
    fn the_administrator_s_commands_take_the_machine_s_environment() {
        use clap::Parser;
        let cmd = |args: &[&str]| {
            Cli::try_parse_from(std::iter::once("nerve-node").chain(args.iter().copied()))
                .unwrap()
                .cmd
        };
        for args in [
            &["install"][..],
            &["update"],
            &["uninstall", "--purge"],
            &["restore", "b.nerve"],
        ] {
            assert!(takes_machine_environment(&cmd(args)), "{args:?}");
        }
        for args in [&["status"][..], &["backup", "b.nerve"], &["sudo", "on"]] {
            assert!(!takes_machine_environment(&cmd(args)), "{args:?}");
        }
    }

    /// `install --owner=root --accept-root-owner` makes root the owner;
    /// either flag alone is refused with what the pair means, and no other
    /// account can be named.
    #[test]
    fn install_takes_root_as_the_owner_only_with_both_flags() {
        use crate::service::RootOwner;
        let flags = |args: &[&str]| -> Result<RootOwner, String> {
            let argv = ["nerve-node", "install"].iter().chain(args).copied();
            match Cli::try_parse_from(argv).map_err(|e| e.to_string())?.cmd {
                Cmd::Install {
                    owner,
                    accept_root_owner,
                    ..
                } => root_owner(owner.as_deref(), accept_root_owner, false),
                _ => unreachable!(),
            }
        };
        assert_eq!(flags(&[]).unwrap(), RootOwner::Ask);
        assert_eq!(
            flags(&["--owner=root", "--accept-root-owner"]).unwrap(),
            RootOwner::Accepted
        );
        for alone in [&["--owner=root"][..], &["--accept-root-owner"]] {
            let e = flags(alone).unwrap_err();
            assert!(e.contains("go together"), "{e}");
            assert!(e.contains(crate::service::ROOT_OWNER_MEANS), "{e}");
        }
        // No owner, root or another, is chosen with --owner=none alone.
        assert_eq!(flags(&["--owner=none"]).unwrap(), RootOwner::NoOwner);
        let e = flags(&["--owner=none", "--accept-root-owner"]).unwrap_err();
        assert!(e.contains("--owner=root only"), "{e}");
        let e = flags(&["--owner=alice", "--accept-root-owner"]).unwrap_err();
        assert!(e.contains("invalid value"), "{e}");
        // Input that is no terminal's answers no question.
        let mut piped = std::io::Cursor::new(b"y\n".to_vec());
        assert!(terminal_input(false, &mut piped).is_none());
        assert!(terminal_input(true, &mut piped).is_some());
    }

    /// On Windows, where the account that installs is the owner, either
    /// flag is refused with what holds there, before the pair is looked at.
    #[test]
    fn windows_refuses_the_owner_flags_first() {
        use crate::service::RootOwner;
        for (owner, accepted) in [
            (Some("root"), false),
            (None, true),
            (Some("root"), true),
            (Some("none"), false),
        ] {
            let e = root_owner(owner, accepted, true).unwrap_err();
            assert_eq!(
                e,
                "--owner and --accept-root-owner are for Linux: on Windows the account that installs is the owner",
                "{owner:?} {accepted}"
            );
        }
        assert_eq!(root_owner(None, false, true).unwrap(), RootOwner::Ask);
    }

    /// Install asks only where its input and its output are a terminal and
    /// it runs without --json: elsewhere nobody would see the question.
    #[test]
    fn install_asks_only_where_the_question_is_seen() {
        assert!(at_terminal(true, true, false));
        for (stdin, stdout, json) in [
            (false, true, false),
            (true, false, false),
            (true, true, true),
            (false, false, false),
        ] {
            assert!(!at_terminal(stdin, stdout, json), "{stdin} {stdout} {json}");
        }
        let said = crate::service::NO_QUESTION;
        assert!(said.contains("--owner=root --accept-root-owner"), "{said}");
        assert!(said.contains("the answer is no"), "{said}");
    }

    /// `run` runs the node only on the installed node's folders, where the
    /// service manager starts it on Windows; on others it is refused there
    /// (#176). Other commands are left to themselves.
    #[test]
    fn run_runs_only_the_service_node() {
        let d = tempfile::tempdir().unwrap();
        let config = format!("--config-dir={}", d.path().join("config").display());
        let state = format!("--state-dir={}", d.path().join("state").display());
        let cli = |args: &[&str]| {
            let mut argv = vec!["nerve-node", &config, &state];
            argv.extend(args);
            Cli::try_parse_from(argv).unwrap()
        };
        assert_eq!(service_log(&cli(&["run"])), Some(Err(BY_HAND.to_string())));
        assert_eq!(service_log(&cli(&["status"])), None);
        let sys = Layout::system().paths;
        let cli = Cli::try_parse_from([
            "nerve-node".to_string(),
            format!("--config-dir={}", sys.config_dir.display()),
            format!("--state-dir={}", sys.state_dir.display()),
            "run".to_string(),
        ])
        .unwrap();
        assert_eq!(service_log(&cli), Some(Ok(sys.log_file())));
        // It says where the app does it, and sends nobody to a terminal.
        assert!(BY_HAND.contains("Overview"), "{BY_HAND}");
        assert!(!BY_HAND.contains("nerve-node "), "{BY_HAND}");
    }

    /// What `update` asks of the new program (`service::files_args`) is what
    /// `service-files` takes: a flag renamed on one side is refused at the
    /// next update, so the two are held together here, for every owner and
    /// every polkit.
    #[test]
    fn service_files_takes_what_update_asks() {
        use crate::service::{Polkit, files_args, service_files_text};
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        for owner in [None, Some("alice"), Some("root")] {
            for polkit in [Polkit::Rules, Polkit::Old, Polkit::Missing] {
                let args = files_args(owner.map(String::from), polkit);
                let mut argv = vec!["nerve-node", "service-files"];
                argv.extend(args.iter().map(String::as_str));
                let cli = Cli::try_parse_from(&argv).unwrap();
                let mut said = Vec::new();
                rt.block_on(execute(cli, &mut said)).unwrap();
                let said = String::from_utf8(said).unwrap();
                let kind = match polkit {
                    Polkit::Rules => "rules",
                    Polkit::Old => "pkla",
                    Polkit::Missing => "none",
                };
                let want = service_files_text(
                    &Layout::system(),
                    owner,
                    kind,
                    crate::service::System::restricts_userns(&Host),
                );
                assert_eq!(said.trim(), want, "{argv:?}");
            }
        }
    }
}
