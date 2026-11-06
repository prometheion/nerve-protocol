//! Flags and `NERVE_CENTER_*` variables. A harness starts `nerve-center` from
//! its MCP entry, so every setting is a flag or a variable there. The only
//! subcommands are the owner's: `backup` and `restore`, which run by hand on a
//! center that is not running (`restore`) or may be (`backup`),
//! `owner-token` ([`crate::owner`]), and the service's `install`, `update`
//! and `uninstall`, run as root on Linux ([`crate::service`]).

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use nerve_transport::log::Level;

/// How harnesses reach the center (`--mcp`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpMode {
    /// MCP over this process's stdin and stdout.
    Stdio,
    /// MCP over Streamable HTTP at this address.
    Http(String),
    /// No MCP of its own: the center only, for harnesses that attach.
    Off,
}

/// The HTTP MCP address of `--mcp http`.
pub const MCP_HTTP: &str = "127.0.0.1:7481";

impl std::str::FromStr for McpMode {
    type Err = String;

    /// `stdio`, `off`, `http` (at [`MCP_HTTP`]) or an address and port.
    fn from_str(s: &str) -> Result<McpMode, String> {
        match s {
            "stdio" => Ok(McpMode::Stdio),
            "off" => Ok(McpMode::Off),
            "http" => Ok(McpMode::Http(MCP_HTTP.into())),
            a if a.parse::<std::net::SocketAddr>().is_ok() || a.starts_with("localhost:") => {
                Ok(McpMode::Http(a.into()))
            }
            other => Err(format!(
                "{other:?}: stdio, off, http ({MCP_HTTP}) or an address and port, like 0.0.0.0:7481"
            )),
        }
    }
}

/// The variables of the center and the node before they had a prefix of
/// their own, and their names now. A program refuses to start while one of
/// its old names is set ([`refuse_old_names`]), so a setting is never lost
/// without a word.
pub const OLD_NAMES: &[(&str, &str)] = &[
    ("NERVE_STATE_DIR", "NERVE_CENTER_STATE_DIR"),
    ("NERVE_NAME", "NERVE_CENTER_NAME"),
    ("NERVE_LISTEN", "NERVE_CENTER_LISTEN"),
    ("NERVE_PUBLIC_URL", "NERVE_CENTER_PUBLIC_URL"),
    ("NERVE_PLAIN_LOOPBACK", "NERVE_CENTER_PLAIN_LOOPBACK"),
    ("NERVE_UI", "NERVE_CENTER_UI"),
    ("NERVE_MCP", "NERVE_CENTER_MCP"),
    ("NERVE_MCP_LISTEN", "NERVE_CENTER_MCP"),
    ("NERVE_HARNESS_TOKEN", "NERVE_CENTER_HARNESS_TOKEN"),
    ("NERVE_CALL_WAIT", "NERVE_CENTER_CALL_WAIT"),
    ("NERVE_LOG", "NERVE_CENTER_LOG"),
];

/// Refuses an old name of `OLD_NAMES` that `var` finds set, with what to
/// do and where: the settings file of the installed center, or where the
/// center is started.
pub fn refuse_old_names(
    var: impl Fn(&str) -> Option<String>,
    settings: &std::path::Path,
) -> Result<(), String> {
    let set: Vec<(&str, &str)> = OLD_NAMES
        .iter()
        .copied()
        .filter(|(old, _)| var(old).is_some())
        .collect();
    let Some((old, new)) = set.first() else {
        return Ok(());
    };
    let what = match *old {
        "NERVE_MCP_LISTEN" => {
            format!("put the address of {old} into {new} (`{new}=127.0.0.1:7481`)")
        }
        _ => format!("rename {old} to {new}"),
    };
    let more = match set.len() {
        1 => String::new(),
        n => format!(
            " ({} more old names are set: each NERVE_X is NERVE_CENTER_X now)",
            n - 1
        ),
    };
    Err(format!(
        "{what} in {} (the installed center's settings), or where you start nerve-center (the harness's MCP entry, your shell){more}; the center does not start while an old name is set",
        settings.display()
    ))
}

#[derive(Debug, Clone, Parser)]
#[command(
    name = "nerve-center",
    version,
    // `--help` gives one line each here; `help <command>` the whole text.
    disable_help_flag = true,
    about = "The Nerve center as an MCP server. Start it from a harness's MCP configuration."
)]
pub struct Args {
    /// Print help (`nerve-center help <command>` for one command's whole text)
    #[arg(short = 'h', long = "help", action = clap::ArgAction::HelpShort)]
    help: Option<bool>,
    /// The state folder (identity, paired machines, statistics)
    ///
    /// The state folder (identity, paired nodes, statistics); the installed center's for `owner-token`, `status`, `backup` and `restore` where it is installed.
    #[arg(
        long,
        env = "NERVE_CENTER_STATE_DIR",
        global = true,
        help_heading = "Advanced"
    )]
    pub state_dir: Option<PathBuf>,
    /// The center name shown to nodes and in the web UI.
    #[arg(long, env = "NERVE_CENTER_NAME")]
    pub name: Option<String>,
    /// Where nodes reach the center.
    #[arg(long, env = "NERVE_CENTER_LISTEN", default_value = "0.0.0.0:7443")]
    pub listen: String,
    /// The URL put into pairing links; https://<host name>:<port> by default.
    #[arg(long, env = "NERVE_CENTER_PUBLIC_URL")]
    pub public_url: Option<String>,
    /// Serve nodes over plain HTTP, on a loopback --listen only
    ///
    /// Serve nodes over plain HTTP; only on a loopback `--listen`, for tests and nodes on the same machine.
    #[arg(long, env = "NERVE_CENTER_PLAIN_LOOPBACK", help_heading = "Advanced")]
    pub plain_loopback: bool,
    /// The web UI address, or `off`; it asks for the owner token
    ///
    /// The web UI address, or `off`. It always asks for the owner token (`nerve-center owner-token`).
    #[arg(long, env = "NERVE_CENTER_UI", default_value = "127.0.0.1:7480")]
    pub ui: String,
    /// How harnesses reach the center: stdio, off, http or an address
    ///
    /// How harnesses reach the center: `stdio`, `off`, `http` (127.0.0.1:7481) or an address and port for HTTP MCP.
    #[arg(
        long,
        env = "NERVE_CENTER_MCP",
        value_name = "stdio|off|ADDRESS",
        default_value = "stdio"
    )]
    pub mcp: McpMode,
    /// A harness token for the HTTP MCP endpoint (not a web UI login)
    ///
    /// A harness token: a bearer token of the HTTP MCP endpoint, besides the tokens made in the web UI. It does not log in to the web UI.
    #[arg(
        long,
        env = "NERVE_CENTER_HARNESS_TOKEN",
        hide_env_values = true,
        help_heading = "Advanced"
    )]
    pub harness_token: Option<String>,
    /// How long `execute` waits before a call becomes a job (20s)
    ///
    /// How long `execute` waits for a call's result: a call still running then becomes a job, whose id `execute` answers at once (`20`, `20s` or `500ms`; 10 ms to 600 s). Keep it below your harness's own timeout for a tool call.
    #[arg(long, env = "NERVE_CENTER_CALL_WAIT", default_value = "20s", value_parser = crate::jobs::parse_wait, help_heading = "Advanced")]
    pub call_wait: std::time::Duration,
    /// The log level for this run (error, warn, info, debug)
    ///
    /// The log level (error, warn, info, debug). Without it the level set in the web UI holds, info at first; with it this level holds for this run.
    #[arg(long, env = "NERVE_CENTER_LOG", help_heading = "Advanced")]
    pub log: Option<Level>,
    #[command(subcommand)]
    pub cmd: Option<Cmd>,
}

/// What the owner runs by hand; a harness never does. Without one,
/// `nerve-center` runs the center.
#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum Cmd {
    /// Run the center as a service (as root)
    ///
    /// Install the center as a service that starts with the machine and runs under a user of its own, with MCP over HTTP (Linux with systemd, as root). --name, --public-url and --listen go into its settings.
    Install,
    /// Show whether the center runs, its URLs and its machines
    ///
    /// Show whether the center runs, its URLs, where its owner token is, and its machines; the installed center's where it is installed.
    Status,
    /// Show the token that logs in to the web UI
    ///
    /// Say the owner token, the secret that logs in to the web UI, and where it is kept; with --new, make a new one first. Run it as the center's user, or as root for the installed center.
    OwnerToken {
        /// Make a new token in place of the old one, which stops at once
        ///
        /// Make a new token in place of the old one: the old one stops at once, also on a running center.
        #[arg(long)]
        new: bool,
    },
    /// Update to the latest release; the state and the settings stay
    ///
    /// Replace the installed program with the latest release and restart the service; the state and the settings stay.
    Update {
        /// Take the new program from this file instead of downloading the latest release.
        #[arg(long, value_name = "FILE")]
        from: Option<PathBuf>,
    },
    /// Remove the service and the program; state and settings stay
    ///
    /// Stop and remove the service, its user and the program; the state and settings folders stay.
    Uninstall {
        /// Delete the state and settings folders too
        ///
        /// Delete the state and settings folders too: the center's key, its pairings and its log.
        #[arg(long)]
        purge: bool,
    },
    /// Save the center's identity and pairings to a passphrase-protected file
    ///
    /// Write the center's identity and state (its certificate and key, the paired nodes, the harness tokens' hashes and the statistics) to a file that a passphrase protects, to keep or to move the center to another machine.
    Backup {
        /// The file to write. It is private to you (mode 0600).
        file: PathBuf,
        /// Replace the file when it exists.
        #[arg(long)]
        overwrite: bool,
        /// Read the passphrase from the first line of this file instead of asking.
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<PathBuf>,
    },
    /// Restore a backup (the center must not run)
    ///
    /// Put the identity and state of a backup in place of this center's. No center may run on the state folder.
    Restore {
        /// The backup file.
        file: PathBuf,
        /// Replace a center here that is not the one the backup is of.
        #[arg(long)]
        replace: bool,
        /// Read the passphrase from the first line of this file instead of asking.
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<PathBuf>,
    },
    /// Print the files of the service this program installs, as JSON (for `update`)
    ///
    /// Print the files of the service this program installs besides itself, as JSON: `update` of the installed program runs the new one so, to put them in place with it.
    #[command(hide = true)]
    ServiceFiles,
}

impl Cmd {
    /// install, update and uninstall: they work on the installed service,
    /// as root, not on `--state-dir`. `install` takes the settings it
    /// writes into the service's file ([`INSTALL_SETTINGS`]).
    pub fn is_service(&self) -> bool {
        matches!(
            self,
            Cmd::Install | Cmd::Update { .. } | Cmd::Uninstall { .. }
        )
    }
}

/// The settings `install` takes and writes into the service's settings
/// file, by flag and variable.
pub const INSTALL_SETTINGS: &[(&str, &str)] = &[
    ("--name", "NERVE_CENTER_NAME"),
    ("--public-url", "NERVE_CENTER_PUBLIC_URL"),
    ("--listen", "NERVE_CENTER_LISTEN"),
];

/// The center's settings given with a command, as the owner wrote them: a
/// flag (`--public-url`) or a variable (`NERVE_CENTER_PUBLIC_URL`). Defaults are
/// not given.
pub fn settings_given(m: &clap::ArgMatches) -> Vec<String> {
    use clap::CommandFactory;
    use clap::parser::ValueSource;
    let cmd = Args::command();
    let mut given = Vec::new();
    for a in cmd.get_arguments() {
        let id = a.get_id().as_str();
        // A global flag may come after the subcommand, where its value is.
        let below = || {
            m.subcommand()
                .filter(|_| a.is_global_set())
                .and_then(|(_, s)| s.value_source(id))
        };
        let source = match m.value_source(id) {
            Some(clap::parser::ValueSource::DefaultValue) | None => below().or(m.value_source(id)),
            s => s,
        };
        match source {
            Some(ValueSource::CommandLine) => {
                given.push(format!("--{}", a.get_long().unwrap_or(id)));
            }
            Some(ValueSource::EnvVariable) => given.push(
                a.get_env()
                    .map_or_else(|| id.to_string(), |e| e.to_string_lossy().into_owned()),
            ),
            _ => {}
        }
    }
    given
}

impl Args {
    pub fn state_dir(&self) -> PathBuf {
        self.state_dir.clone().unwrap_or_else(default_state_dir)
    }

    /// The state folder of the owner's commands (`owner-token`, `status`,
    /// `backup`, `restore`): the one given, else the installed center's
    /// where it is installed, else the one a harness-started center uses.
    /// The center a harness starts keeps its own ([`Args::state_dir`]).
    pub fn owner_state_dir(&self) -> PathBuf {
        let installed = crate::service::Layout::system();
        owner_state_of(
            self.state_dir.clone(),
            installed.installed().then_some(installed.state),
        )
    }

    pub fn ui_off(&self) -> bool {
        self.ui.eq_ignore_ascii_case("off")
    }

    /// The public URL, from the flag or from the host name and the port.
    pub fn public_url(&self, port: u16) -> String {
        if let Some(u) = &self.public_url {
            return u.clone();
        }
        if self.plain_loopback {
            return format!("http://127.0.0.1:{port}");
        }
        format!("https://{}:{port}", crate::center::host_name())
    }
}

/// [`Args::owner_state_dir`]: the folder `given`, else the `installed`
/// center's, else the default.
fn owner_state_of(given: Option<PathBuf>, installed: Option<PathBuf>) -> PathBuf {
    given.or(installed).unwrap_or_else(default_state_dir)
}

/// `$XDG_STATE_HOME/nerve-center`, `~/.local/state/nerve-center`, or on Windows
/// `%LOCALAPPDATA%\nerve-center`.
pub fn default_state_dir() -> PathBuf {
    if cfg!(windows)
        && let Some(d) = std::env::var_os("LOCALAPPDATA")
    {
        return PathBuf::from(d).join("nerve-center");
    }
    if let Some(d) = std::env::var_os("XDG_STATE_HOME").filter(|d| !d.is_empty()) {
        return PathBuf::from(d).join("nerve-center");
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".local/state/nerve-center")
}

/// Whether an address like `127.0.0.1:7480` or `[::1]:7480` is loopback.
pub fn is_loopback(addr: &str) -> bool {
    match addr.parse::<std::net::SocketAddr>() {
        Ok(a) => a.ip().is_loopback(),
        Err(_) => addr.starts_with("localhost:"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One line first (plan 4.1): every command's `about` and every flag's
    /// `help` is at most 80 characters; the rest is the long help.
    #[test]
    fn every_help_line_is_short() {
        use clap::CommandFactory;
        let cmd = Args::command();
        let mut long = Vec::new();
        for c in std::iter::once(&cmd).chain(cmd.get_subcommands()) {
            if let Some(a) = c.get_about().map(|a| a.to_string())
                && a.chars().count() > 80
            {
                long.push(format!("{}: {a}", c.get_name()));
            }
            for arg in c.get_arguments() {
                if let Some(h) = arg.get_help().map(|h| h.to_string())
                    && h.chars().count() > 80
                {
                    long.push(format!("{} {}: {h}", c.get_name(), arg.get_id()));
                }
            }
        }
        assert!(long.is_empty(), "{long:#?}");
    }

    /// The owner's commands take the installed center's folder where there
    /// is one and none is given; the center a harness starts its own.
    #[test]
    fn the_owner_s_commands_take_the_installed_center() {
        let installed = Some(PathBuf::from("/var/lib/nerve-center"));
        assert_eq!(
            owner_state_of(None, installed.clone()),
            PathBuf::from("/var/lib/nerve-center")
        );
        assert_eq!(
            owner_state_of(Some("/srv/c".into()), installed),
            PathBuf::from("/srv/c")
        );
        assert_eq!(owner_state_of(None, None), default_state_dir());
        let a = Args::try_parse_from(["nerve-center"]).unwrap();
        assert_eq!(a.state_dir(), default_state_dir());
    }

    /// A program refuses to start while an old variable name is set, and
    /// says what to rename and in which file; the new names pass.
    #[test]
    fn an_old_variable_name_is_refused_with_its_new_name() {
        let file = std::path::Path::new("/etc/nerve-center/center.env");
        let only = |names: &'static [&'static str]| {
            move |k: &str| names.contains(&k).then(|| "x".to_string())
        };
        assert!(refuse_old_names(only(&[]), file).is_ok());
        assert!(refuse_old_names(only(&["NERVE_CENTER_HARNESS_TOKEN"]), file).is_ok());
        let e = refuse_old_names(only(&["NERVE_HARNESS_TOKEN"]), file).unwrap_err();
        assert!(
            e.starts_with(
                "rename NERVE_HARNESS_TOKEN to NERVE_CENTER_HARNESS_TOKEN in /etc/nerve-center/center.env"
            ),
            "{e}"
        );
        let e = refuse_old_names(only(&["NERVE_MCP_LISTEN", "NERVE_LOG"]), file).unwrap_err();
        assert!(e.contains("NERVE_CENTER_MCP=127.0.0.1:7481"), "{e}");
        assert!(e.contains("1 more old names are set"), "{e}");
        // Every flag's variable is a new name.
        use clap::CommandFactory;
        for a in Args::command().get_arguments() {
            if let Some(env) = a.get_env() {
                assert!(
                    env.to_string_lossy().starts_with("NERVE_CENTER_"),
                    "{env:?}"
                );
            }
        }
    }

    /// The settings an owner gives with a command, wherever the flag stands;
    /// none when only defaults hold.
    #[test]
    fn the_settings_given_are_named() {
        use clap::CommandFactory;
        let given = |args: &[&str]| {
            let m = Args::command()
                .try_get_matches_from(std::iter::once("nerve-center").chain(args.iter().copied()))
                .unwrap();
            settings_given(&m)
        };
        assert!(given(&["install"]).is_empty());
        assert!(given(&["uninstall", "--purge"]).is_empty());
        assert_eq!(
            given(&["--public-url", "https://center.example:7443", "install"]),
            ["--public-url"]
        );
        assert_eq!(
            given(&["install", "--state-dir", "/srv/c"]),
            ["--state-dir"]
        );
        assert_eq!(
            given(&["--state-dir", "/srv/c", "install"]),
            ["--state-dir"]
        );
        assert_eq!(
            given(&["--listen", "0.0.0.0:9443", "--ui", "off", "update"]),
            ["--listen", "--ui"]
        );
    }

    #[test]
    fn flags_and_defaults() {
        let a = Args::try_parse_from(["nerve-center"]).unwrap();
        assert_eq!(a.mcp, McpMode::Stdio);
        // `--mcp` is stdio, off, http or an address; `none` and
        // `--mcp-listen` are gone.
        let mcp = |v: &str| Args::try_parse_from(["nerve-center", "--mcp", v]).map(|a| a.mcp);
        assert_eq!(mcp("http").unwrap(), McpMode::Http(MCP_HTTP.into()));
        assert_eq!(mcp("off").unwrap(), McpMode::Off);
        assert_eq!(
            mcp("0.0.0.0:9481").unwrap(),
            McpMode::Http("0.0.0.0:9481".into())
        );
        assert!(mcp("none").is_err());
        assert!(Args::try_parse_from(["nerve-center", "--mcp-listen", "127.0.0.1:1"]).is_err());
        assert_eq!(a.listen, "0.0.0.0:7443");
        assert!(!a.ui_off());
        assert_eq!(a.call_wait, crate::jobs::CALL_WAIT);
        let a = Args::try_parse_from(["nerve-center", "--call-wait", "500ms"]).unwrap();
        assert_eq!(a.call_wait, std::time::Duration::from_millis(500));
        assert!(Args::try_parse_from(["nerve-center", "--call-wait", "0"]).is_err());
        let a = Args::try_parse_from([
            "nerve-center",
            "--plain-loopback",
            "--ui",
            "off",
            "--mcp",
            "off",
        ])
        .unwrap();
        assert_eq!(a.public_url(9), "http://127.0.0.1:9");
        assert!(a.ui_off());
        // The web UI always logs in with the owner token: there is no
        // password of its own and no switch to turn the login off.
        assert!(Args::try_parse_from(["nerve-center", "--ui-password", "x"]).is_err());
        assert!(Args::try_parse_from(["nerve-center", "--ui-no-login"]).is_err());
        let a = Args::try_parse_from(["nerve-center"]).unwrap();
        // The level comes from the flag, or else from the settings.
        assert_eq!(a.log, None);
        let a = Args::try_parse_from(["nerve-center", "--log", "Debug"]).unwrap();
        assert_eq!(a.log, Some(Level::Debug));
        assert!(Args::try_parse_from(["nerve-center", "--log", "loud"]).is_err());
        // The owner's subcommands only: anything else positional is refused.
        assert!(a.cmd.is_none());
        assert!(Args::try_parse_from(["nerve-center", "pair"]).is_err());
        let cmd = |args: &[&str]| {
            Args::try_parse_from(std::iter::once("nerve-center").chain(args.iter().copied()))
                .unwrap()
                .cmd
        };
        assert_eq!(cmd(&["install"]), Some(Cmd::Install));
        assert_eq!(
            cmd(&["update", "--from", "x"]),
            Some(Cmd::Update {
                from: Some("x".into())
            })
        );
        assert_eq!(cmd(&["update"]), Some(Cmd::Update { from: None }));
        assert_eq!(
            cmd(&["uninstall", "--purge"]),
            Some(Cmd::Uninstall { purge: true })
        );
        assert!(Args::try_parse_from(["nerve-center", "install", "x"]).is_err());
        // The service's go to the service, backup and restore to the state
        // folder.
        assert!(cmd(&["install"]).unwrap().is_service());
        assert!(!cmd(&["backup", "f"]).unwrap().is_service());
        assert!(!cmd(&["restore", "f"]).unwrap().is_service());
        assert_eq!(cmd(&["owner-token"]), Some(Cmd::OwnerToken { new: false }));
        assert_eq!(
            cmd(&["owner-token", "--new"]),
            Some(Cmd::OwnerToken { new: true })
        );
        assert!(!cmd(&["owner-token"]).unwrap().is_service());
        assert!(
            is_loopback("127.0.0.1:7480") && is_loopback("[::1]:1") && !is_loopback("0.0.0.0:7480")
        );
    }
}
