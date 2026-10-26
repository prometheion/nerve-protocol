//! Flags and `NERVE_*` variables. A harness starts `nerve-center` from its MCP
//! entry, so every setting is a flag or a variable there. The only
//! subcommands are the owner's: `backup` and `restore`, which run by hand on a
//! center that is not running (`restore`) or may be (`backup`), and the
//! service's `install`, `update` and `uninstall`, run as root on Linux
//! ([`crate::service`]).

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use nerve_transport::log::Level;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum McpMode {
    /// MCP over this process's stdin and stdout.
    Stdio,
    /// MCP over Streamable HTTP at `--mcp-listen`.
    Http,
    /// No MCP of its own: the center only, for harnesses that attach.
    None,
}

#[derive(Debug, Clone, Parser)]
#[command(
    name = "nerve-center",
    version,
    about = "The Nerve center as an MCP server. Start it from a harness's MCP configuration."
)]
pub struct Args {
    /// The state folder (identity, paired nodes, statistics).
    #[arg(long, env = "NERVE_STATE_DIR", global = true)]
    pub state_dir: Option<PathBuf>,
    /// The center name shown to nodes and in the web UI.
    #[arg(long, env = "NERVE_NAME")]
    pub name: Option<String>,
    /// Where nodes reach the center.
    #[arg(long, env = "NERVE_LISTEN", default_value = "0.0.0.0:7443")]
    pub listen: String,
    /// The URL put into pairing links; https://<host name>:<port> by default.
    #[arg(long, env = "NERVE_PUBLIC_URL")]
    pub public_url: Option<String>,
    /// Serve nodes over plain HTTP; only on a loopback `--listen`, for tests
    /// and nodes on the same machine.
    #[arg(long, env = "NERVE_PLAIN_LOOPBACK")]
    pub plain_loopback: bool,
    /// The web UI address, or `off`.
    #[arg(long, env = "NERVE_UI", default_value = "127.0.0.1:7480")]
    pub ui: String,
    /// Let the web UI in without a login. It logs in with a harness token
    /// otherwise; only for a UI on loopback, a UI beyond it always needs one.
    #[arg(long, env = "NERVE_UI_NO_LOGIN")]
    pub ui_no_login: bool,
    /// How harnesses talk to the center.
    #[arg(long, env = "NERVE_MCP", value_enum, default_value = "stdio")]
    pub mcp: McpMode,
    /// The HTTP MCP address (with `--mcp http`).
    #[arg(long, env = "NERVE_MCP_LISTEN", default_value = "127.0.0.1:7481")]
    pub mcp_listen: String,
    /// A harness token: the bearer token of the HTTP MCP endpoint and the
    /// secret that logs in to the web UI, besides tokens made in the web UI.
    #[arg(long, env = "NERVE_HARNESS_TOKEN", hide_env_values = true)]
    pub harness_token: Option<String>,
    /// How long `execute` waits for a call's result: a call still running
    /// then becomes a job, whose id `execute` answers at once (`20`, `20s`
    /// or `500ms`; 10 ms to 600 s). Keep it below your harness's own timeout
    /// for a tool call.
    #[arg(long, env = "NERVE_CALL_WAIT", default_value = "20s", value_parser = crate::jobs::parse_wait)]
    pub call_wait: std::time::Duration,
    /// The log level (error, warn, info, debug). Without it the level set in
    /// the web UI holds, info at first; with it this level holds for this run.
    #[arg(long, env = "NERVE_LOG")]
    pub log: Option<Level>,
    #[command(subcommand)]
    pub cmd: Option<Cmd>,
}

/// What the owner runs by hand; a harness never does. Without one,
/// `nerve-center` runs the center.
#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum Cmd {
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
    /// Install the center as a service that starts with the machine and runs under a user of its own, with MCP over HTTP (Linux with systemd, as root).
    Install,
    /// Replace the installed program with the latest release and restart the service; the state and the settings stay.
    Update {
        /// Take the new program from this file instead of downloading the latest release.
        #[arg(long, value_name = "FILE")]
        from: Option<PathBuf>,
    },
    /// Stop and remove the service, its user and the program; the state and settings folders stay.
    Uninstall {
        /// Delete the state and settings folders too: the center's key, its pairings and its log.
        #[arg(long)]
        purge: bool,
    },
}

impl Cmd {
    /// install, update and uninstall: they work on the installed service,
    /// as root, not on `--state-dir`.
    pub fn is_service(&self) -> bool {
        matches!(
            self,
            Cmd::Install | Cmd::Update { .. } | Cmd::Uninstall { .. }
        )
    }
}

/// The center's settings given with a command, as the owner wrote them: a
/// flag (`--public-url`) or a variable (`NERVE_PUBLIC_URL`). Defaults are
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
            "none",
        ])
        .unwrap();
        assert_eq!(a.public_url(9), "http://127.0.0.1:9");
        assert!(a.ui_off());
        // The web UI logs in with the harness token; there is no password of
        // its own, and the login is switched off by a flag alone.
        assert!(!a.ui_no_login);
        assert!(Args::try_parse_from(["nerve-center", "--ui-password", "x"]).is_err());
        let a = Args::try_parse_from(["nerve-center", "--ui-no-login"]).unwrap();
        assert!(a.ui_no_login);
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
        assert!(
            is_loopback("127.0.0.1:7480") && is_loopback("[::1]:1") && !is_loopback("0.0.0.0:7480")
        );
    }
}
