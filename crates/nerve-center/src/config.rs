//! Flags and `NERVE_CENTER_*` variables. A harness starts `nerve-center` from
//! its MCP entry, so every setting is a flag or a variable there. The only
//! subcommands are the owner's: `backup` and `restore`, which run by hand on a
//! center that is not running (`restore`) or may be (`backup`),
//! `owner-token` ([`crate::owner`]), and the service's `install`, `set`,
//! `update` and `uninstall`, run as root on Linux ([`crate::service`]).

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

impl McpMode {
    /// The mode as the service's settings file writes it, for `install
    /// --mcp`: `stdio`, `off` or the HTTP MCP address.
    pub fn setting(&self) -> String {
        match self {
            McpMode::Stdio => "stdio".into(),
            McpMode::Off => "off".into(),
            McpMode::Http(a) => a.clone(),
        }
    }
}

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

// The doc comments are the help: the first paragraph is an option's or a
// command's line on the pages of `--help`, the rest what `help <command>`
// adds to it, so it does not say the line again. The variables are named
// once under the options ([`VARIABLES`]), not after each.
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
    // Global, so that every command has its own `--help` too.
    #[arg(short = 'h', long = "help", global = true, action = clap::ArgAction::HelpShort)]
    help: Option<bool>,
    /// The state folder (identity, paired machines, statistics)
    ///
    /// Where the center is installed, `owner-token`, `status`, `backup` and `restore` take the installed center's.
    #[arg(
        long,
        env = "NERVE_CENTER_STATE_DIR",
        hide_env = true,
        value_name = "FOLDER",
        global = true,
        help_heading = "Advanced"
    )]
    pub state_dir: Option<PathBuf>,
    /// The center name shown to nodes and in the web UI
    ///
    /// It replaces the name set in the web UI each time the center starts.
    #[arg(long, env = "NERVE_CENTER_NAME", hide_env = true, global = true)]
    pub name: Option<String>,
    /// Where nodes reach the center
    #[arg(
        long,
        env = "NERVE_CENTER_LISTEN",
        hide_env = true,
        value_name = "ADDRESS",
        default_value = "0.0.0.0:7443",
        global = true
    )]
    pub listen: String,
    /// The URL in pairing links; {port} in it is the node port
    ///
    /// Set it when nodes reach the center under another name than its host name, such as a DNS name or a forwarded port. Without it: https://<host name>:<node port>.
    #[arg(
        long,
        env = "NERVE_CENTER_PUBLIC_URL",
        hide_env = true,
        value_name = "URL",
        global = true
    )]
    pub public_url: Option<String>,
    /// Serve nodes over plain HTTP, on a loopback --listen only
    ///
    /// For tests, and nodes on the same machine.
    #[arg(
        long,
        env = "NERVE_CENTER_PLAIN_LOOPBACK",
        hide_env = true,
        help_heading = "Advanced"
    )]
    pub plain_loopback: bool,
    /// The web UI address, or off
    ///
    /// It always asks for the owner token, which `nerve-center owner-token` shows. Beyond loopback it uses TLS with the center's self-signed certificate.
    #[arg(
        long,
        env = "NERVE_CENTER_UI",
        hide_env = true,
        value_name = "ADDRESS",
        default_value = "127.0.0.1:7480",
        global = true
    )]
    pub ui: String,
    /// How harnesses reach the center: stdio, off, http or an address
    ///
    /// `http` is HTTP MCP at 127.0.0.1:7481, an address and port puts it there; beyond loopback it uses TLS. The installed service runs with `http`.
    #[arg(
        long,
        env = "NERVE_CENTER_MCP",
        hide_env = true,
        value_name = "MODE",
        default_value = "stdio",
        global = true
    )]
    pub mcp: McpMode,
    /// A harness token for the HTTP MCP endpoint (not a web UI login)
    ///
    /// A bearer token, besides those made in the web UI. Given as the flag it is in the process list; the variable is not.
    #[arg(
        long,
        env = "NERVE_CENTER_HARNESS_TOKEN",
        hide_env = true,
        value_name = "TOKEN",
        help_heading = "Advanced"
    )]
    pub harness_token: Option<String>,
    /// How long `execute` waits before a call becomes a job
    ///
    /// The job's id is the answer then, at once. `20`, `20s` or `500ms`, from 10 ms to 600 s; keep it below your harness's own timeout for a tool call.
    #[arg(long, env = "NERVE_CENTER_CALL_WAIT", hide_env = true, value_name = "TIME", default_value = "20s", value_parser = crate::jobs::parse_wait, help_heading = "Advanced")]
    pub call_wait: std::time::Duration,
    /// The log level for this run (error, warn, info, debug)
    ///
    /// Without it the level set in the web UI holds, info at first.
    #[arg(
        long,
        env = "NERVE_CENTER_LOG",
        hide_env = true,
        value_name = "LEVEL",
        help_heading = "Advanced"
    )]
    pub log: Option<Level>,
    #[command(subcommand)]
    pub cmd: Option<Cmd>,
}

/// What the owner runs by hand; a harness never does. Without one,
/// `nerve-center` runs the center.
#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum Cmd {
    /// Run the center as a service (as root or an administrator)
    ///
    /// It starts with the machine and runs under an account of its own, with MCP over HTTP: on Linux with systemd, as root; on Windows, in an administrator's terminal. --name, --public-url, --listen, --ui and --mcp go into its settings file, where `set` changes them later.
    Install,
    /// Show or change the installed center's settings, and restart it
    ///
    /// Alone, it shows the settings and the file they are kept in. With a setting and a value, it writes the value into that file and restarts the service when it runs: name, public-url, listen (the node port), ui (an address and a port, or off) or mcp (http, off, or an address and a port). As root on Linux; on Windows, in an administrator's terminal.
    Set {
        /// The setting to change
        #[arg(value_parser = set_names(), requires = "value")]
        setting: Option<String>,
        /// Its new value, like 0.0.0.0:7480 for ui
        value: Option<String>,
    },
    /// Show whether the center runs, its URLs and its machines
    ///
    /// Also where its owner token is. Where the center is installed, it is the installed one's.
    Status,
    /// Show the token that logs in to the web UI
    ///
    /// It says where the token is kept; with --new it makes a new one first. Run it as the center's user, or for the installed center as root (on Windows, in an administrator's terminal).
    OwnerToken {
        /// Make a new token in place of the old one, which stops at once
        ///
        /// A running center takes the new one at once too.
        #[arg(long)]
        new: bool,
    },
    /// Update to the latest release; the state and the settings stay
    ///
    /// It checks the download against the release's SHA256SUMS, restarts the service, and puts the old program back when the new one does not start.
    Update {
        /// Take the new program from this file instead of downloading the latest release.
        #[arg(long, value_name = "FILE")]
        from: Option<PathBuf>,
    },
    /// Remove the service and the program; state and settings stay
    ///
    /// The service's account goes with it.
    Uninstall {
        /// Delete the state and settings folders too
        ///
        /// That is the center's key, its pairings and its log.
        #[arg(long)]
        purge: bool,
    },
    /// Save the center's identity and pairings to a passphrase-protected file
    ///
    /// The file holds its certificate and key, the paired nodes, the harness tokens' hashes and the statistics: to keep, or to move the center to another machine.
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
    /// The backup's identity and state take this center's place. A running installed service is stopped for it and started again after.
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
    /// Start, stop or restart the installed center
    ///
    /// As root on Linux; on Windows, in an administrator's terminal. `status` shows whether it runs. Bare, `service` is how Windows starts the installed center, with the settings of the `center.env` that `install` wrote.
    Service {
        #[command(subcommand)]
        cmd: Option<ServiceCmd>,
    },
    /// Make a link that pairs a new machine
    ///
    /// The link pairs one machine until it runs out, as the web UI's Pair a machine card makes one: on Linux paste it into `nerve-node center add -`, on Windows open it. It asks the running center.
    Pair,
    /// Show the paired machines, or turn one off, on, or remove it
    ///
    /// As the web UI's Overview shows and changes them. A machine that is off keeps its pairing, and the agent cannot use it until it is on again. It asks the running center.
    #[command(args_conflicts_with_subcommands = true)]
    Nodes {
        #[command(subcommand)]
        cmd: Option<NodesCmd>,
    },
    /// Make, list or remove the harness tokens of the HTTP MCP endpoint
    ///
    /// A new token is shown once, as the web UI's Connect a harness card shows it; the center keeps only its hash. It asks the running center.
    #[command(subcommand)]
    Token(TokenCmd),
    /// Show the center's log: its starts, its machines, and what went wrong
    ///
    /// The log file in its state folder, the older one first.
    Log {
        /// Keep running and print new lines as they arrive.
        #[arg(long)]
        follow: bool,
        /// Show only the newest N lines (with --follow, then the new ones).
        #[arg(long, value_name = "N")]
        last: Option<usize>,
        /// Show only errors and warnings (with --last, the newest N of them).
        #[arg(long)]
        problems: bool,
    },
    /// Print the files of the service this program installs, as JSON (for `update`)
    ///
    /// The files besides the program itself: `update` runs the new program so, to put them in place with it.
    #[command(hide = true)]
    ServiceFiles,
}

/// What `service` does to the installed center.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Subcommand)]
pub enum ServiceCmd {
    /// Start the installed center.
    Start,
    /// Stop it: the machines lose their link, and harnesses their tools.
    Stop,
    /// Stop it and start it again.
    Restart,
}

/// What `nodes` changes of a paired machine, by its name.
#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum NodesCmd {
    /// Turn a machine off: its link ends and the agent cannot use it.
    Disable {
        /// The machine's name, as `nodes` shows it.
        name: String,
    },
    /// Turn a machine on again.
    Enable {
        /// The machine's name, as `nodes` shows it.
        name: String,
    },
    /// Remove a machine: the pairing ends, and it pairs again with a new link.
    Rm {
        /// The machine's name, as `nodes` shows it.
        name: String,
    },
}

/// What `token` does with the harness tokens.
#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum TokenCmd {
    /// Make a harness token; it is shown once.
    New {
        /// A label to tell it apart, like the harness's name (`harness` if left out).
        label: Option<String>,
    },
    /// List the harness tokens by their labels.
    List,
    /// Remove a harness token: a harness that uses it is refused at once.
    Rm {
        /// The token's label, as `token list` shows it, or its id.
        label: String,
    },
}

impl Cmd {
    /// install, set, update, uninstall and service start|stop|restart: they
    /// work on the installed service, as root, not on `--state-dir`.
    /// `install` takes the settings it writes into the service's file
    /// ([`INSTALL_SETTINGS`]), and `set` changes one of them there.
    pub fn is_service(&self) -> bool {
        matches!(
            self,
            Cmd::Install
                | Cmd::Set { .. }
                | Cmd::Update { .. }
                | Cmd::Uninstall { .. }
                | Cmd::Service { cmd: Some(_) }
        )
    }

    /// Whether this is how Windows starts the installed center: `service`
    /// alone.
    pub fn runs_the_service(&self) -> bool {
        matches!(self, Cmd::Service { cmd: None })
    }
}

/// The settings `install` takes and writes into the service's settings
/// file, by flag and variable. `set` changes the same ones, by the flag's
/// name without its dashes ([`set_names`]).
pub const INSTALL_SETTINGS: &[(&str, &str)] = &[
    ("--name", "NERVE_CENTER_NAME"),
    ("--public-url", "NERVE_CENTER_PUBLIC_URL"),
    ("--listen", "NERVE_CENTER_LISTEN"),
    ("--ui", "NERVE_CENTER_UI"),
    ("--mcp", "NERVE_CENTER_MCP"),
];

/// The names `set` takes, as [`INSTALL_SETTINGS`] has them: `name`,
/// `public-url`, `listen`, `ui` and `mcp`.
fn set_names() -> clap::builder::PossibleValuesParser {
    clap::builder::PossibleValuesParser::new(
        INSTALL_SETTINGS
            .iter()
            .map(|(flag, _)| flag.trim_start_matches('-')),
    )
}

/// The variable of the setting `set` takes by `name` ([`INSTALL_SETTINGS`]).
pub fn set_variable(name: &str) -> Option<&'static str> {
    INSTALL_SETTINGS
        .iter()
        .find(|(flag, _)| flag.trim_start_matches('-') == name)
        .map(|(_, var)| *var)
}

/// The command line as `main` parses it: [`Args`], whose `--help` and
/// `help` print the top page of [`top_help`], and each command's own page
/// with [`VARIABLES`] under its options.
pub fn command() -> clap::Command {
    use clap::CommandFactory;
    let cmd = Args::command();
    let top = top_help(&cmd);
    let names: Vec<String> = cmd
        .get_subcommands()
        .map(|c| c.get_name().to_string())
        .collect();
    names
        .iter()
        .fold(cmd, |cmd, name| {
            cmd.mut_subcommand(name, |c| c.after_help(VARIABLES))
        })
        .help_template(TOP_TEMPLATE)
        .after_help(top)
}

/// The top page of `--help` and `help`: the about line, the usage, and
/// what [`top_help`] lists.
const TOP_TEMPLATE: &str = "{about-with-newline}\n{usage-heading} {usage}{after-help}";

/// The line under the options: each has a variable of the same name, as
/// the installed service's settings file sets them, and clap's `[env: …]`
/// after each would say it ten times.
pub const VARIABLES: &str = "Each option can also be set as NERVE_CENTER_<NAME> (--public-url as NERVE_CENTER_PUBLIC_URL), as the installed service's settings file does.";

/// What the center does without a command, the line of `Run` on the top
/// page.
const RUN_LINE: &str =
    "Run the center for a harness, with MCP on stdin; --mcp http runs it on its own";

/// Where each command stands on the top page, by what the owner wants to
/// do. A command missing here fails a test until it is placed.
const COMMAND_GROUPS: &[(&str, &[&str])] = &[
    (
        "The service",
        &["install", "set", "service", "update", "uninstall"],
    ),
    (
        "The owner's commands",
        &[
            "status",
            "pair",
            "nodes",
            "token",
            "log",
            "owner-token",
            "backup",
            "restore",
        ],
    ),
];

/// The commands in their groups and the options under Settings and
/// Advanced, one line each with the default where there is one, read from
/// the definition of `cmd`; then [`VARIABLES`] and how to read more.
fn top_help(cmd: &clap::Command) -> String {
    let program = cmd.get_name();
    let mut groups = vec![("Run", vec![(program.to_string(), RUN_LINE.to_string())])];
    for (heading, names) in COMMAND_GROUPS {
        let lines = names
            .iter()
            .filter_map(|n| cmd.find_subcommand(n))
            .map(|c| {
                let about = c.get_about().map(ToString::to_string);
                (c.get_name().to_string(), about.unwrap_or_default())
            })
            .collect();
        groups.push((heading, lines));
    }
    let options: Vec<(String, String, bool)> = top_options(cmd)
        .map(|a| {
            let advanced = a.get_help_heading() == Some("Advanced");
            (option_name(a), option_line(a), advanced)
        })
        .collect();
    let options = [("Settings", false), ("Advanced", true)].map(|(heading, advanced)| {
        let lines = options
            .iter()
            .filter(|(.., a)| *a == advanced)
            .map(|(n, l, _)| (n.clone(), l.clone()))
            .collect();
        (heading, lines)
    });
    let mut out = String::new();
    for list in [&groups[..], &options[..]] {
        let width = list
            .iter()
            .flat_map(|(_, lines)| lines.iter().map(|(n, _): &(String, String)| n.len()))
            .max()
            .unwrap_or(0);
        for (heading, lines) in list {
            out.push_str(&format!("{heading}:\n"));
            for (name, line) in lines {
                out.push_str(&format!("  {name:width$}  {line}\n"));
            }
            out.push('\n');
        }
    }
    out.push_str(VARIABLES);
    out.push_str(&format!(
        "\n`{program} help <command>` says all of one command; `{program} --version` prints the version."
    ));
    out
}

/// The options of the top page: all but `--help` and `--version`, which
/// its last line names.
fn top_options(cmd: &clap::Command) -> impl Iterator<Item = &clap::Arg> {
    cmd.get_arguments()
        .filter(|a| !a.is_hide_set() && a.get_long().is_some_and(|l| l != "help" && l != "version"))
}

/// An option as it is written: `--ui <ADDRESS>`, `--plain-loopback`.
fn option_name(a: &clap::Arg) -> String {
    let long = a.get_long().unwrap_or_default();
    match a.get_value_names().and_then(|v| v.first()) {
        Some(value) if a.get_action().takes_values() => format!("--{long} <{value}>"),
        _ if a.get_action().takes_values() => {
            format!("--{long} <{}>", a.get_id().as_str().to_uppercase())
        }
        _ => format!("--{long}"),
    }
}

/// An option's line: its help and, where it has one, its default.
fn option_line(a: &clap::Arg) -> String {
    let line = a.get_help().map(ToString::to_string).unwrap_or_default();
    match a.get_default_values().first() {
        Some(d) if a.get_action().takes_values() => format!("{line} ({})", d.to_string_lossy()),
        _ => line,
    }
}

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

/// Refuses the state folder of an owner command (`status`, `owner-token`,
/// `backup`, `restore`) when an administrator's terminal took it from the
/// variable `NERVE_CENTER_STATE_DIR`. An elevated terminal on Windows takes
/// the account's own variables, which any unelevated program of the account
/// writes, so a restore or a backup would go to a folder of that program's
/// instead of the installed center's; `sudo` drops the variable on Linux
/// (round 7, security 2). `given` is [`settings_given`]; `elevated` is
/// whether this is Windows and the process an administrator's.
pub fn refuse_state_variable(given: &[String], elevated: bool) -> Result<(), String> {
    if elevated && given.iter().any(|g| g == "NERVE_CENTER_STATE_DIR") {
        return Err("NERVE_CENTER_STATE_DIR is set in this terminal, and an administrator's terminal takes the variables of the account's other programs too; give the folder with --state-dir, or clear the variable".into());
    }
    Ok(())
}

/// An administrator's `install` takes `--name`, `--public-url`, `--listen`,
/// `--ui` and `--mcp` from the flags only: the variables of the account, which its other
/// programs may set, would go into the settings file the service trusts and
/// into the firewall rule (round 9, security 1). `given` is
/// [`settings_given`]; `elevated` as for [`refuse_state_variable`].
pub fn refuse_install_variables(given: &[String], elevated: bool) -> Result<(), String> {
    if !elevated {
        return Ok(());
    }
    for (flag, var) in INSTALL_SETTINGS {
        if given.iter().any(|g| g == var) {
            return Err(format!(
                "{var} is set in this terminal, and an administrator's terminal takes the variables of the account's other programs too; give {flag} instead, or clear the variable"
            ));
        }
    }
    Ok(())
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

    /// The public URL, from the flag (with `{port}` as `port`) or from the
    /// host name and the port.
    pub fn public_url(&self, port: u16) -> String {
        if let Some(u) = &self.public_url {
            return u.replace("{port}", &port.to_string());
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

/// What `nerve-center` says when it is started by hand at a terminal with
/// MCP on stdin: it would seem to hang, waiting for a harness. `program` is
/// the program as it was started (`nerve-center`, or the downloaded file
/// on Windows, which is on no `PATH` before `install`), so the command it
/// names runs as it is typed.
pub fn terminal_notice(mcp: &McpMode, stdin_is_terminal: bool, program: &str) -> Option<String> {
    (*mcp == McpMode::Stdio && stdin_is_terminal).then(|| {
        format!(
            "nerve-center: waiting for MCP on stdin, as a harness starts it: what you type here goes to the center as MCP, so type no commands here. To sign in to its web UI, run `{program} owner-token` in another terminal and use the token it prints. {} runs it as a service; `{program} --help` lists the commands.",
            crate::service::admin_command("install")
        )
    })
}

/// Whether a double-click in Explorer started the center: no arguments,
/// a console of its own (`alone`, nerve_service::win::console) and that
/// console as stdin. A person meant to install it then, not to run a
/// harness's center in a window that ends it when it closes; a harness
/// gives a pipe on stdin, and a terminal shares its console with the shell.
pub fn double_clicked(arguments: usize, stdin_is_terminal: bool, alone: bool) -> bool {
    arguments == 0 && stdin_is_terminal && alone
}

/// The program as the person started it, for [`terminal_notice`]:
/// `nerve-center` when it was found by name, else the path given.
pub fn started_as(arg0: Option<std::ffi::OsString>) -> String {
    let given = arg0
        .map(|a| a.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name = std::path::Path::new(&given)
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    if given.is_empty() || (name == "nerve-center" && !given.contains(['/', '\\'])) {
        "nerve-center".into()
    } else if given.contains(' ') {
        // PowerShell runs a quoted path with `&`; a Unix shell takes it
        // quoted as it is.
        if cfg!(windows) {
            format!("& '{given}'")
        } else {
            format!("'{given}'")
        }
    } else {
        given
    }
}

/// The URL a person or a harness reaches the address `a` at: http on
/// loopback, https beyond it, and this machine's name for an address that
/// listens on all of them (`0.0.0.0`, `[::]`), which no client connects to.
pub fn address_url(a: &str) -> String {
    if is_loopback(a) {
        return format!("http://{a}");
    }
    match a.parse::<std::net::SocketAddr>() {
        Ok(s) if s.ip().is_unspecified() => {
            format!("https://{}:{}", crate::center::host_name(), s.port())
        }
        _ => format!("https://{a}"),
    }
}

/// [`address_url`] of `a` with the port the listener got, for a port 0.
pub fn address_url_on(a: &str, port: u16) -> String {
    match a.rsplit_once(':') {
        Some((host, _)) => address_url(&format!("{host}:{port}")),
        None => address_url(a),
    }
}

#[cfg(test)]
mod tests {
    /// By hand at a terminal the center says what it waits for (round 2,
    /// spec 3); under a harness, with a pipe on stdin, it says nothing.
    #[test]
    fn a_center_at_a_terminal_says_it_waits_for_mcp() {
        let say = terminal_notice(&McpMode::Stdio, true, "nerve-center").unwrap();
        assert!(say.contains("waiting for MCP on stdin"), "{say}");
        // A person at that terminal types a command into the center's MCP
        // input, and finds no token (#213): it says both.
        assert!(say.contains("type no commands here"), "{say}");
        assert!(
            say.contains("run `nerve-center owner-token` in another terminal"),
            "{say}"
        );
        assert!(
            say.contains(&crate::service::admin_command("install")),
            "{say}"
        );
        assert_eq!(
            terminal_notice(&McpMode::Stdio, false, "nerve-center"),
            None
        );
        // On Windows the downloaded file is on no PATH before `install`:
        // the command is named as it was started.
        let started = started_as(Some(r".\nerve-center-x86_64-windows.exe".into()));
        assert_eq!(started, r".\nerve-center-x86_64-windows.exe");
        let say = terminal_notice(&McpMode::Stdio, true, &started).unwrap();
        assert!(
            say.contains(r"run `.\nerve-center-x86_64-windows.exe owner-token`"),
            "{say}"
        );
        assert_eq!(started_as(Some("nerve-center".into())), "nerve-center");
        assert_eq!(started_as(None), "nerve-center");
        let spaced = started_as(Some(r"C:\My Tools\nerve-center.exe".into()));
        let want = if cfg!(windows) {
            r"& 'C:\My Tools\nerve-center.exe'"
        } else {
            r"'C:\My Tools\nerve-center.exe'"
        };
        assert_eq!(spaced, want);
        assert_eq!(terminal_notice(&McpMode::Off, true, "nerve-center"), None);
    }

    /// A double-click installs (#213): no arguments, a console of its own
    /// as stdin. A harness (a pipe), a terminal (shared with the shell) and
    /// any command keep the center as it was.
    #[test]
    fn only_a_double_click_installs() {
        assert!(double_clicked(0, true, true));
        assert!(!double_clicked(0, false, true), "a harness gives a pipe");
        assert!(
            !double_clicked(0, true, false),
            "a terminal's shell shares it"
        );
        assert!(!double_clicked(1, true, true), "a command was given");
    }

    use super::*;

    /// An address that listens on all of them is named by the machine's
    /// name, as a harness connects to it (round 1, correctness 12).
    #[test]
    fn a_wildcard_address_is_reached_by_the_machines_name() {
        let host = crate::center::host_name();
        assert_eq!(address_url("0.0.0.0:7481"), format!("https://{host}:7481"));
        assert_eq!(address_url("[::]:7481"), format!("https://{host}:7481"));
        assert_eq!(address_url("127.0.0.1:7481"), "http://127.0.0.1:7481");
        assert_eq!(address_url("10.0.0.5:7481"), "https://10.0.0.5:7481");
        // A port 0 is named by the port the listener got.
        assert_eq!(
            address_url_on("0.0.0.0:0", 4321),
            format!("https://{host}:4321")
        );
        assert_eq!(
            address_url_on("[::]:0", 4321),
            format!("https://{host}:4321")
        );
        assert_eq!(address_url_on("10.0.0.5:0", 4321), "https://10.0.0.5:4321");
    }

    /// Every command answers `--help` and `-h`, not only the top level
    /// (round 4, correctness 1): turning clap's own flag off had taken it
    /// from the subcommands too.
    #[test]
    fn status_takes_the_web_ui_and_mcp_flags_after_its_name() {
        let a = Args::try_parse_from(["nerve-center", "status", "--ui", "127.0.0.1:7490"])
            .expect("--ui after status");
        assert_eq!(a.ui, "127.0.0.1:7490");
        assert!(Args::try_parse_from(["nerve-center", "status", "--mcp", "off"]).is_ok());
    }

    #[test]
    fn every_command_has_its_own_help_flag() {
        for c in command().get_subcommands() {
            for flag in ["--help", "-h"] {
                let e = command()
                    .try_get_matches_from(["nerve-center", c.get_name(), flag])
                    .expect_err("help is no run");
                assert_eq!(
                    e.kind(),
                    clap::error::ErrorKind::DisplayHelp,
                    "{} {flag}",
                    c.get_name()
                );
            }
        }
    }

    /// `--help`, `-h` and `help` print one page (#229): every command in
    /// its group and every option under Settings or Advanced, one line
    /// each with its default; the variables once, under the options, not
    /// `[env: …]` after each.
    #[test]
    fn the_top_help_is_one_line_per_command_and_option() {
        let page = |args: &[&str]| {
            let e = command()
                .try_get_matches_from(std::iter::once("nerve-center").chain(args.iter().copied()))
                .expect_err("help is no run");
            e.render().to_string()
        };
        let top = page(&["--help"]);
        assert_eq!(page(&["-h"]), top);
        assert_eq!(page(&["help"]), top);
        assert!(
            !top.contains("[env:") && !top.contains("[default:"),
            "{top}"
        );
        assert!(top.contains(&format!("\n{VARIABLES}\n")), "{top}");
        for heading in [
            "Run",
            "The service",
            "The owner's commands",
            "Settings",
            "Advanced",
        ] {
            assert!(top.contains(&format!("\n{heading}:\n")), "{heading}: {top}");
        }
        let line_of = |name: &str| {
            let lines: Vec<&str> = top
                .lines()
                .filter(|l| l.split_whitespace().next() == Some(name))
                .collect();
            assert_eq!(lines.len(), 1, "{name}: {top}");
            lines[0].to_string()
        };
        // Every command a person runs is placed in a group, once.
        let cmd = command();
        for c in cmd
            .get_subcommands()
            .filter(|c| !c.is_hide_set() && c.get_name() != "help")
        {
            let line = line_of(c.get_name());
            assert!(
                line.ends_with(&c.get_about().unwrap().to_string()),
                "{line}"
            );
        }
        assert!(line_of("set").contains("Show or change the installed center's settings"));
        assert!(!top.contains("service-files"), "{top}");
        // Every option, with its default where it has one.
        for a in top_options(&cmd) {
            assert!(
                top.contains(&format!("  {}  ", option_name(a))),
                "{}",
                option_name(a)
            );
        }
        assert!(
            line_of("--ui").ends_with("  The web UI address, or off (127.0.0.1:7480)"),
            "{top}"
        );
        assert!(line_of("--call-wait").ends_with("(20s)"), "{top}");
        // The line under the options holds: each option has the variable
        // NERVE_CENTER_<NAME>, its name in capitals with `_` for `-`.
        for a in top_options(&cmd) {
            let long = a.get_long().unwrap();
            let want = format!("NERVE_CENTER_{}", long.to_uppercase().replace('-', "_"));
            let env = a.get_env().map(|e| e.to_string_lossy().into_owned());
            assert_eq!(env, Some(want), "--{long}");
        }
        assert!(
            line_of("--plain-loopback").ends_with("loopback --listen only"),
            "{top}"
        );
        // A command's own page has the whole text and the variables' line.
        let set = page(&["help", "set"]);
        assert!(set.contains("Alone, it shows the settings"), "{set}");
        assert!(set.contains(VARIABLES) && !set.contains("[env:"), "{set}");
        assert!(page(&["set", "--help"]).contains("Usage: nerve-center set"));
    }

    /// A long help adds to its line and does not say it again (#229): the
    /// text after the line does not start with the line's first words.
    #[test]
    fn no_long_help_says_its_line_again() {
        let first_words = |t: &str| {
            t.split_whitespace()
                .take(2)
                .map(str::to_lowercase)
                .collect::<Vec<_>>()
        };
        let mut said_again = Vec::new();
        let mut check = |what: String, line: Option<String>, long: Option<String>| {
            let (Some(line), Some(long)) = (line, long) else {
                return;
            };
            let rest = long.strip_prefix(&line).unwrap_or(&long).trim();
            if !rest.is_empty() && first_words(rest) == first_words(&line) {
                said_again.push(format!("{what}: {rest}"));
            }
        };
        let cmd = command();
        for c in std::iter::once(&cmd).chain(cmd.get_subcommands()) {
            check(
                c.get_name().to_string(),
                c.get_about().map(|a| a.to_string()),
                c.get_long_about().map(|a| a.to_string()),
            );
            for a in c.get_arguments() {
                check(
                    format!("{} {}", c.get_name(), a.get_id()),
                    a.get_help().map(|h| h.to_string()),
                    a.get_long_help().map(|h| h.to_string()),
                );
            }
        }
        assert!(said_again.is_empty(), "{said_again:#?}");
    }

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

    /// An administrator's terminal does not steer the owner's commands to a
    /// state folder by a variable; the flag works, and an unelevated start
    /// (a harness's, a person's) takes the variable as ever.
    #[test]
    fn an_elevated_command_takes_the_state_folder_from_the_flag_only() {
        let var = vec!["NERVE_CENTER_STATE_DIR".to_string()];
        let flag = vec!["--state-dir".to_string()];
        let e = refuse_state_variable(&var, true).unwrap_err();
        assert!(
            e.contains("NERVE_CENTER_STATE_DIR") && e.contains("--state-dir"),
            "{e}"
        );
        assert!(refuse_state_variable(&flag, true).is_ok());
        assert!(refuse_state_variable(&[], true).is_ok());
        assert!(refuse_state_variable(&var, false).is_ok());
    }

    /// An elevated `install` takes its settings from the flags only.
    #[test]
    fn an_elevated_install_takes_its_settings_from_the_flags_only() {
        for (flag, var) in INSTALL_SETTINGS {
            let v = vec![var.to_string()];
            let e = refuse_install_variables(&v, true).unwrap_err();
            assert!(e.contains(var) && e.contains(flag), "{e}");
            assert!(refuse_install_variables(&v, false).is_ok());
            assert!(refuse_install_variables(&[flag.to_string()], true).is_ok());
        }
        assert!(refuse_install_variables(&[], true).is_ok());
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
        // `install` takes its settings after its name too, as the docs
        // write it, and the value is the program's.
        assert_eq!(
            given(&[
                "install",
                "--name",
                "lab",
                "--public-url",
                "https://lab.example:7443",
                "--listen",
                "0.0.0.0:9443"
            ]),
            ["--name", "--listen", "--public-url"]
        );
        let a = Args::try_parse_from([
            "nerve-center",
            "install",
            "--name",
            "lab",
            "--listen",
            "0.0.0.0:9443",
        ])
        .unwrap();
        assert_eq!(
            (a.name.as_deref(), a.listen.as_str()),
            (Some("lab"), "0.0.0.0:9443")
        );
        assert_eq!(
            given(&["--state-dir", "/srv/c", "install"]),
            ["--state-dir"]
        );
        assert_eq!(
            given(&["--listen", "0.0.0.0:9443", "--ui", "off", "update"]),
            ["--listen", "--ui"]
        );
        // `install --ui --mcp` (#229): the web UI and MCP beyond loopback
        // from the first install.
        assert_eq!(
            given(&["install", "--ui", "0.0.0.0:7480", "--mcp", "0.0.0.0:7481"]),
            ["--ui", "--mcp"]
        );
        // `set` takes its setting by name, not as a flag.
        assert!(given(&["set", "ui", "0.0.0.0:7480"]).is_empty());
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
        // A URL given names the port the center got for a --listen of
        // port 0 (#40, shared-2).
        let given = |url: &str| {
            Args::try_parse_from(["nerve-center", "--public-url", url])
                .unwrap()
                .public_url(4711)
        };
        assert_eq!(given("https://127.0.0.1:{port}"), "https://127.0.0.1:4711");
        assert_eq!(given("https://c.example:7443"), "https://c.example:7443");
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
        assert!(Args::try_parse_from(["nerve-center", "serve"]).is_err());
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
        // `service start|stop|restart` is the service's, as root; bare,
        // it is how Windows starts the installed center (#213).
        assert_eq!(
            cmd(&["service", "restart"]),
            Some(Cmd::Service {
                cmd: Some(ServiceCmd::Restart)
            })
        );
        assert!(cmd(&["service", "stop"]).unwrap().is_service());
        assert!(cmd(&["service"]).unwrap().runs_the_service());
        assert!(!cmd(&["service"]).unwrap().is_service());
        // The owner's commands that ask the running center are no service
        // commands: they go to the state folder.
        for (args, want) in [
            (&["pair"][..], Cmd::Pair),
            (&["nodes"], Cmd::Nodes { cmd: None }),
            (
                &["nodes", "disable", "lab"],
                Cmd::Nodes {
                    cmd: Some(NodesCmd::Disable { name: "lab".into() }),
                },
            ),
            (&["token", "new"], Cmd::Token(TokenCmd::New { label: None })),
            (
                &["token", "rm", "ci"],
                Cmd::Token(TokenCmd::Rm { label: "ci".into() }),
            ),
            (
                &["log", "--last", "5", "--problems"],
                Cmd::Log {
                    follow: false,
                    last: Some(5),
                    problems: true,
                },
            ),
        ] {
            let c = cmd(args).unwrap();
            assert!(!c.is_service() && !c.runs_the_service(), "{args:?}");
            assert_eq!(c, want);
        }
        assert!(Args::try_parse_from(["nerve-center", "token"]).is_err());
        // `set` alone lists, `set <name> <value>` changes one; a name
        // without a value, or a name that is no setting of it, is refused.
        assert_eq!(
            cmd(&["set"]),
            Some(Cmd::Set {
                setting: None,
                value: None
            })
        );
        assert_eq!(
            cmd(&["set", "ui", "0.0.0.0:7480"]),
            Some(Cmd::Set {
                setting: Some("ui".into()),
                value: Some("0.0.0.0:7480".into())
            })
        );
        assert!(cmd(&["set"]).unwrap().is_service());
        assert!(Args::try_parse_from(["nerve-center", "set", "ui"]).is_err());
        assert!(Args::try_parse_from(["nerve-center", "set", "harness-token", "x"]).is_err());
        for (flag, var) in INSTALL_SETTINGS {
            let name = flag.trim_start_matches('-');
            assert_eq!(set_variable(name), Some(*var));
            assert!(cmd(&["set", name, "x"]).is_some(), "{name}");
        }
        assert!(
            is_loopback("127.0.0.1:7480") && is_loopback("[::1]:1") && !is_loopback("0.0.0.0:7480")
        );
    }
}
