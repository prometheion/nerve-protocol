//! The `nerve-node` command line (docs/dev/settings-and-config.md). Commands talk to the
//! running daemon over the control socket (on Windows the folder changes
//! over its control pipe, crate::pipe); when none runs they edit the config
//! file directly through the same [`SettingsStore`], which signs it.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Args, CommandFactory, Parser, Subcommand};
use serde::Serialize;
use serde_json::{Value, json};

use nerve_policy::audit::AuditLog;
use nerve_policy::config::{Access, CapSetting, Folder, SecretStorage, SettingsGrant};
use nerve_policy::{Mode, NodeConfig, SetError, SettingsStore, rules, sudo_command};
use nerve_proto::link::PairLink;

use crate::daemon::{Daemon, NodeOptions};
use crate::folder_change::{Applied, FolderChange};
use crate::paths::NodePaths;
use crate::service::{Host, Layout};

mod json;

#[derive(Debug, Parser)]
#[command(
    name = "nerve-node",
    version,
    about = "Links this machine to its Nerve centers."
)]
pub struct Cli {
    /// Where node.toml and the keys live [env: NERVE_CONFIG_DIR] [default: ~/.config/nerve, or /etc/nerve when installed as a service]
    #[arg(long, global = true)]
    pub config_dir: Option<PathBuf>,
    /// Where the control socket and the audit log live [env: NERVE_STATE_DIR] [default: ~/.local/state/nerve, or /var/lib/nerve/state when installed as a service]
    #[arg(long, global = true)]
    pub state_dir: Option<PathBuf>,
    /// Print JSON for programs instead of text: the read commands their data, the others the lines they print, an error {"error": ...}
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub cmd: Cmd,
}

/// Picks one paired center; required when several are paired.
#[derive(Debug, Args, Clone, Default)]
pub struct CenterArg {
    /// Which center, when more than one is paired.
    #[arg(long)]
    pub center: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Pair this machine with centers and decide what each one may change.
    #[command(subcommand)]
    Center(CenterCmd),
    /// Choose the folders a center may use and what it may do in each.
    #[command(subcommand)]
    Folder(FolderCmd),
    /// Choose how much a center may do: only what allow rules name, what each folder allows (as nerve-run, an account of its own), or all you can do (as you).
    #[command(subcommand)]
    Mode(ModeCmd),
    /// Keep the lists of commands that are allowed, forbidden or run with sudo.
    #[command(subcommand)]
    Rule(RuleCmd),
    /// Turn capabilities and single actions on or off.
    #[command(subcommand)]
    Cap(CapCmd),
    /// Use sudo for the commands on the sudo list.
    #[command(subcommand)]
    Sudo(SudoCmd),
    /// Choose the proxy the node uses to reach centers.
    #[command(subcommand)]
    Proxy(ProxyCmd),
    /// Let nodes that cannot reach a center themselves reach this node's centers through it.
    #[command(subcommand)]
    Relay(RelayCmd),
    /// Read or change any setting in node.toml by its name.
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Run the node in the foreground.
    Run,
    /// Show whether the node runs and which centers it is paired with.
    Status,
    /// Show what the node allowed and refused.
    #[command(args_conflicts_with_subcommands = true)]
    Audit {
        #[command(subcommand)]
        clear: Option<AuditCmd>,
        /// Keep running and print new entries as they arrive.
        #[arg(long)]
        follow: bool,
        /// Show only the calls that were refused.
        #[arg(long)]
        denied: bool,
        /// Show only the newest N entries (with --follow, then the new ones).
        #[arg(long, value_name = "N")]
        last: Option<usize>,
    },
    /// Show the node's log: its starts and stops, its links, and what went wrong.
    #[command(args_conflicts_with_subcommands = true)]
    Log {
        #[command(subcommand)]
        clear: Option<LogCmd>,
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
    /// Stop everything at once; nothing runs until `unlock`.
    Panic,
    /// Let the node work again after `panic`.
    Unlock,
    /// Install the node as a service that starts with the machine and runs under a user of its own, make the account nerve-run for its commands and take you as the owner (Linux with sudo from your own account, Windows as administrator).
    Install {
        /// Run by root itself (Linux): `root` makes root the owner, so that user mode, and allowlist mode as the owner, run commands as root, with every right on the machine and over Nerve; needs --accept-root-owner. At a terminal install asks instead, and an owner root confirmed before stays. `none` leaves the node without an owner, root or another.
        #[arg(long, value_name = "ACCOUNT", value_parser = ["root", "none"])]
        owner: Option<String>,
        /// Confirms --owner=root: you accept that nothing in Nerve holds those commands back.
        #[arg(long)]
        accept_root_owner: bool,
    },
    /// Name the node, choose where it keeps its keys, pair the first center and choose its mode and folder, one question at a time.
    Setup,
    /// Replace the installed program with the latest release and restart the service; config, keys and audit log stay.
    Update {
        /// Take the new program from this file instead of downloading the latest release.
        #[arg(long, value_name = "FILE")]
        from: Option<PathBuf>,
    },
    /// Start, stop or restart the installed service, or show its state.
    #[command(subcommand)]
    Service(ServiceCmd),
    /// Stop and remove the service, nerve-run and its entries on your folders, the node's user and the program; the config and state folders stay.
    Uninstall {
        /// Delete the config and state folders too: the keys, the pairings and the audit log.
        #[arg(long)]
        purge: bool,
    },
    /// Write the config and the keys to a file that a passphrase protects, to keep or to move the node to another machine.
    Backup {
        /// The file to write. It is private to you (mode 0600).
        file: PathBuf,
        /// Also take the keys that are in the system keyring into the file; without it they stay there and are left out.
        #[arg(long)]
        include_keyring: bool,
        /// Replace the file when it exists.
        #[arg(long)]
        overwrite: bool,
        /// Read the passphrase from the first line of this file instead of asking.
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<PathBuf>,
    },
    /// Put the config and keys of a backup in place of this node's. The node must not run.
    Restore {
        /// The backup file.
        file: PathBuf,
        /// Replace a node here that is not the one the backup is of.
        #[arg(long)]
        replace: bool,
        /// Keep the keys in `file` or in the system `keyring` here, whatever the backup's config says.
        #[arg(long, value_name = "file|keyring")]
        secret_storage: Option<String>,
        /// Leave the proxy out of the restored config, with its password and header values; set it again on this machine.
        #[arg(long)]
        without_proxy: bool,
        /// Read the passphrase from the first line of this file instead of asking.
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
pub enum CenterCmd {
    /// Pair this machine with a center, using the pairing link it showed.
    Add {
        /// The pairing link.
        link: String,
        /// The name to use for the center here (the center's own name if left out).
        #[arg(long)]
        name: Option<String>,
        /// Do not ask before pairing.
        #[arg(long)]
        yes: bool,
    },
    /// Forget a center and delete its key.
    Rm(CenterArg),
    /// List the paired centers and how they are set.
    Ls,
    /// Stop the link to a center until you resume it.
    Pause(CenterArg),
    /// Link to a paused center again.
    Resume(CenterArg),
    /// Give this machine a new key for a center; the center takes the old one for 7 more days. Needs the running node, linked to that center.
    RotateKey {
        /// End the 7 days now: the center takes only the new key from then on.
        #[arg(long)]
        end_grace: bool,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Let a center change its own rights on this machine, up to user mode and sudo, or take that right away.
    Grant {
        /// What to grant; only `settings` exists.
        what: String,
        /// `off`, or `write`: the center may then set everything this machine lets it do.
        value: String,
        #[command(flatten)]
        center: CenterArg,
    },
}

#[derive(Debug, Subcommand)]
pub enum ModeCmd {
    /// Pick allowlist, folder or user mode.
    Set {
        /// `allowlist` (only what an allow rule names, as nerve-run), `folder`
        /// (what each folder's rights allow, as nerve-run, the default; on
        /// the installed node a file call may also read what every account
        /// may read) or
        /// `user` (anything you could do yourself, as you, protected files
        /// aside).
        mode: String,
        /// Go back to allowlist after this many hours (folder and user mode
        /// otherwise stay until you change them).
        #[arg(long = "for", value_name = "HOURS")]
        for_hours: Option<u64>,
        /// With allowlist: run the allowed commands as you instead of as
        /// nerve-run, outside the folders' sandbox (installed node, Linux).
        #[arg(long)]
        as_owner: bool,
        #[command(flatten)]
        center: CenterArg,
    },
}

/// The three lists of commands in a center's policy.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum List {
    Allow,
    Deny,
    Sudo,
}

#[derive(Debug, Subcommand)]
pub enum RuleCmd {
    /// Put a command on a list.
    Add {
        /// The list: `allow` (may run in allowlist mode), `deny` (a command
        /// line that matches never runs, in any mode) or `sudo` (may run with
        /// sudo while sudo is on).
        list: List,
        /// The command line.
        command: String,
        /// Cover every command that starts with the same program.
        #[arg(long)]
        wildcard: bool,
        /// Make the rule of an audit entry of this action instead, as the audit buttons do: `fs.read` takes a path and covers its folder with --wildcard, an action without a target takes "" and covers its capability.
        #[arg(long, value_name = "CAP.ACTION")]
        action: Option<String>,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Take a command off a list.
    Rm {
        /// The list: `allow`, `deny` or `sudo`.
        list: List,
        /// The command line, or an entry as `ls` shows it.
        command: String,
        /// The entry was added with --wildcard.
        #[arg(long)]
        wildcard: bool,
        /// The entry was added with this --action.
        #[arg(long, value_name = "CAP.ACTION")]
        action: Option<String>,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Show one list, or all three.
    Ls {
        /// The list; all three if left out.
        list: Option<List>,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Change one entry of a list in place, as one change: the entry as `ls` shows it, and what it becomes.
    Edit {
        /// The list: `allow`, `deny` or `sudo`.
        list: List,
        /// The entry as `ls` shows it.
        entry: String,
        /// What it becomes: an entry as `ls` shows them (`exec.run:git status`, `fs.read:~/notes/*`; on the sudo list a sudo command's pattern), or a plain command line, which becomes the rule `add` makes of it.
        new: String,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Put the deny rules that keep a center's commands off this node itself (its programs, service, socket and folders) on the deny list, as a new pairing has them, in place of their older texts. They catch mistakes, not someone who hides the name.
    Guard {
        #[command(flatten)]
        center: CenterArg,
    },
}

#[derive(Debug, Subcommand)]
pub enum CapCmd {
    /// Set a capability (`fs`) or one action (`exec.run`) to on, off or hidden.
    Set {
        /// The capability (`fs`) or action (`exec.run`).
        cap: String,
        /// `on`, `off` or `hidden`.
        setting: String,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Show every capability: the node's own and those of the programs you allow, each action with what it does (its effect), where it comes from, and how each center has it set. A stopped node shows its own and the programs you allow.
    Ls {
        /// Only this center's settings.
        #[arg(long)]
        center: Option<String>,
    },
    /// Allow a program on this machine to add capabilities (a provider), remove it, or list them.
    #[command(subcommand)]
    Provider(ProviderCmd),
}

#[derive(Debug, Subcommand)]
pub enum ProviderCmd {
    /// Let the program EXE attach as the provider NAME; it replaces the program allowed under that name. The node checks that the program that attaches runs this very file.
    Allow {
        /// The provider's name, which its capabilities carry: 1 to 32 of a-z, 0-9 and `-`.
        name: String,
        /// The full path of the program's executable.
        exe: String,
    },
    /// Remove the program allowed as NAME; its capabilities leave at once.
    Rm {
        /// The provider's name.
        name: String,
    },
    /// Show the programs you allow, and on a running node whether each is attached.
    Ls,
}

#[derive(Debug, Subcommand, Clone, Copy)]
pub enum ServiceCmd {
    /// Start the installed service; the owner needs no root or administrator for it.
    Start,
    /// Stop it: the node ends its links and runs nothing until it starts again, at the latest with the machine.
    Stop,
    /// Stop it and start it again, so the node takes every change in node.toml.
    Restart,
    /// Show whether the node is installed as a service, whether it runs, and the program it runs with its version.
    Status,
}

#[derive(Debug, Subcommand)]
pub enum AuditCmd {
    /// Start the audit log afresh. The entries so far become its one older file (audit.jsonl.1, in place of the one before), and the new log begins with an entry of who cleared it.
    Clear,
}

#[derive(Debug, Subcommand)]
pub enum LogCmd {
    /// Empty the node's log and its older file. The new log begins with a line of who cleared it.
    Clear,
}

#[derive(Debug, Subcommand)]
pub enum SudoCmd {
    /// Turn sudo on; asks for your sudo password and keeps it in memory only (on Windows the password of the account commands run as, kept with DPAPI).
    On,
    /// Turn sudo off and forget the password.
    Off,
    /// Show whether sudo is on.
    Status,
}

#[derive(Debug, Subcommand)]
pub enum FolderCmd {
    /// Let a center use a folder; name at least one right: +r, +w or +x.
    Add {
        /// The folder.
        path: PathBuf,
        /// The rights: +r reads, +w writes, +x runs commands (`+r +x`, `+rw`).
        #[arg(value_name = "+r|+w|+x", required = true, num_args = 1..)]
        rights: Vec<String>,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Change what a center may do in a folder it already has.
    Set {
        /// The folder.
        path: PathBuf,
        /// The changes, applied left to right: `=rwx` sets exactly these
        /// rights, `+x` adds one, `-w` takes one away.
        #[arg(
            value_name = "=rwx|+x|-w",
            required = true,
            num_args = 1..,
            allow_hyphen_values = true
        )]
        changes: Vec<String>,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Take a folder away from a center.
    Rm {
        /// The folder.
        path: PathBuf,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Show a center's folders and their rights.
    Ls {
        #[command(flatten)]
        center: CenterArg,
    },
}

#[derive(Debug, Subcommand)]
pub enum ConfigCmd {
    /// Print one setting.
    Get {
        /// The dotted key of the setting, like `center.<name>.policy.mode`.
        key: String,
    },
    /// Change one setting.
    Set {
        /// The dotted key of the setting, like `center.<name>.policy.mode`.
        key: String,
        /// The new value.
        value: String,
    },
    /// Remove one setting (its default applies again).
    Unset {
        /// The dotted key of the setting, like `center.<name>.policy.mode`.
        key: String,
    },
    /// Append a value to a list.
    Add {
        /// The dotted key of a list, like `center.<name>.policy.allow`.
        key: String,
        /// The value to append.
        value: String,
    },
    /// Remove a value from a list.
    Remove {
        /// The dotted key of a list, like `center.<name>.policy.allow`.
        key: String,
        /// The value to remove.
        value: String,
    },
    /// Trust node.toml as it is now, after the node refused it for a change
    /// made outside nerve-node. Read the file first.
    Accept,
}

#[derive(Debug, Subcommand)]
pub enum ProxyCmd {
    /// Reach centers through an HTTP proxy. Header values and a password are kept in the system keyring, never in node.toml; the installed node on Windows takes neither.
    Set {
        /// The proxy, http://host:port, or http://user:password@host:port when it wants a login; https://... for another proxy reached over TLS; or the nerve://relay link a relay showed, which holds its address, pin and this node's token.
        url: String,
        /// The pin of an https:// proxy's certificate (a relay's: `nerve-node relay ls` there shows it); without it the system's roots check it.
        #[arg(long)]
        pin: Option<String>,
        /// A header for the proxy, `Name: value`; can be given more than once. The value goes into the system keyring.
        #[arg(long = "header", value_name = "NAME: VALUE")]
        headers: Vec<String>,
        /// Read the proxy's password from the first line of stdin, for a URL with a user name and no password (http://user@host:port); it never shows in the process list.
        #[arg(long)]
        password_stdin: bool,
        /// Read headers from stdin, one `Name: value` a line, after the password with --password-stdin.
        #[arg(long)]
        headers_stdin: bool,
    },
    /// Reach centers directly again, and delete the proxy's values from the system keyring.
    Rm,
    /// Show the proxy that is set and the names of its headers, never their values.
    Ls,
}

#[derive(Debug, Subcommand)]
pub enum RelayCmd {
    /// Turn the relay on: listen for other nodes at ADDRESS, like 0.0.0.0:7490. A node reaches only this node's own https centers through it.
    Set {
        /// The address and port to listen on, like 0.0.0.0:7490 or [::]:7490.
        address: String,
        /// Tunnels at once, over every relayed node (16 unless set).
        #[arg(long, value_name = "N")]
        max_links: Option<u32>,
        /// Tunnels at once of one relayed node (4 unless set).
        #[arg(long, value_name = "N")]
        max_links_per_node: Option<u32>,
        /// Tunnels one relayed node may open a minute, every node alike (30 unless set; for a relay behind this one, use `relay set-limits <name>`).
        #[arg(long, value_name = "N")]
        max_opens_per_minute: Option<u32>,
    },
    /// Turn the relay off: stop listening and end every tunnel. The nodes and their tokens stay.
    Off,
    /// Let a node use the relay: makes its token and shows it once, in a link the other node pastes. Without --center its tunnels may go to every https center of this node.
    Add {
        /// The relayed node's name here, 1 to 32 of a-z, 0-9 and -, starting and
        /// ending with a letter or digit.
        name: String,
        /// A center of this node the relayed node may reach; can be given more than once. Without it, every one.
        #[arg(long = "center", value_name = "CENTER")]
        centers: Vec<String>,
        /// Where the other node reaches this machine, HOST or HOST:PORT, for its link (without it: the address the relay listens on, else this machine's host name).
        #[arg(long, value_name = "HOST[:PORT]")]
        address: Option<String>,
    },
    /// Change which centers of this node a relayed node may reach; without --center, every one. Its tunnels to others end.
    SetCenters {
        /// The relayed node's name.
        name: String,
        /// A center of this node the relayed node may reach; can be given more than once.
        #[arg(long = "center", value_name = "CENTER")]
        centers: Vec<String>,
    },
    /// Give a relayed node limits of its own, in place of the relay's --max-links-per-node and --max-opens-per-minute: for a relay behind this one, which carries many nodes. A flag not given keeps that limit; without either flag, the relay's limits again.
    SetLimits {
        /// The relayed node's name.
        name: String,
        /// Its tunnels at once.
        #[arg(long, value_name = "N")]
        max_links: Option<u32>,
        /// The tunnels it may open a minute.
        #[arg(long, value_name = "N")]
        max_opens_per_minute: Option<u32>,
    },
    /// Give a relayed node a new token and end the tunnels of the old one; its centers and limits stay. Shows the token once, in a link the other node pastes.
    Token {
        /// The relayed node's name.
        name: String,
        /// Where the other node reaches this machine, HOST or HOST:PORT, for its link (as for `relay add`).
        #[arg(long, value_name = "HOST[:PORT]")]
        address: Option<String>,
    },
    /// Take a node's token away and end its tunnels.
    Rm {
        /// The relayed node's name.
        name: String,
    },
    /// Show the relay, the nodes that may use it and, on a running node, who is connected.
    Ls,
}

/// The command list as `nerve-node --help` has it, for anything that shows
/// the commands elsewhere (the center's help page). It is read from the
/// [`Cli`] definition above, so a new command or flag shows up there by
/// being written once; [`SECTIONS`] only says where on the page it goes.
#[derive(Debug, Clone, Serialize)]
pub struct Help {
    /// What the node is.
    pub about: String,
    /// Options every command takes.
    pub global: Vec<ArgHelp>,
    /// Arguments that cards on different places take alike (`--center`),
    /// said once here and left out of the cards.
    pub common: Vec<ArgHelp>,
    /// The cards, grouped by what a person wants to do, in reading order.
    pub sections: Vec<Section>,
}

/// Where each command stands on the help page: the heading, the sentence
/// under it, and the cards. A card is the commands named in one slice: a
/// noun with its verbs (`["folder"]`), or loose commands that belong
/// together (`["panic", "unlock"]`). A command missing here still shows up,
/// in a section of its own, and a test fails until it is placed.
const SECTIONS: &[(&str, &str, &[&[&str]])] = &[
    (
        "Install and set up",
        "Run the node as a service under a user of its own (Linux with sudo, Windows as administrator), set it up, keep it current, and back it up or move it.",
        &[
            &["install", "uninstall"],
            &["service"],
            &["setup"],
            &["update"],
            &["backup", "restore"],
        ],
    ),
    (
        "Pair and connect",
        "Link this machine to centers and choose how it reaches them.",
        &[&["center"], &["proxy"], &["relay"]],
    ),
    (
        "What a center may do",
        "Every center has its own rights on this machine. `config` reaches any setting by its name.",
        &[
            &["mode"],
            &["folder"],
            &["rule"],
            &["cap"],
            &["sudo"],
            &["config"],
        ],
    ),
    (
        "Run and watch",
        "Start the node, see what it did, and stop it.",
        &[
            &["run"],
            &["status"],
            &["audit"],
            &["log"],
            &["panic", "unlock"],
        ],
    ),
];

/// A heading with its sentence, and the cards below it.
#[derive(Debug, Clone, Serialize)]
pub struct Section {
    pub name: String,
    /// What the section is for, said once for all its cards.
    pub about: String,
    pub cards: Vec<Card>,
}

/// One thing a person looks up: a noun with its verbs, or loose commands
/// that go together.
#[derive(Debug, Clone, Serialize)]
pub struct Card {
    /// `folder`, `panic / unlock`.
    pub name: String,
    /// What it is for; empty when its commands say it themselves.
    pub about: String,
    /// The commands that only hold more commands (`folder`), which the card
    /// covers without a line of their own.
    pub holds: Vec<String>,
    /// Arguments that two or more verbs take in the same way, said once.
    pub shared_args: Vec<ArgHelp>,
    pub verbs: Vec<Verb>,
}

/// A command that does something.
#[derive(Debug, Clone, Serialize)]
pub struct Verb {
    /// The words after `nerve-node`: `status`, `folder add`.
    pub name: String,
    /// The usage line, for example `nerve-node folder add [OPTIONS] <PATH>`.
    pub usage: String,
    /// The explanation: the doc comment of the command.
    pub about: String,
    /// Its own arguments and flags, without the global and the shared ones.
    pub args: Vec<ArgHelp>,
    /// Every argument and flag it takes but the global ones, the shared
    /// ones too: for a page that shows one command on its own (the desktop
    /// app's reference), where the card's and the page's are not in sight.
    #[serde(skip)]
    pub takes: Vec<ArgHelp>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ArgHelp {
    /// How it is written: `--for <HOURS>`, `<PATH>`, `--wildcard`.
    pub name: String,
    /// The explanation; empty when the argument has none.
    pub about: String,
    /// Whether it can be left out.
    pub optional: bool,
}

impl Help {
    /// Every verb, card by card.
    pub fn verbs(&self) -> impl Iterator<Item = &Verb> {
        self.sections
            .iter()
            .flat_map(|s| &s.cards)
            .flat_map(|c| &c.verbs)
    }

    /// Every command the page covers: the verbs and the commands that only
    /// hold more commands.
    pub fn command_names(&self) -> Vec<&str> {
        let cards = self.sections.iter().flat_map(|s| &s.cards);
        let holds = cards.clone().flat_map(|c| &c.holds).map(String::as_str);
        let verbs = self.verbs().map(|v| v.name.as_str());
        holds.chain(verbs).collect()
    }
}

fn visible(c: &clap::Command) -> bool {
    // clap adds a `help` sub-command of its own to every level.
    c.get_name() != "help" && !c.is_hide_set()
}

/// Reads [`Help`] from the [`Cli`] definition.
pub fn help() -> Help {
    let mut root = Cli::command();
    root.build();
    let mut left: Vec<&clap::Command> = root.get_subcommands().filter(|c| visible(c)).collect();
    let mut sections = Vec::new();
    for (name, about, cards) in SECTIONS {
        let mut out = Vec::new();
        for names in *cards {
            let cmds: Vec<&clap::Command> = names
                .iter()
                .filter_map(|n| root.find_subcommand(n))
                .collect();
            left.retain(|c| !names.contains(&c.get_name()));
            out.extend(cards_of(&cmds));
        }
        sections.push(Section {
            name: (*name).into(),
            about: (*about).into(),
            cards: out,
        });
    }
    if !left.is_empty() {
        sections.push(Section {
            name: "Other commands".into(),
            about: String::new(),
            cards: left.into_iter().flat_map(|c| cards_of(&[c])).collect(),
        });
    }
    let common = hoist_common(&mut sections);
    Help {
        about: about_of(&root),
        global: root
            .get_arguments()
            .filter(|a| a.is_global_set())
            .map(arg_help)
            .collect(),
        common,
        sections,
    }
}

/// Takes the arguments that two or more cards have alike out of the cards.
fn hoist_common(sections: &mut [Section]) -> Vec<ArgHelp> {
    let args_of = |c: &Card| -> Vec<ArgHelp> {
        let own = c.verbs.iter().flat_map(|v| &v.args);
        c.shared_args.iter().chain(own).cloned().collect()
    };
    let mut common: Vec<ArgHelp> = Vec::new();
    for a in sections.iter().flat_map(|s| &s.cards).flat_map(args_of) {
        let on = sections
            .iter()
            .flat_map(|s| &s.cards)
            .filter(|c| args_of(c).contains(&a))
            .count();
        if on > 1 && !common.contains(&a) {
            common.push(a);
        }
    }
    for c in sections.iter_mut().flat_map(|s| &mut s.cards) {
        c.shared_args.retain(|a| !common.contains(a));
        for v in &mut c.verbs {
            v.args.retain(|a| !common.contains(a));
        }
    }
    common
}

fn about_of(c: &clap::Command) -> String {
    c.get_about().map(ToString::to_string).unwrap_or_default()
}

fn cards_of(cmds: &[&clap::Command]) -> Vec<Card> {
    if let [one] = cmds
        && one.has_subcommands()
    {
        return noun_cards(one, one.get_name());
    }
    let verbs = cmds.iter().map(|c| verb(c, c.get_name())).collect();
    let names: Vec<&str> = cmds.iter().map(|c| c.get_name()).collect();
    vec![card(&names.join(" / "), String::new(), Vec::new(), verbs)]
}

fn card(name: &str, about: String, holds: Vec<String>, mut verbs: Vec<Verb>) -> Card {
    // An argument that two verbs take alike is said once, on the card.
    let mut shared: Vec<ArgHelp> = Vec::new();
    for a in verbs.iter().flat_map(|v| &v.args) {
        if !shared.contains(a) && verbs.iter().filter(|v| v.args.contains(a)).count() > 1 {
            shared.push(a.clone());
        }
    }
    for v in &mut verbs {
        v.args.retain(|a| !shared.contains(a));
    }
    Card {
        name: name.into(),
        about,
        holds,
        shared_args: shared,
        verbs,
    }
}

/// The cards of a noun (`folder`): its verbs on one card, and a card for
/// each sub-noun below it.
fn noun_cards(noun: &clap::Command, name: &str) -> Vec<Card> {
    let (holders, leaves): (Vec<_>, Vec<_>) = noun
        .get_subcommands()
        .filter(|c| visible(c))
        .partition(|c| c.has_subcommands());
    let mut out = Vec::new();
    // A noun that also runs on its own (`audit`, beside `audit clear`) is
    // its card's first verb, and holds nothing.
    let alone = !noun.is_subcommand_required_set();
    let holds = if alone { Vec::new() } else { vec![name.into()] };
    if !leaves.is_empty() {
        let verbs = alone
            .then(|| verb(noun, name))
            .into_iter()
            .chain(
                leaves
                    .iter()
                    .map(|c| verb(c, &format!("{name} {}", c.get_name()))),
            )
            .collect();
        out.push(card(name, about_of(noun), holds, verbs));
    }
    for h in &holders {
        out.extend(noun_cards(h, &format!("{name} {}", h.get_name())));
    }
    if !alone
        && !out.iter().any(|c| c.holds.iter().any(|h| h == name))
        && let Some(first) = out.first_mut()
    {
        first.holds.insert(0, name.into());
    }
    out
}

fn verb(sub: &clap::Command, name: &str) -> Verb {
    let usage = sub.clone().render_usage().to_string();
    // A command that also holds others has their form on a second line:
    // that is theirs.
    let usage = usage.lines().next().unwrap_or_default();
    let args: Vec<ArgHelp> = sub
        .get_arguments()
        .filter(|a| !a.is_global_set() && !matches!(a.get_id().as_str(), "help" | "version"))
        .map(arg_help)
        .collect();
    Verb {
        name: name.into(),
        usage: usage.strip_prefix("Usage: ").unwrap_or(usage).to_string(),
        about: about_of(sub),
        takes: args.clone(),
        args,
    }
}

fn arg_help(a: &clap::Arg) -> ArgHelp {
    let value = a
        .get_value_names()
        .and_then(|v| v.first())
        .map_or_else(|| a.get_id().as_str().to_uppercase(), ToString::to_string);
    let name = match a.get_long() {
        Some(long) if a.get_action().takes_values() => format!("--{long} <{value}>"),
        Some(long) => format!("--{long}"),
        None => format!("<{value}>"),
    };
    ArgHelp {
        name,
        about: a.get_help().map(ToString::to_string).unwrap_or_default(),
        optional: !a.is_required_set(),
    }
}

/// Reads the config: from the daemon when it runs, else from the file.
/// The version is the daemon's (`None` when read from the file).
pub async fn read_config(paths: &NodePaths) -> Result<(NodeConfig, Option<u64>), String> {
    #[cfg(unix)]
    match nerve_transport::ctl::call(&paths.ctl_socket(), "config.read", json!({})).await {
        Ok(v) => {
            let text = v["config"].as_str().unwrap_or_default();
            return Ok((NodeConfig::parse(text)?, v["version"].as_u64()));
        }
        Err(e) if e != nerve_transport::ctl::NOT_RUNNING => return Err(e),
        Err(_) => {}
    }
    Ok((
        SettingsStore::peek_with(
            &paths.config_file(),
            &crate::secrets::NodeSecrets::for_cli(paths),
        )?,
        None,
    ))
}

/// Changes the config: through the daemon (retrying when someone else wrote
/// meanwhile), or directly in the file when no daemon runs. An error also
/// when the config is saved but the folder grants do not follow it.
pub async fn edit(
    paths: &NodePaths,
    f: impl Fn(&mut NodeConfig) -> Result<(), String>,
) -> Result<NodeConfig, String> {
    let saved = edit_saved(paths, f).await?;
    match grants_failed(&saved.grants) {
        Some(e) => Err(e),
        None => Ok(saved.cfg),
    }
}

/// The config [`edit_saved`] saved, and what the folder grants did when no
/// daemon took the change (nothing when one did).
pub struct Saved {
    pub cfg: NodeConfig,
    pub grants: crate::grants::Synced,
}

/// Why the folder grants do not follow a saved config, if they do not.
fn grants_failed(s: &crate::grants::Synced) -> Option<String> {
    s.errors
        .first()
        .map(|e| format!("the config is saved, but the folder grants do not follow it: {e}"))
}

/// [`edit`], which is also done when the folder grants do not follow.
pub async fn edit_saved(
    paths: &NodePaths,
    f: impl Fn(&mut NodeConfig) -> Result<(), String>,
) -> Result<Saved, String> {
    #[cfg(unix)]
    {
        let sock = paths.ctl_socket();
        let mut conflicts = 0;
        loop {
            let read = match nerve_transport::ctl::call(&sock, "config.read", json!({})).await {
                Ok(v) => v,
                // Only a node that is not there leaves the file to the CLI.
                Err(e) if e == nerve_transport::ctl::NOT_RUNNING => break,
                Err(e) => return Err(e),
            };
            let old = NodeConfig::parse(read["config"].as_str().unwrap_or_default())?;
            let mut cfg = old.clone();
            f(&mut cfg)?;
            crate::owner::check_change(&old, &cfg)?;
            let params = json!({
                "config": cfg.to_toml(),
                "if_version": read["version"],
                "user": changed_by(),
            });
            match nerve_transport::ctl::call(&sock, "config.write", params).await {
                Ok(_) => {
                    return Ok(Saved {
                        cfg,
                        grants: Default::default(),
                    });
                }
                Err(e) if e.starts_with("conflict") => {
                    conflicts += 1;
                    // A node that answered has the file: writing it here
                    // would be undone by its next write, and the change
                    // reported as made.
                    if conflicts == 5 {
                        return Err("the config keeps changing; try again".into());
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }
    let mut store = SettingsStore::open_with(
        paths.config_file(),
        Box::new(crate::secrets::NodeSecrets::for_cli(paths)),
        AuditLog::new(paths.audit_log()),
    )?;
    store.set_user(Some(changed_by()));
    let old = store.config().clone();
    match store.update(|c| {
        f(c)?;
        crate::owner::check_change(&old, c)
    }) {
        Ok(_) => {
            let cfg = store.config().clone();
            // No daemon took the change, so the folder grants of Windows
            // folder mode follow it here (crate::grants); a running node
            // brings them in line with its own config again before a
            // command. A change that takes long says how far it is here.
            let grants =
                crate::grants::apply_outside(paths, &cfg, &crate::paths::home_dir(), &mut |m| {
                    eprintln!("{m}")
                });
            Ok(Saved { cfg, grants })
        }
        Err(SetError::Conflict { .. }) => Err("the config changed meanwhile; try again".into()),
        Err(e) => Err(e.to_string()),
    }
}

/// The center a per-center command means: the one named, or the only one.
pub fn pick_center(cfg: &NodeConfig, given: &CenterArg) -> Result<String, String> {
    crate::folder_change::pick_center(cfg, given.center.as_deref())
}

/// `center rotate-key`: the running node makes the new key and sends it to
/// the center over its link (crate::rotate), or ends the grace of the old
/// one. The new public key is shown once.
async fn rotate_key(
    paths: &NodePaths,
    center: &CenterArg,
    end_grace: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    let (cfg, _) = read_config(paths).await?;
    let name = pick_center(&cfg, center)?;
    let params = json!({"center": name, "end_grace": end_grace});
    #[cfg(unix)]
    let r = nerve_transport::ctl::call(&paths.ctl_socket(), "center.rotate-key", params).await;
    #[cfg(windows)]
    let r = crate::pipe::call(paths, "center.rotate-key", params).await;
    #[cfg(not(any(unix, windows)))]
    let r: Result<Value, String> = {
        let _ = params;
        Err(nerve_transport::ctl::NOT_RUNNING.to_string())
    };
    let v = match r {
        Ok(v) => v,
        Err(e) if e == nerve_transport::ctl::NOT_RUNNING => {
            return Err(format!(
                "the node does not run: a key rotation goes to center {name} over the node's link. Start it (`nerve-node run`, or the service), then try again"
            ));
        }
        Err(e) => return Err(e),
    };
    let key = v["public_key"].as_str().unwrap_or_default();
    if end_grace {
        let _ = writeln!(
            out,
            "center {name} no longer takes this machine's old key; it takes only {key}"
        );
        return Ok(());
    }
    let days = nerve_proto::ROTATE_GRACE_MS / 86_400_000;
    json::also("public_key", json!(key));
    let _ = writeln!(
        out,
        "center {name} took this machine's new key:\n  {key}\nThe old key is deleted here. The center takes it for {days} more days, unless you end that now with `nerve-node center rotate-key --end-grace --center {name}`."
    );
    Ok(())
}

/// Changes one center's entry.
async fn edit_center(
    paths: &NodePaths,
    center: &CenterArg,
    f: impl Fn(&mut nerve_policy::CenterEntry) -> Result<(), String>,
) -> Result<String, String> {
    let (cfg, _) = read_config(paths).await?;
    let name = pick_center(&cfg, center)?;
    edit(paths, |c| {
        let e = c
            .center_mut(&name)
            .ok_or_else(|| format!("no center named {name}"))?;
        f(e)
    })
    .await?;
    Ok(name)
}

/// `folder set` takes changes that start with `-`, so clap hands it every
/// word after the path, `--center` included. This takes the flag out again.
fn take_center_flag(
    words: Vec<String>,
    mut center: CenterArg,
) -> Result<(Vec<String>, CenterArg), String> {
    let mut changes = Vec::new();
    let mut words = words.into_iter();
    while let Some(word) = words.next() {
        let given = if word == "--center" {
            Some(words.next().ok_or("--center needs a name")?)
        } else {
            word.strip_prefix("--center=").map(str::to_string)
        };
        match given {
            Some(name) if center.center.is_none() => center.center = Some(name),
            Some(_) => return Err("--center is given twice".into()),
            None if word.starts_with("--") => return Err(format!("unknown option {word}")),
            None => changes.push(word),
        }
    }
    if changes.is_empty() {
        return Err("name what to change: =rwx, +x or -w".into());
    }
    Ok((changes, center))
}

fn push_unique(list: &mut Vec<String>, rule: &str) {
    if !list.iter().any(|r| r == rule) {
        list.push(rule.to_string());
    }
}

/// `center pause` and `center resume`: the owner's switch, the only way a
/// pause ends (a center can pause itself, never unpause).
async fn pause_center(
    paths: &NodePaths,
    center: &CenterArg,
    pause: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    let name = edit_center(paths, center, |e| {
        e.paused = pause;
        Ok(())
    })
    .await?;
    let _ = writeln!(out, "{name}: {}", if pause { "paused" } else { "resumed" });
    Ok(())
}

impl List {
    fn of(self, p: &mut nerve_policy::CenterPolicy) -> &mut Vec<String> {
        match self {
            List::Allow => &mut p.allow,
            List::Deny => &mut p.deny,
            List::Sudo => &mut p.sudo_allow,
        }
    }

    fn word(self) -> &'static str {
        match self {
            List::Allow => "allow",
            List::Deny => "deny",
            List::Sudo => "sudo",
        }
    }

    fn label(self) -> &'static str {
        match self {
            List::Allow => "allow rule (allowlist mode)",
            List::Deny => "deny rule",
            List::Sudo => "sudo allow list",
        }
    }

    /// The entry a command line stands for, for `rule add`: the same as
    /// [`List::command_rule`], but a line in the pattern form of `config add`
    /// (`fs.read:~/notes/*`, `fs:~/private/*`) is refused. As a command it
    /// would become a rule that never matches. A single letter before the `:`
    /// is a drive (`C:\tools\x.exe`), not a capability.
    fn entry(self, command: &str, wildcard: bool, action: Option<&str>) -> Result<String, String> {
        if let Some(action) = action {
            return self.action_rule(action, command, wildcard);
        }
        if matches!(self, List::Allow | List::Deny)
            && let Some((scope, _)) = command.trim().split_once(':')
            && (scope.contains('.') || scope.len() > 1)
            && rules::valid_scope(scope)
        {
            let hint = if scope == "guard" {
                "; the guard's rules are put on with `nerve-node rule guard`".to_string()
            } else {
                String::new()
            };
            return Err(format!(
                "`{scope}:` is the pattern form for files and other actions, not a command: add it with `nerve-node config add center.<name>.policy.{}`{hint}",
                self.word()
            ));
        }
        self.command_rule(command, wildcard)
    }

    /// What an edited entry becomes, for `rule edit`: an entry in the form
    /// `ls` shows (a `cap.action:pattern` rule; on the sudo list a pattern
    /// of a sudo command) as it is, a plain command line as `add` makes it.
    fn edited(self, new: &str) -> Result<String, String> {
        let new = new.trim();
        if new.is_empty() {
            return Err("the new entry is empty: `rule rm` takes an entry away".into());
        }
        match self {
            List::Allow | List::Deny => match new.split_once(':') {
                // A single letter before the `:` is a drive, not a
                // capability (`C:\tools\x.exe`).
                Some((scope, _)) if scope.len() > 1 && rules::valid_scope(scope) => {
                    rules::validate(new)?;
                    Ok(new.to_string())
                }
                _ => self.command_rule(new, false),
            },
            List::Sudo => {
                let glob = if sudo_command(new).is_some() {
                    new.to_string()
                } else {
                    format!("sudo {new}")
                };
                rules::validate_command_glob(&glob)?;
                Ok(glob)
            }
        }
    }

    /// The rule of an audit entry of `action` (`fs.read`) with `target`, as
    /// the audit buttons of the desktop app and of the center make it
    /// ([`rules::rule_for`]). The sudo list takes sudo commands only.
    fn action_rule(self, action: &str, target: &str, wildcard: bool) -> Result<String, String> {
        // A cut target is no longer the call's, so no rule can name it.
        if nerve_policy::audit::is_cut_target(target) {
            return Err("the target was cut to its start, so a rule cannot name it".into());
        }
        let (cap, act) = action
            .split_once('.')
            .ok_or_else(|| format!("{action:?} is not a capability and action, like fs.read"))?;
        match self {
            List::Sudo if (cap, act) != ("exec", "run") => {
                Err("the sudo list is for sudo commands (--action exec.run)".into())
            }
            List::Sudo => self.command_rule(target, wildcard),
            List::Allow if (cap, act) == ("exec", "run") => self.command_rule(target, wildcard),
            List::Allow | List::Deny => rules::rule_for(cap, act, target, wildcard),
        }
    }

    /// The rule a command line stands for. The allow and deny lists hold
    /// `exec.run` rules; the sudo list holds the sudo command lines, and takes
    /// the command with or without the `sudo` in front. `rule rm` uses it
    /// as it is, so a rule is removed with the arguments that made it.
    fn command_rule(self, command: &str, wildcard: bool) -> Result<String, String> {
        match self {
            List::Allow if sudo_command(command).is_some() => {
                Err("a sudo command goes on the sudo list: `nerve-node rule add sudo`".into())
            }
            List::Allow | List::Deny => rules::rule_for("exec", "run", command, wildcard),
            List::Sudo if sudo_command(command).is_some() => {
                rules::sudo_rule_for(command, wildcard)
            }
            List::Sudo => rules::sudo_rule_for(&format!("sudo {}", command.trim()), wildcard),
        }
    }
}

/// The entry of `list` that `text` names: `text` itself, or the entry that
/// `rule ls` prints as `text` (its tab, carriage return and line feed written
/// `\t`, `\r`, `\n`). Else `text`.
fn shown_entry(list: &[String], text: &str) -> String {
    if list.iter().any(|r| r == text) {
        return text.to_string();
    }
    let raw = rules::unescape_controls(text);
    if raw != text && list.contains(&raw) {
        raw
    } else {
        text.to_string()
    }
}

/// `rule add|rm|ls`.
async fn rule_cmd(paths: &NodePaths, c: RuleCmd, out: &mut dyn Write) -> Result<(), String> {
    match c {
        RuleCmd::Add {
            list,
            command,
            wildcard,
            action,
            center,
        } => {
            let rule = list.entry(&command, wildcard, action.as_deref())?;
            let name = edit_center(paths, &center, |e| {
                push_unique(list.of(&mut e.policy), &rule);
                Ok(())
            })
            .await?;
            let note = match list {
                List::Deny => "; commands it matches are forbidden",
                _ => "",
            };
            let _ = writeln!(out, "{name}: {} {rule:?}{note}", list.label());
        }
        RuleCmd::Rm {
            list,
            command,
            wildcard,
            action,
            center,
        } => {
            let removed = std::sync::Mutex::new(String::new());
            let name = edit_center(paths, &center, |e| {
                let name = e.name.clone();
                let l = list.of(&mut e.policy);
                // An entry copied from `ls` goes as it is, so rules for
                // files and other actions can be removed too (also one with
                // a line break, which `ls` writes `\n`). The arguments of
                // `add` stand for the command rule they made.
                let command = shown_entry(l, &command);
                let made = match &action {
                    Some(a) => list.action_rule(a, &command, wildcard),
                    None => list.command_rule(&command, wildcard),
                };
                let rule = match made {
                    Ok(made) if made != command && l.contains(&command) && l.contains(&made) => {
                        return Err(format!(
                            "both {command:?} and {made:?} are on the {}: remove {made:?} first with `nerve-node rule rm {word} '{made}' --center {center}`, and then {command:?} with `nerve-node rule rm {word} '{command}' --center {center}`",
                            list.label(),
                            word = list.word(),
                            center = name
                        ));
                    }
                    _ if l.contains(&command) => command.clone(),
                    made => made?,
                };
                let before = l.len();
                l.retain(|r| *r != rule);
                if l.len() == before {
                    return Err(format!("{rule:?} is not on the {}", list.label()));
                }
                *removed.lock().unwrap() = rule;
                Ok(())
            })
            .await?;
            let removed = removed.into_inner().unwrap();
            let _ = writeln!(out, "{name}: removed {removed:?} from the {}", list.label());
        }
        RuleCmd::Edit {
            list,
            entry,
            new,
            center,
        } => {
            let done = std::sync::Mutex::new((String::new(), String::new()));
            let name = edit_center(paths, &center, |e| {
                let l = list.of(&mut e.policy);
                // The entry as `ls` prints it, with its line breaks written
                // `\n`: the new entry is written so too.
                let (entry, new) = match shown_entry(l, &entry) {
                    shown if shown == entry => (entry.clone(), new.clone()),
                    shown => (shown, rules::unescape_controls(&new)),
                };
                let rule = list.edited(&new)?;
                rules::check_not_a_listed_form(&rule, l)?;
                let Some(at) = l.iter().position(|r| *r == entry) else {
                    return Err(format!("{entry:?} is not on the {}", list.label()));
                };
                if rule == entry {
                    return Err(format!("{entry:?} is that already"));
                }
                // In its place; a copy of the new entry elsewhere on the
                // list goes, so the list holds each entry once.
                l[at] = rule.clone();
                let mut i = 0;
                l.retain(|r| {
                    i += 1;
                    i - 1 == at || *r != rule
                });
                *done.lock().unwrap() = (entry, rule);
                Ok(())
            })
            .await?;
            let (entry, rule) = done.into_inner().unwrap();
            let _ = writeln!(
                out,
                "{name}: the {} {entry:?} is {rule:?} now",
                list.label()
            );
        }
        RuleCmd::Guard { center } => {
            let added = std::sync::Mutex::new((0usize, 0usize));
            let name = edit_center(paths, &center, |e| {
                // The guard's older texts go: the new ones replace them.
                let mut deny: Vec<String> = e
                    .policy
                    .deny
                    .iter()
                    .filter(|r| !nerve_policy::rules::GUARD_OLD.contains(&r.as_str()))
                    .cloned()
                    .collect();
                let replaced = e.policy.deny.len() - deny.len();
                let missing = nerve_policy::rules::guard_missing(&deny);
                if missing.is_empty() && replaced == 0 {
                    return Err(format!(
                        "{} has every deny rule of the guard already",
                        e.name
                    ));
                }
                *added.lock().unwrap() = (missing.len(), replaced);
                deny.extend(missing.into_iter().map(str::to_string));
                e.policy.deny = deny;
                Ok(())
            })
            .await?;
            let (added, replaced) = added.into_inner().unwrap();
            let replaced = match replaced {
                0 => String::new(),
                n => format!(" ({n} of an older text replaced)"),
            };
            let _ = writeln!(
                out,
                "{name}: added {added} deny rules of the guard{replaced}; commands that run this node's programs, name its socket or folders, or stop its service are forbidden"
            );
        }
        RuleCmd::Ls { list, center } => {
            let (cfg, _) = read_config(paths).await?;
            let name = pick_center(&cfg, &center)?;
            let mut policy = cfg.center(&name).expect("picked").policy.clone();
            if let Some(list) = list {
                let entries = list.of(&mut policy);
                if entries.is_empty() {
                    let _ = writeln!(out, "{name}: nothing on the {}", list.label());
                }
                for r in entries.iter() {
                    let _ = writeln!(out, "{}", rules::escape_controls(r));
                }
            } else {
                // All three: each line says which list it is on.
                let mut any = false;
                for list in [List::Allow, List::Deny, List::Sudo] {
                    for r in list.of(&mut policy).iter() {
                        any = true;
                        let _ = writeln!(out, "{}  {}", list.word(), rules::escape_controls(r));
                    }
                }
                if !any {
                    let _ = writeln!(out, "{name}: nothing on any rule list");
                }
            }
        }
    }
    Ok(())
}

/// When a change that only the file holds counts.
pub(crate) const NEXT_START: &str = "takes effect at the next start of the node";

/// Runs one command line, writing what it shows to `out`. A change made
/// while no daemon answers on the control socket (none runs, or Windows,
/// whose pipe takes folder changes only) is only in the file, so the output
/// says when it counts.
pub async fn execute(cli: Cli, out: &mut dyn Write) -> Result<(), String> {
    let service = cli.cmd.is_service();
    if service && (cli.config_dir.is_some() || cli.state_dir.is_some()) {
        let l = Layout::system();
        return Err(format!(
            "install, update and uninstall keep the node's files in {} and {}; --config-dir and --state-dir do not go with them",
            l.paths.config_dir.display(),
            l.paths.state_dir.display()
        ));
    }
    let paths = NodePaths::from_args(cli.config_dir, cli.state_dir);
    if !service {
        crate::service::check_access(&paths)?;
    }
    if !cli.json {
        return said(paths, cli.cmd, out).await;
    }
    // The read commands have a JSON form of their own; the others give the
    // lines they print as a list.
    if json::own_form(&cli.cmd) {
        return json::command(&paths, cli.cmd, out).await;
    }
    json::changed(paths, cli.cmd, out).await
}

/// Whether `line` is one a change prints to say that the node takes it
/// only at its next start: a node that does not run, the installed node on
/// Windows for anything but folders, a relay change or sudo on Windows. The
/// desktop app shows such a line in words of its own. Only the whole line
/// counts: a change also prints what others chose (a rule a center's
/// command became), and such text could hold the same words.
pub fn takes_at_next_start(line: &str) -> bool {
    line == in_file_line()
        || line == RELAY_AT_NEXT_START
        || line == crate::winsudo::next_start_line()
}

/// What a change says when only node.toml holds it.
fn in_file_line() -> String {
    format!("the change is in node.toml; it {NEXT_START}")
}

/// Says, as `"next_start": true` with `--json`, that the node takes the
/// change only at its next start: called where the line that says so is
/// written, so a program learns it from what the command did and not from
/// its text.
pub(crate) fn waits_for_next_start() {
    json::also("next_start", json!(true));
}

/// [`execute`] with the text output, and what it says when a change is
/// only in the file.
async fn said(paths: NodePaths, cmd: Cmd, out: &mut dyn Write) -> Result<(), String> {
    let service = cmd.is_service();
    // The daemon writes the file itself while it runs; the service commands
    // leave it alone (or delete it with the rest). Sudo on Windows says
    // itself when its change counts (crate::winsudo).
    // A restore says itself what comes next.
    let own_say =
        (cfg!(windows) && matches!(cmd, Cmd::Sudo(_))) || matches!(cmd, Cmd::Restore { .. });
    let before = (!matches!(cmd, Cmd::Run) && !service && !own_say)
        .then(|| std::fs::read(paths.config_file()).ok());
    // On Windows the running node takes folder changes over its pipe, and
    // nothing else yet.
    let folders = matches!(
        cmd,
        Cmd::Folder(FolderCmd::Add { .. } | FolderCmd::Set { .. } | FolderCmd::Rm { .. })
    );
    let r = command(paths.clone(), cmd, out).await;
    if r.is_ok()
        && let Some(before) = before
        && std::fs::read(paths.config_file()).ok() != before
        && !daemon_answers(&paths, folders).await
    {
        let _ = writeln!(out, "{}", in_file_line());
        waits_for_next_start();
    }
    r
}

impl Cmd {
    /// install, update and uninstall: they work on the installed node, as
    /// root.
    pub(crate) fn is_service(&self) -> bool {
        matches!(
            self,
            Cmd::Install { .. } | Cmd::Update { .. } | Cmd::Uninstall { .. } | Cmd::Service(_)
        )
    }
}

/// Run first in `main`, while the process has one thread: a command that
/// root runs on a node whose folders belong to another user, as the
/// installed node's belong to `nerve`, runs as that user
/// ([`crate::service::become_owner`]), so that what it writes stays the
/// node's. install, update and uninstall keep root; setup keeps it as its
/// saved id, to restart the node once a keyring it installed answers.
pub fn settle_user(cli: &Cli) -> Result<(), String> {
    #[cfg(unix)]
    STARTED_AS.get_or_init(own_real_uid);
    if cli.cmd.is_service() {
        return Ok(());
    }
    let paths = NodePaths::from_args(cli.config_dir.clone(), cli.state_dir.clone());
    // The backup file is the asker's, in the asker's folders: it is opened
    // as the user who ran sudo (crate::caller_file), not as the node's.
    if crate::service::becomes_owner(&paths) {
        use crate::caller_file::{Job, prepare};
        match &cli.cmd {
            Cmd::Backup {
                file, overwrite, ..
            } => prepare(Job::Write {
                path: file.clone(),
                overwrite: *overwrite,
            })?,
            Cmd::Restore { file, .. } => prepare(Job::Read(file.clone()))?,
            _ => {}
        }
    }
    crate::service::become_owner(&paths, matches!(cli.cmd, Cmd::Setup))
}

/// Set by the desktop app's broker on Windows for the commands it runs: the
/// SID of the app's user. The broker runs as the administrator who answered
/// the UAC prompt, who is another account when the app's user is a standard
/// user.
pub const DESKTOP_USER_SID: &str = "NERVE_DESKTOP_USER_SID";

/// The account that ran this command through sudo, else root. On Windows
/// the account this command runs as, or the desktop app's user for the
/// app's broker ([`DESKTOP_USER_SID`]). A command the node runs for one of
/// its owners is that owner's (crate::owner).
pub(crate) fn invoker() -> String {
    if let Some(owner) = crate::owner::owner_running() {
        return owner;
    }
    #[cfg(windows)]
    if let Some(name) = windows_invoker(std::env::var(DESKTOP_USER_SID).ok()) {
        return name;
    }
    invoker_of(
        std::env::var("SUDO_USER").ok(),
        std::env::var("PKEXEC_UID").ok(),
        crate::account::name_of,
    )
}

/// Who makes a change, for the audit: the [`invoker`], and without sudo or
/// pkexec the account that started this command, which is root only when
/// it was.
pub(crate) fn changed_by() -> String {
    let who = invoker();
    #[cfg(unix)]
    if who == "root" {
        let uid = *STARTED_AS.get_or_init(own_real_uid);
        if uid != 0 {
            return crate::account::name_of(uid).unwrap_or_else(|| format!("uid {uid}"));
        }
    }
    who
}

/// The real user id this process started with, before
/// [`settle_user`] made it the node's user.
#[cfg(unix)]
static STARTED_AS: std::sync::OnceLock<u32> = std::sync::OnceLock::new();

#[cfg(unix)]
fn own_real_uid() -> u32 {
    // SAFETY: a plain getter.
    unsafe { libc::getuid() }
}

/// [`invoker`] on Windows: the desktop app's user when its broker names
/// one by SID (`app_user`), else the account this command runs as.
#[cfg(windows)]
fn windows_invoker(app_user: Option<String>) -> Option<String> {
    app_user
        .and_then(|sid| crate::win_user::name_of_sid(&sid).ok())
        .or_else(|| crate::win_user::current_user().ok())
}

/// [`invoker`] from `SUDO_USER`, else `PKEXEC_UID`: polkit's pkexec, with
/// which the desktop app asks for root, names the user who asked by uid.
fn invoker_of(
    sudo_user: Option<String>,
    pkexec_uid: Option<String>,
    name_of: impl Fn(u32) -> Option<String>,
) -> String {
    sudo_user
        .filter(|u| !u.is_empty())
        .or_else(|| {
            pkexec_uid
                .and_then(|u| u.trim().parse::<u32>().ok())
                .filter(|u| *u != 0)
                .and_then(name_of)
        })
        .unwrap_or_else(|| "root".into())
}

/// On Windows, `run` on the installed node's folders runs under the service
/// control manager (crate::win_service): the node's log file, where a start
/// that fails is said. `None` for any other command.
pub fn service_log(cli: &Cli) -> Option<PathBuf> {
    if !matches!(cli.cmd, Cmd::Run) {
        return None;
    }
    let paths = NodePaths::from_args(cli.config_dir.clone(), cli.state_dir.clone());
    crate::service::is_service_node(&paths).then(|| paths.log_file())
}

/// `service status` as JSON (crate::service::service_status): the
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

/// The rule of the other owner commands (docs/dev/spec/node-local.md §5):
/// nothing a command of a center starts may install, set up, update or
/// remove the node, nor back it up or restore it. The node that runs knows
/// its commands, so it is asked over its control socket, and refuses a
/// caller below one of them.
pub async fn owner_check(paths: &[&NodePaths]) -> Result<(), String> {
    #[cfg(unix)]
    for p in paths {
        match nerve_transport::ctl::call(&p.ctl_socket(), "owner.check", json!({})).await {
            Ok(_) => {}
            // No node runs, so no command of one does.
            Err(e) if e == nerve_transport::ctl::NOT_RUNNING => {}
            // A node that does not know the method cannot answer it. It is let
            // through.
            Err(e) if e.starts_with("unknown method") => {}
            Err(e) => return Err(e),
        }
    }
    #[cfg(not(unix))]
    let _ = paths;
    Ok(())
}

/// Whether a daemon runs on the control socket; it then took every change
/// at once. One that takes no connection now runs all the same; a socket
/// that cannot be reached at all is none. On Windows it takes only `folders`
/// changes over its pipe, so only those count as taken when it answers.
async fn daemon_answers(paths: &NodePaths, folders: bool) -> bool {
    #[cfg(unix)]
    {
        let _ = folders;
        let outcome = nerve_transport::ctl::call(&paths.ctl_socket(), "status", json!({})).await;
        nerve_transport::ctl::node_is_there(&outcome).unwrap_or(false)
    }
    #[cfg(windows)]
    {
        folders && crate::pipe::call(paths, "status", json!({})).await.is_ok()
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (paths, folders);
        false
    }
}

/// What `status` says of the limits per command (crate::cgroup::status):
/// what a command gets and may ask for, then where they hold or why not.
fn limits_lines(v: &Value) -> Vec<String> {
    let n = |k: &str| v[k].as_u64().unwrap_or_default();
    let mut lines = vec![format!(
        "limits per command: memory {} MiB, CPU {} %, {} processes; a call may ask for up to {} MiB, {} %, {} processes",
        n("memory_mb"),
        n("cpu_percent"),
        n("processes"),
        n("memory_max_mb"),
        n("cpu_max_percent"),
        n("processes_max"),
    )];
    let list = |k: &str| -> Vec<&str> {
        v[k].as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect()
    };
    let (enforced, lost) = (list("enforced"), list("lost"));
    if let Some(cgroup) = v["cgroup"].as_str() {
        let not: Vec<&str> = ["memory", "cpu", "processes"]
            .into_iter()
            .filter(|l| !enforced.contains(l) && !lost.contains(l))
            .collect();
        let mut line = match enforced.is_empty() {
            true => format!("limits held by the cgroup {cgroup}: none"),
            false => format!(
                "limits held by the cgroup {cgroup}: {}",
                enforced.join(", ")
            ),
        };
        if !not.is_empty() {
            line.push_str(&format!(
                "; not {} (the cgroup has no controller for it)",
                not.join(", ")
            ));
        }
        lines.push(line);
        // Turned off while the node ran: no command runs (crate::cgroup).
        if !lost.is_empty() {
            lines.push(format!(
                "NO COMMAND RUNS: {} turned off in the cgroup since the node started; start the node again",
                lost.join(", ")
            ));
        }
    } else if let Some(why) = v["off"].as_str() {
        lines.push(format!("commands run WITHOUT these limits: {why}"));
    }
    lines
}

/// The running node's status: over the control socket, on Windows over its
/// pipe; `None` when no node runs.
async fn live_status(paths: &NodePaths) -> Result<Option<Value>, String> {
    #[cfg(unix)]
    let r = nerve_transport::ctl::call(&paths.ctl_socket(), "status", json!({})).await;
    #[cfg(windows)]
    let r = crate::pipe::call(paths, "status", json!({})).await;
    #[cfg(not(any(unix, windows)))]
    let r: Result<Value, String> = {
        let _ = paths;
        Err(nerve_transport::ctl::NOT_RUNNING.to_string())
    };
    match r {
        Ok(v) => Ok(Some(v)),
        Err(e) if e == nerve_transport::ctl::NOT_RUNNING => Ok(None),
        Err(e) => Err(e),
    }
}

async fn command(paths: NodePaths, cmd: Cmd, out: &mut dyn Write) -> Result<(), String> {
    let w = |out: &mut dyn Write, s: String| {
        let _ = writeln!(out, "{s}");
    };
    match cmd {
        Cmd::Run => {
            let mut opts = NodeOptions::new(paths);
            opts.exe = std::env::current_exe().ok();
            Daemon::run(opts).await
        }
        Cmd::Center(CenterCmd::Add { link, name, yes }) => {
            let link = PairLink::parse(&link)?;
            w(out, crate::pair::preview(&link, name.as_deref()));
            if !yes {
                // Asked only when the pairing can work: the center answers,
                // its certificate is the pinned one and the code is open.
                let check = crate::pair::check(&paths, &link).await?;
                if !check.ready() {
                    return Err(check.said());
                }
                w(out, check.said());
                if !confirm(&mut std::io::stdin().lock(), out)? {
                    return Err("not paired".into());
                }
            }
            let e = crate::pair::pair(&paths, &link, name.as_deref()).await?;
            w(out, format!("paired with {} as {}", e.url, e.name));
            Ok(())
        }
        Cmd::Center(CenterCmd::Rm(center)) => {
            let (cfg, _) = read_config(&paths).await?;
            let name = pick_center(&cfg, &center)?;
            let gone = std::sync::Mutex::new(Vec::new());
            // Saved also when the folder grants of the other pairings do not
            // follow: the pairing is gone then, so its key and profile go
            // now, or nothing names them later.
            let saved = edit_saved(&paths, |c| {
                let mut g = gone.lock().unwrap_or_else(|p| p.into_inner());
                g.clear();
                g.extend(
                    c.centers
                        .iter()
                        .filter(|e| e.name == name)
                        .map(|e| e.node_id.clone()),
                );
                c.centers.retain(|e| e.name != name);
                Ok(())
            })
            .await?;
            let cfg = &saved.cfg;
            // The center is gone either way; a key that stays behind is
            // said, not hidden.
            if let Err(e) =
                crate::secrets::remove_center_key(&paths, cfg.machine.secret_storage, &name)
            {
                w(out, format!("the node key for {name} was not deleted: {e}"));
            }
            // So is the profile of its container on Windows (crate::grants):
            // with its last grant when the record names it, else found by
            // the pairing. A node that runs still serves the center until it
            // starts again, so there it stays.
            let mut p = saved.grants.profiles.clone();
            let mut ours = Vec::new();
            for id in gone.into_inner().unwrap_or_else(|p| p.into_inner()) {
                if cfg.centers.iter().any(|c| c.node_id == id) {
                    continue;
                }
                ours.extend(crate::grants::containers(&paths, &id));
                p.merge(crate::grants::forget(&paths, &id));
            }
            let of = |n: &String| {
                if ours.contains(n) {
                    format!("{n} of {name}")
                } else {
                    n.clone()
                }
            };
            for n in &p.removed {
                w(out, format!("removed the AppContainer profile {}", of(n)));
            }
            if let Some(why) = &p.why {
                for n in &p.kept {
                    w(
                        out,
                        format!(
                            "the AppContainer profile {} stays, since {why}: once the node stopped, remove it by hand (docs/user/modes.md)",
                            of(n)
                        ),
                    );
                }
            }
            for e in &p.errors {
                w(
                    out,
                    format!("the AppContainer profile of {name} was not removed: {e}"),
                );
            }
            w(out, format!("unpaired {name}"));
            match grants_failed(&saved.grants) {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }
        Cmd::Center(CenterCmd::Ls) => {
            let (cfg, _) = read_config(&paths).await?;
            if cfg.centers.is_empty() {
                w(out, "no center is paired".into());
            }
            let now = crate::now_ms();
            for c in &cfg.centers {
                let mut flags = Vec::new();
                for (on, f) in [
                    (c.paused, "paused"),
                    (c.revoked, "revoked"),
                    (c.unknown, "unknown"),
                ] {
                    if on {
                        flags.push(f);
                    }
                }
                w(
                    out,
                    format!(
                        "{}  {}  mode {}  settings {}{}",
                        c.name,
                        c.url,
                        c.policy.mode_at(now).as_str(),
                        enum_str(&c.settings),
                        if flags.is_empty() {
                            String::new()
                        } else {
                            format!("  [{}]", flags.join(", "))
                        }
                    ),
                );
                // Which `nerve.*` profile is this pairing's: the others
                // belong to other nodes or are left over (docs/user/modes.md).
                if cfg!(windows) {
                    w(
                        out,
                        format!(
                            "  AppContainer {}",
                            crate::grants::profile_name(&paths, &c.node_id)
                        ),
                    );
                }
            }
            Ok(())
        }
        Cmd::Center(CenterCmd::RotateKey { end_grace, center }) => {
            rotate_key(&paths, &center, end_grace, out).await
        }
        Cmd::Center(CenterCmd::Pause(center)) => pause_center(&paths, &center, true, out).await,
        Cmd::Center(CenterCmd::Resume(center)) => pause_center(&paths, &center, false, out).await,
        Cmd::Center(CenterCmd::Grant {
            what,
            value,
            center,
        }) => {
            let (name, g) = match what.as_str() {
                "settings" => {
                    let g: SettingsGrant = parse_enum(&value, "off or write")?;
                    let name = edit_center(&paths, &center, |e| {
                        e.settings = g;
                        Ok(())
                    })
                    .await?;
                    (name, g)
                }
                other => return Err(format!("unknown grant {other} (settings)")),
            };
            w(out, format!("{name}: {what} {value}"));
            let root = crate::owner::is_root(crate::service::owner_of(&paths).as_deref());
            if let Some(warning) = settings_grant_warning(&name, g, root) {
                w(out, warning);
            }
            Ok(())
        }
        Cmd::Status => {
            // On Windows the node answers over its control pipe.
            if let Some(v) = live_status(&paths).await? {
                for line in status_lines(&v) {
                    w(out, line);
                }
                return Ok(());
            }
            let cfg = SettingsStore::peek_with(
                &paths.config_file(),
                &crate::secrets::NodeSecrets::for_cli(&paths),
            )?;
            let owner = crate::service::owner_of(&paths);
            for line in stopped_lines(&cfg, owner.as_deref()) {
                w(out, line);
            }
            Ok(())
        }
        Cmd::Mode(ModeCmd::Set {
            mode,
            for_hours,
            as_owner,
            center,
        }) => set_mode(&paths, &mode, for_hours, as_owner, &center, out).await,
        Cmd::Folder(FolderCmd::Add {
            path,
            rights,
            center,
        }) => add_folder(&paths, &path, &rights, &center, out).await,
        Cmd::Folder(FolderCmd::Set {
            path,
            changes,
            center,
        }) => {
            let (changes, center) = take_center_flag(changes, center)?;
            let a = change_stored_folder(&paths, &center, &path, |at| FolderChange::Set {
                path: at.clone(),
                given: at,
                changes: changes.clone(),
            })
            .await?;
            let access = a.access.unwrap_or(Access::NONE);
            w(
                out,
                format!("{}: folder {} {}", a.center, a.path, access.to_chmod()),
            );
            if access.is_none() {
                w(
                    out,
                    "note: the folder grants nothing now (`nerve-node folder rm` removes it)"
                        .into(),
                );
            }
            tell_grants(&paths, out).await;
            Ok(())
        }
        Cmd::Folder(FolderCmd::Rm { path, center }) => {
            let a = change_stored_folder(&paths, &center, &path, |at| FolderChange::Rm {
                path: at.clone(),
                given: at,
            })
            .await?;
            w(out, format!("{}: removed {}", a.center, a.path));
            tell_grants(&paths, out).await;
            Ok(())
        }
        Cmd::Folder(FolderCmd::Ls { center }) => {
            let (cfg, _) = read_config(&paths).await?;
            let name = pick_center(&cfg, &center)?;
            let folders = &cfg.center(&name).expect("picked").policy.folders;
            if folders.is_empty() {
                w(out, format!("{name}: no folders"));
            }
            for f in folders {
                w(out, format!("{}  {}", f.access.to_chmod(), f.path));
            }
            Ok(())
        }
        Cmd::Cap(CapCmd::Set {
            cap,
            setting,
            center,
        }) => {
            let s = CapSetting::parse(&setting)
                .ok_or_else(|| format!("unknown setting {setting} (on, off or hidden)"))?;
            let name = edit_center(&paths, &center, |e| {
                e.policy.caps.insert(cap.clone(), s);
                Ok(())
            })
            .await?;
            w(out, format!("{name}: {cap} {setting}"));
            Ok(())
        }
        Cmd::Cap(CapCmd::Ls { center }) => {
            let (cfg, _) = read_config(&paths).await?;
            if let Some(c) = &center {
                cfg.center(c)
                    .ok_or_else(|| format!("no center named {c}"))?;
            }
            let v = cap_listing(&paths, &cfg).await?;
            for l in cap_lines(&cfg, &v, center.as_deref()) {
                w(out, l);
            }
            Ok(())
        }
        Cmd::Cap(CapCmd::Provider(ProviderCmd::Allow { name, exe })) => {
            if !nerve_policy::config::valid_provider_name(&name) {
                return Err(format!(
                    "{name:?} cannot name a provider: 1 to 32 of a-z, 0-9 and -, starting and ending with a letter or digit, and not node"
                ));
            }
            if !Path::new(&exe).is_absolute() {
                return Err(format!(
                    "{exe}: give the program by its full path, as the node compares it"
                ));
            }
            edit(&paths, |c| {
                match c.providers.allowed.iter_mut().find(|p| p.name == name) {
                    Some(p) => p.exe = exe.clone(),
                    None => c
                        .providers
                        .allowed
                        .push(nerve_policy::config::AllowedProvider {
                            name: name.clone(),
                            exe: exe.clone(),
                        }),
                }
                Ok(())
            })
            .await?;
            w(out, format!("provider {name} allowed: {exe}"));
            Ok(())
        }
        Cmd::Cap(CapCmd::Provider(ProviderCmd::Rm { name })) => {
            edit(&paths, |c| {
                let before = c.providers.allowed.len();
                c.providers.allowed.retain(|p| p.name != name);
                if c.providers.allowed.len() == before {
                    return Err(format!("no provider {name} is allowed"));
                }
                Ok(())
            })
            .await?;
            w(out, format!("provider {name} removed"));
            Ok(())
        }
        Cmd::Cap(CapCmd::Provider(ProviderCmd::Ls)) => {
            let (cfg, _) = read_config(&paths).await?;
            let v = cap_listing(&paths, &cfg).await?;
            for l in program_lines(&v) {
                w(out, l);
            }
            Ok(())
        }
        Cmd::Config(c) => config_cmd(&paths, c, out).await,
        Cmd::Rule(c) => rule_cmd(&paths, c, out).await,
        Cmd::Panic => {
            edit(&paths, |c| {
                c.locked = true;
                Ok(())
            })
            .await?;
            w(
                out,
                "locked: every link ends and nothing runs until `nerve-node unlock`".into(),
            );
            Ok(())
        }
        Cmd::Unlock => {
            edit(&paths, |c| {
                c.locked = false;
                Ok(())
            })
            .await?;
            w(out, "unlocked".into());
            Ok(())
        }
        Cmd::Audit {
            clear: Some(AuditCmd::Clear),
            ..
        } => {
            // A command of a center must not wipe what it did from the
            // owner's sight.
            owner_check(&[&paths]).await?;
            let who = changed_by();
            AuditLog::new(paths.audit_log())
                .clear(&who)
                .map_err(|e| format!("{}: {e}", paths.audit_log().display()))?;
            w(
                out,
                format!(
                    "audit cleared; the entries so far are kept in {}",
                    AuditLog::new(paths.audit_log()).old_path().display()
                ),
            );
            Ok(())
        }
        Cmd::Audit {
            clear: None,
            follow,
            denied,
            last,
        } => audit(&paths, follow, denied, last, false, out).await,
        Cmd::Log {
            clear: Some(LogCmd::Clear),
            ..
        } => {
            owner_check(&[&paths]).await?;
            clear_log(&paths, &changed_by())?;
            w(out, "log cleared".into());
            Ok(())
        }
        Cmd::Log {
            clear: None,
            follow,
            last,
            problems,
        } => log_cmd(&paths, follow, last, problems, false, out).await,
        Cmd::Proxy(c) => proxy_cmd(&paths, c, out).await,
        Cmd::Relay(c) => relay_cmd(&paths, c, out).await,
        Cmd::Sudo(c) => sudo_cmd(&paths, c, out).await,
        Cmd::Backup {
            file,
            include_keyring,
            overwrite,
            passphrase_file,
        } => {
            // A command of a center must not take the node's keys out under a
            // passphrase of its own.
            owner_check(&[&paths]).await?;
            let (cfg, _) = read_config(&paths).await?;
            let pass = crate::prompt::passphrase(passphrase_file.as_deref(), out, true)?;
            let opts = crate::backup::BackupOpts {
                include_keyring,
                overwrite,
                rounds: nerve_transport::backup::ITERATIONS,
            };
            let r = crate::backup::backup(&paths, &cfg, &file, &pass, &opts)?;
            crate::backup::print_backup(&r, &file, out);
            json::also("backup", crate::backup::backup_data(&r, &file));
            Ok(())
        }
        Cmd::Restore {
            file,
            replace,
            secret_storage,
            without_proxy,
            passphrase_file,
        } => {
            owner_check(&[&paths]).await?;
            let bytes = crate::caller_file::read(&file)?;
            let kind = nerve_transport::backup::kind_of(&bytes)?;
            if kind != nerve_transport::backup::Kind::Node {
                return Err(format!(
                    "this is the backup of a {}, not of a node: restore it with `nerve-center restore`",
                    kind.word()
                ));
            }
            let storage = secret_storage
                .map(|s| parse_enum::<SecretStorage>(&s, "file or keyring"))
                .transpose()?;
            let pass = crate::prompt::passphrase(passphrase_file.as_deref(), out, false)?;
            let parsed = crate::backup::open(&bytes, &pass)?;
            // An owner restores what an owner may change, nothing that
            // picks the account or program commands run as.
            if crate::owner::owner_running().is_some()
                && let Some(key) = crate::backup::root_only_change(&paths, &parsed)
            {
                return Err(crate::owner::restore_needs_admin(key));
            }
            let opts = crate::backup::RestoreOpts {
                replace,
                secret_storage: storage,
                without_proxy,
            };
            let r = crate::backup::restore(&paths, &parsed, &opts)?;
            crate::backup::print_restore(&r, &parsed, out);
            json::also("restored", crate::backup::restore_data(&r, &parsed));
            Ok(())
        }
        Cmd::Install {
            owner,
            accept_root_owner,
        } => {
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
                out,
            );
            #[cfg(not(windows))]
            {
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
                )
            }
        }
        Cmd::Setup => {
            owner_check(&[&paths]).await?;
            let mut input = std::io::BufReader::new(std::io::stdin());
            let layout = Layout::system();
            let machine = (!cfg!(windows) && layout.installed() && paths == layout.paths)
                .then_some(&Host as &dyn crate::service::System);
            // The installed program, which the node's user can run, asks
            // its keyring.
            let keyring = match machine {
                Some(_) => crate::keyring_setup::HostKeyring {
                    exe: layout.bin.clone(),
                },
                None => crate::keyring_setup::HostKeyring::this_program(),
            };
            // Asked whether to install a keyring as root only at a
            // terminal: the owner's own, for a setup the node runs for its
            // owner (crate::owner).
            let terminal = crate::owner::at_terminal();
            setup(&paths, machine, &keyring, &mut input, terminal, out).await
        }
        Cmd::Update { from } => {
            let layout = Layout::system();
            owner_check(&[&layout.paths]).await?;
            #[cfg(windows)]
            return crate::winsvc::update(&layout, &crate::win_host::WinHost, from.as_deref(), out)
                .await;
            #[cfg(not(windows))]
            crate::service::update(&layout, &Host, from.as_deref(), out).await
        }
        Cmd::Service(ServiceCmd::Status) => {
            let v = service_status(&Layout::system())?;
            let state = match v["state"].as_str() {
                None => "not installed as a service".to_string(),
                Some(state) => {
                    let boot = match v["enabled"].as_bool() {
                        Some(true) => ", starts with the machine",
                        Some(false) => ", does not start with the machine",
                        None => "",
                    };
                    format!("{state}{boot}")
                }
            };
            let version = v["version"]
                .as_str()
                .map_or_else(String::new, |v| format!(" (version {v})"));
            let program = if v["present"] == true {
                format!("{}{version}", v["program"].as_str().unwrap_or_default())
            } else {
                format!("none at {}", v["program"].as_str().unwrap_or_default())
            };
            writeln!(out, "service: {state}\nprogram: {program}").map_err(|e| e.to_string())
        }
        Cmd::Service(c) => {
            let action = match c {
                ServiceCmd::Start => crate::service::ServiceAction::Start,
                ServiceCmd::Stop => crate::service::ServiceAction::Stop,
                _ => crate::service::ServiceAction::Restart,
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
        Cmd::Uninstall { purge } => {
            let layout = Layout::system();
            // The desktop app took this node over: its service, parts and
            // program are the app's, so the app's own uninstall removes it
            // all, and its checks are its own.
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
                out,
            );
            #[cfg(not(windows))]
            crate::service::uninstall(&layout, &Host, purge, out)
        }
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

/// The line of `status` on the node's owner, which says plainly what root
/// as the owner means.
fn owner_line(owner: Option<&str>, root: bool) -> Option<String> {
    match (owner, root) {
        (Some(_), true) => Some(format!("owner: {}", crate::owner::ROOT_OWNER_NOTE)),
        (Some(o), false) => Some(format!("owner: {o}")),
        (None, _) => None,
    }
}

/// What `center grant settings write` warns of where root is the owner
/// (`root`): the center may then set its own mode to user, whose commands
/// run as root, with no password asked.
fn settings_grant_warning(name: &str, g: SettingsGrant, root: bool) -> Option<String> {
    (root && g == SettingsGrant::Write).then(|| {
        format!(
            "Warning: root is the owner of this node, so {name} can now set its own mode to user, and its commands then run as root: anything on this machine, Nerve and its keys included"
        )
    })
}

/// What `status` says of a node that does not run, with the config `cfg`
/// and the `owner` the unit names, a line each.
fn stopped_lines(cfg: &NodeConfig, owner: Option<&str>) -> Vec<String> {
    let mut lines = vec!["daemon: not running".to_string()];
    lines.extend(owner_line(owner, crate::owner::is_root(owner)));
    let limits = crate::cgroup::status(&cfg.limits.command, &Err("the node does not run".into()));
    if let Some(line) = limits_lines(&limits).first() {
        lines.push(line.clone());
    }
    if cfg.locked {
        lines.push("LOCKED (panic): nothing runs until `nerve-node unlock`".into());
    }
    for c in &cfg.centers {
        lines.push(format!("{}  {}", c.name, c.url));
    }
    lines
}

/// What `status` says of a running node, from its `status` answer `v`, a
/// line each.
fn status_lines(v: &Value) -> Vec<String> {
    let mut lines = vec![format!(
        "daemon: running (confinement {})",
        v["confinement"].as_str().unwrap_or("?")
    )];
    if let Some(why) = v["folder_commands_off"].as_str() {
        lines.push(format!("folder mode runs no command: {why}"));
    }
    lines.extend(limits_lines(&v["command_limits"]));
    if v["locked"] == true {
        lines.push("LOCKED (panic): nothing runs until `nerve-node unlock`".into());
    }
    lines.extend(owner_line(v["owner"].as_str(), v["owner_is_root"] == true));
    if let Some(h) = v["home_warning"]["warning"].as_str() {
        lines.push(format!("warning: {h}"));
    }
    lines.extend(
        grant_lines(&v["folder_grants"])
            .into_iter()
            .map(|l| format!("warning: {l}")),
    );
    for c in v["centers"].as_array().into_iter().flatten() {
        // The installed node says as whom its commands run. Where Landlock
        // is missing nerve-run runs without it.
        let whom = match c["account"].as_str() {
            Some(a) if a == crate::account::RUN_USER && c["landlock"] == false => {
                format!(", as {a}, without Landlock")
            }
            Some(a) => format!(", as {a}"),
            None => String::new(),
        };
        lines.push(format!(
            "{}  {}  mode {}{whom}",
            c["name"].as_str().unwrap_or_default(),
            c["status"].as_str().unwrap_or_default(),
            c["mode"].as_str().unwrap_or_default(),
        ));
    }
    for p in v["providers"].as_array().into_iter().flatten() {
        let caps: Vec<&str> = p["capabilities"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let name = p["name"].as_str().unwrap_or_default();
        lines.push(format!("provider {name} attached: {}", caps.join(", ")));
        // Actions whose schemas a center cannot check are not offered.
        for b in p["broken"].as_array().into_iter().flatten() {
            lines.push(format!(
                "provider {name}: {} left out: {}",
                b["name"].as_str().unwrap_or_default(),
                b["reason"].as_str().unwrap_or_default()
            ));
        }
    }
    let relay = &v["relay"];
    if relay["listen"].is_string() {
        let tunnels = relay["tunnels"].as_array().map_or(0, Vec::len);
        lines.push(format!(
            "relay: {}, {tunnels} tunnels open (`nerve-node relay ls` names them)",
            relay["status"].as_str().unwrap_or_default()
        ));
    }
    lines
}

/// The texts of `v`, a list of strings.
fn texts(v: &Value) -> Vec<&str> {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

/// Whether the error `e` of a folder grant (`<path>: <why>`) is about
/// `path` or something below it.
fn error_about(e: &str, path: &str) -> bool {
    e.strip_prefix(path)
        .is_some_and(|rest| rest.starts_with(':') || rest.starts_with('/'))
}

/// What the node's folder grants (`status`'s `folder_grants`, the answer of
/// `folder.grants`) say, a line each. Access `nerve-run` keeps although it
/// should have lost it (`stale`) comes first, as no command of it runs
/// until it is off; then the grants it did not get whole.
fn grant_lines(g: &Value) -> Vec<String> {
    let stale = texts(&g["stale"]);
    let errors = texts(&g["errors"]);
    let mut lines = Vec::new();
    for p in &stale {
        let why: Vec<&str> = errors
            .iter()
            .copied()
            .filter(|e| error_about(e, p))
            .collect();
        lines.push(format!(
            "nerve-run keeps its access to {p}, which it should have lost; no command of nerve-run runs until it is taken off{}",
            if why.is_empty() {
                String::new()
            } else {
                format!(": {}", why.join("; "))
            }
        ));
    }
    for e in errors
        .iter()
        .filter(|e| !stale.iter().any(|p| error_about(e, p)))
    {
        lines.push(format!("nerve-run did not get every folder: {e}"));
    }
    lines
}

/// `setup`: the first-run steps in the terminal: the node's name, where it
/// keeps its keys, its first center, that center's mode and a folder. Each
/// answer is saved when it is given, through the same owner path as the
/// other commands (the running node, or the signed `node.toml`), so setup
/// can stop anywhere and run again; Enter keeps what is there. The steps
/// done are audited. `machine` is there on the installed node, which setup
/// restarts once a keyring it installed answers. Keys in the system keyring
/// need one that answers; `keyring` checks it, and installs one when the
/// owner says yes to it at a terminal (`terminal`, [`crate::keyring_setup`]).
pub async fn setup(
    paths: &NodePaths,
    machine: Option<&dyn crate::service::System>,
    keyring: &dyn crate::keyring_setup::Keyring,
    input: &mut dyn BufRead,
    terminal: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    let mut steps = Vec::new();
    let r = setup_steps(paths, machine, keyring, input, terminal, out, &mut steps).await;
    let log = AuditLog::new(paths.audit_log());
    if let Err(e) = log.node("setup", &steps, r.as_ref().err().map(String::as_str)) {
        let _ = writeln!(out, "the audit log cannot be written: {e}");
    }
    r
}

/// Once the keyring answers setup, whether setup installed it or it came some
/// other way: a node that runs and found none before does not look again
/// (`keyring_failed` in its status, [`crate::secrets::store::failed`]), so it
/// would refuse the move. The installed node is restarted; a node run by hand
/// is left to its owner.
async fn after_keyring_answers(
    paths: &NodePaths,
    machine: Option<&dyn crate::service::System>,
    out: &mut dyn Write,
) -> Result<(), String> {
    #[cfg(unix)]
    match nerve_transport::ctl::call(&paths.ctl_socket(), "status", json!({})).await {
        Ok(status) => {
            let for_owner = crate::owner::owner_running().is_some();
            return restart_for_keyring(&status, paths, machine, for_owner, out);
        }
        Err(e) if e == nerve_transport::ctl::NOT_RUNNING => {}
        Err(e) => {
            let _ = writeln!(
                out,
                "the running node was not asked whether it found a keyring ({e}); restart it if it did not"
            );
            return Ok(());
        }
    }
    #[cfg(not(unix))]
    let _ = (paths, machine, out);
    Ok(())
}

/// What [`after_keyring_answers`] does with the running node's `status`;
/// `for_owner`: setup runs in the node, for its owner (crate::owner).
#[cfg_attr(not(unix), allow(dead_code))]
fn restart_for_keyring(
    status: &Value,
    paths: &NodePaths,
    machine: Option<&dyn crate::service::System>,
    for_owner: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    if status["keyring_failed"] != true {
        return Ok(());
    }
    // Run by the node for its owner, setup would end with the node it runs
    // in.
    if for_owner {
        return Err("the system keyring answers now, but the node found none when it started and does not look again until it is restarted; `nerve-node service restart`, then run `nerve-node setup` again".into());
    }
    let Some(sys) = machine else {
        return Err("the system keyring answers now, but the node that runs for this folder found none before and does not look again until it is restarted; restart it, then run `nerve-node setup` again".into());
    };
    sys.systemctl(&["restart", crate::service::UNIT_NAME])?;
    sys.wait_running(paths)?;
    let _ = writeln!(
        out,
        "restarted the node, which had found no keyring before this one answered"
    );
    Ok(())
}

async fn setup_steps(
    paths: &NodePaths,
    machine: Option<&dyn crate::service::System>,
    keyring: &dyn crate::keyring_setup::Keyring,
    input: &mut dyn BufRead,
    terminal: bool,
    out: &mut dyn Write,
    steps: &mut Vec<String>,
) -> Result<(), String> {
    // Keys in a keyring that does not answer: nothing can be read, so that
    // comes first, also where the keys may not stay there, so that they can go
    // into files below. The installed node on Windows asks none: the keyring
    // setup reaches is not the service's.
    let no_keyring = crate::secrets::no_keyring(paths);
    if crate::secrets::stated_storage(paths) == SecretStorage::Keyring
        && no_keyring != Some(crate::secrets::NoKeyring::WindowsService)
    {
        let me = crate::keyring_setup::me()?;
        crate::keyring_setup::ensure(keyring, &me, terminal.then_some(&mut *input), out)?;
        after_keyring_answers(paths, machine, out).await?;
    }
    let (cfg, _) = read_config(paths).await?;
    let _ = writeln!(out, "Set up this node. Enter keeps what is in [brackets].");
    let current = crate::descriptor::node_name(&cfg);
    let name = ask(
        input,
        out,
        &format!("Name of this node, as centers show it [{current}]: "),
    )?;
    if !name.is_empty() && name != current {
        if !nerve_proto::valid_node_name(&name) {
            return Err(format!(
                "{name:?} is not a node name: 1 to 32 characters of a-z, 0-9 and -, starting and ending with a letter or digit"
            ));
        }
        edit(paths, |c| {
            c.node.name = Some(name.clone());
            Ok(())
        })
        .await?;
        steps.push(format!("named the node {name}"));
    }

    // Where the keys go, before pairing makes one. Where they may not be in
    // the keyring (the installed node on Windows), setup does not ask; it
    // says why.
    let now = read_config(paths).await?.0.machine.secret_storage;
    let storage = if let Some(n) = no_keyring {
        let _ = writeln!(out, "Warning: {}.", n.why());
        SecretStorage::File
    } else {
        let answer = ask(
            input,
            out,
            &format!(
                "Where the node keeps its keys: file (files only the node's user can read) or keyring (the system keyring) [{}]: ",
                enum_str(&now)
            ),
        )?;
        match answer.as_str() {
            "" => now,
            a => parse_enum::<SecretStorage>(a, "file or keyring")?,
        }
    };
    if storage != now {
        if storage == SecretStorage::Keyring {
            let me = crate::keyring_setup::me()?;
            crate::keyring_setup::ensure(keyring, &me, terminal.then_some(&mut *input), out)?;
            after_keyring_answers(paths, machine, out).await?;
        }
        let cfg = edit(paths, |c| {
            c.machine.secret_storage = storage;
            Ok(())
        })
        .await?;
        let step = format!("the node's keys are in {} now", storage_place(storage));
        let _ = writeln!(out, "{step}");
        steps.push(step);
        if storage == SecretStorage::Keyring {
            tell_folder_commands(paths, &cfg, out).await;
        }
    }

    let link = ask(
        input,
        out,
        "Pairing link from the center's web UI (Enter to skip): ",
    )?;
    let mut center = None;
    if !link.is_empty() {
        let link = PairLink::parse(&link)?;
        let _ = writeln!(out, "{}", crate::pair::preview(&link, None));
        if confirm(input, out)? {
            let e = crate::pair::pair(paths, &link, None).await?;
            let _ = writeln!(out, "paired with {} as {}", e.url, e.name);
            steps.push(format!("paired with {} as {}", e.url, e.name));
            center = Some(e.name);
        } else {
            let _ = writeln!(out, "not paired");
        }
    }
    let center = match center {
        Some(c) => c,
        None => match read_config(paths).await?.0.centers.as_slice() {
            [one] => one.name.clone(),
            [] => {
                let _ = writeln!(
                    out,
                    "No center is paired; `nerve-node center add '<link>'` pairs one."
                );
                return Ok(());
            }
            _ => {
                let _ = writeln!(
                    out,
                    "Several centers are paired; `nerve-node mode set <mode> --center <name>` sets the mode of each."
                );
                return Ok(());
            }
        },
    };

    let (cfg, _) = read_config(paths).await?;
    let entry = cfg
        .center(&center)
        .ok_or_else(|| format!("no center named {center}"))?;
    let now = entry.policy.mode_at(crate::now_ms()).as_str().to_string();
    let mode = ask(
        input,
        out,
        &format!(
            "Mode for {center}: folder (writes and commands in the folders you give it, as nerve-run; reads also where every account may), allowlist (only what allow rules name) or user (all you may do, as you) [{now}]: "
        ),
    )?;
    let mode = if mode.is_empty() { now.clone() } else { mode };
    let which = CenterArg {
        center: Some(center.clone()),
    };
    if mode != now {
        set_mode(paths, &mode, None, false, &which, out).await?;
        steps.push(format!("{center}: mode {mode}"));
    }
    if mode == "folder" {
        let folder = ask(
            input,
            out,
            &format!("A folder {center} may use (Enter to skip): "),
        )?;
        if !folder.is_empty() {
            let rights = ask(
                input,
                out,
                "What it may do there: +r reads, +w writes, +x runs commands, as in `+r +x` [+rwx]: ",
            )?;
            // Folder mode runs a command only where it may run one, so
            // Enter gives a folder commands can work in.
            let rights: Vec<String> = if rights.is_empty() {
                vec!["+rwx".into()]
            } else {
                rights.split_whitespace().map(str::to_string).collect()
            };
            add_folder(paths, Path::new(&folder), &rights, &which, out).await?;
            steps.push(format!("{center}: folder {folder} {}", rights.join(" ")));
        }
    }
    let _ = writeln!(
        out,
        "Done. `nerve-node folder add <folder> +rwx` gives a folder, `nerve-node rule add allow '<command>'` allows a command in allowlist mode; `nerve-node --help` lists the rest."
    );
    Ok(())
}

/// How setup names where the keys are.
fn storage_place(s: SecretStorage) -> &'static str {
    match s {
        SecretStorage::File => "files",
        SecretStorage::Keyring => "the system keyring",
    }
}

/// Asks one question; the answer without the line break and the spaces
/// around it. The end of the input is an error, so setup never loops on it.
pub(crate) fn ask(
    input: &mut dyn BufRead,
    out: &mut dyn Write,
    question: &str,
) -> Result<String, String> {
    let _ = write!(out, "{question}");
    let _ = out.flush();
    let mut line = String::new();
    if input.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
        let _ = writeln!(out);
        return Err("stopped: the input ended before every question was answered".into());
    }
    Ok(line.trim().to_string())
}

/// `mode set`, and the mode step of `setup`.
async fn set_mode(
    paths: &NodePaths,
    mode: &str,
    for_hours: Option<u64>,
    as_owner: bool,
    center: &CenterArg,
    out: &mut dyn Write,
) -> Result<(), String> {
    let w = |out: &mut dyn Write, s: String| {
        let _ = writeln!(out, "{s}");
    };
    let m = match mode {
        "allowlist" => Mode::Allowlist,
        "folder" => Mode::Folder,
        "user" => Mode::User,
        other => {
            return Err(format!("unknown mode {other} (allowlist, folder or user)"));
        }
    };
    if for_hours.is_some() && m == Mode::Allowlist {
        return Err("--for only goes with folder or user".into());
    }
    if as_owner && m != Mode::Allowlist {
        return Err(
            "--as-owner only goes with allowlist: folder mode always runs as nerve-run, user mode always as you".into(),
        );
    }
    // No --for: no limit, and an old one is cleared. The end is a
    // millisecond count that the config file (a TOML integer) holds.
    let until = for_hours
        .map(|h| {
            if h == 0 {
                return Err("--for must be at least 1 hour".to_string());
            }
            h.checked_mul(3_600_000)
                .and_then(|ms| crate::now_ms().checked_add(ms))
                .filter(|t| i64::try_from(*t).is_ok())
                .ok_or_else(|| "--for is too large".to_string())
        })
        .transpose()?;
    let name = edit_center(paths, center, |e| {
        e.policy.mode = m;
        e.policy.until = until;
        e.policy.as_owner = as_owner;
        Ok(())
    })
    .await?;
    let whom = if as_owner { ", as you" } else { "" };
    w(out, format!("{name}: mode {}{whom}", m.as_str()));
    Ok(())
}

/// `folder add`, and the folder step of `setup`.
async fn add_folder(
    paths: &NodePaths,
    path: &Path,
    rights: &[String],
    center: &CenterArg,
    out: &mut dyn Write,
) -> Result<(), String> {
    let w = |out: &mut dyn Write, s: String| {
        let _ = writeln!(out, "{s}");
    };
    // The rights are checked before the folder is looked at.
    let access = FolderChange::new_rights(rights)?;
    let (cfg, _) = read_config(paths).await?;
    let name = pick_center(&cfg, center)?;
    let given = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path)
    };
    let given = nerve_policy::paths::normal_folder(&given.display().to_string())?;
    // A running node judges the path as the account the commands run as,
    // which this command may not be (the installed node's CLI runs as the
    // node's own user): it follows the links on the path a link at a time,
    // refuses one a command may have put inside a `w` folder, and stores and
    // records the real place, all in one step.
    #[cfg(unix)]
    let asked = {
        let params = json!({"center": name, "path": given, "access": access.to_string()});
        match nerve_transport::ctl::call(&paths.ctl_socket(), "folder.add", params).await {
            Ok(v) => Some((
                v["stored"].as_str().unwrap_or(&given).to_string(),
                v["recorded"] == true,
                v["mode"].as_str().map(str::to_string),
                v["counts"].as_bool(),
            )),
            Err(e) if e == nerve_transport::ctl::NOT_RUNNING => None,
            Err(e) => return Err(e),
        }
    };
    #[cfg(not(unix))]
    let asked: Option<(String, bool, Option<String>, Option<bool>)> = None;
    let (stored, recorded, mode, counts) = match asked {
        Some(a) => a,
        None => {
            // No node to ask (on Windows the node's pipe takes the change but
            // not the judging): judge the path here, as this process sees it.
            let settled = crate::exec::settle(&cfg, &crate::paths::home_dir(), Path::new(&given));
            let (stored, recorded) = match settled {
                crate::exec::Settled::Refused(why) => {
                    return Err(crate::daemon::refusal(&given, &why));
                }
                crate::exec::Settled::At(place) => (place.display().to_string(), true),
                crate::exec::Settled::Unknown => (given.clone(), false),
            };
            let change = FolderChange::Add {
                path: stored.clone(),
                access,
                recorded,
            };
            let a = change_folder(paths, center, &change).await?;
            (stored, recorded, Some(a.mode.as_str().to_string()), None)
        }
    };
    w(
        out,
        format!("{name}: folder {stored} {}", access.to_chmod()),
    );
    if !recorded {
        w(
            out,
            format!(
                "note: {stored} is stored as given and not recorded at its real place, since this command cannot tell where its path leads (the installed node's CLI may not look into the account's home) and no running node could: a link that replaces the folder later is followed once no `w` folder shows it, see modes.md \"A folder keeps the place you added\"; start the node and add the folder again"
            ),
        );
    } else if !same_folder(&stored, &given) {
        w(
            out,
            format!("note: {given} leads to {stored}; the folder is stored there"),
        );
    }
    // The running node says whether the folders hold the center's commands
    // (also allowlist mode as nerve-run); without one, folder mode alone is
    // sure to.
    let counts = counts.unwrap_or_else(|| mode.as_deref() == Some(Mode::Folder.as_str()));
    if let Some(mode) = mode.filter(|_| !counts) {
        w(
            out,
            format!(
                "note: folders do not count here: {name} is in {mode} mode, whose commands are not held to them (`nerve-node mode set folder`)"
            ),
        );
    }
    tell_grants(paths, out).await;
    Ok(())
}

/// Tells what the running installed Linux node did not manage after a
/// change of the folders: a grant `nerve-run` did not get, or an entry that
/// did not come off (crate::acl). The node brings them in line before it
/// answers. Nothing without such a node.
async fn tell_grants(paths: &NodePaths, out: &mut dyn Write) {
    #[cfg(target_os = "linux")]
    if let Ok(v) = nerve_transport::ctl::call(&paths.ctl_socket(), "folder.grants", json!({})).await
    {
        tell_grants_of(&v, out);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (paths, out);
}

/// What [`tell_grants`] says of the node's answer `v`, and adds to `--json`:
/// `grant_errors` and `grant_stale`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn tell_grants_of(v: &Value, out: &mut dyn Write) {
    for line in grant_lines(v) {
        let _ = writeln!(out, "warning: {line}");
    }
    let errors = texts(&v["errors"]);
    if !errors.is_empty() {
        json::also("grant_errors", json!(errors));
    }
    let stale = texts(&v["stale"]);
    if !stale.is_empty() {
        json::also("grant_stale", json!(stale));
    }
}

/// Whether two folder paths name one place.
fn same_folder(a: &str, b: &str) -> bool {
    use nerve_policy::paths::within;
    within(Path::new(a), Path::new(b)) && within(Path::new(b), Path::new(a))
}

/// `folder set` and `folder rm`: the change `make` builds for the stored
/// folder `path` means ([`stored_folder`]), made as [`change_folder`] makes
/// it. The folder is looked up on the config as the CLI reads it, then named
/// by its stored path, so that a change to the file in between ends in "not
/// a folder of this center" and never in another folder.
async fn change_stored_folder(
    paths: &NodePaths,
    center: &CenterArg,
    path: &Path,
    make: impl FnOnce(String) -> FolderChange,
) -> Result<Applied, String> {
    let (cfg, _) = read_config(paths).await?;
    let name = pick_center(&cfg, center)?;
    let folders = &cfg.center(&name).expect("picked above").policy.folders;
    let at = stored_folder(folders, path)?;
    change_folder(paths, center, &make(at)).await
}

/// Changes a center's folders. On Windows a running node takes the change
/// over its control pipe and makes it itself, folder grants included
/// (crate::pipe); a node that does not run, and the other platforms, take
/// it as every other change ([`edit`]).
async fn change_folder(
    paths: &NodePaths,
    center: &CenterArg,
    change: &FolderChange,
) -> Result<Applied, String> {
    #[cfg(windows)]
    match crate::pipe::call(
        paths,
        change.method(),
        change.params(center.center.as_deref()),
    )
    .await
    {
        Ok(v) => {
            return serde_json::from_value(v)
                .map_err(|e| format!("the node's answer is not understood: {e}"));
        }
        // A node that runs holds the keys' lock.
        Err(e)
            if crate::pipe::file_instead(&e, || {
                !matches!(crate::secrets::KeysLock::try_take(paths), Ok(Some(_)))
            }) => {}
        Err(e) => return Err(e),
    }
    let (cfg, _) = read_config(paths).await?;
    let name = pick_center(&cfg, center)?;
    let applied = std::cell::RefCell::new(None);
    edit(paths, |c| {
        *applied.borrow_mut() = Some(crate::folder_change::apply_to(c, Some(&name), change)?);
        Ok(())
    })
    .await?;
    Ok(applied.into_inner().expect("applied when edit succeeds"))
}

/// `nerve-node sudo on|off|status`. The password lives in the running
/// daemon only, so `on` needs one; `off` without a daemon edits the file.
/// Windows has no control socket: there the password is kept with DPAPI
/// for the service (crate::winsudo).
async fn sudo_cmd(paths: &NodePaths, c: SudoCmd, out: &mut dyn Write) -> Result<(), String> {
    let w = |out: &mut dyn Write, s: &str| {
        let _ = writeln!(out, "{s}");
    };
    #[cfg(unix)]
    {
        use nerve_transport::ctl::{NOT_RUNNING, call};
        let sock = paths.ctl_socket();
        match c {
            SudoCmd::On => {
                // Fail before asking for the password when nothing can take it.
                match call(&sock, "status", json!({})).await {
                    Ok(_) => {}
                    Err(e) if e == NOT_RUNNING => {
                        return Err(
                            "sudo on needs the running daemon: it keeps the password in memory only"
                                .into(),
                        );
                    }
                    Err(e) => return Err(e),
                }
                let password = read_password(out, "sudo password: ")?;
                call(&sock, "sudo.on", json!({"password": password})).await?;
                w(
                    out,
                    "sudo: on (only commands the sudo allow list names run with sudo)",
                );
            }
            SudoCmd::Off => {
                match call(&sock, "sudo.off", json!({})).await {
                    Ok(_) => {}
                    Err(e) if e == NOT_RUNNING => {
                        edit(paths, |c| {
                            c.machine.sudo = nerve_policy::config::Sudo::Off;
                            Ok(())
                        })
                        .await?;
                    }
                    Err(e) => return Err(e),
                }
                w(out, "sudo: off");
            }
            SudoCmd::Status => {
                let on = sudo_is_on(paths).await?;
                w(out, if on { "sudo: on" } else { "sudo: off" });
            }
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        use crate::win_host::WinHost;
        match c {
            SudoCmd::On => {
                let installed = crate::service::is_service_node(paths);
                crate::winsudo::on(paths, &WinHost, installed, out).await
            }
            SudoCmd::Off => crate::winsudo::off(paths, &WinHost, out).await,
            SudoCmd::Status => {
                let on = sudo_is_on(paths).await?;
                w(out, if on { "sudo: on" } else { "sudo: off" });
                Ok(())
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (paths, out, w);
        match c {
            SudoCmd::Status => Ok(()),
            _ => Err("the sudo switch works on Linux and Windows only".into()),
        }
    }
}

/// Whether sudo is on: the running node holds the password (on Windows the
/// signed config says so and the password is kept, crate::winsudo).
async fn sudo_is_on(paths: &NodePaths) -> Result<bool, String> {
    #[cfg(unix)]
    {
        match nerve_transport::ctl::call(&paths.ctl_socket(), "sudo.status", json!({})).await {
            Ok(v) => Ok(v["sudo"] == "on"),
            // A node that does not run holds no password.
            Err(e) if e == nerve_transport::ctl::NOT_RUNNING => Ok(false),
            Err(e) => Err(e),
        }
    }
    #[cfg(windows)]
    {
        crate::winsudo::status(paths)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = paths;
        Ok(false)
    }
}

/// Reads a password: from the terminal without echo, else one line of stdin.
#[cfg(unix)]
fn read_password(out: &mut dyn Write, prompt: &str) -> Result<String, String> {
    use std::os::fd::AsRawFd;
    let stdin = std::io::stdin();
    let fd = stdin.as_raw_fd();
    // SAFETY: plain termios calls on stdin with a zeroed struct to fill.
    let mut old: libc::termios = unsafe { std::mem::zeroed() };
    let tty = unsafe { libc::isatty(fd) == 1 && libc::tcgetattr(fd, &mut old) == 0 };
    if tty {
        let _ = write!(out, "{prompt}");
        let _ = out.flush();
        let mut quiet = old;
        quiet.c_lflag &= !libc::ECHO;
        // SAFETY: as above; restored below.
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) };
    }
    let mut line = String::new();
    let r = stdin.lock().read_line(&mut line);
    if tty {
        // SAFETY: restores what tcgetattr returned.
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &old) };
        let _ = writeln!(out);
    }
    r.map_err(|e| e.to_string())?;
    let password = line.strip_suffix('\n').unwrap_or(&line);
    let password = password.strip_suffix('\r').unwrap_or(password).to_string();
    line.clear();
    if password.is_empty() {
        return Err("no password given".into());
    }
    Ok(password)
}

fn confirm(input: &mut dyn BufRead, out: &mut dyn Write) -> Result<bool, String> {
    let _ = write!(out, "Pair with this center? [y/N] ");
    let _ = out.flush();
    let mut line = String::new();
    input.read_line(&mut line).map_err(|e| e.to_string())?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes"))
}

/// What `cap ls` lists (crate::provider::listing): the running node's, over
/// its control socket (on Windows its pipe), else what the config alone
/// tells.
async fn cap_listing(paths: &NodePaths, cfg: &NodeConfig) -> Result<Value, String> {
    #[cfg(unix)]
    let r = nerve_transport::ctl::call(&paths.ctl_socket(), "caps.list", json!({})).await;
    #[cfg(windows)]
    let r = crate::pipe::call(paths, "caps.list", json!({})).await;
    #[cfg(not(any(unix, windows)))]
    let r: Result<Value, String> = {
        let _ = paths;
        Err(nerve_transport::ctl::NOT_RUNNING.to_string())
    };
    match r {
        Ok(v) => Ok(v),
        Err(e) if e == nerve_transport::ctl::NOT_RUNNING => Ok(crate::provider::listing(cfg, None)),
        Err(e) => Err(e),
    }
}

/// The lines of `cap ls`: one per action, with its effect, where it comes
/// from and each center's setting (`center` only), the settings that name
/// no action offered now, and the programs.
fn cap_lines(cfg: &NodeConfig, v: &Value, center: Option<&str>) -> Vec<String> {
    let rows = v["capabilities"].as_array().cloned().unwrap_or_default();
    let text = |r: &Value, k: &str| r[k].as_str().unwrap_or("-").to_string();
    let names: Vec<String> = rows.iter().map(|r| text(r, "name")).collect();
    let width = |k: &str| rows.iter().map(|r| text(r, k).len()).max().unwrap_or(0);
    let (wn, we, ws) = (width("name"), width("effect"), width("source"));
    let mut lines = Vec::new();
    for r in &rows {
        let what = match r["broken"].as_str() {
            Some(why) => format!("left out: {why}"),
            None => r["centers"]
                .as_object()
                .into_iter()
                .flatten()
                .filter(|(c, _)| center.is_none_or(|w| w == c.as_str()))
                .map(|(c, set)| {
                    let set = set.as_str().unwrap_or_default();
                    // The running node says whether the center may use it
                    // now, and the switch where the owner set one.
                    let state = match (r["now"][c].as_str(), set) {
                        (_, "hidden") | (None, _) => set.to_string(),
                        (Some(now), "default") => now.to_string(),
                        (Some(now), set) => format!("{now} (set {set})"),
                    };
                    format!("{c}: {state}")
                })
                .collect::<Vec<_>>()
                .join(", "),
        };
        let line = format!(
            "{:wn$}  {:we$}  {:ws$}  {what}",
            text(r, "name"),
            text(r, "effect"),
            text(r, "source"),
        );
        lines.push(line.trim_end().to_string());
    }
    // A setting for a capability or action that nothing offers now still
    // counts once something does.
    for c in &cfg.centers {
        if center.is_some_and(|w| w != c.name) {
            continue;
        }
        for (key, set) in &c.policy.caps {
            let offered = names
                .iter()
                .any(|n| n == key || n.split_once('.').is_some_and(|(cap, _)| cap == key));
            if !offered {
                lines.push(format!(
                    "{}: {key} {} (offered by nothing now)",
                    c.name,
                    enum_str(set)
                ));
            }
        }
    }
    if v["running"] == false {
        lines.push(
            "the node does not run: each center's switch shows (cap set); whether it may use an action now, and the programs' capabilities, show while the node runs"
                .into(),
        );
    }
    lines.extend(program_lines(v));
    lines
}

/// The lines of `cap provider ls`: each program allowed, and whether it is
/// attached.
fn program_lines(v: &Value) -> Vec<String> {
    let programs = v["programs"].as_array().cloned().unwrap_or_default();
    if programs.is_empty() {
        return vec!["no program is allowed as a provider".into()];
    }
    programs
        .iter()
        .map(|p| {
            let state = match p["attached"].as_bool() {
                Some(true) => "attached",
                Some(false) => "not attached",
                None => "the node does not run",
            };
            format!(
                "program {}: {}, {state}",
                p["name"].as_str().unwrap_or_default(),
                p["exe"].as_str().unwrap_or_default()
            )
        })
        .collect()
}

fn enum_str<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn parse_enum<T: serde::de::DeserializeOwned>(s: &str, choices: &str) -> Result<T, String> {
    serde_json::from_value(json!(s)).map_err(|_| format!("{s:?}: expected {choices}"))
}

/// The path of the stored folder `folder set` and `folder rm` mean by `path`,
/// found before the path is resolved, which fails where a dangling link or a
/// loop of links stands now. In this order: the folder the path is spelled as
/// (made absolute and tidy, no link followed); the folder its resolution lands
/// at, a link at a time (`folder add` stored the real place of a path through
/// a link of the owner's, and a link may have replaced that place since); the
/// folder at the real place the path leads to.
fn stored_folder(folders: &[Folder], path: &Path) -> Result<String, String> {
    use nerve_policy::paths::within;
    let same = |a: &Path, b: &Path| within(a, b) && within(b, a);
    let stored = |p: &Path| {
        folders
            .iter()
            .find(|f| same(p, Path::new(&f.path)))
            .map(|f| f.path.clone())
    };
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path)
    };
    let spelled = nerve_policy::paths::normal_folder(&abs.display().to_string()).ok();
    if let Some(f) = spelled.and_then(|s| stored(Path::new(&s))) {
        return Ok(f);
    }
    if let Some(f) = crate::exec::lands_at(&abs, |p| stored(p).is_some()).and_then(|p| stored(&p)) {
        return Ok(f);
    }
    let real = resolve_folder(path)?;
    stored(Path::new(&real)).ok_or_else(|| crate::folder_change::not_a_folder(&real, folders))
}

/// Folders are stored resolved (symlinks followed), the way the policy
/// compares them.
fn resolve_folder(p: &Path) -> Result<String, String> {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().map_err(|e| e.to_string())?.join(p)
    };
    match nerve_policy::paths::resolve(&abs) {
        Ok(real) => Ok(real.display().to_string()),
        // On the installed node this command runs as `nerve`, which may not
        // look into the account's home; the folder is kept as given, and the
        // node looks at it as the account when a call comes.
        Err(nerve_policy::paths::PathError::Io(e))
            if e.kind() == std::io::ErrorKind::PermissionDenied =>
        {
            nerve_policy::paths::normal_folder(&abs.display().to_string())
        }
        Err(e) => Err(e.to_string()),
    }
}

fn audit_line(v: &Value) -> String {
    let s = |k: &str| match &v[k] {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    };
    if v.get("changes").is_some() {
        // A local change names the account that made it, when known.
        let user = v["user"]
            .as_str()
            .map_or_else(String::new, |u| format!(" ({u})"));
        return format!(
            "{}  settings v{} by {}{user}",
            s("ts"),
            s("version"),
            s("by")
        );
    }
    if v["kind"] == "node" {
        let steps: Vec<String> = v["steps"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|s| s.as_str().map(str::to_string))
            .collect();
        let mut line = format!("{}  {}: {}", s("ts"), s("event"), steps.join("; "));
        if let Some(e) = v["error"].as_str() {
            line.push_str(&format!(" (failed: {e})"));
        }
        return line;
    }
    if v["kind"] == "relay" {
        return format!(
            "{}  relay  {} from {} to center {}: {} after {} ({} bytes up, {} down)",
            s("ts"),
            s("node"),
            s("from"),
            s("center"),
            s("reason"),
            nerve_transport::log::span(Duration::from_millis(
                v["end"]
                    .as_u64()
                    .unwrap_or(0)
                    .saturating_sub(v["start"].as_u64().unwrap_or(0))
            )),
            s("up"),
            s("down"),
        );
    }
    if v["kind"] == "config" {
        return format!(
            "{}  config {}  {}: {}",
            s("ts"),
            s("event"),
            s("file"),
            s("reason")
        );
    }
    if v["kind"] == "audit" {
        return format!("{}  audit {} by {}", s("ts"), s("event"), s("user"));
    }
    if v["kind"] == "key" {
        return format!(
            "{}  {}  key {}: {}",
            s("ts"),
            s("center"),
            s("event"),
            s("detail")
        );
    }
    let line = format!(
        "{}  {}  {}.{}  {}  {}",
        s("ts"),
        s("center"),
        s("cap"),
        s("action"),
        s("target"),
        s("decision")
    );
    match v["reason"].as_str() {
        Some(reason) => format!("{line}: {reason}"),
        None => line,
    }
}

/// `audit`: the log through [`AuditLog::lines`], the rotated file first.
/// `--follow` looks again every 500 ms and shows the lines after the last one
/// it showed, wherever that line is now: in `audit.jsonl.1` after a rotation,
/// so the old file is finished before the new one, or further up after the
/// log dropped old refusals. With `json` the entries are as the log holds
/// them: one list, or with `follow` one JSON line each.
async fn audit(
    paths: &NodePaths,
    follow: bool,
    denied: bool,
    last: Option<usize>,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    let log = AuditLog::new(paths.audit_log());
    let mut entries = Vec::new();
    let mut shown = Shown::default();
    // --last cuts what is there at the start; with --follow every new
    // entry comes after it.
    let mut first = true;
    let mut stamp = None;
    loop {
        // Both files as they are now; the same as at the last look is
        // nothing new, and is not read again.
        let now = [log.path().to_path_buf(), log.old_path()].map(|p| {
            std::fs::metadata(p)
                .ok()
                .map(|m| (m.len(), m.modified().ok()))
        });
        if stamp.as_ref() == Some(&now) {
            tokio::time::sleep(Duration::from_millis(500)).await;
            continue;
        }
        stamp = Some(now);
        let lines = log
            .lines()
            .map_err(|e| format!("{}: {e}", log.path().display()))?;
        let mut new: Vec<Value> = lines[shown.next(&lines)..]
            .iter()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|v| {
                !denied
                    || v["decision"].as_str() == Some("forbidden")
                    || v["event"].as_str() == Some("refused")
            })
            .collect();
        if first && let Some(n) = last {
            new.drain(..new.len().saturating_sub(n));
        }
        first = false;
        for v in new {
            match (json, follow) {
                (false, _) => {
                    let _ = writeln!(out, "{}", audit_line(&v));
                }
                (true, false) => entries.push(v),
                (true, true) => {
                    let _ = writeln!(out, "{v}");
                }
            }
        }
        shown.saw(&lines);
        if !follow {
            if json {
                let _ = writeln!(out, "{}", json!({ "entries": entries }));
            }
            return Ok(());
        }
        let _ = out.flush();
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// `log clear`: the node's log and its moved-aside file emptied, and one
/// line in it of who did it. The running node writes on at the end of the
/// emptied file.
fn clear_log(paths: &NodePaths, who: &str) -> Result<(), String> {
    let file = paths.log_file();
    let mut old = file.clone().into_os_string();
    old.push(".1");
    match std::fs::remove_file(&old) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(format!("{}: {e}", Path::new(&old).display()));
        }
        _ => {}
    }
    let line = nerve_transport::log::Entry {
        ts: nerve_proto::msg::now_ms(),
        level: nerve_transport::log::Level::Info,
        node: None,
        node_id: None,
        msg: format!("the log was cleared by {who}"),
    };
    let mut line = serde_json::to_vec(&line).map_err(|e| e.to_string())?;
    line.push(b'\n');
    let mut o = std::fs::OpenOptions::new();
    o.write(true).truncate(true);
    match o.open(&file) {
        Ok(mut f) => f.write_all(&line),
        // No log yet: nothing to clear, and no line either.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
    .map_err(|e| format!("{}: {e}", file.display()))
}

/// `log`: the node's log file, the moved-aside one first (docs/user/logs.md).
/// `--follow` looks again every 500 ms and reads what was added to the file,
/// or the new file from its start once the old one was moved aside. With
/// `json` the lines are as the file holds them: one list, or with `follow`
/// one JSON line each.
async fn log_cmd(
    paths: &NodePaths,
    follow: bool,
    last: Option<usize>,
    problems: bool,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    let file = paths.log_file();
    let read = |p: &Path| match std::fs::read(p) {
        Ok(b) => Ok(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("{}: {e}", p.display())),
    };
    let mut old = file.clone().into_os_string();
    old.push(".1");
    let mut bytes = read(Path::new(&old))?;
    let current = read(&file)?;
    let mut at = current.len();
    // The file's first bytes tell it from the one that replaces it, which
    // can be as long already.
    let head = |b: &[u8]| b[..b.len().min(64)].to_vec();
    let mut first = head(&current);
    // A line the node is still writing waits for its end, also at the
    // start: read now, its first half would be no line, and the rest,
    // read later, none either.
    let whole = current
        .iter()
        .rposition(|b| *b == b'\n')
        .map_or(0, |i| i + 1);
    bytes.extend_from_slice(&current[..whole]);
    let mut rest: Vec<u8> = current[whole..].to_vec();
    // --problems: errors and warnings only, before --last counts them.
    let parse = |bytes: &[u8]| -> Vec<Value> {
        String::from_utf8_lossy(bytes)
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|v| !problems || matches!(v["level"].as_str(), Some("error" | "warn")))
            .collect()
    };
    let mut lines = parse(&bytes);
    if let Some(n) = last {
        lines.drain(..lines.len().saturating_sub(n));
    }
    let show = |out: &mut dyn Write, v: &Value| {
        let _ = if json {
            writeln!(out, "{v}")
        } else {
            writeln!(out, "{}", log_line(v))
        };
    };
    if json && !follow {
        let _ = writeln!(out, "{}", json!({ "entries": lines }));
        return Ok(());
    }
    for v in &lines {
        show(out, v);
    }
    if !follow {
        return Ok(());
    }
    loop {
        let _ = out.flush();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let now = read(&file)?;
        if now.len() < at || !now.starts_with(&first) {
            // Moved aside: what the old file got after the last look, then
            // the new file from its start.
            let moved = read(Path::new(&old))?;
            rest.extend_from_slice(moved.get(at..).unwrap_or_default());
            at = 0;
        }
        if first.len() < 64 {
            first = head(&now);
        }
        rest.extend_from_slice(&now[at..]);
        at = now.len();
        let Some(end) = rest.iter().rposition(|b| *b == b'\n') else {
            continue;
        };
        let done: Vec<u8> = rest.drain(..=end).collect();
        for v in parse(&done) {
            show(out, &v);
        }
    }
}

/// One line of the log for people: the time, the level, the message.
fn log_line(v: &Value) -> String {
    let mut line = format!(
        "{}  {}  {}",
        v["ts"].as_u64().unwrap_or_default(),
        v["level"].as_str().unwrap_or_default(),
        v["msg"].as_str().unwrap_or_default()
    );
    if let Some(n) = v["node"].as_str() {
        line.push_str(&format!(" ({n})"));
    }
    line
}

/// Where `audit --follow` is: the last line it looked at, how many copies
/// of it ended what it saw, and its time.
#[derive(Default)]
struct Shown {
    last: Option<(String, usize, u64)>,
}

impl Shown {
    /// The index in `lines` of the first line not looked at yet.
    fn next(&self, lines: &[String]) -> usize {
        let Some((last, copies, ts)) = &self.last else {
            return 0;
        };
        match lines.iter().rposition(|l| l == last) {
            Some(end) => {
                let run = lines[..=end]
                    .iter()
                    .rev()
                    .take_while(|l| *l == last)
                    .count();
                // The copies seen began the run; the rest are new.
                if run > *copies {
                    end + 1 - run + copies
                } else {
                    end + 1
                }
            }
            // The log dropped that line meanwhile (a refusal, or two
            // rotations): what came after it is newer.
            None => lines
                .iter()
                .position(|l| line_ts(l) > *ts)
                .unwrap_or(lines.len()),
        }
    }

    fn saw(&mut self, lines: &[String]) {
        if let Some(last) = lines.last() {
            let copies = lines.iter().rev().take_while(|l| *l == last).count();
            self.last = Some((last.clone(), copies, line_ts(last)));
        }
    }
}

fn line_ts(line: &str) -> u64 {
    serde_json::from_str::<Value>(line)
        .ok()
        .and_then(|v| v["ts"].as_u64())
        .unwrap_or(0)
}

/// Why `config set machine.user` is refused on Linux.
pub const NO_ACCOUNT_TO_CHOOSE: &str = "machine.user is Windows's: on Linux commands run as nerve-run, or in user mode as the owner, the account that ran `install`";

/// `config get|set|unset|add|remove` on dotted keys. `center.<name>` picks
/// a `[[center]]` entry by its name.
async fn config_cmd(paths: &NodePaths, c: ConfigCmd, out: &mut dyn Write) -> Result<(), String> {
    if let ConfigCmd::Accept = c {
        let v = accept(paths).await?;
        let _ = writeln!(out, "accepted node.toml as version {v}");
        return Ok(());
    }
    if let ConfigCmd::Get { key } = &c {
        let (cfg, _) = read_config(paths).await?;
        let doc = as_table(&cfg)?;
        let v = lookup(&toml::Value::Table(doc), &segments(key))
            .ok_or_else(|| format!("{key} is not set"))?;
        let _ = writeln!(out, "{}", show(&v));
        return Ok(());
    }
    // Linux chooses no account for the commands: they run as nerve-run or
    // as the owner, the account that ran `install`.
    if !cfg!(windows)
        && let ConfigCmd::Set { key, .. }
        | ConfigCmd::Unset { key }
        | ConfigCmd::Add { key, .. }
        | ConfigCmd::Remove { key, .. } = &c
        && key == "machine.user"
    {
        return Err(NO_ACCOUNT_TO_CHOOSE.into());
    }
    let before = std::cell::Cell::new(SecretStorage::File);
    let cfg = edit(paths, |cfg| {
        before.set(cfg.machine.secret_storage);
        let mut doc = toml::Value::Table(as_table(cfg)?);
        match &c {
            ConfigCmd::Get { .. } | ConfigCmd::Accept => {}
            ConfigCmd::Set { key, value } => {
                let (parent, last) = split_key(key)?;
                table_at(&mut doc, &parent, true)?.insert(last, literal(value));
            }
            ConfigCmd::Unset { key } => {
                let (parent, last) = split_key(key)?;
                table_at(&mut doc, &parent, false)?
                    .remove(&last)
                    .ok_or_else(|| format!("{key} is not set"))?;
            }
            ConfigCmd::Add { key, value } => {
                let (parent, last) = split_key(key)?;
                let t = table_at(&mut doc, &parent, true)?;
                let list = t
                    .entry(last)
                    .or_insert_with(|| toml::Value::Array(Vec::new()));
                let toml::Value::Array(a) = list else {
                    return Err(format!("{key} is not a list"));
                };
                // The text `rule ls` prints for a tab or line break is not
                // one: the rule would look like the listed one and not be.
                // Any other text is a rule as it stands (`C:\tools` too).
                if ["allow", "deny", "sudo_allow"]
                    .iter()
                    .any(|l| key.starts_with("center.") && key.ends_with(&format!(".policy.{l}")))
                {
                    let listed: Vec<String> = a
                        .iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect();
                    rules::check_not_a_listed_form(value, &listed)?;
                }
                a.push(literal(value));
            }
            ConfigCmd::Remove { key, value } => {
                let (parent, last) = split_key(key)?;
                let t = table_at(&mut doc, &parent, false)?;
                let Some(toml::Value::Array(a)) = t.get_mut(&last) else {
                    return Err(format!("{key} is not a list"));
                };
                let v = literal(value);
                let before = a.len();
                a.retain(|x| x != &v);
                if a.len() == before {
                    return Err(format!("{value} is not in {key}"));
                }
            }
        }
        let text = toml::to_string(&doc).map_err(|e| e.to_string())?;
        let mut new = NodeConfig::parse(&text)?;
        new.version = cfg.version;
        *cfg = new;
        Ok(())
    })
    .await?;
    let _ = writeln!(out, "saved");
    if before.get() != SecretStorage::Keyring
        && cfg.machine.secret_storage == SecretStorage::Keyring
    {
        tell_folder_commands(paths, &cfg, out).await;
    }
    Ok(())
}

/// Says, once the keys went into the keyring, that folder mode now runs no
/// command where Landlock cannot keep a command off the session bus
/// (crate::daemon::KEYRING_NOT_CONFINED). The running node knows; without one,
/// the kernel here and the account `cfg` runs commands as tell.
async fn tell_folder_commands(paths: &NodePaths, cfg: &NodeConfig, out: &mut dyn Write) {
    #[cfg(unix)]
    match nerve_transport::ctl::call(&paths.ctl_socket(), "status", json!({})).await {
        Ok(v) => {
            if v["folder_commands_off"] == crate::daemon::KEYRING_NOT_CONFINED {
                let _ = writeln!(out, "{}", folder_commands_off());
            }
            return;
        }
        Err(e) if e == nerve_transport::ctl::NOT_RUNNING => {}
        // The node that runs knows, and was not asked.
        Err(e) => {
            let _ = writeln!(
                out,
                "the running node was not asked whether folder mode still runs commands ({e}); `nerve-node status` shows it"
            );
            return;
        }
    }
    if keyring_turns_commands_off(nerve_sandbox::Confinement::detect(), || {
        node_command_account(paths, cfg)
    }) {
        let _ = writeln!(out, "{}", folder_commands_off());
    }
}

/// The account the node at `paths` runs commands as with `cfg`, looked up as
/// that node does (crate::account::for_commands), for a CLI that finds no
/// node to ask: the installed node runs as its own user and can switch, a
/// node run by hand as this CLI's user. `None` for the node's own user, and
/// where no command runs.
fn node_command_account(paths: &NodePaths, cfg: &NodeConfig) -> Option<crate::service::Account> {
    let me = nerve_transport::net::euid();
    let service = crate::service::is_service_node(paths);
    let own = match service {
        true => crate::account::lookup(crate::service::USER)
            .ok()
            .flatten()
            .map_or(me, |a| a.uid),
        false => me,
    };
    // Folder mode's account; the owner is the unit's on Linux, the
    // config's on Windows.
    let owner = if cfg!(windows) {
        cfg.machine.user.clone()
    } else {
        crate::service::owner_of(paths)
    };
    crate::account::for_commands(
        false,
        owner.as_deref(),
        own,
        service,
        service || crate::account::can_switch(),
        crate::account::lookup,
    )
    .ok()
    .flatten()
}

fn folder_commands_off() -> String {
    format!(
        "folder mode runs no command: {}",
        crate::daemon::KEYRING_NOT_CONFINED
    )
}

/// Whether, with the keys in the keyring, `c` leaves folder mode's commands
/// a way to the session bus: for commands that run as the node's own user or
/// root (crate::daemon::keys_kept_from_commands). `account` is asked only
/// where commands are confined at all.
fn keyring_turns_commands_off(
    c: nerve_sandbox::Confinement,
    account: impl FnOnce() -> Option<crate::service::Account>,
) -> bool {
    c.available() && !crate::daemon::keys_kept_from_commands(SecretStorage::Keyring, account)
}

/// `proxy set|rm|ls`. The header values, and a user name and password given
/// in an `http://` URL, go into the system keyring ([`crate::secrets`]);
/// `node.toml` keeps the URL without them and the header names. The
/// installed node on Windows refuses them, as the service does not read the
/// keyring of the account that runs this. The password of an `https://`
/// proxy, a relay token, is kept with the node's own keys instead, where
/// `machine.secret_storage` says, and its user name in `connection.login`.
/// Nothing here prints, logs or audits a value.
async fn proxy_cmd(paths: &NodePaths, c: ProxyCmd, out: &mut dyn Write) -> Result<(), String> {
    match c {
        ProxyCmd::Set {
            url,
            pin,
            mut headers,
            password_stdin,
            headers_stdin,
        } => {
            let mut stdin_password = None;
            if password_stdin || headers_stdin {
                let mut text = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)
                    .map_err(|e| format!("cannot read stdin: {e}"))?;
                let (password, more) = stdin_secrets(&text, password_stdin, headers_stdin);
                stdin_password = password;
                headers.extend(more);
            }
            // A relay's link holds the proxy URL with this node's login and
            // the pin: one paste (docs/user/relay.md).
            let (url, pin) =
                if nerve_proto::link::strip_prefix_ci(url.trim(), "nerve://relay").is_some() {
                    let link = nerve_proto::link::RelayLink::parse(&url)?;
                    if pin.as_ref().is_some_and(|p| *p != link.pin) {
                        return Err("the relay link carries the pin; give no other --pin".into());
                    }
                    (link.proxy_url(), Some(link.pin))
                } else {
                    (url, pin)
                };
            let mut hs: Vec<(String, String)> = Vec::new();
            for (i, h) in headers.iter().enumerate() {
                // Not echoed: without its colon the whole line may be the secret.
                let (k, v) = h
                    .split_once(':')
                    .ok_or_else(|| format!("--header number {} is not `Name: value`", i + 1))?;
                let k = k.trim().to_string();
                if hs.iter().any(|(n, _)| n.eq_ignore_ascii_case(&k)) {
                    return Err(format!("the header {k} is given twice"));
                }
                hs.push((k, v.trim().to_string()));
            }
            let (url, mut login) = split_credentials(&url)?;
            if let Some(password) = stdin_password {
                match &mut login {
                    Some((_, p)) if p.is_empty() => *p = password,
                    Some(_) => {
                        return Err("the proxy URL has a password already; with --password-stdin give the user name alone, http://user@host:port".into());
                    }
                    None => {
                        return Err("--password-stdin needs a proxy URL with a user name: http://user@host:port".into());
                    }
                }
            }
            let https = url.to_ascii_lowercase().starts_with("https://");
            let (now, _) = read_config(paths).await?;
            let storage = now.machine.secret_storage;
            // An https:// proxy's login is the node's own secret.
            let (login, kept) = match login {
                Some((user, password)) if https => {
                    if !nerve_policy::config::valid_login(&user) {
                        return Err("the proxy URL has an empty or bad user name".into());
                    }
                    if hs
                        .iter()
                        .any(|(n, _)| n.eq_ignore_ascii_case(PROXY_AUTHORIZATION))
                    {
                        return Err(format!(
                            "give the proxy's user name and password either in the URL or as a {PROXY_AUTHORIZATION} header, not both"
                        ));
                    }
                    (None, Some((user, password)))
                }
                other => (other, None),
            };
            if let Some((user, password)) = login {
                if hs
                    .iter()
                    .any(|(n, _)| n.eq_ignore_ascii_case(PROXY_AUTHORIZATION))
                {
                    return Err(format!(
                        "give the proxy's user name and password either in the URL or as a {PROXY_AUTHORIZATION} header, not both"
                    ));
                }
                use base64::Engine;
                let basic =
                    base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
                hs.push((PROXY_AUTHORIZATION.into(), format!("Basic {basic}")));
            }
            nerve_transport::net::Proxy::parse(&url, hs.clone())?.pinned(pin.clone())?;
            let names: Vec<String> = hs.iter().map(|(k, _)| k.clone()).collect();
            // The relay token goes where the node's keys are; where that is
            // a keyring that does not answer, this fails as for any key of
            // the node, and nothing is changed.
            match &kept {
                Some((_, password)) => crate::secrets::store_proxy_login(paths, storage, password)?,
                None if now.connection.login.is_some() => {
                    let _ = crate::secrets::remove_proxy_login(paths, storage);
                }
                None => {}
            }
            // The keyring first: when it cannot take the values, node.toml
            // stays as it was rather than name headers nobody can send. A
            // proxy without headers leaves the keyring alone, unless the one
            // before had some: their entry would only linger.
            if !hs.is_empty() {
                crate::secrets::store_proxy_headers(paths, &hs)?;
            } else if !now.connection.headers.is_empty() {
                let _ = crate::secrets::remove_proxy_headers(paths);
            }
            let user = kept.as_ref().map(|(u, _)| u.clone());
            edit(paths, |c| {
                c.connection.proxy = Some(url.clone());
                c.connection.pin = pin.clone();
                c.connection.login = user.clone();
                c.connection.headers = names.clone();
                Ok(())
            })
            .await?;
            let _ = writeln!(out, "proxy {url}");
            if let Some(p) = &pin {
                let _ = writeln!(out, "pin {p}");
            }
            if let Some(u) = &user {
                let _ = writeln!(
                    out,
                    "login {u} (its password is kept with the node's keys: {})",
                    keys_place(storage)
                );
            }
            for n in &names {
                let _ = writeln!(out, "header {n} (its value is in the system keyring)");
            }
            Ok(())
        }
        ProxyCmd::Rm => {
            let (cfg, _) = read_config(paths).await?;
            edit(paths, |c| {
                c.connection.proxy = None;
                c.connection.pin = None;
                c.connection.login = None;
                c.connection.headers.clear();
                Ok(())
            })
            .await?;
            let _ = writeln!(out, "no proxy");
            if cfg.connection.login.is_some()
                && let Err(e) =
                    crate::secrets::remove_proxy_login(paths, cfg.machine.secret_storage)
            {
                return Err(format!("the proxy is removed, but {e}"));
            }
            // A proxy without headers has no entry; where there is no
            // keyring, asking for one would only fail.
            if cfg.connection.headers.is_empty() {
                return Ok(());
            }
            match crate::secrets::remove_proxy_headers(paths) {
                Ok(true) => {
                    let _ = writeln!(out, "deleted the header values from the system keyring");
                }
                Ok(false) => {}
                Err(e) => return Err(format!("the proxy is removed, but {e}")),
            }
            Ok(())
        }
        ProxyCmd::Ls => {
            let (cfg, _) = read_config(paths).await?;
            let Some(url) = &cfg.connection.proxy else {
                let _ = writeln!(out, "no proxy");
                return Ok(());
            };
            let _ = writeln!(out, "proxy {url}");
            if let Some(p) = &cfg.connection.pin {
                let _ = writeln!(out, "pin {p}");
            }
            if let Some(u) = &cfg.connection.login {
                let storage = cfg.machine.secret_storage;
                match crate::secrets::proxy_login(paths, storage) {
                    Ok(_) => {
                        let _ = writeln!(
                            out,
                            "login {u} (its password is kept with the node's keys: {})",
                            keys_place(storage)
                        );
                    }
                    Err(e) => {
                        let _ = writeln!(out, "login {u}");
                        let _ = writeln!(out, "the link cannot use this proxy: {e}");
                    }
                }
            }
            // The keyring is asked whether it holds every value; only the
            // names are shown.
            let names = &cfg.connection.headers;
            match crate::secrets::proxy_headers(paths, names) {
                Ok(_) => {
                    for n in names {
                        let _ = writeln!(out, "header {n} (its value is in the system keyring)");
                    }
                }
                Err(e) => {
                    for n in names {
                        let _ = writeln!(out, "header {n}");
                    }
                    let _ = writeln!(out, "the link cannot use this proxy: {e}");
                }
            }
            Ok(())
        }
    }
}

/// `relay set|off|add|token|set-centers|set-limits|rm|ls` (crate::relay).
/// A token is shown once, by `add` or `token`; `node.toml` keeps only its
/// hash. Each change says when it is in force ([`relay_in_force`]).
async fn relay_cmd(paths: &NodePaths, c: RelayCmd, out: &mut dyn Write) -> Result<(), String> {
    let w = |out: &mut dyn Write, s: String| {
        let _ = writeln!(out, "{s}");
    };
    match c {
        RelayCmd::Set {
            address,
            max_links,
            max_links_per_node,
            max_opens_per_minute,
        } => {
            if address.parse::<std::net::SocketAddr>().is_err() {
                return Err(format!(
                    "relay.listen {address:?}: an address and a port, like 0.0.0.0:7490 or [::]:7490"
                ));
            }
            let (now, _) = read_config(paths).await?;
            let (pin, made) = relay_pin(paths, &now, Some(&address))?;
            let cfg = edit(paths, |c| {
                c.relay.listen = Some(address.clone());
                c.relay.pin = Some(pin.clone());
                if let Some(n) = max_links {
                    c.relay.max_links = n;
                }
                if let Some(n) = max_links_per_node {
                    c.relay.max_links_per_node = n;
                }
                if let Some(n) = max_opens_per_minute {
                    c.relay.max_opens_per_minute = n;
                }
                Ok(())
            })
            .await?;
            w(
                out,
                format!(
                    "relay on {address}: at most {} tunnels, {} per node, {} opened a minute per node",
                    cfg.relay.max_links,
                    cfg.relay.max_links_per_node,
                    cfg.relay.max_opens_per_minute
                ),
            );
            w(out, format!("its TLS certificate has the pin {pin}"));
            if made && now.relay.pin.is_some() {
                w(
                    out,
                    "that is a new certificate: the relayed nodes need the new pin in `proxy set --pin`".into(),
                );
            }
            if cfg.relay.nodes.is_empty() {
                w(
                    out,
                    "no node may use it yet: `nerve-node relay add <name>` makes a token".into(),
                );
            }
            relay_in_force(paths, out, None).await;
            Ok(())
        }
        RelayCmd::Off => {
            edit(paths, |c| {
                c.relay.listen = None;
                Ok(())
            })
            .await?;
            w(out, "relay off".into());
            relay_in_force(
                paths,
                out,
                Some("the relay stops listening, and every tunnel ends"),
            )
            .await;
            Ok(())
        }
        RelayCmd::Add {
            name,
            centers,
            address,
        } => {
            if !nerve_proto::valid_node_name(&name) {
                return Err(format!(
                    "{name:?} is not a relay node name: 1 to 32 characters of a-z, 0-9 and -, starting and ending with a letter or digit"
                ));
            }
            let (now, _) = read_config(paths).await?;
            relay_centers(&now, &centers)?;
            let at = link_address(now.relay.listen.as_deref(), address.as_deref())?;
            let (pin, made) = relay_pin(paths, &now, now.relay.listen.as_deref())?;
            let (token, hash) = crate::relay::new_token();
            let cfg = edit(paths, |c| {
                if c.relay.node(&name).is_some() {
                    return Err(format!(
                        "the relay knows a node {name} already; `nerve-node relay rm {name}` takes its token away first"
                    ));
                }
                relay_centers(c, &centers)?;
                c.relay.pin = Some(pin.clone());
                c.relay.nodes.push(nerve_policy::config::RelayNode {
                    name: name.clone(),
                    token_sha256: hash.clone(),
                    centers: centers.clone(),
                    max_links: None,
                    max_opens_per_minute: None,
                });
                Ok(())
            })
            .await?;
            if made && now.relay.pin.is_some() {
                w(
                    out,
                    format!(
                        "the relay's TLS key was gone or did not match its pin, so it has a new certificate (pin {pin}): the relayed nodes need the new pin in `proxy set --pin`"
                    ),
                );
            }
            w(
                out,
                format!("relay node {name} added; its link, shown only now:"),
            );
            relay_link(out, &name, &token, &at, &pin, address.is_none());
            w(out, format!("it may reach {}", reach_of(&centers)));
            json::also(
                "token",
                link_json(
                    &name,
                    &token,
                    &at,
                    &pin,
                    &centers,
                    made && now.relay.pin.is_some(),
                    cfg.relay.listen.is_none(),
                ),
            );
            if cfg.relay.listen.is_none() {
                w(
                    out,
                    "the relay is off: `nerve-node relay set <address>` turns it on".into(),
                );
            }
            relay_in_force(paths, out, None).await;
            Ok(())
        }
        RelayCmd::SetLimits {
            name,
            max_links,
            max_opens_per_minute,
        } => {
            let cfg = edit(paths, |c| {
                let node = c
                    .relay
                    .nodes
                    .iter_mut()
                    .find(|n| n.name == name)
                    .ok_or_else(|| format!("the relay knows no node {name}"))?;
                // As `relay set`: a limit not given stays; no flag at all
                // gives the node the relay's limits again.
                if max_links.is_none() && max_opens_per_minute.is_none() {
                    node.max_links = None;
                    node.max_opens_per_minute = None;
                }
                if let Some(n) = max_links {
                    node.max_links = Some(n);
                }
                if let Some(n) = max_opens_per_minute {
                    node.max_opens_per_minute = Some(n);
                }
                Ok(())
            })
            .await?;
            let node = cfg.relay.node(&name).expect("set above");
            let links = node.links(&cfg.relay);
            let mut line = format!(
                "relay node {name}: at most {links} tunnels at once, {} opened a minute",
                node.opens(&cfg.relay)
            );
            if cfg.relay.max_links < links {
                line.push_str(&format!(
                    " (the relay's {} tunnels in all bound it; `relay set <address> --max-links N` raises that)",
                    cfg.relay.max_links
                ));
            }
            w(out, line);
            relay_in_force(paths, out, None).await;
            Ok(())
        }
        RelayCmd::Token { name, address } => {
            let (now, _) = read_config(paths).await?;
            let at = link_address(now.relay.listen.as_deref(), address.as_deref())?;
            let (pin, made) = relay_pin(paths, &now, now.relay.listen.as_deref())?;
            let (token, hash) = crate::relay::new_token();
            let cfg = edit(paths, |c| {
                c.relay.pin = Some(pin.clone());
                let node = c
                    .relay
                    .nodes
                    .iter_mut()
                    .find(|n| n.name == name)
                    .ok_or_else(|| {
                        format!("the relay knows no node {name}; `relay add {name}` makes one")
                    })?;
                node.token_sha256 = hash.clone();
                Ok(())
            })
            .await?;
            if made && now.relay.pin.is_some() {
                w(
                    out,
                    format!(
                        "the relay's TLS key was gone or did not match its pin, so it has a new certificate (pin {pin}): the relayed nodes need the new pin in `proxy set --pin`"
                    ),
                );
            }
            let node = cfg.relay.node(&name).expect("set above");
            // Whether the old token is dead is the running node's to say
            // (`relay_in_force`): on Windows it takes the change at its next
            // start.
            w(
                out,
                format!("relay node {name} has a new token; its link, shown only now:"),
            );
            relay_link(out, &name, &token, &at, &pin, address.is_none());
            w(out, format!("it may reach {}", reach_of(&node.centers)));
            json::also(
                "token",
                link_json(
                    &name,
                    &token,
                    &at,
                    &pin,
                    &node.centers,
                    made && now.relay.pin.is_some(),
                    cfg.relay.listen.is_none(),
                ),
            );
            if cfg.relay.listen.is_none() {
                w(
                    out,
                    "the relay is off: `nerve-node relay set <address>` turns it on".into(),
                );
            }
            relay_in_force(
                paths,
                out,
                Some("the old token no longer works, and its tunnels end"),
            )
            .await;
            Ok(())
        }
        RelayCmd::SetCenters { name, centers } => {
            edit(paths, |c| {
                relay_centers(c, &centers)?;
                let node = c
                    .relay
                    .nodes
                    .iter_mut()
                    .find(|n| n.name == name)
                    .ok_or_else(|| format!("the relay knows no node {name}"))?;
                node.centers = centers.clone();
                Ok(())
            })
            .await?;
            w(
                out,
                format!("relay node {name} may reach {}", reach_of(&centers)),
            );
            relay_in_force(paths, out, Some("its tunnels to other centers end")).await;
            Ok(())
        }
        RelayCmd::Rm { name } => {
            edit(paths, |c| {
                let before = c.relay.nodes.len();
                c.relay.nodes.retain(|n| n.name != name);
                if c.relay.nodes.len() == before {
                    return Err(format!("the relay knows no node {name}"));
                }
                Ok(())
            })
            .await?;
            w(out, format!("relay node {name} removed"));
            relay_in_force(
                paths,
                out,
                Some("its token no longer works, and its tunnels end"),
            )
            .await;
            Ok(())
        }
        RelayCmd::Ls => {
            let (cfg, _) = read_config(paths).await?;
            let r = &cfg.relay;
            #[cfg(unix)]
            let live =
                match nerve_transport::ctl::call(&paths.ctl_socket(), "status", json!({})).await {
                    Ok(v) => Some(v["relay"].clone()),
                    Err(e) if e == nerve_transport::ctl::NOT_RUNNING => None,
                    Err(e) => return Err(e),
                };
            // Windows: the control pipe answers `status` too. Only a pipe
            // that is not there means no node runs; any other error is
            // said, not taken for "no tunnel".
            #[cfg(windows)]
            let live = match crate::pipe::call(paths, "status", json!({})).await {
                Ok(v) => Some(v["relay"].clone()),
                Err(e) if e == nerve_transport::ctl::NOT_RUNNING => None,
                Err(e) => return Err(format!("cannot ask the running node: {e}")),
            };
            #[cfg(not(any(unix, windows)))]
            let live: Option<Value> = None;
            match (&r.listen, &live) {
                (None, _) => w(out, "relay off".into()),
                (Some(l), Some(v)) => w(
                    out,
                    format!(
                        "relay on {l}: {}",
                        v["status"].as_str().unwrap_or("not known")
                    ),
                ),
                (Some(l), None) => w(out, format!("relay on {l}")),
            }
            w(
                out,
                format!(
                    "at most {} tunnels, {} per node, {} opened a minute per node",
                    r.max_links, r.max_links_per_node, r.max_opens_per_minute
                ),
            );
            if let Some(pin) = &r.pin {
                w(out, format!("pin {pin}"));
            }
            if r.nodes.is_empty() {
                w(out, "no node may use it".into());
            }
            for n in &r.nodes {
                let mut line = format!("node {}: {}", n.name, reach_of(&n.centers));
                if n.max_links.is_some() || n.max_opens_per_minute.is_some() {
                    line.push_str(&format!(
                        "; its own limits: {} tunnels at once, {} opened a minute",
                        n.links(r),
                        n.opens(r)
                    ));
                }
                w(out, line);
            }
            match live {
                Some(v) => {
                    let now = crate::now_ms();
                    for t in v["tunnels"].as_array().into_iter().flatten() {
                        let since = t["since_ms"].as_u64().unwrap_or(now);
                        w(
                            out,
                            format!(
                                "tunnel {} from {} to center {} for {}",
                                t["node"].as_str().unwrap_or_default(),
                                t["from"].as_str().unwrap_or_default(),
                                t["center"].as_str().unwrap_or_default(),
                                nerve_transport::log::span(std::time::Duration::from_millis(
                                    now.saturating_sub(since)
                                )),
                            ),
                        );
                    }
                }
                None if r.listen.is_some() => {
                    w(out, "no node runs here, so no tunnel is open".into())
                }
                None => {}
            }
            Ok(())
        }
    }
}

/// Says when a relay change is in force. A running node that took it
/// applies it at once: `now` says what that does ("its tunnels end"), for
/// the changes that take something away. On Windows the CLI writes the file
/// and the running node reads it at its next start, so until then that node
/// goes on by its old relay settings, for new tunnels as well as open ones:
/// a removed or replaced token still opens tunnels, and a new one is
/// refused. With no node running there is nothing to say.
async fn relay_in_force(paths: &NodePaths, out: &mut dyn Write, now: Option<&str>) {
    if daemon_answers(paths, false).await {
        if let Some(what) = now {
            let _ = writeln!(out, "{what} now");
        }
    } else if cfg!(windows) {
        let _ = writeln!(out, "{RELAY_AT_NEXT_START}");
        waits_for_next_start();
    }
}

/// [`relay_in_force`] on Windows, where a running node has not taken the
/// change.
const RELAY_AT_NEXT_START: &str = "a running node takes this change only at its next start, and until then works by its old relay settings: a removed or replaced token still opens new tunnels, the tunnels it carries stay, and a new token or node is refused. Restart it (`Restart-Service nerve-node` for the installed node) to apply the change now";

/// Refuses a `--center` list that names a center this node is not paired
/// with, or one twice.
fn relay_centers(cfg: &NodeConfig, centers: &[String]) -> Result<(), String> {
    for (i, c) in centers.iter().enumerate() {
        let Some(entry) = cfg.center(c) else {
            return Err(format!("no center named {c} is paired here"));
        };
        if centers[..i].contains(c) {
            return Err(format!("--center {c} is given twice"));
        }
        // A tunnel reaches a host and port, not a center: a center there
        // that is not on the list would be reached as well.
        let at = |url: &str| {
            nerve_proto::link::CenterUrl::parse(url)
                .ok()
                .map(|u| (u.host, u.port))
        };
        let same = |a: Option<(String, u16)>, b: Option<(String, u16)>| match (a, b) {
            (Some((ha, pa)), Some((hb, pb))) => pa == pb && crate::relay::same_host(&ha, &hb),
            _ => false,
        };
        if let Some(other) = cfg.centers.iter().find(|o| {
            o.name != entry.name && !centers.contains(&o.name) && same(at(&o.url), at(&entry.url))
        }) {
            return Err(format!(
                "the centers {c} and {} share one host and port, and a tunnel reaches the host and port, so the relay cannot keep them apart: name both or neither",
                other.name
            ));
        }
    }
    Ok(())
}

/// What a relay node's center list allows, in words.
fn reach_of(centers: &[String]) -> String {
    if centers.is_empty() {
        "every https center of this node".into()
    } else {
        format!("the centers {}", centers.join(", "))
    }
}

/// The pin of the relay's TLS certificate, and whether it was made now: one
/// is made when the relay has none, or its key is gone or is not the one
/// `relay.pin` names. The key goes where the node keeps its keys
/// (`machine.secret_storage`), before the config names its pin; where that
/// is a keyring that does not answer, this fails as for any of its keys.
fn relay_pin(
    paths: &NodePaths,
    cfg: &NodeConfig,
    address: Option<&str>,
) -> Result<(String, bool), String> {
    let storage = cfg.machine.secret_storage;
    if let Some(pin) = &cfg.relay.pin
        && let Ok(Some(id)) = crate::secrets::relay_tls(paths, storage)
        && id.pin() == *pin
    {
        return Ok((pin.clone(), false));
    }
    let names: Vec<String> = address
        .and_then(|a| a.parse::<std::net::SocketAddr>().ok())
        .filter(|a| !a.ip().is_unspecified())
        .map(|a| a.ip().to_string())
        .into_iter()
        .collect();
    let id = nerve_transport::tls::ServerIdentity::generate(&names)?;
    crate::secrets::store_relay_tls(paths, storage, &id)?;
    Ok((id.pin(), true))
}

/// The port a relay link names when the relay has no address to listen on
/// yet: the one docs/user/relay.md uses.
const RELAY_PORT: u16 = 7490;

/// Where a relayed node finds the relay, for its link: `given` (with the
/// relay's port when it names none), else the address the relay listens on,
/// else this machine's host name, at the port it listens on.
pub fn link_address(listen: Option<&str>, given: Option<&str>) -> Result<String, String> {
    use nerve_proto::link::valid_host_port;
    let listen = listen.and_then(|l| l.parse::<std::net::SocketAddr>().ok());
    let port = listen.map_or(RELAY_PORT, |a| a.port());
    let at = match given.map(str::trim) {
        Some(g) if valid_host_port(g) => g.to_string(),
        Some(g) if g.parse::<std::net::Ipv6Addr>().is_ok() => format!("[{g}]:{port}"),
        Some(g) => format!("{g}:{port}"),
        None => match listen {
            Some(a) if !a.ip().is_unspecified() => a.to_string(),
            _ => format!("{}:{port}", crate::descriptor::host_name()),
        },
    };
    if let Some(g) = given
        && !valid_host_port(&at)
    {
        return Err(format!(
            "--address {g:?}: a host name or address, with or without :PORT"
        ));
    }
    Ok(at)
}

/// The lines that hand a relayed node its link: the link, and how the other
/// node takes it. `guessed`: the address is this program's guess, which the
/// owner may need to give.
fn relay_link(out: &mut dyn Write, name: &str, token: &str, at: &str, pin: &str, guessed: bool) {
    let link = nerve_proto::link::RelayLink {
        address: at.into(),
        node: name.into(),
        token: token.into(),
        pin: pin.into(),
    }
    .render();
    let _ = writeln!(out, "  {link}");
    let _ = writeln!(
        out,
        "on {name}, paste it in the desktop app (Relay, Connect), or run:"
    );
    let _ = writeln!(out, "  nerve-node proxy set '{link}'");
    if guessed {
        let _ = writeln!(
            out,
            "the link reaches this machine as {at}; if {name} knows it by another name or address, make a new link with `relay token {name} --address <it>`"
        );
    }
}

/// What `relay add` and `relay token` give a program besides their lines.
fn link_json(
    name: &str,
    token: &str,
    at: &str,
    pin: &str,
    centers: &[String],
    new_pin: bool,
    relay_off: bool,
) -> Value {
    let link = nerve_proto::link::RelayLink {
        address: at.into(),
        node: name.into(),
        token: token.into(),
        pin: pin.into(),
    };
    json!({
        "node": name,
        "token": token,
        "address": at,
        "link": link.render(),
        "proxy": link.proxy_url(),
        "pin": pin,
        "reach": reach_of(centers),
        "new_pin": new_pin,
        "relay_off": relay_off,
    })
}

const PROXY_AUTHORIZATION: &str = "Proxy-Authorization";

/// Where the node's keys are, in words.
fn keys_place(storage: SecretStorage) -> &'static str {
    match storage {
        SecretStorage::File => "a file in the config folder",
        SecretStorage::Keyring => "the system keyring",
    }
}

/// Splits a user name and password off a proxy URL
/// (`http://user:pass@host:port`), percent-escapes decoded. Errors never quote
/// the URL once it holds an `@`.
/// What `proxy set` reads from stdin: with `password`, the first line is
/// the password; with `headers`, every other line that is not empty is a
/// header.
fn stdin_secrets(text: &str, password: bool, headers: bool) -> (Option<String>, Vec<String>) {
    let mut lines = text.lines().map(|l| l.trim_end_matches('\r'));
    let pw = if password {
        Some(lines.next().unwrap_or_default().to_string())
    } else {
        None
    };
    let hs = if headers {
        lines
            .filter(|l| !l.trim().is_empty())
            .map(str::to_string)
            .collect()
    } else {
        Vec::new()
    };
    (pw, hs)
}

fn split_credentials(url: &str) -> Result<(String, Option<(String, String)>), String> {
    let Some(at) = url.rfind('@') else {
        return Ok((url.to_string(), None));
    };
    let scheme_end = url
        .find("://")
        .filter(|i| *i < at)
        .ok_or("a proxy URL with a user name starts with http://")?;
    let (scheme, info, rest) = (
        &url[..scheme_end + 3],
        &url[scheme_end + 3..at],
        &url[at + 1..],
    );
    let (user, password) = info.split_once(':').unwrap_or((info, ""));
    let decode = |s: &str| {
        pct_decode(s).ok_or("the user name or password in the proxy URL has a bad %-escape")
    };
    let (user, password) = (decode(user)?, decode(password)?);
    if user.is_empty() || user.contains(':') {
        return Err("the proxy URL has an empty or bad user name".into());
    }
    Ok((format!("{scheme}{rest}"), Some((user, password))))
}

/// `%XX` escapes decoded; `None` for a broken escape or text that is not UTF-8.
fn pct_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// `config accept`: the running daemon takes the file, or, when none runs,
/// the file is signed here.
async fn accept(paths: &NodePaths) -> Result<u64, String> {
    // Keys already in the keyring move nowhere when the file is taken, so
    // the settings store alone would not refuse it.
    if crate::secrets::stated_storage(paths) == SecretStorage::Keyring
        && let Some(n) = crate::secrets::no_keyring(paths)
    {
        return Err(format!(
            "{} says machine.secret_storage = \"keyring\", but {}. So the file was not accepted: change it to `secret_storage = \"file\"` and accept it again, which takes keys found in the keyring into files",
            paths.config_file().display(),
            n.why()
        ));
    }
    #[cfg(unix)]
    match nerve_transport::ctl::call(
        &paths.ctl_socket(),
        "config.accept",
        json!({"user": changed_by()}),
    )
    .await
    {
        Ok(v) => return Ok(v["version"].as_u64().unwrap_or_default()),
        Err(e) if e != nerve_transport::ctl::NOT_RUNNING => return Err(e),
        Err(_) => {}
    }
    let (_, v) = SettingsStore::open_accepting_with(
        paths.config_file(),
        Box::new(crate::secrets::NodeSecrets::for_accept(paths)),
        AuditLog::new(paths.audit_log()),
    )?;
    Ok(v)
}

fn as_table(cfg: &NodeConfig) -> Result<toml::Table, String> {
    toml::from_str(&cfg.to_toml()).map_err(|e| e.to_string())
}

fn segments(key: &str) -> Vec<String> {
    key.split('.').map(str::to_string).collect()
}

fn split_key(key: &str) -> Result<(Vec<String>, String), String> {
    let mut s = segments(key);
    let last = s.pop().filter(|l| !l.is_empty()).ok_or("empty key")?;
    Ok((s, last))
}

/// A value as TOML reads it (`true`, `3`, `["a"]`), else as a string.
fn literal(s: &str) -> toml::Value {
    toml::from_str::<toml::Table>(&format!("v = {s}"))
        .ok()
        .and_then(|mut t| t.remove("v"))
        .unwrap_or_else(|| toml::Value::String(s.to_string()))
}

fn show(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => s.clone(),
        toml::Value::Table(t) => toml::to_string(t).unwrap_or_default(),
        other => other.to_string(),
    }
}

fn lookup(v: &toml::Value, key: &[String]) -> Option<toml::Value> {
    let Some((first, rest)) = key.split_first() else {
        return Some(v.clone());
    };
    if first == "center" && !rest.is_empty() {
        let list = v.get("center")?.as_array()?;
        let entry = list
            .iter()
            .find(|e| e.get("name").and_then(|n| n.as_str()) == Some(rest[0].as_str()))?;
        return lookup(entry, &rest[1..]);
    }
    lookup(v.get(first.as_str())?, rest)
}

fn table_at<'a>(
    v: &'a mut toml::Value,
    key: &[String],
    create: bool,
) -> Result<&'a mut toml::Table, String> {
    let Some((first, rest)) = key.split_first() else {
        return v.as_table_mut().ok_or_else(|| "not a table".to_string());
    };
    let t = v
        .as_table_mut()
        .ok_or_else(|| format!("{first}: not a table"))?;
    if first == "center" && !rest.is_empty() {
        let list = t
            .get_mut("center")
            .and_then(toml::Value::as_array_mut)
            .ok_or("no center is paired")?;
        let entry = list
            .iter_mut()
            .find(|e| e.get("name").and_then(|n| n.as_str()) == Some(rest[0].as_str()))
            .ok_or_else(|| format!("no center named {}", rest[0]))?;
        return table_at(entry, &rest[1..], create);
    }
    if !t.contains_key(first.as_str()) {
        if !create {
            return Err(format!("{first} is not set"));
        }
        t.insert(first.clone(), toml::Value::Table(toml::Table::new()));
    }
    table_at(t.get_mut(first.as_str()).expect("present"), rest, create)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_secrets_come_from_stdin() {
        let text = "s3cret pass\r\nProxy-Authorization: Bearer x\n\nX-Team: a\n";
        assert_eq!(
            stdin_secrets(text, true, true),
            (
                Some("s3cret pass".into()),
                vec!["Proxy-Authorization: Bearer x".into(), "X-Team: a".into()]
            )
        );
        assert_eq!(stdin_secrets("X-A: 1\nX-B: 2", false, true).1.len(), 2);
        assert_eq!(
            stdin_secrets("pw\nX-A: 1", true, false),
            (Some("pw".into()), vec![])
        );
        assert_eq!(stdin_secrets("", true, false).0.as_deref(), Some(""));
    }

    #[test]
    fn the_invoker_is_who_ran_sudo_or_pkexec() {
        let alice = |uid: u32| (uid == 1000).then(|| "alice".to_string());
        assert_eq!(
            invoker_of(Some("bob".into()), Some("1000".into()), alice),
            "bob"
        );
        assert_eq!(invoker_of(None, Some("1000".into()), alice), "alice");
        assert_eq!(
            invoker_of(Some(String::new()), Some("1000".into()), alice),
            "alice"
        );
        assert_eq!(invoker_of(None, Some("1001".into()), alice), "root");
        assert_eq!(invoker_of(None, Some("0".into()), alice), "root");
        assert_eq!(invoker_of(None, None, alice), "root");
    }

    /// On Windows the desktop app's broker names the app's user by SID, and
    /// that user is the one who asked, not the account the broker runs as
    /// (an administrator who answered the UAC prompt).
    #[cfg(windows)]
    #[test]
    fn the_invoker_on_windows_is_the_apps_user_the_broker_names() {
        // LOCAL SERVICE: an account that never runs this test.
        let other = "S-1-5-19";
        let name = crate::win_user::name_of_sid(other).unwrap();
        let me = crate::win_user::current_user().unwrap();
        assert_ne!(name, me);
        assert_eq!(windows_invoker(Some(other.into())), Some(name));
        assert_eq!(windows_invoker(None), Some(me.clone()));
        // A SID without an account names nobody: then this command's user.
        assert_eq!(
            windows_invoker(Some("S-1-5-21-1-2-3-4242".into())),
            Some(me)
        );
    }

    /// A folder in a home the node's user may not look into (the installed
    /// node's CLI runs as `nerve`) is kept as given, in its normal form;
    /// what may be seen is resolved.
    #[cfg(unix)]
    #[test]
    fn a_folder_the_cli_cannot_look_into_is_kept_as_given() {
        use std::os::unix::fs::PermissionsExt;
        if nerve_transport::net::euid() == 0 {
            return; // root looks into every folder
        }
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let home = root.join("home");
        std::fs::create_dir_all(home.join("proj")).unwrap();
        std::os::unix::fs::symlink(home.join("proj"), root.join("link")).unwrap();
        assert_eq!(
            resolve_folder(&root.join("link")).unwrap(),
            home.join("proj").display().to_string()
        );
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o000)).unwrap();
        let given = format!("{}//proj/./x/", home.display());
        let r = resolve_folder(Path::new(&given));
        let up = resolve_folder(&home.join("proj/../../etc"));
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(r.unwrap(), home.join("proj/x").display().to_string());
        assert!(up.is_err(), "{up:?}");
    }

    fn run(paths: &NodePaths, args: &[&str]) -> Result<String, String> {
        let mut argv = vec![
            "nerve-node".to_string(),
            "--config-dir".into(),
            paths.config_dir.display().to_string(),
            "--state-dir".into(),
            paths.state_dir.display().to_string(),
        ];
        argv.extend(args.iter().map(|s| s.to_string()));
        let cli = Cli::try_parse_from(argv).map_err(|e| e.to_string())?;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut out = Vec::new();
        rt.block_on(execute(cli, &mut out))?;
        Ok(String::from_utf8(out).unwrap())
    }

    fn entry(name: &str) -> nerve_policy::CenterEntry {
        nerve_policy::CenterEntry {
            name: name.into(),
            url: "http://127.0.0.1:1".into(),
            pin: None,
            center_id: format!("id-{name}"),
            node_id: "n".into(),
            settings: SettingsGrant::Off,
            paused: false,
            revoked: false,
            unknown: false,
            public_key: None,
            key_rotations: 0,
            pin_rotations: 0,
            old_pin: None,
            policy: Default::default(),
        }
    }

    fn setup(names: &[&str]) -> (tempfile::TempDir, NodePaths) {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("c"), d.path().join("s"));
        let mut cfg = NodeConfig::default();
        for n in names {
            cfg.centers.push(entry(n));
        }
        cfg.save(&paths.config_file()).unwrap();
        (d, paths)
    }

    fn load(paths: &NodePaths) -> NodeConfig {
        NodeConfig::load(&paths.config_file()).unwrap()
    }

    #[test]
    fn per_center_commands_refuse_to_guess() {
        let (_d, paths) = setup(&["a", "b"]);
        let e = run(&paths, &["mode", "set", "user"]).unwrap_err();
        assert!(e.contains("--center"), "{e}");
        run(&paths, &["mode", "set", "user", "--center", "b"]).unwrap();
        assert_eq!(load(&paths).center("b").unwrap().policy.mode, Mode::User);
        // A center whose file names no mode is in default deny.
        assert_eq!(
            load(&paths).center("a").unwrap().policy.mode,
            Mode::Allowlist
        );
        run(&paths, &["mode", "set", "folder", "--center", "a"]).unwrap();
        assert_eq!(load(&paths).center("a").unwrap().policy.mode, Mode::Folder);
        run(&paths, &["mode", "set", "allowlist", "--center", "a"]).unwrap();
        assert_eq!(
            load(&paths).center("a").unwrap().policy.mode,
            Mode::Allowlist
        );
        let e = run(&paths, &["mode", "set", "ask", "--center", "a"]).unwrap_err();
        assert!(e.contains("unknown mode"), "{e}");
        let e = run(&paths, &["cap", "set", "fs", "ask", "--center", "a"]).unwrap_err();
        assert!(e.contains("unknown setting"), "{e}");
    }

    /// Allowlist mode runs as the owner only when asked for, and setting a
    /// mode again without the flag takes it back; the other modes refuse it.
    #[test]
    fn allowlist_mode_runs_as_the_owner_when_asked_for() {
        let (_d, paths) = setup(&["home"]);
        let policy = || load(&paths).centers[0].policy.clone();
        let out = run(&paths, &["mode", "set", "allowlist", "--as-owner"]).unwrap();
        assert!(out.contains("mode allowlist, as you"), "{out}");
        assert!(policy().as_owner && policy().runs_as_owner(crate::now_ms()));
        run(&paths, &["mode", "set", "allowlist"]).unwrap();
        assert!(!policy().as_owner);
        for mode in ["folder", "user"] {
            let e = run(&paths, &["mode", "set", mode, "--as-owner"]).unwrap_err();
            assert!(e.contains("--as-owner only goes with allowlist"), "{e}");
        }
        assert!(!policy().as_owner);
    }

    #[test]
    fn folder_and_user_mode_have_no_limit_unless_asked_for() {
        let (_d, paths) = setup(&["home"]);
        let policy = || load(&paths).centers[0].policy.clone();
        for mode in ["user", "folder"] {
            run(&paths, &["mode", "set", mode]).unwrap();
            assert_eq!(policy().until, None, "{mode}");
        }
        // --for sets a limit of any length, on folder as on user.
        let before = crate::now_ms();
        run(&paths, &["mode", "set", "folder", "--for", "1000"]).unwrap();
        let until = policy().until.unwrap();
        assert!(until >= before + 1000 * 3_600_000, "{until}");
        assert_eq!(policy().mode_at(before), Mode::Folder);
        assert_eq!(policy().mode_at(until), Mode::Allowlist);
        run(&paths, &["mode", "set", "user", "--for", "9"]).unwrap();
        assert_eq!(policy().mode, Mode::User);
        // Setting the mode again without --for drops the old limit.
        run(&paths, &["mode", "set", "user"]).unwrap();
        assert_eq!(policy().until, None);
        // Allowlist has nothing to limit; nonsense hours are refused.
        run(&paths, &["mode", "set", "folder", "--for", "1"]).unwrap();
        let e = run(&paths, &["mode", "set", "allowlist", "--for", "1"]).unwrap_err();
        assert!(e.contains("--for"), "{e}");
        let e = run(&paths, &["mode", "set", "user", "--for", "0"]).unwrap_err();
        assert!(e.contains("at least 1"), "{e}");
        let e = run(
            &paths,
            &["mode", "set", "user", "--for", "18446744073709551615"],
        )
        .unwrap_err();
        assert!(e.contains("too large"), "{e}");
        let e = run(&paths, &["mode", "set", "user", "--for", "soon"]).unwrap_err();
        assert!(e.contains("invalid value"), "{e}");
        // A refused change leaves the mode as it was.
        assert_eq!(policy().mode, Mode::Folder);
        run(&paths, &["mode", "set", "allowlist"]).unwrap();
        assert_eq!(policy().until, None);
    }

    /// Without a control socket to tell (no daemon, or Windows, which has
    /// none), a change lands in the file only, and the CLI says when it
    /// counts; what changes nothing says nothing of the kind.
    #[test]
    fn a_change_no_running_node_was_told_of_says_when_it_takes_effect() {
        let (d, paths) = setup(&["home"]);
        let folder = d.path().join("work");
        std::fs::create_dir(&folder).unwrap();
        let next = "takes effect at the next start of the node";
        let line = format!("the change is in node.toml; it {next}");
        for args in [
            &["folder", "add", folder.to_str().unwrap(), "+r"][..],
            &["mode", "set", "user"],
            &["rule", "add", "deny", "rm -rf /"],
        ] {
            let out = run(&paths, args).unwrap();
            assert_eq!(out.lines().last(), Some(line.as_str()), "{args:?}: {out}");
            assert_eq!(out.matches(next).count(), 1, "{args:?}: {out}");
        }
        for args in [&["status"][..], &["center", "ls"], &["folder", "ls"]] {
            let out = run(&paths, args).unwrap();
            assert!(!out.contains(&line), "{args:?}: {out}");
        }
        // A command that fails changed nothing.
        assert!(run(&paths, &["mode", "set", "ask"]).is_err());
    }

    #[test]
    fn edits_without_a_daemon_land_in_the_file_and_the_audit_log() {
        let (d, paths) = setup(&["home"]);
        let folder = d.path().join("work");
        std::fs::create_dir(&folder).unwrap();
        let note = run(
            &paths,
            &["folder", "add", folder.to_str().unwrap(), "+rw", "+x"],
        )
        .unwrap();
        assert!(note.contains("folders do not count here"), "{note}");
        run(&paths, &["cap", "set", "exec.run", "off"]).unwrap();
        run(&paths, &["center", "grant", "settings", "write"]).unwrap();
        run(
            &paths,
            &["rule", "add", "allow", "git status --short", "--wildcard"],
        )
        .unwrap();
        run(&paths, &["rule", "add", "sudo", "sudo apt update"]).unwrap();
        run(&paths, &["rule", "add", "deny", "rm -rf /"]).unwrap();
        run(&paths, &["rule", "add", "deny", "rm -rf /"]).unwrap();
        run(&paths, &["mode", "set", "user", "--for", "2"]).unwrap();
        let cfg = load(&paths);
        let c = cfg.center("home").unwrap();
        let real = nerve_policy::paths::resolve(&folder).unwrap();
        assert_eq!(c.policy.folders[0].path, real.display().to_string());
        assert_eq!(c.policy.folders[0].access, Access::ALL);
        assert_eq!(c.policy.caps["exec.run"], CapSetting::Off);
        assert_eq!(c.settings, SettingsGrant::Write);
        assert_eq!(c.policy.allow, vec!["exec.run:git *".to_string()]);
        assert_eq!(c.policy.sudo_allow, vec!["sudo apt update".to_string()]);
        assert_eq!(c.policy.deny, vec!["exec.run:rm -rf /".to_string()]);
        assert_eq!(c.policy.mode, Mode::User);
        assert!(c.policy.until.is_some());
        let log = std::fs::read_to_string(paths.audit_log()).unwrap();
        assert!(log.contains("local"), "{log}");
        run(&paths, &["panic"]).unwrap();
        assert!(load(&paths).locked);
        run(&paths, &["unlock"]).unwrap();
        assert!(!load(&paths).locked);
    }

    #[test]
    fn folder_add_needs_a_right_and_takes_only_plus() {
        let (d, paths) = setup(&["home"]);
        let dir = d.path().join("work");
        std::fs::create_dir(&dir).unwrap();
        let dir = dir.to_str().unwrap();
        let folders = || load(&paths).centers[0].policy.folders.clone();
        // No sign at all: refused, nothing stored.
        let e = run(&paths, &["folder", "add", dir]).unwrap_err();
        assert!(e.contains("+r"), "{e}");
        assert!(folders().is_empty());
        // The old flags and the other signs are no rights of a new folder.
        for bad in [
            &["--rw"][..],
            &["--execute"],
            &["--ro"],
            &["rw"],
            &["-w"],
            &["=r"],
            &["+"],
            &["+q"],
        ] {
            let mut args = vec!["folder", "add", dir];
            args.extend(bad);
            assert!(run(&paths, &args).is_err(), "{bad:?}");
        }
        assert!(folders().is_empty());
        // Each right alone, and several in one word or in several.
        for (rights, want) in [
            (&["+r"][..], "r"),
            (&["+w"], "w"),
            (&["+x"], "x"),
            (&["+r", "+x"], "rx"),
            (&["+wx"], "wx"),
            (&["+r", "+w", "+x"], "rwx"),
        ] {
            let mut args = vec!["folder", "add", dir];
            args.extend(rights);
            run(&paths, &args).unwrap();
            assert_eq!(folders().len(), 1, "added again, not twice");
            assert_eq!(folders()[0].access.to_string(), want, "{rights:?}");
        }
    }

    /// `folder add` records the place it stores, so that a link which
    /// replaces the folder later is refused (`exec::folder_sets`). Adding it
    /// again, also through a link of the owner's, keeps one entry; `folder
    /// set` keeps it, and `folder rm` takes it away with the folder.
    #[cfg(unix)]
    #[test]
    fn folder_add_records_the_place_and_rm_forgets_it() {
        let (d, paths) = setup(&["home"]);
        let work = d.path().join("work");
        std::fs::create_dir(&work).unwrap();
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&work, &link).unwrap();
        let real = nerve_policy::paths::resolve(&work)
            .unwrap()
            .display()
            .to_string();
        let (work, link) = (work.to_str().unwrap(), link.to_str().unwrap());
        let places = || load(&paths).centers[0].policy.places.clone();
        assert!(places().is_empty());
        run(&paths, &["folder", "add", work, "+r"]).unwrap();
        assert_eq!(places(), std::slice::from_ref(&real));
        // The same place again, and by a link: one folder, one entry.
        run(&paths, &["folder", "add", link, "+rw"]).unwrap();
        run(&paths, &["folder", "set", work, "+x"]).unwrap();
        assert_eq!(load(&paths).centers[0].policy.folders.len(), 1);
        assert_eq!(places(), std::slice::from_ref(&real));
        run(&paths, &["folder", "rm", link]).unwrap();
        assert!(load(&paths).centers[0].policy.folders.is_empty());
        assert!(places().is_empty());
        // Added once more, it is recorded once more.
        run(&paths, &["folder", "add", work, "+r"]).unwrap();
        assert_eq!(places(), std::slice::from_ref(&real));
    }

    /// A folder the CLI cannot look into (the installed node's CLI runs as
    /// `nerve`, a home may be closed to it) is stored as given and cannot be
    /// recorded here: with no running node to judge it as the account, the
    /// command says so.
    #[cfg(unix)]
    #[test]
    fn a_folder_the_cli_cannot_judge_is_added_with_a_note_and_no_record() {
        use std::os::unix::fs::PermissionsExt;
        if nerve_transport::net::euid() == 0 {
            return; // root looks into every folder
        }
        let (d, paths) = setup(&["home"]);
        let root = std::fs::canonicalize(d.path()).unwrap();
        let home = root.join("home");
        std::fs::create_dir_all(home.join("proj")).unwrap();
        let proj = home.join("proj");
        let closed = std::fs::Permissions::from_mode(0o000);
        std::fs::set_permissions(&home, closed).unwrap();
        let out = run(&paths, &["folder", "add", proj.to_str().unwrap(), "+rw"]);
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        let out = out.unwrap();
        assert!(out.contains("not recorded at its real place"), "{out}");
        assert!(out.contains(&proj.display().to_string()), "{out}");
        let policy = load(&paths).centers[0].policy.clone();
        assert_eq!(policy.folders.len(), 1);
        assert!(policy.places.is_empty(), "{policy:?}");
        // One it could judge says nothing of the kind.
        let out = run(&paths, &["folder", "add", proj.to_str().unwrap(), "+rw"]).unwrap();
        assert!(!out.contains("not recorded"), "{out}");
        assert_eq!(load(&paths).centers[0].policy.places.len(), 1);
        // Added again where it cannot look, the rights change and the record
        // it has stays: a record only narrows, and the node checks it as the
        // account before each command.
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o000)).unwrap();
        let out = run(&paths, &["folder", "add", proj.to_str().unwrap(), "+r"]);
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(out.unwrap().contains("not recorded at its real place"));
        let policy = load(&paths).centers[0].policy.clone();
        assert_eq!(policy.folders.len(), 1);
        assert_eq!(policy.folders[0].access.to_string(), "r");
        assert_eq!(policy.places, [proj.display().to_string()]);
    }

    /// In the state the new warning reports, a link has replaced a recorded
    /// folder and its real place is another folder. `folder set` and `folder
    /// rm` act on the folder the path is spelled as (also with a trailing
    /// slash), name it, and leave the folder the link leads to alone; a path
    /// that is a link to a folder still finds the folder at its real place.
    #[cfg(unix)]
    #[test]
    fn folder_set_and_rm_find_a_folder_a_link_replaced_by_its_spelling() {
        let (d, paths) = setup(&["home"]);
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (work, docs) = (root.join("work"), root.join("docs"));
        let bin = work.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir(&docs).unwrap();
        for (p, rights) in [(&work, "+rw"), (&bin, "+r"), (&docs, "+r")] {
            run(&paths, &["folder", "add", p.to_str().unwrap(), rights]).unwrap();
        }
        std::fs::remove_dir(&bin).unwrap();
        std::os::unix::fs::symlink(&docs, &bin).unwrap();
        let folders = || load(&paths).centers[0].policy.clone();
        let access = |p: &Path| {
            let policy = folders();
            let f = policy.folders.iter().find(|f| Path::new(&f.path) == p);
            f.map(|f| f.access.to_string())
        };
        let spelled = format!("{}/", bin.display());

        let out = run(&paths, &["folder", "set", &spelled, "+x"]).unwrap();
        assert!(
            out.contains(&format!("folder {} r-x", bin.display())),
            "{out}"
        );
        assert_eq!(access(&bin).as_deref(), Some("rx"));
        assert_eq!(access(&docs).as_deref(), Some("r"));

        let out = run(&paths, &["folder", "rm", &spelled]).unwrap();
        assert!(out.contains(&format!("removed {}", bin.display())), "{out}");
        assert_eq!(access(&bin), None);
        assert_eq!(access(&docs).as_deref(), Some("r"));
        assert!(!folders().is_placed(&bin.display().to_string()));
        assert!(folders().is_placed(&docs.display().to_string()));

        // The owner's own link to a folder finds the folder it leads to.
        let to_docs = root.join("to-docs");
        std::os::unix::fs::symlink(&docs, &to_docs).unwrap();
        let out = run(&paths, &["folder", "rm", to_docs.to_str().unwrap()]).unwrap();
        assert!(
            out.contains(&format!("removed {}", docs.display())),
            "{out}"
        );
        assert_eq!(access(&docs), None);
        assert_eq!(access(&work).as_deref(), Some("rw"));
    }

    /// `folder rm` and `folder set` find the stored folder by the path the
    /// owner gave `folder add`, when that went through a link of the owner's
    /// and the stored place has been replaced by a link since; and where a
    /// dangling link or a loop of links stands in the folder's place, which
    /// resolving the path would refuse. A folder the path only passes is not
    /// the folder it names.
    #[cfg(unix)]
    #[test]
    fn folder_rm_and_set_reach_a_folder_through_links_and_where_none_resolves() {
        let (d, paths) = setup(&["home"]);
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (work, docs, data) = (root.join("work"), root.join("docs"), root.join("data"));
        let (real, code) = (data.join("real"), root.join("code"));
        for p in [&work.join("bin"), &work.join("sub"), &docs, &real] {
            std::fs::create_dir_all(p).unwrap();
        }
        std::os::unix::fs::symlink(&real, &code).unwrap();
        for (p, rights) in [
            (&work, "+rw"),
            (&work.join("bin"), "+r"),
            (&code, "+r"),
            (&docs, "+r"),
        ] {
            run(&paths, &["folder", "add", p.to_str().unwrap(), rights]).unwrap();
        }
        let listed = || -> Vec<String> {
            load(&paths).centers[0]
                .policy
                .folders
                .iter()
                .map(|f| f.path.clone())
                .collect()
        };
        let has = |p: &Path| listed().contains(&p.display().to_string());
        assert!(has(&real) && !has(&code), "stored at the real place");

        // The stored place is replaced by a link to `docs`: `code`, the path
        // the owner gave, still names the stored folder and not `docs`.
        std::fs::remove_dir(&real).unwrap();
        std::os::unix::fs::symlink(&docs, &real).unwrap();
        let out = run(&paths, &["folder", "set", code.to_str().unwrap(), "+x"]).unwrap();
        assert!(
            out.contains(&format!("folder {} r-x", real.display())),
            "{out}"
        );
        let out = run(&paths, &["folder", "rm", code.to_str().unwrap()]).unwrap();
        assert!(
            out.contains(&format!("removed {}", real.display())),
            "{out}"
        );
        assert!(!has(&real) && has(&docs));

        // A folder the path only passes is not the folder it names.
        let e = run(
            &paths,
            &["folder", "rm", work.join("sub").to_str().unwrap()],
        )
        .unwrap_err();
        assert!(e.contains("not a folder of this center"), "{e}");
        assert!(has(&work));

        // A dangling link, and then a loop, stand where `work/bin` was.
        let bin = work.join("bin");
        std::fs::remove_dir(&bin).unwrap();
        std::os::unix::fs::symlink(root.join("nowhere"), &bin).unwrap();
        let out = run(&paths, &["folder", "set", bin.to_str().unwrap(), "-r"]).unwrap();
        assert!(
            out.contains(&format!("folder {} ---", bin.display())),
            "{out}"
        );
        std::fs::remove_file(&bin).unwrap();
        std::os::unix::fs::symlink(&bin, &bin).unwrap();
        let out = run(&paths, &["folder", "rm", bin.to_str().unwrap()]).unwrap();
        assert!(out.contains(&format!("removed {}", bin.display())), "{out}");
        assert!(!has(&bin) && has(&work) && has(&docs));
        // What is not stored under any spelling still says why.
        let e = run(&paths, &["folder", "rm", bin.to_str().unwrap()]).unwrap_err();
        assert!(
            e.contains("Too many levels") || e.contains("symlink"),
            "{e}"
        );
    }

    /// The installed node's CLI runs as `nerve`, which cannot look into the
    /// owner's home: a link there stays as typed, and the folder `folder add`
    /// stored at the place the link leads to is not found. `folder set` and
    /// `folder rm` then name the path `folder ls` shows (issue #98), also where
    /// the center has more folders than the hint would list.
    #[cfg(unix)]
    #[test]
    fn folder_set_and_rm_name_the_listed_folder_for_a_link_the_cli_cannot_look_into() {
        use std::os::unix::fs::PermissionsExt;
        if nerve_transport::net::euid() == 0 {
            return; // root looks into every folder
        }
        let (d, paths) = setup(&["home"]);
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (home, data) = (root.join("home"), root.join("data"));
        let (proj, work) = (home.join("proj"), data.join("work"));
        for p in [&proj, &work] {
            std::fs::create_dir_all(p).unwrap();
        }
        let (link, far) = (home.join("linkproj"), home.join("sub").join("linkwork"));
        std::fs::create_dir(home.join("sub")).unwrap();
        std::os::unix::fs::symlink(&proj, &link).unwrap();
        std::os::unix::fs::symlink(&work, &far).unwrap();
        for p in [&proj, &work] {
            run(&paths, &["folder", "add", p.to_str().unwrap(), "+r"]).unwrap();
        }
        let listed = |n: usize| load(&paths).centers[0].policy.folders.len() == n;
        // While the CLI can look at the link, it finds the folder.
        let out = run(&paths, &["folder", "set", link.to_str().unwrap(), "+x"]).unwrap();
        assert!(
            out.contains(&format!("folder {} r-x", proj.display())),
            "{out}"
        );
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o000)).unwrap();
        let mut errors = Vec::new();
        for args in [["set", "+w"], ["rm", ""]] {
            let mut cmd = vec!["folder", args[0], link.to_str().unwrap()];
            if !args[1].is_empty() {
                cmd.push(args[1]);
            }
            errors.push(run(&paths, &cmd).unwrap_err());
        }
        // Only folders far from the path are listed, and more than the hint
        // would name: it still says what to do.
        for n in ["a", "b"] {
            let p = root.join(n);
            std::fs::create_dir(&p).unwrap();
            run(&paths, &["folder", "add", p.to_str().unwrap(), "+r"]).unwrap();
        }
        errors.push(run(&paths, &["folder", "rm", far.to_str().unwrap()]).unwrap_err());
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        for e in &errors[..2] {
            assert!(
                e.starts_with(&format!(
                    "{} is not a folder of this center",
                    link.display()
                )),
                "{e}"
            );
            assert!(
                e.ends_with(&format!(
                    "`nerve-node folder ls` shows for the folder: {}",
                    proj.display()
                )),
                "{e}"
            );
        }
        let e = &errors[2];
        assert!(e.contains("this account cannot look into it"), "{e}");
        assert!(e.ends_with("shows for the folder"), "{e}");
        // The refused calls changed nothing.
        assert!(listed(4));
    }

    /// A link a command may have put inside a folder it can write in is not
    /// followed by `folder add`: it would store, and record, whatever the link
    /// leads to, past the check that keeps such a folder out of the sandbox.
    /// A link of the owner's elsewhere is followed, as before.
    #[cfg(unix)]
    #[test]
    fn folder_add_does_not_follow_a_link_inside_a_write_folder() {
        let (d, paths) = setup(&["home"]);
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (work, docs) = (root.join("work"), root.join("docs"));
        let bin = work.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir(&docs).unwrap();
        run(&paths, &["folder", "add", work.to_str().unwrap(), "+rw"]).unwrap();
        // The folder is a plain one first, and then a command replaces it.
        run(&paths, &["folder", "add", bin.to_str().unwrap(), "+r"]).unwrap();
        std::fs::remove_dir(&bin).unwrap();
        std::os::unix::fs::symlink(&docs, &bin).unwrap();
        let before = load(&paths).centers[0].policy.clone();
        let e = run(&paths, &["folder", "add", bin.to_str().unwrap(), "+rx"]).unwrap_err();
        assert!(e.contains("link") && e.contains("may write"), "{e}");
        let policy = load(&paths).centers[0].policy.clone();
        assert_eq!(
            policy, before,
            "nothing changed, the record of `bin` included"
        );
        assert!(policy.is_placed(&bin.display().to_string()));
        assert!(!policy.is_placed(&docs.display().to_string()));
        assert!(!policy.is_placed(&docs.display().to_string()));
        // A link of the owner's outside every write folder is followed.
        let to_docs = root.join("to-docs");
        std::os::unix::fs::symlink(&docs, &to_docs).unwrap();
        run(&paths, &["folder", "add", to_docs.to_str().unwrap(), "+r"]).unwrap();
        assert!(
            load(&paths).centers[0]
                .policy
                .is_placed(&docs.display().to_string())
        );
    }

    /// On Windows, a junction a command may have put inside a folder it can
    /// write in is not followed by `folder add` either.
    #[cfg(windows)]
    #[test]
    fn folder_add_does_not_follow_a_junction_inside_a_write_folder() {
        let (d, paths) = setup(&["home"]);
        let root = nerve_policy::paths::resolve(d.path()).unwrap();
        let (work, docs) = (root.join("work"), root.join("docs"));
        let bin = work.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir(&docs).unwrap();
        run(&paths, &["folder", "add", work.to_str().unwrap(), "+rw"]).unwrap();
        std::fs::remove_dir(&bin).unwrap();
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&bin)
            .arg(&docs)
            .output()
            .unwrap();
        assert!(made.status.success(), "{made:?}");
        let e = run(&paths, &["folder", "add", bin.to_str().unwrap(), "+rx"]).unwrap_err();
        assert!(e.contains("link") && e.contains("may write"), "{e}");
        let policy = load(&paths).centers[0].policy.clone();
        assert_eq!(policy.folders.len(), 1, "nothing was stored: {policy:?}");
        assert!(!policy.is_placed(&docs.display().to_string()));
    }

    #[test]
    fn folder_set_applies_its_changes_left_to_right() {
        let (d, paths) = setup(&["home"]);
        let dir = d.path().join("work");
        std::fs::create_dir(&dir).unwrap();
        let dir = dir.to_str().unwrap();
        let access = || load(&paths).centers[0].policy.folders[0].access.to_string();
        // A folder that is not the center's is an error.
        assert!(run(&paths, &["folder", "set", dir, "+x"]).is_err());
        run(&paths, &["folder", "add", dir, "+r"]).unwrap();
        for (change, want) in [
            (&["+x"][..], "rx"),
            (&["-r"], "x"),
            (&["=rwx"], "rwx"),
            (&["-w"], "rx"),
            (&["+rw"], "rwx"),
            (&["-rw"], "x"),
            (&["=w"], "w"),
            (&["=rwx", "-x", "+x", "-r"], "wx"),
            (&["=r", "+w", "-r"], "w"),
            (&["="], ""),
        ] {
            let mut args = vec!["folder", "set", dir];
            args.extend(change);
            run(&paths, &args).unwrap();
            assert_eq!(access(), want, "{change:?}");
        }
        // A bad change anywhere in the list changes nothing.
        run(&paths, &["folder", "set", dir, "=rx"]).unwrap();
        for bad in [&["+w", "rw"][..], &["+q"], &["+"], &["=rr"]] {
            let mut args = vec!["folder", "set", dir];
            args.extend(bad);
            assert!(run(&paths, &args).is_err(), "{bad:?}");
            assert_eq!(access(), "rx", "{bad:?}");
        }
        // --center still works after hyphen-led changes.
        run(&paths, &["folder", "set", dir, "-w", "--center", "home"]).unwrap();
        run(&paths, &["folder", "set", dir, "+w", "--center=home"]).unwrap();
        run(&paths, &["folder", "set", "--center", "home", dir, "-w"]).unwrap();
        assert_eq!(access(), "rx");
        for bad in [
            &["--center", "nobody", "-w"][..],
            &["-w", "--center"],
            &["-w", "--bogus"],
            &["--center", "home"],
        ] {
            let mut args = vec!["folder", "set", dir];
            args.extend(bad);
            assert!(run(&paths, &args).is_err(), "{bad:?}");
        }
        assert_eq!(access(), "rx");
        let out = run(&paths, &["folder", "ls"]).unwrap();
        assert!(out.starts_with("r-x  "), "{out}");
        run(&paths, &["folder", "rm", dir]).unwrap();
        assert!(load(&paths).centers[0].policy.folders.is_empty());
        assert!(run(&paths, &["folder", "rm", dir]).is_err());
    }

    #[test]
    fn centers_pause_and_resume_by_the_owner() {
        let (_d, paths) = setup(&["a", "b"]);
        assert!(run(&paths, &["center", "pause"]).is_err());
        run(&paths, &["center", "pause", "--center", "a"]).unwrap();
        let cfg = load(&paths);
        assert!(cfg.center("a").unwrap().paused);
        assert!(!cfg.center("b").unwrap().paused);
        let ls = run(&paths, &["center", "ls"]).unwrap();
        assert!(ls.contains("[paused]"), "{ls}");
        run(&paths, &["center", "resume", "--center", "a"]).unwrap();
        assert!(!load(&paths).center("a").unwrap().paused);
        run(&paths, &["center", "rm", "--center", "b"]).unwrap();
        assert!(load(&paths).center("b").is_none());
    }

    /// On Windows: `center rm` removes the profile of the pairing's
    /// AppContainer also when the record of the grants does not name it,
    /// as after the state folder was deleted.
    #[cfg(windows)]
    #[test]
    fn center_rm_removes_the_profile_the_record_does_not_name() {
        let (_d, paths) = setup(&["home"]);
        let name = crate::grants::container(&paths, "n");
        let profile = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap())
            .join("Packages")
            .join(&name);
        // Starting a command in the container makes its profile; whether
        // the command runs does not matter here.
        let _ = nerve_sandbox::appcontainer::run(
            Path::new("cmd.exe"),
            &["/C".into(), "exit 0".into()],
            &name,
        );
        assert!(profile.exists(), "{}", profile.display());
        assert!(!crate::grants::record_file(&paths).exists());
        let ls = run(&paths, &["center", "ls"]).unwrap();
        assert!(ls.contains(&format!("AppContainer {name}")), "{ls}");
        let out = run(&paths, &["center", "rm"]).unwrap();
        assert!(
            out.contains(&format!("removed the AppContainer profile {name} of home")),
            "{out}"
        );
        assert!(!profile.exists(), "{}", profile.display());
    }

    /// On Windows: a node that spelled its state folder with `/`, as the
    /// default one is, is found by the folder typed with `\`.
    #[cfg(windows)]
    #[test]
    fn center_rm_finds_the_profile_of_the_state_folder_spelled_otherwise() {
        let (d, paths) = setup(&["home"]);
        let spelled = NodePaths::new(
            &paths.config_dir,
            PathBuf::from(format!("{}/s", d.path().display())),
        );
        assert_eq!(spelled.state_dir, paths.state_dir);
        let name = crate::grants::container(&spelled, "n");
        assert_ne!(name, crate::grants::container(&paths, "n"));
        let profile = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap())
            .join("Packages")
            .join(&name);
        let _ = nerve_sandbox::appcontainer::run(
            Path::new("cmd.exe"),
            &["/C".into(), "exit 0".into()],
            &name,
        );
        assert!(profile.exists(), "{}", profile.display());
        let ls = run(&paths, &["center", "ls"]).unwrap();
        assert!(ls.contains(&format!("AppContainer {name}")), "{ls}");
        let out = run(&paths, &["center", "rm"]).unwrap();
        assert!(out.contains(&name), "{out}");
        assert!(!profile.exists(), "{}", profile.display());
    }

    /// The profile folder of the container `name`, made by starting a
    /// command in it; whether the command runs does not matter.
    #[cfg(windows)]
    fn profile_of(name: &str) -> PathBuf {
        let _ = nerve_sandbox::appcontainer::run(
            Path::new("cmd.exe"),
            &["/C".into(), "exit 0".into()],
            name,
        );
        let profile = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap())
            .join("Packages")
            .join(name);
        assert!(profile.exists(), "{}", profile.display());
        profile
    }

    /// On Windows: the profile of a pairing with folder entries goes with
    /// their grants at `center rm`, which says so, and stays while the node
    /// runs, which it says too.
    #[cfg(windows)]
    #[test]
    fn center_rm_names_the_profile_that_goes_with_the_last_grant() {
        let (d, paths) = setup(&["home"]);
        let work = d.path().join("work");
        std::fs::create_dir(&work).unwrap();
        run(&paths, &["folder", "add", work.to_str().unwrap(), "+rw"]).unwrap();
        assert!(crate::grants::record_file(&paths).exists());
        let name = crate::grants::container(&paths, "n");
        let profile = profile_of(&name);
        // A node that runs holds the lock.
        let held = crate::secrets::KeysLock::try_take(&paths).unwrap().unwrap();
        let out = run(&paths, &["center", "rm"]).unwrap();
        drop(held);
        assert!(
            out.contains(&format!(
                "the AppContainer profile {name} of home stays, since the node at"
            )),
            "{out}"
        );
        assert!(profile.exists(), "{}", profile.display());
        nerve_sandbox::appcontainer::remove_profile(&name).unwrap();

        let (d, paths) = setup(&["home"]);
        let work = d.path().join("work");
        std::fs::create_dir(&work).unwrap();
        run(&paths, &["folder", "add", work.to_str().unwrap(), "+rw"]).unwrap();
        let name = crate::grants::container(&paths, "n");
        let profile = profile_of(&name);
        let out = run(&paths, &["center", "rm"]).unwrap();
        assert!(
            out.contains(&format!("removed the AppContainer profile {name} of home")),
            "{out}"
        );
        assert!(!profile.exists(), "{}", profile.display());
    }

    /// On Windows: when the grants of the pairings that stay do not follow
    /// (a hard link below a folder they write), `center rm` still removes
    /// the pairing's profile, as nothing names it once the pairing is gone,
    /// and then says what failed.
    #[cfg(windows)]
    #[test]
    fn center_rm_removes_the_profile_when_the_other_grants_do_not_follow() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("c"), d.path().join("s"));
        let work = d.path().join("work");
        std::fs::create_dir(&work).unwrap();
        std::fs::write(work.join("a.txt"), "x").unwrap();
        std::fs::hard_link(work.join("a.txt"), work.join("b.txt")).unwrap();
        let real = nerve_policy::paths::resolve(&work).unwrap();
        let mut cfg = NodeConfig::default();
        let mut home = entry("home");
        home.node_id = "n-home".into();
        home.policy.folders.push(nerve_policy::config::Folder {
            path: real.display().to_string(),
            access: Access::parse("rw").unwrap(),
        });
        let mut lab = entry("lab");
        lab.node_id = "n-lab".into();
        cfg.centers = vec![home, lab];
        cfg.save(&paths.config_file()).unwrap();
        let name = crate::grants::container(&paths, "n-lab");
        let profile = profile_of(&name);
        let e = run(&paths, &["center", "rm", "--center", "lab"]).unwrap_err();
        assert!(e.contains("the folder grants do not follow"), "{e}");
        assert!(load(&paths).center("lab").is_none());
        assert!(!profile.exists(), "{}", profile.display());
    }

    #[test]
    fn config_get_set_by_dotted_key() {
        let (_d, paths) = setup(&["home"]);
        run(&paths, &["config", "set", "limits.max_running", "4"]).unwrap();
        assert_eq!(load(&paths).limits.max_running, 4);
        run(&paths, &["config", "set", "center.home.policy.until", "30"]).unwrap();
        assert_eq!(
            run(&paths, &["config", "get", "center.home.policy.until"]).unwrap(),
            "30\n"
        );
        run(
            &paths,
            &["config", "add", "center.home.policy.deny", "fs:~/secret/*"],
        )
        .unwrap();
        assert_eq!(
            load(&paths).centers[0].policy.deny,
            vec!["fs:~/secret/*".to_string()]
        );
        run(
            &paths,
            &[
                "config",
                "remove",
                "center.home.policy.deny",
                "fs:~/secret/*",
            ],
        )
        .unwrap();
        assert!(load(&paths).centers[0].policy.deny.is_empty());
        // Unknown keys fail validation and change nothing.
        assert!(run(&paths, &["config", "set", "limits.bogus", "1"]).is_err());
        run(&paths, &["config", "unset", "limits.max_running"]).unwrap();
        assert_eq!(load(&paths).limits.max_running, 16);
    }

    /// No account for the commands is chosen on Linux: `config` refuses
    /// `machine.user` in every verb, and nothing changes.
    #[cfg(not(windows))]
    #[test]
    fn config_chooses_no_account_on_linux() {
        let (_d, paths) = setup(&["home"]);
        for cmd in [
            &["config", "set", "machine.user", "bob"][..],
            &["config", "unset", "machine.user"],
            &["config", "add", "machine.user", "bob"],
        ] {
            let e = run(&paths, cmd).unwrap_err();
            assert_eq!(e, NO_ACCOUNT_TO_CHOOSE, "{cmd:?}");
        }
        assert_eq!(load(&paths).machine.user, None);
    }

    /// The owner sets the run-time limits by name; a limit of 0 is refused
    /// and changes nothing, and unsetting one gives the default back.
    #[test]
    fn config_sets_the_run_time_limits() {
        let (_d, paths) = setup(&["home"]);
        assert_eq!(load(&paths).limits.default_timeout_secs, 600);
        assert_eq!(load(&paths).limits.max_timeout_secs, 3600);
        run(
            &paths,
            &["config", "set", "limits.default_timeout_secs", "30"],
        )
        .unwrap();
        run(&paths, &["config", "set", "limits.max_timeout_secs", "90"]).unwrap();
        assert_eq!(load(&paths).limits.default_timeout_secs, 30);
        assert_eq!(load(&paths).limits.max_timeout_secs, 90);
        assert_eq!(
            run(&paths, &["config", "get", "limits.max_timeout_secs"]).unwrap(),
            "90\n"
        );
        for key in ["default_timeout_secs", "max_timeout_secs"] {
            let e = run(&paths, &["config", "set", &format!("limits.{key}"), "0"]).unwrap_err();
            assert!(e.contains("must be at least 1"), "{e}");
        }
        assert_eq!(load(&paths).limits.max_timeout_secs, 90);
        run(&paths, &["config", "unset", "limits.max_timeout_secs"]).unwrap();
        assert_eq!(load(&paths).limits.max_timeout_secs, 3600);
    }

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
            assert!(e.contains("--config-dir and --state-dir do not go"), "{e}");
            assert!(!e.contains("not done"), "{e}");
        }
    }

    fn setup_with(paths: &NodePaths, answers: &str) -> (Result<(), String>, String) {
        let keyring = crate::keyring_setup::tests::FakeKeyring::new(true);
        setup_keyring(paths, None, &keyring, answers)
    }

    fn setup_keyring(
        paths: &NodePaths,
        machine: Option<&dyn crate::service::System>,
        keyring: &dyn crate::keyring_setup::Keyring,
        answers: &str,
    ) -> (Result<(), String>, String) {
        setup_at(paths, machine, keyring, answers, true)
    }

    /// Setup with `answers`, at a terminal (`terminal`) or not.
    fn setup_at(
        paths: &NodePaths,
        machine: Option<&dyn crate::service::System>,
        keyring: &dyn crate::keyring_setup::Keyring,
        answers: &str,
        terminal: bool,
    ) -> (Result<(), String>, String) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut out = Vec::new();
        let mut input = std::io::Cursor::new(answers.as_bytes().to_vec());
        let r = rt.block_on(super::setup(
            paths, machine, keyring, &mut input, terminal, &mut out,
        ));
        (r, String::from_utf8(out).unwrap())
    }

    /// `status` of a running node: as whom each pairing runs and whether
    /// without Landlock, what nerve-run may read of the owner's home, and
    /// the folder grants, access nerve-run should have lost worded as such
    /// (#142).
    #[test]
    fn the_status_says_landlock_the_home_and_the_grants() {
        let v = json!({
            "confinement": "landlock abi 6",
            "owner": "alice",
            "home_warning": {"warning": "Without Landlock, nerve-run can read every file in your home /home/alice"},
            "folder_grants": {
                "stale": ["/home/alice/gone", "/var/lib/nerve/state/acl.json"],
                "errors": [
                    "/home/alice/gone/x: Permission denied (os error 13)",
                    "/var/lib/nerve/state/acl.json: expected value at line 1",
                    "/home/alice/usb: its file system does not support POSIX ACLs",
                ],
            },
            "centers": [
                {"name": "a", "status": "connected", "mode": "folder", "account": "nerve-run", "landlock": false},
                {"name": "b", "status": "connected", "mode": "folder", "account": "nerve-run", "landlock": true},
                {"name": "c", "status": "connected", "mode": "user", "account": "alice", "landlock": false},
                {"name": "d", "status": "connected", "mode": "folder"},
            ],
        });
        let lines = status_lines(&v);
        let has = |l: &str| lines.iter().any(|x| x == l);
        assert!(has("owner: alice"), "{lines:#?}");
        assert!(
            has(
                "warning: Without Landlock, nerve-run can read every file in your home /home/alice"
            ),
            "{lines:#?}"
        );
        assert!(
            has("a  connected  mode folder, as nerve-run, without Landlock"),
            "{lines:#?}"
        );
        assert!(has("b  connected  mode folder, as nerve-run"), "{lines:#?}");
        assert!(has("c  connected  mode user, as alice"), "{lines:#?}");
        assert!(has("d  connected  mode folder"), "{lines:#?}");
        assert!(
            has(
                "warning: nerve-run keeps its access to /home/alice/gone, which it should have lost; no command of nerve-run runs until it is taken off: /home/alice/gone/x: Permission denied (os error 13)"
            ),
            "{lines:#?}"
        );
        assert!(
            has(
                "warning: nerve-run keeps its access to /var/lib/nerve/state/acl.json, which it should have lost; no command of nerve-run runs until it is taken off: /var/lib/nerve/state/acl.json: expected value at line 1"
            ),
            "{lines:#?}"
        );
        assert!(
            has(
                "warning: nerve-run did not get every folder: /home/alice/usb: its file system does not support POSIX ACLs"
            ),
            "{lines:#?}"
        );
        assert_eq!(
            lines.iter().filter(|l| l.contains("did not get")).count(),
            1,
            "{lines:#?}"
        );
        // Root as the owner is said plainly.
        let root = status_lines(&json!({"owner": "root", "owner_is_root": true}));
        assert!(
            root.iter()
                .any(|l| *l == format!("owner: {}", crate::owner::ROOT_OWNER_NOTE)),
            "{root:#?}"
        );
        assert!(crate::owner::ROOT_OWNER_NOTE.contains("run as root"));
        assert_eq!(owner_line(None, false), None);
        // So does a stopped node's.
        let cfg = NodeConfig::default();
        let root_line = format!("owner: {}", crate::owner::ROOT_OWNER_NOTE);
        let stopped = stopped_lines(&cfg, Some("root"));
        assert_eq!(stopped[0], "daemon: not running");
        assert_eq!(stopped.contains(&root_line), !cfg!(windows), "{stopped:#?}");
        let alice = stopped_lines(&cfg, Some("alice"));
        assert!(alice.contains(&"owner: alice".to_string()), "{alice:#?}");
        assert!(!alice.contains(&root_line), "{alice:#?}");
        assert!(
            !stopped_lines(&cfg, None)
                .iter()
                .any(|l| l.starts_with("owner:")),
            "no owner, no line"
        );
        // Nothing of the kind on a node that has none of it.
        let plain = status_lines(&json!({"confinement": "landlock abi 6"})).join("\n");
        assert!(
            !plain.contains("warning") && !plain.contains("Landlock,"),
            "{plain}"
        );
    }

    /// After a change of the folders the CLI says what the node's sync
    /// left: access that should have gone as such, a grant not given whole
    /// as that (#142).
    #[test]
    fn a_folder_change_tells_what_the_grants_left() {
        let mut out = Vec::new();
        tell_grants_of(
            &json!({
                "stale": ["/home/alice/old"],
                "errors": [
                    "/home/alice/old: Permission denied (os error 13)",
                    "/home/alice/older: not this one",
                    "/home/alice/new: Operation not supported",
                ],
            }),
            &mut out,
        );
        let out = String::from_utf8(out).unwrap();
        assert_eq!(
            out,
            "warning: nerve-run keeps its access to /home/alice/old, which it should have lost; no command of nerve-run runs until it is taken off: /home/alice/old: Permission denied (os error 13)\n\
             warning: nerve-run did not get every folder: /home/alice/older: not this one\n\
             warning: nerve-run did not get every folder: /home/alice/new: Operation not supported\n"
        );
        let mut out = Vec::new();
        tell_grants_of(&json!({"stale": [], "errors": []}), &mut out);
        assert!(out.is_empty());
    }

    /// Setup's folder step gives a folder commands can work in where the
    /// owner presses Enter: `+rwx`, as folder mode runs a command only where
    /// it may run one.
    #[test]
    fn setup_gives_a_folder_every_right_on_enter() {
        let (d, paths) = setup(&["home"]);
        let work = d.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        let (r, out) = setup_with(&paths, &format!("\n\n\nfolder\n{}\n\n", work.display()));
        r.unwrap();
        assert!(out.contains("[+rwx]: "), "{out}");
        let folders = &load(&paths).centers[0].policy.folders;
        assert_eq!(folders.len(), 1, "{folders:?}");
        assert_eq!(folders[0].access, Access::parse("rwx").unwrap());
    }

    /// Only at a terminal is the owner asked whether to install a keyring
    /// as root: piped answers, or a setup without a terminal, get the
    /// refusal and install nothing, whatever they say.
    #[test]
    fn setup_offers_a_keyring_only_at_a_terminal() {
        let (_d, paths) = setup(&[]);
        crate::secrets::store::set_unreachable(true);
        let k = crate::keyring_setup::tests::FakeKeyring::new(false);
        let (r, out) = setup_at(&paths, None, &k, "\nkeyring\ny\n\n", false);
        let e = r.unwrap_err();
        assert!(e.contains("run in a terminal"), "{e}");
        assert!(!out.contains("Install it now?"), "{out}");
        assert!(k.installed.borrow().is_empty());
        assert_eq!(load(&paths).machine.secret_storage, SecretStorage::File);
        crate::secrets::store::set_unreachable(false);
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

    /// `center grant settings write` warns where root is the owner: the
    /// center can make itself root by setting its own mode to user.
    #[test]
    fn the_settings_grant_warns_where_root_is_the_owner() {
        let w = settings_grant_warning("home", SettingsGrant::Write, true).unwrap();
        assert!(
            w.starts_with("Warning: root is the owner of this node"),
            "{w}"
        );
        assert!(w.contains("home can now set its own mode to user"), "{w}");
        assert!(w.contains("run as root"), "{w}");
        assert_eq!(
            settings_grant_warning("home", SettingsGrant::Off, true),
            None
        );
        assert_eq!(
            settings_grant_warning("home", SettingsGrant::Write, false),
            None
        );
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

    /// Setup chooses no account: it has no flags, and asks for none.
    #[test]
    fn setup_chooses_no_account() {
        for flag in ["--create-user", "--account-only"] {
            assert!(Cli::try_parse_from(["nerve-node", "setup", flag, "bob"]).is_err());
        }
        let (_d, paths) = setup(&["home"]);
        let (r, out) = setup_with(&paths, "lab-pc\n\n\nuser\n");
        r.unwrap();
        assert!(!out.contains("Account that commands"), "{out}");
    }

    fn node_audit(paths: &NodePaths) -> Vec<Value> {
        AuditLog::new(paths.audit_log())
            .read()
            .unwrap()
            .into_iter()
            .filter(|v| v["kind"] == "node")
            .collect()
    }

    /// Setup asks name, center and mode; Enter keeps each, and every answer
    /// goes through the owner's path into the signed file and the audit log.
    #[test]
    fn setup_names_the_node_and_sets_the_first_centers_mode() {
        let (d, paths) = setup(&["home"]);
        let dir = d.path().join("work");
        std::fs::create_dir(&dir).unwrap();
        // A name, the keys where they are, no new center (the one paired is
        // the first), folder mode with one folder.
        let answers = format!("lab-pc\n\n\nfolder\n{}\n+r +x\n", dir.display());
        let (r, out) = setup_with(&paths, &answers);
        r.unwrap();
        assert!(out.contains("Name of this node"), "{out}");
        assert!(out.contains("home: mode folder"), "{out}");
        let cfg = SettingsStore::peek(&paths.config_file(), &paths.config_key()).unwrap();
        assert_eq!(cfg.node.name.as_deref(), Some("lab-pc"));
        let c = cfg.center("home").unwrap();
        assert_eq!(c.policy.mode, Mode::Folder);
        assert_eq!(c.policy.folders.len(), 1);
        assert_eq!(c.policy.folders[0].access.to_string(), "rx");
        let a = node_audit(&paths);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0]["event"], "setup");
        assert_eq!(a[0]["steps"].as_array().unwrap().len(), 3, "{}", a[0]);
        // Again with Enter everywhere: nothing changes.
        let before = std::fs::read(paths.config_file()).unwrap();
        let (r, _) = setup_with(&paths, "\n\n\n\n\n");
        r.unwrap();
        assert_eq!(std::fs::read(paths.config_file()).unwrap(), before);
        // A bad name or a short input stops it, and the audit log says so.
        let (r, _) = setup_with(&paths, "Bad Name\n");
        assert!(r.unwrap_err().contains("not a node name"));
        let (r, _) = setup_with(&paths, "");
        assert!(r.unwrap_err().contains("input ended"));
        let a = node_audit(&paths);
        assert!(
            a.last().unwrap()["error"]
                .as_str()
                .unwrap()
                .contains("input ended")
        );
        let shown = run(&paths, &["audit"]).unwrap();
        assert!(
            shown.contains("setup: named the node lab-pc; home: mode folder"),
            "{shown}"
        );
    }

    /// Folder mode's commands are told off where they run as the node's own
    /// user or root, whatever the kernel, and `status` prints why the node
    /// says they are.
    #[test]
    fn the_keyring_turns_folder_commands_of_the_nodes_own_user_off() {
        use nerve_sandbox::Confinement;
        let abi = |v| Confinement {
            landlock_abi: v,
            appcontainer: false,
        };
        let account = |uid| crate::service::Account {
            name: "alice".into(),
            uid,
            gid: uid,
            comment: String::new(),
            home: "/home/alice".into(),
            groups: vec![uid],
        };
        let (root, alice) = (account(0), account(4242));
        assert!(keyring_turns_commands_off(abi(Some(6)), || None));
        assert!(keyring_turns_commands_off(abi(Some(6)), || Some(root)));
        // Another account than root cannot reach the bus: its commands run.
        assert!(!keyring_turns_commands_off(abi(Some(6)), || Some(
            alice.clone()
        )));
        let asked = std::cell::Cell::new(false);
        let ask = || {
            asked.set(true);
            None
        };
        assert!(keyring_turns_commands_off(abi(Some(9)), || None));
        assert!(!keyring_turns_commands_off(abi(Some(9)), || Some(alice)));
        assert!(!keyring_turns_commands_off(abi(None), ask));
        assert!(!asked.get());
        assert!(folder_commands_off().contains("machine.secret_storage file"));
    }

    /// The node's keys as setup and `config set` leave them: whether the
    /// config's key is in its file, and in the test keyring.
    fn config_key_at(paths: &NodePaths) -> (bool, bool) {
        let entry = crate::secrets::Entry::config_key(paths);
        (
            paths.config_key().exists(),
            crate::secrets::store::get(entry.account())
                .unwrap()
                .is_some(),
        )
    }

    #[test]
    fn config_set_moves_the_keys_and_center_rm_deletes_them_from_the_keyring() {
        let (_d, paths) = setup(&["home"]);
        let key = nerve_transport::keys::NodeKey::generate().unwrap();
        crate::secrets::store_center_key(&paths, SecretStorage::File, "home", &key).unwrap();
        let set = |to: &str| run(&paths, &["config", "set", "machine.secret_storage", to]);
        // Without a keyring nothing moves, and the setting stays.
        crate::secrets::store::set_unreachable(true);
        let e = set("keyring").unwrap_err();
        crate::secrets::store::set_unreachable(false);
        assert!(e.contains("nothing was changed"), "{e}");
        assert_eq!(load(&paths).machine.secret_storage, SecretStorage::File);
        assert_eq!(config_key_at(&paths), (true, false));
        assert!(paths.key_file("home").exists());
        set("keyring").unwrap();
        assert_eq!(load(&paths).machine.secret_storage, SecretStorage::Keyring);
        assert_eq!(config_key_at(&paths), (false, true));
        assert!(!paths.key_file("home").exists());
        let read = crate::secrets::center_key(&paths, SecretStorage::Keyring, "home").unwrap();
        assert_eq!(read.public_key(), key.public_key());
        run(&paths, &["center", "rm", "--center", "home"]).unwrap();
        assert!(crate::secrets::center_key(&paths, SecretStorage::Keyring, "home").is_err());
        set("file").unwrap();
        assert_eq!(config_key_at(&paths), (true, false));
        assert_eq!(
            run(&paths, &["config", "get", "machine.secret_storage"])
                .unwrap()
                .trim(),
            "file"
        );
    }

    /// Setup asks where the keys go; `keyring` moves them there.
    #[test]
    fn setup_keeps_the_keys_in_the_keyring_when_asked() {
        let (_d, paths) = setup(&[]);
        // Name kept, keys to the keyring, no link.
        let (r, out) = setup_with(&paths, "\nkeyring\n\n");
        r.unwrap();
        assert!(out.contains("Where the node keeps its keys"), "{out}");
        assert!(out.contains("[file]"), "{out}");
        assert!(
            out.contains("the node's keys are in the system keyring now"),
            "{out}"
        );
        assert_eq!(load(&paths).machine.secret_storage, SecretStorage::Keyring);
        assert_eq!(config_key_at(&paths), (false, true));
        let steps = node_audit(&paths)[0]["steps"].to_string();
        assert!(steps.contains("system keyring"), "{steps}");
        // Asked again, the keyring is what Enter keeps.
        let (r, out) = setup_with(&paths, "\n\n\n");
        r.unwrap();
        assert!(out.contains("[keyring]"), "{out}");
        let (r, _) = setup_with(&paths, "\nwallet\n");
        assert!(r.unwrap_err().contains("file or keyring"));
    }

    /// The installed node on Windows keeps its keys in files: `config set`
    /// refuses the keyring and changes nothing, and setup does not ask
    /// where the keys go but takes keys left in the keyring into files.
    #[test]
    fn config_get_says_whether_the_keyring_can_hold_the_keys() {
        let (_d, paths) = setup(&["home"]);
        crate::secrets::for_tests::pretend_windows_service(&paths);
        let said = run(
            &paths,
            &["--json", "config", "get", "machine.secret_storage"],
        )
        .unwrap();
        let v: Value = serde_json::from_str(said.trim()).unwrap();
        assert_eq!(v["value"], "file");
        assert_eq!(v["keyring"]["usable"], false, "{v}");
        assert_eq!(v["keyring"]["reason"], "windows-service");
        assert!(
            v["keyring"]["why"]
                .as_str()
                .unwrap()
                .contains("Credential Manager")
        );
        // Another key says nothing of it.
        let said = run(&paths, &["--json", "config", "get", "log.level"]).unwrap();
        let v: Value = serde_json::from_str(said.trim()).unwrap();
        assert!(v.get("keyring").is_none(), "{v}");
    }

    #[test]
    fn the_installed_node_on_windows_keeps_its_keys_in_files() {
        let (_d, paths) = setup(&["home"]);
        let key = nerve_transport::keys::NodeKey::generate().unwrap();
        crate::secrets::store_center_key(&paths, SecretStorage::File, "home", &key).unwrap();
        let set = |to: &str| run(&paths, &["config", "set", "machine.secret_storage", to]);
        // Moved there before it was the installed node.
        set("keyring").unwrap();
        crate::secrets::for_tests::pretend_windows_service(&paths);
        let (r, out) = setup_with(&paths, "\n\n\n");
        r.unwrap();
        assert!(!out.contains("Where the node keeps its keys"), "{out}");
        assert!(
            out.contains("Warning: the installed node on Windows"),
            "{out}"
        );
        assert!(out.contains("the node's keys are in files now"), "{out}");
        assert_eq!(load(&paths).machine.secret_storage, SecretStorage::File);
        assert_eq!(config_key_at(&paths), (true, false));
        assert!(paths.key_file("home").exists());
        let e = set("keyring").unwrap_err();
        assert!(e.contains("cannot be \"keyring\""), "{e}");
        assert!(
            e.contains(
                "go to the Credential Manager of the account that runs them, not to that of nerve"
            ),
            "{e}"
        );
        assert!(e.contains("nothing was changed"), "{e}");
        assert_eq!(load(&paths).machine.secret_storage, SecretStorage::File);
        assert_eq!(config_key_at(&paths), (true, false));
        // Asked again, setup leaves the files as they are.
        let (r, out) = setup_with(&paths, "\n\n\n");
        r.unwrap();
        assert!(!out.contains("are in files now"), "{out}");
        assert_eq!(load(&paths).machine.secret_storage, SecretStorage::File);
    }

    /// Where no keyring answers, setup offers to install one: no keeps the
    /// files, yes installs it and moves the keys.
    #[test]
    fn setup_offers_a_keyring_where_none_answers() {
        let (_d, paths) = setup(&[]);
        crate::secrets::store::set_unreachable(true);
        let k = crate::keyring_setup::tests::FakeKeyring::new(false);
        let (r, out) = setup_keyring(&paths, None, &k, "\nkeyring\nn\n");
        let e = r.unwrap_err();
        assert!(e.contains("no system keyring answers"), "{e}");
        assert!(out.contains("Install it now? [y/N]"), "{out}");
        assert!(k.installed.borrow().is_empty());
        assert_eq!(load(&paths).machine.secret_storage, SecretStorage::File);
        let (r, out) = setup_keyring(&paths, None, &k, "\nkeyring\ny\n\n");
        r.unwrap();
        assert_eq!(k.installed.borrow().len(), 1);
        assert!(out.contains("the system keyring answers"), "{out}");
        assert_eq!(load(&paths).machine.secret_storage, SecretStorage::Keyring);
        assert_eq!(config_key_at(&paths), (false, true));
    }

    /// A running node that found no keyring keeps that failure: after
    /// setup installed one, the installed node is restarted before the keys
    /// move, and the owner of a node run by hand is told to restart it. A
    /// node that never failed is left alone.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_node_that_found_no_keyring_is_restarted_after_one_is_installed() {
        let (_d, paths) = setup(&[]);
        let failed = json!({"version": 1, "keyring_failed": true});
        let sys = crate::service::tests::Fake::new();
        let mut out = Vec::new();
        restart_for_keyring(&failed, &paths, Some(&sys), false, &mut out).unwrap();
        assert!(
            sys.calls()
                .contains(&format!("systemctl restart {}", crate::service::UNIT_NAME)),
            "{:?}",
            sys.calls()
        );
        assert!(String::from_utf8_lossy(&out).contains("restarted the node"));
        let e = restart_for_keyring(&failed, &paths, None, false, &mut out).unwrap_err();
        assert!(
            e.contains("restart it, then run `nerve-node setup` again"),
            "{e}"
        );
        let sys = crate::service::tests::Fake::new();
        let fine = json!({"version": 1, "keyring_failed": false});
        restart_for_keyring(&fine, &paths, Some(&sys), false, &mut out).unwrap();
        restart_for_keyring(&fine, &paths, None, false, &mut out).unwrap();
        assert!(sys.calls().is_empty(), "{:?}", sys.calls());
        // Run by the node for its owner, setup does not restart the node it
        // runs in: it says how, and to run it again.
        let e = restart_for_keyring(&failed, &paths, Some(&sys), true, &mut out).unwrap_err();
        assert!(
            e.contains("`nerve-node service restart`, then run `nerve-node setup` again"),
            "{e}"
        );
        assert!(sys.calls().is_empty(), "{:?}", sys.calls());
        restart_for_keyring(&fine, &paths, Some(&sys), true, &mut out).unwrap();
    }

    /// `status` shows the limits per command the owner set, and whether
    /// the running node holds commands to them, or why not.
    #[cfg(unix)]
    #[test]
    fn the_status_shows_the_limits_per_command() {
        let (d, paths) = setup(&[]);
        run(
            &paths,
            &["config", "set", "limits.command.memory_mb", "512"],
        )
        .unwrap();
        let out = run(&paths, &["status"]).unwrap();
        assert!(
            out.contains("limits per command: memory 512 MiB, CPU 200 %, 1024 processes; a call may ask for up to 16384 MiB, 800 %, 8192 processes"),
            "{out}"
        );
        let (ready_tx, ready) = std::sync::mpsc::channel();
        let (stop, stop_rx) = std::sync::mpsc::channel::<()>();
        let node = {
            let (home, paths) = (d.path().to_path_buf(), paths.clone());
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                let mut opts = NodeOptions::new(paths);
                opts.home = home;
                opts.full_rights = Some(false);
                opts.cgroups = Some(Err("no cgroup for this test".into()));
                let daemon = rt.block_on(Daemon::start(opts)).unwrap();
                ready_tx.send(()).unwrap();
                rt.block_on(async {
                    while stop_rx.try_recv().is_err() {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    daemon.stop().await;
                });
            })
        };
        ready.recv().unwrap();
        let out = run(&paths, &["status"]);
        stop.send(()).unwrap();
        node.join().unwrap();
        let out = out.unwrap();
        assert!(out.contains("limits per command: memory 512 MiB"), "{out}");
        assert!(
            out.contains("commands run WITHOUT these limits: no cgroup for this test"),
            "{out}"
        );
    }

    #[test]
    fn the_status_names_the_cgroup_and_what_it_holds() {
        let v = json!({"memory_mb": 1, "memory_max_mb": 2, "cpu_percent": 3,
                       "cpu_max_percent": 4, "processes": 5, "processes_max": 6,
                       "cgroup": "/system.slice/nerve-node.service",
                       "enforced": ["memory", "processes"], "off": null});
        assert_eq!(
            limits_lines(&v),
            [
                "limits per command: memory 1 MiB, CPU 3 %, 5 processes; a call may ask for up to 2 MiB, 4 %, 6 processes",
                "limits held by the cgroup /system.slice/nerve-node.service: memory, processes; not cpu (the cgroup has no controller for it)",
            ]
        );
        // Turned off since the start: said apart from what the cgroup never
        // had, with what follows from it.
        let v = json!({"memory_mb": 1, "memory_max_mb": 2, "cpu_percent": 3,
                       "cpu_max_percent": 4, "processes": 5, "processes_max": 6,
                       "cgroup": "/", "enforced": [], "lost": ["memory", "processes"],
                       "off": null});
        assert_eq!(
            limits_lines(&v)[1..],
            [
                "limits held by the cgroup /: none; not cpu (the cgroup has no controller for it)",
                "NO COMMAND RUNS: memory, processes turned off in the cgroup since the node started; start the node again",
            ]
        );
    }

    /// Setup restarts a node that found no keyring also when the keyring
    /// answers without setup installing it, e.g. installed by hand.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_node_that_found_no_keyring_is_restarted_when_one_answers_setup() {
        let (d, paths) = setup(&[]);
        let (ready_tx, ready) = std::sync::mpsc::channel();
        let (stop, stop_rx) = std::sync::mpsc::channel::<()>();
        let node = {
            let (home, paths) = (d.path().to_path_buf(), paths.clone());
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                // This node asked a keyring that was not there yet, and
                // keeps that answer.
                crate::secrets::store::set_unreachable(true);
                assert!(crate::secrets::store::get("any").is_err());
                let mut opts = NodeOptions::new(paths);
                opts.home = home;
                opts.full_rights = Some(false);
                let daemon = rt.block_on(Daemon::start(opts)).unwrap();
                ready_tx.send(()).unwrap();
                rt.block_on(async {
                    while stop_rx.try_recv().is_err() {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    daemon.stop().await;
                });
            })
        };
        ready.recv().unwrap();
        // The keyring answers setup: nothing to install.
        let k = crate::keyring_setup::tests::FakeKeyring::new(true);
        let (r, _) = setup_keyring(&paths, None, &k, "\nkeyring\n");
        let e = r.unwrap_err();
        assert!(
            e.contains("restart it, then run `nerve-node setup` again"),
            "{e}"
        );
        assert!(k.installed.borrow().is_empty());
        let sys = crate::service::tests::Fake::new();
        // Name, the keys.
        let (r, out) = setup_keyring(&paths, Some(&sys), &k, "\nkeyring\n");
        assert!(
            sys.calls()
                .contains(&format!("systemctl restart {}", crate::service::UNIT_NAME)),
            "{:?} {r:?} {out}",
            sys.calls()
        );
        stop.send(()).unwrap();
        node.join().unwrap();
    }

    /// The running node says in its status whether it found no keyring.
    #[cfg(unix)]
    #[test]
    fn the_status_says_whether_the_node_found_no_keyring() {
        let (d, paths) = setup(&["home"]);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut opts = NodeOptions::new(paths.clone());
        opts.home = d.path().to_path_buf();
        opts.ctl = false;
        let daemon = rt.block_on(Daemon::start(opts)).unwrap();
        assert_eq!(daemon.status()["keyring_failed"], false);
        crate::secrets::store::set_unreachable(true);
        assert!(crate::secrets::store::get("any").is_err());
        assert_eq!(daemon.status()["keyring_failed"], true);
        crate::secrets::store::set_unreachable(false);
        rt.block_on(daemon.stop());
    }

    /// A node whose keys are in a keyring that no longer answers: setup
    /// asks about that before anything else, and a no stops it.
    #[test]
    fn setup_on_keys_in_a_keyring_that_does_not_answer_asks_first() {
        let (_d, paths) = setup(&[]);
        run(
            &paths,
            &["config", "set", "machine.secret_storage", "keyring"],
        )
        .unwrap();
        crate::secrets::store::set_unreachable(true);
        let k = crate::keyring_setup::tests::FakeKeyring::new(false);
        let (r, out) = setup_keyring(&paths, None, &k, "\n");
        assert!(r.unwrap_err().contains("no system keyring answers"));
        assert!(!out.contains("Name of this node"), "{out}");
        assert!(run(&paths, &["status"]).is_err());
        let (r, out) = setup_keyring(&paths, None, &k, "y\n\n\n\n");
        r.unwrap();
        assert!(out.contains("Name of this node"), "{out}");
        assert!(run(&paths, &["status"]).is_ok());
    }

    #[test]
    fn setup_without_a_center_stops_after_the_name() {
        let (_d, paths) = setup(&[]);
        let (r, out) = setup_with(&paths, "\n\n\n");
        r.unwrap();
        assert!(out.contains("No center is paired"), "{out}");
        let (_d, paths) = setup(&["a", "b"]);
        let (r, out) = setup_with(&paths, "\n\n\n");
        r.unwrap();
        assert!(out.contains("Several centers are paired"), "{out}");
        // A link that does not parse pairs nothing.
        let (r, _) = setup_with(&paths, "\n\nnot a link\n");
        assert!(r.unwrap_err().contains("nerve://pair"));
    }

    /// A control socket whose queue is full and that nothing accepts from: a
    /// node that runs but takes no connection now. Dropped, the socket is
    /// gone with it.
    #[cfg(unix)]
    struct BusyNode {
        _listener: std::os::unix::net::UnixListener,
        _queued: Vec<tokio::net::UnixStream>,
    }

    #[cfg(unix)]
    impl BusyNode {
        async fn start(paths: &NodePaths) -> BusyNode {
            use std::os::unix::io::AsRawFd;
            let sock = paths.ctl_socket();
            std::fs::create_dir_all(sock.parent().unwrap()).unwrap();
            let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
            // SAFETY: listen on a socket this test owns; a backlog of one is
            // full after a few connections, and nothing accepts them.
            assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 1) }, 0);
            let mut queued = vec![];
            while let Ok(s) = tokio::net::UnixStream::connect(&sock).await {
                queued.push(s);
                assert!(queued.len() < 100, "the queue never filled");
            }
            BusyNode {
                _listener: listener,
                _queued: queued,
            }
        }

        fn stop(self, paths: &NodePaths) {
            drop(self);
            std::fs::remove_file(paths.ctl_socket()).unwrap();
        }
    }

    /// A node that runs but takes no connection now (its queue is full) is
    /// not "not running": `panic` and `sudo off` must not write the file and
    /// report the change as done while the node never got it.
    #[cfg(unix)]
    #[test]
    fn a_busy_node_is_not_taken_for_none() {
        let (_d, paths) = setup(&["home"]);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let node = rt.block_on(BusyNode::start(&paths));
        let before = std::fs::read(paths.config_file()).unwrap();
        let busy = nerve_transport::ctl::BUSY;
        for args in [
            &["panic"][..],
            &["sudo", "off"],
            &["rule", "add", "allow", "ls"],
        ] {
            let e = run(&paths, args).unwrap_err();
            assert_eq!(e, busy, "{args:?}");
        }
        assert_eq!(std::fs::read(paths.config_file()).unwrap(), before);
        assert!(!load(&paths).locked);
        // Gone, the node is none, and the same commands go to the file.
        node.stop(&paths);
        run(&paths, &["panic"]).unwrap();
        assert!(load(&paths).locked);
    }

    /// A node that answers but keeps refusing the write with a conflict (the
    /// settings change under the CLI) is a node that did not get the change:
    /// `panic` fails and the file stays as it is. Writing the file here
    /// would be undone by the node's next write, with the change reported as
    /// made.
    #[cfg(unix)]
    #[test]
    fn a_node_that_always_answers_conflict_does_not_get_the_file_written() {
        use nerve_transport::ctl::{Reply, serve};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (_d, paths) = setup(&["home"]);
        let text = std::fs::read_to_string(paths.config_file()).unwrap();
        let writes = std::sync::Arc::new(AtomicUsize::new(0));
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (sock, counted) = (paths.ctl_socket(), writes.clone());
        rt.spawn(async move {
            let _ = serve(&sock, move |req, _| {
                let (text, counted) = (text.clone(), counted.clone());
                async move {
                    match req.method.as_str() {
                        "config.read" => Reply::Ok(json!({"config": text, "version": 7})),
                        "config.write" => {
                            counted.fetch_add(1, Ordering::SeqCst);
                            Reply::Err("conflict: the config changed (version 8)".into())
                        }
                        _ => Reply::Ok(json!({})),
                    }
                }
            })
            .await;
        });
        while !paths.ctl_socket().exists() {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let before = std::fs::read(paths.config_file()).unwrap();
        let e = run(&paths, &["panic"]).unwrap_err();
        assert!(e.contains("keeps changing"), "{e}");
        assert_eq!(writes.load(Ordering::SeqCst), 5);
        assert_eq!(std::fs::read(paths.config_file()).unwrap(), before);
        assert!(!load(&paths).locked);
    }

    /// The callers that only ask whether a node runs take a busy one for a
    /// node: it is not told that a change waits for the next start, and a
    /// second node does not start beside it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_busy_node_still_counts_as_running() {
        let (d, paths) = setup(&["home"]);
        assert!(!daemon_answers(&paths, false).await);
        let node = BusyNode::start(&paths).await;
        assert!(daemon_answers(&paths, false).await);
        let mut out = Vec::new();
        after_keyring_answers(&paths, None, &mut out).await.unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("was not asked whether it found a keyring"),
            "{out}"
        );
        let cfg = NodeConfig::load(&paths.config_file()).unwrap();
        let mut out = Vec::new();
        tell_folder_commands(&paths, &cfg, &mut out).await;
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("was not asked whether folder mode"), "{out}");
        let mut opts = crate::NodeOptions::new(paths.clone());
        opts.home = d.path().to_path_buf();
        let e = crate::Daemon::start(opts)
            .await
            .err()
            .expect("a second node");
        assert!(e.contains("already runs"), "{e}");
        node.stop(&paths);
        assert!(!daemon_answers(&paths, false).await);
        // A socket that cannot be reached at all is neither a node nor the
        // lack of one: the start says what is wrong.
        std::fs::remove_dir_all(paths.state_dir.join("run")).unwrap();
        std::fs::write(paths.state_dir.join("run"), b"").unwrap();
        assert!(!daemon_answers(&paths, false).await);
        let mut opts = crate::NodeOptions::new(paths.clone());
        opts.home = d.path().to_path_buf();
        let e = crate::Daemon::start(opts).await.err().expect("no socket");
        assert!(e.contains("cannot tell whether a node runs"), "{e}");
        assert!(!e.contains("already runs"), "{e}");
    }

    /// With several centers the commands the ambiguous `rule rm` prints name
    /// the center, so they work as printed.
    #[test]
    fn the_rm_refusal_names_the_center_it_means() {
        let (_d, paths) = setup(&["home", "work"]);
        let made = "exec.run:exec.run:git [*]";
        for rule in ["exec.run:git *", made] {
            let list = "center.work.policy.allow";
            run(&paths, &["config", "add", list, rule]).unwrap();
        }
        let args = ["rule", "rm", "allow", "exec.run:git *", "--center", "work"];
        let e = run(&paths, &args).unwrap_err();
        assert!(
            e.contains(&format!("rule rm allow '{made}' --center work")),
            "{e}"
        );
        assert!(
            e.contains("rule rm allow 'exec.run:git *' --center work"),
            "{e}"
        );
        // Run as printed.
        run(&paths, &["rule", "rm", "allow", made, "--center", "work"]).unwrap();
        run(&paths, &args).unwrap();
        assert!(load(&paths).center("work").unwrap().policy.allow.is_empty());
    }

    #[test]
    fn the_three_lists_add_remove_and_show() {
        let (_d, paths) = setup(&["home"]);
        run(&paths, &["rule", "add", "allow", "git status"]).unwrap();
        run(&paths, &["rule", "add", "deny", "git status"]).unwrap();
        run(&paths, &["rule", "add", "deny", "rm *", "--wildcard"]).unwrap();
        run(
            &paths,
            &["rule", "add", "sudo", "sudo apt update", "--wildcard"],
        )
        .unwrap();
        // The sudo list takes the command without the sudo as well.
        run(&paths, &["rule", "add", "sudo", "systemctl restart nginx"]).unwrap();
        let p = load(&paths).centers[0].policy.clone();
        // Neither list loses a rule to the other; deny wins when they meet.
        assert_eq!(p.allow, ["exec.run:git status"]);
        assert_eq!(p.deny, ["exec.run:git status", "exec.run:rm *"]);
        assert_eq!(p.sudo_allow, ["sudo apt *", "sudo systemctl restart nginx"]);
        assert!(run(&paths, &["rule", "add", "allow", "  "]).is_err());
        // A sudo command is not an allow rule.
        let e = run(&paths, &["rule", "add", "allow", "sudo apt update"]).unwrap_err();
        assert!(e.contains("rule add sudo"), "{e}");
        // The `cap.action:pattern` form is for `config add`; as a command it
        // would become a rule that never matches.
        for list in ["allow", "deny"] {
            let e = run(&paths, &["rule", "add", list, "exec.run:echo *"]).unwrap_err();
            assert!(e.contains("config add"), "{e}");
        }
        let e = run(&paths, &["rule", "add", "allow", "fs.read:~/notes/*"]).unwrap_err();
        assert!(e.contains("policy.allow"), "{e}");
        // So is the form with a capability alone, which the docs show.
        for (list, rule) in [("deny", "fs:~/private/*"), ("allow", "exec:git *")] {
            let e = run(&paths, &["rule", "add", list, rule]).unwrap_err();
            assert!(e.contains("config add"), "{e}");
        }
        assert_eq!(
            load(&paths).centers[0].policy.allow,
            ["exec.run:git status"]
        );
        // With the working rule on the list as well (added as the refusal
        // says), the arguments name neither of the two: the user picks one.
        let broken = "exec.run:fs:~/private/[*]";
        run(
            &paths,
            &["config", "add", "center.home.policy.deny", broken],
        )
        .unwrap();
        run(
            &paths,
            &["config", "add", "center.home.policy.deny", "fs:~/private/*"],
        )
        .unwrap();
        let e = run(&paths, &["rule", "rm", "deny", "fs:~/private/*"]).unwrap_err();
        assert!(
            e.contains(broken) && e.contains("\"fs:~/private/*\""),
            "{e}"
        );
        // The refusal's own instructions work, also for an entry as `ls`
        // shows the working one.
        assert!(
            e.contains(&format!("rule rm deny '{broken}' --center home")),
            "{e}"
        );
        let out = run(&paths, &["rule", "rm", "deny", broken]).unwrap();
        assert!(out.contains(broken), "{out}");
        assert_eq!(
            load(&paths).centers[0].policy.deny,
            ["exec.run:git status", "exec.run:rm *", "fs:~/private/*"]
        );
        run(&paths, &["rule", "rm", "deny", "fs:~/private/*"]).unwrap();
        for rule in ["exec.run:git *", "exec.run:exec.run:git [*]"] {
            let list = "center.home.policy.allow";
            run(&paths, &["config", "add", list, rule]).unwrap();
        }
        let e = run(&paths, &["rule", "rm", "allow", "exec.run:git *"]).unwrap_err();
        assert!(
            e.contains("rule rm allow 'exec.run:exec.run:git [*]'"),
            "{e}"
        );
        run(
            &paths,
            &["rule", "rm", "allow", "exec.run:exec.run:git [*]"],
        )
        .unwrap();
        run(&paths, &["rule", "rm", "allow", "exec.run:git *"]).unwrap();
        // A colon in a command that is not a scope stays a command.
        run(&paths, &["rule", "add", "allow", "C:\\tools\\x.exe"]).unwrap();
        run(&paths, &["rule", "rm", "allow", "C:\\tools\\x.exe"]).unwrap();
        assert_eq!(
            load(&paths).centers[0].policy.allow,
            ["exec.run:git status"]
        );
        // A command with a glob character in it is allowed as itself.
        run(&paths, &["rule", "add", "allow", "rm *"]).unwrap();
        assert!(load(&paths).centers[0].policy.allow[1].contains("[*]"));
        // Rules for other actions go in through `config add` and show in `ls`.
        run(
            &paths,
            &[
                "config",
                "add",
                "center.home.policy.allow",
                "fs.read:~/notes/*",
            ],
        )
        .unwrap();
        assert!(
            run(
                &paths,
                &["config", "add", "center.home.policy.allow", "~/notes"]
            )
            .is_err()
        );
        let ls = run(&paths, &["rule", "ls", "allow"]).unwrap();
        assert_eq!(ls.lines().count(), 3, "{ls}");
        assert!(ls.contains("fs.read:~/notes/*"), "{ls}");
        // rm takes the command like add, or an entry as ls shows it.
        run(&paths, &["rule", "rm", "allow", "git status"]).unwrap();
        run(&paths, &["rule", "rm", "allow", "fs.read:~/notes/*"]).unwrap();
        run(&paths, &["rule", "rm", "deny", "rm *", "--wildcard"]).unwrap();
        run(&paths, &["rule", "rm", "sudo", "apt update", "--wildcard"]).unwrap();
        let p = load(&paths).centers[0].policy.clone();
        assert_eq!(p.allow.len(), 1, "{:?}", p.allow);
        assert_eq!(p.deny, ["exec.run:git status"]);
        assert_eq!(p.sudo_allow, ["sudo systemctl restart nginx"]);
        // Something that is not on the list is an error.
        let e = run(&paths, &["rule", "rm", "deny", "ls"]).unwrap_err();
        assert!(e.contains("not on the deny rule"), "{e}");
        let ls = run(&paths, &["rule", "ls", "sudo"]).unwrap();
        assert_eq!(ls, "sudo systemctl restart nginx\n");
        // Without a list, `ls` shows all three, each line with its list.
        let all = run(&paths, &["rule", "ls"]).unwrap();
        assert!(all.contains("deny  exec.run:git status\n"), "{all}");
        assert!(
            all.contains("sudo  sudo systemctl restart nginx\n"),
            "{all}"
        );
        run(&paths, &["rule", "rm", "sudo", "systemctl restart nginx"]).unwrap();
        let ls = run(&paths, &["rule", "ls", "sudo"]).unwrap();
        assert!(ls.contains("nothing on the sudo allow list"), "{ls}");
    }

    #[test]
    fn caps_and_proxy_show_what_is_set() {
        let (_d, paths) = setup(&["home"]);
        let ls = run(&paths, &["cap", "ls"]).unwrap();
        assert!(ls.contains("fs.read"), "{ls}");
        assert!(ls.contains("no program is allowed as a provider"), "{ls}");
        run(&paths, &["cap", "set", "exec", "hidden"]).unwrap();
        let ls = run(&paths, &["cap", "ls"]).unwrap();
        let run_line = ls.lines().find(|l| l.starts_with("exec.run ")).unwrap();
        assert!(run_line.ends_with("home: hidden"), "{ls}");
        assert_eq!(run(&paths, &["proxy", "ls"]).unwrap(), "no proxy\n");
        run(
            &paths,
            &[
                "proxy",
                "set",
                "http://127.0.0.1:3128",
                "--header",
                "X-Key: s3cret-value",
            ],
        )
        .unwrap();
        let ls = run(&paths, &["proxy", "ls"]).unwrap();
        assert!(
            ls.contains("http://127.0.0.1:3128") && ls.contains("X-Key"),
            "{ls}"
        );
        assert!(!ls.contains("s3cret"), "{ls}");
        run(&paths, &["proxy", "rm"]).unwrap();
        assert_eq!(run(&paths, &["proxy", "ls"]).unwrap(), "no proxy\n");
    }

    /// What the test keyring holds for the node at `paths`.
    fn keyring_entry(paths: &NodePaths) -> Option<String> {
        let entry = crate::secrets::Entry::proxy(paths);
        crate::secrets::store::get(entry.account()).unwrap()
    }

    #[test]
    fn proxy_set_keeps_header_values_in_the_keyring_not_in_node_toml() {
        let (_d, paths) = setup(&["home"]);
        let out = run(
            &paths,
            &[
                "proxy",
                "set",
                "http://127.0.0.1:3128",
                "--header",
                "X-Key: s3cret-value",
                "--header",
                "X-Other:  two words ",
            ],
        )
        .unwrap();
        assert!(
            out.contains("header X-Key") && out.contains("header X-Other"),
            "{out}"
        );
        assert!(!out.contains("s3cret"), "{out}");
        let file = std::fs::read_to_string(paths.config_file()).unwrap();
        assert!(
            !file.contains("s3cret") && !file.contains("two words"),
            "{file}"
        );
        let cfg = load(&paths);
        assert_eq!(
            cfg.connection.proxy.as_deref(),
            Some("http://127.0.0.1:3128")
        );
        assert_eq!(cfg.connection.headers, ["X-Key", "X-Other"]);
        let held: std::collections::BTreeMap<String, String> =
            serde_json::from_str(&keyring_entry(&paths).unwrap()).unwrap();
        assert_eq!(held["X-Key"], "s3cret-value");
        assert_eq!(held["X-Other"], "two words");
        // A proxy without headers needs no entry; the old one goes.
        run(&paths, &["proxy", "set", "http://127.0.0.1:3129"]).unwrap();
        assert_eq!(keyring_entry(&paths), None);
        assert!(load(&paths).connection.headers.is_empty());
    }

    #[test]
    fn a_user_and_password_in_the_url_go_to_the_keyring() {
        let (_d, paths) = setup(&["home"]);
        let out = run(
            &paths,
            &["proxy", "set", "http://alice:pa%40ss-w0rd@127.0.0.1:3128"],
        )
        .unwrap();
        assert!(!out.contains("pa%40ss") && !out.contains("alice"), "{out}");
        let file = std::fs::read_to_string(paths.config_file()).unwrap();
        assert!(
            !file.contains("alice") && !file.contains("pa%40ss"),
            "{file}"
        );
        let cfg = load(&paths);
        assert_eq!(
            cfg.connection.proxy.as_deref(),
            Some("http://127.0.0.1:3128")
        );
        assert_eq!(cfg.connection.headers, [PROXY_AUTHORIZATION]);
        use base64::Engine;
        let basic = base64::engine::general_purpose::STANDARD.encode("alice:pa@ss-w0rd");
        assert!(!file.contains(&basic), "{file}");
        let held: std::collections::BTreeMap<String, String> =
            serde_json::from_str(&keyring_entry(&paths).unwrap()).unwrap();
        assert_eq!(held[PROXY_AUTHORIZATION], format!("Basic {basic}"));
        // Both ways at once is refused, and so is a bad URL, without quoting it.
        let both = [
            "proxy",
            "set",
            "http://alice:s3cret@127.0.0.1:3128",
            "--header",
            "proxy-authorization: Basic x",
        ];
        assert!(run(&paths, &both).unwrap_err().contains("not both"));
        for bad in [
            "alice:s3cret@127.0.0.1:3128",
            "http://alice:s3cret@127.0.0.1:3128/path",
            "https://alice:s3cret@127.0.0.1:3128/path",
            "http://alice:s3cr%zzet@127.0.0.1:3128",
        ] {
            let e = run(&paths, &["proxy", "set", bad]).unwrap_err();
            assert!(!e.contains("s3cr"), "{bad}: {e}");
        }
        // A --header without its colon is not quoted either.
        let e = run(
            &paths,
            &["proxy", "set", "http://127.0.0.1:1", "--header", "s3cret"],
        )
        .unwrap_err();
        assert!(!e.contains("s3cret"), "{e}");
    }

    #[test]
    fn a_node_toml_with_header_values_is_refused_with_run_proxy_set_again() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("c"), d.path().join("s"));
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        std::fs::write(
            paths.config_file(),
            "[connection]\nproxy = \"http://127.0.0.1:3128\"\nheaders = { X-Key = \"s3cret-value\" }\n",
        )
        .unwrap();
        for args in [&["proxy", "ls"][..], &["status"]] {
            let e = run(&paths, args).unwrap_err();
            assert!(e.contains("run `nerve-node proxy set` again"), "{e}");
            assert!(!e.contains("s3cret"), "{e}");
        }
    }

    /// `relay add` shows a node's token once, with the line its node runs
    /// (an https:// proxy with the relay's pin), and `node.toml` keeps only
    /// the token's hash; the relay's TLS key is kept with the node's keys;
    /// `set`, `set-centers`, `rm` and `off` change the relay and nothing
    /// else.
    #[test]
    fn relay_add_shows_the_token_once_and_keeps_only_its_hash() {
        let (_d, paths) = setup(&["home", "work"]);
        // home and its neighbour share one address, behind one proxy.
        let mut cfg = load(&paths);
        cfg.centers[0].url = "https://h.example/a".into();
        cfg.centers[1].url = "https://w.example".into();
        let mut neighbour = entry("home-b");
        neighbour.url = "https://H.example:443/b".into();
        cfg.centers.push(neighbour);
        cfg.save(&paths.config_file()).unwrap();
        let paired = load(&paths).centers;
        let out = run(
            &paths,
            &["relay", "set", "0.0.0.0:7490", "--max-links", "8"],
        )
        .unwrap();
        let pin = load(&paths).relay.pin.expect("a pin");
        assert!(
            out.starts_with(&format!(
                "relay on 0.0.0.0:7490: at most 8 tunnels, 4 per node, 30 opened a minute per node\nits TLS certificate has the pin {pin}\nno node may use it yet"
            )),
            "{out}"
        );
        let id = crate::secrets::relay_tls(&paths, SecretStorage::File)
            .unwrap()
            .expect("the relay's TLS key");
        assert_eq!(id.pin(), pin);
        assert!(paths.relay_tls_file().exists());
        // Again: the same certificate.
        run(
            &paths,
            &[
                "relay",
                "set",
                "0.0.0.0:7491",
                "--max-opens-per-minute",
                "300",
            ],
        )
        .unwrap();
        assert_eq!(load(&paths).relay.max_opens_per_minute, 300);
        assert!(
            run(
                &paths,
                &[
                    "relay",
                    "set",
                    "0.0.0.0:7491",
                    "--max-opens-per-minute",
                    "0"
                ]
            )
            .is_err()
        );
        assert_eq!(load(&paths).relay.pin.as_deref(), Some(pin.as_str()));
        let e = run(&paths, &["relay", "set", "relay.example:7490"]).unwrap_err();
        assert!(e.contains("relay.listen"), "{e}");
        assert_eq!(load(&paths).relay.listen.as_deref(), Some("0.0.0.0:7491"));

        let out = run(&paths, &["relay", "add", "lab-pc"]).unwrap();
        // One link holds all the other node needs: the relay's address (the
        // host name here, as the relay listens on every address), the
        // node's name and token, and the pin.
        let link = out.lines().nth(1).unwrap().trim().to_string();
        let parsed = nerve_proto::link::RelayLink::parse(&link).unwrap();
        let token = parsed.token.clone();
        assert_eq!(token.len(), 43, "{out}");
        assert_eq!(parsed.node, "lab-pc");
        assert_eq!(parsed.pin, pin);
        let host = crate::descriptor::host_name();
        assert_eq!(parsed.address, format!("{host}:7491"));
        assert!(
            out.contains(&format!(
                "on lab-pc, paste it in the desktop app (Relay, Connect), or run:\n  nerve-node proxy set '{link}'\nthe link reaches this machine as {host}:7491;"
            )),
            "{out}"
        );
        assert!(
            out.contains("it may reach every https center of this node\n"),
            "{out}"
        );
        let file = std::fs::read_to_string(paths.config_file()).unwrap();
        assert!(!file.contains(&token), "{file}");
        let cfg = load(&paths);
        let node = cfg.relay.node("lab-pc").unwrap();
        assert_eq!(node.token_sha256, crate::relay::token_hash(&token));
        assert!(node.centers.is_empty());
        assert_eq!(cfg.centers, paired);
        let e = run(&paths, &["relay", "add", "lab-pc"]).unwrap_err();
        assert!(e.contains("relay rm lab-pc"), "{e}");
        assert!(run(&paths, &["relay", "add", "Lab PC"]).is_err());

        // A node limited to some centers; only paired ones can be named.
        // A list that splits one address is refused: the relay cannot keep
        // the two apart.
        let e = run(&paths, &["relay", "add", "lab-2", "--center", "home"]).unwrap_err();
        assert!(e.contains("home and home-b share one host and port"), "{e}");
        assert!(load(&paths).relay.node("lab-2").is_none());
        let out = run(&paths, &["relay", "add", "lab-2", "--center", "work"]).unwrap();
        assert!(out.contains("it may reach the centers work\n"), "{out}");
        assert_eq!(load(&paths).relay.node("lab-2").unwrap().centers, ["work"]);
        let e = run(&paths, &["relay", "add", "lab-3", "--center", "elsewhere"]).unwrap_err();
        assert!(e.contains("no center named elsewhere"), "{e}");
        assert!(load(&paths).relay.node("lab-3").is_none());
        let out = run(
            &paths,
            &[
                "relay",
                "set-centers",
                "lab-2",
                "--center",
                "work",
                "--center",
                "home",
                "--center",
                "home-b",
            ],
        )
        .unwrap();
        assert!(
            out.starts_with("relay node lab-2 may reach the centers work, home, home-b\n"),
            "{out}"
        );
        assert!(
            run(
                &paths,
                &["relay", "set-centers", "nobody", "--center", "home"]
            )
            .is_err()
        );

        // A node of its own limits, for a relay behind this one.
        let out = run(
            &paths,
            &[
                "relay",
                "set-limits",
                "lab-2",
                "--max-links",
                "12",
                "--max-opens-per-minute",
                "300",
            ],
        )
        .unwrap();
        assert!(
            out.starts_with("relay node lab-2: at most 12 tunnels at once, 300 opened a minute (the relay's 8 tunnels in all bound it;"),
            "{out}"
        );
        let node = load(&paths).relay.node("lab-2").unwrap().clone();
        assert_eq!(
            (node.max_links, node.max_opens_per_minute),
            (Some(12), Some(300))
        );
        // One flag sets that limit and keeps the other, as `relay set` does.
        run(
            &paths,
            &["relay", "set-limits", "lab-2", "--max-links", "20"],
        )
        .unwrap();
        let node = load(&paths).relay.node("lab-2").unwrap().clone();
        assert_eq!(
            (node.max_links, node.max_opens_per_minute),
            (Some(20), Some(300))
        );
        run(
            &paths,
            &["relay", "set-limits", "lab-2", "--max-links", "12"],
        )
        .unwrap();
        // A new token keeps the node's centers and limits; the old one
        // stops working.
        let before = load(&paths).relay.node("lab-2").unwrap().clone();
        let out = run(
            &paths,
            &["relay", "token", "lab-2", "--address", "relay.example"],
        )
        .unwrap();
        let link = nerve_proto::link::RelayLink::parse(out.lines().nth(1).unwrap()).unwrap();
        let token2 = link.token.clone();
        assert_eq!(token2.len(), 43, "{out}");
        // The address given, at the relay's port; no guess to warn about.
        assert_eq!(link.address, "relay.example:7491");
        assert!(!out.contains("make a new link"), "{out}");
        assert!(
            out.contains("it may reach the centers work, home, home-b\n"),
            "{out}"
        );
        let after = load(&paths).relay.node("lab-2").unwrap().clone();
        assert_eq!(after.token_sha256, crate::relay::token_hash(&token2));
        assert_ne!(after.token_sha256, before.token_sha256);
        assert_eq!(
            (&after.centers, after.max_links, after.max_opens_per_minute),
            (
                &before.centers,
                before.max_links,
                before.max_opens_per_minute
            )
        );
        assert!(
            !std::fs::read_to_string(paths.config_file())
                .unwrap()
                .contains(&token2)
        );
        assert!(run(&paths, &["relay", "token", "nobody"]).is_err());
        // The flag's help sends a chain to `set-limits`, not to the
        // relay-wide budget.
        let help = Cli::command()
            .find_subcommand_mut("relay")
            .unwrap()
            .find_subcommand_mut("set")
            .unwrap()
            .render_long_help()
            .to_string();
        assert!(help.contains("relay set-limits <name>"), "{help}");
        assert!(!help.contains("more for a relay behind this one"), "{help}");
        assert_eq!(
            load(&paths).relay.max_links_per_node,
            4,
            "the relay's stays"
        );
        assert!(
            run(
                &paths,
                &["relay", "set-limits", "lab-2", "--max-links", "0"]
            )
            .is_err()
        );
        assert!(
            run(
                &paths,
                &["relay", "set-limits", "nobody", "--max-links", "2"]
            )
            .is_err()
        );
        let ls = run(&paths, &["relay", "ls"]).unwrap();
        assert!(
            ls.contains("node lab-2: the centers work, home, home-b; its own limits: 12 tunnels at once, 300 opened a minute\n"),
            "{ls}"
        );
        run(&paths, &["relay", "set-limits", "lab-2"]).unwrap();
        let node = load(&paths).relay.node("lab-2").unwrap().clone();
        assert_eq!((node.max_links, node.max_opens_per_minute), (None, None));

        let ls = run(&paths, &["relay", "ls"]).unwrap();
        assert!(
            ls.starts_with(&format!(
                "relay on 0.0.0.0:7491\nat most 8 tunnels, 4 per node, 300 opened a minute per node\npin {pin}\nnode lab-pc: every https center of this node\nnode lab-2: the centers work, home, home-b\n"
            )),
            "{ls}"
        );
        assert!(!ls.contains(&token), "{ls}");
        run(&paths, &["relay", "set-centers", "lab-2"]).unwrap();
        assert!(load(&paths).relay.node("lab-2").unwrap().centers.is_empty());

        // A lost TLS key: relay add makes a new certificate and says so.
        std::fs::remove_file(paths.relay_tls_file()).unwrap();
        let out = run(&paths, &["relay", "add", "lab-4"]).unwrap();
        let new_pin = load(&paths).relay.pin.unwrap();
        assert_ne!(new_pin, pin);
        assert!(
            out.starts_with(&format!(
                "the relay's TLS key was gone or did not match its pin, so it has a new certificate (pin {new_pin})"
            )),
            "{out}"
        );
        let out = run(&paths, &["relay", "add", "lab-5"]).unwrap();
        assert!(!out.contains("new certificate"), "{out}");

        let out = run(&paths, &["relay", "rm", "lab-pc"]).unwrap();
        assert!(out.starts_with("relay node lab-pc removed"), "{out}");
        assert!(load(&paths).relay.node("lab-pc").is_none());
        assert!(run(&paths, &["relay", "rm", "lab-pc"]).is_err());
        let out = run(&paths, &["relay", "off"]).unwrap();
        assert!(out.starts_with("relay off\n"), "{out}");
        let cfg = load(&paths);
        assert_eq!(cfg.relay.listen, None);
        assert_eq!(cfg.relay.max_links, 8);
        assert!(
            run(&paths, &["relay", "ls"])
                .unwrap()
                .starts_with("relay off\n")
        );
    }

    /// The login of an https:// proxy, a relay token, is kept where the
    /// node keeps its keys: its file by default, the keyring with
    /// `keyring`, which refuses clearly when it does not answer; never in
    /// node.toml, and `proxy rm` deletes it.
    #[test]
    fn an_https_proxy_login_is_kept_with_the_node_keys() {
        let pin = "A".repeat(43);
        let url = "https://lab:t0ken-value@127.0.0.1:7490";
        for storage in [SecretStorage::File, SecretStorage::Keyring] {
            let (_d, paths) = setup(&["home"]);
            if storage == SecretStorage::Keyring {
                let mut cfg = load(&paths);
                cfg.machine.secret_storage = storage;
                cfg.save(&paths.config_file()).unwrap();
            }
            let out = run(&paths, &["proxy", "set", url, "--pin", &pin]).unwrap();
            assert!(
                out.contains(&format!(
                    "pin {pin}\nlogin lab (its password is kept with the node's keys"
                )),
                "{out}"
            );
            assert!(!out.contains("t0ken"), "{out}");
            let cfg = load(&paths);
            assert_eq!(
                cfg.connection.proxy.as_deref(),
                Some("https://127.0.0.1:7490")
            );
            assert_eq!(cfg.connection.login.as_deref(), Some("lab"));
            assert!(cfg.connection.headers.is_empty());
            let toml = std::fs::read_to_string(paths.config_file()).unwrap();
            assert!(!toml.contains("t0ken"), "{toml}");
            assert_eq!(keyring_entry(&paths), None, "the header entry stays empty");
            let entry = crate::secrets::Entry::proxy_login(&paths);
            let in_keyring = crate::secrets::store::get(entry.account()).unwrap();
            let in_file = std::fs::read_to_string(paths.proxy_login_file()).ok();
            match storage {
                SecretStorage::File => {
                    assert_eq!(in_file.as_deref().map(str::trim), Some("t0ken-value"));
                    assert_eq!(in_keyring, None);
                }
                SecretStorage::Keyring => {
                    assert_eq!(in_keyring.as_deref(), Some("t0ken-value"));
                    assert_eq!(in_file, None);
                }
            }
            let ls = run(&paths, &["proxy", "ls"]).unwrap();
            assert!(ls.contains("login lab (its password is kept"), "{ls}");
            run(&paths, &["proxy", "rm"]).unwrap();
            assert_eq!(crate::secrets::store::get(entry.account()).unwrap(), None);
            assert!(!paths.proxy_login_file().exists());
            assert_eq!(load(&paths).connection, Default::default());
        }
        // With the keys in a keyring that does not answer, it refuses and
        // changes nothing, as for any key of the node.
        let (_d, paths) = setup(&["home"]);
        let mut cfg = load(&paths);
        cfg.machine.secret_storage = SecretStorage::Keyring;
        cfg.save(&paths.config_file()).unwrap();
        run(&paths, &["status"]).unwrap();
        crate::secrets::store::set_unreachable(true);
        let r = run(&paths, &["proxy", "set", url, "--pin", &pin]);
        crate::secrets::store::set_unreachable(false);
        let e = r.unwrap_err();
        assert!(e.contains("system keyring"), "{e}");
        assert!(!e.contains("t0ken"), "{e}");
        assert_eq!(load(&paths).connection, Default::default());
        assert!(!paths.proxy_login_file().exists());
        // A pin is for an https:// proxy only.
        let e = run(
            &paths,
            &["proxy", "set", "http://127.0.0.1:3128", "--pin", &pin],
        )
        .unwrap_err();
        assert!(e.contains("https"), "{e}");
    }

    #[test]
    fn proxy_ls_and_rm_with_and_without_a_keyring_entry() {
        let (_d, paths) = setup(&["home"]);
        let set = [
            "proxy",
            "set",
            "http://127.0.0.1:3128",
            "--header",
            "X-Key: s3cret-value",
        ];
        // With the entry: ls says the value is there, rm deletes it.
        run(&paths, &set).unwrap();
        let ls = run(&paths, &["proxy", "ls"]).unwrap();
        assert_eq!(
            ls,
            "proxy http://127.0.0.1:3128\nheader X-Key (its value is in the system keyring)\n"
        );
        let rm = run(&paths, &["proxy", "rm"]).unwrap();
        assert!(rm.contains("deleted the header values"), "{rm}");
        assert_eq!(keyring_entry(&paths), None);
        assert_eq!(run(&paths, &["proxy", "ls"]).unwrap(), "no proxy\n");

        // Without it: ls names the entry the link misses, rm still works.
        run(&paths, &set).unwrap();
        let entry = crate::secrets::Entry::proxy(&paths);
        crate::secrets::store::delete(entry.account()).unwrap();
        let ls = run(&paths, &["proxy", "ls"]).unwrap();
        assert!(ls.contains("header X-Key\n"), "{ls}");
        assert!(ls.contains(&format!("no entry {entry}")), "{ls}");
        let rm = run(&paths, &["proxy", "rm"]).unwrap();
        assert_eq!(
            rm,
            format!("no proxy\nthe change is in node.toml; it {NEXT_START}\n")
        );
        assert_eq!(load(&paths).connection, Default::default());

        // A proxy without headers never needs the keyring, reachable or not.
        crate::secrets::store::set_unreachable(true);
        let plain = run(&paths, &["proxy", "set", "http://127.0.0.1:3128"]);
        let ls = run(&paths, &["proxy", "ls"]);
        let rm = run(&paths, &["proxy", "rm"]);
        crate::secrets::store::set_unreachable(false);
        let next = format!("the change is in node.toml; it {NEXT_START}\n");
        assert_eq!(
            plain.unwrap(),
            format!("proxy http://127.0.0.1:3128\n{next}")
        );
        assert_eq!(ls.unwrap(), "proxy http://127.0.0.1:3128\n");
        assert_eq!(rm.unwrap(), format!("no proxy\n{next}"));
    }

    #[test]
    fn without_a_keyring_proxy_set_refuses_and_writes_no_value() {
        let (_d, paths) = setup(&["home"]);
        let before = std::fs::read_to_string(paths.config_file()).unwrap();
        crate::secrets::store::set_unreachable(true);
        let r = run(
            &paths,
            &[
                "proxy",
                "set",
                "http://alice:pa55w0rd@127.0.0.1:3128",
                "--header",
                "X-Key: s3cret-value",
            ],
        );
        crate::secrets::store::set_unreachable(false);
        let e = r.unwrap_err();
        assert!(
            e.contains("cannot store the proxy's header values in the system keyring"),
            "{e}"
        );
        assert!(e.contains(crate::secrets::store::NO_SERVICE), "{e}");
        assert!(!e.contains("s3cret") && !e.contains("pa55w0rd"), "{e}");
        // Nothing changed, and no value went to any file of the node.
        assert_eq!(
            std::fs::read_to_string(paths.config_file()).unwrap(),
            before
        );
        assert_eq!(keyring_entry(&paths), None);
        for dir in [&paths.config_dir, &paths.state_dir] {
            for f in files_below(dir) {
                let bytes = std::fs::read(&f).unwrap();
                let text = String::from_utf8_lossy(&bytes);
                assert!(
                    !text.contains("s3cret") && !text.contains("pa55w0rd"),
                    "{f:?}"
                );
            }
        }
    }

    /// The installed node on Windows runs as `nerve`, whose Credential
    /// Manager is not the administrator's that `proxy set` writes to. So
    /// a header or a password is refused, with the keyring left alone and
    /// nothing changed; a proxy that needs neither works, and its call
    /// takes an entry left by an earlier `proxy set` away.
    #[test]
    fn on_the_installed_node_on_windows_proxy_set_refuses_header_values_and_a_password() {
        let (_d, paths) = setup(&["home"]);
        // Set as an administrator before the node was installed.
        run(
            &paths,
            &[
                "proxy",
                "set",
                "http://127.0.0.1:3128",
                "--header",
                "X-Old: o1d-value",
            ],
        )
        .unwrap();
        crate::secrets::for_tests::pretend_windows_service(&paths);
        let before = std::fs::read_to_string(paths.config_file()).unwrap();
        let held = keyring_entry(&paths);
        assert!(held.is_some());
        let asked = crate::secrets::store::calls();
        for args in [
            &[
                "proxy",
                "set",
                "http://127.0.0.1:3129",
                "--header",
                "X-Key: s3cret-value",
            ][..],
            &["proxy", "set", "http://alice:pa55w0rd@127.0.0.1:3129"],
        ] {
            let e = run(&paths, args).unwrap_err();
            assert!(
                e.contains(
                    "go to the Credential Manager of the account that runs it, not to that of nerve"
                ),
                "{e}"
            );
            assert!(e.contains("nothing was changed"), "{e}");
            assert!(e.contains("`nerve-node proxy set <url>`"), "{e}");
            assert!(!e.contains("s3cret") && !e.contains("pa55w0rd"), "{e}");
            assert!(!e.contains("alice"), "{e}");
        }
        // The keyring was not asked, and node.toml and the old entry stayed.
        assert_eq!(crate::secrets::store::calls(), asked);
        assert_eq!(
            std::fs::read_to_string(paths.config_file()).unwrap(),
            before
        );
        assert_eq!(keyring_entry(&paths), held);

        // The entry an administrator's keyring holds is not what the service
        // reads, so `proxy ls` does not call it good.
        let ls = run(&paths, &["proxy", "ls"]).unwrap();
        assert!(ls.contains("header X-Old\n"), "{ls}");
        assert!(!ls.contains("its value is in the system keyring"), "{ls}");
        assert!(ls.contains("the link cannot use this proxy"), "{ls}");
        assert!(ls.contains("the service does not find them"), "{ls}");
        assert!(!ls.contains("o1d-value"), "{ls}");

        // A proxy that needs neither works, and takes the old entry away.
        let next = format!("the change is in node.toml; it {NEXT_START}\n");
        let out = run(&paths, &["proxy", "set", "http://127.0.0.1:3129"]).unwrap();
        assert_eq!(out, format!("proxy http://127.0.0.1:3129\n{next}"));
        let cfg = load(&paths);
        assert_eq!(
            cfg.connection.proxy.as_deref(),
            Some("http://127.0.0.1:3129")
        );
        assert!(cfg.connection.headers.is_empty());
        assert_eq!(keyring_entry(&paths), None);
        assert_eq!(
            run(&paths, &["proxy", "ls"]).unwrap(),
            "proxy http://127.0.0.1:3129\n"
        );
        assert_eq!(
            run(&paths, &["proxy", "rm"]).unwrap(),
            format!("no proxy\n{next}")
        );
    }

    fn files_below(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(files_below(&p));
            } else {
                out.push(p);
            }
        }
        out
    }

    /// A buffer the test's log subscriber writes into (the one test that
    /// reads it is Unix only).
    #[cfg(unix)]
    #[derive(Clone, Default)]
    struct LogBuf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    #[cfg(unix)]
    impl std::io::Write for LogBuf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Everything the test process logs, from every thread. A subscriber
    /// for one thread or one test misses lines: tracing caches per call site
    /// whether anyone listens, and other tests' threads reach the same sites.
    #[cfg(unix)]
    fn process_logs() -> LogBuf {
        static LOGS: std::sync::OnceLock<LogBuf> = std::sync::OnceLock::new();
        LOGS.get_or_init(|| {
            let logs = LogBuf::default();
            let sink = logs.clone();
            tracing::subscriber::set_global_default(
                tracing_subscriber::fmt()
                    .with_writer(move || sink.clone())
                    .with_max_level(tracing::Level::TRACE)
                    .with_ansi(false)
                    .finish(),
            )
            .expect("no other test sets a global subscriber");
            logs
        })
        .clone()
    }

    /// `proxy set` through a running daemon: the audit log records the
    /// change, and neither it nor the log holds a value.
    #[cfg(unix)]
    #[test]
    fn no_secret_reaches_the_audit_log_or_the_log() {
        let logs = process_logs();
        let (d, paths) = setup(&["home"]);
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let mut opts = NodeOptions::new(paths.clone());
        opts.home = d.path().to_path_buf();
        let daemon = rt.block_on(Daemon::start(opts)).unwrap();
        let set = [
            "proxy",
            "set",
            "http://alice:pa55w0rd@127.0.0.1:3128",
            "--header",
            "X-Key: s3cret-value",
        ];
        let out = run(&paths, &set).unwrap();
        assert_eq!(
            daemon.config().connection.headers,
            ["X-Key", PROXY_AUTHORIZATION]
        );
        // The running node took the change at once.
        assert!(!out.contains("next start"), "{out}");
        rt.block_on(daemon.stop());
        drop(rt);
        let audit = std::fs::read_to_string(paths.audit_log()).unwrap();
        assert!(audit.contains("connection.headers"), "{audit}");
        let logs = String::from_utf8_lossy(&logs.0.lock().unwrap()).to_string();
        assert!(logs.contains("node daemon running"), "{logs}");
        use base64::Engine;
        let basic = base64::engine::general_purpose::STANDARD.encode("alice:pa55w0rd");
        for (what, text) in [("audit", &audit), ("log", &logs), ("output", &out)] {
            for secret in ["s3cret", "pa55w0rd", &basic] {
                assert!(!text.contains(secret), "{what} holds {secret}: {text}");
            }
        }
    }

    /// The names of the commands, noun then verb: the first list parses, the
    /// second (single words and other orders) does not.
    #[test]
    fn the_commands_are_noun_then_verb() {
        let parses = |args: &[&str]| {
            let mut argv = vec!["nerve-node"];
            argv.extend(args);
            Cli::try_parse_from(argv).is_ok()
        };
        for ok in [
            &["center", "add", "nerve://x"][..],
            &["center", "rm"],
            &["center", "ls"],
            &["center", "pause"],
            &["center", "resume"],
            &["center", "grant", "settings", "write"],
            &["folder", "add", "/p", "+r"],
            &["folder", "set", "/p", "=rwx", "-w"],
            &["folder", "rm", "/p"],
            &["folder", "ls"],
            &["mode", "set", "user", "--for", "2"],
            &["rule", "add", "allow", "ls", "--wildcard"],
            &["rule", "rm", "deny", "ls"],
            &["rule", "ls", "sudo"],
            &["cap", "set", "fs", "on"],
            &["cap", "ls"],
            &["cap", "provider", "allow", "desk", "/usr/bin/desk"],
            &["cap", "provider", "rm", "desk"],
            &["cap", "provider", "ls"],
            &["proxy", "set", "http://p:1"],
            &["proxy", "rm"],
            &["proxy", "ls"],
            &["config", "get", "limits"],
            &["sudo", "on"],
            &["sudo", "off"],
            &["sudo", "status"],
            &["audit", "--denied"],
            &["panic"],
            &["unlock"],
            &["status"],
            &["run"],
        ] {
            assert!(parses(ok), "{ok:?}");
        }
        for bad in [
            &["pair", "nerve://x"][..],
            &["unpair"],
            &["centers"],
            &["caps", "fs", "on"],
            &["provider", "allow", "desk", "/usr/bin/desk"],
            &["cap", "allow", "desk", "/usr/bin/desk"],
            &["grant", "settings", "write"],
            &["allow", "ls"],
            &["deny", "ls"],
            &["mode", "user"],
            &["mode", "user", "--hours", "2"],
            &["mode", "set", "user", "--hours", "2"],
            &["folder", "add", "/p", "--rw"],
            &["folder", "add", "/p", "--execute"],
            &["folder", "add", "/p", "--ro"],
            &["folder", "remove", "/p"],
            &["proxy", "clear"],
            &["sudo", "rule", "add", "x"],
            &["rule", "add", "x"],
            &["rule", "allow", "add", "x"],
            &["rule", "deny", "rm", "x"],
            &["rule", "sudo", "ls"],
            &["rule", "add", "allow"],
            &["rule", "add", "bogus", "x"],
            &["rule", "ls", "allow", "extra"],
        ] {
            assert!(!parses(bad), "{bad:?}");
        }
    }

    /// Every command and sub-command name of the clap definition, walked
    /// here on its own so the test does not trust [`help`] to find them.
    fn all_names(cmd: &clap::Command, prefix: &str, out: &mut Vec<String>) {
        for sub in cmd.get_subcommands() {
            if sub.get_name() == "help" {
                continue;
            }
            let name = format!("{prefix}{}", sub.get_name());
            all_names(sub, &format!("{name} "), out);
            out.push(name);
        }
    }

    #[test]
    fn help_lists_every_command_with_an_explanation() {
        let mut names = Vec::new();
        all_names(&Cli::command(), "", &mut names);
        assert!(names.len() > 40, "{names:?}");
        let h = help();
        // Every command is on a card, once: the ones that do something as a
        // verb, the ones that only hold more commands in the card's `holds`.
        let mut listed: Vec<String> = h.command_names().iter().map(|n| n.to_string()).collect();
        let mut want = names.clone();
        want.sort();
        listed.sort();
        assert_eq!(listed, want);
        for s in &h.sections {
            assert!(!s.about.is_empty(), "section `{}` has no sentence", s.name);
            assert!(!s.cards.is_empty(), "section `{}` is empty", s.name);
        }
        for v in h.verbs() {
            assert!(!v.about.is_empty(), "`{}` has no explanation", v.name);
            assert!(
                v.usage.starts_with(&format!("nerve-node {}", v.name)),
                "{}",
                v.usage
            );
        }
        // Every command is placed in SECTIONS, none in the catch-all.
        let names: Vec<&str> = h.sections.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "Install and set up",
                "Pair and connect",
                "What a center may do",
                "Run and watch",
            ]
        );
        // A noun is one card with its verbs; `rule` has the three lists as
        // an argument, not as three sub-trees.
        let card = |n: &str| {
            h.sections
                .iter()
                .flat_map(|s| &s.cards)
                .find(|c| c.name == n)
                .unwrap_or_else(|| panic!("no card `{n}`"))
        };
        let rule = card("rule");
        let rule_verbs: Vec<&str> = rule.verbs.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(
            rule_verbs,
            ["rule add", "rule rm", "rule ls", "rule edit", "rule guard"]
        );
        assert_eq!(rule.holds, ["rule"]);
        assert!(
            rule.verbs[0].usage.contains("<LIST>"),
            "{}",
            rule.verbs[0].usage
        );
        assert!(
            rule.verbs[2].usage.contains("[LIST]"),
            "{}",
            rule.verbs[2].usage
        );
        // `cap provider` is a noun below `cap`, with a card of its own.
        let provider: Vec<&str> = card("cap provider")
            .verbs
            .iter()
            .map(|v| v.name.as_str())
            .collect();
        assert_eq!(
            provider,
            ["cap provider allow", "cap provider rm", "cap provider ls"]
        );
        assert_eq!(card("panic / unlock").verbs.len(), 2);
        assert_eq!(card("install / uninstall").verbs.len(), 2);
        assert_eq!(card("setup").verbs.len(), 1);
        assert_eq!(card("update").verbs.len(), 1);
        // What several verbs take alike is said once, on the card, and what
        // several cards take alike once on the page.
        let folder = card("folder");
        assert!(folder.shared_args.iter().any(|a| a.name == "<PATH>"));
        assert!(h.common.iter().any(|a| a.name == "--center <CENTER>"));
        let cards: Vec<&Card> = h.sections.iter().flat_map(|s| &s.cards).collect();
        for a in &h.common {
            assert!(cards.iter().all(|c| !c.shared_args.contains(a)));
            assert!(h.verbs().all(|v| !v.args.contains(a)));
        }
        // `config add` and `remove` take the key of a list, the other verbs
        // the key of any setting; each text is said once on the card.
        let key = card("config");
        let keys: Vec<&str> = key
            .shared_args
            .iter()
            .filter(|a| a.name == "<KEY>")
            .map(|a| a.about.as_str())
            .collect();
        assert_eq!(keys.len(), 2, "{keys:?}");
        assert!(
            keys.iter()
                .any(|k| k.contains("of a list") && k.contains(".policy.allow")),
            "{keys:?}"
        );
        assert!(keys.iter().any(|k| k.contains(".policy.mode")), "{keys:?}");
        // The rights of `folder add` are required, so the page does not call
        // them optional.
        let add = h.verbs().find(|v| v.name == "folder add").unwrap();
        assert!(
            add.args
                .iter()
                .any(|a| a.name == "<+r|+w|+x>" && !a.about.is_empty() && !a.optional),
            "{:?}",
            add.args
        );
        // What can be left out says so.
        let mode = h.verbs().find(|v| v.name == "mode set").unwrap();
        assert!(
            mode.args
                .iter()
                .any(|a| a.name == "--for <HOURS>" && a.optional)
        );
        assert!(mode.args.iter().any(|a| a.name == "<MODE>" && !a.optional));
        // The options every command takes are listed once, not per command.
        assert!(h.global.iter().any(|a| a.name.starts_with("--config-dir")));
        assert!(add.args.iter().all(|a| !a.name.starts_with("--config-dir")));
        // No usage line, and no explanation of a verb, is on the page twice.
        let mut usages: Vec<&str> = h.verbs().map(|v| v.usage.as_str()).collect();
        usages.sort();
        usages.dedup();
        assert_eq!(usages.len(), h.verbs().count());
        let mut abouts: Vec<&str> = h.verbs().map(|v| v.about.as_str()).collect();
        abouts.sort();
        let n = abouts.len();
        abouts.dedup();
        assert_eq!(abouts.len(), n, "two commands say the same");
    }

    /// The help page calls no command not done.
    #[test]
    fn no_command_is_called_not_done() {
        let text = Cli::command().render_help().to_string();
        assert!(!text.contains("not done"), "{text}");
        assert!(text.contains("install"), "{text}");
        let page = serde_json::to_string(&help()).unwrap();
        assert!(!page.to_lowercase().contains("not done"), "{page}");
    }

    #[test]
    fn every_argument_is_explained() {
        let h = help();
        let cards = h.sections.iter().flat_map(|s| &s.cards);
        for a in &h.common {
            assert!(!a.about.is_empty(), "{} has no explanation", a.name);
        }
        for c in cards.clone() {
            for a in &c.shared_args {
                assert!(
                    !a.about.is_empty(),
                    "`{}` {} has no explanation",
                    c.name,
                    a.name
                );
            }
        }
        for v in h.verbs() {
            for a in &v.args {
                assert!(
                    !a.about.is_empty(),
                    "`{}` {} has no explanation",
                    v.name,
                    a.name
                );
            }
        }
    }

    #[test]
    fn the_shim_is_not_a_command() {
        let e = Cli::try_parse_from(["nerve-node", "__exec-shim"]).unwrap_err();
        assert!(e.to_string().contains("__exec-shim"));
    }

    /// An audit line of a decision.
    fn decided(ts: u64, cap: &str, action: &str, target: &str, decision: &str) -> String {
        format!(
            "{}\n",
            serde_json::json!({"ts": ts, "center": "lab", "cap": cap, "action": action,
                "target": target, "decision": decision})
        )
    }

    /// After a rotation the older entries are in `audit.jsonl.1`; `audit`
    /// shows them before the current file's.
    #[test]
    fn audit_shows_the_rotated_file_too() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("c"), d.path().join("s"));
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        let old = paths.state_dir.join("audit.jsonl.1");
        std::fs::write(
            &old,
            decided(1, "fs", "read", "~/.ssh/id_ed25519", "allowed")
                + &decided(2, "exec", "run", "curl -d @~/notes x", "allowed"),
        )
        .unwrap();
        std::fs::write(
            paths.audit_log(),
            decided(3, "exec", "run", "ls", "forbidden"),
        )
        .unwrap();
        let out = run(&paths, &["audit"]).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3, "{out}");
        assert!(
            lines[0].contains("fs.read  ~/.ssh/id_ed25519  allowed"),
            "{out}"
        );
        assert!(lines[1].contains("curl -d @~/notes x  allowed"), "{out}");
        assert!(lines[2].contains("exec.run  ls  forbidden"), "{out}");
        let out = run(&paths, &["audit", "--denied"]).unwrap();
        assert_eq!(out.lines().count(), 1, "{out}");
        assert!(out.contains("ls  forbidden"), "{out}");
    }

    /// Output that a test reads while `audit --follow` writes it.
    #[derive(Clone, Default)]
    struct Seen(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl Write for Seen {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Seen {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }

        async fn until(&self, what: &str) {
            for _ in 0..100 {
                if self.text().contains(what) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            panic!("{what:?} was not shown: {}", self.text());
        }
    }

    /// `--follow` goes on after the line it looked at last: also when the
    /// log dropped lines before it (old refusals), when the same line came
    /// again, and by time when that line itself was dropped.
    #[test]
    fn audit_follow_goes_on_after_the_last_line_it_saw() {
        let l = |ts: u64, t: &str| {
            decided(ts, "exec", "run", t, "forbidden")
                .trim()
                .to_string()
        };
        let mut shown = Shown::default();
        let first = vec![l(1, "a"), l(2, "b"), l(3, "c"), l(3, "c")];
        assert_eq!(shown.next(&first), 0);
        shown.saw(&first);
        // `a` and `b` were dropped; one more `c` and a `d` came.
        let now = vec![l(3, "c"), l(3, "c"), l(3, "c"), l(4, "d")];
        assert_eq!(&now[shown.next(&now)..], &now[2..]);
        shown.saw(&now);
        // `d` itself was dropped: what is newer than it is new.
        let now = vec![l(3, "c"), l(5, "e")];
        assert_eq!(&now[shown.next(&now)..], &now[1..]);
        shown.saw(&now);
        assert_eq!(shown.next(&now), now.len());
    }

    /// `--follow` finishes the old file after a rotation before it reads the
    /// new one: a line written right before the rotation is shown, and each
    /// line once.
    #[tokio::test]
    async fn audit_follow_finishes_the_old_file_after_a_rotation() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("c"), d.path().join("s"));
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        let log = paths.audit_log();
        let append = |line: String| {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log)
                .unwrap();
            f.write_all(line.as_bytes()).unwrap();
        };
        append(decided(1, "fs", "read", "first", "allowed"));
        let seen = Seen::default();
        let mut out = seen.clone();
        let follow = audit(&paths, true, false, None, false, &mut out);
        let writer = async {
            seen.until("first").await;
            append(decided(2, "fs", "read", "before-the-rotation", "allowed"));
            std::fs::rename(&log, paths.state_dir.join("audit.jsonl.1")).unwrap();
            append(decided(3, "fs", "read", "after-the-rotation", "allowed"));
            seen.until("after-the-rotation").await;
            // One more look, which must show nothing twice.
            tokio::time::sleep(Duration::from_millis(1200)).await;
        };
        tokio::select! {
            r = follow => panic!("follow ended: {r:?}"),
            () = writer => {}
        }
        let text = seen.text();
        let shown: Vec<&str> = text
            .lines()
            .map(|l| l.split("fs.read  ").nth(1).unwrap_or(l))
            .collect();
        assert_eq!(
            shown,
            [
                "first  allowed",
                "before-the-rotation  allowed",
                "after-the-rotation  allowed"
            ],
            "{text}"
        );
    }

    fn json_of(paths: &NodePaths, args: &[&str]) -> Value {
        let mut a = vec!["--json"];
        a.extend_from_slice(args);
        let out = run(paths, &a).unwrap();
        assert_eq!(out.lines().count(), 1, "one JSON line: {out}");
        serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out}"))
    }

    /// The read commands print their data as JSON for the desktop app,
    /// which never reads the text meant for people.
    #[test]
    fn the_read_commands_print_json() {
        let (d, paths) = setup(&["home"]);
        let work = d.path().join("work");
        std::fs::create_dir(&work).unwrap();
        run(
            &paths,
            &["folder", "add", &work.display().to_string(), "+r", "+x"],
        )
        .unwrap();
        run(&paths, &["rule", "add", "allow", "git status"]).unwrap();
        run(&paths, &["rule", "add", "deny", "rm", "--wildcard"]).unwrap();
        run(&paths, &["cap", "set", "fs.write", "off"]).unwrap();
        run(&paths, &["mode", "set", "folder"]).unwrap();

        let v = json_of(&paths, &["status"]);
        assert_eq!(v["daemon"], "not running", "{v}");
        assert_eq!(v["locked"], false, "{v}");
        assert_eq!(v["sudo"], "off", "{v}");
        assert_eq!(v["centers"][0]["name"], "home", "{v}");
        assert_eq!(v["centers"][0]["mode"], "folder", "{v}");
        assert!(v["centers"][0]["status"].is_null(), "{v}");
        assert!(v["command_limits"]["memory_mb"].is_u64(), "{v}");

        let v = json_of(&paths, &["center", "ls"]);
        let c = &v["centers"][0];
        assert_eq!(
            (
                &c["name"],
                &c["url"],
                &c["mode"],
                &c["settings"],
                &c["paused"]
            ),
            (
                &json!("home"),
                &json!("http://127.0.0.1:1"),
                &json!("folder"),
                &json!("off"),
                &json!(false)
            ),
            "{v}"
        );

        let v = json_of(&paths, &["folder", "ls"]);
        assert_eq!(v["center"], "home");
        let f = &v["folders"][0];
        assert_eq!(
            (&f["rights"], &f["read"], &f["write"], &f["execute"]),
            (&json!("r-x"), &json!(true), &json!(false), &json!(true)),
            "{v}"
        );

        let v = json_of(&paths, &["rule", "ls"]);
        assert_eq!(v["allow"], json!(["exec.run:git status"]), "{v}");
        assert_eq!(v["deny"], json!(["exec.run:rm *"]), "{v}");
        assert_eq!(v["sudo"], json!([]), "{v}");
        let v = json_of(&paths, &["rule", "ls", "deny"]);
        assert!(v.get("allow").is_none() && v["deny"].is_array(), "{v}");

        let v = json_of(&paths, &["cap", "ls"]);
        assert_eq!(v["caps"], json!({"fs.write": "off"}), "{v}");

        let v = json_of(&paths, &["config", "get", "center.home.policy.mode"]);
        assert_eq!(
            v,
            json!({"key": "center.home.policy.mode", "value": "folder"})
        );
        let v = json_of(&paths, &["config", "get", "center.home.policy.allow"]);
        assert_eq!(v["value"], json!(["exec.run:git status"]), "{v}");

        assert_eq!(json_of(&paths, &["proxy", "ls"]), json!({"proxy": null}));
        let v = json_of(&paths, &["relay", "ls"]);
        assert!(v["listen"].is_null() && v["tunnels"].is_null(), "{v}");
        assert_eq!(v["nodes"], json!([]), "{v}");
        assert_eq!(json_of(&paths, &["sudo", "status"]), json!({"sudo": "off"}));
    }

    /// The other commands give the lines they print, so a program can show
    /// them, and say nothing else on stdout.
    #[test]
    fn a_change_with_json_gives_its_lines() {
        let (_d, paths) = setup(&["home"]);
        let v = json_of(&paths, &["mode", "set", "user"]);
        let m = v["messages"].as_array().unwrap();
        assert_eq!(m[0], "home: mode user", "{v}");
        assert!(m[1].as_str().unwrap().contains(NEXT_START), "{v}");
        // As data too, for a program that offers the restart.
        assert_eq!(v["next_start"], true, "{v}");
        assert_eq!(load(&paths).center("home").unwrap().policy.mode, Mode::User);
        // The same again changes nothing, and says no such thing.
        let v = json_of(&paths, &["mode", "set", "user"]);
        assert!(v.get("next_start").is_none(), "{v}");
        // A change prints what others chose, such as a command a center
        // sent: the same words in it are no such thing either.
        let odd = format!("echo {NEXT_START}");
        run(&paths, &["rule", "add", "deny", &odd]).unwrap();
        let v = json_of(&paths, &["rule", "add", "deny", &odd]);
        assert!(
            v["messages"][0].as_str().unwrap().contains(NEXT_START),
            "{v}"
        );
        assert!(v.get("next_start").is_none(), "{v}");
        assert!(!takes_at_next_start(v["messages"][0].as_str().unwrap()));

        // A relay token: the lines, and what the other node needs as data.
        run(&paths, &["relay", "set", "0.0.0.0:7491"]).unwrap();
        let v = json_of(&paths, &["relay", "add", "lab-pc"]);
        let t = &v["token"];
        let token = t["token"].as_str().unwrap();
        assert_eq!(t["node"], "lab-pc", "{v}");
        assert_eq!(t["pin"], json!(load(&paths).relay.pin), "{v}");
        assert!(
            t["proxy"]
                .as_str()
                .unwrap()
                .starts_with(&format!("https://lab-pc:{token}@")),
            "{v}"
        );
        let link = nerve_proto::link::RelayLink::parse(t["link"].as_str().unwrap()).unwrap();
        assert_eq!(link.token, token, "{v}");
        assert_eq!(t["address"], link.address.as_str(), "{v}");
        let v = json_of(
            &paths,
            &["relay", "token", "lab-pc", "--address", "10.0.0.2:9000"],
        );
        assert_ne!(v["token"]["token"].as_str().unwrap(), token, "{v}");
        assert_eq!(v["token"]["address"], "10.0.0.2:9000", "{v}");
        assert!(run(&paths, &["relay", "token", "lab-pc", "--address", "a b"]).is_err());
        // The relayed node takes the link whole: the relay as its proxy,
        // its login, and the pin.
        let (_d2, other) = setup(&[]);
        let out = run(
            &other,
            &["proxy", "set", v["token"]["link"].as_str().unwrap()],
        )
        .unwrap();
        assert!(out.starts_with("proxy https://10.0.0.2:9000\n"), "{out}");
        let c = load(&other).connection;
        assert_eq!(c.proxy.as_deref(), Some("https://10.0.0.2:9000"));
        assert_eq!(c.login.as_deref(), Some("lab-pc"));
        assert_eq!(c.pin, load(&paths).relay.pin);
        let e = run(
            &other,
            &[
                "proxy",
                "set",
                v["token"]["link"].as_str().unwrap(),
                "--pin",
                &"B".repeat(43),
            ],
        )
        .unwrap_err();
        assert!(e.contains("carries the pin"), "{e}");
    }

    /// Without --yes, `center add --json` shows what the owner confirms and
    /// pairs nothing: the desktop app asks, then runs it with --yes.
    #[test]
    fn center_add_json_without_yes_only_shows_the_link() {
        let (_d, paths) = setup(&[]);
        let before = std::fs::read(paths.config_file()).unwrap();
        let v = json_of(
            &paths,
            &[
                "center",
                "add",
                "nerve://pair?center=https%3A%2F%2Fc.example%3A8443&code=abc&pin=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "--name",
                "lab",
            ],
        );
        assert_eq!(v["paired"], false, "{v}");
        assert_eq!(v["preview"]["center"], "https://c.example:8443", "{v}");
        assert_eq!(v["preview"]["tls"], true, "{v}");
        assert_eq!(v["preview"]["pin"], "A".repeat(43), "{v}");
        assert_eq!(v["preview"]["name"], "lab", "{v}");
        // The check found no center there: the app offers no Pair.
        assert_eq!(v["check"]["ready"], false, "{v}");
        assert!(v["check"]["problem"].is_string(), "{v}");
        assert_eq!(std::fs::read(paths.config_file()).unwrap(), before);
        let e = run(&paths, &["--json", "center", "add", "nerve://x"]).unwrap_err();
        assert!(e.contains("nerve://pair?"), "{e}");
    }

    #[test]
    fn audit_json_gives_the_entries_as_the_log_holds_them() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("c"), d.path().join("s"));
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        std::fs::write(
            paths.audit_log(),
            decided(1, "fs", "read", "/srv/a", "allowed")
                + &decided(2, "exec", "run", "ls", "forbidden"),
        )
        .unwrap();
        let v = json_of(&paths, &["audit"]);
        let e = v["entries"].as_array().unwrap();
        assert_eq!(e.len(), 2, "{v}");
        assert_eq!(
            (&e[0]["target"], &e[1]["decision"]),
            (&json!("/srv/a"), &json!("forbidden"))
        );
        let v = json_of(&paths, &["audit", "--denied"]);
        assert_eq!(v["entries"].as_array().unwrap().len(), 1, "{v}");
        // The newest only, after --denied picked.
        let v = json_of(&paths, &["audit", "--last", "1"]);
        assert_eq!(v["entries"][0]["target"], "ls", "{v}");
        assert_eq!(v["entries"].as_array().unwrap().len(), 1, "{v}");
        std::fs::write(
            paths.audit_log(),
            decided(1, "exec", "run", "a", "forbidden")
                + &decided(2, "exec", "run", "b", "forbidden")
                + &decided(3, "fs", "read", "/c", "allowed"),
        )
        .unwrap();
        let v = json_of(&paths, &["audit", "--denied", "--last", "1"]);
        assert_eq!(v["entries"].as_array().unwrap().len(), 1, "{v}");
        assert_eq!(v["entries"][0]["target"], "b", "{v}");
        let out = run(&paths, &["audit", "--last", "2"]).unwrap();
        assert_eq!(out.lines().count(), 2, "{out}");
        assert!(out.contains("fs.read  /c"), "{out}");
    }

    /// `rule guard` puts the guard's deny rules that a pairing lacks on its
    /// deny list, keeps what is there, and says so when nothing is missing.
    #[test]
    fn rule_guard_adds_the_missing_deny_rules_of_the_guard() {
        let (_d, paths) = setup(&["home"]);
        let deny = || load(&paths).centers[0].policy.deny.clone();
        run(&paths, &["rule", "add", "deny", "rm", "--wildcard"]).unwrap();
        run(
            &paths,
            &[
                "config",
                "add",
                "center.home.policy.deny",
                nerve_policy::rules::GUARD[2],
            ],
        )
        .unwrap();
        let out = run(&paths, &["rule", "guard"]).unwrap();
        let n = nerve_policy::rules::GUARD.len() - 1;
        assert!(out.contains(&format!("added {n} deny rules")), "{out}");
        let d = deny();
        assert_eq!(d.len(), n + 2, "{d:?}");
        assert_eq!(d[0], "exec.run:rm *");
        for g in nerve_policy::rules::GUARD {
            assert_eq!(d.iter().filter(|r| r == g).count(), 1, "{g}: {d:?}");
        }
        let e = run(&paths, &["rule", "guard", "--center", "home"]).unwrap_err();
        assert!(
            e.contains("has every deny rule of the guard already"),
            "{e}"
        );
        assert_eq!(deny(), d);
        // The owner may take a rule of the guard off as it is listed, and
        // `rule guard` puts it back.
        run(&paths, &["rule", "rm", "deny", "guard:node-service"]).unwrap();
        assert!(!deny().iter().any(|r| r == "guard:node-service"));
        assert_eq!(deny().len(), d.len() - 1);
        assert_eq!(
            nerve_policy::rules::guard_missing(&deny()),
            ["guard:node-service"]
        );
        run(&paths, &["rule", "guard"]).unwrap();
        assert_eq!(deny().len(), d.len());
    }

    /// A pairing that has every rule of the guard and also a text from
    /// before has nothing to add, but `rule guard` still takes the text off.
    #[test]
    fn rule_guard_takes_an_older_text_off_when_nothing_is_missing() {
        let (_d, paths) = setup(&["home"]);
        let deny = || load(&paths).centers[0].policy.deny.clone();
        run(&paths, &["rule", "guard"]).unwrap();
        let older = nerve_policy::rules::GUARD_OLD[0];
        run(&paths, &["config", "add", "center.home.policy.deny", older]).unwrap();
        assert!(deny().iter().any(|r| r == older));
        let out = run(&paths, &["rule", "guard"]).unwrap();
        assert!(out.contains("1 of an older text replaced"), "{out}");
        assert!(!deny().iter().any(|r| r == older));
        assert!(nerve_policy::rules::guard_missing(&deny()).is_empty());
    }

    /// A rule of the guard is no command to `rule add`; the answer points at
    /// the way to put one on.
    #[test]
    fn rule_add_points_at_rule_guard_for_a_guard_rule() {
        let (_d, paths) = setup(&["home"]);
        let e = run(&paths, &["rule", "add", "deny", "guard:node-service"]).unwrap_err();
        assert!(e.contains("nerve-node rule guard"), "{e}");
        let e = run(&paths, &["rule", "add", "allow", "fs.read:~/notes/*"]).unwrap_err();
        assert!(!e.contains("nerve-node rule guard"), "{e}");
    }

    /// `rule edit` changes one entry in its place, on any list and a rule of
    /// the guard too, as one change in the audit.
    #[test]
    fn rule_edit_changes_an_entry_in_place_as_one_change() {
        let (_d, paths) = setup(&["home"]);
        let policy = || load(&paths).centers[0].policy.clone();
        let changes = || {
            nerve_policy::audit::AuditLog::new(paths.audit_log())
                .read()
                .unwrap()
                .iter()
                .filter(|e| e["kind"] == "settings")
                .count()
        };
        for (list, rule) in [
            ("allow", "git status"),
            ("allow", "cargo test"),
            ("allow", "ls"),
            ("sudo", "sudo apt update"),
        ] {
            run(&paths, &["rule", "add", list, rule]).unwrap();
        }
        let before = changes();
        // A plain command line becomes the rule `add` makes of it.
        let out = run(
            &paths,
            &[
                "rule",
                "edit",
                "allow",
                "exec.run:cargo test",
                "cargo test --workspace",
            ],
        )
        .unwrap();
        assert!(
            out.contains("\"exec.run:cargo test\" is \"exec.run:cargo test --workspace\" now"),
            "{out}"
        );
        assert_eq!(
            policy().allow,
            [
                "exec.run:git status",
                "exec.run:cargo test --workspace",
                "exec.run:ls"
            ]
        );
        assert_eq!(changes(), before + 1);
        // An entry in the form `ls` shows goes as it is; one that is on the
        // list already is not there twice.
        run(
            &paths,
            &["rule", "edit", "allow", "exec.run:ls", "fs.read:/srv/*"],
        )
        .unwrap();
        run(
            &paths,
            &[
                "rule",
                "edit",
                "allow",
                "fs.read:/srv/*",
                "exec.run:git status",
            ],
        )
        .unwrap();
        assert_eq!(
            policy().allow,
            ["exec.run:cargo test --workspace", "exec.run:git status"]
        );
        // The sudo list takes the command with or without its sudo.
        run(
            &paths,
            &["rule", "edit", "sudo", "sudo apt update", "apt upgrade"],
        )
        .unwrap();
        assert_eq!(policy().sudo_allow, ["sudo apt upgrade"]);
        // A rule of the guard is edited like any other.
        let guard = nerve_policy::rules::GUARD[0];
        run(&paths, &["config", "add", "center.home.policy.deny", guard]).unwrap();
        run(
            &paths,
            &["rule", "edit", "deny", guard, "exec.run:nerve-node *"],
        )
        .unwrap();
        assert_eq!(policy().deny, ["exec.run:nerve-node *"]);
        // What is not there, the same again, a bad pattern: refused, and
        // nothing changes.
        let now = policy();
        let n = changes();
        for (args, says) in [
            (
                &["rule", "edit", "allow", "exec.run:nope", "x"][..],
                "is not on",
            ),
            (
                &[
                    "rule",
                    "edit",
                    "deny",
                    "exec.run:nerve-node *",
                    "exec.run:nerve-node *",
                ],
                "that already",
            ),
            (
                &[
                    "rule",
                    "edit",
                    "deny",
                    "exec.run:nerve-node *",
                    "fs.read:[z-a]",
                ],
                "fs.read:[z-a]",
            ),
            (
                &["rule", "edit", "deny", "exec.run:nerve-node *", " "],
                "empty",
            ),
        ] {
            let e = run(&paths, args).unwrap_err();
            assert!(e.contains(says), "{args:?}: {e}");
        }
        assert_eq!(policy(), now);
        assert_eq!(changes(), n);
    }

    /// An older text of the guard holds a line break; `rule ls` writes it
    /// `\n` so a listing keeps a line a rule, and `rule rm` and `rule edit`
    /// take the entry as `ls` printed it.
    #[test]
    fn rule_ls_writes_line_breaks_out_and_rm_and_edit_take_them_back() {
        let (_d, paths) = setup(&["home"]);
        let deny = || load(&paths).centers[0].policy.deny.clone();
        let guard = &nerve_policy::rules::GUARD_OLD[..18];
        assert!(guard.iter().any(|g| g.contains('\n')));
        for old in guard {
            run(&paths, &["config", "add", "center.home.policy.deny", old]).unwrap();
        }
        let ls = run(&paths, &["rule", "ls", "deny"]).unwrap();
        assert_eq!(ls.lines().count(), deny().len(), "{ls}");
        for (line, rule) in ls.lines().zip(deny()) {
            assert_eq!(line, nerve_policy::rules::escape_controls(&rule));
            assert!(!line.contains(['\t', '\r']), "{line:?}");
        }
        assert!(ls.contains("\\r\\n"), "{ls}");
        let all = run(&paths, &["rule", "ls"]).unwrap();
        assert_eq!(all.lines().count(), deny().len(), "{all}");
        assert!(all.lines().all(|l| l.starts_with("deny  ")), "{all}");
        // The entry as `ls` printed it is removed; the raw one too.
        let shown = nerve_policy::rules::escape_controls(guard[9]);
        assert_ne!(shown, guard[9]);
        let out = run(&paths, &["rule", "rm", "deny", &shown]).unwrap();
        assert!(out.contains("removed"), "{out}");
        assert!(!deny().iter().any(|r| r == guard[9]));
        run(&paths, &["rule", "rm", "deny", guard[10]]).unwrap();
        assert!(!deny().iter().any(|r| r == guard[10]));
        // Edit: the entry and the new one both as `ls` prints them.
        let shown = nerve_policy::rules::escape_controls(guard[11]);
        let new = "exec.run:systemctl stop nerve-node\\n*";
        let out = run(&paths, &["rule", "edit", "deny", &shown, new]).unwrap();
        assert!(out.contains("now"), "{out}");
        assert!(!deny().iter().any(|r| r == guard[11]));
        assert!(
            deny()
                .iter()
                .any(|r| r == "exec.run:systemctl stop nerve-node\n*"),
            "{:?}",
            deny()
        );
        // A Windows path rule has backslashes before t, r and n: a rule as
        // it stands, added, listed, edited and removed on every OS.
        let paths_rules = [
            "exec.run:type C:\\tools\\x.exe",
            "exec.run:*C:\\Users\\nina\\repos\\*",
            "exec.run:\"C:\\Program Files\\nodejs\\node.exe\" --version",
        ];
        for own in paths_rules {
            run(&paths, &["config", "add", "center.home.policy.deny", own]).unwrap();
            let ls = run(&paths, &["rule", "ls", "deny"]).unwrap();
            assert!(ls.lines().any(|l| l == own), "{ls}");
        }
        run(
            &paths,
            &[
                "rule",
                "edit",
                "deny",
                paths_rules[0],
                "exec.run:type C:\\temp\\x.exe",
            ],
        )
        .unwrap();
        assert!(deny().iter().any(|r| r == "exec.run:type C:\\temp\\x.exe"));
        for own in &paths_rules[1..] {
            run(&paths, &["rule", "rm", "deny", own]).unwrap();
            assert!(!deny().iter().any(|r| r == own));
        }
        run(
            &paths,
            &["rule", "rm", "deny", "exec.run:type C:\\temp\\x.exe"],
        )
        .unwrap();
        // The listed text of a rule with a line break is not a rule: pasted
        // so, its `\n` would be the letter. Refused for a guard rule and for
        // an entry of the list, by `config add` and `rule edit`; nothing
        // changes.
        run(
            &paths,
            &["config", "add", "center.home.policy.deny", "exec.run:a\nb*"],
        )
        .unwrap();
        let before = deny();
        for listed in [
            nerve_policy::rules::escape_controls(guard[12]),
            nerve_policy::rules::escape_controls(guard[13]),
            "exec.run:a\\nb*".to_string(),
        ] {
            let e = run(
                &paths,
                &["config", "add", "center.home.policy.deny", &listed],
            )
            .unwrap_err();
            assert!(e.contains("how `rule ls` writes a rule"), "{e}");
            let e = run(&paths, &["rule", "edit", "deny", "exec.run:a\nb*", &listed]).unwrap_err();
            assert!(e.contains("how `rule ls` writes a rule"), "{e}");
        }
        assert_eq!(deny(), before);
        // Not there: refused, nothing changes.
        let now = deny();
        let e = run(&paths, &["rule", "rm", "deny", "exec.run:nope\\n"]).unwrap_err();
        assert!(e.contains("is not on"), "{e}");
        assert_eq!(deny(), now);
    }

    /// `rule guard` takes the guard's older texts off when it puts the new
    /// ones on.
    #[test]
    fn rule_guard_replaces_the_older_texts() {
        let (_d, paths) = setup(&["home"]);
        let deny = || load(&paths).centers[0].policy.deny.clone();
        for old in nerve_policy::rules::GUARD_OLD {
            run(&paths, &["config", "add", "center.home.policy.deny", old]).unwrap();
        }
        let out = run(&paths, &["rule", "guard"]).unwrap();
        assert!(out.contains("of an older text replaced"), "{out}");
        let d = deny();
        for old in nerve_policy::rules::GUARD_OLD {
            assert!(!d.iter().any(|r| r == old), "{old}");
        }
        for g in nerve_policy::rules::GUARD {
            assert_eq!(d.iter().filter(|r| r == g).count(), 1, "{g}");
        }
    }

    /// `rule add --action` makes the rule an audit button makes for an entry
    /// of that action, and `rule rm` takes the same arguments.
    #[test]
    fn rule_add_with_an_action_makes_the_audit_buttons_rule() {
        let (_d, paths) = setup(&["home"]);
        let policy = || load(&paths).centers[0].policy.clone();
        run(
            &paths,
            &[
                "rule",
                "add",
                "allow",
                "/srv/data/a.txt",
                "--action",
                "fs.read",
            ],
        )
        .unwrap();
        run(
            &paths,
            &[
                "rule",
                "add",
                "deny",
                "/srv/data/a.txt",
                "--action",
                "fs.write",
                "--wildcard",
            ],
        )
        .unwrap();
        run(
            &paths,
            &[
                "rule",
                "add",
                "allow",
                "",
                "--action",
                "settings.read",
                "--wildcard",
            ],
        )
        .unwrap();
        run(
            &paths,
            &[
                "rule",
                "add",
                "deny",
                "make all",
                "--action",
                "exec.run",
                "--wildcard",
            ],
        )
        .unwrap();
        run(
            &paths,
            &[
                "rule",
                "add",
                "sudo",
                "sudo apt update",
                "--action",
                "exec.run",
                "--wildcard",
            ],
        )
        .unwrap();
        assert_eq!(policy().allow, ["fs.read:/srv/data/a.txt", "settings"]);
        assert_eq!(policy().deny, ["fs.write:/srv/data/*", "exec.run:make *"]);
        assert_eq!(policy().sudo_allow, ["sudo apt *"]);
        // The same as the center's buttons for the same entries.
        for (list, cap, action, target, wildcard) in [
            ("allow", "fs", "read", "/srv/data/a.txt", false),
            ("deny", "fs", "write", "/srv/data/a.txt", true),
            ("deny", "exec", "run", "make all", true),
        ] {
            let rule = rules::rule_for(cap, action, target, wildcard).unwrap();
            let l = if list == "allow" {
                policy().allow
            } else {
                policy().deny
            };
            assert!(l.contains(&rule), "{rule}");
        }
        run(
            &paths,
            &[
                "rule",
                "rm",
                "deny",
                "/srv/data/a.txt",
                "--action",
                "fs.write",
                "--wildcard",
            ],
        )
        .unwrap();
        assert_eq!(policy().deny, ["exec.run:make *"]);

        let e = run(
            &paths,
            &["rule", "add", "sudo", "/etc/x", "--action", "fs.read"],
        )
        .unwrap_err();
        assert!(e.contains("sudo commands"), "{e}");
        let e = run(
            &paths,
            &[
                "rule",
                "add",
                "allow",
                "sudo apt update",
                "--action",
                "exec.run",
            ],
        )
        .unwrap_err();
        assert!(e.contains("sudo list"), "{e}");
        let e = run(&paths, &["rule", "add", "allow", "x", "--action", "read"]).unwrap_err();
        assert!(e.contains("capability and action"), "{e}");
        let cut = format!(
            "{}… [cut at {n} of {} characters]",
            "a".repeat(nerve_policy::audit::TARGET_MAX_CHARS),
            nerve_policy::audit::TARGET_MAX_CHARS + 5,
            n = nerve_policy::audit::TARGET_MAX_CHARS
        );
        let e = run(
            &paths,
            &["rule", "add", "deny", &cut, "--action", "exec.run"],
        )
        .unwrap_err();
        assert!(e.contains("cut"), "{e}");
    }

    fn logged(ts: u64, level: &str, msg: &str) -> String {
        format!("{}\n", json!({"ts": ts, "level": level, "msg": msg}))
    }

    #[test]
    fn log_shows_the_moved_file_first_and_the_newest_with_last() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("c"), d.path().join("s"));
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        std::fs::write(
            paths.state_dir.join("log.jsonl.1"),
            logged(1, "info", "node started"),
        )
        .unwrap();
        std::fs::write(
            paths.log_file(),
            logged(2, "warn", "link dropped") + &logged(3, "error", "cannot connect"),
        )
        .unwrap();
        let out = run(&paths, &["log"]).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines,
            [
                "1  info  node started",
                "2  warn  link dropped",
                "3  error  cannot connect"
            ]
        );
        let v = json_of(&paths, &["log", "--last", "2"]);
        assert_eq!(v["entries"][0]["msg"], "link dropped", "{v}");
        assert_eq!(v["entries"].as_array().unwrap().len(), 2, "{v}");
        // The problems only, the newest first counted: the warning that
        // came before more lines than --last is still found.
        std::fs::write(
            paths.log_file(),
            logged(2, "warn", "link dropped")
                + &logged(3, "info", "linked")
                + &logged(4, "info", "linked again"),
        )
        .unwrap();
        let v = json_of(&paths, &["log", "--problems", "--last", "1"]);
        assert_eq!(v["entries"].as_array().unwrap().len(), 1, "{v}");
        assert_eq!(v["entries"][0]["msg"], "link dropped", "{v}");
        let out = run(&paths, &["log", "--problems"]).unwrap();
        assert_eq!(out, "2  warn  link dropped\n");
        // No log yet is no error.
        let empty = NodePaths::new(d.path().join("c2"), d.path().join("s2"));
        assert_eq!(json_of(&empty, &["log"]), json!({"entries": []}));
    }

    /// `log clear` empties the log and its older file and says who did it;
    /// `audit clear` keeps the entries so far as the older file, and the
    /// audit shows only the entry of the clearing then. Neither takes
    /// arguments of the reading form.
    #[test]
    fn log_and_audit_clear_start_afresh_and_say_who() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("c"), d.path().join("s"));
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        // No log yet: nothing to clear, and no error.
        run(&paths, &["log", "clear"]).unwrap();
        assert!(!paths.log_file().exists());
        std::fs::write(
            paths.state_dir.join("log.jsonl.1"),
            logged(1, "info", "node started"),
        )
        .unwrap();
        std::fs::write(paths.log_file(), logged(2, "warn", "link dropped")).unwrap();
        let out = run(&paths, &["log", "clear"]).unwrap();
        assert_eq!(out, "log cleared\n");
        assert!(!paths.state_dir.join("log.jsonl.1").exists());
        let v = json_of(&paths, &["log"]);
        let entries = v["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1, "{v}");
        let who = changed_by();
        assert_eq!(
            entries[0]["msg"],
            format!("the log was cleared by {who}"),
            "{v}"
        );

        let log = AuditLog::new(paths.audit_log());
        log.settings("local", 1, &[]).unwrap();
        log.settings("local", 2, &[]).unwrap();
        let before = std::fs::read(paths.audit_log()).unwrap();
        let v = json_of(&paths, &["audit", "clear"]);
        assert!(
            v["messages"][0]
                .as_str()
                .unwrap()
                .starts_with("audit cleared; the entries so far are kept in "),
            "{v}"
        );
        assert_eq!(std::fs::read(log.old_path()).unwrap(), before);
        let v = json_of(&paths, &["audit"]);
        let entries = v["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1, "{v}");
        assert_eq!(entries[0]["event"], "cleared");
        assert_eq!(entries[0]["user"], who.as_str());
        let out = run(&paths, &["audit"]).unwrap();
        assert!(out.ends_with(&format!("audit cleared by {who}\n")), "{out}");
        for args in [
            &["audit", "clear", "--last", "2"][..],
            &["log", "--follow", "clear"],
        ] {
            assert!(run(&paths, args).is_err(), "{args:?}");
        }
    }

    /// `log --follow` goes on with the new file once the old one is moved
    /// aside, the lines written to the old one before that included.
    #[tokio::test]
    async fn log_follow_goes_on_after_the_file_is_moved_aside() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("c"), d.path().join("s"));
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        let file = paths.log_file();
        let append = |line: String| {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&file)
                .unwrap();
            f.write_all(line.as_bytes()).unwrap();
        };
        append(logged(1, "info", "first"));
        let seen = Seen::default();
        let mut out = seen.clone();
        let follow = log_cmd(&paths, true, Some(5), false, true, &mut out);
        let writer = async {
            seen.until("first").await;
            append(logged(2, "info", "before-the-move"));
            std::fs::rename(&file, paths.state_dir.join("log.jsonl.1")).unwrap();
            append(logged(3, "info", "after-the-move"));
            seen.until("after-the-move").await;
            tokio::time::sleep(Duration::from_millis(1200)).await;
        };
        tokio::select! {
            r = follow => panic!("follow ended: {r:?}"),
            () = writer => {}
        }
        let text = seen.text();
        let msgs: Vec<String> = text
            .lines()
            .map(|l| {
                serde_json::from_str::<Value>(l).unwrap()["msg"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(
            msgs,
            ["first", "before-the-move", "after-the-move"],
            "{text}"
        );
    }

    /// A line half written when `log --follow` starts is shown once it is
    /// whole, not lost.
    #[tokio::test]
    async fn log_follow_waits_for_a_line_half_written_at_its_start() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("c"), d.path().join("s"));
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        let file = paths.log_file();
        let append = |text: &str| {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&file)
                .unwrap();
            f.write_all(text.as_bytes()).unwrap();
        };
        let half = logged(2, "info", "half-written");
        let (start, end) = half.split_at(half.len() / 2);
        append(&logged(1, "info", "first"));
        append(start);
        let seen = Seen::default();
        let mut out = seen.clone();
        let follow = log_cmd(&paths, true, None, false, true, &mut out);
        let writer = async {
            seen.until("first").await;
            append(end);
            seen.until("half-written").await;
        };
        tokio::select! {
            r = follow => panic!("follow ended: {r:?}"),
            () = writer => {}
            () = tokio::time::sleep(Duration::from_secs(5)) => {
                panic!("the line written in two halves never came: {}", seen.text())
            }
        }
    }

    /// A full path of a program on this platform, from `/`-separated parts.
    fn program_path(parts: &str) -> String {
        if cfg!(windows) {
            format!("C:\\{}", parts.replace('/', "\\"))
        } else {
            format!("/{parts}")
        }
    }

    /// `cap ls` lists every action of the node's own capabilities with its
    /// effect, where it comes from and each center's setting (`--center`:
    /// that one's), a setting for what nothing offers now, and the programs
    /// allowed; a stopped node knows no program's capabilities and says so.
    #[test]
    fn cap_ls_lists_every_capability_with_its_effect_and_settings() {
        let (_d, paths) = setup(&["home", "lab"]);
        let desk = program_path("usr/bin/desk");
        run(
            &paths,
            &["cap", "set", "fs.write", "off", "--center", "home"],
        )
        .unwrap();
        run(&paths, &["cap", "set", "lamp", "on", "--center", "lab"]).unwrap();
        run(&paths, &["cap", "provider", "allow", "desk", &desk]).unwrap();
        let ls = run(&paths, &["cap", "ls"]).unwrap();
        let line = |name: &str| {
            ls.lines()
                .find(|l| l.split_whitespace().next() == Some(name))
                .unwrap_or_else(|| panic!("no {name}: {ls}"))
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        assert_eq!(
            line("fs.write"),
            "fs.write write built-in home: off, lab: default"
        );
        assert_eq!(
            line("exec.run"),
            "exec.run execute built-in home: default, lab: default"
        );
        assert!(ls.contains("lab: lamp on (offered by nothing now)"), "{ls}");
        assert!(ls.contains("the node does not run"), "{ls}");
        assert!(
            ls.contains(&format!("program desk: {desk}, the node does not run")),
            "{ls}"
        );
        let one = run(&paths, &["cap", "ls", "--center", "lab"]).unwrap();
        assert!(!one.contains("home:"), "{one}");
        assert!(one.contains("fs.write"), "{one}");
        assert!(run(&paths, &["cap", "ls", "--center", "nope"]).is_err());

        let v = json_of(&paths, &["cap", "ls"]);
        let write = v["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == "fs.write")
            .unwrap();
        assert_eq!(write["effect"], "write", "{v}");
        assert_eq!(write["source"], "built-in", "{v}");
        assert_eq!(write["centers"], json!({"home": "off", "lab": "default"}));
        assert_eq!(v["running"], false, "{v}");
        assert_eq!(
            v["programs"],
            json!([{"name": "desk", "exe": desk, "attached": null}])
        );
        // Two centers and none picked: no one center's switches.
        assert!(v.get("known").is_none(), "{v}");
        let v = json_of(&paths, &["cap", "ls", "--center", "lab"]);
        assert_eq!(v["center"], "lab");
        assert_eq!(v["caps"], json!({"lamp": "on"}));
    }

    /// `cap ls` of a running node asks it, on Windows over its pipe: it
    /// does not say the node does not run, and tells each center's state
    /// now.
    #[test]
    fn cap_ls_asks_the_running_node() {
        let (d, paths) = setup(&["home"]);
        let desk = program_path("usr/bin/desk");
        run(&paths, &["cap", "provider", "allow", "desk", &desk]).unwrap();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let mut opts = NodeOptions::new(paths.clone());
        opts.home = d.path().to_path_buf();
        let daemon = rt.block_on(Daemon::start(opts)).unwrap();
        let ls = run(&paths, &["cap", "ls"]).unwrap();
        assert!(!ls.contains("does not run"), "{ls}");
        assert!(
            ls.contains(&format!("program desk: {desk}, not attached")),
            "{ls}"
        );
        let v = json_of(&paths, &["cap", "ls"]);
        assert_eq!(v["running"], true, "{v}");
        let read = v["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == "fs.read")
            .unwrap();
        assert!(read["now"]["home"].is_string(), "{v}");
        rt.block_on(daemon.stop());
    }

    /// `cap provider allow` names a program, again to replace it, `rm`
    /// takes it off, and `ls` shows them; a bad name or a relative path is
    /// refused.
    #[test]
    fn cap_provider_allows_lists_and_removes_programs() {
        let (_d, paths) = setup(&["home"]);
        let (a, b, lamp) = (
            program_path("usr/bin/a"),
            program_path("usr/bin/b"),
            program_path("opt/lamp"),
        );
        let said = run(&paths, &["cap", "provider", "allow", "desk", &a]).unwrap();
        // A stopped node takes it at its next start, and is told so.
        assert!(
            said.starts_with(&format!("provider desk allowed: {a}\n")),
            "{said}"
        );
        run(&paths, &["cap", "provider", "allow", "desk", &b]).unwrap();
        run(&paths, &["cap", "provider", "allow", "lamp-2", &lamp]).unwrap();
        let cfg =
            NodeConfig::parse(&std::fs::read_to_string(paths.config_file()).unwrap()).unwrap();
        let allowed: Vec<(&str, &str)> = cfg
            .providers
            .allowed
            .iter()
            .map(|p| (p.name.as_str(), p.exe.as_str()))
            .collect();
        assert_eq!(allowed, [("desk", b.as_str()), ("lamp-2", lamp.as_str())]);
        assert_eq!(
            run(&paths, &["cap", "provider", "ls"]).unwrap(),
            format!(
                "program desk: {b}, the node does not run\nprogram lamp-2: {lamp}, the node does \
                 not run\n"
            )
        );
        let v = json_of(&paths, &["cap", "provider", "ls"]);
        assert_eq!(v["programs"][1]["name"], "lamp-2", "{v}");
        assert_eq!(v["running"], false, "{v}");
        for (bad, why) in [
            (
                &["cap", "provider", "allow", "Desk", &a][..],
                "cannot name a provider",
            ),
            (
                &["cap", "provider", "allow", "node", &a],
                "cannot name a provider",
            ),
            (
                &["cap", "provider", "allow", "desk", "bin/a"],
                "by its full path",
            ),
            (&["cap", "provider", "rm", "nope"], "no provider nope"),
        ] {
            let e = run(&paths, bad).unwrap_err();
            assert!(e.contains(why), "{bad:?}: {e}");
        }
        let said = run(&paths, &["cap", "provider", "rm", "desk"]).unwrap();
        assert!(said.starts_with("provider desk removed\n"), "{said}");
        let v = json_of(&paths, &["cap", "provider", "ls"]);
        assert_eq!(v["programs"].as_array().unwrap().len(), 1, "{v}");
        run(&paths, &["cap", "provider", "rm", "lamp-2"]).unwrap();
        assert_eq!(
            run(&paths, &["cap", "provider", "ls"]).unwrap(),
            "no program is allowed as a provider\n"
        );
    }

    /// `cap ls --json` names what `cap set` switches, so the app need not.
    #[test]
    fn cap_ls_json_names_the_switchable_capabilities() {
        let (_d, paths) = setup(&["home"]);
        run(&paths, &["cap", "set", "exec", "off"]).unwrap();
        let v = json_of(&paths, &["cap", "ls"]);
        let known = &v["known"];
        assert!(
            known["fs"].as_array().unwrap().contains(&json!("read")),
            "{v}"
        );
        assert!(
            known["exec"].as_array().unwrap().contains(&json!("run")),
            "{v}"
        );
        assert!(
            known.get("settings").is_none() && known.get("node").is_none(),
            "{v}"
        );
        assert_eq!(v["caps"], json!({"exec": "off"}));
    }
}
