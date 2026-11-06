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
use nerve_policy::config::{CapSetting, Folder, SecretStorage, SettingsGrant};
use nerve_policy::{Mode, NodeConfig, SetError, SettingsStore, rules, sudo_command};
use nerve_proto::link::PairLink;

use crate::daemon::{Daemon, NodeOptions};
use crate::folder_change::{Applied, FolderChange};
use crate::paths::NodePaths;
use crate::service::{Host, Layout};

mod backup;
mod cap;
mod center;
mod config;
mod folder;
mod help;
mod install;
mod json;
mod log;
mod mode;
mod network;
mod provider;
mod proxy;
mod relay;
mod rule;
mod setup;
mod status;
mod sudo;
pub mod ui;

use cap::{added_by_other, cap_listing};
#[cfg(unix)]
use cap::{dropped_note, held_note, shadowed_note, with_own_note};
use center::tell_pairings_apart;
pub(crate) use center::{given_link, pairings_warning_here};
use config::setting;
pub use config::{NO_ACCOUNT_TO_CHOOSE, moves_keys_to_keyring};
use folder::{add_folder, grant_lines};
pub use help::{
    ArgHelp, Card, Help, Section, TOP_TEMPLATE, Verb, doc_of, everyday, guide_url, help,
    help_pages, top_help,
};
pub(crate) use install::service_status;
pub use install::{BY_HAND, service_log};
// For crate::service's tests.
#[cfg(all(test, unix))]
pub(crate) use install::terminal_input;
use log::{audit, log_cmd};
pub(crate) use mode::mode_data;
use mode::{set_mode, then_text};
use network::{NO_NETWORK_LINE, apart_by_hand_here, network_mode_note, set_network};
use provider::program_lines;
use proxy::keys_place;
pub use proxy::{proxy_password, proxy_wants_password};
use relay::RELAY_AT_NEXT_START;
pub use relay::link_address;
use rule::stale_rules;
pub use rule::wildcard_target;
pub use setup::setup;
#[cfg(unix)]
use setup::setup_after_install;
use setup::{keyring_of, offer_keyring};
use status::live_status;
#[cfg(unix)]
use sudo::read_password;
use sudo::sudo_is_on;

pub use ui::{UiCmd, UiTokenCmd};

#[derive(Debug, Parser)]
#[command(
    name = "nerve-node",
    version,
    about = "Links this machine to its Nerve centers."
)]
pub struct Cli {
    /// Where node.toml and the keys live
    ///
    /// Where node.toml and the keys live [env: NERVE_NODE_CONFIG_DIR] [default: ~/.config/nerve, or /etc/nerve when installed as a service]
    #[arg(long, global = true, hide = true)]
    pub config_dir: Option<PathBuf>,
    /// Where the control socket and the audit log live
    ///
    /// Where the control socket and the audit log live [env: NERVE_NODE_STATE_DIR] [default: ~/.local/state/nerve, or /var/lib/nerve/state when installed as a service]
    #[arg(long, global = true, hide = true)]
    pub state_dir: Option<PathBuf>,
    /// Print JSON instead of text
    ///
    /// Print JSON for programs instead of text: the read commands their data, the others the lines they print, an error {"error": ...}
    #[arg(long, global = true, hide = true)]
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

/// The center a `center` verb is about, as its argument: `center rm lab`.
#[derive(Debug, Args, Clone, Default)]
pub struct CenterName {
    /// The center's name; needed when more than one is paired.
    #[arg(value_name = "NAME")]
    pub name: Option<String>,
}

impl CenterName {
    pub fn arg(&self) -> CenterArg {
        CenterArg {
            center: self.name.clone(),
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Install the node as a service (Linux: with sudo; Windows: as administrator)
    ///
    /// Install the node as a service that starts with the machine and runs under a user of its own, make the account nerve-run for its commands and take you as the owner (Linux with sudo from your own account, Windows as administrator).
    Install {
        /// Who owns the node: you (default), `root` (needs --accept-root-owner) or `none`
        ///
        /// Run by root itself (Linux): `root` makes root the owner, so that user mode, and allowlist mode as the owner, run commands as root, with every right on the machine and over Nerve; needs --accept-root-owner. At a terminal install asks instead, and an owner root confirmed before stays. `none` leaves the node without an owner, root or another.
        #[arg(long, value_name = "ACCOUNT", value_parser = ["root", "none"])]
        owner: Option<String>,
        /// Confirms --owner=root: nothing in Nerve holds those commands back
        ///
        /// Confirms --owner=root: you accept that nothing in Nerve holds those commands back.
        #[arg(long)]
        accept_root_owner: bool,
    },
    /// Pair a first center and give it a folder, step by step
    ///
    /// Pair a first center and give it a folder, step by step: the link, the mode, a folder and its rights, the network.
    Setup,
    /// Update to the latest release; config, keys and audit stay
    ///
    /// Replace the installed program with the latest release and restart the service; config, keys and audit log stay.
    Update {
        /// Take the new program from this file instead of downloading the latest release.
        #[arg(long, value_name = "FILE")]
        from: Option<PathBuf>,
    },
    /// Remove the service and the program; config and state stay
    ///
    /// Stop and remove the service, nerve-run and its entries on your folders, the node's user and the program; the config and state folders stay.
    Uninstall {
        /// Delete the config and state folders too (keys, pairings, audit)
        ///
        /// Delete the config and state folders too: the keys, the pairings and the audit log.
        #[arg(long)]
        purge: bool,
    },
    /// Save the config and keys to a passphrase-protected file
    ///
    /// Write the config and the keys to a file that a passphrase protects, to keep or to move the node to another machine.
    Backup {
        /// The file to write. It is private to you (mode 0600).
        file: PathBuf,
        /// Also take the keys that are in the system keyring into the file
        ///
        /// Also take the keys that are in the system keyring into the file; without it they stay there and are left out.
        #[arg(long)]
        include_keyring: bool,
        /// Replace the file when it exists.
        #[arg(long)]
        overwrite: bool,
        /// Read the passphrase from this file (`-`: from stdin) instead of asking
        ///
        /// Read the passphrase from the first line of this file instead of asking; `-` reads it from stdin.
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<PathBuf>,
    },
    /// Restore a backup (stop the node first)
    ///
    /// Put the config and keys of a backup in place of this node's. The node must not run.
    Restore {
        /// The backup file.
        file: PathBuf,
        /// Replace a node here that is not the one the backup is of.
        #[arg(long)]
        replace: bool,
        /// Keep the keys in `file` or in the `keyring` here, whatever the backup says
        ///
        /// Keep the keys in `file` or in the system `keyring` here, whatever the backup's config says.
        #[arg(long, value_name = "file|keyring")]
        secret_storage: Option<String>,
        /// Leave the proxy, with its secrets, out of the restored config
        ///
        /// Leave the proxy out of the restored config, with its password and header values; set it again on this machine.
        #[arg(long)]
        without_proxy: bool,
        /// Read the passphrase from this file (`-`: from stdin) instead of asking
        ///
        /// Read the passphrase from the first line of this file instead of asking; `-` reads it from stdin.
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<PathBuf>,
    },
    /// Start, stop or restart the installed service (`status` shows its state)
    #[command(subcommand)]
    Service(ServiceCmd),
    /// Print the files of the service this program installs, as JSON (for `update`)
    ///
    /// Print the files of the service this program installs besides itself, as JSON: `update` of the installed program runs the new one so, to put them in place with it.
    #[command(hide = true)]
    ServiceFiles {
        /// The owner the unit names.
        #[arg(long, value_name = "ACCOUNT")]
        owner: Option<String>,
        /// What polkit takes here: rules, a .pkla file (polkit 0.105), or none.
        #[arg(long, default_value = "rules", value_parser = ["rules", "pkla", "none"])]
        polkit: String,
    },
    /// Show the paired centers, pair another, and set what each may change
    ///
    /// Show the paired centers, pair this machine with another, and decide what each one may change.
    #[command(args_conflicts_with_subcommands = true)]
    Center {
        #[command(subcommand)]
        cmd: Option<CenterCmd>,
    },
    /// Choose how much a center may do: folder, allowlist or user mode (as you)
    ///
    /// Show each center's mode, or choose how much a center may do: only what allow rules name, what each folder allows (as nerve-run, an account of its own), or all you can do (as you).
    Mode {
        /// `folder` (default; reads what all accounts may), `allowlist`, `user` (as you)
        ///
        /// `allowlist` (only what an allow rule names, as nerve-run), `folder` (what each folder's rights allow, as nerve-run, the default; on the installed node a file call may also read what every account may read) or `user` (anything you could do yourself, as you, protected files aside). Without it, each center's mode is shown.
        #[arg(value_name = "MODE")]
        mode: Option<String>,
        /// End the mode after this many hours (user: back to the mode before)
        ///
        /// End the mode after this many hours: user goes back to the mode before it, folder to allowlist (without it they stay until you change them).
        #[arg(long = "for", value_name = "HOURS")]
        for_hours: Option<u64>,
        /// With allowlist: run the allowed commands as you, outside the sandbox
        ///
        /// With allowlist: run the allowed commands as you instead of as nerve-run, outside the folders' sandbox (installed node, Linux).
        #[arg(long)]
        as_owner: bool,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Show a center's folders, or choose them and their rights
    ///
    /// Show a center's folders, or choose the folders it may use and what it may do in each.
    #[command(args_conflicts_with_subcommands = true)]
    Folder {
        #[command(subcommand)]
        cmd: Option<FolderCmd>,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Keep a center's commands off the network (`off`); in user mode nothing runs
    ///
    /// Keep a center's commands off the network, or let them on it again: `off` lets them open no socket but a unix one, in every mode, and no sudo-list command runs; where they run as you (user mode, allowlist --as-owner) or the machine cannot hold them, none of them runs.
    Network {
        /// `off` or `on`; without it, each center's network is shown.
        #[arg(value_parser = ["on", "off"])]
        state: Option<String>,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Show a center's rules, or keep its lists of allowed and forbidden commands
    ///
    /// Show a center's rules, or keep its lists of commands that are allowed, forbidden or run with sudo.
    #[command(args_conflicts_with_subcommands = true)]
    Rule {
        #[command(subcommand)]
        cmd: Option<RuleCmd>,
        /// The list to show: `allow`, `deny` or `sudo`; all three if left out.
        list: Option<List>,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Show whether sudo is on, or use sudo for the commands on the sudo list.
    #[command(args_conflicts_with_subcommands = true)]
    Sudo {
        #[command(subcommand)]
        cmd: Option<SudoCmd>,
    },
    /// Show how the node is: its service, each center, and what to do next.
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
        refused: bool,
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
    /// Turn capabilities on or off, and add your own
    ///
    /// Show every capability, turn capabilities and single actions on or off, and declare capabilities of your own in node.toml.
    #[command(args_conflicts_with_subcommands = true)]
    Cap {
        #[command(subcommand)]
        cmd: Option<CapCmd>,
        /// Only this center's settings.
        #[arg(long)]
        center: Option<String>,
    },
    /// Show the programs that may add capabilities (providers), allow one, or remove it.
    #[command(args_conflicts_with_subcommands = true)]
    Provider {
        #[command(subcommand)]
        cmd: Option<ProviderCmd>,
    },
    /// Show or choose the proxy the node uses to reach centers.
    #[command(args_conflicts_with_subcommands = true)]
    Proxy {
        #[command(subcommand)]
        cmd: Option<ProxyCmd>,
    },
    /// Let other nodes reach your centers through this node
    ///
    /// Let nodes that cannot reach a center themselves reach this node's centers through it.
    #[command(args_conflicts_with_subcommands = true)]
    Relay {
        #[command(subcommand)]
        cmd: Option<RelayCmd>,
    },
    /// Turn the node's web UI on or off, and manage its tokens
    ///
    /// Turn the node's web UI on or off, and make the tokens that log in to it (the installed node on Linux; off unless turned on).
    #[command(args_conflicts_with_subcommands = true)]
    Ui {
        #[command(subcommand)]
        cmd: Option<UiCmd>,
    },
    /// Read or change any setting in node.toml by its name.
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Run the node in the foreground.
    Run,
}

#[derive(Debug, Subcommand)]
pub enum CenterCmd {
    /// Pair this machine with a center, using the pairing link it showed.
    Add {
        /// The pairing link; `-` reads it from stdin (never in the process list)
        ///
        /// The pairing link; `-` reads it from the first line of stdin, where it never shows in the process list.
        link: String,
        /// The name to use for the center here (the center's own name if left out).
        #[arg(long)]
        name: Option<String>,
        /// Do not ask before pairing.
        #[arg(long)]
        yes: bool,
    },
    /// Forget a center and delete its key.
    Rm(CenterName),
    /// Stop the link to a center until you resume it.
    Pause(CenterName),
    /// Link to a paused center again.
    Resume(CenterName),
    /// Give this machine a new key for a center (the node must run)
    ///
    /// Give this machine a new key for a center; the center takes the old one for 7 more days. Needs the running node, linked to that center.
    RotateKey {
        #[command(flatten)]
        center: CenterName,
        /// End the 7 days now: the center takes only the new key from then on.
        #[arg(long)]
        end_grace: bool,
    },
    /// Let a center change its own rights here (`on`), up to user mode and sudo
    ///
    /// Let a center change its own rights on this machine, up to user mode and sudo (`on`), or take that right away (`off`).
    Settings {
        /// `on` or `off`.
        #[arg(value_parser = ["on", "off"])]
        state: String,
        #[command(flatten)]
        center: CenterName,
    },
}

/// The three lists of commands in a center's policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum List {
    Allow,
    Deny,
    Sudo,
}

/// The lists `rule add` puts a command on: a sudo command goes on the sudo
/// list by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum AddList {
    Allow,
    Deny,
}

#[derive(Debug, Subcommand)]
pub enum RuleCmd {
    /// Allow or forbid a command; `sudo …` goes on the sudo list, ` *` is a wildcard
    ///
    /// Put a command on a list; one that starts with `sudo` goes on the sudo list. A trailing ` *` covers every command that starts so (`'git status *'`).
    Add {
        /// `allow` (in allowlist mode; a sudo command: with sudo) or `deny` (never runs)
        ///
        /// The list: `allow` (may run in allowlist mode; a sudo command may run with sudo while sudo is on) or `deny` (a command line that matches never runs, in any mode).
        list: AddList,
        /// The command line; a trailing ` *` covers what starts with the words before it
        ///
        /// The command line; a trailing ` *` covers every command that starts with the words before it.
        command: String,
        /// Make the rule from an audit entry's action, as the audit buttons do
        ///
        /// Make the rule of an audit entry of this action instead, as the audit buttons do: `fs.read` takes a path (`/srv/data/*` covers the folder), an action without a target takes "" (`*` covers its capability).
        #[arg(long, value_name = "CAP.ACTION")]
        action: Option<String>,
        /// With --action: hold the rule to one argument, like room=office
        ///
        /// With --action: hold the rule to one argument of the call, as the audit buttons do: `--arg room=office` makes `lamp.set:room=office`.
        #[arg(long, value_name = "FIELD=VALUE", requires = "action")]
        arg: Option<String>,
        /// With --action: take the target as it is, a `*` in it too (the exact buttons)
        ///
        /// With --action: take the target as the audit entry has it, a `*` at its end too, so that `rm -rf *` stays that one command. The audit's Allow and Deny buttons make their rule so; without it a trailing `*` is the wildcard.
        #[arg(long, requires = "action")]
        exact: bool,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Take a rule off its list, as `rule` shows it
    ///
    /// Take an entry off its list: the entry as `rule` shows it, or the command line that made it.
    #[command(override_usage = "nerve-node rule rm [OPTIONS] [LIST] <ENTRY>")]
    Rm {
        /// The list, needed only when the entry is on two; then the entry
        ///
        /// The list (`allow`, `deny` or `sudo`), needed only when the entry is on two; then the entry.
        #[arg(value_name = "ENTRY", required = true, num_args = 1..=2)]
        words: Vec<String>,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Change one rule in place, as one change
    ///
    /// Change one entry of a list in place, as one change: the entry as `rule` shows it, and what it becomes.
    Edit {
        /// The list: `allow`, `deny` or `sudo`.
        list: List,
        /// The entry as `rule` shows it.
        entry: String,
        /// The new rule, as `rule` shows it, or a plain command line
        ///
        /// What it becomes: an entry as `rule` shows them (`exec.run:git status`, `fs.read:~/notes/*`; on the sudo list a sudo command's pattern), or a plain command line, which becomes the rule `add` makes of it.
        new: String,
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
    /// Declare a capability that runs a fixed command (the words after `--`)
    ///
    /// Declare a capability of your own, NAME (`cap.action`, like sensors.read), that runs a fixed command: the words after `--`, the program first. A word written `{field}` is the call's argument `field`, as one whole argument; no shell reads it. It runs as nerve-run on the installed Linux node, held to the folders; a node run by hand offers none.
    Add {
        /// `cap.action`, like sensors.read.
        name: String,
        #[command(flatten)]
        spec: CapSpec,
        /// The program and its arguments, after `--`.
        #[arg(last = true, required = true, value_name = "COMMAND")]
        command: Vec<String>,
    },
    /// Change a capability you declared
    ///
    /// Change a capability you declared: what you give replaces what it has, and a command after `--` its command.
    Edit {
        /// The capability, `cap.action`.
        name: String,
        #[command(flatten)]
        spec: CapSpec,
        /// The program and its arguments, after `--`.
        #[arg(last = true, value_name = "COMMAND")]
        command: Vec<String>,
    },
    /// Remove a capability you declared (from every center at once)
    ///
    /// Remove a capability you declared; it leaves every center at once. With --center, remove one that center added itself (settings on); `cap set NAME off --center` turns it off instead.
    Rm {
        /// The capability, `cap.action`.
        name: String,
        /// The center that added it, for a capability a center added.
        #[arg(long)]
        center: Option<String>,
    },
}

/// What `cap add` and `cap edit` set of a capability of node.toml
/// (docs/dev/capabilities.md). The schemas come inline or on stdin
/// (`-`), never from a file the node would open.
#[derive(Debug, Args, Clone, Default)]
pub struct CapSpec {
    /// What it does: read, write, execute, sense or actuate
    ///
    /// What it does: read, write, execute, sense or actuate. Sense and actuate need your `cap set NAME on` for a center.
    #[arg(long)]
    pub effect: Option<String>,
    /// One line for the agent: what it does.
    #[arg(long)]
    pub summary: Option<String>,
    /// JSON Schema of its arguments, `none`, or `-` for stdin
    ///
    /// The JSON Schema of its arguments, an object; `none` takes no arguments; `-` reads it from stdin. A property marked "x-nerve-path": "read" or "write" is a path the node holds to the folders.
    #[arg(long, value_name = "JSON")]
    pub params: Option<String>,
    /// What it returns: `text` (the default), or a JSON Schema; `-` for stdin
    ///
    /// What it returns: `text`, what the command prints (the default), or a JSON Schema the printed JSON must fit; `-` reads it from stdin.
    #[arg(long, value_name = "text|JSON")]
    pub result: Option<String>,
    /// How long it may run, in seconds, or `default`
    ///
    /// How long it may run, in seconds, up to limits.max_timeout_secs; `default` for the node's default.
    #[arg(long, value_name = "SECS")]
    pub timeout: Option<String>,
    /// Where it runs: any (the default), linux or windows
    ///
    /// Where it runs: any (the default), linux or windows. A node offers only those of its platform.
    #[arg(long)]
    pub platform: Option<String>,
}

impl CapSpec {
    /// `--params -`: the schema comes on stdin.
    pub fn params_stdin(&self) -> bool {
        self.params.as_deref() == Some("-")
    }

    /// `--result -`: the schema comes on stdin.
    pub fn result_stdin(&self) -> bool {
        self.result.as_deref() == Some("-")
    }
}

#[derive(Debug, Subcommand)]
pub enum ProviderCmd {
    /// Allow the program EXE to add capabilities as provider NAME
    ///
    /// Let the program EXE attach as the provider NAME; it replaces the program allowed under that name. The node checks that the program that attaches runs this very file.
    Add {
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
}

#[derive(Debug, Subcommand, Clone, Copy)]
pub enum ServiceCmd {
    /// Start the installed service; the owner needs no root or administrator for it.
    Start,
    /// Stop the service: the node ends its links and runs nothing
    ///
    /// Stop it: the node ends its links and runs nothing until it starts again, at the latest with the machine.
    Stop,
    /// Stop it and start it again, so the node takes every change in node.toml.
    Restart,
}

#[derive(Debug, Subcommand)]
pub enum AuditCmd {
    /// Start the audit log afresh (the old one becomes audit.jsonl.1)
    ///
    /// Start the audit log afresh. The entries so far become its one older file (audit.jsonl.1, in place of the one before), and the new log begins with an entry of who cleared it.
    Clear,
}

#[derive(Debug, Subcommand)]
pub enum LogCmd {
    /// Empty the node's log and its older file
    ///
    /// Empty the node's log and its older file. The new log begins with a line of who cleared it.
    Clear,
}

#[derive(Debug, Subcommand)]
pub enum SudoCmd {
    /// Turn sudo on; the password stays in memory only
    ///
    /// Turn sudo on; asks for your sudo password and keeps it in memory only (on Windows the password of the account commands run as, kept with DPAPI).
    On,
    /// Turn sudo off and forget the password.
    Off,
}

#[derive(Debug, Subcommand)]
pub enum FolderCmd {
    /// Let a center use a folder (r, w, x); none closes one to file calls only
    ///
    /// Let a center use a folder, or change what it may do in one it has: `r` reads, `w` writes, `x` runs commands (`rw`, `rx`). `none` closes a folder inside one it may use to file calls; a command run in the folder around it still reaches it.
    Add {
        /// The folder.
        path: PathBuf,
        /// The rights, one word: `r`, `rw`, `rwx` and so on, or `none`.
        #[arg(value_name = "RIGHTS")]
        rights: String,
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
    /// Give nerve-run its access to every granted folder again (installed Linux node)
    ///
    /// Give nerve-run its access to everything in the folders of every center again, also what was moved into them (the installed node on Linux): a pass over every granted folder.
    Sync,
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
    Rm {
        /// The dotted key of a list, like `center.<name>.policy.allow`.
        key: String,
        /// The value to remove.
        value: String,
    },
    /// Trust node.toml as it is now, after a change made outside nerve-node
    ///
    /// Trust node.toml as it is now, after the node refused it for a change made outside nerve-node. Read the file first.
    Accept,
}

#[derive(Debug, Subcommand)]
pub enum ProxyCmd {
    /// Reach centers through an HTTP proxy or a relay
    ///
    /// Reach centers through an HTTP proxy. Header values and a password are kept in the system keyring, never in node.toml; the installed node on Windows takes neither.
    Set {
        /// http://[user[:password]@]host:port, https://…, a nerve://relay link; - for stdin
        ///
        /// The proxy, http://host:port, or http://user:password@host:port when it wants a login (http://user@host:port asks for the password, or reads it from the next line of stdin); https://... for another proxy reached over TLS; or the nerve://relay link a relay showed, which holds its address, pin and this node's token. `-` reads it from the first line of stdin, where it never shows in the process list.
        url: String,
        /// The pin of an https:// proxy's certificate
        ///
        /// The pin of an https:// proxy's certificate (a relay's: `nerve-node relay` there shows it); without it the system's roots check it.
        #[arg(long)]
        pin: Option<String>,
        /// A header for the proxy, `Name: value`, kept in the keyring; `-` for stdin
        ///
        /// A header for the proxy, `Name: value`; can be given more than once. The value goes into the system keyring. `-` reads headers from stdin, one a line, after the password.
        #[arg(long = "header", value_name = "NAME: VALUE")]
        headers: Vec<String>,
    },
    /// Reach centers directly again, without a proxy
    ///
    /// Reach centers directly again, and delete the proxy's values from the system keyring.
    Off,
}

#[derive(Debug, Subcommand)]
pub enum RelayCmd {
    /// Turn the relay on at ADDRESS, like 0.0.0.0:7490
    ///
    /// Turn the relay on: listen for other nodes at ADDRESS, like 0.0.0.0:7490. A node reaches only this node's own https centers through it.
    On {
        /// The address and port to listen on, like 0.0.0.0:7490 or [::]:7490.
        address: String,
        /// Tunnels at once, over every relayed node (16 unless set).
        #[arg(long, value_name = "N")]
        max_links: Option<u32>,
        /// Tunnels at once of one relayed node (4 unless set).
        #[arg(long, value_name = "N")]
        max_links_per_node: Option<u32>,
        /// Tunnels one relayed node may open per minute (30)
        ///
        /// Tunnels one relayed node may open a minute, every node alike (30 unless set; for a relay behind this one, use `relay set <name>`).
        #[arg(long, value_name = "N")]
        max_opens_per_minute: Option<u32>,
    },
    /// Turn the relay off; its nodes and their tokens stay
    ///
    /// Turn the relay off: stop listening and end every tunnel. The nodes and their tokens stay.
    Off,
    /// Let a node use the relay (shows its link once)
    ///
    /// Let a node use the relay: makes its token and shows it once, in a link the other node pastes. Without --to its tunnels may go to every https center of this node.
    Add {
        /// The relayed node's name here: 1 to 32 of a-z, 0-9 and -
        ///
        /// The relayed node's name here, 1 to 32 of a-z, 0-9 and -, starting and ending with a letter or digit.
        name: String,
        /// A center it may reach (more than once); without it, every one
        ///
        /// A center of this node the relayed node may reach; can be given more than once. Without it, every one.
        #[arg(long = "to", value_name = "CENTER")]
        centers: Vec<String>,
        /// Where the other node reaches this machine, HOST[:PORT], for its link
        ///
        /// Where the other node reaches this machine, HOST or HOST:PORT, for its link (without it: the address the relay listens on, else this machine's host name).
        #[arg(long, value_name = "HOST[:PORT]")]
        address: Option<String>,
    },
    /// Change the centers or the limits of one relayed node
    ///
    /// Change what a relayed node may: the centers it may reach (its tunnels to others end), and limits of its own in place of the relay's, for a relay behind this one, which carries many nodes. What is not given stays.
    Set {
        /// The relayed node's name.
        name: String,
        /// A center it may reach (more than once); `*` for every one
        ///
        /// A center of this node the relayed node may reach; can be given more than once; `*` for every one.
        #[arg(long = "to", value_name = "CENTER")]
        centers: Vec<String>,
        /// Its tunnels at once; `default` for the relay's --max-links-per-node.
        #[arg(long, value_name = "N")]
        max_links: Option<String>,
        /// The tunnels it may open a minute; `default` for the relay's.
        #[arg(long, value_name = "N")]
        max_opens_per_minute: Option<String>,
    },
    /// Give a relayed node a new token (shows its link once)
    ///
    /// Give a relayed node a new token and end the tunnels of the old one; its centers and limits stay. Shows the token once, in a link the other node pastes.
    Token {
        /// The relayed node's name.
        name: String,
        /// Where the other node reaches this machine, HOST[:PORT], for its link
        ///
        /// Where the other node reaches this machine, HOST or HOST:PORT, for its link (as for `relay add`).
        #[arg(long, value_name = "HOST[:PORT]")]
        address: Option<String>,
    },
    /// Take a node's token away and end its tunnels.
    Rm {
        /// The relayed node's name.
        name: String,
    },
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
    edit_saved_as(paths, false, f).await
}

/// [`edit_saved`] for `panic` when `panic` is set: the node then ends the web
/// UI's sessions also when the config does not change (it was locked).
async fn edit_saved_as(
    paths: &NodePaths,
    panic: bool,
    f: impl Fn(&mut NodeConfig) -> Result<(), String>,
) -> Result<Saved, String> {
    // Windows has no node to ask: the file is the node's.
    #[cfg(not(unix))]
    let _ = panic;
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
            // A rule's conditions are checked against what the running node
            // offers now, programs and all.
            if !added_conditions(&old, &cfg).is_empty() {
                check_conditions(&cap_listing(paths, &old).await?, &old, &cfg)?;
            }
            let mut params = json!({
                "config": cfg.to_toml(),
                "if_version": read["version"],
                "user": changed_by(),
            });
            // A page's request that a panic overtook writes nothing.
            if let Some(n) = crate::owner::web_epoch() {
                params["web_locks"] = json!(n);
            }
            if panic {
                params["panic"] = json!(true);
            }
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
    // A rule's conditions are checked against what the node would offer as
    // the config stands (it runs no program now).
    let mut probe = old.clone();
    f(&mut probe)?;
    if !added_conditions(&old, &probe).is_empty() {
        let listing = crate::provider::listing(&old, None, crate::service::is_service_node(paths));
        check_conditions(&listing, &old, &probe)?;
    }
    match store.update(|c| {
        f(c)?;
        // As the daemon's `config.write` does: a center's own the change
        // removes takes its switches along.
        crate::config_cap::drop_removed(&old, c);
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

/// The allow and deny rules with conditions on a call's arguments
/// (nerve_policy::conditions) that `new` gives a center and `old` did not,
/// with the center's name. The rules a center kept stay as they are, also
/// one whose argument went since (`rule` says so).
fn added_conditions(old: &NodeConfig, new: &NodeConfig) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for c in &new.centers {
        let was = old.center(&c.name).map(|e| &e.policy);
        for (rules, before) in [
            (&c.policy.allow, was.map(|p| &p.allow)),
            (&c.policy.deny, was.map(|p| &p.deny)),
        ] {
            for r in rules {
                if rules::has_conditions(r) && !before.is_some_and(|b| b.contains(r)) {
                    out.push((c.name.clone(), r.clone()));
                }
            }
        }
    }
    out
}

/// The arguments schema of each action that `cap`'s listing `v` shows,
/// for a rule of `center`: not one another center added.
fn listed_params(v: &Value, center: &str) -> impl Fn(&str, &str) -> Option<Value> + use<> {
    let rows: Vec<(String, Value)> = v["capabilities"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| !added_by_other(r, center))
        .filter_map(|r| Some((r["name"].as_str()?.to_string(), r.get("params")?.clone())))
        .collect();
    move |cap, action| {
        let name = format!("{cap}.{action}");
        rows.iter()
            .find(|(n, _)| *n == name)
            .map(|(_, p)| p.clone())
    }
}

/// Checks the conditions of each rule `new` adds ([`added_conditions`])
/// against the schemas of `listing`, `cap`'s.
fn check_conditions(listing: &Value, old: &NodeConfig, new: &NodeConfig) -> Result<(), String> {
    for (center, rule) in added_conditions(old, new) {
        rules::check_typed(&rule, &listed_params(listing, &center))?;
    }
    Ok(())
}

/// The center a per-center command means: the one named, or the only one.
pub fn pick_center(cfg: &NodeConfig, given: &CenterArg) -> Result<String, String> {
    crate::folder_change::pick_center(cfg, given.center.as_deref())
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
        let missing = no_center_named(c, &name);
        let e = c.center_mut(&name).ok_or(missing)?;
        f(e)
    })
    .await?;
    Ok(name)
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
            "install, update, uninstall and service keep the node's files in {} and {}: leave out --config-dir and --state-dir",
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
        (cfg!(windows) && matches!(cmd, Cmd::Sudo { .. })) || matches!(cmd, Cmd::Restore { .. });
    let before = (!matches!(cmd, Cmd::Run) && !service && !own_say)
        .then(|| std::fs::read(paths.config_file()).ok());
    // On Windows the running node takes folder changes over its pipe, and
    // nothing else yet.
    let folders = matches!(
        cmd,
        Cmd::Folder {
            cmd: Some(FolderCmd::Add { .. } | FolderCmd::Rm { .. }),
            ..
        }
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
            Cmd::Install { .. }
                | Cmd::Update { .. }
                | Cmd::Uninstall { .. }
                | Cmd::Service(_)
                | Cmd::ServiceFiles { .. }
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

/// The rule of the other owner commands (docs/dev/spec/node-local.md §5):
/// nothing a command of a center starts may install, set up, update or
/// remove the node, nor back it up or restore it. The node that runs knows
/// its commands, so it is asked over its control socket, and refuses a
/// caller below one of them.
pub async fn owner_check(paths: &[&NodePaths]) -> Result<(), String> {
    let sockets: Vec<PathBuf> = paths.iter().map(|p| p.ctl_socket()).collect();
    nerve_service::owner_check(&sockets).await
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
}

/// Writes `s` as one line of what a command shows.
fn w(out: &mut dyn Write, s: String) {
    let _ = writeln!(out, "{s}");
}

/// Runs one command: each subcommand is the function that does it.
async fn command(paths: NodePaths, cmd: Cmd, out: &mut dyn Write) -> Result<(), String> {
    match cmd {
        Cmd::Run => run(paths).await,
        Cmd::Center {
            cmd: Some(CenterCmd::Add { link, name, yes }),
        } => center::add(paths, link, name, yes, out).await,
        Cmd::Center {
            cmd: Some(CenterCmd::Rm(center)),
        } => center::rm(paths, center, out).await,
        Cmd::Center { cmd: None } => center::list(paths, out).await,
        Cmd::Center {
            cmd: Some(CenterCmd::RotateKey { end_grace, center }),
        } => center::rotate_key(&paths, &center.arg(), end_grace, out).await,
        Cmd::Center {
            cmd: Some(CenterCmd::Pause(center)),
        } => center::pause_center(&paths, &center.arg(), true, out).await,
        Cmd::Center {
            cmd: Some(CenterCmd::Resume(center)),
        } => center::pause_center(&paths, &center.arg(), false, out).await,
        Cmd::Center {
            cmd: Some(CenterCmd::Settings { state, center }),
        } => center::settings(paths, state, center, out).await,
        Cmd::Status => status::status(paths, out).await,
        Cmd::Mode {
            mode: Some(mode),
            for_hours,
            as_owner,
            center,
        } => mode::set_mode(&paths, &mode, for_hours, as_owner, &center, out).await,
        Cmd::Mode {
            mode: None,
            for_hours,
            as_owner,
            center,
        } => mode::show_mode(paths, for_hours, as_owner, center, out).await,
        Cmd::Folder {
            cmd:
                Some(FolderCmd::Add {
                    path,
                    rights,
                    center,
                }),
            ..
        } => folder::add_folder(&paths, &path, &rights, &center, out).await,
        Cmd::Folder {
            cmd: Some(FolderCmd::Rm { path, center }),
            ..
        } => folder::rm_folder(paths, path, center, out).await,
        Cmd::Folder {
            cmd: Some(FolderCmd::Sync),
            ..
        } => folder::sync_folders(&paths, out).await,
        Cmd::Network {
            state: Some(state),
            center,
        } => network::set_network(&paths, &state, &center, out).await,
        Cmd::Network {
            state: None,
            center,
        } => network::show_network(paths, center, out).await,
        Cmd::Folder { cmd: None, center } => folder::show_folders(paths, center, out).await,
        Cmd::Cap {
            cmd:
                Some(CapCmd::Set {
                    cap,
                    setting,
                    center,
                }),
            ..
        } => cap::set_cap(paths, cap, setting, center, out).await,
        Cmd::Cap { cmd: None, center } => cap::show_caps(paths, center, out).await,
        Cmd::Cap {
            cmd:
                Some(CapCmd::Add {
                    name,
                    spec,
                    command,
                }),
            ..
        } => cap::add_cap(paths, name, spec, command, out).await,
        Cmd::Cap {
            cmd:
                Some(CapCmd::Edit {
                    name,
                    spec,
                    command,
                }),
            ..
        } => cap::edit_cap(paths, name, spec, command, out).await,
        Cmd::Cap {
            cmd:
                Some(CapCmd::Rm {
                    name,
                    center: Some(center),
                }),
            ..
        } => cap::rm_added_cap(paths, name, center, out).await,
        Cmd::Cap {
            cmd: Some(CapCmd::Rm { name, center: None }),
            ..
        } => cap::rm_cap(paths, name, out).await,
        Cmd::Provider {
            cmd: Some(ProviderCmd::Add { name, exe }),
        } => provider::add_provider(paths, name, exe, out).await,
        Cmd::Provider {
            cmd: Some(ProviderCmd::Rm { name }),
        } => provider::rm_provider(paths, name, out).await,
        Cmd::Provider { cmd: None } => provider::show_providers(paths, out).await,
        Cmd::Config(c) => config::config_cmd(&paths, c, out).await,
        Cmd::Rule { cmd, list, center } => rule::rule_cmd(&paths, cmd, list, center, out).await,
        Cmd::Panic => lock(paths, out).await,
        Cmd::Unlock => unlock(paths, out).await,
        Cmd::Audit {
            clear: Some(AuditCmd::Clear),
            ..
        } => log::audit_clear(paths, out).await,
        Cmd::Audit {
            clear: None,
            follow,
            refused,
            last,
        } => log::audit(&paths, follow, refused, last, false, out).await,
        Cmd::Log {
            clear: Some(LogCmd::Clear),
            ..
        } => log::log_clear(paths, out).await,
        Cmd::Log {
            clear: None,
            follow,
            last,
            problems,
        } => log::log_cmd(&paths, follow, last, problems, false, out).await,
        Cmd::Proxy { cmd } => proxy::proxy_cmd(&paths, cmd, out).await,
        Cmd::Relay { cmd } => relay::relay_cmd(&paths, cmd, out).await,
        Cmd::Ui { cmd } => ui::ui_cmd(&paths, cmd, out).await,
        Cmd::Sudo { cmd } => sudo::sudo_cmd(&paths, cmd, out).await,
        Cmd::Backup {
            file,
            include_keyring,
            overwrite,
            passphrase_file,
        } => {
            backup::backup(
                paths,
                file,
                include_keyring,
                overwrite,
                passphrase_file,
                out,
            )
            .await
        }
        Cmd::Restore {
            file,
            replace,
            secret_storage,
            without_proxy,
            passphrase_file,
        } => {
            backup::restore(
                paths,
                file,
                replace,
                secret_storage,
                without_proxy,
                passphrase_file,
                out,
            )
            .await
        }
        Cmd::Install {
            owner,
            accept_root_owner,
        } => install::install(paths, owner, accept_root_owner, out).await,
        Cmd::Setup => setup::setup_cmd(paths, out).await,
        Cmd::Update { from } => install::update(from, out).await,
        Cmd::ServiceFiles { owner, polkit } => install::service_files(owner, polkit, out),
        Cmd::Service(c) => install::service(c, out).await,
        Cmd::Uninstall { purge } => install::uninstall(paths, purge, out).await,
    }
}

/// `run`: the node itself, until it is stopped.
async fn run(paths: NodePaths) -> Result<(), String> {
    let mut opts = NodeOptions::new(paths);
    opts.exe = std::env::current_exe().ok();
    Daemon::run(opts).await
}

/// `panic`: every link ends and nothing runs until `unlock`.
async fn lock(paths: NodePaths, out: &mut dyn Write) -> Result<(), String> {
    let saved = edit_saved_as(&paths, true, |c| {
        c.locked = true;
        Ok(())
    })
    .await?;
    if let Some(e) = grants_failed(&saved.grants) {
        return Err(e);
    }
    w(
        out,
        "locked: every link ends and nothing runs until `nerve-node unlock`".into(),
    );
    Ok(())
}

/// `unlock`: undoes `panic`.
async fn unlock(paths: NodePaths, out: &mut dyn Write) -> Result<(), String> {
    edit(&paths, |c| {
        c.locked = false;
        Ok(())
    })
    .await?;
    w(out, "unlocked".into());
    Ok(())
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

pub(crate) use crate::folder_change::{NO_CENTER_PAIRED, no_center_named};

fn confirm(input: &mut dyn BufRead, out: &mut dyn Write) -> Result<bool, String> {
    let _ = write!(out, "Pair with this center? [y/N] ");
    let _ = out.flush();
    let mut line = String::new();
    input.read_line(&mut line).map_err(|e| e.to_string())?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes"))
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

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::config::tell_folder_commands;
    #[cfg(unix)]
    use super::proxy::PROXY_AUTHORIZATION;
    #[cfg(unix)]
    use super::setup::after_keyring_answers;
    use super::*;
    use nerve_policy::config::Access;

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

    pub(super) fn run(paths: &NodePaths, args: &[&str]) -> Result<String, String> {
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

    pub(super) fn entry(name: &str) -> nerve_policy::CenterEntry {
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
            capabilities: Vec::new(),
        }
    }

    pub(super) fn setup(names: &[&str]) -> (tempfile::TempDir, NodePaths) {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("c"), d.path().join("s"));
        let mut cfg = NodeConfig::default();
        for n in names {
            cfg.centers.push(entry(n));
        }
        cfg.save(&paths.config_file()).unwrap();
        (d, paths)
    }

    pub(super) fn load(paths: &NodePaths) -> NodeConfig {
        NodeConfig::load(&paths.config_file()).unwrap()
    }

    #[test]
    fn per_center_commands_refuse_to_guess() {
        let (_d, paths) = setup(&["a", "b"]);
        let e = run(&paths, &["mode", "user"]).unwrap_err();
        assert!(e.contains("--center"), "{e}");
        run(&paths, &["mode", "user", "--center", "b"]).unwrap();
        assert_eq!(load(&paths).center("b").unwrap().policy.mode, Mode::User);
        // A center whose file names no mode is in default deny.
        assert_eq!(
            load(&paths).center("a").unwrap().policy.mode,
            Mode::Allowlist
        );
        run(&paths, &["mode", "folder", "--center", "a"]).unwrap();
        assert_eq!(load(&paths).center("a").unwrap().policy.mode, Mode::Folder);
        run(&paths, &["mode", "allowlist", "--center", "a"]).unwrap();
        assert_eq!(
            load(&paths).center("a").unwrap().policy.mode,
            Mode::Allowlist
        );
        let e = run(&paths, &["mode", "ask", "--center", "a"]).unwrap_err();
        assert!(e.contains("unknown mode"), "{e}");
        let e = run(&paths, &["cap", "set", "fs", "ask", "--center", "a"]).unwrap_err();
        assert!(e.contains("unknown setting"), "{e}");
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
            &["folder", "add", folder.to_str().unwrap(), "r"][..],
            &["mode", "user"],
            &["rule", "add", "deny", "rm -rf /"],
        ] {
            let out = run(&paths, args).unwrap();
            assert_eq!(out.lines().last(), Some(line.as_str()), "{args:?}: {out}");
            assert_eq!(out.matches(next).count(), 1, "{args:?}: {out}");
        }
        for args in [&["status"][..], &["center"], &["folder"]] {
            let out = run(&paths, args).unwrap();
            assert!(!out.contains(&line), "{args:?}: {out}");
        }
        // A command that fails changed nothing.
        assert!(run(&paths, &["mode", "ask"]).is_err());
    }

    #[test]
    fn edits_without_a_daemon_land_in_the_file_and_the_audit_log() {
        let (d, paths) = setup(&["home"]);
        let folder = d.path().join("work");
        std::fs::create_dir(&folder).unwrap();
        let note = run(&paths, &["folder", "add", folder.to_str().unwrap(), "rwx"]).unwrap();
        assert!(note.contains("folders do not count here"), "{note}");
        run(&paths, &["cap", "set", "exec.run", "off"]).unwrap();
        run(&paths, &["center", "settings", "on"]).unwrap();
        let out = run(&paths, &["rule", "add", "allow", "git *"]).unwrap();
        assert!(out.contains("it allows every `git` command"), "{out}");
        run(&paths, &["rule", "add", "allow", "sudo apt update"]).unwrap();
        run(&paths, &["rule", "add", "deny", "rm -rf /"]).unwrap();
        run(&paths, &["rule", "add", "deny", "rm -rf /"]).unwrap();
        run(&paths, &["mode", "user", "--for", "2"]).unwrap();
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

    /// The errors of a command name what to do next: how to pair, the
    /// centers that are paired, the command that lists what was meant.
    #[test]
    fn the_errors_name_the_fix() {
        let (_d, none) = setup(&[]);
        let e = run(&none, &["folder"]).unwrap_err();
        assert!(
            e.contains("pair one: `nerve-node center add -`, then paste the link"),
            "{e}"
        );
        let (_d, paths) = setup(&["home", "work"]);
        let e = run(&paths, &["folder", "--center", "lab"]).unwrap_err();
        assert_eq!(e, "no center named lab; paired: home, work");
        let e = run(&paths, &["rule", "rm", "allow", "ls", "--center", "home"]).unwrap_err();
        assert!(e.contains("`nerve-node rule allow` shows it"), "{e}");
        let e = run(&paths, &["cap", "edit", "a.b", "--timeout", "5"]).unwrap_err();
        assert!(e.contains("`nerve-node cap` lists them"), "{e}");
        let e = run(&paths, &["provider", "rm", "desk"]).unwrap_err();
        assert!(e.contains("`nerve-node provider` lists them"), "{e}");
    }

    pub(super) fn setup_with(paths: &NodePaths, answers: &str) -> (Result<(), String>, String) {
        let keyring = crate::keyring_setup::tests::FakeKeyring::new(true);
        setup_keyring(paths, None, &keyring, answers)
    }

    pub(super) fn setup_keyring(
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

    #[test]
    fn caps_and_proxy_show_what_is_set() {
        let (_d, paths) = setup(&["home"]);
        let ls = run(&paths, &["cap"]).unwrap();
        assert!(ls.contains("fs.read"), "{ls}");
        assert!(ls.contains("no program is allowed as a provider"), "{ls}");
        run(&paths, &["cap", "set", "exec", "hidden"]).unwrap();
        let ls = run(&paths, &["cap"]).unwrap();
        let run_line = ls.lines().find(|l| l.starts_with("exec.run ")).unwrap();
        assert!(run_line.ends_with("home: hidden"), "{ls}");
        assert_eq!(run(&paths, &["proxy"]).unwrap(), "no proxy\n");
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
        let ls = run(&paths, &["proxy"]).unwrap();
        assert!(
            ls.contains("http://127.0.0.1:3128") && ls.contains("X-Key"),
            "{ls}"
        );
        assert!(!ls.contains("s3cret"), "{ls}");
        run(&paths, &["proxy", "off"]).unwrap();
        assert_eq!(run(&paths, &["proxy"]).unwrap(), "no proxy\n");
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
            &["center"],
            &["center", "pause"],
            &["center", "resume"],
            &["center", "settings", "on"],
            &["folder", "add", "/p", "r"],
            &["folder", "add", "/p", "none"],
            &["folder", "rm", "/p"],
            &["folder"],
            &["network", "off"],
            &["mode", "user", "--for", "2"],
            &["mode"],
            &["rule", "add", "allow", "ls *"],
            &["rule", "rm", "deny", "ls"],
            &["rule", "rm", "ls"],
            &["relay", "on", "0.0.0.0:7490"],
            &["relay", "set", "lab", "--to", "home"],
            &["relay"],
            &["rule", "sudo"],
            &["cap", "set", "fs", "on"],
            &["cap"],
            &["provider", "add", "desk", "/usr/bin/desk"],
            &["provider", "rm", "desk"],
            &["provider"],
            &["cap", "add", "a.b", "--effect", "read", "--", "true"],
            &["cap", "edit", "a.b", "--timeout", "5"],
            &["cap", "rm", "a.b"],
            &["proxy", "set", "http://p:1"],
            &["proxy", "off"],
            &["proxy"],
            &["config", "get", "limits"],
            &["sudo", "on"],
            &["sudo", "off"],
            &["sudo"],
            &["audit", "--refused"],
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
            &["mode", "set", "user"],
            &["mode", "user", "--hours", "2"],
            &["folder", "set", "/p", "=rwx"],
            &["folder", "network", "off"],
            &["folder", "ls"],
            &["center", "ls"],
            &["center", "grant", "settings", "write"],
            &["rule", "add", "sudo", "x"],
            &["rule", "add", "allow", "x", "--wildcard"],
            &["rule", "ls"],
            &["cap", "ls"],
            &["cap", "provider", "ls"],
            &["sudo", "status"],
            &["audit", "--denied"],
            &["config", "remove", "a", "b"],
            &["proxy", "rm"],
            &["relay", "set-limits", "lab"],
            &["mode", "user", "--hours", "2"],
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
            &["rule", "allow", "extra"],
        ] {
            assert!(!parses(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_shim_is_not_a_command() {
        let e = Cli::try_parse_from(["nerve-node", "__exec-shim"]).unwrap_err();
        assert!(e.to_string().contains("__exec-shim"));
    }

    pub(super) fn json_of(paths: &NodePaths, args: &[&str]) -> Value {
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
            &["folder", "add", &work.display().to_string(), "rx"],
        )
        .unwrap();
        run(&paths, &["rule", "add", "allow", "git status"]).unwrap();
        run(&paths, &["rule", "add", "deny", "rm *"]).unwrap();
        run(&paths, &["cap", "set", "fs.write", "off"]).unwrap();
        run(&paths, &["mode", "folder"]).unwrap();

        let v = json_of(&paths, &["status"]);
        assert_eq!(v["daemon"], "not running", "{v}");
        assert_eq!(v["locked"], false, "{v}");
        assert_eq!(v["sudo"], "off", "{v}");
        assert_eq!(v["centers"][0]["name"], "home", "{v}");
        assert_eq!(v["centers"][0]["mode"], "folder", "{v}");
        assert!(v["centers"][0]["status"].is_null(), "{v}");
        assert!(v["command_limits"]["memory_mb"].is_u64(), "{v}");

        let v = json_of(&paths, &["center"]);
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

        let v = json_of(&paths, &["folder"]);
        assert_eq!(v["center"], "home");
        let f = &v["folders"][0];
        assert_eq!(
            (&f["rights"], &f["read"], &f["write"], &f["execute"]),
            (&json!("r-x"), &json!(true), &json!(false), &json!(true)),
            "{v}"
        );

        let v = json_of(&paths, &["rule"]);
        assert_eq!(v["allow"], json!(["exec.run:git status"]), "{v}");
        assert_eq!(v["deny"], json!(["exec.run:rm *"]), "{v}");
        assert_eq!(v["sudo"], json!([]), "{v}");
        let v = json_of(&paths, &["rule", "deny"]);
        assert!(v.get("allow").is_none() && v["deny"].is_array(), "{v}");

        let v = json_of(&paths, &["cap"]);
        assert_eq!(v["caps"], json!({"fs.write": "off"}), "{v}");

        let v = json_of(&paths, &["config", "get", "center.home.policy.mode"]);
        assert_eq!(
            v,
            json!({"key": "center.home.policy.mode", "value": "folder"})
        );
        let v = json_of(&paths, &["config", "get", "center.home.policy.allow"]);
        assert_eq!(v["value"], json!(["exec.run:git status"]), "{v}");

        assert_eq!(json_of(&paths, &["proxy"]), json!({"proxy": null}));
        let v = json_of(&paths, &["relay"]);
        assert!(v["listen"].is_null() && v["tunnels"].is_null(), "{v}");
        assert_eq!(v["nodes"], json!([]), "{v}");
        assert_eq!(json_of(&paths, &["sudo"]), json!({"sudo": "off"}));
    }

    /// The other commands give the lines they print, so a program can show
    /// them, and say nothing else on stdout.
    #[test]
    fn a_change_with_json_gives_its_lines() {
        let (_d, paths) = setup(&["home"]);
        let v = json_of(&paths, &["mode", "user"]);
        let m = v["messages"].as_array().unwrap();
        assert_eq!(m[0], "home: mode user", "{v}");
        assert!(m[1].as_str().unwrap().contains(NEXT_START), "{v}");
        // As data too, for a program that offers the restart.
        assert_eq!(v["next_start"], true, "{v}");
        assert_eq!(load(&paths).center("home").unwrap().policy.mode, Mode::User);
        // The same again changes nothing, and says no such thing.
        let v = json_of(&paths, &["mode", "user"]);
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
        run(&paths, &["relay", "on", "0.0.0.0:7491"]).unwrap();
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

    /// A full path of a program on this platform, from `/`-separated parts.
    pub(super) fn program_path(parts: &str) -> String {
        if cfg!(windows) {
            format!("C:\\{}", parts.replace('/', "\\"))
        } else {
            format!("/{parts}")
        }
    }
}
