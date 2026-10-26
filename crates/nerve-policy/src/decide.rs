//! The decision engine: whether one call of one center may run
//! (docs/dev/policy-engine.md, spec node-local §3).
//!
//! There are two outcomes, allowed and refused; nothing waits for an answer.
//! The order only ever narrows: a command line too long to check is
//! forbidden first; a call that touches the node's own folders (config,
//! keys, state) is forbidden before anything else is looked at, and nothing
//! lifts that; an `off` capability is disabled; a sudo
//! command with the sudo switch off, and anything a deny rule matches, is
//! forbidden whatever else says; then a sudo command needs the sudo allow
//! list, and any other call the mode: allow rules in `allowlist` mode, the
//! folders in `folder` mode (a read outside them also what the command
//! account may read without them, where the node reads as it: [`Reads`]),
//! the user's own reach in
//! `user` mode. A call no mode and no rule allows is refused at once, and so
//! is one that touches a protected path, whatever allowed it.

use std::path::{Path, PathBuf};

use nerve_proto::Effect;

use crate::command::Shell;
use crate::config::{CapSetting, CenterPolicy, Folder, Mode};
use crate::paths::{depth, to_wire, within};
use crate::protected::Protected;
use crate::rules::{RuleSet, command_matches};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Policy refuses the call.
    Forbidden(String),
    /// The capability or action is off.
    Disabled(String),
}

/// One path a call touches, already resolved (`paths::resolve`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub path: PathBuf,
    pub access: PathAccess,
}

/// What a call does at one of its paths. Each needs its own folder flag:
/// `r`, `w`, or `x` for the working directory of a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathAccess {
    Read,
    Write,
    Run,
}

/// The paths a call names, as the effect table ([`effect_rule`]) sees them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathArgs {
    /// No path, no working directory and no command: an action whose schema
    /// marks no path (`x-nerve-path`), or one whose marked paths the call
    /// left out.
    None,
    /// Paths, and whether every one lies in a folder whose flag allows what
    /// the call does there, and an execute call's working directory in one
    /// with `x`. A path a read call reads that lies in no folder at all
    /// counts as in them where the command account holds it
    /// ([`Reads::Account`]).
    Some { all_in_folders: bool },
}

/// What holds a read call to the places it may read in `folder` mode.
#[derive(Clone, Copy)]
pub enum Reads<'a> {
    /// The folders: each path it reads needs a folder with `r`. This holds
    /// where the node reads with its own or the owner's rights (a node run
    /// by hand, Windows), which reach further than the folders.
    Folders,
    /// The command account's own file access (`nerve-run` on the installed
    /// Linux node): the node reads as that account. Inside the folders their
    /// flags still decide, the deepest one as for any path, so a folder the
    /// owner closed stays closed. A path in no folder may be read where
    /// `may_read` says so (`Ok`), else it gives the reason (`Err`): the node
    /// asks whether the account reaches it without the entries the node put
    /// on for it, which are the folders' and not the account's own.
    /// `may_read` is asked of each such path a call reads, as a provider
    /// reads it with the owner's rights, not with the account's.
    Account(&'a dyn Fn(&Path) -> Result<(), String>),
}

impl std::fmt::Debug for Reads<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Reads::Folders => "Folders",
            Reads::Account(_) => "Account",
        })
    }
}

/// What a call still needs before its mode allows it ([`effect_rule`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    /// An allow rule that covers it (`allowlist` mode): the rules decide.
    AllowRule,
    /// Nothing: the mode allows it.
    Allowed,
    /// Its paths in the folders: one lies outside every folder whose flag
    /// allows what the call does there.
    InFolders,
    /// The owner's `on` for it, which it does not have.
    NeedsOn,
    /// The owner to switch it back: it is set to `off` or `hidden`, and
    /// nothing allows it then.
    Off,
}

/// The effect table: what `mode` lets a call of `effect` do, with `paths`
/// and the owner's `setting` for its `cap.action`. It is the one place that
/// says so: [`decide`] follows it, and the node's descriptor offers an
/// action by it, so what a center is shown is what a call may do. The one
/// exception lies outside the table: on a machine that cannot confine a
/// command, `folder` mode offers no `exec` action (with an empty sudo
/// allow list), so `exec.signal` set to `on` is not shown there though a
/// call of it would be allowed; no command can run there to signal.
///
/// | effect | `allowlist` | `folder` | `user` |
/// |---|---|---|---|
/// | read, write, execute | allow rule | paths in the folders; no path: `on` | allowed |
/// | sense, actuate | allow rule | `on`, and its paths in the folders | `on` |
///
/// "In the folders" is each path in a folder whose flag allows what the
/// call does there; a path a read call reads that lies in no folder counts
/// as in them where the command account holds the read ([`Reads::Account`]),
/// which [`decide`] then asks of that account. `on` never widens what the
/// folders refuse. A write that names only paths it reads names no place it
/// writes, so [`decide`] asks the table as for a write with no path.
/// `off` and `hidden` give [`Need::Off`] in every cell ([`decide`] disables
/// such a call before it asks); the sudo allow list decides beside the
/// table, and a command in `folder` mode also needs to be confined.
pub fn effect_rule(
    mode: Mode,
    effect: Effect,
    paths: PathArgs,
    setting: Option<CapSetting>,
) -> Need {
    let on = match setting {
        Some(CapSetting::Off | CapSetting::Hidden) => return Need::Off,
        Some(CapSetting::On) => Need::Allowed,
        None => Need::NeedsOn,
    };
    match (mode, effect, paths) {
        (Mode::Allowlist, _, _) => Need::AllowRule,
        // `on` lets a sense or actuate action run, and its paths stay in the
        // folders as any other call's.
        (
            Mode::Folder,
            Effect::Sense | Effect::Actuate,
            PathArgs::Some {
                all_in_folders: false,
            },
        ) => Need::InFolders,
        // No mode allows these; only the owner's `on` does.
        (Mode::Folder | Mode::User, Effect::Sense | Effect::Actuate, _) => on,
        (Mode::User, Effect::Read | Effect::Write | Effect::Execute, _) => Need::Allowed,
        // An action that names no path lies in no folder, so the folders
        // cannot allow it: without this an empty list of paths would pass
        // the folder check for every write. A read that names none is a
        // program's (every `fs` call names its path), which reads with the
        // owner's rights where the node cannot see: the protected paths
        // and the node's own files would not hold for it.
        (Mode::Folder, Effect::Read | Effect::Write | Effect::Execute, PathArgs::None) => on,
        (
            Mode::Folder,
            Effect::Read | Effect::Write | Effect::Execute,
            PathArgs::Some { all_in_folders },
        ) => {
            if all_in_folders {
                Need::Allowed
            } else {
                Need::InFolders
            }
        }
    }
}

/// One call to decide on.
#[derive(Debug, Clone)]
pub struct Call<'a> {
    pub cap: &'a str,
    pub action: &'a str,
    pub effect: Effect,
    pub targets: &'a [Target],
    /// For `exec.run`: the command line and its working directory (also in
    /// `targets`).
    pub command: Option<&'a str>,
    pub cwd: Option<&'a Path>,
    pub now_ms: u64,
}

/// What the node knows besides the center's policy.
#[derive(Debug, Clone)]
pub struct Env<'a> {
    pub home: &'a Path,
    pub protected: &'a Protected,
    /// Why commands run in `folder` mode cannot be confined (Landlock, a
    /// Windows AppContainer) here, or `None` when they can. When they cannot, a command in a folder that
    /// allows running is refused with this reason.
    pub unconfined: Option<&'a str>,
    /// The node's sudo switch: on only while the node holds a sudo password
    /// it has checked.
    pub sudo: bool,
    /// The shell `exec.run` lines run in: the guard reads them by its rules.
    pub shell: Shell,
    /// What holds a read in `folder` mode.
    pub reads: Reads<'a>,
}

/// The arguments of a command that runs through `sudo`: its first word is
/// `sudo` (or a path ending in `/sudo`). Anything else (`env sudo`, `ls;
/// sudo x`) is not a sudo command here; the node runs those so that sudo
/// cannot gain privileges at all.
pub fn sudo_command(command: &str) -> Option<&str> {
    let command = command.trim_start();
    let end = command
        .find(|c: char| c.is_ascii_whitespace())
        .unwrap_or(command.len());
    let (first, rest) = command.split_at(end);
    (first == "sudo" || first.ends_with("/sudo")).then_some(rest.trim_start())
}

/// The longest command line, in bytes, that the node checks and runs. The
/// checks read a line a few times over (own folders, rules, wildcards) and a
/// center can send up to the 4 MiB message limit, so a longer line is
/// refused before any of them; 64 KiB is far past what a person or a harness
/// writes, Windows starts no process with a command line over 32 767
/// characters, and Linux takes no single argument (`sh -c` gets the line as
/// one) over 128 KiB.
pub const COMMAND_MAX_BYTES: usize = 64 * 1024;

/// Characters that chain, substitute or redirect in a shell.
const SHELL_CONTROL: &[char] = &[';', '&', '|', '$', '`', '(', ')', '<', '>', '\n', '\r'];

/// Characters besides [`SHELL_CONTROL`] that open an expression, a script
/// block, a variable, a quote, a comment, an array or an escape in sh,
/// PowerShell or cmd. A wildcard cannot tell what the shell makes of them
/// (PowerShell runs the value of `@{a=...}`), so it does not cover a line
/// with one of them.
const EXPRESSION: &[char] = &['@', '{', '}', '%', '\'', '"', '#', ',', '\\'];

/// Words that start another shell or run a string as code, compared without
/// case and without a `.exe`: a wildcard on the rest of a line cannot say
/// what such a word is handed.
const INNER_COMMAND: &[&str] = &[
    "powershell",
    "pwsh",
    "cmd",
    "iex",
    "invoke-expression",
    "invoke-command",
    "icm",
    "start",
    "start-process",
    "saps",
    "start-job",
    "-command",
    "-encodedcommand",
    "-enc",
    "-ec",
    "-file",
    "-commandwithargs",
    "/c",
    "/k",
    "sh",
    "bash",
    "eval",
];

/// Whether a wildcard rule may cover the command line `line`: one plain
/// command of printable characters, with no character of
/// [`SHELL_CONTROL`] or [`EXPRESSION`] and no word of [`INNER_COMMAND`].
/// Otherwise only a rule that names the line exactly covers it.
fn plain_command(line: &str) -> bool {
    not_plain(line).is_none()
}

/// What keeps `line` from being a plain command ([`plain_command`]): the
/// first such character or word, quoted, for a refusal to name.
fn not_plain(line: &str) -> Option<String> {
    // Control characters, the Unicode line breaks and the typographic quotes
    // PowerShell reads as quotes.
    let odd =
        |c: char| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}' | '\u{2018}'..='\u{201F}');
    if let Some(c) = line
        .chars()
        .find(|c| SHELL_CONTROL.contains(c) || EXPRESSION.contains(c) || odd(*c))
    {
        // One the owner cannot see is named by its number.
        return Some(if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') {
            format!("the invisible character U+{:04X}", u32::from(c))
        } else {
            format!("`{c}`")
        });
    }
    line.split_whitespace()
        .find(|w| {
            let w = w.to_lowercase();
            let name = w.rsplit('/').next().unwrap_or(&w);
            let name = name.strip_suffix(".exe").unwrap_or(name);
            INNER_COMMAND.contains(&w.as_str()) || INNER_COMMAND.contains(&name)
        })
        .map(|w| format!("`{w}`"))
}

fn inside_folder<'f>(folders: &'f [Folder], path: &Path) -> Option<&'f Folder> {
    // The deepest folder wins, so a read-only folder inside a read-write one
    // stays read-only. Deepest by components, as `within` counts them: a
    // longer spelling of the same place (`/a/b/`) is no deeper.
    folders
        .iter()
        .filter(|f| within(path, Path::new(&f.path)))
        .max_by_key(|f| depth(Path::new(&f.path)))
}

/// Whether the folders let `path` be read (or written): the deepest folder
/// that holds it decides, by its flag. `folder` mode asks this of every
/// target, and a walk (`grep`, `find`, `list`) asks it of every entry, so the
/// two cannot disagree.
pub fn folder_reach(folders: &[Folder], path: &Path, write: bool) -> bool {
    let access = if write {
        PathAccess::Write
    } else {
        PathAccess::Read
    };
    reaches(folders, path, access)
}

/// Whether `folder` mode lets a read call read `path`, as [`decide`] judges
/// a path such a call reads: the deepest folder that holds it decides by its
/// `r`, and a path in no folder is read only where the command account holds
/// the reads and `may_read` lets it ([`Reads::Account`]). A walk (`grep`,
/// `find`, `list`) asks it of every entry, so the walk and a direct read
/// cannot disagree.
pub fn read_reach(folders: &[Folder], path: &Path, reads: Reads) -> bool {
    match inside_folder(folders, path) {
        Some(f) => f.access.read,
        None => matches!(reads, Reads::Account(may_read) if may_read(path).is_ok()),
    }
}

/// Whether the deepest folder that holds `path` has the flag `access` needs.
fn reaches(folders: &[Folder], path: &Path, access: PathAccess) -> bool {
    inside_folder(folders, path).is_some_and(|f| match access {
        PathAccess::Read => f.access.read,
        PathAccess::Write => f.access.write,
        PathAccess::Run => f.access.execute,
    })
}

/// Whether a folder with `r` lies strictly inside `dir`: a walk passes
/// through a sealed folder to reach it, and reads only what is readable.
pub fn readable_below(folders: &[Folder], dir: &Path) -> bool {
    folders.iter().any(|f| {
        let path = Path::new(&f.path);
        f.access.read && within(path, dir) && !within(dir, path)
    })
}

/// One string rules are tried on (`rules`), and whether it is a path.
struct RuleTarget {
    text: String,
    path: bool,
}

/// The strings rules are tried on (`rules`): the command line of `exec.run`,
/// the paths of any other call that names them (an `fs` call's, the marked
/// arguments of another action), else the action itself.
fn rule_targets(call: &Call) -> Vec<RuleTarget> {
    if let Some(cmd) = call.command {
        vec![RuleTarget {
            text: cmd.trim().to_string(),
            path: false,
        }]
    } else if call.targets.is_empty() {
        vec![RuleTarget {
            text: format!("{}.{}", call.cap, call.action),
            path: false,
        }]
    } else {
        call.targets
            .iter()
            .map(|t| RuleTarget {
                text: to_wire(&t.path),
                path: true,
            })
            .collect()
    }
}

/// The rule of `rules` that covers `target` of `call`, a path read as one.
fn find_rule<'r>(rules: &'r RuleSet, call: &Call, target: &RuleTarget) -> Option<&'r str> {
    if target.path {
        rules.find_path(call.cap, call.action, &target.text)
    } else {
        rules.find(call.cap, call.action, &target.text)
    }
}

/// How a refusal names a rule target.
fn name(call: &Call, target: &str) -> String {
    if call.command.is_some() {
        format!("the command {target:?}")
    } else {
        target.to_string()
    }
}

/// The node's own folder `call` touches: one of its paths, its working
/// directory, or a path its command line names plainly; for a call that
/// works below its paths ([`works_below`]), one that lies below one of them.
fn own_folder<'p>(env: &'p Env, call: &Call) -> Option<&'p Path> {
    call.targets
        .iter()
        .map(|t| t.path.as_path())
        .chain(call.cwd)
        .find_map(|p| env.protected.own(p))
        .or_else(|| {
            call.command
                .and_then(|c| env.protected.own_in_command(c, call.cwd))
        })
        .or_else(|| {
            call.targets
                .iter()
                .filter(|_| works_below(call))
                .find_map(|t| env.protected.own_below(&t.path))
        })
}

/// Whether `call` hands its paths to a program that may read or write below
/// them as well: any capability's but the node's own `fs`, whose walks
/// (`grep`, `find`, `list`) skip what a direct call there would be refused,
/// and a command, whose working directory the sandbox and the guard hold.
/// A folder given to such a call counts as everything in it, so whatever
/// lies below it that the call may not touch refuses the call.
fn works_below(call: &Call) -> bool {
    call.cap != crate::rules::FS && call.command.is_none()
}

/// A folder of `folders` strictly below `dir` whose flag does not allow
/// `access`: a call that works below `dir` ([`works_below`]) would reach it.
fn closed_below<'f>(folders: &'f [Folder], dir: &Path, access: PathAccess) -> Option<&'f Folder> {
    folders.iter().find(|f| {
        let path = Path::new(&f.path);
        within(path, dir)
            && !within(dir, path)
            && !match access {
                PathAccess::Read => f.access.read,
                PathAccess::Write => f.access.write,
                PathAccess::Run => f.access.execute,
            }
    })
}

/// Decides `call` under `policy`.
pub fn decide(policy: &CenterPolicy, env: &Env, call: &Call) -> Decision {
    if let Some(c) = call.command
        && c.len() > COMMAND_MAX_BYTES
    {
        return Decision::Forbidden(format!(
            "the command line is {} bytes, longer than the {COMMAND_MAX_BYTES} a node checks",
            c.len()
        ));
    }

    // The node's own folders hold the policy itself and the keys that sign
    // it: no rule, mode or release reaches them, so they come first.
    if let Some(own) = own_folder(env, call) {
        return Decision::Forbidden(format!(
            "{} belongs to the node itself; no rule or mode reaches it",
            own.display()
        ));
    }

    let setting = policy.cap_setting(call.cap, Some(call.action));
    if matches!(setting, Some(CapSetting::Off | CapSetting::Hidden)) {
        return Decision::Disabled(format!("{}.{} is off", call.cap, call.action));
    }

    // The switch is checked before any rule: off, no sudo allow entry makes a
    // sudo command run, because the node has no password to give it.
    let sudo = call.command.is_some_and(|c| sudo_command(c).is_some());
    if sudo && !env.sudo {
        return Decision::Forbidden("sudo is off on this node".into());
    }

    // Deny rules: forbidden in every mode, and they win over any allow.
    let targets = rule_targets(call);
    let deny = RuleSet::new(&policy.deny, env.home).with_shell(env.shell);
    for t in &targets {
        if let Some(rule) = find_rule(&deny, call, t) {
            // The rule as `rule ls` shows it: the guard's hold tabs and line
            // breaks, and a reason is one line in the audit and the log.
            let rule = crate::rules::escape_controls(rule);
            return Decision::Forbidden(format!("{} is denied ({rule})", name(call, &t.text)));
        }
    }
    // A program handed a folder works below it, so a deny rule of its own
    // that covers a place there refuses the folder as well; the node's own
    // walks skip such places instead.
    if works_below(call) {
        for t in targets.iter().filter(|t| t.path) {
            if let Some(rule) = deny.find_below(call.cap, call.action, &t.text) {
                let rule = crate::rules::escape_controls(rule);
                return Decision::Forbidden(format!(
                    "{} holds a place that is denied ({rule})",
                    t.text
                ));
            }
        }
    }

    let mode = policy.mode_at(call.now_ms);
    let mut reasons = Vec::new();
    let mut allowed = if sudo {
        by_sudo_list(policy, call, &mut reasons)
    } else {
        by_mode(policy, env, call, mode, &targets, &mut reasons)
    };
    if !allowed && reasons.is_empty() {
        reasons.push("not allowed".into());
    }

    // Narrowing that holds in every mode.
    // A folder releases a protected path only for the access the call needs
    // there: a read `r`, a write `w`, a command in it `x`.
    for t in call.targets {
        let write = t.access == PathAccess::Write;
        let entry = if t.access == PathAccess::Run {
            env.protected.check_run(&t.path, &policy.folders)
        } else {
            env.protected.check(&t.path, write, &policy.folders)
        };
        // A path handed to a program that works below it reaches what lies
        // there too: a protected entry below it, unless a folder releases
        // that entry, and in `folder` mode a folder below it that the owner
        // gave less. The refusal does not name what lies below: the agent
        // is never shown a closed folder or the owner's extra protected
        // paths, and naming the parent must not tell it them.
        let below = works_below(call) && t.access != PathAccess::Run;
        if below
            && entry.is_none()
            && env
                .protected
                .entry_below(&t.path, write, &policy.folders)
                .is_some()
        {
            allowed = false;
            reasons.push(format!("{} holds a protected path", t.path.display()));
        } else if below
            && mode == Mode::Folder
            && closed_below(&policy.folders, &t.path, t.access).is_some()
        {
            allowed = false;
            reasons.push(format!(
                "{} holds a folder that does not allow {}",
                t.path.display(),
                if write { "writing" } else { "reading" }
            ));
        }
        if let Some(entry) = entry {
            allowed = false;
            reasons.push(format!(
                "{} is protected ({})",
                t.path.display(),
                entry.display()
            ));
        } else if write && let Some(tc) = env.protected.tool_config(&t.path) {
            allowed = false;
            reasons.push(format!("writes to {tc} run code later"));
        }
    }
    // A command runs in its working directory whatever access its call
    // site gave that path, so only `x` releases it.
    if let Some(cwd) = call.cwd
        && !call
            .targets
            .iter()
            .any(|t| t.access == PathAccess::Run && t.path == cwd)
        && let Some(entry) = env.protected.check_run(cwd, &policy.folders)
    {
        allowed = false;
        let why = format!("{} is protected ({})", cwd.display(), entry.display());
        // A target at the same path may have said so already.
        if !reasons.contains(&why) {
            reasons.push(why);
        }
    }

    if allowed {
        Decision::Allow
    } else {
        Decision::Forbidden(reasons.join("; "))
    }
}

/// A sudo command runs only when the sudo allow list names it, in every mode.
fn by_sudo_list(policy: &CenterPolicy, call: &Call, reasons: &mut Vec<String>) -> bool {
    let cmd = call.command.unwrap_or_default();
    // An entry names one command; `sudo apt update; rm -rf /` must not slip
    // through a `sudo apt *` entry with a second command.
    if cmd.trim().contains(SHELL_CONTROL) {
        reasons.push(
            "a sudo command is one simple command (no ; & | $ ` ( ) < > or line breaks)".into(),
        );
        return false;
    }
    // As for the allow rules: a wildcard entry covers no expression the
    // shell runs and no word that starts another one (PowerShell runs the
    // value of `@{a=...}`), only an entry that names the line exactly does.
    // The command runs with full rights, so this holds on every platform.
    let cmd = cmd.trim();
    let wild = command_matches(&policy.sudo_allow, cmd);
    let odd = not_plain(cmd);
    let ok = match &odd {
        None => wild,
        Some(_) => {
            let want = crate::rules::escape(cmd);
            policy.sudo_allow.iter().any(|e| e.trim() == want)
        }
    };
    if !ok {
        reasons.push(match odd.filter(|_| wild) {
            // Words such as `start` start another command (`cmd /c start`,
            // PowerShell's `start` is Start-Process), so a wildcard cannot
            // say what they are handed.
            Some(what) => format!(
                "a wildcard sudo entry does not cover a line with {what}: it covers no expression character, invisible character or word that starts another command; add an entry for the whole line with `nerve-node rule add sudo`, without --wildcard"
            ),
            None => "a sudo command runs only when the sudo allow list names it".into(),
        });
    }
    ok
}

/// `allowlist` mode: every target needs an allow rule.
fn by_allow_rules(
    policy: &CenterPolicy,
    env: &Env,
    call: &Call,
    targets: &[RuleTarget],
    reasons: &mut Vec<String>,
) -> bool {
    let allow = RuleSet::new(&policy.allow, env.home);
    for t in targets {
        // Commands run unconfined here, so a wildcard must not cover a second
        // command chained on or an expression the shell runs: only a rule
        // that names the line exactly does.
        let chained = call.command.is_some() && !plain_command(&t.text);
        let found = if chained {
            allow.find_exact(call.cap, call.action, &t.text)
        } else {
            find_rule(&allow, call, t)
        };
        if found.is_none() {
            reasons.push(if chained && find_rule(&allow, call, t).is_some() {
                format!(
                    "{} chains commands or holds an expression (; & | $ ` ( ) < > @ {{ }} % ' \" # , \\, a line break, or a word such as powershell, cmd, iex or -Command); only an allow rule that names it exactly covers that",
                    name(call, &t.text)
                )
            } else {
                format!("no allow rule matches {}", name(call, &t.text))
            });
            return false;
        }
    }
    true
}

/// What the mode allows, by the effect table ([`effect_rule`]): the allow
/// rules in `allowlist` mode, else the mode itself, where allow rules are not
/// looked at.
fn by_mode(
    policy: &CenterPolicy,
    env: &Env,
    call: &Call,
    mode: Mode,
    targets: &[RuleTarget],
    reasons: &mut Vec<String>,
) -> bool {
    let pathless = call.targets.is_empty() && call.cwd.is_none() && call.command.is_none();
    let outside = if pathless {
        None
    } else {
        outside_folders(policy, call, env.reads)
    };
    // A write that names only paths it reads names no place it writes: the
    // folders cannot say where it writes, so it needs `on` as a write with
    // no path does, and a path it reads outside them still refuses it.
    let writes_nowhere = call.effect == Effect::Write
        && call.command.is_none()
        && !call.targets.iter().any(|t| t.access == PathAccess::Write);
    let paths = if pathless || writes_nowhere && outside.is_none() {
        PathArgs::None
    } else {
        PathArgs::Some {
            all_in_folders: outside.is_none(),
        }
    };
    let setting = policy.cap_setting(call.cap, Some(call.action));
    match effect_rule(mode, call.effect, paths, setting) {
        Need::AllowRule => by_allow_rules(policy, env, call, targets, reasons),
        Need::Allowed => {
            // Folder mode runs a command only where it can be confined to
            // the folders it holds; an action with no path the owner set on
            // holds none.
            let unconfined = (mode == Mode::Folder && call.effect == Effect::Execute && !pathless)
                .then_some(env.unconfined)
                .flatten();
            if let Some(why) = unconfined {
                reasons.push(why.into());
                return false;
            }
            // Where the command account holds what folder mode reads, a path
            // a read call reads in no folder must be one that account may
            // read: the node reads it as that account, a provider with the
            // owner's rights.
            if mode == Mode::Folder
                && call.effect == Effect::Read
                && let Reads::Account(may_read) = env.reads
                && let Some(why) = call
                    .targets
                    .iter()
                    .filter(|t| {
                        t.access == PathAccess::Read
                            && inside_folder(&policy.folders, &t.path).is_none()
                    })
                    .find_map(|t| may_read(&t.path).err())
            {
                reasons.push(why);
                return false;
            }
            true
        }
        Need::NeedsOn => {
            reasons.push(match call.effect {
                Effect::Sense | Effect::Actuate => format!(
                    "{} is allowed only where {}.{} is set to on",
                    call.effect.as_str(),
                    call.cap,
                    call.action
                ),
                _ if pathless => format!(
                    "{}.{} touches no folder; folder mode allows it only where it is set to on",
                    call.cap, call.action
                ),
                _ => format!(
                    "{}.{} names no folder it writes to; folder mode allows it only where it is set to on",
                    call.cap, call.action
                ),
            });
            false
        }
        Need::InFolders => {
            reasons.push(match outside {
                Some(PathAccess::Write) => "outside the folders that allow writing".into(),
                Some(PathAccess::Run) if call.command.is_some() || call.cwd.is_some() => {
                    "the working directory is not in a folder that allows running".into()
                }
                Some(PathAccess::Run) => "outside the folders that allow running".into(),
                _ => "outside the folders that allow reading".into(),
            });
            false
        }
        // `decide` disables such a call before it asks the mode.
        Need::Off => {
            reasons.push(format!("{}.{} is off", call.cap, call.action));
            false
        }
    }
}

/// What `call` does at the first of its paths that lies in no folder
/// allowing it there, or `None` when every one does. A command needs its
/// working directory in a folder with `x`; another execute call (a
/// provider's) runs where its paths are, so each of them needs `x` as well.
/// Every call needs each target in a folder with the flag its access needs
/// (each flag stands alone: writing needs `w` and no `r`, reading `r` and no
/// `w`). A path a read call reads that lies in no folder at all is left to
/// the command account where it holds the read (`reads`, asked by
/// [`by_mode`]); inside a folder the deepest one decides as for every path,
/// and a write or an execute call that reads a path still needs `r` there.
fn outside_folders(policy: &CenterPolicy, call: &Call, reads: Reads) -> Option<PathAccess> {
    let folders = &policy.folders;
    let runs_at = |p: &Path| reaches(folders, p, PathAccess::Run);
    if call.effect == Effect::Execute {
        let command = call.command.is_some() || call.cwd.is_some();
        if command && !call.cwd.is_some_and(runs_at)
            || !command && !call.targets.iter().all(|t| runs_at(&t.path))
        {
            return Some(PathAccess::Run);
        }
    }
    let by_account = call.effect == Effect::Read && matches!(reads, Reads::Account(_));
    call.targets
        .iter()
        .filter(|t| {
            !(by_account
                && t.access == PathAccess::Read
                && inside_folder(folders, &t.path).is_none())
        })
        .find(|t| !reaches(folders, &t.path, t.access))
        .map(|t| t.access)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Access, ProtectedOptions};
    use crate::protected::{Platform, WinFolders};

    const NOW: u64 = 1_000_000;

    /// `mode` with two folders, a denied path and two denied commands.
    fn policy(mode: Mode) -> CenterPolicy {
        CenterPolicy {
            mode,
            folders: vec![
                Folder {
                    path: "/w/ro".into(),
                    access: acc("r"),
                },
                Folder {
                    path: "/w/rw".into(),
                    access: acc("rwx"),
                },
            ],
            deny: vec![
                "fs:/w/rw/secret/*".into(),
                "exec.run:rm -rf /*".into(),
                "exec.run:git push*".into(),
            ],
            ..Default::default()
        }
    }

    fn acc(s: &str) -> Access {
        Access::parse(s).unwrap()
    }

    /// The deepest folder is the one with the most components, not the
    /// longest spelling.
    #[test]
    fn the_deepest_folder_goes_by_components_not_by_length() {
        let folders = [
            Folder {
                path: "/w/a///".into(),
                access: acc("rw"),
            },
            Folder {
                path: "/w/a/b".into(),
                access: acc("r"),
            },
        ];
        assert!(!folder_reach(&folders, Path::new("/w/a/b/x"), true));
        assert!(folder_reach(&folders, Path::new("/w/a/b/x"), false));
        assert!(folder_reach(&folders, Path::new("/w/a/c"), true));
    }

    /// A refusal by a guard rule names the rule, on one line: an older text
    /// of the guard holds tabs and line breaks, and the reason goes into the
    /// audit and the log as it is.
    #[test]
    fn a_refusal_by_the_guard_names_the_rule_on_one_line() {
        let t = T::new();
        let env = t.env(true);
        let mut p = policy(Mode::User);
        for (deny, names) in [
            (crate::rules::GUARD, "is denied (guard:node-"),
            (crate::rules::GUARD_OLD, "is denied (exec.run:"),
        ] {
            p.deny = deny.iter().map(|g| g.to_string()).collect();
            for c in [
                "systemctl stop nerve-node",
                "nerve-node status",
                "pkill nerve-node",
            ] {
                let Decision::Forbidden(why) =
                    decide(&p, &env, &call(Effect::Execute, &[], Some(c)))
                else {
                    panic!("{c} should be refused");
                };
                assert!(why.contains(names), "{why}");
                assert!(!why.contains(['\n', '\r', '\t']), "{why:?}");
            }
        }
    }

    /// The guard reads a line by the rules of the node's shell: a quoted
    /// mention in PowerShell is text, and a line it cannot read is checked
    /// with the guard's text patterns.
    #[test]
    fn the_guard_reads_the_line_in_the_nodes_shell() {
        let t = T::new();
        let mut p = policy(Mode::User);
        p.deny = crate::rules::GUARD.iter().map(|g| g.to_string()).collect();
        let refused = |shell: Shell, c: &str| {
            let env = Env {
                shell,
                ..t.env(true)
            };
            matches!(
                decide(&p, &env, &call(Effect::Execute, &[], Some(c))),
                Decision::Forbidden(_)
            )
        };
        // In PowerShell a backtick escapes the quote, so the mention stays
        // inside it; sh reads the same line as a quote that ends early.
        let line = "echo \"a`\"; Stop-Service nerve-node\"";
        assert!(!refused(Shell::PowerShell, line));
        assert!(refused(Shell::Sh, "echo \"a\"; Stop-Service nerve-node"));
        assert!(refused(Shell::Sh, "systemctl stop nerve-node; echo \"open"));
        assert!(!refused(Shell::Sh, "echo \"open"));
    }

    /// The effect table for an action that names no path (a provider's, or
    /// one whose marked paths the call left out): folder mode allows it only
    /// where the owner set it on, whatever its effect, as the folders cannot
    /// hold it; user mode allows read, write and execute as
    /// for the built-in capabilities; allowlist mode needs an allow rule on
    /// `cap.action`. A deny rule wins in every mode.
    #[test]
    fn the_effect_table() {
        let t = T::new();
        let env = t.env(true);
        let decide_as = |policy: &CenterPolicy, effect| {
            let call = Call {
                cap: "echo",
                action: "say",
                effect,
                targets: &[],
                command: None,
                cwd: None,
                now_ms: NOW,
            };
            decide(policy, &env, &call)
        };
        let effects = [
            Effect::Read,
            Effect::Write,
            Effect::Execute,
            Effect::Sense,
            Effect::Actuate,
        ];
        for effect in effects {
            let mut p = policy(Mode::Folder);
            let Decision::Forbidden(why) = decide_as(&p, effect) else {
                panic!("{effect:?} passed folder mode without on");
            };
            assert!(why.contains("echo.say"), "{why}");
            p.caps.insert("echo.say".into(), CapSetting::On);
            assert_eq!(decide_as(&p, effect), Decision::Allow, "{effect:?}");
            // A deny rule still wins.
            p.deny.push("echo".into());
            assert!(matches!(decide_as(&p, effect), Decision::Forbidden(_)));

            let mut p = policy(Mode::User);
            let quiet = matches!(effect, Effect::Sense | Effect::Actuate);
            assert_eq!(
                decide_as(&p, effect) == Decision::Allow,
                !quiet,
                "{effect:?}"
            );
            p.caps.insert("echo".into(), CapSetting::On);
            assert_eq!(decide_as(&p, effect), Decision::Allow, "{effect:?}");
            p.deny.push("echo.say".into());
            assert!(matches!(decide_as(&p, effect), Decision::Forbidden(_)));

            let mut p = policy(Mode::Allowlist);
            assert!(matches!(decide_as(&p, effect), Decision::Forbidden(_)));
            p.allow.push("echo.say".into());
            assert_eq!(decide_as(&p, effect), Decision::Allow, "{effect:?}");
            p.allow = vec!["echo.shout".into()];
            assert!(matches!(decide_as(&p, effect), Decision::Forbidden(_)));
        }
    }

    /// The effect table, cell by cell as policy-engine.md gives it, and
    /// `decide` following it for every effect, mode, `on`, allow rule,
    /// confinement and hold on reads: with no path, with its paths in the
    /// folders, and with one outside them. Where the command account holds
    /// the reads, a read call's path in no folder counts as in them if that
    /// account may read it, and is refused if it may not; a path inside the
    /// folders is theirs to decide.
    #[test]
    fn every_call_is_decided_by_the_effect_table() {
        use Need::{AllowRule, Allowed, InFolders, NeedsOn};
        // (mode, effect, no path, paths in the folders, a path outside)
        #[rustfmt::skip]
        let table = [
            (Mode::Allowlist, Effect::Read, AllowRule, AllowRule, AllowRule),
            (Mode::Allowlist, Effect::Write, AllowRule, AllowRule, AllowRule),
            (Mode::Allowlist, Effect::Execute, AllowRule, AllowRule, AllowRule),
            (Mode::Allowlist, Effect::Sense, AllowRule, AllowRule, AllowRule),
            (Mode::Allowlist, Effect::Actuate, AllowRule, AllowRule, AllowRule),
            (Mode::Folder, Effect::Read, NeedsOn, Allowed, InFolders),
            (Mode::Folder, Effect::Write, NeedsOn, Allowed, InFolders),
            (Mode::Folder, Effect::Execute, NeedsOn, Allowed, InFolders),
            (Mode::Folder, Effect::Sense, NeedsOn, NeedsOn, InFolders),
            (Mode::Folder, Effect::Actuate, NeedsOn, NeedsOn, InFolders),
            (Mode::User, Effect::Read, Allowed, Allowed, Allowed),
            (Mode::User, Effect::Write, Allowed, Allowed, Allowed),
            (Mode::User, Effect::Execute, Allowed, Allowed, Allowed),
            (Mode::User, Effect::Sense, NeedsOn, NeedsOn, NeedsOn),
            (Mode::User, Effect::Actuate, NeedsOn, NeedsOn, NeedsOn),
        ];
        let may = |_: &Path| Ok(());
        let may_not = |p: &Path| Err(format!("may not read {}", p.display()));
        let holds = [
            Reads::Folders,
            Reads::Account(&may),
            Reads::Account(&may_not),
        ];
        let x = T::new();
        for (mode, effect, none, inside, outside) in table {
            let p = policy(mode);
            // A path in the rwx folder, or one outside every folder; a
            // command runs in it.
            let at = |path: &str| {
                vec![Target {
                    path: path.into(),
                    access: match effect {
                        Effect::Write => PathAccess::Write,
                        Effect::Execute => PathAccess::Run,
                        _ => PathAccess::Read,
                    },
                }]
            };
            let (inside_t, outside_t) = (at("/w/rw/a"), at("/elsewhere/a"));
            let cells = [
                (PathArgs::None, none, &[][..]),
                (
                    PathArgs::Some {
                        all_in_folders: true,
                    },
                    inside,
                    &inside_t[..],
                ),
                (
                    PathArgs::Some {
                        all_in_folders: false,
                    },
                    outside,
                    &outside_t[..],
                ),
            ];
            for (paths, need, targets) in cells {
                let what = format!("{mode:?} {effect:?} {paths:?}");
                assert_eq!(effect_rule(mode, effect, paths, None), need, "{what}");
                // `on` allows what needs only `on`, and widens nothing else.
                let with_on = if need == NeedsOn { Allowed } else { need };
                let on = Some(CapSetting::On);
                assert_eq!(effect_rule(mode, effect, paths, on), with_on, "{what}");
                // A switched-off action is allowed in no cell.
                for off in [CapSetting::Off, CapSetting::Hidden] {
                    assert_eq!(
                        effect_rule(mode, effect, paths, Some(off)),
                        Need::Off,
                        "{what}"
                    );
                }
                for (setting, reads) in [None, on]
                    .into_iter()
                    .flat_map(|s| holds.iter().map(move |r| (s, *r)))
                {
                    for allow in [&[][..], &["echo.say"][..], &["echo"][..], &["echo.x"][..]] {
                        for confined in [true, false] {
                            let mut p = p.clone();
                            p.allow = rules(allow);
                            if setting.is_some() {
                                p.caps.insert("echo.say".into(), CapSetting::On);
                            }
                            let command = targets.first().filter(|_| effect == Effect::Execute);
                            let call = Call {
                                cap: "echo",
                                action: "say",
                                effect,
                                targets,
                                command: command.map(|_| "make"),
                                cwd: command.map(|t| t.path.as_path()),
                                now_ms: NOW,
                            };
                            // A read call's path in no folder that the
                            // account holds counts as in the folders.
                            let account = matches!(reads, Reads::Account(_));
                            let paths = match paths {
                                PathArgs::Some { .. } if account && effect == Effect::Read => {
                                    PathArgs::Some {
                                        all_in_folders: true,
                                    }
                                }
                                paths => paths,
                            };
                            let want = match effect_rule(mode, effect, paths, setting) {
                                // A command in folder mode also needs to be
                                // confined; an action with no path is none.
                                // A path a read call reads in no folder, where
                                // the account holds reads, must be one it may
                                // read.
                                Allowed => {
                                    (confined
                                        || mode != Mode::Folder
                                        || effect != Effect::Execute
                                        || paths == PathArgs::None)
                                        && !(mode == Mode::Folder
                                            && effect == Effect::Read
                                            && matches!(reads, Reads::Account(f) if f(Path::new("/")).is_err())
                                            && targets.iter().any(|t| {
                                                inside_folder(&p.folders, &t.path).is_none()
                                            }))
                                }
                                AllowRule => matches!(allow, ["echo.say"] | ["echo"]),
                                InFolders | NeedsOn | Need::Off => false,
                            };
                            let env = Env {
                                reads,
                                ..x.env(confined)
                            };
                            let d = decide(&p, &env, &call);
                            assert_eq!(
                                d == Decision::Allow,
                                want,
                                "{what} {setting:?} {reads:?} {allow:?} confined={confined}: {d:?}"
                            );
                        }
                    }
                }
            }
        }
    }

    /// A call of `notes.<action>` with `effect` at `targets`: a provider's
    /// action whose schema marks its paths.
    fn marked<'a>(action: &'a str, effect: Effect, targets: &'a [Target]) -> Call<'a> {
        Call {
            cap: "notes",
            action,
            effect,
            targets,
            command: None,
            cwd: None,
            now_ms: NOW,
        }
    }

    /// Where the folders hold what folder mode reads, a path read outside
    /// the folders with `r` is refused, `on` or not. Where the command
    /// account holds it, a read in no folder goes as far as that account may
    /// read, and no further, while the folders still decide inside them; a
    /// write or a command that reads a path still needs `r` there, and
    /// protected paths and deny rules win either way.
    #[test]
    fn a_read_path_outside_the_r_folders_is_refused() {
        let x = T::new();
        let folders = x.env(true);
        let may = |_: &Path| Ok(());
        let may_not = |p: &Path| Err(format!("not open to every account: {}", p.display()));
        let account = Env {
            reads: Reads::Account(&may),
            ..x.env(true)
        };
        let closed = Env {
            reads: Reads::Account(&may_not),
            ..x.env(true)
        };
        let mut p = policy(Mode::Folder);
        let outside = t("/elsewhere/a", false);
        let in_ro = t("/w/ro/a", false);
        assert_eq!(
            decide(&p, &folders, &marked("open", Effect::Read, &outside)),
            Decision::Forbidden("outside the folders that allow reading".into())
        );
        assert_eq!(
            decide(&p, &folders, &marked("open", Effect::Read, &in_ro)),
            Decision::Allow
        );
        p.caps.insert("notes".into(), CapSetting::On);
        assert_eq!(
            run(&p, &folders, &marked("open", Effect::Read, &outside)),
            "refused"
        );
        // The account holds it: in no folder, as far as it may read.
        assert_eq!(
            decide(&p, &account, &marked("open", Effect::Read, &outside)),
            Decision::Allow
        );
        assert_eq!(
            decide(&p, &closed, &marked("open", Effect::Read, &outside)),
            Decision::Forbidden("not open to every account: /elsewhere/a".into())
        );
        // Inside the folders the account is not asked: the folder decides,
        // and the node reads there as the account all the same.
        assert_eq!(
            decide(&p, &closed, &marked("open", Effect::Read, &in_ro)),
            Decision::Allow
        );
        // A write that reads a path still needs `r` for it.
        let both = [
            Target {
                path: "/w/rw/out".into(),
                access: PathAccess::Write,
            },
            Target {
                path: "/elsewhere/a".into(),
                access: PathAccess::Read,
            },
        ];
        assert_eq!(
            decide(&p, &account, &marked("copy", Effect::Write, &both)),
            Decision::Forbidden("outside the folders that allow reading".into())
        );
        // Protected paths and deny rules win.
        let key = t("/h/.ssh/id_rsa", false);
        assert_eq!(
            run(&p, &account, &marked("open", Effect::Read, &key)),
            "refused"
        );
        p.deny.push("notes.open:/elsewhere/*".into());
        assert_eq!(
            run(&p, &account, &marked("open", Effect::Read, &outside)),
            "refused"
        );
        // The other modes do not ask the account.
        for mode in [Mode::User, Mode::Allowlist] {
            let mut p = policy(mode);
            p.allow = rules(&["notes"]);
            assert_eq!(
                run(&p, &closed, &marked("open", Effect::Read, &outside)),
                "allow",
                "{mode:?}"
            );
        }
    }

    /// A write's paths must each lie in a folder with `w`; `on` does not
    /// widen that.
    #[test]
    fn a_write_with_paths_outside_the_folders_is_refused_even_with_on() {
        let x = T::new();
        let env = x.env(true);
        let mut p = policy(Mode::Folder);
        p.caps.insert("notes.save".into(), CapSetting::On);
        for (path, want) in [
            ("/w/rw/a", Decision::Allow),
            (
                "/w/ro/a",
                Decision::Forbidden("outside the folders that allow writing".into()),
            ),
            (
                "/elsewhere/a",
                Decision::Forbidden("outside the folders that allow writing".into()),
            ),
        ] {
            let at = t(path, true);
            assert_eq!(
                decide(&p, &env, &marked("save", Effect::Write, &at)),
                want,
                "{path}"
            );
        }
        // One path outside among several in the folders is refused too.
        let mut two = t("/w/rw/a", true);
        two.extend(t("/elsewhere/b", true));
        assert_eq!(
            run(&p, &env, &marked("save", Effect::Write, &two)),
            "refused"
        );
    }

    /// An execute action that is no command (a provider's) runs where its
    /// paths are: each needs a folder with `x` besides the flag for what it
    /// does there.
    #[test]
    fn an_execute_action_with_paths_needs_them_in_folders_that_allow_running() {
        let x = T::new();
        let env = x.env(true);
        let mut p = policy(Mode::Folder);
        p.folders.push(Folder {
            path: "/w/rwonly".into(),
            access: acc("rw"),
        });
        let running = Decision::Forbidden("outside the folders that allow running".into());
        for (target, want) in [
            (t("/w/rw/src", true), Decision::Allow),
            (t("/w/rw/src", false), Decision::Allow),
            (t("/w/rwonly/src", true), running.clone()),
            (t("/w/ro/src", false), running.clone()),
            (t("/elsewhere/src", false), running),
        ] {
            assert_eq!(
                decide(&p, &env, &marked("build", Effect::Execute, &target)),
                want,
                "{target:?}"
            );
        }
        // `x` alone does not let it write there.
        p.folders = vec![Folder {
            path: "/w/x".into(),
            access: acc("x"),
        }];
        assert_eq!(
            decide(
                &p,
                &env,
                &marked("build", Effect::Execute, &t("/w/x/out", true))
            ),
            Decision::Forbidden("outside the folders that allow writing".into())
        );
    }

    /// A write or a command that names no path passes no folder check:
    /// it needs `on`, which allows it then.
    #[test]
    fn zero_path_write_needs_on() {
        let x = T::new();
        let env = x.env(true);
        for effect in [Effect::Write, Effect::Execute] {
            let mut p = policy(Mode::Folder);
            let c = marked("save", effect, &[]);
            assert_eq!(
                decide(&p, &env, &c),
                Decision::Forbidden(
                    "notes.save touches no folder; folder mode allows it only where it is set to on"
                        .into()
                ),
                "{effect:?}"
            );
            p.caps.insert("notes.save".into(), CapSetting::On);
            assert_eq!(decide(&p, &env, &c), Decision::Allow, "{effect:?}");
        }
    }

    /// `on` lets a sense or actuate action run in folder mode, and its
    /// paths stay in the folders as any call's: one outside them refuses
    /// it, `on` or not.
    #[test]
    fn a_sense_or_actuate_path_stays_in_the_folders_with_on() {
        let x = T::new();
        let env = x.env(true);
        for effect in [Effect::Sense, Effect::Actuate] {
            let mut p = policy(Mode::Folder);
            p.caps.insert("notes".into(), CapSetting::On);
            assert_eq!(
                decide(&p, &env, &marked("snap", effect, &t("/w/rw/a", true))),
                Decision::Allow,
                "{effect:?}"
            );
            assert_eq!(
                decide(&p, &env, &marked("snap", effect, &t("/elsewhere/a", true))),
                Decision::Forbidden("outside the folders that allow writing".into()),
                "{effect:?}"
            );
            assert_eq!(
                decide(&p, &env, &marked("snap", effect, &t("/elsewhere/a", false))),
                Decision::Forbidden("outside the folders that allow reading".into()),
                "{effect:?}"
            );
            // In user mode the folders hold nothing: `on` decides.
            p.mode = Mode::User;
            assert_eq!(
                decide(&p, &env, &marked("snap", effect, &t("/elsewhere/a", true))),
                Decision::Allow,
                "{effect:?}"
            );
        }
    }

    /// A folder the owner closed (no flag, or no `r`) inside a folder with
    /// `r` stays closed to reads where the command account holds them: the
    /// deepest folder decides, though the account may read there. A walk
    /// asks the same ([`read_reach`]).
    #[test]
    fn a_closed_folder_stays_closed_where_the_account_holds_reads() {
        let x = T::new();
        let may = |_: &Path| Ok(());
        let account = Env {
            reads: Reads::Account(&may),
            ..x.env(true)
        };
        let mut p = policy(Mode::Folder);
        p.deny.clear();
        p.folders.push(Folder {
            path: "/w/rw/secret".into(),
            access: Access::NONE,
        });
        p.folders.push(Folder {
            path: "/w/rw/drop".into(),
            access: acc("w"),
        });
        for path in ["/w/rw/secret/prod.env", "/w/rw/drop/a"] {
            let at = t(path, false);
            for c in [fs_read(&at), marked("open", Effect::Read, &at)] {
                assert_eq!(
                    decide(&p, &account, &c),
                    Decision::Forbidden("outside the folders that allow reading".into()),
                    "{path}"
                );
            }
            assert!(!read_reach(&p.folders, Path::new(path), account.reads));
        }
        for path in ["/w/rw/a", "/elsewhere/a"] {
            assert_eq!(
                decide(&p, &account, &fs_read(&t(path, false))),
                Decision::Allow
            );
            assert!(read_reach(&p.folders, Path::new(path), account.reads));
        }
        // Where the folders hold reads, a path in no folder is not read.
        assert!(!read_reach(
            &p.folders,
            Path::new("/elsewhere/a"),
            Reads::Folders
        ));
    }

    /// A write that names only paths it reads names no place it writes: it
    /// needs `on` as a write with no path does, and its read paths stay in
    /// the `r` folders with `on`.
    #[test]
    fn a_write_that_names_only_read_paths_needs_on() {
        let x = T::new();
        let env = x.env(true);
        let mut p = policy(Mode::Folder);
        let from = t("/w/ro/a.md", false);
        assert_eq!(
            decide(&p, &env, &marked("import", Effect::Write, &from)),
            Decision::Forbidden(
                "notes.import names no folder it writes to; folder mode allows it only where it is set to on"
                    .into()
            )
        );
        p.caps.insert("notes.import".into(), CapSetting::On);
        assert_eq!(
            decide(&p, &env, &marked("import", Effect::Write, &from)),
            Decision::Allow
        );
        assert_eq!(
            decide(
                &p,
                &env,
                &marked("import", Effect::Write, &t("/elsewhere/a.md", false))
            ),
            Decision::Forbidden("outside the folders that allow reading".into())
        );
    }

    /// A path handed to a provider counts with what lies below it, which the
    /// provider may read or write as it likes: a folder that holds the
    /// node's own folders, a protected entry no folder releases, or in
    /// folder mode a folder the owner gave less is refused. The node's own
    /// `fs` walks skip such places instead, so its calls are not refused.
    #[test]
    fn a_folder_handed_to_a_provider_counts_with_what_lies_below_it() {
        let prot = Protected::new(
            &Platform::Unix,
            Path::new("/h"),
            &[PathBuf::from("/h/.config/nerve")],
            &ProtectedOptions::default(),
        );
        let x = T::new();
        let env = Env {
            protected: &prot,
            ..x.env(true)
        };
        let mut p = policy(Mode::Folder);
        p.folders = vec![
            Folder {
                path: "/h".into(),
                access: acc("rw"),
            },
            Folder {
                path: "/h/proj/secret".into(),
                access: acc("w"),
            },
        ];
        let home = t("/h", false);
        let Decision::Forbidden(why) = decide(&p, &env, &marked("search", Effect::Read, &home))
        else {
            panic!("a folder holding the node's own was handed over");
        };
        assert!(
            why.contains("/h/.config/nerve belongs to the node"),
            "{why}"
        );
        // Without the own folder below it, a protected entry (`.ssh` and
        // the like) refuses it.
        let env = x.env(true);
        let Decision::Forbidden(why) = decide(&p, &env, &marked("search", Effect::Read, &home))
        else {
            panic!("a folder holding a protected entry was handed over");
        };
        assert_eq!(why, "/h holds a protected path");
        // A folder with less below it.
        let proj = t("/h/proj", false);
        assert_eq!(
            decide(&p, &env, &marked("search", Effect::Read, &proj)),
            Decision::Forbidden("/h/proj holds a folder that does not allow reading".into())
        );
        assert_eq!(
            decide(
                &p,
                &env,
                &marked("save", Effect::Write, &t("/h/proj", true))
            ),
            Decision::Allow
        );
        assert_eq!(
            decide(
                &p,
                &env,
                &marked("search", Effect::Read, &t("/h/proj/other", false))
            ),
            Decision::Allow
        );
        // The node's own walks skip such places, so `fs` is not refused.
        assert_eq!(decide(&p, &env, &fs_read(&home)), Decision::Allow);
        // A folder that releases the protected entry for reads lets it be
        // read, and only read.
        let prot = Protected::new(
            &Platform::Unix,
            Path::new("/h"),
            &[],
            &ProtectedOptions {
                extra: vec!["/data/keys".into()],
                ..Default::default()
            },
        );
        let env = Env {
            protected: &prot,
            ..x.env(true)
        };
        p.folders = vec![Folder {
            path: "/data".into(),
            access: acc("rw"),
        }];
        let data = t("/data", false);
        assert_eq!(
            decide(&p, &env, &marked("search", Effect::Read, &data)),
            Decision::Forbidden("/data holds a protected path".into())
        );
        p.folders.push(Folder {
            path: "/data/keys".into(),
            access: acc("r"),
        });
        assert_eq!(
            decide(&p, &env, &marked("search", Effect::Read, &data)),
            Decision::Allow
        );
        assert_eq!(
            decide(&p, &env, &marked("save", Effect::Write, &t("/data", true))),
            Decision::Forbidden("/data holds a protected path".into())
        );
    }

    /// A path argument of any action meets the rules as an `fs` path does:
    /// `~/` is the owner's home, and on Windows a path rule ignores case.
    #[test]
    fn a_deny_rule_with_tilde_covers_a_provider_path() {
        let x = T::new();
        let env = x.env(true);
        let secret = t("/h/secret/k", false);
        let other = t("/h/other", false);
        let mut p = policy(Mode::User);
        p.deny = rules(&["notes:~/secret/*"]);
        assert_eq!(
            decide(&p, &env, &marked("open", Effect::Read, &secret)),
            Decision::Forbidden("/h/secret/k is denied (notes:~/secret/*)".into())
        );
        assert_eq!(
            run(&p, &env, &marked("open", Effect::Read, &other)),
            "allow"
        );
        // An action that names no path is not a path, and one rule of an
        // action covers no other.
        p.deny = rules(&["notes.save:~/*"]);
        assert_eq!(
            run(&p, &env, &marked("open", Effect::Read, &secret)),
            "allow"
        );
        // Allow rules read it the same way.
        let mut p = policy(Mode::Allowlist);
        p.allow = rules(&["notes.open:~/secret/*"]);
        assert_eq!(
            run(&p, &env, &marked("open", Effect::Read, &secret)),
            "allow"
        );
        assert_eq!(
            run(&p, &env, &marked("open", Effect::Read, &other)),
            "refused"
        );
        // NTFS ignores case, and so does a path rule on Windows.
        let mut p = policy(Mode::User);
        p.deny = rules(&["notes:~/SECRET/*"]);
        assert_eq!(
            run(&p, &env, &marked("open", Effect::Read, &secret)),
            if cfg!(windows) { "refused" } else { "allow" }
        );
    }

    /// A deny rule of a capability holds below a folder handed to it: the
    /// program works there, so the folder above the denied place is refused
    /// too, in every mode, for reads and writes. The node's own `fs` walks
    /// skip the denied place instead.
    #[test]
    fn a_deny_rule_holds_below_a_folder_handed_to_a_provider() {
        let x = T::new();
        let env = x.env(true);
        let mut p = policy(Mode::Folder);
        p.folders = vec![
            Folder {
                path: "/h/work".into(),
                access: acc("r"),
            },
            Folder {
                path: "/h/proj".into(),
                access: acc("rw"),
            },
        ];
        p.deny = rules(&["notes:/h/work/clients/*", "notes.save:~/proj/keep/*"]);
        let denied = |p: &CenterPolicy, c: &Call| match decide(p, &env, c) {
            Decision::Forbidden(why) => why,
            d => panic!("{d:?}"),
        };
        assert_eq!(
            denied(
                &p,
                &marked("search", Effect::Read, &t("/h/work/clients/a.txt", false))
            ),
            "/h/work/clients/a.txt is denied (notes:/h/work/clients/*)"
        );
        let work = t("/h/work", false);
        assert_eq!(
            denied(&p, &marked("search", Effect::Read, &work)),
            "/h/work holds a place that is denied (notes:/h/work/clients/*)"
        );
        let proj = t("/h/proj", true);
        assert_eq!(
            denied(&p, &marked("save", Effect::Write, &proj)),
            "/h/proj holds a place that is denied (notes.save:~/proj/keep/*)"
        );
        // Beside the denied place, and for another capability, it holds no more.
        assert_eq!(
            run(
                &p,
                &env,
                &marked("search", Effect::Read, &t("/h/work/other", false))
            ),
            "allow"
        );
        assert_eq!(run(&p, &env, &fs_read(&work)), "allow");
        // An allow rule above the denied place does not let it through.
        p.mode = Mode::Allowlist;
        p.allow = rules(&["notes.search:/h/work/*"]);
        assert_eq!(
            run(&p, &env, &marked("search", Effect::Read, &work)),
            "refused"
        );
    }

    const MODES: [Mode; 3] = [Mode::Allowlist, Mode::Folder, Mode::User];

    struct T {
        prot: Protected,
    }

    impl T {
        fn new() -> T {
            T {
                prot: Protected::new(
                    &Platform::Unix,
                    Path::new("/h"),
                    &[],
                    &ProtectedOptions::default(),
                ),
            }
        }

        fn env(&self, confined: bool) -> Env<'_> {
            Env {
                home: Path::new("/h"),
                protected: &self.prot,
                unconfined: (!confined).then_some("commands cannot be confined on this machine"),
                sudo: false,
                shell: Shell::Sh,
                reads: Reads::Folders,
            }
        }

        fn sudo_on(&self) -> Env<'_> {
            Env {
                sudo: true,
                ..self.env(true)
            }
        }
    }

    fn call<'a>(effect: Effect, targets: &'a [Target], command: Option<&'a str>) -> Call<'a> {
        Call {
            cap: if effect == Effect::Execute {
                "exec"
            } else {
                "fs"
            },
            action: match effect {
                Effect::Execute => "run",
                Effect::Write => "write",
                _ => "read",
            },
            effect,
            targets,
            command,
            cwd: command.and(targets.first().map(|t| t.path.as_path())),
            now_ms: NOW,
        }
    }

    /// A call of another capability, with no path and no command.
    fn action<'a>(effect: Effect, cap: &'a str, action: &'a str) -> Call<'a> {
        Call {
            cap,
            action,
            effect,
            targets: &[],
            command: None,
            cwd: None,
            now_ms: NOW,
        }
    }

    /// An `fs.read` of `targets`.
    fn fs_read(targets: &[Target]) -> Call<'_> {
        call(Effect::Read, targets, None)
    }

    fn t(p: &str, write: bool) -> Vec<Target> {
        vec![Target {
            path: p.into(),
            access: if write {
                PathAccess::Write
            } else {
                PathAccess::Read
            },
        }]
    }

    /// The working directory of a command.
    fn cwd_at(p: &str) -> Vec<Target> {
        vec![Target {
            path: p.into(),
            access: PathAccess::Run,
        }]
    }

    fn short(d: &Decision) -> &'static str {
        match d {
            Decision::Allow => "allow",
            Decision::Forbidden(_) => "refused",
            Decision::Disabled(_) => "disabled",
        }
    }

    fn run(p: &CenterPolicy, env: &Env, c: &Call) -> &'static str {
        short(&decide(p, env, c))
    }

    fn rules(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn folder_and_user_mode_matrix() {
        let x = T::new();
        let env = x.env(true);
        let inside_ro = t("/w/ro/a", false);
        let inside_rw_w = t("/w/rw/a", true);
        let ro_w = t("/w/ro/a", true);
        let outside = t("/elsewhere/a", false);
        let exec_in = cwd_at("/w/rw");
        let exec_ro = cwd_at("/w/ro");
        let denied = t("/w/rw/secret/k", false);
        let key = t("/h/.ssh/id_rsa", false);
        let hook = t("/w/rw/.git/hooks/x", true);
        // (mode, effect, targets, command, expected)
        type Case<'a> = (Mode, Effect, &'a [Target], Option<&'a str>, &'a str);
        let cases: Vec<Case> = vec![
            (Mode::Folder, Effect::Read, &inside_ro, None, "allow"),
            (Mode::Folder, Effect::Read, &outside, None, "refused"),
            (Mode::Folder, Effect::Write, &inside_rw_w, None, "allow"),
            (Mode::Folder, Effect::Write, &ro_w, None, "refused"),
            (
                Mode::Folder,
                Effect::Execute,
                &exec_in,
                Some("make"),
                "allow",
            ),
            (
                Mode::Folder,
                Effect::Execute,
                &exec_ro,
                Some("make"),
                "refused",
            ),
            (Mode::Folder, Effect::Sense, &[], None, "refused"),
            (Mode::Folder, Effect::Actuate, &[], None, "refused"),
            (Mode::User, Effect::Read, &outside, None, "allow"),
            (Mode::User, Effect::Write, &ro_w, None, "allow"),
            (Mode::User, Effect::Execute, &exec_ro, Some("make"), "allow"),
            (Mode::User, Effect::Sense, &[], None, "refused"),
            (Mode::User, Effect::Actuate, &[], None, "refused"),
            // Deny rules on commands.
            (
                Mode::User,
                Effect::Execute,
                &exec_in,
                Some("git push origin"),
                "refused",
            ),
            (
                Mode::Folder,
                Effect::Execute,
                &exec_in,
                Some("git push origin"),
                "refused",
            ),
            (
                Mode::User,
                Effect::Execute,
                &exec_in,
                Some("rm -rf /home"),
                "refused",
            ),
            // Denied paths, in every mode.
            (Mode::User, Effect::Read, &denied, None, "refused"),
            (Mode::Folder, Effect::Read, &denied, None, "refused"),
            // Protected paths are refused, also in user mode.
            (Mode::User, Effect::Read, &key, None, "refused"),
            (Mode::User, Effect::Write, &hook, None, "refused"),
        ];
        for (mode, effect, targets, cmd, want) in cases {
            let p = policy(mode);
            let d = decide(&p, &env, &call(effect, targets, cmd));
            assert_eq!(
                short(&d),
                want,
                "{mode:?} {effect:?} {targets:?} {cmd:?}: {d:?}"
            );
        }
        // Folder mode without confinement refuses commands.
        let d = decide(
            &policy(Mode::Folder),
            &x.env(false),
            &call(Effect::Execute, &exec_in, Some("make")),
        );
        assert_eq!(short(&d), "refused");
        // The refusal names the node's reason.
        let why = "kept off by the keyring";
        let d = decide(
            &policy(Mode::Folder),
            &Env {
                unconfined: Some(why),
                ..x.env(false)
            },
            &call(Effect::Execute, &exec_in, Some("make")),
        );
        assert!(
            matches!(&d, Decision::Forbidden(m) if m.contains(why)),
            "{d:?}"
        );
        // A limit that is still running changes nothing; one that has run out
        // leaves default deny, so a read in a folder needs a rule again.
        for mode in [Mode::Folder, Mode::User] {
            let mut p = policy(mode);
            p.until = Some(NOW + 1);
            let read = call(Effect::Read, &inside_ro, None);
            assert_eq!(run(&p, &env, &read), "allow", "{mode:?}");
            p.until = Some(NOW);
            assert_eq!(run(&p, &env, &read), "refused", "{mode:?}");
            p.allow = vec!["fs:/w/ro/*".into()];
            assert_eq!(run(&p, &env, &read), "allow", "{mode:?}");
        }
    }

    /// In user mode the owner's folder at a protected entry releases it only
    /// for what its flags give: `r` on `~/.ssh` lets a call read there, but
    /// neither write `authorized_keys` nor run a command in it.
    #[test]
    fn a_release_in_user_mode_gives_only_its_folders_access() {
        let x = T::new();
        let env = x.env(true);
        let keys_w = t("/h/.ssh/authorized_keys", true);
        let config_r = t("/h/.ssh/config", false);
        let ssh = cwd_at("/h/.ssh");
        let owner = |access: &str| CenterPolicy {
            mode: Mode::User,
            folders: vec![Folder {
                path: "/h/.ssh".into(),
                access: acc(access),
            }],
            ..Default::default()
        };
        let cases = [
            ("r", call(Effect::Write, &keys_w, None), "refused"),
            ("r", call(Effect::Read, &config_r, None), "allow"),
            ("r", call(Effect::Execute, &ssh, Some("ls")), "refused"),
            ("rw", call(Effect::Write, &keys_w, None), "allow"),
            ("rw", call(Effect::Read, &config_r, None), "allow"),
            ("w", call(Effect::Read, &config_r, None), "refused"),
            ("rx", call(Effect::Execute, &ssh, Some("ls")), "allow"),
        ];
        for (access, c, want) in cases {
            let d = decide(&owner(access), &env, &c);
            assert_eq!(
                short(&d),
                want,
                "{access} {} {:?}: {d:?}",
                c.action,
                c.targets
            );
        }
        // The rest of the place stays protected: a narrower folder inside
        // the release decides for what it holds.
        let mut p = owner("rw");
        p.folders.push(Folder {
            path: "/h/.ssh/keep".into(),
            access: acc("r"),
        });
        let keep_w = t("/h/.ssh/keep/x", true);
        assert_eq!(
            run(&p, &env, &call(Effect::Write, &keep_w, None)),
            "refused"
        );
    }

    /// A folder releases a protected path for what the call does at that
    /// path, not for the call's effect: a path a command only reads is
    /// released by `r`, the place a call runs in only by `x`.
    #[test]
    fn a_release_follows_what_the_call_does_at_each_path() {
        let x = T::new();
        let env = x.env(true);
        let p = CenterPolicy {
            mode: Mode::User,
            folders: vec![Folder {
                path: "/h/.ssh".into(),
                access: acc("r"),
            }],
            ..Default::default()
        };
        let at = |path: &str, access| Target {
            path: path.into(),
            access,
        };
        let read_there = [
            at("/h/.ssh/config", PathAccess::Read),
            at("/w", PathAccess::Run),
        ];
        let c = Call {
            cwd: Some(Path::new("/w")),
            ..call(Effect::Execute, &read_there, Some("ls"))
        };
        assert_eq!(run(&p, &env, &c), "allow");
        let run_there = [at("/h/.ssh", PathAccess::Run)];
        assert_eq!(
            run(&p, &env, &call(Effect::Read, &run_there, None)),
            "refused"
        );
        // A command runs in its working directory whatever access its call
        // site gave that path, or none: `r` does not release it.
        let cwd_as_read = [at("/h/.ssh", PathAccess::Read)];
        // The protected entry is joined from parts, so Windows shows it with
        // its own separator.
        let protected_text = format!(
            "/h/.ssh is protected ({})",
            Path::new("/h").join(".ssh").display()
        );
        for targets in [&cwd_as_read[..], &[][..]] {
            let c = Call {
                cwd: Some(Path::new("/h/.ssh")),
                ..call(Effect::Execute, targets, Some("ls"))
            };
            assert_eq!(run(&p, &env, &c), "refused", "{targets:?}");
            let d = decide(&p, &env, &c);
            assert_eq!(
                d,
                Decision::Forbidden(protected_text.clone()),
                "{targets:?}"
            );
            // `x` does.
            let mut p = p.clone();
            p.folders[0].access = acc("rx");
            assert_eq!(run(&p, &env, &c), "allow", "{targets:?}");
            // With no release, the place is named once.
            p.folders.clear();
            assert_eq!(
                decide(&p, &env, &c),
                Decision::Forbidden(protected_text.clone()),
                "{targets:?}"
            );
        }
    }

    /// In folder mode an execute call needs its working directory in a
    /// folder with `x`, and every other path it names in a folder with the
    /// flag for what it does there.
    #[test]
    fn an_execute_call_needs_each_of_its_paths_in_the_folders() {
        let x = T::new();
        let env = x.env(true);
        let p = policy(Mode::Folder);
        let at = |path: &str, access| Target {
            path: path.into(),
            access,
        };
        let cases = [
            (vec![at("/w/rw", PathAccess::Run)], Decision::Allow),
            (
                vec![
                    at("/w/rw", PathAccess::Run),
                    at("/w/ro/a", PathAccess::Read),
                ],
                Decision::Allow,
            ),
            (
                vec![
                    at("/w/rw", PathAccess::Run),
                    at("/elsewhere/a", PathAccess::Write),
                ],
                Decision::Forbidden("outside the folders that allow writing".into()),
            ),
            (
                vec![
                    at("/w/rw", PathAccess::Run),
                    at("/w/ro/a", PathAccess::Write),
                ],
                Decision::Forbidden("outside the folders that allow writing".into()),
            ),
            (
                vec![
                    at("/w/rw", PathAccess::Run),
                    at("/elsewhere/a", PathAccess::Read),
                ],
                Decision::Forbidden("outside the folders that allow reading".into()),
            ),
        ];
        for (targets, want) in cases {
            let c = Call {
                cwd: Some(Path::new("/w/rw")),
                ..call(Effect::Execute, &targets, Some("make"))
            };
            assert_eq!(decide(&p, &env, &c), want, "{targets:?}");
        }
        // The working directory is asked first, and stays needed.
        let ro = [
            at("/w/ro", PathAccess::Run),
            at("/w/rw/a", PathAccess::Write),
        ];
        let c = Call {
            cwd: Some(Path::new("/w/ro")),
            ..call(Effect::Execute, &ro, Some("make"))
        };
        assert_eq!(
            decide(&p, &env, &c),
            Decision::Forbidden(
                "the working directory is not in a folder that allows running".into()
            )
        );
    }

    /// All eight combinations of the three flags, in folder mode: a read
    /// needs `r` only, a write `w` only, a command `x` only.
    #[test]
    fn each_folder_flag_decides_its_own_calls() {
        let x = T::new();
        let env = x.env(true);
        for bits in 0..8u8 {
            let access = Access {
                read: bits & 1 != 0,
                write: bits & 2 != 0,
                execute: bits & 4 != 0,
            };
            let mut p = policy(Mode::Folder);
            p.folders = vec![Folder {
                path: "/w/f".into(),
                access,
            }];
            let read = t("/w/f/a", false);
            let write = t("/w/f/a", true);
            let cwd = cwd_at("/w/f");
            let want = |on: bool| if on { "allow" } else { "refused" };
            let label = access.to_chmod();
            assert_eq!(
                run(&p, &env, &call(Effect::Read, &read, None)),
                want(access.read),
                "read in {label}"
            );
            assert_eq!(
                run(&p, &env, &call(Effect::Write, &write, None)),
                want(access.write),
                "write in {label}"
            );
            assert_eq!(
                run(&p, &env, &call(Effect::Execute, &cwd, Some("ls"))),
                want(access.execute),
                "run in {label}"
            );
            // Outside the folder nothing is allowed, whatever the flags.
            let out = t("/w/other/a", false);
            assert_eq!(run(&p, &env, &call(Effect::Read, &out, None)), "refused");
        }
    }

    #[test]
    fn write_without_read_and_execute_without_read() {
        let x = T::new();
        let env = x.env(true);
        let mut p = policy(Mode::Folder);
        p.folders = vec![
            Folder {
                path: "/w/drop".into(),
                access: acc("w"),
            },
            Folder {
                path: "/w/bin".into(),
                access: acc("x"),
            },
        ];
        let w = t("/w/drop/a", true);
        let r = t("/w/drop/a", false);
        assert_eq!(run(&p, &env, &call(Effect::Write, &w, None)), "allow");
        assert_eq!(run(&p, &env, &call(Effect::Read, &r, None)), "refused");
        let cwd = cwd_at("/w/bin");
        assert_eq!(
            run(&p, &env, &call(Effect::Execute, &cwd, Some("./tool"))),
            "allow"
        );
        assert_eq!(
            run(
                &p,
                &env,
                &call(Effect::Read, &t("/w/bin/tool", false), None)
            ),
            "refused"
        );
        // A folder with no flag grants nothing at all.
        p.folders[0].access = Access::NONE;
        assert_eq!(run(&p, &env, &call(Effect::Write, &w, None)), "refused");
        // A narrower folder inside a wider one decides for its own tree.
        p.folders = vec![
            Folder {
                path: "/w/all".into(),
                access: acc("rwx"),
            },
            Folder {
                path: "/w/all/sealed".into(),
                access: acc("r"),
            },
        ];
        let sealed = t("/w/all/sealed/a", true);
        assert_eq!(
            run(&p, &env, &call(Effect::Write, &sealed, None)),
            "refused"
        );
    }

    #[test]
    fn default_deny_refuses_without_a_rule() {
        let x = T::new();
        let env = x.env(true);
        // A new center: allowlist mode, no folder, no rule.
        let p = CenterPolicy::default();
        assert_eq!(p.mode, Mode::Allowlist);
        let r = t("/w/rw/a", false);
        let w = t("/w/rw/a", true);
        let e = cwd_at("/w/rw");
        for c in [
            call(Effect::Read, &r, None),
            call(Effect::Write, &w, None),
            call(Effect::Execute, &e, Some("make")),
            action(Effect::Sense, "camera", "snap"),
            action(Effect::Actuate, "lamp", "on"),
            action(Effect::Read, "notes", "list"),
        ] {
            let d = decide(&p, &env, &c);
            assert!(
                matches!(&d, Decision::Forbidden(why) if !why.is_empty()),
                "{:?}: {d:?}",
                c.effect
            );
        }
        // Folders do not count in allowlist mode, and neither does `on`.
        let mut p = policy(Mode::Allowlist);
        p.caps.insert("camera".into(), CapSetting::On);
        assert_eq!(run(&p, &env, &call(Effect::Read, &r, None)), "refused");
        assert_eq!(
            run(&p, &env, &call(Effect::Execute, &e, Some("make"))),
            "refused"
        );
        assert_eq!(
            run(&p, &env, &action(Effect::Sense, "camera", "snap")),
            "refused"
        );
    }

    #[test]
    fn an_allow_rule_lets_a_matching_call_through_in_allowlist_mode() {
        let x = T::new();
        let env = x.env(true);
        let mut p = policy(Mode::Allowlist);
        p.allow = rules(&["exec.run:make", "fs.read:/elsewhere/a", "fs.write:/w/rw/*"]);
        let e = cwd_at("/w/ro");
        let c = |cmd| call(Effect::Execute, &e, Some(cmd));
        assert_eq!(run(&p, &env, &c("make")), "allow");
        // The rule names one command.
        assert_eq!(run(&p, &env, &c("make all")), "refused");
        assert_eq!(run(&p, &env, &c("cargo build")), "refused");
        let read = t("/elsewhere/a", false);
        assert_eq!(run(&p, &env, &call(Effect::Read, &read, None)), "allow");
        let other = t("/elsewhere/b", false);
        assert_eq!(run(&p, &env, &call(Effect::Read, &other, None)), "refused");
        // A rule of one action does not cover its sibling.
        let write = t("/w/rw/a/b", true);
        assert_eq!(run(&p, &env, &call(Effect::Write, &write, None)), "allow");
        let read_there = t("/w/rw/a/b", false);
        assert_eq!(
            run(&p, &env, &call(Effect::Read, &read_there, None)),
            "refused"
        );
        // A path rule is no command rule and the other way round.
        let mut q = policy(Mode::Allowlist);
        q.allow = rules(&["fs:/w/*"]);
        assert_eq!(
            run(&q, &env, &call(Effect::Execute, &e, Some("/w/tool"))),
            "refused"
        );
        q.allow = rules(&["exec.run:/w/*"]);
        assert_eq!(
            run(&q, &env, &call(Effect::Read, &t("/w/a", false), None)),
            "refused"
        );
        // Other capabilities: by action, or with a wildcard by capability.
        let mut q = policy(Mode::Allowlist);
        q.allow = rules(&["camera.snap"]);
        assert_eq!(
            run(&q, &env, &action(Effect::Sense, "camera", "snap")),
            "allow"
        );
        assert_eq!(
            run(&q, &env, &action(Effect::Sense, "camera", "record")),
            "refused"
        );
        assert_eq!(
            run(&q, &env, &action(Effect::Actuate, "lamp", "on")),
            "refused"
        );
        q.allow = rules(&["camera"]);
        assert_eq!(
            run(&q, &env, &action(Effect::Sense, "camera", "record")),
            "allow"
        );
        // A capability that is off stays off.
        q.caps.insert("camera".into(), CapSetting::Off);
        assert_eq!(
            run(&q, &env, &action(Effect::Sense, "camera", "snap")),
            "disabled"
        );
        // Protected paths are refused whatever allowed them.
        let mut q = policy(Mode::Allowlist);
        q.allow = rules(&["fs:/h/*"]);
        let key = t("/h/.ssh/id_rsa", false);
        assert_eq!(run(&q, &env, &call(Effect::Read, &key, None)), "refused");
        let ok = t("/h/notes", false);
        assert_eq!(run(&q, &env, &call(Effect::Read, &ok, None)), "allow");
    }

    #[test]
    fn wildcard_rules_match() {
        let x = T::new();
        let env = x.env(true);
        let e = cwd_at("/w/ro");
        let c = |cmd| call(Effect::Execute, &e, Some(cmd));
        let mut p = policy(Mode::Allowlist);
        p.allow = rules(&["exec.run:git *", "fs.read:/notes/*"]);
        for cmd in ["git status", "git log -n 3", "git", "  git status  "] {
            assert_eq!(run(&p, &env, &c(cmd)), "allow", "{cmd}");
        }
        for cmd in ["gitk", "echo git status", "cat git"] {
            assert_eq!(run(&p, &env, &c(cmd)), "refused", "{cmd}");
        }
        for path in ["/notes/a", "/notes/a/b/c", "/notes"] {
            let r = t(path, false);
            assert_eq!(
                run(&p, &env, &call(Effect::Read, &r, None)),
                "allow",
                "{path}"
            );
        }
        for path in ["/notes2/a", "/other"] {
            let r = t(path, false);
            assert_eq!(
                run(&p, &env, &call(Effect::Read, &r, None)),
                "refused",
                "{path}"
            );
        }
        // The same forms deny, in a mode that otherwise allows.
        let mut u = policy(Mode::User);
        u.deny = rules(&["exec.run:docker *", "fs:/notes/*"]);
        assert_eq!(run(&u, &env, &c("docker run x")), "refused");
        assert_eq!(run(&u, &env, &c("dockerd")), "allow");
        let r = t("/notes/a/b", false);
        assert_eq!(run(&u, &env, &call(Effect::Read, &r, None)), "refused");
        // The refusal names the rule.
        assert!(matches!(
            decide(&u, &env, &c("docker run x")),
            Decision::Forbidden(m) if m.contains("docker *")
        ));
    }

    #[test]
    fn a_deny_rule_wins_over_an_allow_rule() {
        let x = T::new();
        let env = x.env(true);
        let e = cwd_at("/w/ro");
        let mut p = policy(Mode::Allowlist);
        p.allow = rules(&["exec.run:git *", "fs:/w/*", "camera"]);
        p.deny = rules(&["exec.run:git push*", "fs.write:/w/secret/*", "camera.snap"]);
        assert_eq!(
            run(&p, &env, &call(Effect::Execute, &e, Some("git status"))),
            "allow"
        );
        assert_eq!(
            run(&p, &env, &call(Effect::Execute, &e, Some("git push -f"))),
            "refused"
        );
        let r = t("/w/secret/k", false);
        let w = t("/w/secret/k", true);
        assert_eq!(run(&p, &env, &call(Effect::Read, &r, None)), "allow");
        assert_eq!(run(&p, &env, &call(Effect::Write, &w, None)), "refused");
        assert_eq!(
            run(&p, &env, &action(Effect::Sense, "camera", "snap")),
            "refused"
        );
        assert_eq!(
            run(&p, &env, &action(Effect::Sense, "camera", "record")),
            "allow"
        );
        // The exact same rule on both lists: deny.
        p.allow = rules(&["exec.run:make"]);
        p.deny = rules(&["exec.run:make"]);
        assert_eq!(
            run(&p, &env, &call(Effect::Execute, &e, Some("make"))),
            "refused"
        );
    }

    #[test]
    fn allow_rules_change_nothing_in_folder_and_user_mode() {
        let x = T::new();
        let env = x.env(true);
        let outside = t("/elsewhere/a", false);
        let ro_w = t("/w/ro/a", true);
        let exec_ro = cwd_at("/w/ro");
        let everything = rules(&["fs", "exec", "camera", "lamp.on"]);
        // What folder mode refuses stays refused, rule or not.
        let mut p = policy(Mode::Folder);
        p.allow = everything.clone();
        assert_eq!(
            run(&p, &env, &call(Effect::Read, &outside, None)),
            "refused"
        );
        assert_eq!(run(&p, &env, &call(Effect::Write, &ro_w, None)), "refused");
        assert_eq!(
            run(&p, &env, &call(Effect::Execute, &exec_ro, Some("make"))),
            "refused"
        );
        assert_eq!(
            run(&p, &env, &action(Effect::Sense, "camera", "snap")),
            "refused"
        );
        assert_eq!(
            run(&p, &env, &action(Effect::Actuate, "lamp", "on")),
            "refused"
        );
        // What user mode allows is allowed without one.
        let mut p = policy(Mode::User);
        assert_eq!(run(&p, &env, &call(Effect::Read, &outside, None)), "allow");
        assert_eq!(
            run(&p, &env, &call(Effect::Execute, &exec_ro, Some("make"))),
            "allow"
        );
        p.allow = everything;
        assert_eq!(run(&p, &env, &call(Effect::Read, &outside, None)), "allow");
        // ... and sense and actuate still need `on`, not an allow rule.
        assert_eq!(
            run(&p, &env, &action(Effect::Sense, "camera", "snap")),
            "refused"
        );
        p.caps.insert("camera".into(), CapSetting::On);
        assert_eq!(
            run(&p, &env, &action(Effect::Sense, "camera", "snap")),
            "allow"
        );
    }

    #[test]
    fn a_deny_rule_refuses_in_every_mode() {
        let x = T::new();
        let env = x.env(true);
        let secret = t("/w/rw/secret/k", false);
        let fine = t("/w/rw/a", false);
        let exec = cwd_at("/w/rw");
        for mode in MODES {
            let mut p = policy(mode);
            p.allow = rules(&["fs:/w/*", "exec.run:*"]);
            assert_eq!(
                run(&p, &env, &call(Effect::Read, &secret, None)),
                "refused",
                "{mode:?}"
            );
            assert_eq!(
                run(&p, &env, &call(Effect::Execute, &exec, Some("git push"))),
                "refused",
                "{mode:?}"
            );
            let d = decide(&p, &env, &call(Effect::Read, &secret, None));
            assert!(
                matches!(&d, Decision::Forbidden(m) if m.contains("denied")),
                "{d:?}"
            );
            // The same call outside the denied path is allowed in all three.
            assert_eq!(
                run(&p, &env, &call(Effect::Read, &fine, None)),
                "allow",
                "{mode:?}"
            );
        }
    }

    #[test]
    fn caps_settings() {
        let x = T::new();
        let env = x.env(true);
        let inside = t("/w/ro/a", false);
        let mut p = policy(Mode::Folder);
        p.caps.insert("fs".into(), CapSetting::Off);
        assert_eq!(
            run(&p, &env, &call(Effect::Read, &inside, None)),
            "disabled"
        );
        // An action's own setting wins over its capability's.
        p.caps.insert("fs.read".into(), CapSetting::On);
        assert_eq!(run(&p, &env, &call(Effect::Read, &inside, None)), "allow");
        // `on` does not widen what the mode refuses.
        let outside = t("/elsewhere/a", false);
        assert_eq!(
            run(&p, &env, &call(Effect::Read, &outside, None)),
            "refused"
        );
    }

    #[test]
    fn sense_and_actuate_need_an_explicit_on_in_folder_and_user_mode() {
        let x = T::new();
        let env = x.env(true);
        for effect in [Effect::Sense, Effect::Actuate] {
            for mode in [Mode::Folder, Mode::User] {
                let mut p = policy(mode);
                let c = action(effect, "camera", "snap");
                assert_eq!(run(&p, &env, &c), "refused");
                p.caps.insert("camera".into(), CapSetting::On);
                assert_eq!(run(&p, &env, &c), "allow");
            }
        }
    }

    /// A sudo command runs with full rights (the administrator token on
    /// Windows, through PowerShell): a wildcard sudo entry covers no more
    /// than a wildcard allow rule does, only an entry that names the line.
    #[test]
    fn a_wildcard_sudo_entry_covers_no_expression_or_inner_command() {
        let x = T::new();
        let on = x.sudo_on();
        let e = cwd_at("/w/rw");
        let sudo = |cmd| call(Effect::Execute, &e, Some(cmd));
        let payload = "sudo choco install @{a=powershell -EncodedCommand AAAA}";
        for mode in MODES {
            let mut p = policy(mode);
            p.sudo_allow = vec![crate::rules::sudo_rule_for("sudo choco install", true).unwrap()];
            assert_eq!(p.sudo_allow, ["sudo choco *"]);
            assert_eq!(run(&p, &on, &sudo("sudo choco install git -y")), "allow");
            // The refusal names what kept the entry from covering the line.
            for (line, what) in [
                (payload, "`@`"),
                ("sudo choco install powershell", "`powershell`"),
                (
                    "sudo choco install x -EncodedCommand AAAA",
                    "`-EncodedCommand`",
                ),
                ("sudo choco install 'a b'", "`'`"),
                ("sudo choco install a,b", "`,`"),
                ("sudo choco start x", "`start`"),
                // Invisible ones by their number.
                (
                    "sudo choco install x\u{2028}y",
                    "the invisible character U+2028",
                ),
                ("sudo choco install x\ty", "the invisible character U+0009"),
            ] {
                let d = decide(&p, &on, &sudo(line));
                // The hint quotes nothing: a line with `'` in `'…'` would
                // be another line.
                assert!(
                    matches!(&d, Decision::Forbidden(m)
                        if m.contains(&format!("does not cover a line with {what}:"))
                            && m.contains("with `nerve-node rule add sudo`, without --wildcard")
                            && !m.contains("'<")),
                    "{mode:?} {line}: {d:?}"
                );
            }
            // An entry that names the line exactly covers it.
            p.sudo_allow
                .push(crate::rules::sudo_rule_for(payload, false).unwrap());
            assert_eq!(run(&p, &on, &sudo(payload)), "allow", "{mode:?}");
            assert_eq!(
                run(&p, &on, &sudo("sudo choco install @{a=1}")),
                "refused",
                "{mode:?}"
            );
        }
    }

    #[test]
    fn sudo_needs_the_switch_and_a_sudo_allow_entry_in_every_mode() {
        let x = T::new();
        let off = x.env(true);
        let on = x.sudo_on();
        let e = cwd_at("/w/rw");
        let sudo = |cmd| call(Effect::Execute, &e, Some(cmd));
        for mode in MODES {
            let mut p = policy(mode);
            // No entry: refused in every mode, and no normal allow rule helps.
            p.allow = rules(&["exec.run:sudo *", "exec"]);
            let d = decide(&p, &on, &sudo("sudo apt update"));
            assert!(
                matches!(&d, Decision::Forbidden(m) if m.contains("sudo allow list")),
                "{mode:?}: {d:?}"
            );
            // An entry, the switch on: it runs, in every mode.
            p.sudo_allow.push("sudo apt update".into());
            assert_eq!(run(&p, &on, &sudo("sudo apt update")), "allow", "{mode:?}");
            // Off, even an entry does not run it.
            assert_eq!(
                decide(&p, &off, &sudo("sudo apt update")),
                Decision::Forbidden("sudo is off on this node".into()),
                "{mode:?}"
            );
            // Only what the list names.
            for other in ["sudo rm -rf /", "/usr/bin/sudo apt upgrade", "  sudo -i"] {
                assert_eq!(run(&p, &on, &sudo(other)), "refused", "{mode:?} {other}");
            }
            // An entry never covers a second command.
            p.sudo_allow.push("sudo apt *".into());
            for chained in [
                "sudo apt x; id",
                "sudo apt $(id)",
                "sudo apt x > /etc/y",
                "sudo apt x\nid",
            ] {
                assert_eq!(run(&p, &on, &sudo(chained)), "refused", "{chained}");
            }
            assert_eq!(run(&p, &on, &sudo("sudo apt upgrade -y")), "allow");
            // Deny rules still apply to a sudo command.
            p.deny.push("exec.run:sudo apt*".into());
            assert_eq!(
                run(&p, &on, &sudo("sudo apt update")),
                "refused",
                "{mode:?}"
            );
        }
        // The sudo list is for sudo commands: without `sudo`, it allows nothing.
        let mut p = policy(Mode::Allowlist);
        p.sudo_allow = rules(&["apt *", "sudo apt *"]);
        assert_eq!(run(&p, &on, &sudo("apt update")), "refused");
        // A sudo command in a protected working directory is refused as well.
        p.sudo_allow = rules(&["sudo id"]);
        let key = cwd_at("/h/.ssh");
        let c = call(Effect::Execute, &key, Some("sudo id"));
        assert_eq!(run(&p, &on, &c), "refused");
    }

    #[test]
    fn a_wildcard_allow_does_not_cover_a_chained_command() {
        let x = T::new();
        let env = x.env(true);
        let e = cwd_at("/w/ro");
        let c = |cmd| call(Effect::Execute, &e, Some(cmd));
        let mut p = policy(Mode::Allowlist);
        p.allow = rules(&["exec.run:git *"]);
        for chained in [
            "git status; rm -rf ~",
            "git status && id",
            "git log | sh",
            "git $(id)",
            "git status\nid",
        ] {
            let d = decide(&p, &env, &c(chained));
            assert!(
                matches!(&d, Decision::Forbidden(m) if m.contains("chains")),
                "{chained}: {d:?}"
            );
        }
        // A rule that names the whole line covers it.
        p.allow
            .push(crate::rules::rule_for("exec", "run", "git log | head", false).unwrap());
        assert_eq!(run(&p, &env, &c("git log | head")), "allow");
        assert_eq!(run(&p, &env, &c("git log | sh")), "refused");
        // A literal `*` in the line is not a wildcard.
        p.allow = vec![crate::rules::rule_for("exec", "run", "rm *", false).unwrap()];
        assert_eq!(run(&p, &env, &c("rm *")), "allow");
        assert_eq!(run(&p, &env, &c("rm -rf /")), "refused");
    }

    /// A wildcard allow covers one plain command only. Each character class
    /// that can open a second command or a sub-expression in sh, PowerShell or
    /// cmd, and each word that runs a string as code, needs a rule that names
    /// the line.
    #[test]
    fn a_wildcard_allow_covers_no_expression_or_inner_command() {
        let x = T::new();
        let env = x.env(true);
        let e = cwd_at("/w/ro");
        let c = |cmd| call(Effect::Execute, &e, Some(cmd));
        let mut p = policy(Mode::Allowlist);
        p.allow = rules(&["exec.run:echo *"]);
        assert_eq!(run(&p, &env, &c("echo hello")), "allow");
        assert_eq!(run(&p, &env, &c("echo hello world-2.txt")), "allow");
        let refused = |cmd: &str| {
            let d = decide(&p, &env, &call(Effect::Execute, &e, Some(cmd)));
            assert!(
                matches!(&d, Decision::Forbidden(m) if m.contains("exactly")),
                "{cmd:?}: {d:?}"
            );
        };
        // The report's payload.
        refused("echo @{a=powershell -EncodedCommand AAAA}");
        // One line per character class.
        for cmd in [
            "echo @{a=1}",
            "echo @(1)",
            "echo {a}",
            "echo a}",
            "echo %PATH%",
            "echo 'a'",
            "echo \"a\"",
            "echo a #b",
            "echo a,b",
            "echo a\\b",
            "echo a && b",
            "echo a || b",
            "echo $(a)",
            "echo a\tb",
            "echo a\u{2028}b",
            "echo \u{201C}a\u{201D}",
        ] {
            refused(cmd);
        }
        // Words that start another shell or run a string as code.
        for cmd in [
            "echo powershell",
            "echo -EncodedCommand AAAA",
            "echo -Command x",
            "echo -File x.ps1",
            "echo iex",
            "echo Invoke-Expression",
            "echo start x",
            "echo Start-Process x",
            "echo cmd /c x",
            "echo PWSH.EXE",
        ] {
            refused(cmd);
        }
        // A rule that names the line exactly still covers it.
        p.allow
            .push(crate::rules::rule_for("exec", "run", "echo @{a=1}", false).unwrap());
        assert_eq!(run(&p, &env, &c("echo @{a=1}")), "allow");
    }

    /// A Windows node in `user` mode: the OpenSSH server's key list and the
    /// registry hives are refused to `fs` calls and as a command's working
    /// directory.
    #[test]
    fn windows_system_files_are_refused_in_user_mode() {
        let folders = WinFolders {
            program_data: vec!["C:\\ProgramData".into()],
            system_root: vec!["C:\\Windows".into()],
            program_files: vec!["C:\\Program Files".into()],
            documents: vec![],
        };
        let prot = Protected::new(
            &Platform::Windows(folders),
            Path::new("C:\\Users\\u"),
            &[],
            &ProtectedOptions::default(),
        );
        let env = Env {
            home: Path::new("C:\\Users\\u"),
            protected: &prot,
            unconfined: Some("commands cannot be confined on this machine"),
            sudo: false,
            shell: Shell::PowerShell,
            reads: Reads::Folders,
        };
        let p = policy(Mode::User);
        let keys = t("C:\\ProgramData\\ssh\\administrators_authorized_keys", true);
        let d = decide(&p, &env, &call(Effect::Write, &keys, None));
        assert!(
            matches!(&d, Decision::Forbidden(m) if m.contains("is protected")),
            "{d:?}"
        );
        // PowerShell 7's profile and modules, which it runs at every start.
        for path in [
            "C:\\Program Files\\PowerShell\\7\\profile.ps1",
            "C:\\Program Files\\PowerShell\\7\\Modules\\x\\x.psm1",
        ] {
            let w = t(path, true);
            assert_eq!(
                run(&p, &env, &call(Effect::Write, &w, None)),
                "refused",
                "{path}"
            );
        }
        for path in [
            "C:\\ProgramData\\ssh\\sshd_config",
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Users\\u\\NTUSER.DAT",
        ] {
            let r = t(path, false);
            assert_eq!(
                run(&p, &env, &call(Effect::Read, &r, None)),
                "refused",
                "{path}"
            );
        }
        let cwd = cwd_at("C:\\Windows\\System32\\config");
        assert_eq!(
            run(&p, &env, &call(Effect::Execute, &cwd, Some("dir"))),
            "refused"
        );
        // What lies beside them stays the user's.
        let notes = t("C:\\Users\\u\\notes\\a.txt", true);
        assert_eq!(run(&p, &env, &call(Effect::Write, &notes, None)), "allow");
        let app = t("C:\\Program Files\\Some App\\x.exe", true);
        assert_eq!(run(&p, &env, &call(Effect::Write, &app, None)), "allow");
        let cwd = cwd_at("C:\\Users\\u");
        assert_eq!(
            run(&p, &env, &call(Effect::Execute, &cwd, Some("dir"))),
            "allow"
        );
    }

    #[test]
    fn what_counts_as_a_sudo_command() {
        assert_eq!(sudo_command("sudo apt update"), Some("apt update"));
        assert_eq!(sudo_command("  /usr/bin/sudo -n true"), Some("-n true"));
        assert_eq!(sudo_command("sudo"), Some(""));
        for not in ["sudoedit x", "ls; sudo x", "env sudo x", "echo sudo"] {
            assert_eq!(sudo_command(not), None, "{not}");
        }
    }
}
