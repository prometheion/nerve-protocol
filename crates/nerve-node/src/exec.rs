//! The `exec` capability (spec §7.3): shell commands, each in its own
//! process group so the whole tree can be signalled and is killed when the
//! call ends or its link ends (a dropped link that is resumed goes on). Windows has no process groups; there each
//! command runs in a job object of its own (crate::job), and only when
//! Windows makes none does the node record the processes below the shell
//! while it runs (crate::tree), best effort.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use nerve_policy::NodeConfig;
use nerve_policy::config::{Access, CenterPolicy, Folder};
use nerve_policy::paths::{to_wire, within};
use nerve_policy::protected::{Platform, Protected};
use nerve_policy::{Target, protected::expand};
use nerve_proto::rpc::params;
use nerve_proto::{ErrorCode, RpcError};
use nerve_sandbox::{ContainerSpec, LandlockSpec, SHIM_ARG, ShimSpec};

use crate::fs::WirePath;

/// The most of stdout and of stderr a result carries, whatever the config
/// says, so the result fits the 4 MiB message limit.
pub const OUTPUT_HARD_CAP: usize = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunArgs {
    command: String,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default)]
    memory_mb: Option<u64>,
    #[serde(default)]
    cpu_percent: Option<u32>,
    #[serde(default)]
    processes: Option<u32>,
}

/// The limits a call asks for its command; each up to the node's most
/// (`limits.command`, [`nerve_policy::config::CommandLimits::grant`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Asked {
    pub memory_mb: Option<u64>,
    pub cpu_percent: Option<u32>,
    pub processes: Option<u32>,
}

/// A parsed `exec.run`.
#[derive(Debug, Clone)]
pub struct RunCall {
    pub command: String,
    pub cwd: PathBuf,
    /// What the call asked for; `None` when it gave no `timeout_ms` (0 counts
    /// as none). [`Timeouts`] turns it into the limit the command runs under.
    pub timeout: Option<Duration>,
    pub limits: Asked,
}

impl RunCall {
    /// `cwd` defaults to `home`, the home of the account the command runs
    /// as, resolved like a given one: the policy judges the real folder, and
    /// a root start opens it without following a link (AsRoot), so a home
    /// whose path runs through one would fail there. On the installed node
    /// the folder is looked at as that account (crate::account::FsAs).
    pub fn parse(args: &Map<String, Value>, home: &Path) -> Result<RunCall, RpcError> {
        let a: RunArgs = params(args)?;
        if a.command.trim().is_empty() {
            return Err(RpcError::invalid_args("command is empty"));
        }
        let cwd = match a.cwd {
            Some(c) => WirePath::parse(&c)?.real,
            // One that does not resolve is refused below as it is named.
            None => nerve_policy::paths::resolve(home).unwrap_or_else(|_| home.to_path_buf()),
        };
        if !cwd.is_dir() {
            return Err(crate::fs::bad_path(format!(
                "{} is not a directory",
                to_wire(&cwd)
            )));
        }
        Ok(RunCall {
            command: a.command,
            cwd,
            timeout: a.timeout_ms.filter(|t| *t > 0).map(Duration::from_millis),
            limits: Asked {
                memory_mb: a.memory_mb,
                cpu_percent: a.cpu_percent,
                processes: a.processes,
            },
        })
    }

    /// The working directory is judged as a read; the command itself by the
    /// command rules and the folders that allow running.
    pub fn targets(&self) -> Vec<Target> {
        vec![Target {
            path: self.cwd.clone(),
            write: false,
        }]
    }
}

/// How long a command may run, from the owner's `limits`: a call that gives
/// no `timeout_ms` gets `default`, and no call gets more than `max`. So no
/// command runs without an end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    pub default: Duration,
    pub max: Duration,
}

impl Default for Timeouts {
    fn default() -> Timeouts {
        Timeouts::from_limits(&nerve_policy::config::Limits::default())
    }
}

impl Timeouts {
    pub fn from_limits(l: &nerve_policy::config::Limits) -> Timeouts {
        Timeouts {
            default: Duration::from_secs(l.default_timeout_secs),
            max: Duration::from_secs(l.max_timeout_secs),
        }
    }

    /// The limit of a call that asked for `asked`. The default is cut to the
    /// maximum like a `timeout_ms` is, so an owner who lowers the maximum
    /// below the default needs no second change.
    pub fn limit(&self, asked: Option<Duration>) -> RunLimit {
        let wanted = asked.unwrap_or(self.default);
        RunLimit {
            after: wanted.min(self.max),
            asked,
            capped: wanted > self.max,
            max: self.max,
        }
    }
}

/// The time one command has, and what it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunLimit {
    pub after: Duration,
    asked: Option<Duration>,
    /// What was wanted was more than the maximum.
    capped: bool,
    max: Duration,
}

impl RunLimit {
    /// The error of a command that ran past it. It says which limit that was,
    /// so the model knows whether a larger `timeout_ms` helps.
    pub fn timed_out(&self) -> RpcError {
        let after = nerve_transport::log::span(self.after);
        let text = match (self.asked, self.capped) {
            (Some(_), false) => {
                format!("the command ran past timeout_ms ({after}) and was killed")
            }
            (Some(asked), true) => format!(
                "the command ran past the node's maximum of {after} and was killed: timeout_ms asked for {}, which the owner's limits.max_timeout_secs cuts",
                nerve_transport::log::span(asked)
            ),
            (None, false) if self.max > self.after => format!(
                "the command ran past the default limit of {after} and was killed: no timeout_ms was given (up to {} is allowed)",
                nerve_transport::log::span(self.max)
            ),
            (None, false) => format!(
                "the command ran past the node's limit of {after} and was killed: no timeout_ms was given"
            ),
            (None, true) => format!(
                "the command ran past the node's maximum of {after} and was killed: no timeout_ms was given, and the owner's limits.max_timeout_secs is below the default"
            ),
        };
        RpcError::new(ErrorCode::Timeout, text)
    }
}

/// The arguments of `exec.signal`. `call` is the id of the `invoke` that
/// runs the command; it is a number, as the descriptor publishes it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalArgs {
    pub call: u64,
    pub signal: String,
}

/// The shell program and its arguments for `command`.
pub fn shell_command(shell: Option<&str>, command: &str) -> (String, Vec<String>) {
    let default = if cfg!(windows) {
        "powershell.exe"
    } else {
        "/bin/sh"
    };
    let sh = shell.unwrap_or(default).to_string();
    let lower = sh.to_lowercase();
    let flag = if powershell(&sh) {
        vec!["-NoProfile".to_string(), "-Command".to_string()]
    } else if lower.ends_with("cmd.exe") || lower == "cmd" {
        vec!["/C".to_string()]
    } else {
        vec!["-c".to_string()]
    };
    let mut args = flag;
    args.push(command.into());
    (sh, args)
}

/// Whether `shell` is Windows PowerShell or PowerShell 7.
fn powershell(shell: &str) -> bool {
    let lower = shell.to_lowercase();
    lower.contains("powershell") || lower.contains("pwsh")
}

/// A Windows command line for `program` and `args`, quoted as the Rust
/// standard library quotes one for `CreateProcessW` (the rules of the
/// Microsoft C runtime): a command started with another account's token
/// (crate::win_user) gets the same arguments as one the node starts as
/// itself.
pub fn windows_command_line(program: &str, args: &[String]) -> String {
    let mut line = format!("\"{program}\"");
    for a in args {
        line.push(' ');
        let quote = a.is_empty() || a.contains([' ', '\t']);
        if quote {
            line.push('"');
        }
        // Backslashes count only before a quote: doubled there, and one
        // more escapes the quote itself.
        let mut backslashes = 0;
        for c in a.chars() {
            if c == '\\' {
                backslashes += 1;
            } else {
                if c == '"' {
                    line.extend(std::iter::repeat_n('\\', backslashes + 1));
                }
                backslashes = 0;
            }
            line.push(c);
        }
        if quote {
            line.extend(std::iter::repeat_n('\\', backslashes));
            line.push('"');
        }
    }
    line
}

/// An account's environment (`NAME=value` entries) pointed at its profile
/// folder `home`. While the account is not signed in its registry is not
/// loaded, and Windows builds the environment from the default profile,
/// without the folders of the account's own: those are set as a sign-in
/// sets them, and any other value below the default profile is moved to
/// `home`. The entries come sorted by name, as Windows wants them.
pub fn rehome_env(vars: Vec<String>, home: &str) -> Vec<String> {
    let name = |v: &str| {
        v.split_once('=')
            .map_or(String::new(), |(n, _)| n.to_uppercase())
    };
    let Some(profile) = vars.iter().find_map(|v| {
        let (n, val) = v.split_once('=')?;
        n.eq_ignore_ascii_case("USERPROFILE")
            .then(|| val.to_string())
    }) else {
        return vars;
    };
    if profile.eq_ignore_ascii_case(home) || profile.is_empty() {
        return vars;
    }
    let (drive, path) = match home.get(..2) {
        Some(d) if d.ends_with(':') => (d, &home[2..]),
        _ => ("", home),
    };
    let own = [
        ("USERPROFILE", home.to_string()),
        ("HOMEDRIVE", drive.to_string()),
        ("HOMEPATH", path.to_string()),
        ("APPDATA", format!("{home}\\AppData\\Roaming")),
        ("LOCALAPPDATA", format!("{home}\\AppData\\Local")),
        ("TEMP", format!("{home}\\AppData\\Local\\Temp")),
        ("TMP", format!("{home}\\AppData\\Local\\Temp")),
    ];
    let mut out: Vec<String> = vars
        .into_iter()
        .filter(|v| !own.iter().any(|(n, _)| *n == name(v)))
        .map(|v| {
            let Some((n, val)) = v.split_once('=') else {
                return v;
            };
            let below = val
                .get(..profile.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(&profile))
                && matches!(val[profile.len()..].chars().next(), None | Some('\\'));
            if below {
                format!("{n}={home}{}", &val[profile.len()..])
            } else {
                v
            }
        })
        .collect();
    out.extend(own.iter().map(|(n, v)| format!("{n}={v}")));
    out.sort_by_key(|v| name(v));
    out
}

/// What the `exec.run` action says about the shell, so a model writes the
/// syntax of the shell that runs it: Windows PowerShell 5.1 is the default
/// on Windows, and cmd's `a & b` is a parser error there.
pub fn shell_summary(shell: Option<&str>) -> String {
    let (sh, mut args) = shell_command(shell, "");
    args.pop();
    let line = format!("`{sh} {}`", args.join(" "));
    let lower = sh.to_lowercase();
    if lower.contains("pwsh") {
        format!("Runs a command in PowerShell 7 ({line}): PowerShell syntax, not cmd or sh.")
    } else if lower.contains("powershell") {
        format!(
            "Runs a command in Windows PowerShell 5.1 ({line}): PowerShell syntax, not cmd or sh. \
             Chain commands with `;`; `&&` and `a & b` are parser errors there."
        )
    } else if args == ["/C"] {
        format!("Runs a command in cmd ({line}): cmd syntax.")
    } else {
        format!("Runs a command with {line}.")
    }
}

/// What the `exec.run` action says about the time a command has, so a model
/// knows what it gets without `timeout_ms` and what it cannot get.
pub fn timeout_summary(t: &Timeouts) -> String {
    use nerve_transport::log::span;
    format!(
        "A command is killed after timeout_ms, after {} when you give none, and never runs longer than {}.",
        span(t.limit(None).after),
        span(t.max)
    )
}

/// Command output as text. UTF-8 is taken as it is, also when the cap cut
/// its last character (`cut`); other bytes are decoded by `other`, the code
/// page the shell wrote in (Windows PowerShell 5.1 writes the console code
/// page, not UTF-8), and what neither reads is replaced.
pub fn output_text(bytes: &[u8], cut: bool, other: impl Fn(&[u8]) -> Option<String>) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(e) if cut && e.error_len().is_none() => String::from_utf8_lossy(bytes).into_owned(),
        Err(_) => other(bytes).unwrap_or_else(|| String::from_utf8_lossy(bytes).into_owned()),
    }
}

/// [`output_text`] with this platform's other encoding: the console code
/// page on Windows, none elsewhere.
fn decode(bytes: &[u8], cut: bool) -> String {
    #[cfg(windows)]
    let other = |b: &[u8]| crate::win::code_page_text(crate::win::console_code_page(), b);
    #[cfg(not(windows))]
    let other = |_: &[u8]| None;
    output_text(bytes, cut, other)
}

/// The Landlock rules for a command of a center in `folders` mode: it reads
/// the system and its `r` folders, writes its `w` folders, runs programs from
/// the system and its `x` folders ([`folder_sets`]). The node's own folders
/// (`own`: its config, keys and state) are in none of these sets, whatever
/// the folders say ([`leave_out`]). The system folders are not cut: what a
/// command reads there is the system's to guard.
///
/// `writable` are the configured folders where commands may write: the `w`
/// folders of every center ([`write_folders`]), since another center's
/// command may be the one that wrote. A folder whose resolution crosses a
/// link inside one is left out ([`led_away`]): a command may have put that
/// link, and the rule would grant the folder's flags wherever it leads.
pub fn landlock_spec(
    policy: &CenterPolicy,
    home: &Path,
    own: &[PathBuf],
    writable: &[PathBuf],
) -> LandlockSpec {
    // Landlock is Linux's, so the list is the Unix one.
    let f = folder_sets(policy, home, own, &Platform::Unix, writable);
    LandlockSpec {
        read: leave_out(&[nerve_sandbox::system_dirs(), f.read].concat(), own),
        write: leave_out(&[nerve_sandbox::system_writable(), f.write].concat(), own),
        exec: leave_out(&[nerve_sandbox::system_dirs(), f.exec].concat(), own),
    }
}

/// A center's folders by what its commands may do there, the system's
/// aside.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FolderSets {
    pub read: Vec<PathBuf>,
    pub write: Vec<PathBuf>,
    pub exec: Vec<PathBuf>,
}

/// The folders of a center in `folders` mode by flag. The three flags are
/// independent, so each set takes the folders with its own flag and nothing
/// else: a folder with only `w` is in `write` alone, and the write rule
/// carries no read right (the command can put files there but not list or
/// read them), and a folder with only `x` can run its programs but not be
/// listed: Landlock refuses to run a file it may not read, so the `exec`
/// rule carries ReadFile and the files there can be read by name.
///
/// Each folder is resolved again here, since it may have become a link
/// after it was added and Landlock (like a Windows grant) follows a link in
/// a rule's path: one that now leads into a protected entry the folders do
/// not release with its flags is left out and the reason logged
/// (`Protected::real_folder`). The others go in by their real path, the
/// place that was judged.
///
/// A folder that holds a protected entry gives none of it either: it is
/// replaced by its other entries, level by level down to the protected one,
/// as the own folders are ([`leave_protected_out`]). The write set leaves
/// out the entries protected for writes as well. The node's own folders are
/// the caller's to leave out ([`leave_out`]).
///
/// A folder whose resolution crosses a link or junction at or inside a
/// place where commands may write (`writable`, configured paths, `~`
/// expanded) is left out ([`led_away`]): commands may have put that link.
/// So is a folder recorded at its real place whose path leads elsewhere now,
/// whatever `writable` says ([`replaced`]): the link may have come while a
/// `w` folder let commands write there, and that `w` is gone.
pub fn folder_sets(
    policy: &CenterPolicy,
    home: &Path,
    own: &[PathBuf],
    platform: &Platform,
    writable: &[PathBuf],
) -> FolderSets {
    let protected = Protected::new(platform, home, own, &policy.protected);
    // The boundary is judged by resolved places, so a writable folder
    // reached by one spelling catches a folder configured by another.
    let bounds: Vec<PathBuf> = writable.iter().map(|w| real(w)).collect();
    let real: Vec<(Access, PathBuf)> = policy
        .folders
        .iter()
        .filter_map(|x| {
            let path = expand(home, &x.path)?;
            let folder = Folder {
                path: path.display().to_string(),
                access: x.access,
            };
            let real = protected
                .real_folder(&folder, &policy.folders)
                .and_then(|real| match led_away(&path, &bounds) {
                    Some(why) => Err(why),
                    None => Ok(real),
                })
                .and_then(|real| match replaced(policy, &x.path, &real) {
                    Some(why) => Err(why),
                    None => Ok(real),
                });
            match real {
                Ok(real) => Some((x.access, real)),
                Err(why) => {
                    tracing::warn!("folder {} left out of the command's sandbox: {why}", x.path);
                    None
                }
            }
        })
        .collect();
    let folders = |f: &dyn Fn(Access) -> bool, write: bool| -> Vec<PathBuf> {
        let granted: Vec<PathBuf> = real
            .iter()
            .filter(|(a, _)| f(*a))
            .map(|(_, p)| p.clone())
            .collect();
        leave_protected_out(&granted, &protected, write)
    };
    FolderSets {
        read: folders(&|a| a.read, false),
        write: folders(&|a| a.write, true),
        exec: folders(&|a| a.execute, false),
    }
}

/// Why the folder at `path`, which resolves to `real`, is not the place the
/// owner added, if it is not: the node recorded it at its real place
/// (`CenterPolicy::places`, written by `folder add`, which stores the
/// resolved path), so a path that leads elsewhere now has a link in its way
/// that came later. A command may have put it there. [`led_away`] sees such a
/// link only while a `w` folder in the config lets commands write where it
/// lies; this holds after that `w` is taken off, or the pairing that had it
/// is removed.
fn replaced(policy: &CenterPolicy, path: &str, real: &Path) -> Option<String> {
    let at = Path::new(path);
    (policy.is_placed(path) && !(within(real, at) && within(at, real))).then(|| {
        format!(
            "it was added at its own place and its path leads to {} now, through a link put there since; `folder rm` it and `folder add` the place you mean",
            real.display()
        )
    })
}

/// The grants a center's AppContainer gets on Windows: every path of
/// [`folder_sets`] (the node's own folders left out, [`leave_out`]) with the
/// flags of the sets it is in. A grant covers what is below its path, as a
/// Landlock rule does. Windows opens its system folders to every
/// AppContainer, so they need none.
///
/// `writable` are the folders that any container may write (`w`, of every
/// center): a folder strictly inside one gets no grant where a link or
/// junction on its way now leads, since a command may have put it there.
/// The grant goes on by the path below that folder, so a link put there
/// later is refused when it goes on (`crate::grants::sync`).
pub fn container_grants(
    policy: &CenterPolicy,
    home: &Path,
    own: &[PathBuf],
    platform: &Platform,
    writable: &[PathBuf],
) -> Vec<(PathBuf, Access)> {
    let f = folder_sets(policy, home, own, platform, writable);
    let mut out: Vec<(PathBuf, Access)> = Vec::new();
    for (set, flag) in [(f.read, 'r'), (f.write, 'w'), (f.exec, 'x')] {
        for p in leave_out(&set, own) {
            let i = match out.iter().position(|(q, _)| within(q, &p) && within(&p, q)) {
                Some(i) => i,
                None => {
                    out.push((p, Access::NONE));
                    out.len() - 1
                }
            };
            let a = &mut out[i].1;
            match flag {
                'r' => a.read = true,
                'w' => a.write = true,
                _ => a.execute = true,
            }
        }
    }
    out
}

/// `p` resolved, as the policy compares paths (on Windows without the
/// `\\?\` prefix); `p` itself when it cannot be resolved.
fn real(p: &Path) -> PathBuf {
    real_checked(p).unwrap_or_else(|_| p.to_path_buf())
}

/// [`real`] with the reason it could not resolve.
fn real_checked(p: &Path) -> std::io::Result<PathBuf> {
    let c = std::fs::canonicalize(p)?;
    #[cfg(windows)]
    {
        Ok(PathBuf::from(nerve_policy::paths::win::strip_verbatim(
            &c.to_string_lossy(),
        )))
    }
    #[cfg(not(windows))]
    {
        Ok(c)
    }
}

/// The configured folders where commands may write: the `w` folders of every
/// center in `cfg` (`~` expanded with `home`), whatever the center's mode. A
/// command of one center can replace a folder of another that lies inside
/// one of them, so `landlock_spec` judges the folders against all of these.
pub fn write_folders(cfg: &NodeConfig, home: &Path) -> Vec<PathBuf> {
    cfg.centers
        .iter()
        .flat_map(|c| &c.policy.folders)
        .filter(|f| f.access.write)
        .filter_map(|f| expand(home, &f.path))
        .collect()
}

/// What [`settle`] made of the path of a folder about to be added.
#[derive(Debug, PartialEq, Eq)]
pub enum Settled {
    /// The folder's real place: the path followed a link at a time, none of
    /// them inside a `w` folder, and it resolves to itself.
    At(PathBuf),
    /// The folder must not be added at the place the path leads to: it crosses
    /// a link inside a `w` folder of any center, which a command may have put
    /// there, or cannot be followed, or changed while it was looked at.
    Refused(String),
    /// This process cannot tell: it may not look into the folder, or into a
    /// `w` folder it would have to judge the links by (the installed node's
    /// CLI runs as the node's own user, not as the account).
    Unknown,
}

/// Where a folder about to be added at `path` (absolute, as given) really is,
/// judged for `folder add` in one pass: [`walk`] follows the path a link at a
/// time against the `w` folders of every center in `cfg` and ends where it
/// leads; that place must resolve to itself, so a link swapped in after the
/// walk (a command can exchange a folder and a link at any moment) is caught
/// rather than followed, and what is stored is what was looked at. A `w` folder
/// that cannot be resolved here makes the answer [`Settled::Unknown`]: which
/// links lie inside it cannot be told.
pub fn settle(cfg: &NodeConfig, home: &Path, path: &Path) -> Settled {
    settle_by(cfg, home, path, nerve_policy::paths::resolve)
}

fn settle_by(
    cfg: &NodeConfig,
    home: &Path,
    path: &Path,
    resolve: impl Fn(&Path) -> Result<PathBuf, nerve_policy::paths::PathError>,
) -> Settled {
    // The `w` folders that resolve judge the links as they are; one that
    // cannot be resolved here only makes an answer of "fine" uncertain.
    let mut bounds = Vec::new();
    let mut unresolved = false;
    for w in write_folders(cfg, home) {
        match real_checked(&w) {
            Ok(r) => bounds.push(r),
            // A `w` folder that is not there (yet) holds no link.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => bounds.push(w),
            Err(_) => {
                unresolved = true;
                bounds.push(w);
            }
        }
    }
    // A drive-relative path (`C:sub`) leads to the drive's current folder,
    // which no walk of the path can judge.
    if !path.is_absolute() {
        return Settled::Refused("the path must be absolute".into());
    }
    // A folder that is not on a drive letter (a share, `\\?\GLOBALROOT\…`)
    // can reach a folder a drive also names, and a junction on the way would
    // be followed without being judged: only a drive's path is walked.
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        let on_drive = matches!(
            path.components().next(),
            Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        );
        if !on_drive {
            return Settled::Refused(
                "the folder must be on a drive; give its path as C:\\…".into(),
            );
        }
    }
    let path = &long_names(path);
    // A link to nothing could point anywhere once something is made there.
    if let Err(e @ nerve_policy::paths::PathError::DanglingSymlink(_)) = resolve(path) {
        return Settled::Refused(e.to_string());
    }
    let walked = match walk(path, &bounds) {
        Ok(p) => p,
        Err(why) => return Settled::Refused(why),
    };
    if unresolved {
        return Settled::Unknown;
    }
    match resolve(&walked) {
        Ok(place) if within(&place, &walked) && within(&walked, &place) => Settled::At(place),
        Ok(place) => Settled::Refused(format!(
            "it leads to {} where it was looked at as {}: a link was put there meanwhile, or it is spelled with an 8.3 short name (use the full name)",
            place.display(),
            walked.display()
        )),
        Err(nerve_policy::paths::PathError::Io(e))
            if e.kind() == std::io::ErrorKind::PermissionDenied =>
        {
            Settled::Unknown
        }
        Err(e) => Settled::Refused(e.to_string()),
    }
}

/// Why resolving `path` leads out of its own place: a link the resolution
/// crosses lies at or inside a place where commands may write (`writable`,
/// resolved), and a command may have put it there. `path` is resolved the way
/// the system does, a link at a time: its target is spliced into the rest of
/// the path, so a link of the owner's that leads into a write folder is
/// followed down to where it ends and every link on that way is judged too,
/// not only the ones in the spelling `path` has. Above a write folder the
/// links are the owner's and are followed, the write folder's own place (it
/// may be a link of the owner's) among them. The folder that holds a link is
/// compared resolved, so a write folder reached by one spelling catches a
/// link reached by another (case, an 8.3 name, a `\\?\` prefix from a
/// junction's target on Windows). On Windows a junction is a link here, as
/// `symlink_metadata` reports it.
fn led_away(path: &Path, writable: &[PathBuf]) -> Option<String> {
    walk(path, writable).err()
}

/// [`led_away`], and where the path ends when nothing leads it away: the path
/// followed a link at a time, which is also what `folder add` stores.
fn walk(path: &Path, writable: &[PathBuf]) -> Result<PathBuf, String> {
    walk_by(path, writable, real)
}

/// [`walk`] with the resolution of the folder that holds a link given, which
/// the tests replace to play a swap between two looks.
///
/// A link is judged by the folder that holds it as spelled (`here`, made only
/// of names that were folders when looked at) and as it resolves now
/// (`holder`): either inside a `w` folder refuses it, and so does a holder
/// that is not the place `here` names, since a name of it was swapped for a
/// link meanwhile. So a link seen inside a `w` folder is refused whatever the
/// timing, and a `here` outside every `w` folder has no name a confined
/// command can swap.
fn walk_by(
    path: &Path,
    writable: &[PathBuf],
    real: impl Fn(&Path) -> PathBuf,
) -> Result<PathBuf, String> {
    // The most links one resolution may cross, as the kernel's limit.
    const LINKS: usize = 40;
    let inside = |p: &Path| writable.iter().any(|w| within(p, w));
    let mut here = PathBuf::new();
    let mut todo = steps(path);
    let mut crossed = 0;
    while let Some(step) = todo.pop() {
        match step {
            Step::Top(top) => {
                #[cfg(windows)]
                match root_kind(&top) {
                    // A `subst` drive is a name for a folder, and the folder
                    // may hold a junction: the walk goes through its names one
                    // by one like through a link, not through the resolved
                    // drive.
                    Root::Subst(mapped) => {
                        crossed += 1;
                        if crossed > LINKS {
                            return Err(format!(
                                "it cannot be resolved through the drive {}",
                                top.display()
                            ));
                        }
                        // `subst` keeps the folder as it was typed, short
                        // names too.
                        todo.extend(steps(&long_names(&mapped)));
                        continue;
                    }
                    // A volume root is the place its mount point names, and
                    // nothing on its own volume lies above it.
                    Root::Volume(mount) => {
                        here = mount;
                        continue;
                    }
                    Root::Drive => {}
                    Root::Other => {
                        return Err(format!(
                            "it passes through a link to {}, which is not a path on a drive",
                            top.display()
                        ));
                    }
                }
                here = top;
            }
            Step::Up => {
                here.pop();
            }
            Step::Name(name) => {
                // A name with a colon is a drive or a stream: joining it would
                // leave the path being walked.
                #[cfg(windows)]
                if name.to_string_lossy().contains(':') {
                    return Err(format!(
                        "it passes through the name {}, which is not a folder name",
                        name.to_string_lossy()
                    ));
                }
                let at = here.join(&name);
                // A name that cannot be looked at (missing, or behind a
                // folder that cannot be searched) is no link; `real_folder`
                // has judged whether the path resolves at all.
                let link = std::fs::symlink_metadata(&at).is_ok_and(|m| m.is_symlink());
                if !link {
                    here = at;
                    continue;
                }
                let holder = real(&here);
                if inside(&here) || inside(&holder) {
                    return Err(format!(
                        "it passes through the link {} inside a folder where commands may write",
                        at.display()
                    ));
                }
                if !(within(&holder, &here) && within(&here, &holder)) {
                    return Err(format!(
                        "it passes through the link {}, and {} leads to {} where it was looked at as itself: a link was put there meanwhile",
                        at.display(),
                        here.display(),
                        holder.display()
                    ));
                }
                crossed += 1;
                let target = std::fs::read_link(&at).ok().filter(|_| crossed <= LINKS);
                match target {
                    Some(t) => todo.extend(steps(&long_names(&t))),
                    None => {
                        return Err(format!(
                            "it cannot be resolved through the link {}",
                            at.display()
                        ));
                    }
                }
            }
        }
    }
    Ok(here)
}

/// What the root `top` of a path is, for the walk (Windows).
#[cfg(windows)]
enum Root {
    /// A drive of a volume: taken as it is.
    Drive,
    /// A drive made by `subst`, and the folder it names.
    Subst(PathBuf),
    /// A volume root (`\\?\Volume{guid}\`), as the drive or folder path it
    /// is mounted at.
    Volume(PathBuf),
    /// Anything else (a share, a device path): nothing can judge the links
    /// below it, since no drive path names where it is.
    Other,
}

#[cfg(windows)]
fn root_kind(top: &Path) -> Root {
    use std::path::{Component, Prefix};
    let on_drive = |p: &Path| {
        matches!(
            p.components().next(),
            Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        )
    };
    match top.components().next() {
        Some(Component::Prefix(p)) => match p.kind() {
            Prefix::Disk(_) | Prefix::VerbatimDisk(_) => {
                subst_target(top).map_or(Root::Drive, Root::Subst)
            }
            Prefix::Verbatim(name) if name.to_string_lossy().starts_with("Volume{") => {
                match real_checked(top) {
                    Ok(mount) if on_drive(&mount) => Root::Volume(mount),
                    _ => Root::Other,
                }
            }
            _ => Root::Other,
        },
        _ => Root::Other,
    }
}

/// The folder the drive `top` (`Z:\`) is made to name by `subst`, as a path;
/// `None` for a drive of a volume, and for what is no drive letter.
#[cfg(windows)]
fn subst_target(top: &Path) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;
    let text = top.to_string_lossy();
    let text = nerve_policy::paths::win::strip_verbatim(&text);
    let letter = text.get(..2).filter(|l| {
        let b = l.as_bytes();
        b[0].is_ascii_alphabetic() && b[1] == b':'
    })?;
    let name: Vec<u16> = std::ffi::OsStr::new(letter)
        .encode_wide()
        .chain([0])
        .collect();
    let mut buf = vec![0u16; 1024];
    // SAFETY: a NUL-terminated name and a buffer of the length given.
    let n = unsafe { QueryDosDeviceW(name.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
    if n == 0 {
        return None;
    }
    // The first of the NUL-separated names; a subst drive gives `\??\<path>`.
    let first = &buf[..buf.iter().position(|&c| c == 0).unwrap_or(n as usize)];
    let target = String::from_utf16_lossy(first);
    let path = target.strip_prefix("\\??\\")?;
    (path.as_bytes().get(1) == Some(&b':')).then(|| PathBuf::from(path))
}

/// `p` with the short (8.3) names in it written out, as the final path of
/// what it names has them (Windows; the existing part of `p`, links stay as
/// they are); `p` as it is elsewhere, for a relative path, and where that
/// fails.
fn long_names(p: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        if !p.is_absolute() {
            return p.to_path_buf();
        }
        // The longest part that exists is expanded, the rest follows as it is.
        let mut head = p;
        let mut tail = Vec::new();
        while std::fs::symlink_metadata(head).is_err() {
            let (Some(parent), Some(name)) = (head.parent(), head.file_name()) else {
                return p.to_path_buf();
            };
            tail.push(name);
            head = parent;
        }
        let mut out = nerve_sandbox::appcontainer::long_path(head);
        out.extend(tail.iter().rev());
        out
    }
    #[cfg(not(windows))]
    {
        p.to_path_buf()
    }
}

/// The first place the resolution of `path` lands at that `wanted` accepts,
/// taken a link at a time as [`led_away`] does: where `path` itself ends, and
/// then where each link it ends at leads, the link itself judged before it is
/// followed. A folder the path only passes does not count. `None` when no
/// such place is accepted, and where the resolution runs out (a dangling
/// link, a loop of links): it needs no part of the path to exist.
pub fn lands_at(path: &Path, wanted: impl Fn(&Path) -> bool) -> Option<PathBuf> {
    // The most links one resolution may cross, as the kernel's limit.
    const LINKS: usize = 40;
    let mut here = PathBuf::new();
    let mut todo = steps(path);
    let mut crossed = 0;
    while let Some(step) = todo.pop() {
        match step {
            Step::Top(top) => here = top,
            Step::Up => {
                here.pop();
            }
            Step::Name(name) => {
                let at = here.join(&name);
                if todo.is_empty() && wanted(&at) {
                    return Some(at);
                }
                let link = std::fs::symlink_metadata(&at).is_ok_and(|m| m.is_symlink());
                if !link {
                    here = at;
                    continue;
                }
                crossed += 1;
                todo.extend(steps(
                    &std::fs::read_link(&at).ok().filter(|_| crossed <= LINKS)?,
                ));
            }
        }
    }
    None
}

/// One step of a path, as [`led_away`] takes it.
enum Step {
    /// Where an absolute path starts: the root, with the drive on Windows.
    Top(PathBuf),
    /// One level up.
    Up,
    Name(std::ffi::OsString),
}

/// The steps of `p`, the last first, so that `pop` gives the next one.
fn steps(p: &Path) -> Vec<Step> {
    use std::path::Component;
    let mut top = PathBuf::new();
    let mut out = Vec::new();
    for c in p.components() {
        match c {
            Component::Prefix(_) | Component::RootDir => top.push(c.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => out.push(Step::Up),
            Component::Normal(n) => out.push(Step::Name(n.to_os_string())),
        }
    }
    if !top.as_os_str().is_empty() {
        out.insert(0, Step::Top(top));
    }
    out.reverse();
    out
}

/// `paths` without the folders in `own`. A Landlock rule grants a folder and
/// everything below it and nothing can carve a hole into it, so a path inside
/// an own folder is dropped, and a path that holds one is replaced by its
/// other entries, level by level down to the own folder. What the command
/// loses there: listing those levels, and making new entries right in them.
///
/// Paths are compared resolved, because Landlock follows a symlink in a
/// rule's path; an entry that is a symlink to or around an own folder is
/// dropped as well.
pub fn leave_out(paths: &[PathBuf], own: &[PathBuf]) -> Vec<PathBuf> {
    let own: Vec<PathBuf> = own.iter().map(|o| real(o)).collect();
    let mut out = Vec::new();
    for p in paths {
        let r = real(p);
        if own.iter().any(|o| within(&r, o)) {
            continue;
        }
        if own.iter().any(|o| within(o, &r)) {
            let inside = |p: &Path| own.iter().any(|o| within(p, o));
            let holds = |p: &Path| own.iter().any(|o| within(o, p));
            split(&r, &inside, &holds, &mut out);
        } else {
            out.push(p.clone());
        }
    }
    out
}

/// `paths` without the protected entries (with `write`, also those
/// protected for writes) that lie strictly inside one of them: such a path
/// is replaced by its other entries, level by level down to the protected
/// one, like an own folder in [`leave_out`]. A path at or inside an entry
/// stays whole: it is a folder the owner released there, and
/// `Protected::real_folder` has judged it for its flags.
pub fn leave_protected_out(paths: &[PathBuf], protected: &Protected, write: bool) -> Vec<PathBuf> {
    let inside = |p: &Path| protected.in_entry(p, write);
    let holds = |p: &Path| protected.holds_entry(p, write);
    let mut out = Vec::new();
    for p in paths {
        let r = real(p);
        if !inside(&r) && holds(&r) {
            split(&r, &inside, &holds, &mut out);
        } else {
            out.push(p.clone());
        }
    }
    out
}

/// Pushes the entries of `dir` (which holds a folder to leave out) that hold
/// none, and goes down into the ones that do. `inside` says whether a
/// resolved path is such a folder or inside one, `holds` whether one lies
/// below it.
fn split(
    dir: &Path,
    inside: &dyn Fn(&Path) -> bool,
    holds: &dyn Fn(&Path) -> bool,
    out: &mut Vec<PathBuf>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let path = e.path();
        let link = e.file_type().is_ok_and(|t| t.is_symlink());
        let r = real(&path);
        let held = holds(&r);
        if inside(&r) || (held && link) {
            continue;
        }
        if held {
            split(&r, inside, holds, out);
        } else {
            out.push(path);
        }
    }
}

/// How one command runs.
#[derive(Debug, Clone)]
pub struct RunOptions {
    pub shell: Option<String>,
    /// Confine with these rules through the shim (`exe __exec-shim`).
    pub landlock: Option<LandlockSpec>,
    /// Windows: run in this AppContainer through the shim, whose folders
    /// carry their grants already (crate::grants).
    pub container: Option<ContainerSpec>,
    /// The `nerve-node` binary that hosts the shim.
    pub exe: PathBuf,
    pub output_cap: usize,
    /// The time a command has when its call gives none, and the most it gets.
    pub timeouts: Timeouts,
    /// Set only for a `sudo` command the sudo allow list names (already rewritten with
    /// [`sudo_line`]): the password goes to sudo's stdin once sudo shows the
    /// prompt. Every other command runs with no_new_privs (Linux), so a
    /// `sudo` the rules did not see (`ls; sudo x`) cannot gain privileges.
    pub sudo: Option<SudoInput>,
    /// The account the command runs as (the installed node, every mode,
    /// crate::account); `None` runs it as the node's own user.
    pub account: Option<crate::service::Account>,
    /// Whether that account is `nerve-run`, whose command gets the
    /// environment of its own home ([`separate_env`]).
    pub separate: bool,
    /// The node's own folders, which the account must not reach.
    pub own: Vec<PathBuf>,
    /// Set only for an allowed sudo command of `nerve-run`, which runs as
    /// `account`, root: where it starts, and how ([`AsRoot`]).
    pub root: Option<AsRoot>,
    /// Linux: the command runs in a cgroup of its own below these, held to
    /// these limits (crate::cgroup); `None` runs it without.
    pub limits: Option<(
        std::sync::Arc<crate::cgroup::Cgroups>,
        nerve_policy::config::Granted,
    )>,
}

/// The environment of a command of `nerve-run` besides HOME, USER and
/// LOGNAME: what it sets, and what it takes away. Its tools keep their
/// configs and caches in its own `home` (the XDG folders), it has no session
/// of anyone's to talk to, and git trusts the repositories it reaches: they
/// belong to the owner, whose folders it was given, and git refuses them as
/// another account's otherwise ("dubious ownership"). The setting goes in as
/// git's command-line configuration (`GIT_CONFIG_COUNT`, git 2.31 on), the
/// one place besides the account's own files it honours `safe.directory`.
pub fn separate_env(home: &Path) -> (Vec<(String, String)>, Vec<&'static str>) {
    let under = |p: &str| home.join(p).display().to_string();
    let set = vec![
        ("XDG_CONFIG_HOME".into(), under(".config")),
        ("XDG_CACHE_HOME".into(), under(".cache")),
        ("XDG_DATA_HOME".into(), under(".local/share")),
        ("XDG_STATE_HOME".into(), under(".local/state")),
        ("GIT_CONFIG_COUNT".into(), "1".into()),
        ("GIT_CONFIG_KEY_0".into(), "safe.directory".into()),
        ("GIT_CONFIG_VALUE_0".into(), "*".into()),
    ];
    (set, vec!["XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"])
}

/// What a sudo command needs: the password and the prompt sudo was told to
/// show before it reads one ([`sudo_prompt`]).
#[derive(Debug, Clone)]
pub struct SudoInput {
    pub password: String,
    pub prompt: String,
}

/// How long a sudo command's stdin stays open for a prompt that has not come
/// while sudo has not started the command either.
const PROMPT_WAIT: Duration = Duration::from_secs(10);
/// How often the node looks whether sudo started the command.
const PROMPT_POLL: Duration = Duration::from_millis(25);
/// Stderr a sudo prints before its prompt is short; past this much the
/// prompt is not looked for any more.
const PROMPT_SCAN_MAX: usize = 64 * 1024;

/// Quotes `s` for a POSIX shell.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// A fresh prompt for one sudo command: random, so output that only happens
/// to look like a prompt is not answered with the password. Letters, digits
/// and `-` only, which sudo prints as they are.
pub fn sudo_prompt() -> String {
    format!("nerve-sudo-{}:", nerve_transport::keys::random_token(16))
}

/// The command line that runs `args` (what followed `sudo`) through
/// `sudo_path`, reading the password from stdin. `-k` makes sudo ignore a
/// cached credential; sudo still asks for nothing for a NOPASSWD entry or as
/// root, so the node writes the password only after sudo printed `prompt`
/// (`run`), and a command sudo starts without asking never gets it. The
/// shell `exec`s sudo, so the process the node started is sudo itself and
/// its first child is the command.
///
/// Windows has no sudo program: the line is what followed `sudo`, which
/// the shell runs with the account's administrator token (`run`,
/// crate::winsudo).
pub fn sudo_line(sudo_path: &str, args: &str, prompt: &str) -> String {
    if cfg!(windows) {
        return args.to_string();
    }
    format!(
        "exec {} -S -k -p {} {args}",
        sh_quote(sudo_path),
        sh_quote(prompt)
    )
}

/// The line root's shell gets for an allowed `sudo <args>` that the node
/// starts as root itself ([`AsRoot`]): `args` without a leading `-n` and
/// `--`, which change nothing for a start without sudo (it asks for no
/// password, and the command is what follows). Any other option of sudo
/// (`-E`, `-u <user>`, …) asks for something this start does not do, and
/// the shell would read it as an option of its own, so the call is refused
/// with the reason; so is a line that names no command.
pub fn root_line(args: &str) -> Result<&str, RpcError> {
    let mut rest = args.trim_start();
    loop {
        let end = rest
            .find(|c: char| c.is_ascii_whitespace())
            .unwrap_or(rest.len());
        let (word, after) = rest.split_at(end);
        match word {
            "-n" => rest = after.trim_start(),
            "--" => {
                rest = after.trim_start();
                break;
            }
            _ => break,
        }
    }
    if rest.is_empty() {
        return Err(RpcError::invalid_args("the sudo command names no command"));
    }
    if rest.starts_with('-') {
        let word = rest.split_ascii_whitespace().next().unwrap_or(rest);
        return Err(RpcError::invalid_args(format!(
            "a sudo command of a pairing whose commands run as nerve-run starts as root without the sudo program, so it takes no sudo option but -n and -- (this one starts with {word}); allow and send the command without it"
        )));
    }
    Ok(rest)
}

/// An allowed sudo command of a pairing whose commands run as `nerve-run`,
/// which the node starts as root itself (crate::link). Its shell gets only
/// the line the sudo allow list named, and starts in `folder`: the call's
/// working folder, opened by the node as `by` (the owner, whose sudo list
/// let it run, or the node's own user for `None`) without following a link,
/// so it is the folder the policy judged. The child enters it with `by`'s
/// file system ids before it becomes root: it holds CAP_SETUID and
/// CAP_SETGID only, so as root it has no right past a folder's mode until
/// the shell runs, and the folder is often in the owner's closed home. The
/// command gets a fixed environment ([`ROOT_PATH`]) and `/bin/sh`.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct AsRoot {
    folder: std::sync::Arc<std::os::fd::OwnedFd>,
    by: Option<crate::service::Account>,
}

/// [`AsRoot`]: Linux only.
#[cfg(not(target_os = "linux"))]
#[derive(Debug, Clone)]
pub enum AsRoot {}

/// The `PATH` of a command the node starts as root: the system's own
/// folders, never one the node's environment names.
pub const ROOT_PATH: &str = crate::keyring_setup::SYSTEM_PATH;

impl AsRoot {
    /// Opens `cwd`, the resolved folder the policy judged, as `by`.
    pub fn open(cwd: &Path, by: Option<&crate::service::Account>) -> Result<AsRoot, RpcError> {
        #[cfg(target_os = "linux")]
        {
            let folder = {
                let _as = by.map(crate::account::FsAs::new).transpose();
                let _as = _as.map_err(|e| {
                    RpcError::new(
                        ErrorCode::Unavailable,
                        format!("cannot act as {}: {e}", by.map_or("", |a| &a.name)),
                    )
                })?;
                crate::fs::open_folder(cwd)
            };
            let folder = folder
                .map_err(|e| crate::fs::bad_path(format!("cannot open {}: {e}", to_wire(cwd))))?;
            Ok(AsRoot {
                folder: std::sync::Arc::new(folder),
                by: by.cloned(),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (cwd, by);
            Err(RpcError::new(
                ErrorCode::Unavailable,
                "only the installed Linux node starts commands as root",
            ))
        }
    }
}

/// Checks `password` with `sudo -S -k -v`, which runs nothing and caches
/// nothing; its output is discarded. It runs as `account`, the account the
/// commands run as (crate::account), so sudo checks that account's
/// password; `None` runs it as the node's own user.
pub async fn sudo_check(
    sudo_path: &str,
    password: &str,
    account: Option<&crate::service::Account>,
) -> Result<(), String> {
    let mut cmd = Command::new(sudo_path);
    cmd.args(["-S", "-k", "-v", "-p", ""])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(target_os = "linux")]
    {
        let switch = account
            .map(|a| crate::account::Switch::new(a, None, &[]))
            .transpose()
            .map_err(|e| e.to_string())?;
        // SAFETY: plain system calls on memory moved into the closure.
        unsafe {
            cmd.pre_exec(move || match &switch {
                Some(s) => s.apply(),
                None if nerve_transport::net::euid() != 0 => crate::account::drop_caps(),
                None => Ok(()),
            });
        }
    }
    if let Some(a) = account {
        cmd.env("HOME", &a.home)
            .env("USER", &a.name)
            .env("LOGNAME", &a.name);
    }
    let as_whom = account.map_or(String::new(), |a| format!(" as {}", a.name));
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("cannot run {sudo_path}{as_whom}: {e}"))?;
    let mut stdin = child.stdin.take().expect("piped");
    // sudo may exit before reading (no such user in sudoers); the exit
    // status says what matters.
    let _ = stdin.write_all(format!("{password}\n").as_bytes()).await;
    drop(stdin);
    match tokio::time::timeout(Duration::from_secs(30), child.wait()).await {
        Ok(Ok(s)) if s.success() => Ok(()),
        Ok(Ok(_)) => Err(format!(
            "the sudo password is wrong (sudo -v{as_whom} refused it)"
        )),
        Ok(Err(e)) => Err(format!("waiting for sudo: {e}")),
        Err(_) => Err("sudo -v did not answer within 30 s".into()),
    }
}

/// What ends one running command, for its call and `exec.signal`: its
/// process group on Unix; on Windows its job (crate::job), or, when Windows
/// made none, the processes recorded below its shell (crate::tree). It is the
/// call's, so a pid that Windows gave to another process after the shell
/// exited leads nowhere.
#[derive(Clone)]
pub struct Ender {
    pid: u32,
    /// The account the command runs as, when it is not the node's: the
    /// node signals it as that account.
    #[cfg(unix)]
    uid: Option<u32>,
    #[cfg(windows)]
    ending: crate::job::Ending<crate::job::Held, Option<std::sync::Arc<crate::tree::Watch>>>,
}

impl Ender {
    /// The shell's pid.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Whether the command runs in a job of its own.
    #[cfg(windows)]
    pub fn has_job(&self) -> bool {
        self.ending.has_job()
    }

    /// Signals the command's processes. Windows has no signals: `kill` ends
    /// them, `term` and `int` ask them to end (crate::win_stop) and end what
    /// is left after [`crate::job::GRACE`], in the background.
    pub fn signal(&self, sig: Sig) {
        #[cfg(windows)]
        {
            let walk = |w: &Option<std::sync::Arc<crate::tree::Watch>>| {
                if let Some(w) = w {
                    w.kill();
                }
            };
            if sig == Sig::Kill {
                self.ending.end(walk);
                return;
            }
            // A stop runs already; it ends the job within its grace.
            if !self.ending.claim_stop() {
                return;
            }
            // The copy holds the job open until it is ended.
            let ending = self.ending.clone();
            let stop = std::thread::Builder::new()
                .name("exec-stop".into())
                .spawn(move || ending.stop(crate::job::GRACE, walk));
            if stop.is_err() {
                self.ending.end(walk);
            }
        }
        #[cfg(unix)]
        kill_group(self.pid, sig, self.uid);
        #[cfg(not(any(unix, windows)))]
        kill_group(self.pid, sig);
    }

    /// Windows, on a timeout: asks the command's processes to end and gives
    /// them [`crate::job::GRACE`] while `work`, the call's wait for the
    /// command, goes on reading its output. The caller ends what is left.
    #[cfg(windows)]
    async fn grace<F: std::future::Future + Unpin>(&self, work: &mut F) {
        let ending = self.ending.clone();
        let mut ask = tokio::task::spawn_blocking(move || ending.ask());
        let asked = tokio::select! {
            r = &mut ask => r.unwrap_or(false),
            // The command ended while it was asked.
            _ = &mut *work => return,
        };
        if asked {
            let _ = tokio::time::timeout(crate::job::GRACE, work).await;
        }
    }
}

/// Kills the command's whole process group when dropped: a cancelled call, a
/// dropped link and a finished command all leave nothing behind.
struct Group(Option<Ender>);

impl Group {
    #[cfg(unix)]
    fn start(pid: Option<u32>, uid: Option<u32>) -> Group {
        Group(pid.map(|pid| Ender { pid, uid }))
    }

    #[cfg(not(any(unix, windows)))]
    fn start(pid: Option<u32>) -> Group {
        Group(pid.map(|pid| Ender { pid }))
    }

    /// `job` is the shell's job; without one the processes below the shell
    /// are recorded while it runs.
    #[cfg(windows)]
    fn start(pid: Option<u32>, job: Option<std::sync::Arc<crate::job::Held>>) -> Group {
        use crate::job::Ending;
        Group(pid.map(|pid| Ender {
            pid,
            ending: match job {
                Some(j) => Ending::Job(j),
                None => Ending::Walk(crate::tree::watch(pid)),
            },
        }))
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        if let Some(e) = &self.0 {
            e.signal(Sig::Kill);
            #[cfg(windows)]
            if let crate::job::Ending::Walk(Some(w)) = &e.ending {
                w.forget();
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sig {
    Term,
    Kill,
    Int,
}

impl Sig {
    pub fn parse(s: &str) -> Option<Sig> {
        match s {
            "term" => Some(Sig::Term),
            "kill" => Some(Sig::Kill),
            "int" => Some(Sig::Int),
            _ => None,
        }
    }
}

/// Signals the process group led by `pid`, as `uid` when the command runs
/// as another account.
#[cfg(unix)]
fn kill_group(pid: u32, sig: Sig, uid: Option<u32>) {
    let s = match sig {
        Sig::Term => libc::SIGTERM,
        Sig::Kill => libc::SIGKILL,
        Sig::Int => libc::SIGINT,
    };
    #[cfg(target_os = "linux")]
    if let Some(uid) = uid {
        crate::account::kill_as(uid, pid, s);
        return;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = uid;
    // SAFETY: kill with a negative pid signals that process group only.
    unsafe {
        libc::kill(-(pid as libc::pid_t), s);
    }
}

#[cfg(not(any(unix, windows)))]
fn kill_group(_pid: u32, _sig: Sig) {}

/// Reads up to `cap` bytes and drains the rest, so the command never blocks
/// on a full pipe. Returns the bytes and whether some were dropped.
async fn capped(mut r: impl AsyncRead + Unpin, cap: usize) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    let mut cut = false;
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let room = cap.saturating_sub(out.len());
                if n > room {
                    cut = true;
                }
                out.extend_from_slice(&buf[..n.min(room)]);
            }
        }
    }
    (out, cut)
}

/// A sudo command's stderr, like [`capped`], and its stdin: the password is
/// written only once sudo has printed `sudo.prompt`, then stdin is closed.
/// When sudo asks for nothing (NOPASSWD, root) it starts the command right
/// away; stdin is then closed without the password as soon as sudo has a
/// child process, the process ends, or [`PROMPT_WAIT`] passes. The prompt is
/// left out of the stderr returned.
async fn sudo_stderr(
    mut err: tokio::process::ChildStderr,
    stdin: tokio::process::ChildStdin,
    sudo: &SudoInput,
    pid: Option<u32>,
    cap: usize,
) -> (Vec<u8>, bool) {
    let prompt = sudo.prompt.as_bytes();
    let mut stdin = Some(stdin);
    let mut seen = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    let until = tokio::time::Instant::now() + PROMPT_WAIT;
    while stdin.is_some() {
        match tokio::time::timeout(PROMPT_POLL, err.read(&mut buf)).await {
            Ok(Ok(0) | Err(_)) => {
                // Everything that held stderr is gone; so is the command.
                stdin = None;
            }
            Ok(Ok(n)) => {
                seen.extend_from_slice(&buf[..n]);
                if seen.windows(prompt.len()).any(|w| w == prompt) {
                    let mut s = stdin.take().expect("still open");
                    // A sudo that fails early closes the pipe; its exit code tells.
                    let _ = s.write_all(format!("{}\n", sudo.password).as_bytes()).await;
                } else if seen.len() > PROMPT_SCAN_MAX {
                    stdin = None;
                }
            }
            Err(_) => {
                if pid.is_some_and(has_child) || tokio::time::Instant::now() >= until {
                    stdin = None;
                }
            }
        }
    }
    let (rest, cut) = capped(err, cap).await;
    seen.extend_from_slice(&rest);
    let mut out = Vec::with_capacity(seen.len().min(cap));
    let mut i = 0;
    while i < seen.len() {
        if seen[i..].starts_with(prompt) {
            i += prompt.len();
        } else {
            out.push(seen[i]);
            i += 1;
        }
    }
    let cut = cut || out.len() > cap;
    out.truncate(cap);
    (out, cut)
}

/// Whether some process has `pid` as its parent: sudo forks the command it
/// runs, so a child means sudo is past asking for a password. A shell that
/// did not `exec` sudo has sudo as its child at once; stdin then closes
/// early and a sudo that asks fails, which leaks nothing.
#[cfg(target_os = "linux")]
fn has_child(pid: u32) -> bool {
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return false;
    };
    dir.flatten().any(|e| {
        let name = e.file_name();
        let Some(name) = name
            .to_str()
            .filter(|n| n.bytes().all(|b| b.is_ascii_digit()))
        else {
            return false;
        };
        // `pid (comm) state ppid ...`; comm may hold spaces and parentheses.
        std::fs::read_to_string(format!("/proc/{name}/stat")).is_ok_and(|s| {
            s.rsplit_once(')')
                .and_then(|(_, rest)| rest.split_whitespace().nth(1)?.parse::<u32>().ok())
                == Some(pid)
        })
    })
}

#[cfg(not(target_os = "linux"))]
fn has_child(_pid: u32) -> bool {
    // Only Linux runs a sudo program; elsewhere the wait or the end decides.
    false
}

/// Runs `call`. `started` hears what ends the command once it runs (for
/// `exec.signal`, and its pid for the control socket's ancestry check).
pub async fn run(
    call: &RunCall,
    opts: &RunOptions,
    started: impl FnOnce(&Ender),
) -> Result<Value, RpcError> {
    // Root's command runs in /bin/sh, whatever shell the others use.
    let shell = opts.shell.as_deref().filter(|_| opts.root.is_none());
    let (program, mut args) = shell_command(shell, &call.command);
    // PowerShell in a container would stand somewhere else than its folder.
    if opts.container.is_some()
        && powershell(&program)
        && let Some(line) = args.last_mut()
    {
        line.insert_str(0, nerve_sandbox::POWERSHELL_START);
    }
    let shim = (opts.landlock.is_some() || opts.container.is_some()).then(|| ShimSpec {
        program: program.clone().into(),
        args: args.clone(),
        parent: std::process::id(),
        landlock: opts.landlock.clone(),
        container: opts.container.clone(),
    });
    // The shim makes the container's profile and window station for the
    // user it runs as, which is not wired for another account yet; such a
    // command would run without its container (crate::daemon, which gives
    // the installed Windows node none).
    if opts.container.is_some()
        && let Some(a) = &opts.account
    {
        return Err(RpcError::new(
            ErrorCode::Unavailable,
            format!(
                "the command was not run: folder mode cannot run a command in its AppContainer as {}",
                a.name
            ),
        ));
    }
    #[cfg(windows)]
    if let Some(a) = &opts.account {
        return run_as(call, opts, a, &program, &args, started).await;
    }
    // Only the installed node can start a command with the administrator
    // token of the account commands run as (crate::winsudo).
    #[cfg(windows)]
    if opts.sudo.is_some() {
        return Err(RpcError::new(
            ErrorCode::Unavailable,
            crate::winsudo::INSTALLED_ONLY,
        ));
    }
    let mut cmd = match &shim {
        Some(_) => {
            let mut c = Command::new(&opts.exe);
            c.arg(SHIM_ARG).stdin(Stdio::piped());
            c
        }
        None => {
            let mut c = Command::new(&program);
            c.args(&args).stdin(if opts.sudo.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            });
            c
        }
    };
    // The command's cgroup, which it joins in the child before anything
    // else, so all it starts is held to its limits. One that cannot be made
    // keeps the command from running: the owner set the limits.
    #[cfg(target_os = "linux")]
    let cgroup = match &opts.limits {
        Some((cgroups, granted)) => Some(cgroups.command(granted).map_err(|e| {
            RpcError::new(
                ErrorCode::Unavailable,
                format!("the command was not run: {e}"),
            )
        })?),
        None => None,
    };
    // A command of another account takes its ids, drops the service's
    // capabilities and enters its folder in the child (crate::account);
    // any other drops the capabilities.
    #[cfg(target_os = "linux")]
    {
        let join = cgroup.as_ref().map(crate::cgroup::CommandCgroup::procs_fd);
        let switch = match (&opts.account, &opts.root) {
            (Some(a), Some(r)) => Some(
                r.folder
                    .try_clone()
                    .and_then(|f| crate::account::Switch::entering(a, f, r.by.as_ref(), &opts.own))
                    .map_err(|e| RpcError::internal(e.to_string()))?,
            ),
            (Some(a), None) => Some(
                crate::account::Switch::new(a, Some(&call.cwd), &opts.own)
                    .map_err(|e| RpcError::invalid_args(e.to_string()))?,
            ),
            (None, Some(_)) => return Err(RpcError::internal("a root command needs root")),
            (None, None) => None,
        };
        // Root as the account (the owner chose it, warned) gets root's
        // rights back at exec, which no_new_privs would keep from it.
        let nnp = opts.sudo.is_none() && opts.account.as_ref().is_none_or(|a| a.uid != 0);
        // SAFETY: plain system calls on memory moved into the closure.
        unsafe {
            cmd.pre_exec(move || {
                if let Some(fd) = join {
                    crate::cgroup::join(fd)?;
                }
                match &switch {
                    Some(s) => s.apply()?,
                    None if nerve_transport::net::euid() != 0 => crate::account::drop_caps()?,
                    None => {}
                }
                if nnp && libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    if let Some(r) = &opts.root {
        match *r {}
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    if let Some(a) = &opts.account {
        return Err(RpcError::new(
            ErrorCode::Unavailable,
            format!("cannot run commands as {}: Linux and Windows only", a.name),
        ));
    }
    match &opts.account {
        Some(a) => {
            // Root's command gets nothing of the node's environment.
            if opts.root.is_some() {
                cmd.env_clear().env("PATH", ROOT_PATH);
            }
            cmd.env("HOME", &a.home)
                .env("USER", &a.name)
                .env("LOGNAME", &a.name);
            if opts.separate {
                let (set, unset) = separate_env(&a.home);
                cmd.envs(set);
                for k in unset {
                    cmd.env_remove(k);
                }
            }
        }
        None => {
            cmd.current_dir(&call.cwd);
        }
    }
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    cmd.process_group(0);
    // The shell starts suspended and runs only once it is in its job, so
    // nothing it starts escapes the job. No console is needed for this, so
    // a node that runs as a service does the same. It gets a console of its
    // own, which a stop sends Ctrl+C (crate::win_stop).
    #[cfg(windows)]
    let job = crate::job::make();
    #[cfg(windows)]
    cmd.creation_flags(match job {
        Some(_) => crate::job::CONSOLE | crate::job::SUSPENDED,
        None => crate::job::CONSOLE,
    });
    // Without a job the control pipe cannot tell this command's processes
    // from others while it runs, and refuses every caller (crate::pipe).
    #[cfg(windows)]
    let _jobless = job.is_none().then(crate::job::Jobless::count);
    #[cfg(windows)]
    crate::win_stop::hear_ctrl_c();
    let mut child = cmd.spawn().map_err(|e| {
        RpcError::new(
            ErrorCode::Unavailable,
            match &opts.account {
                #[cfg(target_os = "linux")]
                Some(a) if e.raw_os_error() == Some(crate::account::IN_REACH) => format!(
                    "cannot start as {}: that account can open the node's own folders, where its keys are",
                    a.name
                ),
                Some(a) => format!(
                    "cannot start as {} in {}: {e}",
                    a.name,
                    to_wire(&call.cwd)
                ),
                None => format!("cannot start: {e}"),
            },
        )
    })?;
    #[cfg(windows)]
    let job = match job {
        Some(job) => Some(
            crate::job::adopt(
                job,
                &mut child,
                crate::win_stop::Asker::Own(opts.exe.clone()),
            )
            .map_err(|e| RpcError::new(ErrorCode::Unavailable, e))?,
        ),
        None => None,
    };
    #[cfg(windows)]
    let group = Group::start(child.id(), job);
    #[cfg(unix)]
    let group = Group::start(child.id(), opts.account.as_ref().map(|a| a.uid));
    #[cfg(not(any(unix, windows)))]
    let group = Group::start(child.id());
    let mut sudo_stdin = None;
    if let Some(spec) = shim {
        let mut stdin = child.stdin.take().expect("piped");
        let json = serde_json::to_vec(&spec).map_err(|e| RpcError::internal(e.to_string()))?;
        stdin
            .write_all(&json)
            .await
            .map_err(|e| RpcError::internal(format!("cannot hand the shim its spec: {e}")))?;
        drop(stdin);
    } else if let Some(sudo) = &opts.sudo {
        sudo_stdin = Some((child.stdin.take().expect("piped"), sudo));
    }
    let pid = child.id();
    if let Some(e) = &group.0 {
        started(e);
    }
    let stdout = child.stdout.take().expect("piped");
    let stderr = child.stderr.take().expect("piped");
    let cap = opts.output_cap.min(OUTPUT_HARD_CAP);
    let limit = opts.timeouts.limit(call.timeout);
    let err = async {
        match sudo_stdin {
            Some((stdin, sudo)) => sudo_stderr(stderr, stdin, sudo, pid, cap).await,
            None => capped(stderr, cap).await,
        }
    };
    let work = async {
        let (o, e, st) = tokio::join!(capped(stdout, cap), err, child.wait());
        (o, e, st)
    };
    tokio::pin!(work);
    let (out, err, status, timed_out) = match tokio::time::timeout(limit.after, &mut work).await {
        Ok((o, e, s)) => (o, e, Some(s), false),
        Err(_) => {
            #[cfg(windows)]
            if let Some(e) = &group.0 {
                e.grace(&mut work).await;
            }
            ((Vec::new(), false), (Vec::new(), false), None, true)
        }
    };
    drop(group);
    // Read before the cgroup goes with what is left in it.
    #[cfg(target_os = "linux")]
    let out_of_memory = cgroup
        .as_ref()
        .filter(|c| c.out_of_memory())
        .map(crate::cgroup::CommandCgroup::memory_mb);
    #[cfg(target_os = "linux")]
    drop(cgroup);
    if timed_out {
        return Err(limit.timed_out());
    }
    let status = status
        .expect("set unless timed out")
        .map_err(|e| RpcError::internal(format!("waiting for the command: {e}")))?;
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut result = json!({
        "exit_code": status.code(),
        "stdout": decode(&out.0, out.1),
        "stderr": decode(&err.0, err.1),
        "truncated": out.1 || err.1,
    });
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(s) = status.signal() {
            let name = match s {
                libc::SIGTERM => "term".to_string(),
                libc::SIGKILL => "kill".to_string(),
                libc::SIGINT => "int".to_string(),
                n => format!("signal {n}"),
            };
            result["signal"] = name.into();
        }
    }
    #[cfg(target_os = "linux")]
    if let Some(mb) = out_of_memory {
        result["killed"] = "memory".into();
        result["reason"] = crate::cgroup::memory_reason(mb).into();
    }
    Ok(result)
}

/// [`run`] as another account on Windows (crate::win_user): the shell
/// starts suspended with the account's token in the call's folder, is put
/// in a job of its own and runs only then. It does not start when its
/// account can open the node's own folders, nor without a job: the node
/// may not end another account's processes one by one, only the job. A
/// sudo command starts with the account's administrator token instead
/// (crate::winsudo), which can open every folder.
#[cfg(windows)]
async fn run_as(
    call: &RunCall,
    opts: &RunOptions,
    account: &crate::service::Account,
    program: &str,
    args: &[String],
    started: impl FnOnce(&Ender),
) -> Result<Value, RpcError> {
    let unavailable = |m: String| RpcError::new(ErrorCode::Unavailable, m);
    let token = crate::win_user::token_for(account)
        .map_err(|e| unavailable(format!("cannot start as {}: {e}", account.name)))?;
    let elevated = match &opts.sudo {
        Some(s) => Some(std::sync::Arc::new(
            crate::win_user::sudo_token(&account.name, &s.password).map_err(|e| {
                unavailable(format!(
                    "cannot start as {} with its administrator rights: {e}",
                    account.name
                ))
            })?,
        )),
        None => None,
    };
    let reach = match elevated {
        Some(_) => Ok(None),
        None => crate::win_user::reach(&token, &opts.own),
    };
    match reach {
        Ok(None) => {}
        Ok(Some(_)) => {
            return Err(unavailable(format!(
                "cannot start as {}: that account can open the node's own folders, where its keys are",
                account.name
            )));
        }
        Err(e) => {
            return Err(unavailable(format!(
                "cannot start as {}: cannot check what it can open ({e})",
                account.name
            )));
        }
    }
    let job = crate::win::Job::new().map_err(|e| {
        unavailable(format!(
            "the command was not run: Windows made no job object for it ({e})"
        ))
    })?;
    let line = windows_command_line(program, args);
    // The command's own token also starts the helper that asks it to end
    // (crate::win_stop).
    let token = elevated.unwrap_or(token);
    crate::win_stop::hear_ctrl_c();
    let child = crate::win_user::spawn(&token, &line, Some(&call.cwd), Some(&account.home))
        .map_err(|e| {
            unavailable(format!(
                "cannot start as {} in {}: {e}",
                account.name,
                to_wire(&call.cwd)
            ))
        })?;
    if let Err(e) = job.assign(child.process()) {
        child.kill();
        return Err(unavailable(crate::job::assign_error(
            crate::win::in_job(child.process()),
            &e,
        )));
    }
    if let Err(e) = child.resume() {
        job.terminate();
        return Err(unavailable(format!(
            "the command was not run: its shell could not be resumed ({e})"
        )));
    }
    let asker = crate::win_stop::Asker::As(opts.exe.clone(), token);
    let job = crate::job::Held::new(job, child.handle().ok(), asker);
    let group = Group::start(Some(child.pid), Some(std::sync::Arc::new(job)));
    if let Some(e) = &group.0 {
        started(e);
    }
    let wait = child
        .waiter()
        .map_err(|e| RpcError::internal(format!("waiting for the command: {e}")))?;
    let crate::win_user::Spawned { stdout, stderr, .. } = child;
    let cap = opts.output_cap.min(OUTPUT_HARD_CAP);
    let limit = opts.timeouts.limit(call.timeout);
    let work = async {
        tokio::join!(
            capped(tokio::fs::File::from_std(stdout), cap),
            capped(tokio::fs::File::from_std(stderr), cap),
            async {
                tokio::task::spawn_blocking(wait)
                    .await
                    .map_err(std::io::Error::other)
                    .and_then(|r| r)
            }
        )
    };
    tokio::pin!(work);
    let (out, err, code) = match tokio::time::timeout(limit.after, &mut work).await {
        Ok(r) => r,
        Err(_) => {
            if let Some(e) = &group.0 {
                e.grace(&mut work).await;
            }
            drop(group);
            return Err(limit.timed_out());
        }
    };
    drop(group);
    let code = code.map_err(|e| RpcError::internal(format!("waiting for the command: {e}")))?;
    Ok(json!({
        "exit_code": code as i32,
        "stdout": decode(&out.0, out.1),
        "stderr": decode(&err.0, err.1),
        "truncated": out.1 || err.1,
    }))
}

/// The command lines a command of another account gets on Windows.
#[cfg(test)]
mod command_line_tests {
    use super::windows_command_line;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn arguments_are_quoted_as_the_standard_library_quotes_them() {
        assert_eq!(
            windows_command_line(
                "powershell.exe",
                &args(&["-NoProfile", "-Command", r#"echo "a b" \x\"#])
            ),
            r#""powershell.exe" -NoProfile -Command "echo \"a b\" \x\\""#
        );
        // Without a space no quotes, and a quote is escaped all the same,
        // with the backslashes before it doubled.
        assert_eq!(
            windows_command_line("cmd.exe", &args(&["/C", r#"a\"b"#, ""])),
            r#""cmd.exe" /C a\\\"b """#
        );
        assert_eq!(
            windows_command_line(r"C:\Program Files\x.exe", &args(&["a\tb", r"c\"])),
            "\"C:\\Program Files\\x.exe\" \"a\tb\" c\\"
        );
    }

    /// The environment Windows builds from the default profile names the
    /// account's own; one that names it already stays as it is.
    #[test]
    fn the_environment_names_the_accounts_profile() {
        let default = args(&[
            "=C:=C:\\",
            r"Path=C:\Windows\system32",
            r"USERPROFILE=C:\Users\Default",
            r"TEMP=C:\WINDOWS\TEMP",
            r"OneDrive=c:\users\default\OneDrive",
            r"OTHER=C:\Users\DefaultAppPool",
        ]);
        assert_eq!(
            super::rehome_env(default, r"D:\Users\bob"),
            args(&[
                "=C:=C:\\",
                r"APPDATA=D:\Users\bob\AppData\Roaming",
                r"HOMEDRIVE=D:",
                r"HOMEPATH=\Users\bob",
                r"LOCALAPPDATA=D:\Users\bob\AppData\Local",
                r"OneDrive=D:\Users\bob\OneDrive",
                r"OTHER=C:\Users\DefaultAppPool",
                r"Path=C:\Windows\system32",
                r"TEMP=D:\Users\bob\AppData\Local\Temp",
                r"TMP=D:\Users\bob\AppData\Local\Temp",
                r"USERPROFILE=D:\Users\bob",
            ])
        );
        let own = args(&[r"HOMEPATH=\x", r"USERPROFILE=C:\Users\bob"]);
        assert_eq!(super::rehome_env(own.clone(), r"C:\Users\bob"), own);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use nerve_policy::config::Access;

    fn opts(cap: usize) -> RunOptions {
        RunOptions {
            shell: None,
            landlock: None,
            container: None,
            exe: PathBuf::from("/nonexistent"),
            output_cap: cap,
            timeouts: Timeouts::default(),
            sudo: None,
            account: None,
            separate: false,
            own: Vec::new(),
            root: None,
            limits: None,
        }
    }

    fn call(cmd: &str) -> RunCall {
        RunCall {
            command: cmd.into(),
            cwd: std::env::temp_dir(),
            timeout: Some(Duration::from_secs(10)),
            limits: Default::default(),
        }
    }

    /// A command runs in a cgroup of its own, held to its limits: past its
    /// memory it is killed and its result says so, past its processes it
    /// cannot start more, and what it left behind ends with it, also
    /// outside its process group. This needs a cgroup delegated to the
    /// process, so the test runs [`limits_in_a_real_cgroup`] in a scope
    /// systemd's user manager makes for it; without one it is skipped.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_command_is_held_to_its_limits_in_a_cgroup_of_its_own() {
        let exe = std::env::current_exe().unwrap();
        let out = std::process::Command::new("systemd-run")
            .args(["--user", "--scope", "--quiet", "-p", "Delegate=yes"])
            // The helper's own bound, whatever its commands do.
            .args(["-p", "MemoryMax=1G", "-p", "MemorySwapMax=0", "--"])
            .arg(&exe)
            .args([
                "--ignored",
                "--exact",
                "exec::tests::limits_in_a_real_cgroup",
                "--nocapture",
                "--test-threads=1",
            ])
            .output();
        let Ok(out) = out else {
            eprintln!("skipped: no systemd-run here");
            return;
        };
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if !text.contains("limits helper started") {
            eprintln!("skipped: systemd-run --user made no scope: {text}");
            return;
        }
        assert!(text.contains("limits helper passed"), "{text}");
    }

    /// A command whose cgroup cannot be made does not run: the owner set
    /// limits, and it would run without them. The cgroups are plain folders
    /// here, the node's made read-only.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_command_without_its_cgroup_does_not_run() {
        use std::os::unix::fs::PermissionsExt;
        let me = nerve_transport::net::euid();
        if me == 0 {
            eprintln!("skipped: root writes a read-only folder");
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let own = t.path().join("node.scope");
        std::fs::create_dir_all(&own).unwrap();
        std::fs::write(t.path().join("cgroup.controllers"), "cpu memory pids").unwrap();
        std::fs::write(own.join("cgroup.controllers"), "cpu memory pids").unwrap();
        std::fs::write(own.join("cgroup.procs"), "").unwrap();
        let cgroups =
            crate::cgroup::Cgroups::at(t.path(), "/node.scope", std::process::id(), me, &|_| true)
                .unwrap();
        std::fs::write(own.join("cgroup.subtree_control"), "cpu memory pids").unwrap();
        let mut o = opts(1024);
        o.limits = Some((
            std::sync::Arc::new(cgroups),
            nerve_policy::config::Granted {
                memory_mb: 64,
                cpu_percent: 100,
                processes: 16,
            },
        ));
        let ran = t.path().join("ran");
        let line = format!("touch {}", ran.display());
        std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o555)).unwrap();
        let r = run(&call(&line), &o, |_| {}).await;
        std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o755)).unwrap();
        let e = r.unwrap_err();
        assert_eq!(e.kind(), ErrorCode::Unavailable, "{e:?}");
        assert!(
            e.message
                .starts_with("the command was not run: cannot make a cgroup for the command"),
            "{e:?}"
        );
        assert!(!ran.exists(), "the command ran without its cgroup");
        // With its cgroup, the same command runs.
        let r = run(&call(&line), &o, |_| {}).await.unwrap();
        assert_eq!(r["exit_code"], 0, "{r}");
        assert!(ran.exists());
    }

    /// A child that cannot join its cgroup is not started.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_failed_join_is_an_error() {
        use std::os::fd::AsRawFd;
        let full = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap();
        assert!(crate::cgroup::join(full.as_raw_fd()).is_err());
        assert!(crate::cgroup::join(-1).is_err());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "a helper of a_command_is_held_to_its_limits_in_a_cgroup_of_its_own"]
    async fn limits_in_a_real_cgroup() {
        use nerve_policy::config::Granted;
        println!("limits helper started");
        let cgroups = std::sync::Arc::new(crate::cgroup::Cgroups::find().unwrap());
        assert!(
            cgroups.enforced().contains(&"memory") && cgroups.enforced().contains(&"processes"),
            "{:?}",
            cgroups.enforced()
        );
        let held = |memory_mb, processes| {
            let mut o = opts(1024);
            o.limits = Some((
                cgroups.clone(),
                Granted {
                    memory_mb,
                    cpu_percent: 100,
                    processes,
                },
            ));
            o
        };
        // About 64 MB in the shell's own memory.
        let big = "x=$(head -c 64000000 /dev/zero | tr '\\0' a); echo ${#x}";
        let r = run(&call(big), &held(16, 64), |_| {}).await.unwrap();
        assert_eq!(r["killed"], "memory", "{r}");
        assert_eq!(r["signal"], "kill", "{r}");
        assert_eq!(
            r["reason"],
            "the command went past its memory limit of 16 MiB and was killed"
        );
        let r = run(&call(big), &held(512, 64), |_| {}).await.unwrap();
        assert_eq!(r["stdout"], "64000000\n", "{r}");
        assert!(r.get("killed").is_none(), "{r}");

        // A shell with 4 processes at most starts no 10 more.
        let many = "for i in 1 2 3 4 5 6 7 8 9 10; do sleep 1 & done; wait";
        let r = run(&call(many), &held(64, 4), |_| {}).await.unwrap();
        assert!(!r["stderr"].as_str().unwrap().is_empty(), "{r}");
        assert!(r.get("killed").is_none(), "{r}");

        // What left the process group is in the cgroup still, and ends.
        let left = "setsid sleep 60 >/dev/null 2>&1 < /dev/null & echo $!";
        let r = run(&call(left), &held(64, 64), |_| {}).await.unwrap();
        let pid: i32 = r["stdout"].as_str().unwrap().trim().parse().unwrap();
        let mut ended = false;
        for _ in 0..100 {
            // SAFETY: signal 0 only asks whether the process is there.
            if unsafe { libc::kill(pid, 0) } != 0 {
                ended = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(ended, "the process {pid} outlived its command");
        // And the commands' cgroups are gone.
        let own = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        let dir = Path::new("/sys/fs/cgroup").join(
            own.trim()
                .trim_start_matches("0::/")
                .trim_end_matches("/node"),
        );
        let mut left = Vec::new();
        for _ in 0..100 {
            left = std::fs::read_dir(&dir)
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with("cmd-"))
                .collect();
            if left.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(left.is_empty(), "{left:?}");
        println!("limits helper passed");
    }

    #[tokio::test]
    async fn runs_and_caps() {
        let r = run(&call("echo hi; echo err >&2; exit 3"), &opts(1024), |_| {})
            .await
            .unwrap();
        assert_eq!(r["exit_code"], 3);
        assert_eq!(r["stdout"], "hi\n");
        assert_eq!(r["stderr"], "err\n");
        assert_eq!(r["truncated"], false);
        let r = run(&call("head -c 5000 /dev/zero"), &opts(100), |_| {})
            .await
            .unwrap();
        assert_eq!(r["stdout"].as_str().unwrap().len(), 100);
        assert_eq!(r["truncated"], true);
    }

    fn sudo_input(password: &str) -> Option<SudoInput> {
        Some(SudoInput {
            password: password.into(),
            prompt: "nerve-sudo-test:".into(),
        })
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn only_a_sudo_command_may_gain_privileges() {
        // Like sudo, the probe asks with the prompt before it reads.
        let probe = "printf %s nerve-sudo-test: >&2; read l; echo got=$l; \
                     grep NoNewPrivs /proc/self/status";
        let r = run(&call(probe), &opts(1024), |_| {}).await.unwrap();
        let out = r["stdout"].as_str().unwrap();
        assert!(out.contains("got=\n"), "{out}");
        assert!(out.contains("NoNewPrivs:\t1"), "{out}");
        let mut o = opts(1024);
        o.sudo = sudo_input("pw");
        let r = run(&call(probe), &o, |_| {}).await.unwrap();
        let out = r["stdout"].as_str().unwrap();
        assert!(out.contains("got=pw\n"), "{out}");
        assert!(!out.contains("NoNewPrivs:\t1"), "{out}");
        assert_eq!(r["stderr"], "", "the prompt is left out: {r}");
    }

    /// Writes an executable script at `path` from another process. Written
    /// here, its descriptor would leak into a command that another test
    /// thread forks meanwhile, and running the script would fail with "Text
    /// file busy" until that command execs.
    #[cfg(target_os = "linux")]
    fn write_script(path: &Path, text: &str) {
        use std::io::Write;
        let mut c = std::process::Command::new("sh")
            .args(["-c", "cat > \"$0\" && chmod 755 \"$0\""])
            .arg(path)
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin.take().unwrap().write_all(text.as_bytes()).unwrap();
        assert!(c.wait().unwrap().success(), "cannot write {path:?}");
    }

    /// A fake sudo at `dir/sudo`: with `asks` it prints its `-p` prompt to
    /// stderr and reads the password like `sudo -S`, else it asks for none
    /// (NOPASSWD, root). Either way it runs the command as its child.
    #[cfg(target_os = "linux")]
    fn fake_sudo(dir: &Path, asks: bool) -> String {
        let ask = if asks {
            "printf %s \"$p\" >&2\nIFS= read -r pw\n[ \"$pw\" = right-pw ] || exit 1\n"
        } else {
            ""
        };
        let sudo = dir.join("sudo");
        write_script(
            &sudo,
            &format!(
                "#!/bin/sh\nwhile [ $# -gt 0 ]; do case \"$1\" in -S|-k) shift ;; \
                 -p) p=\"$2\"; shift 2 ;; *) break ;; esac; done\n{ask}\"$@\"\n"
            ),
        );
        sudo.display().to_string()
    }

    /// A folder-mode command of another account is not started at all
    /// while the AppContainer is not wired for that account: it would run
    /// without its container.
    #[tokio::test]
    async fn a_container_command_of_another_account_does_not_run() {
        let d = tempfile::tempdir().unwrap();
        let mark = d.path().join("ran");
        let mut o = opts(1024);
        o.container = Some(ContainerSpec {
            name: "nerve.test".into(),
        });
        o.account = Some(crate::service::Account {
            name: "chosen".into(),
            uid: 4242,
            gid: 4242,
            comment: String::new(),
            home: d.path().to_path_buf(),
            groups: vec![4242],
        });
        let e = run(&call(&format!("touch '{}'", mark.display())), &o, |_| {})
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorCode::Unavailable, "{e:?}");
        assert!(
            e.message
                .contains("cannot run a command in its AppContainer as chosen"),
            "{e:?}"
        );
        assert!(!mark.exists());
    }

    /// `sudo on` checks the password of the account the commands run as:
    /// sudo -v runs as that account, so sudo asks for its password.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_sudo_check_runs_as_the_chosen_account() {
        let d = tempfile::tempdir().unwrap();
        let seen = d.path().join("seen");
        let sudo = d.path().join("sudo");
        // Like sudo -v: takes the password of the user it runs as.
        write_script(
            &sudo,
            &format!(
                "#!/bin/sh\nIFS= read -r pw\necho \"$USER $(id -u)\" > '{}'\n[ \"$pw\" = \"pw-of-$USER\" ]\n",
                seen.display()
            ),
        );
        let sudo = sudo.display().to_string();
        // SAFETY: plain getters.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let chosen = crate::service::Account {
            name: "chosen".into(),
            uid,
            gid,
            comment: String::new(),
            home: d.path().to_path_buf(),
            groups: vec![gid],
        };
        sudo_check(&sudo, "pw-of-chosen", Some(&chosen))
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&seen).unwrap(),
            format!("chosen {uid}\n")
        );
        let e = sudo_check(&sudo, "pw-of-nerve", Some(&chosen))
            .await
            .unwrap_err();
        assert!(e.contains("sudo -v as chosen refused it"), "{e}");
    }

    /// A sudo that asks for no password: the command it starts finds no
    /// password on its stdin, only its end.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_sudo_that_does_not_ask_leaves_the_command_no_password() {
        let d = tempfile::tempdir().unwrap();
        let sudo = fake_sudo(d.path(), false);
        let mut o = opts(1024);
        o.sudo = sudo_input("right-pw");
        let prompt = o.sudo.as_ref().unwrap().prompt.clone();
        let c = call(&sudo_line(&sudo, "cat", &prompt));
        let started = std::time::Instant::now();
        let r = run(&c, &o, |_| {}).await.unwrap();
        assert_eq!(r["exit_code"], 0, "{r}");
        assert_eq!(r["stdout"], "", "the command read the password: {r}");
        // Closed once sudo started the command, not after PROMPT_WAIT.
        assert!(
            started.elapsed() < PROMPT_WAIT / 2,
            "{:?}",
            started.elapsed()
        );
    }

    /// A sudo that asks gets the password after its prompt; the command
    /// after it finds stdin at its end.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_sudo_that_asks_gets_the_password() {
        let d = tempfile::tempdir().unwrap();
        let sudo = fake_sudo(d.path(), true);
        let mut o = opts(1024);
        o.sudo = sudo_input("right-pw");
        let prompt = o.sudo.as_ref().unwrap().prompt.clone();
        let c = call(&sudo_line(&sudo, "cat", &prompt));
        let r = run(&c, &o, |_| {}).await.unwrap();
        assert_eq!(r["exit_code"], 0, "{r}");
        assert_eq!(r["stdout"], "", "{r}");
        assert_eq!(r["stderr"], "", "the prompt is left out: {r}");
    }

    #[test]
    fn sudo_line_quotes_the_program() {
        assert_eq!(
            sudo_line("/opt/my sudo", "apt update", "p:"),
            "exec '/opt/my sudo' -S -k -p 'p:' apt update"
        );
        assert_eq!(sudo_line("a'b", "x", "p"), "exec 'a'\\''b' -S -k -p 'p' x");
        let p = sudo_prompt();
        assert!(p.starts_with("nerve-sudo-") && p.ends_with(':'), "{p}");
        assert!(!p.contains('%'), "sudo would expand it: {p}");
        assert_ne!(p, sudo_prompt());
    }

    /// Windows has no sudo program: the shell runs what followed `sudo`,
    /// started with the administrator token.
    #[cfg(windows)]
    #[test]
    fn sudo_line_is_the_command_on_windows() {
        assert_eq!(sudo_line("sudo", "net session", "p:"), "net session");
    }

    #[tokio::test]
    async fn timeout_kills_the_group() {
        let mut c = call("sleep 30 & sleep 30; wait");
        c.timeout = Some(Duration::from_millis(200));
        let mut pid = 0;
        let e = run(&c, &opts(1024), |p| pid = p.pid()).await.unwrap_err();
        assert_eq!(e.kind(), ErrorCode::Timeout);
        tokio::time::sleep(Duration::from_millis(100)).await;
        // SAFETY: signal 0 only checks whether the group exists.
        let alive = unsafe { libc::kill(-(pid as libc::pid_t), 0) } == 0;
        assert!(!alive, "the process group outlived the call");
    }

    /// A guard so a command that is not ended fails the test and does not
    /// hang it.
    async fn within_a_few_seconds(
        call: &RunCall,
        opts: &RunOptions,
    ) -> (Result<Value, RpcError>, Duration) {
        let started = std::time::Instant::now();
        let r = tokio::time::timeout(Duration::from_secs(20), run(call, opts, |_| {}))
            .await
            .expect("the command was not ended");
        (r, started.elapsed())
    }

    /// A call without `timeout_ms` is ended at the default.
    #[tokio::test]
    async fn a_call_without_timeout_ms_ends_at_the_default() {
        let mut o = opts(1024);
        o.timeouts = Timeouts {
            default: Duration::from_millis(300),
            max: Duration::from_secs(10),
        };
        let mut c = call("sleep 30");
        c.timeout = None;
        let (r, took) = within_a_few_seconds(&c, &o).await;
        let e = r.unwrap_err();
        assert_eq!(e.kind(), ErrorCode::Timeout);
        assert!(e.message.contains("default limit"), "{}", e.message);
        assert!(took >= Duration::from_millis(300), "{took:?}");
        // One that ends before the default is left alone.
        c.command = "echo done".into();
        let (r, _) = within_a_few_seconds(&c, &o).await;
        assert_eq!(r.unwrap()["stdout"], "done\n");
    }

    /// A `timeout_ms` above the maximum is cut to it, and one below it is kept.
    #[tokio::test]
    async fn a_larger_timeout_ms_is_cut_to_the_maximum() {
        let mut o = opts(1024);
        o.timeouts = Timeouts {
            default: Duration::from_secs(10),
            max: Duration::from_millis(400),
        };
        let mut c = call("sleep 30");
        c.timeout = Some(Duration::from_secs(600));
        let (r, took) = within_a_few_seconds(&c, &o).await;
        let e = r.unwrap_err();
        assert_eq!(e.kind(), ErrorCode::Timeout);
        assert!(e.message.contains("maximum"), "{}", e.message);
        assert!(took >= Duration::from_millis(400), "{took:?}");
        // Below the maximum the call's own value counts.
        c.timeout = Some(Duration::from_millis(100));
        let (r, _) = within_a_few_seconds(&c, &o).await;
        let e = r.unwrap_err();
        assert!(e.message.contains("past timeout_ms"), "{}", e.message);
    }

    #[test]
    fn leaves_the_nodes_folders_out_of_every_set() {
        let d = tempfile::tempdir().unwrap();
        let w = std::fs::canonicalize(d.path()).unwrap();
        for dir in ["a", "deep/cfg/keys", "deep/sib", "other"] {
            std::fs::create_dir_all(w.join(dir)).unwrap();
        }
        std::fs::write(w.join("file.txt"), "x").unwrap();
        std::os::unix::fs::symlink(w.join("deep"), w.join("link")).unwrap();
        std::os::unix::fs::symlink(w.join("deep/cfg"), w.join("other/to-cfg")).unwrap();
        let own = [w.join("deep/cfg")];
        let mut got = leave_out(&[w.clone(), w.join("other")], &own);
        got.sort();
        got.dedup();
        // The folder that holds `cfg` is replaced by its other entries, down
        // to `cfg`; the symlink around it is gone; a folder beside it stays
        // whole (a symlink deeper inside is no rule, and Landlock judges what
        // it resolves to).
        let want: Vec<PathBuf> = ["a", "deep/sib", "file.txt", "other"]
            .iter()
            .map(|p| w.join(p))
            .collect();
        assert_eq!(got, want);
        assert!(leave_out(&[w.join("deep/cfg/keys")], &own).is_empty());
        assert!(leave_out(&[w.join("link/cfg")], &own).is_empty());
        // A symlink given as a folder is judged by where it leads.
        let mut via_link = leave_out(&[w.join("link")], &own);
        via_link.sort();
        assert_eq!(via_link, [w.join("deep/sib")]);

        let policy = CenterPolicy {
            folders: vec![nerve_policy::config::Folder {
                path: w.display().to_string(),
                access: Access::ALL,
            }],
            ..Default::default()
        };
        let spec = landlock_spec(&policy, &w, &own, &[]);
        for set in [&spec.read, &spec.write, &spec.exec] {
            assert!(set.contains(&w.join("a")), "{set:?}");
            assert!(!set.iter().any(|p| own[0].starts_with(p)), "{set:?}");
        }
    }

    /// A folder that is, or since became, a link into a protected entry is
    /// left out of every set, unless the folders release that place with its
    /// flags. The protected entry is the `.ssh` of a home in a temp dir.
    #[test]
    fn leaves_a_link_into_a_protected_entry_out() {
        let d = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(d.path()).unwrap().join("home");
        let ssh = home.join(".ssh");
        let work = home.join("work");
        std::fs::create_dir_all(&ssh).unwrap();
        std::fs::create_dir_all(work.join("plain")).unwrap();
        std::os::unix::fs::symlink(&ssh, work.join("link")).unwrap();
        let folder = |p: &Path, access: &str| nerve_policy::config::Folder {
            path: p.display().to_string(),
            access: Access::parse(access).unwrap(),
        };
        let mut policy = CenterPolicy {
            folders: vec![
                folder(&work.join("link"), "rwx"),
                folder(&work.join("plain"), "rwx"),
            ],
            ..Default::default()
        };
        let reaches = |spec: &LandlockSpec, p: &Path| {
            [&spec.read, &spec.write, &spec.exec]
                .iter()
                .any(|set| set.iter().any(|s| s.starts_with(p)))
        };
        let spec = landlock_spec(&policy, &home, &[], &[]);
        assert!(!reaches(&spec, &ssh), "{spec:?}");
        assert!(!reaches(&spec, &work.join("link")), "{spec:?}");
        for set in [&spec.read, &spec.write, &spec.exec] {
            assert!(set.contains(&work.join("plain")), "{set:?}");
        }
        // The plain folder becomes a link after it was added.
        std::fs::remove_dir(work.join("plain")).unwrap();
        std::os::unix::fs::symlink(&ssh, work.join("plain")).unwrap();
        let spec = landlock_spec(&policy, &home, &[], &[]);
        assert!(!reaches(&spec, &ssh), "{spec:?}");
        assert!(!reaches(&spec, &work.join("plain")), "{spec:?}");
        // The owner released `.ssh` for reading: a link there reads it.
        policy.folders = vec![folder(&ssh, "r"), folder(&work.join("link"), "r")];
        let spec = landlock_spec(&policy, &home, &[], &[]);
        assert!(spec.read.contains(&ssh), "{spec:?}");
        assert!(!spec.write.iter().any(|s| s.starts_with(&ssh)), "{spec:?}");
    }

    /// A folder that holds a protected entry gives none of it: Landlock
    /// cannot deny inside a rule, so the folder is replaced by its other
    /// entries, level by level down to the protected one, in each set. The
    /// protected entries are those of a home in a temp dir.
    #[test]
    fn a_folder_around_a_protected_entry_leaves_it_out() {
        let d = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(d.path()).unwrap().join("home");
        let ssh = home.join(".ssh");
        for dir in [".ssh", "other", ".local/bin"] {
            std::fs::create_dir_all(home.join(dir)).unwrap();
        }
        std::os::unix::fs::symlink(&ssh, home.join("to-ssh")).unwrap();
        let folder = |p: &Path, access: &str| nerve_policy::config::Folder {
            path: p.display().to_string(),
            access: Access::parse(access).unwrap(),
        };
        let real = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        // No rule is the entry, inside it, around it, or a link into it.
        let grants = |set: &[PathBuf], p: &Path| {
            set.iter()
                .any(|s| p.starts_with(s) || s.starts_with(p) || real(s).starts_with(p))
        };
        let mut policy = CenterPolicy {
            folders: vec![folder(&home, "rwx")],
            ..Default::default()
        };
        let spec = landlock_spec(&policy, &home, &[], &[]);
        for set in [&spec.read, &spec.write, &spec.exec] {
            assert!(!grants(set, &ssh), "{set:?}");
            assert!(set.contains(&home.join("other")), "{set:?}");
        }
        // `.local/bin` is protected for writes only.
        let bin = home.join(".local/bin");
        assert!(!grants(&spec.write, &bin), "{:?}", spec.write);
        assert!(spec.read.contains(&bin), "{:?}", spec.read);
        // The owner's own folder at the entry still gives it what it says.
        policy.folders.push(folder(&ssh, "r"));
        let spec = landlock_spec(&policy, &home, &[], &[]);
        assert!(spec.read.contains(&ssh), "{:?}", spec.read);
        assert!(!grants(&spec.write, &ssh), "{:?}", spec.write);
        assert!(!grants(&spec.exec, &ssh), "{:?}", spec.exec);
    }

    /// Every combination of the three flags puts a folder in exactly the
    /// sets of its flags: `w` without `r` is in `write` only.
    #[test]
    fn each_folder_flag_puts_it_in_its_own_set() {
        // A home beside the folder, so that the folder holds none of its
        // protected entries.
        let (d, h) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let w = std::fs::canonicalize(d.path()).unwrap();
        for bits in 0..8u8 {
            let access = Access {
                read: bits & 1 != 0,
                write: bits & 2 != 0,
                execute: bits & 4 != 0,
            };
            let policy = CenterPolicy {
                folders: vec![nerve_policy::config::Folder {
                    path: w.display().to_string(),
                    access,
                }],
                ..Default::default()
            };
            let spec = landlock_spec(&policy, h.path(), &[], &[]);
            let label = access.to_chmod();
            assert_eq!(spec.read.contains(&w), access.read, "read set of {label}");
            assert_eq!(
                spec.write.contains(&w),
                access.write,
                "write set of {label}"
            );
            assert_eq!(
                spec.exec.contains(&w),
                access.execute,
                "exec set of {label}"
            );
        }
    }

    /// Whether a rule of `spec` for a folder is `p`, holds it, lies inside it
    /// or leads there. The system's own rules are left aside.
    fn spec_reaches(spec: &LandlockSpec, p: &Path) -> bool {
        let system = [
            nerve_sandbox::system_dirs(),
            nerve_sandbox::system_writable(),
        ]
        .concat();
        [&spec.read, &spec.write, &spec.exec]
            .into_iter()
            .flatten()
            .filter(|s| !system.contains(s))
            .any(|s| {
                let r = real(s);
                p.starts_with(&r) || r.starts_with(p)
            })
    }

    fn folder(p: &Path, access: &str) -> Folder {
        Folder {
            path: p.display().to_string(),
            access: Access::parse(access).unwrap(),
        }
    }

    /// A home in a temp dir with `work`, a `work/bin` and, beside them, the
    /// `docs` that no folder names.
    fn nested_home(d: &tempfile::TempDir) -> (PathBuf, PathBuf, PathBuf) {
        let home = std::fs::canonicalize(d.path()).unwrap().join("home");
        for dir in ["work/bin", "docs"] {
            std::fs::create_dir_all(home.join(dir)).unwrap();
        }
        (home.clone(), home.join("work"), home.join("docs"))
    }

    /// A command with `w` on `work` replaces `work/bin`, a folder of its own,
    /// by a link to a place no folder names (issue #74): the next command's
    /// rules must not grant the flags of `bin` there, whether the folder is
    /// one of the same center, the only one of another, or deeper down.
    #[test]
    fn a_link_put_in_place_of_a_nested_folder_gets_no_rule() {
        let d = tempfile::tempdir().unwrap();
        let (home, work, docs) = nested_home(&d);
        let bin = work.join("bin");
        let both = CenterPolicy {
            folders: vec![folder(&work, "rw"), folder(&bin, "rx")],
            ..Default::default()
        };
        // Another center holds only `bin`; `work` is writable by the first.
        let only_bin = CenterPolicy {
            folders: vec![folder(&bin, "rx")],
            ..Default::default()
        };
        let writable = [work.clone()];

        // Plain, `bin` is a rule of its own.
        let spec = landlock_spec(&both, &home, &[], &writable);
        assert!(spec.read.contains(&bin), "{spec:?}");
        assert!(spec.exec.contains(&bin), "{spec:?}");
        let spec = landlock_spec(&only_bin, &home, &[], &writable);
        assert!(spec.read.contains(&bin), "{spec:?}");

        std::fs::remove_dir(&bin).unwrap();
        std::os::unix::fs::symlink(&docs, &bin).unwrap();
        for policy in [&both, &only_bin] {
            let spec = landlock_spec(policy, &home, &[], &writable);
            assert!(!spec_reaches(&spec, &docs), "{spec:?}");
            assert!(
                !spec.read.contains(&bin) && !spec.exec.contains(&bin),
                "{spec:?}"
            );
        }
        // `work` itself stays, with its own flags.
        let spec = landlock_spec(&both, &home, &[], &writable);
        assert!(spec.write.contains(&work), "{spec:?}");
        assert!(spec.read.contains(&work), "{spec:?}");

        // A link further down the folder's path is the same.
        std::fs::remove_file(&bin).unwrap();
        std::fs::create_dir_all(docs.join("sub/deep")).unwrap();
        std::fs::create_dir_all(work.join("a/sub/deep")).unwrap();
        let deep = work.join("a/sub/deep");
        let policy = CenterPolicy {
            folders: vec![folder(&work, "rw"), folder(&deep, "r")],
            ..Default::default()
        };
        let spec = landlock_spec(&policy, &home, &[], &writable);
        assert!(spec.read.contains(&deep), "{spec:?}");
        std::fs::remove_dir_all(work.join("a")).unwrap();
        std::fs::create_dir_all(work.join("a")).unwrap();
        std::os::unix::fs::symlink(docs.join("sub"), work.join("a/sub")).unwrap();
        let spec = landlock_spec(&policy, &home, &[], &writable);
        assert!(!spec_reaches(&spec, &docs), "{spec:?}");
        assert!(spec.read.contains(&work), "{spec:?}");
    }

    /// The links of the owner stay what they were: a folder behind a link
    /// outside every write folder is followed, and so is a write folder that
    /// is a link itself, with a folder inside it.
    #[test]
    fn a_link_of_the_owner_is_followed_outside_the_write_folders() {
        let d = tempfile::tempdir().unwrap();
        let (home, work, docs) = nested_home(&d);
        let bin = work.join("bin");
        // No write folder: the folder is the only one, and its link is followed.
        std::os::unix::fs::symlink(&docs, home.join("to-docs")).unwrap();
        let policy = CenterPolicy {
            folders: vec![folder(&home.join("to-docs"), "r")],
            ..Default::default()
        };
        let spec = landlock_spec(&policy, &home, &[], &[]);
        assert!(spec.read.contains(&docs), "{spec:?}");
        // Beside the write folder, not inside it.
        let spec = landlock_spec(&policy, &home, &[], std::slice::from_ref(&work));
        assert!(spec.read.contains(&docs), "{spec:?}");

        // The write folder is the owner's link to `work`, and a command
        // writes through it: the folder inside it is where it really is.
        std::os::unix::fs::symlink(&work, home.join("w")).unwrap();
        let policy = CenterPolicy {
            folders: vec![
                folder(&home.join("w"), "rw"),
                folder(&home.join("w/bin"), "r"),
            ],
            ..Default::default()
        };
        let spec = landlock_spec(&policy, &home, &[], &[home.join("w")]);
        assert!(spec.read.contains(&work), "{spec:?}");
        assert!(spec.read.contains(&bin), "{spec:?}");
        // The write folder spelled by its real path catches the same folder.
        let spec = landlock_spec(&policy, &home, &[], std::slice::from_ref(&work));
        assert!(spec.read.contains(&bin), "{spec:?}");
        // The write folder is named by the link, the folder by the real path.
        let policy = CenterPolicy {
            folders: vec![folder(&bin, "r")],
            ..Default::default()
        };
        std::fs::remove_dir(&bin).unwrap();
        std::os::unix::fs::symlink(&docs, &bin).unwrap();
        let spec = landlock_spec(&policy, &home, &[], &[home.join("w")]);
        assert!(!spec_reaches(&spec, &docs), "{spec:?}");
    }

    /// Issue #77: a link a command put in place of a nested folder while its
    /// outer folder had `w` stays out of the rules after that `w` is gone
    /// (narrowed to `r`, or the pairing removed), when the node recorded the
    /// folder at its real place (`folder add`). A folder without the record
    /// is followed again, and a plain folder at the recorded place is a rule.
    #[test]
    fn a_link_put_in_place_of_a_recorded_folder_stays_out_once_the_write_is_gone() {
        let d = tempfile::tempdir().unwrap();
        let (home, work, docs) = nested_home(&d);
        let bin = work.join("bin");
        std::fs::create_dir_all(docs.join("sub/deep")).unwrap();
        std::fs::create_dir_all(work.join("a/sub/deep")).unwrap();
        let deep = work.join("a/sub/deep");
        let mut policy = CenterPolicy {
            folders: vec![folder(&work, "r"), folder(&bin, "rx"), folder(&deep, "r")],
            ..Default::default()
        };
        for f in [&bin, &deep] {
            policy.set_placed(&f.display().to_string(), true);
        }
        let writable = [work.clone()];
        let spec = landlock_spec(&policy, &home, &[], &[]);
        assert!(
            spec.read.contains(&bin) && spec.exec.contains(&bin),
            "{spec:?}"
        );
        assert!(spec.read.contains(&deep), "{spec:?}");

        // A command with `w` on `work` replaces `bin`, and `a` above `deep`.
        std::fs::remove_dir(&bin).unwrap();
        std::os::unix::fs::symlink(&docs, &bin).unwrap();
        std::fs::remove_dir_all(work.join("a")).unwrap();
        std::os::unix::fs::symlink(&docs, work.join("a")).unwrap();
        let spec = landlock_spec(&policy, &home, &[], &writable);
        assert!(!spec_reaches(&spec, &docs), "{spec:?}");

        // `work` is `r` now, or its pairing is gone: no `w` folder is left
        // to show the links, and the record keeps them out.
        let spec = landlock_spec(&policy, &home, &[], &[]);
        assert!(!spec_reaches(&spec, &docs), "{spec:?}");
        assert!(spec.read.contains(&work), "{spec:?}");
        // The same without the record: the links are followed.
        let mut loose = policy.clone();
        loose.places.clear();
        let spec = landlock_spec(&loose, &home, &[], &[]);
        assert!(spec.read.contains(&docs.join("sub/deep")), "{spec:?}");

        // Plain folders at the recorded places are rules again.
        std::fs::remove_file(&bin).unwrap();
        std::fs::create_dir(&bin).unwrap();
        std::fs::remove_file(work.join("a")).unwrap();
        std::fs::create_dir_all(&deep).unwrap();
        let spec = landlock_spec(&policy, &home, &[], &[]);
        assert!(
            spec.read.contains(&bin) && spec.exec.contains(&bin),
            "{spec:?}"
        );
        assert!(spec.read.contains(&deep), "{spec:?}");
    }

    /// A recorded folder that did not exist yet is judged the same: a link
    /// at its place later keeps it out. An owner's link in the path of a
    /// folder that was not recorded stays followed.
    #[test]
    fn a_folder_recorded_before_it_existed_is_not_followed_through_a_link() {
        let d = tempfile::tempdir().unwrap();
        let (home, work, docs) = nested_home(&d);
        let later = home.join("later");
        let mut policy = CenterPolicy {
            folders: vec![folder(&later, "r")],
            ..Default::default()
        };
        policy.set_placed(&later.display().to_string(), true);
        std::os::unix::fs::symlink(&docs, &later).unwrap();
        let spec = landlock_spec(&policy, &home, &[], &[]);
        assert!(!spec_reaches(&spec, &docs), "{spec:?}");
        std::fs::remove_file(&later).unwrap();
        std::fs::create_dir(&later).unwrap();
        let spec = landlock_spec(&policy, &home, &[], &[]);
        assert!(spec.read.contains(&later), "{spec:?}");

        let to_work = home.join("to-work");
        std::os::unix::fs::symlink(&work, &to_work).unwrap();
        let owner = CenterPolicy {
            folders: vec![folder(&to_work, "r")],
            ..Default::default()
        };
        let spec = landlock_spec(&owner, &home, &[], &[]);
        assert!(spec.read.contains(&work), "{spec:?}");
    }

    /// A link of the owner's that leads into a write folder is followed down
    /// to where it ends, and the links on that way are judged too: a command
    /// that replaces the folder the owner's link leads to, or one above it,
    /// by a link of its own gets no rule for the place that leads to.
    #[test]
    fn a_link_put_below_an_owners_link_into_a_write_folder_gets_no_rule() {
        let d = tempfile::tempdir().unwrap();
        let (home, work, docs) = nested_home(&d);
        let bin = work.join("bin");
        let writable = [work.clone()];

        // The owner's relative link to `work/bin`, beside the write folder.
        std::os::unix::fs::symlink("work/bin", home.join("tools")).unwrap();
        let policy = CenterPolicy {
            folders: vec![folder(&work, "rw"), folder(&home.join("tools"), "rx")],
            ..Default::default()
        };
        let spec = landlock_spec(&policy, &home, &[], &writable);
        assert!(spec.read.contains(&bin), "{spec:?}");
        std::fs::remove_dir(&bin).unwrap();
        std::os::unix::fs::symlink(&docs, &bin).unwrap();
        let spec = landlock_spec(&policy, &home, &[], &writable);
        assert!(!spec_reaches(&spec, &docs), "{spec:?}");
        assert!(spec.write.contains(&work), "{spec:?}");

        // The only folder of another center leads through two levels, and the
        // command replaces the upper one.
        std::fs::remove_file(&bin).unwrap();
        std::fs::create_dir_all(work.join("a/b")).unwrap();
        std::fs::create_dir_all(docs.join("b")).unwrap();
        std::os::unix::fs::symlink(work.join("a/b"), home.join("proj")).unwrap();
        let reader = CenterPolicy {
            folders: vec![folder(&home.join("proj"), "r")],
            ..Default::default()
        };
        let spec = landlock_spec(&reader, &home, &[], &writable);
        assert!(spec.read.contains(&work.join("a/b")), "{spec:?}");
        std::fs::remove_dir_all(work.join("a")).unwrap();
        std::os::unix::fs::symlink(&docs, work.join("a")).unwrap();
        let spec = landlock_spec(&reader, &home, &[], &writable);
        assert!(!spec_reaches(&spec, &docs), "{spec:?}");
    }

    /// `settle` follows the path of a folder about to be added a link at a
    /// time and answers with where it really is: a link of the owner's
    /// outside the `w` folders is followed, one inside a `w` folder or one to
    /// nowhere refuses, a link swapped in after the walk is caught instead of
    /// followed, and a `w` folder this process cannot resolve makes it say it
    /// cannot tell.
    #[test]
    fn a_folder_about_to_be_added_is_settled_where_it_really_is() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let (home, work, docs) = nested_home(&d);
        let bin = work.join("bin");
        let policy = |w: &Path| CenterPolicy {
            folders: vec![folder(w, "rw")],
            ..Default::default()
        };
        let mut cfg = NodeConfig::default();
        let mut entry = nerve_policy::CenterEntry {
            name: "lab".into(),
            url: "https://center.example".into(),
            pin: None,
            center_id: "c".into(),
            node_id: "n".into(),
            settings: Default::default(),
            paused: false,
            revoked: false,
            unknown: false,
            public_key: None,
            key_rotations: 0,
            pin_rotations: 0,
            old_pin: None,
            policy: policy(&work),
        };
        cfg.centers.push(entry.clone());
        // A plain folder, one that is not there yet, and the owner's link
        // outside every `w` folder.
        assert_eq!(settle(&cfg, &home, &bin), Settled::At(bin.clone()));
        let later = work.join("later/deeper");
        assert_eq!(settle(&cfg, &home, &later), Settled::At(later.clone()));
        std::os::unix::fs::symlink(&docs, home.join("to-docs")).unwrap();
        assert_eq!(
            settle(&cfg, &home, &home.join("to-docs")),
            Settled::At(docs.clone())
        );
        // Tidied: a doubled separator and a `.` part.
        let odd = PathBuf::from(format!("{}//./bin", work.display()));
        assert_eq!(settle(&cfg, &home, &odd), Settled::At(bin.clone()));

        // A link inside the `w` folder is not followed, whoever made it.
        std::fs::remove_dir(&bin).unwrap();
        std::os::unix::fs::symlink(&docs, &bin).unwrap();
        let Settled::Refused(why) = settle(&cfg, &home, &bin) else {
            panic!("a link in a write folder was followed")
        };
        assert!(why.contains("may write"), "{why}");
        assert!(matches!(
            settle(&cfg, &home, &bin.join("sub")),
            Settled::Refused(_)
        ));
        // A link to nothing is refused.
        std::os::unix::fs::symlink(home.join("nowhere"), home.join("dangling")).unwrap();
        assert!(matches!(
            settle(&cfg, &home, &home.join("dangling")),
            Settled::Refused(_)
        ));

        // A link swapped in after the walk: what resolves is not what was
        // looked at.
        std::fs::remove_file(&bin).unwrap();
        std::fs::create_dir(&bin).unwrap();
        let swapped = |_: &Path| Ok(docs.clone());
        let Settled::Refused(why) = settle_by(&cfg, &home, &bin, swapped) else {
            panic!("a swapped link was followed")
        };
        assert!(why.contains("meanwhile"), "{why}");

        // A `w` folder that cannot be resolved here (a closed folder holds
        // it) makes the links inside it impossible to judge.
        if nerve_transport::net::euid() == 0 {
            return; // root looks into every folder
        }
        let closed = home.join("closed");
        std::fs::create_dir_all(closed.join("code")).unwrap();
        entry.policy = policy(&closed.join("code"));
        cfg.centers[0] = entry;
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).unwrap();
        let settled = settle(&cfg, &home, &bin);
        let inside = settle(&cfg, &home, &closed.join("code/x"));
        // With another `w` folder that does resolve, a link it holds is
        // still refused, and only a path with no such link is not told.
        entry = cfg.centers[0].clone();
        entry.policy.folders.push(folder(&work, "rw"));
        cfg.centers[0] = entry;
        let lnk = work.join("lnk");
        std::os::unix::fs::symlink(&docs, &lnk).unwrap();
        let (kept, plain) = (
            settle(&cfg, &home, &lnk),
            settle(&cfg, &home, &work.join("plain")),
        );
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(settled, Settled::Unknown);
        assert_eq!(inside, Settled::Unknown);
        assert!(matches!(kept, Settled::Refused(w) if w.contains("may write")));
        assert_eq!(plain, Settled::Unknown);
    }

    /// A link is judged by the folder that holds it as spelled and as it
    /// resolves: a holder inside a `w` folder either way refuses it, and a
    /// holder that is not the place it was looked at as (a name of it was
    /// swapped for a link between the two looks, played here by a
    /// resolution that leads elsewhere) refuses it too. Otherwise the link
    /// of the owner's is followed.
    #[test]
    fn a_link_is_judged_by_its_holder_as_spelled_and_as_resolved() {
        let d = tempfile::tempdir().unwrap();
        let (home, work, docs) = nested_home(&d);
        let (x, outside) = (work.join("x"), home.join("outside"));
        std::fs::create_dir_all(&x).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&docs, x.join("name")).unwrap();
        std::os::unix::fs::symlink(&docs, outside.join("name")).unwrap();
        // Resolving anything but the root leads elsewhere (a swapped name).
        let root = PathBuf::from("/");
        let swapped = |p: &Path| {
            if p == root.as_path() {
                root.clone()
            } else {
                PathBuf::from("/nowhere")
            }
        };
        let w = [work.clone()];
        // The holder is inside the `w` folder as spelled, though it
        // resolves outside it now: refused all the same.
        let e = walk_by(&x.join("name"), &w, swapped).unwrap_err();
        assert!(e.contains("may write"), "{e}");
        // Outside every `w` folder but not the place it was looked at as.
        let e = walk_by(&outside.join("name"), &w, swapped).unwrap_err();
        assert!(e.contains("meanwhile"), "{e}");
        // Nothing swapped: the link outside is the owner's and is followed,
        // the one inside is not.
        assert_eq!(walk_by(&outside.join("name"), &w, real), Ok(docs.clone()));
        assert!(walk_by(&x.join("name"), &w, real).is_err());
    }

    /// `lands_at` follows a path a link at a time and answers with the first
    /// place the path lands at that is wanted: its own end, then where each
    /// link at an end leads, a link itself judged before it is followed. A
    /// folder it only passes does not count, and a dangling link or a loop
    /// ends it.
    #[test]
    fn a_path_lands_where_its_links_lead() {
        let d = tempfile::tempdir().unwrap();
        let (home, _, docs) = nested_home(&d);
        let (real, code) = (home.join("data/real"), home.join("code"));
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink("data/real", &code).unwrap();
        let at = |wanted: &Path| lands_at(&code, |p| p == wanted);
        assert_eq!(at(&real), Some(real.clone()));
        assert_eq!(at(&code), Some(code.clone()));
        assert_eq!(at(&docs), None);
        // The place itself is a link now: judged as a link, not followed.
        std::fs::remove_dir(&real).unwrap();
        std::os::unix::fs::symlink(&docs, &real).unwrap();
        assert_eq!(at(&real), Some(real.clone()));
        assert_eq!(at(&docs), Some(docs.clone()));
        // A folder passed on the way is not where the path lands.
        assert_eq!(lands_at(&real.join("sub"), |p| p == real), None);
        assert_eq!(lands_at(&home.join("data/gone"), |p| p == real), None);
        // Dangling links and loops end it.
        std::os::unix::fs::symlink(home.join("nowhere"), home.join("dangling")).unwrap();
        assert_eq!(lands_at(&home.join("dangling"), |_| false), None);
        std::os::unix::fs::symlink("two", home.join("one")).unwrap();
        std::os::unix::fs::symlink("one", home.join("two")).unwrap();
        assert_eq!(lands_at(&home.join("one"), |p| p == docs), None);
    }

    /// Links that lead into one another are no way to a folder.
    #[test]
    fn a_loop_of_links_is_led_away() {
        let d = tempfile::tempdir().unwrap();
        let (home, work, _) = nested_home(&d);
        std::os::unix::fs::symlink("two", home.join("one")).unwrap();
        std::os::unix::fs::symlink("one", home.join("two")).unwrap();
        assert!(led_away(&home.join("one"), &[]).is_some());
        assert!(led_away(&work, &[]).is_none());
    }

    /// The write folders that bound the others are those of every center
    /// in the config, `~` expanded, whatever the center's mode.
    #[test]
    fn the_write_folders_of_every_center_bound_the_others() {
        let d = tempfile::tempdir().unwrap();
        let (home, work, docs) = nested_home(&d);
        let entry = |name: &str, mode, folders: Vec<Folder>| nerve_policy::CenterEntry {
            name: name.into(),
            url: "https://center.example".into(),
            pin: None,
            center_id: name.into(),
            node_id: name.into(),
            settings: Default::default(),
            paused: false,
            revoked: false,
            unknown: false,
            public_key: None,
            key_rotations: 0,
            pin_rotations: 0,
            old_pin: None,
            policy: CenterPolicy {
                mode,
                folders,
                ..Default::default()
            },
        };
        let mut cfg = NodeConfig::default();
        cfg.centers.push(entry(
            "writer",
            nerve_policy::Mode::Allowlist,
            vec![folder(&work, "rw"), folder(Path::new("~/docs"), "r")],
        ));
        cfg.centers.push(entry(
            "reader",
            nerve_policy::Mode::Folder,
            vec![folder(&work.join("bin"), "rx")],
        ));
        assert_eq!(write_folders(&cfg, &home), std::slice::from_ref(&work));

        // The writer's command swaps the reader's only folder.
        std::fs::remove_dir(work.join("bin")).unwrap();
        std::os::unix::fs::symlink(&docs, work.join("bin")).unwrap();
        let reader = &cfg.centers[1].policy;
        let spec = landlock_spec(reader, &home, &[], &write_folders(&cfg, &home));
        assert!(!spec_reaches(&spec, &docs), "{spec:?}");
        // Judged by its own folders alone, the link would be followed.
        let spec = landlock_spec(reader, &home, &[], &[]);
        assert!(spec.read.contains(&docs), "{spec:?}");
    }

    #[test]
    fn parses_args() {
        let home = std::env::temp_dir();
        let a = json!({"command": "ls"}).as_object().unwrap().clone();
        let c = RunCall::parse(&a, &home).unwrap();
        assert_eq!(c.cwd, std::fs::canonicalize(&home).unwrap());
        let bad = json!({"command": "ls", "shell": "x"})
            .as_object()
            .unwrap()
            .clone();
        assert!(RunCall::parse(&bad, &home).is_err());
        assert_eq!(shell_command(None, "ls").1, ["-c", "ls"]);
    }
}

/// The shell's text, the output decoding and the run-time limits: plain
/// logic, on every platform.
#[cfg(test)]
mod text_tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn timeouts(default: u64, max: u64) -> Timeouts {
        Timeouts {
            default: secs(default),
            max: secs(max),
        }
    }

    /// Root's shell gets an allowed sudo line without a leading `-n` and
    /// `--`; any other option of sudo, and a line that names no command,
    /// are refused with the reason (#142).
    #[test]
    fn a_root_line_takes_only_n_and_the_end_of_options() {
        for (args, line) in [
            ("apt update", "apt update"),
            ("-n apt update", "apt update"),
            ("-- apt update", "apt update"),
            ("-n -- apt update", "apt update"),
            ("-n  -n\tapt -y install x", "apt -y install x"),
        ] {
            assert_eq!(root_line(args).unwrap(), line, "{args:?}");
        }
        for args in [
            "-E apt update",
            "-u bob id",
            "-n -E id",
            "-nE id",
            "-- -x",
            "-- -n id",
            "-- -- id",
            "-i",
        ] {
            let e = root_line(args).unwrap_err();
            assert!(
                e.message.contains("no sudo option but -n and --"),
                "{args:?}: {e:?}"
            );
        }
        for args in ["", "-n", "--", "-n --  "] {
            let e = root_line(args).unwrap_err();
            assert!(e.message.contains("names no command"), "{args:?}: {e:?}");
        }
    }

    /// A call without `timeout_ms` gets the default, one within the maximum
    /// gets what it asked for, and a larger one is cut to the maximum. The
    /// default is cut as well.
    #[test]
    fn a_call_gets_the_default_and_no_more_than_the_maximum() {
        let t = timeouts(60, 300);
        assert_eq!(t.limit(None).after, secs(60));
        assert_eq!(t.limit(Some(secs(5))).after, secs(5));
        assert_eq!(t.limit(Some(secs(300))).after, secs(300));
        assert_eq!(t.limit(Some(secs(301))).after, secs(300));
        assert_eq!(t.limit(Some(secs(86_400))).after, secs(300));
        assert_eq!(
            t.limit(Some(Duration::from_millis(u64::MAX))).after,
            secs(300)
        );
        // An owner who lowers the maximum below the default.
        assert_eq!(timeouts(600, 30).limit(None).after, secs(30));
        // What `limits` holds when the owner set nothing.
        assert_eq!(Timeouts::default(), timeouts(600, 3600));
    }

    /// `timeout_ms` of 0 is no value: it gets the default, never no limit.
    #[test]
    fn a_zero_timeout_is_no_timeout_and_not_no_limit() {
        let home = std::env::temp_dir();
        let zero = json!({"command": "ls", "timeout_ms": 0})
            .as_object()
            .unwrap()
            .clone();
        let c = RunCall::parse(&zero, &home).unwrap();
        assert_eq!(c.timeout, None);
        assert_eq!(timeouts(60, 300).limit(c.timeout).after, secs(60));
        let some = json!({"command": "ls", "timeout_ms": 1500})
            .as_object()
            .unwrap()
            .clone();
        assert_eq!(
            RunCall::parse(&some, &home).unwrap().timeout,
            Some(Duration::from_millis(1500))
        );
    }

    /// The error says which limit ended the command, so a model knows whether
    /// a larger `timeout_ms` would help.
    #[test]
    fn the_timeout_says_which_limit_it_was() {
        let t = timeouts(600, 3600);
        let say = |l: RunLimit| {
            let e = l.timed_out();
            assert_eq!(e.kind(), ErrorCode::Timeout);
            e.message
        };
        assert_eq!(
            say(t.limit(Some(secs(30)))),
            "the command ran past timeout_ms (30 s) and was killed"
        );
        assert_eq!(
            say(t.limit(None)),
            "the command ran past the default limit of 10 min and was killed: no timeout_ms was given (up to 1 h is allowed)"
        );
        assert_eq!(
            say(t.limit(Some(secs(7200)))),
            "the command ran past the node's maximum of 1 h and was killed: timeout_ms asked for 2 h, which the owner's limits.max_timeout_secs cuts"
        );
        // The default is the maximum: a larger timeout_ms would not help.
        assert_eq!(
            say(timeouts(60, 60).limit(None)),
            "the command ran past the node's limit of 1 min and was killed: no timeout_ms was given"
        );
        assert_eq!(
            say(timeouts(600, 30).limit(None)),
            "the command ran past the node's maximum of 30 s and was killed: no timeout_ms was given, and the owner's limits.max_timeout_secs is below the default"
        );
    }

    /// The `exec.run` text tells a model what a command gets.
    #[test]
    fn the_run_action_names_its_time_limits() {
        assert_eq!(
            timeout_summary(&timeouts(600, 3600)),
            "A command is killed after timeout_ms, after 10 min when you give none, and never runs longer than 1 h."
        );
        // The default shown is the one that applies.
        assert_eq!(
            timeout_summary(&timeouts(600, 90)),
            "A command is killed after timeout_ms, after 1 min 30 s when you give none, and never runs longer than 1 min 30 s."
        );
    }

    /// A stand-in for code page 850 with the two letters the tests use.
    fn cp850(b: &[u8]) -> Option<String> {
        b.iter()
            .map(|c| match c {
                0x81 => Some('ü'),
                0xE1 => Some('ß'),
                c if c.is_ascii() => Some(*c as char),
                _ => None,
            })
            .collect()
    }

    /// Windows PowerShell 5.1 wrote a German error in the console code page:
    /// it comes back with its umlauts, not as replacement characters.
    #[test]
    fn output_in_another_code_page_is_decoded_with_it() {
        let oem = b"Gr\x81\xE1e: Fehler beim Ausf\x81hren";
        assert_eq!(
            output_text(oem, false, cp850),
            "Grüße: Fehler beim Ausführen"
        );
        // UTF-8 stays UTF-8, and the code page is not asked.
        assert_eq!(output_text("Grüße".as_bytes(), false, |_| None), "Grüße");
        // The cap cut the last character: still UTF-8, not the code page.
        let cut = &"Grüß".as_bytes()[..5];
        assert_eq!(output_text(cut, true, cp850), "Grü\u{FFFD}");
        // Neither reads it: replaced.
        assert_eq!(output_text(b"a\xFFb", false, |_| None), "a\u{FFFD}b");
    }

    /// The `exec.run` text names the shell and, for Windows PowerShell 5.1,
    /// how to chain commands there.
    #[test]
    fn the_run_action_names_its_shell() {
        assert_eq!(
            shell_summary(Some("powershell.exe")),
            "Runs a command in Windows PowerShell 5.1 (`powershell.exe -NoProfile -Command`): \
             PowerShell syntax, not cmd or sh. Chain commands with `;`; `&&` and `a & b` are \
             parser errors there."
        );
        assert_eq!(
            shell_summary(Some(r"C:\Program Files\PowerShell\7\pwsh.exe")),
            "Runs a command in PowerShell 7 (`C:\\Program Files\\PowerShell\\7\\pwsh.exe \
             -NoProfile -Command`): PowerShell syntax, not cmd or sh."
        );
        assert_eq!(
            shell_summary(Some("cmd.exe")),
            "Runs a command in cmd (`cmd.exe /C`): cmd syntax."
        );
        assert_eq!(
            shell_summary(Some("/bin/bash")),
            "Runs a command with `/bin/bash -c`."
        );
        let default = shell_summary(None);
        if cfg!(windows) {
            assert!(default.contains("Windows PowerShell 5.1"), "{default}");
        } else {
            assert_eq!(default, "Runs a command with `/bin/sh -c`.");
        }
    }
}

/// Windows only: the real shell, code pages and process table. The owner
/// runs these on a Windows machine.
#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    fn opts() -> RunOptions {
        RunOptions {
            shell: None,
            landlock: None,
            container: None,
            exe: PathBuf::from("nerve-node.exe"),
            output_cap: 64 * 1024,
            timeouts: Timeouts::default(),
            sudo: None,
            account: None,
            separate: false,
            own: Vec::new(),
            root: None,
            limits: None,
        }
    }

    fn call(cmd: &str, cwd: &Path, timeout: Duration) -> RunCall {
        RunCall {
            command: cmd.into(),
            cwd: cwd.to_path_buf(),
            timeout: Some(timeout),
            limits: Default::default(),
        }
    }

    /// The short (8.3) spelling of `p`, which must exist.
    fn short_name(p: &Path) -> PathBuf {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        use windows_sys::Win32::Storage::FileSystem::GetShortPathNameW;
        let w: Vec<u16> = p.as_os_str().encode_wide().chain([0]).collect();
        let mut buf = vec![0u16; 1024];
        // SAFETY: a NUL-terminated path and a buffer of the length given.
        let n = unsafe { GetShortPathNameW(w.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
        assert!(n > 0 && (n as usize) < buf.len(), "no short name for {p:?}");
        buf.truncate(n as usize);
        PathBuf::from(std::ffi::OsString::from_wide(&buf))
    }

    /// A folder is settled at its real place when the path spells it another
    /// way than the system does and nothing was swapped: a `subst` drive, and
    /// a junction whose target is written with 8.3 names. Both stood in the
    /// way of the end check, which compares spellings.
    #[test]
    fn a_folder_is_settled_at_its_real_place_through_a_subst_drive_and_a_short_name() {
        let d = tempfile::tempdir().unwrap();
        let root = PathBuf::from(nerve_policy::paths::win::strip_verbatim(
            &std::fs::canonicalize(d.path()).unwrap().to_string_lossy(),
        ));
        let (base, cfg) = (root.join("Some Long Folder Name"), NodeConfig::default());
        let real_dir = base.join("proj");
        std::fs::create_dir_all(&real_dir).unwrap();
        let at = |p: &Path| settle(&cfg, &root, p);
        let place = nerve_policy::paths::resolve(&real_dir).unwrap();

        // A junction to the folder, written with the short names.
        let target = short_name(&base).join("proj");
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(root.join("j8"))
            .arg(&target)
            .output()
            .unwrap();
        assert!(made.status.success(), "{made:?}");
        assert_eq!(at(&root.join("j8")), Settled::At(place.clone()));
        // The short spelling of the folder itself is written out.
        assert_eq!(at(&target), Settled::At(place.clone()));

        // A `subst` drive: the drive is a folder.
        let Some(drive) = Subst::new(&base) else {
            return;
        };
        assert_eq!(at(&drive.join("proj")), Settled::At(place.clone()));
        // The folder mapped by its short names: `subst` keeps them, and the
        // walk writes them out.
        let Some(short) = Subst::new(&short_name(&base)) else {
            return;
        };
        assert_eq!(at(&short.join("proj")), Settled::At(place));
    }

    /// A config with one center whose only folder is `work`, rw.
    fn lab_config(work: &Path) -> NodeConfig {
        let mut cfg = NodeConfig::default();
        cfg.centers.push(nerve_policy::CenterEntry {
            name: "lab".into(),
            url: "https://center.example".into(),
            pin: None,
            center_id: "c".into(),
            node_id: "n".into(),
            settings: Default::default(),
            paused: false,
            revoked: false,
            unknown: false,
            public_key: None,
            key_rotations: 0,
            pin_rotations: 0,
            old_pin: None,
            policy: CenterPolicy {
                folders: vec![Folder {
                    path: work.display().to_string(),
                    access: Access::parse("rw").unwrap(),
                }],
                ..Default::default()
            },
        });
        cfg
    }

    /// An owner's symlink at `link` to the directory `target`; `None` where
    /// the process may not make one.
    fn symlink_to(link: &Path, target: &str) -> Option<()> {
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::windows::fs::symlink_dir(target, link).ok()
    }

    /// The canonical form of a temporary folder.
    fn canonical_tmp(d: &tempfile::TempDir) -> PathBuf {
        PathBuf::from(nerve_policy::paths::win::strip_verbatim(
            &std::fs::canonicalize(d.path()).unwrap().to_string_lossy(),
        ))
    }

    /// The volume GUID path of the volume that holds `p` (`\\?\Volume{…}\`).
    fn volume_root(p: &Path) -> String {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::GetVolumeNameForVolumeMountPointW;
        let drive: Vec<u16> = std::ffi::OsStr::new(&p.display().to_string()[..3])
            .encode_wide()
            .chain([0])
            .collect();
        let mut buf = vec![0u16; 64];
        // SAFETY: a NUL-terminated drive root and a buffer of the length given.
        let ok = unsafe {
            GetVolumeNameForVolumeMountPointW(drive.as_ptr(), buf.as_mut_ptr(), buf.len() as u32)
        };
        assert!(ok != 0, "no volume name for {p:?}");
        let end = buf.iter().position(|&c| c == 0).unwrap();
        String::from_utf16_lossy(&buf[..end])
    }

    /// A `subst` drive on a free letter, unmapped when dropped.
    struct Subst(String);

    impl Subst {
        /// `None` when no letter is free. Tests that run at the same time
        /// can find the same letter free and both take it: the one that
        /// comes second ("Drive already SUBSTed") tries the next.
        fn new(base: &Path) -> Option<Subst> {
            let mut failed = None;
            for letter in ('R'..='Z').rev() {
                let drive = format!("{letter}:");
                if Path::new(&format!("{drive}\\")).exists() {
                    continue;
                }
                let made = std::process::Command::new("subst")
                    .arg(&drive)
                    .arg(base)
                    .output()
                    .unwrap();
                if made.status.success() {
                    return Some(Subst(drive));
                }
                failed = Some(made);
            }
            if let Some(made) = failed {
                panic!("no free letter took the drive: {made:?}");
            }
            None
        }

        /// A path on the drive.
        fn join(&self, rest: &str) -> PathBuf {
            PathBuf::from(format!("{}\\{rest}", self.0))
        }
    }

    impl Drop for Subst {
        fn drop(&mut self) {
            let _ = std::process::Command::new("subst")
                .args([self.0.as_str(), "/d"])
                .output();
        }
    }

    /// A letter that looks free can be taken: by a test that took it
    /// meanwhile, or by a drive whose folder is gone, as here. A new drive
    /// goes to the next letter instead of failing.
    #[test]
    fn a_subst_drive_takes_the_next_letter_when_one_is_taken() {
        let d = tempfile::tempdir().unwrap();
        let gone = d.path().join("gone");
        std::fs::create_dir(&gone).unwrap();
        let Some(taken) = Subst::new(&gone) else {
            return;
        };
        std::fs::remove_dir(&gone).unwrap();
        assert!(!Path::new(&format!("{}\\", taken.0)).exists());
        let Some(next) = Subst::new(d.path()) else {
            return;
        };
        assert_ne!(next.0, taken.0);
        assert!(Path::new(&format!("{}\\", next.0)).exists());
    }

    /// A symlink to a volume root (`\\?\Volume{guid}\…`) is walked as the
    /// place the volume is mounted at, which canonicalize never spells as the
    /// GUID: a folder behind it is settled at its real place (a mounted
    /// volume gave the "meanwhile" refusal before), and a junction in a `w`
    /// folder on the way is still refused.
    #[test]
    fn a_volume_root_is_walked_as_the_place_it_is_mounted_at() {
        let d = tempfile::tempdir().unwrap();
        let root = canonical_tmp(&d);
        let (work, secret) = (root.join("work"), root.join("secret"));
        let project = work.join("project");
        std::fs::create_dir_all(project.join("inner")).unwrap();
        std::fs::create_dir_all(secret.join("inner")).unwrap();
        let cfg = lab_config(&work);
        let at = |p: &Path| settle(&cfg, &root, p);
        let volume = volume_root(&root);
        let on_volume = |p: &Path| format!("{volume}{}", &p.display().to_string()[3..]);
        let Some(()) = symlink_to(&root.join("links").join("vol"), &on_volume(&project)) else {
            return;
        };
        let via = root.join("links").join("vol").join("inner");
        let inner = nerve_policy::paths::resolve(&project.join("inner")).unwrap();
        assert_eq!(at(&via), Settled::At(inner));
        // A command replaces the folder by a junction to `secret`.
        std::fs::rename(&project, work.join("old")).unwrap();
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&project)
            .arg(&secret)
            .output()
            .unwrap();
        assert!(made.status.success(), "{made:?}");
        let Settled::Refused(why) = at(&via) else {
            panic!("{} was followed through the junction", via.display())
        };
        assert!(why.contains("may write"), "{why}");
    }

    /// A `subst` drive is walked through the folder it maps, name by name: a
    /// junction a command put in place of that folder, inside a `w` folder,
    /// is refused like any other, where resolving the drive would have
    /// followed it. A path with a drive but no root (`C:sub`) leads to the
    /// drive's current folder, which no walk can judge, and is refused.
    #[test]
    fn a_subst_drive_is_walked_through_its_folder_name_by_name() {
        let d = tempfile::tempdir().unwrap();
        let root = PathBuf::from(nerve_policy::paths::win::strip_verbatim(
            &std::fs::canonicalize(d.path()).unwrap().to_string_lossy(),
        ));
        let (work, secret) = (root.join("work"), root.join("secret"));
        let project = work.join("project");
        for dir in [project.join("inner"), secret.join("inner")] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let cfg = lab_config(&work);
        let at = |p: &Path| settle(&cfg, &root, p);
        assert!(matches!(at(Path::new("C:sub")), Settled::Refused(_)));
        let Some(drive) = Subst::new(&project) else {
            return;
        };
        let inner = nerve_policy::paths::resolve(&project.join("inner")).unwrap();
        assert_eq!(at(&drive.join("inner")), Settled::At(inner));
        // A command replaces the mapped folder by a junction to `secret`.
        std::fs::rename(&project, work.join("old")).unwrap();
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&project)
            .arg(&secret)
            .output()
            .unwrap();
        assert!(made.status.success(), "{made:?}");
        for path in [drive.join("inner"), drive.join("")] {
            let Settled::Refused(why) = at(&path) else {
                panic!("{} was followed through the junction", path.display())
            };
            assert!(why.contains("may write"), "{why}");
        }
        // An owner's symlink outside `work` to the drive through the object
        // manager reaches the junction too, and is refused the same way.
        let link = root.join("links").join("groot");
        if symlink_to(&link, &format!("\\\\?\\GLOBALROOT\\??\\{}\\", drive.0)).is_some() {
            let given =
                nerve_policy::paths::normal_folder(&link.join("inner").display().to_string())
                    .unwrap();
            assert!(
                matches!(at(Path::new(&given)), Settled::Refused(_)),
                "{given} was followed"
            );
        }
        // The same folder by its own path is refused alike, and so is every
        // other spelling of it that does not name a drive: a device path and a
        // share would reach the junction without it being judged.
        assert!(matches!(at(&project.join("inner")), Settled::Refused(_)));
        let letter = &drive.0;
        let share = project.display().to_string().replacen(':', "$", 1);
        for spelled in [
            format!("\\\\?\\GLOBALROOT\\??\\{letter}\\inner"),
            format!("\\\\?\\GLOBALROOT\\DosDevices\\{letter}\\inner"),
            format!("\\\\?\\UNC\\localhost\\{share}\\inner"),
        ] {
            let given = nerve_policy::paths::normal_folder(&spelled).unwrap();
            assert!(
                matches!(at(Path::new(&given)), Settled::Refused(_)),
                "{spelled} was followed"
            );
        }
    }

    #[test]
    fn code_pages_decode() {
        assert_eq!(
            crate::win::code_page_text(850, b"Gr\x81\xE1e").as_deref(),
            Some("Grüße")
        );
        assert_eq!(
            crate::win::code_page_text(1252, b"Gr\xFC\xDFe").as_deref(),
            Some("Grüße")
        );
        assert_ne!(crate::win::console_code_page(), 0);
    }

    /// What Windows PowerShell 5.1 prints, on stdout and stderr, comes back
    /// with its umlauts whatever the console code page is.
    #[tokio::test]
    async fn powershell_output_keeps_its_umlauts() {
        let d = tempfile::tempdir().unwrap();
        let c = call(
            "Write-Output 'Grüße'; [Console]::Error.WriteLine('Größe')",
            d.path(),
            Duration::from_secs(60),
        );
        let r = run(&c, &opts(), |_| {}).await.unwrap();
        assert_eq!(r["stdout"].as_str().unwrap().trim_end(), "Grüße", "{r}");
        assert_eq!(r["stderr"].as_str().unwrap().trim_end(), "Größe", "{r}");
    }

    /// The pid a process wrote to `file`, once it is there.
    async fn pid_in(file: &Path) -> u32 {
        for _ in 0..600 {
            if let Ok(t) = std::fs::read_to_string(file)
                && let Ok(pid) = t.trim().parse()
            {
                return pid;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("no pid in {}", file.display())
    }

    async fn gone(pid: u32) -> bool {
        for _ in 0..100 {
            if !crate::win::running(pid) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    /// A timeout ends a child of the shell and a grandchild whose parent
    /// exited long before (the parent lives 1.5 s, so the poll sees it).
    #[tokio::test]
    async fn a_timeout_ends_a_grandchild_whose_parent_exited() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(
            d.path().join("inner.ps1"),
            "$p = Start-Process ping -ArgumentList '-n','120','127.0.0.1' -WindowStyle Hidden -PassThru\r\n\
             Set-Content -Path grandchild.pid -Value $p.Id\r\n\
             Start-Sleep -Milliseconds 1500\r\n",
        )
        .unwrap();
        let command = "$c = Start-Process ping -ArgumentList '-n','120','127.0.0.1' -WindowStyle Hidden -PassThru; \
             Set-Content -Path child.pid -Value $c.Id; \
             Start-Process powershell -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','inner.ps1' -WindowStyle Hidden; \
             Start-Sleep 120";
        let c = call(command, d.path(), Duration::from_secs(15));
        let task = tokio::spawn(async move { run(&c, &opts(), |_| {}).await });
        let child = pid_in(&d.path().join("child.pid")).await;
        let grandchild = pid_in(&d.path().join("grandchild.pid")).await;
        let e = task.await.unwrap().unwrap_err();
        assert_eq!(e.kind(), ErrorCode::Timeout);
        assert!(gone(child).await, "the shell's child outlived the timeout");
        assert!(
            gone(grandchild).await,
            "the orphaned grandchild outlived the timeout"
        );
    }

    /// Ends `pid` when a failed test left it running.
    fn sweep(pid: u32) {
        if let Some(start) = crate::win::start_of(pid) {
            crate::win::terminate(pid, start);
        }
    }

    /// Runs `command` in `dir` until `pid_file` names a process, then
    /// cancels the call the way the link does (the task is aborted, so the
    /// run future is dropped); whether that process is gone afterwards.
    async fn ended_by_cancel(command: &str, dir: &Path, pid_file: &str) -> bool {
        let c = call(command, dir, Duration::from_secs(120));
        let task = tokio::spawn(async move { run(&c, &opts(), |_| {}).await });
        let pid = pid_in(&dir.join(pid_file)).await;
        // Long enough for every parent in between to have exited.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let ended = gone(pid).await;
        sweep(pid);
        ended
    }

    /// A cancel ends a grandchild whose parents exited at once: three cmd
    /// levels that each start the next and exit.
    #[tokio::test]
    async fn a_cancel_ends_a_grandchild_whose_parents_exited_at_once() {
        let d = tempfile::tempdir().unwrap();
        let w = |name: &str, text: &str| std::fs::write(d.path().join(name), text).unwrap();
        w("a.cmd", "@start \"\" /b cmd /c b.cmd\r\n");
        w("b.cmd", "@start \"\" /b cmd /c c.cmd\r\n");
        w(
            "c.cmd",
            "@start \"\" /b powershell -NoProfile -ExecutionPolicy Bypass -File gc.ps1\r\n",
        );
        w(
            "gc.ps1",
            "Set-Content -Path gc.pid -Value $PID\r\nStart-Sleep 120\r\n",
        );
        assert!(
            ended_by_cancel("cmd /c a.cmd; Start-Sleep 120", d.path(), "gc.pid").await,
            "the grandchild outlived the cancel"
        );
    }

    /// A process that keeps starting its successor and exiting, each one a
    /// grandchild whose parent is gone: a walk of the process table loses
    /// the chain when one hop lives shorter than a poll, the job holds every
    /// one. Each hop adds a line to `hops.txt`; after the cancel the file
    /// must stop growing.
    #[tokio::test]
    async fn a_cancel_ends_a_chain_of_processes_that_hand_over_and_exit() {
        let d = tempfile::tempdir().unwrap();
        // `stop` ends a chain a failed test left running.
        std::fs::write(
            d.path().join("hop.cmd"),
            "@if exist stop exit /b\r\n@echo x>>hops.txt\r\n@start \"\" /b cmd /c hop.cmd\r\n",
        )
        .unwrap();
        // Ten chains side by side, so the walk has a lot to keep up with.
        std::fs::write(
            d.path().join("go.cmd"),
            "@start \"\" /b cmd /c hop.cmd\r\n".repeat(10),
        )
        .unwrap();
        let c = call(
            "cmd /c go.cmd; Start-Sleep 120",
            d.path(),
            Duration::from_secs(120),
        );
        let task = tokio::spawn(async move { run(&c, &opts(), |_| {}).await });
        let hops = d.path().join("hops.txt");
        let count = || {
            std::fs::read_to_string(&hops)
                .map(|t| t.lines().count())
                .unwrap_or(0)
        };
        // Long enough for many hops.
        tokio::time::sleep(Duration::from_secs(4)).await;
        assert!(count() > 10, "the chain did not run: {} hops", count());
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::time::sleep(Duration::from_millis(500)).await;
        let after = count();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let later = count();
        std::fs::write(d.path().join("stop"), "").unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(after, later, "the chain went on after the cancel");
    }

    /// A process the command starts through WMI. Its parent is the WMI
    /// provider host (WmiPrvSE.exe), and a new process is born into its
    /// parent's job, so it is in the provider host's job, not the
    /// command's: no job object holds it, and neither does the walk. Kept
    /// as the open gap it is (run it with `--ignored`); closing it takes
    /// keeping the command from WMI, which a job cannot.
    #[tokio::test]
    #[ignore = "open gap: WMI starts the process outside the command's job"]
    async fn a_cancel_ends_a_process_started_through_wmi() {
        let d = tempfile::tempdir().unwrap();
        let command = "$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create \
             -Arguments @{CommandLine = 'powershell -NoProfile -Command Start-Sleep 120'}; \
             Set-Content -Path wmi.pid -Value $r.ProcessId; \
             Start-Sleep 120";
        assert!(
            ended_by_cancel(command, d.path(), "wmi.pid").await,
            "the process started through WMI outlived the cancel"
        );
    }

    /// The shell runs in a job of its own, nested in the job the test runs
    /// in when there is one (a CI runner, an SSH session).
    #[tokio::test]
    async fn the_shell_runs_in_a_job_of_its_own() {
        let d = tempfile::tempdir().unwrap();
        let c = call("exit 0", d.path(), Duration::from_secs(60));
        let mut held = false;
        let r = run(&c, &opts(), |e| held = e.has_job()).await.unwrap();
        assert_eq!(r["exit_code"], 0, "{r}");
        assert!(held, "the shell ran without a job");
    }

    /// Command A's shell exits at once while a ping it started in the
    /// background keeps A's output open; then commands B run one after
    /// another until a B shell gets A's old shell pid. Neither may end the
    /// other's processes: A's ping runs on, and every B exits with its own
    /// code. Windows takes minutes to give a pid out again, so run it with
    /// `--ignored`.
    #[tokio::test]
    #[ignore = "slow: waits until Windows gives a shell's pid to another shell"]
    async fn a_shell_pid_given_to_another_command_reaches_no_other_job() {
        let d = tempfile::tempdir().unwrap();
        let mut o = opts();
        o.shell = Some("cmd.exe".into());
        let a = call(
            "start /b ping -n 900 127.0.0.1",
            d.path(),
            Duration::from_secs(1200),
        );
        let (tx, rx) = tokio::sync::oneshot::channel();
        let oa = o.clone();
        let task = tokio::spawn(async move {
            run(&a, &oa, |e| {
                let _ = tx.send(e.pid());
            })
            .await
        });
        let a_pid = rx.await.unwrap();
        assert!(gone(a_pid).await, "A's shell did not exit");
        let mut reused = false;
        for _ in 0..20_000 {
            let mut b_pid = 0;
            let b = call("exit 0", d.path(), Duration::from_secs(60));
            let r = run(&b, &o, |e| b_pid = e.pid()).await.unwrap();
            assert_eq!(r["exit_code"], 0, "A's end ended a B: {r}");
            if b_pid == a_pid {
                reused = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        let a_runs = !task.is_finished();
        task.abort();
        assert!(reused, "no B shell got A's pid");
        assert!(a_runs, "A's command ended when a B shell got its pid");
    }

    /// Run by [`a_node_that_dies_leaves_no_command_running`] in a process
    /// of its own, which that test then kills: a command whose shell starts
    /// a ping and waits.
    #[tokio::test]
    #[ignore = "a helper of a_node_that_dies_leaves_no_command_running"]
    async fn helper_runs_a_command_until_killed() {
        let dir = PathBuf::from(std::env::var_os("NERVE_TEST_DIR").expect("set by the test"));
        let command = "Set-Content -Path shell.pid -Value $PID; \
             $p = Start-Process ping -ArgumentList '-n','120','127.0.0.1' -WindowStyle Hidden -PassThru; \
             Set-Content -Path ping.pid -Value $p.Id; \
             Start-Sleep 120";
        let _ = run(
            &call(command, &dir, Duration::from_secs(120)),
            &opts(),
            |_| {},
        )
        .await;
    }

    /// A node that dies without ending its commands (killed, crashed)
    /// leaves none running: its handle to the job closes with it, and the
    /// job's KILL_ON_JOB_CLOSE ends every process in it. The walk dies with
    /// the node and ends nothing.
    #[tokio::test]
    async fn a_node_that_dies_leaves_no_command_running() {
        let d = tempfile::tempdir().unwrap();
        let mut node = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "exec::windows_tests::helper_runs_a_command_until_killed",
            ])
            .env("NERVE_TEST_DIR", d.path())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let shell = pid_in(&d.path().join("shell.pid")).await;
        let ping = pid_in(&d.path().join("ping.pid")).await;
        // TerminateProcess: no destructor of the node runs, as in a crash.
        node.kill().unwrap();
        node.wait().unwrap();
        let shell_gone = gone(shell).await;
        let ping_gone = gone(ping).await;
        sweep(shell);
        sweep(ping);
        assert!(shell_gone, "the shell outlived the node");
        assert!(ping_gone, "the shell's child outlived the node");
    }
}
