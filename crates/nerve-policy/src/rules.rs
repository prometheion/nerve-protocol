//! Allow and deny rules (docs/dev/policy-engine.md, spec node-local §3).
//!
//! A rule is `<scope>` or `<scope>:<pattern>`. The scope is a capability or
//! `cap.action`, as in `caps`. The pattern is a glob over the call's target:
//! the whole command line for `exec.run`, the resolved path for every `fs`
//! action and for each path argument of any other action (one its schema
//! marks with `x-nerve-path`), and `<cap>.<action>` for an action that names
//! no path. A path is in the center's form (`/c/Users/x` on Windows, where a
//! path pattern ignores case as NTFS does), and `~/` in a pattern is the
//! owner's home. `*` matches across `/` and spaces. A rule without a pattern
//! covers every target of its scope.
//!
//! A pattern ending in ` *` also covers the bare program (`git *` covers
//! `git`), and one ending in `/*` the folder itself, so the wildcard the
//! buttons write covers what the owner clicked on. The audit buttons write
//! rules with [`rule_for`], the CLI with the same function.
//!
//! A rule `guard:<name>` is one of the guard's ([`crate::guard`]): it looks
//! at the commands of an `exec.run` line, not at its text.

use std::path::Path;
use std::sync::OnceLock;

use globset::{GlobBuilder, GlobMatcher};

use crate::command::{Shell, parse};
use crate::decide::sudo_command;
use crate::guard::Guard;
use crate::paths::to_wire;

/// The capability whose targets are all paths.
pub(crate) const FS: &str = "fs";

/// Whether `s` is `cap` or `cap.action`: the shape of a `caps` key.
pub fn valid_scope(s: &str) -> bool {
    !s.is_empty()
        && s.split('.').count() <= 2
        && s.split('.').all(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
}

fn split(rule: &str) -> Result<(&str, Option<&str>), String> {
    let (scope, pattern) = match rule.split_once(':') {
        Some((s, p)) => (s, Some(p)),
        None => (rule, None),
    };
    if !valid_scope(scope) {
        return Err(format!(
            "rule {rule:?}: it starts with `cap` or `cap.action`, then `:` and a pattern"
        ));
    }
    if pattern == Some("") {
        return Err(format!("rule {rule:?}: the pattern after `:` is empty"));
    }
    Ok((scope, pattern))
}

/// Whether every target of `scope` is a path (`fs`). Any other scope's
/// target is a path where its call names one ([`RuleSet::find_path`]).
fn always_paths(scope: &str) -> bool {
    scope.split('.').next() == Some(FS)
}

fn build(pattern: &str, path: bool) -> Result<GlobMatcher, globset::Error> {
    // globset matches every target as a path and on Windows turns its `\`
    // into `/` first, so the pattern must too: else a rule with a `\` (most
    // Windows command lines have one) never matches, and a deny rule denies
    // nothing.
    let pattern = if cfg!(windows) {
        pattern.replace('\\', "/")
    } else {
        pattern.to_string()
    };
    GlobBuilder::new(&pattern)
        // NTFS ignores case; a Windows path rule must too.
        .case_insensitive(path && cfg!(windows))
        // `{,.exe}` is "nothing or `.exe`", as a reader takes it; globset
        // would drop the empty choice otherwise.
        .empty_alternates(true)
        .build()
        .map(|g| g.compile_matcher())
}

/// The scope a rule covers: `cap` or `cap.action`, and `exec.run` for a rule
/// of the guard.
pub fn scope_of(rule: &str) -> &str {
    if Guard::of_rule(rule).is_some() {
        return "exec.run";
    }
    rule.split(':').next().unwrap_or(rule)
}

/// Checks a rule of the allow or deny list.
pub fn validate(rule: &str) -> Result<(), String> {
    if rule.split(':').next() == Some(GUARD_SCOPE) {
        return match Guard::of_rule(rule) {
            Some(_) => Ok(()),
            None => Err(format!(
                "rule {rule:?}: the guard's rules are {}",
                Guard::ALL.map(Guard::rule).join(", ")
            )),
        };
    }
    let (scope, pattern) = split(rule)?;
    if let Some(p) = pattern {
        // Any scope's pattern may meet a path.
        for path in [always_paths(scope), true] {
            build(p, path).map_err(|e| format!("rule {rule:?}: {e}"))?;
        }
    }
    Ok(())
}

/// Checks an entry of the sudo allow list: a glob over the command line.
pub fn validate_command_glob(glob: &str) -> Result<(), String> {
    build(glob, false)
        .map(|_| ())
        .map_err(|e| format!("sudo rule {glob:?}: {e}"))
}

/// The pattern without the tail that stands for "and anything after":
/// ` *` after a program, `/*` or `/**` after a folder.
fn bare(pattern: &str, path: bool) -> Option<String> {
    if path {
        let rest = pattern
            .strip_suffix("/**")
            .or_else(|| pattern.strip_suffix("/*"))?;
        Some(if rest.is_empty() { "/" } else { rest }.to_string())
    } else {
        pattern
            .strip_suffix(" *")
            .filter(|r| !r.is_empty())
            .map(str::to_string)
    }
}

/// The matchers of one pattern: itself and its bare form.
fn matchers(pattern: &str, path: bool) -> Vec<GlobMatcher> {
    let mut out = Vec::new();
    out.extend(build(pattern, path).ok());
    if let Some(b) = bare(pattern, path) {
        out.extend(build(&b, path).ok());
    }
    out
}

/// Whether `command` matches one of the globs `patterns` (the sudo allow
/// list).
pub fn command_matches(patterns: &[String], command: &str) -> bool {
    let command = command.trim();
    patterns
        .iter()
        .any(|p| matchers(p, false).iter().any(|m| m.is_match(command)))
}

/// Whether an allow rule of `rules` covers `cap.action` for some target: the
/// scope decides, the pattern does not. The rule may allow only some paths or
/// commands, so an action it covers is offered and each call is still checked.
/// A rule that does not parse covers nothing, as in [`RuleSet::new`].
pub fn offers(rules: &[String], cap: &str, action: &str) -> bool {
    rules.iter().any(|text| {
        validate(text).is_ok()
            && split(text).is_ok_and(|(scope, _)| match scope.split_once('.') {
                Some((c, a)) => c == cap && a == action,
                None => scope == cap,
            })
    })
}

/// The scope word of the guard's rules (`guard:node-programs`).
const GUARD_SCOPE: &str = "guard";

struct Compiled {
    text: String,
    cap: String,
    action: Option<String>,
    /// The pattern with `~/` resolved; [`RuleSet::find_exact`] compares it.
    pattern: Option<String>,
    globs: Vec<GlobMatcher>,
    /// The globs a path target is matched with: `~/` resolved and, on
    /// Windows, without case, whatever the scope.
    path_globs: Vec<GlobMatcher>,
    /// The pattern as a path target reads it (`~/` resolved), which
    /// [`RuleSet::find_below`] looks at.
    path_pattern: Option<String>,
    /// A rule of the guard: it matches parsed commands, not the text.
    guard: Option<Guard>,
}

/// An allow or deny list, compiled.
pub struct RuleSet {
    rules: Vec<Compiled>,
    /// The shell that runs the commands, by whose rules the guard reads them.
    shell: Shell,
}

impl RuleSet {
    /// Compiles `rules`; one that does not parse is left out (the config
    /// check refuses them before they get here). `~/` in an `fs` pattern is
    /// `home`. The guard reads a command line as the node's default shell
    /// does; [`RuleSet::with_shell`] names another.
    pub fn new(rules: &[String], home: &Path) -> RuleSet {
        let home = to_wire(home);
        let rules = rules
            .iter()
            .filter_map(|text| {
                if let Some(guard) = Guard::of_rule(text) {
                    return Some(Compiled {
                        text: text.clone(),
                        cap: "exec".into(),
                        action: Some("run".into()),
                        pattern: None,
                        globs: Vec::new(),
                        path_globs: Vec::new(),
                        path_pattern: None,
                        guard: Some(guard),
                    });
                }
                let (scope, pattern) = split(text).ok()?;
                if scope == GUARD_SCOPE {
                    return None;
                }
                let (cap, action) = match scope.split_once('.') {
                    Some((c, a)) => (c, Some(a)),
                    None => (scope, None),
                };
                let path = always_paths(scope);
                let globs_of = |path: bool| match pattern {
                    Some(p) => {
                        let g = matchers(&expand_home(p, &home, path), path);
                        (!g.is_empty()).then_some(g)
                    }
                    None => Some(Vec::new()),
                };
                let globs = globs_of(path)?;
                let path_globs = globs_of(true)?;
                Some(Compiled {
                    text: text.clone(),
                    cap: cap.into(),
                    action: action.map(Into::into),
                    pattern: pattern.map(|p| expand_home(p, &home, path)),
                    globs,
                    path_globs,
                    path_pattern: pattern.map(|p| expand_home(p, &home, true)),
                    guard: None,
                })
            })
            .collect();
        RuleSet {
            rules,
            shell: Shell::native(),
        }
    }

    /// The list with its command lines read as `shell` reads them.
    pub fn with_shell(mut self, shell: Shell) -> RuleSet {
        self.shell = shell;
        self
    }

    /// The first rule that covers `target` of `cap.action`. A rule of the
    /// guard parses the line once (for all of them); a line that does not
    /// parse is checked with the guard's text patterns.
    pub fn find(&self, cap: &str, action: &str, target: &str) -> Option<&str> {
        let mut parsed = None;
        self.rules
            .iter()
            .filter(|r| r.covers(cap, action))
            .find(|r| match r.guard {
                Some(g) => match parsed.get_or_insert_with(|| parse(target, self.shell)) {
                    Ok(script) => g.refuses(script),
                    // What was read before the line gave out is checked as
                    // a line is, and the text patterns look at all of it.
                    Err(e) => g.refuses(&e.read) || fallback(g).iter().any(|m| m.is_match(target)),
                },
                None => r.globs.is_empty() || r.globs.iter().any(|g| g.is_match(target)),
            })
            .map(|r| r.text.as_str())
    }

    /// The first rule that covers the path `target` of `cap.action`: a path
    /// argument of any action, matched as `fs` paths are (`~/` is the
    /// owner's home, Windows ignores case). The guard's rules look at
    /// command lines only.
    pub fn find_path(&self, cap: &str, action: &str, target: &str) -> Option<&str> {
        self.rules
            .iter()
            .filter(|r| r.guard.is_none() && r.covers(cap, action))
            .find(|r| r.path_globs.is_empty() || r.path_globs.iter().any(|g| g.is_match(target)))
            .map(|r| r.text.as_str())
    }

    /// The first rule that may cover a path strictly below the folder `dir`
    /// of `cap.action`, a path argument as [`RuleSet::find_path`] reads one:
    /// a program handed `dir` works below it. A rule may cover such a path
    /// where the text its pattern starts with, up to its first wildcard,
    /// lies below `dir`, or `dir` below that text when a wildcard follows. That is wider than the pattern, which is the
    /// side to err on: the rule is the owner's "no".
    pub fn find_below(&self, cap: &str, action: &str, dir: &str) -> Option<&str> {
        let fold = |s: &str| {
            if cfg!(windows) {
                s.replace('\\', "/").to_lowercase()
            } else {
                s.to_string()
            }
        };
        let dir = fold(dir);
        let below = if dir.ends_with('/') {
            dir
        } else {
            format!("{dir}/")
        };
        self.rules
            .iter()
            .filter(|r| r.guard.is_none() && r.covers(cap, action))
            .find(|r| {
                let Some(pattern) = &r.path_pattern else {
                    // A rule without a pattern covers every path.
                    return true;
                };
                let pattern = fold(pattern);
                let wild = pattern.find(['*', '?', '[', '{']);
                let fixed = &pattern[..wild.unwrap_or(pattern.len())];
                // A pattern with no wildcard names one path; after its
                // first wildcard it may go on with anything below.
                fixed.starts_with(&below) || wild.is_some() && below.starts_with(fixed)
            })
            .map(|r| r.text.as_str())
    }

    /// The first rule of this scope that names `target` and nothing else: one
    /// the "Allow" button writes, not a wildcard.
    pub fn find_exact(&self, cap: &str, action: &str, target: &str) -> Option<&str> {
        let want = escape(target);
        self.rules
            .iter()
            .filter(|r| r.covers(cap, action))
            .find(|r| r.pattern.as_deref() == Some(want.as_str()))
            .map(|r| r.text.as_str())
    }
}

impl Compiled {
    fn covers(&self, cap: &str, action: &str) -> bool {
        self.cap == cap && self.action.as_deref().is_none_or(|a| a == action)
    }
}

fn expand_home(pattern: &str, home: &str, path: bool) -> String {
    if !path {
        return pattern.to_string();
    }
    if pattern == "~" {
        escape(home)
    } else if let Some(rest) = pattern.strip_prefix("~/") {
        format!("{}/{rest}", escape(home.trim_end_matches('/')))
    } else {
        pattern.to_string()
    }
}

/// `s` as a glob that matches exactly `s`: every character a glob reads is
/// put in a class of its own.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '{' | '}' | '\\') {
            out.push('[');
            out.push(c);
            out.push(']');
        } else {
            out.push(c);
        }
    }
    out
}

/// The rule an audit button writes for the entry `cap.action` with `target`
/// (the entry's `target` field): `wildcard` widens it to the program and
/// anything after it (`exec.run`), the folder and anything below it (`fs`),
/// or the whole capability (any other action).
pub fn rule_for(cap: &str, action: &str, target: &str, wildcard: bool) -> Result<String, String> {
    let scope = format!("{cap}.{action}");
    if !valid_scope(&scope) {
        return Err(format!("{scope:?} is not a capability and action"));
    }
    let target = target.trim();
    match (cap, action) {
        ("exec", "run") => {
            if target.is_empty() {
                return Err("no command".into());
            }
            let pattern = if wildcard {
                let program = target.split_whitespace().next().unwrap_or(target);
                format!("{} *", escape(program))
            } else {
                escape(target)
            };
            Ok(format!("{scope}:{pattern}"))
        }
        (FS, _) => {
            if !target.starts_with('/') {
                return Err(format!("{target:?} is not an absolute path"));
            }
            let pattern = if wildcard {
                let target = target.trim_end_matches('/');
                let folder = target.rfind('/').map_or("", |i| &target[..i]);
                format!("{}/*", escape(folder))
            } else {
                escape(target)
            };
            Ok(format!("{scope}:{pattern}"))
        }
        // No pattern: the rule is the action, or with a wildcard its capability.
        _ => Ok(if wildcard { cap.to_string() } else { scope }),
    }
}

/// A letter as a class of both cases, for the Windows commands: PowerShell
/// and cmd ignore case, and a rule's glob does not. Each macro is one word.
macro_rules! sc {
    () => {
        "[Ss][Cc]"
    };
}
macro_rules! net {
    () => {
        "[Nn][Ee][Tt]"
    };
}
macro_rules! exe {
    () => {
        "[Ee][Xx][Ee]"
    };
}
macro_rules! stop {
    () => {
        "[Ss][Tt][Oo][Pp]"
    };
}
macro_rules! config {
    () => {
        "[Cc][Oo][Nn][Ff][Ii][Gg]"
    };
}
macro_rules! delete {
    () => {
        "[Dd][Ee][Ll][Ee][Tt][Ee]"
    };
}
macro_rules! restart {
    () => {
        "[Rr][Ee][Ss][Tt][Aa][Rr][Tt]"
    };
}
macro_rules! set {
    () => {
        "[Ss][Ee][Tt]"
    };
}
macro_rules! remove {
    () => {
        "[Rr][Ee][Mm][Oo][Vv][Ee]"
    };
}
macro_rules! service {
    () => {
        "[Ss][Ee][Rr][Vv][Ii][Cc][Ee]"
    };
}
macro_rules! process {
    () => {
        "[Pp][Rr][Oo][Cc][Ee][Ss][Ss]"
    };
}
macro_rules! taskkill {
    () => {
        "[Tt][Aa][Ss][Kk][Kk][Ii][Ll][Ll]"
    };
}
macro_rules! desktop {
    () => {
        "[Dd][Ee][Ss][Kk][Tt][Oo][Pp]"
    };
}
macro_rules! node {
    () => {
        "[Nn][Ee][Rr][Vv][Ee]-[Nn][Oo][Dd][Ee]"
    };
}

/// Up to sixteen spaces, tabs or line breaks: the indent of a line in a
/// script, four levels of four.
macro_rules! ws {
    () => {
        concat!(ws8!(), ws8!())
    };
}

macro_rules! ws8 {
    () => {
        concat!(
            "{,[ \t\r\n]}{,[ \t\r\n]}{,[ \t\r\n]}{,[ \t\r\n]}",
            "{,[ \t\r\n]}{,[ \t\r\n]}{,[ \t\r\n]}{,[ \t\r\n]}"
        )
    };
}

/// The scope and where a command starts: the line's start or after `;`,
/// `&`, `|`, `(`, `{` or a line break, then a shell keyword (`then`, `do`,
/// `else`, `!`, `time`, `nohup`) or a brace.
macro_rules! begin {
    () => {
        concat!(
            "exec.run:{,*[;&|({\r\n]}",
            ws!(),
            "{,then ,do ,else ,[{] ,! ,time ,nohup }"
        )
    };
}

/// [`begin!`], then `sudo` and its flags if the command begins with it. `sudo`
/// counts only at a command's start, so a quoted mention on one line (`git
/// commit -m "run sudo systemctl stop nerve-node"`) runs.
macro_rules! command {
    () => {
        concat!(begin!(), "{,sudo ,sudo * }")
    };
}

/// What ends a name: the line's end, or a space, tab, line break, quote, `)`
/// or a character that chains the next command.
macro_rules! end {
    () => {
        "{,[ \t\r\n\"');&|}]*}"
    };
}

/// [`end!`], and a comma, which ends a name in a PowerShell list.
macro_rules! end_ps {
    () => {
        "{,[ \t\r\n\"');,&|}]*}"
    };
}

/// The deny rules every new pairing gets, the guard against an agent that
/// changes the node it runs on (owner's decisions of 2026-10-20 and
/// 2026-10-22): a command that runs the node's programs, one that names its
/// socket, pipes or config and state folders, and one that stops, restarts,
/// disables or kills its service or process ([`Guard`], on the parsed
/// commands of the line), and a write into those folders. Only running or
/// stopping the node counts, not its name anywhere: `cargo build -p
/// nerve-node`, `journalctl -u nerve-node`, `systemctl status nerve-node`
/// and a commit message that names them stay allowed. They are on top of the
/// node's own folders, which nothing releases (crate::protected). They catch
/// a confused agent, not one that builds the name at run time: the real
/// protection is that commands run as an account of their own. The owner may
/// remove any of them.
pub const GUARD: &[&str] = &[
    "guard:node-programs",
    "guard:node-paths",
    "guard:node-service",
    "fs.write:~/.config/nerve/*",
    "fs.write:~/.local/state/nerve/*",
    "fs.write:/etc/nerve/*",
    "fs.write:/var/lib/nerve/*",
    "fs.write:/?/ProgramData/Nerve/*",
];

/// The guard's text patterns from before it read commands (0.0.6), as globs
/// over the whole line: a command that runs the node's programs (`..2`),
/// names its paths (`2..9`) or stops its service (`9..`), where a command
/// starts. They miss what a pattern cannot see (`env X=1 sudo …`) and refuse
/// some mentions; the guard still checks a line it cannot parse with them,
/// so such a line is refused wherever they refused it.
const TEXTS: [&str; 18] = [
    // By name where a command starts: the line's start, after `;`, `&`,
    // `|`, `(`, `{` or a line break (with its indent), a shell keyword, and
    // `sudo`; then the line's end, a space, a tab, a line break or a quote.
    // The program follows `sudo` or one of its common flags directly, so
    // `sudo cargo build -p nerve-node` runs.
    concat!(
        begin!(),
        "{,sudo ,sudo -? ,sudo -- ,sudo -u root ,sudo -n -u root }",
        "nerve-node{,-desktop}{,.exe}{,[ \t\r\n\"']*}"
    ),
    "exec.run:*[/\\]nerve-node{,-desktop}{,.exe}{,[ \t\r\n\"']*}",
    "exec.run:*/run/nerve-node{,/*,[ \t\r\n\"']*}",
    "exec.run:*[/\\][/\\].[/\\]pipe[/\\]nerve-node*",
    "exec.run:*/etc/nerve{,/*,[ \t\r\n\"']*}",
    "exec.run:*/var/lib/nerve{,/*,[ \t\r\n\"']*}",
    "exec.run:*.config/nerve{,/*,[ \t\r\n\"']*}",
    "exec.run:*.local/state/nerve{,/*,[ \t\r\n\"']*}",
    // `C:\ProgramData\Nerve`, `%ProgramData%\Nerve`, `$env:ProgramData\Nerve`:
    // the line's `\` is matched as `/` on Windows.
    "exec.run:*[Pp]rogram[Dd]ata*/[Nn]erve{,/*,[ \t\r\n\"']*}",
    // Stopping, restarting, disabling or killing the node's service or
    // process, by its name, with the same line starts (and the program's path).
    // Reading it stays allowed: `systemctl status`, `sc query`, `Get-Service`.
    concat!(
        command!(),
        "{,*[/\\]}systemctl{, *} {stop,restart,try-restart,reload-or-restart,disable,kill,mask} {,*[ \"']}nerve-node{,.service}",
        end!()
    ),
    concat!(
        command!(),
        "{,*[/\\]}",
        sc!(),
        "{,.",
        exe!(),
        "} {,*[ ]}{",
        stop!(),
        ",",
        config!(),
        ",",
        delete!(),
        "} {,*[ \"']}",
        node!(),
        end!()
    ),
    concat!(
        command!(),
        "{,*[/\\]}",
        net!(),
        "{,.",
        exe!(),
        "} ",
        stop!(),
        " {,*[ \"']}",
        node!(),
        end!()
    ),
    concat!(
        command!(),
        "{",
        stop!(),
        ",",
        restart!(),
        ",",
        set!(),
        ",",
        remove!(),
        "}-",
        service!(),
        "{, *}[ \"':=,]",
        node!(),
        end_ps!()
    ),
    concat!(
        command!(),
        "{,*[/\\]}",
        taskkill!(),
        "{,.",
        exe!(),
        "} *[ \"':=]",
        node!(),
        "{,-",
        desktop!(),
        "}{,.",
        exe!(),
        "}",
        end!()
    ),
    concat!(
        command!(),
        stop!(),
        "-",
        process!(),
        "{, *}[ \"':=,]",
        node!(),
        "{,-",
        desktop!(),
        "}{,.",
        exe!(),
        "}",
        end_ps!()
    ),
    // The same through a pipe: `Get-Service nerve-node | Stop-Service`.
    concat!(
        "exec.run:*[ \"'(,:=]",
        node!(),
        "{,-",
        desktop!(),
        "}{,.",
        exe!(),
        "}*|",
        ws!(),
        "{",
        stop!(),
        ",",
        restart!(),
        ",",
        set!(),
        ",",
        remove!(),
        "}-{",
        service!(),
        ",",
        process!(),
        "}",
        end_ps!()
    ),
    // The SysV wrapper, `service nerve-node stop` (it calls systemctl).
    concat!(
        command!(),
        "{,*[/\\]}service {,*[ \"']}nerve-node{,.service}{,[\"']} {stop,restart,try-restart,force-reload,condrestart}",
        end!()
    ),
    // By the process's name: `pkill nerve-node`, `killall -9 nerve-node`,
    // `pkill -f '^/usr/bin/nerve-node'`. `pgrep` and `ps` stay allowed.
    concat!(
        command!(),
        "{,*[/\\]}{pkill,killall} {,-* }{,[\"']}{,^}{,*/}nerve-node{,-desktop}{,[$\"']}",
        end!()
    ),
];

/// The [`TEXTS`] that stand in for `guard` on a line that does not parse.
fn fallback(guard: Guard) -> &'static [GlobMatcher] {
    static COMPILED: OnceLock<[Vec<GlobMatcher>; 3]> = OnceLock::new();
    let all = COMPILED.get_or_init(|| {
        let globs = |texts: &[&str]| {
            texts
                .iter()
                .filter_map(|t| t.strip_prefix("exec.run:"))
                .flat_map(|p| matchers(p, false))
                .collect::<Vec<_>>()
        };
        [globs(&TEXTS[..2]), globs(&TEXTS[2..9]), globs(&TEXTS[9..])]
    });
    match guard {
        Guard::Programs => &all[0],
        Guard::Paths => &all[1],
        Guard::Service => &all[2],
    }
}

/// The guard's older texts, which `rule guard` takes off a deny list when it
/// puts the current ones on: the text patterns of 0.0.6 ([`TEXTS`]) and
/// those from before a line break ended a command. A pairing that still has
/// them keeps them as plain deny rules until then.
pub const GUARD_OLD: &[&str] = &[
    TEXTS[0],
    TEXTS[1],
    TEXTS[2],
    TEXTS[3],
    TEXTS[4],
    TEXTS[5],
    TEXTS[6],
    TEXTS[7],
    TEXTS[8],
    TEXTS[9],
    TEXTS[10],
    TEXTS[11],
    TEXTS[12],
    TEXTS[13],
    TEXTS[14],
    TEXTS[15],
    TEXTS[16],
    TEXTS[17],
    "exec.run:{,*[;&|(] ,*[;&|(],*sudo }nerve-node{,-desktop}{,.exe}{,[ \"']*}",
    "exec.run:*[/\\]nerve-node{,-desktop}{,.exe}{,[ \"']*}",
    "exec.run:*/run/nerve-node{,/*,[ \"']*}",
    "exec.run:*/etc/nerve{,/*,[ \"']*}",
    "exec.run:*/var/lib/nerve{,/*,[ \"']*}",
    "exec.run:*.config/nerve{,/*,[ \"']*}",
    "exec.run:*.local/state/nerve{,/*,[ \"']*}",
    "exec.run:*[Pp]rogram[Dd]ata*/[Nn]erve{,/*,[ \"']*}",
];

/// `rule` with its tab, carriage return and line feed written `\t`, `\r` and
/// `\n`, as `rule ls` and the app show it: an older text of the guard holds
/// them (they end a command in a script), and a listing keeps one line a rule.
pub fn escape_controls(rule: &str) -> String {
    let mut out = String::with_capacity(rule.len());
    for c in rule.chars() {
        match c {
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

/// Refuses `rule` if it is the listed form ([`escape_controls`]) of a rule
/// with a tab or line break: of one of the guard's (also an older text) or of
/// an entry of `listed`, the list it goes on. A rule pasted from `rule ls` so
/// would look like that rule and be another: there `\n` is the letter `n`
/// (and on Windows `\` a separator). Any other text is taken as it is, so a
/// path like `C:\tools\x.exe` is a rule on every OS.
pub fn check_not_a_listed_form(rule: &str, listed: &[String]) -> Result<(), String> {
    let raw = unescape_controls(rule);
    if raw == rule
        || !(GUARD.contains(&raw.as_str())
            || GUARD_OLD.contains(&raw.as_str())
            || listed.contains(&raw))
    {
        return Ok(());
    }
    Err(format!(
        "rule {rule:?} is how `rule ls` writes a rule with a tab or line break, not the rule: pasted so, a `\\n` is the letter n. Add the rule itself (`nerve-node rule guard` puts the guard's rules on), or give `rule rm` and `rule edit` the listed text"
    ))
}

/// The reverse of [`escape_controls`]: `\t`, `\r` and `\n` become the
/// character. A `\\` pair is kept as it is, so `[/\\]n` stays. A rule that
/// has a `\n` of its own (a path `C:\new`) is not for this: the callers use
/// it only on an entry that is not on the list as it stands.
pub fn unescape_controls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('n') => out.push('\n'),
            Some(o) => {
                out.push('\\');
                out.push(o);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// The rules of [`GUARD`] that `deny` lacks.
pub fn guard_missing(deny: &[String]) -> Vec<&'static str> {
    GUARD
        .iter()
        .copied()
        .filter(|g| !deny.iter().any(|d| d == g))
        .collect()
}

/// Whether `deny` still holds a text of the guard from before it read
/// commands ([`GUARD_OLD`]): it works, but as text patterns.
pub fn guard_older(deny: &[String]) -> bool {
    deny.iter().any(|d| GUARD_OLD.contains(&d.as_str()))
}

/// The sudo allow list entry for `command`: the command itself, or with
/// `wildcard` its leading words up to the program that follows `sudo` and
/// its flags, then anything after (`sudo apt *`). A bare `sudo *` would let
/// a click allow everything, so the wildcard keeps the program.
pub fn sudo_rule_for(command: &str, wildcard: bool) -> Result<String, String> {
    let command = command.trim();
    if sudo_command(command).is_none() {
        return Err(format!("{command:?} is not a sudo command"));
    }
    if !wildcard {
        return Ok(escape(command));
    }
    let mut words = Vec::new();
    for (i, w) in command.split_whitespace().enumerate() {
        words.push(w);
        if i > 0 && !w.starts_with('-') {
            break;
        }
    }
    Ok(format!("{} *", escape(&words.join(" "))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(rules: &[&str]) -> RuleSet {
        let rules: Vec<String> = rules.iter().map(|s| s.to_string()).collect();
        RuleSet::new(&rules, Path::new("/h"))
    }

    #[test]
    fn scope_and_pattern() {
        let s = set(&[
            "exec.run:git *",
            "fs:/w/*",
            "fs.write:/x/*",
            "camera.snap",
            "mic",
        ]);
        assert!(s.find("exec", "run", "git status").is_some());
        assert!(s.find("exec", "run", "git").is_some(), "the bare program");
        assert!(s.find("exec", "run", "gitk").is_none());
        assert!(s.find("exec", "run", "ls").is_none());
        // A path pattern never matches a command and the other way round.
        assert!(s.find("exec", "run", "/w/evil").is_none());
        assert!(s.find("fs", "read", "git status").is_none());
        assert!(s.find("fs", "read", "/w/a/b").is_some());
        assert!(s.find("fs", "list", "/w").is_some(), "the folder itself");
        assert!(s.find("fs", "read", "/x/a").is_none());
        assert!(s.find("fs", "write", "/x/a").is_some());
        assert!(s.find("camera", "snap", "camera.snap").is_some());
        assert!(s.find("camera", "record", "camera.record").is_none());
        assert!(s.find("mic", "listen", "mic.listen").is_some());
    }

    #[test]
    fn home_is_the_owners() {
        let s = set(&["fs:~/notes/*"]);
        assert!(s.find("fs", "read", "/h/notes/a").is_some());
        assert!(s.find("fs", "read", "/h/other").is_none());
        // `~` means nothing in a command.
        let s = set(&["exec.run:~/bin/*"]);
        assert!(s.find("exec", "run", "/h/bin/x").is_none());
    }

    /// A path target of any scope is matched as an `fs` path: `~/` is the
    /// owner's home and a Windows path rule ignores case. The same rule
    /// still reads its pattern as text where the target is no path, and the
    /// guard's rules never cover a path.
    #[test]
    fn a_path_target_of_any_scope_is_matched_as_a_path() {
        let s = set(&["notes:~/secret/*", "lamp.set", "guard:node-paths"]);
        assert!(s.find_path("notes", "open", "/h/secret/a").is_some());
        assert!(s.find_path("notes", "open", "/h/secret").is_some());
        assert!(s.find_path("notes", "open", "/h/other").is_none());
        assert!(s.find("notes", "open", "/h/secret/a").is_none());
        assert!(s.find_path("lamp", "set", "/anywhere").is_some());
        assert!(s.find_path("exec", "run", "/h/.config/nerve").is_none());
        let s = set(&["notes:/W/Secret/*"]);
        assert_eq!(
            s.find_path("notes", "open", "/w/secret/a").is_some(),
            cfg!(windows)
        );
        assert!(s.find("notes", "open", "/w/secret/a").is_none());
    }

    /// A rule covers what lies below a folder where its pattern may go on
    /// below it: its fixed start lies there, or the folder lies below that
    /// start and a wildcard follows.
    #[test]
    fn a_rule_may_cover_a_place_below_a_folder() {
        let s = set(&["notes:~/work/clients/*", "notes:/h/data/key.pem"]);
        for dir in ["/h", "/h/work", "/h/work/", "/h/work/clients", "/h/data"] {
            assert!(s.find_below("notes", "search", dir).is_some(), "{dir}");
        }
        for dir in [
            "/h/workshop",
            "/h/other",
            "/h/data/key.pem",
            "/h/work/clientele",
        ] {
            assert!(s.find_below("notes", "search", dir).is_none(), "{dir}");
        }
        assert!(s.find_below("files", "search", "/h").is_none());
        // A wildcard may go on with anything: one in the middle of a name,
        // or one before any folder.
        let s = set(&["notes:/h/wo*", "sync:**/.env"]);
        assert!(s.find_below("notes", "search", "/h/work/a").is_some());
        assert!(s.find_below("notes", "search", "/h/other").is_none());
        assert!(s.find_below("sync", "pull", "/srv/proj").is_some());
        // A rule of the whole scope covers every path.
        assert!(set(&["notes"]).find_below("notes", "x", "/").is_some());
        // The guard's rules never cover a path.
        assert!(
            set(&["guard:node-paths"])
                .find_below("exec", "run", "/")
                .is_none()
        );
        let s = set(&["notes:/W/Secret/*"]);
        assert_eq!(
            s.find_below("notes", "search", "/w").is_some(),
            cfg!(windows)
        );
    }

    #[test]
    fn bad_rules_are_refused() {
        for ok in ["fs:/a/*", "exec.run:git status", "camera.snap", "fs"] {
            validate(ok).unwrap();
        }
        for bad in [
            "",
            "~/private",
            "/home/u/x",
            "git status",
            "fs:",
            "fs.read.x:/a",
            "fs:/a/[",
            "exec.run:{a",
        ] {
            assert!(validate(bad).is_err(), "{bad}");
        }
        assert!(validate_command_glob("sudo apt *").is_ok());
        assert!(validate_command_glob("sudo [").is_err());
    }

    #[test]
    fn escaping_matches_the_text_and_nothing_else() {
        for s in [
            "rm *",
            "ls [a-z]?",
            "echo {a,b}",
            "grep \\d x",
            "a]b}",
            "plain",
        ] {
            let g = build(&escape(s), false).unwrap();
            assert!(g.is_match(s), "{s}");
            assert!(!g.is_match(format!("{s}x")), "{s}");
        }
        assert!(!build(&escape("rm *"), false).unwrap().is_match("rm -rf /"));
        // A button's exact rule names that command only.
        let rule = rule_for("exec", "run", "rm *", false).unwrap();
        let s = set(&[&rule]);
        assert!(s.find("exec", "run", "rm *").is_some());
        assert!(s.find("exec", "run", "rm -rf /").is_none());
    }

    /// Windows command lines name paths with `\`; a rule for them matches
    /// (a `\` is an escape in a Unix glob, so this is Windows only).
    #[cfg(windows)]
    #[test]
    fn a_command_rule_with_backslashes_matches_on_windows() {
        let s = set(&["exec.run:Remove-Item C:\\data\\*"]);
        assert!(s.find("exec", "run", "Remove-Item C:\\data\\x").is_some());
        assert!(s.find("exec", "run", "Remove-Item C:\\other\\x").is_none());
        let exact = rule_for("exec", "run", "type C:\\x\\a.txt", false).unwrap();
        assert!(
            set(&[&exact])
                .find("exec", "run", "type C:\\x\\a.txt")
                .is_some()
        );
    }

    /// Only the listed form of a rule with a tab or line break is refused as
    /// a new rule; the rest is taken as it is, a Windows path too (there `\`
    /// is a separator, and `C:\tools` has a `\t`).
    #[test]
    fn only_the_listed_form_of_a_rule_with_controls_is_refused() {
        let listed = vec!["exec.run:a\nb*".to_string()];
        for rule in GUARD.iter().chain(GUARD_OLD) {
            let shown = escape_controls(rule);
            let r = check_not_a_listed_form(&shown, &[]);
            assert_eq!(r.is_err(), shown != *rule, "{shown}");
            assert!(check_not_a_listed_form(rule, &[]).is_ok());
        }
        assert!(check_not_a_listed_form("exec.run:a\\nb*", &listed).is_err());
        assert!(check_not_a_listed_form("exec.run:a\\nb*", &[]).is_ok());
        for rule in [
            "exec.run:type C:\\tools\\x.exe",
            "exec.run:*C:\\Users\\nina\\repos\\*",
            "exec.run:\"C:\\Program Files\\nodejs\\node.exe\" --version",
            "exec.run:type C:\\\\new",
            "fs.read:C:\\temp\\*",
        ] {
            validate(rule).unwrap();
            assert!(
                check_not_a_listed_form(rule, &[rule.to_string()]).is_ok(),
                "{rule}"
            );
            assert!(check_not_a_listed_form(rule, &listed).is_ok(), "{rule}");
        }
    }

    #[test]
    fn controls_are_written_out_and_read_back() {
        for rule in GUARD.iter().chain(GUARD_OLD) {
            let shown = escape_controls(rule);
            assert!(!shown.contains(['\t', '\r', '\n']), "{shown}");
            assert_eq!(unescape_controls(&shown), *rule);
        }
        assert_eq!(escape_controls("a\tb\r\nc"), "a\\tb\\r\\nc");
        assert_eq!(unescape_controls("a\\tb\\r\\nc"), "a\tb\r\nc");
        // A pair of backslashes stays, and so does a lone one.
        assert_eq!(unescape_controls("[/\\\\]n \\x \\"), "[/\\\\]n \\x \\");
        assert_eq!(escape_controls("fs.read:/a b/*"), "fs.read:/a b/*");
    }

    #[test]
    fn rules_for_the_buttons() {
        let r = |cap, action, target, wild| rule_for(cap, action, target, wild).unwrap();
        assert_eq!(
            r("exec", "run", "git push origin", false),
            "exec.run:git push origin"
        );
        assert_eq!(
            r("exec", "run", " git push origin ", true),
            "exec.run:git *"
        );
        assert_eq!(r("fs", "read", "/h/p/a.rs", false), "fs.read:/h/p/a.rs");
        assert_eq!(r("fs", "read", "/h/p/a.rs", true), "fs.read:/h/p/*");
        assert_eq!(r("fs", "list", "/h", true), "fs.list:/*");
        assert_eq!(r("camera", "snap", "camera.snap", false), "camera.snap");
        assert_eq!(r("camera", "snap", "camera.snap", true), "camera");
        for (cap, action, target) in [
            ("exec", "run", "  "),
            ("fs", "read", "relative"),
            ("fs.x", "read", "/a"),
        ] {
            assert!(rule_for(cap, action, target, false).is_err());
        }
        // Whatever a button writes is a valid rule that covers its entry.
        for (cap, action, target) in [
            ("exec", "run", "git status"),
            ("fs", "write", "/h/p/[x]/a"),
            ("camera", "snap", "camera.snap"),
        ] {
            for wild in [false, true] {
                let rule = rule_for(cap, action, target, wild).unwrap();
                validate(&rule).unwrap();
                assert!(set(&[&rule]).find(cap, action, target).is_some(), "{rule}");
            }
        }
    }

    #[test]
    fn rules_offer_actions_by_scope() {
        let r = |rules: &[&str]| rules.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(!offers(&r(&[]), "fs", "read"));
        // The pattern is not looked at; the scope is.
        assert!(offers(&r(&["fs:~/notes/*"]), "fs", "write"));
        assert!(offers(&r(&["fs.read:/a/*"]), "fs", "read"));
        assert!(!offers(&r(&["fs.read:/a/*"]), "fs", "write"));
        assert!(offers(&r(&["exec"]), "exec", "signal"));
        assert!(offers(&r(&["exec.run"]), "exec", "run"));
        assert!(!offers(&r(&["exec.run"]), "exec", "signal"));
        assert!(!offers(&r(&["execute:x", "fs"]), "exec", "run"));
        // Not a rule: nothing is covered.
        assert!(!offers(&r(&["fs:", "fs.read:[", "a.b.c"]), "fs", "read"));
    }

    #[test]
    fn sudo_rules() {
        assert_eq!(
            sudo_rule_for("sudo apt update", false).unwrap(),
            "sudo apt update"
        );
        assert_eq!(
            sudo_rule_for("sudo apt update", true).unwrap(),
            "sudo apt *"
        );
        assert_eq!(
            sudo_rule_for("sudo -n true x", true).unwrap(),
            "sudo -n true *"
        );
        assert_eq!(sudo_rule_for("sudo -i", true).unwrap(), "sudo -i *");
        assert!(sudo_rule_for("apt update", false).is_err());
        let list = vec![sudo_rule_for("sudo apt update", true).unwrap()];
        assert!(command_matches(&list, "sudo apt upgrade -y"));
        assert!(!command_matches(&list, "sudo rm -rf /"));
    }
}
