//! The guard against changing the node, on parsed commands
//! (docs/dev/policy-engine.md, the guard; docs/user/rules.md).
//!
//! Each rule of the guard is a deny rule `guard:<name>` that looks at every
//! command of an `exec.run` line ([`crate::command`]): at any depth (`$( … )`,
//! backticks, `sh -c`, PowerShell blocks), behind any wrapper (`sudo`, `env`,
//! `timeout`, `Start-Process`), and in every part of a list or pipe. The line
//! is refused when one command in it is a guarded one. A word of another
//! program that only mentions the node (`git commit -m "…"`, `echo`) is data.
//!
//! A line the parser cannot read is checked with the guard's text patterns
//! instead (crate::rules), so it is refused wherever those refused it.

use crate::command::{Command, Run, Script, Shell, Word, base_name, run};

/// One rule of the guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Guard {
    /// A command that runs `nerve-node` or `nerve-node-desktop`.
    Programs,
    /// A command that names the node's socket, pipes, config or state
    /// folders.
    Paths,
    /// A command that stops, restarts, disables or kills the node's service
    /// or process.
    Service,
}

impl Guard {
    pub const ALL: [Guard; 3] = [Guard::Programs, Guard::Paths, Guard::Service];

    /// The rule's text on a deny list.
    pub fn rule(self) -> &'static str {
        match self {
            Guard::Programs => "guard:node-programs",
            Guard::Paths => "guard:node-paths",
            Guard::Service => "guard:node-service",
        }
    }

    /// The rule a deny list entry is, if it is one of the guard's.
    pub fn of_rule(text: &str) -> Option<Guard> {
        Guard::ALL.into_iter().find(|g| g.rule() == text)
    }

    /// Whether a command of `script` refuses the line.
    pub fn refuses(self, script: &Script, shell: Shell) -> bool {
        let mut hit = false;
        script.visit(&mut |s: &Script, i| {
            hit = hit || self.command(s, i, shell);
        });
        hit
    }

    fn command(self, script: &Script, i: usize, shell: Shell) -> bool {
        let cmd = &script.commands[i];
        let win = shell.windows();
        match self {
            Guard::Programs => run(cmd, shell).is_some_and(|r| is_node(&r.name)),
            Guard::Paths => cmd
                .words
                .iter()
                .chain(&cmd.redirects)
                .any(|w| names_node_path(&w.text, win)),
            Guard::Service => run(cmd, shell).is_some_and(|r| stops(&r, script, i, win)),
        }
    }
}

/// The node's programs, as [`base_name`] gives them.
const NODE: [&str; 2] = ["nerve-node", "nerve-node-desktop"];

fn is_node(name: &str) -> bool {
    NODE.contains(&name)
}

/// The node's service (systemd's unit, Windows' service).
fn is_service(word: &str, win: bool) -> bool {
    let w = if win {
        word.to_lowercase()
    } else {
        word.to_string()
    };
    w == "nerve-node" || w == "nerve-node.service"
}

/// Whether a word names the node's program or service by its name: the
/// whole word, or a part of it after `-Name:`, `=` or a comma, or a word of
/// a filter (`"IMAGENAME eq nerve-node.exe"`).
fn names_node(word: &str, win: bool) -> bool {
    word.split(|c: char| matches!(c, ',' | ':' | '=') || c.is_whitespace())
        .any(|part| is_node(&base_name(part, win)))
}

/// The paths of the node's socket and pipes and its folders, and whether
/// anything may follow the name (a pipe's name goes on: `nerve-node-owner`).
const PATHS: &[(&str, bool)] = &[
    ("/run/nerve-node", false),
    ("//./pipe/nerve-node", true),
    ("/etc/nerve", false),
    ("/var/lib/nerve", false),
    (".config/nerve", false),
    (".local/state/nerve", false),
];

/// Whether `word` names one of the node's paths. The path may stand after a
/// prefix (`--config=`, `UNIX-CONNECT:`, `$HOME/`), but not after a blank: a
/// path in a sentence (a commit message) is data. On Windows `\` separates
/// and case does not count, and `%ProgramData%\Nerve` and its kin count.
fn names_node_path(word: &str, win: bool) -> bool {
    let text = if win {
        word.replace('\\', "/").to_lowercase()
    } else {
        word.to_string()
    };
    let ends = |rest: &str| {
        !rest.starts_with(|c: char| c.is_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    for (path, open) in PATHS {
        for (at, _) in text.match_indices(path) {
            if !text[..at].contains(char::is_whitespace)
                && (*open || ends(&text[at + path.len()..]))
            {
                return true;
            }
        }
    }
    // `C:\ProgramData\Nerve`, `%ProgramData%\Nerve`, `$env:ProgramData\Nerve`.
    let lower = text.to_lowercase();
    for (at, _) in lower.match_indices("programdata") {
        let rest = lower[at + "programdata".len()..].trim_start_matches(['%', '}', '"', '\'']);
        if !lower[..at].contains(char::is_whitespace)
            && let Some(after) = rest.strip_prefix("/nerve")
            && ends(after)
        {
            return true;
        }
    }
    false
}

/// What stops, restarts, disables or kills the node, by the program `r` and
/// its arguments; `script` and `i` place the command, for what a pipe feeds
/// into it.
fn stops(r: &Run, script: &Script, i: usize, win: bool) -> bool {
    let args = &r.args;
    let name = r.name.to_lowercase();
    match name.as_str() {
        "systemctl" => systemctl(args, win),
        "service" => {
            let ops: Vec<&str> = operands(args, &[]);
            ops.len() >= 2
                && is_service(ops[0], win)
                && matches!(
                    ops[1],
                    "stop" | "restart" | "try-restart" | "force-reload" | "condrestart"
                )
        }
        "sc" => {
            let ops: Vec<&str> = args
                .iter()
                .map(|w| w.text.as_str())
                .skip_while(|a| a.starts_with("\\\\"))
                .collect();
            ops.len() >= 2
                && matches!(ops[0].to_lowercase().as_str(), "stop" | "config" | "delete")
                && is_service(ops[1], true)
        }
        "net" => {
            let ops = operands(args, &[]);
            ops.len() >= 2 && ops[0].eq_ignore_ascii_case("stop") && is_service(ops[1], true)
        }
        "pkill" | "killall" => {
            let values: &[&str] = if name == "pkill" {
                &[
                    "-u",
                    "-U",
                    "-g",
                    "-G",
                    "-P",
                    "-s",
                    "-t",
                    "-F",
                    "-r",
                    "--signal",
                    "--ns",
                    "--nslist",
                    "--euid",
                    "--uid",
                    "--group",
                    "--pgroup",
                    "--parent",
                    "--session",
                    "--terminal",
                    "--pidfile",
                    "--runstates",
                ]
            } else {
                &[
                    "-s",
                    "-u",
                    "-o",
                    "-y",
                    "-n",
                    "-Z",
                    "--signal",
                    "--user",
                    "--older-than",
                    "--younger-than",
                    "--ns",
                    "--context",
                ]
            };
            operands(args, values)
                .iter()
                .any(|p| pattern_names_node(p, win))
        }
        // These take the node by its name, by what a substitution in them
        // finds (`kill $(pidof nerve-node)`), or by what a pipe feeds them
        // (`Get-Service nerve-node | Stop-Service`, `pgrep … | xargs kill`).
        "stop-service" | "spsv" | "restart-service" | "set-service" | "remove-service"
        | "suspend-service" | "stop-process" | "spps" | "kill" | "taskkill" => {
            let cmd = &script.commands[i];
            args.iter().any(|w| names_node(&w.text, win))
                || cmd.inner.iter().any(|s| mentions(s, win))
                || fed(script, i).any(|c| mention(c, win))
        }
        _ => false,
    }
}

/// `systemctl stop|restart|… nerve-node`: the verb is its first operand,
/// the unit any later one.
fn systemctl(args: &[Word], win: bool) -> bool {
    const VALUES: &[&str] = &[
        "-s",
        "-t",
        "-p",
        "-H",
        "-M",
        "-n",
        "-o",
        "--signal",
        "--type",
        "--property",
        "--host",
        "--machine",
        "--lines",
        "--output",
        "--kill-whom",
        "--kill-value",
        "--state",
        "--job-mode",
        "--root",
        "--what",
        "--when",
        "--message",
    ];
    let ops = operands(args, VALUES);
    let Some((verb, units)) = ops.split_first() else {
        return false;
    };
    matches!(
        *verb,
        "stop"
            | "restart"
            | "try-restart"
            | "reload-or-restart"
            | "try-reload-or-restart"
            | "disable"
            | "kill"
            | "mask"
    ) && units.iter().any(|u| is_service(u, win))
}

/// The words of `args` that are not options or their values.
fn operands<'a>(args: &'a [Word], values: &[&str]) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(w) = args.get(i) {
        let t = w.text.as_str();
        if t.starts_with('-') && t.len() > 1 {
            if values.contains(&t) {
                i += 1;
            }
        } else {
            out.push(t);
        }
        i += 1;
    }
    out
}

/// Whether a `pkill`/`killall` pattern names the node: its first word
/// (`pkill -f 'nerve-node --config x'`), without `^`, `$` and a trailing
/// `.*`, by its program's name (`^/usr/bin/nerve-node`). A pattern that
/// names it later (`pkill -f "cargo run -p nerve-node"`) is another program.
fn pattern_names_node(pattern: &str, win: bool) -> bool {
    let first = pattern.split_whitespace().next().unwrap_or("");
    let first = first.trim_start_matches('^').trim_end_matches('$');
    let name = base_name(first, win);
    is_node(name.trim_end_matches(['*', '.', '$', '+', '?']))
}

/// The commands before `i` in its pipe, nearest first.
fn fed(script: &Script, i: usize) -> impl Iterator<Item = &Command> {
    let cmds = &script.commands;
    (0..i)
        .rev()
        .take_while(move |&j| cmds[j + 1].piped)
        .map(move |j| &cmds[j])
}

/// Whether a command (or one nested in it) names the node's program or
/// service in a word.
fn mention(cmd: &Command, win: bool) -> bool {
    cmd.words.iter().any(|w| names_node(&w.text, win)) || cmd.inner.iter().any(|s| mentions(s, win))
}

fn mentions(script: &Script, win: bool) -> bool {
    script.commands.iter().any(|c| mention(c, win))
}
