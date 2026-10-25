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
//! A line the parser cannot read is checked on the commands it read before
//! it gave out, and with the guard's text patterns (crate::rules), so it is
//! refused wherever those refused it.

use crate::command::{Command, Run, Script, Shell, Word, base_name, run};

/// One rule of the guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Guard {
    /// A command that runs `nerve-node` or `nerve-node-desktop`, or that
    /// copies, moves, links, deletes or overwrites their files.
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

    /// Whether a command of `script` refuses the line. Every command is read
    /// by the rules of the shell its text was written for (`script.shell`):
    /// a `powershell -Command` body in a line for sh is PowerShell.
    pub fn refuses(self, script: &Script) -> bool {
        self.scan(script).0
    }

    /// [`Guard::refuses`], and whether a word of the script, or of one
    /// nested in it, names the node's program file. A nested script is read
    /// once, whatever the depth, so the answer for a pipe does not cost a
    /// pass over what is in the commands before it for each level.
    fn scan(self, script: &Script) -> (bool, bool) {
        // What the earlier commands of the pipe the command stands in
        // name: one pass, so a long pipe costs no more than it is long.
        let mut fed = Fed::default();
        let mut file = false;
        for cmd in &script.commands {
            // The closer of a group (`{ echo <program>; } | xargs rm`) is a
            // command of its own, but the pipe goes on through it.
            if !cmd.piped && !is_closer(cmd) {
                fed = Fed::default();
            }
            let mut nested = false;
            for inner in &cmd.inner {
                let (refused, named) = self.scan(inner);
                if refused {
                    return (true, true);
                }
                nested |= named;
            }
            if self.command(cmd, script.shell, fed) {
                return (true, true);
            }
            match self {
                Guard::Service => fed.service |= mention(cmd, script.shell.windows()),
                Guard::Programs if !fed.file => {
                    let spelling = Spelling::of(script.shell);
                    fed.file = nested || cmd.words.iter().any(|w| is_node_file(&w.text, spelling));
                    file |= fed.file;
                }
                _ => {}
            }
        }
        (false, file)
    }

    fn command(self, cmd: &Command, shell: Shell, fed: Fed) -> bool {
        let win = shell.windows();
        match self {
            Guard::Programs => {
                // A redirection onto the program writes it, whatever
                // command it stands on.
                cmd.redirects.iter().any(|w| names_node(&w.text, win))
                    || run(cmd, shell).is_some_and(|r| {
                        is_node(&r.name)
                            || changes_file(&r, Spelling::of(shell))
                            // `Get-Item <program> | Remove-Item`,
                            // `echo <program> | xargs rm`: the path comes
                            // from the command before.
                            || (fed.file && TAKES_PATHS.contains(&r.name.to_lowercase().as_str()))
                    })
            }
            Guard::Paths => cmd
                .words
                .iter()
                .chain(&cmd.redirects)
                .any(|w| names_node_path(&w.text, win)),
            Guard::Service => run(cmd, shell).is_some_and(|r| stops(&r, cmd, fed.service, win)),
        }
    }
}

/// Whether a command is the word that ends a group or a block.
fn is_closer(cmd: &Command) -> bool {
    matches!(cmd.words.as_slice(), [w] if matches!(w.text.as_str(), "}" | "fi" | "done" | "esac" | "end"))
}

/// What the earlier commands of a pipe name, for the rule that looks at it.
#[derive(Debug, Clone, Copy, Default)]
struct Fed {
    /// Service rule: the node's program or service by name.
    service: bool,
    /// Programs rule: a path of the node's program.
    file: bool,
}

/// How a shell spells the paths in a word of a file tool.
#[derive(Debug, Clone, Copy)]
struct Spelling {
    /// Case does not count and `\` separates.
    win: bool,
    /// A comma separates paths, where PowerShell or cmd reads the line: a
    /// Windows node's sh keeps it in the word, as any sh does.
    comma: bool,
    /// `{a,b}` is several words, in sh and fish.
    brace: bool,
}

impl Spelling {
    fn of(shell: Shell) -> Spelling {
        Spelling {
            win: shell.windows(),
            comma: !shell.posix(),
            brace: shell.posix(),
        }
    }
}

/// The node's programs, as [`base_name`] gives them.
const NODE: [&str; 2] = ["nerve-node", "nerve-node-desktop"];

fn is_node(name: &str) -> bool {
    NODE.contains(&name)
}

/// The programs that copy, move, link, delete, overwrite or change a file:
/// the file tools proper, the writers (`tee`, `dd`, `sed`), the downloaders
/// (`curl -o`, `wget -O`, `Invoke-WebRequest -OutFile`), the packers and
/// binary editors (`gzip`, `upx`, `objcopy`) and those that change its mode
/// or owner. The programs that only look at a file are not here, and a
/// program that is not on the list (an interpreter, a .NET call) is not
/// seen when it writes the file.
const FILE_TOOLS: &[&str] = &[
    "rm",
    "mv",
    "cp",
    "install",
    "ln",
    "unlink",
    "shred",
    "truncate",
    "del",
    "erase",
    "move",
    "copy",
    "xcopy",
    "ren",
    "rename",
    "remove-item",
    "ri",
    "move-item",
    "mi",
    "copy-item",
    "cpi",
    "rename-item",
    "rni",
    "tee",
    "dd",
    "sed",
    "patch",
    "strip",
    "chmod",
    "chown",
    "chgrp",
    "setcap",
    "rsync",
    "scp",
    "curl",
    "wget",
    "invoke-webrequest",
    "iwr",
    "invoke-restmethod",
    "irm",
    "set-content",
    "add-content",
    "out-file",
    "new-item",
    "set-itemproperty",
    "icacls",
    "takeown",
    "attrib",
    "clear-content",
    "clc",
    "start-bitstransfer",
    "certutil",
    "gzip",
    "xz",
    "bzip2",
    "zstd",
    "upx",
    "objcopy",
    "patchelf",
];

/// The file tools that get the paths they work on, not data, from what a
/// pipe feeds them (`xargs rm`, PowerShell's pipeline into `Remove-Item`).
/// The writers (`tee`, `sed`, `dd`, `curl`, `Out-File`) are not here: what
/// they get from a pipe is data, and `cargo build -p nerve-node | tee log`
/// is not a change of the program.
const TAKES_PATHS: &[&str] = &[
    "rm",
    "mv",
    "cp",
    "install",
    "ln",
    "unlink",
    "shred",
    "truncate",
    "chmod",
    "chown",
    "chgrp",
    "del",
    "erase",
    "move",
    "copy",
    "ren",
    "rename",
    "remove-item",
    "ri",
    "move-item",
    "mi",
    "copy-item",
    "cpi",
    "rename-item",
    "rni",
    // Takes no data from a pipe: only the path, by property name.
    "clear-content",
    "clc",
];

/// Whether `r` copies, moves, links, deletes or overwrites the node's
/// program file: replacing the binary of the node is changing it. Looking at
/// it (`ls`, `file`, `sha256sum`) is not.
fn changes_file(r: &Run, spelling: Spelling) -> bool {
    FILE_TOOLS.contains(&r.name.to_lowercase().as_str())
        && r.args.iter().any(|w| is_node_file(&w.text, spelling))
}

/// Whether an argument of a file tool names the node's program: the whole
/// argument as a path (it may hold blanks: `C:\Program Files\…`), or the
/// value of `of=`, `--output=` or `-Destination:`. Data that only holds the
/// name (`curl -d name=nerve-node`, `--exclude=nerve-node`) is not it.
/// In PowerShell and cmd (`comma`) a comma separates paths (`Remove-Item
/// a,b`); in sh it is part of the word (`sed -i "s,a/nerve-node,b,"`). In sh
/// and fish (`brace`) a word with `{a,b}` is several (`mv nerve-node{,.bak}`),
/// whether it was quoted or not.
fn is_node_file(word: &str, spelling: Spelling) -> bool {
    let Spelling { win, comma, brace } = spelling;
    // A brace group can build the name (`nerve-{node,x}`).
    if !(brace && word.contains('{')) && !may_name_node(word, win) {
        return false;
    }
    let value = match word.split_once('=') {
        Some((key, v))
            if key == "of"
                || ["--output", "--target", "--dest"]
                    .iter()
                    .any(|k| key.starts_with(k)) =>
        {
            v
        }
        _ => match word.split_once(':') {
            Some((_, v)) if word.starts_with('-') => v,
            _ => word,
        },
    };
    [word, value].iter().any(|w| {
        w.split(|c| comma && c == ',').any(|p| {
            if brace && p.contains('{') {
                let mut all = Vec::new();
                expand_braces(p, &mut all, &mut Budget::of(p));
                all.iter().any(|p| is_node(&base_name(p, win)))
            } else {
                is_node(&base_name(p, win))
            }
        })
    })
}

/// How much of one word `expand_braces` builds: a few times the word's
/// length in bytes, where every alternative copies the rest of the word and
/// every word built costs [`WORD_COST`] besides. What is left stays as
/// written, so a hostile word costs work in proportion to its length, not to
/// its groups. There is no cap on the number of groups besides: every
/// expansion pays for the words it builds, at least `2 * WORD_COST`, so the
/// number of expansions, and the depth of the recursion, stay far under the
/// word's length.
struct Budget {
    bytes: usize,
}

/// What a word built by `expand_braces` costs besides its bytes (its
/// allocation, and the base name taken from it).
const WORD_COST: usize = 32;

impl Budget {
    fn of(word: &str) -> Budget {
        Budget {
            bytes: 16 * word.len() + 256,
        }
    }
}

/// `word` with its first `{a,b,…}` group expanded into each alternative, and
/// so on for the groups left. A group without a comma at its top level
/// (`{}`, `{a..c}`) is not one.
fn expand_braces(word: &str, out: &mut Vec<String>, budget: &mut Budget) {
    let mut open = 0;
    let mut depth = 0usize;
    let mut cuts: Vec<usize> = Vec::new();
    for (i, c) in word.char_indices() {
        match c {
            '{' => {
                if depth == 0 {
                    open = i;
                    cuts.clear();
                }
                depth += 1;
            }
            ',' if depth == 1 => cuts.push(i),
            '}' if depth > 0 => {
                depth -= 1;
                if depth == 0 && !cuts.is_empty() {
                    // The words this group makes, counted before one is
                    // built: a group that does not fit stays as written.
                    // Each word costs a fixed amount too, so many short
                    // alternatives are not free.
                    let rest = word.len() - (i + 1 - open);
                    let cost = (cuts.len() + 1) * (rest + WORD_COST) + (i - open - 1) - cuts.len();
                    if cost > budget.bytes {
                        break;
                    }
                    budget.bytes -= cost;
                    let mut start = open + 1;
                    for end in cuts.iter().copied().chain([i]) {
                        let alt = &word[start..end];
                        let expanded = format!("{}{alt}{}", &word[..open], &word[i + 1..]);
                        expand_braces(&expanded, out, budget);
                        start = end + 1;
                    }
                    return;
                }
            }
            _ => {}
        }
    }

    out.push(word.to_string());
}

/// Whether a registry key is the node's service or below it:
/// `…\Services\nerve-node` and its subkeys (`…\Parameters` holds the list
/// of the node's owners).
fn is_service_key(key: &str) -> bool {
    let key = key.replace('/', "\\").to_lowercase();
    let key = key.trim_end_matches('\\');
    key.match_indices("\\services\\nerve-node").any(|(at, m)| {
        let rest = &key[at + m.len()..];
        // Services of the registry only: a folder `C:\Services\nerve-node`
        // is a folder.
        let set = key[..at].rsplit('\\').next().unwrap_or("");
        let in_registry = set == "currentcontrolset"
            || set
                .strip_prefix("controlset")
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
        in_registry && (rest.is_empty() || rest.starts_with('\\'))
    })
}

/// The node's service (systemd's unit, Windows' service).
fn is_service(word: &str, win: bool) -> bool {
    let w = if win {
        word.to_lowercase()
    } else {
        word.to_string()
    };
    w == "nerve-node" || w == "nerve-node.service" || (win && w == DISPLAY_NAME)
}

/// Whether `word` holds the node's name at all (the display name has a blank
/// where the program's has a dash). The exact checks cut the word into parts,
/// so this keeps a long word that cannot name the node from costing a pass of
/// them; on Windows case does not count.
fn may_name_node(word: &str, win: bool) -> bool {
    if win {
        let lower = word.to_ascii_lowercase();
        lower.contains("nerve-node") || lower.contains(DISPLAY_NAME)
    } else {
        word.contains("nerve-node")
    }
}

/// The Windows service's display name, which `net` and the service cmdlets
/// take as well as its key name (lower case).
const DISPLAY_NAME: &str = "nerve node";

/// Whether a word names the node's program or service by its name: the
/// whole word, or a part of it after `-Name:`, `=` or a comma, or a word of
/// a filter (`"IMAGENAME eq nerve-node.exe"`).
fn names_node(word: &str, win: bool) -> bool {
    may_name_node(word, win)
        && word
            .split(|c: char| matches!(c, ',' | ':' | '=') || c.is_whitespace())
            .any(|part| is_node(&base_name(part, win)))
}

/// [`names_node`], or on Windows the service's display name, which holds a
/// blank (`-DisplayName 'Nerve node'`).
fn names_service(word: &str, win: bool) -> bool {
    if !may_name_node(word, win) {
        return false;
    }
    // One pass over the word: the display name is a part between the
    // separators, the program or service name is a blank-separated word of
    // one.
    word.split([',', ':', '=']).any(|part| {
        (win && part.trim().eq_ignore_ascii_case(DISPLAY_NAME))
            || part
                .split_whitespace()
                .any(|name| is_node(&base_name(name, win)))
    })
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

/// For every byte position of `word`: whether a blank stands before it in
/// the same region of the word. The regions are the word itself and each
/// `$( … )` or pair of backticks in it; a region starts with the blank state
/// of the one it opens in, since a backtick in a word is often only
/// Markdown inline code in a sentence. A path after a blank is a sentence
/// (a commit message, the text of a here-document), not a path the command
/// opens; `$(echo $HOME)/…` has no blank outside its substitution, so it
/// stays a path. The commands of a substitution are checked on their own.
/// One pass over the word, so a word with many paths costs no more than a
/// word with one.
fn blank_before(word: &str) -> Vec<bool> {
    let mut out = vec![false; word.len() + 1];
    // The regions entered and not left yet (`true`: backticks), and the
    // ones that saw a blank; region 0 is the word.
    let mut open: Vec<(usize, bool)> = vec![(0, false)];
    let mut blank = vec![false];
    let mut prev = ' ';
    for (i, c) in word.char_indices() {
        let top = open.last().copied().unwrap_or((0, false));
        out[i] = blank[top.0];
        match c {
            '(' if prev == '$' => {
                blank.push(blank[top.0]);
                open.push((blank.len() - 1, false));
            }
            ')' if !top.1 && open.len() > 1 => {
                open.pop();
            }
            '`' if top.1 => {
                open.pop();
            }
            '`' => {
                blank.push(blank[top.0]);
                open.push((blank.len() - 1, true));
            }
            c if c.is_whitespace() => blank[top.0] = true,
            _ => {}
        }
        prev = c;
    }
    out[word.len()] = open.last().is_some_and(|(id, _)| blank[*id]);
    out
}

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
    let blanks = blank_before(&text);
    for (path, open) in PATHS {
        for (at, _) in text.match_indices(path) {
            if !blanks[at] && (*open || ends(&text[at + path.len()..])) {
                return true;
            }
        }
    }
    // `C:\ProgramData\Nerve`, `%ProgramData%\Nerve`, `$env:ProgramData\Nerve`.
    let lower = text.to_lowercase();
    let blanks = blank_before(&lower);
    for (at, _) in lower.match_indices("programdata") {
        let rest = lower[at + "programdata".len()..].trim_start_matches(['%', '}', ')', '"', '\'']);
        if !blanks[at]
            && let Some(after) = rest.strip_prefix("/nerve")
            && ends(after)
        {
            return true;
        }
    }
    false
}

/// What stops, restarts, disables or kills the node, by the program `r` and
/// its arguments; `fed`: an earlier command of its pipe names the node.
fn stops(r: &Run, cmd: &Command, fed: bool, win: bool) -> bool {
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
            // net takes its switches (`/y`) before the service as well.
            let ops: Vec<&str> = operands(args, &[])
                .into_iter()
                .filter(|o| !o.starts_with('/'))
                .collect();
            ops.len() >= 2 && ops[0].eq_ignore_ascii_case("stop") && is_service(ops[1], true)
        }
        // The service's registry key holds its start type and its path:
        // changing or deleting the key disables or removes the service.
        "reg" => {
            let ops: Vec<&str> = operands(args, &[])
                .into_iter()
                .filter(|o| !o.starts_with('/'))
                .collect();
            ops.split_first().is_some_and(|(verb, keys)| {
                matches!(
                    verb.to_lowercase().as_str(),
                    "add" | "delete" | "copy" | "restore"
                ) && keys.iter().any(|k| is_service_key(k))
            })
        }
        // The same key through PowerShell's registry provider, with the
        // names `Remove-Item` and the other item cmdlets go by.
        "new-itemproperty"
        | "remove-itemproperty"
        | "clear-itemproperty"
        | "rename-itemproperty"
        | "copy-itemproperty"
        | "move-itemproperty"
        | "set-itemproperty"
        | "sp"
        | "rp"
        | "clp"
        | "rnp"
        | "cpp"
        | "mp"
        | "remove-item"
        | "ri"
        | "rm"
        | "del"
        | "erase"
        | "rd"
        | "rmdir"
        | "clear-item"
        | "cli"
        | "rename-item"
        | "rni"
        | "ren"
        | "move-item"
        | "mi"
        | "move"
        | "mv"
        | "new-item"
        | "ni"
            if win =>
        {
            // `-Path:HKLM:\…` holds the key as well as `-Path HKLM:\…`.
            args.iter().any(|w| is_service_key(&w.text))
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
            args.iter().any(|w| names_service(&w.text, win))
                || cmd.inner.iter().any(|s| mentions(s, win))
                || fed
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
            | "reload-or-try-restart"
            | "force-reload"
            | "condreload"
            | "condrestart"
            | "condstop"
            | "freeze"
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
/// `.*`, by its program's name (`^/usr/bin/nerve-node`), in any of its
/// alternatives (`nerve-node|nerve-center`). A pattern that
/// names it later (`pkill -f "cargo run -p nerve-node"`) is another program.
fn pattern_names_node(pattern: &str, win: bool) -> bool {
    let first = pattern.split_whitespace().next().unwrap_or("");
    // The pattern is a regular expression: `|` separates alternatives, and
    // a group's brackets surround one.
    first.split('|').any(|alt| {
        let alt = alt.trim_matches(['^', '$', '(', ')']);
        // A group before the name stays on it (`debug/(nerve-node`,
        // `(debug/)?nerve-node`).
        let name = base_name(alt, win);
        let name = name.trim_start_matches(['(', ')', '?', '^']);
        is_node(name.trim_end_matches(['*', '.', '$', '+', '?']))
    })
}

/// Whether a command (or one nested in it) names the node's program or
/// service in a word.
fn mention(cmd: &Command, win: bool) -> bool {
    cmd.words.iter().any(|w| names_service(&w.text, win))
        || cmd.inner.iter().any(|s| mentions(s, win))
}

fn mentions(script: &Script, win: bool) -> bool {
    script.commands.iter().any(|c| mention(c, win))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SH: Spelling = Spelling {
        win: false,
        comma: false,
        brace: true,
    };
    const PS: Spelling = Spelling {
        win: true,
        comma: true,
        brace: false,
    };
    // sh on a Windows node.
    const WIN_SH: Spelling = Spelling {
        win: true,
        comma: false,
        brace: true,
    };

    #[test]
    fn a_comma_splits_paths_only_where_the_dialect_says() {
        // PowerShell and cmd: `Remove-Item a.txt,C:\x\nerve-node.exe`.
        assert!(is_node_file("a.txt,C:\\x\\nerve-node.exe", PS));
        // sh on a Windows node: case and `\` count, the comma stays in the
        // word (`sed -i "s,a/nerve-node,b,"`).
        assert!(!is_node_file("s,crates/nerve-node,crates/node,g", WIN_SH));
        assert!(is_node_file("C:\\x\\NERVE-NODE.exe", WIN_SH));
    }

    #[test]
    fn a_brace_group_is_several_words_in_sh_and_fish_only() {
        for word in [
            "/usr/local/bin/nerve-node{,.bak}",
            "nerve-{node,x}",
            "nerve-{x,node-desktop}",
            "/usr/{bin,sbin}/nerve-node",
            "{a,b}/nerve-{c,node}",
        ] {
            assert!(is_node_file(word, SH), "{word:?}");
        }
        // PowerShell and cmd do not expand it.
        assert!(!is_node_file("/usr/local/bin/nerve-node{,.bak}", PS));
        for word in [
            "/usr/local/bin/nerve-node{.old,.bak}",
            "nerve-{a,b}",
            "nerve-node{}",
            "{a..c}nerve",
            "a{,b",
            "}nerve-{",
        ] {
            assert!(!is_node_file(word, SH), "{word:?}");
        }
        // A word that expands to many stays bounded.
        let big = "{a,b}".repeat(5000) + "/nerve-node";
        assert!(is_node_file(&big, SH));
    }

    #[test]
    fn the_expansion_of_one_word_builds_a_bounded_amount() {
        // Many short alternatives in front of a long tail: every alternative
        // copies the tail, in each of the groups.
        let word = |alts: usize, tail: usize| {
            let group = format!("{{{}a}}", "a,".repeat(alts - 1));
            group.repeat(2) + &"x".repeat(tail)
        };
        for (alts, tail) in [(1000, 8000), (2000, 16_000), (8000, 32_000)] {
            let word = word(alts, tail);
            let mut out = Vec::new();
            expand_braces(&word, &mut out, &mut Budget::of(&word));
            let built: usize = out.iter().map(String::len).sum();
            assert!(built <= 20 * word.len() + 2048, "{alts} x {tail}: {built}");
            assert!(!out.is_empty());
        }
        // Many groups: each fits, together they do not.
        let word = "{a,b}".repeat(12) + &"x".repeat(4000);
        let mut out = Vec::new();
        expand_braces(&word, &mut out, &mut Budget::of(&word));
        let built: usize = out.iter().map(String::len).sum();
        assert!(built <= 20 * word.len() + 2048, "{built}");
        // Short alternatives are not free either: every word built costs
        // `WORD_COST` besides its bytes.
        for word in ["{,}".repeat(7), "{a,b}".repeat(7), "{,}".repeat(2000)] {
            let mut out = Vec::new();
            let budget = Budget::of(&word);
            let allowed = 1 + budget.bytes / WORD_COST;
            expand_braces(&word, &mut out, &mut Budget::of(&word));
            assert!(out.len() <= allowed, "{} words of {word:.20}", out.len());
        }
        // A group that fits is still expanded in full.
        let mut out = Vec::new();
        expand_braces("a{b,c}d{e,f}", &mut out, &mut Budget::of("a{b,c}d{e,f}"));
        assert_eq!(out, ["abde", "abdf", "acde", "acdf"]);
    }

    #[test]
    fn a_registry_key_of_the_service_is_the_key_and_the_keys_below_it() {
        for key in [
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\nerve-node",
            "hklm\\system\\controlset001\\SERVICES\\Nerve-Node\\",
            "HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/nerve-node",
            "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\nerve-node\\Parameters",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\nerve-node\\Parameters\\x",
            "HKLM:\\SYSTEM\\ControlSet002\\Services\\nerve-node",
        ] {
            assert!(is_service_key(key), "{key:?}");
        }
        for key in [
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\spooler",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\nerve-node.exe",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\nerve-node-desktop\\x",
            "HKLM\\SOFTWARE\\nerve-node",
            // Folders and values that hold the same words are not keys.
            "C:\\Services\\nerve-node\\logs\\old.log",
            "C:\\Users\\a\\Services\\nerve-node\\target",
            "HKLM\\SYSTEM\\ControlSet\\Services\\nerve-node",
            "\\Services\\nerve-node",
        ] {
            assert!(!is_service_key(key), "{key:?}");
        }
    }

    #[test]
    fn a_pkill_pattern_names_the_node_in_any_alternative() {
        for p in [
            "nerve-node",
            "nerve-node|nerve-center",
            "nerve-center|nerve-node",
            "^nerve-node|foo$",
            "(nerve-center|nerve-node)",
            "^(a|nerve-node)$",
            "target/debug/(nerve-node|nerve-center)",
            "(target/debug/)?nerve-node",
            "nerve-node|nerve-node-desktop",
        ] {
            assert!(pattern_names_node(p, false), "{p:?}");
        }
        for p in ["nginx|php-fpm", "nerve-center|nerve", "nerve-node-x|y"] {
            assert!(!pattern_names_node(p, false), "{p:?}");
        }
    }

    #[test]
    fn the_display_name_counts_on_windows_only() {
        for w in [
            "Nerve node",
            "NERVE NODE",
            "-DisplayName:Nerve node",
            "x=Nerve node",
        ] {
            assert!(names_service(w, true), "{w:?}");
            assert!(!names_service(w, false), "{w:?}");
        }
        assert!(!names_service("Nerve nodes", true));
        // A file named so is not the node's program.
        assert!(!names_node("Nerve node", true));
        assert!(is_service("Nerve node", true));
        assert!(!is_service("Nerve node", false));
        assert!(!is_service("nerve node", false));
    }
}
