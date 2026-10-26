//! Pulling a command line apart so the blocklist sees the real commands, not
//! just the raw string (docs/dev/action-checker.md).
//!
//! The blocklist is there to catch an agent's mistakes (a hallucinated
//! `rm -rf ~`, a force-push to main), not to stop someone who crafts a line
//! to get past it: that is the node's policy. So the splitter is simple and
//! conservative: where it is unsure, it reads more text as commands, not
//! less.
//!
//! [`parse`] reads the line twice and keeps the commands of both readings:
//! with nerve-policy's parser ([`nerve_policy::command`], the node's guard
//! reads commands with it), which knows more wrappers and the texts more
//! programs run, and with the text splitter of this module, which reads
//! what the parser reads otherwise or cannot read (see [`parse`]).
//!
//! The splitter splits the line into its individual commands: at `;`, `&&`,
//! `||`, `|`, `&`, newlines and the parentheses of a subshell, and inside
//! `$( )`, backticks (also within double quotes, for a POSIX shell), process
//! substitution `<( )`, `sh -c '…'` (with the `c` anywhere in the flag word:
//! `-c`, `-lc`, `-ce`, `-c -e`), `cmd /c …` and `powershell -Command` bodies,
//! and a here-string fed to a shell. The lines of a here-document (and of a
//! PowerShell here-string) are read as commands like any other line, whatever
//! the document is for. A `#` at the start of a word starts a comment that
//! runs to the end of its line. It strips wrappers (`sudo`, `env A=B`,
//! `nohup`, `command`, `exec`, `time`, `nice`, `xargs`, …) and shell keywords
//! (`if`, `then`, `do`, `!`, `{`, …), reads the program `Start-Process` or
//! `start` runs as a command of its own, takes the program's base name
//! (`/bin/rm` → `rm`, `bash.exe` → `bash`) and expands combined short flags
//! (`-rf` → `-r -f`) so `-rf`, `-fr` and `-r -f` all look the same.
//!
//! The line is read by the rules of the node's shell ([`Shell`]): a POSIX
//! shell's backslash escapes and backticks inside double quotes, or
//! PowerShell's, where a backslash is an ordinary character (`C:\`) and a
//! backtick is its escape.
//!
//! The whole walk is bounded: nesting (`$( )`, backticks, `-c` bodies, the
//! program a starter runs, all together) at [`MAX_DEPTH`], and the number of commands at [`MAX_COMMANDS`],
//! far above any real script (the node refuses a command line over 64 KiB
//! anyway). A line past a bound is reported as [`Parsed::overflow`], and the
//! checker refuses it rather than pass a line it could not take apart.
//!
//! What it cannot see is in the docs: variables, aliases, a script written
//! then run, base64. Those the decision model and the node's own policy are
//! for.

use std::collections::HashSet;

use nerve_policy::command;

/// The deepest nesting the walk descends, counting `$( )`, backticks, `-c`
/// bodies and started programs together. Real commands nest a few levels;
/// past this the line is reported as overflow.
pub const MAX_DEPTH: usize = 16;
/// The most commands the walk pulls from one line. A 64 KiB command line (the
/// node's own limit) holds at most about 32 000; a script or here-document
/// of ordinary size is far below. Only a line built to drown the matcher gets
/// here.
pub const MAX_COMMANDS: usize = 100_000;

/// One command pulled from a command line.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Command {
    /// The program's base name, lower-cased, without `.exe` (`/usr/bin/RM` →
    /// `rm`, `C:\Windows\System32\cmd.exe` → `cmd`).
    pub program: String,
    /// Every argument after the program, in order, with combined short flags
    /// expanded (`-rf` → `-r`, `-f`).
    pub args: Vec<String>,
    /// The arguments as written (not expanded), for the patterns that look at
    /// words such as PowerShell's `-Recurse`.
    pub raw: Vec<String>,
}

impl Command {
    /// The short flags the command carries, each as one letter (`-rf -v` →
    /// `r`, `f`, `v`). Long flags (`--force`) are not here.
    pub fn short_flags(&self) -> Vec<char> {
        self.args
            .iter()
            .filter(|a| {
                a.len() == 2 && a.starts_with('-') && a.as_bytes()[1].is_ascii_alphanumeric()
            })
            .map(|a| a.chars().nth(1).unwrap())
            .collect()
    }

    /// The long flags, without the `--` (`--force` → `force`), lower-cased.
    pub fn long_flags(&self) -> Vec<String> {
        self.args
            .iter()
            .filter_map(|a| a.strip_prefix("--").filter(|r| !r.is_empty()))
            .map(|r| r.split('=').next().unwrap_or(r).to_ascii_lowercase())
            .collect()
    }

    /// The operands: the arguments that are not flags.
    pub fn operands(&self) -> Vec<&str> {
        self.args
            .iter()
            .filter(|a| !a.starts_with('-'))
            .map(String::as_str)
            .collect()
    }

    /// The command as one lower-case line, `program arg1 arg2 …` with the
    /// arguments as written: what a `cmd-re:` pattern matches. An argument
    /// with a blank in it is written in double quotes, so a pattern can tell
    /// where it ends (`"c:\users\max mustermann\build"` is one operand, not
    /// `c:\users\max` and more).
    pub fn line(&self) -> String {
        let mut s = self.program.clone();
        for a in &self.raw {
            s.push(' ');
            if a.chars().any(char::is_whitespace) {
                s.push('"');
                s.push_str(&a.to_lowercase());
                s.push('"');
            } else {
                s.push_str(&a.to_lowercase());
            }
        }
        s
    }
}

/// Which bound a line hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overflow {
    /// Nested deeper than [`MAX_DEPTH`].
    Depth,
    /// More commands than [`MAX_COMMANDS`].
    Commands,
}

/// The result of pulling a command line apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub commands: Vec<Command>,
    /// The walk hit a bound and could not take the whole line apart. The
    /// checker treats this as "cannot see" and refuses.
    pub overflow: Option<Overflow>,
}

/// Wrapper programs that run another command: stripped so the real program is
/// seen. `env` and `xargs` also drop their `NAME=value` and flag arguments.
const WRAPPERS: &[&str] = &[
    "sudo",
    "doas",
    "env",
    "nohup",
    "command",
    "exec",
    "time",
    "nice",
    "ionice",
    "xargs",
    "setsid",
    "stdbuf",
    "npx",
    "pnpx",
    "builtin",
    "nocorrect",
    "noglob",
];

/// Shell words that may stand before a command and are not the program
/// (`if rm …`, `then rm …`, `! rm …`, `{ rm …; }`).
const KEYWORDS: &[&str] = &[
    "!", "{", "}", "if", "then", "else", "elif", "fi", "do", "done", "while", "until", "esac",
];

/// Programs whose `-c` argument is itself a command line to pull apart.
const SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "mksh", "fish", "ash", "busybox",
];
const POWERSHELLS: &[&str] = &["powershell", "pwsh"];
/// PowerShell's `Start-Process` (with its aliases) and cmd's `start`: they
/// run another program, so that program is read as a command of its own.
/// `Start-Process … -Verb RunAs` is how a Windows agent runs a program
/// elevated, its `sudo`.
const STARTERS: &[&str] = &["start-process", "saps", "start"];
/// `Start-Process`'s switches, which take no value (every other parameter
/// takes the next word).
const START_SWITCHES: &[&str] = &[
    "wait",
    "passthru",
    "nonewwindow",
    "loaduserprofile",
    "usenewenvironment",
];

/// The shell whose rules a line is read by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    /// `sh`, `bash` and the like: `\` escapes the next character, and a
    /// backtick inside double quotes is a command substitution.
    Posix,
    /// Windows PowerShell or PowerShell 7: `\` is an ordinary character (a
    /// path separator), and a backtick is the escape character, so neither
    /// is read the POSIX way.
    PowerShell,
}

impl Shell {
    /// The shell a node runs `exec.run` in by default, by its platform: the
    /// node uses PowerShell on Windows and `/bin/sh` everywhere else
    /// (nerve-node `exec::shell_command`).
    pub fn for_os(os: &str) -> Shell {
        if os.eq_ignore_ascii_case("windows") {
            Shell::PowerShell
        } else {
            Shell::Posix
        }
    }
}

/// The commands in `line`, read as a POSIX shell would, with the overflow flag
/// ignored. Kept for the tests and callers that only want the commands.
pub fn commands(line: &str) -> Vec<Command> {
    parse(line, Shell::Posix).commands
}

/// Pulls `line` apart by the rules of `shell`, bounded in depth and in the
/// number of commands.
///
/// Two readers take the line apart, and a command either finds is one
/// here:
///
/// - nerve-policy's parser, the one the node's guard reads commands with
///   ([`nerve_policy::command`]): every command it finds, at any depth and
///   behind every wrapper it knows (`timeout`, `env -S`, `runuser`, `eval`,
///   `Invoke-Expression`, cmd's `call` and `if`, …), as the program it runs;
///   for a line it cannot read with confidence, the commands it read before
///   it gave out;
/// - the text splitter below ([`walk`]), for what the parser reads otherwise
///   or not at all: a line it cannot read, the lines of a here-document or
///   a PowerShell here-string (read as commands whatever the text is for:
///   the owner's decision rules out a special reading of documents), a
///   Windows path after a POSIX `\`, a `\` before a CRLF, cmd's `start ""`
///   written in PowerShell, and a chain of starters past the parser's bound.
///
/// So the blocklist catches all it caught with the splitter alone, and what
/// the parser sees besides.
pub fn parse(line: &str, shell: Shell) -> Parsed {
    let mut out = walk(line, shell);
    if out.overflow.is_some() {
        return out;
    }
    let mut seen: HashSet<Command> = out.commands.iter().cloned().collect();
    let script = match command::parse(line, shell.policy()) {
        Ok(script) => script,
        Err(gave_out) => gave_out.read,
    };
    script.visit(&mut |s, i| {
        if out.overflow.is_some() {
            return;
        }
        let Some(run) = command::run(&s.commands[i], s.shell) else {
            return;
        };
        let raw: Vec<String> = run.args.iter().map(|w| w.text.clone()).collect();
        let c = Command {
            program: base_name(&run.name),
            args: raw.iter().flat_map(|a| expand_flags(a)).collect(),
            raw,
        };
        if seen.contains(&c) {
            return;
        }
        if out.commands.len() >= MAX_COMMANDS {
            out.overflow = Some(Overflow::Commands);
            return;
        }
        seen.insert(c.clone());
        out.commands.push(c);
    });
    out
}

impl Shell {
    fn policy(self) -> command::Shell {
        match self {
            Shell::Posix => command::Shell::Sh,
            Shell::PowerShell => command::Shell::PowerShell,
        }
    }
}

/// The text splitter: pulls `line` apart by the rules of `shell` without
/// the parser, for a line the parser cannot read. Where it is unsure it
/// reads more text as commands, not less.
fn walk(line: &str, shell: Shell) -> Parsed {
    let mut w = Walk {
        commands: Vec::new(),
        overflow: None,
    };
    w.collect(line, shell, 0);
    Parsed {
        commands: w.commands,
        overflow: w.overflow,
    }
}

/// The state threaded through one walk. One `Walk` per [`walk`], so the
/// bounds cover the whole line, not each nesting level on its own.
struct Walk {
    commands: Vec<Command>,
    overflow: Option<Overflow>,
}

impl Walk {
    fn collect(&mut self, line: &str, shell: Shell, depth: usize) {
        if depth > MAX_DEPTH {
            self.overflow = Some(Overflow::Depth);
            return;
        }
        let (segments, subs) = split_segments(line, shell);
        // The line's own commands first, then the nested ones, so the outer
        // command is seen before what it runs.
        for segment in &segments {
            if self.commands.len() >= MAX_COMMANDS {
                self.overflow = Some(Overflow::Commands);
                return;
            }
            if let Some(words) = tokenize(segment, shell).filter(|w| !w.is_empty()) {
                self.parse_command(&words, shell, depth);
                if self.overflow.is_some() {
                    return;
                }
            }
        }
        for body in subs {
            self.collect(&body, shell, depth + 1);
            if self.overflow.is_some() {
                return;
            }
        }
    }

    /// One tokenized command, keywords and wrappers stripped, flags expanded;
    /// a nested shell's body and a started program are walked at `depth + 1`,
    /// by that shell's rules.
    fn parse_command(&mut self, words: &[String], shell: Shell, depth: usize) {
        // A started program is a level of its own, so a chain of starters
        // counts against both bounds like any other nesting.
        if depth > MAX_DEPTH {
            self.overflow = Some(Overflow::Depth);
            return;
        }
        if self.commands.len() >= MAX_COMMANDS {
            self.overflow = Some(Overflow::Commands);
            return;
        }
        let Some(i) = program_index(words) else {
            return;
        };
        let program = base_name(&words[i]);
        let rest = &words[i + 1..];

        let args = rest.iter().flat_map(|a| expand_flags(a)).collect();
        self.commands.push(Command {
            program: program.clone(),
            args,
            raw: rest.to_vec(),
        });

        // A nested shell: its `-c` / `/c` / `-Command` body is another
        // command line, read by that shell's rules (`cmd` has neither
        // escape, so it keeps the outer line's).
        let body = if SHELLS.contains(&program.as_str()) {
            shell_c_body(rest).map(|b| (b, Shell::Posix))
        } else if program == "cmd" {
            cmd_c_body(rest).map(|b| (b, shell))
        } else if POWERSHELLS.contains(&program.as_str()) {
            powershell_body(rest).map(|b| (b, Shell::PowerShell))
        } else {
            None
        };
        if let Some((body, inner)) = body {
            self.collect(&body, inner, depth + 1);
            if self.overflow.is_some() {
                return;
            }
        }
        // `Start-Process diskpart -Verb RunAs`: the program started, with the
        // words after it, is a command too, one level down, so a line of
        // nothing but starters stops at the depth bound instead of recursing
        // (and copying its words) once per word.
        if STARTERS.contains(&program.as_str())
            && let Some(started) = started_program(rest)
        {
            self.parse_command(&started, shell, depth + 1);
        }
    }
}

/// The index of the program in a command's words: past the leading shell
/// keywords and wrappers (with a wrapper's own arguments: `env A=B`,
/// `nice -n 5`, `sudo -u user`, `xargs -0`).
fn program_index(words: &[String]) -> Option<usize> {
    let mut i = 0;
    while i < words.len() {
        let w = base_name(&words[i]);
        if KEYWORDS.contains(&words[i].as_str()) {
            i += 1;
            continue;
        }
        if !WRAPPERS.contains(&w.as_str()) {
            break;
        }
        i += 1;
        while i < words.len() {
            let a = &words[i];
            if a.contains('=') && !a.starts_with('-') {
                i += 1;
            } else if a.starts_with('-') {
                let takes_value = a.len() == 2 && wrapper_value_flag(&w, a.as_bytes()[1]);
                i += 1;
                if takes_value && i < words.len() && !words[i].starts_with('-') {
                    i += 1;
                }
            } else {
                break;
            }
        }
    }
    (i < words.len()).then_some(i)
}

/// The program a segment runs, for telling whether a here-string is fed to a
/// shell.
fn segment_program(segment: &str, shell: Shell) -> Option<String> {
    let words = tokenize(segment, shell)?;
    let i = program_index(&words)?;
    Some(base_name(&words[i]))
}

/// Splits a command line at the separators that start a new command (`;`,
/// `&&`, `||`, `|`, `&`, newlines, and the parentheses of a subshell), and
/// returns the bodies that run as commands of their own separately (raw, not
/// split) so the caller walks them at the next depth: `$( )`, backticks,
/// `<( )`/`>( )`, and here-strings fed to a shell. Quotes are honoured (and
/// kept, for the tokenizer) so a separator inside a string does not split,
/// and nothing inside single quotes expands.
///
/// The lines of a here-document are split like any other line, so a command
/// in it is seen whether the document is fed to a shell or written to a
/// file; only a quote does not run past the end of a body line (see
/// [`close_body_quotes`]). A `#` at the start of a word starts a comment
/// that runs to the end of the line; nothing in it (a quote, a `<<`) changes
/// how the next lines are read.
fn split_segments(line: &str, shell: Shell) -> (Vec<String>, Vec<String>) {
    let posix = shell == Shell::Posix;
    let line = if posix {
        close_body_quotes(line)
    } else {
        close_here_strings(line)
    };
    let mut segments = Vec::new();
    let mut subs = Vec::new();
    let mut cur = String::new();
    let mut chars = line.chars().peekable();
    let mut quote: Option<char> = None;
    let mut herestrings: Vec<String> = Vec::new();
    // The first segment of the current line, for telling whether it feeds a
    // shell when the line ends.
    let mut line_start = 0;
    // The character before this one, for telling a word's start (where a
    // `#` starts a comment) from the middle of a word (`a#b`, `$#`).
    let mut prev: Option<char> = None;
    while let Some(c) = chars.next() {
        let before = prev.replace(c);
        if let Some(q) = quote {
            cur.push(c);
            if q == '"' && c == '$' && chars.peek() == Some(&'(') {
                chars.next();
                cur.push('(');
                let body = take_until_balanced(&mut chars, '(', ')');
                cur.push_str(&body);
                cur.push(')');
                subs.push(body);
            } else if posix && q == '"' && c == '`' {
                // Only a POSIX shell runs a backtick in double quotes; in
                // PowerShell it is the escape character (`` `n ``).
                let body = take_until(&mut chars, '`');
                cur.push_str(&body);
                cur.push('`');
                subs.push(body);
            } else if posix && q == '"' && c == '\\' {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' => {
                quote = Some(c);
                cur.push(c);
            }
            '#' if before.is_none_or(|p| p.is_whitespace() || ";&|()".contains(p)) => {
                // A comment, to the end of the line (the line break itself
                // still ends the command).
                while chars.peek().is_some_and(|n| *n != '\n' && *n != '\r') {
                    chars.next();
                }
            }
            '\\' if posix => {
                // Keep the escape with its character for the tokenizer.
                cur.push(c);
                if let Some(n) = chars.next() {
                    cur.push(n);
                    // A `\` continuing a CRLF line takes the whole break.
                    if n == '\r' && chars.peek() == Some(&'\n') {
                        cur.push(chars.next().unwrap());
                    }
                }
            }
            '`' => subs.push(take_until(&mut chars, '`')),
            '$' if chars.peek() == Some(&'(') => {
                chars.next();
                subs.push(take_until_balanced(&mut chars, '(', ')'));
            }
            '<' | '>' if chars.peek() == Some(&'(') => {
                chars.next();
                subs.push(take_until_balanced(&mut chars, '(', ')'));
            }
            '<' if starts_with(&chars, "<<") => {
                // A here-string: its word is the command's input. It is read
                // ahead on a copy, so the word is still split as usual.
                chars.next();
                chars.next();
                cur.push_str("<<<");
                herestrings.push(take_word(&mut chars.clone()));
            }
            '\n' | '\r' => {
                push_segment(&mut segments, &mut cur);
                if !herestrings.is_empty() {
                    let feeds = feeds_shell(&segments[line_start..], shell);
                    for h in herestrings.drain(..) {
                        if feeds {
                            subs.push(dequote(&h));
                        }
                    }
                }
                line_start = segments.len();
            }
            ';' | '&' | '|' | '(' | ')' => {
                // `&&` and `||` are two characters; one `&` or `|` splits too.
                if (c == '&' || c == '|') && chars.peek() == Some(&c) {
                    chars.next();
                }
                push_segment(&mut segments, &mut cur);
            }
            _ => cur.push(c),
        }
    }
    push_segment(&mut segments, &mut cur);
    // A here-string on the last line.
    if !herestrings.is_empty() && feeds_shell(&segments[line_start..], shell) {
        subs.extend(herestrings.iter().map(|h| dequote(h)));
    }
    (segments, subs)
}

/// Whether the next characters are `s`, without consuming them.
fn starts_with(chars: &std::iter::Peekable<std::str::Chars>, s: &str) -> bool {
    let mut ahead = chars.clone();
    s.chars().all(|c| ahead.next() == Some(c))
}

/// `text` with every quote or backtick still open at the end of a
/// here-document's body line closed there.
///
/// The shell takes a body as plain text, so an apostrophe in it ("Don't", a
/// Rust `'a`) or a lone `"` means nothing. The walk reads body lines as
/// commands, though, and a quote opened there would run on past the
/// document's end and hide every command after it in one word. Closing it at
/// the line's end keeps each body line to itself. Lines outside a body keep
/// their quotes as written, so a quoted string may still span lines there.
fn close_body_quotes(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.contains("<<") {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 16);
    // The end words of the documents opened on the current command line, and
    // of the ones whose bodies come next, in order (with whether `<<-` lets
    // tabs stand before the end word).
    let mut opened: Vec<(String, bool)> = Vec::new();
    let mut bodies: std::collections::VecDeque<(String, bool)> = Default::default();
    // A quote still open from an earlier command line.
    let mut quote: Option<char> = None;
    for (i, raw) in text.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if let Some((word, dash)) = bodies.front() {
            let bare = if *dash {
                line.trim_start_matches('\t')
            } else {
                line
            };
            if bare == word {
                bodies.pop_front();
                out.push_str(raw);
            } else {
                out.push_str(line);
                out.push_str(&scan_line(line, None, None, Shell::Posix).1);
                out.push_str(&raw[line.len()..]);
            }
            continue;
        }
        quote = scan_line(line, quote, Some(&mut opened), Shell::Posix).0;
        out.push_str(raw);
        // A document's body starts on the line after the one that opened it,
        // once its quotes are closed.
        if quote.is_none() {
            bodies.extend(opened.drain(..));
        }
    }
    std::borrow::Cow::Owned(out)
}

/// `text` with PowerShell's here-strings made plain for the splitter: the
/// quote of the `@'` or `@"` that opens one (at a line's end) and of the
/// `'@` or `"@` that ends it (at a line's start) is dropped, and a quote
/// still open at the end of a line inside it is closed there.
///
/// PowerShell takes a here-string's lines as plain text, so an apostrophe in
/// them ("Don't") means nothing; read as a quote, it would run past the
/// here-string's end and hide every command after it in one word. The lines
/// are still read as commands, as a POSIX here-document's are
/// ([`close_body_quotes`]).
fn close_here_strings(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.contains("@'") && !text.contains("@\"") {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 16);
    // The quote of the here-string the current line is in.
    let mut inside: Option<char> = None;
    // A quote still open from an earlier line outside a here-string.
    let mut quote: Option<char> = None;
    for (i, raw) in text.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let eol = &raw[line.len()..];
        let mut rest = line;
        if let Some(q) = inside {
            let mut end = line.chars();
            if end.next() == Some(q) && end.next() == Some('@') {
                // The end: its quote goes, the rest of the line is read as
                // usual.
                inside = None;
                out.push(' ');
                rest = &line[1..];
            } else {
                out.push_str(line);
                out.push_str(&scan_line(line, None, None, Shell::PowerShell).1);
                out.push_str(eol);
                continue;
            }
        }
        let body = rest.trim_end();
        let opens = (body.ends_with("@'") || body.ends_with("@\""))
            && scan_line(&body[..body.len() - 1], quote, None, Shell::PowerShell)
                .0
                .is_none();
        if opens {
            inside = body.chars().last();
            out.push_str(&body[..body.len() - 1]);
            out.push_str(&rest[body.len()..]);
        } else {
            quote = scan_line(rest, quote, None, Shell::PowerShell).0;
            out.push_str(rest);
        }
        out.push_str(eol);
    }
    std::borrow::Cow::Owned(out)
}

/// Reads one line's quotes by the rules of [`split_segments`] for `shell`,
/// starting inside `quote` (one left open by an earlier line). Returns the
/// quote open at the line's end and what closes everything still open there
/// (a backtick, then the quote). With `opened`, notes the end word of each
/// POSIX here-document the line opens outside quotes.
fn scan_line(
    line: &str,
    mut quote: Option<char>,
    mut opened: Option<&mut Vec<(String, bool)>>,
    shell: Shell,
) -> (Option<char>, String) {
    let posix = shell == Shell::Posix;
    let mut chars = line.chars().peekable();
    let mut prev: Option<char> = None;
    let mut tick = false;
    while let Some(c) = chars.next() {
        let before = prev.replace(c);
        if let Some(q) = quote {
            if posix && q == '"' && c == '\\' {
                chars.next();
            } else if posix && q == '"' && c == '`' {
                if !skip_ticked(&mut chars) {
                    tick = true;
                    break;
                }
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' => quote = Some(c),
            '\\' if posix => {
                chars.next();
            }
            '`' => {
                if !skip_ticked(&mut chars) {
                    tick = true;
                    break;
                }
            }
            '#' if before.is_none_or(|p| p.is_whitespace() || ";&|()".contains(p)) => break,
            '<' if chars.peek() == Some(&'<') => {
                chars.next();
                if chars.peek() == Some(&'<') {
                    // A here-string, not a document.
                    chars.next();
                    continue;
                }
                let dash = chars.peek() == Some(&'-');
                if dash {
                    chars.next();
                }
                let word = dequote(&take_word(&mut chars));
                if let Some(o) = opened.as_deref_mut().filter(|_| !word.is_empty()) {
                    o.push((word, dash));
                }
            }
            _ => {}
        }
    }
    let mut close = String::new();
    if tick {
        close.push('`');
    }
    if let Some(q) = quote {
        close.push(q);
    }
    (quote, close)
}

/// Past a backtick's closing one on the same line, if there is one; `false`
/// (and nothing taken) when the backtick stays open to the line's end.
fn skip_ticked(chars: &mut std::iter::Peekable<std::str::Chars>) -> bool {
    // Read ahead on a copy and take it only when the closing one is there,
    // so each character is read at most twice.
    let mut ahead = chars.clone();
    while let Some(c) = ahead.next() {
        if c == '`' {
            *chars = ahead;
            return true;
        }
    }
    false
}

/// Whether any segment of a line runs a shell (so a here-string on it is a
/// script).
fn feeds_shell(segments: &[String], shell: Shell) -> bool {
    segments
        .iter()
        .filter_map(|s| segment_program(s, shell))
        .any(|p| SHELLS.contains(&p.as_str()) || POWERSHELLS.contains(&p.as_str()))
}

/// One shell word after `<<<`, with its quotes kept, after any blanks.
fn take_word(chars: &mut std::iter::Peekable<std::str::Chars>) -> String {
    while chars.peek().is_some_and(|c| *c == ' ' || *c == '\t') {
        chars.next();
    }
    let mut out = String::new();
    let mut quote: Option<char> = None;
    while let Some(&c) = chars.peek() {
        match quote {
            Some(q) => {
                out.push(c);
                chars.next();
                if c == q {
                    quote = None;
                }
            }
            None => {
                if c.is_whitespace() || ";&|()<>".contains(c) {
                    break;
                }
                if c == '\'' || c == '"' {
                    quote = Some(c);
                }
                out.push(c);
                chars.next();
            }
        }
    }
    out
}

/// A shell word with its quotes removed but its spaces kept, for a here-string
/// body (`'rm -rf ~'` → `rm -rf ~`): the shell runs it as input.
fn dequote(word: &str) -> String {
    let mut out = String::with_capacity(word.len());
    let mut quote: Option<char> = None;
    let mut chars = word.chars();
    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else {
                    out.push(c);
                }
            }
            None => match c {
                '\'' | '"' => quote = Some(c),
                '\\' => {
                    if let Some(n) = chars.next() {
                        out.push(n);
                    }
                }
                _ => out.push(c),
            },
        }
    }
    out
}

fn push_segment(segments: &mut Vec<String>, cur: &mut String) {
    let s = cur.trim();
    if !s.is_empty() {
        segments.push(s.to_string());
    }
    cur.clear();
}

fn take_until(chars: &mut std::iter::Peekable<std::str::Chars>, end: char) -> String {
    let mut out = String::new();
    for c in chars.by_ref() {
        if c == end {
            break;
        }
        out.push(c);
    }
    out
}

/// Reads up to the matching close, honouring nesting of `open`/`close`.
fn take_until_balanced(
    chars: &mut std::iter::Peekable<std::str::Chars>,
    open: char,
    close: char,
) -> String {
    let mut out = String::new();
    let mut depth = 1;
    for c in chars.by_ref() {
        if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                break;
            }
        }
        out.push(c);
    }
    out
}

/// Splits one command (no separators) into words, honouring quotes. For a
/// POSIX shell a `\` before a blank joins it to the word and other
/// backslashes are resolved per word by [`unescape`]; for PowerShell a `\` is
/// an ordinary character (`C:\ -Recurse` is two words). Returns `None` only for
/// an empty line. A quote that is not closed is taken to the end, so a
/// half-written line still yields its words.
fn tokenize(segment: &str, shell: Shell) -> Option<Vec<String>> {
    let posix = shell == Shell::Posix;
    let finish = |w: &str| if posix { unescape(w) } else { w.to_string() };
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    let mut chars = segment.chars().peekable();
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else {
                cur.push(c);
            }
            continue;
        }
        match c {
            '\'' | '"' => {
                quote = Some(c);
                in_word = true;
            }
            '\\' if posix && matches!(chars.peek(), Some('\n' | '\r')) => {
                // A line continuation: the shell drops it, so the command
                // goes on as one (`docker run \` + `--privileged img`).
                if chars.next() == Some('\r') && chars.peek() == Some(&'\n') {
                    chars.next();
                }
            }
            '\\' if posix && chars.peek().is_some_and(|n| n.is_whitespace()) => {
                cur.push(chars.next().unwrap());
                in_word = true;
            }
            c if c.is_whitespace() => {
                if in_word {
                    words.push(finish(&std::mem::take(&mut cur)));
                    in_word = false;
                }
            }
            _ => {
                cur.push(c);
                in_word = true;
            }
        }
    }
    if in_word {
        words.push(finish(&cur));
    }
    Some(words)
}

/// A word with its POSIX backslash escapes resolved: a `\` before a shell
/// metacharacter or a blank is dropped (`\~` → `~`, `a\ b` → `a b`), but a
/// `\` before a letter or digit is kept, so a Windows path keeps its
/// separators (`C:\Windows\System32` stays).
fn unescape(word: &str) -> String {
    if !word.contains('\\') {
        return word.to_string();
    }
    let special = |c: char| c.is_whitespace() || " ;&|<>()$`\"'#*?[]{}~=,\\".contains(c);
    let mut out = String::with_capacity(word.len());
    let mut chars = word.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek().copied().is_some_and(special) {
            out.push(chars.next().unwrap());
        } else {
            out.push(c);
        }
    }
    out
}

/// Whether a wrapper's short flag takes a value as the next word (`nice -n 5`,
/// `sudo -u user`), so that value is dropped with it, not taken as the
/// command.
fn wrapper_value_flag(wrapper: &str, flag: u8) -> bool {
    let flags: &[u8] = match wrapper {
        "sudo" | "doas" => b"ughpCrtT",
        "nice" | "ionice" => b"nc",
        "env" => b"uCS",
        "xargs" => b"nPIisdELa",
        "stdbuf" => b"ioe",
        _ => b"",
    };
    flags.contains(&flag)
}

/// The base name of a program path, lower-cased, without `.exe`: `/bin/rm` →
/// `rm`, `C:\Windows\System32\cmd.exe` → `cmd`, `bash.exe` → `bash`.
fn base_name(word: &str) -> String {
    let w = word.rsplit(['/', '\\']).next().unwrap_or(word);
    let w = w.to_ascii_lowercase();
    match w.strip_suffix(".exe") {
        Some(b) if !b.is_empty() => b.to_string(),
        _ => w,
    }
}

/// The body a shell's `-c` carries. As in bash, the `c` may be anywhere in a
/// short-flag word (`-c`, `-lc`, `-ce`, `-xec`) and other options may follow
/// (`bash -c -e '…'`, `bash -c -- '…'`): the body is the first word that is
/// not an option. The words after it (`$0`, `$1`, …) are kept with it.
fn shell_c_body(rest: &[String]) -> Option<String> {
    let mut have_c = false;
    let mut i = 0;
    while i < rest.len() {
        let w = rest[i].as_str();
        if w == "--" {
            i += 1;
            break;
        }
        if let Some(long) = w.strip_prefix("--") {
            // `--login`, `--norc`, `--rcfile <file>`.
            i += if long == "rcfile" || long == "init-file" {
                2
            } else {
                1
            };
            continue;
        }
        let flags = w.strip_prefix('-').or_else(|| w.strip_prefix('+'));
        match flags {
            Some(f) if !f.is_empty() && f.bytes().all(|b| b.is_ascii_alphabetic()) => {
                if f.contains('c') {
                    have_c = true;
                }
                // `-o pipefail`, `-O extglob`: the option's name follows.
                i += if f.ends_with('o') || f.ends_with('O') {
                    2
                } else {
                    1
                };
            }
            _ => break,
        }
    }
    (have_c && i < rest.len()).then(|| rest[i..].join(" "))
}

/// The command `cmd /c …` or `cmd /k …` runs: the words after the switch.
/// One word is the whole command (`cmd /c "rd /s /q C:\"`: cmd drops the
/// outer quotes); of several, one with a blank in it keeps its quotes, as
/// cmd sees them (`cmd /c rd /s "C:\Users\Max Mustermann\build"`).
fn cmd_c_body(rest: &[String]) -> Option<String> {
    let i = rest.iter().position(|w| {
        let l = w.to_ascii_lowercase();
        l == "/c" || l == "/k" || l == "/r"
    })?;
    match &rest[i + 1..] {
        [] => None,
        [one] => Some(one.clone()),
        words => Some(
            words
                .iter()
                .map(|w| {
                    if w.chars().any(char::is_whitespace) {
                        format!("\"{w}\"")
                    } else {
                        w.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join(" "),
        ),
    }
}

/// The program `Start-Process` or `start` runs, with the words after it:
/// the value of `-FilePath` (or its alias `-Path`), else the first word that
/// is not a parameter, its value, or one of cmd's `/wait`-style switches or
/// an empty window title (`start "" diskpart`).
fn started_program(rest: &[String]) -> Option<Vec<String>> {
    let mut i = 0;
    while i < rest.len() {
        let w = &rest[i];
        let lower = w.to_ascii_lowercase();
        if let Some(param) = lower.strip_prefix('-').filter(|p| !p.is_empty()) {
            let (name, inline) = match param.split_once(':') {
                Some((n, _)) => (n, Some(&w[n.len() + 2..])),
                None => (param, None),
            };
            let file = !name.is_empty()
                && ("filepath".starts_with(name) || name == "path" || name == "pspath");
            if file {
                return match inline {
                    Some(v) => Some(
                        std::iter::once(v.to_string())
                            .chain(rest[i + 1..].iter().cloned())
                            .collect(),
                    ),
                    None => (i + 1 < rest.len()).then(|| rest[i + 1..].to_vec()),
                };
            }
            let switch = START_SWITCHES.iter().any(|s| s.starts_with(name));
            i += if switch || inline.is_some() { 1 } else { 2 };
            continue;
        }
        let cmd_switch = lower
            .strip_prefix('/')
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphabetic()));
        if let Some(s) = cmd_switch {
            // `/d <folder>` takes the folder.
            i += if s == "d" { 2 } else { 1 };
            continue;
        }
        if w.is_empty() {
            i += 1;
            continue;
        }
        return Some(rest[i..].to_vec());
    }
    None
}

/// The command `powershell -Command …` runs, with `-Command` written in full or
/// shortened (`-c`, `-com`, …), or as `-Command:…`. An `-EncodedCommand`
/// (base64) is not decoded; that limit is in the docs.
fn powershell_body(rest: &[String]) -> Option<String> {
    for (i, w) in rest.iter().enumerate() {
        let lower = w.to_ascii_lowercase();
        let (name, inline) = match lower.split_once(':') {
            Some((n, _)) => (n.to_string(), Some(w[n.len() + 1..].to_string())),
            None => (lower.clone(), None),
        };
        let is_command =
            name.len() >= 2 && name.starts_with('-') && "-command".starts_with(name.as_str());
        if is_command {
            if let Some(v) = inline {
                return Some(v);
            }
            return (i + 1 < rest.len()).then(|| rest[i + 1..].join(" "));
        }
    }
    None
}

/// Expands a combined short-flag word into one flag each: `-rf` → `-r`, `-f`.
/// A long flag (`--force`), a `-` alone, or anything that is not a run of
/// letters stays as it is.
fn expand_flags(word: &str) -> Vec<String> {
    let is_combined = word.len() > 2
        && word.starts_with('-')
        && !word.starts_with("--")
        && word[1..].bytes().all(|b| b.is_ascii_alphanumeric());
    if is_combined {
        word[1..].chars().map(|c| format!("-{c}")).collect()
    } else {
        vec![word.to_string()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The programs the text splitter reads in `line`, in order: the tests
    /// of its reading. What the parser adds is tested on its own.
    fn progs(line: &str) -> Vec<String> {
        walk(line, Shell::Posix)
            .commands
            .into_iter()
            .map(|c| c.program)
            .collect()
    }

    #[test]
    fn plain_command() {
        let c = commands("rm -rf ./build");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].program, "rm");
        assert_eq!(c[0].operands(), ["./build"]);
        assert_eq!(c[0].short_flags(), ['r', 'f']);
    }

    #[test]
    fn combined_flags_in_any_order_look_the_same() {
        for line in ["rm -rf x", "rm -fr x", "rm -r -f x", "rm -f -r x"] {
            let c = commands(line);
            let mut f = c[0].short_flags();
            f.sort_unstable();
            assert_eq!(f, ['f', 'r'], "{line}");
        }
    }

    #[test]
    fn long_flags_count_as_the_same_intent() {
        let c = commands("rm --recursive --force /x");
        assert_eq!(c[0].long_flags(), ["recursive", "force"]);
    }

    #[test]
    fn base_name_of_an_absolute_program() {
        assert_eq!(commands("/bin/rm -rf /")[0].program, "rm");
        assert_eq!(commands("/usr/bin/RM x")[0].program, "rm");
        assert_eq!(commands("bash.exe -c x")[0].program, "bash");
    }

    #[test]
    fn a_windows_path_keeps_its_backslashes() {
        let c = commands(r"Remove-Item C:\Windows\System32 -Recurse");
        assert_eq!(c[0].program, "remove-item");
        assert_eq!(c[0].operands(), [r"C:\Windows\System32"]);
        assert_eq!(c[0].line(), r"remove-item c:\windows\system32 -recurse");
    }

    /// An argument with a blank in it stays one operand on the line a
    /// `cmd-re:` reads (review r5, finding 1).
    #[test]
    fn an_argument_with_a_blank_is_quoted_on_the_line() {
        let c = parse(
            r#"Remove-Item "C:\Users\Max Mustermann\build" -Recurse"#,
            Shell::PowerShell,
        );
        assert_eq!(
            c.commands[0].line(),
            r#"remove-item "c:\users\max mustermann\build" -recurse"#
        );
        let c = parse(
            r#"cmd /c rd /s /q "C:\Users\Max Mustermann\build""#,
            Shell::PowerShell,
        );
        assert_eq!(
            c.commands[1].line(),
            r#"rd /s /q "c:\users\max mustermann\build""#
        );
    }

    /// The program `Start-Process` or `start` runs is a command of its own
    /// (review r5, finding 4).
    #[test]
    fn a_started_program_is_a_command() {
        for (line, program) in [
            ("Start-Process diskpart -Verb RunAs", "diskpart"),
            (
                r"Start-Process -Verb RunAs -FilePath C:\Windows\System32\bcdedit.exe",
                "bcdedit",
            ),
            ("saps -FilePath:diskpart -Wait", "diskpart"),
            ("Start-Process -Wait -NoNewWindow notepad x.txt", "notepad"),
            ("start \"\" /wait /d C:\\tmp diskpart", "diskpart"),
        ] {
            let progs: Vec<String> = parse(line, Shell::PowerShell)
                .commands
                .into_iter()
                .map(|c| c.program)
                .collect();
            assert!(progs.iter().any(|p| p == program), "{line}: {progs:?}");
        }
    }

    /// A PowerShell here-string's lines are commands, but a quote in one
    /// (an apostrophe) ends with its line, so the commands after the
    /// here-string are seen (review r5, finding 2).
    #[test]
    fn a_quote_in_a_powershell_here_string_ends_with_its_line() {
        let progs = |line: &str| -> Vec<String> {
            walk(line, Shell::PowerShell)
                .commands
                .into_iter()
                .map(|c| c.program)
                .collect()
        };
        let p = progs("Set-Content n.md @'\nDon't run this\n'@\ngit status");
        assert_eq!(p.first().map(String::as_str), Some("set-content"));
        assert_eq!(p.last().map(String::as_str), Some("git"));
        let p = progs("@\"\nIt's $x\n\"@ | Set-Content n.md; git status");
        assert!(p.contains(&"set-content".to_string()), "{p:?}");
        assert_eq!(p.last().map(String::as_str), Some("git"));
        // A quote across lines outside a here-string still spans them, and
        // an `@'` inside it opens none.
        let p = progs("Write-Host \"a\nb @'\nc\"; git status");
        assert_eq!(p, ["write-host", "git"]);
    }

    #[test]
    fn separators_split_into_commands() {
        assert_eq!(progs("git status; rm -rf x"), ["git", "rm"]);
        assert_eq!(progs("a && b || c"), ["a", "b", "c"]);
        assert_eq!(progs("cat f | grep x | wc -l"), ["cat", "grep", "wc"]);
        assert_eq!(progs("make &\nrm -rf /"), ["make", "rm"]);
    }

    #[test]
    fn a_separator_inside_quotes_does_not_split() {
        let c = commands("echo 'a; b' && ls");
        assert_eq!(progs("echo 'a; b' && ls"), ["echo", "ls"]);
        assert_eq!(c[0].operands(), ["a; b"]);
    }

    #[test]
    fn wrappers_are_stripped() {
        assert_eq!(progs("sudo rm -rf /"), ["rm"]);
        assert_eq!(progs("env FOO=bar nohup rm x"), ["rm"]);
        assert_eq!(progs("time nice -n 5 make"), ["make"]);
        let c = commands("sudo rm -rf /");
        assert_eq!(c[0].program, "rm");
        assert_eq!(c[0].short_flags(), ['r', 'f']);
    }

    #[test]
    fn a_nested_shell_body_is_pulled_apart() {
        assert_eq!(progs("sh -c 'rm -rf /'"), ["sh", "rm"]);
        assert_eq!(
            progs("bash -c \"git pull && rm -rf ~\""),
            ["bash", "git", "rm"]
        );
        assert_eq!(
            progs("powershell -Command \"Remove-Item x\""),
            ["powershell", "remove-item"]
        );
    }

    /// `c` anywhere in a `-c` flag word, and other options around it, still
    /// hand the body over (review r1 and r2, finding 4).
    #[test]
    fn shell_c_bodies_are_found_in_every_form() {
        for line in [
            "bash -lc 'rm -rf /'",
            "sh -xec 'mkfs.ext4 /dev/sda'",
            "bash -ec 'git pull'",
            "bash -ce 'git pull'",
            "sh -cx 'git pull'",
            "bash -c -e 'git pull'",
            "bash -c -- 'git pull'",
            "bash -o pipefail -c 'git pull'",
        ] {
            assert!(
                commands(line)
                    .iter()
                    .any(|c| c.program == "git" || c.program == "rm" || c.program == "mkfs.ext4"),
                "no inner command from {line:?}"
            );
        }
    }

    /// cmd's `/c` and PowerShell's shortened `-c`/`-Command:` bodies.
    #[test]
    fn cmd_and_powershell_bodies() {
        assert_eq!(progs("cmd /c rd /s /q C:\\"), ["cmd", "rd"]);
        assert_eq!(progs("cmd.exe /c \"del x\""), ["cmd", "del"]);
        assert_eq!(progs("pwsh -c \"Remove-Item x\""), ["pwsh", "remove-item"]);
        assert_eq!(
            progs("powershell -Command:Get-ChildItem"),
            ["powershell", "get-childitem"]
        );
    }

    /// Subshells, groups and keywords do not become the program.
    #[test]
    fn groups_and_keywords_are_seen_through() {
        assert_eq!(progs("(rm -rf ~)"), ["rm"]);
        assert_eq!(progs("( rm -rf ~ )"), ["rm"]);
        assert_eq!(progs("{ rm -rf ~; }"), ["rm"]);
        assert_eq!(progs("if true; then rm -rf ~; fi"), ["true", "rm"]);
        assert_eq!(progs("for i in 1; do rm -rf ~; done"), ["for", "rm"]);
        assert_eq!(progs("! rm -rf ~"), ["rm"]);
        assert_eq!(progs("(cd / && chmod -R 777 /)"), ["cd", "chmod"]);
    }

    #[test]
    fn command_substitution_is_pulled_apart() {
        assert_eq!(progs("echo $(rm -rf /)"), ["echo", "rm"]);
        assert_eq!(progs("echo `rm -rf /`"), ["echo", "rm"]);
        assert_eq!(progs("echo \"`rm -rf /`\""), ["echo", "rm"]);
        assert_eq!(progs("cat <(rm -rf /)"), ["cat", "rm"]);
    }

    /// The lines of a here-document are commands like any other line,
    /// whether it is fed to a shell or written to a file (as before review
    /// r2; the owner's decision of 2026-10-18). A here-string fed to a shell
    /// is a script too.
    #[test]
    fn heredocs_and_herestrings() {
        assert_eq!(progs("bash <<'EOF'\nrm -rf /\nEOF"), ["bash", "rm", "eof"]);
        assert_eq!(
            progs("cat <<'EOF' | sh\nrm -rf /\nEOF"),
            ["cat", "sh", "rm", "eof"]
        );
        assert_eq!(
            progs("cat > clean.sh <<'EOF'\nrm -rf /\nEOF"),
            ["cat", "rm", "eof"]
        );
        assert!(
            commands("cat > out <<EOF\n$(rm -rf /)\nEOF")
                .iter()
                .any(|c| c.program == "rm")
        );
        assert_eq!(progs("bash <<< 'rm -rf /'"), ["bash", "rm"]);
        // A here-string not fed to a shell stays the command's argument.
        let c = commands("grep -c x <<< 'a b'");
        assert_eq!(progs("grep -c x <<< 'a b'"), ["grep"]);
        assert_eq!(c[0].operands(), ["x", "<<<", "a b"]);
    }

    /// A `#` at the start of a word starts a comment to the end of its line:
    /// what is in it (an apostrophe, a `<<`) does not change how the next
    /// lines are read, and a `#` inside a word is not one.
    #[test]
    fn a_comment_runs_to_the_end_of_its_line() {
        assert_eq!(progs("# don't forget the cache\ngit status"), ["git"]);
        assert_eq!(
            progs("make # see the notes <<here\ngit status"),
            ["make", "git"]
        );
        assert_eq!(progs("ls;# it's done\npwd"), ["ls", "pwd"]);
        assert_eq!(commands("echo a#b")[0].operands(), ["a#b"]);
        assert_eq!(commands("echo '# kept'")[0].operands(), ["# kept"]);
        assert_eq!(
            parse("# a note\r\nGet-ChildItem", Shell::PowerShell)
                .commands
                .iter()
                .map(|c| c.program.as_str())
                .collect::<Vec<_>>(),
            ["get-childitem"]
        );
    }

    /// PowerShell's rules for a Windows node: a backtick in double quotes is
    /// its escape (`` `n ``), not a substitution, and a backslash is an
    /// ordinary character, so a path such as `C:\` stays a word of its own.
    #[test]
    fn a_powershell_line_is_read_by_powershells_rules() {
        let ps = |line: &str| -> Vec<String> {
            walk(line, Shell::PowerShell)
                .commands
                .into_iter()
                .map(|c| c.program)
                .collect()
        };
        assert_eq!(
            ps("Write-Host \"done`n\"; Get-ChildItem"),
            ["write-host", "get-childitem"]
        );
        assert_eq!(
            ps(r#"Set-Location "C:\"; Get-ChildItem"#),
            ["set-location", "get-childitem"]
        );
        let c = parse(r"Remove-Item C:\ -Recurse -Force", Shell::PowerShell).commands;
        assert_eq!(c[0].raw, [r"C:\", "-Recurse", "-Force"]);
        // A POSIX shell inside keeps its own rules.
        assert_eq!(ps("bash -c 'echo \"`date`\"'"), ["bash", "echo", "date"]);
        assert_eq!(Shell::for_os("windows"), Shell::PowerShell);
        assert_eq!(Shell::for_os("linux"), Shell::Posix);
        assert_eq!(Shell::for_os("freebsd"), Shell::Posix);
    }

    /// A quote opened on a here-document's body line (an apostrophe in
    /// prose, a Rust lifetime, a lone `"` or backtick) ends with that line,
    /// so the commands after the document are still seen (review r4,
    /// finding 1). Outside a body a quoted string still spans lines.
    #[test]
    fn a_quote_in_a_heredoc_body_ends_with_its_line() {
        for line in [
            "cat > notes.md <<'EOF'\nDon't run this on prod.\nEOF\nrm -rf ~",
            "git commit -F - <<'EOF'\nFix the parser's crash\nEOF\nrm -rf ~",
            "cat > lib.rs <<'EOF'\nfn f<'a>(x: &'a str) -> &'a str { x }\nEOF\nrm -rf ~",
            "cat > a.txt <<EOF\nA 12\" screen\nEOF\nrm -rf ~",
            "cat > a.md <<EOF\nSay \"don't\nEOF\nrm -rf ~",
            "cat > a.md <<-EOF\n\tPress the ` key\n\tEOF\nrm -rf ~",
            "cat > a.md <<\\EOF\r\nIt's done.\r\nEOF\r\nrm -rf ~",
            "cat <<A >a <<B\nit's\nA\nit's\nB\nrm -rf ~",
        ] {
            let c = commands(line);
            assert!(
                c.iter().any(|c| c.program == "rm" && c.operands() == ["~"]),
                "{line:?}: {c:?}"
            );
        }
        assert_eq!(
            progs("cat <<EOF\nit's\nEOF\necho 'a\nb; c' && ls"),
            ["cat", "its", "eof", "echo", "ls"]
        );
        assert_eq!(progs("echo 'a\nb; c' && ls"), ["echo", "ls"]);
        // A body line keeps its own quoted words.
        let c = commands("cat > x.sh <<'EOF'\necho 'a; b' 'c\nEOF");
        assert_eq!(c[1].operands(), ["a; b", "c"]);
    }

    /// A `\` at a line's end continues the command on the next line, as in
    /// the shell, also before a CRLF.
    #[test]
    fn a_line_continuation_joins_the_command() {
        let c = commands("docker run \\\n  --privileged img");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].raw, ["run", "--privileged", "img"]);
        let c = commands("docker run \\\r\n  --privileged img");
        assert_eq!(c[0].raw, ["run", "--privileged", "img"]);
    }

    #[test]
    fn a_half_written_quote_still_yields_words() {
        let c = commands("rm -rf 'x");
        assert_eq!(c[0].program, "rm");
        assert_eq!(c[0].operands(), ["x"]);
    }

    /// A line nested past the depth bound is reported as overflow instead of
    /// recursing without end (review r1, finding 1).
    #[test]
    fn deep_nesting_is_bounded_not_a_stack_overflow() {
        let bomb = format!("echo {}", "$(".repeat(100_000));
        assert_eq!(parse(&bomb, Shell::Posix).overflow, Some(Overflow::Depth));
        let ok = parse("echo $(printf '%s' $(date))", Shell::Posix);
        assert_eq!(ok.overflow, None);
        assert!(ok.commands.iter().any(|c| c.program == "date"));
    }

    /// A line of nothing but starters (`start start …`) stops at the depth
    /// bound instead of recursing once per word, which overflowed the stack
    /// of a 2 MiB thread such as a tokio worker and aborted the center
    /// (review r6, finding 1). A short chain is still read through.
    #[test]
    fn a_chain_of_starters_is_bounded_not_a_stack_overflow() {
        let run = || {
            for (word, shell) in [
                ("start", Shell::Posix),
                ("saps", Shell::PowerShell),
                ("Start-Process", Shell::PowerShell),
            ] {
                let chain = vec![word; 6000].join(" ");
                let p = parse(&chain, shell);
                assert_eq!(p.overflow, Some(Overflow::Depth), "{word}");
                assert!(p.commands.len() <= MAX_DEPTH + 1, "{word}");
            }
            let short = parse("start start Start-Process diskpart", Shell::PowerShell);
            assert_eq!(short.overflow, None);
            assert!(short.commands.iter().any(|c| c.program == "diskpart"));
        };
        std::thread::Builder::new()
            .stack_size(2 * 1024 * 1024)
            .spawn(run)
            .unwrap()
            .join()
            .unwrap();
    }

    /// A line with a huge number of commands overflows on the command bound,
    /// but an ordinary long script does not (review r2, finding 3).
    #[test]
    fn the_command_bound_catches_only_abuse() {
        let many = vec!["true"; MAX_COMMANDS + 50].join(";");
        let p = parse(&many, Shell::Posix);
        assert_eq!(p.overflow, Some(Overflow::Commands));
        assert!(p.commands.len() <= MAX_COMMANDS);
        let script = (0..500)
            .map(|i| format!("echo {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(parse(&script, Shell::Posix).overflow, None);
    }
}
