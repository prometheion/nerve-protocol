//! Splitting a command line into the commands it runs, as the node's shell
//! reads it (docs/dev/policy-engine.md, the guard).
//!
//! [`parse`] takes a line apart by the rules of [`Shell`]: into commands at
//! `;`, `&`, `&&`, `||`, `|` and line breaks, with groups, subshells and
//! PowerShell blocks, and into words with their quotes and escapes taken off.
//! What runs inside a command runs as a command of its own and is kept with
//! it ([`Command::inner`]): `$( … )`, backticks, `<( … )`, PowerShell's
//! `( … )`, `$( … )` and `{ … }`, and the text a shell is given to run
//! (`sh -c '…'`, `powershell -Command …`, `cmd /c …`, `eval`,
//! `Invoke-Expression`, a here-document fed to a shell).
//!
//! It is a reader for a mistake guard, not a shell: it reads what agents
//! write (lists, pipes, `if`/`for`/`while`/`case`, functions, here-documents)
//! and gives up on the rest. A line it cannot read with confidence (a quote
//! or bracket left open, a shell that reads its script from a pipe, a bound
//! hit) is [`Unparsed`], which carries the commands read until then; the
//! guard checks those and the whole line with its text patterns, so nothing
//! gets past that they caught.
//!
//! The walk is bounded: nesting (brackets, substitutions and the text a shell
//! runs, all together) at [`MAX_DEPTH`], the number of commands at
//! [`MAX_COMMANDS`], and the characters read (a text a shell runs is read
//! again) at [`MAX_WORK`]. A hostile line costs no more than that, and past
//! a bound it is [`Unparsed`].

use std::cell::Cell;

/// The deepest nesting the reader descends. Real lines nest a few levels.
pub const MAX_DEPTH: usize = 16;
/// The most commands one line may hold. A 64 KiB line (the node's limit,
/// [`crate::COMMAND_MAX_BYTES`]) of one-letter commands holds about 32 000;
/// anything a person or an agent writes is far below this.
pub const MAX_COMMANDS: usize = 10_000;
/// The most characters the reader takes, counting a text a shell runs again
/// for each level it is nested in.
pub const MAX_WORK: usize = 1 << 21;

/// The shell a command line is read for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    /// `sh`, `bash` and the like: `\` escapes, `'…'` is literal, `"…"`
    /// expands `$( … )` and backticks.
    Sh,
    /// fish: read like `sh`, but `( … )` is a command substitution, and
    /// `and`, `or`, `not`, `begin` and `end` are keywords.
    Fish,
    /// Windows PowerShell or PowerShell 7: a backtick escapes, `\` is a path
    /// separator, and `( … )`, `$( … )` and `{ … }` hold commands.
    PowerShell,
    /// cmd: `^` escapes, and `"…"` quotes without escapes.
    Cmd,
}

impl Shell {
    /// The shell `program` is, as the node picks the flag it runs a line
    /// with (nerve-node `exec::shell_command`).
    pub fn of_program(program: &str) -> Shell {
        let lower = program.to_lowercase();
        if lower.contains("powershell") || lower.contains("pwsh") {
            Shell::PowerShell
        } else if lower.ends_with("cmd.exe") || lower == "cmd" {
            Shell::Cmd
        } else if base_name(program, false) == "fish" {
            Shell::Fish
        } else {
            Shell::Sh
        }
    }

    /// `sh` or a shell read like it.
    fn posix(self) -> bool {
        matches!(self, Shell::Sh | Shell::Fish)
    }

    /// The shell a node runs a command in when none is set: PowerShell on
    /// Windows, `/bin/sh` everywhere else.
    pub fn native() -> Shell {
        if cfg!(windows) {
            Shell::PowerShell
        } else {
            Shell::Sh
        }
    }

    /// Whether program names are compared without case and `\` separates a
    /// path's parts, as on Windows: in PowerShell and cmd, and in any shell
    /// on a Windows node.
    pub fn windows(self) -> bool {
        !self.posix() || cfg!(windows)
    }
}

/// One word of a command, as the program gets it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Word {
    /// The word with its quotes and escapes taken off. A variable or a
    /// substitution stays as written (`$HOME`, `$(pidof x)`): the reader
    /// does not know what it holds.
    pub text: String,
    /// No variable, substitution or block in it: `text` is exactly what the
    /// program gets.
    pub literal: bool,
    /// Some of it was quoted or escaped.
    pub quoted: bool,
}

/// One command: its words, and what runs inside it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Command {
    /// The words in order, the shell's keywords, assignments and wrappers
    /// (`if`, `X=1`, `sudo`) included.
    pub words: Vec<Word>,
    /// The targets of its redirections (`> file`, `2>> log`).
    pub redirects: Vec<Word>,
    /// The text it reads as its input: here-documents and here-strings.
    pub input: Vec<String>,
    /// What runs as a part of it: its substitutions and blocks, the body of
    /// a group or subshell, and the text it runs as a shell.
    pub inner: Vec<Script>,
    /// It reads the output of the command before it (`a | b`).
    pub piped: bool,
}

/// The commands of a line (or of a part of one) in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Script {
    pub commands: Vec<Command>,
    /// The shell the text was read as: a text a shell runs is read by that
    /// shell's rules, whatever the line around it is.
    pub shell: Shell,
}

impl Script {
    pub fn new(shell: Shell) -> Script {
        Script {
            commands: Vec::new(),
            shell,
        }
    }

    /// Calls `f` with every command, at any depth: the script it stands in
    /// and its place there, so `f` can look at the pipe it is in.
    pub fn visit<'s, F: FnMut(&'s Script, usize)>(&'s self, f: &mut F) {
        for (i, c) in self.commands.iter().enumerate() {
            f(self, i);
            for s in &c.inner {
                s.visit(f);
            }
        }
    }
}

/// Why a line could not be read with confidence, and the commands read
/// before it came to that. The caller checks them as it checks a line it
/// read whole: they are commands of the line, and what is wrong further on
/// does not make them harmless.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unparsed {
    pub why: &'static str,
    /// The commands read up to the place that could not be read, nested as
    /// the line nests them; the command it came to is among them as far as
    /// it was read.
    pub read: Script,
}

impl Unparsed {
    fn because(why: &'static str) -> Unparsed {
        Unparsed {
            why,
            read: Script::new(Shell::Sh),
        }
    }

    /// The error with `subs`, the substitutions of a word read before it
    /// gave out, kept among what was read.
    fn with_subs(mut self, subs: Vec<Script>, shell: Shell) -> Unparsed {
        if !subs.is_empty() {
            if self.read.commands.is_empty() {
                self.read.shell = shell;
            }
            self.read.commands.insert(
                0,
                Command {
                    inner: subs,
                    ..Command::default()
                },
            );
        }
        self
    }
}

/// Takes `line` apart by the rules of `shell`.
pub fn parse(line: &str, shell: Shell) -> Result<Script, Unparsed> {
    let budget = Budget::default();
    let read = Parser::new(line, shell, 0, &budget).list(None);
    if budget.blown.get() {
        return Err(Unparsed {
            why: "the line is longer or deeper than the guard reads",
            read: match read {
                Ok(script) => script,
                Err(e) => e.read,
            },
        });
    }
    read
}

#[derive(Default)]
struct Budget {
    work: Cell<usize>,
    commands: Cell<usize>,
    /// [`MAX_WORK`] was reached: the reader saw an end there that is not
    /// the line's.
    blown: Cell<bool>,
}

enum Tok {
    Word(Word, Vec<Script>),
    /// `;`, `&`, `&&`, `||` or a line break.
    Sep,
    /// `|`.
    Pipe,
    /// A redirection; `true` when a target follows (`2>&1` has none).
    Redirect(bool),
    /// `<<` (`true`: `<<-`, which strips leading tabs).
    HereDoc(bool),
    /// `<<<`.
    HereString,
    /// `(` that opens a group or subshell (sh, cmd).
    Open,
    /// The bracket that closes what [`Parser::list`] reads.
    Close(char),
    End,
}

struct Parser<'b> {
    s: Vec<char>,
    i: usize,
    shell: Shell,
    depth: usize,
    budget: &'b Budget,
    /// Where reading goes on at the end of the current line: past the
    /// bodies of the here-documents it opened (sh).
    resume: Option<usize>,
    /// How many `case … esac` the reader is in (sh): there a pattern ends
    /// at `)` and its branch at `;;`.
    cases: usize,
    /// How many `$(( … ))` and `(( … ))` the reader is in (sh): there `<<` is
    /// a shift, not a here-document.
    arith: usize,
}

/// Whether `w` is a word a command may start with before its own words: a
/// keyword of sh, or one that is followed by brackets or a `case`.
fn leads(w: &Word) -> bool {
    !w.quoted
        && (SH_KEYWORDS.contains(&w.text.as_str())
            || matches!(w.text.as_str(), "for" | "select" | "time" | "coproc"))
}

/// The shells that run a `-c` text or their input as sh.
const SH: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "yash", "fish",
];

impl<'b> Parser<'b> {
    fn new(text: &str, shell: Shell, depth: usize, budget: &'b Budget) -> Parser<'b> {
        Parser {
            s: text.chars().collect(),
            i: 0,
            shell,
            depth,
            budget,
            resume: None,
            cases: 0,
            arith: 0,
        }
    }

    /// The next character; none once the budget is spent, so every loop
    /// that reads on ends there.
    fn peek(&self) -> Option<char> {
        self.peek_at(0)
    }

    fn peek_at(&self, n: usize) -> Option<char> {
        if self.budget.blown.get() {
            return None;
        }
        self.s.get(self.i + n).copied()
    }

    /// Takes the next character. Past [`MAX_WORK`] the line ends here, and
    /// [`parse`] reports it.
    fn bump(&mut self) -> Option<char> {
        if !self.charge(1) {
            return None;
        }
        let c = self.peek()?;
        self.i += 1;
        Some(c)
    }

    fn charge(&self, n: usize) -> bool {
        let w = self.budget.work.get() + n;
        self.budget.work.set(w);
        if w > MAX_WORK {
            self.budget.blown.set(true);
        }
        !self.budget.blown.get()
    }

    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(c) {
            self.bump();
            true
        } else {
            false
        }
    }

    /// Whether the text at the reader starts with `word` (any case),
    /// followed by a blank or the line's end.
    fn at_word(&self, word: &str) -> bool {
        let n = word.chars().count();
        let here: String = self.s[self.i..].iter().take(n).collect();
        here.eq_ignore_ascii_case(word)
            && matches!(self.peek_at(n), None | Some(' ' | '\t' | '\r' | '\n'))
    }

    fn skip_line(&mut self) {
        while !matches!(self.peek(), None | Some('\n')) {
            self.bump();
        }
    }

    fn raw(&self, from: usize) -> String {
        self.s[from..self.i].iter().collect()
    }

    /// Reads `text` as a script one level down, with this line's budget.
    fn nested(&self, text: &str, shell: Shell) -> Result<Script, Unparsed> {
        Parser::new(text, shell, self.depth, self.budget).list(None)
    }

    /// Reads commands up to `close` (or the end of the text). When the text
    /// cannot be read, the error carries what was read until then.
    fn list(&mut self, close: Option<char>) -> Result<Script, Unparsed> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(Unparsed::because(
                "the line nests deeper than the guard reads",
            ));
        }
        // A `case` of this list ends in this list: a `)` after its patterns
        // is not the one that closes a group around it.
        let outer_cases = std::mem::take(&mut self.cases);
        let mut script = Script::new(self.shell);
        let mut cmd = Command::default();
        let mut piped = false;
        let read = self.commands(close, &mut script, &mut cmd, &mut piped);
        self.cases = outer_cases;
        match read {
            Ok(()) => {
                self.depth -= 1;
                Ok(script)
            }
            Err(mut e) => {
                // What a list below read is a part of the command that was
                // being read here.
                if !e.read.commands.is_empty() {
                    let below = std::mem::replace(&mut e.read, Script::new(self.shell));
                    cmd.inner.push(below);
                }
                if !cmd.words.is_empty()
                    || !cmd.inner.is_empty()
                    || !cmd.redirects.is_empty()
                    || !cmd.input.is_empty()
                {
                    // The command comes with the text it runs and the pipe
                    // it stands in, as far as they were read.
                    cmd.piped = piped;
                    let _ = self.read_bodies(&mut cmd);
                    script.commands.push(cmd);
                }
                e.read = script;
                Err(e)
            }
        }
    }

    fn commands(
        &mut self,
        close: Option<char>,
        script: &mut Script,
        cmd: &mut Command,
        piped: &mut bool,
    ) -> Result<(), Unparsed> {
        loop {
            // A command starts where its first word can: after a PowerShell
            // assignment too (`$r = & prog`).
            let start = cmd.words.is_empty()
                || (self.shell == Shell::PowerShell
                    && cmd.words.len() == 2
                    && cmd.words[0].text.starts_with('$')
                    && is_ps_assign(&cmd.words[1].text));
            match self.token(start, close)? {
                Tok::End => {
                    if close.is_some() && !self.budget.blown.get() {
                        return Err(Unparsed::because(
                            "a bracket or a substitution is not closed",
                        ));
                    }
                    break;
                }
                Tok::Close(c) => {
                    if self.cases > 0 && c == ')' {
                        // A `case` pattern: its words are not a command,
                        // but a substitution in it runs.
                        cmd.words.clear();
                        cmd.redirects.clear();
                        cmd.input.clear();
                        continue;
                    }
                    if close == Some(c) {
                        break;
                    }
                    return Err(Unparsed::because("a bracket closes that was not opened"));
                }
                Tok::Sep => self.finish(script, cmd, piped, false)?,
                Tok::Pipe => self.finish(script, cmd, piped, true)?,
                Tok::Word(w, subs) => {
                    let mut header = false;
                    if self.shell == Shell::Sh && !w.quoted {
                        let lead = cmd.words.iter().take_while(|w| leads(w)).count();
                        if lead == cmd.words.len() {
                            match w.text.as_str() {
                                "case" => self.cases += 1,
                                "esac" => self.cases = self.cases.saturating_sub(1),
                                _ => {}
                            }
                        }
                        // `case WORD in` is a command of its own: the
                        // patterns after it are not its words.
                        header = w.text == "in"
                            && cmd.words.len() == lead + 2
                            && cmd.words[lead].text == "case"
                            && !cmd.words[lead].quoted;
                    }
                    cmd.words.push(w);
                    cmd.inner.extend(subs);
                    if header {
                        self.finish(script, cmd, piped, false)?;
                    }
                }
                Tok::Redirect(false) => {}
                Tok::Redirect(true) => {
                    let (w, subs) = self.target(close)?;
                    cmd.redirects.push(w);
                    cmd.inner.extend(subs);
                }
                Tok::HereString => {
                    let (w, subs) = self.target(close)?;
                    cmd.input.push(w.text);
                    cmd.inner.extend(subs);
                }
                Tok::HereDoc(strip) => self.here_doc(strip, close, cmd)?,
                Tok::Open => {
                    if self.shell == Shell::Sh && !cmd.words.is_empty() {
                        // `name()` defines a function: the name is not a
                        // command, and the body follows as commands.
                        while matches!(self.peek(), Some(' ' | '\t')) {
                            self.bump();
                        }
                        if self.eat(')') {
                            *cmd = Command::default();
                            continue;
                        }
                        let mut inner = self.group(self.peek() == Some('('))?;
                        if !cmd.words.iter().all(leads) {
                            // After a word the brackets hold an array
                            // (`a=(x y)`) or a regular expression: the
                            // words in them are data, a substitution in
                            // them runs. After `if`, `while`, `for` and the
                            // like they are a subshell.
                            for c in &mut inner.commands {
                                c.words.clear();
                                c.redirects.clear();
                                c.input.clear();
                            }
                        }
                        cmd.inner.push(inner);
                        continue;
                    }
                    let inner = self.group(self.shell.posix() && self.peek() == Some('('))?;
                    cmd.inner.push(inner);
                }
            }
        }
        self.finish(script, cmd, piped, false)
    }

    /// The commands of a group up to its `)`; `arith`: it is `((`, where
    /// `<<` shifts.
    fn group(&mut self, arith: bool) -> Result<Script, Unparsed> {
        if arith {
            self.arith += 1;
        }
        let read = self.list(Some(')'));
        if arith {
            self.arith -= 1;
        }
        read
    }

    /// The word after a redirection or `<<<`.
    fn target(&mut self, close: Option<char>) -> Result<(Word, Vec<Script>), Unparsed> {
        match self.token(false, close)? {
            Tok::Word(w, subs) => Ok((w, subs)),
            _ => Err(Unparsed::because("a redirection has no target")),
        }
    }

    /// Ends `cmd` and puts it on `script`; `pipe`: the next command reads
    /// its output.
    fn finish(
        &mut self,
        script: &mut Script,
        cmd: &mut Command,
        piped: &mut bool,
        pipe: bool,
    ) -> Result<(), Unparsed> {
        if cmd.words.is_empty()
            && cmd.inner.is_empty()
            && cmd.redirects.is_empty()
            && cmd.input.is_empty()
        {
            // A line break after `|` or `&&` goes on with the same pipe.
            return Ok(());
        }
        let n = self.budget.commands.get() + 1;
        self.budget.commands.set(n);
        if n > MAX_COMMANDS {
            return Err(Unparsed::because(
                "the line holds more commands than the guard reads",
            ));
        }
        let mut c = std::mem::take(cmd);
        c.piped = *piped;
        let read = self.read_bodies(&mut c);
        script.commands.push(c);
        read?;
        *piped = pipe;
        Ok(())
    }

    /// [`Parser::bodies`], and when the text a command runs cannot be read,
    /// what was read of it stays with the command.
    fn read_bodies(&self, c: &mut Command) -> Result<(), Unparsed> {
        let mut read = self.bodies(c);
        if let Err(e) = &mut read
            && !e.read.commands.is_empty()
        {
            c.inner
                .push(std::mem::replace(&mut e.read, Script::new(self.shell)));
        }
        read
    }

    fn token(&mut self, start: bool, close: Option<char>) -> Result<Tok, Unparsed> {
        match self.shell {
            Shell::Sh | Shell::Fish => self.sh_token(),
            Shell::PowerShell => self.ps_token(start),
            Shell::Cmd => self.cmd_token(start, close),
        }
    }

    // ---- sh ----

    fn sh_token(&mut self) -> Result<Tok, Unparsed> {
        loop {
            match self.peek() {
                // A carriage return ends a word as a blank does: a line
                // written on Windows still splits where it looks split.
                Some(' ' | '\t' | '\r') => {
                    self.bump();
                }
                Some('\\') if self.peek_at(1) == Some('\n') => {
                    self.bump();
                    self.bump();
                }
                Some('#') => self.skip_line(),
                _ => break,
            }
        }
        let Some(c) = self.peek() else {
            return Ok(Tok::End);
        };
        Ok(match c {
            '\n' => {
                self.bump();
                if let Some(r) = self.resume.take() {
                    self.i = r;
                }
                Tok::Sep
            }
            ';' => {
                self.bump();
                // `;;`, `;&` and `;;&` end a branch of a `case`.
                if matches!(self.peek(), Some(';' | '&')) {
                    if self.cases == 0 {
                        return Err(Unparsed::because("a ;; outside a case"));
                    }
                    self.bump();
                    self.eat('&');
                }
                Tok::Sep
            }
            '&' => {
                self.bump();
                if self.eat('&') {
                    Tok::Sep
                } else if self.eat('>') {
                    self.eat('>');
                    Tok::Redirect(true)
                } else {
                    Tok::Sep
                }
            }
            '|' => {
                self.bump();
                if self.eat('|') {
                    Tok::Sep
                } else {
                    self.eat('&');
                    Tok::Pipe
                }
            }
            '(' => {
                self.bump();
                Tok::Open
            }
            ')' => {
                self.bump();
                Tok::Close(')')
            }
            '<' | '>' if self.peek_at(1) == Some('(') => return self.sh_word(),
            '<' | '>' => self.sh_redirect(),
            '0'..='9' => {
                let digits = self.s[self.i..]
                    .iter()
                    .take_while(|c| c.is_ascii_digit())
                    .count();
                if matches!(self.peek_at(digits), Some('<' | '>'))
                    && self.peek_at(digits + 1) != Some('(')
                {
                    for _ in 0..digits {
                        self.bump();
                    }
                    self.sh_redirect()
                } else {
                    return self.sh_word();
                }
            }
            _ => return self.sh_word(),
        })
    }

    fn sh_redirect(&mut self) -> Tok {
        if self.bump() == Some('<') {
            if self.arith > 0 && self.peek() == Some('<') && self.peek_at(1) != Some('<') {
                // `1 << 4` in an arithmetic expression shifts.
                self.bump();
                return Tok::Redirect(true);
            }
            if self.eat('<') {
                if self.eat('<') {
                    return Tok::HereString;
                }
                return Tok::HereDoc(self.eat('-'));
            }
            let _ = self.eat('&') || self.eat('>');
        } else {
            let _ = self.eat('>') || self.eat('|') || self.eat('&');
        }
        Tok::Redirect(true)
    }

    fn sh_word(&mut self) -> Result<Tok, Unparsed> {
        let mut w = Word {
            literal: true,
            ..Word::default()
        };
        let mut subs = Vec::new();
        match self.sh_word_parts(&mut w, &mut subs) {
            Ok(()) => Ok(Tok::Word(w, subs)),
            // The substitutions read before the place that gave out run.
            Err(e) => Err(e.with_subs(subs, self.shell)),
        }
    }

    fn sh_word_parts(&mut self, w: &mut Word, subs: &mut Vec<Script>) -> Result<(), Unparsed> {
        while let Some(c) = self.peek() {
            match c {
                ' ' | '\t' | '\r' | '\n' | ';' | '&' | '|' | '(' | ')' => break,
                '<' | '>' if self.peek_at(1) == Some('(') => {
                    // Process substitution: `<( … )` runs its commands.
                    let from = self.i;
                    self.bump();
                    self.bump();
                    subs.push(self.list(Some(')'))?);
                    w.text.push_str(&self.raw(from));
                    w.literal = false;
                }
                // zsh's `=( … )` runs its commands as `<( … )` does.
                '=' if w.text.is_empty() && self.peek_at(1) == Some('(') => {
                    let from = self.i;
                    self.bump();
                    self.bump();
                    subs.push(self.list(Some(')'))?);
                    w.text.push_str(&self.raw(from));
                    w.literal = false;
                }
                '<' | '>' => break,
                '\\' => {
                    self.bump();
                    match self.bump() {
                        Some('\n') => {}
                        Some(x) => {
                            w.text.push(x);
                            w.quoted = true;
                        }
                        None => w.text.push('\\'),
                    }
                }
                '\'' => {
                    self.bump();
                    w.quoted = true;
                    loop {
                        match self.bump() {
                            Some('\'') => break,
                            Some(x) => w.text.push(x),
                            None => return Err(Unparsed::because("a quote is not closed")),
                        }
                    }
                }
                '"' => {
                    self.bump();
                    w.quoted = true;
                    self.sh_double(w, subs, true)?;
                }
                '`' => {
                    let from = self.i;
                    self.bump();
                    subs.push(self.backtick()?);
                    w.text.push_str(&self.raw(from));
                    w.literal = false;
                }
                '$' => self.sh_dollar(w, subs, false)?,
                _ => {
                    self.bump();
                    w.text.push(c);
                }
            }
        }
        Ok(())
    }

    /// The inside of `"…"` up to its closing quote, or (`quoted` false) a
    /// here-document's body to its end, where `"` is a plain character.
    fn sh_double(
        &mut self,
        w: &mut Word,
        subs: &mut Vec<Script>,
        quoted: bool,
    ) -> Result<(), Unparsed> {
        loop {
            match self.peek() {
                None if quoted => return Err(Unparsed::because("a quote is not closed")),
                None => return Ok(()),
                Some('"') if quoted => {
                    self.bump();
                    return Ok(());
                }
                Some('\\') => {
                    self.bump();
                    match self.peek() {
                        Some(c @ ('$' | '`' | '"' | '\\')) => {
                            self.bump();
                            w.text.push(c);
                        }
                        Some('\n') => {
                            self.bump();
                        }
                        _ => w.text.push('\\'),
                    }
                }
                Some('`') => {
                    let from = self.i;
                    self.bump();
                    subs.push(self.backtick()?);
                    w.text.push_str(&self.raw(from));
                    w.literal = false;
                }
                Some('$') => self.sh_dollar(w, subs, true)?,
                Some(c) => {
                    self.bump();
                    w.text.push(c);
                }
            }
        }
    }

    /// `$…`: a substitution, a variable, `$'…'`, or a plain `$`.
    fn sh_dollar(
        &mut self,
        w: &mut Word,
        subs: &mut Vec<Script>,
        in_quotes: bool,
    ) -> Result<(), Unparsed> {
        let from = self.i;
        self.bump();
        match self.peek() {
            Some('(') => {
                // `$((…))` reads as a subshell inside: its words are data.
                self.bump();
                subs.push(self.group(self.peek() == Some('('))?);
                w.literal = false;
            }
            Some('{') => {
                self.bump();
                let mut open = 1;
                while open > 0 {
                    match self.bump() {
                        None => return Err(Unparsed::because("a ${ is not closed")),
                        Some('{') => open += 1,
                        Some('}') => open -= 1,
                        // A substitution in `${x:-$(…)}` would run: rather
                        // than read that far, the line is not read.
                        Some('`') => return Err(Unparsed::because("a substitution inside ${…}")),
                        Some('$') if self.peek() == Some('(') => {
                            return Err(Unparsed::because("a substitution inside ${…}"));
                        }
                        Some(_) => {}
                    }
                }
                w.literal = false;
            }
            Some('\'') if !in_quotes => {
                self.bump();
                w.quoted = true;
                loop {
                    match self.bump() {
                        None => return Err(Unparsed::because("a quote is not closed")),
                        Some('\'') => break,
                        Some('\\') => match self.bump() {
                            None => return Err(Unparsed::because("a quote is not closed")),
                            Some('n') => w.text.push('\n'),
                            Some('t') => w.text.push('\t'),
                            Some(x) => w.text.push(x),
                        },
                        Some(x) => w.text.push(x),
                    }
                }
                return Ok(());
            }
            Some('"') if !in_quotes => {
                self.bump();
                w.quoted = true;
                return self.sh_double(w, subs, true);
            }
            Some(c) if c.is_alphanumeric() || c == '_' => {
                while self.peek().is_some_and(|c| c.is_alphanumeric() || c == '_') {
                    self.bump();
                }
                w.literal = false;
            }
            Some('?' | '$' | '!' | '#' | '*' | '@' | '-') => {
                self.bump();
                w.literal = false;
            }
            _ => {}
        }
        w.text.push_str(&self.raw(from));
        Ok(())
    }

    /// The body of a backtick substitution (the opening one taken), read as
    /// a script.
    fn backtick(&mut self) -> Result<Script, Unparsed> {
        let mut body = String::new();
        loop {
            match self.bump() {
                None => return Err(Unparsed::because("a backtick is not closed")),
                Some('`') => break,
                Some('\\') => match self.peek() {
                    Some(c @ ('`' | '\\' | '$')) => {
                        self.bump();
                        body.push(c);
                    }
                    _ => body.push('\\'),
                },
                Some(c) => body.push(c),
            }
        }
        self.nested(&body, Shell::Sh)
    }

    /// A here-document: its end word, then its body from the next line (or
    /// after the body of one opened before on this line). Reading goes on
    /// after the body at the end of this line. An unquoted end word lets
    /// the body's substitutions run. The body and what runs in it go on
    /// `cmd`; a here-document that does not end is read to the end of the
    /// text (sh runs it so) and the line is not read with confidence.
    fn here_doc(
        &mut self,
        strip: bool,
        close: Option<char>,
        cmd: &mut Command,
    ) -> Result<(), Unparsed> {
        let Tok::Word(end, _) = self.token(false, close)? else {
            return Err(Unparsed::because("a here-document has no end word"));
        };
        let from = match self.resume {
            Some(r) => r,
            None => match self.s[self.i..].iter().position(|&c| c == '\n') {
                Some(p) => self.i + p + 1,
                None => return Err(Unparsed::because("a here-document has no body")),
            },
        };
        let mut at = from;
        let mut body = String::new();
        loop {
            if at >= self.s.len() {
                let subs = if end.quoted {
                    Ok(Vec::new())
                } else {
                    self.here_subs(&body)
                };
                cmd.input.push(body);
                cmd.inner.extend(subs?);
                return Err(Unparsed::because("a here-document does not end"));
            }
            let stop = self.s[at..]
                .iter()
                .position(|&c| c == '\n')
                .map_or(self.s.len(), |p| at + p);
            if !self.charge(stop + 1 - at) {
                return Err(Unparsed::because(
                    "the line is longer or deeper than the guard reads",
                ));
            }
            let line: String = self.s[at..stop].iter().collect();
            at = (stop + 1).min(self.s.len());
            let bare = if strip {
                line.trim_start_matches('\t')
            } else {
                &line
            };
            if bare.trim_end_matches('\r') == end.text {
                break;
            }
            body.push_str(&line);
            body.push('\n');
        }
        self.resume = Some(at);
        if !end.quoted {
            cmd.inner.extend(self.here_subs(&body)?);
        }
        cmd.input.push(body);
        Ok(())
    }

    /// What runs in the body of a here-document whose end word is not
    /// quoted.
    fn here_subs(&self, body: &str) -> Result<Vec<Script>, Unparsed> {
        let mut subs = Vec::new();
        let mut p = Parser::new(body, Shell::Sh, self.depth, self.budget);
        match p.sh_double(&mut Word::default(), &mut subs, false) {
            Ok(()) => Ok(subs),
            Err(e) => Err(e.with_subs(subs, Shell::Sh)),
        }
    }

    // ---- PowerShell ----

    fn ps_token(&mut self, start: bool) -> Result<Tok, Unparsed> {
        loop {
            match self.peek() {
                Some(' ' | '\t' | '\r') => {
                    self.bump();
                }
                Some('`') if self.peek_at(1) == Some('\n') => {
                    self.bump();
                    self.bump();
                }
                Some('<') if self.peek_at(1) == Some('#') => {
                    self.bump();
                    self.bump();
                    loop {
                        match self.bump() {
                            None => return Err(Unparsed::because("a <# comment is not closed")),
                            Some('#') if self.peek() == Some('>') => {
                                self.bump();
                                break;
                            }
                            Some(_) => {}
                        }
                    }
                }
                Some('#') => self.skip_line(),
                _ => break,
            }
        }
        let Some(c) = self.peek() else {
            return Ok(Tok::End);
        };
        Ok(match c {
            '\n' | ';' => {
                self.bump();
                Tok::Sep
            }
            '|' => {
                self.bump();
                if self.eat('|') { Tok::Sep } else { Tok::Pipe }
            }
            '&' => {
                self.bump();
                if self.eat('&') {
                    Tok::Sep
                } else if start {
                    // The call operator: what follows is run.
                    Tok::Word(
                        Word {
                            text: "&".into(),
                            literal: true,
                            quoted: false,
                        },
                        Vec::new(),
                    )
                } else {
                    Tok::Sep
                }
            }
            ')' | '}' => {
                self.bump();
                Tok::Close(c)
            }
            '>' | '<' => self.ps_redirect(),
            '*' | '1'..='6' if self.peek_at(1) == Some('>') => self.ps_redirect(),
            _ => return self.ps_word(),
        })
    }

    fn ps_redirect(&mut self) -> Tok {
        if matches!(self.peek(), Some('*' | '1'..='6')) {
            self.bump();
        }
        self.bump();
        self.eat('>');
        if self.peek() == Some('&') && self.peek_at(1).is_some_and(|c| c.is_ascii_digit()) {
            self.bump();
            self.bump();
            return Tok::Redirect(false);
        }
        Tok::Redirect(true)
    }

    fn ps_word(&mut self) -> Result<Tok, Unparsed> {
        let mut w = Word {
            literal: true,
            ..Word::default()
        };
        let mut subs = Vec::new();
        match self.ps_word_parts(&mut w, &mut subs) {
            Ok(()) => Ok(Tok::Word(w, subs)),
            // The substitutions read before the place that gave out run.
            Err(e) => Err(e.with_subs(subs, self.shell)),
        }
    }

    fn ps_word_parts(&mut self, w: &mut Word, subs: &mut Vec<Script>) -> Result<(), Unparsed> {
        if self.peek() == Some('-') && self.peek_at(1) == Some('-') && self.peek_at(2) == Some('%')
        {
            return Err(Unparsed::because("PowerShell's --%"));
        }
        if self.peek() == Some('@')
            && matches!(self.peek_at(1), Some('\'' | '"'))
            && matches!(self.peek_at(2), Some('\n' | '\r'))
        {
            self.bump();
            let q = self.bump().unwrap_or('\'');
            self.ps_here_string(q, w, subs)?;
        }
        while let Some(c) = self.peek() {
            match c {
                ' ' | '\t' | '\r' | '\n' | ';' | '|' | '&' | ')' | '}' | '>' => break,
                '`' => {
                    self.bump();
                    match self.bump() {
                        // A line continuation ends the word as a blank.
                        Some('\n') => break,
                        Some(x) => {
                            w.text.push(x);
                            w.quoted = true;
                        }
                        None => w.text.push('`'),
                    }
                }
                '\'' | '‘' | '’' | '‚' | '‛' => {
                    self.bump();
                    w.quoted = true;
                    loop {
                        match self.bump() {
                            None => return Err(Unparsed::because("a quote is not closed")),
                            Some(q) if is_ps_single(q) => {
                                if self.peek().is_some_and(is_ps_single) {
                                    self.bump();
                                    w.text.push('\'');
                                } else {
                                    break;
                                }
                            }
                            Some(x) => w.text.push(x),
                        }
                    }
                }
                '"' | '“' | '”' | '„' => {
                    self.bump();
                    w.quoted = true;
                    self.ps_double(w, subs, true)?;
                }
                '(' | '{' => {
                    let from = self.i;
                    self.bump();
                    subs.push(self.list(Some(if c == '(' { ')' } else { '}' }))?);
                    w.text.push_str(&self.raw(from));
                    w.literal = false;
                }
                '@' if matches!(self.peek_at(1), Some('(' | '{')) => {
                    let from = self.i;
                    self.bump();
                    let open = self.bump();
                    subs.push(self.list(Some(if open == Some('(') { ')' } else { '}' }))?);
                    w.text.push_str(&self.raw(from));
                    w.literal = false;
                }
                '$' => self.ps_dollar(w, subs)?,
                _ => {
                    self.bump();
                    w.text.push(c);
                }
            }
        }
        Ok(())
    }

    /// `$…` in PowerShell: `$( … )` runs its commands, `${…}` and `$name`
    /// are variables.
    fn ps_dollar(&mut self, w: &mut Word, subs: &mut Vec<Script>) -> Result<(), Unparsed> {
        let from = self.i;
        self.bump();
        match self.peek() {
            Some('(') => {
                self.bump();
                subs.push(self.list(Some(')'))?);
                w.literal = false;
            }
            Some('{') => {
                self.bump();
                loop {
                    match self.bump() {
                        None => return Err(Unparsed::because("a ${ is not closed")),
                        Some('}') => break,
                        Some(_) => {}
                    }
                }
                w.literal = false;
            }
            Some(c) if c.is_alphanumeric() || matches!(c, '_' | '?' | '$' | '^') => {
                self.bump();
                while self
                    .peek()
                    .is_some_and(|c| c.is_alphanumeric() || matches!(c, '_' | ':'))
                {
                    self.bump();
                }
                w.literal = false;
            }
            _ => {}
        }
        w.text.push_str(&self.raw(from));
        Ok(())
    }

    /// The inside of a PowerShell `"…"` up to its closing quote, or
    /// (`quoted` false) a `@"…"@` here-string's text to its end.
    fn ps_double(
        &mut self,
        w: &mut Word,
        subs: &mut Vec<Script>,
        quoted: bool,
    ) -> Result<(), Unparsed> {
        loop {
            match self.peek() {
                None if quoted => return Err(Unparsed::because("a quote is not closed")),
                None => return Ok(()),
                Some(q) if quoted && is_ps_double(q) => {
                    self.bump();
                    if self.peek().is_some_and(is_ps_double) {
                        self.bump();
                        w.text.push('"');
                    } else {
                        return Ok(());
                    }
                }
                Some('`') => {
                    self.bump();
                    match self.bump() {
                        Some(x) => w.text.push(x),
                        None => return Err(Unparsed::because("a quote is not closed")),
                    }
                }
                Some('$') => self.ps_dollar(w, subs)?,
                Some(c) => {
                    self.bump();
                    w.text.push(c);
                }
            }
        }
    }

    /// A here-string after its `@'` or `@"`: its lines up to a line that
    /// starts with `'@` or `"@`.
    fn ps_here_string(
        &mut self,
        q: char,
        w: &mut Word,
        subs: &mut Vec<Script>,
    ) -> Result<(), Unparsed> {
        w.quoted = true;
        self.eat('\r');
        self.eat('\n');
        let from = self.i;
        loop {
            match self.bump() {
                None => return Err(Unparsed::because("a here-string is not closed")),
                Some('\n') if self.peek() == Some(q) && self.peek_at(1) == Some('@') => {
                    let text: String = self.s[from..self.i - 1].iter().collect();
                    self.bump();
                    self.bump();
                    if q == '"' {
                        let mut p = Parser::new(&text, Shell::PowerShell, self.depth, self.budget);
                        p.ps_double(w, subs, false)?;
                    } else {
                        w.text.push_str(&text);
                    }
                    return Ok(());
                }
                Some(_) => {}
            }
        }
    }

    // ---- cmd ----

    fn cmd_token(&mut self, start: bool, close: Option<char>) -> Result<Tok, Unparsed> {
        loop {
            match self.peek() {
                Some(' ' | '\t' | '\r') => {
                    self.bump();
                }
                Some('^') if self.peek_at(1) == Some('\n') => {
                    self.bump();
                    self.bump();
                }
                // `@` before a command only keeps it from being echoed.
                Some('@') if start => {
                    self.bump();
                }
                _ if start
                    && (self.at_word("rem") || self.s[self.i..].starts_with(&[':', ':'])) =>
                {
                    self.skip_line()
                }
                _ => break,
            }
        }
        let Some(c) = self.peek() else {
            return Ok(Tok::End);
        };
        Ok(match c {
            '\n' => {
                self.bump();
                Tok::Sep
            }
            '&' => {
                self.bump();
                self.eat('&');
                Tok::Sep
            }
            '|' => {
                self.bump();
                if self.eat('|') { Tok::Sep } else { Tok::Pipe }
            }
            '(' => {
                self.bump();
                Tok::Open
            }
            ')' if close == Some(')') => {
                self.bump();
                Tok::Close(')')
            }
            '<' | '>' => self.cmd_redirect(),
            '0'..='9' if self.peek_at(1) == Some('>') => self.cmd_redirect(),
            _ => return self.cmd_word(close),
        })
    }

    fn cmd_redirect(&mut self) -> Tok {
        if self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.bump();
        }
        self.bump();
        self.eat('>');
        if self.peek() == Some('&') && self.peek_at(1).is_some_and(|c| c.is_ascii_digit()) {
            self.bump();
            self.bump();
            return Tok::Redirect(false);
        }
        Tok::Redirect(true)
    }

    fn cmd_word(&mut self, close: Option<char>) -> Result<Tok, Unparsed> {
        let mut w = Word {
            literal: true,
            ..Word::default()
        };
        while let Some(c) = self.peek() {
            match c {
                ' ' | '\t' | '\r' | '\n' | '&' | '|' | '<' | '>' | '(' => break,
                ')' if close == Some(')') => break,
                '^' => {
                    self.bump();
                    if let Some(x) = self.bump() {
                        w.text.push(x);
                        w.quoted = true;
                    }
                }
                '"' => {
                    self.bump();
                    w.quoted = true;
                    loop {
                        match self.bump() {
                            None | Some('\n') => {
                                return Err(Unparsed::because("a quote is not closed"));
                            }
                            Some('"') => break,
                            Some(x) => {
                                w.literal &= x != '%';
                                w.text.push(x);
                            }
                        }
                    }
                }
                _ => {
                    self.bump();
                    w.literal &= c != '%';
                    w.text.push(c);
                }
            }
        }
        Ok(Tok::Word(w, Vec::new()))
    }

    // ---- the text a command runs ----

    /// Reads what `cmd` runs as a shell: the text after `sh -c`,
    /// `powershell -Command`, `cmd /c`, `eval` and `Invoke-Expression`, and
    /// the here-documents fed to a shell. A shell that reads its script
    /// from a pipe runs what the reader cannot see.
    fn bodies(&self, cmd: &mut Command) -> Result<(), Unparsed> {
        let run = match unwrap(cmd, self.shell) {
            Ok(Some(run)) => run,
            Ok(None) => return Ok(()),
            Err(Wrapped) => {
                return Err(Unparsed::because(
                    "a command is wrapped in more than the guard unwraps",
                ));
            }
        };
        let body = match runs(&run.name, &run.args, self.shell) {
            Runs::Nothing => return Ok(()),
            Runs::Text(text, shell) => text.map(|t| (t, shell)),
            Runs::Input(shell) => {
                if cmd.piped {
                    return Err(Unparsed::because("a shell reads its script from a pipe"));
                }
                let inputs = std::mem::take(&mut cmd.input);
                for text in &inputs {
                    cmd.inner.push(self.nested(text, shell)?);
                }
                cmd.input = inputs;
                return Ok(());
            }
            Runs::Hidden => return Err(Unparsed::because("a shell runs an encoded command")),
        };
        if let Some((text, shell)) = body {
            cmd.inner.push(self.nested(&text, shell)?);
        }
        Ok(())
    }
}

fn is_ps_single(c: char) -> bool {
    matches!(c, '\'' | '‘' | '’' | '‚' | '‛')
}

fn is_ps_double(c: char) -> bool {
    matches!(c, '"' | '“' | '”' | '„')
}

/// What a program runs as a shell, by its name and arguments.
enum Runs {
    Nothing,
    /// This text, in this shell (`None`: the flag has no text after it).
    Text(Option<String>, Shell),
    /// Its input: a here-document, or a pipe.
    Input(Shell),
    /// A text it is given in a form the reader cannot read.
    Hidden,
}

fn joined(args: &[Word]) -> Option<String> {
    (!args.is_empty()).then(|| {
        args.iter()
            .map(|w| w.text.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    })
}

/// What `name` runs with `args` when it stands in a script of `shell`.
fn runs(name: &str, args: &[Word], shell: Shell) -> Runs {
    if SH.contains(&name) {
        return runs_sh(args, if name == "fish" { Shell::Fish } else { Shell::Sh });
    }
    match name {
        "powershell" | "pwsh" => runs_powershell(args),
        "cmd" => {
            let mut i = 0;
            while let Some(a) = args.get(i) {
                let a = a.text.to_lowercase();
                if a == "/c" || a == "/k" {
                    return Runs::Text(joined(&args[i + 1..]), Shell::Cmd);
                }
                if !a.starts_with('/') {
                    break;
                }
                i += 1;
            }
            Runs::Nothing
        }
        // `eval` runs its text in the shell it stands in.
        "eval" => Runs::Text(
            joined(args),
            if shell == Shell::Fish {
                Shell::Fish
            } else {
                Shell::Sh
            },
        ),
        // Without `-c` they start a shell, which runs its input.
        "su" | "runuser" => match args
            .iter()
            .position(|w| w.text == "-c" || w.text == "--command")
        {
            Some(at) => Runs::Text(args.get(at + 1).map(|w| w.text.clone()), Shell::Sh),
            None => Runs::Input(Shell::Sh),
        },
        "invoke-expression" | "iex" => {
            let args = match args.first() {
                Some(a) if a.text.starts_with('-') => &args[1..],
                _ => args,
            };
            Runs::Text(joined(args), Shell::PowerShell)
        }
        _ => Runs::Nothing,
    }
}

/// `sh` and its kin: `-c` (alone or in a group such as `-lc`) runs the first
/// word after the options; with neither `-c` nor a script file the shell
/// runs its input, and so it does with `-s`, whose words after it are the
/// script's arguments.
fn runs_sh(args: &[Word], shell: Shell) -> Runs {
    let mut i = 0;
    let mut c = false;
    let mut s = false;
    while let Some(a) = args.get(i) {
        let a = a.text.as_str();
        if a == "--" || a == "-" {
            i += 1;
            break;
        }
        if let Some(long) = a.strip_prefix("--") {
            if matches!(long, "rcfile" | "init-file") {
                i += 1;
            }
        } else if let Some(flags) = a.strip_prefix(['-', '+']).filter(|f| !f.is_empty()) {
            c |= flags.contains('c');
            s |= a.starts_with('-') && flags.contains('s');
            if flags.contains(['o', 'O']) {
                i += 1;
            }
        } else {
            break;
        }
        i += 1;
    }
    let rest = args.get(i..).unwrap_or_default();
    if c {
        Runs::Text(rest.first().map(|w| w.text.clone()), shell)
    } else if rest.is_empty() || s {
        Runs::Input(shell)
    } else {
        Runs::Nothing
    }
}

/// PowerShell's own switches: `-Command` (any prefix of it) runs the rest
/// of the line, `-EncodedCommand` hides it, `-File` runs a file, and the
/// first word that is not a switch starts the command.
fn runs_powershell(args: &[Word]) -> Runs {
    const VALUES: &[&str] = &[
        "executionpolicy",
        "ep",
        "windowstyle",
        "inputformat",
        "outputformat",
        "of",
        "version",
        "configurationname",
        "workingdirectory",
        "wd",
        "settingsfile",
        "custompipename",
        "psconsolefile",
    ];
    let mut i = 0;
    while let Some(a) = args.get(i) {
        let lower = a.text.to_lowercase();
        let Some(name) = lower.strip_prefix('-').filter(|n| !n.is_empty()) else {
            break;
        };
        if "command".starts_with(name) {
            let rest = &args[i + 1..];
            if rest.len() == 1 && rest[0].text == "-" {
                return Runs::Input(Shell::PowerShell);
            }
            return Runs::Text(joined(rest), Shell::PowerShell);
        }
        if "encodedcommand".starts_with(name) || name == "ec" {
            return Runs::Hidden;
        }
        if "file".starts_with(name) {
            return Runs::Nothing;
        }
        if name == "w" || VALUES.iter().any(|v| v.starts_with(name) && name.len() > 1) {
            i += 1;
        }
        i += 1;
    }
    match args.get(i..) {
        Some(rest) if !rest.is_empty() => Runs::Text(joined(rest), Shell::PowerShell),
        _ => Runs::Input(Shell::PowerShell),
    }
}

/// A program's name as the guard compares it: the last part of its path,
/// without `.exe`, and on Windows in lower case.
pub fn base_name(word: &str, windows: bool) -> String {
    let base = if windows {
        word.rsplit(['/', '\\']).next()
    } else {
        word.rsplit('/').next()
    }
    .unwrap_or(word);
    // The suffix is compared on bytes: a name is not cut inside a character.
    let base = match base.len().checked_sub(4) {
        Some(at) if at > 0 && base.as_bytes()[at..].eq_ignore_ascii_case(b".exe") => &base[..at],
        _ => base,
    };
    if windows {
        base.to_lowercase()
    } else {
        base.to_string()
    }
}

/// The shell's own words that may stand before a command.
const SH_KEYWORDS: &[&str] = &[
    "!", "{", "}", "if", "then", "else", "elif", "fi", "do", "done", "while", "until",
];
const FISH_KEYWORDS: &[&str] = &[
    "!", "{", "}", "if", "then", "else", "elif", "fi", "do", "done", "while", "until", "and", "or",
    "not", "begin", "end",
];
const PS_KEYWORDS: &[&str] = &[
    "&", ".", "if", "elseif", "else", "foreach", "for", "while", "do", "until", "switch", "try",
    "catch", "finally", "trap", "return", "throw",
];

/// The program a command runs, behind the shell's keywords and assignments
/// and the wrappers that run another program: `sudo` (and `doas`) with
/// their options, `env` (with `-u`, `-S` and assignments), `timeout`,
/// `nohup`, `nice`, `ionice`, `time`, `stdbuf`, `xargs`, `exec`, `command`,
/// `setsid`, `busybox`; on Windows PowerShell's `&` and `Start-Process`, and
/// cmd's `start`, `call`, `if` and `for … do`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    /// The program's name as [`base_name`] gives it (`/usr/bin/systemctl` →
    /// `systemctl`).
    pub name: String,
    /// Its arguments.
    pub args: Vec<Word>,
}

/// Each wrapper's options that take a value: as the next word, or after
/// `=` (`--user=x`), or (a short one) the rest of the word (`-uroot`).
const SUDO: &[&str] = &[
    "-u",
    "-g",
    "-C",
    "-D",
    "-p",
    "-r",
    "-t",
    "-T",
    "-U",
    "-R",
    "--user",
    "--group",
    "--close-from",
    "--chdir",
    "--prompt",
    "--role",
    "--type",
    "--other-user",
    "--chroot",
    "--command-timeout",
    "--host",
];
const ENV: &[&str] = &["-u", "-C", "-P", "--unset", "--chdir"];
const TIMEOUT: &[&str] = &["-s", "-k", "--signal", "--kill-after"];
const NICE: &[&str] = &["-n", "--adjustment"];
const IONICE: &[&str] = &["-c", "-n", "--class", "--classdata"];
const TIME: &[&str] = &["-f", "-o", "--format", "--output"];
const STDBUF: &[&str] = &["-i", "-o", "-e", "--input", "--output", "--error"];
const XARGS: &[&str] = &[
    "-a",
    "-d",
    "-E",
    "-I",
    "-L",
    "-n",
    "-P",
    "-s",
    "--arg-file",
    "--delimiter",
    "--eof",
    "--replace",
    "--max-lines",
    "--max-args",
    "--max-procs",
    "--max-chars",
    "--process-slot-var",
];
const EXEC: &[&str] = &["-a"];

/// How many of `rest` are options (with their values) before the program.
fn options(rest: &[Word], values: &[&str]) -> usize {
    let mut n = 0;
    while let Some(w) = rest.get(n) {
        let t = w.text.as_str();
        if t == "--" {
            return n + 1;
        }
        if !t.starts_with('-') || t == "-" {
            break;
        }
        n += 1;
        if t.starts_with("--") {
            if values.contains(&t) {
                n += 1;
            }
        } else {
            // In a group of short options, the first that takes a value
            // takes the rest of the group, or the next word at its end.
            let letters: Vec<char> = t.chars().skip(1).collect();
            if let Some(p) = letters
                .iter()
                .position(|c| values.contains(&format!("-{c}").as_str()))
                && p + 1 == letters.len()
            {
                n += 1;
            }
        }
    }
    // An option that ends the line has no value to take.
    n.min(rest.len())
}

/// Whether the options of `sudo` or `doas` ask for a shell (`-s`, `-i`,
/// `--shell`, `--login`, also in a group such as `-iu`).
fn sudo_shell(opts: &[Word]) -> bool {
    let mut k = 0;
    while let Some(w) = opts.get(k) {
        k += 1;
        let t = w.text.as_str();
        if let Some(long) = t.strip_prefix("--") {
            if matches!(long, "shell" | "login") {
                return true;
            }
            if SUDO.contains(&t) {
                k += 1;
            }
        } else if let Some(letters) = t.strip_prefix('-') {
            let letters: Vec<char> = letters.chars().collect();
            for (p, c) in letters.iter().enumerate() {
                if matches!(c, 's' | 'i') {
                    return true;
                }
                if SUDO.contains(&format!("-{c}").as_str()) {
                    if p + 1 == letters.len() {
                        k += 1;
                    }
                    break;
                }
            }
        }
    }
    false
}

/// Finds the program `cmd` runs. `None`: it runs none (only keywords, a
/// wrapper with nothing after it, `command -v`), or the unwrapping stopped
/// at its bound ([`parse`] reports that as a line it cannot read).
pub fn run(cmd: &Command, shell: Shell) -> Option<Run> {
    unwrap(cmd, shell).ok().flatten()
}

/// [`run`] cut off at the bound of its walk.
struct Wrapped;

fn unwrap(cmd: &Command, shell: Shell) -> Result<Option<Run>, Wrapped> {
    let win = shell.windows();
    let mut words = cmd.words.clone();
    let mut i = 0;
    // PowerShell's `&` or `.` was the last word taken: what follows is run
    // even when it is a quoted string, which is a value anywhere else.
    let mut called = false;
    // Every turn takes a word or rewrites one away (`env -S`, a stuck `{`,
    // `Start-Process`); the bound only stops a line built to turn forever.
    for _ in 0..256 {
        let Some(w) = words.get(i) else {
            return Ok(None);
        };
        let t = w.text.clone();
        let lower = t.to_lowercase();
        let keyword = !w.quoted
            && match shell {
                Shell::Sh => SH_KEYWORDS.contains(&t.as_str()),
                Shell::Fish => FISH_KEYWORDS.contains(&t.as_str()),
                Shell::PowerShell => PS_KEYWORDS.contains(&lower.as_str()),
                Shell::Cmd => lower == "else",
            };
        if keyword {
            called = shell == Shell::PowerShell && matches!(t.as_str(), "&" | ".");
            i += 1;
            continue;
        }
        if !w.quoted && t == "function" && shell != Shell::Cmd {
            i += 2;
            continue;
        }
        if shell.posix() && !w.quoted && t.len() > 1 && t.starts_with('{') {
            // `{cmd` reads as the brace and the command.
            words[i].text.remove(0);
            continue;
        }
        if shell.posix() && is_assignment(&t) {
            i += 1;
            continue;
        }
        if shell == Shell::Sh && !w.quoted && t == "coproc" {
            // `coproc NAME { cmd; }` and `coproc cmd`.
            i += if words.get(i + 2).is_some_and(|n| n.text.starts_with('{')) {
                2
            } else {
                1
            };
            continue;
        }
        if shell == Shell::PowerShell
            && t.starts_with('$')
            && words.get(i + 1).is_some_and(|n| is_ps_assign(&n.text))
        {
            i += 2;
            continue;
        }
        // In PowerShell a quoted string that starts a statement is a value.
        if shell == Shell::PowerShell && w.quoted && !called {
            return Ok(None);
        }
        let name = base_name(&t, win);
        let rest = &words[i + 1..];
        let skip = match name.as_str() {
            "sudo" | "doas" => {
                let n = options(rest, SUDO);
                if n == rest.len() && sudo_shell(&rest[..n]) {
                    // `sudo -s` and `sudo -i` with no command start a
                    // shell, which runs its input.
                    return Ok(Some(Run {
                        name: "sh".into(),
                        args: Vec::new(),
                    }));
                }
                n
            }
            "env" => {
                if let Some(split) = env_split(rest) {
                    words.splice(i + 1..i + 1 + split.0, split.1);
                    continue;
                }
                let n = options(rest, ENV);
                n + rest[n..]
                    .iter()
                    .take_while(|w| is_assignment(&w.text))
                    .count()
            }
            "timeout" => options(rest, TIMEOUT) + 1,
            "nice" => options(rest, NICE),
            "ionice" => options(rest, IONICE),
            "time" => options(rest, TIME),
            "stdbuf" => options(rest, STDBUF),
            "xargs" => options(rest, XARGS),
            "exec" => options(rest, EXEC),
            "command" => {
                let n = options(rest, &[]);
                if rest[..n]
                    .iter()
                    .any(|w| w.text.starts_with("-v") || w.text.starts_with("-V"))
                {
                    return Ok(None);
                }
                n
            }
            "setsid" => options(rest, &[]),
            "nohup" | "builtin" | "nocorrect" | "noglob" | "busybox" => {
                usize::from(rest.first().is_some_and(|w| w.text == "--"))
            }
            "start-process" | "saps" if shell != Shell::Cmd => {
                let Some(started) = start_process(rest) else {
                    return Ok(None);
                };
                words.splice(i.., started);
                called = true;
                continue;
            }
            "start" if shell == Shell::PowerShell => {
                let Some(started) = start_process(rest) else {
                    return Ok(None);
                };
                words.splice(i.., started);
                called = true;
                continue;
            }
            "start" if shell == Shell::Cmd => cmd_start(rest),
            "call" if shell == Shell::Cmd => 0,
            "if" if shell == Shell::Cmd => cmd_if(rest),
            "for" if shell == Shell::Cmd => {
                let Some(at) = rest.iter().position(|w| w.text.eq_ignore_ascii_case("do")) else {
                    return Ok(None);
                };
                at + 1
            }
            _ => {
                return Ok(Some(Run {
                    name,
                    args: rest.to_vec(),
                }));
            }
        };
        i += 1 + skip;
    }
    Err(Wrapped)
}

/// `env -S text` (or `--split-string`): how many words the option takes,
/// and the text split at blanks into the words that run.
fn env_split(rest: &[Word]) -> Option<(usize, Vec<Word>)> {
    for (n, w) in rest.iter().enumerate() {
        let t = w.text.as_str();
        let (taken, text) = if t == "-S" || t == "--split-string" {
            (2, rest.get(n + 1)?.text.clone())
        } else if let Some(v) = t.strip_prefix("--split-string=") {
            (1, v.to_string())
        } else if let Some(v) = t.strip_prefix("-S") {
            (1, v.to_string())
        } else if t.starts_with('-') && t != "-" {
            continue;
        } else {
            return None;
        };
        let split = text.split_whitespace().map(|s| Word {
            text: s.to_string(),
            literal: w.literal,
            quoted: false,
        });
        let mut out: Vec<Word> = rest[..n].to_vec();
        out.extend(split);
        return Some((n + taken, out));
    }
    None
}

/// PowerShell's `Start-Process`: the program (`-FilePath` or the first
/// word) and its arguments (`-ArgumentList` or the second word, a list
/// split at commas and blanks).
fn start_process(rest: &[Word]) -> Option<Vec<Word>> {
    const SWITCHES: &[&str] = &[
        "wait",
        "passthru",
        "nonewwindow",
        "loaduserprofile",
        "usenewenvironment",
    ];
    let mut file = None;
    let mut list = None;
    let mut positional = 0;
    let mut n = 0;
    while let Some(w) = rest.get(n) {
        n += 1;
        let lower = w.text.to_lowercase();
        let Some(param) = lower
            .strip_prefix('-')
            .filter(|p| !p.is_empty() && !w.quoted)
        else {
            match positional {
                0 => file = Some(w.clone()),
                1 => list = Some(w.clone()),
                _ => {}
            }
            positional += 1;
            continue;
        };
        let (param, attached) = match param.split_once(':') {
            Some((p, _)) => (p, w.text[1..].split_once(':').map(|(_, v)| v)),
            None => (param, None),
        };
        if SWITCHES.iter().any(|s| s.starts_with(param)) {
            continue;
        }
        let value = match attached {
            Some(v) if !v.is_empty() => Some(Word {
                text: v.to_string(),
                ..w.clone()
            }),
            _ => {
                n += 1;
                rest.get(n - 1).cloned()
            }
        };
        if "filepath".starts_with(param) || param == "path" || param == "pspath" {
            file = value;
        } else if "argumentlist".starts_with(param) || param == "args" {
            list = value;
        }
    }
    let mut out = vec![file?];
    if let Some(l) = list {
        out.extend(
            l.text
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|s| !s.is_empty())
                .map(|s| Word {
                    text: s.to_string(),
                    literal: l.literal,
                    quoted: false,
                }),
        );
    }
    Some(out)
}

/// cmd's `start`: its switches and the window title (its first quoted word)
/// before the program.
fn cmd_start(rest: &[Word]) -> usize {
    let mut n = 0;
    let mut title = false;
    while let Some(w) = rest.get(n) {
        let lower = w.text.to_lowercase();
        if lower.starts_with('/') && !w.quoted {
            if matches!(lower.as_str(), "/d" | "/node" | "/affinity") {
                n += 1;
            }
        } else if w.quoted && !title {
            title = true;
        } else {
            break;
        }
        n += 1;
    }
    n
}

/// cmd's `if`: its condition before the command (`if exist x cmd`,
/// `if /i a==b cmd`, `if not errorlevel 1 cmd`, `if a equ b cmd`).
fn cmd_if(rest: &[Word]) -> usize {
    let low = |n: usize| rest.get(n).map(|w| w.text.to_lowercase());
    let mut n = 0;
    if low(n).as_deref() == Some("/i") {
        n += 1;
    }
    if low(n).as_deref() == Some("not") {
        n += 1;
    }
    match low(n).as_deref() {
        Some("exist" | "defined" | "errorlevel" | "cmdextversion") => n + 2,
        Some(x) if x.contains("==") => n + 1,
        _ => n + 3,
    }
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && !name.starts_with(|c: char| c.is_ascii_digit())
            && name
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '+')
    })
}

fn is_ps_assign(word: &str) -> bool {
    matches!(word, "=" | "+=" | "-=" | "*=" | "/=" | "%=" | "??=")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every command's words, at any depth, in visiting order.
    fn words(line: &str, shell: Shell) -> Vec<Vec<String>> {
        let s = parse(line, shell).unwrap_or_else(|e| panic!("{line:?}: {e:?}"));
        let mut out = Vec::new();
        s.visit(&mut |s: &Script, i| {
            out.push(s.commands[i].words.iter().map(|w| w.text.clone()).collect());
        });
        out
    }

    fn w(list: &[&[&str]]) -> Vec<Vec<String>> {
        list.iter()
            .map(|c| c.iter().map(|s| s.to_string()).collect())
            .collect()
    }

    #[test]
    fn sh_splits_at_separators_and_line_breaks() {
        let sh = |l| words(l, Shell::Sh);
        assert_eq!(
            sh("a b; c && d || e & f"),
            w(&[&["a", "b"], &["c"], &["d"], &["e"], &["f"]])
        );
        assert_eq!(sh("a\nb\r\nc\td"), w(&[&["a"], &["b"], &["c", "d"]]));
        assert_eq!(sh("a |\n  b &&\n c"), w(&[&["a"], &["b"], &["c"]]));
        assert_eq!(sh("a \\\n b"), w(&[&["a", "b"]]));
        assert_eq!(sh("a # b; c\nd"), w(&[&["a"], &["d"]]));
        assert_eq!(sh(""), Vec::<Vec<String>>::new());
    }

    #[test]
    fn sh_marks_pipes() {
        let s = parse("a | b |& c; d", Shell::Sh).unwrap();
        let piped: Vec<bool> = s.commands.iter().map(|c| c.piped).collect();
        assert_eq!(piped, [false, true, true, false]);
    }

    #[test]
    fn sh_quotes_and_escapes() {
        let sh = |l| words(l, Shell::Sh);
        assert_eq!(
            sh(r#"git commit -m "a; b | c" 'd && e' f\ g"#),
            w(&[&["git", "commit", "-m", "a; b | c", "d && e", "f g"]])
        );
        assert_eq!(
            sh(r#"echo "a \"b\" \$c \x""#),
            w(&[&["echo", r#"a "b" $c \x"#]])
        );
        assert_eq!(sh(r"echo $'a\'b' x"), w(&[&["echo", "a'b", "x"]]));
        assert_eq!(sh("echo \"a\nb\""), w(&[&["echo", "a\nb"]]));
        let s = parse("echo $HOME/x 'y'", Shell::Sh).unwrap();
        let ws = &s.commands[0].words;
        assert!(ws[0].literal && !ws[1].literal && ws[2].literal && ws[2].quoted);
        assert_eq!(ws[1].text, "$HOME/x");
    }

    #[test]
    fn sh_substitutions_run_as_commands() {
        let sh = |l| words(l, Shell::Sh);
        assert_eq!(
            sh("kill $(pidof x)"),
            w(&[&["kill", "$(pidof x)"], &["pidof", "x"]])
        );
        assert_eq!(
            sh("kill `pgrep x`"),
            w(&[&["kill", "`pgrep x`"], &["pgrep", "x"]])
        );
        assert_eq!(
            sh("echo \"a $(b \"c\") d\""),
            w(&[&["echo", "a $(b \"c\") d"], &["b", "c"]])
        );
        assert_eq!(sh("echo \"`b`\""), w(&[&["echo", "`b`"], &["b"]]));
        assert_eq!(
            sh("diff <(a) >(b)"),
            w(&[&["diff", "<(a)", ">(b)"], &["a"], &["b"]])
        );
        assert_eq!(
            sh("echo $(a $(b))"),
            w(&[&["echo", "$(a $(b))"], &["a", "$(b)"], &["b"]])
        );
        assert_eq!(
            sh("echo $((1 + 2))"),
            w(&[&["echo", "$((1 + 2))"], &[], &["1", "+", "2"]])
        );
        // Nothing runs inside single quotes.
        assert_eq!(sh("echo '$(a)'"), w(&[&["echo", "$(a)"]]));
    }

    #[test]
    fn sh_groups_subshells_and_functions() {
        let sh = |l| words(l, Shell::Sh);
        assert_eq!(sh("(a; b) | c"), w(&[&[], &["a"], &["b"], &["c"]]));
        assert_eq!(sh("{ a; }"), w(&[&["{", "a"], &["}"]]));
        assert_eq!(sh("f() { a; }"), w(&[&["{", "a"], &["}"]]));
        assert_eq!(
            sh("if a; then b; else c; fi"),
            w(&[&["if", "a"], &["then", "b"], &["else", "c"], &["fi"]])
        );
        let s = parse("(a) | c", Shell::Sh).unwrap();
        assert!(s.commands[1].piped);
    }

    #[test]
    fn sh_case_branches_are_commands() {
        let sh = |l| words(l, Shell::Sh);
        assert_eq!(
            sh("case $x in a|b) c;; (d) e; f;& *) g;;& esac"),
            // A pattern in `( … )` reads as a group: its word counts as a
            // command, which only ever refuses more.
            w(&[
                &["case", "$x", "in"],
                &["a"],
                &["c"],
                &["e"],
                &["d"],
                &["f"],
                &["g"],
                &["esac"]
            ])
        );
        assert_eq!(
            sh("case x in\n  a)\n    b\n    ;;\nesac\nc"),
            w(&[&["case", "x", "in"], &["b"], &["esac"], &["c"]])
        );
    }

    /// Whether some command ends in the word `c` (`do c` runs it).
    fn runs_c(all: &[Vec<String>]) -> bool {
        all.iter().any(|c| c.last().is_some_and(|w| w == "c"))
    }

    /// The header of a `case` is a command of its own, so its substitutions
    /// stay when the first pattern stands on the same line, and a `case`
    /// after a keyword or in a substitution is read like any other.
    #[test]
    fn sh_case_header_and_nesting() {
        let sh = |l| words(l, Shell::Sh);
        assert_eq!(
            sh("case $(a b) in *) c;; esac"),
            w(&[&["case", "$(a b)", "in"], &["a", "b"], &["c"], &["esac"]])
        );
        assert_eq!(
            sh("case \"$(a)\" in x) c;; esac"),
            w(&[&["case", "$(a)", "in"], &["a"], &["c"], &["esac"]])
        );
        for line in [
            "for f in *; do case $f in *.txt) c;; esac; done; d",
            "if x; then case y in a) c;; esac; fi; d",
            "! case y in a) c;; esac",
            "echo $(case x in a) c;; esac) d",
            "( case x in a) c;; esac ); d",
            "case x in (a) c;; esac; d",
            "case x in a) echo $(c);; esac",
        ] {
            let all = words(line, Shell::Sh);
            assert!(runs_c(&all), "{line}: {all:?}");
        }
    }

    /// Brackets after a word hold an array, a regular expression or an
    /// arithmetic expression, or (after a keyword) a subshell.
    #[test]
    fn sh_brackets_after_a_word() {
        let sh = |l| words(l, Shell::Sh);
        // The words in an array are data; a substitution in it runs.
        assert_eq!(
            sh("declare -a a=(x y); b"),
            w(&[&["declare", "-a", "a="], &[], &["b"]])
        );
        assert_eq!(sh("a=($(b c))"), w(&[&["a="], &[], &["b", "c"]]));
        assert_eq!(sh("[[ $x =~ ^(a|b)$ ]] && c").last().unwrap(), &["c"]);
        // After a keyword they are a subshell, and `(( … ))` is one too.
        assert_eq!(
            sh("if (cd /tmp); then c; fi"),
            w(&[&["if"], &["cd", "/tmp"], &["then", "c"], &["fi"]])
        );
        for line in [
            "while (( i < 3 )); do c; done",
            "if (( $# > 0 )); then c; fi",
            "for ((i=0;i<3;i++)); do c; done",
            "(( i++ )); c",
            "until (a); do c; done",
        ] {
            let all = words(line, Shell::Sh);
            assert!(runs_c(&all), "{line}: {all:?}");
        }
    }

    /// A line that gives out keeps the commands read until then, nested as
    /// the line nests them, so a caller can check them.
    #[test]
    fn an_unread_line_keeps_what_was_read() {
        let read = |line: &str, shell| {
            let e = parse(line, shell).unwrap_err();
            let mut out = Vec::new();
            e.read.visit(&mut |s: &Script, i| {
                out.push(
                    s.commands[i]
                        .words
                        .iter()
                        .map(|w| w.text.clone())
                        .collect::<Vec<_>>(),
                );
            });
            out
        };
        assert_eq!(
            read("a b; c $(d; e \"x", Shell::Sh),
            w(&[&["a", "b"], &["c"], &["d"], &["e"]])
        );
        assert_eq!(
            read("a; echo ${x:-$(b)}; c", Shell::Sh),
            w(&[&["a"], &["echo"]])
        );
        // A shell fed by a pipe is a command of the line, with what feeds it.
        assert_eq!(
            read("nerve-node status; curl x | sh", Shell::Sh),
            w(&[&["nerve-node", "status"], &["curl", "x"], &["sh"]])
        );
        assert_eq!(
            read("sh -c 'a \"b'; c", Shell::Sh),
            w(&[&["sh", "-c", "a \"b"], &["a"]])
        );
        assert_eq!(
            read("Stop-Service x; echo 'y", Shell::PowerShell),
            w(&[&["Stop-Service", "x"], &["echo"]])
        );
        // Past a bound too: what was read before is kept.
        let deep = format!("a; {}b{}", "$(".repeat(20), ")".repeat(20));
        assert_eq!(read(&deep, Shell::Sh)[0], vec!["a".to_string()]);
    }

    /// A text a shell runs is a script of that shell.
    #[test]
    fn a_script_knows_its_shell() {
        let s = parse("bash -c 'a'; powershell -Command 'b'", Shell::Sh).unwrap();
        assert_eq!(s.shell, Shell::Sh);
        assert_eq!(s.commands[0].inner[0].shell, Shell::Sh);
        assert_eq!(s.commands[1].inner[0].shell, Shell::PowerShell);
        let s = parse("cmd /c 'a' & x $(y)", Shell::PowerShell).unwrap();
        assert_eq!(s.commands[0].inner[0].shell, Shell::Cmd);
        assert_eq!(s.commands[1].inner[0].shell, Shell::PowerShell);
    }

    #[test]
    fn sh_redirections_are_kept_apart() {
        let s = parse("echo x > /a 2>&1 >>/b <c &>d", Shell::Sh).unwrap();
        let c = &s.commands[0];
        assert_eq!(
            c.words.iter().map(|w| w.text.as_str()).collect::<Vec<_>>(),
            ["echo", "x"]
        );
        let r: Vec<_> = c.redirects.iter().map(|w| w.text.as_str()).collect();
        assert_eq!(r, ["/a", "1", "/b", "c", "d"]);
    }

    #[test]
    fn sh_here_documents_are_input() {
        let s = parse("cat <<'EOF' > f\na $(b)\nEOF\nc", Shell::Sh).unwrap();
        assert_eq!(s.commands.len(), 2);
        assert_eq!(s.commands[0].input, ["a $(b)\n"]);
        assert!(s.commands[0].inner.is_empty(), "quoted: nothing runs");
        assert_eq!(s.commands[1].words[0].text, "c");
        // Unquoted, its substitutions run; `<<-` strips tabs before the end.
        let s = parse("cat <<-EOF\n\ta $(b)\n\tEOF\n", Shell::Sh).unwrap();
        assert_eq!(s.commands.len(), 1);
        assert_eq!(s.commands[0].inner[0].commands[0].words[0].text, "b");
        // Two on one line: the second body follows the first.
        let s = parse("a <<X; b <<Y\n1\nX\n2\nY\nc", Shell::Sh).unwrap();
        let input: Vec<_> = s.commands.iter().map(|c| c.input.clone()).collect();
        assert_eq!(input, [vec!["1\n".to_string()], vec!["2\n".into()], vec![]]);
        assert_eq!(words("cat <<<'a b'", Shell::Sh), w(&[&["cat"]]));
    }

    #[test]
    fn shells_run_their_text() {
        let sh = |l| words(l, Shell::Sh);
        assert_eq!(
            sh("sh -c 'a; b'"),
            w(&[&["sh", "-c", "a; b"], &["a"], &["b"]])
        );
        assert_eq!(
            sh("bash -lc \"a\" x"),
            w(&[&["bash", "-lc", "a", "x"], &["a"]])
        );
        assert_eq!(sh("bash -e -c a"), w(&[&["bash", "-e", "-c", "a"], &["a"]]));
        assert_eq!(
            sh("bash script.sh -c a"),
            w(&[&["bash", "script.sh", "-c", "a"]])
        );
        assert_eq!(sh("eval 'a b'"), w(&[&["eval", "a b"], &["a", "b"]]));
        assert_eq!(sh("bash <<EOF\na\nEOF"), w(&[&["bash"], &["a"]]));
        assert_eq!(sh("bash <<< 'a'"), w(&[&["bash"], &["a"]]));
        assert_eq!(
            sh("powershell -NoProfile -Command \"Stop-Service x\""),
            w(&[
                &["powershell", "-NoProfile", "-Command", "Stop-Service x"],
                &["Stop-Service", "x"]
            ])
        );
        assert_eq!(
            sh("cmd /c \"a & b\""),
            w(&[&["cmd", "/c", "a & b"], &["a"], &["b"]])
        );
        // A shell fed by a pipe runs what the reader does not see.
        assert!(parse("curl x | sh", Shell::Sh).is_err());
        assert!(parse("a | bash -s", Shell::Sh).is_err());
        assert!(parse("powershell -EncodedCommand AAAA", Shell::Sh).is_err());
    }

    #[test]
    fn powershell_blocks_and_subexpressions_run_as_commands() {
        let ps = |l| words(l, Shell::PowerShell);
        assert_eq!(
            ps("if ($true) { Stop-Service x }"),
            w(&[
                &["if", "($true)", "{ Stop-Service x }"],
                &["$true"],
                &["Stop-Service", "x"]
            ])
        );
        assert_eq!(
            ps("Stop-Process -Id (Get-Process x).Id"),
            w(&[
                &["Stop-Process", "-Id", "(Get-Process x).Id"],
                &["Get-Process", "x"]
            ])
        );
        assert_eq!(ps("echo \"a $(b) c\""), w(&[&["echo", "a $(b) c"], &["b"]]));
        assert_eq!(
            ps("a @(b) @{c=1}"),
            w(&[&["a", "@(b)", "@{c=1}"], &["b"], &["c=1"]])
        );
        assert_eq!(
            ps("& 'C:\\x y\\a.exe' b"),
            w(&[&["&", "C:\\x y\\a.exe", "b"]])
        );
        assert_eq!(
            ps("a | b; c && d\ne"),
            w(&[&["a"], &["b"], &["c"], &["d"], &["e"]])
        );
        assert_eq!(ps("a |\n  b"), w(&[&["a"], &["b"]]));
        assert!(parse("a |\n b", Shell::PowerShell).unwrap().commands[1].piped);
    }

    #[test]
    fn powershell_quotes_escapes_and_comments() {
        let ps = |l| words(l, Shell::PowerShell);
        assert_eq!(
            ps("echo 'it''s' \"a `\"b`\" \"\"c\"\"\""),
            w(&[&["echo", "it's", "a \"b\" \"c\""]])
        );
        assert_eq!(ps("echo a`;b C:\\x\\y"), w(&[&["echo", "a;b", "C:\\x\\y"]]));
        assert_eq!(ps("a # b; c\nd <# e\nf #> g"), w(&[&["a"], &["d", "g"]]));
        assert_eq!(ps("echo ‘a b’ “c d”"), w(&[&["echo", "a b", "c d"]]));
        assert_eq!(ps("@'\na; b\n'@ | x"), w(&[&["a; b"], &["x"]]));
        let s = parse(
            "Get-Item $env:ProgramData\\Nerve 2>&1 > out",
            Shell::PowerShell,
        )
        .unwrap();
        let c = &s.commands[0];
        assert_eq!(c.words[1].text, "$env:ProgramData\\Nerve");
        assert!(!c.words[1].literal);
        assert_eq!(c.redirects[0].text, "out");
    }

    #[test]
    fn cmd_splits_and_quotes() {
        let cmd = |l| words(l, Shell::Cmd);
        assert_eq!(
            cmd("a & b && c || d | e"),
            w(&[&["a"], &["b"], &["c"], &["d"], &["e"]])
        );
        assert_eq!(cmd("echo \"a & b\" c^&d"), w(&[&["echo", "a & b", "c&d"]]));
        assert_eq!(
            cmd("@echo off\nrem a & b\n:: c\nd"),
            w(&[&["echo", "off"], &["d"]])
        );
        assert_eq!(
            cmd("if exist x (a & b) else (c)"),
            w(&[&["if", "exist", "x", "else"], &["a"], &["b"], &["c"]])
        );
        assert_eq!(cmd("echo a)"), w(&[&["echo", "a)"]]));
        assert_eq!(cmd("dir > out 2>&1"), w(&[&["dir"]]));
        let s = parse("echo %PATH%", Shell::Cmd).unwrap();
        assert!(!s.commands[0].words[1].literal);
    }

    #[test]
    fn what_cannot_be_read_is_unparsed() {
        for (line, shell) in [
            ("echo 'a", Shell::Sh),
            ("echo \"a", Shell::Sh),
            ("echo $(a", Shell::Sh),
            ("echo `a", Shell::Sh),
            ("(a", Shell::Sh),
            ("a)", Shell::Sh),
            ("a;; b", Shell::Sh),
            ("cat <<EOF\na", Shell::Sh),
            ("cat <<EOF", Shell::Sh),
            ("echo ${x:-$(a)}", Shell::Sh),
            ("sh -c 'a \"b'", Shell::Sh),
            ("echo 'a", Shell::PowerShell),
            ("if ($a) { b", Shell::PowerShell),
            ("a <# b", Shell::PowerShell),
            ("a --% b", Shell::PowerShell),
            ("echo \"a", Shell::Cmd),
            ("(a & b", Shell::Cmd),
        ] {
            assert!(parse(line, shell).is_err(), "{line:?} {shell:?}");
        }
    }

    #[test]
    fn shell_by_program() {
        assert_eq!(Shell::of_program("/bin/sh"), Shell::Sh);
        assert_eq!(Shell::of_program("/usr/bin/bash"), Shell::Sh);
        assert_eq!(Shell::of_program("powershell.exe"), Shell::PowerShell);
        assert_eq!(
            Shell::of_program("C:\\Program Files\\PowerShell\\7\\pwsh.exe"),
            Shell::PowerShell
        );
        assert_eq!(
            Shell::of_program("C:\\Windows\\System32\\CMD.EXE"),
            Shell::Cmd
        );
        assert_eq!(base_name("/usr/bin/nerve-node", false), "nerve-node");
        assert_eq!(base_name("C:\\x\\Nerve-Node.EXE", true), "nerve-node");
        assert_eq!(base_name("C:\\x\\a", false), "C:\\x\\a");
    }

    /// The program the first command runs, and its arguments.
    fn ran(line: &str, shell: Shell) -> Option<(String, String)> {
        let s = parse(line, shell).unwrap_or_else(|e| panic!("{line:?}: {e:?}"));
        run(&s.commands[0], shell).map(|r| {
            let args: Vec<_> = r.args.iter().map(|w| w.text.as_str()).collect();
            (r.name, args.join(" "))
        })
    }

    #[test]
    fn wrappers_are_unwrapped_to_the_program() {
        use Shell::*;
        for (line, shell, name, args) in [
            ("sudo systemctl stop x", Sh, "systemctl", "stop x"),
            (
                "sudo -n -u root systemctl stop x",
                Sh,
                "systemctl",
                "stop x",
            ),
            ("sudo -uroot -E systemctl stop x", Sh, "systemctl", "stop x"),
            (
                "sudo --user root -- systemctl stop x",
                Sh,
                "systemctl",
                "stop x",
            ),
            ("doas -u root systemctl stop x", Sh, "systemctl", "stop x"),
            ("env X=1 sudo systemctl stop x", Sh, "systemctl", "stop x"),
            (
                "env -i -u HOME X=1 systemctl stop x",
                Sh,
                "systemctl",
                "stop x",
            ),
            ("env -S 'systemctl stop' x", Sh, "systemctl", "stop x"),
            (
                "timeout 30 sudo systemctl stop x",
                Sh,
                "systemctl",
                "stop x",
            ),
            (
                "timeout -s KILL -k 5 30 systemctl stop x",
                Sh,
                "systemctl",
                "stop x",
            ),
            (
                "nohup nice -n 5 ionice -c 3 systemctl stop x",
                Sh,
                "systemctl",
                "stop x",
            ),
            ("nice -10 systemctl stop x", Sh, "systemctl", "stop x"),
            (
                "time -p stdbuf -oL systemctl stop x",
                Sh,
                "systemctl",
                "stop x",
            ),
            ("xargs -0 -n 1 kill -9", Sh, "kill", "-9"),
            ("exec -a y systemctl stop x", Sh, "systemctl", "stop x"),
            ("command systemctl stop x", Sh, "systemctl", "stop x"),
            ("setsid -f busybox kill 1", Sh, "kill", "1"),
            (
                "X=1 Y=2 /usr/bin/systemctl stop x",
                Sh,
                "systemctl",
                "stop x",
            ),
            ("! { if then systemctl stop x", Sh, "systemctl", "stop x"),
            ("{systemctl stop x;}", Sh, "systemctl", "stop x"),
            (
                "& 'C:\\x\\Nerve-Node.exe' status",
                PowerShell,
                "nerve-node",
                "status",
            ),
            (
                "Start-Process sc.exe -ArgumentList 'stop','x' -Verb RunAs",
                PowerShell,
                "sc",
                "stop x",
            ),
            (
                "Start-Process -Wait -FilePath sc -ArgumentList \"stop x\"",
                PowerShell,
                "sc",
                "stop x",
            ),
            ("start C:\\w\\sc.exe 'stop x'", PowerShell, "sc", "stop x"),
            ("$null = Stop-Service x", PowerShell, "stop-service", "x"),
            ("start \"\" /b sc stop x", Cmd, "sc", "stop x"),
            ("if exist C:\\x sc stop x", Cmd, "sc", "stop x"),
            ("if /i not %a%==b sc stop x", Cmd, "sc", "stop x"),
            ("if %a% equ 1 sc stop x", Cmd, "sc", "stop x"),
            ("for %i in (1) do sc stop x", Cmd, "sc", "stop x"),
            ("call sc stop x", Cmd, "sc", "stop x"),
        ] {
            assert_eq!(
                ran(line, shell),
                Some((name.to_string(), args.to_string())),
                "{line}"
            );
        }
        // Nothing runs: a lookup, a wrapper alone, only keywords.
        for (line, shell) in [
            ("command -v systemctl", Sh),
            ("sudo -l", Sh),
            ("env", Sh),
            ("then", Sh),
            ("for %i in (1)", Cmd),
        ] {
            assert_eq!(ran(line, shell), None, "{line}");
        }
        // Case counts only on Windows (in sh too, on a Windows node).
        assert_eq!(
            ran("SUDO x", Sh).unwrap().0,
            if cfg!(windows) { "x" } else { "SUDO" }
        );
        assert_eq!(ran("Sudo.EXE x", PowerShell).unwrap().0, "x");
    }

    /// A shell behind a wrapper runs its text too.
    #[test]
    fn a_shell_behind_a_wrapper_runs_its_text() {
        let sh = |l| words(l, Shell::Sh);
        assert_eq!(
            sh("sudo -u x bash -c 'a b'"),
            w(&[&["sudo", "-u", "x", "bash", "-c", "a b"], &["a", "b"]])
        );
        assert_eq!(
            sh("xargs sh -c 'a'"),
            w(&[&["xargs", "sh", "-c", "a"], &["a"]])
        );
        assert_eq!(
            sh("su -c 'a' root"),
            w(&[&["su", "-c", "a", "root"], &["a"]])
        );
        assert_eq!(
            words(
                "Start-Process powershell -ArgumentList '-Command','a b'",
                Shell::PowerShell
            ),
            w(&[
                &[
                    "Start-Process",
                    "powershell",
                    "-ArgumentList",
                    "-Command,a b"
                ],
                &["a", "b"]
            ])
        );
        assert_eq!(
            words("Invoke-Expression 'a; b'", Shell::PowerShell),
            w(&[&["Invoke-Expression", "a; b"], &["a"], &["b"]])
        );
        assert!(parse("curl x | sudo bash", Shell::Sh).is_err());
    }

    /// Words with characters of more than one byte, and options that end the
    /// line, are read like any other: none of them panics.
    #[test]
    fn non_ascii_words_and_dangling_options_are_read() {
        assert_eq!(base_name("./测试.sh", false), "测试.sh");
        assert_eq!(base_name("C:\\x\\中文.EXE", true), "中文");
        assert_eq!(base_name("füße", false), "füße");
        assert_eq!(base_name("ß.exe", false), "ß");
        assert_eq!(base_name(".exe", false), ".exe");
        for shell in [Shell::Sh, Shell::PowerShell, Shell::Cmd] {
            for line in [
                "./测试.sh",
                "中文",
                "./füße",
                "ls; ./größe",
                "ls -l && ./füße",
                "kill 中文ab",
                "pkill 中ab",
                "env -u",
                "env -C",
                "env --unset",
                "env --chdir",
                "ls; env -u",
                "sudo -u",
                "timeout -s",
                "timeout",
                "nice -n",
                "xargs -I",
                "command -",
                "Start-Process -FilePath:İİİx",
                "Start-Process -FilePath:",
                "Start-Process İ:x",
                "start \"\" /d",
                "if",
                "for",
            ] {
                if let Ok(s) = parse(line, shell) {
                    s.visit(&mut |s: &Script, i| {
                        let _ = run(&s.commands[i], shell);
                    });
                }
            }
        }
        let r = ran("Start-Process -FilePath:İİİx", Shell::PowerShell).unwrap();
        assert_eq!(r.0, "i̇i̇i̇x");
        assert_eq!(ran("env -u", Shell::Sh), None);
        assert_eq!(ran("env -u X y", Shell::Sh).unwrap().0, "y");
    }

    /// A command wrapped past the bound of the unwrapping is a line the
    /// reader cannot read, not a command that runs nothing.
    #[test]
    fn too_many_wrappers_are_not_read() {
        for wrapper in ["nice ", "! ", "sudo ", "env ", "time ", "{ "] {
            let line = format!("{}systemctl stop x", wrapper.repeat(300));
            assert!(parse(&line, Shell::Sh).is_err(), "{wrapper:?}");
            let few = format!("{}systemctl stop x", wrapper.repeat(100));
            assert_eq!(ran(&few, Shell::Sh).map(|r| r.0), Some("systemctl".into()));
        }
    }

    /// A line built to drown the reader is refused at a bound, quickly, and
    /// one just inside the bounds is read.
    #[test]
    fn the_bounds_hold() {
        let deep = |n: usize| format!("{}a{}", "$(".repeat(n), ")".repeat(n));
        assert!(parse(&deep(MAX_DEPTH - 1), Shell::Sh).is_ok());
        assert!(parse(&deep(MAX_DEPTH), Shell::Sh).is_err());
        assert!(parse(&deep(100_000), Shell::Sh).is_err());
        let ps = format!("{}a{}", "(".repeat(100_000), ")".repeat(100_000));
        assert!(parse(&ps, Shell::PowerShell).is_err());
        let nested = format!("{}a", "eval ".repeat(40));
        assert!(parse(&nested, Shell::Sh).is_err());
        assert!(parse(&"a;".repeat(MAX_COMMANDS), Shell::Sh).is_ok());
        assert!(parse(&"a;".repeat(MAX_COMMANDS + 1), Shell::Sh).is_err());
        // Each level of `sh -c` reads its text again: past the work bound
        // the line is not read, though no single level is deep or long.
        let wide = format!("a {}", "x".repeat(MAX_WORK / 8));
        let mut line = wide.clone();
        for _ in 0..10 {
            line = format!("sh -c {line:?}");
        }
        assert!(line.len() < MAX_WORK);
        assert!(parse(&line, Shell::Sh).is_err());
        assert!(parse(&wide, Shell::Sh).is_ok());
    }

    /// Every command read before the line gave out, at any depth.
    fn unread(line: &str, shell: Shell) -> (Vec<Vec<String>>, bool) {
        let e = parse(line, shell).unwrap_err();
        let mut out = Vec::new();
        e.read.visit(&mut |s: &Script, i| {
            out.push(s.commands[i].words.iter().map(|w| w.text.clone()).collect());
        });
        (out, e.read.commands.last().is_some_and(|c| c.piped))
    }

    /// The command the line gives out in keeps the text it runs, its pipe,
    /// the substitutions of its last word and a here-document that does not
    /// end.
    #[test]
    fn the_command_a_line_gives_out_in_is_kept_whole() {
        let (read, _) = unread("bash -c 'a b' ${X:-$(c)}", Shell::Sh);
        assert!(read.contains(&vec!["a".to_string(), "b".to_string()]), "{read:?}");
        let (read, _) = unread("echo \"$(a) ${X:-$(b)}\"", Shell::Sh);
        assert!(read.contains(&vec!["a".to_string()]), "{read:?}");
        let (read, _) = unread("echo $(a) \"x $(b) ${X:-$(c)}\" y", Shell::Sh);
        assert!(read.contains(&vec!["a".to_string()]), "{read:?}");
        assert!(read.contains(&vec!["b".to_string()]), "{read:?}");
        let (_, piped) = unread("a | b ${X:-$(c)}", Shell::Sh);
        assert!(piped);
        let (read, _) = unread("bash <<'EOF'\na b\n", Shell::Sh);
        assert!(read.contains(&vec!["a".to_string(), "b".to_string()]), "{read:?}");
        let (read, _) = unread("cat <<EOF\n$(a b)\n", Shell::Sh);
        assert!(read.contains(&vec!["a".to_string(), "b".to_string()]), "{read:?}");
        let (read, _) = unread("echo $(a) \"${X:-$(c)}", Shell::PowerShell);
        assert!(read.contains(&vec!["a".to_string()]), "{read:?}");
    }

    /// `<<` shifts in arithmetic: the line is read, and what follows is
    /// read as commands.
    #[test]
    fn a_shift_in_arithmetic_is_not_a_here_document() {
        for line in [
            "echo $((1 << 4)); b",
            "echo $((1<<4)); b",
            "(( x = 1 << 4 )); b",
            "x=$(( y << 2 )); b",
            "for ((i=0; i < 1 << 2; i++)); do :; done; b",
            "echo \"$((1 << 4))\"; b",
        ] {
            let all = words(line, Shell::Sh);
            assert_eq!(all.last().unwrap(), &["b"], "{line}: {all:?}");
        }
        // Outside arithmetic it is a here-document still.
        assert!(parse("b <<4", Shell::Sh).is_err());
        assert!(parse("echo $(a <<EOF\nx\nEOF\n)", Shell::Sh).is_ok());
    }

    /// fish: `( … )` runs, and `and`, `or` and `not` lead a command.
    #[test]
    fn fish_brackets_run_and_its_keywords_lead() {
        assert_eq!(Shell::of_program("/usr/bin/fish"), Shell::Fish);
        assert_eq!(Shell::of_program("fish"), Shell::Fish);
        assert_eq!(Shell::of_program("/usr/bin/fishfood"), Shell::Sh);
        assert_eq!(
            words("set v (a b); c", Shell::Fish),
            w(&[&["set", "v"], &["a", "b"], &["c"]])
        );
        assert_eq!(
            words("fish -c 'echo (a b)'", Shell::Sh),
            w(&[&["fish", "-c", "echo (a b)"], &["echo"], &["a", "b"]])
        );
        assert_eq!(
            words("bash -c 'echo (a b)'", Shell::Fish)[1],
            vec!["echo".to_string()]
        );
        for (line, name) in [
            ("true; and a b", "a"),
            ("not a b", "a"),
            ("a; or b", "b"),
        ] {
            assert_eq!(ran_last(line, Shell::Fish), Some(name.into()), "{line}");
        }
        assert_eq!(ran("and a", Shell::Fish).unwrap().0, "a");
        assert_eq!(ran("and a", Shell::Sh).unwrap().0, "and");
        // `eval` stays in the shell it stands in.
        assert_eq!(
            words("eval 'echo (a)'", Shell::Fish).last().unwrap(),
            &["a"]
        );
    }

    fn ran_last(line: &str, shell: Shell) -> Option<String> {
        let s = parse(line, shell).unwrap();
        run(s.commands.last()?, shell).map(|r| r.name)
    }

    /// A shell with `-s`, `su` and `sudo -s` or `-i` run their input.
    #[test]
    fn a_shell_that_runs_its_input_with_arguments() {
        for line in [
            "bash -s x <<'EOF'\na b\nEOF",
            "bash -s -- --verbose <<'EOF'\na b\nEOF",
            "sh -es x <<'EOF'\na b\nEOF",
            "sudo bash -s -- x <<'EOF'\na b\nEOF",
            "su root <<'EOF'\na b\nEOF",
            "su - <<'EOF'\na b\nEOF",
            "sudo su <<'EOF'\na b\nEOF",
            "sudo -s <<'EOF'\na b\nEOF",
            "sudo -i <<'EOF'\na b\nEOF",
            "sudo -u root -i <<'EOF'\na b\nEOF",
            "doas -s <<'EOF'\na b\nEOF",
            "sudo --login <<'EOF'\na b\nEOF",
            "sudo sh -s x <<< 'a b'",
        ] {
            let all = words(line, Shell::Sh);
            assert_eq!(all.last().unwrap(), &["a", "b"], "{line}: {all:?}");
        }
        // Without input, or with a script file, nothing is read as one.
        assert_eq!(words("bash script.sh x", Shell::Sh).len(), 1);
        assert_eq!(words("sudo -u root ls", Shell::Sh).len(), 1);
        assert_eq!(ran("sudo -s ls", Shell::Sh).unwrap().0, "ls");
        assert_eq!(ran("sudo -u root", Shell::Sh), None);
        // The shell of a pipe is not read.
        assert!(parse("a | su root", Shell::Sh).is_err());
    }

    /// In PowerShell a quoted string that starts a statement is a value,
    /// unless `&`, `.` or `Start-Process` runs it.
    #[test]
    fn a_quoted_string_in_powershell_is_a_value() {
        use Shell::PowerShell as Ps;
        for line in [
            "'x' a",
            "\"x\" -replace 'a','b'",
            "$n = 'x'",
            "$n = \"x\"",
            "$n = 'x' a",
            "'x' | Set-Content a",
        ] {
            assert_eq!(ran(line, Ps), None, "{line}");
        }
        for (line, name) in [
            ("& 'x' a", "x"),
            (". 'x' a", "x"),
            ("$r = & 'x' a", "x"),
            ("Start-Process 'x' a", "x"),
            ("Start-Process -FilePath 'x'", "x"),
            ("& \"x\"", "x"),
            ("x a", "x"),
        ] {
            assert_eq!(ran(line, Ps).map(|r| r.0), Some(name.into()), "{line}");
        }
        // In sh and cmd a quoted word is a program as before.
        assert_eq!(ran("'x' a", Shell::Sh).unwrap().0, "x");
        assert_eq!(ran("\"x\" a", Shell::Cmd).unwrap().0, "x");
    }

    /// `coproc NAME { … }` and `coproc cmd` run the command.
    #[test]
    fn coproc_runs_its_command() {
        assert_eq!(ran("coproc X { a b; }", Shell::Sh).unwrap().0, "a");
        assert_eq!(ran("coproc { a b; }", Shell::Sh).unwrap().0, "a");
        assert_eq!(ran("coproc a b", Shell::Sh).unwrap().0, "a");
        assert_eq!(ran("coproc X {a b; }", Shell::Sh).unwrap().0, "a");
    }

    /// zsh's `=( … )` runs its commands.
    #[test]
    fn zsh_process_substitution_runs() {
        assert_eq!(
            words("diff =(a b) x", Shell::Sh),
            w(&[&["diff", "=(a b)", "x"], &["a", "b"]])
        );
        // An assignment is not one.
        assert_eq!(words("x=(a b)", Shell::Sh), w(&[&["x="], &[]]));
    }
}
