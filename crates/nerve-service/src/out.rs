//! One output style for the commands of both programs (#213): a head line
//! with the program, its version and its state; a block of short aligned
//! label and value lines; lists as aligned columns; and set apart at the
//! end, what to look at (`Warning`, `Note`) and what to do (`Next`, a
//! command each). What a value needs to explain belongs in `Next` or in the
//! docs, not in the line.
//!
//! A change says its lines as it makes them ([`Said`]), and its warnings,
//! notes and next steps come together at the end. Bold and colour mark the
//! state only on a real terminal: never in a pipe, a log or with `NO_COLOR`.
//! `--json` never comes here.

use std::io::Write;

/// Whether the output may carry bold and colour.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Style {
    color: bool,
}

impl Style {
    /// No bold or colour: a pipe, a file, a test.
    pub const PLAIN: Style = Style { color: false };
    /// Bold and colour.
    pub const COLOR: Style = Style { color: true };

    /// The style of stdout: colour only where it is a terminal.
    pub fn stdout() -> Style {
        use std::io::IsTerminal;
        Style::of(std::io::stdout().is_terminal() && terminal_colors(true))
    }

    /// The style of stderr, for the error line.
    pub fn stderr() -> Style {
        use std::io::IsTerminal;
        Style::of(std::io::stderr().is_terminal() && terminal_colors(false))
    }

    /// The style of a terminal or not, as `NO_COLOR` and `TERM` of this
    /// process allow.
    fn of(terminal: bool) -> Style {
        Style::decide(
            terminal,
            std::env::var_os("NO_COLOR"),
            std::env::var_os("TERM"),
        )
    }

    /// Colour on a `terminal`, unless `NO_COLOR` is set to anything but
    /// empty (no-color.org) or the terminal is `dumb`.
    pub fn decide(
        terminal: bool,
        no_color: Option<std::ffi::OsString>,
        term: Option<std::ffi::OsString>,
    ) -> Style {
        let no_color = no_color.is_some_and(|v| !v.is_empty());
        let dumb = term.is_some_and(|t| t == "dumb");
        Style {
            color: terminal && !no_color && !dumb,
        }
    }

    pub fn has_color(&self) -> bool {
        self.color
    }

    /// `text` in `tone`, bold; as it is without colour.
    pub fn paint(&self, text: &str, tone: Tone) -> String {
        if !self.color {
            return text.to_string();
        }
        let code = match tone {
            Tone::Good => "1;32",
            Tone::Warn => "1;33",
            Tone::Bad => "1;31",
            Tone::Plain => "1",
        };
        format!("\x1b[{code}m{text}\x1b[0m")
    }
}

/// Whether the console takes colour codes. On Windows they are turned on
/// for this console first; a console that cannot gets none.
fn terminal_colors(stdout: bool) -> bool {
    #[cfg(windows)]
    return crate::win::console::virtual_terminal(stdout);
    #[cfg(not(windows))]
    {
        let _ = stdout;
        true
    }
}

/// How a state reads: fine, needs a look, or wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Good,
    Warn,
    Bad,
    Plain,
}

/// What one command shows: a head line, label and value lines, lists, and
/// set apart the warnings, notes and next steps.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Page {
    title: String,
    state: Option<(String, Tone)>,
    rows: Vec<(String, String)>,
    lists: Vec<(Option<String>, Vec<Vec<String>>)>,
    warnings: Vec<String>,
    notes: Vec<String>,
    next: Vec<(String, String)>,
}

/// The least width of the labels, so that the pages of both programs line
/// up alike.
const LABEL: usize = 12;

impl Page {
    /// A page whose head line names `program` ("Nerve center") and its
    /// `version`.
    pub fn new(program: &str, version: &str) -> Page {
        Page {
            title: format!("{program} {version}"),
            ..Page::default()
        }
    }

    /// The version on the head line in place of the one given: the
    /// installed program's, which an update changed.
    pub fn set_version(&mut self, version: &str) {
        if let Some((program, _)) = self.title.rsplit_once(' ') {
            self.title = format!("{program} {version}");
        }
    }

    /// The program's state after its name, as `tone` reads.
    pub fn state(mut self, state: impl Into<String>, tone: Tone) -> Page {
        self.state = Some((state.into(), tone));
        self
    }

    /// A label and its value.
    pub fn row(&mut self, label: impl Into<String>, value: impl Into<String>) -> &mut Page {
        self.rows.push((label.into(), value.into()));
        self
    }

    /// A list as aligned columns, under `title` where it has one.
    pub fn list(&mut self, title: Option<&str>, rows: Vec<Vec<String>>) -> &mut Page {
        if !rows.is_empty() {
            self.lists.push((title.map(str::to_string), rows));
        }
        self
    }

    /// Something to look at, set apart under `Warning`.
    pub fn warn(&mut self, text: impl Into<String>) -> &mut Page {
        let text = text.into();
        if !self.warnings.contains(&text) {
            self.warnings.push(text);
        }
        self
    }

    /// Something worth knowing, set apart under `Note`.
    pub fn note(&mut self, text: impl Into<String>) -> &mut Page {
        let text = text.into();
        if !self.notes.contains(&text) {
            self.notes.push(text);
        }
        self
    }

    /// A next step: what it does (`""` for none) and its command.
    pub fn next(&mut self, what: impl Into<String>, command: impl Into<String>) -> &mut Page {
        let step = (what.into(), command.into());
        if !self.next.contains(&step) {
            self.next.push(step);
        }
        self
    }

    /// Whether the page has next steps.
    pub fn has_next(&self) -> bool {
        !self.next.is_empty()
    }

    /// The page as text, a line each, ending in a line break. Every text
    /// on it is one line without control characters ([`one_line`]): a
    /// value may come from a machine, and the colour is added after.
    pub fn render(&self, style: Style) -> String {
        let mut blocks: Vec<Vec<String>> = Vec::new();
        let mut head = one_line(&self.title);
        if let Some((state, tone)) = &self.state {
            head.push_str(" · ");
            head.push_str(&style.paint(&one_line(state), *tone));
        }
        blocks.push(vec![head]);
        if !self.rows.is_empty() {
            let width = self
                .rows
                .iter()
                .map(|(l, _)| width(&one_line(l)) + 3)
                .max()
                .unwrap_or(0)
                .max(LABEL);
            blocks.push(
                self.rows
                    .iter()
                    .map(|(l, v)| {
                        format!("  {}", pad(&one_line(l), width) + &one_line(v))
                            .trim_end()
                            .to_string()
                    })
                    .collect(),
            );
        }
        for (title, rows) in &self.lists {
            let mut block = Vec::new();
            let indent = match title {
                Some(t) => {
                    block.push(format!("  {}", one_line(t)));
                    "    "
                }
                None => "  ",
            };
            block.extend(columns(rows).into_iter().map(|l| format!("{indent}{l}")));
            blocks.push(block);
        }
        blocks.extend(set_apart(
            "Warning",
            Tone::Warn,
            &bare(&self.warnings),
            style,
        ));
        blocks.extend(set_apart("Note", Tone::Plain, &bare(&self.notes), style));
        blocks.extend(set_apart("Next", Tone::Plain, &self.next, style));
        let mut text = blocks
            .into_iter()
            .map(|b| b.join("\n"))
            .collect::<Vec<_>>()
            .join("\n\n");
        text.push('\n');
        text
    }
}

/// `items` without a label each.
fn bare(items: &[String]) -> Vec<(String, String)> {
    items.iter().map(|i| (String::new(), i.clone())).collect()
}

/// A block set apart under `label` ("Next"): the first item beside the
/// label, the others under it, their labels (`what`, with a colon) and
/// their texts aligned. None for no items.
fn set_apart(
    label: &str,
    tone: Tone,
    items: &[(String, String)],
    style: Style,
) -> Option<Vec<String>> {
    if items.is_empty() {
        return None;
    }
    let items: Vec<(String, String)> = items
        .iter()
        .map(|(w, t)| (one_line(w), one_line(t)))
        .collect();
    let what = items
        .iter()
        .filter(|(w, _)| !w.is_empty())
        .map(|(w, _)| width(w) + 3)
        .max()
        .unwrap_or(0);
    let lead = width(label) + 2;
    Some(
        items
            .iter()
            .enumerate()
            .map(|(i, (w, text))| {
                let start = match i {
                    0 => style.paint(label, tone) + &" ".repeat(lead - width(label)),
                    _ => " ".repeat(lead),
                };
                let w = match w.is_empty() {
                    true => " ".repeat(what),
                    false => pad(&format!("{w}:"), what),
                };
                format!("{start}{w}{text}").trim_end().to_string()
            })
            .collect(),
    )
}

/// `rows` as aligned columns, three blanks apart; the last column is not
/// padded. Each cell is one line without control characters
/// ([`one_line`]).
pub fn columns(rows: &[Vec<String>]) -> Vec<String> {
    let rows: Vec<Vec<String>> = rows
        .iter()
        .map(|r| r.iter().map(|c| one_line(c)).collect())
        .collect();
    let rows = &rows[..];
    let n = rows.iter().map(Vec::len).max().unwrap_or(0);
    let widths: Vec<usize> = (0..n)
        .map(|i| {
            rows.iter()
                .filter_map(|r| r.get(i))
                .map(|c| width(c))
                .max()
                .unwrap_or(0)
        })
        .collect();
    rows.iter()
        .map(|r| {
            let mut line = String::new();
            for (i, c) in r.iter().enumerate() {
                match i + 1 == r.len() {
                    true => line.push_str(c),
                    false => line.push_str(&pad(c, widths[i] + 3)),
                }
            }
            line.trim_end().to_string()
        })
        .collect()
}

/// `text` as one line that does nothing to a terminal: control characters
/// (C0, DEL and C1, escapes and line breaks among them) and the Unicode
/// line and paragraph separators become blanks. A machine's name, system
/// or version reaches a page as it sent it, and the owner's terminal must
/// show it, not act on it.
pub fn one_line(text: &str) -> String {
    text.chars()
        .map(
            |c| match c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') {
                true => ' ',
                false => c,
            },
        )
        .collect()
}

/// The width of `s` on a terminal, a char each.
fn width(s: &str) -> usize {
    s.chars().count()
}

/// `s` with blanks up to `to` chars.
fn pad(s: &str, to: usize) -> String {
    let mut p = s.to_string();
    p.push_str(&" ".repeat(to.saturating_sub(width(s))));
    p
}

/// `text` with a capital first letter, as a sentence set apart starts.
pub fn capital(text: &str) -> String {
    let mut c = text.chars();
    c.next()
        .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
        .unwrap_or_default()
}

/// A time in milliseconds since 1970 as people read it, in UTC:
/// `2026-11-13 14:02:07`.
pub fn time(ms: u64) -> String {
    let secs = ms / 1000;
    let (days, rest) = (secs / 86_400, secs % 86_400);
    // The civil date of a day count (Howard Hinnant's days_from_civil,
    // reversed).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// The line a failed command ends with on stderr: the program's name, red
/// on a terminal, and why.
pub fn error(program: &str, why: &str, style: Style) -> String {
    format!("{} {why}", style.paint(&format!("{program}:"), Tone::Bad))
}

/// The lines a change says as it makes them, written on as they come; its
/// warnings (`Warning: …`), notes (`note: …`) and next steps (`Next: …`)
/// are kept for the end ([`Said::finish`]), set apart. A prompt that waits
/// for an answer on the same line is written when it is flushed. The lines
/// themselves stay as they are: `--json` gives them to programs, and the
/// desktop app reads them.
pub struct Said<'a> {
    out: &'a mut dyn Write,
    style: Style,
    line: Vec<u8>,
    page: Page,
}

impl<'a> Said<'a> {
    pub fn new(out: &'a mut dyn Write, style: Style) -> Said<'a> {
        Said {
            out,
            style,
            line: Vec::new(),
            page: Page::default(),
        }
    }

    /// Takes one whole line: a warning, note or next step is kept, any
    /// other is written.
    fn take(&mut self, line: &str) -> std::io::Result<()> {
        let kept = |prefixes: &[&str]| {
            prefixes
                .iter()
                .find_map(|p| line.strip_prefix(p))
                .map(str::to_string)
        };
        if let Some(w) = kept(&["Warning: ", "warning: "]) {
            self.page.warn(capital(&w));
        } else if let Some(n) = kept(&["Note: ", "note: "]) {
            self.page.note(capital(&n));
        } else if let Some(n) = kept(&["Next: ", "next: "]) {
            self.page.next("", n);
        } else {
            writeln!(self.out, "{line}")?;
        }
        Ok(())
    }

    /// Writes what was kept, set apart; with `page`, that page after the
    /// lines, its warnings and next steps together with the kept ones.
    pub fn finish(mut self, page: Option<Page>) -> std::io::Result<()> {
        if !self.line.is_empty() {
            let rest = String::from_utf8_lossy(&std::mem::take(&mut self.line)).into_owned();
            self.out.write_all(rest.as_bytes())?;
        }
        let kept = std::mem::take(&mut self.page);
        let page = match page {
            Some(mut p) => {
                for w in kept.warnings {
                    p.warn(w);
                }
                for n in kept.notes {
                    p.note(n);
                }
                for (w, c) in kept.next {
                    p.next(w, c);
                }
                writeln!(self.out)?;
                p
            }
            None if kept == Page::default() => return self.out.flush(),
            None => {
                writeln!(self.out)?;
                kept
            }
        };
        // Without a head line the blocks stand alone.
        let text = page.render(self.style);
        let text = match page.title.is_empty() {
            true => text.trim_start_matches('\n').to_string(),
            false => text,
        };
        self.out.write_all(text.as_bytes())?;
        self.out.flush()
    }
}

impl Write for Said<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.line.extend_from_slice(buf);
        while let Some(end) = self.line.iter().position(|b| *b == b'\n') {
            let rest = self.line.split_off(end + 1);
            let line = std::mem::replace(&mut self.line, rest);
            let line = String::from_utf8_lossy(&line[..end]).into_owned();
            self.take(line.strip_suffix('\r').unwrap_or(&line))?;
        }
        Ok(buf.len())
    }

    /// A prompt waits on its line: it is written now.
    fn flush(&mut self) -> std::io::Result<()> {
        if !self.line.is_empty() {
            let rest = std::mem::take(&mut self.line);
            self.out.write_all(&rest)?;
        }
        self.out.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The center's status as the owner approved it (#213): the head line,
    /// the aligned rows, and the next steps apart, their commands aligned.
    #[test]
    fn a_page_reads_as_the_owner_approved_it() {
        let mut p = Page::new("Nerve center", "0.1.0").state("running as a service", Tone::Good);
        p.row("Web UI", "https://lxcpithagoras:7480")
            .row("Harnesses", "http://127.0.0.1:7481/mcp")
            .row("Machines", "none paired yet");
        p.next("Pair a machine", "sudo nerve-center pair")
            .next("Owner token", "sudo nerve-center owner-token");
        assert_eq!(
            p.render(Style::PLAIN),
            "Nerve center 0.1.0 · running as a service

  Web UI      https://lxcpithagoras:7480
  Harnesses   http://127.0.0.1:7481/mcp
  Machines    none paired yet

Next  Pair a machine:  sudo nerve-center pair
      Owner token:     sudo nerve-center owner-token
"
        );
    }

    /// Lists are aligned columns; warnings and notes stand apart, before
    /// the next steps.
    #[test]
    fn lists_line_up_and_warnings_stand_apart() {
        let mut p = Page::new("Nerve node", "0.1.0").state("running", Tone::Good);
        p.row("Sudo", "off");
        p.list(
            Some("Centers"),
            vec![
                vec!["lab".into(), "connected".into(), "folder mode".into()],
                vec!["home-server".into(), "paused".into(), "user mode".into()],
            ],
        );
        p.warn("one").warn("two").warn("one");
        p.next("", "nerve-node unlock");
        assert_eq!(
            p.render(Style::PLAIN),
            "Nerve node 0.1.0 · running

  Sudo        off

  Centers
    lab           connected   folder mode
    home-server   paused      user mode

Warning  one
         two

Next  nerve-node unlock
"
        );
    }

    /// Bold and colour only for a terminal, never with NO_COLOR or a dumb
    /// terminal; the state carries them, the rest of the page does not.
    #[test]
    fn colour_only_on_a_terminal_and_never_with_no_color() {
        assert!(Style::decide(true, None, None).has_color());
        assert!(!Style::decide(false, None, None).has_color());
        assert!(!Style::decide(true, Some("1".into()), None).has_color());
        // An empty NO_COLOR counts as not set (no-color.org).
        assert!(Style::decide(true, Some("".into()), None).has_color());
        assert!(!Style::decide(true, None, Some("dumb".into())).has_color());
        let p = Page::new("Nerve node", "0.1.0").state("not running", Tone::Bad);
        assert_eq!(p.render(Style::PLAIN), "Nerve node 0.1.0 · not running\n");
        assert_eq!(
            p.render(Style::COLOR),
            "Nerve node 0.1.0 · \x1b[1;31mnot running\x1b[0m\n"
        );
        assert_eq!(error("nerve-node", "no", Style::PLAIN), "nerve-node: no");
    }

    /// What a machine sent reaches a page as text, never as a control
    /// sequence for the terminal: escapes, C1 controls and line breaks in
    /// a value, a cell or a label become blanks (round 1 of #213's second
    /// pass, security 2).
    #[test]
    fn a_page_shows_control_characters_as_blanks() {
        let evil = "0.1\x1b]52;c;aGk=\x07\u{9b}2J\r\nx\u{2028}y";
        let mut p = Page::new("Nerve center", evil).state(evil, Tone::Good);
        p.row(evil, evil);
        p.list(Some(evil), vec![vec![evil.into(), evil.into()]]);
        p.warn(evil).note(evil).next(evil, evil);
        for style in [Style::PLAIN, Style::COLOR] {
            let text = p.render(style);
            // Colour codes are the page's own; nothing else is a control.
            let bare = text
                .replace("\x1b[1;32m", "")
                .replace("\x1b[1;33m", "")
                .replace("\x1b[1m", "")
                .replace("\x1b[0m", "");
            assert!(
                !bare
                    .chars()
                    .any(|c| (c.is_control() && c != '\n') || matches!(c, '\u{2028}' | '\u{2029}')),
                "{bare:?}"
            );
            assert!(bare.contains("0.1 ]52;c;aGk=  2J  x y"), "{bare:?}");
        }
        let cells = columns(&[vec!["a\x1bb".into(), "c\u{85}d".into()]]);
        assert_eq!(cells, ["a b   c d"]);
    }

    /// A time reads as a date and a clock, in UTC.
    #[test]
    fn a_time_reads_as_a_date_and_a_clock() {
        assert_eq!(time(0), "1970-01-01 00:00:00");
        assert_eq!(time(1_791_834_106_607), "2026-10-12 19:41:46");
        assert_eq!(time(951_782_400_000), "2000-02-29 00:00:00");
    }

    /// A change's lines are written as they come, a prompt when flushed;
    /// its warnings, notes and next steps come set apart at the end, also
    /// after a page.
    #[test]
    fn a_change_says_its_lines_and_keeps_the_rest_for_the_end() {
        let mut out = Vec::new();
        let mut said = Said::new(&mut out, Style::PLAIN);
        writeln!(said, "made the user nerve").unwrap();
        writeln!(said, "Warning: polkit is not installed").unwrap();
        writeln!(said, "Next: `nerve-node center add -` pairs it").unwrap();
        write!(said, "Owner? [y/N] ").unwrap();
        said.flush().unwrap();
        writeln!(said, "y").unwrap();
        said.finish(None).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "made the user nerve\nOwner? [y/N] y\n\nWarning  Polkit is not installed\n\nNext  `nerve-node center add -` pairs it\n"
        );
        let mut out = Vec::new();
        let mut said = Said::new(&mut out, Style::PLAIN);
        writeln!(said, "started the service").unwrap();
        writeln!(said, "note: kept").unwrap();
        let mut page = Page::new("Nerve node", "0.1.0").state("running", Tone::Good);
        page.next("Pair a center", "nerve-node center add -");
        said.finish(Some(page)).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "started the service\n\nNerve node 0.1.0 · running\n\nNote  Kept\n\nNext  Pair a center:  nerve-node center add -\n"
        );
        // Nothing kept, no page: nothing more.
        let mut out = Vec::new();
        let mut said = Said::new(&mut out, Style::PLAIN);
        writeln!(said, "sudo: off").unwrap();
        said.finish(None).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "sudo: off\n");
    }
}
