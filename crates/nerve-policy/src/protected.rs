//! Protected paths: places whose content gives away secrets or runs code later.
//!
//! They are refused in every mode, also in `user`, unless the
//! owner releases them by name: a folder grant at or inside the protected path, or an
//! entry in `protected.allow`. A folder releases only what its flags give: `r`
//! for reads, `w` for writes, `x` for commands run there. A grant of a whole
//! home does not release `~/.ssh`.
//! Matching ignores case, so a case-insensitive filesystem cannot slip `~/.SSH` past.
//!
//! The node's own folders (its config, keys, state and audit log) are refused
//! harder still: nothing releases them, and `decide` looks at them before any
//! rule or mode.
//!
//! Both platforms' lists and path rules are here on every platform, picked by
//! [`Platform`], so the Windows ones are tested on Linux as well.

use std::path::{Path, PathBuf};

use crate::config::{Access, Folder, ProtectedOptions};
use crate::paths::{resolve, win};

/// Relative to the home directory.
const UNIX_HOME: &[&str] = &[
    // keys and credentials
    ".ssh",
    ".gnupg",
    ".local/share/keyrings",
    ".local/share/kwalletd",
    ".kde/share/apps/kwallet",
    ".kde4/share/apps/kwallet",
    ".password-store",
    ".config/keepassxc",
    ".config/Bitwarden",
    ".config/1Password",
    ".git-credentials",
    ".netrc",
    ".aws",
    ".kube",
    ".docker",
    ".config/gh",
    ".config/hub",
    ".config/gcloud",
    ".azure",
    ".npmrc",
    ".pypirc",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".vault-token",
    // browser and mail profiles
    ".mozilla",
    ".librewolf",
    ".thunderbird",
    ".config/google-chrome",
    ".config/chromium",
    ".config/BraveSoftware",
    ".config/vivaldi",
    ".config/microsoft-edge",
    ".config/opera",
    ".var/app",
    ".local/share/flatpak/app",
    // shell start-up and session environment
    ".bashrc",
    ".bashrc.d",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
    ".zlogout",
    ".config/fish",
    ".config/nushell",
    ".xprofile",
    ".xinitrc",
    ".xsession",
    ".xsessionrc",
    ".pam_environment",
    ".config/environment.d",
    // autostart, systemd user units, cron
    ".config/autostart",
    ".config/autostart-scripts",
    ".config/plasma-workspace",
    ".kde/Autostart",
    ".config/systemd",
    ".local/share/systemd",
];

/// Relative to the home directory: config that makes tools run commands, and
/// programs that run later in place of others (`~/.local/bin` comes early in
/// `PATH` on many systems, a fake `sudo` there would catch the password; a
/// `.desktop` file runs its `Exec=` line when its app is opened). Reading them is
/// harmless and tools need it (git's identity), so only writes prompt.
const HOME_WRITE_ONLY: &[&str] = &[
    ".gitconfig",
    ".config/git",
    ".local/bin",
    ".local/share/applications",
];

/// Relative to the user profile on Windows.
const WIN_HOME: &[&str] = &[
    // keys and credentials
    ".ssh",
    ".gnupg",
    "AppData/Roaming/gnupg",
    "AppData/Roaming/Microsoft/Credentials",
    "AppData/Local/Microsoft/Credentials",
    "AppData/Roaming/Microsoft/Protect",
    "AppData/Roaming/Microsoft/Vault",
    "AppData/Local/Microsoft/Vault",
    "AppData/Roaming/Microsoft/Crypto",
    "AppData/Roaming/Microsoft/SystemCertificates",
    "AppData/Roaming/Bitwarden",
    "AppData/Roaming/KeePass",
    "AppData/Roaming/KeePassXC",
    "AppData/Local/1Password",
    "AppData/Roaming/GitHub CLI",
    "AppData/Roaming/gcloud",
    ".git-credentials",
    "_netrc",
    ".aws",
    ".kube",
    ".docker",
    ".azure",
    ".npmrc",
    ".pypirc",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".vault-token",
    // browser and mail profiles
    "AppData/Local/Google/Chrome/User Data",
    "AppData/Local/Microsoft/Edge/User Data",
    "AppData/Local/BraveSoftware",
    "AppData/Local/Vivaldi",
    "AppData/Roaming/Mozilla",
    "AppData/Roaming/Opera Software",
    "AppData/Roaming/Thunderbird",
    // start-up, shell profiles and history
    "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup",
    "AppData/Roaming/Microsoft/Windows/PowerShell",
    "Documents/WindowsPowerShell",
    "Documents/PowerShell",
    // The user's registry hive: its Run keys start programs at every logon,
    // and programs keep credentials in it.
    "NTUSER.DAT",
];

/// System paths, for a client that runs as root (or reads what others may write).
const UNIX_SYSTEM: &[&str] = &[
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/ssh",
    "/etc/pam.d",
    "/etc/security",
    "/etc/polkit-1",
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
    "/etc/systemd",
    "/etc/profile",
    "/etc/profile.d",
    "/etc/environment",
    "/etc/bash.bashrc",
    "/etc/zsh",
    "/etc/xdg/autostart",
];

/// Relative to `%ProgramData%`, for a node that runs as an administrator.
const WIN_PROGRAM_DATA: &[&str] = &[
    // The OpenSSH server: `sshd_config`, the host keys, and
    // `administrators_authorized_keys`, the key list of every administrator
    // account; a line there opens the machine, a broken file locks it.
    "ssh",
    // The all-users Startup folder: what lies there runs at every user's logon.
    "Microsoft/Windows/Start Menu/Programs/StartUp",
];

/// Relative to the Windows folder (`%SystemRoot%`), likewise.
const WIN_SYSTEM_ROOT: &[&str] = &[
    // The registry hives: SAM and SECURITY hold the password hashes and the
    // LSA secrets, SYSTEM the key that opens them.
    "System32/config",
    // Windows PowerShell's home: its all-users profiles run in every session,
    // its modules load on use; SysWOW64 holds the 32-bit one's.
    "System32/WindowsPowerShell/v1.0",
    "SysWOW64/WindowsPowerShell/v1.0",
];

/// Relative to `%ProgramFiles%` (and its x86 twin), likewise.
const WIN_PROGRAM_FILES: &[&str] = &[
    // PowerShell 7's home (`$PSHOME`, `PowerShell\7`) and its all-users
    // modules: it runs the profiles and loads the modules there at every start.
    "PowerShell",
];

/// Relative to the user's Documents folder where it really is: PowerShell
/// takes `$PROFILE` and the user's modules from there, and OneDrive's backup
/// or a redirect moves that folder away from the profile.
const WIN_DOCUMENTS: &[&str] = &["WindowsPowerShell", "PowerShell"];

/// Which platform's lists and path rules a [`Protected`] follows. The node
/// passes the one it runs on; a test may pass either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Platform {
    Unix,
    Windows(WinFolders),
}

/// Where the Windows system entries hang off. Windows need not live in
/// `C:\Windows`, so the node takes them from the environment; each may have
/// more than one path, all of them protected.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WinFolders {
    /// `%ProgramData%`.
    pub program_data: Vec<PathBuf>,
    /// `%SystemRoot%`, the Windows folder.
    pub system_root: Vec<PathBuf>,
    /// `%ProgramFiles%`, and `%ProgramFiles(x86)%` where there is one.
    pub program_files: Vec<PathBuf>,
    /// The user's Documents folder where it really is (OneDrive's backup
    /// or a redirect moves it away from the profile).
    pub documents: Vec<PathBuf>,
}

impl Platform {
    fn windows(&self) -> bool {
        matches!(self, Platform::Windows(_))
    }
}

/// Inside any folder: whose content the user's tools run. Writes there are refused.
pub const TOOL_CONFIG: &[&str] = &[".git", ".envrc", ".vscode", ".idea"];

#[derive(Debug, Clone)]
pub struct Protected {
    /// Windows path rules: `\` and `/` both separate, case never counts.
    windows: bool,
    entries: Vec<PathBuf>,
    write_only: Vec<PathBuf>,
    /// The node's own folders, folded and resolved; never released.
    own: Vec<PathBuf>,
    /// The same as a command line names them once it is [`normalise`]d,
    /// with the folder each one stands for.
    own_names: Vec<(String, PathBuf)>,
    /// The home as `~` and `$HOME` stand for it in a command line,
    /// normalised: as given and resolved.
    homes: Vec<String>,
}

fn fold(p: &Path) -> PathBuf {
    PathBuf::from(p.to_string_lossy().to_lowercase())
}

/// Characters that end a word on a command line, besides white space: quotes,
/// shell control and the `=` of `--file=x`.
const BREAKS: &[char] = &['"', '\'', '`', ';', '&', '|', '<', '>', '(', ')', ',', '='];

fn breaks(c: char) -> bool {
    c.is_whitespace() || BREAKS.contains(&c)
}

/// A command line or a path the way the own-folder check compares them:
/// lower case, `/` for `\`, no `\\?\` or `\\.\` prefix and no dot or space
/// at the end of a name on Windows, and no doubled separator or `/./`.
fn normalise(s: &str, windows: bool) -> String {
    let mut s = s.to_lowercase();
    if windows {
        s = s.replace('\\', "/");
        s = trim_names(&admin_shares(&device_paths(&s)));
    }
    tidy(&s)
}

/// `\\?\` and `\\.\` paths (here `//?/` and `//./`) in the forms the rest
/// of the check reads: a drive path as it is, `UNC\host\share` as
/// `//host/share`, and a volume or device (`Volume{GUID}`,
/// `GLOBALROOT\Device\HarddiskVolume3`), whose drive the node does not
/// know, as a path without a drive, which stands for every drive.
fn device_paths(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    loop {
        let at = [rest.find("//?/"), rest.find("//./")]
            .into_iter()
            .flatten()
            .min();
        let Some(at) = at else { break };
        out.push_str(&rest[..at]);
        let mut after = &rest[at + 4..];
        // `\\?\GLOBALROOT\??\C:\...` is the drive path again.
        while let Some(r) = after
            .strip_prefix("globalroot/")
            .or_else(|| after.strip_prefix("??/"))
        {
            after = r;
        }
        let b = after.as_bytes();
        if let Some(r) = after.strip_prefix("unc/") {
            out.push_str("//");
            rest = r;
        } else if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
            rest = after;
        } else {
            let device = after.strip_prefix("device/").unwrap_or(after);
            let name = device
                .find(|c: char| c == '/' || breaks(c))
                .unwrap_or(device.len());
            rest = &device[name..];
        }
    }
    out.push_str(rest);
    out
}

/// Without the dots Windows drops from the end of a name, so
/// `node-state.\x` reads as `node-state/x`; `.` and `..` stay, and so
/// does a dot inside a name (`a.txt`). Dots before a space go as well
/// (`node-state. x`), but the space stays: it may end a word, and the name
/// before it is seen either way, as Windows drops a trailing space too.
fn trim_names(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    // Dots and spaces after a name, not yet written.
    let mut run = String::new();
    let mut after_name = false;
    let flush = |run: &mut String, out: &mut String, name_follows: bool| {
        match run.find(' ') {
            Some(space) => out.push_str(&run[space..]),
            None if name_follows => out.push_str(run),
            None => {}
        }
        run.clear();
    };
    for c in s.chars() {
        if after_name && matches!(c, '.' | ' ') {
            run.push(c);
            continue;
        }
        let ends_name = c == '/' || breaks(c);
        flush(&mut run, &mut out, !ends_name);
        after_name = !(ends_name || c == ':' || c == '.');
        out.push(c);
    }
    flush(&mut run, &mut out, false);
    out
}

/// `//host/c$/x` as `c:/x`: an admin share names a drive. Any host counts,
/// since the node cannot tell which names reach this machine; a share of
/// another machine at the same path is refused as well, which costs nothing.
fn admin_shares(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(at) = rest.find("//") {
        out.push_str(&rest[..at]);
        let after = &rest[at + 2..];
        let host = after
            .find(|c: char| c == '/' || breaks(c))
            .unwrap_or(after.len());
        let share = after[host..].strip_prefix('/').unwrap_or("");
        let b = share.as_bytes();
        let drive = host > 0
            && b.len() >= 2
            && b[0].is_ascii_alphabetic()
            && b[1] == b'$'
            && b.get(2).is_none_or(|c| *c == b'/' || breaks(*c as char));
        if drive {
            out.push(b[0] as char);
            out.push(':');
            rest = &share[2..];
            if rest.is_empty() || !rest.starts_with('/') {
                out.push('/');
            }
        } else {
            out.push_str("//");
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// Whether the path segment `pattern` of a command line may name `name`:
/// a shell's wildcards (`*`, `?`, `[...]`) are matched, and on Windows an
/// 8.3 short name (`NODE-S~1`, a `~` and a digit) may stand for any name,
/// since the node does not know which short name the file system gave.
fn segment_matches(pattern: &str, name: &str, windows: bool) -> bool {
    work(pattern.len());
    let short = |p: &str| {
        p.char_indices()
            .any(|(at, c)| c == '~' && p[at + 1..].starts_with(|d: char| d.is_ascii_digit()))
    };
    if windows && short(pattern) {
        return true;
    }
    if !pattern.contains(['*', '?', '[']) {
        return pattern == name;
    }
    glob(pattern, name)
}

#[cfg(test)]
thread_local! {
    /// The characters the own-folder check looked at, so a test can tell
    /// that the work grows with the line, not with its square.
    static WORK: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn work(n: usize) {
    WORK.with(|w| w.set(w.get() + n));
}

#[cfg(not(test))]
fn work(_: usize) {}

/// One piece of a wildcard pattern.
enum Piece {
    Any,
    One,
    Class(Vec<char>, bool),
    Lit(char),
}

/// `name` against a pattern of `*`, `?`, `[...]` (with `!` or `^` for
/// "not", and ranges) and literal characters, in time linear in both for
/// each `*`, so a long line from the center cannot make it slow.
fn glob(pattern: &str, name: &str) -> bool {
    glob_closed(pattern, name, pattern.rfind(']'))
}

/// [`glob`], told where the last `]` of `pattern` is (a byte index), so a
/// `[` that nothing closes is known as plain at once. Every piece but `*`
/// takes one character of `name`, so the pattern is read only as far as
/// `name` is long: the own-folder check tries the tail of one long word
/// from each drive letter in it, and each such try reads no more than the
/// start of its tail.
fn glob_closed(pattern: &str, name: &str, last_close: Option<usize>) -> bool {
    let name: Vec<char> = name.chars().collect();
    let mut pieces = Vec::new();
    let mut single = 0;
    let mut i = 0;
    while let Some(c) = pattern[i..].chars().next() {
        work(1);
        if c != '*' {
            if single == name.len() {
                return false;
            }
            single += 1;
        }
        i += c.len_utf8();
        match c {
            '*' => pieces.push(Piece::Any),
            '?' => pieces.push(Piece::One),
            '[' if last_close.is_some_and(|l| l > i) => match class(&pattern[i..]) {
                Some((set, not, len)) => {
                    pieces.push(Piece::Class(set, not));
                    i += len;
                }
                None => pieces.push(Piece::Lit('[')),
            },
            c => pieces.push(Piece::Lit(c)),
        }
    }
    let one = |p: &Piece, c: char| match p {
        Piece::One => true,
        Piece::Class(set, not) => set.contains(&c) != *not,
        Piece::Lit(l) => *l == c,
        Piece::Any => false,
    };
    let (mut p, mut n) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        work(1);
        if p < pieces.len() && matches!(pieces[p], Piece::Any) {
            star = Some((p, n));
            p += 1;
        } else if p < pieces.len() && one(&pieces[p], name[n]) {
            p += 1;
            n += 1;
        } else if let Some((sp, sn)) = star {
            p = sp + 1;
            n = sn + 1;
            star = Some((sp, sn + 1));
        } else {
            return false;
        }
    }
    pieces[p..].iter().all(|x| matches!(x, Piece::Any))
}

/// The class a `[` opens, from what follows the `[`: its members, whether
/// it is "not", and the bytes it takes up to and with its `]`; `None` when
/// no `]` closes it. A `]` right after the `[` is a member, not the end.
fn class(s: &str) -> Option<(Vec<char>, bool, usize)> {
    let mut it = s.char_indices().peekable();
    let not = matches!(it.peek(), Some((_, '!' | '^')));
    if not {
        it.next();
    }
    let mut set = Vec::new();
    let mut first = true;
    while let Some((at, c)) = it.next() {
        work(1);
        if c == ']' && !first {
            return Some((set, not, at + 1));
        }
        first = false;
        let mut ahead = it.clone();
        match (ahead.next(), ahead.next()) {
            (Some((_, '-')), Some((_, d))) if d != ']' => {
                set.extend((c..=d).take(256));
                it = ahead;
            }
            _ => set.push(c),
        }
    }
    None
}

/// Folds `//` and `/./` into one `/`.
fn tidy(s: &str) -> String {
    let mut s = s.to_string();
    while s.contains("//") {
        s = s.replace("//", "/");
    }
    while s.contains("/./") {
        s = s.replace("/./", "/");
    }
    s
}

/// Takes out every `seg/..` whose `seg` is a plain name after a `/`, word
/// by word, in one pass (the line comes from the center and may be long).
fn fold_dotdot(s: &str) -> String {
    fn word(w: &str, out: &mut String) {
        let mut kept: Vec<&str> = Vec::new();
        for seg in w.split('/') {
            let top = kept.last().copied();
            let plain = top.is_some_and(|t| !t.is_empty() && t != ".." && t != ".");
            if seg == ".." && plain && kept.len() > 1 {
                kept.pop();
            } else {
                kept.push(seg);
            }
        }
        out.push_str(&kept.join("/"));
    }
    let mut out = String::with_capacity(s.len());
    let mut start = 0;
    for (at, c) in s.char_indices().filter(|(_, c)| breaks(*c)) {
        word(&s[start..at], &mut out);
        out.push(c);
        start = at + c.len_utf8();
    }
    word(&s[start..], &mut out);
    out
}

/// `text` with every way a shell names the home replaced by `home`: `~` at
/// the start of a word, `$HOME` and `${HOME}`, and on Windows also
/// `$env:USERPROFILE`, `${env:USERPROFILE}` and `%USERPROFILE%`. `text` is
/// normalised already, so the names are in lower case.
fn expand_home(text: &str, home: &str, windows: bool) -> String {
    let mut vars: Vec<(&str, &str)> = vec![("${home}", home), ("$home", home)];
    if windows {
        // `%HOMEDRIVE%%HOMEPATH%` is the profile as well, in two halves.
        let (drive, path) = match home.as_bytes().get(1) {
            Some(b':') => home.split_at(2),
            _ => ("", home),
        };
        for (names, value) in [
            (
                ["${env:userprofile}", "$env:userprofile", "%userprofile%"],
                home,
            ),
            (["${env:homedrive}", "$env:homedrive", "%homedrive%"], drive),
            (["${env:homepath}", "$env:homepath", "%homepath%"], path),
        ] {
            vars.extend(names.into_iter().map(|n| (n, value)));
        }
    }
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    let mut prev: Option<char> = None;
    while let Some(c) = rest.chars().next() {
        let var = vars.iter().find(|(v, _)| {
            rest.starts_with(*v) && (v.ends_with(['}', '%']) || !rest[v.len()..].starts_with(ident))
        });
        let tilde = c == '~'
            && prev.is_none_or(|p| breaks(p) || p == ':')
            && rest[1..]
                .chars()
                .next()
                .is_none_or(|n| n == '/' || breaks(n));
        let (len, value) = match var {
            Some((v, value)) => (v.len(), *value),
            None if tilde => (1, home),
            None => {
                out.push(c);
                prev = Some(c);
                rest = &rest[c.len_utf8()..];
                continue;
            }
        };
        out.push_str(value);
        prev = value.chars().last().or(prev);
        rest = &rest[len..];
    }
    out
}

/// `~/x` relative to `home`, or an absolute path; `None` for anything else.
pub fn expand(home: &Path, s: &str) -> Option<PathBuf> {
    if let Some(rest) = s.strip_prefix("~/") {
        Some(home.join(rest))
    } else if s == "~" {
        Some(home.to_path_buf())
    } else if Path::new(s).is_absolute() {
        Some(PathBuf::from(s))
    } else {
        None
    }
}

/// Folds a list, adds each entry's resolved form (resolved paths are what gets
/// checked, also when the home is a symlink and the entry does not exist yet) and
/// drops what the owner released.
fn finish(list: impl Iterator<Item = PathBuf>, allow: &[PathBuf]) -> Vec<PathBuf> {
    let mut all: Vec<PathBuf> = list.collect();
    let real: Vec<PathBuf> = all.iter().filter_map(|e| resolve(e).ok()).collect();
    all.extend(real);
    let mut all: Vec<PathBuf> = all.iter().map(|e| fold(e)).collect();
    all.retain(|e| !allow.contains(e));
    all.sort();
    all.dedup();
    all
}

/// A character that goes on a file name: `nerve-notes` is not `nerve`.
fn name_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '.' | '_' | '-')
}

/// Where `name` first ends in `text` followed by no more of a file name,
/// trying it at every place, also where one try overlaps another.
fn named_end(text: &str, name: &str) -> Option<usize> {
    text.char_indices().find_map(|(at, _)| {
        work(1);
        let end = at + name.len();
        (text[at..].starts_with(name) && !text[end..].starts_with(name_char)).then_some(end)
    })
}

/// The working directory, normalised, as the own-folder check joins a
/// relative word to it: `fold_dotdot(tidy("{text}/{word}"))`. A word's
/// `..` only takes segments off the end of the directory, so what a joined
/// path holds of it is one of its prefixes. What each prefix names is
/// worked out here once, so each word costs only its own length, however
/// long the directory and however many words the line has.
struct Base<'c> {
    text: &'c str,
    /// `None` for a directory that `fold_dotdot` would change, or with a
    /// `.`, `..` or empty segment where a `..` could take it off; no
    /// resolved path is such a directory. Each word is then joined to it in
    /// full.
    at: Option<Prefixes>,
}

struct Prefixes {
    /// Where each `/` segment of the directory ends.
    ends: Vec<usize>,
    /// The segment with the last break of the directory in it (a space, as
    /// in `program files`), else the first: [`fold_dotdot`] folds within a
    /// word, so a `..` takes off only the segments after this one.
    first: usize,
    /// For each own name, where it first ends in the directory, so that
    /// each prefix as long or longer holds it.
    named: Vec<Option<usize>>,
    /// For each own name, how many of the directory's first segments match
    /// its own, with [`segment_matches`].
    leading: Vec<usize>,
}

impl<'c> Base<'c> {
    fn new(p: &Protected, text: &'c str) -> Base<'c> {
        let mut ends: Vec<usize> = text.match_indices('/').map(|(at, _)| at).collect();
        ends.push(text.len());
        let first = text
            .rfind(breaks)
            .map_or(0, |b| ends.iter().position(|e| *e >= b).unwrap_or(0));
        let seg = |i: usize| &text[if i == 0 { 0 } else { ends[i - 1] + 1 }..ends[i]];
        work(text.len());
        let plain = (first + 1..ends.len()).all(|i| !matches!(seg(i), "" | "." | ".."));
        if !plain || fold_dotdot(text) != text {
            return Base { text, at: None };
        }
        let named = p
            .own_names
            .iter()
            .map(|(name, _)| named_end(text, name))
            .collect();
        let leading = p
            .own_names
            .iter()
            .map(|(name, _)| {
                name.split('/')
                    .zip(0..ends.len())
                    .take_while(|(w, i)| segment_matches(seg(*i), w, p.windows))
                    .count()
            })
            .collect();
        Base {
            text,
            at: Some(Prefixes {
                ends,
                first,
                named,
                leading,
            }),
        }
    }

    /// The relative `word` joined to the directory, in full.
    fn slow_join(&self, word: &str) -> String {
        fold_dotdot(&tidy(&format!("{}/{word}", self.text)))
    }
}

impl Prefixes {
    /// The relative `word` joined to the directory as
    /// [`Base::slow_join`] would: how many of the directory's segments
    /// stay, and the word's segments after them.
    fn join<'w>(&self, word: &'w str) -> (usize, Vec<&'w str>) {
        // `tidy` takes the `/./` out that a leading `./` makes.
        let word = word.strip_prefix("./").unwrap_or(word);
        let mut kept = self.ends.len();
        let mut rest: Vec<&str> = Vec::new();
        for seg in word.split('/') {
            work(seg.len() + 1);
            // As `fold_dotdot`: a `..` takes off a plain name before it,
            // never the first of a word; the directory's segments after
            // `first` are all plain.
            let pop = seg == ".."
                && match rest.last() {
                    Some(t) => !matches!(*t, "" | "." | ".."),
                    None => kept - 1 > self.first,
                };
            if !pop {
                rest.push(seg);
            } else if rest.pop().is_none() {
                kept -= 1;
            }
        }
        (kept, rest)
    }
}

impl Protected {
    /// `own` are the node's own config and state directories: a command or a
    /// write must not change the node's policy behind its back, nor read the
    /// keys there. No folder grant and no `protected.allow` releases them.
    pub fn new(
        platform: &Platform,
        home: &Path,
        own: &[PathBuf],
        opts: &ProtectedOptions,
    ) -> Protected {
        let allow: Vec<PathBuf> = opts
            .allow
            .iter()
            .filter_map(|s| expand(home, s))
            .map(|p| fold(&p))
            .collect();
        let (in_home, system): (&[&str], Vec<PathBuf>) = match platform {
            Platform::Unix => (UNIX_HOME, UNIX_SYSTEM.iter().map(PathBuf::from).collect()),
            Platform::Windows(f) => {
                let below = |roots: &[PathBuf], list: &[&str]| -> Vec<PathBuf> {
                    roots
                        .iter()
                        .flat_map(|r| list.iter().map(move |e| r.join(e)))
                        .collect()
                };
                let mut system = below(&f.program_data, WIN_PROGRAM_DATA);
                system.extend(below(&f.system_root, WIN_SYSTEM_ROOT));
                system.extend(below(&f.program_files, WIN_PROGRAM_FILES));
                system.extend(below(&f.documents, WIN_DOCUMENTS));
                (WIN_HOME, system)
            }
        };
        let entries = in_home
            .iter()
            .map(|r| home.join(r))
            .chain(system)
            .chain(opts.extra.iter().filter_map(|s| expand(home, s)));
        let write_only = HOME_WRITE_ONLY.iter().map(|r| home.join(r));
        let windows = platform.windows();
        let own = finish(own.iter().cloned(), &[]);
        let spelled = |p: &Path| {
            let s = normalise(&p.to_string_lossy(), windows);
            match s.trim_end_matches('/') {
                "" => s,
                t => t.to_string(),
            }
        };
        let own_names = own.iter().map(|o| (spelled(o), o.clone())).collect();
        let homes = finish(std::iter::once(home.to_path_buf()), &[])
            .iter()
            .map(|h| spelled(h))
            .collect();
        Protected {
            windows,
            entries: finish(entries, &allow),
            write_only: finish(write_only, &allow),
            own,
            own_names,
            homes,
        }
    }

    /// `path` is `base` or inside it, by whole components; on Windows by
    /// either separator and ignoring case. Both are folded already.
    fn inside(&self, path: &Path, base: &Path) -> bool {
        if self.windows {
            win::within(&path.to_string_lossy(), &base.to_string_lossy())
        } else {
            path.starts_with(base)
        }
    }

    /// The node's own folder `path` falls in.
    pub fn own(&self, path: &Path) -> Option<&Path> {
        let folded = fold(path);
        self.own
            .iter()
            .find(|o| self.inside(&folded, o))
            .map(PathBuf::as_path)
    }

    /// The node's own folder a command line names, as far as a plain look
    /// can tell. The line is normalised first: case, on Windows `\` or `/`
    /// and a `\\?\` prefix, doubled separators, `seg/..`, and the home in
    /// any spelling the shells take (`~`, `$HOME`, `${HOME}`, and on Windows
    /// `$env:USERPROFILE` and `%USERPROFILE%`). Then it looks for an absolute
    /// path, and for a word that is a relative path from `cwd`. A path built
    /// at run time (`cd ~/.config; cat nerve/x`) is not seen here; in
    /// `folder` mode Landlock still keeps the command out.
    pub fn own_in_command(&self, command: &str, cwd: Option<&Path>) -> Option<&Path> {
        let text = normalise(command, self.windows);
        let cwd = cwd.map(|c| {
            normalise(&c.to_string_lossy(), self.windows)
                .trim_end_matches('/')
                .to_string()
        });
        let base = cwd.as_deref().map(|c| Base::new(self, c));
        let absolute =
            |w: &str| w.starts_with('/') || (self.windows && w.as_bytes().get(1) == Some(&b':'));
        for home in &self.homes {
            let text = fold_dotdot(&tidy(&expand_home(&text, home, self.windows)));
            if let Some(own) = self.names_own(&text) {
                return Some(own);
            }
            for word in text.split(breaks).filter(|w| !w.is_empty()) {
                if let Some(own) = self.globs_own(word, base.as_ref()) {
                    return Some(own);
                }
                let Some(base) = &base else { continue };
                if absolute(word) {
                    continue;
                }
                if let Some(own) = self.joined_names_own(base, word) {
                    return Some(own);
                }
            }
        }
        None
    }

    /// The own folder one normalised word may name segment by segment, with
    /// [`segment_matches`]: an absolute path in it (on Windows also one
    /// after a prefix such as `filesystem::`, and one without a drive, which
    /// the shell takes on its current drive), else the word as a path from
    /// `cwd`. A drive-relative `c:name` is `name` from `cwd` when that is
    /// on drive `c`, else from the root of `c`, where a new shell has it.
    fn globs_own(&self, word: &str, base: Option<&Base>) -> Option<&Path> {
        let mut drives = false;
        if self.windows {
            let (own, any) = self.drives_own(word, base);
            if own.is_some() {
                return own;
            }
            drives = any;
        }
        let path = if word.starts_with('/') {
            if self.windows {
                // Any drive: `?` matches the drive's letter.
                format!("?:{word}")
            } else {
                word.to_string()
            }
        } else if drives {
            return None;
        } else {
            return self.joined_globs_own(base?, word);
        };
        let path = fold_dotdot(&tidy(&path));
        let segs: Vec<&str> = path.split('/').collect();
        self.own_names.iter().find_map(|(name, own)| {
            let want: Vec<&str> = name.split('/').collect();
            let hit = segs.len() >= want.len()
                && want
                    .iter()
                    .zip(&segs)
                    .all(|(w, s)| segment_matches(s, w, self.windows));
            hit.then_some(own.as_path())
        })
    }

    /// The own folder a path from a drive letter in `word` names (`c:/...`,
    /// also after a prefix such as `filesystem::`), and whether `word` has a
    /// drive letter at all. Each drive letter starts a path that runs to the
    /// end of the word; a drive-relative one (`c:name`) runs from `base`
    /// when that is on the same drive, else from the drive's root, as
    /// [`globs_own`](Self::globs_own) says. `word` is normalised already,
    /// and so is each such tail; the tails that start in the same segment
    /// share every segment after it, which is matched once for all of them,
    /// and the part of the segment each starts with is matched with what the
    /// segment holds looked up once. So a word of drive letters
    /// (`a:a:a:...`) takes work that grows with its length, not with its
    /// square.
    fn drives_own(&self, word: &str, base: Option<&Base>) -> (Option<&Path>, bool) {
        let b = word.as_bytes();
        let cwd_drive = base.and_then(|c| {
            let d = c.text.as_bytes();
            (d.len() >= 2 && d[0].is_ascii_alphabetic() && d[1] == b':').then_some(d[0])
        });
        let mut segs = Vec::new();
        let mut start = 0;
        for (at, _) in word.match_indices('/') {
            segs.push((start, at));
            start = at + 1;
        }
        segs.push((start, word.len()));
        let mut any = false;
        for (k, &(start, end)) in segs.iter().enumerate() {
            let drives: Vec<usize> = (start..end.saturating_sub(1))
                .filter(|&at| {
                    (at == 0 || !b[at - 1].is_ascii_alphanumeric())
                        && b[at].is_ascii_alphabetic()
                        && b[at + 1] == b':'
                })
                .collect();
            work(end - start);
            if drives.is_empty() {
                continue;
            }
            any = true;
            let seg = &word[start..end];
            // Where in the segment the last short name, wildcard and `]`
            // are: a tail from a drive letter holds one when it starts at or
            // before it.
            let short = seg
                .char_indices()
                .rev()
                .find(|(at, c)| {
                    *c == '~' && seg[at + 1..].starts_with(|d: char| d.is_ascii_digit())
                })
                .map(|(at, _)| start + at);
            let wild = seg.rfind(['*', '?', '[']).map(|at| start + at);
            let close = seg.rfind(']').map(|at| start + at);
            // Whether the segment from `from` on may name `w`.
            let part_is = |from: usize, w: &str| {
                work(1);
                let part = &word[from..end];
                if short.is_some_and(|s| s >= from) {
                    true
                } else if wild.is_none_or(|x| x < from) {
                    part == w
                } else {
                    glob_closed(part, w, close.and_then(|c| c.checked_sub(from)))
                }
            };
            let after = &segs[k + 1..];
            let last = after.is_empty();
            // The `..` right after the segment, which take off what a
            // drive-relative tail starts with. The line is folded already,
            // so only a word's first segment can have any.
            let ups = after
                .iter()
                .take_while(|&&(s, e)| &word[s..e] == "..")
                .count();
            // A working directory the quick join does not take (no resolved
            // path is one) has each drive-relative tail joined in full.
            if let Some(base) = base.filter(|c| c.at.is_none()) {
                for &at in &drives {
                    let relative = at + 2 < end || last;
                    if relative
                        && Some(b[at]) == cwd_drive
                        && let Some(own) = self.joined_globs_own(base, &word[at + 2..])
                    {
                        return (Some(own), true);
                    }
                }
            }
            for (i, (name, own)) in self.own_names.iter().enumerate() {
                let want: Vec<&str> = name.split('/').collect();
                // `want` from `s` on against the segments after this one
                // from `t` on, to the end of `want`: looked at once for all
                // the drive letters in the segment.
                let mut seen: Vec<((usize, usize), bool)> = Vec::new();
                let mut tail = |s: usize, t: usize| {
                    if let Some(&(_, hit)) = seen.iter().find(|(at, _)| *at == (s, t)) {
                        return hit;
                    }
                    let hit = s >= want.len()
                        || (after.len().saturating_sub(t) >= want.len() - s
                            && want[s..]
                                .iter()
                                .zip(&after[t..])
                                .all(|(w, &(a, z))| segment_matches(&word[a..z], w, true)));
                    seen.push(((s, t), hit));
                    hit
                };
                let absolute = drives.iter().any(|&at| part_is(at, want[0])) && tail(1, 0);
                let relative = drives.iter().any(|&at| {
                    let from = at + 2;
                    let part = &word[from..end];
                    if part.is_empty() && !last {
                        // `c:/...`, an absolute path.
                        return false;
                    }
                    let plain = !matches!(part, "" | "." | "..");
                    if Some(b[at]) != cwd_drive {
                        // From the root of the drive: `c:/part/...`, where a
                        // `..` after the part takes it off and `/./` goes.
                        let d = want[0].as_bytes();
                        if d.len() != 2 || d[0] != b[at] || d[1] != b':' {
                            false
                        } else if part == "." && !last {
                            tail(1, 0)
                        } else if plain && ups > 0 {
                            tail(1, 1)
                        } else {
                            want.get(1).is_none_or(|w| part_is(from, w)) && tail(2, 0)
                        }
                    } else if let Some(pre) = base.and_then(|c| c.at.as_ref()) {
                        // From the working directory, as `Prefixes::join`
                        // would join the tail: either the part stays after
                        // the whole directory, or it goes and the `..`
                        // take off the directory's last segments.
                        let len = pre.ends.len();
                        let leading = pre.leading[i];
                        if part != ".." && ups == 0 && (plain || last) {
                            return leading >= len.min(want.len())
                                && (want.len() <= len
                                    || (part_is(from, want[len]) && tail(len + 1, 0)));
                        }
                        let up = match part {
                            ".." => ups + 1,
                            "." => ups,
                            _ => ups - 1,
                        };
                        let gone = up.min(len - 1 - pre.first);
                        let kept = len - gone;
                        let dots = up - gone;
                        leading >= kept.min(want.len())
                            && (kept..(kept + dots).min(want.len())).all(|j| want[j] == "..")
                            && tail(kept + dots, ups)
                    } else {
                        false
                    }
                });
                if absolute || relative {
                    return (Some(own.as_path()), true);
                }
            }
        }
        (None, any)
    }

    /// [`names_own`](Self::names_own) of the relative `word` joined to the
    /// working directory.
    fn joined_names_own(&self, base: &Base, word: &str) -> Option<&Path> {
        let Some(at) = &base.at else {
            return self.names_own(&base.slow_join(word));
        };
        let (kept, rest) = at.join(word);
        let end = at.ends[kept - 1];
        let tail = if rest.is_empty() {
            String::new()
        } else {
            format!("/{}", rest.join("/"))
        };
        self.own_names
            .iter()
            .zip(&at.named)
            .find_map(|((name, own), named)| {
                // A name in the part of the directory that stays, or one that
                // reaches into what the word adds.
                let mut from = end.saturating_sub(name.len());
                while !base.text.is_char_boundary(from) {
                    from -= 1;
                }
                let near = format!("{}{tail}", &base.text[from..end]);
                let hit = named.is_some_and(|n| n <= end) || named_end(&near, name).is_some();
                hit.then_some(own.as_path())
            })
    }

    /// [`globs_own`](Self::globs_own) of the relative `word` joined to the
    /// working directory.
    fn joined_globs_own(&self, base: &Base, word: &str) -> Option<&Path> {
        let Some(at) = &base.at else {
            let path = base.slow_join(word);
            let segs: Vec<&str> = path.split('/').collect();
            return self.own_names.iter().find_map(|(name, own)| {
                let want: Vec<&str> = name.split('/').collect();
                let hit = segs.len() >= want.len()
                    && want
                        .iter()
                        .zip(&segs)
                        .all(|(w, s)| segment_matches(s, w, self.windows));
                hit.then_some(own.as_path())
            });
        };
        let (kept, rest) = at.join(word);
        self.own_names
            .iter()
            .zip(&at.leading)
            .find_map(|((name, own), &leading)| {
                let want: Vec<&str> = name.split('/').collect();
                let from_base = kept.min(want.len());
                let hit = kept + rest.len() >= want.len()
                    && leading >= from_base
                    && want[from_base..]
                        .iter()
                        .zip(&rest)
                        .all(|(w, s)| segment_matches(s, w, self.windows));
                hit.then_some(own.as_path())
            })
    }

    /// The node's own folder that lies strictly below `dir`: a program
    /// handed `dir` would reach it.
    pub fn own_below(&self, dir: &Path) -> Option<&Path> {
        let folded = fold(dir);
        self.own
            .iter()
            .find(|o| self.inside(o, &folded) && !self.inside(&folded, o))
            .map(PathBuf::as_path)
    }

    /// The own folder whose name `text` holds, followed by anything but
    /// more of a file name (`nerve-notes` is not `nerve`).
    fn names_own(&self, text: &str) -> Option<&Path> {
        self.own_names.iter().find_map(|(name, own)| {
            let hit = text
                .match_indices(name.as_str())
                .any(|(at, _)| !text[at + name.len()..].starts_with(name_char));
            hit.then_some(own.as_path())
        })
    }

    /// The protected entry `path` falls in, unless a folder releases it for
    /// a read (`r`) or a write (`w`) of `path`. The node's own folders are
    /// never released.
    pub fn check(&self, path: &Path, write: bool, folders: &[Folder]) -> Option<&Path> {
        let needs = |a: Access| if write { a.write } else { a.read };
        self.check_for(path, write, folders, needs)
    }

    /// [`Protected::check`] for the working directory of a command: a
    /// folder releases it only with `x`.
    pub fn check_run(&self, path: &Path, folders: &[Folder]) -> Option<&Path> {
        self.check_for(path, false, folders, |a| a.execute)
    }

    fn check_for(
        &self,
        path: &Path,
        write: bool,
        folders: &[Folder],
        needs: impl Fn(Access) -> bool,
    ) -> Option<&Path> {
        if let Some(own) = self.own(path) {
            return Some(own);
        }
        let folded = fold(path);
        let mut write_only = self.write_only.iter().filter(|_| write);
        let entry = self
            .entries
            .iter()
            .find(|e| self.inside(&folded, e))
            .or_else(|| write_only.find(|e| self.inside(&folded, e)))?;
        // Released by name and by flag: the deepest folder that holds `path`
        // lies at or inside the protected entry and gives what the call
        // needs. A folder with `r` there releases reads only, and the rest
        // of the place stays protected in every mode, `user` too.
        let released = self
            .deepest(folders, path)
            .is_some_and(|g| self.holds(entry, Path::new(&g.path)) && needs(g.access));
        if released { None } else { Some(entry) }
    }

    /// Where `folder` really is: its path resolved through the links on it.
    /// Landlock follows a link in a rule's path, so a folder that is, or
    /// passes through, a link into a protected entry would give a command
    /// that entry. Such a folder is refused (`Err`, with the reason) unless
    /// `folders` release the place it leads to for each flag it sets, by
    /// name, as [`Protected::check`] judges a call there. A folder that
    /// does not exist yet is judged by the part of it that does; a dangling
    /// link, or a path that cannot be resolved, is refused. A node resolves
    /// the list of the platform it runs on: on Windows a folder's grant for
    /// the command's AppContainer lands where a link or junction leads too.
    /// A list of the other platform (a test's) takes the path as it is.
    pub fn real_folder(&self, folder: &Folder, folders: &[Folder]) -> Result<PathBuf, String> {
        let path = Path::new(&folder.path);
        if self.windows != cfg!(windows) {
            return Ok(path.to_path_buf());
        }
        let real =
            resolve(path).map_err(|e| format!("{} cannot be resolved: {e}", path.display()))?;
        let a = folder.access;
        let unreleased = [
            ("r", a.read, self.check(&real, false, folders)),
            ("w", a.write, self.check(&real, true, folders)),
            ("x", a.execute, self.check_run(&real, folders)),
        ]
        .into_iter()
        .find_map(|(flag, set, entry)| entry.filter(|_| set).map(|e| (flag, e)));
        match unreleased {
            Some((flag, entry)) => Err(format!(
                "{} leads to {}, which is protected ({}) and not released there with {flag}",
                path.display(),
                real.display(),
                entry.display()
            )),
            None => Ok(real),
        }
    }

    /// Whether `path` is `base` or inside it, by this list's path rules.
    pub fn holds(&self, base: &Path, path: &Path) -> bool {
        self.inside(&fold(path), &fold(base))
    }

    /// The entries a read (or, with `write`, a write) is refused in.
    fn listed(&self, write: bool) -> impl Iterator<Item = &PathBuf> {
        let write_only = self.write_only.iter().filter(move |_| write);
        self.entries.iter().chain(write_only)
    }

    /// Whether `path` is a protected entry or inside one, whatever a folder
    /// releases; with `write` the entries protected for writes count too.
    pub fn in_entry(&self, path: &Path, write: bool) -> bool {
        let folded = fold(path);
        self.listed(write).any(|e| self.inside(&folded, e))
    }

    /// Whether a protected entry lies strictly inside `dir` (with `write`,
    /// one protected for writes counts too), so that a Landlock rule for
    /// `dir` would grant it.
    pub fn holds_entry(&self, dir: &Path, write: bool) -> bool {
        let folded = fold(dir);
        self.listed(write)
            .any(|e| self.inside(e, &folded) && !self.inside(&folded, e))
    }

    /// A protected entry strictly below `dir` (with `write`, one protected
    /// for writes counts too) that `folders` do not release for that
    /// access, as [`Protected::check`] judges a call at the entry itself: a
    /// program handed `dir` would reach it.
    pub fn entry_below(&self, dir: &Path, write: bool, folders: &[Folder]) -> Option<&Path> {
        let folded = fold(dir);
        self.listed(write)
            .find(|e| {
                self.inside(e, &folded)
                    && !self.inside(&folded, e)
                    && self.check(e, write, folders).is_some()
            })
            .map(PathBuf::as_path)
    }

    /// The deepest of `folders` that holds `path`, by this list's path rules
    /// and by components, as the decision picks it (`decide::inside_folder`).
    pub fn deepest<'f>(&self, folders: &'f [Folder], path: &Path) -> Option<&'f Folder> {
        let depth = |f: &Folder| {
            let p = fold(Path::new(&f.path));
            if self.windows {
                win::depth(&p.to_string_lossy())
            } else {
                p.components().count()
            }
        };
        folders
            .iter()
            .filter(|f| self.holds(Path::new(&f.path), path))
            .max_by_key(|f| depth(f))
    }

    /// The tool-config component (`.git`, `.envrc`, ...) a write to `path` touches.
    pub fn tool_config(&self, path: &Path) -> Option<&'static str> {
        let windows = self.windows;
        path.to_string_lossy()
            .split(|c| c == '/' || (windows && c == '\\'))
            .find_map(|n| {
                let n = n.to_lowercase();
                TOOL_CONFIG.iter().find(|t| **t == n).copied()
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Access;

    fn prot() -> Protected {
        Protected::new(
            &Platform::Unix,
            Path::new("/home/u"),
            &[PathBuf::from("/home/u/.config/nerve")],
            &ProtectedOptions::default(),
        )
    }

    /// A Windows node's list, built from plain strings so it is tested on
    /// every platform.
    fn win_prot() -> Protected {
        let folders = WinFolders {
            program_data: vec![PathBuf::from("C:\\ProgramData")],
            system_root: vec![PathBuf::from("C:\\Windows")],
            program_files: vec![
                PathBuf::from("C:\\Program Files"),
                PathBuf::from("C:\\Program Files (x86)"),
            ],
            documents: vec![],
        };
        Protected::new(
            &Platform::Windows(folders),
            Path::new("C:\\Users\\u"),
            &[
                PathBuf::from("C:\\Users\\u\\nerve-test\\node-config"),
                PathBuf::from("C:\\Users\\u\\nerve-test\\node-state"),
            ],
            &ProtectedOptions::default(),
        )
    }

    fn folder(p: &str) -> Folder {
        Folder {
            path: p.into(),
            access: Access::parse("rw").unwrap(),
        }
    }

    #[test]
    fn protects_keys_shell_startup_and_own_config() {
        let p = prot();
        for path in [
            "/home/u/.ssh/id_ed25519",
            "/home/u/.bashrc",
            "/home/u/.config/systemd/user/x.service",
            "/home/u/.config/nerve/node.toml",
            "/etc/sudoers.d/x",
            "/home/u/.SSH/id_rsa",
        ] {
            assert!(p.check(Path::new(path), false, &[]).is_some(), "{path}");
        }
        assert!(
            p.check(Path::new("/home/u/.local/bin/sudo"), false, &[])
                .is_none()
        );
        assert!(
            p.check(Path::new("/home/u/.local/bin/sudo"), true, &[])
                .is_some()
        );
        for path in ["/home/u/proj/a.rs", "/home/u/.sshx", "/home/u/.config"] {
            assert!(p.check(Path::new(path), true, &[]).is_none(), "{path}");
        }
    }

    /// The OpenSSH server's files, the registry hives with the password
    /// hashes and the user's own hive, besides the keys in the profile.
    #[test]
    fn protects_windows_system_and_credential_files() {
        let p = win_prot();
        for path in [
            "C:\\ProgramData\\ssh\\administrators_authorized_keys",
            "C:\\ProgramData\\ssh\\sshd_config",
            "C:\\ProgramData\\ssh\\ssh_host_ed25519_key",
            "c:\\programdata\\SSH",
            "\\\\?\\C:\\ProgramData\\ssh\\sshd_config",
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\System32\\config\\SYSTEM",
            "C:\\WINDOWS\\system32\\CONFIG\\security",
            "C:\\Windows\\System32\\config\\RegBack\\SAM",
            "C:\\Users\\u\\NTUSER.DAT",
            "C:\\Users\\u\\ntuser.dat",
            "C:\\Users\\u\\.ssh\\id_ed25519",
            "C:\\Users\\u\\AppData\\Roaming\\Microsoft\\Credentials\\x",
            "C:\\Users\\u\\.cargo\\credentials.toml",
            "C:\\Users\\u\\nerve-test\\node-config\\node.toml",
        ] {
            for write in [false, true] {
                assert!(
                    p.check(Path::new(path), write, &[]).is_some(),
                    "{path} {write}"
                );
            }
        }
        for path in [
            "C:\\ProgramData\\sshx",
            "C:\\ProgramData\\Other\\ssh",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\Windows\\System32\\configx",
            "C:\\Users\\u\\NTUSER.DAT.txt",
            "C:\\Users\\u\\proj\\a.rs",
            "D:\\ProgramData\\ssh\\sshd_config",
        ] {
            assert!(p.check(Path::new(path), true, &[]).is_none(), "{path}");
        }
        // A grant of the whole drive does not release them; one by name does.
        let keys = Path::new("C:\\ProgramData\\ssh\\administrators_authorized_keys");
        assert!(p.check(keys, true, &[folder("C:\\")]).is_some());
        assert!(
            p.check(keys, true, &[folder("C:\\ProgramData\\ssh")])
                .is_none()
        );
        // Writes to tool config by either separator.
        assert_eq!(
            p.tool_config(Path::new("C:\\w\\.GIT\\hooks\\x")),
            Some(".git")
        );
        assert_eq!(p.tool_config(Path::new("C:\\w\\src\\git.rs")), None);
    }

    /// The all-users Startup folder and the all-users PowerShell profiles run
    /// code at every user's logon or in every PowerShell session, like
    /// `/etc/xdg/autostart` and `/etc/profile`.
    #[test]
    fn protects_the_windows_all_users_start_up_and_profiles() {
        let p = win_prot();
        for path in [
            "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\x.cmd",
            "c:\\programdata\\microsoft\\windows\\start menu\\programs\\startup",
            "C:/ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp/x.lnk",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\profile.ps1",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Microsoft.PowerShell_profile.ps1",
            "C:\\WINDOWS\\system32\\windowspowershell\\V1.0\\Modules\\x\\x.psm1",
            "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\profile.ps1",
        ] {
            for write in [false, true] {
                assert!(
                    p.check(Path::new(path), write, &[]).is_some(),
                    "{path} {write}"
                );
            }
        }
        for path in [
            "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Accessories\\x.lnk",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0x\\profile.ps1",
        ] {
            assert!(p.check(Path::new(path), true, &[]).is_none(), "{path}");
        }
    }

    /// PowerShell 7's home, `%ProgramFiles%\PowerShell\7`: it runs the
    /// all-users profiles and loads the modules there at every start, so a
    /// write there plants code in every PowerShell 7 session.
    #[test]
    fn protects_the_powershell_7_install_folder() {
        let p = win_prot();
        for path in [
            "C:\\Program Files\\PowerShell\\7\\profile.ps1",
            "C:\\Program Files\\PowerShell\\7\\Microsoft.PowerShell_profile.ps1",
            "C:\\Program Files\\PowerShell\\7\\Modules\\x\\x.psm1",
            "C:\\Program Files\\PowerShell\\Modules\\x\\x.psm1",
            "C:\\Program Files\\PowerShell\\7-preview\\profile.ps1",
            "c:/program files/powershell/7/PROFILE.PS1",
            "C:\\Program Files (x86)\\PowerShell\\7\\profile.ps1",
        ] {
            for write in [false, true] {
                assert!(
                    p.check(Path::new(path), write, &[]).is_some(),
                    "{path} {write}"
                );
            }
        }
        for path in [
            "C:\\Program Files\\Some App\\x.exe",
            "C:\\Program Files\\PowerShellx\\profile.ps1",
            "C:\\Program Files (x86)\\Some App\\x.exe",
        ] {
            assert!(p.check(Path::new(path), true, &[]).is_none(), "{path}");
        }
    }

    #[test]
    fn released_only_by_name() {
        let p = prot();
        let ssh = Path::new("/home/u/.ssh/config");
        assert!(p.check(ssh, false, &[folder("/home/u")]).is_some());
        assert!(p.check(ssh, false, &[folder("/home/u/.ssh")]).is_none());
        let opts = ProtectedOptions {
            allow: vec!["~/.docker".into()],
            extra: vec!["~/secret".into()],
        };
        let p = Protected::new(&Platform::Unix, Path::new("/home/u"), &[], &opts);
        assert!(
            p.check(Path::new("/home/u/.docker/x"), false, &[])
                .is_none()
        );
        assert!(p.check(Path::new("/home/u/secret/x"), false, &[]).is_some());
    }

    /// A folder at a protected entry releases it only for what its flags
    /// give: `r` on `~/.ssh` lets a call read there, not write
    /// `authorized_keys`, and the deepest folder decides for what it holds.
    #[test]
    fn a_release_gives_only_the_access_of_its_folder() {
        let p = prot();
        let with = |path: &str, access: &str| Folder {
            path: path.into(),
            access: Access::parse(access).unwrap(),
        };
        let keys = Path::new("/home/u/.ssh/authorized_keys");
        let ro = [with("/home/u/.ssh", "r")];
        assert!(p.check(keys, false, &ro).is_none());
        assert!(p.check(keys, true, &ro).is_some());
        let wo = [with("/home/u/.ssh", "w")];
        assert!(p.check(keys, true, &wo).is_none());
        assert!(p.check(keys, false, &wo).is_some());
        assert!(p.check(keys, true, &[folder("/home/u/.ssh")]).is_none());
        let nested = [folder("/home/u/.ssh"), with("/home/u/.ssh/keep", "r")];
        assert!(
            p.check(Path::new("/home/u/.ssh/keep/x"), true, &nested)
                .is_some()
        );
        assert!(p.check(keys, true, &nested).is_none());
        // A folder around the entry gives it nothing, whatever its flags.
        let around = [folder("/home/u"), with("/home/u/.ssh", "r")];
        assert!(p.check(keys, true, &around).is_some());
        // A command there needs `x`.
        let ssh = Path::new("/home/u/.ssh");
        assert!(p.check_run(ssh, &[folder("/home/u/.ssh")]).is_some());
        assert!(p.check_run(ssh, &[with("/home/u/.ssh", "x")]).is_none());
        assert!(
            p.check_run(Path::new("/home/u/proj"), &[with("/home/u/.ssh", "r")])
                .is_none()
        );
    }

    #[test]
    fn finds_tool_config() {
        let p = prot();
        assert_eq!(p.tool_config(Path::new("/w/.git/hooks/x")), Some(".git"));
        assert_eq!(p.tool_config(Path::new("/w/src/git.rs")), None);
    }

    /// Spellings that could slip past the check: forward slashes,
    /// the home in each shell's form, `..` from the working directory, quotes
    /// and other case.
    #[test]
    fn sees_the_own_folders_in_windows_spellings() {
        let p = win_prot();
        let proj = Path::new("C:\\Users\\u\\nerve-test\\proj");
        let home = Path::new("C:\\Users\\u");
        for (command, cwd) in [
            (
                "type C:\\Users\\u\\nerve-test\\node-config\\node.toml",
                home,
            ),
            (
                "type \"C:\\Users\\U\\Nerve-Test\\node-config\\node.toml\"",
                home,
            ),
            (
                "type \\\\?\\C:\\Users\\u\\nerve-test\\node-config\\node.toml",
                home,
            ),
            ("type C:/Users/u/nerve-test/node-state/config.key", home),
            ("type \"C:/Users/u/nerve-test/node-state/config.key\"", home),
            ("type 'c:/users/u/nerve-test/node-state'", home),
            (
                "type C:\\\\Users\\\\u\\\\nerve-test\\\\node-state\\\\config.key",
                home,
            ),
            ("Get-Content ~/nerve-test/node-config/node.toml", proj),
            ("Get-Content ~\\nerve-test\\node-config\\node.toml", proj),
            (
                "Get-Content \"~\\nerve-test\\node-config\\node.toml\"",
                proj,
            ),
            ("Get-Content $HOME/nerve-test/node-config/node.toml", proj),
            (
                "Get-Content $HOME\\nerve-test\\node-state\\config.key",
                proj,
            ),
            (
                "Get-Content ${HOME}\\nerve-test\\node-state\\config.key",
                proj,
            ),
            (
                "Get-Content $env:USERPROFILE\\nerve-test\\node-config\\node.toml",
                proj,
            ),
            (
                "gc \"$env:userprofile/nerve-test/node-config/node.toml\"",
                proj,
            ),
            (
                "gc ${env:USERPROFILE}\\nerve-test\\node-config\\node.toml",
                proj,
            ),
            (
                "cmd /c type %USERPROFILE%\\nerve-test\\node-config\\node.toml",
                proj,
            ),
            ("Get-Content ..\\node-config\\node.toml", proj),
            ("Get-Content '..\\node-state\\config.key'", proj),
            ("Get-Content ../node-config/node.toml", proj),
            ("Get-Content .\\nerve-test\\node-config\\node.toml", home),
            ("Get-Content nerve-test\\node-config", home),
            (
                "type C:\\Users\\u\\nerve-test\\proj\\..\\node-config\\node.toml",
                home,
            ),
            (
                "Set-Content -Path=~\\nerve-test\\node-config\\node.toml x",
                proj,
            ),
        ] {
            assert!(
                p.own_in_command(command, Some(cwd)).is_some(),
                "{command} in {cwd:?}"
            );
        }
        for (command, cwd) in [
            ("type C:\\Users\\u\\nerve-test\\node-config-notes\\a", home),
            ("type C:/Users/u/nerve-test/proj/a", home),
            ("Get-Content ~/nerve-test/proj/a", proj),
            ("Get-Content ..\\proj\\a", proj),
            ("Get-Content node-config\\node.toml", proj),
            ("type D:\\Users\\u\\nerve-test\\node-config\\x", home),
            ("Get-Content $HOMEX\\nerve-test\\node-config", proj),
            ("echo a~\\nerve-test\\node-config", proj),
        ] {
            assert!(
                p.own_in_command(command, Some(cwd)).is_none(),
                "{command} in {cwd:?}"
            );
        }
    }

    /// More spellings that could slip past the check:
    /// 8.3 short names, a path without a drive, an admin share and
    /// wildcards in a folder's name.
    #[test]
    fn sees_the_own_folders_in_short_unc_driveless_and_wildcard_spellings() {
        let p = win_prot();
        let proj = Path::new("C:\\Users\\u\\nerve-test\\proj");
        let home = Path::new("C:\\Users\\u");
        for (command, cwd) in [
            ("type C:\\Users\\U~1\\NERVE-~1\\NODE-S~1\\config.key", home),
            ("type C:\\Users\\u\\nerve-test\\NODE-S~1\\config.key", home),
            (
                "type C:\\PROGRA~1\\..\\Users\\u\\NERVE-~3\\node-state",
                home,
            ),
            ("type /Users/u/nerve-test/node-state/config.key", proj),
            ("type \\Users\\u\\nerve-test\\node-state\\config.key", proj),
            (
                "type \\\\localhost\\C$\\Users\\u\\nerve-test\\node-state\\config.key",
                proj,
            ),
            (
                "type \\\\127.0.0.1\\c$\\Users\\u\\nerve-test\\node-config\\node.toml",
                proj,
            ),
            (
                "type \\\\?\\UNC\\localhost\\C$\\Users\\u\\nerve-test\\node-state\\config.key",
                proj,
            ),
            ("type C:/Users/u/nerve-test/node-st*/config.key", proj),
            ("type C:/Users/u/nerve-test/node-s?ate/config.key", proj),
            ("type C:/Users/u/nerve-test/node-*", proj),
            ("type C:/Users/u/*/node-[s]tate/config.key", proj),
            ("type C:/*/*/*/*/config.key", proj),
            ("type ../node-st*/config.key", proj),
            (
                "type $env:HOMEDRIVE$env:HOMEPATH\\nerve-test\\node-state\\config.key",
                proj,
            ),
            ("type %HOMEPATH%\\nerve-test\\node-state\\config.key", proj),
        ] {
            assert!(
                p.own_in_command(command, Some(cwd)).is_some(),
                "{command} in {cwd:?}"
            );
        }
        for (command, cwd) in [
            ("type C:/Users/u/nerve-test/proj*/a", home),
            ("type C:/Users/u/nerve-test/node-c*x/a", home),
            ("type C:/Users/u/*.txt", home),
            ("type D:/Users/u/nerve-test/proj/node-st*", home),
            (
                "type \\\\localhost\\C$\\Users\\u\\nerve-test\\proj\\a",
                proj,
            ),
            ("type C:\\PROGRA~1\\x\\y", home),
            ("type /Users/u/nerve-test/proj/a", proj),
        ] {
            assert!(
                p.own_in_command(command, Some(cwd)).is_none(),
                "{command} in {cwd:?}"
            );
        }
    }

    /// Still more spellings that could slip past the check:
    /// a trailing dot or space on a name, which Windows drops, a volume or
    /// device path, and a drive-relative path (`C:name`) from the working
    /// directory.
    #[test]
    fn sees_the_own_folders_with_trailing_dots_volumes_and_drive_relative_paths() {
        let p = win_prot();
        let test = Path::new("C:\\Users\\u\\nerve-test");
        let proj = Path::new("C:\\Users\\u\\nerve-test\\proj");
        let home = Path::new("C:\\Users\\u");
        let other = Path::new("D:\\work");
        for (command, cwd) in [
            (
                "type C:\\Users\\u\\nerve-test\\node-state.\\config.key",
                home,
            ),
            ("type C:/Users/u/nerve-test/node-state./config.key", home),
            (
                "type C:\\Users\\u\\nerve-test\\node-config.\\node.toml",
                home,
            ),
            (
                "type C:\\Users\\u\\nerve-test\\node-config..\\node.toml",
                home,
            ),
            (
                "type 'C:\\Users\\u\\nerve-test\\node-state .\\config.key'",
                home,
            ),
            (
                "type C:\\Users\\u\\nerve-test.\\node-state\\config.key",
                home,
            ),
            ("Remove-Item C:\\Users\\u\\nerve-test\\node-state.", home),
            ("type node-state.\\config.key", test),
            ("type ..\\node-state.\\config.key", proj),
            (
                "type \\\\?\\Volume{4803db6f-0000-0000-0000-100000000000}\\Users\\u\\nerve-test\\node-state\\config.key",
                other,
            ),
            (
                "type \\\\.\\Volume{4803db6f-0000-0000-0000-100000000000}\\Users\\u\\nerve-test\\node-config\\node.toml",
                other,
            ),
            (
                "type \\\\?\\GLOBALROOT\\Device\\HarddiskVolume3\\Users\\u\\nerve-test\\node-state\\config.key",
                other,
            ),
            (
                "type \\\\.\\UNC\\localhost\\C$\\Users\\u\\nerve-test\\node-state\\config.key",
                other,
            ),
            ("type C:node-state\\config.key", test),
            ("type c:node-config\\node.toml", test),
            ("type C:nerve-test\\node-state\\config.key", home),
            ("type C:..\\node-state\\config.key", proj),
            ("type \"C:node-state\"", test),
        ] {
            assert!(
                p.own_in_command(command, Some(cwd)).is_some(),
                "{command} in {cwd:?}"
            );
        }
        for (command, cwd) in [
            ("type C:\\Users\\u\\nerve-test\\proj.\\a", home),
            ("type C:\\Users\\u\\nerve-test\\node-state.bak\\a", home),
            ("type C:\\Users\\u\\nerve-test\\node-state.txt", home),
            ("echo node-state. done", proj),
            (
                "type \\\\?\\Volume{4803db6f-0000-0000-0000-100000000000}\\Users\\u\\nerve-test\\proj\\a",
                other,
            ),
            ("type C:proj\\a", test),
            ("type C:node-state\\config.key", other),
            ("type D:nerve-test\\node-state\\config.key", home),
            ("type C:.\\a", test),
        ] {
            assert!(
                p.own_in_command(command, Some(cwd)).is_none(),
                "{command} in {cwd:?}"
            );
        }
    }

    /// PowerShell takes `$PROFILE` and the user's modules from the Documents
    /// known folder, which OneDrive's backup or a redirect moves away from
    /// the profile: both places are protected.
    #[test]
    fn protects_the_powershell_profiles_in_a_moved_documents_folder() {
        let folders = WinFolders {
            documents: vec![PathBuf::from("D:\\OneDrive\\Documents")],
            ..WinFolders::default()
        };
        let p = Protected::new(
            &Platform::Windows(folders),
            Path::new("C:\\Users\\u"),
            &[],
            &ProtectedOptions::default(),
        );
        for path in [
            "D:\\OneDrive\\Documents\\WindowsPowerShell\\Microsoft.PowerShell_profile.ps1",
            "D:\\OneDrive\\Documents\\PowerShell\\Microsoft.PowerShell_profile.ps1",
            "d:/onedrive/documents/powershell/Modules/x/x.psm1",
            "D:\\OneDrive\\Documents\\WindowsPowerShell",
            "C:\\Users\\u\\Documents\\WindowsPowerShell\\profile.ps1",
            "C:\\Users\\u\\Documents\\PowerShell\\profile.ps1",
        ] {
            for write in [false, true] {
                assert!(
                    p.check(Path::new(path), write, &[]).is_some(),
                    "{path} {write}"
                );
            }
        }
        for path in [
            "D:\\OneDrive\\Documents\\notes.txt",
            "D:\\OneDrive\\Documents\\PowerShellx\\a",
            "D:\\OneDrive\\WindowsPowerShell\\a",
        ] {
            assert!(p.check(Path::new(path), true, &[]).is_none(), "{path}");
        }
    }

    #[test]
    fn globs_match_like_the_shells() {
        for (pattern, name) in [
            ("node-*", "node-state"),
            ("*", ""),
            ("n*e", "node-state"),
            ("*-*-*", "a-b-c"),
            ("node-[!x]tate", "node-state"),
            ("node-[a-z]tate", "node-state"),
            ("[]a]", "]"),
        ] {
            assert!(glob(pattern, name), "{pattern} {name}");
        }
        for (pattern, name) in [
            ("node-*x", "node-state"),
            ("?", ""),
            ("node-[^s]tate", "node-state"),
            ("node-[s", "node-s"),
        ] {
            assert!(!glob(pattern, name), "{pattern} {name}");
        }
        assert!(glob("node-[s", "node-[s"));
        assert!(segment_matches("node-s~1", "node-state", true));
        assert!(!segment_matches("node-s~1", "node-state", false));
        assert!(!segment_matches("node~x", "node-state", true));
    }

    /// The short name Windows gave a real folder reaches it as well.
    /// Volumes without 8.3 names give none, and the test then has nothing to
    /// check.
    #[cfg(windows)]
    #[test]
    fn a_windows_short_name_names_the_own_folder() {
        use std::os::windows::process::CommandExt;
        let tmp = tempfile::tempdir().unwrap();
        let own = tmp.path().join("node-state-of-this-test");
        std::fs::create_dir(&own).unwrap();
        // cmd's `%~sI` prints the 8.3 form of a path.
        let out = std::process::Command::new("cmd")
            .raw_arg(format!(
                "/c for %I in (\"{}\") do @echo %~sI",
                own.display()
            ))
            .output()
            .unwrap();
        let short = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if short.is_empty() || short.eq_ignore_ascii_case(&own.to_string_lossy()) {
            eprintln!("no 8.3 name for {own:?}, nothing to check");
            return;
        }
        let p = Protected::new(
            &Platform::Windows(WinFolders::default()),
            tmp.path(),
            std::slice::from_ref(&own),
            &ProtectedOptions::default(),
        );
        let command = format!("Get-Content {short}\\config.key");
        assert!(
            p.own_in_command(&command, Some(tmp.path())).is_some(),
            "{command}"
        );
        let beside = format!("Get-Content {}\\other", tmp.path().display());
        assert!(
            p.own_in_command(&beside, Some(tmp.path())).is_none(),
            "{beside}"
        );
    }

    /// The Unix shells' forms; the Windows ones mean nothing there.
    #[test]
    fn sees_the_own_folders_in_unix_spellings() {
        let p = prot();
        let home = Path::new("/home/u");
        for command in [
            "cat ~/.config/nerve/node.toml",
            "cat $HOME/.config/nerve",
            "cat ${HOME}/.config//nerve/x",
            "cat /home/u/./.config/nerve/x",
            "cat /home/u/a/b/../../.config/nerve/x",
            "cat '~/.config/nerve/x'",
            "cat .config/nerve/x",
            "cat x>~/.config/nerve/x",
            // Two words; the second is a path from the working directory.
            "cat /home/u/a b/../.config/nerve/x",
        ] {
            assert!(p.own_in_command(command, Some(home)).is_some(), "{command}");
        }
        for command in [
            "cat $env:USERPROFILE/.config/nerve/x",
            "cat %USERPROFILE%/.config/nerve/x",
            "cat ~\\.config\\nerve\\x",
            "cat ~/.config/nerve-notes",
        ] {
            assert!(p.own_in_command(command, Some(home)).is_none(), "{command}");
        }
    }

    /// A word of many drive letters (`a:a:a:…`) or many brackets, or many
    /// words from a deep working directory, are looked at in work that
    /// grows with their length, not with its square or with words times
    /// directory: no copy and no new pass per drive letter or per word.
    #[test]
    fn long_lines_take_linear_work() {
        let n = 16 * 1024;
        let tail = "/users/u/nerve-test/other/x";
        let win_deep = format!("C:\\Users\\u\\nerve-test\\proj{}", "\\d".repeat(2000));
        let unix_deep = format!("/home/u/a b{}", "/d".repeat(2000));
        let win_test = "C:\\Users\\u\\nerve-test";
        let cases = [
            (win_prot(), "a:".repeat(n), "/x"),
            (win_prot(), format!("{}{tail}", "c:".repeat(n)), "/x"),
            (win_prot(), "a:*".repeat(n), "/x"),
            (win_prot(), "a:[".repeat(n), "/x"),
            (win_prot(), "a:~1".repeat(n), "/x"),
            (win_prot(), format!("/{}{tail}", "[".repeat(2 * n)), "/x"),
            (prot(), format!("/{}/a/b/c/d", "[".repeat(2 * n)), "/x"),
            (win_prot(), "a ".repeat(n), &win_deep),
            (win_prot(), "..\\..\\x ".repeat(n / 4), &win_deep),
            (prot(), "a ".repeat(n), &unix_deep),
            (prot(), "../../x ".repeat(n / 4), &unix_deep),
            // Drive-relative from a working directory on the same drive.
            (win_prot(), "c:-".repeat(n), win_test),
            (win_prot(), "c:*-".repeat(n), win_test),
            (win_prot(), "c:[".repeat(n), win_test),
            (win_prot(), format!("{}\\..\\x", "c:-".repeat(n)), win_test),
        ];
        for (p, line, cwd) in cases {
            WORK.with(|w| w.set(0));
            let command = format!("type {line}");
            assert!(p.own_in_command(&command, Some(Path::new(cwd))).is_none());
            let work = WORK.with(std::cell::Cell::get);
            assert!(
                work <= 64 * (command.len() + cwd.len()),
                "{work} for {} bytes in {} bytes: {}",
                command.len(),
                cwd.len(),
                &line[..12]
            );
        }
        // Still seen behind the drive letters, and back up from the deep
        // directory.
        let command = format!("type {}c:/users/u/nerve-test/node-config/x", "a:".repeat(n));
        assert!(win_prot().own_in_command(&command, None).is_some());
        let command = format!("type {}node-config", "..\\".repeat(2001));
        let deep = Path::new(&win_deep);
        assert!(win_prot().own_in_command(&command, Some(deep)).is_some());
        let command = format!(
            "type {}c:{}node-config",
            "c:".repeat(n),
            "..\\".repeat(2001)
        );
        assert!(win_prot().own_in_command(&command, Some(deep)).is_some());
        let command = format!("type {}.config/nerve", "../".repeat(2000));
        let deep = format!("/home/u{}", "/d".repeat(2000));
        assert!(
            prot()
                .own_in_command(&command, Some(Path::new(&deep)))
                .is_some()
        );
    }

    #[test]
    fn dotdot_folds_only_plain_names_within_a_word() {
        assert_eq!(fold_dotdot("/a/b/../c"), "/a/c");
        assert_eq!(fold_dotdot("/a/b/c/../../d"), "/a/d");
        assert_eq!(fold_dotdot("/a/b/.."), "/a");
        assert_eq!(fold_dotdot("/../a"), "/../a");
        assert_eq!(fold_dotdot("/a/../../b"), "/../b");
        assert_eq!(fold_dotdot("/a/..b/c"), "/a/..b/c");
        assert_eq!(fold_dotdot("x a b/../c"), "x a b/../c");
        assert_eq!(fold_dotdot("c:/../x"), "c:/../x");
        assert_eq!(
            expand_home("~ ~/a a~ x=~/b", "/h", false),
            "/h /h/a a~ x=/h/b"
        );
        assert_eq!(expand_home("$home/a $homes", "/h", false), "/h/a $homes");
    }
}
