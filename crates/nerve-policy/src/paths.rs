//! Turning a path from the center into the real path the policy judges.
//!
//! The center sends absolute device paths in one form on every platform: `/home/x`
//! on Linux, `/c/Users/x` for `C:\Users\x` on Windows. The device refuses anything
//! else instead of guessing (relative paths, untranslated drive letters, UNC and
//! `\\?\` paths, NUL bytes, Windows device names and alternate data streams), then
//! resolves symlinks and `..` so the policy sees where a call would really land. On
//! Unix the node's `fs.read` and `fs.write` then open that resolved path one
//! component at a time without following a symlink, so a symlink that appears
//! between check and use fails the call. The other `fs` actions, and every action
//! on Windows, go by the resolved path as it is then.

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

#[derive(Debug)]
pub enum PathError {
    Empty,
    Relative,
    /// `C:\...` or `C:/...`: the center must translate drive letters to `/c/...`.
    DriveLetter,
    /// UNC, `\\?\` or device paths, or a backslash in a Windows wire path.
    Unc,
    Nul,
    /// A Windows device name (`CON`, `NUL`, `COM1`, ...) as a path component.
    Reserved(String),
    /// A component Windows would silently change or read as a stream: a `:`
    /// (alternate data stream), a trailing dot or space, or a wildcard character.
    BadComponent(String),
    /// The path names a symlink whose target does not exist.
    DanglingSymlink(PathBuf),
    /// `..` after the part of the path that exists; it cannot be resolved safely.
    ParentInMissingPart,
    Io(io::Error),
}

impl std::fmt::Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathError::Empty => write!(f, "empty path"),
            PathError::Relative => write!(f, "path must be absolute"),
            PathError::DriveLetter => write!(
                f,
                "untranslated drive-letter path; use /c/... (the drive as a folder), \
                 for example /c/Users/... for C:\\Users\\..."
            ),
            PathError::Unc => write!(f, "UNC and device paths are not accepted"),
            PathError::Nul => write!(f, "path contains a NUL byte"),
            PathError::Reserved(c) => write!(f, "{c} is a Windows device name"),
            PathError::BadComponent(c) => write!(f, "{c:?} is not a plain file name"),
            PathError::DanglingSymlink(p) => write!(f, "{} is a dangling symlink", p.display()),
            PathError::ParentInMissingPart => {
                write!(f, "'..' after a path component that does not exist")
            }
            PathError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for PathError {}

fn common_checks(s: &str) -> Result<(), PathError> {
    if s.is_empty() {
        return Err(PathError::Empty);
    }
    if s.contains('\0') {
        return Err(PathError::Nul);
    }
    let b = s.as_bytes();
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        return Err(PathError::DriveLetter);
    }
    if s.starts_with("\\\\") || s.starts_with("//") {
        return Err(PathError::Unc);
    }
    if !s.starts_with('/') {
        return Err(PathError::Relative);
    }
    Ok(())
}

/// Checks the syntax of a path from the center and turns it into a native path.
#[cfg(not(windows))]
pub fn parse_device_path(s: &str) -> Result<PathBuf, PathError> {
    common_checks(s)?;
    Ok(PathBuf::from(s))
}

/// Checks the syntax of a path from the center and turns it into a native path.
#[cfg(windows)]
pub fn parse_device_path(s: &str) -> Result<PathBuf, PathError> {
    common_checks(s)?;
    win::from_wire(s).map(PathBuf::from)
}

/// A native path as the center sees it.
pub fn to_wire(p: &Path) -> String {
    #[cfg(windows)]
    {
        win::to_wire(&p.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        p.to_string_lossy().into_owned()
    }
}

/// Windows path rules as pure string functions, so they are tested on every
/// platform. On Windows they back `parse_device_path`, `within` and `to_wire`.
pub mod win {
    use super::PathError;

    const RESERVED: &[&str] = &[
        "con",
        "prn",
        "aux",
        "nul",
        "conin$",
        "conout$",
        "clock$",
        "com0",
        "com1",
        "com2",
        "com3",
        "com4",
        "com5",
        "com6",
        "com7",
        "com8",
        "com9",
        "com\u{b9}",
        "com\u{b2}",
        "com\u{b3}",
        "lpt0",
        "lpt1",
        "lpt2",
        "lpt3",
        "lpt4",
        "lpt5",
        "lpt6",
        "lpt7",
        "lpt8",
        "lpt9",
        "lpt\u{b9}",
        "lpt\u{b2}",
        "lpt\u{b3}",
    ];

    /// `/c/Users/x` to `C:\Users\x`. Refuses backslashes (the wire separator is `/`),
    /// device names with or without an extension (`NUL.txt`), `:` (alternate data
    /// streams), names ending in a dot or space (Windows strips them, so `a.` would
    /// open `a`) and wildcard characters.
    pub fn from_wire(s: &str) -> Result<String, PathError> {
        super::common_checks(s)?;
        if s.contains('\\') {
            return Err(PathError::Unc);
        }
        let mut parts = s[1..].split('/');
        let drive = parts.next().unwrap_or_default();
        if drive.len() != 1 || !drive.as_bytes()[0].is_ascii_alphabetic() {
            return Err(PathError::Relative);
        }
        let mut out = format!("{}:\\", drive.to_ascii_uppercase());
        let mut first = true;
        for c in parts {
            if c.is_empty() || c == "." {
                continue;
            }
            if c != ".." {
                check_component(c)?;
            }
            if !first {
                out.push('\\');
            }
            out.push_str(c);
            first = false;
        }
        Ok(out)
    }

    fn check_component(c: &str) -> Result<(), PathError> {
        if c.contains([':', '*', '?', '"', '<', '>', '|']) || c.chars().any(|ch| (ch as u32) < 32) {
            return Err(PathError::BadComponent(c.to_string()));
        }
        if c.ends_with('.') || c.ends_with(' ') {
            return Err(PathError::BadComponent(c.to_string()));
        }
        let base = c
            .split('.')
            .next()
            .unwrap_or_default()
            .trim_end()
            .to_lowercase();
        if RESERVED.contains(&base.as_str()) {
            return Err(PathError::Reserved(c.to_string()));
        }
        Ok(())
    }

    /// Drops the `\\?\` prefix of a local drive path. A verbatim UNC path stays
    /// as it is (and fails `to_wire`'s drive form).
    pub fn strip_verbatim(s: &str) -> &str {
        match s.strip_prefix("\\\\?\\") {
            Some(rest) if rest.as_bytes().get(1) == Some(&b':') => rest,
            _ => s,
        }
    }

    /// `C:\Users\x` (or its `\\?\` form) to `/c/Users/x`.
    pub fn to_wire(native: &str) -> String {
        let s = strip_verbatim(native);
        let b = s.as_bytes();
        if b.len() >= 2 && b[1] == b':' {
            let rest = s[2..].replace('\\', "/");
            let rest = rest.trim_end_matches('/');
            format!("/{}{}", (b[0] as char).to_ascii_lowercase(), rest)
        } else {
            s.replace('\\', "/")
        }
    }

    /// The components `within` compares: by either separator, in lower case.
    fn parts(s: &str) -> Vec<String> {
        strip_verbatim(s)
            .split(['\\', '/'])
            .filter(|c| !c.is_empty())
            .map(|c| c.to_lowercase())
            .collect()
    }

    /// `path` is `base` or inside it, by whole components and ignoring case, as NTFS
    /// does by default.
    pub fn within(path: &str, base: &str) -> bool {
        let (p, b) = (parts(path), parts(base));
        p.len() >= b.len() && p[..b.len()] == b[..]
    }

    /// How many components `within` sees in `path`.
    pub fn depth(path: &str) -> usize {
        parts(path).len()
    }

    /// A folder path in the form the policy keeps it: `\` between the parts,
    /// no `\\?\` prefix, no doubled separator, no `.` part and no separator
    /// at the end (`C:\` keeps its one). Case stays as it was given. A path
    /// that is not on a drive (a UNC path) stays as it is; no resolved path
    /// is one, so such a folder holds nothing.
    pub fn normal(path: &str) -> Result<String, String> {
        let s = strip_verbatim(path);
        let b = s.as_bytes();
        if !(b.len() >= 3
            && b[0].is_ascii_alphabetic()
            && b[1] == b':'
            && matches!(b[2], b'\\' | b'/'))
        {
            return Ok(s.to_string());
        }
        let mut out = format!("{}\\", &s[..2]);
        let kept = super::kept_parts(&s[3..], &['\\', '/'], path)?;
        out.push_str(&kept.join("\\"));
        Ok(out)
    }
}

/// The parts of `rest` between `seps`, without empty and `.` parts. `..` is
/// refused: with a symlink on the way it names another place than the
/// policy would see (`whole` is the path for the message).
fn kept_parts<'a>(rest: &'a str, seps: &[char], whole: &str) -> Result<Vec<&'a str>, String> {
    let mut kept = Vec::new();
    for part in rest.split(seps).filter(|p| !p.is_empty() && *p != ".") {
        if part == ".." {
            return Err(format!(
                "folder {whole:?} has a .. in it; give the folder's path without one"
            ));
        }
        kept.push(part);
    }
    Ok(kept)
}

/// [`normal_folder`] for a Unix path: `/` between the parts, no doubled
/// `/`, no `.` part and no `/` at the end (`/` itself stays).
pub fn normal_unix(path: &str) -> Result<String, String> {
    let rest = path.strip_prefix('/').unwrap_or(path);
    Ok(format!("/{}", kept_parts(rest, &['/'], path)?.join("/")))
}

/// An absolute folder path in the one form the policy keeps, so that two
/// spellings of one place are one string and compare as one folder.
pub fn normal_folder(path: &str) -> Result<String, String> {
    #[cfg(windows)]
    {
        win::normal(path)
    }
    #[cfg(not(windows))]
    {
        normal_unix(path)
    }
}

/// How many components [`within`] compares in `path`: the deeper of two
/// folders that both hold a path is the one with more.
pub fn depth(path: &Path) -> usize {
    #[cfg(windows)]
    {
        win::depth(&path.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        path.components().count()
    }
}

/// Resolves an absolute path: the part that exists through `realpath`, the rest
/// appended as is. A missing rest may not contain `..`, and a dangling symlink is
/// refused, since either could point anywhere once created.
pub fn resolve(path: &Path) -> Result<PathBuf, PathError> {
    if !path.is_absolute() {
        return Err(PathError::Relative);
    }
    match canonical(path) {
        Ok(p) => return Ok(p),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(PathError::Io(e)),
    }
    let comps: Vec<Component> = path.components().collect();
    // The root (and on Windows the drive) always exists.
    let roots = comps
        .iter()
        .take_while(|c| matches!(c, Component::Prefix(_) | Component::RootDir))
        .count();
    let mut prefix: PathBuf = comps[..roots].iter().collect();
    let mut existing = roots;
    // The longest prefix that exists (as anything, symlinks included).
    for (i, c) in comps.iter().enumerate().skip(roots) {
        let next = prefix.join(c.as_os_str());
        match fs::symlink_metadata(&next) {
            Ok(_) => {
                prefix = next;
                existing = i + 1;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => break,
            Err(e) => return Err(PathError::Io(e)),
        }
    }
    let real_prefix = match canonical(&prefix) {
        Ok(p) => p,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(PathError::DanglingSymlink(prefix));
        }
        Err(e) => return Err(PathError::Io(e)),
    };
    let mut out = real_prefix;
    for c in &comps[existing..] {
        match c {
            Component::Normal(name) => out.push(name),
            Component::CurDir => {}
            _ => return Err(PathError::ParentInMissingPart),
        }
    }
    Ok(out)
}

/// Whether a link's `target`, as the link holds it, may be a place on
/// another machine: anything but a path on a drive or volume of this one
/// (`C:\…`, `\\?\C:\…`, `\??\Volume{…}\…`) or one relative to the link.
/// So a share (`\\host\share`, `\\?\UNC\…`, `\??\UNC\…`) is, and so is
/// every device path, which may name one (`\\?\GLOBALROOT\Device\Mup\…`,
/// `\Device\Mup\…`), and every other path from a root (`\…`): Windows may
/// read that from the root of all its object names, which hold more ways
/// to a share. Windows connects to a share as whoever follows the link,
/// and sends that account's NTLM answer to whatever host it names (#149's
/// probe).
pub fn remote_target(target: &str) -> bool {
    let lower = target.replace('/', "\\").to_ascii_lowercase();
    let rest = match ["\\\\?\\", "\\\\.\\", "\\??\\"]
        .iter()
        .find_map(|p| lower.strip_prefix(p))
    {
        Some(r) => r,
        // Only a path relative to the link, or on a drive, is this
        // machine's; one from a root (`\\host\…`, `\x`) may not be.
        None => return lower.starts_with('\\'),
    };
    let b = rest.as_bytes();
    let drive = b.len() >= 2
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && b.get(2).is_none_or(|c| *c == b'\\');
    !(drive || rest.starts_with("volume{"))
}

/// The first link on the way of `p` (absolute), and on the way of where each
/// link leads, that leads to another machine ([`remote_target`]), found
/// without following any: a symbolic link to a share is followed by a
/// connection to it. Windows only; elsewhere a network mount is a path.
///
/// `None` also where a part of the way cannot be looked at (the caller has
/// no right on it); [`remote_link_checked`] tells those apart. Fit for a
/// caller that acts as an account which can look at the whole way.
pub fn remote_link(p: &Path) -> Option<PathBuf> {
    remote_link_checked(p).unwrap_or(None)
}

/// [`remote_link`], but an error where a part of the way cannot be looked
/// at: the caller cannot tell there is no link, and Windows follows a link in
/// a folder its caller may not look into (traversing is not checked), so
/// whoever follows the path next would connect to a share it names.
pub fn remote_link_checked(p: &Path) -> io::Result<Option<PathBuf>> {
    #[cfg(windows)]
    {
        remote_link_by(p, 0, &link_target)
    }
    #[cfg(not(windows))]
    {
        let _ = p;
        Ok(None)
    }
}

/// Where the link at `at` leads, or `None` when `at` is not a link.
#[cfg(windows)]
fn link_target(at: &Path) -> io::Result<Option<PathBuf>> {
    if !fs::symlink_metadata(at)?.file_type().is_symlink() {
        return Ok(None);
    }
    fs::read_link(at).map(Some)
}

/// [`remote_link_checked`] with the file system behind `target`: the place
/// the link at a path leads to (`Ok(None)` for a path that is none), or why
/// it cannot be told. A path that is not there ends the way (nothing
/// below it is a link).
#[cfg(any(windows, test))]
fn remote_link_by(
    p: &Path,
    depth: usize,
    target: &dyn Fn(&Path) -> io::Result<Option<PathBuf>>,
) -> io::Result<Option<PathBuf>> {
    // Windows follows no more than 63 links on a path.
    if depth > 63 {
        return Ok(None);
    }
    let mut at = PathBuf::new();
    for c in p.components() {
        at.push(c.as_os_str());
        let to = match target(&at) {
            Ok(Some(to)) => to,
            Ok(None) => continue,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        if remote_target(&to.to_string_lossy()) {
            return Ok(Some(at));
        }
        let next = match at.parent() {
            Some(dir) if to.is_relative() => dir.join(&to),
            _ => to,
        };
        if remote_link_by(&next, depth + 1, target)?.is_some() {
            return Ok(Some(at));
        }
    }
    Ok(None)
}

/// `realpath`, on Windows without the `\\?\` prefix so resolved paths compare with
/// configured ones. A path whose links lead to another machine is refused
/// before anything follows them ([`remote_link`]).
fn canonical(p: &Path) -> io::Result<PathBuf> {
    if let Some(link) = remote_link(p) {
        return Err(io::Error::other(format!(
            "{} is a link to another machine, which is not followed",
            link.display()
        )));
    }
    let c = fs::canonicalize(p)?;
    #[cfg(windows)]
    {
        let s = c.to_string_lossy();
        let stripped = win::strip_verbatim(&s);
        if stripped.starts_with("\\\\") {
            return Err(io::Error::other("network paths are not accepted"));
        }
        Ok(PathBuf::from(stripped))
    }
    #[cfg(not(windows))]
    {
        Ok(c)
    }
}

/// `path` is `base` or inside it, compared by whole components (`/a/bc` is not inside
/// `/a/b`); on Windows ignoring case. Both should be resolved paths.
pub fn within(path: &Path, base: &Path) -> bool {
    #[cfg(windows)]
    {
        win::within(&path.to_string_lossy(), &base.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        path.starts_with(base)
    }
}

#[cfg(test)]
mod win_tests {
    use super::PathError;
    use super::win::*;

    #[test]
    fn translates_wire_paths() {
        assert_eq!(from_wire("/c/Users/x/proj").unwrap(), "C:\\Users\\x\\proj");
        assert_eq!(from_wire("/d").unwrap(), "D:\\");
        assert_eq!(from_wire("/c/a//./b/").unwrap(), "C:\\a\\b");
        assert_eq!(to_wire("C:\\Users\\x"), "/c/Users/x");
        assert_eq!(to_wire("\\\\?\\C:\\Users\\x\\"), "/c/Users/x");
        assert_eq!(to_wire("C:\\"), "/c");
    }

    #[test]
    fn refuses_what_windows_would_reinterpret() {
        let bad = |s: &str| from_wire(s).unwrap_err();
        assert!(matches!(bad("C:\\Users"), PathError::DriveLetter));
        assert!(matches!(bad("c:/Users"), PathError::DriveLetter));
        assert!(matches!(bad("\\\\?\\C:\\x"), PathError::Unc));
        assert!(matches!(bad("\\\\server\\share"), PathError::Unc));
        assert!(matches!(bad("//server/share"), PathError::Unc));
        assert!(matches!(bad("/c/Users\\x"), PathError::Unc));
        assert!(matches!(bad("/cc/x"), PathError::Relative));
        assert!(matches!(bad("/c/proj/NUL"), PathError::Reserved(_)));
        assert!(matches!(bad("/c/proj/con.txt"), PathError::Reserved(_)));
        assert!(matches!(bad("/c/proj/COM1.log"), PathError::Reserved(_)));
        assert!(matches!(bad("/c/proj/lpt\u{b9}"), PathError::Reserved(_)));
        assert!(matches!(bad("/c/proj/aux /x"), PathError::BadComponent(_)));
        assert!(matches!(
            bad("/c/proj/a.txt:secret"),
            PathError::BadComponent(_)
        ));
        assert!(matches!(
            bad("/c/proj/a.txt::$DATA"),
            PathError::BadComponent(_)
        ));
        assert!(matches!(bad("/c/proj/x."), PathError::BadComponent(_)));
        assert!(matches!(bad("/c/proj/x "), PathError::BadComponent(_)));
        assert!(matches!(bad("/c/proj/*.rs"), PathError::BadComponent(_)));
        // Ordinary names that only look close are fine.
        assert!(from_wire("/c/proj/console.log").is_ok());
        assert!(from_wire("/c/proj/nulled").is_ok());
        assert!(from_wire("/c/PROGRA~1/x").is_ok());
    }

    #[test]
    fn folders_are_kept_in_one_form() {
        assert_eq!(normal("C:/u//proj/./").unwrap(), "C:\\u\\proj");
        assert_eq!(normal("\\\\?\\C:\\Users\\x\\").unwrap(), "C:\\Users\\x");
        assert_eq!(normal("c:\\Users\\X").unwrap(), "c:\\Users\\X");
        assert_eq!(normal("C:\\").unwrap(), "C:\\");
        assert_eq!(normal("C:/").unwrap(), "C:\\");
        assert!(normal("C:\\a\\..\\b").unwrap_err().contains(".."));
        // Two spellings of one place hold each other and are as deep.
        let (a, b) = ("C:\\Users\\u\\.ssh", "c:/users/U/.ssh/");
        assert!(within(a, b) && within(b, a));
        assert_eq!(depth(a), depth(b));
        assert!(depth("C:\\Users\\u\\.ssh\\inner") > depth(a));
    }

    #[test]
    fn within_ignores_case_and_verbatim_prefixes() {
        assert!(within("C:\\Users\\X\\Proj\\a", "c:\\users\\x\\proj"));
        assert!(within("\\\\?\\C:\\Users\\x\\proj", "C:\\Users\\x\\proj"));
        assert!(!within("C:\\Users\\x\\project", "C:\\Users\\x\\proj"));
        assert!(!within("D:\\Users\\x\\proj", "C:\\Users\\x\\proj"));
        assert!(!within("C:\\Users", "C:\\Users\\x"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_what_it_cannot_interpret() {
        assert!(matches!(parse_device_path(""), Err(PathError::Empty)));
        assert!(matches!(parse_device_path("a/b"), Err(PathError::Relative)));
        assert!(matches!(parse_device_path("~/x"), Err(PathError::Relative)));
        assert!(matches!(
            parse_device_path("C:\\Users"),
            Err(PathError::DriveLetter)
        ));
        assert!(matches!(
            parse_device_path("c:/x"),
            Err(PathError::DriveLetter)
        ));
        assert!(matches!(
            parse_device_path("\\\\srv\\share"),
            Err(PathError::Unc)
        ));
        assert!(matches!(parse_device_path("/a\0b"), Err(PathError::Nul)));
        // The wire form is the native one on Unix; Windows reads a drive.
        let native = if cfg!(windows) {
            "C:\\Users"
        } else {
            "/c/Users"
        };
        assert_eq!(parse_device_path("/c/Users").unwrap(), Path::new(native));
    }

    /// A model that sends `C:\...` for a Windows node is told the wire form.
    #[test]
    fn a_drive_letter_path_is_told_the_wire_form() {
        for s in ["C:\\Users\\x\\a.txt", "c:/Users/x"] {
            let e = parse_device_path(s).unwrap_err().to_string();
            assert!(
                e.contains("/c/...") && e.contains("/c/Users/... for C:\\Users\\..."),
                "{s}: {e}"
            );
        }
    }

    #[test]
    fn unix_folders_are_kept_in_one_form() {
        assert_eq!(normal_unix("/home/u//proj/./").unwrap(), "/home/u/proj");
        assert_eq!(normal_unix("/").unwrap(), "/");
        assert_eq!(normal_unix("//").unwrap(), "/");
        assert!(normal_unix("/a/../b").unwrap_err().contains(".."));
        #[cfg(not(windows))]
        {
            assert_eq!(depth(Path::new("/a/b/")), depth(Path::new("/a//b")));
            assert!(depth(Path::new("/a/b/c")) > depth(Path::new("/a/b///")));
        }
    }

    #[test]
    fn within_compares_components() {
        assert!(within(Path::new("/a/b"), Path::new("/a/b")));
        assert!(within(Path::new("/a/b/c"), Path::new("/a/b")));
        assert!(!within(Path::new("/a/bc"), Path::new("/a/b")));
        assert!(!within(Path::new("/a"), Path::new("/a/b")));
    }
}

/// Needs real symlinks, which a Windows test run may not create (they take
/// developer mode or the privilege to create them).
#[cfg(all(test, unix))]
mod unix_tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn resolves_symlinks_and_dotdot() {
        let t = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(t.path()).unwrap();
        fs::create_dir(root.join("granted")).unwrap();
        fs::create_dir(root.join("outside")).unwrap();
        symlink(root.join("outside"), root.join("granted/link")).unwrap();
        assert_eq!(
            resolve(&root.join("granted/link/new.txt")).unwrap(),
            root.join("outside/new.txt")
        );
        assert_eq!(
            resolve(&root.join("granted/../outside/x")).unwrap(),
            root.join("outside/x")
        );
        assert_eq!(
            resolve(&root.join("granted/./a/b")).unwrap(),
            root.join("granted/a/b")
        );
        assert!(matches!(
            resolve(&root.join("granted/missing/../../outside")),
            Err(PathError::ParentInMissingPart)
        ));
        symlink(root.join("nowhere/x"), root.join("granted/dangling")).unwrap();
        assert!(matches!(
            resolve(&root.join("granted/dangling")),
            Err(PathError::DanglingSymlink(_))
        ));
        assert!(matches!(
            resolve(&root.join("granted/dangling/y")),
            Err(PathError::DanglingSymlink(_))
        ));
    }
}

#[cfg(test)]
mod remote_tests {
    use super::*;

    #[test]
    fn a_link_to_another_machine_is_told_by_its_target() {
        for t in [
            r"\\host\share",
            r"\\host\share\sub",
            "//host/share",
            r"\\?\UNC\host\share",
            r"\??\UNC\host\share",
            r"\\?\unc\host\share",
            r"\\.\UNC\host\share",
            r"\\?\GLOBALROOT\Device\Mup\host\share",
            r"\??\GLOBALROOT\Device\Mup\host\share",
            r"\Device\Mup\host\share",
            r"\GLOBALROOT\Device\Mup\host\share",
            // Another root of Windows' object names that leads to shares.
            r"\GLOBAL??\UNC\host\share",
            // From a root: the node cannot tell where Windows reads it from.
            r"\x\y",
            "/home/x",
            // Only drives and volumes count as this machine's.
            r"\\.\pipe\x",
            r"\\?\Device\HarddiskVolume1\x",
        ] {
            assert!(remote_target(t), "{t}");
        }
        for t in [
            r"C:\Users\x",
            "C:",
            r"\\?\C:\Users\x",
            r"\\.\C:\x",
            r"\??\C:\x",
            r"\\?\Volume{0b1c2d3e-0000-0000-0000-100000000000}\x",
            r"..\x",
            "x",
            "C:x",
        ] {
            assert!(!remote_target(t), "{t}");
        }
    }

    /// The links of a made-up file system: `links` maps a path to where it
    /// leads, `hidden` are paths the caller may not look at, anything else
    /// is a plain folder, and `/gone` is not there.
    fn fake_fs<'a>(
        links: &'a [(&'a str, &'a str)],
        hidden: &'a [&'a str],
    ) -> impl Fn(&Path) -> io::Result<Option<PathBuf>> + 'a {
        move |at| {
            let s = at.to_string_lossy();
            if hidden.iter().any(|h| *h == s) {
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
            if s == "/gone" {
                return Err(io::Error::from(io::ErrorKind::NotFound));
            }
            Ok(links
                .iter()
                .find(|(l, _)| *l == s)
                .map(|(_, to)| PathBuf::from(to)))
        }
    }

    /// The walk names a link to a share, also behind a local link, and goes
    /// on past a plain folder and a path that is not there.
    #[test]
    fn the_link_walk_finds_a_link_to_another_machine() {
        let fs = fake_fs(
            &[
                ("/a/share", r"\\192.0.2.1\share"),
                ("/b/hop", "/a/share"),
                ("/b/rel", "hop"),
            ],
            &[],
        );
        for (path, want) in [
            ("/a/share/x", Some("/a/share")),
            ("/b/hop", Some("/b/hop")),
            ("/b/rel", Some("/b/rel")),
            ("/a/plain/x", None),
            ("/gone/x", None),
        ] {
            let got = remote_link_by(Path::new(path), 0, &fs).unwrap();
            assert_eq!(got, want.map(PathBuf::from), "{path}");
        }
    }

    /// A part of the way the caller may not look at is an error, not "no
    /// link": Windows follows a link in a folder its caller may not look
    /// into, by a connection to the share, so a caller that went on would
    /// send its NTLM answer there (the installed node's own account, in the
    /// owner's folders). A link it did see before that is still named.
    #[test]
    fn the_link_walk_does_not_call_a_path_plain_that_it_cannot_look_at() {
        let fs = fake_fs(&[("/open/share", r"\\192.0.2.1\share")], &["/owner/g"]);
        let e = remote_link_by(Path::new("/owner/g/sub"), 0, &fs).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            remote_link_by(Path::new("/open/share/owner/g"), 0, &fs).unwrap(),
            Some(PathBuf::from("/open/share"))
        );
        // A link that leads to a place it cannot look at is no better.
        let fs = fake_fs(&[("/open/l", "d")], &["/open/d"]);
        assert!(remote_link_by(Path::new("/open/l"), 0, &fs).is_err());
    }

    /// A symbolic link to a share is refused by its target, before
    /// anything follows it: following it would connect to the share as the
    /// account the node acts as (#149's probe). An address of TEST-NET
    /// would hold a connection for half a minute. Needs the right to make
    /// symbolic links (an administrator, as CI).
    #[cfg(windows)]
    #[test]
    fn a_link_to_another_machine_is_not_followed() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("w");
        std::fs::create_dir_all(&dir).unwrap();
        let link = dir.join("share");
        if let Err(e) = std::os::windows::fs::symlink_dir(r"\\192.0.2.1\share", &link) {
            panic!("cannot make a symbolic link (an administrator makes one): {e}");
        }
        // And one that leads to it through another, local, link.
        let hop = d.path().join("hop");
        std::os::windows::fs::symlink_dir(&dir, &hop).unwrap();
        let t = std::time::Instant::now();
        for p in [link.join("x"), hop.join("share").join("x")] {
            assert!(remote_link(&p).is_some(), "{p:?}");
            let e = resolve(&p).unwrap_err().to_string();
            assert!(e.contains("link to another machine"), "{e}");
        }
        assert!(t.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(remote_link(&dir.join("x")), None);
    }
}
