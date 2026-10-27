//! The `fs` capability (spec §7.2). Calls are parsed first ([`FsCall::parse`])
//! so the policy can judge their paths, then run on a blocking thread.

use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use globset::{Glob, GlobMatcher};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use nerve_policy::paths::{parse_device_path, resolve, to_wire};
use nerve_policy::{Link, PathAccess, Target};
use nerve_proto::rpc::params;
use nerve_proto::{ErrorCode, RpcError};

/// The most bytes one `read` returns, so the result stays well inside the
/// 4 MiB message limit once base64 grows it.
pub const READ_MAX: u64 = 2 * 1024 * 1024;
/// The largest file `write` takes (the message limit bounds it anyway).
pub const WRITE_MAX: usize = 3 * 1024 * 1024;
/// `grep` skips files larger than this.
const GREP_FILE_MAX: u64 = 8 * 1024 * 1024;
/// Default and largest `max` for `grep` and `find`.
const MAX_DEFAULT: usize = 200;
const MAX_LIMIT: usize = 5000;
/// Entries a walk visits at most, so a call on `/` ends.
const WALK_LIMIT: usize = 200_000;
/// Entries `list` returns at most.
const LIST_MAX: usize = 10_000;
/// Entries [`links_below`] looks at at most, as many as a walk visits.
pub const LINKS_LIMIT: usize = WALK_LIMIT;

pub fn bad_path(msg: impl Into<String>) -> RpcError {
    RpcError::new(ErrorCode::Other("bad_path".into()), msg)
}

pub fn io_error(e: impl std::fmt::Display) -> RpcError {
    RpcError::new(ErrorCode::Other("io".into()), e.to_string())
}

pub fn conflict(msg: impl Into<String>) -> RpcError {
    RpcError::new(ErrorCode::Other("conflict".into()), msg)
}

/// A path from the center: as given (native form) and resolved.
#[derive(Debug, Clone)]
pub struct WirePath {
    pub given: PathBuf,
    pub real: PathBuf,
}

impl WirePath {
    pub fn parse(s: &str) -> Result<WirePath, RpcError> {
        let given = parse_device_path(s).map_err(|e| bad_path(format!("{s}: {e}")))?;
        let real = resolve(&given).map_err(|e| bad_path(format!("{s}: {e}")))?;
        Ok(WirePath { given, real })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PathArgs {
    path: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadArgs {
    path: String,
    #[serde(default)]
    offset: Option<u64>,
    #[serde(default)]
    length: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrepArgs {
    path: String,
    pattern: String,
    #[serde(default)]
    glob: Option<String>,
    #[serde(default)]
    max: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FindArgs {
    path: String,
    glob: String,
    #[serde(default)]
    max: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteArgs {
    path: String,
    content: String,
    #[serde(default)]
    encoding: Option<String>,
    #[serde(default)]
    if_match: Option<String>,
}

/// Why [`readable`] says no.
#[derive(Debug, PartialEq)]
pub enum Unreadable {
    /// The account may not open it for reading.
    Closed,
    /// It is neither a file nor a folder (a device, a FIFO, a socket). No
    /// read of `fs` opens one, and opening one does things of its own: a
    /// serial port's lines change, which resets the board on it, and a
    /// writer that waits on a FIFO goes on and then breaks. So it is never
    /// opened to ask.
    NotFile,
}

/// Whether this thread's file access may read `path`: as the account
/// [`crate::link::act_as`] gives it, where a call reads as its command
/// account. A file or a folder is opened for reading and closed again; on
/// Linux it is first opened without reading it (`O_PATH`) and asked what it
/// is, and only then opened, through that same entry ([`reopen`]), so what
/// is opened is what was asked. A path that does not exist passes: nothing
/// can be read there, and the call says so itself.
#[cfg(target_os = "linux")]
pub fn readable(path: &Path) -> Result<(), Unreadable> {
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| Unreadable::Closed)?;
    // Through libc, not `OpenOptions`: on musl the standard library takes
    // O_PATH out of the flags (crate::service's `chown_entry` says more).
    // SAFETY: a valid C string; the new descriptor is owned below.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        return match e.kind() {
            std::io::ErrorKind::NotFound => Ok(()),
            _ => Err(Unreadable::Closed),
        };
    }
    // SAFETY: open returned a fresh descriptor nothing else owns.
    let held = std::fs::File::from(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) });
    match held.metadata() {
        Ok(m) if m.is_file() || m.is_dir() => {}
        Ok(_) => return Err(Unreadable::NotFile),
        Err(_) => return Err(Unreadable::Closed),
    }
    reopen(&held).map(drop).map_err(|_| Unreadable::Closed)
}

/// [`readable`] where no command account reads (crate::fs::open_to_all
/// says no to all there): the type is asked first, then the path opened.
#[cfg(not(target_os = "linux"))]
pub fn readable(path: &Path) -> Result<(), Unreadable> {
    match std::fs::metadata(path) {
        Ok(m) if m.is_file() || m.is_dir() => {}
        Ok(_) => return Err(Unreadable::NotFile),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(Unreadable::Closed),
    }
    std::fs::File::open(path)
        .map(drop)
        .map_err(|_| Unreadable::Closed)
}

/// Opens for reading the file or folder `held` holds, opened without
/// reading it (`O_PATH`). Through `/proc/self/fd` the kernel checks the
/// rights of the file itself again, as the account this thread's file
/// access acts as, and it is the very file held, whatever was put at its
/// path meanwhile. Non-blocking: an open for reading of a file another
/// process holds a write lease on (`F_SETLEASE`) waits until it lets go,
/// up to `lease-break-time` (45 s by default), and the gate asks on a
/// worker of the node's runtime. A file or a folder reads the same either
/// way.
#[cfg(target_os = "linux")]
fn reopen(held: &std::fs::File) -> std::io::Result<std::fs::File> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(format!("/proc/self/fd/{}", held.as_raw_fd()))
}

/// Whether `path` is open to every account on this machine by its mode
/// bits: each folder above it lets others pass (`o+x`) and it lets them read
/// (`o+r`). The command account reaches more than that only through what
/// the node gives it for the folders (their entries, and the pass-through
/// on the owner's folders above them: crate::acl), and through its own
/// folders; those belong to the folders, so a read in no folder goes only
/// where this says yes. A part of the path that does not exist passes, as in
/// [`readable`]: nothing can be read there. Asked as the account
/// ([`crate::link::act_as`]), a folder it cannot even look into says no.
#[cfg(unix)]
pub fn open_to_all(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    // The mode bits others have at `p`, or `None` where nothing is.
    let others = |p: &Path| match std::fs::metadata(p) {
        Ok(m) => Some(Some(m.permissions().mode() & 0o007)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(None),
        Err(_) => None,
    };
    let passes = path.ancestors().skip(1).all(|dir| match others(dir) {
        Some(Some(bits)) => bits & 0o001 != 0,
        Some(None) => true,
        None => false,
    });
    passes
        && match others(path) {
            Some(Some(bits)) => bits & 0o004 != 0,
            Some(None) => true,
            None => false,
        }
}

/// No platform but Unix has a command account of its own
/// (nerve_policy::decide::Reads::Account is Linux only), so nothing counts
/// as open to it.
#[cfg(not(unix))]
pub fn open_to_all(_: &Path) -> bool {
    false
}

/// Whether a call in folder mode may read `path`, which lies in no folder
/// of its pairing, where the node reads as the command account
/// (nerve_policy::decide::Reads::Account); asked as that account
/// ([`crate::link::act_as`]). `Err` says why not. The path must be open to
/// every account ([`open_to_all`]), so the entries the node put on for the
/// folders (another pairing's, the pass-through on the owner's folders above
/// them) reach no further than the folders, and a file or a folder the
/// account may open ([`readable`]). The node's own process is not the account's, though its
/// files under `/proc` look open to all: the kernel lets the node's threads
/// read them whatever account they act as. A `provider` reads with the
/// owner's rights, so a folder handed to it here would let it read below as
/// the owner whatever is closed to others.
///
/// The refusals other than the node's own process name no path: `path` is
/// resolved as the command account, which every pairing's commands share,
/// and a link of another of its processes (`/proc/<n>/cwd`) leads where
/// that process works. The center gave the path, and the audit entry names
/// where it led.
pub fn may_read_outside(path: &Path, provider: bool) -> Result<(), String> {
    if own_process(path) {
        Err(format!(
            "{} belongs to the node's own process; no mode reaches it",
            path.display()
        ))
    } else if !open_to_all(path) {
        Err(
            "a path this call reads is in no folder that allows reading, and not open to every \
             account on this machine"
                .into(),
        )
    } else if provider && path.is_dir() {
        Err(
            "a folder this call hands over is outside the folders that allow reading: a \
             provider would read below it with the owner's rights"
                .into(),
        )
    } else {
        readable(path).map_err(|why| match why {
            Unreadable::Closed => {
                "the account this center's commands run as may not read a path this call reads"
                    .into()
            }
            Unreadable::NotFile => "a path this call reads is in no folder that allows reading, \
                                    and is neither a file nor a folder"
                .into(),
        })
    }
}

/// Whether `path`, handed to a program, may hold other paths it reaches
/// (nerve_policy::decide::Target::holds): a folder, or for a `write` a path
/// that does not exist yet, where the program may make one. Asked as the
/// account the path was resolved as. What cannot be told counts as a
/// folder, so the checks below it err wide.
pub fn holds(path: &Path, write: bool) -> bool {
    match std::fs::metadata(path) {
        Ok(m) => m.is_dir(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => write,
        Err(_) => true,
    }
}

/// What [`links_below`] does with a folder it may not list, or an entry
/// whose type it cannot tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Closed {
    /// Leaves it out, as the node's own walks do: the program that gets the
    /// paths runs as the account that walks, and cannot list it either.
    Skip,
    /// Refuses the call: the program runs as another account (the owner, or
    /// root), which may list the folder and follow a link in it.
    Refuse,
}

/// Hands `judge` each link that lies below the paths of `targets` that may
/// hold others ([`Target::holds`]), with where it leads, for a call that
/// hands them to a program (nerve_policy::works_below). The node's own walks
/// never follow a link, but a program does, so each place a link leads to
/// is judged as a path of the call (nerve_policy::LinkCheck). A link is
/// judged when it is found, and a folder it leads to is looked into only
/// once it passed: a place the call may not reach is never walked, and no
/// refusal names what lies there. Asked as the account the paths were
/// resolved as; a folder it may not read is left out or refuses the call,
/// as `closed` says.
/// A link that leads nowhere is left out where the call reads (nothing is
/// there to read), and judged at the place it names where the call writes,
/// since a write through it makes that place. `Err` is the first refusal of
/// `judge`, or says why the node cannot tell where they all lead: more than
/// `limit` entries, counting those of the folders the links lead to, or a
/// link it cannot follow. The limit counts the entries below all the paths
/// together, so it bounds what one call costs. `stop` ends the walk once
/// nobody waits for its answer any more (the call's deadline passed, or it
/// was cancelled), so it does not run on after the call.
pub fn links_below(
    targets: &[Target],
    limit: usize,
    closed: Closed,
    stop: &AtomicBool,
    judge: &mut dyn FnMut(&Link) -> Option<String>,
) -> Result<(), String> {
    let mut seen = 0usize;
    for (handed, t) in targets.iter().enumerate().filter(|(_, t)| t.holds) {
        let write = t.access == PathAccess::Write;
        let given = to_wire(&t.path);
        // The folders to look into: the path itself, then each folder a
        // link leads to that lies in none looked into already.
        let mut roots = vec![t.path.clone()];
        let mut walked: HashSet<PathBuf> = HashSet::new();
        while let Some(root) = roots.pop() {
            if looked_into(&walked, &root) {
                continue;
            }
            walked.insert(root.clone());
            let mut stack = vec![root.clone()];
            while let Some(dir) = stack.pop() {
                let shut = || {
                    format!(
                        "{given} holds a folder the node may not look into, so it cannot tell \
                         where the links there lead"
                    )
                };
                let rd = match std::fs::read_dir(&dir) {
                    Ok(rd) => rd,
                    // Gone since it was found: nothing there to follow.
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(_) if closed == Closed::Refuse => return Err(shut()),
                    Err(_) => continue,
                };
                for e in rd {
                    // An entry the listing could not read, or whose type the
                    // walk cannot tell, may be a link or a folder. Where the
                    // filesystem names no types the walk asks for each with a
                    // stat, which a folder it may list but not enter refuses,
                    // so for another account's program that hides as much as
                    // a folder it may not list.
                    let (e, ft) = match e.and_then(|e| entry_type(&e).map(|ft| (e, ft))) {
                        Ok(typed) => typed,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(_) if closed == Closed::Refuse => return Err(shut()),
                        Err(_) => continue,
                    };
                    if stop.load(Ordering::Relaxed) {
                        return Err(format!(
                            "the call ended before the node had checked where the links below \
                             {given} lead"
                        ));
                    }
                    seen += 1;
                    if seen > limit {
                        return Err(format!(
                            "the paths this call hands over hold more than {limit} entries in \
                             all, counting those of the folders their links lead to; the node \
                             cannot check where the links in them lead"
                        ));
                    }
                    let at = e.path();
                    if ft.is_dir() {
                        stack.push(at);
                        continue;
                    }
                    if !ft.is_symlink() {
                        continue;
                    }
                    let cannot = || {
                        format!(
                            "{given} holds a link ({}) the node cannot follow",
                            to_wire(&at)
                        )
                    };
                    let to = match resolve(&at) {
                        Ok(to) => to,
                        Err(nerve_policy::paths::PathError::DanglingSymlink(_)) if !write => {
                            continue;
                        }
                        Err(nerve_policy::paths::PathError::DanglingSymlink(_)) => {
                            let named = std::fs::read_link(&at).map_err(|_| cannot())?;
                            let named = at.parent().map_or(named.clone(), |p| p.join(&named));
                            resolve(&named).map_err(|_| cannot())?
                        }
                        Err(_) => return Err(cannot()),
                    };
                    let link = Link {
                        handed,
                        at,
                        found_in: root.clone(),
                        to: Target {
                            holds: holds(&to, write),
                            path: to,
                            access: t.access,
                        },
                    };
                    if let Some(why) = judge(&link) {
                        return Err(why);
                    }
                    if link.to.holds {
                        roots.push(link.to.path);
                    }
                }
            }
        }
    }
    Ok(())
}

/// The type of an entry [`links_below`] lists. A test makes it fail, as it
/// does on a filesystem that names no types, where the walk may list a
/// folder but not enter it.
fn entry_type(e: &std::fs::DirEntry) -> std::io::Result<std::fs::FileType> {
    #[cfg(test)]
    if tests::UNTYPED.with(std::cell::Cell::get) {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    e.file_type()
}

/// Whether `root` lies in a folder [`links_below`] looked into already. It
/// asks for the folder and each one above it, so a walk of many links to
/// many folders costs each of them no more than its depth, not as much as
/// the folders looked into so far. Resolved paths keep the case they have
/// on disk, so where [`nerve_policy::paths::within`] ignores case (Windows)
/// a folder is still found by its own name.
fn looked_into(walked: &HashSet<PathBuf>, root: &Path) -> bool {
    root.ancestors().any(|a| {
        #[cfg(test)]
        tests::LOOKED_UP.with(|c| c.set(c.get() + 1));
        walked.contains(a)
    })
}

/// Whether `path` lies in the node's own entry of `/proc`: `/proc/self`,
/// `/proc/thread-self`, or `/proc/<n>` where `n` is the node or one of its
/// threads (a thread's entry is there too, though `/proc` does not list it).
/// A `/proc/<n>` that does not exist counts as the node's as well: the
/// thread the node starts for the read may take that id before it opens
/// the path, and nothing else can be read there.
#[cfg(target_os = "linux")]
pub fn own_process(path: &Path) -> bool {
    let Ok(rest) = path.strip_prefix("/proc") else {
        return false;
    };
    let Some(first) = rest.components().next() else {
        return false;
    };
    let first = first.as_os_str().to_string_lossy();
    if first == "self" || first == "thread-self" {
        return true;
    }
    first.parse::<u32>().is_ok_and(|n| {
        n == std::process::id()
            || Path::new("/proc/self/task").join(&*first).exists()
            || !Path::new("/proc").join(&*first).exists()
    })
}

/// Only Linux has a command account the node reads as.
#[cfg(not(target_os = "linux"))]
pub fn own_process(_: &Path) -> bool {
    false
}

/// One parsed `fs` call.
pub enum FsCall {
    Stat(WirePath),
    List(WirePath),
    Read {
        path: WirePath,
        offset: u64,
        length: Option<u64>,
    },
    Grep {
        path: WirePath,
        pattern: String,
        glob: Option<GlobMatcher>,
        max: usize,
    },
    Find {
        path: WirePath,
        glob: GlobMatcher,
        max: usize,
    },
    Write {
        path: WirePath,
        content: Vec<u8>,
        if_match: Option<String>,
    },
}

fn glob(s: &str) -> Result<GlobMatcher, RpcError> {
    Glob::new(s)
        .map(|g| g.compile_matcher())
        .map_err(|e| RpcError::invalid_args(format!("bad glob {s:?}: {e}")))
}

fn max(m: Option<usize>) -> Result<usize, RpcError> {
    match m {
        None => Ok(MAX_DEFAULT),
        Some(0) => Err(RpcError::invalid_args("max must be at least 1")),
        Some(m) => Ok(m.min(MAX_LIMIT)),
    }
}

impl FsCall {
    pub fn parse(action: &str, args: &Map<String, Value>) -> Result<FsCall, RpcError> {
        Ok(match action {
            "stat" => FsCall::Stat(WirePath::parse(&params::<PathArgs>(args)?.path)?),
            "list" => FsCall::List(WirePath::parse(&params::<PathArgs>(args)?.path)?),
            "read" => {
                let a: ReadArgs = params(args)?;
                FsCall::Read {
                    path: WirePath::parse(&a.path)?,
                    offset: a.offset.unwrap_or(0),
                    length: a.length,
                }
            }
            "grep" => {
                let a: GrepArgs = params(args)?;
                if a.pattern.is_empty() {
                    return Err(RpcError::invalid_args("pattern is empty"));
                }
                FsCall::Grep {
                    path: WirePath::parse(&a.path)?,
                    pattern: a.pattern,
                    glob: a.glob.as_deref().map(glob).transpose()?,
                    max: max(a.max)?,
                }
            }
            "find" => {
                let a: FindArgs = params(args)?;
                FsCall::Find {
                    path: WirePath::parse(&a.path)?,
                    glob: glob(&a.glob)?,
                    max: max(a.max)?,
                }
            }
            "write" => {
                let a: WriteArgs = params(args)?;
                let content = match a.encoding.as_deref() {
                    None | Some("utf8") => a.content.into_bytes(),
                    Some("base64") => B64
                        .decode(a.content.as_bytes())
                        .map_err(|e| RpcError::invalid_args(format!("bad base64: {e}")))?,
                    Some(e) => {
                        return Err(RpcError::invalid_args(format!(
                            "encoding must be utf8 or base64, not {e}"
                        )));
                    }
                };
                if content.len() > WRITE_MAX {
                    return Err(RpcError::new(
                        ErrorCode::TooLarge,
                        format!("at most {WRITE_MAX} bytes per write"),
                    ));
                }
                FsCall::Write {
                    path: WirePath::parse(&a.path)?,
                    content,
                    if_match: a.if_match,
                }
            }
            other => {
                return Err(RpcError::new(
                    ErrorCode::UnknownMember,
                    format!("fs has no action {other}"),
                ));
            }
        })
    }

    fn path(&self) -> &WirePath {
        match self {
            FsCall::Stat(p) | FsCall::List(p) => p,
            FsCall::Read { path, .. }
            | FsCall::Grep { path, .. }
            | FsCall::Find { path, .. }
            | FsCall::Write { path, .. } => path,
        }
    }

    /// What the policy judges.
    pub fn targets(&self) -> Vec<Target> {
        vec![Target {
            path: self.path().real.clone(),
            access: if matches!(self, FsCall::Write { .. }) {
                PathAccess::Write
            } else {
                PathAccess::Read
            },
            holds: true,
        }]
    }

    /// The target as the audit log shows it.
    pub fn target_text(&self) -> String {
        to_wire(&self.path().real)
    }

    /// Runs the call. `skip(path, through)` says which paths a walk leaves out
    /// (the protected, denied and, in folder mode, unreadable ones), so `grep`,
    /// `find` and `list` below an allowed folder never reveal what the policy
    /// hides. `through` is true for a folder `grep` and `find` would only pass
    /// through, which they may still do to reach a readable folder inside it.
    pub fn run(self, skip: &dyn Fn(&Path, bool) -> bool) -> Result<Value, RpcError> {
        match self {
            FsCall::Stat(p) => stat(&p.given),
            FsCall::List(p) => list(&p.real, skip),
            FsCall::Read {
                path,
                offset,
                length,
            } => read(&path.real, offset, length),
            FsCall::Grep {
                path,
                pattern,
                glob,
                max,
            } => grep(&path.real, &pattern, glob.as_ref(), max, skip),
            FsCall::Find { path, glob, max } => find(&path.real, &glob, max, skip),
            FsCall::Write {
                path,
                content,
                if_match,
            } => write(&path.real, &content, if_match.as_deref()),
        }
    }
}

fn type_of(ft: std::fs::FileType) -> &'static str {
    if ft.is_symlink() {
        "link"
    } else if ft.is_dir() {
        "dir"
    } else if ft.is_file() {
        "file"
    } else {
        "other"
    }
}

fn mtime_ms(m: &std::fs::Metadata) -> u64 {
    m.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn stat(path: &Path) -> Result<Value, RpcError> {
    let m = std::fs::symlink_metadata(path).map_err(io_error)?;
    Ok(json!({"type": type_of(m.file_type()), "size": m.len(), "mtime_ms": mtime_ms(&m)}))
}

fn list(path: &Path, skip: &dyn Fn(&Path, bool) -> bool) -> Result<Value, RpcError> {
    let mut entries = Vec::new();
    for e in std::fs::read_dir(path).map_err(io_error)? {
        let e = e.map_err(io_error)?;
        // A listed folder shows its name, so it is judged like a read.
        if skip(&e.path(), false) {
            continue;
        }
        let m = e.metadata().map_err(io_error)?;
        entries.push(json!({
            "name": e.file_name().to_string_lossy(),
            "type": type_of(m.file_type()),
            "size": m.len(),
        }));
        if entries.len() >= LIST_MAX {
            break;
        }
    }
    entries.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(json!({ "entries": entries }))
}

/// The hex SHA-256 of a file's bytes.
pub fn etag_of(path: &Path) -> std::io::Result<String> {
    digest(&mut std::fs::File::open(path)?)
}

/// The hex SHA-256 of what `r` reads.
fn digest(r: &mut impl Read) -> std::io::Result<String> {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    Ok(nerve_proto::msg::hex(ctx.finish().as_ref()))
}

/// An error opening `path`. A symlink, or a file where a folder was, means
/// the path changed after the policy judged it (it judged the resolved path,
/// which has neither).
fn open_error(path: &Path, e: std::io::Error) -> RpcError {
    #[cfg(unix)]
    if matches!(e.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) {
        return io_error(format!(
            "{}: the path changed after the policy checked it (a symlink or a file is in it now)",
            path.display()
        ));
    }
    io_error(format!("{}: {e}", path.display()))
}

/// The folder and the name of `path`.
fn split(path: &Path) -> Result<(&Path, &std::ffi::OsStr), RpcError> {
    let dir = path
        .parent()
        .ok_or_else(|| bad_path("the root is not a file"))?;
    let name = path.file_name().ok_or_else(|| bad_path("no file name"))?;
    Ok((dir, name))
}

fn read(path: &Path, offset: u64, length: Option<u64>) -> Result<Value, RpcError> {
    let (dir, name) = split(path)?;
    let dir = Dir::open(dir).map_err(|e| open_error(path, e))?;
    let not_file = || io_error(format!("{} is not a file", path.display()));
    let mut f = dir
        .open_file(name)
        .map_err(|e| open_error(path, e))?
        .ok_or_else(not_file)?;
    let m = f.metadata().map_err(io_error)?;
    let size = m.len();
    let want = length.unwrap_or(u64::MAX).min(READ_MAX);
    f.seek(SeekFrom::Start(offset.min(size)))
        .map_err(io_error)?;
    let mut bytes = Vec::new();
    (&mut f)
        .take(want)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    f.seek(SeekFrom::Start(0)).map_err(io_error)?;
    let etag = digest(&mut f).map_err(io_error)?;
    let (content, encoding) = match String::from_utf8(bytes) {
        Ok(s) => (s, "utf8"),
        Err(e) => (B64.encode(e.into_bytes()), "base64"),
    };
    Ok(json!({"content": content, "encoding": encoding, "size": size, "etag": etag}))
}

/// Visits files below `root` (or `root` itself), depth first, sorted, never
/// following symlinks, leaving out what `skip` names. `each` returns false to
/// stop. Returns whether the walk was cut short.
fn walk(
    root: &Path,
    skip: &dyn Fn(&Path, bool) -> bool,
    each: &mut dyn FnMut(&Path) -> bool,
) -> Result<bool, RpcError> {
    let m = std::fs::metadata(root).map_err(io_error)?;
    if m.is_file() {
        each(root);
        return Ok(false);
    }
    let mut stack = vec![root.to_path_buf()];
    let mut visited = 0usize;
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut names: Vec<_> = rd.filter_map(Result::ok).collect();
        names.sort_by_key(|e| std::cmp::Reverse(e.file_name()));
        let mut files = Vec::new();
        for e in names {
            visited += 1;
            if visited > WALK_LIMIT {
                return Ok(true);
            }
            let p = e.path();
            match e.file_type() {
                Ok(t) if t.is_dir() && !skip(&p, true) => stack.push(p),
                Ok(t) if t.is_file() && !skip(&p, false) => files.push(p),
                _ => {}
            }
        }
        for f in files.iter().rev() {
            if !each(f) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn relative_glob_match(glob: &GlobMatcher, root: &Path, p: &Path) -> bool {
    glob.is_match(p.strip_prefix(root).unwrap_or(p))
        || p.file_name().is_some_and(|n| glob.is_match(n))
}

fn grep(
    root: &Path,
    pattern: &str,
    glob: Option<&GlobMatcher>,
    max: usize,
    skip: &dyn Fn(&Path, bool) -> bool,
) -> Result<Value, RpcError> {
    let mut matches = Vec::new();
    let mut truncated = false;
    let cut = walk(root, skip, &mut |p| {
        if glob.is_some_and(|g| !relative_glob_match(g, root, p)) {
            return true;
        }
        let small = std::fs::metadata(p).is_ok_and(|m| m.len() <= GREP_FILE_MAX);
        let Some(text) = small
            .then(|| std::fs::read(p).ok())
            .flatten()
            .and_then(|b| String::from_utf8(b).ok())
        else {
            // Binary, unreadable or huge files are not searched.
            return true;
        };
        for (i, line) in text.lines().enumerate() {
            if line.contains(pattern) {
                if matches.len() >= max {
                    truncated = true;
                    return false;
                }
                let text: String = line.chars().take(500).collect();
                matches.push(json!({"path": to_wire(p), "line": i + 1, "text": text}));
            }
        }
        true
    })?;
    Ok(json!({"matches": matches, "truncated": truncated || cut}))
}

fn find(
    root: &Path,
    glob: &GlobMatcher,
    max: usize,
    skip: &dyn Fn(&Path, bool) -> bool,
) -> Result<Value, RpcError> {
    let mut paths = Vec::new();
    let mut truncated = false;
    let cut = walk(root, skip, &mut |p| {
        if relative_glob_match(glob, root, p) {
            if paths.len() >= max {
                truncated = true;
                return false;
            }
            paths.push(to_wire(p));
        }
        true
    })?;
    Ok(json!({"paths": paths, "truncated": truncated || cut}))
}

fn write(path: &Path, content: &[u8], if_match: Option<&str>) -> Result<Value, RpcError> {
    let (dir, name) = split(path)?;
    let dir = Dir::open(dir).map_err(|e| open_error(path, e))?;
    let current = match dir.open_file(name) {
        Ok(None) => return Err(io_error(format!("{} is not a file", path.display()))),
        Ok(Some(mut f)) => {
            let perm = f.metadata().map_err(io_error)?.permissions();
            Some((digest(&mut f).map_err(io_error)?, perm))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(open_error(path, e)),
    };
    let etag = current.as_ref().map(|(t, _)| t.as_str());
    if let Some(want) = if_match
        && etag != Some(want)
    {
        return Err(
            conflict(format!("{} changed since it was read", path.display()))
                .with("etag", etag.map(Value::from).unwrap_or(Value::Null)),
        );
    }
    // Written aside and renamed over, so a reader never sees half a file.
    let tmp = std::ffi::OsString::from(format!(
        ".{}.nerve-{}",
        name.to_string_lossy(),
        nerve_transport::keys::random_token(6)
    ));
    let result = (|| {
        let mut f = dir.create_new(&tmp)?;
        f.write_all(content)?;
        f.sync_all()?;
        if let Some((_, perm)) = current {
            f.set_permissions(perm)?;
        }
        dir.rename(&tmp, name)
    })();
    if let Err(e) = result {
        let _ = dir.remove(&tmp);
        return Err(open_error(path, e));
    }
    let h = ring::digest::digest(&ring::digest::SHA256, content);
    Ok(json!({"etag": nerve_proto::msg::hex(h.as_ref()), "size": content.len()}))
}

/// The resolved folder `path`, opened a part at a time from `/` without
/// following a link, as [`Dir`] opens one: a link swapped in after the
/// policy judged the path fails the call instead of leading elsewhere
/// (crate::exec::AsRoot).
#[cfg(target_os = "linux")]
pub fn open_folder(path: &Path) -> std::io::Result<std::os::fd::OwnedFd> {
    Dir::open(path).map(|d| d.fd)
}

/// The folder a `read` or `write` works in. On Unix it is opened one
/// component at a time from `/` without following a symlink, and every later
/// step works relative to that handle, never through a symlink either: the
/// policy judged the resolved path, so a symlink swapped in after that check
/// fails the call instead of moving it out of the folder.
struct Dir {
    #[cfg(unix)]
    fd: std::os::fd::OwnedFd,
    #[cfg(not(unix))]
    path: PathBuf,
}

#[cfg(unix)]
impl Dir {
    /// Directories are only searched: `O_PATH` (Linux) needs no read right,
    /// as walking a path does not.
    #[cfg(target_os = "linux")]
    const SEARCH: libc::c_int = libc::O_PATH;
    #[cfg(not(target_os = "linux"))]
    const SEARCH: libc::c_int = libc::O_RDONLY;

    fn at(
        dir: Option<&std::os::fd::OwnedFd>,
        name: &std::ffi::OsStr,
        flags: libc::c_int,
    ) -> std::io::Result<std::os::fd::OwnedFd> {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(name.as_bytes())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        let base = dir.map_or(libc::AT_FDCWD, |d| d.as_raw_fd());
        // SAFETY: `name` is a valid C string and `base` an open folder (or
        // AT_FDCWD); the new descriptor is owned below.
        let fd = unsafe {
            libc::openat(
                base,
                name.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o666 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: openat returned a fresh descriptor nothing else owns.
        Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
    }

    fn open(path: &Path) -> std::io::Result<Dir> {
        use std::path::Component;
        let mut fd = Dir::at(None, "/".as_ref(), libc::O_DIRECTORY | Dir::SEARCH)?;
        for c in path.components() {
            match c {
                Component::RootDir => {}
                Component::Normal(n) => {
                    fd = Dir::at(Some(&fd), n, libc::O_DIRECTORY | Dir::SEARCH)?;
                }
                // The policy judged a resolved path; this is not one.
                _ => return Err(std::io::Error::from_raw_os_error(libc::ENOTDIR)),
            }
        }
        Ok(Dir { fd })
    }

    /// `name` for reading, if it is a file (`None` if it is something
    /// else). It is first opened without reading it (`O_PATH`) and asked
    /// what it is, and only a file is opened, through that same entry
    /// ([`reopen`]): opening a device or a FIFO does things of its own
    /// ([`Unreadable::NotFile`]).
    #[cfg(target_os = "linux")]
    fn open_file(&self, name: &std::ffi::OsStr) -> std::io::Result<Option<std::fs::File>> {
        let held = std::fs::File::from(Dir::at(Some(&self.fd), name, libc::O_PATH)?);
        let m = held.metadata()?;
        // With O_PATH, O_NOFOLLOW opens a symlink itself instead of failing;
        // it fails as an open for reading would.
        if m.is_symlink() {
            return Err(std::io::Error::from_raw_os_error(libc::ELOOP));
        }
        if !m.is_file() {
            return Ok(None);
        }
        reopen(&held).map(Some)
    }

    /// `name` for reading, if it is a file. Non-blocking, so a FIFO put
    /// there cannot hold the call; a regular file reads the same either way.
    #[cfg(not(target_os = "linux"))]
    fn open_file(&self, name: &std::ffi::OsStr) -> std::io::Result<Option<std::fs::File>> {
        let f: std::fs::File =
            Dir::at(Some(&self.fd), name, libc::O_RDONLY | libc::O_NONBLOCK)?.into();
        let file = f.metadata()?.is_file();
        Ok(file.then_some(f))
    }

    fn create_new(&self, name: &std::ffi::OsStr) -> std::io::Result<std::fs::File> {
        let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL;
        Dir::at(Some(&self.fd), name, flags).map(Into::into)
    }

    fn rename(&self, from: &std::ffi::OsStr, to: &std::ffi::OsStr) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        use std::os::unix::ffi::OsStrExt;
        let c = |s: &std::ffi::OsStr| {
            std::ffi::CString::new(s.as_bytes())
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))
        };
        let (from, to) = (c(from)?, c(to)?);
        let fd = self.fd.as_raw_fd();
        // SAFETY: both names are valid C strings in the folder `fd` holds.
        // rename replaces a symlink at `to` and never follows it.
        if unsafe { libc::renameat(fd, from.as_ptr(), fd, to.as_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn remove(&self, name: &std::ffi::OsStr) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(name.as_bytes())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        // SAFETY: `name` is a valid C string in the folder the handle holds.
        if unsafe { libc::unlinkat(self.fd.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

/// On Windows the steps go by path, as resolved.
#[cfg(not(unix))]
impl Dir {
    fn open(path: &Path) -> std::io::Result<Dir> {
        Ok(Dir {
            path: path.to_path_buf(),
        })
    }

    fn open_file(&self, name: &std::ffi::OsStr) -> std::io::Result<Option<std::fs::File>> {
        let f = std::fs::File::open(self.path.join(name))?;
        let file = f.metadata()?.is_file();
        Ok(file.then_some(f))
    }

    fn create_new(&self, name: &std::ffi::OsStr) -> std::io::Result<std::fs::File> {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.path.join(name))
    }

    fn rename(&self, from: &std::ffi::OsStr, to: &std::ffi::OsStr) -> std::io::Result<()> {
        std::fs::rename(self.path.join(from), self.path.join(to))
    }

    fn remove(&self, name: &std::ffi::OsStr) -> std::io::Result<()> {
        std::fs::remove_file(self.path.join(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        /// How many folders [`looked_into`] asked for on this thread.
        pub(super) static LOOKED_UP: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
        /// Whether [`entry_type`] fails on this thread.
        pub(super) static UNTYPED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// A walk nobody stops.
    #[cfg(unix)]
    static GOES_ON: AtomicBool = AtomicBool::new(false);

    fn args(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn run(action: &str, v: Value) -> Result<Value, RpcError> {
        FsCall::parse(action, &args(v))?.run(&|_, _| false)
    }

    /// A local path the way the center sends it (`/c/...` on Windows).
    fn wire(p: &Path) -> String {
        nerve_policy::paths::to_wire(p)
    }

    /// `readable` opens what this thread's account may read, a file or a
    /// folder; a path that does not exist passes, one the account may not
    /// open does not, and a pipe is not even opened.
    #[cfg(unix)]
    #[test]
    fn readable_says_what_the_account_may_open() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("a.txt");
        std::fs::write(&file, "x").unwrap();
        assert_eq!(readable(&file), Ok(()));
        assert_eq!(readable(d.path()), Ok(()));
        assert_eq!(readable(&d.path().join("missing/b")), Ok(()));
        let fifo = d.path().join("pipe");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        assert_eq!(readable(&fifo), Err(Unreadable::NotFile));
        // Root opens anything, so the closed file says nothing there.
        if unsafe { libc::geteuid() } != 0 {
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o200)).unwrap();
            assert_eq!(readable(&file), Err(Unreadable::Closed));
        }
    }

    /// A FIFO open to all at `path`, and a writer that waits in its `open`
    /// for a reader; this returns once it waits there, and the receiver
    /// hears once that open returned. A reader that comes and goes before
    /// the writer waits lets nothing go, so it has to wait first.
    #[cfg(target_os = "linux")]
    fn a_writer_waits_on(
        path: &Path,
    ) -> (std::thread::JoinHandle<()>, std::sync::mpsc::Receiver<()>) {
        use std::os::unix::fs::PermissionsExt;
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o666) }, 0);
        // mkfifo takes the umask off (027 leaves others nothing).
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let (tx, rx) = std::sync::mpsc::channel();
        let at = path.to_path_buf();
        let writer = std::thread::spawn(move || {
            tid_tx.send(unsafe { libc::gettid() }).unwrap();
            let _f = std::fs::OpenOptions::new().write(true).open(at).unwrap();
            tx.send(()).unwrap();
        });
        // Once the thread sleeps after it said its id, it sleeps in `open`:
        // it does nothing else there that waits.
        let stat = format!("/proc/self/task/{}/stat", tid_rx.recv().unwrap());
        let sleeps = || {
            let s = std::fs::read_to_string(&stat).unwrap();
            s.rsplit_once(") ")
                .is_some_and(|(_, rest)| rest.starts_with('S'))
        };
        let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !sleeps() {
            assert!(std::time::Instant::now() < until, "the writer never waited");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        (writer, rx)
    }

    /// Lets the writer of [`a_writer_waits_on`] go, and says whether it was
    /// still waiting.
    #[cfg(target_os = "linux")]
    fn still_waiting(
        path: &Path,
        (writer, rx): (std::thread::JoinHandle<()>, std::sync::mpsc::Receiver<()>),
    ) -> bool {
        use std::os::unix::fs::OpenOptionsExt;
        let waiting = rx
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err();
        let _r = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
            .unwrap();
        writer.join().unwrap();
        waiting
    }

    /// Neither the folder-mode check of a read outside the folders nor
    /// `read` and `write` open what is not a file: a writer waiting on a
    /// FIFO stays waiting (as a serial port's lines stay as they are).
    #[cfg(target_os = "linux")]
    #[test]
    fn what_is_not_a_file_is_never_opened() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let fifo = d.path().join("pipe");
        let writer = a_writer_waits_on(&fifo);
        let why = may_read_outside(&fifo, false).unwrap_err();
        assert!(
            why.contains("neither a file nor a folder")
                && !why.contains(&*d.path().to_string_lossy()),
            "{why}"
        );
        assert!(still_waiting(&fifo, writer), "the check opened the pipe");
        std::fs::remove_file(&fifo).unwrap();
        let writer = a_writer_waits_on(&fifo);
        let e = run("read", json!({"path": wire(&fifo)})).unwrap_err();
        assert!(e.message.contains("is not a file"), "{e:?}");
        let e = run("write", json!({"path": wire(&fifo), "content": "x"})).unwrap_err();
        assert!(e.message.contains("is not a file"), "{e:?}");
        assert!(
            still_waiting(&fifo, writer),
            "the read or the write opened the pipe"
        );
    }

    /// A file another process holds a write lease on: asking whether it may
    /// be read, and reading it, answer at once instead of waiting until the
    /// holder lets go (up to `lease-break-time`, 45 s by default). In the
    /// gate that wait would hold a worker of the node's runtime.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_leased_file_is_not_waited_on() {
        use std::io::Read;
        use std::os::fd::FromRawFd;
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let file = d.path().join("leased");
        std::fs::write(&file, "x").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let c = std::ffi::CString::new(file.as_os_str().as_encoded_bytes()).unwrap();
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: the child calls only async-signal-safe functions and
        // leaves with _exit; it ignores the signal a lease break sends, so
        // it holds the lease until the kernel takes it or the test ends it.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                libc::signal(libc::SIGIO, libc::SIG_IGN);
                let fd = libc::open(c.as_ptr(), libc::O_RDWR);
                let ok = fd >= 0 && libc::fcntl(fd, libc::F_SETLEASE, libc::F_WRLCK) == 0;
                libc::write(fds[1], [u8::from(ok)].as_ptr().cast(), 1);
                loop {
                    libc::pause();
                }
            }
        }
        unsafe { libc::close(fds[1]) };
        let mut ready = std::fs::File::from(unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[0]) });
        let mut held = [0u8];
        ready.read_exact(&mut held).unwrap();
        let end = || unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        };
        if held[0] != 1 {
            end();
            eprintln!("no write lease can be taken here (fs.leases-enable, or the file system)");
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let at = file.clone();
        let asks = std::thread::spawn(move || {
            tx.send((readable(&at), run("read", json!({"path": wire(&at)}))))
                .unwrap();
        });
        let answer = rx.recv_timeout(std::time::Duration::from_secs(5));
        // Ending the holder lets a waiting open go, so the thread ends too.
        end();
        asks.join().unwrap();
        let (check, read) = answer.expect("the leased file was waited on");
        assert_eq!(check, Err(Unreadable::Closed));
        assert!(read.is_err(), "{read:?}");
    }

    /// A path is open to every account only where each folder above it
    /// lets others pass and it lets them read: a file others may read in a
    /// folder they may not enter (an owner's home that is 750) is not.
    #[cfg(unix)]
    #[test]
    fn open_to_all_goes_by_the_others_bits_on_the_whole_way() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path, m: u32| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap()
        };
        let d = tempfile::tempdir().unwrap();
        mode(d.path(), 0o755);
        let home = d.path().join("home");
        let docs = home.join("docs");
        std::fs::create_dir_all(&docs).unwrap();
        let file = docs.join("a.txt");
        std::fs::write(&file, "x").unwrap();
        mode(&home, 0o755);
        mode(&docs, 0o755);
        mode(&file, 0o644);
        assert!(open_to_all(&file));
        assert!(open_to_all(&docs));
        assert!(open_to_all(&docs.join("missing")));
        mode(&file, 0o640);
        assert!(!open_to_all(&file));
        mode(&file, 0o644);
        // A folder on the way others may not pass closes all below it.
        mode(&home, 0o750);
        assert!(!open_to_all(&file));
        assert!(!open_to_all(&docs));
        assert!(!open_to_all(&docs.join("missing")));
        // Listing it is reading it: `o+x` alone does not open a folder.
        mode(&home, 0o711);
        assert!(open_to_all(&file));
        assert!(!open_to_all(&home));
        mode(&home, 0o755);
    }

    /// A read in no folder, where the node reads as the command account,
    /// goes only where the path is open to every account and that account
    /// may open it, never into the node's own process, and a provider is
    /// never handed a folder there.
    #[cfg(unix)]
    #[test]
    fn a_read_outside_the_folders_goes_where_all_may_read() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path, m: u32| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap()
        };
        let d = tempfile::tempdir().unwrap();
        mode(d.path(), 0o755);
        let file = d.path().join("a.txt");
        std::fs::write(&file, "x").unwrap();
        mode(&file, 0o644);
        assert_eq!(may_read_outside(&file, false), Ok(()));
        assert_eq!(may_read_outside(&file, true), Ok(()));
        assert_eq!(may_read_outside(&d.path().join("missing"), true), Ok(()));
        assert_eq!(may_read_outside(d.path(), false), Ok(()));
        // The refusals name no path: one resolved as the command account
        // may be where another of its processes works.
        let named = |why: &str| why.contains(&*d.path().to_string_lossy());
        let why = may_read_outside(d.path(), true).unwrap_err();
        assert!(
            why.contains("a provider would read below it") && !named(&why),
            "{why}"
        );
        mode(&file, 0o600);
        let why = may_read_outside(&file, false).unwrap_err();
        assert!(
            why.contains("not open to every account") && !named(&why),
            "{why}"
        );
        // Others may read it, its owner may not; root opens anything.
        if unsafe { libc::geteuid() } != 0 {
            mode(&file, 0o004);
            let why = may_read_outside(&file, false).unwrap_err();
            assert!(why.contains("may not read") && !named(&why), "{why}");
        }
        mode(&file, 0o644);
        #[cfg(target_os = "linux")]
        {
            // The node's own process: its map is open to all by its mode,
            // and any of its threads' entries leads there too.
            let own = PathBuf::from(format!("/proc/{}/maps", std::process::id()));
            assert!(open_to_all(&own));
            let thread = std::thread::spawn(move || {
                let (tx, rx) = std::sync::mpsc::channel();
                let t = std::thread::spawn(move || {
                    tx.send(unsafe { libc::gettid() }).unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(500));
                });
                let tid = rx.recv().unwrap();
                let r = may_read_outside(&PathBuf::from(format!("/proc/{tid}/stat")), false);
                t.join().unwrap();
                r
            })
            .join()
            .unwrap();
            for r in [
                may_read_outside(&own, false),
                may_read_outside(Path::new("/proc/self/maps"), false),
                may_read_outside(Path::new("/proc/thread-self/stat"), false),
                thread,
                // No process or thread has this id (it lies above every
                // `pid_max`); the node's next thread could take an unused one.
                may_read_outside(Path::new("/proc/4294967295/maps"), false),
            ] {
                let why = r.unwrap_err();
                assert!(why.contains("the node's own process"), "{why}");
            }
        }
    }

    /// A folder holds other paths, a file does not, and a missing path only
    /// where a write may make a folder there.
    #[test]
    fn a_folder_holds_paths_a_file_does_not() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("a.txt");
        std::fs::write(&file, "x").unwrap();
        let missing = d.path().join("missing");
        for write in [false, true] {
            assert!(holds(d.path(), write));
            assert!(!holds(&file, write));
            assert_eq!(holds(&missing, write), write);
        }
    }

    /// A folder the walk may not list is left out where the program runs as
    /// the walking account, which could not list it either, and refuses the
    /// call where it runs as another, which could follow a link in it. The
    /// refusal names neither the folder nor the link.
    #[cfg(unix)]
    #[test]
    fn a_folder_the_walk_may_not_list_refuses_a_program_of_another_account() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        if nerve_transport::net::euid() == 0 {
            eprintln!("skipped: root lists every folder");
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let proj = d.path().canonicalize().unwrap().join("proj");
        let shut = proj.join("shut");
        std::fs::create_dir_all(&shut).unwrap();
        symlink("/etc/hostname", shut.join("to-elsewhere")).unwrap();
        std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o000)).unwrap();
        let handed = [Target {
            path: proj.clone(),
            access: PathAccess::Read,
            holds: true,
        }];
        let mut pass = |_: &Link| None;
        let skipped = links_below(&handed, LINKS_LIMIT, Closed::Skip, &GOES_ON, &mut pass);
        let refused = links_below(&handed, LINKS_LIMIT, Closed::Refuse, &GOES_ON, &mut pass);
        std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(skipped, Ok(()));
        let e = refused.unwrap_err();
        assert_eq!(
            e,
            format!(
                "{} holds a folder the node may not look into, so it cannot tell where the \
                 links there lead",
                to_wire(&proj)
            )
        );
    }

    /// An entry whose type the walk cannot tell (a filesystem that names
    /// no types, in a folder the walk may list but not enter) may be a link
    /// or a folder: it is left out for the walking account's program and
    /// refuses another account's, as a folder the walk may not list does.
    #[cfg(unix)]
    #[test]
    fn an_entry_the_walk_cannot_type_refuses_a_program_of_another_account() {
        let d = tempfile::tempdir().unwrap();
        let proj = d.path().canonicalize().unwrap().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", proj.join("to-elsewhere")).unwrap();
        let handed = [Target {
            path: proj.clone(),
            access: PathAccess::Read,
            holds: true,
        }];
        let judged = std::cell::Cell::new(0);
        let mut count = |_: &Link| {
            judged.set(judged.get() + 1);
            None
        };
        UNTYPED.with(|u| u.set(true));
        let skipped = links_below(&handed, LINKS_LIMIT, Closed::Skip, &GOES_ON, &mut count);
        let refused = links_below(&handed, LINKS_LIMIT, Closed::Refuse, &GOES_ON, &mut count);
        UNTYPED.with(|u| u.set(false));
        assert_eq!(skipped, Ok(()));
        assert_eq!(
            refused.unwrap_err(),
            format!(
                "{} holds a folder the node may not look into, so it cannot tell where the \
                 links there lead",
                to_wire(&proj)
            )
        );
        assert_eq!(judged.get(), 0);
        let typed = links_below(&handed, LINKS_LIMIT, Closed::Refuse, &GOES_ON, &mut count);
        assert_eq!(typed, Ok(()));
        assert_eq!(judged.get(), 1, "with its type the link is judged");
    }

    /// The links below a folder handed to a program, and where they lead:
    /// a link to a folder is looked into, each folder once; a link that
    /// leads nowhere counts only for a write, at the place it names. Too
    /// many entries, and nothing can be told.
    #[cfg(unix)]
    #[test]
    fn the_links_below_a_handed_folder_are_found() {
        use std::os::unix::fs::symlink;
        let d = tempfile::tempdir().unwrap();
        let root = d.path().canonicalize().unwrap();
        let (proj, out) = (root.join("proj"), root.join("out"));
        for p in [proj.join("sub/deep"), out.join("inner")] {
            std::fs::create_dir_all(p).unwrap();
        }
        std::fs::write(out.join("secret"), "s").unwrap();
        symlink(out.join("secret"), proj.join("sub/deep/env")).unwrap();
        symlink(&out, proj.join("out")).unwrap();
        symlink(out.join("inner/../secret"), out.join("inner/again")).unwrap();
        // Back into the folder: nothing new to look into.
        symlink(&proj, proj.join("sub/up")).unwrap();
        symlink(root.join("gone/new"), proj.join("dangling")).unwrap();
        let target = |access| Target {
            path: proj.clone(),
            access,
            holds: true,
        };
        let found = |access| {
            let mut v: Vec<(PathBuf, PathBuf, bool)> = Vec::new();
            links_below(
                &[target(access)],
                LINKS_LIMIT,
                Closed::Skip,
                &GOES_ON,
                &mut |l| {
                    assert_eq!((l.handed, l.to.access), (0, access));
                    let root = if l.at.starts_with(&proj) { &proj } else { &out };
                    assert_eq!(&l.found_in, root);
                    v.push((l.at.clone(), l.to.path.clone(), l.to.holds));
                    None
                },
            )
            .unwrap();
            v.sort();
            v
        };
        let mut read = vec![
            (proj.join("out"), out.clone(), true),
            (proj.join("sub/deep/env"), out.join("secret"), false),
            (proj.join("sub/up"), proj.clone(), true),
            (out.join("inner/again"), out.join("secret"), false),
        ];
        read.sort();
        assert_eq!(found(PathAccess::Read), read);
        let mut write = read.clone();
        write.push((proj.join("dangling"), root.join("gone/new"), true));
        write.sort();
        assert_eq!(found(PathAccess::Write), write);
        // A file holds nothing to look into.
        let file = Target {
            path: out.join("secret"),
            access: PathAccess::Read,
            holds: false,
        };
        let mut none = |_: &Link| -> Option<String> { panic!("a file was walked") };
        assert_eq!(
            links_below(&[file], LINKS_LIMIT, Closed::Skip, &GOES_ON, &mut none),
            Ok(())
        );
        let mut pass = |_: &Link| None;
        // Cut short: refused, never judged by the part looked at.
        let e = links_below(
            &[target(PathAccess::Read)],
            3,
            Closed::Skip,
            &GOES_ON,
            &mut pass,
        )
        .unwrap_err();
        assert!(e.contains("hold more than 3 entries in all"), "{e}");
        // The limit holds for the call: two paths share it, and the refusal
        // names neither as the one too big.
        let (a, b) = (root.join("a"), root.join("b"));
        for (dir, n) in [(&a, 0), (&a, 1), (&a, 2), (&b, 0), (&b, 1), (&b, 2)] {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(dir.join(format!("f{n}")), "f").unwrap();
        }
        let both = [&a, &b].map(|p| Target {
            path: p.clone(),
            access: PathAccess::Read,
            holds: true,
        });
        assert_eq!(
            links_below(&both[..1], 5, Closed::Skip, &GOES_ON, &mut pass),
            Ok(())
        );
        let e = links_below(&both, 5, Closed::Skip, &GOES_ON, &mut pass).unwrap_err();
        assert!(
            e.starts_with("the paths this call hands over hold more than 5 entries in all"),
            "{e}"
        );
        // Nobody waits any more: the walk ends at the next entry.
        let e = links_below(
            &[target(PathAccess::Read)],
            LINKS_LIMIT,
            Closed::Skip,
            &AtomicBool::new(true),
            &mut |_| panic!("a link was judged after the call ended"),
        )
        .unwrap_err();
        assert!(
            e.starts_with("the call ended before the node had checked"),
            "{e}"
        );
        // A link it cannot follow: a loop.
        symlink(proj.join("loop"), proj.join("loop")).unwrap();
        let e = links_below(
            &[target(PathAccess::Read)],
            LINKS_LIMIT,
            Closed::Skip,
            &GOES_ON,
            &mut pass,
        )
        .unwrap_err();
        assert!(e.contains("holds a link") && e.contains("loop"), "{e}");
    }

    /// A link is judged when it is found: one that is refused stops the
    /// walk with its own reason, and the folder it leads to is not looked
    /// into, so neither its size nor a link there the node cannot follow
    /// gives the refusal, which would name a place the call may not reach.
    /// A folder a link that passed leads to counts towards the limit.
    #[cfg(unix)]
    #[test]
    fn a_refused_link_is_not_followed() {
        use std::os::unix::fs::symlink;
        let d = tempfile::tempdir().unwrap();
        let root = d.path().canonicalize().unwrap();
        let (proj, far) = (root.join("proj"), root.join("far"));
        for p in [&proj, &far] {
            std::fs::create_dir(p).unwrap();
        }
        std::fs::write(proj.join("a.txt"), "a").unwrap();
        symlink(&far, proj.join("far")).unwrap();
        for n in 0..10 {
            std::fs::write(far.join(format!("f{n}")), "f").unwrap();
        }
        symlink(far.join("loop"), far.join("loop")).unwrap();
        let proj = [Target {
            path: proj.clone(),
            access: PathAccess::Read,
            holds: true,
        }];
        let mut judged = Vec::new();
        let mut refuse_far = |l: &Link| {
            judged.push(l.at.clone());
            (l.to.path == far).then(|| "refused".to_string())
        };
        assert_eq!(
            links_below(&proj, 5, Closed::Skip, &GOES_ON, &mut refuse_far),
            Err("refused".into())
        );
        assert_eq!(judged, [root.join("proj/far")]);
        // Without the loop for the limit: which of the two a walk meets first
        // follows the order a file system lists a folder in (ext4 and btrfs
        // differ).
        std::fs::remove_file(far.join("loop")).unwrap();
        let mut pass = |_: &Link| None;
        let e = links_below(&proj, 5, Closed::Skip, &GOES_ON, &mut pass).unwrap_err();
        assert!(
            e.contains(
                "hold more than 5 entries in all, counting those of the folders their links lead to"
            ),
            "{e}"
        );
        symlink(far.join("loop"), far.join("loop")).unwrap();
        let e = links_below(&proj, LINKS_LIMIT, Closed::Skip, &GOES_ON, &mut pass).unwrap_err();
        assert!(e.contains("far/loop) the node cannot follow"), "{e}");
    }

    /// Many links to many folders: each folder a link leads to is looked
    /// up by its own path and those above it, not against every folder
    /// looked into before it, so the walk grows with the links, not with
    /// their square.
    #[cfg(unix)]
    #[test]
    fn many_links_to_many_folders_cost_no_more_than_their_number() {
        use std::os::unix::fs::symlink;
        let d = tempfile::tempdir().unwrap();
        let root = d.path().canonicalize().unwrap();
        let (proj, far) = (root.join("proj"), root.join("far"));
        std::fs::create_dir(&proj).unwrap();
        const N: usize = 2000;
        for n in 0..N {
            let to = far.join(format!("d{n}"));
            std::fs::create_dir_all(&to).unwrap();
            symlink(&to, proj.join(format!("l{n}"))).unwrap();
        }
        let proj = [Target {
            path: proj,
            access: PathAccess::Read,
            holds: true,
        }];
        let before = LOOKED_UP.with(|c| c.get());
        let mut judged = 0;
        let r = links_below(&proj, LINKS_LIMIT, Closed::Skip, &GOES_ON, &mut |_| {
            judged += 1;
            None
        });
        assert_eq!((r, judged), (Ok(()), N));
        let looked = LOOKED_UP.with(|c| c.get()) - before;
        let depth = far.components().count() + 2;
        assert!(
            looked <= (N + 1) * depth,
            "{looked} folders asked for {N} links"
        );
    }

    #[test]
    fn read_write_conflict() {
        let d = tempfile::tempdir().unwrap();
        let f = wire(&d.path().join("a.txt"));
        let p = f.as_str();
        let w = run("write", json!({"path": p, "content": "hello\nworld\n"})).unwrap();
        let r = run("read", json!({"path": p})).unwrap();
        assert_eq!(r["content"], "hello\nworld\n");
        assert_eq!(r["encoding"], "utf8");
        assert_eq!(r["etag"], w["etag"]);
        let part = run("read", json!({"path": p, "offset": 6, "length": 5})).unwrap();
        assert_eq!(part["content"], "world");
        assert_eq!(part["size"], 12);

        let stale = run(
            "write",
            json!({"path": p, "content": "x", "if_match": "0".repeat(64)}),
        )
        .unwrap_err();
        assert_eq!(stale.kind().as_str(), "conflict");
        run(
            "write",
            json!({"path": p, "content": "AP8=", "encoding": "base64", "if_match": w["etag"]}),
        )
        .unwrap();
        let bin = run("read", json!({"path": p})).unwrap();
        assert_eq!(bin["encoding"], "base64");
        assert_eq!(bin["content"], "AP8=");
    }

    #[test]
    fn grep_find_list_stat_and_skip() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("sub/secret")).unwrap();
        std::fs::write(d.path().join("sub/one.rs"), "fn main() {}\nneedle here\n").unwrap();
        std::fs::write(d.path().join("sub/secret/two.rs"), "needle\n").unwrap();
        std::fs::write(d.path().join("three.txt"), "needle too\n").unwrap();
        let root = wire(d.path());
        let root = root.as_str();
        let secret = d.path().join("sub/secret");
        let skip = |p: &Path, _| p.starts_with(&secret);
        let g = FsCall::parse("grep", &args(json!({"path": root, "pattern": "needle"})))
            .unwrap()
            .run(&skip)
            .unwrap();
        assert_eq!(g["matches"].as_array().unwrap().len(), 2, "{g}");
        let g = run(
            "grep",
            json!({"path": root, "pattern": "needle", "glob": "*.rs", "max": 1}),
        )
        .unwrap();
        assert_eq!(g["matches"].as_array().unwrap().len(), 1);
        assert_eq!(g["truncated"], true);
        let f = run("find", json!({"path": root, "glob": "**/*.rs"})).unwrap();
        assert_eq!(f["paths"].as_array().unwrap().len(), 2);
        let l = run("list", json!({"path": root})).unwrap();
        assert_eq!(l["entries"][0]["name"], "sub");
        assert_eq!(l["entries"][0]["type"], "dir");
        let s = run("stat", json!({"path": format!("{root}/three.txt")})).unwrap();
        assert_eq!(s["type"], "file");
        assert_eq!(s["size"], 11);
    }

    /// The policy judged the path as it was at parse time; a folder swapped
    /// for a symlink before the call runs must not move the call out.
    #[cfg(unix)]
    #[test]
    fn a_symlink_swapped_in_after_the_check_fails_the_call() {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (work, outside) = (root.join("work"), root.join("outside"));
        std::fs::create_dir_all(work.join("d")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(work.join("d/note"), "inside").unwrap();
        std::fs::write(outside.join("note"), "outside secret").unwrap();
        let swap = |p: &Path| {
            std::fs::rename(p, work.join("d.old")).unwrap();
            std::os::unix::fs::symlink(&outside, p).unwrap();
        };
        let path = wire(&work.join("d/authorized_keys"));
        let write = FsCall::parse(
            "write",
            &args(json!({"path": path, "content": "ssh-ed25519 AAAA attacker"})),
        )
        .unwrap();
        let read =
            FsCall::parse("read", &args(json!({"path": wire(&work.join("d/note"))}))).unwrap();
        assert_eq!(read.targets()[0].path, work.join("d/note"));
        swap(&work.join("d"));
        assert!(
            write.run(&|_, _| false).is_err(),
            "the write followed the link"
        );
        assert!(!outside.join("authorized_keys").exists());
        let r = read.run(&|_, _| false);
        assert!(r.is_err(), "the read followed the link: {r:?}");

        // A last component swapped for a symlink fails the same way.
        std::fs::remove_file(work.join("d")).unwrap();
        std::fs::rename(work.join("d.old"), work.join("d")).unwrap();
        let note = work.join("d/note");
        let read = FsCall::parse("read", &args(json!({"path": wire(&note)}))).unwrap();
        let write =
            FsCall::parse("write", &args(json!({"path": wire(&note), "content": "x"}))).unwrap();
        std::fs::remove_file(&note).unwrap();
        std::os::unix::fs::symlink(outside.join("note"), &note).unwrap();
        let r = read.run(&|_, _| false);
        assert!(r.is_err(), "the read followed the link: {r:?}");
        assert!(
            write.run(&|_, _| false).is_err(),
            "the write followed the link"
        );
        assert_eq!(
            std::fs::read_to_string(outside.join("note")).unwrap(),
            "outside secret"
        );
    }

    #[test]
    fn refuses_bad_paths_and_args() {
        let e = run("read", json!({"path": "relative"})).unwrap_err();
        assert_eq!(e.kind().as_str(), "bad_path");
        let e = run("read", json!({"path": "/x", "bogus": 1})).unwrap_err();
        assert_eq!(e.kind(), ErrorCode::InvalidArgs);
        let e = run("chmod", json!({})).unwrap_err();
        assert_eq!(e.kind(), ErrorCode::UnknownMember);
    }
}
