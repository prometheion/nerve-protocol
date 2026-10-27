//! The `fs` capability (spec §7.2). Calls are parsed first ([`FsCall::parse`])
//! so the policy can judge their paths, then run on a blocking thread.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use globset::{Glob, GlobMatcher};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use nerve_policy::paths::{parse_device_path, resolve, to_wire};
use nerve_policy::{PathAccess, Target};
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
    let mut f = dir.open_file(name).map_err(|e| open_error(path, e))?;
    let m = f.metadata().map_err(io_error)?;
    if !m.is_file() {
        return Err(io_error(format!("{} is not a file", path.display())));
    }
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
        Ok(mut f) => {
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

    /// `name` for reading. Non-blocking, so a FIFO put there cannot hold the
    /// call; a regular file reads the same either way.
    fn open_file(&self, name: &std::ffi::OsStr) -> std::io::Result<std::fs::File> {
        Dir::at(Some(&self.fd), name, libc::O_RDONLY | libc::O_NONBLOCK).map(Into::into)
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

    fn open_file(&self, name: &std::ffi::OsStr) -> std::io::Result<std::fs::File> {
        std::fs::File::open(self.path.join(name))
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
