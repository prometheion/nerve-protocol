//! The backup file of root's `backup` or `restore` on the installed node.
//! The command runs as the node's user ([`crate::service::become_owner`]),
//! who may not open the folders of whoever asked: a home folder is closed
//! to others, and a backup written there as the node's user would be that
//! user's, not the asker's. So the file is opened as the one who asked: the
//! user who ran `sudo`, or for whom pkexec started the desktop app's broker;
//! root itself where nobody else asked. A process forked before the switch,
//! while the command has one thread, does that for the command: it reads
//! the backup at once, or waits for the backup the command makes and writes
//! it.
//!
//! Where the user who ran `sudo` may not open the file, it is opened as the
//! owner of its folder: `sudo` gave that user root, and a root shell
//! (`sudo -i`) keeps `SUDO_UID`, so root's own folders stay root's to
//! write, and the node's state folder the node's user's, as before. The
//! desktop app's broker (pkexec) gets no such second try: it runs node
//! commands, not whatever its user may not do. An asker whose account
//! cannot be found is refused, never taken for root.

use std::path::{Path, PathBuf};

/// What the command does with its file.
// Opened elsewhere only on Linux, where root's command becomes the node's
// user.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub enum Job {
    Read(PathBuf),
    Write { path: PathBuf, overwrite: bool },
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::io::{Read, Write};
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use super::Job;

    /// What the process forked for the file did or will do.
    enum Kept {
        Read {
            path: PathBuf,
            bytes: Result<Vec<u8>, String>,
        },
        Write {
            path: PathBuf,
            overwrite: bool,
            to: std::fs::File,
            from: std::fs::File,
            pid: libc::pid_t,
        },
    }

    static KEPT: Mutex<Option<Kept>> = Mutex::new(None);

    /// The user who asked root for the command.
    #[derive(Clone, Copy)]
    struct Caller {
        uid: u32,
        gid: u32,
        /// Through `sudo`, which gave that user root; else through pkexec,
        /// for the desktop app's broker.
        sudo: bool,
    }

    /// The user who asked root for the command: `sudo`'s, else pkexec's,
    /// with that user's group. `None` for root itself; an error for an
    /// asker whose account cannot be found.
    fn caller() -> Result<Option<Caller>, String> {
        let (var, sudo) = if std::env::var_os("SUDO_UID").is_some() {
            ("SUDO_UID", true)
        } else if std::env::var_os("PKEXEC_UID").is_some() {
            ("PKEXEC_UID", false)
        } else {
            return Ok(None);
        };
        let id = |k: &str| {
            std::env::var(k)
                .ok()
                .and_then(|v| v.trim().parse::<u32>().ok())
        };
        let uid = id(var).ok_or_else(|| format!("{var} is not a user id"))?;
        if uid == 0 {
            return Ok(None);
        }
        let (group, _) = account(uid).ok_or_else(|| {
            format!(
                "cannot open the file as the user who asked ({var} {uid}): no account has that id here"
            )
        })?;
        let gid = match sudo.then(|| std::env::var_os("SUDO_GID")).flatten() {
            Some(_) => id("SUDO_GID").ok_or("SUDO_GID is not a group id")?,
            None => group,
        };
        Ok(Some(Caller { uid, gid, sudo }))
    }

    /// The group of `uid` in the account database, and its name.
    fn account(uid: u32) -> Option<(u32, std::ffi::CString)> {
        let mut buf = vec![0u8; 16 * 1024];
        // SAFETY: getpwuid_r writes into `pw` and `buf`, both ours and as
        // large as said; `found` points at `pw` or is null.
        unsafe {
            let mut pw: libc::passwd = std::mem::zeroed();
            let mut found: *mut libc::passwd = std::ptr::null_mut();
            if libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr().cast(), buf.len(), &mut found) != 0
                || found.is_null()
            {
                return None;
            }
            Some((pw.pw_gid, std::ffi::CStr::from_ptr(pw.pw_name).to_owned()))
        }
    }

    /// Becomes `uid` with `gid` and the user's other groups (none for a uid
    /// the account database does not know), for good: real, effective and
    /// saved ids.
    fn become_user(uid: u32, gid: u32) -> Result<(), String> {
        let name = account(uid).map(|(_, n)| n);
        // SAFETY: plain calls; `name` lives across initgroups.
        let failed = unsafe {
            (match &name {
                Some(n) => libc::initgroups(n.as_ptr(), gid),
                None => libc::setgroups(0, std::ptr::null()),
            }) != 0
                || libc::setresgid(gid, gid, gid) != 0
                || libc::setresuid(uid, uid, uid) != 0
        };
        if failed {
            return Err(format!(
                "cannot open the file as the user (uid {uid}) who asked: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    /// The folder `path` is in.
    fn folder(path: &Path) -> &Path {
        match path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => Path::new("."),
        }
    }

    /// Whether this process may not open `path` as `job` needs: read it, or
    /// make a file in its folder. Only a refusal counts; any other error is
    /// the reading's or writing's to say.
    fn refused(path: &Path, write: bool) -> bool {
        let (at, mode) = if write {
            (folder(path), libc::W_OK | libc::X_OK)
        } else {
            (path, libc::R_OK)
        };
        let Ok(c) = CString::new(at.as_os_str().as_bytes()) else {
            return false;
        };
        // SAFETY: a plain check of a path that lives across the call.
        let failed = unsafe { libc::access(c.as_ptr(), mode) } != 0;
        failed && std::io::Error::last_os_error().raw_os_error() == Some(libc::EACCES)
    }

    /// What became of the file in one try.
    enum Tried {
        Done(Result<Vec<u8>, String>),
        /// The user may not open it; why.
        Refused(String),
    }

    /// Reads the file of `job`, or writes `bytes` to it, in this process.
    fn open(job: &Job, bytes: &[u8]) -> Result<Vec<u8>, String> {
        match job {
            Job::Read(path) => nerve_transport::backup::read_file(path),
            Job::Write { path, overwrite } => {
                nerve_transport::backup::write_file(path, bytes, *overwrite).map(|()| Vec::new())
            }
        }
    }

    /// Opens the file of `job` in a process that is `uid` with `gid` for
    /// good. With `check`, a file that user may not open is refused before
    /// it is touched.
    fn try_as(uid: u32, gid: u32, job: &Job, bytes: &[u8], check: bool) -> Tried {
        let (mut answer_in, answer_out) = match pipe() {
            Ok(p) => p,
            Err(e) => return Tried::Done(Err(e)),
        };
        // SAFETY: this process has one thread (the one `prepare` forked);
        // the child runs this module's code and leaves with _exit.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Tried::Done(Err(format!(
                "cannot start the process that opens the file: {}",
                std::io::Error::last_os_error()
            )));
        }
        if pid == 0 {
            drop(answer_in);
            let mut out = answer_out;
            let (path, write) = match job {
                Job::Read(p) => (p, false),
                Job::Write { path, .. } => (path, true),
            };
            let tried = match become_user(uid, gid) {
                Err(e) => Tried::Done(Err(e)),
                Ok(()) if check && refused(path, write) => {
                    let who = account(uid).map_or(format!("uid {uid}"), |(_, n)| {
                        format!("{} (uid {uid})", n.to_string_lossy())
                    });
                    Tried::Refused(if write {
                        format!(
                            "cannot write {}: it is written as the user who asked, {who}, who may not write in {}",
                            path.display(),
                            folder(path).display()
                        )
                    } else {
                        format!(
                            "cannot read {}: it is read as the user who asked, {who}, who may not read it",
                            path.display()
                        )
                    })
                }
                Ok(()) => Tried::Done(open(job, bytes)),
            };
            match tried {
                Tried::Done(r) => send(&mut out, r),
                Tried::Refused(e) => {
                    let _ = out.write_all(&[b"2".as_slice(), e.as_bytes()].concat());
                }
            }
            drop(out);
            // SAFETY: leaves the child without running the parent's exit
            // handlers.
            unsafe { libc::_exit(0) };
        }
        drop(answer_out);
        let mut frame = Vec::new();
        let read = answer_in.read_to_end(&mut frame);
        wait(pid);
        if let Err(e) = read {
            return Tried::Done(Err(format!("the file's process: {e}")));
        }
        match frame.split_first() {
            Some((b'2', e)) => Tried::Refused(String::from_utf8_lossy(e).into_owned()),
            _ => Tried::Done(decode(&frame)),
        }
    }

    /// What the process forked by [`prepare`] does: opens the file of
    /// `job` as `caller`, or as the owner of its folder where `sudo`'s user
    /// may not, or as root where nobody else asked. `None` when nothing is
    /// to be written (the command made no backup).
    fn for_caller(
        caller: Option<Caller>,
        job: &Job,
        bytes_in: Option<std::fs::File>,
    ) -> Option<Result<Vec<u8>, String>> {
        let mut bytes = Vec::new();
        if let Some(mut from) = bytes_in {
            // Nothing came: the command failed before it had a backup, and
            // no file is made.
            if from.read_to_end(&mut bytes).is_err() || bytes.is_empty() {
                return None;
            }
        }
        let Some(c) = caller else {
            return Some(open(job, &bytes));
        };
        let path = match job {
            Job::Read(p) => p,
            Job::Write { path, .. } => path,
        };
        Some(match try_as(c.uid, c.gid, job, &bytes, true) {
            Tried::Done(r) => r,
            Tried::Refused(e) if !c.sudo => Err(e),
            Tried::Refused(e) => match std::fs::metadata(folder(path)) {
                Err(_) => Err(e),
                Ok(m) if m.uid() == 0 => open(job, &bytes),
                Ok(m) => {
                    let gid = account(m.uid()).map_or(m.gid(), |(g, _)| g);
                    match try_as(m.uid(), gid, job, &bytes, false) {
                        Tried::Done(r) => r,
                        Tried::Refused(e) => Err(e),
                    }
                }
            },
        })
    }

    fn pipe() -> Result<(std::fs::File, std::fs::File), String> {
        let mut fds = [0; 2];
        // SAFETY: pipe2 writes two descriptors into `fds`.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(format!(
                "cannot make a pipe: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: both are open, and nothing else owns them.
        unsafe {
            Ok((
                OwnedFd::from_raw_fd(fds[0]).into(),
                OwnedFd::from_raw_fd(fds[1]).into(),
            ))
        }
    }

    /// An answer over a pipe: `0` and the bytes, or `1` and the error.
    fn send(to: &mut std::fs::File, r: Result<Vec<u8>, String>) {
        let frame = match r {
            Ok(mut b) => {
                b.insert(0, b'0');
                b
            }
            Err(e) => [b"1".as_slice(), e.as_bytes()].concat(),
        };
        let _ = to.write_all(&frame);
    }

    fn receive(from: &mut std::fs::File) -> Result<Vec<u8>, String> {
        let mut frame = Vec::new();
        from.read_to_end(&mut frame)
            .map_err(|e| format!("the file's process: {e}"))?;
        decode(&frame)
    }

    fn decode(frame: &[u8]) -> Result<Vec<u8>, String> {
        match frame.split_first() {
            Some((b'0', bytes)) => Ok(bytes.to_vec()),
            Some((_, e)) => Err(String::from_utf8_lossy(e).into_owned()),
            None => Err("the process that opens the file ended without an answer".into()),
        }
    }

    fn wait(pid: libc::pid_t) {
        let mut status = 0;
        // SAFETY: the child is this process's.
        unsafe { libc::waitpid(pid, &mut status, 0) };
    }

    pub fn prepare(job: Job) -> Result<(), String> {
        let caller = caller()?;
        let (mut answer_in, answer_out) = pipe()?;
        let (bytes_in, bytes_out) = match &job {
            Job::Read(_) => (None, None),
            Job::Write { .. } => {
                let (i, o) = pipe()?;
                (Some(i), Some(o))
            }
        };
        // SAFETY: `main` calls this while the process has one thread; the
        // child runs this module's code and leaves with _exit.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(format!(
                "cannot start the process that opens the file: {}",
                std::io::Error::last_os_error()
            ));
        }
        if pid == 0 {
            drop(answer_in);
            drop(bytes_out);
            let mut out = answer_out;
            if let Some(r) = for_caller(caller, &job, bytes_in) {
                send(&mut out, r);
            }
            drop(out);
            // SAFETY: leaves the child without running the parent's exit
            // handlers.
            unsafe { libc::_exit(0) };
        }
        drop(answer_out);
        drop(bytes_in);
        let kept = match job {
            Job::Read(path) => {
                let bytes = receive(&mut answer_in);
                wait(pid);
                Kept::Read { path, bytes }
            }
            Job::Write { path, overwrite } => Kept::Write {
                path,
                overwrite,
                to: bytes_out.expect("a pipe for the bytes"),
                from: answer_in,
                pid,
            },
        };
        *nerve_transport::sync::lock(&KEPT) = Some(kept);
        Ok(())
    }

    /// What [`prepare`] read of `path`, once; `None` when it read nothing
    /// or another file.
    pub fn take_read(path: &Path) -> Option<Result<Vec<u8>, String>> {
        let mut kept = nerve_transport::sync::lock(&KEPT);
        match kept.take() {
            Some(Kept::Read { path: p, bytes }) if p == path => Some(bytes),
            other => {
                *kept = other;
                None
            }
        }
    }

    /// Writes `bytes` through the process [`prepare`] started for `path`;
    /// `None` when there is none for that file.
    pub fn take_write(path: &Path, bytes: &[u8], overwrite: bool) -> Option<Result<(), String>> {
        let mut kept = nerve_transport::sync::lock(&KEPT);
        match kept.take() {
            Some(Kept::Write {
                path: p,
                overwrite: o,
                mut to,
                mut from,
                pid,
            }) if p == path && o == overwrite => {
                let sent = to.write_all(bytes);
                drop(to);
                // The process's own error first: one that could not become
                // the user ends before it takes the bytes.
                let answer = receive(&mut from);
                wait(pid);
                Some(answer.and_then(|_| sent.map_err(|e| format!("the file's process: {e}"))))
            }
            other => {
                *kept = other;
                None
            }
        }
    }
}

/// Set by the node for an owner's `backup` or `restore` (crate::owner): the
/// file the owner's own program opened and handed over, as `fd:N` (Linux),
/// or a file in the node's state folder that carries its bytes (Windows).
pub const OWNER_FILE_ENV: &str = "NERVE_OWNER_FILE";

/// The file handed over for a command that runs for an owner: `None` when
/// it runs for none. One that runs for an owner without it is refused: the
/// node never opens an owner's path as itself.
fn handed(path: &Path, write: bool) -> Option<Result<std::fs::File, String>> {
    use std::sync::atomic::{AtomicBool, Ordering};
    static TAKEN: AtomicBool = AtomicBool::new(false);
    crate::owner::owner_running()?;
    let missing = || {
        format!(
            "{} is opened by the program of the owner who asked, and none came with the command",
            path.display()
        )
    };
    let Some(given) = std::env::var(OWNER_FILE_ENV).ok().filter(|v| !v.is_empty()) else {
        return Some(Err(missing()));
    };
    // Taken once: the descriptor is closed with the file.
    if TAKEN.swap(true, Ordering::SeqCst) {
        return Some(Err(missing()));
    }
    #[cfg(unix)]
    if let Some(n) = given.strip_prefix("fd:") {
        use std::os::fd::FromRawFd;
        return Some(match n.parse::<i32>() {
            // SAFETY: the node opened this descriptor for this program
            // alone (crate::owner), and it is taken once.
            Ok(n) if n > 2 => Ok(unsafe { std::fs::File::from_raw_fd(n) }),
            _ => Err(missing()),
        });
    }
    let at = Path::new(&given);
    Some(
        if write {
            std::fs::File::create(at)
        } else {
            std::fs::File::open(at)
        }
        .map_err(|e| format!("{}: {e}", at.display())),
    )
}

/// Opens the file of `job` as the user who asked, before `main` makes the
/// command the node's user: reads it now, or starts the process that
/// writes it later ([`write`]). Called while the process has one thread.
pub fn prepare(job: Job) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    return linux::prepare(job);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = job;
        Ok(())
    }
}

/// The backup at `path`: what [`prepare`] read as the user who asked, else
/// read now.
pub fn read(path: &Path) -> Result<Vec<u8>, String> {
    if let Some(file) = handed(path, false) {
        return nerve_transport::backup::read_open(file?, &path.display().to_string());
    }
    #[cfg(target_os = "linux")]
    if let Some(r) = linux::take_read(path) {
        return r;
    }
    nerve_transport::backup::read_file(path)
}

/// Writes the backup to `path`: through the process [`prepare`] started as
/// the user who asked, else here.
pub fn write(path: &Path, bytes: &[u8], overwrite: bool) -> Result<(), String> {
    if let Some(file) = handed(path, true) {
        // The owner's program made it new, and puts it in place.
        use std::io::Write;
        let mut file = file?;
        return file
            .write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("cannot write {}: {e}", path.display()));
    }
    #[cfg(target_os = "linux")]
    if let Some(r) = linux::take_write(path, bytes, overwrite) {
        return r;
    }
    nerve_transport::backup::write_file(path, bytes, overwrite)
}
