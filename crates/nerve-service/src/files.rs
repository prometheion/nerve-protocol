//! The files root writes for a service, and the user root's command becomes
//! on a service's folders.

use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use crate::Account;

/// Writes `data` to `path` through a temporary file beside it and a rename,
/// with `mode`.
pub fn write_file(path: &Path, data: &[u8], mode: u32) -> Result<(), String> {
    let at = |e: std::io::Error| format!("{}: {e}", path.display());
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).map_err(at)?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = dir.join(format!(
        ".{name}.{}.tmp",
        nerve_transport::keys::random_token(8)
    ));
    let r = (|| {
        std::fs::write(&tmp, data)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
        }
        #[cfg(not(unix))]
        let _ = mode;
        std::fs::rename(&tmp, path)
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r.map_err(at)
}

pub fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| format!("{}: {e}", path.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

/// Root's file access as the owner of `dir`, on this thread, while the
/// result lives ([`crate::account::FsAs`]): what root writes into a folder
/// of the service's user then cannot reach through a link that user made more
/// than that user may. A link in place of `dir` is refused. Nothing changes
/// for another caller than root, or a folder of root's.
pub fn as_owner_of(dir: &Path) -> Result<Option<impl Drop>, String> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        if m.file_type().is_symlink() {
            return Err(format!(
                "{} is a link; the service's folders are folders, and root does not follow it",
                dir.display()
            ));
        }
        if nerve_transport::net::euid() != 0 || m.uid() == 0 {
            return Ok(None);
        }
        let owner = Account {
            name: format!("uid {}", m.uid()),
            uid: m.uid(),
            gid: m.gid(),
            comment: String::new(),
            home: dir.to_path_buf(),
            groups: vec![m.gid()],
        };
        crate::account::FsAs::new(&owner)
            .map(Some)
            .map_err(|e| format!("cannot write as the owner of {}: {e}", dir.display()))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = dir;
        Ok(None::<NoDrop>)
    }
}

#[cfg(not(target_os = "linux"))]
struct NoDrop;
#[cfg(not(target_os = "linux"))]
impl Drop for NoDrop {
    fn drop(&mut self) {}
}

#[cfg(not(target_os = "linux"))]
fn chown(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        std::os::unix::fs::lchown(path, Some(uid), Some(gid))
            .map_err(|e| format!("{}: {e}", path.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, uid, gid);
        Ok(())
    }
}

/// Gives `path` and everything below it to `uid`:`gid`. Links are changed
/// themselves and never followed. On Linux each folder is opened without
/// following a link and read through its descriptor, so a folder that the
/// service's user swaps for a link meanwhile is not walked.
pub fn chown_tree(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        chown_below(path, path, uid, gid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        chown_tree_by_path(path, uid, gid)
    }
}

/// [`chown_tree`] on Linux: `at` is the path to open (below a folder's
/// descriptor), `shown` the one errors name.
#[cfg(target_os = "linux")]
fn chown_below(at: &Path, shown: &Path, uid: u32, gid: u32) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let err = |e: std::io::Error| format!("{}: {e}", shown.display());
    let dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(at);
    let dir = match dir {
        Ok(d) => d,
        // A file or a link: changed itself, through a descriptor of the
        // entry (not followed), so the file checked is the one changed.
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTDIR | libc::ELOOP)) => {
            return chown_entry(at, uid, gid).map_err(|e| format!("{}: {e}", shown.display()));
        }
        Err(e) => return Err(err(e)),
    };
    std::os::unix::fs::fchown(&dir, Some(uid), Some(gid)).map_err(err)?;
    let fd = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
    for e in std::fs::read_dir(&fd).map_err(err)? {
        let name = e.map_err(err)?.file_name();
        chown_below(&fd.join(&name), &shown.join(&name), uid, gid)?;
    }
    Ok(())
}

/// Gives the file or link at `at` (not followed) to `uid`:`gid`. A file
/// with more than one name is refused: its other name can be anywhere on
/// the same file system, as a hard link the service's user made to a file of
/// root's.
#[cfg(target_os = "linux")]
fn chown_entry(at: &Path, uid: u32, gid: u32) -> Result<(), String> {
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    let path = std::ffi::CString::new(at.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    // Through libc, not `OpenOptions::custom_flags`: on musl, the C library
    // of the released programs, the standard library takes O_PATH out of
    // the flags (musl's O_ACCMODE holds it), and the entry would be opened
    // for reading, which a socket refuses, a link fails and a FIFO waits on.
    // SAFETY: a valid C string; the new descriptor is owned below.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: open returned a fresh descriptor nothing else owns.
    let f = std::fs::File::from(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) });
    let m = f.metadata().map_err(|e| e.to_string())?;
    if m.nlink() > 1 {
        return Err(
            "it has another name (a hard link), which may be outside the service's folders; remove it and run this again".into(),
        );
    }
    // SAFETY: an empty NUL-terminated path with AT_EMPTY_PATH on an open
    // descriptor: the call changes that inode.
    let r = unsafe {
        libc::fchownat(
            std::os::fd::AsRawFd::as_raw_fd(&f),
            c"".as_ptr(),
            uid,
            gid,
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if r != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn chown_tree_by_path(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    chown(path, uid, gid)?;
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.is_dir() {
        let entries = std::fs::read_dir(path).map_err(|e| format!("{}: {e}", path.display()))?;
        for e in entries {
            let e = e.map_err(|e| format!("{}: {e}", path.display()))?;
            chown_tree_by_path(&e.path(), uid, gid)?;
        }
    }
    Ok(())
}

/// A command root runs on a service's folders `dirs` that belong to another
/// user (the installed node's `nerve`, the center's `nerve-center`) runs as
/// that user, so that what it writes stays readable to the service, and
/// root follows no link that user put there. The first of `dirs` that is
/// there decides. Called before anything else runs in the process:
/// it changes the user of the calling thread only where the C library does
/// not change every thread's. With `keep_root` (setup) root stays the saved
/// id, so the process can get it back for one thing, making an account
/// (`System::add_account`); a process of the service's user cannot trace or
/// read it, since its ids are not all that user's.
pub fn become_owner(dirs: &[&Path], keep_root: bool) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Some(m) = owner_to_become(dirs) else {
            return Ok(());
        };
        #[cfg(target_os = "linux")]
        let (setgid, setuid) = {
            let saved = |id: u32| if keep_root { 0 } else { id };
            (
                // SAFETY: plain calls without pointers.
                move |g: u32| unsafe { libc::setresgid(g, g, saved(g)) },
                move |u: u32| unsafe { libc::setresuid(u, u, saved(u)) },
            )
        };
        #[cfg(not(target_os = "linux"))]
        let (setgid, setuid) = {
            let _ = keep_root;
            // SAFETY: plain calls without pointers.
            (
                |g: u32| unsafe { libc::setgid(g) },
                |u: u32| unsafe { libc::setuid(u) },
            )
        };
        // SAFETY: the empty group list; groups first, the user last, while
        // root may still change both.
        let failed = unsafe { libc::setgroups(0, std::ptr::null()) != 0 }
            || setgid(m.gid()) != 0
            || setuid(m.uid()) != 0;
        if failed {
            return Err(format!(
                "cannot run as the owner (uid {}) of {}: {}",
                m.uid(),
                dirs.first().map_or(Path::new("?"), |d| *d).display(),
                std::io::Error::last_os_error()
            ));
        }
        // The session bus these name is the caller's, not the owner's: the
        // system keyring is found in the owner's session (/run/user/<uid>).
        // SAFETY: `main` calls this while the process has one thread.
        unsafe {
            std::env::remove_var("DBUS_SESSION_BUS_ADDRESS");
            std::env::remove_var("XDG_RUNTIME_DIR");
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (dirs, keep_root);
        Ok(())
    }
}

/// The folders whose owner root's command becomes ([`become_owner`]): the
/// first of them that is there, when this process is root and they are not
/// root's.
#[cfg(unix)]
pub fn owner_to_become(dirs: &[&Path]) -> Option<std::fs::Metadata> {
    use std::os::unix::fs::MetadataExt;
    if nerve_transport::net::euid() != 0 {
        return None;
    }
    dirs.iter()
        .find_map(|d| std::fs::metadata(d).ok())
        .filter(|m| m.uid() != 0)
}
