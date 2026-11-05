//! The home and temporary folder of each pairing's commands of `nerve-run`
//! on the installed Linux node (#167, [`crate::account::Own`]). The node
//! makes them when the pairing comes and deletes them, with what they hold,
//! when it goes. It does both as `nerve-run` ([`crate::account::FsAs`]):
//! the folders are that account's, below its home, which the node's own
//! user may not enter. A record in the node's state folder names the
//! pairings it made folders for, each with the node's id at that center,
//! so that a pairing made again under the same name gets new folders, and
//! nothing else in the account's home is ever taken for a pairing's: a
//! folder under a pairing's name that the node did not make for it is
//! refused (it may be left from an earlier version, or made there by a
//! command), unless it is as empty as a new one.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use nerve_policy::NodeConfig;

use crate::account::{FsAs, Own};
use crate::fs::names;
use crate::paths::NodePaths;
use crate::service::Account;

/// The record of the pairings whose folders the node made: center name ->
/// the node's id at that center.
pub fn record_file(paths: &NodePaths) -> PathBuf {
    paths.state_dir.join("own-folders.json")
}

fn read_record(file: &Path) -> BTreeMap<String, String> {
    std::fs::read(file)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn write_record(file: &Path, r: &BTreeMap<String, String>) -> Result<(), String> {
    let json = serde_json::to_vec_pretty(r).map_err(|e| e.to_string())?;
    nerve_transport::files::write_private(file, &json)
        .map_err(|e| format!("{}: {e}", file.display()))
}

/// One [`sync`] at a time: each reads the config once its turn has come,
/// so that one started for an older version cannot undo a newer one.
static SYNCING: Mutex<()> = Mutex::new(());

/// The record is read, changed and written back under this, and nothing
/// slow is done while it is held: two changes at once would lose what the
/// other wrote.
static RECORD: Mutex<()> = Mutex::new(());

/// One lock per pairing name, held while that pairing's folders are made
/// or deleted. A delete of a big home takes seconds or minutes, and the
/// commands of every other pairing go on meanwhile; a command of the
/// pairing itself waits, so it never makes folders into a tree being
/// deleted.
static NAMES: Mutex<BTreeMap<String, Arc<Mutex<()>>>> = Mutex::new(BTreeMap::new());

fn name_lock(name: &str) -> Arc<Mutex<()>> {
    let mut names = NAMES.lock().unwrap_or_else(PoisonError::into_inner);
    names.entry(name.to_string()).or_default().clone()
}

/// The node's id at the center `name` that the record has folders for.
fn recorded(file: &Path, name: &str) -> Option<String> {
    let _one = RECORD.lock().unwrap_or_else(PoisonError::into_inner);
    read_record(file).remove(name)
}

fn change_record(
    file: &Path,
    change: impl FnOnce(&mut BTreeMap<String, String>),
) -> Result<(), String> {
    let _one = RECORD.lock().unwrap_or_else(PoisonError::into_inner);
    let mut record = read_record(file);
    change(&mut record);
    write_record(file, &record)
}

/// Brings the pairings' folders in line with the config `cfg` gives, as
/// `run` (`nerve-run`, whose home holds them): those of a pairing that is
/// gone, or was made again under its name, are deleted with what they hold,
/// and every pairing's are made where missing. What failed is said, and the
/// record keeps a pairing whose folders could not all be deleted, so the
/// next sync tries again. A pairing's folders are handled under its own
/// lock, so the commands of the others do not wait for a long delete.
pub fn sync(run: &Account, cfg: impl FnOnce() -> NodeConfig, file: &Path) -> Vec<String> {
    let _one = SYNCING.lock().unwrap_or_else(PoisonError::into_inner);
    // The config as it is once this sync's turn has come: one started for
    // an older version would delete the folders of a pairing a newer one
    // made.
    let cfg = cfg();
    let mut errors = Vec::new();
    let now: BTreeMap<&str, &str> = cfg
        .centers
        .iter()
        .map(|c| (c.name.as_str(), c.node_id.as_str()))
        .collect();
    let gone: Vec<(String, String)> = {
        let _one = RECORD.lock().unwrap_or_else(PoisonError::into_inner);
        read_record(file)
            .into_iter()
            .filter(|(name, id)| now.get(name.as_str()) != Some(&id.as_str()))
            .collect()
    };
    for (name, old) in gone {
        let lock = name_lock(&name);
        let _name = lock.lock().unwrap_or_else(PoisonError::into_inner);
        // A command may have made the pairing's folders again while this
        // waited for its lock, also for a pairing made after this sync read
        // its config: only the folders of the id it saw are its to delete.
        // The next sync judges the newer ones by the newer config.
        if recorded(file, &name).as_deref() != Some(old.as_str()) {
            continue;
        }
        match remove(run, &name) {
            Ok(()) => {
                if let Err(e) = change_record(file, |r| {
                    r.remove(&name);
                }) {
                    errors.push(e);
                }
                tracing::info!("deleted the home and temporary folder of the pairing {name}");
            }
            Err(e) => errors.push(e),
        }
    }
    for (name, id) in now {
        let lock = name_lock(name);
        let _name = lock.lock().unwrap_or_else(PoisonError::into_inner);
        if recorded(file, name).is_some() {
            // Made again only where a command found them gone.
            continue;
        }
        match make_new(run, name) {
            Ok(_) => {
                if let Err(e) = change_record(file, |r| {
                    r.insert(name.to_string(), id.to_string());
                }) {
                    errors.push(e);
                }
            }
            Err(e) => errors.push(e),
        }
    }
    errors
}

/// The folders of the pairing `center`, whose node id at that center is
/// `node_id`, for a command, made where they are missing: what [`sync`]
/// does for that pairing alone, for a command that comes before it. The
/// folders of an earlier pairing under its name are deleted first, and a
/// folder the node did not make for it is refused. It waits only for work
/// on this pairing's own folders.
pub fn ready(run: &Account, center: &str, node_id: &str, file: &Path) -> Result<Own, String> {
    let lock = name_lock(center);
    let _name = lock.lock().unwrap_or_else(PoisonError::into_inner);
    match recorded(file, center) {
        Some(id) if id == node_id => return make(run, center),
        Some(_) => {
            remove(run, center)?;
            change_record(file, |r| {
                r.remove(center);
            })?;
        }
        None => {}
    }
    let own = make_new(run, center)?;
    change_record(file, |r| {
        r.insert(center.to_string(), node_id.to_string());
    })?;
    Ok(own)
}

/// [`make`] for a pairing the record does not name: its folder must not be
/// there yet, or hold nothing but an empty `home` and `tmp` (what a make
/// that the record missed leaves).
fn make_new(run: &Account, center: &str) -> Result<Own, String> {
    let root = run.home.join(center);
    let unused = {
        let _as = act_as(run)?;
        unused(&root)
    };
    if !unused {
        return Err(format!(
            "{} is there already, and the node did not make it for the pairing {center}: \
             delete it or move it away (it may be left from an earlier version), and the \
             pairing gets a home of its own",
            root.display()
        ));
    }
    make(run, center)
}

/// Whether `root` is missing, or a folder (not a link) that holds nothing
/// but its `home` and `tmp` folders, both empty.
fn unused(root: &Path) -> bool {
    let empty_dir = |p: &Path| {
        std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir())
            && std::fs::read_dir(p).is_ok_and(|mut d| d.next().is_none())
    };
    match std::fs::symlink_metadata(root) {
        Err(e) => e.kind() == std::io::ErrorKind::NotFound,
        Ok(m) if !m.is_dir() => false,
        Ok(_) => std::fs::read_dir(root).is_ok_and(|d| {
            d.into_iter().all(|e| {
                e.is_ok_and(|e| {
                    (e.file_name() == "home" || e.file_name() == "tmp") && empty_dir(&e.path())
                })
            })
        }),
    }
}

/// Makes the folders of the pairing `center` where they are missing, as
/// `run`, each 0700: its folder below the account's home, and in it `home`
/// and `tmp`. A command of a pairing may have opened them, or the
/// account's home, to others (`chmod`, which Landlock does not rule), and
/// they close again here. Something else under one of those names (a file,
/// a link, another account's folder) is refused, not followed.
fn make(run: &Account, center: &str) -> Result<Own, String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let own = Own::of(&run.home, center);
    let root = own.home.parent().unwrap_or(&run.home).to_path_buf();
    let _as = act_as(run)?;
    if let Ok(m) = std::fs::symlink_metadata(&run.home)
        && m.is_dir()
        && m.mode() & 0o077 != 0
    {
        std::fs::set_permissions(&run.home, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("{}: {e}", run.home.display()))?;
    }
    for dir in [&root, &own.home, &own.temp] {
        let err = |e: std::io::Error| format!("{}: {e}", dir.display());
        match std::fs::DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(err(e)),
        }
        let m = std::fs::symlink_metadata(dir).map_err(err)?;
        if !m.is_dir() || m.uid() != run.uid {
            return Err(format!(
                "{} is not a folder of {}, so the pairing {center} has no home of its own; delete it",
                dir.display(),
                run.name
            ));
        }
        if m.mode() & 0o7777 != 0o700 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(err)?;
        }
    }
    Ok(own)
}

/// How many folder levels [`remove`] holds open at once: each holds a
/// descriptor, and a command can make a tree deeper than the descriptors a
/// process may have. A folder deeper than this is moved up to the
/// pairing's folder and deleted from there.
const WALK_DEPTH: usize = 64;

/// Deletes the folder of the pairing `center` below `run`'s home, with
/// everything in it, as `run`. It goes through descriptors and follows no
/// link, and stays on the folder's own file system: what a command of the
/// pairing put there points nowhere the walk goes. A folder the account
/// made closed (`chmod 0`) is opened up first. Gone already is fine.
pub fn remove(run: &Account, center: &str) -> Result<(), String> {
    let shown = run.home.join(center);
    let _as = act_as(run)?;
    let home = open_dir(libc::AT_FDCWD, &cstr(run.home.as_os_str())?)
        .map_err(|e| format!("{}: {e}", run.home.display()))?;
    let name = cstr(std::ffi::OsStr::new(center))?;
    let top = match open_or_open_up(&home, &name) {
        Ok(Some(fd)) => fd,
        // Not a folder: its name alone goes.
        Ok(None) => {
            return unlink(&home, &name, false).map_err(|e| format!("{}: {e}", shown.display()));
        }
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(()),
        Err(e) => return Err(format!("{}: {e}", shown.display())),
    };
    let dev = stat_fd(&top)
        .map_err(|e| format!("{}: {e}", shown.display()))?
        .st_dev;
    let mut errors = Vec::new();
    let mut moved = 0usize;
    // A pass that moved a deep folder up has more to do.
    loop {
        let before = moved;
        empty(&top, &top, &shown, dev, 0, &mut moved, &mut errors);
        if moved == before || !errors.is_empty() {
            break;
        }
    }
    if errors.is_empty()
        && let Err(e) = unlink(&home, &name, true)
    {
        errors.push(format!("{}: {e}", shown.display()));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "the folders of the pairing {center} were not all deleted: {}",
            errors.join("; ")
        ))
    }
}

/// The node's file access as `run` on this thread; none needed where the
/// node is that account already (a test).
fn act_as(run: &Account) -> Result<Option<FsAs>, String> {
    if run.uid == nerve_transport::net::euid() {
        return Ok(None);
    }
    FsAs::new(run)
        .map(Some)
        .map_err(|e| format!("cannot act as {}: {e}", run.name))
}

fn cstr(s: &std::ffi::OsStr) -> Result<CString, String> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(s.as_bytes()).map_err(|e| e.to_string())
}

fn last() -> std::io::Error {
    std::io::Error::last_os_error()
}

/// The folder `name` in `at`, opened to read and never followed.
fn open_dir(at: libc::c_int, name: &CStr) -> std::io::Result<OwnedFd> {
    // SAFETY: a valid C string; the descriptor returned is ours alone.
    let fd = unsafe {
        libc::openat(
            at,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(last());
    }
    // SAFETY: just opened, owned by nothing else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn stat_fd(fd: &OwnedFd) -> std::io::Result<libc::stat> {
    // SAFETY: fstat into a zeroed struct of the right type.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd.as_raw_fd(), &mut st) != 0 {
            return Err(last());
        }
        Ok(st)
    }
}

fn stat_at(dir: &OwnedFd, name: &CStr) -> std::io::Result<libc::stat> {
    // SAFETY: fstatat of a valid C string into a zeroed struct, no link
    // followed.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        ) != 0
        {
            return Err(last());
        }
        Ok(st)
    }
}

fn is_dir(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR
}

/// `fchmodat2` (Linux 6.6), whose `AT_SYMLINK_NOFOLLOW` refuses a link:
/// the same number on every architecture the node is built for.
const SYS_FCHMODAT2: libc::c_long = 452;

/// The folder `name` in `dir`, opened; one its account closed to itself is
/// opened up (0700) first. `None` where `name` is no folder. The folder is
/// changed by name without following a link where the kernel can
/// (`fchmodat2`); an older one follows a link that a command put in its
/// place since it was looked at, which can only change the mode of a file
/// of the same account.
fn open_or_open_up(dir: &OwnedFd, name: &CStr) -> std::io::Result<Option<OwnedFd>> {
    let st = stat_at(dir, name)?;
    if !is_dir(&st) {
        return Ok(None);
    }
    let fd = match open_dir(dir.as_raw_fd(), name) {
        Ok(fd) => fd,
        Err(e) if e.raw_os_error() == Some(libc::EACCES) => {
            // SAFETY: plain system calls with a valid C string.
            let r = unsafe {
                let r = libc::syscall(
                    SYS_FCHMODAT2,
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    0o700 as libc::mode_t,
                    libc::AT_SYMLINK_NOFOLLOW,
                );
                if r != 0 && last().raw_os_error() == Some(libc::ENOSYS) {
                    libc::fchmodat(dir.as_raw_fd(), name.as_ptr(), 0o700, 0) as libc::c_long
                } else {
                    r
                }
            };
            if r != 0 {
                return Err(last());
            }
            open_dir(dir.as_raw_fd(), name)?
        }
        Err(e)
            if e.raw_os_error() == Some(libc::ENOTDIR) || e.raw_os_error() == Some(libc::ELOOP) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    // The folder looked at, not one swapped in since.
    let now = stat_fd(&fd)?;
    if now.st_ino != st.st_ino || now.st_dev != st.st_dev {
        return Err(std::io::Error::from_raw_os_error(libc::EAGAIN));
    }
    // Its entries can be deleted only while it may be written.
    // SAFETY: fchmod of a descriptor we hold.
    if now.st_mode & 0o700 != 0o700 && unsafe { libc::fchmod(fd.as_raw_fd(), 0o700) } != 0 {
        return Err(last());
    }
    Ok(Some(fd))
}

fn unlink(dir: &OwnedFd, name: &CStr, folder: bool) -> std::io::Result<()> {
    let flag = if folder { libc::AT_REMOVEDIR } else { 0 };
    // SAFETY: a valid C string, relative to the open folder `dir`.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), flag) } != 0 {
        let e = last();
        if e.raw_os_error() != Some(libc::ENOENT) {
            return Err(e);
        }
    }
    Ok(())
}

/// Numbers the folders [`remove`] moves up, for the whole process: a tree
/// that an earlier call left under its number (it stopped on an error) must
/// not meet a later call's folder of the same name.
static DEEPER: AtomicUsize = AtomicUsize::new(0);

/// A name in `top` for a folder moved up that nothing has: not one an
/// earlier call left (also of an earlier process of the same id).
fn free_deeper_name(top: &OwnedFd) -> std::io::Result<CString> {
    for _ in 0..4096 {
        let n = DEEPER.fetch_add(1, Ordering::Relaxed);
        let name = CString::new(format!(".deeper-{}-{n}", std::process::id()))
            .expect("no NUL in the name");
        match stat_at(top, &name) {
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(name),
            Err(e) => return Err(e),
            Ok(_) => {}
        }
    }
    Err(std::io::Error::from_raw_os_error(libc::EEXIST))
}

/// Deletes what the open folder `dir` (shown as `shown`, `depth` levels
/// below `top`) holds. A folder at [`WALK_DEPTH`] is moved up into `top`
/// under a new name and counted in `moved`, for the next pass.
fn empty(
    dir: &OwnedFd,
    top: &OwnedFd,
    shown: &Path,
    dev: libc::dev_t,
    depth: usize,
    moved: &mut usize,
    errors: &mut Vec<String>,
) {
    use std::os::unix::ffi::OsStrExt;
    let list = match names(dir) {
        Ok(n) => n,
        Err(e) => {
            errors.push(format!("{}: {e}", shown.display()));
            return;
        }
    };
    for name in list {
        let here = shown.join(std::ffi::OsStr::from_bytes(name.to_bytes()));
        let st = match stat_at(dir, &name) {
            Ok(st) => st,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
            Err(e) => {
                errors.push(format!("{}: {e}", here.display()));
                continue;
            }
        };
        if is_dir(&st) {
            // Another file system mounted here is not the pairing's.
            if st.st_dev != dev {
                errors.push(format!(
                    "{}: another file system is mounted there",
                    here.display()
                ));
                continue;
            }
            if depth + 1 >= WALK_DEPTH {
                let up = match free_deeper_name(top) {
                    Ok(up) => up,
                    Err(e) => {
                        errors.push(format!("{}: {e}", here.display()));
                        continue;
                    }
                };
                // SAFETY: valid C strings, relative to descriptors we hold.
                let r = unsafe {
                    libc::renameat(dir.as_raw_fd(), name.as_ptr(), top.as_raw_fd(), up.as_ptr())
                };
                if r != 0 {
                    errors.push(format!("{}: {}", here.display(), last()));
                } else {
                    *moved += 1;
                }
                continue;
            }
            match open_or_open_up(dir, &name) {
                Ok(Some(sub)) => empty(&sub, top, &here, dev, depth + 1, moved, errors),
                Ok(None) => {}
                Err(e) => {
                    errors.push(format!("{}: {e}", here.display()));
                    continue;
                }
            }
        }
        if let Err(e) = unlink(dir, &name, is_dir(&st)) {
            // A folder moved up from below it is deleted in the next pass.
            if !(is_dir(&st) && e.raw_os_error() == Some(libc::ENOTEMPTY) && *moved > 0) {
                errors.push(format!("{}: {e}", here.display()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn me(home: &Path) -> Account {
        // SAFETY: plain getters.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        Account {
            name: "nerve-run".into(),
            uid,
            gid,
            comment: String::new(),
            home: home.to_path_buf(),
            groups: vec![gid],
        }
    }

    fn mode(p: &Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().mode() & 0o7777
    }

    #[test]
    fn a_pairing_gets_a_closed_home_and_temporary_folder_of_its_own() {
        let d = tempfile::tempdir().unwrap();
        let run = me(d.path());
        let own = make(&run, "lab").unwrap();
        assert_eq!(own, Own::of(d.path(), "lab"));
        for p in [d.path().join("lab"), own.home.clone(), own.temp.clone()] {
            assert!(p.is_dir(), "{}", p.display());
            assert_eq!(mode(&p), 0o700, "{}", p.display());
        }
        // A home a command opened to others closes again, and so does the
        // account's.
        std::fs::set_permissions(&own.home, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        make(&run, "lab").unwrap();
        assert_eq!(mode(&own.home), 0o700);
        assert_eq!(mode(d.path()), 0o700);
        // A link in the home's place is refused, not followed.
        std::fs::remove_dir(&own.temp).unwrap();
        std::os::unix::fs::symlink(d.path(), &own.temp).unwrap();
        let e = make(&run, "lab").unwrap_err();
        assert!(e.contains("is not a folder of nerve-run"), "{e}");
    }

    #[test]
    fn removing_a_pairing_deletes_what_its_folders_hold_and_nothing_else() {
        let d = tempfile::tempdir().unwrap();
        let run = me(&d.path().join("run"));
        std::fs::create_dir(&run.home).unwrap();
        let own = make(&run, "lab").unwrap();
        let other = make(&run, "home").unwrap();
        let outside = d.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("keep"), "x").unwrap();
        std::fs::write(other.home.join(".gitconfig"), "x").unwrap();
        // What a command leaves: files, a closed folder, links out, a deep
        // tree.
        std::fs::write(own.home.join(".gitconfig"), "x").unwrap();
        std::fs::create_dir_all(own.temp.join("a/b")).unwrap();
        std::fs::write(own.temp.join("a/b/f"), "x").unwrap();
        std::fs::set_permissions(own.temp.join("a/b"), std::fs::Permissions::from_mode(0o000))
            .unwrap();
        std::fs::set_permissions(own.temp.join("a"), std::fs::Permissions::from_mode(0o500))
            .unwrap();
        std::os::unix::fs::symlink(&outside, own.home.join("out")).unwrap();
        std::os::unix::fs::symlink(&other.home, own.home.join("other")).unwrap();
        let mut deep = own.home.join("deep");
        for _ in 0..WALK_DEPTH + 10 {
            deep.push("d");
        }
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("f"), "x").unwrap();
        remove(&run, "lab").unwrap();
        assert!(!run.home.join("lab").exists());
        assert!(outside.join("keep").exists());
        assert!(other.home.join(".gitconfig").exists());
        // Gone already is fine.
        remove(&run, "lab").unwrap();
    }

    /// A deep tree that an earlier removal moved up (and stopped on an
    /// error) lies under a `.deeper-` name; a later removal of the pairing
    /// moves new ones under names of their own, and deletes the old tree
    /// too.
    #[test]
    fn a_removal_moves_deep_folders_up_under_names_nothing_has() {
        let d = tempfile::tempdir().unwrap();
        let run = me(&d.path().join("run"));
        std::fs::create_dir(&run.home).unwrap();
        let own = make(&run, "lab").unwrap();
        let top = run.home.join("lab");
        // Every name the next moves would take, as a tree with a file in
        // it (a rename onto an empty folder would replace it, onto this
        // one it fails), the first of them holding a deep tree itself.
        let from = DEEPER.load(Ordering::Relaxed);
        let pid = std::process::id();
        for n in from..from + 64 {
            let left = top.join(format!(".deeper-{pid}-{n}"));
            let mut deep = left.clone();
            if n == from {
                for _ in 0..WALK_DEPTH + 5 {
                    deep.push("d");
                }
            }
            std::fs::create_dir_all(&deep).unwrap();
            std::fs::write(deep.join("f"), "x").unwrap();
        }
        let mut deep = own.home.join("deep");
        for _ in 0..WALK_DEPTH + 10 {
            deep.push("d");
        }
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("f"), "x").unwrap();
        remove(&run, "lab").unwrap();
        assert!(!top.exists());
    }

    /// The commands of one pairing do not wait while another pairing's
    /// folders are made or deleted; its own do.
    #[test]
    fn a_pairing_waits_only_for_work_on_its_own_folders() {
        let d = tempfile::tempdir().unwrap();
        let run = me(&d.path().join("run"));
        std::fs::create_dir(&run.home).unwrap();
        let file = d.path().join("own-folders.json");
        let busy = name_lock("busy");
        let held = busy.lock().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        for name in ["other", "busy"] {
            let (run, file, tx) = (run.clone(), file.clone(), tx.clone());
            std::thread::spawn(move || {
                ready(&run, name, "n1", &file).unwrap();
                tx.send(name).unwrap();
            });
        }
        let first = rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
        assert_eq!(first, "other");
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(300))
                .is_err(),
            "it did not wait for the lock of its own folders"
        );
        drop(held);
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap(),
            "busy"
        );
    }

    fn center(name: &str, id: &str) -> nerve_policy::CenterEntry {
        nerve_policy::CenterEntry {
            name: name.into(),
            url: "https://c".into(),
            pin: None,
            center_id: "c".into(),
            node_id: id.into(),
            settings: Default::default(),
            paused: false,
            revoked: false,
            unknown: false,
            public_key: None,
            key_rotations: 0,
            pin_rotations: 0,
            old_pin: None,
            policy: Default::default(),
            capabilities: Vec::new(),
        }
    }

    /// A folder under a new pairing's name that the node did not make for
    /// it (an earlier version's, or one a command made) is neither taken
    /// nor deleted, by the sync and before a command; one as empty as a new
    /// one is taken.
    #[test]
    fn a_folder_the_node_did_not_make_is_not_taken_for_a_pairing() {
        let d = tempfile::tempdir().unwrap();
        let run = me(&d.path().join("run"));
        std::fs::create_dir(&run.home).unwrap();
        let file = d.path().join("own-folders.json");
        let lab = Own::of(&run.home, "lab");
        std::fs::create_dir_all(&lab.home).unwrap();
        std::fs::write(lab.home.join(".gitconfig"), "x").unwrap();
        let home = Own::of(&run.home, "home");
        std::fs::create_dir_all(&home.home).unwrap();
        std::fs::create_dir_all(&home.temp).unwrap();
        let cfg = NodeConfig {
            centers: vec![center("lab", "n1"), center("home", "n2")],
            ..Default::default()
        };
        let errors = sync(&run, || cfg.clone(), &file);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("the node did not make it"), "{errors:?}");
        let record = read_record(&file);
        assert!(!record.contains_key("lab") && record.contains_key("home"));
        assert!(lab.home.join(".gitconfig").exists());
        let e = ready(&run, "lab", "n1", &file).unwrap_err();
        assert!(e.contains("the node did not make it"), "{e}");
        assert!(lab.home.join(".gitconfig").exists());
        // Once it is gone, the pairing gets its own.
        std::fs::remove_dir_all(run.home.join("lab")).unwrap();
        assert_eq!(ready(&run, "lab", "n1", &file).unwrap(), lab);
        assert_eq!(
            read_record(&file).get("lab").map(String::as_str),
            Some("n1")
        );
    }

    /// A command that comes before the sync gets its pairing's folders, not
    /// those an earlier pairing under its name left, and gets them again
    /// where they went.
    #[test]
    fn a_command_before_the_sync_gets_folders_of_its_own_pairing() {
        let d = tempfile::tempdir().unwrap();
        let run = me(&d.path().join("run"));
        std::fs::create_dir(&run.home).unwrap();
        let file = d.path().join("own-folders.json");
        let lab = ready(&run, "lab", "n1", &file).unwrap();
        std::fs::write(lab.home.join(".bashrc"), "x").unwrap();
        assert_eq!(ready(&run, "lab", "n1", &file).unwrap(), lab);
        assert!(lab.home.join(".bashrc").exists());
        // Paired again under the name, before a sync.
        assert_eq!(ready(&run, "lab", "n2", &file).unwrap(), lab);
        assert!(lab.home.is_dir() && !lab.home.join(".bashrc").exists());
        assert_eq!(
            read_record(&file).get("lab").map(String::as_str),
            Some("n2")
        );
        std::fs::remove_dir(&lab.temp).unwrap();
        ready(&run, "lab", "n2", &file).unwrap();
        assert!(lab.temp.is_dir());
    }

    /// A sync waits for the one running, and then goes by the config as it
    /// is then: one started for an older version would undo a newer one.
    #[test]
    fn a_sync_waits_for_the_one_running_and_takes_the_config_as_it_is_then() {
        let d = tempfile::tempdir().unwrap();
        let run = me(&d.path().join("run"));
        std::fs::create_dir(&run.home).unwrap();
        let file = d.path().join("own-folders.json");
        let cfg = std::sync::Arc::new(Mutex::new(NodeConfig::default()));
        let running = SYNCING.lock().unwrap();
        let waiting = {
            let (run, cfg, file) = (run.clone(), cfg.clone(), file.clone());
            std::thread::spawn(move || sync(&run, || cfg.lock().unwrap().clone(), &file))
        };
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(!file.exists(), "it did not wait");
        cfg.lock().unwrap().centers = vec![center("lab", "n1")];
        drop(running);
        assert!(waiting.join().unwrap().is_empty());
        assert!(Own::of(&run.home, "lab").home.is_dir());
    }

    /// A pairing made under a name again after a sync read its config keeps
    /// the folders a command made for it, while that sync is busy with
    /// another pairing's.
    #[test]
    fn a_sync_leaves_the_folders_of_a_pairing_made_again_after_it_read_the_config() {
        let d = tempfile::tempdir().unwrap();
        let run = me(&d.path().join("run"));
        std::fs::create_dir(&run.home).unwrap();
        let file = d.path().join("own-folders.json");
        let before = NodeConfig {
            centers: vec![center("alpha", "a1"), center("lab", "n1")],
            ..Default::default()
        };
        assert!(sync(&run, || before.clone(), &file).is_empty());
        let lab = Own::of(&run.home, "lab");
        std::fs::write(lab.home.join(".bashrc"), "x").unwrap();
        // The sync sees neither pairing, and waits on alpha's lock.
        let busy = name_lock("alpha");
        let held = busy.lock().unwrap();
        let syncing = {
            let (run, file) = (run.clone(), file.clone());
            std::thread::spawn(move || sync(&run, NodeConfig::default, &file))
        };
        // It has read its config and the record once it asks for alpha's lock
        // (the map holds one handle, this test one, the sync the third).
        let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while Arc::strong_count(&busy) < 3 {
            assert!(
                std::time::Instant::now() < until,
                "the sync did not get there"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        // Paired again as lab, and a command comes.
        assert_eq!(ready(&run, "lab", "n2", &file).unwrap(), lab);
        std::fs::write(lab.home.join(".gitconfig"), "y").unwrap();
        drop(held);
        assert!(syncing.join().unwrap().is_empty());
        assert!(lab.home.join(".gitconfig").exists() && !lab.home.join(".bashrc").exists());
        assert_eq!(
            read_record(&file).get("lab").map(String::as_str),
            Some("n2")
        );
        assert!(!run.home.join("alpha").exists());
    }

    #[test]
    fn a_sync_deletes_the_folders_of_a_pairing_that_went_or_was_made_again() {
        let d = tempfile::tempdir().unwrap();
        let run = me(&d.path().join("run"));
        std::fs::create_dir(&run.home).unwrap();
        let file = d.path().join("own-folders.json");
        // What the account's home held before: never a pairing's.
        std::fs::create_dir(run.home.join("bin")).unwrap();
        let mut cfg = NodeConfig {
            centers: vec![center("lab", "n1"), center("home", "n2")],
            ..Default::default()
        };
        assert!(sync(&run, || cfg.clone(), &file).is_empty());
        let lab = Own::of(&run.home, "lab");
        assert!(lab.home.is_dir() && Own::of(&run.home, "home").temp.is_dir());
        std::fs::write(lab.home.join(".bashrc"), "x").unwrap();
        // Paired again under the same name: a new id, empty folders.
        cfg.centers = vec![center("lab", "n3")];
        assert!(sync(&run, || cfg.clone(), &file).is_empty());
        assert!(lab.home.is_dir() && !lab.home.join(".bashrc").exists());
        assert!(!run.home.join("home").exists());
        assert!(run.home.join("bin").is_dir());
        cfg.centers.clear();
        assert!(sync(&run, || cfg.clone(), &file).is_empty());
        assert!(!run.home.join("lab").exists());
        assert!(read_record(&file).is_empty());
    }
}
