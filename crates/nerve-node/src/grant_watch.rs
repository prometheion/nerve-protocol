//! The node walks the folders it granted by itself once names in them
//! changed (#149): a file installed or cloned into a granted folder as a
//! hard link (pnpm's `node_modules`, a uv `.venv`, `git clone --local`, a
//! command's install from its own store) keeps the access list of its other
//! name until a walk of the folder reaches it, and so does a file or folder
//! moved in. Windows tells the node of new names in each granted folder
//! (directory change notifications over the folder and everything below
//! it); the node walks that folder a few seconds after the names stop
//! changing ([`QUIET`]), and no later than [`AT_MOST`] after the first
//! change while they go on. **Sync folders** stays as the way by hand.
//!
//! Only names count, never security changes, so the walk's own changes of
//! the access lists do not wake it again. A change the system could not
//! tell in full (its buffer ran over) walks the folder as well: the walk
//! goes through the whole folder anyway. A folder that cannot be watched
//! (a removable drive, which a held handle would keep from being ejected,
//! or an error) is left to the other syncs, and the log says so once.
//!
//! What it holds stays bounded: one handle and one buffer per granted
//! folder, and one entry per folder that changed, however many changes
//! come. The walk itself is the grant sync's (crate::grants::apply, in its
//! turn), so it never races a change of the config. The supervisor starts
//! one grant sync at a time ([`Watch::next_sync`]) and leaves a pause after
//! a walk, twice as long as the walk took, so a command that makes new names
//! all the time cannot keep the turn: the walk covers the changes of the
//! whole time it ran, and the next one waits. The start walk leaves none:
//! no name made it, and a pause as long as the longest walk there is would
//! hold back the first changes after every start. The first sync after the
//! node's start is a plain one; the walk of every grant (what was installed
//! or moved in while the node did not run) follows it as a walk of the
//! watch. A command of a pairing does not wait for a walk of the watch when
//! the config is the one the last sync saw and every recorded grant is
//! still where it was, nothing is at the place of a folder the last sync
//! found missing, and the owner's Documents folder is the one the last sync
//! used ([`Watch::walking`], crate::grants::in_place): with all of these as
//! they were, the walk only caps the files linked in and adds inherited
//! entries, so what the command sees is as good as the last sync's answer;
//! a folder that moved since, or Documents moved into a granted folder, is
//! something the sync in its turn reacts to, and the command waits for it.
//!
//! A watch is of the object the record names at the folder's path, not of
//! the path: the handle goes along with a folder renamed away, so one made
//! again at the path is watched anew ([`Folder`]).
//!
//! The handle on a granted folder has a cost NTFS sets: while it is open,
//! the folders above the granted folder cannot be renamed or moved, only
//! the granted folder itself and what is in it (docs/dev/windows.md says
//! so). A volume's change journal would not hold a handle on a folder, but
//! reading it takes an administrator's volume handle and sees every change
//! of the drive, which is more than a granted folder is worth.
//!
//! On Linux a new file in a granted folder gets its ACL entries from the
//! folder's default entries, and a file with a second name gets none and
//! keeps its own rights (crate::acl), so nothing waits for a walk there.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nerve_policy::paths::within;
use nerve_transport::sync::lock;

use crate::grants::{Rewalk, Synced};

/// How long the names in a granted folder stay as they are before the node
/// walks it: an install or a clone is a burst of new names, walked once.
pub const QUIET: Duration = Duration::from_secs(3);

/// The longest a change waits for its walk while names go on changing.
pub const AT_MOST: Duration = Duration::from_secs(30);

/// What the node asks Windows to tell (`FILE_NOTIFY_CHANGE_FILE_NAME`,
/// `FILE_NOTIFY_CHANGE_DIR_NAME`): names of files and folders, nothing of
/// their contents, times or security.
pub const NOTIFY: u32 = 0x1 | 0x2;

/// A name added (`FILE_ACTION_ADDED`), and the new name of a rename
/// (`FILE_ACTION_RENAMED_NEW_NAME`): what may carry another folder's list.
const ADDED: u32 = 1;
const RENAMED_NEW_NAME: u32 = 5;

/// Whether a buffer of directory change records (`FILE_NOTIFY_INFORMATION`:
/// the offset of the next one, the action, the name's length, the name), as
/// one notification fills it, asks for a walk: a name added or renamed to.
/// An empty buffer is one the system could not fill (it ran over), and one
/// cut short counts too: either may hide a new name.
pub fn wakes(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return true;
    }
    let word = |at: usize| -> Option<u32> {
        let b = buf.get(at..at + 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let mut at = 0usize;
    loop {
        let (Some(next), Some(action)) = (word(at), word(at + 4)) else {
            return true;
        };
        if action == ADDED || action == RENAMED_NEW_NAME {
            return true;
        }
        if next == 0 {
            return false;
        }
        at += next as usize;
    }
}

/// The granted folders whose names changed and that are not walked yet, and
/// where the supervisor's grant syncs stand.
#[derive(Debug, Default)]
pub struct Pending {
    folders: Vec<Changed>,
    /// When the grant sync the supervisor started began, while it runs.
    running: Option<Instant>,
    /// Whether that sync is a walk of the watch: folders where names
    /// changed, or the start walk.
    watch_walk: bool,
    /// The first sync is done and the start walk of every grant is still to
    /// come: the next sync is it.
    start_walk: bool,
    /// Whether the sync that runs leaves a pause when it ends: every walk
    /// of the watch but the start walk.
    pause: bool,
    /// No walk of the watch before this: the pause after a walk.
    not_before: Option<Instant>,
    /// The config version the last finished sync saw, and what it left.
    last: Option<(u64, Synced)>,
}

#[derive(Debug)]
struct Changed {
    path: PathBuf,
    first: Instant,
    last: Instant,
}

impl Pending {
    /// Names changed in `folder` at `now`.
    pub fn changed(&mut self, folder: &Path, now: Instant) {
        match self.folders.iter_mut().find(|c| c.path == folder) {
            Some(c) => c.last = now,
            None => self.folders.push(Changed {
                path: folder.to_path_buf(),
                first: now,
                last: now,
            }),
        }
    }

    /// The folders to walk at `now`, which are pending no more: each one
    /// whose names were quiet for [`QUIET`], or that waits [`AT_MOST`],
    /// none in the pause after a walk ([`Pending::end`]). A
    /// folder inside one of them goes along, due or not, as its walk goes
    /// through it; of the folders due, only the outermost are named.
    pub fn due(&mut self, now: Instant) -> Vec<PathBuf> {
        if self.not_before.is_some_and(|t| now < t) {
            return Vec::new();
        }
        let ready = |c: &Changed| {
            now.saturating_duration_since(c.last) >= QUIET
                || now.saturating_duration_since(c.first) >= AT_MOST
        };
        let walked: Vec<PathBuf> = self
            .folders
            .iter()
            .filter(|c| ready(c))
            .map(|c| c.path.clone())
            .collect();
        let mut out: Vec<PathBuf> = walked
            .iter()
            .filter(|p| !walked.iter().any(|o| o != *p && within(p, o)))
            .cloned()
            .collect();
        out.sort();
        out.dedup();
        self.folders
            .retain(|c| !out.iter().any(|o| within(&c.path, o)));
        out
    }

    /// A grant sync of the supervisor begins at `now`; `by_watch` when it
    /// is a walk of the watch, `pause` when it leaves a pause.
    fn begin(&mut self, now: Instant, by_watch: bool, pause: bool) {
        self.running = Some(now);
        self.watch_walk = by_watch;
        self.pause = by_watch && pause;
    }

    /// The sync ended at `now`. After a walk of the watch the next one
    /// waits as long as the walk took, twice over, so the walks hold the
    /// sync's turn for a third of the time at most, however fast names
    /// come. A sync of a new config is no walk and leaves no pause: the
    /// names that changed meanwhile are walked as soon as they are quiet.
    /// The start walk leaves none either: no name made it, it goes through
    /// every grant and so is the longest walk there is, and a pause as long
    /// as that would hold back the first changes after every start.
    fn end(&mut self, now: Instant) {
        if let Some(began) = self.running.take()
            && self.pause
        {
            self.not_before = Some(now + now.saturating_duration_since(began) * 2);
        }
        self.watch_walk = false;
        self.pause = false;
    }
}

/// A grant sync of the supervisor that runs: it ends when this is dropped,
/// also when the sync panicked.
pub struct Began(Arc<Mutex<Pending>>);

impl Drop for Began {
    fn drop(&mut self) {
        lock(&self.0).end(Instant::now());
    }
}

/// The watches of the granted folders, and what they found changed.
#[derive(Default)]
pub struct Watch {
    pending: Arc<Mutex<Pending>>,
    #[cfg(windows)]
    win: Mutex<win::Watches>,
}

impl Watch {
    /// The granted folders to walk now ([`Pending::due`]).
    #[cfg(test)]
    pub fn due(&self, now: Instant) -> Vec<PathBuf> {
        lock(&self.pending).due(now)
    }

    /// Names changed in `folder` at `now`.
    #[cfg(all(test, unix))]
    pub fn changed(&self, folder: &Path, now: Instant) {
        lock(&self.pending).changed(folder, now);
    }

    /// The grant sync the supervisor starts at `now`, if any, and the
    /// guard that holds the place until it ends: none while one runs (the
    /// changes meanwhile join the next walk). `granted`: the config
    /// version it last synced, none before the first. The first is a plain
    /// sync, so a command finds its answer at once, and the walk of every
    /// grant follows it (as on Linux, so what was installed or moved into a
    /// granted folder while the node did not run gets its entries); then
    /// one for folders that changed walks those (and follows the config as
    /// it is), and one for a new config walks only what changes.
    pub fn next_sync(
        &self,
        granted: Option<u64>,
        version: u64,
        now: Instant,
    ) -> Option<(Rewalk, Began)> {
        let mut p = lock(&self.pending);
        if p.running.is_some() {
            return None;
        }
        let mut pause = true;
        let walk = if granted.is_none() {
            p.start_walk = true;
            Rewalk::None
        } else if p.start_walk {
            // It goes through every folder, the changed ones too.
            p.start_walk = false;
            p.folders.clear();
            pause = false;
            Rewalk::Every
        } else {
            let due = p.due(now);
            if !due.is_empty() {
                Rewalk::At(due)
            } else if granted != Some(version) {
                Rewalk::None
            } else {
                return None;
            }
        };
        p.begin(now, walk != Rewalk::None, pause);
        Some((walk, Began(self.pending.clone())))
    }

    /// A grant sync finished that saw the config of `version`.
    pub fn finished(&self, version: u64, synced: &Synced) {
        lock(&self.pending).last = Some((version, synced.kept()));
    }

    /// What the last sync left, for a command that would wait for the turn
    /// while a walk of the watch holds it: only when the config is the one
    /// that sync saw. A changed config waits for the walk like any other
    /// sync. What moved on the disk since, and the owner's Documents folder,
    /// are not told here: the caller looks at them itself
    /// (crate::grants::in_place); with those as they were, the walk only
    /// caps files linked in and adds inherited entries, and a name made
    /// meanwhile is as unwalked as one made before it.
    pub fn walking(&self, version: u64) -> Option<Synced> {
        let p = lock(&self.pending);
        match &p.last {
            Some((v, synced)) if p.watch_walk && *v == version => Some(synced.kept()),
            _ => None,
        }
    }

    /// Watches `folders` from now on, and no other: a new one is looked at
    /// and opened as `act` acts (the owner, whose folders they are, on the
    /// installed service), one no longer granted is closed. `folders` is asked once
    /// the watches are held, so of two syncs that follow, the last to hold
    /// them follows the newest record. A watch on an object the record no
    /// longer names at its path is closed and opened again there. A folder that could not be started
    /// twice is not tried again while it stays granted; the log says why.
    #[cfg(windows)]
    pub fn follow<G>(
        &self,
        folders: impl FnOnce() -> Vec<Folder>,
        act: impl FnOnce() -> std::io::Result<G>,
    ) {
        let mut win = lock(&self.win);
        let folders = folders();
        win.follow(&folders, &self.pending, act);
    }
}

/// A granted folder to watch: its path, and the objects the record names
/// there (one, unless grants of two containers disagree; none where the
/// volume names no object).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folder {
    pub path: PathBuf,
    pub ids: Vec<String>,
}

#[cfg(any(windows, test))]
impl Folder {
    /// Whether a watch on the object `id` (`None`: the system named none)
    /// is the folder's: the record names no object, or names that one.
    fn holds(&self, id: Option<&str>) -> bool {
        self.ids.is_empty() || id.is_none_or(|i| self.ids.iter().any(|x| x == i))
    }
}

/// A watch held: the folder, and the object its handle is on.
#[cfg(any(windows, test))]
type Held = (PathBuf, Option<String>);

/// What a follow changes about the watches held for the folders granted
/// now: the watches to close (the folder is not granted any more, or the
/// handle is on another object than the record names at that path), and
/// the folders to open (not held, and not in `left`). A granted folder
/// renamed away and made again at its path keeps its handle on the object
/// that moved, so a watch by path alone would go on telling the old folder's
/// names and none of the new one's.
#[cfg(any(windows, test))]
fn reconcile<'a>(
    held: &[Held],
    folders: &'a [Folder],
    left: impl Fn(&Path) -> bool,
) -> (Vec<PathBuf>, Vec<&'a Folder>) {
    let right = |(path, id): &Held| {
        folders
            .iter()
            .any(|f| f.path == *path && f.holds(id.as_deref()))
    };
    let close = held
        .iter()
        .filter(|h| !right(h))
        .map(|h| h.0.clone())
        .collect();
    let open = folders
        .iter()
        .filter(|f| !held.iter().any(|h| h.0 == f.path && right(h)) && !left(&f.path))
        .collect();
    (close, open)
}

/// What is at the path of a granted place, as [`at`] finds it.
#[cfg(any(windows, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum At {
    Nothing,
    /// A plain file: a granted file, a split home's too.
    File,
    /// A folder, a link or junction, or what could not be looked at: opened,
    /// and where it is no folder of its own the open says why.
    Other,
}

/// What is at `path`, as whoever this thread acts as sees it.
#[cfg(any(windows, test))]
fn at(path: &Path) -> At {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_file() => At::File,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => At::Nothing,
        _ => At::Other,
    }
}

/// The places of `new` to open, looked at (`look`, [`at`]) while `act`
/// acts, which goes on while its result lives: on the installed service the
/// owner, whose profile the node's own account may not look into (it would
/// find nothing there). A place with nothing there is left for the next
/// follow; a plain file is no folder to watch and goes into `files`, which
/// the caller does not look at again while the record names it so. Where
/// `act` fails, the looks run as the node, and the log says why.
#[cfg(any(windows, test))]
fn to_open<'a, G>(
    new: Vec<&'a Folder>,
    files: &mut Vec<Folder>,
    act: impl FnOnce() -> std::io::Result<G>,
    look: impl Fn(&Path) -> At,
) -> (Option<G>, Vec<&'a Folder>) {
    let acting = act()
        .inspect_err(|e| tracing::warn!("folder grants: {e}"))
        .ok();
    let mut open = Vec::new();
    for f in new {
        match look(&f.path) {
            At::Nothing => {}
            At::File => files.push(f.clone()),
            At::Other => open.push(f),
        }
    }
    (acting, open)
}

/// How many times in a row a folder's watch may fail to start before it is
/// left alone while the folder stays granted: a start that fails once may
/// be a folder busy or just made, one that fails again will not work, and
/// every sync would otherwise open the folder as the owner and log it again.
#[cfg(any(windows, test))]
const START_TRIES: u32 = 2;

/// The folders whose watch failed to start, and how often in a row.
#[cfg(any(windows, test))]
#[derive(Debug, Default)]
struct Starts(std::collections::HashMap<PathBuf, u32>);

#[cfg(any(windows, test))]
impl Starts {
    /// The watch of `folder` ended; `started`: it had run (a folder that
    /// went, or a read that failed later). Whether to leave the folder
    /// alone from now on.
    fn ended(&mut self, folder: &Path, started: bool) -> bool {
        if started {
            self.0.remove(folder);
            return false;
        }
        let n = self.0.entry(folder.to_path_buf()).or_insert(0);
        *n += 1;
        *n >= START_TRIES
    }

    /// Forgets the folders that are not granted any more.
    fn keep(&mut self, folders: &[PathBuf]) {
        self.0.retain(|f, _| folders.contains(f));
    }
}

#[cfg(windows)]
mod win {
    //! One thread waits on one completion port for the changes of every
    //! watched folder: each folder's handle reads its changes (overlapped,
    //! `ReadDirectoryChangesW` over the folder and everything below it)
    //! into a buffer of its own, which the thread hands back to the system
    //! after each notification.

    use std::collections::{HashMap, HashSet};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::path::{Path, PathBuf};
    use std::sync::mpsc::{Receiver, Sender, channel};
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use windows_sys::Win32::Foundation::{FALSE, HANDLE, INVALID_HANDLE_VALUE, TRUE};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_FLAG_OVERLAPPED, FILE_LIST_DIRECTORY, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, GetDriveTypeW, GetFileInformationByHandle, GetVolumePathNameW,
        OPEN_EXISTING, ReadDirectoryChangesW,
    };
    use windows_sys::Win32::System::IO::{
        CancelIoEx, CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED,
        PostQueuedCompletionStatus,
    };
    use windows_sys::Win32::System::Threading::INFINITE;
    use windows_sys::Win32::System::WindowsProgramming::{DRIVE_REMOTE, DRIVE_REMOVABLE};

    use super::{Folder, Held, NOTIFY, Pending, Starts, at, lock, reconcile, to_open, wakes};

    /// The size of each folder's buffer: the most one notification over the
    /// network may carry; a burst beyond it runs over, which walks the
    /// folder all the same.
    const BUF: usize = 64 * 1024;
    /// The completion key of a message to the thread.
    const WAKE: usize = 0;

    enum Msg {
        Open(PathBuf, OwnedHandle),
        Close(PathBuf),
        Stop,
    }

    /// The completion port and its thread, started with the first folder.
    #[derive(Default)]
    pub struct Watches {
        running: Option<Running>,
        /// The folders watched now, and the object each handle is on.
        watched: Vec<Held>,
        /// The folders that could not be opened, or not started twice in a
        /// row, and are not tried again while they stay granted.
        failed: HashSet<PathBuf>,
        /// How often each folder's watch failed to start in a row.
        starts: Starts,
        /// The granted places that are plain files, with the objects the
        /// record names there: not watched, and not looked at again while
        /// the record names them so ([`to_open`]).
        files: Vec<Folder>,
        /// The folders whose watch ended (gone, or an error), and whether
        /// it had started: watched again at the next follow where they are
        /// still granted.
        ended: Arc<Mutex<Vec<Ended>>>,
    }

    /// A watch that ended: its folder, and whether it had started.
    type Ended = (PathBuf, bool);

    struct Running {
        port: OwnedHandle,
        tx: Sender<Msg>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Running {
        fn send(&self, m: Msg) {
            if self.tx.send(m).is_ok() {
                // SAFETY: the port lives while `self` does.
                unsafe {
                    PostQueuedCompletionStatus(self.port.as_raw_handle(), 0, WAKE, std::ptr::null())
                };
            }
        }
    }

    impl Drop for Running {
        fn drop(&mut self) {
            self.send(Msg::Stop);
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    impl Watches {
        pub fn follow<G>(
            &mut self,
            folders: &[Folder],
            pending: &Arc<Mutex<Pending>>,
            act: impl FnOnce() -> std::io::Result<G>,
        ) {
            // A thread that ended (its port failed) is started again.
            if self
                .running
                .as_ref()
                .and_then(|r| r.thread.as_ref())
                .is_some_and(|t| t.is_finished())
            {
                self.running = None;
            }
            let ended: Vec<Ended> = std::mem::take(&mut *lock(&self.ended));
            for (folder, started) in &ended {
                self.watched.retain(|(w, _)| w != folder);
                if self.starts.ended(folder, *started) {
                    tracing::warn!(
                        "folder grants: {} could not be watched twice and is left alone; what is installed or moved into it gets its entries at the next start, change or Sync folders",
                        folder.display()
                    );
                    self.failed.insert(folder.clone());
                }
            }
            let paths: Vec<PathBuf> = folders.iter().map(|f| f.path.clone()).collect();
            self.starts.keep(&paths);
            self.failed.retain(|f| paths.contains(f));
            self.files.retain(|f| folders.contains(f));
            let (gone, new) = reconcile(&self.watched, folders, |f| {
                self.failed.contains(f) || self.files.iter().any(|x| x.path == f)
            });
            self.watched.retain(|(w, _)| !gone.contains(w));
            if let Some(r) = &self.running {
                for g in gone {
                    r.send(Msg::Close(g));
                }
            }
            if new.is_empty() {
                return;
            }
            // Looked at and opened as the owner, whose folders they are;
            // the handle keeps what it was opened with.
            let (_as, new) = to_open(new, &mut self.files, act, at);
            if new.is_empty() {
                return;
            }
            if self.running.is_none() {
                match start(pending.clone(), self.ended.clone()) {
                    Ok(r) => self.running = Some(r),
                    Err(e) => {
                        tracing::warn!(
                            "folder grants: the granted folders are not watched ({e}); what is installed or moved into one gets its entries at the next start, change or Sync folders"
                        );
                        self.failed.extend(new.into_iter().map(|f| f.path.clone()));
                        return;
                    }
                }
            }
            for f in new {
                match open(&f.path) {
                    Ok((h, id)) => {
                        self.watched.push((f.path.clone(), id));
                        if let Some(r) = &self.running {
                            r.send(Msg::Open(f.path.clone(), h));
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "folder grants: {} is not watched ({e}); what is installed or moved into it gets its entries at the next start, change or Sync folders",
                            f.path.display()
                        );
                        self.failed.insert(f.path.clone());
                    }
                }
            }
        }
    }

    fn wide(p: &Path) -> Vec<u16> {
        p.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    /// The folder `path` opened to read its changes: not through a link
    /// (a granted folder is one of its own), not one on another machine,
    /// and not one on a removable drive; and the object it is on, as the
    /// record names it ([`Folder::ids`]), when the system names one.
    fn open(path: &Path) -> std::io::Result<(OwnedHandle, Option<String>)> {
        use std::io::{Error, ErrorKind};
        if let Some(link) = nerve_policy::paths::remote_link(path) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("{} leads to another machine", link.display()),
            ));
        }
        let mut root = vec![0u16; 1024];
        // SAFETY: a NUL-terminated path and a buffer of the length given.
        if unsafe { GetVolumePathNameW(wide(path).as_ptr(), root.as_mut_ptr(), root.len() as u32) }
            == FALSE
        {
            return Err(Error::last_os_error());
        }
        // SAFETY: the NUL-terminated root the call above wrote.
        match unsafe { GetDriveTypeW(root.as_ptr()) } {
            DRIVE_REMOVABLE => {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "it is on a removable drive, which a watch would keep from being ejected",
                ));
            }
            DRIVE_REMOTE => {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "it is on another machine",
                ));
            }
            _ => {}
        }
        // SAFETY: a NUL-terminated path; the handle is owned at once.
        let h = unsafe {
            CreateFileW(
                wide(path).as_ptr(),
                FILE_LIST_DIRECTORY,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OVERLAPPED,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(Error::last_os_error());
        }
        // SAFETY: a valid handle this function owns.
        let h = unsafe { OwnedHandle::from_raw_handle(h) };
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: a valid handle and a struct of the right size.
        if unsafe { GetFileInformationByHandle(h.as_raw_handle(), &mut info) } == FALSE {
            return Err(Error::last_os_error());
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "it is not a folder of its own",
            ));
        }
        let id = nerve_sandbox::appcontainer::handle_id(&h)
            .ok()
            .map(|id| id.to_string());
        Ok((h, id))
    }

    fn start(
        pending: Arc<Mutex<Pending>>,
        ended: Arc<Mutex<Vec<Ended>>>,
    ) -> std::io::Result<Running> {
        // SAFETY: a new port, owned at once.
        let port =
            unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, std::ptr::null_mut(), 0, 1) };
        if port.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the port the call above made.
        let port = unsafe { OwnedHandle::from_raw_handle(port) };
        let (tx, rx) = channel();
        let raw = port.as_raw_handle() as usize;
        let thread = std::thread::Builder::new()
            .name("grant-watch".into())
            .stack_size(256 * 1024)
            .spawn(move || run(raw as HANDLE, rx, &pending, &ended))?;
        Ok(Running {
            port,
            tx,
            thread: Some(thread),
        })
    }

    /// One watched folder: its handle, and the buffer and the overlapped
    /// structure of the read in flight, which stay where they are until it
    /// completes.
    struct Slot {
        path: PathBuf,
        dir: OwnedHandle,
        ov: Box<OVERLAPPED>,
        buf: Box<[u32]>,
        closing: bool,
    }

    impl Slot {
        /// Hands the buffer to the system for the next changes.
        fn arm(&mut self) -> std::io::Result<()> {
            *self.ov = OVERLAPPED::default();
            // SAFETY: the buffer and the overlapped structure are boxed and
            // live in the slot until the read completes ([`run`]).
            let ok = unsafe {
                ReadDirectoryChangesW(
                    self.dir.as_raw_handle(),
                    self.buf.as_mut_ptr().cast(),
                    (self.buf.len() * 4) as u32,
                    TRUE,
                    NOTIFY,
                    std::ptr::null_mut(),
                    &mut *self.ov,
                    None,
                )
            };
            if ok == FALSE {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        }
    }

    fn run(port: HANDLE, rx: Receiver<Msg>, pending: &Mutex<Pending>, ended: &Mutex<Vec<Ended>>) {
        let mut slots: HashMap<usize, Slot> = HashMap::new();
        let mut next = WAKE + 1;
        let mut stopping = false;
        let end = |slot: &Slot| {
            lock(pending).changed(&slot.path, Instant::now());
            lock(ended).push((slot.path.clone(), true));
        };
        loop {
            let (mut n, mut key, mut ov) = (0u32, 0usize, std::ptr::null_mut());
            // SAFETY: the port lives until this thread is joined.
            let ok =
                unsafe { GetQueuedCompletionStatus(port, &mut n, &mut key, &mut ov, INFINITE) };
            if ok == FALSE && ov.is_null() {
                // The port itself failed: nothing more comes. The reads in
                // flight may still write their buffers, which stay.
                tracing::warn!(
                    "folder grants: the watch of the granted folders ended ({})",
                    std::io::Error::last_os_error()
                );
                for slot in slots.values() {
                    lock(ended).push((slot.path.clone(), true));
                }
                std::mem::forget(slots);
                return;
            }
            if key == WAKE {
                while let Ok(m) = rx.try_recv() {
                    match m {
                        Msg::Open(path, dir) => {
                            let k = next;
                            next += 1;
                            let mut slot = Slot {
                                path,
                                dir,
                                ov: Box::default(),
                                buf: vec![0u32; BUF / 4].into_boxed_slice(),
                                closing: false,
                            };
                            // SAFETY: a valid handle and the port.
                            let started = if unsafe {
                                CreateIoCompletionPort(slot.dir.as_raw_handle(), port, k, 0)
                            }
                            .is_null()
                            {
                                Err(std::io::Error::last_os_error())
                            } else {
                                slot.arm()
                            };
                            match started {
                                Ok(()) => {
                                    slots.insert(k, slot);
                                }
                                Err(e) => {
                                    // Watched again at the next follow, as
                                    // after a failed read, until it failed
                                    // to start twice; no walk is asked for,
                                    // which would only fail again.
                                    tracing::warn!(
                                        "folder grants: {} is not watched ({e})",
                                        slot.path.display()
                                    );
                                    lock(ended).push((slot.path.clone(), false));
                                }
                            }
                        }
                        Msg::Close(path) => {
                            for s in slots.values_mut().filter(|s| s.path == path && !s.closing) {
                                // SAFETY: the read in flight on this handle.
                                unsafe { CancelIoEx(s.dir.as_raw_handle(), &*s.ov) };
                                s.closing = true;
                            }
                        }
                        Msg::Stop => {
                            stopping = true;
                            for s in slots.values_mut().filter(|s| !s.closing) {
                                // SAFETY: as above.
                                unsafe { CancelIoEx(s.dir.as_raw_handle(), &*s.ov) };
                                s.closing = true;
                            }
                        }
                    }
                }
                if stopping && slots.is_empty() {
                    return;
                }
                continue;
            }
            // The read of the slot `key` completed: its buffer is free now.
            let Some(slot) = slots.get_mut(&key) else {
                continue;
            };
            if slot.closing {
                slots.remove(&key);
                if stopping && slots.is_empty() {
                    return;
                }
                continue;
            }
            if ok == FALSE {
                // The folder went, or cannot be read any more: its walk
                // finds what is there, and the next sync watches it again
                // where it is still granted.
                end(slot);
                slots.remove(&key);
                continue;
            }
            // SAFETY: the system wrote `n` bytes of the slot's buffer.
            let got =
                unsafe { std::slice::from_raw_parts(slot.buf.as_ptr().cast::<u8>(), n as usize) };
            if wakes(got) {
                lock(pending).changed(&slot.path, Instant::now());
            }
            if slot.arm().is_err() {
                end(slot);
                slots.remove(&key);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::windows::fs::OpenOptionsExt;

        /// A watch that cannot start (here the handle is a file's, which
        /// cannot be read for changes) ends at once and says it never
        /// started, so the next follow opens the folder again, and gives it
        /// up after the second time ([`Starts`]).
        #[test]
        fn a_watch_that_cannot_start_is_tried_again() {
            let d = tempfile::tempdir().unwrap();
            let file = d.path().join("f.txt");
            std::fs::write(&file, "f").unwrap();
            let pending = Arc::new(Mutex::new(Pending::default()));
            let ended = Arc::new(Mutex::new(Vec::new()));
            let running = start(pending.clone(), ended.clone()).unwrap();
            let handle = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(FILE_FLAG_OVERLAPPED)
                .open(&file)
                .unwrap();
            running.send(Msg::Open(file.clone(), OwnedHandle::from(handle)));
            let mut told = false;
            for _ in 0..50 {
                std::thread::sleep(std::time::Duration::from_millis(100));
                if *lock(&ended) == [(file.clone(), false)] {
                    told = true;
                    break;
                }
            }
            assert!(told, "the failed start is told");
            assert!(
                lock(&pending)
                    .due(Instant::now() + super::super::AT_MOST)
                    .is_empty()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record of a directory change: the offset of the next one, the
    /// action, the length of the name and the name (UTF-16).
    fn record(action: u32, name: &str, last: bool) -> Vec<u8> {
        let name: Vec<u8> = name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let len = (12 + name.len()).next_multiple_of(4);
        let next = if last { 0 } else { len as u32 };
        let mut r = Vec::new();
        r.extend(next.to_le_bytes());
        r.extend(action.to_le_bytes());
        r.extend((name.len() as u32).to_le_bytes());
        r.extend(name);
        r.resize(len, 0);
        r
    }

    /// A name added, or renamed to, wakes the walk; a name removed or
    /// renamed from does not. A notification the system could not fill (it
    /// ran over) or one cut short wakes it as well.
    #[test]
    fn new_names_and_lost_ones_wake_the_walk() {
        const REMOVED: u32 = 2;
        const RENAMED_OLD_NAME: u32 = 4;
        let removed = [
            record(REMOVED, "a.js", false),
            record(RENAMED_OLD_NAME, "b", true),
        ]
        .concat();
        assert!(!wakes(&removed));
        for action in [ADDED, RENAMED_NEW_NAME] {
            let one = [
                record(REMOVED, "a.js", false),
                record(action, "x\\y.js", true),
            ]
            .concat();
            assert!(wakes(&one), "{action}");
        }
        assert!(wakes(&[]), "ran over");
        let mut cut = removed.clone();
        let past = cut.len() as u32 + 8;
        cut[..4].copy_from_slice(&past.to_le_bytes());
        assert!(wakes(&cut), "cut short");
    }

    /// The watch asks for names only: the walk changes access lists, which
    /// must not wake it again, and a write into a file is no new name.
    #[test]
    fn the_watch_asks_for_names_only() {
        const SECURITY: u32 = 0x100;
        const ATTRIBUTES: u32 = 0x4;
        const LAST_WRITE: u32 = 0x10;
        assert_eq!(NOTIFY, 0x1 | 0x2);
        assert_eq!(NOTIFY & (SECURITY | ATTRIBUTES | LAST_WRITE), 0);
        #[cfg(windows)]
        {
            use windows_sys::Win32::Storage::FileSystem as fs;
            assert_eq!(
                NOTIFY,
                fs::FILE_NOTIFY_CHANGE_FILE_NAME | fs::FILE_NOTIFY_CHANGE_DIR_NAME
            );
            assert_eq!(
                (ADDED, RENAMED_NEW_NAME),
                (fs::FILE_ACTION_ADDED, fs::FILE_ACTION_RENAMED_NEW_NAME)
            );
        }
    }

    /// A burst of changes is walked once, [`QUIET`] after its last change;
    /// a folder whose names go on changing is walked [`AT_MOST`] after the
    /// first, and the changes after that wait for the next walk.
    #[test]
    fn a_burst_is_walked_once_after_it_stops() {
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let proj = Path::new("/w/proj");
        let mut p = Pending::default();
        for s in 0..3 {
            p.changed(proj, at(s));
            assert!(p.due(at(s)).is_empty());
        }
        assert!(p.due(at(2) + QUIET - Duration::from_millis(1)).is_empty());
        assert_eq!(p.due(at(2) + QUIET), [proj]);
        assert!(p.due(at(60)).is_empty(), "walked once");
        assert_eq!(p.folders.len(), 0);

        // Changes every second for 70 s: a walk at the bound, then another
        // at the bound after the next change.
        let mut walks = Vec::new();
        for s in 100..170 {
            p.changed(proj, at(s));
            if !p.due(at(s)).is_empty() {
                walks.push(s);
            }
            assert!(p.folders.len() <= 1, "one entry however many changes");
        }
        assert_eq!(
            walks,
            [100 + AT_MOST.as_secs(), 101 + 2 * AT_MOST.as_secs()]
        );
    }

    /// A folder inside another granted folder that changed goes with the
    /// walk of the outer one, which goes through it; one beside it waits
    /// for its own quiet time.
    #[test]
    fn a_walk_takes_the_folders_inside_it_along() {
        let t0 = Instant::now();
        let (outer, inner, beside) = (
            Path::new("/w/proj"),
            Path::new("/w/proj/out"),
            Path::new("/w/other"),
        );
        let mut p = Pending::default();
        p.changed(outer, t0);
        p.changed(inner, t0 + Duration::from_secs(2));
        p.changed(beside, t0 + Duration::from_secs(2));
        assert_eq!(p.due(t0 + QUIET), [outer]);
        assert_eq!(p.due(t0 + QUIET + Duration::from_secs(2)), [beside]);
        assert!(p.due(t0 + AT_MOST).is_empty());
        // Both due: the outer one alone is named.
        p.changed(inner, t0);
        p.changed(outer, t0);
        assert_eq!(p.due(t0 + QUIET), [outer]);
    }

    /// The supervisor's grant syncs: the first is a plain one and the walk
    /// of every grant follows it at once (also past changed folders and the
    /// pause), then one where names changed walks those folders (also with
    /// a new config), one for a new config only what changes, and none
    /// while nothing changed.
    #[test]
    fn the_grant_sync_chooses_its_walk() {
        let proj = PathBuf::from("/w/proj");
        let t0 = Instant::now();
        let later = t0 + AT_MOST;
        let sync =
            |w: &Watch, granted, version, now| w.next_sync(granted, version, now).map(|s| s.0);
        let changed = |w: &Watch| lock(&w.pending).changed(&proj, t0);
        let w = Watch::default();
        changed(&w);
        assert_eq!(sync(&w, None, 1, later), Some(Rewalk::None));
        assert!(
            lock(&w.pending).not_before.is_none(),
            "a plain sync leaves no pause"
        );
        assert_eq!(sync(&w, Some(1), 1, later), Some(Rewalk::Every));
        assert!(
            lock(&w.pending).folders.is_empty(),
            "the start walk takes them"
        );
        assert_eq!(sync(&w, Some(1), 1, later), None, "the start walk is done");
        let w = Watch::default();
        changed(&w);
        assert_eq!(
            sync(&w, Some(1), 1, later),
            Some(Rewalk::At(vec![proj.clone()]))
        );
        let w = Watch::default();
        changed(&w);
        assert_eq!(
            sync(&w, Some(1), 2, later),
            Some(Rewalk::At(vec![proj.clone()]))
        );
        assert_eq!(
            sync(&Watch::default(), Some(1), 2, later),
            Some(Rewalk::None)
        );
        assert_eq!(sync(&Watch::default(), Some(2), 2, later), None);
    }

    /// New names every tick while a walk goes on start no second sync, so
    /// the syncs cannot pile up behind the turn; the changes meanwhile join
    /// the walk after it.
    #[test]
    fn one_grant_sync_runs_at_a_time() {
        let proj = PathBuf::from("/w/proj");
        let t0 = Instant::now();
        let w = Watch::default();
        let mut started = 0;
        let mut held = Vec::new();
        for s in 0..200u64 {
            let now = t0 + Duration::from_secs(s);
            lock(&w.pending).changed(&proj, now);
            if let Some((_, began)) = w.next_sync(Some(1), 1, now) {
                started += 1;
                held.push(began);
            }
        }
        assert_eq!(started, 1, "the sync that runs holds the place");
        // Not even a new config starts one beside it.
        assert!(
            w.next_sync(Some(1), 2, t0 + Duration::from_secs(300))
                .is_none()
        );
        held.clear();
        lock(&w.pending).not_before = None;
        assert!(
            w.next_sync(Some(1), 1, t0 + Duration::from_secs(400))
                .is_some()
        );
    }

    /// After a walk that took 20 s the next one waits 40 s more, however
    /// many names come: the walks hold the turn a third of the time at
    /// most. A sync for a new config does not wait for the pause.
    #[test]
    fn a_walk_is_followed_by_a_pause_twice_its_length() {
        let proj = Path::new("/w/proj");
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let mut p = Pending::default();
        p.begin(at(0), true, true);
        p.changed(proj, at(5));
        p.end(at(20));
        p.changed(proj, at(21));
        assert!(p.due(at(21) + AT_MOST).is_empty(), "paused until 60 s");
        assert!(p.due(at(59)).is_empty());
        assert_eq!(p.due(at(60)), [proj]);
        // A short walk leaves a short pause.
        p.begin(at(100), true, true);
        p.end(at(100));
        p.changed(proj, at(101));
        assert_eq!(p.due(at(101) + QUIET), [proj]);
    }

    /// A command does not wait for a walk the watch started when the config
    /// is the one the last sync saw, and takes that sync's answer; with
    /// another config, with no walk of the watch running, or before any
    /// sync finished, it waits for the turn.
    #[test]
    fn a_command_takes_the_last_answer_during_a_walk_of_the_watch() {
        let t0 = Instant::now();
        let w = Watch::default();
        let closed = crate::grants::Grant {
            container: "c1".into(),
            path: "/w/proj/vault".into(),
            access: nerve_policy::config::Access::NONE,
            id: None,
            unfinished: false,
            toward: Vec::new(),
            closed_at: None,
        };
        let left = Synced {
            unclosed: vec![closed],
            errors: vec!["only the sync's own".into()],
            ..Synced::default()
        };
        assert!(w.walking(1).is_none(), "no sync finished yet");
        w.finished(1, &left);
        lock(&w.pending).changed(Path::new("/w/proj"), t0);
        assert!(w.walking(1).is_none(), "no walk runs");
        let (_, began) = w.next_sync(Some(1), 1, t0 + AT_MOST).unwrap();
        let answer = w.walking(1).expect("a walk of the watch runs");
        assert!(answer.refusal("c1").is_some(), "{answer:?}");
        assert!(answer.refusal("c2").is_none());
        assert!(answer.errors.is_empty());
        assert!(w.walking(2).is_none(), "a new config waits for the turn");
        drop(began);
        assert!(w.walking(1).is_none(), "the walk is over");
        // A sync that is not a walk of the watch is waited for.
        let (_, config) = w
            .next_sync(Some(1), 3, t0 + Duration::from_secs(900))
            .unwrap();
        assert!(w.walking(1).is_none());
        drop(config);
    }

    /// After the node's start the commands take the first (plain) sync's
    /// answer while the walk of every grant runs, as they do during any
    /// walk of the watch; they wait only for the first sync itself.
    #[test]
    fn a_command_does_not_wait_for_the_start_walk() {
        let t0 = Instant::now();
        let w = Watch::default();
        let (first, began) = w.next_sync(None, 1, t0).unwrap();
        assert_eq!(first, Rewalk::None);
        assert!(w.walking(1).is_none(), "the first sync is waited for");
        w.finished(1, &Synced::default());
        drop(began);
        let (walk, began) = w.next_sync(Some(1), 1, t0).unwrap();
        assert_eq!(walk, Rewalk::Every);
        assert!(w.walking(1).is_some(), "the start walk is not waited for");
        drop(began);
        assert!(w.walking(1).is_none());
    }

    /// The start walk goes through every grant, so it is the longest walk
    /// the node makes; the pause that follows walks would hold back the
    /// first changes after each start for as long again. It is a walk of
    /// the watch (commands do not wait) and leaves no pause.
    #[test]
    fn the_start_walk_leaves_no_pause() {
        let proj = Path::new("/w/proj");
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let w = Watch::default();
        let (_, first) = w.next_sync(None, 1, t0).unwrap();
        drop(first);
        let (walk, began) = w.next_sync(Some(1), 1, t0).unwrap();
        assert_eq!(walk, Rewalk::Every);
        assert!(lock(&w.pending).watch_walk, "commands do not wait for it");
        assert!(!lock(&w.pending).pause, "the start walk leaves no pause");
        drop(began);
        // A walk for changed names does.
        lock(&w.pending).changed(proj, t0);
        let (walk, _began) = w.next_sync(Some(1), 1, at(60)).unwrap();
        assert_eq!(walk, Rewalk::At(vec![proj.to_path_buf()]));
        assert!(lock(&w.pending).pause);
        // Whatever the walk took, its end leaves nothing.
        let mut p = Pending::default();
        p.begin(at(0), true, false);
        p.changed(proj, at(301));
        p.end(at(300));
        assert_eq!(p.due(at(301) + QUIET), [proj]);
    }

    /// Only a walk leaves the pause: a sync for a new config, which walks
    /// nothing, does not hold back the walk of names that changed
    /// meanwhile.
    #[test]
    fn a_sync_that_walks_nothing_leaves_no_pause() {
        let proj = Path::new("/w/proj");
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let mut p = Pending::default();
        p.begin(at(0), false, true);
        p.changed(proj, at(5));
        p.end(at(60));
        assert_eq!(p.due(at(60) + QUIET), [proj]);
    }

    /// On the installed service the node's own account may not look into
    /// the owner's profile, so the granted places are looked at as the
    /// owner (`act`), before any is opened: a folder (or a link, which the
    /// open says why it does not watch) is opened, a plain file is
    /// remembered and not watched, and a place with nothing there is left
    /// for the next follow.
    #[cfg(unix)]
    #[test]
    fn the_granted_places_are_looked_at_as_the_owner() {
        let d = tempfile::tempdir().unwrap();
        let (proj, notes) = (d.path().join("proj"), d.path().join("notes.txt"));
        std::fs::create_dir(&proj).unwrap();
        std::fs::write(&notes, "n").unwrap();
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&proj, &link).unwrap();
        let place = |path: &Path| Folder {
            path: path.to_path_buf(),
            ids: vec!["v:1".into()],
        };
        let places = [
            place(&proj),
            place(&notes),
            place(&d.path().join("gone")),
            place(&link),
        ];
        let acting = std::cell::Cell::new(false);
        let mut files = Vec::new();
        let (held, open) = to_open(
            places.iter().collect(),
            &mut files,
            || {
                acting.set(true);
                Ok(())
            },
            |p| {
                assert!(acting.get(), "{} is looked at as the node", p.display());
                at(p)
            },
        );
        assert!(held.is_some());
        assert_eq!(open, [&places[0], &places[3]]);
        assert_eq!(files, [places[1].clone()]);
    }

    /// A watch is of the object the record names at the folder's path, not
    /// of the path: a folder renamed away and another made at its path (a
    /// fresh clone) is watched again, and one no longer granted is closed.
    #[test]
    fn a_watch_on_another_object_is_closed_and_opened_again() {
        let folder = |p: &str, ids: &[&str]| Folder {
            path: p.into(),
            ids: ids.iter().map(|i| i.to_string()).collect(),
        };
        let held = |p: &str, id: Option<&str>| -> Held { (p.into(), id.map(str::to_string)) };
        let never = |_: &Path| false;
        let proj = [folder("/w/proj", &["a"])];
        let (close, open) = reconcile(&[held("/w/proj", Some("a"))], &proj, never);
        assert!(close.is_empty() && open.is_empty(), "the same object");
        // Another folder at the path now: closed, and opened again.
        let (close, open) = reconcile(&[held("/w/proj", Some("old"))], &proj, never);
        assert_eq!(close, [PathBuf::from("/w/proj")]);
        assert_eq!(open, [&proj[0]]);
        // The record names no object, or the system named none: the path
        // counts.
        let unnamed = [folder("/w/proj", &[])];
        let (close, open) = reconcile(&[held("/w/proj", Some("old"))], &unnamed, never);
        assert!(close.is_empty() && open.is_empty());
        let (close, open) = reconcile(&[held("/w/proj", None)], &proj, never);
        assert!(close.is_empty() && open.is_empty());
        // Grants of two containers that disagree: either object is right.
        let two = [folder("/w/proj", &["a", "b"])];
        let (close, _) = reconcile(&[held("/w/proj", Some("b"))], &two, never);
        assert!(close.is_empty());
        // No longer granted: closed; a new one opens unless left alone.
        let (close, open) = reconcile(&[held("/w/gone", Some("a"))], &proj, never);
        assert_eq!(close, [PathBuf::from("/w/gone")]);
        assert_eq!(open, [&proj[0]]);
        let (_, open) = reconcile(&[], &proj, |p| p == Path::new("/w/proj"));
        assert!(open.is_empty(), "a folder left alone is not opened");
    }

    /// A folder whose watch could not be started twice in a row is left
    /// alone (it was opened as the owner and logged at every sync); one
    /// that ran before it ended starts afresh.
    #[test]
    fn a_watch_that_cannot_start_twice_is_left_alone() {
        let f = Path::new("/w/proj");
        let mut s = Starts::default();
        assert!(!s.ended(f, false), "once may be a fluke");
        assert!(s.ended(f, false), "twice will not work");
        let mut s = Starts::default();
        assert!(!s.ended(f, false));
        assert!(!s.ended(f, true), "it ran: the count starts again");
        assert!(!s.ended(f, false));
        s.keep(&[]);
        assert!(!s.ended(f, false), "no longer granted: forgotten");
    }

    /// On Windows: the folders to follow are asked for once the watches are
    /// held, so of two syncs that follow, the one that holds them last
    /// follows the newest record.
    #[cfg(windows)]
    #[test]
    fn the_folders_are_asked_for_under_the_watches_lock() {
        let w = Watch::default();
        let mut asked = false;
        w.follow(
            || {
                asked = true;
                assert!(w.win.try_lock().is_err(), "asked before the lock");
                Vec::new()
            },
            || Ok(()),
        );
        assert!(asked);
    }

    /// On Windows: a watched folder tells a new name below it, also a hard
    /// link made there, and not a change of an access list or of a file's
    /// contents; a folder that goes ends its watch, and a folder no longer
    /// granted is closed (it can be removed then).
    #[cfg(windows)]
    #[test]
    fn a_watched_folder_tells_new_names_and_not_security_changes() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("granted");
        let deep = root.join("a").join("b");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("old.txt"), "old").unwrap();
        let store = d.path().join("store.js");
        std::fs::write(&store, "stored").unwrap();
        let w = Watch::default();
        let granted = |p: &Path| {
            vec![Folder {
                path: p.to_path_buf(),
                ids: vec![nerve_sandbox::appcontainer::file_id(p).unwrap().to_string()],
            }]
        };
        w.follow(|| granted(&root), || Ok(()));
        let quiet = |w: &Watch| -> bool {
            std::thread::sleep(Duration::from_millis(500));
            w.due(Instant::now() + AT_MOST).is_empty()
        };
        assert!(quiet(&w));
        // The node's own kind of change: the folder's access list, and a
        // file's contents.
        let icacls = std::process::Command::new("icacls")
            .arg(&deep)
            .args(["/grant", "*S-1-15-2-1:(OI)(CI)(RX)"])
            .output()
            .unwrap();
        assert!(icacls.status.success(), "{icacls:?}");
        std::fs::write(deep.join("old.txt"), "changed").unwrap();
        assert!(quiet(&w), "security and contents wake nothing");
        // A hard link below it.
        std::fs::hard_link(&store, deep.join("linked.js")).unwrap();
        let mut told = false;
        for _ in 0..20 {
            std::thread::sleep(Duration::from_millis(100));
            if w.due(Instant::now() + AT_MOST) == [root.clone()] {
                told = true;
                break;
            }
        }
        assert!(told, "a new name below the folder is told");
        // No longer granted: closed, so the folder can be removed.
        w.follow(Vec::new, || Ok(()));
        std::thread::sleep(Duration::from_millis(200));
        std::fs::remove_dir_all(&root).unwrap();
        assert!(quiet(&w));
    }

    /// On Windows: a granted folder renamed away (the handle goes along
    /// with it) and another made at its path is watched again once the
    /// record names the new object: its names are told, those of the old
    /// folder no more.
    #[cfg(windows)]
    #[test]
    fn a_folder_made_again_at_a_watched_path_is_watched_again() {
        let d = tempfile::tempdir().unwrap();
        let app = d.path().join("app");
        let old = d.path().join("app-old");
        std::fs::create_dir(&app).unwrap();
        let store = d.path().join("store.js");
        std::fs::write(&store, "stored").unwrap();
        let granted = |p: &Path| {
            vec![Folder {
                path: p.to_path_buf(),
                ids: vec![nerve_sandbox::appcontainer::file_id(p).unwrap().to_string()],
            }]
        };
        let told = |w: &Watch| -> bool {
            for _ in 0..20 {
                std::thread::sleep(Duration::from_millis(100));
                if !w.due(Instant::now() + AT_MOST).is_empty() {
                    return true;
                }
            }
            false
        };
        let w = Watch::default();
        w.follow(|| granted(&app), || Ok(()));
        std::fs::rename(&app, &old).unwrap();
        std::fs::create_dir(&app).unwrap();
        // The sync moved the grant: the record names the new folder.
        w.follow(|| granted(&app), || Ok(()));
        // The watch is armed on its own thread, a moment after `follow`: a
        // name made before that is not told, so a new one is made until one
        // is.
        let new_told = (0..10).any(|i| {
            std::fs::hard_link(&store, app.join(format!("linked{i}.js"))).unwrap();
            told(&w)
        });
        assert!(new_told, "a name in the new folder is told");
        std::fs::hard_link(&store, old.join("linked.js")).unwrap();
        assert!(!told(&w), "the old folder is not watched any more");
    }
}
