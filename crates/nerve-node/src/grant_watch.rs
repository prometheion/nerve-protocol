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
//! keeps its own rights (crate::acl); a file or folder moved in keeps the ACL
//! it had, and a copy that keeps its source's mode has a mask that cuts the
//! entries. So the installed Linux node watches its granted folders for what
//! is moved in ([`linux`]: inotify, a watch on each folder in them) and walks
//! them on the same timing ([`Pending`]); a folder too big to watch, or one
//! the system's limit of watches leaves out, is left to the other syncs, and
//! the log says so once.

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

/// How often the Linux watch looks again for a granted folder that was
/// missing ([`Watch::follow_due`]).
#[cfg(target_os = "linux")]
pub const REFOLLOW: Duration = Duration::from_secs(10);

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
    /// The errors of that sync, which [`Synced::kept`] leaves out.
    errors: Vec<String>,
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
    #[cfg(target_os = "linux")]
    linux: Mutex<linux::Watches>,
    /// A granted folder had no watch at the last follow (Linux).
    #[cfg(target_os = "linux")]
    unwatched: std::sync::atomic::AtomicBool,
    /// A granted folder had a watch at the last follow (Linux).
    #[cfg(target_os = "linux")]
    watching: std::sync::atomic::AtomicBool,
    /// The follow the supervisor starts now and then (Linux).
    #[cfg(target_os = "linux")]
    refollow: Arc<Refollow>,
}

/// The follow the supervisor starts now and then: one at a time, and the
/// next only [`REFOLLOW`] after the last began or ended.
#[cfg(target_os = "linux")]
#[derive(Default)]
struct Refollow {
    running: std::sync::atomic::AtomicBool,
    at: Mutex<Option<Instant>>,
}

/// A follow started through [`Watch::follow_due`]; the next may start once it
/// is dropped, and not before [`REFOLLOW`] has passed.
#[cfg(target_os = "linux")]
pub struct Following(Arc<Refollow>);

#[cfg(target_os = "linux")]
impl Drop for Following {
    fn drop(&mut self) {
        *lock(&self.0.at) = Some(Instant::now());
        self.0
            .running
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }
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
            // A new config syncs first and alone: the folders due wait for
            // the next sync, so a command filling a folder cannot hold a
            // folder taken away behind its walk.
            if granted != Some(version) {
                Rewalk::None
            } else {
                let due = p.due(now);
                if due.is_empty() {
                    return None;
                }
                Rewalk::At(due)
            }
        };
        p.begin(now, walk != Rewalk::None, pause);
        Some((walk, Began(self.pending.clone())))
    }

    /// A grant sync finished that saw the config of `version`.
    pub fn finished(&self, version: u64, synced: &Synced) {
        let mut p = lock(&self.pending);
        p.last = Some((version, synced.kept()));
        p.errors.clone_from(&synced.errors);
    }

    /// What the last sync left, its errors too: `status`'s `folder_access`
    /// on Windows, so the app shows a grant that failed or stayed (arch-3).
    /// None before the first sync.
    pub fn last(&self) -> Option<Synced> {
        let p = lock(&self.pending);
        p.last.as_ref().map(|(_, s)| Synced {
            errors: p.errors.clone(),
            ..s.kept()
        })
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

#[cfg(target_os = "linux")]
impl Watch {
    /// Watches the granted folders `folders` gives from now on, and no other:
    /// a folder inside another is watched with it. `folders` is asked once
    /// the watches are held, so of two follows, the last to hold them follows
    /// the newest record. The folders below each are looked at and watched
    /// as `owner` (the owner of the installed node, whose folders they are;
    /// none watches as the node). A folder too big to watch, or one the
    /// system's limit of watches leaves out, is left to the other syncs, and
    /// the log says so once (crate::grant_watch).
    pub fn follow_linux(
        &self,
        folders: impl FnOnce() -> Vec<PathBuf>,
        owner: Option<crate::service::Account>,
    ) {
        let mut linux = lock(&self.linux);
        let folders = folders();
        let unwatched = linux.follow(&folders, owner, &self.pending);
        self.unwatched
            .store(unwatched, std::sync::atomic::Ordering::SeqCst);
        self.watching
            .store(linux.watching(), std::sync::atomic::Ordering::SeqCst);
    }

    /// The follow to start at `now`, when none runs and none began or ended
    /// within [`REFOLLOW`]: one is missing at the last follow (a folder made
    /// later, or a drive mounted later), or one is watched, as a drive mounted
    /// over a watched folder gives no event and only a follow sees it. A
    /// follow that cannot get on (a folder on a share that does not answer)
    /// holds the next back, so they do not pile up.
    pub fn follow_due(&self, now: Instant) -> Option<Following> {
        use std::sync::atomic::Ordering::SeqCst;
        if !self.unwatched.load(SeqCst) && !self.watching.load(SeqCst) {
            return None;
        }
        let mut at = lock(&self.refollow.at);
        if at.is_some_and(|t| now.saturating_duration_since(t) < REFOLLOW) {
            return None;
        }
        if self.refollow.running.swap(true, SeqCst) {
            return None;
        }
        *at = Some(now);
        Some(Following(self.refollow.clone()))
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

#[cfg(target_os = "linux")]
mod linux {
    //! One inotify instance watches every folder in the granted folders: a
    //! watch per folder, as inotify watches one folder and not what is
    //! below it. A thread reads its events. A name made or moved in (a
    //! folder made is watched at once, as it may get something moved in
    //! before) marks its granted folder changed: a file made gets the
    //! folder's default entries, but a copy that keeps the source's mode
    //! (`mv` across file systems, `cp -a`) gets a mask that cuts them, so
    //! a walk is due for it as well (crate::acl). The node's own changes of
    //! the entries are attribute changes, which the watch does not ask for,
    //! so they do not wake it. An overflow of the event queue walks every
    //! granted folder, and a watched folder moved away or gone has its
    //! granted folder walked and watched anew at the next follow, as has
    //! one whose file system was unmounted. Every watch is added from a
    //! descriptor opened below the granted folder, so a link put in the way
    //! leads nowhere.

    use std::collections::{HashMap, HashSet};
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::rc::Rc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use nerve_policy::paths::within;

    use super::{Pending, lock};
    use crate::service::Account;

    /// What each watch asks for: a name made or moved in, and the folder
    /// itself moved away or gone. No attribute change: the walk's own.
    const ASKED: u32 =
        libc::IN_CREATE | libc::IN_MOVED_TO | libc::IN_MOVE_SELF | libc::IN_DELETE_SELF;

    /// The most folders watched in one granted folder: one with more is
    /// left to the other syncs, as watches cost the kernel's memory (about
    /// 1 KiB each) and count against a limit of the system's.
    pub const MOST: usize = 65_536;

    /// The longest path of a folder watched, in bytes: the system's own
    /// limit for a path. A folder at this length or deeper, and everything
    /// below it, is not watched, so what a command makes cannot take more
    /// of the node's memory than [`MOST`] paths of this length.
    pub const LONGEST: usize = libc::PATH_MAX as usize;

    /// One inotify event: the watch, what happened, and the name in the
    /// folder it happened to, if any.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Event {
        pub wd: i32,
        pub mask: u32,
        pub name: Option<std::ffi::OsString>,
    }

    /// The events in `buf`, as one read of an inotify descriptor filled
    /// it: each a fixed head (watch, mask, cookie, length) and a name of
    /// that length, padded with NULs. A record cut short ends the list.
    pub fn events(buf: &[u8]) -> Vec<Event> {
        let word = |at: usize| -> Option<[u8; 4]> { buf.get(at..at + 4)?.try_into().ok() };
        let mut out = Vec::new();
        let mut at = 0usize;
        while let (Some(wd), Some(mask), Some(len)) = (word(at), word(at + 4), word(at + 12)) {
            let len = u32::from_ne_bytes(len) as usize;
            let Some(raw) = buf.get(at + 16..at + 16 + len) else {
                break;
            };
            let name: Vec<u8> = raw.iter().copied().take_while(|b| *b != 0).collect();
            out.push(Event {
                wd: i32::from_ne_bytes(wd),
                mask: u32::from_ne_bytes(mask),
                name: (!name.is_empty()).then(|| std::ffi::OsString::from_vec(name)),
            });
            at += 16 + len;
        }
        out
    }

    /// Which watch is on which folder, by granted folder.
    #[derive(Debug, Default)]
    pub struct State {
        /// Each watch: its granted folder (the one path all its watches
        /// share), and the folder it is on.
        by_wd: HashMap<i32, (Arc<Path>, PathBuf)>,
        /// The granted folders watched, each with its watches. A folder
        /// with no watch at all (missing, or not readable) is not here, so
        /// that the next follow tries it again.
        roots: HashMap<Arc<Path>, HashSet<i32>>,
        /// Granted folders to watch anew at the next follow: a folder in
        /// them moved away, or events were lost.
        stale: HashSet<PathBuf>,
        /// Granted folders that were a mount point when last watched: one
        /// that is a plain folder afterwards had its file system unmounted,
        /// and is not watched until something is mounted there again.
        mounted: HashSet<PathBuf>,
        /// The object (device, inode) each granted folder was when it was
        /// watched. Mounting a file system over a watched folder gives no
        /// event: the watches stay on the folder underneath, so the path is
        /// compared with this from time to time ([`State::covered`]).
        objects: HashMap<PathBuf, (u64, u64)>,
    }

    /// What an event asks for: the granted folders to walk, and the new
    /// folders to watch, each with its granted folder.
    #[derive(Debug, Default, PartialEq, Eq)]
    pub struct Asked {
        pub walk: Vec<PathBuf>,
        pub watch: Vec<(PathBuf, PathBuf)>,
    }

    impl State {
        fn held(&mut self, root: &Path, wd: i32, dir: &Path) {
            let root: Arc<Path> = match self.roots.get_key_value(root) {
                Some((r, _)) => r.clone(),
                None => Arc::from(root),
            };
            self.by_wd.insert(wd, (root.clone(), dir.to_path_buf()));
            self.roots.entry(root).or_default().insert(wd);
        }

        /// `root` was walked anew and the walk found the watches `made`.
        /// Those held before the walk (`before`) that it did not find are
        /// forgotten and returned, for the caller to take off. A watch added
        /// since the walk began, for a folder made while it ran, stays: the
        /// walk may have listed that folder's parent already.
        fn renewed(&mut self, root: &Path, before: &HashSet<i32>, made: &HashSet<i32>) -> Vec<i32> {
            let gone: Vec<i32> = before.difference(made).copied().collect();
            for wd in &gone {
                self.by_wd.remove(wd);
            }
            if let Some(set) = self.roots.get_mut(root) {
                for wd in &gone {
                    set.remove(wd);
                }
                if set.is_empty() {
                    self.roots.remove(root);
                }
            }
            gone
        }

        /// The watches of `root`, which no longer count.
        fn drop_root(&mut self, root: &Path) -> HashSet<i32> {
            let wds = self.roots.remove(root).unwrap_or_default();
            self.by_wd.retain(|wd, _| !wds.contains(wd));
            self.stale.remove(root);
            self.objects.remove(root);
            wds
        }

        /// The watched granted folders with the object each was watched on.
        fn objects(&self) -> Vec<(PathBuf, (u64, u64))> {
            self.objects.iter().map(|(r, o)| (r.clone(), *o)).collect()
        }

        /// Marks the granted folders of `seen` that are watched still on the
        /// object they were looked at on stale, to be watched anew; those
        /// watched anew meanwhile are left.
        fn mark_covered(&mut self, seen: Vec<(PathBuf, (u64, u64))>) -> Vec<PathBuf> {
            let mut covered: Vec<PathBuf> = seen
                .into_iter()
                .filter(|(root, was)| self.objects.get(root) == Some(was))
                .map(|(root, _)| root)
                .collect();
            covered.sort();
            self.stale.extend(covered.iter().cloned());
            covered
        }

        #[cfg(test)]
        pub fn covered_for_test(
            &mut self,
            now: impl Fn(&Path) -> Option<(u64, u64)>,
        ) -> Vec<PathBuf> {
            let seen = changed(self.objects(), now);
            self.mark_covered(seen)
        }

        #[cfg(test)]
        pub fn object_for_test(&mut self, root: &str, id: (u64, u64)) {
            self.objects.insert(PathBuf::from(root), id);
        }

        #[cfg(test)]
        pub fn dirs_for_test(&self, root: &Path) -> Vec<PathBuf> {
            let mut dirs: Vec<PathBuf> = self
                .by_wd
                .values()
                .filter(|(r, _)| &**r == root)
                .map(|(_, d)| d.clone())
                .collect();
            dirs.sort();
            dirs
        }

        /// Notes whether `root` is a mount point now (`is_mount`), and tells
        /// whether it is the bare folder of one that was: the file system
        /// that held the granted folder is gone, so a watch of the folder
        /// there would see nothing of what is mounted at it later.
        fn bare_mountpoint(&mut self, root: &Path, is_mount: bool) -> bool {
            if is_mount {
                self.mounted.insert(root.to_path_buf());
                false
            } else {
                self.mounted.contains(root)
            }
        }

        #[cfg(test)]
        pub fn bare_mountpoint_for_test(&mut self, root: &str, is_mount: bool) -> bool {
            self.bare_mountpoint(Path::new(root), is_mount)
        }

        #[cfg(test)]
        pub fn hold_for_test(&mut self, root: &str, wd: i32, dir: &str) {
            self.held(Path::new(root), wd, Path::new(dir));
        }

        #[cfg(test)]
        pub fn is_stale_for_test(&self, root: &str) -> bool {
            self.stale.contains(Path::new(root))
        }

        #[cfg(test)]
        pub fn renewed_for_test(&mut self, root: &str, before: &[i32], made: &[i32]) -> Vec<i32> {
            let (before, made) = (
                before.iter().copied().collect(),
                made.iter().copied().collect(),
            );
            let mut gone = self.renewed(Path::new(root), &before, &made);
            gone.sort();
            gone
        }

        #[cfg(test)]
        pub fn is_held_for_test(&self, root: &str) -> bool {
            self.roots.contains_key(Path::new(root))
        }

        #[cfg(test)]
        pub fn watches_for_test(&self, root: &str) -> Vec<i32> {
            let mut wds: Vec<i32> = self
                .roots
                .get(Path::new(root))
                .map_or_else(Vec::new, |s| s.iter().copied().collect());
            wds.sort();
            wds
        }

        /// What `e` asks for.
        pub fn react(&mut self, e: &Event) -> Asked {
            let mut asked = Asked::default();
            if e.mask & libc::IN_Q_OVERFLOW != 0 {
                // What was lost may be anything: every granted folder is
                // walked and watched anew.
                asked.walk = self.roots.keys().map(|r| r.to_path_buf()).collect();
                self.stale.extend(asked.walk.iter().cloned());
                return asked;
            }
            if e.mask & libc::IN_IGNORED != 0 {
                let mut last = None;
                if let Some((root, _)) = self.by_wd.remove(&e.wd)
                    && let Some(set) = self.roots.get_mut(&root)
                {
                    set.remove(&e.wd);
                    if set.is_empty() {
                        last = Some(root);
                    }
                }
                if let Some(root) = last {
                    // The last watch of a granted folder went with no
                    // move or delete told: its file system was unmounted.
                    // The folder is not held any more, so the next follow
                    // looks at it again, and a walk makes that follow come.
                    self.roots.remove(&root);
                    self.objects.remove(&*root);
                    asked.walk.push(root.to_path_buf());
                }
                return asked;
            }
            let Some((root, dir)) = self.by_wd.get(&e.wd).cloned() else {
                return asked;
            };
            if e.mask & (libc::IN_MOVE_SELF | libc::IN_DELETE_SELF) != 0 {
                // The watch goes along with a folder moved away, which may
                // now lie outside the granted folder.
                self.stale.insert(root.to_path_buf());
                asked.walk.push(root.to_path_buf());
                return asked;
            }
            if e.mask & (libc::IN_CREATE | libc::IN_MOVED_TO) != 0 {
                if e.mask & libc::IN_ISDIR != 0
                    && let Some(name) = &e.name
                {
                    asked.watch.push((root.to_path_buf(), dir.join(name)));
                }
                asked.walk.push(root.to_path_buf());
            }
            asked
        }
    }

    /// The inotify instance, its thread, and what the two share.
    struct Inner {
        fd: OwnedFd,
        state: Mutex<State>,
        /// As whom the folders are looked at and watched.
        owner: Mutex<Option<Account>>,
        pending: Arc<Mutex<Pending>>,
        /// The granted folders left to the other syncs, and said so once.
        left: Mutex<HashSet<PathBuf>>,
        /// The granted folders found missing (or not readable) when last
        /// watched: once one is watched, it is walked, as what it holds now
        /// may have come in since.
        missing: Mutex<HashSet<PathBuf>>,
        most: usize,
        longest: usize,
        stop: AtomicBool,
    }

    /// The watches of the granted folders on Linux.
    #[derive(Default)]
    pub struct Watches {
        running: Option<(Arc<Inner>, std::thread::JoinHandle<()>)>,
        /// Why the watch could not start, said once.
        failed: bool,
        /// [`MOST`], or less for a test.
        most: Option<usize>,
        /// [`LONGEST`], or less for a test.
        longest: Option<usize>,
    }

    impl Drop for Watches {
        fn drop(&mut self) {
            if let Some((inner, t)) = self.running.take() {
                inner.stop.store(true, Ordering::SeqCst);
                let _ = t.join();
            }
        }
    }

    impl Watches {
        /// Watches with at most `most` folders in a granted folder.
        #[cfg(test)]
        pub fn with_most(most: usize) -> Watches {
            Watches {
                running: None,
                failed: false,
                most: Some(most),
                longest: None,
            }
        }

        /// Watches with no folder whose path is `longest` bytes or more.
        #[cfg(test)]
        pub fn with_longest(longest: usize) -> Watches {
            Watches {
                running: None,
                failed: false,
                most: None,
                longest: Some(longest),
            }
        }

        /// Remembers `root` as a mount point that is bare now, as the watch
        /// does when a drive is unmounted.
        #[cfg(test)]
        pub fn remember_mount_for_test(&self, root: &Path) {
            if let Some((inner, _)) = &self.running {
                lock(&inner.state).mounted.insert(root.to_path_buf());
                lock(&inner.missing).insert(root.to_path_buf());
            }
        }

        /// The folders watched in the granted folder `root`, by path.
        #[cfg(test)]
        pub fn watched_for_test(&self, root: &Path) -> Vec<PathBuf> {
            self.running.as_ref().map_or_else(Vec::new, |(inner, _)| {
                lock(&inner.state).dirs_for_test(root)
            })
        }

        /// Watches `dir`, which an event named under the path recorded for
        /// a watch, as the thread does for a folder made.
        #[cfg(test)]
        pub fn watch_for_test(&self, root: &Path, dir: &Path) {
            if let Some((inner, _)) = &self.running {
                inner.watch(root, dir);
            }
        }

        /// Whether a granted folder is watched.
        pub fn watching(&self) -> bool {
            self.running
                .as_ref()
                .is_some_and(|(inner, _)| !lock(&inner.state).roots.is_empty())
        }

        /// Watches `folders` and no other. True when a granted folder is
        /// not watched yet because it is missing or cannot be read (not one
        /// left for being too big): it is tried again at the next follow.
        pub fn follow(
            &mut self,
            folders: &[PathBuf],
            owner: Option<Account>,
            pending: &Arc<Mutex<Pending>>,
        ) -> bool {
            if self.running.is_none() && !folders.is_empty() && !self.failed {
                match start(
                    pending.clone(),
                    self.most.unwrap_or(MOST),
                    self.longest.unwrap_or(LONGEST),
                ) {
                    Ok(r) => self.running = Some(r),
                    Err(e) => {
                        self.failed = true;
                        tracing::warn!(
                            "folder grants: the granted folders are not watched ({e}); what is moved into one gets its entries at the next start, change or Sync folders"
                        );
                    }
                }
            }
            let Some((inner, _)) = &self.running else {
                return false;
            };
            *lock(&inner.owner) = owner;
            // Each folder is tried once: one that has no watch afterwards
            // (missing) waits for the next follow.
            let mut tried: HashSet<PathBuf> = HashSet::new();
            loop {
                let roots = outermost(folders, &lock(&inner.left));
                lock(&inner.left).retain(|f| roots.contains(f));
                // What is remembered of a folder (a mount, or that it is
                // missing) ends with its grant: it may be granted again
                // later as the plain folder it is then.
                lock(&inner.state).mounted.retain(|f| roots.contains(f));
                lock(&inner.missing).retain(|f| roots.contains(f));
                covered(inner);
                let (gone, new): (Vec<PathBuf>, Vec<PathBuf>) = {
                    let st = lock(&inner.state);
                    let left = lock(&inner.left);
                    let gone = st
                        .roots
                        .keys()
                        .map(|r| r.to_path_buf())
                        .filter(|r| !roots.contains(r))
                        .collect();
                    let new = roots
                        .iter()
                        .filter(|r| !st.roots.contains_key(r.as_path()) || st.stale.contains(*r))
                        .filter(|r| !left.contains(*r) && !tried.contains(*r))
                        .cloned()
                        .collect();
                    (gone, new)
                };
                for root in gone {
                    unwatch(inner, &root);
                    lock(&inner.state).mounted.remove(&root);
                }
                if new.is_empty() {
                    break;
                }
                for root in new {
                    inner.watch(&root, &root);
                    tried.insert(root);
                }
            }
            let roots = outermost(folders, &lock(&inner.left));
            let st = lock(&inner.state);
            let left = lock(&inner.left);
            roots
                .iter()
                .any(|r| !left.contains(r) && !st.roots.contains_key(r.as_path()))
        }
    }

    /// The granted folders to watch for themselves: those not inside
    /// another that is watched, as that one's watches reach them. A folder
    /// inside one left out (too big) is one to watch for itself.
    fn outermost(folders: &[PathBuf], left: &HashSet<PathBuf>) -> Vec<PathBuf> {
        let mut roots: Vec<PathBuf> = folders
            .iter()
            .filter(|f| {
                !folders
                    .iter()
                    .any(|o| o != *f && within(f, o) && !left.contains(o))
            })
            .cloned()
            .collect();
        roots.sort();
        roots.dedup();
        roots
    }

    /// Starts the inotify instance and its thread.
    fn start(
        pending: Arc<Mutex<Pending>>,
        most: usize,
        longest: usize,
    ) -> std::io::Result<(Arc<Inner>, std::thread::JoinHandle<()>)> {
        // SAFETY: a plain call; the descriptor is owned at once.
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let inner = Arc::new(Inner {
            // SAFETY: the descriptor just made, owned from here.
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            state: Mutex::new(State::default()),
            owner: Mutex::new(None),
            pending,
            left: Mutex::new(HashSet::new()),
            missing: Mutex::new(HashSet::new()),
            most,
            longest,
            stop: AtomicBool::new(false),
        });
        let reader = inner.clone();
        let t = std::thread::Builder::new()
            .name("grant-watch".into())
            .spawn(move || read(&reader))?;
        Ok((inner, t))
    }

    /// Marks the watched granted folders that are another object now than
    /// when they were watched, and asks their walk: a file system mounted
    /// over a watched folder (a drive that came after the node started)
    /// gives no event, and the watches stay on the folder underneath.
    fn covered(inner: &Inner) {
        let owner = lock(&inner.owner).clone();
        let _as = owner
            .as_ref()
            .and_then(|o| crate::account::FsAs::new(o).ok());
        let now = |p: &Path| {
            std::fs::symlink_metadata(p)
                .ok()
                .map(|m| (m.dev(), m.ino()))
        };
        let covered = covered_in(&inner.state, now);
        let at = Instant::now();
        let mut pending = lock(&inner.pending);
        for root in covered {
            pending.changed(&root, at);
        }
    }

    /// The granted folders of `seen` that are another object now, according
    /// to `now` (what the path is: none where it cannot be said).
    fn changed(
        seen: Vec<(PathBuf, (u64, u64))>,
        now: impl Fn(&Path) -> Option<(u64, u64)>,
    ) -> Vec<(PathBuf, (u64, u64))> {
        seen.into_iter()
            .filter(|(root, was)| now(root).is_some_and(|is| is != *was))
            .collect()
    }

    /// The watched granted folders that are another object now, marked
    /// stale to be watched anew. The paths are looked at without `state`
    /// held: a path on a share that does not answer waits for as long as the
    /// share does, and the thread that reads the events needs `state`.
    pub(super) fn covered_in(
        state: &Mutex<State>,
        now: impl Fn(&Path) -> Option<(u64, u64)>,
    ) -> Vec<PathBuf> {
        let seen = lock(state).objects();
        let seen = changed(seen, now);
        lock(state).mark_covered(seen)
    }

    /// Takes every watch of `root` off.
    fn unwatch(inner: &Inner, root: &Path) {
        for wd in lock(&inner.state).drop_root(root) {
            // SAFETY: a watch of this instance; one gone already is refused.
            unsafe { libc::inotify_rm_watch(inner.fd.as_raw_fd(), wd) };
        }
    }

    impl Inner {
        /// Watches `dir` and every folder below it as part of the granted
        /// folder `root`, as the owner; a watch already there stays. Where
        /// `dir` is the granted folder, its watches that are no longer on a
        /// folder in it go, but not one the thread added meanwhile. One too
        /// big, or past the system's limit, is not watched at all, and the
        /// log says so once. A granted folder with nothing to watch (it is
        /// missing) has no watches and is tried again at the next follow.
        fn watch(&self, root: &Path, dir: &Path) {
            let owner = lock(&self.owner).clone();
            let _as = owner.as_ref().and_then(|o| {
                crate::account::FsAs::new(o)
                    .inspect_err(|e| tracing::warn!("folder grants: cannot act as {}: {e}", o.name))
                    .ok()
            });
            let before = if dir == root {
                // Taken before the walk, and the mark off now, so that a
                // folder moved away while it runs asks for another one.
                let mut st = lock(&self.state);
                st.stale.remove(root);
                st.roots.get(root).cloned().unwrap_or_default()
            } else {
                HashSet::new()
            };
            let mut made = HashSet::new();
            let r = self.add_tree(root, dir, &mut made);
            let object = r.as_ref().ok().copied().flatten();
            let is_mount = dir == root && is_mount(root);
            let mut st = lock(&self.state);
            if let Err(why) = r {
                drop(st);
                unwatch(self, root);
                if lock(&self.left).insert(root.to_path_buf()) {
                    tracing::warn!(
                        "folder grants: {} is not watched ({why}); what is moved into it gets its entries at the next start, change or Sync folders",
                        root.display()
                    );
                }
                return;
            }
            if dir == root && st.bare_mountpoint(root, is_mount) {
                // What was mounted here is gone: the folder under it is no
                // place to watch. It is looked for again like a missing one,
                // and walked once something is mounted there.
                drop(st);
                unwatch(self, root);
                lock(&self.missing).insert(root.to_path_buf());
                return;
            }
            if dir == root {
                match object {
                    Some(object) if !made.is_empty() => {
                        st.objects.insert(root.to_path_buf(), object);
                    }
                    _ => {
                        st.objects.remove(root);
                    }
                }
                // Made anew: what the folders below hold now is all.
                for wd in st.renewed(root, &before, &made) {
                    // SAFETY: a watch of this instance.
                    unsafe { libc::inotify_rm_watch(self.fd.as_raw_fd(), wd) };
                }
                drop(st);
                let mut missing = lock(&self.missing);
                if made.is_empty() {
                    missing.insert(root.to_path_buf());
                } else if missing.remove(root) {
                    // It is there now: what it holds may be new to the node.
                    lock(&self.pending).changed(root, Instant::now());
                }
            }
        }

        /// Adds a watch on `dir` and on every folder below it, links not
        /// followed and other file systems left out, as the ACL walk does:
        /// `dir` is opened a part at a time from the granted folder's own
        /// descriptor and each folder below it from its parent's, and each
        /// is watched through its descriptor, so a link put in the way (or at
        /// the place of a folder renamed away, whose old name an event still
        /// carries) leads nowhere. What vanished meanwhile, and a folder this
        /// account may not read, are passed over, and so is a folder whose
        /// path is `longest` bytes or more, with everything below it: a
        /// command could otherwise make a chain of folders deeper than any
        /// path, and the paths kept for it would fill the node's memory. The
        /// walks reach such a folder all the same. Gives the object the
        /// granted folder is, as it was opened, if it could be.
        fn add_tree(
            &self,
            root: &Path,
            dir: &Path,
            made: &mut HashSet<i32>,
        ) -> Result<Option<(u64, u64)>, String> {
            let Ok(top) = crate::acl::open_path(root) else {
                return Ok(None);
            };
            if !top.m.is_dir() {
                return Ok(None);
            }
            let dev = top.m.dev();
            let id = (dev, top.m.ino());
            let mut todo: Vec<(Rc<crate::acl::Opened>, PathBuf)> = Vec::new();
            let mut first = Some(dir.to_path_buf()).filter(|d| d.as_os_str().len() < self.longest);
            loop {
                let (open, d) = match first.take() {
                    Some(d) => match open_below(&top, root, &d) {
                        Some(o) => (o, d),
                        None => continue,
                    },
                    None => match todo.pop() {
                        Some((parent, d)) => {
                            let opened = d
                                .file_name()
                                .and_then(|n| CString::new(n.as_bytes()).ok())
                                .and_then(|n| {
                                    crate::acl::open_in(parent.file.as_raw_fd(), &n).ok()
                                });
                            match opened {
                                Some(o) => (o, d),
                                None => continue,
                            }
                        }
                        None => break,
                    },
                };
                if !open.m.is_dir() || open.m.dev() != dev {
                    continue;
                }
                let open = Rc::new(open);
                let at = open.path();
                let Ok(c) = CString::new(at.as_os_str().as_bytes()) else {
                    continue;
                };
                let mask = ASKED | libc::IN_ONLYDIR | libc::IN_EXCL_UNLINK;
                // SAFETY: an open instance and a NUL-terminated path.
                let wd = unsafe { libc::inotify_add_watch(self.fd.as_raw_fd(), c.as_ptr(), mask) };
                if wd < 0 {
                    let e = std::io::Error::last_os_error();
                    match e.raw_os_error() {
                        Some(libc::ENOSPC) => {
                            return Err(
                                "the system's limit of watches is reached (fs.inotify.max_user_watches)"
                                    .into(),
                            );
                        }
                        _ => continue,
                    }
                }
                made.insert(wd);
                lock(&self.state).held(root, wd, &d);
                let in_root = lock(&self.state).roots.get(root).map_or(0, HashSet::len);
                if made.len().max(in_root) > self.most {
                    return Err(format!("it holds more than {} folders", self.most));
                }
                // What is queued counts as well, so the queue stays as
                // short as the watches may be many.
                let room = self.most.saturating_sub(made.len() + todo.len());
                let Some(subs) = subfolders(&at, &d, dev, room) else {
                    return Err(format!("it holds more than {} folders", self.most));
                };
                todo.extend(
                    subs.into_iter()
                        .filter(|p| p.as_os_str().len() < self.longest)
                        .map(|p| (open.clone(), p)),
                );
            }
            Ok(Some(id))
        }
    }

    /// The folder `dir`, which lies in the granted folder `root` (opened as
    /// `top`), opened from `top` a part at a time without following a link.
    /// None where it is not below `root` or a part of the way is gone or is
    /// not a folder now.
    fn open_below(top: &crate::acl::Opened, root: &Path, dir: &Path) -> Option<crate::acl::Opened> {
        let rel = dir.strip_prefix(root).ok()?;
        let mut at = crate::acl::open_in(top.file.as_raw_fd(), c".").ok()?;
        for part in rel.components() {
            let std::path::Component::Normal(name) = part else {
                return None;
            };
            if !at.m.is_dir() {
                return None;
            }
            let name = CString::new(name.as_bytes()).ok()?;
            at = crate::acl::open_in(at.file.as_raw_fd(), &name).ok()?;
        }
        Some(at)
    }

    /// Whether `root` is a mount point: its device is not its parent's.
    fn is_mount(root: &Path) -> bool {
        let dev = |p: &Path| std::fs::symlink_metadata(p).map(|m| m.dev());
        match (dev(root), root.parent().map(dev)) {
            (Ok(a), Some(Ok(b))) => a != b,
            _ => false,
        }
    }

    /// The folders directly in `dir` on the device `dev`, links not
    /// followed; none when it cannot be read, and none at all when there
    /// are more than `room`, so a folder with very many is not queued whole.
    /// `read` is the path the folder is read through (a descriptor's), and
    /// `dir` the one its folders are named under.
    fn subfolders(read: &Path, dir: &Path, dev: u64, room: usize) -> Option<Vec<PathBuf>> {
        let Ok(entries) = std::fs::read_dir(read) else {
            return Some(Vec::new());
        };
        let mut out = Vec::new();
        for e in entries.flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir()) && e.metadata().is_ok_and(|m| m.dev() == dev)
            {
                if out.len() >= room {
                    return None;
                }
                out.push(dir.join(e.file_name()));
            }
        }
        Some(out)
    }

    #[cfg(test)]
    pub fn subfolders_for_test(dir: &Path, dev: u64, room: usize) -> Option<Vec<PathBuf>> {
        subfolders(dir, dir, dev, room)
    }

    /// The thread: reads the events until the watches are dropped, marks
    /// the granted folders they name changed, and watches the folders made
    /// or moved in.
    fn read(inner: &Inner) {
        let mut buf = vec![0u8; 64 * 1024];
        while !inner.stop.load(Ordering::SeqCst) {
            let mut p = libc::pollfd {
                fd: inner.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one pollfd; half a second, so a stop is seen.
            if unsafe { libc::poll(&mut p, 1, 500) } <= 0 {
                continue;
            }
            // SAFETY: a buffer of the length given.
            let n = unsafe { libc::read(inner.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                continue;
            }
            let mut asked = Asked::default();
            {
                let mut st = lock(&inner.state);
                for e in events(&buf[..n as usize]) {
                    let a = st.react(&e);
                    asked.walk.extend(a.walk);
                    asked.watch.extend(a.watch);
                }
            }
            for (root, dir) in asked.watch {
                if !lock(&inner.left).contains(&root) {
                    inner.watch(&root, &dir);
                }
            }
            let now = Instant::now();
            let mut p = lock(&inner.pending);
            for root in asked.walk {
                p.changed(&root, now);
            }
        }
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
    pub(super) fn open(path: &Path) -> std::io::Result<(OwnedHandle, Option<String>)> {
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
            Some(Rewalk::None),
            "a new config does not wait for a walk of a folder due"
        );
        assert_eq!(
            sync(&w, Some(2), 2, later),
            Some(Rewalk::At(vec![proj.clone()])),
            "the folder is still due after it"
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
                ids: vec![super::win::open(p).unwrap().1.unwrap()],
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
                ids: vec![super::win::open(p).unwrap().1.unwrap()],
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

    /// What the last sync left is kept with its errors, so `status` says a
    /// grant that failed or stayed on Windows too (arch-3); none before the
    /// first sync.
    #[test]
    fn the_last_sync_is_kept_with_its_errors() {
        let w = Watch::default();
        assert!(w.last().is_none());
        let grant = |path: &str| crate::grants::Grant {
            container: "c1".into(),
            path: path.into(),
            access: nerve_policy::config::Access::parse("rw").unwrap(),
            id: None,
            unfinished: false,
            toward: Vec::new(),
            closed_at: None,
        };
        let synced = Synced {
            errors: vec!["C:\\w\\gone: access denied".into()],
            stale: vec![grant("C:\\w\\gone")],
            unclosed: vec![grant("C:\\w\\shut")],
            ..Default::default()
        };
        w.finished(3, &synced);
        let st = w.last().unwrap().report(0).json();
        assert_eq!(
            st["errors"],
            serde_json::json!(["C:\\w\\gone: access denied"])
        );
        assert_eq!(st["stale"], serde_json::json!(["C:\\w\\gone"]));
        assert_eq!(st["unclosed"], serde_json::json!(["C:\\w\\shut"]));
        w.finished(4, &Synced::default());
        assert_eq!(
            w.last().unwrap().report(0).json()["errors"],
            serde_json::json!([])
        );
    }

    /// One inotify record as the kernel writes it: the watch, the mask, the
    /// cookie, the name's padded length and the name.
    #[cfg(target_os = "linux")]
    fn inotify_record(wd: i32, mask: u32, name: &str) -> Vec<u8> {
        let mut n = name.as_bytes().to_vec();
        if !n.is_empty() {
            n.push(0);
            n.resize(n.len().next_multiple_of(16), 0);
        }
        let mut r = Vec::new();
        r.extend(wd.to_ne_bytes());
        r.extend(mask.to_ne_bytes());
        r.extend(0u32.to_ne_bytes());
        r.extend((n.len() as u32).to_ne_bytes());
        r.extend(n);
        r
    }

    /// The events of a read are parsed whole; one cut short ends them.
    #[cfg(target_os = "linux")]
    #[test]
    fn inotify_events_are_read_from_their_records() {
        use linux::{Event, events};
        let mut buf = inotify_record(1, libc::IN_MOVED_TO, "moved.txt");
        buf.extend(inotify_record(-1, libc::IN_Q_OVERFLOW, ""));
        let got = events(&buf);
        assert_eq!(
            got,
            [
                Event {
                    wd: 1,
                    mask: libc::IN_MOVED_TO,
                    name: Some("moved.txt".into())
                },
                Event {
                    wd: -1,
                    mask: libc::IN_Q_OVERFLOW,
                    name: None
                }
            ]
        );
        buf.extend(&inotify_record(2, libc::IN_CREATE, "cut")[..20]);
        assert_eq!(events(&buf).len(), 2);
    }

    /// What wakes the Linux watch: a file or folder made or moved in (a
    /// folder is watched too), a watched folder moved away; not the node's
    /// own changes of the entries (attributes). An overflow walks every
    /// granted folder.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_linux_watch_wakes_for_names_and_not_for_attributes() {
        use linux::{Asked, Event};
        let ev = |wd: i32, mask: u32, name: &str| Event {
            wd,
            mask,
            name: (!name.is_empty()).then(|| name.into()),
        };
        let mut st = linux::State::default();
        st.hold_for_test("/w/proj", 1, "/w/proj");
        st.hold_for_test("/w/proj", 2, "/w/proj/src");
        st.hold_for_test("/w/other", 3, "/w/other");
        let walk = |r: &str| Asked {
            walk: vec![PathBuf::from(r)],
            watch: Vec::new(),
        };
        assert_eq!(
            st.react(&ev(2, libc::IN_MOVED_TO, "a.txt")),
            walk("/w/proj")
        );
        // A copy that kept its source's mode (`mv` from another file
        // system, `cp -a`) is a file made, with a mask that cuts the
        // folder's default entries.
        assert_eq!(st.react(&ev(2, libc::IN_CREATE, "b.txt")), walk("/w/proj"));
        for own in [libc::IN_ATTRIB, libc::IN_MODIFY, libc::IN_CLOSE_WRITE] {
            assert_eq!(st.react(&ev(2, own, "a.txt")), Asked::default(), "{own:#x}");
        }
        assert_eq!(
            st.react(&ev(1, libc::IN_CREATE | libc::IN_ISDIR, "new")),
            Asked {
                walk: vec![PathBuf::from("/w/proj")],
                watch: vec![(PathBuf::from("/w/proj"), PathBuf::from("/w/proj/new"))]
            }
        );
        assert_eq!(st.react(&ev(9, libc::IN_MOVED_TO, "x")), Asked::default());
        assert_eq!(st.react(&ev(2, libc::IN_MOVE_SELF, "")), walk("/w/proj"));
        assert!(st.is_stale_for_test("/w/proj"));
        let mut all = st.react(&ev(-1, libc::IN_Q_OVERFLOW, "")).walk;
        all.sort();
        assert_eq!(all, [PathBuf::from("/w/other"), PathBuf::from("/w/proj")]);
        assert!(st.is_stale_for_test("/w/other"));
        // A watch the kernel took off is forgotten.
        assert_eq!(st.react(&ev(1, libc::IN_IGNORED, "")), Asked::default());
        assert_eq!(st.react(&ev(1, libc::IN_MOVED_TO, "y")), Asked::default());
        assert_eq!(st.watches_for_test("/w/proj"), [2]);
    }

    /// A granted folder whose file system is unmounted loses its watches
    /// with an ignore event each and no move or delete: when the last goes,
    /// the folder is not held any more and its walk is asked for, so the
    /// next follow watches it again (and the supervisor is told to look).
    #[cfg(target_os = "linux")]
    #[test]
    fn a_granted_folder_whose_drive_is_unmounted_is_followed_again() {
        use linux::{Asked, Event};
        let ev = |wd: i32, mask: u32| Event {
            wd,
            mask,
            name: None,
        };
        let mut st = linux::State::default();
        st.hold_for_test("/m/usb/work", 1, "/m/usb/work");
        st.hold_for_test("/m/usb/work", 2, "/m/usb/work/sub");
        st.object_for_test("/m/usb/work", (1, 1));
        assert_eq!(
            st.react(&ev(1, libc::IN_UNMOUNT | libc::IN_ISDIR)),
            Asked::default()
        );
        assert_eq!(st.react(&ev(1, libc::IN_IGNORED)), Asked::default());
        assert_eq!(st.watches_for_test("/m/usb/work"), [2]);
        assert_eq!(
            st.react(&ev(2, libc::IN_IGNORED)),
            Asked {
                walk: vec![PathBuf::from("/m/usb/work")],
                watch: Vec::new()
            }
        );
        assert!(
            !st.is_held_for_test("/m/usb/work"),
            "the folder is looked at again at the next follow"
        );
        // And it is not compared with the object it was: it is not held.
        assert!(st.covered_for_test(|_| Some((2, 2))).is_empty());
        // What was mounted at the folder and is not any more: the folder
        // under it is not watched until a mount is there again.
        assert!(!st.bare_mountpoint_for_test("/m/usb/work", true));
        assert!(st.bare_mountpoint_for_test("/m/usb/work", false));
        assert!(!st.bare_mountpoint_for_test("/m/usb/work", true));
        assert!(!st.bare_mountpoint_for_test("/m/plain", false));
    }

    /// Waits up to two seconds for `done`.
    #[cfg(target_os = "linux")]
    fn soon(done: impl Fn() -> bool) -> bool {
        let until = Instant::now() + Duration::from_secs(2);
        while Instant::now() < until {
            if done() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        done()
    }

    /// The real watch, of a folder of this test's: a burst of files moved
    /// in, also into a folder made just before, is one walk of the granted
    /// folder once the names are quiet; the walk's own changes (the mode,
    /// an entry) wake nothing.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_burst_moved_into_a_granted_folder_is_one_walk() {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (granted, outside) = (root.join("granted"), root.join("outside"));
        std::fs::create_dir_all(granted.join("deep/er")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let w = Watch::default();
        w.follow_linux(|| vec![granted.clone()], None);
        let quiet = || lock(&w.pending).folders.is_empty();
        // The walk's own changes: the mode and an extended attribute.
        let f = granted.join("deep/er/kept.txt");
        std::fs::write(&f, "k").unwrap();
        std::thread::sleep(Duration::from_millis(300));
        // A file made wakes the walk: a copy that kept a narrow mode (what
        // `mv` from another file system leaves) has a mask that cuts the
        // folder's default entries for nerve-run.
        assert!(soon(|| !quiet()), "a file made wakes the walk");
        std::thread::sleep(Duration::from_millis(300));
        lock(&w.pending).folders.clear();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o640)).unwrap();
        let c = std::ffi::CString::new(f.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a NUL-terminated path, name and a value of the length given.
        unsafe {
            libc::setxattr(
                c.as_ptr(),
                c"user.nerve-test".as_ptr(),
                b"1".as_ptr().cast(),
                1,
                0,
            )
        };
        std::thread::sleep(Duration::from_millis(300));
        assert!(quiet(), "the node's own changes woke the watch");
        // A folder made deep inside, then files moved into it at once.
        std::fs::create_dir(granted.join("deep/er/new")).unwrap();
        for n in 0..50 {
            let from = outside.join(format!("f{n}"));
            std::fs::write(&from, "x").unwrap();
            std::fs::rename(&from, granted.join(format!("deep/er/new/f{n}"))).unwrap();
        }
        assert!(soon(|| !quiet()), "the moves did not wake the watch");
        // The thread reads what is left of the burst.
        std::thread::sleep(Duration::from_millis(300));
        let t0 = Instant::now();
        assert!(w.due(t0).is_empty(), "walked before the names were quiet");
        assert_eq!(
            w.due(t0 + QUIET + Duration::from_secs(1)),
            std::slice::from_ref(&granted)
        );
        assert!(w.due(t0 + QUIET * 3).is_empty(), "one walk per burst");
        // A file moved into the folder made after the watch started is
        // seen: the folder was watched when it was made.
        std::thread::sleep(Duration::from_millis(200));
        lock(&w.pending).folders.clear();
        std::fs::write(outside.join("late"), "x").unwrap();
        std::fs::rename(outside.join("late"), granted.join("deep/er/new/late")).unwrap();
        assert!(soon(|| !quiet()), "the new folder is not watched");
    }

    /// A granted folder with more folders than a watch may hold is left to
    /// the other syncs, and the log says so once; a smaller one is watched.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_folder_too_big_to_watch_is_left_and_said_once() {
        use tracing_subscriber::layer::SubscriberExt;
        let log = nerve_transport::log::Log::new(nerve_transport::log::Level::Info);
        let sub = tracing_subscriber::Registry::default().with(log.layer());
        let _guard = tracing::subscriber::set_default(sub);
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (big, small) = (root.join("big"), root.join("small"));
        std::fs::create_dir_all(big.join("a/b/c")).unwrap();
        std::fs::create_dir_all(small.join("a")).unwrap();
        let pending = Arc::new(Mutex::new(Pending::default()));
        let mut w = linux::Watches::with_most(2);
        let folders = [big.clone(), small.clone()];
        w.follow(&folders, None, &pending);
        w.follow(&folders, None, &pending);
        let q = nerve_transport::log::Query {
            limit: usize::MAX,
            ..Default::default()
        };
        let said: Vec<String> = log
            .entries(&q)
            .into_iter()
            .map(|(_, e)| e.msg)
            .filter(|m| m.contains("is not watched"))
            .collect();
        assert_eq!(said.len(), 1, "{said:#?}");
        assert!(said[0].contains(&big.display().to_string()), "{said:#?}");
        assert!(said[0].contains("more than 2 folders"), "{said:#?}");
        assert!(said[0].contains("Sync folders"), "{said:#?}");
        std::fs::write(root.join("m"), "x").unwrap();
        std::fs::rename(root.join("m"), small.join("a/m")).unwrap();
        assert!(soon(|| !lock(&pending).folders.is_empty()));
        assert_eq!(lock(&pending).folders[0].path, small);
    }
    /// A granted folder inside one too big to watch is watched for itself:
    /// the outer one is left to the other syncs, the inner one is small.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_granted_folder_inside_one_too_big_to_watch_is_watched_for_itself() {
        // The outer folder says it is left out; with a log of this test's,
        // as the test of that line has, so neither can hide it from the other.
        use tracing_subscriber::layer::SubscriberExt;
        let log = nerve_transport::log::Log::new(nerve_transport::log::Level::Info);
        let sub = tracing_subscriber::Registry::default().with(log.layer());
        let _guard = tracing::subscriber::set_default(sub);
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (outer, inner) = (root.join("outer"), root.join("outer/inner"));
        for sub in ["a", "b", "c", "inner"] {
            std::fs::create_dir_all(outer.join(sub)).unwrap();
        }
        let pending = Arc::new(Mutex::new(Pending::default()));
        let mut w = linux::Watches::with_most(2);
        let folders = [outer.clone(), inner.clone()];
        w.follow(&folders, None, &pending);
        w.follow(&folders, None, &pending);
        std::fs::write(root.join("m"), "x").unwrap();
        std::fs::rename(root.join("m"), inner.join("m")).unwrap();
        assert!(
            soon(|| !lock(&pending).folders.is_empty()),
            "inner is not watched"
        );
        assert_eq!(lock(&pending).folders[0].path, inner);
        // The outer one is left out: what is moved into it wakes nothing.
        lock(&pending).folders.clear();
        std::fs::write(root.join("n"), "x").unwrap();
        std::fs::rename(root.join("n"), outer.join("a/n")).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert!(lock(&pending).folders.is_empty());
    }

    /// A granted folder that is missing has no watch and is tried again:
    /// made later, or made again after it was moved away, it is watched and
    /// walked, and the supervisor is told to look for it meanwhile.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_granted_folder_missing_is_watched_once_it_is_there() {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let later = root.join("later");
        let pending = Arc::new(Mutex::new(Pending::default()));
        let mut w = linux::Watches::default();
        let folders = std::slice::from_ref(&later);
        assert!(
            w.follow(folders, None, &pending),
            "a missing folder is unwatched"
        );
        std::fs::create_dir_all(later.join("sub")).unwrap();
        assert!(!w.follow(folders, None, &pending));
        let walked = |p: &Arc<Mutex<Pending>>| lock(p).folders.iter().any(|f| f.path == later);
        assert!(walked(&pending), "a folder that came walks");
        lock(&pending).folders.clear();
        let moved_in = |name: &str| {
            std::fs::write(root.join(name), "x").unwrap();
            std::fs::rename(root.join(name), later.join("sub").join(name)).unwrap();
        };
        moved_in("one");
        assert!(soon(|| walked(&pending)), "the folder is not watched");
        lock(&pending).folders.clear();
        // Moved away and made again: the walk of the watch ends with
        // nothing to watch, and the next follow finds the new folder.
        std::fs::rename(&later, root.join("later.old")).unwrap();
        assert!(soon(|| walked(&pending)), "a folder moved away walks");
        lock(&pending).folders.clear();
        assert!(w.follow(folders, None, &pending), "the folder is gone");
        std::fs::create_dir_all(later.join("sub")).unwrap();
        assert!(!w.follow(folders, None, &pending));
        assert!(walked(&pending), "a folder made again walks");
        lock(&pending).folders.clear();
        moved_in("two");
        assert!(soon(|| walked(&pending)), "the new folder is not watched");
    }

    /// The supervisor looks again for a missing granted folder, every
    /// `REFOLLOW`, until it is there.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_missing_granted_folder_is_looked_for_again_now_and_then() {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let later = root.join("later");
        let w = Watch::default();
        let t0 = Instant::now();
        assert!(w.follow_due(t0).is_none(), "nothing was followed yet");
        w.follow_linux(|| vec![later.clone()], None);
        assert!(w.follow_due(t0).is_some());
        // The last follow ended just now, which holds the next back too.
        assert!(w.follow_due(t0 + Duration::from_secs(1)).is_none());
        assert!(w.follow_due(t0 + REFOLLOW * 2).is_some());
        std::fs::create_dir(&later).unwrap();
        w.follow_linux(|| vec![later.clone()], None);
        assert!(
            w.follow_due(t0 + REFOLLOW * 5).is_some(),
            "a watched folder is looked at now and then"
        );
        w.follow_linux(Vec::new, None);
        assert!(
            w.follow_due(t0 + REFOLLOW * 10).is_none(),
            "nothing is watched now"
        );
    }

    /// The look at the watched folders' paths does not hold `state`: the
    /// thread that reads the events needs it, and a path on a share that does
    /// not answer waits for as long as the share does.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_path_that_does_not_answer_does_not_hold_the_events() {
        let mut st = linux::State::default();
        st.object_for_test("/w/share", (1, 1));
        st.object_for_test("/w/usb", (1, 2));
        let state = Mutex::new(st);
        let free = std::cell::Cell::new(0);
        let covered = linux::covered_in(&state, |p| {
            if state.try_lock().is_ok() {
                free.set(free.get() + 1);
            }
            Some(if p.ends_with("usb") { (9, 2) } else { (1, 1) })
        });
        assert_eq!(
            free.get(),
            2,
            "the state was held while a path was looked at"
        );
        assert_eq!(covered, [PathBuf::from("/w/usb")]);
        // A folder watched anew meanwhile is not marked for the old object.
        let covered = linux::covered_in(&state, |p| {
            if p.ends_with("usb") {
                lock(&state).object_for_test("/w/usb", (9, 2));
            }
            Some((9, 9))
        });
        assert_eq!(covered, [PathBuf::from("/w/share")]);
    }

    /// The supervisor starts a follow when none runs, and the next only
    /// [`REFOLLOW`] after the last one ended: a follow that cannot get on
    /// does not bring a thread for each round.
    #[cfg(target_os = "linux")]
    #[test]
    fn one_follow_runs_at_a_time() {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let w = Watch::default();
        w.follow_linux(|| vec![root.join("later")], None);
        let t0 = Instant::now();
        let first = w.follow_due(t0).expect("a folder is missing");
        assert!(
            w.follow_due(t0 + REFOLLOW * 100).is_none(),
            "a second follow started while the first runs"
        );
        drop(first);
        assert!(
            w.follow_due(t0 + REFOLLOW).is_none(),
            "the next follow was due REFOLLOW after the last began, not ended"
        );
        assert!(
            w.follow_due(t0 + REFOLLOW * 100).is_some(),
            "no follow starts after the last ended"
        );
    }

    /// Of two follows that meet at the watches, the one that gets them
    /// reads the record then: a follow that waited does not put the folders
    /// of an older record over a newer one's.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_follow_that_waits_follows_the_record_as_it_is_then() {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (old, new) = (root.join("old"), root.join("new"));
        std::fs::create_dir(&old).unwrap();
        std::fs::create_dir(&new).unwrap();
        let w = Arc::new(Watch::default());
        let record = Arc::new(Mutex::new(vec![old.clone()]));
        let asked = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let held = lock(&w.linux);
        let t = {
            let (w, record, asked) = (w.clone(), record.clone(), asked.clone());
            std::thread::spawn(move || {
                w.follow_linux(
                    || {
                        asked.store(true, std::sync::atomic::Ordering::SeqCst);
                        lock(&record).clone()
                    },
                    None,
                )
            })
        };
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            !asked.load(std::sync::atomic::Ordering::SeqCst),
            "the record was read before the watches were held"
        );
        *lock(&record) = vec![new.clone()];
        drop(held);
        t.join().unwrap();
        let linux = lock(&w.linux);
        assert!(linux.watched_for_test(&old).is_empty());
        assert!(!linux.watched_for_test(&new).is_empty());
    }

    /// A watch the thread added while a granted folder was walked anew
    /// stays; one the walk did not find goes.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_folder_made_during_a_rewalk_keeps_its_watch() {
        let mut st = linux::State::default();
        st.hold_for_test("/w/p", 1, "/w/p");
        st.hold_for_test("/w/p", 2, "/w/p/old");
        // The thread's, for a folder made while the walk ran.
        st.hold_for_test("/w/p", 3, "/w/p/new");
        assert_eq!(st.renewed_for_test("/w/p", &[1, 2], &[1]), [2]);
        assert_eq!(st.watches_for_test("/w/p"), [1, 3]);
        assert_eq!(st.renewed_for_test("/w/p", &[1, 3], &[]), [1, 3]);
        assert!(st.watches_for_test("/w/p").is_empty());
    }

    /// A folder with more folders in it than the room left is not queued
    /// whole.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_folder_with_very_many_folders_is_not_queued_whole() {
        use std::os::unix::fs::MetadataExt;
        let d = tempfile::tempdir().unwrap();
        for n in 0..3 {
            std::fs::create_dir(d.path().join(format!("d{n}"))).unwrap();
        }
        std::fs::write(d.path().join("file"), "x").unwrap();
        let dev = std::fs::metadata(d.path()).unwrap().dev();
        let got = linux::subfolders_for_test(d.path(), dev, 3).unwrap();
        assert_eq!(got.len(), 3, "files are not folders");
        assert!(linux::subfolders_for_test(d.path(), dev, 2).is_none());
    }

    /// A file made with a narrow mode, as a copy across file systems leaves
    /// it, makes its granted folder due, also deep inside.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_file_copied_in_with_a_narrow_mode_makes_the_folder_due() {
        use std::os::unix::fs::OpenOptionsExt;
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let granted = root.join("granted");
        std::fs::create_dir_all(granted.join("deep")).unwrap();
        let w = Watch::default();
        w.follow_linux(|| vec![granted.clone()], None);
        let mut f = std::fs::OpenOptions::new();
        f.write(true).create_new(true).mode(0o600);
        f.open(granted.join("deep/key")).unwrap();
        assert!(soon(|| !lock(&w.pending).folders.is_empty()));
        assert_eq!(
            w.due(Instant::now() + QUIET + Duration::from_secs(1)),
            std::slice::from_ref(&granted)
        );
    }

    /// A watched folder renamed away with a link to a folder outside put at
    /// its old name: a folder made in the renamed one is named under the old
    /// path by an event that comes before the folder is watched at its new
    /// one, and must not be watched through the link.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_link_put_at_a_renamed_folders_old_name_is_not_followed() {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (granted, outside) = (root.join("granted"), root.join("outside"));
        std::fs::create_dir_all(granted.join("a")).unwrap();
        std::fs::create_dir_all(outside.join("new")).unwrap();
        let pending = Arc::new(Mutex::new(Pending::default()));
        let mut w = linux::Watches::default();
        w.follow(std::slice::from_ref(&granted), None, &pending);
        std::fs::rename(granted.join("a"), granted.join("b")).unwrap();
        std::os::unix::fs::symlink(&outside, granted.join("a")).unwrap();
        w.watch_for_test(&granted, &granted.join("a/new"));
        std::thread::sleep(Duration::from_millis(300));
        lock(&pending).folders.clear();
        std::fs::write(root.join("m"), "x").unwrap();
        std::fs::rename(root.join("m"), outside.join("new/m")).unwrap();
        std::thread::sleep(Duration::from_millis(500));
        assert!(
            lock(&pending).folders.is_empty(),
            "a folder outside the grant is watched through a link"
        );
        // A real folder below the grant is watched the same way.
        std::fs::create_dir(granted.join("b/new")).unwrap();
        w.watch_for_test(&granted, &granted.join("b/new"));
        std::thread::sleep(Duration::from_millis(300));
        lock(&pending).folders.clear();
        std::fs::write(root.join("n"), "x").unwrap();
        std::fs::rename(root.join("n"), granted.join("b/new/n")).unwrap();
        assert!(soon(|| !lock(&pending).folders.is_empty()));
    }

    /// Runs the test `name` again as root of a mount namespace of its own
    /// (a user namespace too, unless it is root already), where it may mount
    /// a file system. False where that is done or not possible here: the
    /// caller returns then. True in the re-run itself.
    #[cfg(target_os = "linux")]
    fn in_a_mount_namespace(name: &str) -> bool {
        if std::env::var_os("NERVE_TEST_IN_NS").is_some() {
            return true;
        }
        if let Err(why) = rerun_in_a_mount_namespace(&["unshare"], name) {
            eprintln!("skipped: {why}");
        }
        false
    }

    /// The re-run of [`in_a_mount_namespace`] with `unshare` (a command and
    /// its first arguments). Err where a probe shows that no mount may be
    /// made in a namespace here: AppArmor holds user namespaces back on
    /// some systems, and `unshare` then fails in more than one way.
    #[cfg(target_os = "linux")]
    fn rerun_in_a_mount_namespace(unshare: &[&str], name: &str) -> Result<(), &'static str> {
        use std::process::Command;
        // SAFETY: a plain call.
        let args: &[&str] = if unsafe { libc::geteuid() } == 0 {
            &["--mount"]
        } else {
            &["--map-root-user", "--mount"]
        };
        let namespace = || {
            let mut c = Command::new(unshare[0]);
            c.args(&unshare[1..]).args(args);
            c
        };
        let probe = namespace()
            .args([
                "sh",
                "-c",
                r#"d=$(mktemp -d) || exit 1; mount -t tmpfs none "$d"; r=$?; umount "$d" 2>/dev/null; rmdir "$d"; exit $r"#,
            ])
            .output()
            .is_ok_and(|o| o.status.success());
        if !probe {
            return Err("needs a mount namespace where the account may mount");
        }
        let test = format!("{}::{name}", module_path!().split_once("::").unwrap().1);
        crate::acl::ns::run_saying_skips(
            namespace()
                .arg(std::env::current_exe().unwrap())
                .args(["--exact", &test, "--nocapture", "--test-threads=1"])
                .env("NERVE_TEST_IN_NS", "1"),
        );
        Ok(())
    }

    /// Where the system refuses a namespace (ubuntu-24.04 does for an
    /// account with no profile: `unshare` starts, and writing its uid map is
    /// refused), the test is skipped and says so, and does not fail.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_namespace_the_system_refuses_is_a_skip_and_not_a_failure() {
        let refusing = [
            "sh",
            "-c",
            "echo 'unshare: write failed /proc/self/uid_map: Operation not permitted' >&2; exit 1",
            "unshare",
        ];
        assert!(rerun_in_a_mount_namespace(&refusing, "any_test").is_err());
    }

    /// Mounts a tmpfs on `at`.
    #[cfg(target_os = "linux")]
    fn mount_tmpfs(at: &Path) {
        let c = std::ffi::CString::new(at.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: NUL-terminated strings; a tmpfs without data.
        let r = unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                c.as_ptr(),
                c"tmpfs".as_ptr(),
                0,
                std::ptr::null(),
            )
        };
        assert_eq!(r, 0, "{}", std::io::Error::last_os_error());
    }

    /// Takes the mount on `at` away, now or when it is not busy.
    #[cfg(target_os = "linux")]
    fn unmount(at: &Path, flags: i32) -> i32 {
        let c = std::ffi::CString::new(at.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a NUL-terminated path.
        unsafe { libc::umount2(c.as_ptr(), flags) }
    }

    /// A granted folder that is a mount: unmounted, it is no place to watch
    /// (what is mounted there later would go unseen), and it is looked for
    /// until a mount is there again, when it is watched and walked. Needs
    /// the right to mount: it runs again in a namespace where it has it, and
    /// is skipped where there is none.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_granted_folder_unmounted_and_mounted_again_is_watched_again() {
        if !in_a_mount_namespace("a_granted_folder_unmounted_and_mounted_again_is_watched_again") {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let granted = root.join("drive");
        std::fs::create_dir(&granted).unwrap();
        mount_tmpfs(&granted);
        std::fs::create_dir(granted.join("sub")).unwrap();
        let pending = Arc::new(Mutex::new(Pending::default()));
        let mut w = linux::Watches::default();
        let folders = std::slice::from_ref(&granted);
        assert!(!w.follow(folders, None, &pending));
        let walked = || lock(&pending).folders.iter().any(|f| f.path == granted);
        assert_eq!(unmount(&granted, 0), 0);
        assert!(soon(walked), "an unmount walks");
        lock(&pending).folders.clear();
        assert!(w.follow(folders, None, &pending), "it is looked for again");
        assert!(
            w.follow(folders, None, &pending),
            "the bare folder is no place"
        );
        mount_tmpfs(&granted);
        std::fs::create_dir(granted.join("sub")).unwrap();
        assert!(!w.follow(folders, None, &pending), "it is watched again");
        assert!(walked(), "a drive that came walks");
        lock(&pending).folders.clear();
        std::fs::write(granted.join("m"), "x").unwrap();
        std::fs::rename(granted.join("m"), granted.join("sub/m")).unwrap();
        assert!(soon(walked), "the drive's folders are watched");
        unmount(&granted, libc::MNT_DETACH);
    }

    /// A drive mounted over a granted folder that the node already watches
    /// as a plain, empty folder (the drive came after the node started)
    /// gives no event: the next follow sees that the path is another object
    /// now, walks the folder and watches what is mounted.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_drive_mounted_over_a_watched_granted_folder_is_watched_instead() {
        if !in_a_mount_namespace("a_drive_mounted_over_a_watched_granted_folder_is_watched_instead")
        {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let granted = root.join("drive");
        std::fs::create_dir(&granted).unwrap();
        let pending = Arc::new(Mutex::new(Pending::default()));
        let mut w = linux::Watches::default();
        let folders = std::slice::from_ref(&granted);
        assert!(!w.follow(folders, None, &pending));
        mount_tmpfs(&granted);
        std::fs::create_dir(granted.join("sub")).unwrap();
        lock(&pending).folders.clear();
        assert!(!w.follow(folders, None, &pending));
        assert!(
            lock(&pending).folders.iter().any(|f| f.path == granted),
            "a drive that came walks"
        );
        lock(&pending).folders.clear();
        std::fs::write(granted.join("m"), "x").unwrap();
        std::fs::rename(granted.join("m"), granted.join("sub/m")).unwrap();
        assert!(
            soon(|| !lock(&pending).folders.is_empty()),
            "the drive's folders are watched"
        );
        unmount(&granted, libc::MNT_DETACH);
    }

    /// A watched granted folder is compared with what its path is now: the
    /// same object, another one (a file system mounted over it), or none
    /// that can be said.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_granted_folder_that_is_another_object_now_is_watched_anew() {
        let mut st = linux::State::default();
        st.object_for_test("/m/usb", (7, 100));
        st.object_for_test("/m/other", (7, 200));
        assert!(
            st.covered_for_test(|p| Some(if p.ends_with("usb") {
                (7, 100)
            } else {
                (7, 200)
            }))
            .is_empty()
        );
        assert!(!st.is_stale_for_test("/m/usb"));
        let covered = st.covered_for_test(|p| p.ends_with("usb").then_some((9, 2)));
        assert_eq!(covered, [PathBuf::from("/m/usb")]);
        assert!(st.is_stale_for_test("/m/usb"));
        assert!(!st.is_stale_for_test("/m/other"), "not told: left alone");
    }

    /// A mount point that was ungranted while it was unmounted is a plain
    /// folder when it is granted again: it is watched, not held bare.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_mount_forgotten_with_its_grant_is_not_held_against_the_plain_folder() {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let granted = root.join("usb");
        std::fs::create_dir(&granted).unwrap();
        let pending = Arc::new(Mutex::new(Pending::default()));
        let mut w = linux::Watches::default();
        w.follow(std::slice::from_ref(&granted), None, &pending);
        w.follow(&[], None, &pending);
        // It was a mount point, and its drive is gone: not held, but
        // remembered bare, as the watch leaves it.
        w.remember_mount_for_test(&granted);
        w.follow(&[], None, &pending);
        assert!(
            !w.follow(std::slice::from_ref(&granted), None, &pending),
            "a plain folder is watched"
        );
        assert!(w.watching());
    }

    /// No folder whose path is as long as the limit is watched, nor
    /// anything below it; a folder made inside the limit is.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_chain_of_folders_longer_than_a_path_is_not_watched() {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let granted = root.join("granted");
        std::fs::create_dir_all(granted.join("a/b/c/d/e")).unwrap();
        // "/a/b/c" is inside the limit, "/a/b/c/d" is not.
        let mut w = linux::Watches::with_longest(granted.as_os_str().len() + 8);
        let pending = Arc::new(Mutex::new(Pending::default()));
        w.follow(std::slice::from_ref(&granted), None, &pending);
        let inside = [
            granted.clone(),
            granted.join("a"),
            granted.join("a/b"),
            granted.join("a/b/c"),
        ];
        assert_eq!(w.watched_for_test(&granted), inside);
        std::fs::create_dir(granted.join("z")).unwrap();
        w.watch_for_test(&granted, &granted.join("z"));
        w.watch_for_test(&granted, &granted.join("a/b/c/d"));
        let mut want = inside.to_vec();
        want.push(granted.join("z"));
        assert_eq!(w.watched_for_test(&granted), want);
    }
}
