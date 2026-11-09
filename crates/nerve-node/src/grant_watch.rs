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
//! turn), so it never races a change of the config.
//!
//! On Linux a new file in a granted folder gets its ACL entries from the
//! folder's default entries, and a file with a second name gets none and
//! keeps its own rights (crate::acl), so nothing waits for a walk there.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nerve_policy::paths::within;

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

/// The granted folders whose names changed and that are not walked yet.
#[derive(Debug, Default)]
pub struct Pending {
    folders: Vec<Changed>,
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
    /// whose names were quiet for [`QUIET`], or that waits [`AT_MOST`]. A
    /// folder inside one of them goes along, due or not, as its walk goes
    /// through it; of the folders due, only the outermost are named.
    pub fn due(&mut self, now: Instant) -> Vec<PathBuf> {
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
    pub fn due(&self, now: Instant) -> Vec<PathBuf> {
        lock(&self.pending).due(now)
    }

    /// Watches `folders` from now on, and no other: a new one is opened as
    /// `act` acts (the owner, whose folders they are, on the installed
    /// service), one no longer granted is closed. A folder that could not
    /// be opened is not tried again while it stays granted; the log says
    /// why, once.
    #[cfg(windows)]
    pub fn follow<G>(&self, folders: &[PathBuf], act: impl FnOnce() -> std::io::Result<G>) {
        lock(&self.win).follow(folders, &self.pending, act);
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
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

    use super::{NOTIFY, Pending, lock, wakes};

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
        /// The folders watched now.
        watched: Vec<PathBuf>,
        /// The folders that could not be opened, and are not tried again
        /// while they stay granted.
        failed: HashSet<PathBuf>,
        /// The folders whose watch ended (gone, or an error): watched again
        /// at the next follow where they are still granted.
        ended: Arc<Mutex<Vec<PathBuf>>>,
    }

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
            folders: &[PathBuf],
            pending: &Arc<Mutex<Pending>>,
            act: impl FnOnce() -> std::io::Result<G>,
        ) {
            let ended: Vec<PathBuf> = std::mem::take(&mut *lock(&self.ended));
            self.watched.retain(|w| !ended.contains(w));
            self.failed.retain(|f| folders.contains(f));
            let gone: Vec<PathBuf> = self
                .watched
                .iter()
                .filter(|w| !folders.contains(w))
                .cloned()
                .collect();
            self.watched.retain(|w| folders.contains(w));
            let new: Vec<&PathBuf> = folders
                .iter()
                .filter(|f| !self.watched.contains(f) && !self.failed.contains(*f))
                .collect();
            if let Some(r) = &self.running {
                for g in gone {
                    r.send(Msg::Close(g));
                }
            }
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
                        self.failed.extend(new.into_iter().cloned());
                        return;
                    }
                }
            }
            // Opened as the owner, whose folders they are; the handle keeps
            // what it was opened with.
            let _as = act()
                .inspect_err(|e| tracing::warn!("folder grants: {e}"))
                .ok();
            for f in new {
                match open(f) {
                    Ok(h) => {
                        self.watched.push(f.clone());
                        if let Some(r) = &self.running {
                            r.send(Msg::Open(f.clone(), h));
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "folder grants: {} is not watched ({e}); what is installed or moved into it gets its entries at the next start, change or Sync folders",
                            f.display()
                        );
                        self.failed.insert(f.clone());
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
    /// and not one on a removable drive.
    fn open(path: &Path) -> std::io::Result<OwnedHandle> {
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
        Ok(h)
    }

    fn start(
        pending: Arc<Mutex<Pending>>,
        ended: Arc<Mutex<Vec<PathBuf>>>,
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
        fn read(&mut self) -> std::io::Result<()> {
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

    fn run(port: HANDLE, rx: Receiver<Msg>, pending: &Mutex<Pending>, ended: &Mutex<Vec<PathBuf>>) {
        let mut slots: HashMap<usize, Slot> = HashMap::new();
        let mut next = WAKE + 1;
        let mut stopping = false;
        let end = |slot: &Slot| {
            lock(pending).changed(&slot.path, Instant::now());
            lock(ended).push(slot.path.clone());
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
                std::mem::forget(slots);
                return;
            }
            if key == WAKE {
                while let Ok(m) = rx.try_recv() {
                    match m {
                        Msg::Open(path, dir) => {
                            let k = next;
                            next += 1;
                            // SAFETY: a valid handle and the port.
                            if unsafe { CreateIoCompletionPort(dir.as_raw_handle(), port, k, 0) }
                                .is_null()
                            {
                                tracing::warn!(
                                    "folder grants: {} is not watched ({})",
                                    path.display(),
                                    std::io::Error::last_os_error()
                                );
                                continue;
                            }
                            let mut slot = Slot {
                                path,
                                dir,
                                ov: Box::default(),
                                buf: vec![0u32; BUF / 4].into_boxed_slice(),
                                closing: false,
                            };
                            match slot.read() {
                                Ok(()) => {
                                    slots.insert(k, slot);
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "folder grants: {} is not watched ({e})",
                                        slot.path.display()
                                    );
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
            if slot.read().is_err() {
                end(slot);
                slots.remove(&key);
            }
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
        w.follow(std::slice::from_ref(&root), || Ok(()));
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
        w.follow(&[], || Ok(()));
        std::thread::sleep(Duration::from_millis(200));
        std::fs::remove_dir_all(&root).unwrap();
        assert!(quiet(&w));
    }
}
