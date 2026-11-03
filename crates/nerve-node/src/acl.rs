//! The folder grants of the installed Linux node as POSIX ACLs
//! (docs/user/modes.md). Its commands of `folder` and `allowlist` mode run as
//! `nerve-run` (crate::account), which reaches the owner's files only through
//! the entries this module puts on the folders the owner gives a center:
//! an access entry `user:nerve-run` on the folder and on everything below it
//! with the rights of its flags, and on each folder below a default entry
//! for it and one for the owner, so that what either makes there stays
//! usable for the other. The owner's files keep their owner; the group bits
//! `ls -l` shows are the ACL's mask then, and taking the entries off again
//! gives them back their mode. Landlock holds each command to its own
//! pairing's folders on top (crate::exec::landlock_spec): the account is one
//! for all pairings, so its entries are the union of every pairing's grants.
//!
//! A folder of the owner's above a grant that others may not enter gets an
//! entry that lets `nerve-run` pass through it. With Landlock that is all
//! it does there; without, `nerve-run` reaches through it whatever below is
//! open to others, which the node tells (crate::account::home_warning). A
//! default ACL of the owner's own on a folder below a grant keeps its plain
//! entries and the owner's own entry when the grant goes
//! ([`Record::defaults`], [`Record::own_entries`]); one the node made goes
//! ([`Record::made_defaults`]). The node
//! changes only what the owner owns, acting with the owner's file system
//! ids (crate::account::FsAs): a file of anyone else's is left as it is, and
//! so is a link and what lies on another file system below a grant. A file
//! with a second name, which may lie outside the folder, gets no entry, and
//! one it has comes off.
//!
//! A command of `nerve-run` may change the folders it may write while the
//! node walks them, and put a link where a folder was. So the walk never
//! goes by a path twice: it opens each entry once, without following a
//! link, from the descriptor of the folder it lies in, and reads and writes
//! the entries through that descriptor. A link on the way to a granted
//! folder, which its real path (crate::exec::folder_sets) did not have, makes
//! that grant fail.
//!
//! What `nerve-run` made in a granted folder is its own, and keeps the
//! entries it got there from the folder's default entries after the grant
//! went: the owner may not change another account's files, and `nerve-run`
//! has every right on its own files whatever their entries say. What keeps
//! it from them then is that it can no longer get there, through the
//! owner's folders above that lost its entries. `uninstall`, as root, takes
//! the entries off them too, before the account's uid is freed.
//!
//! The node keeps a record of what it gave (`acl.json` in its state
//! folder), so that it takes the entries off again after the config
//! changed, also while it did not run, and `uninstall` takes them all off.
//! It brings them in line at its start, when its config changes, and before
//! a command of `nerve-run` runs; a folder whose grant did not change is not
//! walked again, as its default entries give new files theirs.
//!
//! The entries are written as the kernel keeps them, in the extended
//! attributes `system.posix_acl_access` and `system.posix_acl_default`, so
//! no tool is needed. A file system without ACLs refuses them, and the grant
//! of that folder fails with that reason.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ffi::{CStr, CString, OsString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;

use nerve_policy::config::{Access, NodeConfig};
use nerve_policy::paths::within;
use nerve_policy::protected::Platform;
use serde::{Deserialize, Serialize};

use crate::paths::NodePaths;

const VERSION: u32 = 2;
const USER_OBJ: u16 = 0x01;
const USER: u16 = 0x02;
const GROUP_OBJ: u16 = 0x04;
const GROUP: u16 = 0x08;
const MASK: u16 = 0x10;
const OTHER: u16 = 0x20;
const NO_ID: u32 = u32::MAX;
const ACCESS: &str = "system.posix_acl_access";
const DEFAULT: &str = "system.posix_acl_default";

const R: u16 = 4;
const W: u16 = 2;
const X: u16 = 1;

/// One entry of an ACL: what it is for (`tag`, `id`) and its rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub tag: u16,
    pub id: u32,
    pub perm: u16,
}

/// An ACL as the kernel keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Acl(pub Vec<Entry>);

impl Acl {
    /// The ACL a file without one has: its mode.
    pub fn of_mode(mode: u32) -> Acl {
        let bits = |shift: u32| ((mode >> shift) & 7) as u16;
        Acl(vec![
            Entry {
                tag: USER_OBJ,
                id: NO_ID,
                perm: bits(6),
            },
            Entry {
                tag: GROUP_OBJ,
                id: NO_ID,
                perm: bits(3),
            },
            Entry {
                tag: OTHER,
                id: NO_ID,
                perm: bits(0),
            },
        ])
    }

    /// The ACL in an extended attribute's bytes.
    pub fn parse(b: &[u8]) -> Result<Acl, String> {
        let bad = || "not a POSIX ACL".to_string();
        let head = b.get(..4).ok_or_else(bad)?;
        if u32::from_le_bytes(head.try_into().map_err(|_| bad())?) != VERSION
            || !(b.len() - 4).is_multiple_of(8)
        {
            return Err(bad());
        }
        let entries = b[4..]
            .chunks(8)
            .map(|c| Entry {
                tag: u16::from_le_bytes([c[0], c[1]]),
                perm: u16::from_le_bytes([c[2], c[3]]),
                id: u32::from_le_bytes([c[4], c[5], c[6], c[7]]),
            })
            .collect();
        Ok(Acl(entries))
    }

    /// The bytes of the extended attribute, in the order the kernel wants:
    /// by tag, the named entries by id.
    pub fn bytes(&self) -> Vec<u8> {
        let mut entries = self.0.clone();
        entries.sort_by_key(|e| (e.tag, e.id));
        let mut b = VERSION.to_le_bytes().to_vec();
        for e in entries {
            b.extend(e.tag.to_le_bytes());
            b.extend(e.perm.to_le_bytes());
            b.extend(e.id.to_le_bytes());
        }
        b
    }

    /// The rights of the named entry for `uid`.
    pub fn user(&self, uid: u32) -> Option<u16> {
        self.0
            .iter()
            .find(|e| e.tag == USER && e.id == uid)
            .map(|e| e.perm)
    }

    fn get(&self, tag: u16) -> Option<u16> {
        self.0.iter().find(|e| e.tag == tag).map(|e| e.perm)
    }

    /// Whether it has a named entry, which needs a mask.
    pub fn has_named(&self) -> bool {
        self.0.iter().any(|e| e.tag == USER || e.tag == GROUP)
    }

    /// Sets the named entry for `uid` to `perm`, or takes it off. The mask
    /// grows to let the entry's rights through, and goes once no named entry
    /// is left: it never narrows what the others had.
    pub fn set_user(&mut self, uid: u32, perm: Option<u16>) {
        self.0.retain(|e| !(e.tag == USER && e.id == uid));
        if let Some(p) = perm {
            self.0.push(Entry {
                tag: USER,
                id: uid,
                perm: p,
            });
        }
        if !self.has_named() {
            self.0.retain(|e| e.tag != MASK);
            return;
        }
        let mask = match (self.get(MASK), perm) {
            (Some(m), Some(p)) => m | p,
            (Some(m), None) => m,
            (None, p) => self.get(GROUP_OBJ).unwrap_or(0) | p.unwrap_or(0),
        };
        self.0.retain(|e| e.tag != MASK);
        self.0.push(Entry {
            tag: MASK,
            id: NO_ID,
            perm: mask,
        });
    }
}

/// The rights `access` gives on a folder: reading lists and enters it,
/// writing makes and removes entries (and enters it), running enters it.
pub fn dir_perm(access: Access) -> u16 {
    let mut p = 0;
    if access.read {
        p |= R | X;
    }
    if access.write {
        p |= W | X;
    }
    if access.execute {
        p |= X;
    }
    p
}

/// The rights `access` gives on a file of `mode`: running only a file that
/// someone may run already.
pub fn file_perm(access: Access, mode: u32) -> u16 {
    let mut p = 0;
    if access.read {
        p |= R;
    }
    if access.write {
        p |= W;
    }
    if access.execute && mode & 0o111 != 0 {
        p |= X;
    }
    p
}

/// What the node gave `nerve-run`, as its record keeps it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// The uid the entries are for: the `nerve-run` of when they were put on.
    pub uid: u32,
    /// The owner whose files carry them.
    #[serde(default)]
    pub owner: u32,
    /// The granted folders and their flags.
    #[serde(default)]
    pub grants: Vec<Granted>,
    /// The folders above them it may pass through.
    #[serde(default)]
    pub traverse: Vec<PathBuf>,
    /// The granted folders whose entries could not all be put on: tried
    /// again, also after the node started again (crate::daemon).
    #[serde(default)]
    pub failed: Vec<PathBuf>,
    /// The folders below the grants whose default ACL was the owner's own
    /// before the node added its entries to it: it stays when they come off
    /// again. A folder made later below one of them got it from there, and
    /// keeps it too.
    #[serde(default)]
    pub defaults: Vec<PathBuf>,
    /// The folders among `defaults` whose default ACL had a named entry for
    /// the owner of the owner's own: the node leaves it as it is, and it
    /// stays when the grant goes. A folder made later below one of them got
    /// it from there.
    #[serde(default)]
    pub own_entries: Vec<PathBuf>,
    /// The folders below one of `defaults` that had no default ACL before
    /// the grant: the one the node made goes again with it, and so does the
    /// one a folder made later below them got from there.
    #[serde(default)]
    pub made_defaults: Vec<PathBuf>,
    /// Grants of an earlier owner or `nerve-run` whose entries could not all
    /// be taken off after the accounts changed ([`sync`]): walked again at
    /// each sync, and by `uninstall` as root. No command of `nerve-run` runs
    /// while one is left.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub left: Vec<Left>,
}

/// A grant of earlier accounts still to come off ([`Record::left`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Left {
    pub path: PathBuf,
    /// The `nerve-run` and the owner of when its entries were put on.
    pub run: u32,
    pub owner: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Granted {
    pub path: PathBuf,
    pub access: Access,
}

/// The record's file in the state folder.
pub fn record_file(paths: &NodePaths) -> PathBuf {
    paths.state_dir.join("acl.json")
}

fn read_record(file: &Path) -> Result<Option<Record>, String> {
    match std::fs::read(file) {
        Ok(b) => serde_json::from_slice(&b)
            .map(Some)
            .map_err(|e| format!("{}: {e}", file.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", file.display())),
    }
}

fn write_record(file: &Path, r: &Record) -> Result<(), String> {
    let text = serde_json::to_vec_pretty(r).map_err(|e| e.to_string())?;
    nerve_transport::files::write_private(file, &text)
        .map_err(|e| format!("{}: {e}", file.display()))
}

/// The folders the config gives the account, with the union of their flags
/// over every pairing whose commands run as it at `now_ms`: each pairing's
/// folders as its sandbox has them (crate::exec::container_grants), its
/// protected entries and the node's own folders left out, `~` the owner's
/// `home`. A pairing whose commands run as the owner (user mode, allowlist
/// mode as the owner) gives `nerve-run` none of its folders.
pub fn wanted(cfg: &NodeConfig, paths: &NodePaths, home: &Path, now_ms: u64) -> Vec<Granted> {
    let own = paths.own();
    let writable = crate::exec::write_folders(cfg, home);
    let mut by_path: BTreeMap<PathBuf, Access> = BTreeMap::new();
    for c in cfg
        .centers
        .iter()
        .filter(|c| !c.policy.runs_as_owner(now_ms))
    {
        for (path, a) in
            crate::exec::container_grants(&c.policy, home, &own, &Platform::Unix, &writable)
        {
            let e = by_path.entry(path).or_insert(Access::NONE);
            e.read |= a.read;
            e.write |= a.write;
            e.execute |= a.execute;
        }
    }
    by_path
        .into_iter()
        .filter(|(_, a)| *a != Access::NONE)
        .map(|(path, access)| Granted { path, access })
        .collect()
}

/// What a sync did and left.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    /// Each change that failed.
    pub errors: Vec<String>,
    /// Folders whose entries could not be taken off, or not all of them:
    /// `nerve-run` may still reach there. No command of it runs while one
    /// is left.
    pub stale: Vec<PathBuf>,
    /// Granted folders whose entries could not all be put on: `nerve-run`
    /// may not reach all of them. Tried again (crate::daemon).
    pub failed: Vec<PathBuf>,
    /// Files and folders left as they are: another account's, with a
    /// second name, or on another file system.
    pub skipped: usize,
    /// Of those at `uninstall`: what `nerve-run` owns there that is no
    /// folder and has a second name, which may lie outside every grant. It
    /// is not given to the owner, as ownership goes with the file and not
    /// the name, so it keeps `nerve-run`'s uid (crate::service says so).
    /// Counted by file, not by name or walk.
    pub not_given: usize,
    /// The files (device, inode) in `not_given`, as a file lies under
    /// more than one name and in more than one grant.
    twins: HashSet<(u64, u64)>,
}

impl Report {
    /// Why no command of `nerve-run` may run now, if it may not.
    pub fn refusal(&self) -> Option<String> {
        (!self.stale.is_empty()).then(|| {
            format!(
                "the command was not run: the access of nerve-run to {} could not be taken off ({})",
                self.stale
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                self.errors.join("; ")
            )
        })
    }
}

/// The ACL of the file `at` leads to (access or default), `None` where it
/// has none. `at` is the path of an open descriptor ([`Opened::at`]).
fn get(at: &CStr, name: &str) -> std::io::Result<Option<Acl>> {
    let name = CString::new(name).expect("no NUL");
    let mut buf = vec![0u8; 512];
    loop {
        // SAFETY: a NUL-terminated path and name, and a buffer of its length.
        let n = unsafe {
            libc::getxattr(
                at.as_ptr(),
                name.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if n >= 0 {
            buf.truncate(n as usize);
            return Acl::parse(&buf).map(Some).map_err(std::io::Error::other);
        }
        let e = std::io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::ENODATA) => return Ok(None),
            Some(libc::ERANGE) if buf.len() < 1 << 20 => buf.resize(buf.len() * 4, 0),
            _ => return Err(e),
        }
    }
}

fn set(at: &CStr, name: &str, acl: &Acl) -> std::io::Result<()> {
    let name = CString::new(name).expect("no NUL");
    let b = acl.bytes();
    // SAFETY: a NUL-terminated path and name, and the bytes with their length.
    let r = unsafe { libc::setxattr(at.as_ptr(), name.as_ptr(), b.as_ptr().cast(), b.len(), 0) };
    if r == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn remove(at: &CStr, name: &str) -> std::io::Result<()> {
    let name = CString::new(name).expect("no NUL");
    // SAFETY: a NUL-terminated path and name.
    let r = unsafe { libc::removexattr(at.as_ptr(), name.as_ptr()) };
    if r == 0 {
        return Ok(());
    }
    let e = std::io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::ENODATA) {
        return Ok(());
    }
    Err(e)
}

/// A file or folder opened without following it (`O_PATH`), and what it
/// was when it was opened.
struct Opened {
    file: std::fs::File,
    m: std::fs::Metadata,
}

impl Opened {
    /// A path that leads to this very file, whatever is done to its own
    /// path meanwhile.
    fn path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
    }

    fn at(&self) -> CString {
        CString::new(self.path().into_os_string().into_vec()).expect("no NUL")
    }

    /// The names in the folder.
    fn names(&self) -> std::io::Result<Vec<OsString>> {
        std::fs::read_dir(self.path())?
            .map(|e| e.map(|e| e.file_name()))
            .collect()
    }
}

/// Opens the entry `name` of the folder `dir` without following it.
fn open_in(dir: libc::c_int, name: &CStr) -> std::io::Result<Opened> {
    // Through libc, not `OpenOptions`: on musl the standard library takes
    // O_PATH out of the flags (crate::service's `chown_entry` says more).
    // SAFETY: a NUL-terminated name; the new descriptor is owned below.
    let fd = unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: openat returned a fresh descriptor nothing else owns.
    let file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    let m = file.metadata()?;
    Ok(Opened { file, m })
}

/// Opens the absolute path `p` a folder at a time, following no link on
/// the way. The grants' paths are real ones (crate::exec::folder_sets), so a
/// link on the way came later, and a command may have put it there. The
/// last part is opened as it is: a link there is the caller's to see.
fn open_path(p: &Path) -> std::io::Result<Opened> {
    let bad = |why: &str| std::io::Error::new(std::io::ErrorKind::InvalidInput, why.to_string());
    let mut parts = p.components();
    if parts.next() != Some(Component::RootDir) {
        return Err(bad("not an absolute path"));
    }
    let mut at = open_in(libc::AT_FDCWD, c"/")?;
    let mut so_far = PathBuf::from("/");
    for part in parts {
        let Component::Normal(name) = part else {
            return Err(bad("not a plain path"));
        };
        if !at.m.is_dir() {
            return Err(std::io::Error::other(format!(
                "{} is a link or a file now, which it was not when the folder was given; nothing below it was changed",
                so_far.display()
            )));
        }
        let name = CString::new(name.as_bytes()).map_err(|_| bad("a NUL in the path"))?;
        at = open_in(at.file.as_raw_fd(), &name)?;
        so_far.push(part);
    }
    Ok(at)
}

#[cfg(test)]
fn c_path(p: &Path) -> std::io::Result<CString> {
    CString::new(p.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "a NUL in the path"))
}

/// What an error on `path` says, with the reason for a file system that
/// has no ACLs.
fn failed(path: &Path, e: &std::io::Error) -> String {
    if e.raw_os_error() == Some(libc::EOPNOTSUPP) {
        format!(
            "{}: its file system does not support POSIX ACLs, so nerve-run cannot be given it; give a folder on another file system (ext4, xfs, btrfs and tmpfs have them)",
            path.display()
        )
    } else {
        format!("{}: {e}", path.display())
    }
}

/// The accounts a sync is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Who {
    /// `nerve-run`.
    pub run: u32,
    /// The owner, whose files alone are changed.
    pub owner: u32,
}

/// What a folder's default ACL holds of the owner's own, besides the
/// node's entries: its plain entries (`plain`), and a named entry for the
/// owner (`entry`). Both stay when the node's entries come off.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Own {
    plain: bool,
    entry: bool,
}

/// What [`put`] found and did on a folder.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Put {
    /// What of its default ACL is the owner's own now.
    own: Own,
    /// It had no default ACL, and the node made one.
    made: bool,
}

/// Gives `who.run` on the opened `o` the access entry `perm` (`None` takes
/// it off), and on a folder the default entries for it and the owner. On a
/// folder that is not the owner's (`mine`), only taken off, the owner's
/// default entry stays: it came from the default entries above.
///
/// A default ACL without an entry of `who.run` is not the node's, and is
/// left as it is where nothing is to be given. Where the node's entries come
/// off, what is left of it stays as far as it was the owner's own before
/// (`keep`, [`Own`]), as a default ACL of the plain entries still sets the
/// rights new files get; one the node made goes. A named entry the owner had
/// for itself is never changed.
fn put(o: &Opened, who: Who, perm: Option<u16>, mine: bool, keep: Own) -> std::io::Result<Put> {
    let at = o.at();
    let mut acl = get(&at, ACCESS)?.unwrap_or_else(|| Acl::of_mode(o.m.mode()));
    if acl.user(who.run) != perm {
        acl.set_user(who.run, perm);
        set(&at, ACCESS, &acl)?;
    }
    if !o.m.is_dir() {
        return Ok(Put::default());
    }
    let before = get(&at, DEFAULT)?;
    let theirs = before.as_ref().is_some_and(|b| b.user(who.run).is_none());
    let own = match &before {
        Some(b) if theirs => Own {
            plain: true,
            entry: b.user(who.owner).is_some(),
        },
        Some(_) => keep,
        None => Own::default(),
    };
    let done = Put { own, made: false };
    if perm.is_none() && (before.is_none() || theirs) {
        return Ok(done);
    }
    let mut d = before.clone().unwrap_or_else(|| Acl::of_mode(o.m.mode()));
    d.set_user(who.run, perm);
    if mine && !own.entry {
        d.set_user(who.owner, perm.map(|_| R | W | X));
    }
    if !d.has_named() && !own.plain {
        if before.is_some() {
            remove(&at, DEFAULT)?;
        }
    } else if before.as_ref() != Some(&d) {
        set(&at, DEFAULT, &d)?;
    }
    // Only below a default ACL of the owner's is that worth a note: else
    // nothing of it is kept anyway.
    Ok(Put {
        made: before.is_none() && perm.is_some() && keep.plain,
        ..done
    })
}

/// Gives the opened `o`, which `who.run` owns, to `to` (uid, gid): what
/// `nerve-run` made in a granted folder goes to the owner at `uninstall`,
/// as its uid is freed next and the next account to get it must not own
/// it. Through the descriptor (`AT_EMPTY_PATH`), so the file changed is the
/// one checked, also a link.
fn give(o: &Opened, to: (u32, u32)) -> std::io::Result<()> {
    // SAFETY: an empty NUL-terminated path with AT_EMPTY_PATH on an open
    // descriptor: the call changes that inode.
    let r = unsafe {
        libc::fchownat(
            o.file.as_raw_fd(),
            c"".as_ptr(),
            to.0,
            to.1,
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Gives or takes the pass-through entry (`--x`) of a folder above a grant.
fn pass(path: &Path, who: Who, on: bool) -> std::io::Result<()> {
    let o = open_path(path)?;
    if !o.m.is_dir() {
        return Err(std::io::Error::other("it is no folder now"));
    }
    if on && o.m.uid() != who.owner {
        return Err(std::io::Error::other("it is not yours now"));
    }
    let at = o.at();
    let mut acl = get(&at, ACCESS)?.unwrap_or_else(|| Acl::of_mode(o.m.mode()));
    let want = on.then_some(X);
    if acl.user(who.run) != want {
        acl.set_user(who.run, want);
        set(&at, ACCESS, &acl)?;
    }
    Ok(())
}

/// The flags of the grants among `all` that cover `path`, joined.
fn covering(all: &[Granted], path: &Path) -> Access {
    let mut a = Access::NONE;
    for g in all.iter().filter(|g| within(path, &g.path)) {
        a.read |= g.access.read;
        a.write |= g.access.write;
        a.execute |= g.access.execute;
    }
    a
}

#[cfg(test)]
type Hook = Box<dyn FnMut(&Path)>;

#[cfg(test)]
thread_local! {
    /// Runs in [`walk`] after an entry was changed and before its folder is
    /// read: a test changes the tree there, as a command may meanwhile.
    static CHANGED: std::cell::RefCell<Option<Hook>> =
        const { std::cell::RefCell::new(None) };
}

/// What the walks know of the folders' default ACLs, kept in the record
/// ([`Record::defaults`], [`Record::own_entries`], [`Record::made_defaults`]).
#[derive(Debug, Default)]
struct Defaults {
    own: BTreeSet<PathBuf>,
    entries: BTreeSet<PathBuf>,
    made: BTreeSet<PathBuf>,
}

impl Defaults {
    fn of(r: &Record) -> Defaults {
        let set = |v: &[PathBuf]| v.iter().cloned().collect();
        Defaults {
            own: set(&r.defaults),
            entries: set(&r.own_entries),
            made: set(&r.made_defaults),
        }
    }

    /// What of the default ACL of `path` is the owner's: as the record
    /// knows it, else as it came from the folder above (`above`).
    fn keep(&self, path: &Path, above: Own) -> Own {
        if self.own.contains(path) {
            Own {
                plain: true,
                entry: self.entries.contains(path),
            }
        } else if self.made.contains(path) {
            Own::default()
        } else {
            above
        }
    }

    /// What `put` found on `path`, taken in.
    fn note(&mut self, path: &Path, p: Put, revoked: bool) {
        let flag = |set: &mut BTreeSet<PathBuf>, on: bool| {
            if on {
                set.insert(path.to_path_buf());
            } else {
                set.remove(path);
            }
        };
        flag(&mut self.own, p.own.plain);
        flag(&mut self.entries, p.own.plain && p.own.entry);
        if p.made {
            self.made.insert(path.to_path_buf());
        } else if revoked || p.own.plain {
            self.made.remove(path);
        }
    }
}

/// How a [`walk`] went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Walked {
    /// Every change it tried went through.
    whole: bool,
    /// It saw everything below its root: it skipped no folder on another
    /// file system and none the owner may not list. Only then does it stand
    /// for a grant inside, whose entries could lie there.
    seen_all: bool,
}

/// Brings the entries below `root` in line with `all` (what every grant now
/// gives there), walking it without following links or leaving its file
/// system. Only the owner's files are changed. With `everyone` (root at
/// `uninstall`, `all` empty) the entries of `who.run` come off anyone's, and
/// what `who.run` owns goes to `everyone` (uid, gid). `defaults` is what is
/// known of the default ACLs, kept up to date. Errors go to `report`; the
/// walk goes on.
fn walk(
    root: &Path,
    all: &[Granted],
    who: Who,
    everyone: Option<(u32, u32)>,
    defaults: &mut Defaults,
    report: &mut Report,
) -> Walked {
    let top = match open_path(root) {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Walked {
                whole: true,
                seen_all: true,
            };
        }
        Err(e) => {
            report.errors.push(failed(root, &e));
            return Walked {
                whole: false,
                seen_all: false,
            };
        }
    };
    let dev = top.m.dev();
    let mut whole = true;
    let mut seen_all = true;
    // The entries of a folder are opened when their turn comes, from the
    // folder's descriptor, so only the folders on the way are held open.
    // With each goes what of its folder's default ACL was the owner's.
    let mut stack: Vec<(Rc<Opened>, OsString, PathBuf, Own)> = Vec::new();
    let mut next = Some((root.to_path_buf(), top, Own::default()));
    loop {
        let (path, o, above) = match next.take() {
            Some(n) => n,
            None => {
                let Some((dir, name, path, above)) = stack.pop() else {
                    break;
                };
                let Ok(c) = CString::new(name.as_bytes()) else {
                    continue;
                };
                match open_in(dir.file.as_raw_fd(), &c) {
                    Ok(o) => (path, o, above),
                    // Gone meanwhile.
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => {
                        report.errors.push(failed(&path, &e));
                        whole = false;
                        continue;
                    }
                }
            }
        };
        let ft = o.m.file_type();
        // What is no folder and has a second name may lie outside every
        // grant, as for its entries below: it is not given away either.
        let twin = !ft.is_dir() && o.m.nlink() > 1;
        if let Some(to) = everyone
            && o.m.uid() == who.run
            && o.m.dev() == dev
        {
            if twin {
                if report.twins.insert((o.m.dev(), o.m.ino())) {
                    report.not_given += 1;
                }
            } else if let Err(e) = give(&o, to) {
                report.errors.push(failed(&path, &e));
                whole = false;
            }
        }
        if ft.is_symlink() || o.m.dev() != dev || !(ft.is_dir() || ft.is_file()) {
            if ft.is_dir() {
                seen_all = false;
            }
            report.skipped += 1;
            continue;
        }
        let mine = o.m.uid() == who.owner;
        let keep = defaults.keep(&path, above);
        let mut own_here = keep;
        if mine || everyone.is_some() {
            // A file with a second name may lie outside the grant: it gets
            // no entry, and one it has comes off.
            let a = if twin || !mine {
                Access::NONE
            } else {
                covering(all, &path)
            };
            let perm = if ft.is_dir() {
                dir_perm(a)
            } else {
                file_perm(a, o.m.mode())
            };
            if twin {
                report.skipped += 1;
            }
            match put(&o, who, (perm != 0).then_some(perm), mine, keep) {
                Ok(p) if ft.is_dir() => {
                    own_here = p.own;
                    defaults.note(&path, p, perm == 0);
                }
                Ok(_) => {}
                Err(e) => {
                    report.errors.push(failed(&path, &e));
                    whole = false;
                    if e.raw_os_error() == Some(libc::EOPNOTSUPP) {
                        return Walked {
                            whole: false,
                            seen_all: false,
                        };
                    }
                }
            }
        } else {
            report.skipped += 1;
        }
        #[cfg(test)]
        CHANGED.with(|h| {
            if let Some(f) = h.borrow_mut().as_mut() {
                f(&path)
            }
        });
        if ft.is_dir() {
            match o.names() {
                Ok(names) => {
                    let dir = Rc::new(o);
                    for n in names {
                        let p = path.join(&n);
                        stack.push((dir.clone(), n, p, own_here));
                    }
                }
                // Another account's folder the owner may not read.
                Err(_) if !mine && everyone.is_none() => seen_all = false,
                Err(e) => {
                    report.errors.push(failed(&path, &e));
                    whole = false;
                    seen_all = false;
                }
            }
        }
    }
    Walked { whole, seen_all }
}

/// The grant among `all` nearest above `path`, which is no grant itself.
fn granted_above<'a>(all: &'a [Granted], path: &Path) -> Option<&'a Path> {
    all.iter()
        .map(|g| g.path.as_path())
        .filter(|g| *g != path && within(path, g))
        .max_by_key(|g| g.components().count())
}

/// The folders above the grants of `all` that `who.run` must pass through:
/// the owner's that others may not enter and that no grant covers. A folder
/// of anyone else's that it cannot enter makes its grant fail (`missed`).
fn traverse(
    all: &[Granted],
    who: Who,
    report: &mut Report,
    missed: &mut Vec<PathBuf>,
) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for g in all {
        for dir in g.path.ancestors().skip(1) {
            if dir.as_os_str().is_empty() || dir == Path::new("/") {
                continue;
            }
            if all.iter().any(|o| within(dir, &o.path)) || out.iter().any(|d| d == dir) {
                continue;
            }
            // A link on the way makes the grant's own walk fail.
            let Ok(o) = open_path(dir) else {
                continue;
            };
            if !o.m.is_dir() || o.m.mode() & 0o001 != 0 {
                continue;
            }
            if o.m.uid() == who.owner {
                out.push(dir.to_path_buf());
            } else {
                report.errors.push(format!(
                    "{}: nerve-run cannot reach it, as {} is closed to it and not yours",
                    g.path.display(),
                    dir.display()
                ));
                missed.push(g.path.clone());
            }
        }
    }
    out.sort();
    out
}

/// Brings the entries of `who.run` in line with `want`, after the record in
/// `file`: the grants that changed are walked again, and so are the ones
/// that failed last time, the ones that went are taken off, the
/// pass-through folders follow. The record is written last, with what is on
/// now, so a sync that stopped half way is done again next time. Runs as the
/// owner (crate::account::FsAs), but for the record, which `write` writes as
/// the node.
pub fn sync(
    file: &Path,
    want: &[Granted],
    who: Who,
    act_as: &dyn Fn() -> Result<Option<crate::account::FsAs>, String>,
) -> Report {
    sync_with(file, want, who, act_as, false)
}

/// [`sync`] that walks every grant, also one that did not change: a file or
/// folder moved into a granted folder keeps the ACL it had, and only a walk
/// gives it the grant's entries. It costs a pass over every granted tree.
pub fn sync_all(
    file: &Path,
    want: &[Granted],
    who: Who,
    act_as: &dyn Fn() -> Result<Option<crate::account::FsAs>, String>,
) -> Report {
    sync_with(file, want, who, act_as, true)
}

/// [`sync`], walking every grant of `want` when `every`.
fn sync_with(
    file: &Path,
    want: &[Granted],
    who: Who,
    act_as: &dyn Fn() -> Result<Option<crate::account::FsAs>, String>,
    every: bool,
) -> Report {
    let mut report = Report::default();
    let before = match read_record(file) {
        Ok(r) => r.unwrap_or_default(),
        Err(e) => {
            report.errors.push(e);
            report.stale.push(file.to_path_buf());
            return report;
        }
    };
    // Entries of an earlier `nerve-run` (another uid), or on the files of
    // an earlier owner, come off everywhere.
    let old_uid = (before.uid != who.run || before.owner != who.owner)
        && !(before.grants.is_empty() && before.traverse.is_empty());
    let mut kept = Record {
        uid: who.run,
        owner: who.owner,
        ..Record::default()
    };
    let mut missed: Vec<PathBuf> = Vec::new();
    let mut defaults = Defaults::of(&before);
    {
        let _as = match act_as() {
            Ok(a) => a,
            Err(e) => {
                report.errors.push(e);
                report
                    .stale
                    .extend(before.grants.iter().map(|g| g.path.clone()));
                return report;
            }
        };
        // What earlier accounts left is tried again; what still does not
        // come off stays.
        for l in &before.left {
            let gone = Who {
                run: l.run,
                owner: l.owner,
            };
            if !walk(&l.path, &[], gone, None, &mut defaults, &mut report).whole {
                report.stale.push(l.path.clone());
                kept.left.push(l.clone());
            }
        }
        if old_uid {
            let gone = Who {
                run: before.uid,
                owner: before.owner,
            };
            for g in &before.grants {
                if !walk(&g.path, &[], gone, None, &mut defaults, &mut report).whole {
                    report.stale.push(g.path.clone());
                    kept.left.push(Left {
                        path: g.path.clone(),
                        run: gone.run,
                        owner: gone.owner,
                    });
                }
            }
            for d in &before.traverse {
                if let Err(e) = pass(d, gone, false)
                    && e.kind() != std::io::ErrorKind::NotFound
                {
                    report.errors.push(failed(d, &e));
                }
            }
        }
        let had = if old_uid { &[][..] } else { &before.grants[..] };
        let retry = if old_uid { &[][..] } else { &before.failed[..] };
        // A grant is walked when it is new, changed, failed last time or
        // gone, or when every one is.
        let mut roots: Vec<&Path> = Vec::new();
        for g in want
            .iter()
            .filter(|g| every || !had.contains(g) || retry.contains(&g.path))
        {
            roots.push(&g.path);
        }
        for g in had.iter().filter(|g| !want.contains(g)) {
            roots.push(&g.path);
        }
        let mut walked_above: Vec<&Path> = Vec::new();
        for root in roots {
            let errors = report.errors.len();
            if walk(root, want, who, None, &mut defaults, &mut report).whole {
                continue;
            }
            if want.iter().any(|g| g.path == root) {
                missed.push(root.to_path_buf());
                continue;
            }
            // A grant that went, inside one that is still given, may be
            // out of reach by its path: a command may have put a link on
            // the way there. The folder it was is inside the grant above,
            // wherever it lies now, and a walk of that whole grant gives it
            // that grant's entries and no more, if it saw all of it: on
            // another file system, or below a folder the owner may not
            // list, it is left stale.
            if let Some(up) = granted_above(want, root)
                && (walked_above.contains(&up) || {
                    let w = walk(up, want, who, None, &mut defaults, &mut report);
                    w.whole && w.seen_all
                })
            {
                report.errors.truncate(errors);
                walked_above.push(up);
                continue;
            }
            report.stale.push(root.to_path_buf());
        }
        // What is still to come off stays in the record.
        kept.grants = want.to_vec();
        for g in had {
            if report.stale.contains(&g.path) && !kept.grants.iter().any(|k| k.path == g.path) {
                kept.grants.push(Granted {
                    path: g.path.clone(),
                    access: Access::NONE,
                });
            }
        }
        let now = traverse(want, who, &mut report, &mut missed);
        let had_pass = if old_uid {
            &[][..]
        } else {
            &before.traverse[..]
        };
        for d in &now {
            if had_pass.contains(d) {
                kept.traverse.push(d.clone());
                continue;
            }
            match pass(d, who, true) {
                Ok(()) => kept.traverse.push(d.clone()),
                Err(e) => {
                    report.errors.push(failed(d, &e));
                    // The grants below it are out of reach; it is tried
                    // again with them.
                    missed.extend(
                        want.iter()
                            .filter(|g| within(&g.path, d))
                            .map(|g| g.path.clone()),
                    );
                }
            }
        }
        for d in had_pass.iter().filter(|d| !now.contains(d)) {
            if want.iter().any(|g| within(d, &g.path)) {
                continue;
            }
            match pass(d, who, false) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    report.errors.push(failed(d, &e));
                    report.stale.push(d.clone());
                    kept.traverse.push(d.clone());
                }
            }
        }
    }
    missed.sort();
    missed.dedup();
    let below = |set: BTreeSet<PathBuf>| -> Vec<PathBuf> {
        set.into_iter()
            .filter(|p| kept.grants.iter().any(|g| within(p, &g.path)))
            .collect()
    };
    kept.defaults = below(defaults.own);
    kept.own_entries = below(defaults.entries);
    kept.made_defaults = below(defaults.made);
    kept.failed = missed.clone();
    report.failed = missed;
    if let Err(e) = write_record(file, &kept) {
        report.errors.push(e);
    }
    report
}

/// Whether the record in `file` is behind `want`: a sync has something to
/// do. With `retry`, a grant that failed last time counts too. Cheap: it
/// reads the record, nothing else.
pub fn behind(file: &Path, want: &[Granted], who: Who, retry: bool) -> bool {
    match read_record(file) {
        Ok(Some(r)) => {
            r.uid != who.run
                || r.owner != who.owner
                || r.grants != want
                || (retry && !(r.failed.is_empty() && r.left.is_empty()))
        }
        Ok(None) => !want.is_empty(),
        Err(_) => true,
    }
}

/// The accounts the record in `file` names entries for, and whether it
/// keeps entries of earlier ones ([`Record::left`]): `None` without a
/// record, with one that names none, and with one that cannot be read,
/// where the node refuses every command of `nerve-run` until it can
/// ([`sync`]).
pub fn recorded(file: &Path) -> Option<(Who, bool)> {
    match read_record(file) {
        Ok(Some(r)) if !(r.grants.is_empty() && r.traverse.is_empty() && r.left.is_empty()) => {
            Some((
                Who {
                    run: r.uid,
                    owner: r.owner,
                },
                !r.left.is_empty(),
            ))
        }
        _ => None,
    }
}

/// Marks every grant of the record in `file` as failed, so that the node
/// walks each again at its next sync ([`behind`] with `retry`, as at its
/// start): after [`remove_all`] stopped half way, the record says entries
/// are on that the walk took off.
pub fn retry_all(file: &Path) -> Result<(), String> {
    let Some(mut r) = read_record(file)? else {
        return Ok(());
    };
    r.failed = r.grants.iter().map(|g| g.path.clone()).collect();
    write_record(file, &r)
}

/// The access entry of `uid` on `p`, for the tests of other modules.
#[cfg(test)]
pub(crate) fn access_entry(p: &Path, uid: u32) -> Option<u16> {
    get(&c_path(p).unwrap(), ACCESS)
        .unwrap()
        .and_then(|a| a.user(uid))
}

/// Takes every entry the record in `file` names off again: `uninstall`, as
/// root, which may change any file. Also those on files `nerve-run` made
/// there, which are its own, and those go to the owner, as `heir` names its
/// uid and gid for the record's owner: its uid is freed next, and the next
/// account to get it must not have them. The record goes once all are off.
/// `install` does the same before the owner changes (crate::service), so
/// that no entry stays that the new owner could not take off.
pub fn remove_all(file: &Path, heir: &dyn Fn(u32) -> (u32, u32)) -> Report {
    let mut report = Report::default();
    let r = match read_record(file) {
        Ok(Some(r)) => r,
        Ok(None) => return report,
        Err(e) => {
            report.errors.push(e);
            return report;
        }
    };
    let who = Who {
        run: r.uid,
        owner: r.owner,
    };
    let to_owner = heir(r.owner);
    let mut defaults = Defaults::of(&r);
    // The outer grants first: a grant inside one that came off whole, and
    // whose walk saw all of it, is done even where a link on its way keeps
    // its own walk out.
    let mut grants: Vec<&Granted> = r.grants.iter().collect();
    grants.sort_by_key(|g| g.path.components().count());
    let mut done: Vec<&Path> = Vec::new();
    for g in grants {
        let errors = report.errors.len();
        let w = walk(
            &g.path,
            &[],
            who,
            Some(to_owner),
            &mut defaults,
            &mut report,
        );
        if w.whole {
            if w.seen_all {
                done.push(&g.path);
            }
        } else if done.iter().any(|d| within(&g.path, d)) {
            report.errors.truncate(errors);
        } else {
            report.stale.push(g.path.clone());
        }
    }
    for d in &r.traverse {
        if let Err(e) = pass(d, who, false)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            report.errors.push(failed(d, &e));
            report.stale.push(d.clone());
        }
    }
    for l in &r.left {
        let gone = Who {
            run: l.run,
            owner: l.owner,
        };
        let to = heir(l.owner);
        if !walk(&l.path, &[], gone, Some(to), &mut defaults, &mut report).whole {
            report.stale.push(l.path.clone());
        }
    }
    if report.stale.is_empty() {
        let _ = std::fs::remove_file(file);
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn uid() -> u32 {
        // SAFETY: a plain getter.
        unsafe { libc::geteuid() }
    }

    fn gid() -> u32 {
        // SAFETY: a plain getter.
        unsafe { libc::getegid() }
    }

    fn acl_of(p: &Path, name: &str) -> Option<Acl> {
        get(&c_path(p).unwrap(), name).unwrap()
    }

    fn rights(p: &Path, run: u32) -> Option<u16> {
        acl_of(p, ACCESS).and_then(|a| a.user(run))
    }

    fn mode(p: &Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
    }

    /// A folder for the test on a file system with ACLs, or `None` (the test
    /// is skipped there).
    fn tree() -> Option<tempfile::TempDir> {
        let d = tempfile::tempdir().ok()?;
        let probe = d.path().join("probe");
        std::fs::write(&probe, "x").ok()?;
        let mut acl = Acl::of_mode(0o644);
        acl.set_user(4242, Some(R));
        match set(&c_path(&probe).unwrap(), ACCESS, &acl) {
            Ok(()) => {
                std::fs::remove_file(&probe).ok()?;
                Some(d)
            }
            Err(e) => {
                eprintln!("skipped: no POSIX ACLs here ({e})");
                None
            }
        }
    }

    fn none() -> Result<Option<crate::account::FsAs>, String> {
        Ok(None)
    }

    const RUN: u32 = 4242;

    fn who() -> Who {
        Who {
            run: RUN,
            owner: uid(),
        }
    }

    fn grant(p: &Path, a: &str) -> Granted {
        Granted {
            path: p.to_path_buf(),
            access: Access::parse(a).unwrap(),
        }
    }

    #[test]
    fn an_acl_is_read_and_written_as_the_kernel_keeps_it() {
        let mut a = Acl::of_mode(0o640);
        assert!(!a.has_named());
        a.set_user(1000, Some(R | W));
        assert_eq!(a.user(1000), Some(R | W));
        // The mask lets the entry through: group r plus rw.
        assert_eq!(a.get(MASK), Some(R | W));
        let b = a.bytes();
        assert_eq!(&b[..4], &2u32.to_le_bytes());
        // Sorted: user_obj, the named user, group_obj, mask, other.
        let back = Acl::parse(&b).unwrap();
        let tags: Vec<u16> = back.0.iter().map(|e| e.tag).collect();
        assert_eq!(tags, [USER_OBJ, USER, GROUP_OBJ, MASK, OTHER]);
        // Taken off, the mask goes with the last named entry.
        a.set_user(1000, None);
        assert_eq!(a, Acl::of_mode(0o640));
        assert!(Acl::parse(b"xx").is_err());
        assert!(Acl::parse(&[1, 0, 0, 0]).is_err());
    }

    /// The mask never narrows what the others had: it only grows for the
    /// entry set.
    #[test]
    fn the_mask_only_grows() {
        let mut a = Acl::of_mode(0o600);
        a.set_user(7, Some(R | W | X));
        a.set_user(8, Some(R));
        assert_eq!(a.get(MASK), Some(R | W | X));
        a.set_user(7, None);
        assert_eq!(a.get(MASK), Some(R | W | X), "8 keeps what it had");
    }

    #[test]
    fn the_flags_make_the_rights() {
        let a = |s: &str| Access::parse(s).unwrap();
        assert_eq!(dir_perm(a("r")), R | X);
        assert_eq!(dir_perm(a("w")), W | X);
        assert_eq!(dir_perm(a("x")), X);
        assert_eq!(dir_perm(a("")), 0);
        assert_eq!(file_perm(a("rwx"), 0o644), R | W);
        assert_eq!(file_perm(a("rx"), 0o755), R | X);
        assert_eq!(file_perm(a("w"), 0o755), W);
    }

    /// A file and a folder moved into a granted folder keep the ACL they
    /// had: a sync of the unchanged grants passes them over, a walk of every
    /// grant gives them the grant's entries.
    #[test]
    fn a_walk_of_every_grant_gives_what_was_moved_in_its_entries() {
        let Some(d) = tree() else { return };
        let root = std::fs::canonicalize(d.path()).unwrap();
        let work = root.join("work");
        let outside = root.join("outside");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::create_dir_all(outside.join("tree")).unwrap();
        std::fs::write(outside.join("moved.txt"), "m").unwrap();
        std::fs::write(outside.join("tree/deep.txt"), "d").unwrap();
        let file = root.join("acl.json");
        let want = [grant(&work, "rw")];
        assert!(sync(&file, &want, who(), &none).errors.is_empty());
        std::fs::rename(outside.join("moved.txt"), work.join("moved.txt")).unwrap();
        std::fs::rename(outside.join("tree"), work.join("tree")).unwrap();
        assert!(sync(&file, &want, who(), &none).errors.is_empty());
        assert_eq!(rights(&work.join("moved.txt"), RUN), None);
        let r = sync_all(&file, &want, who(), &none);
        assert_eq!(r.errors, Vec::<String>::new());
        assert_eq!(rights(&work.join("moved.txt"), RUN), Some(R | W));
        assert_eq!(rights(&work.join("tree"), RUN), Some(R | W | X));
        assert_eq!(rights(&work.join("tree/deep.txt"), RUN), Some(R | W));
        // The walk changed nothing of the record: the next sync has nothing
        // to do.
        assert!(!behind(&file, &want, who(), true));
    }

    /// A grant puts the entries on the folder and everything below, and the
    /// default ones on its folders; a file made there later gets them by the
    /// default; revoking takes all off again and gives the files their mode
    /// back.
    #[test]
    fn a_grant_puts_the_entries_on_and_a_revoke_takes_them_off() {
        let Some(d) = tree() else { return };
        let root = std::fs::canonicalize(d.path()).unwrap();
        let work = root.join("work");
        std::fs::create_dir_all(work.join("sub")).unwrap();
        std::fs::write(work.join("a.txt"), "a").unwrap();
        std::fs::write(work.join("sub/b.txt"), "b").unwrap();
        std::fs::set_permissions(work.join("a.txt"), std::fs::Permissions::from_mode(0o640))
            .unwrap();
        let file = root.join("acl.json");
        let want = [grant(&work, "rw")];
        assert!(behind(&file, &want, who(), false));
        let r = sync(&file, &want, who(), &none);
        assert_eq!(r.errors, Vec::<String>::new());
        assert!(!behind(&file, &want, who(), false));
        assert_eq!(rights(&work, RUN), Some(R | W | X));
        assert_eq!(rights(&work.join("sub"), RUN), Some(R | W | X));
        assert_eq!(rights(&work.join("a.txt"), RUN), Some(R | W));
        assert_eq!(rights(&work.join("sub/b.txt"), RUN), Some(R | W));
        let def = acl_of(&work, DEFAULT).unwrap();
        assert_eq!(def.user(RUN), Some(R | W | X));
        assert_eq!(def.user(uid()), Some(R | W | X));
        // A file made after the grant has the entry by the default, held
        // by the mask to what its mode lets through (no `x` for 0666).
        std::fs::write(work.join("new.txt"), "n").unwrap();
        let new = acl_of(&work.join("new.txt"), ACCESS).unwrap();
        assert_eq!(
            new.user(RUN).zip(new.get(MASK)).map(|(p, m)| p & m),
            Some(R | W)
        );
        // Revoked: every entry goes, the mode is as it was.
        let r = sync(&file, &[], who(), &none);
        assert_eq!(r.errors, Vec::<String>::new());
        for p in [
            &work,
            &work.join("sub"),
            &work.join("a.txt"),
            &work.join("new.txt"),
        ] {
            assert_eq!(rights(p, RUN), None, "{p:?}");
        }
        assert_eq!(acl_of(&work, DEFAULT), None);
        assert_eq!(acl_of(&work.join("a.txt"), ACCESS), None);
        assert_eq!(mode(&work.join("a.txt")), 0o640);
        assert!(!behind(&file, &[], who(), false));
    }

    /// A folder two pairings share keeps the account's entry while one
    /// still has it, with the rights it still gives; a folder inside
    /// another keeps the outer one's.
    #[test]
    fn a_shared_folder_stays_while_a_grant_is_left() {
        let Some(d) = tree() else { return };
        let root = std::fs::canonicalize(d.path()).unwrap();
        let outer = root.join("outer");
        let inner = outer.join("inner");
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::write(inner.join("f"), "f").unwrap();
        let file = root.join("acl.json");
        // Two pairings, one with r on the outer, one with rw on the inner.
        let want = [grant(&inner, "rw"), grant(&outer, "r")];
        assert!(sync(&file, &want, who(), &none).errors.is_empty());
        assert_eq!(rights(&inner.join("f"), RUN), Some(R | W));
        assert_eq!(rights(&outer, RUN), Some(R | X));
        // The inner one goes: the outer's read stays below it.
        assert!(sync(&file, &want[1..], who(), &none).errors.is_empty());
        assert_eq!(rights(&inner.join("f"), RUN), Some(R));
        assert_eq!(rights(&inner, RUN), Some(R | X));
        // Merged into one entry for the same folder, it is the union
        // (crate::acl::wanted); taking that away leaves nothing.
        assert!(sync(&file, &[], who(), &none).errors.is_empty());
        assert_eq!(rights(&inner.join("f"), RUN), None);
    }

    /// A folder of the owner's above a grant that others may not enter gets
    /// a pass-through entry and nothing more, which goes with the grant.
    #[test]
    fn a_closed_folder_above_a_grant_lets_the_account_pass() {
        let Some(d) = tree() else { return };
        let root = std::fs::canonicalize(d.path()).unwrap();
        let home = root.join("home");
        let work = home.join("work");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        let file = root.join("acl.json");
        let r = sync(&file, &[grant(&work, "r")], who(), &none);
        assert_eq!(r.errors, Vec::<String>::new());
        assert_eq!(rights(&home, RUN), Some(X));
        assert_eq!(acl_of(&home, DEFAULT), None, "no default above the grant");
        assert!(sync(&file, &[], who(), &none).errors.is_empty());
        assert_eq!(rights(&home, RUN), None);
        assert_eq!(mode(&home), 0o700);
    }

    /// A link is not followed, and a file with a second name, which may lie
    /// outside the grant, gets no entry.
    #[test]
    fn links_and_second_names_are_left_alone() {
        let Some(d) = tree() else { return };
        let root = std::fs::canonicalize(d.path()).unwrap();
        let work = root.join("work");
        let outside = root.join("outside");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret"), "s").unwrap();
        std::os::unix::fs::symlink(&outside, work.join("link")).unwrap();
        std::fs::hard_link(outside.join("secret"), work.join("twin")).unwrap();
        let file = root.join("acl.json");
        let r = sync(&file, &[grant(&work, "rw")], who(), &none);
        assert!(r.errors.is_empty(), "{r:?}");
        assert!(r.skipped >= 2, "{r:?}");
        assert_eq!(rights(&outside, RUN), None);
        assert_eq!(rights(&outside.join("secret"), RUN), None);
    }

    /// `uninstall` takes every entry off by the record, and the record goes.
    #[test]
    fn remove_all_takes_everything_off() {
        let Some(d) = tree() else { return };
        let root = std::fs::canonicalize(d.path()).unwrap();
        let work = root.join("work");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::write(work.join("f"), "f").unwrap();
        let file = root.join("acl.json");
        assert!(
            sync(&file, &[grant(&work, "rwx")], who(), &none)
                .errors
                .is_empty()
        );
        let r = remove_all(&file, &|_| (uid(), gid()));
        assert!(r.errors.is_empty() && r.stale.is_empty(), "{r:?}");
        assert_eq!(rights(&work, RUN), None);
        assert_eq!(rights(&work.join("f"), RUN), None);
        assert!(!file.exists());
    }

    /// A new `nerve-run` (another uid, after an install again) gets the
    /// entries, and the old uid's come off.
    #[test]
    fn a_new_account_takes_the_old_ones_place() {
        let Some(d) = tree() else { return };
        let root = std::fs::canonicalize(d.path()).unwrap();
        let work = root.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let file = root.join("acl.json");
        let want = [grant(&work, "r")];
        assert!(sync(&file, &want, who(), &none).errors.is_empty());
        let next = Who {
            run: RUN + 1,
            ..who()
        };
        assert!(behind(&file, &want, next, false));
        assert!(sync(&file, &want, next, &none).errors.is_empty());
        assert_eq!(rights(&work, RUN), None);
        assert_eq!(rights(&work, RUN + 1), Some(R | X));
    }

    /// A folder that a command swaps for a link while the walk is in it is
    /// not followed: what the link leads to gets no entry.
    #[test]
    fn a_folder_swapped_for_a_link_during_the_walk_is_not_followed() {
        let Some(d) = tree() else { return };
        let root = std::fs::canonicalize(d.path()).unwrap();
        let work = root.join("work");
        let outside = root.join("outside");
        std::fs::create_dir_all(work.join("sub")).unwrap();
        std::fs::create_dir_all(outside.join("deeper")).unwrap();
        std::fs::write(outside.join("secret"), "s").unwrap();
        let sub = work.join("sub");
        let (at, to) = (sub.clone(), outside.clone());
        CHANGED.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |p: &Path| {
                if p == at {
                    std::fs::rename(&at, at.with_file_name("sub.old")).unwrap();
                    std::os::unix::fs::symlink(&to, &at).unwrap();
                }
            }))
        });
        let file = root.join("acl.json");
        let r = sync(&file, &[grant(&work, "rw")], who(), &none);
        CHANGED.with(|h| *h.borrow_mut() = None);
        assert!(r.errors.is_empty(), "{r:?}");
        assert!(std::fs::symlink_metadata(&sub).unwrap().is_symlink());
        for p in [&outside, &outside.join("secret"), &outside.join("deeper")] {
            assert_eq!(rights(p, RUN), None, "{p:?}");
            assert_eq!(acl_of(p, DEFAULT), None, "{p:?}");
        }
        // The folder itself, moved within the grant, has its entry.
        assert_eq!(rights(&work.join("sub.old"), RUN), Some(R | W | X));
    }

    /// A link put on the way to a granted folder since it was given (inside
    /// another grant a command may write) makes its grant fail, and what it
    /// leads to gets no entry.
    #[test]
    fn a_link_on_the_way_to_a_grant_is_not_followed() {
        let Some(d) = tree() else { return };
        let root = std::fs::canonicalize(d.path()).unwrap();
        let work = root.join("work");
        let deep = work.join("inner/deep");
        let outside = root.join("outside");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::create_dir_all(outside.join("deep")).unwrap();
        std::fs::write(outside.join("deep/secret"), "s").unwrap();
        let file = root.join("acl.json");
        let r = sync(&file, &[grant(&work, "r"), grant(&deep, "r")], who(), &none);
        assert!(r.errors.is_empty(), "{r:?}");
        std::fs::rename(work.join("inner"), work.join("inner.old")).unwrap();
        std::os::unix::fs::symlink(&outside, work.join("inner")).unwrap();
        // The inner grant changes, so it is walked again.
        let want = [grant(&work, "r"), grant(&deep, "rw")];
        let r = sync(&file, &want, who(), &none);
        assert_eq!(r.failed, vec![deep.clone()], "{r:?}");
        assert!(
            r.errors
                .iter()
                .any(|e| e.contains("is a link or a file now")),
            "{r:?}"
        );
        for p in [
            &outside,
            &outside.join("deep"),
            &outside.join("deep/secret"),
        ] {
            assert_eq!(rights(p, RUN), None, "{p:?}");
            assert_eq!(acl_of(p, DEFAULT), None, "{p:?}");
        }
    }

    /// A file that got a second name after it had its entry (a command may
    /// link a file it may write to a place outside the grant) loses the
    /// entry when the grant goes.
    #[test]
    fn a_revoke_takes_the_entry_off_a_file_with_a_second_name() {
        let Some(d) = tree() else { return };
        let root = std::fs::canonicalize(d.path()).unwrap();
        let work = root.join("work");
        let outside = root.join("outside");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(work.join("f"), "f").unwrap();
        let file = root.join("acl.json");
        assert!(
            sync(&file, &[grant(&work, "rw")], who(), &none)
                .errors
                .is_empty()
        );
        assert_eq!(rights(&work.join("f"), RUN), Some(R | W));
        std::fs::hard_link(work.join("f"), outside.join("twin")).unwrap();
        let r = sync(&file, &[], who(), &none);
        assert!(r.errors.is_empty(), "{r:?}");
        assert_eq!(rights(&outside.join("twin"), RUN), None);
    }

    /// `uninstall` takes the entries off the files `nerve-run` made in a
    /// grant as well, which are not the owner's: here the test's own files
    /// stand for them, under a record that names another owner.
    #[test]
    fn remove_all_takes_the_entries_off_what_nerve_run_made() {
        let Some(d) = tree() else { return };
        let root = std::fs::canonicalize(d.path()).unwrap();
        let work = root.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let file = root.join("acl.json");
        assert!(
            sync(&file, &[grant(&work, "rw")], who(), &none)
                .errors
                .is_empty()
        );
        // Made below the grant: the default entries give it the account's.
        let made = work.join("made");
        std::fs::create_dir(&made).unwrap();
        std::fs::write(made.join("f"), "f").unwrap();
        assert!(rights(&made, RUN).is_some());
        assert!(acl_of(&made, DEFAULT).and_then(|a| a.user(RUN)).is_some());
        // The owner is someone else now: these files are another account's.
        let mut rec = read_record(&file).unwrap().unwrap();
        rec.owner = uid() + 1;
        write_record(&file, &rec).unwrap();
        let r = remove_all(&file, &|_| (uid(), gid()));
        assert!(r.errors.is_empty() && r.stale.is_empty(), "{r:?}");
        for p in [&work, &made, &made.join("f")] {
            assert_eq!(rights(p, RUN), None, "{p:?}");
        }
        assert_eq!(acl_of(&made, DEFAULT).and_then(|a| a.user(RUN)), None);
        // The default entry of the owner it came with stays on the folder.
        assert!(acl_of(&made, DEFAULT).and_then(|a| a.user(uid())).is_some());
        assert!(!file.exists());
    }

    fn set_default(p: &Path, text: &str) {
        let mut a = Acl::of_mode(0);
        for (tag, perm) in text.split(',').map(|e| e.split_once(':').unwrap()) {
            let tag = match tag {
                "u" => USER_OBJ,
                "g" => GROUP_OBJ,
                _ => OTHER,
            };
            let perm = perm
                .chars()
                .map(|c| match c {
                    'r' => R,
                    'w' => W,
                    'x' => X,
                    _ => 0,
                })
                .sum();
            a.0.retain(|e| e.tag != tag);
            a.0.push(Entry {
                tag,
                id: NO_ID,
                perm,
            });
        }
        set(&c_path(p).unwrap(), DEFAULT, &a).unwrap();
    }

    /// A default ACL of the owner's own without named entries (it keeps new
    /// files private whatever the umask) is there again after a grant and a
    /// revoke, on the folder and on one made below it meanwhile; a folder
    /// that had none has none again (#142).
    #[test]
    fn a_default_acl_of_the_owners_own_stays_after_a_revoke() {
        let Some(d) = tree() else { return };
        let root = std::fs::canonicalize(d.path()).unwrap();
        let work = root.join("work");
        let private = work.join("private");
        let plain = work.join("plain");
        std::fs::create_dir_all(&private).unwrap();
        std::fs::create_dir_all(&plain).unwrap();
        set_default(&private, "u:rwx,g:rx,o:");
        let theirs = acl_of(&private, DEFAULT).unwrap();
        let file = root.join("acl.json");
        let r = sync(&file, &[grant(&work, "rw")], who(), &none);
        assert!(r.errors.is_empty(), "{r:?}");
        assert_eq!(
            acl_of(&private, DEFAULT).unwrap().user(RUN),
            Some(R | W | X)
        );
        // Made during the grant: it got the owner's default from above.
        let later = private.join("later");
        std::fs::create_dir(&later).unwrap();
        let r = sync(&file, &[], who(), &none);
        assert!(r.errors.is_empty(), "{r:?}");
        assert_eq!(acl_of(&private, DEFAULT), Some(theirs.clone()));
        assert_eq!(acl_of(&later, DEFAULT), Some(theirs));
        assert_eq!(acl_of(&plain, DEFAULT), None);
        assert_eq!(acl_of(&work, DEFAULT), None);
        assert!(read_record(&file).unwrap().unwrap().defaults.is_empty());
    }

    /// `uninstall` leaves a default ACL alone that has no entry of the
    /// account's: here one of another account's folder below a grant.
    #[test]
    fn remove_all_leaves_a_default_acl_without_the_accounts_entry() {
        let Some(d) = tree() else { return };
        let root = std::fs::canonicalize(d.path()).unwrap();
        let work = root.join("work");
        let shared = work.join("shared");
        std::fs::create_dir_all(&shared).unwrap();
        let file = root.join("acl.json");
        assert!(
            sync(&file, &[grant(&work, "r")], who(), &none)
                .errors
                .is_empty()
        );
        // Another account's folder now (the record names another owner),
        // with a default ACL of its own and no entry of nerve-run's.
        set_default(&shared, "u:rwx,g:rwx,o:");
        let theirs = acl_of(&shared, DEFAULT);
        let mut rec = read_record(&file).unwrap().unwrap();
        rec.owner = uid() + 1;
        write_record(&file, &rec).unwrap();
        let r = remove_all(&file, &|_| (uid(), gid()));
        assert!(r.errors.is_empty() && r.stale.is_empty(), "{r:?}");
        assert!(theirs.is_some());
        assert_eq!(acl_of(&shared, DEFAULT), theirs);
    }

    /// A command may swap a folder on the way to a grant inside another
    /// grant for a link. Once the inner grant goes, the folder it was gets
    /// the outer grant's entries by a walk of the outer one, and no command
    /// is refused for it: neither a sync nor `uninstall` keeps it (#142).
    #[test]
    fn a_link_on_the_way_to_a_revoked_inner_grant_leaves_nothing_stale() {
        let Some(d) = tree() else { return };
        let root = std::fs::canonicalize(d.path()).unwrap();
        let work = root.join("work");
        let data = work.join("x/data");
        let outside = root.join("outside");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::create_dir_all(outside.join("data")).unwrap();
        std::fs::write(data.join("f"), "f").unwrap();
        let file = root.join("acl.json");
        let want = [grant(&work, "r"), grant(&data, "rw")];
        assert!(sync(&file, &want, who(), &none).errors.is_empty());
        assert_eq!(rights(&data.join("f"), RUN), Some(R | W));
        std::fs::rename(work.join("x"), work.join("x.old")).unwrap();
        std::os::unix::fs::symlink(&outside, work.join("x")).unwrap();
        let r = sync(&file, &want[..1], who(), &none);
        assert!(r.stale.is_empty() && r.errors.is_empty(), "{r:?}");
        assert_eq!(r.refusal(), None);
        // The folder it was, moved within the outer grant: its rights only.
        assert_eq!(rights(&work.join("x.old/data/f"), RUN), Some(R));
        assert_eq!(rights(&outside.join("data"), RUN), None);
        // The same at `uninstall`, with both grants in the record.
        assert!(sync(&file, &want, who(), &none).stale.is_empty());
        let r = remove_all(&file, &|_| (uid(), gid()));
        assert!(r.stale.is_empty() && r.errors.is_empty(), "{r:?}");
        assert_eq!(rights(&work.join("x.old/data/f"), RUN), None);
        assert!(!file.exists());
    }

    /// `uninstall` gives what `nerve-run` made in a grant to the owner, as
    /// its uid is freed next. Needs root to make files of another uid: runs
    /// as root only (the real test on a test machine, or a user namespace).
    #[test]
    fn remove_all_gives_what_nerve_run_made_to_the_owner() {
        if uid() != 0 {
            eprintln!("skipped: needs root");
            return;
        }
        let Some(d) = tree() else { return };
        let root = std::fs::canonicalize(d.path()).unwrap();
        let work = root.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let file = root.join("acl.json");
        assert!(
            sync(&file, &[grant(&work, "rw")], who(), &none)
                .errors
                .is_empty()
        );
        // As if nerve-run made them: a folder, a file in it, and a link.
        let made = work.join("made");
        std::fs::create_dir(&made).unwrap();
        std::fs::write(made.join("f"), "f").unwrap();
        std::os::unix::fs::symlink("f", made.join("l")).unwrap();
        for p in [&made, &made.join("f"), &made.join("l")] {
            std::os::unix::fs::lchown(p, Some(RUN), Some(RUN)).unwrap();
        }
        let mine = work.join("mine");
        std::fs::write(&mine, "m").unwrap();
        let heir = (RUN + 1, RUN + 2);
        let r = remove_all(&file, &|owner| {
            assert_eq!(owner, uid());
            heir
        });
        assert!(r.errors.is_empty() && r.stale.is_empty(), "{r:?}");
        for p in [&made, &made.join("f"), &made.join("l")] {
            let m = std::fs::symlink_metadata(p).unwrap();
            assert_eq!((m.uid(), m.gid()), heir, "{p:?}");
        }
        // The owner's own stay as they were.
        assert_eq!(std::fs::metadata(&mine).unwrap().uid(), uid());
    }

    /// `uninstall` gives nothing of `nerve-run`'s that is no folder and has
    /// a second name: ownership goes with the file, and the other name may
    /// lie outside every grant, here in a folder open to all. Such a file
    /// is counted, and what has one name is given as before (#142). Root in
    /// a namespace of its own, to own files as other accounts.
    #[test]
    fn remove_all_gives_no_file_with_a_second_name() {
        if !in_a_namespace("remove_all_gives_no_file_with_a_second_name") {
            return;
        }
        let Some(d) = tree() else { return };
        let root = std::fs::canonicalize(d.path()).unwrap();
        let work = root.join("work");
        let open = root.join("open");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::create_dir_all(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o1777)).unwrap();
        let file = root.join("acl.json");
        assert!(
            sync(&file, &[grant(&work, "rw")], who(), &none)
                .errors
                .is_empty()
        );
        // As if nerve-run made them: a file and a link, each also named in
        // the open folder outside the grant, and a file with one name.
        std::fs::write(open.join("f"), "f").unwrap();
        std::os::unix::fs::symlink("f", open.join("l")).unwrap();
        std::fs::hard_link(open.join("f"), work.join("f")).unwrap();
        std::fs::hard_link(open.join("l"), work.join("l")).unwrap();
        std::fs::write(work.join("one"), "1").unwrap();
        for p in [open.join("f"), open.join("l"), work.join("one")] {
            std::os::unix::fs::lchown(&p, Some(RUN), Some(RUN)).unwrap();
        }
        let heir = (RUN + 1, RUN + 2);
        let r = remove_all(&file, &|_| heir);
        assert!(r.errors.is_empty() && r.stale.is_empty(), "{r:?}");
        assert_eq!(r.not_given, 2, "{r:?}");
        assert!(r.skipped >= 2, "{r:?}");
        let owner = |p: &Path| {
            let m = std::fs::symlink_metadata(p).unwrap();
            (m.uid(), m.gid())
        };
        for p in [
            open.join("f"),
            open.join("l"),
            work.join("f"),
            work.join("l"),
        ] {
            assert_eq!(owner(&p), (RUN, RUN), "{p:?}");
        }
        assert_eq!(owner(&work.join("one")), heir);

        // A file is one file whatever its names and however many grants
        // walk it: grants inside each other, and one file with a name
        // outside them and one with both names inside.
        let outer = root.join("outer");
        let inner = outer.join("inner");
        std::fs::create_dir_all(&inner).unwrap();
        let file = root.join("acl2.json");
        let grants = [grant(&outer, "rw"), grant(&inner, "rw")];
        assert!(sync(&file, &grants, who(), &none).errors.is_empty());
        std::fs::write(inner.join("g"), "g").unwrap();
        std::fs::hard_link(inner.join("g"), open.join("g")).unwrap();
        std::fs::write(inner.join("h"), "h").unwrap();
        std::fs::hard_link(inner.join("h"), outer.join("h2")).unwrap();
        for p in [inner.join("g"), inner.join("h")] {
            std::os::unix::fs::lchown(&p, Some(RUN), Some(RUN)).unwrap();
        }
        let r = remove_all(&file, &|_| heir);
        assert!(r.errors.is_empty() && r.stale.is_empty(), "{r:?}");
        assert_eq!(r.not_given, 2, "{r:?}");
    }

    /// A grant that failed (a folder below it closed) stays failed in the
    /// record, so it is tried again without a change to the config, and
    /// gets its entries once the folder is open.
    #[test]
    fn a_failed_grant_is_tried_again() {
        if uid() == 0 {
            return;
        }
        let Some(d) = tree() else { return };
        let root = std::fs::canonicalize(d.path()).unwrap();
        let work = root.join("work");
        let closed = work.join("closed");
        std::fs::create_dir_all(&closed).unwrap();
        std::fs::write(closed.join("f"), "f").unwrap();
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).unwrap();
        let file = root.join("acl.json");
        let want = [grant(&work, "r")];
        let r = sync(&file, &want, who(), &none);
        assert_eq!(r.failed, vec![work.clone()], "{r:?}");
        assert!(!r.errors.is_empty());
        // Nothing changed, but the grant is behind when it is time to try.
        assert!(!behind(&file, &want, who(), false));
        assert!(behind(&file, &want, who(), true));
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o755)).unwrap();
        let r = sync(&file, &want, who(), &none);
        assert!(r.errors.is_empty() && r.failed.is_empty(), "{r:?}");
        assert_eq!(rights(&closed.join("f"), RUN), Some(R));
        assert!(!behind(&file, &want, who(), true));
    }

    /// Only the pairings whose commands run as `nerve-run` give it their
    /// folders: not user mode, nor allowlist mode as the owner.
    #[test]
    fn the_folders_of_pairings_that_run_as_the_owner_are_not_given() {
        use nerve_policy::config::{CenterPolicy, Folder, Mode};
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let paths = NodePaths::new(root.join("config"), root.join("state"));
        let mut cfg = NodeConfig::default();
        let mut add = |name: &str, mode: Mode, as_owner: bool| {
            let path = root.join(name);
            std::fs::create_dir_all(&path).unwrap();
            cfg.centers.push(nerve_policy::CenterEntry {
                name: name.into(),
                url: "https://center.example".into(),
                pin: None,
                center_id: "c".into(),
                node_id: name.into(),
                settings: Default::default(),
                paused: false,
                revoked: false,
                unknown: false,
                public_key: None,
                key_rotations: 0,
                pin_rotations: 0,
                old_pin: None,
                policy: CenterPolicy {
                    mode,
                    as_owner,
                    folders: vec![Folder {
                        path: path.display().to_string(),
                        access: Access::parse("rw").unwrap(),
                    }],
                    ..Default::default()
                },
                capabilities: Vec::new(),
            });
        };
        add("folder", Mode::Folder, false);
        add("allow", Mode::Allowlist, false);
        add("user", Mode::User, false);
        add("owner", Mode::Allowlist, true);
        let got: Vec<PathBuf> = wanted(&cfg, &paths, &root, 0)
            .into_iter()
            .map(|g| g.path)
            .collect();
        assert_eq!(got, vec![root.join("allow"), root.join("folder")]);
    }

    /// The default ACL of `p` but its mask, which a grant only grows.
    fn default_but_mask(p: &Path) -> Option<Vec<Entry>> {
        acl_of(p, DEFAULT).map(|a| a.0.into_iter().filter(|e| e.tag != MASK).collect())
    }

    /// A folder that was there before the grant without a default ACL, below
    /// one with a default ACL of the owner's own, has none again after a
    /// revoke, and neither has one made below it meanwhile (#142).
    #[test]
    fn a_folder_that_had_no_default_acl_has_none_after_a_revoke() {
        let Some(d) = tree() else { return };
        let root = std::fs::canonicalize(d.path()).unwrap();
        let work = root.join("work");
        let private = work.join("private");
        let old = private.join("old");
        let deeper = old.join("deeper");
        std::fs::create_dir_all(&deeper).unwrap();
        set_default(&private, "u:rwx,g:rx,o:");
        let theirs = acl_of(&private, DEFAULT).unwrap();
        let file = root.join("acl.json");
        let r = sync(&file, &[grant(&work, "rw")], who(), &none);
        assert!(r.errors.is_empty(), "{r:?}");
        assert_eq!(acl_of(&old, DEFAULT).unwrap().user(RUN), Some(R | W | X));
        // Made during the grant below `old`: it got the node's default.
        let later = old.join("later");
        std::fs::create_dir(&later).unwrap();
        // Another walk while given, with other flags.
        let r = sync(&file, &[grant(&work, "r")], who(), &none);
        assert!(r.errors.is_empty(), "{r:?}");
        let r = sync(&file, &[], who(), &none);
        assert!(r.errors.is_empty() && r.stale.is_empty(), "{r:?}");
        assert_eq!(acl_of(&private, DEFAULT), Some(theirs));
        for p in [&old, &deeper, &later] {
            assert_eq!(acl_of(p, DEFAULT), None, "{p:?}");
        }
    }

    /// The owner's own named entry in a default ACL stays as the owner set
    /// it, during a grant and after its revoke, also on a folder made below
    /// it meanwhile, which got it from there (#142).
    #[test]
    fn the_owners_own_default_entry_stays() {
        let Some(d) = tree() else { return };
        let root = std::fs::canonicalize(d.path()).unwrap();
        let work = root.join("work");
        let shared = work.join("shared");
        std::fs::create_dir_all(&shared).unwrap();
        set_default(&shared, "u:rwx,g:rx,o:");
        let mut a = acl_of(&shared, DEFAULT).unwrap();
        a.set_user(uid(), Some(R | X));
        set(&c_path(&shared).unwrap(), DEFAULT, &a).unwrap();
        let theirs = default_but_mask(&shared).unwrap();
        let file = root.join("acl.json");
        let r = sync(&file, &[grant(&work, "rw")], who(), &none);
        assert!(r.errors.is_empty(), "{r:?}");
        let during = acl_of(&shared, DEFAULT).unwrap();
        assert_eq!(during.user(RUN), Some(R | W | X));
        assert_eq!(during.user(uid()), Some(R | X), "as the owner set it");
        let later = shared.join("later");
        std::fs::create_dir(&later).unwrap();
        let r = sync(&file, &[grant(&work, "r")], who(), &none);
        assert!(r.errors.is_empty(), "{r:?}");
        let r = sync(&file, &[], who(), &none);
        assert!(r.errors.is_empty() && r.stale.is_empty(), "{r:?}");
        for p in [&shared, &later] {
            assert_eq!(default_but_mask(p), Some(theirs.clone()), "{p:?}");
        }
        // Where the node put the owner's entry itself, it goes again.
        assert_eq!(acl_of(&work, DEFAULT), None);
    }

    /// Runs the test `name` again as root in a mount namespace of its own
    /// (in a user namespace too, unless it is root already), where it may
    /// mount a file system and own files as other accounts. False where
    /// that is done, or not possible here: the caller returns then.
    fn in_a_namespace(name: &str) -> bool {
        use std::process::Command;
        if std::env::var_os("NERVE_TEST_IN_NS").is_some() {
            assert_eq!(uid(), 0, "not root in the namespace");
            return true;
        }
        let args: &[&str] = if uid() == 0 {
            &["--mount"]
        } else {
            &["--map-root-user", "--map-auto", "--mount"]
        };
        let probe = Command::new("unshare")
            .args(args)
            .args([
                "sh",
                "-c",
                r#"d=$(mktemp -d) || exit 1; mount -t tmpfs none "$d" && chown 4303 "$d"; r=$?; umount "$d" 2>/dev/null; rmdir "$d"; exit $r"#,
            ])
            .output()
            .is_ok_and(|o| o.status.success());
        if !probe {
            eprintln!("skipped: needs a mount namespace where root may mount and change owners");
            return false;
        }
        let test = format!("{}::{name}", module_path!().split_once("::").unwrap().1);
        let status = Command::new("unshare")
            .args(args)
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", &test, "--nocapture", "--test-threads=1"])
            .env("NERVE_TEST_IN_NS", "1")
            .status()
            .unwrap();
        assert!(status.success(), "in the namespace: {status}");
        false
    }

    /// `f` on a thread of its own without the capabilities that pass a
    /// folder's mode: root then is held to the modes as the owner is.
    fn without_passing<T: Send>(f: impl FnOnce() -> T + Send) -> T {
        #[repr(C)]
        struct Header {
            version: u32,
            pid: libc::c_int,
        }
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct Data {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }
        std::thread::scope(|s| {
            s.spawn(|| {
                let h = Header {
                    version: 0x2008_0522,
                    pid: 0,
                };
                let mut caps = [Data {
                    effective: 0,
                    permitted: 0,
                    inheritable: 0,
                }; 2];
                // SAFETY: capget and capset with structs laid out as the
                // kernel's, on this thread.
                unsafe {
                    assert_eq!(
                        libc::syscall(libc::SYS_capget, &h as *const Header, caps.as_mut_ptr()),
                        0
                    );
                    // CAP_DAC_OVERRIDE and CAP_DAC_READ_SEARCH.
                    caps[0].effective &= !((1 << 1) | (1 << 2));
                    assert_eq!(
                        libc::syscall(libc::SYS_capset, &h as *const Header, caps.as_ptr()),
                        0
                    );
                }
                f()
            })
            .join()
            .unwrap()
        })
    }

    /// A tmpfs mounted on a folder, until it is dropped, also when the
    /// test fails: the folder around it can be removed then.
    struct Mounted(PathBuf);

    impl Mounted {
        fn tmpfs(p: &Path) -> Mounted {
            let ok = std::process::Command::new("mount")
                .args(["-t", "tmpfs", "none"])
                .arg(p)
                .status()
                .unwrap();
            assert!(ok.success());
            Mounted(p.to_path_buf())
        }
    }

    impl Drop for Mounted {
        fn drop(&mut self) {
            let _ = std::process::Command::new("umount").arg(&self.0).status();
        }
    }

    /// An inner grant on another file system, whose own walk fails on its
    /// revoke (a link on the way), is not counted done by a walk of the
    /// grant around it, which does not cross into that file system: it is
    /// stale until its own walk takes the entries off. The same at
    /// `uninstall` (#142).
    #[test]
    fn a_revoked_inner_grant_on_another_file_system_stays_stale() {
        if !in_a_namespace("a_revoked_inner_grant_on_another_file_system_stays_stale") {
            return;
        }
        let Some(d) = tree() else { return };
        let root = std::fs::canonicalize(d.path()).unwrap();
        let work = root.join("work");
        let data = work.join("x/data");
        let outside = root.join("outside");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::create_dir_all(outside.join("data")).unwrap();
        let mut mounted = Mounted::tmpfs(&data);
        std::fs::write(data.join("f"), "f").unwrap();
        let file = root.join("acl.json");
        let want = [grant(&work, "r"), grant(&data, "rw")];
        let r = sync(&file, &want, who(), &none);
        assert!(r.errors.is_empty(), "{r:?}");
        assert_eq!(rights(&data.join("f"), RUN), Some(R | W));
        std::fs::rename(work.join("x"), work.join("x.old")).unwrap();
        std::os::unix::fs::symlink(&outside, work.join("x")).unwrap();
        let moved = work.join("x.old/data");
        mounted.0 = moved.clone();
        let r = sync(&file, &want[..1], who(), &none);
        // The entries are still there, and that is said.
        assert_eq!(rights(&moved.join("f"), RUN), Some(R | W));
        assert!(r.stale.contains(&data), "{r:?}");
        assert!(r.refusal().is_some());
        let r = remove_all(&file, &|_| (uid(), gid()));
        assert!(r.stale.contains(&data), "{r:?}");
        assert!(file.exists());
        // Back where it was, its own walk takes them off.
        std::fs::remove_file(work.join("x")).unwrap();
        std::fs::rename(work.join("x.old"), work.join("x")).unwrap();
        mounted.0 = data.clone();
        let r = sync(&file, &want[..1], who(), &none);
        assert!(r.stale.is_empty() && r.errors.is_empty(), "{r:?}");
        // The outer grant's rights only.
        assert_eq!(rights(&data.join("f"), RUN), Some(R));
        drop(mounted);
    }

    /// The same for an inner grant below a folder of another account's that
    /// the owner may not list any more: the walk around it cannot see it.
    #[test]
    fn a_revoked_inner_grant_the_owner_cannot_reach_stays_stale() {
        if !in_a_namespace("a_revoked_inner_grant_the_owner_cannot_reach_stays_stale") {
            return;
        }
        let Some(d) = tree() else { return };
        let root = std::fs::canonicalize(d.path()).unwrap();
        let work = root.join("work");
        let other = work.join("other");
        let mine = other.join("mine");
        std::fs::create_dir_all(&mine).unwrap();
        std::fs::write(mine.join("f"), "f").unwrap();
        std::os::unix::fs::chown(&other, Some(4303), Some(4303)).unwrap();
        let file = root.join("acl.json");
        let want = [grant(&work, "r"), grant(&mine, "rw")];
        let r = sync(&file, &want, who(), &none);
        assert!(r.errors.is_empty(), "{r:?}");
        assert_eq!(rights(&mine.join("f"), RUN), Some(R | W));
        // The other account closes its folder (open again at the end, so
        // that the folder can be removed also when the test fails).
        struct Reopen<'a>(&'a Path);
        impl Drop for Reopen<'_> {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(self.0, std::fs::Permissions::from_mode(0o755));
            }
        }
        let _reopen = Reopen(&other);
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o700)).unwrap();
        let r = without_passing(|| sync(&file, &want[..1], who(), &none));
        assert_eq!(rights(&mine.join("f"), RUN), Some(R | W));
        assert!(r.stale.contains(&mine), "{r:?}");
        let r = without_passing(|| remove_all(&file, &|_| (uid(), gid())));
        assert!(r.stale.contains(&mine), "{r:?}");
        // Open again, the revoke goes through.
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o755)).unwrap();
        let r = without_passing(|| sync(&file, &want[..1], who(), &none));
        assert!(r.stale.is_empty() && r.errors.is_empty(), "{r:?}");
        assert_eq!(rights(&mine.join("f"), RUN), Some(R));
    }

    /// After the owner changed, the entries of the earlier owner's grants
    /// that could not come off stay in the record ([`Record::left`]): every
    /// sync walks them again and refuses nerve-run's commands while one is
    /// left, and `uninstall` takes them off.
    #[test]
    fn what_an_earlier_owner_left_stays_until_it_comes_off() {
        if uid() == 0 {
            return;
        }
        let Some(d) = tree() else { return };
        let root = std::fs::canonicalize(d.path()).unwrap();
        let work = root.join("work");
        let sub = work.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("f"), "f").unwrap();
        let file = root.join("acl.json");
        let want = [grant(&work, "rw")];
        let r = sync(&file, &want, who(), &none);
        assert!(r.errors.is_empty(), "{r:?}");
        assert_eq!(rights(&sub.join("f"), RUN), Some(R | W));
        struct Reopen<'a>(&'a Path);
        impl Drop for Reopen<'_> {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(self.0, std::fs::Permissions::from_mode(0o755));
            }
        }
        let _reopen = Reopen(&sub);
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o000)).unwrap();
        // Another owner now, with no grants.
        let new = Who {
            run: RUN,
            owner: uid() + 1,
        };
        let r = sync(&file, &[], new, &none);
        assert!(r.refusal().is_some(), "{r:?}");
        assert_eq!(recorded(&file).map(|(_, left)| left), Some(true));
        assert!(behind(&file, &[], new, true));
        // Still there at the next sync.
        let r = sync(&file, &[], new, &none);
        assert!(r.stale.contains(&work), "{r:?}");
        // Open again, it comes off, and nothing is left.
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755)).unwrap();
        let r = sync(&file, &[], new, &none);
        assert!(r.stale.is_empty() && r.errors.is_empty(), "{r:?}");
        assert_eq!(rights(&sub.join("f"), RUN), None);
        assert_eq!(recorded(&file), None);
        // uninstall takes what is left off too.
        let r = sync(&file, &want, who(), &none);
        assert!(r.errors.is_empty(), "{r:?}");
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o000)).unwrap();
        let r = sync(&file, &[], new, &none);
        assert!(r.refusal().is_some(), "{r:?}");
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755)).unwrap();
        let r = remove_all(&file, &|_| (uid(), gid()));
        assert!(r.stale.is_empty(), "{r:?}");
        assert_eq!(rights(&sub.join("f"), RUN), None);
        assert!(!file.exists());
    }
}
