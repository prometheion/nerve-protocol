//! The folder grants of Windows folder mode (docs/dev/windows.md). Each
//! pairing's commands run in an AppContainer of their own
//! (`nerve_sandbox::appcontainer`), which reaches only what carries a grant
//! for its SID. The node puts those grants on the center's folders, with the
//! rights of their flags (`exec::container_grants`), so the grants follow
//! the folders: a folder added gets one, a folder or center removed loses
//! it, and `uninstall` takes them all off. They follow the folders whatever
//! the mode; only folder mode runs commands in the container.
//!
//! The node keeps a record of the grants it put on (`grants.json` in its
//! state folder), so it finds them again to take them off, also after the
//! config changed while it did not run. It brings them in line when it
//! starts, when its config changes (also before the control pipe answers a
//! folder change, crate::pipe), and before each folder-mode command; the
//! CLI does when it writes the config itself, which on Windows it does for
//! every other change and when no node runs (`cli::edit`). The comparison
//! and the record are plain logic, tested on every platform; the change on
//! a folder is the caller's ([`Folders`]).
//!
//! A grant is an entry in the folder's own access list, so it goes where the
//! folder goes: the record keeps which object it is on (its file ID), and a
//! grant whose folder was moved or renamed comes off where the folder is
//! now. A folder made again in place of a granted one has no grant, so each
//! sync looks at every grant and puts a missing one on again.
//!
//! Commands move only what they read and write, and a granted folder only
//! out of another one they read and write (`nerve_sandbox::acl`), so taking
//! a grant off where a moved folder is now makes nothing readable that was
//! not. Where they write, though, they can put something in place of a
//! granted folder inside it, such as a junction to another folder; a grant
//! goes on there only on a folder of its own ([`Folders::set`]).
//!
//! A change of a grant passes down to what is below its folder only as far
//! as it changes something (`nerve_sandbox::inherit`), and looks for hard
//! links only there (`held`). The first grant of a large folder still
//! reaches every file in it, so a change that takes long says how far it is
//! ([`apply`]).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
#[cfg(any(windows, test))]
use std::time::{Duration, Instant};

use nerve_policy::config::{Access, NodeConfig};
use nerve_policy::paths::within;
use nerve_policy::protected::Platform;
pub use nerve_sandbox::acl::Found;
use nerve_sandbox::acl::{Untouched, untouched_by};
#[cfg(any(windows, test))]
use nerve_sandbox::inherit::Walked;
use nerve_transport::files::Format;
use serde::{Deserialize, Serialize};

use crate::paths::NodePaths;

/// One grant the node put on a folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    /// The AppContainer it is for ([`container`]).
    pub container: String,
    pub path: PathBuf,
    pub access: Access,
    /// The object that carries it ([`Folders::look`]), to find it again
    /// when it was moved. None in what the config wants, and where the
    /// volume names no object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// A change of the grant on its folder started and may have stopped
    /// part way (it failed, or the node stopped): what it changed below the
    /// folder does not show on the folders above it. The next change there
    /// goes into every folder below ([`sync`]).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unfinished: bool,
    /// The flags of each change that may have stopped part way since the
    /// last one that finished: what it wrote below the folder may give
    /// those, whatever the folder shows. Empty once a change finished.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub toward: Vec<Access>,
    /// A grant of no flag (a closed folder) whose folder was moved away
    /// from the place closed to its container, which this names: it stays
    /// where the folder is now while that place is closed ([`sync`]), as
    /// what the folder holds is what the owner closed. `None` for every
    /// other grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<PathBuf>,
}

impl Grant {
    /// Every set of flags the grant may give somewhere below its folder:
    /// its own, and where a change stopped part way, those it was heading
    /// for.
    fn states(&self) -> impl Iterator<Item = Access> + '_ {
        std::iter::once(self.access).chain(self.toward.iter().copied())
    }

    /// The grant marked as one whose change may stop part way, heading for
    /// `to` (`None`: taken off, which gives nothing).
    fn heading(&self, to: Option<Access>) -> Grant {
        let mut g = Grant {
            unfinished: true,
            ..self.clone()
        };
        if let Some(a) = to
            && !g.toward.contains(&a)
        {
            g.toward.push(a);
        }
        g
    }

    fn same_place(&self, other: &Grant) -> bool {
        self.container == other.container
            && within(&self.path, &other.path)
            && within(&other.path, &self.path)
    }
}

/// The record of the grants the node put on.
pub fn record_file(paths: &NodePaths) -> PathBuf {
    paths.state_dir.join("grants.json")
}

/// The AppContainer of the commands of the pairing `node_id` (the node's id
/// at its center, made fresh at each pairing) on the node at `paths`: one
/// per pairing and per node, so neither reaches another's folders. Not by
/// the center's name: a command may give what it makes entries of its own
/// for its container, which the node does not take off, and a later
/// pairing, also of the same center or under the same name, must not find
/// them. A name of 30 characters of `[a-z0-9.]`, within Windows' 64.
pub fn container(paths: &NodePaths, node_id: &str) -> String {
    container_at(&paths.state_dir.display().to_string(), node_id)
}

/// [`container`] for the state folder spelled `state`. The name hashes the
/// spelling, not the folder: the default folder is `…\.local/state/nerve`
/// to the node and `…\.local\state\nerve` to whoever types it.
fn container_at(state: &str, node_id: &str) -> String {
    let seed = format!("{state}\n{node_id}");
    let d = ring::digest::digest(&ring::digest::SHA256, seed.as_bytes());
    let hex: String = d.as_ref()[..12]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("nerve.{hex}")
}

/// The grants the config asks for: every center's folders, each with the
/// flags of its sets (`exec::container_grants`), and a grant of no flag,
/// which closes it, on a folder without one inside a granted folder.
/// `home` is the `~` of the rules, the home of the account commands run as.
/// A folder whose
/// resolution crosses a link or junction at or inside a place where any
/// center's commands may write gets no grant, wherever that link leads
/// (`exec::led_away`): a command may have put it there.
pub fn wanted(cfg: &NodeConfig, paths: &NodePaths, home: &Path, platform: &Platform) -> Vec<Grant> {
    let own = paths.own();
    let writable: Vec<PathBuf> = cfg
        .centers
        .iter()
        .flat_map(|c| &c.policy.folders)
        .filter(|f| f.access.write)
        .filter_map(|f| nerve_policy::protected::expand(home, &f.path))
        .collect();
    cfg.centers
        .iter()
        .flat_map(|c| {
            let name = container(paths, &c.node_id);
            crate::exec::container_grants(&c.policy, home, &own, platform, &writable)
                .into_iter()
                .map(move |(path, access)| Grant {
                    container: name.clone(),
                    path,
                    access,
                    id: None,
                    unfinished: false,
                    toward: Vec::new(),
                    closed_at: None,
                })
        })
        .collect()
}

/// The grants a node wants on this machine: [`wanted`], and on the
/// installed service, whose commands run as the command account in their
/// containers, grants for that account too (`run`, its SID): a process of
/// a container opens only what both its container and its account may
/// (#149). The account's are the union of every pairing's, one per folder
/// with every flag a pairing has there; only the containers keep the
/// pairings apart. A folder closed to a container gets none.
pub fn wanted_on(
    run: Option<&str>,
    cfg: &NodeConfig,
    paths: &NodePaths,
    home: &Path,
    platform: &Platform,
) -> Vec<Grant> {
    let mut want = wanted(cfg, paths, home, platform);
    let Some(sid) = run.filter(|s| !s.is_empty()) else {
        return want;
    };
    let mut union: Vec<Grant> = Vec::new();
    for g in want.iter().filter(|g| g.access != Access::NONE) {
        match union.iter_mut().find(|u| same_path(&u.path, &g.path)) {
            Some(u) => {
                u.access.read |= g.access.read;
                u.access.write |= g.access.write;
                u.access.execute |= g.access.execute;
            }
            None => union.push(Grant {
                container: sid.to_string(),
                ..g.clone()
            }),
        }
    }
    want.extend(union);
    want
}

/// Whether the grant's `container` is an account's SID ([`wanted_on`]).
#[cfg(any(windows, test))]
fn is_account(container: &str) -> bool {
    container.starts_with("S-1-")
}

/// Whether `a` and `b` name one folder, as the grants compare them.
fn same_path(a: &Path, b: &Path) -> bool {
    within(a, b) && within(b, a)
}

/// What [`sync`] left.
#[derive(Debug, Default)]
pub struct Synced {
    /// Each change that failed.
    pub errors: Vec<String>,
    /// Grants that may be on where the folders no longer give them: their
    /// removal failed, or the object they are on could not be found. The
    /// record keeps them to try again. A command of their container must
    /// not run while one is left.
    pub stale: Vec<Grant>,
    /// Folders closed to a container (a grant of no flag) whose denying
    /// entry is not on as it should be: its change was refused or failed,
    /// or could not be made. Such a folder keeps what it inherits from the
    /// granted folder around it, so a command of that container must not
    /// run while one is left, as for [`Synced::stale`].
    pub unclosed: Vec<Grant>,
    /// Why the record could not be read or held, when it could not: which
    /// grants are on is then not known, so no command may run in any
    /// container until it can.
    pub unknown: Option<String>,
    /// Grants on a volume that is not on the machine now: nothing reaches
    /// them while it is away, and the record keeps them until it is back.
    pub away: Vec<Grant>,
    /// Containers that had grants and have none now.
    pub emptied: Vec<String>,
    /// How many grants were taken off.
    pub removed: usize,
    /// The containers' profiles a cleanup removed or left ([`remove_all`]).
    pub profiles: Profiles,
}

impl Synced {
    fn not_known(mut self, why: String) -> Synced {
        self.errors
            .push(format!("the record of the folder grants: {why}"));
        self.unknown = Some(why);
        self
    }

    /// Why a command of `container` must not run after this sync, if it
    /// must not: a grant of its own that should be off is on, or the grants
    /// are not known at all.
    pub fn refusal(&self, container: &str) -> Option<String> {
        if let Some(why) = &self.unknown {
            return Some(format!(
                "the command was not run: the node cannot tell which folders carry grants for the commands ({why})"
            ));
        }
        if let Some(g) = self.unclosed.iter().find(|g| g.container == container) {
            let wire = nerve_policy::paths::to_wire;
            return Some(match &g.closed_at {
                Some(was) => format!(
                    "the command was not run: {} is closed to this center's commands, and a command moved it to {}; move it back, or change this center's folders",
                    wire(was),
                    wire(&g.path)
                ),
                None => format!(
                    "the command was not run: {} is closed to this center's commands, and the node could not close it",
                    wire(&g.path)
                ),
            });
        }
        self.stale.iter().find(|g| g.container == container).map(|g| {
            format!(
                "the command was not run: {} keeps a grant for this center's commands that its folders no longer give, and it could not be taken off",
                nerve_policy::paths::to_wire(&g.path)
            )
        })
    }

    /// What `folder sync` hears of the sync: its errors, the folders of the
    /// grants left stale, and how many grants it walked (`walked`).
    pub fn json(&self, walked: usize) -> serde_json::Value {
        serde_json::json!({
            "errors": self.errors,
            "stale": self.stale.iter().map(|g| g.path.display().to_string()).collect::<Vec<_>>(),
            "unclosed": self.unclosed.iter().map(|g| g.path.display().to_string()).collect::<Vec<_>>(),
            "walked": walked,
        })
    }
}

/// Has the next sync walk every grant of the record `file` again, into
/// every folder below it, as after a change that stopped part way: what was
/// moved into a granted folder since, which keeps the list it had, gets the
/// grant then (`folder sync`). How many grants there are.
pub fn walk_every(file: &Path) -> Result<usize, String> {
    let _one = nerve_transport::sync::turn(&SYNC);
    let _held =
        RecordLock::take(file).map_err(|e| format!("{}: {e}", lock_file(file).display()))?;
    let record = read_record(file)?;
    if record.is_empty() {
        return Ok(0);
    }
    let marked: Vec<Grant> = record
        .iter()
        .map(|g| Grant {
            unfinished: true,
            ..g.clone()
        })
        .collect();
    write_record(file, &marked)?;
    Ok(record.len())
}

/// What a sync looks at and changes on the folders: on Windows their
/// access lists (`nerve_sandbox::appcontainer`), in the tests a fake.
pub trait Folders {
    /// What is at `path`: `None` when nothing is there.
    fn look(&mut self, path: &Path, container: &str, access: Access) -> io::Result<Option<Look>>;
    /// Where the object `id` is now; `near` is a path it had.
    fn locate(&mut self, id: &str, near: &Path) -> io::Result<Found>;
    /// Puts `container`'s grant with `access` on `path` in place of any it
    /// had, or takes it off (`None`); NotFound when nothing is there. With
    /// `own`, a grant goes on only an object of its own at `path` (not a
    /// link or junction to elsewhere, not a file with other names, and with
    /// a list that inherits); otherwise it is refused and nothing changes.
    /// A refusal, and nothing at `path`, are marked as such
    /// ([`Untouched`]); every other error may come after a part of the
    /// change was made. The change passes down to what is below `path`;
    /// `links` says which files with more than one name it may reach there,
    /// and one it may not stops it as it gets there (an error; what it
    /// changed stays). With `whole` it goes into every folder below, also
    /// where the list of `path` stays as it is ([`Grant::unfinished`]).
    /// With `expect` (a recorded id), it goes only through that object, and
    /// is refused before any write where another one is at `path` now. The
    /// id of the object it changed, when the volume names one.
    #[allow(clippy::too_many_arguments)]
    fn set(
        &mut self,
        path: &Path,
        container: &str,
        access: Option<Access>,
        own: bool,
        links: Links,
        whole: bool,
        expect: Option<&str>,
    ) -> io::Result<Option<String>>;
    /// The first file below the folder `dir` with more than one name (hard
    /// links) that a change of `container`'s grant there to `access` would
    /// reach, and how many names it has; `None` for a file or when there is
    /// none. A file that passes for cargo's `target` with `grants` (the
    /// paths of every wanted and recorded grant, `Judge`) is not
    /// one; `None` gives no pass. `whole` as for [`Folders::set`]. Changes
    /// nothing.
    fn linked(
        &mut self,
        dir: &Path,
        container: &str,
        access: Option<Access>,
        whole: bool,
        grants: Option<&[PathBuf]>,
    ) -> io::Result<Option<(PathBuf, u64)>>;
}

/// Which files with more than one name (hard links) a change of a grant
/// may reach below its folder.
#[derive(Debug, Clone, Copy)]
pub enum Links<'a> {
    /// Any: no command writes at, above or below the folder
    /// (`written_in`), so none linked a file there.
    Any,
    /// Only those that pass for cargo's `target` with these grant paths
    /// (`Judge`); none without them.
    Passing(Option<&'a [PathBuf]>),
}

/// What [`Folders::look`] saw at a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Look {
    /// The object there, when the volume names one.
    pub id: Option<String>,
    /// Whether it carries exactly the container's grant with the access
    /// asked about.
    pub granted: bool,
}

/// The record's file: its format and the grants.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordFile<G> {
    #[serde(default)]
    format: Format,
    #[serde(default)]
    grants: G,
}

fn read_record(file: &Path) -> Result<Vec<Grant>, String> {
    match std::fs::read(file) {
        Ok(b) => Format::of_json(&b)
            .check()
            .and_then(|()| {
                serde_json::from_slice::<RecordFile<Vec<Grant>>>(&b).map_err(|e| e.to_string())
            })
            .map(|r| r.grants)
            .map_err(|e| format!("{}: {e}", file.display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("{}: {e}", file.display())),
    }
}

fn write_record(file: &Path, grants: &[Grant]) -> Result<(), String> {
    let record = RecordFile {
        format: Format::CURRENT,
        grants,
    };
    let json = serde_json::to_vec_pretty(&record).expect("grants serialise");
    nerve_transport::files::write_private(file, &json).map_err(|e| {
        format!(
            "cannot write the record of the folder grants {}: {e}",
            file.display()
        )
    })
}

/// Whether commands may put something at `path`: it lies inside a folder
/// that a container may write, by a wanted or a recorded grant. What is
/// there may then be a junction to another folder, or a file linked to one
/// elsewhere, and a grant on it would reach that.
fn open_to_commands(path: &Path, want: &[Grant], record: &[Grant]) -> bool {
    want.iter()
        .chain(record)
        .any(|g| g.states().any(|a| a.write) && within(path, &g.path) && !within(&g.path, path))
}

/// Whether commands may write in `path` or below it: a folder a container
/// may write, by a wanted or a recorded grant (also by the flags a change
/// that stopped part way was heading for, [`Grant::states`]), is `path`,
/// holds it, or lies inside it. A change of its list that Windows passes
/// down then reaches what commands put there, also through a writable
/// folder below it.
fn written_in(path: &Path, want: &[Grant], record: &[Grant]) -> bool {
    want.iter()
        .chain(record)
        .any(|g| g.states().any(|a| a.write) && (within(path, &g.path) || within(&g.path, path)))
}

/// Why the list of `path` must not be changed now for `container` and
/// `access`, if it must not: the change passes down to what is below
/// `path`, and a file there with more than one name (a hard link) shares
/// its list with its other names, which may be in a folder the commands may
/// only write. Commands may have linked it there, so the change is refused
/// until the link is gone. Only the files the change reaches count, and
/// only where `links` asks for it.
fn held(
    folders: &mut impl Folders,
    path: &Path,
    container: &str,
    access: Option<Access>,
    whole: bool,
    links: Links,
) -> Option<String> {
    let Links::Passing(grants) = links else {
        return None;
    };
    match folders.linked(path, container, access, whole, grants) {
        Ok(None) => None,
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Ok(Some((file, names))) => Some(format!(
            "the node does not change the permissions of {}, since {} below it has {names} names (hard links), and the change would reach them all",
            path.display(),
            file.display()
        )),
        Err(e) => Some(format!(
            "the node does not change the permissions of {}, since it cannot check it for hard links: {e}",
            path.display()
        )),
    }
}

/// The folder cargo fills with hard links between names of its own: each
/// program and test is built under two names in `target`. Matched by the
/// whole name of a folder, never by a start of one.
#[cfg(any(windows, test))]
const BUILD_FOLDER: &str = "target";

/// Whether a folder of `rest` (a path below another, without its last
/// part, the file's name) is named [`BUILD_FOLDER`].
#[cfg(any(windows, test))]
fn in_build_folder(rest: &Path) -> bool {
    let mut parts: Vec<_> = rest.components().collect();
    parts.pop();
    parts.iter().any(|c| c.as_os_str() == BUILD_FOLDER)
}

/// The first file below the folder `dir` with more than one name, by
/// `count`, that does not pass ([`Judge`]), and how many names it has;
/// `None` for a file or when there is none. Only plain folders are walked
/// into: a link or junction below `dir` is not followed, and is checked as
/// itself like every other entry that is not a folder (`count` opens it as
/// itself), so a file that is a reparse point of another kind is checked
/// too.
///
/// The fake volume of the tests walks the whole folder so. On Windows the
/// walk goes only as far as the change reaches
/// (`nerve_sandbox::appcontainer::reaches`), which skips what the change
/// leaves as it is, and judges each file with more than one name it reaches
/// the same way.
#[cfg(all(test, unix))]
fn linked_below(
    dir: &Path,
    grants: Option<&[PathBuf]>,
    count: &dyn Fn(&Path) -> io::Result<u64>,
    names: &dyn Fn(&Path) -> io::Result<Vec<PathBuf>>,
) -> io::Result<Option<(PathBuf, u64)>> {
    // `dir` itself as the change reaches it: through a link of the owner's.
    if !std::fs::metadata(dir)?.is_dir() {
        return Ok(None);
    }
    let judge = Judge::new(dir, grants);
    let gone = |e: &io::Error| e.kind() == io::ErrorKind::NotFound;
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        let entries = match std::fs::read_dir(&d) {
            Ok(e) => e,
            Err(e) if gone(&e) => continue,
            Err(e) => return Err(e),
        };
        for e in entries {
            let path = e?.path();
            let m = match std::fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(e) if gone(&e) => continue,
                Err(e) => return Err(e),
            };
            // A link or junction to a folder is not a folder here.
            if m.is_dir() {
                todo.push(path);
                continue;
            }
            let n = match count(&path) {
                Ok(n) => n,
                Err(e) if gone(&e) => continue,
                Err(e) => return Err(e),
            };
            if n >= 2 && !judge.passes(&path, n, names)? {
                return Ok(Some((path, n)));
            }
        }
    }
    Ok(None)
}

/// Whether a file below the folder `dir` with more than one name may be
/// changed all the same. Only one kind does, for what cargo makes: a file
/// below a [`BUILD_FOLDER`] of `dir` passes when its names are all listed
/// (as many as it has), every one inside `dir` (compared resolved),
/// below a build folder of it, and held by exactly the same of `grants`
/// (the paths of every wanted and recorded grant, of any container) as the
/// walked name. Such a link gains nothing from the change: every name gets
/// the same rights from the node's grants. A command may also give a folder
/// it makes an entry of its own, which the change then passes to a file
/// linked into it; `sync` gives `grants` only where every container that
/// may write may read too ([`pass`]), so such an entry opens nothing it
/// could not read already. A file with a name anywhere else does not pass,
/// and neither does one whose names cannot all be listed. Without `grants`
/// (a granted folder is not where its record says, or one at, above or
/// inside `dir` may be written but not read, `sync`) nothing passes.
#[cfg(any(windows, test))]
struct Judge<'a> {
    dir: &'a Path,
    /// The place the names are compared with; one that cannot be resolved
    /// holds no name, so nothing passes.
    real_dir: Option<PathBuf>,
    grants: Option<&'a [PathBuf]>,
}

#[cfg(any(windows, test))]
impl<'a> Judge<'a> {
    fn new(dir: &'a Path, grants: Option<&'a [PathBuf]>) -> Judge<'a> {
        Judge {
            dir,
            real_dir: nerve_policy::paths::resolve(dir).ok(),
            grants,
        }
    }

    /// Whether the file at `path` (below `dir`) may pass at all, before its
    /// names are looked at.
    fn may(&self, path: &Path) -> bool {
        let rest = path.strip_prefix(self.dir).unwrap_or(path);
        self.real_dir.is_some() && self.grants.is_some() && in_build_folder(rest)
    }

    /// Whether the file at `path` (below `dir`), with `n` names, passes:
    /// `all` are its names. The change, which holds the file open, gives
    /// them as the file itself has them, not by its path: so where a command
    /// removed the name the walk found, the names it has left count.
    fn holds(&self, path: &Path, n: u64, all: &[PathBuf]) -> bool {
        let (Some(real_dir), Some(grants)) = (&self.real_dir, self.grants) else {
            return false;
        };
        if !self.may(path) {
            return false;
        }
        // The grants that hold a place, by their place in `grants`.
        let held_by = |p: &Path| -> Vec<usize> {
            grants
                .iter()
                .enumerate()
                .filter(|(_, g)| within(p, g))
                .map(|(i, _)| i)
                .collect()
        };
        let rest = path.strip_prefix(self.dir).unwrap_or(path);
        let depth = real_dir.components().count();
        let mine = held_by(&real_dir.join(rest));
        all.len() as u64 >= n
            && all.iter().all(|name| {
                let rest: PathBuf = name.components().skip(depth).collect();
                within(name, real_dir)
                    && !within(real_dir, name)
                    && in_build_folder(&rest)
                    && held_by(name) == mine
            })
    }

    /// Whether the file at `path`, with `n` names, passes in a walk by path,
    /// its names listed by `names`. A file gone meanwhile passes, as such a
    /// walk no longer reaches it; one whose names cannot be listed while it
    /// is there (a path too long for it, say) is an error.
    #[cfg(all(test, unix))]
    fn passes(
        &self,
        path: &Path,
        n: u64,
        names: &dyn Fn(&Path) -> io::Result<Vec<PathBuf>>,
    ) -> io::Result<bool> {
        let gone = |e: &io::Error| e.kind() == io::ErrorKind::NotFound;
        if !self.may(path) {
            return Ok(false);
        }
        match names(path) {
            Ok(all) => Ok(self.holds(path, n, &all)),
            Err(e) if gone(&e) && matches!(std::fs::symlink_metadata(path), Err(m) if gone(&m)) => {
                Ok(true)
            }
            Err(e) => Err(io::Error::other(format!(
                "cannot list the names of {}: {e}",
                path.display()
            ))),
        }
    }
}

/// The grant paths for the pass for cargo's `target` in a walk of `dir`
/// (`Judge`): `places`, or none when a wanted or recorded grant of
/// any container at, above or inside `dir` may write but not read. A
/// command that may make a folder there may give it an entry of its own,
/// read for its container, say, and a change of `dir` passes that entry to
/// a file linked into the folder: so the pass is given only where every
/// container that can make such a folder can read every name there already.
fn pass<'a>(
    dir: &Path,
    places: Option<&'a [PathBuf]>,
    want: &[Grant],
    record: &[Grant],
) -> Option<&'a [PathBuf]> {
    let blind = want.iter().chain(record).any(|g| {
        g.states().any(|a| a.write && !a.read) && (within(dir, &g.path) || within(&g.path, dir))
    });
    if blind { None } else { places }
}

/// One process changes grants at a time: commands of several centers, and
/// the daemon's own sync, may want it at once.
static SYNC: Mutex<()> = Mutex::new(());

/// The lock file beside the record (`grants.json.lock`).
fn lock_file(record: &Path) -> PathBuf {
    let mut s = record.as_os_str().to_owned();
    s.push(".lock");
    PathBuf::from(s)
}

/// Holds the record while it lives. Other processes change the grants too
/// (the CLI, while a node run by hand does), each reading the record,
/// changing folders and writing it back, so one must not write over what
/// another recorded meanwhile. The lock file is held with flock on Unix,
/// and on Windows by keeping it open for nobody else; both end with the
/// process.
struct RecordLock {
    _file: std::fs::File,
}

impl RecordLock {
    fn take(record: &Path) -> io::Result<RecordLock> {
        let path = lock_file(record);
        if let Some(dir) = path.parent() {
            nerve_transport::files::create_private_dir(dir)?;
        }
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
            let file = opts.open(&path)?;
            loop {
                // SAFETY: flock on a descriptor this function owns.
                if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                    return Ok(RecordLock { _file: file });
                }
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::Interrupted {
                    return Err(e);
                }
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const ERROR_SHARING_VIOLATION: i32 = 32;
            opts.share_mode(0);
            loop {
                match opts.open(&path) {
                    Ok(file) => return Ok(RecordLock { _file: file }),
                    Err(e) if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => {
                        std::thread::sleep(std::time::Duration::from_millis(50))
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }
}

/// Brings the grants in line with `want`, holding the record meanwhile.
///
/// Each recorded grant is looked at where its object is now. One that is
/// not wanted is taken off; one whose object moved away from its path (a
/// rename, a move on the volume) is taken off where the object is now,
/// since it went along. A wanted one whose object is at its path with the
/// same flags stays when the grant is still on, and is put on again when it
/// is not (the object was made again, or its list changed); one with other
/// flags is replaced. Each wanted grant without a record is put on, and is
/// recorded before it is, so no failure can leave a grant on that the record
/// does not hold. A path that is gone gets no grant: it gets one at a later
/// sync. A path inside a folder commands may write gets one only on an
/// object of its own ([`open_to_commands`]). A grant that could not be taken
/// off, or whose object could not be found, stays recorded and is stale. A
/// record that cannot be read stops the sync, since the grants in it could
/// not be found again.
pub fn sync(file: &Path, want: &[Grant], folders: &mut impl Folders) -> Synced {
    let _one = nerve_transport::sync::turn(&SYNC);
    sync_in_turn(file, want, folders)
}

/// [`sync`] by a caller that holds the turn ([`SYNC`]) already: the node,
/// which removes profiles in the same turn ([`apply_in`]).
fn sync_in_turn(file: &Path, want: &[Grant], folders: &mut impl Folders) -> Synced {
    let out = Synced::default();
    // Without a state folder nothing is recorded, and with nothing wanted
    // there is nothing to do: no folder and no lock file are made for it
    // (uninstall on a machine where the node never ran).
    let dir = file.parent().unwrap_or(Path::new(""));
    if want.is_empty()
        && matches!(std::fs::metadata(dir), Err(e) if e.kind() == io::ErrorKind::NotFound)
    {
        return out;
    }
    let _held = match RecordLock::take(file) {
        Ok(l) => l,
        Err(e) => return out.not_known(format!("{}: {e}", lock_file(file).display())),
    };
    let record = match read_record(file) {
        Ok(r) => r,
        Err(e) => return out.not_known(e),
    };
    let mut out = out;
    // Whether the object with a recorded grant is still at its path. A
    // record without the object's id takes the one there; one that cannot
    // be told counts as there (a change there fails in turn and keeps it).
    let at_path = |old: &Grant, here: &io::Result<Option<Look>>| match here {
        Ok(Some(l)) => old.id.is_none() || l.id.is_none() || old.id == l.id,
        Ok(None) => false,
        Err(_) => true,
    };
    // Each recorded grant's object, looked up before anything changes: and
    // where one is not at its path, where it is now.
    let mut seen = Vec::with_capacity(record.len());
    for old in &record {
        let here = folders.look(&old.path, &old.container, old.access);
        let found = (!at_path(old, &here)).then(|| match &old.id {
            Some(id) => folders.locate(id, &old.path),
            None => Ok(Found::Gone),
        });
        seen.push((here, found));
    }
    // Where every wanted and recorded grant is, for the hard-link check's
    // pass for cargo's `target` (`Judge`). It compares the grants by
    // their paths, while a grant's entry goes with its folder: so when a
    // granted folder is somewhere else now, or cannot be told, the paths do
    // not show what holds a name, and this sync gives no pass.
    let settled = seen.iter().all(|(here, found)| {
        here.is_ok() && !matches!(found, Some(Ok(Found::At(_))) | Some(Err(_)))
    });
    let places: Option<Vec<PathBuf>> =
        settled.then(|| want.iter().chain(&record).map(|g| g.path.clone()).collect());
    let pass_at = |dir: &Path| pass(dir, places.as_deref(), want, &record);
    // The files with more than one name a change of `dir` may reach.
    let links_at = |dir: &Path| {
        if written_in(dir, want, &record) {
            Links::Passing(pass_at(dir))
        } else {
            Links::Any
        }
    };
    // A change that changed nothing at all is marked so (`acl::untouched`):
    // gone (nothing at its path) or refused before it wrote. An error of
    // any other origin, whatever its kind, may come after a part of the
    // change was written.
    let gone = |e: &io::Error| untouched_by(e) == Some(Untouched::Gone);
    let refusal = |e: &io::Error| untouched_by(e) == Some(Untouched::Refused);
    // A place where a change may have stopped part way: what it changed
    // below the folder does not show on the folders above it, so the next
    // change there goes into every folder below, also one back to the flags
    // the folder shows. Only a mark on the object at the place now counts:
    // that of a folder moved away is about its walk where it is now (whose
    // take-off goes into every folder anyway), not about one made anew in
    // its place.
    let marked_here: Vec<bool> = record
        .iter()
        .zip(&seen)
        .map(|(o, (here, _))| o.unfinished && at_path(o, here))
        .collect();
    let unfinished_at = |g: &Grant| {
        record
            .iter()
            .zip(&marked_here)
            .any(|(o, m)| *m && o.same_place(g))
    };
    // Whether `place` is closed to `container` by a wanted grant of no flag.
    let closes = |container: &str, place: &Path| {
        want.iter().any(|w| {
            w.container == container && w.access == Access::NONE && same_path(&w.path, place)
        })
    };
    // A denying grant on a closed folder that a command moved: within the
    // granted folder around it a command renames it through that folder's
    // rights, whatever its own entry says. It stays on where the folder is
    // now, recorded there, while its place is closed (the place is put
    // under a new entry of its own, as any folder made again): taking it
    // off would give the commands what the owner closed.
    let keeps_closed = |old: &Grant| {
        old.access == Access::NONE
            && closes(
                &old.container,
                old.closed_at.as_deref().unwrap_or(&old.path),
            )
    };
    // One such grant at its new place, which no wanted grant closes. It
    // stays also where a wanted grant of its container gives that place
    // flags: putting that one on would replace the denying entry
    // (`Folders::set`) and open what the owner closed, so it does not go
    // on (`onto` below).
    let moved_closed = |old: &Grant| {
        old.closed_at.is_some()
            && keeps_closed(old)
            && !want
                .iter()
                .any(|w| w.same_place(old) && w.access == Access::NONE)
    };
    // Whether the sync changes the folder of a recorded grant: it is taken
    // off, here or where its folder is now, or replaced. Each such grant is
    // marked in the record before anything changes, and the mark goes once
    // the change is done; so a change that stops part way, also by the
    // node's own end, leaves its mark.
    let changes =
        |old: &Grant, (here, found): &(io::Result<Option<Look>>, Option<io::Result<Found>>)| {
            if at_path(old, here) {
                !moved_closed(old)
                    && (!want
                        .iter()
                        .any(|w| w.same_place(old) && w.access == old.access)
                        || !matches!(here, Ok(Some(l)) if l.granted)
                        || unfinished_at(old))
            } else {
                matches!(found, Some(Ok(Found::At(_)))) && !keeps_closed(old)
            }
        };
    let mut changed = false;
    let mut unmarkable = false;
    if record.iter().zip(&seen).any(|(old, s)| changes(old, s)) {
        let marked: Vec<Grant> = record
            .iter()
            .zip(&seen)
            .map(|(old, s)| {
                if changes(old, s) {
                    let to = want.iter().find(|w| w.same_place(old)).map(|w| w.access);
                    old.heading(to)
                } else {
                    old.clone()
                }
            })
            .collect();
        if let Err(e) = write_record(file, &marked) {
            // Only take-offs run then, here and where moved folders are
            // now: one goes into every folder, and one that stops part way
            // gives less, never more. Puts and replacements wait for a sync
            // that can mark them, and a grant one would change is stale
            // where it may give flags that are not wanted.
            out.errors.push(e);
            unmarkable = true;
        } else {
            // The record is written again at the end, with the marks of
            // what was done taken off.
            changed = true;
        }
    }
    let mut kept: Vec<Grant> = Vec::new();
    // The wanted grants that are on as they should be.
    let mut done = vec![false; want.len()];
    // The wanted grants of no flag whose denying entry is on, or that have
    // nothing to close; those that are not stop their container's commands
    // ([`Synced::unclosed`]).
    let mut shut: Vec<bool> = want.iter().map(|w| w.access != Access::NONE).collect();
    let index = |w: &Grant| want.iter().position(|x| std::ptr::eq(x, w));
    // Recorded grants at their path that a wanted one replaces below.
    let mut replaced: Vec<Grant> = Vec::new();
    for (old, (here, found)) in record.iter().zip(seen) {
        let wanted = want.iter().position(|w| w.same_place(old));
        if at_path(old, &here) {
            let look = here.ok().flatten();
            match wanted {
                _ if moved_closed(old) => {
                    if !look.is_some_and(|l| l.granted) {
                        out.unclosed.push(old.clone());
                    }
                    kept.push(old.clone());
                }
                // Another record of the same object holds the place.
                Some(i) if done[i] => changed = true,
                Some(i)
                    if want[i].access == old.access
                        && look.as_ref().is_some_and(|l| l.granted)
                        && !unfinished_at(old) =>
                {
                    done[i] = true;
                    shut[i] = true;
                    let id = old.id.clone().or_else(|| look.and_then(|l| l.id));
                    changed |= id != old.id;
                    kept.push(Grant { id, ..old.clone() });
                }
                Some(i) if unmarkable => {
                    if old.states().any(|a| a != want[i].access) {
                        out.stale.push(old.clone());
                    }
                    kept.push(old.clone());
                }
                Some(_) => replaced.push(old.clone()),
                None => {
                    // Taking it off passes the change down too.
                    let links = links_at(&old.path);
                    let hold = held(folders, &old.path, &old.container, None, false, links);
                    let refused = hold.is_some();
                    match hold.map_or_else(
                        || {
                            let id = old.id.as_deref();
                            folders.set(&old.path, &old.container, None, false, links, false, id)
                        },
                        |why| Err(io::Error::other(why)),
                    ) {
                        Ok(_) => {
                            changed = true;
                            out.removed += 1;
                        }
                        Err(e) if gone(&e) => changed = true,
                        Err(e) => {
                            out.errors.push(format!(
                                "cannot take the grant off {}: {e}",
                                old.path.display()
                            ));
                            out.stale.push(old.clone());
                            kept.push(Grant {
                                unfinished: old.unfinished || !(refused || refusal(&e)),
                                ..old.clone()
                            });
                        }
                    }
                }
            }
            continue;
        }
        // Moved, made again, or deleted: the grant is where the object is.
        match found.unwrap_or(Ok(Found::Gone)) {
            Ok(Found::Gone) => changed = true,
            // Nothing reaches it while its volume is away; a later sync
            // looks again.
            Ok(Found::Away) => {
                out.away.push(old.clone());
                kept.push(old.clone());
            }
            Ok(Found::At(now)) if keeps_closed(old) => {
                changed = true;
                let granted = matches!(
                    folders.look(&now, &old.container, Access::NONE),
                    Ok(Some(l)) if l.granted
                );
                let g = Grant {
                    closed_at: Some(old.closed_at.clone().unwrap_or_else(|| old.path.clone())),
                    path: now,
                    ..old.clone()
                };
                if !granted {
                    out.unclosed.push(g.clone());
                }
                kept.push(g);
            }
            Ok(Found::At(now)) => {
                // Commands wrote in it, or below it, where it was (the record
                // still holds what was below it under its old path), or write
                // where it is now, and taking the grant off passes the change
                // down.
                let links = if old.states().any(|a| a.write)
                    || written_in(&old.path, want, &record)
                    || written_in(&now, want, &record)
                {
                    Links::Passing(pass_at(&now))
                } else {
                    Links::Any
                };
                let hold = held(folders, &now, &old.container, None, false, links);
                let refused = hold.is_some();
                match hold.map_or_else(
                    || {
                        let id = old.id.as_deref();
                        folders.set(&now, &old.container, None, false, links, false, id)
                    },
                    |why| Err(io::Error::other(why)),
                ) {
                    Ok(_) => {
                        changed = true;
                        out.removed += 1;
                    }
                    Err(e) if gone(&e) => changed = true,
                    Err(e) => {
                        out.errors.push(format!(
                            "cannot take the grant off {}, which was {}: {e}",
                            now.display(),
                            old.path.display()
                        ));
                        out.stale.push(old.clone());
                        kept.push(Grant {
                            unfinished: old.unfinished || !(refused || refusal(&e)),
                            ..old.clone()
                        });
                    }
                }
            }
            Err(e) => {
                out.errors.push(format!(
                    "cannot find what was {} again to take its grant off: {e}",
                    old.path.display()
                ));
                out.stale.push(old.clone());
                kept.push(old.clone());
            }
        }
    }
    // What was on at a place stays on when its replacement fails, and
    // unfinished where the replacement may have stopped part way (`cut`):
    // stale when any flags it may give below its folder are not the wanted
    // ones, also those of an earlier change that stopped there.
    let keep_replaced = |w: &Grant, out: &mut Synced, kept: &mut Vec<Grant>, cut: bool| {
        for o in replaced.iter().filter(|o| o.same_place(w)) {
            let o = if cut {
                o.heading(Some(w.access))
            } else {
                o.clone()
            };
            if o.states().any(|a| a != w.access) {
                out.stale.push(o.clone());
            }
            kept.push(o);
        }
    };
    // A wanted grant with flags at or below the place where a command
    // moved a folder closed to its container: at the place it would take
    // the denying entry's, and below it an allowing entry comes before the
    // inherited deny, so either opens what the owner closed. It does not go
    // on, and the container's commands stop until the folder is moved back
    // or the owner changes the folders.
    let moved_over = |k: &Grant, w: &Grant| {
        k.closed_at.is_some()
            && keeps_closed(k)
            && k.container == w.container
            && within(&w.path, &k.path)
    };
    let onto: Vec<bool> = want
        .iter()
        .map(|w| w.access != Access::NONE && kept.iter().any(|k| moved_over(k, w)))
        .collect();
    for w in want.iter().zip(&onto).filter(|(_, o)| **o).map(|(w, _)| w) {
        out.errors.push(format!(
            "the node does not grant {} to the commands, since a command moved a folder closed to them there",
            w.path.display()
        ));
        if let Some(k) = kept.iter().find(|k| moved_over(k, w)) {
            out.unclosed.push(k.clone());
        }
        keep_replaced(w, &mut out, &mut kept, false);
    }
    let todo: Vec<&Grant> = want
        .iter()
        .zip(done.iter().zip(&onto))
        .filter(|(_, (d, o))| !**d && !**o)
        .map(|(w, _)| w)
        .collect();
    if !todo.is_empty() && !unmarkable {
        // A new grant is recorded with the object at its path, as one that
        // goes on is: should its change stop part way and the folder be
        // moved, the next sync finds it where it is now.
        let ids: Vec<Option<String>> = todo
            .iter()
            .map(|w| {
                if replaced.iter().any(|o| o.same_place(w)) {
                    return None;
                }
                match folders.look(&w.path, &w.container, w.access) {
                    Ok(Some(l)) => l.id,
                    _ => None,
                }
            })
            .collect();
        // Recorded, and marked, before they go on.
        let mut ahead = kept.clone();
        ahead.extend(replaced.iter().map(|o| {
            let to = todo.iter().find(|w| w.same_place(o)).map(|w| w.access);
            o.heading(to)
        }));
        ahead.extend(
            todo.iter()
                .zip(&ids)
                .filter(|(w, _)| !replaced.iter().any(|o| o.same_place(w)))
                .map(|(w, id)| Grant {
                    unfinished: true,
                    id: id.clone(),
                    ..(*w).clone()
                }),
        );
        match write_record(file, &ahead) {
            Err(e) => {
                // Nothing goes on.
                out.errors.push(e);
                for w in &todo {
                    keep_replaced(w, &mut out, &mut kept, false);
                }
            }
            Ok(()) => {
                changed = true;
                for (w, id) in todo.into_iter().zip(ids) {
                    // A denying entry is no exception: each object below
                    // whose list changes gets the whole list worked out from
                    // the folder's, with what the folder inherits, and a file
                    // with other names elsewhere would carry it there too.
                    // One held back stops its container's commands
                    // (`Synced::unclosed`).
                    let links = links_at(&w.path);
                    // Refused before anything changed: what was there stays.
                    let whole = unfinished_at(w);
                    let access = Some(w.access);
                    if let Some(why) = held(folders, &w.path, &w.container, access, whole, links) {
                        out.errors.push(why);
                        keep_replaced(w, &mut out, &mut kept, false);
                        continue;
                    }
                    let own = open_to_commands(&w.path, want, &record);
                    // Only through the object recorded for the place.
                    let expect = replaced
                        .iter()
                        .find(|o| o.same_place(w))
                        .map_or(id.clone(), |o| o.id.clone());
                    match folders.set(
                        &w.path,
                        &w.container,
                        access,
                        own,
                        links,
                        whole,
                        expect.as_deref(),
                    ) {
                        Ok(id) => {
                            if let Some(i) = index(w) {
                                shut[i] = true;
                            }
                            kept.push(Grant { id, ..w.clone() })
                        }
                        // Nothing there to close.
                        Err(e) if gone(&e) => {
                            if let Some(i) = index(w) {
                                shut[i] = true;
                            }
                        }
                        // Refused before anything changed: what was there
                        // stays.
                        Err(e) if refusal(&e) => {
                            out.errors.push(format!("{}: {e}", w.path.display()));
                            keep_replaced(w, &mut out, &mut kept, false);
                        }
                        Err(e) => {
                            out.errors.push(format!(
                                "cannot grant {} to the commands: {e}",
                                w.path.display()
                            ));
                            // It may be on in part, or what was there stays.
                            if !replaced.iter().any(|o| o.same_place(w)) {
                                kept.push(Grant {
                                    unfinished: true,
                                    id,
                                    ..w.clone()
                                });
                            }
                            keep_replaced(w, &mut out, &mut kept, true);
                        }
                    }
                }
            }
        }
    }
    out.unclosed.extend(
        want.iter()
            .zip(&shut)
            .filter(|(_, s)| !**s)
            .map(|(w, _)| w.clone()),
    );
    out.emptied = record
        .iter()
        .map(|g| g.container.clone())
        .filter(|c| !kept.iter().any(|k| &k.container == c))
        .collect();
    out.emptied.sort();
    out.emptied.dedup();
    if changed
        && !unmarkable
        && let Err(e) = write_record(file, &kept)
    {
        out.errors.push(e);
    }
    out
}

/// The SID of the command account, for the installed service's grants
/// ([`wanted_on`]); `None` for a node run by hand, whose commands run as
/// itself. A service without that account gets the containers' grants only:
/// it runs no command then.
#[cfg(windows)]
fn run_sid(paths: &NodePaths) -> Option<String> {
    if !crate::service::is_service_node(paths) {
        return None;
    }
    let sid = crate::win_host::sid_of(crate::account::RUN_USER)
        .and_then(|s| crate::win_host::sid_text(&s))
        .unwrap_or_default();
    Some(sid)
}

/// Brings the grants on this machine in line with the config `current`
/// gives, with the `~` of its rules ([`wanted`], [`sync`]), and removes the
/// profile of a container left without grants. `current` is asked once this
/// sync's turn has come ([`apply_in`]). Nothing to do where commands are not
/// confined by grants (Linux). `report` is told how far a change is once it
/// takes long (`Pace`): it passes down to every file and folder below the
/// folder that it changes. For the node itself, which holds the lock that
/// [`apply_outside`] looks at. `owner`: the installed service's owner, as
/// whom the folders' entries are read and changed (`Acls`).
pub fn apply(
    paths: &NodePaths,
    owner: Option<&crate::service::Account>,
    current: impl FnOnce() -> (Arc<NodeConfig>, PathBuf),
    report: &mut dyn FnMut(&str),
) -> Synced {
    #[cfg(windows)]
    {
        let run = run_sid(paths);
        let want = || {
            let (cfg, home) = current();
            let grants = wanted_on(
                run.as_deref(),
                &cfg,
                paths,
                &home,
                &crate::paths::platform(),
            );
            (grants, pairings(paths, &cfg))
        };
        apply_in(
            paths,
            want,
            &mut Acls {
                report,
                owner: owner.filter(|_| run.is_some()),
            },
            &mut WinProfiles,
        )
    }
    #[cfg(not(windows))]
    {
        let _ = (paths, owner, current, report);
        Synced::default()
    }
}

/// [`apply`] by the CLI (`report` as there): the profile of a container left without grants
/// stays while the node runs, as its commands may still use it, and
/// [`Synced::profiles`] says which went and which stayed.
pub fn apply_outside(
    paths: &NodePaths,
    cfg: &NodeConfig,
    home: &Path,
    report: &mut dyn FnMut(&str),
) -> Synced {
    #[cfg(windows)]
    {
        let want = wanted_on(
            run_sid(paths).as_deref(),
            cfg,
            paths,
            home,
            &crate::paths::platform(),
        );
        sync_outside_in(
            paths,
            &want,
            &pairings(paths, cfg),
            &mut Acls {
                report,
                owner: None,
            },
            &mut WinProfiles,
        )
    }
    #[cfg(not(windows))]
    {
        let _ = (paths, cfg, home, report);
        Synced::default()
    }
}

/// [`apply_outside`] for `want`, on `folders` and the profiles in `store`.
/// The profile of a container of `live` (the config's pairings,
/// [`pairings`]) stays, also without grants: it holds its pairing's home.
#[cfg(any(windows, test))]
fn sync_outside_in(
    paths: &NodePaths,
    want: &[Grant],
    live: &[String],
    folders: &mut impl Folders,
    store: &mut impl ProfileStore,
) -> Synced {
    let mut s = sync(&record_file(paths), want, folders);
    let emptied: Vec<String> = s
        .emptied
        .iter()
        .filter(|c| !live.contains(c))
        .cloned()
        .collect();
    let p = drop_profiles(paths, &emptied, store);
    s.errors.extend(p.errors.iter().cloned());
    s.profiles = p;
    s
}

/// The ids of the pairings in the config at `paths`, which name the
/// profiles of their containers ([`container`]) also when the state folder,
/// and the record of the grants in it, is gone. The file is read without
/// its MAC: the key is in the state folder or the keyring, which may be
/// gone too, and an id read here only leads to a container of this node.
/// A missing file names none.
pub fn node_ids(paths: &NodePaths) -> Result<Vec<String>, String> {
    // Only the ids: a config that fails a check of its own still names its
    // pairings.
    #[derive(Deserialize)]
    struct Config {
        #[serde(default, rename = "center")]
        centers: Vec<Pairing>,
    }
    #[derive(Deserialize)]
    struct Pairing {
        node_id: String,
    }
    let file = paths.config_file();
    let text = match std::fs::read_to_string(&file) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("{}: {e}", file.display())),
    };
    let c: Config = toml::from_str(&text).map_err(|e| format!("{}: {e}", file.display()))?;
    Ok(c.centers.into_iter().map(|p| p.node_id).collect())
}

/// The ways a Windows path is spelled with `\` and `/` that `Path` takes for
/// the same folder and that the node itself makes: as given, all `\`, and
/// each `\` prefix with `/` after it, as a folder joined with `a/b/c` reads
/// (the default state folder is one). Each is one path, so a container
/// found by any of them is this node's.
fn spellings(path: &str) -> Vec<String> {
    let seps: Vec<usize> = path
        .char_indices()
        .filter(|&(_, c)| c == '\\' || c == '/')
        .map(|(i, _)| i)
        .collect();
    let mut all = vec![path.to_string()];
    for k in 0..=seps.len() {
        let mut s = path.to_string();
        // Both separators are one byte, so the offsets hold.
        for (n, &i) in seps.iter().enumerate() {
            let sep = if n < k { "\\" } else { "/" };
            s.replace_range(i..i + 1, sep);
        }
        all.push(s);
    }
    let mut seen = Vec::new();
    all.retain(|s| {
        let new = !seen.contains(s);
        seen.push(s.clone());
        new
    });
    all
}

/// The names the container of the pairing `node_id` may have on the node at
/// `paths`: [`container`], and on Windows those of the other spellings of
/// its state folder ([`spellings`]), for a folder named otherwise than the
/// node named it.
pub fn containers(paths: &NodePaths, node_id: &str) -> Vec<String> {
    let state = paths.state_dir.display().to_string();
    let all = if cfg!(windows) {
        spellings(&state)
    } else {
        vec![state]
    };
    all.iter().map(|s| container_at(s, node_id)).collect()
}

/// The name of the container of the pairing `node_id` whose profile this
/// account has, of [`containers`]; [`container`] when it has none. So the
/// owner tells the profiles of the nodes they keep from leftovers
/// (`center`).
pub fn profile_name(paths: &NodePaths, node_id: &str) -> String {
    #[cfg(windows)]
    {
        profile_in(paths, node_id, &mut WinProfiles)
    }
    #[cfg(not(windows))]
    {
        container(paths, node_id)
    }
}

/// [`profile_name`] with the profiles in `store`.
#[cfg(any(windows, test))]
fn profile_in(paths: &NodePaths, node_id: &str, store: &mut impl ProfileStore) -> String {
    let all = containers(paths, node_id);
    all.iter()
        .find(|n| store.exists(n))
        .unwrap_or(&all[0])
        .clone()
}

/// The profiles of AppContainers this account has: on Windows a folder
/// below `%LOCALAPPDATA%\Packages` and a registry key; in the tests a fake.
pub trait ProfileStore {
    fn exists(&mut self, name: &str) -> bool;
    /// Removes the profile `name`; one that is not there is fine.
    fn remove(&mut self, name: &str) -> io::Result<()>;
}

/// The profiles of the account the containers run as on Windows: this
/// process's, or on the installed service `nerve-run`'s, which the node
/// changes through a helper it starts as that account
/// (crate::win_profile::remove_as).
#[cfg(windows)]
pub struct WinProfiles;

#[cfg(windows)]
impl ProfileStore for WinProfiles {
    // Windows answers the removal of a missing profile as done, so whether
    // one was there is its folder's. The service may not look into
    // `nerve-run`'s profile: there each one counts.
    fn exists(&mut self, name: &str) -> bool {
        crate::win_service::is_service()
            || std::env::var_os("LOCALAPPDATA")
                .is_some_and(|d| Path::new(&d).join("Packages").join(name).is_dir())
    }
    fn remove(&mut self, name: &str) -> io::Result<()> {
        if crate::win_service::is_service() {
            let exe = std::env::current_exe()?;
            return crate::win_profile::remove_as(&exe, name).map_err(io::Error::other);
        }
        nerve_sandbox::appcontainer::remove_profile(name)
    }
}

/// What became of the profiles of a node's containers.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Profiles {
    /// Those removed.
    pub removed: Vec<String>,
    /// Those left because their node may run ([`Profiles::why`]): its
    /// commands use them.
    pub kept: Vec<String>,
    pub why: Option<String>,
    pub errors: Vec<String>,
}

impl Profiles {
    /// Adds what `other` did, each profile once.
    pub fn merge(&mut self, other: Profiles) {
        for (to, from) in [
            (&mut self.removed, other.removed),
            (&mut self.kept, other.kept),
            (&mut self.errors, other.errors),
        ] {
            for n in from {
                if !to.contains(&n) {
                    to.push(n);
                }
            }
        }
        self.why = self.why.take().or(other.why);
    }
}

/// Keeps the node at `paths` from starting while its profiles go: the lock
/// a running node holds for its life ([`crate::secrets::KeysLock`]). Why
/// its profiles must stay instead: it runs, or that cannot be told. A node
/// without a state folder does not run, and none is made to look.
#[cfg(any(windows, test))]
fn hold(paths: &NodePaths) -> Result<Option<crate::secrets::KeysLock>, String> {
    if !paths.state_dir.is_dir() {
        return Ok(None);
    }
    match crate::secrets::KeysLock::try_take(paths) {
        Ok(Some(l)) => Ok(Some(l)),
        Ok(None) => Err(format!("the node at {} runs", paths.state_dir.display())),
        Err(e) => Err(format!("whether the node runs is not known: {e}")),
    }
}

/// Removes the profiles `names` of the node at `paths` from `store`, unless
/// that node runs.
#[cfg(any(windows, test))]
fn drop_profiles(paths: &NodePaths, names: &[String], store: &mut impl ProfileStore) -> Profiles {
    let mut p = Profiles::default();
    // The command account's grants are an account's, with no profile.
    let names: Vec<String> = names.iter().filter(|n| !is_account(n)).cloned().collect();
    let names = names.as_slice();
    // Nothing to remove takes no lock.
    if names.is_empty() {
        return p;
    }
    let there: Vec<String> = names.iter().filter(|n| store.exists(n)).cloned().collect();
    let _held = match hold(paths) {
        Ok(h) => h,
        Err(why) => {
            p.kept = there;
            p.why = (!p.kept.is_empty()).then_some(why);
            return p;
        }
    };
    for n in names {
        // Also where its folder is gone: the registry key may not be.
        match store.remove(n) {
            Ok(()) if there.contains(n) => p.removed.push(n.clone()),
            Ok(()) => {}
            Err(e) => p.errors.push(e.to_string()),
        }
    }
    p
}

/// Removes the profile of the container of the pairing `node_id`, which
/// goes with the pairing: the record of the grants names a container only
/// while it has grants, and is lost with the state folder. Kept while the
/// node runs, since it still serves the pairing until it starts again.
pub fn forget(paths: &NodePaths, node_id: &str) -> Profiles {
    #[cfg(windows)]
    {
        forget_in(paths, node_id, &mut WinProfiles)
    }
    #[cfg(not(windows))]
    {
        let _ = (paths, node_id);
        Profiles::default()
    }
}

/// [`forget`] with the profiles in `store`.
#[cfg(any(windows, test))]
fn forget_in(paths: &NodePaths, node_id: &str, store: &mut impl ProfileStore) -> Profiles {
    drop_profiles(paths, &containers(paths, node_id), store)
}

/// Takes off every grant the node put on, and the profiles of its
/// containers: those in the record and those of the pairings `node_ids`
/// ([`node_ids`]), which are found without the record. The profiles stay
/// while the node runs. For uninstall; `report` as for [`apply`].
pub fn remove_all(paths: &NodePaths, node_ids: &[String], report: &mut dyn FnMut(&str)) -> Synced {
    #[cfg(windows)]
    {
        remove_all_in(
            paths,
            node_ids,
            &mut Acls {
                report,
                owner: None,
            },
            &mut WinProfiles,
        )
    }
    #[cfg(not(windows))]
    {
        let _ = (paths, node_ids, report);
        Synced::default()
    }
}

/// [`remove_all`] on `folders` and the profiles in `store`.
#[cfg(any(windows, test))]
fn remove_all_in(
    paths: &NodePaths,
    node_ids: &[String],
    folders: &mut impl Folders,
    store: &mut impl ProfileStore,
) -> Synced {
    let mut s = sync(&record_file(paths), &[], folders);
    let mut names = s.emptied.clone();
    names.extend(node_ids.iter().flat_map(|n| containers(paths, n)));
    // And those of pairings the node served that the config no longer
    // names.
    match read_profiles(&profiles_file(paths)) {
        Ok(had) => names.extend(had),
        Err(e) => s.errors.push(e),
    }
    names.sort();
    names.dedup();
    let p = drop_profiles(paths, &names, store);
    s.errors.extend(p.errors.iter().cloned());
    s.profiles = p;
    s
}

/// What a change of a grant is doing, as its progress names it.
#[cfg(any(windows, test))]
#[derive(Debug, Clone, Copy)]
enum Doing {
    /// Looking for hard links it would reach ([`held`]).
    Check,
    Put,
    Remove,
}

/// When a change that takes long tells how far it is: first after
/// [`Pace::FIRST`], then every [`Pace::EVERY`].
#[cfg(any(windows, test))]
struct Pace {
    start: Instant,
    /// When it tells next, from `start`.
    next: Duration,
    told: bool,
}

#[cfg(any(windows, test))]
impl Pace {
    const FIRST: Duration = Duration::from_secs(3);
    const EVERY: Duration = Duration::from_secs(15);

    fn new(start: Instant) -> Pace {
        Pace {
            start,
            next: Pace::FIRST,
            told: false,
        }
    }

    /// Whether to tell at `now`, and if so whether it is the first time.
    fn due(&mut self, now: Instant) -> Option<bool> {
        let gone = now.saturating_duration_since(self.start);
        if gone < self.next {
            return None;
        }
        self.next = gone + Pace::EVERY;
        let first = !self.told;
        self.told = true;
        Some(first)
    }
}

/// How far the change of the grant on `path` is.
#[cfg(any(windows, test))]
fn progress_text(doing: Doing, path: &Path, w: Walked, first: bool) -> String {
    let path = path.display();
    let (what, done) = match doing {
        Doing::Check => (format!("checking {path} for hard links"), "to change"),
        Doing::Put => (format!("putting the grant on {path}"), "changed"),
        Doing::Remove => (format!("taking the grant off {path}"), "changed"),
    };
    let so_far = format!(
        "{} files and folders looked at, {} {done} so far",
        w.seen, w.changed
    );
    match (first, doing) {
        (true, Doing::Check) => format!(
            "{what} takes a while: the node looks at each file and folder below it whose permissions the change reaches ({so_far})"
        ),
        (true, _) => format!(
            "{what} takes a while: Windows keeps the permissions of each file and folder, so the node changes each one below it that the change reaches ({so_far})"
        ),
        (false, _) => format!("still {what}: {so_far}"),
    }
}

/// How the change of the grant on `path` ended after `took`: with `w`, or
/// with an error (`None`), which the sync gives.
#[cfg(any(windows, test))]
fn done_text(doing: Doing, path: &Path, w: Option<Walked>, took: Duration) -> String {
    let path = path.display();
    let secs = took.as_secs();
    let (what, did, changed) = match doing {
        Doing::Check => (
            format!("checking {path} for hard links"),
            format!("checked {path} for hard links"),
            "to change",
        ),
        Doing::Put => (
            format!("putting the grant on {path}"),
            format!("put the grant on {path}"),
            "changed",
        ),
        Doing::Remove => (
            format!("taking the grant off {path}"),
            format!("took the grant off {path}"),
            "changed",
        ),
    };
    match w {
        Some(w) => format!(
            "{did} in {secs} s: {} files and folders looked at, {} {changed}",
            w.seen, w.changed
        ),
        None => format!("{what} stopped after {secs} s"),
    }
}

/// Runs `run` with a progress that tells `report` how far it is once it
/// takes long ([`Pace`], by the clock `now`), and how it ended.
#[cfg(any(windows, test))]
fn paced<T>(
    report: &mut dyn FnMut(&str),
    doing: Doing,
    path: &Path,
    now: &dyn Fn() -> Instant,
    run: impl FnOnce(&mut dyn FnMut(Walked)) -> io::Result<(T, Walked)>,
) -> io::Result<T> {
    let start = now();
    let mut pace = Pace::new(start);
    let r = run(&mut |w| {
        if let Some(first) = pace.due(now()) {
            report(&progress_text(doing, path, w, first));
        }
    });
    if pace.told {
        let w = r.as_ref().ok().map(|(_, w)| *w);
        report(&done_text(
            doing,
            path,
            w,
            now().saturating_duration_since(start),
        ));
    }
    r.map(|(t, _)| t)
}

/// The rights of a grant with `access`: a grant without a flag closes its
/// folder, inside a granted one ([`wanted`]).
#[cfg(windows)]
fn masks_of(access: Access) -> nerve_sandbox::acl::Masks {
    use nerve_sandbox::acl;
    if access == Access::NONE {
        acl::closed()
    } else {
        acl::masks(access.read, access.write, access.execute)
    }
}

/// The folders' access lists on Windows; `report` is told how far a change
/// is once it takes long ([`paced`]). On the installed service the folders
/// are the owner's, which the service's own account may neither read nor
/// change: each look and change acts as the `owner`
/// (crate::win_user::FsAs), as Linux's ACL sync does. Only the folders'
/// work does: the record stays in the node's state folder, which the owner
/// may not open.
#[cfg(windows)]
struct Acls<'a> {
    report: &'a mut dyn FnMut(&str),
    owner: Option<&'a crate::service::Account>,
}

#[cfg(windows)]
impl Acls<'_> {
    /// Acts as the owner on this thread while the result lives. It logs
    /// the owner on with the password the install stored: where that fails,
    /// no folder's entry changes, and the error says where it is saved.
    fn act(&self) -> io::Result<Option<crate::win_user::FsAs>> {
        self.owner
            .map(|o| {
                crate::win_user::FsAs::new(o).map_err(|e| {
                    io::Error::other(format!(
                        "the node changes the permissions of your folders as {}, and cannot log on as {0} ({e}); save your Windows password again under Settings, General, Account for commands",
                        o.name
                    ))
                })
            })
            .transpose()
    }
}

/// Refuses `path` where its links lead to another machine
/// (nerve_policy::paths::remote_link): opening it would connect there as
/// whoever the sync acts as, and send that account's NTLM answer (#149's
/// probe). Refused before anything changed.
#[cfg(windows)]
fn not_remote(path: &Path) -> io::Result<()> {
    match nerve_policy::paths::remote_link(path) {
        None => Ok(()),
        Some(link) => Err(nerve_sandbox::acl::untouched(
            Untouched::Refused,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} is a link to another machine, which the node does not follow",
                    link.display()
                ),
            ),
        )),
    }
}

#[cfg(windows)]
impl Folders for Acls<'_> {
    fn look(&mut self, path: &Path, container: &str, access: Access) -> io::Result<Option<Look>> {
        use nerve_sandbox::appcontainer;
        // Nothing the node may look at: a recorded grant is looked for by
        // its object then (`locate`).
        if not_remote(path).is_err() {
            return Ok(None);
        }
        let _as = self.act()?;
        let masks = masks_of(access);
        match appcontainer::look(path, container, masks) {
            Ok((id, granted)) => Ok(Some(Look {
                id: id.map(|i| i.to_string()),
                granted,
            })),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn locate(&mut self, id: &str, near: &Path) -> io::Result<Found> {
        // The folders on the way are opened to find the volume: not
        // through a link to another machine.
        let near = if not_remote(near).is_ok() {
            near
        } else {
            Path::new("")
        };
        let _as = self.act()?;
        let id = id.parse().map_err(io::Error::other)?;
        nerve_sandbox::appcontainer::locate(&id, near)
    }

    fn set(
        &mut self,
        path: &Path,
        container: &str,
        access: Option<Access>,
        own: bool,
        links: Links,
        whole: bool,
        expect: Option<&str>,
    ) -> io::Result<Option<String>> {
        use nerve_sandbox::{acl, appcontainer};
        not_remote(path)?;
        // What commands made belongs to the command account, whose list
        // the owner may not change outside their profile: the change is
        // made as that account there (`Below::maker`). Logged on before
        // the thread acts as the owner.
        let maker = self.owner.and_then(|_| crate::win_user::run_logon().ok());
        let _as = self.act()?;
        let masks = access.map(masks_of);
        let expect = expect
            .map(|e| e.parse::<acl::FileId>().map_err(io::Error::other))
            .transpose()?;
        let judge = match links {
            Links::Passing(grants) => Some(Judge::new(path, grants)),
            Links::Any => None,
        };
        // Each file with more than one name is judged again as the change
        // gets to it, by the names it has then, so a link a command made
        // after the check stops it.
        let mut check = judge
            .as_ref()
            .map(|j| move |p: &Path, n: u32, all: &[PathBuf]| Ok(j.holds(p, n.into(), all)));
        let doing = if access.is_some() {
            Doing::Put
        } else {
            Doing::Remove
        };
        // The object changed, as its handle names it: the path may lead
        // elsewhere by now.
        let id = paced(self.report, doing, path, &Instant::now, |progress| {
            let below = appcontainer::Below {
                links: check.as_mut().map(|c| c as nerve_sandbox::inherit::Links),
                progress,
                maker: maker.as_ref().map(|t| t.raw()),
            };
            appcontainer::set_below(path, container, masks, own, whole, expect, below)
        })?;
        Ok(id.map(|i| i.to_string()))
    }

    fn linked(
        &mut self,
        dir: &Path,
        container: &str,
        access: Option<Access>,
        whole: bool,
        grants: Option<&[PathBuf]>,
    ) -> io::Result<Option<(PathBuf, u64)>> {
        use nerve_sandbox::appcontainer;
        not_remote(dir)?;
        let _as = self.act()?;
        let masks = access.map(masks_of);
        let judge = Judge::new(dir, grants);
        let mut links = |p: &Path, n: u32, all: &[PathBuf]| Ok(judge.holds(p, n.into(), all));
        let found = paced(self.report, Doing::Check, dir, &Instant::now, |progress| {
            let below = appcontainer::Below {
                links: Some(&mut links),
                progress,
                maker: None,
            };
            appcontainer::reaches(dir, container, masks, whole, below)
        })?;
        Ok(found.map(|(p, n)| (p, n.into())))
    }
}

/// [`apply`] for the grants `want`, as the tests on Windows give them.
#[cfg(all(windows, test))]
fn windows_sync(paths: &NodePaths, want: &[Grant], report: &mut dyn FnMut(&str)) -> Synced {
    apply_in(
        paths,
        || (want.to_vec(), Vec::new()),
        &mut Acls {
            report,
            owner: None,
        },
        &mut WinProfiles,
    )
}

/// The containers of the pairings in `cfg`, whose profiles stay while
/// their pairings do ([`apply_in`]).
pub fn pairings(paths: &NodePaths, cfg: &NodeConfig) -> Vec<String> {
    cfg.centers
        .iter()
        .map(|c| container(paths, &c.node_id))
        .collect()
}

/// The containers whose profiles the node may have made (`profiles.json`
/// in its state folder): those of its pairings at its last sync, and those
/// whose removal failed. A container's profile holds its pairing's home on
/// the installed service (crate::account::Own), so it goes with the
/// pairing, not with its last grant: also one that never had a grant.
#[cfg(any(windows, test))]
fn profiles_file(paths: &NodePaths) -> PathBuf {
    paths.state_dir.join("profiles.json")
}

#[cfg(any(windows, test))]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfilesFile<C> {
    #[serde(default)]
    format: Format,
    #[serde(default)]
    containers: C,
}

#[cfg(any(windows, test))]
fn read_profiles(file: &Path) -> Result<Vec<String>, String> {
    match std::fs::read(file) {
        Ok(b) => Format::of_json(&b)
            .check()
            .and_then(|()| {
                serde_json::from_slice::<ProfilesFile<Vec<String>>>(&b).map_err(|e| e.to_string())
            })
            .map(|r| r.containers)
            .map_err(|e| format!("{}: {e}", file.display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("{}: {e}", file.display())),
    }
}

#[cfg(any(windows, test))]
fn write_profiles(file: &Path, containers: &[String]) -> Result<(), String> {
    let json = serde_json::to_vec_pretty(&ProfilesFile {
        format: Format::CURRENT,
        containers,
    })
    .expect("containers serialise");
    nerve_transport::files::write_private(file, &json)
        .map_err(|e| format!("cannot write {}: {e}", file.display()))
}

/// [`apply`] for the grants `want` gives, on `folders` and the profiles in
/// `store`. `want` gives the grants and the containers of the config's
/// pairings ([`pairings`]), and is asked once this sync's turn has come: the node starts a
/// sync for each change, and one that waited for a sync of a newer config
/// would otherwise put back a grant the owner took away since. The profile
/// of each container the sync left without grants goes in the same turn as
/// the grants, so a sync that waited for this one returns only once it is
/// gone. `center rm` asks the node for one (`folder.grants`) while the
/// node's own sync of the change may hold the turn, and then looks at the
/// profiles itself: one still on its way out would be said to stay.
#[cfg(any(windows, test))]
fn apply_in(
    paths: &NodePaths,
    want: impl FnOnce() -> (Vec<Grant>, Vec<String>),
    folders: &mut impl Folders,
    store: &mut impl ProfileStore,
) -> Synced {
    let _one = nerve_transport::sync::turn(&SYNC);
    let (want, live) = want();
    let mut s = sync_in_turn(&record_file(paths), &want, folders);
    // A profile goes with its pairing: those of containers the sync left
    // without grants and of pairings the node had, unless the pairing is
    // still there.
    let file = profiles_file(paths);
    let had = read_profiles(&file).unwrap_or_else(|e| {
        s.errors.push(e);
        Vec::new()
    });
    let mut gone: Vec<String> = s.emptied.iter().chain(&had).cloned().collect();
    gone.sort();
    gone.dedup();
    let mut now = live.clone();
    for c in gone.iter().filter(|c| !is_account(c) && !live.contains(c)) {
        if let Err(e) = store.remove(c) {
            s.errors.push(e.to_string());
            now.push(c.clone());
        }
    }
    now.sort();
    now.dedup();
    let mut was = had;
    was.sort();
    if now != was
        && let Err(e) = write_profiles(&file, &now)
    {
        s.errors.push(e);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use nerve_sandbox::acl::untouched;

    fn grant(container: &str, path: &str, access: &str) -> Grant {
        Grant {
            container: container.into(),
            path: path.into(),
            access: Access::parse(access).unwrap(),
            id: None,
            unfinished: false,
            toward: Vec::new(),
            closed_at: None,
        }
    }

    /// `grants.json` is written as an object with `format: 1` and the
    /// grants; a file without the format is at format 1; one of a newer
    /// version is refused for its format, also when it has fields this
    /// version does not know.
    #[test]
    fn the_record_has_a_format_and_a_newer_one_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let g = grant("c1", "/w/a", "rw");
        write_record(&file, std::slice::from_ref(&g)).unwrap();
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(
            text.starts_with("{\n  \"format\": 1,\n  \"grants\": ["),
            "{text}"
        );
        assert_eq!(read_record(&file).unwrap(), [g]);
        std::fs::write(&file, r#"{"grants": []}"#).unwrap();
        assert!(read_record(&file).unwrap().is_empty());
        for newer in [
            r#"{"format": 2}"#,
            r#"{"format": 2, "grants": [], "later": 1}"#,
        ] {
            std::fs::write(&file, newer).unwrap();
            let e = read_record(&file).unwrap_err();
            assert!(e.contains("format 2") && e.contains("newer version"), "{e}");
        }
    }

    /// A grant as the record holds it, without the object's id and the
    /// marks of a change that stopped (tested on their own).
    fn plain(g: &Grant) -> Grant {
        Grant {
            id: None,
            unfinished: false,
            toward: Vec::new(),
            ..g.clone()
        }
    }

    fn recorded(file: &Path) -> Vec<Grant> {
        read_record(file).unwrap().iter().map(plain).collect()
    }

    /// A fake volume: objects with ids at paths, as on NTFS, and the grants
    /// on each object, which go with it when it moves.
    #[derive(Default)]
    struct Fake {
        at: Vec<(PathBuf, String)>,
        /// (object, container, access)
        on: Vec<(String, String, Access)>,
        /// Paths whose access list cannot be changed.
        locked: Vec<PathBuf>,
        /// Paths where nothing can be looked at.
        unseen: Vec<PathBuf>,
        /// Objects that cannot be looked for.
        lost: Vec<String>,
        /// Paths whose object is not one of its own there: a junction to
        /// elsewhere, a file with other names.
        foreign: Vec<PathBuf>,
        /// Files with a second name (hard links).
        linked: Vec<PathBuf>,
        /// Walk the real files below this folder instead (`linked_below`).
        #[cfg(unix)]
        walk: Option<PathBuf>,
        /// The `own` of each grant put on, by path.
        asked: Vec<(PathBuf, bool)>,
        /// The volume is not on the machine.
        away: bool,
        /// How many changes were made or tried.
        sets: usize,
        /// The record, when a sync must have written it before a change.
        record: Option<PathBuf>,
        /// Whether each change must find its place marked unfinished in
        /// `record` first.
        marked: bool,
        /// Paths where a change stops part way: it fails after changing
        /// what is below the folder, and the folder keeps its list.
        cut: Vec<PathBuf>,
        /// Paths where the process ends during a change (a panic, as the
        /// CLI stopped by Ctrl-C or a node killed): only what the sync
        /// wrote before stays.
        die: Vec<PathBuf>,
        /// Paths whose folder is replaced by a new one right after it is
        /// looked at (once).
        replace_after_look: Vec<PathBuf>,
        /// Paths whose folder is moved to `<path>.old` right after it is
        /// looked at or found (once), with a new one made in its place
        /// where the flag says so.
        move_after_look: Vec<(PathBuf, bool)>,
        /// Each change made or tried: its path, whether it checks for hard
        /// links ([`Links::Passing`]), and whether it goes into every
        /// folder below (`whole`).
        changes: Vec<(PathBuf, bool, bool)>,
        next: usize,
    }

    impl Fake {
        fn make(&mut self, path: &str) -> String {
            self.next += 1;
            let id = format!("id{}", self.next);
            self.at.push((path.into(), id.clone()));
            id
        }
        fn mv(&mut self, from: &str, to: &str) {
            for (p, _) in &mut self.at {
                if p == Path::new(from) {
                    *p = to.into();
                }
            }
        }
        /// The move of `move_after_look` at `path`, if one is due.
        fn move_after(&mut self, path: &Path) {
            if let Some(i) = self.move_after_look.iter().position(|(m, _)| m == path) {
                let (_, remake) = self.move_after_look.remove(i);
                let p = path.display().to_string();
                self.mv(&p, &format!("{p}.old"));
                if remake {
                    self.make(&p);
                }
            }
        }
        fn rm(&mut self, path: &str) {
            let id = self.id(Path::new(path)).unwrap();
            self.at.retain(|(_, i)| *i != id);
            self.on.retain(|(i, _, _)| *i != id);
        }
        fn id(&self, path: &Path) -> Option<String> {
            self.at
                .iter()
                .find(|(p, _)| p == path)
                .map(|(_, i)| i.clone())
        }
        /// The grants on what is at `path`.
        fn on(&self, path: &str) -> Vec<(String, Access)> {
            let id = self.id(Path::new(path));
            self.on
                .iter()
                .filter(|(i, _, _)| Some(i) == id.as_ref())
                .map(|(_, c, a)| (c.clone(), *a))
                .collect()
        }
        /// Every grant on the volume, by the path of its object.
        fn all(&self) -> Vec<Grant> {
            let mut all: Vec<Grant> = self
                .on
                .iter()
                .map(|(i, c, a)| Grant {
                    container: c.clone(),
                    path: self.at.iter().find(|(_, j)| j == i).unwrap().0.clone(),
                    access: *a,
                    id: None,
                    unfinished: false,
                    toward: Vec::new(),
                    closed_at: None,
                })
                .collect();
            all.sort_by(|a, b| a.path.cmp(&b.path));
            all
        }
    }

    impl Folders for Fake {
        fn look(
            &mut self,
            path: &Path,
            container: &str,
            access: Access,
        ) -> io::Result<Option<Look>> {
            if self.unseen.iter().any(|m| m == path) {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            let look = self.id(path).map(|id| {
                let granted = self
                    .on
                    .iter()
                    .filter(|(i, c, _)| *i == id && c == container)
                    .map(|(_, _, a)| *a)
                    .eq([access]);
                Look {
                    id: Some(id),
                    granted,
                }
            });
            self.move_after(path);
            if let Some(i) = self.replace_after_look.iter().position(|m| m == path) {
                self.replace_after_look.remove(i);
                let p = path.display().to_string();
                self.rm(&p);
                self.make(&p);
            }
            Ok(look)
        }
        fn locate(&mut self, id: &str, _near: &Path) -> io::Result<Found> {
            if self.away {
                return Ok(Found::Away);
            }
            if self.lost.iter().any(|i| i == id) {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            let found = self
                .at
                .iter()
                .find(|(_, i)| i == id)
                .map_or(Found::Gone, |(p, _)| Found::At(p.clone()));
            if let Found::At(p) = &found {
                self.move_after(p);
            }
            Ok(found)
        }
        fn set(
            &mut self,
            path: &Path,
            container: &str,
            access: Option<Access>,
            own: bool,
            links: Links,
            whole: bool,
            expect: Option<&str>,
        ) -> io::Result<Option<String>> {
            self.sets += 1;
            // As `set_below`: nothing at the path is gone, but where an
            // object was recorded, it is not there, which is refused; so is
            // another object.
            match (expect, self.id(path)) {
                (None, None) => {
                    return Err(untouched(Untouched::Gone, io::ErrorKind::NotFound.into()));
                }
                (Some(e), now) if now.as_deref() != Some(e) => {
                    let e = io::Error::new(io::ErrorKind::InvalidInput, "another folder");
                    return Err(untouched(Untouched::Refused, e));
                }
                _ => {}
            }
            let checked = matches!(links, Links::Passing(_));
            self.changes.push((path.into(), checked, whole));
            if self.marked {
                let file = self.record.as_ref().expect("a record to look at");
                assert!(
                    read_record(file)
                        .unwrap()
                        .iter()
                        .any(|g| g.path == path && g.container == container && g.unfinished),
                    "{} is changed before it is marked",
                    path.display()
                );
            }
            if access.is_some() {
                self.asked.push((path.into(), own));
                if own && self.foreign.iter().any(|m| m == path) {
                    let e = io::Error::new(io::ErrorKind::InvalidInput, "not an object of its own");
                    return Err(untouched(Untouched::Refused, e));
                }
            }
            if let (Some(file), Some(_)) = (&self.record, access) {
                assert!(
                    recorded(file).iter().any(|g| g.path == path),
                    "{} is put on before it is recorded",
                    path.display()
                );
            }
            let id = self
                .id(path)
                .ok_or_else(|| untouched(Untouched::Gone, io::ErrorKind::NotFound.into()))?;
            if self.locked.iter().any(|m| m == path) {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            // Of a kind a refusal has, as an error from deep in a walk may
            // be: it says nothing about whether the change was made.
            if self.die.iter().any(|m| m == path) {
                panic!("the node stops during the change of {}", path.display());
            }
            if self.cut.iter().any(|m| m == path) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "it stopped part way",
                ));
            }
            self.on.retain(|(i, c, _)| !(*i == id && c == container));
            if let Some(a) = access {
                self.on.push((id.clone(), container.into(), a));
            }
            Ok(Some(id))
        }
        fn linked(
            &mut self,
            dir: &Path,
            _: &str,
            _: Option<Access>,
            _: bool,
            grants: Option<&[PathBuf]>,
        ) -> io::Result<Option<(PathBuf, u64)>> {
            #[cfg(unix)]
            if let Some(root) = &self.walk {
                use std::os::unix::fs::MetadataExt;
                let count = |p: &Path| std::fs::symlink_metadata(p).map(|m| m.nlink());
                let names = |p: &Path| names_below(root, p);
                return linked_below(dir, grants, &count, &names);
            }
            let _ = grants;
            Ok(self
                .linked
                .iter()
                .find(|f| within(f, dir) && !within(dir, f))
                .map(|f| (f.clone(), 2)))
        }
    }

    /// Folders added get their grant, one removed loses it, a changed flag
    /// replaces it, and a sync with nothing to do changes nothing.
    #[test]
    fn grants_follow_the_folders() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/a");
        f.make("/w/b");
        let (a, b) = (grant("c1", "/w/a", "rwx"), grant("c1", "/w/b", "r"));
        let s = sync(&file, &[a.clone(), b.clone()], &mut f);
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        assert_eq!(f.all(), [a.clone(), b.clone()]);
        assert_eq!(recorded(&file), [a.clone(), b.clone()]);

        f.sets = 0;
        sync(&file, &[a.clone(), b.clone()], &mut f);
        assert_eq!(f.sets, 0, "nothing to change");

        let b2 = grant("c1", "/w/b", "rw");
        let s = sync(&file, std::slice::from_ref(&b2), &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        assert_eq!(f.all(), std::slice::from_ref(&b2));
        assert_eq!(recorded(&file), [b2]);
        assert!(s.emptied.is_empty());

        let s = sync(&file, &[], &mut f);
        assert!(f.all().is_empty());
        assert!(recorded(&file).is_empty());
        assert_eq!(s.emptied, ["c1"]);
    }

    /// A grant that cannot be taken off stays recorded and is reported as
    /// stale, so its container's commands do not run; the next sync tries
    /// again. A folder that is gone loses its record.
    #[test]
    fn a_grant_that_stays_on_is_kept_and_reported() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/a");
        f.make("/w/b");
        let (a, b) = (grant("c1", "/w/a", "rwx"), grant("c2", "/w/b", "r"));
        sync(&file, &[a.clone(), b.clone()], &mut f);
        f.locked.push("/w/a".into());
        f.rm("/w/b");
        let s = sync(&file, &[], &mut f);
        assert_eq!(
            s.stale.iter().map(plain).collect::<Vec<_>>(),
            std::slice::from_ref(&a)
        );
        assert_eq!(s.errors.len(), 1, "{s:?}");
        assert_eq!(s.emptied, ["c2"]);
        assert_eq!(recorded(&file), std::slice::from_ref(&a));
        assert!(s.refusal(&a.container).is_some());
        assert!(s.refusal("c2").is_none());
        f.locked.clear();
        let s = sync(&file, &[], &mut f);
        assert!(s.stale.is_empty() && s.errors.is_empty(), "{s:?}");
        assert!(recorded(&file).is_empty());
        // A wanted folder that is not there yet gets no grant and no record.
        let c = grant("c1", "/w/b", "r");
        let s = sync(&file, &[c], &mut f);
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        assert!(recorded(&file).is_empty());
    }

    /// A changed flag that cannot be put on leaves the old grant recorded,
    /// since it is still on, and reports it as stale.
    #[test]
    fn a_failed_change_keeps_the_old_grant_recorded() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/a");
        let a = grant("c1", "/w/a", "rwx");
        sync(&file, std::slice::from_ref(&a), &mut f);
        f.locked.push("/w/a".into());
        let s = sync(&file, &[grant("c1", "/w/a", "r")], &mut f);
        assert_eq!(
            s.stale.iter().map(plain).collect::<Vec<_>>(),
            std::slice::from_ref(&a)
        );
        assert_eq!(recorded(&file), [a]);
    }

    /// A granted folder that was moved or renamed takes its grant along:
    /// the sync takes it off where the folder is now, also when a new
    /// folder took the old place. One that cannot be taken off there is
    /// stale; one on a volume that is away stays recorded until it is back.
    #[test]
    fn a_moved_folder_loses_its_grant_where_it_is_now() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/a");
        f.make("/w/b");
        let (a, b) = (grant("c1", "/w/a", "rwx"), grant("c1", "/w/b", "r"));
        sync(&file, &[a.clone(), b.clone()], &mut f);

        f.mv("/w/a", "/archive/a");
        let s = sync(&file, std::slice::from_ref(&b), &mut f);
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        assert_eq!(s.removed, 1);
        assert!(f.on("/archive/a").is_empty(), "{:?}", f.all());
        assert_eq!(recorded(&file), std::slice::from_ref(&b));

        // Moved away and made again: the grant leaves the old folder and
        // goes on the new one.
        f.mv("/w/b", "/archive/b");
        f.make("/w/b");
        let s = sync(&file, std::slice::from_ref(&b), &mut f);
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        assert!(f.on("/archive/b").is_empty(), "{:?}", f.all());
        assert_eq!(f.all(), std::slice::from_ref(&b));
        assert_eq!(read_record(&file).unwrap()[0].id, f.id(Path::new("/w/b")));

        // Where it cannot be taken off, the grant stays recorded and stops
        // the container's commands.
        f.mv("/w/b", "/archive/b2");
        f.locked.push("/archive/b2".into());
        let s = sync(&file, &[], &mut f);
        assert_eq!(
            s.stale.iter().map(plain).collect::<Vec<_>>(),
            std::slice::from_ref(&b)
        );
        assert!(s.refusal("c1").is_some());
        assert_eq!(recorded(&file), std::slice::from_ref(&b));

        // A volume that is away: nothing reaches the grant, so it neither
        // stops the commands nor leaves the record, and it is named.
        f.away = true;
        let s = sync(&file, &[], &mut f);
        assert!(s.stale.is_empty() && s.errors.is_empty(), "{s:?}");
        assert_eq!(
            s.away.iter().map(plain).collect::<Vec<_>>(),
            std::slice::from_ref(&b)
        );
        assert_eq!(recorded(&file), std::slice::from_ref(&b));
        f.away = false;
        f.locked.clear();
        let s = sync(&file, &[], &mut f);
        assert!(s.stale.is_empty() && s.errors.is_empty(), "{s:?}");
        assert!(f.all().is_empty() && recorded(&file).is_empty());
    }

    /// A granted folder or file that was deleted and made again, or whose
    /// grant went otherwise, gets it again at the next sync.
    #[test]
    fn a_folder_made_again_gets_its_grant_again() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/a");
        f.make("/home/notes.txt");
        let want = [
            grant("c1", "/w/a", "rwx"),
            grant("c1", "/home/notes.txt", "rw"),
        ];
        sync(&file, &want, &mut f);
        f.rm("/w/a");
        f.make("/w/a");
        // Saved by an editor through a new file renamed over the old one.
        f.rm("/home/notes.txt");
        f.make("/home/notes.txt");
        let s = sync(&file, &want, &mut f);
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        let mut on = want.to_vec();
        on.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(f.all(), on);
        // Its own list changed: the grant goes on again too.
        f.on.clear();
        sync(&file, &want, &mut f);
        assert_eq!(f.all(), on);
    }

    /// Inside a folder that commands may write, a command can put a
    /// junction or a linked file in place of a granted folder: a grant goes
    /// on there only on an object of its own, and one refused leaves what
    /// was on as it was. Elsewhere, what the owner granted is taken as it is.
    #[test]
    fn inside_a_writable_folder_a_grant_goes_on_an_object_of_its_own() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        for p in ["/w", "/w/p", "/w/z", "/x", "/r", "/r/q"] {
            f.make(p);
        }
        f.foreign = ["/w/p", "/x", "/r/q"].map(PathBuf::from).to_vec();
        let p = grant("c1", "/w/p", "r");
        let want = [
            grant("c1", "/w", "rw"),
            p.clone(),
            // Inside another container's writable folder too.
            grant("c2", "/w/z", "r"),
            // The owner's own junction, where no command writes.
            grant("c1", "/x", "r"),
            grant("c2", "/r", "r"),
            grant("c2", "/r/q", "rw"),
        ];
        let s = sync(&file, &want, &mut f);
        assert_eq!(s.errors.len(), 1, "{s:?}");
        assert!(s.errors[0].contains("/w/p"), "{s:?}");
        assert!(s.stale.is_empty() && s.refusal("c1").is_none(), "{s:?}");
        let mut asked = f.asked.clone();
        asked.sort();
        assert_eq!(
            asked,
            [
                ("/r".into(), false),
                ("/r/q".into(), false),
                ("/w".into(), false),
                ("/w/p".into(), true),
                ("/w/z".into(), true),
                ("/x".into(), false),
            ]
        );
        assert!(f.on("/w/p").is_empty(), "{:?}", f.all());
        assert!(!recorded(&file).contains(&p));
        // Once a folder of its own is there, it gets its grant.
        f.foreign.clear();
        let s = sync(&file, &want, &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        assert_eq!(f.on("/w/p"), [("c1".to_string(), p.access)]);
        // A refused change keeps the grant that is on, as stale.
        f.foreign.push("/w/p".into());
        let mut changed = want.to_vec();
        changed[1] = grant("c1", "/w/p", "rw");
        let s = sync(&file, &changed, &mut f);
        assert_eq!(s.errors.len(), 1, "{s:?}");
        assert_eq!(
            s.stale.iter().map(plain).collect::<Vec<_>>(),
            std::slice::from_ref(&p)
        );
        assert!(s.refusal("c1").is_some());
        assert!(recorded(&file).contains(&p));
        assert_eq!(f.on("/w/p"), [("c1".to_string(), p.access)]);
    }

    /// A change whose list Windows would pass down into a folder commands
    /// may write in is refused while a file below it has a second name (a
    /// hard link): a grant put on, one taken off, and one taken off where a
    /// moved folder is now. The refusal names the folder and the file; a
    /// refused removal stays recorded and stops the container's commands. A
    /// folder no command writes in is changed as before.
    #[test]
    fn a_hard_link_below_a_writable_folder_stops_the_change() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        for p in ["/w", "/w/b", "/w/c", "/r", "/r/q"] {
            f.make(p);
        }
        let (w, b) = (grant("c1", "/w", "rw"), grant("c1", "/w/b", "rwx"));
        let s = sync(&file, &[w.clone(), b.clone()], &mut f);
        assert!(s.errors.is_empty(), "{s:?}");

        // A grant put on: refused, nothing on, not recorded.
        f.linked.push("/w/c/s".into());
        let c = grant("c1", "/w/c", "r");
        let s = sync(&file, &[w.clone(), b.clone(), c.clone()], &mut f);
        assert_eq!(s.errors.len(), 1, "{s:?}");
        assert!(
            s.errors[0].contains("/w/c/s") && s.errors[0].contains("hard links"),
            "{s:?}"
        );
        assert!(s.errors[0].contains("permissions of /w/c"), "{s:?}");
        assert!(f.on("/w/c").is_empty(), "{:?}", f.all());
        assert!(!recorded(&file).contains(&c));
        assert!(s.stale.is_empty(), "{s:?}");

        // A folder moved inside the writable one, with a link in it: its
        // grant is not taken off where it is now, and stops the commands.
        f.linked = vec!["/w/b2/s".into()];
        f.mv("/w/b", "/w/b2");
        let s = sync(&file, std::slice::from_ref(&w), &mut f);
        assert_eq!(s.errors.len(), 1, "{s:?}");
        assert!(s.errors[0].contains("/w/b2/s"), "{s:?}");
        assert_eq!(
            s.stale.iter().map(plain).collect::<Vec<_>>(),
            std::slice::from_ref(&b)
        );
        assert!(s.refusal("c1").is_some());
        assert_eq!(f.on("/w/b2"), [("c1".to_string(), b.access)]);

        // Taken off at its path: refused as well while the link is there.
        f.linked = vec!["/w/s".into()];
        f.mv("/w/b2", "/elsewhere/b2");
        let s = sync(&file, &[], &mut f);
        assert!(
            s.errors
                .iter()
                .any(|e| e.contains("/w/s") && e.contains("take the grant off /w")),
            "{s:?}"
        );
        assert!(s.stale.iter().any(|g| g.path == Path::new("/w")), "{s:?}");
        assert_eq!(f.on("/w"), [("c1".to_string(), w.access)]);

        // Without the link, all goes as before.
        f.linked.clear();
        let s = sync(&file, &[], &mut f);
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        assert!(f.all().is_empty(), "{:?}", f.all());

        // Where no command writes, a link below changes nothing.
        f.linked = vec!["/r/q/s".into()];
        let r = grant("c2", "/r", "r");
        let s = sync(&file, std::slice::from_ref(&r), &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        assert_eq!(f.on("/r"), [("c2".to_string(), r.access)]);
    }

    /// A folder that holds a writable one passes a change down through it,
    /// so it is checked too: put on, changed, taken off, by another
    /// container, and taken off where it is after a move (also when the
    /// writable folder below it is recorded under the old path).
    #[test]
    fn a_folder_that_holds_a_writable_one_is_checked() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        for p in ["/d", "/d/in", "/out"] {
            f.make(p);
        }
        let (inbox, out) = (grant("c1", "/d/in", "rw"), grant("c1", "/out", "w"));
        let base = [inbox.clone(), out.clone()];
        let s = sync(&file, &base, &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        f.linked.push("/d/in/x".into());
        let refused = |s: &Synced| {
            s.errors.len() == 1 && s.errors[0].contains("/d/in/x") && s.errors[0].contains("/d")
        };

        // Put on, for this container and another one.
        for dr in [grant("c1", "/d", "r"), grant("c2", "/d", "r")] {
            let s = sync(&file, &[base.to_vec(), vec![dr.clone()]].concat(), &mut f);
            assert!(refused(&s), "{s:?}");
            assert!(f.on("/d").is_empty(), "{:?}", f.all());
        }

        // Changed and taken off: what is on stays.
        f.linked.clear();
        let dr = grant("c1", "/d", "r");
        let s = sync(&file, &[base.to_vec(), vec![dr.clone()]].concat(), &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        f.linked.push("/d/in/x".into());
        let s = sync(
            &file,
            &[base.to_vec(), vec![grant("c1", "/d", "rx")]].concat(),
            &mut f,
        );
        assert!(refused(&s), "{s:?}");
        assert_eq!(f.on("/d"), [("c1".to_string(), dr.access)]);
        let s = sync(&file, &base, &mut f);
        assert!(refused(&s), "{s:?}");
        assert!(s.stale.iter().any(|g| g.path == Path::new("/d")), "{s:?}");
        assert_eq!(f.on("/d"), [("c1".to_string(), dr.access)]);

        // Moved with the writable folder in it: neither comes off there.
        f.mv("/d", "/d2");
        f.mv("/d/in", "/d2/in");
        f.linked = vec!["/d2/in/x".into()];
        let s = sync(&file, std::slice::from_ref(&out), &mut f);
        assert!(s.errors.iter().all(|e| e.contains("/d2/in/x")), "{s:?}");
        assert_eq!(s.errors.len(), 2, "{s:?}");
        assert_eq!(f.on("/d2"), [("c1".to_string(), dr.access)]);
        assert_eq!(f.on("/d2/in"), [("c1".to_string(), inbox.access)]);
        assert!(s.refusal("c1").is_some());

        // Without the link, all comes off.
        f.linked.clear();
        let s = sync(&file, std::slice::from_ref(&out), &mut f);
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        assert!(f.on("/d2").is_empty() && f.on("/d2/in").is_empty());
    }

    /// The names of a file on Linux, for the walk: every path below `root`
    /// that is the same file (Linux has no call that lists them).
    #[cfg(unix)]
    fn names_below(root: &Path, p: &Path) -> io::Result<Vec<PathBuf>> {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::symlink_metadata(p)?;
        let mut out = Vec::new();
        let mut todo = vec![root.to_path_buf()];
        while let Some(d) = todo.pop() {
            for e in std::fs::read_dir(&d)? {
                let path = e?.path();
                let n = std::fs::symlink_metadata(&path)?;
                if n.is_dir() {
                    todo.push(path);
                } else if (n.dev(), n.ino()) == (m.dev(), m.ino()) {
                    out.push(path);
                }
            }
        }
        Ok(out)
    }

    /// The walk finds a file with a second name below a folder, also deep
    /// down, and does not follow a link out of the folder.
    #[cfg(unix)]
    #[test]
    fn the_walk_finds_a_file_with_a_second_name() {
        use std::os::unix::fs::MetadataExt;
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (dir, outside) = (root.join("dir"), root.join("outside"));
        std::fs::create_dir_all(dir.join("a/b")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(dir.join("a/b/one.txt"), "x").unwrap();
        std::fs::write(outside.join("secret.txt"), "x").unwrap();
        std::fs::hard_link(outside.join("secret.txt"), outside.join("again.txt")).unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("a/link")).unwrap();
        let count = |p: &Path| std::fs::symlink_metadata(p).map(|m| m.nlink());
        let names = |p: &Path| names_below(&root, p);
        let walk =
            |d: &Path| linked_below(d, Some(std::slice::from_ref(&dir)), &count, &names).unwrap();
        assert_eq!(walk(&dir), None);
        assert_eq!(walk(&dir.join("a/b/one.txt")), None);
        std::fs::hard_link(outside.join("secret.txt"), dir.join("a/b/s")).unwrap();
        assert_eq!(walk(&dir), Some((dir.join("a/b/s"), 3)));
        std::fs::remove_file(dir.join("a/b/s")).unwrap();
        assert_eq!(walk(&dir), None);
    }

    /// A project with real hard links: `proj` granted, `drop` outside it.
    #[cfg(unix)]
    struct Project {
        _d: tempfile::TempDir,
        root: PathBuf,
        proj: PathBuf,
    }

    #[cfg(unix)]
    impl Project {
        fn new() -> Project {
            let d = tempfile::tempdir().unwrap();
            let root = std::fs::canonicalize(d.path()).unwrap();
            let proj = root.join("proj");
            std::fs::create_dir_all(&proj).unwrap();
            Project { _d: d, root, proj }
        }
        /// Makes the file `from` (below the root) and links it as `to`.
        fn link(&self, from: &str, to: &str) -> PathBuf {
            let (from, to) = (self.root.join(from), self.root.join(to));
            for p in [&from, &to] {
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            }
            if !from.exists() {
                std::fs::write(&from, "x").unwrap();
            }
            std::fs::hard_link(&from, &to).unwrap();
            to
        }
        /// The walk of `proj` with these grants (below the root).
        fn walk(&self, grants: &[&str]) -> Option<(PathBuf, u64)> {
            use std::os::unix::fs::MetadataExt;
            let grants: Vec<PathBuf> = grants.iter().map(|g| self.root.join(g)).collect();
            let count = |p: &Path| std::fs::symlink_metadata(p).map(|m| m.nlink());
            let names = |p: &Path| names_below(&self.root, p);
            linked_below(&self.proj, Some(&grants), &count, &names).unwrap()
        }
    }

    /// A file in a `target` folder whose names all lie in `target` folders of
    /// the same project, under the same grants, passes, as cargo makes them.
    /// `node_modules` and `.venv` get no such pass, and neither does a folder
    /// whose name only starts like `target`, a link from `target` to another
    /// folder of the project, or one to a file outside it, also when that
    /// file lies in a folder named `target` too.
    #[cfg(unix)]
    #[test]
    fn target_passes_with_its_own_links_only() {
        let p = Project::new();
        p.link("proj/target/debug/demo", "proj/target/debug/deps/demo-0123");
        assert_eq!(p.walk(&["proj"]), None);

        for (from, to) in [
            (
                "proj/node_modules/a/index.js",
                "proj/node_modules/b/index.js",
            ),
            ("proj/.venv/lib/x.py", "proj/.venv/lib/y.py"),
            ("proj/target/debug/lib.rlib", "proj/src/lib.rlib"),
            ("proj/targets/a", "proj/targets/b"),
            ("drop/target/secret", "proj/target/debug/s"),
        ] {
            let to = p.link(from, to);
            // Also where no grant path holds the folder: then only the
            // place of each name counts. (A sync where a granted folder has
            // moved gives no pass at all, `a_moved_project_gives_no_pass`.)
            for grants in [&["proj", "drop"][..], &[]] {
                let found = p.walk(grants);
                assert!(found.is_some(), "{from} -> {}: {found:?}", to.display());
            }
            std::fs::remove_file(&to).unwrap();
            assert_eq!(p.walk(&["proj", "drop"]), None, "{from}");
        }
    }

    /// Two names in `target` folders of the project that lie under
    /// different grants are refused: the change would give the file the
    /// rights of each, so a command could read through one what it may only
    /// write through the other. Also with grants of two pairings.
    #[cfg(unix)]
    #[test]
    fn target_links_between_two_grants_are_refused() {
        let p = Project::new();
        let x = p.link("proj/target/secret.bin", "proj/target/work/x");
        assert_eq!(p.walk(&["proj"]), None, "one grant holds both");
        assert!(p.walk(&["proj", "proj/target/work"]).is_some());
        assert!(
            p.walk(&["proj", "proj/target", "proj/target/work"])
                .is_some()
        );
        std::fs::remove_file(&x).unwrap();
        assert_eq!(p.walk(&["proj", "proj/target/work"]), None);
    }

    /// The pass for `target` compares grants by their paths, but a grant's
    /// entry goes with its folder. So in a sync where a granted folder is
    /// not where its record says, nothing passes: a project the owner
    /// renamed, with another pairing's grant in its `target`, keeps its
    /// grant where it is now while a link between the two grants is there.
    #[cfg(unix)]
    #[test]
    fn a_moved_project_gives_no_pass() {
        let p = Project::new();
        let work = p.proj.join("target/work");
        std::fs::create_dir_all(&work).unwrap();
        let file = p.root.join("grants.json");
        let mut f = Fake {
            walk: Some(p.root.clone()),
            ..Default::default()
        };
        let s = |q: &Path| q.display().to_string();
        f.make(&s(&p.proj));
        f.make(&s(&work));
        let want = [grant("lab", &s(&p.proj), "rw"), grant("m", &s(&work), "r")];
        let r = sync(&file, &want, &mut f);
        assert!(r.errors.is_empty(), "{r:?}");
        p.link("proj/target/secret.bin", "proj/target/work/x");

        let proj2 = p.root.join("proj2");
        std::fs::rename(&p.proj, &proj2).unwrap();
        f.mv(&s(&p.proj), &s(&proj2));
        f.mv(&s(&work), &s(&proj2.join("target/work")));
        let r = sync(&file, &want, &mut f);
        assert!(
            r.errors
                .iter()
                .any(|e| e.contains("secret.bin") || e.contains("work/x")),
            "{r:?}"
        );
        assert_eq!(
            f.on(&s(&proj2)),
            [("lab".to_string(), Access::parse("rw").unwrap())],
            "{r:?}"
        );
    }

    /// The same for a granted folder a command moved into `target`: its
    /// grant is not under its recorded path, so a change on the folder
    /// around it gets no pass for a link into it. Nor when where it is
    /// cannot be told: something the node cannot look at was put in its
    /// place, or the object cannot be looked for.
    #[cfg(unix)]
    #[test]
    fn a_grant_moved_into_target_gives_no_pass() {
        for how in ["moved", "unseen", "lost"] {
            let p = Project::new();
            let (x, g) = (p.root.join("x"), p.root.join("x/g"));
            std::fs::create_dir_all(p.proj.join("target")).unwrap();
            std::fs::create_dir_all(&g).unwrap();
            let file = p.root.join("grants.json");
            let mut f = Fake {
                walk: Some(p.root.clone()),
                ..Default::default()
            };
            let s = |q: &Path| q.display().to_string();
            for q in [&p.proj, &x] {
                f.make(&s(q));
            }
            let id = f.make(&s(&g));
            let want = |proj: &str| {
                [
                    grant("lab", &s(&p.proj), proj),
                    grant("lab", &s(&x), "rw"),
                    grant("m", &s(&g), "r"),
                ]
            };
            let r = sync(&file, &want("rw"), &mut f);
            assert!(r.errors.is_empty(), "{r:?}");

            let moved = p.proj.join("target/g");
            std::fs::rename(&g, &moved).unwrap();
            f.mv(&s(&g), &s(&moved));
            match how {
                "unseen" => {
                    std::fs::create_dir(&g).unwrap();
                    f.make(&s(&g));
                    f.unseen.push(g.clone());
                }
                "lost" => f.lost.push(id),
                _ => {}
            }
            p.link("proj/target/secret.bin", "proj/target/g/s");
            let r = sync(&file, &want("rwx"), &mut f);
            assert!(
                r.errors
                    .iter()
                    .any(|e| e.contains("permissions of") && e.contains("hard links")),
                "{how}: {r:?}"
            );
            assert_eq!(
                f.on(&s(&p.proj)),
                [("lab".to_string(), Access::parse("rw").unwrap())],
                "{how}: {r:?}"
            );
        }
    }

    /// A command may give a folder it makes in `target` an entry of its own,
    /// read for its container, which a change passes to a file linked into
    /// that folder. So no pass is given while a grant of any pairing at,
    /// above or inside the changed folder may write but not read: neither for
    /// a change nor for a take-off. With `rw`, cargo's links pass.
    #[cfg(unix)]
    #[test]
    fn a_folder_written_but_not_read_gives_no_pass() {
        type Grants<'a> = &'a [(&'a str, &'a str, &'a str)];
        // (grants as they are, grants after the change, the link)
        let cases: [(Grants, Grants, (&str, &str)); 5] = [
            // At: the owner's file in a `w`-only project, changed or taken
            // off, and in a project narrowed to `w`.
            (
                &[("lab", "proj", "w")],
                &[("lab", "proj", "wx")],
                ("proj/target/secret.bin", "proj/target/zzz/x"),
            ),
            (
                &[("lab", "proj", "w")],
                &[],
                ("proj/target/secret.bin", "proj/target/zzz/x"),
            ),
            (
                &[("lab", "proj", "rw")],
                &[("lab", "proj", "w")],
                ("proj/target/secret.bin", "proj/target/zzz/x"),
            ),
            // Above: another pairing writes in the folder around it.
            (
                &[("lab", "proj", "rw"), ("m", ".", "w")],
                &[("lab", "proj", "rwx"), ("m", ".", "w")],
                ("proj/target/secret.bin", "proj/target/zzz/x"),
            ),
            // Inside: another pairing writes in a folder in `target`.
            (
                &[("lab", "proj", "rw"), ("m", "proj/target/out", "w")],
                &[("lab", "proj", "rwx"), ("m", "proj/target/out", "w")],
                ("proj/target/out/secret.bin", "proj/target/out/zzz/x"),
            ),
        ];
        for (before, after, (from, to)) in cases {
            let p = Project::new();
            std::fs::create_dir_all(p.proj.join("target/out")).unwrap();
            let file = p.root.join("grants.json");
            let mut f = Fake {
                walk: Some(p.root.clone()),
                ..Default::default()
            };
            let at = |q: &str| match q {
                "." => p.root.display().to_string(),
                q => p.root.join(q).display().to_string(),
            };
            for q in [".", "proj", "proj/target/out"] {
                f.make(&at(q));
            }
            let grants = |gs: Grants| -> Vec<Grant> {
                gs.iter().map(|(c, q, a)| grant(c, &at(q), a)).collect()
            };
            let r = sync(&file, &grants(before), &mut f);
            assert!(r.errors.is_empty(), "{r:?}");
            p.link(from, to);
            let r = sync(&file, &grants(after), &mut f);
            assert!(
                r.errors
                    .iter()
                    .any(|e| e.contains("permissions of") && e.contains("hard links")),
                "{after:?}: {r:?}"
            );
            let lab = Access::parse(before[0].2).unwrap();
            assert_eq!(
                f.on(&at("proj")),
                [("lab".to_string(), lab)],
                "{after:?}: {r:?}"
            );
        }

        // Where every pairing reads what it writes, cargo's links pass.
        let p = Project::new();
        let file = p.root.join("grants.json");
        let mut f = Fake {
            walk: Some(p.root.clone()),
            ..Default::default()
        };
        let proj = p.proj.display().to_string();
        f.make(&proj);
        let r = sync(&file, &[grant("lab", &proj, "rw")], &mut f);
        assert!(r.errors.is_empty(), "{r:?}");
        p.link("proj/target/debug/demo", "proj/target/debug/deps/demo-0123");
        let r = sync(&file, &[grant("lab", &proj, "rwx")], &mut f);
        assert!(r.errors.is_empty(), "{r:?}");
        assert_eq!(
            f.on(&proj),
            [("lab".to_string(), Access::parse("rwx").unwrap())]
        );
        let r = sync(&file, &[], &mut f);
        assert!(r.errors.is_empty() && r.removed == 1, "{r:?}");
    }

    /// A change to `w` without `r` that stopped part way may have given
    /// that below the folder: until a change there finishes, cargo's links
    /// get no pass there, also on the change back.
    #[cfg(unix)]
    #[test]
    fn a_stopped_change_to_write_only_gives_no_pass() {
        let p = Project::new();
        let file = p.root.join("grants.json");
        let mut f = Fake {
            walk: Some(p.root.clone()),
            ..Default::default()
        };
        let proj = p.proj.display().to_string();
        f.make(&proj);
        let (rw, w) = (grant("lab", &proj, "rw"), grant("lab", &proj, "w"));
        let r = sync(&file, std::slice::from_ref(&rw), &mut f);
        assert!(r.errors.is_empty(), "{r:?}");
        f.cut.push(p.proj.clone());
        sync(&file, std::slice::from_ref(&w), &mut f);
        f.cut.clear();
        p.link("proj/target/debug/demo", "proj/target/debug/deps/demo-0123");
        let r = sync(&file, std::slice::from_ref(&rw), &mut f);
        assert!(
            r.errors
                .iter()
                .any(|e| e.contains("permissions of") && e.contains("hard links")),
            "{r:?}"
        );
    }

    /// A file whose names cannot all be listed passes nothing: a listing
    /// that fails while the file is there (as for a path too long for it)
    /// stops the walk, and a listing with fewer names than the file has
    /// finds it.
    #[cfg(unix)]
    #[test]
    fn names_that_cannot_be_listed_pass_nothing() {
        let p = Project::new();
        let x = p.link("proj/target/a", "proj/target/b");
        let grants = [p.proj.clone()];
        let count = |_: &Path| Ok(2);
        let failing =
            |_: &Path| -> io::Result<Vec<PathBuf>> { Err(io::ErrorKind::NotFound.into()) };
        let e = linked_below(&p.proj, Some(&grants), &count, &failing).unwrap_err();
        assert_ne!(e.kind(), io::ErrorKind::NotFound, "{e}");
        let short = |q: &Path| -> io::Result<Vec<PathBuf>> { Ok(vec![q.to_path_buf()]) };
        assert!(
            linked_below(&p.proj, Some(&grants), &count, &short)
                .unwrap()
                .is_some()
        );
        // Gone meanwhile (removed while its names are listed): the walk
        // goes on.
        let vanish = |q: &Path| -> io::Result<Vec<PathBuf>> {
            std::fs::remove_file(q)?;
            Err(io::ErrorKind::NotFound.into())
        };
        assert_eq!(
            linked_below(&p.proj, Some(&grants), &count, &vanish).unwrap(),
            None
        );
        assert!(!x.exists() || !p.proj.join("target/a").exists());
    }

    /// A file the change holds open is judged by the names it has, as the
    /// file gives them: cargo's own pair passes, a file linked in from
    /// outside does not, and neither does it once a command removed the
    /// name the walk found, leaving it with its name outside only. A walk by
    /// path lets that one pass, as it no longer reaches it; the change,
    /// which holds it open, would.
    #[cfg(unix)]
    #[test]
    fn a_held_file_is_judged_by_the_names_it_has() {
        let p = Project::new();
        let grants = [p.proj.clone()];
        let names = |q: &Path| names_below(&p.root, q);
        let judge = Judge::new(&p.proj, Some(&grants));
        let pair = p.link("proj/target/debug/demo", "proj/target/debug/deps/demo-0123");
        assert!(judge.holds(&pair, 2, &names(&pair).unwrap()));
        let x = p.link("drop/target/secret", "proj/target/debug/x");
        let both = names(&x).unwrap();
        assert_eq!(both.len(), 2);
        assert!(!judge.holds(&x, 2, &both));
        std::fs::remove_file(&x).unwrap();
        let left = names(&p.root.join("drop/target/secret")).unwrap();
        assert!(!judge.holds(&x, 2, &left));
        assert!(
            judge.passes(&x, 2, &names).unwrap(),
            "a walk by path does not reach it"
        );
    }

    /// Without a state folder and with nothing wanted, a sync makes neither
    /// the folder nor its lock file: uninstall on a machine where no node
    /// ran leaves nothing behind. Something wanted makes them.
    #[test]
    fn a_sync_with_nothing_to_do_makes_no_state_folder() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("config"), d.path().join("state"));
        let file = record_file(&paths);
        let mut f = Fake::default();
        let s = sync(&file, &[], &mut f);
        assert!(s.errors.is_empty() && s.unknown.is_none(), "{s:?}");
        assert!(!paths.state_dir.exists());
        let s = remove_all(&paths, &[], &mut |_| {});
        assert!(s.errors.is_empty() && s.unknown.is_none(), "{s:?}");
        assert!(!paths.state_dir.exists());
        f.make("/w/a");
        let a = grant("c1", "/w/a", "r");
        sync(&file, std::slice::from_ref(&a), &mut f);
        assert_eq!(recorded(&file), [a]);
    }

    /// The pairings' ids come from the config without its MAC key, which
    /// went with the state folder, and so do the names of their containers;
    /// a node without a config has none.
    #[test]
    fn the_pairings_are_found_without_the_state_folder() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("config"), d.path().join("state"));
        assert_eq!(node_ids(&paths).unwrap(), Vec::<String>::new());
        let mut store = nerve_policy::SettingsStore::open(
            paths.config_file(),
            paths.config_key(),
            nerve_policy::audit::AuditLog::new(paths.audit_log()),
        )
        .unwrap();
        store
            .update(|c| {
                for name in ["lab", "home"] {
                    c.centers.push(nerve_policy::CenterEntry {
                        url: "https://center.example".into(),
                        ..center(name, &[])
                    });
                }
                Ok(())
            })
            .unwrap();
        drop(store);
        let names: Vec<String> = [node("lab"), node("home")]
            .iter()
            .map(|n| container(&paths, n))
            .collect();
        std::fs::remove_dir_all(&paths.state_dir).unwrap();
        let ids = node_ids(&paths).unwrap();
        assert_eq!(ids, [node("lab"), node("home")]);
        let found: Vec<String> = ids.iter().map(|n| container(&paths, n)).collect();
        assert_eq!(found, names);
        // Nothing to remove where no container has a profile.
        assert_eq!(forget(&paths, &node("lab")), Profiles::default());
        std::fs::write(paths.config_file(), "[[center]]\nnode_id = 1\n").unwrap();
        assert!(node_ids(&paths).unwrap_err().contains("node.toml"));
    }

    /// `folder sync`: once every grant is marked for a walk, the next sync
    /// puts each on again into every folder below it, and the marks go; a
    /// sync after that walks nothing.
    #[test]
    fn folder_sync_walks_every_grant_once() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let (a, b) = (PathBuf::from("/srv/a"), PathBuf::from("/srv/b"));
        let mut f = Fake::default();
        f.make("/srv/a");
        f.make("/srv/b");
        let want = [grant("lab", "/srv/a", "rw"), grant("lab", "/srv/b", "r")];
        let s = sync(&file, &want, &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        f.changes.clear();
        // Nothing changed: a plain sync walks nothing.
        sync(&file, &want, &mut f);
        assert!(f.changes.is_empty(), "{:?}", f.changes);
        assert_eq!(walk_every(&file), Ok(2));
        let s = sync(&file, &want, &mut f);
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        let mut walked: Vec<_> = f
            .changes
            .iter()
            .filter(|c| c.2)
            .map(|c| c.0.clone())
            .collect();
        walked.sort();
        assert_eq!(walked, [a.clone(), b.clone()]);
        assert!(recorded(&file).iter().all(|g| !g.unfinished));
        f.changes.clear();
        sync(&file, &want, &mut f);
        assert!(f.changes.is_empty(), "{:?}", f.changes);
        let json = s.json(2);
        assert_eq!(json["walked"], 2);
        assert_eq!(json["errors"], serde_json::json!([]));
        // No record yet: nothing to walk.
        assert_eq!(walk_every(&d.path().join("none.json")), Ok(0));
    }

    /// Profiles by name, as an account has them.
    #[derive(Default)]
    struct FakeProfiles {
        there: Vec<String>,
        removed: Vec<String>,
    }

    impl ProfileStore for FakeProfiles {
        fn exists(&mut self, name: &str) -> bool {
            self.there.iter().any(|n| n == name)
        }
        fn remove(&mut self, name: &str) -> io::Result<()> {
            self.there.retain(|n| n != name);
            self.removed.push(name.into());
            Ok(())
        }
    }

    /// A Windows path, spelled with `\` and `/` in each way the node makes
    /// it: the default state folder is the user's folder joined with
    /// `.local/state/nerve`, which an owner types with `\`.
    #[test]
    fn a_state_folder_has_the_spellings_the_node_makes() {
        let typed = r"C:\Users\u\.local\state\nerve";
        let all = spellings(typed);
        assert_eq!(all[0], typed);
        assert!(all.contains(&r"C:\Users\u\.local/state/nerve".to_string()));
        assert!(all.contains(&"C:/Users/u/.local/state/nerve".to_string()));
        assert_eq!(all.len(), 6, "{all:?}");
        let default = r"C:\Users\u\.local/state/nerve";
        assert!(spellings(default).contains(&typed.to_string()));
        assert_eq!(spellings("x"), ["x"]);
        // The names follow the spelling, and the first is the node's own.
        assert_ne!(container_at(typed, "n"), container_at(default, "n"));
        let paths = NodePaths::new("/c", "/s/state");
        assert_eq!(containers(&paths, "n")[0], container(&paths, "n"));
        // `center` names the one with a profile, else the node's own.
        let mut store = FakeProfiles::default();
        assert_eq!(profile_in(&paths, "n", &mut store), container(&paths, "n"));
        let last = containers(&paths, "n").pop().unwrap();
        store.there.push(last.clone());
        assert_eq!(profile_in(&paths, "n", &mut store), last);
    }

    /// `forget` removes the profile of the pairing's container and says it
    /// did, but not while the node runs: it still serves the pairing, and
    /// its commands use the profile.
    #[test]
    fn forget_keeps_the_profile_while_the_node_runs() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("config"), d.path().join("state"));
        let name = container(&paths, &node("lab"));
        let mut store = FakeProfiles {
            there: vec![name.clone(), "nerve.other".into()],
            ..Default::default()
        };
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        let held = crate::secrets::HeldByANode::take(&paths);
        let p = forget_in(&paths, &node("lab"), &mut store);
        assert_eq!(p.kept, std::slice::from_ref(&name));
        assert!(p.why.unwrap().contains("runs"));
        assert!(p.removed.is_empty() && store.removed.is_empty());
        drop(held);
        let p = forget_in(&paths, &node("lab"), &mut store);
        assert_eq!(p.removed, std::slice::from_ref(&name));
        assert!(p.kept.is_empty() && p.why.is_none() && p.errors.is_empty());
        assert_eq!(store.there, ["nerve.other"]);
        // Nothing there is nothing removed.
        let p = forget_in(&paths, &node("lab"), &mut store);
        assert_eq!(p, Profiles::default());
        // No state folder: no node runs there, and none is made to look.
        std::fs::remove_dir_all(&paths.state_dir).unwrap();
        store.there.push(name.clone());
        assert_eq!(forget_in(&paths, &node("lab"), &mut store).removed, [name]);
        assert!(!paths.state_dir.exists());
    }

    /// The CLI's sync (`center rm`, `folder rm`) takes the grants of a
    /// container off, and its profile only while the node does not run,
    /// and says which went and which stayed.
    #[test]
    fn the_clis_sync_keeps_the_profile_of_an_emptied_container_while_the_node_runs() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("config"), d.path().join("state"));
        let lab = container(&paths, &node("lab"));
        let home = container(&paths, &node("home"));
        let mut f = Fake::default();
        f.make("/w/a");
        f.make("/w/b");
        let a = grant(&lab, "/w/a", "r");
        let b = grant(&home, "/w/b", "r");
        let mut store = FakeProfiles {
            there: vec![lab.clone(), home.clone()],
            ..Default::default()
        };
        let both = [a.clone(), b.clone()];
        let s = sync_outside_in(&paths, &both, &[], &mut f, &mut store);
        assert_eq!(s.profiles, Profiles::default());
        // No container emptied, so no profile to remove: the keys' lock is
        // not taken, and its file not made.
        assert!(!paths.keys_lock().exists());
        let held = crate::secrets::HeldByANode::take(&paths);
        let s = sync_outside_in(&paths, std::slice::from_ref(&b), &[], &mut f, &mut store);
        assert_eq!(s.removed, 1);
        assert_eq!(s.profiles.kept, std::slice::from_ref(&lab));
        assert!(s.profiles.why.unwrap().contains("runs"));
        assert!(store.removed.is_empty());
        drop(held);
        // With the node stopped, the profile goes with the last grant.
        sync_outside_in(&paths, &both, &[], &mut f, &mut store);
        let s = sync_outside_in(&paths, std::slice::from_ref(&b), &[], &mut f, &mut store);
        assert_eq!(s.profiles.removed, std::slice::from_ref(&lab));
        assert_eq!(store.there, std::slice::from_ref(&home));
        assert!(s.errors.is_empty(), "{s:?}");
    }

    /// The node removes the profile of a container its sync left without
    /// grants in the same turn: another sync, as the `folder.grants` that
    /// `center rm` asks for while the node's own sync of the change runs,
    /// returns only once the profile is gone. `center rm` looks at the
    /// profiles right after it and says one it finds stays.
    #[test]
    fn a_sync_after_the_nodes_own_finds_the_emptied_profile_gone() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::mpsc;
        /// A profile whose removal waits for the test's word.
        struct Slow {
            removing: mpsc::Sender<()>,
            go: mpsc::Receiver<()>,
            gone: Arc<AtomicBool>,
        }
        impl ProfileStore for Slow {
            fn exists(&mut self, _: &str) -> bool {
                !self.gone.load(Ordering::SeqCst)
            }
            fn remove(&mut self, _: &str) -> io::Result<()> {
                self.removing.send(()).unwrap();
                self.go.recv().unwrap();
                self.gone.store(true, Ordering::SeqCst);
                Ok(())
            }
        }
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("config"), d.path().join("state"));
        let lab = container(&paths, &node("lab"));
        let mut f = Fake::default();
        f.make("/w/a");
        sync(&record_file(&paths), &[grant(&lab, "/w/a", "r")], &mut f);
        let gone = Arc::new(AtomicBool::new(false));
        let (removing, removing_rx) = mpsc::channel();
        let (go, go_rx) = mpsc::channel();
        // The node's own sync of the change: the grant goes, then the
        // profile, which waits.
        let own = {
            let (paths, gone) = (paths.clone(), gone.clone());
            std::thread::spawn(move || {
                let mut store = Slow {
                    removing,
                    go: go_rx,
                    gone,
                };
                apply_in(&paths, Default::default, &mut f, &mut store)
            })
        };
        let wait = std::time::Duration::from_secs(20);
        removing_rx.recv_timeout(wait).unwrap();
        // The one `center rm` asks for: it finds nothing left to take off,
        // and says whether the profile was gone when it returned.
        let (done, done_rx) = mpsc::channel();
        let asked = {
            let (paths, gone) = (paths.clone(), gone.clone());
            std::thread::spawn(move || {
                let mut store = FakeProfiles::default();
                let s = apply_in(&paths, Default::default, &mut Fake::default(), &mut store);
                done.send(gone.load(Ordering::SeqCst)).unwrap();
                s
            })
        };
        let short = std::time::Duration::from_millis(300);
        assert!(
            done_rx.recv_timeout(short).is_err(),
            "the sync returned while the profile was still there"
        );
        go.send(()).unwrap();
        assert!(done_rx.recv_timeout(wait).unwrap());
        let s = own.join().unwrap();
        assert_eq!(s.emptied, [lab]);
        assert!(s.errors.is_empty(), "{s:?}");
        let s = asked.join().unwrap();
        assert!(s.emptied.is_empty() && s.errors.is_empty(), "{s:?}");
    }

    /// The profile of a pairing's container holds its home on the
    /// installed service: it stays while the pairing does, also once its
    /// last folder is gone, and goes with the pairing, also when it never
    /// had a grant; the CLI's sync keeps it the same way. A removal that
    /// fails is tried again.
    #[test]
    fn a_pairings_profile_goes_with_the_pairing_not_its_last_grant() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("config"), d.path().join("state"));
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        let lab = container(&paths, &node("lab"));
        let home = container(&paths, &node("home"));
        let mut f = Fake::default();
        f.make("/w/a");
        let a = grant(&lab, "/w/a", "rw");
        let mut store = FakeProfiles {
            there: vec![lab.clone(), home.clone()],
            ..Default::default()
        };
        let both = || vec![lab.clone(), home.clone()];
        apply_in(&paths, || (vec![a.clone()], both()), &mut f, &mut store);
        // The last folder goes: the profile stays.
        let s = apply_in(&paths, || (Vec::new(), both()), &mut f, &mut store);
        assert_eq!(s.emptied, std::slice::from_ref(&lab));
        assert!(store.removed.is_empty(), "{:?}", store.removed);
        // The pairings go: both profiles go, `home` without a grant ever.
        let s = apply_in(&paths, Default::default, &mut f, &mut store);
        assert!(s.errors.is_empty(), "{s:?}");
        store.removed.sort();
        let mut gone = both();
        gone.sort();
        assert_eq!(store.removed, gone);
        assert!(store.there.is_empty());
        // A removal that fails is kept to try again.
        struct Failing(usize);
        impl ProfileStore for Failing {
            fn exists(&mut self, _: &str) -> bool {
                true
            }
            fn remove(&mut self, _: &str) -> io::Result<()> {
                self.0 += 1;
                Err(io::Error::other("in use"))
            }
        }
        apply_in(
            &paths,
            || (Vec::new(), vec![lab.clone()]),
            &mut f,
            &mut store,
        );
        let mut failing = Failing(0);
        let s = apply_in(&paths, Default::default, &mut f, &mut failing);
        assert_eq!(failing.0, 1, "{s:?}");
        apply_in(&paths, Default::default, &mut f, &mut failing);
        assert_eq!(failing.0, 2);
        apply_in(&paths, Default::default, &mut f, &mut store);
        assert_eq!(store.removed.last(), Some(&lab));
        // The CLI's sync keeps a pairing's profile too.
        f.make("/w/b");
        let b = grant(&lab, "/w/b", "r");
        store.there.push(lab.clone());
        sync_outside_in(
            &paths,
            std::slice::from_ref(&b),
            std::slice::from_ref(&lab),
            &mut f,
            &mut store,
        );
        let s = sync_outside_in(&paths, &[], std::slice::from_ref(&lab), &mut f, &mut store);
        assert_eq!(s.emptied, std::slice::from_ref(&lab));
        assert!(
            s.profiles.removed.is_empty() && store.there.contains(&lab),
            "{s:?}"
        );
    }

    /// A sync that waited for its turn applies the config as it is once
    /// its turn has come: the node starts one for each change, and one
    /// started for the older config of two quick changes, which waited while
    /// the newer one took a grant off, must not put that grant back.
    #[test]
    fn a_sync_that_waited_applies_the_newest_config() {
        use std::sync::mpsc;
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("config"), d.path().join("state"));
        let file = record_file(&paths);
        let a = grant(&container(&paths, &node("lab")), "/w/a", "r");
        // The grants the node's config wants: `a`, until the owner takes it
        // away.
        let current = Arc::new(Mutex::new(vec![a.clone()]));
        let mut f = Fake::default();
        f.make("/w/a");
        let mut store = FakeProfiles::default();
        apply_in(
            &paths,
            || (current.lock().unwrap().clone(), Vec::new()),
            &mut f,
            &mut store,
        );
        assert_eq!(recorded(&file), std::slice::from_ref(&a));
        // A sync runs: the one the node started for the change before.
        let running = nerve_transport::sync::turn(&SYNC);
        let (read, read_rx) = mpsc::channel();
        let waited = {
            let (paths, current) = (paths.clone(), current.clone());
            std::thread::spawn(move || {
                let mut f = Fake::default();
                f.make("/w/a");
                let want = || {
                    let _ = read.send(());
                    (current.lock().unwrap().clone(), Vec::new())
                };
                let s = apply_in(&paths, want, &mut f, &mut FakeProfiles::default());
                (s, f.all())
            })
        };
        // Time for it to read the config, were it to read it before its
        // turn; then the owner takes `a` away, and the running sync takes
        // it off.
        let _ = read_rx.recv_timeout(std::time::Duration::from_millis(300));
        current.lock().unwrap().clear();
        let s = sync_in_turn(&file, &[], &mut f);
        assert_eq!(s.removed, 1);
        drop(running);
        let (s, on) = waited.join().unwrap();
        assert!(s.errors.is_empty(), "{s:?}");
        assert!(on.is_empty(), "the grant came back: {on:?}");
        assert!(recorded(&file).is_empty());
    }

    /// What two cleanups did, each profile once.
    #[test]
    fn profiles_merge_each_once() {
        let mut p = Profiles {
            removed: vec!["a".into()],
            ..Default::default()
        };
        p.merge(Profiles {
            removed: vec!["a".into(), "b".into()],
            kept: vec!["c".into()],
            why: Some("runs".into()),
            errors: vec!["e".into()],
        });
        assert_eq!(p.removed, ["a", "b"]);
        assert_eq!(p.kept, ["c"]);
        assert_eq!(p.why.as_deref(), Some("runs"));
        assert_eq!(p.errors, ["e"]);
    }

    /// `remove_all` takes the grants off and removes the profiles of the
    /// recorded containers and of the pairings; while the node runs the
    /// profiles stay.
    #[test]
    fn remove_all_removes_the_profiles_unless_the_node_runs() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("config"), d.path().join("state"));
        let lab = container(&paths, &node("lab"));
        let home = container(&paths, &node("home"));
        let mut f = Fake::default();
        f.make("/w/a");
        sync(&record_file(&paths), &[grant(&lab, "/w/a", "r")], &mut f);
        let ids = [node("lab"), node("home")];
        let held = crate::secrets::HeldByANode::take(&paths);
        let mut store = FakeProfiles {
            there: vec![lab.clone(), home.clone()],
            ..Default::default()
        };
        let s = remove_all_in(&paths, &ids, &mut f, &mut store);
        assert_eq!(s.removed, 1);
        let mut kept = s.profiles.kept.clone();
        kept.sort();
        let mut both = vec![lab.clone(), home.clone()];
        both.sort();
        assert_eq!(kept, both);
        assert!(store.removed.is_empty());
        drop(held);
        let s = remove_all_in(&paths, &ids, &mut f, &mut store);
        let mut removed = s.profiles.removed.clone();
        removed.sort();
        assert_eq!(removed, both);
        assert!(store.there.is_empty() && s.errors.is_empty(), "{s:?}");
    }

    /// Each grant is in the record before it goes on, and stays in it when
    /// putting it on failed, since part of it may be on.
    #[test]
    fn a_grant_is_recorded_before_it_goes_on() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake {
            record: Some(file.clone()),
            ..Default::default()
        };
        f.make("/w/a");
        f.make("/w/b");
        f.locked.push("/w/b".into());
        let (a, b) = (grant("c1", "/w/a", "rwx"), grant("c1", "/w/b", "r"));
        let s = sync(&file, &[a.clone(), b.clone()], &mut f);
        assert_eq!(s.errors.len(), 1, "{s:?}");
        assert!(s.stale.is_empty(), "{s:?}");
        assert_eq!(recorded(&file), [a.clone(), b.clone()]);
        // Not wanted any more, it is taken off as any other.
        f.locked.clear();
        sync(&file, std::slice::from_ref(&a), &mut f);
        assert_eq!(recorded(&file), [a]);
    }

    /// The record is held while a sync reads, changes and writes it: a sync
    /// waits while another process holds it, so neither writes over what the
    /// other recorded.
    #[test]
    fn a_sync_waits_while_the_record_is_held() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let held = RecordLock::take(&file).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let path = file.clone();
        let t = std::thread::spawn(move || {
            let mut f = Fake::default();
            f.make("/w/a");
            let s = sync(&path, &[grant("c1", "/w/a", "r")], &mut f);
            tx.send(()).unwrap();
            s
        });
        let wait = std::time::Duration::from_millis(300);
        assert!(rx.recv_timeout(wait).is_err(), "the sync did not wait");
        assert!(!file.exists());
        drop(held);
        rx.recv_timeout(std::time::Duration::from_secs(20)).unwrap();
        assert!(t.join().unwrap().errors.is_empty());
        assert_eq!(recorded(&file), [grant("c1", "/w/a", "r")]);
    }

    /// A change that stopped part way (it failed after it changed what is
    /// below the folder, or the node stopped) leaves its grant marked in the
    /// record, and the next change there goes into every folder below: also
    /// one back to the flags the folder still shows, where a sync would see
    /// nothing to do. Each change finds its grant marked before it starts,
    /// and a finished change leaves no mark.
    #[test]
    fn a_change_that_stopped_part_way_is_walked_again_whole() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake {
            record: Some(file.clone()),
            marked: true,
            ..Default::default()
        };
        f.make("/w/a");
        let (r, rw) = (grant("c1", "/w/a", "r"), grant("c1", "/w/a", "rw"));
        let s = sync(&file, std::slice::from_ref(&r), &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        let marks = || -> Vec<bool> {
            read_record(&file)
                .unwrap()
                .iter()
                .map(|g| g.unfinished)
                .collect()
        };
        assert_eq!(marks(), [false]);

        // Widened, stopped part way: the folder keeps `r`.
        f.cut.push("/w/a".into());
        let s = sync(&file, std::slice::from_ref(&rw), &mut f);
        assert_eq!(s.errors.len(), 1, "{s:?}");
        assert_eq!(f.on("/w/a"), [("c1".to_string(), r.access)]);
        assert!(marks().iter().all(|m| *m), "{:?}", read_record(&file));

        // The record keeps the flags it was heading for.
        let record = read_record(&file).unwrap();
        assert_eq!(record[0].toward, [rw.access], "{record:?}");

        // Back to `r`: the folder shows it, and yet the change goes through
        // every folder below, to take the `rw` the stopped one left there;
        // and as commands may have written there, it checks for hard links.
        f.cut.clear();
        f.changes.clear();
        let s = sync(&file, std::slice::from_ref(&r), &mut f);
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        assert_eq!(f.changes, [(PathBuf::from("/w/a"), true, true)]);
        assert!(read_record(&file).unwrap()[0].toward.is_empty());
        assert_eq!(marks(), [false]);
        f.changes.clear();
        sync(&file, std::slice::from_ref(&r), &mut f);
        assert!(f.changes.is_empty(), "done");

        // The node stopped during a change: the record holds its mark.
        let mut stopped = read_record(&file).unwrap();
        stopped[0].unfinished = true;
        write_record(&file, &stopped).unwrap();
        let s = sync(&file, std::slice::from_ref(&r), &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        assert_eq!(f.changes, [(PathBuf::from("/w/a"), false, true)]);
        assert_eq!(marks(), [false]);

        // A take-off that stops part way stays marked too.
        f.cut.push("/w/a".into());
        let s = sync(&file, &[], &mut f);
        assert_eq!(s.stale.len(), 1, "{s:?}");
        assert_eq!(marks(), [true]);
    }

    /// After a widening to `w` stopped part way, a change back that a hard
    /// link below refuses leaves the grant stale, so its commands do not
    /// run: what the stopped change wrote may give them `w`, which the user
    /// took away. Once the link is gone, the change goes through.
    #[test]
    fn a_refused_change_after_a_stopped_widening_is_stale() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/a");
        let (r, rw) = (grant("c1", "/w/a", "r"), grant("c1", "/w/a", "rw"));
        sync(&file, std::slice::from_ref(&r), &mut f);
        f.cut.push("/w/a".into());
        sync(&file, std::slice::from_ref(&rw), &mut f);
        f.cut.clear();
        f.linked.push("/w/a/sub/l".into());
        let s = sync(&file, std::slice::from_ref(&r), &mut f);
        assert!(
            s.errors.len() == 1 && s.errors[0].contains("hard links"),
            "{s:?}"
        );
        assert!(s.refusal("c1").is_some(), "{s:?}");
        f.linked.clear();
        let s = sync(&file, std::slice::from_ref(&r), &mut f);
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        assert!(s.refusal("c1").is_none());
    }

    /// The node ended during a widening (killed, or the CLI stopped): the
    /// record it wrote before the change holds the mark and the flags the
    /// change was heading for, so the change back goes into every folder
    /// and checks for hard links.
    #[test]
    fn a_change_the_node_died_in_is_walked_again_whole_and_checked() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/a");
        let (r, rw) = (grant("c1", "/w/a", "r"), grant("c1", "/w/a", "rw"));
        sync(&file, std::slice::from_ref(&r), &mut f);
        f.die.push("/w/a".into());
        let died = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sync(&file, std::slice::from_ref(&rw), &mut f)
        }));
        assert!(died.is_err());
        let record = read_record(&file).unwrap();
        assert!(
            record
                .iter()
                .any(|g| g.access == r.access && g.unfinished && g.toward == [rw.access]),
            "{record:?}"
        );
        f.die.clear();
        f.changes.clear();
        let s = sync(&file, std::slice::from_ref(&r), &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        assert_eq!(f.changes, [(PathBuf::from("/w/a"), true, true)]);
    }

    /// Where the record cannot be marked before a change, only take-offs
    /// run, here and where moved folders are now; puts and replacements
    /// wait, and a grant one would change is stale where it may give flags
    /// that are not wanted, as one whose widening stopped and is wanted
    /// back.
    #[cfg(unix)]
    #[test]
    fn a_record_that_cannot_be_marked_leaves_what_gives_more_stale() {
        use std::os::unix::fs::PermissionsExt;
        let read_only = |dir: &Path, on: bool| {
            let mode = if on { 0o500 } else { 0o700 };
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        let (r, rw) = (grant("c1", "/w/a", "r"), grant("c1", "/w/a", "rw"));

        // A widening stopped, then the old flags wanted again.
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/a");
        sync(&file, std::slice::from_ref(&r), &mut f);
        f.cut.push("/w/a".into());
        sync(&file, std::slice::from_ref(&rw), &mut f);
        f.cut.clear();
        read_only(d.path(), true);
        let s = sync(&file, std::slice::from_ref(&r), &mut f);
        read_only(d.path(), false);
        assert!(!s.errors.is_empty(), "{s:?}");
        assert!(s.refusal("c1").is_some(), "{s:?}");

        // Moved away, the config unchanged: taken off where it is now, as
        // a take-off needs no mark; nothing goes on at the old path.
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/a");
        sync(&file, std::slice::from_ref(&rw), &mut f);
        f.mv("/w/a", "/x/private");
        f.make("/w/a");
        read_only(d.path(), true);
        let s = sync(&file, std::slice::from_ref(&rw), &mut f);
        read_only(d.path(), false);
        assert!(!s.errors.is_empty(), "{s:?}");
        assert_eq!(s.removed, 1, "{s:?}");
        assert!(f.on("/x/private").is_empty() && f.on("/w/a").is_empty());

        // Taken off the pairing, as by `uninstall`: every grant comes off.
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/a");
        f.make("/w/b");
        sync(&file, &[rw.clone(), grant("c2", "/w/b", "r")], &mut f);
        read_only(d.path(), true);
        let s = sync(&file, &[], &mut f);
        read_only(d.path(), false);
        assert!(!s.errors.is_empty(), "{s:?}");
        assert_eq!(s.removed, 2, "{s:?}");
        assert!(s.stale.is_empty(), "{s:?}");
        assert!(f.all().is_empty(), "{:?}", f.all());

        // Moved where it cannot be found, or to a volume that is away, while
        // another pairing's folder is taken off: lost is stale, away is
        // named, as without the record's trouble.
        for away in [false, true] {
            let d = tempfile::tempdir().unwrap();
            let file = d.path().join("grants.json");
            let mut f = Fake::default();
            let id = f.make("/w/a");
            f.make("/w/b");
            let b = grant("c2", "/w/b", "r");
            sync(&file, &[rw.clone(), b], &mut f);
            f.mv("/w/a", "/x/a");
            if away {
                f.away = true;
            } else {
                f.lost.push(id);
            }
            read_only(d.path(), true);
            let s = sync(&file, std::slice::from_ref(&rw), &mut f);
            read_only(d.path(), false);
            assert!(!s.errors.is_empty(), "{s:?}");
            if away {
                assert_eq!(s.away.len(), 1, "{s:?}");
            } else {
                assert!(s.refusal("c1").is_some(), "{s:?}");
            }
        }
    }

    /// A change goes only through the object recorded for its place: one
    /// whose folder was replaced after the sync looked (`rm -rf dist &&
    /// mkdir dist`) is refused before anything is written, and the next
    /// sync puts the grant on the new folder.
    #[test]
    fn a_change_goes_only_through_the_recorded_object() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/a");
        f.replace_after_look.push("/w/a".into());
        let a = grant("c1", "/w/a", "rw");
        let s = sync(&file, std::slice::from_ref(&a), &mut f);
        assert_eq!(s.errors.len(), 1, "{s:?}");
        assert!(f.all().is_empty(), "nothing written: {:?}", f.all());
        assert!(read_record(&file).unwrap().is_empty());
        let s = sync(&file, std::slice::from_ref(&a), &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        assert_eq!(f.on("/w/a"), [("c1".to_string(), a.access)]);
    }

    /// A take-off at its path, a take-off where a moved folder is now, and
    /// a replacement each go only through the recorded object: one whose
    /// folder is moved away right after the sync found it, with or without
    /// a new folder in its place, is refused with nothing written and the
    /// record kept, and the next sync takes the grant off where the folder
    /// went.
    #[test]
    fn take_offs_and_replacements_go_only_through_the_recorded_object() {
        let (r, rw) = (grant("c1", "/w/a", "r"), grant("c1", "/w/a", "rw"));
        for remake in [false, true] {
            for case in ["take-off", "moved take-off", "replacement"] {
                let d = tempfile::tempdir().unwrap();
                let file = d.path().join("grants.json");
                let mut f = Fake::default();
                f.make("/w/a");
                let first = if case == "replacement" { &r } else { &rw };
                sync(&file, std::slice::from_ref(first), &mut f);
                // Where the change finds the folder: at its path, or where
                // it was moved before this sync.
                let at = if case == "moved take-off" {
                    f.mv("/w/a", "/x/a");
                    "/x/a"
                } else {
                    "/w/a"
                };
                f.move_after_look.push((at.into(), remake));
                let want: &[Grant] = if case == "replacement" {
                    std::slice::from_ref(&rw)
                } else {
                    &[]
                };
                let s = sync(&file, want, &mut f);
                let what = format!("{case}, remade {remake}: {s:?}");
                assert_eq!(s.errors.len(), 1, "{what}");
                assert_eq!(s.stale.len(), 1, "{what}");
                let old = format!("{at}.old");
                assert_eq!(f.on(&old), [("c1".to_string(), first.access)], "{what}");
                if remake {
                    assert!(f.on(at).is_empty(), "nothing written: {what}");
                }
                assert_eq!(read_record(&file).unwrap().len(), 1, "{what}");
                let s = sync(&file, &[], &mut f);
                assert!(s.errors.is_empty(), "{case}, remade {remake}: {s:?}");
                assert!(f.all().is_empty(), "{case}, remade {remake}: {:?}", f.all());
                assert!(read_record(&file).unwrap().is_empty());
            }
        }
    }

    /// A first grant that stopped part way, failing or with the node's end,
    /// is recorded with its folder's object: moved before the next sync,
    /// it is found where it is now and taken off there.
    #[test]
    fn a_first_grant_that_stopped_is_found_where_its_folder_went() {
        for die in [false, true] {
            let d = tempfile::tempdir().unwrap();
            let file = d.path().join("grants.json");
            let mut f = Fake::default();
            f.make("/w/a");
            let a = grant("c1", "/w/a", "rw");
            if die {
                f.die.push("/w/a".into());
                let died = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    sync(&file, std::slice::from_ref(&a), &mut f)
                }));
                assert!(died.is_err());
            } else {
                f.cut.push("/w/a".into());
                sync(&file, std::slice::from_ref(&a), &mut f);
            }
            let record = read_record(&file).unwrap();
            assert!(record[0].id.is_some(), "{die}: {record:?}");
            f.die.clear();
            f.cut.clear();
            f.mv("/w/a", "/x/a");
            f.changes.clear();
            let s = sync(&file, &[], &mut f);
            assert!(s.errors.is_empty(), "{die}: {s:?}");
            assert_eq!(s.removed, 1, "{die}: {s:?}");
            assert_eq!(f.changes, [(PathBuf::from("/x/a"), true, false)], "{die}");
            assert!(read_record(&file).unwrap().is_empty());
        }
    }

    /// The mark of a folder moved away whose take-off stopped is about its
    /// walk where it is now: a folder made anew at its old path gets its
    /// grant once, and is not walked again at each sync.
    #[test]
    fn a_moved_folders_mark_does_not_hold_the_new_one() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/a");
        let rw = grant("c1", "/w/a", "rw");
        sync(&file, std::slice::from_ref(&rw), &mut f);
        f.mv("/w/a", "/x/a");
        f.make("/w/a");
        f.cut.push("/x/a".into());
        let s = sync(&file, std::slice::from_ref(&rw), &mut f);
        assert_eq!(s.stale.len(), 1, "{s:?}");
        assert_eq!(f.on("/w/a"), [("c1".to_string(), rw.access)]);
        for _ in 0..2 {
            f.changes.clear();
            sync(&file, std::slice::from_ref(&rw), &mut f);
            assert!(
                f.changes.iter().all(|(p, _, _)| p == Path::new("/x/a")),
                "{:?}",
                f.changes
            );
        }
    }

    /// After a widening of `/w/a` stopped, a grant asked for inside it goes
    /// on an object of its own only: commands may have written there.
    #[test]
    fn a_grant_inside_a_stopped_widening_goes_on_an_object_of_its_own() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/a");
        f.make("/w/a/n");
        let (r, rw) = (grant("c1", "/w/a", "r"), grant("c1", "/w/a", "rw"));
        sync(&file, std::slice::from_ref(&r), &mut f);
        f.cut.push("/w/a".into());
        sync(&file, std::slice::from_ref(&rw), &mut f);
        f.cut.clear();
        f.asked.clear();
        sync(&file, &[r.clone(), grant("c1", "/w/a/n", "r")], &mut f);
        assert!(
            f.asked.contains(&(PathBuf::from("/w/a/n"), true)),
            "{:?}",
            f.asked
        );
    }

    /// An error of the kind a refusal has, from a change that stopped part
    /// way, is not taken for one that changed nothing: a first grant stays
    /// recorded and marked, and comes off when the folder is no longer
    /// wanted. Only an error marked as a refusal changes nothing
    /// ([`Untouched`]; `inside_a_writable_folder_a_grant_goes_on_an_object_of_its_own`).
    #[test]
    fn a_first_grant_that_stopped_part_way_stays_recorded() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/a");
        f.cut.push("/w/a".into());
        let a = grant("c1", "/w/a", "rw");
        let s = sync(&file, std::slice::from_ref(&a), &mut f);
        assert_eq!(s.errors.len(), 1, "{s:?}");
        let record = read_record(&file).unwrap();
        assert_eq!(record.len(), 1, "{record:?}");
        assert!(record[0].unfinished, "{record:?}");
        f.cut.clear();
        f.changes.clear();
        let s = sync(&file, &[], &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        assert_eq!(s.removed, 1, "{s:?}");
        assert!(read_record(&file).unwrap().is_empty());
    }

    /// Each change checks for hard links where commands write at, above or
    /// below its folder, as it makes it, and only there: putting on, taking
    /// off, and taking off where a moved folder is now.
    #[test]
    fn each_change_checks_for_hard_links_where_commands_write() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        for p in ["/w", "/w/sub", "/r", "/m"] {
            f.make(p);
        }
        let want = [
            grant("c1", "/w", "rw"),
            grant("c1", "/w/sub", "r"),
            grant("c1", "/r", "r"),
            grant("c2", "/m", "rw"),
        ];
        let s = sync(&file, &want, &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        let checked = |f: &Fake| -> Vec<(String, bool)> {
            let mut c: Vec<(String, bool)> = f
                .changes
                .iter()
                .map(|(p, c, _)| (p.display().to_string(), *c))
                .collect();
            c.sort();
            c
        };
        let expect = |pairs: &[(&str, bool)]| -> Vec<(String, bool)> {
            pairs.iter().map(|(p, c)| (p.to_string(), *c)).collect()
        };
        assert_eq!(
            checked(&f),
            expect(&[("/m", true), ("/r", false), ("/w", true), ("/w/sub", true)])
        );

        // Taken off, and `/m` moved: where it is now, it is checked, as
        // commands wrote in it.
        f.changes.clear();
        f.mv("/m", "/m2");
        let s = sync(&file, &want[..1], &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        assert_eq!(
            checked(&f),
            expect(&[("/m2", true), ("/r", false), ("/w/sub", true)])
        );
    }

    /// A change that takes long tells how far it is: first after a few
    /// seconds, with why it takes long, then now and then, and how it ended.
    /// A quick one says nothing.
    #[test]
    fn a_long_change_tells_how_far_it_is() {
        let start = Instant::now();
        let clock = std::cell::Cell::new(start);
        let now = || clock.get();
        let path = Path::new("/w/big");
        // Passes `secs` (from the start), 256 more objects done at each, and
        // ends as `ok` says.
        let run = |doing: Doing, secs: &[u64], ok: bool| {
            clock.set(start);
            let mut told = Vec::new();
            let r = paced(
                &mut |m: &str| told.push(m.to_string()),
                doing,
                path,
                &now,
                |progress| {
                    let mut w = Walked::default();
                    for s in secs {
                        w.seen += 256;
                        w.changed += 256;
                        clock.set(start + Duration::from_secs(*s));
                        progress(w);
                    }
                    if ok {
                        Ok(((), w))
                    } else {
                        Err(io::Error::other("refused"))
                    }
                },
            );
            assert_eq!(r.is_ok(), ok);
            told
        };

        assert!(run(Doing::Put, &[1, 2], true).is_empty());

        let told = run(Doing::Put, &[1, 4, 10, 19, 20, 35], true);
        assert_eq!(told.len(), 4, "{told:#?}");
        assert!(
            told[0].starts_with("putting the grant on /w/big takes a while: Windows keeps")
                && told[0].ends_with("(512 files and folders looked at, 512 changed so far)"),
            "{told:#?}"
        );
        assert_eq!(
            told[1],
            "still putting the grant on /w/big: 1024 files and folders looked at, 1024 changed so far"
        );
        assert!(told[2].contains(": 1536 files"), "{told:#?}");
        assert_eq!(
            told[3],
            "put the grant on /w/big in 35 s: 1536 files and folders looked at, 1536 changed"
        );

        let told = run(Doing::Remove, &[5], false);
        assert_eq!(told.len(), 2, "{told:#?}");
        assert!(told[0].starts_with("taking the grant off /w/big takes a while"));
        assert_eq!(told[1], "taking the grant off /w/big stopped after 5 s");

        let told = run(Doing::Check, &[3], true);
        assert!(
            told[0].starts_with("checking /w/big for hard links takes a while")
                && told[0].contains("256 to change so far"),
            "{told:#?}"
        );
        assert_eq!(
            told[1],
            "checked /w/big for hard links in 3 s: 256 files and folders looked at, 256 to change"
        );
    }

    /// A record that cannot be read stops the sync, since the grants in it
    /// could not be found again, and stops every container's commands.
    #[test]
    fn an_unreadable_record_changes_nothing_and_stops_the_commands() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        std::fs::write(&file, "not json").unwrap();
        let mut f = Fake::default();
        f.make("/w/a");
        let s = sync(&file, &[grant("c1", "/w/a", "r")], &mut f);
        assert_eq!(s.errors.len(), 1, "{s:?}");
        assert_eq!(f.sets, 0);
        let why = s.refusal("any").unwrap();
        assert!(why.contains(&file.display().to_string()), "{why}");
    }

    /// Each pairing has a container of its own, and so has each node.
    #[test]
    fn containers_differ_by_pairing_and_node() {
        let p = NodePaths::new("/n1/config", "/n1/state");
        let q = NodePaths::new("/n2/config", "/n2/state");
        let a = container(&p, &node("lab"));
        assert_eq!(a, container(&p, &node("lab")));
        assert_ne!(a, container(&p, &node("home")));
        assert_ne!(a, container(&q, &node("lab")));
        assert!(a.len() <= 64, "{a}");
        assert!(
            a.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.'),
            "{a}"
        );
    }

    /// A pairing's container is its own, not its center's name's: a later
    /// pairing under the same name on the same node (also of the same
    /// center) runs in another one. Entries a command of the first gave what
    /// it made, which the node does not take off, then do not count for the
    /// second; the first's grant comes off and the second's goes on.
    #[cfg(unix)]
    #[test]
    fn a_new_pairing_under_the_same_name_gets_a_container_of_its_own() {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (home, work) = (root.join("home"), root.join("work"));
        for p in [&home, &work] {
            std::fs::create_dir_all(p).unwrap();
        }
        let paths = NodePaths::new(root.join("cfg"), root.join("state"));
        let pairing = |node_id: &str| {
            let mut c = center("lab", &[(&work, "rw")]);
            c.node_id = node_id.into();
            let mut cfg = NodeConfig::default();
            cfg.centers.push(c);
            wanted(&cfg, &paths, &home, &Platform::Unix)
        };
        let (first, second) = (pairing("n1"), pairing("n2"));
        assert_eq!(first.len(), 1, "{first:?}");
        assert_eq!(second.len(), 1, "{second:?}");
        assert_eq!(first[0].container, container(&paths, "n1"));
        assert_eq!(second[0].container, container(&paths, "n2"));
        assert_ne!(first[0].container, second[0].container);

        let file = record_file(&paths);
        let mut f = Fake::default();
        let at = work.display().to_string();
        f.make(&at);
        let r = sync(&file, &first, &mut f);
        assert!(r.errors.is_empty(), "{r:?}");
        let r = sync(&file, &second, &mut f);
        assert!(r.errors.is_empty(), "{r:?}");
        assert_eq!(
            f.on(&at),
            [(second[0].container.clone(), Access::parse("rw").unwrap())]
        );
    }

    /// The config's folders become grants per center; the node's own
    /// folders are in none, and a folder without flags gets none. With the
    /// Unix list; Windows has its own test below.
    #[cfg(unix)]
    #[test]
    fn the_config_wants_each_centers_folders() {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (home, work, other) = (root.join("home"), root.join("work"), root.join("other"));
        for p in [&home, &work, &other] {
            std::fs::create_dir_all(p).unwrap();
        }
        let paths = NodePaths::new(work.join("cfg"), root.join("state"));
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        std::fs::write(work.join("file.txt"), "x").unwrap();
        let folder = |p: &Path, a: &str| nerve_policy::config::Folder {
            path: p.display().to_string(),
            access: Access::parse(a).unwrap(),
        };
        let mut cfg = NodeConfig::default();
        for (name, folders) in [
            ("lab", vec![folder(&work, "rwx")]),
            ("home", vec![folder(&other, "r"), folder(&home, "")]),
        ] {
            cfg.centers.push(nerve_policy::CenterEntry {
                name: name.into(),
                url: String::new(),
                pin: None,
                center_id: String::new(),
                node_id: node(name),
                settings: Default::default(),
                paused: false,
                revoked: false,
                unknown: false,
                public_key: None,
                key_rotations: 0,
                pin_rotations: 0,
                old_pin: None,
                policy: nerve_policy::CenterPolicy {
                    folders,
                    ..Default::default()
                },
                capabilities: Vec::new(),
            });
        }
        let want = wanted(&cfg, &paths, &home, &Platform::Unix);
        let lab = container(&paths, &node("lab"));
        let home_c = container(&paths, &node("home"));
        // `work` holds the config folder: its other entries instead.
        assert!(
            want.contains(&Grant {
                container: lab.clone(),
                path: work.join("file.txt"),
                access: Access::ALL,
                id: None,
                unfinished: false,
                toward: Vec::new(),
                closed_at: None,
            }),
            "{want:?}"
        );
        assert!(
            !want.iter().any(|g| paths.config_dir.starts_with(&g.path)),
            "{want:?}"
        );
        assert_eq!(
            want.iter()
                .filter(|g| g.container == home_c)
                .collect::<Vec<_>>(),
            [&Grant {
                container: home_c.clone(),
                path: other.clone(),
                access: Access::parse("r").unwrap(),
                id: None,
                unfinished: false,
                toward: Vec::new(),
                closed_at: None,
            }]
        );
        // A node run by hand wants these; the installed service, whose
        // commands run as the command account in their containers, wants
        // them and one grant for that account per folder, with every flag
        // any pairing has there (#149).
        assert_eq!(wanted_on(None, &cfg, &paths, &home, &Platform::Unix), want);
        assert_eq!(
            wanted_on(Some(""), &cfg, &paths, &home, &Platform::Unix),
            want
        );
        let run = "S-1-5-21-1-2-3-1011";
        let on = wanted_on(Some(run), &cfg, &paths, &home, &Platform::Unix);
        assert_eq!(on[..want.len()], want[..]);
        let union = &on[want.len()..];
        assert!(!union.is_empty());
        for w in &want {
            let theirs: Vec<_> = union
                .iter()
                .filter(|g| same_path(&g.path, &w.path))
                .collect();
            assert_eq!(theirs.len(), 1, "{w:?}");
            let all =
                want.iter()
                    .filter(|o| same_path(&o.path, &w.path))
                    .fold(Access::NONE, |a, o| Access {
                        read: a.read || o.access.read,
                        write: a.write || o.access.write,
                        execute: a.execute || o.access.execute,
                    });
            assert_eq!(theirs[0].access, all, "{w:?}");
            assert_eq!(theirs[0].container, run);
        }
        assert!(is_account(run) && !is_account(&lab));
    }

    /// A center named `name` with these folders.
    /// The node id of the test pairing with the center `name`.
    fn node(name: &str) -> String {
        format!("node-{name}")
    }

    /// A folder without a flag inside a `w` folder is closed to that
    /// pairing's container: a grant of no flag, which denies it every
    /// right, whatever it inherits from the folder around (#149). One
    /// inside no granted folder needs none, and the command account gets no
    /// grant for a closed folder.
    #[test]
    fn a_folder_without_flags_inside_a_granted_one_is_closed() {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (work, secret, apart) = (
            root.join("work"),
            root.join("work/secret"),
            root.join("apart"),
        );
        for p in [&secret, &apart] {
            std::fs::create_dir_all(p).unwrap();
        }
        let paths = NodePaths::new(root.join("cfg"), root.join("state"));
        let mut cfg = NodeConfig::default();
        cfg.centers
            .push(center("lab", &[(&work, "w"), (&secret, ""), (&apart, "")]));
        cfg.centers.push(center("home", &[(&work, "r")]));
        let lab = container(&paths, &node("lab"));
        let want = wanted(&cfg, &paths, &root, &Platform::Unix);
        let closed: Vec<_> = want.iter().filter(|g| g.access == Access::NONE).collect();
        assert_eq!(closed.len(), 1, "{want:?}");
        assert_eq!(closed[0].path, secret);
        assert_eq!(closed[0].container, lab);
        let run = "S-1-5-21-1-2-3-1011";
        let on = wanted_on(Some(run), &cfg, &paths, &root, &Platform::Unix);
        assert!(
            !on.iter()
                .any(|g| g.container == run && same_path(&g.path, &secret)),
            "{on:?}"
        );
        // The account's grant on the folder both pairings have holds what
        // each has: `w` and `r`.
        let both: Vec<_> = on
            .iter()
            .filter(|g| g.container == run && same_path(&g.path, &work))
            .collect();
        assert_eq!(both.len(), 1, "{on:?}");
        assert_eq!(both[0].access, Access::parse("rw").unwrap());
    }

    /// A granted folder that holds a protected entry is split into its
    /// other entries, each with its flags; a closed folder among them, or
    /// one that holds the protected entry itself, takes none of them: no
    /// grant with a flag at or inside it, for the container or the command
    /// account.
    #[cfg(unix)]
    #[test]
    fn a_closed_folder_takes_no_flags_from_a_split_folder() {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let home = root.join("home");
        let work = root.join("work");
        for p in [
            home.join(".ssh"),
            home.join("pub"),
            home.join("private/deep"),
            work.join("deploy"),
            work.join("pub"),
            work.join("private/deep"),
        ] {
            std::fs::create_dir_all(p).unwrap();
        }
        std::fs::write(work.join("deploy/prod.key"), "").unwrap();
        std::fs::write(work.join("private/prod.key"), "").unwrap();
        let paths = NodePaths::new(root.join("cfg"), root.join("state"));
        let run = "S-1-5-21-1-2-3-1011";
        let cases: [(&Path, &str); 3] = [
            // The home holds `.ssh`.
            (&home, ""),
            // An extra protected path beside the closed folder.
            (&work, "deploy/prod.key"),
            // One inside it: the split would go down into it.
            (&work, "private/prod.key"),
        ];
        for (granted, extra) in cases {
            let private = granted.join("private");
            let mut lab = center("lab", &[(granted, "rw"), (&private, "")]);
            if !extra.is_empty() {
                lab.policy.protected.extra = vec![granted.join(extra).display().to_string()];
            }
            let mut cfg = NodeConfig::default();
            cfg.centers.push(lab);
            let want = wanted_on(Some(run), &cfg, &paths, &home, &Platform::Unix);
            assert!(
                want.iter()
                    .any(|g| g.path == granted.join("pub") && g.access != Access::NONE),
                "{extra}: split: {want:?}"
            );
            assert!(
                !want
                    .iter()
                    .any(|g| g.path.starts_with(&private) && g.access != Access::NONE),
                "{extra}: {want:?}"
            );
        }
        // Granted by another spelling of its place (a link of the owner's)
        // as well: closed wins.
        let private = work.join("private");
        std::os::unix::fs::symlink(&work, root.join("link")).unwrap();
        let mut cfg = NodeConfig::default();
        cfg.centers.push(center(
            "lab",
            &[
                (&work, "rw"),
                (&private, ""),
                (&root.join("link/private"), "r"),
            ],
        ));
        let want = wanted(&cfg, &paths, &home, &Platform::Unix);
        let at: Vec<_> = want.iter().filter(|g| g.path == private).collect();
        assert_eq!(at.len(), 1, "{want:?}");
        assert_eq!(at[0].access, Access::NONE, "{want:?}");
    }

    /// A closed folder's denying entry is held back where a file below it
    /// has another name (a local `git clone` links its objects), as any
    /// change of a folder commands write in: the file's list would be
    /// worked out anew from the closed folder's, wherever its other name
    /// is. One that does not go on (held, refused, failed, or not on any
    /// more) stops its container's commands, since the folder keeps the
    /// rights of the granted folder around it; other containers run.
    #[test]
    fn a_closed_folder_that_is_not_closed_stops_its_containers_commands() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/a");
        f.make("/w/a/closed");
        f.make("/w/b");
        f.linked.push("/w/a/closed/.git/objects/x".into());
        let (a, closed) = (grant("c1", "/w/a", "rw"), grant("c1", "/w/a/closed", ""));
        let b = grant("c2", "/w/b", "rw");
        let want = [a.clone(), closed.clone(), b.clone()];
        let s = sync(&file, &want, &mut f);
        assert!(f.on("/w/a/closed").is_empty(), "{:?}", f.all());
        assert!(s.errors.iter().any(|e| e.contains("hard links")), "{s:?}");
        assert!(
            s.refusal("c1").is_some() && s.refusal("c2").is_none(),
            "{s:?}"
        );
        f.linked.clear();
        let s = sync(&file, &want, &mut f);
        assert_eq!(f.on("/w/a/closed"), [("c1".to_string(), Access::NONE)]);
        assert!(s.unclosed.is_empty() && s.refusal("c1").is_none(), "{s:?}");

        // Its entry cannot be put on again: the commands of c1 stop.
        f.rm("/w/a/closed");
        f.make("/w/a/closed");
        f.locked.push("/w/a/closed".into());
        let s = sync(&file, &want, &mut f);
        let why = s.refusal("c1").expect("c1's commands stop");
        assert!(
            why.contains("/w/a/closed") && why.contains("could not close"),
            "{why}"
        );
        assert!(s.refusal("c2").is_none(), "{s:?}");

        // Nor where a command put something else in its place.
        f.locked.clear();
        f.foreign.push("/w/a/closed".into());
        let s = sync(&file, &want, &mut f);
        assert!(s.refusal("c1").is_some(), "{s:?}");
        f.foreign.clear();
        let s = sync(&file, &want, &mut f);
        assert!(s.refusal("c1").is_none(), "{s:?}");
        assert_eq!(f.on("/w/a/closed"), [("c1".to_string(), Access::NONE)]);

        // Nothing there: nothing to close.
        f.rm("/w/a/closed");
        let s = sync(&file, &want, &mut f);
        assert!(s.refusal("c1").is_none(), "{s:?}");
    }

    /// A command renames a closed folder within the folder around it, whose
    /// rights let it, and makes a new one in its place: the denying entry
    /// stays on the renamed folder, recorded where it is now, and the new
    /// one gets its own. Once the owner opens the place, or on uninstall,
    /// both come off.
    #[test]
    fn a_moved_closed_folder_stays_closed() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/a");
        f.make("/w/a/secret");
        let (a, secret) = (grant("c1", "/w/a", "rw"), grant("c1", "/w/a/secret", ""));
        let want = [a.clone(), secret.clone()];
        sync(&file, &want, &mut f);
        let none = || [("c1".to_string(), Access::NONE)];

        f.mv("/w/a/secret", "/w/a/renamed");
        f.make("/w/a/secret");
        let s = sync(&file, &want, &mut f);
        assert!(s.errors.is_empty() && s.refusal("c1").is_none(), "{s:?}");
        assert_eq!(f.on("/w/a/renamed"), none());
        assert_eq!(f.on("/w/a/secret"), none());
        let rec = read_record(&file).unwrap();
        let moved = rec
            .iter()
            .find(|g| g.path == Path::new("/w/a/renamed"))
            .expect("recorded where it is now");
        assert_eq!(moved.closed_at.as_deref(), Some(Path::new("/w/a/secret")));
        // It stays, also moved again, and nothing changes once it is in
        // line.
        f.mv("/w/a/renamed", "/w/a/again");
        sync(&file, &want, &mut f);
        f.sets = 0;
        let s = sync(&file, &want, &mut f);
        assert_eq!(f.sets, 0, "{:?}", f.all());
        assert!(s.refusal("c1").is_none(), "{s:?}");
        assert_eq!(f.on("/w/a/again"), none());

        // Opened by the owner: both come off.
        let s = sync(&file, std::slice::from_ref(&a), &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        assert_eq!(f.all(), std::slice::from_ref(&a));

        // Uninstall takes a moved one off too.
        sync(&file, &want, &mut f);
        f.mv("/w/a/secret", "/w/a/other");
        sync(&file, &want, &mut f);
        assert_eq!(f.on("/w/a/other"), none());
        sync(&file, &[], &mut f);
        assert!(f.all().is_empty(), "{:?}", f.all());
    }

    /// A command renames a closed folder and puts a link at its path, to a
    /// folder it may write: the closed grant stays at the path as given,
    /// not where the link leads, so the renamed folder keeps its denying
    /// entry, and the one at the link is refused, which stops the
    /// container's commands until the link is gone. Also where the owner
    /// named the granted folder through a link of their own: that one is
    /// followed, the command's is not.
    #[cfg(unix)]
    #[test]
    fn a_link_at_a_closed_folders_path_does_not_move_its_entry() {
        // The last two only rename the closed folder: with the granted
        // folder named through a link of the owner's, the closed one is
        // still found where that link leads, gone as it is.
        for (owners_link, put_link) in [(false, true), (true, true), (true, false), (false, false)]
        {
            let d = tempfile::tempdir().unwrap();
            let root = std::fs::canonicalize(d.path()).unwrap();
            let work = root.join("work");
            let (secret, renamed, decoy) = (
                work.join("secret"),
                work.join("renamed"),
                work.join("decoy"),
            );
            std::fs::create_dir_all(&secret).unwrap();
            let given = if owners_link {
                std::os::unix::fs::symlink(&work, root.join("link")).unwrap();
                root.join("link")
            } else {
                work.clone()
            };
            let paths = NodePaths::new(root.join("cfg"), root.join("state"));
            let mut cfg = NodeConfig::default();
            cfg.centers.push(center(
                "lab",
                &[(&given, "rw"), (&given.join("secret"), "")],
            ));
            let lab = container(&paths, &node("lab"));
            let want = || wanted(&cfg, &paths, &root, &Platform::Unix);
            let s = |p: &Path| p.display().to_string();
            let file = root.join("grants.json");
            let mut f = Fake::default();
            f.make(&s(&work));
            f.make(&s(&secret));
            let synced = sync(&file, &want(), &mut f);
            assert!(synced.refusal(&lab).is_none(), "{synced:?}");
            let none = || [(lab.clone(), Access::NONE)];
            assert_eq!(f.on(&s(&secret)), none(), "{:?}", f.all());

            std::fs::rename(&secret, &renamed).unwrap();
            f.mv(&s(&secret), &s(&renamed));
            if put_link {
                std::fs::create_dir(&decoy).unwrap();
                std::os::unix::fs::symlink(&decoy, &secret).unwrap();
                f.make(&s(&decoy));
                f.make(&s(&secret));
                f.foreign.push(secret.clone());
            }
            let now = want();
            let closed: Vec<_> = now.iter().filter(|g| g.access == Access::NONE).collect();
            assert_eq!(closed.len(), 1, "{owners_link} {put_link}: {now:?}");
            assert_eq!(closed[0].path, secret, "{owners_link} {put_link}: {now:?}");
            for _ in 0..2 {
                let synced = sync(&file, &now, &mut f);
                assert_eq!(f.on(&s(&renamed)), none(), "{:?}", f.all());
                assert!(f.on(&s(&decoy)).is_empty(), "{:?}", f.all());
                assert_eq!(synced.refusal(&lab).is_some(), put_link, "{synced:?}");
            }
        }
    }

    /// A command moves a closed folder to a place its own container is
    /// granted, one it emptied or one not made yet, or above one: the grant
    /// there would take the denying entry's place, or come before it, and
    /// open what the owner closed. It does not go on, the denying entry
    /// stays, and the container's commands stop until the folder is moved
    /// back or the owner opens it.
    #[test]
    fn a_closed_folder_moved_onto_a_granted_place_stays_closed() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/a");
        f.make("/w/a/secret");
        f.make("/w/a/bin");
        let (a, secret) = (grant("c1", "/w/a", "rw"), grant("c1", "/w/a/secret", ""));
        let (bin, out) = (
            grant("c1", "/w/a/bin", "rwx"),
            grant("c1", "/w/a/out", "rwx"),
        );
        let other = grant("c2", "/w/b", "rw");
        f.make("/w/b");
        let want = [a.clone(), secret.clone(), bin.clone(), out.clone(), other];
        let s = sync(&file, &want, &mut f);
        assert!(s.refusal("c1").is_none(), "{s:?}");
        let none = || [("c1".to_string(), Access::NONE)];

        for place in ["/w/a/bin", "/w/a/out"] {
            if f.id(Path::new(place)).is_some() {
                f.rm(place);
            }
            f.mv("/w/a/secret", place);
            for _ in 0..2 {
                let s = sync(&file, &want, &mut f);
                assert_eq!(f.on(place), none(), "{place}: {:?}", f.all());
                let why = s.refusal("c1").expect("c1's commands stop");
                assert!(why.contains("moved it to"), "{why}");
                assert!(s.refusal("c2").is_none(), "{s:?}");
            }
            // Moved back: it is closed where it was, and the place is
            // granted again once there is a folder.
            f.mv(place, "/w/a/secret");
            let s = sync(&file, &want, &mut f);
            assert!(s.refusal("c1").is_none(), "{s:?}");
            assert_eq!(f.on("/w/a/secret"), none());
        }

        // Nor below that place: an allowing entry there comes before the
        // denying one it inherits, and would open that part of the closed
        // folder.
        {
            let file = d.path().join("below.json");
            let mut f = Fake::default();
            f.make("/w/a");
            f.make("/w/a/secret");
            f.make("/w/a/secret/bin");
            let below = grant("c1", "/w/a/out/bin", "rwx");
            let want = [a.clone(), secret.clone(), below.clone()];
            let s = sync(&file, &want, &mut f);
            assert!(s.refusal("c1").is_none(), "{s:?}");
            f.mv("/w/a/secret", "/w/a/out");
            f.mv("/w/a/secret/bin", "/w/a/out/bin");
            for _ in 0..2 {
                let s = sync(&file, &want, &mut f);
                assert_eq!(f.on("/w/a/out"), none(), "{:?}", f.all());
                assert!(f.on("/w/a/out/bin").is_empty(), "{:?}", f.all());
                let why = s.refusal("c1").expect("c1's commands stop");
                assert!(why.contains("moved it to"), "{why}");
            }
            // Moved back, the grant goes on once there is a folder.
            f.mv("/w/a/out", "/w/a/secret");
            f.mv("/w/a/out/bin", "/w/a/secret/bin");
            f.make("/w/a/out");
            f.make("/w/a/out/bin");
            let s = sync(&file, &want, &mut f);
            assert!(s.refusal("c1").is_none(), "{s:?}");
            assert_eq!(f.on("/w/a/secret"), none());
            assert_eq!(f.on("/w/a/out/bin"), [("c1".to_string(), below.access)]);
        }

        // Opened by the owner where it was moved: the grant goes on there.
        f.mv("/w/a/secret", "/w/a/out");
        sync(&file, &want, &mut f);
        let opened = [a.clone(), bin.clone(), out.clone()];
        let s = sync(&file, &opened, &mut f);
        assert!(s.errors.is_empty() && s.refusal("c1").is_none(), "{s:?}");
        assert_eq!(f.on("/w/a/out"), [("c1".to_string(), out.access)]);
    }

    fn center(name: &str, folders: &[(&Path, &str)]) -> nerve_policy::CenterEntry {
        nerve_policy::CenterEntry {
            name: name.into(),
            url: String::new(),
            pin: None,
            center_id: String::new(),
            node_id: node(name),
            settings: Default::default(),
            paused: false,
            revoked: false,
            unknown: false,
            public_key: None,
            key_rotations: 0,
            pin_rotations: 0,
            old_pin: None,
            policy: nerve_policy::CenterPolicy {
                folders: folders
                    .iter()
                    .map(|(p, a)| nerve_policy::config::Folder {
                        path: p.display().to_string(),
                        access: Access::parse(a).unwrap(),
                    })
                    .collect(),
                ..Default::default()
            },
            capabilities: Vec::new(),
        }
    }

    /// A folder granted inside a folder that commands may write (of its own
    /// center or another one) that a command replaced by a link to another
    /// folder gets no grant there: the folder it leads to keeps its own
    /// flags and gets none of the nested folder's. The link put there
    /// between `wanted` and the change is the Windows `set`'s to refuse
    /// (`a_junction_in_place_of_a_granted_folder_gets_no_grant`). A link the
    /// owner put above the writable folder is followed.
    #[cfg(unix)]
    #[test]
    fn a_link_put_in_place_of_a_nested_folder_gets_no_grant() {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (real_work, outbox) = (root.join("real-work"), root.join("outbox"));
        let work = root.join("work");
        let bin = work.join("bin");
        std::fs::create_dir_all(real_work.join("bin")).unwrap();
        std::fs::create_dir_all(&outbox).unwrap();
        // The owner's own link to the work folder.
        std::os::unix::fs::symlink(&real_work, &work).unwrap();
        let paths = NodePaths::new(root.join("cfg"), root.join("state"));
        let mut cfg = NodeConfig::default();
        cfg.centers.push(center(
            "lab",
            &[(&work, "rw"), (&bin, "rwx"), (&outbox, "w")],
        ));
        cfg.centers.push(center("home", &[(&bin, "r")]));
        let (lab, home) = (
            container(&paths, &node("lab")),
            container(&paths, &node("home")),
        );
        let g = |c: &str, p: &Path, a: &str| Grant {
            container: c.into(),
            path: p.into(),
            access: Access::parse(a).unwrap(),
            id: None,
            unfinished: false,
            toward: Vec::new(),
            closed_at: None,
        };
        let sorted = |mut v: Vec<Grant>| {
            v.sort_by(|a, b| (&a.container, &a.path).cmp(&(&b.container, &b.path)));
            v
        };
        let want = wanted(&cfg, &paths, &root, &Platform::Unix);
        assert_eq!(
            sorted(want.clone()),
            sorted(vec![
                g(&lab, &real_work, "rw"),
                g(&lab, &real_work.join("bin"), "rwx"),
                g(&lab, &outbox, "w"),
                g(&home, &real_work.join("bin"), "r"),
            ])
        );

        std::fs::remove_dir(real_work.join("bin")).unwrap();
        std::os::unix::fs::symlink(&outbox, real_work.join("bin")).unwrap();
        let swapped = wanted(&cfg, &paths, &root, &Platform::Unix);
        assert_eq!(
            sorted(swapped.clone()),
            sorted(vec![g(&lab, &real_work, "rw"), g(&lab, &outbox, "w")])
        );
        // The sync puts nothing more on the outbox.
        let file = root.join("grants.json");
        let mut f = Fake::default();
        for p in [&real_work, &real_work.join("bin"), &outbox] {
            f.make(&p.display().to_string());
        }
        sync(&file, &want, &mut f);
        let s = sync(&file, &swapped, &mut f);
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        assert_eq!(
            f.on(&outbox.display().to_string()),
            [(lab.clone(), Access::parse("w").unwrap())]
        );
    }

    /// The writable folder and the nested folder are spelled differently:
    /// the owner gives the write folder through a link of their own and the
    /// nested folder by its real path. A command's link at the nested
    /// folder is still caught, because the boundary is judged by resolved
    /// places, not by the spelling (`exec::led_away`).
    #[cfg(unix)]
    #[test]
    fn a_junction_with_two_spellings_gets_no_grant() {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (real_work, outbox) = (root.join("real-work"), root.join("outbox"));
        // The owner gives the write folder through their own link `work`,
        // and the folder inside it by its real path `real-work/bin`.
        let work = root.join("work");
        let bin = real_work.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&outbox).unwrap();
        std::os::unix::fs::symlink(&real_work, &work).unwrap();
        let paths = NodePaths::new(root.join("cfg"), root.join("state"));
        let mut cfg = NodeConfig::default();
        cfg.centers.push(center(
            "lab",
            &[(&work, "rw"), (&bin, "rwx"), (&outbox, "w")],
        ));
        let lab = container(&paths, &node("lab"));
        let g = |p: &Path, a: &str| Grant {
            container: lab.clone(),
            path: p.into(),
            access: Access::parse(a).unwrap(),
            id: None,
            unfinished: false,
            toward: Vec::new(),
            closed_at: None,
        };
        let sorted = |mut v: Vec<Grant>| {
            v.sort_by(|a, b| a.path.cmp(&b.path));
            v
        };
        let want = wanted(&cfg, &paths, &root, &Platform::Unix);
        assert_eq!(
            sorted(want.clone()),
            sorted(vec![g(&real_work, "rw"), g(&bin, "rwx"), g(&outbox, "w"),])
        );

        // A command swaps the real nested folder for a link to the outbox.
        std::fs::remove_dir(&bin).unwrap();
        std::os::unix::fs::symlink(&outbox, &bin).unwrap();
        let swapped = wanted(&cfg, &paths, &root, &Platform::Unix);
        assert_eq!(
            sorted(swapped),
            sorted(vec![g(&real_work, "rw"), g(&outbox, "w")]),
            "the outbox must not gain the nested folder's flags"
        );
    }

    /// The same on Windows (#82): the owner gives the write folder through a
    /// junction of their own and the folder inside it by its real path, in
    /// another case. A command's junction in place of the nested folder is
    /// still caught, because the boundary is judged by resolved places
    /// (`exec::led_away`): the outbox does not gain the nested folder's
    /// flags.
    #[cfg(windows)]
    #[test]
    fn a_junction_with_two_spellings_gets_no_grant_on_windows() {
        use nerve_sandbox::acl::same_path;
        let d = tempfile::tempdir().unwrap();
        let root = canonical(d.path());
        let (real_work, outbox) = (root.join("real-work"), root.join("outbox"));
        let work = root.join("work");
        let bin = real_work.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&outbox).unwrap();
        junction(&work, &real_work);
        let spelled = root.join("REAL-WORK").join("BIN");
        let paths = NodePaths::new(root.join("cfg"), root.join("state"));
        let mut cfg = NodeConfig::default();
        cfg.centers.push(center(
            "lab",
            &[(&work, "rw"), (&spelled, "rwx"), (&outbox, "w")],
        ));
        let platform = crate::paths::platform();
        let on = |want: &[Grant], p: &Path| -> Vec<String> {
            let p = p.display().to_string();
            want.iter()
                .filter(|g| same_path(&g.path.display().to_string(), &p))
                .map(|g| g.access.to_string())
                .collect()
        };
        let want = wanted(&cfg, &paths, &root, &platform);
        assert_eq!(on(&want, &bin), ["rwx"], "{want:?}");
        assert_eq!(on(&want, &outbox), ["w"], "{want:?}");

        // A command swaps the real nested folder for a junction to the
        // outbox.
        std::fs::remove_dir(&bin).unwrap();
        junction(&bin, &outbox);
        let swapped = wanted(&cfg, &paths, &root, &platform);
        assert_eq!(
            on(&swapped, &outbox),
            ["w"],
            "the outbox must not gain the nested folder's flags: {swapped:?}"
        );
        assert!(on(&swapped, &bin).is_empty(), "{swapped:?}");
    }

    /// Issue #77: a link a command put in place of a nested folder while the
    /// outer folder had `w` gets no grant after that `w` is gone (the folder
    /// narrowed to `r`, or its pairing removed), when the node recorded the
    /// nested folder at its real place (`folder add`). Without the record
    /// the link is followed, and the folder it leads to gets the grant.
    #[cfg(unix)]
    #[test]
    fn a_link_put_in_place_of_a_recorded_folder_gets_no_grant_once_the_write_is_gone() {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (work, outbox) = (root.join("work"), root.join("outbox"));
        let bin = work.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&outbox).unwrap();
        let paths = NodePaths::new(root.join("cfg"), root.join("state"));
        let (lab, home) = (
            container(&paths, &node("lab")),
            container(&paths, &node("home")),
        );
        let mut cfg = NodeConfig::default();
        cfg.centers
            .push(center("lab", &[(&work, "rw"), (&bin, "rwx")]));
        cfg.centers.push(center("home", &[(&bin, "r")]));
        for c in &mut cfg.centers {
            c.policy.set_placed(&bin.display().to_string(), true);
        }
        let reaches = |want: &[Grant], c: &str, p: &Path| {
            want.iter().any(|g| g.container == c && within(&g.path, p))
        };
        let want = wanted(&cfg, &paths, &root, &Platform::Unix);
        assert!(
            reaches(&want, &lab, &bin) && reaches(&want, &home, &bin),
            "{want:?}"
        );

        // A command of `lab` replaces `bin` by a link to the outbox.
        std::fs::remove_dir(&bin).unwrap();
        std::os::unix::fs::symlink(&outbox, &bin).unwrap();
        let now = wanted(&cfg, &paths, &root, &Platform::Unix);
        assert!(
            !reaches(&now, &lab, &outbox) && !reaches(&now, &home, &outbox),
            "{now:?}"
        );

        // `lab` has `r` on `work` only now: nothing shows the link any more,
        // and the record still keeps the outbox clear.
        cfg.centers[0].policy.folders[0].access = Access::parse("r").unwrap();
        let narrowed = wanted(&cfg, &paths, &root, &Platform::Unix);
        assert!(!reaches(&narrowed, &lab, &outbox), "{narrowed:?}");
        assert!(!reaches(&narrowed, &home, &outbox), "{narrowed:?}");
        assert!(reaches(&narrowed, &lab, &work), "{narrowed:?}");
        // The pairing is removed: `home` keeps clear of the outbox too.
        cfg.centers.remove(0);
        let alone = wanted(&cfg, &paths, &root, &Platform::Unix);
        assert!(!reaches(&alone, &home, &outbox), "{alone:?}");

        // Without the record the link is followed once `w` is gone.
        cfg.centers[0].policy.places.clear();
        let loose = wanted(&cfg, &paths, &root, &Platform::Unix);
        assert!(reaches(&loose, &home, &outbox), "{loose:?}");
    }

    /// The access list of `path` as icacls prints it.
    #[cfg(windows)]
    fn icacls(path: &Path) -> String {
        let o = std::process::Command::new("icacls")
            .arg(path)
            .output()
            .unwrap();
        String::from_utf8_lossy(&o.stdout).into_owned()
    }

    /// On Windows: a grant lands on the folder for the container's SID, and
    /// `remove_all` (uninstall) takes it off and leaves the folder's access
    /// list as it was.
    #[cfg(windows)]
    #[test]
    fn remove_all_leaves_the_folders_as_they_were() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("config"), d.path().join("state"));
        let work = d.path().join("work");
        std::fs::create_dir_all(work.join("sub")).unwrap();
        let (before, root) = (icacls(&work.join("sub")), icacls(&work));
        let want = [Grant {
            container: container(&paths, &node("lab")),
            path: work.clone(),
            access: Access::ALL,
            id: None,
            unfinished: false,
            toward: Vec::new(),
            closed_at: None,
        }];
        let s = windows_sync(&paths, &want, &mut |_| {});
        assert!(s.errors.is_empty(), "{s:?}");
        // Inherited below the folder too.
        assert!(
            icacls(&work.join("sub")).contains("S-1-15-2-"),
            "{}",
            icacls(&work)
        );
        let s = remove_all(&paths, &[node("lab")], &mut |_| {});
        assert!(s.errors.is_empty(), "{s:?}");
        assert_eq!(s.removed, 1);
        assert!(!icacls(&work).contains("S-1-15-2-"), "{}", icacls(&work));
        assert_eq!(icacls(&work), root, "the inherited entries stay");
        assert_eq!(icacls(&work.join("sub")), before);
        assert!(read_record(&record_file(&paths)).unwrap().is_empty());
    }

    /// The canonical form of a temporary folder, as the policy compares
    /// paths: long names, no `\\?\`.
    #[cfg(windows)]
    fn canonical(p: &Path) -> PathBuf {
        PathBuf::from(nerve_policy::paths::win::strip_verbatim(
            &std::fs::canonicalize(p).unwrap().display().to_string(),
        ))
    }

    /// Makes `link` a junction to `to`.
    #[cfg(windows)]
    fn junction(link: &Path, to: &Path) {
        let o = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(to)
            .output()
            .unwrap();
        assert!(o.status.success(), "{o:?}");
    }

    /// Whether `path` carries exactly `container`'s grant of `access`.
    #[cfg(windows)]
    fn carries(path: &Path, container: &str, access: &str) -> bool {
        let a = Access::parse(access).unwrap();
        let m = nerve_sandbox::acl::masks(a.read, a.write, a.execute);
        nerve_sandbox::appcontainer::look(path, container, m)
            .unwrap()
            .1
    }

    /// On Windows: a project whose `target` holds links between names of
    /// its own, as cargo builds them, gets its grant, changes it and loses
    /// it. A link from `target` to a file outside the project (also one
    /// below a folder named `target` there) stops a change that would reach
    /// that file, and its list stays as it was; a take-off that leaves the
    /// file's list as it is goes through. After a move, a sync gives no pass
    /// for `target` (it finds a granted folder moved), so cargo's own links
    /// stop the take-off where the project is now too, until `target` is
    /// clean of links.
    #[cfg(windows)]
    #[test]
    fn a_built_project_keeps_working() {
        let d = tempfile::tempdir().unwrap();
        let root = canonical(d.path());
        let paths = NodePaths::new(root.join("config"), root.join("state"));
        let (proj, proj2, outside) = (root.join("proj"), root.join("proj2"), root.join("outside"));
        let link = |from: &str, to: &str| {
            let (from, to) = (proj.join(from), proj.join(to));
            for p in [&from, &to] {
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            }
            std::fs::write(&from, "x").unwrap();
            std::fs::hard_link(&from, &to).unwrap();
        };
        link(
            "target\\debug\\demo.exe",
            "target\\debug\\deps\\demo-0123.exe",
        );
        std::fs::create_dir_all(&outside).unwrap();
        let lab = container(&paths, &node("lab"));
        let platform = crate::paths::platform();
        let config = |flags: Option<&str>| {
            let mut cfg = NodeConfig::default();
            cfg.centers.push(match flags {
                Some(a) => center("lab", &[(&proj, a)]),
                None => center("lab", &[]),
            });
            cfg
        };
        let want = |flags: Option<&str>| wanted(&config(flags), &paths, &root, &platform);

        // Put on and changed.
        let s = windows_sync(&paths, &want(Some("rw")), &mut |_| {});
        assert!(s.errors.is_empty(), "{s:?}");
        assert!(carries(&proj, &lab, "rw"), "{}", icacls(&proj));
        let s = windows_sync(&paths, &want(Some("rwx")), &mut |_| {});
        assert!(s.errors.is_empty(), "{s:?}");
        assert!(carries(&proj, &lab, "rwx"), "{}", icacls(&proj));

        // A link from target to a file outside: a change that would reach
        // it is refused.
        let secret = outside.join("target\\secret.txt");
        std::fs::create_dir_all(secret.parent().unwrap()).unwrap();
        std::fs::write(&secret, "secret").unwrap();
        // Its permissions marked inherited, as Windows keeps them in a
        // user's folders. A test's temporary folder has them unmarked, and a
        // file whose unmarked permissions differ from what the folder it is
        // linked into gives keeps them as its own: the change would not
        // reach it, and nothing would be refused.
        let marks = "nerve.test.marks";
        let m = nerve_sandbox::acl::masks(true, false, false);
        nerve_sandbox::appcontainer::set(&outside, marks, Some(m), false).unwrap();
        nerve_sandbox::appcontainer::set(&outside, marks, None, false).unwrap();
        std::fs::hard_link(&secret, proj.join("target\\debug\\s")).unwrap();
        let before = icacls(&secret);
        let refused = |s: &Synced| {
            s.errors.len() == 1
                && s.errors[0].contains("target\\debug\\s")
                && s.errors[0].contains("hard links")
        };
        let s = windows_sync(&paths, &want(Some("rw")), &mut |_| {});
        assert!(refused(&s), "{s:?}");
        assert!(s.refusal(&lab).is_some(), "{s:?}");
        assert!(carries(&proj, &lab, "rwx"), "{}", icacls(&proj));
        // Taken off: the file gets from `target` what it has from the
        // folder outside, so its list stays, and nothing stops the take-off.
        let s = windows_sync(&paths, &want(None), &mut |_| {});
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        assert_eq!(s.removed, 1, "{s:?}");
        assert!(!carries(&proj, &lab, "rwx"), "{}", icacls(&proj));
        assert_eq!(icacls(&secret), before);
        // Put on again, it would reach the file: refused.
        let s = windows_sync(&paths, &want(Some("rwx")), &mut |_| {});
        assert!(refused(&s), "{s:?}");
        assert!(!carries(&proj, &lab, "rwx"), "{}", icacls(&proj));
        assert_eq!(icacls(&secret), before);
        std::fs::remove_file(proj.join("target\\debug\\s")).unwrap();
        let s = windows_sync(&paths, &want(Some("rwx")), &mut |_| {});
        assert!(s.errors.is_empty(), "{s:?}");
        assert!(carries(&proj, &lab, "rwx"), "{}", icacls(&proj));

        // Moved: no pass, so cargo's own link stops the take-off where the
        // project is now.
        std::fs::rename(&proj, &proj2).unwrap();
        let cargo_refused = |s: &Synced| {
            s.errors.len() == 1
                && s.errors[0].contains("hard links")
                && (s.errors[0].contains("target\\debug\\demo.exe")
                    || s.errors[0].contains("target\\debug\\deps\\demo-0123.exe"))
        };
        let s = windows_sync(&paths, &want(Some("rwx")), &mut |_| {});
        assert!(cargo_refused(&s), "{s:?}");
        assert!(s.refusal(&lab).is_some(), "{s:?}");
        assert!(carries(&proj2, &lab, "rwx"), "{}", icacls(&proj2));
        assert_eq!(icacls(&secret), before);

        // Cleaned of cargo's links (as `cargo clean` does).
        for f in [
            "target\\debug\\demo.exe",
            "target\\debug\\deps\\demo-0123.exe",
        ] {
            std::fs::remove_file(proj2.join(f)).unwrap();
        }

        // Without any link, the moved project loses its grant.
        let s = windows_sync(&paths, &want(Some("rwx")), &mut |_| {});
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        assert_eq!(s.removed, 1, "{s:?}");
        assert!(!carries(&proj2, &lab, "rwx"), "{}", icacls(&proj2));

        // Back in place: put on again, then taken off.
        std::fs::rename(&proj2, &proj).unwrap();
        let s = windows_sync(&paths, &want(Some("rwx")), &mut |_| {});
        assert!(s.errors.is_empty(), "{s:?}");
        assert!(carries(&proj, &lab, "rwx"), "{}", icacls(&proj));
        let s = windows_sync(&paths, &want(None), &mut |_| {});
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        assert_eq!(s.removed, 1, "{s:?}");
        let s = remove_all(&paths, &[node("lab")], &mut |_| {});
        assert!(s.errors.is_empty(), "{s:?}");
        for p in [&proj, &secret] {
            assert!(!icacls(p).contains("S-1-15-2-"), "{}", icacls(p));
        }
    }

    /// On Windows: a folder inside a writable one, configured in another
    /// case than its name on disk, is the same place (NTFS ignores case),
    /// so it gets its grant and is not taken for a link.
    #[cfg(windows)]
    #[test]
    fn a_folder_spelled_in_another_case_gets_its_grant() {
        let d = tempfile::tempdir().unwrap();
        let root = canonical(d.path());
        let paths = NodePaths::new(root.join("config"), root.join("state"));
        let work = root.join("work");
        std::fs::create_dir_all(work.join("bin")).unwrap();
        let mut cfg = NodeConfig::default();
        cfg.centers
            .push(center("lab", &[(&work, "rw"), (&work.join("BIN"), "rwx")]));
        let want = wanted(&cfg, &paths, &root, &crate::paths::platform());
        assert!(
            want.iter()
                .any(|g| within(&g.path, &work.join("bin")) && g.access == Access::ALL),
            "{want:?}"
        );
    }

    /// On Windows: a folder granted inside a folder with `w` that a command
    /// replaced by a junction to another folder gets no grant, and the
    /// folder it leads to keeps its own flags: `wanted` leaves it out when
    /// the junction is there already, and `set` refuses it when the junction
    /// comes between `wanted` and the change. A plain folder there again
    /// gets it.
    #[cfg(windows)]
    #[test]
    fn a_junction_in_place_of_a_granted_folder_gets_no_grant() {
        let d = tempfile::tempdir().unwrap();
        let root = canonical(d.path());
        let paths = NodePaths::new(root.join("config"), root.join("state"));
        let (work, outbox) = (root.join("work"), root.join("outbox"));
        let bin = work.join("bin");
        for p in [&bin, &outbox] {
            std::fs::create_dir_all(p).unwrap();
        }
        let mut cfg = NodeConfig::default();
        cfg.centers.push(center(
            "lab",
            &[(&work, "rw"), (&bin, "rwx"), (&outbox, "w")],
        ));
        let lab = container(&paths, &node("lab"));
        let platform = crate::paths::platform();
        let want = wanted(&cfg, &paths, &root, &platform);
        assert_eq!(want.len(), 3, "{want:?}");
        let s = windows_sync(&paths, &want, &mut |_| {});
        assert!(s.errors.is_empty(), "{s:?}");
        std::fs::remove_dir(&bin).unwrap();
        junction(&bin, &outbox);

        let now = wanted(&cfg, &paths, &root, &platform);
        assert!(
            now.iter()
                .all(|g| !within(&g.path, &bin) && g.access != Access::ALL),
            "{now:?}"
        );
        let s = windows_sync(&paths, &now, &mut |_| {});
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        assert!(carries(&outbox, &lab, "w"), "{}", icacls(&outbox));

        let s = windows_sync(&paths, &want, &mut |_| {});
        assert_eq!(s.errors.len(), 1, "{s:?}");
        assert!(s.errors[0].contains("junction"), "{s:?}");
        assert!(carries(&outbox, &lab, "w"), "{}", icacls(&outbox));

        std::fs::remove_dir(&bin).unwrap();
        std::fs::create_dir(&bin).unwrap();
        let s = windows_sync(&paths, &wanted(&cfg, &paths, &root, &platform), &mut |_| {});
        assert!(s.errors.is_empty(), "{s:?}");
        assert!(carries(&bin, &lab, "rwx"), "{}", icacls(&bin));
        let s = remove_all(&paths, &[node("lab")], &mut |_| {});
        assert!(s.errors.is_empty(), "{s:?}");
    }

    /// On Windows, issue #77: a junction a command made in place of a granted
    /// folder while the outer folder had `w` gets no grant after that `w` is
    /// taken off, when the node recorded the folder at its real place; the
    /// folder the junction leads to keeps its own list. A plain folder there
    /// again gets its grant.
    #[cfg(windows)]
    #[test]
    fn a_junction_in_place_of_a_recorded_folder_gets_no_grant_once_the_write_is_gone() {
        let d = tempfile::tempdir().unwrap();
        let root = canonical(d.path());
        let paths = NodePaths::new(root.join("config"), root.join("state"));
        let (work, outbox) = (root.join("work"), root.join("outbox"));
        let bin = work.join("bin");
        for p in [&bin, &outbox] {
            std::fs::create_dir_all(p).unwrap();
        }
        let mut cfg = NodeConfig::default();
        cfg.centers
            .push(center("lab", &[(&work, "rw"), (&bin, "rwx")]));
        cfg.centers[0]
            .policy
            .set_placed(&bin.display().to_string(), true);
        let lab = container(&paths, &node("lab"));
        let platform = crate::paths::platform();
        let s = windows_sync(&paths, &wanted(&cfg, &paths, &root, &platform), &mut |_| {});
        assert!(s.errors.is_empty(), "{s:?}");
        assert!(carries(&bin, &lab, "rwx"), "{}", icacls(&bin));

        // A command replaces `bin` by a junction to the outbox, and `w` is
        // taken off `work`.
        std::fs::remove_dir(&bin).unwrap();
        junction(&bin, &outbox);
        cfg.centers[0].policy.folders[0].access = Access::parse("r").unwrap();
        let now = wanted(&cfg, &paths, &root, &platform);
        assert!(now.iter().all(|g| !within(&g.path, &outbox)), "{now:?}");
        let s = windows_sync(&paths, &now, &mut |_| {});
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        assert!(
            !icacls(&outbox).contains("S-1-15-2-"),
            "{}",
            icacls(&outbox)
        );
        // Without the record the junction is followed.
        cfg.centers[0].policy.places.clear();
        let loose = wanted(&cfg, &paths, &root, &platform);
        assert!(loose.iter().any(|g| within(&g.path, &outbox)), "{loose:?}");

        // A plain folder at the recorded place gets its grant again.
        cfg.centers[0]
            .policy
            .set_placed(&bin.display().to_string(), true);
        std::fs::remove_dir(&bin).unwrap();
        std::fs::create_dir(&bin).unwrap();
        let s = windows_sync(&paths, &wanted(&cfg, &paths, &root, &platform), &mut |_| {});
        assert!(s.errors.is_empty(), "{s:?}");
        assert!(carries(&bin, &lab, "rwx"), "{}", icacls(&bin));
        let s = remove_all(&paths, &[node("lab")], &mut |_| {});
        assert!(s.errors.is_empty(), "{s:?}");
    }

    /// On Windows: a granted folder that was renamed takes its grant along,
    /// and the sync takes it off there; one deleted and made again gets its
    /// grant back.
    #[cfg(windows)]
    #[test]
    fn grants_follow_a_renamed_and_a_remade_folder() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("config"), d.path().join("state"));
        let (work, moved) = (d.path().join("work"), d.path().join("moved"));
        std::fs::create_dir_all(work.join("sub")).unwrap();
        let want = [Grant {
            container: container(&paths, &node("lab")),
            path: work.clone(),
            access: Access::ALL,
            id: None,
            unfinished: false,
            toward: Vec::new(),
            closed_at: None,
        }];
        let s = windows_sync(&paths, &want, &mut |_| {});
        assert!(s.errors.is_empty(), "{s:?}");
        std::fs::rename(&work, &moved).unwrap();
        assert!(icacls(&moved).contains("S-1-15-2-"), "{}", icacls(&moved));
        let s = windows_sync(&paths, &[], &mut |_| {});
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        assert_eq!(s.removed, 1);
        assert!(!icacls(&moved).contains("S-1-15-2-"), "{}", icacls(&moved));
        assert!(
            !icacls(&moved.join("sub")).contains("S-1-15-2-"),
            "{}",
            icacls(&moved.join("sub"))
        );

        std::fs::create_dir_all(&work).unwrap();
        windows_sync(&paths, &want, &mut |_| {});
        std::fs::remove_dir_all(&work).unwrap();
        std::fs::create_dir_all(&work).unwrap();
        assert!(!icacls(&work).contains("S-1-15-2-"), "{}", icacls(&work));
        let s = windows_sync(&paths, &want, &mut |_| {});
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        assert!(icacls(&work).contains("S-1-15-2-"), "{}", icacls(&work));
        // The same folder, with its grant taken off by hand: it comes back.
        nerve_sandbox::appcontainer::set(&work, &want[0].container, None, false).unwrap();
        assert!(!icacls(&work).contains("S-1-15-2-"), "{}", icacls(&work));
        windows_sync(&paths, &want, &mut |_| {});
        assert!(icacls(&work).contains("S-1-15-2-"), "{}", icacls(&work));
        let s = remove_all(&paths, &[node("lab")], &mut |_| {});
        assert!(s.errors.is_empty(), "{s:?}");
        assert!(!icacls(&work).contains("S-1-15-2-"), "{}", icacls(&work));
    }

    /// On Windows: a granted home gives neither the node's own folders in
    /// it nor its protected entries; the folders around them are split into
    /// their other entries, as for Landlock.
    #[cfg(windows)]
    #[test]
    fn a_granted_home_gives_neither_the_nodes_folders_nor_protected_ones() {
        let d = tempfile::tempdir().unwrap();
        let home = PathBuf::from(nerve_policy::paths::win::strip_verbatim(
            &std::fs::canonicalize(d.path())
                .unwrap()
                .display()
                .to_string(),
        ));
        let paths = NodePaths::new(
            home.join(".config\\nerve"),
            home.join(".local\\state\\nerve"),
        );
        for p in [
            ".config\\nerve",
            ".config\\other",
            ".local\\state\\nerve",
            ".ssh",
            "proj",
        ] {
            std::fs::create_dir_all(home.join(p)).unwrap();
        }
        let mut cfg = NodeConfig::default();
        cfg.centers.push(nerve_policy::CenterEntry {
            name: "lab".into(),
            url: String::new(),
            pin: None,
            center_id: String::new(),
            node_id: String::new(),
            settings: Default::default(),
            paused: false,
            revoked: false,
            unknown: false,
            public_key: None,
            key_rotations: 0,
            pin_rotations: 0,
            old_pin: None,
            policy: nerve_policy::CenterPolicy {
                folders: vec![nerve_policy::config::Folder {
                    path: home.display().to_string(),
                    access: Access::ALL,
                }],
                ..Default::default()
            },
            capabilities: Vec::new(),
        });
        let want = wanted(&cfg, &paths, &home, &crate::paths::platform());
        let granted = |p: &Path| want.iter().any(|g| within(p, &g.path));
        assert!(granted(&home.join("proj")), "{want:?}");
        assert!(granted(&home.join(".config\\other")), "{want:?}");
        for closed in [".config\\nerve", ".local\\state\\nerve", ".ssh"] {
            assert!(!granted(&home.join(closed)), "{closed}: {want:?}");
        }
    }
}
