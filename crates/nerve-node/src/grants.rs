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
//! starts (walking every grant then), when its config changes (also before
//! the control pipe answers a folder change, crate::pipe), before each
//! folder-mode command, and walks a granted folder again soon after names
//! in it changed (crate::grant_watch); the
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
//! as it changes something (`nerve_sandbox::inherit`). The first grant of a
//! large folder still reaches every file in it, so a change that takes long
//! says how far it is ([`apply`]).
//!
//! A file with more than one name (a hard link: pnpm's `node_modules`, a
//! uv `.venv`, a local `git clone`) has one access list for all its names,
//! which a change reaches through any of them. Unless all its names lie
//! under the same grants, it gets no more than read and execute for the
//! commands, and no more than any of its names' folders gives; closed where
//! one of them lies in a closed folder or a protected entry ([`Links`],
//! [`Shut`]). On Linux such a file gets no entry and keeps its own, usually
//! readable, rights; Windows has no such rights for a container, so the
//! node gives each container whose grant holds a name read and execute of
//! its own, the same whichever name a change reaches it through.

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
use nerve_sandbox::inherit::{Cap, Gets, Linked, Walked};
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
    /// Folders granted or closed to a container that have nothing at their
    /// path: no grant is recorded for them, so a folder made there later is
    /// not seen as moved ([`in_place`]).
    pub absent: Vec<Grant>,
    /// The platform the protected list followed for what the sync wanted
    /// (crate::paths::platform_for: the owner's Documents folder): a
    /// protected entry that moved into a granted folder since splits it
    /// ([`in_place`]). `None` where the sync did not read it.
    pub platform: Option<Platform>,
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

    /// What decides whether a command may run after this sync
    /// ([`Synced::refusal`]), for a command that takes the answer of a sync
    /// that ran before it.
    pub fn kept(&self) -> Synced {
        Synced {
            stale: self.stale.clone(),
            unclosed: self.unclosed.clone(),
            unknown: self.unknown.clone(),
            away: self.away.clone(),
            absent: self.absent.clone(),
            platform: self.platform.clone(),
            ..Synced::default()
        }
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
    mark_walks(file, &Rewalk::Every)
}

/// Which recorded grants a sync walks again into every folder below them,
/// besides those a change reaches ([`apply`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rewalk {
    None,
    /// Every one, as the node's first sync after its start does: what was
    /// installed or moved into a granted folder while it did not run gets
    /// its entries.
    Every,
    /// Those on these folders (as the record names them): where names
    /// changed since (crate::grant_watch).
    At(Vec<PathBuf>),
}

/// Marks the grants of the record `file` that `walk` names as unfinished,
/// so the next sync walks them into every folder below them; how many it
/// marked. The caller holds the turn ([`SYNC`]).
fn mark_walks(file: &Path, walk: &Rewalk) -> Result<usize, String> {
    let named = |g: &Grant| match walk {
        Rewalk::None => false,
        Rewalk::Every => true,
        Rewalk::At(folders) => folders.contains(&g.path),
    };
    if *walk == Rewalk::None {
        return Ok(0);
    }
    let _held =
        RecordLock::take(file).map_err(|e| format!("{}: {e}", lock_file(file).display()))?;
    let record = read_record(file)?;
    let count = record.iter().filter(|g| named(g)).count();
    if count == 0 {
        return Ok(0);
    }
    let marked: Vec<Grant> = record
        .iter()
        .map(|g| Grant {
            unfinished: g.unfinished || named(g),
            ..g.clone()
        })
        .collect();
    write_record(file, &marked)?;
    Ok(count)
}

/// The places the record of the node at `paths` holds a grant with flags
/// on, where the last sync found them, each once with the objects the
/// record names there: those the node watches for new names
/// (crate::grant_watch). A closed folder lies inside one of them. Read from
/// the record alone, as the node: what is at each place now (a granted file,
/// also a split home's files, is no folder to watch) is for the watch to
/// look at as the owner, since the node's own account may not see into the
/// owner's profile. Nothing where the record cannot be read.
pub fn granted_folders(paths: &NodePaths) -> Vec<crate::grant_watch::Folder> {
    let mut out: Vec<crate::grant_watch::Folder> = Vec::new();
    let grants = read_record(&record_file(paths)).unwrap_or_default();
    for g in grants.into_iter().filter(|g| g.access != Access::NONE) {
        match out.iter_mut().find(|f| f.path == g.path) {
            Some(f) => {
                if let Some(id) = g.id.filter(|id| !f.ids.contains(id)) {
                    f.ids.push(id);
                }
            }
            None => out.push(crate::grant_watch::Folder {
                path: g.path,
                ids: g.id.into_iter().collect(),
            }),
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
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
    /// `links` says what a file with more than one name gets, there and at
    /// `path` itself. With `whole` it goes into every folder below, also
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
}

/// What a change of a grant gives a file with more than one name (hard
/// links) below its folder, whose access list all its names share
/// ([`Judge`]). A file whose names all lie inside the folder and under the
/// same grants gets the change as any file: each name gets the same from
/// the grants. Every other one gets, for each container, no more than read
/// and execute, and no more than each of its names' grants gives there
/// (nothing where one lies in a folder closed to it, or in its protected
/// list); so a grant on one name never opens the file wider than another
/// name's folder allows. A sandboxed process may only make a hard link to
/// a file it may write (Windows since 2015), so a command cannot link a
/// file in that it may not already write, and read it through this.
#[derive(Debug, Clone, Copy)]
pub struct Links<'a> {
    /// Every wanted grant, by which each name's rights are told.
    pub want: &'a [Grant],
    /// The recorded grants that keep a folder closed where a command moved
    /// it ([`Grant::closed_at`]): a name there is closed as one under a
    /// wanted closed folder.
    pub moved: &'a [Grant],
    /// What closes a name to a container besides the grants.
    pub shut: &'a Shut,
    /// The paths of every wanted and recorded grant (of any container), by
    /// which a file whose names all lie under the same ones gets the change
    /// as any file; `None`: none does (a granted folder is somewhere else
    /// now, or cannot be told).
    pub places: Option<&'a [PathBuf]>,
    /// The containers of every wanted and recorded grant, and the command
    /// account, whose rights on such a file a change sets.
    pub containers: &'a [String],
}

/// What closes a name of a file with more than one name to a container's
/// commands besides the node's grants ([`Judge`]): the protected list of
/// its pairing with the node's own folders, around which a granted folder
/// is split, and the pairing's folders without flags, of which one inside
/// a split folder gets no grant at all (`exec::container_grants`). Neither
/// carries an entry for the container that the file could keep, so the
/// node closes the file to it under every name there instead. It also
/// holds each container's own folder ([`Shut::own`]).
#[derive(Debug, Default)]
pub struct Shut {
    #[cfg(any(windows, test))]
    lists: Vec<ShutList>,
    /// Each container's own folder (its AppContainer's `AC` folder, where
    /// pnpm and uv keep their store and cache) and the command account's
    /// profile, by the container or the account's SID: a name there holds
    /// a file the command account made for it to read and run
    /// ([`Judge::cap`]).
    #[cfg(any(windows, test))]
    own: Vec<(String, PathBuf)>,
    /// The command account's SID, the owner of what its commands make.
    #[cfg(any(windows, test))]
    run: String,
}

/// [`Shut`] for one container.
#[cfg(any(windows, test))]
#[derive(Debug)]
struct ShutList {
    container: String,
    protected: nerve_policy::protected::Protected,
    /// The pairing's folders, which release a protected entry for a read.
    folders: Vec<nerve_policy::config::Folder>,
    /// The pairing's folders as places (`~` written out, and where they
    /// resolve), with their flags.
    places: Vec<(PathBuf, Access)>,
}

#[cfg(any(windows, test))]
impl Shut {
    /// The [`Shut`] of every pairing in `cfg`, whose `~` is `home`.
    pub fn of(cfg: &NodeConfig, paths: &NodePaths, home: &Path, platform: &Platform) -> Shut {
        let own = paths.own();
        let lists = cfg
            .centers
            .iter()
            .map(|c| {
                let mut places = Vec::new();
                for f in &c.policy.folders {
                    let Some(p) = nerve_policy::protected::expand(home, &f.path) else {
                        continue;
                    };
                    if let Ok(real) = nerve_policy::paths::resolve(&p) {
                        places.push((real, f.access));
                    }
                    places.push((p, f.access));
                }
                ShutList {
                    container: container(paths, &c.node_id),
                    protected: nerve_policy::protected::Protected::new(
                        platform,
                        home,
                        &own,
                        &c.policy.protected,
                    ),
                    folders: c.policy.folders.clone(),
                    places,
                }
            })
            .collect();
        Shut {
            lists,
            own: Vec::new(),
            run: String::new(),
        }
    }

    /// `self` with the own folders of the containers of `cfg` and of the
    /// command account `run` (its SID), in its profile `run_home`: on the
    /// installed service, where the files its commands make belong to it.
    /// On a node run by hand the commands run as you, so nothing tells a
    /// store's file from one of yours a command linked there, and no
    /// folder holds a file.
    pub fn own(mut self, cfg: &NodeConfig, paths: &NodePaths, run: &str, run_home: &Path) -> Shut {
        // Also where the profile resolves, as the names of a file come,
        // but not a container's own folder: its commands may make that a
        // link to a folder they may write, which would then count as
        // theirs.
        let mut homes = vec![run_home.to_path_buf()];
        if let Ok(real) = nerve_policy::paths::resolve(run_home)
            && real != run_home
        {
            homes.push(real);
        }
        let mut own = Vec::new();
        for home in &homes {
            for c in &cfg.centers {
                let name = container(paths, &c.node_id);
                let ac = crate::account::Own::in_container(home, &name).temp;
                own.push((name, ac));
            }
            own.push((run.to_string(), home.clone()));
        }
        self.own = own;
        self.run = run.to_string();
        self
    }

    /// Whether `name` lies in `container`'s own folder ([`Shut::own`]) and
    /// the file is the command account's (`owner`): one its commands made
    /// there. A file of yours keeps you as its owner wherever a command
    /// links it, and no grant lets a command change that.
    fn owns(&self, container: &str, name: &Path, owner: Option<&str>) -> bool {
        owner.is_some_and(|o| !self.run.is_empty() && o.eq_ignore_ascii_case(&self.run))
            && self
                .own
                .iter()
                .any(|(c, p)| c == container && within(name, p))
    }

    /// Whether `name` is closed to `container`'s commands: it lies in a
    /// protected entry its folders do not release for a read, or the
    /// deepest of its folders that holds it has no flag.
    fn closes(&self, container: &str, name: &Path) -> bool {
        self.lists
            .iter()
            .filter(|l| l.container == container)
            .any(|l| {
                if l.protected.check(name, false, &l.folders).is_some() {
                    return true;
                }
                let depth = |p: &Path| p.components().count();
                let holding: Vec<&(PathBuf, Access)> =
                    l.places.iter().filter(|(p, _)| within(name, p)).collect();
                let deepest = holding.iter().map(|(p, _)| depth(p)).max();
                holding
                    .iter()
                    .any(|(p, a)| Some(depth(p)) == deepest && *a == Access::NONE)
            })
    }
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

/// How a change of a grant judges a file with more than one name below the
/// folder `dir` ([`Links`]), by the names the file gives as the change holds
/// it open, not by its path: where a command removed the name the walk
/// found, the names it has left count.
#[cfg(any(windows, test))]
struct Judge<'a> {
    /// The place the names are compared with; one that cannot be resolved
    /// holds no name, so none gets the change as any file.
    real_dir: Option<PathBuf>,
    /// Whether a folder closed to any container lies inside the folder
    /// ([`Judge::verdict`]).
    closed_inside: bool,
    links: Links<'a>,
}

#[cfg(any(windows, test))]
impl<'a> Judge<'a> {
    fn new(dir: &Path, links: Links<'a>) -> Judge<'a> {
        let real_dir = nerve_policy::paths::resolve(dir).ok();
        let inside = |p: &Path| {
            [Some(dir), real_dir.as_deref()]
                .into_iter()
                .flatten()
                .any(|d| within(p, d) && !within(d, p))
        };
        let closed_inside = links
            .want
            .iter()
            .chain(links.moved)
            .any(|g| g.access == Access::NONE && inside(&g.path));
        Judge {
            real_dir,
            closed_inside,
            links,
        }
    }

    /// What a file with `n` names, `all` of them listed, owned by `owner`
    /// (a SID), gets. Where a folder closed to a container lies inside the
    /// folder, no file gets the change as any file: a command may rename
    /// that closed folder (through the rights of the folder around it)
    /// while the walk goes on, and a file linked across its edge would be
    /// judged by names the folder no longer has, and take the whole list of
    /// a folder around it (write included). Capped, it gets read and run at
    /// most. A closed folder from outside the walked folder (inside another
    /// folder a container writes) that a command moves in during the walk is
    /// not looked for: that would cap every project under a writable folder
    /// that holds any closed one. The next walk sees it and closes the file.
    fn verdict(&self, n: u64, all: &[PathBuf], owner: Option<&str>) -> Linked {
        let containers = self.links.containers;
        let shut = all
            .iter()
            .any(|name| containers.iter().any(|c| self.links.shut.closes(c, name)));
        if !shut && !self.closed_inside && self.holds(n, all) {
            return Linked::Full(containers.to_vec());
        }
        Linked::Capped(Cap {
            containers: containers
                .iter()
                .map(|c| (c.clone(), self.cap(c, all, owner)))
                .collect(),
        })
    }

    /// Whether the file gets the change as any file: its names are all
    /// listed (as many as it has), every one inside the folder (compared
    /// resolved), and held by exactly the same of the grant paths (of any
    /// container) as each other. Each name then gets the same rights from
    /// the node's grants. A command may also give a folder it makes an
    /// entry of its own, which the change then passes to a file linked into
    /// it; every container that may write there may read too (`w` reads),
    /// so such an entry opens nothing it could not read already. Cargo's `target` (each program under two names), a
    /// repository's own packs, and links within a project are such files.
    fn holds(&self, n: u64, all: &[PathBuf]) -> bool {
        let (Some(real_dir), Some(places)) = (&self.real_dir, self.links.places) else {
            return false;
        };
        // The grants that hold a place, by their place in `places`.
        let held_by = |p: &Path| -> Vec<usize> {
            places
                .iter()
                .enumerate()
                .filter(|(_, g)| within(p, g))
                .map(|(i, _)| i)
                .collect()
        };
        let Some(first) = all.first() else {
            return false;
        };
        let mine = held_by(first);
        all.len() as u64 >= n
            && all.iter().all(|name| {
                within(name, real_dir) && !within(real_dir, name) && held_by(name) == mine
            })
    }

    /// What the commands of `container` get on a file with the names `all`
    /// (`acl` file rights): nothing ([`Gets::Closed`]) where a name lies in a
    /// folder closed to it (the closed grant nearest to the name, as a grant
    /// inside a closed folder opens its own; also one a command moved, or
    /// one [`Shut`] closes), otherwise read and execute at most, and no more
    /// than the grants of the container that hold a name give there (inside
    /// the deepest closed folder that holds it, where one does). A name
    /// under none of its grants does not restrict: such a file outside the
    /// folders (pnpm's store, uv's cache, the repository a clone came from)
    /// is read through the granted name, as on Linux, where it keeps its
    /// own, usually readable, rights. A name in its own folder (a store or
    /// cache of its commands, [`Shut::own`]) holds a file the command
    /// account made (`owner`) for it to read and run: the node's entries
    /// take the place of what the file inherits there, so without them the
    /// container would lose its own store's files once no grant holds
    /// another name. Not one of yours that a command linked there from a
    /// folder it was granted: as on Linux, where a grant taken off leaves
    /// such a file only its own mode. Where nothing holds any name,
    /// [`Gets::Unheld`]: the node's own entries for it go.
    fn cap(&self, container: &str, all: &[PathBuf], owner: Option<&str>) -> Gets {
        use nerve_sandbox::acl;
        let mut cap = acl::READ_AND_EXECUTE;
        let mut held_any = false;
        for name in all {
            if self.links.shut.closes(container, name) {
                return Gets::Closed;
            }
            let held: Vec<&Grant> = self
                .links
                .want
                .iter()
                .chain(self.links.moved)
                .filter(|g| g.container == container && within(name, &g.path))
                .collect();
            let opened = |closed: &Grant| {
                held.iter().any(|g| {
                    g.access != Access::NONE
                        && within(&g.path, &closed.path)
                        && !within(&closed.path, &g.path)
                })
            };
            if held.iter().any(|g| g.access == Access::NONE && !opened(g)) {
                return Gets::Closed;
            }
            if self.links.shut.owns(container, name, owner) {
                held_any = true;
                continue;
            }
            // Only the grants inside the deepest folder closed to it that
            // holds the name count: that folder's denial comes after their
            // entries and before those of the grants around it, so an `r`
            // folder inside a closed one gives no execute from an `rwx`
            // around.
            let depth = |p: &Path| p.components().count();
            let fence = held
                .iter()
                .filter(|g| g.access == Access::NONE)
                .map(|g| g.path.as_path())
                .max_by_key(|p| depth(p));
            let opening: Vec<&&Grant> = held
                .iter()
                .filter(|g| {
                    g.access != Access::NONE
                        && fence.is_none_or(|f| within(&g.path, f) && !within(f, &g.path))
                })
                .collect();
            if opening.is_empty() {
                continue;
            }
            held_any = true;
            let a = opening.iter().fold(Access::NONE, |a, g| Access {
                read: a.read || g.access.read,
                write: a.write || g.access.write,
                execute: a.execute || g.access.execute,
            });
            cap &= acl::file_cap(a.read, a.write, a.execute);
        }
        if held_any {
            Gets::Rights(cap)
        } else {
            Gets::Unheld
        }
    }
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
    sync_shut(file, want, &Shut::default(), folders)
}

/// Whether the object with the recorded grant `old` is still at its path,
/// `here` being what a look there saw. A record without the object's id
/// takes the one there; one that cannot be told counts as there (a change
/// there fails in turn and keeps it).
fn at_path(old: &Grant, here: &io::Result<Option<Look>>) -> bool {
    match here {
        Ok(Some(l)) => old.id.is_none() || l.id.is_none() || old.id == l.id,
        Ok(None) => false,
        Err(_) => true,
    }
}

/// Whether every grant the record of the node at `paths` holds is still on
/// its object at the path recorded, and nothing is at the path of a grant
/// the last sync (`last`) found nothing for (a granted or closed folder that
/// was not there, or on a volume that was away), and the protected list
/// follows the owner's Documents folder the last sync used, looked at as a
/// sync does but without changing or walking anything (so while another
/// sync walks): a granted or closed folder that was moved, removed or made
/// again since is not, nor a Documents folder moved (into a granted folder,
/// which the sync splits around its PowerShell profiles). A command that would wait for a long walk may go on with the answer
/// of the last sync only while this holds; what moved on the disk is for a
/// sync in its turn (a take-off of the moved grant, the refusal for a closed
/// folder a command moved or made). `owner` as in [`apply`]. Not on
/// Windows, no grant is on a folder.
pub fn in_place(paths: &NodePaths, owner: Option<&crate::service::Account>, last: &Synced) -> bool {
    #[cfg(windows)]
    {
        // Logged on once for all the looks.
        let owner = owner.filter(|_| run_sid(paths).is_some());
        in_place_as(
            &record_file(paths),
            last,
            || act_as(owner),
            || Some(crate::paths::platform_for(paths)),
            &mut Acls {
                report: &mut |_| {},
                owner: None,
            },
        )
    }
    #[cfg(not(windows))]
    {
        let _ = (paths, owner, last);
        true
    }
}

/// [`in_place`] for the record `file`, on `folders`, which `act` makes the
/// looks as while its result lives, and the `platform` read as it acts (the
/// owner's registry names the owner's Documents folder). The record is read
/// before `act` runs: it lives in the node's own state folder, which the
/// owner may not read.
#[cfg(any(windows, test))]
fn in_place_as<G>(
    file: &Path,
    last: &Synced,
    act: impl FnOnce() -> io::Result<G>,
    platform: impl FnOnce() -> Option<Platform>,
    folders: &mut impl Folders,
) -> bool {
    let Ok(record) = read_record(file) else {
        return false;
    };
    let Ok(_as) = act() else {
        return false;
    };
    platform() == last.platform
        && record
            .iter()
            .all(|old| at_path(old, &folders.look(&old.path, &old.container, old.access)))
        && last
            .absent
            .iter()
            .chain(&last.away)
            .all(|g| !matches!(folders.look(&g.path, &g.container, g.access), Ok(Some(_))))
}

/// [`in_place_as`] with no change of whom the looks are made as, and the
/// platform of the last sync.
#[cfg(test)]
fn in_place_with(file: &Path, last: &Synced, folders: &mut impl Folders) -> bool {
    in_place_as(file, last, || Ok(()), || last.platform.clone(), folders)
}

/// [`sync`], with what closes a name of a file with more than one name
/// besides the grants (`shut`).
fn sync_shut(file: &Path, want: &[Grant], shut: &Shut, folders: &mut impl Folders) -> Synced {
    let _one = nerve_transport::sync::turn(&SYNC);
    sync_in_turn(file, want, shut, folders)
}

/// [`sync_shut`] by a caller that holds the turn ([`SYNC`]) already: the
/// node, which removes profiles in the same turn ([`apply_in`]).
fn sync_in_turn(file: &Path, want: &[Grant], shut: &Shut, folders: &mut impl Folders) -> Synced {
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
    // Where every wanted and recorded grant is, by which a file with more
    // than one name whose names all lie under the same ones gets a change
    // as any file (`Judge::holds`). It compares the grants by their paths,
    // while a grant's entry goes with its folder: so when a granted folder
    // is somewhere else now, or cannot be told, the paths do not show what
    // holds a name, and no file does.
    let settled = seen.iter().all(|(here, found)| {
        here.is_ok() && !matches!(found, Some(Ok(Found::At(_))) | Some(Err(_)))
    });
    let places: Option<Vec<PathBuf>> =
        settled.then(|| want.iter().chain(&record).map(|g| g.path.clone()).collect());
    // The command account too: a process of a container opens only what
    // both may, so the account's entry on such a file must not hang on the
    // name walked either.
    let mut containers: Vec<String> = want
        .iter()
        .chain(&record)
        .map(|g| g.container.clone())
        .collect();
    containers.sort();
    containers.dedup();
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
    // Each such grant where its folder is now: a name of a file with more
    // than one name there stays closed to its container.
    let moved: Vec<Grant> = record
        .iter()
        .zip(&seen)
        .filter(|(old, _)| keeps_closed(old))
        .filter_map(|(old, (here, found))| match found {
            _ if at_path(old, here) => old.closed_at.is_some().then(|| old.clone()),
            Some(Ok(Found::At(now))) => Some(Grant {
                path: now.clone(),
                ..old.clone()
            }),
            _ => None,
        })
        .collect();
    // What a change gives a file with more than one name.
    let links = Links {
        want,
        moved: &moved,
        shut,
        places: places.as_deref(),
        containers: &containers,
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
                    let id = old.id.as_deref();
                    match folders.set(&old.path, &old.container, None, false, links, false, id) {
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
                                unfinished: old.unfinished || !refusal(&e),
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
                // Taking the grant off passes the change down too.
                let id = old.id.as_deref();
                match folders.set(&now, &old.container, None, false, links, false, id) {
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
                            unfinished: old.unfinished || !refusal(&e),
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
                    // A denying entry is no exception: a file below with a
                    // name elsewhere gets it too, under every name
                    // (`Judge::cap`).
                    let whole = unfinished_at(w);
                    let access = Some(w.access);
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
                            out.absent.push(w.clone());
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

/// `shut` with the containers' own folders ([`Shut::own`]) in the profile
/// of the command account (`run`, its SID) on the installed service.
#[cfg(windows)]
fn with_own(shut: Shut, cfg: &NodeConfig, paths: &NodePaths, run: Option<&str>) -> Shut {
    match run.filter(|s| !s.is_empty()) {
        Some(sid) => match crate::win_user::profile_of_sid(sid) {
            Some(at) => shut.own(cfg, paths, sid, &at),
            None => shut,
        },
        None => shut,
    }
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
    walk: Rewalk,
    report: &mut dyn FnMut(&str),
) -> Synced {
    #[cfg(windows)]
    {
        let run = run_sid(paths);
        let owner = owner.filter(|_| run.is_some());
        let used = std::cell::Cell::new(None);
        let want = || {
            let (cfg, home) = current();
            // The folders are resolved, walked and split as the owner sees
            // them: the service's account may not list the owner's home, and
            // a granted folder there that holds a protected entry (the home,
            // Documents) is given by its entries.
            let mut shut = Shut::default();
            let grants = looked_as(
                || act_as(owner),
                || {
                    let platform = crate::paths::platform_for(paths);
                    let of = Shut::of(&cfg, paths, &home, &platform);
                    shut = with_own(of, &cfg, paths, run.as_deref());
                    let grants = wanted_on(run.as_deref(), &cfg, paths, &home, &platform);
                    used.set(Some(platform));
                    grants
                },
            );
            (grants, pairings(paths, &cfg), shut)
        };
        let mut synced = apply_in(
            paths,
            walk,
            want,
            &mut Acls { report, owner },
            &mut WinProfiles,
        );
        synced.platform = used.take();
        synced
    }
    #[cfg(not(windows))]
    {
        let _ = (paths, owner, current, walk, report);
        Synced::default()
    }
}

/// What `look` gives, looked at as `act` acts on this thread while its
/// result lives ([`apply`]: as the owner, whom `Acls` acts as too). Where it
/// cannot act so, `look` runs as the node, and the log says why: a folder
/// it may not list then gives nothing, and no change of a folder's entry
/// can be made either.
#[cfg(any(windows, test))]
fn looked_as<G>(
    act: impl FnOnce() -> io::Result<G>,
    look: impl FnOnce() -> Vec<Grant>,
) -> Vec<Grant> {
    let _as = act()
        .inspect_err(|e| tracing::warn!("folder grants: {e}"))
        .ok();
    look()
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
        let platform = crate::paths::platform_for(paths);
        let run = run_sid(paths);
        let want = wanted_on(run.as_deref(), cfg, paths, home, &platform);
        let shut = with_own(
            Shut::of(cfg, paths, home, &platform),
            cfg,
            paths,
            run.as_deref(),
        );
        sync_outside_in(
            paths,
            &want,
            &shut,
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
    shut: &Shut,
    live: &[String],
    folders: &mut impl Folders,
    store: &mut impl ProfileStore,
) -> Synced {
    let mut s = sync_shut(&record_file(paths), want, shut, folders);
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
    let what = match doing {
        Doing::Put => format!("putting the grant on {path}"),
        Doing::Remove => format!("taking the grant off {path}"),
    };
    let so_far = format!(
        "{} files and folders looked at, {} changed so far",
        w.seen, w.changed
    );
    if first {
        format!(
            "{what} takes a while: Windows keeps the permissions of each file and folder, so the node changes each one below it that the change reaches ({so_far})"
        )
    } else {
        format!("still {what}: {so_far}")
    }
}

/// How the change of the grant on `path` ended after `took`: with `w`, or
/// with an error (`None`), which the sync gives.
#[cfg(any(windows, test))]
fn done_text(doing: Doing, path: &Path, w: Option<Walked>, took: Duration) -> String {
    let path = path.display();
    let secs = took.as_secs();
    let (what, did) = match doing {
        Doing::Put => (
            format!("putting the grant on {path}"),
            format!("put the grant on {path}"),
        ),
        Doing::Remove => (
            format!("taking the grant off {path}"),
            format!("took the grant off {path}"),
        ),
    };
    match w {
        Some(w) => format!(
            "{did} in {secs} s: {} files and folders looked at, {} changed",
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
        act_as(self.owner)
    }
}

/// Acts as `owner`, where there is one, on this thread while the result
/// lives ([`Acls::act`]).
#[cfg(windows)]
pub(crate) fn act_as(
    owner: Option<&crate::service::Account>,
) -> io::Result<Option<crate::win_user::FsAs>> {
    owner
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
        // The links on the way are looked at as the owner too: the node's
        // own account may not look into the owner's folders, and would
        // find no link there.
        let _as = self.act()?;
        // Nothing the node may look at: a recorded grant is looked for by
        // its object then (`locate`).
        if let Err(e) = not_remote(path) {
            tracing::warn!("folder grants: {e}");
            return Ok(None);
        }
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
        let _as = self.act()?;
        // The folders on the way are opened to find the volume: not
        // through a link to another machine.
        let near = match not_remote(near) {
            Ok(()) => near,
            Err(e) => {
                tracing::warn!("folder grants: {e}");
                Path::new("")
            }
        };
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
        // What commands made belongs to the command account, whose list
        // the owner may not change outside their profile: the change is
        // made as that account there (`Below::maker`). Logged on before
        // the thread acts as the owner.
        let maker = self.owner.and_then(|_| crate::win_user::run_logon().ok());
        let _as = self.act()?;
        not_remote(path)?;
        let masks = access.map(masks_of);
        let expect = expect
            .map(|e| e.parse::<acl::FileId>().map_err(io::Error::other))
            .transpose()?;
        // Each file with more than one name is judged as the change gets to
        // it, by the names it has then.
        let judge = Judge::new(path, links);
        let mut check = |_: &Path, n: u32, all: &[PathBuf], owner: Option<&str>| {
            Ok(judge.verdict(n.into(), all, owner))
        };
        let doing = if access.is_some() {
            Doing::Put
        } else {
            Doing::Remove
        };
        // The object changed, as its handle names it: the path may lead
        // elsewhere by now.
        let id = paced(self.report, doing, path, &Instant::now, |progress| {
            let below = appcontainer::Below {
                links: Some(&mut check),
                progress,
                maker: maker.as_ref().map(|t| t.raw()),
            };
            appcontainer::set_below(path, container, masks, own, whole, expect, below)
        })?;
        Ok(id.map(|i| i.to_string()))
    }
}

/// [`apply`] for the grants `want`, as the tests on Windows give them.
#[cfg(all(windows, test))]
fn windows_sync(paths: &NodePaths, want: &[Grant], report: &mut dyn FnMut(&str)) -> Synced {
    apply_in(
        paths,
        Rewalk::None,
        || (want.to_vec(), Vec::new(), Shut::default()),
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

/// Notes the containers of the pairings in `cfg` among those whose profiles
/// the node may have made (`profiles.json`). The node does so at its start,
/// before it takes a call: a pairing removed before its first sync saw it
/// then has its profile removed by the sync after the change too
/// ([`apply_in`]), also one that never had a grant. Its syncs run only after
/// it, and no other process writes the file.
pub fn note_pairings(paths: &NodePaths, cfg: &NodeConfig) -> Result<(), String> {
    #[cfg(windows)]
    {
        note_in(&profiles_file(paths), &pairings(paths, cfg))
    }
    #[cfg(not(windows))]
    {
        let _ = (paths, cfg);
        Ok(())
    }
}

/// [`note_pairings`] for the containers `live`, in the file `file`.
#[cfg(any(windows, test))]
fn note_in(file: &Path, live: &[String]) -> Result<(), String> {
    let mut all = read_profiles(file)?;
    let before = all.len();
    for c in live {
        if !all.contains(c) {
            all.push(c.clone());
        }
    }
    if all.len() == before {
        return Ok(());
    }
    all.sort();
    write_profiles(file, &all)
}

/// Holds off every sync of this process while the guard lives: a test of
/// the node's start sees what only its start wrote ([`noted`]).
#[cfg(all(windows, test))]
pub(crate) fn hold_syncs() -> std::sync::MutexGuard<'static, ()> {
    nerve_transport::sync::turn(&SYNC)
}

/// The containers in `profiles.json` at `paths` ([`note_pairings`]).
#[cfg(all(windows, test))]
pub(crate) fn noted(paths: &NodePaths) -> Vec<String> {
    read_profiles(&profiles_file(paths)).unwrap()
}

/// [`apply`] for the grants `want` gives, on `folders` and the profiles in
/// `store`. `want` gives the grants, the containers of the config's
/// pairings ([`pairings`]) and what closes a linked file's name besides the
/// grants ([`Shut`]), and is asked once this sync's turn has come: the node starts a
/// sync for each change, and one that waited for a sync of a newer config
/// would otherwise put back a grant the owner took away since. The profile
/// of each container the sync left without grants goes in the same turn as
/// the grants, so a sync that waited for this one returns only once it is
/// gone. `center rm` asks the node for one (`folder.grants`) while the
/// node's own sync of the change may hold the turn, and then looks at the
/// profiles itself: one still on its way out would be said to stay. The
/// grants `walk` names are marked to be walked whole in the same turn, so
/// the walk is this sync's, after any change of the config before it.
#[cfg(any(windows, test))]
fn apply_in(
    paths: &NodePaths,
    walk: Rewalk,
    want: impl FnOnce() -> (Vec<Grant>, Vec<String>, Shut),
    folders: &mut impl Folders,
    store: &mut impl ProfileStore,
) -> Synced {
    let _one = nerve_transport::sync::turn(&SYNC);
    let marked = mark_walks(&record_file(paths), &walk);
    let (want, live, shut) = want();
    let mut s = sync_in_turn(&record_file(paths), &want, &shut, folders);
    if let Err(e) = marked {
        s.errors.push(e);
    }
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
        /// Files with more than one name (hard links), as [`Fake::link`]
        /// makes them.
        files: Vec<LinkedFile>,
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
        /// Each change made or tried: its path, and whether it goes into
        /// every folder below (`whole`).
        changes: Vec<(PathBuf, bool)>,
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

        /// A file with these names (hard links), which no container may
        /// open yet.
        fn link(&mut self, names: &[&str]) {
            self.files.push(LinkedFile {
                names: names.iter().map(PathBuf::from).collect(),
                ..LinkedFile::default()
            });
        }

        /// What the commands of `container` may do with the file named
        /// `name` ([`Fake::link`]): `None` when it is closed to them. The
        /// node's own entry for it decides where it has one (its denial
        /// comes first, its allowing entry before the inherited ones);
        /// otherwise what it inherits, cut to read and run where the file
        /// was capped.
        fn may(&self, name: &str, container: &str) -> Option<Access> {
            let f = self
                .files
                .iter()
                .find(|f| f.names.iter().any(|n| n == Path::new(name)))
                .expect("a linked file");
            if let Some((_, r)) = f.own.iter().find(|(c, _)| c == container) {
                return *r;
            }
            match f.inherited.iter().find(|(c, _)| c == container) {
                Some((_, Some(a))) if f.capped => Some(Access { write: false, ..*a }),
                Some((_, r)) => *r,
                None => Some(Access::NONE),
            }
        }

        /// What the grants on now give `container` at `name`, as Windows
        /// passes them down: `None` where the nearest of its grants that
        /// closes a folder holds the name and no grant inside that one does;
        /// otherwise only the grants inside that one give it anything.
        fn given(&self, container: &str, name: &Path) -> Option<Access> {
            let held: Vec<(PathBuf, Access)> = self
                .on
                .iter()
                .filter(|(_, c, _)| c == container)
                .filter_map(|(i, _, a)| {
                    let (p, _) = self.at.iter().find(|(_, j)| j == i)?;
                    within(name, p).then(|| (p.clone(), *a))
                })
                .collect();
            // The deepest closing one denies what the ones around it give.
            let fence = held
                .iter()
                .filter(|(_, a)| *a == Access::NONE)
                .map(|(p, _)| p)
                .max_by_key(|p| p.components().count());
            let inside: Vec<&(PathBuf, Access)> = held
                .iter()
                .filter(|(q, b)| {
                    *b != Access::NONE && fence.is_none_or(|p| within(q, p) && !within(p, q))
                })
                .collect();
            if fence.is_some() && inside.is_empty() {
                return None;
            }
            Some(inside.iter().fold(Access::NONE, |a, (_, b)| Access {
                read: a.read || b.read,
                write: a.write || b.write,
                execute: a.execute || b.execute,
            }))
        }

        /// A change of a grant on `path` as it reaches each linked file
        /// with a name below it, as Windows works the file's list out under
        /// the folder of the name walked: every inherited entry is that
        /// folder's, for every container, while the file's own entries
        /// stay; then what `links` says (`Judge::verdict`), as
        /// `nerve_sandbox::acl::capped` and `uncapped` give it.
        fn pass_to_files(&mut self, path: &Path, links: Links) {
            use nerve_sandbox::acl;
            let judge = Judge::new(path, links);
            let mut all: Vec<String> = self
                .on
                .iter()
                .map(|(_, c, _)| c.clone())
                .chain(links.containers.iter().cloned())
                .collect();
            all.sort();
            all.dedup();
            for i in 0..self.files.len() {
                let names = self.files[i].names.clone();
                let Some(walked) = names.iter().find(|n| within(n, path)) else {
                    continue;
                };
                let inherited: Vec<(String, Option<Access>)> = all
                    .iter()
                    .map(|c| (c.clone(), self.given(c, walked)))
                    .collect();
                let f = &mut self.files[i];
                f.inherited = inherited;
                match judge.verdict(names.len() as u64, &names, f.owner.as_deref()) {
                    Linked::Full(listed) => {
                        f.own.retain(|(c, _)| !listed.contains(c));
                        f.capped = false;
                    }
                    Linked::Capped(cap) => {
                        f.own = cap
                            .containers
                            .iter()
                            .filter_map(|(c, g)| match g {
                                Gets::Closed => Some((c.clone(), None)),
                                Gets::Rights(m) => Some((
                                    c.clone(),
                                    Some(Access {
                                        read: m & acl::READ_DATA != 0,
                                        write: false,
                                        execute: m & acl::EXECUTE != 0,
                                    }),
                                )),
                                Gets::Unheld => None,
                            })
                            .collect();
                        f.capped = true;
                    }
                }
            }
        }
    }

    /// A file of the fake volume with more than one name.
    #[derive(Default)]
    struct LinkedFile {
        names: Vec<PathBuf>,
        /// The node's own entries on it, for each container: the rights
        /// they allow, or `None`: closed to it.
        own: Vec<(String, Option<Access>)>,
        /// What each container inherits from the folder of the name walked
        /// last; `None`: denied there.
        inherited: Vec<(String, Option<Access>)>,
        /// Whether its last walk capped it, which cuts every inherited
        /// entry to read and run.
        capped: bool,
        /// Its owner's SID; `None`: yours.
        owner: Option<String>,
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
            self.changes.push((path.into(), whole));
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
            self.pass_to_files(path, links);
            Ok(Some(id))
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

    /// A file whose names all lie inside the changed folder and under the
    /// same grants gets the change as any file, wherever in the folder they
    /// are: cargo's `target`, and links within a project. One with a name
    /// under another grant, of this pairing or another, or outside the
    /// folder, gets no more than read and execute, and no more than each
    /// name's grants give. So does every such file in a sync that finds a
    /// granted folder moved.
    // The fake volume's `/w/...` paths are no paths on Windows, where the
    // pass resolves them on the real disk (`Judge::new`) and the protected
    // entries are Windows' own: win_account.rs shows these cases there.
    #[cfg(unix)]
    #[test]
    fn a_file_whose_names_lie_under_the_same_grants_gets_the_change() {
        let access = |a: &str| Some(Access::parse(a).unwrap());
        // (the grants, the file's names, what each container may do)
        type Case<'a> = (
            &'a [(&'a str, &'a str, &'a str)],
            [&'a str; 2],
            &'a [(&'a str, &'a str)],
        );
        let cases: [Case; 7] = [
            (
                &[("c1", "/w/proj", "rw")],
                [
                    "/w/proj/target/debug/demo",
                    "/w/proj/target/debug/deps/demo-0",
                ],
                &[("c1", "rw")],
            ),
            (
                &[("c1", "/w/proj", "rwx")],
                ["/w/proj/a.txt", "/w/proj/docs/b.txt"],
                &[("c1", "rwx")],
            ),
            (
                &[("c1", "/w/proj", "rw"), ("c2", "/w/proj/sub", "r")],
                ["/w/proj/x", "/w/proj/sub/x"],
                &[("c1", "r"), ("c2", "r")],
            ),
            (
                &[("c1", "/w/proj", "rw"), ("c1", "/w/proj/sub", "rwx")],
                ["/w/proj/x", "/w/proj/sub/x"],
                &[("c1", "r")],
            ),
            (
                &[("c1", "/w/proj", "rw")],
                ["/w/proj/x", "/store/x"],
                &[("c1", "r")],
            ),
            (
                &[("c1", "/w/proj", "rw"), ("c2", "/w/proj", "rw")],
                ["/w/proj/a", "/w/proj/b"],
                &[("c1", "rw"), ("c2", "rw")],
            ),
            (
                &[("c1", "/w/proj", "rwx"), ("c1", "/w/out", "r")],
                ["/w/proj/x", "/w/out/x"],
                &[("c1", "r")],
            ),
        ];
        for (want, names, rights) in cases {
            let d = tempfile::tempdir().unwrap();
            let file = d.path().join("grants.json");
            let mut f = Fake::default();
            for p in ["/w/proj", "/w/proj/sub", "/w/out"] {
                f.make(p);
            }
            f.link(&names);
            let want: Vec<Grant> = want.iter().map(|(c, p, a)| grant(c, p, a)).collect();
            let s = sync(&file, &want, &mut f);
            assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
            for (c, a) in rights {
                assert_eq!(f.may(names[0], c), access(a), "{c} on {names:?}");
            }
        }

        // In a sync that finds a granted folder moved, the grants' paths do
        // not show what holds a name.
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        for p in ["/w/proj", "/w/other"] {
            f.make(p);
        }
        let other = grant("c2", "/w/other", "r");
        sync(&file, std::slice::from_ref(&other), &mut f);
        f.mv("/w/other", "/w/moved");
        f.link(&["/w/proj/target/a", "/w/proj/target/b"]);
        let s = sync(&file, &[grant("c1", "/w/proj", "rw"), other], &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        assert_eq!(f.may("/w/proj/target/a", "c1"), access("r"));
    }

    /// pnpm, uv and a local `git clone` link a project's files to a store
    /// outside it. A grant that commands write in goes on all the same, and
    /// the commands run: such a file is read and run through either name,
    /// not written, and a narrower grant or one taken off cuts it down as
    /// any file.
    #[test]
    fn a_file_with_a_name_elsewhere_is_read_only_for_the_commands() {
        let access = |a: &str| Some(Access::parse(a).unwrap());
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/proj");
        let x = "/w/proj/node_modules/x/index.js";
        f.link(&[x, "/store/x/index.js"]);
        for (flags, may) in [("rw", "r"), ("rwx", "rx"), ("r", "r"), ("x", "rx")] {
            let g = grant("c1", "/w/proj", flags);
            let s = sync(&file, std::slice::from_ref(&g), &mut f);
            assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
            assert!(s.refusal("c1").is_none(), "{s:?}");
            assert_eq!(f.on("/w/proj"), [("c1".to_string(), g.access)]);
            assert_eq!(f.may(x, "c1"), access(may), "{flags}");
            assert_eq!(f.may("/store/x/index.js", "c1"), access(may), "{flags}");
        }
        let s = sync(&file, &[], &mut f);
        assert!(s.errors.is_empty() && s.removed == 1, "{s:?}");
        assert_eq!(f.may(x, "c1"), access(""));
    }

    /// A folder closed inside a granted one closes a file with a name in it
    /// under every name, and the commands go on running. A later change that
    /// reaches the file through another name, and a walk into every folder,
    /// keep it closed; another pairing keeps what its grants give. Opened
    /// again, the file is read and run again, not written.
    #[test]
    fn a_closed_folder_closes_a_linked_file_under_every_name() {
        let access = |a: &str| Some(Access::parse(a).unwrap());
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/proj");
        f.make("/w/proj/node_modules");
        let (x, y) = ("/w/proj/node_modules/x", "/w/proj/src/y");
        f.link(&[x, "/store/x"]);
        f.link(&[y, "/w/proj/node_modules/y"]);
        let other = grant("c2", "/w/proj", "r");
        let want = |flags: &str| {
            vec![
                grant("c1", "/w/proj/node_modules", ""),
                grant("c1", "/w/proj", flags),
                other.clone(),
            ]
        };
        let s = sync(&file, &want("rw"), &mut f);
        assert!(s.errors.is_empty() && s.unclosed.is_empty(), "{s:?}");
        assert!(s.refusal("c1").is_none(), "{s:?}");
        assert_eq!(
            f.on("/w/proj/node_modules"),
            [("c1".to_string(), Access::NONE)]
        );
        for n in [x, "/store/x", y, "/w/proj/node_modules/y"] {
            assert_eq!(f.may(n, "c1"), None, "{n}");
        }
        assert_eq!(f.may(y, "c2"), access("r"));

        // Reached through `src`, which the pairing may write.
        let s = sync(&file, &want("rwx"), &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        assert!(f.changes.iter().any(|(p, _)| p == Path::new("/w/proj")));
        assert_eq!(f.may(y, "c1"), None);
        walk_every(&file).unwrap();
        let s = sync(&file, &want("rwx"), &mut f);
        assert!(s.errors.is_empty() && s.unclosed.is_empty(), "{s:?}");
        assert_eq!((f.may(x, "c1"), f.may(y, "c1")), (None, None));

        // Opened again.
        let s = sync(&file, &[grant("c1", "/w/proj", "rwx"), other], &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        for n in [x, y] {
            assert_eq!(f.may(n, "c1"), access("rx"), "{n}");
        }
    }

    /// A linked file the owner widened again (Explorer and `icacls` pass a
    /// folder's list down, which gives it the folder's whole entry) is cut
    /// down again by the next walk into every folder (`folder sync`); a
    /// sync that leaves the folder as it is does not reach it.
    #[test]
    fn a_widened_linked_file_is_cut_down_again() {
        let access = |a: &str| Some(Access::parse(a).unwrap());
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/proj");
        let x = "/w/proj/node_modules/x";
        f.link(&[x, "/store/x"]);
        let want = [grant("c1", "/w/proj", "rw")];
        sync(&file, &want, &mut f);
        assert_eq!(f.may(x, "c1"), access("r"));
        // Explorer passes the folder's list down: the node's own denial
        // keeps writes off.
        f.files[0].inherited = vec![("c1".into(), access("rw"))];
        f.files[0].capped = false;
        assert_eq!(f.may(x, "c1"), access("r"));
        // "Replace all child object permission entries" (or `icacls
        // /reset`) takes the node's own entries off too.
        f.files[0].own.clear();
        sync(&file, &want, &mut f);
        assert_eq!(f.may(x, "c1"), access("rw"));
        walk_every(&file).unwrap();
        let s = sync(&file, &want, &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        assert_eq!(f.may(x, "c1"), access("r"));
    }

    /// A file linked into a granted folder after its grant (an install, a
    /// clone) keeps its store's list through a sync that changes nothing
    /// there, and gets its cap once a sync walks that folder
    /// ([`Rewalk::At`], where names changed, crate::grant_watch): only that
    /// folder, in the sync's own turn. [`Rewalk::Every`] walks them all.
    #[test]
    fn a_sync_walks_the_folders_where_names_changed() {
        let access = |a: &str| Some(Access::parse(a).unwrap());
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("cfg"), d.path().join("state"));
        let mut f = Fake::default();
        f.make("/w/proj");
        f.make("/w/other");
        let want = vec![grant("c1", "/w/proj", "rw"), grant("c1", "/w/other", "r")];
        let sync_walking = |f: &mut Fake, walk: Rewalk| {
            f.changes.clear();
            let want = want.clone();
            let s = apply_in(
                &paths,
                walk,
                || (want, Vec::new(), Shut::default()),
                f,
                &mut FakeProfiles::default(),
            );
            assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        };
        sync_walking(&mut f, Rewalk::None);
        let (x, y) = ("/w/proj/node_modules/x", "/w/other/.venv/y");
        f.link(&[x, "/store/x"]);
        f.link(&[y, "/store/y"]);
        sync_walking(&mut f, Rewalk::None);
        assert_eq!(f.may(x, "c1"), access(""), "not reached");
        sync_walking(&mut f, Rewalk::At(vec!["/w/proj".into()]));
        assert_eq!(f.may(x, "c1"), access("r"));
        assert_eq!(f.may(y, "c1"), access(""), "the other folder is not walked");
        assert_eq!(f.changes, [(PathBuf::from("/w/proj"), true)]);
        sync_walking(&mut f, Rewalk::Every);
        assert_eq!(f.may(y, "c1"), access("r"));
        // Marked once: the next sync walks nothing.
        sync_walking(&mut f, Rewalk::None);
        assert!(f.changes.is_empty(), "{:?}", f.changes);
    }

    /// The places to watch come from the record alone, granted files and
    /// places with nothing there too: the node may not look at the owner's
    /// folders, and the watch looks at them as the owner
    /// (crate::grant_watch). A closed folder is no place to watch.
    #[test]
    fn the_places_to_watch_are_read_from_the_record_alone() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("cfg"), d.path().join("state"));
        let (proj, notes) = (d.path().join("proj"), d.path().join("notes.txt"));
        std::fs::create_dir(&proj).unwrap();
        let lib = d.path().join("lib");
        std::fs::create_dir(&lib).unwrap();
        std::fs::write(&notes, "n").unwrap();
        let gone = d.path().join("gone");
        let with_id = |mut g: Grant, id: &str| {
            g.id = Some(id.to_string());
            g
        };
        let grants = [
            with_id(grant("c1", proj.to_str().unwrap(), "rw"), "v:1"),
            with_id(grant("c2", proj.to_str().unwrap(), "r"), "v:1"),
            with_id(grant("c3", proj.to_str().unwrap(), "r"), "v:2"),
            with_id(grant("c1", lib.to_str().unwrap(), "r"), "v:3"),
            grant("c1", notes.to_str().unwrap(), "r"),
            grant("c1", gone.to_str().unwrap(), "r"),
            grant("c1", d.path().join("closed").to_str().unwrap(), ""),
        ];
        write_record(&record_file(&paths), &grants).unwrap();
        // Each place once, with the objects the record names there.
        let place = |path: PathBuf, ids: &[&str]| crate::grant_watch::Folder {
            path,
            ids: ids.iter().map(|i| i.to_string()).collect(),
        };
        assert_eq!(
            granted_folders(&paths),
            [
                place(gone, &[]),
                place(lib, &["v:3"]),
                place(notes, &[]),
                place(proj, &["v:1", "v:2"]),
            ]
        );
    }

    /// Two pairings whose projects are linked to one store (pnpm's): the
    /// file's list is worked out under the folder of whichever name a walk
    /// came through, which holds only that pairing's entry, yet each reads
    /// it through its own name, writes it through neither, and keeps that
    /// when the other's project is walked, changed or taken off. So does the
    /// command account, whose entry a process of either container needs
    /// too.
    #[test]
    fn a_file_linked_into_two_pairings_projects_is_read_in_both() {
        let access = |a: &str| Some(Access::parse(a).unwrap());
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/p1");
        f.make("/w/p2");
        let (x1, x2) = ("/w/p1/node_modules/x", "/w/p2/node_modules/x");
        f.link(&[x1, x2, "/store/x"]);
        let run = "S-1-5-21-1-2-3-1011";
        let (a, b) = (grant("c1", "/w/p1", "rw"), grant("c2", "/w/p2", "rw"));
        let (run_a, run_b) = (grant(run, "/w/p1", "rw"), grant(run, "/w/p2", "rw"));
        let both = [a.clone(), b.clone(), run_a.clone(), run_b.clone()];
        let s = sync(&file, &both, &mut f);
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        let reads = |f: &Fake, who: &[&str]| {
            for c in who {
                for n in [x1, x2] {
                    assert_eq!(f.may(n, c), access("r"), "{c} on {n}");
                }
            }
        };
        reads(&f, &["c1", "c2", run]);
        // A change of each project in turn, and a walk of every grant.
        let a_rwx = grant("c1", "/w/p1", "rwx");
        let s = sync(
            &file,
            &[a_rwx.clone(), b.clone(), run_a.clone(), run_b.clone()],
            &mut f,
        );
        assert!(s.errors.is_empty(), "{s:?}");
        assert_eq!(f.may(x1, "c1"), access("rx"));
        reads(&f, &["c2", run]);
        let s = sync(&file, &both, &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        walk_every(&file).unwrap();
        let s = sync(&file, &both, &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        reads(&f, &["c1", "c2", run]);
        // The second pairing goes, and the account's grant on its project.
        let s = sync(&file, &[a.clone(), run_a.clone()], &mut f);
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        reads(&f, &["c1", run]);
        assert_eq!(f.may(x2, "c2"), access(""));
    }

    /// A folder opened again inside a closed one gives a file with a name
    /// in it only its own flags, as Windows does: the closed folder's
    /// denial comes before the entries of the grants around it. So an `rw`
    /// or `r` folder inside a closed folder of an `rwx` project gives no
    /// execute of a file a command linked from it into the project.
    #[test]
    fn a_folder_opened_inside_a_closed_one_gives_a_linked_file_only_its_own_flags() {
        let access = |a: &str| Some(Access::parse(a).unwrap());
        let (report, l) = ("/w/proj/vault/inbox/report", "/w/proj/src/l");
        for (outer, inner, may) in [("rwx", "rw", "r"), ("rwx", "r", "r")] {
            let d = tempfile::tempdir().unwrap();
            let file = d.path().join("grants.json");
            let mut f = Fake::default();
            for p in ["/w/proj", "/w/proj/vault", "/w/proj/vault/inbox"] {
                f.make(p);
            }
            f.link(&[report, l]);
            let want = [
                grant("c1", "/w/proj", outer),
                grant("c1", "/w/proj/vault", ""),
                grant("c1", "/w/proj/vault/inbox", inner),
            ];
            let s = sync(&file, &want, &mut f);
            assert!(s.errors.is_empty() && s.unclosed.is_empty(), "{s:?}");
            for n in [report, l] {
                assert_eq!(f.may(n, "c1"), access(may), "{outer} {inner}: {n}");
            }
        }
    }

    /// A closed folder that a command renamed keeps its deny where it went
    /// (`Grant::closed_at`), and so a file with a name in it stays closed
    /// under every name: a later change that reaches the file through a
    /// name in the open folder around it does not open it.
    #[test]
    fn a_closed_folder_a_command_moved_keeps_its_linked_files_closed() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/proj");
        f.make("/w/proj/secret");
        f.link(&["/w/proj/secret/repo/obj", "/w/proj/work/obj"]);
        let want = |flags: &str| {
            [
                grant("c1", "/w/proj", flags),
                grant("c1", "/w/proj/secret", ""),
            ]
        };
        let s = sync(&file, &want("rw"), &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        assert_eq!(f.may("/w/proj/work/obj", "c1"), None);
        // Renamed through the rights of `proj`, with its files.
        f.mv("/w/proj/secret", "/w/proj/s2");
        f.files[0].names[0] = "/w/proj/s2/repo/obj".into();
        for flags in ["rw", "rwx"] {
            let s = sync(&file, &want(flags), &mut f);
            assert!(s.errors.is_empty(), "{flags}: {s:?}");
            assert!(f.changes.iter().any(|(p, _)| p == Path::new("/w/proj")));
            for n in ["/w/proj/work/obj", "/w/proj/s2/repo/obj"] {
                assert_eq!(f.may(n, "c1"), None, "{flags}: {n}");
            }
        }
    }

    /// A file linked across the edge of a closed folder is judged by the
    /// names it has when the walk reaches it, and a command may rename the
    /// closed folder meanwhile (through the rights of the folder around
    /// it). So where a closed folder lies inside the walked one, no such
    /// file gets the change as any file, which would give it the whole list
    /// of the folder around the closed one, write included: it gets read
    /// and execute at most. Without a closed folder inside, it does.
    // The fake volume's `/w/...` paths are no paths on Windows, where the
    // pass resolves them on the real disk (`Judge::new`) and the protected
    // entries are Windows' own: win_account.rs shows these cases there.
    #[cfg(unix)]
    #[test]
    fn a_file_linked_across_a_closed_folders_edge_is_capped() {
        let access = |a: &str| Some(Access::parse(a).unwrap());
        for (closed, rights) in [("/w/proj/vault", "r"), ("/w/other/vault", "rw")] {
            let d = tempfile::tempdir().unwrap();
            let file = d.path().join("grants.json");
            let mut f = Fake::default();
            for p in ["/w/proj", "/w/proj/vault", "/w/other", "/w/other/vault"] {
                f.make(p);
            }
            // The closed folder was renamed after the sync looked at it.
            let names = ["/w/proj/v2/repo/obj", "/w/proj/work/obj"];
            f.link(&names);
            let want = [grant("c1", "/w/proj", "rw"), grant("c1", closed, "")];
            let s = sync(&file, &want, &mut f);
            assert!(s.errors.is_empty() && s.unclosed.is_empty(), "{s:?}");
            for n in names {
                assert_eq!(f.may(n, "c1"), access(rights), "{closed}: {n}");
            }
        }
    }

    /// A command goes on with the last sync's answer during a walk only
    /// while every recorded grant is where it was: a granted or closed
    /// folder moved, or removed and made again, is for a sync to react to.
    #[test]
    fn grants_are_in_place_until_a_folder_moved_or_was_made_again() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let none = Synced::default();
        let mut f = Fake::default();
        for p in ["/w/proj", "/w/proj/vault", "/w/other"] {
            f.make(p);
        }
        assert!(
            in_place_with(&file, &none, &mut f),
            "no record: nothing to move"
        );
        let want = [
            grant("c1", "/w/proj", "rw"),
            grant("c1", "/w/proj/vault", ""),
            grant("c1", "/w/other", "r"),
        ];
        let s = sync(&file, &want, &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        assert!(in_place_with(&file, &none, &mut f));
        // A closed folder renamed.
        f.mv("/w/proj/vault", "/w/proj/v2");
        assert!(!in_place_with(&file, &none, &mut f));
        f.mv("/w/proj/v2", "/w/proj/vault");
        assert!(in_place_with(&file, &none, &mut f));
        // A closed folder removed and made again.
        f.rm("/w/proj/vault");
        f.make("/w/proj/vault");
        assert!(!in_place_with(&file, &none, &mut f));
        let s = sync(&file, &want, &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        assert!(in_place_with(&file, &none, &mut f));
        // A granted folder moved away.
        f.mv("/w/other", "/w/elsewhere");
        assert!(!in_place_with(&file, &none, &mut f));
        // A record that cannot be read tells nothing.
        std::fs::write(&file, "not json").unwrap();
        assert!(!in_place_with(&file, &none, &mut f));
    }

    /// The record is read as the node, before the looks act as the owner:
    /// the installed node's state folder is closed to a standard owner, and
    /// a read that fails makes every command wait for the walk.
    #[test]
    fn the_record_is_read_before_the_looks_act_as_the_owner() {
        struct Acting<'a>(&'a Path, String);
        impl Drop for Acting<'_> {
            fn drop(&mut self) {
                std::fs::write(self.0, &self.1).unwrap();
            }
        }
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/proj");
        let s = sync(&file, &[grant("c1", "/w/proj", "rw")], &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        // While the looks act as the owner, the record cannot be read.
        let acting = || {
            let kept = std::fs::read_to_string(&file).unwrap();
            std::fs::write(&file, "not json").unwrap();
            Ok(Acting(&file, kept))
        };
        assert!(in_place_as(
            &file,
            &Synced::default(),
            acting,
            || None,
            &mut f
        ));
        // A logon that fails tells nothing.
        assert!(!in_place_as(
            &file,
            &Synced::default(),
            || Err::<(), _>(io::Error::other("no logon")),
            || None,
            &mut f
        ));
    }

    /// The owner's Documents folder moved since the last sync (OneDrive's
    /// backup into a granted folder): its PowerShell profiles are protected
    /// only once a sync split the granted folder around them, so a command
    /// does not take the last answer. The folder is read as the owner, whose
    /// registry names it.
    #[test]
    fn a_documents_folder_moved_since_the_last_sync_is_not_in_place() {
        use nerve_policy::protected::WinFolders;
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/proj");
        let mut s = sync(&file, &[grant("c1", "/w/proj", "rw")], &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        let at = |p: &str| {
            Platform::Windows(WinFolders {
                documents: vec![p.into()],
                ..WinFolders::default()
            })
        };
        s.platform = Some(at("/home/me/Documents"));
        let last = s.kept();
        let acting = std::cell::Cell::new(false);
        let mut place = |now: &str| {
            acting.set(false);
            in_place_as(
                &file,
                &last,
                || {
                    acting.set(true);
                    Ok(())
                },
                || acting.get().then(|| at(now)),
                &mut f,
            )
        };
        assert!(place("/home/me/Documents"));
        assert!(!place("/w/proj/Documents"));
    }

    /// A granted or closed folder that was not there at the last sync has no
    /// record, and neither has a grant on a volume that was away; the sync names
    /// them, so a command does not take the last answer once something is
    /// at their path.
    #[test]
    fn a_folder_that_was_not_there_at_the_last_sync_is_not_in_place_once_it_is() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let none = Synced::default();
        let mut f = Fake::default();
        for p in ["/w/proj", "/w/other"] {
            f.make(p);
        }
        let mut want = vec![
            grant("c1", "/w/proj", "rw"),
            grant("c1", "/w/proj/vault", ""),
            grant("c1", "/w/other", "r"),
        ];
        let s = sync(&file, &want, &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        assert_eq!(
            s.absent.iter().map(plain).collect::<Vec<_>>(),
            [want[1].clone()]
        );
        let last = s.kept();
        assert!(in_place_with(&file, &last, &mut f));
        // The record tells nothing of the closed folder made now.
        f.make("/w/proj/vault");
        assert!(in_place_with(&file, &none, &mut f));
        assert!(!in_place_with(&file, &last, &mut f));
        let s = sync(&file, &want, &mut f);
        assert!(s.errors.is_empty() && s.absent.is_empty(), "{s:?}");
        assert!(in_place_with(&file, &s.kept(), &mut f));
        // The same for a granted folder with flags that was not there.
        want.push(grant("c1", "/w/new", "rw"));
        let s = sync(&file, &want, &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        assert_eq!(
            s.absent.iter().map(plain).collect::<Vec<_>>(),
            [want[3].clone()]
        );
        let last = s.kept();
        assert!(in_place_with(&file, &last, &mut f));
        f.make("/w/new");
        assert!(in_place_with(&file, &none, &mut f));
        assert!(!in_place_with(&file, &last, &mut f), "made after the sync");
        let s = sync(&file, &want, &mut f);
        assert!(s.errors.is_empty() && s.absent.is_empty(), "{s:?}");
        assert!(in_place_with(&file, &s.kept(), &mut f));
        want.pop();
        // A grant the config dropped while its volume was away: the record
        // keeps it, and it is at its path again when the volume is back.
        f.mv("/w/other", "/archive/other");
        f.away = true;
        want.pop();
        let s = sync(&file, &want, &mut f);
        assert!(s.errors.is_empty() && s.away.len() == 1, "{s:?}");
        let last = s.kept();
        assert!(!in_place_with(&file, &last, &mut f), "not at its path");
        f.mv("/archive/other", "/w/other");
        f.away = false;
        assert!(in_place_with(&file, &none, &mut f));
        assert!(
            !in_place_with(&file, &last, &mut f),
            "back, and to be taken off"
        );
    }

    /// A name in the pairing's protected list, or in a folder of it
    /// without flags that has no grant (inside a folder split around a
    /// protected entry), closes a linked file under every name: no grant
    /// holds that name, so it would not restrict, and a granted name would
    /// give the file's read. A protected entry its folders release for a
    /// read does not close it.
    // The fake volume's `/w/...` paths are no paths on Windows, where the
    // pass resolves them on the real disk (`Judge::new`) and the protected
    // entries are Windows' own: win_account.rs shows these cases there.
    #[cfg(unix)]
    #[test]
    fn a_protected_or_closed_name_without_a_grant_closes_a_linked_file() {
        let access = |a: &str| Some(Access::parse(a).unwrap());
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("cfg"), d.path().join("state"));
        let file = record_file(&paths);
        let home = Path::new("/w/home");
        let mut lab = center(
            "lab",
            &[
                (&home.join("dotfiles"), "rw"),
                (&home.join("proj"), "rw"),
                (&home.join("proj/secret"), ""),
                (&home.join("open/key"), "r"),
            ],
        );
        lab.policy.protected.extra = vec![
            home.join("keys").display().to_string(),
            home.join("open/key").display().to_string(),
            home.join("dotfiles/private").display().to_string(),
        ];
        let mut cfg = NodeConfig::default();
        cfg.centers.push(lab);
        let c = container(&paths, &node("lab"));
        let shut = Shut::of(&cfg, &paths, home, &Platform::Unix);
        let mut f = Fake::default();
        for p in ["/w/home/dotfiles", "/w/home/proj/src", "/w/home/open/key"] {
            f.make(p);
        }
        f.link(&["/w/home/dotfiles/npmrc", "/w/home/.npmrc"]);
        f.link(&["/w/home/dotfiles/notes", "/w/home/notes.txt"]);
        f.link(&["/w/home/dotfiles/id", "/w/home/keys/id"]);
        f.link(&["/w/home/proj/src/obj", "/w/home/proj/secret/obj"]);
        f.link(&["/w/home/dotfiles/k", "/w/home/open/key/k"]);
        // Both names in the granted folder, one in a protected entry there.
        f.link(&["/w/home/dotfiles/x", "/w/home/dotfiles/private/x"]);
        // The split gives `proj`'s entries, not `secret`.
        let want = [
            grant(&c, "/w/home/dotfiles", "rw"),
            grant(&c, "/w/home/proj/src", "rw"),
            grant(&c, "/w/home/open/key", "r"),
        ];
        let s = sync_shut(&file, &want, &shut, &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        assert_eq!(f.may("/w/home/dotfiles/notes", &c), access("r"));
        assert_eq!(f.may("/w/home/dotfiles/npmrc", &c), None);
        assert_eq!(f.may("/w/home/dotfiles/id", &c), None);
        assert_eq!(f.may("/w/home/proj/src/obj", &c), None);
        assert_eq!(f.may("/w/home/dotfiles/k", &c), access("r"));
        assert_eq!(f.may("/w/home/dotfiles/x", &c), None);
        // Without the lists, they would be read through the granted name.
        let s = sync_shut(&file, &want, &Shut::default(), &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        walk_every(&file).unwrap();
        sync_shut(&file, &want, &Shut::default(), &mut f);
        assert_eq!(f.may("/w/home/dotfiles/id", &c), access("r"));
    }

    /// A file a command linked from its own store (pnpm's, in its
    /// container's own folder; the command account made it) into a granted
    /// project stays readable to that container and the command account
    /// after the project's grant comes off: the store's name holds it for
    /// them, so the take-off does not leave them without the entries the
    /// file had in their own store.
    #[test]
    fn a_file_from_a_containers_own_store_stays_readable_to_it() {
        let access = |a: &str| Some(Access::parse(a).unwrap());
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("cfg"), d.path().join("state"));
        let file = record_file(&paths);
        let home = Path::new("/w/home");
        let mut cfg = NodeConfig::default();
        cfg.centers
            .push(center("lab", &[(&home.join("proj"), "rw")]));
        let c = container(&paths, &node("lab"));
        let run = "S-1-5-21-1-2-3-1001";
        let run_home = Path::new("/w/run");
        let shut = Shut::of(&cfg, &paths, home, &Platform::Unix).own(&cfg, &paths, run, run_home);
        let store = crate::account::Own::in_container(run_home, &c)
            .temp
            .join("pnpm/store/x.js");
        let store = store.to_str().unwrap();
        let mut f = Fake::default();
        f.make("/w/home/proj");
        let x = "/w/home/proj/node_modules/x.js";
        f.link(&[x, store]);
        f.files[0].owner = Some(run.into());
        let want = [
            grant(&c, "/w/home/proj", "rw"),
            grant(run, "/w/home/proj", "rw"),
        ];
        let s = sync_shut(&file, &want, &shut, &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        for who in [c.as_str(), run] {
            assert_eq!(f.may(x, who), access("r"), "{who}");
        }
        let s = sync_shut(&file, &[], &shut, &mut f);
        assert!(s.errors.is_empty() && s.removed == 2, "{s:?}");
        for who in [c.as_str(), run] {
            assert_eq!(f.may(store, who), access("rx"), "{who}");
        }
    }

    /// A file of yours that a command linked from a granted folder into
    /// its container's own folder gets no read there once the folder's
    /// grant comes off: you still own it, so the container's own folder
    /// does not hold it, as on Linux, where it keeps only its own mode.
    #[test]
    fn a_file_of_yours_linked_into_a_containers_own_folder_is_not_held_there() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("cfg"), d.path().join("state"));
        let file = record_file(&paths);
        let home = Path::new("/w/home");
        let c = container(&paths, &node("lab"));
        let run = "S-1-5-21-1-2-3-1001";
        let run_home = Path::new("/w/run");
        let ac = crate::account::Own::in_container(run_home, &c).temp;
        {
            let (folder, flags) = ("/w/home/proj", "rw");
            let mut cfg = NodeConfig::default();
            cfg.centers
                .push(center("lab", &[(Path::new(folder), flags)]));
            let shut =
                Shut::of(&cfg, &paths, home, &Platform::Unix).own(&cfg, &paths, run, run_home);
            let mut f = Fake::default();
            f.make(folder);
            let mine = format!("{folder}/.env");
            let linked = ac.join("k");
            f.link(&[&mine, linked.to_str().unwrap()]);
            f.files[0].owner = Some("S-1-5-21-1-2-3-1000".into());
            let want = [grant(&c, folder, flags), grant(run, folder, flags)];
            let s = sync_shut(&file, &want, &shut, &mut f);
            assert!(s.errors.is_empty(), "{s:?}");
            for who in [c.as_str(), run] {
                let may = f.may(&mine, who).unwrap_or(Access::NONE);
                assert!(may.read, "{folder} {who}: {may:?}");
            }
            let s = sync_shut(&file, &[], &shut, &mut f);
            assert!(s.errors.is_empty() && s.removed == 2, "{s:?}");
            for who in [c.as_str(), run] {
                let may = f.may(&mine, who).unwrap_or(Access::NONE);
                assert!(
                    !may.read && !may.execute,
                    "{folder} {who} taken off: {may:?}"
                );
            }
        }
    }

    /// A container's own folder counts where it is, not where it leads:
    /// its commands may make it a link to another folder they were granted,
    /// which would otherwise hold the files there for them, so a file of an
    /// `r` folder linked into an `rwx` one would be run.
    #[cfg(unix)]
    #[test]
    fn a_containers_own_folder_made_a_link_holds_nothing_where_it_leads() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("cfg"), d.path().join("state"));
        let file = record_file(&paths);
        let home = d.path().join("home");
        let (proj, drop) = (d.path().join("proj"), d.path().join("drop"));
        for p in [&home, &proj, &drop] {
            std::fs::create_dir_all(p).unwrap();
        }
        let mut cfg = NodeConfig::default();
        cfg.centers
            .push(center("lab", &[(&proj, "rwx"), (&drop, "r")]));
        let c = container(&paths, &node("lab"));
        let run = "S-1-5-21-1-2-3-1001";
        let run_home = d.path().join("run");
        let ac = crate::account::Own::in_container(&run_home, &c).temp;
        std::fs::create_dir_all(ac.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&drop, &ac).unwrap();
        let shut = Shut::of(&cfg, &paths, &home, &Platform::Unix).own(&cfg, &paths, run, &run_home);
        let mut f = Fake::default();
        let (proj_s, drop_s) = (proj.to_str().unwrap(), drop.to_str().unwrap());
        f.make(proj_s);
        f.make(drop_s);
        let report = drop.join("report");
        let r = proj.join("r");
        f.link(&[report.to_str().unwrap(), r.to_str().unwrap()]);
        f.files[0].owner = Some(run.into());
        let want = [grant(&c, proj_s, "rwx"), grant(&c, drop_s, "r")];
        let s = sync_shut(&file, &want, &shut, &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        let may = f.may(r.to_str().unwrap(), &c).unwrap_or(Access::NONE);
        assert!(may.read && !may.execute, "{may:?}");
    }

    /// A file that was capped and later changes as any file (its other
    /// name now lies in the same folder under the same grants) loses the
    /// node's own entries: it gets what the folder gives, and a grant taken
    /// off leaves it nothing of the node's.
    // The fake volume's `/w/...` paths are no paths on Windows, where the
    // pass resolves them on the real disk (`Judge::new`) and the protected
    // entries are Windows' own: win_account.rs shows these cases there.
    #[cfg(unix)]
    #[test]
    fn a_linked_file_that_changes_as_any_file_loses_the_nodes_entries() {
        let access = |a: &str| Some(Access::parse(a).unwrap());
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/proj");
        f.link(&["/w/proj/a", "/store/a"]);
        let s = sync(&file, &[grant("c1", "/w/proj", "rw")], &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        assert_eq!(f.may("/w/proj/a", "c1"), access("r"));
        // The store's name went, and the project got a second one.
        f.files[0].names[1] = "/w/proj/b".into();
        let s = sync(&file, &[grant("c1", "/w/proj", "rwx")], &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        assert_eq!(f.may("/w/proj/a", "c1"), access("rwx"));
        assert!(f.files[0].own.is_empty(), "{:?}", f.files[0].own);
        let s = sync(&file, &[], &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        assert_eq!(f.may("/w/proj/a", "c1"), access(""));
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
            .filter(|c| c.1)
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
        let s = sync_outside_in(&paths, &both, &Shut::default(), &[], &mut f, &mut store);
        assert_eq!(s.profiles, Profiles::default());
        // No container emptied, so no profile to remove: the keys' lock is
        // not taken, and its file not made.
        assert!(!paths.keys_lock().exists());
        let held = crate::secrets::HeldByANode::take(&paths);
        let s = sync_outside_in(
            &paths,
            std::slice::from_ref(&b),
            &Shut::default(),
            &[],
            &mut f,
            &mut store,
        );
        assert_eq!(s.removed, 1);
        assert_eq!(s.profiles.kept, std::slice::from_ref(&lab));
        assert!(s.profiles.why.unwrap().contains("runs"));
        assert!(store.removed.is_empty());
        drop(held);
        // With the node stopped, the profile goes with the last grant.
        sync_outside_in(&paths, &both, &Shut::default(), &[], &mut f, &mut store);
        let s = sync_outside_in(
            &paths,
            std::slice::from_ref(&b),
            &Shut::default(),
            &[],
            &mut f,
            &mut store,
        );
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
                apply_in(&paths, Rewalk::None, Default::default, &mut f, &mut store)
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
                let s = apply_in(
                    &paths,
                    Rewalk::None,
                    Default::default,
                    &mut Fake::default(),
                    &mut store,
                );
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
        apply_in(
            &paths,
            Rewalk::None,
            || (vec![a.clone()], both(), Shut::default()),
            &mut f,
            &mut store,
        );
        // The last folder goes: the profile stays.
        let s = apply_in(
            &paths,
            Rewalk::None,
            || (Vec::new(), both(), Shut::default()),
            &mut f,
            &mut store,
        );
        assert_eq!(s.emptied, std::slice::from_ref(&lab));
        assert!(store.removed.is_empty(), "{:?}", store.removed);
        // The pairings go: both profiles go, `home` without a grant ever.
        let s = apply_in(&paths, Rewalk::None, Default::default, &mut f, &mut store);
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
            Rewalk::None,
            || (Vec::new(), vec![lab.clone()], Shut::default()),
            &mut f,
            &mut store,
        );
        let mut failing = Failing(0);
        let s = apply_in(&paths, Rewalk::None, Default::default, &mut f, &mut failing);
        assert_eq!(failing.0, 1, "{s:?}");
        apply_in(&paths, Rewalk::None, Default::default, &mut f, &mut failing);
        assert_eq!(failing.0, 2);
        apply_in(&paths, Rewalk::None, Default::default, &mut f, &mut store);
        assert_eq!(store.removed.last(), Some(&lab));
        // The CLI's sync keeps a pairing's profile too.
        f.make("/w/b");
        let b = grant(&lab, "/w/b", "r");
        store.there.push(lab.clone());
        sync_outside_in(
            &paths,
            std::slice::from_ref(&b),
            &Shut::default(),
            std::slice::from_ref(&lab),
            &mut f,
            &mut store,
        );
        let s = sync_outside_in(
            &paths,
            &[],
            &Shut::default(),
            std::slice::from_ref(&lab),
            &mut f,
            &mut store,
        );
        assert_eq!(s.emptied, std::slice::from_ref(&lab));
        assert!(
            s.profiles.removed.is_empty() && store.there.contains(&lab),
            "{s:?}"
        );
    }

    /// A pairing removed before the node's first sync saw it: the note the
    /// node makes at its start (`note_pairings`) has the first sync after
    /// the change remove its profile, though it never had a grant. Without
    /// it, `center rm` right after the start found the profile left to the
    /// owner, or not, as the start's sync came first or not.
    #[test]
    fn a_pairing_removed_before_the_first_sync_loses_its_profile() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("config"), d.path().join("state"));
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        let home = container(&paths, &node("home"));
        let lab = container(&paths, &node("lab"));
        let file = profiles_file(&paths);
        note_in(&file, std::slice::from_ref(&home)).unwrap();
        // Each once, also when noted again, beside what was there.
        note_in(&file, &[lab.clone(), home.clone()]).unwrap();
        let mut both = vec![home.clone(), lab.clone()];
        both.sort();
        assert_eq!(read_profiles(&file), Ok(both));
        let mut f = Fake::default();
        let mut store = FakeProfiles {
            there: vec![home.clone()],
            ..Default::default()
        };
        // The first sync sees the config with `lab` only.
        let s = apply_in(
            &paths,
            Rewalk::None,
            || (Vec::new(), vec![lab.clone()], Shut::default()),
            &mut f,
            &mut store,
        );
        assert!(s.errors.is_empty(), "{s:?}");
        assert_eq!(store.removed, std::slice::from_ref(&home));
        assert_eq!(read_profiles(&file), Ok(vec![lab.clone()]));
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
            Rewalk::None,
            || (current.lock().unwrap().clone(), Vec::new(), Shut::default()),
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
                    (current.lock().unwrap().clone(), Vec::new(), Shut::default())
                };
                let s = apply_in(
                    &paths,
                    Rewalk::None,
                    want,
                    &mut f,
                    &mut FakeProfiles::default(),
                );
                (s, f.all())
            })
        };
        // Time for it to read the config, were it to read it before its
        // turn; then the owner takes `a` away, and the running sync takes
        // it off.
        let _ = read_rx.recv_timeout(std::time::Duration::from_millis(300));
        current.lock().unwrap().clear();
        let s = sync_in_turn(&file, &[], &Shut::default(), &mut f);
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
        // every folder below, to take the `rw` the stopped one left there.
        f.cut.clear();
        f.changes.clear();
        let s = sync(&file, std::slice::from_ref(&r), &mut f);
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        assert_eq!(f.changes, [(PathBuf::from("/w/a"), true)]);
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
        assert_eq!(f.changes, [(PathBuf::from("/w/a"), true)]);
        assert_eq!(marks(), [false]);

        // A take-off that stops part way stays marked too.
        f.cut.push("/w/a".into());
        let s = sync(&file, &[], &mut f);
        assert_eq!(s.stale.len(), 1, "{s:?}");
        assert_eq!(marks(), [true]);
    }

    /// The node ended during a widening (killed, or the CLI stopped): the
    /// record it wrote before the change holds the mark and the flags the
    /// change was heading for, so the change back goes into every folder.
    #[test]
    fn a_change_the_node_died_in_is_walked_again_whole() {
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
        assert_eq!(f.changes, [(PathBuf::from("/w/a"), true)]);
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
            assert_eq!(f.changes, [(PathBuf::from("/x/a"), false)], "{die}");
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
                f.changes.iter().all(|(p, _)| p == Path::new("/x/a")),
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

    /// `w` reads too, also where the folders to write are split finer than
    /// the folders to read, around an entry protected for writes only
    /// (`.local/bin`) in a folder that holds no entry protected for reads
    /// (here the owner released those; on Windows `.config` and `.local`
    /// hold none): every grant that writes reads.
    #[cfg(unix)]
    #[test]
    fn every_grant_that_writes_reads() {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let home = root.join("home");
        for p in [".local/bin", ".local/state"] {
            std::fs::create_dir_all(home.join(p)).unwrap();
        }
        let paths = NodePaths::new(root.join("cfg"), root.join("state"));
        let mut lab = center("lab", &[(&home.join(".local"), "rw")]);
        lab.policy.protected.allow = [
            ".local/share/keyrings",
            ".local/share/kwalletd",
            ".local/share/flatpak/app",
            ".local/share/systemd",
        ]
        .map(|p| home.join(p).display().to_string())
        .to_vec();
        let mut cfg = NodeConfig::default();
        cfg.centers.push(lab);
        let want = wanted(&cfg, &paths, &home, &Platform::Unix);
        let state = want.iter().find(|g| g.path == home.join(".local/state"));
        assert_eq!(
            state.map(|g| g.access),
            Some(Access::parse("rw").unwrap()),
            "{want:?}"
        );
        assert!(
            want.iter().all(|g| !g.access.write || g.access.read),
            "{want:?}"
        );
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
            .push(center("lab", &[(&work, "rw"), (&secret, ""), (&apart, "")]));
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

    /// The grants a sync wants are looked at while the sync acts as whom
    /// it changes the folders as (on the service the owner, whose home the
    /// service's account may not list, so a split there would give
    /// nothing), and as the node where it cannot act so.
    #[test]
    fn the_wanted_grants_are_looked_at_as_the_sync_acts() {
        struct Acting<'a>(&'a std::cell::Cell<bool>);
        impl Drop for Acting<'_> {
            fn drop(&mut self) {
                self.0.set(false);
            }
        }
        let acting = std::cell::Cell::new(false);
        let look = || vec![grant("c", "/x", if acting.get() { "r" } else { "" })];
        let seen = looked_as(
            || {
                acting.set(true);
                Ok(Acting(&acting))
            },
            look,
        );
        assert_eq!(seen, vec![grant("c", "/x", "r")]);
        assert!(!acting.get());
        let seen = looked_as(|| Err::<(), _>(io::Error::other("no logon")), look);
        assert_eq!(seen, vec![grant("c", "/x", "")]);
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

    /// A closed folder whose denying entry does not go on (refused, failed,
    /// or not on any more) stops its container's commands, since the folder
    /// keeps the rights of the granted folder around it; other containers
    /// run.
    #[test]
    fn a_closed_folder_that_is_not_closed_stops_its_containers_commands() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/a");
        f.make("/w/a/closed");
        f.make("/w/b");
        let (a, closed) = (grant("c1", "/w/a", "rw"), grant("c1", "/w/a/closed", ""));
        let b = grant("c2", "/w/b", "rw");
        let want = [a.clone(), closed.clone(), b.clone()];
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
            &[(&work, "rw"), (&bin, "rwx"), (&outbox, "rw")],
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
                g(&lab, &outbox, "rw"),
                g(&home, &real_work.join("bin"), "r"),
            ])
        );

        std::fs::remove_dir(real_work.join("bin")).unwrap();
        std::os::unix::fs::symlink(&outbox, real_work.join("bin")).unwrap();
        let swapped = wanted(&cfg, &paths, &root, &Platform::Unix);
        assert_eq!(
            sorted(swapped.clone()),
            sorted(vec![g(&lab, &real_work, "rw"), g(&lab, &outbox, "rw")])
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
            [(lab.clone(), Access::parse("rw").unwrap())]
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
            &[(&work, "rw"), (&bin, "rwx"), (&outbox, "rw")],
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
            sorted(vec![g(&real_work, "rw"), g(&bin, "rwx"), g(&outbox, "rw"),])
        );

        // A command swaps the real nested folder for a link to the outbox.
        std::fs::remove_dir(&bin).unwrap();
        std::os::unix::fs::symlink(&outbox, &bin).unwrap();
        let swapped = wanted(&cfg, &paths, &root, &Platform::Unix);
        assert_eq!(
            sorted(swapped),
            sorted(vec![g(&real_work, "rw"), g(&outbox, "rw")]),
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
            &[(&work, "rw"), (&spelled, "rwx"), (&outbox, "rw")],
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
        assert_eq!(on(&want, &outbox), ["rw"], "{want:?}");

        // A command swaps the real nested folder for a junction to the
        // outbox.
        std::fs::remove_dir(&bin).unwrap();
        junction(&bin, &outbox);
        let swapped = wanted(&cfg, &paths, &root, &platform);
        assert_eq!(
            on(&swapped, &outbox),
            ["rw"],
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
    /// it, and so do cargo's files. A file linked in from outside the project
    /// changes nothing of that: it gets read and run, under both names, and
    /// a denying entry of every other right, and loses both with the grant.
    /// A project moved away loses its grant where it is now.
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

        // The container's lines of a list, and whether one allows a write.
        let ours = |p: &Path| -> Vec<String> {
            icacls(p)
                .lines()
                .filter(|l| l.contains("S-1-15-2-"))
                .map(str::to_string)
                .collect()
        };
        let writes = |l: &String| ["(W", ",W", "(M)", "(F)"].iter().any(|w| l.contains(w));
        let built = proj.join("target\\debug\\deps\\demo-0123.exe");
        assert!(ours(&built).iter().any(writes), "{}", icacls(&built));

        // A link from target to a file outside.
        let secret = outside.join("target\\secret.txt");
        std::fs::create_dir_all(secret.parent().unwrap()).unwrap();
        std::fs::write(&secret, "secret").unwrap();
        // Its permissions marked inherited, as Windows keeps them in a
        // user's folders. A test's temporary folder has them unmarked, and a
        // file whose unmarked permissions differ from what the folder it is
        // linked into gives keeps them as its own.
        let marks = "nerve.test.marks";
        let m = nerve_sandbox::acl::masks(true, false, false);
        nerve_sandbox::appcontainer::set(&outside, marks, Some(m), false).unwrap();
        nerve_sandbox::appcontainer::set(&outside, marks, None, false).unwrap();
        let linked = proj.join("target\\debug\\s");
        std::fs::hard_link(&secret, &linked).unwrap();
        let s = windows_sync(&paths, &want(Some("rw")), &mut |_| {});
        assert!(s.errors.is_empty() && s.refusal(&lab).is_none(), "{s:?}");
        assert!(carries(&proj, &lab, "rw"), "{}", icacls(&proj));
        for p in [&secret, &linked] {
            let lines = ours(p);
            assert!(lines.iter().any(|l| l.contains("(DENY)")), "{lines:?}");
            let allows: Vec<&String> = lines.iter().filter(|l| !l.contains("(DENY)")).collect();
            assert!(
                !allows.is_empty() && !allows.iter().any(|l| writes(l)),
                "{lines:?}"
            );
        }
        assert!(ours(&built).iter().any(writes), "{}", icacls(&built));
        // Taken off: neither name keeps anything of the container's.
        let s = windows_sync(&paths, &want(None), &mut |_| {});
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        assert_eq!(s.removed, 1, "{s:?}");
        for p in [&proj, &secret, &built] {
            assert!(ours(p).is_empty(), "{}", icacls(p));
        }
        let s = windows_sync(&paths, &want(Some("rwx")), &mut |_| {});
        assert!(s.errors.is_empty(), "{s:?}");
        assert!(carries(&proj, &lab, "rwx"), "{}", icacls(&proj));

        // Moved: it loses its grant where it is now.
        std::fs::rename(&proj, &proj2).unwrap();
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
        for p in [&proj, &secret, &built] {
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
            &[(&work, "rw"), (&bin, "rwx"), (&outbox, "rw")],
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
        assert!(carries(&outbox, &lab, "rw"), "{}", icacls(&outbox));

        let s = windows_sync(&paths, &want, &mut |_| {});
        assert_eq!(s.errors.len(), 1, "{s:?}");
        assert!(s.errors[0].contains("junction"), "{s:?}");
        assert!(carries(&outbox, &lab, "rw"), "{}", icacls(&outbox));

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
