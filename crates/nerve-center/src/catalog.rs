//! What a node offers the agent, as the center checked it
//! (docs/dev/spec/protocol.md §6).
//!
//! The descriptor is the node's own word. The catalog is the center's reading
//! of it: one unit per action (and per state key, event and stream of a
//! program's capability), named `cap.action`, whose names and schemas
//! the center can check, and the units it leaves out (broken), each with the
//! reason. One bad unit leaves out that unit only; the rest of the node stays
//! usable.
//!
//! The catalog is derived from the descriptor and never stored: it is built
//! again whenever the descriptor changes and after the state file is read.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde::Serialize;
use serde_json::{Value, json};

use nerve_proto::descriptor::{
    Access, AccessMode, Exposure, FolderAccess, bad_member_name, plain_line,
};
use nerve_proto::schema::{self, Role};
use nerve_proto::{Descriptor, Effect, UnitKind};

use crate::jobs::WAIT_MS_MAX;
use crate::listing::one_line;
use crate::streams::{READ_DEFAULT, READ_MAX, READ_MIN};
use crate::tools::{CENTER_CAPS, RESERVED_CAPS};
use crate::util;

/// The provider of the units the center serves itself.
pub const CENTER: &str = "center";

/// The longest description a unit keeps, in bytes. A model needs a few
/// sentences, and a node's long text is not copied into every unit.
pub const DESCRIPTION_MAX: usize = 2048;

/// The longest capability or action name, in bytes: a node refuses a
/// longer one, and the center leaves out its capability or action.
pub use nerve_proto::descriptor::NAME_MAX;

/// The most folders a listing names; the rest are counted.
pub const FOLDERS_MAX: usize = 64;
/// The longest folder path a listing repeats, in bytes.
const PATH_MAX: usize = 1024;
/// The longest account name a listing repeats, in bytes.
const ACCOUNT_MAX: usize = 64;

/// What the node told this center it may do there (its descriptor's
/// `access`), as the center read it: well-formed folders only, each named as
/// the node wrote it (cut when long), at most [`FOLDERS_MAX`] of them, the
/// account's own ones kept first.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Reach {
    pub mode: AccessMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    pub confined: bool,
    /// The owner's sudo allow list for this center names commands and the
    /// node's sudo switch is on, so those run by that list alone
    /// ([`Access::sudo`]).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub sudo: bool,
    /// In folder mode the node reads as the command account, so a read goes
    /// as far as that account may read ([`Access::reads_by_account`]).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub reads_by_account: bool,
    pub folders: Vec<FolderAccess>,
    /// The folders past [`FOLDERS_MAX`], not named.
    pub more_folders: usize,
    /// The granted folders the node left out for their names
    /// ([`Access::unnamed`]).
    #[serde(skip_serializing_if = "is_zero")]
    pub unnamed: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl Reach {
    fn read(a: &Access) -> Reach {
        // A path is absolute in the center's form, and the flags are one to
        // three of `r`, `w`, `x`; a folder that is not is left out, as it
        // names nothing a call could use. So is a path that would read
        // otherwise on one line: shown changed, it would name another place.
        let mut folders: Vec<FolderAccess> = a
            .folders
            .iter()
            .filter(|f| f.path.starts_with('/') && plain_line(&f.path) && f.flags().is_some())
            .map(|f| FolderAccess {
                path: util::clip(&f.path, PATH_MAX),
                access: f.access.clone(),
                own: f.own,
                closed_below: f.closed_below,
            })
            .collect();
        let all = folders.len();
        // Past the limit the account's own folders are kept before the
        // others, in the node's order: the advice turns on them, and a node
        // lists them after the owner's grants.
        let mut own_room = folders.iter().filter(|f| f.own).count().min(FOLDERS_MAX);
        let mut other_room = FOLDERS_MAX - own_room;
        folders.retain(|f| {
            let room = if f.own {
                &mut own_room
            } else {
                &mut other_room
            };
            let keep = *room > 0;
            *room = room.saturating_sub(1);
            keep
        });
        let more_folders = all - folders.len();
        Reach {
            mode: a.mode,
            until_ms: a.until_ms,
            account: a
                .account
                .as_deref()
                .map(|n| util::clip(&one_line(n), ACCOUNT_MAX))
                .filter(|n| !n.is_empty()),
            confined: a.confined,
            sudo: a.sudo,
            reads_by_account: a.reads_by_account,
            folders,
            more_folders,
            unnamed: a.unnamed,
        }
    }

    /// The folders as one line: `/home/me/proj (rw, some folders below
    /// allow less), /tmp (rwx, own)`.
    pub fn folder_list(&self) -> String {
        let mut parts: Vec<String> = self
            .folders
            .iter()
            .map(|f| {
                let own = if f.own { ", own" } else { "" };
                let closed = if f.closed_below {
                    ", some folders below allow less"
                } else {
                    ""
                };
                format!("{} ({}{own}{closed})", f.path, f.access)
            })
            .collect();
        if self.more_folders > 0 {
            parts.push(format!("{} more", self.more_folders));
        }
        if self.unnamed > 0 {
            parts.push(format!(
                "{} more whose names cannot be shown on one line",
                self.unnamed
            ));
        }
        parts.join(", ")
    }

    /// Whether the node named or counted no folder at all.
    pub fn no_folder(&self) -> bool {
        self.folders.is_empty() && self.more_folders == 0 && self.unnamed == 0
    }

    /// The folder note of the units that take paths (`fs.*`, `exec.run`,
    /// any action whose schema marks one with `x-nerve-path`) in folder
    /// mode: the folders as the node named them, which stand inside the
    /// device-content framing and which the units' hash covers. None in
    /// the other modes.
    fn note(&self) -> Option<String> {
        if self.mode != AccessMode::Folder {
            return None;
        }
        if self.no_folder() {
            return Some("none granted".into());
        }
        Some(self.folder_list())
    }

    /// What the center says of the folder note, in its own words and
    /// outside the framing: how to read it, how far a read goes, what holds
    /// the commands, and where files go. Where the node reads as the command
    /// account (`reads_by_account`), a file call reads in the `r` folders
    /// and, if its effect is read, outside every folder what is open to
    /// every account; writes, a command's start and the reads of other
    /// calls keep to the folders; elsewhere every
    /// path a call names does. The advice of a command (this one) says
    /// nothing of file calls' reads, which a command does not get. A sandbox holds what a
    /// command reaches to the folders that grant something, closed ones
    /// below them included, and without one (`confined` false) only its
    /// account holds it. A command on the sudo allow list is held by
    /// neither. Files made
    /// in the owner's folders should stay readable for the owner, which
    /// matters only where the commands run as an account of their own (the
    /// node then marks that account's folders `own`). Those folders are
    /// shared by every pairing whose commands run as that account, and
    /// `/tmp` by every account on the machine, the settings and caches its
    /// programs keep there included, so they are for throwaway files only.
    /// None outside folder mode.
    pub fn advice(&self) -> Option<String> {
        self.advice_on(false, true)
    }

    /// The advice for the calls that name paths but start no command:
    /// [`Reach::advice`] without what holds a command (the sandbox, the
    /// sudo list), which none of them depends on. `fs.*` and other
    /// capabilities' path-taking actions carry it, so a sudo or sandbox
    /// change does not ask for a new `list` of them.
    pub fn file_advice(&self) -> Option<String> {
        self.advice_on(true, false)
    }

    /// The advice for an answer that details file calls and `exec.run`
    /// together: [`Reach::advice`], and where the node reads as the command
    /// account also what [`Reach::file_advice`] says of reads and writes,
    /// which the command's advice leaves out.
    pub fn all_advice(&self) -> Option<String> {
        self.advice_on(true, true)
    }

    fn advice_on(&self, files: bool, commands: bool) -> Option<String> {
        self.note()?;
        // Where the node reads as the command account, the folders hold
        // only what a call writes, where a command starts and what a call
        // that is no read reads; outside them a read reads what every
        // account may. A program other
        // than the node reads with the owner's rights, so the node hands it
        // no folder there, and the command account's own folders do not
        // count for it. A capability of the node's config that runs as the
        // command account is a command of that account, and its details say
        // so: it reads what that account may, but where a sandbox holds the
        // commands, only within the folders and the system's files. Said
        // whether one does, so the advice of file calls stays apart from
        // the sandbox.
        const OPEN: &str = "what is open to every account on the machine, except protected \
                            paths and the node's own files";
        const NO_FOLDER: &str = "An action of any capability but fs may name a file there, \
                                 never a folder: its program would read below it with the \
                                 owner's rights. For such an action a folder marked own counts \
                                 as none: it is the command account's, not the owner's. One \
                                 whose details say it runs as the command account is a command \
                                 of that account: it reads what that account may, and where the \
                                 machine's sandbox holds the commands, only in the folders of \
                                 the `folders:` line and the system's files.";
        let reads = self.reads_by_account;
        if self.no_folder() && !commands {
            return Some(if reads {
                format!(
                    "The node is in folder mode with no folder granted: a call whose effect is \
                     read may read {OPEN}; any other call that names a path is refused until its \
                     owner grants a folder. {NO_FOLDER}"
                )
            } else {
                "The node is in folder mode with no folder granted: its calls that name paths \
                 are refused until its owner grants one."
                    .into()
            });
        }
        if self.no_folder() && reads && files {
            let sudo = if self.sudo {
                ", except one on the owner's sudo list for you, which runs by that list alone, \
                 with full rights"
            } else {
                ""
            };
            return Some(format!(
                "The node is in folder mode with no folder granted: a call whose effect is read \
                 may read {OPEN}; any other call that names a path is refused until its owner \
                 grants a folder, and so are its commands{sudo}. {NO_FOLDER}"
            ));
        }
        if self.no_folder() && reads {
            return Some(if self.sudo {
                "The node is in folder mode with no folder granted: its commands are refused \
                 until its owner grants one, except one on the owner's sudo list for you, which \
                 runs by that list alone, with full rights."
                    .into()
            } else {
                "The node is in folder mode with no folder granted: its commands are refused \
                 until its owner grants one."
                    .into()
            });
        }
        if self.no_folder() {
            return Some(if self.sudo {
                "The node is in folder mode with no folder granted: its calls that name paths \
                 are refused until its owner grants one, and so are its commands, except one on \
                 the owner's sudo list for you, which runs by that list alone, with full rights."
            } else {
                "The node is in folder mode with no folder granted: its calls that name paths and \
                 its commands are refused until its owner grants one."
            }
            .into());
        }
        let mut out = if reads && commands && files {
            format!(
                "The node is in folder mode: a call may read in the folders of the `folders:` \
                 line marked r, and one whose effect is read also, outside every folder, {OPEN}. \
                 {NO_FOLDER} A call may write only in the folders marked w, and a command may \
                 start only in one marked x (r read, w write, x run commands)"
            )
        } else if reads && commands {
            "The node is in folder mode: a command may start only in a folder of the \
             `folders:` line marked x (r read, w write, x run commands)"
                .to_string()
        } else if reads {
            format!(
                "The node is in folder mode: a call may read in the folders of the `folders:` \
                 line marked r, and one whose effect is read also, outside every folder, {OPEN}. \
                 {NO_FOLDER} A call may write only in the folders marked w (r read, w write, x \
                 run commands)"
            )
        } else {
            "The node is in folder mode: its calls may name paths only in the folders of the \
             `folders:` line (r read, w write, x run commands)"
                .to_string()
        };
        if commands && !reads {
            out.push_str(", and a command may start only in one marked x");
        }
        out.push_str(". Where folders nest, the deepest one decides.");
        if commands {
            out.push_str(if self.confined {
                " The machine's sandbox holds what a command reaches to these folders and the \
                 system's files."
            } else {
                " The machine does not hold what a command reaches to these folders: where it \
                 runs commands, they reach what the account they run as may reach."
            });
        }
        if commands && self.sudo {
            out.push_str(
                " A command on the owner's sudo list for you runs by that list alone, with full \
                 rights: in any folder, and beyond the folders and the sandbox.",
            );
        }
        if self.folders.iter().any(|f| f.closed_below) {
            out.push_str(
                " A folder marked \"some folders below allow less\" holds folders, not named, \
                 that allow less than it or nothing, where a file call or a command's start may \
                 be refused; a command started in a folder around them still reaches them.",
            );
        }
        if self.folders.iter().any(|f| f.own) {
            out.push_str(
                " Its commands run as an account of their own, not as the machine's owner, \
                 whose access to the files they make goes through the group bits: keep those, \
                 0640 or 0660 for files and 0750 or 0770 for folders, not 0600 or 0700 unless \
                 asked.",
            );
        }
        // The advice stands outside the framing, so it names no path: the
        // paths are the node's words.
        if self
            .folders
            .iter()
            .any(|f| f.own && f.flags().is_some_and(|(_, w, _)| w))
        {
            out.push_str(
                " The folders marked own belong to that account, and every pairing whose \
                 commands run as it shares them (a temporary folder also every account on the \
                 machine), with the settings and caches its programs keep there: what one \
                 pairing leaves there can change what another one's commands do. Use one \
                 marked w for throwaway files only, keep nothing secret there, and change no \
                 program's settings there unless asked.",
            );
        }
        Some(out)
    }
}

/// One action a node offers, with schemas that passed the subset check.
#[derive(Debug, Clone, PartialEq)]
pub struct Unit {
    /// `cap.action`.
    pub name: String,
    pub cap: String,
    pub action: String,
    pub effect: Effect,
    /// What `list` tells of it: the action's own summary, else its
    /// capability's, on one line and cut at [`DESCRIPTION_MAX`]. Not both: a
    /// capability's summary speaks of all its actions ("stat, list, read …
    /// and write"), and a model shown it beside one action took that action
    /// to do them all. The units without a summary of their own share their
    /// capability's text.
    pub description: Arc<str>,
    /// Always an object schema: a descriptor without params takes any
    /// arguments, as the node does.
    pub params: Value,
    /// `null` when the descriptor states no result.
    pub result: Value,
    /// `node` for a built-in capability, else the provider's name, shared by
    /// the capability's units.
    pub provider: Arc<str>,
    /// The node's owner switched it, or its whole capability, off: it is
    /// named as off and cannot be called.
    pub off: bool,
    /// In folder mode, the folders the units that take paths may use and
    /// how ([`Reach::note`]); shared by the node's units that have it.
    pub note: Option<Arc<str>>,
    /// The center's advice on that note, for the units that have one:
    /// [`Reach::advice`] for `exec.run`, [`Reach::file_advice`] for the
    /// others.
    /// The details show the fullest one once for all of them; the hash
    /// covers it, so a sudo list or sandbox that changes what `exec.run`'s
    /// says asks for a new `list` of it, not of the file calls.
    pub advice: Option<Arc<str>>,
    /// The node runs it as its command account and holds it like `fs`
    /// (a capability of its config, `Action::as_account`): the details say
    /// so, as the advice on the folders tells such an action apart.
    pub as_account: bool,
    /// What `execute` does with it: calls an action, reads a state key
    /// (`get`), subscribes to an event, or opens a stream.
    pub kind: UnitKind,
}

impl Unit {
    /// What the model was told of this unit, as one number: SHA-256 over
    /// its name, effect, description, params, result, folder note and the
    /// center's advice on it, cut to 53 bits so it is exact as a JSON
    /// number. `execute` compares it with the one `list` gave the session: a
    /// unit that changed must be listed again, while a rule, mode or
    /// `until` change on the node leaves it alone, unless it changes what
    /// the folder note or the advice says.
    pub fn hash(&self) -> u64 {
        let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
        // Each part with its length first, so no two units run together
        // into the same bytes. The schemas' keys are sorted (serde_json's
        // map), so the same schema gives the same text.
        for part in [
            self.name.clone(),
            self.effect.as_str().to_string(),
            self.description.to_string(),
            self.params.to_string(),
            self.result.to_string(),
            self.note.as_deref().unwrap_or("").to_string(),
            self.advice.as_deref().unwrap_or("").to_string(),
        ] {
            ctx.update(&(part.len() as u64).to_be_bytes());
            ctx.update(part.as_bytes());
        }
        // Only where it is set, so the units of programs and the node keep
        // their numbers.
        if self.as_account {
            ctx.update(b"as_account");
        }
        if self.kind != UnitKind::Action {
            ctx.update(self.kind.as_str().as_bytes());
        }
        let d = ctx.finish();
        let mut first = [0u8; 8];
        first.copy_from_slice(&d.as_ref()[..8]);
        u64::from_be_bytes(first) & ((1 << 53) - 1)
    }
}

/// A unit the center leaves out, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Broken {
    /// `cap.action`, or the capability's id when a schema of a capability
    /// without actions is outside the subset.
    pub name: String,
    pub reason: String,
}

/// A node's units and the ones left out, both sorted by name. The built-in
/// capabilities `node`, `settings` and `audit` are in neither: they are the
/// center's own business, never the agent's.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Catalog {
    pub units: Vec<Unit>,
    pub broken: Vec<Broken>,
    /// What the node told this center it may do there; none when it did
    /// not say.
    pub reach: Option<Reach>,
}

impl Catalog {
    pub fn build(d: &Descriptor) -> Catalog {
        let mut c = Catalog {
            reach: d.access.as_ref().map(Reach::read),
            ..Catalog::default()
        };
        let note: Option<Arc<str>> = c.reach.as_ref().and_then(Reach::note).map(Into::into);
        let advice: Option<Arc<str>> = c.reach.as_ref().and_then(Reach::advice).map(Into::into);
        let file_advice: Option<Arc<str>> = c
            .reach
            .as_ref()
            .and_then(Reach::file_advice)
            .map(Into::into);

        // A capability id given twice would make `cap.action` name two
        // actions: `list` would show one and `execute` might check the
        // other. Neither is offered.
        let mut count: HashMap<&str, usize> = HashMap::new();
        for cap in &d.capabilities {
            *count.entry(cap.id.as_str()).or_default() += 1;
        }
        let mut left_out: HashSet<&str> = HashSet::new();
        for cap in &d.capabilities {
            if RESERVED_CAPS.contains(&cap.id.as_str()) {
                continue;
            }
            // `job` and `stream` are the center's: a node's capability of that
            // name would stand beside the center's own units under it.
            if CENTER_CAPS.contains(&cap.id.as_str()) {
                if left_out.insert(cap.id.as_str()) {
                    c.broken.push(Broken {
                        name: cap.id.clone(),
                        reason: format!(
                            "capability {}: the name is the center's own, for the units it serves itself",
                            cap.id
                        ),
                    });
                }
                continue;
            }
            // A capability whose name is not offered is one entry, however
            // many actions it has: its name is never copied into each.
            let unnamed = bad_name("capability", &cap.id).or_else(|| {
                (count[cap.id.as_str()] > 1).then(|| "named twice in the description".to_string())
            });
            if let Some(reason) = unnamed {
                if left_out.insert(cap.id.as_str()) {
                    c.broken.push(Broken {
                        name: shown_name(&cap.id),
                        reason,
                    });
                }
                continue;
            }
            // A capability's event data and state are checked as well, so
            // every schema the node publishes keeps to the subset; one that
            // does not leaves out the whole capability.
            let cap_description = described(&cap.summary);
            let provider: Arc<str> = cap.provider.as_str().into();
            let node = cap.provider == "node";
            // A program's state keys and events are units of their own, each
            // checked alone below.
            let whole = if node { cap_outside_subset(cap) } else { None };
            if cap.actions.is_empty()
                && let Some(reason) = whole.clone()
            {
                c.broken.push(Broken {
                    name: cap.id.clone(),
                    reason,
                });
            }
            // In a program's capability a name given to two kinds of unit
            // would name two things: neither is offered.
            let twice = if node {
                Default::default()
            } else {
                cap.names_twice()
            };
            for (action, def) in &cap.actions {
                if twice.contains(action.as_str()) {
                    c.broken.push(Broken {
                        name: format!("{}.{}", cap.id, shown_name(action)),
                        reason: TWICE.into(),
                    });
                    continue;
                }
                if let Some(reason) = bad_name("action", action) {
                    c.broken.push(Broken {
                        name: format!("{}.{}", cap.id, shown_name(action)),
                        reason,
                    });
                    continue;
                }
                let name = format!("{}.{action}", cap.id);
                if let Some(reason) = whole.clone() {
                    c.broken.push(Broken { name, reason });
                    continue;
                }
                let params = if def.params.is_null() {
                    json!({"type": "object"})
                } else {
                    def.params.clone()
                };
                if let Some(reason) = outside_subset(&params, &def.result) {
                    c.broken.push(Broken { name, reason });
                    continue;
                }
                // The node's `exec.signal` names its call by the `invoke` id,
                // which only the center knows: the agent names the job, and
                // the center maps it (docs/dev/spec/harness.md §4.4).
                let (params, own) = if is_signal(&cap.id, action) {
                    match signal_by_job(&params) {
                        Ok(p) => (p, Some(described(SIGNAL_SUMMARY))),
                        Err(reason) => {
                            c.broken.push(Broken { name, reason });
                            continue;
                        }
                    }
                } else {
                    (params, None)
                };
                // The actions that take paths are bound by the folders,
                // whoever provides them: `fs.*`, `exec.run` and any other
                // whose schema marks a path. `exec.signal` names a call, not
                // a path, so a grant leaves it alone. Of them only
                // `exec.run` starts a command.
                let bound = !schema::path_args(&params).is_empty();
                let command = node && cap.id == "exec" && action == "run";
                c.units.push(Unit {
                    name,
                    cap: cap.id.clone(),
                    action: action.clone(),
                    effect: def.effect,
                    description: match own.unwrap_or_else(|| described(&def.summary)) {
                        own if own.is_empty() => cap_description.clone(),
                        own => own,
                    },
                    params,
                    result: def.result.clone(),
                    provider: provider.clone(),
                    off: cap.exposure == Exposure::Off || def.exposure == Some(Exposure::Off),
                    note: note.clone().filter(|_| bound),
                    // Only `exec.run` carries what holds a command, so a
                    // sudo or sandbox change leaves the other calls alone.
                    advice: if command {
                        advice.clone()
                    } else {
                        file_advice.clone()
                    }
                    .filter(|_| bound),
                    as_account: def.as_account,
                    kind: UnitKind::Action,
                });
            }
            if !node {
                program_units(&mut c, cap, &cap_description, &provider);
            }
        }
        // Beside a node's own units only: a node that offers nothing runs
        // no call that could become a job.
        if c.units.iter().any(|u| !u.off) {
            c.units.extend(center_units());
        }
        c.units.sort_by(|a, b| a.name.cmp(&b.name));
        c.broken.sort_by(|a, b| a.name.cmp(&b.name));
        c
    }

    /// The unit `name` (`cap.action`); none for a broken or unknown one.
    /// Found by halving: `execute` and `list` ask for units under the
    /// store's lock, and a node may offer many.
    pub fn unit(&self, name: &str) -> Option<&Unit> {
        self.units
            .binary_search_by(|u| u.name.as_str().cmp(name))
            .ok()
            .map(|i| &self.units[i])
    }

    /// Why `name` (`cap.action`) is left out, when it or its whole
    /// capability is.
    pub fn broken(&self, name: &str) -> Option<&Broken> {
        self.broken.iter().find(|b| {
            name.strip_prefix(b.name.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
        })
    }

    /// Whether `cap.action` is a unit, so it may be offered to the agent.
    pub fn offers(&self, cap: &str, action: &str) -> bool {
        self.unit(&format!("{cap}.{action}")).is_some()
    }
}

/// Why a unit of a program's capability is left out whose name the
/// capability gives to two kinds of unit.
const TWICE: &str = "its name is given to more than one of the capability's actions, state keys, events and streams";

/// The params of a state key or an event: `execute` takes no arguments.
fn no_args() -> Value {
    json!({"type": "object", "additionalProperties": false})
}

/// The state keys, events and streams of the program's capability `cap` as
/// units, beside its actions: a state key is read with `get`, an event is
/// subscribed to, a stream is opened (docs/dev/spec/harness.md §4.5). Each
/// is checked alone; one whose name is given twice, or whose schema is
/// outside the subset, is left out with the reason.
fn program_units(
    c: &mut Catalog,
    cap: &nerve_proto::Capability,
    cap_description: &Arc<str>,
    provider: &Arc<str>,
) {
    let twice = cap.names_twice();
    let cap_off = cap.exposure == Exposure::Off;
    let mut add = |name: &str,
                   kind: UnitKind,
                   effect: Effect,
                   summary: &str,
                   params: Value,
                   result: Value,
                   off: bool,
                   bad: Option<String>| {
        let full = format!("{}.{}", cap.id, shown_name(name));
        let reason = bad_name(kind.as_str(), name)
            .or_else(|| twice.contains(name).then(|| TWICE.to_string()))
            .or(bad);
        if let Some(reason) = reason {
            c.broken.push(Broken { name: full, reason });
            return;
        }
        c.units.push(Unit {
            name: full,
            cap: cap.id.clone(),
            action: name.to_string(),
            effect,
            description: match described(summary) {
                own if own.is_empty() => cap_description.clone(),
                own => own,
            },
            params,
            result,
            provider: provider.clone(),
            off: cap_off || off,
            note: None,
            advice: None,
            as_account: false,
            kind,
        });
    };
    let schema_of = |what: &str, s: &Value| {
        (!s.is_null())
            .then(|| schema::check(s, Role::Result).err())
            .flatten()
            .map(|e| schema::brief(&format!("{what}: {e}")))
    };
    for (n, d) in &cap.state {
        let bad = schema_of("value", &d.schema);
        let off = d.exposure == Some(Exposure::Off);
        add(
            n,
            UnitKind::State,
            d.effect,
            &d.summary,
            no_args(),
            d.schema.clone(),
            off,
            bad,
        );
    }
    for (n, d) in &cap.events {
        let bad = schema_of("data", &d.data);
        let off = d.exposure == Some(Exposure::Off);
        add(
            n,
            UnitKind::Event,
            d.effect,
            &d.summary,
            no_args(),
            d.data.clone(),
            off,
            bad,
        );
    }
    for (n, d) in &cap.streams {
        let params = if d.params.is_null() {
            json!({"type": "object"})
        } else {
            d.params.clone()
        };
        // A stream marks no path: the node opens it as a call that names
        // none, so the agent is never told one is judged.
        let bad = schema::check_stream_params(&params)
            .err()
            .map(|e| schema::brief(&format!("params: {e}")));
        let off = d.exposure == Some(Exposure::Off);
        add(
            n,
            UnitKind::Stream,
            d.effect,
            &d.summary,
            params,
            Value::Null,
            off,
            bad,
        );
    }
}

/// What the agent is told `exec.signal` does.
const SIGNAL_SUMMARY: &str = "Signals a command that runs as a job of this session, named by the job's id: term asks it to stop, int interrupts it, kill ends it.";

/// The node's `exec.signal` params with its `call` (the `invoke` id) named
/// as the `job` the center maps to it.
fn signal_by_job(params: &Value) -> Result<Value, String> {
    let mut p = params.clone();
    let props = p
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .filter(|m| m.contains_key("call"))
        .ok_or("params: exec.signal names no call")?;
    props.remove("call");
    props.insert(
        "job".into(),
        json!({"type": "string", "minLength": 1,
               "description": "The id of a running job of this session, from execute (like j-...)."}),
    );
    // The job is required whatever the node said of its call: a signal
    // without one would name nothing to the center.
    let mut req: Vec<Value> = match p.get("required") {
        Some(Value::Array(r)) => r.iter().filter(|r| *r != "call").cloned().collect(),
        _ => Vec::new(),
    };
    req.insert(0, json!("job"));
    p["required"] = Value::Array(req);
    Ok(p)
}

/// Whether `u` is one of the units the center serves itself. Told by its
/// capability, never by its provider: a node names its providers, but a
/// capability of a center's name is left out of its catalog.
pub fn is_center(u: &Unit) -> bool {
    CENTER_CAPS.contains(&u.cap.as_str())
}

/// Whether `cap.action` is the node's `exec.signal`, which names its call by
/// the `invoke` id: the agent names the job, and the center maps it. Told by
/// its name, whatever provider the node wrote: the provider is the node's
/// word, and a raw `call` would reach other sessions' commands.
pub fn is_signal(cap: &str, action: &str) -> bool {
    (cap, action) == ("exec", "signal")
}

/// The units the center serves itself on every node: `job.status` and
/// `job.cancel` (docs/dev/spec/harness.md §4.4). They are never sent to the
/// node and never go to the action checker.
pub fn center_units() -> Vec<Unit> {
    let job = json!({"type": "string", "minLength": 1,
                     "description": "The job's id, from execute (like j-...)."});
    let stream = json!({"type": "string", "minLength": 1,
                        "description": "The stream's id, from execute's answer (like s-...)."});
    let unit = |name: &str, effect: Effect, summary: &str, params: Value| Unit {
        name: name.into(),
        cap: name.split_once('.').map_or(name, |(c, _)| c).into(),
        action: name.split_once('.').map_or("", |(_, a)| a).into(),
        effect,
        description: summary.into(),
        params,
        result: Value::Null,
        provider: CENTER.into(),
        off: false,
        note: None,
        advice: None,
        as_account: false,
        kind: UnitKind::Action,
    };
    vec![
        unit(
            "job.cancel",
            Effect::Actuate,
            "Stops a running job of this session: the node cancels its call.",
            json!({"type": "object", "properties": {"job": job}, "required": ["job"],
                   "additionalProperties": false}),
        ),
        unit(
            "job.status",
            Effect::Read,
            "A job's state: running, or its result once it ended (given once). A job is a call that execute answered with a job id.",
            json!({"type": "object",
                   "properties": {"job": job,
                                  "wait_ms": {"type": "integer", "minimum": 0, "maximum": WAIT_MS_MAX,
                                              "description": "How long to wait for the job to end, in milliseconds, at most the center's call wait (20 s unless its owner set another); none or 0 answers at once."}},
                   "required": ["job"], "additionalProperties": false}),
        ),
        unit(
            "stream.close",
            Effect::Read,
            "Closes a stream of this session (a subscription too): nothing more of it is kept or read.",
            json!({"type": "object", "properties": {"stream": stream}, "required": ["stream"],
                   "additionalProperties": false}),
        ),
        unit(
            "stream.read",
            Effect::Read,
            "Reads what a stream (a job's command output, a program's stream, or the events of a subscription, one JSON line each) sent since the last read; eof once it ended and all was read.",
            json!({"type": "object",
                   "properties": {"stream": stream,
                                  "max_bytes": {"type": "integer", "minimum": READ_MIN, "maximum": READ_MAX,
                                                "description": format!("The most bytes to read, {READ_DEFAULT} when none is given.")},
                                  "wait_ms": {"type": "integer", "minimum": 0, "maximum": WAIT_MS_MAX,
                                              "description": "How long to wait for more when nothing is there yet, in milliseconds, at most the center's call wait; none or 0 answers at once."}},
                   "required": ["stream"], "additionalProperties": false}),
        ),
    ]
}

/// `summary` as a unit's description: one line, cut.
pub(crate) fn described(summary: &str) -> Arc<str> {
    util::clip(&one_line(summary), DESCRIPTION_MAX).into()
}

/// Names hold letters, digits, `-` and `_`: `.` joins a unit's name, so a
/// name with one could not be split again. The reason never repeats a long
/// name whole.
fn bad_name(what: &str, name: &str) -> Option<String> {
    bad_member_name(name).map(|why| format!("{what} {why}"))
}

/// A name left out as the owner sees it: on one line and cut.
fn shown_name(name: &str) -> String {
    util::clip(&one_line(name), NAME_MAX)
}

/// Why the state or an event's data of `cap` is outside the subset. Each
/// reason is brief, as on the node: it holds the node's own names, and the
/// Overview and the log repeat it.
fn cap_outside_subset(cap: &nerve_proto::Capability) -> Option<String> {
    for (k, decl) in &cap.state {
        if !decl.schema.is_null()
            && let Err(e) = schema::check(&decl.schema, Role::Result)
        {
            return Some(schema::brief(&format!("state {k}: {e}")));
        }
    }
    cap.events.iter().find_map(|(name, ev)| {
        if ev.data.is_null() {
            return None;
        }
        schema::check(&ev.data, Role::Result)
            .err()
            .map(|e| schema::brief(&format!("event {name}: {e}")))
    })
}

/// Why the schemas of an action are outside the subset the center checks
/// arguments with, in the words the node uses for its providers.
fn outside_subset(params: &Value, result: &Value) -> Option<String> {
    if let Err(e) = schema::check(params, Role::Params) {
        return Some(schema::brief(&format!("params: {e}")));
    }
    if !result.is_null()
        && let Err(e) = schema::check(result, Role::Result)
    {
        return Some(schema::brief(&format!("result: {e}")));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::tests::{cap, desc, signal_params};

    /// The arguments of `fs.read`: one path it reads.
    fn path() -> Value {
        json!({"type": "object", "properties": {"path": {"type": "string", "x-nerve-path": "read"}},
               "required": ["path"]})
    }

    /// The node's units (the center's own, in every catalog, aside) and the
    /// ones left out.
    fn names(c: &Catalog) -> (Vec<&str>, Vec<&str>) {
        (
            c.units
                .iter()
                .filter(|u| &*u.provider != CENTER)
                .map(|u| u.name.as_str())
                .collect(),
            c.broken.iter().map(|b| b.name.as_str()).collect(),
        )
    }

    #[test]
    fn units_are_cap_dot_action_without_the_reserved_ones() {
        let d = desc(
            "box",
            vec![
                cap(
                    "fs",
                    "fs",
                    &[
                        ("read", Effect::Read, path()),
                        ("write", Effect::Write, path()),
                    ],
                ),
                cap("exec", "exec", &[("run", Effect::Execute, path())]),
                cap("settings", "settings", &[("set", Effect::Write, json!({}))]),
                cap("audit", "audit", &[("list", Effect::Read, json!({}))]),
                cap("node", "node", &[("ping", Effect::Read, json!({}))]),
            ],
        );
        let c = Catalog::build(&d);
        assert_eq!(names(&c), (vec!["exec.run", "fs.read", "fs.write"], vec![]));
        let u = c.unit("fs.read").unwrap();
        assert_eq!(
            u,
            &Unit {
                name: "fs.read".into(),
                cap: "fs".into(),
                action: "read".into(),
                effect: Effect::Read,
                description: "read it".into(),
                params: path(),
                result: Value::Null,
                provider: "node".into(),
                off: false,
                note: None,
                advice: None,
                as_account: false,
                kind: UnitKind::Action,
            }
        );
        assert!(c.offers("fs", "write"));
        assert!(!c.offers("settings", "set"));
        assert!(c.unit("settings.set").is_none());
    }

    /// Every node offers the center's `job.status` and `job.cancel`, served
    /// by the center; a node's capability named `job` or `stream` is left
    /// out. The node's `exec.signal` is offered by the job's id.
    #[test]
    fn the_centers_job_units_are_on_every_node_and_signal_names_a_job() {
        let d = desc(
            "box",
            vec![
                cap(
                    "exec",
                    "exec",
                    &[
                        ("run", Effect::Execute, path()),
                        ("signal", Effect::Actuate, signal_params()),
                    ],
                ),
                cap("job", "", &[("status", Effect::Read, json!({}))]),
                cap("stream", "", &[("read", Effect::Read, json!({}))]),
            ],
        );
        let c = Catalog::build(&d);
        assert_eq!(
            c.units.iter().map(|u| u.name.as_str()).collect::<Vec<_>>(),
            [
                "exec.run",
                "exec.signal",
                "job.cancel",
                "job.status",
                "stream.close",
                "stream.read"
            ]
        );
        assert_eq!(names(&c).1, ["job", "stream"]);
        assert!(
            c.broken[0].reason.contains("the center's own"),
            "{:?}",
            c.broken
        );
        let status = c.unit("job.status").unwrap();
        assert_eq!(&*status.provider, CENTER);
        assert_eq!(status.effect, Effect::Read);
        assert_eq!(status.params["required"], json!(["job"]));
        assert_eq!(
            status.params["properties"]["wait_ms"]["maximum"],
            WAIT_MS_MAX
        );
        let cancel = c.unit("job.cancel").unwrap();
        assert_eq!(
            (&*cancel.provider, cancel.effect),
            (CENTER, Effect::Actuate)
        );
        // The stream units read only: they change nothing on the machine.
        let read = c.unit("stream.read").unwrap();
        assert_eq!((&*read.provider, read.effect), (CENTER, Effect::Read));
        assert_eq!(read.params["required"], json!(["stream"]));
        let close = c.unit("stream.close").unwrap();
        assert_eq!(close.effect, Effect::Read);
        for u in [status, cancel, read, close] {
            schema::check(&u.params, Role::Params).unwrap();
            assert_eq!(u.note, None);
            assert!(is_center(u));
        }
        // Beside the node's own units only: one that offers nothing, or
        // only units its owner turned off, has none.
        let one = Catalog::build(&desc(
            "one",
            vec![cap("fs", "fs", &[("read", Effect::Read, path())])],
        ));
        assert_eq!(one.units.len(), 5);
        assert_eq!(one.units[2], *c.unit("job.status").unwrap());
        assert!(Catalog::build(&desc("bare", vec![])).units.is_empty());
        let mut off = cap("fs", "fs", &[("read", Effect::Read, path())]);
        off.exposure = Exposure::Off;
        assert_eq!(
            names(&Catalog::build(&desc("off", vec![off]))).0,
            ["fs.read"]
        );

        let signal = c.unit("exec.signal").unwrap();
        assert_eq!(&*signal.provider, "node");
        assert!(is_signal(&signal.cap, &signal.action));
        assert_eq!(signal.params["required"], json!(["job", "signal"]));
        assert_eq!(signal.params["properties"]["job"]["type"], "string");
        assert!(signal.params["properties"].get("call").is_none());
        assert_eq!(
            signal.params["properties"]["signal"],
            json!({"enum": ["term", "kill", "int"]})
        );
        assert!(signal.description.contains("job"), "{}", signal.description);
        // The job is required also where the node's call was not, so no
        // signal reaches the center without one.
        for required in [Some(json!(["signal"])), None] {
            let mut p = signal_params();
            match required {
                Some(r) => p["required"] = r,
                None => {
                    p.as_object_mut().unwrap().remove("required");
                }
            }
            let d = desc(
                "box",
                vec![cap("exec", "exec", &[("signal", Effect::Actuate, p)])],
            );
            let c = Catalog::build(&d);
            let req = &c.unit("exec.signal").unwrap().params["required"];
            assert_eq!(req[0], "job", "{req}");
            assert!(!req.as_array().unwrap().contains(&json!("call")), "{req}");
        }
        // The center's units are told by their capability: a provider a
        // node named `center` is the node's.
        let mut lamp = cap("lamp", "", &[("on", Effect::Actuate, path())]);
        lamp.provider = CENTER.into();
        let c = Catalog::build(&desc("box", vec![lamp]));
        let on = c.unit("lamp.on").unwrap();
        assert_eq!(&*on.provider, CENTER);
        assert!(!is_center(on));
        assert!(is_center(c.unit("job.status").unwrap()));
        // Told by its name: the node's `exec.signal` names a job also where
        // the node wrote another provider, so no session signals a call by
        // its raw id.
        let mut exec = cap(
            "exec",
            "exec",
            &[("signal", Effect::Actuate, signal_params())],
        );
        exec.provider = "p".into();
        let c = Catalog::build(&desc("box", vec![exec]));
        let other = c.unit("exec.signal").unwrap();
        assert_eq!(&*other.provider, "p");
        assert_eq!(other.params["required"], json!(["job", "signal"]));
        assert!(other.params["properties"].get("call").is_none());
        assert!(is_signal(&other.cap, &other.action));
        assert!(!is_signal("lamp", "signal"));
        // One that names no call cannot be offered by job.
        let d = desc(
            "box",
            vec![cap("exec", "exec", &[("signal", Effect::Actuate, path())])],
        );
        let c = Catalog::build(&d);
        assert_eq!(names(&c).1, ["exec.signal"]);
        // A provider's `signal` of another capability is its own.
        let d = desc(
            "box",
            vec![cap("lamp", "", &[("signal", Effect::Actuate, path())])],
        );
        assert_eq!(
            Catalog::build(&d).unit("lamp.signal").unwrap().params,
            path()
        );
    }

    /// A name with `.` could not be split again, so it leaves out its own
    /// units only; `_` is a letter like the others. A capability with a bad
    /// name is left out as one entry.
    #[test]
    fn a_bad_name_leaves_out_that_capability_only() {
        let d = desc(
            "box",
            vec![
                cap(
                    "my_fs",
                    "fs",
                    &[
                        ("read", Effect::Read, path()),
                        ("list_all", Effect::Read, path()),
                    ],
                ),
                cap(
                    "exec",
                    "exec",
                    &[
                        ("run", Effect::Execute, path()),
                        ("run.all", Effect::Execute, path()),
                    ],
                ),
                cap("a.b", "", &[("go", Effect::Read, path())]),
            ],
        );
        let c = Catalog::build(&d);
        assert_eq!(
            names(&c),
            (
                vec!["exec.run", "my_fs.list_all", "my_fs.read"],
                vec!["a.b", "exec.run.all"]
            )
        );
        // The capability is one entry, and its actions are found under it.
        assert_eq!(c.broken("a.b.go"), Some(&c.broken[0]));
        assert_eq!(c.broken("a.bgo"), None);
        assert_eq!(
            c.broken[0].reason,
            "capability name \"a.b\": letters, digits, - and _ only"
        );
        assert_eq!(
            c.broken[1].reason,
            "action name \"run.all\": letters, digits, - and _ only"
        );
        assert_eq!(c.broken("exec.run.all"), Some(&c.broken[1]));
        assert_eq!(c.broken("exec.run"), None);
        assert!(c.offers("my_fs", "read"));
    }

    /// The bytes of names and reasons a catalog holds.
    fn footprint(c: &Catalog) -> usize {
        c.units
            .iter()
            .map(|u| u.name.len() + u.cap.len() + u.action.len())
            .chain(c.broken.iter().map(|b| b.name.len() + b.reason.len()))
            .sum()
    }

    /// A node's long name is not copied into each of its actions: the
    /// capability or action is left out with a short reason, so the catalog
    /// stays small however long the names and however many the actions.
    #[test]
    fn a_long_name_is_left_out_and_never_copied() {
        let many: Vec<(String, Effect, Value)> = (0..2000)
            .map(|i| (format!("a{i}"), Effect::Read, Value::Null))
            .collect();
        let actions: Vec<(&str, Effect, Value)> = many
            .iter()
            .map(|(n, e, p)| (n.as_str(), *e, p.clone()))
            .collect();
        let long = "c".repeat(16 * 1024);
        let mut bad = "d".repeat(16 * 1024);
        bad.push_str(".x\nmore");
        let edge = "e".repeat(NAME_MAX);
        let over = "f".repeat(NAME_MAX + 1);
        let long_action = "g".repeat(16 * 1024);
        let mut d = desc(
            "box",
            vec![
                cap(&long, "", &actions),
                cap(&bad, "", &actions),
                cap(&edge, "", &[("go", Effect::Read, Value::Null)]),
                cap(&over, "", &[("go", Effect::Read, Value::Null)]),
                cap("q\nr", "", &[("go", Effect::Read, Value::Null)]),
                cap(
                    "fs",
                    "fs",
                    &[
                        ("read", Effect::Read, path()),
                        (long_action.as_str(), Effect::Read, path()),
                        (edge.as_str(), Effect::Read, path()),
                    ],
                ),
            ],
        );
        // A long provider name is shared by its units, not copied.
        d.capabilities[5].provider = "p".repeat(16 * 1024);
        let c = Catalog::build(&d);
        assert_eq!(
            names(&c).0,
            [format!("{edge}.go"), format!("fs.{edge}"), "fs.read".into()]
        );
        assert!(Arc::ptr_eq(&c.units[1].provider, &c.units[2].provider));
        assert_eq!(c.broken.len(), 5, "{:?}", names(&c).1);
        let reasons: Vec<&str> = c.broken.iter().map(|b| b.reason.as_str()).collect();
        assert!(
            reasons.contains(&"capability name of 16384 bytes: at most 64"),
            "{reasons:?}"
        );
        assert!(
            reasons.contains(&"capability name of 16391 bytes: at most 64"),
            "{reasons:?}"
        );
        assert!(
            reasons.contains(&"capability name of 65 bytes: at most 64"),
            "{reasons:?}"
        );
        assert!(
            reasons.contains(&"action name of 16384 bytes: at most 64"),
            "{reasons:?}"
        );
        for b in &c.broken {
            assert!(b.name.len() <= 2 * NAME_MAX + 4, "{}", b.name.len());
            assert!(!b.name.chars().any(char::is_control), "{:?}", b.name);
        }
        // The owner sees the start of a long name, on one line.
        let shown: Vec<&str> = c.broken.iter().map(|b| b.name.as_str()).collect();
        assert!(
            shown.contains(&format!("{}…", &over[..NAME_MAX]).as_str()),
            "{shown:?}"
        );
        assert!(shown.contains(&format!("fs.{}…", &long_action[..NAME_MAX]).as_str()));
        assert!(shown.contains(&"q r"), "{shown:?}");
        assert!(footprint(&c) < 4096, "{}", footprint(&c));
    }

    /// A capability id given twice names two declarations with one unit
    /// name: `list` would show one and `execute` might check the other's
    /// params. Neither is offered; the owner sees one entry.
    #[test]
    fn a_capability_named_twice_is_not_offered() {
        let level = json!({"type": "object", "properties": {"level": {"type": "integer"}}});
        let percent = json!({"type": "object", "properties": {"percent": {"type": "integer"}},
                             "required": ["percent"]});
        let d = desc(
            "box",
            vec![
                cap("lamp", "", &[("dim", Effect::Actuate, level)]),
                cap("fs", "fs", &[("read", Effect::Read, path())]),
                cap("lamp", "", &[("dim", Effect::Actuate, percent)]),
            ],
        );
        let c = Catalog::build(&d);
        assert_eq!(names(&c), (vec!["fs.read"], vec!["lamp"]));
        assert_eq!(c.broken[0].reason, "named twice in the description");
        assert!(c.unit("lamp.dim").is_none());
        assert_eq!(c.broken("lamp.dim"), Some(&c.broken[0]));
    }

    /// A unit's hash follows what `list` tells of it, and only that: the
    /// node's rules, its mode and the other units leave it alone.
    #[test]
    fn a_units_hash_changes_with_what_list_tells_of_it() {
        let d = desc(
            "box",
            vec![
                cap("fs", "fs", &[("read", Effect::Read, path())]),
                cap("exec", "exec", &[("run", Effect::Execute, path())]),
            ],
        );
        let hash = |d: &Descriptor| Catalog::build(d).unit("fs.read").unwrap().hash();
        let h = hash(&d);
        assert!(h < 1 << 53, "{h}");
        assert_eq!(hash(&d), h, "the same unit, the same hash");

        // A new revision of the descriptor (a rule edit, a mode change), a
        // change of another unit, and the capability's summary beside the
        // action's own (which `list` does not show) are not this unit's
        // business; nor is text past what the description keeps.
        let mut same = d.clone();
        same.rev = 7;
        same.summary = "now in folder mode".into();
        same.capabilities[1].actions.get_mut("run").unwrap().params = json!({"type": "object"});
        same.capabilities[0].summary = "Files.".into();
        assert_eq!(hash(&same), h);
        let long = "x".repeat(DESCRIPTION_MAX);
        let mut a = d.clone();
        a.capabilities[0].actions.get_mut("read").unwrap().summary = format!("{long}a");
        let mut b = d.clone();
        b.capabilities[0].actions.get_mut("read").unwrap().summary = format!("{long}b");
        assert_eq!(hash(&a), hash(&b));

        // Each thing `list` tells of it is.
        type Edit = fn(&mut Descriptor);
        let edits: [(&str, Edit); 5] = [
            ("params", |d| {
                d.capabilities[0].actions.get_mut("read").unwrap().params = json!({
                    "type": "object", "properties": {"path": {"type": "string"},
                    "max": {"type": "integer"}}, "required": ["path"]})
            }),
            ("result", |d| {
                d.capabilities[0].actions.get_mut("read").unwrap().result =
                    json!({"type": "string"})
            }),
            ("effect", |d| {
                d.capabilities[0].actions.get_mut("read").unwrap().effect = Effect::Write
            }),
            ("summary", |d| {
                d.capabilities[0].actions.get_mut("read").unwrap().summary = "Read.".into()
            }),
            (
                "the capability's summary, which it shows for want of its own",
                |d| d.capabilities[0].actions.get_mut("read").unwrap().summary = String::new(),
            ),
        ];
        for (what, edit) in edits {
            let mut changed = d.clone();
            edit(&mut changed);
            assert_ne!(hash(&changed), h, "{what}");
        }
        let mut bare = d.clone();
        bare.capabilities[0]
            .actions
            .get_mut("read")
            .unwrap()
            .summary = String::new();
        let mut files = bare.clone();
        files.capabilities[0].summary = "Files.".into();
        assert_ne!(
            hash(&bare),
            hash(&files),
            "the capability's summary it shows"
        );
    }

    /// Text moved from the end of one part to the start of the next is
    /// another unit: the hash takes each part with its length.
    #[test]
    fn a_units_hash_tells_where_one_part_ends() {
        let unit = |description: &str, params: Value| Unit {
            name: "fs.read".into(),
            cap: "fs".into(),
            action: "read".into(),
            effect: Effect::Read,
            description: description.into(),
            params,
            result: Value::Null,
            provider: "node".into(),
            off: false,
            note: None,
            advice: None,
            as_account: false,
            kind: UnitKind::Action,
        };
        assert_ne!(unit("x1", json!(2)).hash(), unit("x", json!(12)).hash());
    }

    fn access(v: Value) -> Option<nerve_proto::descriptor::Access> {
        Some(serde_json::from_value(v).unwrap())
    }

    /// The folder note goes into the hash of the node's own `fs.*` and
    /// `exec.run` only: a grant changes theirs and no other unit's, and the
    /// mode's end or the account, which the note does not name, none.
    #[test]
    fn a_grant_changes_the_hash_of_fs_and_exec_units_only() {
        let mut d = desc(
            "box",
            vec![
                cap("fs", "fs", &[("read", Effect::Read, path())]),
                cap(
                    "exec",
                    "exec",
                    &[
                        ("run", Effect::Execute, path()),
                        ("signal", Effect::Actuate, signal_params()),
                    ],
                ),
                cap(
                    "lamp",
                    "",
                    &[("get", Effect::Read, json!({"type": "object"}))],
                ),
            ],
        );
        d.capabilities[2].provider = "desk".into();
        let hashes = |d: &Descriptor| -> Vec<u64> {
            let c = Catalog::build(d);
            ["fs.read", "exec.run", "lamp.get", "exec.signal"]
                .iter()
                .map(|u| c.unit(u).unwrap().hash())
                .collect()
        };
        let folder = |folders: Value, until: u64, account: &str| {
            access(
                json!({"mode": "folder", "until_ms": until, "account": account,
                          "confined": true, "folders": folders}),
            )
        };
        d.access = folder(json!([{"path": "/a", "access": "rw"}]), 5, "nerve-run");
        let one = hashes(&d);
        let c = Catalog::build(&d);
        assert!(
            c.unit("fs.read")
                .unwrap()
                .note
                .as_deref()
                .unwrap()
                .contains("/a (rw)")
        );
        assert_eq!(c.unit("lamp.get").unwrap().note, None);
        // `exec.signal` names no folder, so it carries neither the folders
        // nor the advice.
        assert_eq!(c.unit("exec.signal").unwrap().note, None);
        assert_eq!(c.unit("exec.signal").unwrap().advice, None);
        d.access = folder(json!([{"path": "/a", "access": "rw"}]), 9, "me");
        assert_eq!(hashes(&d), one);
        d.access = folder(
            json!([{"path": "/a", "access": "rw"}, {"path": "/b", "access": "r"}]),
            9,
            "me",
        );
        let two = hashes(&d);
        assert_ne!(two[0], one[0]);
        assert_ne!(two[1], one[1]);
        assert_eq!(two[2], one[2]);
        assert_eq!(two[3], one[3]);
        // What the center's advice says of commands counts for `exec.run`
        // only: a sudo list that comes into force, or a sandbox that goes,
        // changes its hash and leaves the file calls' alone.
        let mut a = d.access.clone().unwrap();
        a.sudo = true;
        d.access = Some(a.clone());
        let sudo = hashes(&d);
        assert_eq!(sudo[0], two[0]);
        assert_ne!(sudo[1], two[1]);
        assert_eq!(sudo[2..], two[2..]);
        a.sudo = false;
        a.confined = false;
        d.access = Some(a.clone());
        let loose = hashes(&d);
        assert_eq!(loose[0], two[0]);
        assert_ne!(loose[1], two[1]);
        assert_eq!(loose[2..], two[2..]);
        // With no folder granted the same holds.
        a.folders.clear();
        d.access = Some(a.clone());
        let bare = hashes(&d);
        a.sudo = true;
        d.access = Some(a);
        let bare_sudo = hashes(&d);
        assert_eq!(bare_sudo[0], bare[0]);
        assert_ne!(bare_sudo[1], bare[1]);
        // Out of folder mode the folders decide nothing and no note is told.
        d.access = access(json!({"mode": "user", "account": "me"}));
        let user = hashes(&d);
        assert_ne!(user[0], two[0]);
        assert_eq!(user[2], one[2]);
        assert_eq!(Catalog::build(&d).unit("fs.read").unwrap().note, None);
        d.access = None;
        assert_eq!(hashes(&d), user);
    }

    /// Any capability that takes paths is bound by the folders as `fs` is:
    /// a provider's action whose schema marks a path carries the folder
    /// note and the advice of the calls that start no command; one that
    /// names no path carries neither.
    #[test]
    fn a_provider_action_with_a_path_carries_the_folder_note() {
        let marked = json!({"type": "object", "properties": {
            "to": {"type": "string", "x-nerve-path": "write"}}});
        let mut d = desc(
            "box",
            vec![cap(
                "notes",
                "",
                &[
                    ("save", Effect::Write, marked),
                    ("count", Effect::Read, json!({"type": "object"})),
                ],
            )],
        );
        d.capabilities[0].provider = "desk".into();
        d.access = access(
            json!({"mode": "folder", "account": "nerve-run", "confined": true,
                                 "folders": [{"path": "/a", "access": "rw"}]}),
        );
        let c = Catalog::build(&d);
        let save = c.unit("notes.save").unwrap();
        assert_eq!(save.note.as_deref(), Some("/a (rw)"));
        assert_eq!(
            save.advice.as_deref(),
            c.reach.as_ref().unwrap().file_advice().as_deref()
        );
        let count = c.unit("notes.count").unwrap();
        assert_eq!((&count.note, &count.advice), (&None, &None));
    }

    /// Where the node reads as the command account, the advice says that a
    /// call whose effect is read goes as far as that account may read, and
    /// writes, commands and the reads of other calls keep to the folders,
    /// granted or none; the hash of the units
    /// that take paths moves with it, and no other.
    #[test]
    fn the_advice_says_how_far_a_read_goes() {
        let reach = |reads: bool, folders: Value, sudo: bool| {
            Reach::read(
                &serde_json::from_value(json!({"mode": "folder", "account": "nerve-run",
                    "confined": true, "sudo": sudo, "reads_by_account": reads,
                    "folders": folders}))
                .unwrap(),
            )
        };
        let open = "what is open to every account on the machine, except protected paths and \
                    the node's own files";
        // A program other than the node's `fs` is never handed a folder
        // outside the folders; a capability of the config that runs as the
        // command account is held like that account's commands.
        let never = "An action of any capability but fs may name a file there, never a folder: \
                     its program would read below it with the owner's rights. For such an action \
                     a folder marked own counts as none: it is the command account's, not the \
                     owner's. One whose details say it runs as the command account is a command \
                     of that account: it reads what that account may, and where the machine's \
                     sandbox holds the commands, only in the folders of the `folders:` line and \
                     the system's files.";
        let granted = json!([{"path": "/a", "access": "rw"}]);
        let r = reach(true, granted.clone(), false);
        let a = r.file_advice().unwrap();
        assert!(
            a.starts_with(&format!(
                "The node is in folder mode: a call may read in the folders of the `folders:` \
                 line marked r, and one whose effect is read also, outside every folder, \
                 {open}. {never} A call may write only in the folders marked w (r read, w \
                 write, x run commands). Where folders nest, the deepest one decides."
            )),
            "{a}"
        );
        // A command gets none of that: it starts in an `x` folder, and the
        // sandbox holds what it reaches.
        let a = r.advice().unwrap();
        assert!(
            a.starts_with(
                "The node is in folder mode: a command may start only in a folder of the \
                 `folders:` line marked x (r read, w write, x run commands). Where folders \
                 nest, the deepest one decides. The machine's sandbox holds"
            ),
            "{a}"
        );
        assert!(!a.contains(open), "{a}");
        let by_folders = reach(false, granted, false);
        assert!(!by_folders.advice().unwrap().contains(open));
        assert!(
            by_folders
                .file_advice()
                .unwrap()
                .starts_with("The node is in folder mode: its calls may name paths only in the")
        );
        // None granted: reads still go, writes and commands wait.
        assert_eq!(
            reach(true, json!([]), false).file_advice().unwrap(),
            format!(
                "The node is in folder mode with no folder granted: a call whose effect is \
                 read may read {open}; any other call that names a path is refused until its \
                 owner grants a folder. {never}"
            )
        );
        assert_eq!(
            reach(true, json!([]), false).advice().unwrap(),
            "The node is in folder mode with no folder granted: its commands are refused until \
             its owner grants one."
        );
        assert!(
            reach(true, json!([]), true)
                .advice()
                .unwrap()
                .contains("its commands are refused until its owner grants one, except one on")
        );
        // The hash of the units that take paths, and only theirs.
        let mut d = desc(
            "box",
            vec![
                cap("fs", "fs", &[("read", Effect::Read, path())]),
                cap(
                    "lamp",
                    "",
                    &[("get", Effect::Read, json!({"type": "object"}))],
                ),
            ],
        );
        d.capabilities[1].provider = "desk".into();
        let hashes = |d: &Descriptor| -> Vec<u64> {
            let c = Catalog::build(d);
            ["fs.read", "lamp.get"]
                .iter()
                .map(|u| c.unit(u).unwrap().hash())
                .collect()
        };
        let block = |reads: bool| {
            access(
                json!({"mode": "folder", "account": "nerve-run", "confined": true,
                          "reads_by_account": reads,
                          "folders": [{"path": "/a", "access": "rw"}]}),
            )
        };
        d.access = block(false);
        let before = hashes(&d);
        d.access = block(true);
        let after = hashes(&d);
        assert_ne!(after[0], before[0]);
        assert_eq!(after[1], before[1]);
    }

    /// The center's advice names the account's own folders as the place
    /// for throwaway files, shared with every pairing of that account, and
    /// asks for owner-readable files (the group bits kept) only where the
    /// commands run as an account of their own; where they run as the
    /// owner, a granted `/tmp` is no such place and nothing is asked.
    #[test]
    fn the_advice_names_scratch_folders_only_where_they_are_the_accounts_own() {
        let reach = |folders: Value| {
            Catalog::build(&Descriptor {
                access: access(json!({"mode": "folder", "confined": true, "folders": folders})),
                ..desc("box", vec![])
            })
            .reach
            .unwrap()
        };
        let separate = reach(json!([
            {"path": "/home/me/proj", "access": "rw", "closed_below": true},
            {"path": "/home/me/proj/keys", "access": ""},
            {"path": "/tmp", "access": "rwx", "own": true},
            {"path": "/var/lib/nerve-run", "access": "rwx", "own": true},
            {"path": "/srv/own-r", "access": "r", "own": true}]));
        assert_eq!(
            separate.note().unwrap(),
            "/home/me/proj (rw, some folders below allow less), /tmp (rwx, own), \
             /var/lib/nerve-run (rwx, own), /srv/own-r (r, own)"
        );
        let advice = separate.advice().unwrap();
        // A folder below that allows less (closed, or left out for its
        // name) may refuse file calls and a command's start, not a command
        // that started around it.
        assert!(
            advice.contains(
                "A folder marked \"some folders below allow less\" holds folders, not named, \
                 that allow less than it or nothing, where a file call or a command's start may \
                 be refused; a command started in a folder around them still reaches them."
            ),
            "{advice}"
        );
        assert!(!advice.contains("every call"), "{advice}");
        // The block says a sandbox holds the commands.
        assert!(
            advice.contains(
                "The machine's sandbox holds what a command reaches to these folders and the \
                 system's files."
            ),
            "{advice}"
        );
        // What keeps the owner in is the group bits: the advice names the
        // modes to use, not only the ones to avoid.
        assert!(
            advice.contains(
                "goes through the group bits: keep those, 0640 or 0660 for files and 0750 or \
                 0770 for folders, not 0600 or 0700 unless asked."
            ),
            "{advice}"
        );
        // The own folders are shared, the settings its programs keep there
        // too, so they are for throwaway files and never called private.
        assert!(
            advice.ends_with(
                "The folders marked own belong to that account, and every pairing whose \
                 commands run as it shares them (a temporary folder also every account on the \
                 machine), with the settings and caches its programs keep there: what one \
                 pairing leaves there can change what another one's commands do. Use one \
                 marked w for throwaway files only, keep nothing secret there, and change no \
                 program's settings there unless asked."
            ),
            "{advice}"
        );
        assert!(!advice.contains("sudo"), "{advice}");
        assert!(!advice.contains("private"), "{advice}");
        // It names no path: the paths are the node's words.
        assert!(!advice.contains('/'), "{advice}");
        // An own folder that may not be written is no place for throwaway files.
        let read_only = reach(json!([{"path": "/srv/own-r", "access": "r", "own": true}]));
        let advice = read_only.advice().unwrap();
        assert!(advice.contains("group bits") && !advice.contains("throwaway"));
        assert!(!advice.contains("closed"), "{advice}");
        // Run as the owner: no own folder, so neither throwaway files nor
        // file modes.
        let by_hand = reach(json!([
            {"path": "/home/me/proj", "access": "rw"},
            {"path": "/tmp", "access": "r"}]));
        let advice = by_hand.advice().unwrap();
        for never in ["throwaway", "0600", "/tmp", "own"] {
            assert!(!advice.contains(never), "{never}: {advice}");
        }
        // Where no sandbox holds the commands, the advice does not say one
        // does: they reach what their account may reach.
        let held = Catalog::build(&Descriptor {
            access: access(json!({"mode": "folder", "confined": false,
                                  "folders": [{"path": "/srv/proj", "access": "rwx"}]})),
            ..desc("box", vec![])
        })
        .reach
        .unwrap()
        .advice()
        .unwrap();
        assert!(!held.contains("sandbox"), "{held}");
        assert!(
            held.contains(
                "The machine does not hold what a command reaches to these folders: where it \
                 runs commands, they reach what the account they run as may reach."
            ),
            "{held}"
        );
        // The own mark is in the note, so it moves the units' hash.
        assert_ne!(
            reach(json!([{"path": "/tmp", "access": "rwx", "own": true}])).note(),
            reach(json!([{"path": "/tmp", "access": "rwx"}])).note()
        );
        // No folder: refused until one is granted; outside folder mode none.
        assert!(
            reach(json!([]))
                .advice()
                .unwrap()
                .contains("no folder granted")
        );
        // A command on the sudo list runs by that list alone, beyond the
        // folders, the folders' `x` and the sandbox.
        let sudo = |folders: Value| {
            Catalog::build(&Descriptor {
                access: access(json!({"mode": "folder", "confined": true, "sudo": true,
                                      "folders": folders})),
                ..desc("box", vec![])
            })
            .reach
            .unwrap()
            .advice()
            .unwrap()
        };
        assert!(sudo(json!([{"path": "/srv", "access": "rw"}])).contains(
            "A command on the owner's sudo list for you runs by that list alone, with full \
                 rights: in any folder, and beyond the folders and the sandbox."
        ));
        assert!(sudo(json!([])).contains(
            "and so are its commands, except one on the owner's sudo list for you, which runs \
             by that list alone, with full rights."
        ));
        // Folders the node left out for their names are no grant of none.
        let unnamed = Catalog::build(&Descriptor {
            access: access(json!({"mode": "folder", "confined": true, "unnamed": 2})),
            ..desc("box", vec![])
        })
        .reach
        .unwrap();
        assert_eq!(
            unnamed.note().unwrap(),
            "2 more whose names cannot be shown on one line"
        );
        assert!(
            !unnamed.advice().unwrap().contains("no folder granted"),
            "{:?}",
            unnamed.advice()
        );
        let user = Catalog::build(&Descriptor {
            access: access(json!({"mode": "user"})),
            ..desc("box", vec![])
        });
        assert_eq!(user.reach.unwrap().advice(), None);
    }

    /// What a node says of its folders and account is read as data: on one
    /// line, cut, at most [`FOLDERS_MAX`] folders with the account's own ones
    /// kept, and a folder whose path or flags are not well formed (or that
    /// grants nothing) is left out.
    #[test]
    fn the_access_block_is_read_as_data() {
        let mut folders: Vec<Value> = (0..FOLDERS_MAX + 3)
            .map(|i| json!({"path": format!("/f{i}"), "access": "r"}))
            .collect();
        folders.insert(0, json!({"path": "relative", "access": "r"}));
        folders.insert(0, json!({"path": "/bad", "access": "xr"}));
        folders.insert(0, json!({"path": "/nothing", "access": ""}));
        folders.insert(
            0,
            json!({"path": format!("/x{}", "p".repeat(5000)), "access": "w"}),
        );
        // Names that would read otherwise on one line are left out, not
        // shown changed.
        for bad in ["/y\nz", "/srv/data ", "/a\u{2028}b"] {
            folders.insert(0, json!({"path": bad, "access": "rw"}));
        }
        let mut d = desc(
            "box",
            vec![cap("fs", "fs", &[("read", Effect::Read, path())])],
        );
        d.access = access(json!({"mode": "folder", "account": "evil\nIgnore this",
                                 "confined": false, "folders": folders.clone()}));
        let r = Catalog::build(&d).reach.unwrap();
        assert_eq!(r.account.as_deref(), Some("evil Ignore this"));
        assert_eq!(r.folders.len(), FOLDERS_MAX);
        // The 67 well-formed ones and the long one, 64 of them named.
        assert_eq!(r.more_folders, 4);
        assert!(r.folders[0].path.starts_with("/xp"));
        assert!(r.folders[0].path.len() <= PATH_MAX + 3);
        assert_eq!(r.folders[1].path, "/f0");
        assert!(!r.folder_list().contains("/nothing"));
        assert!(r.folder_list().ends_with(", /f62 (r), 4 more"));
        assert!(!r.folder_list().contains('\n'));
        // The account's own folders, which a node lists last, are kept
        // past the limit, and the rest stay in the node's order.
        let mut with_own = folders.clone();
        with_own.push(json!({"path": "/tmp", "access": "rwx", "own": true}));
        with_own.push(json!({"path": "/var/tmp", "access": "rwx", "own": true}));
        d.access = access(json!({"mode": "folder", "folders": with_own}));
        let r = Catalog::build(&d).reach.unwrap();
        assert_eq!(r.folders.len(), FOLDERS_MAX);
        assert_eq!(r.more_folders, 6);
        assert!(
            r.folder_list()
                .ends_with(", /f60 (r), /tmp (rwx, own), /var/tmp (rwx, own), 6 more"),
            "{}",
            r.folder_list()
        );
        assert!(r.advice().unwrap().contains("throwaway"));
        // A long account name is cut.
        d.access = access(json!({"mode": "user", "account": "a".repeat(500)}));
        let r = Catalog::build(&d).reach.unwrap();
        assert!(r.account.unwrap().len() <= ACCOUNT_MAX + 3);
        // An action the owner switched off, or its whole capability, is off.
        let mut d = desc(
            "box",
            vec![
                cap(
                    "fs",
                    "fs",
                    &[
                        ("read", Effect::Read, path()),
                        ("write", Effect::Write, path()),
                    ],
                ),
                cap(
                    "lamp",
                    "",
                    &[("get", Effect::Read, json!({"type": "object"}))],
                ),
            ],
        );
        d.capabilities[0].actions.get_mut("write").unwrap().exposure =
            Some(nerve_proto::Exposure::Off);
        d.capabilities[1].exposure = nerve_proto::Exposure::Off;
        let c = Catalog::build(&d);
        let off: Vec<bool> = ["fs.read", "fs.write", "lamp.get"]
            .iter()
            .map(|u| c.unit(u).unwrap().off)
            .collect();
        assert_eq!(off, [false, true, true]);
    }

    /// The units of a capability without summaries of their own share its
    /// summary, cut: a node's long text is kept once, not once per unit.
    #[test]
    fn a_long_summary_is_kept_once_and_cut() {
        let actions: Vec<(String, Effect, Value)> = (0..50)
            .map(|i| (format!("a{i}"), Effect::Read, json!({"type": "object"})))
            .collect();
        let refs: Vec<(&str, Effect, Value)> = actions
            .iter()
            .map(|(n, e, p)| (n.as_str(), *e, p.clone()))
            .collect();
        let mut big = cap("big", "big", &refs);
        big.summary = "y".repeat(100_000);
        for a in big.actions.values_mut() {
            a.summary = String::new();
        }
        big.actions.get_mut("a7").unwrap().summary = "z\n".repeat(100_000);
        let c = Catalog::build(&desc("box", vec![big]));
        assert_eq!(names(&c).0.len(), 50);
        let first = &c.units[0].description;
        assert!(first.starts_with("yyy") && first.ends_with('…'), "{first}");
        assert_eq!(first.len(), DESCRIPTION_MAX + '…'.len_utf8());
        for u in c.units.iter().filter(|u| u.cap == "big") {
            if u.action == "a7" {
                assert!(u.description.starts_with("z z "), "{}", u.description);
                assert!(u.description.len() <= DESCRIPTION_MAX + '…'.len_utf8());
            } else {
                assert!(Arc::ptr_eq(&u.description, first), "{}", u.name);
            }
        }
    }

    #[test]
    fn a_schema_outside_the_subset_is_broken_with_its_reason() {
        let mut lamp = cap(
            "lamp",
            "",
            &[
                (
                    "dim",
                    Effect::Actuate,
                    json!({"type": "object", "properties": {"level": {"oneOf": [
                        {"type": "integer"}, {"type": "string"}]}}}),
                ),
                ("on", Effect::Actuate, Value::Null),
                ("off", Effect::Actuate, json!({"type": "object"})),
                ("state", Effect::Sense, json!({"type": "object"})),
                ("untyped", Effect::Actuate, json!({})),
            ],
        );
        lamp.actions.get_mut("off").unwrap().result = json!({"$ref": "#/x"});
        lamp.actions.get_mut("state").unwrap().result =
            json!({"type": "object", "properties": {"on": {"type": "boolean"}}});
        let c = Catalog::build(&desc("box", vec![lamp]));
        assert_eq!(
            names(&c),
            (
                vec!["lamp.on", "lamp.state"],
                vec!["lamp.dim", "lamp.off", "lamp.untyped"]
            )
        );
        let reason = |n: &str| {
            c.broken
                .iter()
                .find(|b| b.name == n)
                .unwrap()
                .reason
                .clone()
        };
        assert!(
            reason("lamp.dim").starts_with("params: /properties/level"),
            "{}",
            reason("lamp.dim")
        );
        assert!(
            reason("lamp.dim").contains("oneOf"),
            "{}",
            reason("lamp.dim")
        );
        assert!(
            reason("lamp.off").starts_with("result: "),
            "{}",
            reason("lamp.off")
        );
        assert!(
            reason("lamp.untyped").starts_with("params: "),
            "{}",
            reason("lamp.untyped")
        );
        // No params is any arguments, as on the node.
        assert_eq!(c.unit("lamp.on").unwrap().params, json!({"type": "object"}));
        assert_eq!(
            c.unit("lamp.state").unwrap().result["properties"]["on"],
            json!({"type": "boolean"})
        );
    }

    /// A program's state keys, events and streams are units beside its
    /// actions, each with its kind, checked alone: a name given to two
    /// kinds leaves out both, and a schema outside the subset only its
    /// unit. The node's own state and events are no units.
    #[test]
    fn a_programs_state_events_and_streams_are_units_with_their_kinds() {
        let mut board: nerve_proto::Capability = serde_json::from_value(json!(
            {"id": "board", "provider": "desk", "exposure": "on", "summary": "A board.",
             "actions": {"reset": {"effect": "actuate"}, "led": {"effect": "write"}},
             "state": {"temp": {"effect": "sense", "summary": "Degrees.",
                                "schema": {"type": "number"}},
                       "led": {"effect": "read"},
                       "odd": {"effect": "read", "schema": {"anyOf": []}}},
             "events": {"alarm": {"effect": "read", "exposure": "off"},
                        "bad": {"effect": "read", "data": {"$ref": "#/x"}}},
             "streams": {"feed": {"kind": "reliable", "direction": "up", "effect": "sense",
                                  "params": {"type": "object", "properties": {
                                      "every_ms": {"type": "integer"}}}},
                         "tail": {"kind": "reliable", "direction": "up", "effect": "read",
                                  "params": {"type": "object", "properties": {
                                      "file": {"type": "string", "x-nerve-path": "read"}}}}}}))
        .unwrap();
        board.exposure = Exposure::On;
        let mut exec = cap(
            "exec",
            "exec",
            &[("run", Effect::Execute, json!({"type": "object"}))],
        );
        exec.events = board.events.clone();
        exec.events.remove("bad");
        exec.state = board.state.clone();
        exec.state.remove("odd");
        let c = Catalog::build(&desc("box", vec![board, exec]));
        assert_eq!(
            names(&c),
            (
                vec![
                    "board.alarm",
                    "board.feed",
                    "board.reset",
                    "board.temp",
                    "exec.run"
                ],
                vec![
                    "board.bad",
                    "board.led",
                    "board.led",
                    "board.odd",
                    "board.tail"
                ]
            )
        );
        let unit = |n: &str| c.unit(n).unwrap();
        assert_eq!(unit("board.temp").kind, UnitKind::State);
        assert_eq!(unit("board.temp").effect, Effect::Sense);
        assert_eq!(unit("board.temp").result, json!({"type": "number"}));
        assert_eq!(&*unit("board.temp").description, "Degrees.");
        assert_eq!(
            unit("board.temp").params,
            json!({"type": "object", "additionalProperties": false})
        );
        assert_eq!(unit("board.alarm").kind, UnitKind::Event);
        assert!(unit("board.alarm").off);
        assert_eq!(&*unit("board.alarm").description, "A board.");
        assert_eq!(unit("board.feed").kind, UnitKind::Stream);
        assert_eq!(
            unit("board.feed").params["properties"]["every_ms"]["type"],
            "integer"
        );
        assert_eq!(unit("board.reset").kind, UnitKind::Action);
        let reason = |n: &str| {
            c.broken
                .iter()
                .find(|b| b.name == n)
                .unwrap()
                .reason
                .clone()
        };
        assert_eq!(reason("board.led"), TWICE);
        assert!(
            reason("board.bad").starts_with("data: "),
            "{}",
            reason("board.bad")
        );
        assert!(
            reason("board.odd").starts_with("value: "),
            "{}",
            reason("board.odd")
        );
        // A stream's open names no path, so the agent is never told one.
        assert!(
            reason("board.tail").contains("a stream takes no path"),
            "{}",
            reason("board.tail")
        );
        // The kind is part of what the model was told.
        let mut as_action = unit("board.temp").clone();
        as_action.kind = UnitKind::Action;
        assert_ne!(as_action.hash(), unit("board.temp").hash());
    }

    /// One state key `value` with `schema`.
    fn state_of(
        schema: Value,
    ) -> std::collections::BTreeMap<String, nerve_proto::descriptor::StateDecl> {
        let decl = nerve_proto::descriptor::StateDecl {
            effect: Effect::Read,
            summary: String::new(),
            schema,
            exposure: None,
        };
        [("value".to_string(), decl)].into()
    }

    /// Event data and state are published schemas too: one outside the
    /// subset leaves out every action of its capability, and a capability
    /// without actions is named on its own.
    #[test]
    fn a_broken_event_or_state_leaves_out_its_capability() {
        let mut lamp = cap(
            "lamp",
            "",
            &[
                ("on", Effect::Actuate, json!({"type": "object"})),
                ("off", Effect::Actuate, json!({"type": "object"})),
            ],
        );
        lamp.state = state_of(json!({"$ref": "#/x"}));
        let mut door = cap("door", "", &[("open", Effect::Actuate, path())]);
        door.events.insert(
            "opened".into(),
            nerve_proto::descriptor::EventDecl {
                effect: Effect::Read,
                summary: "It opened.".into(),
                implicit: false,
                data: json!({"oneOf": [{"type": "string"}]}),
                exposure: None,
            },
        );
        let mut bell = cap("bell", "", &[]);
        bell.events = door.events.clone();
        let mut fine = cap("fine", "", &[("go", Effect::Read, path())]);
        fine.state = state_of(json!({"type": "boolean"}));
        fine.events.insert(
            "went".into(),
            nerve_proto::descriptor::EventDecl {
                effect: Effect::Read,
                summary: "It went.".into(),
                implicit: false,
                data: json!({"type": "integer"}),
                exposure: None,
            },
        );
        let c = Catalog::build(&desc("box", vec![lamp, door, bell, fine]));
        assert_eq!(
            names(&c),
            (
                vec!["fine.go"],
                vec!["bell", "door.open", "lamp.off", "lamp.on"]
            )
        );
        let reason = |n: &str| {
            c.broken
                .iter()
                .find(|b| b.name == n)
                .unwrap()
                .reason
                .clone()
        };
        assert!(
            reason("lamp.on").starts_with("state value: "),
            "{}",
            reason("lamp.on")
        );
        assert!(
            reason("door.open").starts_with("event opened: ")
                && reason("door.open").contains("oneOf"),
            "{}",
            reason("door.open")
        );
        assert_eq!(reason("bell"), reason("door.open"));
    }

    /// A reason holds the node's own names, so it is kept to one short line
    /// for the Overview and the log.
    #[test]
    fn a_reason_is_one_short_line() {
        let long = "/".repeat(4000);
        let mut lamp = cap(
            "lamp",
            "",
            &[(
                "dim",
                Effect::Actuate,
                json!({"type": "object", "properties": {
                    "x\nfake\u{1b}[2J": {"type": "string", "pattern": "a"}}}),
            )],
        );
        lamp.actions.insert(
            "get".into(),
            nerve_proto::descriptor::Action {
                effect: Effect::Read,
                summary: String::new(),
                params: Value::Null,
                result: json!({"type": "object", long.clone(): 1}),
                exposure: None,
                as_account: false,
            },
        );
        let mut door = cap("door", "", &[("open", Effect::Actuate, path())]);
        door.state = state_of(json!({"type": "object", long.clone(): 1}));
        let mut bell = cap("bell", "", &[]);
        bell.events.insert(
            "rang".into(),
            nerve_proto::descriptor::EventDecl {
                effect: Effect::Read,
                summary: "It rang.".into(),
                implicit: false,
                data: json!({"type": "object", long: 1}),
                exposure: None,
            },
        );
        let c = Catalog::build(&desc("box", vec![lamp, door, bell]));
        assert_eq!(names(&c).1, ["bell", "door.open", "lamp.dim", "lamp.get"]);
        for b in &c.broken {
            assert!(!b.reason.chars().any(char::is_control), "{b:?}");
            assert!(
                b.reason.chars().count() <= schema::BRIEF_MAX + 1,
                "{}: {}",
                b.name,
                b.reason.len()
            );
        }
        assert!(
            c.broken[2]
                .reason
                .starts_with("params: /properties/x fake [2J/pattern"),
            "{:?}",
            c.broken
        );
    }

    /// Units are looked up under the store's lock, so finding one must not
    /// scan them all: with a hundred thousand units a scan each would take
    /// minutes.
    #[test]
    fn many_units_are_found_without_a_scan_each() {
        let units: Vec<Unit> = (0..100_000)
            .map(|i| Unit {
                name: format!("c{i:06}.a"),
                cap: format!("c{i:06}"),
                action: "a".into(),
                effect: Effect::Read,
                description: "".into(),
                params: Value::Null,
                result: Value::Null,
                provider: "".into(),
                off: false,
                note: None,
                advice: None,
                as_account: false,
                kind: UnitKind::Action,
            })
            .collect();
        let c = Catalog {
            units,
            broken: Vec::new(),
            reach: None,
        };
        let started = std::time::Instant::now();
        for u in &c.units {
            assert!(c.offers(&u.cap, &u.action));
        }
        assert!(!c.offers("c", "a"));
        assert!(c.unit("c050000.a").is_some());
        let took = started.elapsed();
        assert!(took < std::time::Duration::from_secs(5), "{took:?}");
    }

    /// The node's own descriptor, in every mode, is whole in the catalog: a
    /// unit the center left out of its own node would be a capability lost.
    #[test]
    fn the_nodes_own_descriptor_has_no_broken_unit() {
        use nerve_policy::{CenterEntry, NodeConfig};
        for mode in [
            nerve_policy::Mode::Allowlist,
            nerve_policy::Mode::Folder,
            nerve_policy::Mode::User,
        ] {
            let mut e: CenterEntry = serde_json::from_value(json!({
                "name": "home", "url": "https://center.example", "center_id": "c1",
                "node_id": "n1"
            }))
            .unwrap();
            e.policy.mode = mode;
            let d = nerve_node::descriptor::for_center(
                &NodeConfig::default(),
                &e,
                &nerve_node::descriptor::Reach::of(&e, 0, None, true, None),
                &[],
            );
            let c = Catalog::build(&d);
            assert_eq!(c.broken, [], "{mode:?}");
            // In allowlist mode without rules the node offers nothing yet.
            if mode == nerve_policy::Mode::User {
                assert!(c.unit("exec.run").is_some() && c.unit("fs.read").is_some());
            }
        }
    }
}
