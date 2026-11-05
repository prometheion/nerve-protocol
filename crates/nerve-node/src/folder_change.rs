//! A change to a center's folders: `nerve-node folder add` and `rm`.
//! The CLI makes it on the config itself, or, on Windows while a node runs,
//! hands it to that node over its control pipe (crate::pipe), which reads it
//! back with [`FolderChange::from_request`] and makes it with the same
//! [`apply_to`]. Both sides check a change the same way, and the config
//! checks the result ([`NodeConfig::validate`]) wherever it is saved.

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use nerve_policy::config::{Access, Folder};
use nerve_policy::{CenterEntry, Mode, NodeConfig};

/// The longest path a request may name: Windows' longest path in bytes.
const PATH_BYTES: usize = 32 * 1024 * 3;

/// One change to a center's folders. `path` is the folder resolved by the
/// CLI (links followed), `given` the folder as typed: an entry is found by
/// either, so one saved before it was resolved can still be removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FolderChange {
    /// Adds the folder with these rights, or replaces the rights it had.
    /// `recorded` says the CLI settled `path` at its real place, so the
    /// center's record of places gets the folder (`CenterPolicy::places`);
    /// without it a record the folder has stays as it is.
    Add {
        path: String,
        access: Access,
        recorded: bool,
    },
    /// Takes a folder away from the center.
    Rm { path: String, given: String },
}

/// What a change did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Applied {
    pub center: String,
    pub path: String,
    /// The folder's rights now; `None` once it is removed.
    pub access: Option<Access>,
    /// The center's mode: folders count in folder mode only.
    pub mode: Mode,
}

/// The request's parameters, as they go over the pipe. A field the node
/// does not know refuses the request.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Params {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    center: Option<String>,
    path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    given: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    access: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recorded: Option<bool>,
}

impl FolderChange {
    /// The rights of `folder add`, one word: the letters `r`, `w` and `x`
    /// (`rw`), or `none`, which closes a folder inside one the center may
    /// use. An empty word is refused: a folder that grants nothing is said
    /// so, never given by a slip.
    pub fn new_rights(rights: &str) -> Result<Access, String> {
        const NAME: &str =
            "name the rights: r (read), w (write), x (run commands), as one word like rw, or none";
        match rights.trim() {
            "none" => Ok(Access::NONE),
            "" => Err(NAME.into()),
            r => Access::parse(r).map_err(|e| format!("{e}; {NAME}")),
        }
    }

    /// The control pipe's method for this change (the CLI's call on
    /// Windows).
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn method(&self) -> &'static str {
        match self {
            FolderChange::Add { .. } => "folder.add",
            FolderChange::Rm { .. } => "folder.rm",
        }
    }

    /// The parameters of the pipe's request, for `center` (`None`: the only
    /// one paired, as the CLI picks it).
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn params(&self, center: Option<&str>) -> Value {
        let mut p = Params {
            center: center.map(str::to_string),
            path: String::new(),
            given: None,
            access: None,
            recorded: None,
        };
        match self {
            FolderChange::Add {
                path,
                access,
                recorded,
            } => {
                p.path = path.clone();
                p.access = Some(access.to_string());
                p.recorded = Some(*recorded);
            }
            FolderChange::Rm { path, given } => {
                p.path = path.clone();
                p.given = Some(given.clone());
            }
        }
        serde_json::to_value(p).expect("the parameters serialize")
    }

    /// The change a pipe request asks for, and the center it names. It is
    /// checked as the CLI checks what it was given: an `add` names rights
    /// [`Access::parse`] takes (none closes a folder); nothing is left out
    /// and nothing else is given.
    pub fn from_request(
        method: &str,
        params: Value,
    ) -> Result<(Option<String>, FolderChange), String> {
        let p: Params =
            serde_json::from_value(params).map_err(|e| format!("bad parameters: {e}"))?;
        let check = |what: &str, s: &str| {
            if s.is_empty() || s.len() > PATH_BYTES || s.contains('\0') {
                return Err(format!("bad parameters: {what} is not a folder path"));
            }
            Ok(())
        };
        check("path", &p.path)?;
        if let Some(g) = &p.given {
            check("given", g)?;
        }
        let change = match (method, p.given, p.access, p.recorded) {
            ("folder.add", None, Some(access), recorded) => FolderChange::Add {
                path: p.path,
                access: Access::parse(&access)?,
                recorded: recorded.unwrap_or(false),
            },
            ("folder.rm", Some(given), None, None) => FolderChange::Rm {
                path: p.path,
                given,
            },
            ("folder.add" | "folder.rm", ..) => {
                return Err(format!("bad parameters for {method}"));
            }
            (other, ..) => return Err(format!("unknown method {other}")),
        };
        Ok((p.center, change))
    }

    /// Makes the change on one center's entry: the folder's rights after
    /// it, `None` for a removed one.
    pub fn apply(&self, e: &mut CenterEntry) -> Result<Option<Access>, String> {
        match self {
            FolderChange::Add {
                path,
                access,
                recorded,
            } => {
                // The same place in another spelling is the same folder: one
                // entry, as `validate` keeps it.
                e.policy.folders.retain(|f| !same_place(&f.path, path));
                e.policy.folders.push(Folder {
                    path: path.clone(),
                    access: *access,
                });
                if *recorded {
                    e.policy.set_placed(path, true);
                }
                Ok(Some(*access))
            }
            FolderChange::Rm { path, given } => {
                let before = e.policy.folders.len();
                e.policy
                    .folders
                    .retain(|f| f.path != *path && f.path != *given);
                if e.policy.folders.len() == before {
                    return Err(format!("{path} is not a folder of this center"));
                }
                Ok(None)
            }
        }
    }

    fn path(&self) -> &str {
        match self {
            FolderChange::Add { path, .. } | FolderChange::Rm { path, .. } => path,
        }
    }
}

/// The most folders named in the hint when none of them lies beside the path.
const HINT_MAX: usize = 3;

/// The error for a path no folder of the center has. When the node may not
/// even look at the path (the installed node's CLI runs as `nerve`, which
/// cannot read the account's home, so a link there was kept as typed and
/// not resolved), the folder may be listed under the path the link leads
/// to: the message names the folders `folder` shows that could be it,
/// the ones beside the path first, or, with none to name, that `folder`
/// shows it. The lookup itself is `stored_folder`'s, in the CLI.
pub fn not_a_folder(path: &str, folders: &[Folder]) -> String {
    let plain = format!("{path} is not a folder of this center");
    let refused = matches!(
        std::fs::symlink_metadata(path),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied
    );
    if !refused {
        return plain;
    }
    if folders.is_empty() {
        return plain;
    }
    let parent = Path::new(path).parent();
    let beside: Vec<&str> = folders
        .iter()
        .filter(|f| Path::new(&f.path).parent() == parent)
        .map(|f| f.path.as_str())
        .collect();
    let named = if beside.is_empty() && folders.len() <= HINT_MAX {
        folders.iter().map(|f| f.path.as_str()).collect()
    } else {
        beside
    };
    let hint = format!(
        "{plain}; this account cannot look into it, so if it is a link, use the path `nerve-node folder` shows for the folder"
    );
    match named.is_empty() {
        true => hint,
        false => format!("{hint}: {}", named.join(", ")),
    }
}

/// Whether two folder paths name one place, compared as the policy does.
fn same_place(a: &str, b: &str) -> bool {
    use nerve_policy::paths::within;
    let (a, b) = (std::path::Path::new(a), std::path::Path::new(b));
    within(a, b) && within(b, a)
}

/// What a command that needs a pairing says when there is none: how to
/// make one.
pub const NO_CENTER_PAIRED: &str =
    "no center is paired; pair one: `nerve-node center add '<link>'`";

/// The error for a center `name` this node has not paired: the names it
/// has, or how to pair one.
pub fn no_center_named(cfg: &NodeConfig, name: &str) -> String {
    match cfg.centers.as_slice() {
        [] => format!("no center named {name}: {NO_CENTER_PAIRED}"),
        many => format!(
            "no center named {name}; paired: {}",
            many.iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// The center a per-center command means: the one named, or the only one.
pub fn pick_center(cfg: &NodeConfig, given: Option<&str>) -> Result<String, String> {
    if let Some(n) = given {
        return cfg
            .center(n)
            .map(|c| c.name.clone())
            .ok_or_else(|| no_center_named(cfg, n));
    }
    match cfg.centers.as_slice() {
        [] => Err(NO_CENTER_PAIRED.into()),
        [one] => Ok(one.name.clone()),
        many => Err(format!(
            "several centers are paired; pick one with --center ({})",
            many.iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// Makes `change` on the center `center` names in `cfg`.
pub fn apply_to(
    cfg: &mut NodeConfig,
    center: Option<&str>,
    change: &FolderChange,
) -> Result<Applied, String> {
    let name = pick_center(cfg, center)?;
    let missing = no_center_named(cfg, &name);
    let e = cfg.center_mut(&name).ok_or(missing)?;
    let access = change.apply(e)?;
    Ok(Applied {
        mode: e.policy.mode,
        center: name,
        path: change.path().to_string(),
        access,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn center(name: &str) -> CenterEntry {
        CenterEntry {
            name: name.into(),
            url: "wss://127.0.0.1:1".into(),
            pin: None,
            center_id: "c".into(),
            node_id: "n".into(),
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

    fn config(names: &[&str]) -> NodeConfig {
        NodeConfig {
            centers: names.iter().map(|n| center(n)).collect(),
            ..Default::default()
        }
    }

    /// Each change goes over the pipe and comes back as it was.
    #[test]
    fn a_change_survives_the_pipe() {
        let changes = [
            FolderChange::Add {
                path: "/srv/a".into(),
                access: FolderChange::new_rights("rx").unwrap(),
                recorded: false,
            },
            FolderChange::Add {
                path: "/srv/a".into(),
                access: FolderChange::new_rights("w").unwrap(),
                recorded: true,
            },
            FolderChange::Add {
                path: "/srv/a/secret".into(),
                access: FolderChange::new_rights("none").unwrap(),
                recorded: true,
            },
            FolderChange::Rm {
                path: "/srv/a".into(),
                given: "./a".into(),
            },
        ];
        for c in changes {
            for center in [None, Some("home")] {
                let (got_center, got) =
                    FolderChange::from_request(c.method(), c.params(center)).unwrap();
                assert_eq!(got, c);
                assert_eq!(got_center.as_deref(), center);
            }
        }
    }

    /// An `add` that does not say it was recorded is not.
    #[test]
    fn an_add_without_the_record_records_nothing() {
        let (_, got) =
            FolderChange::from_request("folder.add", json!({"path": "/srv/a", "access": "r"}))
                .unwrap();
        assert_eq!(
            got,
            FolderChange::Add {
                path: "/srv/a".into(),
                access: Access::parse("r").unwrap(),
                recorded: false,
            }
        );
    }

    /// A request is checked as the CLI checks what it was given, and one that
    /// is not exactly what its method takes is refused.
    #[test]
    fn a_request_is_checked_before_the_config_is_touched() {
        let refused = |method: &str, params: Value| {
            FolderChange::from_request(method, params).expect_err("taken")
        };
        // An unknown right, or one given twice; the method `folder set`
        // had is gone.
        let e = refused("folder.add", json!({"path": "/srv/a", "access": "rq"}));
        assert!(e.contains("not a folder flag"), "{e}");
        refused("folder.add", json!({"path": "/srv/a", "access": "rr"}));
        let e = refused(
            "folder.set",
            json!({"path": "/srv/a", "given": "a", "changes": ["=rw"]}),
        );
        assert!(e.contains("unknown field"), "{e}");
        // What another method takes, a field the node does not know, a
        // field missing, or no path.
        let e = refused(
            "folder.rm",
            json!({"path": "/srv/a", "given": "a", "access": "r"}),
        );
        assert!(e.contains("bad parameters for folder.rm"), "{e}");
        let e = refused(
            "folder.rm",
            json!({"path": "/srv/a", "given": "a", "sudo": "on"}),
        );
        assert!(e.contains("unknown field"), "{e}");
        // The record goes with an `add` only.
        let e = refused(
            "folder.rm",
            json!({"path": "/srv/a", "given": "a", "recorded": true}),
        );
        assert!(e.contains("bad parameters for folder.rm"), "{e}");
        refused("folder.rm", json!({"path": "/srv/a"}));
        refused("folder.add", json!({"path": "", "access": "r"}));
        refused("folder.add", json!({"path": "/srv/\0a", "access": "r"}));
        refused(
            "folder.add",
            json!({"path": "/".repeat(PATH_BYTES + 1), "access": "r"}),
        );
        refused("folder.add", json!(["/srv/a", "r"]));
        let e = refused("config.write", json!({"path": "/srv/a"}));
        assert_eq!(e, "unknown method config.write");
    }

    /// A change finds its center as the CLI does, and does what the CLI's
    /// commands do to the folders.
    #[test]
    fn changes_to_a_centers_folders() {
        let mut one = config(&["home"]);
        let add = FolderChange::Add {
            path: "/srv/a".into(),
            access: Access::parse("rw").unwrap(),
            recorded: false,
        };
        let a = apply_to(&mut one, None, &add).unwrap();
        assert_eq!(
            a,
            Applied {
                center: "home".into(),
                path: "/srv/a".into(),
                access: Some(Access::parse("rw").unwrap()),
                mode: Mode::Allowlist,
            }
        );
        assert!(one.center("home").unwrap().policy.places.is_empty());
        // Adding it again replaces its rights, and records the place the CLI
        // settled it at.
        let again = FolderChange::Add {
            path: "/srv/a".into(),
            access: Access::parse("x").unwrap(),
            recorded: true,
        };
        apply_to(&mut one, Some("home"), &again).unwrap();
        let policy = &one.center("home").unwrap().policy;
        assert_eq!(policy.folders.len(), 1);
        assert_eq!(policy.folders[0].access.to_chmod(), "--x");
        assert_eq!(policy.places, ["/srv/a"]);
        // The same place in another spelling is the same folder; a change
        // that records nothing leaves the record it has.
        let spelled = FolderChange::Add {
            path: "/srv//a/".into(),
            access: Access::parse("r").unwrap(),
            recorded: false,
        };
        apply_to(&mut one, Some("home"), &spelled).unwrap();
        let policy = &one.center("home").unwrap().policy;
        assert_eq!(policy.folders.len(), 1);
        assert_eq!(policy.folders[0].path, "/srv//a/");
        assert_eq!(policy.places, ["/srv/a"]);
        let again = FolderChange::Add {
            path: "/srv/a".into(),
            access: Access::parse("x").unwrap(),
            recorded: false,
        };
        apply_to(&mut one, Some("home"), &again).unwrap();
        // A folder with no rights closes a place inside another.
        let closed = FolderChange::Add {
            path: "/srv/a/secret".into(),
            access: Access::NONE,
            recorded: false,
        };
        let a = apply_to(&mut one, None, &closed).unwrap();
        assert_eq!(a.access.unwrap().to_chmod(), "---");
        // A folder saved as typed is found by that spelling.
        let rm_closed = FolderChange::Rm {
            path: "/elsewhere".into(),
            given: "/srv/a/secret".into(),
        };
        apply_to(&mut one, None, &rm_closed).unwrap();
        let rm = FolderChange::Rm {
            path: "/srv/a".into(),
            given: "/srv/a".into(),
        };
        assert_eq!(apply_to(&mut one, None, &rm).unwrap().access, None);
        assert!(one.center("home").unwrap().policy.folders.is_empty());
        let e = apply_to(&mut one, None, &rm).unwrap_err();
        assert_eq!(e, "/srv/a is not a folder of this center");
        let e = apply_to(&mut one, None, &rm_closed).unwrap_err();
        assert_eq!(e, "/elsewhere is not a folder of this center");
        // The center: the one named, or the only one.
        let mut two = config(&["home", "work"]);
        let e = apply_to(&mut two, None, &add).unwrap_err();
        assert!(e.starts_with("several centers are paired"), "{e}");
        assert_eq!(
            apply_to(&mut two, Some("lab"), &add).unwrap_err(),
            "no center named lab; paired: home, work"
        );
        assert_eq!(
            apply_to(&mut config(&[]), None, &add).unwrap_err(),
            NO_CENTER_PAIRED
        );
        apply_to(&mut two, Some("work"), &add).unwrap();
        assert!(two.center("home").unwrap().policy.folders.is_empty());
        assert_eq!(two.center("work").unwrap().policy.folders.len(), 1);
    }

    /// `folder add` takes its rights as one word, or `none`, and an empty
    /// word is refused.
    #[test]
    fn a_new_folder_names_its_rights() {
        let rights = FolderChange::new_rights;
        assert_eq!(rights("rx").unwrap().to_chmod(), "r-x");
        assert_eq!(rights("xwr").unwrap().to_chmod(), "rwx");
        assert_eq!(rights("none").unwrap(), Access::NONE);
        assert!(rights("+r").unwrap_err().contains("name the rights"));
        assert!(rights("=rw").unwrap_err().contains("not a folder flag"));
        assert!(rights("").unwrap_err().contains("name the rights"));
    }

    /// A path the node's account may not look into may be a link to a listed
    /// folder: the error then names the folders `folder` shows, the ones
    /// beside the path first, and says what to look for when none is named.
    #[cfg(unix)]
    #[test]
    fn a_path_the_node_cannot_look_into_points_to_the_listed_folders() {
        use std::os::unix::fs::PermissionsExt;
        if nerve_transport::net::euid() == 0 {
            return; // root looks into every folder
        }
        let d = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(d.path()).unwrap().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let link = home.join("linkproj").display().to_string();
        let folder = |p: &str| Folder {
            path: p.into(),
            access: Access::parse("r").unwrap(),
        };
        let beside = format!("{}/proj", home.display());
        let plain = format!("{link} is not a folder of this center");
        let hint = format!(
            "{plain}; this account cannot look into it, so if it is a link, use the path `nerve-node folder` shows for the folder"
        );
        let few = [folder(&beside), folder("/srv/a")];
        let many: Vec<Folder> = ["/srv/a", "/srv/b", "/srv/c", "/data/work"]
            .map(folder)
            .into();
        // While the node can look at the path, it is a plain miss.
        assert_eq!(not_a_folder(&link, &few), plain);
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o000)).unwrap();
        let got = [
            not_a_folder(&link, &[]),
            not_a_folder(&link, &few),
            not_a_folder(&link, &[folder("/srv/a"), folder("/srv/b")]),
            not_a_folder(&link, &many),
        ];
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        // No folder at all: nothing to point to.
        assert_eq!(got[0], plain);
        // A folder beside the path is named alone.
        assert_eq!(got[1], format!("{hint}: {beside}"));
        // None beside, and no more than a few in all: every folder.
        assert_eq!(got[2], format!("{hint}: /srv/a, /srv/b"));
        // None beside and more than a few: still the hint, with no names.
        assert_eq!(got[3], hint);
    }
}
