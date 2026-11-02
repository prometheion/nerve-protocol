//! A change to a center's folders: `nerve-node folder add`, `set` and `rm`.
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

/// The most changes one `set` takes.
const CHANGES_MAX: usize = 64;

/// One change to a center's folders. `path` is the folder resolved by the
/// CLI (links followed), `given` the folder as typed: an entry is found by
/// either, so one saved before it was resolved can still be changed.
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
    /// Changes the rights of a folder the center has, left to right (`=rwx`,
    /// `+x`, `-w`).
    Set {
        path: String,
        given: String,
        changes: Vec<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    changes: Option<Vec<String>>,
}

impl FolderChange {
    /// The rights of `folder add`: each starts with `+`, and at least one
    /// is named. A folder that grants nothing is never what was meant.
    pub fn new_rights(rights: &[String]) -> Result<Access, String> {
        let access = rights.iter().try_fold(Access::NONE, |a, r| {
            if r.starts_with('+') {
                a.change(r)
            } else {
                Err(format!("{r:?}: a new folder takes +r, +w or +x"))
            }
        })?;
        if access.is_none() {
            return Err(
                "name what the center may do in the folder: +r (read), +w (write), +x (run commands)"
                    .into(),
            );
        }
        Ok(access)
    }

    /// The control pipe's method for this change (the CLI's call on
    /// Windows).
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn method(&self) -> &'static str {
        match self {
            FolderChange::Add { .. } => "folder.add",
            FolderChange::Set { .. } => "folder.set",
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
            changes: None,
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
            FolderChange::Set {
                path,
                given,
                changes,
            } => {
                p.path = path.clone();
                p.given = Some(given.clone());
                p.changes = Some(changes.clone());
            }
            FolderChange::Rm { path, given } => {
                p.path = path.clone();
                p.given = Some(given.clone());
            }
        }
        serde_json::to_value(p).expect("the parameters serialize")
    }

    /// The change a pipe request asks for, and the center it names. It is
    /// checked as the CLI checks what it was given: an `add` names some
    /// right, a `set` some change, each a change [`Access::change`] takes;
    /// nothing is left out and nothing else is given.
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
        let change = match (method, p.given, p.access, p.recorded, p.changes) {
            ("folder.add", None, Some(access), recorded, None) => {
                let access = Access::parse(&access)?;
                if access.is_none() {
                    return Err("a new folder grants some right: r, w or x".into());
                }
                FolderChange::Add {
                    path: p.path,
                    access,
                    recorded: recorded.unwrap_or(false),
                }
            }
            ("folder.set", Some(given), None, None, Some(changes)) => {
                if changes.is_empty() {
                    return Err("name what to change: =rwx, +x or -w".into());
                }
                if changes.len() > CHANGES_MAX {
                    return Err(format!(
                        "at most {CHANGES_MAX} changes at once; =rwx sets the rights in one"
                    ));
                }
                // Each is checked here, before the config is touched.
                changes.iter().try_fold(Access::NONE, |a, c| a.change(c))?;
                FolderChange::Set {
                    path: p.path,
                    given,
                    changes,
                }
            }
            ("folder.rm", Some(given), None, None, None) => FolderChange::Rm {
                path: p.path,
                given,
            },
            ("folder.add" | "folder.set" | "folder.rm", ..) => {
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
            FolderChange::Set {
                path,
                given,
                changes,
            } => {
                let f = e
                    .policy
                    .folders
                    .iter_mut()
                    .find(|f| f.path == *path || f.path == *given)
                    .ok_or_else(|| format!("{path} is not a folder of this center"))?;
                f.access = changes.iter().try_fold(f.access, |a, c| a.change(c))?;
                Ok(Some(f.access))
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
            FolderChange::Add { path, .. }
            | FolderChange::Set { path, .. }
            | FolderChange::Rm { path, .. } => path,
        }
    }
}

/// The most folders named in the hint when none of them lies beside the path.
const HINT_MAX: usize = 3;

/// The error for a path no folder of the center has. When the node may not
/// even look at the path (the installed node's CLI runs as `nerve`, which
/// cannot read the account's home, so a link there was kept as typed and
/// not resolved), the folder may be listed under the path the link leads
/// to: the message names the folders `folder ls` shows that could be it,
/// the ones beside the path first, or, with none to name, that `folder ls`
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
        "{plain}; this account cannot look into it, so if it is a link, use the path `nerve-node folder ls` shows for the folder"
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

/// The center a per-center command means: the one named, or the only one.
pub fn pick_center(cfg: &NodeConfig, given: Option<&str>) -> Result<String, String> {
    if let Some(n) = given {
        return cfg
            .center(n)
            .map(|c| c.name.clone())
            .ok_or_else(|| format!("no center named {n}"));
    }
    match cfg.centers.as_slice() {
        [] => Err("no center is paired".into()),
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
    let e = cfg
        .center_mut(&name)
        .ok_or_else(|| format!("no center named {name}"))?;
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
                access: FolderChange::new_rights(&["+r".into(), "+x".into()]).unwrap(),
                recorded: false,
            },
            FolderChange::Add {
                path: "/srv/a".into(),
                access: FolderChange::new_rights(&["+w".into()]).unwrap(),
                recorded: true,
            },
            FolderChange::Set {
                path: "/srv/a".into(),
                given: "a".into(),
                changes: vec!["=rw".into(), "-w".into()],
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
        // No right, an unknown one, or one given twice.
        let e = refused("folder.add", json!({"path": "/srv/a", "access": ""}));
        assert!(e.contains("grants some right"), "{e}");
        let e = refused("folder.add", json!({"path": "/srv/a", "access": "rq"}));
        assert!(e.contains("not a folder flag"), "{e}");
        refused("folder.add", json!({"path": "/srv/a", "access": "rr"}));
        // A change that is none, or too many of them.
        let e = refused(
            "folder.set",
            json!({"path": "/srv/a", "given": "a", "changes": []}),
        );
        assert!(e.contains("name what to change"), "{e}");
        let e = refused(
            "folder.set",
            json!({"path": "/srv/a", "given": "a", "changes": ["x"]}),
        );
        assert!(e.contains("start with =, + or -"), "{e}");
        let e = refused(
            "folder.set",
            json!({"path": "/srv/a", "given": "a", "changes": vec!["+r"; CHANGES_MAX + 1]}),
        );
        assert!(e.starts_with("at most 64 changes"), "{e}");
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
        // A folder saved as typed is found by that spelling.
        let set = FolderChange::Set {
            path: "/elsewhere".into(),
            given: "/srv/a".into(),
            changes: vec!["+r".into(), "-x".into()],
        };
        let a = apply_to(&mut one, None, &set).unwrap();
        assert_eq!(a.access.unwrap().to_chmod(), "r--");
        let rm = FolderChange::Rm {
            path: "/srv/a".into(),
            given: "/srv/a".into(),
        };
        assert_eq!(apply_to(&mut one, None, &rm).unwrap().access, None);
        assert!(one.center("home").unwrap().policy.folders.is_empty());
        let e = apply_to(&mut one, None, &rm).unwrap_err();
        assert_eq!(e, "/srv/a is not a folder of this center");
        let e = apply_to(&mut one, None, &set).unwrap_err();
        assert_eq!(e, "/elsewhere is not a folder of this center");
        // The center: the one named, or the only one.
        let mut two = config(&["home", "work"]);
        let e = apply_to(&mut two, None, &add).unwrap_err();
        assert!(e.starts_with("several centers are paired"), "{e}");
        assert_eq!(
            apply_to(&mut two, Some("lab"), &add).unwrap_err(),
            "no center named lab"
        );
        assert_eq!(
            apply_to(&mut config(&[]), None, &add).unwrap_err(),
            "no center is paired"
        );
        apply_to(&mut two, Some("work"), &add).unwrap();
        assert!(two.center("home").unwrap().policy.folders.is_empty());
        assert_eq!(two.center("work").unwrap().policy.folders.len(), 1);
    }

    /// `folder add` takes rights that each start with `+`, and some right.
    #[test]
    fn a_new_folder_names_its_rights() {
        let rights = |r: &[&str]| {
            FolderChange::new_rights(&r.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        };
        assert_eq!(rights(&["+r", "+x"]).unwrap().to_chmod(), "r-x");
        assert!(rights(&["=rw"]).unwrap_err().contains("takes +r, +w or +x"));
        assert!(rights(&["-r"]).unwrap_err().contains("takes +r, +w or +x"));
        assert!(
            rights(&[])
                .unwrap_err()
                .contains("name what the center may do")
        );
    }

    /// A path the node's account may not look into may be a link to a listed
    /// folder: the error then names the folders `folder ls` shows, the ones
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
            "{plain}; this account cannot look into it, so if it is a link, use the path `nerve-node folder ls` shows for the folder"
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
