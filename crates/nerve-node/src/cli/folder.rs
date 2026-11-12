//! `nerve-node folder`: the folders a center gets, and the grants that
//! give them to its commands on the machine.

use super::*;

/// `folder rm`: a center no longer gets the folder.
pub(super) async fn rm_folder(
    paths: NodePaths,
    path: PathBuf,
    center: CenterArg,
    out: &mut dyn Write,
) -> Result<(), String> {
    let a = change_stored_folder(&paths, &center, &path, |at| FolderChange::Rm {
        path: at.clone(),
        given: at,
    })
    .await?;
    w(out, format!("{}: removed {}", a.center, a.path));
    tell_grants(&paths, false, out).await;
    Ok(())
}

/// A bare `folder`: the folders a center gets, with their rights.
pub(super) async fn show_folders(
    paths: NodePaths,
    center: CenterArg,
    out: &mut dyn Write,
) -> Result<(), String> {
    let (cfg, _) = read_config(&paths).await?;
    let name = pick_center(&cfg, &center)?;
    let policy = &cfg.center(&name).expect("picked").policy;
    if policy.folders.is_empty() {
        w(out, format!("{name}: no folders"));
    }
    for f in &policy.folders {
        w(out, format!("{}  {}", f.access.to_chmod(), f.path));
    }
    if policy.no_network {
        w(out, format!("{name}: {NO_NETWORK_LINE}"));
    }
    if let Some(note) = network_mode_note(
        policy,
        crate::service::is_service_node(&paths),
        apart_by_hand_here(),
    ) {
        w(out, note);
    }
    Ok(())
}

/// The texts of `v`, a list of strings.
fn texts(v: &Value) -> Vec<&str> {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

/// Whether the error `e` of a folder grant (`<path>: <why>`) is about
/// `path` or something below it.
fn error_about(e: &str, path: &str) -> bool {
    e.strip_prefix(path)
        .is_some_and(|rest| rest.starts_with(':') || rest.starts_with('/'))
}

/// What the node's folder grants (`status`'s `folder_access`, the answer of
/// `folder.grants`) say, a line each. Access `nerve-run` keeps although it
/// should have lost it (`stale`) comes first, as no command of it runs
/// until it is off; then the grants it did not get whole.
pub(super) fn grant_lines(g: &Value) -> Vec<String> {
    let stale = texts(&g["stale"]);
    let errors = texts(&g["errors"]);
    let mut lines = Vec::new();
    for p in &stale {
        let why: Vec<&str> = errors
            .iter()
            .copied()
            .filter(|e| error_about(e, p))
            .collect();
        lines.push(format!(
            "nerve-run keeps its access to {p}, which it should have lost; no command of nerve-run runs until it is taken off{}",
            if why.is_empty() {
                String::new()
            } else {
                format!(": {}", why.join("; "))
            }
        ));
    }
    for e in errors
        .iter()
        .filter(|e| !stale.iter().any(|p| error_about(e, p)))
    {
        lines.push(format!("nerve-run did not get every folder: {e}"));
    }
    lines
}

/// `folder add`, and the folder step of `setup`.
/// What `folder.add` is asked: a page's request that a panic overtook (its
/// count of locks is no longer the node's) adds nothing.
#[cfg(unix)]
fn folder_add_params(
    center: &str,
    path: &str,
    access: nerve_policy::config::Access,
    web_locks: Option<u64>,
) -> Value {
    let mut params = json!({"center": center, "path": path, "access": access.to_string()});
    if let Some(n) = web_locks {
        params["web_locks"] = json!(n);
    }
    params
}

pub(super) async fn add_folder(
    paths: &NodePaths,
    path: &Path,
    rights: &str,
    center: &CenterArg,
    out: &mut dyn Write,
) -> Result<(), String> {
    let w = |out: &mut dyn Write, s: String| {
        let _ = writeln!(out, "{s}");
    };
    // The rights are checked before the folder is looked at.
    let access = FolderChange::new_rights(rights)?;
    let (cfg, _) = read_config(paths).await?;
    let name = pick_center(&cfg, center)?;
    let given = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path)
    };
    // A network folder or drive, which the node cannot hold, is refused
    // before anything looks at it.
    if let Some(why) = crate::drives::refusal(&given.display().to_string()) {
        return Err(why);
    }
    let given = nerve_policy::paths::normal_folder(&given.display().to_string())?;
    // A running node judges the path as the account the commands run as,
    // which this command may not be (the installed node's CLI runs as the
    // node's own user): it follows the links on the path a link at a time,
    // refuses one a command may have put inside a `w` folder, and stores and
    // records the real place, all in one step.
    #[cfg(unix)]
    let asked = {
        let params = folder_add_params(&name, &given, access, crate::owner::web_epoch());
        match nerve_transport::ctl::call(&paths.ctl_socket(), "folder.add", params).await {
            Ok(v) => Some((
                v["stored"].as_str().unwrap_or(&given).to_string(),
                v["recorded"] == true,
                v["mode"].as_str().map(str::to_string),
                v["counts"].as_bool(),
            )),
            Err(e) if e == nerve_transport::ctl::NOT_RUNNING => None,
            Err(e) => return Err(e),
        }
    };
    #[cfg(not(unix))]
    let asked: Option<(String, bool, Option<String>, Option<bool>)> = None;
    let (stored, recorded, mode, counts) = match asked {
        Some(a) => a,
        None => {
            // No node to ask (on Windows the node's pipe takes the change but
            // not the judging): judge the path here, as this process sees it,
            // unless it narrows a listed folder, which stays that entry.
            let listed = cfg
                .center(&name)
                .and_then(|e| crate::folder_change::narrowed(e, &given, access));
            let (stored, recorded) = match listed {
                Some(entry) => entry,
                None => {
                    match crate::exec::settle(&cfg, &crate::paths::home_dir(), Path::new(&given)) {
                        crate::exec::Settled::Refused(why) => {
                            return Err(crate::daemon::refusal(&given, &why));
                        }
                        crate::exec::Settled::At(place) => (place.display().to_string(), true),
                        crate::exec::Settled::Unknown => (given.clone(), false),
                    }
                }
            };
            let change = FolderChange::Add {
                path: stored.clone(),
                access,
                recorded,
            };
            let a = change_folder(paths, center, &change).await?;
            (stored, recorded, Some(a.mode.as_str().to_string()), None)
        }
    };
    w(
        out,
        format!("{name}: folder {stored} {}", access.to_chmod()),
    );
    if access.is_none() {
        w(
            out,
            "note: the folder grants nothing: it closes it to file calls; a command run in the folder around it still reaches it (`nerve-node folder rm` removes it)"
                .into(),
        );
    }
    if !recorded {
        w(
            out,
            format!(
                "note: {stored} is stored as given and not recorded at its real place, since this command cannot tell where its path leads (the installed node's CLI may not look into the account's home) and no running node could: a link that replaces the folder later is followed once no `w` folder shows it, see modes.md \"A folder keeps the place you added\"; start the node and add the folder again"
            ),
        );
    } else if !same_folder(&stored, &given) {
        w(
            out,
            format!("note: {given} leads to {stored}; the folder is stored there"),
        );
    }
    // The running node says whether the folders hold the center's commands
    // (also allowlist mode as nerve-run); without one, folder mode alone is
    // sure to.
    let counts = counts.unwrap_or_else(|| mode.as_deref() == Some(Mode::Folder.as_str()));
    if let Some(mode) = mode.filter(|_| !counts) {
        w(
            out,
            format!(
                "note: folders do not count here: {name} is in {mode} mode, whose commands are not held to them (`nerve-node mode folder`)"
            ),
        );
    }
    // New rights for a folder it had reach what is in it already, and what
    // was moved into it: every grant is walked, as `folder sync` does.
    let had = cfg.center(&name).is_some_and(|c| {
        c.policy
            .folders
            .iter()
            .any(|f| same_folder(&f.path, &stored) || same_folder(&f.path, &given))
    });
    tell_grants(paths, had, out).await;
    Ok(())
}

/// Tells what the running installed Linux node did not manage after a
/// change of the folders: a grant `nerve-run` did not get, or an entry that
/// did not come off (crate::acl). The node brings them in line before it
/// answers, with `every` walking every grant. Nothing without such a node.
async fn tell_grants(paths: &NodePaths, every: bool, out: &mut dyn Write) {
    #[cfg(target_os = "linux")]
    match nerve_transport::ctl::call(
        &paths.ctl_socket(),
        "folder.grants",
        json!({ "every": every }),
    )
    .await
    {
        Ok(v) => {
            tell_grants_of(&v, out);
            grants_also(&v);
        }
        Err(e) => {
            if let Some(line) = walk_goes_on(&e) {
                let _ = writeln!(out, "{line}");
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (paths, every, out);
}

/// What to tell when the node did not answer a walk of the folders in time:
/// on a large tree the walk takes longer than the wait, and it goes on. A
/// second call would only queue another walk.
#[cfg(any(target_os = "linux", windows))]
fn walk_goes_on(error: &str) -> Option<String> {
    // Windows has no `status` at the CLI: the app shows what the walk left.
    let left = if cfg!(windows) {
        ""
    } else {
        ", `nerve-node status` shows what it left"
    };
    (error == nerve_transport::ctl::NO_ANSWER).then(|| {
        format!("the node is still walking the folders and goes on; do not run this again{left}")
    })
}

/// What `folder sync` tells when the call to the node failed.
#[cfg(target_os = "linux")]
fn sync_failed(error: String) -> String {
    if error == nerve_transport::ctl::NOT_RUNNING {
        return "the node does not run; it walks the folders when it starts".to_string();
    }
    walk_goes_on(&error).unwrap_or(error)
}

/// `folder sync`: the running installed Linux node walks every grant now,
/// as it does at its start, and says what that left. On Windows the running
/// node, or this command when none runs, walks every folder grant of the
/// pairings' AppContainers again (crate::grants::walk_every).
pub(super) async fn sync_folders(paths: &NodePaths, out: &mut dyn Write) -> Result<(), String> {
    #[cfg(windows)]
    {
        let v = match crate::cli::node_call(paths, "folder.grants", json!({ "every": true })).await
        {
            Ok(v) => v,
            Err(e) if crate::cli::no_node(paths, &e) => {
                let walked = crate::grants::walk_every(&crate::grants::record_file(paths))?;
                let (cfg, _) = read_config(paths).await?;
                crate::grants::apply_outside(paths, &cfg, &crate::paths::home_dir(), &mut |m| {
                    eprintln!("{m}")
                })
                .report(walked)
                .json()
            }
            Err(e) => return Err(walk_goes_on(&e).unwrap_or(e)),
        };
        report_also(&v);
        for line in windows_sync_lines(&v) {
            let _ = writeln!(out, "{line}");
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        let v = nerve_transport::ctl::call(
            &paths.ctl_socket(),
            "folder.grants",
            json!({ "every": true }),
        )
        .await
        .map_err(sync_failed)?;
        report_also(&v);
        if v["service"] != true {
            let _ = writeln!(out, "{FOLDERS_WITHOUT_ACL}");
            return Ok(());
        }
        let warned = !grant_lines(&v).is_empty();
        tell_grants_of(&v, out);
        if !warned {
            let _ = writeln!(
                out,
                "nerve-run has its access to everything in the folders given to it"
            );
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = paths;
        let _ = writeln!(out, "{FOLDERS_WITHOUT_ACL}");
        Ok(())
    }
}

/// The report of the sync (`folder.grants`, crate::grants::Report) as the
/// data of `folder sync --json`, beside its lines: the same fields on Linux
/// and Windows.
#[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]
fn report_also(v: &Value) {
    for k in ["errors", "stale", "unclosed", "failed", "skipped", "walked"] {
        super::json::also(k, v[k].clone());
    }
}

/// What `folder sync` says on Windows of the answer `v`
/// (crate::grants::Synced::json): each error as a warning, or that every
/// pairing's commands reach what their folders give them.
#[cfg_attr(not(windows), allow(dead_code))]
fn windows_sync_lines(v: &Value) -> Vec<String> {
    let errors = texts(&v["errors"]);
    let stale = texts(&v["stale"]);
    if !errors.is_empty() || !stale.is_empty() {
        let mut lines: Vec<String> = errors.iter().map(|e| format!("warning: {e}")).collect();
        lines.extend(stale.iter().map(|p| {
            format!("warning: {p} keeps a grant its folders no longer give; that pairing's commands do not run until it is taken off")
        }));
        return lines;
    }
    if v["walked"].as_u64() == Some(0) {
        return vec!["nothing to sync: no folder of a pairing carries a grant here".into()];
    }
    vec!["every pairing's commands reach everything in the folders given to them".into()]
}

/// What `folder sync` says where no ACL gives the folders: a node run by
/// hand runs its commands as its own user. Windows walks its pairings'
/// grants instead ([`windows_sync_lines`]).
#[cfg_attr(windows, allow(dead_code))]
const FOLDERS_WITHOUT_ACL: &str =
    "nothing to sync: only the installed node on Linux gives nerve-run its folders by their ACLs";

/// What [`tell_grants`] says of the node's answer `v`, and adds to `--json`:
/// `grant_errors` and `grant_stale`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn tell_grants_of(v: &Value, out: &mut dyn Write) {
    for line in grant_lines(v) {
        let _ = writeln!(out, "warning: {line}");
    }
}

/// What a folder change's `--json` says of the grants besides its lines:
/// the errors and the stale folders, when there are any (`folder sync`
/// gives the whole report instead, [`report_also`]).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn grants_also(v: &Value) {
    let errors = texts(&v["errors"]);
    if !errors.is_empty() {
        json::also("grant_errors", json!(errors));
    }
    let stale = texts(&v["stale"]);
    if !stale.is_empty() {
        json::also("grant_stale", json!(stale));
    }
}

/// Whether two folder paths name one place.
fn same_folder(a: &str, b: &str) -> bool {
    use nerve_policy::paths::within;
    within(Path::new(a), Path::new(b)) && within(Path::new(b), Path::new(a))
}

/// `folder rm`: the change `make` builds for the stored
/// folder `path` means ([`stored_folder`]), made as [`change_folder`] makes
/// it. The folder is looked up on the config as the CLI reads it, then named
/// by its stored path, so that a change to the file in between ends in "not
/// a folder of this center" and never in another folder.
async fn change_stored_folder(
    paths: &NodePaths,
    center: &CenterArg,
    path: &Path,
    make: impl FnOnce(String) -> FolderChange,
) -> Result<Applied, String> {
    let (cfg, _) = read_config(paths).await?;
    let name = pick_center(&cfg, center)?;
    let folders = &cfg.center(&name).expect("picked above").policy.folders;
    let at = stored_folder(folders, path)?;
    change_folder(paths, center, &make(at)).await
}

/// Changes a center's folders. On Windows a running node takes the change
/// over its control pipe and makes it itself, folder grants included
/// (crate::pipe); a node that does not run, and the other platforms, take
/// it as every other change ([`edit`]).
async fn change_folder(
    paths: &NodePaths,
    center: &CenterArg,
    change: &FolderChange,
) -> Result<Applied, String> {
    #[cfg(windows)]
    match crate::pipe::call(
        paths,
        change.method(),
        change.params(center.center.as_deref()),
    )
    .await
    {
        Ok(v) => {
            return serde_json::from_value(v)
                .map_err(|e| format!("the node's answer is not understood: {e}"));
        }
        // A node that runs holds the keys' lock.
        Err(e) if crate::pipe::file_instead(&e, || crate::secrets::KeysLock::node_runs(paths)) => {}
        // The change is not undone by a late answer: the node goes on.
        Err(e) => return Err(walk_goes_on(&e).unwrap_or(e)),
    }
    let (cfg, _) = read_config(paths).await?;
    let name = pick_center(&cfg, center)?;
    let applied = std::cell::RefCell::new(None);
    edit(paths, |c| {
        *applied.borrow_mut() = Some(crate::folder_change::apply_to(c, Some(&name), change)?);
        Ok(())
    })
    .await?;
    Ok(applied.into_inner().expect("applied when edit succeeds"))
}

/// The path of the stored folder `folder rm` means by `path`,
/// found before the path is resolved, which fails where a dangling link or a
/// loop of links stands now. In this order: the folder the path is spelled as
/// (made absolute and tidy, no link followed); the folder its resolution lands
/// at, a link at a time (`folder add` stored the real place of a path through
/// a link of the owner's, and a link may have replaced that place since); the
/// folder at the real place the path leads to.
fn stored_folder(folders: &[Folder], path: &Path) -> Result<String, String> {
    use nerve_policy::paths::within;
    let same = |a: &Path, b: &Path| within(a, b) && within(b, a);
    let stored = |p: &Path| {
        folders
            .iter()
            .find(|f| same(p, Path::new(&f.path)))
            .map(|f| f.path.clone())
    };
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path)
    };
    let spelled = nerve_policy::paths::normal_folder(&abs.display().to_string()).ok();
    if let Some(f) = spelled.and_then(|s| stored(Path::new(&s))) {
        return Ok(f);
    }
    if let Some(f) = crate::exec::lands_at(&abs, |p| stored(p).is_some()).and_then(|p| stored(&p)) {
        return Ok(f);
    }
    let real = resolve_folder(path)?;
    stored(Path::new(&real)).ok_or_else(|| crate::folder_change::not_a_folder(&real, folders))
}

/// Folders are stored resolved (symlinks followed), the way the policy
/// compares them.
fn resolve_folder(p: &Path) -> Result<String, String> {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().map_err(|e| e.to_string())?.join(p)
    };
    match nerve_policy::paths::resolve(&abs) {
        Ok(real) => Ok(real.display().to_string()),
        // On the installed node this command runs as `nerve`, which may not
        // look into the account's home; the folder is kept as given, and the
        // node looks at it as the account when a call comes.
        Err(nerve_policy::paths::PathError::Io(e))
            if e.kind() == std::io::ErrorKind::PermissionDenied =>
        {
            nerve_policy::paths::normal_folder(&abs.display().to_string())
        }
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What Windows' `folder sync` says: each error and stale grant as a
    /// warning, else that the grants hold, or that there are none.
    #[test]
    fn windows_folder_sync_says_what_the_walk_left() {
        let ok = windows_sync_lines(&json!({"errors": [], "stale": [], "walked": 3}));
        assert_eq!(
            ok,
            ["every pairing's commands reach everything in the folders given to them"]
        );
        let none = windows_sync_lines(&json!({"errors": [], "stale": [], "walked": 0}));
        assert!(none[0].starts_with("nothing to sync"), "{none:?}");
        let bad = windows_sync_lines(&json!({
            "errors": ["cannot take the grant off C:\\a: denied"],
            "stale": ["C:\\a"],
            "walked": 1,
        }));
        assert_eq!(bad.len(), 2, "{bad:?}");
        assert!(bad.iter().all(|l| l.starts_with("warning: ")), "{bad:?}");
        assert!(
            bad[1].contains("keeps a grant its folders no longer give"),
            "{bad:?}"
        );
    }
    use crate::cli::tests::{load, run, setup};
    use nerve_policy::config::Access;

    /// A folder the web UI adds carries the count of locks its request began
    /// with, so a panic that overtook it adds nothing (the node compares it
    /// under the store's lock); the CLI of a person carries none.
    #[cfg(unix)]
    #[test]
    fn a_web_folder_add_names_the_locks_it_began_with() {
        let access = Access::parse("r").unwrap();
        let by_hand = folder_add_params("home", "/srv/docs", access, None);
        assert_eq!(by_hand.get("web_locks"), None, "{by_hand}");
        let from_web = folder_add_params("home", "/srv/docs", access, Some(3));
        assert_eq!(from_web["web_locks"], 3, "{from_web}");
        assert_eq!(from_web["center"], "home");
        assert_eq!(from_web["access"], "r");
    }

    /// A folder in a home the node's user may not look into (the installed
    /// node's CLI runs as `nerve`) is kept as given, in its normal form;
    /// what may be seen is resolved.
    #[cfg(unix)]
    #[test]
    fn a_folder_the_cli_cannot_look_into_is_kept_as_given() {
        use std::os::unix::fs::PermissionsExt;
        if nerve_transport::net::euid() == 0 {
            return; // root looks into every folder
        }
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let home = root.join("home");
        std::fs::create_dir_all(home.join("proj")).unwrap();
        std::os::unix::fs::symlink(home.join("proj"), root.join("link")).unwrap();
        assert_eq!(
            resolve_folder(&root.join("link")).unwrap(),
            home.join("proj").display().to_string()
        );
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o000)).unwrap();
        let given = format!("{}//proj/./x/", home.display());
        let r = resolve_folder(Path::new(&given));
        let up = resolve_folder(&home.join("proj/../../etc"));
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(r.unwrap(), home.join("proj/x").display().to_string());
        assert!(up.is_err(), "{up:?}");
    }

    /// Narrowing a listed folder changes that entry, also where its path
    /// has become a link to elsewhere since: the wider entry does not stay
    /// beside a narrow one at the link's end (round 1, correctness 10).
    #[cfg(unix)]
    #[test]
    fn narrowing_a_listed_folder_changes_that_entry() {
        let (d, paths) = setup(&["home"]);
        let proj = d.path().join("proj");
        std::fs::create_dir(&proj).unwrap();
        let listed = proj.to_str().unwrap().to_string();
        run(&paths, &["folder", "add", &listed, "rwx"]).unwrap();
        let folders = || load(&paths).centers[0].policy.folders.clone();
        assert_eq!(folders()[0].path, listed);
        let moved = d.path().join("srv-proj");
        std::fs::rename(&proj, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &proj).unwrap();
        run(&paths, &["folder", "add", &listed, "r"]).unwrap();
        let f = folders();
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(
            (f[0].path.as_str(), f[0].access.to_string().as_str()),
            (listed.as_str(), "r")
        );
        // Wider is looked at again: the link's end is the folder then.
        run(&paths, &["folder", "add", &listed, "rw"]).unwrap();
        assert!(folders().iter().any(|f| f.path == moved.to_str().unwrap()));
    }

    /// `folder add` takes its rights as one word, and changes the rights of
    /// a folder it has; `none` closes one inside another.
    #[test]
    fn folder_add_takes_its_rights_as_one_word() {
        let (d, paths) = setup(&["home"]);
        let dir = d.path().join("work");
        std::fs::create_dir(&dir).unwrap();
        let dir = dir.to_str().unwrap();
        let folders = || load(&paths).centers[0].policy.folders.clone();
        // No rights at all: refused, nothing stored.
        assert!(run(&paths, &["folder", "add", dir]).is_err());
        assert!(folders().is_empty());
        // The old signs, flags and other words are no rights.
        for bad in ["--rw", "--execute", "+r", "-w", "=r", "+", "q", "rr", ""] {
            assert!(
                run(&paths, &["folder", "add", dir, bad]).is_err(),
                "{bad:?}"
            );
        }
        // Two words are not one.
        assert!(run(&paths, &["folder", "add", dir, "r", "x"]).is_err());
        assert!(folders().is_empty());
        // Each right alone, and several in one word; `w` reads too.
        for (rights, want) in [
            ("r", "r"),
            ("w", "rw"),
            ("x", "x"),
            ("rx", "rx"),
            ("xw", "rwx"),
            ("rwx", "rwx"),
        ] {
            run(&paths, &["folder", "add", dir, rights]).unwrap();
            assert_eq!(folders().len(), 1, "added again, not twice");
            assert_eq!(folders()[0].access.to_string(), want, "{rights:?}");
        }
        let inner = d.path().join("work/secret");
        std::fs::create_dir(&inner).unwrap();
        let out = run(&paths, &["folder", "add", inner.to_str().unwrap(), "none"]).unwrap();
        assert!(out.contains("the folder grants nothing"), "{out}");
        // Its limit is said where it is made, and in the first line of its
        // help (round 1, security 3).
        assert!(
            out.contains("a command run in the folder around it still reaches it"),
            "{out}"
        );
        let add = Cli::command();
        let add = add
            .find_subcommand("folder")
            .and_then(|f| f.find_subcommand("add"))
            .unwrap();
        assert!(
            add.get_about()
                .unwrap()
                .to_string()
                .contains("file calls only"),
            "{:?}",
            add.get_about()
        );
        assert_eq!(folders()[1].access, Access::NONE);
    }

    /// `folder add` records the place it stores, so that a link which
    /// replaces the folder later is refused (`exec::folder_sets`). Adding it
    /// again, also through a link of the owner's, keeps one entry; `folder
    /// set` keeps it, and `folder rm` takes it away with the folder.
    #[cfg(unix)]
    #[test]
    fn folder_add_records_the_place_and_rm_forgets_it() {
        let (d, paths) = setup(&["home"]);
        let work = d.path().join("work");
        std::fs::create_dir(&work).unwrap();
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&work, &link).unwrap();
        let real = nerve_policy::paths::resolve(&work)
            .unwrap()
            .display()
            .to_string();
        let (work, link) = (work.to_str().unwrap(), link.to_str().unwrap());
        let places = || load(&paths).centers[0].policy.places.clone();
        assert!(places().is_empty());
        run(&paths, &["folder", "add", work, "r"]).unwrap();
        assert_eq!(places(), std::slice::from_ref(&real));
        // The same place again, and by a link: one folder, one entry.
        run(&paths, &["folder", "add", link, "rw"]).unwrap();
        run(&paths, &["folder", "add", work, "rwx"]).unwrap();
        assert_eq!(load(&paths).centers[0].policy.folders.len(), 1);
        assert_eq!(places(), std::slice::from_ref(&real));
        run(&paths, &["folder", "rm", link]).unwrap();
        assert!(load(&paths).centers[0].policy.folders.is_empty());
        assert!(places().is_empty());
        // Added once more, it is recorded once more.
        run(&paths, &["folder", "add", work, "r"]).unwrap();
        assert_eq!(places(), std::slice::from_ref(&real));
    }

    /// A folder the CLI cannot look into (the installed node's CLI runs as
    /// `nerve`, a home may be closed to it) is stored as given and cannot be
    /// recorded here: with no running node to judge it as the account, the
    /// command says so.
    #[cfg(unix)]
    #[test]
    fn a_folder_the_cli_cannot_judge_is_added_with_a_note_and_no_record() {
        use std::os::unix::fs::PermissionsExt;
        if nerve_transport::net::euid() == 0 {
            return; // root looks into every folder
        }
        let (d, paths) = setup(&["home"]);
        let root = std::fs::canonicalize(d.path()).unwrap();
        let home = root.join("home");
        std::fs::create_dir_all(home.join("proj")).unwrap();
        let proj = home.join("proj");
        let closed = std::fs::Permissions::from_mode(0o000);
        std::fs::set_permissions(&home, closed).unwrap();
        let out = run(&paths, &["folder", "add", proj.to_str().unwrap(), "rw"]);
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        let out = out.unwrap();
        assert!(out.contains("not recorded at its real place"), "{out}");
        assert!(out.contains(&proj.display().to_string()), "{out}");
        let policy = load(&paths).centers[0].policy.clone();
        assert_eq!(policy.folders.len(), 1);
        assert!(policy.places.is_empty(), "{policy:?}");
        // One it could judge says nothing of the kind.
        let out = run(&paths, &["folder", "add", proj.to_str().unwrap(), "rw"]).unwrap();
        assert!(!out.contains("not recorded"), "{out}");
        assert_eq!(load(&paths).centers[0].policy.places.len(), 1);
        // Narrowed where it cannot look, the listed entry changes in place
        // with its record: nothing needs a look.
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o000)).unwrap();
        let out = run(&paths, &["folder", "add", proj.to_str().unwrap(), "r"]);
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!out.unwrap().contains("not recorded"));
        let policy = load(&paths).centers[0].policy.clone();
        assert_eq!(policy.folders.len(), 1);
        assert_eq!(policy.folders[0].access.to_string(), "r");
        assert_eq!(policy.places, [proj.display().to_string()]);
        // Widened where it cannot look, the rights change and the record it
        // has stays: a record only narrows, and the node checks it as the
        // account before each command.
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o000)).unwrap();
        let out = run(&paths, &["folder", "add", proj.to_str().unwrap(), "rwx"]);
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(out.unwrap().contains("not recorded at its real place"));
        let policy = load(&paths).centers[0].policy.clone();
        assert_eq!(policy.folders.len(), 1);
        assert_eq!(policy.folders[0].access.to_string(), "rwx");
        assert_eq!(policy.places, [proj.display().to_string()]);
    }

    /// In the state the new warning reports, a link has replaced a recorded
    /// folder and its real place is another folder. `folder rm` acts on the
    /// folder the path is spelled as (also with a trailing slash), names it,
    /// and leaves the folder the link leads to alone; a path that is a link
    /// to a folder still finds the folder at its real place.
    #[cfg(unix)]
    #[test]
    fn folder_rm_finds_a_folder_a_link_replaced_by_its_spelling() {
        let (d, paths) = setup(&["home"]);
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (work, docs) = (root.join("work"), root.join("docs"));
        let bin = work.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir(&docs).unwrap();
        for (p, rights) in [(&work, "rw"), (&bin, "r"), (&docs, "r")] {
            run(&paths, &["folder", "add", p.to_str().unwrap(), rights]).unwrap();
        }
        std::fs::remove_dir(&bin).unwrap();
        std::os::unix::fs::symlink(&docs, &bin).unwrap();
        let folders = || load(&paths).centers[0].policy.clone();
        let access = |p: &Path| {
            let policy = folders();
            let f = policy.folders.iter().find(|f| Path::new(&f.path) == p);
            f.map(|f| f.access.to_string())
        };
        let spelled = format!("{}/", bin.display());
        assert_eq!(access(&bin).as_deref(), Some("r"));

        let out = run(&paths, &["folder", "rm", &spelled]).unwrap();
        assert!(out.contains(&format!("removed {}", bin.display())), "{out}");
        assert_eq!(access(&bin), None);
        assert_eq!(access(&docs).as_deref(), Some("r"));
        assert!(!folders().is_placed(&bin.display().to_string()));
        assert!(folders().is_placed(&docs.display().to_string()));

        // The owner's own link to a folder finds the folder it leads to.
        let to_docs = root.join("to-docs");
        std::os::unix::fs::symlink(&docs, &to_docs).unwrap();
        let out = run(&paths, &["folder", "rm", to_docs.to_str().unwrap()]).unwrap();
        assert!(
            out.contains(&format!("removed {}", docs.display())),
            "{out}"
        );
        assert_eq!(access(&docs), None);
        assert_eq!(access(&work).as_deref(), Some("rw"));
    }

    /// `folder rm` finds the stored folder by the path the owner gave
    /// `folder add`, when that went through a link of the owner's
    /// and the stored place has been replaced by a link since; and where a
    /// dangling link or a loop of links stands in the folder's place, which
    /// resolving the path would refuse. A folder the path only passes is not
    /// the folder it names.
    #[cfg(unix)]
    #[test]
    fn folder_rm_reaches_a_folder_through_links_and_where_none_resolves() {
        let (d, paths) = setup(&["home"]);
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (work, docs, data) = (root.join("work"), root.join("docs"), root.join("data"));
        let (real, code) = (data.join("real"), root.join("code"));
        for p in [&work.join("bin"), &work.join("sub"), &docs, &real] {
            std::fs::create_dir_all(p).unwrap();
        }
        std::os::unix::fs::symlink(&real, &code).unwrap();
        for (p, rights) in [
            (&work, "rw"),
            (&work.join("bin"), "r"),
            (&code, "r"),
            (&docs, "r"),
        ] {
            run(&paths, &["folder", "add", p.to_str().unwrap(), rights]).unwrap();
        }
        let listed = || -> Vec<String> {
            load(&paths).centers[0]
                .policy
                .folders
                .iter()
                .map(|f| f.path.clone())
                .collect()
        };
        let has = |p: &Path| listed().contains(&p.display().to_string());
        assert!(has(&real) && !has(&code), "stored at the real place");

        // The stored place is replaced by a link to `docs`: `code`, the path
        // the owner gave, still names the stored folder and not `docs`.
        std::fs::remove_dir(&real).unwrap();
        std::os::unix::fs::symlink(&docs, &real).unwrap();
        let out = run(&paths, &["folder", "rm", code.to_str().unwrap()]).unwrap();
        assert!(
            out.contains(&format!("removed {}", real.display())),
            "{out}"
        );
        assert!(!has(&real) && has(&docs));

        // A folder the path only passes is not the folder it names.
        let e = run(
            &paths,
            &["folder", "rm", work.join("sub").to_str().unwrap()],
        )
        .unwrap_err();
        assert!(e.contains("not a folder of this center"), "{e}");
        assert!(has(&work));

        // A dangling link, and then a loop, stand where `work/bin` was.
        let bin = work.join("bin");
        std::fs::remove_dir(&bin).unwrap();
        std::os::unix::fs::symlink(root.join("nowhere"), &bin).unwrap();
        assert!(has(&bin));
        std::fs::remove_file(&bin).unwrap();
        std::os::unix::fs::symlink(&bin, &bin).unwrap();
        let out = run(&paths, &["folder", "rm", bin.to_str().unwrap()]).unwrap();
        assert!(out.contains(&format!("removed {}", bin.display())), "{out}");
        assert!(!has(&bin) && has(&work) && has(&docs));
        // What is not stored under any spelling still says why.
        let e = run(&paths, &["folder", "rm", bin.to_str().unwrap()]).unwrap_err();
        assert!(
            e.contains("Too many levels") || e.contains("symlink"),
            "{e}"
        );
    }

    /// The installed node's CLI runs as `nerve`, which cannot look into the
    /// owner's home: a link there stays as typed, and the folder `folder add`
    /// stored at the place the link leads to is not found. `folder rm` then
    /// names the path `folder` shows (issue #98), also where the center has
    /// more folders than the hint would list.
    #[cfg(unix)]
    #[test]
    fn folder_rm_names_the_listed_folder_for_a_link_the_cli_cannot_look_into() {
        use std::os::unix::fs::PermissionsExt;
        if nerve_transport::net::euid() == 0 {
            return; // root looks into every folder
        }
        let (d, paths) = setup(&["home"]);
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (home, data) = (root.join("home"), root.join("data"));
        let (proj, work) = (home.join("proj"), data.join("work"));
        for p in [&proj, &work] {
            std::fs::create_dir_all(p).unwrap();
        }
        let (link, far) = (home.join("linkproj"), home.join("sub").join("linkwork"));
        std::fs::create_dir(home.join("sub")).unwrap();
        std::os::unix::fs::symlink(&proj, &link).unwrap();
        std::os::unix::fs::symlink(&work, &far).unwrap();
        for p in [&proj, &work] {
            run(&paths, &["folder", "add", p.to_str().unwrap(), "r"]).unwrap();
        }
        let listed = |n: usize| load(&paths).centers[0].policy.folders.len() == n;
        // While the CLI can look at the link, it finds the folder.
        let out = run(&paths, &["folder", "add", link.to_str().unwrap(), "rx"]).unwrap();
        assert!(
            out.contains(&format!("folder {} r-x", proj.display())),
            "{out}"
        );
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o000)).unwrap();
        let mut errors = Vec::new();
        errors.push(run(&paths, &["folder", "rm", link.to_str().unwrap()]).unwrap_err());
        // Only folders far from the path are listed, and more than the hint
        // would name: it still says what to do.
        for n in ["a", "b"] {
            let p = root.join(n);
            std::fs::create_dir(&p).unwrap();
            run(&paths, &["folder", "add", p.to_str().unwrap(), "r"]).unwrap();
        }
        errors.push(run(&paths, &["folder", "rm", far.to_str().unwrap()]).unwrap_err());
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        for e in &errors[..1] {
            assert!(
                e.starts_with(&format!(
                    "{} is not a folder of this center",
                    link.display()
                )),
                "{e}"
            );
            assert!(
                e.ends_with(&format!(
                    "`nerve-node folder` shows for the folder: {}",
                    proj.display()
                )),
                "{e}"
            );
        }
        let e = &errors[1];
        assert!(e.contains("this account cannot look into it"), "{e}");
        assert!(e.ends_with("shows for the folder"), "{e}");
        // The refused calls changed nothing.
        assert!(listed(4));
    }

    /// A link a command may have put inside a folder it can write in is not
    /// followed by `folder add`: it would store, and record, whatever the link
    /// leads to, past the check that keeps such a folder out of the sandbox.
    /// A link of the owner's elsewhere is followed, as before.
    #[cfg(unix)]
    #[test]
    fn folder_add_does_not_follow_a_link_inside_a_write_folder() {
        let (d, paths) = setup(&["home"]);
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (work, docs) = (root.join("work"), root.join("docs"));
        let bin = work.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir(&docs).unwrap();
        run(&paths, &["folder", "add", work.to_str().unwrap(), "rw"]).unwrap();
        // The folder is a plain one first, and then a command replaces it.
        run(&paths, &["folder", "add", bin.to_str().unwrap(), "r"]).unwrap();
        std::fs::remove_dir(&bin).unwrap();
        std::os::unix::fs::symlink(&docs, &bin).unwrap();
        let before = load(&paths).centers[0].policy.clone();
        let e = run(&paths, &["folder", "add", bin.to_str().unwrap(), "rx"]).unwrap_err();
        assert!(e.contains("link") && e.contains("may write"), "{e}");
        let policy = load(&paths).centers[0].policy.clone();
        assert_eq!(
            policy, before,
            "nothing changed, the record of `bin` included"
        );
        assert!(policy.is_placed(&bin.display().to_string()));
        assert!(!policy.is_placed(&docs.display().to_string()));
        assert!(!policy.is_placed(&docs.display().to_string()));
        // A link of the owner's outside every write folder is followed.
        let to_docs = root.join("to-docs");
        std::os::unix::fs::symlink(&docs, &to_docs).unwrap();
        run(&paths, &["folder", "add", to_docs.to_str().unwrap(), "r"]).unwrap();
        assert!(
            load(&paths).centers[0]
                .policy
                .is_placed(&docs.display().to_string())
        );
    }

    /// On Windows, a junction a command may have put inside a folder it can
    /// write in is not followed by `folder add` either.
    #[cfg(windows)]
    #[test]
    fn folder_add_does_not_follow_a_junction_inside_a_write_folder() {
        let (d, paths) = setup(&["home"]);
        let root = nerve_policy::paths::resolve(d.path()).unwrap();
        let (work, docs) = (root.join("work"), root.join("docs"));
        let bin = work.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir(&docs).unwrap();
        run(&paths, &["folder", "add", work.to_str().unwrap(), "rw"]).unwrap();
        std::fs::remove_dir(&bin).unwrap();
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&bin)
            .arg(&docs)
            .output()
            .unwrap();
        assert!(made.status.success(), "{made:?}");
        let e = run(&paths, &["folder", "add", bin.to_str().unwrap(), "rx"]).unwrap_err();
        assert!(e.contains("link") && e.contains("may write"), "{e}");
        let policy = load(&paths).centers[0].policy.clone();
        assert_eq!(policy.folders.len(), 1, "nothing was stored: {policy:?}");
        assert!(!policy.is_placed(&docs.display().to_string()));
    }

    /// `folder add` of a folder the center has sets its rights to the ones
    /// given; a bad word changes nothing.
    #[test]
    fn folder_add_again_changes_the_rights() {
        let (d, paths) = setup(&["home"]);
        let dir = d.path().join("work");
        std::fs::create_dir(&dir).unwrap();
        let dir = dir.to_str().unwrap();
        let access = || load(&paths).centers[0].policy.folders[0].access.to_string();
        run(&paths, &["folder", "add", dir, "r"]).unwrap();
        for (rights, want) in [("rx", "rx"), ("x", "x"), ("rwx", "rwx"), ("none", "")] {
            run(&paths, &["folder", "add", dir, rights, "--center", "home"]).unwrap();
            assert_eq!(access(), want, "{rights}");
        }
        run(&paths, &["folder", "add", dir, "rx", "--center=home"]).unwrap();
        for bad in ["+w", "q", "=rr", "rr"] {
            assert!(
                run(&paths, &["folder", "add", dir, bad]).is_err(),
                "{bad:?}"
            );
            assert_eq!(access(), "rx", "{bad:?}");
        }
        assert!(run(&paths, &["folder", "add", dir, "r", "--center", "nobody"]).is_err());
        assert_eq!(access(), "rx");
        let out = run(&paths, &["folder"]).unwrap();
        assert!(out.starts_with("r-x  "), "{out}");
        run(&paths, &["folder", "rm", dir]).unwrap();
        assert!(load(&paths).centers[0].policy.folders.is_empty());
        assert!(run(&paths, &["folder", "rm", dir]).is_err());
    }

    /// After a change of the folders the CLI says what the node's sync
    /// left: access that should have gone as such, a grant not given whole
    /// as that (#142).
    #[test]
    fn a_folder_change_tells_what_the_grants_left() {
        let mut out = Vec::new();
        tell_grants_of(
            &json!({
                "stale": ["/home/alice/old"],
                "errors": [
                    "/home/alice/old: Permission denied (os error 13)",
                    "/home/alice/older: not this one",
                    "/home/alice/new: Operation not supported",
                ],
            }),
            &mut out,
        );
        let out = String::from_utf8(out).unwrap();
        assert_eq!(
            out,
            "warning: nerve-run keeps its access to /home/alice/old, which it should have lost; no command of nerve-run runs until it is taken off: /home/alice/old: Permission denied (os error 13)\n\
             warning: nerve-run did not get every folder: /home/alice/older: not this one\n\
             warning: nerve-run did not get every folder: /home/alice/new: Operation not supported\n"
        );
        let mut out = Vec::new();
        tell_grants_of(&json!({"stale": [], "errors": []}), &mut out);
        assert!(out.is_empty());
    }

    /// A node whose `folder.grants` answers `answer` and keeps the requests
    /// it got.
    #[cfg(target_os = "linux")]
    fn grants_node(
        paths: &NodePaths,
        answer: Value,
    ) -> std::sync::Arc<std::sync::Mutex<Vec<(String, Value)>>> {
        let got = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (sock, kept) = (paths.ctl_socket(), got.clone());
        tokio::spawn(async move {
            let _ = nerve_transport::ctl::serve(&sock, move |req, _| {
                let (answer, kept) = (answer.clone(), kept.clone());
                async move {
                    kept.lock().unwrap().push((req.method.clone(), req.params));
                    nerve_transport::ctl::Reply::Ok(answer)
                }
            })
            .await;
        });
        while !paths.ctl_socket().exists() {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        got
    }

    /// `folder sync` asks the node to walk every grant, and tells the owner
    /// what that left, or that there is nothing to sync where no ACL gives the
    /// folders. `folder add` of a listed folder asks the same; `folder rm`
    /// only for the changed grants.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread")]
    async fn folder_sync_walks_every_grant_and_tells_what_it_left() {
        let (_d, paths) = setup(&["home"]);
        let mut out = Vec::new();
        let e = sync_folders(&paths, &mut out).await.unwrap_err();
        assert!(e.contains("does not run"), "{e}");

        let got = grants_node(&paths, json!({"service": true, "errors": [], "stale": []}));
        let mut out = Vec::new();
        sync_folders(&paths, &mut out).await.unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("nerve-run has its access"), "{out}");
        assert_eq!(
            got.lock().unwrap().last().unwrap(),
            &("folder.grants".to_string(), json!({"every": true}))
        );
        for (every, want) in [(true, true), (false, false)] {
            tell_grants(&paths, every, &mut Vec::new()).await;
            assert_eq!(got.lock().unwrap().last().unwrap().1["every"], want);
        }
    }

    /// `folder sync --json` gives the sync's report as its data, the same
    /// fields on Linux and Windows (crate::grants::Report), beside its
    /// lines.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread")]
    async fn folder_sync_json_gives_the_report() {
        let (_d, paths) = setup(&["home"]);
        let report = crate::grants::Report {
            failed: vec!["/home/alice/usb".into()],
            skipped: 2,
            walked: 3,
            ..Default::default()
        };
        let mut answer = report.json();
        answer["service"] = json!(true);
        grants_node(&paths, answer);
        let cli = crate::cli::Cli::try_parse_from([
            "nerve-node".as_ref(),
            "--config-dir".as_ref(),
            paths.config_dir.as_os_str(),
            "--state-dir".as_ref(),
            paths.state_dir.as_os_str(),
            "--json".as_ref(),
            "folder".as_ref(),
            "sync".as_ref(),
        ])
        .unwrap();
        let mut out = Vec::new();
        crate::cli::execute(cli, &mut out).await.unwrap();
        let v: Value = serde_json::from_slice(&out).unwrap();
        for (k, want) in report.json().as_object().unwrap() {
            assert_eq!(&v[k], want, "{k}: {v}");
        }
        assert!(v["messages"].is_array(), "{v}");
    }

    /// A walk that outlasts the wait for the node's answer goes on: the
    /// owner is told not to ask again, which would queue one more walk.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_walk_longer_than_the_wait_is_said_to_go_on() {
        let line = walk_goes_on(nerve_transport::ctl::NO_ANSWER).unwrap();
        assert!(
            line.contains("still walking") && !line.contains("try again"),
            "{line}"
        );
        assert_eq!(walk_goes_on(nerve_transport::ctl::NOT_RUNNING), None);
        assert_eq!(sync_failed(nerve_transport::ctl::NO_ANSWER.into()), line);
        assert!(sync_failed(nerve_transport::ctl::NOT_RUNNING.into()).contains("does not run"));
        assert_eq!(sync_failed("other".into()), "other");
    }

    /// `folder add` of a folder the center has walks every grant of the
    /// running node, as `folder sync` does (what was moved into a folder
    /// gets its entries with the change); `folder rm` only what changed.
    #[cfg(target_os = "linux")]
    #[test]
    fn folder_add_again_asks_the_node_for_a_walk_of_every_grant() {
        use nerve_transport::ctl::{Reply, serve};
        let (d, paths) = setup(&["home"]);
        let folder = d.path().join("srv");
        std::fs::create_dir(&folder).unwrap();
        let folder = folder.display().to_string();
        run(&paths, &["folder", "add", &folder, "r"]).unwrap();
        let text = std::fs::read_to_string(paths.config_file()).unwrap();
        let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (sock, kept) = (paths.ctl_socket(), asked.clone());
        rt.spawn(async move {
            let _ = serve(&sock, move |req, _| {
                let (text, kept) = (text.clone(), kept.clone());
                async move {
                    match req.method.as_str() {
                        "config.read" => Reply::Ok(json!({"config": text, "version": 7})),
                        "folder.grants" => {
                            kept.lock().unwrap().push(req.params["every"].clone());
                            Reply::Ok(json!({"service": true}))
                        }
                        _ => Reply::Ok(json!({})),
                    }
                }
            })
            .await;
        });
        while !paths.ctl_socket().exists() {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        run(&paths, &["folder", "add", &folder, "rw"]).unwrap();
        run(&paths, &["folder", "rm", &folder]).unwrap();
        assert_eq!(*asked.lock().unwrap(), [json!(true), json!(false)]);
    }

    /// `folder sync` does not say `nerve-run` has its access where the node
    /// gave nothing, or where a grant did not come whole.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread")]
    async fn folder_sync_does_not_claim_access_that_was_not_given() {
        let (_d, paths) = setup(&["home"]);
        grants_node(&paths, json!({"service": false}));
        let mut out = Vec::new();
        sync_folders(&paths, &mut out).await.unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("nothing to sync"), "{out}");
        assert!(!out.contains("has its access"), "{out}");

        let (_d, paths) = setup(&["home"]);
        grants_node(
            &paths,
            json!({"service": true, "errors": ["/srv/x: no access"], "stale": []}),
        );
        let mut out = Vec::new();
        sync_folders(&paths, &mut out).await.unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("did not get every folder"), "{out}");
        assert!(!out.contains("has its access"), "{out}");
    }
}
