//! `nerve-node center`: pairing and unpairing a center, pausing it, its
//! node key and whether it may change the node's settings.

use super::*;

/// `center rotate-key`: the running node makes the new key and sends it to
/// the center over its link (crate::rotate), or ends the grace of the old
/// one. The new public key is shown once.
pub(super) async fn rotate_key(
    paths: &NodePaths,
    center: &CenterArg,
    end_grace: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    let (cfg, _) = read_config(paths).await?;
    let name = pick_center(&cfg, center)?;
    let params = json!({"center": name, "end_grace": end_grace});
    #[cfg(unix)]
    let r = nerve_transport::ctl::call(&paths.ctl_socket(), "center.rotate-key", params).await;
    #[cfg(windows)]
    let r = crate::pipe::call(paths, "center.rotate-key", params).await;
    let v = match r {
        Ok(v) => v,
        Err(e) if e == nerve_transport::ctl::NOT_RUNNING => {
            return Err(format!(
                "the node does not run: a key rotation goes to center {name} over the node's link. Start it (`nerve-node run`, or the service), then try again"
            ));
        }
        Err(e) => return Err(e),
    };
    let key = v["public_key"].as_str().unwrap_or_default();
    if end_grace {
        let _ = writeln!(
            out,
            "center {name} no longer takes this machine's old key; it takes only {key}"
        );
        return Ok(());
    }
    json::also("public_key", json!(key));
    let _ = writeln!(out, "{}", rotated_text(&name, key));
    Ok(())
}

/// What `center rotate-key` says once the center took the new key, with
/// the command that ends the old key's grace.
fn rotated_text(name: &str, key: &str) -> String {
    let days = nerve_proto::ROTATE_GRACE_MS / 86_400_000;
    format!(
        "center {name} took this machine's new key:\n  {key}\nThe old key is deleted here. The center takes it for {days} more days, unless you end that now with `nerve-node center rotate-key --end-grace {name}`."
    )
}

/// `center pause` and `center resume`: the owner's switch, the only way a
/// pause ends (a center can pause itself, never unpause).
pub(super) async fn pause_center(
    paths: &NodePaths,
    center: &CenterArg,
    pause: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    let name = edit_center(paths, center, |e| {
        e.paused = pause;
        Ok(())
    })
    .await?;
    let _ = writeln!(out, "{name}: {}", if pause { "paused" } else { "resumed" });
    Ok(())
}

/// `center add`: pairs with the center of a link, after asking unless
/// `--yes`.
pub(super) async fn add(
    paths: NodePaths,
    link: String,
    name: Option<String>,
    yes: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    let link = PairLink::parse(&given_link(&link)?)?;
    w(out, crate::pair::preview(&link, name.as_deref()));
    if !yes {
        // Asked only when the pairing can work: the center answers,
        // its certificate is the pinned one and the code is open.
        let check = crate::pair::check(&paths, &link).await?;
        if !check.ready() {
            return Err(check.said());
        }
        w(out, check.said());
        if !confirm(&mut std::io::stdin().lock(), out)? {
            return Err("not paired".into());
        }
    }
    let e = crate::pair::pair(&paths, &link, name.as_deref()).await?;
    w(out, format!("paired with {} as {}", e.url, e.name));
    tell_pairings_apart(&paths, out).await;
    Ok(())
}

/// `center rm`: unpairs a center, with its node key and, on Windows, the
/// profile of its container.
pub(super) async fn rm(
    paths: NodePaths,
    center: CenterName,
    out: &mut dyn Write,
) -> Result<(), String> {
    let (cfg, _) = read_config(&paths).await?;
    let name = pick_center(&cfg, &center.arg())?;
    let gone = std::sync::Mutex::new(Vec::new());
    // Saved also when the folder grants of the other pairings do not
    // follow: the pairing is gone then, so its key and profile go
    // now, or nothing names them later.
    let saved = edit_saved(&paths, |c| {
        let mut g = gone.lock().unwrap_or_else(|p| p.into_inner());
        g.clear();
        g.extend(
            c.centers
                .iter()
                .filter(|e| e.name == name)
                .map(|e| e.node_id.clone()),
        );
        c.centers.retain(|e| e.name != name);
        Ok(())
    })
    .await?;
    let cfg = &saved.cfg;
    // The center is gone either way; a key that stays behind is
    // said, not hidden.
    if let Err(e) = crate::secrets::remove_center_key(&paths, cfg.machine.secret_storage, &name) {
        w(out, format!("the node key for {name} was not deleted: {e}"));
    }
    // So is the profile of its container on Windows (crate::grants):
    // with its last grant when the record names it, else found by
    // the pairing. A node that runs still serves the center until it
    // starts again, so there it stays.
    let mut p = saved.grants.profiles.clone();
    let mut ours = Vec::new();
    for id in gone.into_inner().unwrap_or_else(|p| p.into_inner()) {
        if cfg.centers.iter().any(|c| c.node_id == id) {
            continue;
        }
        ours.extend(crate::grants::containers(&paths, &id));
        p.merge(crate::grants::forget(&paths, &id));
    }
    let of = |n: &String| {
        if ours.contains(n) {
            format!("{n} of {name}")
        } else {
            n.clone()
        }
    };
    for n in &p.removed {
        w(out, format!("removed the AppContainer profile {}", of(n)));
    }
    if let Some(why) = &p.why {
        for n in &p.kept {
            w(
                out,
                format!(
                    "the AppContainer profile {} stays, since {why}: once the node stopped, remove it by hand (docs/dev/windows.md)",
                    of(n)
                ),
            );
        }
    }
    for e in &p.errors {
        w(
            out,
            format!("the AppContainer profile of {name} was not removed: {e}"),
        );
    }
    w(out, format!("unpaired {name}"));
    match grants_failed(&saved.grants) {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// `center`: the paired centers, each with its mode and settings.
pub(super) async fn list(paths: NodePaths, out: &mut dyn Write) -> Result<(), String> {
    let (cfg, _) = read_config(&paths).await?;
    if cfg.centers.is_empty() {
        w(out, NO_CENTER_PAIRED.into());
    }
    let now = crate::now_ms();
    for c in &cfg.centers {
        let mut flags = Vec::new();
        for (on, f) in [
            (c.paused, "paused"),
            (c.revoked, "revoked"),
            (c.unknown, "unknown"),
        ] {
            if on {
                flags.push(f);
            }
        }
        w(
            out,
            format!(
                "{}  {}  mode {}  settings {}{}",
                c.name,
                c.url,
                c.policy.mode_at(now).as_str(),
                enum_str(&c.settings),
                if flags.is_empty() {
                    String::new()
                } else {
                    format!("  [{}]", flags.join(", "))
                }
            ),
        );
        // Which `nerve.*` profile is this pairing's: the others
        // belong to other nodes or are left over (docs/dev/windows.md).
        if cfg!(windows) {
            w(
                out,
                format!(
                    "  AppContainer {}",
                    crate::grants::profile_name(&paths, &c.node_id)
                ),
            );
        }
    }
    Ok(())
}

/// `center settings on|off`: whether a center may change the node's
/// settings.
pub(super) async fn settings(
    paths: NodePaths,
    state: String,
    center: CenterName,
    out: &mut dyn Write,
) -> Result<(), String> {
    let g = match state.as_str() {
        "on" => SettingsGrant::Write,
        _ => SettingsGrant::Off,
    };
    let name = edit_center(&paths, &center.arg(), |e| {
        e.settings = g;
        Ok(())
    })
    .await?;
    w(out, format!("{name}: settings {state}"));
    let root = crate::owner::is_root(crate::service::owner_of(&paths).as_deref());
    if let Some(warning) = settings_grant_warning(&name, g, root) {
        w(out, warning);
    }
    Ok(())
}

/// What `center settings on` warns of where root is the owner
/// (`root`): the center may then set its own mode to user, whose commands
/// run as root, with no password asked.
fn settings_grant_warning(name: &str, g: SettingsGrant, root: bool) -> Option<String> {
    (root && g == SettingsGrant::Write).then(|| {
        format!(
            "Warning: root is the owner of this node, so {name} can now set its own mode to user, and its commands then run as root: anything on this machine, Nerve and its keys included"
        )
    })
}

/// [`crate::account::pairings_warning`] for the node at `paths` with the
/// config `cfg`, as this machine stands: whether it is the installed node,
/// and its kernel's Landlock. For a node that does not run, and right after
/// a pairing, which the running node may not have read yet.
pub(crate) fn pairings_warning_here(paths: &NodePaths, cfg: &NodeConfig) -> Option<String> {
    let separate = cfg!(target_os = "linux") && crate::service::is_service_node(paths);
    crate::account::pairings_warning(
        separate,
        nerve_sandbox::Confinement::detect().landlock_abi,
        cfg,
        crate::now_ms(),
    )
}

/// Says after a pairing that nothing keeps the pairings of nerve-run apart
/// here ([`pairings_warning_here`]), once there are two of them.
pub(super) async fn tell_pairings_apart(paths: &NodePaths, out: &mut dyn Write) {
    if let Ok((cfg, _)) = read_config(paths).await
        && let Some(w) = pairings_warning_here(paths, &cfg)
    {
        let _ = writeln!(out, "Warning: {w}");
    }
}

/// The pairing link of `center add`: the one given, or for `-` the first
/// line of stdin.
pub(crate) fn given_link(link: &str) -> Result<String, String> {
    if link != "-" {
        return Ok(link.to_string());
    }
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("cannot read the pairing link: {e}"))?;
    let line = line.trim();
    if line.is_empty() {
        return Err("center add -: the first line of stdin is empty, not a pairing link".into());
    }
    Ok(line.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use crate::cli::tests::entry;
    use crate::cli::tests::{json_of, load, run, setup};
    #[cfg(windows)]
    use nerve_policy::config::Access;

    #[test]
    fn centers_pause_and_resume_by_the_owner() {
        let (_d, paths) = setup(&["a", "b"]);
        assert!(run(&paths, &["center", "pause"]).is_err());
        run(&paths, &["center", "pause", "a"]).unwrap();
        let cfg = load(&paths);
        assert!(cfg.center("a").unwrap().paused);
        assert!(!cfg.center("b").unwrap().paused);
        let ls = run(&paths, &["center"]).unwrap();
        assert!(ls.contains("[paused]"), "{ls}");
        run(&paths, &["center", "resume", "a"]).unwrap();
        assert!(!load(&paths).center("a").unwrap().paused);
        run(&paths, &["center", "rm", "b"]).unwrap();
        assert!(load(&paths).center("b").is_none());
    }

    /// On Windows: `center rm` removes the profile of the pairing's
    /// AppContainer also when the record of the grants does not name it,
    /// as after the state folder was deleted.
    #[cfg(windows)]
    #[test]
    fn center_rm_removes_the_profile_the_record_does_not_name() {
        let (_d, paths) = setup(&["home"]);
        let name = crate::grants::container(&paths, "n");
        let profile = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap())
            .join("Packages")
            .join(&name);
        // Starting a command in the container makes its profile; whether
        // the command runs does not matter here.
        let _ = nerve_sandbox::appcontainer::run(
            Path::new("cmd.exe"),
            &["/C".into(), "exit 0".into()],
            &name,
        );
        assert!(profile.exists(), "{}", profile.display());
        assert!(!crate::grants::record_file(&paths).exists());
        let ls = run(&paths, &["center"]).unwrap();
        assert!(ls.contains(&format!("AppContainer {name}")), "{ls}");
        let out = run(&paths, &["center", "rm"]).unwrap();
        assert!(
            out.contains(&format!("removed the AppContainer profile {name} of home")),
            "{out}"
        );
        assert!(!profile.exists(), "{}", profile.display());
    }

    /// On Windows: a node that spelled its state folder with `/`, as the
    /// default one is, is found by the folder typed with `\`.
    #[cfg(windows)]
    #[test]
    fn center_rm_finds_the_profile_of_the_state_folder_spelled_otherwise() {
        let (d, paths) = setup(&["home"]);
        let spelled = NodePaths::new(
            &paths.config_dir,
            PathBuf::from(format!("{}/s", d.path().display())),
        );
        assert_eq!(spelled.state_dir, paths.state_dir);
        let name = crate::grants::container(&spelled, "n");
        assert_ne!(name, crate::grants::container(&paths, "n"));
        let profile = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap())
            .join("Packages")
            .join(&name);
        let _ = nerve_sandbox::appcontainer::run(
            Path::new("cmd.exe"),
            &["/C".into(), "exit 0".into()],
            &name,
        );
        assert!(profile.exists(), "{}", profile.display());
        let ls = run(&paths, &["center"]).unwrap();
        assert!(ls.contains(&format!("AppContainer {name}")), "{ls}");
        let out = run(&paths, &["center", "rm"]).unwrap();
        assert!(out.contains(&name), "{out}");
        assert!(!profile.exists(), "{}", profile.display());
    }

    /// The profile folder of the container `name`, made by starting a
    /// command in it; whether the command runs does not matter.
    #[cfg(windows)]
    fn profile_of(name: &str) -> PathBuf {
        let _ = nerve_sandbox::appcontainer::run(
            Path::new("cmd.exe"),
            &["/C".into(), "exit 0".into()],
            name,
        );
        let profile = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap())
            .join("Packages")
            .join(name);
        assert!(profile.exists(), "{}", profile.display());
        profile
    }

    /// On Windows: the profile of a pairing with folder entries goes with
    /// their grants at `center rm`, which says so, and stays while the node
    /// runs, which it says too.
    #[cfg(windows)]
    #[test]
    fn center_rm_names_the_profile_that_goes_with_the_last_grant() {
        let (d, paths) = setup(&["home"]);
        let work = d.path().join("work");
        std::fs::create_dir(&work).unwrap();
        run(&paths, &["folder", "add", work.to_str().unwrap(), "rw"]).unwrap();
        assert!(crate::grants::record_file(&paths).exists());
        let name = crate::grants::container(&paths, "n");
        let profile = profile_of(&name);
        // A node that runs holds the lock.
        let held = crate::secrets::KeysLock::try_take(&paths).unwrap().unwrap();
        let out = run(&paths, &["center", "rm"]).unwrap();
        drop(held);
        assert!(
            out.contains(&format!(
                "the AppContainer profile {name} of home stays, since the node at"
            )),
            "{out}"
        );
        assert!(profile.exists(), "{}", profile.display());
        nerve_sandbox::appcontainer::remove_profile(&name).unwrap();

        let (d, paths) = setup(&["home"]);
        let work = d.path().join("work");
        std::fs::create_dir(&work).unwrap();
        run(&paths, &["folder", "add", work.to_str().unwrap(), "rw"]).unwrap();
        let name = crate::grants::container(&paths, "n");
        let profile = profile_of(&name);
        let out = run(&paths, &["center", "rm"]).unwrap();
        assert!(
            out.contains(&format!("removed the AppContainer profile {name} of home")),
            "{out}"
        );
        assert!(!profile.exists(), "{}", profile.display());
    }

    /// On Windows: when the grants of the pairings that stay do not follow
    /// (a hard link below a folder they write), `center rm` still removes
    /// the pairing's profile, as nothing names it once the pairing is gone,
    /// and then says what failed.
    #[cfg(windows)]
    #[test]
    fn center_rm_removes_the_profile_when_the_other_grants_do_not_follow() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("c"), d.path().join("s"));
        let work = d.path().join("work");
        std::fs::create_dir(&work).unwrap();
        std::fs::write(work.join("a.txt"), "x").unwrap();
        std::fs::hard_link(work.join("a.txt"), work.join("b.txt")).unwrap();
        let real = nerve_policy::paths::resolve(&work).unwrap();
        let mut cfg = NodeConfig::default();
        let mut home = entry("home");
        home.node_id = "n-home".into();
        home.policy.folders.push(nerve_policy::config::Folder {
            path: real.display().to_string(),
            access: Access::parse("rw").unwrap(),
        });
        let mut lab = entry("lab");
        lab.node_id = "n-lab".into();
        cfg.centers = vec![home, lab];
        cfg.save(&paths.config_file()).unwrap();
        let name = crate::grants::container(&paths, "n-lab");
        let profile = profile_of(&name);
        let e = run(&paths, &["center", "rm", "lab"]).unwrap_err();
        assert!(e.contains("the folder grants do not follow"), "{e}");
        assert!(load(&paths).center("lab").is_none());
        assert!(!profile.exists(), "{}", profile.display());
    }

    /// `center settings on` warns where root is the owner: the
    /// center can make itself root by setting its own mode to user.
    #[test]
    fn the_settings_grant_warns_where_root_is_the_owner() {
        let w = settings_grant_warning("home", SettingsGrant::Write, true).unwrap();
        assert!(
            w.starts_with("Warning: root is the owner of this node"),
            "{w}"
        );
        assert!(w.contains("home can now set its own mode to user"), "{w}");
        assert!(w.contains("run as root"), "{w}");
        assert_eq!(
            settings_grant_warning("home", SettingsGrant::Off, true),
            None
        );
        assert_eq!(
            settings_grant_warning("home", SettingsGrant::Write, false),
            None
        );
    }

    /// The command `center rotate-key` names to end the grace is one the
    /// CLI takes (round 1, correctness 4).
    #[test]
    fn the_rotate_key_hint_is_a_command_that_parses() {
        let text = rotated_text("lab", "k");
        let command = text.split('`').nth(1).unwrap();
        let words: Vec<&str> = command.split_whitespace().collect();
        let cli = Cli::try_parse_from(&words).unwrap_or_else(|e| panic!("{command}: {e}"));
        assert!(
            matches!(
                cli.cmd,
                Cmd::Center {
                    cmd: Some(CenterCmd::RotateKey {
                        end_grace: true,
                        ..
                    }),
                    ..
                }
            ),
            "{command}"
        );
    }

    /// Without --yes, `center add --json` shows what the owner confirms and
    /// pairs nothing: the desktop app asks, then runs it with --yes.
    #[test]
    fn center_add_json_without_yes_only_shows_the_link() {
        let (_d, paths) = setup(&[]);
        let before = std::fs::read(paths.config_file()).unwrap();
        let v = json_of(
            &paths,
            &[
                "center",
                "add",
                "nerve://pair?center=https%3A%2F%2Fc.example%3A8443&code=abc&pin=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "--name",
                "lab",
            ],
        );
        assert_eq!(v["paired"], false, "{v}");
        assert_eq!(v["preview"]["center"], "https://c.example:8443", "{v}");
        assert_eq!(v["preview"]["tls"], true, "{v}");
        assert_eq!(v["preview"]["pin"], "A".repeat(43), "{v}");
        assert_eq!(v["preview"]["name"], "lab", "{v}");
        // The check found no center there: the app offers no Pair.
        assert_eq!(v["check"]["ready"], false, "{v}");
        assert!(v["check"]["problem"].is_string(), "{v}");
        assert_eq!(std::fs::read(paths.config_file()).unwrap(), before);
        let e = run(&paths, &["--json", "center", "add", "nerve://x"]).unwrap_err();
        assert!(e.contains("nerve://pair?"), "{e}");
    }
}
