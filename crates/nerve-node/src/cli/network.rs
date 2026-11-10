//! `nerve-node network`: whether a center's commands reach the network.

use super::*;

/// A bare `network`: whether each center's commands, or the named one's,
/// reach the network.
pub(super) async fn show_network(
    paths: NodePaths,
    center: CenterArg,
    out: &mut dyn Write,
) -> Result<(), String> {
    let (cfg, _) = read_config(&paths).await?;
    let names = match &center.center {
        Some(_) => vec![pick_center(&cfg, &center)?],
        None => cfg.centers.iter().map(|c| c.name.clone()).collect(),
    };
    if names.is_empty() {
        w(out, NO_CENTER_PAIRED.into());
    }
    let installed = crate::service::is_service_node(&paths);
    for name in names {
        let p = &cfg.center(&name).expect("listed").policy;
        match p.no_network {
            true => w(out, format!("{name}: off: {NO_NETWORK_LINE}")),
            false => w(out, format!("{name}: on")),
        }
        if let Some(note) = network_mode_note(p, installed, apart_by_hand_here()) {
            w(out, note);
        }
    }
    Ok(())
}

/// What `network off` and `folder` say of a center whose network
/// is off.
pub(super) const NO_NETWORK_LINE: &str =
    "its commands have no network (no socket but unix ones), and its sudo-list commands do not run";

/// What `network off` adds: a command that started with the network
/// does not keep it, which the running node sees to (`link::Link::
/// end_commands_without_network`).
const NO_NETWORK_RUNNING: &str = "a command of it that runs now is ended by the node";

/// `network`: the pairing's network switch for its commands
/// (`policy.no_network`), in every mode. Where this machine cannot hold
/// them to it, or they run as the owner in the mode the pairing is in, the
/// node runs none of them, and this says so.
pub(super) async fn set_network(
    paths: &NodePaths,
    state: &str,
    center: &CenterArg,
    out: &mut dyn Write,
) -> Result<(), String> {
    let off = match state {
        "off" => true,
        "on" => false,
        other => return Err(format!("unknown network setting {other} (on or off)")),
    };
    let name = edit_center(paths, center, |e| {
        e.policy.no_network = off;
        Ok(())
    })
    .await?;
    let _ = writeln!(
        out,
        "{name}: {}",
        if off {
            NO_NETWORK_LINE
        } else {
            "its commands may use the network"
        }
    );
    if off {
        let _ = writeln!(out, "{NO_NETWORK_RUNNING}");
    }
    if off && !network_rules_here() {
        let _ = writeln!(out, "warning: {}", crate::daemon::NETWORK_NOT_HELD);
    }
    let (cfg, _) = read_config(paths).await?;
    let installed = crate::service::is_service_node(paths);
    if let Some(note) = cfg
        .center(&name)
        .and_then(|c| network_mode_note(&c.policy, installed, apart_by_hand_here()))
    {
        let _ = writeln!(out, "{note}");
    }
    Ok(())
}

/// What `network off` and `folder` add where the center's
/// commands run as the owner in the mode it is in now: user mode and
/// allowlist mode as the owner on the installed node; on a node run by hand
/// every mode, but folder mode where it can keep them apart
/// ([`crate::daemon::by_hand_apart`], `apart_by_hand`: not root, and Landlock
/// with unix sockets by path). `installed` says which node it is. The switch
/// does not hold such a command, so the node runs none of them while it is
/// on.
pub(super) fn network_mode_note(
    policy: &nerve_policy::config::CenterPolicy,
    installed: bool,
    apart_by_hand: bool,
) -> Option<String> {
    let mode = policy.mode_at(crate::now_ms());
    let as_owner = if installed {
        policy.runs_as_owner(crate::now_ms())
    } else {
        mode != Mode::Folder || !apart_by_hand
    };
    if !policy.no_network || !as_owner {
        return None;
    }
    if !installed {
        return Some(
            "note: this node runs by hand, so its commands run as you, and nothing keeps them off \
             the network here (only folder mode does, as a user that is not root and on Linux 7.1 \
             or later), so the node runs none of them while their network is off; the installed \
             node runs folder mode's commands as nerve-run"
                .into(),
        );
    }
    let whom = if policy.as_owner && mode == Mode::Allowlist {
        " as you"
    } else {
        ""
    };
    Some(format!(
        "note: it is in {} mode{whom} now, where its commands run as you, so the node runs \
         none of them while their network is off; folder mode, or allowlist mode without \
         --as-owner, runs them as nerve-run on the installed node",
        mode.as_str()
    ))
}

/// [`network_mode_note`]'s `apart_by_hand` for this machine and user.
pub(super) fn apart_by_hand_here() -> bool {
    crate::daemon::by_hand_apart(
        crate::rights::full_rights(),
        nerve_sandbox::Confinement::detect().landlock_abi,
    )
}

/// Whether this machine can keep a command off the network: the node's
/// seccomp filter (nerve_sandbox::net_filter), on Windows the container
/// without network capabilities while the Windows Firewall service runs
/// (crate::daemon::container_holds_network).
fn network_rules_here() -> bool {
    #[cfg(target_os = "linux")]
    return nerve_sandbox::net_filter::available();
    #[cfg(windows)]
    return crate::win_host::firewall_runs();
    #[cfg(not(any(target_os = "linux", windows)))]
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests::{json_of, load, run, setup};

    /// `network off` keeps the center's commands off the network,
    /// `on` lets them on it again, `folder` says which, and a machine
    /// without the node's network filter is warned of; so is a mode in
    /// which the commands run as the owner, where none of them runs.
    #[test]
    fn network_switches_the_commands_network() {
        let (_d, paths) = setup(&["home"]);
        let policy = || load(&paths).centers[0].policy.clone();
        // A node by hand runs allowlist commands as the owner.
        let by_hand = "note: this node runs by hand, so its commands run as you";
        let out = run(&paths, &["network", "off"]).unwrap();
        assert!(out.contains(by_hand), "{out}");
        assert!(run(&paths, &["folder"]).unwrap().contains(by_hand));
        // The installed node runs them as nerve-run, unless as the owner.
        let mut p = policy();
        assert!(network_mode_note(&p, true, false).is_none());
        p.as_owner = true;
        assert!(
            network_mode_note(&p, true, false)
                .is_some_and(|n| n.contains("allowlist mode as you now")),
            "{p:?}"
        );
        p.mode = Mode::User;
        assert!(network_mode_note(&p, true, false).is_some_and(|n| n.contains("user mode now")));
        p.mode = Mode::Folder;
        assert!(network_mode_note(&p, true, false).is_none());
        // A node by hand keeps folder mode apart only as a user that is not
        // root, with Landlock's unix socket rule; else it says so there too.
        assert!(network_mode_note(&p, false, true).is_none());
        assert!(network_mode_note(&p, false, false).is_some_and(|n| n.contains(by_hand)));
        run(&paths, &["mode", "folder"]).unwrap();
        let out = run(&paths, &["network", "off"]).unwrap();
        assert_eq!(out.contains("note:"), !apart_by_hand_here(), "{out}");
        assert!(
            out.starts_with(&format!("home: {NO_NETWORK_LINE}\n")),
            "{out}"
        );
        assert!(out.contains(NO_NETWORK_RUNNING), "{out}");
        assert_eq!(out.contains("warning:"), !network_rules_here(), "{out}");
        assert!(policy().no_network);
        let ls = run(&paths, &["folder"]).unwrap();
        assert!(ls.contains(&format!("home: {NO_NETWORK_LINE}\n")), "{ls}");
        let out = run(&paths, &["network", "on"]).unwrap();
        assert!(
            out.starts_with("home: its commands may use the network\n"),
            "{out}"
        );
        assert!(!policy().no_network);
        assert!(!run(&paths, &["folder"]).unwrap().contains("network"));
        let e = run(&paths, &["network", "maybe"]).unwrap_err();
        assert!(e.contains("'maybe'"), "{e}");
        // Bare, it shows each center's switch.
        assert_eq!(run(&paths, &["network"]).unwrap(), "home: on\n");
        run(&paths, &["network", "off"]).unwrap();
        let shown = run(&paths, &["network"]).unwrap();
        assert!(
            shown.starts_with(&format!("home: off: {NO_NETWORK_LINE}\n")),
            "{shown}"
        );
        // A mode whose commands run as you says, with the network off, that
        // none of them runs.
        let out = run(&paths, &["mode", "user", "--for", "1"]).unwrap();
        assert!(
            out.contains("note:") && out.contains("runs none of them"),
            "{out}"
        );
    }

    /// Bare `network` is a read like bare `mode`: `--json` gives each
    /// center's switch as data, not the words of a change (round 4,
    /// correctness 4).
    #[test]
    fn bare_network_prints_its_data_as_json() {
        let (_d, paths) = setup(&["home", "work"]);
        let v = json_of(&paths, &["network"]);
        assert_eq!(v["networks"].as_array().unwrap().len(), 2, "{v}");
        assert_eq!(v["networks"][0]["no_network"], false, "{v}");
        run(&paths, &["network", "off", "--center", "work"]).unwrap();
        let v = json_of(&paths, &["network", "--center", "work"]);
        assert_eq!(v["networks"].as_array().unwrap().len(), 1, "{v}");
        assert_eq!(v["networks"][0]["center"], "work", "{v}");
        assert_eq!(v["networks"][0]["no_network"], true, "{v}");
        assert!(v.get("messages").is_none(), "{v}");
    }
}
