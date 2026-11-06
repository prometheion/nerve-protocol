//! `nerve-node mode`: how much a center may do, also for some hours only.

use super::*;

/// A bare `mode`: the mode of each center, or of the one named.
pub(super) async fn show_mode(
    paths: NodePaths,
    for_hours: Option<u64>,
    as_owner: bool,
    center: CenterArg,
    out: &mut dyn Write,
) -> Result<(), String> {
    if for_hours.is_some() || as_owner {
        return Err("name the mode: `nerve-node mode allowlist|folder|user`".into());
    }
    let (cfg, _) = read_config(&paths).await?;
    let names = match &center.center {
        Some(_) => vec![pick_center(&cfg, &center)?],
        None => cfg.centers.iter().map(|c| c.name.clone()).collect(),
    };
    if names.is_empty() {
        w(out, NO_CENTER_PAIRED.into());
    }
    let now = crate::now_ms();
    for name in names {
        let p = &cfg.center(&name).expect("listed").policy;
        w(out, format!("{name}: {}", mode_line(p, now)));
    }
    Ok(())
}

/// A center's mode as `mode` shows it: `folder`, `allowlist, as you`,
/// `user for 1h 59m more, then folder`.
fn mode_line(p: &nerve_policy::config::CenterPolicy, now: u64) -> String {
    let mode = p.mode_at(now);
    let whom = if p.runs_as_owner(now) && mode == Mode::Allowlist {
        ", as you"
    } else {
        ""
    };
    let timer = match p.ends(now) {
        Some((until, then)) => format!(
            " for {} more, then {}",
            nerve_transport::log::span(Duration::from_millis(until - now)),
            then_text(then, p.allow.len())
        ),
        None => String::new(),
    };
    format!("{}{whom}{timer}", mode.as_str())
}

/// The mode a timer ends in, in words: allowlist says what it then runs.
pub(super) fn then_text(then: Mode, allow_rules: usize) -> String {
    match (then, allow_rules) {
        (Mode::Allowlist, 0) => "allowlist (no allow rule: nothing runs)".into(),
        (Mode::Allowlist, 1) => "allowlist (1 allow rule)".into(),
        (Mode::Allowlist, n) => format!("allowlist ({n} allow rules)"),
        (m, _) => m.as_str().into(),
    }
}

/// A center's mode for `mode --json`.
pub(crate) fn mode_data(name: &str, p: &nerve_policy::config::CenterPolicy, now: u64) -> Value {
    let ends = p.ends(now);
    json!({
        "center": name,
        "mode": p.mode_at(now).as_str(),
        "as_owner": p.as_owner && p.mode_at(now) == Mode::Allowlist,
        "until_ms": ends.map(|(u, _)| u),
        "then": ends.map(|(_, m)| m.as_str()),
    })
}

/// `mode <MODE>`, and the mode step of `setup`.
pub(super) async fn set_mode(
    paths: &NodePaths,
    mode: &str,
    for_hours: Option<u64>,
    as_owner: bool,
    center: &CenterArg,
    out: &mut dyn Write,
) -> Result<(), String> {
    let w = |out: &mut dyn Write, s: String| {
        let _ = writeln!(out, "{s}");
    };
    let m = match mode {
        "allowlist" => Mode::Allowlist,
        "folder" => Mode::Folder,
        "user" => Mode::User,
        other => {
            return Err(format!("unknown mode {other} (allowlist, folder or user)"));
        }
    };
    if for_hours.is_some() && m == Mode::Allowlist {
        return Err("--for only goes with folder or user".into());
    }
    if as_owner && m != Mode::Allowlist {
        return Err(
            "--as-owner only goes with allowlist: folder mode always runs as nerve-run, user mode always as you".into(),
        );
    }
    // No --for: no limit, and an old one is cleared. The end is a
    // millisecond count that the config file (a TOML integer) holds.
    let until = for_hours
        .map(|h| {
            if h == 0 {
                return Err("--for must be at least 1 hour".to_string());
            }
            h.checked_mul(3_600_000)
                .and_then(|ms| crate::now_ms().checked_add(ms))
                .filter(|t| i64::try_from(*t).is_ok())
                .ok_or_else(|| "--for is too large".to_string())
        })
        .transpose()?;
    let ends = std::cell::Cell::new(None);
    let name = edit_center(paths, center, |e| {
        // A timed user mode goes back to the mode before it, never to
        // user; a timed folder mode to allowlist (CenterPolicy::after).
        // The mode before is a folder mode without a timer, or the one a
        // timed user mode in force came from, so a timer set again ends
        // where it did. A timed folder mode would lose its own end there,
        // so a user mode from it ends in allowlist.
        let now = crate::now_ms();
        let from = match e.policy.mode_at(now) {
            Mode::Folder if e.policy.ends(now).is_none() => Some(Mode::Folder),
            Mode::User if e.policy.ends(now).is_some() => e.policy.then,
            _ => None,
        };
        e.policy.then = from.filter(|_| m == Mode::User && until.is_some());
        e.policy.mode = m;
        e.policy.until = until;
        e.policy.as_owner = as_owner;
        ends.set(
            e.policy
                .ends(crate::now_ms())
                .map(|(_, then)| (then, e.policy.allow.len())),
        );
        Ok(())
    })
    .await?;
    let whom = if as_owner { ", as you" } else { "" };
    let timer = match (for_hours, ends.get()) {
        (Some(h), Some((then, rules))) => format!(" for {h} h, then {}", then_text(then, rules)),
        _ => String::new(),
    };
    w(out, format!("{name}: mode {}{whom}{timer}", m.as_str()));
    // A mode whose commands run as you, with the network off, runs none of
    // them: said now, not found out from a refused call.
    let (cfg, _) = read_config(paths).await?;
    let installed = crate::service::is_service_node(paths);
    if let Some(note) = cfg
        .center(&name)
        .and_then(|c| network_mode_note(&c.policy, installed, apart_by_hand_here()))
    {
        w(out, note);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests::{json_of, load, run, setup};

    /// Allowlist mode runs as the owner only when asked for, and setting a
    /// mode again without the flag takes it back; the other modes refuse it.
    #[test]
    fn allowlist_mode_runs_as_the_owner_when_asked_for() {
        let (_d, paths) = setup(&["home"]);
        let policy = || load(&paths).centers[0].policy.clone();
        let out = run(&paths, &["mode", "allowlist", "--as-owner"]).unwrap();
        assert!(out.contains("mode allowlist, as you"), "{out}");
        assert!(policy().as_owner && policy().runs_as_owner(crate::now_ms()));
        run(&paths, &["mode", "allowlist"]).unwrap();
        assert!(!policy().as_owner);
        for mode in ["folder", "user"] {
            let e = run(&paths, &["mode", mode, "--as-owner"]).unwrap_err();
            assert!(e.contains("--as-owner only goes with allowlist"), "{e}");
        }
        assert!(!policy().as_owner);
    }

    #[test]
    fn folder_and_user_mode_have_no_limit_unless_asked_for() {
        let (_d, paths) = setup(&["home"]);
        let policy = || load(&paths).centers[0].policy.clone();
        for mode in ["user", "folder"] {
            run(&paths, &["mode", mode]).unwrap();
            assert_eq!(policy().until, None, "{mode}");
        }
        // --for sets a limit of any length, on folder as on user.
        let before = crate::now_ms();
        run(&paths, &["mode", "folder", "--for", "1000"]).unwrap();
        let until = policy().until.unwrap();
        assert!(until >= before + 1000 * 3_600_000, "{until}");
        assert_eq!(policy().mode_at(before), Mode::Folder);
        assert_eq!(policy().mode_at(until), Mode::Allowlist);
        run(&paths, &["mode", "user", "--for", "9"]).unwrap();
        assert_eq!(policy().mode, Mode::User);
        // Setting the mode again without --for drops the old limit.
        run(&paths, &["mode", "user"]).unwrap();
        assert_eq!(policy().until, None);
        // Allowlist has nothing to limit; nonsense hours are refused.
        run(&paths, &["mode", "folder", "--for", "1"]).unwrap();
        let e = run(&paths, &["mode", "allowlist", "--for", "1"]).unwrap_err();
        assert!(e.contains("--for"), "{e}");
        let e = run(&paths, &["mode", "user", "--for", "0"]).unwrap_err();
        assert!(e.contains("at least 1"), "{e}");
        let e = run(&paths, &["mode", "user", "--for", "18446744073709551615"]).unwrap_err();
        assert!(e.contains("too large"), "{e}");
        let e = run(&paths, &["mode", "user", "--for", "soon"]).unwrap_err();
        assert!(e.contains("invalid value"), "{e}");
        // A refused change leaves the mode as it was.
        assert_eq!(policy().mode, Mode::Folder);
        run(&paths, &["mode", "allowlist"]).unwrap();
        assert_eq!(policy().until, None);
    }

    /// A timed user mode goes back to the mode before it, never to user; a
    /// timed folder mode ends in allowlist. `mode` and `status` say where a
    /// timer ends, and what allowlist mode then runs.
    #[test]
    fn a_timer_ends_in_the_mode_before_and_says_where() {
        let (_d, paths) = setup(&["home"]);
        let policy = || load(&paths).centers[0].policy.clone();
        run(&paths, &["mode", "folder"]).unwrap();
        let out = run(&paths, &["mode", "user", "--for", "2"]).unwrap();
        assert!(
            out.starts_with("home: mode user for 2 h, then folder\n"),
            "{out}"
        );
        let until = policy().until.unwrap();
        assert_eq!(policy().mode_at(until - 1), Mode::User);
        assert_eq!(policy().mode_at(until), Mode::Folder);
        let shown = run(&paths, &["mode"]).unwrap();
        assert!(
            shown.starts_with("home: user for 1 h 59 min more, then folder\n"),
            "{shown}"
        );
        let status = run(&paths, &["status"]).unwrap();
        assert!(
            status.contains("mode user for 1 h 59 min more, then folder"),
            "{status}"
        );
        let v = json_of(&paths, &["mode"]);
        assert_eq!(v["modes"][0]["then"], "folder", "{v}");
        // Timed again from that timed user mode: it ends where that one
        // did, in folder mode (round 1, correctness 1).
        let out = run(&paths, &["mode", "user", "--for", "1"]).unwrap();
        assert!(out.contains("for 1 h, then folder"), "{out}");
        assert_eq!(policy().mode_at(policy().until.unwrap()), Mode::Folder);
        // From a timed folder mode a timed user mode ends in allowlist, not
        // in a folder mode that would have lost its own end; allowlist
        // says it runs nothing without a rule.
        run(&paths, &["mode", "folder", "--for", "3"]).unwrap();
        let out = run(&paths, &["mode", "user", "--for", "1"]).unwrap();
        assert!(
            out.contains("then allowlist (no allow rule: nothing runs)"),
            "{out}"
        );
        assert_eq!(policy().then, None);
        assert_eq!(policy().mode_at(policy().until.unwrap()), Mode::Allowlist);
        // A timed folder mode ends in allowlist.
        run(&paths, &["mode", "folder"]).unwrap();
        run(&paths, &["rule", "add", "allow", "git status"]).unwrap();
        let out = run(&paths, &["mode", "folder", "--for", "1"]).unwrap();
        assert!(out.contains("then allowlist (1 allow rule)"), "{out}");
        assert_eq!(policy().then, None);
        assert_eq!(policy().mode_at(policy().until.unwrap()), Mode::Allowlist);
        // Without a timer nothing is said of one.
        run(&paths, &["mode", "user"]).unwrap();
        assert_eq!(run(&paths, &["mode"]).unwrap(), "home: user\n");
    }
}
