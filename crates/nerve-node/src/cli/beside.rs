//! What a node says when the machine is also a center (design of #232, 6):
//! both roles on one machine are the terminal programs' (the app installs
//! one), and the node's owner is the account whose harnesses hold the local
//! center's tokens. A command of the node that runs as that account, or a
//! folder that gives `nerve-run` its harness settings, reaches the center's
//! owner channel through them: said, not refused.

use std::path::{Path, PathBuf};

use nerve_policy::config::{Access, Mode};

/// Where harnesses keep their settings, below an account's home: the files
/// and folders that hold the tokens they use for an MCP server.
const HARNESS_SETTINGS: &[&str] = &[
    ".claude",
    ".claude.json",
    ".codex",
    ".cursor",
    ".gemini",
    ".config",
];

/// Whether this machine also runs a center, which the node's terminal
/// program may run beside it.
pub(super) fn center_here() -> bool {
    #[cfg(test)]
    if let Some(forced) = tests::FORCED.with(|f| f.get()) {
        return forced;
    }
    nerve_service::role::Roles::here().center
}

/// The note for `mode` (as the owner for `as_owner`) on a machine that is
/// also a center: its commands run as you.
pub(super) fn mode_note(mode: Mode, as_owner: bool) -> Option<&'static str> {
    let as_you = mode == Mode::User || (mode == Mode::Allowlist && as_owner);
    (as_you && center_here()).then_some(
        "note: a center runs on this machine too, and commands that run as you can read its owner token and the tokens in your harnesses' settings; folder mode, or a machine of its own for the center, keeps them apart",
    )
}

/// The note for the folder `folder` given `access` on a machine that is also
/// a center, when it holds the home of one of `homes` or a harness's
/// settings there: `nerve-run` then reads what the center's harnesses hold.
pub(super) fn folder_note(folder: &Path, access: Access, homes: &[PathBuf]) -> Option<String> {
    if access.is_none() || !center_here() || !covers_settings(folder, homes) {
        return None;
    }
    Some(format!(
        "note: a center runs on this machine too, and {} holds your harnesses' settings, with the tokens the center's owner uses: nerve-run can read them now",
        folder.display()
    ))
}

/// Whether `folder` holds a home, or a harness's settings below one, or lies
/// inside those settings.
fn covers_settings(folder: &Path, homes: &[PathBuf]) -> bool {
    homes.iter().any(|home| {
        home.starts_with(folder)
            || HARNESS_SETTINGS.iter().any(|s| {
                let at = home.join(s);
                at.starts_with(folder) || folder.starts_with(&at)
            })
    })
}

/// The homes whose harness settings a folder grant may cover: this
/// command's own, and the owner's it runs for.
pub(super) fn homes() -> Vec<PathBuf> {
    let mut homes = vec![crate::paths::home_dir()];
    if let Some(owner) = crate::owner::owner_running()
        && let Ok(Some(account)) = crate::account::lookup(&owner)
    {
        homes.push(account.home);
    }
    homes
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::cell::Cell;

    thread_local! {
        /// What the tests say about the machine: a center runs on it or not.
        pub static FORCED: Cell<Option<bool>> = const { Cell::new(None) };
    }

    /// Runs `f` on a machine that is (`center`) or is not also a center.
    pub fn with_center<T>(center: bool, f: impl FnOnce() -> T) -> T {
        FORCED.with(|c| c.set(Some(center)));
        let r = f();
        FORCED.with(|c| c.set(None));
        r
    }

    #[test]
    fn a_mode_that_runs_as_you_is_said_where_a_center_runs_too() {
        with_center(true, || {
            assert!(mode_note(Mode::User, false).is_some());
            assert!(mode_note(Mode::Allowlist, true).is_some());
            assert!(mode_note(Mode::Allowlist, false).is_none());
            assert!(mode_note(Mode::Folder, false).is_none());
        });
        with_center(false, || {
            assert!(mode_note(Mode::User, false).is_none());
            assert!(mode_note(Mode::Allowlist, true).is_none());
        });
    }

    #[test]
    fn a_folder_over_the_harnesses_settings_is_said_where_a_center_runs_too() {
        let homes = [PathBuf::from("/home/alice")];
        let rw = Access::ALL;
        let said = |folder: &str, access, center| {
            with_center(center, || folder_note(Path::new(folder), access, &homes))
        };
        for folder in [
            "/home/alice",
            "/home",
            "/",
            "/home/alice/.claude",
            "/home/alice/.claude/projects",
            "/home/alice/.config",
        ] {
            assert!(said(folder, rw, true).is_some(), "{folder}");
            assert!(said(folder, rw, false).is_none(), "{folder}");
        }
        // A folder of a project beside them, and a grant of nothing.
        assert!(said("/home/alice/src/app", rw, true).is_none());
        assert!(said("/home/alicia", rw, true).is_none());
        assert!(said("/srv/data", rw, true).is_none());
        assert!(said("/home/alice", Access::NONE, true).is_none());
    }
}
