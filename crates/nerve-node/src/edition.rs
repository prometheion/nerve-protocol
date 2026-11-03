//! Which program of the release this is: `nerve-node`, or the desktop app
//! `nerve-node-desktop` (crates/nerve-node-desktop), which holds the node and
//! its CLI too. The name decides where `install` puts the program, which
//! release file `update` takes, and what `--version` says; the desktop app
//! also installs and removes its own parts (the menu entry, the `nerve://`
//! handler) with the node, through [`Parts`].
//!
//! The edition is the running program's own: each program's `main` sets it
//! before anything else, and nothing reads the name it was started by
//! (argv[0]). Through a link named `nerve-node`, as a node installed alone
//! becomes on Linux when the desktop app takes it over
//! (`crate::service::node_beside`), the app is still the app, so `update`
//! there updates the app. Windows has only the app's edition in the release.

use std::path::Path;
use std::sync::OnceLock;

/// What a program installs besides the node itself. The desktop app's menu
/// entry and link handler: they come and go with the node, so one
/// `install`, `update` or `uninstall` does all of it.
pub trait Parts: Sync {
    /// Puts the parts in place for the installed program at `bin`, or puts
    /// them back; what it did, one step a line.
    fn install(&self, bin: &Path) -> Result<Vec<String>, String>;
    /// Removes what [`Parts::install`] put in place for `bin`; what it did.
    fn uninstall(&self, bin: &Path) -> Result<Vec<String>, String>;
}

/// This program.
pub struct Edition {
    /// Its name: the installed program's file, the release file's start, and
    /// the first word of `--version`.
    pub program: &'static str,
    pub parts: Option<&'static dyn Parts>,
}

/// The node alone.
pub const NODE: Edition = Edition {
    program: "nerve-node",
    parts: None,
};

/// The desktop app's name. The node alone knows it to find the app beside
/// it on Linux: a node the app took over is the app's to uninstall
/// (`crate::service::app_beside`).
pub const DESKTOP_PROGRAM: &str = "nerve-node-desktop";

static EDITION: OnceLock<&'static Edition> = OnceLock::new();

/// Makes this program `edition`; once, at its start, before any command.
pub fn set(edition: &'static Edition) {
    let _ = EDITION.set(edition);
}

/// This program: [`NODE`] unless [`set`] said otherwise.
pub fn get() -> &'static Edition {
    EDITION.get().copied().unwrap_or(&NODE)
}

impl std::fmt::Debug for Edition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.program)
    }
}

// Two editions are one when their names are: the name decides everything
// else.
impl PartialEq for Edition {
    fn eq(&self, other: &Edition) -> bool {
        self.program == other.program
    }
}

impl Eq for Edition {}
