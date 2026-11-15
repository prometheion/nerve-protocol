//! Which program of the release runs the center: `nerve-center`, or the app
//! `nerve` (crates/nerve), which holds the node, the center and the window
//! in one program and runs the center's command line behind its hidden
//! first word `__center`. The edition decides where `install` puts the
//! program, which release file `update` takes, and the service's command
//! line, which starts the program with that word.
//!
//! As the node's (nerve_node::edition), the edition is the running
//! program's own: the app's `main` sets it before anything else, and a link
//! named `nerve-center` to the app is still the app, whose `update` updates
//! the app. The terminal program `nerve-center` keeps its own edition.

use std::path::Path;
use std::sync::OnceLock;

/// What the app installs besides the center, as the app's role: its entry
/// in the menu (Linux) or in the Start menu and Apps & features (Windows),
/// so the app opens again and removes the center. They come and go with the
/// center's service, in one `install` and `uninstall`.
pub trait Parts: Sync {
    /// Puts the parts in place for the installed program at `bin`, or puts
    /// them back; what it did, one step a line.
    fn install(&self, bin: &Path) -> Result<Vec<String>, String>;
    /// Removes what [`Parts::install`] put in place; what it did.
    fn uninstall(&self, bin: &Path) -> Result<Vec<String>, String>;
}

/// The parts of a program, if it has any: the app's (crates/nerve).
#[derive(Clone, Copy, Default)]
pub struct AppParts(pub Option<&'static dyn Parts>);

impl std::fmt::Debug for AppParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_some() {
            "AppParts(Some)"
        } else {
            "AppParts(None)"
        })
    }
}

impl PartialEq for AppParts {
    fn eq(&self, other: &AppParts) -> bool {
        match (self.0, other.0) {
            (Some(a), Some(b)) => std::ptr::addr_eq(a, b),
            (a, b) => a.is_none() && b.is_none(),
        }
    }
}

impl Eq for AppParts {}

/// This program.
#[derive(Debug, PartialEq, Eq)]
pub struct Edition {
    /// Its name: the installed program's file, the release file's start,
    /// and the first word of `--version`.
    pub program: &'static str,
    /// The hidden first word that makes the program the center's command
    /// line, where it is another program's too: the service's command line
    /// starts it so.
    pub word: Option<&'static str>,
    /// What the program installs and removes with the center besides it.
    pub parts: AppParts,
}

/// The center alone: the terminal and server program.
pub const CENTER: Edition = Edition {
    program: "nerve-center",
    word: None,
    parts: AppParts(None),
};

/// The app's hidden first word for the center's command line.
pub const APP_WORD: &str = "__center";

/// The app, which is the center behind [`APP_WORD`]. The app's own
/// edition adds its [`Parts`] to it (crates/nerve).
pub const APP: Edition = Edition {
    program: "nerve",
    word: Some(APP_WORD),
    parts: AppParts(None),
};

/// The mark the app's .deb and .rpm leave (nerve_node::service::Package's
/// `MARK`, which a test of the app keeps equal): its program is then the
/// package's, in /usr/bin.
pub const PACKAGE_MARK: &str = "/usr/share/nerve/package";

/// The name of the link to the app that `install` of the app's center puts
/// on the `PATH`, for the terminal, as the app's node has `nerve-node`.
pub const TERMINAL_NAME: &str = "nerve-center";

static EDITION: OnceLock<&'static Edition> = OnceLock::new();

/// Makes this program `edition`; once, at its start, before any command.
pub fn set(edition: &'static Edition) {
    let _ = EDITION.set(edition);
}

/// This program: [`CENTER`] unless [`set`] said otherwise.
pub fn get() -> &'static Edition {
    EDITION.get().copied().unwrap_or(&CENTER)
}

impl Edition {
    /// Whether this is the app, which one machine runs in one role: its
    /// folder goes on no machine's `Path` (Windows has no terminal for it),
    /// and a package's program is the package manager's.
    pub fn is_app(&self) -> bool {
        self.word.is_some()
    }

    /// The words that start this program's center command line: the hidden
    /// word, if any.
    pub fn words(&self) -> &'static [&'static str] {
        match self.word {
            Some(_) => &[APP_WORD],
            None => &[],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_app_runs_the_center_behind_its_word() {
        assert_eq!(get(), &CENTER);
        assert!(!CENTER.is_app() && CENTER.words().is_empty());
        assert!(APP.is_app());
        assert_eq!(APP.words(), ["__center"]);
    }
}
