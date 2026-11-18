//! The node's desktop app: a window that drives `nerve-node`. Every action
//! runs the CLI (the same program, [`runner`]) and shows its JSON answer
//! ([`view`]), so the app has the CLI's checks and audit records and keeps
//! no settings of its own.

/// The window, its pages and dialogs, compiled from ui/ in a crate of
/// their own (crates/nerve-ui), so that the tests' builds compile them once.
pub use nerve_ui::*;

pub mod app;
pub mod broker;
pub mod browser;
pub mod deps;
pub mod dialog;
pub mod headless;
pub mod hub;
pub mod in_app;
pub mod instance;
pub mod motion;
pub mod parts;
pub mod reference;
pub mod runner;
pub mod scheme;
pub mod settings;
pub mod view;

/// What the program runs, by the name it was started by and its first word
/// (src/main.rs): the center's command line behind the hidden word
/// `__center` or by the terminal name `nerve-center`, the node's by the
/// terminal name `nerve-node` (both links to this program on Linux), and
/// the app otherwise, which is the window without arguments and the node's
/// command line with them. Only those two names count: the edition stays
/// the app's either way (nerve_node::edition).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartedAs {
    /// The center's command line, after `skip` of the program's arguments.
    Center { skip: usize },
    /// The node's command line.
    Node,
    /// The app.
    App,
}

/// [`StartedAs`] of the program started as `argv0` with the first argument
/// `first`.
pub fn started_as(argv0: Option<&std::ffi::OsStr>, first: Option<&str>) -> StartedAs {
    if first == Some(nerve_center::edition::APP_WORD) {
        return StartedAs::Center { skip: 1 };
    }
    let name = argv0
        .map(std::path::Path::new)
        .and_then(std::path::Path::file_stem)
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    match name {
        n if n == nerve_center::edition::TERMINAL_NAME => StartedAs::Center { skip: 0 },
        n if n == nerve_node::edition::NODE.program => StartedAs::Node,
        _ => StartedAs::App,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn the_name_and_the_first_word_pick_what_runs() {
        let start = |argv0: &str, first: Option<&str>| started_as(Some(OsStr::new(argv0)), first);
        assert_eq!(
            start("/usr/bin/nerve", Some("__center")),
            StartedAs::Center { skip: 1 }
        );
        assert_eq!(
            start("/usr/local/bin/nerve-center", Some("status")),
            StartedAs::Center { skip: 0 }
        );
        assert_eq!(start("nerve-center", None), StartedAs::Center { skip: 0 });
        assert_eq!(start("/usr/local/bin/nerve-node", None), StartedAs::Node);
        assert_eq!(
            start(r"C:\Program Files\Nerve\nerve.exe", None),
            StartedAs::App
        );
        assert_eq!(start("/usr/bin/nerve", Some("status")), StartedAs::App);
        // Another name is the app, whatever it holds.
        assert_eq!(start("/tmp/nerve-center-old", None), StartedAs::App);
    }

    /// The center finds the app's package by the mark the package leaves.
    #[test]
    fn the_center_knows_the_app_s_package() {
        assert_eq!(
            nerve_center::edition::PACKAGE_MARK,
            nerve_node::service::Package::MARK
        );
    }
}
