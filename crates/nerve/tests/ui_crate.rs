//! The app's Slint UI is compiled once, in the crate `nerve-ui`: the code
//! Slint generates takes about 8 GB of one rustc, and a test build of the
//! app's crate compiled it twice side by side (the library and its unit
//! tests), which the 16 GB CI runners did not survive (#232). These tests
//! keep it that way; they read the manifests and sources by path.

use std::path::{Path, PathBuf};

fn crates() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_owned()
}

fn read(path: &str) -> String {
    std::fs::read_to_string(crates().join(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The manifest's lines without comments and blanks.
fn lines(path: &str) -> Vec<String> {
    read(path)
        .lines()
        .map(|l| l.trim().to_owned())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

/// No test build of the UI crate: it would compile the generated code again.
#[test]
fn the_ui_crate_builds_no_test_program() {
    let manifest = lines("nerve-ui/Cargo.toml");
    assert!(manifest.contains(&"[lib]".to_owned()), "{manifest:?}");
    assert!(
        manifest.contains(&"test = false".to_owned()),
        "{manifest:?}"
    );
    assert!(
        manifest.contains(&"doctest = false".to_owned()),
        "{manifest:?}"
    );
}

/// The app's crate takes the generated code from the UI crate and neither
/// compiles nor includes the Slint files itself.
#[test]
fn the_app_crate_takes_its_ui_from_the_ui_crate() {
    let manifest = lines("nerve/Cargo.toml");
    assert!(
        manifest.iter().any(|l| l.starts_with("nerve-ui = ")),
        "{manifest:?}"
    );
    assert!(
        !manifest.contains(&"[build-dependencies]".to_owned()),
        "{manifest:?}"
    );
    assert!(!read("nerve/build.rs").contains("slint_build"));
    let lib = read("nerve/src/lib.rs");
    assert!(lib.contains("pub use nerve_ui::*;"));
    assert!(!lib.contains("include_modules"));
}
