//! Every TCP listener of the node and the center is bound through
//! `nerve_service::listen`, which on Windows binds it for the service alone
//! (`SO_EXCLUSIVEADDRUSE`): a listener bound another way could have its port
//! taken by another account's program while the service listens.

use std::path::{Path, PathBuf};

/// The `.rs` files below `dir`.
fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The lines of `source` before its tests, without comments.
fn code(source: &str) -> Vec<(usize, &str)> {
    source
        .lines()
        .enumerate()
        .take_while(|(_, l)| {
            !l.trim_start()
                .trim_start_matches("pub(crate) ")
                .starts_with("mod tests")
        })
        .filter(|(_, l)| !l.trim_start().starts_with("//"))
        .map(|(i, l)| (i + 1, l))
        .collect()
}

#[test]
fn every_listener_of_the_services_is_bound_for_them_alone() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for c in ["nerve-node", "nerve-center"] {
        sources(&crates.join(c).join("src"), &mut files);
    }
    assert!(files.len() > 20, "{files:?}");
    let mut found = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap();
        for (line, l) in code(&text) {
            // A port probe binds and drops at once, for a program that
            // listens itself (the checker's llama-server): no listener.
            if l.contains("TcpListener::bind(")
                && !l.contains("std::net::TcpListener::bind(\"127.0.0.1:0\")")
            {
                found.push(format!("{}:{line}: {}", file.display(), l.trim()));
            }
        }
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
}
