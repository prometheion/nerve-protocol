//! Names the git ref the user guide links point at, and embeds the built web
//! UIs.
//!
//! - A release build sets `NERVE_GUIDE_REF` to its tag (`v<version>`, the
//!   release workflow does that), so the guide matches the program. Any other
//!   build links `main`: a tag that does not exist yet (a pre-release, a build
//!   between two releases) would be a dead link.
//! - The web UIs of the center and the node are built from `webui/` at the
//!   repository's root into `webui/dist`, which is committed: this lists
//!   every file there for `include_bytes!`, so `cargo build` needs no Node
//!   (docs/dev/web-uis.md, "Changing the pages").

use std::path::{Path, PathBuf};

#[path = "src/guide_ref.rs"]
mod guide_ref;

fn main() {
    println!("cargo:rerun-if-changed=src/guide_ref.rs");
    println!("cargo:rerun-if-env-changed=NERVE_GUIDE_REF");
    let wanted = std::env::var("NERVE_GUIDE_REF").unwrap_or_default();
    println!(
        "cargo:rustc-env=NERVE_GUIDE_REF={}",
        guide_ref::guide_ref(&wanted)
    );
    embed_dist();
}

/// Writes `$OUT_DIR/webui_dist.rs`: `DIST`, each file of `webui/dist` by its
/// path there (`/` between folders) and its bytes, in the order of the paths.
fn embed_dist() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let dist = manifest.join("../../webui/dist");
    println!("cargo:rerun-if-changed={}", dist.display());
    let mut files = Vec::new();
    walk(&dist, &dist, &mut files);
    if !files.iter().any(|(p, _)| p == "center.html") {
        panic!(
            "{} holds no built web UI: run `npm ci && npm run build` in webui/",
            dist.display()
        );
    }
    files.sort();
    let mut out = String::from(
        "/// The built web UIs, `webui/dist`: each file by its path and its bytes.\npub static DIST: &[(&str, &[u8])] = &[\n",
    );
    for (rel, abs) in &files {
        let abs = abs.canonicalize().unwrap();
        out.push_str(&format!(
            "    ({rel:?}, include_bytes!({:?})),\n",
            abs.display().to_string()
        ));
    }
    out.push_str("];\n");
    let to = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("webui_dist.rs");
    std::fs::write(to, out).unwrap();
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let path = e.path();
        if path.is_dir() {
            walk(root, &path, out);
        } else {
            let rel = path.strip_prefix(root).unwrap();
            let rel: Vec<String> = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            out.push((rel.join("/"), path));
        }
    }
}
