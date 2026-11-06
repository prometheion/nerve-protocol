//! Names the git ref the user guide links point at. A release build sets
//! `NERVE_GUIDE_REF` to its tag (`v<version>`, the release workflow does
//! that), so the guide matches the program. Any other build links `main`: a
//! tag that does not exist yet (a pre-release, a build between two releases)
//! would be a dead link.

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
}
