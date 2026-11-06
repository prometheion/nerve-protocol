//! Which git ref the user guide links point at, given what the build was
//! asked for. build.rs includes this file; the library compiles it for its
//! tests only.

/// `wanted` when it is a tag's name, `main` when the build was asked for
/// nothing or for anything else. The ref goes into a URL and into a script,
/// and into build.rs's output, which a newline would end early.
pub fn guide_ref(wanted: &str) -> &str {
    let fine = !wanted.is_empty()
        && wanted
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c));
    if fine { wanted } else { "main" }
}

#[cfg(test)]
mod tests {
    use super::guide_ref;

    /// A release names its tag; a build asked for nothing links `main`, and
    /// so does one asked for something that is no tag's name.
    #[test]
    fn a_tag_is_taken_and_anything_else_is_main() {
        assert_eq!(guide_ref("v0.0.7"), "v0.0.7");
        assert_eq!(guide_ref(""), "main");
        for bad in [
            "a b",
            "v1\nv2",
            "v1\ncargo:rustc-env=X=1",
            "v1/../x",
            "\"v1\"",
            "v1`",
        ] {
            assert_eq!(guide_ref(bad), "main", "{bad:?}");
        }
    }
}
