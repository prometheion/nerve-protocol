//! Help's task map has a row for each place the node's Windows messages
//! send the owner to (docs-14), and on Windows a link to the user guide's
//! Windows page, whose map it is the short form of.

const HELP: &str = include_str!("../ui/help.slint");

/// The places a row names, each `where:` of the task map.
fn places() -> Vec<&'static str> {
    HELP.lines()
        .filter_map(|l| l.trim().strip_prefix("where: \""))
        .filter_map(|l| l.strip_suffix("\";"))
        .collect()
}

#[test]
fn the_task_map_has_the_places_the_messages_name() {
    let places = places();
    for place in [
        // The owner's password (INSTALL_AGAIN).
        "Settings › General › Account for commands",
        // A file moved in where the watch does not reach.
        "Permissions › Folders › Sync folders",
        "Settings › Limits",
        "Permissions › Sudo",
        "Settings › Keys",
        "Centers › New key…",
    ] {
        assert!(places.contains(&place), "{place}: {places:?}");
    }
    let page = include_str!("../../../docs/user/windows.md");
    assert!(page.contains("\n## Where each task is\n"));
    assert!(
        HELP.contains("if Install.windows: HorizontalLayout {")
            && HELP.contains("/docs/user/windows.md#where-each-task-is\");"),
        "Help links the Windows page on Windows"
    );
    // The messages name the same place.
    let winsvc = include_str!("../../nerve-node/src/winsvc.rs");
    assert!(winsvc.contains("Settings › General › Account for commands"));
}
