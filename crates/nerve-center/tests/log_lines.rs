//! Reading the center's `log.jsonl` in a test: each line is a JSON entry, so
//! a Windows path in a message is stored with doubled backslashes and a
//! search of the raw text for it never matches. The installed-service test
//! (`win_service.rs`) includes this file.

use serde_json::Value;

/// The first message in the log text `text` that holds every one of `parts`.
pub fn message_with(text: &str, parts: &[&str]) -> Option<String> {
    text.lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter_map(|v| v["msg"].as_str().map(str::to_string))
        .find(|m| parts.iter().all(|p| m.contains(p)))
}

/// A message with a Windows path is found by the path as written, and an
/// older line with only some of the parts does not satisfy the search
/// (round 5, correctness 1).
#[test]
fn a_path_in_a_log_line_is_found_as_written() {
    use nerve_transport::log::{Level, Log};
    let d = tempfile::tempdir().unwrap();
    let file = d.path().join("log.jsonl");
    let folder = r"C:\ProgramData\nerve-center\settings";
    Log::append_entry(&file, Level::Error, "another account owns something else").unwrap();
    Log::append_entry(
        &file,
        Level::Error,
        &format!("the service cannot start: {folder}: another account owns it"),
    )
    .unwrap();
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(!text.contains(folder), "{text}");
    let found = message_with(&text, &["another account", folder]).unwrap();
    assert!(found.contains(folder), "{found}");
    assert!(message_with(&text, &["another account", r"C:\elsewhere"]).is_none());
}
