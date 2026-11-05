//! The re-run of a test in a namespace, shared by the tests that need root
//! and start themselves again where they may have it (`acl.rs`'s lib tests,
//! `backup_caller.rs`, `root_start.rs`).

use std::process::Command;

/// Runs `rerun`, the test started again as root in a namespace, and fails
/// when it fails. Its output is held back, since a child's own lines come out
/// raw, outside this test's captured output, where `.github/scripts/skips.py`
/// does not look: each of its lines that starts with `skipped` is said again
/// here with `eprintln!`, so a re-run that skipped (no ACLs on the temp
/// folder, say) is a skip of this test and not a pass.
pub fn run_saying_skips(rerun: &mut Command) {
    let out = rerun.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    for line in stdout.lines().chain(stderr.lines()) {
        if line.trim_start().starts_with("skipped") {
            eprintln!("{}", line.trim());
        }
    }
    assert!(
        out.status.success(),
        "in the namespace: {}\n{stdout}{stderr}",
        out.status
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHILD: &str = "NERVE_TEST_NS_SKIP_CHILD";

    /// The test below runs this one in a process of its own, where it plays
    /// the parent of a re-run that skips.
    #[test]
    fn a_skip_of_the_rerun_is_said_in_the_tests_own_output() {
        const NAME: &str = "a_skip_of_the_rerun_is_said_in_the_tests_own_output";
        if std::env::var_os(CHILD).is_some() {
            run_saying_skips(Command::new("sh").args([
                "-c",
                "echo 'skipped: no POSIX ACLs here' >&2; echo 'test result: ok. 1 passed'",
            ]));
            return;
        }
        let test = format!("{}::{NAME}", module_path!().split_once("::").unwrap().1);
        let out = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test, "--show-output", "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let log = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{log}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        // In the parent's block, where skips.py reads it.
        let block = log
            .split(&format!("---- {test} stdout ----"))
            .nth(1)
            .unwrap_or_else(|| panic!("no block for {test}:\n{log}"));
        assert!(
            block.lines().any(|l| l == "skipped: no POSIX ACLs here"),
            "the child's skip is not in the parent's block:\n{log}"
        );
    }

    #[test]
    #[should_panic(expected = "in the namespace")]
    fn a_failing_rerun_fails_the_test() {
        run_saying_skips(Command::new("sh").args(["-c", "echo boom >&2; exit 3"]));
    }
}
