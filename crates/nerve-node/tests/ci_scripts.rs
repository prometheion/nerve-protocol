//! The shell scripts of the CI workflows that have a part worth a test of
//! its own: the load of `repeat.yml` ends with its script, and the
//! diagnostics of the installed test survive what a failed run leaves
//! behind (issue #180).

#![cfg(unix)]

use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn script(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.github/scripts")
        .join(name)
}

/// The processes of group `pgid`, or None where there is no `pgrep`.
fn group(pgid: u32) -> Option<usize> {
    let out = Command::new("pgrep")
        .args(["-g", &pgid.to_string()])
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&out.stdout).lines().count())
}

/// Waits until the group has `want` processes (`at_least`: or more).
fn wait_group(pgid: u32, want: usize, at_least: bool) -> usize {
    let t = Instant::now();
    loop {
        let n = group(pgid).unwrap();
        if (at_least && n >= want)
            || (!at_least && n == want)
            || t.elapsed() > Duration::from_secs(20)
        {
            return n;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn the_load_ends_every_loop_with_its_script() {
    if group(1).is_none() {
        eprintln!("skipped: needs pgrep");
        return;
    }
    // Its own group, so the test counts the script's loops and nothing else.
    let mut load = Command::new("bash")
        .arg(script("repeat-load.sh"))
        .arg("2")
        .process_group(0)
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let pgid = load.id();
    // The script and its four loops.
    let up = wait_group(pgid, 5, true);
    let term = Command::new("kill")
        .args(["-TERM", &pgid.to_string()])
        .status()
        .unwrap();
    let status = load.wait().unwrap();
    // A loop may be in the middle of starting `env`: it ends with that.
    let left = wait_group(pgid, 0, false);
    if left != 0 {
        let _ = Command::new("kill")
            .args(["-KILL", "--", &format!("-{pgid}")])
            .status();
    }
    assert!(up >= 5, "the load started {up} processes, not 5");
    assert!(term.success());
    assert!(status.success(), "the script ended with {status}");
    assert_eq!(left, 0, "{left} processes of the load outlived its script");
}

#[test]
fn the_load_wants_a_number_of_workers() {
    for args in [&[][..], &["x"], &["2x"], &[""]] {
        let status = Command::new("bash")
            .arg(script("repeat-load.sh"))
            .args(args)
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(2), "{args:?}");
    }
}

/// Runs `unit_processes` of the installed test's script under its own
/// shell options (`set -euo pipefail`, in the EXIT trap), on nothing of the
/// machine it runs on: the unit's control group and the `/proc` of `pids`
/// are folders of the test, and `systemctl`, `find`, `ps` and `top` are
/// shell functions. `find` lists `pids` and then fails, as it does when a
/// command's cgroup goes during the walk, and `top` writes its arguments to
/// `top.args`. No program the test writes is started: a script written
/// just now fails to start (`Text file busy`) while a process that another
/// test's thread starts at that moment still holds it open, and the
/// function then stops at its first line, as it does on a machine without
/// the cgroup folder. Returns the output and the arguments `top` got.
fn unit_processes_after_a_failed_walk(pids: &[u32]) -> (std::process::Output, String) {
    let d = tempfile::tempdir().unwrap();
    let root = d.path();
    std::fs::create_dir_all(root.join("cgroup/system.slice/nerve-node.service")).unwrap();
    for p in pids {
        let proc = root.join(format!("proc/{p}"));
        let task = proc.join(format!("task/{p}"));
        std::fs::create_dir_all(&task).unwrap();
        std::fs::create_dir(proc.join("fd")).unwrap();
        std::fs::write(proc.join("cmdline"), format!("fake-{p}\0--wait\0")).unwrap();
        std::fs::write(proc.join("status"), "State:\tS (sleeping)\nSigQ:\t0/63\n").unwrap();
        std::fs::write(task.join("comm"), format!("fake-{p}\n")).unwrap();
        std::fs::write(task.join("wchan"), "do_wait").unwrap();
        std::fs::write(task.join("stack"), "[<0>] do_wait+0x1/0x2\n").unwrap();
    }
    // The function, cut out of the script as it stands, with the places of
    // the machine it reads moved into the test's folder.
    let text = std::fs::read_to_string(script("keyring-end-to-end.sh")).unwrap();
    let start = text.find("unit_processes() {").unwrap();
    let end = start + text[start..].find("\n}\n").unwrap() + 3;
    let function = &text[start..end];
    let (cgroup, proc) = ("/sys/fs/cgroup", "/proc/");
    for place in [cgroup, proc] {
        assert!(function.contains(place), "{place} is not in {function}");
    }
    let rest = function.replace(cgroup, "").replace(proc, "");
    assert!(
        !rest.contains("/sys") && !rest.contains("/proc"),
        "the function reads another place of the machine: {function}"
    );
    let function = function
        .replace(cgroup, &format!("{}/cgroup", root.display()))
        .replace(proc, &format!("{}/proc/", root.display()));
    let list = pids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let fakes = format!(
        r#"systemctl() {{ echo /system.slice/nerve-node.service; }}
find() {{ printf '%s\n' {list}; return 1; }}
ps() {{ echo 'PID TID STAT WCHAN %CPU COMMAND'; for p in {list} 4242; do echo "$p $p S do_wait 0.0 fake-$p"; done; }}
top() {{ echo "$@" > '{}'; }}
"#,
        root.join("top.args").display()
    );
    let run =
        format!("set -euo pipefail\n{fakes}{function}\nunit_processes\necho reached-the-end\n");
    let out = Command::new("bash").arg("-c").arg(run).output().unwrap();
    let args = std::fs::read_to_string(root.join("top.args")).unwrap_or_default();
    (out, args)
}

#[test]
fn the_diagnostics_go_on_when_the_walk_of_the_cgroups_fails() {
    let (out, _) = unit_processes_after_a_failed_walk(&[1, 2]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{out:?}");
    assert!(text.contains("the unit's processes: 1 2"), "{out:?}");
    // Each process in turn, from `ps` and its folder in /proc: only the
    // unit's.
    assert!(text.contains("\n2 2 S do_wait 0.0 fake-2\n"), "{text}");
    assert!(!text.contains("fake-4242"), "{text}");
    assert!(text.contains("-- 2: fake-2 --wait"), "{text}");
    assert!(text.contains("State:\tS (sleeping)"), "{text}");
    assert!(text.contains("thread 2 (fake-2, wchan do_wait):"), "{text}");
    assert!(text.contains("     [<0>] do_wait+0x1/0x2"), "{text}");
    assert!(text.ends_with("reached-the-end\n"), "{text}");
}

#[test]
fn top_gets_no_more_pids_than_it_takes() {
    let pids: Vec<u32> = (1..=30).collect();
    let (out, args) = unit_processes_after_a_failed_walk(&pids);
    assert!(out.status.success(), "{out:?}");
    let given = args.split_whitespace().last().unwrap_or_default();
    assert_eq!(given.split(',').count(), 20, "top got: {args}");
}
