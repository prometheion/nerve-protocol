//! The app's way to the administrator rights on Linux: the pipe to the
//! broker pkexec starts. Another process of the same user must not reach
//! it, as it could through `/proc/<app>/fd` before (review issue-10 r1).
//! Here pkexec is a script that starts the broker without asking, so the
//! broker runs as this user; the app's side is the app's own code.
#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use nerve::broker::{self, Launch};

#[test]
fn another_process_of_the_user_cannot_write_to_the_broker() {
    // SAFETY: a plain query.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: root may open any process's pipes");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let pid_file = d.path().join("broker.pid");
    let pkexec = d.path().join("pkexec");
    std::fs::write(
        &pkexec,
        format!(
            "#!/bin/sh\necho $$ > '{}'\nshift\nexec \"$@\"\n",
            pid_file.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&pkexec, std::fs::Permissions::from_mode(0o755)).unwrap();
    // Only the script's folder: the real pkexec must never be asked.
    let path = d.path().to_str().unwrap();
    assert_eq!(
        nerve::deps::find_program("pkexec", Some(path.as_ref())),
        Some(pkexec.clone())
    );
    // SAFETY: the only test of this program, before any thread of its own.
    unsafe { std::env::set_var("PATH", path) };

    let exe = Path::new(env!("CARGO_BIN_EXE_nerve"));
    let client = broker::launch(exe, Launch::Elevated).unwrap();
    let out = client.run(vec!["--version".into()], None).unwrap();
    assert!(
        String::from_utf8_lossy(&out.stdout).starts_with("nerve "),
        "{out:?}"
    );

    // The app's end of the broker's stdin: the pipe the broker reads.
    let broker: u32 = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let pipe = std::fs::read_link(format!("/proc/{broker}/fd/0")).unwrap();
    let fd = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|e| e.ok())
        .find(|e| std::fs::read_link(e.path()).ok().as_ref() == Some(&pipe))
        .map(|e| e.file_name().into_string().unwrap())
        .expect("the app holds the broker's stdin");

    // What the reviewer did, from a process that is not the app.
    let tried = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!(
            "printf '{{\"id\":4242,\"args\":[\"--version\"]}}\\n' > /proc/{}/fd/{fd}",
            std::process::id()
        ))
        .env("LC_ALL", "C")
        .output()
        .unwrap();
    let said = String::from_utf8_lossy(&tried.stderr);
    assert!(!tried.status.success(), "the write went through");
    assert!(said.contains("Permission denied"), "{said}");
    // The app's own requests still go through.
    assert!(client.run(vec!["--version".into()], None).unwrap().ok);
}
