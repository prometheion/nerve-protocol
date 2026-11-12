//! `nerve-node run` under the Windows service control manager. The service
//! `install` registers starts the program with the installed folders; the
//! program then hands its main thread to the manager, which runs the node
//! on a thread of its own and stops it on request. The node says it runs
//! once it has started ([`running`]), so a service that runs is a node that
//! took its config; one that fails stops with exit code 1, and its log says
//! why. The dispatcher is the center's too (nerve_service::win::dispatch).
//!
//! The service's start, its stop, a start that fails and a crash also go to
//! the Windows Event Log as the source [`crate::eventlog::SOURCE`], where an
//! owner looks first; the entries name the log file, which has the rest.

use nerve_service::win::dispatch::{self, Events, Served};
pub use nerve_service::win::dispatch::{is_service, running, stop_requested};

use crate::eventlog::SOURCE;
use crate::winsvc::SERVICE_NAME;

/// What the service runs: the command line's `run`.
type Body = Box<dyn FnOnce() -> Result<(), String> + Send>;

/// The node's entries in the Event Log, which name `log`.
fn events(log: std::path::PathBuf) -> Events {
    Events {
        source: SOURCE,
        what: "Nerve node",
        log,
    }
}

/// Says in the node's log file why the service stopped. Nobody reads stderr
/// here. The line is appended without reading the file or following a link:
/// a start that stops on a state folder another account owns (crate::entry)
/// must not read or write through what that account put there, and the
/// manager starts it again every minute. The Event Log has the error too.
fn stopped(file: &std::path::Path, e: &str) {
    let _ = nerve_transport::log::Log::append_entry(
        file,
        nerve_transport::log::Level::Error,
        &format!("the service stopped: {e}"),
    );
}

/// Runs `body` as the service when the service control manager started
/// this program; its exit code. Started any other way, as from a terminal,
/// the node does not run (crate::cli::BY_HAND). `log` is the node's log
/// file, where a start that fails is said; `json` whether the error is said
/// as JSON too.
pub fn serve(body: Body, log: std::path::PathBuf, json: bool) -> i32 {
    let file = log.clone();
    let body: Body = Box::new(move || {
        let r = body();
        if let Err(e) = &r {
            stopped(&file, e);
        }
        r
    });
    match dispatch::serve(SERVICE_NAME, body, Some(events(log))) {
        Ok(Served::Ran(_)) => 0,
        // Not started by the manager, as from a terminal: the installed node
        // runs as its service only, which the desktop app starts.
        Ok(Served::NotAService) => crate::entry::failed(json, crate::cli::BY_HAND),
        Err(e) => crate::entry::failed(json, &e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eventlog::Event;
    use crate::win_user::wide;
    use nerve_service::win::dispatch::{event, run_body};
    use std::sync::Mutex;

    /// Entries go to the Event Log as the node's.
    fn watch_crashes() {
        dispatch::log_events(events("C:\\ProgramData\\Nerve\\state\\log.jsonl".into()));
    }

    /// What a Windows PowerShell line prints, line by line.
    fn powershell(script: &str) -> Vec<String> {
        let o = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", script])
            .output()
            .unwrap();
        String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// The newest entries of the source in the Application log, one line
    /// each: the kind, the event id and the text, its line breaks made
    /// spaces.
    fn entries() -> Vec<String> {
        entries_after(0)
    }

    /// Those numbered above `index` only.
    fn entries_after(index: u64) -> Vec<String> {
        powershell(&format!(
            "Get-EventLog -LogName Application -Source {SOURCE} -Newest 50 | Where-Object {{ $_.Index -gt {index} }} | ForEach-Object {{ \"$($_.EntryType) $($_.InstanceId) $(($_.ReplacementStrings -join ' ') -replace '[\\r\\n]+', ' ')\" }}"
        ))
    }

    /// The number of the newest entry in the Application log.
    fn last_index() -> u64 {
        powershell("(Get-EventLog -LogName Application -Newest 1).Index")
            .first()
            .and_then(|l| l.trim().parse().ok())
            .unwrap_or(0)
    }

    fn entry_with(marker: &str) -> String {
        let all = entries();
        all.iter()
            .find(|l| l.contains(marker))
            .cloned()
            .unwrap_or_else(|| panic!("no entry with {marker} in {all:#?}"))
    }

    /// Every event has its text in this program: the one string it is
    /// given, as the Event Viewer shows it.
    #[test]
    fn the_program_carries_the_text_of_its_events() {
        use windows_sys::Win32::System::Diagnostics::Debug::{
            FORMAT_MESSAGE_ARGUMENT_ARRAY, FORMAT_MESSAGE_FROM_HMODULE, FormatMessageW,
        };
        use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
        // SAFETY: null is this program.
        let me = unsafe { GetModuleHandleW(std::ptr::null()) };
        for e in Event::ALL {
            let line = wide("the node did this");
            let args = [line.as_ptr()];
            let mut buf = [0u16; 256];
            // SAFETY: this program's message table, one string for %1 and
            // a buffer of the length given.
            let n = unsafe {
                FormatMessageW(
                    FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ARGUMENT_ARRAY,
                    me as *const _,
                    e.id(),
                    0,
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    args.as_ptr().cast(),
                )
            };
            assert_ne!(n, 0, "{e:?}: {}", std::io::Error::last_os_error());
            assert_eq!(
                String::from_utf16_lossy(&buf[..n as usize]),
                "the node did this\r\n",
                "{e:?}"
            );
        }
    }

    /// An entry reaches the Application log with its kind and id, without
    /// the secret its text held; a panic is written as a crash.
    #[test]
    fn events_and_crashes_reach_the_event_log() {
        watch_crashes();
        let marker = nerve_transport::keys::random_token(12);
        event(
            Event::Started,
            &format!("test entry {marker} with password=hunter22"),
        )
        .unwrap();
        let got = entry_with(&marker);
        assert!(got.starts_with("Information 1 test entry"), "{got}");
        assert!(!got.contains("hunter22"), "{got}");
        // A value on the next line goes too, as in the log.
        event(
            Event::NotStarted,
            &format!("test lines {marker}z token:\nhunter23"),
        )
        .unwrap();
        let got = entry_with(&format!("{marker}z"));
        assert!(!got.contains("hunter23"), "{got}");
        event(Event::NotStarted, &format!("test refusal {marker}x")).unwrap();
        assert!(entry_with(&format!("{marker}x")).starts_with("Error 3 "));
        watch_crashes();
        let crash = format!("test crash {marker}y");
        let thrown = crash.clone();
        assert!(
            std::thread::spawn(move || panic!("{thrown}"))
                .join()
                .is_err()
        );
        // Another thread than the body's: the node runs on.
        let got = entry_with(&crash);
        assert!(
            got.starts_with("Error 4 A part of the Nerve node panicked at "),
            "{got}"
        );
        assert!(got.contains("It runs on."), "{got}");
        assert!(got.contains("Its log is C:\\ProgramData"), "{got}");
    }

    /// Stands in for [`service_main`]: the body runs in a function that
    /// cannot unwind.
    extern "system" fn serve_panicking() {
        let marker = std::env::var("NERVE_TEST_CRASH").unwrap();
        run_body(Some(Box::new(move || panic!("test body crash {marker}"))));
    }

    /// A start that stops says why in the node's log file, and writes
    /// nothing through a link that stands in its place: the file may be the
    /// account's that owns the folder (security-2).
    #[test]
    fn a_stop_is_said_in_the_log_file_but_not_through_a_link() {
        let d = tempfile::tempdir().unwrap();
        let log = d.path().join("log.jsonl");
        stopped(&log, "state folder refused");
        let said = std::fs::read_to_string(&log).unwrap();
        assert!(
            said.contains("the service stopped: state folder refused"),
            "{said}"
        );
        let (elsewhere, link) = (d.path().join("elsewhere.txt"), d.path().join("link.jsonl"));
        std::fs::write(&elsewhere, "keep\n").unwrap();
        if std::os::windows::fs::symlink_file(&elsewhere, &link).is_err() {
            // A link needs the privilege for it.
            return;
        }
        stopped(&link, "state folder refused");
        assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), "keep\n");
    }

    /// Run by the test below in a program of its own, which it ends.
    #[test]
    #[ignore = "a child of a_crash_of_the_body_is_one_entry"]
    fn crash_the_body() {
        if std::env::var_os("NERVE_TEST_CRASH").is_none() {
            return;
        }
        watch_crashes();
        serve_panicking();
    }

    /// Run by the test below in a program of its own, which it ends.
    #[test]
    #[ignore = "a child of a_lock_a_task_poisoned_ends_the_service"]
    fn poison_a_lock_in_a_task() {
        static HELD: Mutex<u32> = Mutex::new(0);
        let Ok(marker) = std::env::var("NERVE_TEST_POISON") else {
            return;
        };
        watch_crashes();
        run_body(Some(Box::new(move || {
            // A task panics under the lock and the node runs on, as one
            // that tokio catches does.
            let _ = std::thread::spawn(move || {
                let _g = nerve_transport::sync::lock(&HELD);
                panic!("test task crash {marker}");
            })
            .join();
            *nerve_transport::sync::lock(&HELD) += 1;
            Ok(())
        })));
    }

    /// A task that panics under a lock leaves the node running; the next
    /// take of that lock ends it with the poisoned-lock code, before the
    /// body could say it stopped, so the failure actions start it again.
    #[test]
    fn a_lock_a_task_poisoned_ends_the_service() {
        let marker = nerve_transport::keys::random_token(12);
        let before = last_index();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "win_service::tests::poison_a_lock_in_a_task",
                "--exact",
                "--ignored",
                "--nocapture",
            ])
            .env("NERVE_TEST_POISON", &marker)
            .output()
            .unwrap();
        assert_eq!(
            child.status.code(),
            Some(nerve_transport::sync::POISONED),
            "{}",
            String::from_utf8_lossy(&child.stderr)
        );
        let all = entries_after(before);
        let ours: Vec<&String> = all.iter().filter(|l| l.contains(&marker)).collect();
        assert_eq!(ours.len(), 1, "{all:#?}");
        assert!(
            ours[0].starts_with("Error 4 A part of the Nerve node panicked at ")
                && ours[0].contains("If the panic left a lock poisoned"),
            "{}",
            ours[0]
        );
    }

    /// A panic in the body ends the program and writes one crash, not a
    /// second one for the frame that cannot unwind.
    #[test]
    fn a_crash_of_the_body_is_one_entry() {
        let marker = nerve_transport::keys::random_token(12);
        let before = last_index();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "win_service::tests::crash_the_body",
                "--exact",
                "--ignored",
                "--nocapture",
            ])
            .env("NERVE_TEST_CRASH", &marker)
            .output()
            .unwrap();
        assert!(!child.status.success());
        let all = entries_after(before);
        let crashes: Vec<&String> = all.iter().filter(|l| l.contains(&marker)).collect();
        assert_eq!(crashes.len(), 1, "{all:#?}");
        assert!(
            crashes[0].starts_with("Error 4 The Nerve node crashed (a panic at "),
            "{}",
            crashes[0]
        );
        // The failure actions restart it as often as it fails (arch-1).
        assert!(
            crashes[0].contains("its recovery settings start it again."),
            "{}",
            crashes[0]
        );
        assert!(!crashes[0].contains("three times"), "{}", crashes[0]);
        let not_unwinding = all
            .iter()
            .filter(|l| l.contains("panic in a function that cannot unwind"))
            .count();
        assert_eq!(not_unwinding, 0, "{all:#?}");
    }
}
