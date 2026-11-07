//! `nerve-node run` under the Windows service control manager. The service
//! `install` registers starts the program with the installed folders; the
//! program then hands its main thread to the manager, which runs the node
//! on a thread of its own and stops it on request. The node says it runs
//! once it has started ([`running`]), so a service that runs is a node that
//! took its config; one that fails stops with exit code 1, and its log says
//! why.
//!
//! The service's start, its stop, a start that fails and a crash also go to
//! the Windows Event Log ([`event`], [`crate::eventlog`]), where an owner
//! looks first; the entries name the log file, which has the rest.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, Once, OnceLock};

use windows_sys::Win32::Foundation::{
    ERROR_CALL_NOT_IMPLEMENTED, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT,
    ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR,
};
use windows_sys::Win32::System::EventLog::{
    DeregisterEventSource, EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, RegisterEventSourceW,
    ReportEventW,
};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING,
    SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE,
    SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
    SetServiceStatus, StartServiceCtrlDispatcherW,
};

use crate::eventlog::{Event, SOURCE};
use crate::win_user::wide;
use crate::winsvc::SERVICE_NAME;

/// What the service runs: the command line's `run`.
type Body = Box<dyn FnOnce() -> Result<(), String> + Send>;

static BODY: Mutex<Option<Body>> = Mutex::new(None);
/// The handle the manager gave for this service's status, as a number:
/// set while the program runs as the service.
static STATUS: Mutex<Option<usize>> = Mutex::new(None);
/// Rung when the manager asks the service to stop.
static STOP: OnceLock<tokio::sync::Notify> = OnceLock::new();
/// Where a start that fails is logged.
static LOG: OnceLock<std::path::PathBuf> = OnceLock::new();
/// Set once the node said it runs: a body that fails before did not start.
static STARTED: AtomicBool = AtomicBool::new(false);
/// Why the manager asked the service to stop, for the Event Log.
static ASKED: Mutex<Option<&'static str>> = Mutex::new(None);

thread_local! {
    /// Set on the thread that runs the node's body: a panic there ends the
    /// program, one elsewhere (a task, which tokio catches) does not.
    static BODY_THREAD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn stop_bell() -> &'static tokio::sync::Notify {
    STOP.get_or_init(tokio::sync::Notify::new)
}

/// Runs `body` as the service when the service control manager started
/// this program; its exit code. Started any other way, as from a terminal,
/// the node does not run (crate::cli::BY_HAND). `log` is the node's log
/// file, where a start that fails is said; `json` whether the error is said
/// as JSON too.
pub fn serve(body: Body, log: std::path::PathBuf, json: bool) -> i32 {
    let _ = LOG.set(log);
    *nerve_transport::sync::lock(&BODY) = Some(body);
    let mut name = wide(SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: a table ended by an empty entry; it returns when the service
    // has stopped, or at once when no manager started this program.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } != 0 {
        return 0;
    }
    let e = std::io::Error::last_os_error();
    nerve_transport::sync::lock(&BODY).take();
    if e.raw_os_error() != Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT as i32) {
        return crate::entry::failed(json, &format!("cannot run as a service: {e}"));
    }
    // Not started by the manager, as from a terminal: the installed node
    // runs as its service only, which the desktop app starts.
    crate::entry::failed(json, crate::cli::BY_HAND)
}

/// Whether this program runs as the service.
pub fn is_service() -> bool {
    nerve_transport::sync::lock(&STATUS).is_some()
}

/// Tells the manager the node runs: called once it has started.
pub fn running() {
    report(SERVICE_RUNNING, 0);
    if is_service() && !STARTED.swap(true, Ordering::SeqCst) {
        let _ = event(
            Event::Started,
            &format!("The Nerve node started. Its log is {}.", log_path()),
        );
    }
}

/// The node's log file, as an entry names it.
fn log_path() -> String {
    LOG.get()
        .map_or_else(|| "in its state folder".into(), |p| p.display().to_string())
}

/// Writes an entry to the Windows Event Log (Application) as the source
/// [`SOURCE`]. Every user of the machine may read that log, so the text is
/// made one line, redacted and cut as a line of the node's log is.
pub fn event(e: Event, text: &str) -> Result<(), String> {
    let text = nerve_transport::log::scrub(text);
    let source = wide(SOURCE);
    // SAFETY: this machine and a NUL-terminated name; a source that is not
    // registered still writes, to the Application log.
    let h = unsafe { RegisterEventSourceW(std::ptr::null(), source.as_ptr()) };
    if h.is_null() {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let line = wide(&text);
    let strings = [line.as_ptr()];
    let kind = if e.is_error() {
        EVENTLOG_ERROR_TYPE
    } else {
        EVENTLOG_INFORMATION_TYPE
    };
    // SAFETY: an open source, one NUL-terminated string and no data.
    let ok = unsafe {
        ReportEventW(
            h,
            kind,
            0,
            e.id(),
            std::ptr::null_mut(),
            1,
            0,
            strings.as_ptr(),
            std::ptr::null(),
        )
    };
    let err = std::io::Error::last_os_error();
    // SAFETY: the handle from above, closed once.
    unsafe { DeregisterEventSource(h) };
    if ok == 0 {
        return Err(err.to_string());
    }
    Ok(())
}

/// Writes each panic to the Event Log, then does what the hook before did. A
/// panic in the body's thread ends the program ([`run_body`]), and the
/// service's recovery settings start it again (three times a day at most);
/// one elsewhere leaves the node running, unless it left a lock poisoned:
/// the next take of that lock ends the program (nerve_transport::sync), and
/// the recovery settings start it again as well. The log file is left alone
/// here: the panic may have come while its lock was held.
fn watch_crashes() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let before = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = event(Event::Crashed, &crash_text(info));
            before(info);
        }));
    });
}

fn crash_text(info: &std::panic::PanicHookInfo<'_>) -> String {
    let p = info.payload();
    let what = p
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| p.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("no message");
    let at = info
        .location()
        .map(|l| format!(" at {}:{}", l.file(), l.line()))
        .unwrap_or_default();
    if BODY_THREAD.with(|b| b.get()) {
        format!(
            "The Nerve node crashed (a panic{at}): {what}. The service ends; its recovery settings start it again, three times a day at most. Its log is {}.",
            log_path()
        )
    } else {
        format!(
            "A part of the Nerve node panicked{at}: {what}. The node runs on. If the panic left a lock poisoned, the node ends when it next takes it, and its recovery settings start it again. Its log is {}.",
            log_path()
        )
    }
}

/// Waits until the manager asks the service to stop.
pub async fn stop_requested() {
    stop_bell().notified().await;
}

fn report(state: SERVICE_STATUS_CURRENT_STATE, code: u32) {
    let Some(h) = *nerve_transport::sync::lock(&STATUS) else {
        return;
    };
    let st = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dwWin32ExitCode: if code == 0 {
            NO_ERROR
        } else {
            ERROR_SERVICE_SPECIFIC_ERROR
        },
        dwServiceSpecificExitCode: code,
        dwCheckPoint: 0,
        // The node takes a few seconds at most to start or stop.
        dwWaitHint: 30_000,
    };
    // SAFETY: the handle the manager gave and a filled status.
    unsafe { SetServiceStatus(h as SERVICE_STATUS_HANDLE, &st) };
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut windows_sys::core::PWSTR) {
    let name = wide(SERVICE_NAME);
    // SAFETY: a NUL-terminated name and a handler that lives as long as the
    // program.
    let h =
        unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control), std::ptr::null()) };
    if h.is_null() {
        return;
    }
    *nerve_transport::sync::lock(&STATUS) = Some(h as usize);
    report(SERVICE_START_PENDING, 0);
    watch_crashes();
    let body = nerve_transport::sync::lock(&BODY).take();
    let code = run_body(body);
    report(SERVICE_STOPPED, code);
}

/// Runs the node's body and writes how it ended to the Event Log; the
/// service's exit code. A panic is caught here, after the hook wrote it
/// ([`watch_crashes`]): left to unwind into [`service_main`], which cannot
/// unwind, it would panic a second time and write a second crash. The
/// program then ends at once, as a crash does, so the service's failure
/// actions start it again.
/// A lock the panic left poisoned is not taken again on the way: the
/// program aborts before anything here locks.
fn run_body(body: Option<Body>) -> u32 {
    BODY_THREAD.with(|b| b.set(true));
    let ended = match body {
        Some(b) => std::panic::catch_unwind(std::panic::AssertUnwindSafe(b)),
        None => Ok(Ok(())),
    };
    let Ok(ended) = ended else {
        std::process::abort();
    };
    match ended {
        Err(e) => {
            // Nobody reads stderr here: the node's log file has it.
            if let (Some(log), Some(path)) = (nerve_transport::log::global(), LOG.get()) {
                let _ = log.attach_file(path);
            }
            tracing::error!("the service stopped: {e}");
            let (kind, what) = if STARTED.load(Ordering::SeqCst) {
                (Event::Crashed, "stopped with an error")
            } else {
                (Event::NotStarted, "did not start")
            };
            let _ = event(
                kind,
                &format!("The Nerve node {what}: {e}. Its log is {}.", log_path()),
            );
            1
        }
        Ok(()) => {
            let why = nerve_transport::sync::lock(&ASKED).unwrap_or("its work ended");
            let _ = event(Event::Stopped, &format!("The Nerve node stopped: {why}."));
            0
        }
    }
}

unsafe extern "system" fn control(
    control: u32,
    _event: u32,
    _data: *mut core::ffi::c_void,
    _context: *mut core::ffi::c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            *nerve_transport::sync::lock(&ASKED) = Some(if control == SERVICE_CONTROL_STOP {
                "the service control manager asked it to"
            } else {
                "Windows shuts down"
            });
            report(SERVICE_STOP_PENDING, 0);
            // A permit is kept when the node does not wait yet.
            stop_bell().notify_one();
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(got.contains("The node runs on."), "{got}");
    }

    /// Stands in for [`service_main`]: the body runs in a function that
    /// cannot unwind.
    extern "system" fn serve_panicking() {
        let marker = std::env::var("NERVE_TEST_CRASH").unwrap();
        run_body(Some(Box::new(move || panic!("test body crash {marker}"))));
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
        // The failure actions restart it a few times only; the entry
        // promises no more.
        assert!(
            crashes[0].contains("start it again, three times a day at most"),
            "{}",
            crashes[0]
        );
        let not_unwinding = all
            .iter()
            .filter(|l| l.contains("panic in a function that cannot unwind"))
            .count();
        assert_eq!(not_unwinding, 0, "{all:#?}");
    }
}
