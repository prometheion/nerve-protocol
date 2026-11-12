//! A program under the Windows service control manager, as the node's and
//! the center's services run: the program hands its main thread to the
//! manager, which runs the program's body on a thread of its own and asks it
//! to stop. The body says it runs once it has started ([`running`]), so a
//! service that runs is a program that took its settings; one that fails
//! stops with exit code 1. A panic in the body ends the program at once, and
//! a lock a panic poisoned ends it when it is next taken
//! (nerve_transport::sync): either way the program ends without saying it
//! stopped, which the manager counts as a failure, and its failure actions
//! start it again ([`crate::win::service::put`]), as they do a stop with an
//! error.
//!
//! With [`Events`] the service's start, its stop, a start that fails and a
//! crash also go to the Windows Event Log ([`event`],
//! [`crate::eventlog`]), where an owner looks first; the entries name the
//! log file, which has the rest.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, Once, OnceLock};

use windows_sys::Win32::Foundation::{
    ERROR_CALL_NOT_IMPLEMENTED, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT,
    ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR,
};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING,
    SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE,
    SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
    SetServiceStatus, StartServiceCtrlDispatcherW,
};

use crate::eventlog::Event;
use crate::win::sid::wide;

/// What the service runs.
pub type Body = Box<dyn FnOnce() -> Result<(), String> + Send>;

/// Where a service writes its entries in the Event Log.
pub struct Events {
    /// The source they come from ([`crate::eventlog`]), registered by the
    /// install with the program as the file of their text.
    pub source: &'static str,
    /// What the entries call the program: `Nerve node`.
    pub what: &'static str,
    /// Its log file, which every entry names.
    pub log: PathBuf,
}

static BODY: Mutex<Option<Body>> = Mutex::new(None);
/// The service's name, as the manager knows it.
static NAME: OnceLock<String> = OnceLock::new();
/// The handle the manager gave for this service's status, as a number:
/// set while the program runs as the service.
static STATUS: Mutex<Option<usize>> = Mutex::new(None);
/// Rung when the manager asks the service to stop.
static STOP: OnceLock<tokio::sync::Notify> = OnceLock::new();
/// Why the body ended with an error, for the caller of [`serve`].
static FAILED: Mutex<Option<String>> = Mutex::new(None);
/// Where the entries go; none writes no entry.
static EVENTS: OnceLock<Events> = OnceLock::new();
/// Set once the body said it runs: a body that fails before did not start.
static STARTED: AtomicBool = AtomicBool::new(false);
/// Why the manager asked the service to stop, for the Event Log.
static ASKED: Mutex<Option<&'static str>> = Mutex::new(None);

thread_local! {
    /// Set on the thread that runs the body: a panic there ends the
    /// program, one elsewhere (a task, which tokio catches) does not.
    static BODY_THREAD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn stop_bell() -> &'static tokio::sync::Notify {
    STOP.get_or_init(tokio::sync::Notify::new)
}

/// How [`serve`] ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Served {
    /// The service ran and stopped; with why when its body failed.
    Ran(Option<String>),
    /// The manager did not start this program, as from a terminal.
    NotAService,
}

/// Runs `body` as the service `name` when the service control manager
/// started this program, and returns once it stopped; with `events` its
/// start, stop and failures go to the Event Log too. Started any other way,
/// it runs nothing and says so.
pub fn serve(name: &str, body: Body, events: Option<Events>) -> Result<Served, String> {
    let _ = NAME.set(name.to_string());
    if let Some(e) = events {
        log_events(e);
    }
    *nerve_transport::sync::lock(&BODY) = Some(body);
    let mut wname = wide(name);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: wname.as_mut_ptr(),
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
        return Ok(Served::Ran(nerve_transport::sync::lock(&FAILED).take()));
    }
    let e = std::io::Error::last_os_error();
    nerve_transport::sync::lock(&BODY).take();
    if e.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT as i32) {
        return Ok(Served::NotAService);
    }
    Err(format!("cannot run as a service: {e}"))
}

/// Writes the service's entries to the Event Log as `events` says, each
/// panic among them ([`serve`] does this; the tests call it alone).
pub fn log_events(events: Events) {
    if EVENTS.set(events).is_ok() {
        watch_crashes();
    }
}

/// Whether this program runs as a service now.
pub fn is_service() -> bool {
    nerve_transport::sync::lock(&STATUS).is_some()
}

/// Tells the manager the service runs: called once its body has started.
/// Nothing where the program is no service.
pub fn running() {
    report(SERVICE_RUNNING, 0);
    if is_service() && !STARTED.swap(true, Ordering::SeqCst) {
        let _ = event(Event::Started, &format!("{} started.", the()));
    }
}

/// Waits until the manager asks the service to stop; never where the
/// program is no service.
pub async fn stop_requested() {
    stop_bell().notified().await;
}

/// `Nerve node`: what the entries call the program.
fn what() -> &'static str {
    EVENTS.get().map_or("service", |e| e.what)
}

/// `The Nerve node`, as an entry starts.
fn the() -> String {
    format!("The {}", what())
}

/// Writes an entry to the Windows Event Log (Application) as the source of
/// [`Events`], with where the log is at its end
/// (crate::win::event::report); nothing without [`Events`].
pub fn event(e: Event, text: &str) -> Result<(), String> {
    let Some(events) = EVENTS.get() else {
        return Ok(());
    };
    let text = format!("{text} Its log is {}.", events.log.display());
    crate::win::event::report(events.source, e.id(), e.is_error(), &text)
}

/// Writes each panic to the Event Log, then does what the hook before did.
/// A panic in the body's thread ends the program ([`run_body`]), and the
/// service's failure actions start it again; one elsewhere leaves the
/// program running, unless it left a lock poisoned: the next take of that
/// lock ends the program (nerve_transport::sync), and the failure actions
/// start it again as well. The log file is left alone here: the panic may
/// have come while its lock was held.
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
    let said = p
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
            "{} crashed (a panic{at}): {said}. The service ends; its recovery settings start it again.",
            the()
        )
    } else {
        format!(
            "A part of the {} panicked{at}: {said}. It runs on. If the panic left a lock poisoned, it ends when it next takes it, and its recovery settings start it again.",
            what()
        )
    }
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
        // A start or a stop takes a few seconds at most.
        dwWaitHint: 30_000,
    };
    // SAFETY: the handle the manager gave and a filled status.
    unsafe { SetServiceStatus(h as SERVICE_STATUS_HANDLE, &st) };
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut windows_sys::core::PWSTR) {
    let name = wide(NAME.get().map_or("", String::as_str));
    // SAFETY: a NUL-terminated name and a handler that lives as long as the
    // program.
    let h =
        unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control), std::ptr::null()) };
    if h.is_null() {
        return;
    }
    *nerve_transport::sync::lock(&STATUS) = Some(h as usize);
    report(SERVICE_START_PENDING, 0);
    let body = nerve_transport::sync::lock(&BODY).take();
    let code = run_body(body);
    report(SERVICE_STOPPED, code);
}

/// Runs the service's body and writes how it ended to the Event Log; the
/// service's exit code. A panic is caught here, after the hook wrote it
/// ([`watch_crashes`]): left to unwind into [`service_main`], which cannot
/// unwind, it would panic a second time and write a second crash. The
/// program then ends at once, as a crash does, so the service's failure
/// actions start it again. A lock the panic left poisoned is not taken again
/// on the way: the program aborts before anything here locks. Public for
/// the node's tests, whose program carries the entries' text.
#[doc(hidden)]
pub fn run_body(body: Option<Body>) -> u32 {
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
            let (kind, what) = if STARTED.load(Ordering::SeqCst) {
                (Event::Crashed, "stopped with an error")
            } else {
                (Event::NotStarted, "did not start")
            };
            let _ = event(kind, &format!("{} {what}: {e}.", the()));
            *nerve_transport::sync::lock(&FAILED) = Some(e);
            1
        }
        Ok(()) => {
            let why = nerve_transport::sync::lock(&ASKED).unwrap_or("its work ended");
            let _ = event(Event::Stopped, &format!("{} stopped: {why}.", the()));
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
            // A permit is kept when the body does not wait yet.
            stop_bell().notify_one();
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}
