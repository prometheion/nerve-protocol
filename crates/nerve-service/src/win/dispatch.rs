//! A program under the Windows service control manager, as the center's
//! service runs: the program hands its main thread to the manager, which
//! runs the program's body on a thread of its own and asks it to stop. The
//! body says it runs once it has started ([`running`]), so a service that
//! runs is a program that took its settings; one that fails stops with
//! exit code 1. A panic in the body ends the program at once, and a lock a
//! panic poisoned ends it when it is next taken (nerve_transport::sync):
//! either way the program ends without saying it stopped, which the
//! manager counts as a failure, and its failure actions start it again
//! ([`crate::win::service::put`]). The node keeps its own dispatcher, which
//! also writes to the Event Log (nerve-node's `win_service`).

use std::sync::{Mutex, OnceLock};

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

use crate::win::sid::wide;

/// What the service runs.
pub type Body = Box<dyn FnOnce() -> Result<(), String> + Send>;

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
/// started this program, and returns once it stopped. Started any other
/// way, it runs nothing and says so.
pub fn serve(name: &str, body: Body) -> Result<Served, String> {
    let _ = NAME.set(name.to_string());
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

/// Whether this program runs as a service now.
pub fn is_service() -> bool {
    nerve_transport::sync::lock(&STATUS).is_some()
}

/// Tells the manager the service runs: called once its body has started.
/// Nothing where the program is no service.
pub fn running() {
    report(SERVICE_RUNNING, 0);
}

/// Waits until the manager asks the service to stop; never where the
/// program is no service.
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
    // A panic here cannot unwind out of this function: the program ends at
    // once, without saying it stopped, so the failure actions start it
    // again.
    let ended = match body {
        Some(b) => std::panic::catch_unwind(std::panic::AssertUnwindSafe(b)),
        None => Ok(Ok(())),
    };
    let Ok(ended) = ended else {
        std::process::abort();
    };
    let code = match ended {
        Ok(()) => 0,
        Err(e) => {
            *nerve_transport::sync::lock(&FAILED) = Some(e);
            1
        }
    };
    report(SERVICE_STOPPED, code);
}

unsafe extern "system" fn control(
    control: u32,
    _event: u32,
    _data: *mut core::ffi::c_void,
    _context: *mut core::ffi::c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            report(SERVICE_STOP_PENDING, 0);
            // A permit is kept when the body does not wait yet.
            stop_bell().notify_one();
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}
