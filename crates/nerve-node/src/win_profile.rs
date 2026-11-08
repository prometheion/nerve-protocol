//! The service that keeps the command account's profile loaded on Windows
//! ([`crate::winsvc::PROFILE_SERVICE`]). Windows makes an AppContainer's
//! profile, and starts a process in one, only for an account whose registry
//! is loaded. Only an administrator or SYSTEM may load it, and the node runs
//! as neither; the service control manager loads it for a service of that
//! account. So `install` registers this service as `nerve-run`: the node's
//! own program, started with [`PROFILE_ARG`], which does nothing until the
//! manager stops it. The node's service depends on it, so the manager starts
//! it first. It holds no handle of the node's and takes no request.

use std::sync::{Condvar, Mutex};

use windows_sys::Win32::Foundation::NO_ERROR;
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_STATUS,
    SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW,
    SERVICE_WIN32_OWN_PROCESS, SetServiceStatus, StartServiceCtrlDispatcherW,
};

use crate::win_user::wide;
use crate::winsvc::PROFILE_SERVICE;

/// The argument the service is registered with. Hidden from `--help`.
pub const PROFILE_ARG: &str = "__profile-service";

/// Set once the manager asks the service to stop.
static STOP: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());
/// The handle the manager gave for the status, as a number.
static STATUS: Mutex<Option<usize>> = Mutex::new(None);

/// Runs the service; returns when the manager stopped it, or at once with 1
/// when no manager started this program.
pub fn main() -> i32 {
    let mut name = wide(PROFILE_SERVICE);
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
    // SAFETY: a table ended by an empty entry, alive until the call returns.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        eprintln!(
            "nerve-node: {PROFILE_ARG} runs only as the service {PROFILE_SERVICE}, which Nerve's installer registers"
        );
        return 1;
    }
    0
}

fn report(state: SERVICE_STATUS_CURRENT_STATE) {
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
        dwWin32ExitCode: NO_ERROR,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    // SAFETY: the handle the manager gave and a filled status.
    unsafe { SetServiceStatus(h as SERVICE_STATUS_HANDLE, &st) };
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut windows_sys::core::PWSTR) {
    let name = wide(PROFILE_SERVICE);
    // SAFETY: a NUL-terminated name and a handler that lives as long as the
    // program.
    let h =
        unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control), std::ptr::null()) };
    if h.is_null() {
        return;
    }
    *nerve_transport::sync::lock(&STATUS) = Some(h as usize);
    report(SERVICE_RUNNING);
    let (stopped, bell) = &STOP;
    let mut s = nerve_transport::sync::lock(stopped);
    while !*s {
        s = bell.wait(s).unwrap_or_else(|e| e.into_inner());
    }
    drop(s);
    report(SERVICE_STOPPED);
}

unsafe extern "system" fn control(
    control: u32,
    _event: u32,
    _data: *mut core::ffi::c_void,
    _context: *mut core::ffi::c_void,
) -> u32 {
    if control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN {
        let (stopped, bell) = &STOP;
        *nerve_transport::sync::lock(stopped) = true;
        bell.notify_all();
    }
    NO_ERROR
}
