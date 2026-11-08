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

/// The argument of the helper that makes or removes an AppContainer's
/// profile as the account it runs as: `__container-profile ready <name>`
/// or `__container-profile remove <name>`. Hidden from `--help`.
pub const CONTAINER_ARG: &str = "__container-profile";

/// The helper of [`CONTAINER_ARG`]; its exit code.
pub fn helper_main() -> i32 {
    let args: Vec<String> = std::env::args().skip(2).collect();
    let r = match args.as_slice() {
        [what, name] if what == "ready" => nerve_sandbox::appcontainer::ready(name).map(drop),
        [what, name] if what == "remove" => nerve_sandbox::appcontainer::remove_profile(name),
        _ => Err(std::io::Error::other(format!(
            "usage: {CONTAINER_ARG} ready|remove <name>"
        ))),
    };
    match r {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("nerve-node: {e}");
            1
        }
    }
}

/// The containers whose profile this node made as `nerve-run` since it
/// started ([`ready_as`]).
static MADE: Mutex<std::collections::BTreeSet<String>> =
    Mutex::new(std::collections::BTreeSet::new());

/// Runs the helper of [`CONTAINER_ARG`] with `what` for the container
/// `name` as `nerve-run`, which alone may write its profile, with `exe`,
/// the node's program.
fn as_run(exe: &std::path::Path, what: &str, name: &str) -> Result<(), String> {
    let t = crate::win_user::run_logon()?;
    let line = crate::exec::windows_command_line(
        &exe.display().to_string(),
        &[CONTAINER_ARG.to_string(), what.into(), name.into()],
    );
    let (code, out) =
        crate::win_user::run_capture(&t, &line, std::time::Duration::from_secs(60), None)
            .map_err(|e| format!("the AppContainer {name} as nerve-run: {e}"))?;
    if code != 0 {
        return Err(format!(
            "the AppContainer {name} as nerve-run: {}",
            String::from_utf8_lossy(&out).trim()
        ));
    }
    Ok(())
}

/// Makes the profile of the container `name` in `nerve-run`'s profile, with
/// its home (nerve_sandbox::appcontainer::ready), once while the node runs:
/// a command's shim makes it again where it went meanwhile.
pub fn ready_as(exe: &std::path::Path, name: &str) -> Result<(), String> {
    if nerve_transport::sync::lock(&MADE).contains(name) {
        return Ok(());
    }
    as_run(exe, "ready", name)?;
    nerve_transport::sync::lock(&MADE).insert(name.to_string());
    Ok(())
}

/// Removes the profile of the container `name` from `nerve-run`'s profile.
pub fn remove_as(exe: &std::path::Path, name: &str) -> Result<(), String> {
    nerve_transport::sync::lock(&MADE).remove(name);
    as_run(exe, "remove", name)
}
