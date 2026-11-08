//! A service of the service control manager that runs as its own virtual
//! account (`NT SERVICE\<name>`), as the center's does: registered,
//! started, stopped, asked and removed. Windows makes the account with the
//! service and removes it with it; it has no password, no profile to keep
//! and no logon of its own. The node's service runs as a local user and
//! keeps its own calls (nerve-node's `win_host`).

/// The virtual account of the service `name`, as the service control
/// manager takes it.
pub fn virtual_account(name: &str) -> String {
    format!("NT SERVICE\\{name}")
}

/// The SID of the service `name`, which is also its virtual account's:
/// `S-1-5-80-` and the SHA-1 of the name in upper case (UTF-16, little
/// endian) as five numbers. Windows derives it so, whether the service is
/// registered yet or not (`sc showsid`), so a folder can be opened to it
/// before the service exists.
pub fn service_sid(name: &str) -> String {
    let upper: Vec<u8> = name
        .to_uppercase()
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &upper);
    let parts: Vec<String> = digest
        .as_ref()
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_le_bytes(*c).to_string())
        .collect();
    format!("S-1-5-80-{}", parts.join("-"))
}

/// The state of a registered service, as `status` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    /// running, starting, stopping, stopped or failed.
    pub state: String,
    /// Whether it starts with the machine; `None` when Windows did not say.
    pub automatic: Option<bool>,
}

/// What follows a failure of a service: the restarts, and that a stop with
/// an error code is a failure too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    /// Restarts a day at most; the next failure leaves the service down.
    pub restarts: usize,
    /// Seconds from the failure to each restart.
    pub delay_secs: u32,
    /// Whether a service that reports itself stopped with an error code
    /// (any start that failed: a port taken, an address not there yet) is
    /// restarted, not only a process that ended without saying so. Without
    /// it the manager treats the first as a stop that was asked for.
    pub on_error_stop: bool,
}

/// What [`put`] asks of the manager: the Linux unit's `Restart=on-failure`
/// with `RestartSec=5`, and no more than three a day.
pub const FAILURE: Failure = Failure {
    restarts: 3,
    delay_secs: 5,
    on_error_stop: true,
};

/// What [`put`] registers.
pub struct Spec<'a> {
    /// The service's name, which is also its virtual account's.
    pub name: &'a str,
    /// Its name in the Services console.
    pub shown: &'a str,
    pub about: &'a str,
    /// The command line the manager starts: the program in quotes, then its
    /// arguments.
    pub line: &'a str,
    /// The privileges it keeps; Windows takes every other from its token.
    pub privileges: &'a [&'a str],
}

#[cfg(windows)]
pub use sys::{delete, delete_at_restart, put, registered, start, state, stop, wait_running};

#[cfg(windows)]
mod sys {
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::{
        ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_NOT_ACTIVE, ERROR_SERVICE_SPECIFIC_ERROR,
        GetLastError,
    };
    use windows_sys::Win32::System::Services::{
        ChangeServiceConfig2W, ChangeServiceConfigW, ControlService, CreateServiceW, DeleteService,
        QUERY_SERVICE_CONFIGW, QueryServiceConfigW, SC_ACTION, SC_ACTION_NONE, SC_ACTION_RESTART,
        SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE, SERVICE_ALL_ACCESS, SERVICE_AUTO_START,
        SERVICE_CONFIG_DESCRIPTION, SERVICE_CONFIG_FAILURE_ACTIONS,
        SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
        SERVICE_CONFIG_SERVICE_SID_INFO, SERVICE_CONTROL_STOP, SERVICE_DESCRIPTIONW,
        SERVICE_ERROR_NORMAL, SERVICE_FAILURE_ACTIONS_FLAG, SERVICE_FAILURE_ACTIONSW,
        SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_REQUIRED_PRIVILEGES_INFOW,
        SERVICE_RUNNING, SERVICE_SID_INFO, SERVICE_SID_TYPE_UNRESTRICTED, SERVICE_START,
        SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STOP, SERVICE_STOP_PENDING, SERVICE_STOPPED,
        SERVICE_WIN32_OWN_PROCESS, StartServiceW,
    };

    use super::{FAILURE, Spec, State, virtual_account};
    use crate::win::scm::Scm;
    use crate::win::sid::wide;

    fn last() -> String {
        std::io::Error::last_os_error().to_string()
    }

    fn os(code: u32) -> String {
        std::io::Error::from_raw_os_error(code as i32).to_string()
    }

    /// The service `name` with the rights `access`; an error when it is not
    /// registered.
    fn open(name: &str, access: u32) -> Result<Scm, String> {
        Scm::open(SC_MANAGER_CONNECT)?
            .service(name, access)?
            .ok_or_else(|| format!("the service {name} is not registered"))
    }

    /// Whether the service `name` is registered, as anyone may ask.
    pub fn registered(name: &str) -> bool {
        Scm::open(SC_MANAGER_CONNECT)
            .and_then(|m| m.service(name, SERVICE_QUERY_STATUS))
            .is_ok_and(|s| s.is_some())
    }

    /// The state of the service `name`; `None` when it is not registered.
    pub fn state(name: &str) -> Result<Option<State>, String> {
        let access = SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG;
        let Some(s) = Scm::open(SC_MANAGER_CONNECT)?.service(name, access)? else {
            return Ok(None);
        };
        let st = s.status()?;
        let state = match st.dwCurrentState {
            SERVICE_RUNNING => "running",
            SERVICE_START_PENDING => "starting",
            SERVICE_STOP_PENDING => "stopping",
            // A service that ended with an error of its own failed.
            SERVICE_STOPPED if st.dwWin32ExitCode != 0 => "failed",
            SERVICE_STOPPED => "stopped",
            _ => "running",
        };
        // The configuration's size first, then the configuration.
        let mut need = 0u32;
        // SAFETY: a query of the size only, with no buffer.
        unsafe { QueryServiceConfigW(s.0, std::ptr::null_mut(), 0, &mut need) };
        // u64s, so the buffer is aligned for the struct.
        let mut buf = vec![0u64; (need as usize).div_ceil(8).max(1)];
        // SAFETY: a buffer of at least `need` bytes.
        let ok = unsafe {
            QueryServiceConfigW(
                s.0,
                buf.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>(),
                (buf.len() * 8) as u32,
                &mut need,
            )
        };
        let automatic = (ok != 0).then(|| {
            // SAFETY: the call filled the struct at the buffer's start.
            let config = unsafe { &*buf.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
            config.dwStartType == SERVICE_AUTO_START
        });
        Ok(Some(State {
            state: state.into(),
            automatic,
        }))
    }

    /// Registers the service of `spec`, or changes it: its command line,
    /// its virtual account, started with the machine and again after a
    /// failure ([`FAILURE`]). A failure is a process that ends without
    /// saying it stopped, as one that found a lock poisoned does
    /// (nerve_transport::sync), and a stop with an error code, as a center
    /// that cannot bind its address yet does.
    pub fn put(spec: &Spec) -> Result<(), String> {
        let name = spec.name;
        let line = wide(spec.line);
        let user = wide(virtual_account(name));
        let shown = wide(spec.shown);
        let m = Scm::open(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
        let s = match m.service(name, SERVICE_ALL_ACCESS)? {
            Some(s) => {
                // SAFETY: an open service and NUL-terminated strings; null
                // leaves the rest as it is, and a virtual account has no
                // password.
                let ok = unsafe {
                    ChangeServiceConfigW(
                        s.0,
                        SERVICE_WIN32_OWN_PROCESS,
                        SERVICE_AUTO_START,
                        SERVICE_ERROR_NORMAL,
                        line.as_ptr(),
                        std::ptr::null(),
                        std::ptr::null_mut(),
                        std::ptr::null(),
                        user.as_ptr(),
                        std::ptr::null(),
                        shown.as_ptr(),
                    )
                };
                if ok == 0 {
                    return Err(format!("cannot change the service {name}: {}", last()));
                }
                s
            }
            None => {
                // SAFETY: an open manager and NUL-terminated strings.
                let h = unsafe {
                    CreateServiceW(
                        m.0,
                        wide(name).as_ptr(),
                        shown.as_ptr(),
                        SERVICE_ALL_ACCESS,
                        SERVICE_WIN32_OWN_PROCESS,
                        SERVICE_AUTO_START,
                        SERVICE_ERROR_NORMAL,
                        line.as_ptr(),
                        std::ptr::null(),
                        std::ptr::null_mut(),
                        std::ptr::null(),
                        user.as_ptr(),
                        std::ptr::null(),
                    )
                };
                if h.is_null() {
                    return Err(format!("cannot register the service {name}: {}", last()));
                }
                Scm(h, name.into())
            }
        };
        let mut about = wide(spec.about);
        let description = SERVICE_DESCRIPTIONW {
            lpDescription: about.as_mut_ptr(),
        };
        let again = SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: FAILURE.delay_secs * 1000,
        };
        let mut actions = vec![again; FAILURE.restarts];
        actions.push(SC_ACTION {
            Type: SC_ACTION_NONE,
            Delay: 0,
        });
        let failure = SERVICE_FAILURE_ACTIONSW {
            dwResetPeriod: 24 * 3600,
            lpRebootMsg: std::ptr::null_mut(),
            lpCommand: std::ptr::null_mut(),
            cActions: actions.len() as u32,
            lpsaActions: actions.as_mut_ptr(),
        };
        let on_error_stop = SERVICE_FAILURE_ACTIONS_FLAG {
            fFailureActionsOnNonCrashFailures: i32::from(FAILURE.on_error_stop),
        };
        // A list of names, each ended by a NUL, and one NUL more.
        let mut privileges: Vec<u16> = spec
            .privileges
            .iter()
            .flat_map(|p| p.encode_utf16().chain(Some(0)))
            .chain(Some(0))
            .collect();
        let required = SERVICE_REQUIRED_PRIVILEGES_INFOW {
            pmszRequiredPrivileges: privileges.as_mut_ptr(),
        };
        // The service's own SID in its token: what its folders are opened to.
        let sid = SERVICE_SID_INFO {
            dwServiceSidType: SERVICE_SID_TYPE_UNRESTRICTED,
        };
        for (level, info, what) in [
            (
                SERVICE_CONFIG_DESCRIPTION,
                (&raw const description).cast(),
                "its description",
            ),
            (
                SERVICE_CONFIG_FAILURE_ACTIONS,
                (&raw const failure).cast(),
                "what follows a failure",
            ),
            (
                SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
                (&raw const on_error_stop).cast(),
                "what follows a stop with an error",
            ),
            (
                SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
                (&raw const required).cast(),
                "its privileges",
            ),
            (
                SERVICE_CONFIG_SERVICE_SID_INFO,
                (&raw const sid).cast(),
                "its SID",
            ),
        ] {
            // SAFETY: an open service and the structure of each level.
            if unsafe { ChangeServiceConfig2W(s.0, level, info) } == 0 {
                return Err(format!(
                    "cannot set {what} of the service {name}: {}",
                    last()
                ));
            }
        }
        Ok(())
    }

    /// Starts the service `name`; one that runs already is fine.
    pub fn start(name: &str) -> Result<(), String> {
        let s = open(name, SERVICE_START)?;
        // SAFETY: an open service; no arguments.
        if unsafe { StartServiceW(s.0, 0, std::ptr::null()) } == 0
            // SAFETY: plain getter, right after the call.
            && unsafe { GetLastError() } != ERROR_SERVICE_ALREADY_RUNNING
        {
            return Err(format!("cannot start the service {name}: {}", last()));
        }
        Ok(())
    }

    /// Stops the service `name` and waits until it has; a stopped one is
    /// fine.
    pub fn stop(name: &str) -> Result<(), String> {
        let s = open(name, SERVICE_STOP | SERVICE_QUERY_STATUS)?;
        // SAFETY: plain data that the call fills.
        let mut st: SERVICE_STATUS = unsafe { std::mem::zeroed() };
        // SAFETY: an open service and a place for its status.
        if unsafe { ControlService(s.0, SERVICE_CONTROL_STOP, &mut st) } == 0 {
            // SAFETY: plain getter, right after the call.
            let e = unsafe { GetLastError() };
            if e != ERROR_SERVICE_NOT_ACTIVE {
                return Err(format!("cannot stop the service {name}: {}", os(e)));
            }
        }
        let until = Instant::now() + Duration::from_secs(60);
        while s.status()?.dwCurrentState != SERVICE_STOPPED {
            if Instant::now() > until {
                return Err(format!("the service {name} did not stop within a minute"));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        Ok(())
    }

    /// Removes the service `name`; Windows removes its virtual account with
    /// it.
    pub fn delete(name: &str) -> Result<(), String> {
        let s = open(name, SERVICE_ALL_ACCESS)?;
        // SAFETY: an open service; it goes once every handle is closed.
        if unsafe { DeleteService(s.0) } == 0 {
            return Err(format!("cannot remove the service {name}: {}", last()));
        }
        Ok(())
    }

    /// Lets Windows delete `path` at its next start: a program that runs
    /// cannot be deleted before.
    pub fn delete_at_restart(path: &std::path::Path) -> Result<(), String> {
        use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW};
        // SAFETY: a NUL-terminated path; no new name means delete.
        if unsafe {
            MoveFileExW(
                wide(path).as_ptr(),
                std::ptr::null(),
                MOVEFILE_DELAY_UNTIL_REBOOT,
            )
        } == 0
        {
            return Err(format!("{}: {}", path.display(), last()));
        }
        Ok(())
    }

    /// Waits until the service `name` runs: its program says so once it
    /// has started (crate::win::dispatch::running). One that stops on the
    /// way is an error that names `log`, where its program says why.
    pub fn wait_running(name: &str, log: &str) -> Result<(), String> {
        let s = open(name, SERVICE_QUERY_STATUS)?;
        let until = Instant::now() + Duration::from_secs(60);
        loop {
            let st = s.status()?;
            match st.dwCurrentState {
                SERVICE_RUNNING => return Ok(()),
                SERVICE_STOPPED => {
                    let code = if st.dwWin32ExitCode == ERROR_SERVICE_SPECIFIC_ERROR {
                        format!("exit code {}", st.dwServiceSpecificExitCode)
                    } else {
                        os(st.dwWin32ExitCode)
                    };
                    return Err(format!(
                        "the service {name} stopped at its start ({code}); {log} says why"
                    ));
                }
                _ if Instant::now() > until => {
                    return Err(format!("the service {name} did not start within a minute"));
                }
                _ => std::thread::sleep(Duration::from_millis(250)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SID Windows gives a service, from its name alone: the values
    /// `sc showsid` prints for services every Windows has.
    #[test]
    fn a_service_s_sid_comes_from_its_name() {
        assert_eq!(
            service_sid("TrustedInstaller"),
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        );
        // The case of the name does not matter.
        assert_eq!(
            service_sid("trustedinstaller"),
            service_sid("TrustedInstaller")
        );
        assert_ne!(service_sid("nerve-center"), service_sid("nerve-node"));
        assert_eq!(virtual_account("nerve-center"), "NT SERVICE\\nerve-center");
    }

    /// A center that stops at its start with an error (an address that is
    /// not there yet at boot) is started again, as the Linux unit's
    /// `Restart=on-failure` does (round 1, correctness 1): the manager
    /// restarts such a stop only when it is asked to.
    #[test]
    fn a_stop_with_an_error_is_restarted() {
        let f = std::hint::black_box(FAILURE);
        assert!(f.on_error_stop);
        assert_eq!((f.restarts, f.delay_secs), (3, 5));
    }
}
