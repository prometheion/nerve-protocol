//! A service of the service control manager: registered, started, stopped,
//! asked and removed, for the node's and the center's alike. The center's
//! runs as its own virtual account (`NT SERVICE\<name>`), which Windows
//! makes with the service and removes with it: no password, no profile to
//! keep and no logon of its own. The node's services run as local accounts
//! of their own, whose passwords the manager keeps.

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
    /// Seconds from a failure to the restart, for the first, second, ...
    /// failure; the manager repeats the last for every later one until the
    /// failures are counted afresh (a day without one), so the service is
    /// never left down for good.
    pub delays_secs: &'static [u32],
    /// Whether a service that reports itself stopped with an error code
    /// (any start that failed: a port taken, an address not there yet) is
    /// restarted, not only a process that ended without saying so. Without
    /// it the manager treats the first as a stop that was asked for.
    pub on_error_stop: bool,
}

/// What [`put`] asks of the manager: the Linux unit's `Restart=on-failure`
/// with `RestartSec=5`, then a minute between tries, as long as it takes
/// (a VPN address that comes 30 seconds after boot is waited for).
pub const FAILURE: Failure = Failure {
    delays_secs: &[5, 5, 60],
    on_error_stop: true,
};

/// What the manager is told of a service besides its program and account:
/// what [`put`] registers, and what `update` gives the service again when a
/// new program names other settings (the program says them on
/// `service-files`, [`settings_text`]), as Linux writes the new unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// The privileges it keeps; Windows takes every other from its token.
    pub privileges: Vec<String>,
    /// The services it needs running first.
    pub after: Vec<String>,
    /// Seconds from a failure to the restart ([`Failure::delays_secs`]).
    pub restart_secs: Vec<u32>,
    /// [`Failure::on_error_stop`].
    pub restart_on_error_stop: bool,
    /// Who may start, stop and ask it, as SDDL; `None` leaves what Windows
    /// gave it.
    pub dacl: Option<String>,
}

/// The names of [`Settings`] in what `service-files` prints.
const SETTINGS: [&str; 5] = [
    "privileges",
    "after",
    "restart_secs",
    "restart_on_error_stop",
    "dacl",
];

impl Settings {
    /// A service's settings with the restarts of [`FAILURE`].
    pub fn new(privileges: &[&str], after: &[&str], dacl: Option<String>) -> Settings {
        Settings {
            privileges: privileges.iter().map(|p| p.to_string()).collect(),
            after: after.iter().map(|a| a.to_string()).collect(),
            restart_secs: FAILURE.delays_secs.to_vec(),
            restart_on_error_stop: FAILURE.on_error_stop,
            dacl,
        }
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "privileges": self.privileges,
            "after": self.after,
            "restart_secs": self.restart_secs,
            "restart_on_error_stop": self.restart_on_error_stop,
            "dacl": self.dacl,
        })
    }

    /// The settings of `v`, and the names in it this program does not know
    /// (a later program's): those it cannot give the service.
    fn of(v: &serde_json::Value) -> Result<(Settings, Vec<String>), String> {
        let map = v.as_object().ok_or("not an object")?;
        let names = |k: &str| -> Result<Vec<String>, String> {
            map.get(k)
                .and_then(|v| v.as_array())
                .ok_or_else(|| format!("{k}: not a list"))?
                .iter()
                .map(|n| {
                    n.as_str()
                        .map(String::from)
                        .ok_or(format!("{k}: not names"))
                })
                .collect()
        };
        let restart_secs = map
            .get("restart_secs")
            .and_then(|v| v.as_array())
            .ok_or("restart_secs: not a list")?
            .iter()
            .map(|n| {
                n.as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or("restart_secs: not seconds")
            })
            .collect::<Result<Vec<u32>, _>>()?;
        let restart_on_error_stop = map
            .get("restart_on_error_stop")
            .and_then(|v| v.as_bool())
            .ok_or("restart_on_error_stop: not true or false")?;
        let dacl = match map.get("dacl") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(d)) => Some(d.clone()),
            Some(_) => return Err("dacl: neither a text nor null".into()),
        };
        let unknown = map
            .keys()
            .filter(|k| !SETTINGS.contains(&k.as_str()))
            .cloned()
            .collect();
        Ok((
            Settings {
                privileges: names("privileges")?,
                after: names("after")?,
                restart_secs,
                restart_on_error_stop,
                dacl,
            },
            unknown,
        ))
    }
}

/// The settings of services, by name.
pub type Named = Vec<(String, Settings)>;

/// What a Windows program prints on `service-files`: the settings of each
/// service it installs, by name.
pub fn settings_text(services: &[(&str, Settings)]) -> String {
    let map: serde_json::Map<String, serde_json::Value> = services
        .iter()
        .map(|(name, s)| (name.to_string(), s.json()))
        .collect();
    serde_json::Value::Object(map).to_string()
}

/// The settings `said` names (what `service-files` printed) of the services
/// `known`; and what it names that this program cannot give: another
/// service, or a setting it does not know.
pub fn settings_from(said: &str, known: &[&str]) -> Result<(Named, Vec<String>), String> {
    let v: serde_json::Value = serde_json::from_str(said).map_err(|e| format!("not JSON: {e}"))?;
    let map = v.as_object().ok_or("not an object")?;
    let mut services = Vec::new();
    let mut unknown = Vec::new();
    for (name, s) in map {
        if !known.contains(&name.as_str()) {
            unknown.push(name.clone());
            continue;
        }
        let (s, new) = Settings::of(s).map_err(|e| format!("{name}: {e}"))?;
        unknown.extend(new.into_iter().map(|k| format!("{name}: {k}")));
        services.push((name.clone(), s));
    }
    Ok((services, unknown))
}

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
    /// The local account it runs as and that account's password; `None`:
    /// its own virtual account, with the service's SID in its token.
    pub logon: Option<(&'a str, &'a str)>,
    pub settings: &'a Settings,
}

#[cfg(windows)]
pub use sys::{
    configure, delete, delete_at_restart, put, registered, set_dacl, start, state, stop,
    wait_running,
};

#[cfg(windows)]
mod sys {
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::{
        ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_NOT_ACTIVE, ERROR_SERVICE_SPECIFIC_ERROR,
        GetLastError,
    };
    use windows_sys::Win32::System::Services::{
        ChangeServiceConfig2W, ChangeServiceConfigW, ControlService, CreateServiceW, DeleteService,
        QUERY_SERVICE_CONFIGW, QueryServiceConfigW, SC_ACTION, SC_ACTION_RESTART,
        SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE, SERVICE_ALL_ACCESS, SERVICE_AUTO_START,
        SERVICE_CONFIG_DESCRIPTION, SERVICE_CONFIG_FAILURE_ACTIONS,
        SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
        SERVICE_CONFIG_SERVICE_SID_INFO, SERVICE_CONTROL_STOP, SERVICE_DESCRIPTIONW,
        SERVICE_ERROR_NORMAL, SERVICE_FAILURE_ACTIONS_FLAG, SERVICE_FAILURE_ACTIONSW,
        SERVICE_NO_CHANGE, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
        SERVICE_REQUIRED_PRIVILEGES_INFOW, SERVICE_RUNNING, SERVICE_SID_INFO,
        SERVICE_SID_TYPE_UNRESTRICTED, SERVICE_START, SERVICE_START_PENDING, SERVICE_STATUS,
        SERVICE_STOP, SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS,
        StartServiceW,
    };

    use super::{Settings, Spec, State, virtual_account};
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

    /// A list of names as the manager takes it: each ended by a NUL, and
    /// one NUL more; an empty one is two NULs.
    fn names(list: &[String]) -> Vec<u16> {
        let mut out: Vec<u16> = list
            .iter()
            .flat_map(|n| n.encode_utf16().chain(Some(0)))
            .collect();
        if out.is_empty() {
            out.push(0);
        }
        out.push(0);
        out
    }

    /// Registers the service of `spec`, or changes it: its command line,
    /// its account, started with the machine and again after a failure
    /// ([`FAILURE`]), with its settings ([`configure`]). A failure is a
    /// process that ends without saying it stopped, as one that found a
    /// lock poisoned does (nerve_transport::sync), and a stop with an error
    /// code, as a center that cannot bind its address yet does, or a node
    /// whose folders are not the administrators'.
    pub fn put(spec: &Spec) -> Result<(), String> {
        let name = spec.name;
        let line = wide(spec.line);
        let (user, password) = match spec.logon {
            Some((account, password)) => (wide(format!(".\\{account}")), Some(wide(password))),
            None => (wide(virtual_account(name)), None),
        };
        // A virtual account has no password.
        let password = password.as_ref().map_or(std::ptr::null(), |p| p.as_ptr());
        let shown = wide(spec.shown);
        let after = names(&spec.settings.after);
        let m = Scm::open(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
        let s = match m.service(name, SERVICE_ALL_ACCESS)? {
            Some(s) => {
                // SAFETY: an open service and NUL-terminated strings; null
                // leaves the rest as it is.
                let ok = unsafe {
                    ChangeServiceConfigW(
                        s.0,
                        SERVICE_WIN32_OWN_PROCESS,
                        SERVICE_AUTO_START,
                        SERVICE_ERROR_NORMAL,
                        line.as_ptr(),
                        std::ptr::null(),
                        std::ptr::null_mut(),
                        after.as_ptr(),
                        user.as_ptr(),
                        password,
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
                        after.as_ptr(),
                        user.as_ptr(),
                        password,
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
        change(
            &s,
            SERVICE_CONFIG_DESCRIPTION,
            (&raw const description).cast(),
            "its description",
        )?;
        if spec.logon.is_none() {
            // The service's own SID in its token: what its folders are
            // opened to.
            let sid = SERVICE_SID_INFO {
                dwServiceSidType: SERVICE_SID_TYPE_UNRESTRICTED,
            };
            change(
                &s,
                SERVICE_CONFIG_SERVICE_SID_INFO,
                (&raw const sid).cast(),
                "its SID",
            )?;
        }
        settle(&s, spec.settings)
    }

    /// One part of the configuration of the open service `s`.
    fn change(
        s: &Scm,
        level: u32,
        info: *const core::ffi::c_void,
        what: &str,
    ) -> Result<(), String> {
        // SAFETY: an open service and the structure of the level.
        if unsafe { ChangeServiceConfig2W(s.0, level, info) } == 0 {
            return Err(format!(
                "cannot set {what} of the service {}: {}",
                s.1,
                last()
            ));
        }
        Ok(())
    }

    /// Gives the registered service `name` the settings `settings`, and
    /// leaves its program and account as they are: what `update` does when
    /// the new program names other settings, and puts back with the old
    /// program.
    pub fn configure(name: &str, settings: &Settings) -> Result<(), String> {
        let s = open(name, SERVICE_ALL_ACCESS)?;
        let after = names(&settings.after);
        // SAFETY: an open service and a NUL-terminated list; the rest is
        // left as it is.
        let ok = unsafe {
            ChangeServiceConfigW(
                s.0,
                SERVICE_NO_CHANGE,
                SERVICE_NO_CHANGE,
                SERVICE_NO_CHANGE,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut(),
                after.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if ok == 0 {
            return Err(format!("cannot change the service {name}: {}", last()));
        }
        settle(&s, settings)
    }

    /// The settings but the dependencies, which go with the configuration.
    fn settle(s: &Scm, settings: &Settings) -> Result<(), String> {
        let mut actions: Vec<SC_ACTION> = settings
            .restart_secs
            .iter()
            .map(|secs| SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: secs * 1000,
            })
            .collect();
        let failure = SERVICE_FAILURE_ACTIONSW {
            dwResetPeriod: 24 * 3600,
            lpRebootMsg: std::ptr::null_mut(),
            lpCommand: std::ptr::null_mut(),
            cActions: actions.len() as u32,
            lpsaActions: actions.as_mut_ptr(),
        };
        let on_error_stop = SERVICE_FAILURE_ACTIONS_FLAG {
            fFailureActionsOnNonCrashFailures: i32::from(settings.restart_on_error_stop),
        };
        let mut privileges = names(&settings.privileges);
        let required = SERVICE_REQUIRED_PRIVILEGES_INFOW {
            pmszRequiredPrivileges: privileges.as_mut_ptr(),
        };
        change(
            s,
            SERVICE_CONFIG_FAILURE_ACTIONS,
            (&raw const failure).cast(),
            "what follows a failure",
        )?;
        change(
            s,
            SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
            (&raw const on_error_stop).cast(),
            "what follows a stop with an error",
        )?;
        change(
            s,
            SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
            (&raw const required).cast(),
            "its privileges",
        )?;
        if let Some(dacl) = &settings.dacl {
            dacl_of_open(s, dacl)?;
        }
        Ok(())
    }

    /// Gives the service `name` the DACL `sddl`: who may start, stop and
    /// ask it.
    pub fn set_dacl(name: &str, sddl: &str) -> Result<(), String> {
        dacl_of_open(&open(name, SERVICE_ALL_ACCESS)?, sddl)
    }

    fn dacl_of_open(s: &Scm, sddl: &str) -> Result<(), String> {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
        use windows_sys::Win32::System::Services::SetServiceObjectSecurity;
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: a NUL-terminated SDDL string; the descriptor is freed
        // below.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(sddl).as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(format!(
                "cannot make the DACL of the service {}: {}",
                s.1,
                last()
            ));
        }
        // SAFETY: an open service and a valid descriptor.
        let ok = unsafe { SetServiceObjectSecurity(s.0, DACL_SECURITY_INFORMATION, sd) };
        let e = last();
        // SAFETY: the descriptor from the conversion, freed once.
        unsafe { LocalFree(sd) };
        if ok == 0 {
            return Err(format!("cannot set the DACL of the service {}: {e}", s.1));
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
        // The last action is repeated for every later failure: it must be
        // a restart, or three early failures leave the service down for the
        // day (round 2, correctness 3).
        assert_eq!(f.delays_secs, &[5, 5, 60]);
        assert!(f.delays_secs.iter().all(|s| *s > 0));
    }

    /// What a program says on `service-files` comes back as it said it,
    /// with the restarts of [`FAILURE`]; a service or a setting this
    /// program does not know is named, not given (node-5).
    #[test]
    fn the_settings_a_program_says_come_back() {
        let node = Settings::new(
            &["SeChangeNotifyPrivilege"],
            &["nerve-run-profile"],
            Some("D:(A;;GA;;;SY)".into()),
        );
        assert_eq!(node.restart_secs, [5, 5, 60]);
        assert!(node.restart_on_error_stop);
        let profile = Settings::new(&["SeChangeNotifyPrivilege"], &[], None);
        let text = settings_text(&[
            ("nerve-node", node.clone()),
            ("nerve-run-profile", profile.clone()),
        ]);
        let (got, unknown) = settings_from(&text, &["nerve-node", "nerve-run-profile"]).unwrap();
        assert!(unknown.is_empty(), "{unknown:?}");
        assert_eq!(
            got,
            [
                ("nerve-node".to_string(), node.clone()),
                ("nerve-run-profile".to_string(), profile)
            ]
        );
        let mut later: serde_json::Value = serde_json::from_str(&text).unwrap();
        later["nerve-node"]["sid_type"] = serde_json::json!("restricted");
        later["nerve-helper"] = later["nerve-node"].clone();
        let (got, unknown) = settings_from(&later.to_string(), &["nerve-node"]).unwrap();
        assert_eq!(got, [("nerve-node".to_string(), node)]);
        assert_eq!(
            unknown,
            ["nerve-helper", "nerve-node: sid_type", "nerve-run-profile"]
        );
        for bad in [
            "[]",
            r#"{"nerve-node": {"privileges": "x"}}"#,
            r#"{"nerve-node": {"privileges": [], "after": [], "restart_secs": [-1], "restart_on_error_stop": true}}"#,
        ] {
            assert!(settings_from(bad, &["nerve-node"]).is_err(), "{bad}");
        }
    }
}
