//! The Windows calls behind `install`, `update` and `uninstall`
//! ([`crate::winsvc::WinSystem`]): the local account `nerve` and its rights,
//! the folders' DACL, the service control manager, DPAPI and the logon of
//! the account the commands run as.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_SERVICE_ALREADY_RUNNING,
    ERROR_SERVICE_NOT_ACTIVE, ERROR_SERVICE_SPECIFIC_ERROR, ERROR_SHARING_VIOLATION, GetLastError,
    STATUS_SUCCESS,
};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NetUserAdd, NetUserDel, NetUserSetInfo, UF_DONT_EXPIRE_PASSWD, UF_PASSWD_CANT_CHANGE,
    UF_SCRIPT, USER_INFO_1, USER_INFO_1003, USER_PRIV_USER,
};
use windows_sys::Win32::Security::Authentication::Identity::{
    LSA_HANDLE, LSA_OBJECT_ATTRIBUTES, LSA_UNICODE_STRING, LsaAddAccountRights, LsaClose,
    LsaNtStatusToWinError, LsaOpenPolicy, LsaRemoveAccountRights, POLICY_CREATE_ACCOUNT,
    POLICY_LOOKUP_NAMES,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, PSID};
use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW};
use windows_sys::Win32::System::Console::{
    ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
};
use windows_sys::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, REG_DWORD, RegDeleteKeyValueW, RegSetKeyValueW,
};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, ChangeServiceConfigW, ControlService, CreateServiceW, DeleteService,
    QUERY_SERVICE_CONFIGW, QueryServiceConfigW, SC_ACTION, SC_ACTION_NONE, SC_ACTION_RESTART,
    SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE, SERVICE_ALL_ACCESS, SERVICE_AUTO_START,
    SERVICE_CONFIG_DESCRIPTION, SERVICE_CONFIG_FAILURE_ACTIONS,
    SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, SERVICE_CONTROL_STOP, SERVICE_DESCRIPTIONW,
    SERVICE_ERROR_NORMAL, SERVICE_FAILURE_ACTIONSW, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
    SERVICE_REQUIRED_PRIVILEGES_INFOW, SERVICE_RUNNING, SERVICE_START, SERVICE_START_PENDING,
    SERVICE_STATUS, SERVICE_STOP, SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS,
    SetServiceObjectSecurity, StartServiceW,
};

use nerve_service::win::scm::Scm;
pub use nerve_service::win::sid::is_admin;
pub(crate) use nerve_service::win::sid::{sid_of, sid_text};

use crate::eventlog::{SOURCE, SOURCE_KEY};
use crate::service::{Account, Layout, ServiceState, USER, USER_MARK};
use crate::win_user::{self, wide};
use crate::winsvc::{Kind, PROFILE_SERVICE, SERVICE_NAME, WinSystem};

/// The rights `nerve` gets: to run as a service, and to start a process
/// with another account's token (the two privileges the service keeps).
const GRANTED: &[&str] = &[
    "SeServiceLogonRight",
    "SeAssignPrimaryTokenPrivilege",
    "SeIncreaseQuotaPrivilege",
];

/// The logons `nerve` may not make: it has no person behind it.
const DENIED: &[&str] = &[
    "SeDenyInteractiveLogonRight",
    "SeDenyRemoteInteractiveLogonRight",
    "SeDenyNetworkLogonRight",
    "SeDenyBatchLogonRight",
];

/// The rights `nerve-run` gets: the batch logon its commands start with,
/// and the service logon of [`crate::winsvc::PROFILE_SERVICE`]. A service
/// logon's token would carry SeImpersonatePrivilege, so no command starts
/// with one.
const RUN_GRANTED: &[&str] = &["SeBatchLogonRight", "SeServiceLogonRight"];

/// The logons `nerve-run` may not make: no person signs in as it, here or
/// over the network.
const RUN_DENIED: &[&str] = &[
    "SeDenyInteractiveLogonRight",
    "SeDenyRemoteInteractiveLogonRight",
    "SeDenyNetworkLogonRight",
];

/// The privileges [`crate::winsvc::PROFILE_SERVICE`] keeps: none but the one
/// every process has.
const PROFILE_PRIVILEGES: &[&str] = &["SeChangeNotifyPrivilege"];

/// The privileges the service keeps; Windows takes every other from its
/// token, SeImpersonatePrivilege included.
const SERVICE_PRIVILEGES: &[&str] = &[
    "SeAssignPrimaryTokenPrivilege",
    "SeIncreaseQuotaPrivilege",
    "SeChangeNotifyPrivilege",
];

/// Where Windows keeps the accounts it does not show on the sign-in screen.
const HIDDEN: &str =
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList";

fn last() -> String {
    std::io::Error::last_os_error().to_string()
}

fn os(code: u32) -> String {
    std::io::Error::from_raw_os_error(code as i32).to_string()
}

/// Whether the service is registered, as anyone may ask.
pub fn service_registered() -> bool {
    Scm::open(SC_MANAGER_CONNECT)
        .and_then(|m| m.service(SERVICE_NAME, SERVICE_QUERY_STATUS))
        .is_ok_and(|s| s.is_some())
}

/// Whether the Windows Firewall service (MpsSvc) runs, whose filters keep an
/// AppContainer without network capabilities off the network (#149); not
/// known counts as not.
pub fn firewall_runs() -> bool {
    Scm::open(SC_MANAGER_CONNECT)
        .and_then(|m| m.service("MpsSvc", SERVICE_QUERY_STATUS))
        .ok()
        .flatten()
        .and_then(|s| s.status().ok())
        .is_some_and(|st| st.dwCurrentState == SERVICE_RUNNING)
}

/// One of the folders the service checks at its start
/// (crate::winsvc::own_folders): there, and SYSTEM's or the administrators'.
pub fn check_own_folder(dir: &Path) -> Result<(), String> {
    if dir.symlink_metadata().is_err() {
        return Err(format!(
            "{}: it is not there; {}",
            dir.display(),
            crate::winsvc::INSTALL_AGAIN
        ));
    }
    nerve_service::win::dacl::admins_folder(dir)
        .map_err(|e| format!("{e}; delete it, then install Nerve again with its installer"))
}

/// The node's service with every right; an error when it is not there.
fn the_service() -> Result<Scm, String> {
    the_service_for(SERVICE_ALL_ACCESS)
}

/// The node's service with the rights `access` only, which an owner has
/// for starting and stopping it (crate::owner).
fn the_service_for(access: u32) -> Result<Scm, String> {
    Scm::open(SC_MANAGER_CONNECT)?
        .service(SERVICE_NAME, access)?
        .ok_or_else(|| format!("the service {SERVICE_NAME} is not registered"))
}

/// The service's registry key, where its owner is named.
fn parameters_key() -> String {
    format!("SYSTEM\\CurrentControlSet\\Services\\{SERVICE_NAME}\\Parameters")
}

/// The owner's SID the service's key names (crate::owner): none when the
/// value or the service is not there.
pub fn owner() -> Result<Option<String>, String> {
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA};
    use windows_sys::Win32::System::Registry::{RRF_RT_REG_SZ, RegGetValueW};
    let key = wide(parameters_key());
    let value = wide(crate::owner::OWNER_VALUE);
    let mut buf = vec![0u16; 256];
    loop {
        let mut len = (buf.len() * 2) as u32;
        // SAFETY: NUL-terminated names and a buffer of the size given.
        let r = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut len,
            )
        };
        match r {
            0 => {
                let n = (len as usize / 2).min(buf.len());
                let sid = String::from_utf16_lossy(&buf[..n])
                    .trim_end_matches('\0')
                    .to_string();
                return Ok((!sid.is_empty()).then_some(sid));
            }
            ERROR_FILE_NOT_FOUND => return Ok(None),
            ERROR_MORE_DATA => buf.resize(len as usize / 2 + 1, 0),
            e => return Err(format!("cannot read the owner of the service: {}", os(e))),
        }
    }
}

/// Grants (`add`) or takes back rights of the account with `sid`.
fn rights(sid: &[u8], names: &[&str], add: bool) -> Result<(), String> {
    // SAFETY: zeroed object attributes are what LsaOpenPolicy takes.
    let attrs: LSA_OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed() };
    let mut policy: LSA_HANDLE = 0;
    // SAFETY: this machine's policy, a place for the handle.
    let st = unsafe {
        LsaOpenPolicy(
            std::ptr::null(),
            &attrs,
            (POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES) as u32,
            &mut policy,
        )
    };
    if st != STATUS_SUCCESS {
        // SAFETY: plain conversion.
        return Err(format!(
            "cannot open the security policy: {}",
            os(unsafe { LsaNtStatusToWinError(st) })
        ));
    }
    let mut texts: Vec<Vec<u16>> = names.iter().map(|n| n.encode_utf16().collect()).collect();
    let list: Vec<LSA_UNICODE_STRING> = texts
        .iter_mut()
        .map(|t| LSA_UNICODE_STRING {
            Length: (t.len() * 2) as u16,
            MaximumLength: (t.len() * 2) as u16,
            Buffer: t.as_mut_ptr(),
        })
        .collect();
    // SAFETY: an open policy, a valid SID and the strings above.
    let st = unsafe {
        let st = if add {
            LsaAddAccountRights(
                policy,
                sid.as_ptr() as PSID,
                list.as_ptr(),
                list.len() as u32,
            )
        } else {
            LsaRemoveAccountRights(policy, sid.as_ptr() as PSID, true, std::ptr::null(), 0)
        };
        LsaClose(policy);
        st
    };
    if st != STATUS_SUCCESS {
        // SAFETY: plain conversion.
        let code = unsafe { LsaNtStatusToWinError(st) };
        // An account without rights has none to take back.
        if !add && code == ERROR_FILE_NOT_FOUND {
            return Ok(());
        }
        return Err(format!("cannot change an account's rights: {}", os(code)));
    }
    Ok(())
}

/// Gives one of the node's accounts the rights of its `kind` and keeps it
/// off the sign-in screen.
fn settle(name: &str, kind: Kind) -> Result<(), String> {
    let sid = sid_of(name)?;
    let (granted, denied) = match kind {
        Kind::Node => (GRANTED, DENIED),
        Kind::Commands => (RUN_GRANTED, RUN_DENIED),
    };
    rights(&sid, granted, true)?;
    rights(&sid, denied, true)?;
    let zero = 0u32;
    // SAFETY: NUL-terminated key and value names, a DWORD of 4 bytes.
    let r = unsafe {
        RegSetKeyValueW(
            HKEY_LOCAL_MACHINE,
            wide(HIDDEN).as_ptr(),
            wide(name).as_ptr(),
            REG_DWORD,
            (&raw const zero).cast(),
            4,
        )
    };
    if r != 0 {
        return Err(format!(
            "cannot hide {name} from the sign-in screen: {}",
            os(r)
        ));
    }
    Ok(())
}

/// This machine.
pub struct WinHost;

impl WinSystem for WinHost {
    fn is_admin(&self) -> bool {
        is_admin()
    }

    fn account(&self, name: &str) -> Result<Option<Account>, String> {
        win_user::lookup(name)
    }

    fn add_account(&self, name: &str, password: &str, kind: Kind) -> Result<(), String> {
        let mark = match kind {
            Kind::Node => USER_MARK,
            Kind::Commands => crate::account::RUN_MARK,
        };
        let (mut n, mut p, mut c) = (wide(name), wide(password), wide(mark));
        let info = USER_INFO_1 {
            usri1_name: n.as_mut_ptr(),
            usri1_password: p.as_mut_ptr(),
            usri1_password_age: 0,
            usri1_priv: USER_PRIV_USER,
            usri1_home_dir: std::ptr::null_mut(),
            usri1_comment: c.as_mut_ptr(),
            usri1_flags: UF_SCRIPT | UF_DONT_EXPIRE_PASSWD | UF_PASSWD_CANT_CHANGE,
            usri1_script_path: std::ptr::null_mut(),
        };
        let mut bad = 0;
        // SAFETY: the local machine and a USER_INFO_1 of live strings.
        let r = unsafe { NetUserAdd(std::ptr::null(), 1, (&raw const info).cast(), &mut bad) };
        if r != 0 {
            return Err(format!("cannot make the user {name}: {}", os(r)));
        }
        settle(name, kind)
    }

    fn reset_account(&self, name: &str, password: &str, kind: Kind) -> Result<(), String> {
        let mut p = wide(password);
        let info = USER_INFO_1003 {
            usri1003_password: p.as_mut_ptr(),
        };
        let mut bad = 0;
        // SAFETY: the local machine, a NUL-terminated name, a live string.
        let r = unsafe {
            NetUserSetInfo(
                std::ptr::null(),
                wide(name).as_ptr(),
                1003,
                (&raw const info).cast(),
                &mut bad,
            )
        };
        if r != 0 {
            return Err(format!("cannot give {name} a new password: {}", os(r)));
        }
        settle(name, kind)
    }

    fn make_profile(&self, name: &str, password: &str) -> Result<PathBuf, String> {
        let t = win_user::batch_logon(name, password)?;
        win_user::make_profile(&t, name)
            .map_err(|e| format!("cannot make the profile of {name}: {e}"))
    }

    fn put_profile_service(
        &self,
        layout: &Layout,
        name: &str,
        password: &str,
    ) -> Result<(), String> {
        let s = put(&Spec {
            name: PROFILE_SERVICE,
            shown: "Nerve commands' profile",
            line: format!(
                "\"{}\" {}",
                layout.bin.display(),
                crate::win_profile::PROFILE_ARG
            ),
            account: name,
            password,
            about: "Keeps the profile of nerve-run loaded, where the AppContainers of Nerve's commands keep theirs.",
            privileges: PROFILE_PRIVILEGES,
            after: None,
        })?;
        // SAFETY: an open service; no arguments.
        if unsafe { StartServiceW(s.0, 0, std::ptr::null()) } == 0
            // SAFETY: plain getter, right after the call.
            && unsafe { GetLastError() } != ERROR_SERVICE_ALREADY_RUNNING
        {
            return Err(format!(
                "cannot start the service {PROFILE_SERVICE}: {}",
                last()
            ));
        }
        Ok(())
    }

    fn delete_profile_service(&self) -> Result<bool, String> {
        let Some(s) =
            Scm::open(SC_MANAGER_CONNECT)?.service(PROFILE_SERVICE, SERVICE_ALL_ACCESS)?
        else {
            return Ok(false);
        };
        stop_and_wait(&s, PROFILE_SERVICE)?;
        // SAFETY: an open service; it goes once every handle is closed.
        if unsafe { DeleteService(s.0) } == 0 {
            return Err(format!(
                "cannot remove the service {PROFILE_SERVICE}: {}",
                last()
            ));
        }
        Ok(true)
    }

    fn run_reach(
        &self,
        name: &str,
        password: &str,
        own: &[PathBuf],
        owner: Option<&str>,
    ) -> Result<Option<String>, String> {
        let t = win_user::batch_logon(name, password)?;
        let at = |e: std::io::Error| format!("cannot check what {name} can open: {e}");
        if let Some(p) = win_user::reach(&t, own).map_err(at)? {
            return Ok(Some(p.display().to_string()));
        }
        // The owner's registry, while it is loaded; its Environment key
        // holds what the owner set for every program of theirs (#90).
        if let Some(sid) = owner {
            for key in [sid.to_string(), format!("{sid}\\Environment")] {
                if win_user::opens_key(&t, &key).map_err(at)? {
                    return Ok(Some(format!("HKEY_USERS\\{key}")));
                }
            }
        }
        Ok(None)
    }

    fn remove_account(&self, name: &str) -> Result<Option<String>, String> {
        let sid = sid_of(name)?;
        let text = sid_text(&sid)?;
        // SAFETY: a valid SID.
        let profile = unsafe { win_user::profile_dir(sid.as_ptr() as PSID) };
        // The profile Windows made at the service's first logon. Its registry
        // may stay loaded after the service stopped: for a few seconds, or,
        // where Windows Search holds it, until Windows restarts. One that was
        // never made is fine.
        let until = Instant::now() + Duration::from_secs(15);
        let held = loop {
            // SAFETY: a NUL-terminated SID string.
            let ok = unsafe {
                windows_sys::Win32::UI::Shell::DeleteProfileW(
                    wide(&text).as_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            };
            // SAFETY: plain getter, right after the call.
            let e = unsafe { GetLastError() };
            if ok != 0 || e == ERROR_FILE_NOT_FOUND {
                break false;
            }
            if e != ERROR_SHARING_VIOLATION {
                return Err(format!("cannot remove the profile of {name}: {}", os(e)));
            }
            if Instant::now() > until {
                break true;
            }
            std::thread::sleep(Duration::from_secs(1));
        };
        rights(&sid, &[], false)?;
        // SAFETY: the local machine and a NUL-terminated name.
        let r = unsafe { NetUserDel(std::ptr::null(), wide(name).as_ptr()) };
        if r != 0 {
            return Err(format!("cannot remove the user {name}: {}", os(r)));
        }
        // SAFETY: NUL-terminated key and value names.
        unsafe {
            RegDeleteKeyValueW(
                HKEY_LOCAL_MACHINE,
                wide(HIDDEN).as_ptr(),
                wide(name).as_ptr(),
            )
        };
        Ok(held.then(|| {
            format!(
                "Windows still holds the profile folder {} of {name} (SID {text}); after a restart of Windows, delete that folder in Explorer; if it will not go, delete it under System Properties › Advanced › User Profiles › Settings, where it shows as Account Unknown with the date of this uninstall (other rows of Account Unknown belong to other deleted accounts: leave them)",
                profile.map_or_else(|| "?".into(), |p| p.display().to_string())
            )
        }))
    }

    fn secure(&self, dir: &Path, sddl: &str) -> Result<(), String> {
        nerve_service::win::dacl::private_folder(dir, sddl)
    }

    fn admins_own(&self, dir: &Path) -> Result<(), String> {
        nerve_service::win::dacl::admins_folder(dir)
    }

    fn machine_sid(&self) -> Result<String, String> {
        win_user::machine_sid()
    }

    fn service(&self) -> Result<Option<bool>, String> {
        let Some(s) = Scm::open(SC_MANAGER_CONNECT)?.service(SERVICE_NAME, SERVICE_QUERY_STATUS)?
        else {
            return Ok(None);
        };
        Ok(Some(s.status()?.dwCurrentState != SERVICE_STOPPED))
    }

    fn service_state(&self) -> Result<Option<ServiceState>, String> {
        let access = SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG;
        let Some(s) = Scm::open(SC_MANAGER_CONNECT)?.service(SERVICE_NAME, access)? else {
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
        let enabled = (ok != 0).then(|| {
            // SAFETY: the call filled the struct at the buffer's start.
            let config = unsafe { &*buf.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
            config.dwStartType == SERVICE_AUTO_START
        });
        Ok(Some(ServiceState {
            state: state.into(),
            enabled,
        }))
    }

    fn put_service(&self, layout: &Layout, password: &str) -> Result<(), String> {
        put(&Spec {
            name: SERVICE_NAME,
            shown: "Nerve node",
            line: format!(
                "\"{}\" --config-dir \"{}\" --state-dir \"{}\" run",
                layout.bin.display(),
                layout.paths.config_dir.display(),
                layout.paths.state_dir.display()
            ),
            account: USER,
            password,
            about: concat!(
                "Links this machine to its Nerve centers. ",
                env!("CARGO_PKG_REPOSITORY")
            ),
            privileges: SERVICE_PRIVILEGES,
            after: Some(PROFILE_SERVICE),
        })
        .map(|_| ())
    }

    fn start(&self) -> Result<(), String> {
        let s = the_service_for(SERVICE_START)?;
        // SAFETY: an open service; no arguments.
        if unsafe { StartServiceW(s.0, 0, std::ptr::null()) } == 0
            // SAFETY: plain getter, right after the call.
            && unsafe { GetLastError() } != ERROR_SERVICE_ALREADY_RUNNING
        {
            return Err(format!(
                "cannot start the service {SERVICE_NAME}: {}",
                last()
            ));
        }
        Ok(())
    }

    fn stop(&self) -> Result<(), String> {
        let s = the_service_for(SERVICE_STOP | SERVICE_QUERY_STATUS)?;
        stop_and_wait(&s, SERVICE_NAME)
    }

    fn owner_sid(&self) -> Option<(String, String)> {
        // The app's broker names its user; the name says the SID is one.
        if let Ok(sid) = std::env::var(crate::cli::DESKTOP_USER_SID)
            && let Ok(name) = win_user::name_of_sid(&sid)
        {
            return Some((sid, name));
        }
        let sid = win_user::own_sid().ok()?;
        let sid = sid_text(&sid).ok()?;
        let name = win_user::current_user().ok()?;
        Some((sid, name))
    }

    fn owner(&self) -> Result<Option<(String, String)>, String> {
        let Some(sid) = owner()? else {
            return Ok(None);
        };
        let name = win_user::name_of_sid(&sid).unwrap_or_else(|_| sid.clone());
        Ok(Some((sid, name)))
    }

    fn put_owner(&self, sid: &str) -> Result<(), String> {
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
        use windows_sys::Win32::System::Registry::REG_SZ;
        let data = wide(sid);
        // SAFETY: NUL-terminated names and data of the size given; the key
        // is made when it is missing.
        let r = unsafe {
            RegSetKeyValueW(
                HKEY_LOCAL_MACHINE,
                wide(parameters_key()).as_ptr(),
                wide(crate::owner::OWNER_VALUE).as_ptr(),
                REG_SZ,
                data.as_ptr().cast(),
                (data.len() * 2) as u32,
            )
        };
        if r != 0 {
            return Err(format!("cannot write the owner of the service: {}", os(r)));
        }
        let s = the_service()?;
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: a NUL-terminated SDDL string; the descriptor is freed
        // below.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(crate::winsvc::service_dacl(Some(sid))).as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(format!("cannot make the service's DACL: {}", last()));
        }
        // SAFETY: an open service and a valid descriptor, freed once.
        let ok = unsafe { SetServiceObjectSecurity(s.0, DACL_SECURITY_INFORMATION, sd) };
        let e = last();
        // SAFETY: the descriptor from the conversion.
        unsafe { windows_sys::Win32::Foundation::LocalFree(sd) };
        if ok == 0 {
            return Err(format!("cannot set the service's DACL: {e}"));
        }
        Ok(())
    }

    fn stage_vault(&self, paths: &crate::paths::NodePaths) -> Result<u64, String> {
        crate::secrets::vault::stage_in_service(paths)
    }

    fn delete_service(&self) -> Result<(), String> {
        let s = the_service()?;
        // SAFETY: an open service; it goes once every handle is closed.
        if unsafe { DeleteService(s.0) } == 0 {
            return Err(format!(
                "cannot remove the service {SERVICE_NAME}: {}",
                last()
            ));
        }
        Ok(())
    }

    fn put_event_source(&self, layout: &Layout) -> Result<(), String> {
        nerve_service::win::event::put_source(SOURCE_KEY, SOURCE, &layout.bin)
    }

    fn delete_event_source(&self) -> Result<bool, String> {
        nerve_service::win::event::delete_source(SOURCE_KEY, SOURCE)
    }

    fn wait_running(&self, layout: &Layout) -> Result<(), String> {
        let s = the_service_for(SERVICE_QUERY_STATUS)?;
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
                        "the service {SERVICE_NAME} stopped at its start ({code}); {} says why",
                        layout.paths.log_file().display()
                    ));
                }
                _ if Instant::now() > until => {
                    return Err(format!(
                        "the service {SERVICE_NAME} did not start within a minute"
                    ));
                }
                _ => std::thread::sleep(Duration::from_millis(250)),
            }
        }
    }

    fn read_password(&self, prompt: &str, out: &mut dyn Write) -> Result<String, String> {
        // SAFETY: plain calls on this process's stdin; the mode is restored.
        let console = unsafe {
            let h = GetStdHandle(STD_INPUT_HANDLE);
            let mut mode = 0;
            (GetConsoleMode(h, &mut mode) != 0).then(|| {
                SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT);
                (h, mode)
            })
        };
        // A program that pipes the password in (the desktop app) is not
        // asked, so its output stays the command's own.
        if console.is_some() {
            let _ = write!(out, "{prompt}");
            let _ = out.flush();
        }
        let mut line = String::new();
        let r = std::io::stdin().lock().read_line(&mut line);
        if let Some((h, mode)) = console {
            // SAFETY: as above.
            unsafe { SetConsoleMode(h, mode) };
            // A console without echo does not end the line.
            let _ = writeln!(out);
        }
        r.map_err(|e| e.to_string())?;
        let password = line.trim_end_matches(['\n', '\r']).to_string();
        line.clear();
        if password.is_empty() {
            return Err(crate::winsvc::BLANK_PASSWORD.into());
        }
        Ok(password)
    }

    fn check_logon(
        &self,
        name: &str,
        password: &str,
        own: &[PathBuf],
    ) -> Result<Option<PathBuf>, String> {
        let t = win_user::logon(name, password)?;
        win_user::reach(&t, own).map_err(|e| format!("cannot check what {name} can open: {e}"))
    }

    fn sudo_logon(&self, name: &str, password: &str) -> Result<bool, String> {
        let t = win_user::batch_logon(name, password)?;
        win_user::has_admins(&t)
            .map_err(|e| format!("cannot read the groups of {name}'s logon: {e}"))
    }

    fn protect(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        win_user::protect(data).map_err(|e| format!("DPAPI: {e}"))
    }

    fn unprotect(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        win_user::unprotect(data).map_err(|e| format!("DPAPI: {e}"))
    }

    fn admin_groups(&self, account: &Account) -> Vec<String> {
        win_user::admin_groups(account)
    }

    fn version_of(&self, program: &Path) -> Result<String, String> {
        let at = |e: std::io::Error| format!("{} --version: {e}", program.display());
        let t = win_user::restricted().map_err(at)?;
        let line = crate::exec::windows_command_line(
            &program.display().to_string(),
            &["--version".to_string()],
        );
        let (code, out) =
            win_user::run_capture(&t, &line, Duration::from_secs(30), None).map_err(at)?;
        if code != 0 {
            return Err(format!("{} --version: exit code {code}", program.display()));
        }
        Ok(String::from_utf8_lossy(&out).trim().to_string())
    }

    fn remove_program(&self, path: &Path) -> Result<bool, String> {
        let at = |e: std::io::Error| format!("{}: {e}", path.display());
        let dir = path.parent().unwrap_or(Path::new("."));
        match std::fs::remove_file(path) {
            Ok(()) => {
                // The folder goes too when nothing else is in it.
                let _ = std::fs::remove_dir(dir);
                Ok(true)
            }
            // A program that runs cannot be deleted, but it can be renamed:
            // it moves aside, so its name is free for a later install, and
            // Windows deletes it at its next start, with the folder if that
            // is empty by then.
            Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {
                let aside = dir.join(format!(
                    "{}{}.del",
                    crate::winsvc::ASIDE,
                    nerve_transport::keys::random_token(8)
                ));
                std::fs::rename(path, &aside).map_err(at)?;
                later(&aside)?;
                let _ = later(dir);
                Ok(false)
            }
            Err(e) => Err(at(e)),
        }
    }

    fn remove_grants(
        &self,
        paths: &crate::paths::NodePaths,
        node_ids: &[String],
    ) -> crate::grants::Synced {
        crate::grants::remove_all(paths, node_ids, &mut |m| eprintln!("{m}"))
    }
}

/// Asks the service `s` (`name`) to stop and waits until it has; a stopped
/// one is fine.
fn stop_and_wait(s: &Scm, name: &str) -> Result<(), String> {
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

/// A service as [`put`] registers it.
struct Spec<'a> {
    name: &'a str,
    shown: &'a str,
    /// Its command line.
    line: String,
    /// The local account it runs as, and that account's password.
    account: &'a str,
    password: &'a str,
    about: &'a str,
    /// The privileges it keeps; Windows takes every other from its token.
    privileges: &'a [&'a str],
    /// The service it needs running first.
    after: Option<&'a str>,
}

/// Registers the service `spec` names, or changes it: started with the
/// machine and again after a failure (5 seconds later, three times a day
/// at most).
fn put(spec: &Spec) -> Result<Scm, String> {
    let name = spec.name;
    let bin = wide(&spec.line);
    let user = wide(format!(".\\{}", spec.account));
    let password = wide(spec.password);
    let wname = wide(name);
    let shown = wide(spec.shown);
    // A list of names, each ended by a NUL, and one NUL more; an empty one
    // takes the dependencies away.
    let after: Vec<u16> = spec
        .after
        .into_iter()
        .flat_map(|a| a.encode_utf16().chain(Some(0)))
        .chain([0, 0])
        .collect();
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
                    bin.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    after.as_ptr(),
                    user.as_ptr(),
                    password.as_ptr(),
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
                    wname.as_ptr(),
                    shown.as_ptr(),
                    SERVICE_ALL_ACCESS,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    bin.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    after.as_ptr(),
                    user.as_ptr(),
                    password.as_ptr(),
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
    let mut actions = [
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 5000,
        },
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 5000,
        },
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 5000,
        },
        SC_ACTION {
            Type: SC_ACTION_NONE,
            Delay: 0,
        },
    ];
    let failure = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: 24 * 3600,
        lpRebootMsg: std::ptr::null_mut(),
        lpCommand: std::ptr::null_mut(),
        cActions: actions.len() as u32,
        lpsaActions: actions.as_mut_ptr(),
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
            SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
            (&raw const required).cast(),
            "its privileges",
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
    Ok(s)
}

/// Lets Windows delete `path` at its next start.
fn later(path: &Path) -> Result<(), String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn icacls(p: &Path) -> String {
        let o = std::process::Command::new("icacls")
            .arg(p)
            .output()
            .unwrap();
        String::from_utf8_lossy(&o.stdout).into_owned()
    }

    fn junction(link: &Path, to: &Path) {
        let ok = std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(to)
            .output()
            .unwrap()
            .status
            .success();
        assert!(ok, "mklink /J {link:?}");
    }

    /// The folder gets the DACL, what is in it inherits it, and a junction
    /// below it is not followed: the folder it leads to keeps its own. A
    /// junction in place of the folder is refused, and the administrators
    /// own the folder. Needs an elevated administrator, whose new folders
    /// the administrators own.
    #[test]
    fn secure_sets_the_dacl_and_follows_no_junction() {
        let d = tempfile::tempdir().unwrap();
        let top = d.path().join("top");
        let outside = d.path().join("outside");
        std::fs::create_dir_all(top.join("sub")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(top.join("sub/f"), "y").unwrap();
        std::fs::write(outside.join("f"), "x").unwrap();
        junction(&top.join("j"), &outside);
        let before = icacls(&outside.join("f"));
        let me = win_user::current_user().unwrap();
        let sid = sid_text(&win_user::own_sid().unwrap()).unwrap();
        WinHost
            .secure(&top, &crate::winsvc::folder_dacl(Some(&sid)))
            .unwrap();
        let acl = icacls(&top.join("sub/f"));
        assert!(acl.contains(&format!("\\{me}:(I)(F)")), "{acl}");
        assert_eq!(acl.lines().filter(|l| l.contains(":(")).count(), 3, "{acl}");
        assert_eq!(icacls(&outside.join("f")), before);
        WinHost.admins_own(&top).unwrap();
        junction(&d.path().join("link"), &outside);
        let e = WinHost
            .secure(&d.path().join("link"), &crate::winsvc::folder_dacl(None))
            .unwrap_err();
        assert!(e.contains("is a link"), "{e}");
        assert_eq!(icacls(&outside.join("f")), before);
    }

    /// DPAPI gives back what it sealed, and the sealed bytes are not the
    /// text.
    #[test]
    fn dpapi_round_trip() {
        let plain = crate::winsvc::Secret {
            sid: "S-1-5-21-1-2-3-1001".into(),
            name: "alice".into(),
            password: "not a real password".into(),
        }
        .text();
        let sealed = win_user::protect(&plain).unwrap();
        assert!(!sealed.windows(4).any(|w| w == b"real"));
        assert_eq!(win_user::unprotect(&sealed).unwrap(), plain);
        assert!(win_user::unprotect(b"garbage").is_err());
    }

    /// A program run with the restricted token says its version.
    #[test]
    fn a_program_runs_with_the_restricted_token() {
        let exe =
            std::env::var_os("ComSpec").unwrap_or_else(|| "C:\\Windows\\System32\\cmd.exe".into());
        let t = win_user::restricted().unwrap();
        let line = crate::exec::windows_command_line(
            &exe.to_string_lossy(),
            &["/D".into(), "/C".into(), "whoami /groups".into()],
        );
        let (code, out) = win_user::run_capture(&t, &line, Duration::from_secs(30), None).unwrap();
        assert_eq!(code, 0);
        assert!(!out.is_empty());
    }

    /// A program run in a job, as the helper that asks a command of another
    /// account to end runs in the command's job (crate::win_stop), is ended
    /// with that job.
    #[test]
    fn a_program_run_in_a_job_ends_with_it() {
        let exe =
            std::env::var_os("ComSpec").unwrap_or_else(|| "C:\\Windows\\System32\\cmd.exe".into());
        let t = win_user::restricted().unwrap();
        let line = crate::exec::windows_command_line(
            &exe.to_string_lossy(),
            &["/D".into(), "/C".into(), "ping -n 60 127.0.0.1".into()],
        );
        let job = std::sync::Arc::new(crate::win::Job::new().unwrap());
        let ender = {
            let job = job.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(1));
                job.terminate()
            })
        };
        let t0 = std::time::Instant::now();
        let r = win_user::run_capture(&t, &line, Duration::from_secs(30), Some(&job));
        assert!(ender.join().unwrap(), "the job was not ended");
        let (code, _) = r.unwrap();
        // TerminateJobObject's exit code.
        assert_eq!(code, 1);
        assert!(
            t0.elapsed() < Duration::from_secs(20),
            "the program outlived its job"
        );
    }

    /// A batch logon of an administrator holds the Administrators group;
    /// the interactive logon of the same account is filtered. A wrong
    /// password is refused. Needs an administrator account of a test
    /// machine and its password in `NERVE_WIN_SUDO_ACCOUNT` and
    /// `NERVE_WIN_SUDO_PASSWORD`; tests/win_sudo.rs starts commands with it.
    #[test]
    #[ignore = "needs an administrator account of a Windows test machine"]
    fn an_administrators_batch_logon_has_the_full_token() {
        let name = std::env::var("NERVE_WIN_SUDO_ACCOUNT").unwrap();
        let password = std::env::var("NERVE_WIN_SUDO_PASSWORD").unwrap();
        let e = WinHost.sudo_logon(&name, "not-the-password").unwrap_err();
        assert!(e.contains("is wrong"), "{e}");
        assert!(WinHost.sudo_logon(&name, &password).unwrap());
        assert!(win_user::sudo_token(&name, &password).is_ok());
        let filtered = win_user::logon(&name, &password).unwrap();
        assert!(!win_user::has_admins(&filtered).unwrap());
    }

    fn reg_query(key: &str) -> String {
        let o = std::process::Command::new("reg")
            .args(["query", &format!("HKLM\\{key}")])
            .output()
            .unwrap();
        String::from_utf8_lossy(&o.stdout).into_owned()
    }

    /// The Event Log source is registered with the program as its message
    /// file, and removed again. Needs an administrator, and leaves the
    /// source of an installed node alone.
    #[test]
    fn the_event_source_is_registered_and_removed() {
        if !reg_query(SOURCE_KEY).is_empty() {
            eprintln!("skipped: the source {SOURCE} is registered on this machine");
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let l = Layout {
            bin: d.path().join("Nerve Test").join("nerve-node.exe"),
            ..Layout::system()
        };
        WinHost.put_event_source(&l).unwrap();
        let got = reg_query(SOURCE_KEY);
        let removed = WinHost.delete_event_source();
        assert!(
            got.contains(&format!(
                "EventMessageFile    REG_SZ    {}",
                l.bin.display()
            )),
            "{got}"
        );
        assert!(got.contains("TypesSupported    REG_DWORD    0x5"), "{got}");
        assert_eq!(removed, Ok(true));
        assert!(reg_query(SOURCE_KEY).is_empty());
        assert_eq!(WinHost.delete_event_source(), Ok(false));
    }

    /// The account this test runs as is found, with its profile folder.
    #[test]
    fn the_own_account_is_found() {
        let me = win_user::current_user().unwrap();
        let a = win_user::lookup(&me).unwrap().expect("this account");
        assert!(a.name.eq_ignore_ascii_case(&me));
        assert_eq!(a.uid, win_user::own_uid());
        assert!(a.home.is_dir(), "{:?}", a.home);
        assert_eq!(win_user::lookup("no-such-account-x").unwrap(), None);
    }

    /// A local account's SID is the machine's and its number: this
    /// account's (a local one, as on the test machines and the runner).
    #[test]
    fn a_local_account_s_sid_is_the_machine_s() {
        let machine = WinHost.machine_sid().unwrap();
        assert!(machine.starts_with("S-1-5-21-"), "{machine}");
        let own = sid_text(&win_user::own_sid().unwrap()).unwrap();
        assert_eq!(crate::winsvc::local_sid(&machine, win_user::own_uid()), own);
    }
}
