//! The Windows calls behind `install`, `update` and `uninstall`
//! ([`crate::winsvc::WinSystem`]): the local account `nerve` and its rights,
//! the folders' DACL, the service control manager, DPAPI and the logon of
//! the account the commands run as.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_SERVICE_ALREADY_RUNNING,
    ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_NOT_ACTIVE, ERROR_SERVICE_SPECIFIC_ERROR,
    ERROR_SHARING_VIOLATION, GetLastError, LocalFree, STATUS_SUCCESS,
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
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    CheckTokenMembership, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, LookupAccountNameW,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SID_NAME_USE,
    WinBuiltinAdministratorsSid,
};
use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW};
use windows_sys::Win32::System::Console::{
    ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
};
use windows_sys::Win32::System::EventLog::{EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE};
use windows_sys::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, REG_DWORD, REG_SZ, RegDeleteKeyValueW, RegDeleteKeyW, RegSetKeyValueW,
};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, ControlService,
    CreateServiceW, DeleteService, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW,
    QueryServiceConfigW, QueryServiceStatusEx, SC_ACTION, SC_ACTION_NONE, SC_ACTION_RESTART,
    SC_HANDLE, SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE, SC_STATUS_PROCESS_INFO,
    SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_CONFIG_DESCRIPTION,
    SERVICE_CONFIG_FAILURE_ACTIONS, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, SERVICE_CONTROL_STOP,
    SERVICE_DESCRIPTIONW, SERVICE_ERROR_NORMAL, SERVICE_FAILURE_ACTIONSW, SERVICE_QUERY_CONFIG,
    SERVICE_QUERY_STATUS, SERVICE_REQUIRED_PRIVILEGES_INFOW, SERVICE_RUNNING, SERVICE_START,
    SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOP,
    SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS, SetServiceObjectSecurity,
    StartServiceW,
};

use crate::eventlog::{SOURCE, SOURCE_KEY};
use crate::service::{Account, Layout, ServiceState, USER, USER_MARK};
use crate::win_user::{self, wide};
use crate::winsvc::{SERVICE_NAME, WinSystem};

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

/// Whether this process runs as an administrator, elevated: the
/// Administrators group is in effect in its token.
pub fn is_admin() -> bool {
    let Ok(sid) = win_user::well_known_sid(WinBuiltinAdministratorsSid) else {
        return false;
    };
    let mut member = 0;
    // SAFETY: a null token is this thread's or process's own; a valid SID.
    let ok =
        unsafe { CheckTokenMembership(std::ptr::null_mut(), sid.as_ptr() as PSID, &mut member) };
    ok != 0 && member != 0
}

/// Whether the service is registered, as anyone may ask.
pub fn service_registered() -> bool {
    Scm::open(SC_MANAGER_CONNECT)
        .and_then(|m| m.service(SERVICE_QUERY_STATUS))
        .is_ok_and(|s| s.is_some())
}

/// A handle of the service control manager, or of a service, closed when
/// dropped.
struct Scm(SC_HANDLE);

impl Drop for Scm {
    fn drop(&mut self) {
        // SAFETY: a handle from OpenSCManagerW or OpenServiceW, closed once.
        unsafe { CloseServiceHandle(self.0) };
    }
}

impl Scm {
    fn open(access: u32) -> Result<Scm, String> {
        // SAFETY: this machine's active database.
        let h = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), access) };
        if h.is_null() {
            return Err(format!(
                "cannot open the service control manager: {}",
                last()
            ));
        }
        Ok(Scm(h))
    }

    /// The node's service; `None` when it is not registered.
    fn service(&self, access: u32) -> Result<Option<Scm>, String> {
        // SAFETY: an open manager and a NUL-terminated name.
        let h = unsafe { OpenServiceW(self.0, wide(SERVICE_NAME).as_ptr(), access) };
        if h.is_null() {
            // SAFETY: plain getter, right after the call.
            if unsafe { GetLastError() } == ERROR_SERVICE_DOES_NOT_EXIST {
                return Ok(None);
            }
            return Err(format!(
                "cannot open the service {SERVICE_NAME}: {}",
                last()
            ));
        }
        Ok(Some(Scm(h)))
    }

    fn status(&self) -> Result<SERVICE_STATUS_PROCESS, String> {
        // SAFETY: plain data that the call fills.
        let mut st: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
        let mut need = 0;
        // SAFETY: a buffer of the size given.
        let ok = unsafe {
            QueryServiceStatusEx(
                self.0,
                SC_STATUS_PROCESS_INFO,
                (&raw mut st).cast(),
                std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut need,
            )
        };
        if ok == 0 {
            return Err(format!("cannot ask the service {SERVICE_NAME}: {}", last()));
        }
        Ok(st)
    }
}

/// The node's service with every right; an error when it is not there.
fn the_service() -> Result<Scm, String> {
    the_service_for(SERVICE_ALL_ACCESS)
}

/// The node's service with the rights `access` only, which an owner has
/// for starting and stopping it (crate::owner).
fn the_service_for(access: u32) -> Result<Scm, String> {
    Scm::open(SC_MANAGER_CONNECT)?
        .service(access)?
        .ok_or_else(|| format!("the service {SERVICE_NAME} is not registered"))
}

/// The service's registry key, where its owners are listed.
fn parameters_key() -> String {
    format!("SYSTEM\\CurrentControlSet\\Services\\{SERVICE_NAME}\\Parameters")
}

/// The owners' SIDs the service's key lists (crate::owner): none when the
/// value or the service is not there.
pub fn owners() -> Result<Vec<String>, String> {
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA};
    use windows_sys::Win32::System::Registry::{RRF_RT_REG_MULTI_SZ, RegGetValueW};
    let key = wide(parameters_key());
    let value = wide(crate::owner::OWNERS_VALUE);
    let mut buf = vec![0u16; 1024];
    loop {
        let mut len = (buf.len() * 2) as u32;
        // SAFETY: NUL-terminated names and a buffer of the size given.
        let r = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_MULTI_SZ,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut len,
            )
        };
        match r {
            0 => {
                let n = (len as usize / 2).min(buf.len());
                return Ok(String::from_utf16_lossy(&buf[..n])
                    .split('\0')
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect());
            }
            ERROR_FILE_NOT_FOUND => return Ok(Vec::new()),
            ERROR_MORE_DATA => buf.resize(len as usize / 2 + 1, 0),
            e => return Err(format!("cannot read the owners of the service: {}", os(e))),
        }
    }
}

/// The SID of the local account `name`.
pub(crate) fn sid_of(name: &str) -> Result<Vec<u8>, String> {
    let mut sid = vec![0u8; 68];
    let mut len = sid.len() as u32;
    let mut domain = vec![0u16; 256];
    let mut dlen = domain.len() as u32;
    let mut kind: SID_NAME_USE = 0;
    // The machine's name first, so a domain account of that name is not it.
    let full = wide(format!(
        "{}\\{name}",
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| ".".into())
    ));
    // SAFETY: buffers of the sizes given.
    let ok = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            full.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut len,
            domain.as_mut_ptr(),
            &mut dlen,
            &mut kind,
        )
    };
    if ok == 0 {
        return Err(format!("cannot find the SID of {name}: {}", last()));
    }
    // The call leaves `len` at the buffer's size when the SID fits, so the
    // SID's own length cuts it: a SID compared as bytes must have no tail.
    // SAFETY: a valid SID the call wrote.
    let real = unsafe { windows_sys::Win32::Security::GetLengthSid(sid.as_ptr() as PSID) };
    sid.truncate((real as usize).min(len as usize));
    Ok(sid)
}

/// A SID as text, `S-1-5-…`.
pub(crate) fn sid_text(sid: &[u8]) -> Result<String, String> {
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: a valid SID; the string is freed with LocalFree.
    if unsafe { ConvertSidToStringSidW(sid.as_ptr() as PSID, &mut text) } == 0 {
        return Err(last());
    }
    // SAFETY: a NUL-terminated string, freed once.
    unsafe {
        let s = win_user::from_wide(text);
        LocalFree(text.cast());
        Ok(s)
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
        return Err(format!("cannot change the rights of {USER}: {}", os(code)));
    }
    Ok(())
}

/// Gives `nerve` its rights and keeps it off the sign-in screen.
fn settle(name: &str) -> Result<(), String> {
    let sid = sid_of(name)?;
    rights(&sid, GRANTED, true)?;
    rights(&sid, DENIED, true)?;
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

/// The DACL in SDDL: full control for `owner` (a SID), SYSTEM and the
/// administrators, inherited by every file and folder below; `P` keeps out
/// what the folders above would hand down.
pub fn dacl_text(owner: Option<&str>) -> String {
    let mut s = String::from("D:P");
    if let Some(o) = owner {
        s.push_str(&format!("(A;OICI;FA;;;{o})"));
    }
    s.push_str("(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
    s
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

    fn add_account(&self, name: &str, password: &str) -> Result<(), String> {
        let (mut n, mut p, mut c) = (wide(name), wide(password), wide(USER_MARK));
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
        settle(name)
    }

    fn reset_account(&self, name: &str, password: &str) -> Result<(), String> {
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
        settle(name)
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
                "Windows still holds the profile folder {} of {name} (SID {text}); after a restart of Windows, delete it under System Properties › Advanced › User Profiles › Settings, where it shows as Account Unknown",
                profile.map_or_else(|| "?".into(), |p| p.display().to_string())
            )
        }))
    }

    fn secure(&self, dir: &Path, owner: Option<&str>) -> Result<(), String> {
        let at = |e: String| format!("{}: {e}", dir.display());
        match std::fs::symlink_metadata(dir) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(at(
                    "it is a link; the node's folders are folders, and install does not follow it"
                        .into(),
                ));
            }
            Ok(m) if !m.is_dir() => return Err(at("it is not a folder".into())),
            Ok(_) => {}
            Err(_) => std::fs::create_dir_all(dir).map_err(|e| at(e.to_string()))?,
        }
        let owner = owner
            .map(sid_of)
            .transpose()?
            .map(|s| sid_text(&s))
            .transpose()?;
        let text = wide(dacl_text(owner.as_deref()));
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: a NUL-terminated SDDL string; the descriptor is freed below.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(at(last()));
        }
        let (mut present, mut defaulted) = (0, 0);
        let mut dacl = std::ptr::null_mut();
        // SAFETY: the descriptor just made; the DACL points into it.
        let r = unsafe {
            if GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) == 0 {
                Err(last())
            } else {
                // Inheritable entries go down to what is below.
                let r = SetNamedSecurityInfoW(
                    wide(dir).as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    dacl,
                    std::ptr::null(),
                );
                if r == 0 { Ok(()) } else { Err(os(r)) }
            }
        };
        // SAFETY: the descriptor from the conversion, freed once.
        unsafe { LocalFree(sd) };
        r.map_err(at)
    }

    fn service(&self) -> Result<Option<bool>, String> {
        let Some(s) = Scm::open(SC_MANAGER_CONNECT)?.service(SERVICE_QUERY_STATUS)? else {
            return Ok(None);
        };
        Ok(Some(s.status()?.dwCurrentState != SERVICE_STOPPED))
    }

    fn service_state(&self) -> Result<Option<ServiceState>, String> {
        let access = SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG;
        let Some(s) = Scm::open(SC_MANAGER_CONNECT)?.service(access)? else {
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
        let bin = wide(format!(
            "\"{}\" --config-dir \"{}\" --state-dir \"{}\" run",
            layout.bin.display(),
            layout.paths.config_dir.display(),
            layout.paths.state_dir.display()
        ));
        let user = wide(format!(".\\{USER}"));
        let password = wide(password);
        let name = wide(SERVICE_NAME);
        let shown = wide("Nerve node");
        let m = Scm::open(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
        let s = match m.service(SERVICE_ALL_ACCESS)? {
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
                        std::ptr::null(),
                        user.as_ptr(),
                        password.as_ptr(),
                        shown.as_ptr(),
                    )
                };
                if ok == 0 {
                    return Err(format!(
                        "cannot change the service {SERVICE_NAME}: {}",
                        last()
                    ));
                }
                s
            }
            None => {
                // SAFETY: an open manager and NUL-terminated strings.
                let h = unsafe {
                    CreateServiceW(
                        m.0,
                        name.as_ptr(),
                        shown.as_ptr(),
                        SERVICE_ALL_ACCESS,
                        SERVICE_WIN32_OWN_PROCESS,
                        SERVICE_AUTO_START,
                        SERVICE_ERROR_NORMAL,
                        bin.as_ptr(),
                        std::ptr::null(),
                        std::ptr::null_mut(),
                        std::ptr::null(),
                        user.as_ptr(),
                        password.as_ptr(),
                    )
                };
                if h.is_null() {
                    return Err(format!(
                        "cannot register the service {SERVICE_NAME}: {}",
                        last()
                    ));
                }
                Scm(h)
            }
        };
        let mut about = wide(concat!(
            "Links this machine to its Nerve centers. ",
            env!("CARGO_PKG_REPOSITORY")
        ));
        let description = SERVICE_DESCRIPTIONW {
            lpDescription: about.as_mut_ptr(),
        };
        // Started again 5 seconds after a failure, three times a day at most.
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
        let mut privileges: Vec<u16> = SERVICE_PRIVILEGES
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
                    "cannot set {what} of the service {SERVICE_NAME}: {}",
                    last()
                ));
            }
        }
        Ok(())
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
        // SAFETY: plain data that the call fills.
        let mut st: SERVICE_STATUS = unsafe { std::mem::zeroed() };
        // SAFETY: an open service and a place for its status.
        if unsafe { ControlService(s.0, SERVICE_CONTROL_STOP, &mut st) } == 0 {
            // SAFETY: plain getter, right after the call.
            let e = unsafe { GetLastError() };
            if e != ERROR_SERVICE_NOT_ACTIVE {
                return Err(format!("cannot stop the service {SERVICE_NAME}: {}", os(e)));
            }
        }
        let until = Instant::now() + Duration::from_secs(60);
        while s.status()?.dwCurrentState != SERVICE_STOPPED {
            if Instant::now() > until {
                return Err(format!(
                    "the service {SERVICE_NAME} did not stop within a minute"
                ));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        Ok(())
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

    fn owners(&self) -> Result<Vec<String>, String> {
        owners()
    }

    fn put_owners(&self, sids: &[String]) -> Result<(), String> {
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
        use windows_sys::Win32::System::Registry::REG_MULTI_SZ;
        // A list of strings, each ended by a NUL, and one NUL more.
        let data: Vec<u16> = sids
            .iter()
            .flat_map(|s| s.encode_utf16().chain(Some(0)))
            .chain(Some(0))
            .collect();
        // SAFETY: NUL-terminated names and data of the size given; the key
        // is made when it is missing.
        let r = unsafe {
            RegSetKeyValueW(
                HKEY_LOCAL_MACHINE,
                wide(parameters_key()).as_ptr(),
                wide(crate::owner::OWNERS_VALUE).as_ptr(),
                REG_MULTI_SZ,
                data.as_ptr().cast(),
                (data.len() * 2) as u32,
            )
        };
        if r != 0 {
            return Err(format!("cannot write the owners of the service: {}", os(r)));
        }
        let s = the_service()?;
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: a NUL-terminated SDDL string; the descriptor is freed
        // below.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(crate::winsvc::service_dacl(sids)).as_ptr(),
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
        let file = wide(&layout.bin);
        // The node writes errors and information, nothing else.
        let types = u32::from(EVENTLOG_ERROR_TYPE | EVENTLOG_INFORMATION_TYPE);
        for (name, kind, data, len) in [
            (
                "EventMessageFile",
                REG_SZ,
                file.as_ptr().cast(),
                (file.len() * 2) as u32,
            ),
            ("TypesSupported", REG_DWORD, (&raw const types).cast(), 4),
        ] {
            // SAFETY: NUL-terminated key and value names; data of the length
            // given (the path with its NUL, or a DWORD). The key is made when
            // it is missing.
            let r = unsafe {
                RegSetKeyValueW(
                    HKEY_LOCAL_MACHINE,
                    wide(SOURCE_KEY).as_ptr(),
                    wide(name).as_ptr(),
                    kind,
                    data,
                    len,
                )
            };
            if r != 0 {
                return Err(format!(
                    "cannot register the source {SOURCE} in the Windows Event Log: {}",
                    os(r)
                ));
            }
        }
        Ok(())
    }

    fn delete_event_source(&self) -> Result<bool, String> {
        // SAFETY: a NUL-terminated key name; the key has values only.
        match unsafe { RegDeleteKeyW(HKEY_LOCAL_MACHINE, wide(SOURCE_KEY).as_ptr()) } {
            0 => Ok(true),
            ERROR_FILE_NOT_FOUND => Ok(false),
            r => Err(format!(
                "cannot remove the source {SOURCE} from the Windows Event Log: {}",
                os(r)
            )),
        }
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
            return Err("no password given".into());
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

    /// The DACL of the node's folders names nerve, SYSTEM and the
    /// administrators, and nothing from the folders above.
    #[test]
    fn the_folders_get_a_dacl_of_their_own() {
        assert_eq!(
            dacl_text(Some("S-1-5-21-1-2-3-1010")),
            "D:P(A;OICI;FA;;;S-1-5-21-1-2-3-1010)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        );
        assert_eq!(dacl_text(None), "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
    }

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
    /// junction in place of the folder is refused. Needs an administrator.
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
        WinHost.secure(&top, Some(&me)).unwrap();
        let acl = icacls(&top.join("sub/f"));
        assert!(acl.contains(&format!("\\{me}:(I)(F)")), "{acl}");
        assert_eq!(acl.lines().filter(|l| l.contains(":(")).count(), 3, "{acl}");
        assert_eq!(icacls(&outside.join("f")), before);
        junction(&d.path().join("link"), &outside);
        let e = WinHost.secure(&d.path().join("link"), None).unwrap_err();
        assert!(e.contains("is a link"), "{e}");
        assert_eq!(icacls(&outside.join("f")), before);
    }

    /// DPAPI gives back what it sealed, and the sealed bytes are not the
    /// text.
    #[test]
    fn dpapi_round_trip() {
        let plain = crate::winsvc::secret("alice", "not a real password");
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
}
