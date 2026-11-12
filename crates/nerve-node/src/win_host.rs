//! The Windows calls behind `install`, `update` and `uninstall`
//! ([`crate::winsvc::WinSystem`]): the local account `nerve` and its rights,
//! the folders' DACL, the service control manager, DPAPI and the logon of
//! the account the commands run as.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_SHARING_VIOLATION, GetLastError, STATUS_SUCCESS,
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
use windows_sys::Win32::Security::PSID;
use windows_sys::Win32::System::Console::{
    ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
};
use windows_sys::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, REG_DWORD, RegDeleteKeyValueW, RegSetKeyValueW,
};
use windows_sys::Win32::System::Services::{
    SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
};

use nerve_service::win::scm::Scm;
use nerve_service::win::service::{self as svc, Settings, Spec};
pub use nerve_service::win::sid::is_admin;
pub(crate) use nerve_service::win::sid::{sid_of, sid_text};

use crate::eventlog::{SOURCE, SOURCE_KEY};
use crate::service::{Account, Layout, ServiceState, USER, USER_MARK};
use crate::win_user::{self, wide};
use crate::winsvc::{ASIDE, Kind, PROFILE_SERVICE, SERVICE_NAME, WinSystem, registered_settings};

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

/// Where Windows keeps the accounts it does not show on the sign-in screen.
const HIDDEN: &str =
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList";

fn os(code: u32) -> String {
    std::io::Error::from_raw_os_error(code as i32).to_string()
}

/// Whether the service is registered, as anyone may ask.
pub fn service_registered() -> bool {
    svc::registered(SERVICE_NAME)
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
        svc::put(&Spec {
            name: PROFILE_SERVICE,
            shown: "Nerve commands' profile",
            about: "Keeps the profile of nerve-run loaded, where the AppContainers of Nerve's commands keep theirs.",
            line: &format!(
                "\"{}\" {}",
                layout.bin.display(),
                crate::win_profile::PROFILE_ARG
            ),
            logon: Some((name, password)),
            settings: &registered_settings(PROFILE_SERVICE),
        })?;
        svc::start(PROFILE_SERVICE)
    }

    fn delete_profile_service(&self) -> Result<bool, String> {
        if !svc::registered(PROFILE_SERVICE) {
            return Ok(false);
        }
        svc::stop(PROFILE_SERVICE)?;
        svc::delete(PROFILE_SERVICE)?;
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

    fn nothing_foreign_below(&self, dir: &Path, node_sid: &str) -> Result<(), String> {
        // The node's own account, and the accounts deleted since (the node
        // made them, and a kept folder still names them), may own what is
        // below; a live account of someone else may not.
        let allowed = |owner: &[u8]| {
            nerve_service::win::sid::sid_text(owner).is_ok_and(|text| {
                text == node_sid || matches!(win_user::lookup_sid(&text), Ok(None))
            })
        };
        match nerve_service::win::dacl::foreign_below(dir, allowed)? {
            None => Ok(()),
            Some((path, owner)) => {
                let who = nerve_service::win::sid::sid_text(&owner).unwrap_or_else(|e| e);
                Err(format!(
                    "{}: another account ({who}) owns it, and could open it again; delete it, then install again",
                    path.display()
                ))
            }
        }
    }

    fn machine_sid(&self) -> Result<String, String> {
        win_user::machine_sid()
    }

    fn service(&self) -> Result<Option<bool>, String> {
        Ok(svc::state(SERVICE_NAME)?.map(|s| s.state != "stopped" && s.state != "failed"))
    }

    fn service_state(&self) -> Result<Option<ServiceState>, String> {
        Ok(svc::state(SERVICE_NAME)?.map(|s| ServiceState {
            state: s.state,
            enabled: s.automatic,
        }))
    }

    fn put_service(&self, layout: &Layout, password: &str) -> Result<(), String> {
        svc::put(&Spec {
            name: SERVICE_NAME,
            shown: "Nerve node",
            about: concat!(
                "Links this machine to its Nerve centers. ",
                env!("CARGO_PKG_REPOSITORY")
            ),
            line: &format!(
                "\"{}\" --config-dir \"{}\" --state-dir \"{}\" run",
                layout.bin.display(),
                layout.paths.config_dir.display(),
                layout.paths.state_dir.display()
            ),
            logon: Some((USER, password)),
            settings: &registered_settings(SERVICE_NAME),
        })
    }

    fn start(&self) -> Result<(), String> {
        svc::start(SERVICE_NAME)
    }

    fn stop(&self) -> Result<(), String> {
        svc::stop(SERVICE_NAME)
    }

    fn owner_sid(&self) -> Option<(String, String)> {
        crate::winsvc::app_or_own_owner(
            crate::cli::desktop_user(),
            |sid| win_user::name_of_sid(sid).ok(),
            || {
                let sid = sid_text(&win_user::own_sid().ok()?).ok()?;
                Some((sid, win_user::current_user().ok()?))
            },
        )
    }

    fn owner(&self) -> Result<Option<(String, String)>, String> {
        let Some(sid) = owner()? else {
            return Ok(None);
        };
        let name = win_user::name_of_sid(&sid).unwrap_or_else(|_| sid.clone());
        Ok(Some((sid, name)))
    }

    fn put_owner(&self, sid: &str) -> Result<(), String> {
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
        svc::set_dacl(SERVICE_NAME, &crate::winsvc::service_dacl(Some(sid)))
    }

    fn stage_vault(&self, paths: &crate::paths::NodePaths) -> Result<u64, String> {
        crate::secrets::vault::stage_in_service(paths)
    }

    fn delete_service(&self) -> Result<(), String> {
        svc::delete(SERVICE_NAME)
    }

    fn put_event_source(&self, layout: &Layout) -> Result<(), String> {
        nerve_service::win::event::put_source(SOURCE_KEY, SOURCE, &layout.bin)
    }

    fn delete_event_source(&self) -> Result<bool, String> {
        nerve_service::win::event::delete_source(SOURCE_KEY, SOURCE)
    }

    fn wait_running(&self, layout: &Layout) -> Result<(), String> {
        svc::wait_running(SERVICE_NAME, &layout.paths.log_file().display().to_string())
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
        let read = r.map_err(|e| e.to_string())?;
        let password = crate::winsvc::password_of_line(read, &line);
        line.clear();
        password
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
        output_of(program, &["--version"])
    }

    fn settings_of(&self, program: &Path, args: &[String]) -> Result<String, String> {
        let mut all = vec![nerve_service::SERVICE_FILES];
        all.extend(args.iter().map(String::as_str));
        output_of(program, &all)
    }

    fn configure_service(&self, name: &str, s: &Settings) -> Result<(), String> {
        svc::configure(name, s)
    }

    fn remove_program(&self, path: &Path) -> Result<bool, String> {
        nerve_service::win::update::remove_program(path, ASIDE)
    }

    fn remove_grants(
        &self,
        paths: &crate::paths::NodePaths,
        node_ids: &[String],
    ) -> crate::grants::Synced {
        crate::grants::remove_all(paths, node_ids, &mut |m| eprintln!("{m}"))
    }
}

/// What `<program> <args>` prints, run without the administrators' rights
/// and with a bare environment (nerve_service::win::restricted::output_of).
fn output_of(program: &Path, args: &[&str]) -> Result<String, String> {
    let line = format!("{} {}", program.display(), args.join(" "));
    let (code, out) =
        nerve_service::win::restricted::output_of(program, args, Duration::from_secs(30))
            .map_err(|e| format!("{line}: {e}"))?;
    if code != 0 {
        return Err(format!("{line}: exit code {code}"));
    }
    Ok(String::from_utf8_lossy(&out).trim().to_string())
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
    /// own the folder. Needs an elevated administrator; the folder is given
    /// to the administrators first, since the built-in Administrator (CI)
    /// owns what it makes itself, which `secure` refuses.
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
        let given = std::process::Command::new("icacls")
            .arg(&top)
            .args(["/setowner", "*S-1-5-32-544"])
            .output()
            .unwrap();
        assert!(given.status.success(), "{given:?}");
        WinHost
            .secure(&top, &crate::winsvc::folder_dacl(Some(&sid)))
            .unwrap();
        let acl = icacls(&top.join("sub/f"));
        assert!(acl.contains(&format!("\\{me}:(I)(F)")), "{acl}");
        // The DACL's three entries are what the file inherits. An entry of
        // its own that the file got where it was made stays (CI's built-in
        // Administrator gets one from the runner's temp folder).
        assert_eq!(
            acl.lines().filter(|l| l.contains(":(I)")).count(),
            3,
            "{acl}"
        );
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

    /// A program run in a job, as the helper that asks a command of another
    /// account to end runs in the command's job (crate::win_stop), is ended
    /// with that job.
    #[test]
    fn a_program_run_in_a_job_ends_with_it() {
        let exe =
            std::env::var_os("ComSpec").unwrap_or_else(|| "C:\\Windows\\System32\\cmd.exe".into());
        let t = win_user::Token::from(nerve_service::win::restricted::restricted().unwrap());
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
