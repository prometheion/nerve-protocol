//! The account a center's commands run as on a node installed as a Windows
//! service (docs/dev/windows.md). The service runs as `nerve`, which alone
//! (with SYSTEM and the administrators) may open the node's config, keys and
//! state; every command runs as the owner instead, the account that ran
//! `install`, logged on with the password `install` stored with DPAPI in the
//! config folder ([`crate::winsvc::SECRET_FILE`]). To start a process with that
//! account's token the service keeps two privileges,
//! SeAssignPrimaryTokenPrivilege and SeIncreaseQuotaPrivilege; the command
//! gets none of them, since it gets the account's own token.
//!
//! The node's own file work for a center (`fs`, and the checks of a call's
//! paths) runs while the thread impersonates that account ([`FsAs`]), as
//! Linux switches the thread's file system ids.

use std::io;
use std::marker::PhantomData;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCOUNT_RESTRICTION, ERROR_LOGON_FAILURE, ERROR_LOGON_TYPE_NOT_GRANTED,
    ERROR_NOT_ALL_ASSIGNED, ERROR_SHARING_VIOLATION, GENERIC_READ, GetLastError, HANDLE,
    HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, LUID, LocalFree, SetHandleInformation,
    WAIT_OBJECT_0,
};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    LG_INCLUDE_INDIRECT, LOCALGROUP_USERS_INFO_0, NERR_UserNotFound, NetApiBufferFree,
    NetUserGetInfo, NetUserGetLocalGroups, USER_INFO_23,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    CryptUnprotectData,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, EqualSid, GetLengthSid,
    GetSecurityDescriptorDacl, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation,
    ImpersonateLoggedOnUser, IsWellKnownSid, LOGON32_LOGON, LOGON32_LOGON_BATCH,
    LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, LUID_AND_ATTRIBUTES, LogonUserW,
    LookupAccountSidW, LookupPrivilegeValueW, PSECURITY_DESCRIPTOR, PSID, RevertToSelf,
    SE_PRIVILEGE_ENABLED, SECURITY_ATTRIBUTES, SID_AND_ATTRIBUTES, SID_NAME_USE,
    SetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_PRIVILEGES, TOKEN_ASSIGN_PRIMARY,
    TOKEN_DEFAULT_DACL, TOKEN_DUPLICATE, TOKEN_GROUPS, TOKEN_IMPERSONATE, TOKEN_INFORMATION_CLASS,
    TOKEN_OWNER, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER, TokenDefaultDacl, TokenGroups,
    TokenOwner, TokenPrivileges, TokenUser, WinBuiltinAdministratorsSid,
    WinBuiltinBackupOperatorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_DATA,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFinalPathNameByHandleW, OPEN_EXISTING,
};
use windows_sys::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ, RegGetValueW,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
    GetCurrentThread, GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList,
    OpenProcessToken, OpenThreadToken, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION,
    ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, SetThreadToken, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject,
};
use windows_sys::Win32::System::WindowsProgramming::GetUserNameW;

pub(crate) use nerve_service::win::sid::{from_wide, well_known_sid, wide};

use crate::service::Account;

/// How long a logon of the command account is used before the node logs
/// it on again: a password changed meanwhile then shows within this time.
const FRESH: Duration = Duration::from_secs(300);

/// The most entries [`reach`] looks at below the node's folders.
const REACH_MAX: usize = 4096;

/// What DPAPI mixes into the stored password, so that a blob of another
/// program's does not pass for it.
const ENTROPY: &[u8] = b"nerve-node: the password of the account commands run as";

fn last() -> io::Error {
    io::Error::last_os_error()
}

/// The last error, said with the call that failed.
fn failed(call: &str) -> io::Error {
    let e = last();
    io::Error::new(e.kind(), format!("{call}: {e}"))
}

/// An access token, closed when dropped.
pub struct Token(OwnedHandle);

impl Token {
    pub(crate) fn raw(&self) -> HANDLE {
        self.0.as_raw_handle() as HANDLE
    }
}

/// This process's own token, opened with `access`.
fn process_token(access: u32) -> io::Result<Token> {
    let mut h: HANDLE = std::ptr::null_mut();
    // SAFETY: the pseudo handle of this process and a place for the token.
    if unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut h) } == 0 {
        return Err(last());
    }
    // SAFETY: OpenProcessToken returned a handle this code now owns.
    Ok(Token(unsafe { OwnedHandle::from_raw_handle(h as _) }))
}

/// One class of information about `t`, in a buffer aligned for the
/// structures Windows writes into it.
fn token_info(t: HANDLE, class: TOKEN_INFORMATION_CLASS) -> io::Result<Vec<u64>> {
    let mut len = 0u32;
    // SAFETY: a null buffer of length 0 asks for the length only.
    unsafe { GetTokenInformation(t, class, std::ptr::null_mut(), 0, &mut len) };
    if len == 0 {
        return Err(last());
    }
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: the buffer holds `len` bytes.
    if unsafe { GetTokenInformation(t, class, buf.as_mut_ptr().cast(), len, &mut len) } == 0 {
        return Err(last());
    }
    Ok(buf)
}

/// The last part of a SID: the account's number on its machine.
///
/// # Safety
/// `sid` is a valid SID.
unsafe fn rid(sid: PSID) -> u32 {
    // SAFETY: as the caller says.
    unsafe {
        let n = *GetSidSubAuthorityCount(sid);
        if n == 0 {
            0
        } else {
            *GetSidSubAuthority(sid, u32::from(n) - 1)
        }
    }
}

/// The name of the account whose SID is `text` (`S-1-5-21-…`).
pub fn name_of_sid(text: &str) -> Result<String, String> {
    let mut sid: PSID = std::ptr::null_mut();
    // SAFETY: a NUL-terminated string; the SID Windows allocates is copied
    // and freed.
    let bytes = unsafe {
        if ConvertStringSidToSidW(wide(text).as_ptr(), &mut sid) == 0 {
            return Err(format!("{text} is not a SID: {}", last()));
        }
        let bytes =
            std::slice::from_raw_parts(sid as *const u8, GetLengthSid(sid) as usize).to_vec();
        LocalFree(sid as _);
        bytes
    };
    sid_name(&bytes).map_err(|e| format!("no account has the SID {text}: {e}"))
}

/// Runs `f` on this thread as this process, also where the thread acts as
/// another account ([`FsAs`]), and then as that account again: the node's
/// own state folder is open to the node, not to the owner it acts as. An
/// error where the thread cannot act as that account again; it is then
/// itself, which [`FsAs`]'s end leaves it as anyway.
pub fn as_process<T>(f: impl FnOnce() -> T) -> io::Result<T> {
    use windows_sys::Win32::Foundation::ERROR_NO_TOKEN;
    use windows_sys::Win32::Security::TOKEN_IMPERSONATE;
    use windows_sys::Win32::System::Threading::{
        GetCurrentThread, OpenThreadToken, SetThreadToken,
    };
    let mut h: HANDLE = std::ptr::null_mut();
    // SAFETY: the thread's own token, opened as the process, owned below.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_IMPERSONATE, 1, &mut h) } == 0 {
        let e = last();
        if e.raw_os_error() == Some(ERROR_NO_TOKEN as i32) {
            return Ok(f());
        }
        return Err(e);
    }
    // SAFETY: OpenThreadToken returned a handle this code now owns.
    let was = Token(unsafe { OwnedHandle::from_raw_handle(h as _) });
    // SAFETY: plain call; the thread is itself until the token goes back.
    unsafe { RevertToSelf() };
    let r = f();
    // SAFETY: the thread's own token, opened above.
    if unsafe { SetThreadToken(std::ptr::null(), was.raw()) } == 0 {
        return Err(failed("SetThreadToken"));
    }
    Ok(r)
}

/// The profile folder of the account whose SID is `text`, where Windows
/// keeps it; `None` before its first logon, and for a text that is no SID.
pub fn profile_of_sid(text: &str) -> Option<PathBuf> {
    let mut sid: PSID = std::ptr::null_mut();
    // SAFETY: a NUL-terminated string; the SID Windows allocates is freed
    // once it was read.
    unsafe {
        if ConvertStringSidToSidW(wide(text).as_ptr(), &mut sid) == 0 {
            return None;
        }
        let dir = profile_dir(sid);
        LocalFree(sid as _);
        dir
    }
}

/// The name an account or group has on this machine, by its SID.
fn sid_name(sid: &[u8]) -> io::Result<String> {
    let mut name = vec![0u16; 256];
    let mut domain = vec![0u16; 256];
    let (mut n, mut d) = (name.len() as u32, domain.len() as u32);
    let mut kind: SID_NAME_USE = 0;
    // SAFETY: a valid SID and two buffers of the sizes given.
    let ok = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid.as_ptr() as PSID,
            name.as_mut_ptr(),
            &mut n,
            domain.as_mut_ptr(),
            &mut d,
            &mut kind,
        )
    };
    if ok == 0 {
        return Err(last());
    }
    // SAFETY: LookupAccountSidW wrote a NUL-terminated name.
    Ok(unsafe { from_wide(name.as_ptr()) })
}

/// The number this process's account has, as Linux has its uid: the last
/// part of its SID. SYSTEM is 0, as root is.
pub fn own_uid() -> u32 {
    let Ok(t) = process_token(TOKEN_QUERY) else {
        return 0;
    };
    let Ok(buf) = token_info(t.raw(), TokenUser) else {
        return 0;
    };
    // SAFETY: the buffer holds a TOKEN_USER, whose SID points into it.
    unsafe {
        let sid = (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid;
        if IsWellKnownSid(sid, WinLocalSystemSid) != 0 {
            return 0;
        }
        rid(sid)
    }
}

/// The token this thread acts with now (one it impersonates), for a query.
pub(crate) fn thread_token() -> io::Result<Token> {
    let mut h: HANDLE = std::ptr::null_mut();
    // SAFETY: this thread's pseudo handle and a place for the token, opened
    // with the process's own rights (`OpenAsSelf`).
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut h) } == 0 {
        return Err(last());
    }
    // SAFETY: OpenThreadToken returned a handle this code now owns.
    Ok(Token(unsafe { OwnedHandle::from_raw_handle(h as _) }))
}

/// The SID of the account of `t`, as text.
pub(crate) fn token_sid(t: &Token) -> io::Result<String> {
    let buf = token_info(t.raw(), TokenUser)?;
    // SAFETY: the buffer holds a TOKEN_USER, whose SID points into it; the
    // SID is copied while the buffer lives.
    let sid = unsafe {
        let sid = (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid;
        let len = GetLengthSid(sid) as usize;
        std::slice::from_raw_parts(sid.cast::<u8>(), len).to_vec()
    };
    crate::win_host::sid_text(&sid).map_err(io::Error::other)
}

/// The SID of the account this process runs as.
pub(crate) fn own_sid() -> io::Result<Vec<u8>> {
    let t = process_token(TOKEN_QUERY)?;
    let buf = token_info(t.raw(), TokenUser)?;
    // SAFETY: the buffer holds a TOKEN_USER, whose SID points into it; the
    // SID is copied while the buffer lives.
    unsafe {
        let sid = (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid;
        let len = GetLengthSid(sid) as usize;
        Ok(std::slice::from_raw_parts(sid.cast::<u8>(), len).to_vec())
    }
}

/// The SID of this machine's own accounts (`S-1-5-21-…`), as its security
/// policy names it: every local account's SID is it and the account's
/// number, an account of a domain or of Microsoft Entra ID has another.
pub fn machine_sid() -> Result<String, String> {
    use windows_sys::Win32::Foundation::STATUS_SUCCESS;
    use windows_sys::Win32::Security::Authentication::Identity::{
        LSA_HANDLE, LSA_OBJECT_ATTRIBUTES, LsaClose, LsaFreeMemory, LsaNtStatusToWinError,
        LsaOpenPolicy, LsaQueryInformationPolicy, POLICY_ACCOUNT_DOMAIN_INFO,
        POLICY_VIEW_LOCAL_INFORMATION, PolicyAccountDomainInformation,
    };
    static SID: OnceLock<String> = OnceLock::new();
    if let Some(s) = SID.get() {
        return Ok(s.clone());
    }
    let said = |st| {
        // SAFETY: plain conversion.
        let code = unsafe { LsaNtStatusToWinError(st) };
        format!(
            "cannot read the SID of this machine: {}",
            io::Error::from_raw_os_error(code as i32)
        )
    };
    // SAFETY: zeroed object attributes are what LsaOpenPolicy takes.
    let attrs: LSA_OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed() };
    let mut policy: LSA_HANDLE = 0;
    // SAFETY: this machine's policy, a place for the handle; every account
    // may read this part of it.
    let st = unsafe {
        LsaOpenPolicy(
            std::ptr::null(),
            &attrs,
            POLICY_VIEW_LOCAL_INFORMATION as u32,
            &mut policy,
        )
    };
    if st != STATUS_SUCCESS {
        return Err(said(st));
    }
    let mut buf: *mut std::ffi::c_void = std::ptr::null_mut();
    // SAFETY: an open policy and a place for the buffer, which LSA
    // allocates; its SID is copied before it is freed, and the policy is
    // closed once.
    let sid = unsafe {
        let st = LsaQueryInformationPolicy(policy, PolicyAccountDomainInformation, &mut buf);
        LsaClose(policy);
        if st != STATUS_SUCCESS {
            return Err(said(st));
        }
        let sid = (*buf.cast::<POLICY_ACCOUNT_DOMAIN_INFO>()).DomainSid;
        let bytes =
            std::slice::from_raw_parts(sid.cast::<u8>(), GetLengthSid(sid) as usize).to_vec();
        LsaFreeMemory(buf);
        bytes
    };
    let text = crate::win_host::sid_text(&sid)?;
    Ok(SID.get_or_init(|| text).clone())
}

/// The name of the account this process runs as.
pub fn current_user() -> Result<String, String> {
    let mut buf = vec![0u16; 257];
    let mut n = buf.len() as u32;
    // SAFETY: a buffer of the size given.
    if unsafe { GetUserNameW(buf.as_mut_ptr(), &mut n) } == 0 {
        return Err(format!("cannot read the name of this account: {}", last()));
    }
    // SAFETY: GetUserNameW wrote a NUL-terminated name.
    Ok(unsafe { from_wide(buf.as_ptr()) })
}

/// Looks `name` up among the local accounts of this machine. `uid` is the
/// last part of its SID, `home` its profile folder. A name is taken as
/// Windows names accounts: with blanks and letters beyond ASCII.
pub fn lookup(name: &str) -> Result<Option<Account>, String> {
    if !nerve_policy::config::valid_windows_account_name(name) {
        return Err(format!("{name:?} is not an account name"));
    }
    let mut buf: *mut u8 = std::ptr::null_mut();
    // SAFETY: the local machine, a NUL-terminated name and a place for the
    // buffer, which NetApiBufferFree frees below.
    let r = unsafe { NetUserGetInfo(std::ptr::null(), wide(name).as_ptr(), 23, &mut buf) };
    if r == NERR_UserNotFound {
        return Ok(None);
    }
    if r != 0 {
        return Err(format!(
            "cannot look up the account {name}: {}",
            io::Error::from_raw_os_error(r as i32)
        ));
    }
    // SAFETY: level 23 fills a USER_INFO_23, whose strings and SID live in
    // the same buffer until it is freed.
    let a = unsafe {
        let info = &*(buf as *const USER_INFO_23);
        let uid = rid(info.usri23_user_sid);
        let found = from_wide(info.usri23_name);
        let home = profile_dir(info.usri23_user_sid).unwrap_or_else(|| {
            // The Windows folder's drive, not the variable's.
            let windows = nerve_service::win::folders::windows_dir();
            let drive = nerve_service::win::folders::drive_of(&windows.to_string_lossy());
            PathBuf::from(format!("{drive}\\Users")).join(&found)
        });
        Account {
            name: found,
            uid,
            gid: uid,
            comment: from_wide(info.usri23_comment),
            home,
            groups: Vec::new(),
        }
    };
    // SAFETY: the buffer NetUserGetInfo allocated, freed once.
    unsafe { NetApiBufferFree(buf.cast()) };
    Ok(Some(a))
}

/// The local account whose SID is `sid`, found by its name and taken only
/// where it has that SID (crate::winsvc::owner_by_sid): the owner the
/// service's key names is that SID, not whichever account has its name. An
/// owner of a domain or of Microsoft Entra ID is refused by its SID.
pub fn lookup_sid(sid: &str) -> Result<Option<Account>, String> {
    let machine = machine_sid()?;
    if crate::winsvc::local_rid(sid, &machine).is_none() {
        let name = name_of_sid(sid).unwrap_or_else(|_| sid.to_string());
        return Err(crate::winsvc::not_local(&name));
    }
    let Ok(name) = name_of_sid(sid) else {
        return Ok(None);
    };
    crate::winsvc::owner_by_sid(sid, &name, &machine, lookup(&name)?)
}

/// The owner of the installed node, by the SID the service's key names
/// ([`lookup_sid`]); `None` where it names none.
pub fn service_owner() -> Result<Option<Account>, String> {
    match crate::win_host::owner()? {
        Some(sid) => lookup_sid(&sid),
        None => Ok(None),
    }
}

/// The profile folder of the account with `sid`, where Windows keeps it;
/// `None` before its first logon.
///
/// # Safety
/// `sid` is a valid SID.
pub(crate) unsafe fn profile_dir(sid: PSID) -> Option<PathBuf> {
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: as the caller says; the string is freed with LocalFree.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return None;
    }
    // SAFETY: a NUL-terminated string from ConvertSidToStringSidW, freed once.
    let sid = unsafe {
        let s = from_wide(text);
        LocalFree(text.cast());
        s
    };
    let key = wide(format!(
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{sid}"
    ));
    let value = wide("ProfileImagePath");
    let mut len = 0u32;
    let flags = RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ;
    // SAFETY: a null buffer asks for the size, the second call fills one of
    // that size; an expandable string comes back expanded.
    unsafe {
        if RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            flags,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut len,
        ) != 0
        {
            return None;
        }
        let mut buf = vec![0u16; (len as usize).div_ceil(2) + 1];
        let mut len = (buf.len() * 2) as u32;
        if RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            flags,
            std::ptr::null_mut(),
            buf.as_mut_ptr().cast(),
            &mut len,
        ) != 0
        {
            return None;
        }
        let p = from_wide(buf.as_ptr());
        (!p.is_empty()).then(|| PathBuf::from(p))
    }
}

/// The groups of `account` whose members can read every file on the
/// machine, the node's keys included: Administrators (with UAC, which is
/// no security boundary, a command can rise to them) and Backup Operators.
pub fn admin_groups(account: &Account) -> Vec<String> {
    let wanted: Vec<String> = [WinBuiltinAdministratorsSid, WinBuiltinBackupOperatorsSid]
        .into_iter()
        .filter_map(|k| sid_name(&well_known_sid(k).ok()?).ok())
        .collect();
    let mut buf: *mut u8 = std::ptr::null_mut();
    let (mut read, mut total) = (0u32, 0u32);
    // SAFETY: the local machine, a NUL-terminated name and places for the
    // buffer and its counts; the buffer is freed below.
    let r = unsafe {
        NetUserGetLocalGroups(
            std::ptr::null(),
            wide(&account.name).as_ptr(),
            0,
            LG_INCLUDE_INDIRECT,
            &mut buf,
            u32::MAX,
            &mut read,
            &mut total,
        )
    };
    if r != 0 || buf.is_null() {
        return Vec::new();
    }
    // SAFETY: `read` entries of LOCALGROUP_USERS_INFO_0 in the buffer.
    let groups: Vec<String> = unsafe {
        std::slice::from_raw_parts(buf as *const LOCALGROUP_USERS_INFO_0, read as usize)
            .iter()
            .map(|g| from_wide(g.lgrui0_name))
            .collect()
    };
    // SAFETY: the buffer NetUserGetLocalGroups allocated, freed once.
    unsafe { NetApiBufferFree(buf.cast()) };
    groups
        .into_iter()
        .filter(|g| wanted.iter().any(|w| w.eq_ignore_ascii_case(g)))
        .collect()
}

/// The LUID of a privilege by its name.
fn privilege(name: &str) -> io::Result<LUID> {
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    // SAFETY: the local machine, a NUL-terminated name, a place for the LUID.
    if unsafe { LookupPrivilegeValueW(std::ptr::null(), wide(name).as_ptr(), &mut luid) } == 0 {
        return Err(last());
    }
    Ok(luid)
}

/// The privileges that let the node start a process with another
/// account's token.
const SWITCH: [&str; 2] = ["SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege"];

/// Whether this process holds what starting a command as another account
/// takes: [`SWITCH`], as the installed service does, or SYSTEM.
pub fn can_switch() -> bool {
    if own_uid() == 0 {
        return true;
    }
    let Ok(t) = process_token(TOKEN_QUERY) else {
        return false;
    };
    let Ok(buf) = token_info(t.raw(), TokenPrivileges) else {
        return false;
    };
    let Ok(want) = SWITCH
        .iter()
        .map(|p| privilege(p))
        .collect::<io::Result<Vec<_>>>()
    else {
        return false;
    };
    // SAFETY: the buffer holds a TOKEN_PRIVILEGES with its count of entries.
    let held: Vec<LUID> = unsafe {
        let p = &*buf.as_ptr().cast::<TOKEN_PRIVILEGES>();
        std::slice::from_raw_parts(p.Privileges.as_ptr(), p.PrivilegeCount as usize)
            .iter()
            .map(|a| a.Luid)
            .collect()
    };
    want.iter().all(|w| {
        held.iter()
            .any(|h| h.LowPart == w.LowPart && h.HighPart == w.HighPart)
    })
}

/// Enables the privileges named in this process's token. One it does not
/// hold is an error.
pub(crate) fn enable(names: &[&str]) -> io::Result<()> {
    let t = process_token(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)?;
    for name in names {
        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: privilege(name)?,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        // SAFETY: an open token and one privilege to enable.
        let ok = unsafe {
            AdjustTokenPrivileges(
                t.raw(),
                0,
                &tp,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        // SAFETY: plain getter, right after the call.
        if ok == 0 || unsafe { GetLastError() } == ERROR_NOT_ALL_ASSIGNED {
            return Err(io::Error::other(format!(
                "this process does not hold {name}"
            )));
        }
    }
    Ok(())
}

/// Logs `name`, a local account, on with `password`, as a person at the
/// machine would be: an administrator gets the filtered token UAC gives
/// such a logon, without the Administrators group.
pub fn logon(name: &str, password: &str) -> Result<Token, String> {
    logon_as(name, password, LOGON32_LOGON_INTERACTIVE).map_err(|(why, _)| why)
}

/// Logs `name` on with `password` as a batch job, as the task scheduler
/// does for a task that runs with highest privileges: UAC filters no such
/// logon, so an administrator gets its full token, with the Administrators
/// group. What a sudo command starts with (crate::winsudo).
pub fn batch_logon(name: &str, password: &str) -> Result<Token, String> {
    logon_as(name, password, LOGON32_LOGON_BATCH).map_err(|(why, _)| why)
}

/// [`logon`], and whether a failure is the password's: the one Windows
/// counts toward a lockout.
fn logon_counted(name: &str, password: &str) -> Result<Token, (String, bool)> {
    logon_as(name, password, LOGON32_LOGON_INTERACTIVE)
}

fn logon_as(name: &str, password: &str, kind: LOGON32_LOGON) -> Result<Token, (String, bool)> {
    let mut h: HANDLE = std::ptr::null_mut();
    // SAFETY: NUL-terminated strings ("." is this machine) and a place for
    // the token.
    let ok = unsafe {
        LogonUserW(
            wide(name).as_ptr(),
            wide(".").as_ptr(),
            wide(password).as_ptr(),
            kind,
            LOGON32_PROVIDER_DEFAULT,
            &mut h,
        )
    };
    if ok == 0 {
        let e = last();
        let wrong = e.raw_os_error().map(|c| c as u32) == Some(ERROR_LOGON_FAILURE);
        return Err((
            match e.raw_os_error().map(|c| c as u32) {
                Some(ERROR_LOGON_FAILURE) => {
                    format!(
                        "the password of {name} is wrong, or {name} cannot log on with a password"
                    )
                }
                // Windows lets no program log on to an account without a
                // password, and none to one a policy restricts.
                Some(ERROR_ACCOUNT_RESTRICTION) => format!(
                    "Windows does not let {name} log on here: an account without a password cannot, nor one a policy restricts; {}",
                    crate::account::BLANK_PASSWORD_FIX
                ),
                // Administrators may log on as a batch job unless a policy
                // took it from them.
                Some(ERROR_LOGON_TYPE_NOT_GRANTED) if kind == LOGON32_LOGON_BATCH => format!(
                    "{name} may not log on as a batch job, which a sudo command needs; administrators have the right \"Log on as a batch job\" unless a policy takes it"
                ),
                _ => format!("cannot log {name} on: {e}"),
            },
            wrong,
        ));
    }
    // SAFETY: LogonUserW returned a token this code now owns.
    Ok(Token(unsafe { OwnedHandle::from_raw_handle(h as _) }))
}

/// Group attributes from winnt.h, which windows-sys keeps in a module the
/// node does not otherwise use.
const SE_GROUP_ENABLED: u32 = 0x4;
const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x10;

/// Whether `t` holds the Administrators group in effect: a full token of an
/// administrator, not one that UAC filtered, where the group only denies.
pub fn has_admins(t: &Token) -> io::Result<bool> {
    let admins = well_known_sid(WinBuiltinAdministratorsSid)?;
    let buf = token_info(t.raw(), TokenGroups)?;
    // SAFETY: the buffer holds a TOKEN_GROUPS with its count of entries,
    // whose SIDs point into it.
    unsafe {
        let g = &*buf.as_ptr().cast::<TOKEN_GROUPS>();
        Ok(
            std::slice::from_raw_parts(g.Groups.as_ptr(), g.GroupCount as usize)
                .iter()
                .any(|a| {
                    a.Attributes & SE_GROUP_ENABLED != 0
                        && a.Attributes & SE_GROUP_USE_FOR_DENY_ONLY == 0
                        && EqualSid(a.Sid, admins.as_ptr() as PSID) != 0
                }),
        )
    }
}

/// The sudo password of the owner that did not work, so that every sudo
/// command does not log on with it again (see [`crate::winsvc::sudo_attempt`]).
static STALE_SUDO: Mutex<crate::winsvc::StalePassword> =
    Mutex::new(crate::winsvc::StalePassword::default_const());

/// The token a sudo command of `name` starts with: its batch logon with
/// `password`, which must hold the Administrators group. A password that
/// Windows refused is not tried again until `sudo on` keeps another: every
/// wrong one counts toward locking the account.
pub fn sudo_token(name: &str, password: &str) -> Result<Token, String> {
    let t = crate::winsvc::sudo_attempt(
        &mut nerve_transport::sync::lock(&STALE_SUDO),
        name,
        password,
        || logon_as(name, password, LOGON32_LOGON_BATCH),
    )?;
    match has_admins(&t) {
        Ok(true) => Ok(t),
        Ok(false) => Err(crate::winsudo::not_admin(name)),
        Err(e) => Err(format!("cannot read the groups of {name}'s logon: {e}")),
    }
}

/// The thread acts as another account while this lives. It is not `Send`,
/// so it stays on its thread and cannot be held across an `.await`. The
/// policy's path resolve knows it ([`nerve_policy::paths::Acting`]): the node's
/// own account is refused a path it cannot look at to the end, an account it
/// acts as is not.
struct Impersonation(PhantomData<*const ()>, nerve_policy::paths::Acting);

impl Impersonation {
    fn new(t: &Token) -> io::Result<Impersonation> {
        // SAFETY: an open token; RevertToSelf in Drop ends it.
        if unsafe { ImpersonateLoggedOnUser(t.raw()) } == 0 {
            return Err(last());
        }
        Ok(Impersonation(
            PhantomData,
            nerve_policy::paths::Acting::begin(),
        ))
    }
}

impl Drop for Impersonation {
    fn drop(&mut self) {
        // SAFETY: plain call; the thread is itself again.
        unsafe { RevertToSelf() };
    }
}

/// The full name of `p` (`\\?\C:\…`), for [`nerve_policy::paths`] when
/// the account this thread acts as is refused it: Windows Server refuses a
/// pairing's AppContainer the name of a folder it may open (os error 5).
/// The path is opened as that account, so what it may not open stays
/// refused; only the name of that open object is asked for as the node,
/// which then acts as the account again.
pub fn name_as_self(p: &Path) -> io::Result<PathBuf> {
    use std::os::windows::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .access_mode(0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(p)?;
    let mut raw: HANDLE = std::ptr::null_mut();
    // SAFETY: this thread's token, opened with the node's own rights.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_IMPERSONATE, 1, &mut raw) } == 0 {
        return Err(last());
    }
    // SAFETY: a handle OpenThreadToken just gave.
    let acting = unsafe { OwnedHandle::from_raw_handle(raw as _) };
    // SAFETY: plain call; the thread acts again below.
    unsafe { RevertToSelf() };
    let name = final_name(&f);
    // SAFETY: the token this thread acted with a moment ago.
    if unsafe { SetThreadToken(std::ptr::null(), acting.as_raw_handle() as HANDLE) } == 0 {
        // A thread that cannot act as the account again would go on as the
        // node, which may open the node's keys: never.
        std::process::abort();
    }
    name
}

/// The full name of the object open as `f`, by its drive.
fn final_name(f: &std::fs::File) -> io::Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    let mut buf = vec![0u16; 512];
    loop {
        // SAFETY: an open handle and a buffer of the length given.
        let n = unsafe {
            GetFinalPathNameByHandleW(
                f.as_raw_handle() as HANDLE,
                buf.as_mut_ptr(),
                buf.len() as u32,
                0,
            )
        } as usize;
        if n == 0 {
            return Err(last());
        }
        if n < buf.len() {
            buf.truncate(n);
            return Ok(PathBuf::from(std::ffi::OsString::from_wide(&buf)));
        }
        buf.resize(n, 0);
    }
}

/// The first of the node's folders `own`, or of the entries below them,
/// that `t`'s account can open: list for a folder, read for a file. The
/// file system decides, as the account. Windows skips the check of the
/// folders on the way for every account, so a file is tried on its own as
/// well as its folder.
pub fn reach(t: &Token, own: &[PathBuf]) -> io::Result<Option<PathBuf>> {
    let mut all = Vec::new();
    for d in own {
        entries(d, &mut all, 0);
    }
    let _as = Impersonation::new(t)?;
    Ok(all.into_iter().find(|p| opens(p)))
}

/// `p` and what is below it, looked at as the node.
fn entries(p: &Path, all: &mut Vec<PathBuf>, depth: usize) {
    if all.len() >= REACH_MAX {
        return;
    }
    all.push(p.to_path_buf());
    let dir = std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir());
    if dir && depth < 8 {
        for e in std::fs::read_dir(p).into_iter().flatten().flatten() {
            entries(&e.path(), all, depth + 1);
        }
    }
}

/// Whether this thread may open `p` to read (or list) it. A file another
/// process holds without sharing was opened past the access check.
fn opens(p: &Path) -> bool {
    // SAFETY: a NUL-terminated path; the handle is closed at once.
    unsafe {
        let h = CreateFileW(
            wide(p).as_ptr(),
            FILE_READ_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        );
        if h != INVALID_HANDLE_VALUE {
            CloseHandle(h);
            return true;
        }
        GetLastError() == ERROR_SHARING_VIOLATION
    }
}

/// Makes the profile of `name`, whose logon `t` is, where Windows has none,
/// by loading it once: the folder and the registry Windows makes at the
/// first logon. Needs an administrator (`install`). Its folder.
pub fn make_profile(t: &Token, name: &str) -> io::Result<PathBuf> {
    use windows_sys::Win32::UI::Shell::{LoadUserProfileW, PROFILEINFOW, UnloadUserProfile};
    /// PI_NOUI: no message box when it fails.
    const PI_NOUI: u32 = 1;
    let mut user = wide(name);
    let mut info = PROFILEINFOW {
        dwSize: std::mem::size_of::<PROFILEINFOW>() as u32,
        dwFlags: PI_NOUI,
        lpUserName: user.as_mut_ptr(),
        ..Default::default()
    };
    // SAFETY: a logon token and a filled PROFILEINFOW whose name lives for
    // the call; the profile is unloaded below.
    if unsafe { LoadUserProfileW(t.raw(), &mut info) } == 0 {
        return Err(failed("LoadUserProfileW"));
    }
    // SAFETY: the token and the profile handle the load gave.
    unsafe { UnloadUserProfile(t.raw(), info.hProfile) };
    let buf = token_info(t.raw(), TokenUser)?;
    // SAFETY: the buffer holds a TOKEN_USER whose SID points into it.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    // SAFETY: a valid SID.
    unsafe { profile_dir(sid) }
        .ok_or_else(|| io::Error::other("Windows names no profile folder for it"))
}

/// Whether the account of `t` may read the registry key `key` below
/// `HKEY_USERS`: one that is not there (a hive not loaded) is not read.
pub fn opens_key(t: &Token, key: &str) -> io::Result<bool> {
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND};
    use windows_sys::Win32::System::Registry::{HKEY_USERS, KEY_READ, RegCloseKey, RegOpenKeyExW};
    let _as = Impersonation::new(t)?;
    let mut h = std::ptr::null_mut();
    // SAFETY: a NUL-terminated key name and a place for the handle, closed
    // below.
    let r = unsafe { RegOpenKeyExW(HKEY_USERS, wide(key).as_ptr(), 0, KEY_READ, &mut h) };
    match r {
        0 => {
            // SAFETY: the handle the call opened.
            unsafe { RegCloseKey(h) };
            Ok(true)
        }
        ERROR_ACCESS_DENIED | ERROR_FILE_NOT_FOUND => Ok(false),
        e => Err(io::Error::from_raw_os_error(e as i32)),
    }
}

/// `data` encrypted with DPAPI for this machine: any process here that
/// reads the file it is in can decrypt it, so the file's folder decides
/// who can. The node's folders are open to `nerve` and the administrators
/// only.
pub fn protect(data: &[u8]) -> io::Result<Vec<u8>> {
    crypt(data, true)
}

/// What [`protect`] encrypted.
pub fn unprotect(data: &[u8]) -> io::Result<Vec<u8>> {
    crypt(data, false)
}

fn crypt(data: &[u8], seal: bool) -> io::Result<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len()).map_err(io::Error::other)?,
        pbData: data.as_ptr().cast_mut(),
    };
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: ENTROPY.len() as u32,
        pbData: ENTROPY.as_ptr().cast_mut(),
    };
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // SAFETY: the blobs point to buffers of their sizes, which DPAPI only
    // reads; it allocates `out`, freed below with LocalFree.
    let ok = unsafe {
        if seal {
            CryptProtectData(
                &input,
                std::ptr::null(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        } else {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        }
    };
    if ok == 0 {
        return Err(last());
    }
    // SAFETY: DPAPI's buffer of `cbData` bytes; a decrypted one is wiped
    // before it is freed.
    unsafe {
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        if !seal {
            std::ptr::write_bytes(out.pbData, 0, out.cbData as usize);
        }
        LocalFree(out.pbData.cast());
        Ok(v)
    }
}

/// The config folder, where the daemon finds the stored passwords: set
/// once at its start.
static SECRET: OnceLock<PathBuf> = OnceLock::new();

/// The last logon of the command account, and when it was made.
static LOGON: Mutex<Option<(String, Instant, Arc<Token>)>> = Mutex::new(None);

/// The stored password of the owner that did not work, so that it is tried
/// once, not at every look at the folders' entries.
static STALE: Mutex<crate::winsvc::StalePassword> =
    Mutex::new(crate::winsvc::StalePassword::default_const());

/// Tells the commands where the stored passwords are: the config folder.
pub fn init(config_dir: &Path) {
    let _ = SECRET.set(config_dir.to_path_buf());
}

/// A logon of `account`, with the password `install` stored; one of the
/// owner's is kept for [`FRESH`]. The command account `nerve-run` logs on
/// as a batch job ([`run_logon`]), anew each time.
pub fn token_for(account: &Account) -> Result<Arc<Token>, String> {
    if account.name.eq_ignore_ascii_case(crate::account::RUN_USER) {
        return run_logon().map(Arc::new);
    }
    let mut cached = nerve_transport::sync::lock(&LOGON);
    if let Some((n, at, t)) = cached.as_ref()
        && *n == account.name
        && at.elapsed() < FRESH
    {
        return Ok(t.clone());
    }
    let again = crate::account::NO_ACCOUNT_INSTALL;
    let file = SECRET
        .get()
        .map(|d| d.join(crate::winsvc::SECRET_FILE))
        .ok_or_else(|| format!("no password of {} is stored; {again}", account.name))?;
    let blob = match std::fs::read(&file) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(format!(
                "no password of {} is stored; {again}",
                account.name
            ));
        }
        Err(e) => return Err(format!("{}: {e}", file.display())),
    };
    let plain = unprotect(&blob).map_err(|e| {
        format!(
            "the stored password of {} cannot be decrypted ({e}); {again}",
            account.name
        )
    })?;
    let stored = crate::winsvc::Secret::read(&plain)
        .map_err(|e| format!("the stored password cannot be read: {e}; {again}"))?;
    // The account by its SID, not by a name another account may have
    // since.
    let sid = crate::winsvc::local_sid(&machine_sid()?, account.uid);
    if stored.sid != sid {
        return Err(format!(
            "the stored password is {}'s, not {}'s; {again}",
            stored.name, account.name
        ));
    }
    // A password that failed stays failed until the owner saves another:
    // Windows locks the account after a few wrong ones, and every sync of
    // the folders' entries logs the owner on.
    let t = nerve_transport::sync::lock(&STALE)
        .attempt(&blob, || logon_counted(&account.name, &stored.password))
        .map_err(|e| format!("{e}; {again}"))?;
    let t = Arc::new(t);
    *cached = Some((account.name.clone(), Instant::now(), t.clone()));
    Ok(t)
}

/// What `status` says of the owner's stored password: missing, stale (a
/// logon refused it and it is not tried again) or stored
/// (crate::winsvc::owner_password_state).
pub fn owner_password_state() -> &'static str {
    let blob = SECRET
        .get()
        .and_then(|d| std::fs::read(d.join(crate::winsvc::SECRET_FILE)).ok());
    crate::winsvc::owner_password_state(blob.as_deref(), &nerve_transport::sync::lock(&STALE))
}

/// A logon of the command account `nerve-run` as a batch job, the logon its
/// commands start with, with the password `install` made and stored
/// ([`crate::winsvc::RUN_SECRET_FILE`]). Made anew for each command: each
/// gets the window station of a logon of its own, which no other pairing's
/// command shares (nerve_sandbox::appcontainer).
pub fn run_logon() -> Result<Token, String> {
    let name = crate::account::RUN_USER;
    let again = "install Nerve again with its installer, which makes it again";
    let file = SECRET
        .get()
        .map(|d| d.join(crate::winsvc::RUN_SECRET_FILE))
        .ok_or_else(|| format!("no password of {name} is stored; {again}"))?;
    let blob = std::fs::read(&file).map_err(|e| format!("{}: {e}; {again}", file.display()))?;
    let plain = unprotect(&blob)
        .map_err(|e| format!("the stored password of {name} cannot be decrypted ({e}); {again}"))?;
    let stored = crate::winsvc::Secret::read(&plain)
        .ok()
        .filter(|s| s.name.eq_ignore_ascii_case(name))
        .ok_or_else(|| format!("the stored password of {name} cannot be read; {again}"))?;
    batch_logon(&stored.name, &stored.password).map_err(|e| format!("{e}; {again}"))
}

#[repr(C)]
struct ObjectAttributes {
    len: u32,
    root: HANDLE,
    name: *mut std::ffi::c_void,
    attributes: u32,
    descriptor: *mut std::ffi::c_void,
    quality: *mut std::ffi::c_void,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateLowBoxToken(
        token: *mut HANDLE,
        existing: HANDLE,
        access: u32,
        attributes: *const ObjectAttributes,
        package: PSID,
        capability_count: u32,
        capabilities: *mut SID_AND_ATTRIBUTES,
        handle_count: u32,
        handles: *mut HANDLE,
    ) -> i32;
}

/// `t` as a process of the container `name` holds it: what that container
/// may open, the folders granted to it and what Windows opens to every
/// AppContainer, and only where `t`'s account may open it too. Without
/// capabilities: it opens files, nothing of the network. Needs no profile.
pub fn lowbox(t: &Token, name: &str) -> io::Result<Token> {
    use windows_sys::Win32::Security::TOKEN_ALL_ACCESS;
    let sid = nerve_sandbox::appcontainer::Sid::derive(name)?;
    let attributes = ObjectAttributes {
        len: std::mem::size_of::<ObjectAttributes>() as u32,
        root: std::ptr::null_mut(),
        name: std::ptr::null_mut(),
        attributes: 0,
        descriptor: std::ptr::null_mut(),
        quality: std::ptr::null_mut(),
    };
    let mut h: HANDLE = std::ptr::null_mut();
    // SAFETY: an open token, empty object attributes, the container's SID
    // and no capabilities or handles; the new token is owned below.
    let st = unsafe {
        NtCreateLowBoxToken(
            &mut h,
            t.raw(),
            TOKEN_ALL_ACCESS,
            &attributes,
            sid.as_ptr(),
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
        )
    };
    if st < 0 {
        return Err(io::Error::other(format!(
            "cannot make the token of the AppContainer {name} ({st:#x})"
        )));
    }
    // SAFETY: the call made a token this code now owns.
    Ok(Token(unsafe { OwnedHandle::from_raw_handle(h as _) }))
}

/// The node's own file access as `account`, on this thread only, while it
/// lives: the `fs` actions of a center and the path checks of its calls
/// see what the account sees, and files they make belong to it. It is not
/// `Send`, so it cannot be held across an `.await` and leak to another
/// task.
pub struct FsAs {
    _as: Impersonation,
}

impl FsAs {
    pub fn new(account: &Account) -> io::Result<FsAs> {
        let t = token_for(account).map_err(io::Error::other)?;
        Ok(FsAs {
            _as: Impersonation::new(&t)?,
        })
    }

    /// As `account` in the pairing's container `name` ([`lowbox`]): what
    /// its commands may open, and not what the account may besides, which
    /// is every pairing's folders (#149, Q4).
    pub fn in_container(account: &Account, name: &str) -> io::Result<FsAs> {
        let t = token_for(account).map_err(io::Error::other)?;
        let boxed = lowbox(&t, name)?;
        Ok(FsAs {
            _as: Impersonation::new(&boxed)?,
        })
    }
}

/// A process started suspended with another token: it runs once
/// [`Spawned::resume`] lets it.
pub struct Spawned {
    pub pid: u32,
    process: OwnedHandle,
    thread: OwnedHandle,
    pub stdout: std::fs::File,
    pub stderr: std::fs::File,
}

impl Spawned {
    pub fn process(&self) -> crate::win::Handle {
        self.process.as_raw_handle()
    }

    /// A handle of its own to the process, which keeps its pid from going
    /// to another process while it is open.
    pub fn handle(&self) -> io::Result<OwnedHandle> {
        self.process.try_clone()
    }

    pub fn resume(&self) -> io::Result<()> {
        // SAFETY: the main thread of the process, started suspended.
        if unsafe { ResumeThread(self.thread.as_raw_handle() as HANDLE) } == u32::MAX {
            return Err(last());
        }
        Ok(())
    }

    pub fn kill(&self) {
        // SAFETY: an open process handle with every right.
        unsafe { TerminateProcess(self.process.as_raw_handle() as HANDLE, 1) };
    }

    /// Waits for the process to end (blocking); its exit code.
    pub fn waiter(&self) -> io::Result<impl FnOnce() -> io::Result<u32> + Send + 'static> {
        let h = self.process.try_clone()?;
        Ok(move || {
            let raw = h.as_raw_handle() as HANDLE;
            // SAFETY: an open process handle this closure owns.
            unsafe {
                if WaitForSingleObject(raw, INFINITE) != WAIT_OBJECT_0 {
                    return Err(last());
                }
                let mut code = 0u32;
                if GetExitCodeProcess(raw, &mut code) == 0 {
                    return Err(last());
                }
                Ok(code)
            }
        })
    }
}

/// A pipe whose ends this process does not hand down; the child's end is
/// made inheritable for its start only.
fn pipe() -> io::Result<(OwnedHandle, OwnedHandle)> {
    let (mut r, mut w): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
    // SAFETY: places for both ends; no security attributes: not inherited.
    if unsafe { CreatePipe(&mut r, &mut w, std::ptr::null(), 0) } == 0 {
        return Err(last());
    }
    // SAFETY: CreatePipe returned two handles this code now owns.
    unsafe {
        Ok((
            OwnedHandle::from_raw_handle(r as _),
            OwnedHandle::from_raw_handle(w as _),
        ))
    }
}

/// The NUL device to read from: a command reads no input.
fn nul() -> io::Result<OwnedHandle> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 0,
    };
    // SAFETY: a NUL-terminated device name; the handle is owned below.
    let h = unsafe {
        CreateFileW(
            wide("NUL").as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &sa,
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(last());
    }
    // SAFETY: CreateFileW returned a handle this code now owns.
    Ok(unsafe { OwnedHandle::from_raw_handle(h as _) })
}

/// Starts `line` (a command line, [`crate::exec::windows_command_line`])
/// suspended with token `t`, in `cwd`, with the account's own environment
/// and no window. It gets `input` on its stdin, a pipe that a thread of the
/// node fills and closes (the shim's spec, which a full pipe would hold
/// while the process waits to be resumed), else the NUL device; a pipe each
/// for stdout and stderr, and no other handle of the node. A token that is
/// not a restricted copy of this process's own needs [`SWITCH`].
pub fn spawn(
    t: &Token,
    line: &str,
    cwd: Option<&Path>,
    home: Option<&Path>,
    input: Option<Vec<u8>>,
) -> io::Result<Spawned> {
    // Held by the service; another caller starts only restricted copies of
    // its own token, which need neither.
    let _ = enable(&SWITCH);
    let (out_r, out_w) = pipe()?;
    let (err_r, err_w) = pipe()?;
    let (input, feed) = match input {
        Some(bytes) => {
            let (r, w) = pipe()?;
            (r, Some((w, bytes)))
        }
        None => (nul()?, None),
    };
    let given = [
        input.as_raw_handle() as HANDLE,
        out_w.as_raw_handle() as HANDLE,
        err_w.as_raw_handle() as HANDLE,
    ];
    // Only for the start: another program the node starts meanwhile would
    // hold the pipes open too, and its end would come late.
    for h in given {
        // SAFETY: open handles of this process.
        if unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
            return Err(last());
        }
    }
    let r = start(t, line, cwd, home, &given);
    for h in given {
        // SAFETY: as above.
        unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0) };
    }
    let pi = r?;
    // SAFETY: CreateProcessAsUserW returned two handles this code now owns.
    let (process, thread) = unsafe {
        (
            OwnedHandle::from_raw_handle(pi.hProcess as _),
            OwnedHandle::from_raw_handle(pi.hThread as _),
        )
    };
    drop((input, out_w, err_w));
    if let Some((w, bytes)) = feed {
        std::thread::spawn(move || {
            use std::io::Write;
            let mut w = std::fs::File::from(w);
            let _ = w.write_all(&bytes);
        });
    }
    Ok(Spawned {
        pid: pi.dwProcessId,
        process,
        thread,
        stdout: out_r.into(),
        stderr: err_r.into(),
    })
}

/// CreateProcessAsUserW with `given` as the only handles the process gets.
fn start(
    t: &Token,
    line: &str,
    cwd: Option<&Path>,
    home: Option<&Path>,
    given: &[HANDLE; 3],
) -> io::Result<PROCESS_INFORMATION> {
    // The attribute list that names the handles the process may inherit.
    let mut size = 0usize;
    // SAFETY: a null list asks for the size.
    unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size) };
    let mut list = vec![0u64; size.div_ceil(8)];
    let attrs = list.as_mut_ptr().cast();
    // SAFETY: a buffer of the size asked for.
    if unsafe { InitializeProcThreadAttributeList(attrs, 1, 0, &mut size) } == 0 {
        return Err(last());
    }
    struct List(*mut std::ffi::c_void);
    impl Drop for List {
        fn drop(&mut self) {
            // SAFETY: an initialized list, deleted once.
            unsafe { DeleteProcThreadAttributeList(self.0) };
        }
    }
    let _list = List(attrs);
    // SAFETY: the handles live until the process has started.
    if unsafe {
        UpdateProcThreadAttribute(
            attrs,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            given.as_ptr().cast(),
            std::mem::size_of_val(given),
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    } == 0
    {
        return Err(last());
    }
    let mut env = std::ptr::null_mut();
    // The block is read as the account: the service, which keeps no
    // SeImpersonatePrivilege, is refused the account's registry otherwise.
    let made = {
        let _as = Impersonation::new(t)?;
        // SAFETY: the account's token; the block is destroyed below.
        unsafe { CreateEnvironmentBlock(&mut env, t.raw(), 0) }
    };
    if made == 0 {
        return Err(failed("CreateEnvironmentBlock"));
    }
    struct Env(*mut std::ffi::c_void);
    impl Drop for Env {
        fn drop(&mut self) {
            // SAFETY: a block from CreateEnvironmentBlock, destroyed once.
            unsafe { DestroyEnvironmentBlock(self.0) };
        }
    }
    let _env = Env(env);
    // Pointed at the account's profile, which Windows leaves out while the
    // account is not signed in.
    let block: Option<Vec<u16>> = home.map(|h| {
        // SAFETY: the block holds NUL-ended strings, the last one empty.
        let vars = unsafe { env_vars(env.cast()) };
        let mut b: Vec<u16> = crate::exec::rehome_env(vars, &h.display().to_string())
            .iter()
            .flat_map(|v| v.encode_utf16().chain(Some(0)))
            .collect();
        b.push(0);
        b
    });
    let env = block
        .as_ref()
        .map_or(env.cast_const(), |b| b.as_ptr().cast());
    // An empty desktop name gives the process a window station of its own
    // logon session, so it shares no desktop with the service.
    let mut desktop = wide("");
    // SAFETY: STARTUPINFOEXW is plain data; zero is its empty value.
    let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = given[0];
    si.StartupInfo.hStdOutput = given[1];
    si.StartupInfo.hStdError = given[2];
    si.StartupInfo.lpDesktop = desktop.as_mut_ptr();
    si.lpAttributeList = attrs;
    let mut line = wide(line);
    let cwd = cwd.map(wide);
    // SAFETY: PROCESS_INFORMATION is plain data that the call fills.
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: every pointer is to a live, NUL-terminated or initialized
    // value of this frame; the command line is writable, as required.
    let ok = unsafe {
        CreateProcessAsUserW(
            t.raw(),
            std::ptr::null(),
            line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            CREATE_SUSPENDED
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT
                | CREATE_NO_WINDOW,
            env,
            cwd.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            &si.StartupInfo,
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(failed("CreateProcessAsUserW"));
    }
    Ok(pi)
}

/// The `NAME=value` strings of an environment block.
///
/// # Safety
/// `p` points to NUL-ended UTF-16 strings that end with an empty one.
unsafe fn env_vars(mut p: *const u16) -> Vec<String> {
    let mut out = Vec::new();
    // SAFETY: as the caller says; each string is read up to its NUL.
    unsafe {
        while *p != 0 {
            let s = from_wide(p);
            p = p.add(s.encode_utf16().count() + 1);
            out.push(s);
        }
    }
    out
}

/// This process's token without its privileges and with Administrators as
/// a group that only denies: what `update` runs a downloaded program with.
pub fn restricted() -> io::Result<Token> {
    // The new token has the rights this handle has; it is changed below.
    let own =
        process_token(TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT)?;
    let admins = well_known_sid(WinBuiltinAdministratorsSid)?;
    let deny = [SID_AND_ATTRIBUTES {
        Sid: admins.as_ptr() as PSID,
        Attributes: 0,
    }];
    let mut h: HANDLE = std::ptr::null_mut();
    // SAFETY: an open token, one SID to deny, a place for the new token.
    let ok = unsafe {
        CreateRestrictedToken(
            own.raw(),
            DISABLE_MAX_PRIVILEGE,
            1,
            deny.as_ptr(),
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            &mut h,
        )
    };
    if ok == 0 {
        return Err(last());
    }
    // SAFETY: CreateRestrictedToken returned a token this code now owns.
    let t = Token(unsafe { OwnedHandle::from_raw_handle(h as _) });
    // An administrator's token makes Administrators the owner of what it
    // makes, and lets only them and SYSTEM in: the program could not open
    // its own process. Its user takes their place.
    let user = token_info(own.raw(), TokenUser)?;
    // SAFETY: the buffer holds a TOKEN_USER, whose SID points into it.
    let sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let owner = TOKEN_OWNER { Owner: sid };
    // SAFETY: the new token, opened with every right, and a TOKEN_OWNER.
    if unsafe {
        SetTokenInformation(
            t.raw(),
            TokenOwner,
            (&raw const owner).cast(),
            std::mem::size_of::<TOKEN_OWNER>() as u32,
        )
    } == 0
    {
        return Err(last());
    }
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: a valid SID; the string is freed with LocalFree.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(last());
    }
    // SAFETY: a NUL-terminated string, freed once.
    let sid = unsafe {
        let s = from_wide(text);
        LocalFree(text.cast());
        s
    };
    let sddl = wide(format!("D:(A;;GA;;;{sid})(A;;GA;;;SY)"));
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: a NUL-terminated SDDL string; the descriptor is freed below.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(last());
    }
    let (mut present, mut defaulted) = (0, 0);
    let mut acl = std::ptr::null_mut();
    // SAFETY: the descriptor just made; the ACL points into it, which lives
    // until LocalFree.
    let r = unsafe {
        if GetSecurityDescriptorDacl(sd, &mut present, &mut acl, &mut defaulted) == 0 {
            Err(last())
        } else {
            let d = TOKEN_DEFAULT_DACL { DefaultDacl: acl };
            if SetTokenInformation(
                t.raw(),
                TokenDefaultDacl,
                (&raw const d).cast(),
                std::mem::size_of::<TOKEN_DEFAULT_DACL>() as u32,
            ) == 0
            {
                Err(last())
            } else {
                Ok(())
            }
        }
    };
    // SAFETY: the descriptor from the conversion, freed once.
    unsafe { LocalFree(sd) };
    r.map(|()| t)
}

/// Runs `line` with token `t` and waits up to `limit` for it; its exit
/// code and stdout. One that runs longer is ended. With `job` it is put in
/// that job before it runs anything.
pub fn run_capture(
    t: &Token,
    line: &str,
    limit: Duration,
    job: Option<&crate::win::Job>,
) -> io::Result<(u32, Vec<u8>)> {
    use std::io::Read;
    let child = spawn(t, line, None, None, None)?;
    if let Some(job) = job
        && let Err(e) = job.assign(child.process())
    {
        child.kill();
        return Err(e);
    }
    child.resume()?;
    let wait = child.waiter()?;
    let Spawned {
        process,
        stdout: mut out,
        stderr: mut err,
        ..
    } = child;
    let reader = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out.by_ref().take(64 * 1024).read_to_end(&mut b);
        b
    });
    let drain = std::thread::spawn(move || {
        let _ = std::io::copy(&mut err, &mut std::io::sink());
    });
    let raw = process.as_raw_handle() as HANDLE;
    // SAFETY: an open process handle.
    let waited =
        unsafe { WaitForSingleObject(raw, u32::try_from(limit.as_millis()).unwrap_or(u32::MAX)) };
    if waited != WAIT_OBJECT_0 {
        // SAFETY: as above, with every right.
        unsafe { TerminateProcess(raw, 1) };
        let _ = wait();
        let _ = (reader.join(), drain.join());
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "it did not end in time",
        ));
    }
    let code = wait()?;
    let out = reader.join().unwrap_or_default();
    let _ = drain.join();
    Ok((code, out))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The account of a SID as text, which the desktop app's broker hands
    /// to the commands (crate::cli::DESKTOP_USER_SID): this process's own.
    #[test]
    fn a_sid_names_its_account() {
        let sid = own_sid().unwrap();
        let mut text: *mut u16 = std::ptr::null_mut();
        // SAFETY: a valid SID; the string Windows allocates is read and
        // freed.
        let text = unsafe {
            assert_ne!(ConvertSidToStringSidW(sid.as_ptr() as PSID, &mut text), 0);
            let s = from_wide(text);
            LocalFree(text as _);
            s
        };
        assert_eq!(name_of_sid(&text).unwrap(), current_user().unwrap());
        assert!(name_of_sid("S-1-5-21-1-2-3-999999").is_err());
        assert!(name_of_sid("nobody").is_err());
    }
}
