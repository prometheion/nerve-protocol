//! A program run without the administrators' rights by a command that has
//! them, as `update` asks a downloaded program its version before it puts
//! it in place: a token made from this process's own with every privilege
//! but one taken and the Administrators group for denying only.

use std::io::{self, Read};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    HANDLE, HANDLE_FLAG_INHERIT, LocalFree, SetHandleInformation, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, GetSecurityDescriptorDacl, PSECURITY_DESCRIPTOR,
    PSID, SID_AND_ATTRIBUTES, SetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY,
    TOKEN_DEFAULT_DACL, TOKEN_DUPLICATE, TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER, TokenDefaultDacl,
    TokenOwner, TokenUser, WinBuiltinAdministratorsSid,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess,
    InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES,
    STARTUPINFOEXW, STARTUPINFOW, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};

use crate::win::job_object::Job;
use crate::win::process::{token, token_info};
use crate::win::sid::{sid_text, well_known_sid, wide};

fn last() -> io::Error {
    io::Error::last_os_error()
}

/// This process's token without the administrators' rights. What it makes
/// belongs to its user and is open to that user and SYSTEM, as an
/// administrator's own token would give it to the Administrators group:
/// the program could not open its own process then. The node's `update`
/// asks a program its version with it, and its tests act as an owner with
/// it.
pub fn restricted() -> io::Result<OwnedHandle> {
    let own = token(
        None,
        TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
    )?;
    let admins = well_known_sid(WinBuiltinAdministratorsSid)?;
    let deny = [SID_AND_ATTRIBUTES {
        Sid: admins.as_ptr() as PSID,
        Attributes: 0,
    }];
    let mut h: HANDLE = std::ptr::null_mut();
    // SAFETY: an open token, one SID to deny, a place for the new token.
    if unsafe {
        CreateRestrictedToken(
            own.as_raw_handle(),
            DISABLE_MAX_PRIVILEGE,
            1,
            deny.as_ptr(),
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            &mut h,
        )
    } == 0
    {
        return Err(last());
    }
    // SAFETY: the token the call made, owned from here.
    let t = unsafe { OwnedHandle::from_raw_handle(h) };
    let user = token_info(&own, TokenUser)?;
    // SAFETY: the buffer holds a TOKEN_USER, whose SID points into it.
    let sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let owner = TOKEN_OWNER { Owner: sid };
    // SAFETY: the new token, opened with every right, and a TOKEN_OWNER.
    if unsafe {
        SetTokenInformation(
            t.as_raw_handle(),
            TokenOwner,
            (&raw const owner).cast(),
            std::mem::size_of::<TOKEN_OWNER>() as u32,
        )
    } == 0
    {
        return Err(last());
    }
    // SAFETY: a valid SID, read while the buffer lives.
    let me = unsafe {
        std::slice::from_raw_parts(
            sid.cast::<u8>(),
            windows_sys::Win32::Security::GetLengthSid(sid) as usize,
        )
    };
    let me = sid_text(me).map_err(io::Error::other)?;
    let sddl = wide(format!("D:(A;;GA;;;{me})(A;;GA;;;SY)"));
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
    let mut dacl = std::ptr::null_mut();
    // SAFETY: the descriptor just made; the DACL points into it, which is
    // freed once it was set.
    let r = unsafe {
        if GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) == 0 {
            Err(last())
        } else {
            let d = TOKEN_DEFAULT_DACL { DefaultDacl: dacl };
            if SetTokenInformation(
                t.as_raw_handle(),
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

/// `program` with `args` in Windows' quoting: each in quotes that has a
/// space or none at all.
fn command_line(program: &Path, args: &[&str]) -> String {
    let quote = |s: &str| {
        if s.is_empty() || s.contains([' ', '\t']) {
            format!("\"{s}\"")
        } else {
            s.to_string()
        }
    };
    std::iter::once(format!("\"{}\"", program.display()))
        .chain(args.iter().map(|a| quote(a)))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The system folder and an environment of `SystemRoot` alone: the program
/// is not yet accepted, so it gets none of the variables of the terminal
/// that runs `update` (tokens often are there), as the Linux service's
/// check runs with an empty environment.
fn bare_environment() -> (Vec<u16>, Vec<u16>) {
    // From Windows, not from the variables, which the account's unelevated
    // programs may set (round 6, security 1).
    let root = crate::win::folders::windows_dir();
    let env = format!("SystemRoot={}\0\0", root.display())
        .encode_utf16()
        .collect();
    (env, wide(crate::win::folders::system32()))
}

/// An attribute list that names `handle` as the one handle a new process
/// inherits, freed when dropped: `bInheritHandles` alone hands over every
/// inheritable handle of the caller, among them those of the terminal that
/// started it.
struct OnlyHandle {
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
    // The list points at these; they live as long as it does.
    _memory: Vec<u64>,
    _handle: Box<HANDLE>,
}

impl OnlyHandle {
    fn new(handle: HANDLE) -> io::Result<OnlyHandle> {
        let mut size = 0usize;
        // SAFETY: a query of the size only; it fails with the size set.
        unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size) };
        // u64s, so the memory is aligned for the list.
        let mut memory = vec![0u64; size.div_ceil(8).max(1)];
        let list: LPPROC_THREAD_ATTRIBUTE_LIST = memory.as_mut_ptr().cast();
        // SAFETY: memory of the size asked for.
        if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut size) } == 0 {
            return Err(last());
        }
        let mut handle = Box::new(handle);
        // SAFETY: the list just made, and one handle that outlives it.
        if unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                (&raw mut *handle).cast(),
                std::mem::size_of::<HANDLE>(),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
        {
            let e = last();
            // SAFETY: the list made above, deleted once.
            unsafe { DeleteProcThreadAttributeList(list) };
            return Err(e);
        }
        Ok(OnlyHandle {
            list,
            _memory: memory,
            _handle: handle,
        })
    }
}

impl Drop for OnlyHandle {
    fn drop(&mut self) {
        // SAFETY: the list made in `new`, deleted once.
        unsafe { DeleteProcThreadAttributeList(self.list) };
    }
}

/// Runs `program` with `args` (plain words, a path at most) without the
/// administrators' rights, no longer than `limit`: its exit code and the
/// first 64 KiB of its output. Its error output goes nowhere.
pub fn output_of(program: &Path, args: &[&str], limit: Duration) -> io::Result<(u32, Vec<u8>)> {
    let t = restricted()?;
    let (mut reader, writer) = std::io::pipe()?;
    let w = writer.as_raw_handle();
    // The one handle the program gets: its output.
    // SAFETY: an open handle of this process.
    if unsafe { SetHandleInformation(w, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
        return Err(last());
    }
    let only = OnlyHandle::new(w)?;
    let si = STARTUPINFOEXW {
        StartupInfo: STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: std::ptr::null_mut(),
            hStdOutput: w,
            hStdError: std::ptr::null_mut(),
            ..Default::default()
        },
        lpAttributeList: only.list,
    };
    let mut pi = PROCESS_INFORMATION::default();
    let mut line = wide(command_line(program, args));
    let (env, folder) = bare_environment();
    // SAFETY: the restricted token, a writable command line, a Unicode
    // environment block ended by two NULs, a NUL-terminated folder, the
    // extended startup information with the one inheritable output handle
    // (its list lives until after the call); the handles the call returns
    // are closed below.
    let ok = unsafe {
        CreateProcessAsUserW(
            t.as_raw_handle(),
            std::ptr::null(),
            line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            CREATE_NO_WINDOW
                | CREATE_SUSPENDED
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT,
            env.as_ptr().cast(),
            folder.as_ptr(),
            (&raw const si).cast::<STARTUPINFOW>(),
            &mut pi,
        )
    };
    // Only the program holds the pipe's end now, so reading ends with it.
    drop(only);
    drop(writer);
    if ok == 0 {
        return Err(last());
    }
    // SAFETY: handles the call returned, owned from here.
    let (process, thread) = unsafe {
        (
            OwnedHandle::from_raw_handle(pi.hProcess),
            OwnedHandle::from_raw_handle(pi.hThread),
        )
    };
    // What it starts ends with it, also on every return below: the job
    // kills what is in it when it is dropped. The program runs only once it
    // is in the job.
    let started = Job::new().and_then(|job| {
        job.assign(process.as_raw_handle())?;
        // SAFETY: the main thread's handle of the process just made.
        if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
            return Err(last());
        }
        Ok(job)
    });
    let job = match started {
        Ok(job) => job,
        Err(e) => {
            // SAFETY: an open process handle; it never ran.
            unsafe { TerminateProcess(process.as_raw_handle(), 1) };
            return Err(e);
        }
    };
    let read = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = reader.by_ref().take(64 * 1024).read_to_end(&mut b);
        b
    });
    let ms = u32::try_from(limit.as_millis()).unwrap_or(u32::MAX);
    // SAFETY: an open process handle.
    if unsafe { WaitForSingleObject(process.as_raw_handle(), ms) } != WAIT_OBJECT_0 {
        // SAFETY: as above.
        unsafe { TerminateProcess(process.as_raw_handle(), 1) };
        // Whatever it started holds the pipe too: reading ends with them.
        job.terminate();
        let _ = read.join();
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "it did not end in time",
        ));
    }
    let mut code = 0u32;
    // SAFETY: an open process that ended, and a place for its code.
    if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) } == 0 {
        return Err(last());
    }
    // What it left running goes before the output is read to its end.
    drop(job);
    Ok((code, read.join().unwrap_or_default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A program run so says what it is asked, and is no administrator:
    /// `whoami /groups` shows the Administrators group for denying only.
    /// The tests run as an administrator.
    #[test]
    fn a_program_runs_without_the_administrators_rights() {
        let cmd = std::path::PathBuf::from(
            std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()),
        )
        .join("System32")
        .join("whoami.exe");
        let (code, out) = output_of(&cmd, &["/groups"], Duration::from_secs(30)).unwrap();
        assert_eq!(code, 0);
        let out = String::from_utf8_lossy(&out);
        // S-1-5-32-544, the Administrators group, held for deny only where
        // it is held at all.
        if let Some(line) = out.lines().find(|l| l.contains("S-1-5-32-544")) {
            assert!(
                line.contains("Group used for deny only") || line.contains("deny"),
                "{line}"
            );
        }
        assert_eq!(
            command_line(Path::new("C:\\a b\\p.exe"), &["--version", "x y"]),
            "\"C:\\a b\\p.exe\" --version \"x y\""
        );
    }

    /// The program gets no variable of the terminal that runs `update` and
    /// starts in the system folder (round 2, security 2).
    #[test]
    fn the_program_gets_a_bare_environment_and_the_system_folder() {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        let cmd = std::path::PathBuf::from(&root)
            .join("System32")
            .join("cmd.exe");
        let (code, out) = output_of(&cmd, &["/c", "set"], Duration::from_secs(30)).unwrap();
        assert_eq!(code, 0);
        let out = String::from_utf8_lossy(&out).to_lowercase();
        assert!(out.contains("systemroot="), "{out}");
        for var in ["userprofile=", "path=", "temp=", "username="] {
            assert!(!out.lines().any(|l| l.starts_with(var)), "{var} in {out}");
        }
        let (_, out) = output_of(&cmd, &["/c", "cd"], Duration::from_secs(30)).unwrap();
        let out = String::from_utf8_lossy(&out).to_lowercase();
        let system = std::path::Path::new(&root).join("System32");
        assert_eq!(out.trim(), system.display().to_string().to_lowercase());
    }

    /// What the program started ends with it: the job it runs in kills
    /// them when `output_of` returns.
    #[test]
    fn what_the_program_started_ends_with_it() {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        let ps = std::path::PathBuf::from(&root)
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        // It starts a sleeper, says its id and ends. Through .NET, not
        // Start-Process: a cmdlet loads its module from PSModulePath, which a
        // test started from PowerShell 7 inherits with PowerShell 7's own
        // modules first, and Windows PowerShell then may take its time.
        let (code, out) = output_of(
            &ps,
            &[
                "-NoProfile",
                "-Command",
                "$i = [Diagnostics.ProcessStartInfo]::new('cmd.exe', '/c ping -n 60 127.0.0.1 > nul'); $i.UseShellExecute = $false; $i.CreateNoWindow = $true; [Diagnostics.Process]::Start($i).Id",
            ],
            Duration::from_secs(60),
        )
        .unwrap();
        assert_eq!(code, 0);
        let pid: u32 = String::from_utf8_lossy(&out).trim().parse().unwrap();
        std::thread::sleep(Duration::from_secs(2));
        // SAFETY: a plain call; a handle that opened is closed below.
        let h = unsafe {
            windows_sys::Win32::System::Threading::OpenProcess(
                windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                pid,
            )
        };
        if !h.is_null() {
            let mut code = 0u32;
            // SAFETY: an open process handle and a place for its code.
            let ok = unsafe { GetExitCodeProcess(h, &mut code) };
            // SAFETY: the handle opened above.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(h) };
            assert!(ok != 0 && code != 259, "the sleeper still runs");
        }
    }

    /// The program gets its output handle and no other (round 1, security
    /// 6): an inheritable handle of this process, as one from the terminal
    /// that started an elevated `update` would be, does not reach it.
    #[test]
    fn only_the_output_handle_is_inherited() {
        let (_reader, writer) = std::io::pipe().unwrap();
        let h = writer.as_raw_handle();
        // SAFETY: an open handle of this process.
        assert_ne!(
            unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) },
            0
        );
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        let ps = std::path::PathBuf::from(root)
            .join("System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        let script = format!(
            "try {{ $h = New-Object Microsoft.Win32.SafeHandles.SafeFileHandle([IntPtr]{}, $false); $s = New-Object System.IO.FileStream($h, [System.IO.FileAccess]::Write); 'inherited' }} catch {{ 'not inherited' }}",
            h as usize
        );
        let (code, out) = output_of(
            &ps,
            &["-NoProfile", "-NonInteractive", "-Command", &script],
            Duration::from_secs(120),
        )
        .unwrap();
        let out = String::from_utf8_lossy(&out);
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("not inherited"), "{out}");
    }
}
