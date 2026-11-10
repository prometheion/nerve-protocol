//! A named pipe that only some accounts may open, as the node's control
//! pipe is on Windows: its DACL ([`dacl_text`]), its instances, the process
//! at the other end, and whether a pipe of the expected name was made by an
//! account the caller may trust ([`foreign_owner`]).

/// The pipe's DACL in SDDL: full access for SYSTEM, the administrators and
/// `own` (the SID of the node's account, `S-1-5-…`), nothing for anyone
/// else. `P` keeps out anything inherited.
pub fn dacl_text(own: &str) -> String {
    let mut s = String::from("D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    if !matches!(own, "S-1-5-18" | "S-1-5-32-544") {
        s.push_str(&format!("(A;;GA;;;{own})"));
    }
    s
}

/// What a pipe's DACL gives a client that is not the node's own account (the
/// owners of the owner and provider pipes), as SDDL rights:
/// `FILE_GENERIC_READ | FILE_WRITE_DATA`. Not `GA`, and not `GENERIC_WRITE`:
/// on a pipe `FILE_APPEND_DATA` is `FILE_CREATE_PIPE_INSTANCE`, and whoever
/// holds it may make further server instances of the node's pipe, which all
/// share the first one's descriptor, so that a client could not tell them
/// from the node's. A client opens the pipe with exactly these rights
/// (`open_limited`).
pub const CLIENT_RIGHTS: &str = "0x12008b";

/// Whether a pipe whose owner is `owner` may be the node's: SYSTEM, the
/// administrators, or `node` (the account the node runs as). Another
/// account cannot make an object one of them owns.
pub fn trusted_owner<S: PartialEq>(owner: &S, system: &S, admins: &S, node: Option<&S>) -> bool {
    owner == system || owner == admins || node.is_some_and(|n| owner == n)
}

/// The name of the pipe `prefix` of a program's state folder `dir`: a hash
/// of the folder, so the name says nothing of the account's paths and is
/// never too long. The node's control pipe is named so (`nerve-node`), and
/// the center's attach pipe (`nerve-center`).
pub fn name_for(prefix: &str, dir: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, dir.to_lowercase().as_bytes());
    let hex: String = digest.as_ref()[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!(r"\\.\pipe\{prefix}-{hex}")
}

#[cfg(windows)]
pub use sys::{
    Descriptor, PIPE_BUSY, client_pid, foreign_owner, instance, node_owner_check, open_identified,
    open_limited, owner_of,
};

#[cfg(windows)]
mod sys {
    use std::ffi::c_void;
    use std::io;
    use std::os::windows::io::AsRawHandle;

    use std::os::windows::io::FromRawHandle;
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

    use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
        SE_KERNEL_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetLengthSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ, FILE_WRITE_DATA, OPEN_EXISTING,
        SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    };
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;

    use super::trusted_owner;
    use crate::win::sid::{well_known_sid, wide};

    /// What opening a pipe says while every instance of it is in use.
    pub const PIPE_BUSY: i32 = windows_sys::Win32::Foundation::ERROR_PIPE_BUSY as i32;

    /// A security descriptor made from SDDL, freed when dropped.
    pub struct Descriptor(PSECURITY_DESCRIPTOR);

    // SAFETY: the descriptor is plain memory that is only read once made.
    unsafe impl Send for Descriptor {}
    // SAFETY: as above.
    unsafe impl Sync for Descriptor {}

    impl Descriptor {
        /// The descriptor, for a call that takes security attributes; it
        /// lives as long as this.
        pub fn raw(&self) -> PSECURITY_DESCRIPTOR {
            self.0
        }

        pub fn from_sddl(sddl: &str) -> io::Result<Descriptor> {
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            // SAFETY: a NUL-terminated SDDL string; the descriptor is freed
            // on drop.
            if unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide(sddl).as_ptr(),
                    SDDL_REVISION_1,
                    &mut sd,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(Descriptor(sd))
        }
    }

    impl Drop for Descriptor {
        fn drop(&mut self) {
            // SAFETY: the descriptor from the conversion, freed once.
            unsafe { LocalFree(self.0) };
        }
    }

    /// One instance of the pipe `name` with the node's DACL; the first one
    /// only where no pipe of that name is.
    pub fn instance(name: &str, sd: &Descriptor, first: bool) -> io::Result<NamedPipeServer> {
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        // SAFETY: the attributes are valid and their descriptor lives
        // through the call.
        unsafe {
            ServerOptions::new()
                .first_pipe_instance(first)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(name, (&raw mut sa).cast::<c_void>())
        }
    }

    /// The id of the process at the other end of a connected instance.
    pub fn client_pid(pipe: &NamedPipeServer) -> Option<u32> {
        let mut pid = 0u32;
        // SAFETY: a connected pipe instance and a place for the id.
        let ok =
            unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle() as HANDLE, &mut pid) } != 0;
        (ok && pid != 0).then_some(pid)
    }

    /// The SID that owns the pipe `pipe` is open on.
    // A handle is no pointer this code reads: Windows checks it, and a closed
    // or wrong one is an error.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn owner_of(pipe: HANDLE) -> io::Result<Vec<u8>> {
        let mut owner: PSID = std::ptr::null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: an open handle; the owner points into the descriptor,
        // which is freed below.
        let r = unsafe {
            GetSecurityInfo(
                pipe,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            )
        };
        if r != 0 {
            return Err(io::Error::from_raw_os_error(r as i32));
        }
        // SAFETY: a valid SID in the descriptor, copied before it is freed.
        let sid = unsafe {
            let len = GetLengthSid(owner) as usize;
            let v = std::slice::from_raw_parts(owner.cast::<u8>(), len).to_vec();
            LocalFree(sd);
            v
        };
        Ok(sid)
    }

    /// Opens the pipe `name` as a client that the server may identify, not
    /// act as: a pipe of another account learns who calls, but cannot use
    /// the caller's rights.
    pub fn open_identified(
        name: &str,
    ) -> io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
        use windows_sys::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION;
        tokio::net::windows::named_pipe::ClientOptions::new()
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(name)
    }

    /// What [`open_limited`] asks for: [`super::CLIENT_RIGHTS`].
    const LIMITED: u32 = FILE_GENERIC_READ | FILE_WRITE_DATA;

    /// Opens the pipe `name` for identification only, with just the rights
    /// [`super::CLIENT_RIGHTS`] gives: tokio's client asks `GENERIC_WRITE`,
    /// which a pipe that keeps its owners from making instances refuses.
    pub fn open_limited(
        name: &str,
    ) -> io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
        use std::os::windows::io::IntoRawHandle;
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: `wide` ends in a NUL; the handle is the caller's alone and
        // is handed to tokio, which closes it.
        let h = unsafe {
            CreateFileW(
                wide.as_ptr(),
                LIMITED,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                SECURITY_IDENTIFICATION | SECURITY_SQOS_PRESENT | FILE_FLAG_OVERLAPPED,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let handle = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(h as _) };
        // SAFETY: an overlapped pipe handle, which tokio takes over.
        unsafe {
            tokio::net::windows::named_pipe::NamedPipeClient::from_raw_handle(
                handle.into_raw_handle(),
            )
        }
    }

    /// The folder `%ProgramData%` stands for, as Windows keeps it: no
    /// variable of the caller's reaches it ([`crate::win::folders`]). The
    /// answer is still never taken as proof that no node runs ([`no_pipe`];
    /// round 4, security 1).
    pub(super) fn program_data() -> std::path::PathBuf {
        crate::win::folders::program_data()
    }

    /// Whether the node's service is registered and not stopped, as the
    /// service control manager says, whatever the caller's environment
    /// says. An error reading it counts as running.
    fn node_service_runs() -> bool {
        use windows_sys::Win32::System::Services::{
            SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS, SERVICE_STOPPED,
        };
        let state = || -> Result<Option<u32>, String> {
            let m = crate::win::scm::Scm::open(SC_MANAGER_CONNECT)?;
            match m.service("nerve-node", SERVICE_QUERY_STATUS)? {
                Some(s) => Ok(Some(s.status()?.dwCurrentState)),
                None => Ok(None),
            }
        };
        !matches!(state(), Ok(None) | Ok(Some(SERVICE_STOPPED)))
    }

    /// Asks the node Nerve's installer put on this machine, on its control
    /// pipe, whether the caller is a command it runs (`owner.check`):
    /// [`nerve_transport::ctl::NOT_RUNNING`] where no node made the pipe.
    /// A pipe that SYSTEM, the administrators or the node's account `nerve`
    /// did not make is not asked.
    pub async fn node_owner_check() -> Result<serde_json::Value, String> {
        use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY};
        let state = program_data().join(crate::NODE_SERVICE_STATE);
        // As the node names it: by the folder's real path.
        let dir = std::fs::canonicalize(&state)
            .or_else(|_| std::path::absolute(&state))
            .unwrap_or(state);
        let name = super::name_for("nerve-node", &dir.to_string_lossy());
        let mut busy = 0;
        let client = loop {
            match open_identified(&name) {
                Ok(c) => break c,
                Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) => {
                    return Err(super::no_pipe(node_service_runs()));
                }
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && busy < 50 => {
                    busy += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                Err(e) => return Err(format!("cannot ask the node on {name}: {e}")),
            }
        };
        let nerve = crate::win::sid::sid_of("nerve").ok();
        let raw = std::os::windows::io::AsRawHandle::as_raw_handle(&client);
        let foreign = foreign_owner(raw as HANDLE, nerve.as_deref())
            .map_err(|e| format!("cannot check the node's control pipe {name}: {e}"))?;
        if foreign.is_some() {
            return Err(format!(
                "the control pipe {name} is not the node's, so nothing was asked on it; restart the node and run this again"
            ));
        }
        let call = nerve_transport::ctl::call_on(client, "owner.check", serde_json::json!({}));
        tokio::time::timeout(nerve_transport::ctl::ANSWER_WAIT, call)
            .await
            .map_err(|_| nerve_transport::ctl::NO_ANSWER.to_string())?
    }

    /// The owner of the pipe `pipe` is open on when it is none of SYSTEM,
    /// the administrators and `account`, who alone may be trusted with what
    /// is sent on it: another account cannot make an object one of them owns.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn foreign_owner(pipe: HANDLE, account: Option<&[u8]>) -> io::Result<Option<Vec<u8>>> {
        let owner = owner_of(pipe)?;
        let system = well_known_sid(WinLocalSystemSid)?;
        let admins = well_known_sid(WinBuiltinAdministratorsSid)?;
        let account = account.map(<[u8]>::to_vec);
        Ok((!trusted_owner(&owner, &system, &admins, account.as_ref())).then_some(owner))
    }
}

/// What a missing control pipe of the node means: "no node runs" only
/// where the service control manager says its service does not run. A
/// caller's environment can send the lookup to a folder with no pipe in
/// it, so the missing pipe alone proves nothing.
pub fn no_pipe(node_service_runs: bool) -> String {
    if node_service_runs {
        "the node's service runs, but its control pipe cannot be found; stop the node, then run this again"
            .into()
    } else {
        nerve_transport::ctl::NOT_RUNNING.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SYSTEM, the administrators and the node's account, nobody else; no
    /// entry twice where the node runs as one of the first two.
    #[test]
    fn the_dacl_names_the_owners_accounts_only() {
        let nerve = "S-1-5-21-1-2-3-1001";
        assert_eq!(
            dacl_text(nerve),
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;S-1-5-21-1-2-3-1001)"
        );
        assert_eq!(dacl_text("S-1-5-18"), "D:P(A;;GA;;;SY)(A;;GA;;;BA)");
        assert_eq!(dacl_text("S-1-5-32-544"), "D:P(A;;GA;;;SY)(A;;GA;;;BA)");
        // No entry for everyone, the users, the network or an AppContainer.
        for other in ["WD", "BU", "AU", "NU", "AC", "S-1-15-"] {
            assert!(!dacl_text(nerve).contains(other), "{other}");
        }
    }

    /// The rights an owner gets on a pipe are those [`open_limited`] asks
    /// for: reading and writing data, never `FILE_APPEND_DATA` (which on a
    /// pipe makes instances) nor the generic rights.
    #[cfg(windows)]
    #[test]
    fn a_client_gets_what_it_opens_with_and_cannot_make_instances() {
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_APPEND_DATA, FILE_CREATE_PIPE_INSTANCE, FILE_GENERIC_READ, FILE_WRITE_DATA,
        };
        let rights = u32::from_str_radix(CLIENT_RIGHTS.trim_start_matches("0x"), 16).unwrap();
        assert_eq!(rights, FILE_GENERIC_READ | FILE_WRITE_DATA);
        assert_eq!(rights & (FILE_APPEND_DATA | FILE_CREATE_PIPE_INSTANCE), 0);
    }

    /// A pipe's name hides the folder, holds no case of it, and differs per
    /// program and folder.
    #[test]
    fn a_pipe_is_named_by_a_hash_of_its_folder() {
        let a = name_for("nerve-center", r"C:\Users\Alice\AppData\Local\nerve-center");
        assert!(a.starts_with(r"\\.\pipe\nerve-center-"), "{a}");
        assert_eq!(a.len(), r"\\.\pipe\nerve-center-".len() + 32);
        assert!(!a.contains("Alice"));
        assert_eq!(
            a,
            name_for("nerve-center", r"c:\users\alice\appdata\local\nerve-center")
        );
        assert_ne!(
            a,
            name_for("nerve-node", r"C:\Users\Alice\AppData\Local\nerve-center")
        );
        assert_ne!(a, name_for("nerve-center", r"C:\other"));
    }

    /// The folder of the node's state comes from Windows, not from the
    /// caller's variable: a command that sets `ProgramData` elsewhere asks
    /// the same pipe.
    #[cfg(windows)]
    #[test]
    fn the_program_data_folder_is_the_systems() {
        let system = sys::program_data();
        // SAFETY: this test is the only thread that reads the variable.
        unsafe { std::env::set_var("ProgramData", r"C:\somewhere-else") };
        assert_eq!(system, sys::program_data());
        assert!(system.is_absolute());
        assert!(!system.starts_with(r"C:\somewhere-else"));
    }

    /// A pipe that cannot be found is "no node runs" only for a stopped or
    /// missing service (round 4, security 1).
    #[test]
    fn a_missing_pipe_of_a_running_service_is_a_refusal() {
        assert_eq!(no_pipe(false), nerve_transport::ctl::NOT_RUNNING);
        assert_ne!(no_pipe(true), nerve_transport::ctl::NOT_RUNNING);
        assert!(no_pipe(true).contains("service runs"));
    }

    /// The CLI talks to a pipe only when SYSTEM, the administrators or the
    /// node's account own it.
    #[test]
    fn a_pipe_another_account_made_is_not_the_nodes() {
        let (system, admins, nerve, other) = ("SY", "BA", "nerve", "mallory");
        assert!(trusted_owner(&system, &system, &admins, Some(&nerve)));
        assert!(trusted_owner(&admins, &system, &admins, Some(&nerve)));
        assert!(trusted_owner(&nerve, &system, &admins, Some(&nerve)));
        assert!(!trusted_owner(&other, &system, &admins, Some(&nerve)));
        // Without the node's account, only the first two.
        assert!(!trusted_owner(&nerve, &system, &admins, None));
        assert!(trusted_owner(&system, &system, &admins, None));
    }
}
