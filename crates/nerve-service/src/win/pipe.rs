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
    Descriptor, client_pid, foreign_owner, instance, node_owner_check, open_identified, owner_of,
};

#[cfg(windows)]
mod sys {
    use std::ffi::c_void;
    use std::io;
    use std::os::windows::io::AsRawHandle;

    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
        SE_KERNEL_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetLengthSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;

    use super::trusted_owner;
    use crate::win::sid::{well_known_sid, wide};

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

    /// Asks the node Nerve's installer put on this machine, on its control
    /// pipe, whether the caller is a command it runs (`owner.check`):
    /// [`nerve_transport::ctl::NOT_RUNNING`] where no node made the pipe.
    /// A pipe that SYSTEM, the administrators or the node's account `nerve`
    /// did not make is not asked.
    pub async fn node_owner_check() -> Result<serde_json::Value, String> {
        use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY};
        let data = std::env::var_os("ProgramData")
            .filter(|v| !v.is_empty())
            .map_or_else(|| "C:\\ProgramData".into(), std::path::PathBuf::from);
        let state = data.join(crate::NODE_SERVICE_STATE);
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
                    return Err(nerve_transport::ctl::NOT_RUNNING.into());
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
