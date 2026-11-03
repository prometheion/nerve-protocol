//! The control pipe of a node on Windows, where Unix has its control socket
//! (nerve_transport::ctl): the same lines, on a named pipe of the node's
//! state folder ([`crate::paths::NodePaths::ctl_pipe`]). For now it serves
//! the status and the changes to a center's folders
//! ([`crate::daemon::pipe_control`]); every other change the CLI still
//! writes to `node.toml`, which the node takes at its next start.
//!
//! Who may write to it:
//! - Its DACL lets SYSTEM, the administrators (elevated) and the node's own
//!   account open it, nobody else ([`dacl_text`]). An AppContainer, a folder
//!   mode command, gets no access: no entry names its package. A command of
//!   the installed node runs as another account, without the administrators
//!   in effect, and gets none either.
//! - It refuses remote clients (PIPE_REJECT_REMOTE_CLIENTS).
//! - A caller in the job of a command the node runs is refused whatever it
//!   asks ([`crate::job::from_a_command`]). That is for those the DACL lets
//!   in: a sudo command (the account's elevated token), and every command
//!   of a node run by hand, which runs as the node's own account.
//!
//! What it does not stop: a process another program starts on a command's
//! request (the task scheduler, WMI) is in no job of the node's; it opens
//! the pipe only if its account may. A sudo command can also change the
//! node's files with its administrator rights, and a command of a node run
//! by hand can make another process of the account call; neither is more
//! than what that command can do anyway. The node knows a caller by the
//! process id Windows keeps for the connection: a command's process that
//! hands its connection to another one of the command and ends could pass
//! if Windows gave its id to a process outside the job meanwhile. Only a
//! caller the DACL lets in can try that, the same two.
//!
//! The pipe's name is known to everyone, so another account could make a
//! pipe of that name before the node starts. The node makes its first
//! instance with FILE_FLAG_FIRST_PIPE_INSTANCE and keeps one open while it
//! runs, so it never serves on a pipe someone else made; the CLI opens it
//! for identification only and talks to it only when its owner is SYSTEM,
//! the administrators or the node's account ([`trusted_owner`]).

/// How the CLI's error starts when the pipe of the node's name is another
/// account's.
pub const NOT_THE_NODES: &str = "the control pipe is not the node's";

/// Whether the CLI makes a folder change in node.toml itself after the pipe
/// call failed with `e`: when no node made a pipe, and when the pipe is
/// another account's but no node runs (`node_runs`, asked only then), so a
/// pipe someone made of the node's name does not keep the owner from
/// changing folders with the node stopped. Any other failure is the
/// answer.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn file_instead(e: &str, node_runs: impl FnOnce() -> bool) -> bool {
    e == nerve_transport::ctl::NOT_RUNNING || (e.starts_with(NOT_THE_NODES) && !node_runs())
}

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
#[cfg_attr(not(windows), allow(dead_code))]
fn trusted_owner<S: PartialEq>(owner: &S, system: &S, admins: &S, node: Option<&S>) -> bool {
    owner == system || owner == admins || node.is_some_and(|n| owner == n)
}

#[cfg(windows)]
pub(crate) use sys::{Descriptor, check_owner, client_pid, instance};
#[cfg(windows)]
pub use sys::{call, serve};

#[cfg(windows)]
mod sys {
    use std::ffi::c_void;
    use std::io;
    use std::os::windows::io::AsRawHandle;
    use std::sync::Arc;
    use std::time::Duration;

    use serde_json::Value;
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
    use tokio::task::JoinHandle;
    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, HANDLE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
        SE_KERNEL_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetLengthSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION;
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;

    use nerve_transport::ctl::NOT_RUNNING;

    use super::{NOT_THE_NODES, dacl_text, trusted_owner};
    use crate::daemon::Shared;
    use crate::paths::NodePaths;
    use crate::win_user::{well_known_sid, wide};

    /// A security descriptor made from SDDL, freed when dropped.
    pub(crate) struct Descriptor(PSECURITY_DESCRIPTOR);

    // SAFETY: the descriptor is plain memory that is only read once made.
    unsafe impl Send for Descriptor {}
    // SAFETY: as above.
    unsafe impl Sync for Descriptor {}

    impl Descriptor {
        pub(crate) fn from_sddl(sddl: &str) -> io::Result<Descriptor> {
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
    pub(crate) fn instance(
        name: &str,
        sd: &Descriptor,
        first: bool,
    ) -> io::Result<NamedPipeServer> {
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
    pub(crate) fn client_pid(pipe: &NamedPipeServer) -> Option<u32> {
        let mut pid = 0u32;
        // SAFETY: a connected pipe instance and a place for the id.
        let ok =
            unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle() as HANDLE, &mut pid) } != 0;
        (ok && pid != 0).then_some(pid)
    }

    /// Serves the control pipe of `shared`'s node until the task is
    /// aborted. The first instance is made before this returns, so a CLI
    /// started right after finds the node; an error then means the pipe
    /// could not be made, or another holds its name.
    pub fn serve(shared: Arc<Shared>) -> Result<JoinHandle<()>, String> {
        let name = shared.paths.ctl_pipe();
        let own = crate::win_user::own_sid()
            .and_then(|s| crate::win_host::sid_text(&s).map_err(io::Error::other))
            .map_err(|e| format!("the control pipe: cannot read this account's SID: {e}"))?;
        let sd = Descriptor::from_sddl(&dacl_text(&own))
            .map_err(|e| format!("the control pipe: cannot make its DACL: {e}"))?;
        let first = instance(&name, &sd, true).map_err(|e| match e.raw_os_error() {
            Some(c) if c == ERROR_ACCESS_DENIED as i32 => {
                format!("the control pipe {name} is taken: another process made it first")
            }
            _ => format!("the control pipe {name}: {e}"),
        })?;
        Ok(tokio::spawn(accept(shared, name, sd, first)))
    }

    /// Takes connections one after another. The next instance is made
    /// before a connected one is handed on, so the pipe always has one of
    /// the node's and its name cannot pass to another process while the node
    /// runs. As on the socket, at most
    /// [`nerve_transport::ctl::MAX_CONNECTIONS`] are served at once; one over
    /// them is told [`nerve_transport::ctl::BUSY`] and closed.
    async fn accept(
        shared: Arc<Shared>,
        name: String,
        sd: Descriptor,
        mut listening: NamedPipeServer,
    ) {
        let places = Arc::new(tokio::sync::Semaphore::new(
            nerve_transport::ctl::MAX_CONNECTIONS,
        ));
        let mut failing = false;
        loop {
            if let Err(e) = listening.connect().await {
                // A client that went before it was taken; the instance
                // listens again.
                if !std::mem::replace(&mut failing, true) {
                    tracing::warn!("the control pipe cannot take a connection now: {e}");
                }
                let _ = listening.disconnect();
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            failing = false;
            let next = loop {
                match instance(&name, &sd, false) {
                    Ok(n) => break n,
                    Err(e) => {
                        if !std::mem::replace(&mut failing, true) {
                            tracing::warn!(
                                "the control pipe cannot make another instance now: {e}"
                            );
                        }
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            };
            failing = false;
            let conn = std::mem::replace(&mut listening, next);
            let Ok(place) = places.clone().try_acquire_owned() else {
                // Said without waiting; the client reads it as its answer.
                if conn.writable().await.is_ok() {
                    let busy = serde_json::json!({"error": nerve_transport::ctl::BUSY});
                    let _ = conn.try_write(format!("{busy}\n").as_bytes());
                }
                continue;
            };
            let pid = client_pid(&conn);
            let s = shared.clone();
            tokio::spawn(async move {
                let _place = place;
                let handler = Arc::new(move |req: nerve_transport::ctl::CtlRequest, pid| {
                    let s = s.clone();
                    async move {
                        // Asked at each request: the commands running change.
                        let from_command = crate::win::from_a_command(pid);
                        crate::daemon::pipe_control(&s, &req.method, req.params, from_command).await
                    }
                });
                let _ = nerve_transport::ctl::serve_stream(conn, pid, handler).await;
            });
        }
    }

    /// The SID that owns the pipe `pipe` is open on.
    fn owner_of(pipe: HANDLE) -> io::Result<Vec<u8>> {
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

    /// The account the node at `paths` runs as: `nerve` for the installed
    /// node, else this one (a node run by hand is its owner's).
    fn node_account(paths: &NodePaths) -> Option<Vec<u8>> {
        if *paths == crate::service::Layout::system().paths {
            crate::win_host::sid_of(crate::service::USER).ok()
        } else {
            crate::win_user::own_sid().ok()
        }
    }

    /// One call to the node at `paths` over its pipe: [`NOT_RUNNING`] when
    /// no node made one.
    pub async fn call(paths: &NodePaths, method: &str, params: Value) -> Result<Value, String> {
        let name = paths.ctl_pipe();
        let mut busy = 0;
        let client = loop {
            // Identification only: a pipe that is not the node's learns who
            // calls, but cannot act as that account.
            match ClientOptions::new()
                .security_qos_flags(SECURITY_IDENTIFICATION)
                .open(&name)
            {
                Ok(c) => break c,
                Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) => {
                    return Err(NOT_RUNNING.into());
                }
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && busy < 50 => {
                    busy += 1;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {
                    return Err(
                        "the running node lets only the administrators, SYSTEM and its own account change it: the app asks Windows for an administrator's rights where they are needed".into(),
                    );
                }
                Err(e) => return Err(format!("cannot reach the running node: {e}")),
            }
        };
        check_owner(paths, &client, &name)?;
        nerve_transport::ctl::call_on(client, method, params).await
    }

    /// Talks to the pipe `name` that `client` is open on only when SYSTEM,
    /// the administrators or the node's account own it.
    pub(crate) fn check_owner(
        paths: &NodePaths,
        client: &tokio::net::windows::named_pipe::NamedPipeClient,
        name: &str,
    ) -> Result<(), String> {
        let owner = owner_of(client.as_raw_handle() as HANDLE)
            .map_err(|e| format!("cannot check the control pipe {name}: {e}"))?;
        let system = well_known_sid(WinLocalSystemSid).map_err(|e| e.to_string())?;
        let admins = well_known_sid(WinBuiltinAdministratorsSid).map_err(|e| e.to_string())?;
        let node = node_account(paths);
        if !trusted_owner(&owner, &system, &admins, node.as_ref()) {
            let who = crate::win_host::sid_text(&owner).unwrap_or_else(|e| e);
            return Err(format!(
                "{NOT_THE_NODES}: {name} belongs to {who}, so nothing was sent to it. Another process made it before the node started, and the node runs without its pipe: end that process and restart the node (docs/user/troubleshooting.md, \"The control pipe is not the node's\"). With the node stopped, folder changes go to node.toml"
            ));
        }
        Ok(())
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

    /// The CLI writes the file itself when no node made the pipe, and when
    /// another account's pipe holds the name but no node runs; with a node
    /// running, or for any other failure, it does not.
    #[test]
    fn the_cli_writes_the_file_only_where_no_node_takes_the_change() {
        use nerve_transport::ctl::NOT_RUNNING;
        let foreign = format!("{NOT_THE_NODES}: \\\\.\\pipe\\nerve-node-1 belongs to S-1-5-21-9");
        let asked = std::cell::Cell::new(false);
        let asked = &asked;
        let runs = |r| {
            move || {
                asked.set(true);
                r
            }
        };
        assert!(file_instead(NOT_RUNNING, runs(true)));
        assert!(!asked.get(), "asked whether a node runs without need");
        assert!(file_instead(&foreign, runs(false)));
        assert!(!file_instead(&foreign, runs(true)));
        for other in [
            "refused: this request comes from a command the node runs for a center",
            "the running node lets only the administrators, SYSTEM and its own account change it",
            "cannot reach the running node: All pipe instances are busy. (os error 231)",
            "/srv/a is not a folder of this center",
        ] {
            assert!(!file_instead(other, runs(false)), "{other}");
        }
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
