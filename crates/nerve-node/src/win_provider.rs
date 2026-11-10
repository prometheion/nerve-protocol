//! The provider pipe of the installed node on Windows
//! ([`crate::provider::PIPE_NAME`]), where Linux has its provider socket
//! (crate::provider::serve): a program of the owner, or of an
//! administrator, attaches to it as a capability provider
//! (docs/dev/spec/node-local.md §7, docs/dev/windows.md "Providers on
//! Windows").
//!
//! Who gets in:
//! - Its DACL lets SYSTEM, the administrators (elevated), the node's own
//!   account and the owner open it, as the owner pipe's
//!   ([`crate::owner::dacl_text`]); no AppContainer, no `nerve-run`, no other
//!   standard account. It refuses remote clients
//!   (PIPE_REJECT_REMOTE_CLIENTS).
//! - The client's token decides, read by impersonating it
//!   (`ImpersonateNamedPipeClient`): the owner's account, SYSTEM, or a token
//!   that holds the Administrators group in effect
//!   ([`crate::provider::admits`]).
//! - A process in the job of a command the node runs is refused.
//! - The program is the one the owner named in `provider add`: the image of
//!   the client's process (`GetNamedPipeClientProcessId`, then
//!   `QueryFullProcessImageNameW`) against that path. Where the node's
//!   account may not open the process (the owner's, an administrator's
//!   elevated one), Windows names its image by the process id, which needs
//!   no handle of it ([`image_of`]); the allowed path is resolved as the
//!   node, or in the owner's folders as the owner ([`resolved`]). The node
//!   keeps no SeImpersonatePrivilege, so acting as the client would only
//!   identify it.
//!
//! A provider runs as whoever started it, outside the node's containers,
//! as on Linux. The check is a guard against mistakes, as the owner pipe's
//! is: a program of the owner may start the allowed one for its own ends.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use std::os::windows::io::AsRawHandle;
use tokio::net::windows::named_pipe::NamedPipeServer;
use tokio::task::JoinHandle;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::RevertToSelf;
use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

use crate::daemon::Shared;
use crate::pipe::{Descriptor, client_pid, instance};
use crate::provider::{Caller, PIPE_NAME, Seen};

/// The thread acts as the pipe's client while this lives; not `Send`, so
/// it stays on its thread.
struct AsClient(std::marker::PhantomData<*const ()>);

impl AsClient {
    fn new(pipe: HANDLE) -> std::io::Result<AsClient> {
        // SAFETY: a connected pipe the server read the client's request
        // from; RevertToSelf in Drop ends it.
        if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(AsClient(std::marker::PhantomData))
    }
}

impl Drop for AsClient {
    fn drop(&mut self) {
        // SAFETY: plain call; the thread is the node again.
        unsafe { RevertToSelf() };
    }
}

/// `SystemProcessIdInformation` of `NtQuerySystemInformation`: the image of
/// a process by its id (`SYSTEM_PROCESS_ID_INFORMATION`).
const PROCESS_ID_INFORMATION: i32 = 88;

#[repr(C)]
struct ProcessIdInformation {
    pid: usize,
    /// A UNICODE_STRING: its length and room in bytes, and its buffer.
    length: u16,
    room: u16,
    buffer: *mut u16,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQuerySystemInformation(
        class: i32,
        info: *mut std::ffi::c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
}

/// The full path of the program `pid` runs, as Windows names it: from the
/// process where the node may open it, else by its id ([`image_by_id`]).
fn image_of(pid: u32) -> std::io::Result<PathBuf> {
    image_opened(pid).or_else(|e| {
        image_by_id(pid).map_err(|by_id| std::io::Error::other(format!("{e}; by its id: {by_id}")))
    })
}

/// The image of `pid` by its id, which needs no handle of the process:
/// Windows names it by its NT path, and the drive letters' devices give
/// the Win32 one ([`crate::provider::drive_path`]).
fn image_by_id(pid: u32) -> std::io::Result<PathBuf> {
    let mut buf = vec![0u16; 32_767];
    let mut info = ProcessIdInformation {
        pid: pid as usize,
        length: 0,
        room: (buf.len() * 2) as u16,
        buffer: buf.as_mut_ptr(),
    };
    // SAFETY: the structure Windows fills, whose buffer of the room given
    // lives across the call.
    let status = unsafe {
        NtQuerySystemInformation(
            PROCESS_ID_INFORMATION,
            (&raw mut info).cast(),
            std::mem::size_of::<ProcessIdInformation>() as u32,
            std::ptr::null_mut(),
        )
    };
    if status < 0 {
        return Err(std::io::Error::other(format!(
            "NtQuerySystemInformation: {:#x}",
            status as u32
        )));
    }
    let nt = String::from_utf16_lossy(&buf[..usize::from(info.length) / 2]);
    let devices: Vec<(char, String)> = ('A'..='Z')
        .filter_map(|letter| {
            let drive = crate::win_user::wide(format!("{letter}:"));
            let mut target = vec![0u16; 1024];
            // SAFETY: a NUL-ended name and a buffer of the size given.
            let n = unsafe {
                QueryDosDeviceW(drive.as_ptr(), target.as_mut_ptr(), target.len() as u32)
            } as usize;
            // The first of the names it gives, up to its NUL.
            let first = target[..n].split(|c| *c == 0).next()?;
            (!first.is_empty()).then(|| (letter, String::from_utf16_lossy(first)))
        })
        .collect();
    crate::provider::drive_path(&nt, &devices)
        .ok_or_else(|| std::io::Error::other(format!("{nt} is on no drive letter")))
}

/// The image of `pid`, read from the process, which the node must open.
fn image_opened(pid: u32) -> std::io::Result<PathBuf> {
    // SAFETY: a handle this code closes below, and a buffer of the size
    // given.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let mut buf = vec![0u16; 32_768];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
        let e = std::io::Error::last_os_error();
        CloseHandle(h);
        if ok == 0 {
            return Err(e);
        }
        Ok(PathBuf::from(String::from_utf16_lossy(
            &buf[..len as usize],
        )))
    }
}

/// What the client of `pipe` is ([`Seen`]), against the program `allowed`
/// names: its account must be let in ([`crate::provider::admits`], with
/// `owners`), told by its token, which identifying the client shows; then
/// the image of its process `pid` ([`image_of`]) and the allowed program's
/// real path ([`resolved`]). Blocks.
pub(crate) fn look(
    pipe: usize,
    pid: Option<u32>,
    allowed: &Path,
    owners: &[String],
) -> Result<Seen, String> {
    let pid = pid.ok_or("refused: the node cannot tell which process asks")?;
    let who = |e: std::io::Error| format!("refused: the node cannot tell who asks: {e}");
    let (sid, admin) = {
        let _as = AsClient::new(pipe as HANDLE).map_err(who)?;
        let token = crate::win_user::thread_token().map_err(who)?;
        let sid = crate::win_user::token_sid(&token).map_err(who)?;
        let admin = crate::win_user::has_admins(&token).map_err(who)?;
        (sid, admin)
    };
    crate::provider::admits(&sid, owners, admin)?;
    let running = image_of(pid)
        .map_err(|e| format!("refused: the node cannot tell which program asks: {e}"))?;
    let real = resolved(allowed, owners)?;
    Ok(Seen {
        same: crate::provider::same_image(&running, &real),
        running,
        nnp: false,
        chain: vec![pid],
    })
}

/// `allowed` resolved as the node, and where the node's account may not
/// open it (a program in the owner's folders) as the owner, with the logon
/// the owner's stored password gives, as the folder grants act as the
/// owner ([`crate::win_user::FsAs`]).
fn resolved(allowed: &Path, owners: &[String]) -> Result<PathBuf, String> {
    std::fs::canonicalize(allowed).or_else(|mine| {
        let mut why = mine.to_string();
        for sid in owners {
            let account = crate::win_user::name_of_sid(sid).and_then(|n| {
                crate::win_user::lookup(&n)?.ok_or_else(|| format!("no account {n}"))
            });
            let as_owner = account.and_then(|a| {
                let _as =
                    crate::win_user::FsAs::new(&a).map_err(|e| format!("as {}: {e}", a.name))?;
                std::fs::canonicalize(allowed).map_err(|e| format!("as {}: {e}", a.name))
            });
            match as_owner {
                Ok(p) => return Ok(p),
                Err(e) => why = format!("{why}; {e}"),
            }
        }
        Err(format!(
            "refused: the node cannot open {}: {why}",
            allowed.display()
        ))
    })
}

/// Serves the provider pipe until the task is aborted, for the owners
/// `owners` (SIDs); the first instance is made before this returns. A
/// provider's connection stays, and holds one of the pipe's own places
/// ([`nerve_transport::ctl::MAX_PROVIDERS`]): neither this pipe nor the
/// owner's can take the other's.
pub(crate) fn serve(shared: Arc<Shared>, owners: Vec<String>) -> Result<JoinHandle<()>, String> {
    let own = crate::win_user::own_sid()
        .map_err(|e| e.to_string())
        .and_then(|s| crate::win_host::sid_text(&s))
        .map_err(|e| format!("the provider pipe: cannot read this account's SID: {e}"))?;
    let sd = Descriptor::from_sddl(&crate::owner::dacl_text(&own, &owners))
        .map_err(|e| format!("the provider pipe: cannot make its DACL: {e}"))?;
    let first = instance(PIPE_NAME, &sd, true)
        .map_err(|e| format!("the provider pipe {PIPE_NAME}: {e}"))?;
    Ok(tokio::spawn(accept(shared, owners, sd, first)))
}

async fn accept(
    shared: Arc<Shared>,
    owners: Vec<String>,
    sd: Descriptor,
    mut listening: NamedPipeServer,
) {
    let places = Arc::new(tokio::sync::Semaphore::new(
        nerve_transport::ctl::MAX_PROVIDERS,
    ));
    loop {
        if listening.connect().await.is_err() {
            let _ = listening.disconnect();
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        }
        let next = loop {
            match instance(PIPE_NAME, &sd, false) {
                Ok(n) => break n,
                Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
            }
        };
        let conn = std::mem::replace(&mut listening, next);
        let Ok(place) = places.clone().try_acquire_owned() else {
            if conn.writable().await.is_ok() {
                let busy = serde_json::json!({"error": nerve_transport::ctl::BUSY});
                let _ = conn.try_write(format!("{busy}\n").as_bytes());
            }
            continue;
        };
        let (pid, pipe) = (client_pid(&conn), conn.as_raw_handle() as usize);
        let s = shared.clone();
        let owners = owners.clone();
        tokio::spawn(async move {
            let _place = place;
            let handler = Arc::new(move |req: nerve_transport::ctl::CtlRequest, _: ()| {
                let s = s.clone();
                let owners = owners.clone();
                async move {
                    if req.method != "hello" {
                        return nerve_transport::ctl::Reply::Err(format!(
                            "the provider pipe takes a provider's hello only, not {:?}",
                            req.method
                        ));
                    }
                    // The pipe lives while its request is answered, and
                    // with the session after.
                    let caller = Caller { pid, pipe, owners };
                    crate::provider::attach(&s, req.params, caller).await
                }
            });
            let _ = nerve_transport::ctl::serve_stream(conn, (), handler).await;
        });
    }
}
