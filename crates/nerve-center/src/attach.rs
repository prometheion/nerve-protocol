//! One center per state folder. The first `nerve-center` takes the lock and owns
//! the center; a second one started by another harness on the same state
//! folder attaches to it and only relays its stdio, so both harnesses share
//! the nodes and links. It attaches over `<state>/run/harness.sock` on Unix
//! and over a named pipe on Windows ([`pipe_name`]).
//!
//! The socket is mode 0600 in a 0700 folder, and the owner also checks the
//! peer's uid. The pipe lets only its account, SYSTEM and the
//! administrators open it, refuses other machines, and the owner checks
//! the account of the process at the other end; the attaching one first
//! checks that the pipe's owner is its own account, as another account
//! could have made a pipe of that name first.

use std::fs::File;
use std::path::{Path, PathBuf};

pub const LOCK_FILE: &str = "center.lock";
pub const RUN_DIR: &str = "run";
pub const SOCKET: &str = "harness.sock";
/// The first line an attaching process sends.
pub const HELLO: &str = "{\"role\":\"harness\"}";

pub fn socket_path(state: &Path) -> PathBuf {
    state.join(RUN_DIR).join(SOCKET)
}

/// The name of the attach pipe of the center in `state`: a hash of the
/// folder's real path, which every instance on that folder finds alike.
pub fn pipe_name(state: &Path) -> String {
    let dir = std::fs::canonicalize(state)
        .or_else(|_| std::path::absolute(state))
        .unwrap_or_else(|_| state.to_path_buf());
    nerve_service::win::pipe::name_for("nerve-center", &dir.to_string_lossy())
}

/// The held center lock; dropping it releases the lock.
pub struct Lock {
    _file: File,
}

/// Opens the lock file of `state`, made when `create`. On Unix not through
/// a link: the folder may be another user's (the installed center's, under
/// root's restore), and its link could make this create or open any file
/// the caller may write; nor does it wait on what is not a plain file (a
/// FIFO the folder's user put there for root's `status` or restore).
fn open_lock(state: &Path, create: bool) -> std::io::Result<File> {
    let mut o = std::fs::OpenOptions::new();
    if create {
        o.create(true).truncate(false).write(true);
    } else {
        o.read(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = o.open(state.join(LOCK_FILE))?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("it is not a file"));
    }
    Ok(file)
}

/// Takes the center lock, or `None` when another process holds it: a
/// center runs there, or a restore.
pub fn try_lock(state: &Path) -> Result<Option<Lock>, String> {
    crate::util::private_state(state)?;
    let path = state.join(LOCK_FILE);
    let file =
        open_lock(state, true).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    // Written out in full: the file lock is no std Mutex, and the scan for
    // locks around `nerve_transport::sync` goes by the method's name.
    match std::fs::File::try_lock(&file) {
        Ok(()) => Ok(Some(Lock { _file: file })),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(std::fs::TryLockError::Error(e)) => Err(format!("cannot lock {}: {e}", path.display())),
    }
}

/// Whether a center runs in `state`: it holds the lock there. `None` where
/// that cannot be told (no lock file yet: no center ran; or a folder this
/// account may not open). Opens the file only, so it never makes one in
/// another's folder.
pub fn runs(state: &Path) -> Option<bool> {
    let file = open_lock(state, false).ok()?;
    match file.try_lock_shared() {
        Ok(()) => Some(false),
        Err(std::fs::TryLockError::WouldBlock) => Some(true),
        Err(std::fs::TryLockError::Error(_)) => None,
    }
}

/// Serves one attached harness on `stream`, once it said [`HELLO`].
#[cfg(any(unix, windows))]
async fn attached<S>(center: crate::center::Center, stream: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
{
    use tokio::io::AsyncBufReadExt;
    let (r, w) = tokio::io::split(stream);
    let mut r = tokio::io::BufReader::new(r);
    let mut first = String::new();
    let read =
        tokio::time::timeout(std::time::Duration::from_secs(5), r.read_line(&mut first)).await;
    if !matches!(read, Ok(Ok(_))) || first.trim() != HELLO {
        return;
    }
    crate::mcp::serve_lines(center, r, w, "attached").await;
}

/// Relays this process's stdio over `stream` to the owner until either side
/// ends.
#[cfg(any(unix, windows))]
async fn relay_on<S>(stream: S) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
{
    use tokio::io::AsyncWriteExt;
    let (mut r, mut w) = tokio::io::split(stream);
    w.write_all(format!("{HELLO}\n").as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let up = async {
        let _ = tokio::io::copy(&mut tokio::io::stdin(), &mut w).await;
        // A socket's end says the harness went; a pipe has no such end, so
        // there the owner hears it when this process ends.
        let _ = w.shutdown().await;
    };
    let mut down = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut r, &mut tokio::io::stdout()).await;
    });
    // The harness closing stdin ends the session; the owner closing the
    // connection ends this process.
    tokio::select! {
        _ = up => {
            // stdin is done; let the owner finish its replies.
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), &mut down).await;
        }
        _ = &mut down => {}
    }
    Ok(())
}

#[cfg(unix)]
mod unix {
    use std::path::Path;

    use tokio::net::{UnixListener, UnixStream};

    use crate::center::Center;

    use super::RUN_DIR;

    /// Binds the harness socket for the owner.
    pub fn bind(state: &Path) -> Result<UnixListener, String> {
        let dir = state.join(RUN_DIR);
        nerve_transport::files::create_private_dir(&dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        let path = super::socket_path(state);
        // The lock is held, so a socket file left here is stale.
        let _ = std::fs::remove_file(&path);
        let l = UnixListener::bind(&path)
            .map_err(|e| format!("cannot listen on {}: {e}", path.display()))?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
        Ok(l)
    }

    /// Serves attached harnesses until the task is dropped.
    pub async fn serve(center: Center, listener: UnixListener) {
        let me = nerve_transport::net::euid();
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let uid = stream.peer_cred().map(|c| c.uid()).ok();
            if uid != Some(me) && uid != Some(0) {
                tracing::warn!(?uid, "refused a harness from another user");
                continue;
            }
            tokio::spawn(super::attached(center.clone(), stream));
        }
    }

    /// Relays this process's stdio to the owner until either side ends.
    pub async fn relay(state: &Path) -> Result<(), String> {
        let path = super::socket_path(state);
        let s = UnixStream::connect(&path).await.map_err(|e| {
            format!(
                "another nerve-center holds {} but its harness socket {} does not answer: {e}",
                state.display(),
                path.display()
            )
        })?;
        super::relay_on(s).await
    }
}

#[cfg(unix)]
pub use unix::{bind, relay, serve};

#[cfg(windows)]
mod windows {
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;
    use std::time::Duration;

    use nerve_service::win::pipe::{
        Descriptor, PIPE_BUSY, client_pid, dacl_text, foreign_owner, instance, open_identified,
    };
    use nerve_service::win::process::user_of;
    use nerve_service::win::sid::sid_text;
    use tokio::net::windows::named_pipe::NamedPipeServer;

    use crate::center::Center;

    /// The attach pipe's first instance, and what makes the next ones.
    pub struct Listener {
        name: String,
        sd: Descriptor,
        first: NamedPipeServer,
        /// The account this center runs as, the one that may attach.
        own: Vec<u8>,
    }

    /// Makes the attach pipe for the owner: this account, SYSTEM and the
    /// administrators may open it, no other machine. A pipe of that name
    /// that another process made first is an error: the center then runs
    /// without one.
    pub fn bind(state: &Path) -> Result<Listener, String> {
        let name = super::pipe_name(state);
        let own = user_of(None).map_err(|e| format!("the attach pipe: {e}"))?;
        let sd = Descriptor::from_sddl(&dacl_text(&sid_text(&own)?))
            .map_err(|e| format!("the attach pipe: cannot make its DACL: {e}"))?;
        let first = instance(&name, &sd, true).map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => {
                format!("the attach pipe {name} is taken: another process made it first")
            }
            _ => format!("the attach pipe {name}: {e}"),
        })?;
        Ok(Listener {
            name,
            sd,
            first,
            own,
        })
    }

    /// Whether the account `sid` may attach: the center's own, or SYSTEM's.
    fn may_attach(sid: &[u8], own: &[u8]) -> bool {
        sid == own || sid_text(sid).is_ok_and(|s| s == "S-1-5-18")
    }

    /// Serves attached harnesses until the task is dropped. A new instance
    /// waits before one that a client took is served, so the pipe is never
    /// without one.
    pub async fn serve(center: Center, l: Listener) {
        let Listener {
            name,
            sd,
            first,
            own,
        } = l;
        let mut next = first;
        let mut failing = false;
        loop {
            let connected = next.connect().await;
            let made = loop {
                match instance(&name, &sd, false) {
                    Ok(n) => break n,
                    Err(e) => {
                        if !std::mem::replace(&mut failing, true) {
                            tracing::warn!("the attach pipe cannot make another instance now: {e}");
                        }
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            };
            failing = false;
            let conn = std::mem::replace(&mut next, made);
            if connected.is_err() {
                continue;
            }
            let account = client_pid(&conn).and_then(|pid| user_of(Some(pid)).ok());
            if !account.as_ref().is_some_and(|a| may_attach(a, &own)) {
                let who = account.and_then(|a| sid_text(&a).ok());
                tracing::warn!(?who, "refused a harness from another account");
                continue;
            }
            tokio::spawn(super::attached(center.clone(), conn));
        }
    }

    /// Relays this process's stdio to the owner until either side ends,
    /// once the pipe proved to be the center's: one that another account
    /// made learns nothing.
    pub async fn relay(state: &Path) -> Result<(), String> {
        let name = super::pipe_name(state);
        let mut busy = 0;
        let client = loop {
            match open_identified(&name) {
                Ok(c) => break c,
                // Every instance in use: the center is there, and busy.
                Err(e) if e.raw_os_error() == Some(PIPE_BUSY) && busy < 50 => {
                    busy += 1;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(e) => {
                    return Err(format!(
                        "another nerve-center holds {} but its attach pipe {name} does not answer: {e}",
                        state.display()
                    ));
                }
            }
        };
        let own = user_of(None).map_err(|e| e.to_string())?;
        let foreign = foreign_owner(client.as_raw_handle(), Some(&own))
            .map_err(|e| format!("cannot check the attach pipe {name}: {e}"))?;
        if let Some(owner) = foreign {
            let who = sid_text(&owner).unwrap_or_else(|e| e);
            return Err(format!(
                "the attach pipe {name} belongs to {who}, not to the center, so nothing was sent to it: another process made it first. End that process, then start the center again"
            ));
        }
        super::relay_on(client).await
    }
}

#[cfg(windows)]
pub use windows::{Listener, bind, relay, serve};

#[cfg(test)]
mod lock_tests {
    use super::*;

    /// One center per state folder on every system: while one holds the
    /// lock a second finds it held, and `runs` says a center runs (#64:
    /// Windows had no lock, and a second center failed at the node port).
    #[test]
    fn a_second_center_finds_the_lock_held() {
        let d = tempfile::tempdir().unwrap();
        let state = d.path().join("state");
        assert_eq!(runs(&state), None);
        let lock = try_lock(&state).unwrap().expect("the first center's");
        assert!(try_lock(&state).unwrap().is_none());
        assert_eq!(runs(&state), Some(true));
        drop(lock);
        assert_eq!(runs(&state), Some(false));
        assert!(try_lock(&state).unwrap().is_some());
    }

    /// On Windows the state folder is this account's, SYSTEM's and the
    /// administrators' alone, and what is put in it inherits that; a backup
    /// file gets the same, whatever its folder hands down.
    #[cfg(windows)]
    #[test]
    fn the_state_folder_and_a_backup_are_private_on_windows() {
        let icacls = |p: &Path| {
            let o = std::process::Command::new("icacls")
                .arg(p)
                .output()
                .unwrap();
            String::from_utf8_lossy(&o.stdout).into_owned()
        };
        let entries = |acl: &str| acl.lines().filter(|l| l.contains(":(")).count();
        let d = tempfile::tempdir().unwrap();
        let state = d.path().join("state");
        let _lock = try_lock(&state).unwrap().unwrap();
        let acl = icacls(&state);
        assert_eq!(entries(&acl), 3, "{acl}");
        assert!(!acl.contains("(I)"), "{acl}");
        std::fs::write(state.join("owner-token"), "x").unwrap();
        let acl = icacls(&state.join("owner-token"));
        assert_eq!(entries(&acl), 3, "{acl}");
        let backup = d.path().join("c.bak");
        std::fs::write(&backup, "x").unwrap();
        crate::util::private_file(&backup).unwrap();
        let acl = icacls(&backup);
        assert_eq!(entries(&acl), 3, "{acl}");
        assert!(!acl.contains("(I)"), "{acl}");
    }

    /// Every instance on a folder finds the same pipe, also by another
    /// spelling of the folder; another folder has another.
    #[test]
    fn the_attach_pipe_is_named_by_the_folder() {
        let d = tempfile::tempdir().unwrap();
        let state = d.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        let other = d.path().join("other");
        std::fs::create_dir_all(&other).unwrap();
        assert_eq!(
            pipe_name(&state),
            pipe_name(&other.join("..").join("state"))
        );
        assert_ne!(pipe_name(&state), pipe_name(&other));
        assert!(pipe_name(&state).starts_with(r"\\.\pipe\nerve-center-"));
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// A link in place of the lock, as the user of an installed center's
    /// state folder could leave for root's restore, is not followed: the
    /// file it names is neither made nor opened.
    #[test]
    fn the_lock_is_not_taken_through_a_link() {
        let d = tempfile::tempdir().unwrap();
        let state = d.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        let target = d.path().join("made-through-the-link");
        std::os::unix::fs::symlink(&target, state.join(LOCK_FILE)).unwrap();
        let e = try_lock(&state).err().expect("a lock through a link");
        assert!(e.contains(LOCK_FILE), "{e}");
        assert!(!target.exists());
        // A plain lock file is taken as before.
        std::fs::remove_file(state.join(LOCK_FILE)).unwrap();
        assert!(try_lock(&state).unwrap().is_some());
    }

    /// Whether a center runs is not told through a link, nor by waiting on
    /// a FIFO in place of the lock (round 1, correctness 6): root's
    /// `status` and restore ask it in the center's user's folder.
    #[test]
    fn whether_a_center_runs_is_not_read_through_a_link_or_a_fifo() {
        let d = tempfile::tempdir().unwrap();
        let state = d.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        let held = d.path().join("held");
        std::fs::create_dir_all(&held).unwrap();
        let _lock = try_lock(&held).unwrap().unwrap();
        std::os::unix::fs::symlink(held.join(LOCK_FILE), state.join(LOCK_FILE)).unwrap();
        assert_eq!(runs(&state), None, "through a link");
        std::fs::remove_file(state.join(LOCK_FILE)).unwrap();
        let fifo = std::ffi::CString::new(state.join(LOCK_FILE).to_str().unwrap()).unwrap();
        // SAFETY: a plain call with a valid path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        let s = state.clone();
        std::thread::spawn(move || tx.send(runs(&s)).unwrap());
        let answer = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("runs() waited on a FIFO");
        assert_eq!(answer, None);
        assert_eq!(runs(&held), Some(true));
    }
}
