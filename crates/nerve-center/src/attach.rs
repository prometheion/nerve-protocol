//! One center per state folder. The first `nerve-center` takes the lock and owns
//! the center; a second one started by another harness on the same state
//! folder attaches to it over `<state>/run/harness.sock` and only relays its
//! stdio, so both harnesses share the nodes and links.
//!
//! The socket is mode 0600 in a 0700 folder, and the owner also checks the
//! peer's uid. Windows has neither the lock nor the socket: a second
//! instance there fails when it cannot bind the node port.

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

/// The held center lock; dropping it releases the lock.
pub struct Lock {
    _file: File,
}

/// Takes the center lock, or `None` when another process holds it.
#[cfg(unix)]
pub fn try_lock(state: &Path) -> Result<Option<Lock>, String> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    nerve_transport::files::create_private_dir(state)
        .map_err(|e| format!("cannot create {}: {e}", state.display()))?;
    let path = state.join(LOCK_FILE);
    // Not through a link: the folder may be another user's (the installed
    // center's, under root's restore), and its link could make this create
    // or open any file the caller may write.
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    // SAFETY: flock on a file descriptor this function owns.
    let r = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if r == 0 {
        return Ok(Some(Lock { _file: file }));
    }
    let e = std::io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
        Ok(None)
    } else {
        Err(format!("cannot lock {}: {e}", path.display()))
    }
}

#[cfg(not(unix))]
pub fn try_lock(state: &Path) -> Result<Option<Lock>, String> {
    std::fs::create_dir_all(state)
        .map_err(|e| format!("cannot create {}: {e}", state.display()))?;
    let path = state.join(LOCK_FILE);
    let file = File::create(&path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    Ok(Some(Lock { _file: file }))
}

/// Whether a center runs in `state`: it holds the lock there. `None` where
/// that cannot be told (no lock file yet: no center ran; or another
/// platform). Opens the file only, so it never makes one in another's
/// folder.
#[cfg(unix)]
pub fn runs(state: &Path) -> Option<bool> {
    use std::os::fd::AsRawFd;
    let file = std::fs::File::open(state.join(LOCK_FILE)).ok()?;
    // SAFETY: flock on a file descriptor this function owns.
    let r = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) };
    Some(r != 0)
}

#[cfg(not(unix))]
pub fn runs(_state: &Path) -> Option<bool> {
    None
}

/// Takes the center lock for work on the state folder that a running center
/// must not meet (a restore): `None` when a center runs. Where `try_lock`
/// has a real lock this is it. On Windows `try_lock` takes none, so a center
/// there holds its lock file open and this opens it without sharing, which a
/// running center's handle refuses.
#[cfg(unix)]
pub fn claim(state: &Path) -> Result<Option<Lock>, String> {
    try_lock(state)
}

#[cfg(not(unix))]
pub fn claim(state: &Path) -> Result<Option<Lock>, String> {
    use std::os::windows::fs::OpenOptionsExt;
    const SHARING_VIOLATION: i32 = 32;
    std::fs::create_dir_all(state)
        .map_err(|e| format!("cannot create {}: {e}", state.display()))?;
    let path = state.join(LOCK_FILE);
    match std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .share_mode(0)
        .open(&path)
    {
        Ok(file) => Ok(Some(Lock { _file: file })),
        Err(e) if e.raw_os_error() == Some(SHARING_VIOLATION) => Ok(None),
        Err(e) => Err(format!("cannot open {}: {e}", path.display())),
    }
}

#[cfg(unix)]
mod unix {
    use std::path::Path;

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};

    use crate::center::Center;

    use super::{HELLO, RUN_DIR};

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
            let center = center.clone();
            tokio::spawn(async move {
                let (r, w) = stream.into_split();
                let mut r = BufReader::new(r);
                let mut first = String::new();
                let read = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    r.read_line(&mut first),
                )
                .await;
                if !matches!(read, Ok(Ok(_))) || first.trim() != HELLO {
                    return;
                }
                crate::mcp::serve_lines(center, r, w, "attached").await;
            });
        }
    }

    /// Relays this process's stdio to the owner until either side ends.
    pub async fn relay(state: &Path) -> Result<(), String> {
        let path = super::socket_path(state);
        let mut s = UnixStream::connect(&path).await.map_err(|e| {
            format!(
                "another nerve-center holds {} but its harness socket {} does not answer: {e}",
                state.display(),
                path.display()
            )
        })?;
        s.write_all(format!("{HELLO}\n").as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let (mut r, mut w) = s.into_split();
        let up = async {
            let _ = tokio::io::copy(&mut tokio::io::stdin(), &mut w).await;
            let _ = w.shutdown().await;
        };
        let mut down = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut r, &mut tokio::io::stdout()).await;
        });
        // The harness closing stdin ends the session; the owner closing the
        // socket ends this process.
        tokio::select! {
            _ = up => {
                // stdin is done; let the owner finish its replies.
                let _ = tokio::time::timeout(std::time::Duration::from_secs(5), &mut down).await;
            }
            _ = &mut down => {}
        }
        Ok(())
    }
}

#[cfg(unix)]
pub use unix::{bind, relay, serve};

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
        let e = claim(&state).err().expect("a lock through a link");
        assert!(e.contains(LOCK_FILE), "{e}");
        assert!(!target.exists());
        // A plain lock file is taken as before.
        std::fs::remove_file(state.join(LOCK_FILE)).unwrap();
        assert!(claim(&state).unwrap().is_some());
    }
}
