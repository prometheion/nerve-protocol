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
//!
//! The owner's commands in the terminal (`pair`, `nodes`, `token`) come the
//! same way, as one request after [`OWNER_HELLO`] (crate::owner_calls). Of
//! the two ways to the running center a command could take, this one adds
//! nothing another account can reach: it works with the web UI off, and it
//! needs no owner token read from the folder and sent to a TCP port that
//! every account of the machine may connect to. Root and the center's own
//! account may use it on Linux; on Windows its account, SYSTEM, and an
//! administrator in an elevated terminal, whom the pipe's access list lets
//! in and who may only make these requests, not attach a harness.

use std::fs::File;
use std::path::{Path, PathBuf};

pub const LOCK_FILE: &str = "center.lock";
pub const RUN_DIR: &str = "run";
pub const SOCKET: &str = "harness.sock";
/// The first line an attaching process sends.
pub const HELLO: &str = "{\"role\":\"harness\"}";
/// The first line an owner's command sends, then its request.
pub const OWNER_HELLO: &str = "{\"role\":\"owner\"}";
/// The longest request line of an owner's command.
const OWNER_REQUEST: u64 = 64 * 1024;

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

/// Whether the account `sid` (as `S-1-5-…`) may attach a harness to the
/// center of `own`: that one, or SYSTEM. Any other account the pipe's
/// access list lets in (the administrators) makes the owner's requests
/// only. So does one whose account is not known (`None`): a service that
/// is no administrator cannot open an elevated administrator's process to
/// read it, and the access list lets in no one else.
#[cfg_attr(not(windows), allow(dead_code))]
fn may_attach_sid(sid: Option<&str>, own: &str) -> bool {
    sid.is_some_and(|sid| sid == own || sid == "S-1-5-18")
}

/// The held center lock; dropping it releases the lock.
pub struct Lock {
    _file: File,
}

/// Opens the lock file of `state`, made when `create`. Not through a link:
/// the folder may be another account's (the installed center's, under an
/// administrator's or root's restore), and its link could make this create
/// or open any file the caller may write; nor does it wait on what is not a
/// plain file (a FIFO the folder's user put there for root's `status` or
/// restore).
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
        o.mode(0o600);
    }
    let file = nerve_transport::files::no_follow(&mut o).open(state.join(LOCK_FILE))?;
    if !nerve_transport::files::is_plain(&file)? {
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

/// Serves one attached harness on `stream`, once it said [`HELLO`], or one
/// owner's request after [`OWNER_HELLO`]. `harness` says whether the peer
/// may attach a harness, as only the center's own account may; an
/// administrator on Windows may make an owner's request only.
#[cfg(any(unix, windows))]
async fn attached<S>(
    center: crate::center::Center,
    ui: std::sync::Arc<crate::ui::Ui>,
    stream: S,
    harness: bool,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
{
    use tokio::io::{AsyncBufReadExt, AsyncReadExt};
    let (r, w) = tokio::io::split(stream);
    let mut r = tokio::io::BufReader::new(r);
    let mut first = String::new();
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        (&mut r).take(OWNER_REQUEST).read_line(&mut first),
    )
    .await;
    if !matches!(read, Ok(Ok(_))) {
        return;
    }
    match first.trim() {
        HELLO if harness => crate::mcp::serve_lines(center, r, w, "attached").await,
        // The accept loop of Linux refuses such a peer before this; on
        // Windows an administrator's account gets here, and the log is the
        // only place that says why its harness ended at once.
        HELLO => {
            tracing::warn!("refused a harness: this account may make the owner's requests only")
        }
        OWNER_HELLO => owner_request(&ui, r, w).await,
        _ => {}
    }
}

/// Answers one owner's request: a line `{"method", "path", "body"}`, as
/// the web UI would send it, answered by its handler
/// ([`crate::ui::Ui::owner_call`]) with a line `{"ok": …}` or
/// `{"error": …}`.
#[cfg(any(unix, windows))]
async fn owner_request<R, W>(ui: &crate::ui::Ui, r: R, mut w: W)
where
    R: tokio::io::AsyncBufRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
    let mut line = String::new();
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        r.take(OWNER_REQUEST).read_line(&mut line),
    )
    .await;
    if !matches!(read, Ok(Ok(n)) if n > 0) {
        return;
    }
    let answer = match serde_json::from_str::<serde_json::Value>(&line) {
        Ok(req) => {
            let s = |k: &str| req[k].as_str().unwrap_or_default().to_string();
            match ui.owner_call(&s("method"), &s("path"), &req["body"]).await {
                Ok(v) => serde_json::json!({ "ok": v }),
                Err((_, e)) => serde_json::json!({ "error": e["error"] }),
            }
        }
        Err(e) => serde_json::json!({ "error": format!("not a request: {e}") }),
    };
    let _ = w.write_all(format!("{answer}\n").as_bytes()).await;
    let _ = w.shutdown().await;
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

    /// Serves attached harnesses and the owner's requests until the task
    /// is dropped.
    pub async fn serve(center: Center, ui: std::sync::Arc<crate::ui::Ui>, listener: UnixListener) {
        let me = nerve_transport::net::euid();
        let mut failing = false;
        loop {
            let Some((stream, _)) = accepted(listener.accept().await, &mut failing).await else {
                continue;
            };
            let uid = stream.peer_cred().map(|c| c.uid()).ok();
            if uid != Some(me) && uid != Some(0) {
                tracing::warn!(?uid, "refused a harness from another user");
                continue;
            }
            tokio::spawn(super::attached(center.clone(), ui.clone(), stream, true));
        }
    }

    /// The connection an accept gave, or `None` after a failed one, which
    /// is logged once while it lasts and followed by a pause: a lasting
    /// failure (no file descriptor left) would turn the loop into a spin
    /// that burns a core and holds up the tasks that would free one.
    pub(super) async fn accepted<T>(r: std::io::Result<T>, failing: &mut bool) -> Option<T> {
        match r {
            Ok(c) => {
                *failing = false;
                Some(c)
            }
            Err(e) => {
                if !std::mem::replace(failing, true) {
                    tracing::warn!("the harness socket cannot accept a connection: {e}");
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                None
            }
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

    /// Whether the account `sid`, where it is known, may attach a harness
    /// ([`super::may_attach_sid`]).
    fn may_attach(sid: Option<&[u8]>, own: &[u8]) -> bool {
        let sid = sid.and_then(|s| sid_text(s).ok());
        match sid_text(own) {
            Ok(own) => super::may_attach_sid(sid.as_deref(), &own),
            Err(_) => false,
        }
    }

    /// Serves attached harnesses and the owner's requests until the task
    /// is dropped. A new instance waits before one that a client took is
    /// served, so the pipe is never without one.
    pub async fn serve(center: Center, ui: std::sync::Arc<crate::ui::Ui>, l: Listener) {
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
            // Any other account the pipe's access list let in is an
            // administrator in an elevated terminal, whose process the
            // service may not open: the owner's requests only, no harness.
            let account = client_pid(&conn).and_then(|pid| user_of(Some(pid)).ok());
            let harness = may_attach(account.as_deref(), &own);
            tokio::spawn(super::attached(center.clone(), ui.clone(), conn, harness));
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
        // The three entries are this account's, SYSTEM's and the
        // administrators': an access list that names anyone else, or
        // another account where this one belongs, has three entries too.
        let me = std::process::Command::new("whoami").output().unwrap();
        let me = String::from_utf8_lossy(&me.stdout).trim().to_lowercase();
        let named = |acl: &str| {
            let acl = acl.to_lowercase();
            [
                me.as_str(),
                "nt authority\\system",
                "builtin\\administrators",
            ]
            .iter()
            .all(|who| acl.contains(&format!("{who}:(")))
        };
        let d = tempfile::tempdir().unwrap();
        let state = d.path().join("state");
        let _lock = try_lock(&state).unwrap().unwrap();
        let acl = icacls(&state);
        assert_eq!(entries(&acl), 3, "{acl}");
        assert!(named(&acl), "{acl}");
        assert!(!acl.contains("(I)"), "{acl}");
        std::fs::write(state.join("owner-token"), "x").unwrap();
        let acl = icacls(&state.join("owner-token"));
        assert_eq!(entries(&acl), 3, "{acl}");
        assert!(named(&acl), "{acl}");
        let backup = d.path().join("c.bak");
        std::fs::write(&backup, "x").unwrap();
        crate::util::private_file(&backup).unwrap();
        let acl = icacls(&backup);
        assert_eq!(entries(&acl), 3, "{acl}");
        assert!(named(&acl), "{acl}");
        assert!(!acl.contains("(I)"), "{acl}");
    }

    /// Only the center's own account and SYSTEM attach (round 1,
    /// correctness 5): the pipe's access list also names the
    /// administrators, so this is the line that keeps another account of
    /// theirs, and everyone else, out.
    #[test]
    fn only_the_centers_account_and_system_attach() {
        let own = "S-1-5-21-1-2-3-1001";
        assert!(may_attach_sid(Some(own), own));
        assert!(may_attach_sid(Some("S-1-5-18"), own));
        // An account the service could not read is an administrator's in
        // an elevated terminal: the owner's requests, no harness.
        assert!(!may_attach_sid(None, own));
        for other in [
            "S-1-5-21-1-2-3-1002",
            "S-1-5-32-544",
            "S-1-1-0",
            "S-1-5-19",
            "S-1-5-80-1-2-3-4-5",
            "",
        ] {
            assert!(!may_attach_sid(Some(other), own), "{other}");
        }
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

#[cfg(test)]
mod link_tests {
    use super::*;

    /// A link in place of the lock, as the user of an installed center's
    /// state folder could leave for root's or an administrator's restore,
    /// is not followed: the file it names is neither made nor opened.
    /// (Making a link takes a privilege on Windows; the `windows` job runs
    /// as an administrator.)
    #[test]
    fn the_lock_is_not_taken_through_a_link() {
        let d = tempfile::tempdir().unwrap();
        let state = d.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        let target = d.path().join("made-through-the-link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, state.join(LOCK_FILE)).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&target, state.join(LOCK_FILE)).unwrap();
        let e = try_lock(&state).err().expect("a lock through a link");
        assert!(e.contains(LOCK_FILE), "{e}");
        assert!(!target.exists());
        // A plain lock file is taken as before.
        std::fs::remove_file(state.join(LOCK_FILE)).unwrap();
        assert!(try_lock(&state).unwrap().is_some());
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// A failed accept pauses the harness socket's loop, so a lasting
    /// failure (EMFILE) does not spin a core.
    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn a_failed_accept_pauses_the_loop() {
        let mut failing = false;
        let started = tokio::time::Instant::now();
        for _ in 0..10 {
            let r: std::io::Result<()> = Err(std::io::Error::from_raw_os_error(libc::EMFILE));
            assert!(unix::accepted(r, &mut failing).await.is_none());
        }
        assert!(failing);
        assert!(started.elapsed() >= std::time::Duration::from_secs(1));
        assert_eq!(unix::accepted(Ok(()), &mut failing).await, Some(()));
        assert!(!failing);
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

#[cfg(test)]
mod role_tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    /// What a peer gets for `lines` on a connection that may or may not
    /// attach a harness: the first line of the answer, empty for none.
    async fn first_answer(harness: bool, lines: &str) -> String {
        nerve_transport::init_crypto();
        let d = tempfile::tempdir().unwrap();
        let center = crate::center::Center::open(crate::center::Options {
            state_dir: d.path().to_path_buf(),
            name: Some("test".into()),
            public_url: "http://127.0.0.1:1".into(),
            log: None,
            log_level: None,
        })
        .unwrap();
        let ui = crate::ui::Ui::new(&center, None, true);
        let (mine, theirs) = tokio::io::duplex(64 * 1024);
        tokio::spawn(attached(center, ui, theirs, harness));
        let (r, mut w) = tokio::io::split(mine);
        w.write_all(lines.as_bytes()).await.unwrap();
        let mut answer = String::new();
        let mut r = tokio::io::BufReader::new(r);
        let read =
            tokio::time::timeout(std::time::Duration::from_secs(10), r.read_line(&mut answer))
                .await;
        assert!(read.is_ok(), "no answer and no end within 10 s");
        answer
    }

    /// The `tracing` events of a thread: their level and message.
    struct Events(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    impl tracing::Subscriber for Events {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, e: &tracing::Event<'_>) {
            struct Message(String);
            impl tracing::field::Visit for Message {
                fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
                    if f.name() == "message" {
                        self.0 = format!("{v:?}");
                    }
                }
            }
            let mut m = Message(String::new());
            e.record(&mut m);
            self.0
                .lock()
                .unwrap()
                .push(format!("{} {}", e.metadata().level(), m.0));
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// What `run` gives and the events of this thread while it ran (the
    /// test's runtime runs its tasks on this thread).
    async fn said<T>(run: impl std::future::Future<Output = T>) -> (T, Vec<String>) {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let _guard = tracing::subscriber::set_default(Events(seen.clone()));
        let answer = run.await;
        let events = seen.lock().unwrap().clone();
        (answer, events)
    }

    /// A peer that may not attach a harness (an administrator's other
    /// account on Windows) gets no MCP session, only the owner's requests
    /// (round 1 of #213's second pass, security 4).
    #[tokio::test]
    async fn only_a_peer_that_may_attach_gets_a_harness_session() {
        let init = format!(
            "{HELLO}\n{}\n",
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "t", "version": "1"}}})
        );
        let (refused, said) = said(first_answer(false, &init)).await;
        assert_eq!(refused, "", "{refused}");
        // The refusal is in the log (round 2 of #213's second pass,
        // correctness 5).
        assert!(
            said.iter().any(|l| l.contains("refused a harness")),
            "{said:?}"
        );
        let served = first_answer(true, &init).await;
        assert!(served.contains("\"serverInfo\""), "{served}");
        let request = format!(
            "{OWNER_HELLO}\n{}\n",
            serde_json::json!({"method": "GET", "path": "/api/overview", "body": {}})
        );
        let owners = first_answer(false, &request).await;
        let v: serde_json::Value = serde_json::from_str(&owners).unwrap();
        assert!(v["ok"]["nodes"].is_array(), "{v}");
    }
}
