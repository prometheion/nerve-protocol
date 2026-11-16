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
//! The owner's commands in the terminal and the app's center pages come the
//! same way, as one request after an owner's hello (crate::owner_calls):
//! the local owner channel, which works with the web UI off. Root and an
//! administrator make those requests as they are; any other caller gives
//! the owner token in its hello, checked as the web UI's login checks it
//! ([`crate::ui::Ui::channel_login`]), so a program of the owner, an agent
//! among them, gets nothing without it. Root and the center's own account
//! may attach a harness on Linux; on Windows its account and SYSTEM.
//!
//! The installed center also serves the owner endpoint, for the account
//! that installed it ([`OWNER_FILE`]), who cannot open the center's state
//! folder: on Linux the socket [`OWNER_SOCKET`] in the service's runtime
//! folder, which every account may open and the center checks the peer of;
//! on Windows the pipe [`OWNER_PIPE`], which only that account, the
//! center's, SYSTEM and the administrators may open. It takes the owner's
//! requests only, never a harness.

use std::fs::File;
use std::path::{Path, PathBuf};

pub const LOCK_FILE: &str = "center.lock";
pub const RUN_DIR: &str = "run";
pub const SOCKET: &str = "harness.sock";
/// The first line an attaching process sends.
pub const HELLO: &str = "{\"role\":\"harness\"}";
/// The first line an owner's command sends, then its request; a caller
/// that is not root or an administrator adds `"token"`, the owner token
/// ([`owner_hello`]).
pub const OWNER_HELLO: &str = "{\"role\":\"owner\"}";
/// The file in the installed center's state folder that names the account
/// that installed it, who may use the owner endpoint: its uid on Linux,
/// its SID on Windows. `install` writes it.
pub const OWNER_FILE: &str = "owner-account";
/// The owner socket's name in the installed service's runtime folder
/// (Linux).
pub const OWNER_SOCKET: &str = "owner.sock";
/// The installed center's owner pipe (Windows). Its name is fixed, not made
/// from the state folder as the attach pipe's is: the owner cannot open
/// that folder to learn its real path.
pub const OWNER_PIPE: &str = r"\\.\pipe\nerve-center-owner";
/// What a request that only checks the owner token asks: the app's log-in.
pub const LOGIN: &str = "/login";

/// An owner's hello, with the owner token where one is given.
pub fn owner_hello(token: Option<&str>) -> String {
    match token {
        Some(t) => serde_json::json!({"role": "owner", "token": t}).to_string(),
        None => OWNER_HELLO.to_string(),
    }
}

/// Who is at the other end of the attach socket or pipe, or of the owner
/// endpoint, by the account the system names for the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caller {
    /// It may attach a harness: the center's own account, root, SYSTEM.
    pub harness: bool,
    /// Its owner's requests need the owner token: all but root and an
    /// administrator.
    pub needs_token: bool,
}

/// [`Caller`] by uid (Linux): root, the center's own account `me`, or the
/// account that installed it (`owner`); `None` for anyone else.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn caller_of_uid(uid: Option<u32>, me: u32, owner: Option<u32>) -> Option<Caller> {
    match uid? {
        0 => Some(Caller {
            harness: true,
            needs_token: false,
        }),
        u if u == me => Some(Caller {
            harness: true,
            needs_token: true,
        }),
        u if Some(u) == owner => Some(Caller {
            harness: false,
            needs_token: true,
        }),
        _ => None,
    }
}

/// [`Caller`] by SID (Windows): `admin` says the caller's token holds the
/// administrators' group enabled (an elevated administrator; SYSTEM too).
/// SYSTEM, and the center's own account `own`, may attach; an elevated
/// administrator makes the owner's requests without the token; the
/// account that installed it (`owner`) and `own` unelevated with it.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn caller_of_sid(
    sid: Option<&str>,
    admin: bool,
    own: &str,
    owner: Option<&str>,
) -> Option<Caller> {
    let sid = sid?;
    let harness = sid == own || sid == "S-1-5-18";
    if admin || sid == "S-1-5-18" {
        return Some(Caller {
            harness,
            needs_token: false,
        });
    }
    (harness || Some(sid) == owner).then_some(Caller {
        harness,
        needs_token: true,
    })
}

/// The installed center's owner endpoint in `layout`: the socket in its
/// runtime folder (Linux; `None` while systemd has not made the folder), or
/// the fixed pipe (Windows).
pub fn owner_endpoint(layout: &crate::service::Layout) -> Option<PathBuf> {
    (cfg!(windows) || layout.run.is_dir()).then(|| owner_endpoint_at(layout))
}

/// Where [`owner_endpoint`] is, whether the center runs or not: for the
/// app, which says "not running" where nothing answers there.
pub fn owner_endpoint_at(layout: &crate::service::Layout) -> PathBuf {
    match cfg!(windows) {
        true => OWNER_PIPE.into(),
        false => layout.run.join(OWNER_SOCKET),
    }
}

/// The app's user the broker named for this command, by SID (Windows):
/// the account an `install` of the app makes the one that may ask the
/// center ([`installing_account`]).
static DESKTOP_USER: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Keeps the SID of `--desktop-user-sid`.
pub fn set_desktop_user(sid: Option<&str>) {
    if let Some(s) = sid.filter(|s| s.starts_with("S-1-")) {
        let _ = DESKTOP_USER.set(s.to_string());
    }
}

/// The account that runs `install`, for [`OWNER_FILE`]: on Linux the one
/// sudo or pkexec names (its uid), none for root itself; on Windows the
/// app's user the broker named, else the account this runs as (its SID).
pub fn installing_account() -> Option<String> {
    #[cfg(windows)]
    {
        if let Some(s) = DESKTOP_USER.get() {
            return Some(s.clone());
        }
        nerve_service::win::process::user_of(None)
            .ok()
            .and_then(|s| nerve_service::win::sid::sid_text(&s).ok())
    }
    #[cfg(not(windows))]
    {
        installing_uid(
            std::env::var("SUDO_UID").ok(),
            std::env::var("PKEXEC_UID").ok(),
        )
        .map(|u| u.to_string())
    }
}

/// [`installing_account`] on Linux from `SUDO_UID`, else `PKEXEC_UID` (the
/// app asks for root with pkexec); root is none.
#[cfg_attr(windows, allow(dead_code))]
fn installing_uid(sudo: Option<String>, pkexec: Option<String>) -> Option<u32> {
    let uid = |v: Option<String>| v.and_then(|u| u.trim().parse::<u32>().ok());
    uid(sudo).or_else(|| uid(pkexec)).filter(|u| *u != 0)
}

/// Names `account` in [`OWNER_FILE`] of `state`, where `install` knows one;
/// root's own install keeps the one an earlier install named.
pub fn keep_owner_account(state: &Path, account: Option<&str>) -> Result<(), String> {
    let Some(account) = account else {
        return Ok(());
    };
    let file = state.join(OWNER_FILE);
    nerve_service::write_file(&file, format!("{account}\n").as_bytes(), 0o600)
}

/// Who answers at an owner endpoint: the account of the process at the
/// other end of the socket (Linux, its uid), or the owner of the pipe
/// (Windows, its SID).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Peer {
    Uid(u32),
    Sid(String),
}

/// Whether `peer` is the installed center's service: the `nerve-center`
/// account or root on Linux; on Windows the service's account, SYSTEM or
/// the administrators, as no other account can make a pipe one of them
/// owns.
pub fn is_center_service(peer: &Peer) -> Result<bool, String> {
    Ok(match peer {
        #[cfg(not(windows))]
        Peer::Uid(uid) => {
            *uid == 0
                || nerve_service::account::lookup(crate::service::USER)?
                    .is_some_and(|a| a.uid == *uid)
        }
        #[cfg(windows)]
        Peer::Uid(_) => false,
        Peer::Sid(sid) => {
            sid == "S-1-5-18" || sid == "S-1-5-32-544" || *sid == crate::winsvc::account_sid()
        }
    })
}

/// A connection to an owner endpoint ([`open_owner`]).
#[cfg(unix)]
pub type OwnerStream = tokio::net::UnixStream;
#[cfg(windows)]
pub type OwnerStream = tokio::net::windows::named_pipe::NamedPipeClient;

/// Opens the owner endpoint `at` (the app's way to the installed center),
/// and says who answers there; nothing is sent. `Err(None)` where nothing
/// answers: the center does not run. The pipe is opened for identification
/// only, with the rights it gives the owner.
#[cfg(unix)]
pub async fn open_owner(at: &Path) -> Result<(OwnerStream, Peer), Option<String>> {
    let s = tokio::net::UnixStream::connect(at)
        .await
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => None,
            _ => Some(format!("cannot reach the center at {}: {e}", at.display())),
        })?;
    let uid = s
        .peer_cred()
        .map_err(|e| Some(format!("cannot tell who answers: {e}")))?
        .uid();
    Ok((s, Peer::Uid(uid)))
}

/// [`open_owner`] on Windows.
#[cfg(windows)]
pub async fn open_owner(at: &Path) -> Result<(OwnerStream, Peer), Option<String>> {
    use nerve_service::win::pipe::{PIPE_BUSY, open_limited, owner_of};
    use std::os::windows::io::AsRawHandle;
    let name = at.to_string_lossy().into_owned();
    let mut busy = 0;
    let client = loop {
        match open_limited(&name) {
            Ok(c) => break c,
            // ERROR_FILE_NOT_FOUND: no center made the pipe.
            Err(e) if e.raw_os_error() == Some(2) => return Err(None),
            Err(e) if e.raw_os_error() == Some(PIPE_BUSY) && busy < 50 => {
                busy += 1;
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(e) => return Err(Some(format!("cannot reach the center at {name}: {e}"))),
        }
    };
    let owner = owner_of(client.as_raw_handle() as _)
        .map_err(|e| e.to_string())
        .and_then(|s| nerve_service::win::sid::sid_text(&s))
        .map_err(|e| Some(format!("cannot tell who answers: {e}")))?;
    Ok((client, Peer::Sid(owner)))
}

/// The account that installed the center in `state`, as [`OWNER_FILE`]
/// names it; `None` where it names none (a center a harness started).
pub fn owner_account(state: &Path) -> Option<String> {
    let text = std::fs::read_to_string(state.join(OWNER_FILE)).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_string())
}
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
/// owner's request after an owner's hello. `who` names the caller once its
/// first line is read (a pipe's client is known only then): `None` for an
/// account that may not be served at all.
#[cfg(any(unix, windows))]
async fn attached<S>(
    center: crate::center::Center,
    ui: std::sync::Arc<crate::ui::Ui>,
    stream: S,
    who: impl FnOnce() -> Option<Caller>,
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
    let Some(caller) = who() else {
        tracing::warn!("refused a caller of another account");
        return;
    };
    let hello: serde_json::Value = serde_json::from_str(first.trim()).unwrap_or_default();
    match hello["role"].as_str() {
        Some("harness") if caller.harness => {
            crate::mcp::serve_lines(center, r, w, "attached").await
        }
        // The accept loop of Linux refuses such a peer before this; on
        // Windows an administrator's account gets here, and the log is the
        // only place that says why its harness ended at once.
        Some("harness") => {
            tracing::warn!("refused a harness: this account may make the owner's requests only")
        }
        Some("owner") => {
            let token = hello["token"].as_str();
            owner_request(&ui, caller, token, r, w).await
        }
        _ => {}
    }
}

/// Answers one owner's request: a line `{"method", "path", "query",
/// "body"}`, as the web UI would send it, answered by its handler
/// ([`crate::ui::Ui::owner_call`]) with a line `{"ok": …}` or `{"error",
/// "status"}` (the web UI's status of the refusal).
/// A caller that needs the owner token and gave a wrong one (or none) gets
/// `{"error", "login": true}`, after the wait of a wrong login. [`LOGIN`]
/// only checks the token.
#[cfg(any(unix, windows))]
async fn owner_request<R, W>(
    ui: &crate::ui::Ui,
    caller: Caller,
    token: Option<&str>,
    r: R,
    mut w: W,
) where
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
            let login = s("path") == LOGIN;
            // A token given is checked, also an administrator's: the app's
            // log-in asks whether the token is the owner's.
            let signed = match caller.needs_token || token.is_some() {
                true => ui.channel_login(token.unwrap_or_default(), login).await,
                false => Ok(()),
            };
            match signed {
                Err(e) => serde_json::json!({ "error": e, "login": true }),
                Ok(()) if login => serde_json::json!({ "ok": {} }),
                Ok(()) => match ui
                    .owner_call(&s("method"), &s("path"), &s("query"), &req["body"])
                    .await
                {
                    Ok(v) => serde_json::json!({ "ok": v }),
                    Err((status, e)) => {
                        serde_json::json!({ "error": e["error"], "status": status })
                    }
                },
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

    /// Binds the installed center's owner socket at `path` (in the
    /// service's runtime folder, which only the center may write): every
    /// account may open it, and [`serve`] checks who did.
    pub fn bind_owner(path: &Path) -> Result<UnixListener, String> {
        let _ = std::fs::remove_file(path);
        let l = UnixListener::bind(path)
            .map_err(|e| format!("cannot listen on {}: {e}", path.display()))?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))
            .map_err(|e| e.to_string())?;
        Ok(l)
    }

    /// Serves attached harnesses and the owner's requests until the task
    /// is dropped: from root, the center's own account, and `owner`, the
    /// uid of the account that installed it ([`super::OWNER_FILE`]).
    pub async fn serve(
        center: Center,
        ui: std::sync::Arc<crate::ui::Ui>,
        listener: UnixListener,
        owner: Option<u32>,
    ) {
        let me = nerve_transport::net::euid();
        let mut failing = false;
        loop {
            let Some((stream, _)) = accepted(listener.accept().await, &mut failing).await else {
                continue;
            };
            let uid = stream.peer_cred().map(|c| c.uid()).ok();
            let Some(caller) = super::caller_of_uid(uid, me, owner) else {
                tracing::warn!(?uid, "refused a caller from another user");
                continue;
            };
            tokio::spawn(super::attached(
                center.clone(),
                ui.clone(),
                stream,
                move || Some(caller),
            ));
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
pub use unix::{bind, bind_owner, relay, serve};

#[cfg(windows)]
mod windows {
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;
    use std::time::Duration;

    use nerve_service::win::pipe::{
        CLIENT_RIGHTS, Descriptor, PIPE_BUSY, client_identity, dacl_text, foreign_owner, instance,
        open_identified,
    };
    use nerve_service::win::process::user_of;
    use nerve_service::win::sid::sid_text;
    use tokio::net::windows::named_pipe::NamedPipeServer;

    use crate::center::Center;

    /// The attach pipe's (or the owner pipe's) first instance, and what
    /// makes the next ones.
    pub struct Listener {
        name: String,
        sd: Descriptor,
        first: NamedPipeServer,
        /// The account this center runs as, the one that may attach.
        own: String,
        /// The account that installed it, as a SID, where one is named.
        owner: Option<String>,
    }

    /// Makes the attach pipe for the owner: this account, SYSTEM and the
    /// administrators may open it, no other machine. A pipe of that name
    /// that another process made first is an error: the center then runs
    /// without one.
    pub fn bind(state: &Path) -> Result<Listener, String> {
        make(&super::pipe_name(state), None)
    }

    /// Makes the installed center's owner pipe `name`: the attach pipe's
    /// accounts, and the account that installed it (`owner`, a SID), which
    /// may read and write on it and make no instance of it
    /// ([`CLIENT_RIGHTS`]).
    pub fn bind_owner(name: &str, owner: Option<&str>) -> Result<Listener, String> {
        make(name, owner)
    }

    fn make(name: &str, owner: Option<&str>) -> Result<Listener, String> {
        let own = user_of(None)
            .map_err(|e| format!("the pipe {name}: {e}"))
            .and_then(|s| sid_text(&s))?;
        let mut dacl = dacl_text(&own);
        if let Some(o) = owner {
            dacl.push_str(&format!("(A;;{CLIENT_RIGHTS};;;{o})"));
        }
        let sd = Descriptor::from_sddl(&dacl)
            .map_err(|e| format!("the pipe {name}: cannot make its DACL: {e}"))?;
        let first = instance(name, &sd, true).map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => {
                format!("the pipe {name} is taken: another process made it first")
            }
            _ => format!("the pipe {name}: {e}"),
        })?;
        Ok(Listener {
            name: name.to_string(),
            sd,
            first,
            own,
            owner: owner.map(str::to_string),
        })
    }

    /// Serves attached harnesses and the owner's requests until the task
    /// is dropped. A new instance waits before one that a client took is
    /// served, so the pipe is never without one. The caller is named by
    /// its token, read at identification level once its first line came
    /// ([`super::caller_of_sid`]).
    pub async fn serve(
        center: Center,
        ui: std::sync::Arc<crate::ui::Ui>,
        l: Listener,
        _owner: Option<u32>,
    ) {
        let Listener {
            name,
            sd,
            first,
            own,
            owner,
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
                            tracing::warn!("the pipe {name} cannot make another instance now: {e}");
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
            // The handle lives while the task holds the connection, which
            // is past the first line, when the caller is named.
            let raw = conn.as_raw_handle() as usize;
            let (own, owner) = (own.clone(), owner.clone());
            let who = move || {
                let (sid, admin) = client_identity(raw as _)?;
                let sid = sid_text(&sid).ok();
                super::caller_of_sid(sid.as_deref(), admin, &own, owner.as_deref())
            };
            tokio::spawn(super::attached(center.clone(), ui.clone(), conn, who));
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
pub use windows::{Listener, bind, bind_owner, relay, serve};

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
    /// theirs, and everyone else, out. An elevated administrator makes the
    /// owner's requests without the owner token; the account that
    /// installed the center, and the center's own unelevated, only with it
    /// (owner, 2026-11-16).
    #[test]
    fn who_attaches_and_who_needs_the_owner_token_on_windows() {
        let own = "S-1-5-21-1-2-3-1001";
        let owner = "S-1-5-21-1-2-3-1002";
        let c = |harness, needs_token| {
            Some(Caller {
                harness,
                needs_token,
            })
        };
        assert_eq!(
            caller_of_sid(Some(own), false, own, Some(owner)),
            c(true, true)
        );
        assert_eq!(
            caller_of_sid(Some(own), true, own, Some(owner)),
            c(true, false)
        );
        assert_eq!(
            caller_of_sid(Some("S-1-5-18"), true, own, None),
            c(true, false)
        );
        assert_eq!(
            caller_of_sid(Some(owner), false, own, Some(owner)),
            c(false, true)
        );
        // The owner elevated is an administrator.
        assert_eq!(
            caller_of_sid(Some(owner), true, own, Some(owner)),
            c(false, false)
        );
        // An administrator who is no owner, elevated.
        assert_eq!(
            caller_of_sid(Some("S-1-5-21-1-2-3-1003"), true, own, Some(owner)),
            c(false, false)
        );
        // An account the service could not read gets nothing.
        assert_eq!(caller_of_sid(None, true, own, Some(owner)), None);
        for other in [
            "S-1-5-21-1-2-3-1003",
            "S-1-5-32-544",
            "S-1-1-0",
            "S-1-5-19",
            "S-1-5-80-1-2-3-4-5",
            "",
        ] {
            assert_eq!(
                caller_of_sid(Some(other), false, own, Some(owner)),
                None,
                "{other}"
            );
            assert_eq!(
                caller_of_sid(Some(other), false, own, None),
                None,
                "{other}"
            );
        }
        // No owner named: the owner's account is anyone else's.
        assert_eq!(caller_of_sid(Some(owner), false, own, None), None);
    }

    /// The Linux twin: root attaches and needs no token; the center's own
    /// account attaches and needs it for the owner's requests; the account
    /// that installed it makes those requests with the token only; nobody
    /// else gets in.
    #[test]
    fn who_attaches_and_who_needs_the_owner_token_on_linux() {
        let c = |harness, needs_token| {
            Some(Caller {
                harness,
                needs_token,
            })
        };
        assert_eq!(caller_of_uid(Some(0), 990, Some(1000)), c(true, false));
        assert_eq!(caller_of_uid(Some(990), 990, Some(1000)), c(true, true));
        assert_eq!(caller_of_uid(Some(1000), 990, Some(1000)), c(false, true));
        assert_eq!(caller_of_uid(Some(1001), 990, Some(1000)), None);
        assert_eq!(caller_of_uid(Some(1000), 990, None), None);
        assert_eq!(caller_of_uid(None, 990, Some(1000)), None);
    }

    /// `install` names the account that ran it through sudo or pkexec,
    /// never root itself, and root's own install keeps the one named
    /// before; the running center reads it back.
    #[test]
    fn install_names_the_account_that_ran_it() {
        let s = |v: &str| Some(v.to_string());
        assert_eq!(installing_uid(s("1000"), None), Some(1000));
        assert_eq!(installing_uid(None, s("1001")), Some(1001));
        assert_eq!(installing_uid(s("1000"), s("1001")), Some(1000));
        assert_eq!(installing_uid(s("0"), None), None);
        assert_eq!(installing_uid(None, s("0")), None);
        assert_eq!(installing_uid(s("nobody"), None), None);
        assert_eq!(installing_uid(None, None), None);
        let d = tempfile::tempdir().unwrap();
        assert_eq!(owner_account(d.path()), None);
        keep_owner_account(d.path(), Some("1000")).unwrap();
        assert_eq!(owner_account(d.path()).as_deref(), Some("1000"));
        keep_owner_account(d.path(), None).unwrap();
        assert_eq!(owner_account(d.path()).as_deref(), Some("1000"));
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

    /// A center of its own in `d`.
    fn center_in(d: &Path) -> crate::center::Center {
        nerve_transport::init_crypto();
        crate::center::Center::open(crate::center::Options {
            state_dir: d.to_path_buf(),
            name: Some("test".into()),
            public_url: "http://127.0.0.1:1".into(),
            log: None,
            log_level: None,
        })
        .unwrap()
    }

    /// What a peer gets for `lines` on a connection of `caller`: the first
    /// line of the answer, empty for none.
    async fn first_answer(caller: Caller, lines: &str) -> String {
        let d = tempfile::tempdir().unwrap();
        let center = center_in(d.path());
        let ui = crate::ui::Ui::new(&center, None, true);
        answer_of(&center, &ui, Some(caller), lines).await
    }

    /// [`first_answer`] of the center `center` and its `ui`.
    async fn answer_of(
        center: &crate::center::Center,
        ui: &std::sync::Arc<crate::ui::Ui>,
        caller: Option<Caller>,
        lines: &str,
    ) -> String {
        let (mine, theirs) = tokio::io::duplex(64 * 1024);
        tokio::spawn(attached(center.clone(), ui.clone(), theirs, move || caller));
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
        let admin = Caller {
            harness: false,
            needs_token: false,
        };
        let (refused, said) = said(first_answer(admin, &init)).await;
        assert_eq!(refused, "", "{refused}");
        // The refusal is in the log (round 2 of #213's second pass,
        // correctness 5).
        assert!(
            said.iter().any(|l| l.contains("refused a harness")),
            "{said:?}"
        );
        let own = Caller {
            harness: true,
            needs_token: true,
        };
        let served = first_answer(own, &init).await;
        assert!(served.contains("\"serverInfo\""), "{served}");
        let request = format!(
            "{OWNER_HELLO}\n{}\n",
            serde_json::json!({"method": "GET", "path": "/api/overview", "body": {}})
        );
        let owners = first_answer(admin, &request).await;
        let v: serde_json::Value = serde_json::from_str(&owners).unwrap();
        assert!(v["ok"]["nodes"].is_array(), "{v}");
        // A caller of another account gets nothing at all.
        let d = tempfile::tempdir().unwrap();
        let center = center_in(d.path());
        let ui = crate::ui::Ui::new(&center, None, true);
        assert_eq!(answer_of(&center, &ui, None, &request).await, "");
    }

    /// The owner's requests of a caller that is not root or an
    /// administrator (the account that installed the center, the center's
    /// own) need the owner token in the hello (owner, 2026-11-16): none or
    /// a wrong one is refused as the web UI's login refuses it, with its
    /// wait and its line in the log, and changes nothing; the right one is
    /// served. Root and an administrator need none.
    #[tokio::test]
    async fn an_owner_s_request_needs_the_owner_token_unless_root_or_an_administrator() {
        let d = tempfile::tempdir().unwrap();
        let center = center_in(d.path());
        let ui = crate::ui::Ui::new(&center, None, true);
        let (token, _) = crate::owner::ensure(d.path()).unwrap();
        let owner = Some(Caller {
            harness: false,
            needs_token: true,
        });
        let make = serde_json::json!({"method": "POST", "path": "/api/tokens/create",
            "body": {"label": "agent"}});
        let tokens = || center.read(|st| st.harness_tokens.len());
        for hello in [
            owner_hello(None),
            owner_hello(Some("nrv_not_the_owner_token")),
            owner_hello(Some("")),
        ] {
            let started = std::time::Instant::now();
            let answer = answer_of(&center, &ui, owner, &format!("{hello}\n{make}\n")).await;
            assert!(started.elapsed() >= nerve_transport::webui::WRONG_SECRET_DELAY);
            let v: serde_json::Value = serde_json::from_str(&answer).unwrap();
            assert_eq!(v["login"], true, "{v}");
            assert!(
                v["error"]
                    .as_str()
                    .unwrap()
                    .starts_with("Wrong owner token."),
                "{v}"
            );
            assert_eq!(tokens(), 0);
        }
        // Told in the log as the web UI's are, the token never.
        let told = center.log_json(&nerve_transport::log::Query {
            text: Some("owner sign-in".into()),
            limit: 100,
            ..Default::default()
        });
        let told = told["entries"].to_string();
        assert!(
            told.contains("an owner sign-in on this machine was refused: wrong owner token"),
            "{told}"
        );
        assert!(!told.contains("nrv_not_the_owner_token"), "{told}");
        // The right token: served, and the app's log-in is told.
        let answer = answer_of(
            &center,
            &ui,
            owner,
            &format!("{}\n{make}\n", owner_hello(Some(&token))),
        )
        .await;
        let v: serde_json::Value = serde_json::from_str(&answer).unwrap();
        assert!(
            v["ok"]["token"].as_str().unwrap().starts_with("nrv_"),
            "{v}"
        );
        assert_eq!(tokens(), 1);
        let login = serde_json::json!({"method": "POST", "path": LOGIN, "body": {}});
        let answer = answer_of(
            &center,
            &ui,
            owner,
            &format!("{}\n{login}\n", owner_hello(Some(&token))),
        )
        .await;
        assert_eq!(answer.trim(), r#"{"ok":{}}"#);
        let told = center.log_json(&nerve_transport::log::Query {
            text: Some("signed in on this machine".into()),
            limit: 100,
            ..Default::default()
        });
        assert_eq!(told["entries"].as_array().unwrap().len(), 1, "{told}");
        // Root and an administrator, without a token; a wrong one they give
        // is refused all the same.
        let root = Some(Caller {
            harness: true,
            needs_token: false,
        });
        let answer = answer_of(
            &center,
            &ui,
            root,
            &format!("{}\n{login}\n", owner_hello(Some("nrv_wrong"))),
        )
        .await;
        assert!(answer.contains("\"login\":true"), "{answer}");
        let answer = answer_of(&center, &ui, root, &format!("{OWNER_HELLO}\n{make}\n")).await;
        let v: serde_json::Value = serde_json::from_str(&answer).unwrap();
        assert!(v["ok"]["token"].is_string(), "{v}");
        assert_eq!(tokens(), 2);
    }
}
