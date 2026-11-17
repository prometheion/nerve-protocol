//! The center role's pages reach the installed center as its CLI does:
//! over its local owner channel (nerve_center::attach), the owner endpoint
//! it serves for the account that installed it, not through the web UI
//! (owner, 2026-11-16). So they work with the web UI off. Each request's
//! hello carries the owner token, which the center checks as its web UI's
//! login does: a program of the same user, a harness's agent among them,
//! gets nothing without it. Only an administrator's command (install,
//! update, `set`, showing the owner token, backup) goes through the
//! elevated broker, one command at a time ([`crate::app`]).
//!
//! Before anything goes out, the token or a request, the other end is
//! checked to be the center's: on Linux the socket's peer is the
//! `nerve-center` account (or root), on Windows the pipe's owner is the
//! service's account, SYSTEM or the administrators. A program that made
//! the endpoint while the center was stopped gets nothing.

pub mod clip;
pub mod keep;
pub mod view;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

pub use nerve_center::holder::Holder;

/// How long one call may take: the center answers at once, but a change
/// that reaches a machine (its settings, a capability) waits for it.
const WAIT: Duration = Duration::from_secs(40);
/// The most an answer may hold: the log's download is the largest.
const MAX_ANSWER: u64 = 64 * 1024 * 1024;

/// What the page says when the endpoint is not the center's service.
pub const NOT_RUNNING: &str = "The center is not running.";

pub use nerve_center::attach::Peer;

/// Whether a peer is the center's service; tests answer for it.
pub type Judge = Arc<dyn Fn(&Peer) -> Result<Holder, String> + Send + Sync>;

/// The system's answer (nerve_center::attach::is_center_service).
pub fn system_judge() -> Judge {
    Arc::new(|peer: &Peer| {
        Ok(match nerve_center::attach::is_center_service(peer)? {
            true => Holder::Service,
            false => Holder::Other,
        })
    })
}

/// The installed center's owner endpoint on this machine.
pub fn endpoint() -> PathBuf {
    nerve_center::attach::owner_endpoint_at(&nerve_center::service::Layout::system())
}

/// Why a call did not give an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failed {
    /// The endpoint is not the center service's (or nobody's): nothing was
    /// sent.
    NotTheCenter(String),
    /// The token no longer works (a new owner token): the page logs in
    /// again.
    LoggedOut,
    /// The center answered with an error, in its words, with the status its
    /// web UI gives it.
    Refused(u16, String),
    /// It could not be reached.
    Unreachable(String),
}

impl Failed {
    /// The words for the page.
    pub fn text(&self) -> String {
        match self {
            Failed::NotTheCenter(e) | Failed::Unreachable(e) => e.clone(),
            Failed::LoggedOut => "Log in again: the owner token changed.".into(),
            Failed::Refused(_, e) => e.clone(),
        }
    }
}

/// The installed center's owner endpoint, and the owner token the app logged
/// in with, in memory. Shared by the threads that ask it.
#[derive(Clone)]
pub struct Hub {
    at: PathBuf,
    judge: Judge,
    token: Arc<Mutex<Option<String>>>,
}

impl Hub {
    /// `at` is the endpoint: the socket's path, or the pipe's name.
    pub fn new(at: PathBuf, judge: Judge) -> Hub {
        Hub {
            at,
            judge,
            token: Arc::default(),
        }
    }

    pub fn at(&self) -> &Path {
        &self.at
    }

    /// Whether the app logged in.
    pub fn logged_in(&self) -> bool {
        self.token().is_some()
    }

    fn token(&self) -> Option<String> {
        self.token.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    fn set_token(&self, t: Option<String>) {
        *self.token.lock().unwrap_or_else(|p| p.into_inner()) = t;
    }

    /// The endpoint is the center service's, or why not. Nothing is sent.
    pub fn check(&self) -> Result<(), Failed> {
        let rt = runtime()?;
        rt.block_on(async { self.open().await.map(drop) })
    }

    /// Logs in with the owner token: the center checks it, and the app keeps
    /// it for the calls that follow.
    pub fn login(&self, token: &str) -> Result<(), Failed> {
        let token = token.trim();
        match self.send(token, "POST", nerve_center::attach::LOGIN, &json!({})) {
            Ok(_) => {
                self.set_token(Some(token.to_string()));
                Ok(())
            }
            Err(Failed::LoggedOut) => Err(Failed::Refused(401, WRONG_TOKEN.into())),
            Err(e) => Err(e),
        }
    }

    /// Forgets the token here; the center keeps no session of the app.
    pub fn logout(&self) {
        self.set_token(None);
    }

    /// `GET path` (with its query) of the center's calls.
    pub fn get(&self, target: &str) -> Result<Value, Failed> {
        self.call("GET", target, &json!({}))
    }

    /// `POST path` of the center's calls with `body`.
    pub fn post(&self, path: &str, body: &Value) -> Result<Value, Failed> {
        self.call("POST", path, body)
    }

    /// The log file the center keeps, as its web UI downloads it.
    pub fn log_file(&self) -> Result<Vec<u8>, Failed> {
        let v = self.get("/api/log/download")?;
        Ok(v["text"].as_str().unwrap_or_default().as_bytes().to_vec())
    }

    fn call(&self, method: &str, target: &str, body: &Value) -> Result<Value, Failed> {
        let token = self.token().ok_or(Failed::LoggedOut)?;
        let r = self.send(&token, method, target, body);
        if r == Err(Failed::LoggedOut) {
            self.set_token(None);
        }
        r
    }

    /// One request with `token` in its hello: the center's answer.
    fn send(&self, token: &str, method: &str, target: &str, body: &Value) -> Result<Value, Failed> {
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let request = json!({"method": method, "path": path, "query": query, "body": body});
        let lines = format!(
            "{}\n{request}\n",
            nerve_center::attach::owner_hello(Some(token))
        );
        let rt = runtime()?;
        let line = rt.block_on(async {
            use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
            // The other end is checked before a byte goes out.
            let io = self.open().await?;
            let (r, mut w) = tokio::io::split(io);
            w.write_all(lines.as_bytes())
                .await
                .map_err(|e| Failed::Unreachable(format!("Cannot ask the center: {e}")))?;
            let mut line = String::new();
            let mut r = tokio::io::BufReader::new(r).take(MAX_ANSWER);
            match tokio::time::timeout(WAIT, r.read_line(&mut line)).await {
                Ok(Ok(n)) if n > 0 => Ok(line),
                Ok(Ok(_)) => Err(Failed::Unreachable(
                    "The center ended the connection without an answer.".into(),
                )),
                Ok(Err(e)) => Err(Failed::Unreachable(format!(
                    "Cannot read the center's answer: {e}"
                ))),
                Err(_) => Err(Failed::Unreachable(
                    "The center did not answer in time.".into(),
                )),
            }
        })?;
        let v: Value = serde_json::from_str(&line)
            .map_err(|e| Failed::Unreachable(format!("The center's answer: {e}")))?;
        if let Some(ok) = v.get("ok") {
            return Ok(ok.clone());
        }
        if v["login"] == true {
            return Err(Failed::LoggedOut);
        }
        let status = v["status"].as_u64().unwrap_or(400) as u16;
        Err(Failed::Refused(status, error_of(&v, status)))
    }

    /// The connection to the endpoint, once its other end proved to be the
    /// center's.
    async fn open(&self) -> Result<Stream, Failed> {
        let (io, peer) = connect(&self.at).await?;
        match (self.judge)(&peer) {
            Ok(Holder::Service) => Ok(io),
            Ok(Holder::Nobody) => Err(Failed::NotTheCenter(NOT_RUNNING.into())),
            Ok(Holder::Other) => Err(Failed::NotTheCenter(format!(
                "Another program answers at {}, not the center's service: the owner token is not sent there.",
                self.at.display()
            ))),
            Err(e) => Err(Failed::NotTheCenter(format!(
                "Cannot tell which program answers at {}: {e}",
                self.at.display()
            ))),
        }
    }
}

/// What the log-in says to a wrong token.
pub const WRONG_TOKEN: &str = "That is not the center's owner token.";

fn runtime() -> Result<tokio::runtime::Runtime, Failed> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Failed::Unreachable(e.to_string()))
}

type Stream = nerve_center::attach::OwnerStream;

/// Opens the owner endpoint `at`, and says whose it is. One that is not
/// there, or that nobody listens on, is a center that does not run.
async fn connect(at: &Path) -> Result<(Stream, Peer), Failed> {
    nerve_center::attach::open_owner(at)
        .await
        .map_err(|e| match e {
            None => Failed::NotTheCenter(NOT_RUNNING.into()),
            Some(e) => Failed::Unreachable(e),
        })
}

/// The error an answer names, or its status.
fn error_of(v: &Value, status: u16) -> String {
    v["error"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| format!("The center answered {status}."))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// Nothing goes to an endpoint another account made, or nobody: not
    /// the token, not a request.
    #[test]
    fn nothing_goes_out_before_the_endpoint_is_the_center_s() {
        use std::io::Read;
        let d = tempfile::tempdir().unwrap();
        let at = d.path().join("owner.sock");
        let listener = std::os::unix::net::UnixListener::bind(&at).unwrap();
        let got = std::thread::spawn(move || {
            let mut all = Vec::new();
            for _ in 0..2 {
                let (mut c, _) = listener.accept().unwrap();
                let mut bytes = Vec::new();
                let _ = c.read_to_end(&mut bytes);
                all.extend(bytes);
            }
            all
        });
        let mine = nerve_transport::net::euid();
        let asked: Arc<Mutex<Vec<Peer>>> = Arc::default();
        let said = asked.clone();
        let hub = Hub::new(
            at.clone(),
            Arc::new(move |p: &Peer| {
                said.lock().unwrap().push(p.clone());
                Ok(Holder::Other)
            }),
        );
        match hub.login("nrv_owner_secret") {
            Err(Failed::NotTheCenter(e)) => assert!(e.contains("Another program"), "{e}"),
            other => panic!("{other:?}"),
        }
        hub.set_token(Some("nrv_owner_secret".into()));
        assert!(matches!(
            hub.get("/api/overview"),
            Err(Failed::NotTheCenter(_))
        ));
        assert!(got.join().unwrap().is_empty(), "something went out");
        // The judge was asked about the account at the other end.
        assert_eq!(*asked.lock().unwrap(), [Peer::Uid(mine), Peer::Uid(mine)]);
        // No socket: the center does not run.
        let gone = Hub::new(d.path().join("none.sock"), system_judge());
        assert_eq!(
            gone.login("x"),
            Err(Failed::NotTheCenter(NOT_RUNNING.into()))
        );
    }

    /// The system's judge takes root and the center's account, nobody
    /// else; on Windows the service's account, SYSTEM and the
    /// administrators.
    #[test]
    fn the_system_judge_takes_the_center_s_accounts_only() {
        let judge = system_judge();
        assert_eq!(judge(&Peer::Uid(0)).unwrap(), Holder::Service);
        let me = nerve_transport::net::euid();
        if me != 0 {
            assert_eq!(judge(&Peer::Uid(me)).unwrap(), Holder::Other);
        }
        for sid in ["S-1-5-18", "S-1-5-32-544"] {
            assert_eq!(judge(&Peer::Sid(sid.into())).unwrap(), Holder::Service);
        }
        assert_eq!(
            judge(&Peer::Sid(nerve_center::winsvc::account_sid())).unwrap(),
            Holder::Service
        );
        assert_eq!(
            judge(&Peer::Sid("S-1-5-21-1-2-3-1001".into())).unwrap(),
            Holder::Other
        );
    }
}
