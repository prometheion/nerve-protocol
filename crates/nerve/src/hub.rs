//! The center role's pages reach the installed center as a browser does:
//! over its web UI's API on loopback, logged in with the owner token
//! (design of #232, section 2). No owner account on the center and no
//! broker for the daily pages: the center's owner powers stay behind the
//! owner token, which a harness's agent, a program of the same user, does
//! not have. Only an administrator's command (install, update, `set`,
//! showing the owner token, backup) goes through the elevated broker, one
//! command at a time ([`crate::app`]).
//!
//! Before anything goes out, the token or the session, the port is checked
//! to be the center service's ([`nerve_center::holder`]): a program that
//! took it while the center was stopped gets nothing.

pub mod clip;
pub mod keep;
pub mod view;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

pub use nerve_center::holder::Holder;

/// How long one call may take: the center answers at once, but a change
/// that reaches a machine (its settings, a capability) waits for it.
const WAIT: Duration = Duration::from_secs(40);
/// The most an answer may hold: the log's download is the largest.
const MAX_BODY: usize = 64 * 1024 * 1024;

/// What the page says when the port's holder is not the center's service.
pub const NOT_RUNNING: &str = "The center is not running.";
/// What the page says when its web UI is off.
pub const UI_OFF: &str = "The center's web UI is off.";

/// Where the installed center's web UI listens, as its address file says
/// (nerve_center::ui_file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    /// The URL a program here opens: `http://127.0.0.1:7480`, or https
    /// with `pin` where the web UI listens beyond loopback.
    pub url: String,
    pub at: SocketAddr,
    pub pin: Option<String>,
}

/// What the center's address file says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Found {
    Ui(Address),
    /// The center runs with its web UI off.
    Off,
    /// No file: the center does not run.
    NotRunning,
}

/// Reads the address file in the center's run folder `run`.
pub fn find(run: &Path) -> Result<Found, String> {
    let file = nerve_center::ui_file::path_in(run);
    let Some(said) = nerve_center::ui_file::read(&file)? else {
        return Ok(Found::NotRunning);
    };
    let Some(url) = said.url else {
        return Ok(Found::Off);
    };
    let at: SocketAddr = url
        .split_once("://")
        .map(|(_, a)| a)
        .unwrap_or_default()
        .parse()
        .map_err(|_| format!("{url} names no address"))?;
    Ok(Found::Ui(Address {
        url,
        at,
        pin: said.pin,
    }))
}

/// Who holds a port (nerve_center::holder::of); tests answer for it.
pub type Judge = Arc<dyn Fn(SocketAddr) -> Result<Holder, String> + Send + Sync>;

/// The system's answer: the center's service, by its account (Linux) or
/// its process (Windows).
pub fn system_judge() -> Judge {
    Arc::new(nerve_center::holder::of)
}

/// Why a call did not give an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failed {
    /// The port is not the center service's (or nobody's): nothing was
    /// sent.
    NotTheCenter(String),
    /// The session ended (a new owner token, a restart of the center):
    /// the page logs in again.
    LoggedOut,
    /// The center answered with an error, in its words.
    Refused(u16, String),
    /// It could not be reached.
    Unreachable(String),
}

impl Failed {
    /// The words for the page.
    pub fn text(&self) -> String {
        match self {
            Failed::NotTheCenter(e) | Failed::Unreachable(e) => e.clone(),
            Failed::LoggedOut => "Log in again: the center ended the session.".into(),
            Failed::Refused(_, e) => e.clone(),
        }
    }
}

/// One center's web UI, and the app's session on it. Shared by the threads
/// that ask it.
#[derive(Clone)]
pub struct Hub {
    address: Address,
    judge: Judge,
    session: Arc<Mutex<Option<String>>>,
}

impl Hub {
    pub fn new(address: Address, judge: Judge) -> Hub {
        Hub {
            address,
            judge,
            session: Arc::default(),
        }
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Whether the app holds a session.
    pub fn logged_in(&self) -> bool {
        self.session().is_some()
    }

    fn session(&self) -> Option<String> {
        self.session
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn set_session(&self, s: Option<String>) {
        *self.session.lock().unwrap_or_else(|p| p.into_inner()) = s;
    }

    /// The port is the center service's, or why not.
    pub fn check(&self) -> Result<(), Failed> {
        match (self.judge)(self.address.at) {
            Ok(Holder::Service) => Ok(()),
            Ok(Holder::Nobody) => Err(Failed::NotTheCenter(NOT_RUNNING.into())),
            Ok(Holder::Other) => Err(Failed::NotTheCenter(format!(
                "Another program listens on {}, not the center's service: the owner token is not sent there.",
                self.address.at
            ))),
            Err(e) => Err(Failed::NotTheCenter(format!(
                "Cannot tell which program listens on {}: {e}",
                self.address.at
            ))),
        }
    }

    /// Logs in with the owner token: the app keeps the session it gets.
    pub fn login(&self, token: &str) -> Result<(), Failed> {
        self.check()?;
        let (status, body) = self.send(
            "POST",
            "/login",
            Some(&json!({"token": token.trim()})),
            None,
        )?;
        let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        match (status, v["session"].as_str()) {
            (200, Some(s)) => {
                self.set_session(Some(s.to_string()));
                Ok(())
            }
            // The center's text names its terminal command; the app has a
            // button for that.
            (401, _) => Err(Failed::Refused(401, WRONG_TOKEN.into())),
            (s, _) => Err(Failed::Refused(s, error_of(&v, s))),
        }
    }

    /// Ends the session on the center too.
    pub fn logout(&self) {
        if let Some(s) = self.session()
            && self.check().is_ok()
        {
            let _ = self.send("POST", "/logout", Some(&json!({})), Some(&s));
        }
        self.set_session(None);
    }

    /// `GET path` (with its query) of the API.
    pub fn get(&self, target: &str) -> Result<Value, Failed> {
        self.call("GET", target, None)
    }

    /// `POST path` of the API with `body`.
    pub fn post(&self, path: &str, body: &Value) -> Result<Value, Failed> {
        self.call("POST", path, Some(body))
    }

    /// The log file the center keeps, as its web UI downloads it.
    pub fn log_file(&self) -> Result<Vec<u8>, Failed> {
        let s = self.session().ok_or(Failed::LoggedOut)?;
        self.check()?;
        match self.send("GET", "/api/log/download", None, Some(&s))? {
            (200, body) => Ok(body),
            (401, _) => {
                self.set_session(None);
                Err(Failed::LoggedOut)
            }
            (status, body) => {
                let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                Err(Failed::Refused(status, error_of(&v, status)))
            }
        }
    }

    fn call(&self, method: &str, target: &str, body: Option<&Value>) -> Result<Value, Failed> {
        let s = self.session().ok_or(Failed::LoggedOut)?;
        self.check()?;
        let (status, bytes) = self.send(method, target, body, Some(&s))?;
        let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        match status {
            200 => Ok(v),
            401 => {
                self.set_session(None);
                Err(Failed::LoggedOut)
            }
            s => Err(Failed::Refused(s, error_of(&v, s))),
        }
    }

    /// One request: its status and body.
    fn send(
        &self,
        method: &str,
        target: &str,
        body: Option<&Value>,
        session: Option<&str>,
    ) -> Result<(u16, Vec<u8>), Failed> {
        let body = body.map(Value::to_string).unwrap_or_default();
        let mut head = format!(
            "{method} {target} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nConnection: close\r\nUser-Agent: nerve/{}\r\nContent-Length: {}\r\n",
            self.address.at,
            env!("CARGO_PKG_VERSION"),
            body.len()
        );
        if !body.is_empty() {
            head.push_str("Content-Type: application/json\r\n");
        }
        if let Some(s) = session {
            head.push_str(&format!(
                "{}: {s}\r\n",
                nerve_transport::webui::SESSION_HEADER
            ));
        }
        head.push_str("\r\n");
        head.push_str(&body);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Failed::Unreachable(e.to_string()))?;
        let address = self.address.clone();
        rt.block_on(async move {
            use tokio::io::AsyncWriteExt;
            let mut io = open(&address).await.map_err(Failed::Unreachable)?;
            io.write_all(head.as_bytes())
                .await
                .map_err(|e| Failed::Unreachable(e.to_string()))?;
            let r = nerve_transport::http::read_client_response(&mut io, MAX_BODY, WAIT)
                .await
                .map_err(Failed::Unreachable)?;
            Ok((r.status, r.body))
        })
    }
}

/// What the login says to a wrong token.
pub const WRONG_TOKEN: &str = "That is not the center's owner token.";

/// The connection to the web UI: plain on loopback, TLS pinned to the
/// center's certificate beyond it.
async fn open(a: &Address) -> Result<nerve_transport::BoxIo, String> {
    match &a.pin {
        None => {
            let tcp =
                tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(a.at))
                    .await
                    .map_err(|_| format!("{} did not answer", a.at))?
                    .map_err(|e| format!("cannot reach {}: {e}", a.at))?;
            Ok(Box::new(tcp))
        }
        Some(pin) => {
            let url = nerve_proto::link::CenterUrl::parse(&a.url)?;
            nerve_transport::net::open(&url, Some(pin), None).await
        }
    }
}

/// The error an answer names, or its status.
fn error_of(v: &Value, status: u16) -> String {
    v["error"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| format!("The center answered {status}."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_address_file_says_where_the_web_ui_is() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(find(d.path()).unwrap(), Found::NotRunning);
        let file = nerve_center::ui_file::path_in(d.path());
        nerve_center::ui_file::write(&file, &nerve_center::ui_file::UiAddress::of(None, None))
            .unwrap();
        assert_eq!(find(d.path()).unwrap(), Found::Off);
        let at: SocketAddr = "127.0.0.1:7480".parse().unwrap();
        nerve_center::ui_file::write(&file, &nerve_center::ui_file::UiAddress::of(Some(at), None))
            .unwrap();
        assert_eq!(
            find(d.path()).unwrap(),
            Found::Ui(Address {
                url: "http://127.0.0.1:7480".into(),
                at,
                pin: None
            })
        );
    }

    /// Nothing goes to a port another program holds, or nobody: not the
    /// token, not the session.
    #[test]
    fn nothing_goes_out_before_the_port_is_the_center_s() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let at = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = Address {
            url: format!("http://{at}"),
            at,
            pin: None,
        };
        for (holder, said) in [
            (Holder::Other, "Another program"),
            (Holder::Nobody, NOT_RUNNING),
        ] {
            let hub = Hub::new(address.clone(), Arc::new(move |_| Ok(holder)));
            match hub.login("nrv_owner_secret") {
                Err(Failed::NotTheCenter(e)) => assert!(e.contains(said), "{e}"),
                other => panic!("{other:?}"),
            }
            hub.set_session(Some("s".into()));
            assert!(matches!(
                hub.get("/api/overview"),
                Err(Failed::NotTheCenter(_))
            ));
        }
        // Nobody connected.
        assert!(listener.accept().is_err());
    }
}
