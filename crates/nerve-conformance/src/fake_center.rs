//! A minimal center for the node part: plain HTTP on loopback, one pairing
//! code, one paired node. In `auto` mode it also runs the handshake and asks
//! for the descriptor by itself, which makes it a center the center part can
//! check (the suite's self-test).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use nerve_proto::link::{CenterUrl, PairLink, PairRequest};
use nerve_proto::msg::{self, Hello, method};
use nerve_proto::{
    CONNECT_PATH, Message, NODE_HEADER, PAIR_CHECK_PATH, PAIR_PATH, PROTOCOL_VERSION, rpc::params,
};
use nerve_transport::http::{Request, Response, read_request};

use crate::wire::{Conn, Recv};

/// The node paired with the fake center.
#[derive(Debug, Clone)]
pub struct Paired {
    pub node_id: String,
    pub request: PairRequest,
}

#[derive(Default)]
struct State {
    code: Option<String>,
    tries: u32,
    paired: Option<Paired>,
}

/// An authenticated or raw link, as the node part receives it.
pub struct Incoming {
    /// The `Nerve-Node` header.
    pub node_header: String,
    pub conn: Conn<TcpStream>,
}

pub struct FakeCenter {
    pub url: CenterUrl,
    pub center_id: String,
    pub code: String,
    state: Arc<Mutex<State>>,
    links: mpsc::Receiver<Incoming>,
}

const CENTER_NAME: &str = "conformance-center";

impl FakeCenter {
    pub async fn start(auto: bool) -> std::io::Result<FakeCenter> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let url =
            CenterUrl::parse(&format!("http://127.0.0.1:{port}")).map_err(std::io::Error::other)?;
        let code = nerve_transport::keys::random_token(12);
        let center_id = format!("conformance-{}", nerve_transport::keys::random_token(16));
        let state = Arc::new(Mutex::new(State {
            code: Some(code.clone()),
            ..State::default()
        }));
        let (tx, links) = mpsc::channel(8);
        let st = state.clone();
        let cid = center_id.clone();
        tokio::spawn(async move {
            while let Ok((io, _)) = listener.accept().await {
                let (st, tx, cid) = (st.clone(), tx.clone(), cid.clone());
                tokio::spawn(async move {
                    let _ = connection(io, st, tx, cid, auto).await;
                });
            }
        });
        Ok(FakeCenter {
            url,
            center_id,
            code,
            state,
            links,
        })
    }

    pub fn link(&self) -> PairLink {
        PairLink {
            center: self.url.clone(),
            code: self.code.clone(),
            pin: None,
        }
    }

    pub fn paired(&self) -> Option<Paired> {
        self.state.lock().unwrap().paired.clone()
    }

    /// The next link a node opened (not in auto mode).
    pub async fn next_link(&mut self, wait: Duration) -> Option<Incoming> {
        tokio::time::timeout(wait, self.links.recv())
            .await
            .ok()
            .flatten()
    }
}

async fn connection(
    mut io: TcpStream,
    st: Arc<Mutex<State>>,
    tx: mpsc::Sender<Incoming>,
    center_id: String,
    auto: bool,
) -> Result<(), String> {
    let req = read_request(&mut io, 64 * 1024).await?;
    if req.method == "POST" && req.path == PAIR_PATH {
        let resp = pair(&req, &st, &center_id);
        return resp.write(&mut io).await.map_err(|e| e.to_string());
    }
    if req.method == "POST" && req.path == PAIR_CHECK_PATH {
        return check(&req, &st)
            .write(&mut io)
            .await
            .map_err(|e| e.to_string());
    }
    if req.method == "GET" && req.path == CONNECT_PATH && req.is_upgrade() {
        let header = req
            .header(&NODE_HEADER.to_ascii_lowercase())
            .unwrap_or("")
            .to_string();
        let known = st
            .lock()
            .unwrap()
            .paired
            .clone()
            .filter(|p| p.node_id == header);
        if known.is_none() {
            return Response::json(401, &json!({"error": "unknown node"}))
                .write(&mut io)
                .await
                .map_err(|e| e.to_string());
        }
        let ws = nerve_transport::ws::accept(io, &req, nerve_proto::limits::MESSAGE_BYTES as usize)
            .await?;
        let conn = Conn::new(ws);
        if auto {
            let p = known.expect("checked above");
            return auto_link(conn, &center_id, &p).await;
        }
        let _ = tx
            .send(Incoming {
                node_header: header,
                conn,
            })
            .await;
        return Ok(());
    }
    Response::json(404, &json!({"error": "not found"}))
        .write(&mut io)
        .await
        .map_err(|e| e.to_string())
}

/// The check before pairing (protocol §3.2): what the code is, nothing used.
fn check(req: &Request, st: &Mutex<State>) -> Response {
    let code = serde_json::from_slice::<Value>(&req.body)
        .ok()
        .and_then(|v| v["code"].as_str().map(str::to_string));
    let Some(code) = code else {
        return Response::json(400, &json!({"error": "no code"}));
    };
    let s = st.lock().unwrap();
    let word = if s.code.as_deref() == Some(code.as_str()) && s.tries < 10 {
        "open"
    } else if s.paired.is_some() {
        "used"
    } else {
        "gone"
    };
    Response::json(200, &json!({ "code": word }))
}

fn pair(req: &Request, st: &Mutex<State>, center_id: &str) -> Response {
    let err = |s: u16, e: &str| Response::json(s, &json!({"error": e}));
    let Ok(v) = serde_json::from_slice::<Value>(&req.body) else {
        return err(400, "not JSON");
    };
    let Ok(p) = serde_json::from_value::<PairRequest>(v) else {
        return err(400, "malformed pair request");
    };
    let Some(pk) = msg::unhex(&p.public_key).filter(|k| k.len() == 32) else {
        return err(400, "public_key is not 32 bytes of hex");
    };
    if !nerve_proto::valid_node_name(&p.name) {
        return err(400, "bad node name");
    }
    let mut s = st.lock().unwrap();
    s.tries += 1;
    if s.tries > 10 || s.code.as_deref() != Some(p.code.as_str()) {
        return err(403, "unknown, used or expired code");
    }
    s.code = None;
    let node_id = nerve_transport::keys::node_id(&pk);
    s.paired = Some(Paired {
        node_id: node_id.clone(),
        request: p,
    });
    Response::json(
        200,
        &json!({"center_id": center_id, "center_name": CENTER_NAME, "node_id": node_id}),
    )
}

/// The center's handshake: challenge, hello check, welcome. Returns the hello,
/// or the bye reason it sent. The welcome offers no resume (§4.9), as a
/// center that cannot resume links answers.
pub async fn handshake(
    conn: &mut Conn<TcpStream>,
    center_id: &str,
    paired: &Paired,
) -> Result<Hello, String> {
    let hello = hello(conn, center_id, paired).await?;
    welcome(conn, None).await?;
    Ok(hello)
}

/// [`handshake`] against the node key `public_key` (hex), which a rotation
/// may have replaced since the pairing.
pub async fn handshake_with(
    conn: &mut Conn<TcpStream>,
    center_id: &str,
    node_id: &str,
    public_key: &str,
) -> Result<Hello, String> {
    let hello = hello_with(conn, center_id, node_id, public_key).await?;
    welcome(conn, None).await?;
    Ok(hello)
}

/// The center's handshake up to the checked hello: challenge, hello check.
/// Returns the hello, or the bye reason it sent.
pub async fn hello(
    conn: &mut Conn<TcpStream>,
    center_id: &str,
    paired: &Paired,
) -> Result<Hello, String> {
    hello_with(conn, center_id, &paired.node_id, &paired.request.public_key).await
}

/// [`hello`] against the node key `public_key` (hex).
pub async fn hello_with(
    conn: &mut Conn<TcpStream>,
    center_id: &str,
    node_id: &str,
    public_key: &str,
) -> Result<Hello, String> {
    let nonce = nerve_transport::keys::random_bytes(32);
    conn.notify(
        method::CHALLENGE,
        json!({"nonce": msg::hex(&nonce), "center_id": center_id}),
    )
    .await?;
    let hello = match conn.recv(Duration::from_secs(15)).await {
        Recv::Msg(Message::Notification {
            method: m,
            params: p,
        }) if m == method::HELLO => match params::<Hello>(&p) {
            Ok(h) => h,
            Err(e) => {
                conn.bye("protocol_error").await;
                return Err(format!("bad hello: {}", e.message));
            }
        },
        other => {
            conn.bye("protocol_error").await;
            return Err(format!("expected hello, got {other:?}"));
        }
    };
    let signed =
        nerve_transport::keys::verify_connect(public_key, center_id, &nonce, &hello.auth.sig);
    if !signed || hello.node_id != node_id {
        conn.bye("protocol_error").await;
        return Err("the hello signature does not verify".into());
    }
    if !hello.versions.iter().any(|v| v == PROTOCOL_VERSION) {
        conn.bye("unsupported_version").await;
        return Err("no common version".into());
    }
    Ok(hello)
}

/// The last handshake step: `welcome`, with no features (§1.1) and `resume`
/// as given, else a new link (§4.9).
pub async fn welcome(
    conn: &mut Conn<TcpStream>,
    resume: Option<msg::Resumed>,
) -> Result<(), String> {
    let resume = resume.unwrap_or(msg::Resumed {
        resumed: false,
        got: 0,
    });
    let w = json!({
        "version": PROTOCOL_VERSION,
        "limits": msg::Limits::default(),
        "features": [],
        "resume": resume,
    });
    conn.notify(method::WELCOME, w).await
}

async fn auto_link(mut conn: Conn<TcpStream>, center_id: &str, p: &Paired) -> Result<(), String> {
    handshake(&mut conn, center_id, p).await?;
    conn.call(
        method::DESCRIBE,
        json!({"detail": "full"}),
        Duration::from_secs(15),
    )
    .await?
    .map_err(|e| e.message)?;
    // Hold the link until the node ends it.
    let _ = conn.ends_within(Duration::from_secs(60)).await;
    Ok(())
}
