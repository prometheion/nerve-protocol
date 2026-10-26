//! A JSON-RPC view of a link WebSocket, for checks that drive each message.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::WebSocketStream;

use nerve_proto::frame::Frame;
use nerve_proto::msg::method;
use nerve_proto::{Id, Message, RpcError};
use nerve_transport::ws::WsMessage;

/// What the other side did next.
#[derive(Debug, Clone, PartialEq)]
pub enum Recv {
    Msg(Message),
    /// A `bye` notification, with its reason.
    Bye(String),
    /// The socket closed (or failed) without a `bye`.
    Closed,
    Timeout,
    /// A binary frame (a stream's data).
    Frame(Frame),
    /// A text frame that was not a valid JSON-RPC message, or a binary frame
    /// that is not one.
    Garbage(String),
}

/// One end of a node link.
pub struct Conn<S> {
    ws: WebSocketStream<S>,
    next_id: u64,
    /// Binary frames that came while [`Conn::answer`] waited.
    frames: Vec<Frame>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Conn<S> {
    pub fn new(ws: WebSocketStream<S>) -> Conn<S> {
        Conn {
            ws,
            next_id: 1,
            frames: Vec::new(),
        }
    }

    pub async fn send(&mut self, m: &Message) -> Result<(), String> {
        self.send_raw(&m.encode()).await
    }

    pub async fn notify(&mut self, method: &str, params: Value) -> Result<(), String> {
        self.send(&Message::notification(method, params)).await
    }

    /// Sends a request and returns its id.
    pub async fn request(&mut self, method: &str, params: Value) -> Result<u64, String> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&Message::request(id, method, params)).await?;
        Ok(id)
    }

    /// Sends raw text, for checks that need malformed input.
    pub async fn send_raw(&mut self, text: &str) -> Result<(), String> {
        self.ws
            .send(WsMessage::text(text.to_string()))
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn send_binary(&mut self, data: Vec<u8>) -> Result<(), String> {
        self.ws
            .send(WsMessage::binary(data))
            .await
            .map_err(|e| e.to_string())
    }

    /// The next message, skipping pings and pongs.
    pub async fn recv(&mut self, wait: Duration) -> Recv {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let next = match tokio::time::timeout_at(deadline, self.ws.next()).await {
                Err(_) => return Recv::Timeout,
                Ok(None) | Ok(Some(Err(_))) => return Recv::Closed,
                Ok(Some(Ok(m))) => m,
            };
            match next {
                WsMessage::Text(t) => {
                    return match Message::decode(t.as_str()) {
                        Ok(Message::Notification { method: m, params }) if m == method::BYE => {
                            Recv::Bye(
                                params
                                    .get("reason")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string(),
                            )
                        }
                        Ok(m) => Recv::Msg(m),
                        Err(_) => Recv::Garbage(t.as_str().to_string()),
                    };
                }
                WsMessage::Binary(b) => {
                    return match Frame::decode(&b) {
                        Ok(f) => Recv::Frame(f),
                        Err(e) => {
                            Recv::Garbage(format!("a binary frame of {} bytes: {e}", b.len()))
                        }
                    };
                }
                WsMessage::Close(_) => return Recv::Closed,
                _ => continue,
            }
        }
    }

    /// Waits for the answer to request `id`. Everything else that arrives
    /// meanwhile (events, the peer's own requests) is collected in `others`.
    pub async fn answer(
        &mut self,
        id: u64,
        wait: Duration,
        others: &mut Vec<Message>,
    ) -> Result<Result<Value, RpcError>, String> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match self.recv(left).await {
                Recv::Msg(Message::Result { id: got, result }) if got == Id::Num(id) => {
                    return Ok(Ok(result));
                }
                Recv::Msg(Message::Error {
                    id: Some(got),
                    error,
                }) if got == Id::Num(id) => return Ok(Err(error)),
                Recv::Msg(m) => others.push(m),
                Recv::Frame(f) => self.frames.push(f),
                Recv::Bye(r) => return Err(format!("the peer said bye ({r})")),
                Recv::Closed => return Err("the link closed".into()),
                Recv::Timeout => return Err(format!("no answer within {wait:?}")),
                Recv::Garbage(g) => return Err(format!("not a JSON-RPC message: {g}")),
            }
        }
    }

    /// The binary frames [`Conn::answer`] put aside, oldest first.
    pub fn take_frames(&mut self) -> Vec<Frame> {
        std::mem::take(&mut self.frames)
    }

    /// One request and its answer.
    pub async fn call(
        &mut self,
        method: &str,
        params: Value,
        wait: Duration,
    ) -> Result<Result<Value, RpcError>, String> {
        let id = self.request(method, params).await?;
        let mut others = Vec::new();
        self.answer(id, wait, &mut others).await
    }

    /// Sends `bye` and closes.
    pub async fn bye(&mut self, reason: &str) {
        let _ = self.notify(method::BYE, json!({"reason": reason})).await;
        let _ = self.ws.close(None).await;
    }

    /// Whether the peer ends the link within `wait`, with a bye or a close.
    pub async fn ends_within(&mut self, wait: Duration) -> Option<String> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match self.recv(left).await {
                Recv::Bye(r) => return Some(r),
                Recv::Closed => return Some(String::new()),
                Recv::Timeout => return None,
                _ => continue,
            }
        }
    }
}

/// The error code string of an RPC error, for messages.
pub fn code_of(e: &RpcError) -> String {
    e.kind().as_str().to_string()
}
