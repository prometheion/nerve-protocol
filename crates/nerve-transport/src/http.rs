//! Just enough HTTP/1.1 for Nerve: the center's listeners read one request per
//! connection (pairing, the WebSocket upgrade, the web UI and the MCP
//! endpoint), and a node posts its pairing request.
//!
//! Connections are not kept alive: every response carries `Connection: close`.
//! That keeps the parser small and is plenty for the traffic these endpoints see.

use std::collections::BTreeMap;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The largest request or response head read.
pub const HEAD_BYTES: usize = 16 * 1024;
/// How long a peer may take to send its request head.
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(15);
/// The slowest a peer may send a request body or take a response, on
/// average after [`HEAD_TIMEOUT`]: a peer that sends or reads slower holds
/// one of the listener's connections, so it is dropped.
pub const MIN_RATE: u64 = 16 * 1024;
/// The size of each part of a response written; one that the peer does not
/// take within [`HEAD_TIMEOUT`] ends the write.
const WRITE_PART: usize = 16 * 1024;

/// How long a peer has to send or take `len` bytes: [`HEAD_TIMEOUT`], and
/// a second more for each [`MIN_RATE`] bytes.
pub fn time_for(len: usize) -> Duration {
    HEAD_TIMEOUT + Duration::from_millis(len as u64 * 1000 / MIN_RATE)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    /// The path without the query.
    pub path: String,
    pub query: String,
    /// Header names lowercased; a repeated header keeps its last value.
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    /// The value of `key` in the query string, percent-decoded.
    pub fn query_param(&self, key: &str) -> Option<String> {
        param(&self.query, key)
    }

    /// The value of `key` in an `application/x-www-form-urlencoded` body,
    /// decoded the same way.
    pub fn form_param(&self, key: &str) -> Option<String> {
        param(&String::from_utf8_lossy(&self.body), key)
    }

    /// The bearer token of `Authorization`, if any.
    pub fn bearer(&self) -> Option<&str> {
        let v = self.header("authorization")?;
        let (scheme, token) = v.split_once(' ')?;
        scheme
            .eq_ignore_ascii_case("bearer")
            .then_some(token.trim())
    }

    pub fn is_upgrade(&self) -> bool {
        self.header("upgrade")
            .is_some_and(|u| u.eq_ignore_ascii_case("websocket"))
    }
}

fn param(encoded: &str, key: &str) -> Option<String> {
    encoded.split('&').find_map(|p| {
        let (k, v) = p.split_once('=').unwrap_or((p, ""));
        (k == key).then(|| pct_decode(v))
    })
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 3 <= b.len() => {
                match std::str::from_utf8(&b[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                {
                    Some(v) => {
                        out.push(v);
                        i += 3;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Reads up to the blank line ending a head. Returns the head and whatever
/// was read past it.
async fn read_head<R: AsyncRead + Unpin>(io: &mut R) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            let rest = buf.split_off(i + 4);
            return Ok((buf, rest));
        }
        if buf.len() > HEAD_BYTES {
            return Err("HTTP head over 16 KiB".into());
        }
        let n = io.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("connection closed before the HTTP head ended".into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// Reads one request, its body capped at `max_body` bytes. Chunked request
/// bodies are refused; every Nerve client sends `Content-Length`.
pub async fn read_request<R: AsyncRead + Unpin>(
    io: &mut R,
    max_body: usize,
) -> Result<Request, String> {
    let (head, mut rest) = tokio::time::timeout(HEAD_TIMEOUT, read_head(io))
        .await
        .map_err(|_| "timed out waiting for the HTTP request".to_string())??;
    let mut out = parse_head(&head)?;
    if out.header("transfer-encoding").is_some() {
        return Err("chunked request bodies are not supported".into());
    }
    let len: usize = match out.header("content-length") {
        None => 0,
        Some(v) => v.parse().map_err(|_| "bad Content-Length".to_string())?,
    };
    if len > max_body {
        return Err(format!("request body of {len} bytes over the limit"));
    }
    if rest.len() > len {
        rest.truncate(len);
    }
    // Each read has HEAD_TIMEOUT, and the whole body `time_for` its length:
    // a body sent a byte at a time would otherwise hold the connection for
    // as long as the peer likes.
    let read = async {
        let mut body = rest;
        while body.len() < len {
            let mut chunk = vec![0u8; (len - body.len()).min(64 * 1024)];
            let n = tokio::time::timeout(HEAD_TIMEOUT, io.read(&mut chunk))
                .await
                .map_err(|_| "timed out reading the request body".to_string())?
                .map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("connection closed inside the request body".to_string());
            }
            body.extend_from_slice(&chunk[..n]);
        }
        Ok(body)
    };
    out.body = tokio::time::timeout(time_for(len), read)
        .await
        .map_err(|_| "the request body came too slowly".to_string())??;
    Ok(out)
}

/// Reads one request head a byte at a time, so that nothing past its blank
/// line is taken: what follows a `CONNECT` belongs to the tunnel. Reads no
/// body.
pub async fn read_request_head<R: AsyncRead + Unpin>(io: &mut R) -> Result<Request, String> {
    let read = async {
        let mut head = Vec::with_capacity(512);
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if head.len() > HEAD_BYTES {
                return Err("HTTP head over 16 KiB".to_string());
            }
            let n = io.read(&mut b).await.map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("connection closed before the HTTP head ended".to_string());
            }
            head.push(b[0]);
        }
        Ok(head)
    };
    let head = tokio::time::timeout(HEAD_TIMEOUT, read)
        .await
        .map_err(|_| "timed out waiting for the HTTP request".to_string())??;
    parse_head(&head)
}

/// A request head as [`Request`], with no body yet.
fn parse_head(head: &[u8]) -> Result<Request, String> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(head) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return Err("malformed HTTP request".into()),
    }
    let target = req.path.unwrap_or("/");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut map = BTreeMap::new();
    for h in req.headers.iter() {
        map.insert(
            h.name.to_ascii_lowercase(),
            String::from_utf8_lossy(h.value).trim().to_string(),
        );
    }
    Ok(Request {
        method: req.method.unwrap_or("").to_string(),
        path: path.to_string(),
        query: query.to_string(),
        headers: map,
        body: Vec::new(),
    })
}

/// A response to write.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Response {
        Response {
            status,
            headers: vec![("Content-Type".into(), content_type.into())],
            body: body.into(),
        }
    }

    pub fn json(status: u16, v: &serde_json::Value) -> Response {
        Response::new(status, "application/json", v.to_string())
    }

    pub fn text(status: u16, s: &str) -> Response {
        Response::new(status, "text/plain; charset=utf-8", s.as_bytes().to_vec())
    }

    pub fn with_header(mut self, k: &str, v: &str) -> Response {
        self.headers.push((k.into(), v.into()));
        self
    }

    /// Writes the response. A peer that takes no part of it for
    /// [`HEAD_TIMEOUT`], or takes all of it slower than [`time_for`] allows,
    /// gets `TimedOut`: it would hold the connection, and with it one of the
    /// listener's, for as long as it likes.
    pub async fn write<W: AsyncWrite + Unpin>(&self, io: &mut W) -> std::io::Result<()> {
        let mut head = format!("HTTP/1.1 {} {}\r\n", self.status, reason(self.status));
        for (k, v) in &self.headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str(&format!(
            "Content-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
            self.body.len()
        ));
        let timed_out = || {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the peer takes the response too slowly",
            )
        };
        let write = async {
            for part in std::iter::once(head.as_bytes()).chain(self.body.chunks(WRITE_PART)) {
                tokio::time::timeout(HEAD_TIMEOUT, io.write_all(part))
                    .await
                    .map_err(|_| timed_out())??;
            }
            tokio::time::timeout(HEAD_TIMEOUT, io.flush())
                .await
                .map_err(|_| timed_out())?
        };
        tokio::time::timeout(time_for(head.len() + self.body.len()), write)
            .await
            .map_err(|_| timed_out())?
    }
}

pub fn reason(status: u16) -> &'static str {
    match status {
        101 => "Switching Protocols",
        200 => "OK",
        202 => "Accepted",
        204 => "No Content",
        303 => "See Other",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        407 => "Proxy Authentication Required",
        409 => "Conflict",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

/// A response a client read.
#[derive(Debug, Clone)]
pub struct ClientResponse {
    pub status: u16,
    /// The `Location` header, which a redirect carries.
    pub location: Option<String>,
    pub body: Vec<u8>,
}

/// Sends `POST path` with a JSON body over `io` and reads the answer, its body
/// capped at `max_body`.
pub async fn post_json<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    host: &str,
    path: &str,
    body: &serde_json::Value,
    max_body: usize,
) -> Result<ClientResponse, String> {
    let body = body.to_string();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nUser-Agent: nerve/{}\r\n\r\n{body}",
        body.len(),
        env!("CARGO_PKG_VERSION")
    );
    io.write_all(req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    read_response(io, max_body).await
}

/// Sends `GET target` (a path with its query) over `io` and reads the
/// answer, its body capped at `max_body`. A redirect is returned as it is,
/// with its `location`.
pub async fn get<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    host: &str,
    target: &str,
    max_body: usize,
) -> Result<ClientResponse, String> {
    let req = format!(
        "GET {target} HTTP/1.1\r\nHost: {host}\r\nAccept: */*\r\nConnection: close\r\nUser-Agent: nerve/{}\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );
    io.write_all(req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    read_response(io, max_body).await
}

/// Reads an answer to a request sent with `Connection: close`: up to its
/// `Content-Length`, or to the end of the connection; a chunked body is
/// decoded. Public so a caller that wrote its own request bytes (for a header
/// `get`/`post_json` do not offer, such as an `Authorization`) can read the
/// answer the same way. `wait` bounds the wait for the head and for each read
/// of the body: a caller whose server may think for long (a decision model
/// on a slow CPU) passes its own limit instead of [`HEAD_TIMEOUT`].
pub async fn read_client_response<S: AsyncRead + Unpin>(
    io: &mut S,
    max_body: usize,
    wait: Duration,
) -> Result<ClientResponse, String> {
    read_response_within(io, max_body, wait).await
}

/// Reads an answer to a request sent with `Connection: close`: up to its
/// `Content-Length`, or to the end of the connection; a chunked body is
/// decoded.
async fn read_response<S: AsyncRead + Unpin>(
    io: &mut S,
    max_body: usize,
) -> Result<ClientResponse, String> {
    read_response_within(io, max_body, HEAD_TIMEOUT).await
}

async fn read_response_within<S: AsyncRead + Unpin>(
    io: &mut S,
    max_body: usize,
    wait: Duration,
) -> Result<ClientResponse, String> {
    let (head, rest) = tokio::time::timeout(wait, read_head(io))
        .await
        .map_err(|_| "timed out waiting for the answer".to_string())??;
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);
    match resp.parse(&head) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return Err("malformed HTTP answer".into()),
    }
    let status = resp.code.unwrap_or(0);
    let header = |name: &str| {
        resp.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .and_then(|h| std::str::from_utf8(h.value).ok())
            .map(|v| v.trim().to_string())
    };
    let len = header("content-length").and_then(|v| v.parse::<usize>().ok());
    let chunked = header("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked"));
    let location = header("location");
    if len.is_some_and(|l| l > max_body) {
        return Err("answer over the size limit".into());
    }
    let mut body = rest;
    let mut chunk = [0u8; 8192];
    loop {
        if len.is_some_and(|l| body.len() >= l) {
            break;
        }
        if body.len() > max_body {
            return Err("answer over the size limit".into());
        }
        let n = tokio::time::timeout(wait, io.read(&mut chunk))
            .await
            .map_err(|_| "timed out reading the answer".to_string())?
            .map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    if let Some(l) = len {
        if body.len() < l {
            return Err("the answer ended before its Content-Length".into());
        }
        body.truncate(l);
    } else if chunked {
        body = dechunk(&body).ok_or("malformed chunked answer")?;
    }
    Ok(ClientResponse {
        status,
        location,
        body,
    })
}

/// A chunked body (RFC 9112 §7.1) without its framing; `None` when it is cut
/// short or malformed. Extensions and trailers are skipped.
fn dechunk(mut b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(b.len());
    loop {
        let eol = find(b, b"\r\n")?;
        let size = std::str::from_utf8(&b[..eol]).ok()?;
        let size = size.split(';').next()?.trim();
        let n = usize::from_str_radix(size, 16).ok()?;
        b = &b[eol + 2..];
        if n == 0 {
            return Some(out);
        }
        out.extend_from_slice(b.get(..n)?);
        b = b.get(n..)?.strip_prefix(b"\r\n")?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reads_requests_and_answers() {
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        let client = tokio::spawn(async move {
            post_json(
                &mut a,
                "c.example",
                "/nerve/v0/pair?x=a%20b",
                &serde_json::json!({"code": "abc"}),
                1024,
            )
            .await
            .unwrap()
        });
        let req = read_request(&mut b, 1024).await.unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/nerve/v0/pair");
        assert_eq!(req.query_param("x").as_deref(), Some("a b"));
        assert_eq!(req.header("Content-Type"), Some("application/json"));
        let v: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(v["code"], "abc");
        Response::json(201, &serde_json::json!({"ok": true}))
            .write(&mut b)
            .await
            .unwrap();
        let resp = client.await.unwrap();
        assert_eq!(resp.status, 201);
        assert_eq!(resp.body, br#"{"ok":true}"#);
    }

    /// A head read alone leaves what follows it in the stream: the bytes
    /// after a `CONNECT` are the tunnel's.
    #[tokio::test]
    async fn a_head_read_alone_takes_nothing_past_it() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        a.write_all(
            b"CONNECT c.example:443 HTTP/1.1\r\nHost: c.example:443\r\nProxy-Authorization: Basic eA==\r\n\r\ntunnel",
        )
        .await
        .unwrap();
        let req = read_request_head(&mut b).await.unwrap();
        assert_eq!(req.method, "CONNECT");
        assert_eq!(req.path, "c.example:443");
        assert_eq!(req.header("proxy-authorization"), Some("Basic eA=="));
        let mut rest = [0u8; 6];
        b.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"tunnel");
        a.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        drop(a);
        assert!(read_request_head(&mut b).await.is_err());
    }

    /// A peer that reads nothing of its answer is dropped once a part of it
    /// waits [`HEAD_TIMEOUT`]: it would hold the connection, and one of the
    /// listener's slots, for good (issue #150).
    /// The clock is paused: the timeout passes without the test waiting it.
    #[tokio::test(start_paused = true)]
    async fn a_peer_that_takes_nothing_of_the_response_is_dropped() {
        let (_a, mut b) = tokio::io::duplex(1024);
        let resp = Response::new(200, "text/plain", vec![b'x'; 64 * 1024]);
        let t = tokio::time::Instant::now();
        let r = tokio::time::timeout(HEAD_TIMEOUT * 3, resp.write(&mut b))
            .await
            .expect("the write waited on a peer that takes nothing");
        assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        assert!(t.elapsed() >= HEAD_TIMEOUT, "{:?}", t.elapsed());
    }

    /// A peer that reads all the time, but too slowly, is dropped after
    /// [`time_for`] the answer, though it takes every part within
    /// [`HEAD_TIMEOUT`]: 1 KiB every 0.9 s would hold a 10 MiB answer for
    /// hours.
    #[tokio::test(start_paused = true)]
    async fn a_peer_that_reads_too_slowly_is_dropped() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let reader = tokio::spawn(async move {
            let mut got = 0usize;
            let mut buf = [0u8; 1024];
            loop {
                match a.read(&mut buf).await {
                    Ok(0) | Err(_) => return got,
                    Ok(n) => got += n,
                }
                tokio::time::sleep(Duration::from_millis(900)).await;
            }
        });
        let len = 256 * 1024;
        let resp = Response::new(200, "text/plain", vec![b'x'; len]);
        let t = tokio::time::Instant::now();
        let r = resp.write(&mut b).await;
        assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        let took = t.elapsed();
        assert!(
            took >= time_for(len) && took < time_for(len) + Duration::from_secs(2),
            "{took:?}"
        );
        drop(b);
        assert!(reader.await.unwrap() < len);
    }

    /// A request body sent a byte now and then is dropped after
    /// [`time_for`] its length, though each byte comes within
    /// [`HEAD_TIMEOUT`] of the last (issue #150). The clock is paused, so
    /// the 2 s between the bytes pass without the test waiting them.
    #[tokio::test(start_paused = true)]
    async fn a_body_sent_a_byte_at_a_time_is_dropped() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let sender = tokio::spawn(async move {
            a.write_all(b"POST / HTTP/1.1\r\nContent-Length: 1000\r\n\r\n")
                .await
                .unwrap();
            for _ in 0..1000 {
                tokio::time::sleep(Duration::from_secs(2)).await;
                if a.write_all(b"x").await.is_err() {
                    return;
                }
            }
        });
        let r = tokio::time::timeout(HEAD_TIMEOUT * 3, read_request(&mut b, 1000))
            .await
            .expect("the body was waited for without end");
        assert!(r.unwrap_err().contains("too slowly"));
        sender.abort();
    }

    #[tokio::test]
    async fn refuses_big_bodies_and_chunks() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        a.write_all(b"POST / HTTP/1.1\r\nContent-Length: 99\r\n\r\n")
            .await
            .unwrap();
        assert!(read_request(&mut b, 10).await.is_err());
        let (mut a, mut b) = tokio::io::duplex(4096);
        a.write_all(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await
            .unwrap();
        assert!(read_request(&mut b, 10).await.is_err());
    }

    #[tokio::test]
    async fn get_reads_lengths_chunks_and_redirects() {
        async fn answer(raw: &'static [u8], max: usize) -> Result<ClientResponse, String> {
            let (mut a, mut b) = tokio::io::duplex(64 * 1024);
            let server = tokio::spawn(async move {
                let req = read_request(&mut b, 0).await.unwrap();
                assert_eq!(req.method, "GET");
                assert_eq!(req.path, "/a/b");
                assert_eq!(req.query_param("x").as_deref(), Some("1"));
                b.write_all(raw).await.unwrap();
            });
            let r = get(&mut a, "h.example", "/a/b?x=1", max).await;
            server.await.unwrap();
            r
        }
        let r = answer(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcdef", 10)
            .await
            .unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &b"abc"[..]));
        let r = answer(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n2\r\nde\r\n0\r\n\r\n",
            64,
        )
        .await
        .unwrap();
        assert_eq!(r.body, b"abcde");
        let r = answer(
            b"HTTP/1.1 302 Found\r\nLocation: /next?s=1\r\nContent-Length: 0\r\n\r\n",
            10,
        )
        .await
        .unwrap();
        assert_eq!((r.status, r.location.as_deref()), (302, Some("/next?s=1")));
        // Too big, cut short, or a broken chunk: an error, not a short body.
        for raw in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n"[..],
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabc",
        ] {
            assert!(
                answer(raw, 10).await.is_err(),
                "{:?}",
                String::from_utf8_lossy(raw)
            );
        }
    }

    #[test]
    fn bearer_and_decode() {
        let mut r = Request {
            method: "GET".into(),
            path: "/".into(),
            query: "a=%41%zz+b".into(),
            headers: BTreeMap::new(),
            body: vec![],
        };
        r.headers
            .insert("authorization".into(), "Bearer  tok ".into());
        assert_eq!(r.bearer(), Some("tok"));
        assert_eq!(r.query_param("a").as_deref(), Some("A%zz b"));
        // A form body decodes like a query string.
        r.body = b"password=p%26w%3Dd+x&next=%2F".to_vec();
        assert_eq!(r.form_param("password").as_deref(), Some("p&w=d x"));
        assert_eq!(r.form_param("next").as_deref(), Some("/"));
        assert_eq!(r.form_param("missing"), None);
        assert_eq!(reason(303), "See Other");
    }
}
